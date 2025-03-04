package dns

import (
	"bytes"
	"context"
	"github.com/Dreamacro/clash/component/system_dns"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Dreamacro/clash/component/dhcp"
	"github.com/Dreamacro/clash/component/iface"
	"github.com/Dreamacro/clash/component/resolver"

	D "github.com/miekg/dns"
)

const (
	IfaceTTL    = time.Second * 20
	DHCPTTL     = time.Hour
	DHCPTimeout = time.Minute
)

type dhcpClient struct {
	ifaceName string

	lock            sync.Mutex
	ifaceInvalidate time.Time
	dnsInvalidate   time.Time

	ifaceAddr *net.IPNet
	done      chan struct{}
	clients   []dnsClient
	err       error
	getDialer func() (C.Proxy, error)
}

func (d *dhcpClient) GetServers() []string {
	var servers []string
	for _, c := range d.clients {
		servers = append(servers, c.GetServers()...)
	}
	return servers
}

func (d *dhcpClient) Exchange(m *D.Msg) (msg *D.Msg, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
	defer cancel()

	return d.ExchangeContext(ctx, m)
}

func (d *dhcpClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	var clients = d.clients
	if len(clients) == 0 {
		clients, err = d.resolve(ctx)
		if err != nil {
			return nil, err
		}
	}
	mRes, err := batchExchange(ctx, clients, m)
	if err != nil {
		go d.update()
	}
	return mRes, err
}

func (d *dhcpClient) resolve(ctx context.Context) ([]dnsClient, error) {
	d.lock.Lock()

	invalidated, err := d.invalidate()
	if err != nil {
		d.err = err
	} else if invalidated {
		done := make(chan struct{})

		d.done = done

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), DHCPTimeout)
			defer cancel()

			var res []dnsClient
			dns, err := dhcp.ResolveDNSFromDHCP(ctx, d.ifaceName)
			// dns never empty if err is nil
			if err == nil {
				nameserver := make([]NameServer, 0, len(dns))
				for _, item := range dns {
					nameserver = append(nameserver, NameServer{
						Addr:      net.JoinHostPort(item.String(), "53"),
						Interface: d.ifaceName,
					})
				}

				res = transform(nameserver, d.getDialer)
			}

			d.lock.Lock()
			defer d.lock.Unlock()

			close(done)

			d.done = nil
			if len(res) != 0 {
				d.clients = res
			}
			d.err = err
		}()
	}

	d.lock.Unlock()

	for {
		d.lock.Lock()

		res, err, done := d.clients, d.err, d.done

		d.lock.Unlock()

		// initializing
		if res == nil && err == nil {
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		// dirty return
		return res, err
	}
}

func (d *dhcpClient) invalidate() (bool, error) {
	if time.Now().Before(d.ifaceInvalidate) {
		return false, nil
	}

	d.ifaceInvalidate = time.Now().Add(IfaceTTL)

	ifaceObj, err := iface.ResolveInterface(d.ifaceName)
	if err != nil {
		return false, err
	}

	addr, err := ifaceObj.PickIPv4Addr(nil)
	if err != nil {
		return false, err
	}

	if time.Now().Before(d.dnsInvalidate) && d.ifaceAddr.IP.Equal(addr.IP) && bytes.Equal(d.ifaceAddr.Mask, addr.Mask) {
		return false, nil
	}

	d.dnsInvalidate = time.Now().Add(DHCPTTL)
	d.ifaceAddr = addr

	return d.done == nil, nil
}

func (d *dhcpClient) update() {
	ctx, cancel := context.WithTimeout(context.Background(), DHCPTimeout)
	defer cancel()
	_, err := d.resolve(ctx)
	if err != nil {
		log.Warnln("DHCP resolve failed on updating: %s\n", err)
	}
}

func (d *dhcpClient) init() {
	dns, err := system_dns.ResolveServers(d.ifaceName)
	if err != nil {
		log.Warnln("DHCP resolve failed on init: %s\n", err)
	} else {
		log.Infoln("DHCP resolve: %s\n", dns)
	}
	var res []dnsClient
	nameserver := make([]NameServer, 0, len(dns))
	for _, item := range dns {
		itemAddr, err := netip.ParseAddr(item)
		if err == nil && itemAddr.Is4() {
			nameserver = append(nameserver, NameServer{
				Addr:      net.JoinHostPort(item, "53"),
				Interface: d.ifaceName,
			})
		}

	}

	res = transform(nameserver, d.getDialer)
	d.lock.Lock()
	d.clients = res
	d.lock.Unlock()
}

func newDHCPClient(ifaceName string, getDialer func() (C.Proxy, error)) *dhcpClient {
	newClient := &dhcpClient{ifaceName: ifaceName, getDialer: getDialer}
	newClient.init()
	return newClient
}
