package provider

import (
	"encoding/json"
	"errors"
	"runtime"
	"time"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/common/singledo"
	C "github.com/Dreamacro/clash/constant"
	types "github.com/Dreamacro/clash/constant/provider"

	regexp "github.com/dlclark/regexp2"
	"github.com/samber/lo"
)

var reject = adapter.NewProxy(outbound.NewReject())

const (
	ReservedName = "default"
)

type ProxySchema struct {
	Proxies []map[string]any `yaml:"proxies"`
}

// for auto gc
type ProxySetProvider struct {
	*proxySetProvider
}

type proxySetProvider struct {
	*fetcher
	proxies     []C.Proxy
	healthCheck *HealthCheck
}

func (pp *proxySetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":        pp.Name(),
		"type":        pp.Type().String(),
		"vehicleType": pp.VehicleType().String(),
		"proxies":     pp.Proxies(),
		"updatedAt":   pp.updatedAt,
	})
}

func (pp *proxySetProvider) Name() string {
	return pp.name
}

func (pp *proxySetProvider) HealthCheck() {
	pp.healthCheck.checkAll()
}

func (pp *proxySetProvider) Update() error {
	elm, same, err := pp.fetcher.Update()
	if err == nil && !same {
		pp.onUpdate(elm)
	}
	return err
}

func (pp *proxySetProvider) Initial() error {
	elm, err := pp.fetcher.Initial()
	if err != nil {
		return err
	}

	pp.onUpdate(elm)
	return nil
}

func (pp *proxySetProvider) Type() types.ProviderType {
	return types.Proxy
}

func (pp *proxySetProvider) Proxies() []C.Proxy {
	return pp.proxies
}

func (pp *proxySetProvider) Touch() {
	pp.healthCheck.touch()
}

func (pp *proxySetProvider) setProxies(proxies []C.Proxy) {
	pp.proxies = proxies
	pp.healthCheck.setProxy(proxies)
	if pp.healthCheck.auto() {
		go pp.healthCheck.checkAll()
	}
}

func stopProxyProvider(pd *ProxySetProvider) {
	pd.healthCheck.close()
	pd.fetcher.Destroy()
}

// for auto gc
type CompatibleProvider struct {
	*compatibleProvider
}

type compatibleProvider struct {
	name        string
	healthCheck *HealthCheck
	proxies     []C.Proxy
}

func (cp *compatibleProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":        cp.Name(),
		"type":        cp.Type().String(),
		"vehicleType": cp.VehicleType().String(),
		"proxies":     cp.Proxies(),
	})
}

func (cp *compatibleProvider) Name() string {
	return cp.name
}

func (cp *compatibleProvider) HealthCheck() {
	cp.healthCheck.checkAll()
}

func (cp *compatibleProvider) Update() error {
	return nil
}

func (cp *compatibleProvider) Initial() error {
	return nil
}

func (cp *compatibleProvider) VehicleType() types.VehicleType {
	return types.Compatible
}

func (cp *compatibleProvider) Type() types.ProviderType {
	return types.Proxy
}

func (cp *compatibleProvider) Proxies() []C.Proxy {
	return cp.proxies
}

func (cp *compatibleProvider) Touch() {
	cp.healthCheck.touch()
}

func stopCompatibleProvider(pd *CompatibleProvider) {
	pd.healthCheck.close()
}

func NewCompatibleProvider(name string, proxies []C.Proxy, hc *HealthCheck) (*CompatibleProvider, error) {
	if len(proxies) == 0 {
		return nil, errors.New("provider need one proxy at least")
	}

	if hc.auto() {
		go hc.process()
	}

	pd := &compatibleProvider{
		name:        name,
		proxies:     proxies,
		healthCheck: hc,
	}

	wrapper := &CompatibleProvider{pd}
	runtime.SetFinalizer(wrapper, stopCompatibleProvider)
	return wrapper, nil
}

var _ types.ProxyProvider = (*FilterableProvider)(nil)

type FilterableProvider struct {
	name      string
	providers []types.ProxyProvider
	filterReg *regexp.Regexp
	single    *singledo.Single
}

func (fp *FilterableProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":        fp.Name(),
		"type":        fp.Type().String(),
		"vehicleType": fp.VehicleType().String(),
		"proxies":     fp.Proxies(),
	})
}

func (fp *FilterableProvider) Name() string {
	return fp.name
}

func (fp *FilterableProvider) HealthCheck() {
}

func (fp *FilterableProvider) Update() error {
	return nil
}

func (fp *FilterableProvider) Initial() error {
	return nil
}

func (fp *FilterableProvider) VehicleType() types.VehicleType {
	return types.Compatible
}

func (fp *FilterableProvider) Type() types.ProviderType {
	return types.Proxy
}

func (fp *FilterableProvider) Proxies() []C.Proxy {
	elm, _, _ := fp.single.Do(func() (any, error) {
		proxies := lo.FlatMap(
			fp.providers,
			func(item types.ProxyProvider, _ int) []C.Proxy {
				return lo.Filter(
					item.Proxies(),
					func(item C.Proxy, _ int) bool {
						matched, _ := fp.filterReg.MatchString(item.Name())
						return matched
					})
			})

		if len(proxies) == 0 {
			proxies = append(proxies, reject)
		}
		return proxies, nil
	})

	return elm.([]C.Proxy)
}

func (fp *FilterableProvider) Touch() {
	for _, provider := range fp.providers {
		provider.Touch()
	}
}

func NewFilterableProvider(name string, providers []types.ProxyProvider, filterReg *regexp.Regexp) *FilterableProvider {
	return &FilterableProvider{
		name:      name,
		providers: providers,
		filterReg: filterReg,
		single:    singledo.NewSingle(time.Second * 10),
	}
}
