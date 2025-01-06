package system_dns

import (
	"context"
	"fmt"
	"github.com/johnstarich/go/dns/scutil"
	"time"
)

func ResolveServers(ifaceName string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	config, err := scutil.ReadMacOSDNS(ctx)
	if err != nil {
		return nil, err
	}
	servers := make([]string, 0, len(config.Resolvers))
	for _, resolver := range config.Resolvers {
		if resolver.InterfaceName == ifaceName {
			for _, nameSever := range resolver.Nameservers {
				servers = append(servers, nameSever)
				return servers, nil
			}
		}
	}
	return nil, fmt.Errorf("resolve system dns servers for %s failed", ifaceName)
}
