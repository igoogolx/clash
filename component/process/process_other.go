//go:build !darwin && !windows && !freebsd

package process

import (
	"net/netip"
)

func findProcessPath(_ string, _, _ netip.AddrPort) (string, error) {
	return "", ErrPlatformNotSupport
}
