//go:build windows

package owamp

import "syscall"

// Номера опций уровня IPPROTO_IP в Winsock.
const (
	winIPTOS = 3
	winIPTTL = 4
)

func setTOSFD(fd uintptr, tos int) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, winIPTOS, tos)
}

func setSendTTLFD(fd uintptr, ttl int) error {
	if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, winIPTTL, ttl); err != nil {
		return err
	}
	// Значение 4 — это IPV6_UNICAST_HOPS.
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, 4, ttl)
}
