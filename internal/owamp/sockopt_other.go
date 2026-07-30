//go:build !linux && !darwin

package owamp

import (
	"net"
	"syscall"
)

// setTOS работает по принципу «получится — хорошо». В Windows вызов setsockopt
// с IP_TOS принимается, но стек обычно его игнорирует, если не задана политика
// QoS; на остальных платформах мы просто пропускаем эту настройку.
func setTOS(rc syscall.RawConn, tos int) {
	_ = rc.Control(func(fd uintptr) {
		_ = setTOSFD(fd, tos)
	})
}

// setSendTTL задаёт исходящий IP TTL тестового сокета, чтобы вторая сторона
// могла вычислить по нему число хопов (RFC 4656 ожидает, что отправители
// выставляют 255).
func setSendTTL(conn *net.UDPConn, ttl int) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = setSendTTLFD(fd, ttl)
	})
}

// enableRecvTTL здесь не поддерживается: стандартная библиотека Go не даёт
// переносимого способа читать вспомогательные IP-данные на этих платформах,
// поэтому число хопов обратного пути показывается как «не сообщается».
func enableRecvTTL(*net.UDPConn) bool { return false }

func readTTLFrom(conn *net.UDPConn, buf, _ []byte) (n int, ttl uint8, addr *net.UDPAddr, err error) {
	n, addr, err = conn.ReadFromUDP(buf)
	return n, 0, addr, err
}

const oobBufSize = 1
