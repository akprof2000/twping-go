//go:build linux || darwin

package owamp

import (
	"net"
	"syscall"
)

// setTOS применяет к сокету байт IP TOS (класс трафика). Ошибки игнорируются:
// не всякая платформа и не всякий уровень прав это позволяют, и owamp тоже
// считает такую настройку необязательной.
func setTOS(rc syscall.RawConn, tos int) {
	_ = rc.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, tos)
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, tos)
	})
}

// setSendTTL задаёт исходящий IP TTL (для IPv6 — предел числа хопов) тестового
// сокета.
func setSendTTL(conn *net.UDPConn, ttl int) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, sysIPTTL, ttl)
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
	})
}

// enableRecvTTL просит ядро доставлять принятый IP TTL как вспомогательные
// данные. Возвращает признак того, что опция была принята.
func enableRecvTTL(conn *net.UDPConn) bool {
	rc, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	ok := false
	_ = rc.Control(func(fd uintptr) {
		if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, sysIPRecvTTL, 1); err == nil {
			ok = true
		}
		if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, sysIPv6RecvHopLimit, 1); err == nil {
			ok = true
		}
	})
	return ok
}

// readTTLFrom читает датаграмму и извлекает принятый TTL из управляющего
// сообщения, если он доступен. Значение ttl равно нулю, если TTL определить
// не удалось.
func readTTLFrom(conn *net.UDPConn, buf, oob []byte) (n int, ttl uint8, addr *net.UDPAddr, err error) {
	n, oobn, _, addr, err := conn.ReadMsgUDP(buf, oob)
	if err != nil {
		return n, 0, addr, err
	}
	ttl = parseTTL(oob[:oobn])
	return n, ttl, addr, nil
}

func parseTTL(oob []byte) uint8 {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == syscall.IPPROTO_IP &&
			(m.Header.Type == sysIPRecvTTL || m.Header.Type == sysIPTTL):
			if len(m.Data) >= 1 {
				return m.Data[0]
			}
		case m.Header.Level == syscall.IPPROTO_IPV6 &&
			m.Header.Type == sysIPv6HopLimit:
			if len(m.Data) >= 1 {
				return m.Data[0]
			}
		}
	}
	return 0
}

// oobBufSize с запасом вмещает одно управляющее сообщение с TTL.
const oobBufSize = 128
