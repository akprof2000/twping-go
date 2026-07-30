package owamp

import "syscall"

// syscallRawConn — псевдоним интерфейса, который передаётся в
// net.Dialer.Control и net.ListenConfig.Control; он позволяет не писать полное
// имя syscall.RawConn в каждом месте вызова.
type syscallRawConn = syscall.RawConn
