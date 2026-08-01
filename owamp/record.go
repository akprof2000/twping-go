package owamp

import (
	"fmt"
	"io"
)

// DataRec — одна половина двустороннего измерения: пакет, отправленный в момент
// Send и зафиксированный в момент Recv.
type DataRec struct {
	SeqNo uint32
	Send  Timestamp
	Recv  Timestamp
	TTL   uint8
}

// TWDataRec — полная двусторонняя запись: пакет клиента, каким его увидел
// отражатель, и отражённый пакет, каким его увидел клиент.
type TWDataRec struct {
	Sent      DataRec
	Reflected DataRec
	// Lost равно true, если отражённый пакет так и не пришёл. В этом случае
	// отражённая половина содержит момент истечения таймаута потери.
	Lost bool
}

// WriteRaw печатает запись в формате twping -R. Названия полей и их порядок
// сохранены в исходном виде: это машинный формат, который разбирают внешние
// инструменты.
//
//	SSEQ STIME SS SERR SRTIME SRS SRERR STTL RSEQ RSTIME RSS RSERR RTIME RS RERR RTTL
func (r *TWDataRec) WriteRaw(w io.Writer) error {
	_, err := fmt.Fprintf(w,
		"%d %020d %d %g %020d %d %g %d %d %020d %d %g %020d %d %g %d\n",
		r.Sent.SeqNo,
		uint64(r.Sent.Send.Time), b2i(r.Sent.Send.Sync), r.Sent.Send.ErrEstimate(),
		uint64(r.Sent.Recv.Time), b2i(r.Sent.Recv.Sync), r.Sent.Recv.ErrEstimate(),
		r.Sent.TTL,
		r.Reflected.SeqNo,
		uint64(r.Reflected.Send.Time), b2i(r.Reflected.Send.Sync), r.Reflected.Send.ErrEstimate(),
		uint64(r.Reflected.Recv.Time), b2i(r.Reflected.Recv.Sync), r.Reflected.Recv.ErrEstimate(),
		r.Reflected.TTL,
	)
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
