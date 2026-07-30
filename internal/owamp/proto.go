package owamp

import "fmt"

// Режимы сессии, согласуемые в приветствии управляющего соединения.
const (
	ModeUndefined uint32 = 0
	ModeOpen      uint32 = 1
	ModeAuth      uint32 = 2
	ModeEncrypted uint32 = 4
	ModeMixed     uint32 = 8 // TWAMP: шифрованное управление, тестовые пакеты в открытом формате

	// ModeDoCipherTest — набор режимов, в которых шифруются тестовые пакеты.
	ModeDoCipherTest = ModeAuth | ModeEncrypted
	// ModeDoCipherControl — набор режимов, в которых шифруется управляющий
	// канал.
	ModeDoCipherControl = ModeAuth | ModeEncrypted | ModeMixed

	// TWPDefaultOfferedMode — режимы, которые twping готов использовать.
	TWPDefaultOfferedMode = ModeOpen | ModeAuth | ModeEncrypted | ModeMixed
)

// ModeString возвращает название режима так, как его показывает twping.
func ModeString(m uint32) string {
	switch m {
	case ModeOpen:
		return "открытый"
	case ModeAuth:
		return "с аутентификацией"
	case ModeEncrypted:
		return "шифрованный"
	case ModeMixed:
		return "смешанный"
	default:
		return fmt.Sprintf("0x%x", m)
	}
}

// Типы управляющих сообщений-запросов.
const (
	ReqTest          = 1
	ReqStartSessions = 2
	ReqStopSessions  = 3
	ReqFetchSession  = 4
	ReqTestTW        = 5
)

// AcceptType — код принятия или отказа, передаваемый в нескольких управляющих
// сообщениях.
type AcceptType uint8

const (
	AcceptOK              AcceptType = 0
	AcceptFailure         AcceptType = 1
	AcceptReject          AcceptType = 2
	AcceptUnsupported     AcceptType = 3
	AcceptUnavailablePerm AcceptType = 4
	AcceptUnavailableTemp AcceptType = 5
)

func (a AcceptType) String() string {
	switch a {
	case AcceptOK:
		return "принято"
	case AcceptFailure:
		return "внутренняя ошибка"
	case AcceptReject:
		return "отклонено"
	case AcceptUnsupported:
		return "не поддерживается"
	case AcceptUnavailablePerm:
		return "постоянно недоступно"
	case AcceptUnavailableTemp:
		return "временно недоступно"
	default:
		return fmt.Sprintf("неизвестный код принятия %d", uint8(a))
	}
}

func validAccept(v uint8) (AcceptType, error) {
	if v > 5 {
		return AcceptFailure, fmt.Errorf("owamp: недопустимый код принятия %d", v)
	}
	return AcceptType(v), nil
}

// Размеры сообщений на проводе.
const (
	blockSize = 16

	greetingLen      = 64
	setupResponseLen = 164
	serverStartLen   = 48
	testRequestLen   = 112
	acceptSessionLen = 48
	startSessionsLen = 32
	startAckLen      = 32
	stopSessionsLen  = 32

	sidLen   = 16
	saltLen  = 16
	tokenLen = 64

	defaultPBKDF2Count = 2048
)

// TestPayloadSize возвращает размер тестового пакета отправителя для заданного
// режима.
func TestPayloadSize(mode uint32, padding uint32) uint32 {
	var base uint32
	switch mode {
	case ModeOpen, ModeMixed:
		base = 14
	case ModeAuth, ModeEncrypted:
		base = 48
	}
	return base + padding
}

// TestTWPayloadSize возвращает размер отражённого тестового пакета для
// заданного режима.
func TestTWPayloadSize(mode uint32, padding uint32) uint32 {
	var base uint32
	switch mode {
	case ModeOpen, ModeMixed:
		base = 41
	case ModeAuth, ModeEncrypted:
		base = 112
	}
	return base + padding
}

// MaxPaddingSize повторяет ограничение owamp на размер заполнения тестового
// пакета.
const MaxPaddingSize = 65000
