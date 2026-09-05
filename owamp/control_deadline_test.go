package owamp

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// silentServer принимает соединения и молчит: сервер, который «висит».
func silentServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("не поднять слушатель: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Соединение принято и оставлено открытым: приветствия не будет.
			t.Cleanup(func() { conn.Close() })
		}
	}()
	return ln.Addr().String()
}

func TestOpenControl_SilentServerHitsExchangeTimeout(t *testing.T) {
	// Сервер, принявший соединение и замолчавший, раньше держал клиента
	// бесконечно: время было ограничено только у подключения, а чтение
	// приветствия не ограничивалось ничем. Программе, ведущей тысячи замеров,
	// такие «висяки» стоят портов и рабочих слотов — они копятся навсегда.
	started := time.Now()
	_, err := OpenControl(ControlConfig{
		Server:          silentServer(t),
		OfferedModes:    ModeOpen,
		Timeout:         2 * time.Second,
		ExchangeTimeout: 300 * time.Millisecond,
	})

	if err == nil {
		t.Fatal("молчащий сервер принят как исправный")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Errorf("ожидание длилось %v — ограничение обмена не сработало", elapsed)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Logf("ошибка: %v", err) // текст может отличаться, важно само прерывание
	}
}

func TestOpenControl_CancelStopsSilentServer(t *testing.T) {
	// Отмена обязана прерывать и уже начатое чтение: закрытие сокета — то
	// единственное, что снимает клиента с молчащего сервера немедленно.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	started := time.Now()
	_, err := OpenControlContext(ctx, ControlConfig{
		Server:       silentServer(t),
		OfferedModes: ModeOpen,
		Timeout:      2 * time.Second,
		// Ограничение обмена нарочно большое: проверяем именно отмену.
		ExchangeTimeout: time.Minute,
	})

	if err == nil {
		t.Fatal("после отмены соединение считается открытым")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("ожидалась ошибка отмены контекста, получено %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Errorf("отмена сработала через %v — соединение не закрылось", elapsed)
	}
}

func TestOpenControl_NegativeExchangeTimeoutKeepsOldBehaviour(t *testing.T) {
	// Отрицательное значение означает «без ограничения» — прежнее поведение
	// для тех, кому оно нужно. Проверяем, что клиент действительно ждёт:
	// отменяем сами, иначе тест не закончится.
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := OpenControlContext(ctx, ControlConfig{
		Server:          silentServer(t),
		OfferedModes:    ModeOpen,
		Timeout:         2 * time.Second,
		ExchangeTimeout: -1,
	})

	if err == nil {
		t.Fatal("молчащий сервер принят как исправный")
	}
	if elapsed := time.Since(started); elapsed < 300*time.Millisecond {
		t.Errorf("клиент сдался через %v — ограничение всё-таки применилось", elapsed)
	}
}
