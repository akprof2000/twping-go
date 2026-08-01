// Команда twping измеряет двусторонние задержки до сервера TWAMP (RFC 5357).
//
// Это реализация на Go клиента twping из состава perfSONAR owamp;
// сведения об авторстве оригинала — в файле NOTICE.
//
// Вся работа выполняется пакетом twping — здесь остаётся только то, что
// свойственно именно программе: обработка Ctrl+C и код возврата. Благодаря
// этому вызов twping.Run из чужой программы даёт тот же результат, что и
// запуск утилиты, и расхождению между ними взяться неоткуда.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/akprof2000/twping-go/twping"
)

func main() {
	// Ctrl+C прерывает идущую сессию: отмена контекста доходит до неё внутри Run.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := twping.Run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "twping: %v\n", err)
		os.Exit(1)
	}
}
