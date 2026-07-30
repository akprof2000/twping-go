#!/bin/bash
# Стенд нагрузочного сравнения: запускает оригинальный twping на C и порт на Go
# против одного и того же сервера twampd в одинаковых условиях и выводит рядом
# потери, статистику задержек и расход ресурсов клиентом.
#
# Использование: loadtest.sh СЕРВЕР [число_повторов]
set -u

SERVER="${1:-twamp-server}"
REPEATS="${2:-3}"

# количество:интервал:заполнение
SCENARIOS=(
    "1000:0.001:0"      # 1 kpps, минимум пакетов
    "5000:0.001:0"      # 1 kpps, более длинный прогон
    "10000:0.0005:0"    # 2 kpps
    "20000:0.0002:0"    # 5 kpps
    "5000:0.001:1000"   # 1 kpps с заполнением 1000 октетов
)

# run_one КЛИЕНТ КОЛИЧЕСТВО ИНТЕРВАЛ ЗАПОЛНЕНИЕ
#   -> "время cpu rss отправлено потеряно rtt_min rtt_med rtt_max"
run_one() {
    local client="$1" count="$2" interval="$3" padding="$4"
    local out rc

    out=$(/usr/bin/time -f '%e %U %S %M' -o /tmp/time.$$ \
          "$client" -c "$count" -i "$interval" -s "$padding" -L 1 -M "$SERVER" 2>/dev/null)
    rc=$?
    read -r wall user sys rss < /tmp/time.$$
    rm -f /tmp/time.$$

    if [ "$rc" -ne 0 ]; then
        echo "FAILED"
        return
    fi

    # Имена полей машинной сводки (-M) одинаковы у обоих клиентов.
    local sent lost minv medv maxv
    sent=$(awk -F'\t' '$1=="SENT"{print $2}' <<<"$out")
    lost=$(awk -F'\t' '$1=="LOST"{print $2}' <<<"$out")
    minv=$(awk -F'\t' '$1=="MIN"{print $2}' <<<"$out")
    medv=$(awk -F'\t' '$1=="MEDIAN"{print $2}' <<<"$out")
    maxv=$(awk -F'\t' '$1=="MAX"{print $2}' <<<"$out")

    local cpu
    cpu=$(awk "BEGIN{printf \"%.2f\", $user + $sys}")

    echo "${wall} ${cpu} ${rss} ${sent:-0} ${lost:-0} ${minv:-nan} ${medv:-nan} ${maxv:-nan}"
}

printf '%-22s %-10s %8s %8s %9s %7s %7s %10s %10s %10s\n' \
    СЦЕНАРИЙ КЛИЕНТ ВРЕМЯ_С CPU_С RSS_КБ ОТПР ПОТЕР RTT_MIN_С RTT_MED_С RTT_MAX_С
printf '%s\n' "--------------------------------------------------------------------------------------------------------"

for sc in "${SCENARIOS[@]}"; do
    IFS=: read -r count interval padding <<<"$sc"
    label="${count}п/${interval}с/${padding}Б"

    for client in twping twping-go; do
        for _ in $(seq 1 "$REPEATS"); do
            res=$(run_one "$client" "$count" "$interval" "$padding")
            if [ "$res" = "FAILED" ]; then
                printf '%-22s %-10s %s\n' "$label" "$client" "ОШИБКА"
                continue
            fi
            # shellcheck disable=SC2086
            set -- $res
            printf '%-22s %-10s %8s %8s %9s %7s %7s %10s %10s %10s\n' \
                "$label" "$client" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8"
        done
    done
    echo
done
