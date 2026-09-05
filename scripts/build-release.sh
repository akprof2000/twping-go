#!/usr/bin/env bash
# Собирает воспроизводимые архивы релиза для всех поддерживаемых платформ.
#
# Использование: scripts/build-release.sh [версия]
#
# Результат: dist/twping-go_<версия>_<ос>_<архитектура>.{tar.gz,zip} и SHA256SUMS.
set -euo pipefail

VERSION="${1:-dev}"
OUT=dist

# Убираем ведущую "v" из версии, которая вкомпилируется в бинарник.
LDVERSION="${VERSION#v}"

rm -rf "$OUT"
mkdir -p "$OUT"

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

# Единое время файлов в архивах: иначе tar и zip записывают момент сборки,
# и две сборки одного коммита дают разные архивы. Берём время коммита,
# как принято для SOURCE_DATE_EPOCH.
EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 0)}"

build() {
    local goos="$1" goarch="$2"
    local name="twping-go_${VERSION}_${goos}_${goarch}"
    local dir="$STAGE/$name"
    local bin=twping

    if [ "$goos" = windows ]; then
        bin=twping.exe
    fi

    mkdir -p "$dir"
    echo "==> $goos/$goarch"

    # Флаг -trimpath и явно пустой build id обеспечивают воспроизводимость
    # результата сборки.
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
        go build -trimpath \
            -ldflags "-s -w -buildid= -X github.com/akprof2000/twping-go/twping.version=${LDVERSION}" \
            -o "$dir/$bin" ./cmd/twping

    cp README.md LICENSE NOTICE "$dir/"
    find "$dir" -exec touch -d "@$EPOCH" {} +

    if [ "$goos" = windows ]; then
        # -X не пишет расширенные атрибуты с uid/gid, а TZ фиксирует
        # локальное время, в котором zip хранит метки файлов.
        (cd "$STAGE" && TZ=UTC zip -q -X -r "$name.zip" "$name")
        mv "$STAGE/$name.zip" "$OUT/"
    else
        # Фиксированный порядок файлов, владелец и время; gzip -n не пишет
        # имя и время исходного файла в заголовок.
        tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$EPOCH" \
            -cf - -C "$STAGE" "$name" | gzip -n -9 > "$OUT/$name.tar.gz"
    fi
}

while read -r goos goarch; do
    [ -n "$goos" ] || continue
    build "$goos" "$goarch"
done <<'TARGETS'
linux amd64
linux arm64
windows amd64
windows arm64
darwin amd64
darwin arm64
TARGETS

(cd "$OUT" && sha256sum ./* > SHA256SUMS)

echo
echo "Артефакты в каталоге $OUT:"
ls -1 "$OUT"
