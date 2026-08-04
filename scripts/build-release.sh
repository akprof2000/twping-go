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

    if [ "$goos" = windows ]; then
        (cd "$STAGE" && zip -q -r "$name.zip" "$name")
        mv "$STAGE/$name.zip" "$OUT/"
    else
        tar -czf "$OUT/$name.tar.gz" -C "$STAGE" "$name"
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
