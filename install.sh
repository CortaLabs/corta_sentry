#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
DESTDIR="${DESTDIR:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --destdir) DESTDIR="$2"; shift 2 ;;
    -h|--help) echo "usage: ./install.sh [--prefix /usr/local] [--destdir PATH]"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT

command -v go >/dev/null || { echo "Go 1.25+ is required" >&2; exit 1; }
command -v npm >/dev/null || { echo "Node.js/npm is required to build the embedded UI" >&2; exit 1; }

echo "==> Building CortaSentry frontend"
cd "$ROOT/web"
npm ci --ignore-scripts
npm run typecheck
npm test
npm run build

echo "==> Building CortaSentry binaries"
cd "$ROOT"
go test ./...
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BUILD/cortasentry" ./cmd/cortasentry
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BUILD/cortasentry-fixtures" ./cmd/cortasentry-fixtures
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BUILD/cortasentry-sensor" ./cmd/cortasentry-sensor

TARGET="$DESTDIR$PREFIX"
INSTALL=(install)
WRITABLE="$TARGET"
while [[ ! -e "$WRITABLE" && "$WRITABLE" != "/" ]]; do WRITABLE="$(dirname "$WRITABLE")"; done
if [[ ! -w "$WRITABLE" ]]; then
  command -v sudo >/dev/null || { echo "$TARGET is not writable and sudo is unavailable; use --prefix \"$HOME/.local\"" >&2; exit 1; }
  INSTALL=(sudo install)
  echo "==> Administrator permission is required only for the installation copy"
fi
echo "==> Installing into $TARGET"
"${INSTALL[@]}" -d -m 0755 "$TARGET/bin" "$TARGET/share/cortasentry/rules/devices" "$TARGET/share/cortasentry/rules/services" "$TARGET/share/cortasentry/rules/advisories" "$TARGET/share/cortasentry/configs"
"${INSTALL[@]}" -m 0755 "$BUILD/cortasentry" "$BUILD/cortasentry-fixtures" "$BUILD/cortasentry-sensor" "$TARGET/bin/"
for section in devices services advisories; do
  while IFS= read -r file; do "${INSTALL[@]}" -m 0644 "$file" "$TARGET/share/cortasentry/rules/$section/"; done < <(find "$ROOT/rules/$section" -maxdepth 1 -type f -name '*.yaml' -print)
done
while IFS= read -r file; do "${INSTALL[@]}" -m 0644 "$file" "$TARGET/share/cortasentry/configs/"; done < <(find "$ROOT/configs" -maxdepth 1 -type f -name '*.example*' -print)

echo "CortaSentry installed successfully."
echo "Next: mkdir cortasentry-data && cd cortasentry-data && cortasentry init"
