#!/usr/bin/env bash
# install.sh — Build and install kafka-security-scanner to ~/.local/bin (or $1).
#
# Requires: Java 25 (preview features), Gradle 8.12+ (or Gradle wrapper).
# Idempotent: safe to re-run after pulling updates.

set -euo pipefail

PREFIX="${1:-$HOME/.local}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$PREFIX/lib/kafka-security-scanner"
BIN_DIR="$PREFIX/bin"

echo "→ Building distribution"
cd "$SCRIPT_DIR"
if [[ -x ./gradlew ]]; then
  ./gradlew installDist -x test -x check
else
  gradle installDist -x test -x check
fi

DIST="$SCRIPT_DIR/build/install/kafka-security-scanner"
if [[ ! -d "$DIST" ]]; then
  echo "✗ build/install/kafka-security-scanner not found"
  exit 1
fi

echo "→ Installing to $LIB_DIR"
mkdir -p "$LIB_DIR" "$BIN_DIR"
rm -rf "$LIB_DIR"/*
cp -R "$DIST"/* "$LIB_DIR/"

# Bundled policies
mkdir -p "$LIB_DIR/policies"
cp -R "$SCRIPT_DIR/policies/." "$LIB_DIR/policies/"

# Wrapper script that resolves policies relative to install dir.
cat > "$BIN_DIR/kafka-security-scanner" <<EOF
#!/usr/bin/env bash
set -e
export KAFKA_SCANNER_HOME="$LIB_DIR"
cd "\$KAFKA_SCANNER_HOME"
exec "\$KAFKA_SCANNER_HOME/bin/kafka-security-scanner" "\$@"
EOF
chmod +x "$BIN_DIR/kafka-security-scanner"

echo "✓ Installed to $BIN_DIR/kafka-security-scanner"
echo "  Run: kafka-security-scanner --help"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "  NOTE: $BIN_DIR is not on PATH. Add it to your shell rc." ;;
esac
