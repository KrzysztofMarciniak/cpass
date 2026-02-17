#!/bin/sh
set -eu

CC=${CC:-cc}
CFLAGS="-std=c11 -Wall -Wextra -Wpedantic -O2"
LDFLAGS="-lcrypto"

OUTDIR="bin"
CPASS="$OUTDIR/cpass"
TEST="$OUTDIR/openssl_tests"

mkdir -p "$OUTDIR"

case "${1:-build}" in
    build)
        echo "[*] compiling main.c -> $CPASS"
        $CC $CFLAGS main.c openssl.c -o "$CPASS" $LDFLAGS
        echo "[+] build complete: $CPASS"
        ;;

    test)
        echo "[*] compiling openssl_tests.c -> $TEST"
        $CC $CFLAGS openssl.c openssl_tests.c -o "$TEST" $LDFLAGS
        echo "[*] running tests..."
        "$TEST"
        ;;

    clean)
        echo "[*] cleaning bin/ directory"
        rm -f "$CPASS" "$TEST"
        ;;
install)
    if [ ! -f "$CPASS" ]; then
        echo "[*] cpass binary not found, building first..."
        $0 build
    fi

    if command -v sudo >/dev/null 2>&1; then
        ESC="sudo"
    elif command -v doas >/dev/null 2>&1; then
        ESC="doas"
    else
        echo "Error: neither sudo nor doas found. Cannot install."
        exit 1
    fi

    echo "[*] installing $CPASS -> /usr/local/bin/cpass using $ESC"
    $ESC cp "$CPASS" /usr/local/bin/cpass
    $ESC chmod 755 /usr/local/bin/cpass
    echo "[+] installation complete."
    ;;

    *)
        echo "Usage: $0 [build|test|clean|install]"
        exit 1
        ;;
esac
