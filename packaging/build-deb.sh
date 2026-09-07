#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

ARCH="amd64"
build_binary

STAGE="$DIST/deb/${NAME}_${DEB_VERSION}_${ARCH}"
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/bin"

install -Dm755 "$BIN" "$STAGE/usr/bin/$NAME"

# Les lignes de la description sont indentées d'une espace, et une ligne vide s'y écrit « . » :
# c'est le format que dpkg attend, pas une coquetterie.
{
    cat <<CONTROL
Package: $NAME
Version: $DEB_VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Maintainer: $MAINTAINER
Description: $SUMMARY
CONTROL
    printf '%s\n' "$DESCRIPTION" | sed 's/^$/./; s/^/ /'
} > "$STAGE/DEBIAN/control"

OUT="$DIST/${NAME}_${DEB_VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT"
echo ">> $OUT"
