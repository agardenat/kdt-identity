#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"

# Le dépôt est un workspace sans paquet racine : aucun `[package] name` à lire. Le nom est celui
# du binaire — le plugin de `crates/cli` — et c'est lui qui nomme le paquet comme la commande.
NAME="kdt-identity"
# La version vit sous [workspace.package] : les trois crates la partagent, le dépôt n'a qu'un tag
# et qu'un CHANGELOG.
VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/{s/^version *= *"\(.*\)"/\1/p;}' "$ROOT/Cargo.toml" | head -n1)"
[[ -n "$VERSION" ]] || { echo "version introuvable dans Cargo.toml" >&2; exit 1; }
SUMMARY="kdt-identity — plugin d'authentification kubectl"
MAINTAINER="Antoine Gardenat <agardenat@leisambro.net>"
LICENSE="Apache-2.0"
DESCRIPTION="Plugin d'authentification pour kubectl : renouvelle sans intervention le credential
d'un compte kdt-identity et le remet à kubectl, sans mot de passe à ressaisir tant que le droit
de session dure."

TARGET_TRIPLE="x86_64-unknown-linux-musl"

# A SemVer pre-release (`1.2.0-beta.1`) is spelled the same way by nobody: Cargo writes it with a
# dash, `rpm` refuses a dash in `Version` outright, and `dpkg` would read it as an upstream version
# followed by a revision. Both have to sort **below** the final release, which is the whole point of
# cutting a beta:
#   dpkg — `~` sorts lower than anything, the empty string included, so `1.2.0~beta.1 < 1.2.0`.
#   rpm  — the pre-release moves into `Release`, prefixed `0.` so that `0.beta.1` sorts below the
#          `1` the final build uses.
if [[ "$VERSION" == *-* ]]; then
    UPSTREAM="${VERSION%%-*}"
    PRERELEASE="${VERSION#*-}"
    DEB_VERSION="${UPSTREAM}~${PRERELEASE}"
    RPM_VERSION="$UPSTREAM"
    RPM_RELEASE="0.${PRERELEASE}"
else
    DEB_VERSION="$VERSION"
    RPM_VERSION="$VERSION"
    RPM_RELEASE="1"
fi

build_binary() {
    echo ">> cargo build --release --bin $NAME ($TARGET_TRIPLE)"
    # `--bin kdt-identity` : le workspace porte aussi le serveur, qui tourne dans un cluster par
    # son image et n'a rien à faire dans un paquet destiné à un poste de travail.
    # Statique : le paquet atterrit sur des distributions dont on ne connaît pas la libc.
    ( cd "$ROOT" && cargo build --release --locked --bin "$NAME" --target "$TARGET_TRIPLE" )
    BIN="$ROOT/target/$TARGET_TRIPLE/release/$NAME"
    [[ -x "$BIN" ]] || { echo "binaire introuvable : $BIN" >&2; exit 1; }
    echo ">> binaire: $BIN"
}
