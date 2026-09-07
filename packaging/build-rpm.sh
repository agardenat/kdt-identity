#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

ARCH="x86_64"
build_binary

TOP="$DIST/rpmbuild"
rm -rf "$TOP"
mkdir -p "$TOP"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

install -Dm755 "$BIN" "$TOP/SOURCES/$NAME"

cat > "$TOP/SPECS/$NAME.spec" <<SPEC
Name:           $NAME
Version:        $RPM_VERSION
Release:        $RPM_RELEASE%{?dist}
Summary:        $SUMMARY
License:        $LICENSE
URL:            https://github.com/agardenat/kdt-identity
BuildArch:      $ARCH
Source0:        $NAME

%description
$DESCRIPTION

%install
install -Dm755 %{_sourcedir}/$NAME %{buildroot}%{_bindir}/$NAME

%files
%{_bindir}/$NAME

%changelog
* $(LC_ALL=C date '+%a %b %d %Y') $MAINTAINER - $RPM_VERSION-$RPM_RELEASE
- Build $VERSION
SPEC

rpmbuild \
    --define "_topdir $TOP" \
    --define "_rpmdir $DIST" \
    --define "_build_id_links none" \
    -bb "$TOP/SPECS/$NAME.spec"

echo ">> $(find "$DIST" -maxdepth 2 -name "${NAME}-${RPM_VERSION}-${RPM_RELEASE}*.rpm" | head -n1)"
