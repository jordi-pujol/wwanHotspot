#!/bin/sh

#  wwanHotspot
#
#  Wireless WAN Hotspot management application for OpenWrt routers.
#  $Revision: 1.5 $
#
#  Copyright (C) 2017-2017 Jordi Pujol <jordipujolp AT gmail DOT com>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3, or (at your option)
#  any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#************************************************************************

set -o errexit -o xtrace

_control_value() {
	awk -v var="${1}" '$1 == var {print $2; rc=-1; exit}
		END{exit rc+1}' < control
}

_package_attrs() {
	dir="$(dirname "${0}")"
	[ -z "${dir}" ] || \
		cd "${dir}"

	PKG="$(_control_value "Package:")"
	PKG_VERSION="$(_control_value "Version:")"
	PKG_ARCH="$(_control_value "Architecture:")"
	PKG_IPK="${PKG}_${PKG_VERSION}_${PKG_ARCH}.ipk"
}

_check_syntax() {
	local f rc=0
	for f in ../files/* postinst prerm; do
		busybox sh -n "${f}" || rc=1
	done
	return "${rc}"
}

case "${1}" in
all|build)
	_package_attrs
	if [ -s "${PKG_IPK}" ]; then
		echo "Nothing to do" >&2
		exit 0
	fi
	# check syntax
	_check_syntax || exit 1
	# fill package directories
	rm -rf ./ipk
	mkdir -p ./ipk/etc/config ./ipk/etc/init.d ./ipk/usr/sbin
	cp ../files/${PKG}.config ./ipk/etc/config/${PKG}
	cp ../files/${PKG}.init ./ipk/etc/init.d/${PKG}
	cp ../files/${PKG}.sh ./ipk/usr/sbin/${PKG}
	chmod a+x ./ipk/etc/init.d/${PKG} ./ipk/usr/sbin/${PKG}
	echo "2.0" > ./debian-binary
	chmod a+x ./postinst ./prerm
	# compress package files
	tar --owner=0 --group=0 --format=gnu -czvpf control.tar.gz \
		./control ./conffiles \
		./postinst ./prerm
	#cd ./ipk; tar --owner=0 --group=0 -czvf ../data.tar.gz *; cd ..
	tar --owner=0 --group=0 --format=gnu --transform 's|^.*ipk/|./|' \
		--show-stored-names \
		-czvpf data.tar.gz ipk/*
	tar --owner=0 --group=0 --format=gnu -czvf "${PKG_IPK}" \
		./debian-binary ./data.tar.gz ./control.tar.gz
	;;
clean)
	_package_attrs
	rm -rf ./ipk
	rm -f ./control.tar.gz \
		./data.tar.gz \
		./debian-binary \
		./"${PKG_IPK}"
	;;
*)
	echo "Usage '$0' all|build|clean" >&2
	exit 1
	;;
esac
