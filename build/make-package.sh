#!/bin/sh

#  wwanHotspot
#
#  Wireless WAN Hotspot management application for OpenWrt routers.
#  $Revision: 2.8 $
#
#  Copyright (C) 2017-2021 Jordi Pujol <jordipujolp AT gmail DOT com>
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

_control_value() {
	awk -v var="${1}" '$1 == var {$1=""
		gsub(/^[[:blank:]]+|[[:blank:]]+$/, "")
		print; rc=-1; exit}
		END{exit rc+1}' < control
}

_package_attrs() {
	[ -z "${PKG_IPK:-}" ] || \
		return 0
	echo "Parsing package attributes" >&2
	PKG="$(_control_value "Package:")"
	PKG_VERSION="$(_control_value "Version:")"
	PKG_ARCH="$(_control_value "Architecture:")"
	PKG_IPK="${PKG}_${PKG_VERSION}_${PKG_ARCH}.ipk"
}

_check_syntax() {
	local f rc=0
	echo "Checking syntax" >&2
	[ -n "${DEBUG}" ] || \
		set -o xtrace
	for f in ../files/* postinst prerm; do
		busybox sh -n "${f}" || rc=1
	done
	{ [ -n "${DEBUG}" ] || \
		set +o xtrace; } 2> /dev/null
	return "${rc}"
}

_cleanup() {
	echo "Cleaning" >&2
	rm -vrf ./ipk
	rm -vf ./control.tar.gz \
		./data.tar.gz \
		./debian-binary \
		./*.ipk
}

set -o errexit -o nounset +o noglob

[ -z "${DEBUG:=}" ] || \
	set -o xtrace

dir="$(dirname "${0}")"
[ -z "${dir}" ] || \
	cd "${dir}"
if [ ! -f "./control" -o ! -s "./control" ]; then
	echo "Invalid package" >&2
	exit 1
fi

for cmd in "${@:-"build"}"; do
	case "${cmd}" in
	all|build)
		_package_attrs
		if [ -s "${PKG_IPK}" ]; then
			rc=0
			for f in ../files/* postinst prerm control; do
				if [ "${f}" -nt "${PKG_IPK}" ]; then
					echo "File \"${f}\" has been modified" >&2
					rc=1
				fi
			done
			if [ "${rc}" = 0 ]; then
				echo "Nothing to do" >&2
				continue
			fi
			echo "Some files have been modified. This package must be updated" >&2
		fi
		echo "Building package" >&2
		_check_syntax || \
			exit 1
		_cleanup
		echo "Populating package directories" >&2
		mkdir -p ./ipk/etc/config ./ipk/etc/init.d ./ipk/usr/sbin \
			./ipk/etc/hotplug.d/iface
		cp ../files/${PKG}.config ./ipk/etc/config/${PKG}
		cp ../files/${PKG}.init ./ipk/etc/init.d/${PKG}
		cp ../files/${PKG}.sh ./ipk/usr/sbin/${PKG}
		cp ../files/${PKG}.hotplug-iface ./ipk/etc/hotplug.d/iface/99-${PKG}
		chmod a+x ./ipk/etc/init.d/${PKG} ./ipk/usr/sbin/${PKG}
		echo "2.0" > ./debian-binary
		chmod a+x ./postinst ./prerm
		echo "Compressing control files" >&2
		tar --owner=0 --group=0 --format=gnu -czvpf control.tar.gz \
			./control ./conffiles ./postinst ./prerm
		#cd ./ipk; tar --owner=0 --group=0 -czvf ../data.tar.gz *; cd ..
		echo "Compressing data files" >&2
		tar --owner=0 --group=0 --format=gnu --transform 's|^.*ipk/|./|' \
			--show-stored-names -czvpf data.tar.gz ipk/*
		echo "Compressing package" >&2
		tar --owner=0 --group=0 --format=gnu -czvf "${PKG_IPK}" \
			./debian-binary ./data.tar.gz ./control.tar.gz
		echo "Package \"${PKG_IPK}\" has been created" >&2
		;;
	check)
		_check_syntax || \
			exit 1
		echo "Done" >&2
		;;
	clean)
		_cleanup
		echo "Done" >&2
		;;
	*)
		echo "Usage '$0' all|build|clean|check" >&2
		exit 1
		;;
	esac
done
