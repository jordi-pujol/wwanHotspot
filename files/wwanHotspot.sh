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

_applog() {
	printf '%s %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" \
		"$(echo "${@}")" >> "/var/log/${NAME}"
}

_log() {
	logger -t "${NAME}" "${@}"
	_applog "${@}"
}

_sleeping() {
	[ "${Status}" -ne 2 -a \
	\( "${ScanAuto}" = "y" -o ${ScanRequest} -gt 0 \) ] && \
		s=${Sleep} || \
		s=${SleepScanAuto}
	[ -z "${Debug}" ] || \
		_applog "sleeping ${s} seconds" 
	sleep ${s}
}

_sleep() {
	_sleeping > /dev/null 2>&1 &
	PidSleep="${!}"
	wait "${PidSleep}" || :
	[ -z "${Debug}" ] || \
		_applog "sleeping ended" 
	PidSleep=""
}

_ps_children() {
	local p
	for p in $(ps --no-headers --ppid "${1}" -o pid); do
		echo "${p}"
		_ps_children "${p}"
	done
}

ScanRequested() {
	[ -n "${PidSleep}" -a ${ScanRequest} -eq 0 ] || \
		return 0
	_log "Scan requested."
	WwanErr=0
	Status=0
	ScanRequest=${CfgSsidsCnt}
	kill -TERM "${PidSleep}" $(_ps_children "${PidSleep}") || :
}

_exit() {
	_log "Exiting."
	pids="$(_ps_children "${PidDaemon}")"
	if [ -n "${pids}" ]; then
		kill -TERM ${pids} > /dev/null 2>&1 &
		wait || :
	fi
}

LoadConfig() {
	local n=0 ssid

	_log "Loading configuration."

	# config variables, default values
	Debug=""
	ScanAuto="y"
	Sleep=60
	SleepScanAuto="$((${Sleep}*10))"
	net1_ssid=""

	[ ! -s "/etc/config/${NAME}" ] || \
		. "/etc/config/${NAME}"

	if [ -n "${Debug}" ]; then
		exec >> "/var/log/${NAME}.xtrace" 2>&1
		set -x
	else
		exec >> "/var/log/${NAME}" 2>&1
		set +x
	fi

	CfgSsids=""
	while true; do
		n=$((${n}+1))
		[ "${n}" -le "99" ] || \
			return 1
		eval ssid=\"\$net${n}_ssid\" && \
		[ -n "${ssid}" ] || \
			break
		if [ ${n} -eq 1 ]; then
			CfgSsids="${ssid}"
		else
			CfgSsids="${CfgSsids}"$'\n'"${ssid}"
		fi
		CfgSsidsCnt="${n}"
	done
	WwanSsid="$(uci -q get wireless.@wifi-iface[1].ssid)" || :
	[ -n "${CfgSsids}" ] || \
		if [ -n "${WwanSsid}" ]; then
			CfgSsids="${WwanSsid}"
			net1_ssid="${WwanSsid}"
			CfgSsidsCnt=1
		else
			_log "Invalid configuration."
			exit 1
		fi

	WwanErr=0
	Status=0
	ScanRequest=0
	ScanRequested
}

MustScan() {
	[ ${ScanRequest} -eq 0 -a "${ScanAuto}" != "allways" ] || \
		return 0
	[ -n "${ScanAuto}" ] || \
		return 1
	local status
	status="$(cat /sys/class/net/${IfaceWan}/operstate 2> /dev/null)" || \
		return 0
	[ -z "${status}" -o "${status}" = "down" ] || \
		return 1
}

DoScan() {
	local ssid scanned n i

	MustScan || \
		return 1

	scanned="$(iw wlan0 scan | \
		sed -nre '\|^[[:blank:]]+SSID:[[:blank:]]+([^[:blank:]]+.*)$| s||\1|p')"
	[ -n "${scanned}" ] || \
		return 1

	if [ -n "${WwanSsid}" ] && \
	n="$(printf '%s\n' "${CfgSsids}" | \
	awk -v ssid="${WwanSsid}" '$0 == ssid {print NR; rc=-1; exit}
	END{exit rc+1}')"; then
		[ ${n} -lt ${CfgSsidsCnt} ] && \
			n=$((${n}+1)) || \
			n=1
	else
		n=1
	fi

	i=${n}
	while :; do
		eval ssid=\"\$net${i}_ssid\" && \
		[ -n "${ssid}" ] || \
			return 1

		if printf '%s\n' "${scanned}" | \
		grep -qsxe "${ssid}"; then
			printf '%s:%s\n' "${i}" "${ssid}"
			return 0
		fi

		[ ${i} -lt ${CfgSsidsCnt} ] && \
			i=$((${i}+1)) || \
			i=1
		[ ${i} -ne ${n} ] || \
			return 1
	done
}

WifiStatus() {
	# internal variables, daemon scope
	local CfgSsids CfgSsidsCnt ssid WwanSsid
	local ScanRequest WwanErr Status
	local PidDaemon="${$}"
	local PidSleep=""
	local IfaceWan="$(uci -q get network.wan.ifname)" || :

	trap '_exit' EXIT

	rm -f "/var/log/${NAME}" \
		"/var/log/${NAME}.xtrace"
	LoadConfig || exit 1

	trap 'LoadConfig' HUP
	trap 'ScanRequested' USR1

	while [ ${Status} = 0 ] || _sleep; do
		if iwinfo | grep -qsre "wlan0[[:blank:]]*ESSID: unknown"; then
			uci set wireless.@wifi-iface[1].disabled=1
			uci commit wireless
			/etc/init.d/network restart
			if [ ${Status} != 1 ]; then
				_log "Disabling wireless device for Hotspot."
				Status=1
				ScanRequest=1
			fi
			continue
		fi
		WwanSsid="$(uci -q get wireless.@wifi-iface[1].ssid)" || :
		if iwinfo | \
		grep -qsre 'wlan0[[:blank:]]*ESSID: "'"${WwanSsid}"'"'; then
			ScanRequest=0
			WwanErr=0
			if [ ${Status} != 2 ]; then
				_log "Hotspot ${WwanSsid} is connected."
				Status=2
			fi
		elif ssid="$(DoScan)"; then
			local n wifi_disabled=""
			n="$(printf '%s\n' "${ssid}" | \
				cut -f 1 -s -d ':')"
			ssid="$(printf '%s\n' "${ssid}" | \
				cut -f 2- -s -d ':')"
			wifi_disabled="$(uci -q get wireless.@wifi-iface[1].disabled)"
			if [ "${ssid}" != "${WwanSsid}" ]; then
				eval encrypt=\"\$net${n}_encrypt\"
				eval key=\"\$net${n}_key\"
				WwanErr=0
				_log "${ssid} network found. Applying settings.."
				uci set wireless.@wifi-iface[1].ssid="${ssid}"
				uci set wireless.@wifi-iface[1].encryption="${encrypt}"
				uci set wireless.@wifi-iface[1].key="${key}"
				WwanSsid="${ssid}"
				[ "${wifi_disabled}" != 1 ] || \
					uci set wireless.@wifi-iface[1].disabled=0
				uci commit wireless
				/etc/init.d/network restart
				_log "Connecting to '${WwanSsid}'..."
				Status=3
			elif [ "${wifi_disabled}" = 1 ]; then
				uci set wireless.@wifi-iface[1].disabled=0
				uci commit wireless
				wifi down
				wifi up
				_log "Enabling Hotspot client interface to '${WwanSsid}'..."
				Status=3
			fi
			if [ $((WwanErr++)) -gt ${CfgSsidsCnt} ]; then
				ScanRequest=0
				_log "Error: can't connect to Hotspots," \
					"probably configuration is not correct."
			fi
		else
			WwanErr=0
			if [ ${Status} != 4 ]; then
				_log "A Hotspot is not available."
				Status=4
			fi
		fi
		[ ${ScanRequest} -eq 0 ] || \
			ScanRequest=$((${ScanRequest}-1))
	done
}

NAME="$(basename "${0}")"
case "${1:-}" in
start)
	WifiStatus
	;;
*)
	echo "Wrong arguments" >&2
	exit 1
	;;
esac
