#!/bin/sh

#  wwanHotspot
#
#  Wireless WAN Hotspot management application for OpenWrt routers.
#  $Revision: 1.12 $
#
#  Copyright (C) 2017-2018 Jordi Pujol <jordipujolp AT gmail DOT com>
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
	_applog "syslog:" "${@}"
}

_sleep() {
	[ -z "${Debug}" ] || \
		_applog "sleeping ${Interval} seconds"
	sleep ${Interval} > /dev/null 2>&1 &
	PidSleep="${!}"
	wait "${PidSleep}" || :
	[ -z "${Debug}" ] || \
		_applog "sleeping ended"
	PidSleep=""
}

_ps_children() {
	local p
	for p in $(pgrep -P "${1}"); do
		echo "${p}"
		_ps_children "${p}"
	done
}

IsWifiActive() {
	local ssid="${1}" iface="${2:-"wlan0"}" ssid1
	ssid1="$(iwinfo | \
	sed -nre '\|^'"${iface}"'[[:blank:]]+ESSID: (.+)$| {s||\1|p;q0}; ${q1}')" && \
	[ "${ssid1}" = "${ssid}" ]
}

WatchWifi() {
	local c="${1:-10}" iface ApSsid ApDisabled
	[ "$(uci -q get wireless.@wifi-iface[1].disabled)" = 1 ] && \
		iface="wlan0" || \
		iface="wlan0-1"
	ApSsid="$(uci -q get wireless.@wifi-iface[0].ssid)" || :
	ApDisabled="$(uci -q get wireless.@wifi-iface[0].disabled)" || :
	while [ $((c--)) -gt 0 ]; do
		sleep 1
		[ "${ApDisabled}" != 1 ] || \
			break
		! IsWifiActive "\"${ApSsid}\"" "${iface}" || \
			break
	done
}

ScanRequested() {
	[ -n "${PidSleep}" ] || \
		return 0
	_log "Scan requested."
	WwanErr=0
	ScanRequest=${CfgSsidsCnt}
	kill -TERM "${PidSleep}" || :
}

_exit() {
	trap - EXIT HUP USR1 USR2
	_log "Exiting."
	pids="$(_ps_children "${PidDaemon}")"
	[ -z "${pids}" ] || \
		kill -TERM ${pids} > /dev/null 2>&1 &
	wait || :
}

ListStatus() {
	local v
	_applog "${NAME}" "Actual status:"
	_applog
	_applog "Debug=\"${Debug}\""
	_applog "ScanAuto=\"${ScanAuto}\""
	_applog "Sleep=\"${Sleep}\""
	_applog "SleepScanAuto=\"${SleepScanAuto}\""
	_applog "BlackList=\"${BlackList}\""
	_applog
	set | awk -F '=' \
	'$1 ~ "^net[[:digit:]]+_" {print}' 2> /dev/null | sort | \
	while read v; do
		_applog "${v}"
	done
	_applog

	ScanRequested
}

LoadConfig() {
	_log "Loading configuration."

	# config variables, default values
	Debug="y"
	ScanAuto="y"
	Sleep=20
	SleepScanAuto="$((${Sleep}*15))"
	BlackList=3
	unset $(set | awk -F '=' \
		'$1 ~ "^net[[:digit:]]+_" {print $1}') 2> /dev/null || :

	[ ! -s "/etc/config/${NAME}" ] || \
		. "/etc/config/${NAME}"

	Debug="${Debug:-}"
	ScanAuto="${ScanAuto:-}"
	Sleep="${Sleep:-"20"}"
	SleepScanAuto="${SleepScanAuto:-"$((${Sleep}*15))"}"
	BlackList="${BlackList:-"3"}"

	if [ "${Debug}" = "xtrace" ]; then
		exec >> "/var/log/${NAME}.xtrace" 2>&1
		set -x
	else
		exec >> "/var/log/${NAME}" 2>&1
		set +x
	fi

	IfaceWan="$(uci -q get network.wan.ifname)" || :

	CfgSsids=""
	CfgSsidsCnt=0
	local n=0 ssid
	while true; do
		[ "$((n++))" -le "999" ] || \
			return 1
		eval ssid=\"\${net${n}_ssid:-}\" && \
		[ -n "${ssid}" ] || \
			break
		if [ ${n} -eq 1 ]; then
			CfgSsids="${ssid}"
		else
			CfgSsids="${CfgSsids}"$'\n'"${ssid}"
		fi
		CfgSsidsCnt=${n}
	done
	if [ ${CfgSsidsCnt} -eq 0 ]; then
		WwanSsid="$(uci -q get wireless.@wifi-iface[1].ssid)" || :
		if [ -n "${WwanSsid}" ]; then
			CfgSsids="${WwanSsid}"
			net1_ssid="${WwanSsid}"
			CfgSsidsCnt=1
		else
			_log "Invalid configuration."
			exit 1
		fi
	fi

	NetworkRestarted=0
	WwanErr=0
	ScanRequest=${CfgSsidsCnt}
	ConnectingTo=0
	ConnAttempts=0
	ListStatus
}

IsWanConnected() {
	local status
	status="$(cat "/sys/class/net/${IfaceWan}/operstate" 2> /dev/null)" && \
	[ -n "${status}" -a "${status}" != "down" ]
}

IsWwanConnected() {
	local ssid="${1:-"\"${WwanSsid}\""}"
	[ "${WwanDisabled}" != 1 ] && \
	IsWifiActive "${ssid}" && \
	sleep 5 && \
	IsWifiActive "${ssid}"
}

MustScan() {
	[ ${ScanRequest} -le 0 -a "${ScanAuto}" != "allways" ] || \
		return 0
	[ -n "${ScanAuto}" ] && ! IsWanConnected
}

Scanning() {
	local err i=5
	while [ $((i--)) -gt 0 ]; do
		sleep 1
		! err="$(iw wlan0 scan 3>&2 2>&1 1>&3 3>&-)" 2>&1 || \
			return 0
		[ -z "${Debug}" ] || \
			_applog "${err}"
		[ ${i} -le 1 ] && \
		echo "${err}" | grep -qse 'command failed: Network is down' || \
			continue
		_log "Error: Can't scan wifi, restarting the network."
		/etc/init.d/network restart
		sleep 20
		WatchWifi
	done
	_log "Serious error: Can't scan wifi for access points"
	return 1
}

ActiveSsidNbr() {
	echo "${CfgSsids}" | \
	awk -v ssid="${WwanSsid}" '$0 == ssid {print NR; rc=-1; exit}
	END{if (! rc) {print 0}; exit rc+1}'
}

CheckConnectivity() {
	local delay=20 addr check
	if [ "${ConnectingTo}" -gt 0 ] || \
	ConnectingTo="$(ActiveSsidNbr)"; then
		eval check=\"\${net${ConnectingTo}_check:-}\" && \
		[ -n "${check}" ] || \
			return 0
		while [ $((delay--)) -gt 0 ]; do
			sleep 1
			if echo "${check}" | \
			sed -nre '\|^(([[:digit:]]+[.]){3}[[:digit:]]+)$|{q0};{q1}' && \
			[ -n "$(ip -4 route show default dev wlan0)" ]; then
				addr="${check}"
			else
				addr="$(ip -4 route show dev wlan0 | \
				sed -nre '\|^(([[:digit:]]+[.]){3}[[:digit:]]+)[[:blank:]]+.*|{
				s||\1|p;q0};${q1}')" || \
					continue
			fi
			ping -c 3 -I wlan0 "${addr}" || \
				break
			if [ "${Status}" = 2 ]; then
				[ -z "${Debug}" ] || \
					_applog "Connectivity of ${ConnectingTo}:'${WwanSsid}' has been verified"
			else
				_log "Connectivity of ${ConnectingTo}:'${WwanSsid}' has been verified"
			fi
			return 0
		done
		_log "Error: hotspot ${ConnectingTo}:'${WwanSsid}' has limited or no connectivity at all"
	else
		_applog "Error: Can't check connectivity of hotspot '${WwanSsid}'"
	fi
	return 1
}

DoScan() {
	local ssid blacklisted hidden scanned found_hidden n i

	if ! MustScan; then
		[ -z "${Debug}" ] || \
			_applog "Must not scan"
		return 1
	fi

	[ -z "${Debug}" ] || \
		_applog "DoScan - Scanning"

	scanned="$(Scanning | \
	sed -nre '\|^[[:blank:]]+SSID: (.*)$| {
	s||\1|p;h}
	${x;/./{q0};q1}')" || \
		return 1
	found_hidden="$(! echo "${scanned}" | grep -qsxe '' || \
		echo "y")"

	[ ${ConnectingTo} -gt 0 ] || \
		ConnectingTo="$(ActiveSsidNbr)" || :
	n=${ConnectingTo}
	if [ -n "${WwanSsid}" -a ${n} -gt 0 ]; then
		[ $((n++)) -lt ${CfgSsidsCnt} ] || \
			n=1
	else
		n=1
	fi

	i=${n}
	while :; do
		eval ssid=\"\${net${i}_ssid:-}\" && \
		[ -n "${ssid}" ] || \
			break

		eval hidden=\"\${net${i}_hidden:-}\" || :
		if [ "${hidden}" = "y" -a -n "${found_hidden}" ] || \
		( [ -n "${hidden}" -a "${hidden}" != "y" ] && \
			echo "${scanned}" | grep -qsxF "${hidden}" ) || \
		echo "${scanned}" | grep -qsxF "${ssid}"; then
			eval blacklisted=\"\${net${i}_blacklisted:-}\" || :
			if [ -z "${blacklisted}" ]; then
				echo "${i}"
				return 0
			else
				[ -z "${Debug}" ] || \
					_applog "Not selecting blacklisted hotspot ${i}:'${ssid}'"
			fi
		fi
		[ $((i++)) -lt ${CfgSsidsCnt} ] || \
			i=1
		[ ${i} -ne ${n} ] || \
			break
	done
	[ -z "${Debug}" ] || \
		_applog "No Hotspots available."
	return 1
}

WwanDisable() {
	_log "Disabling wireless device for hotspot '${WwanSsid}'"
	uci set wireless.@wifi-iface[1].disabled=1
	WwanDisabled=1
	uci commit wireless
	wifi down
	wifi up
}

HotspotBlackList() {
	_log "Unsuccessful connection ${ConnectingTo}:'${WwanSsid}'"
	if [ ${ConnectingTo} -gt 0 ] && \
	[ ${BlackList} -gt 0 ] && \
	[ $((ConnAttempts++)) -ge ${BlackList} ]; then
		eval net${ConnectingTo}_blacklisted=\"y\" || :
		_log "Blacklisting connection ${ConnectingTo}:'${WwanSsid}'"
	fi
}

WifiStatus() {
	# internal variables, daemon scope
	local CfgSsids CfgSsidsCnt n IfaceWan WwanSsid WwanDisabled
	local ScanRequest WwanErr Status=0 Interval=1
	local ConnectingTo=0 ConnAttempts=1
	local PidDaemon="${$}"
	local PidSleep=""
	local NetworkRestarted=0

	trap '_exit' EXIT

	rm -f "/var/log/${NAME}" \
		"/var/log/${NAME}.xtrace"
	LoadConfig || exit 1

	trap 'LoadConfig' HUP
	trap 'ScanRequested' USR1
	trap 'ListStatus' USR2

	while _sleep; do
		WwanDisabled="$(uci -q get wireless.@wifi-iface[1].disabled)" || :
		WwanSsid="$(uci -q get wireless.@wifi-iface[1].ssid)" || :
		if IsWwanConnected; then
			NetworkRestarted=0
			WwanErr=0
			if ! CheckConnectivity; then
				WwanDisable
				HotspotBlackList
				Status=1
				ScanRequest=1
				Interval=${Sleep}
				WatchWifi
				continue
			fi
			ScanRequest=0
			ConnAttempts=1
			if [ ${Status} != 2 ]; then
				_log "Hotspot is connected to '${WwanSsid}'"
				Status=2
				Interval=${SleepScanAuto}
			else
				[ -z "${Debug}" ] || \
					_applog "Hotspot is already connected to '${WwanSsid}'"
			fi
		elif [ ${NetworkRestarted} -gt 0 ]; then
			NetworkRestarted=$((${NetworkRestarted}-1))
			continue
		elif IsWwanConnected "unknown"; then
			WwanDisable
			if [ ${Status} != 1 ]; then
				[ ${Status} = 2 ] || \
					HotspotBlackList
				Status=1
				ScanRequest=1
				Interval=${Sleep}
			else
				[ -z "${Debug}" ] || \
					_applog "Disabling wireless device for Hotspot, Again ?"
			fi
			WatchWifi
			continue
		elif n="$(DoScan)"; then
			[ -z "${Debug}" ] || \
				_applog "DoScan selected '${n}'"
			local ssid
			eval ssid=\"\${net${n}_ssid:-}\" || :
			if [ ${ConnectingTo} -ne ${n} ]; then
				ConnectingTo=${n}
				ConnAttempts=1
			fi
			if [ "${ssid}" != "${WwanSsid}" ]; then
				local encrypt key
				eval encrypt=\"\${net${n}_encrypt:-}\" || :
				eval key=\"\${net${n}_key:-}\" || :
				WwanErr=0
				_log "Hotspot '${ssid}' found. Applying settings..."
				uci set wireless.@wifi-iface[1].ssid="${ssid}"
				uci set wireless.@wifi-iface[1].encryption="${encrypt}"
				uci set wireless.@wifi-iface[1].key="${key}"
				WwanSsid="${ssid}"
				[ "${WwanDisabled}" != 1 ] || \
					uci set wireless.@wifi-iface[1].disabled=0
				uci commit wireless
				sleep 1
				/etc/init.d/network restart
				NetworkRestarted=2
				_log "Connecting to '${WwanSsid}'..."
				WatchWifi 20
			elif [ "${WwanDisabled}" = 1 ]; then
				uci set wireless.@wifi-iface[1].disabled=0
				uci commit wireless
				wifi down
				wifi up
				_log "Enabling Hotspot client interface to '${WwanSsid}'..."
				WatchWifi
			else
				_applog "Hotspot client interface to '${WwanSsid}' is already enabled"
			fi
			Status=3
			if [ $((WwanErr++)) -gt ${CfgSsidsCnt} ]; then
				Interval=${SleepScanAuto}
				ScanRequest=0
				_log "Error: can't connect to Hotspots," \
					"probably configuration is not correct."
			else
				Interval=${Sleep}
			fi
		else
			WwanErr=0
			[ ${ScanRequest} != ${CfgSsidsCnt} ] || \
				_log "A Hotspot is not available."
			Status=4
			if [ "${WwanDisabled}" != 1 ]; then
				Interval=${Sleep}
			elif [ ${ScanRequest} -gt 0 ] && \
			[ -n "${ScanAuto}" ] && \
			! IsWanConnected; then
				Interval=$((${Sleep}*3))
			else
				Interval=${SleepScanAuto}
			fi
		fi
		[ ${ScanRequest} -le 0 ] || \
			ScanRequest=$((${ScanRequest}-1))
	done
}

set -eu -o pipefail
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
