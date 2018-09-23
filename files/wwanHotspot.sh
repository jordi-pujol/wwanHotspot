#!/bin/sh

#  wwanHotspot
#
#  Wireless WAN Hotspot management application for OpenWrt routers.
#  $Revision: 1.26 $
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

_integer_value() {
	local n="${1}" d="${2}" v 
	v="$(2> /dev/null printf '%d' "$(printf '%s' "${n}" | \
	sed -nre '/^[[:digit:]]+$/p;q')")" && \
		echo ${v} || \
		echo ${d}
}

_datetime() {
	date +'%Y-%m-%d %H:%M:%S'
}

_applog() {
	printf '%s\n' "$(_datetime) $(echo "${@}")" >> "/var/log/${NAME}"
}

_log() {
	logger -t "${NAME}" "${@}"
	_applog "syslog:" "${@}"
}

_msg() {
	msg="$(echo "${@}")"
}

WaitSubprocess() {
	local timeout="${1:-}" continue_on_signal="${2:-}" pid="${3:-${!}}" \
		pidw rc=""
	if [ -n "${timeout}" ]; then
		( sleep "${timeout}" && \
		kill -TERM "${pid}" > /dev/null 2>&1 ) &
		pidw=${!}
	fi
	while wait "${pid}" && rc=0 || rc=${rc:-${?}}; do
		if ! kill -0 "${pid}" > /dev/null 2>&1; then
			[ -z "${timeout}" ] || \
				kill -TERM "${pidw}" > /dev/null 2>&1 || :
			return ${rc}
		fi
		[ -n "${continue_on_signal}" ] && \
			rc="" || \
			kill -TERM "${pid}" > /dev/null 2>&1 || :
	done
}

_sleep() {
	if [ -n "${StatMsgs}" ]; then
		wait || :
		ListStat &
		[ ${Status} -le ${CONNECTING} ] || \
			StatMsgs=""
	fi
	if [ -z "${NoSleep}" ]; then
		local e i
		[ ${Status} -eq ${DISABLED} ] && \
		e="$(set | \
		sed -nre "\|^net[[:digit:]]+_blacklistexp='([[:digit:]]+)'| s||\1|p" | \
		sort -n | head -qn 1)" && \
		[ -n "${e}" ] && \
		[ $((i=${e}+1-$(date --utc +'%s'))) -le ${Interval} ] || \
			i=${Interval}
		if [ ${i} -gt 0 ]; then
			[ -z "${Debug}" ] || \
				_applog "sleeping ${i} seconds"
			sleep ${i} > /dev/null 2>&1 &
			if ! WaitSubprocess; then
				WwanErr=${NONE}
				ScanRequest=${HotSpots}
			fi
			[ -z "${Debug}" ] || \
				_applog "sleeping ended"
		fi
	fi
	NoSleep=""
	wait || :
}

AddStatMsg() {
	StatMsgs="${StatMsgs:+"${StatMsgs}${LF}"}$(_datetime) $(echo "${@}")"
}

HotspotBlackList() {
	local cause="${1}" expires="${2}" reason="${3}"
	eval net${HotSpot}_blacklisted=\"${cause} $(_datetime)\" || :
	if [ ${expires} -eq ${NONE} ]; then
		msg="Blacklisting ${HotSpot}:'${WwanSsid}'"
		_log "${msg}"
		AddStatMsg "${msg}"
	else
		eval net${HotSpot}_blacklistexp=\"$((${expires}+$(date --utc +'%s')))\" || :
		msg="Blacklisting ${HotSpot}:'${WwanSsid}' for ${expires} seconds"
		_log "${msg}"
		AddStatMsg "${msg}"
	fi
	_log "Reason:" "${reason}"
	HotSpot=${NONE}
}

BlackListExpired() {
	local d="" exp hotspot ssid
	while read -r exp hotspot; do
		[ -n "${exp}" ] && \
		[ ${d:="$(date --utc +'%s')"} -ge ${exp} ] || \
			break
		unset net${hotspot}_blacklisted net${hotspot}_blacklistexp || :
		eval ssid=\"\${net${hotspot}_ssid:-}\"
		msg="Blacklisting has expired for ${hotspot}:'${ssid}'"
		_log "${msg}"
		AddStatMsg "${msg}"
	done << EOF
$(set | \
sed -nre "\|^net([[:digit:]]+)_blacklistexp='([[:digit:]]+)'| s||\2 \1|p" | \
sort -n)
EOF
}

IsWifiActive() {
	local ssid="${1}" iface="${2:-"${WIface}"}" ssid1
	ssid1="$(iwinfo "${iface}" info 2> /dev/null | \
	sed -nre '\|^'"${iface}"'[[:blank:]]+ESSID: (.+)$| s||\1|p')" && \
	[ "${ssid1}" = "${ssid}" ]
}

WatchWifi() {
	local c="${1:-10}" iface ApSsid ApDisabled
	if [ -z "${WIfaceAP}" ]; then
		sleep ${c} &
		WaitSubprocess || :
		return 0
	fi
	[ "$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].disabled)" = 1 ] && \
		iface="${WIface}" || \
		iface="${WIface}-1"
	ApSsid="$(uci -q get wireless.@wifi-iface[${WIfaceAP}].ssid)" || :
	ApDisabled="$(uci -q get wireless.@wifi-iface[${WIfaceAP}].disabled)" || :
	while [ $((c--)) -gt 0 ]; do
		sleep 1
		[ "${ApDisabled}" != 1 ] || \
			break
		! IsWifiActive "\"${ApSsid}\"" "${iface}" || \
			break
	done
}

_exit() {
	trap - EXIT HUP USR1 USR2
	_log "Exiting"
	echo "${NAME} daemon exit ..." >> "/var/log/${NAME}.stat"
	kill 0 || :
	wait || :
}

ListStat() {
	exec > "/var/log/${NAME}.stat"
	echo "${NAME} status:"
	echo "${StatMsgs}"
	echo
	echo "STA network interface is ${WIface}"
	echo "Detected STA config in wifi-iface ${WIfaceSTA}"
	[ -n "${WIfaceAP}" ] && \
		echo "Detected AP config in wifi-iface ${WIfaceAP}" || \
		echo "Non standard AP+STA configuration"
	echo
	echo "Debug=\"${Debug}\""
	echo "ScanAuto=\"${ScanAuto}\""
	echo "Sleep=${Sleep}"
	echo "SleepDsc=${SleepDsc}"
	echo "SleepScanAuto=${SleepScanAuto}"
	echo "BlackList=${BlackList}"
	echo "BlackListExpires=${BlackListExpires}"
	echo "BlackListNetwork=${BlackListNetwork}"
	echo "BlackListNetworkExpires=${BlackListNetworkExpires}"
	echo "PingWait=${PingWait}"
	echo "LogRotate=${LogRotate}"
	echo
	local i=0
	while [ $((i++)) -lt ${HotSpots} ]; do
		set | grep -se "^net${i}_" | sort -r
		echo
	done
	[ "$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].disabled)" != 1 ] || \
		echo "Hotspot client is not enabled${LF}"
	iwinfo
	IsWanConnected && \
		echo "WAN interface is connected" || \
		echo "WAN interface is disconnected"
	echo
	ip route show
}

ListStatus() {
	AddStatMsg "Updating status report"
	NoSleep="y"
}

BackupRotate() {
	local f="${1}" r=${LogRotate}
	[ -f "${f}" ] && \
		mv -f "${f}" "${f}_$(date --utc +'%s')" || \
		r=${NONE}
	printf '%s\n' "${f}_"* | \
	head -qn -${r} | \
	while IFS= read -r f; do
		rm -f "${f}"
	done
}

AddHotspot() {
	if [ -n "${net_ssid:-}" -a -n "${net_encrypt:-}" ]; then
		Ssids="${Ssids:+"${Ssids}${LF}"}${net_ssid}"
		[ $((HotSpots++)) ]
		eval net${HotSpots}_ssid=\"${net_ssid}\"
		eval net${HotSpots}_encrypt=\"${net_encrypt}\"
		[ -z "${net_key:-}" ] || \
			eval net${HotSpots}_key=\"${net_key}\"
		[ -z "${net_hidden:-}" ] || \
			eval net${HotSpots}_hidden=\"${net_hidden}\"
		[ -z "${net_blacklisted:-}" ] || \
			eval net${HotSpots}_blacklisted=\"${net_blacklisted}\"
		[ -z "${net_check:-}" ] || \
			eval net${HotSpots}_check=\"${net_check}\"
		if [ -n "${Debug}" ]; then
			msg="Adding new hotspot ${HotSpots}:'${net_ssid}'"
			_applog "${msg}"
			AddStatMsg "${msg}"
		fi
	else
		_applog "Error: AddHotspot, No ssid or encrypt specified"
	fi
	unset net_ssid net_encrypt net_key net_hidden net_blacklisted net_check
}

LoadConfig() {
	msg="Loading configuration"
	_log "${msg}"
	AddStatMsg "${msg}"

	# config variables, default values
	Debug=""
	ScanAuto="y"
	Sleep=20
	SleepDsc="$((${Sleep}*3))"
	SleepScanAuto="$((${Sleep}*15))"
	BlackList=3
	BlackListExpires=${NONE}
	BlackListNetwork=3
	BlackListNetworkExpires=$((10*60))
	PingWait=7
	LogRotate=3
	unset $(set | awk -F '=' \
		'$1 ~ "^net[[:digit:]]*_" {print $1}') 2> /dev/null || :

	Ssids=""
	HotSpots=${NONE}
	[ ! -s "/etc/config/${NAME}" ] || \
		. "/etc/config/${NAME}"

	Debug="${Debug:-}"
	ScanAuto="${ScanAuto:-}"
	Sleep="$(_integer_value "${Sleep}" 20)"
	SleepDsc="$(_integer_value "${SleepDsc}" $((${Sleep}*3)) )"
	SleepScanAuto="$(_integer_value "${SleepScanAuto}" $((${Sleep}*15)) )"
	BlackList="$(_integer_value "${BlackList}" 3)"
	BlackListExpires="$(_integer_value "${BlackListExpires}" ${NONE})"
	BlackListNetwork="$(_integer_value "${BlackListNetwork}" 3)"
	BlackListNetworkExpires="$(_integer_value "${BlackListNetworkExpires}" $((10*60)))"
	PingWait="$(_integer_value "${PingWait}" 7)"
	LogRotate="$(_integer_value "${LogRotate}" 3)"

	BackupRotate "/var/log/${NAME}"
	BackupRotate "/var/log/${NAME}.xtrace"

	if [ "${Debug}" = "xtrace" ]; then
		exec >> "/var/log/${NAME}.xtrace" 2>&1
		set -o xtrace
	else
		set +o xtrace
		exec >> "/var/log/${NAME}" 2>&1
	fi

	IfaceWan="$(uci -q get network.wan.ifname)" || :
	local i=-1 j m d
	WIfaceAP=""
	WIfaceSTA=""
	while [ -z "${WIfaceAP}" ]; do
		while [ $((i++)) ]; do
			if ! m="$(uci -q get wireless.@wifi-iface[${i}].mode)"; then
				[ -z "${WIfaceSTA}" ] || \
					break 2
				_log "Invalid AP+STA configuration. Exiting"
				exit 1
			fi
			if [ "${m}" = "sta" ]; then
				WIfaceSTA=${i}
				d="$(uci -q get wireless.@wifi-iface[${i}].device)"
				WIface="wlan$(iwinfo "${d}" info | \
					sed -nre '/.*PHY name: phy([[:digit:]]+)$/ s//\1/p')"
				break
			fi
		done
		j=-1
		while [ $((j++)) ] && \
		m="$(uci -q get wireless.@wifi-iface[${j}].mode)"; do
			if [ "${m}" = "ap" ] && \
			[ "$(uci -q get wireless.@wifi-iface[${j}].device)" = "${d}" ]; then
				WIfaceAP=${j}
				break
			fi
		done
	done
	_applog "STA network interface is ${WIface}"
	_applog "Detected STA config in wifi-iface ${WIfaceSTA}"
	[ -n "${WIfaceAP}" ] && \
		_applog "Detected AP config in wifi-iface ${WIfaceAP}" || \
		_applog "Non standard AP+STA configuration"

	if [ ${HotSpots} -eq ${NONE} ]; then
		local n=0 ssid
		while [ $((n++)) ]; do
			eval ssid=\"\${net${n}_ssid:-}\" && \
			[ -n "${ssid}" ] || \
				break
			Ssids="${Ssids:+"${Ssids}${LF}"}${ssid}"
			HotSpots=${n}
		done
	fi
	if [ ${HotSpots} -eq ${NONE} ]; then
		WwanSsid="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].ssid)" || :
		if [ -z "${WwanSsid}" ]; then
			_log "Invalid configuration. No hotspots specified. Exiting"
			exit 1
		fi
		Ssids="${WwanSsid}"
		net1_ssid="${WwanSsid}"
		HotSpots=1
	fi
	if [ -n "$(echo "${Ssids}" | sort | uniq -d)" ]; then
		_log "Invalid configuration. Duplicate hotspots SSIDs. Exiting"
		exit 1
	fi

	TryConnection=0
	WwanErr=${NONE}
	ScanRequest=${HotSpots}
	HotSpot=${NONE}
	ConnAttempts=1
	Status=${NONE}
	AddStatMsg "Configuration reloaded"
	NoSleep="y"
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
		! err="$(iw "${WIface}" scan 3>&2 2>&1 1>&3 3>&-)" 2>&1 || \
			return 0
		[ -z "${Debug}" ] || \
			_applog "${err}"
		[ ${i} -le 2 ] && \
		echo "${err}" | grep -qsF 'command failed: Network is down' || \
			continue
		_log "Error: Can't scan wifi, restarting the network"
		/etc/init.d/network restart
		sleep 20 &
		WaitSubprocess || :
		WatchWifi 20
	done
	_log "Serious error: Can't scan wifi for access points"
	return 1
}

ActiveSsidNbr() {
	echo "${Ssids}" | \
	awk -v ssid="${WwanSsid}" \
		'$0 == ssid {n = NR; exit}
		END{print n+0; exit (n+0 == 0)}'
}

CheckConn() {
	[ "${Debug}" = "xtrace" ] || \
		exec > /dev/null 2>&1
	if [ -n "${CheckSrvr}" ]; then
		local s w
		if w="$(which wget)" && \
		s="$(ifconfig "${WIface}" | \
		awk '$1 == "inet" {print $2; rc=-1; exit}
		END{exit rc+1}')"; then
			"${w}" --spider -T ${PingWait} --no-check-certificate \
			--bind-address "${s##"addr:"}" "${CheckAddr}" 2>&1 | \
			grep -qsF "Remote file exists"
		else
			local p
			[ "${CheckAddr:0:8}" = "https://" ] && \
				p=443 || \
				p=80
			echo "GET ${CheckAddr} HTTP/1.0${LF}${LF}" | \
				nc "${CheckSrvr}" ${p}
		fi
	else
		ping -4 -W ${PingWait} -c 3 -I "${WIface}" "${CheckAddr}"
	fi
}

CheckConnectivity() {
	local check
	Interval=${SleepScanAuto}
	eval check=\"\${net${HotSpot}_check:-}\" && \
	[ -n "${check}" ] || \
		return 0
	local delay=20
	while [ -z "${Gateway:="$(ip -4 route show default dev "${WIface}" | \
	awk '$1 == "default" {print $3; exit}')"}" ] && \
	[ $((delay--)) -gt 0 ]; do
		sleep 1
	done
	Interval=${Sleep}
	[ -n "${CheckAddr}" ] || \
		if CheckSrvr="$(echo "${check}" | \
		sed -nre '\|^http[s]?://([^/]+).*| s||\1|p')" && \
		[ -n "${CheckSrvr}" ]; then
			CheckAddr="${check}"
		else
			CheckAddr="$(echo "${check}" | \
			sed -nre '\|^([[:digit:]]+[.]){3}[[:digit:]]+$|p')"
			[ -n "${CheckAddr:="${Gateway}"}" ] || \
			_log "Serious Error: There is no default route" \
				"for interface ${WIface}"
		fi
	local rc=0
	CheckConn &
	WaitSubprocess ${PingWait} || rc=${?}
	if [ ${rc} -eq 0 ]; then
		_msg "Connectivity of ${HotSpot}:'${WwanSsid}'" \
			"to ${CheckAddr} has been verified"
		if [ ${Status} -eq ${CONNECTED} -a ${NetworkAttempts} -eq 1 ]; then
			[ -z "${Debug}" ] || \
				_applog "${msg}"
		else
			NetworkAttempts=1
			_log "${msg}"
			[ -z "${StatMsgs}" ] || \
				AddStatMsg "${msg}"
		fi
		return 0
	fi
	[ ${rc} -le 127 -o ${rc} -eq 143 ] || \
		return 0
	_msg "${NetworkAttempts} connectivity failures" \
		"on ${HotSpot}:'${WwanSsid}'"
	_log "Warning:" "${msg}"
	if [ ${BlackListNetwork} -ne ${NONE} ] && \
	[ ${NetworkAttempts} -ge ${BlackListNetwork} ]; then
		WwanDisable
		HotspotBlackList "network" "${BlackListNetworkExpires}" "${msg}"
		Status=${DISABLING}
		ScanRequest=1
		return 1
	fi
	[ $((NetworkAttempts++)) ]
}

DoScan() {
	local ssid blacklisted hidden scanned found_hidden n i blacklistexp

	if ! MustScan; then
		[ -z "${Debug}" ] || \
			_applog "Must not scan"
		return 1
	fi

	[ -z "${Debug}" ] || \
		_applog "DoScan - Scanning"

	scanned="$(Scanning | \
	sed -nre '\|^[[:blank:]]+(SSID: .*)$| s||\1|p')" && \
	[ -n "${scanned}" ] || \
		return 1
	found_hidden="$(echo "${scanned}" | grep -sx -m 1 -F 'SSID: ')" || :

	n="$(ActiveSsidNbr)" || :
	[ $((n++)) -lt ${HotSpots} ] || \
		n=1

	i=${n}
	while :; do
		eval ssid=\"\${net${i}_ssid:-}\" && \
		[ -n "${ssid}" ] || \
			break

		eval hidden=\"\${net${i}_hidden:-}\" || :
		if [ "${hidden}" = "y" -a -n "${found_hidden}" ] || \
		( [ -n "${hidden}" -a "${hidden}" != "y" ] && \
			echo "${scanned}" | grep -qsxF "SSID: ${hidden}" ) || \
		echo "${scanned}" | grep -qsxF "SSID: ${ssid}"; then
			eval blacklisted=\"\${net${i}_blacklisted:-}\" || :
			if [ -z "${blacklisted}" ]; then
				echo "${i}"
				return 0
			fi
			_applog "Not selecting blacklisted hotspot ${i}:'${ssid}'"
		fi
		[ $((i++)) -lt ${HotSpots} ] || \
			i=1
		[ ${i} -ne ${n} ] || \
			break
	done
	[ -z "${Debug}" ] || \
		_applog "DoScan: No Hotspots available"
	return 1
}

WwanDisable() {
	_log "Disabling wireless device for ${HotSpot}:'${WwanSsid}'"
	uci set wireless.@wifi-iface[${WIfaceSTA}].disabled=1
	uci commit wireless
	wifi down
	wifi up
	WwanDisabled=1
	NoSleep="y"
	WatchWifi &
}

WifiStatus() {
	# constants
	readonly LF=$'\n' \
		NONE=0 DISABLING=1 CONNECTING=2 DISABLED=3 CONNECTED=4
	# internal variables, daemon scope
	local Ssids HotSpots n msg IfaceWan WwanSsid WwanDisabled \
		ScanRequest WwanErr Status=${NONE} StatMsgs="" Interval NoSleep \
		HotSpot=${NONE} ConnAttempts=1 NetworkAttempts \
		PidDaemon="${$}" \
		Gateway CheckAddr CheckSrvr \
		TryConnection=0 WIface WIfaceAP WIfaceSTA

	trap '_exit' EXIT

	LoadConfig || exit 1
	Interval=${Sleep}

	trap 'LoadConfig' HUP
	trap 'NoSleep="y"' USR1
	trap 'ListStatus' USR2

	while _sleep; do
		BlackListExpired
		WwanDisabled="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].disabled)" || :
		WwanSsid="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].ssid)" || :
		if IsWwanConnected; then
			TryConnection=0
			WwanErr=${NONE}
			if [ ${Status} -ne ${CONNECTED} ]; then
				if [ ${HotSpot} -eq ${NONE} ]; then
					HotSpot="$(ActiveSsidNbr)" || \
						_log "Warning: Connected to a non-configured" \
							"hotspot '${WwanSsid}'"
				fi
				msg="Connected to ${HotSpot}:'${WwanSsid}'"
				_log "${msg}"
				AddStatMsg "${msg}"
				NetworkAttempts=1
				Gateway=""
				CheckAddr=""
				if CheckConnectivity; then
					Status=${CONNECTED}
					ScanRequest=0
				fi
			else
				msg="Already connected to ${HotSpot}:'${WwanSsid}'"
				[ -z "${Debug}" ] || \
					_applog "${msg}"
				[ -z "${StatMsgs}" ] || \
					AddStatMsg "${msg}"
				CheckConnectivity || :
			fi
			continue
		fi
		if [ ${TryConnection} -gt 0 ]; then
			[ $((TryConnection--)) ]
			continue
		fi
		if IsWwanConnected "unknown"; then
			WwanDisable
			if [ ${Status} -eq ${CONNECTED} ]; then
				msg="Lost connection ${HotSpot}:'${WwanSsid}'"
				_log "Reason:" "${msg}"
				AddStatMsg "${msg}"
				HotSpot=${NONE}
			else
				if [ ${Status} -eq ${DISABLING} ]; then
					msg="Disabling wireless STA device, Again ?"
					[ -z "${Debug}" ] || \
						_applog "${msg}"
					[ -z "${StatMsgs}" ] || \
						AddStatMsg "${msg}"
				fi
				if [ ${HotSpot} -ne ${NONE} ]; then
					_msg "${ConnAttempts} unsuccessful connection" \
						"to ${HotSpot}:'${WwanSsid}'"
					AddStatMsg "${msg}"
					if [ ${BlackList} -ne ${NONE} ] && \
					[ ${ConnAttempts} -ge ${BlackList} ]; then
						HotspotBlackList "connect" "${BlackListExpires}" \
							"${msg}"
					else
						_log "Reason:" "${msg}"
						[ $((ConnAttempts++)) ]
					fi
				fi
			fi
			Status=${DISABLING}
			ScanRequest=1
			Interval=${Sleep}
			continue
		fi
		if n="$(DoScan)"; then
			local ssid
			eval ssid=\"\${net${n}_ssid:-}\" || :
			[ -z "${Debug}" ] || \
				_applog "DoScan selected ${n}:'${ssid}'"
			if [ ${HotSpot} -ne ${n} ]; then
				HotSpot=${n}
				ConnAttempts=1
			fi
			if [ "${ssid}" != "${WwanSsid}" ]; then
				_log "Hotspot '${ssid}' found. Applying settings..."
				WwanSsid="${ssid}"
				WwanErr=${NONE}
				local encrypt key
				eval encrypt=\"\${net${n}_encrypt:-}\" || :
				eval key=\"\${net${n}_key:-}\" || :
				uci set wireless.@wifi-iface[${WIfaceSTA}].ssid="${ssid}"
				uci set wireless.@wifi-iface[${WIfaceSTA}].encryption="${encrypt}"
				uci set wireless.@wifi-iface[${WIfaceSTA}].key="${key}"
				[ "${WwanDisabled}" != 1 ] || \
					uci set wireless.@wifi-iface[${WIfaceSTA}].disabled=0
				uci commit wireless
				sleep 1
				/etc/init.d/network restart
				TryConnection=2
				msg="Connecting to ${HotSpot}:'${WwanSsid}'..."
				_log "${msg}"
				AddStatMsg "${msg}"
				WatchWifi 20 &
			elif [ "${WwanDisabled}" = 1 ]; then
				uci set wireless.@wifi-iface[${WIfaceSTA}].disabled=0
				uci commit wireless
				wifi down
				wifi up
				TryConnection=2
				_msg "Enabling client interface to" \
					"${HotSpot}:'${WwanSsid}'..."
				_log "${msg}"
				AddStatMsg "${msg}"
				WatchWifi &
			else
				_msg "Client interface to" \
					"${HotSpot}:'${WwanSsid}' is already enabled"
				_applog "${msg}"
				[ -z "${StatMsgs}" ] || \
					AddStatMsg "${msg}"
			fi
			Status=${CONNECTING}
			if [ $((WwanErr++)) -gt ${HotSpots} ]; then
				Interval=${SleepScanAuto}
				ScanRequest=0
				_msg "Error: can't connect to any hotspot," \
					"probably configuration is not correct"
				_log "${msg}"
				AddStatMsg "${msg}"
			else
				Interval=${Sleep}
			fi
			[ ${ScanRequest} -le 0 ] || \
				[ $((ScanRequest--)) ]
			continue
		fi
		WwanErr=${NONE}
		msg="A hotspot is not available"
		if [ ${Status} -ne ${DISABLED} ]; then
			_log "${msg}"
			AddStatMsg "${msg}"
			Status=${DISABLED}
		else
			[ -z "${StatMsgs}" ] || \
				AddStatMsg "${msg}"
		fi
		if [ "${WwanDisabled}" != 1 ]; then
			Interval=${Sleep}
		elif [ -n "${ScanAuto}" ] && \
		! IsWanConnected; then
			Interval=${SleepDsc}
		else
			Interval=${SleepScanAuto}
		fi
		[ ${ScanRequest} -le 0 ] || \
			[ $((ScanRequest--)) ]
	done
}

set -o errexit -o nounset -o pipefail
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
