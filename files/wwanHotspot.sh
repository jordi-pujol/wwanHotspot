#!/bin/sh

#  wwanHotspot
#
#  Wireless WAN Hotspot management application for OpenWrt routers.
#  $Revision: 1.33 $
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

_UTCseconds() {
	date --utc +'%s'
}

_datetime() {
	date +'%Y-%m-%d %H:%M:%S'
}

_ps_children() {
	local ppid=${1:-${$}} excl="${2:-"0"}" pid
	for pid in $(pgrep -P ${ppid} | grep -svwF "${excl}"); do
		_ps_children ${pid} "${excl}"
		echo ${pid}
	done
}

_exit() {
	trap - EXIT INT HUP ALRM USR1 USR2
	LogPrio="warn" _log "Exiting"
	echo $'\n'"$(_datetime) ${NAME} daemon exit ..." >> "/var/log/${NAME}.stat"
	kill -s TERM $(_ps_children) > /dev/null 2>&1 || :
	wait || :
}

_applog() {
	local msg="${@}"
	printf '%s\n' "$(_datetime) ${msg}" >> "/var/log/${NAME}"
}

_log() {
	local msg="${@}" \
		p="daemon.${LogPrio:-"notice"}"
	LogPrio=""
	logger -t "${NAME}" -p "${p}" "${msg}"
	_applog "${p}:" "${msg}"
}

_msg() {
	msg="${@}"
}

_pids_active() {
	local p rc=1
	for p in "${@}"; do
		if kill -s 0 ${p} > /dev/null 2>&1; then
			echo ${p}
			rc=0
		fi
	done
	return ${rc}
}

WaitSubprocess() {
	local timeout="${1:-}" dont_interrupt="${2:-}" pids="${3:-${!}}" \
		pidw rc=""
	[ -n "${pids}" ] || \
		return 255
	if [ -n "${timeout}" ]; then
		( sleep "${timeout}" && kill -s TERM ${pids} > /dev/null 2>&1 ) &
		pidw=${!}
	fi
	while wait ${pids} && rc=0 || rc=${rc:-${?}};
	pids="$(_pids_active ${pids})"; do
		[ -n "${dont_interrupt}" ] && \
			rc="" || \
			kill -s TERM ${pids} > /dev/null 2>&1 || :
	done
	if [ -n "${timeout}" ]; then
		kill -s TERM ${pidw} > /dev/null 2>&1 || :
		wait ${pidw} || :
	fi
	return ${rc}
}

Settle() {
	local pidSleep=""
	if [ -z "${NoSleep}" ]; then
		local e="" i
		[ ${Status} -eq ${DISABLED} ] && \
		[ -n "${e:="$(set | \
		sed -nre "\|^net[[:digit:]]+_blacklistexp='([[:digit:]]+)'| s||\1|p" | \
		sort -n | head -qn 1)"}" ] && \
		[ $((i=${e}+1-$(_UTCseconds))) -le ${Interval} ] || \
			i=${Interval}
		if [ ${i} -gt 0 ]; then
			[ -z "${Debug}" ] || \
				_applog "sleeping ${i} seconds"
			sleep ${i} &
			pidSleep=${!}
		fi
	fi
	local pids="$(_ps_children "" "${pidSleep}")"
	[ -z "${pids}" ] || \
		WaitSubprocess ${Sleep} "y" "${pids}" || :
	if [ -n "${StatMsgs}" ]; then
		Report &
		[ ${Status} -le ${CONNECTING} ] || \
			StatMsgs=""
		WaitSubprocess "" "y" || :
	fi
	if [ -n "${pidSleep}" ]; then
		if ! WaitSubprocess "" "" "${pidSleep}"; then
			WwanErr=${NONE}
			ScanRequest=${HotSpots}
		fi
		[ -z "${Debug}" ] || \
			_applog "sleeping ended"
	fi
	NoSleep=""
}

AddStatMsg() {
	local msg="${@}"
	StatMsgs="${StatMsgs:+"${StatMsgs}${LF}"}$(_datetime) ${msg}"
}

HotspotBlackList() {
	local cause="${1}" expires="${2}" reason="${3}"
	eval net${HotSpot}_blacklisted=\"${cause} $(_datetime)\" || :
	msg="Blacklisting ${HotSpot}:'${WwanSsid}'"
	if [ ${expires} -gt ${NONE} ]; then
		eval net${HotSpot}_blacklistexp=\"$((${expires}+$(_UTCseconds)))\" || :
		msg="${msg} for ${expires} seconds"
	fi
	LogPrio="warn" _log "${msg}"
	AddStatMsg "${msg}"
	LogPrio="info" _log "Reason:" "${reason}"
	HotSpot=${NONE}
}

BlackListExpired() {
	local d="" exp hotspot
	while read -r exp hotspot && \
	[ -n "${exp}" ] && \
	[ ${d:="$(_UTCseconds)"} -ge ${exp} ]; do
		unset net${hotspot}_blacklisted \
			net${hotspot}_blacklistexp || :
		_msg "Blacklisting has expired for" \
			"${hotspot}:'$(eval echo \"\${net${hotspot}_ssid:-}\")'"
		LogPrio="info" _log "${msg}"
		AddStatMsg "${msg}"
	done << EOF
$(set | \
sed -nre "\|^net([[:digit:]]+)_blacklistexp='([[:digit:]]+)'| s||\2 \1|p" | \
sort -n)
EOF
}

IsWifiActive() {
	local ssid="${1:-"\"${WwanSsid}\""}" ssid1
	ssid1="$(iwinfo "${WIface}" info 2> /dev/null | \
	sed -nre '\|^'"${WIface}"'[[:blank:]]+ESSID: (.+)$| s||\1|p')" && \
	[ "${ssid1}" = "${ssid}" ]
}

WatchWifi() {
	local c="${1:-10}" ssid=""
	[ "$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].disabled)" != 1 ] || \
		if [ -z "${WIfaceAP}" ] || \
		[ "$(uci -q get wireless.@wifi-iface[${WIfaceAP}].disabled)" = 1 ] || \
		! ssid="\"$(uci -q get wireless.@wifi-iface[${WIfaceAP}].ssid)\""; then
			sleep ${c}
			return 0
		fi
	while ! IsWifiActive "${ssid}" && \
	[ $((c--)) -gt 0 ]; do
		sleep 1
	done
}

Report() {
	[ -z "${Debug}" ] || \
		_applog "Writing status report"
	exec > "/var/log/${NAME}.stat"
	echo "${NAME} status report."
	echo
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
	echo "Sleep=${Sleep} seconds"
	echo "SleepDsc=${SleepDsc} seconds"
	echo "SleepScanAuto=${SleepScanAuto} seconds"
	echo "BlackList=${BlackList}"
	echo "BlackListExpires=${BlackListExpires} seconds"
	echo "BlackListNetwork=${BlackListNetwork}"
	echo "BlackListNetworkExpires=${BlackListNetworkExpires} seconds"
	echo "PingWait=${PingWait} seconds"
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
	[ -z "${Debug}" ] || \
		_applog "End of status report"
}

ListStatus() {
	AddStatMsg "Updating status report"
	NoSleep="y"
}

NetworkChange() {
	[ ${Status} -le ${CONNECTING} ] || \
		AddStatMsg "Network status has changed"
	NoSleep="y"
}

BackupRotate() {
	local f="${1}" n=${LogRotate}
	[ -f "${f}" ] && \
		mv -f "${f}" "${f}_$(_UTCseconds)" || \
		n=${NONE}
	printf '%s\n' "${f}_"* | \
	head -qn -${n} | \
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
	LogPrio="info" _log "${msg}"
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
	while [ $((i++)) ];
	m="$(uci -q get wireless.@wifi-iface[${i}].mode)"; do
		[ "${m}" = "sta" ] || \
			continue
		LogPrio="info" _log "Found STA config in wifi-iface ${i}"
		WIfaceSTA=${i}
		d="$(uci -q get wireless.@wifi-iface[${i}].device)"
		WIface="wlan$(iwinfo "${d}" info | \
			sed -nre '/.*PHY name: phy([[:digit:]]+)$/ s//\1/p')"
		j=-1
		while [ $((j++)) ];
		m="$(uci -q get wireless.@wifi-iface[${j}].mode)"; do
			if [ "${m}" = "ap" ] && \
			[ "$(uci -q get wireless.@wifi-iface[${j}].device)" = "${d}" ]; then
				LogPrio="info" _log "Found AP config in wifi-iface ${j}"
				WIfaceAP=${j}
				break 2
			fi
		done
	done
	if [ -z "${WIfaceSTA}" ]; then
		LogPrio="err" _log "Invalid AP+STA configuration. Exiting"
		exit 1
	fi
	_applog "STA network interface is ${WIface}"
	_applog "Detected STA config in wifi-iface ${WIfaceSTA}"
	[ -n "${WIfaceAP}" ] && \
		_applog "Detected AP config in wifi-iface ${WIfaceAP}" || \
		_applog "Non standard AP+STA configuration"

	if [ ${HotSpots} -eq ${NONE} ]; then
		local n=0 ssid
		while [ $((n++)) ];
		eval ssid=\"\${net${n}_ssid:-}\" && \
		[ -n "${ssid}" ] && \
		[ -n "$(eval echo \"\${net${n}_encrypt:-}\")" ]; do
			Ssids="${Ssids:+"${Ssids}${LF}"}${ssid}"
			HotSpots=${n}
		done
	fi
	if [ ${HotSpots} -eq ${NONE} ]; then
		WwanSsid="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].ssid)" || :
		if [ -z "${WwanSsid}" ]; then
			LogPrio="err"
			_log "Invalid configuration. No hotspots specified. Exiting"
			exit 1
		fi
		Ssids="${WwanSsid}"
		net1_ssid="${WwanSsid}"
		HotSpots=1
	fi
	if [ -n "$(echo "${Ssids}" | sort | uniq -d)" ]; then
		LogPrio="err"
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
	local ssid="${1:-}"
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
		LogPrio="err"
		_log "Can't scan wifi, restarting the network"
		/etc/init.d/network restart
		sleep 20 &
		WaitSubprocess || :
		WatchWifi 20
	done
	LogPrio="err"
	_log "Serious error: Can't scan wifi for access points"
	return 1
}

CurrentHotSpot() {
	[ ${HotSpot} -ne ${NONE} ] || \
		HotSpot="$(echo "${Ssids}" | \
			awk -v ssid="${WwanSsid}" \
			'$0 == ssid {n = NR; exit}
			END{print n+0; exit (n+0 == 0)}')"
}

CheckConn() {
	[ "${Debug}" = "xtrace" ] || \
		exec > /dev/null 2>&1
	if [ -n "${CheckSrvr}" ]; then
		if [ -n "${CheckInet}" ]; then
			wget --spider -T ${PingWait} --no-check-certificate \
			--bind-address "${CheckInet##"addr:"}" "${CheckAddr}" 2>&1 | \
			grep -qsF "Remote file exists"
		else
			echo "GET ${CheckAddr} HTTP/1.0${LF}${LF}" | \
				nc "${CheckSrvr}" ${CheckPort}
		fi
	else
		ping -4 -W ${PingWait} -c 3 -I "${WIface}" "${CheckAddr}"
	fi
}

CheckConnectivity() {
	local check="$(eval echo \"\${net${HotSpot}_check:-}\")"
	Interval=${SleepScanAuto}
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
			if [ -z "$(which wget)" ] ||  \
			! CheckInet="$(ifconfig "${WIface}" | \
			awk '$1 == "inet" {print $2; rc=-1; exit}
			END{exit rc+1}')"; then
				[ "${CheckAddr:0:8}" = "https://" ] && \
					CheckPort=443 || \
					CheckPort=80
				if [ $(ip -4 route show default | \
				awk '$1 == "default" && $NF != "linkdown" {c++}
				END{print c+0}') -gt 1 ]; then
					_msg "Using the nc utility to check URL connectivity" \
						"while multiple default routes are enabled"
					LogPrio="err" _log "${msg}"
					AddStatMsg "Error:" "${msg}"
				fi
			fi
		else
			CheckAddr="$(echo "${check}" | \
			sed -nre '\|^([[:digit:]]+[.]){3}[[:digit:]]+$|p')"
			[ -n "${CheckAddr:="${Gateway}"}" ] || \
				LogPrio="err" \
				_log "Serious Error: There is no default route" \
					"for interface ${WIface}"
		fi
	local rc=0
	CheckConn &
	WaitSubprocess ${PingWait} || rc=${?}
	if [ ${rc} -eq 0 ]; then
		_msg "Connectivity of ${HotSpot}:'${WwanSsid}' to" \
			"$(test "${CheckAddr}" != "${Gateway}" || \
			echo "gateway:")${CheckAddr}" \
			"has been verified"
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
	LogPrio="warn" _log "${msg}"
	if [ ${BlackListNetwork} -ne ${NONE} ] && \
	[ ${NetworkAttempts} -ge ${BlackListNetwork} ]; then
		WwanDisable
		HotspotBlackList "network" "${BlackListNetworkExpires}" "${msg}"
		Status=${DISABLING}
		ScanRequest=1
		return 1
	fi
	NoSleep=""
	[ $((NetworkAttempts++)) ]
}

DoScan() {
	if ! MustScan; then
		[ -z "${Debug}" ] || \
			_applog "Must not scan"
		return 1
	fi

	[ -z "${Debug}" ] || \
		_applog "DoScan - Scanning"

	local hidden scanned found_hidden n i

	scanned="$(Scanning | \
	sed -nre '\|^[[:blank:]]+(SSID: .*)$| s||\1|p')" && \
	[ -n "${scanned}" ] || \
		return 1
	found_hidden="$(echo "${scanned}" | grep -sx -m 1 -F 'SSID: ')" || :

	CurrentHotSpot || :
	n=${HotSpot}
	[ $((n++)) -lt ${HotSpots} ] || \
		n=1

	i=${n}
	while :; do
		eval ssid=\"\${net${i}_ssid:-}\"
		hidden=""
		if echo "${scanned}" | grep -qsxF "SSID: ${ssid}" || \
		[ "${hidden:="$(eval echo \"\${net${i}_hidden:-}\")"}" = "y" -a \
		-n "${found_hidden}" ] || \
		( [ -n "${hidden}" -a "${hidden}" != "y" ] && \
		echo "${scanned}" | grep -qsxF "SSID: ${hidden}" ); then
			if [ -z "$(eval echo \"\${net${i}_blacklisted:-}\")" ]; then
				[ ${HotSpot} -ne ${i} ] && \
					ConnAttempts=1 && \
					HotSpot=${i} || :
				[ -z "${Debug}" ] || \
					_applog "DoScan selected ${HotSpot}:'${ssid}'"
				return 0
			fi
			[ ${Status} -eq ${DISABLED} -a -z "${Debug}" ] || \
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
	LogPrio="warn"
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
	local Ssids ssid HotSpots IfaceWan WwanSsid WwanDisabled \
		ScanRequest WwanErr Status=${NONE} StatMsgs="" Interval NoSleep \
		HotSpot=${NONE} ConnAttempts=1 NetworkAttempts \
		msg LogPrio="" \
		PidDaemon="${$}" \
		Gateway CheckAddr CheckSrvr CheckInet CheckPort \
		TryConnection=0 WIface WIfaceAP WIfaceSTA

	trap '_exit' EXIT
	trap 'exit' INT

	LoadConfig || exit 1
	Interval=${Sleep}

	trap 'LoadConfig' HUP
	trap 'NetworkChange' ALRM
	trap 'NoSleep="y"' USR1
	trap 'ListStatus' USR2

	while Settle; do
		WwanDisabled="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].disabled)" || :
		WwanSsid="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].ssid)" || :
		if IsWwanConnected; then
			TryConnection=0
			WwanErr=${NONE}
			if [ ${Status} -ne ${CONNECTED} ]; then
				CurrentHotSpot || \
					LogPrio="warn" \
					_log "Connected to a non-configured" \
						"hotspot '${WwanSsid}'"
				msg="Connected to ${HotSpot}:'${WwanSsid}'"
				_log "${msg}"
				AddStatMsg "${msg}"
				NetworkAttempts=1
				Gateway=""; CheckAddr=""; CheckInet=""
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
		[ ${TryConnection} -gt 0 ] && \
			[ $((TryConnection--)) ] && \
			continue || :
		if IsWwanConnected "unknown"; then
			CurrentHotSpot || :
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
						LogPrio="warn" _log "Reason:" "${msg}"
						[ $((ConnAttempts++)) ]
					fi
				fi
			fi
			Status=${DISABLING}
			ScanRequest=1
			Interval=${Sleep}
			continue
		fi
		BlackListExpired
		if DoScan; then
			if [ "${ssid}" != "${WwanSsid}" ]; then
				_log "Hotspot '${ssid}' found. Applying settings..."
				WwanSsid="${ssid}"
				WwanErr=${NONE}
				uci set wireless.@wifi-iface[${WIfaceSTA}].ssid="${ssid}"
				uci set wireless.@wifi-iface[${WIfaceSTA}].encryption="$(
					eval echo \"\${net${HotSpot}_encrypt:-}\")"
				uci set wireless.@wifi-iface[${WIfaceSTA}].key="$(
					eval echo \"\${net${HotSpot}_key:-}\")"
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
				NoSleep="y"
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
				NoSleep="y"
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
				_msg "Can't connect to any hotspot," \
					"probably configuration is not correct"
				LogPrio="err" _log "${msg}"
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

set -o errexit -o nounset -o pipefail +o noglob
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
