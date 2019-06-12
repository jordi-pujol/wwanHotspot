#!/bin/sh

#  wwanHotspot
#
#  Wireless WAN Hotspot management application for OpenWrt routers.
#  $Revision: 1.45 $
#
#  Copyright (C) 2017-2019 Jordi Pujol <jordipujolp AT gmail DOT com>
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
	printf '\n%s\n' "$(_datetime) ${NAME} daemon exit ..." >> "/var/log/${NAME}.stat"
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
		[ ${Status} -eq ${DISABLED} \
		-o \( -z "${WIfaceAP}" -a ${Status} -eq ${DISCONNECTED} \) ] && \
		[ -n "${e:="$(set | \
		sed -nre "\|^net[[:digit:]]+_blacklistexp='([[:digit:]]+)'| s||\1|p" | \
		sort -n | head -qn 1)"}" ] && \
		[ $((i=e+1-$(_UTCseconds))) -le ${Interval} ] || \
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
	if [ -n "${StatMsgsChgd}" ]; then
		StatMsgsChgd=""
		Report &
		WaitSubprocess "" "y" || :
	fi
	if [ -n "${pidSleep}" ]; then
		[ -z "${NoSleep}" ] || \
			kill -s TERM ${pidSleep} > /dev/null 2>&1 || :
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
	StatMsgsChgd="y"
}

GetRxBytes() {
	cat "/sys/class/net/${WIface}/statistics/rx_bytes"
}

HotspotBlackList() {
	local cause="${1}" expires="${2}" reason="${3}" msg
	eval net${HotSpot}_blacklisted=\"${cause} $(_datetime)\" || :
	msg="Blacklisting ${HotSpot}:'${WwanSsid}'"
	if [ ${expires} -gt ${NONE} ]; then
		eval net${HotSpot}_blacklistexp=\"$((expires+$(_UTCseconds)))\" || :
		msg="${msg} for ${expires} seconds"
	fi
	LogPrio="warn" _log "${msg}"
	AddStatMsg "${msg}"
	LogPrio="info" _log "Reason:" "${reason}"
	AddStatMsg "Reason:" "${reason}"
}

BlackListExpired() {
	local d="" exp hotspot msg
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
	iwinfo "${WIface}" info 2> /dev/null | \
	awk -v iface="${WIface}" \
	-v ssid="${1:-"\"${WwanSsid}\""}" \
	-v mode="${2:-"Client"}" \
		'$1 == iface && $2 == "ESSID:" {
			$2=""; $1=""
			gsub("^"FS"+|"FS"+$", "")
			ssid1=$0
			next }
		$1 == "Mode:" {
			rc=-(ssid == ssid1 && $2 == mode)
			exit }
		END{exit rc+1}'
}

WatchWifi() {
	local c="${1:-"$((Sleep/2))"}" ssid="" mode=""
	if [ "$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].disabled)" = 1 ]; then
		if [ -z "${WIfaceAP}" ] || \
		[ "$(uci -q get wireless.@wifi-iface[${WIfaceAP}].disabled)" = 1 ]; then
			sleep ${c}
			return 0
		fi
		ssid="\"$(uci -q get wireless.@wifi-iface[${WIfaceAP}].ssid)\""
		mode="Master"
	fi
	sleep $((Sleep/2))
	while ! IsWifiActive "${ssid}" "${mode}" && \
	[ $((c--)) -gt 0 ]; do
		sleep 1
	done
}

AnotherHotspot() {
	local n=0
	while [ $((n++)) ];
	eval ssid=\"\${net${n}_ssid:-}\" && \
	[ -n "${ssid}" ]; do
		[ -z "$(eval echo \"\${net${n}_blacklisted:-}\")" ] || \
			continue
		HotSpot=${n}
		return 0
	done
	HotSpot=${NONE}
	ssid="\$blacklisted\$"
}

WwanReset() {
	local disable="${1:-"1"}" iface="${2:-"${WIfaceSTA}"}" msg

	if [ -z "${WIfaceAP}" ] && \
	[ ${disable} -eq 1 ]; then
		local ssid
		AnotherHotspot
		[ "$(uci -q get wireless.@wifi-iface[${iface}].ssid)" != "${ssid}" ] || \
			return 0
		WwanSsid="${ssid}"
		uci set wireless.@wifi-iface[${iface}].ssid="${ssid}"
		if [ ${HotSpot} -ne ${NONE} ]; then
			uci set wireless.@wifi-iface[${iface}].encryption="$(
				eval echo \"\${net${HotSpot}_encrypt:-}\")"
			uci set wireless.@wifi-iface[${iface}].key="$(
				eval echo \"\${net${HotSpot}_key:-}\")"
		fi
		_msg "$([ ${HotSpot} -ne ${NONE} ] && \
			echo "Selecting a non blacklisted" || \
			echo "Blacklisting current")" \
			"hotspot for the STA interface"
	else
		local disabled
		disabled="$(uci -q get wireless.@wifi-iface[${iface}].disabled)" || :
		[ ${disabled:-"0"} -ne ${disable} ] || \
			return 0
		uci set wireless.@wifi-iface[${iface}].disabled=${disable}
		_msg "$([ ${disable} -eq 1 ] && echo "Dis" || echo "En")abling wireless" \
			"$([ "${iface}" = "${WIfaceSTA}" ] && \
				echo "interface to ${HotSpot}:'${WwanSsid}'" || \
				echo "Access Point")"
	fi

	_log "${msg}"
	[ "${iface}" != "${WIfaceSTA}" -o ${Status} -eq ${NONE} ] || \
		StatMsgs=""
	AddStatMsg "${msg}"

	uci commit wireless
	wifi down "${WDevice}"
	wifi up "${WDevice}"
	WatchWifi &
}

Report() {
	[ -z "${Debug}" ] || \
		_applog "Writing status report"
	exec > "/var/log/${NAME}.stat"
	printf '%s\n\n' "${NAME} status report."
	printf '%s\n\n' "${StatMsgs}"
	printf '%s\n' "Radio device is ${WDevice}"
	printf '%s\n' "STA network interface is ${WIface}"
	printf '%s\n' "Detected STA config in wifi-iface ${WIfaceSTA}"
	[ -n "${WIfaceAP}" ] && \
		printf '%s\n\n' "Detected AP config in wifi-iface ${WIfaceAP}" || \
		printf '%s\n\n' "Non standard STA only configuration"
	printf '%s="%s"\n' "Debug" "${Debug}"
	printf '%s="%s"\n' "ScanAuto" "${ScanAuto}"
	printf '%s=%d %s\n' "Sleep" "${Sleep}" "seconds"
	printf '%s=%d %s\n' "SleepDsc" "${SleepDsc}" "seconds"
	printf '%s=%d %s\n' "SleepScanAuto" "${SleepScanAuto}" "seconds"
	printf '%s=%d %s\n' "BlackList" "${BlackList}" \
		"$(test ${BlackList} -eq 0 && echo "Disabled" || echo "errors")"
	printf '%s=%d %s\n' "BlackListExpires" "${BlackListExpires}" \
		"$(test ${BlackListExpires} -eq 0 && echo "Never" || echo "seconds")"
	printf '%s=%d %s\n' "BlackListNetwork" "${BlackListNetwork}" \
		"$(test ${BlackListNetwork} -eq 0 && echo "Disabled" || echo "errors")"
	printf '%s=%d %s\n' "BlackListNetworkExpires" "${BlackListNetworkExpires}" \
		"$(test ${BlackListNetworkExpires} -eq 0 && echo "Never" || echo "seconds")"
	printf '%s=%d %s\n' "PingWait" "${PingWait}" "seconds"
	printf '%s=%d %s\n' "MinRxBps" "${MinRxBps}" \
		"$(test ${MinRxBps} -eq 0 && echo "Disabled" || echo "bytes per second")"
	printf '%s=%d %s\n\n' "LogRotate" "${LogRotate}" "log files to keep"
	local i=0
	while [ $((i++)) -lt ${HotSpots} ]; do
		set | grep -se "^net${i}_" | sort -r
		echo
	done
	iwinfo
	printf '%s %s\n' "Current hotspot client is" "${HotSpot}:'${WwanSsid:-}'"
	printf '%s %s%s\n' "Hotspot client is" \
		"$(test "$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].disabled)" != 1 && \
		echo "en" || echo "dis")" "abled"
	printf '%s%s %s\n\n' "Hotspot Wifi connection is" \
		"$(IsWifiActive || echo " not")" "active"
	if [ -n "${IfaceWan}" ]; then
		printf '%s%s%s\n\n' "WAN interface is " \
			"$(IsWanConnected || echo "dis")" "connected"
	else
		printf '%s\n\n' "There is no WAN interface"
	fi
	printf '%s\n\n' "Active default routes: $(ActiveDefaultRoutes)"
	ip route show
	[ -z "${Debug}" ] || \
		_applog "End of status report"
}

ListStatus() {
	StatMsgs=""
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
	if [ -z "${net_ssid:-}" -o -z "${net_encrypt:-}" ]; then
		LogPrio="err"
		_log "AddHotspot, Invalid config." \
			"No ssid or encrypt specified. Exiting"
		exit 1
	fi
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
		local msg="Adding new hotspot ${HotSpots}:'${net_ssid}'"
		_applog "${msg}"
		AddStatMsg "${msg}"
	fi
	unset net_ssid net_encrypt net_key net_hidden net_blacklisted net_check
}

LoadConfig() {
	local msg="Loading configuration"
	LogPrio="info" _log "${msg}"
	StatMsgs=""
	AddStatMsg "${msg}"

	# config variables, default values
	Debug=""
	ScanAuto="y"
	Sleep=20
	SleepDsc="$((Sleep*3))"
	SleepScanAuto="$((Sleep*15))"
	BlackList=3
	BlackListExpires=${NONE}
	BlackListNetwork=3
	BlackListNetworkExpires=$((10*60))
	PingWait=7
	MinRxBps=1024
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
	SleepDsc="$(_integer_value "${SleepDsc}" $((Sleep*3)) )"
	SleepScanAuto="$(_integer_value "${SleepScanAuto}" $((Sleep*15)) )"
	BlackList="$(_integer_value "${BlackList}" 3)"
	BlackListExpires="$(_integer_value "${BlackListExpires}" ${NONE})"
	BlackListNetwork="$(_integer_value "${BlackListNetwork}" 3)"
	BlackListNetworkExpires="$(_integer_value "${BlackListNetworkExpires}" $((10*60)))"
	PingWait="$(_integer_value "${PingWait}" 7)"
	MinRxBps="$(_integer_value "${MinRxBps}" 1024)"
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

	local i=-1 j m
	WIfaceAP=""
	WIfaceSTA=""
	while [ $((i++)) ];
	m="$(uci -q get wireless.@wifi-iface[${i}].mode)"; do
		[ "${m}" = "sta" ] || \
			continue
		LogPrio="info" _log "Found STA config in wifi-iface ${i}"
		WIfaceSTA=${i}
		WDevice="$(uci -q get wireless.@wifi-iface[${i}].device)"
		WIface="wlan$(iwinfo "${WDevice}" info | \
			sed -nre '/.*PHY name: phy([[:digit:]]+)$/ s//\1/p')"
		j=-1
		while [ $((j++)) ];
		m="$(uci -q get wireless.@wifi-iface[${j}].mode)"; do
			if [ "${m}" = "ap" ] && \
			[ "$(uci -q get wireless.@wifi-iface[${j}].device)" = "${WDevice}" ]; then
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
	LogPrio="info" _log "Radio device is ${WDevice}"
	LogPrio="info" _log "STA network interface is ${WIface}"
	[ -n "${WIfaceAP}" ] || \
		LogPrio="info" _log "Non standard STA only configuration"

	if [ ${HotSpots} -eq ${NONE} ]; then
		local n=0 ssid
		while [ $((n++)) ];
		eval ssid=\"\${net${n}_ssid:-}\" && \
		[ -n "${ssid}" ]; do
			if [ -z "$(eval echo \"\${net${n}_encrypt:-}\")" ]; then
				LogPrio="err"
				_log "Invalid config" \
					"Hotspot ${n}, no encryption specified. Exiting"
				exit 1
			fi
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
	WwanSsid=""
	ConnAttempts=1
	Status=${NONE}
	AddStatMsg "Configuration reloaded"
	NoSleep="y"
}

ActiveDefaultRoutes() {
	ip -4 route show default | \
	awk '$1 == "default" && $NF != "linkdown" {n++}
		END{print n+0}'
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
	[ -n "${ScanAuto}" ] && [ $(ActiveDefaultRoutes) -eq 0 ]
}

Scanning() {
	local err i=5
	while [ $((i--)) -gt 0 ]; do
		sleep 1
		! err="$(iw "${WIface}" scan 3>&2 2>&1 1>&3 3>&-)" 2>&1 || \
			return 0
		[ -z "${Debug}" ] || \
			_applog "${err}"
		[ ${i} -eq 2 ] && \
		echo "${err}" | grep -qsF 'command failed: Network is down' || \
			continue
		LogPrio="err"
		_log "Can't scan wifi, restarting the network"
		/etc/init.d/network reload
		WatchWifi ${Sleep}
	done
	return 1
}

CurrentHotSpot() {
	[ ${HotSpot} -ne ${NONE} ] || \
		HotSpot="$(echo "${Ssids}" | \
			awk -v ssid="${WwanSsid}" \
			'$0 == ssid {n = NR; exit}
			END{print n+0; exit (n+0 == 0)}')"
}

CheckNetw() {
	[ "${Debug}" = "xtrace" ] || \
		exec > /dev/null 2>&1
	if [ -n "${CheckSrvr}" ]; then
		if [ -n "${CheckInet}" ]; then
			wget --spider -T ${PingWait} --no-check-certificate \
			--bind-address "${CheckInet##"addr:"}" "${CheckAddr}" 2>&1 | \
			grep -qsF "Remote file exists"
		else
			printf 'GET %s HTTP/1.0\n\n' "${CheckAddr}" | \
				nc "${CheckSrvr}" ${CheckPort}
		fi
	else
		ping -4 -W ${PingWait} -c 3 -I "${WIface}" "${CheckAddr}"
	fi
}

CheckNetworking() {
	local check="$(eval echo \"\${net${HotSpot}_check:-}\")"
	if [ -z "${check}" ]; then
		[ -n "${ScanAuto}" ] && \
			Interval=${SleepDsc} || \
			Interval=${SleepScanAuto}
		return 0
	fi
	Interval=${Sleep}
	local delay=${Sleep} msg rc
	while [ -z "${Gateway:="$(ip -4 route show default dev "${WIface}" | \
	awk '$1 == "default" {print $3; exit}')"}" ] && \
	[ $((delay--)) -gt 0 ]; do
		sleep 1
	done
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
				if [ $(ActiveDefaultRoutes) -gt 1 ]; then
					_msg "Using the nc utility to check networking to URL" \
						"while several default routes are enabled"
					LogPrio="err" _log "${msg}"
					AddStatMsg "Error:" "${msg}"
				fi
			fi
		else
			CheckAddr="$(echo "${check}" | \
			sed -nre '\|^([[:digit:]]+[.]){3}[[:digit:]]+$|p')"
			if [ -z "${CheckAddr:="${Gateway}"}" ]; then
				_msg "Serious Error: no default route for" \
					"${HotSpot}:'${WwanSsid}'." \
					"Disabling networking check."
				LogPrio="err" _log "${msg}"
				[ -z "${StatMsgsChgd}" ] || \
					AddStatMsg "${msg}"
				unset net${HotSpot}_check
				return 0
			fi
		fi
	rc=1
	if [ ${MinRxBps} -ne 0 ]; then
		if [ -n "${CheckTime}" ]; then
			local b=$(($(GetRxBytes)-RxBytes)) \
				t=$(($(_UTCseconds)-CheckTime))
			if [ ${t} -gt 0 ] && \
			[ $((b/t)) -ge ${MinRxBps} ]; then
				rc=0
				_msg "Networking of ${HotSpot}:'${WwanSsid}' to" \
					"the external network is working"
			fi
			[ -z "${Debug}" ] || \
				_applog "STA interface received ${b} bytes in ${t} seconds"
		fi
		CheckTime=$(_UTCseconds)
		RxBytes=$(GetRxBytes)
	fi
	if [ ${rc} -ne 0 ]; then
		CheckNetw &
		rc=0
		WaitSubprocess ${PingWait} && \
			_msg "Networking of ${HotSpot}:'${WwanSsid}' to" \
				"$(test "${CheckAddr}" != "${Gateway}" || \
				echo "gateway:")${CheckAddr}" \
				"has been verified" || \
			rc=${?}
	fi
	if [ ${rc} -eq 0 ]; then
		if [ ${Status} -eq ${CONNECTED} -a ${NetworkAttempts} -eq 1 ]; then
			[ -z "${Debug}" ] || \
				_applog "${msg}"
		else
			NetworkAttempts=1
			_log "${msg}"
			AddStatMsg "${msg}"
		fi
		return 0
	elif [ ${rc} -gt 127 -a ${rc} -ne 143 ]; then
		return 0
	fi
	_msg "${NetworkAttempts} networking" \
		"failure$([ ${NetworkAttempts} -le 1 ] || echo "s")" \
		"on ${HotSpot}:'${WwanSsid}'"
	LogPrio="warn" _log "${msg}"
	if [ ${BlackListNetwork} -ne ${NONE} ] && \
	[ ${NetworkAttempts} -ge ${BlackListNetwork} ]; then
		HotspotBlackList "network" "${BlackListNetworkExpires}" "${msg}"
		WwanReset
		Status=${DISCONNECTED}
		ScanRequest=1
		return 1
	fi
	AddStatMsg "${msg}"
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

	if ! scanned="$(Scanning)"; then
		LogPrio="err"
		_log "Serious error: Can't scan wifi for access points"
		ScanErr="y"
		return 1
	fi
	if [ -n "${ScanErr}" ]; then
		_log "Wifi scan for access points has been successful"
		ScanErr=""
	fi
	scanned="$(echo "${scanned}" | \
	sed -nre '\|^[[:blank:]]+(SSID: .*)$| s||\1|p')" && \
	[ -n "${scanned}" ] || \
		return 1
	found_hidden="$(echo "${scanned}" | grep -sx -m 1 -F 'SSID: ')" || :

	n=${HotSpot}
	[ $((n++)) -lt ${HotSpots} ] || \
		n=1

	local rc=1
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
			[ "${ssid}" != "${WwanSsid}" ] || \
				rc=2
			[ \( ${Status} -eq ${DISABLED} -o -z "${WIfaceAP}" \) \
			-a -z "${Debug}" ] || \
				_applog "Not selecting blacklisted hotspot ${i}:'${ssid}'"
		fi
		[ $((i++)) -lt ${HotSpots} ] || \
			i=1
		[ ${i} -ne ${n} ] || \
			break
	done
	[ -z "${Debug}" ] || \
		_applog "DoScan: No Hotspots available"
	return ${rc}
}

HotSpotLookup() {
	BlackListExpired
	DoScan || \
		return ${?}
	if [ "${ssid}" != "${WwanSsid}" ]; then
		WwanSsid="${ssid}"
		_log "Hotspot ${HotSpot}:'${WwanSsid}' found. Applying settings..."
		WwanErr=${NONE}
		uci set wireless.@wifi-iface[${WIfaceSTA}].ssid="${WwanSsid}"
		uci set wireless.@wifi-iface[${WIfaceSTA}].encryption="$(
			eval echo \"\${net${HotSpot}_encrypt:-}\")"
		uci set wireless.@wifi-iface[${WIfaceSTA}].key="$(
			eval echo \"\${net${HotSpot}_key:-}\")"
		[ "${WwanDisabled}" != 1 ] || \
			uci set wireless.@wifi-iface[${WIfaceSTA}].disabled=0
		uci commit wireless
		if [ "${WwanDisabled}" != 1 ]; then
			wifi down "${WDevice}"
			wifi up "${WDevice}"
		else
			/etc/init.d/network reload
		fi
		TryConnection=2
		msg="Connecting to ${HotSpot}:'${WwanSsid}'..."
		_log "${msg}"
		AddStatMsg "${msg}"
		WatchWifi ${Sleep} &
	elif [ "${WwanDisabled}" = 1 ]; then
		WwanReset 0
		TryConnection=2
	else
		_msg "Client interface to" \
			"${HotSpot}:'${WwanSsid}' is already enabled"
		[ -z "${Debug}" -a  -z "${StatMsgsChgd}" ] || \
			_applog "${msg}"
		[ -z "${StatMsgsChgd}" ] || \
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
}

WifiStatus() {
	# constants
	readonly LF=$'\n' \
		NONE=0 DISCONNECTED=1 CONNECTING=2 DISABLED=3 CONNECTED=4
	# internal variables, daemon scope
	local Ssids ssid HotSpots IfaceWan WwanSsid="" WwanDisabled \
		ScanRequest ScanErr="" WwanErr Status=${NONE} StatMsgsChgd="" StatMsgs="" \
		Interval NoSleep \
		HotSpot=${NONE} ConnAttempts=1 NetworkAttempts RxBytes CheckTime \
		msg LogPrio="" \
		Gateway CheckAddr CheckSrvr CheckInet CheckPort \
		TryConnection=0 WIface WIfaceAP WIfaceSTA WDevice

	trap '_exit' EXIT
	trap 'exit' INT

	LoadConfig || exit 1
	Interval=${Sleep}

	trap 'LoadConfig' HUP
	trap 'NetworkChange' ALRM
	trap 'NoSleep="y"; StatMsgsChgd="y"' USR1
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
				NetworkAttempts=1
				Gateway=""; CheckAddr=""; CheckInet=""; CheckTime=""
				if CheckNetworking; then
					msg="Connected to ${HotSpot}:'${WwanSsid}'"
					_log "${msg}"
					AddStatMsg "${msg}"
					Status=${CONNECTED}
					ScanRequest=0
				fi
			elif CheckNetworking; then
				msg="Connected to ${HotSpot}:'${WwanSsid}'"
				[ -z "${Debug}" -a  -z "${StatMsgsChgd}" ] || \
					_applog "${msg}"
				[ -z "${StatMsgsChgd}" ] || \
					AddStatMsg "${msg}"
			fi
			continue
		fi
		[ ${TryConnection} -gt 0 ] && \
			[ $((TryConnection--)) ] && \
			continue || :
		CurrentHotSpot || :
		if [ -z "${WIfaceAP}" -a "${WwanDisabled}" = 1 ] || \
		( [ -n "${WIfaceAP}" ] && \
		[ "$(uci -q get wireless.@wifi-iface[${WIfaceAP}].disabled)" = 1 ] ); then
			WwanReset 0 "${WIfaceAP}"
			Interval=${Sleep}
			continue
		fi
		if IsWwanConnected "unknown"; then
			if [ ${Status} -eq ${CONNECTED} ]; then
				[ -n "${WIfaceAP}" ] || \
					StatMsgs=""
				msg="Lost connection ${HotSpot}:'${WwanSsid}'"
				_log "${msg}"
				AddStatMsg "${msg}"
			else
				if [ -n "${WIfaceAP}" ] && \
				[ ${Status} -eq ${DISCONNECTED} ]; then
					msg="Disabling wireless STA device, Again ?"
					[ -z "${Debug}" -a  -z "${StatMsgsChgd}" ] || \
						_applog "${msg}"
					[ -z "${StatMsgsChgd}" ] || \
						AddStatMsg "${msg}"
				fi
				if [ ${Status} -eq ${CONNECTING} ]; then
					_msg "${ConnAttempts} unsuccessful" \
						"connection$([ ${ConnAttempts} -le 1 ] || echo "s")" \
						"to ${HotSpot}:'${WwanSsid}'"
					AddStatMsg "${msg}"
					if [ ${BlackList} -ne ${NONE} ] && \
					[ ${ConnAttempts} -ge ${BlackList} ]; then
						HotspotBlackList "connect" "${BlackListExpires}" \
							"${msg}"
					else
						LogPrio="warn" _log "${msg}"
						[ $((ConnAttempts++)) ]
					fi
				fi
			fi
			if HotSpotLookup; then
				continue
			elif [ ${?} -ne 1 -o -n "${WIfaceAP}" ]; then
				WwanReset
			fi
			[ -n "${WIfaceAP}" -o ${Status} -ne ${NONE} ] || \
				StatMsgsChgd="y"
			Status=${DISCONNECTED}
			ScanRequest=1
			if [ -n "${WIfaceAP}" ]; then
				Interval=${Sleep}
				continue
			fi
		elif HotSpotLookup; then
			continue
		fi
		WwanErr=${NONE}
		msg="A hotspot is not available"
		if [ ${Status} -ne ${DISABLED} -a -n "${WIfaceAP}" ]; then
			_log "${msg}"
			AddStatMsg "${msg}"
			Status=${DISABLED}
		elif [ -n "${StatMsgsChgd}" ]; then
			_applog "${msg}"
			AddStatMsg "${msg}"
		else
			StatMsgs=""
		fi
		if [ "${WwanDisabled}" != 1 -a -n "${WIfaceAP}" ]; then
			Interval=${Sleep}
		elif [ -n "${ScanAuto}" ] && \
		[ $(ActiveDefaultRoutes) -eq 0 ]; then
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
