#!/bin/sh

#  wwanHotspot
#
#  Wireless WAN Hotspot management application for OpenWrt routers.
#  $Revision: 2.2 $
#
#  Copyright (C) 2017-2020 Jordi Pujol <jordipujolp AT gmail DOT com>
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

_tolower() {
	printf '%s\n' "${@}" | tr '[A-Z]' '[a-z]'
}

_integer_value() {
	local n="${1}" \
		d="${2}" \
		v
	v="$(2> /dev/null printf '%d' "$(printf '%s\n' "${n}" | \
	sed -nre '/^[[:digit:]]+$/p;q')")" && \
		echo ${v} || \
		echo ${d}
}

_UTCseconds() {
	date +'%s'
}

_datetime() {
	date +'%F %X'
}

_ps_children() {
	local ppid=${1:-${$}} \
		excl="${2:-"0"}" \
		pid
	for pid in $(pgrep -P ${ppid} | grep -svwF "${excl}"); do
		_ps_children ${pid} "${excl}"
		echo ${pid}
	done
}

_exit() {
	trap - EXIT INT HUP ALRM USR1 USR2
	LogPrio="warn" _log "Exit"
	UpdateReport="" ReportUpdtLapse=1 AddStatMsg "Daemon exit"
	kill -s TERM $(_ps_children) > /dev/null 2>&1 || :
	wait || :
}

_applog() {
	local msg="${@:-"${msg}"}"
	printf '%s\n' "$(_datetime) ${msg}" >> "/var/log/${NAME}"
}

_log() {
	local msg="${@:-"${msg}"}" \
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
	local timeout="${1:-}" \
		dont_interrupt="${2:-}" \
		pids="${3:-${!}}" \
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

StatusName() {
	echo -n "Actual Status "
	case ${Status} in
	${NONE}) echo "NONE";;
	${DISCONNECTED}) echo "DISCONNECTED";;
	${CONNECTING}) echo "CONNECTING";;
	${DISABLED}) echo "DISABLED";;
	${CONNECTED}) echo "CONNECTED";;
	*) echo "Invalid";;
	esac
}

HotspotName() {
	local hotspot="${1:-"${Hotspot}"}" \
		bssid="${2:-"${WwanBssid:-}"}" \
		ssid="${3:-"${WwanSsid:-"${BEL}"}"}"
	[ "${bssid}" != "${BEL}" ] || \
		bssid=""
	[ "${ssid}" = "${BEL}" ] && \
		ssid="${NULLSSID}" || \
		ssid="\"${ssid}\""
	echo "${hotspot}.${bssid}.${ssid}"
}

ClrStatMsgs() {
	StatMsgs="${UpdtMsgs}"
	UpdtMsgs=""
}

AddStatMsg() {
	local msg="$(_datetime) ${@:-"${msg}"}"
	if [ -z "${UpdateReport}" -a ${ReportUpdtLapse} -ne 0 ]; then
		awk -v msg="${msg}" \
			'b == 1 {if ($0 ~ "^Radio device is") {print msg; b=2}
				else b=0
				print ""} 
			b != 2 && /^$/ {b=1; next}
			1
			END{if (b == 1) print ""
				if (b != 2) print msg}' \
			< "/var/log/${NAME}.stat" > "/var/log/${NAME}.stat.part"
		mv -f "/var/log/${NAME}.stat.part" "/var/log/${NAME}.stat"
	fi
	StatMsgs="${StatMsgs:+"${StatMsgs}${LF}"}${msg}"
	StatMsgsChgd="y"
}

AddMsg() {
	local msg="${@:-"${msg}"}"
	[ -n "${UpdtMsgs}" ] && \
		UpdtMsgs="${UpdtMsgs}${LF}$(_datetime) ${msg}" || \
		AddStatMsg "${msg}"
}

AppMsg() {
	local msg="${@:-"${msg}"}"
	_applog "${msg}"
	if [ ${ReportUpdtLapse} -eq 0 ]; then
		AddStatMsg "${msg}"
	else
		UpdtMsgs="$(_datetime) ${msg}"
		StatMsgsChgd="y"
	fi
}

IfaceTraffic() {
	local iface="${1:-"${WIface}"}"
	printf '%s\n' $(( $(cat "/sys/class/net/${iface}/statistics/rx_bytes") + \
	$(cat "/sys/class/net/${iface}/statistics/tx_bytes") ))
}

HotspotBlackList() {
	local cause="${1}" \
		expires="${2}" \
		reason="${3:-"${msg}"}" \
		msg
	eval net${Hotspot}_blacklisted=\"${cause} $(_datetime)\" || :
	msg="Blacklisting $(HotspotName)"
	if [ ${expires} -gt ${NONE} ]; then
		eval net${Hotspot}_blacklistexp=\"$((expires+$(_UTCseconds)))\" || :
		msg="${msg} for ${expires} seconds"
	fi
	ClrStatMsgs
	LogPrio="warn" _log "${msg}"
	AddStatMsg "${msg}"
	LogPrio="info" _log "Reason:" "${reason}"
	AddStatMsg "Reason:" "${reason}"
}

BlackListExpired() {
	local d="" exp hotspot msg rc=""
	while read -r exp hotspot && \
	[ -n "${exp}" ] && \
	[ ${d:="$(_UTCseconds)"} -ge ${exp} ]; do
		unset net${hotspot}_blacklisted \
			net${hotspot}_blacklistexp || :
		_msg "Blacklisting has expired for" \
			"$(HotspotName "${hotspot}" \
				"$(eval echo \"\${net${hotspot}_bssid:-}\")" \
				"$(eval echo \"\${net${hotspot}_ssid:-}\")")"
		LogPrio="info" _log "${msg}"
		[ -n "${rc}" ] || \
			[ -n "${WIfaceAP}" ] || \
			[ ${Status} -ne ${DISABLED} -a ${Status} -ne ${DISCONNECTED} ] || \
				ClrStatMsgs
		rc=1
		AddStatMsg "${msg}"
	done << EOF
$(set | \
sed -nre "\|^net([[:digit:]]+)_blacklistexp='([[:digit:]]+)'| s||\2 \1|p" | \
sort -n -k 1,1)
EOF
}

IsWifiActive() {
	local bssid="${1:-}" \
		ssid="${2:-}" \
		mode="${3:-"Client"}"
	[ -z "${ssid}" ] && \
		ssid="${NULLSSID}" || \
		ssid="\"${ssid}\""
	local info ssid1 bssid1 mode1
	info="$(iwinfo "${WIface}" info 2> /dev/null)"
	ssid1="$(echo "${info}" | \
			sed -nre '/^'"${WIface}"'[[:blank:]]+ESSID:[[:blank:]]+(.*)$/ \
			{s//\1/p;q}')"
	[ "${ssid}" = "${ssid1}" ] || \
		return 1
	bssid1="$(_tolower "$(echo "${info}" | \
			sed -nre '/^[[:blank:]]+Access Point:[[:blank:]]+(.*)$/ \
			{s//\1/p;q}')")"
	[ "${bssid}" = "${bssid1}" ] || \
		return 1
	mode1="$(echo "${info}" | \
			sed -nre '/^[[:blank:]]+Mode:[[:blank:]]+([^[:blank:]]+).*$/ \
			{s//\1/p;q}')"
	[ "${mode}" = "${mode1}" ]
}

WatchWifi() {
	local c="${1:-"$((Sleep/2))"}" \
		ifcarrier="/sys/class/net/${WIface}/carrier"
	while [ "$(cat "${ifcarrier}" 2> /dev/null)" != "1" ] && \
	[ $((c--)) -gt 0 ]; do
		sleep 1
	done
}

AnyOtherHotspot() {
	local n=0
	while [ $((n++)) ];
	eval ssid=\"\${net${n}_ssid:-}\" && \
	eval bssid=\"\${net${n}_bssid:-}\" && \
	[ -n "${ssid}" -o -n "${bssid}" ]; do
		[ -z "$(eval echo \"\${net${n}_blacklisted:-}\")" ] || \
			continue
		hotspot=${n}
		return 0
	done
	hotspot=${NONE}
	ssid=""
	bssid="${NULLBSSID}"
}

SetEncryption() {
	local encrypt key
	eval encrypt=\"\${net${Hotspot}_encrypt:-}\"
	eval key=\"\${net${Hotspot}_key:-}\"
	uci set wireless.@wifi-iface[${WIfaceSTA}].encryption="${encrypt}"
	if printf '%s\n' "${encrypt}" | grep -qsie "^psk"; then
		uci set wireless.@wifi-iface[${WIfaceSTA}].key="${key}"
		uci -q delete wireless.@wifi-iface[${WIfaceSTA}].key1 || :
		uci -q delete wireless.@wifi-iface[${WIfaceSTA}].key2 || :
		uci -q delete wireless.@wifi-iface[${WIfaceSTA}].key3 || :
		uci -q delete wireless.@wifi-iface[${WIfaceSTA}].key4 || :
	elif printf '%s\n' "${encrypt}" | grep -qsie "^wep"; then
		uci set wireless.@wifi-iface[${WIfaceSTA}].key="1"
		uci set wireless.@wifi-iface[${WIfaceSTA}].key1="${key}"
		uci -q delete wireless.@wifi-iface[${WIfaceSTA}].key2 || :
		uci -q delete wireless.@wifi-iface[${WIfaceSTA}].key3 || :
		uci -q delete wireless.@wifi-iface[${WIfaceSTA}].key4 || :
	else
		uci -q delete wireless.@wifi-iface[${WIfaceSTA}].key || :
		uci -q delete wireless.@wifi-iface[${WIfaceSTA}].key1 || :
		uci -q delete wireless.@wifi-iface[${WIfaceSTA}].key2 || :
		uci -q delete wireless.@wifi-iface[${WIfaceSTA}].key3 || :
		uci -q delete wireless.@wifi-iface[${WIfaceSTA}].key4 || :
	fi
}

Report() {
	[ -z "${Debug}" ] || \
		_applog "Writing status report"
	exec > "/var/log/${NAME}.stat"
	printf '%s\n\n' "${NAME} status report."
	printf '%s\n' "${StatMsgs}"
	[ -z "${UpdtMsgs}" ] || \
		printf '%s\n' "${UpdtMsgs}"
	printf '\n'
	printf '%s\n' "Radio device is ${WDevice}"
	printf '%s\n' "STA network interface is ${WIface}"
	printf '%s\n' "Detected STA config in wifi-iface ${WIfaceSTA}"
	[ -n "${WIfaceAP}" ] && \
		printf '%s\n\n' "Detected AP config in wifi-iface ${WIfaceAP}" || \
		printf '%s\n\n' "Non standard STA only configuration"
	printf '%s="%s" %s\n' "Debug" "${Debug}" \
		"$(test -z "${Debug}" && echo "Disabled" || echo "Enabled")"
	printf '%s="%s"\n' "ScanAuto" "${ScanAuto}"
	printf '%s="%s" %s\n' "ReScan" "${ReScan}" \
		"$(test -z "${ReScan}" && echo "Disabled" || echo "Enabled")"
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
	printf '%s=%d %s\n' "MinTrafficBps" "${MinTrafficBps}" \
		"$(test ${MinTrafficBps} -eq 0 && echo "Disabled" || echo "bytes per second")"
	printf '%s=%d %s\n' "ReportUpdtLapse" "${ReportUpdtLapse}" \
		"$(test ${ReportUpdtLapse} -eq 0 && echo "Disabled" || echo "seconds")"
	printf '%s=%d %s\n\n' "LogRotate" "${LogRotate}" "log files to keep"
	local i=0
	while [ $((i++)) -lt ${Hotspots} ]; do
		set | grep -se "^net${i}_"
		echo
	done
	iwinfo
	printf '%s %s\n' "Current hotspot client is" \
		"$(HotspotName)"
	printf '%s %s%s\n' "Hotspot client is" \
		"$(test "$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].disabled)" != 1 && \
		echo "en" || echo "dis")" "abled"
	printf '%s%s %s\n\n' "Hotspot Wifi connection is" \
		"$(IsWifiActive "${WwanBssid:-}" "${WwanSsid:-}" || \
		echo " not")" "active"
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
	local msg="${@:-"Updating status report"}"
	UpdateReport="y"
	AppMsg "${msg}"
	[ ${Status} -ne ${CONNECTED} ] || \
		NetworkAttempts=0
	NoSleep="y"
}

NetworkChange() {
	[ ${Status} -le ${CONNECTING} ] || {
		msg="Network status has changed"
		AddStatMsg "${msg}"
		_applog "${msg}"
	}
	NoSleep="y"
}

PleaseScan() {
	local msg="Received an Scan Request"
	if [ ${Status} -eq ${CONNECTED} -o ${Status} -eq ${CONNECTING} ]; then
		_msg "${msg}" "when a Hotspot is" \
			"$([ ${Status} -eq ${CONNECTING} ] && \
				echo "connecting" || \
				echo "already connected")"
		_applog "${msg}"
		AddMsg "${msg}"
		[ ${Status} -ne ${CONNECTED} -o -z "${ReScan}" ] || \
			IndReScan="y"
	else
		ListStatus "${msg}"
	fi
}

BackupRotate() {
	local f="${1}" \
		n=${LogRotate}
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
	[ $((Hotspots++)) ]
	if [ -z "${net_ssid:=""}" -a -z "${net_bssid:=""}" ] || \
	[ -z "${net_encrypt:-}" ]; then
		LogPrio="err"
		_msg "Adding hotspot, Invalid config ${Hotspots}." \
			"No ssid, bssid or encrypt specified"
		_log "${msg}"
		AddStatMsg "Error:" "${msg}"
		exit 1
	fi
	[ -z "${net_ssid}" ] || \
		eval net${Hotspots}_ssid=\"${net_ssid}\"
	[ -z "${net_bssid}" ] || {
		net_bssid="$(_tolower "${net_bssid}")"
		eval net${Hotspots}_bssid=\"${net_bssid}\"
	}
	eval net${Hotspots}_encrypt=\"${net_encrypt}\"
	[ -z "${net_key:-}" ] || \
		eval net${Hotspots}_key=\"${net_key}\"
	[ -z "${net_hidden:-}" ] || \
		eval net${Hotspots}_hidden=\"${net_hidden}\"
	[ -z "${net_blacklisted:-}" ] || \
		eval net${Hotspots}_blacklisted=\"${net_blacklisted}\"
	[ -z "${net_check:-}" ] || \
		eval net${Hotspots}_check=\"${net_check}\"
	Ssids="${Ssids:+"${Ssids}${LF}"}${net_bssid}${TAB}${net_ssid}"
	if [ -n "${Debug}" ]; then
		local msg="Adding new hotspot $( \
		HotspotName "${Hotspots}" \
			"${net_bssid:-"${BEL}"}" \
			"${net_ssid:-"${BEL}"}")"
		_applog "${msg}"
		AddStatMsg "${msg}"
	fi
	unset net_ssid net_bssid net_encrypt net_key net_hidden \
		net_blacklisted net_check
}

LoadConfig() {
	local net_ssid net_bssid net_encrypt net_key net_hidden \
		net_blacklisted net_check \
		msg="Loading configuration"

	# config variables, default values
	Debug=""
	ScanAuto="y"
	ReScan="y"
	Sleep=20
	SleepDsc="$((Sleep*3))"
	SleepScanAuto="$((Sleep*15))"
	BlackList=3
	BlackListExpires=${NONE}
	BlackListNetwork=3
	BlackListNetworkExpires=$((10*60))
	PingWait=7
	MinTrafficBps=1024
	LogRotate=3
	ReportUpdtLapse=$((6*SleepScanAuto))
	unset $(set | awk -F '=' \
		'$1 ~ "^net[[:digit:]]*_" {print $1}') 2> /dev/null || :

	UpdateReport="y"
	StatMsgs=""
	UpdtMsgs=""
	Ssids=""
	Hotspots=${NONE}
	: > "/var/log/${NAME}.stat"
	AddStatMsg "${msg}"

	[ ! -s "/etc/config/${NAME}" ] || \
		. "/etc/config/${NAME}"

	Debug="${Debug:-}"
	ScanAuto="${ScanAuto:-}"
	ReScan="${ReScan:-}"
	Sleep="$(_integer_value "${Sleep}" 20)"
	SleepDsc="$(_integer_value "${SleepDsc}" $((Sleep*3)) )"
	SleepScanAuto="$(_integer_value "${SleepScanAuto}" $((Sleep*15)) )"
	BlackList="$(_integer_value "${BlackList}" 3)"
	BlackListExpires="$(_integer_value "${BlackListExpires}" ${NONE})"
	BlackListNetwork="$(_integer_value "${BlackListNetwork}" 3)"
	BlackListNetworkExpires="$(_integer_value "${BlackListNetworkExpires}" $((10*60)))"
	PingWait="$(_integer_value "${PingWait}" 7)"
	MinTrafficBps="$(_integer_value "${MinTrafficBps}" 1024)"
	LogRotate="$(_integer_value "${LogRotate}" 3)"
	ReportUpdtLapse="$(_integer_value "${ReportUpdtLapse}" $((6*SleepScanAuto)))"

	BackupRotate "/var/log/${NAME}"
	BackupRotate "/var/log/${NAME}.xtrace"

	if [ "${Debug}" = "xtrace" ]; then
		exec >> "/var/log/${NAME}.xtrace" 2>&1
		set -o xtrace
	else
		set +o xtrace
		exec >> "/var/log/${NAME}" 2>&1
	fi

	LogPrio="info" _log "${msg}"

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
			sed -nre '/.*PHY name: phy([[:digit:]]+)$/ s//\1/p')" || {
				LogPrio="err" _log "Invalid device ${WDevice}"
				exit; }
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
		LogPrio="err"
		msg="Invalid AP+STA configuration"
		_log "${msg}"
		AddStatMsg "Error:" "${msg}"
		exit 1
	fi
	LogPrio="info" _log "Radio device is ${WDevice}"
	LogPrio="info" _log "STA network interface is ${WIface}"
	[ -n "${WIfaceAP}" ] || \
		LogPrio="info" _log "Non standard STA only configuration"

	if [ ${Hotspots} -eq ${NONE} ]; then
		local n=0 ssid bssid encrypt
		while [ $((n++)) ];
		eval ssid=\"\${net${n}_ssid:-}\";
		eval bssid=\"\${net${n}_bssid:-}\";
		eval encrypt=\"\${net${n}_encrypt:-}\";
		[ -n "${ssid}" -o -n "${bssid}" -o -n "${encrypt}" ]; do
			if [ -z "${ssid}" -a -z "${bssid}" ] || \
			[ -z "${encrypt:-}" ]; then
				LogPrio="err"
				_msg "Invalid config" \
					"Hotspot ${n}, no ssid, bssid or encryption specified"
				_log "${msg}"
				AddStatMsg "Error:" "${msg}"
				exit 1
			fi
			[ -z "${bssid}" ] || {
				bssid="$(_tolower  "${bssid}")"
				eval net${n}_bssid=\"${bssid}\"
			}
			Ssids="${Ssids:+"${Ssids}${LF}"}${bssid}${TAB}${ssid}"
			Hotspots=${n}
		done
	fi
	if [ ${Hotspots} -eq ${NONE} ]; then
		net_ssid="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].ssid)" || :
		net_bssid="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].bssid)" || :
		net_encrypt="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].encryption)" || :
		net_key="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].key)" || :
		! printf '%s\n' "${net_encrypt}" grep -qse "^wep" || \
			net_key="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].key1)" || :
		LogPrio="warn"
		_msg "No hotspots configured," \
			"importing the current router setup for the STA interface"
		_log "${msg}"
		AddStatMsg "Warning:" "${msg}"
		local add_cfg="$(set | grep -se '^net_')"
		AddHotspot
		[ ! -s "/etc/config/${NAME}" ] || \
			sed -i.bak \
			-re '/^[[:blank:]]*(net[[:digit:]]*_|AddHotspot)/s//# &/' \
			"/etc/config/${NAME}"
		{ printf '\n%s\n' "# $(_datetime) Auto-added hotspot"
		printf '%s\n' "${add_cfg}"
		printf '%s\n' "#net_hidden=y"
		printf '%s\n' "#net_check='https://www.google.com/'"
		printf '%s\n' "AddHotspot"; } >> "/etc/config/${NAME}"
	fi
	if [ -n "$(printf '%s\n' "${Ssids}" | awk 'BEGIN{FS="\t"}
	$1 {print $1}' | sort | uniq -d)" -o \
	-n "$(printf '%s\n' "${Ssids}" | sort | uniq -d)" ]; then
		LogPrio="err"
		msg="Invalid configuration. Duplicate hotspots SSIDs or BSSIDs"
		_log "${msg}"
		AddStatMsg "Error:" "${msg}"
		exit 1
	fi

	local cdt_bssids
	cdt_bssids="$(printf '%s\n' "${Ssids}" | \
		awk 'BEGIN{FS="\t"} $1 {print NR}')"
	HotspotsOrder="$(echo ${cdt_bssids} $(seq 1 ${Hotspots} | \
		grep -svwEe "$(printf '%s' "${cdt_bssids:-0}" | \
		tr -s '\n' '|')"))"
	TryConnection=0
	ScanErr=""
	WwanErr=${NONE}
	ScanRequest=${Hotspots}
	Hotspot=${NONE}
	WwanSsid=""
	WwanBssid=""
	ConnAttempts=1
	Status=${NONE}
	[ -z "${Debug}" ] || \
		_applog "$(StatusName)"
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

IsWwanDisconnected() {
	IsWifiActive "${NULLBSSID}" && \
	sleep 5 && \
	IsWifiActive "${NULLBSSID}" && \
	echo "y" || :
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
		if [ ${i} -ne 2 ]; then
			sleep 5
			continue
		fi
		printf '%s\n' "${err}" | \
		grep -qsF 'command failed: Network is down' || \
			LogPrio="err"
		_log "Can't scan wifi, restarting the network"
		/etc/init.d/network reload
		WatchWifi ${Sleep}
	done
	return 1
}

# param: connected = indicator
# returns: Hotspot WwanSsid WwanBssid
# 	when not listed: returns false and Hotspot=0 
CurrentHotspot() {
	local connected="${1:-}" \
		ssid
	[ ${Hotspot} -eq ${NONE} ] || \
		return 0
	if [ -n "${connected}" -a -z "${WwanBssid}" ] && \
	WwanBssid="$(iwinfo "${WIface}" info 2> /dev/null | \
	awk '/^[[:blank:]]+Access Point:[[:blank:]]+/ {
		print tolower($NF)
		rc=-1
		exit}
	END{exit rc+1}')"; then
		uci set wireless.@wifi-iface[${WIfaceSTA}].bssid="${WwanBssid}"
		[ -z "${Debug}" ] || \
			_applog "Setting uci bssid ${WwanBssid}"
	fi
	if [ -n "${connected}" -a -z "${WwanSsid}" ] && \
	ssid="$(iwinfo "${WIface}" info 2> /dev/null | \
	awk -v iface="${WIface}" \
	'function trim(s) {
		if (!s) s=$0
		return gensub(/^[[:blank:]]+|[[:blank:]]+$/, "", "g", s)
	}
	$1 == iface && $2 == "ESSID:" {
		$2=""; $1=""
		print trim()
		rc=-1; exit
	}
	END{exit rc+1}')"; then
		[ -z "${Debug}" ] || \
			_applog "Setting uci ssid ${ssid}"
		if [ "${ssid}" = "${NULLSSID}" ]; then
			WwanSsid=""
			uci -q delete wireless.@wifi-iface[${WIfaceSTA}].ssid || :
		else
			WwanSsid="$(printf '%s\n' "${ssid}" | \
				sed -e 's/^"//; s/"$//')"
			uci set wireless.@wifi-iface[${WIfaceSTA}].ssid="${WwanSsid}"
		fi
	fi
	Hotspot="$(printf '%s\n' "${Ssids}" | \
			awk -v ssid="${WwanSsid}" \
			-v bssid="${WwanBssid}" \
			'BEGIN{FS="\t"}
			$1 == bssid && ( $2 == ssid || ! $2 ) {n = NR; exit}
			END{print n+0; exit (n+0 == 0)}')" || \
	Hotspot="$(printf '%s\n' "${Ssids}" | \
			awk -v ssid="${WwanSsid}" \
			'BEGIN{FS="\t"}
			! $1 && $2 == ssid {n = NR; exit}
			END{print n+0; exit (n+0 == 0)}')"
}

# returns hotspot ssid bssid
DoScan() {
	local forceScan="${1:-}" \
		availBssid="${2:-}" \
		availSsid="${3:-}"

	[ -n "${forceScan}" ] || \
		if ! MustScan; then
			[ -z "${Debug}" ] || \
				_applog "Must not scan"
			return 1
		fi

	BlackListExpired

	[ -z "${Debug}" ] || \
		_applog "Do-Scan - Scanning"

	local scanned msg

	if ! scanned="$(Scanning)"; then
		LogPrio="err"
		_log "Serious error: Can't scan wifi for access points"
		ScanErr="y"
		return 1
	fi
	if [ -n "${ScanErr}" ]; then
		msg="Wifi scan for access points has been successful"
		[ -z "${Debug}" ] && \
			_applog "${msg}" || \
			_log "${msg}"
		ScanErr=""
	fi
	scanned="$(printf '%s\n' "${scanned}" | awk \
		'function trim(s) {
			if (!s) s=$0
			return gensub(/^[[:blank:]]+|[[:blank:]]+$/, "", "g", s)
		}
		function nospaces() {
			return gensub(/[[:blank:]]+/, ",", "g", trim())
		}
		function prt() {
			if (! bssid) return
			rc=-1
			print seen OFS signal OFS ciph OFS pair OFS auth \
				OFS bssid OFS ssid
			bssid=""
		}
		BEGIN{OFS="\t"}
		$1 == "BSS" {
			prt()
			bssid=substr($2,1,17)
			seen="999999999"
			signal="99"
			ssid=""
			ciph="*"
			pair="*"
			auth="*"
			next
		}
		{if (! bssid) next}
		$1 == "signal:" {
			signal=0-$2
			next}
		/^[[:blank:]]+last seen:[[:blank:]]+/ {
			seen=$3
			next}
		$1 == "SSID:" {
			$1=$1
			ssid=trim()
			next}
		/^[[:blank:]]+\* Group cipher: / {
			$1=$2=$3=""
			ciph=nospaces()
			next}
		/^[[:blank:]]+\* Pairwise ciphers: / {
			$1=$2=$3=""
			pair=nospaces()
			next}
		/^[[:blank:]]+\* Authentication suites: / {
			$1=$2=$3=""
			auth=nospaces()
			next}
		END{prt()
		exit rc+1}' | sort -n -k 1,1)" || \
			return 1

	local i ssid1 bssid1 blacklisted hidden net_ssid \
		seen signal ciph pair auth bssid2 dummy ssid2 \
		cdts="" rc=1

	if [ -n "${availBssid}" ]; then
		while IFS="${TAB}" \
		read -r seen signal ciph pair auth bssid2 dummy ssid2 && \
		[ -n "${bssid2}" ]; do
			! test "${bssid2}" = "${availBssid}" -a \
			\( "${ssid2}" = "${availSsid}" -o \
			"${ssid2}" = "${HIDDENSSID}" \) || \
				return 0
		done << EOF
${scanned}
EOF
		return 1
	fi

	local foundh=0 blackh=0
	for i in ${HotspotsOrder}; do
		eval ssid1=\"\${net${i}_ssid:-}\"
		eval bssid1=\"\${net${i}_bssid:-}\"
		eval blacklisted=\"\${net${i}_blacklisted:-}\"
		eval hidden=\"\${net${i}_hidden:-}\"
		if [ -n "${hidden}" ]; then
			[ "${hidden}" = "y" ] && \
				net_ssid="${HIDDENSSID}" || \
				net_ssid="${hidden}"
		else
			net_ssid="${ssid1}"
		fi
		#local encrypt
		#eval encrypt=\"\${net${i}_encrypt:-}\"
		while IFS="${TAB}" \
		read -r seen signal ciph pair auth bssid2 dummy ssid2 && \
		[ -n "${bssid2}" ]; do
			[ -z "${net_ssid}" -a "${bssid1}" = "${bssid2}" ] || \
			[ -z "${bssid1}" -a "${net_ssid}" = "${ssid2}" ] || \
			[ -n "${net_ssid}" -a -n "${bssid1}" \
			-a "${net_ssid}" = "${ssid2}" -a "${bssid1}" = "${bssid2}" ] || \
				continue
			#printf '%s\n' "${encrypt}" | grep -qsie "${auth}" || \
			#	continue
			[ $((foundh++)) ]
			if [ -n "${blacklisted}" ]; then
				[ $((blackh++)) ]
				if [ -z "${bssid1}" -a "${ssid1}" = "${WwanSsid}" ] || \
				[ -z "${ssid1}" -a "${bssid1}" = "${WwanBssid}" ] || \
				[ -n "${ssid1}" -a -n "${bssid1}" \
				-a "${ssid1}" = "${WwanSsid}" \
				-a "${bssid1}" = "${WwanBssid}" ]; then
					[ -z "${Debug}" ] || \
						_applog "Do-Scan: current hotspot" \
							"$(HotspotName "${i}")" \
							"is blacklisted"
					rc=2
				fi
				[ \( ${Status} -eq ${DISABLED} -o -z "${WIfaceAP}" \) \
				-a -z "${Debug}" ] || \
					_applog "Do-Scan: Not selecting blacklisted hotspot" \
						"$(HotspotName "${i}" "${bssid1}" \
							"${ssid1:+"\"${ssid1}\""}")"
				break
			fi
			if printf '%s\n' "${cdts}" | \
			awk -v bssid="${bssid2}" \
			'BEGIN{FS="\t"}
			bssid == $3 {rc=-1; exit}
			END{exit rc+1}'; then
				[ -z "${Debug}" ] || \
					_applog "Do-Scan: hotspot" \
						"$(HotspotName "${i}" "${bssid2}" "${ssid1}")" \
						"iw scan already listed BSSID"
				continue
			fi
			if [ "${ssid2}" = "${HIDDENSSID}" ]; then
				ssid2="${BEL}"
			elif [ -z "${ssid1}" ]; then
				ssid1="${ssid2}"
			fi
			[ -z "${Debug}" ] || \
				_applog "Do-Scan: signal -${signal} dBm ${auth}" \
					"$(HotspotName "${i}" "${bssid2}" "${ssid2}")"
			cdts="${cdts:+"${cdts}${LF}"}\
${signal}${TAB}${i}${TAB}${bssid2}${TAB}SSID:${TAB}${ssid1}"
		done << EOF
${scanned}
EOF
	done
	if [ -z "${cdts}" ]; then
		if [ ${foundh} -gt 0 ] && \
		[ ${foundh} -le ${blackh} ]; then
			[ -z "${StatMsgsChgd}" -a -z "${Debug}" ] || {
				_msg "Do-Scan: Warning," \
					"all available hotspots are blacklisted"
				_applog "${msg}"
				AddMsg "${msg}"
			}
		else
			[ -z "${Debug}" ] || \
				_applog "Do-Scan: No Hotspots available"
		fi
		return ${rc}
	fi
	local cdt="$(printf '%s\n' "${cdts}" | sort -n -k 1,1 | head -n 1)"
	hotspot="$(printf '%s\n' "${cdt}" | cut -f 2)"
	ssid="$(printf '%s\n' "${cdt}" | cut -f 5- -s)"
	bssid="$(printf '%s\n' "${cdt}" | cut -f 3 -s)"
	_applog "Do-Scan selects" \
		"$(HotspotName "${hotspot}" "${bssid}" "${ssid:-"${BEL}"}")"
}

WwanReset() {
	local disable="${1:-"1"}" \
		iface="${2:-"${WIfaceSTA}"}" \
		dontwwifi="" \
		msg

	if [ -z "${WIfaceAP}" ] && \
	[ ${disable} -eq 1 ]; then
		local hotspot ssid bssid ssid1 bssid1
		DoScan "y" || {
			AnyOtherHotspot
			dontwwifi="y"; }
		Hotspot="${hotspot}"

		ssid1="$(uci -q get wireless.@wifi-iface[${iface}].ssid)" || :
		bssid1="$(uci -q get wireless.@wifi-iface[${iface}].bssid)" || :
		if [ -z "${bssid1}" -a "${ssid1}" = "${ssid}" ] || \
		[ -z "${ssid1}" -a "${bssid1}" = "${bssid}" ] || \
		[ -n "${ssid1}" -a -n "${bssid1}" \
		-a "${ssid1}" = "${ssid}" -a "${bssid1}" = "${bssid}" ]; then
			return 0
		fi
		WwanSsid="${ssid}"
		WwanBssid="${bssid}"
		[ -n "${ssid}" ] && \
			uci set wireless.@wifi-iface[${iface}].ssid="${ssid}" || \
			uci -q delete wireless.@wifi-iface[${iface}].ssid || :
		uci set wireless.@wifi-iface[${iface}].bssid="${bssid}"
		if [ ${Hotspot} -ne ${NONE} ]; then
			SetEncryption
			msg="Selecting $(HotspotName "" "${bssid}""${ssid}") non blacklisted"
		else
			msg="Blacklisting current"
		fi
		msg="${msg} hotspot for the STA interface"
	else
		local disabled
		disabled="$(uci -q get wireless.@wifi-iface[${iface}].disabled)" || :
		[ ${disabled:-"0"} -ne ${disable} ] || \
			return 0
		[ ${disable} -eq 1 ] && \
			uci set wireless.@wifi-iface[${iface}].disabled=${disable} || \
			uci -q delete wireless.@wifi-iface[${iface}].disabled || :
		_msg "$([ ${disable} -eq 1 ] && echo "Dis" || echo "En")abling wireless" \
			"$([ "${iface}" = "${WIfaceSTA}" ] && \
				echo "interface to $(HotspotName)" || \
				echo "Access Point")"
	fi

	_log "${msg}"
	AddStatMsg "${msg}"

	wifi down "${WDevice}"
	wifi up "${WDevice}"
	UpdateReport="y"
	[ -n "${dontwwifi}" ] || \
		WatchWifi &
}

CheckNetw() {
	[ "${Debug}" = "xtrace" ] && \
		exec >&2 || \
		exec > /dev/null 2>&1
	if [ -n "${CheckSrvr}" ]; then
		if [ -n "${CheckInet}" ]; then
			wget -nv --spider -T ${PingWait} --no-check-certificate \
			--bind-address "${CheckInet##"addr:"}" "${CheckAddr}" 2>&1 | \
			grep -sF "200 OK"
		else
			printf 'GET %s HTTP/1.0\n\n' "${CheckAddr}" | \
				nc "${CheckSrvr}" ${CheckPort}
		fi
	else
		ping -4 -W ${PingWait} -c 3 -I "${WIface}" "${CheckAddr}"
	fi
}

CheckNetworking() {
	local check
	eval check=\"\${net${Hotspot}_check:-}\"
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
		if CheckSrvr="$(printf '%s\n' "${check}" | \
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
				[ -z "${Debug}" ] || \
					_applog "check networking, nc ${CheckAddr} ${CheckPort}"
				if [ $(ActiveDefaultRoutes) -gt 1 ]; then
					_msg "Using the nc utility to check networking to URL" \
						"while several default routes are enabled"
					LogPrio="err" _log "${msg}"
					AddStatMsg "Error:" "${msg}"
				fi
			else
				[ -z "${Debug}" ] || \
					_applog "check networking, wget ${CheckAddr}"
			fi
		else
			CheckAddr="$(printf '%s\n' "${check}" | \
			sed -nre '\|^([[:digit:]]+[.]){3}[[:digit:]]+$|p')"
			if [ -z "${CheckAddr:="${Gateway}"}" ]; then
				_msg "Serious Error: no default route for" \
					"$(HotspotName)." \
					"Disabling networking check."
				LogPrio="err" _log "${msg}"
				[ -z "${StatMsgsChgd}" ] || \
					AddStatMsg "${msg}"
				unset net${Hotspot}_check
				return 0
			fi
			[ -z "${Debug}" ] || \
				_applog "check networking, ping ${CheckAddr}"
		fi
	rc=1
	if [ ${MinTrafficBps} -ne 0 ]; then
		local r=$(IfaceTraffic) \
			c=$(_UTCseconds)
		if [ -n "${CheckTime}" ]; then
			local b=$((${r}-Traffic)) \
				t=$((${c}-CheckTime))
			if [ ${t} -gt 0 ] && \
			[ $((b/t)) -ge ${MinTrafficBps} ]; then
				rc=0
				_msg "Networking of $(HotspotName) to" \
					"the external network is working"
			fi
			[ -z "${Debug}" ] || \
				_applog "STA interface received ${b} bytes in ${t} seconds"
		fi
		CheckTime=${c}
		Traffic=${r}
	fi
	if [ ${rc} -ne 0 ]; then
		CheckNetw &
		rc=0
		WaitSubprocess && \
			_msg "Networking of $(HotspotName) to" \
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
			AddMsg "${msg}"
			[ ${NetworkAttempts} -eq 0 ] && \
				_applog "${msg}" || \
				_log "${msg}"
			NetworkAttempts=1
		fi
		return 0
	elif [ ${rc} -gt 127 -a ${rc} -ne 143 ]; then
		return 0
	fi
	[ ${NetworkAttempts} -gt 0 ] || \
		NetworkAttempts=1
	_msg "${NetworkAttempts} networking" \
		"failure$([ ${NetworkAttempts} -le 1 ] || echo "s")" \
		"on $(HotspotName)"
	LogPrio="warn" _log "${msg}"
	if [ ${BlackListNetwork} -ne ${NONE} ] && \
	[ ${NetworkAttempts} -ge ${BlackListNetwork} ]; then
		HotspotBlackList "network" "${BlackListNetworkExpires}" "${msg}"
		if ! HotspotLookup; then
			WwanReset
			Status=${DISCONNECTED}
			[ -z "${Debug}" ] || \
				_applog "$(StatusName)"
			ScanRequest=1
		fi
		return 1
	fi
	AddStatMsg "${msg}"
	NoSleep=""
	[ $((NetworkAttempts++)) ]
}

HotspotLookup() {
	local clrmsgs="${1:-}" \
		hotspot="${2:-}" \
		bssid="${3:-}" \
		ssid="${4:-}"

	[ -n "${hotspot}" ] || \
		DoScan || return ${?}

	[ ${Hotspot} -eq ${hotspot} ] || {
		ConnAttempts=1
		Hotspot=${hotspot}; }

	[ -z "${clrmsgs}" -o ${Status} -le ${CONNECTING} ] || \
		ClrStatMsgs
	local encrypt key hidden wencrypt wkey
	eval encrypt=\"\${net${Hotspot}_encrypt:-}\"
	eval key=\"\${net${Hotspot}_key:-}\"
	eval hidden=\"\${net${Hotspot}_hidden:-}\"
	wencrypt="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].encryption)" || :
	if printf '%s\n' "${wencrypt}" | grep -qsie "^wep"; then
		wkey="$(uci -q get \
			wireless.@wifi-iface[${WIfaceSTA}].key1)" || :
	else
		wkey="$(uci -q get \
			wireless.@wifi-iface[${WIfaceSTA}].key)" || :
	fi
	if [ "${ssid}" != "${WwanSsid}" -a \
	\( -z "${hidden}" -o -n "${ssid}" \) ] || \
	[ "${bssid}" != "${WwanBssid}" -o \
	"${encrypt}" != "${wencrypt}" -o \
	"${key}" != "${wkey}" ]; then
		WwanSsid="${ssid}"
		WwanBssid="${bssid}"
		_log "Hotspot $(HotspotName) found. Applying settings..."
		WwanErr=${NONE}
		[ -n "${WwanSsid}" ] && \
			uci set wireless.@wifi-iface[${WIfaceSTA}].ssid="${WwanSsid}" || \
			uci -q delete wireless.@wifi-iface[${WIfaceSTA}].ssid || :
		uci set wireless.@wifi-iface[${WIfaceSTA}].bssid="${WwanBssid}"
		SetEncryption
		[ "${WwanDisabled}" != 1 ] || \
			uci -q delete wireless.@wifi-iface[${WIfaceSTA}].disabled
		if [ "${WwanDisabled}" != 1 ]; then
			wifi down "${WDevice}"
			wifi up "${WDevice}"
		else
			/etc/init.d/network reload
		fi
		TryConnection=2
		msg="Connecting to $(HotspotName)..."
		_log "${msg}"
		AddStatMsg "${msg}"
		WatchWifi ${Sleep} &
	elif [ "${WwanDisabled}" = 1 ]; then
		WwanReset 0
		TryConnection=2
	else
		_msg "Client interface to" \
			"$(HotspotName) is already enabled"
		[ -z "${Debug}" -a  -z "${StatMsgsChgd}" ] || \
			_applog "${msg}"
		[ -z "${StatMsgsChgd}" ] || \
			AddStatMsg "${msg}"
	fi
	Status=${CONNECTING}
	[ -z "${Debug}" ] || \
		_applog "$(StatusName)"
	if [ $((WwanErr++)) -gt ${Hotspots} ]; then
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

ReScanning() {
	local hotspot ssid bssid msg
	msg="Re-Scanning"
	_applog "${msg}"
	AddMsg "${msg}"
	NoSleep="y"
	DoScan "y" || \
		return 0
	if [ "${ssid}" = "${WwanSsid}" -a "${bssid}" = "${WwanBssid}" ]; then
		msg="Actually the best hotspot is $(HotspotName)"
		_applog "${msg}"
		AddMsg "${msg}"
		return 0
	fi
	ClrStatMsgs
	msg="Reconnection required"
	_applog "${msg}"
	AddMsg "${msg}"
	HotspotLookup "" "${hotspot}" "${bssid}" "${ssid}"
}

Settle() {
	local pidSleep="" pids tl
	IndReScan=""
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
	pids="$(_ps_children "" "${pidSleep}")"
	[ -z "${pids}" ] || \
		WaitSubprocess ${Sleep} "y" "${pids}" || :
	if [ -n "${UpdateReport}" ] || \
	[ -n "${StatMsgsChgd}" -a ${ReportUpdtLapse} -eq 0 ]; then
		StatMsgsChgd=""
		UpdateReport=""
		Report &
		WaitSubprocess "" "y" || :
		UpdtMsgs=""
	elif [ ${ReportUpdtLapse} -ne 0 ] && \
	( [ $((tl=$(_UTCseconds)-$(date +'%s' -r "/var/log/${NAME}.stat"))) \
	-lt 0 ] || [ ${ReportUpdtLapse} -lt ${tl} ] ); then
		ListStatus "Time lapse exceeded, requesting a report update"
	else
		StatMsgsChgd=""
	fi
	if [ -n "${pidSleep}" ]; then
		[ -z "${NoSleep}" ] || \
			kill -s TERM ${pidSleep} > /dev/null 2>&1 || :
		if ! WaitSubprocess "" "" "${pidSleep}"; then
			WwanErr=${NONE}
			ScanRequest=${Hotspots}
		fi
		[ -z "${Debug}" ] || \
			_applog "sleeping ended"
	fi
	NoSleep=""
}

WifiStatus() {
	# constants
	readonly LF=$'\n' TAB=$'\t' BEL=$'\x07' \
		HIDDENSSID="\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
		NULLSSID="unknown" NULLBSSID="00:00:00:00:00:00" \
		NONE=0 DISCONNECTED=1 CONNECTING=2 DISABLED=3 CONNECTED=4
	# config variables
	local Debug ScanAuto ReScan Sleep SleepDsc SleepScanAuto \
		BlackList BlackListExpires BlackListNetwork BlackListNetworkExpires \
		PingWait MinTrafficBps LogRotate ReportUpdtLapse
	# internal variables, daemon scope
	local WwanSsid WwanBssid WwanDisabled WwanErr \
		Ssids Hotspots HotspotsOrder IfaceWan \
		ScanRequest ScanErr IndReScan \
		Status StatMsgsChgd StatMsgs \
		UpdateReport ReportUpdtLapse UpdtMsgs Interval NoSleep \
		Hotspot ConnAttempts NetworkAttempts Traffic CheckTime \
		LogPrio \
		Gateway CheckAddr CheckSrvr CheckInet CheckPort \
		TryConnection WIface WIfaceAP WIfaceSTA WDevice \
		msg wwdsc

	trap '_exit' EXIT
	trap 'exit' INT

	LoadConfig || exit 1
	Interval=${Sleep}

	trap 'LoadConfig' HUP
	trap 'NetworkChange' ALRM
	trap 'PleaseScan' USR1
	trap 'ListStatus' USR2

	while Settle; do
		WwanDisabled="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].disabled)" || :
		WwanSsid="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].ssid)" || :
		WwanBssid="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].bssid)" || :
		wwdsc="$(test "${WwanDisabled}" = 1 || IsWwanDisconnected)"
		if [ "${WwanDisabled}" != 1 -a -z "${wwdsc}" ]; then
			TryConnection=0
			ScanErr=""
			WwanErr=${NONE}
			if [ ${Status} -ne ${CONNECTED} ]; then
				CurrentHotspot "y" || \
					LogPrio="warn" \
					_log "Connected to a non-configured hotspot:" \
						"$(HotspotName)"
				NetworkAttempts=1
				Gateway=""; CheckAddr=""; CheckInet=""; CheckTime=""
				if CheckNetworking; then
					UpdateReport="y"
					[ -n "${WIfaceAP}" -o ${Status} -eq ${CONNECTING} ] || \
						ClrStatMsgs
					msg="Connected to $(HotspotName)"
					_log "${msg}"
					AddMsg "${msg}"
					Status=${CONNECTED}
					[ -z "${Debug}" ] || \
						_applog "$(StatusName)"
					ScanRequest=0
				fi
			elif [ -n "${IndReScan}" ]; then
				ReScanning
			elif CheckNetworking; then
				msg="Connected to $(HotspotName)"
				[ -z "${Debug}" -a  -z "${StatMsgsChgd}" ] || \
					_applog "${msg}"
				[ -z "${StatMsgsChgd}" ] || \
					AddMsg "${msg}"
			fi
			continue
		fi
		if [ ${TryConnection} -gt 0 ]; then
			if DoScan "y" "${WwanBssid}" "${WwanSsid}"; then
				[ $((TryConnection--)) ]
				continue
			fi
			TryConnection=0
			msg="Hotspot $(HotspotName) is gone while connecting"
			_log "${msg}"
			AddStatMsg "${msg}"
		fi
		CurrentHotspot || :
		if [ -z "${WIfaceAP}" -a "${WwanDisabled}" = 1 ] || \
		( [ -n "${WIfaceAP}" ] && \
		[ "$(uci -q get wireless.@wifi-iface[${WIfaceAP}].disabled)" = 1 ] ); then
			WwanReset 0 "${WIfaceAP}"
			Interval=${Sleep}
			continue
		fi
		if [ "${WwanDisabled}" != 1 -a -n "${wwdsc}" ]; then
			if [ ${Status} -eq ${CONNECTED} ]; then
				ClrStatMsgs
				msg="Lost connection $(HotspotName)"
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
						"to $(HotspotName)"
					AddStatMsg "${msg}"
					if [ ${BlackList} -ne ${NONE} ] && \
					[ ${ConnAttempts} -ge ${BlackList} ]; then
						HotspotBlackList "connect" "${BlackListExpires}" \
							"${msg}"
						WwanSsid=""
						uci -q delete wireless.@wifi-iface[${WIfaceSTA}].ssid
						WwanBssid="${NULLBSSID}"
						uci -q delete wireless.@wifi-iface[${WIfaceSTA}].bssid
					else
						LogPrio="warn" _log "${msg}"
						[ $((ConnAttempts++)) ]
					fi
				fi
			fi
			if HotspotLookup; then
				continue
			elif [ ${?} -ne 1 -o -n "${WIfaceAP}" ]; then
				WwanReset
			fi
			[ -n "${WIfaceAP}" -o ${Status} -ne ${NONE} ] || \
				StatMsgsChgd="y"
			Status=${DISCONNECTED}
			[ -z "${Debug}" ] || \
				_applog "$(StatusName)"
			ScanRequest=1
			if [ -n "${WIfaceAP}" ]; then
				Interval=${Sleep}
				continue
			fi
		elif HotspotLookup "y"; then
			continue
		fi
		WwanErr=${NONE}
		msg="No hotspots available"
		if [ -z "${WIfaceAP}" -a ${Status} -ne ${DISCONNECTED} ]; then
			Status=${DISCONNECTED}
			[ -z "${Debug}" ] || \
				_applog "$(StatusName)"
		fi
		if [ ${Status} -ne ${DISABLED} -a -n "${WIfaceAP}" ]; then
			_log "${msg}"
			AddStatMsg "${msg}"
			Status=${DISABLED}
			[ -z "${Debug}" ] || \
				_applog "$(StatusName)"
		elif [ -n "${StatMsgsChgd}" ]; then
			_applog "${msg}"
			AddMsg "${msg}"
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
