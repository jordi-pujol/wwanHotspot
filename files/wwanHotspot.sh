#!/bin/sh

#  wwanHotspot
#
#  Wireless WAN Hotspot management application for OpenWrt routers.
#  $Revision: 2.14 $
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

_toupper() {
	printf '%s\n' "${@}" | tr '[a-z]' '[A-Z]'
}

_unquote() {
	printf '%s\n' "${@}" | sed -re 's/^"(.*)"$/\1/'
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
	date +'%F %X' "${@}"
}

_msgdatetime() {
	_datetime "--date=@${MsgTime}"
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

_applog() {
	local msg="${@}"
	printf '%s\n' "$(_datetime) ${msg}" >> "/var/log/${NAME}"
}

# priority: info notice warn err debug
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
	local p rc=${ERR}
	for p in "${@}"; do
		if kill -s 0 ${p} > /dev/null 2>&1; then
			echo ${p}
			rc=${OK}
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
	while wait ${pids} && rc=${OK} || rc=${rc:-${?}};
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
	MsgTime=$(_UTCseconds)
	local msg="$(_msgdatetime) ${@}"
	if [ -z "${UpdateReport}" -a ${ReportUpdtLapse} -ne ${NONE} ]; then
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
	local msg="${@}"
	if [ -n "${UpdtMsgs}" ]; then
		MsgTime=$(_UTCseconds)
		UpdtMsgs="${UpdtMsgs}${LF}$(_msgdatetime) ${msg}"
	else
		AddStatMsg "${msg}"
	fi
}

_exit() {
	trap - EXIT INT HUP ALRM USR1 USR2
	LogPrio="warn" _log "Exit"
	UpdateReport="" ReportUpdtLapse=1 AddStatMsg "Daemon exit"
	kill -s TERM $(_ps_children) > /dev/null 2>&1 || :
	wait || :
}

IfaceTraffic() {
	local statistics="/sys/class/net/${1:-"${WIface}"}/statistics/"
	printf '%s\n' $(( $(cat "${statistics}rx_bytes") + \
		$(cat "${statistics}tx_bytes") ))	2> /dev/null
}

BlackListHotspot() {
	local cause="${1}" \
		expires="${2}" \
		reason="${3}" \
		msg
	eval net${Hotspot}_blacklisted=\"${cause} $(_datetime)\" || :
	msg="Blacklisting $(HotspotName)"
	if [ ${expires} -gt ${NONE} ]; then
		eval net${Hotspot}_blacklistexp=\"$((expires+$(_UTCseconds)))\" || :
		msg="${msg} for ${expires} seconds"
	fi
	NetwFailures=${NONE}
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
		rc=${ERR}
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
		return ${ERR}
	bssid1="$(_toupper "$(echo "${info}" | \
			sed -nre '/^[[:blank:]]+Access Point:[[:blank:]]+(.*)$/ \
			{s//\1/p;q}')")"
	[ "${bssid}" = "${bssid1}" ] || \
		return ${ERR}
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
	while [ $((n++)) -lt ${Hotspots} ]; do
		[ -z "$(eval echo \"\${net${n}_blacklisted:-}\")" ] || \
			continue
		hotspot=${n}
		eval ssid=\"\${net${n}_ssid:-}\"
		eval bssid=\"\${net${n}_bssid:-}\"
		return ${OK}
	done
	hotspot=${NONE}
	ssid=""
	bssid="${NULLBSSID}"
}

SetEncryption() {
	local encrypt="${1:-}" \
		key="${2:-}" \
		key1="${3:-}" \
		key2="${4:-}" \
		key3="${5:-}" \
		key4="${6:-}"
	if [ -z "${encrypt}" ]; then
		eval encrypt=\"\${net${Hotspot}_encrypt:-}\"
		eval key=\"\${net${Hotspot}_key:-}\"
		eval key1=\"\${net${Hotspot}_key1:-}\"
		eval key2=\"\${net${Hotspot}_key2:-}\"
		eval key3=\"\${net${Hotspot}_key3:-}\"
		eval key4=\"\${net${Hotspot}_key4:-}\"
	fi
	uci set wireless.@wifi-iface[${WIfaceSTA}].encryption="${encrypt}"
	uci set wireless.@wifi-iface[${WIfaceSTA}].key="${key}"
	uci set wireless.@wifi-iface[${WIfaceSTA}].key1="${key1}"
	uci set wireless.@wifi-iface[${WIfaceSTA}].key2="${key2}"
	uci set wireless.@wifi-iface[${WIfaceSTA}].key3="${key3}"
	uci set wireless.@wifi-iface[${WIfaceSTA}].key4="${key4}"
}

ListStatus() {
	local msg="${@:-"Updating status report"}"
	UpdateReport="y"
	_applog "${msg}"
	if [ ${ReportUpdtLapse} -eq ${NONE} ]; then
		AddStatMsg "${msg}"
	else
		MsgTime=$(_UTCseconds)
		UpdtMsgs="$(_msgdatetime) ${msg}"
		StatMsgsChgd="y"
	fi
	NoSleep="y"
}

NetworkChange() {
	ListStatus "Network status has changed"
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
	if [ -z "${net_ssid:=""}" -a -z "${net_bssid:=""}" ] || \
	[ -z "${net_encrypt:-}" ]; then
		_msg "Adding hotspot, Invalid config." \
			"No ssid, bssid or encrypt specified"
		LogPrio="err" _log "${msg}"
		AddStatMsg "Error:" "${msg}"
		return ${ERR}
	fi
	[ $((Hotspots++)) ]
	[ -z "${net_ssid}" ] || \
		eval net${Hotspots}_ssid=\"${net_ssid}\"
	[ -z "${net_bssid}" ] || {
		net_bssid="$(_toupper "${net_bssid}")"
		eval net${Hotspots}_bssid=\"${net_bssid}\"
	}
	eval net${Hotspots}_encrypt=\"${net_encrypt}\"
	[ -z "${net_key:-}" ] || \
		eval net${Hotspots}_key=\"${net_key}\"
	[ -z "${net_key1:-}" ] || \
		eval net${Hotspots}_key1=\"${net_key1}\"
	[ -z "${net_key2:-}" ] || \
		eval net${Hotspots}_key2=\"${net_key2}\"
	[ -z "${net_key3:-}" ] || \
		eval net${Hotspots}_key3=\"${net_key3}\"
	[ -z "${net_key4:-}" ] || \
		eval net${Hotspots}_key4=\"${net_key4}\"
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
	unset net_ssid net_bssid net_encrypt \
		net_key net_key1 net_key2 net_key3 net_key4 \
		net_hidden net_blacklisted net_check
}

ConnectedBssid() {
	iwinfo "${WIface}" info 2> /dev/null | \
	awk '/^[[:blank:]]+Access Point:[[:blank:]]+/ {
		print toupper($NF)
		rc=-1
		exit}
	END{exit rc+1}'
}

ConnectedSsid() {
	iwinfo "${WIface}" info 2> /dev/null | \
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
	END{exit rc+1}'
}

ImportHotspot() {
	local net_ssid net_bssid net_encrypt net_hidden \
		net_key net_key1 net_key2 net_key3 net_key4 \
		msg add_cfg ssid
	net_ssid="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].ssid)" || :
	net_bssid="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].bssid)" || :
	net_encrypt="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].encryption)" || :
	unset net_hidden
	net_key="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].key)" || :
	net_key1="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].key1)" || :
	net_key2="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].key2)" || :
	net_key3="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].key3)" || :
	net_key4="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].key4)" || :
	if [ -z "${WwanDisabled}" -a -z "${WwanDisconnected}" ]; then
		if ssid="$(ConnectedSsid)"; then
			if [ "${ssid}" = "${NULLSSID}" ]; then
				net_hidden="y"
			elif [ -z "${net_ssid}" ]; then
				net_ssid="$(_unquote "${ssid}")"
			fi
		fi
		[ -n "${net_bssid}" ] || \
			net_bssid="$(ConnectedBssid)" || :
	fi
	[ -n "${net_ssid}" ] || unset net_ssid
	[ -n "${net_bssid}" ] && \
		net_bssid="$(_toupper "${net_bssid}")" || \
		unset net_bssid
	[ -n "${net_key}" ] || unset net_key
	[ -n "${net_key1}" ] || unset net_key1
	[ -n "${net_key2}" ] || unset net_key2
	[ -n "${net_key3}" ] || unset net_key3
	[ -n "${net_key4}" ] || unset net_key4
	msg="Importing the current router setup for the STA interface"
	[ ${Hotspots} -ne ${NONE} ] || \
		msg="No hotspots configured, ${msg}"
	LogPrio="warn" _log "${msg}"
	AddStatMsg "Warning:" "${msg}"
	add_cfg="$(set | grep -se '^net_')"
	AddHotspot || \
		return ${ERR}
	[ ${Hotspots} -ne ${NONE} -o ! -s "/etc/config/${NAME}" ] || \
		sed -i.bak \
		-re '/^[[:blank:]]*(net[[:digit:]]*_|AddHotspot)/s//# &/' \
		"/etc/config/${NAME}"
	printf '%s\n' "" \
		"# $(_datetime) Automatic hotspot import" \
		"${add_cfg}" \
		"#net_check='https://www.google.com/'" \
		"AddHotspot" >> "/etc/config/${NAME}"
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

LoadConfig() {
	local net_ssid net_bssid net_encrypt \
		net_key net_key1 net_key2 net_key3 net_key4 \
		net_hidden net_blacklisted net_check \
		msg="Loading configuration"

	# config variables, default values
	Debug=""
	ScanAuto="y"
	ReScan="y"
	ReScanOnNetwFail=1
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
	ImportAuto=""
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
		. "/etc/config/${NAME}" || \
		exit ${ERR}

	Debug="${Debug:-}"
	ScanAuto="${ScanAuto:-}"
	ReScan="${ReScan:-}"
	ReScanOnNetwFail="$(_integer_value "${ReScanOnNetwFail}" 1)"
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
	ImportAuto="${ImportAuto:-}"

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
				exit ${ERR}
				}
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
		msg="Invalid AP+STA configuration"
		LogPrio="err" _log "${msg}"
		AddStatMsg "Error:" "${msg}"
		exit ${ERR}
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
				_msg "Invalid config" \
					"Hotspot ${n}, no ssid, bssid or encryption specified"
				LogPrio="err" _log "${msg}"
				AddStatMsg "Error:" "${msg}"
				exit ${ERR}
			fi
			[ -z "${bssid}" ] || {
				bssid="$(_toupper  "${bssid}")"
				eval net${n}_bssid=\"${bssid}\"
			}
			Ssids="${Ssids:+"${Ssids}${LF}"}${bssid}${TAB}${ssid}"
			Hotspots=${n}
		done
	fi
	if [ ${Hotspots} -eq ${NONE} ]; then
		WwanDisabled="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].disabled | \
			grep -sxF "${UCIDISABLED}")" || :
		WwanDisconnected="$(test -n "${WwanDisabled}" || IsWwanDisconnected)"
		ImportHotspot || \
			exit ${ERR}
	fi
	if [ -n "$(printf '%s\n' "${Ssids}" | sort | uniq -d)" ]; then
		msg="Invalid configuration. Duplicate hotspots SSIDs or BSSIDs"
		LogPrio="err" _log "${msg}"
		AddStatMsg "Error:" "${msg}"
		exit ${ERR}
	fi

	local cdt_bssids
	cdt_bssids="$(printf '%s\n' "${Ssids}" | \
		awk 'BEGIN{FS="\t"} $1 {print NR}')"
	HotspotsOrder="$(echo ${cdt_bssids} $(seq 1 ${Hotspots} | \
		grep -svwEe "$(printf '%s' "${cdt_bssids:-0}" | \
		tr -s "${SPACE}" '|')"))"
	TryConnection=${NONE}
	ScanErr=""
	WwanErr=${NONE}
	ScanRequest=${Hotspots}
	Hotspot=${NONE}
	WwanSsid=""
	WwanBssid=""
	ConnAttempts=1
	WarnBlackList=""
	IndReScan=""
	NetwFailures=${NONE}
	Status=${NONE}
	ConnectedName=""
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
		"$(test -z "${Debug}" && echo "# Disabled" || echo "# Enabled")"
	printf '%s="%s" %s\n' "ScanAuto" "${ScanAuto}" \
		"$(test -z "${ScanAuto}" && echo "# Disabled" || echo "# Enabled")"
	printf '%s="%s" %s\n' "ReScan" "${ReScan}" \
		"$(test -z "${ReScan}" && echo "# Disabled" || echo "# Enabled")"
	printf '%s=%s %s\n' "ReScanOnNetwFail" "${ReScanOnNetwFail}" \
		"$(test ${ReScanOnNetwFail} -eq ${NONE} && echo "# Disabled" || \
		echo "# networking failures")"
	printf '%s=%d %s\n' "Sleep" "${Sleep}" "# seconds"
	printf '%s=%d %s\n' "SleepDsc" "${SleepDsc}" "# seconds"
	printf '%s=%d %s\n' "SleepScanAuto" "${SleepScanAuto}" "# seconds"
	printf '%s=%d %s\n' "BlackList" "${BlackList}" \
		"$(test ${BlackList} -eq ${NONE} && echo "# Disabled" || echo "# errors")"
	printf '%s=%d %s\n' "BlackListExpires" "${BlackListExpires}" \
		"$(test ${BlackListExpires} -eq ${NONE} && echo "# Never" || echo "# seconds")"
	printf '%s=%d %s\n' "BlackListNetwork" "${BlackListNetwork}" \
		"$(test ${BlackListNetwork} -eq ${NONE} && echo "# Disabled" || echo "# errors")"
	printf '%s=%d %s\n' "BlackListNetworkExpires" "${BlackListNetworkExpires}" \
		"$(test ${BlackListNetworkExpires} -eq ${NONE} \
			&& echo "# Never" || echo "# seconds")"
	printf '%s=%d %s\n' "PingWait" "${PingWait}" "# seconds"
	printf '%s=%d %s\n' "MinTrafficBps" "${MinTrafficBps}" \
		"$(test ${MinTrafficBps} -eq ${NONE} && echo "# Disabled" || echo "# bytes per second")"
	printf '%s=%d %s\n' "ReportUpdtLapse" "${ReportUpdtLapse}" \
		"$(test ${ReportUpdtLapse} -eq ${NONE} && echo "# Disabled" || echo "# seconds")"
	printf '%s=%d %s\n' "LogRotate" "${LogRotate}" "# log files to keep"
	printf '%s="%s" %s\n' "ImportAuto" "${ImportAuto}" \
		"$(test -z "${ImportAuto}" && echo "# Disabled" || echo "# Enabled")"
	echo
	local i=0
	while [ $((i++)) -lt ${Hotspots} ]; do
		set | awk -v i="${i}" \
			'BEGIN{FS="="}
			$1 == "net"i"_blacklistexp" {
				printf $0 " "
				system("date +%F_%X --date=@" $2)
				next}
			$1 ~ "^net"i"_" {print}'
		echo
	done
	iwinfo
	printf '%s %s\n' "Current hotspot client is" \
		"$(HotspotName)"
	printf '%s %s%s\n' "Hotspot client is" \
		"$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].disabled | \
		grep -qsxF "${UCIDISABLED}" && \
		echo "dis" || echo "en")" "abled"
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

CurrentHotspot() {
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
			END{print n+0}')"
}

MustScan() {
	[ ${ScanRequest} -le ${NONE} -a "${ScanAuto}" != "allways" ] || \
		return ${OK}
	[ -n "${ScanAuto}" ] && [ $(ActiveDefaultRoutes) -eq ${NONE} ]
}

Scanning() {
	local err i=5
	while [ $((i--)) -gt 0 ]; do
		sleep 1
		! err="$(iw "${WIface}" scan 3>&2 2>&1 1>&3 3>&-)" 2>&1 || \
			return ${OK}
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
	return ${ERR}
}

# returns hotspot ssid bssid
DoScan() {
	local forceScan="${1:-}" \
		availBssid="${2:-}" \
		availSsid="${3:-}" \
		discardAssociated="${4:-}"

	[ -n "${forceScan}" ] || \
		if ! MustScan; then
			[ -z "${Debug}" ] || \
				_applog "Must not scan"
			return ${ERR}
		fi

	BlackListExpired

	[ -z "${Debug}" ] || \
		_applog "Do-Scan - scanning"

	local scanned msg

	if ! scanned="$(Scanning)"; then
		LogPrio="err" \
		_log "Serious error: Can't scan wifi for access points"
		ScanErr="y"
		return ${ERR}
	fi
	if [ -n "${ScanErr}" ]; then
		msg="Wifi scan for access points has been successful"
		[ -z "${Debug}" ] && \
			_applog "${msg}" || \
			_log "${msg}"
		ScanErr=""
	fi
	scanned="$(printf '%s\n' "${scanned}" | \
		awk -v discardAssociated="${discardAssociated}" \
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
			if (discardAssociated && $NF == "associated") next
			bssid=toupper(substr($2,1,17))
			seen="999999999"
			signal="99"
			ssid=""
			ciph="*"
			pair="*"
			auth="*"
			next}
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
		exit rc+1}' | \
		sort -n -k 1,1)" || \
			return ${ERR}

	local i ssid1 bssid1 blacklisted hidden net_ssid \
		seen signal ciph pair auth bssid2 dummy ssid2 \
		cdts="" rc=${ERR}

	if [ -n "${availBssid}" ]; then
		while IFS="${TAB}" \
		read -r seen signal ciph pair auth bssid2 dummy ssid2 && \
		[ -n "${bssid2}" ]; do
			! test "${bssid2}" = "${availBssid}" -a \
			\( "${ssid2}" = "${availSsid}" -o \
			"${ssid2}" = "${HIDDENSSID}" -o -z "${ssid2}" \) || \
				return ${OK}
		done << EOF
${scanned}
EOF
		return ${ERR}
	fi

	local warning=""
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
			if [ -n "${blacklisted}" ]; then
				warning="${warning:+"${warning}${LF}"}${i}"
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
						"$(HotspotName "${i}" "${bssid2}" "${ssid2}")" \
						"iw scan already listed BSSID"
				continue
			fi
			if [ "${ssid2}" = "${HIDDENSSID}" -o -z "${ssid2}" ]; then
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
		if [ -n "${warning}" ]; then
			warning="$(echo $(echo "${warning}" | sort -n -k 1,1) | \
				tr -s ' ' ',')"
			if [ -n "${Debug}" -o -n "${StatMsgsChgd}" ] || \
			[ "${WarnBlackList}" != "${warning}" ]; then
				_msg "Warning, all available hotspots" \
					"(${warning}) are blacklisted"
				_applog "${msg}"
				AddMsg "${msg}"
			fi
		else
			[ -z "${Debug}" ] || \
				_applog "Do-Scan: No Hotspots available"
		fi
		WarnBlackList="${warning}"
		return ${rc}
	fi
	WarnBlackList=""
	local cdt="$(printf '%s\n' "${cdts}" | sort -n -k 1,1 | head -n 1)"
	hotspot="$(printf '%s\n' "${cdt}" | cut -f 2)"
	ssid="$(printf '%s\n' "${cdt}" | cut -f 5- -s)"
	bssid="$(printf '%s\n' "${cdt}" | cut -f 3 -s)"
	_applog "Do-Scan selects" \
		"$(HotspotName "${hotspot}" "${bssid}" "${ssid:-"${BEL}"}")"
}

WwanReset() {
	local disable="${1:-${UCIDISABLED}}" \
		iface="${2:-${WIfaceSTA}}" \
		msg

	if [ -z "${WIfaceAP}" ] && \
	[ ${disable} -eq ${UCIDISABLED} ]; then
		local hotspot ssid bssid ssid1 bssid1
		DoScan "y" || \
			AnyOtherHotspot
		Hotspot="${hotspot}"

		ssid1="$(uci -q get wireless.@wifi-iface[${iface}].ssid)" || :
		bssid1="$(_toupper "$(uci -q get \
			wireless.@wifi-iface[${iface}].bssid)")" || :
		if [ -z "${bssid1}" -a "${ssid1}" = "${ssid}" ] || \
		[ -z "${ssid1}" -a "${bssid1}" = "${bssid}" ] || \
		[ -n "${ssid1}" -a -n "${bssid1}" \
		-a "${ssid1}" = "${ssid}" -a "${bssid1}" = "${bssid}" ]; then
			return ${OK}
		fi
		WwanSsid="${ssid}"
		WwanBssid="${bssid}"
		uci set wireless.@wifi-iface[${iface}].ssid="${ssid}"
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
		disabled="$(uci -q get wireless.@wifi-iface[${iface}].disabled | \
			grep -sxF "${UCIDISABLED}")" || :
		[ ${disabled:-"0"} -ne ${disable} ] || \
			return ${OK}
		[ ${disable} -eq ${UCIDISABLED} ] && \
			uci set wireless.@wifi-iface[${iface}].disabled=${disable} || \
			uci -q delete wireless.@wifi-iface[${iface}].disabled || :
		_msg "$([ ${disable} -eq ${UCIDISABLED} ] && \
			echo "Dis" || echo "En")abling wireless" \
			"$([ "${iface}" = "${WIfaceSTA}" ] && \
				echo "interface to $(HotspotName)" || \
				echo "Access Point")"
	fi

	! test ${iface} -eq ${WIfaceSTA} -a ${disable} -eq ${UCIDISABLED} || \
		Hotspot=${NONE}

	_log "${msg}"
	AddStatMsg "${msg}"

	wifi down "${WDevice}"
	wifi up "${WDevice}"
	UpdateReport="y"
	WatchWifi &
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
	local encrypt wencrypt \
		key key1 key2 key3 key4 \
		wkey wkey1 wkey2 wkey3 wkey4 \
		hidden
	eval encrypt=\"\${net${Hotspot}_encrypt:-}\"
	eval key=\"\${net${Hotspot}_key:-}\"
	eval key1=\"\${net${Hotspot}_key1:-}\"
	eval key2=\"\${net${Hotspot}_key2:-}\"
	eval key3=\"\${net${Hotspot}_key3:-}\"
	eval key4=\"\${net${Hotspot}_key4:-}\"
	eval hidden=\"\${net${Hotspot}_hidden:-}\"
	wencrypt="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].encryption)" || :
	wkey="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].key)" || :
	wkey1="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].key1)" || :
	wkey2="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].key2)" || :
	wkey3="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].key3)" || :
	wkey4="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].key4)" || :
	if [ "${ssid}" != "${WwanSsid}" -a \
	\( -z "${hidden}" -o -n "${ssid}" \) ] || \
	[ "${bssid}" != "${WwanBssid}" -o \
	"${encrypt}" != "${wencrypt}" -o \
	"${key}" != "${wkey}" -o "${key1}" != "${wkey1}" -o \
	"${key2}" != "${wkey2}" -o "${key3}" != "${wkey3}" -o \
	"${key4}" != "${wkey4}" ]; then
		WwanSsid="${ssid}"
		WwanBssid="${bssid}"
		_log "Hotspot $(HotspotName) found. Applying settings..."
		WwanErr=${NONE}
		uci set wireless.@wifi-iface[${WIfaceSTA}].ssid="${WwanSsid}"
		uci set wireless.@wifi-iface[${WIfaceSTA}].bssid="${WwanBssid}"
		SetEncryption "${encrypt}" \
			"${key}" "${key1}" "${key2}" "${key3}" "${key4}"
		if [ -z "${WwanDisabled}" ]; then
			wifi down "${WDevice}"
			wifi up "${WDevice}"
		else
			uci -q delete wireless.@wifi-iface[${WIfaceSTA}].disabled || :
			/etc/init.d/network reload
		fi
		TryConnection=2
		msg="Connecting to $(HotspotName)..."
		_log "${msg}"
		AddStatMsg "${msg}"
		WatchWifi ${Sleep} &
	elif [ -n "${WwanDisabled}" ]; then
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
		ScanRequest=${NONE}
		_msg "Can't connect to any hotspot," \
			"probably configuration is not correct"
		LogPrio="err" _log "${msg}"
		AddStatMsg "${msg}"
	else
		Interval=${Sleep}
	fi
	[ ${ScanRequest} -le ${NONE} ] || \
		[ $((ScanRequest--)) ]
}

ReScanning() {
	local hotspot ssid bssid msg
	msg="Re-scanning"
	_applog "${msg}"
	AddMsg "${msg}"
	NoSleep="y"
	DoScan "y" || \
		return ${OK}
	if [ "${ssid}" = "${WwanSsid}" -a "${bssid}" = "${WwanBssid}" ]; then
		msg="Actually the best hotspot is $(HotspotName)"
		_applog "${msg}"
		AddMsg "${msg}"
		return ${OK}
	fi
	ClrStatMsgs
	msg="Reconnection required"
	_applog "${msg}"
	AddMsg "${msg}"
	HotspotLookup "" "${hotspot}" "${bssid}" "${ssid}"
}

ReScanningOnNetwFail() {
	[ ${ReScanOnNetwFail} -ne ${NONE} ] && \
	[ ${NetwFailures} -ge ${ReScanOnNetwFail} ] || \
		return ${OK}
	local hotspot ssid bssid msg
	msg="Re-scanning on networking failure"
	_applog "${msg}"
	AddMsg "${msg}"
	if DoScan "y" "" "" "y"; then
		ClrStatMsgs
		msg="Reconnection required"
		_applog "${msg}"
		AddMsg "${msg}"
		HotspotLookup "" "${hotspot}" "${bssid}" "${ssid}"
		NoSleep=""
		return ${ERR}
	fi
	msg="Another hotspot is not available"
	AddMsg "${msg}"
	[ -z "${Debug}" ] || \
		_applog "${msg}"
}

CheckNetw() {
	{ [ "${Debug}" = "xtrace" ] && \
		exec >&2 || \
		exec > /dev/null 2>&1; } 2> /dev/null
	if [ -n "${CheckSrvr}" ]; then
		if [ -n "${CheckInet}" ]; then
			wget -nv --spider -T ${PingWait} --no-check-certificate \
			--bind-address "${CheckInet}" "${CheckAddr}" 2>&1 | \
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
		return ${OK}
	fi
	Interval=${Sleep}
	local delay=${Sleep} msg rc
	while [ -z "${Gateway:="$(ip -4 route show default dev "${WIface}" 2> /dev/null | \
	awk '$1 == "default" && \
	$3 ~ /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/ {print $3; exit}')"}" ] && \
	[ $((delay--)) -gt 0 ]; do
		sleep 1
	done
	[ -n "${CheckAddr}" ] || \
		if CheckSrvr="$(printf '%s\n' "${check}" | \
		sed -nre '\|^http[s]?://([^/]+).*| s||\1|p')" && \
		[ -n "${CheckSrvr}" ]; then
			CheckAddr="${check}"
			if [ -z "$(which wget)" ] ||  \
			! CheckInet="$(ip -o -4 addr show "${WIface}" 2> /dev/null | \
			awk 'BEGIN{FS="[ \t\n/]+"}
			$4 ~ /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/ {print $4; rc=-1}
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
				return ${OK}
			fi
			[ -z "${Debug}" ] || \
				_applog "check networking, ping ${CheckAddr}"
		fi
	rc=${ERR}
	if [ ${MinTrafficBps} -ne ${NONE} ]; then
		local r=$(IfaceTraffic) \
			c=$(_UTCseconds)
		if [ -n "${CheckTime}" ]; then
			local b=$((${r}-Traffic)) \
				t=$((${c}-CheckTime))
			if [ ${t} -gt 0 ] && \
			[ $((b/t)) -ge ${MinTrafficBps} ]; then
				rc=${OK}
				_msg "Networking of $(HotspotName) to" \
					"the external network does work"
			fi
			[ -z "${Debug}" ] || \
				_applog "STA interface received ${b} bytes in ${t} seconds"
		fi
		CheckTime=${c}
		Traffic=${r}
	fi
	if [ ${rc} -ne ${OK} ]; then
		CheckNetw &
		rc=${OK}
		WaitSubprocess && \
			_msg "Networking of $(HotspotName) to" \
				"$(test "${CheckAddr}" != "${Gateway}" || \
				echo "gateway:")${CheckAddr}" \
				"has been verified" || \
			rc=${?}
	fi
	if [ ${rc} -eq ${OK} ]; then
		if [ ${Status} -eq ${CONNECTED} -a ${NetwFailures} -eq ${NONE} ]; then
			[ -z "${Debug}" -a  -z "${StatMsgsChgd}" ] || \
				_applog "${msg}"
			[ -z "${StatMsgsChgd}" ] || \
				AddMsg "${msg}"
		else
			AddMsg "${msg}"
			[ ${NetwFailures} -eq ${NONE} ] && \
				_applog "${msg}" || \
				_log "${msg}"
			NetwFailures=${NONE}
		fi
		return ${OK}
	elif [ ${rc} -gt 127 -a ${rc} -ne 143 ]; then
		return ${OK}
	fi
	[ $((NetwFailures++)) ]
	_msg "${NetwFailures} networking" \
		"failure$([ ${NetwFailures} -le 1 ] || echo "s")" \
		"on $(HotspotName)"
	LogPrio="warn" _log "${msg}"
	ReScanningOnNetwFail || \
		return ${ERR}
	if [ ${BlackListNetwork} -ne ${NONE} ] && \
	[ ${NetwFailures} -ge ${BlackListNetwork} ]; then
		BlackListHotspot "network" "${BlackListNetworkExpires}" "${msg}"
		if HotspotLookup; then
			return ${ERR}
		elif [ ${?} -ne ${ERR} -o -n "${WIfaceAP}" ]; then
			WwanReset
		fi
		Status=${DISCONNECTED}
		[ -z "${Debug}" ] || \
			_applog "$(StatusName)"
		ScanRequest=1
		return ${ERR}
	fi
	AddStatMsg "${msg}"
	NoSleep=""
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
	[ -n "${StatMsgsChgd}" -a ${ReportUpdtLapse} -eq ${NONE} ]; then
		StatMsgsChgd=""
		UpdateReport=""
		Report &
		WaitSubprocess "" "y" || :
		UpdtMsgs=""
	elif [ ${ReportUpdtLapse} -ne ${NONE} ] && \
	( [ $((tl=$(_UTCseconds)-MsgTime)) -lt 0 ] || \
	[ ${ReportUpdtLapse} -lt ${tl} ] ); then
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
	readonly OK=0 ERR=1 UCIDISABLED=1 \
		LF=$'\n' TAB=$'\t' BEL=$'\x07' SPACE=' \t\n\r' \
		HIDDENSSID="\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
		NULLSSID="unknown" NULLBSSID="00:00:00:00:00:00" \
		NONE=0 DISCONNECTED=1 CONNECTING=2 DISABLED=3 CONNECTED=4
	# config variables
	local Debug ScanAuto ReScan ReScanOnNetwFail \
		Sleep SleepDsc SleepScanAuto \
		BlackList BlackListExpires BlackListNetwork BlackListNetworkExpires \
		PingWait MinTrafficBps LogRotate ReportUpdtLapse ImportAuto
	# internal variables, daemon scope
	local WwanSsid WwanBssid WwanDisabled WwanErr \
		Ssids Hotspots HotspotsOrder IfaceWan \
		ConnectedName ScanRequest ScanErr IndReScan \
		Status StatMsgsChgd StatMsgs MsgTime \
		UpdateReport UpdtMsgs Interval NoSleep \
		Hotspot ConnAttempts NetwFailures Traffic CheckTime \
		LogPrio WarnBlackList \
		Gateway CheckAddr CheckSrvr CheckInet CheckPort \
		TryConnection WIface WIfaceAP WIfaceSTA WDevice \
		WwanDisconnected msg

	trap '_exit' EXIT
	trap 'exit' INT

	LoadConfig || \
		exit ${ERR}
	Interval=${Sleep}

	! printf '%s\n' "${@}" | grep -qsxiF 'import' || \
		ImportAuto="y"

	trap 'LoadConfig' HUP
	trap 'NetworkChange' ALRM
	trap 'PleaseScan' USR1
	trap 'ListStatus' USR2

	while Settle; do
		WwanDisabled="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].disabled | \
			grep -sxF "${UCIDISABLED}")" || :
		if [ -z "${WIfaceAP}" -a -n "${WwanDisabled}" ] || \
		( [ -n "${WIfaceAP}" ] && \
		[ "$(uci -q get wireless.@wifi-iface[${WIfaceAP}].disabled)" = ${UCIDISABLED} ] ); then
			WwanReset 0 "${WIfaceAP}"
			Interval=${Sleep}
			continue
		fi
		WwanSsid="$(uci -q get wireless.@wifi-iface[${WIfaceSTA}].ssid)" || :
		WwanBssid="$(_toupper "$(uci -q get \
			wireless.@wifi-iface[${WIfaceSTA}].bssid)")" || :
		WwanDisconnected="$(test -n "${WwanDisabled}" || IsWwanDisconnected)"
		CurrentHotspot
		if [ -z "${WwanDisabled}" -a -z "${WwanDisconnected}" ]; then
			TryConnection=${NONE}
			ScanErr=""
			WwanErr=${NONE}
			if [ "${ConnectedName}" != "$(HotspotName)" -o \
			${Status} -ne ${CONNECTED} ]; then
				if [ ${Hotspot} -eq ${NONE} ]; then
					LogPrio="warn" \
					_log "Connected to a non-configured hotspot:" \
						"$(HotspotName)"
					if [ -n "${ImportAuto}" ]; then
						if ImportHotspot; then
							LoadConfig || \
								exit ${ERR}
							msg="This connected hotspot has been imported to the config file"
							_applog "${msg}"
							AddStatMsg "${msg}"
							continue
						fi
						msg="Can't import this connected hotspot to the config file"
						_applog "${msg}"
						AddStatMsg "${msg}"
					fi
				fi
				NetwFailures=${NONE}
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
					ConnectedName="$(HotspotName)"
					ScanRequest=${NONE}
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
		if [ ${TryConnection} -gt ${NONE} ]; then
			if DoScan "y" "${WwanBssid}" "${WwanSsid}"; then
				[ $((TryConnection--)) ]
				continue
			fi
			TryConnection=${NONE}
			msg="Hotspot $(HotspotName) is gone while connecting"
			_log "${msg}"
			AddStatMsg "${msg}"
		fi
		if [ -z "${WwanDisabled}" -a -n "${WwanDisconnected}" ]; then
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
						BlackListHotspot "connect" "${BlackListExpires}" \
							"${msg}"
						WwanSsid=""
						uci -q delete wireless.@wifi-iface[${WIfaceSTA}].ssid || :
						WwanBssid="${NULLBSSID}"
						uci -q delete wireless.@wifi-iface[${WIfaceSTA}].bssid || :
					else
						LogPrio="warn" _log "${msg}"
						[ $((ConnAttempts++)) ]
					fi
				fi
			fi
			if HotspotLookup; then
				continue
			elif [ ${?} -ne ${ERR} -o -n "${WIfaceAP}" ]; then
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
		if [ -z "${WwanDisabled}" -a -n "${WIfaceAP}" ]; then
			Interval=${Sleep}
		elif [ -n "${ScanAuto}" ] && \
		[ $(ActiveDefaultRoutes) -eq ${NONE} ]; then
			Interval=${SleepDsc}
		else
			Interval=${SleepScanAuto}
		fi
		[ ${ScanRequest} -le ${NONE} ] || \
			[ $((ScanRequest--)) ]
	done
}

set -o errexit -o nounset -o pipefail +o noglob
NAME="$(basename "${0}")"
case "${1:-}" in
start)
	shift
	WifiStatus "${@}"
	;;
*)
	echo "Wrong arguments" >&2
	exit 1
	;;
esac
