#!/bin/sh
#
# Fix loss of AP when WWAN (Hotspot client) mode fails
# by disabling the WWAN client.
# Configuration contains a list of Hotspots to connect, will
# re-enable the WWAN client when one becomes available.
# Will look periodically for a Hotspot if ScanAuto is not null or 
# else when a scan request is received.
# Note: ScanAuto is not recommended because overloads the wifi interface,
# is better request an scan to the daemon via ssh or telnet.

# config variables, default values
Debug=""
ScanAuto=""
Sleep=60
SleepScanAuto="$((${Sleep}*10))"

_sleep() {
	local s="${1:-"${Slp}"}"
	( set +x
	while [ ${s} -gt 0 ]; do
		sleep 1
		printf '%s' "." >&2
		s=$((${s}-1))
	done ) &
	PidSleep="${!}"
	wait "${PidSleep}" || :
	PidSleep=""
}

ScanRequested() {
	[ -n "${PidSleep}" -a ${ScanRequest} -eq 0 ] || \
		return 0
	WwanErr=0
	ScanRequest=${CfgSsidsCnt}
	kill -TERM "${PidSleep}" || :
}

_exit() {
	kill -TERM $(ps --no-headers --ppid "${PidDaemon}" -o pid) || :
	wait || :
}

LoadConfig() {
	local n=0 ssid

	[ ! -s "/etc/config/${NAME}" ] || \
	. "/etc/config/${NAME}"

	if [ -n "${Debug}" ]; then
		set -x
		exec > "/var/log/${NAME}" 2>&1
	else
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
	done
	[ -n "${CfgSsids}" ] || \
		CfgSsids="${WwanSsid}"
	[ -n "${CfgSsids}" ] || \
		exit 1
	CfgSsidsCnt="$(printf '%s\n' "${CfgSsids}" | wc -l)"
	WwanErrMax=$((${CfgSsidsCnt}*2))
}

DoScan() {
	local ssid scanned n i

	scanned="$(iw wlan0 scan | \
		awk '$1 == "SSID:" {print}' | \
		cut -f 2- -s -d ' ')"
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
	local CfgSsids CfgSsidsCnt ssid WwanSsid WwanErrMax

	# internal variables, daemon scope
	local PidDaemon="${$}"
	local ScanRequest=1
	local Slp=${Sleep}
	local WwanErr=0
	local Status=0
	local PidSleep=""

	trap '_exit' EXIT

	WwanSsid="$(uci -q get wireless.@wifi-iface[1].ssid)" || :
	LoadConfig || exit 1

	trap 'LoadConfig' HUP
	trap 'ScanRequested' USR1

	while :; do
		if iwinfo | grep -qsre "wlan0[[:blank:]]*ESSID: unknown"; then
			uci set wireless.@wifi-iface[1].disabled=1
			uci commit wireless
			/etc/init.d/network restart
			Slp=${Sleep}
			if [ ${Status} != 1 ]; then
				logger -t "${NAME}" \
					"Disabling wireless device for Hotspot."
				Status=1
				ScanRequest=1
			fi
			_sleep 5
		fi
		if iwinfo | \
		grep -qsre 'wlan0[[:blank:]]*ESSID: "'"${WwanSsid}"'"'; then
			ScanRequest=0
			WwanErr=0
			Slp=${Sleep}
			if [ ${Status} != 2 ]; then
				logger -t "${NAME}" \
					"Hotspot ${WwanSsid} is connected."
				Status=2
			fi
		elif [ -n "${ScanAuto}" -o ${ScanRequest} -gt 0 ] && \
		ssid="$(DoScan)"; then
			local n wifi_change=""
			n="$(printf '%s\n' "${ssid}" | \
				cut -f 1 -s -d ':')"
			ssid="$(printf '%s\n' "${ssid}" | \
				cut -f 2- -s -d ':')"
			if [ "${ssid}" != "${WwanSsid}" ]; then
				eval encrypt=\"\$net${n}_encrypt\"
				eval key=\"\$net${n}_key\"
				WwanErr=0
				wifi_change=y
				logger -t "${NAME}" \
					"${ssid}" network found. Applying settings..
				uci set wireless.@wifi-iface[1].ssid="${ssid}"
				uci set wireless.@wifi-iface[1].encryption="${encrypt}"
				uci set wireless.@wifi-iface[1].key="${key}"
				WwanSsid="${ssid}"
			fi
			if [ "$(uci -q get wireless.@wifi-iface[1].disabled)" = 1 ]; then
				uci set wireless.@wifi-iface[1].disabled=0
				wifi_change=y
			fi
			if [ -n "${wifi_change}" ]; then
				uci commit wireless
				wifi down
				wifi up
				logger -t "${NAME}" \
					"Connecting to '${WwanSsid}'..."
				Slp=5
			fi
			WwanErr=$((${WwanErr}+1))
			if [ ${WwanErr} -ge ${WwanErrMax} ] && \
			[ ${Status} != 3 ]; then
				ScanRequest=0
				[ -z "${ScanAuto}" ] || \
					Slp=${SleepScanAuto}
				logger -t "${NAME}" \
					"Error: can't connect to Hotspots, probably configuration is not correct."
				Status=3
			fi
		else
			WwanErr=0
			Slp=${Sleep}
			if [ ${Status} != 4 ]; then
				logger -t "${NAME}" \
					"A Hotspot is not available."
				Status=4
				Slp=5
			fi
		fi
		[ ${ScanRequest} -eq 0 ] || \
			ScanRequest=$((${ScanRequest}-1))
		_sleep
	done
}

NAME="$(basename "${0}")"
case "${1:-}" in
start)
	WifiStatus
	;;
*)
	echo "Wrong arguments"
	;;
esac
