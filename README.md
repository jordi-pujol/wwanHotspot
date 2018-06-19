# wwanHotspot

It is designed to connect an OpenWrt router to devices that share the Internet connection through a wifi Hotspot, such as mobile phones.

In one place there may be several Hotspots that may be available or not according to the comings and goings of their owners; we will enter the parameters of each one of them in the configuration file therefore wwanHotspot will connect and disconnect the OpenWrt Hotspot client to one of them as they become available.

# Installation
Configure wifi interfaces according to the OpenWrt wiki.

https://wiki.openwrt.org/doc/recipes/ap_sta

and install the package wwanHotspot via ssh or telnet,

0- for better routing, installation of the following packages is advised:
   ```
   opkg install ip ipset iptables iptables-mod-conntrack-extra iptables-mod-ipopt
   ```
1- Install the ipk:
   ```
   opkg install wwanHotspot_VERSION_all.ipk
   ```
2- edit the config file and set your Hotspots parameters.
   ```
   vi /etc/config/wwanHotspot
   ```

3- enable the daemon and start it
   ```
   /etc/init.d/wwanHotspot enable
   /etc/init.d/wwanHotspot restart
   ```
# Configuration

Variables named Debug and ScanAuto are indicators, value is false when null or not set, true when they have any value.

A log is written to the file "/var/log/wwanHotspot".

Debug enabled will make a more verbose log to the file "/var/log/wwanHotspot".

When Debug is set to xtrace will log shell commands to the file "/var/log/wwanHotspot.xtrace".

We can enable ScanAuto to look periodically for a Hotspot only when the Wan interface is disconnected, the time interval is stored in variable Sleep. Setting ScanAuto to the special value "allways" makes wwanHotspot not care of the Wan interface status and will scan periodically, but is better request an scan to the daemon via ssh or telnet. ScanAuto "allways" is not recommended because overloads too much the wifi interface, to avoid this the program increases the time between scans; the value of the large time lapsus is SleepScanAuto. Recommend values are:
   ```
   Sleep=20
   SleepScanAuto="$(($Sleep*15))"
   ```
The variable BlackList contains the number of failed consecutive connections needed to blacklist a hotspot. Blacklisting will be disabled when the variable BlackList is set to 0. The current black list is reset when the configuration is reloaded.
   ```
   BlackList=3
   ```
Set the list of network values for your Hotspots. Multiple Hotspots are allowed, wwanHotspot will try to connect to any of them by rotation. If the list is not populated then wwanHotspot will use the current configuration for this interface.

After changing the config file we must reload the daemon.

# Hidden SSIDs

Each one of the Hotspots may have a variable "netX_hidden" with value:

1- unset or no value when the SSID is not hidden, 

2- "y" when the SSID is hidden and "iw wlan0 scan" doesn't show an SSID for this hotspot.
   ```
   netX_hidden="y"
   ```

3- "iw wlan0 scan" lists an SSID value that doesn't correspond to the hotspot's "netX_ssid"
   ```
   netX_hidden="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
   ```

# Operation

At start wwanHotspot will look once for a Hotspot.
Also will look for availability of another Hotspot after disconnection.

Automatically receives an scan signal when the Hotspot is disconnected, wwanHotspot deactivates the Hotspot client interface and maintains AP allways up.

When the Hotspot client is disconnected and we know that one Hotspot is available we can request a wifi scan issuing the following command:
   ```
   /etc/init.d/wwanHotspot scan
   ```
If we update the config file while wwanHotspot is running we must reload the daemon,
the change is not detected in my current version of OpenWrt.
   ```
   /etc/init.d/wwanHotspot reload # maybe required or not
   ```
# Enhanced routing

Advising installation of other IP related packages for better routing,
iproute will set one default route for each WAN interface that is enabled
and conntrack ensures that the delivery of IP packets is done correctly
when multiple default routes are enabled..
