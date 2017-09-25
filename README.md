# wwanHotspot
OpenWrt daemon to maintain allways up a dual wifi config: Access Point and HotSpot client

It is designed to connect an OpenWrt router to devices that share the Internet connection through a Hotspot, such as mobile phones. In one place there may be several Hotspots that will be available or not according to the comings and goings of their owners; we will enter the parameters of each one of them in the configuration file; then wwanHotspot will connect and disconnect the OpenWrt router to them as they become available

# Installation
Configure wifi interfaces according to the OpenWrt wiki.

https://wiki.openwrt.org/doc/recipes/ap_sta

and install wwanHotspot via ssh or telnet,

1- copy the files

cp files/wwanHotspot.config /etc/config/wwanHotspot
cp files/wwanHotspot.init /etc/init.d/wwanHotspot
cp files/wwanHotspot.sh /usr/sbin/wwanHotspot
chmod a+x /etc/init.d/wwanHotspot /usr/sbin/wwanHotspot

2- edit the config file and set your HotSpots parameters.

vi /etc/config/wwanHotspot

Multiple HotSpots are allowed, the daemon will try to connect to any of them by rotation.

3- enable the daemon and start it

/etc/init.d/wwanHotspot enable
/etc/init.d/wwanHotspot start

# Operation

When the daemon starts will look once for a HotSpot.

Automatically receives an scan signal when the HotSpot is disconnected and deactivates the interface.

ScanAuto is not recommended because overloads the wifi interface, so we must issue the following command when a HotSpot is activated:

/etc/init.d/wwanHotspot scan

Daemon reload is automatic if we edit the config file while the daemon is running.

# Comments

Fix loss of AP when WWAN (Hotspot client) mode fails by disabling the WWAN client.

Configuration contains a list of Hotspots to connect, will re-enable the WWAN client when one becomes available. Also will look periodically for a Hotspot if ScanAuto is not null or else when a scan request is received.

Note: ScanAuto is not recommended because overloads the wifi interface, requesting an scan to the daemon via ssh or telnet is better.
