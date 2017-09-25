# wwanHotspot

It is designed to connect an OpenWrt router to devices that share the Internet connection through a wifi Hotspot, such as mobile phones. In one place there may be several Hotspots that will be available or not according to the comings and goings of their owners; we will enter the parameters of each one of them in the configuration file therefore wwanHotspot will connect and disconnect the OpenWrt HotSpot client to one of them as they become available.

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

/etc/init.d/wwanHotspot enable ; /etc/init.d/wwanHotspot start

# Operation

At start the daemon will look once for a HotSpot.
After HotSpot disconnection will look for availability of an other.

Automatically receives an scan signal when the HotSpot is disconnected, wwanHotspot deactivates the interface and maintains AP allways up.

The ScanAuto method is not recommended because overloads the wifi interface, so it's preferred that we request a HotSpot scan issuing the following command when a HotSpot becomes available:

/etc/init.d/wwanHotspot scan

After changing the config file we must not reload the Daemon because reload is automatic if we update the config file while the daemon is running.

/etc/init.d/wwanHotspot reload # not required

# Comments

Fix loss of AP when WWAN (Hotspot client) mode fails by disabling the WWAN client.

Configuration contains a list of Hotspots to connect, will re-enable the WWAN client when one becomes available. Also will look periodically for a Hotspot if ScanAuto is not null or else when a scan request is received.

Note: ScanAuto is not recommended because overloads the wifi interface, requesting an scan to the daemon via ssh or telnet is better.
