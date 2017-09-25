# wwanHotspot
OpenWrt daemon to maintain allways up a dual wifi config: Access Point and HotSpot client

Fix loss of AP when WWAN (Hotspot client) mode fails by disabling the WWAN client.

Configuration contains a list of Hotspots to connect, will re-enable the WWAN client when one becomes available. Also will look periodically for a Hotspot if ScanAuto is not null or else when a scan request is received.

Note: ScanAuto is not recommended because overloads the wifi interface, is better request an scan to the daemon via ssh or telnet.
