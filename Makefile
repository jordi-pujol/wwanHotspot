#
#  wwanHotspot
#
#  Wireless WAN Hotspot management application for OpenWrt routers.
#  $Revision: 1.23 $
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

# Makefile for OpenWrt, in development, has not been tested

include $(TOPDIR)/rules.mk

PKG_NAME:=wwanHotspot
PKG_VERSION:=1.23
PKG_RELEASE:=1

PKG_SOURCE_URL:=https://github.com/jordi-pujol/wwanHotspot
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz

MAINTAINER:=Jordi Pujol <jordipujolp AT gmail DOT com>
PKG_LICENSE:=GPLv3
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/wwanHotspot
	SECTION:=net
	CATEGORY:=Network
	TITLE:=wwanHotspot OpenWrt daemon to maintain allways up a dual wifi config.
	URL:=https://github.com/jordi-pujol/wwanHotspot/
	DEPENDS:=+iwinfo
	PKGARCH:=all
endef

define Package/wwanHotspot/description
	wwanHotspot is an OpenWrt daemon to maintain allways up a dual wifi config:
	Access Point and HotSpot client.
endef

define Build/Prepare
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/wwanHotspot/conffiles
	/etc/config/$(PKG_NAME)
endef

define Package/wwanHotspot/install
	$(INSTALL_DIR)  $(1)/usr/sbin \
		$(1)/etc/init.d \
		$(1)/etc/config
	$(INSTALL_BIN) ./files/$(PKG_NAME).init $(1)/etc/init.d/$(PKG_NAME)
	$(INSTALL_BIN) ./files/$(PKG_NAME).sh $(1)/usr/sbin/$(PKG_NAME)
	$(INSTALL_DATA) ./files/$(PKG_NAME).config $(1)/etc/config/$(PKG_NAME)
endef

$(eval $(call BuildPackage,wwanHotspot))
