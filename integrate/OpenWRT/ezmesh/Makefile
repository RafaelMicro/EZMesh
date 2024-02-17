# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#


LOCAL_SOURCE_DIR:=$(abspath $(realpath $(dir $(lastword $(MAKEFILE_LIST))))/../../..)
include $(TOPDIR)/rules.mk

PKG_NAME:=ezmesh
PKG_VERSION:=0.0.0


include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

CMAKE_SOURCE_DIR=$(LOCAL_SOURCE_DIR)
CMAKE_OPTIONS+= \
	-DCONFIG_CONTROLLER=true \
	-DCONFIG_UPGRADE=true \
	-DCONFIG_BLUETOOTH=true \
	-DCONFIG_BORDER_ROUTER=true \
	-DCONFIG_ZIGBEE_GW_SERVICE=true \
	-DCONFIG_SUBG_SERVICE=true \
	-DBUILD_TESTING=OFF \
	-DOTBR_DBUS=OFF \
	-DCMAKE_INSTALL_PREFIX=/usr \
	-DOTBR_BORDER_AGENT=ON \
	-DOTBR_BORDER_ROUTING=ON \
	-DOTBR_INFRA_IF_NAME=\"br-lan\" \
	-DOTBR_MDNS="avahi" \
	-DOTBR_OPENWRT=ON \
	-DOTBR_SRP_ADVERTISING_PROXY=ON \
	-DOT_FIREWALL=OFF \
	-DOT_POSIX_SETTINGS_PATH=\"/etc/openthread\" \
	-DOT_READLINE=OFF \
	-DOTBR_WEB=OFF \
	-DOTBR_NAT64=OFF \
	-DNAT64_SERVICE=\"openthread\"

define Package/ezmesh
	TITLE:=EZMesh
	SECTION:=net
	CATEGORY:=Network
	DEPENDS:= +libstdcpp +jsoncpp +libjson-c +libubus +libblobmsg-json +libavahi-client +avahi-daemon +iptables-mod-extra +ipset
endef

define Package/ezmesh/description
  Rafale EZMesh.
endef

define Package/ezmesh/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/ezmeshd $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/ezmesh-upgrade $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/ez-bluetooth $(1)/usr/bin
	$(INSTALL_DIR) $(1)/usr/etc
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/etc/ez_config.ini $(1)/usr/etc/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/otbr-agent $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/ot-ctl $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libezmesh.so.* $(1)/usr/lib/
endef


$(eval $(call BuildPackage,ezmesh))
