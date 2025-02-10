# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#


LOCAL_SOURCE_DIR:=$(abspath $(realpath $(dir $(lastword $(MAKEFILE_LIST))))/../../..)
include $(TOPDIR)/rules.mk

PKG_NAME:=ezmesh
PKG_VERSION:=2.0.0


include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

CMAKE_SOURCE_DIR=$(LOCAL_SOURCE_DIR)
CMAKE_OPTIONS+= \
	-DEZMESH_CRC_0=0 \
	-DCONFIG_CONTROLLER=true \
	-DCONFIG_UPGRADE=true \
	-DCONFIG_BLUETOOTH=true \
	-DCONFIG_BORDER_ROUTER=true \
	-DCONFIG_ZIGBEE_GW_SERVICE=true \
	-DOTBR_VENDOR_NAME="Rafale" \
	-DOTBR_PRODUCT_NAME="EZMesh" \
	-DOTBR_RADIO_URL=\"spinel+ezmesh://ezmeshd_0\" \
	-DBUILD_TESTING=OFF \
	-DOTBR_DBUS=ON \
	-DCMAKE_INSTALL_PREFIX=/usr \
	-DOTBR_BORDER_AGENT=ON \
	-DOTBR_BORDER_ROUTING=ON \
	-DOTBR_INFRA_IF_NAME=\"eth0\" \
	-DOTBR_MDNS="mDNSResponder" \
	-DOTBR_OPENWRT=ON \
	-DOTBR_SRP_ADVERTISING_PROXY=ON \
	-DOT_FIREWALL=OFF \
	-DOT_POSIX_SETTINGS_PATH=\"/etc/openthread\" \
	-DOT_READLINE=OFF \
	-DOTBR_NAT64=OFF \
	-DOTBR_BACKBONE_ROUTER=ON \
	-DOT_BACKBONE_ROUTER=ON \
	-DOT_BORDER_ROUTING=ON \
	-DOT_MLR=ON \
	-DOT_MLR=ON -DOTBR_COVERAGE=ON -DOT_SRP_SERVER=ON -DOT_ECDSA=ON -DOT_SERVICE=ON -DOTBR_DUA_ROUTING=ON -DOT_DUA=ON \
	-DNAT64_SERVICE=\"openthread\"

#TARGET_CFLAGS += -DOPENTHREAD_POSIX_CONFIG_DAEMON_SOCKET_BASENAME=\\\"/tmp/openthread-%s\\\" -DOTBR_ENABLE_PUBLISH_MESHCOP_BA_ID=1 -DOT_DUA=ON -DOT_MLR=ON -DOT_BACKBONE_ROUTER_DUA_NDPROXYING=ON

TARGET_CFLAGS += -DOPENTHREAD_POSIX_CONFIG_DAEMON_SOCKET_BASENAME=\\\"/tmp/openthread-%s\\\" -DOT_MLR=ON -DOTBR_COVERAGE=ON -DOT_SRP_SERVER=ON -DOT_ECDSA=ON -DOT_SERVICE=ON -DOTBR_DUA_ROUTING=ON -DOT_DUA=ON

define Package/ezmesh
	TITLE:=EZMesh
	SECTION:=net
	CATEGORY:=Network
	DEPENDS:= +libstdcpp +jsoncpp +libjson-c +libnetfilter-queue +libubus +libdbus +libncurses +libblobmsg-json +mdnsresponder +iptables-mod-extra +ipset +protobuf
endef

define Package/ezmesh/description
  Rafale EZMesh.
endef

define Package/ezmesh/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/ezmeshd $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/ezmesh-upgrade $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/ez-bluetooth $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/ezmesh-zbgw $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/ezmesh-zbbackup $(1)/usr/bin
	$(INSTALL_DIR) $(1)/usr/var/lib/ezmesh-zbgw/zbdb
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/var/lib/ezmesh-zbgw/zbdb/sc_enddevice.dat $(1)/usr/var/lib/ezmesh-zbgw/zbdb
	$(INSTALL_DIR) $(1)/usr/etc
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/etc/ez_config.ini $(1)/usr/etc/
	$(INSTALL_DIR) $(1)/etc/dbus-1
	$(INSTALL_DIR) $(1)/etc/dbus-1/system.d
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/etc/dbus-1/system.d/otbr-agent.conf $(1)/etc/dbus-1/system.d
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/otbr-agent $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/ot-ctl $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libezmesh.so.* $(1)/usr/lib/
	
	$(INSTALL_DIR) $(1)/etc/openthread
	
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/etc/init.d/* $(1)/etc/init.d

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(PKG_INSTALL_DIR)/etc/config/* $(1)/etc/config

	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller/admin
	$(INSTALL_BIN) $(LOCAL_SOURCE_DIR)/module/border_router/ot-br-posix/src/openwrt/controller/thread.lua $(1)/usr/lib/lua/luci/controller/admin

	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view
	$(CP) $(LOCAL_SOURCE_DIR)/module/border_router/ot-br-posix/src/openwrt/view/admin_thread $(1)/usr/lib/lua/luci/view

	$(INSTALL_DIR) $(1)/www/luci-static/resources
	$(CP) $(LOCAL_SOURCE_DIR)/module/border_router/ot-br-posix/src/openwrt/handle_error.js $(1)/www/luci-static/resources	
	
endef


$(eval $(call BuildPackage,ezmesh))
