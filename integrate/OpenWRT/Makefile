# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=ezmesh
PKG_VERSION:=0.0.0

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

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
	-DOT_FIREWALL=ON \
	-DOT_POSIX_SETTINGS_PATH=\"/etc/openthread\" \
	-DOT_READLINE=OFF \
	-DOTBR_WEB=OFF \
	-DOTBR_NAT64=ON \
	-DNAT64_SERVICE=\"openthread\"

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -fr $(TOPDIR)/package/EZMesh/* $(PKG_BUILD_DIR)
endef

define Package/ezmesh
  TITLE:=EZMesh
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE+=CPP ezmesh
  DEPENDS:= +libstdcpp +jsoncpp +libjson-c +libubus +libblobmsg-json +libavahi-client +avahi-daemon +iptables-mod-extra +ipset,
endef

define Package/ezmesh/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DIR) $(1)/usr/var/
	$(INSTALL_DIR) $(1)/usr/var/lib/
	$(INSTALL_DIR) $(1)/usr/etc/
endef


$(eval $(call BuildPackage,ezmesh))
