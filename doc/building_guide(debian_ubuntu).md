<!-- markdownlint-disable commands-show-output -->

# BUILDING GUIDE With DEBIAN/UBUNTU

## Prepare Env

```markdown
$ sudo apt update && sudo apt install -y git mosquitto libsystemd-dev libprotobuf-dev protobuf-compiler libdbus-1-dev net-tools curl gcc
```

---

## Project setup and pre-install

### Clone EZMesh

```markdown
$ git clone https://github.com/RafaelMicro/EZMesh.git
```

### Install Cmake

- Ubuntu-based platform
  
```markdown
$ sudo curl -L https://github.com/Kitware/CMake/releases/download/v3.21.6/cmake-3.21.6-linux-x86_64.sh --output /tmp/cmake-3.21.6-linux-x86_64.sh \
    && sudo chmod +x /tmp/cmake*.sh && sudo /tmp/cmake*.sh --prefix=/usr/local --skip-license && sudo rm /tmp/cmake*
```

- Debian-based platform
  
```markdown
$ sudo curl -L https://github.com/Kitware/CMake/releases/download/v3.21.6/cmake-3.21.6-linux-aarch64.sh --output /tmp/cmake-3.21.6-linux-aarch64.sh \
    && sudo chmod +x /tmp/cmake*.sh && sudo /tmp/cmake*.sh --prefix=/usr/local --skip-license && sudo rm /tmp/cmake*
```

### Bluetooth pre-install

Rafael's EZMesh Bluetooth is based on Bluez, so make sure Bluez is already in your Host.

### Border Router pre-install

```markdown
$ sudo NAT64=1 module/border_router/ot-br-posix/script/bootstrap
```

---

## Build Project

- Select network interface for Border Router:
  
  ```markdown
  $ ifconfig
  ```

### Build project: default (example network interface is enp0s3)

- Default building: Only build ezmesh controller
  
  ```markdown
  $ cmake -B build -S . -DOTBR_INFRA_IF_NAME=enp0s3 -DCONFIG_GEN_SYSTEM=true \
  && cmake --build ./build && sudo cmake --install ./build/ && sudo ldconfig
  ```

- All compoment building
  
  ```markdown
  $ cmake -B build -S . -DOTBR_INFRA_IF_NAME=enp0s3 -DCONFIG_GEN_SYSTEM=true -DCONFIG_GEN_SYSTEM=true  -DCONFIG_BLUETOOTH=true -DCONFIG_BORDER_ROUTER=true -DCONFIG_ZIGBEE_GW_SERVICE=true -DCONFIG_SUBG_SERVICE=true -DCONFIG_CHECK=true \
  && cmake --build ./build && sudo cmake --install ./build/ && sudo ldconfig
  ```

  **Note: clean build (add --clean-first flag on "cmake --build")**

### EZMesh modeules' configuration
**Note: Using -DConfig on cmake session apply config**

|Module|Config|Description|Default|example|
|:---:|:---|:---|:---:|:---|
|Platfrom config|CONFIG_GEN_SYSTEM|Generate systemd setup (for Ubuntu or debian)|**false**|-DCONFIG_GEN_SYSTEM=true|
|Controller|CONFIG_CONTROLLER|Controller feature|**true**|-DCONFIG_CONTROLLER=true|
|Controller|CONFIG_UPGRADE|Enable controller upgrade|**true**|-DCONFIG_UPGRADE=true|
|Controller|CONFIG_CHECK|Check service statw|**false**|-DCONFIG_CHECK=true|
|Bluetooth|CONFIG_BLUETOOTH|Bluetooth feature|**false**|-DCONFIG_BLUETOOTH=true|
|Border Router|CONFIG_BORDER_ROUTER|Border Router feature|**false**|-DCONFIG_BORDER_ROUTER=true|
|Zigbee Gateway|CONFIG_ZIGBEE_GW_SERVICE|Zigbee GW feature|**false**|-DCONFIG_ZIGBEE_GW_SERVICE=true|
|sub-G Gateway|CONFIG_SUBG_SERVICE|subG Gateway feature|**false**|-DCONFIG_SUBG_SERVICE=true|

---

## Apply Project to system service

### Apply EZmesh controller

```markdown
$ sudo ./build/integrate/debian/controller/setup
```

### Apply Border Router

```markdown
$ sudo ./build/integrate/debian/border_router/setup
```

### Apply Bluetooth

```markdown
$ sudo ./build/integrate/debian/bluetooth/setup
```

Note: </br>
Please make sure your RCP dongle is already attached to the boot  </br>
All services will auto setup on boot  </br>

---

## Manage system service

### Start all service  

```markdown
$ sudo systemctl start ez-mgmt.service
```

### Restart all service  

```markdown
$ sudo systemctl restart ez-mgmt.service
```
