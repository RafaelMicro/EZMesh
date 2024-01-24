# EZMesh
## Introduction
The EZMesh Project is the Host Daemon of Rafael's EZmesh Dongle (Rafael Multi-protocol RCP). The EZMesh, which uses a single Rafael's EZmesh Dongle, can support the Host OS using different communication protocols simultaneously. 

The EZMesh currently supports:
- **Bluetooth**
- **Sub-G**
- **Thread**
- **Matter**
- **Zigbee**

Recommend Platform:
- Ubuntu 22.04.3 LTS (Ubuntu-based)
- Raspberry Pi OS (Legacy) Lite (Debian-based)
  - Release date: December 5th 2023
  - System: 64-bit
  - Kernel version: 6.1
  - Debian version: 11 (bullseye)

**The EZMesh Project is supported by [Rafael Micro](https://www.rafaelmicro.com/).**

---
## Prepare Env
```
$ sudo apt update && sudo apt install git mosquitto libsystemd-dev net-tools curl gcc
```
---
## Project setup and pre-install
### Clone EZMesh
```
$ git clone git@github.com:RafaelMicro/EZMesh.git
```
### Install Cmake
- Ubuntu-based platform
```
$ sudo curl -L https://github.com/Kitware/CMake/releases/download/v3.21.6/cmake-3.21.6-linux-x86_64.sh --output /tmp/cmake-3.21.6-linux-x86_64.sh \
    && sudo chmod +x /tmp/cmake*.sh && sudo /tmp/cmake*.sh --prefix=/usr/local --skip-license && sudo rm /tmp/cmake*
```
- Debian-based platform
```
$ sudo curl -L https://github.com/Kitware/CMake/releases/download/v3.21.6/cmake-3.21.6-linux-aarch64.sh --output /tmp/cmake-3.21.6-linux-aarch64.sh \
    && sudo chmod +x /tmp/cmake*.sh && sudo /tmp/cmake*.sh --prefix=/usr/local --skip-license && sudo rm /tmp/cmake*
```
### Bluetooth pre-install
Rafael's EZMesh Bluetooth is based on Bluez, so make sure Bluez is already in your Host.
### Border Router pre-install
```
$ sudo NAT64=1 module/border_router/ot-br-posix/script/bootstrap
```

---
## Build Project
- Select network interface for Border Router:
```
$ ifconfig
```
- Build project (example network interface is enp0s3)
```
$ mkdir build && cd build && cmake ../ -DOTBR_INFRA_IF_NAME=enp0s3 \
  && sudo make install && sudo ldconfig && cd ..
```

---
## Apply Project to system service
### Apply EZmesh controller
```
$ sudo ./build/integrate/debian/controller/setup
```
### Apply Border Router
```
$ sudo ./build/integrate/debian/border_router/setup
```
### Apply Bluetooth

```
$ sudo ./build/integrate/debian/bluetooth/setup
```
- Note: Please make sure your RCP dongle is already attached to the boot 
- Note: All services will auto setup on boot 

---
## Manage system service
### Start all service  
```
$ sudo systemctl start ez-mgmt.service
```
### Restart all service  
```
$ sudo systemctl restart ez-mgmt.service
```
