# EZMesh
## Introduction
The EZMesh Project is the Host Daemon of Rafael's CPC Dongle (Rafael Multi-protocol RCP). The EZMesh, which use a single Rafael's CPC Dongle, can support Host OS using different communication protocol at the same time. The EZMesh currently supports Bluetooth, Thread, and Matter 

The EZMesh Project is supported by [Rafael Micro](https://www.rafaelmicro.com/). 

---
## Prepare Env
```
$ sudo apt update \
&& sudo apt install git mosquitto libsystemd-dev net-tools curl
```
---
## Project setup and pre-install
### clone EZMesh
```
$ git@github.com:RafaelMicro/EZMesh.git
```
### Install Cmake
- Ubuntu based platfrom
```
$ sudo curl -L https://github.com/Kitware/CMake/releases/download/v3.21.6/cmake-3.21.6-linux-x86_64.sh --output /tmp/cmake-3.21.6-linux-x86_64.sh \
    && sudo chmod +x /tmp/cmake*.sh \
    && sudo /tmp/cmake*.sh --prefix=/usr/local --skip-license \
    && sudo rm /tmp/cmake*
```
- Debian based platfrom
```
$ sudo curl -L https://github.com/Kitware/CMake/releases/download/v3.21.6/cmake-3.21.6-linux-aarch64.sh --output /tmp/cmake-3.21.6-linux-aarch64.sh \
    && sudo chmod +x /tmp/cmake*.sh \
    && sudo /tmp/cmake*.sh --prefix=/usr/local --skip-license \
    && sudo rm /tmp/cmake*
```
### Bluetooth pre-install
Rafael's EZMesh bluetooth based on Bluez, so makesure Bluez already in your Host.
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
$ mkdir build && cd build \
&& cmake ../ -DOTBR_INFRA_IF_NAME=enp0s3 && sudo make install && sudo ldconfig\
&& cd ..
```

---
## Apply Project to system service
### Apply CPC
```
export cpc_path=build/module/cpc/cpcd-system/debconf \
&& sudo bash $cpc_path/prerm && sudo bash $cpc_path/postrm && sudo bash $cpc_path/postinst
```
### Apply Border Router
```
export br=build/module/border_router/cpc-otbr/debconf \
&& sudo bash $br/prerm && sudo bash $br/postinst
```
### Apply Bluetooth

```
export bt=build/module/bluetooth/cpc-bluetooth/debconf \
&& sudo bash $bt/prerm && sudo bash $bt/postinst
```
- Note: Please makesure you RCP dongle already attach on boot 
- Note: All service will auto setup on boot 

---
## Manage system service
### Start all service  
```
$ sudo systemctl start cpc-mgmt.service
```
### Restart all service  
```
$ sudo systemctl restart cpc-mgmt.service
```
