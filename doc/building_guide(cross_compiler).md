<!-- markdownlint-disable commands-show-output -->

# BUILDING GUIDE With CROSS COMPILER

## Project setup

## Prepare Env

```markdown
$ sudo apt update && sudo apt install -y git curl make build-essential pkg-config libdbus-1-dev libprotobuf-dev protobuf-compiler
```

---

### Clone EZMesh and Checkout submodule

```markdown
$ git clone https://github.com/RafaelMicro/EZMesh.git --recurse-submodules
```

---

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

---

## Configuration for Cross Compiler

- Following define is impoortant feature for cross-compiler:
  - CONFIG_USE_CROSS_COMPILER: Using CROSS_COMPILER or not
  - CONFIG_CROSS_COMPILER_SYSTEM_NAME: SYSTEM_NAME (using CMAKE_SYSTEM_NAME)
  - CONFIG_CROSS_COMPILER_SYSTEM_PROCESSOR: SYSTEM_PROCESSOR (using CMAKE_SYSTEM_PROCESSOR)
  - CONFIG_CROSS_COMPILER_PATH: tool-chain path
  - CONFIG_CROSS_COMPILER_PREFIX: compiler prefix</br>
    example:

    ```markdown
    -DCONFIG_USE_CROSS_COMPILER=1
    -DCONFIG_CROSS_COMPILER_SYSTEM_NAME=Generic
    -DCONFIG_CROSS_COMPILER_SYSTEM_PROCESSOR=ARM
    -DCONFIG_CROSS_COMPILER_PATH=/home/meshtest/gcc-arm-x86_64-arm-none-linux-gnueabihf/bin
    -DCONFIG_CROSS_COMPILER_PREFIX=arm-none-linux-gnueabihf
    ```

---

## Building Example

```!/bin/bash
$ cmake -B build -S . \
 -DCONFIG_CONTROLLER=true -DCONFIG_UPGRADE=true -DCONFIG_BLUETOOTH=true \
 -DCONFIG_BORDER_ROUTER=true -DCONFIG_ZIGBEE_GW_SERVICE=true -DCONFIG_SUBG_SERVICE=true \
 -DCONFIG_CHECK=true \
 -DOTBR_DBUS=ON -DBUILD_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr \
 -DOTBR_BORDER_AGENT=ON -DOTBR_BORDER_ROUTING=ON -DOTBR_INFRA_IF_NAME=\"br-lan\" \
 -DOTBR_MDNS="avahi" -DOTBR_OPENWRT=OFF -DOTBR_SRP_ADVERTISING_PROXY=ON \
 -DOT_FIREWALL=ON -DOT_POSIX_SETTINGS_PATH=\"/etc/openthread\" \
 -DOT_READLINE=OFF -DOTBR_INFRA_IF_NAME=br-lan -DOTBR_WEB=OFF \
 -DOT_BORDER_AGENT_ID=ON -DOTBR_REST=ON \
  -DOTBR_ENABLE_PUBLISH_MESHCOP_BA_ID=1 \
 -DCONFIG_USE_CROSS_COMPILER=ON \
 -DCONFIG_CROSS_COMPILER_SYSTEM_NAME=Generic \
 -DCONFIG_CROSS_COMPILER_SYSTEM_PROCESSOR=ARM \
 -DCONFIG_CROSS_COMPILER_PATH=/home/hank/gcc-arm-10.3-2021.07-x86_64-aarch64_be-none-linux-gnu/bin \
 -DCONFIG_CROSS_COMPILER_PREFIX=aarch64_be-none-linux-gnu
$ cmake --build ./build
```
