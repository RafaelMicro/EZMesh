<!-- markdownlint-disable commands-show-output -->

# BUILDING GUIDE With OpenWRT

## Setup EZMesh

- Add ezmesh to your feeds.con
  
    ```markdown
    src-git ezmesh https://github.com/RafaelMicro/EZMesh.git 
    ```

    OR

    ```markdown
    $ echo src-git ezmesh https://github.com/RafaelMicro/EZMesh.git >> feeds.conf 
    ```

    **build with debug mode (add  -j1 V=sc flags)**
- Update and install OpenWRT Setting
  
    ```markdown
    $ ./scripts/feeds update ezmesh 
    $ ./scripts/feeds install -a -p ezmesh
    ```

---

## Enable EZMesh

**EZMesh is a Network package under OpenWRT Platfrom.**</br>
EZMesh is not selected by default, so use menuconfig to select ezmesh

```markdown
$ make menuconfig 
```

In the configure window, use the Up and Down keys to move the cursor and the Left and Right keys to choose an action. </br>
A. Select Network to enter its submenu. </br>
B. Enable ezmesh by moving the cursor to it and pressing Y. </br>
C. Select Exit to exit.</br>
![menuconfig](./img/openwrt_menuconfig.png)

---

## Build EZMesh on OpenWRT

OpenWRT can build all package or indiviual package.</br>
**build with debug mode (add  -j1 V=sc flags)**

- build all package

    ```markdown
    $ make
    ```

- build EZMesh package

    ```markdown
    $ make package/ezmesh/compile 
    ```

    ![make](./img/openwrt_make.png)

---

## Apply EZMesh

The OpenWRT can flush frameware to the target board or insrtall package with opkg tool.

- install with opkg:</br>Copy the generated ipk file into OpenWRT, and install with opkg.

    ```markdown
    $ opkg install ezmesh_*.ipk
    ```

    ![install_ipk](./img/openwrt_ipk.png)

---

## Usage Ezmesh

### Start EZMesh

- Start ezmesh daemon : ezmeshd

    ```markdown
    $ ezmeshd -c /usr/etc/ez_config.ini
    ```

    ![ezmeshd](./img/openwrt_ezmeshd.png)

- Start OpenThread border Router:

    ```markdown
    $ otbr-agent -v -I wpan0 -B br-lan spinel+ezmesh://ezmeshd_0??iid=1 trel://br-lan
    ```

    ![otbr](./img/openwrt_otbr.png)
