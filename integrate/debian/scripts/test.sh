#!/bin/bash

RETRY_MAX=3
TIMEOUT_SECONDS=60

_hw_reset_dongle() {
#    [ ! -d /sys/class/gpio/gpio6 ]&&echo 6 >/sys/class/gpio/export
#    echo out >/sys/class/gpio/gpio6/direction
    sleep 1
#    echo 0 >/sys/class/gpio/gpio6/value
#    sleep 1
#    echo 1 >/sys/class/gpio/gpio6/value
#    sleep 5
}

_restart() {
    SECONDS_ELAPSED=0
    while true; do
        echo "[Wait detached(${SECONDS_ELAPSED})] Try restart Service"
        sudo systemctl restart ez-mgmt.service
        ret=$?
        if [ $ret == 0 ]; then
            echo "[Wait detached(${SECONDS_ELAPSED})] Service restart success"
            break
        fi
        echo "[Wait detached(${SECONDS_ELAPSED})] Service restart Failed"
        sleep 3
    done
}

_check_leader() {
    SECONDS_ELAPSED=0
    RETRY_COUNTS=0
    while true; do
        RETRY_COUNTS=$((RETRY_COUNTS + 1))&&sleep 1
        SECONDS_ELAPSED=$((SECONDS_ELAPSED + 1))&&sleep 1
        ### check otbr status(Not connect -> detached -> leader)
        ot-ctl state leader
        ot-ctl state
        ret=$?
        if [ $ret == 0 ]; then
            echo "[Wait detached(${SECONDS_ELAPSED})] ret: ${ret}(otbr connect)"
            _state=$(ot-ctl state | sed -n "1 p" | sed "s/\r//")
            echo "[Wait leader(${SECONDS_ELAPSED})] state: ${_state}"
            if [ ${_state} == "leader" ]; then
                break
            fi
        fi

        if [ $SECONDS_ELAPSED -ge $TIMEOUT_SECONDS ]; then
            echo "Timeout reached. Exiting or wait detached(otbr not connect)."
            exit 1
        fi
        echo "[Wait detached(${SECONDS_ELAPSED})] ret: ${ret}(otbr not connect)"
        sleep 2

        if [ $RETRY_COUNTS -ge 3 ]; then
            echo "OTBR not enable"
            _hw_reset_dongle
            _restart
            RETRY_COUNTS=0
        fi
    done
}

_get_hex() {
    SECONDS_ELAPSED=0
    while true; do
        SECONDS_ELAPSED=$((SECONDS_ELAPSED + 1))
        otbr_hex=$(echo -n "$(ot-ctl dataset active -x | head -n 1)" | wc -c)
        if [ $otbr_hex == "213" ]; then
            break
        fi

        if [ $SECONDS_ELAPSED -ge $TIMEOUT_SECONDS ]; then
            echo "Timeout reached. Exiting for otbr initial."
            exit 1
        fi
    done
}

_check_bt_state() {
    SECONDS_ELAPSED=0
    while true; do
        SECONDS_ELAPSED=$((SECONDS_ELAPSED + 1))
        bt_status=$(hciconfig hci0 | grep -o "UP RUNNING")
        if [ "$bt_status" == "UP RUNNING" ]; then
            break
        else
            echo "hci0 is not UP and RUNNING. Setting it UP..."
            sudo hciconfig hci0 up
        fi

        if [ $SECONDS_ELAPSED -ge $TIMEOUT_SECONDS ]; then
            echo "Timeout reached. Exiting for bt initial."
            exit 1
        fi
    done
}

check_env() {
    _restart
    _check_leader
    _get_hex
    _check_bt_state
}

_get_thread_state() {
    otbr_hex=$(echo -n "$(ot-ctl dataset active -x | head -n 1)" | wc -c)
    if [ $otbr_hex != "213" ]; then
       check_env
    fi
}

setup_thread() {
    sudo ot-ctl dataset init new
    sudo ot-ctl dataset commit active
    sudo ot-ctl ifconfig up
    sudo ot-ctl thread start
}

connect_device() {
    light_count=$1
    debug_flag=$2
    for((i=0; i<$light_count; i++))
    do
        matter-tool connect L$i LIGHT 20202021 3840 $debug_flag
        matter-tool onoff off L$i $debug_flag
    done
}

toggle_test() {
    cnt=$2
    light_count=$1
    debug_flag=$3
    success_count=0
    failed_count=0
    for((j=0; j<$cnt; j++))
    do
        failed=0
        for((i=0; i<$light_count; i++))
        do
            RETRY_COUNTS=0
            while true; do
                _get_thread_state
                matter-tool onoff toggle L$i $debug_flag
                ret=$?
                if [ $ret == 0 ]; then
                    break
                else
                    failed=1
                    echo "control failed retry: ${RETRY_COUNTS}"
                    RETRY_COUNTS=$((RETRY_COUNTS + 1))
                fi

                if [ $RETRY_COUNTS -ge 5 ]; then
                    _restart
                    RETRY_COUNTS=0
                fi
            done
        done
        if [ $failed == 1 ]; then
            failed_count=$((failed_count+1))
        else
            success_count=$((success_count+1))
        fi
        echo "test count: ${j}, success: ${success_count}, failed: ${failed_count}"
    done
}

_main() {
    case $action_name in
        check_env)
            check_env "$@"
            ;;
        setup_thread)
            setup_thread "$@"
            ;;
        connect_device)
            connect_device "$@"
            ;;
        toggle_test)
            toggle_test "$@"
            ;;
        *)
            echo "help:"
            echo "check_env"
            echo "setup_thread"
            echo "connect_device $device_count -d"
            echo "toggle_test $device_count $action_count -d"
            exit 1
            ;;
    esac
}

if [ -z "$1" ]; then
    echo "No function name provided. Please provide a function name as the first argument."
    exit 1
fi
action_name=$1
shift
_main "$@"
