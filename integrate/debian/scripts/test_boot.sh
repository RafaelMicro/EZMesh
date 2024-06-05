#!/bin/sh

OTBR_INI_LOG=/tmp/rafael_otbr_init.log

RETRY_MAX=3
TIMEOUT_SECONDS=60
CT=0

_hw_reset_dongle() {
    [ ! -d /sys/class/gpio/gpio6 ]&&echo 6 >/sys/class/gpio/export
    echo out >/sys/class/gpio/gpio6/direction
    sleep 1
    echo 0 >/sys/class/gpio/gpio6/value
    sleep 1
    echo 1 >/sys/class/gpio/gpio6/value
    sleep 5
}

_restart() {
        SECONDS_ELAPSED=0
        while true; do
                echo -n "[Wait detached(${SECONDS_ELAPSED})] Try restart Service" >> ${OTBR_INI_LOG}
                sudo systemctl restart ez-mgmt.service
                ret=$?
                if [ $ret == 0 ]; then
                        echo -n "[Wait detached(${SECONDS_ELAPSED})] Service restart success" >> ${OTBR_INI_LOG}
                        echo -e "\n" >> ${OTBR_INI_LOG}
                        break
                fi
                echo -n "[Wait detached(${SECONDS_ELAPSED})] Service restart Failed" >> ${OTBR_INI_LOG}
                echo -e "\n" >> ${OTBR_INI_LOG}
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
                        echo -n "[Wait detached(${SECONDS_ELAPSED})] ret: ${ret}(otbr connect)" >> ${OTBR_INI_LOG}
                        echo -e "\n" >> ${OTBR_INI_LOG}
                        _state=$(ot-ctl state | sed -n "1 p" | sed "s/\r//")
                        echo -n "[Wait leader(${SECONDS_ELAPSED})] state: ${_state}" >> ${OTBR_INI_LOG}
                        echo -e "" >> ${OTBR_INI_LOG}
                        if [ ${_state} == "leader" ]; then
                                break
                        fi
                fi

                if [ $SECONDS_ELAPSED -ge $TIMEOUT_SECONDS ]; then
                        echo -n "Timeout reached. Exiting for wait detached(otbr not connect)." >> ${OTBR_INI_LOG}
                        echo -e "\n" >> ${OTBR_INI_LOG}
                        echo "Timeout reached. Exiting or wait detached(otbr not connect)."
                        exit 1
                fi
                echo -n "[Wait detached(${SECONDS_ELAPSED})] ret: ${ret}(otbr not connect)" >> ${OTBR_INI_LOG}
                echo -e "" >> ${OTBR_INI_LOG}
                sleep 3

                if [ $RETRY_COUNTS -ge 5 ]; then
                        echo -n "OTBR not enable" >> ${OTBR_INI_LOG}
                        echo -e "\n" >> ${OTBR_INI_LOG}
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
                echo $otbr_hex
                if [ $otbr_hex == "213" ]; then
                        echo -n "otbr_hex = 213" >> ${OTBR_INI_LOG}
                        echo -e "\n" >> ${OTBR_INI_LOG}
                        break
                fi

                if [ $SECONDS_ELAPSED -ge $TIMEOUT_SECONDS ]; then
                        echo -n "Timeout reached. Exiting for otbr initial." >> ${OTBR_INI_LOG}
                        echo -e "\n" >> ${OTBR_INI_LOG}
                        echo "Timeout reached. Exiting for otbr initial."
                        exit 1
                fi
        done
}

_main() {
        echo -e "\n\n\n" >> ${OTBR_INI_LOG}
        echo -n "----------------- ${CT} " >> ${OTBR_INI_LOG} && date "+%Y-%m-%d %H:%M:%S" >> ${OTBR_INI_LOG}
        echo -e "" >> ${OTBR_INI_LOG}
        CT=$((CT + 1))
        _restart
        sleep 3
        _check_leader
        _get_hex
}
while true; do
        _main
done