# How to Build EZMesh-Agent

`cd examples/multi_protocol_rcp`

* Enable Zigbee Gateway NCP + Bluetooth LE HCI + Openthread RCP

`rm -rf build_out`

1. Dongle Board (Console :UART1/ EZMesh port :UART0)
   `./en_zb_ncp rt582 dongle`
2. EVK Board (Console :UART0/ EZMesh port :UART1)

   `./en_zb_ncp rt582 evb`

* Only Bluetooth LE HCI + Openthread RCP

`rm -rf build_out`

1. Dongle Board (Console :UART1/ EZMesh port :UART0)
   `./hci_ot_rcp rt582 dongle`
2. EVK Board (Console :UART0/ EZMesh port :UART1)

   `./hci_ot_rcp rt582 evb`

* Binary locate : ``build_out/multi_protocol_rcp.bin``
* How to modify customize uart setting?

  1. Edit file : examples/multi_protocol_rcp/multi_protocol_rcp/cpc_uart.c
  2. Modify macro :
     * UART Port : CONFIG_OPERATION_UART_PORT
     * UART Baudrate : CPC_OPERATION_BAUDRATE
     * UART PIN Select : CPC_OPERARION_UART_PIN_1/CPC_OPERARION_UART_PIN_2
