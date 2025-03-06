/*
 *  Copyright (c) 2017, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *   This file includes all compile-time configuration constants used by SiLabs POSIX builds.
 *
 *   To use this configuration in your POSIX builds, copy this file into the following folder:
 *   <openthread_location>/src/posix/platform/
 */

#ifndef OPENTHREAD_CORE_SILABS_POSIX_CONFIG_H_
#define OPENTHREAD_CORE_SILABS_POSIX_CONFIG_H_

/******************************************************************************
 * RCP BUS defaults
 *****************************************************************************/

/**
 * This setting configures what type of RCP bus to use (default UART)
 *
 * UART: OT_POSIX_RCP_BUS_UART
 * SPI: OT_POSIX_RCP_BUS_SPI
 * EZMESH: OT_POSIX_RCP_BUS_EZMESH
 *
 */
// #ifndef OPENTHREAD_POSIX_CONFIG_RCP_BUS
// #define OPENTHREAD_POSIX_CONFIG_RCP_BUS OT_POSIX_RCP_BUS_UART
// #endif

#define OPENTHREAD_POSIX_CONFIG_SPINEL_HDLC_INTERFACE_ENABLE 0
#define OPENTHREAD_CONFIG_TIME_SYNC_ENABLE 0
/******************************************************************************
 * Co-processor RPC defaults
 *****************************************************************************/



/******************************************************************************
 * Include OpenThread project's POSIX defaults
 *****************************************************************************/
#include "openthread-core-posix-config.h"

#endif // OPENTHREAD_CORE_SILABS_POSIX_CONFIG_H_
