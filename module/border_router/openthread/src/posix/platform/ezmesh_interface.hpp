/*
 *  Copyright (c) 2018, The OpenThread Authors.
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
 *   This file includes definitions for the EZMESH interface to radio (RCP).
 */

#ifndef POSIX_APP_EZMESH_INTERFACE_HPP_
#define POSIX_APP_EZMESH_INTERFACE_HPP_

#include "logger.hpp"
#include "openthread-posix-config.h"
#include "platform-posix.h"
#include "lib/hdlc/hdlc.hpp"
#include "lib/spinel/multi_frame_buffer.hpp"
#include "lib/spinel/openthread-spinel-config.h"
#include "lib/spinel/spinel_interface.hpp"
#if OPENTHREAD_POSIX_CONFIG_SPINEL_VENDOR_INTERFACE_ENABLE
#include "libezmesh.h"
namespace ot {
namespace Posix {

/**
 * This class defines a EZMESH interface to the Radio Co-processor (RCP)
 *
 */
class Ezmesh : public ot::Spinel::SpinelInterface, public Logger<Ezmesh>
{
public:
    static const char kLogModuleName[]; ///< Module name used for logging.

    /**
     * Initializes the object.
     *
     * @param[in] aRadioUrl  RadioUrl parsed from radio url.
     */
    Ezmesh(const Url::Url &aRadioUrl);

    /**
     * This destructor deinitializes the object.
     */
    ~Ezmesh(void);

    /**
     * Initializes the interface to the Radio Co-processor (RCP)
     *
     * @note This method should be called before reading and sending spinel frames to the interface.
     *
     * @param[in] aCallback         Callback on frame received
     * @param[in] aCallbackContext  Callback context
     * @param[in] aFrameBuffer      A reference to a `RxFrameBuffer` object.
     *
     * @retval OT_ERROR_NONE       The interface is initialized successfully
     * @retval OT_ERROR_ALREADY    The interface is already initialized.
     * @retval OT_ERROR_FAILED     Failed to initialize the interface.
     */
    otError Init(ReceiveFrameCallback aCallback, void *aCallbackContext, RxFrameBuffer &aFrameBuffer);

    /**
     * This method deinitializes the interface to the RCP.
     *
     */
    void Deinit(void);

    /**
     * This method sends a spinel frame to Radio Co-processor (RCP) over the socket.
     *
     *
     * @param[in] aFrame     A pointer to buffer containing the spinel frame to send.
     * @param[in] aLength    The length (number of bytes) in the frame.
     *
     * @retval OT_ERROR_NONE     Successfully sent the spinel frame.
     */
    otError SendFrame(const uint8_t *aFrame, uint16_t aLength);

    /**
     * This method waits for receiving part or all of spinel frame within specified interval.
     *
     * @param[in]  aTimeout  The timeout value in microseconds.
     *
     * @retval OT_ERROR_NONE             Part or all of spinel frame is received.
     */
    otError WaitForFrame(uint64_t aTimeoutUs);

    /**
     * This is a stub, ezmesh does not use file descriptors.
     *
     * @param[inout]  aReadFdSet   A reference to the read file descriptors.
     * @param[inout]  aWriteFdSet  A reference to the write file descriptors.
     * @param[inout]  aMaxFd       A reference to the max file descriptor.
     * @param[inout]  aTimeout     A reference to the timeout.
     *
     */
    void UpdateFdSet(void *aMainloopContext);

    /**
     * This method performs radio driver processing.
     *
     * @param[in]   aContext        The context containing fd_sets.
     *
     */
    void Process(const void *aMainloopContext);

    /**
     * This method returns the bus speed between the host and the radio.
     *
     * @returns   Bus speed in bits/second.
     *
     */
    uint32_t GetBusSpeed(void) const { return mBaudRate; }

    /**
     * Hardware resets the RCP.
     *
     * @retval OT_ERROR_NONE            Successfully reset the RCP.
     * @retval OT_ERROR_NOT_IMPLEMENT   The hardware reset is not implemented.
     */
    otError HardwareReset(void) { return OT_ERROR_NOT_IMPLEMENTED; }

    /**
     * This method is called when RCP is reset to recreate the connection with it.
     * Intentionally empty.
     *
     */
    otError ResetConnection(void) { return OT_ERROR_NONE; }

    /**
     * This method returns the RCP interface metrics.
     *
     * @returns The RCP interface metrics.
     *
     */
    const otRcpInterfaceMetrics *GetRcpInterfaceMetrics(void) const { return &mInterfaceMetrics; }

    /**
     * This method is called reinitialise the EZMESH interface if sCpcResetReq indicates that a restart
     * is required.
     */
    void CheckAndReInitCpc(void);

    static bool IsInterfaceNameMatch(const char *aInterfaceName)
    {
        static const char kInterfaceName[] = "spinel+ezmesh";
        return (strncmp(aInterfaceName, kInterfaceName, strlen(kInterfaceName)) == 0);
    }

private:
    /**
     * This method instructs `Ezmesh` to read data from radio over the socket.
     *
     * The mReceiveFrameCallback is used to pass the received frame to be processed.
     *
     */
    void Read(uint64_t aTimeoutUs);

    /**
     * This method waits for the socket file descriptor associated with the HDLC interface to become writable within
     * `kMaxWaitTime` interval.
     *
     * @retval OT_ERROR_NONE   Socket is writable.
     * @retval OT_ERROR_FAILED Socket did not become writable within `kMaxWaitTime`.
     *
     */
    otError WaitForWritable(void);

    /**
     * This method writes a given frame to the socket.
     *
     * This is blocking call, i.e., if the socket is not writable, this method waits for it to become writable for
     * up to `kMaxWaitTime` interval.
     *
     * @param[in] aFrame  A pointer to buffer containing the frame to write.
     * @param[in] aLength The length (number of bytes) in the frame.
     *
     * @retval OT_ERROR_NONE    Frame was written successfully.
     * @retval OT_ERROR_FAILED  Failed to write due to socket not becoming writable within `kMaxWaitTime`.
     *
     */
    otError Write(const uint8_t *aFrame, uint16_t aLength);

    /**
     * Performs HDLC decoding on received data.
     *
     * If a full HDLC frame is decoded while reading data, this method invokes the `HandleReceivedFrame()` (on the
     * `aCallback` object from constructor) to pass the received frame to be processed.
     *
     * @param[in] aBuffer  A pointer to buffer containing data.
     * @param[in] aLength  The length (number of bytes) in the buffer.
     */
    //void Decode(const uint8_t *aBuffer, uint16_t aLength);


    /**
     * This method generates and sends a reset response back to OT.
     *
     * This method is called after the EZMESH layer catches the SPINEL reset command. This is done so that
     * EZMESH can handle resets of the RCP and OT is tricked into thinking it handles resets.
     *
     */
    void SendResetResponse(void);

    enum
    {
        kMaxFrameSize = LIB_EZMESH_READ_MINIMUM_SIZE,
        kMaxWaitTime  = 5000, ///< Maximum wait time in Milliseconds for socket to become writable (see `SendFrame`).
        kMaxSleepDuration   = 100000, ///< Sleep duration in micro seconds before restarting ezmesh connection.
        kMaxRestartAttempts = 300,
        kResetCMDSize       = 4,
    };

    ReceiveFrameCallback mReceiveFrameCallback;
    void                *mReceiveFrameContext;
    RxFrameBuffer       *mReceiveFrameBuffer;

    int             mSockFd;
    ezmesh_handle_t mHandle;
    ezmesh_ep_t     mEndpoint;
    uint32_t        mBaudRate;
    const Url::Url &mRadioUrl;

    static void HandleSecondaryReset(void);
    static void SetCpcResetReq(bool state) { sCpcResetReq = state; }

    // Hard Coded Reset Response
    // 0x72 -> STATUS_RESET_SOFTWARE
    uint8_t mResetResponse[kResetCMDSize] = {0x80, 0x06, 0x00, 0x72};

    const uint8_t   mId = EP_15_4;
    typedef uint8_t ezmeshError;
    static bool     sCpcResetReq;

    otRcpInterfaceMetrics mInterfaceMetrics;

    // Non-copyable, intentionally not implemented.
    Ezmesh(const Ezmesh &);
    Ezmesh &operator=(const Ezmesh &);
};

} // namespace Posix
} // namespace ot

#endif // OPENTHREAD_POSIX_CONFIG_RCP_BUS == OT_POSIX_RCP_BUS_EZMESH
#endif // POSIX_APP_EZMESH_INTERFACE_HPP_
