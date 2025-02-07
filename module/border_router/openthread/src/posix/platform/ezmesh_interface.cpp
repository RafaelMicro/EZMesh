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
 *   This file includes the implementation for the EZMESHd interface to radio (RCP).
 */

#include "ezmesh_interface.hpp"

#include "platform-posix.h"

#include <stdarg.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <termios.h>
#include <unistd.h>

#include <openthread/logging.h>

#include "common/code_utils.hpp"
#include "common/encoding.hpp"
#include "lib/spinel/spinel.h"

#if OPENTHREAD_POSIX_CONFIG_SPINEL_VENDOR_INTERFACE_ENABLE

namespace ot {
namespace Posix {

const char Ezmesh::kLogModuleName[] = "EZMesh";

bool Ezmesh::sCpcResetReq = false;

Ezmesh::Ezmesh(const Url::Url &aRadioUrl)
    : mReceiveFrameCallback(nullptr)
    , mReceiveFrameContext(nullptr)
    , mReceiveFrameBuffer(nullptr)
    , mSockFd(-1)
    , mBaudRate(0)
    , mHdlcDecoder()
    , mRadioUrl(aRadioUrl)
{
    const char *value;
    int         ret = 0;

    // VerifyOrExit(mSockFd == -1, error = OT_ERROR_ALREADY);
    memset(&mInterfaceMetrics, 0, sizeof(mInterfaceMetrics));
    mInterfaceMetrics.mRcpInterfaceType = kSpinelInterfaceTypeVendor;
    otLogInfoPlat("%s", aRadioUrl.GetPath());
    ret = libezmesh_init(&mHandle, aRadioUrl.GetPath(), HandleSecondaryReset);
    if (ret != 0)
    {
        otLogCritPlat(
            "%d EZMESH init failed. Ensure radio-url argument has the form 'spinel+ezmesh://ezmeshd_0?iid=<1..3>'",
            ret);
        DieNow(OT_EXIT_FAILURE);
    }
    mSockFd = libezmesh_open_ep(mHandle, &mEndpoint, mId, 1);
    if (mSockFd < 0)
    {
        otLogCritPlat("EZMESH endpoint open failed");
    }

    if ((value = aRadioUrl.GetValue("ezmesh-bus-speed")))
    {
        mBaudRate = static_cast<uint32_t>(atoi(value));
    }

    otLogInfoPlat("mBaudRate = %d", mBaudRate);
}

void Ezmesh::HandleHdlcFrame(void *aContext, otError aError)
{
    static_cast<Ezmesh *>(aContext)->HandleHdlcFrame(aError);
}

void Ezmesh::HandleHdlcFrame(otError aError)
{
    VerifyOrExit((mReceiveFrameCallback != nullptr) && (mReceiveFrameBuffer != nullptr));

    mInterfaceMetrics.mTransferredFrameCount++;

    if (aError == OT_ERROR_NONE)
    {
        mInterfaceMetrics.mRxFrameCount++;
        mInterfaceMetrics.mRxFrameByteCount += mReceiveFrameBuffer->GetLength();
        mInterfaceMetrics.mTransferredValidFrameCount++;
        mReceiveFrameCallback(mReceiveFrameContext);
    }
    else
    {
        mInterfaceMetrics.mTransferredGarbageFrameCount++;
        mReceiveFrameBuffer->DiscardFrame();
        LogWarn("Error decoding hdlc frame: %s", otThreadErrorToString(aError));
    }

exit:
    return;
}

otError Ezmesh::Init(ReceiveFrameCallback aCallback, void *aCallbackContext, RxFrameBuffer &aFrameBuffer)
{
    otError error = OT_ERROR_NONE;

    mHdlcDecoder.Init(aFrameBuffer, HandleHdlcFrame, this);
    mReceiveFrameCallback = aCallback;
    mReceiveFrameContext  = aCallbackContext;
    mReceiveFrameBuffer   = &aFrameBuffer;

    return error;
}

void Ezmesh::HandleSecondaryReset(void)
{
    SetCpcResetReq(true);
}

Ezmesh::~Ezmesh(void)
{
    Deinit();
}

void Ezmesh::Deinit(void)
{
    VerifyOrExit(mEndpoint.ptr != nullptr);

    // VerifyOrExit(0 == libezmesh_close_ep(&mEndpoint), perror("close ezmesh endpoint"));

exit:
    return;
}

void Ezmesh::Read(uint64_t aTimeoutUs)
{
    uint8_t  buffer[kMaxFrameSize];
    uint8_t *ptr = buffer;
    ssize_t  bytesRead;
    bool     block = false;
    int      ret   = 0;

    otLogInfoPlat("timeout = %ld", aTimeoutUs);

    if (aTimeoutUs > 0)
    {
        ezmesh_timeval_t timeout;

        timeout.seconds      = static_cast<int>(aTimeoutUs / OT_US_PER_S);
        timeout.microseconds = static_cast<int>(aTimeoutUs % OT_US_PER_S);

        block = true;
        ret   = libezmesh_set_ep_option(mEndpoint, OPTION_BLOCKING, &block, sizeof(block));
        // OT_ASSERT(ret == 0);
        ret = libezmesh_set_ep_option(mEndpoint, OPTION_RX_TIMEOUT, &timeout, sizeof(timeout));
        // OT_ASSERT(ret == 0);
    }
    else
    {
        ret = libezmesh_set_ep_option(mEndpoint, OPTION_BLOCKING, &block, sizeof(block));
        // OT_ASSERT(ret == 0);
    }
    bytesRead = libezmesh_read_ep(mEndpoint, buffer, sizeof(buffer), EP_READ_FLAG_NONE);

    if (bytesRead > 0)
    {
        // Unpack concatenated spinel frames (see ncp_cpc.cpp)
        while (bytesRead > 0)
        {
            if (bytesRead < 2)
            {
                break;
            }
            uint16_t bufferLen = BigEndian::ReadUint16(ptr);
            ptr += 2;
            bytesRead -= 2;
            if (bytesRead < bufferLen)
            {
                break;
            }
            for (uint16_t i = 0; i < bufferLen; i++)
            {
                if (!mReceiveFrameBuffer->CanWrite(1) || (mReceiveFrameBuffer->WriteByte(*(ptr++)) != OT_ERROR_NONE))
                {
                    mReceiveFrameBuffer->DiscardFrame();
                    return;
                }
            }
            bytesRead -= bufferLen;
            mReceiveFrameCallback(mReceiveFrameContext);
        }
    }

    else if (bytesRead == -ECONNRESET)
    {
        SetCpcResetReq(true);
    }
    else if ((bytesRead != -EAGAIN) && (bytesRead != -EINTR))
    {
        DieNow(OT_EXIT_ERROR_ERRNO);
    }
}

void Ezmesh::Decode(const uint8_t *aBuffer, uint16_t aLength)
{
    mHdlcDecoder.Decode(aBuffer, aLength);
}

otError Ezmesh::SendFrame(const uint8_t *aFrame, uint16_t aLength)
{
    otError                            error;
    Spinel::FrameBuffer<kMaxFrameSize> encoderBuffer;
    // Hdlc::Encoder                      hdlcEncoder(encoderBuffer);

    CheckAndReInitCpc();

    // SuccessOrExit(error = hdlcEncoder.BeginFrame());
    // SuccessOrExit(error = hdlcEncoder.Encode(aFrame, aLength));
    // SuccessOrExit(error = hdlcEncoder.EndFrame());

    error = Write(aFrame, aLength);

    return error;
}

otError Ezmesh::Write(const uint8_t *aFrame, uint16_t aLength)
{
    otError error = OT_ERROR_NONE;

    // We are catching the SPINEL reset command and returning
    // a SPINEL reset response immediately
    if (SPINEL_HEADER_GET_TID(*aFrame) == 0 && *(aFrame + 1) == SPINEL_CMD_RESET)
    {
        SendResetResponse();
        return error;
    }
    otDumpInfoPlat("W", aFrame, aLength);
    while (aLength)
    {
        ssize_t bytesWritten = libezmesh_write_ep(mEndpoint, aFrame, aLength, EP_WRITE_FLAG_NON_BLOCKING);

        if (bytesWritten == aLength)
        {
            break;
        }
        else if (bytesWritten > 0)
        {
            aLength -= static_cast<uint16_t>(bytesWritten);
            aFrame += static_cast<uint16_t>(bytesWritten);
        }
        else if (bytesWritten < 0)
        {
            VerifyOrExit((bytesWritten == -EPIPE), SetCpcResetReq(true));
            VerifyOrDie((bytesWritten == -EAGAIN) || (bytesWritten == -EWOULDBLOCK) || (bytesWritten == -EINTR),
                        OT_EXIT_ERROR_ERRNO);
        }
    }

exit:
    return error;
}

otError Ezmesh::WaitForFrame(uint64_t aTimeoutUs)
{
    otError error = OT_ERROR_NONE;

    CheckAndReInitCpc();
    Read(aTimeoutUs);

    return error;
}

void Ezmesh::UpdateFdSet(void *aMainloopContext)
{
    otSysMainloopContext *context = reinterpret_cast<otSysMainloopContext *>(aMainloopContext);

    assert(context != nullptr);

    FD_SET(mSockFd, &context->mReadFdSet);

    if (context->mMaxFd < mSockFd)
    {
        context->mMaxFd = mSockFd;
    }
}

void Ezmesh::Process(const void *aMainloopContext)
{
    OT_UNUSED_VARIABLE(aMainloopContext);
    CheckAndReInitCpc();
    Read(0);
}

void Ezmesh::CheckAndReInitCpc(void)
{
    int result;
    int attempts = 0;

    // Check if EZMESH needs to be restarted
    VerifyOrExit(sCpcResetReq);

    do
    {
        // Add some delay before attempting to restart
        usleep(kMaxSleepDuration);
        // Try to restart EZMESH
        result = libezmesh_reset(&mHandle);
        // Mark how many times the restart was attempted
        attempts++;
        // Continue to try and restore EZMESH communication until we
        // have exhausted the retries or restart was successful
    } while ((result != 0) && (attempts < kMaxRestartAttempts));

    // If the restart failed, exit.
    VerifyOrDie(result == 0, OT_EXIT_ERROR_ERRNO);

    // Reopen the endpoint for communication
    mSockFd = libezmesh_open_ep(mHandle, &mEndpoint, mId, 1);

    // If the restart failed, exit.
    VerifyOrDie(mSockFd >= 0, OT_EXIT_ERROR_ERRNO);

    otLogCritPlat("Restarted EZMESH successfully");

    // Clear the flag
    SetCpcResetReq(false);

exit:
    return;
}

void Ezmesh::SendResetResponse(void)
{
    // Put EZMESH Reset call here

    for (int i = 0; i < kResetCMDSize; ++i)
    {
        if (mReceiveFrameBuffer->CanWrite(sizeof(uint8_t)))
        {
            IgnoreError(mReceiveFrameBuffer->WriteByte(mResetResponse[i]));
        }
    }

    mReceiveFrameCallback(mReceiveFrameContext);
}

} // namespace Posix
} // namespace ot
#endif // OPENTHREAD_POSIX_CONFIG_RCP_BUS == OT_POSIX_RCP_BUS_EZMESH
