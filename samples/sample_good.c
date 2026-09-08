/******************************************************************************
 * COPYRIGHT        : Copyright 2026. All rights reserved.
 *
 * DESCRIPTION      : Example of a compliant module. Every rule the scanner
 *                    enforces is satisfied here, so a scan of this file
 *                    reports nothing. Use it as a template.
 *
 ******************************************************************************
 * $Id:$
 ******************************************************************************/

#include <string.h>
#include <stdint.h>
#include "sample_good.h"

#define EXA_CHECKSUM_SEED       (0xA5A5A5A5UL)
#define EXA_CHECKSUM_SHIFT      (3U)

/*****************************************************************************
 * FUNCTION     : EXA_Copy
 * INPUTS       : pSource             - source buffer, must not be NULL
 *                SourceLengthInBytes - number of bytes to copy
 * OUTPUTS      : pFrame              - frame to copy into, must not be NULL
 * RETURNS      : 0 on success, -1 when a parameter is invalid
 * DESCRIPTION  : Copies a payload into a frame. The copy is bounded by the
 *                smaller of the source length and the destination capacity,
 *                so an oversized source is rejected rather than truncated.
 *
 * Revision history:
 * 2026/09/04  example  RSW-00001  initial version
 *****************************************************************************/
int32_t EXA_Copy(EXA_tFrame *pFrame, const uint8_t *pSource,
                 uint16_t SourceLengthInBytes)
{
    int32_t Result = -1;

    if ((NULL != pFrame) && (NULL != pSource) &&
        (SourceLengthInBytes <= EXA_FRAME_MAX_LEN))
    {
        /* bounded to the destination capacity, so no overrun is possible */
        (void)memcpy(pFrame->Payload, pSource, SourceLengthInBytes);
        pFrame->PayloadLengthInBytes = SourceLengthInBytes;
        pFrame->State = EXA_STATE_ACTIVE;
        Result = 0;
    }

    return Result;
}

/*****************************************************************************
 * FUNCTION     : EXA_Checksum
 * INPUTS       : pData         - buffer to sum, must not be NULL
 *                LengthInBytes - number of bytes in pData
 * OUTPUTS      : none
 * RETURNS      : the checksum, or the seed when the input is invalid
 * DESCRIPTION  : Sums a buffer by length rather than by a terminator, so a
 *                missing terminator cannot run the loop off the end.
 *
 * Revision history:
 * 2026/09/04  example  RSW-00001  initial version
 *****************************************************************************/
uint32_t EXA_Checksum(const uint8_t *pData, uint16_t LengthInBytes)
{
    uint32_t Checksum = EXA_CHECKSUM_SEED;
    uint16_t Index = 0U;

    if (NULL == pData)
    {
        return Checksum;
    }

    for (Index = 0U; Index < LengthInBytes; Index++)
    {
        /* widening a byte to the accumulator type loses nothing */
        Checksum = (Checksum << EXA_CHECKSUM_SHIFT) + (uint32_t)pData[Index];
    }

    return Checksum;
}

/*****************************************************************************
 * FUNCTION     : EXA_Describe
 * INPUTS       : State - the state to describe
 * OUTPUTS      : none
 * RETURNS      : a constant string naming the state, never NULL
 * DESCRIPTION  : Maps a state to its name. The default leg covers values
 *                outside the enumeration.
 *
 * Revision history:
 * 2026/09/04  example  RSW-00001  initial version
 *****************************************************************************/
const char *EXA_Describe(EXA_tState State)
{
    const char *pText = "unknown";

    switch (State)
    {
        case EXA_STATE_IDLE:
            pText = "idle";
            break;

        case EXA_STATE_ACTIVE:
            pText = "active";
            break;

        case EXA_STATE_FAULT:
            pText = "fault";
            break;

        default:
            /* Unexpected state - the initial value is returned. */
            break;
    }

    return pText;
}

/*****************************************************************************
 * FUNCTION     : EXA_StatusGet
 * INPUTS       : Failed - true when the last operation reported an error
 * OUTPUTS      : none
 * RETURNS      : EXA_STATE_FAULT on failure, EXA_STATE_IDLE otherwise
 * DESCRIPTION  : Every arm of the if/else returns, so control never reaches
 *                the closing brace. Present so the missing-return check is
 *                exercised against a function that does return on all paths.
 *
 * Revision history:
 * 2026/09/04  example  RSW-00001  initial version
 *****************************************************************************/
EXA_tState EXA_StatusGet(bool Failed)
{
    if (Failed)
    {
        return EXA_STATE_FAULT;
    }
    else
    {
        return EXA_STATE_IDLE;
    }
}

/*****************************************************************************
 * FUNCTION     : EXA_Classify
 * INPUTS       : Value - the value to classify
 * OUTPUTS      : none
 * RETURNS      : the state the value maps to
 * DESCRIPTION  : Every switch clause returns and a default is present, so
 *                again no path reaches the closing brace.
 *
 * Revision history:
 * 2026/09/04  example  RSW-00001  initial version
 *****************************************************************************/
EXA_tState EXA_Classify(uint8_t Value)
{
    switch (Value)
    {
        case 0U:
            return EXA_STATE_IDLE;

        case 1U:
            return EXA_STATE_ACTIVE;

        default:
            return EXA_STATE_FAULT;
    }
}
