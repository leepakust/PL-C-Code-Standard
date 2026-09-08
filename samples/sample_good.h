/******************************************************************************
 * COPYRIGHT        : Copyright 2026. All rights reserved.
 *
 * DESCRIPTION      : Example of a compliant header: include guard, self
 *                    contained includes, prefixed names, no definitions.
 *
 ******************************************************************************
 * $Id:$
 ******************************************************************************/

#ifndef SAMPLE_GOOD_H
#define SAMPLE_GOOD_H

#include <stdint.h>
#include <stdbool.h>

#define EXA_FRAME_MAX_LEN       (64U)
#define EXA_SQUARE(x)           ((x) * (x))

typedef enum EXA_tState
{
    EXA_STATE_IDLE = 0,
    EXA_STATE_ACTIVE,
    EXA_STATE_FAULT
} EXA_tState;

typedef struct EXA_tFrame
{
    uint8_t  Payload[EXA_FRAME_MAX_LEN];
    uint16_t PayloadLengthInBytes;
    EXA_tState State;
} EXA_tFrame;

extern int32_t EXA_Copy(EXA_tFrame *pFrame, const uint8_t *pSource,
                        uint16_t SourceLengthInBytes);
extern uint32_t EXA_Checksum(const uint8_t *pData, uint16_t LengthInBytes);
extern const char *EXA_Describe(EXA_tState State);
extern EXA_tState EXA_StatusGet(bool Failed);
extern EXA_tState EXA_Classify(uint8_t Value);

#endif /* SAMPLE_GOOD_H */
