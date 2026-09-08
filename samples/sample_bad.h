#pragma once
#include <stdint.h>
int g_shared;
typedef uint8_t *tpByte;
void ProcessFrame(uint8_t *pData, uint16_t Length);
