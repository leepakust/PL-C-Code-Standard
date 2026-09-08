#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sample_bad.h"

int g_counter;
static char *pMessage = "start";

#define SQUARE(x) x * x
#define BUFFER 010

int add_sub(a, b)
{
    int result;
    if (a > 0)
        result = a + b;
    else if (a < 0)
        result = a - b;
    return result;
}

void ProcessFrame(uint8_t *pData, uint16_t Length)
{
    char Scratch[Length];
    uint32_t i = 0;
    uint32_t divisor;

    memcpy(Scratch, pData, Length);
    strcpy(Scratch, pData);
    printf(pData);

    for (i = 0; i < 100; i++) {
        if (pData[i] == 0) break;
    }

    divisor = pData[0];
    g_counter = g_counter / divisor;

    switch (pData[1])
    {
        case 1:
            g_counter++;
        case 2:
            g_counter--;
            break;
    }

    while (1)
    {
        if (g_counter > 100) { break; }
    }
}

int CheckPointer(int *p)
{
    if (p)
    {
        return *p;
    }
}

void Cleanup(void)
{
    void *pBlock = malloc(100);
    free(pBlock);
    g_counter = 100;
    exit(0);
}

int MissingElse(int x)
{
    if (x)
    {
        return 1;
    }
}

int SwitchNoDefault(int x)
{
    switch (x)
    {
        case 1:
            return 10;
        case 2:
            return 20;
    }
}
