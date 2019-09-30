#pragma once
#include "SvmStruct.h"

VOID SetvCpuMode(PVIRTUAL_PROCESSOR_DATA pVpdata, CPU_MODE CpuMode);

ULONG64 UtilPaFromVa(void *va);

void *UtilVaFromPa(ULONG64 pa);