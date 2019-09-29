#include "BaseUtil.h"

VOID SetvCpuMode(PVIRTUAL_PROCESSOR_DATA pVpdata, CPU_MODE CpuMode)
{
    //guest_context->stack->processor_data->CpuMode = CpuMode;
    pVpdata->HostStackLayout.pProcessNestData->CpuMode = CpuMode;
}

