#include "BaseUtil.h"
#include "SvmUtil.h"

VOID SetvCpuMode(PVIRTUAL_PROCESSOR_DATA pVpdata, CPU_MODE CpuMode)
{
    //guest_context->stack->processor_data->CpuMode = CpuMode;
    pVpdata->HostStackLayout.pProcessNestData->CpuMode = CpuMode;
}

// VA -> PA
ULONG64 UtilPaFromVa(void *va)
{
    const auto pa = MmGetPhysicalAddress(va);
    return pa.QuadPart;
}

// PA -> VA
void *UtilVaFromPa(ULONG64 pa) 
{
    PHYSICAL_ADDRESS pa2 = {};
    pa2.QuadPart = pa;
    return MmGetVirtualForPhysical(pa2);
}

void SaveHostKernelGsBase(PVIRTUAL_PROCESSOR_DATA pVpdata)
{
	//vcpu->HostKernelGsBase.QuadPart = UtilReadMsr64(Msr::kIa32KernelGsBase);
	pVpdata->HostStackLayout.pProcessNestData->HostKernelGsBase.QuadPart = UtilReadMsr64(Msr::kIa32KernelGsBase);
}