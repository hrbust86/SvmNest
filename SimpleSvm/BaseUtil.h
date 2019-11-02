#pragma once
#include "SvmStruct.h"

VOID SetvCpuMode(PVIRTUAL_PROCESSOR_DATA pVpdata, CPU_MODE CpuMode);

ULONG64 UtilPaFromVa(void *va);

void *UtilVaFromPa(ULONG64 pa);

void SaveHostKernelGsBase(PVIRTUAL_PROCESSOR_DATA pVpdata);

VOID ENTER_GUEST_MODE(_In_ VCPUVMX * vm);

VOID LEAVE_GUEST_MODE(_In_ VCPUVMX * vm);

VMX_MODE VmxGetVmxMode(_In_ VCPUVMX* vmx);

VCPUVMX* VmmpGetVcpuVmx(PVIRTUAL_PROCESSOR_DATA pVpdata);

VOID SaveGuestVmcb12FromGuestVmcb02(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData, 
_Inout_ PGUEST_CONTEXT GuestContext);

VMCB * GetCurrentVmcbGuest12(PVIRTUAL_PROCESSOR_DATA pVpdata);

VMCB * GetCurrentVmcbGuest02(PVIRTUAL_PROCESSOR_DATA pVpdata);

VOID HandleMsrReadAndWrite(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext);

BOOLEAN CheckVmcb12MsrBit(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext);

void ClearVGIF(PVIRTUAL_PROCESSOR_DATA VpData);

void SetVGIF(PVIRTUAL_PROCESSOR_DATA VpData);

void LeaveGuest(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext);