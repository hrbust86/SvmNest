#pragma once
#include "SvmStruct.h"

VOID ENTER_GUEST_MODE(_In_ VCPUVMX * vm);

VOID LEAVE_GUEST_MODE(_In_ VCPUVMX * vm);

VMX_MODE VmxGetVmxMode(_In_ VCPUVMX* vmx);

VCPUVMX* VmmpGetVcpuVmx(PVIRTUAL_PROCESSOR_DATA pVpdata);

_IRQL_requires_same_
VOID
SvInjectGeneralProtectionException(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
);

VOID
SvInjectGeneralProtectionExceptionVmcb02(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
);

VOID
SvInjectBPExceptionVmcb02(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
);

VOID
SvInjectBPExceptionVmcb01(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
);

VMCB * GetCurrentVmcbGuest12(PVIRTUAL_PROCESSOR_DATA pVpdata);

VMCB * GetCurrentVmcbGuest02(PVIRTUAL_PROCESSOR_DATA pVpdata);

VOID HandleMsrReadAndWrite(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext);

void ClearVGIF(PVIRTUAL_PROCESSOR_DATA VpData);

void SetVGIF(PVIRTUAL_PROCESSOR_DATA VpData);

void LeaveGuest(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext);

/////////////////////////////////// simulate VMEXIT

VOID SimulateReloadHostStateInToVmcbGuest02(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData, 
    _Inout_ PGUEST_CONTEXT GuestContext);

VOID SimulateSaveGuestStateIntoVmcbGuest12(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext);

///////////////////////////////////simulate vmrun

void SimulateVmrun02SaveHostStateShadow(
    _Inout_ PVMCB pVmcb,
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext);

void SimulateVmrun02LoadControlInfoToVmcbGuest02(
    _Inout_ PVMCB pVmcb,
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext);

void SimulateVmrun02LoadGuestStateFromVmcbGuest12(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext);