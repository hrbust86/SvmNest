#include "BaseUtil.h"
#include "SvmUtil.h"

//------------------------------------------------------------------------------------------------//
VOID
ENTER_GUEST_MODE(
    _In_	VCPUVMX* vm
)
/*++

Desscription:

    Virtual process enter the Guest Mode.

Paremeters:

    Guest Context

Return Value:

    NO

--*/
{
    vm->inRoot = GuestMode;
    SvDebugPrint("VMM: %I64x Enter Guest mode", vm);
}

//------------------------------------------------------------------------------------------------//
VOID
LEAVE_GUEST_MODE(
    _In_	VCPUVMX* vm
)
/*++

Desscription:

    Virtual process enter the Root Mode.

Paremeters:

    Guest Context

Return Value:

    NO

--*/
{
    vm->inRoot = RootMode;
    //HYPERPLATFORM_LOG_DEBUG("VMM: %I64x Enter Root mode Reason: %d", vm, UtilVmRead(VmcsField::kVmExitReason));
    SvDebugPrint("VMM: %I64x Enter Root mode Reason: ", vm);
}

//------------------------------------------------------------------------------------------------//
VMX_MODE
VmxGetVmxMode(
    _In_ VCPUVMX* vmx
)
/*++

Desscription:

    Get VMX Mode of the corresponding virtual processor

Paremeters:

    Guest Context

Return Value:

    Emulated-Root or Emulated-Guest Mode

--*/
{
    if (vmx)
    {
        return vmx->inRoot;
    }
    else
    {
        return VMX_MODE::RootMode;
    }
}

//----------------------------------------------------------------------------------------------------------------//
VCPUVMX* VmmpGetVcpuVmx(PVIRTUAL_PROCESSOR_DATA pVpdata)
{
    //return guest_context->stack->processor_data->vcpu_vmx;
    return pVpdata->HostStackLayout.pProcessNestData->vcpu_vmx;
}

/*!
@brief          Injects #GP with 0 of error code.

@param[inout]   VpData - Per processor data.
*/
_IRQL_requires_same_
VOID
SvInjectGeneralProtectionException(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
)
{
    //SV_DEBUG_BREAK();
    EVENTINJ event;

    //
    // Inject #GP(vector = 13, type = 3 = exception) with a valid error code.
    // An error code are always zero. See "#GP—General-Protection Exception
    // (Vector 13)" for details about the error code.
    //
    event.AsUInt64 = 0;
    event.Fields.Vector = 13;
    event.Fields.Type = 3;
    event.Fields.ErrorCodeValid = 1;
    event.Fields.Valid = 1;
    VpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
}

VOID
SvInjectGeneralProtectionExceptionVmcb02(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
)
{
    //SV_DEBUG_BREAK();
    EVENTINJ event;

    //
    // Inject #GP(vector = 13, type = 3 = exception) with a valid error code.
    // An error code are always zero. See "#GP—General-Protection Exception
    // (Vector 13)" for details about the error code.
    //
    event.AsUInt64 = 0;
    event.Fields.Vector = 13;
    event.Fields.Type = 3;
    event.Fields.ErrorCodeValid = 1;
    event.Fields.Valid = 1;
    //VpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
    PVMCB pVmcbGuest02va = (PVMCB)UtilVaFromPa(VmmpGetVcpuVmx(VpData)->vmcb_guest_02_pa);
    pVmcbGuest02va->ControlArea.EventInj = event.AsUInt64;
}

VOID
SvInjectBPExceptionVmcb02(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
)
{
    EVENTINJ event;
    event.AsUInt64 = 0;
    event.Fields.Vector = 3; //  #BP¡ªBreakpoint Exception (Vector 3)
    event.Fields.Type = 3;
    //event.Fields.ErrorCodeValid = 1;  // EV (Error Code Valid)¡ªBit 11. Set to 1 if the exception should push an error code onto the stack; clear to 0 otherwise. 
    event.Fields.Valid = 1; //  V (Valid)¡ªBit 31. Set to 1 if an event is to be injected into the guest; clear to 0 otherwise. 

    GetCurrentVmcbGuest02(VpData)->ControlArea.EventInj = event.AsUInt64;
}

VOID
SvInjectBPExceptionVmcb01(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
)
{
    EVENTINJ event;
    event.AsUInt64 = 0;
    event.Fields.Vector = 3; //  #BP¡ªBreakpoint Exception (Vector 3)
    event.Fields.Type = 3;
    //event.Fields.ErrorCodeValid = 1;  // EV (Error Code Valid)¡ªBit 11. Set to 1 if the exception should push an error code onto the stack; clear to 0 otherwise. 
    event.Fields.Valid = 1; //  V (Valid)¡ªBit 31. Set to 1 if an event is to be injected into the guest; clear to 0 otherwise. 
    VpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
}

///////////////////////////////////////////

VOID SimulateReloadHostStateInVmcbGuest02(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData, _Inout_ PGUEST_CONTEXT GuestContext)
{
    //reload host state
    PVMCB pVmcbGuest12va = GetCurrentVmcbGuest12(VpData);
    PVMCB pVmcbGuest02va = GetCurrentVmcbGuest02(VpData);

    GuestContext->VpRegs->Rax = VmmpGetVcpuVmx(VpData)->vmcb_guest_12_pa; //  L2 rax, vmcb12pa
    pVmcbGuest02va->StateSaveArea.Rsp = VpData->GuestVmcb.StateSaveArea.Rsp; // L2 host rsp 
    pVmcbGuest02va->StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip; // L2 host ip 

    // the Rflags is in vmcb01 when ret to L1 host first , but it is in vmcb02 later on. i think that is all right
    //pVmcbGuest02va->StateSaveArea.Rflags = VpData->GuestVmcb.StateSaveArea.Rflags; // not right , but can not find

    SvDebugPrint("[SaveGuestVmcb12FromGuestVmcb02] pVmcbGuest12va->StateSaveArea.Rax  : %I64X \r\n", pVmcbGuest12va->StateSaveArea.Rax);
    SvDebugPrint("[SaveGuestVmcb12FromGuestVmcb02] pVmcbGuest12va->StateSaveArea.Rsp  : %I64X \r\n", pVmcbGuest12va->StateSaveArea.Rsp);
    SvDebugPrint("[SaveGuestVmcb12FromGuestVmcb02] pVmcbGuest12va->StateSaveArea.Rip  : %I64X \r\n", pVmcbGuest12va->StateSaveArea.Rip);
    SvDebugPrint("[SaveGuestVmcb12FromGuestVmcb02] pVmcbGuest12va->ControlArea.NRip  : %I64X \r\n", pVmcbGuest12va->ControlArea.NRip);
    SvDebugPrint("[SaveGuestVmcb12FromGuestVmcb02] GuestContext->VpRegs->Rax  : %I64X \r\n", GuestContext->VpRegs->Rax);
    SvDebugPrint("[SaveGuestVmcb12FromGuestVmcb02] pVmcbGuest02va->StateSaveArea.Rsp  : %I64X \r\n", pVmcbGuest02va->StateSaveArea.Rsp);
    SvDebugPrint("[SaveGuestVmcb12FromGuestVmcb02] pVmcbGuest02va->StateSaveArea.Rip  : %I64X \r\n", pVmcbGuest02va->StateSaveArea.Rip);

}

VOID SimulateSaveGuestStateIntoVmcbGuest12(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData, _Inout_ PGUEST_CONTEXT GuestContext)
{
    PVMCB pVmcbGuest02va = (PVMCB)UtilVaFromPa(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_02_pa);
    PVMCB pVmcbGuest12va = (PVMCB)UtilVaFromPa(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_12_pa);

    pVmcbGuest12va->StateSaveArea.Rax = GuestContext->VpRegs->Rax; // save L2 rax => vmcb12 in L2
    pVmcbGuest12va->StateSaveArea.Rsp = pVmcbGuest02va->StateSaveArea.Rsp; // save L2 guest rsp=> vmcb12
    pVmcbGuest12va->StateSaveArea.Rflags = pVmcbGuest02va->StateSaveArea.Rflags; // save L2 guest rflags => vmcb12
    pVmcbGuest12va->StateSaveArea.Rip = pVmcbGuest02va->StateSaveArea.Rip; // save L2 rip => vmcb12
    pVmcbGuest12va->ControlArea.NRip = pVmcbGuest02va->ControlArea.NRip; // save L2 next rip => vmcb12

    pVmcbGuest12va->ControlArea.ExitCode = pVmcbGuest02va->ControlArea.ExitCode;
    pVmcbGuest12va->ControlArea.ExitInfo1 = pVmcbGuest02va->ControlArea.ExitInfo1;
    pVmcbGuest12va->ControlArea.ExitInfo2 = pVmcbGuest02va->ControlArea.ExitInfo2;
    pVmcbGuest12va->ControlArea.ExitIntInfo = pVmcbGuest02va->ControlArea.ExitIntInfo;
    pVmcbGuest12va->ControlArea.EventInj = pVmcbGuest02va->ControlArea.EventInj;
    pVmcbGuest12va->StateSaveArea.Cpl = pVmcbGuest02va->StateSaveArea.Cpl;
    pVmcbGuest12va->StateSaveArea.LStar = pVmcbGuest02va->StateSaveArea.LStar;

    // simulate save guest state to VMCB12: 

    // ES.{base,limit,attr,sel} 
    // CS.{base,limit,attr,sel} 
    // SS.{base,limit,attr,sel} 
    // DS.{base,limit,attr,sel} 
    pVmcbGuest12va->StateSaveArea.CsLimit = pVmcbGuest02va->StateSaveArea.CsLimit;
    pVmcbGuest12va->StateSaveArea.DsLimit = pVmcbGuest02va->StateSaveArea.DsLimit;
    pVmcbGuest12va->StateSaveArea.EsLimit = pVmcbGuest02va->StateSaveArea.EsLimit;
    pVmcbGuest12va->StateSaveArea.SsLimit = pVmcbGuest02va->StateSaveArea.SsLimit;
    pVmcbGuest12va->StateSaveArea.CsSelector = pVmcbGuest02va->StateSaveArea.CsSelector;
    pVmcbGuest12va->StateSaveArea.DsSelector = pVmcbGuest02va->StateSaveArea.DsSelector;
    pVmcbGuest12va->StateSaveArea.EsSelector = pVmcbGuest02va->StateSaveArea.EsSelector;
    pVmcbGuest12va->StateSaveArea.SsSelector = pVmcbGuest02va->StateSaveArea.SsSelector;
    pVmcbGuest12va->StateSaveArea.CsAttrib = pVmcbGuest02va->StateSaveArea.CsAttrib;
    pVmcbGuest12va->StateSaveArea.DsAttrib = pVmcbGuest02va->StateSaveArea.DsAttrib;
    pVmcbGuest12va->StateSaveArea.EsAttrib = pVmcbGuest02va->StateSaveArea.EsAttrib;
    pVmcbGuest12va->StateSaveArea.SsAttrib = pVmcbGuest02va->StateSaveArea.SsAttrib;

    //GDTR.{base, limit}
    //IDTR.{base, limit}

    pVmcbGuest12va->StateSaveArea.GdtrBase = pVmcbGuest02va->StateSaveArea.GdtrBase;
    pVmcbGuest12va->StateSaveArea.GdtrLimit = pVmcbGuest02va->StateSaveArea.GdtrLimit;
    pVmcbGuest12va->StateSaveArea.IdtrBase = pVmcbGuest02va->StateSaveArea.IdtrBase;
    pVmcbGuest12va->StateSaveArea.IdtrLimit = pVmcbGuest02va->StateSaveArea.IdtrLimit;

    //EFER CR4 CR3 CR2 CR0
    pVmcbGuest12va->StateSaveArea.Efer = pVmcbGuest02va->StateSaveArea.Efer;
    pVmcbGuest12va->StateSaveArea.Cr4 = pVmcbGuest02va->StateSaveArea.Cr4;
    pVmcbGuest12va->StateSaveArea.Cr3 = pVmcbGuest02va->StateSaveArea.Cr3;
    pVmcbGuest12va->StateSaveArea.Cr2 = pVmcbGuest02va->StateSaveArea.Cr2;
    pVmcbGuest12va->StateSaveArea.Cr0 = pVmcbGuest02va->StateSaveArea.Cr0;

    //if (nested paging enabled)    gPAT
    pVmcbGuest12va->StateSaveArea.GPat = pVmcbGuest02va->StateSaveArea.GPat;

    // DR7 DR6 
    pVmcbGuest12va->StateSaveArea.Dr7 = pVmcbGuest02va->StateSaveArea.Dr7;
    pVmcbGuest12va->StateSaveArea.Dr6 = pVmcbGuest02va->StateSaveArea.Dr6;

}

VMCB * GetCurrentVmcbGuest12(PVIRTUAL_PROCESSOR_DATA pVpdata)
{
    PVMCB pVmcbGuest12va = (PVMCB)UtilVaFromPa(VmmpGetVcpuVmx(pVpdata)->vmcb_guest_12_pa);
    return pVmcbGuest12va;
}

VMCB * GetCurrentVmcbGuest02(PVIRTUAL_PROCESSOR_DATA pVpdata)
{
    PVMCB pVmcbGuest02va = (PVMCB)UtilVaFromPa(VmmpGetVcpuVmx(pVpdata)->vmcb_guest_02_pa);
    return pVmcbGuest02va;
}

VOID HandleMsrReadAndWrite(
_Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext)
{
    PVMCB pVmcbGuest02va = GetCurrentVmcbGuest02(VpData);
    LARGE_INTEGER MsrValue = { 0 };
    if (0 == pVmcbGuest02va->ControlArea.ExitInfo1) // read
    {
        Msr MsrNum = (Msr)GuestContext->VpRegs->Rcx;
        MsrValue.QuadPart = UtilReadMsr64(MsrNum); // read from host

        GuestContext->VpRegs->Rax = MsrValue.LowPart;
        GuestContext->VpRegs->Rdx = MsrValue.HighPart;
    }
    else
    {
        Msr MsrNum = (Msr)GuestContext->VpRegs->Rcx;
        MsrValue.LowPart = (ULONG)GuestContext->VpRegs->Rax;
        MsrValue.HighPart = (ULONG)GuestContext->VpRegs->Rdx;
        UtilWriteMsr64(MsrNum, MsrValue.QuadPart);
    }
}

void ClearVGIF(PVIRTUAL_PROCESSOR_DATA VpData)
{
    //60h 9 VGIF value(0 ¨C Virtual interrupts are masked, 1 ¨C Virtual Interrupts are unmasked)
    UINT64 tmp = ~GetCurrentVmcbGuest02(VpData)->ControlArea.VIntr;
    tmp |= (1UL << 9);
    GetCurrentVmcbGuest02(VpData)->ControlArea.VIntr = ~tmp;
}

void SetVGIF(PVIRTUAL_PROCESSOR_DATA VpData)
{
    //60h 9 VGIF value(0 ¨C Virtual interrupts are masked, 1 ¨C Virtual Interrupts are unmasked)
    GetCurrentVmcbGuest02(VpData)->ControlArea.VIntr |= (1UL << 9);
}

void LeaveGuest(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext)
{
    // Clears the global interrupt flag (GIF). While GIF is zero, all external interrupts are disabled. 
    ClearVGIF(VpData);
    SimulateSaveGuestStateIntoVmcbGuest12(VpData, GuestContext);
    SimulateReloadHostStateInVmcbGuest02(VpData, GuestContext);
    LEAVE_GUEST_MODE(VmmpGetVcpuVmx(VpData));
}

void SimulateVmrun02SaveHostStateShadow(
    _Inout_ PVMCB pVmcb,
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext)
{
    // save host state to physical memory indicated in the VM_HSAVE_PA MSR: 

    PVMCB pVmcbHostStateShadow = &(VmmpGetVcpuVmx(VpData)->VmcbHostStateArea02Shadow);
    //ES.sel 
    //CS.sel 
    //SS.sel
    //DS.sel
    pVmcbHostStateShadow->StateSaveArea.CsSelector = pVmcb->StateSaveArea.CsSelector;
    pVmcbHostStateShadow->StateSaveArea.DsSelector = pVmcb->StateSaveArea.DsSelector;
    pVmcbHostStateShadow->StateSaveArea.EsSelector = pVmcb->StateSaveArea.EsSelector;
    pVmcbHostStateShadow->StateSaveArea.SsSelector = pVmcb->StateSaveArea.SsSelector;

    //GDTR.{base,limit} 
    //IDTR.{base,limit} 
    pVmcbHostStateShadow->StateSaveArea.GdtrBase = pVmcb->StateSaveArea.GdtrBase;
    pVmcbHostStateShadow->StateSaveArea.GdtrLimit = pVmcb->StateSaveArea.GdtrLimit;
    pVmcbHostStateShadow->StateSaveArea.IdtrBase = pVmcb->StateSaveArea.IdtrBase;
    pVmcbHostStateShadow->StateSaveArea.IdtrLimit = pVmcb->StateSaveArea.IdtrLimit;

    //EFER 
    //CR0 
    //CR4 
    //CR3
    pVmcbHostStateShadow->StateSaveArea.Efer = pVmcb->StateSaveArea.Efer;
    pVmcbHostStateShadow->StateSaveArea.Cr0 = pVmcb->StateSaveArea.Cr0;
    pVmcbHostStateShadow->StateSaveArea.Cr4 = pVmcb->StateSaveArea.Cr4;
    pVmcbHostStateShadow->StateSaveArea.Cr3 = pVmcb->StateSaveArea.Cr3;

    // host CR2 is not saved 
    //RFLAGS 
    //RIP 
    //RSP 
    //RAX

    pVmcbHostStateShadow->StateSaveArea.Rflags = pVmcb->StateSaveArea.Rflags;
    pVmcbHostStateShadow->StateSaveArea.Rip = pVmcb->StateSaveArea.Rip;
    pVmcbHostStateShadow->StateSaveArea.Rsp = pVmcb->StateSaveArea.Rsp;
    // "vmrun eax" of L1 host store in vmcbguest02.  except firstly it is in the vmcb01
    pVmcbHostStateShadow->StateSaveArea.Rax = pVmcb->StateSaveArea.Rax; 
}