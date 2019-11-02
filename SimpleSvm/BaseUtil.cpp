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

VOID SaveGuestVmcb12FromGuestVmcb02(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData, _Inout_ PGUEST_CONTEXT GuestContext)
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

BOOLEAN CheckVmcb12MsrBit(
_Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext)
{
    PVMCB pVmcbGuest12va = GetCurrentVmcbGuest12(VpData);
	PVMCB pVmcbGuest02va = GetCurrentVmcbGuest02(VpData);
	BOOL bIsWrite = (BOOL)pVmcbGuest02va->ControlArea.ExitInfo1;

    PVOID MsrPermissionsMap = UtilVaFromPa(pVmcbGuest12va->ControlArea.MsrpmBasePa);
    RTL_BITMAP bitmapHeader;
	static const UINT32 FIRST_MSR_RANGE_BASE = 0x00000000;
	static const UINT32 SECOND_MSR_RANGE_BASE = 0xc0000000;
	static const UINT32 THIRD_MSR_RANGE_BASE = 0xC0010000;
	static const UINT32 BITS_PER_MSR = 2;
	static const UINT32 FIRST_MSRPM_OFFSET = 0x000 * CHAR_BIT;
	static const UINT32 SECOND_MSRPM_OFFSET = 0x800 * CHAR_BIT;
	static const UINT32 THIRD_MSRPM_OFFSET = 0x1000 * CHAR_BIT;
	ULONG64 offsetFromBase = 0;
    ULONG64 offset = 0;

    RtlInitializeBitMap(&bitmapHeader,
        reinterpret_cast<PULONG>(MsrPermissionsMap),
        SVM_MSR_PERMISSIONS_MAP_SIZE * CHAR_BIT
    );

	UINT64 MsrNum = GuestContext->VpRegs->Rcx;
	if (MsrNum > FIRST_MSR_RANGE_BASE && MsrNum < SECOND_MSR_RANGE_BASE)
	{
		offsetFromBase = (MsrNum - FIRST_MSR_RANGE_BASE) * BITS_PER_MSR;
		offset = FIRST_MSRPM_OFFSET + offsetFromBase;
	}
	if (MsrNum > SECOND_MSR_RANGE_BASE && MsrNum < THIRD_MSR_RANGE_BASE)
	{
        offsetFromBase = (MsrNum - SECOND_MSR_RANGE_BASE) * BITS_PER_MSR;
        offset = SECOND_MSRPM_OFFSET + offsetFromBase;
	}
	if (MsrNum > THIRD_MSR_RANGE_BASE)
	{
        offsetFromBase = (MsrNum - THIRD_MSR_RANGE_BASE) * BITS_PER_MSR;
        offset = THIRD_MSRPM_OFFSET + offsetFromBase;
	}

    BOOLEAN bret = FALSE;
    if (FALSE == bIsWrite)
    {
        bret = RtlTestBit(&bitmapHeader, (ULONG)offset);
    }
    else
    {
        bret = RtlTestBit(&bitmapHeader, ULONG(offset + 1));
    }
    return bret;
}

void ClearVGIF(PVIRTUAL_PROCESSOR_DATA VpData)
{
    //60h 9 VGIF value(0 每 Virtual interrupts are masked, 1 每 Virtual Interrupts are unmasked)
    UINT64 tmp = ~GetCurrentVmcbGuest02(VpData)->ControlArea.VIntr;
    tmp |= (1UL << 9);
    GetCurrentVmcbGuest02(VpData)->ControlArea.VIntr = ~tmp;
}

void SetVGIF(PVIRTUAL_PROCESSOR_DATA VpData)
{
    //60h 9 VGIF value(0 每 Virtual interrupts are masked, 1 每 Virtual Interrupts are unmasked)
    GetCurrentVmcbGuest02(VpData)->ControlArea.VIntr |= (1UL << 9);
}