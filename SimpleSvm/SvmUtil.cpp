#include "SvmUtil.h"
#include "BaseUtil.h"

/*!
@brief      Sends a message to the kernel debugger.

@param[in]  Format - The format string to print.
@param[in]  arguments - Arguments for the format string, as in printf.
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
SvDebugPrint(
	_In_z_ _Printf_format_string_ PCSTR Format,
	...
	)
{
	va_list argList;

	va_start(argList, Format);
	vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, argList);
	va_end(argList);
}

NTSTATUS UtilVmCall(HypercallNumber hypercall_number,
	void *context) {
	__try {
		AsmSvmCall(static_cast<ULONG>(hypercall_number), context);
			return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		const auto status = GetExceptionCode();
		HYPERPLATFORM_COMMON_DBG_BREAK();
		HYPERPLATFORM_LOG_WARN_SAFE("Exception thrown (code %08x)", status);
		return status;
	}
}

void UtilWriteMsr64(Msr msr, ULONG64 value) {
	__writemsr(static_cast<unsigned long>(msr), value);
}

ULONG64 UtilReadMsr64(Msr msr) {
	return __readmsr(static_cast<unsigned long>(msr));
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

VOID SetvCpuMode(PVIRTUAL_PROCESSOR_DATA pVpdata, CPU_MODE CpuMode)
{
    //guest_context->stack->processor_data->CpuMode = CpuMode;
    pVpdata->HostStackLayout.pProcessNestData->CpuMode = CpuMode;
}

void SaveHostKernelGsBase(PVIRTUAL_PROCESSOR_DATA pVpdata)
{
    //vcpu->HostKernelGsBase.QuadPart = UtilReadMsr64(Msr::kIa32KernelGsBase);
    pVpdata->HostStackLayout.pProcessNestData->HostKernelGsBase.QuadPart = UtilReadMsr64(Msr::kIa32KernelGsBase);
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

VOID  CopyVmcbBasic(PVMCB pVmcbDest, PVMCB pVmcbSrc)
{
    pVmcbDest->StateSaveArea.FsBase = pVmcbSrc->StateSaveArea.FsBase;
    pVmcbDest->StateSaveArea.FsLimit = pVmcbSrc->StateSaveArea.FsLimit;
    pVmcbDest->StateSaveArea.FsSelector = pVmcbSrc->StateSaveArea.FsSelector;
    pVmcbDest->StateSaveArea.FsAttrib = pVmcbSrc->StateSaveArea.FsAttrib;


    pVmcbDest->StateSaveArea.GsBase = pVmcbSrc->StateSaveArea.GsBase;
    pVmcbDest->StateSaveArea.GsLimit = pVmcbSrc->StateSaveArea.GsLimit;
    pVmcbDest->StateSaveArea.GsSelector = pVmcbSrc->StateSaveArea.GsSelector;
    pVmcbDest->StateSaveArea.GsAttrib = pVmcbSrc->StateSaveArea.GsAttrib;

    pVmcbDest->StateSaveArea.KernelGsBase = pVmcbSrc->StateSaveArea.KernelGsBase;


    pVmcbDest->StateSaveArea.TrBase = pVmcbSrc->StateSaveArea.TrBase;
    pVmcbDest->StateSaveArea.TrLimit = pVmcbSrc->StateSaveArea.TrLimit;
    pVmcbDest->StateSaveArea.TrSelector = pVmcbSrc->StateSaveArea.TrSelector;
    pVmcbDest->StateSaveArea.TrAttrib = pVmcbSrc->StateSaveArea.TrAttrib;

    pVmcbDest->StateSaveArea.LdtrBase = pVmcbSrc->StateSaveArea.LdtrBase;
    pVmcbDest->StateSaveArea.LdtrLimit = pVmcbSrc->StateSaveArea.LdtrLimit;
    pVmcbDest->StateSaveArea.LdtrSelector = pVmcbSrc->StateSaveArea.LdtrSelector;
    pVmcbDest->StateSaveArea.LdtrAttrib = pVmcbSrc->StateSaveArea.LdtrAttrib;

    // star
    pVmcbDest->StateSaveArea.Star = pVmcbSrc->StateSaveArea.Star;

    // lstar
    pVmcbDest->StateSaveArea.LStar = pVmcbSrc->StateSaveArea.LStar;

    // cstar 
    pVmcbDest->StateSaveArea.CStar = pVmcbSrc->StateSaveArea.CStar;

    // sfmask
    pVmcbDest->StateSaveArea.SfMask = pVmcbSrc->StateSaveArea.SfMask;

    // sysentercs
    pVmcbDest->StateSaveArea.SysenterCs = pVmcbSrc->StateSaveArea.SysenterCs;

    // sysenteresp
    pVmcbDest->StateSaveArea.SysenterEsp = pVmcbSrc->StateSaveArea.SysenterEsp;

    // sysentereip
    pVmcbDest->StateSaveArea.SysenterEip = pVmcbSrc->StateSaveArea.SysenterEip;
}

VOID CopyVmcbAdv(PVMCB pVmcbDest, PVMCB pVmcbSrc)
{
    //ES.{base, limit, attr, sel}             
    //CS.{base, limit, attr, sel}             
    //SS.{base, limit, attr, sel}             
    //DS.{base, limit, attr, sel}
    pVmcbDest->StateSaveArea.CsBase = pVmcbSrc->StateSaveArea.CsBase;
    pVmcbDest->StateSaveArea.DsBase = pVmcbSrc->StateSaveArea.DsBase;
    pVmcbDest->StateSaveArea.EsBase = pVmcbSrc->StateSaveArea.EsBase;
    pVmcbDest->StateSaveArea.SsBase = pVmcbSrc->StateSaveArea.SsBase;
    pVmcbDest->StateSaveArea.CsLimit = pVmcbSrc->StateSaveArea.CsLimit;
    pVmcbDest->StateSaveArea.DsLimit = pVmcbSrc->StateSaveArea.DsLimit;
    pVmcbDest->StateSaveArea.EsLimit = pVmcbSrc->StateSaveArea.EsLimit;
    pVmcbDest->StateSaveArea.SsLimit = pVmcbSrc->StateSaveArea.SsLimit;
    pVmcbDest->StateSaveArea.CsSelector = pVmcbSrc->StateSaveArea.CsSelector;
    pVmcbDest->StateSaveArea.DsSelector = pVmcbSrc->StateSaveArea.DsSelector;
    pVmcbDest->StateSaveArea.EsSelector = pVmcbSrc->StateSaveArea.EsSelector;
    pVmcbDest->StateSaveArea.SsSelector = pVmcbSrc->StateSaveArea.SsSelector;
    pVmcbDest->StateSaveArea.CsAttrib = pVmcbSrc->StateSaveArea.CsAttrib;
    pVmcbDest->StateSaveArea.DsAttrib = pVmcbSrc->StateSaveArea.DsAttrib;
    pVmcbDest->StateSaveArea.EsAttrib = pVmcbSrc->StateSaveArea.EsAttrib;
    pVmcbDest->StateSaveArea.SsAttrib = pVmcbSrc->StateSaveArea.SsAttrib;

    pVmcbDest->StateSaveArea.Dr7 = pVmcbSrc->StateSaveArea.Dr7;
    pVmcbDest->StateSaveArea.Dr6 = pVmcbSrc->StateSaveArea.Dr6;

    pVmcbDest->ControlArea.InterruptShadow = pVmcbSrc->ControlArea.InterruptShadow;

    pVmcbDest->StateSaveArea.Cr2 = pVmcbSrc->StateSaveArea.Cr2;

}

NTSTATUS UtilForEachProcessor(NTSTATUS(*callback_routine)(void *), void *context) {
	PAGED_CODE();

	const auto number_of_processors =
		KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	for (ULONG processor_index = 0; processor_index < number_of_processors;
	processor_index++) {
		PROCESSOR_NUMBER processor_number = {};
		auto status =
			KeGetProcessorNumberFromIndex(processor_index, &processor_number);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		// Switch the current processor
		GROUP_AFFINITY affinity = {};
		affinity.Group = processor_number.Group;
		affinity.Mask = 1ull << processor_number.Number;
		GROUP_AFFINITY previous_affinity = {};
		KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);

		// Execute callback
		status = callback_routine(context);

		KeRevertToUserGroupAffinityThread(&previous_affinity);
		if (!NT_SUCCESS(status)) {
			return status;
		}
	}
	return STATUS_SUCCESS;
}

BOOL StartAmdSvmAndHookMsr()
{
	BOOL ret = FALSE;
	NTSTATUS status;

	SV_DEBUG_BREAK();
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	status = SvVirtualizeAllProcessors();
	if (!NT_SUCCESS(status))
	{
		goto EXIT;
	}

	status = SyscallHookEnable();
	if (!NT_SUCCESS(status))
	{
		SvDevirtualizeAllProcessors();
		goto EXIT;
	}

	ret = TRUE;

EXIT:

	return ret;
}

VOID StopAmdSvm()
{
	SyscallHookDisable();
	SvDevirtualizeAllProcessors();
}