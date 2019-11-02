#include "SvmTraps.h"
#include "BaseUtil.h"
#include "log/log.h"

/*!
@brief          Handles #VMEXIT due to execution of the WRMSR and RDMSR
instructions.

@details        This protects EFER.SVME from being cleared by the guest by
injecting #GP when it is about to be cleared.

@param[inout]   VpData - Per processor data.
@param[inout]   GuestRegisters - Guest's GPRs.
*/

VOID SvHandleEFERWrite(
			_Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
			_Inout_ PGUEST_CONTEXT GuestContext)
{
	UINT64 writeValueLow, writeValueHi, writeValue;

	//
	// #VMEXIT should only occur on write accesses to IA32_MSR_EFER. 1 of
	// ExitInfo1 indicates a write access.
	//
	NT_ASSERT(GuestContext->VpRegs->Rcx == IA32_MSR_EFER);
	NT_ASSERT(VpData->GuestVmcb.ControlArea.ExitInfo1 != 0);

	writeValueLow = GuestContext->VpRegs->Rax & MAXUINT32;
	if ((writeValueLow & EFER_SVME) == 0)
	{
		//
		// Inject #GP if the guest attempts to clear the SVME bit. Protection of
		// this bit is required because clearing the bit while guest is running
		// leads to undefined behavior.
		//
		SvInjectGeneralProtectionException(VpData);
	}

	//
	// Otherwise, update the MSR as requested. Important to note that the value
	// should be checked not to allow any illegal values, and inject #GP as
	// needed. Otherwise, the hypervisor attempts to resume the guest with an
	// illegal EFER and immediately receives #VMEXIT due to VMEXIT_INVALID,
	// which in our case, results in a bug check. See "Extended Feature Enable
	// Register (EFER)" for what values are allowed.
	//
	// This code does not implement the check intentionally, for simplicity.
	//
	writeValueHi = GuestContext->VpRegs->Rdx & MAXUINT32;
	writeValue = writeValueHi << 32 | writeValueLow;
	VpData->GuestVmcb.StateSaveArea.Efer = writeValue;

	//
	// Then, advance RIP to "complete" the instruction.
	//
	VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip;
	//VpData->GuestVmcb.StateSaveArea.Rip += 2;
}

VOID SvHandleLstrRead(
	_Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
	_Inout_ PGUEST_CONTEXT GuestContext)
{
	NT_ASSERT(GuestContext->VpRegs->Rcx == IA32_MSR_LSTR);
	//NT_ASSERT(VpData->GuestVmcb.ControlArea.ExitInfo1 != 0); // ?????

	LARGE_INTEGER MsrValue = {0};

	if (0 == VpData->GuestVmcb.ControlArea.ExitInfo1) // read
	{
// 		if (0 == VpData->HostStackLayout.OriginalMsrLstar)
// 		{
 			MsrValue.QuadPart = VpData->GuestVmcb.StateSaveArea.LStar;
// 		}
// 		else
// 		{
// 			MsrValue.QuadPart = VpData->HostStackLayout.OriginalMsrLstar;
// 		}
 		GuestContext->VpRegs->Rax = MsrValue.LowPart;
 		GuestContext->VpRegs->Rdx = MsrValue.HighPart;
	}
	else // write
	{
		// never write success
	}

	VpData->GuestVmcb.StateSaveArea.Rip += 2;
}

VOID SvHandleSvmHsave(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext)
{
    NT_ASSERT(GuestContext->VpRegs->Rcx == (UINT64)Msr::kIa32svmHsave);

    if (0 == VpData->GuestVmcb.ControlArea.ExitInfo1) // read
    {
        GuestContext->VpRegs->Rax = VpData->HostStackLayout.pProcessNestData->GuestSvmHsave12.LowPart;
        GuestContext->VpRegs->Rdx = VpData->HostStackLayout.pProcessNestData->GuestSvmHsave12.HighPart;
    }
    else // write
    {
        VpData->HostStackLayout.pProcessNestData->GuestSvmHsave12.LowPart = (ULONG)GuestContext->VpRegs->Rax;
        VpData->HostStackLayout.pProcessNestData->GuestSvmHsave12.HighPart = (ULONG)GuestContext->VpRegs->Rdx;
    }

    VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip; // need npt
}

VOID SvHandleEffer(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext)
{
    NT_ASSERT(GuestContext->VpRegs->Rcx == IA32_MSR_EFER);

    if (0 == VpData->GuestVmcb.ControlArea.ExitInfo1) // read
    {
        GuestContext->VpRegs->Rax = VpData->HostStackLayout.pProcessNestData->GuestMsrEFER.LowPart;
        GuestContext->VpRegs->Rdx = VpData->HostStackLayout.pProcessNestData->GuestMsrEFER.HighPart;
    }
    else
    {
        VpData->HostStackLayout.pProcessNestData->GuestMsrEFER.LowPart = (ULONG)GuestContext->VpRegs->Rax;
        VpData->HostStackLayout.pProcessNestData->GuestMsrEFER.HighPart = (ULONG)GuestContext->VpRegs->Rdx;
    }

    VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip; // need npt
}

VOID SvHandleBreakPointException(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
)
{
    UNREFERENCED_PARAMETER(GuestContext);
    SvInjectBPExceptionVmcb01(VpData);
    VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip; // need npt
}

_IRQL_requires_same_
VOID
SvHandleVmrunEx(
	_Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
	_Inout_ PGUEST_CONTEXT GuestContext
)
{
	//SV_DEBUG_BREAK();
	NT_ASSERT(GuestContext->VpRegs->Rax != 0);

    if (NULL == VpData->HostStackLayout.pProcessNestData->vcpu_vmx && 
        CPU_MODE::VmxMode != VpData->HostStackLayout.pProcessNestData->CpuMode) // 没有开始嵌套
    {
        VCPUVMX *	 nested_vmx = NULL;
        PROCESSOR_NUMBER      number = { 0 };
        nested_vmx = (VCPUVMX*)ExAllocatePool(NonPagedPoolNx, sizeof(VCPUVMX));
        memset(nested_vmx, 0, sizeof(VCPUVMX));
        nested_vmx->inRoot = VMX_MODE::RootMode;
        nested_vmx->blockINITsignal = TRUE;
        nested_vmx->blockAndDisableA20M = TRUE;
        nested_vmx->InitialCpuNumber = KeGetCurrentProcessorNumberEx(&number);

        // vcpu etner vmx-root mode now
        SetvCpuMode(VpData, CPU_MODE::VmxMode);
        VpData->HostStackLayout.pProcessNestData->vcpu_vmx = nested_vmx;

        SvDebugPrint("[SvHandleVmrunEx]: Run Successfully with  Total Vitrualized Core: %x  Current Cpu: %x in Cpu Group : %x  Number: %x \r\n",
             nested_vmx->InitialCpuNumber, number.Group, number.Number);
        
        // Load VMCB02 into physical cpu , And perform some check on VMCB12
        PVOID pVmcb02VaGuest = ExAllocatePool(NonPagedPoolNx, PAGE_SIZE);
        PVOID pVmcb02VaHost = ExAllocatePool(NonPagedPoolNx, PAGE_SIZE);
        RtlZeroMemory(pVmcb02VaGuest, PAGE_SIZE);
        RtlZeroMemory(pVmcb02VaHost, PAGE_SIZE);
        
        VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_02_pa = UtilPaFromVa(pVmcb02VaGuest);
        VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_host_02_pa = UtilPaFromVa(pVmcb02VaHost);
        VpData->HostStackLayout.pProcessNestData->vcpu_vmx->hostStateAreaPa_02_pa = UtilPaFromVa(VpData->HostStateArea);

        nested_vmx->kVirtualProcessorId = (USHORT)KeGetCurrentProcessorNumberEx(nullptr) + 1;

        SvDebugPrint("[SvHandleVmrunEx] Run Successfully \r\n");
        SvDebugPrint("[SvHandleVmrunEx] Current Cpu: %x in Cpu Group : %x  Number: %x \r\n", nested_vmx->InitialCpuNumber, number.Group, number.Number);

        // emulate write and read 
        //  SvLaunchVm(&vpData->HostStackLayout.GuestVmcbPa);
        VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_12_pa = GuestContext->VpRegs->Rax;
        SvDebugPrint("[SvHandleVmrunEx] : vmcb12pa : %I64X  \r\n", GuestContext->VpRegs->Rax);
		//VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_host_12_pa = VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_02_pa;
        VpData->HostStackLayout.pProcessNestData->vcpu_vmx->hostStateAreaPa_12_pa = VpData->HostStackLayout.pProcessNestData->GuestSvmHsave12.QuadPart;

		// 01 -> 02
		// PrepareHostAndControlField
		PVMCB pVmcbGuest02va = (PVMCB)UtilVaFromPa(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_02_pa);
		PVMCB pVmcbGuest12va = (PVMCB)UtilVaFromPa(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_12_pa);
		PVMCB pVmcbGuest01va = &VpData->GuestVmcb;

        __svm_vmsave(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_02_pa);
		// 01 and 12 -> 02  ControlField
		pVmcbGuest02va->ControlArea.InterceptMisc1 = pVmcbGuest01va->ControlArea.InterceptMisc1 | pVmcbGuest12va->ControlArea.InterceptMisc1;
		pVmcbGuest02va->ControlArea.InterceptMisc2 = pVmcbGuest01va->ControlArea.InterceptMisc2 | pVmcbGuest12va->ControlArea.InterceptMisc2;
		pVmcbGuest02va->ControlArea.MsrpmBasePa = pVmcbGuest01va->ControlArea.MsrpmBasePa; // only use 01 msr int
        pVmcbGuest02va->ControlArea.InterceptException = pVmcbGuest01va->ControlArea.InterceptException; // only use 01 int
		pVmcbGuest02va->ControlArea.GuestAsid = pVmcbGuest01va->ControlArea.GuestAsid;
		pVmcbGuest02va->ControlArea.NpEnable = pVmcbGuest01va->ControlArea.NpEnable;
		pVmcbGuest02va->ControlArea.NCr3 = pVmcbGuest01va->ControlArea.NCr3;
		pVmcbGuest02va->ControlArea.LbrVirtualizationEnable = pVmcbGuest01va->ControlArea.LbrVirtualizationEnable;
		pVmcbGuest02va->ControlArea.VIntr = pVmcbGuest01va->ControlArea.VIntr;
		
		// 12 -> 02 statesavearea and guestfield
		pVmcbGuest02va->StateSaveArea.GdtrBase = pVmcbGuest12va->StateSaveArea.GdtrBase;
		pVmcbGuest02va->StateSaveArea.GdtrLimit = pVmcbGuest12va->StateSaveArea.GdtrLimit;
		pVmcbGuest02va->StateSaveArea.IdtrBase = pVmcbGuest12va->StateSaveArea.IdtrBase;
		pVmcbGuest02va->StateSaveArea.IdtrLimit = pVmcbGuest12va->StateSaveArea.IdtrLimit;

		pVmcbGuest02va->StateSaveArea.CsLimit = pVmcbGuest12va->StateSaveArea.CsLimit;
		pVmcbGuest02va->StateSaveArea.DsLimit = pVmcbGuest12va->StateSaveArea.DsLimit;
		pVmcbGuest02va->StateSaveArea.EsLimit = pVmcbGuest12va->StateSaveArea.EsLimit;
		pVmcbGuest02va->StateSaveArea.SsLimit = pVmcbGuest12va->StateSaveArea.SsLimit;
		pVmcbGuest02va->StateSaveArea.CsSelector = pVmcbGuest12va->StateSaveArea.CsSelector;
		pVmcbGuest02va->StateSaveArea.DsSelector = pVmcbGuest12va->StateSaveArea.DsSelector;
		pVmcbGuest02va->StateSaveArea.EsSelector = pVmcbGuest12va->StateSaveArea.EsSelector;
		pVmcbGuest02va->StateSaveArea.SsSelector = pVmcbGuest12va->StateSaveArea.SsSelector;
		pVmcbGuest02va->StateSaveArea.CsAttrib = pVmcbGuest12va->StateSaveArea.CsAttrib;
		pVmcbGuest02va->StateSaveArea.DsAttrib = pVmcbGuest12va->StateSaveArea.DsAttrib;
		pVmcbGuest02va->StateSaveArea.EsAttrib = pVmcbGuest12va->StateSaveArea.EsAttrib;
		pVmcbGuest02va->StateSaveArea.SsAttrib = pVmcbGuest12va->StateSaveArea.SsAttrib;

		SV_DEBUG_BREAK();
		pVmcbGuest02va->StateSaveArea.Efer = __readmsr(IA32_MSR_EFER);
		pVmcbGuest02va->StateSaveArea.Cr0 = __readcr0();
		pVmcbGuest02va->StateSaveArea.Cr2 = __readcr2();
		pVmcbGuest02va->StateSaveArea.Cr3 = __readcr3();
		pVmcbGuest02va->StateSaveArea.Cr4 = __readcr4();
		pVmcbGuest02va->StateSaveArea.Rflags = pVmcbGuest12va->StateSaveArea.Rflags;
		pVmcbGuest02va->StateSaveArea.Rsp = pVmcbGuest12va->StateSaveArea.Rsp;
		pVmcbGuest02va->StateSaveArea.Rip = pVmcbGuest12va->StateSaveArea.Rip;
		pVmcbGuest02va->StateSaveArea.GPat = __readmsr(IA32_MSR_PAT);

		SaveHostKernelGsBase(VpData);
		__writemsr(SVM_MSR_VM_HSAVE_PA, VpData->HostStackLayout.pProcessNestData->GuestSvmHsave12.QuadPart); // prevent to destroy the 01 HostStateArea
		//__svm_vmrun(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_02_pa);
		VpData->HostStackLayout.pProcessNestData->vcpu_vmx->pVpdata = VpData;
        __svm_vmsave(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_host_02_pa);

		//SvLaunchVm(&(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_02_pa));
        GuestContext->ExitVm = EXIT_REASON::EXIT_NEST_SET_VMCB02;
        GuestContext->VpRegs->Rbx = (UINT64)&(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_02_pa);

        ENTER_GUEST_MODE(VpData->HostStackLayout.pProcessNestData->vcpu_vmx);

    }
	else // 嵌套环境已经建立
    {
		SV_DEBUG_BREAK();
		//SvInjectGeneralProtectionException(VpData);
// 		PVMCB pVmcbGuest12va = (PVMCB)UtilVaFromPa(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_12_pa);
// 		VpData->GuestVmcb.StateSaveArea.Rip = pVmcbGuest12va->StateSaveArea.Rip;
    }

	//VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip; // need npt
}

VOID
SvHandleVmrunExForL1ToL2(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
)
{
    UNREFERENCED_PARAMETER(GuestContext);
    if ( VMX_MODE::RootMode == VmxGetVmxMode(VmmpGetVcpuVmx(VpData)))
    {
        PVMCB pVmcbGuest02va = (PVMCB)UtilVaFromPa(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_02_pa);
        PVMCB pVmcbGuest12va = (PVMCB)UtilVaFromPa(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_12_pa);
        pVmcbGuest02va->StateSaveArea.Rflags = pVmcbGuest12va->StateSaveArea.Rflags;
        pVmcbGuest02va->StateSaveArea.Rsp = pVmcbGuest12va->StateSaveArea.Rsp;
        pVmcbGuest02va->StateSaveArea.Rip = pVmcbGuest12va->StateSaveArea.Rip;
        pVmcbGuest02va->StateSaveArea.LStar = pVmcbGuest12va->StateSaveArea.LStar;
		GuestContext->VpRegs->Rax = pVmcbGuest12va->StateSaveArea.Rax;
		pVmcbGuest02va->StateSaveArea.Rax = pVmcbGuest12va->StateSaveArea.Rax;

        ENTER_GUEST_MODE(VpData->HostStackLayout.pProcessNestData->vcpu_vmx);
        // Sets the global interrupt flag (GIF) to 1. 
        SetVGIF(VpData);
    }
    else
    {
        SvInjectGeneralProtectionExceptionVmcb02(VpData);
        // something error
    }
}

//Mnemonic Opcode Description
//VMMCALL 0F 01 D9 Explicit communication with the VMM.
VOID SvHandleVmmcall(
	_Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
	_Inout_ PGUEST_CONTEXT GuestContext)
{
	if (0 == VpData->GuestVmcb.StateSaveArea.Cpl)
	{
		auto HyperNum = (HypercallNumber)(GuestContext->VpRegs->Rcx);
		unsigned __int64 context = (unsigned __int64)GuestContext->VpRegs->Rdx;
		//SV_DEBUG_BREAK();
		switch (HyperNum)
		{
		case HypercallNumber::kTerminateVmm:
			break;
		case HypercallNumber::kHookSyscall:
			VmmpHandleVmCallHookSyscall(VpData, (void *)context);
			break;
		case HypercallNumber::kUnhookSyscall:
			VmmpHandleVmCallUnHookSyscall(VpData);
			break;
		default:
			SvInjectGeneralProtectionException(VpData);
		}
		VpData->GuestVmcb.StateSaveArea.Rip += 3; 
	}
	else
	{
		SvInjectGeneralProtectionException(VpData);
	}
	
}

VOID SvHandleVmmcallNest(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext)
{
    if (VMX_MODE::RootMode == VmxGetVmxMode(VmmpGetVcpuVmx(VpData)))
    {
        PVMCB pVmcbGuest02va = (PVMCB)UtilVaFromPa(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_02_pa);
        pVmcbGuest02va->StateSaveArea.Rip = pVmcbGuest02va->ControlArea.NRip;
        return; // return L1
    }

//     SaveGuestVmcb12FromGuestVmcb02(VpData, GuestContext);
//     LEAVE_GUEST_MODE(VmmpGetVcpuVmx(VpData));     // retrun L1 host
    LeaveGuest(VpData, GuestContext);
}

void VmmpHandleVmCallHookSyscall(
	PVIRTUAL_PROCESSOR_DATA VpData, void * NewSysCallEntry)
{
    UNREFERENCED_PARAMETER(VpData);
    UNREFERENCED_PARAMETER(NewSysCallEntry);
// 	VpData->HostStackLayout.OriginalMsrLstar = UtilReadMsr64(Msr::kIa32Lstar); // read from host
// 	VpData->GuestVmcb.StateSaveArea.LStar = (UINT64)NewSysCallEntry;
}

void VmmpHandleVmCallUnHookSyscall(PVIRTUAL_PROCESSOR_DATA VpData)
{
    UNREFERENCED_PARAMETER(VpData);
// 	VpData->GuestVmcb.StateSaveArea.LStar = VpData->HostStackLayout.OriginalMsrLstar;
// 	VpData->HostStackLayout.OriginalMsrLstar = NULL;
}

VOID SvHandleCpuidForL2ToL1(
	_Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
	_Inout_ PGUEST_CONTEXT GuestContext
)
{
	int registers[4];   // EAX, EBX, ECX, and EDX
	int leaf, subLeaf;
	SEGMENT_ATTRIBUTE attribute;
	UNREFERENCED_PARAMETER(attribute);

	//
	// Execute CPUID as requested.
	//
	leaf = static_cast<int>(GuestContext->VpRegs->Rax);
	subLeaf = static_cast<int>(GuestContext->VpRegs->Rcx);
	__cpuidex(registers, leaf, subLeaf);

	switch (leaf)
	{
	//case 0x40000000:
    case 123456:
		//
		// Return a maximum supported hypervisor CPUID leaf range and a vendor
		// ID signature as required by the spec.
		//
		registers[0] = CPUID_HV_MAX;
		registers[1] = 'NmvS';  // "SvmNest     "
		registers[2] = 'Jtse';
		registers[3] = '    ';
		break;

	default:
		break;
	}

    if (VMX_MODE::RootMode == VmxGetVmxMode(VmmpGetVcpuVmx(VpData)))
    {
		//
		// Update guest's GPRs with results.
		//
		GuestContext->VpRegs->Rax = registers[0];
		GuestContext->VpRegs->Rbx = registers[1];
		GuestContext->VpRegs->Rcx = registers[2];
		GuestContext->VpRegs->Rdx = registers[3];
        PVMCB pVmcbGuest02va = (PVMCB)UtilVaFromPa(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_02_pa);
        pVmcbGuest02va->StateSaveArea.Rip = pVmcbGuest02va->ControlArea.NRip;
        return; // return L1
    }

//     SaveGuestVmcb12FromGuestVmcb02(VpData, GuestContext);
//     LEAVE_GUEST_MODE(VmmpGetVcpuVmx(VpData));     // retrun L1 host
    LeaveGuest(VpData, GuestContext);
}

VOID
SvHandleMsrAccessNest(
	_Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
	_Inout_ PGUEST_CONTEXT GuestContext
)
{
    PVMCB pVmcbGuest02va = GetCurrentVmcbGuest02(VpData);
	if (VMX_MODE::RootMode == VmxGetVmxMode(VmmpGetVcpuVmx(VpData)))
	{
        HandleMsrReadAndWrite(VpData, GuestContext);
		pVmcbGuest02va->StateSaveArea.Rip = pVmcbGuest02va->ControlArea.NRip;
		return; // return L1
	}

    UINT32 InterceptMisc1 = GetCurrentVmcbGuest12(VpData)->ControlArea.InterceptMisc1;
    if ((InterceptMisc1 & SVM_INTERCEPT_MISC1_MSR_PROT) && CheckVmcb12MsrBit(VpData, GuestContext))
    {
//         SaveGuestVmcb12FromGuestVmcb02(VpData, GuestContext);
//         LEAVE_GUEST_MODE(VmmpGetVcpuVmx(VpData));     // retrun L1 host
        LeaveGuest(VpData, GuestContext);
        return;
    }
    else
    {
        HandleMsrReadAndWrite(VpData, GuestContext);
        pVmcbGuest02va->StateSaveArea.Rip = pVmcbGuest02va->ControlArea.NRip;
        return;
    }
}

VOID SvHandleBreakPointExceptionNest(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
)
{
    PVMCB pVmcbGuest02va = GetCurrentVmcbGuest02(VpData);

    if (VMX_MODE::RootMode == VmxGetVmxMode(VmmpGetVcpuVmx(VpData)))
    {
        SvInjectBPExceptionVmcb02(VpData);
        pVmcbGuest02va->StateSaveArea.Rip = pVmcbGuest02va->ControlArea.NRip;
        return;
    }

    PVMCB pVmcbGuest12va = GetCurrentVmcbGuest12(VpData);
    UINT32 InterceptException = pVmcbGuest12va->ControlArea.InterceptException;
    if (InterceptException &  (1UL << 3)) // need retrun L1 host
    {
//         SaveGuestVmcb12FromGuestVmcb02(VpData, GuestContext);
//         LEAVE_GUEST_MODE(VmmpGetVcpuVmx(VpData));     // retrun L1 host
        LeaveGuest(VpData, GuestContext);
        return;
    }
    else // return L2
    {
        SvInjectBPExceptionVmcb02(VpData);
        pVmcbGuest02va->StateSaveArea.Rip = pVmcbGuest02va->ControlArea.NRip; 
        return; 
    }
}