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
	//VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip;
	VpData->GuestVmcb.StateSaveArea.Rip += 2;
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

        HYPERPLATFORM_LOG_DEBUG("VMXON: Run Successfully with  Total Vitrualized Core: %x  Current Cpu: %x in Cpu Group : %x  Number: %x \r\n",
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

        HYPERPLATFORM_LOG_DEBUG_SAFE("[VMPTRLD] Run Successfully \r\n");
        HYPERPLATFORM_LOG_DEBUG_SAFE("[VMPTRLD] Current Cpu: %x in Cpu Group : %x  Number: %x \r\n", nested_vmx->InitialCpuNumber, number.Group, number.Number);

        // emulate write and read 
        //  SvLaunchVm(&vpData->HostStackLayout.GuestVmcbPa);
        VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_12_pa = GuestContext->VpRegs->Rax;
		//VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_host_12_pa = VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_02_pa;
        VpData->HostStackLayout.pProcessNestData->vcpu_vmx->hostStateAreaPa_12_pa = VpData->HostStackLayout.pProcessNestData->GuestSvmHsave12.QuadPart;

        /*
        Emulating VMEntry behavior from L1 to L2.

        After L1 handles any VM Exit and should be executes VMRESUME for back L2
        But this time trapped by VMCS01 and We can't get any VM-Exit information
        from it. So we need to read from VMCS12 and return from here immediately.
        We saved the vmcs02 GuestRip into VMCS12 our VMExit Handler because when
        L1 was executing VMRESUME(We injected VMExit to it), and it is running on
        VMCS01, we can't and shouldn't change it.
        */

		// 01 -> 02
		// PrepareHostAndControlField
		__svm_vmsave(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_host_02_pa);
		PVMCB pVmcbGuest02va = (PVMCB)UtilVaFromPa(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_02_pa);
		PVMCB pVmcbGuest12va = (PVMCB)UtilVaFromPa(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_12_pa);
		PVMCB pVmcbGuest01va = &VpData->GuestVmcb;

		// 01 and 12 -> 02  ControlField
		pVmcbGuest02va->ControlArea.InterceptMisc1 = pVmcbGuest01va->ControlArea.InterceptMisc1 | pVmcbGuest12va->ControlArea.InterceptMisc1;
		pVmcbGuest02va->ControlArea.InterceptMisc2 = pVmcbGuest01va->ControlArea.InterceptMisc2 | pVmcbGuest12va->ControlArea.InterceptMisc2;
		pVmcbGuest02va->ControlArea.MsrpmBasePa = pVmcbGuest01va->ControlArea.MsrpmBasePa; // only use 01 msr int
		pVmcbGuest02va->ControlArea.GuestAsid = pVmcbGuest01va->ControlArea.GuestAsid;
		pVmcbGuest02va->ControlArea.NpEnable = pVmcbGuest01va->ControlArea.NpEnable;
		pVmcbGuest02va->ControlArea.NCr3 = pVmcbGuest01va->ControlArea.NCr3;
		pVmcbGuest02va->ControlArea.LbrVirtualizationEnable = pVmcbGuest01va->ControlArea.LbrVirtualizationEnable;
		pVmcbGuest02va->ControlArea.VIntr = pVmcbGuest01va->ControlArea.VIntr;
		
		// 12 -> 02 statesavearea
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

    }
	else // 嵌套环境已经建立
    {
    
    }

	VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip; // need npt
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