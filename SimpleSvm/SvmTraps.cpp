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

VOID SvHandleVmload(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext)
{
    if (VpData->GuestVmcb.StateSaveArea.Cpl > 0)
    {
        SvInjectGeneralProtectionException(VpData);
        return;
    }

    PVMCB pVmcbGuestL2Hostva = (PVMCB)UtilVaFromPa(GuestContext->VpRegs->Rax);
    PVMCB pVmcbGuest01va = &VpData->GuestVmcb;

    // Load from a VMCB at system-physical address rAX: 
    // FS, GS, TR, LDTR (including all hidden state) 
    // KernelGsBase
    // STAR, LSTAR, CSTAR, SFMASK 
    // SYSENTER_CS, SYSENTER_ESP, SYSENTER_EIP 

    pVmcbGuest01va->StateSaveArea.FsBase = pVmcbGuestL2Hostva->StateSaveArea.FsBase;
    pVmcbGuest01va->StateSaveArea.FsLimit = pVmcbGuestL2Hostva->StateSaveArea.FsLimit;
    pVmcbGuest01va->StateSaveArea.FsSelector = pVmcbGuestL2Hostva->StateSaveArea.FsSelector;
    pVmcbGuest01va->StateSaveArea.FsAttrib = pVmcbGuestL2Hostva->StateSaveArea.FsAttrib;

    pVmcbGuest01va->StateSaveArea.GsBase = pVmcbGuestL2Hostva->StateSaveArea.GsBase;
    pVmcbGuest01va->StateSaveArea.GsLimit = pVmcbGuestL2Hostva->StateSaveArea.GsLimit;
    pVmcbGuest01va->StateSaveArea.GsSelector = pVmcbGuestL2Hostva->StateSaveArea.GsSelector;
    pVmcbGuest01va->StateSaveArea.GsAttrib = pVmcbGuestL2Hostva->StateSaveArea.GsAttrib;

    pVmcbGuest01va->StateSaveArea.TrBase = pVmcbGuestL2Hostva->StateSaveArea.TrBase;
    pVmcbGuest01va->StateSaveArea.TrLimit = pVmcbGuestL2Hostva->StateSaveArea.TrLimit;
    pVmcbGuest01va->StateSaveArea.TrSelector = pVmcbGuestL2Hostva->StateSaveArea.TrSelector;
    pVmcbGuest01va->StateSaveArea.TrAttrib = pVmcbGuestL2Hostva->StateSaveArea.TrAttrib;

    pVmcbGuest01va->StateSaveArea.LdtrBase = pVmcbGuestL2Hostva->StateSaveArea.LdtrBase;
    pVmcbGuest01va->StateSaveArea.LdtrLimit = pVmcbGuestL2Hostva->StateSaveArea.LdtrLimit;
    pVmcbGuest01va->StateSaveArea.LdtrSelector = pVmcbGuestL2Hostva->StateSaveArea.LdtrSelector;
    pVmcbGuest01va->StateSaveArea.LdtrAttrib = pVmcbGuestL2Hostva->StateSaveArea.LdtrAttrib;

    pVmcbGuest01va->StateSaveArea.KernelGsBase = pVmcbGuestL2Hostva->StateSaveArea.KernelGsBase;

    pVmcbGuest01va->StateSaveArea.Star = pVmcbGuestL2Hostva->StateSaveArea.Star;

    pVmcbGuest01va->StateSaveArea.LStar = pVmcbGuestL2Hostva->StateSaveArea.LStar;

    pVmcbGuest01va->StateSaveArea.CStar = pVmcbGuestL2Hostva->StateSaveArea.CStar;

    pVmcbGuest01va->StateSaveArea.SfMask = pVmcbGuestL2Hostva->StateSaveArea.SfMask;

    pVmcbGuest01va->StateSaveArea.SysenterCs = pVmcbGuestL2Hostva->StateSaveArea.SysenterCs;

    pVmcbGuest01va->StateSaveArea.SysenterEsp = pVmcbGuestL2Hostva->StateSaveArea.SysenterEsp;

    pVmcbGuest01va->StateSaveArea.SysenterEip = pVmcbGuestL2Hostva->StateSaveArea.SysenterEip;

    VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip; // need npt
}

VOID SvHandleVmsave(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext)
{
    if (VpData->GuestVmcb.StateSaveArea.Cpl > 0)
    {
        SvInjectGeneralProtectionException(VpData);
        return;
    }

    PVMCB pVmcbGuest12va = (PVMCB)UtilVaFromPa(GuestContext->VpRegs->Rax);
    PVMCB pVmcbGuest01va = &VpData->GuestVmcb;

    // Store to a VMCB at system-physical address rAX:
    // FS, GS, TR, LDTR (including all hidden state) 
    // KernelGsBase
    // STAR, LSTAR, CSTAR, SFMASK
    // SYSENTER_CS, SYSENTER_ESP, SYSENTER_EIP 

    pVmcbGuest12va->StateSaveArea.FsBase = pVmcbGuest01va->StateSaveArea.FsBase;
    pVmcbGuest12va->StateSaveArea.FsLimit = pVmcbGuest01va->StateSaveArea.FsLimit;
    pVmcbGuest12va->StateSaveArea.FsSelector = pVmcbGuest01va->StateSaveArea.FsSelector;
    pVmcbGuest12va->StateSaveArea.FsAttrib = pVmcbGuest01va->StateSaveArea.FsAttrib;

    pVmcbGuest12va->StateSaveArea.GsBase = pVmcbGuest01va->StateSaveArea.GsBase;
    pVmcbGuest12va->StateSaveArea.GsLimit = pVmcbGuest01va->StateSaveArea.GsLimit;
    pVmcbGuest12va->StateSaveArea.GsSelector = pVmcbGuest01va->StateSaveArea.GsSelector;
    pVmcbGuest12va->StateSaveArea.GsAttrib = pVmcbGuest01va->StateSaveArea.GsAttrib;

    pVmcbGuest12va->StateSaveArea.TrBase = pVmcbGuest01va->StateSaveArea.TrBase;
    pVmcbGuest12va->StateSaveArea.TrLimit = pVmcbGuest01va->StateSaveArea.TrLimit;
    pVmcbGuest12va->StateSaveArea.TrSelector = pVmcbGuest01va->StateSaveArea.TrSelector;
    pVmcbGuest12va->StateSaveArea.TrAttrib = pVmcbGuest01va->StateSaveArea.TrAttrib;

    pVmcbGuest12va->StateSaveArea.LdtrBase = pVmcbGuest01va->StateSaveArea.LdtrBase;
    pVmcbGuest12va->StateSaveArea.LdtrLimit = pVmcbGuest01va->StateSaveArea.LdtrLimit;
    pVmcbGuest12va->StateSaveArea.LdtrSelector = pVmcbGuest01va->StateSaveArea.LdtrSelector;
    pVmcbGuest12va->StateSaveArea.LdtrAttrib = pVmcbGuest01va->StateSaveArea.LdtrAttrib;

    pVmcbGuest12va->StateSaveArea.KernelGsBase = pVmcbGuest01va->StateSaveArea.KernelGsBase;

    // star
    pVmcbGuest12va->StateSaveArea.Star = pVmcbGuest01va->StateSaveArea.Star;

    // lstar
    pVmcbGuest12va->StateSaveArea.LStar = pVmcbGuest01va->StateSaveArea.LStar;

    // cstar 
    pVmcbGuest12va->StateSaveArea.CStar = pVmcbGuest01va->StateSaveArea.CStar;

    // sfmask
    pVmcbGuest12va->StateSaveArea.SfMask = pVmcbGuest01va->StateSaveArea.SfMask;

    // sysentercs
    pVmcbGuest12va->StateSaveArea.SysenterCs = pVmcbGuest01va->StateSaveArea.SysenterCs;

    // sysenteresp
    pVmcbGuest12va->StateSaveArea.SysenterEsp = pVmcbGuest01va->StateSaveArea.SysenterEsp;

    // sysentereip
    pVmcbGuest12va->StateSaveArea.SysenterEip = pVmcbGuest01va->StateSaveArea.SysenterEip;

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

    //VMRUN is available only at CPL-0. A #GP exception is raised if the CPL is greater than 0. 
    if (VpData->GuestVmcb.StateSaveArea.Cpl > 0)
    {
        SvInjectGeneralProtectionException(VpData);
        return;
    }

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
		//PVMCB pVmcbGuest02va = (PVMCB)UtilVaFromPa(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_02_pa);
		PVMCB pVmcbGuest12va = (PVMCB)UtilVaFromPa(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_12_pa);
		PVMCB pVmcbGuest01va = &VpData->GuestVmcb;

        __svm_vmsave(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_02_pa);
		// 01 and 12 -> 02  ControlField
// 		pVmcbGuest02va->ControlArea.InterceptMisc1 = pVmcbGuest01va->ControlArea.InterceptMisc1 | pVmcbGuest12va->ControlArea.InterceptMisc1;
// 		pVmcbGuest02va->ControlArea.InterceptMisc2 = pVmcbGuest01va->ControlArea.InterceptMisc2 | pVmcbGuest12va->ControlArea.InterceptMisc2;
// 		pVmcbGuest02va->ControlArea.MsrpmBasePa = pVmcbGuest01va->ControlArea.MsrpmBasePa; // only use 01 msr int
//         pVmcbGuest02va->ControlArea.InterceptException = pVmcbGuest01va->ControlArea.InterceptException; // only use 01 int
// 		pVmcbGuest02va->ControlArea.GuestAsid = pVmcbGuest01va->ControlArea.GuestAsid;
// 		pVmcbGuest02va->ControlArea.NpEnable = pVmcbGuest01va->ControlArea.NpEnable;
// 		pVmcbGuest02va->ControlArea.NCr3 = pVmcbGuest01va->ControlArea.NCr3;
// 		pVmcbGuest02va->ControlArea.LbrVirtualizationEnable = pVmcbGuest01va->ControlArea.LbrVirtualizationEnable;
// 		pVmcbGuest02va->ControlArea.VIntr = pVmcbGuest01va->ControlArea.VIntr;
// 		
		// 12 -> 02 statesavearea and guestfield
// 		pVmcbGuest02va->StateSaveArea.GdtrBase = pVmcbGuest12va->StateSaveArea.GdtrBase;
// 		pVmcbGuest02va->StateSaveArea.GdtrLimit = pVmcbGuest12va->StateSaveArea.GdtrLimit;
// 		pVmcbGuest02va->StateSaveArea.IdtrBase = pVmcbGuest12va->StateSaveArea.IdtrBase;
// 		pVmcbGuest02va->StateSaveArea.IdtrLimit = pVmcbGuest12va->StateSaveArea.IdtrLimit;
// 
// 		pVmcbGuest02va->StateSaveArea.CsLimit = pVmcbGuest12va->StateSaveArea.CsLimit;
// 		pVmcbGuest02va->StateSaveArea.DsLimit = pVmcbGuest12va->StateSaveArea.DsLimit;
// 		pVmcbGuest02va->StateSaveArea.EsLimit = pVmcbGuest12va->StateSaveArea.EsLimit;
// 		pVmcbGuest02va->StateSaveArea.SsLimit = pVmcbGuest12va->StateSaveArea.SsLimit;
// 		pVmcbGuest02va->StateSaveArea.CsSelector = pVmcbGuest12va->StateSaveArea.CsSelector;
// 		pVmcbGuest02va->StateSaveArea.DsSelector = pVmcbGuest12va->StateSaveArea.DsSelector;
// 		pVmcbGuest02va->StateSaveArea.EsSelector = pVmcbGuest12va->StateSaveArea.EsSelector;
// 		pVmcbGuest02va->StateSaveArea.SsSelector = pVmcbGuest12va->StateSaveArea.SsSelector;
// 		pVmcbGuest02va->StateSaveArea.CsAttrib = pVmcbGuest12va->StateSaveArea.CsAttrib;
// 		pVmcbGuest02va->StateSaveArea.DsAttrib = pVmcbGuest12va->StateSaveArea.DsAttrib;
// 		pVmcbGuest02va->StateSaveArea.EsAttrib = pVmcbGuest12va->StateSaveArea.EsAttrib;
// 		pVmcbGuest02va->StateSaveArea.SsAttrib = pVmcbGuest12va->StateSaveArea.SsAttrib;
// 
 		SV_DEBUG_BREAK();
// 		pVmcbGuest02va->StateSaveArea.Efer = __readmsr(IA32_MSR_EFER);
// 		pVmcbGuest02va->StateSaveArea.Cr0 = __readcr0();
// 		pVmcbGuest02va->StateSaveArea.Cr2 = __readcr2();
// 		pVmcbGuest02va->StateSaveArea.Cr3 = __readcr3();
// 		pVmcbGuest02va->StateSaveArea.Cr4 = __readcr4();
// 		pVmcbGuest02va->StateSaveArea.Rflags = pVmcbGuest12va->StateSaveArea.Rflags;
// 		pVmcbGuest02va->StateSaveArea.Rsp = pVmcbGuest12va->StateSaveArea.Rsp;
// 		pVmcbGuest02va->StateSaveArea.Rip = pVmcbGuest12va->StateSaveArea.Rip;
// 		pVmcbGuest02va->StateSaveArea.GPat = __readmsr(IA32_MSR_PAT);

        SimulateVmrun02SaveHostStateShadow(pVmcbGuest01va, VpData, GuestContext);
        SimulateVmrun02LoadControlInfoToVmcbGuest02(pVmcbGuest12va, VpData, GuestContext);
        SimulateVmrun02LoadGuestStateFromVmcbGuest12(VpData, GuestContext);
		SaveHostKernelGsBase(VpData);
		__writemsr(SVM_MSR_VM_HSAVE_PA, VpData->HostStackLayout.pProcessNestData->GuestSvmHsave12.QuadPart); // prevent to destroy the 01 HostStateArea
		//__svm_vmrun(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_02_pa);
		VpData->HostStackLayout.pProcessNestData->vcpu_vmx->pVpdata = VpData;
        __svm_vmsave(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_host_02_pa);

		//SvLaunchVm(&(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_02_pa));
        GuestContext->ExitVm = EXIT_REASON::EXIT_NEST_SET_VMCB02;
        GuestContext->VpRegs->Rbx = (UINT64)&(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_02_pa);

        SetVGIF(VpData);
        ENTER_GUEST_MODE(VpData->HostStackLayout.pProcessNestData->vcpu_vmx);
        SvDebugPrint("[ENTER_GUEST_MODE]");
        DumpVmcb(VpData);
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

VOID SvHandleVmloadNest(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
)
{
    if (GetCurrentVmcbGuest02(VpData)->StateSaveArea.Cpl > 0)
    {
        SvInjectGeneralProtectionExceptionVmcb02(VpData);
        return;
    }
    if (VMX_MODE::RootMode == VmxGetVmxMode(VmmpGetVcpuVmx(VpData)))
    {
        PVMCB pVmcbGuest02va = GetCurrentVmcbGuest02(VpData);
        PVMCB pVmcbL2Hostva = (PVMCB)UtilVaFromPa(GuestContext->VpRegs->Rax);

        // Load from a VMCB at system-physical address rAX: 
        // FS, GS, TR, LDTR (including all hidden state) 
        // KernelGsBase
        // STAR, LSTAR, CSTAR, SFMASK 
        // SYSENTER_CS, SYSENTER_ESP, SYSENTER_EIP 

        pVmcbGuest02va->StateSaveArea.FsBase = pVmcbL2Hostva->StateSaveArea.FsBase;
        pVmcbGuest02va->StateSaveArea.FsLimit = pVmcbL2Hostva->StateSaveArea.FsLimit;
        pVmcbGuest02va->StateSaveArea.FsSelector = pVmcbL2Hostva->StateSaveArea.FsSelector;
        pVmcbGuest02va->StateSaveArea.FsAttrib = pVmcbL2Hostva->StateSaveArea.FsAttrib;

        pVmcbGuest02va->StateSaveArea.GsBase = pVmcbL2Hostva->StateSaveArea.GsBase;
        pVmcbGuest02va->StateSaveArea.GsLimit = pVmcbL2Hostva->StateSaveArea.GsLimit;
        pVmcbGuest02va->StateSaveArea.GsSelector = pVmcbL2Hostva->StateSaveArea.GsSelector;
        pVmcbGuest02va->StateSaveArea.GsAttrib = pVmcbL2Hostva->StateSaveArea.GsAttrib;

        pVmcbGuest02va->StateSaveArea.TrBase = pVmcbL2Hostva->StateSaveArea.TrBase;
        pVmcbGuest02va->StateSaveArea.TrLimit = pVmcbL2Hostva->StateSaveArea.TrLimit;
        pVmcbGuest02va->StateSaveArea.TrSelector = pVmcbL2Hostva->StateSaveArea.TrSelector;
        pVmcbGuest02va->StateSaveArea.TrAttrib = pVmcbL2Hostva->StateSaveArea.TrAttrib;

        pVmcbGuest02va->StateSaveArea.LdtrBase = pVmcbL2Hostva->StateSaveArea.LdtrBase;
        pVmcbGuest02va->StateSaveArea.LdtrLimit = pVmcbL2Hostva->StateSaveArea.LdtrLimit;
        pVmcbGuest02va->StateSaveArea.LdtrSelector = pVmcbL2Hostva->StateSaveArea.LdtrSelector;
        pVmcbGuest02va->StateSaveArea.LdtrAttrib = pVmcbL2Hostva->StateSaveArea.LdtrAttrib;

        pVmcbGuest02va->StateSaveArea.KernelGsBase = pVmcbL2Hostva->StateSaveArea.KernelGsBase;

        pVmcbGuest02va->StateSaveArea.Star = pVmcbL2Hostva->StateSaveArea.Star;

        pVmcbGuest02va->StateSaveArea.LStar = pVmcbL2Hostva->StateSaveArea.LStar;

        pVmcbGuest02va->StateSaveArea.CStar = pVmcbL2Hostva->StateSaveArea.CStar;

        pVmcbGuest02va->StateSaveArea.SfMask = pVmcbL2Hostva->StateSaveArea.SfMask;

        pVmcbGuest02va->StateSaveArea.SysenterCs = pVmcbL2Hostva->StateSaveArea.SysenterCs;

        pVmcbGuest02va->StateSaveArea.SysenterEsp = pVmcbL2Hostva->StateSaveArea.SysenterEsp;

        pVmcbGuest02va->StateSaveArea.SysenterEip = pVmcbL2Hostva->StateSaveArea.SysenterEip;

        pVmcbGuest02va->StateSaveArea.Rip = pVmcbGuest02va->ControlArea.NRip;
        return; // return L1
    }
    else
    {
        SvInjectGeneralProtectionExceptionVmcb02(VpData);
        // something error
    }
}

VOID SvHandleVmsaveNest(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
)
{
    if (GetCurrentVmcbGuest02(VpData)->StateSaveArea.Cpl > 0)
    {
        SvInjectGeneralProtectionExceptionVmcb02(VpData);
        return;
    }

    if (VMX_MODE::RootMode == VmxGetVmxMode(VmmpGetVcpuVmx(VpData)))
    {
        PVMCB pVmcbGuest02va = GetCurrentVmcbGuest02(VpData);
        PVMCB pVmcbGuest12va = (PVMCB)UtilVaFromPa(GuestContext->VpRegs->Rax);

        // Store to a VMCB at system-physical address rAX:
        // FS, GS, TR, LDTR (including all hidden state) 
        // KernelGsBase
        // STAR, LSTAR, CSTAR, SFMASK
        // SYSENTER_CS, SYSENTER_ESP, SYSENTER_EIP 

        pVmcbGuest12va->StateSaveArea.FsBase = pVmcbGuest02va->StateSaveArea.FsBase;
        pVmcbGuest12va->StateSaveArea.FsLimit = pVmcbGuest02va->StateSaveArea.FsLimit;
        pVmcbGuest12va->StateSaveArea.FsSelector = pVmcbGuest02va->StateSaveArea.FsSelector;
        pVmcbGuest12va->StateSaveArea.FsAttrib = pVmcbGuest02va->StateSaveArea.FsAttrib;

        if (3 == VmmpGetVcpuVmx(VpData)->uintL2GuestCpl)
        {
            pVmcbGuest12va->StateSaveArea.KernelGsBase = VmmpGetVcpuVmx(VpData)->uint64L2KernelGsBase;
            pVmcbGuest12va->StateSaveArea.GsBase = VmmpGetVcpuVmx(VpData)->uint64L2GsBase;
            pVmcbGuest12va->StateSaveArea.GsLimit = VmmpGetVcpuVmx(VpData)->uintL2GsLimit;
            pVmcbGuest12va->StateSaveArea.GsSelector = VmmpGetVcpuVmx(VpData)->uintL2GsSelector;
            pVmcbGuest12va->StateSaveArea.GsAttrib = VmmpGetVcpuVmx(VpData)->uintL2GsAttrib;
        }
        else
        {
            pVmcbGuest12va->StateSaveArea.GsBase = pVmcbGuest02va->StateSaveArea.GsBase;
            pVmcbGuest12va->StateSaveArea.GsLimit = pVmcbGuest02va->StateSaveArea.GsLimit;
            pVmcbGuest12va->StateSaveArea.GsSelector = pVmcbGuest02va->StateSaveArea.GsSelector;
            pVmcbGuest12va->StateSaveArea.GsAttrib = pVmcbGuest02va->StateSaveArea.GsAttrib;

            pVmcbGuest12va->StateSaveArea.KernelGsBase = pVmcbGuest02va->StateSaveArea.KernelGsBase;
        }
        
        pVmcbGuest12va->StateSaveArea.TrBase = pVmcbGuest02va->StateSaveArea.TrBase;
        pVmcbGuest12va->StateSaveArea.TrLimit = pVmcbGuest02va->StateSaveArea.TrLimit;
        pVmcbGuest12va->StateSaveArea.TrSelector = pVmcbGuest02va->StateSaveArea.TrSelector;
        pVmcbGuest12va->StateSaveArea.TrAttrib = pVmcbGuest02va->StateSaveArea.TrAttrib;

        pVmcbGuest12va->StateSaveArea.LdtrBase = pVmcbGuest02va->StateSaveArea.LdtrBase;
        pVmcbGuest12va->StateSaveArea.LdtrLimit = pVmcbGuest02va->StateSaveArea.LdtrLimit;
        pVmcbGuest12va->StateSaveArea.LdtrSelector = pVmcbGuest02va->StateSaveArea.LdtrSelector;
        pVmcbGuest12va->StateSaveArea.LdtrAttrib = pVmcbGuest02va->StateSaveArea.LdtrAttrib;

        // star
        pVmcbGuest12va->StateSaveArea.Star = pVmcbGuest02va->StateSaveArea.Star;

        // lstar
        pVmcbGuest12va->StateSaveArea.LStar = pVmcbGuest02va->StateSaveArea.LStar;

        // cstar 
        pVmcbGuest12va->StateSaveArea.CStar = pVmcbGuest02va->StateSaveArea.CStar;

        // sfmask
        pVmcbGuest12va->StateSaveArea.SfMask = pVmcbGuest02va->StateSaveArea.SfMask;

        // sysentercs
        pVmcbGuest12va->StateSaveArea.SysenterCs = pVmcbGuest02va->StateSaveArea.SysenterCs;

        // sysenteresp
        pVmcbGuest12va->StateSaveArea.SysenterEsp = pVmcbGuest02va->StateSaveArea.SysenterEsp;

        // sysentereip
        pVmcbGuest12va->StateSaveArea.SysenterEip = pVmcbGuest02va->StateSaveArea.SysenterEip;

        pVmcbGuest02va->StateSaveArea.Rip = pVmcbGuest02va->ControlArea.NRip;
        return; // return L1
    }
    else
    {
        SvInjectGeneralProtectionExceptionVmcb02(VpData);
        // something error
    }

}

VOID
SvHandleVmrunExForL1ToL2(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
)
{
    UNREFERENCED_PARAMETER(GuestContext);
    //VMRUN is available only at CPL-0. A #GP exception is raised if the CPL is greater than 0. 
    if (GetCurrentVmcbGuest02(VpData)->StateSaveArea.Cpl > 0)
    {
        SvInjectGeneralProtectionExceptionVmcb02(VpData);
        return;
    }

    if ( VMX_MODE::RootMode == VmxGetVmxMode(VmmpGetVcpuVmx(VpData)))
    {
         PVMCB pVmcbGuest02va = (PVMCB)UtilVaFromPa(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_02_pa);
         PVMCB pVmcbGuest12va = (PVMCB)UtilVaFromPa(VpData->HostStackLayout.pProcessNestData->vcpu_vmx->vmcb_guest_12_pa);
//         pVmcbGuest02va->StateSaveArea.Rflags = pVmcbGuest12va->StateSaveArea.Rflags;
//         pVmcbGuest02va->StateSaveArea.Rsp = pVmcbGuest12va->StateSaveArea.Rsp;
//         pVmcbGuest02va->StateSaveArea.Rip = pVmcbGuest12va->StateSaveArea.Rip;
//         pVmcbGuest02va->StateSaveArea.LStar = pVmcbGuest12va->StateSaveArea.LStar;
// 		pVmcbGuest02va->StateSaveArea.Rax = pVmcbGuest12va->StateSaveArea.Rax;
        SimulateVmrun02SaveHostStateShadow(pVmcbGuest02va, VpData, GuestContext);
        SimulateVmrun02LoadControlInfoToVmcbGuest02(pVmcbGuest12va, VpData, GuestContext);
        SimulateVmrun02LoadGuestStateFromVmcbGuest12(VpData, GuestContext);
        GuestContext->VpRegs->Rax = pVmcbGuest12va->StateSaveArea.Rax;
        ENTER_GUEST_MODE(VpData->HostStackLayout.pProcessNestData->vcpu_vmx);
        // Sets the global interrupt flag (GIF) to 1. 
        SetVGIF(VpData);
        SvDebugPrint("[ENTER_GUEST_MODE]");
        DumpVmcb(VpData);
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
    if ((InterceptMisc1 & SVM_INTERCEPT_MISC1_MSR_PROT))
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