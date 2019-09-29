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
        
        // Load VMCS02 into physical cpu , And perform some check on VMCS12



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