// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Copyright (c) 2016-2017, KelvinChan. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares interfaces to VMM functions.

#ifndef HYPERPLATFORM_VMM_H_
#define HYPERPLATFORM_VMM_H_

#include <fltKernel.h>
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//
typedef enum {
	ProtectedMode = 0,
	VmxMode = 1,
	Virtual8086 = 2,
	RealMode = 3,
	SmmMode = 4,
}CPU_MODE;

typedef enum {
	RootMode = 0,
	GuestMode,
}VMX_MODE;

////////////////////////////////////////////////////////////////////////////////
//
// types
//

/// Represents VMM related data shared across all processors
struct SharedProcessorData {
	volatile long reference_count;  //!< Number of processors sharing this data
	void* msr_bitmap;               //!< Bitmap to activate MSR I/O VM-exit
	void* io_bitmap_a;              //!< Bitmap to activate IO VM-exit (~ 0x7FFF)
	void* io_bitmap_b;              //!< Bitmap to activate IO VM-exit (~ 0xffff)
};

typedef struct _VCPU_VMX
{
    ULONG64  vmcb_guest_02_pa;
    ULONG64  vmcb_host_02_pa;
    ULONG64  hostStateAreaPa_02_pa;
    ULONG64  vmcb_guest_12_pa;
    ULONG64  vmcb_host_12_pa;
    ULONG64  hostStateAreaPa_12_pa;
	ULONG     InitialCpuNumber;				///VCPU number
	BOOLEAN   blockINITsignal;			///NOT USED
	BOOLEAN   blockAndDisableA20M;		///NOT USED
	VMX_MODE  inRoot;					///is it in root mode
	USHORT	  kVirtualProcessorId;		///NOT USED 
	ULONG_PTR   guest_irql;
	ULONG_PTR   guest_cr8;    
}VCPUVMX, *PVCPUVMX;

/// Represents VMM related data associated with each processor
struct ProcessorNestData {
	SharedProcessorData* shared_data;         //!< Shared data
	LARGE_INTEGER Ia32FeatureMsr;			  //!< For Msr Read / Write
	LARGE_INTEGER VmxBasicMsr;				  //!< For Msr Read / Write
	LARGE_INTEGER VmxEptMsr;				  //!< For Msr Read / Write   
	LARGE_INTEGER HostKernelGsBase;			  ///guest_gs_kernel_base 
	LARGE_INTEGER GuestKernelGsBase;		  ///guest_gs_kernel_base  
    LARGE_INTEGER GuestSvmHsave;
	VCPUVMX*		vcpu_vmx;				  //!< For nested vmx context
	CPU_MODE		CpuMode;				  //!< For CPU Mode 
    LARGE_INTEGER        GuestMsrEFER;          // for amd nest 

};



////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

#endif  // HYPERPLATFORM_VMM_H_
