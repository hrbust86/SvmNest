SvmNest
==========

Introduction
-------------
SvmNest is base on SimpleSvm .

SvmNest is a minimalistic frame hypervisor for Windows on AMD processors.
It aims to provide small and explanational code to virtualize and nest Secure Virtual Machine (SVM amd-v),
the AMD version of Intel VT-x, with Nested Page Tables (NPT) from a windows driver.

This frame only simulate four event : (VMEXIT_CPUID, VMEXIT_MSR, VMEXIT_VMRUN, VMEXIT_VMMCALL).
This project could simulate SimpleSvmHookMsr in my git. you can learn SvmNest by SimpleSvmHookMsr.
if you want more event to carry, you should code just like my "SvHandleMsrAccessNest".
but if you want more advance feature, you should fix "SaveGuestVmcb12FromGuestVmcb02" and "SvHandleVmrunExForL1ToL2".

Any questions could send a email to "hrbust86@126.com"

Supported Platforms
----------------------
- Windows 10 x64 and Windows 7 x64
- AMD Processors with SVM and NPT support


Resources
-------------------
- AMD64 Architecture Programmer’s Manual Volume 2 and 3
  - http://developer.amd.com/resources/developer-guides-manuals/
 
- SimpleVisor
  - http://ionescu007.github.io/SimpleVisor/
