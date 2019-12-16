# Virtualization Based Hardening


## Description (POC only)
Virtualization Base Hardening (VBH) utilizes Intel Virtualization Technology to provide an infrastructure for other parties to build security policies (such as introspection engine) on top of it in order to protect hardware (Intel platform only), kernel and native container/user space apps.  It is implemented as an out-of tree Linux module and supports Linux version 4.4 or above.  It has 2 components: 
1. A slim hypervisor, when installed, turns the host into guest
2. APIs to query and control the hypervisor.  The APIs supports the following functionalities:
    * Query and update general guest info
    * vCPU management
    * Event related: to register event callbacks and to report event
    * Memory/EPT related
    * CR and MSR virtualization related
    * Emulation/Single Step related

For a full list of supported functions, please refer to hypervisor_introspection.h.


## File Structure
```
vbh
+-- README.md
+-- sources
|   +-- cpu_switch_debug.c              /* Debug only */
|   +-- cpu_switch_debug.h              /* Header file for debug */
|   +-- guest_info.c                    /* Query and update guest info */
|   +-- hypervisor_introspection.c      /* API functions implementation */
|   +-- hypervisor_introspection.h      /* API function definition */
|   +-- kernelhardending.c              /* MSR and CR virtualization */
|   +-- Makefile                        /* Make file */
|   +-- offsets.h                       /* Register offset */
|   +-- ptable.c                        /* EPT related */
|   +-- vbh_events.c                    /* Event handling */
|   +-- vbh_rt.c                        /* slim hypervisor runtime: mostly for vmexit and vmentry */
|   +-- vbh_setup.c                     /* slim hypervisor initialization */
|   +-- vmexit.S                        /* Assembly for vmexit */
|   +-- vmx_common.h                    /* Shared header file */
+-- tests
|   +-- kernel_hardening_tests          /* tests related to CR and MSR virtualization */
    |   +-- kernel_hardening_test_module_main.c
    |   +-- Makefile
|   +-- query_guest_info_tests          /* tests related to query guest inof */
    |   +-- query_guest_info_tests_module.c
    |   +-- Makefile
|   +-- set_guest_info_tests            /* tests related to set guest info */
    |   +-- set_guest_info_test_module.c
    |   +-- Makefile
|   +-- shared                          /* Shared files to support test infrastructure */
    |   +-- vbh_test_shared.h
    |   +-- vmcall.S
```


## Use Cases
We developed the following use cases so far and we are looking for adding more use cases.
1. Help prevent hardware from being damaged by unsafe modification of CR and MSR registers.  See kernelhardening.c.
2. Help Prevent privilege escalation attack against Linux kernel. (source code not published)
3. Help protect Linux's kernel code against tampering (source code not published)


## How to Use
    - To get source code
        >> git clone https://github.com/intel/vbh.git
    
    - To compile
        >> cd vbh/sources
        >> make
  
    - To clean
        >> make clean

    - To install    
        >> sudo insmod vmx-switch.ko switch_vmx_on_load=1

    - To uninstall
        >> sudo rmmod vmx_switch

    - To use APIs
    Please refer to the files under test directory for sample usage of every api function.


## How to Contribute

### New Use Cases
If you use this project to help your own research or develop your own use cases, we would love to hear your feedback.  Or if you have ideas of new use cases and need help,  we can help you develop them.  Please contact maintainers of the project.

### Bugs or New Features
Feel free to contact project's maintaniers to learn next new features to be developed.  We also welcome pull request with bug fixes or new feature implementations.  Please provide detailed documentation describing proposed changes when sending pull request.

### Any Questions or Suggestions
Feel free to contact project's maintainers.


## Maintainers
```
rong2.liu@intel.com
sainath.grandhi@intel.com
```
