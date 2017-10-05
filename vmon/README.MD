    Update:
    The information below is outdated and only partially valid, since some of the VMWare "monitor"
    backdoor commands have been removed from the VMWare (Workstation) codebase in an effort to fix a
    security vulnerability that I discovered and reported to VMWare.


# VMon for VMWare

VMWare has a built-in backdoor for the communication between its guest
and host operating systems which, for instance, is used by the
"VMWare Tools" package to improve usability. After the backdoor became
publicly known, it has been used in the anti-forensics field and by
malware authors to detect the presence of VMWare virtual machines.
Although the backdoor's services have widely been documented
(http://chitchat.at.infoseek.co.jp/vmware/backdoor.html),
there are still some services that have not been covered to date. One of them is
service 0x10 which directly communicates with the VMWare's virtual machine
monitor (VMM). Using that service, VMon is able to change and override
the virtual machine's configuration settings on the fly - from within the
guest OS.

# Usage:

For VMon to work, service number 0x10 has to be enabled in the virtual
machine's configuration file first. Add the following line to the VM's vmx file:

    isolation.monitor.control.disable = "FALSE"

After that, copy vmon.exe to your guest system, usage is as follows:

    vmon.exe <subservice no> <value/flag>

"subservice" is one of the values listed below. Please be careful since
VMon hasn't been tested intensely.


# description of subservices:

    subservice:     description:

    0               clear flag
    1               set flag
    2               check if flag is set
    3               ?
    4               commit changes?
    5               commit changes?
    6               commit changes?
    7               set ebx?
    8               set ebx?
    9               set ebx?
    10              ?
    11              ?
    12              ?
    13              get number of logical cpus?
    14              suspend vm
    15              set ebx?
    16              bad/unsupported command
    17              bad/unsupported command
    18              is hypervisor enabled?
    19              bad/unsupported command
    20              suspend and resume?
    21              ?
    

The table below shows a list of values/flags that can be used
in conjunction with subservices 0-2.


# description of flags for subservices 0, 1 and 2:

    value/flag:   flag name:

    0             busmem_installcrosscall
    1             dirty_on_unlock
    2             disable_apic
    3             disable_bte1000
    4             disable_bte1000_TDT
    5             disable_btinout
    6             disable_btmemspace
    7             disable_btpriv
    8             disable_btseg
    9             disable_ccf_inval
    10            disable_checkcode
    11            disable_checkcodeexpire
    12            disable_codetracing
    13            disable_directexec
    14            disable_directmemcopy
    15            disable_dtfastwrite
    16            disable_dttracing
    17            disable_eagervalidate
    18            disable_fastsyscalls
    19            disable_faultpfopt
    20            disable_fffxsr
    21            disable_flat_mode
    22            disable_hv_hybridmmu
    23            disable_ics
    24            disable_inlinetraces
    25            disable_inlining
    26            disable_kfc
    27            disable_loadscratchshort
    28            disable_longmode
    29            disable_mca
    30            disable_mmucaching
    31            disable_mmx
    32            disable_nestedpaging
    33            disable_ntreloc
    34            disable_para_a_bit
    35            disable_parafastexc
    36            disable_parafastpf
    37            disable_paratime
    38            disable_rdtscopt_bt
    39            disable_rdtscopt_de
    40            disable_redirectgates
    41            disable_reloc
    42            disable_rsvd_flow
    43            disable_rsvd_binding
    44            disable_scratchlookahead
    45            disable_selfmod
    46            disable_setfsopt
    47            disable_shared_mmu
    48            disable_trimming
    49            disable_tsc_offsetting
    50            disable_v8086
    51            disable_vme
    52            disable_vmeopt
    53            disable_vsyscall_check
    54            disable_zeropage
    55            dump_host_ioapic
    56            enable_biosRebootWorkaround
    57            enable_btSelfIPI
    58            enable_clearIRROnSoftDisable
    59            enable_extended_core
    60            enable_e1000_IMS_workaround
    61            enable_guestdebugger
    62            enable_guestdebugonstart
    63            enable_irqspacing
    64            enable_paravirt
    65            enable_passthrough
    66            enable_pmatch_cui
    67            enable_pmatch_linuxvga
    68            enable_pmatch_w2kvga
    69            enable_pmatch_nt4MapRace
    70            enable_softResetClearTSC
    71            enable_svm
    72            enable_zeromda_irqlatch
    73            growdown_protect
    74            halt_desched
    75            hosted_ballooning
    76            hybrid_mmu
    77            interp_logging
    78            interp_replaying
    79            interp_bt
    80            log_vmsample
    81            mmu_singleptroot
    82            noncacheable_int20
    83            nw_bigmem
    84            nw_jvm
    85            os2
    86            pseudo_perfctr
    87            restrict_backdoor
    88            slowloop
    89            startup_delay
    90            startup_interlock
    91            tcl_step
    92            virtual_rdtsc
    93            vt32
    94            vt64
    95            vmk_segments
    96            vsyscall_hole
    97            disable_mmu_largepages


# Examples:

  vmon.exe 2 5

tests if flag 5 (disable_btinout) is set, indicating
that binary translation for I/O operations is disabled.

  vmon.exe 14 0

suspends the virtual machine

  vmon.exe 18 0

reports if hypervisor is active

  vmon.exe 1 87
  
restricts access to VMWare's backdoor so that only code running in CPL 0 is
allowed to use the backdoor.

This might be used to disable common VMWare detections such as "jerry" (see below).


  c:\>jerry.exe
  You are inside of VMware. Product version: Workstation
  
  c:\>vmon 1 87
  
  c:\>jerry.exe
  You are on a native system.

(c) Dennis Elser
