/*********************IMPORTANT DRAKVUF LICENSE TERMS**********************
*                                                                         *
* DRAKVUF (C) 2014-2017 Tamas K Lengyel.                                  *
* Tamas K Lengyel is hereinafter referred to as the author.               *
* This program is free software; you may redistribute and/or modify it    *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
* CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
* right to use, modify, and redistribute this software under certain      *
* conditions.  If you wish to embed DRAKVUF technology into proprietary   *
* software, alternative licenses can be aquired from the author.          *
*                                                                         *
* Note that the GPL places important restrictions on "derivative works",  *
* yet it does not provide a detailed definition of that term.  To avoid   *
* misunderstandings, we interpret that term as broadly as copyright law   *
* allows.  For example, we consider an application to constitute a        *
* derivative work for the purpose of this license if it does any of the   *
* following with any software or content covered by this license          *
* ("Covered Software"):                                                   *
*                                                                         *
* o Integrates source code from Covered Software.                         *
*                                                                         *
* o Reads or includes copyrighted data files.                             *
*                                                                         *
* o Is designed specifically to execute Covered Software and parse the    *
* results (as opposed to typical shell or execution-menu apps, which will *
* execute anything you tell them to).                                     *
*                                                                         *
* o Includes Covered Software in a proprietary executable installer.  The *
* installers produced by InstallShield are an example of this.  Including *
* DRAKVUF with other software in compressed or archival form does not     *
* trigger this provision, provided appropriate open source decompression  *
* or de-archiving software is widely available for no charge.  For the    *
* purposes of this license, an installer is considered to include Covered *
* Software even if it actually retrieves a copy of Covered Software from  *
* another source during runtime (such as by downloading it from the       *
* Internet).                                                              *
*                                                                         *
* o Links (statically or dynamically) to a library which does any of the  *
* above.                                                                  *
*                                                                         *
* o Executes a helper program, module, or script to do any of the above.  *
*                                                                         *
* This list is not exclusive, but is meant to clarify our interpretation  *
* of derived works with some common examples.  Other people may interpret *
* the plain GPL differently, so we consider this a special exception to   *
* the GPL that we apply to Covered Software.  Works which meet any of     *
* these conditions must conform to all of the terms of this license,      *
* particularly including the GPL Section 3 requirements of providing      *
* source code and allowing free redistribution of the work as a whole.    *
*                                                                         *
* Any redistribution of Covered Software, including any derived works,    *
* must obey and carry forward all of the terms of this license, including *
* obeying all GPL rules and restrictions.  For example, source code of    *
* the whole work must be provided and free redistribution must be         *
* allowed.  All GPL references to "this License", are to be treated as    *
* including the terms and conditions of this license text as well.        *
*                                                                         *
* Because this license imposes special exceptions to the GPL, Covered     *
* Work may not be combined (even as part of a larger work) with plain GPL *
* software.  The terms, conditions, and exceptions of this license must   *
* be included as well.  This license is incompatible with some other open *
* source licenses as well.  In some cases we can relicense portions of    *
* DRAKVUF or grant special permissions to use it in other open source     *
* software.  Please contact tamas.k.lengyel@gmail.com with any such       *
* requests.  Similarly, we don't incorporate incompatible open source     *
* software into Covered Software without special permission from the      *
* copyright holders.                                                      *
*                                                                         *
* If you have any questions about the licensing restrictions on using     *
* DRAKVUF in other works, are happy to help.  As mentioned above,         *
* alternative license can be requested from the author to integrate       *
* DRAKVUF into proprietary applications and appliances.  Please email     *
* tamas.k.lengyel@gmail.com for further information.                      *
*                                                                         *
* If you have received a written license agreement or contract for        *
* Covered Software stating terms other than these, you may choose to use  *
* and redistribute Covered Software under those terms instead of these.   *
*                                                                         *
* Source is provided to this software because we believe users have a     *
* right to know exactly what a program is going to do before they run it. *
* This also allows you to audit the software for security holes.          *
*                                                                         *
* Source code also allows you to port DRAKVUF to new platforms, fix bugs, *
* and add new features.  You are highly encouraged to submit your changes *
* on https://github.com/tklengyel/drakvuf, or by other methods.           *
* By sending these changes, it is understood (unless you specify          *
* otherwise) that you are offering unlimited, non-exclusive right to      *
* reuse, modify, and relicense the code.  DRAKVUF will always be          *
* available Open Source, but this is important because the inability to   *
* relicense code has caused devastating problems for other Free Software  *
* projects (such as KDE and NASM).                                        *
* To specify special license conditions of your contributions, just say   *
* so when you send them.                                                  *
*                                                                         *
* This program is distributed in the hope that it will be useful, but     *
* WITHOUT ANY WARRANTY; without even the implied warranty of              *
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   *
* license file for more details (it's in a COPYING file included with     *
* DRAKVUF, and also available from                                        *
* https://github.com/tklengyel/drakvuf/COPYING)                           *
*                                                                         *
***************************************************************************/

#include <libvmi/libvmi.h>
#include <libvmi/libvmi_extra.h>
#include <libvmi/x86.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <signal.h>
#include <inttypes.h>
#include <glib.h>

#include "libdrakvuf/libdrakvuf.h"
#include "private.h"

struct doppelganging
{
    // Inputs:
    const char* target_proc;
    reg_t target_cr3;
    vmi_pid_t target_pid;
    uint32_t target_tid;

    // Internal:
    drakvuf_t drakvuf;
    vmi_instance_t vmi;
    const char* rekall_profile;
    bool is32bit;
    int hijacked_status;
    addr_t createprocessa;
    addr_t ntcreatesection, loadlibrary, getlasterror;
//    addr_t createtransaction;

    addr_t process_info;
    x86_registers_t saved_regs;

    drakvuf_trap_t bp, cr3_event;

    size_t offsets[OFFSET_MAX];

    // Results:
    reg_t cr3;
    int rc;
    uint32_t pid, tid;
    uint32_t hProc, hThr;
};

#define SW_SHOWDEFAULT 10


struct startup_info_64
{
    uint32_t cb;
    addr_t lpReserved;
    addr_t lpDesktop;
    addr_t lpTitle;
    uint32_t dwX;
    uint32_t dwY;
    uint32_t dwXSize;
    uint32_t dwYSize;
    uint32_t dwXCountChars;
    uint32_t dwYCountChars;
    uint32_t dwFillAttribute;
    uint32_t dwFlags;
    uint16_t wShowWindow;
    uint16_t cbReserved2;
    addr_t lpReserved2;
    addr_t hStdInput;
    addr_t hStdOutput;
    addr_t hStdError;
} __attribute__ ((packed));
// was not packed

struct process_information_64
{
    addr_t hProcess;
    addr_t hThread;
    uint32_t dwProcessId;
    uint32_t dwThreadId;
} __attribute__ ((packed));

struct list_entry_32
{
    uint32_t flink;
    uint32_t blink;
} __attribute__ ((packed));

struct list_entry_64
{
    uint64_t flink;
    uint64_t blink;
} __attribute__ ((packed));

struct kapc_state_64
{
    // apc_list_head[0] = kernel apc list
    // apc_list_head[1] = user apc list
    struct list_entry_64 apc_list_head[2];
    uint64_t process;
    uint8_t kernel_apc_in_progress;
    uint8_t kernel_apc_pending;
    uint8_t user_apc_pending;
} __attribute__ ((packed));
// was not packed

struct kapc_64
{
    uint8_t type;
    uint8_t spare_byte0;
    uint8_t size;
    uint8_t spare_byte1;
    uint32_t spare_long0;
    uint64_t thread;
    struct list_entry_64 apc_list_entry;
    uint64_t kernel_routine;
    uint64_t rundown_routine;
    uint64_t normal_routine;
    uint64_t normal_context;
    uint64_t system_argument_1;
    uint64_t system_argument_2;
    uint8_t apc_state_index;
    uint8_t apc_mode;
    uint8_t inserted;
} __attribute__ ((packed));
// was not packed




/*
    Create stack to call LoadLibrary

    HMODULE WINAPI LoadLibrary( _In_ LPCTSTR lpFileName );
*/
bool loadlibrary_inputs(struct doppelganging* doppelganging, drakvuf_trap_info_t* info, const char* dllname)
{
    addr_t stack_base, stack_limit;

    // get VMI
    vmi_instance_t vmi = doppelganging->vmi;

    reg_t rsp = info->regs->rsp;
    reg_t fsgs = info->regs->gs_base;

    // set Context
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };

    // get Stack Base
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKBASE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_base))
        goto err;

    // get Stack Limit
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKLIMIT];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_limit))
        goto err;


    // Push input arguments on the stack
    uint8_t nul8 = 0;
    uint64_t nul64 = 0;
    addr_t str_addr;

    // stack start here
    addr_t addr = rsp;


    addr -= 0x8; // the stack has to be alligned to 0x8
    // and we need a bit of extra buffer before the string for \0

    // we just going to null out that extra space fully
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    // this string has to be aligned as well
    size_t len = strlen(dllname);
    addr -= len + 0x8 - (len % 0x8);
    str_addr = addr;    // string address
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write(vmi, &ctx, len, (void*) dllname, NULL))
        goto err;

    // add null termination
    ctx.addr = addr+len;
    if (VMI_FAILURE == vmi_write_8(vmi, &ctx, &nul8))
        goto err;


    //http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
    //
    //First 4 parameters to functions are always passed in registers
    //P1=rcx, P2=rdx, P3=r8, P4=r9
    //5th parameter onwards (if any) passed via the stack

    // allocate 0x8 "homing space" for p1 on stack
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    //p1
    info->regs->rcx = str_addr;
    //p2
    info->regs->rdx = 0;
    //p3
    info->regs->r8 = 0;
    //p4
    info->regs->r9 = 0;

    // save the return address
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
        goto err;

    // Grow the stack
    info->regs->rsp = addr;

    return 1;

err:
    PRINT_DEBUG("Failed to pass inputs to loadlibrary hijacked function!\n");
    return 0;
}



// CR3 register callback trap
event_response_t dg_cr3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // get trap data
    struct doppelganging* doppelganging = info->trap->data;

    addr_t thread = 0;
    status_t status;

    // get CR3
    reg_t cr3 = info->regs->cr3;
    PRINT_DEBUG("CR3 changed to 0x%" PRIx64 "\n", info->regs->cr3);

    // if it is not the right process, continue
    if (cr3 != doppelganging->target_cr3)
        return 0;

    // get thread
    thread = drakvuf_get_current_thread(drakvuf, info->vcpu);
    if (!thread)
    {
        PRINT_DEBUG("cr3_cb: Failed to find current thread\n");
        return 0;
    }

    // get thread id
    uint32_t threadid = 0;
    if ( !drakvuf_get_current_thread_id(doppelganging->drakvuf, info->vcpu, &threadid) || !threadid )
        return 0;

    PRINT_DEBUG("Thread @ 0x%lx. ThreadID: %u\n", thread, threadid);

    // if thread was specified as arg and it is not the right thread, continue
    if ( doppelganging->target_tid && doppelganging->target_tid != threadid)
        return 0;


    /*
     * At this point the process is still in kernel mode, so
     * we need to trap when it enters into user mode.
     *
     * For 64-bit Windows we use the trapframe approach, where we read
     * the saved RIP from the stack trap frame and trap it.
     * When this address is hit, we hijack the flow, starting a chain of commands
     * needed to doppelganging.
     * Afterwards return the registers to the original values, thus the process continues to run.
     */
    addr_t trapframe = 0;
    status = vmi_read_addr_va(doppelganging->vmi,
                              thread + doppelganging->offsets[KTHREAD_TRAPFRAME],
                              0, &trapframe);

    if (status == VMI_FAILURE || !trapframe)
    {
        PRINT_DEBUG("cr3_cb: failed to read trapframe (0x%lx)\n", trapframe);
        return 0;
    }

    status = vmi_read_addr_va(doppelganging->vmi,
                              trapframe + doppelganging->offsets[KTRAP_FRAME_RIP],
                              0, &doppelganging->bp.breakpoint.addr);

    if (status == VMI_FAILURE || !doppelganging->bp.breakpoint.addr)
    {
        PRINT_DEBUG("Failed to read RIP from trapframe or RIP is NULL!\n");
        return 0;
    }

    // reset hijacked_status
    doppelganging->hijacked_status = CALL_NONE;

    // register breakpoint trap on "Trap Frame RIP"
    doppelganging->bp.type = BREAKPOINT;
    doppelganging->bp.name = "entry";
    doppelganging->bp.cb = dg_int3_cb;
    doppelganging->bp.data = doppelganging;
    doppelganging->bp.breakpoint.lookup_type = LOOKUP_DTB;
    doppelganging->bp.breakpoint.dtb = cr3;
    doppelganging->bp.breakpoint.addr_type = ADDR_VA;

    if ( drakvuf_add_trap(drakvuf, &doppelganging->bp) )
    {
        PRINT_DEBUG("Got return address 0x%lx from trapframe and it's now trapped!\n",
                    doppelganging->bp.breakpoint.addr);

        // unsubscribe from the CR3 trap
        drakvuf_remove_trap(drakvuf, info->trap, NULL);
    }
    else
        fprintf(stderr, "Failed to trap trapframe return address\n");

    return 0;
}


// INT3 breakpoint callback
event_response_t dg_int3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // get trap data
    struct doppelganging* doppelganging = info->trap->data;
    
    reg_t cr3 = info->regs->cr3;


/* 
    // set Context
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = cr3,
    };
*/

    PRINT_DEBUG("INT3 Callback @ 0x%lx. CR3 0x%lx (status: %d)\n",
                info->regs->rip, cr3, doppelganging->hijacked_status);

    // check breakpoint has been hit by right process
    if ( cr3 != doppelganging->target_cr3 )
    {
        PRINT_DEBUG("INT3 received but CR3 (0x%lx) doesn't match target process (0x%lx)\n",
                    cr3, doppelganging->target_cr3);
        vmi_pid_t current_pid = -1;
        vmi_dtb_to_pid(doppelganging->vmi, cr3, &current_pid);
        PRINT_DEBUG("Current CR3 (0x%lx) is PID %d on VCPU=%d\n", cr3, current_pid, info->vcpu);
        return 0;
    }

    // check current thread exists
    uint32_t threadid = 0;
    if ( !drakvuf_get_current_thread_id(doppelganging->drakvuf, info->vcpu, &threadid) || !threadid )
        return 0;


    // --- CHAIN #0 ---

    // check current RIP is trapframe breakpoint and check hijacked_status
    if ( doppelganging->hijacked_status == CALL_NONE && 
         info->regs->rip == doppelganging->bp.breakpoint.addr )
    {
        // save all regs
        memcpy(&doppelganging->saved_regs, info->regs, sizeof(x86_registers_t));

        // === start execution chain ===

        // setup stack for LoadLibrary function call
        if ( !loadlibrary_inputs(doppelganging, info, "ktmw32.dll") )
        {
            PRINT_DEBUG("Failed to setup stack for LoadLibrary(KtmW32.dll)\n");
            return 0;
        }
        
        // set next chain RIP: LoadLibrary
        info->regs->rip = doppelganging->loadlibrary;

        // set status to CALL_LOADLIBRARY
        doppelganging->hijacked_status = CALL_LOADLIBRARY;

        // if target thread was not defined, the current one is defined now
        if ( !doppelganging->target_tid )
            doppelganging->target_tid = threadid;

        // goto next chain: LoadLibrary
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    // skip this callback in case of:
    // - hijacked_status is CALL_NONE
    // - current RIP is not trapframe breakpoint
    // - current thread is not the target one
    if ( doppelganging->hijacked_status == CALL_NONE || 
         info->regs->rip != doppelganging->bp.breakpoint.addr || 
         threadid != doppelganging->target_tid )
        return 0;


    // --- CHAIN #1 ---
    // check current RIP is trapframe breakpoint and check hijacked_status
    if ( doppelganging->hijacked_status == CALL_LOADLIBRARY && 
         info->regs->rip == doppelganging->bp.breakpoint.addr )
    {
        // === start execution chain ===

        // setup stack for GetLastError function call
        if ( !GetLastError_inputs(doppelganging, info) )
        {
            PRINT_DEBUG("Failed to setup stack for GetLastError()\n");
            return 0;
        }
        
        // set next chain RIP: GetLastError
        info->regs->rip = doppelganging->getlasterror;

        // set status to CALL_GETLASTERROR
        doppelganging->hijacked_status = CALL_GETLASTERROR;

        // if target thread was not defined, the current one is defined now
        if ( !doppelganging->target_tid )
            doppelganging->target_tid = threadid;

        // goto next chain: GetLastError
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }


    // We are now in the return path from GetLastError

    // remove trapframe breakpoint trap
    drakvuf_interrupt(drakvuf, -1);
    drakvuf_remove_trap(drakvuf, &doppelganging->bp, NULL);


    // print GetLastError return code
    PRINT_DEBUG("RAX: 0x%lx\n", info->regs->rax);


    // restore all regs and continue execution to trap frame return point
    memcpy(info->regs, &doppelganging->saved_regs, sizeof(x86_registers_t));
    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}



// Doppelganging main
int doppelganging_start_app(drakvuf_t drakvuf, vmi_pid_t pid, uint32_t tid, const char* app)
{
    struct doppelganging doppelganging = { 0 };
    doppelganging.drakvuf = drakvuf;
    doppelganging.vmi = drakvuf_lock_and_get_vmi(drakvuf);
    doppelganging.rekall_profile = drakvuf_get_rekall_profile(drakvuf);
    doppelganging.target_pid = pid;
    doppelganging.target_tid = tid;
    doppelganging.target_proc = app;

    doppelganging.is32bit = (vmi_get_page_mode(doppelganging.vmi, 0) == VMI_PM_IA32E) ? 0 : 1;

    // initially, only for 64bit arch
    if (doppelganging.is32bit)
    {
        PRINT_DEBUG("Unsupported arch: 32bit\n");
        goto done;        
    }

    // get DTB (CR3) of pid process
    if ( VMI_FAILURE == vmi_pid_to_dtb(doppelganging.vmi, pid, &doppelganging.target_cr3) )
    {
        PRINT_DEBUG("Unable to find target PID's DTB\n");
        goto done;
    }

    // get offsets from the Rekall profile
    unsigned int i;
    for (i = 0; i < OFFSET_MAX; i++)
    {
        if ( !drakvuf_get_struct_member_rva(doppelganging.rekall_profile, offset_names[i][0], offset_names[i][1], &doppelganging.offsets[i]))
        {
            PRINT_DEBUG("Failed to find offset for %s:%s\n", offset_names[i][0],
                        offset_names[i][1]);
        }
    }

    PRINT_DEBUG("Target PID %u with DTB 0x%lx to start '%s'\n", pid, doppelganging.target_cr3, app);

    // get EPROCESS
    addr_t eprocess_base = 0;
    if ( !drakvuf_find_process(doppelganging.drakvuf, pid, NULL, &eprocess_base) )
        goto done;


    // get vaddress of functions to be called

    // CreateProcessA
    doppelganging.createprocessa = drakvuf_exportsym_to_va(doppelganging.drakvuf, eprocess_base, "kernel32.dll", "CreateProcessA");
    if (!doppelganging.createprocessa)
    {
        PRINT_DEBUG("Failed to get address of kernel32.dll!CreateProcessA\n");
        goto done;
    }

    // NtCreateSection
    doppelganging.ntcreatesection = drakvuf_exportsym_to_va(doppelganging.drakvuf, eprocess_base, "ntdll.dll", "NtCreateSection");
    if (!doppelganging.ntcreatesection)
    {
        PRINT_DEBUG("Failed to get address of ntdll.dll!NtCreateSection\n");
        goto done;
    }
    PRINT_DEBUG("ntdll.dll!NtCreateSection: 0x%lx\n", doppelganging.ntcreatesection);

/*
    // CreateTransaction
    doppelganging.createtransaction = drakvuf_exportsym_to_va(doppelganging.drakvuf, eprocess_base, "ktmw32.dll", "CreateTransaction");
    if (!doppelganging.createtransaction)
    {
        PRINT_DEBUG("Failed to get address of ktmw32.dll!CreateTransaction\n");
        goto done;
    }
    PRINT_DEBUG("ktmw32.dll!CreateTransaction: 0x%lx\n", doppelganging.createtransaction);
*/

    // LoadLibraryA
    doppelganging.loadlibrary = drakvuf_exportsym_to_va(doppelganging.drakvuf, eprocess_base, "kernel32.dll", "LoadLibraryA");
    if (!doppelganging.loadlibrary)
    {
        PRINT_DEBUG("Failed to get address of kernel32.dll!LoadLibraryA\n");
        goto done;
    }
    PRINT_DEBUG("kernel32.dll!LoadLibraryA: 0x%lx\n", doppelganging.loadlibrary);

    // GetLastError
    doppelganging.getlasterror = drakvuf_exportsym_to_va(doppelganging.drakvuf, eprocess_base, "kernel32.dll", "GetLastError");
    if (!doppelganging.getlasterror)
    {
        PRINT_DEBUG("Failed to get address of kernel32.dll!GetLastError\n");
        goto done;
    }
    PRINT_DEBUG("kernel32.dll!GetLastError: 0x%lx\n", doppelganging.getlasterror);


    // register CR3 trap
    doppelganging.cr3_event.type = REGISTER;
    doppelganging.cr3_event.reg = CR3;
    doppelganging.cr3_event.cb = dg_cr3_cb;
    doppelganging.cr3_event.data = &doppelganging;
    if ( !drakvuf_add_trap(drakvuf, &doppelganging.cr3_event) )
        goto done;

    // start loop
    PRINT_DEBUG("Starting injection loop\n");
    drakvuf_loop(drakvuf);


    // CreateTransaction
    addr_t createtransaction = drakvuf_exportsym_to_va(doppelganging.drakvuf, eprocess_base, "KtmW32.dll", "CreateTransaction");
    PRINT_DEBUG("--> KtmW32.dll!CreateTransaction: 0x%lx\n", createtransaction);


    // close, remove traps and release vmi
    drakvuf_pause(drakvuf);
    drakvuf_remove_trap(drakvuf, &doppelganging.cr3_event, NULL);

done:
    PRINT_DEBUG("Finished with injection. Ret: %i\n", doppelganging.rc);
    drakvuf_release_vmi(drakvuf);
    return doppelganging.rc;
}
