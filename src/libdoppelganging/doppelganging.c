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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "libdrakvuf/libdrakvuf.h"
#include "private.h"



/* Windows Structures */
/* Conversion type:
    BYTE    --> uint8_t
    WORD    --> uint16_t
    DWORD   --> uint32_t
    HANDLE  --> addr_t
    LPTSTR  --> addr_t
    LPBYTE  --> addr_t
    PSTR    --> addr_t
    PUCHAR  --> addr_t
    UCHAR   --> uint8_t
    ULONGLONG --> uint64_t
    ...

Type                        | S/U | x86    | x64
----------------------------+-----+--------+-------
BYTE, BOOLEAN               | U   | 8 bit  | 8 bit
----------------------------+-----+--------+-------
SHORT                       | S   | 16 bit | 16 bit
USHORT, WORD                | U   | 16 bit | 16 bit
----------------------------+-----+--------+-------
INT, LONG                   | S   | 32 bit | 32 bit
UINT, ULONG, DWORD          | U   | 32 bit | 32 bit
----------------------------+-----+--------+-------
INT_PTR, LONG_PTR, LPARAM   | S   | 32 bit | 64 bit
UINT_PTR, ULONG_PTR, WPARAM | U   | 32 bit | 64 bit
----------------------------+-----+--------+-------
LONGLONG                    | S   | 64 bit | 64 bit
ULONGLONG, QWORD            | U   | 64 bit | 64 bit    
*/


struct process_basic_information {
    addr_t Reserved1;
    addr_t PebBaseAddress;              // process PEB struct pointer
    addr_t Reserved2[2];
    uint64_t UniqueProcessId;
    addr_t Reserved3;
};


// from libvmi/private.h
/** Windows' UNICODE_STRING structure (x64) */
typedef struct _windows_unicode_string64 {
    uint16_t length;
    uint16_t maximum_length;
    uint32_t padding;   // align pBuffer
    uint64_t pBuffer;   // pointer to string contents
} __attribute__ ((packed))
    win64_unicode_string_t;


// from ntdefs.h
typedef struct _curdir
{
    win64_unicode_string_t DosPath;
    addr_t Handle;
} __attribute__ ((packed))
    curdir_t;


#define RTL_MAX_DRIVE_LETTERS 32

typedef struct _rtl_drive_letter_curdir
{
    uint16_t Flags;
    uint16_t Length;
    uint32_t TimeStamp;
    win64_unicode_string_t DosPath;
} __attribute__ ((packed))
    rtl_drive_letter_curdir_t;



typedef struct _rtl_user_process_parameters
{
    uint32_t MaximumLength;
    uint32_t Length;
    uint32_t Flags;
    uint32_t DebugFlags;
    addr_t ConsoleHandle;
    uint32_t ConsoleFlags;
    uint32_t padding1;

    addr_t StandardInput;
    addr_t StandardOutput;
    addr_t StandardError;

    curdir_t CurrentDirectory;
    win64_unicode_string_t DllPath;
    win64_unicode_string_t ImagePathName;
    win64_unicode_string_t CommandLine;
    addr_t Environment;

    uint32_t StartingX;
    uint32_t StartingY;
    uint32_t CountX;
    uint32_t CountY;
    uint32_t CountCharsX;
    uint32_t CountCharsY;
    uint32_t FillAttribute;
    uint32_t WindowFlags;
    uint32_t ShowWindowFlags;
    uint32_t padding2;

    win64_unicode_string_t WindowTitle;
    win64_unicode_string_t DesktopInfo;
    win64_unicode_string_t ShellInfo;
    win64_unicode_string_t RuntimeData;

    rtl_drive_letter_curdir_t CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    addr_t EnvironmentSize;
    addr_t EnvironmentVersion;
    addr_t PackageDependencyData;
    uint32_t ProcessGroupId;
    uint32_t LoaderThreads;
} __attribute__ ((packed))
    rtl_user_process_parameters_t;




struct doppelganging
{
    // Inputs:
    const char* host_file;
    const char* local_proc;
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
    addr_t loadlibrary, getlasterror, createtransaction, createfiletransacted, virtualalloc, rtlzeromemory, writefile, ntcreatesection, ntcreateprocessex, ntqueryinformationprocess, rtlinitunicodestring, rtlcreateprocessparametersex;
    addr_t eprocess_base;

    uint64_t hTransaction;      // HANDLE
    uint64_t hTransactedFile;   // HANDLE

    addr_t hSection_ptr;        // PHANDLE
    addr_t hProcess_ptr;        // PHANDLE

    uint64_t hSection;          // HANDLE
    uint64_t hProcess;          // HANDLE

    addr_t pbi_ptr;
    addr_t proc_entry;
    struct process_basic_information pbi;

    addr_t unicodeDestString_ptr;
    addr_t local_proc_image_ptr, local_proc_dll_ptr, local_proc_currdir_ptr;

    void *hostfile_buffer;
    int64_t hostfile_len;
    addr_t guestfile_buffer;
    addr_t dwBytesWritten;

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







// **** UTILS **** //
char* getImageFromPath(char* path)
{
    for (int i = strlen(path) - 1; i >= 0; i--)  
    {
        if (path[i] == '\\')
        {
            return &path[i+1];
        }
    }
    return path;
}

void stripPathToDir(char* path)
{
    for (int i = strlen(path) - 1; i>=0; i--)  
    {
        if (path[i] == '\\')
        {
            path[i+1] = '\0';
            return;
        }
    }
    path[0] = '.';
    path[1] = '\\';
    path[2] = '\0';
}






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

    PRINT_DEBUG(">>>> LoadLibrary stack\n");

    // get Stack Base
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKBASE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_base))
        goto err;

    // get Stack Limit
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKLIMIT];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_limit))
        goto err;

    PRINT_DEBUG("Stack Base:  0x%lx\n", stack_base);
    PRINT_DEBUG("Stack Limit: 0x%lx\n", stack_limit);


    // Push input arguments on the stack
    uint8_t nul8 = 0;
    uint64_t nul64 = 0;

    // stack start here
    addr_t addr = rsp;
    PRINT_DEBUG("Stack start @ 0x%lx\n", addr);


    // the stack has to be alligned to 0x8
    // we just going to null out that extra space fully
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    // lpFileName string (it has to be aligned as well)
    addr_t dllname_addr;
    size_t len = strlen(dllname);
    addr -= len + 0x8 - (len % 0x8);
    dllname_addr = addr;                // string address
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write(vmi, &ctx, len, (void*) dllname, NULL))
        goto err;
    // add null termination
    ctx.addr = addr + len;
    if (VMI_FAILURE == vmi_write_8(vmi, &ctx, &nul8))
        goto err;
    PRINT_DEBUG("- Var. lpFileName (string): %s (len 0x%lx) @ 0x%lx\n", dllname, len, dllname_addr);


    //http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
    //
    //First 4 parameters to functions are always passed in registers
    //P1=rcx, P2=rdx, P3=r8, P4=r9
    //5th parameter onwards (if any) passed via the stack

    // WARNING: allocate MIN 0x20 "homing space" on stack or call will crash
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;


    //p1
    info->regs->rcx = dllname_addr;
    PRINT_DEBUG("p1: 0x%lx\n", info->regs->rcx);

/*    
    //p2
    info->regs->rdx = 0;
    //p3
    info->regs->r8 = 0;
    //p4
    info->regs->r9 = 0;
*/
    
    // save the return address
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
        goto err;

    PRINT_DEBUG("Stack end @ 0x%lx\n", addr);

    // Grow the stack
    info->regs->rsp = addr;


    return 1;

err:
    PRINT_DEBUG("ERROR: Failed to build LoadLibrary stack\n");
    return 0;
}



/*
    Create stack to call CreateTransaction

    HANDLE WINAPI CreateTransaction(
      _In_opt_ LPSECURITY_ATTRIBUTES lpTransactionAttributes,
      _In_opt_ LPGUID                UOW,
      _In_opt_ DWORD                 CreateOptions,
      _In_opt_ DWORD                 IsolationLevel,
      _In_opt_ DWORD                 IsolationFlags,
      _In_opt_ DWORD                 Timeout,
      _In_opt_ LPWSTR                Description
    );

    Example:

    HANDLE hTransaction = CreateTransaction(NULL,0,0,0,0,0,L"explorer.exe");
*/
bool createtransaction_inputs(struct doppelganging* doppelganging, drakvuf_trap_info_t* info)
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

    PRINT_DEBUG(">>>> CreateTransaction stack\n");

    // get Stack Base
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKBASE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_base))
        goto err;

    // get Stack Limit
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKLIMIT];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_limit))
        goto err;

    PRINT_DEBUG("Stack Base:  0x%lx\n", stack_base);
    PRINT_DEBUG("Stack Limit: 0x%lx\n", stack_limit);

    // Push input arguments on the stack
    uint8_t nul8 = 0;
    uint64_t nul64 = 0;

    // stack start here
    addr_t addr = rsp;
    PRINT_DEBUG("Stack start @ 0x%lx\n", addr);


    // the stack has to be alligned to 0x8
    // we just going to null out that extra space fully
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    // local_proc string has to be aligned as well
    addr_t descr_addr;
    size_t len = strlen(doppelganging->local_proc);
    addr -= len + 0x8 - (len % 0x8);
    descr_addr = addr;                  // string address
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write(vmi, &ctx, len, (void*) doppelganging->local_proc, NULL))
        goto err;
    // add null termination
    ctx.addr = addr+len;
    if (VMI_FAILURE == vmi_write_8(vmi, &ctx, &nul8))
        goto err;
    PRINT_DEBUG("- Var. local_proc (string): %s (len 0x%lx) @ 0x%lx\n", doppelganging->local_proc, len, descr_addr);


    //http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
    //
    //First 4 parameters to functions are always passed in registers
    //P1=rcx, P2=rdx, P3=r8, P4=r9
    //5th parameter onwards (if any) passed via the stack

    // p7
    // _In_opt_ LPWSTR Description 
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &descr_addr))
        goto err;
    PRINT_DEBUG("p7: 0x%lx\n", descr_addr);

    // p6
    // _In_opt_ DWORD Timeout,
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;
    PRINT_DEBUG("p6: 0x%lx\n", nul64);

    // p5
    // _In_opt_ DWORD IsolationFlags 
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;
    PRINT_DEBUG("p5: 0x%lx\n", nul64);


    // WARNING: allocate MIN 0x20 "homing space" on stack or call will crash
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;


    // p1: _In_opt_ LPSECURITY_ATTRIBUTES lpTransactionAttributes
    info->regs->rcx = 0;
    PRINT_DEBUG("p1: 0x%lx\n", info->regs->rcx);

    // p2: _In_opt_ LPGUID UOW
    info->regs->rdx = 0;
    PRINT_DEBUG("p2: 0x%lx\n", info->regs->rdx);

    // p3: _In_opt_ DWORD CreateOptions 
    info->regs->r8 = 0;
    PRINT_DEBUG("p3: 0x%lx\n", info->regs->r8);

    // p4: _In_opt_ DWORD IsolationLevel 
    info->regs->r9 = 0;
    PRINT_DEBUG("p4: 0x%lx\n", info->regs->r9);

    
    // save the return address
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
        goto err;

    PRINT_DEBUG("Stack end @ 0x%lx\n", addr);

    // Grow the stack
    info->regs->rsp = addr;


    return 1;

err:
    PRINT_DEBUG("ERROR: Failed to build CreateTransaction stack\n");
    return 0;
}




/*
    Create stack to call CreateFileTransacted

    HANDLE WINAPI CreateFileTransacted(
      _In_       LPCTSTR               lpFileName,
      _In_       DWORD                 dwDesiredAccess,
      _In_       DWORD                 dwShareMode,
      _In_opt_   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
      _In_       DWORD                 dwCreationDisposition,
      _In_       DWORD                 dwFlagsAndAttributes,
      _In_opt_   HANDLE                hTemplateFile,
      _In_       HANDLE                hTransaction,
      _In_opt_   PUSHORT               pusMiniVersion,
      _Reserved_ PVOID                 pExtendedParameter
    );

    Example:

    HANDLE hTransactedFile = CreateFileTransacted(
                                "explorer.exe", GENERIC_WRITE | GENERIC_READ, 0, NULL, 
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL, hTransaction, 
                                NULL, NULL);
*/
bool createfiletransacted_inputs(struct doppelganging* doppelganging, drakvuf_trap_info_t* info)
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

    PRINT_DEBUG(">>>> CreateFileTransacted stack\n");

    // get Stack Base
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKBASE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_base))
        goto err;

    // get Stack Limit
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKLIMIT];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_limit))
        goto err;

    PRINT_DEBUG("Stack Base:  0x%lx\n", stack_base);
    PRINT_DEBUG("Stack Limit: 0x%lx\n", stack_limit);

    // Push input arguments on the stack
    uint8_t nul8 = 0;
    uint64_t nul64 = 0;

    // stack start here
    addr_t addr = rsp;
    PRINT_DEBUG("Stack start @ 0x%lx\n", addr);


    // the stack has to be alligned to 0x8
    // we just going to null out that extra space fully
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    // local_proc string has to be aligned as well
    addr_t local_proc_addr;
    size_t len = strlen(doppelganging->local_proc);
    addr -= len + 0x8 - (len % 0x8);
    local_proc_addr = addr;                  // string address
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write(vmi, &ctx, len, (void*) doppelganging->local_proc, NULL))
        goto err;
    // add null termination
    ctx.addr = addr+len;
    if (VMI_FAILURE == vmi_write_8(vmi, &ctx, &nul8))
        goto err;
    PRINT_DEBUG("- Var. local_proc (string): %s (len 0x%lx) @ 0x%lx\n", doppelganging->local_proc, len, local_proc_addr);


    // bugfix
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;


    //http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
    //
    //First 4 parameters to functions are always passed in registers
    //P1=rcx, P2=rdx, P3=r8, P4=r9
    //5th parameter onwards (if any) passed via the stack


    // p10
    // _Reserved_ PVOID pExtendedParameter 
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;
    PRINT_DEBUG("p10: 0x%lx\n", nul64);

    // p9
    // _In_opt_ PUSHORT pusMiniVersion
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;
    PRINT_DEBUG("p9: 0x%lx\n", nul64);

    // p8
    // _In_ HANDLE hTransaction 
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &doppelganging->hTransaction))
        goto err;
    PRINT_DEBUG("p8: 0x%lx\n", doppelganging->hTransaction);

    // p7
    // _In_opt_ HANDLE hTemplateFile 
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;
    PRINT_DEBUG("p7: 0x%lx\n", nul64);

    // p6
    // _In_ DWORD dwFlagsAndAttributes
    // #define FILE_ATTRIBUTE_NORMAL 0x00000080
    uint64_t k_FILE_ATTRIBUTE_NORMAL = 0x00000080;
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &k_FILE_ATTRIBUTE_NORMAL))
        goto err;
    PRINT_DEBUG("p6: 0x%lx\n", k_FILE_ATTRIBUTE_NORMAL);

    // p5
    // _In_ DWORD dwCreationDisposition
    // #define OPEN_EXISTING 3
    uint64_t k_OPEN_EXISTING = 3;
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &k_OPEN_EXISTING))
        goto err;
    PRINT_DEBUG("p5: 0x%lx\n", k_OPEN_EXISTING);



    // WARNING: allocate MIN 0x20 "homing space" on stack or call will crash
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;


    // p1: _In_ LPCTSTR lpFileName
    info->regs->rcx = local_proc_addr;
    PRINT_DEBUG("p1: 0x%lx\n", info->regs->rcx);

    // p2: _In_ DWORD dwDesiredAccess
    // #define GENERIC_READ (0x80000000L)
    // #define GENERIC_WRITE (0x40000000L)
    uint64_t k_GENERIC_READ  = 0x80000000;
    uint64_t k_GENERIC_WRITE = 0x40000000;
    uint64_t k_dwDesiredAccess = k_GENERIC_READ | k_GENERIC_WRITE;
    info->regs->rdx = k_dwDesiredAccess;
    PRINT_DEBUG("p2: 0x%lx\n", info->regs->rdx);

    // p3: _In_ DWORD dwShareMode 
    info->regs->r8 = 0;
    PRINT_DEBUG("p3: 0x%lx\n", info->regs->r8);

    // p4: _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
    info->regs->r9 = 0;
    PRINT_DEBUG("p4: 0x%lx\n", info->regs->r9);

    
    // save the return address
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
        goto err;

    PRINT_DEBUG("Stack end @ 0x%lx\n", addr);

    // Grow the stack
    info->regs->rsp = addr;


    return 1;

err:
    PRINT_DEBUG("ERROR: Failed to build CreateFileTransacted stack\n");
    return 0;
}



/*
    Create stack to call VirtualAlloc

    LPVOID WINAPI VirtualAlloc(
      _In_opt_ LPVOID lpAddress,
      _In_     SIZE_T dwSize,
      _In_     DWORD  flAllocationType,
      _In_     DWORD  flProtect
    );

    Example:

    BYTE* myBuf = (BYTE*)VirtualAlloc(NULL, numbdrOfBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
*/
bool virtualalloc_inputs(struct doppelganging* doppelganging, drakvuf_trap_info_t* info)
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

    PRINT_DEBUG(">>>> VirtualAlloc stack\n");

    // get Stack Base
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKBASE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_base))
        goto err;

    // get Stack Limit
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKLIMIT];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_limit))
        goto err;

    PRINT_DEBUG("Stack Base:  0x%lx\n", stack_base);
    PRINT_DEBUG("Stack Limit: 0x%lx\n", stack_limit);

    // Push input arguments on the stack
    uint64_t nul64 = 0;

    // stack start here
    addr_t addr = rsp;
    PRINT_DEBUG("Stack start @ 0x%lx\n", addr);


    // the stack has to be alligned to 0x8
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;


    //http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
    //
    //First 4 parameters to functions are always passed in registers
    //P1=rcx, P2=rdx, P3=r8, P4=r9
    //5th parameter onwards (if any) passed via the stack


    // WARNING: allocate MIN 0x20 "homing space" on stack or call will crash
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;


    // p1: _In_opt_ LPVOID lpAddress
    info->regs->rcx = 0;
    PRINT_DEBUG("p1: 0x%lx\n", info->regs->rcx);

    // p2: _In_ SIZE_T dwSize
    info->regs->rdx = doppelganging->hostfile_len;
    PRINT_DEBUG("p2: 0x%lx\n", info->regs->rdx);

    // p3: _In_ DWORD flAllocationType
    // #define MEM_COMMIT 0x1000
    // #define MEM_RESERVE 0x2000
    uint64_t k_MEM_COMMIT   = 0x1000;
    uint64_t k_MEM_RESERVE  = 0x2000;
    uint64_t k_flAllocationType = k_MEM_COMMIT | k_MEM_RESERVE;
    info->regs->r8 = k_flAllocationType;
    PRINT_DEBUG("p3: 0x%lx\n", info->regs->r8);

    // p4: _In_ DWORD flProtect
    // #define PAGE_READWRITE 0x04
    // #define PAGE_EXECUTE_READWRITE 0x40
    uint64_t k_PAGE_READWRITE  = 0x4;
    //uint64_t k_PAGE_EXECUTE_READWRITE = 0x40;
    info->regs->r9 = k_PAGE_READWRITE;
    PRINT_DEBUG("p4: 0x%lx\n", info->regs->r9);


    // save the return address
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
        goto err;

    PRINT_DEBUG("Stack end @ 0x%lx\n", addr);

    // Grow the stack
    info->regs->rsp = addr;


    return 1;

err:
    PRINT_DEBUG("ERROR: Failed to build VirtualAlloc stack\n");
    return 0;
}




/*
    Create stack to call WriteFile

    BOOL WINAPI WriteFile(
      _In_        HANDLE       hFile,
      _In_        LPCVOID      lpBuffer,
      _In_        DWORD        nNumberOfBytesToWrite,
      _Out_opt_   LPDWORD      lpNumberOfBytesWritten,
      _Inout_opt_ LPOVERLAPPED lpOverlapped
    );

    Example:

    WriteFile(hTransactedFile, buffer, dwFileSize, &wrote, NULL)
*/
bool writefile_inputs(struct doppelganging* doppelganging, drakvuf_trap_info_t* info)
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

    PRINT_DEBUG(">>>> WriteFile stack\n");

    // get Stack Base
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKBASE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_base))
        goto err;

    // get Stack Limit
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKLIMIT];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_limit))
        goto err;

    PRINT_DEBUG("Stack Base:  0x%lx\n", stack_base);
    PRINT_DEBUG("Stack Limit: 0x%lx\n", stack_limit);

    // Push input arguments on the stack
    uint64_t nul64 = 0;

    // stack start here
    addr_t addr = rsp;
    PRINT_DEBUG("Stack start @ 0x%lx\n", addr);


    // the stack has to be alligned to 0x8
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;


    // dwBytesWritten
    addr -= 0x8;
    doppelganging->dwBytesWritten = addr;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;
    PRINT_DEBUG("- Var. dwBytesWritten @ 0x%lx\n", doppelganging->dwBytesWritten);


    //http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
    //
    //First 4 parameters to functions are always passed in registers
    //P1=rcx, P2=rdx, P3=r8, P4=r9
    //5th parameter onwards (if any) passed via the stack

    // p5 
    // _Inout_opt_ LPOVERLAPPED lpOverlapped
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;
    PRINT_DEBUG("p5: 0x%lx\n", nul64);


    // WARNING: allocate MIN 0x20 "homing space" on stack or call will crash
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;


    // p1: _In_ HANDLE hFile
    info->regs->rcx = doppelganging->hTransactedFile;
    PRINT_DEBUG("p1: 0x%lx\n", info->regs->rcx);

    // p2: _In_ LPCVOID lpBuffer
    info->regs->rdx = doppelganging->guestfile_buffer;
    PRINT_DEBUG("p2: 0x%lx\n", info->regs->rdx);

    // p3: _In_ DWORD nNumberOfBytesToWrite
    info->regs->r8 = doppelganging->hostfile_len;
    PRINT_DEBUG("p3: 0x%lx\n", info->regs->r8);

    // p4: _Out_opt_ LPDWORD lpNumberOfBytesWritten
    info->regs->r9 = doppelganging->dwBytesWritten;
    PRINT_DEBUG("p4: 0x%lx\n", info->regs->r9);


    // save the return address
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
        goto err;

    PRINT_DEBUG("Stack end @ 0x%lx\n", addr);

    // Grow the stack
    info->regs->rsp = addr;


    return 1;

err:
    PRINT_DEBUG("ERROR: Failed to build WriteFile stack\n");
    return 0;
}




/*
    Create stack to call RtlZeroMemory

    void RtlZeroMemory(
      [in] PVOID  Destination,
      [in] SIZE_T Length
    );

*/
bool rtlzeromemory_inputs(struct doppelganging* doppelganging, drakvuf_trap_info_t* info)
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

    PRINT_DEBUG(">>>> RtlZeroMemory stack\n");

    // get Stack Base
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKBASE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_base))
        goto err;

    // get Stack Limit
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKLIMIT];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_limit))
        goto err;

    PRINT_DEBUG("Stack Base:  0x%lx\n", stack_base);
    PRINT_DEBUG("Stack Limit: 0x%lx\n", stack_limit);

    // Push input arguments on the stack
    uint64_t nul64 = 0;

    // stack start here
    addr_t addr = rsp;
    PRINT_DEBUG("Stack start @ 0x%lx\n", addr);


    // the stack has to be alligned to 0x8
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;


    //http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
    //
    //First 4 parameters to functions are always passed in registers
    //P1=rcx, P2=rdx, P3=r8, P4=r9
    //5th parameter onwards (if any) passed via the stack


    // WARNING: allocate MIN 0x20 "homing space" on stack or call will crash
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;


    // p1: [in] PVOID Destination
    info->regs->rcx = doppelganging->guestfile_buffer;
    PRINT_DEBUG("p1: 0x%lx\n", info->regs->rcx);

    // p2: [in] SIZE_T Length
    info->regs->rdx = doppelganging->hostfile_len;
    PRINT_DEBUG("p2: 0x%lx\n", info->regs->rdx);

    info->regs->r8 = 0;

    info->regs->r9 = 0;


    // save the return address
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
        goto err;

    PRINT_DEBUG("Stack end @ 0x%lx\n", addr);

    // Grow the stack
    info->regs->rsp = addr;


    return 1;

err:
    PRINT_DEBUG("ERROR: Failed to build RtlZeroMemory stack\n");
    return 0;
}




/*
    Create stack to call NtCreateSection

    NTSTATUS NtCreateSection(
      _Out_    PHANDLE            SectionHandle,
      _In_     ACCESS_MASK        DesiredAccess,
      _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
      _In_opt_ PLARGE_INTEGER     MaximumSize,
      _In_     ULONG              SectionPageProtection,
      _In_     ULONG              AllocationAttributes,
      _In_opt_ HANDLE             FileHandle
    );

    Example:

    NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hTransactedFile)
*/
bool ntcreatesection_inputs(struct doppelganging* doppelganging, drakvuf_trap_info_t* info)
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

    PRINT_DEBUG(">>>> NtCreateSection stack\n");

    // get Stack Base
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKBASE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_base))
        goto err;

    // get Stack Limit
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKLIMIT];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_limit))
        goto err;

    PRINT_DEBUG("Stack Base:  0x%lx\n", stack_base);
    PRINT_DEBUG("Stack Limit: 0x%lx\n", stack_limit);

    // Push input arguments on the stack
    uint64_t nul64 = 0;

    // stack start here
    addr_t addr = rsp;
    PRINT_DEBUG("Stack start @ 0x%lx\n", addr);


    // the stack has to be alligned to 0x8
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;


    // pointer to hSection
    addr -= 0x8;
    doppelganging->hSection_ptr = addr;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;
    PRINT_DEBUG("- Var. hSection_ptr @ 0x%lx\n", doppelganging->hSection_ptr);


    //http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
    //
    //First 4 parameters to functions are always passed in registers
    //P1=rcx, P2=rdx, P3=r8, P4=r9
    //5th parameter onwards (if any) passed via the stack


    // p7
    // _In_opt_ HANDLE FileHandle
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &doppelganging->hTransactedFile))
        goto err;
    PRINT_DEBUG("p7: 0x%lx\n", doppelganging->hTransactedFile);

    // p6 
    // _In_ ULONG AllocationAttributes
    // #define SEC_IMAGE 0x1000000
    uint64_t k_SEC_IMAGE = 0x1000000;
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &k_SEC_IMAGE))
        goto err;
    PRINT_DEBUG("p6: 0x%lx\n", k_SEC_IMAGE);

    // p5 
    // _In_ ULONG SectionPageProtection
    // #define PAGE_READONLY 0x02
    uint64_t k_PAGE_READONLY = 0x2;
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &k_PAGE_READONLY))
        goto err;
    PRINT_DEBUG("p5: 0x%lx\n", k_PAGE_READONLY);


    // WARNING: allocate MIN 0x20 "homing space" on stack or call will crash
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;


    // p1: _Out_ PHANDLE SectionHandle
    info->regs->rcx = doppelganging->hSection_ptr;
    PRINT_DEBUG("p1: 0x%lx\n", info->regs->rcx);

    // p2: _In_ ACCESS_MASK DesiredAccess
    // #define SECTION_ALL_ACCESS 0xf001f
    uint64_t k_SECTION_ALL_ACCESS = 0xf001f;
    info->regs->rdx = k_SECTION_ALL_ACCESS;
    PRINT_DEBUG("p2: 0x%lx\n", info->regs->rdx);

    // p3: _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes
    info->regs->r8 = 0;
    PRINT_DEBUG("p3: 0x%lx\n", info->regs->r8);

    // p4: _In_opt_ PLARGE_INTEGER MaximumSize
    info->regs->r9 = 0;
    PRINT_DEBUG("p4: 0x%lx\n", info->regs->r9);


    // save the return address
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
        goto err;

    PRINT_DEBUG("Stack end @ 0x%lx\n", addr);

    // Grow the stack
    info->regs->rsp = addr;


    return 1;

err:
    PRINT_DEBUG("ERROR: Failed to build NtCreateSection stack\n");
    return 0;
}




/*
    Create stack to call NtCreateProcessEx

    NTSTATUS NtCreateProcessEx(
        _Out_       PHANDLE             ProcessHandle,
        _In_        ACCESS_MASK         DesiredAccess,
        _In_opt_    POBJECT_ATTRIBUTES  ObjectAttributes,
        _In_        HANDLE              ParentProcess,
        _In_        BOOLEAN             InheritObjectTable,
        _In_opt_    HANDLE              SectionHandle,
        _In_opt_    HANDLE              DebugPort,
        _In_opt_    HANDLE              ExceptionPort,
        _In_        BOOLEAN             InJob
    );

    Example:

    NtCreateProcessEx(&hProcess, GENERIC_ALL, NULL, GetCurrentProcess(), PS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE)

    Note:
    GetCurrentProcess() returns a pseudo handle is a special constant, currently (HANDLE)-1 (0xffffffffffffffff)
    For compatibility with future operating systems, it is best to call GetCurrentProcess instead of hard-coding this constant value.
    ANYWAY, for thiis test, I'll use the hardcoded version.

*/
bool ntcreateprocessex_inputs(struct doppelganging* doppelganging, drakvuf_trap_info_t* info)
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

    PRINT_DEBUG(">>>> NtCreateProcessEx stack\n");

    // get Stack Base
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKBASE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_base))
        goto err;

    // get Stack Limit
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKLIMIT];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_limit))
        goto err;

    PRINT_DEBUG("Stack Base:  0x%lx\n", stack_base);
    PRINT_DEBUG("Stack Limit: 0x%lx\n", stack_limit);

    // Push input arguments on the stack
    uint64_t nul64 = 0;

    // stack start here
    addr_t addr = rsp;
    PRINT_DEBUG("Stack start @ 0x%lx\n", addr);


    // the stack has to be alligned to 0x8
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;


    // pointer to hProcess
    addr -= 0x8;
    doppelganging->hProcess_ptr = addr;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;
    PRINT_DEBUG("- Var. hProcess_ptr @ 0x%lx\n", doppelganging->hProcess_ptr);


    //http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
    //
    //First 4 parameters to functions are always passed in registers
    //P1=rcx, P2=rdx, P3=r8, P4=r9
    //5th parameter onwards (if any) passed via the stack


    // p9
    // _In_ BOOLEAN InJob
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;
    PRINT_DEBUG("p9: 0x%lx\n", nul64);

    // p8
    // _In_opt_ HANDLE ExceptionPort
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;
    PRINT_DEBUG("p8: 0x%lx\n", nul64);

    // p7
    // _In_opt_ HANDLE DebugPort
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;
    PRINT_DEBUG("p7: 0x%lx\n", nul64);

    // p6 
    // _In_opt_ HANDLE SectionHandle
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &doppelganging->hSection))
        goto err;
    PRINT_DEBUG("p6: 0x%lx\n", doppelganging->hSection);

    // p5 
    // _In_ BOOLEAN InheritObjectTable
    // #define PS_INHERIT_HANDLES 4
    uint64_t k_PS_INHERIT_HANDLES = 4;
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &k_PS_INHERIT_HANDLES))
        goto err;
    PRINT_DEBUG("p5: 0x%lx\n", k_PS_INHERIT_HANDLES);


    // WARNING: allocate MIN 0x20 "homing space" on stack or call will crash
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;


    // p1: _Out_ PHANDLE ProcessHandle
    info->regs->rcx = doppelganging->hProcess_ptr;
    PRINT_DEBUG("p1: 0x%lx\n", info->regs->rcx);

    // p2: _In_ ACCESS_MASK DesiredAccess
    // #define GENERIC_ALL 0x10000000
    uint64_t k_GENERIC_ALL = 0x10000000;
    info->regs->rdx = k_GENERIC_ALL;
    PRINT_DEBUG("p2: 0x%lx\n", info->regs->rdx);

    // p3: _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes
    info->regs->r8 = 0;
    PRINT_DEBUG("p3: 0x%lx\n", info->regs->r8);

    // p4: _In_ HANDLE ParentProcess
    // GetCurrentProcess() pseudo handle
    info->regs->r9 = 0xffffffffffffffff;
    PRINT_DEBUG("p4: 0x%lx\n", info->regs->r9);


    // save the return address
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
        goto err;

    PRINT_DEBUG("Stack end @ 0x%lx\n", addr);

    // Grow the stack
    info->regs->rsp = addr;


    return 1;

err:
    PRINT_DEBUG("ERROR: Failed to build NtCreateProcessEx stack\n");
    return 0;
}





/*
    Create stack to call NtCreateProcessEx

    NTSTATUS WINAPI NtQueryInformationProcess(
      _In_      HANDLE           ProcessHandle,
      _In_      PROCESSINFOCLASS ProcessInformationClass,
      _Out_     PVOID            ProcessInformation,
      _In_      ULONG            ProcessInformationLength,
      _Out_opt_ PULONG           ReturnLength
    );

    Example:

    status = NtQueryInformationProcess(
            hProcess,
            ProcessBasicInformation,
            &pi,
            sizeof(PROCESS_BASIC_INFORMATION),
            &ReturnLength
        );

*/
bool ntqueryinformationprocess_inputs(struct doppelganging* doppelganging, drakvuf_trap_info_t* info)
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

    PRINT_DEBUG(">>>> NtQueryInformationProcess stack\n");

    // get Stack Base
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKBASE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_base))
        goto err;

    // get Stack Limit
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKLIMIT];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_limit))
        goto err;

    PRINT_DEBUG("Stack Base:  0x%lx\n", stack_base);
    PRINT_DEBUG("Stack Limit: 0x%lx\n", stack_limit);

    // Push input arguments on the stack
    uint64_t nul64 = 0;

    // stack start here
    addr_t addr = rsp;
    PRINT_DEBUG("Stack start @ 0x%lx\n", addr);


    // the stack has to be alligned to 0x8
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;


    // process_basic_information var on stack
    struct process_basic_information pbi;
    memset(&pbi, 0, sizeof(struct process_basic_information));

    size_t len = sizeof(struct process_basic_information);
    addr -= len;
    doppelganging->pbi_ptr = addr;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write(vmi, &ctx, len, &pbi, NULL))
        goto err;
    PRINT_DEBUG("- Var. pbi_ptr @ 0x%lx\n", doppelganging->pbi_ptr);


    // PULONG ReturnLength on stack
    addr -= 0x8;
    ctx.addr = addr;
    addr_t ReturnLength = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;



    //http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
    //
    //First 4 parameters to functions are always passed in registers
    //P1=rcx, P2=rdx, P3=r8, P4=r9
    //5th parameter onwards (if any) passed via the stack


    // p5 
    // _Out_opt_ PULONG ReturnLength
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &ReturnLength))
        goto err;
    PRINT_DEBUG("p5: 0x%lx\n", ReturnLength);


    // WARNING: allocate MIN 0x20 "homing space" on stack or call will crash
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;



    // p1: _In_ HANDLE ProcessHandle
    info->regs->rcx = doppelganging->hProcess;
    PRINT_DEBUG("p1: 0x%lx\n", info->regs->rcx);

    // p2: _In_ PROCESSINFOCLASS ProcessInformationClass,
    // #define ProcessBasicInformation 0
    uint64_t k_ProcessBasicInformation = 0;
    info->regs->rdx = k_ProcessBasicInformation;
    PRINT_DEBUG("p2: 0x%lx\n", info->regs->rdx);

    // p3: _Out_ PVOID ProcessInformation
    info->regs->r8 = doppelganging->pbi_ptr;
    PRINT_DEBUG("p3: 0x%lx\n", info->regs->r8);

    // p4: _In_ ULONG ProcessInformationLength,
    // GetCurrentProcess() pseudo handle
    info->regs->r9 = sizeof(struct process_basic_information);
    PRINT_DEBUG("p4: 0x%lx\n", info->regs->r9);


    // save the return address
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
        goto err;

    PRINT_DEBUG("Stack end @ 0x%lx\n", addr);

    // Grow the stack
    info->regs->rsp = addr;


    return 1;

err:
    PRINT_DEBUG("ERROR: Failed to build NtQueryInformationProcess stack\n");
    return 0;
}




/*
    Create stack to call RtlInitUnicodeString

    VOID WINAPI RtlInitUnicodeString(
      _Inout_  PUNICODE_STRING DestinationString,
      _In_opt_ PCWSTR          SourceString
    );

    Example:

    UNICODE_STRING uTargetPath = { 0 };
    RtlInitUnicodeString(&uTargetPath , targetPath);
*/
bool rtlinitunicodestring_inputs(struct doppelganging* doppelganging, drakvuf_trap_info_t* info, const char* sourceString)
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

    PRINT_DEBUG(">>>> RtlInitUnicodeString stack\n");

    // get Stack Base
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKBASE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_base))
        goto err;

    // get Stack Limit
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKLIMIT];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_limit))
        goto err;

    PRINT_DEBUG("Stack Base:  0x%lx\n", stack_base);
    PRINT_DEBUG("Stack Limit: 0x%lx\n", stack_limit);


    // Push input arguments on the stack
    uint8_t nul8 = 0;
    uint64_t nul64 = 0;

    // stack start here
    addr_t addr = rsp;
    PRINT_DEBUG("Stack start @ 0x%lx\n", addr);


    // the stack has to be alligned to 0x8
    // we just going to null out that extra space fully
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;


    // pointer to unicodeDestString
    addr -= 0x8;
    doppelganging->unicodeDestString_ptr = addr;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;
    PRINT_DEBUG("- Var. unicodeDestString_ptr @ 0x%lx\n", doppelganging->unicodeDestString_ptr);


    // sourceString string (it has to be aligned as well)
    addr_t sourceString_addr;
    size_t len = strlen(sourceString);
    addr -= len + 0x8 - (len % 0x8);
    sourceString_addr = addr;                // string address
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write(vmi, &ctx, len, (void*) sourceString, NULL))
        goto err;
    // add null termination
    ctx.addr = addr + len;
    if (VMI_FAILURE == vmi_write_8(vmi, &ctx, &nul8))
        goto err;
    PRINT_DEBUG("- Var. sourceString (string): %s (len 0x%lx) @ 0x%lx\n", sourceString, len, sourceString_addr);


    //http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
    //
    //First 4 parameters to functions are always passed in registers
    //P1=rcx, P2=rdx, P3=r8, P4=r9
    //5th parameter onwards (if any) passed via the stack

    // WARNING: allocate MIN 0x20 "homing space" on stack or call will crash
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;


    //p1: _Inout_ PUNICODE_STRING DestinationString
    info->regs->rcx = doppelganging->unicodeDestString_ptr;
    PRINT_DEBUG("p1: 0x%lx\n", info->regs->rcx);

    //p2: _In_opt_ PCWSTR SourceString
    info->regs->rdx = sourceString_addr;
    PRINT_DEBUG("p2: 0x%lx\n", info->regs->rdx);

/*    
    //p3
    info->regs->r8 = 0;
    //p4
    info->regs->r9 = 0;
*/
    
    // save the return address
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
        goto err;

    PRINT_DEBUG("Stack end @ 0x%lx\n", addr);

    // Grow the stack
    info->regs->rsp = addr;


    return 1;

err:
    PRINT_DEBUG("ERROR: Failed to build RtlInitUnicodeString stack\n");
    return 0;
}





/*
    Create stack to call RtlCreateProcessParametersEx

    NTSTATUS
    RtlCreateProcessParametersEx(
        _Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
        _In_ PUNICODE_STRING ImagePathName,
        _In_opt_ PUNICODE_STRING DllPath,
        _In_opt_ PUNICODE_STRING CurrentDirectory,
        _In_opt_ PUNICODE_STRING CommandLine,
        _In_opt_ PVOID Environment,
        _In_opt_ PUNICODE_STRING WindowTitle,
        _In_opt_ PUNICODE_STRING DesktopInfo,
        _In_opt_ PUNICODE_STRING ShellInfo,
        _In_opt_ PUNICODE_STRING RuntimeData,
        _In_ ULONG Flags // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
        );


    Example:

    PRTL_USER_PROCESS_PARAMETERS params  = nullptr;
    NTSTATUS status = RtlCreateProcessParametersEx(
        &params,
        (PUNICODE_STRING) &uTargetPath,
        (PUNICODE_STRING) &uDllDir,
        (PUNICODE_STRING) &uCurrentDir,
        (PUNICODE_STRING) &uTargetPath,
        nullptr,
        (PUNICODE_STRING) &uWindowName,
        nullptr,
        nullptr,
        nullptr,
        RTL_USER_PROC_PARAMS_NORMALIZED
    );
*/
bool rtlcreateprocessparametersex_inputs(struct doppelganging* doppelganging, drakvuf_trap_info_t* info)
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

    PRINT_DEBUG(">>>> RtlCreateProcessParametersEx stack\n");

    // get Stack Base
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKBASE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_base))
        goto err;

    // get Stack Limit
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKLIMIT];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_limit))
        goto err;

    PRINT_DEBUG("Stack Base:  0x%lx\n", stack_base);
    PRINT_DEBUG("Stack Limit: 0x%lx\n", stack_limit);

    // Push input arguments on the stack
    uint64_t nul64 = 0;

    // stack start here
    addr_t addr = rsp;
    PRINT_DEBUG("Stack start @ 0x%lx\n", addr);


    // the stack has to be alligned to 0x8
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;


    // rtl_user_process_parameters var on stack
    rtl_user_process_parameters_t params;
    memset(&params, 0, sizeof(rtl_user_process_parameters_t));

    size_t len = sizeof(rtl_user_process_parameters_t);
    addr -= len;
    doppelganging->procparams_ptr = addr;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write(vmi, &ctx, len, &params, NULL))
        goto err;
    PRINT_DEBUG("- Var. procparams_ptr @ 0x%lx\n", doppelganging->procparams_ptr);


    // pointer to procparams_ptr on stack
    addr -= 0x8;
    doppelganging->procparams_ptr_ptr = addr;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &doppelganging->procparams_ptr))
        goto err;


    //http://www.codemachine.com/presentations/GES2010.TRoy.Slides.pdf
    //
    //First 4 parameters to functions are always passed in registers
    //P1=rcx, P2=rdx, P3=r8, P4=r9
    //5th parameter onwards (if any) passed via the stack

    // p11
    // _In_ ULONG Flags
    // #define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001
    uint64_t k_RTL_USER_PROC_PARAMS_NORMALIZED = 0x00000001;
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &k_RTL_USER_PROC_PARAMS_NORMALIZED))
        goto err;
    PRINT_DEBUG("p11: 0x%lx\n", k_RTL_USER_PROC_PARAMS_NORMALIZED);

    // p10
    // _In_opt_ PUNICODE_STRING RuntimeData
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;
    PRINT_DEBUG("p10: 0x%lx\n", nul64);

    // p9
    // _In_opt_ PUNICODE_STRING ShellInfo
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;
    PRINT_DEBUG("p9: 0x%lx\n", nul64);

    // p8
    // _In_opt_ PUNICODE_STRING DesktopInfo
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;
    PRINT_DEBUG("p8: 0x%lx\n", nul64);

    // p7
    // _In_opt_ PUNICODE_STRING WindowTitle
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;
    PRINT_DEBUG("p7: 0x%lx\n", nul64);

    // p6
    // _In_opt_ PVOID Environment
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;
    PRINT_DEBUG("p6: 0x%lx\n", nul64);

    // p5
    // _In_opt_ PUNICODE_STRING CommandLine
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &doppelganging->local_proc_image_ptr))
        goto err;
    PRINT_DEBUG("p5: 0x%lx\n", doppelganging->local_proc_image_ptr);


    // WARNING: allocate MIN 0x20 "homing space" on stack or call will crash
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;

    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
        goto err;


    // p1: _Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters
    info->regs->rcx = doppelganging->procparams_ptr_ptr;
    PRINT_DEBUG("p1: 0x%lx\n", info->regs->rcx);

    // p2: _In_ PUNICODE_STRING ImagePathName
    info->regs->rdx = doppelganging->local_proc_image_ptr;
    PRINT_DEBUG("p2: 0x%lx\n", info->regs->rdx);

    // p3: _In_opt_ PUNICODE_STRING DllPath
    info->regs->r8 = doppelganging->local_proc_dll_ptr;
    PRINT_DEBUG("p3: 0x%lx\n", info->regs->r8);

    // p4: _In_opt_ PUNICODE_STRING CurrentDirectory
    info->regs->r9 = doppelganging->local_proc_currdir_ptr;
    PRINT_DEBUG("p4: 0x%lx\n", info->regs->r9);


    // save the return address
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
        goto err;

    PRINT_DEBUG("Stack end @ 0x%lx\n", addr);

    // Grow the stack
    info->regs->rsp = addr;


    return 1;

err:
    PRINT_DEBUG("ERROR: Failed to build RtlCreateProcessParametersEx stack\n");
    return 0;
}




/*
    Create stack to call GetLastError

    DWORD WINAPI GetLastError(void);
*/
bool getlasterror_inputs(struct doppelganging* doppelganging, drakvuf_trap_info_t* info)
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

    PRINT_DEBUG(">>>> GetLastError stack\n");

    // get Stack Base
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKBASE];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_base))
        goto err;

    // get Stack Limit
    ctx.addr = fsgs + doppelganging->offsets[NT_TIB_STACKLIMIT];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &stack_limit))
        goto err;

    PRINT_DEBUG("Stack Base:  0x%lx\n", stack_base);
    PRINT_DEBUG("Stack Limit: 0x%lx\n", stack_limit);

    // stack start here
    addr_t addr = rsp;
    PRINT_DEBUG("Stack start @ 0x%lx\n", addr);


    // save the return address
    addr -= 0x8;
    ctx.addr = addr;
    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
        goto err;

    PRINT_DEBUG("Stack end @ 0x%lx\n", addr);

    // Grow the stack
    info->regs->rsp = addr;


    return 1;

err:
    PRINT_DEBUG("ERROR: Failed to build GetLastError stack\n");
    return 0;
}





// Read HOST file to get buffer to inject
bool readhostfile(struct doppelganging* doppelganging)
{
    int hfile_fd = 0;

    doppelganging->hostfile_len = 0;
    doppelganging->hostfile_buffer = NULL;

    // open host file to inject
    hfile_fd = open(doppelganging->host_file, O_RDONLY);
    if ( hfile_fd < 0 )
    {
        PRINT_DEBUG("Failed to open host file\n");
        goto err;
    }

    struct stat hfile_info;
    if ( stat(doppelganging->host_file, &hfile_info) < 0 )
    {
        PRINT_DEBUG("Failed retrieving information about host file\n");
        goto err;
    }

    doppelganging->hostfile_len = hfile_info.st_size;
    if ( doppelganging->hostfile_len <= 0 )
    {
        PRINT_DEBUG("Error, host file size is wrong\n");
        goto err;
    }

    doppelganging->hostfile_buffer = malloc(doppelganging->hostfile_len);
    if ( ! doppelganging->hostfile_buffer )
    {
        PRINT_DEBUG("Failed to malloc host file buffer\n");
        goto err;
    }

    if ( read(hfile_fd, doppelganging->hostfile_buffer, doppelganging->hostfile_len) < doppelganging->hostfile_len )
    {
        PRINT_DEBUG("Failed to read host file\n");
        goto err;
    }
    PRINT_DEBUG("Read 0x%lx bytes from host file %s\n", doppelganging->hostfile_len, doppelganging->host_file);


    close(hfile_fd);

    return 1;

err:
    PRINT_DEBUG("Failed to read host file\n");

    if (hfile_fd)
        close(hfile_fd);

    if (doppelganging->hostfile_buffer)
        free(doppelganging->hostfile_buffer);

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

    // set Context
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = cr3,
    };


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
    {
        PRINT_DEBUG("Skip. Error retriving current TID\n");
        return 0;
    }


    // --- CHAIN #0 ---

    // check current RIP is trapframe breakpoint and check hijacked_status
    if ( doppelganging->hijacked_status == CALL_NONE && 
         info->regs->rip == doppelganging->bp.breakpoint.addr )
    {
        // save all regs (TrapFrame original status)
        memcpy(&doppelganging->saved_regs, info->regs, sizeof(x86_registers_t));

        // === start execution chain ===

        // setup stack for LoadLibrary function call
        if ( !loadlibrary_inputs(doppelganging, info, "ktmw32.dll") )
        {
            PRINT_DEBUG("Error: failed to setup stack for LoadLibrary(KtmW32.dll)\n");
            return 0;
        }
        
        // set next chain RIP: LoadLibrary
        info->regs->rip = doppelganging->loadlibrary;

        // set status to CALL_LOADLIBRARY
        doppelganging->hijacked_status = CALL_LOADLIBRARY;

        // if target thread was not defined, the current one is defined now
        if ( !doppelganging->target_tid )
        {
            doppelganging->target_tid = threadid;
            PRINT_DEBUG("Setting TID=0x%x\n", threadid);
        }

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
    {
        PRINT_DEBUG("Skip Check #1. Status=%d RIP=0x%lx BP=0x%lx TID=0x%x TargetTID=0x%x VCPU=%d\n", 
            doppelganging->hijacked_status, info->regs->rip, doppelganging->bp.breakpoint.addr,
            threadid, doppelganging->target_tid, info->vcpu);
        return 0;
    }


    // --- CHAIN #1 ---
    // check status is: "waiting for LoadLibrary return"
    if ( doppelganging->hijacked_status == CALL_LOADLIBRARY )
    {
        // print LoadLibraryA return code
        PRINT_DEBUG("LoadLibraryA RAX: 0x%lx\n", info->regs->rax);

        // check LoadLibraryA return: fails==NULL
        if (! info->regs->rax) {
            PRINT_DEBUG("Error: LoadLibrary(KtmW32.dll) fails\n");
            return 0;
        }

        // Library ktmw32.dll loaded. Now we can get CreateTransaction address
        doppelganging->createtransaction = drakvuf_exportsym_to_va(doppelganging->drakvuf, doppelganging->eprocess_base, "ktmw32.dll", "CreateTransaction");
        if (!doppelganging->createtransaction)
        {
            PRINT_DEBUG("Failed to get address of ktmw32.dll!CreateTransaction\n");
            return 0;
        }
        PRINT_DEBUG("--> ktmw32.dll!CreateTransaction: 0x%lx\n", doppelganging->createtransaction);

        // === start execution chain ===

        // setup stack for CreateTransaction function call
        if ( !createtransaction_inputs(doppelganging, info) )
        {
            PRINT_DEBUG("Failed to setup stack for CreateTransaction()\n");
            return 0;
        }
        
        // set next chain RIP: CreateTransaction
        info->regs->rip = doppelganging->createtransaction;

        // set status to CALL_CREATETRANSACTION
        doppelganging->hijacked_status = CALL_CREATETRANSACTION;

        // goto next chain: CreateTransaction
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }


    // --- CHAIN #2 ---
    // check status is: "waiting for CreateTransaction return"
    if ( doppelganging->hijacked_status == CALL_CREATETRANSACTION )
    {
        // print CreateTransaction return code
        PRINT_DEBUG("CreateTransaction RAX: 0x%lx\n", info->regs->rax);

        // check CreateTransaction return: fails==INVALID_HANDLE_VALUE (-1)
        if (info->regs->rax == 0xffffffffffffffff) {
            PRINT_DEBUG("Error: CreateTransaction() fails\n");
            return 0;
        }

        // save HANDLE returned by CreateTransaction
        doppelganging->hTransaction = info->regs->rax;

        // === start execution chain ===

        // setup stack for CreateFileTransacted function call
        if ( !createfiletransacted_inputs(doppelganging, info) )
        {
            PRINT_DEBUG("Failed to setup stack for CreateFileTransacted()\n");
            return 0;
        }
        
        // set next chain RIP: CreateFileTransacted
        info->regs->rip = doppelganging->createfiletransacted;

        // set status to CALL_CREATEFILETRANSACTED
        doppelganging->hijacked_status = CALL_CREATEFILETRANSACTED;

        // goto next chain: CreateFileTransacted
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }



    // --- CHAIN #3 ---
    // check status is: "waiting for CreateFileTransacted return"
    if ( doppelganging->hijacked_status == CALL_CREATEFILETRANSACTED )
    {
        // print CreateFileTransacted return code
        PRINT_DEBUG("CreateFileTransacted RAX: 0x%lx\n", info->regs->rax);

        // check CreateFileTransacted return: fails==INVALID_HANDLE_VALUE (-1)
        if (info->regs->rax == 0xffffffffffffffff) {
            PRINT_DEBUG("Error: CreateFileTransacted() fails\n");
            return 0;
        }

        // save HANDLE returned by CreateFileTransacted
        doppelganging->hTransactedFile = info->regs->rax;

        // === read host file ===

        if ( !readhostfile(doppelganging) )
        {
            PRINT_DEBUG("Failed to read host file\n");
            return 0;
        }


        // === start execution chain ===

        // setup stack for VirtualAlloc function call
        if ( !virtualalloc_inputs(doppelganging, info) )
        {
            PRINT_DEBUG("Failed to setup stack for VirtualAlloc()\n");
            return 0;
        }

        // set next chain RIP: VirtualAlloc
        info->regs->rip = doppelganging->virtualalloc;

        // set status to CALL_VIRTUALALLOC
        doppelganging->hijacked_status = CALL_VIRTUALALLOC;

        // goto next chain: VirtualAlloc
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }


    // --- CHAIN #4 ---
    // check status is: "waiting for VirtualAlloc return"
    if ( doppelganging->hijacked_status == CALL_VIRTUALALLOC )
    {
        // print VirtualAlloc return code
        PRINT_DEBUG("VirtualAlloc RAX: 0x%lx\n", info->regs->rax);

        // check VirtualAlloc return: fails==NULL
        if (! info->regs->rax) {
            PRINT_DEBUG("Error: VirtualAlloc() fails\n");
            return 0;
        }

        // save address returned by VirtualAlloc
        doppelganging->guestfile_buffer = info->regs->rax;


        // === start execution chain ===

        // setup stack for RtlZeroMemory function call
        if ( !rtlzeromemory_inputs(doppelganging, info) )
        {
            PRINT_DEBUG("Failed to setup stack for RtlZeroMemory()\n");
            return 0;
        }

        // set next chain RIP: RtlZeroMemory
        info->regs->rip = doppelganging->rtlzeromemory;

        // set status to CALL_RTLZEROMEMORY
        doppelganging->hijacked_status = CALL_RTLZEROMEMORY;

        // goto next chain: RtlZeroMemory
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }



    // --- CHAIN #5 ---
    // check status is: "waiting for RtlZeroMemory return"
    if ( doppelganging->hijacked_status == CALL_RTLZEROMEMORY )
    {
        // print RtlZeroMemory return code
        PRINT_DEBUG("RtlZeroMemory RAX: 0x%lx\n", info->regs->rax);


        // === write to guest buffer ===

        // write host file buffer to process userspace buffer
        ctx.addr = doppelganging->guestfile_buffer;
        if (VMI_FAILURE == vmi_write(doppelganging->vmi, &ctx, doppelganging->hostfile_len, (void*) doppelganging->hostfile_buffer, NULL)) {
            PRINT_DEBUG("Failed to write host file buffer to process userspace buffer\n");
            return 0;
        }
        PRINT_DEBUG("Copied host buffer (len 0x%lx) to process userspace memory @ 0x%lx\n", doppelganging->hostfile_len, doppelganging->guestfile_buffer);



        // === start execution chain ===

        // setup stack for WriteFile function call
        if ( !writefile_inputs(doppelganging, info) )
        {
            PRINT_DEBUG("Failed to setup stack for WriteFile()\n");
            return 0;
        }

        // set next chain RIP: WriteFile
        info->regs->rip = doppelganging->writefile;

        // set status to CALL_WRITEFILE
        doppelganging->hijacked_status = CALL_WRITEFILE;

        // goto next chain: WriteFile
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }


    // --- CHAIN #6 ---
    // check status is: "waiting for WriteFile return"
    if ( doppelganging->hijacked_status == CALL_WRITEFILE )
    {
        // print WriteFile return code
        PRINT_DEBUG("WriteFile RAX: 0x%lx\n", info->regs->rax);

        // check WriteFile return: fails==NULL
        if (! info->regs->rax) {
            PRINT_DEBUG("Error: WriteFile() fails\n");
            return 0;
        }

        // check WriteFile() bytes written
        uint32_t bytesWritten = 0;
        ctx.addr = doppelganging->dwBytesWritten;
        if ( VMI_FAILURE == vmi_read_32(doppelganging->vmi, &ctx, &bytesWritten) ) {
            PRINT_DEBUG("Error vmi_reading dwBytesWritten\n");
            return 0;
        }
        PRINT_DEBUG("dwBytesWritten: 0x%x\n", bytesWritten);

        if ( bytesWritten < doppelganging->hostfile_len ) {
            PRINT_DEBUG("Error: WriteFile() dwBytesWritten is less than buffer len\n");
            return 0;
        }


        // === start execution chain ===

        // setup stack for NtCreateSection function call
        if ( !ntcreatesection_inputs(doppelganging, info) )
        {
            PRINT_DEBUG("Failed to setup stack for NtCreateSection()\n");
            return 0;
        }

        // set next chain RIP: NtCreateSection
        info->regs->rip = doppelganging->ntcreatesection;

        // set status to CALL_NTCREATESECTION
        doppelganging->hijacked_status = CALL_NTCREATESECTION;

        // goto next chain: NtCreateSection
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }


    // --- CHAIN #7 ---
    // check status is: "waiting for NtCreateSection return"
    if ( doppelganging->hijacked_status == CALL_NTCREATESECTION )
    {
        // print NtCreateSection return code
        PRINT_DEBUG("NtCreateSection RAX: 0x%lx\n", info->regs->rax);

        // check NtCreateSection return: fails!=STATUS_SUCCESS 0x00
        if (info->regs->rax) {
            PRINT_DEBUG("Error: NtCreateSection() fails\n");
            return 0;
        }


        // retrive "hSection" HANDLE written by NtCreateSection
        doppelganging->hSection = 0;
        ctx.addr = doppelganging->hSection_ptr;
        if ( VMI_FAILURE == vmi_read_64(doppelganging->vmi, &ctx, &doppelganging->hSection) ) {
            PRINT_DEBUG("Error vmi_reading hSection_ptr\n");
            return 0;
        }
        PRINT_DEBUG("hSection: 0x%lx\n", doppelganging->hSection);


        // === start execution chain ===

        // setup stack for NtCreateProcessEx function call
        if ( !ntcreateprocessex_inputs(doppelganging, info) )
        {
            PRINT_DEBUG("Failed to setup stack for NtCreateProcessEx()\n");
            return 0;
        }

        // set next chain RIP: NtCreateProcessEx
        info->regs->rip = doppelganging->ntcreateprocessex;

        // set status to CALL_NTCREATEPROCESSEX
        doppelganging->hijacked_status = CALL_NTCREATEPROCESSEX;

        // goto next chain: NtCreateProcessEx
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }


    // --- CHAIN #8 ---
    // check status is: "waiting for NtCreateProcessEx return"
    if ( doppelganging->hijacked_status == CALL_NTCREATEPROCESSEX )
    {
        // print NtCreateProcessEx return code
        PRINT_DEBUG("NtCreateProcessEx RAX: 0x%lx\n", info->regs->rax);

        // check NtCreateProcessEx return: fails!=STATUS_SUCCESS 0x00
        if (info->regs->rax) {
            PRINT_DEBUG("Error: NtCreateProcessEx() fails\n");
            return 0;
        }


        // retrive "hProcess" HANDLE written by NtCreateProcessEx
        doppelganging->hProcess = 0;
        ctx.addr = doppelganging->hProcess_ptr;
        if ( VMI_FAILURE == vmi_read_64(doppelganging->vmi, &ctx, &doppelganging->hProcess) ) {
            PRINT_DEBUG("Error vmi_reading hProcess_ptr\n");
            return 0;
        }
        PRINT_DEBUG("hProcess: 0x%lx\n", doppelganging->hProcess);



        // === get Address Entry Point ===

        // get IMAGE_DOS_HEADER
        struct image_dos_header *pdoshdr_buffer = (struct image_dos_header *)doppelganging->hostfile_buffer;
        PRINT_DEBUG("buffer IMAGE_DOS_HEADER->e_magic: 0x%x\n", pdoshdr_buffer->e_magic);

        // get IMAGE_NT_HEADERS64
        struct image_nt_headers64 *pimgnthdr_buffer = (struct image_nt_headers64 *)(doppelganging->hostfile_buffer + pdoshdr_buffer->e_lfanew);
        PRINT_DEBUG("buffer IMAGE_NT_HEADERS64->Signature: 0x%x\n", pimgnthdr_buffer->Signature);

        // get AddressOfEntryPoint
        doppelganging->proc_entry = (uint64_t) pimgnthdr_buffer->OptionalHeader.AddressOfEntryPoint;
        PRINT_DEBUG("buffer IMAGE_NT_HEADERS64->OptionalHeader->AddressOfEntryPoint: 0x%x\n", pimgnthdr_buffer->OptionalHeader.AddressOfEntryPoint);


/*
        // I need to retrive ImageBaseAddress of new process
        PROCESS_BASIC_INFORMATION pi = { 0 };
        DWORD ReturnLength = 0;
        status = NtQueryInformationProcess(
            hProcess,
            ProcessBasicInformation,
            &pi,
            sizeof(PROCESS_BASIC_INFORMATION),
            &ReturnLength
        );
        if (status != STATUS_SUCCESS) {
            ERROR
        }
        // here I get PEB of process (vmi_read it)
        PPEB remote_peb_addr = pi.PebBaseAddress;

        // inside PEB there is the value I need: ImageBaseAddress
*/


        // === start execution chain ===

        // setup stack for NtQueryInformationProcess function call
        if ( !ntqueryinformationprocess_inputs(doppelganging, info) )
        {
            PRINT_DEBUG("Failed to setup stack for NtQueryInformationProcess()\n");
            return 0;
        }

        // set next chain RIP: NtQueryInformationProcess
        info->regs->rip = doppelganging->ntqueryinformationprocess;

        // set status to CALL_NTQUERYINFORMATIONPROCESS
        doppelganging->hijacked_status = CALL_NTQUERYINFORMATIONPROCESS;

        // goto next chain: NtQueryInformationProcess
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }


    // --- CHAIN #9 ---
    // check status is: "waiting for NtQueryInformationProcess return"
    if ( doppelganging->hijacked_status == CALL_NTQUERYINFORMATIONPROCESS )
    {
        // print NtQueryInformationProcess return code
        PRINT_DEBUG("NtQueryInformationProcess RAX: 0x%lx\n", info->regs->rax);

        // check NtQueryInformationProcess return: fails!=STATUS_SUCCESS 0x00
        if (info->regs->rax) {
            PRINT_DEBUG("Error: NtQueryInformationProcess() fails\n");
            return 0;
        }


        memset(&doppelganging->pbi, 0, sizeof(struct process_basic_information));
        ctx.addr = doppelganging->pbi_ptr;
        if ( VMI_FAILURE == vmi_read(doppelganging->vmi, &ctx, sizeof(struct process_basic_information), &doppelganging->pbi, NULL) ) {
            PRINT_DEBUG("Error vmi_reading pbi_ptr\n");
            return 0;
        }
        PRINT_DEBUG("PebBaseAddress: 0x%lx\n", doppelganging->pbi.PebBaseAddress);
        PRINT_DEBUG("UniqueProcessId: 0x%lx\n", doppelganging->pbi.UniqueProcessId);



        // new process context
        access_context_t newctx = {
            .translate_mechanism = VMI_TM_PROCESS_PID,
            .addr = doppelganging->pbi.PebBaseAddress + doppelganging->offsets[PEB_IMAGEBASADDRESS],
            .pid = doppelganging->pbi.UniqueProcessId
        };

        addr_t image_base_address = 0;
        if (VMI_FAILURE == vmi_read_addr(doppelganging->vmi, &newctx, &image_base_address)) {
            PRINT_DEBUG("Failed to get ImageBaseAddress from PEB\n");
            return 0;
        }
        PRINT_DEBUG("ImageBaseAddress: 0x%lx\n", image_base_address);

        doppelganging->proc_entry = doppelganging->proc_entry + image_base_address;
        PRINT_DEBUG("proc_entry: 0x%lx\n", doppelganging->proc_entry);


        // === start execution chain ===

        char* local_proc_image = strdup(doppelganging->local_proc);
        local_proc_image = getImageFromPath(local_proc_image);
        PRINT_DEBUG("Extract Image from local_proc path: %s\n", local_proc_image);

        // setup stack for RtlInitUnicodeString function call
        if ( !rtlinitunicodestring_inputs(doppelganging, info, local_proc_image) )
        {
            PRINT_DEBUG("Failed to setup stack for RtlInitUnicodeString()\n");
            return 0;
        }

        // set next chain RIP: RtlInitUnicodeString
        info->regs->rip = doppelganging->rtlinitunicodestring;

        // set status to CALL_RTLINITUNICODESTRING_IMAGE
        doppelganging->hijacked_status = CALL_RTLINITUNICODESTRING_IMAGE;

        // goto next chain: RtlInitUnicodeString
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }



    // --- CHAIN #10 ---
    // check status is: "waiting for RtlInitUnicodeString return"
    if ( doppelganging->hijacked_status == CALL_RTLINITUNICODESTRING_IMAGE )
    {
        // print RtlInitUnicodeString return code
        PRINT_DEBUG("RtlInitUnicodeString RAX: 0x%lx\n", info->regs->rax);

        // check RtlInitUnicodeString return: fails!=STATUS_SUCCESS 0x00
        if (info->regs->rax) {
            PRINT_DEBUG("Error: RtlInitUnicodeString() fails\n");
            return 0;
        }


        // save "unicodeDestString" pointer written by RtlInitUnicodeString
        doppelganging->local_proc_image_ptr = doppelganging->unicodeDestString_ptr;
        PRINT_DEBUG("local_proc_image_ptr: 0x%lx\n", doppelganging->local_proc_image_ptr);


        // === start execution chain ===

        char* local_proc_currdir = strdup(doppelganging->local_proc);
        stripPathToDir(local_proc_currdir);
        PRINT_DEBUG("Extract directory from local_proc path: %s\n", local_proc_currdir);

        // setup stack for RtlInitUnicodeString function call
        if ( !rtlinitunicodestring_inputs(doppelganging, info, local_proc_currdir) )
        {
            PRINT_DEBUG("Failed to setup stack for RtlInitUnicodeString()\n");
            return 0;
        }

        // set next chain RIP: RtlInitUnicodeString
        info->regs->rip = doppelganging->rtlinitunicodestring;

        // set status to CALL_RTLINITUNICODESTRING_CURRDIR
        doppelganging->hijacked_status = CALL_RTLINITUNICODESTRING_CURRDIR;

        // goto next chain: RtlInitUnicodeString
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }



    // --- CHAIN #11 ---
    // check status is: "waiting for RtlInitUnicodeString return"
    if ( doppelganging->hijacked_status == CALL_RTLINITUNICODESTRING_CURRDIR )
    {
        // print RtlInitUnicodeString return code
        PRINT_DEBUG("RtlInitUnicodeString RAX: 0x%lx\n", info->regs->rax);

        // check RtlInitUnicodeString return: fails!=STATUS_SUCCESS 0x00
        if (info->regs->rax) {
            PRINT_DEBUG("Error: RtlInitUnicodeString() fails\n");
            return 0;
        }


        // save "unicodeDestString" pointer written by RtlInitUnicodeString
        doppelganging->local_proc_currdir_ptr = doppelganging->unicodeDestString_ptr;
        PRINT_DEBUG("local_proc_currdir_ptr: 0x%lx\n", doppelganging->local_proc_currdir_ptr);


        // === start execution chain ===

        char local_proc_dll[] = "C:\\Windows\\System32";
        PRINT_DEBUG("local_proc_dll path: %s\n", local_proc_dll);

        // setup stack for RtlInitUnicodeString function call
        if ( !rtlinitunicodestring_inputs(doppelganging, info, local_proc_dll) )
        {
            PRINT_DEBUG("Failed to setup stack for RtlInitUnicodeString()\n");
            return 0;
        }

        // set next chain RIP: RtlInitUnicodeString
        info->regs->rip = doppelganging->rtlinitunicodestring;

        // set status to CALL_RTLINITUNICODESTRING_DLL
        doppelganging->hijacked_status = CALL_RTLINITUNICODESTRING_DLL;

        // goto next chain: RtlInitUnicodeString
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }



    // --- CHAIN #12 ---
    // check status is: "waiting for RtlInitUnicodeString return"
    if ( doppelganging->hijacked_status == CALL_RTLINITUNICODESTRING_DLL )
    {
        // print RtlInitUnicodeString return code
        PRINT_DEBUG("RtlInitUnicodeString RAX: 0x%lx\n", info->regs->rax);

        // check RtlInitUnicodeString return: fails!=STATUS_SUCCESS 0x00
        if (info->regs->rax) {
            PRINT_DEBUG("Error: RtlInitUnicodeString() fails\n");
            return 0;
        }


        // save "unicodeDestString" pointer written by RtlInitUnicodeString
        doppelganging->local_proc_dll_ptr = doppelganging->unicodeDestString_ptr;
        PRINT_DEBUG("local_proc_dll_ptr: 0x%lx\n", doppelganging->local_proc_dll_ptr);


        // === start execution chain ===

        // setup stack for RtlCreateProcessParametersEx function call
        if ( !rtlcreateprocessparametersex_inputs(doppelganging, info) )
        {
            PRINT_DEBUG("Failed to setup stack for RtlCreateProcessParametersEx()\n");
            return 0;
        }

        // set next chain RIP: RtlCreateProcessParametersEx
        info->regs->rip = doppelganging->rtlcreateprocessparametersex;

        // set status to CALL_RTLCREATEPROCESSPARAMETERSEX
        doppelganging->hijacked_status = CALL_RTLCREATEPROCESSPARAMETERSEX;

        // goto next chain: RtlCreateProcessParametersEx
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }


    // --- CHAIN #13 ---
    // check status is: "waiting for RtlCreateProcessParametersEx return"
    if ( doppelganging->hijacked_status == CALL_RTLCREATEPROCESSPARAMETERSEX )
    {
        // print RtlCreateProcessParametersEx return code
        PRINT_DEBUG("RtlCreateProcessParametersEx RAX: 0x%lx\n", info->regs->rax);

        // check RtlCreateProcessParametersEx return: fails!=STATUS_SUCCESS 0x00
        if (info->regs->rax) {
            PRINT_DEBUG("Error: RtlCreateProcessParametersEx() fails\n");
            return 0;
        }

/*
        // === start execution chain ===

        // setup stack for RtlCreateProcessParametersEx function call
        if ( !rtlcreateprocessparametersex_inputs(doppelganging, info) )
        {
            PRINT_DEBUG("Failed to setup stack for RtlCreateProcessParametersEx()\n");
            return 0;
        }

        // set next chain RIP: RtlCreateProcessParametersEx
        info->regs->rip = doppelganging->rtlcreateprocessparametersex;

        // set status to CALL_RTLCREATEPROCESSPARAMETERSEX
        doppelganging->hijacked_status = CALL_RTLCREATEPROCESSPARAMETERSEX;

        // goto next chain: RtlCreateProcessParametersEx
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
*/        
    }





/* Call to be used in case of fails: GetLastError()
    // --- CHAIN #FAILS ---
    // check current RIP is trapframe breakpoint and check hijacked_status
    if ( doppelganging->hijacked_status == CALL_CREATEFILETRANSACTED && 
         info->regs->rax == 0xffffffffffffffff )
    {
        // print CreateTransaction return code
        PRINT_DEBUG("CreateFileTransacted RAX: 0x%lx\n", info->regs->rax);

        // === start execution chain ===

        // setup stack for GetLastError function call
        if ( !getlasterror_inputs(doppelganging, info) )
        {
            PRINT_DEBUG("Failed to setup stack for GetLastError()\n");
            return 0;
        }
        
        // set next chain RIP: GetLastError
        info->regs->rip = doppelganging->getlasterror;

        // set status to CALL_GETLASTERROR
        doppelganging->hijacked_status = CALL_GETLASTERROR;

        // goto next chain: GetLastError
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }
*/

    // We are now in the return path from latest call

    // remove trapframe breakpoint trap
    drakvuf_interrupt(drakvuf, -1);
    drakvuf_remove_trap(drakvuf, &doppelganging->bp, NULL);


    // print latest call return code
    PRINT_DEBUG("RAX: 0x%lx\n", info->regs->rax);


    // restore all regs and continue execution to trap frame return point
    memcpy(info->regs, &doppelganging->saved_regs, sizeof(x86_registers_t));
    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}



// Doppelganging main
int doppelganging_start_app(drakvuf_t drakvuf, vmi_pid_t pid, uint32_t tid, const char* lproc, const char* hfile)
{
    struct doppelganging doppelganging = { 0 };
    doppelganging.drakvuf = drakvuf;
    doppelganging.vmi = drakvuf_lock_and_get_vmi(drakvuf);
    doppelganging.rekall_profile = drakvuf_get_rekall_profile(drakvuf);
    doppelganging.target_pid = pid;
    doppelganging.target_tid = tid;
    doppelganging.local_proc = lproc;
    doppelganging.host_file = hfile;

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

    PRINT_DEBUG("Target PID %u with DTB 0x%lx to start '%s'\n", pid, doppelganging.target_cr3, hfile);

    // get EPROCESS
    doppelganging.eprocess_base = 0;
    if ( !drakvuf_find_process(doppelganging.drakvuf, pid, NULL, &doppelganging.eprocess_base) )
        goto done;


    // get vaddress of functions to be called

    // CreateProcessA
    doppelganging.createprocessa = drakvuf_exportsym_to_va(doppelganging.drakvuf, doppelganging.eprocess_base, "kernel32.dll", "CreateProcessA");
    if (!doppelganging.createprocessa)
    {
        PRINT_DEBUG("Failed to get address of kernel32.dll!CreateProcessA\n");
        goto done;
    }

    // LoadLibraryA
    doppelganging.loadlibrary = drakvuf_exportsym_to_va(doppelganging.drakvuf, doppelganging.eprocess_base, "kernel32.dll", "LoadLibraryA");
    if (!doppelganging.loadlibrary)
    {
        PRINT_DEBUG("Failed to get address of kernel32.dll!LoadLibraryA\n");
        goto done;
    }
    PRINT_DEBUG("kernel32.dll!LoadLibraryA: 0x%lx\n", doppelganging.loadlibrary);

    // CreateFileTransactedA
    doppelganging.createfiletransacted = drakvuf_exportsym_to_va(doppelganging.drakvuf, doppelganging.eprocess_base, "kernel32.dll", "CreateFileTransactedA");
    if (!doppelganging.createfiletransacted)
    {
        PRINT_DEBUG("Failed to get address of kernel32.dll!CreateFileTransactedA\n");
        goto done;
    }
    PRINT_DEBUG("kernel32.dll!CreateFileTransactedA: 0x%lx\n", doppelganging.createfiletransacted);
 
    // GetLastError
    doppelganging.getlasterror = drakvuf_exportsym_to_va(doppelganging.drakvuf, doppelganging.eprocess_base, "kernel32.dll", "GetLastError");
    if (!doppelganging.getlasterror)
    {
        PRINT_DEBUG("Failed to get address of kernel32.dll!GetLastError\n");
        goto done;
    }
    PRINT_DEBUG("kernel32.dll!GetLastError: 0x%lx\n", doppelganging.getlasterror);

    // VirtualAlloc
    doppelganging.virtualalloc = drakvuf_exportsym_to_va(doppelganging.drakvuf, doppelganging.eprocess_base, "kernel32.dll", "VirtualAlloc");
    if (!doppelganging.virtualalloc)
    {
        PRINT_DEBUG("Failed to get address of kernel32.dll!VirtualAlloc\n");
        goto done;
    }
    PRINT_DEBUG("kernel32.dll!VirtualAlloc: 0x%lx\n", doppelganging.virtualalloc);

    // RtlZeroMemory
    doppelganging.rtlzeromemory = drakvuf_exportsym_to_va(doppelganging.drakvuf, doppelganging.eprocess_base, "ntdll.dll", "RtlZeroMemory");
    if (!doppelganging.rtlzeromemory)
    {
        PRINT_DEBUG("Failed to get address of ntdll.dll!RtlZeroMemory\n");
        goto done;
    }
    PRINT_DEBUG("ntdll.dll!RtlZeroMemory: 0x%lx\n", doppelganging.rtlzeromemory);

    // WriteFile
    doppelganging.writefile = drakvuf_exportsym_to_va(doppelganging.drakvuf, doppelganging.eprocess_base, "kernel32.dll", "WriteFile");
    if (!doppelganging.writefile)
    {
        PRINT_DEBUG("Failed to get address of kernel32.dll!WriteFile\n");
        goto done;
    }
    PRINT_DEBUG("kernel32.dll!WriteFile: 0x%lx\n", doppelganging.writefile);

    // NtCreateSection
    doppelganging.ntcreatesection = drakvuf_exportsym_to_va(doppelganging.drakvuf, doppelganging.eprocess_base, "ntdll.dll", "NtCreateSection");
    if (!doppelganging.ntcreatesection)
    {
        PRINT_DEBUG("Failed to get address of ntdll.dll!NtCreateSection\n");
        goto done;
    }
    PRINT_DEBUG("ntdll.dll!NtCreateSection: 0x%lx\n", doppelganging.ntcreatesection);

    // NtCreateProcessEx
    doppelganging.ntcreateprocessex = drakvuf_exportsym_to_va(doppelganging.drakvuf, doppelganging.eprocess_base, "ntdll.dll", "NtCreateProcessEx");
    if (!doppelganging.ntcreateprocessex)
    {
        PRINT_DEBUG("Failed to get address of ntdll.dll!NtCreateProcessEx\n");
        goto done;
    }
    PRINT_DEBUG("ntdll.dll!NtCreateProcessEx: 0x%lx\n", doppelganging.ntcreateprocessex);

    // NtQueryInformationProcess
    doppelganging.ntqueryinformationprocess = drakvuf_exportsym_to_va(doppelganging.drakvuf, doppelganging.eprocess_base, "ntdll.dll", "NtQueryInformationProcess");
    if (!doppelganging.ntqueryinformationprocess)
    {
        PRINT_DEBUG("Failed to get address of ntdll.dll!NtQueryInformationProcess\n");
        goto done;
    }
    PRINT_DEBUG("ntdll.dll!NtQueryInformationProcess: 0x%lx\n", doppelganging.ntqueryinformationprocess);

    // RtlInitUnicodeString
    doppelganging.rtlinitunicodestring = drakvuf_exportsym_to_va(doppelganging.drakvuf, doppelganging.eprocess_base, "ntdll.dll", "RtlInitUnicodeString");
    if (!doppelganging.rtlinitunicodestring)
    {
        PRINT_DEBUG("Failed to get address of ntdll.dll!RtlInitUnicodeString\n");
        goto done;
    }
    PRINT_DEBUG("ntdll.dll!RtlInitUnicodeString: 0x%lx\n", doppelganging.rtlinitunicodestring);

    // RtlCreateProcessParametersEx
    doppelganging.rtlcreateprocessparametersex = drakvuf_exportsym_to_va(doppelganging.drakvuf, doppelganging.eprocess_base, "ntdll.dll", "RtlCreateProcessParametersEx");
    if (!doppelganging.rtlcreateprocessparametersex)
    {
        PRINT_DEBUG("Failed to get address of ntdll.dll!RtlCreateProcessParametersEx\n");
        goto done;
    }
    PRINT_DEBUG("ntdll.dll!RtlCreateProcessParametersEx: 0x%lx\n", doppelganging.rtlcreateprocessparametersex);


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


    // return status OK
    doppelganging.rc = 1;


    // close, remove traps and release vmi
    drakvuf_pause(drakvuf);
    drakvuf_remove_trap(drakvuf, &doppelganging.cr3_event, NULL);

done:
    PRINT_DEBUG("Finished with injection. Ret: %i\n", doppelganging.rc);
    drakvuf_release_vmi(drakvuf);
    return doppelganging.rc;
}
