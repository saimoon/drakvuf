/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
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

#ifndef LIBDOPPELGANGING_PRIVATE_H
#define LIBDOPPELGANGING_PRIVATE_H

#ifdef DRAKVUF_DEBUG

extern bool verbose;

#define PRINT_DEBUG(args...) \
    do { \
        if(verbose) fprintf (stderr, args); \
    } while (0)

#else
#define PRINT_DEBUG(args...) \
    do {} while(0)
#endif

enum hijacked
{
    CALL_NONE,
    CALL_LOADLIBRARY,
    CALL_CREATETRANSACTION,
    CALL_CREATEFILETRANSACTED,
    CALL_VIRTUALALLOC,
    CALL_RTLZEROMEMORY,
    CALL_WRITEFILE,
    CALL_NTCREATESECTION,
    CALL_NTCREATEPROCESSEX,
    CALL_NTQUERYINFORMATIONPROCESS,
    CALL_RTLINITUNICODESTRING_IMAGE,
    CALL_RTLINITUNICODESTRING_CURRDIR,
    CALL_RTLINITUNICODESTRING_DLL,
    CALL_RTLCREATEPROCESSPARAMETERSEX,
    CALL_VIRTUALALLOCEX,
    CALL_WRITEPROCESSMEMORY,

    CALL_GETLASTERROR,

    CALL_MAX
};

enum offset
{
    NT_TIB_STACKBASE,
    NT_TIB_STACKLIMIT,
    KTHREAD_TRAPFRAME,
    KTRAP_FRAME_RIP,
    PEB_IMAGEBASADDRESS,

    OFFSET_MAX
};

static const char* offset_names[OFFSET_MAX][2] =
{
    [NT_TIB_STACKBASE] = { "_NT_TIB", "StackBase" },
    [NT_TIB_STACKLIMIT] = { "_NT_TIB", "StackLimit" },
    [KTHREAD_TRAPFRAME] = {"_KTHREAD", "TrapFrame" },
    [KTRAP_FRAME_RIP] = {"_KTRAP_FRAME", "Rip" },
    [PEB_IMAGEBASADDRESS] = { "_PEB", "ImageBaseAddress" },
};



// ** PE structs ** //
struct list_entry_64
{
    uint64_t flink;
    uint64_t blink;
} __attribute__ ((packed));


struct image_dos_header {       // IMAGE_DOS_HEADER
    uint16_t   e_magic;                     // Magic number
    uint16_t   e_cblp;                      // Bytes on last page of file
    uint16_t   e_cp;                        // Pages in file
    uint16_t   e_crlc;                      // Relocations
    uint16_t   e_cparhdr;                   // Size of header in paragraphs
    uint16_t   e_minalloc;                  // Minimum extra paragraphs needed
    uint16_t   e_maxalloc;                  // Maximum extra paragraphs needed
    uint16_t   e_ss;                        // Initial (relative) SS value
    uint16_t   e_sp;                        // Initial SP value
    uint16_t   e_csum;                      // Checksum
    uint16_t   e_ip;                        // Initial IP value
    uint16_t   e_cs;                        // Initial (relative) CS value
    uint16_t   e_lfarlc;                    // File address of relocation table
    uint16_t   e_ovno;                      // Overlay number
    uint16_t   e_res[4];                    // Reserved words
    uint16_t   e_oemid;                     // OEM identifier (for e_oeminfo)
    uint16_t   e_oeminfo;                   // OEM information; e_oemid specific
    uint16_t   e_res2[10];                  // Reserved words
    uint32_t   e_lfanew;                    // File address of new exe header
};


#define IMAGE_SIZEOF_SHORT_NAME 8

struct image_section_header {      // IMAGE_SECTION_HEADER
    uint8_t Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct loaded_image {      // LOADED_IMAGE
    addr_t ModuleName;
    addr_t hFile;
    addr_t MappedAddress;
    struct image_nt_headers64 *FileHeader;
    struct image_section_header *LastRvaSection;
    uint32_t NumberOfSections;
    struct image_section_header *Sections;
    uint32_t Characteristics;
    uint8_t fSystemImage;
    uint8_t fDOSImage;
    uint8_t fReadOnly;
    uint8_t Version;
    struct list_entry_64 Links;
    uint32_t SizeOfImage;
};


struct image_file_header {      // IMAGE_FILE_HEADER
    uint16_t Machine;                       // architecture type of the computer
    uint16_t NumberOfSections;              // number of sections
    uint32_t TimeDateStamp;                 // low 32 bits of the time stamp of the image
    uint32_t PointerToSymbolTable;          // offset of the symbol table in bytes
    uint32_t NumberOfSymbols;               // number of symbols in the symbol table
    uint16_t SizeOfOptionalHeader;          // size of the optional header in bytes
    uint16_t Characteristics;               // characteristics of the image
};


#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

struct image_data_directory {       // IMAGE_DATA_DIRECTORY
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct image_optional_header64 {    // IMAGE_OPTIONAL_HEADER64
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    struct image_data_directory DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};


struct image_nt_headers64 {     // IMAGE_NT_HEADERS64
    uint32_t Signature;
    struct image_file_header FileHeader;
    struct image_optional_header64 OptionalHeader;
};




event_response_t dg_int3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
event_response_t dg_cr3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

#endif
