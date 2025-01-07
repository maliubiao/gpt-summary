Response:
My thought process for generating the summary goes like this:

1. **Identify the Core Function:** The filename `linker_phdr.cpp` and the surrounding context (Android Bionic linker) strongly suggest this file is responsible for handling ELF program headers during the dynamic linking process.

2. **Scan for Key Data Structures and Operations:** I quickly scan the code for prominent data structures (like `ElfReader`, `Phdr`), functions operating on them (like `Read`, `Load`, `MapSegment`), and the overall flow.

3. **Focus on the `ElfReader` Class:** The `ElfReader` class seems to encapsulate the core functionality. I note its key member variables and the purpose of its main methods.

4. **Understand the ELF Loading Process (as implemented here):**  The comments and function names reveal a multi-stage process:
    * **Reading:** Parsing the ELF header and program headers from the file.
    * **Verification:** Checking the validity of the ELF structure.
    * **Reservation:**  Allocating virtual address space.
    * **Loading:** Mapping the ELF segments into the reserved memory.

5. **Identify Key Functionalities within `ElfReader`:** I look for specific tasks performed by the class, such as:
    * Reading ELF headers.
    * Verifying ELF headers (magic number, architecture, etc.).
    * Reading and checking program headers (number, size, offset, alignment).
    * Reading section headers.
    * Reading the dynamic section.
    * Calculating the required memory size for loading.
    * Reserving address space using `mmap`.
    * Mapping individual segments using `mmap`.
    * Handling segment alignment and padding.

6. **Connect to Dynamic Linking Concepts:** I relate the functionalities to standard dynamic linking concepts like:
    * Loading shared libraries into memory.
    * Resolving symbols.
    * Handling different ELF sections (like `.dynamic`).
    * Understanding the role of program headers in describing memory layout.

7. **Consider Android-Specific Aspects:** The code mentions Android properties and SDK versions, hinting at Android-specific logic. I note this but defer detailed explanation for later parts of the response.

8. **Formulate a Concise Summary:** Based on the above, I draft a summary that highlights the key responsibilities of the `linker_phdr.cpp` file. I try to use clear and concise language.

9. **Refine the Summary:** I review the summary for clarity and completeness. I ensure it accurately reflects the content of the code snippet. I avoid overly technical jargon where simpler terms suffice. I specifically focus on making it understandable as a "Part 1" summary, setting the stage for more detailed explanations later.

Applying these steps leads to the summary:

* **核心职责：**  `linker_phdr.cpp` 文件的核心职责是解析和加载 ELF (Executable and Linkable Format) 文件中的程序头（Program Header），这是动态链接器加载共享库和可执行文件的关键步骤。

* **`ElfReader` 类：**  该文件定义了一个名为 `ElfReader` 的类，该类封装了读取、验证和加载 ELF 文件的过程。它负责从文件系统中读取 ELF 文件头和程序头表，并进行一系列的校验，以确保文件的有效性。

* **读取和验证 ELF 结构：** `ElfReader` 类包含了读取 ELF 文件头 (`ReadElfHeader`)、程序头 (`ReadProgramHeaders`)、节头 (`ReadSectionHeaders`) 以及动态节 (`ReadDynamicSection`) 的方法。它还会进行各种验证 (`VerifyElfHeader`)，例如检查魔数、文件类型、目标架构等，以确保加载的文件与当前平台兼容。

* **内存布局和地址空间管理：**  该文件中的代码负责计算加载 ELF 文件所需的内存大小 (`phdr_table_get_load_size`)，并使用 `mmap` 系统调用在进程的地址空间中预留相应的空间 (`ReserveAddressSpace`)。 它还处理了共享库加载时的地址对齐 (`CheckProgramHeaderAlignment`, `ReserveWithAlignmentPadding`)，以及可能的地址空间随机化。

* **加载段（Segments）：**  `ElfReader` 类负责根据程序头中的信息，将 ELF 文件中的各个段（Segments）映射到预留的内存空间中 (`LoadSegments`, `MapSegment`)。 这包括设置段的访问权限（读、写、执行）。

* **处理特殊的 Note 段：**  代码中还包含处理 `PT_NOTE` 类型的程序头的逻辑 (`ReadPadSegmentNote`)，特别是用于判断是否需要进行段扩展以优化内存管理的 `NT_ANDROID_TYPE_PAD_SEGMENT` Note。

* **辅助功能：**  该文件还包含一些辅助函数，例如获取目标平台的 ELF Machine 类型 (`GetTargetElfMachine`)，以及一些用于错误处理和调试的宏和函数。

Essentially, I broke down the code into its primary responsibilities and the key class involved, highlighting the actions performed at each stage of the ELF loading process. The summary emphasizes the "what" rather than the "how," as detailed explanations are requested in subsequent parts.
好的，这是对 `bionic/linker/linker_phdr.cpp` 文件第一部分的分析和功能归纳。

**核心职责：**  `linker_phdr.cpp` 文件的核心职责是解析和加载 ELF (Executable and Linkable Format) 文件中的程序头（Program Header），这是动态链接器加载共享库和可执行文件的关键步骤。

**主要功能归纳：**

1. **定义了 `ElfReader` 类:**  该文件定义了一个名为 `ElfReader` 的类，该类封装了读取、验证和加载 ELF 文件的过程。它负责从文件系统中读取 ELF 文件头和程序头表，并进行一系列的校验，以确保文件的有效性。

2. **读取和验证 ELF 结构:** `ElfReader` 类包含了读取 ELF 文件头 (`ReadElfHeader`)、程序头 (`ReadProgramHeaders`)、节头 (`ReadSectionHeaders`) 以及动态节 (`ReadDynamicSection`) 的方法。它还会进行各种验证 (`VerifyElfHeader`)，例如检查魔数、文件类型、目标架构等，以确保加载的文件与当前平台兼容。

3. **内存布局和地址空间管理:**  该文件中的代码负责计算加载 ELF 文件所需的内存大小 (`phdr_table_get_load_size`)，并使用 `mmap` 系统调用在进程的地址空间中预留相应的空间 (`ReserveAddressSpace`)。 它还处理了共享库加载时的地址对齐 (`CheckProgramHeaderAlignment`, `ReserveWithAlignmentPadding`)，以及可能的地址空间随机化。

4. **加载段（Segments）：**  `ElfReader` 类负责根据程序头中的信息，将 ELF 文件中的各个段（Segments）映射到预留的内存空间中 (`LoadSegments`, `MapSegment`)。 这包括设置段的访问权限（读、写、执行）。

5. **处理特殊的 Note 段：**  代码中还包含处理 `PT_NOTE` 类型的程序头的逻辑 (`ReadPadSegmentNote`)，特别是用于判断是否需要进行段扩展以优化内存管理的 `NT_ANDROID_TYPE_PAD_SEGMENT` Note。

6. **辅助功能：**  该文件还包含一些辅助函数，例如获取目标平台的 ELF Machine 类型 (`GetTargetElfMachine`)，以及一些用于错误处理和调试的宏和函数。

**总结来说，`linker_phdr.cpp` 的主要作用是作为动态链接器的一部分，负责读取、解析和初步加载 ELF 文件，为后续的符号解析和重定位等操作奠定基础。它确保了加载的 ELF 文件结构正确，并将其映射到进程的内存空间中。**

接下来，我们期待您提供剩余部分的内容，以便进行更深入的分析。

Prompt: 
```
这是目录为bionic/linker/linker_phdr.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2012 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "linker_phdr.h"

#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "linker.h"
#include "linker_debug.h"
#include "linker_dlwarning.h"
#include "linker_globals.h"
#include "linker_logger.h"
#include "linker_main.h"
#include "linker_soinfo.h"
#include "linker_utils.h"

#include "private/bionic_asm_note.h"
#include "private/CFIShadow.h" // For kLibraryAlignment
#include "private/elf_note.h"

#include <android-base/file.h>
#include <android-base/properties.h>

static int GetTargetElfMachine() {
#if defined(__arm__)
  return EM_ARM;
#elif defined(__aarch64__)
  return EM_AARCH64;
#elif defined(__i386__)
  return EM_386;
#elif defined(__riscv)
  return EM_RISCV;
#elif defined(__x86_64__)
  return EM_X86_64;
#endif
}

/**
  TECHNICAL NOTE ON ELF LOADING.

  An ELF file's program header table contains one or more PT_LOAD
  segments, which corresponds to portions of the file that need to
  be mapped into the process' address space.

  Each loadable segment has the following important properties:

    p_offset  -> segment file offset
    p_filesz  -> segment file size
    p_memsz   -> segment memory size (always >= p_filesz)
    p_vaddr   -> segment's virtual address
    p_flags   -> segment flags (e.g. readable, writable, executable)
    p_align   -> segment's in-memory and in-file alignment

  We will ignore the p_paddr field of ElfW(Phdr) for now.

  The loadable segments can be seen as a list of [p_vaddr ... p_vaddr+p_memsz)
  ranges of virtual addresses. A few rules apply:

  - the virtual address ranges should not overlap.

  - if a segment's p_filesz is smaller than its p_memsz, the extra bytes
    between them should always be initialized to 0.

  - ranges do not necessarily start or end at page boundaries. Two distinct
    segments can have their start and end on the same page. In this case, the
    page inherits the mapping flags of the latter segment.

  Finally, the real load addrs of each segment is not p_vaddr. Instead the
  loader decides where to load the first segment, then will load all others
  relative to the first one to respect the initial range layout.

  For example, consider the following list:

    [ offset:0,      filesz:0x4000, memsz:0x4000, vaddr:0x30000 ],
    [ offset:0x4000, filesz:0x2000, memsz:0x8000, vaddr:0x40000 ],

  This corresponds to two segments that cover these virtual address ranges:

       0x30000...0x34000
       0x40000...0x48000

  If the loader decides to load the first segment at address 0xa0000000
  then the segments' load address ranges will be:

       0xa0030000...0xa0034000
       0xa0040000...0xa0048000

  In other words, all segments must be loaded at an address that has the same
  constant offset from their p_vaddr value. This offset is computed as the
  difference between the first segment's load address, and its p_vaddr value.

  However, in practice, segments do _not_ start at page boundaries. Since we
  can only memory-map at page boundaries, this means that the bias is
  computed as:

       load_bias = phdr0_load_address - page_start(phdr0->p_vaddr)

  (NOTE: The value must be used as a 32-bit unsigned integer, to deal with
          possible wrap around UINT32_MAX for possible large p_vaddr values).

  And that the phdr0_load_address must start at a page boundary, with
  the segment's real content starting at:

       phdr0_load_address + page_offset(phdr0->p_vaddr)

  Note that ELF requires the following condition to make the mmap()-ing work:

      page_offset(phdr0->p_vaddr) == page_offset(phdr0->p_offset)

  The load_bias must be added to any p_vaddr value read from the ELF file to
  determine the corresponding memory address.

 **/

static const size_t kPageSize = page_size();

/*
 * Generic PMD size calculation:
 *    - Each page table (PT) is of size 1 page.
 *    - Each page table entry (PTE) is of size 64 bits.
 *    - Each PTE locates one physical page frame (PFN) of size 1 page.
 *    - A PMD entry locates 1 page table (PT)
 *
 *   PMD size = Num entries in a PT * page_size
 */
static const size_t kPmdSize = (kPageSize / sizeof(uint64_t)) * kPageSize;

ElfReader::ElfReader()
    : did_read_(false), did_load_(false), fd_(-1), file_offset_(0), file_size_(0), phdr_num_(0),
      phdr_table_(nullptr), shdr_table_(nullptr), shdr_num_(0), dynamic_(nullptr), strtab_(nullptr),
      strtab_size_(0), load_start_(nullptr), load_size_(0), load_bias_(0), max_align_(0), min_align_(0),
      loaded_phdr_(nullptr), mapped_by_caller_(false) {
}

bool ElfReader::Read(const char* name, int fd, off64_t file_offset, off64_t file_size) {
  if (did_read_) {
    return true;
  }
  name_ = name;
  fd_ = fd;
  file_offset_ = file_offset;
  file_size_ = file_size;

  if (ReadElfHeader() &&
      VerifyElfHeader() &&
      ReadProgramHeaders() &&
      CheckProgramHeaderAlignment() &&
      ReadSectionHeaders() &&
      ReadDynamicSection() &&
      ReadPadSegmentNote()) {
    did_read_ = true;
  }

  if (kPageSize == 16*1024 && min_align_ == 4096) {
    // This prop needs to be read on 16KiB devices for each ELF where min_palign is 4KiB.
    // It cannot be cached since the developer may toggle app compat on/off.
    // This check will be removed once app compat is made the default on 16KiB devices.
    should_use_16kib_app_compat_ =
        ::android::base::GetBoolProperty("bionic.linker.16kb.app_compat.enabled", false) ||
        get_16kb_appcompat_mode();
  }

  return did_read_;
}

bool ElfReader::Load(address_space_params* address_space) {
  CHECK(did_read_);
  if (did_load_) {
    return true;
  }
  bool reserveSuccess = ReserveAddressSpace(address_space);
  if (reserveSuccess && LoadSegments() && FindPhdr() &&
      FindGnuPropertySection()) {
    did_load_ = true;
#if defined(__aarch64__)
    // For Armv8.5-A loaded executable segments may require PROT_BTI.
    if (note_gnu_property_.IsBTICompatible()) {
      did_load_ =
          (phdr_table_protect_segments(phdr_table_, phdr_num_, load_bias_, should_pad_segments_,
                                       should_use_16kib_app_compat_, &note_gnu_property_) == 0);
    }
#endif
  }
  if (reserveSuccess && !did_load_) {
    if (load_start_ != nullptr && load_size_ != 0) {
      if (!mapped_by_caller_) {
        munmap(load_start_, load_size_);
      }
    }
  }

  return did_load_;
}

const char* ElfReader::get_string(ElfW(Word) index) const {
  CHECK(strtab_ != nullptr);
  CHECK(index < strtab_size_);

  return strtab_ + index;
}

bool ElfReader::ReadElfHeader() {
  ssize_t rc = TEMP_FAILURE_RETRY(pread64(fd_, &header_, sizeof(header_), file_offset_));
  if (rc < 0) {
    DL_ERR("can't read file \"%s\": %s", name_.c_str(), strerror(errno));
    return false;
  }

  if (rc != sizeof(header_)) {
    DL_ERR("\"%s\" is too small to be an ELF executable: only found %zd bytes", name_.c_str(),
           static_cast<size_t>(rc));
    return false;
  }
  return true;
}

static const char* EM_to_string(int em) {
  if (em == EM_386) return "EM_386";
  if (em == EM_AARCH64) return "EM_AARCH64";
  if (em == EM_ARM) return "EM_ARM";
  if (em == EM_RISCV) return "EM_RISCV";
  if (em == EM_X86_64) return "EM_X86_64";
  return "EM_???";
}

bool ElfReader::VerifyElfHeader() {
  if (memcmp(header_.e_ident, ELFMAG, SELFMAG) != 0) {
    DL_ERR("\"%s\" has bad ELF magic: %02x%02x%02x%02x", name_.c_str(),
           header_.e_ident[0], header_.e_ident[1], header_.e_ident[2], header_.e_ident[3]);
    return false;
  }

  // Try to give a clear diagnostic for ELF class mismatches, since they're
  // an easy mistake to make during the 32-bit/64-bit transition period.
  int elf_class = header_.e_ident[EI_CLASS];
#if defined(__LP64__)
  if (elf_class != ELFCLASS64) {
    if (elf_class == ELFCLASS32) {
      DL_ERR("\"%s\" is 32-bit instead of 64-bit", name_.c_str());
    } else {
      DL_ERR("\"%s\" has unknown ELF class: %d", name_.c_str(), elf_class);
    }
    return false;
  }
#else
  if (elf_class != ELFCLASS32) {
    if (elf_class == ELFCLASS64) {
      DL_ERR("\"%s\" is 64-bit instead of 32-bit", name_.c_str());
    } else {
      DL_ERR("\"%s\" has unknown ELF class: %d", name_.c_str(), elf_class);
    }
    return false;
  }
#endif

  if (header_.e_ident[EI_DATA] != ELFDATA2LSB) {
    DL_ERR("\"%s\" not little-endian: %d", name_.c_str(), header_.e_ident[EI_DATA]);
    return false;
  }

  if (header_.e_type != ET_DYN) {
    DL_ERR("\"%s\" has unexpected e_type: %d", name_.c_str(), header_.e_type);
    return false;
  }

  if (header_.e_version != EV_CURRENT) {
    DL_ERR("\"%s\" has unexpected e_version: %d", name_.c_str(), header_.e_version);
    return false;
  }

  if (header_.e_machine != GetTargetElfMachine()) {
    DL_ERR("\"%s\" is for %s (%d) instead of %s (%d)",
           name_.c_str(),
           EM_to_string(header_.e_machine), header_.e_machine,
           EM_to_string(GetTargetElfMachine()), GetTargetElfMachine());
    return false;
  }

  if (header_.e_shentsize != sizeof(ElfW(Shdr))) {
    if (get_application_target_sdk_version() >= 26) {
      DL_ERR_AND_LOG("\"%s\" has unsupported e_shentsize: 0x%x (expected 0x%zx)",
                     name_.c_str(), header_.e_shentsize, sizeof(ElfW(Shdr)));
      return false;
    }
    DL_WARN_documented_change(26,
                              "invalid-elf-header_section-headers-enforced-for-api-level-26",
                              "\"%s\" has unsupported e_shentsize 0x%x (expected 0x%zx)",
                              name_.c_str(), header_.e_shentsize, sizeof(ElfW(Shdr)));
    add_dlwarning(name_.c_str(), "has invalid ELF header");
  }

  if (header_.e_shstrndx == 0) {
    if (get_application_target_sdk_version() >= 26) {
      DL_ERR_AND_LOG("\"%s\" has invalid e_shstrndx", name_.c_str());
      return false;
    }
    DL_WARN_documented_change(26,
                              "invalid-elf-header_section-headers-enforced-for-api-level-26",
                              "\"%s\" has invalid e_shstrndx", name_.c_str());
    add_dlwarning(name_.c_str(), "has invalid ELF header");
  }

  return true;
}

bool ElfReader::CheckFileRange(ElfW(Addr) offset, size_t size, size_t alignment) {
  off64_t range_start;
  off64_t range_end;

  // Only header can be located at the 0 offset... This function called to
  // check DYNSYM and DYNAMIC sections and phdr/shdr - none of them can be
  // at offset 0.

  return offset > 0 &&
         safe_add(&range_start, file_offset_, offset) &&
         safe_add(&range_end, range_start, size) &&
         (range_start < file_size_) &&
         (range_end <= file_size_) &&
         ((offset % alignment) == 0);
}

// Loads the program header table from an ELF file into a read-only private
// anonymous mmap-ed block.
bool ElfReader::ReadProgramHeaders() {
  phdr_num_ = header_.e_phnum;

  // Like the kernel, we only accept program header tables that
  // are smaller than 64KiB.
  if (phdr_num_ < 1 || phdr_num_ > 65536/sizeof(ElfW(Phdr))) {
    DL_ERR("\"%s\" has invalid e_phnum: %zd", name_.c_str(), phdr_num_);
    return false;
  }

  // Boundary checks
  size_t size = phdr_num_ * sizeof(ElfW(Phdr));
  if (!CheckFileRange(header_.e_phoff, size, alignof(ElfW(Phdr)))) {
    DL_ERR_AND_LOG("\"%s\" has invalid phdr offset/size: %zu/%zu",
                   name_.c_str(),
                   static_cast<size_t>(header_.e_phoff),
                   size);
    return false;
  }

  if (!phdr_fragment_.Map(fd_, file_offset_, header_.e_phoff, size)) {
    DL_ERR("\"%s\" phdr mmap failed: %m", name_.c_str());
    return false;
  }

  phdr_table_ = static_cast<ElfW(Phdr)*>(phdr_fragment_.data());
  return true;
}

bool ElfReader::ReadSectionHeaders() {
  shdr_num_ = header_.e_shnum;

  if (shdr_num_ == 0) {
    DL_ERR_AND_LOG("\"%s\" has no section headers", name_.c_str());
    return false;
  }

  size_t size = shdr_num_ * sizeof(ElfW(Shdr));
  if (!CheckFileRange(header_.e_shoff, size, alignof(const ElfW(Shdr)))) {
    DL_ERR_AND_LOG("\"%s\" has invalid shdr offset/size: %zu/%zu",
                   name_.c_str(),
                   static_cast<size_t>(header_.e_shoff),
                   size);
    return false;
  }

  if (!shdr_fragment_.Map(fd_, file_offset_, header_.e_shoff, size)) {
    DL_ERR("\"%s\" shdr mmap failed: %m", name_.c_str());
    return false;
  }

  shdr_table_ = static_cast<const ElfW(Shdr)*>(shdr_fragment_.data());
  return true;
}

bool ElfReader::ReadDynamicSection() {
  // 1. Find .dynamic section (in section headers)
  const ElfW(Shdr)* dynamic_shdr = nullptr;
  for (size_t i = 0; i < shdr_num_; ++i) {
    if (shdr_table_[i].sh_type == SHT_DYNAMIC) {
      dynamic_shdr = &shdr_table_ [i];
      break;
    }
  }

  if (dynamic_shdr == nullptr) {
    DL_ERR_AND_LOG("\"%s\" .dynamic section header was not found", name_.c_str());
    return false;
  }

  // Make sure dynamic_shdr offset and size matches PT_DYNAMIC phdr
  size_t pt_dynamic_offset = 0;
  size_t pt_dynamic_filesz = 0;
  for (size_t i = 0; i < phdr_num_; ++i) {
    const ElfW(Phdr)* phdr = &phdr_table_[i];
    if (phdr->p_type == PT_DYNAMIC) {
      pt_dynamic_offset = phdr->p_offset;
      pt_dynamic_filesz = phdr->p_filesz;
    }
  }

  if (pt_dynamic_offset != dynamic_shdr->sh_offset) {
    if (get_application_target_sdk_version() >= 26) {
      DL_ERR_AND_LOG("\"%s\" .dynamic section has invalid offset: 0x%zx, "
                     "expected to match PT_DYNAMIC offset: 0x%zx",
                     name_.c_str(),
                     static_cast<size_t>(dynamic_shdr->sh_offset),
                     pt_dynamic_offset);
      return false;
    }
    DL_WARN_documented_change(26,
                              "invalid-elf-header_section-headers-enforced-for-api-level-26",
                              "\"%s\" .dynamic section has invalid offset: 0x%zx "
                              "(expected to match PT_DYNAMIC offset 0x%zx)",
                              name_.c_str(),
                              static_cast<size_t>(dynamic_shdr->sh_offset),
                              pt_dynamic_offset);
    add_dlwarning(name_.c_str(), "invalid .dynamic section");
  }

  if (pt_dynamic_filesz != dynamic_shdr->sh_size) {
    if (get_application_target_sdk_version() >= 26) {
      DL_ERR_AND_LOG("\"%s\" .dynamic section has invalid size: 0x%zx, "
                     "expected to match PT_DYNAMIC filesz: 0x%zx",
                     name_.c_str(),
                     static_cast<size_t>(dynamic_shdr->sh_size),
                     pt_dynamic_filesz);
      return false;
    }
    DL_WARN_documented_change(26,
                              "invalid-elf-header_section-headers-enforced-for-api-level-26",
                              "\"%s\" .dynamic section has invalid size: 0x%zx "
                              "(expected to match PT_DYNAMIC filesz 0x%zx)",
                              name_.c_str(),
                              static_cast<size_t>(dynamic_shdr->sh_size),
                              pt_dynamic_filesz);
    add_dlwarning(name_.c_str(), "invalid .dynamic section");
  }

  if (dynamic_shdr->sh_link >= shdr_num_) {
    DL_ERR_AND_LOG("\"%s\" .dynamic section has invalid sh_link: %d",
                   name_.c_str(),
                   dynamic_shdr->sh_link);
    return false;
  }

  const ElfW(Shdr)* strtab_shdr = &shdr_table_[dynamic_shdr->sh_link];

  if (strtab_shdr->sh_type != SHT_STRTAB) {
    DL_ERR_AND_LOG("\"%s\" .dynamic section has invalid link(%d) sh_type: %d (expected SHT_STRTAB)",
                   name_.c_str(), dynamic_shdr->sh_link, strtab_shdr->sh_type);
    return false;
  }

  if (!CheckFileRange(dynamic_shdr->sh_offset, dynamic_shdr->sh_size, alignof(const ElfW(Dyn)))) {
    DL_ERR_AND_LOG("\"%s\" has invalid offset/size of .dynamic section", name_.c_str());
    return false;
  }

  if (!dynamic_fragment_.Map(fd_, file_offset_, dynamic_shdr->sh_offset, dynamic_shdr->sh_size)) {
    DL_ERR("\"%s\" dynamic section mmap failed: %m", name_.c_str());
    return false;
  }

  dynamic_ = static_cast<const ElfW(Dyn)*>(dynamic_fragment_.data());

  if (!CheckFileRange(strtab_shdr->sh_offset, strtab_shdr->sh_size, alignof(const char))) {
    DL_ERR_AND_LOG("\"%s\" has invalid offset/size of the .strtab section linked from .dynamic section",
                   name_.c_str());
    return false;
  }

  if (!strtab_fragment_.Map(fd_, file_offset_, strtab_shdr->sh_offset, strtab_shdr->sh_size)) {
    DL_ERR("\"%s\" strtab section mmap failed: %m", name_.c_str());
    return false;
  }

  strtab_ = static_cast<const char*>(strtab_fragment_.data());
  strtab_size_ = strtab_fragment_.size();
  return true;
}

/* Returns the size of the extent of all the possibly non-contiguous
 * loadable segments in an ELF program header table. This corresponds
 * to the page-aligned size in bytes that needs to be reserved in the
 * process' address space. If there are no loadable segments, 0 is
 * returned.
 *
 * If out_min_vaddr or out_max_vaddr are not null, they will be
 * set to the minimum and maximum addresses of pages to be reserved,
 * or 0 if there is nothing to load.
 */
size_t phdr_table_get_load_size(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                ElfW(Addr)* out_min_vaddr,
                                ElfW(Addr)* out_max_vaddr) {
  ElfW(Addr) min_vaddr = UINTPTR_MAX;
  ElfW(Addr) max_vaddr = 0;

  bool found_pt_load = false;
  for (size_t i = 0; i < phdr_count; ++i) {
    const ElfW(Phdr)* phdr = &phdr_table[i];

    if (phdr->p_type != PT_LOAD) {
      continue;
    }
    found_pt_load = true;

    if (phdr->p_vaddr < min_vaddr) {
      min_vaddr = phdr->p_vaddr;
    }

    if (phdr->p_vaddr + phdr->p_memsz > max_vaddr) {
      max_vaddr = phdr->p_vaddr + phdr->p_memsz;
    }
  }
  if (!found_pt_load) {
    min_vaddr = 0;
  }

  min_vaddr = page_start(min_vaddr);
  max_vaddr = page_end(max_vaddr);

  if (out_min_vaddr != nullptr) {
    *out_min_vaddr = min_vaddr;
  }
  if (out_max_vaddr != nullptr) {
    *out_max_vaddr = max_vaddr;
  }
  return max_vaddr - min_vaddr;
}

bool ElfReader::CheckProgramHeaderAlignment() {
  max_align_ = min_align_ = page_size();

  for (size_t i = 0; i < phdr_num_; ++i) {
    const ElfW(Phdr)* phdr = &phdr_table_[i];

    // p_align must be 0, 1, or a positive, integral power of two.
    if (phdr->p_type != PT_LOAD || ((phdr->p_align & (phdr->p_align - 1)) != 0)) {
      // TODO: reject ELF files with bad p_align values.
      continue;
    }

    max_align_ = std::max(max_align_, static_cast<size_t>(phdr->p_align));

    if (phdr->p_align > 1) {
      min_align_ = std::min(min_align_, static_cast<size_t>(phdr->p_align));
    }
  }

  return true;
}

// Reserve a virtual address range such that if it's limits were extended to the next 2**align
// boundary, it would not overlap with any existing mappings.
static void* ReserveWithAlignmentPadding(size_t size, size_t mapping_align, size_t start_align,
                                         void** out_gap_start, size_t* out_gap_size) {
  int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS;
  // Reserve enough space to properly align the library's start address.
  mapping_align = std::max(mapping_align, start_align);
  if (mapping_align == page_size()) {
    void* mmap_ptr = mmap(nullptr, size, PROT_NONE, mmap_flags, -1, 0);
    if (mmap_ptr == MAP_FAILED) {
      return nullptr;
    }
    return mmap_ptr;
  }

  // Minimum alignment of shared library gap. For efficiency, this should match the second level
  // page size of the platform.
#if defined(__LP64__)
  constexpr size_t kGapAlignment = 2 * 1024 * 1024;
#endif
  // Maximum gap size, in the units of kGapAlignment.
  constexpr size_t kMaxGapUnits = 32;
  // Allocate enough space so that the end of the desired region aligned up is still inside the
  // mapping.
  size_t mmap_size = __builtin_align_up(size, mapping_align) + mapping_align - page_size();
  uint8_t* mmap_ptr =
      reinterpret_cast<uint8_t*>(mmap(nullptr, mmap_size, PROT_NONE, mmap_flags, -1, 0));
  if (mmap_ptr == MAP_FAILED) {
    return nullptr;
  }
  size_t gap_size = 0;
  size_t first_byte = reinterpret_cast<size_t>(__builtin_align_up(mmap_ptr, mapping_align));
  size_t last_byte = reinterpret_cast<size_t>(__builtin_align_down(mmap_ptr + mmap_size, mapping_align) - 1);
#if defined(__LP64__)
  if (first_byte / kGapAlignment != last_byte / kGapAlignment) {
    // This library crosses a 2MB boundary and will fragment a new huge page.
    // Lets take advantage of that and insert a random number of inaccessible huge pages before that
    // to improve address randomization and make it harder to locate this library code by probing.
    munmap(mmap_ptr, mmap_size);
    mapping_align = std::max(mapping_align, kGapAlignment);
    gap_size =
        kGapAlignment * (is_first_stage_init() ? 1 : arc4random_uniform(kMaxGapUnits - 1) + 1);
    mmap_size = __builtin_align_up(size + gap_size, mapping_align) + mapping_align - page_size();
    mmap_ptr = reinterpret_cast<uint8_t*>(mmap(nullptr, mmap_size, PROT_NONE, mmap_flags, -1, 0));
    if (mmap_ptr == MAP_FAILED) {
      return nullptr;
    }
  }
#endif

  uint8_t* gap_end = mmap_ptr + mmap_size;
#if defined(__LP64__)
  if (gap_size) {
    gap_end = __builtin_align_down(gap_end, kGapAlignment);
  }
#endif
  uint8_t* gap_start = gap_end - gap_size;

  uint8_t* first = __builtin_align_up(mmap_ptr, mapping_align);
  uint8_t* last = __builtin_align_down(gap_start, mapping_align) - size;

  // arc4random* is not available in first stage init because /dev/urandom hasn't yet been
  // created. Don't randomize then.
  size_t n = is_first_stage_init() ? 0 : arc4random_uniform((last - first) / start_align + 1);
  uint8_t* start = first + n * start_align;
  // Unmap the extra space around the allocation.
  // Keep it mapped PROT_NONE on 64-bit targets where address space is plentiful to make it harder
  // to defeat ASLR by probing for readable memory mappings.
  munmap(mmap_ptr, start - mmap_ptr);
  munmap(start + size, gap_start - (start + size));
  if (gap_end != mmap_ptr + mmap_size) {
    munmap(gap_end, mmap_ptr + mmap_size - gap_end);
  }
  *out_gap_start = gap_start;
  *out_gap_size = gap_size;
  return start;
}

// Reserve a virtual address range big enough to hold all loadable
// segments of a program header table. This is done by creating a
// private anonymous mmap() with PROT_NONE.
bool ElfReader::ReserveAddressSpace(address_space_params* address_space) {
  ElfW(Addr) min_vaddr;
  load_size_ = phdr_table_get_load_size(phdr_table_, phdr_num_, &min_vaddr);
  if (load_size_ == 0) {
    DL_ERR("\"%s\" has no loadable segments", name_.c_str());
    return false;
  }

  if (should_use_16kib_app_compat_) {
    // Reserve additional space for aligning the permission boundary in compat loading
    // Up to kPageSize-kCompatPageSize additional space is needed, but reservation
    // is done with mmap which gives kPageSize multiple-sized reservations.
    load_size_ += kPageSize;
  }

  uint8_t* addr = reinterpret_cast<uint8_t*>(min_vaddr);
  void* start;

  if (load_size_ > address_space->reserved_size) {
    if (address_space->must_use_address) {
      DL_ERR("reserved address space %zd smaller than %zd bytes needed for \"%s\"",
             load_size_ - address_space->reserved_size, load_size_, name_.c_str());
      return false;
    }
    size_t start_alignment = page_size();
    if (get_transparent_hugepages_supported() && get_application_target_sdk_version() >= 31) {
      // Limit alignment to PMD size as other alignments reduce the number of
      // bits available for ASLR for no benefit.
      start_alignment = max_align_ == kPmdSize ? kPmdSize : page_size();
    }
    start = ReserveWithAlignmentPadding(load_size_, kLibraryAlignment, start_alignment, &gap_start_,
                                        &gap_size_);
    if (start == nullptr) {
      DL_ERR("couldn't reserve %zd bytes of address space for \"%s\"", load_size_, name_.c_str());
      return false;
    }
  } else {
    start = address_space->start_addr;
    gap_start_ = nullptr;
    gap_size_ = 0;
    mapped_by_caller_ = true;

    // Update the reserved address space to subtract the space used by this library.
    address_space->start_addr = reinterpret_cast<uint8_t*>(address_space->start_addr) + load_size_;
    address_space->reserved_size -= load_size_;
  }

  load_start_ = start;
  load_bias_ = reinterpret_cast<uint8_t*>(start) - addr;

  if (should_use_16kib_app_compat_) {
    // In compat mode make the initial mapping RW since the ELF contents will be read
    // into it; instead of mapped over it.
    mprotect(reinterpret_cast<void*>(start), load_size_, PROT_READ | PROT_WRITE);
  }

  return true;
}

/*
 * Returns true if the kernel supports page size migration for this process.
 */
bool page_size_migration_supported() {
#if defined(__LP64__)
  static bool pgsize_migration_enabled = []() {
    std::string enabled;
    if (!android::base::ReadFileToString("/sys/kernel/mm/pgsize_migration/enabled", &enabled)) {
      return false;
    }
    return enabled.find("1") != std::string::npos;
  }();
  return pgsize_migration_enabled;
#else
  return false;
#endif
}

// Find the ELF note of type NT_ANDROID_TYPE_PAD_SEGMENT and check that the desc value is 1.
bool ElfReader::ReadPadSegmentNote() {
  if (!page_size_migration_supported()) {
    // Don't attempt to read the note, since segment extension isn't
    // supported; but return true so that loading can continue normally.
    return true;
  }

  // The ELF can have multiple PT_NOTE's, check them all
  for (size_t i = 0; i < phdr_num_; ++i) {
    const ElfW(Phdr)* phdr = &phdr_table_[i];

    if (phdr->p_type != PT_NOTE) {
      continue;
    }

    // Some obfuscated ELFs may contain "empty" PT_NOTE program headers that don't
    // point to any part of the ELF (p_memsz == 0). Skip these since there is
    // nothing to decode. See: b/324468126
    if (phdr->p_memsz == 0) {
      continue;
    }

    // If the PT_NOTE extends beyond the file. The ELF is doing something
    // strange -- obfuscation, embedding hidden loaders, ...
    //
    // It doesn't contain the pad_segment note. Skip it to avoid SIGBUS
    // by accesses beyond the file.
    off64_t note_end_off = file_offset_ + phdr->p_offset + phdr->p_filesz;
    if (note_end_off > file_size_) {
      continue;
    }

    // note_fragment is scoped to within the loop so that there is
    // at most 1 PT_NOTE mapped at anytime during this search.
    MappedFileFragment note_fragment;
    if (!note_fragment.Map(fd_, file_offset_, phdr->p_offset, phdr->p_memsz)) {
      DL_ERR("\"%s\": PT_NOTE mmap(nullptr, %p, PROT_READ, MAP_PRIVATE, %d, %p) failed: %m",
             name_.c_str(), reinterpret_cast<void*>(phdr->p_memsz), fd_,
             reinterpret_cast<void*>(page_start(file_offset_ + phdr->p_offset)));
      return false;
    }

    const ElfW(Nhdr)* note_hdr = nullptr;
    const char* note_desc = nullptr;
    if (!__get_elf_note(NT_ANDROID_TYPE_PAD_SEGMENT, "Android",
                        reinterpret_cast<ElfW(Addr)>(note_fragment.data()),
                        phdr, &note_hdr, &note_desc)) {
      continue;
    }

    if (note_hdr->n_descsz != sizeof(ElfW(Word))) {
      DL_ERR("\"%s\" NT_ANDROID_TYPE_PAD_SEGMENT note has unexpected n_descsz: %u",
             name_.c_str(), reinterpret_cast<unsigned int>(note_hdr->n_descsz));
      return false;
    }

    // 1 == enabled, 0 == disabled
    should_pad_segments_ = *reinterpret_cast<const ElfW(Word)*>(note_desc) == 1;
    return true;
  }

  return true;
}

static inline void _extend_load_segment_vma(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                            size_t phdr_idx, ElfW(Addr)* p_memsz,
                                            ElfW(Addr)* p_filesz, bool should_pad_segments,
                                            bool should_use_16kib_app_compat) {
  // NOTE: Segment extension is only applicable where the ELF's max-page-size > runtime page size;
  // to save kernel VMA slab memory. 16KiB compat mode is the exact opposite scenario.
  if (should_use_16kib_app_compat) {
    return;
  }

  const ElfW(Phdr)* phdr = &phdr_table[phdr_idx];
  const ElfW(Phdr)* next = nullptr;
  size_t next_idx = phdr_idx + 1;

  // Don't do segment extension for p_align > 64KiB, such ELFs already existed in the
  // field e.g. 2MiB p_align for THPs and are relatively small in number.
  //
  // The kernel can only represent padding for p_align up to 64KiB. This is because
  // the kernel uses 4 available bits in the vm_area_struct to represent padding
  // extent; and so cannot enable mitigations to avoid breaking app compatibility for
  // p_aligns > 64KiB.
  //
  // Don't perform segment extension on these to avoid app compatibility issues.
  if (phdr->p_align <= kPageSize || phdr->p_align > 64*1024 || !should_pad_segments) {
    return;
  }

  if (next_idx < phdr_count && phdr_table[next_idx].p_type == PT_LOAD) {
    next = &phdr_table[next_idx];
  }

  // If this is the last LOAD segment, no extension is needed
  if (!next || *p_memsz != *p_filesz) {
    return;
  }

  ElfW(Addr) next_start = page_start(next->p_vaddr);
  ElfW(Addr) curr_end = page_end(phdr->p_vaddr + *p_memsz);

  // If adjacent segment mappings overlap, no extension is needed.
  if (curr_end >= next_start) {
    return;
  }

  // Extend the LOAD segment mapping to be contiguous with that of
  // the next LOAD segment.
  ElfW(Addr) extend = next_start - curr_end;
  *p_memsz += extend;
  *p_filesz += extend;
}

bool ElfReader::MapSegment(size_t seg_idx, size_t len) {
  const ElfW(Phdr)* phdr = &phdr_table_[seg_idx];

  void* start = reinterpret_cast<void*>(page_start(phdr->p_vaddr + load_bias_));

  // The ELF could be being loaded directly from a zipped APK,
  // the zip offset must be added to find the segment offset.
  const ElfW(Addr) offset = file_offset_ + page_start(phdr->p_offset);

  int prot = PFLAGS_TO_PROT(phdr->p_flags);

  void* seg_addr = mmap64(start, len, prot, MAP_FIXED | MAP_PRIVATE, fd_, offset);

  if (seg_addr == MAP_FAILED) {
    DL_ERR("couldn't map \"%s\" segment %zd: %m", name_.c_str(), seg_idx);
    return false;
  }

  // Mark segments as huge page eligible if they meet the requirements
  if ((phdr->p_flags & PF_X) && phdr->p_align == kPmdSize &&
      get_transparent_hugepages_supported()) {
    madvise(seg_addr, len, MADV_HUGEPAGE);
  }

  return true;
}

void ElfReader::ZeroFillSegment(const ElfW(Phdr)* phdr) {
  // NOTE: In 16KiB app compat mode, the ELF mapping is anonymous, meaning that
  // RW segments are COW-ed from the kernel's zero page. So there is no need to
  // explicitly zero-fill until the last page's limit.
  if (should_use_16kib_app_compat_) {
    return;
  }

  ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
  uint64_t unextended_seg_file_end = seg_start + phdr->p_filesz;

  // If the segment is writable, and does not end on a page boundary,
  // zero-fill it until the page limit.
  //
  // Do not attempt to zero the extended region past the first partial page,
  // since doing so may:
  //   1) Result in a SIGBUS, as the region is not backed by the underlying
  //      file.
  //   2) Break the COW backing, faulting in new anon pages for a region
  //     
"""


```