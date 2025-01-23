Response:
The user wants me to summarize the functionality of the provided C++ code snippet from `bionic/linker/linker_phdr.cpp`. This code is part of Android's dynamic linker and deals with processing the program header table of ELF files.

Here's a breakdown of the code's key functions and how to summarize them:

1. **Memory Mapping and Protection:** The code heavily interacts with memory mapping functions like `mmap` and `mprotect`. It maps segments of the ELF file into memory and sets memory protection attributes (read, write, execute).

2. **Handling Different Page Sizes:** It accounts for different page sizes (4KB and 16KB) and compatibility modes.

3. **Zero-filling and Padding:** The code manages the initialization of BSS sections and potentially adds padding to segments.

4. **Relocation Read-Only (RELRO):**  It handles the GNU RELRO feature, which makes parts of the data segment read-only after relocation.

5. **Memory Tagging (MTE):**  The code includes logic for Memory Tagging Extension (MTE), a hardware-assisted memory safety feature.

6. **Finding the Program Header:** It includes functions to locate the program header table in the loaded memory.
这是 `bionic/linker/linker_phdr.cpp` 文件代码片段的第二部分，主要负责处理 ELF 文件的 program header，进行内存映射、权限设置以及一些优化操作。以下是这段代码的功能归纳：

**主要功能归纳:**

这段代码的主要功能是加载 ELF 文件中的各个段 (Segment)，并根据 Program Header 的描述进行内存映射和权限设置。它涵盖了以下关键方面：

1. **内存映射 (Memory Mapping):**
   - 遍历 ELF 文件的 Program Header 表，找到类型为 `PT_LOAD` 的段。
   - 使用 `mmap` 系统调用将这些段映射到内存中。
   - 考虑了不同页面大小 (4KB 和 16KB) 和兼容模式 (16KiB App Compat) 的情况，并据此调整映射策略。
   - 对于 `.bss` 段（未初始化的数据段），会进行匿名映射并清零。

2. **内存保护 (Memory Protection):**
   - 使用 `mprotect` 系统调用设置内存区域的保护属性（读、写、执行）。
   - 实现了 `phdr_table_protect_segments` 函数，用于将加载的段设置为其原始的保护属性（通常在重定位完成后调用）。
   - 实现了 `phdr_table_unprotect_segments` 函数，用于将加载的段设置为可写（通常在重定位之前调用）。
   - 实现了 `phdr_table_protect_gnu_relro` 函数，用于应用 GNU RELRO (Relocation Read-Only) 保护，将某些数据段（如 `.got` 和 `.data.rel.ro`）设置为只读。
   - 实现了针对 16KiB 兼容模式的 RELRO 保护函数 `phdr_table_protect_gnu_relro_16kib_compat`。

3. **段的扩展和填充 (Segment Extension and Padding):**
   - 存在 `_extend_load_segment_vma` 函数，用于扩展 LOAD 段的虚拟内存区域，可能用于避免内存映射中的间隙，尤其是在开启段填充的情况下。
   - `ZeroFillSegment` 函数用于确保 LOAD 段中 `p_filesz` 和 `p_memsz` 之间的部分用零填充。
   - `DropPaddingPages` 函数用于释放段末尾的填充页，以避免后续的回收工作。

4. **内存标签扩展 (Memory Tagging Extension - MTE):**
   - 实现了与内存标签相关的函数 `remap_memtag_globals_segments`，用于在硬件支持的情况下，将可写数据段重新映射为带有 `PROT_MTE` 标志，以启用内存标签。
   - 实现了 `protect_memtag_globals_ro_segments` 函数，用于将启用了内存标签的全局变量段设置为只读。
   - 实现了 `name_memtag_globals_segments` 函数，用于为启用了内存标签的全局变量段设置 VMA 名称，方便调试。

5. **GNU RELRO 的序列化和映射 (GNU RELRO Serialization and Mapping):**
   - 实现了 `phdr_table_serialize_gnu_relro` 函数，用于将 GNU RELRO 段的内容序列化到文件中。
   - 实现了 `phdr_table_map_gnu_relro` 函数，用于将之前序列化的 GNU RELRO 段从文件中映射回内存，以实现跨进程共享。

6. **查找特殊段 (Finding Special Sections):**
   - 实现了 `phdr_table_get_dynamic_section` 函数，用于查找 `.dynamic` 段。
   - 实现了 `phdr_table_get_interpreter_name` 函数，用于查找程序解释器名称（对于动态链接的可执行文件）。
   - 实现了 `ElfReader::FindPhdr` 函数，用于在加载的内存中查找 Program Header 表。
   - 实现了 `ElfReader::FindGnuPropertySection` 函数，用于查找 `.note.gnu.property` 段。

**总结来说，这段代码是动态链接器加载 ELF 文件并准备其在内存中执行的关键步骤，它负责将代码和数据加载到正确的内存位置，并设置必要的保护措施以确保安全和正确的执行。**

### 提示词
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
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
that will not be used.
  if ((phdr->p_flags & PF_W) != 0 && page_offset(unextended_seg_file_end) > 0) {
    memset(reinterpret_cast<void*>(unextended_seg_file_end), 0,
           kPageSize - page_offset(unextended_seg_file_end));
  }
}

void ElfReader::DropPaddingPages(const ElfW(Phdr)* phdr, uint64_t seg_file_end) {
  // NOTE: Padding pages are only applicable where the ELF's max-page-size > runtime page size;
  // 16KiB compat mode is the exact opposite scenario.
  if (should_use_16kib_app_compat_) {
    return;
  }

  ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
  uint64_t unextended_seg_file_end = seg_start + phdr->p_filesz;

  uint64_t pad_start = page_end(unextended_seg_file_end);
  uint64_t pad_end = page_end(seg_file_end);
  CHECK(pad_start <= pad_end);

  uint64_t pad_len = pad_end - pad_start;
  if (pad_len == 0 || !page_size_migration_supported()) {
    return;
  }

  // Pages may be brought in due to readahead.
  // Drop the padding (zero) pages, to avoid reclaim work later.
  //
  // NOTE: The madvise() here is special, as it also serves to hint to the
  // kernel the portion of the LOAD segment that is padding.
  //
  // See: [1] https://android-review.googlesource.com/c/kernel/common/+/3032411
  //      [2] https://android-review.googlesource.com/c/kernel/common/+/3048835
  if (madvise(reinterpret_cast<void*>(pad_start), pad_len, MADV_DONTNEED)) {
    DL_WARN("\"%s\": madvise(0x%" PRIx64 ", 0x%" PRIx64 ", MADV_DONTNEED) failed: %m",
            name_.c_str(), pad_start, pad_len);
  }
}

bool ElfReader::MapBssSection(const ElfW(Phdr)* phdr, ElfW(Addr) seg_page_end,
                              ElfW(Addr) seg_file_end) {
  // NOTE: We do not need to handle .bss in 16KiB compat mode since the mapping
  // reservation is anonymous and RW to begin with.
  if (should_use_16kib_app_compat_) {
    return true;
  }

  // seg_file_end is now the first page address after the file content.
  seg_file_end = page_end(seg_file_end);

  if (seg_page_end <= seg_file_end) {
    return true;
  }

  // If seg_page_end is larger than seg_file_end, we need to zero
  // anything between them. This is done by using a private anonymous
  // map for all extra pages
  size_t zeromap_size = seg_page_end - seg_file_end;
  void* zeromap =
      mmap(reinterpret_cast<void*>(seg_file_end), zeromap_size, PFLAGS_TO_PROT(phdr->p_flags),
           MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (zeromap == MAP_FAILED) {
    DL_ERR("couldn't map .bss section for \"%s\": %m", name_.c_str());
    return false;
  }

  // Set the VMA name using prctl
  prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, zeromap, zeromap_size, ".bss");

  return true;
}

bool ElfReader::LoadSegments() {
  // NOTE: The compat(legacy) page size (4096) must be used when aligning
  // the 4KiB segments for loading in compat mode. The larger 16KiB page size
  // will lead to overwriting adjacent segments since the ELF's segment(s)
  // are not 16KiB aligned.
  size_t seg_align = should_use_16kib_app_compat_ ? kCompatPageSize : kPageSize;

  // Only enforce this on 16 KB systems with app compat disabled.
  // Apps may rely on undefined behavior here on 4 KB systems,
  // which is the norm before this change is introduced
  if (kPageSize >= 16384 && min_align_ < kPageSize && !should_use_16kib_app_compat_) {
    DL_ERR("\"%s\" program alignment (%zu) cannot be smaller than system page size (%zu)",
           name_.c_str(), min_align_, kPageSize);
    return false;
  }

  if (!Setup16KiBAppCompat()) {
    DL_ERR("\"%s\" failed to setup 16KiB App Compat", name_.c_str());
    return false;
  }

  for (size_t i = 0; i < phdr_num_; ++i) {
    const ElfW(Phdr)* phdr = &phdr_table_[i];

    if (phdr->p_type != PT_LOAD) {
      continue;
    }

    ElfW(Addr) p_memsz = phdr->p_memsz;
    ElfW(Addr) p_filesz = phdr->p_filesz;
    _extend_load_segment_vma(phdr_table_, phdr_num_, i, &p_memsz, &p_filesz, should_pad_segments_,
                             should_use_16kib_app_compat_);

    // Segment addresses in memory.
    ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
    ElfW(Addr) seg_end = seg_start + p_memsz;

    ElfW(Addr) seg_page_end = __builtin_align_up(seg_end, seg_align);

    ElfW(Addr) seg_file_end = seg_start + p_filesz;

    // File offsets.
    ElfW(Addr) file_start = phdr->p_offset;
    ElfW(Addr) file_end = file_start + p_filesz;

    ElfW(Addr) file_page_start = __builtin_align_down(file_start, seg_align);
    ElfW(Addr) file_length = file_end - file_page_start;

    if (file_size_ <= 0) {
      DL_ERR("\"%s\" invalid file size: %" PRId64, name_.c_str(), file_size_);
      return false;
    }

    if (file_start + phdr->p_filesz > static_cast<size_t>(file_size_)) {
      DL_ERR("invalid ELF file \"%s\" load segment[%zd]:"
          " p_offset (%p) + p_filesz (%p) ( = %p) past end of file (0x%" PRIx64 ")",
          name_.c_str(), i, reinterpret_cast<void*>(phdr->p_offset),
          reinterpret_cast<void*>(phdr->p_filesz),
          reinterpret_cast<void*>(file_start + phdr->p_filesz), file_size_);
      return false;
    }

    if (file_length != 0) {
      int prot = PFLAGS_TO_PROT(phdr->p_flags);
      if ((prot & (PROT_EXEC | PROT_WRITE)) == (PROT_EXEC | PROT_WRITE)) {
        // W + E PT_LOAD segments are not allowed in O.
        if (get_application_target_sdk_version() >= 26) {
          DL_ERR_AND_LOG("\"%s\": W+E load segments are not allowed", name_.c_str());
          return false;
        }
        DL_WARN_documented_change(26,
                                  "writable-and-executable-segments-enforced-for-api-level-26",
                                  "\"%s\" has load segments that are both writable and executable",
                                  name_.c_str());
        add_dlwarning(name_.c_str(), "W+E load segments");
      }

      // Pass the file_length, since it may have been extended by _extend_load_segment_vma().
      if (should_use_16kib_app_compat_) {
        if (!CompatMapSegment(i, file_length)) {
          return false;
        }
      } else {
        if (!MapSegment(i, file_length)) {
          return false;
        }
      }
    }

    ZeroFillSegment(phdr);

    DropPaddingPages(phdr, seg_file_end);

    if (!MapBssSection(phdr, seg_page_end, seg_file_end)) {
      return false;
    }
  }
  return true;
}

/* Used internally. Used to set the protection bits of all loaded segments
 * with optional extra flags (i.e. really PROT_WRITE). Used by
 * phdr_table_protect_segments and phdr_table_unprotect_segments.
 */
static int _phdr_table_set_load_prot(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                     ElfW(Addr) load_bias, int extra_prot_flags,
                                     bool should_pad_segments, bool should_use_16kib_app_compat) {
  for (size_t i = 0; i < phdr_count; ++i) {
    const ElfW(Phdr)* phdr = &phdr_table[i];

    if (phdr->p_type != PT_LOAD || (phdr->p_flags & PF_W) != 0) {
      continue;
    }

    ElfW(Addr) p_memsz = phdr->p_memsz;
    ElfW(Addr) p_filesz = phdr->p_filesz;
    _extend_load_segment_vma(phdr_table, phdr_count, i, &p_memsz, &p_filesz, should_pad_segments,
                             should_use_16kib_app_compat);

    ElfW(Addr) seg_page_start = page_start(phdr->p_vaddr + load_bias);
    ElfW(Addr) seg_page_end = page_end(phdr->p_vaddr + p_memsz + load_bias);

    int prot = PFLAGS_TO_PROT(phdr->p_flags) | extra_prot_flags;
    if ((prot & PROT_WRITE) != 0) {
      // make sure we're never simultaneously writable / executable
      prot &= ~PROT_EXEC;
    }
#if defined(__aarch64__)
    if ((prot & PROT_EXEC) == 0) {
      // Though it is not specified don't add PROT_BTI if segment is not
      // executable.
      prot &= ~PROT_BTI;
    }
#endif

    int ret =
        mprotect(reinterpret_cast<void*>(seg_page_start), seg_page_end - seg_page_start, prot);
    if (ret < 0) {
      return -1;
    }
  }
  return 0;
}

/* Restore the original protection modes for all loadable segments.
 * You should only call this after phdr_table_unprotect_segments and
 * applying all relocations.
 *
 * AArch64: also called from linker_main and ElfReader::Load to apply
 *     PROT_BTI for loaded main so and other so-s.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 *   should_pad_segments -> Are segments extended to avoid gaps in the memory map
 *   should_use_16kib_app_compat -> Is the ELF being loaded in 16KiB app compat mode.
 *   prop        -> GnuPropertySection or nullptr
 * Return:
 *   0 on success, -1 on failure (error code in errno).
 */
int phdr_table_protect_segments(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                ElfW(Addr) load_bias, bool should_pad_segments,
                                bool should_use_16kib_app_compat,
                                const GnuPropertySection* prop __unused) {
  int prot = 0;
#if defined(__aarch64__)
  if ((prop != nullptr) && prop->IsBTICompatible()) {
    prot |= PROT_BTI;
  }
#endif
  return _phdr_table_set_load_prot(phdr_table, phdr_count, load_bias, prot, should_pad_segments,
                                   should_use_16kib_app_compat);
}

static bool segment_needs_memtag_globals_remapping(const ElfW(Phdr) * phdr) {
  // For now, MTE globals is only supported on writeable data segments.
  return phdr->p_type == PT_LOAD && !(phdr->p_flags & PF_X) && (phdr->p_flags & PF_W);
}

/* When MTE globals are requested by the binary, and when the hardware supports
 * it, remap the executable's PT_LOAD data pages to have PROT_MTE.
 *
 * Returns 0 on success, -1 on failure (error code in errno).
 */
int remap_memtag_globals_segments(const ElfW(Phdr) * phdr_table __unused,
                                  size_t phdr_count __unused, ElfW(Addr) load_bias __unused) {
#if defined(__aarch64__)
  for (const ElfW(Phdr)* phdr = phdr_table; phdr < phdr_table + phdr_count; phdr++) {
    if (!segment_needs_memtag_globals_remapping(phdr)) {
      continue;
    }

    uintptr_t seg_page_start = page_start(phdr->p_vaddr) + load_bias;
    uintptr_t seg_page_end = page_end(phdr->p_vaddr + phdr->p_memsz) + load_bias;
    size_t seg_page_aligned_size = seg_page_end - seg_page_start;

    int prot = PFLAGS_TO_PROT(phdr->p_flags);
    // For anonymous private mappings, it may be possible to simply mprotect()
    // the PROT_MTE flag over the top. For file-based mappings, this will fail,
    // and we'll need to fall back. We also allow PROT_WRITE here to allow
    // writing memory tags (in `soinfo::tag_globals()`), and set these sections
    // back to read-only after tags are applied (similar to RELRO).
    prot |= PROT_MTE;
    if (mprotect(reinterpret_cast<void*>(seg_page_start), seg_page_aligned_size,
                 prot | PROT_WRITE) == 0) {
      continue;
    }

    void* mapping_copy = mmap(nullptr, seg_page_aligned_size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    linker_memcpy(mapping_copy, reinterpret_cast<void*>(seg_page_start), seg_page_aligned_size);

    void* seg_addr = mmap(reinterpret_cast<void*>(seg_page_start), seg_page_aligned_size,
                          prot | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (seg_addr == MAP_FAILED) return -1;

    linker_memcpy(seg_addr, mapping_copy, seg_page_aligned_size);
    munmap(mapping_copy, seg_page_aligned_size);
  }
#endif  // defined(__aarch64__)
  return 0;
}

void protect_memtag_globals_ro_segments(const ElfW(Phdr) * phdr_table __unused,
                                        size_t phdr_count __unused, ElfW(Addr) load_bias __unused) {
#if defined(__aarch64__)
  for (const ElfW(Phdr)* phdr = phdr_table; phdr < phdr_table + phdr_count; phdr++) {
    int prot = PFLAGS_TO_PROT(phdr->p_flags);
    if (!segment_needs_memtag_globals_remapping(phdr) || (prot & PROT_WRITE)) {
      continue;
    }

    prot |= PROT_MTE;

    uintptr_t seg_page_start = page_start(phdr->p_vaddr) + load_bias;
    uintptr_t seg_page_end = page_end(phdr->p_vaddr + phdr->p_memsz) + load_bias;
    size_t seg_page_aligned_size = seg_page_end - seg_page_start;
    mprotect(reinterpret_cast<void*>(seg_page_start), seg_page_aligned_size, prot);
  }
#endif  // defined(__aarch64__)
}

void name_memtag_globals_segments(const ElfW(Phdr) * phdr_table, size_t phdr_count,
                                  ElfW(Addr) load_bias, const char* soname,
                                  std::list<std::string>* vma_names) {
  for (const ElfW(Phdr)* phdr = phdr_table; phdr < phdr_table + phdr_count; phdr++) {
    if (!segment_needs_memtag_globals_remapping(phdr)) {
      continue;
    }

    uintptr_t seg_page_start = page_start(phdr->p_vaddr) + load_bias;
    uintptr_t seg_page_end = page_end(phdr->p_vaddr + phdr->p_memsz) + load_bias;
    size_t seg_page_aligned_size = seg_page_end - seg_page_start;

    // For file-based mappings that we're now forcing to be anonymous mappings, set the VMA name to
    // make debugging easier.
    // Once we are targeting only devices that run kernel 5.10 or newer (and thus include
    // https://android-review.git.corp.google.com/c/kernel/common/+/1934723 which causes the
    // VMA_ANON_NAME to be copied into the kernel), we can get rid of the storage here.
    // For now, that is not the case:
    // https://source.android.com/docs/core/architecture/kernel/android-common#compatibility-matrix
    constexpr int kVmaNameLimit = 80;
    std::string& vma_name = vma_names->emplace_back(kVmaNameLimit, '\0');
    int full_vma_length =
        async_safe_format_buffer(vma_name.data(), kVmaNameLimit, "mt:%s+%" PRIxPTR, soname,
                                 page_start(phdr->p_vaddr)) +
        /* include the null terminator */ 1;
    // There's an upper limit of 80 characters, including the null terminator, in the anonymous VMA
    // name. If we run over that limit, we end up truncating the segment offset and parts of the
    // DSO's name, starting on the right hand side of the basename. Because the basename is the most
    // important thing, chop off the soname from the left hand side first.
    //
    // Example (with '#' as the null terminator):
    //   - "mt:/data/nativetest64/bionic-unit-tests/bionic-loader-test-libs/libdlext_test.so+e000#"
    //     is a `full_vma_length` == 86.
    //
    // We need to left-truncate (86 - 80) 6 characters from the soname, plus the
    // `vma_truncation_prefix`, so 9 characters total.
    if (full_vma_length > kVmaNameLimit) {
      const char vma_truncation_prefix[] = "...";
      int soname_truncated_bytes =
          full_vma_length - kVmaNameLimit + sizeof(vma_truncation_prefix) - 1;
      async_safe_format_buffer(vma_name.data(), kVmaNameLimit, "mt:%s%s+%" PRIxPTR,
                               vma_truncation_prefix, soname + soname_truncated_bytes,
                               page_start(phdr->p_vaddr));
    }
    if (prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, reinterpret_cast<void*>(seg_page_start),
              seg_page_aligned_size, vma_name.data()) != 0) {
      DL_WARN("Failed to rename memtag global segment: %m");
    }
  }
}

/* Change the protection of all loaded segments in memory to writable.
 * This is useful before performing relocations. Once completed, you
 * will have to call phdr_table_protect_segments to restore the original
 * protection flags on all segments.
 *
 * Note that some writable segments can also have their content turned
 * to read-only by calling phdr_table_protect_gnu_relro. This is no
 * performed here.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 *   should_pad_segments -> Are segments extended to avoid gaps in the memory map
 *   should_use_16kib_app_compat -> Is the ELF being loaded in 16KiB app compat mode.
 * Return:
 *   0 on success, -1 on failure (error code in errno).
 */
int phdr_table_unprotect_segments(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                  ElfW(Addr) load_bias, bool should_pad_segments,
                                  bool should_use_16kib_app_compat) {
  return _phdr_table_set_load_prot(phdr_table, phdr_count, load_bias, PROT_WRITE,
                                   should_pad_segments, should_use_16kib_app_compat);
}

static inline void _extend_gnu_relro_prot_end(const ElfW(Phdr)* relro_phdr,
                                              const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                              ElfW(Addr) load_bias, ElfW(Addr)* seg_page_end,
                                              bool should_pad_segments,
                                              bool should_use_16kib_app_compat) {
  // Find the index and phdr of the LOAD containing the GNU_RELRO segment
  for (size_t index = 0; index < phdr_count; ++index) {
    const ElfW(Phdr)* phdr = &phdr_table[index];

    if (phdr->p_type == PT_LOAD && phdr->p_vaddr == relro_phdr->p_vaddr) {
      // If the PT_GNU_RELRO mem size is not at least as large as the corresponding
      // LOAD segment mem size, we need to protect only a partial region of the
      // LOAD segment and therefore cannot avoid a VMA split.
      //
      // Note: Don't check the page-aligned mem sizes since the extended protection
      // may incorrectly write protect non-relocation data.
      //
      // Example:
      //
      //               |---- 3K ----|-- 1K --|---- 3K ---- |-- 1K --|
      //       ----------------------------------------------------------------
      //               |            |        |             |        |
      //        SEG X  |     RO     |   RO   |     RW      |        |   SEG Y
      //               |            |        |             |        |
      //       ----------------------------------------------------------------
      //                            |        |             |
      //                            |        |             |
      //                            |        |             |
      //                    relro_vaddr   relro_vaddr   relro_vaddr
      //                    (load_vaddr)       +            +
      //                                  relro_memsz   load_memsz
      //
      //       ----------------------------------------------------------------
      //               |         PAGE        |         PAGE         |
      //       ----------------------------------------------------------------
      //                                     |       Potential      |
      //                                     |----- Extended RO ----|
      //                                     |      Protection      |
      //
      // If the check below uses  page aligned mem sizes it will cause incorrect write
      // protection of the 3K RW part of the LOAD segment containing the GNU_RELRO.
      if (relro_phdr->p_memsz < phdr->p_memsz) {
        return;
      }

      ElfW(Addr) p_memsz = phdr->p_memsz;
      ElfW(Addr) p_filesz = phdr->p_filesz;

      // Attempt extending the VMA (mprotect range). Without extending the range,
      // mprotect will only RO protect a part of the extended RW LOAD segment, which
      // will leave an extra split RW VMA (the gap).
      _extend_load_segment_vma(phdr_table, phdr_count, index, &p_memsz, &p_filesz,
                               should_pad_segments, should_use_16kib_app_compat);

      *seg_page_end = page_end(phdr->p_vaddr + p_memsz + load_bias);
      return;
    }
  }
}

/* Used internally by phdr_table_protect_gnu_relro and
 * phdr_table_unprotect_gnu_relro.
 */
static int _phdr_table_set_gnu_relro_prot(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                          ElfW(Addr) load_bias, int prot_flags,
                                          bool should_pad_segments,
                                          bool should_use_16kib_app_compat) {
  const ElfW(Phdr)* phdr = phdr_table;
  const ElfW(Phdr)* phdr_limit = phdr + phdr_count;

  for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
    if (phdr->p_type != PT_GNU_RELRO) {
      continue;
    }

    // Tricky: what happens when the relro segment does not start
    // or end at page boundaries? We're going to be over-protective
    // here and put every page touched by the segment as read-only.

    // This seems to match Ian Lance Taylor's description of the
    // feature at http://www.airs.com/blog/archives/189.

    //    Extract:
    //       Note that the current dynamic linker code will only work
    //       correctly if the PT_GNU_RELRO segment starts on a page
    //       boundary. This is because the dynamic linker rounds the
    //       p_vaddr field down to the previous page boundary. If
    //       there is anything on the page which should not be read-only,
    //       the program is likely to fail at runtime. So in effect the
    //       linker must only emit a PT_GNU_RELRO segment if it ensures
    //       that it starts on a page boundary.
    ElfW(Addr) seg_page_start = page_start(phdr->p_vaddr) + load_bias;
    ElfW(Addr) seg_page_end = page_end(phdr->p_vaddr + phdr->p_memsz) + load_bias;
    _extend_gnu_relro_prot_end(phdr, phdr_table, phdr_count, load_bias, &seg_page_end,
                               should_pad_segments, should_use_16kib_app_compat);

    int ret = mprotect(reinterpret_cast<void*>(seg_page_start),
                       seg_page_end - seg_page_start,
                       prot_flags);
    if (ret < 0) {
      return -1;
    }
  }
  return 0;
}

/* Apply GNU relro protection if specified by the program header. This will
 * turn some of the pages of a writable PT_LOAD segment to read-only, as
 * specified by one or more PT_GNU_RELRO segments. This must be always
 * performed after relocations.
 *
 * The areas typically covered are .got and .data.rel.ro, these are
 * read-only from the program's POV, but contain absolute addresses
 * that need to be relocated before use.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 *   should_pad_segments -> Were segments extended to avoid gaps in the memory map
 *   should_use_16kib_app_compat -> Is the ELF being loaded in 16KiB app compat mode.
 * Return:
 *   0 on success, -1 on failure (error code in errno).
 */
int phdr_table_protect_gnu_relro(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                 ElfW(Addr) load_bias, bool should_pad_segments,
                                 bool should_use_16kib_app_compat) {
  return _phdr_table_set_gnu_relro_prot(phdr_table, phdr_count, load_bias, PROT_READ,
                                        should_pad_segments, should_use_16kib_app_compat);
}

/*
 * Apply RX protection to the compat relro region of the ELF being loaded in
 * 16KiB compat mode.
 *
 * Input:
 *   start  -> start address of the compat relro region.
 *   size   -> size of the compat relro region in bytes.
 * Return:
 *   0 on success, -1 on failure (error code in errno).
 */
int phdr_table_protect_gnu_relro_16kib_compat(ElfW(Addr) start, ElfW(Addr) size) {
  return mprotect(reinterpret_cast<void*>(start), size, PROT_READ | PROT_EXEC);
}

/* Serialize the GNU relro segments to the given file descriptor. This can be
 * performed after relocations to allow another process to later share the
 * relocated segment, if it was loaded at the same address.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 *   fd          -> writable file descriptor to use
 *   file_offset -> pointer to offset into file descriptor to use/update
 * Return:
 *   0 on success, -1 on failure (error code in errno).
 */
int phdr_table_serialize_gnu_relro(const ElfW(Phdr)* phdr_table,
                                   size_t phdr_count,
                                   ElfW(Addr) load_bias,
                                   int fd,
                                   size_t* file_offset) {
  const ElfW(Phdr)* phdr = phdr_table;
  const ElfW(Phdr)* phdr_limit = phdr + phdr_count;

  for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
    if (phdr->p_type != PT_GNU_RELRO) {
      continue;
    }

    ElfW(Addr) seg_page_start = page_start(phdr->p_vaddr) + load_bias;
    ElfW(Addr) seg_page_end = page_end(phdr->p_vaddr + phdr->p_memsz) + load_bias;
    ssize_t size = seg_page_end - seg_page_start;

    ssize_t written = TEMP_FAILURE_RETRY(write(fd, reinterpret_cast<void*>(seg_page_start), size));
    if (written != size) {
      return -1;
    }
    void* map = mmap(reinterpret_cast<void*>(seg_page_start), size, PROT_READ,
                     MAP_PRIVATE|MAP_FIXED, fd, *file_offset);
    if (map == MAP_FAILED) {
      return -1;
    }
    *file_offset += size;
  }
  return 0;
}

/* Where possible, replace the GNU relro segments with mappings of the given
 * file descriptor. This can be performed after relocations to allow a file
 * previously created by phdr_table_serialize_gnu_relro in another process to
 * replace the dirty relocated pages, saving memory, if it was loaded at the
 * same address. We have to compare the data before we map over it, since some
 * parts of the relro segment may not be identical due to other libraries in
 * the process being loaded at different addresses.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 *   fd          -> readable file descriptor to use
 *   file_offset -> pointer to offset into file descriptor to use/update
 * Return:
 *   0 on success, -1 on failure (error code in errno).
 */
int phdr_table_map_gnu_relro(const ElfW(Phdr)* phdr_table,
                             size_t phdr_count,
                             ElfW(Addr) load_bias,
                             int fd,
                             size_t* file_offset) {
  // Map the file at a temporary location so we can compare its contents.
  struct stat file_stat;
  if (TEMP_FAILURE_RETRY(fstat(fd, &file_stat)) != 0) {
    return -1;
  }
  off_t file_size = file_stat.st_size;
  void* temp_mapping = nullptr;
  if (file_size > 0) {
    temp_mapping = mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (temp_mapping == MAP_FAILED) {
      return -1;
    }
  }

  // Iterate over the relro segments and compare/remap the pages.
  const ElfW(Phdr)* phdr = phdr_table;
  const ElfW(Phdr)* phdr_limit = phdr + phdr_count;

  for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
    if (phdr->p_type != PT_GNU_RELRO) {
      continue;
    }

    ElfW(Addr) seg_page_start = page_start(phdr->p_vaddr) + load_bias;
    ElfW(Addr) seg_page_end = page_end(phdr->p_vaddr + phdr->p_memsz) + load_bias;

    char* file_base = static_cast<char*>(temp_mapping) + *file_offset;
    char* mem_base = reinterpret_cast<char*>(seg_page_start);
    size_t match_offset = 0;
    size_t size = seg_page_end - seg_page_start;

    if (file_size - *file_offset < size) {
      // File is too short to compare to this segment. The contents are likely
      // different as well (it's probably for a different library version) so
      // just don't bother checking.
      break;
    }

    while (match_offset < size) {
      // Skip over dissimilar pages.
      while (match_offset < size &&
             memcmp(mem_base + match_offset, file_base + match_offset, page_size()) != 0) {
        match_offset += page_size();
      }

      // Count similar pages.
      size_t mismatch_offset = match_offset;
      while (mismatch_offset < size &&
             memcmp(mem_base + mismatch_offset, file_base + mismatch_offset, page_size()) == 0) {
        mismatch_offset += page_size();
      }

      // Map over similar pages.
      if (mismatch_offset > match_offset) {
        void* map = mmap(mem_base + match_offset, mismatch_offset - match_offset,
                         PROT_READ, MAP_PRIVATE|MAP_FIXED, fd, *file_offset + match_offset);
        if (map == MAP_FAILED) {
          munmap(temp_mapping, file_size);
          return -1;
        }
      }

      match_offset = mismatch_offset;
    }

    // Add to the base file offset in case there are multiple relro segments.
    *file_offset += size;
  }
  munmap(temp_mapping, file_size);
  return 0;
}


#if defined(__arm__)
/* Return the address and size of the .ARM.exidx section in memory,
 * if present.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 * Output:
 *   arm_exidx       -> address of table in memory (null on failure).
 *   arm_exidx_count -> number of items in table (0 on failure).
 * Return:
 *   0 on success, -1 on failure (_no_ error code in errno)
 */
int phdr_table_get_arm_exidx(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                             ElfW(Addr) load_bias,
                             ElfW(Addr)** arm_exidx, size_t* arm_exidx_count) {
  const ElfW(Phdr)* phdr = phdr_table;
  const ElfW(Phdr)* phdr_limit = phdr + phdr_count;

  for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
    if (phdr->p_type != PT_ARM_EXIDX) {
      continue;
    }

    *arm_exidx = reinterpret_cast<ElfW(Addr)*>(load_bias + phdr->p_vaddr);
    *arm_exidx_count = phdr->p_memsz / 8;
    return 0;
  }
  *arm_exidx = nullptr;
  *arm_exidx_count = 0;
  return -1;
}
#endif

/* Return the address and size of the ELF file's .dynamic section in memory,
 * or null if missing.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 * Output:
 *   dynamic       -> address of table in memory (null on failure).
 *   dynamic_flags -> protection flags for section (unset on failure)
 * Return:
 *   void
 */
void phdr_table_get_dynamic_section(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                    ElfW(Addr) load_bias, ElfW(Dyn)** dynamic,
                                    ElfW(Word)* dynamic_flags) {
  *dynamic = nullptr;
  for (size_t i = 0; i<phdr_count; ++i) {
    const ElfW(Phdr)& phdr = phdr_table[i];
    if (phdr.p_type == PT_DYNAMIC) {
      *dynamic = reinterpret_cast<ElfW(Dyn)*>(load_bias + phdr.p_vaddr);
      if (dynamic_flags) {
        *dynamic_flags = phdr.p_flags;
      }
      return;
    }
  }
}

/* Return the program interpreter string, or nullptr if missing.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 * Return:
 *   pointer to the program interpreter string.
 */
const char* phdr_table_get_interpreter_name(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                            ElfW(Addr) load_bias) {
  for (size_t i = 0; i<phdr_count; ++i) {
    const ElfW(Phdr)& phdr = phdr_table[i];
    if (phdr.p_type == PT_INTERP) {
      return reinterpret_cast<const char*>(load_bias + phdr.p_vaddr);
    }
  }
  return nullptr;
}

// Sets loaded_phdr_ to the address of the program header table as it appears
// in the loaded segments in memory. This is in contrast with phdr_table_,
// which is temporary and will be released before the library is relocated.
bool ElfReader::FindPhdr() {
  const ElfW(Phdr)* phdr_limit = phdr_table_ + phdr_num_;

  // If there is a PT_PHDR, use it directly.
  for (const ElfW(Phdr)* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
    if (phdr->p_type == PT_PHDR) {
      return CheckPhdr(load_bias_ + phdr->p_vaddr);
    }
  }

  // Otherwise, check the first loadable segment. If its file offset
  // is 0, it starts with the ELF header, and we can trivially find the
  // loaded program header from it.
  for (const ElfW(Phdr)* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
    if (phdr->p_type == PT_LOAD) {
      if (phdr->p_offset == 0) {
        ElfW(Addr)  elf_addr = load_bias_ + phdr->p_vaddr;
        const ElfW(Ehdr)* ehdr = reinterpret_cast<const ElfW(Ehdr)*>(elf_addr);
        ElfW(Addr)  offset = ehdr->e_phoff;
        return CheckPhdr(reinterpret_cast<ElfW(Addr)>(ehdr) + offset);
      }
      break;
    }
  }

  DL_ERR("can't find loaded phdr for \"%s\"", name_.c_str());
  return false;
}

// Tries to find .note.gnu.property section.
// It is not considered an error if such section is missing.
bool ElfReader::FindGnuPropertySection() {
#if defined(__aarch64__)
  note_gnu_property_ = GnuPropertySection(phdr_table_, phdr_num_, load_start(), name_.c_str());
#endif
  return true;
}

// Ensures that our program header is actually within a loadable
// segment. This should help catch badly-formed ELF files that
// would cause the linker to crash later wh
```