Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript examples.

1. **Understanding the Core Goal:** The filename `embedded-data.cc` and the namespace `v8::internal::snapshot::embedded` immediately suggest this code is about embedding data within the V8 snapshot. The presence of terms like "blob," "code," and "data" reinforces this. The "snapshot" part hints at storing a state of the V8 engine.

2. **Initial Skimming for Key Concepts:**  A quick read-through reveals the following recurring themes:
    * **Builtins:**  The code frequently mentions "Builtin," `Builtins::kFirst`, `Builtins::kLast`, etc. This signifies that the data being embedded relates to V8's built-in JavaScript functions.
    * **Code and Data:** There's a clear separation between "code" and "data" sections. This is a common pattern in compiled environments.
    * **Addresses and Offsets:**  Variables like `address`, `offset`, `code_size`, `data_size`, and functions like `InstructionStartOf` indicate low-level memory management and layout.
    * **Isolate Independence:** The code checks for and enforces "isolate independence" of builtins. This suggests the embedded data should be reusable across different V8 isolates (instances).
    * **Hashing:**  Functions like `CreateEmbeddedBlobDataHash` and `CreateEmbeddedBlobCodeHash` suggest integrity checks.
    * **Memory Allocation:**  Functions like `AllocatePages` and `FreePages` are used for managing native memory.
    * **Relocation:** The code deals with relocating code targets, essential for making the embedded code work at different memory locations.

3. **Focusing on Key Functions and Classes:**  The `EmbeddedData` class is central. Let's look at its methods:
    * `TryLookupCode`:  This seems to map an address to a `Builtin`. This is likely how V8 finds the corresponding builtin function in the embedded blob.
    * `NewFromIsolate`: This is likely responsible for *creating* the embedded data blob from the current state of an `Isolate`.
    * `InstructionStartOf`, `InstructionSizeOf`, `PaddedInstructionSizeOf`: These are utility functions for getting information about the layout of builtins.
    * Hashing functions:  For creating checksums.
    * `PrintStatistics`: For debugging and understanding the size distribution of embedded code.

4. **Connecting to JavaScript Functionality:**  The crucial link is the "Builtin."  Builtins are the fundamental JavaScript functions implemented in C++. Therefore, this code is about embedding the *compiled code* of these builtins. When JavaScript code calls a built-in function like `Array.prototype.push`, V8 needs to execute the corresponding C++ implementation. The embedded data provides a way to store this compiled code.

5. **Formulating the Summary:** Based on the above analysis, we can construct a summary that highlights the core functionality: creating, managing, and accessing an embedded blob containing pre-compiled built-in JavaScript functions. It's important to mention the optimization aspects (faster startup, reduced memory) and the "isolate independence" concept.

6. **Generating JavaScript Examples:**  To illustrate the connection to JavaScript, we need to identify common built-in functions. Examples like `Array.prototype.push`, `String.prototype.toUpperCase`, `parseInt`, and `Promise` are good choices because they are frequently used and represent different categories of built-ins. The explanation should clearly link these JavaScript functions to their underlying C++ implementations stored in the embedded data.

7. **Addressing Potential Nuances:** The code mentions "short builtin calls" and shared pointer compression. These are more advanced optimizations, and while not essential for the core summary, they can be included as more technical details.

8. **Review and Refinement:**  Read through the summary and examples to ensure clarity, accuracy, and conciseness. Check for any jargon that needs explanation. For instance, explaining what a "blob" is in this context can be helpful. Ensuring the JavaScript examples are valid and easy to understand is also crucial.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe it's just about storing some metadata.
* **Correction:** The presence of "code" and relocation information strongly suggests it's about executable code.
* **Initial phrasing:** "This file manages built-in functions."
* **Refinement:** "This file manages the *embedded representation* of built-in functions,"  to be more precise about the context of the file.
* **Considering the audience:**  The explanation should be accessible to someone with a basic understanding of how JavaScript engines work, without requiring deep C++ knowledge.

By following these steps, we can systematically analyze the C++ code and generate a comprehensive and informative summary along with illustrative JavaScript examples.
这个C++源代码文件 `embedded-data.cc` 的主要功能是 **创建和管理 V8 引擎中嵌入的内置 (built-in) JavaScript 函数的代码和数据**。  它负责将这些预编译好的、常用的 JavaScript 功能打包成一个“嵌入式 blob”，以便 V8 引擎启动时可以快速访问，而无需从磁盘加载或即时编译。

更具体地说，这个文件实现了 `EmbeddedData` 类，该类封装了对这个嵌入式 blob 的操作。 它的核心职责包括：

1. **创建嵌入式 Blob:**  `EmbeddedData::NewFromIsolate(Isolate* isolate)` 函数负责从当前的 V8 引擎实例 (`Isolate`) 中收集所有标记为“独立于 Isolate”的内置函数的编译后的代码和元数据，并将它们组织成一个连续的内存区域（blob）。

2. **布局管理:** 它定义了嵌入式 blob 的内部结构，包括代码段和数据段的布局，以及如何查找特定内置函数的代码和元数据。它使用 `LayoutDescription` 和 `BuiltinLookupEntry` 结构来记录每个内置函数在 blob 中的偏移量和大小。

3. **代码重定位 (Relocation):**  由于嵌入式 blob 加载到内存的地址可能不同，该文件处理了内置函数内部代码的重定位。 特别是，它会修复代码中对其他内置函数的调用目标地址，确保它们在嵌入式 blob 中的相对位置是正确的。

4. **内存管理:**  它涉及到嵌入式 blob 的内存分配和释放，包括在堆外分配内存来存储 blob。

5. **查找内置函数:** `EmbeddedData::TryLookupCode(Address address)` 函数允许根据给定的内存地址，快速查找对应的内置函数。这在 V8 引擎执行代码时非常重要。

6. **哈希校验:**  为了确保嵌入式 blob 的完整性，该文件还实现了生成和校验 blob 内容哈希值的功能。

7. **优化:** 将内置函数嵌入到引擎中是 V8 的一项重要优化，可以显著提升启动速度和降低内存占用。

**与 JavaScript 功能的关系及 JavaScript 示例：**

这个文件直接关系到 V8 引擎执行 JavaScript 代码的能力，因为 **内置函数是 JavaScript 语言的核心组成部分**。  例如，JavaScript 中的 `Array.prototype.push`、`String.prototype.toUpperCase`、`parseInt`、`Promise` 等等都是由 C++ 实现的内置函数。

`embedded-data.cc` 中创建的嵌入式 blob 就包含了这些内置函数的编译后的机器码。 当 JavaScript 代码调用这些内置函数时，V8 引擎会直接执行 blob 中对应的代码。

**JavaScript 示例：**

```javascript
// 这是一个 JavaScript 例子，它会调用一些 V8 的内置函数

const arr = [1, 2, 3];
arr.push(4); // 调用 Array.prototype.push 内置函数

const str = "hello";
const upperStr = str.toUpperCase(); // 调用 String.prototype.toUpperCase 内置函数

const num = parseInt("10"); // 调用 parseInt 内置函数

const promise = new Promise((resolve, reject) => {
  setTimeout(resolve, 100);
}); // 调用 Promise 相关的内置函数
```

**解释：**

当上面的 JavaScript 代码在 V8 引擎中运行时，对于 `arr.push(4)` 这行代码，V8 引擎会执行以下步骤（简化）：

1. 识别 `push` 是 `Array.prototype` 的一个方法。
2. 查找 `Array.prototype.push` 对应的内置函数的地址。这个地址就存储在 `embedded-data.cc` 创建的嵌入式 blob 中。
3. 跳转到嵌入式 blob 中 `push` 函数的机器码开始执行。
4. 执行 C++ 实现的 `push` 函数逻辑，将元素 `4` 添加到数组 `arr` 中。

类似地，`toUpperCase`、`parseInt` 和 `Promise` 的创建和操作也都依赖于嵌入式 blob 中存储的相应的内置函数代码。

**总结：**

`v8/src/snapshot/embedded/embedded-data.cc` 是 V8 引擎中一个关键的组件，它负责将常用的 JavaScript 内置函数预编译并嵌入到引擎中，从而极大地提升了 JavaScript 代码的执行效率和引擎的启动速度。它通过精心设计的内存布局和重定位机制，使得这些内置函数能够在不同的 V8 实例中高效可靠地运行。

Prompt: 
```
这是目录为v8/src/snapshot/embedded/embedded-data.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/snapshot/embedded/embedded-data.h"

#include "src/codegen/assembler-inl.h"
#include "src/codegen/callable.h"
#include "src/snapshot/embedded/embedded-data-inl.h"
#include "src/snapshot/snapshot-utils.h"
#include "src/snapshot/sort-builtins.h"

namespace v8 {
namespace internal {

Builtin EmbeddedData::TryLookupCode(Address address) const {
  if (!IsInCodeRange(address)) return Builtin::kNoBuiltinId;

  // Note: Addresses within the padding section between builtins (i.e. within
  // start + size <= address < start + padded_size) are interpreted as belonging
  // to the preceding builtin.
  uint32_t offset =
      static_cast<uint32_t>(address - reinterpret_cast<Address>(RawCode()));

  const struct BuiltinLookupEntry* start =
      BuiltinLookupEntry(static_cast<ReorderedBuiltinIndex>(0));
  const struct BuiltinLookupEntry* end = start + kTableSize;
  const struct BuiltinLookupEntry* desc =
      std::upper_bound(start, end, offset,
                       [](uint32_t o, const struct BuiltinLookupEntry& desc) {
                         return o < desc.end_offset;
                       });
  Builtin builtin = static_cast<Builtin>(desc->builtin_id);
  DCHECK_LT(address,
            InstructionStartOf(builtin) + PaddedInstructionSizeOf(builtin));
  DCHECK_GE(address, InstructionStartOf(builtin));
  return builtin;
}

// static
bool OffHeapInstructionStream::PcIsOffHeap(Isolate* isolate, Address pc) {
  // Mksnapshot calls this while the embedded blob is not available yet.
  if (isolate->embedded_blob_code() == nullptr) return false;
  DCHECK_NOT_NULL(Isolate::CurrentEmbeddedBlobCode());

  if (EmbeddedData::FromBlob(isolate).IsInCodeRange(pc)) return true;
  return isolate->is_short_builtin_calls_enabled() &&
         EmbeddedData::FromBlob().IsInCodeRange(pc);
}

// static
bool OffHeapInstructionStream::TryGetAddressForHashing(
    Isolate* isolate, Address address, uint32_t* hashable_address) {
  // Mksnapshot calls this while the embedded blob is not available yet.
  if (isolate->embedded_blob_code() == nullptr) return false;
  DCHECK_NOT_NULL(Isolate::CurrentEmbeddedBlobCode());

  EmbeddedData d = EmbeddedData::FromBlob(isolate);
  if (d.IsInCodeRange(address)) {
    *hashable_address = d.AddressForHashing(address);
    return true;
  }

  if (isolate->is_short_builtin_calls_enabled()) {
    d = EmbeddedData::FromBlob();
    if (d.IsInCodeRange(address)) {
      *hashable_address = d.AddressForHashing(address);
      return true;
    }
  }
  return false;
}

// static
Builtin OffHeapInstructionStream::TryLookupCode(Isolate* isolate,
                                                Address address) {
  // Mksnapshot calls this while the embedded blob is not available yet.
  if (isolate->embedded_blob_code() == nullptr) return Builtin::kNoBuiltinId;
  DCHECK_NOT_NULL(Isolate::CurrentEmbeddedBlobCode());

  Builtin builtin = EmbeddedData::FromBlob(isolate).TryLookupCode(address);

  if (isolate->is_short_builtin_calls_enabled() &&
      !Builtins::IsBuiltinId(builtin)) {
    builtin = EmbeddedData::FromBlob().TryLookupCode(address);
  }

#ifdef V8_COMPRESS_POINTERS_IN_SHARED_CAGE
  if (V8_SHORT_BUILTIN_CALLS_BOOL && !Builtins::IsBuiltinId(builtin)) {
    // When shared pointer compression cage is enabled and it has the embedded
    // code blob copy then it could have been used regardless of whether the
    // isolate uses it or knows about it or not (see
    // InstructionStream::OffHeapInstructionStart()).
    // So, this blob has to be checked too.
    CodeRange* code_range = IsolateGroup::current()->GetCodeRange();
    if (code_range && code_range->embedded_blob_code_copy() != nullptr) {
      builtin = EmbeddedData::FromBlob(code_range).TryLookupCode(address);
    }
  }
#endif
  return builtin;
}

// static
void OffHeapInstructionStream::CreateOffHeapOffHeapInstructionStream(
    Isolate* isolate, uint8_t** code, uint32_t* code_size, uint8_t** data,
    uint32_t* data_size) {
  // Create the embedded blob from scratch using the current Isolate's heap.
  EmbeddedData d = EmbeddedData::NewFromIsolate(isolate);

  // Allocate the backing store that will contain the embedded blob in this
  // Isolate. The backing store is on the native heap, *not* on V8's garbage-
  // collected heap.
  v8::PageAllocator* page_allocator = v8::internal::GetPlatformPageAllocator();
  const uint32_t alignment =
      static_cast<uint32_t>(page_allocator->AllocatePageSize());

  void* const requested_allocation_code_address =
      AlignedAddress(isolate->heap()->GetRandomMmapAddr(), alignment);
  const uint32_t allocation_code_size = RoundUp(d.code_size(), alignment);
  uint8_t* allocated_code_bytes = static_cast<uint8_t*>(AllocatePages(
      page_allocator, requested_allocation_code_address, allocation_code_size,
      alignment, PageAllocator::kReadWrite));
  CHECK_NOT_NULL(allocated_code_bytes);

  void* const requested_allocation_data_address =
      AlignedAddress(isolate->heap()->GetRandomMmapAddr(), alignment);
  const uint32_t allocation_data_size = RoundUp(d.data_size(), alignment);
  uint8_t* allocated_data_bytes = static_cast<uint8_t*>(AllocatePages(
      page_allocator, requested_allocation_data_address, allocation_data_size,
      alignment, PageAllocator::kReadWrite));
  CHECK_NOT_NULL(allocated_data_bytes);

  // Copy the embedded blob into the newly allocated backing store. Switch
  // permissions to read-execute since builtin code is immutable from now on
  // and must be executable in case any JS execution is triggered.
  //
  // Once this backing store is set as the current_embedded_blob, V8 cannot tell
  // the difference between a 'real' embedded build (where the blob is embedded
  // in the binary) and what we are currently setting up here (where the blob is
  // on the native heap).
  std::memcpy(allocated_code_bytes, d.code(), d.code_size());
  if (v8_flags.experimental_flush_embedded_blob_icache) {
    FlushInstructionCache(allocated_code_bytes, d.code_size());
  }
  CHECK(SetPermissions(page_allocator, allocated_code_bytes,
                       allocation_code_size, PageAllocator::kReadExecute));

  std::memcpy(allocated_data_bytes, d.data(), d.data_size());
  CHECK(SetPermissions(page_allocator, allocated_data_bytes,
                       allocation_data_size, PageAllocator::kRead));

  *code = allocated_code_bytes;
  *code_size = d.code_size();
  *data = allocated_data_bytes;
  *data_size = d.data_size();

  d.Dispose();
}

// static
void OffHeapInstructionStream::FreeOffHeapOffHeapInstructionStream(
    uint8_t* code, uint32_t code_size, uint8_t* data, uint32_t data_size) {
  v8::PageAllocator* page_allocator = v8::internal::GetPlatformPageAllocator();
  const uint32_t page_size =
      static_cast<uint32_t>(page_allocator->AllocatePageSize());
  FreePages(page_allocator, code, RoundUp(code_size, page_size));
  FreePages(page_allocator, data, RoundUp(data_size, page_size));
}

namespace {

void FinalizeEmbeddedCodeTargets(Isolate* isolate, EmbeddedData* blob) {
  static const int kRelocMask =
      RelocInfo::ModeMask(RelocInfo::CODE_TARGET) |
      RelocInfo::ModeMask(RelocInfo::RELATIVE_CODE_TARGET);

  static_assert(Builtins::kAllBuiltinsAreIsolateIndependent);
  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
       ++builtin) {
    Tagged<Code> code = isolate->builtins()->code(builtin);
    RelocIterator on_heap_it(code, kRelocMask);
    RelocIterator off_heap_it(blob, code, kRelocMask);

#if defined(V8_TARGET_ARCH_X64) || defined(V8_TARGET_ARCH_ARM64) ||     \
    defined(V8_TARGET_ARCH_ARM) || defined(V8_TARGET_ARCH_IA32) ||      \
    defined(V8_TARGET_ARCH_S390X) || defined(V8_TARGET_ARCH_RISCV64) || \
    defined(V8_TARGET_ARCH_LOONG64) || defined(V8_TARGET_ARCH_RISCV32)
    // On these platforms we emit relative builtin-to-builtin
    // jumps for isolate independent builtins in the snapshot. This fixes up the
    // relative jumps to the right offsets in the snapshot.
    // See also: InstructionStream::IsIsolateIndependent.
    while (!on_heap_it.done()) {
      DCHECK(!off_heap_it.done());

      RelocInfo* rinfo = on_heap_it.rinfo();
      DCHECK_EQ(rinfo->rmode(), off_heap_it.rinfo()->rmode());
      Tagged<Code> target_code =
          Code::FromTargetAddress(rinfo->target_address());
      CHECK(Builtins::IsIsolateIndependentBuiltin(target_code));

      // Do not emit write-barrier for off-heap writes.
      off_heap_it.rinfo()->set_off_heap_target_address(
          blob->InstructionStartOf(target_code->builtin_id()));

      on_heap_it.next();
      off_heap_it.next();
    }
    DCHECK(off_heap_it.done());
#else
    // Architectures other than x64 and arm/arm64 do not use pc-relative calls
    // and thus must not contain embedded code targets. Instead, we use an
    // indirection through the root register.
    CHECK(on_heap_it.done());
    CHECK(off_heap_it.done());
#endif
  }
}

void EnsureRelocatable(Tagged<Code> code) {
  if (code->relocation_size() == 0) return;

  // On some architectures (arm) the builtin might have a non-empty reloc
  // info containing a CONST_POOL entry. These entries don't have to be
  // updated when InstructionStream object is relocated, so it's safe to drop
  // the reloc info alltogether. If it wasn't the case then we'd have to store
  // it in the metadata.
  for (RelocIterator it(code); !it.done(); it.next()) {
    CHECK_EQ(it.rinfo()->rmode(), RelocInfo::CONST_POOL);
  }
}

}  // namespace

// static
EmbeddedData EmbeddedData::NewFromIsolate(Isolate* isolate) {
  Builtins* builtins = isolate->builtins();

  // Store instruction stream lengths and offsets.
  std::vector<struct LayoutDescription> layout_descriptions(kTableSize);
  std::vector<struct BuiltinLookupEntry> offset_descriptions(kTableSize);

  bool saw_unsafe_builtin = false;
  uint32_t raw_code_size = 0;
  uint32_t raw_data_size = 0;
  static_assert(Builtins::kAllBuiltinsAreIsolateIndependent);

  std::vector<Builtin> reordered_builtins;
  if (v8_flags.reorder_builtins &&
      BuiltinsCallGraph::Get()->all_hash_matched()) {
    DCHECK(v8_flags.turbo_profiling_input.value());
    // TODO(ishell, v8:13938): avoid the binary size overhead for non-mksnapshot
    // binaries.
    BuiltinsSorter sorter;
    std::vector<uint32_t> builtin_sizes;
    for (Builtin i = Builtins::kFirst; i <= Builtins::kLast; ++i) {
      Tagged<Code> code = builtins->code(i);
      uint32_t instruction_size =
          static_cast<uint32_t>(code->instruction_size());
      uint32_t padding_size = PadAndAlignCode(instruction_size);
      builtin_sizes.push_back(padding_size);
    }
    reordered_builtins = sorter.SortBuiltins(
        v8_flags.turbo_profiling_input.value(), builtin_sizes);
    CHECK_EQ(reordered_builtins.size(), Builtins::kBuiltinCount);
  }

  for (ReorderedBuiltinIndex embedded_index = 0;
       embedded_index < Builtins::kBuiltinCount; embedded_index++) {
    Builtin builtin;
    if (reordered_builtins.empty()) {
      builtin = static_cast<Builtin>(embedded_index);
    } else {
      builtin = reordered_builtins[embedded_index];
    }
    Tagged<Code> code = builtins->code(builtin);

    // Sanity-check that the given builtin is isolate-independent.
    if (!code->IsIsolateIndependent(isolate)) {
      saw_unsafe_builtin = true;
      fprintf(stderr, "%s is not isolate-independent.\n",
              Builtins::name(builtin));
    }

    uint32_t instruction_size = static_cast<uint32_t>(code->instruction_size());
    DCHECK_EQ(0, raw_code_size % kCodeAlignment);
    {
      // We use builtin id as index in layout_descriptions.
      const int builtin_id = static_cast<int>(builtin);
      struct LayoutDescription& layout_desc = layout_descriptions[builtin_id];
      layout_desc.instruction_offset = raw_code_size;
      layout_desc.instruction_length = instruction_size;
      layout_desc.metadata_offset = raw_data_size;
    }
    // Align the start of each section.
    raw_code_size += PadAndAlignCode(instruction_size);
    raw_data_size += PadAndAlignData(code->metadata_size());

    {
      // We use embedded index as index in offset_descriptions.
      struct BuiltinLookupEntry& offset_desc =
          offset_descriptions[embedded_index];
      offset_desc.end_offset = raw_code_size;
      offset_desc.builtin_id = static_cast<uint32_t>(builtin);
    }
  }
  CHECK_WITH_MSG(
      !saw_unsafe_builtin,
      "One or more builtins marked as isolate-independent either contains "
      "isolate-dependent code or aliases the off-heap trampoline register. "
      "If in doubt, ask jgruber@");

  // Allocate space for the code section, value-initialized to 0.
  static_assert(RawCodeOffset() == 0);
  const uint32_t blob_code_size = RawCodeOffset() + raw_code_size;
  uint8_t* const blob_code = new uint8_t[blob_code_size]();

  // Allocate space for the data section, value-initialized to 0.
  static_assert(
      IsAligned(FixedDataSize(), InstructionStream::kMetadataAlignment));
  const uint32_t blob_data_size = FixedDataSize() + raw_data_size;
  uint8_t* const blob_data = new uint8_t[blob_data_size]();

  // Initially zap the entire blob, effectively padding the alignment area
  // between two builtins with int3's (on x64/ia32).
  ZapCode(reinterpret_cast<Address>(blob_code), blob_code_size);

  // Hash relevant parts of the Isolate's heap and store the result.
  {
    static_assert(IsolateHashSize() == kSizetSize);
    const size_t hash = isolate->HashIsolateForEmbeddedBlob();
    std::memcpy(blob_data + IsolateHashOffset(), &hash, IsolateHashSize());
  }

  // Write the layout_descriptions tables.
  DCHECK_EQ(LayoutDescriptionTableSize(),
            sizeof(layout_descriptions[0]) * layout_descriptions.size());
  std::memcpy(blob_data + LayoutDescriptionTableOffset(),
              layout_descriptions.data(), LayoutDescriptionTableSize());

  // Write the builtin_offset_descriptions tables.
  DCHECK_EQ(BuiltinLookupEntryTableSize(),
            sizeof(offset_descriptions[0]) * offset_descriptions.size());
  std::memcpy(blob_data + BuiltinLookupEntryTableOffset(),
              offset_descriptions.data(), BuiltinLookupEntryTableSize());

  // .. and the variable-size data section.
  uint8_t* const raw_metadata_start = blob_data + RawMetadataOffset();
  static_assert(Builtins::kAllBuiltinsAreIsolateIndependent);
  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
       ++builtin) {
    Tagged<Code> code = builtins->code(builtin);
    uint32_t offset =
        layout_descriptions[static_cast<int>(builtin)].metadata_offset;
    uint8_t* dst = raw_metadata_start + offset;
    DCHECK_LE(RawMetadataOffset() + offset + code->metadata_size(),
              blob_data_size);
    std::memcpy(dst, reinterpret_cast<uint8_t*>(code->metadata_start()),
                code->metadata_size());
  }
  CHECK_IMPLIES(
      kMaxPCRelativeCodeRangeInMB,
      static_cast<size_t>(raw_code_size) <= kMaxPCRelativeCodeRangeInMB * MB);

  // .. and the variable-size code section.
  uint8_t* const raw_code_start = blob_code + RawCodeOffset();
  static_assert(Builtins::kAllBuiltinsAreIsolateIndependent);
  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
       ++builtin) {
    Tagged<Code> code = builtins->code(builtin);
    uint32_t offset =
        layout_descriptions[static_cast<int>(builtin)].instruction_offset;
    uint8_t* dst = raw_code_start + offset;
    DCHECK_LE(RawCodeOffset() + offset + code->instruction_size(),
              blob_code_size);
    std::memcpy(dst, reinterpret_cast<uint8_t*>(code->instruction_start()),
                code->instruction_size());
  }

  EmbeddedData d(blob_code, blob_code_size, blob_data, blob_data_size);

  // Fix up call targets that point to other embedded builtins.
  FinalizeEmbeddedCodeTargets(isolate, &d);

  // Hash the blob and store the result.
  {
    static_assert(EmbeddedBlobDataHashSize() == kSizetSize);
    const size_t data_hash = d.CreateEmbeddedBlobDataHash();
    std::memcpy(blob_data + EmbeddedBlobDataHashOffset(), &data_hash,
                EmbeddedBlobDataHashSize());

    static_assert(EmbeddedBlobCodeHashSize() == kSizetSize);
    const size_t code_hash = d.CreateEmbeddedBlobCodeHash();
    std::memcpy(blob_data + EmbeddedBlobCodeHashOffset(), &code_hash,
                EmbeddedBlobCodeHashSize());

    DCHECK_EQ(data_hash, d.CreateEmbeddedBlobDataHash());
    DCHECK_EQ(data_hash, d.EmbeddedBlobDataHash());
    DCHECK_EQ(code_hash, d.CreateEmbeddedBlobCodeHash());
    DCHECK_EQ(code_hash, d.EmbeddedBlobCodeHash());
  }

  if (DEBUG_BOOL) {
    for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
         ++builtin) {
      Tagged<Code> code = builtins->code(builtin);
      CHECK_EQ(d.InstructionSizeOf(builtin), code->instruction_size());
    }
  }

  // Ensure that InterpreterEntryTrampolineForProfiling is relocatable.
  // See v8_flags.interpreted_frames_native_stack for details.
  EnsureRelocatable(
      builtins->code(Builtin::kInterpreterEntryTrampolineForProfiling));

  if (v8_flags.serialization_statistics) d.PrintStatistics();

  return d;
}

size_t EmbeddedData::CreateEmbeddedBlobDataHash() const {
  static_assert(EmbeddedBlobDataHashOffset() == 0);
  static_assert(EmbeddedBlobCodeHashOffset() == EmbeddedBlobDataHashSize());
  static_assert(IsolateHashOffset() ==
                EmbeddedBlobCodeHashOffset() + EmbeddedBlobCodeHashSize());
  static constexpr uint32_t kFirstHashedDataOffset = IsolateHashOffset();
  // Hash the entire data section except the embedded blob hash fields
  // themselves.
  base::Vector<const uint8_t> payload(data_ + kFirstHashedDataOffset,
                                      data_size_ - kFirstHashedDataOffset);
  return Checksum(payload);
}

size_t EmbeddedData::CreateEmbeddedBlobCodeHash() const {
  CHECK(v8_flags.text_is_readable);
  base::Vector<const uint8_t> payload(code_, code_size_);
  return Checksum(payload);
}

Builtin EmbeddedData::GetBuiltinId(ReorderedBuiltinIndex embedded_index) const {
  Builtin builtin =
      Builtins::FromInt(BuiltinLookupEntry(embedded_index)->builtin_id);
  return builtin;
}

void EmbeddedData::PrintStatistics() const {
  DCHECK(v8_flags.serialization_statistics);

  constexpr int kCount = Builtins::kBuiltinCount;
  int sizes[kCount];
  static_assert(Builtins::kAllBuiltinsAreIsolateIndependent);
  for (int i = 0; i < kCount; i++) {
    sizes[i] = InstructionSizeOf(Builtins::FromInt(i));
  }

  // Sort for percentiles.
  std::sort(&sizes[0], &sizes[kCount]);

  const int k50th = kCount * 0.5;
  const int k75th = kCount * 0.75;
  const int k90th = kCount * 0.90;
  const int k99th = kCount * 0.99;

  PrintF("EmbeddedData:\n");
  PrintF("  Total size:                  %d\n",
         static_cast<int>(code_size() + data_size()));
  PrintF("  Data size:                   %d\n", static_cast<int>(data_size()));
  PrintF("  Code size:                   %d\n", static_cast<int>(code_size()));
  PrintF("  Instruction size (50th percentile): %d\n", sizes[k50th]);
  PrintF("  Instruction size (75th percentile): %d\n", sizes[k75th]);
  PrintF("  Instruction size (90th percentile): %d\n", sizes[k90th]);
  PrintF("  Instruction size (99th percentile): %d\n", sizes[k99th]);
  PrintF("\n");
}

}  // namespace internal
}  // namespace v8

"""

```