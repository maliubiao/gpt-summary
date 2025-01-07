Response:
Let's break down the thought process for analyzing the `snapshot.cc` file.

**1. Initial Skim and High-Level Understanding:**

* **Copyright and License:**  The initial lines clearly indicate this is part of the V8 project and uses a BSD-style license. This is standard for open-source projects.
* **Includes:** The included header files provide significant clues. Keywords like "snapshot," "serializer," "deserializer," "compression," "heap," and "context" immediately jump out, confirming the file's focus. The presence of `#include "src/api/api-inl.h"` suggests interaction with the public V8 API.
* **Namespace:**  The code is within the `v8::internal` namespace, indicating internal V8 implementation details, not intended for direct external use.
* **`SnapshotImpl` Class:**  This private class with static methods suggests an internal implementation detail for managing snapshot data. Its members (like `CreateSnapshotBlob`, `ExtractNumContexts`, etc.) give hints about the structure and manipulation of snapshot blobs.
* **`MaybeDecompress` Function:**  The conditional compilation (`#ifdef V8_SNAPSHOT_COMPRESSION`) and the function name strongly imply that snapshot data can be compressed.
* **`Snapshot` Class (Public Interface):** This class appears to provide the primary public interface for dealing with snapshots (e.g., `Initialize`, `NewContextFromSnapshot`, `Create`).
* **Serialization/Deserialization:** Keywords like "Serialize," "Deserialize," and the names of related classes are scattered throughout.
* **Versioning and Checksums:** The presence of `CheckVersion` and checksum-related functions points to mechanisms for ensuring snapshot compatibility and integrity.

**2. Deconstructing `SnapshotImpl`:**

* **`CreateSnapshotBlob`:**  This function clearly seems to be the core logic for assembling the snapshot blob from its constituent parts (startup, read-only, shared heap, and context snapshots). The parameters and the name solidify this.
* **`Extract...Data` functions:** These are utility functions for extracting different sections of the snapshot blob. This implies a specific structure for the blob.
* **Header Offsets (e.g., `kNumberOfContextsOffset`):**  These constants define the layout of the snapshot blob's header, confirming the structured nature of the data. The comments explaining the layout are crucial for understanding.
* **Checksum Logic:** The `ChecksummedContent`, `kChecksumOffset`, etc., clearly handle calculating and storing a checksum for data integrity.

**3. Analyzing the Public `Snapshot` Class:**

* **`Initialize`:**  This function likely handles the initial setup of an isolate using a snapshot. It involves checking the version, verifying the checksum, and potentially decompressing data.
* **`NewContextFromSnapshot`:**  This function suggests the ability to create new JavaScript contexts from snapshot data.
* **`Create`:** This appears to be the main function for *creating* a snapshot. It involves different serializers for different parts of the heap.
* **`ClearReconstructableDataForSerialization`:** This function is interesting. It seems to be preparing the isolate for snapshot creation by clearing out potentially problematic data (like compiled code) that might not be easily serializable or would bloat the snapshot. This hints at optimization strategies.
* **`SerializeDeserializeAndVerifyForTesting`:** This is a testing utility to ensure that the serialization and deserialization processes work correctly.

**4. Considering the "If .tq" Condition:**

* Torque is mentioned. If the file ended in `.tq`, it would be a Torque source file. Torque is V8's domain-specific language for implementing built-in functions. Since it's `.cc`, it's C++ and deals with the *infrastructure* for snapshots, not necessarily the *implementation* of specific JavaScript features through snapshots.

**5. Connecting to JavaScript (and potential examples):**

* The core idea of snapshots is to speed up the initial startup of the V8 engine by pre-serializing the initial state. This directly relates to how quickly JavaScript code can begin execution.
* Examples would involve scenarios where startup time is critical, like command-line Node.js applications or web browsers.
* The `ClearReconstructableDataForSerialization` function has implications for JavaScript performance. Clearing compiled code means it will need to be recompiled, potentially impacting performance after startup.

**6. Code Logic Inference (Hypothetical Input/Output):**

* **Input:** A `StartupData` blob.
* **Output of `ExtractNumContexts`:** The number of contexts stored in the blob (from the header).
* **Output of `ExtractStartupData`:** The raw bytes of the startup snapshot.
* **Output of `CreateSnapshotBlob`:** A new `StartupData` blob containing the combined and structured snapshot data.

**7. Common Programming Errors:**

* **Version Mismatches:** This is explicitly handled by `CheckVersion`. A user might try to use a snapshot generated by an older or newer V8 version, leading to crashes or incorrect behavior.
* **Corrupted Snapshots:**  The checksum mechanism is in place to detect this. If a snapshot file is corrupted, V8 should detect it and refuse to use it.

**8. Structuring the Output (as requested by the prompt):**

* Group the functionality into logical categories.
* Clearly distinguish between the roles of `SnapshotImpl` and `Snapshot`.
* Use bullet points for easy readability.
* Provide JavaScript examples where relevant.
* Include hypothetical input/output scenarios.
* Give concrete examples of common programming errors.

By following these steps, combining code analysis with domain knowledge about V8 and snapshots, and iteratively refining the understanding, it's possible to generate a comprehensive and accurate summary of the `snapshot.cc` file's functionality.
## 功能归纳：v8/src/snapshot/snapshot.cc (第1部分)

这个C++源代码文件 `v8/src/snapshot/snapshot.cc` 负责 V8 JavaScript 引擎的快照 (snapshot) 功能的核心实现。快照是一种将 V8 引擎的初始状态（包括堆、内置对象等）序列化到磁盘的技术，以便在后续启动时快速恢复，从而显著加快启动速度。

**以下是该文件主要功能的详细列表：**

1. **快照数据的创建 (Serialization):**
    * 提供了 `Snapshot::Create` 函数，用于将当前 V8 引擎的状态序列化成一个 `v8::StartupData` 结构体，该结构体包含原始的快照数据。
    * 涉及到不同类型的序列化器：
        * `ReadOnlySerializer`: 序列化只读堆空间的数据。
        * `SharedHeapSerializer`: 序列化共享堆空间的数据（如果启用）。
        * `StartupSerializer`: 序列化启动时需要的特定对象和数据。
        * `ContextSerializer`: 序列化独立的 JavaScript 上下文。
    * 可以清除可重建的数据 (`Snapshot::ClearReconstructableDataForSerialization`)，例如已编译的代码，以减小快照大小。
    * 可以为测试目的序列化、反序列化和验证快照 (`Snapshot::SerializeDeserializeAndVerifyForTesting`)。
    * 支持在创建快照时执行额外的嵌入式 JavaScript 代码 (`CreateSnapshotDataBlobInternal`)。
    * 可以选择不同的函数代码处理方式 (`v8::SnapshotCreator::FunctionCodeHandling`)。

2. **快照数据的加载 (Deserialization):**
    * 提供了 `Snapshot::Initialize` 函数，用于使用提供的 `v8::StartupData` 快照数据初始化 V8 引擎。
    * 提供了 `Snapshot::NewContextFromSnapshot` 函数，用于从快照数据创建一个新的 JavaScript 上下文。
    * 使用不同的反序列化器：
        * `ContextDeserializer`: 反序列化 JavaScript 上下文。

3. **快照数据的结构和管理:**
    * 定义了 `SnapshotImpl` 内部类，用于管理快照数据的底层布局和操作。
    * 定义了快照数据 `v8::StartupData` 的结构，包括：
        * 上下文数量
        * 可重哈希性标志
        * 校验和
        * 只读快照校验和
        * 版本字符串
        * 指向只读数据、共享堆数据和各个上下文数据的偏移量。
    * 定义了快照数据 blob 的布局 (`SnapshotImpl::k...Offset` 常量)。
    * 提供了函数来提取快照数据的不同部分 (`SnapshotImpl::ExtractStartupData`, `ExtractReadOnlyData`, `ExtractSharedHeapData`, `ExtractContextData`)。

4. **快照的校验和与版本控制:**
    * 提供了计算和验证快照校验和的功能 (`Snapshot::CalculateChecksum`, `Snapshot::VerifyChecksum`)，以确保快照数据的完整性。
    * 包含了版本检查机制 (`Snapshot::VersionIsValid`, `SnapshotImpl::CheckVersion`)，以防止使用与当前 V8 版本不兼容的快照。

5. **快照的压缩与解压缩:**
    * 通过条件编译 (`#ifdef V8_SNAPSHOT_COMPRESSION`) 支持快照数据的压缩和解压缩 (`MaybeDecompress`)。

**关于 .tq 后缀：**

如果 `v8/src/snapshot/snapshot.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。Torque 是 V8 用于定义内置函数和运行时函数的领域特定语言。然而，当前提供的代码是 `.cc` 文件，意味着它是 **C++ 源代码**。`.cc` 文件通常处理更底层的实现细节和数据结构，而 `.tq` 文件则更专注于 JavaScript 语义的实现。

**与 JavaScript 功能的关系及示例：**

快照功能直接影响 V8 引擎启动 JavaScript 代码的速度。

**JavaScript 示例：**

假设你有一个 Node.js 应用程序，它在启动时需要加载大量的模块和执行一些初始化代码。没有快照的情况下，V8 引擎每次启动都需要重新解析和编译这些代码。

```javascript
// 没有使用快照的情况下，启动时间较长

console.time('启动时间');

// 加载大量模块
require('module-a');
require('module-b');
// ... 更多模块

// 执行初始化代码
for (let i = 0; i < 100000; i++) {
  // 一些耗时的初始化操作
}

console.timeEnd('启动时间');
```

使用了快照后，V8 引擎可以将初始状态保存下来，下次启动时直接恢复，跳过了解析和部分编译过程，从而缩短启动时间。

**代码逻辑推理 (假设输入与输出)：**

**假设输入：**

* 一个已经运行了一段时间的 V8 `Isolate` 对象，其中包含一些已加载的对象和状态。
* 调用 `Snapshot::Create(isolate, ...)` 函数。

**预期输出：**

* 一个 `v8::StartupData` 结构体，其中 `data` 成员指向包含序列化后的快照数据的内存区域，`raw_size` 成员表示该内存区域的大小。该数据包含了 `isolate` 的当前状态，可以被用来快速恢复该状态。

**涉及用户常见的编程错误：**

1. **快照版本不匹配:** 用户尝试使用由不同版本的 V8 生成的快照。这会导致 `SnapshotImpl::CheckVersion` 检测到版本不一致并抛出致命错误。

   ```c++
   // 假设当前的 V8 版本是 1.0，而快照是使用 0.9 版本生成的。
   v8::StartupData snapshot_data = LoadSnapshotFromFile("snapshot_v0.9.bin");
   v8::Isolate::CreateParams create_params;
   create_params.snapshot_blob = &snapshot_data;
   v8::Isolate* isolate = v8::Isolate::New(create_params); // 可能导致致命错误
   ```

2. **快照文件损坏:** 快照文件在存储或传输过程中损坏，导致校验和不匹配。

   ```c++
   v8::StartupData snapshot_data = LoadCorruptedSnapshotFromFile("corrupted_snapshot.bin");
   v8::Isolate::CreateParams create_params;
   create_params.snapshot_blob = &snapshot_data;
   v8::Isolate* isolate = v8::Isolate::New(create_params);
   // Snapshot::VerifyChecksum 会检测到校验和错误，可能导致程序退出或行为异常。
   ```

**功能归纳：**

`v8/src/snapshot/snapshot.cc` 的主要功能是提供 **创建、加载和管理 V8 快照的核心机制**。它定义了快照数据的结构、序列化和反序列化的流程，并包含了版本控制和校验和机制以保证快照的兼容性和完整性。这个文件是 V8 快速启动能力的关键组成部分。

Prompt: 
```
这是目录为v8/src/snapshot/snapshot.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/snapshot/snapshot.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2006-2008 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The common functionality when building with or without snapshots.

#include "src/snapshot/snapshot.h"

#include "src/api/api-inl.h"  // For OpenHandle.
#include "src/baseline/baseline-batch-compiler.h"
#include "src/common/assert-scope.h"
#include "src/execution/local-isolate-inl.h"
#include "src/handles/global-handles-inl.h"
#include "src/heap/local-heap-inl.h"
#include "src/heap/read-only-promotion.h"
#include "src/heap/safepoint.h"
#include "src/init/bootstrapper.h"
#include "src/logging/counters-scopes.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/js-regexp-inl.h"
#include "src/snapshot/context-deserializer.h"
#include "src/snapshot/context-serializer.h"
#include "src/snapshot/read-only-serializer.h"
#include "src/snapshot/shared-heap-serializer.h"
#include "src/snapshot/snapshot-utils.h"
#include "src/snapshot/startup-serializer.h"
#include "src/utils/memcopy.h"
#include "src/utils/version.h"

#ifdef V8_SNAPSHOT_COMPRESSION
#include "src/snapshot/snapshot-compression.h"
#endif

namespace v8 {
namespace internal {

namespace {

class SnapshotImpl : public AllStatic {
 public:
  static v8::StartupData CreateSnapshotBlob(
      const SnapshotData* startup_snapshot_in,
      const SnapshotData* read_only_snapshot_in,
      const SnapshotData* shared_heap_snapshot_in,
      const std::vector<SnapshotData*>& context_snapshots_in,
      bool can_be_rehashed);

  static uint32_t ExtractNumContexts(const v8::StartupData* data);
  static uint32_t ExtractContextOffset(const v8::StartupData* data,
                                       uint32_t index);
  static base::Vector<const uint8_t> ExtractStartupData(
      const v8::StartupData* data);
  static base::Vector<const uint8_t> ExtractReadOnlyData(
      const v8::StartupData* data);
  static base::Vector<const uint8_t> ExtractSharedHeapData(
      const v8::StartupData* data);
  static base::Vector<const uint8_t> ExtractContextData(
      const v8::StartupData* data, uint32_t index);

  static uint32_t GetHeaderValue(const v8::StartupData* data, uint32_t offset) {
    DCHECK_NOT_NULL(data);
    DCHECK_LT(offset, static_cast<uint32_t>(data->raw_size));
    return base::ReadLittleEndianValue<uint32_t>(
        reinterpret_cast<Address>(data->data) + offset);
  }
  static void SetHeaderValue(char* data, uint32_t offset, uint32_t value) {
    base::WriteLittleEndianValue(reinterpret_cast<Address>(data) + offset,
                                 value);
  }

  static void CheckVersion(const v8::StartupData* data);

  // Snapshot blob layout:
  // [0] number of contexts N
  // [1] rehashability
  // [2] checksum
  // [3] read-only snapshot checksum
  // [4] (64 bytes) version string
  // [5] offset to readonly
  // [6] offset to shared heap
  // [7] offset to context 0
  // [8] offset to context 1
  // ...
  // ... offset to context N - 1
  // ... startup snapshot data
  // ... read-only snapshot data
  // ... shared heap snapshot data
  // ... context 0 snapshot data
  // ... context 1 snapshot data

  static const uint32_t kNumberOfContextsOffset = 0;
  // TODO(yangguo): generalize rehashing, and remove this flag.
  static const uint32_t kRehashabilityOffset =
      kNumberOfContextsOffset + kUInt32Size;
  static const uint32_t kChecksumOffset = kRehashabilityOffset + kUInt32Size;
  static const uint32_t kReadOnlySnapshotChecksumOffset =
      kChecksumOffset + kUInt32Size;
  static const uint32_t kVersionStringOffset =
      kReadOnlySnapshotChecksumOffset + kUInt32Size;
  static const uint32_t kVersionStringLength = 64;
  static const uint32_t kReadOnlyOffsetOffset =
      kVersionStringOffset + kVersionStringLength;
  static const uint32_t kSharedHeapOffsetOffset =
      kReadOnlyOffsetOffset + kUInt32Size;
  static const uint32_t kFirstContextOffsetOffset =
      kSharedHeapOffsetOffset + kUInt32Size;

  static base::Vector<const uint8_t> ChecksummedContent(
      const v8::StartupData* data) {
    // The hashed region is everything but the header slots up-to-and-including
    // the checksum slot itself.
    // TODO(jgruber): We currently exclude #contexts and rehashability. This
    // seems arbitrary and I think we could shuffle header slot order around to
    // include them, just for consistency.
    static_assert(kReadOnlySnapshotChecksumOffset ==
                  kChecksumOffset + kUInt32Size);
    const uint32_t kChecksumStart = kReadOnlySnapshotChecksumOffset;
    return base::Vector<const uint8_t>(
        reinterpret_cast<const uint8_t*>(data->data + kChecksumStart),
        data->raw_size - kChecksumStart);
  }

  static uint32_t StartupSnapshotOffset(int num_contexts) {
    return POINTER_SIZE_ALIGN(kFirstContextOffsetOffset +
                              num_contexts * kInt32Size);
  }

  static uint32_t ContextSnapshotOffsetOffset(int index) {
    return kFirstContextOffsetOffset + index * kInt32Size;
  }
};

}  // namespace

SnapshotData MaybeDecompress(Isolate* isolate,
                             base::Vector<const uint8_t> snapshot_data) {
#ifdef V8_SNAPSHOT_COMPRESSION
  TRACE_EVENT0("v8", "V8.SnapshotDecompress");
  RCS_SCOPE(isolate, RuntimeCallCounterId::kSnapshotDecompress);
  NestedTimedHistogramScope histogram_timer(
      isolate->counters()->snapshot_decompress());
  return SnapshotCompression::Decompress(snapshot_data);
#else
  return SnapshotData(snapshot_data);
#endif
}

#ifdef DEBUG
bool Snapshot::SnapshotIsValid(const v8::StartupData* snapshot_blob) {
  return SnapshotImpl::ExtractNumContexts(snapshot_blob) > 0;
}
#endif  // DEBUG

bool Snapshot::HasContextSnapshot(Isolate* isolate, size_t index) {
  // Do not use snapshots if the isolate is used to create snapshots.
  const v8::StartupData* blob = isolate->snapshot_blob();
  if (blob == nullptr) return false;
  if (blob->data == nullptr) return false;
  size_t num_contexts =
      static_cast<size_t>(SnapshotImpl::ExtractNumContexts(blob));
  return index < num_contexts;
}

bool Snapshot::VersionIsValid(const v8::StartupData* data) {
  char version[SnapshotImpl::kVersionStringLength];
  memset(version, 0, SnapshotImpl::kVersionStringLength);
  CHECK_LT(
      SnapshotImpl::kVersionStringOffset + SnapshotImpl::kVersionStringLength,
      static_cast<uint32_t>(data->raw_size));
  Version::GetString(
      base::Vector<char>(version, SnapshotImpl::kVersionStringLength));
  return strncmp(version, data->data + SnapshotImpl::kVersionStringOffset,
                 SnapshotImpl::kVersionStringLength) == 0;
}

bool Snapshot::Initialize(Isolate* isolate) {
  if (!isolate->snapshot_available()) return false;

  const v8::StartupData* blob = isolate->snapshot_blob();
  SnapshotImpl::CheckVersion(blob);
  if (Snapshot::ShouldVerifyChecksum(blob)) {
    CHECK(VerifyChecksum(blob));
  }

  base::Vector<const uint8_t> startup_data =
      SnapshotImpl::ExtractStartupData(blob);
  base::Vector<const uint8_t> read_only_data =
      SnapshotImpl::ExtractReadOnlyData(blob);
  base::Vector<const uint8_t> shared_heap_data =
      SnapshotImpl::ExtractSharedHeapData(blob);

  SnapshotData startup_snapshot_data(MaybeDecompress(isolate, startup_data));
  SnapshotData read_only_snapshot_data(
      MaybeDecompress(isolate, read_only_data));
  SnapshotData shared_heap_snapshot_data(
      MaybeDecompress(isolate, shared_heap_data));

  return isolate->InitWithSnapshot(
      &startup_snapshot_data, &read_only_snapshot_data,
      &shared_heap_snapshot_data, ExtractRehashability(blob));
}

MaybeDirectHandle<Context> Snapshot::NewContextFromSnapshot(
    Isolate* isolate, Handle<JSGlobalProxy> global_proxy, size_t context_index,
    DeserializeEmbedderFieldsCallback embedder_fields_deserializer) {
  if (!isolate->snapshot_available()) return Handle<Context>();

  const v8::StartupData* blob = isolate->snapshot_blob();
  bool can_rehash = ExtractRehashability(blob);
  base::Vector<const uint8_t> context_data = SnapshotImpl::ExtractContextData(
      blob, static_cast<uint32_t>(context_index));
  SnapshotData snapshot_data(MaybeDecompress(isolate, context_data));

  return ContextDeserializer::DeserializeContext(
      isolate, &snapshot_data, context_index, can_rehash, global_proxy,
      embedder_fields_deserializer);
}

// static
void Snapshot::ClearReconstructableDataForSerialization(
    Isolate* isolate, bool clear_recompilable_data) {
  // Clear SFIs and JSRegExps.
  PtrComprCageBase cage_base(isolate);

  {
    HandleScope scope(isolate);
    std::vector<i::Handle<i::SharedFunctionInfo>> sfis_to_clear;
    {
      i::HeapObjectIterator it(isolate->heap());
      for (i::Tagged<i::HeapObject> o = it.Next(); !o.is_null();
           o = it.Next()) {
        if (clear_recompilable_data && IsSharedFunctionInfo(o, cage_base)) {
          i::Tagged<i::SharedFunctionInfo> shared =
              i::Cast<i::SharedFunctionInfo>(o);
          if (IsScript(shared->script(cage_base), cage_base) &&
              Cast<Script>(shared->script(cage_base))->type() ==
                  Script::Type::kExtension) {
            continue;  // Don't clear extensions, they cannot be recompiled.
          }
          if (shared->CanDiscardCompiled()) {
            sfis_to_clear.emplace_back(shared, isolate);
          }
        } else if (IsJSRegExp(o, cage_base)) {
          i::Tagged<i::JSRegExp> regexp = i::Cast<i::JSRegExp>(o);
          if (regexp->has_data()) {
            i::Tagged<i::RegExpData> data = regexp->data(isolate);
            if (data->HasCompiledCode()) {
              DCHECK(Is<IrRegExpData>(regexp->data(isolate)));
              Cast<IrRegExpData>(data)->DiscardCompiledCodeForSerialization();
            }
          }
        }
      }
    }

#if V8_ENABLE_WEBASSEMBLY
    // Clear the cached js-to-wasm wrappers.
    DirectHandle<WeakFixedArray> wrappers(
        isolate->heap()->js_to_wasm_wrappers(), isolate);
    MemsetTagged(wrappers->RawFieldOfFirstElement(), ClearedValue(isolate),
                 wrappers->length());
#endif  // V8_ENABLE_WEBASSEMBLY

    // Must happen after heap iteration since SFI::DiscardCompiled may allocate.
    for (i::DirectHandle<i::SharedFunctionInfo> shared : sfis_to_clear) {
      if (shared->CanDiscardCompiled()) {
        i::SharedFunctionInfo::DiscardCompiled(isolate, shared);
      }
    }
  }

  // Clear JSFunctions.
  {
    i::HeapObjectIterator it(isolate->heap());
    for (i::Tagged<i::HeapObject> o = it.Next(); !o.is_null(); o = it.Next()) {
      if (!IsJSFunction(o, cage_base)) continue;

      i::Tagged<i::JSFunction> fun = i::Cast<i::JSFunction>(o);
      fun->CompleteInobjectSlackTrackingIfActive();

      i::Tagged<i::SharedFunctionInfo> shared = fun->shared();
      if (IsScript(shared->script(cage_base), cage_base) &&
          Cast<Script>(shared->script(cage_base))->type() ==
              Script::Type::kExtension) {
        continue;  // Don't clear extensions, they cannot be recompiled.
      }

      // Also, clear out feedback vectors and recompilable code.
      if (fun->CanDiscardCompiled(isolate)) {
        fun->UpdateCode(*BUILTIN_CODE(isolate, CompileLazy));
      }
      if (!IsUndefined(fun->raw_feedback_cell(cage_base)->value(cage_base))) {
        fun->raw_feedback_cell(cage_base)->set_value(
            i::ReadOnlyRoots(isolate).undefined_value());
      }
#ifdef DEBUG
      if (clear_recompilable_data) {
#if V8_ENABLE_WEBASSEMBLY
        DCHECK(fun->shared()->HasWasmExportedFunctionData() ||
               fun->shared()->HasBuiltinId() ||
               fun->shared()->IsApiFunction() ||
               fun->shared()->HasUncompiledDataWithoutPreparseData());
#else
        DCHECK(fun->shared()->HasBuiltinId() ||
               fun->shared()->IsApiFunction() ||
               fun->shared()->HasUncompiledDataWithoutPreparseData());
#endif  // V8_ENABLE_WEBASSEMBLY
      }
#endif  // DEBUG
    }
  }

  // PendingOptimizeTable also contains BytecodeArray, we need to clear the
  // recompilable code same as above.
  ReadOnlyRoots roots(isolate);
  isolate->heap()->SetFunctionsMarkedForManualOptimization(
      roots.undefined_value());

#if V8_ENABLE_WEBASSEMBLY
  {
    // Check if there are any asm.js / wasm functions on the heap.
    // These cannot be serialized due to restrictions with the js-to-wasm
    // wrapper. A tiered-up wrapper would have to be replaced with a generic
    // wrapper which isn't supported. For asm.js there also isn't any support
    // for the generic wrapper at all.
    i::HeapObjectIterator it(isolate->heap(),
                             HeapObjectIterator::kFilterUnreachable);
    for (i::Tagged<i::HeapObject> o = it.Next(); !o.is_null(); o = it.Next()) {
      if (IsJSFunction(o)) {
        i::Tagged<i::JSFunction> fun = i::Cast<i::JSFunction>(o);
        if (fun->shared()->HasAsmWasmData()) {
          FATAL("asm.js functions are not supported in snapshots");
        }
        if (fun->shared()->HasWasmExportedFunctionData()) {
          FATAL(
              "Exported WebAssembly functions are not supported in snapshots");
        }
      }
    }
  }
#endif  // V8_ENABLE_WEBASSEMBLY
}

// static
void Snapshot::SerializeDeserializeAndVerifyForTesting(
    Isolate* isolate, DirectHandle<Context> default_context) {
  StartupData serialized_data;
  std::unique_ptr<const char[]> auto_delete_serialized_data;

  isolate->heap()->CollectAllAvailableGarbage(
      i::GarbageCollectionReason::kSnapshotCreator);

  // Test serialization.
  {
    SafepointKind safepoint_kind = isolate->has_shared_space()
                                       ? SafepointKind::kGlobal
                                       : SafepointKind::kIsolate;
    SafepointScope safepoint_scope(isolate, safepoint_kind);
    DisallowGarbageCollection no_gc;

    Snapshot::SerializerFlags flags(
        Snapshot::kAllowUnknownExternalReferencesForTesting |
        Snapshot::kAllowActiveIsolateForTesting |
        ((isolate->has_shared_space() || ReadOnlyHeap::IsReadOnlySpaceShared())
             ? Snapshot::kReconstructReadOnlyAndSharedObjectCachesForTesting
             : 0));
    std::vector<Tagged<Context>> contexts{*default_context};
    std::vector<SerializeEmbedderFieldsCallback> callbacks{
        SerializeEmbedderFieldsCallback()};
    serialized_data = Snapshot::Create(isolate, &contexts, callbacks,
                                       safepoint_scope, no_gc, flags);
    auto_delete_serialized_data.reset(serialized_data.data);
  }

  // The shared heap is verified on Heap teardown, which performs a global
  // safepoint. Both isolate and new_isolate are running in the same thread, so
  // park isolate before running new_isolate to avoid deadlock.
  isolate->main_thread_local_isolate()->ExecuteMainThreadWhileParked(
      [&serialized_data]() {
        // Test deserialization.
        Isolate* new_isolate = Isolate::New();
        std::unique_ptr<v8::ArrayBuffer::Allocator> array_buffer_allocator(
            v8::ArrayBuffer::Allocator::NewDefaultAllocator());
        {
          // Set serializer_enabled() to not install extensions and experimental
          // natives on the new isolate.
          // TODO(v8:10416): This should be a separate setting on the isolate.
          new_isolate->enable_serializer();
          new_isolate->Enter();
          new_isolate->set_snapshot_blob(&serialized_data);
          new_isolate->set_array_buffer_allocator(array_buffer_allocator.get());
          CHECK(Snapshot::Initialize(new_isolate));

          HandleScope scope(new_isolate);
          DirectHandle<Context> new_native_context =
              new_isolate->bootstrapper()->CreateEnvironmentForTesting();
          CHECK(IsNativeContext(*new_native_context));

#ifdef VERIFY_HEAP
          if (v8_flags.verify_heap)
            HeapVerifier::VerifyHeap(new_isolate->heap());
#endif  // VERIFY_HEAP
        }
        new_isolate->Exit();
        Isolate::Delete(new_isolate);
      });
}

// static
v8::StartupData Snapshot::Create(
    Isolate* isolate, std::vector<Tagged<Context>>* contexts,
    const std::vector<SerializeEmbedderFieldsCallback>&
        embedder_fields_serializers,
    const SafepointScope& safepoint_scope,
    const DisallowGarbageCollection& no_gc, SerializerFlags flags) {
  TRACE_EVENT0("v8", "V8.SnapshotCreate");
  DCHECK_EQ(contexts->size(), embedder_fields_serializers.size());
  DCHECK_GT(contexts->size(), 0);
  HandleScope scope(isolate);

  ReadOnlySerializer read_only_serializer(isolate, flags);
  read_only_serializer.Serialize();

  // TODO(v8:6593): generalize rehashing, and remove this flag.
  bool can_be_rehashed = read_only_serializer.can_be_rehashed();

  SharedHeapSerializer shared_heap_serializer(isolate, flags);
  StartupSerializer startup_serializer(isolate, flags, &shared_heap_serializer);
  startup_serializer.SerializeStrongReferences(no_gc);

  // Serialize each context with a new serializer.
  const int num_contexts = static_cast<int>(contexts->size());
  std::vector<SnapshotData*> context_snapshots;
  context_snapshots.reserve(num_contexts);

  std::vector<int> context_allocation_sizes;
  for (int i = 0; i < num_contexts; i++) {
    ContextSerializer context_serializer(isolate, flags, &startup_serializer,
                                         embedder_fields_serializers[i]);
    context_serializer.Serialize(&contexts->at(i), no_gc);
    can_be_rehashed = can_be_rehashed && context_serializer.can_be_rehashed();
    context_snapshots.push_back(new SnapshotData(&context_serializer));
    if (v8_flags.serialization_statistics) {
      context_allocation_sizes.push_back(
          context_serializer.TotalAllocationSize());
    }
  }

  startup_serializer.SerializeWeakReferencesAndDeferred();
  can_be_rehashed = can_be_rehashed && startup_serializer.can_be_rehashed();

  startup_serializer.CheckNoDirtyFinalizationRegistries();

  shared_heap_serializer.FinalizeSerialization();
  can_be_rehashed = can_be_rehashed && shared_heap_serializer.can_be_rehashed();

  if (v8_flags.serialization_statistics) {
    DCHECK_NE(read_only_serializer.TotalAllocationSize(), 0);
    DCHECK_NE(startup_serializer.TotalAllocationSize(), 0);
    // The shared heap snapshot can be empty, no problem.
    // DCHECK_NE(shared_heap_serializer.TotalAllocationSize(), 0);
    int per_isolate_allocation_size = startup_serializer.TotalAllocationSize();
    int per_process_allocation_size = 0;
    if (ReadOnlyHeap::IsReadOnlySpaceShared()) {
      per_process_allocation_size += read_only_serializer.TotalAllocationSize();
    } else {
      per_isolate_allocation_size += read_only_serializer.TotalAllocationSize();
    }
    // TODO(jgruber): At snapshot-generation time we don't know whether the
    // shared heap snapshot will actually be shared at runtime, or if it will
    // be deserialized into each isolate. Conservatively account to per-isolate
    // memory here.
    per_isolate_allocation_size += shared_heap_serializer.TotalAllocationSize();
    // These prints must match the regexp in test/memory/Memory.json
    PrintF("Deserialization will allocate:\n");
    PrintF("%10d bytes per process\n", per_process_allocation_size);
    PrintF("%10d bytes per isolate\n", per_isolate_allocation_size);
    for (int i = 0; i < num_contexts; i++) {
      DCHECK_NE(context_allocation_sizes[i], 0);
      PrintF("%10d bytes per context #%d\n", context_allocation_sizes[i], i);
    }
    PrintF("\n");
  }

  SnapshotData read_only_snapshot(&read_only_serializer);
  SnapshotData shared_heap_snapshot(&shared_heap_serializer);
  SnapshotData startup_snapshot(&startup_serializer);
  v8::StartupData result = SnapshotImpl::CreateSnapshotBlob(
      &startup_snapshot, &read_only_snapshot, &shared_heap_snapshot,
      context_snapshots, can_be_rehashed);

  for (const SnapshotData* ptr : context_snapshots) delete ptr;

  CHECK(Snapshot::VerifyChecksum(&result));
  return result;
}

v8::StartupData SnapshotImpl::CreateSnapshotBlob(
    const SnapshotData* startup_snapshot_in,
    const SnapshotData* read_only_snapshot_in,
    const SnapshotData* shared_heap_snapshot_in,
    const std::vector<SnapshotData*>& context_snapshots_in,
    bool can_be_rehashed) {
  TRACE_EVENT0("v8", "V8.SnapshotCompress");
  // Have these separate from snapshot_in for compression, since we need to
  // access the compressed data as well as the uncompressed reservations.
  const SnapshotData* startup_snapshot;
  const SnapshotData* read_only_snapshot;
  const SnapshotData* shared_heap_snapshot;
  const std::vector<SnapshotData*>* context_snapshots;
#ifdef V8_SNAPSHOT_COMPRESSION
  SnapshotData startup_compressed(
      SnapshotCompression::Compress(startup_snapshot_in));
  SnapshotData read_only_compressed(
      SnapshotCompression::Compress(read_only_snapshot_in));
  SnapshotData shared_heap_compressed(
      SnapshotCompression::Compress(shared_heap_snapshot_in));
  startup_snapshot = &startup_compressed;
  read_only_snapshot = &read_only_compressed;
  shared_heap_snapshot = &shared_heap_compressed;
  std::vector<SnapshotData> context_snapshots_compressed;
  context_snapshots_compressed.reserve(context_snapshots_in.size());
  std::vector<SnapshotData*> context_snapshots_compressed_ptrs;
  for (unsigned int i = 0; i < context_snapshots_in.size(); ++i) {
    context_snapshots_compressed.push_back(
        SnapshotCompression::Compress(context_snapshots_in[i]));
    context_snapshots_compressed_ptrs.push_back(
        &context_snapshots_compressed[i]);
  }
  context_snapshots = &context_snapshots_compressed_ptrs;
#else
  startup_snapshot = startup_snapshot_in;
  read_only_snapshot = read_only_snapshot_in;
  shared_heap_snapshot = shared_heap_snapshot_in;
  context_snapshots = &context_snapshots_in;
#endif

  uint32_t num_contexts = static_cast<uint32_t>(context_snapshots->size());
  uint32_t startup_snapshot_offset =
      SnapshotImpl::StartupSnapshotOffset(num_contexts);
  uint32_t total_length = startup_snapshot_offset;
  total_length += static_cast<uint32_t>(startup_snapshot->RawData().length());
  total_length += static_cast<uint32_t>(read_only_snapshot->RawData().length());
  total_length +=
      static_cast<uint32_t>(shared_heap_snapshot->RawData().length());
  for (const auto context_snapshot : *context_snapshots) {
    total_length += static_cast<uint32_t>(context_snapshot->RawData().length());
  }

  char* data = new char[total_length];
  // Zero out pre-payload data. Part of that is only used for padding.
  memset(data, 0, SnapshotImpl::StartupSnapshotOffset(num_contexts));

  SnapshotImpl::SetHeaderValue(data, SnapshotImpl::kNumberOfContextsOffset,
                               num_contexts);
  SnapshotImpl::SetHeaderValue(data, SnapshotImpl::kRehashabilityOffset,
                               can_be_rehashed ? 1 : 0);

  // Write version string into snapshot data.
  memset(data + SnapshotImpl::kVersionStringOffset, 0,
         SnapshotImpl::kVersionStringLength);
  Version::GetString(
      base::Vector<char>(data + SnapshotImpl::kVersionStringOffset,
                         SnapshotImpl::kVersionStringLength));

  // Startup snapshot (isolate-specific data).
  uint32_t payload_offset = startup_snapshot_offset;
  uint32_t payload_length =
      static_cast<uint32_t>(startup_snapshot->RawData().length());
  CopyBytes(data + payload_offset,
            reinterpret_cast<const char*>(startup_snapshot->RawData().begin()),
            payload_length);
  if (v8_flags.serialization_statistics) {
    // These prints must match the regexp in test/memory/Memory.json
    PrintF("Snapshot blob consists of:\n");
    PrintF("%10d bytes for startup\n", payload_length);
  }
  payload_offset += payload_length;

  // Read-only.
  SnapshotImpl::SetHeaderValue(data, SnapshotImpl::kReadOnlyOffsetOffset,
                               payload_offset);
  payload_length = read_only_snapshot->RawData().length();
  CopyBytes(
      data + payload_offset,
      reinterpret_cast<const char*>(read_only_snapshot->RawData().begin()),
      payload_length);
  SnapshotImpl::SetHeaderValue(
      data, SnapshotImpl::kReadOnlySnapshotChecksumOffset,
      Checksum(base::VectorOf(
          reinterpret_cast<const uint8_t*>(data + payload_offset),
          payload_length)));
  if (v8_flags.serialization_statistics) {
    // These prints must match the regexp in test/memory/Memory.json
    PrintF("%10d bytes for read-only\n", payload_length);
  }
  payload_offset += payload_length;

  // Shared heap.
  SnapshotImpl::SetHeaderValue(data, SnapshotImpl::kSharedHeapOffsetOffset,
                               payload_offset);
  payload_length = shared_heap_snapshot->RawData().length();
  CopyBytes(
      data + payload_offset,
      reinterpret_cast<const char*>(shared_heap_snapshot->RawData().begin()),
      payload_length);
  if (v8_flags.serialization_statistics) {
    // These prints must match the regexp in test/memory/Memory.json
    PrintF("%10d bytes for shared heap\n", payload_length);
  }
  payload_offset += payload_length;

  // Context snapshots (context-specific data).
  for (uint32_t i = 0; i < num_contexts; i++) {
    SnapshotImpl::SetHeaderValue(
        data, SnapshotImpl::ContextSnapshotOffsetOffset(i), payload_offset);
    SnapshotData* context_snapshot = (*context_snapshots)[i];
    payload_length = context_snapshot->RawData().length();
    CopyBytes(
        data + payload_offset,
        reinterpret_cast<const char*>(context_snapshot->RawData().begin()),
        payload_length);
    if (v8_flags.serialization_statistics) {
      // These prints must match the regexp in test/memory/Memory.json
      PrintF("%10d bytes for context #%d\n", payload_length, i);
    }
    payload_offset += payload_length;
  }
  if (v8_flags.serialization_statistics) PrintF("\n");

  DCHECK_EQ(total_length, payload_offset);
  v8::StartupData result = {data, static_cast<int>(total_length)};

  SnapshotImpl::SetHeaderValue(
      data, SnapshotImpl::kChecksumOffset,
      Checksum(SnapshotImpl::ChecksummedContent(&result)));

  return result;
}

uint32_t SnapshotImpl::ExtractNumContexts(const v8::StartupData* data) {
  return GetHeaderValue(data, kNumberOfContextsOffset);
}

uint32_t Snapshot::GetExpectedChecksum(const v8::StartupData* data) {
  return SnapshotImpl::GetHeaderValue(data, SnapshotImpl::kChecksumOffset);
}
uint32_t Snapshot::CalculateChecksum(const v8::StartupData* data) {
  return Checksum(SnapshotImpl::ChecksummedContent(data));
}

bool Snapshot::VerifyChecksum(const v8::StartupData* data) {
  base::ElapsedTimer timer;
  if (v8_flags.profile_deserialization) timer.Start();
  uint32_t expected = GetExpectedChecksum(data);
  uint32_t result = CalculateChecksum(data);
  if (v8_flags.profile_deserialization) {
    double ms = timer.Elapsed().InMillisecondsF();
    PrintF("[Verifying snapshot checksum took %0.3f ms]\n", ms);
  }
  return result == expected;
}

uint32_t SnapshotImpl::ExtractContextOffset(const v8::StartupData* data,
                                            uint32_t index) {
  // Extract the offset of the context at a given index from the StartupData,
  // and check that it is within bounds.
  uint32_t context_offset =
      GetHeaderValue(data, ContextSnapshotOffsetOffset(index));
  CHECK_LT(context_offset, static_cast<uint32_t>(data->raw_size));
  return context_offset;
}

bool Snapshot::ExtractRehashability(const v8::StartupData* data) {
  uint32_t rehashability =
      SnapshotImpl::GetHeaderValue(data, SnapshotImpl::kRehashabilityOffset);
  CHECK_IMPLIES(rehashability != 0, rehashability == 1);
  return rehashability != 0;
}

// static
uint32_t Snapshot::ExtractReadOnlySnapshotChecksum(
    const v8::StartupData* data) {
  return SnapshotImpl::GetHeaderValue(
      data, SnapshotImpl::kReadOnlySnapshotChecksumOffset);
}

namespace {
base::Vector<const uint8_t> ExtractData(const v8::StartupData* snapshot,
                                        uint32_t start_offset,
                                        uint32_t end_offset) {
  CHECK_LT(start_offset, end_offset);
  CHECK_LT(end_offset, snapshot->raw_size);
  uint32_t length = end_offset - start_offset;
  const uint8_t* data =
      reinterpret_cast<const uint8_t*>(snapshot->data + start_offset);
  return base::Vector<const uint8_t>(data, length);
}
}  // namespace

base::Vector<const uint8_t> SnapshotImpl::ExtractStartupData(
    const v8::StartupData* data) {
  DCHECK(Snapshot::SnapshotIsValid(data));

  uint32_t num_contexts = ExtractNumContexts(data);
  return ExtractData(data, StartupSnapshotOffset(num_contexts),
                     GetHeaderValue(data, kReadOnlyOffsetOffset));
}

base::Vector<const uint8_t> SnapshotImpl::ExtractReadOnlyData(
    const v8::StartupData* data) {
  DCHECK(Snapshot::SnapshotIsValid(data));

  return ExtractData(data, GetHeaderValue(data, kReadOnlyOffsetOffset),
                     GetHeaderValue(data, kSharedHeapOffsetOffset));
}

base::Vector<const uint8_t> SnapshotImpl::ExtractSharedHeapData(
    const v8::StartupData* data) {
  DCHECK(Snapshot::SnapshotIsValid(data));

  return ExtractData(data, GetHeaderValue(data, kSharedHeapOffsetOffset),
                     GetHeaderValue(data, ContextSnapshotOffsetOffset(0)));
}

base::Vector<const uint8_t> SnapshotImpl::ExtractContextData(
    const v8::StartupData* data, uint32_t index) {
  uint32_t num_contexts = ExtractNumContexts(data);
  CHECK_LT(index, num_contexts);

  uint32_t context_offset = ExtractContextOffset(data, index);
  uint32_t next_context_offset;
  if (index == num_contexts - 1) {
    next_context_offset = data->raw_size;
  } else {
    next_context_offset = ExtractContextOffset(data, index + 1);
    CHECK_LT(next_context_offset, data->raw_size);
  }

  const uint8_t* context_data =
      reinterpret_cast<const uint8_t*>(data->data + context_offset);
  uint32_t context_length = next_context_offset - context_offset;
  return base::Vector<const uint8_t>(context_data, context_length);
}

void SnapshotImpl::CheckVersion(const v8::StartupData* data) {
  if (!Snapshot::VersionIsValid(data)) {
    char version[kVersionStringLength];
    memset(version, 0, kVersionStringLength);
    CHECK_LT(kVersionStringOffset + kVersionStringLength,
             static_cast<uint32_t>(data->raw_size));
    Version::GetString(base::Vector<char>(version, kVersionStringLength));
    FATAL(
        "Version mismatch between V8 binary and snapshot.\n"
        "#   V8 binary version: %.*s\n"
        "#    Snapshot version: %.*s\n"
        "# The snapshot consists of %d bytes and contains %d context(s).",
        kVersionStringLength, version, kVersionStringLength,
        data->data + kVersionStringOffset, data->raw_size,
        ExtractNumContexts(data));
  }
}

namespace {

bool RunExtraCode(v8::Isolate* isolate, v8::Local<v8::Context> context,
                  const char* utf8_source, const char* name) {
  v8::Context::Scope context_scope(context);
  v8::TryCatch try_catch(isolate);
  v8::Local<v8::String> source_string;
  if (!v8::String::NewFromUtf8(isolate, utf8_source).ToLocal(&source_string)) {
    return false;
  }
  v8::Local<v8::String> resource_name =
      v8::String::NewFromUtf8(isolate, name).ToLocalChecked();
  v8::ScriptOrigin origin(resource_name);
  v8::ScriptCompiler::Source source(source_string, origin);
  v8::Local<v8::Script> script;
  if (!v8::ScriptCompiler::Compile(context, &source).ToLocal(&script)) {
    return false;
  }
  if (script->Run(context).IsEmpty()) return false;
  CHECK(!try_catch.HasCaught());
  return true;
}

}  // namespace

v8::StartupData CreateSnapshotDataBlobInternal(
    v8::SnapshotCreator::FunctionCodeHandling function_code_handling,
    const char* embedded_source, SnapshotCreator& snapshot_creator,
    Snapshot::SerializerFlags serializer_flags) {
  SnapshotCreatorImpl* creator =
      SnapshotCreatorImpl::FromSnapshotCreator(&snapshot_creator);
  {
    auto v8_isolate = reinterpret_cast<v8::Isolate*>(creator->isolate());
    v8::HandleScope scope(v8_isolate);
    v8::Local<v8::Context> context = v8::Context::New(v8_isolate);
    if (embedded_source != nullptr &&
        !RunExtraCode(v8_isolate, context, embedded_source, "<embedded>")) {
      return {};
    }
    creator->SetDefaultContext(Utils::OpenHandle(*context),
                               SerializeEmbedderFieldsCallback());
  }
  return creator->CreateBlob(function_code_handling, serializer_flags);
}

v8::StartupData CreateSnapshotDataBlobInternal(
    v8::SnapshotCreator::FunctionCodeHandling function_code_handling,
    const char* embedded_source, Snapshot::SerializerFlags serializer_flags) {
  std::unique_ptr<v8::ArrayBuffer::Allocator> array_buffer_allocator(
      v8::
"""


```