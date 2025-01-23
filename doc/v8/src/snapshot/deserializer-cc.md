Response:
My thought process to arrive at the summary of `deserializer.cc` went like this:

1. **Identify the core function:** The filename `deserializer.cc` immediately tells me the primary purpose is deserialization. The surrounding directory `snapshot` reinforces this, indicating it's involved in restoring a saved state.

2. **Scan for key terms and data structures:** I looked for recurring terms and important data structures within the provided code snippet. These included:
    * `Deserializer` (the central class)
    * `snapshot` (the context)
    * `payload` (the input data)
    * `HeapObject`, `Map`, `String`, `Code` (core V8 object types)
    * `SlotAccessor` (a key abstraction for writing to object slots)
    * `WriteBarrier` (memory management concern)
    * `ReferenceDescriptor` (describing object references)
    * `back_refs_`, `new_maps_`, `new_scripts_` (collections of deserialized objects)
    * `magic_number_` (for validation)
    * `should_rehash_` (a flag for string canonicalization)

3. **Analyze the `Deserializer` class:** I focused on the methods of the `Deserializer` class to understand its actions:
    * Constructor: Takes `payload`, `magic_number`, etc., indicating the start of the process.
    * `VisitRootPointers`: The main driver, reading data and populating objects.
    * `ReadObject`:  Core function for reading and creating objects.
    * `WriteHeapPointer`, `WriteExternalPointer`:  Methods for writing references to other objects.
    * `Rehash`:  Handles string canonicalization.
    * `DeserializeDeferredObjects`:  Processes objects that can be deserialized later.
    * `PostProcessNewObject`, `PostProcessNewJSReceiver`:  Steps after basic object creation to set up specific object types.

4. **Understand the role of `SlotAccessor`:** This seemed crucial for safe memory manipulation during deserialization. The different `SlotAccessor` types (`SlotAccessorForHeapObject`, `SlotAccessorForRootSlots`, `SlotAccessorForHandle`) suggest different contexts for writing to object slots.

5. **Connect the dots and infer functionality:** Based on the identified terms and methods, I started to piece together the deserialization process:
    * The deserializer reads data from the `payload`.
    * It uses the `magic_number_` to verify the data.
    * It creates `HeapObject`s, setting their `Map` and initial data.
    * It uses `SlotAccessor` to safely write references to other objects.
    * It handles different types of references (strong, weak, indirect, protected).
    * It has mechanisms for dealing with forward references and backreferences.
    * It performs post-processing steps to initialize specific object types (like `JSArrayBuffer`, `JSTypedArray`, `String`).
    * It handles string canonicalization (`should_rehash_`).
    * It logs events for debugging and analysis.

6. **Address specific questions from the prompt:**
    * **".tq" extension:** The code snippet is `.cc`, so it's C++.
    * **JavaScript relationship:** Deserialization is essential for V8's startup, which directly impacts how JavaScript code is loaded and executed. The deserialized data includes compiled code, built-in objects, and the initial state of the V8 heap, all crucial for running JavaScript.
    * **Code logic inference:** The handling of different `SlotAccessor` types and the `WriteHeapPointer` method, especially with the `ReferenceDescriptor`, pointed to the need to handle various object relationships and memory management strategies.
    * **User programming errors:** While the deserializer itself isn't directly used by JavaScript programmers, understanding its role can help diagnose issues related to snapshots and startup performance. Incorrect snapshot creation or corruption could lead to errors during deserialization.

7. **Structure the summary:**  I organized the findings into logical categories: primary function, key aspects, and then addressed the specific questions from the prompt. This provided a clear and comprehensive overview.

8. **Refine and iterate:** I reviewed the generated summary to ensure accuracy, clarity, and completeness, ensuring it captured the most important aspects of the provided code snippet. For instance, I initially missed the significance of `DeserializeDeferredObjects` but later recognized its role in optimization.
好的，根据你提供的 V8 源代码 `v8/src/snapshot/deserializer.cc` 的第一部分，其主要功能可以归纳如下：

**核心功能：**

* **反序列化 V8 堆快照：**  `deserializer.cc` 的核心职责是将预先序列化好的 V8 堆快照数据（`payload`）恢复到内存中，重建 V8 引擎的运行状态。这对于快速启动 V8 引擎至关重要。

**主要组成部分和机制：**

* **`Deserializer` 类：** 这是反序列化的主要驱动类，负责读取快照数据并创建相应的 V8 对象。
* **`SlotAccessor` 类族：**  定义了用于安全访问和写入堆对象槽位的抽象接口。它考虑了垃圾回收的影响，使用 `Handle` 来确保对象移动后仍然能正确访问。
* **写入操作 (`Write` 方法)：** `SlotAccessor` 提供了 `Write` 方法用于将反序列化的值写入对象的槽位。这些方法会处理写屏障，确保内存管理的正确性。
* **引用处理 (`WriteHeapPointer`, `WriteExternalPointer` 等)：**  反序列化过程中需要处理对象之间的引用关系。这些函数负责根据引用描述符 (`ReferenceDescriptor`) 正确地写入堆指针和外部指针。
* **同步点 (`Synchronize` 方法)：**  在反序列化过程中，会插入同步点以确保数据读取和对象创建的顺序正确。
* **延迟反序列化 (`DeserializeDeferredObjects` 方法)：**  某些对象的反序列化可以被延迟，这个方法负责处理这些延迟对象的反序列化。
* **对象后处理 (`PostProcessNewObject`, `PostProcessNewJSReceiver` 方法)：**  在对象基本创建完成后，需要进行一些额外的初始化和设置，例如处理字符串的哈希值、设置类型化数组的指针、处理 JS 接收器的特殊情况等。
* **字符串处理和规范化 (`Rehash` 方法，`StringTableInsertionKey`)：** 反序列化过程中会处理字符串的哈希值，并确保内部化字符串的唯一性。
* **记录事件 (`LogNewMapEvents`, `LogScriptEvents`)：**  在反序列化过程中会记录一些事件，用于调试和性能分析。
* **处理 Back References：**  使用 `back_refs_` 存储已经反序列化的对象，允许后续反序列化引用回这些对象。
* **处理 Forward References：**  虽然在代码片段中没有明确展示，但根据注释和上下文，反序列化器也会处理前向引用。

**关于你的问题：**

* **`.tq` 结尾：**  根据你提供的代码，`v8/src/snapshot/deserializer.cc` 的文件扩展名是 `.cc`，这意味着它是 **C++** 源代码，而不是 Torque 源代码。Torque 源代码的文件扩展名是 `.tq`。
* **与 JavaScript 功能的关系：**  `deserializer.cc` 与 JavaScript 的功能有着**直接且关键**的关系。V8 使用快照技术来加速 JavaScript 引擎的启动。反序列化器负责将保存的堆状态恢复，这包含了 JavaScript 的内置对象、编译后的代码等。如果没有反序列化，V8 每次启动都需要重新创建这些对象和编译代码，会显著降低启动速度。

**JavaScript 示例：**

虽然你不能直接用 JavaScript 操作 `deserializer.cc` 的内部逻辑，但可以观察到其运行结果带来的影响。例如，当你启动 Chrome 或 Node.js 时，V8 会尝试加载快照。如果加载成功，你会发现启动速度很快。

```javascript
// 例如，在 Node.js 中，如果你修改了一些内置模块，
// 并使用特定的选项生成了新的快照，那么下次启动 Node.js 时，
// 如果成功加载了新的快照，这些修改后的模块就能更快地被使用。

// 这不是直接操作 deserializer.cc，而是体现了其工作的效果。
console.time('启动时间');
// ... 应用程序代码 ...
console.timeEnd('启动时间');
```

**代码逻辑推理 (假设输入与输出)：**

假设我们正在反序列化一个包含一个简单 JavaScript 对象的快照：

**假设输入 (简化的快照数据片段)：**

* `kNewObjectLiteral` (表示创建一个对象字面量)
* `size_in_tagged` (对象的大小)
* `kInternalizedString "name"` (属性名 "name")
* `kSmi 10` (属性值 10)

**预期输出 (内存中的 V8 对象)：**

一个 JavaScript 对象，相当于：

```javascript
{ name: 10 }
```

`Deserializer` 会读取 `kNewObjectLiteral`，然后分配内存，读取属性名和属性值，并将它们关联到新创建的对象上。`SlotAccessor` 会被用来安全地写入属性值。

**用户常见的编程错误 (间接相关)：**

虽然用户不直接编写 `deserializer.cc` 的代码，但与快照相关的错误可能会影响到他们：

* **快照损坏：** 如果快照文件被意外修改或损坏，反序列化过程可能会失败，导致 V8 启动失败或出现不可预测的行为。这通常不是用户直接编程导致的，而是系统或环境问题。
* **不兼容的快照版本：**  不同版本的 V8 引擎生成的快照可能不兼容。尝试用旧版本的 V8 反序列化新版本 V8 的快照可能会导致错误。这在开发者尝试自定义构建 V8 时可能会遇到。

**归纳其功能 (基于提供的第一部分)：**

`v8/src/snapshot/deserializer.cc` 的第一部分主要定义了 `Deserializer` 类及其相关的辅助类和方法，用于从二进制快照数据中读取信息，并逐步重建 V8 堆中的各种对象（如 Maps, Strings, HeapObjects）。它关注于内存安全、对象间的引用关系处理以及特定对象类型的初始化。 这一部分奠定了反序列化的基础框架。

### 提示词
```
这是目录为v8/src/snapshot/deserializer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/snapshot/deserializer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/snapshot/deserializer.h"

#include <inttypes.h>

#include "src/base/logging.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/reloc-info-inl.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/handles/global-handles-inl.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-write-barrier-inl.h"
#include "src/heap/heap-write-barrier.h"
#include "src/heap/heap.h"
#include "src/heap/local-heap-inl.h"
#include "src/logging/local-logger.h"
#include "src/logging/log.h"
#include "src/objects/backing-store.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/maybe-object.h"
#include "src/objects/objects-body-descriptors-inl.h"
#include "src/objects/objects.h"
#include "src/objects/slots.h"
#include "src/objects/string.h"
#include "src/roots/roots.h"
#include "src/sandbox/js-dispatch-table-inl.h"
#include "src/snapshot/embedded/embedded-data-inl.h"
#include "src/snapshot/references.h"
#include "src/snapshot/serializer-deserializer.h"
#include "src/snapshot/shared-heap-serializer.h"
#include "src/snapshot/snapshot-data.h"
#include "src/utils/memcopy.h"

// Has to be the last include (doesn't have include guards)
#include "src/objects/object-macros.h"

namespace v8::internal {

#ifdef V8_COMPRESS_POINTERS
#define PRIxTAGGED PRIx32
#else
#define PRIxTAGGED PRIxPTR
#endif

// A SlotAccessor for a slot in a HeapObject, which abstracts the slot
// operations done by the deserializer in a way which is GC-safe. In particular,
// rather than an absolute slot address, this accessor holds a Handle to the
// HeapObject, which is updated if the HeapObject moves.
class SlotAccessorForHeapObject {
 public:
  static SlotAccessorForHeapObject ForSlotIndex(Handle<HeapObject> object,
                                                int index) {
    return SlotAccessorForHeapObject(object, index * kTaggedSize);
  }
  static SlotAccessorForHeapObject ForSlotOffset(Handle<HeapObject> object,
                                                 int offset) {
    return SlotAccessorForHeapObject(object, offset);
  }

  MaybeObjectSlot slot() const { return object_->RawMaybeWeakField(offset_); }
  ExternalPointerSlot external_pointer_slot(ExternalPointerTag tag) const {
    return object_->RawExternalPointerField(offset_, tag);
  }
  Handle<HeapObject> object() const { return object_; }
  int offset() const { return offset_; }

  // Writes the given value to this slot, with an offset (e.g. for repeat
  // writes). Returns the number of slots written (which is one).
  int Write(Tagged<MaybeObject> value, int slot_offset, WriteBarrierMode mode) {
    MaybeObjectSlot current_slot = slot() + slot_offset;
    current_slot.Relaxed_Store(value);
#ifdef V8_STATIC_ROOTS_BOOL
    if (mode != SKIP_WRITE_BARRIER && FastInReadOnlySpaceOrSmallSmi(value)) {
      // TODO(jgruber): Remove this once WriteBarrier::ForValue() contains the
      // same check.
      mode = SKIP_WRITE_BARRIER;
    }
#endif  // V8_STATIC_ROOTS_BOOL
    WriteBarrier::ForValue(*object_, current_slot, value, mode);
    return 1;
  }
  int Write(Tagged<HeapObject> value, HeapObjectReferenceType ref_type,
            int slot_offset, WriteBarrierMode mode) {
    return Write(Tagged<HeapObjectReference>(value, ref_type), slot_offset,
                 mode);
  }
  int Write(DirectHandle<HeapObject> value, HeapObjectReferenceType ref_type,
            int slot_offset, WriteBarrierMode mode) {
    return Write(*value, ref_type, slot_offset, mode);
  }

  int WriteIndirectPointerTo(Tagged<HeapObject> value, WriteBarrierMode mode) {
    // Only ExposedTrustedObjects can be referenced via indirect pointers, so
    // we must have one of these objects here. See the comments in
    // trusted-object.h for more details.
    DCHECK(IsExposedTrustedObject(value));
    Tagged<ExposedTrustedObject> object = Cast<ExposedTrustedObject>(value);

    InstanceType instance_type = value->map()->instance_type();
    IndirectPointerTag tag = IndirectPointerTagFromInstanceType(instance_type);
    IndirectPointerSlot dest = object_->RawIndirectPointerField(offset_, tag);
    dest.store(object);

    WriteBarrier::ForIndirectPointer(*object_, dest, value, mode);
    return 1;
  }

  int WriteProtectedPointerTo(Tagged<TrustedObject> value,
                              WriteBarrierMode mode) {
    DCHECK(IsTrustedObject(*object_));
    Tagged<TrustedObject> host = Cast<TrustedObject>(*object_);
    ProtectedPointerSlot dest = host->RawProtectedPointerField(offset_);
    dest.store(value);
    WriteBarrier::ForProtectedPointer(host, dest, value, mode);
    return 1;
  }

 private:
  SlotAccessorForHeapObject(Handle<HeapObject> object, int offset)
      : object_(object), offset_(offset) {}

  const Handle<HeapObject> object_;
  const int offset_;
};

// A SlotAccessor for absolute full slot addresses.
class SlotAccessorForRootSlots {
 public:
  explicit SlotAccessorForRootSlots(FullMaybeObjectSlot slot) : slot_(slot) {}

  FullMaybeObjectSlot slot() const { return slot_; }
  ExternalPointerSlot external_pointer_slot(ExternalPointerTag tag) const {
    UNREACHABLE();
  }
  Handle<HeapObject> object() const { UNREACHABLE(); }
  int offset() const { UNREACHABLE(); }

  // Writes the given value to this slot, with an offset (e.g. for repeat
  // writes). Returns the number of slots written (which is one).
  int Write(Tagged<MaybeObject> value, int slot_offset, WriteBarrierMode mode) {
    FullMaybeObjectSlot current_slot = slot() + slot_offset;
    current_slot.Relaxed_Store(value);
    return 1;
  }
  int Write(Tagged<HeapObject> value, HeapObjectReferenceType ref_type,
            int slot_offset, WriteBarrierMode mode) {
    return Write(Tagged<HeapObjectReference>(value, ref_type), slot_offset,
                 mode);
  }
  int Write(DirectHandle<HeapObject> value, HeapObjectReferenceType ref_type,
            int slot_offset, WriteBarrierMode mode) {
    return Write(*value, ref_type, slot_offset, mode);
  }
  int WriteIndirectPointerTo(Tagged<HeapObject> value, WriteBarrierMode mode) {
    UNREACHABLE();
  }
  int WriteProtectedPointerTo(Tagged<TrustedObject> value,
                              WriteBarrierMode mode) {
    UNREACHABLE();
  }

 private:
  const FullMaybeObjectSlot slot_;
};

// A SlotAccessor for creating a Handle, which saves a Handle allocation when
// a Handle already exists.
template <typename IsolateT>
class SlotAccessorForHandle {
 public:
  SlotAccessorForHandle(DirectHandle<HeapObject>* handle, IsolateT* isolate)
      : handle_(handle), isolate_(isolate) {}

  MaybeObjectSlot slot() const { UNREACHABLE(); }
  ExternalPointerSlot external_pointer_slot(ExternalPointerTag tag) const {
    UNREACHABLE();
  }
  Handle<HeapObject> object() const { UNREACHABLE(); }
  int offset() const { UNREACHABLE(); }

  int Write(Tagged<MaybeObject> value, int slot_offset, WriteBarrierMode mode) {
    UNREACHABLE();
  }
  int Write(Tagged<HeapObject> value, HeapObjectReferenceType ref_type,
            int slot_offset, WriteBarrierMode mode) {
    DCHECK_EQ(slot_offset, 0);
    DCHECK_EQ(ref_type, HeapObjectReferenceType::STRONG);
    *handle_ = direct_handle(value, isolate_);
    return 1;
  }
  int Write(DirectHandle<HeapObject> value, HeapObjectReferenceType ref_type,
            int slot_offset, WriteBarrierMode mode) {
    DCHECK_EQ(slot_offset, 0);
    DCHECK_EQ(ref_type, HeapObjectReferenceType::STRONG);
    *handle_ = value;
    return 1;
  }
  int WriteIndirectPointerTo(Tagged<HeapObject> value, WriteBarrierMode mode) {
    UNREACHABLE();
  }
  int WriteProtectedPointerTo(Tagged<TrustedObject> value,
                              WriteBarrierMode mode) {
    UNREACHABLE();
  }

 private:
  DirectHandle<HeapObject>* handle_;
  IsolateT* isolate_;
};

template <typename IsolateT>
template <typename SlotAccessor>
int Deserializer<IsolateT>::WriteHeapPointer(SlotAccessor slot_accessor,
                                             Tagged<HeapObject> heap_object,
                                             ReferenceDescriptor descr,
                                             WriteBarrierMode mode) {
  if (descr.is_indirect_pointer) {
    return slot_accessor.WriteIndirectPointerTo(heap_object, mode);
  } else {
    return slot_accessor.Write(heap_object, descr.type, 0, mode);
  }
}

template <typename IsolateT>
template <typename SlotAccessor>
int Deserializer<IsolateT>::WriteHeapPointer(
    SlotAccessor slot_accessor, DirectHandle<HeapObject> heap_object,
    ReferenceDescriptor descr, WriteBarrierMode mode) {
  if (descr.is_indirect_pointer) {
    return slot_accessor.WriteIndirectPointerTo(*heap_object, mode);
  } else if (descr.is_protected_pointer) {
    DCHECK(IsTrustedObject(*heap_object));
    return slot_accessor.WriteProtectedPointerTo(
        Cast<TrustedObject>(*heap_object), mode);
  } else {
    return slot_accessor.Write(heap_object, descr.type, 0, mode);
  }
}

template <typename IsolateT>
int Deserializer<IsolateT>::WriteExternalPointer(Tagged<HeapObject> host,
                                                 ExternalPointerSlot dest,
                                                 Address value) {
  DCHECK(!next_reference_is_weak_ && !next_reference_is_indirect_pointer_ &&
         !next_reference_is_protected_pointer);

  #ifdef V8_ENABLE_SANDBOX
  ExternalPointerTable::ManagedResource* managed_resource = nullptr;
  ExternalPointerTable* owning_table = nullptr;
  ExternalPointerHandle original_handle = kNullExternalPointerHandle;
  if (IsManagedExternalPointerType(dest.tag())) {
    // This can currently only happen during snapshot stress mode as we cannot
    // normally serialized managed resources. In snapshot stress mode, the new
    // isolate will be destroyed and the old isolate (really, the old isolate's
    // external pointer table) therefore effectively retains ownership of the
    // resource. As such, we need to save and restore the relevant fields of
    // the external resource. Once the external pointer table itself destroys
    // the managed resource when freeing the corresponding table entry, this
    // workaround can be removed again.
    DCHECK(v8_flags.stress_snapshot);
    managed_resource =
        reinterpret_cast<ExternalPointerTable::ManagedResource*>(value);
    owning_table = managed_resource->owning_table_;
    original_handle = managed_resource->ept_entry_;
    managed_resource->owning_table_ = nullptr;
    managed_resource->ept_entry_ = kNullExternalPointerHandle;
  }
#endif  // V8_ENABLE_SANDBOX

  dest.init(main_thread_isolate(), host, value);

#ifdef V8_ENABLE_SANDBOX
  if (managed_resource) {
    managed_resource->owning_table_ = owning_table;
    managed_resource->ept_entry_ = original_handle;
  }
#endif  // V8_ENABLE_SANDBOX

  // ExternalPointers can only be written into HeapObject fields, therefore they
  // cover (kExternalPointerSlotSize / kTaggedSize) slots.
  return (kExternalPointerSlotSize / kTaggedSize);
}

namespace {
#ifdef DEBUG
int GetNumApiReferences(Isolate* isolate) {
  int num_api_references = 0;
  // The read-only deserializer is run by read-only heap set-up before the
  // heap is fully set up. External reference table relies on a few parts of
  // this set-up (like old-space), so it may be uninitialized at this point.
  if (isolate->isolate_data()->external_reference_table()->is_initialized()) {
    // Count the number of external references registered through the API.
    if (isolate->api_external_references() != nullptr) {
      while (isolate->api_external_references()[num_api_references] != 0) {
        num_api_references++;
      }
    }
  }
  return num_api_references;
}
int GetNumApiReferences(LocalIsolate* isolate) { return 0; }
#endif
}  // namespace

template <typename IsolateT>
Deserializer<IsolateT>::Deserializer(IsolateT* isolate,
                                     base::Vector<const uint8_t> payload,
                                     uint32_t magic_number,
                                     bool deserializing_user_code,
                                     bool can_rehash)
    : isolate_(isolate),
      attached_objects_(isolate),
      source_(payload),
      magic_number_(magic_number),
      new_maps_(isolate),
      new_allocation_sites_(isolate),
      new_code_objects_(isolate),
      accessor_infos_(isolate),
      function_template_infos_(isolate),
      new_scripts_(isolate),
      new_descriptor_arrays_(isolate->heap()),
      deserializing_user_code_(deserializing_user_code),
      should_rehash_((v8_flags.rehash_snapshot && can_rehash) ||
                     deserializing_user_code),
      to_rehash_(isolate) {
  DCHECK_NOT_NULL(isolate);
  isolate->RegisterDeserializerStarted();

  // We start the indices here at 1, so that we can distinguish between an
  // actual index and an empty backing store (serialized as
  // kEmptyBackingStoreRefSentinel) in a deserialized object requiring fix-up.
  static_assert(kEmptyBackingStoreRefSentinel == 0);
  backing_stores_.push_back({});

#ifdef DEBUG
  num_api_references_ = GetNumApiReferences(isolate);
#endif  // DEBUG
  CHECK_EQ(magic_number_, SerializedData::kMagicNumber);
}

template <typename IsolateT>
void Deserializer<IsolateT>::Rehash() {
  DCHECK(should_rehash());
  for (DirectHandle<HeapObject> item : to_rehash_) {
    item->RehashBasedOnMap(isolate());
  }
}

template <typename IsolateT>
Deserializer<IsolateT>::~Deserializer() {
#ifdef DEBUG
  // Do not perform checks if we aborted deserialization.
  if (source_.position() == 0) return;
  // Check that we only have padding bytes remaining.
  while (source_.HasMore()) DCHECK_EQ(kNop, source_.Get());
  // Check that there are no remaining forward refs.
  DCHECK_EQ(num_unresolved_forward_refs_, 0);
  DCHECK(unresolved_forward_refs_.empty());
#endif  // DEBUG
  isolate_->RegisterDeserializerFinished();
}

// This is called on the roots.  It is the driver of the deserialization
// process.  It is also called on the body of each function.
template <typename IsolateT>
void Deserializer<IsolateT>::VisitRootPointers(Root root,
                                               const char* description,
                                               FullObjectSlot start,
                                               FullObjectSlot end) {
  ReadData(FullMaybeObjectSlot(start), FullMaybeObjectSlot(end));
}

template <typename IsolateT>
void Deserializer<IsolateT>::Synchronize(VisitorSynchronization::SyncTag tag) {
  static const uint8_t expected = kSynchronize;
  CHECK_EQ(expected, source_.Get());
  if (v8_flags.trace_deserialization) {
    const char* name;
    switch (tag) {
#define CASE(ID, NAME)             \
  case VisitorSynchronization::ID: \
    name = NAME;                   \
    break;
      ROOT_ID_LIST(CASE)
#undef CASE
      default:
        name = "(!unknown!)";
        break;
    }
    PrintF("Synchronize %d %s\n", tag, name);
  }
}

template <typename IsolateT>
void Deserializer<IsolateT>::DeserializeDeferredObjects() {
  if (v8_flags.trace_deserialization) {
    PrintF("-- Deferred objects\n");
  }
  for (int code = source_.Get(); code != kSynchronize; code = source_.Get()) {
    SnapshotSpace space = NewObject::Decode(code);
    ReadObject(space);
  }
}

template <typename IsolateT>
void Deserializer<IsolateT>::LogNewMapEvents() {
  if (V8_LIKELY(!v8_flags.log_maps)) return;
  DisallowGarbageCollection no_gc;
  for (DirectHandle<Map> map : new_maps_) {
    DCHECK(v8_flags.log_maps);
    LOG(isolate(), MapCreate(*map));
    LOG(isolate(), MapDetails(*map));
  }
}

template <typename IsolateT>
void Deserializer<IsolateT>::WeakenDescriptorArrays() {
  isolate()->heap()->WeakenDescriptorArrays(std::move(new_descriptor_arrays_));
}

template <typename IsolateT>
void Deserializer<IsolateT>::LogScriptEvents(Tagged<Script> script) {
  DisallowGarbageCollection no_gc;
  LOG(isolate(), ScriptEvent(ScriptEventType::kDeserialize, script->id()));
  LOG(isolate(), ScriptDetails(script));
}

namespace {
template <typename IsolateT>
uint32_t ComputeRawHashField(IsolateT* isolate, Tagged<String> string) {
  // Make sure raw_hash_field() is computed.
  string->EnsureHash(SharedStringAccessGuardIfNeeded(isolate));
  return string->raw_hash_field();
}
}  // namespace

StringTableInsertionKey::StringTableInsertionKey(
    Isolate* isolate, DirectHandle<String> string,
    DeserializingUserCodeOption deserializing_user_code)
    : StringTableKey(ComputeRawHashField(isolate, *string), string->length()),
      string_(string) {
#ifdef DEBUG
  deserializing_user_code_ = deserializing_user_code;
#endif
  DCHECK(IsInternalizedString(*string));
}

StringTableInsertionKey::StringTableInsertionKey(
    LocalIsolate* isolate, DirectHandle<String> string,
    DeserializingUserCodeOption deserializing_user_code)
    : StringTableKey(ComputeRawHashField(isolate, *string), string->length()),
      string_(string) {
#ifdef DEBUG
  deserializing_user_code_ = deserializing_user_code;
#endif
  DCHECK(IsInternalizedString(*string));
}

template <typename IsolateT>
bool StringTableInsertionKey::IsMatch(IsolateT* isolate,
                                      Tagged<String> string) {
  // We want to compare the content of two strings here.
  return string_->SlowEquals(string, SharedStringAccessGuardIfNeeded(isolate));
}
template bool StringTableInsertionKey::IsMatch(Isolate* isolate,
                                               Tagged<String> string);
template bool StringTableInsertionKey::IsMatch(LocalIsolate* isolate,
                                               Tagged<String> string);

namespace {

void NoExternalReferencesCallback() {
  // The following check will trigger if a function or object template
  // with references to native functions have been deserialized from
  // snapshot, but no actual external references were provided when the
  // isolate was created.
  FATAL("No external references provided via API");
}

void PostProcessExternalString(Tagged<ExternalString> string,
                               Isolate* isolate) {
  DisallowGarbageCollection no_gc;
  uint32_t index = string->GetResourceRefForDeserialization();
  Address address =
      static_cast<Address>(isolate->api_external_references()[index]);
  string->InitExternalPointerFields(isolate);
  string->set_address_as_resource(isolate, address);
  isolate->heap()->UpdateExternalString(string, 0,
                                        string->ExternalPayloadSize());
  isolate->heap()->RegisterExternalString(string);
}

}  // namespace

// Should be called only on the main thread (not thread safe).
template <>
void Deserializer<Isolate>::PostProcessNewJSReceiver(
    Tagged<Map> map, DirectHandle<JSReceiver> obj, InstanceType instance_type,
    SnapshotSpace space) {
  DCHECK_EQ(map->instance_type(), instance_type);

  if (InstanceTypeChecker::IsJSDataView(instance_type) ||
      InstanceTypeChecker::IsJSRabGsabDataView(instance_type)) {
    auto data_view = Cast<JSDataViewOrRabGsabDataView>(*obj);
    auto buffer = Cast<JSArrayBuffer>(data_view->buffer());
    if (buffer->was_detached()) {
      // Directly set the data pointer to point to the EmptyBackingStoreBuffer.
      // Otherwise, we might end up setting it to EmptyBackingStoreBuffer() +
      // byte_offset() which would result in an invalid pointer.
      data_view->set_data_pointer(main_thread_isolate(),
                                  EmptyBackingStoreBuffer());
    } else {
      void* backing_store = buffer->backing_store();
      data_view->set_data_pointer(
          main_thread_isolate(),
          reinterpret_cast<uint8_t*>(backing_store) + data_view->byte_offset());
    }
  } else if (InstanceTypeChecker::IsJSTypedArray(instance_type)) {
    auto typed_array = Cast<JSTypedArray>(*obj);
    // Note: ByteArray objects must not be deferred s.t. they are
    // available here for is_on_heap(). See also: CanBeDeferred.
    // Fixup typed array pointers.
    if (typed_array->is_on_heap()) {
      typed_array->AddExternalPointerCompensationForDeserialization(
          main_thread_isolate());
    } else {
      // Serializer writes backing store ref as a DataPtr() value.
      uint32_t store_index =
          typed_array->GetExternalBackingStoreRefForDeserialization();
      auto backing_store = backing_stores_[store_index];
      void* start = backing_store ? backing_store->buffer_start() : nullptr;
      if (!start) start = EmptyBackingStoreBuffer();
      typed_array->SetOffHeapDataPtr(main_thread_isolate(), start,
                                     typed_array->byte_offset());
    }
  } else if (InstanceTypeChecker::IsJSArrayBuffer(instance_type)) {
    auto buffer = Cast<JSArrayBuffer>(*obj);
    uint32_t store_index = buffer->GetBackingStoreRefForDeserialization();
    buffer->init_extension();
    if (store_index == kEmptyBackingStoreRefSentinel) {
      buffer->set_backing_store(main_thread_isolate(),
                                EmptyBackingStoreBuffer());
    } else {
      auto bs = backing_store(store_index);
      SharedFlag shared =
          bs && bs->is_shared() ? SharedFlag::kShared : SharedFlag::kNotShared;
      DCHECK_IMPLIES(bs,
                     buffer->is_resizable_by_js() == bs->is_resizable_by_js());
      ResizableFlag resizable = bs && bs->is_resizable_by_js()
                                    ? ResizableFlag::kResizable
                                    : ResizableFlag::kNotResizable;
      buffer->Setup(shared, resizable, bs, main_thread_isolate());
    }
  }
}

template <>
void Deserializer<LocalIsolate>::PostProcessNewJSReceiver(
    Tagged<Map> map, DirectHandle<JSReceiver> obj, InstanceType instance_type,
    SnapshotSpace space) {
  UNREACHABLE();
}

template <typename IsolateT>
void Deserializer<IsolateT>::PostProcessNewObject(DirectHandle<Map> map,
                                                  Handle<HeapObject> obj,
                                                  SnapshotSpace space) {
  DisallowGarbageCollection no_gc;
  Tagged<Map> raw_map = *map;
  DCHECK_EQ(raw_map, obj->map(isolate_));
  InstanceType instance_type = raw_map->instance_type();
  Tagged<HeapObject> raw_obj = *obj;
  DCHECK_IMPLIES(deserializing_user_code(), should_rehash());
  if (should_rehash()) {
    if (InstanceTypeChecker::IsString(instance_type)) {
      // Uninitialize hash field as we need to recompute the hash.
      Tagged<String> string = Cast<String>(raw_obj);
      string->set_raw_hash_field(String::kEmptyHashField);
      // Rehash strings before read-only space is sealed. Strings outside
      // read-only space are rehashed lazily. (e.g. when rehashing dictionaries)
      if (space == SnapshotSpace::kReadOnlyHeap) {
        PushObjectToRehash(obj);
      }
    } else if (raw_obj->NeedsRehashing(instance_type)) {
      PushObjectToRehash(obj);
    }

    if (deserializing_user_code()) {
      if (InstanceTypeChecker::IsInternalizedString(instance_type)) {
        // Canonicalize the internalized string. If it already exists in the
        // string table, set the string to point to the existing one and patch
        // the deserialized string handle to point to the existing one.
        // TODO(leszeks): This handle patching is ugly, consider adding an
        // explicit internalized string bytecode. Also, the new thin string
        // should be dead, try immediately freeing it.
        Handle<String> string = Cast<String>(obj);

        StringTableInsertionKey key(
            isolate(), string,
            DeserializingUserCodeOption::kIsDeserializingUserCode);
        Tagged<String> result =
            *isolate()->string_table()->LookupKey(isolate(), &key);

        if (result != raw_obj) {
          Cast<String>(raw_obj)->MakeThin(isolate(), result);
          // Mutate the given object handle so that the backreference entry is
          // also updated.
          obj.PatchValue(result);
        }
        return;
      } else if (InstanceTypeChecker::IsScript(instance_type)) {
        new_scripts_.push_back(Cast<Script>(obj));
      } else if (InstanceTypeChecker::IsAllocationSite(instance_type)) {
        // We should link new allocation sites, but we can't do this immediately
        // because |AllocationSite::HasWeakNext()| internally accesses
        // |Heap::roots_| that may not have been initialized yet. So defer this
        // to |ObjectDeserializer::CommitPostProcessedObjects()|.
        new_allocation_sites_.push_back(Cast<AllocationSite>(obj));
      } else {
        // We dont defer ByteArray because JSTypedArray needs the base_pointer
        // ByteArray immediately if it's on heap.
        DCHECK(CanBeDeferred(*obj, SlotType::kAnySlot) ||
               InstanceTypeChecker::IsByteArray(instance_type));
      }
    }
  }

  if (InstanceTypeChecker::IsInstructionStream(instance_type)) {
    // We flush all code pages after deserializing the startup snapshot.
    // Hence we only remember each individual code object when deserializing
    // user code.
    if (deserializing_user_code()) {
      new_code_objects_.push_back(Cast<InstructionStream>(obj));
    }
  } else if (InstanceTypeChecker::IsCode(instance_type)) {
    Tagged<Code> code = Cast<Code>(raw_obj);
    if (!code->has_instruction_stream()) {
      code->SetInstructionStartForOffHeapBuiltin(
          main_thread_isolate(), EmbeddedData::FromBlob(main_thread_isolate())
                                     .InstructionStartOf(code->builtin_id()));
    } else {
      code->UpdateInstructionStart(main_thread_isolate(),
                                   code->instruction_stream());
    }
  } else if (InstanceTypeChecker::IsSharedFunctionInfo(instance_type)) {
    Tagged<SharedFunctionInfo> sfi = Cast<SharedFunctionInfo>(raw_obj);
    // Reset the id to avoid collisions - it must be unique in this isolate.
    sfi->set_unique_id(isolate()->GetAndIncNextUniqueSfiId());
  } else if (InstanceTypeChecker::IsMap(instance_type)) {
    if (v8_flags.log_maps) {
      // Keep track of all seen Maps to log them later since they might be only
      // partially initialized at this point.
      new_maps_.push_back(Cast<Map>(obj));
    }
  } else if (InstanceTypeChecker::IsAccessorInfo(instance_type)) {
#ifdef USE_SIMULATOR
    accessor_infos_.push_back(Cast<AccessorInfo>(obj));
#endif
  } else if (InstanceTypeChecker::IsFunctionTemplateInfo(instance_type)) {
#ifdef USE_SIMULATOR
    function_template_infos_.push_back(Cast<FunctionTemplateInfo>(obj));
#endif
  } else if (InstanceTypeChecker::IsExternalString(instance_type)) {
    PostProcessExternalString(Cast<ExternalString>(raw_obj),
                              main_thread_isolate());
  } else if (InstanceTypeChecker::IsJSReceiver(instance_type)) {
    // PostProcessNewJSReceiver may trigger GC.
    no_gc.Release();
    return PostProcessNewJSReceiver(raw_map, Cast<JSReceiver>(obj),
                                    instance_type, space);
  } else if (InstanceTypeChecker::IsDescriptorArray(instance_type)) {
    DCHECK(InstanceTypeChecker::IsStrongDescriptorArray(instance_type));
    auto descriptors = Cast<DescriptorArray>(obj);
    new_descriptor_arrays_.Push(*descriptors);
  } else if (InstanceTypeChecker::IsNativeContext(instance_type)) {
    Cast<NativeContext>(raw_obj)->init_microtask_queue(main_thread_isolate(),
                                                       nullptr);
  } else if (InstanceTypeChecker::IsScript(instance_type)) {
    LogScriptEvents(Cast<Script>(*obj));
  }
}

template <typename IsolateT>
typename Deserializer<IsolateT>::ReferenceDescriptor
Deserializer<IsolateT>::GetAndResetNextReferenceDescriptor() {
  DCHECK(!(next_reference_is_weak_ && next_reference_is_indirect_pointer_));
  ReferenceDescriptor desc;
  desc.type = next_reference_is_weak_ ? HeapObjectReferenceType::WEAK
                                      : HeapObjectReferenceType::STRONG;
  next_reference_is_weak_ = false;
  desc.is_indirect_pointer = next_reference_is_indirect_pointer_;
  next_reference_is_indirect_pointer_ = false;
  desc.is_protected_pointer = next_reference_is_protected_pointer;
  next_reference_is_protected_pointer = false;
  return desc;
}

template <typename IsolateT>
Handle<HeapObject> Deserializer<IsolateT>::GetBackReferencedObject() {
  return GetBackReferencedObject(source_.GetUint30());
}

template <typename IsolateT>
Handle<HeapObject> Deserializer<IsolateT>::GetBackReferencedObject(
    uint32_t index) {
  Handle<HeapObject> obj = back_refs_[index];

  // We don't allow ThinStrings in backreferences -- if internalization produces
  // a thin string, then it should also update the backref handle.
  DCHECK(!IsThinString(*obj, isolate()));

  hot_objects_.Add(obj);
  DCHECK(!HasWeakHeapObjectTag(*obj));
  return obj;
}

template <typename IsolateT>
DirectHandle<HeapObject> Deserializer<IsolateT>::ReadObject() {
  DirectHandle<HeapObject> ret;
  CHECK_EQ(ReadSingleBytecodeData(
               source_.Get(), SlotAccessorForHandle<IsolateT>(&ret, isolate())),
           1);
  return ret;
}

namespace {
AllocationType SpaceToAllocation(SnapshotSpace space) {
  switch (space) {
    case SnapshotSpace::kCode:
      return AllocationType::kCode;
    case SnapshotSpace::kOld:
      return AllocationType::kOld;
    case SnapshotSpace::kReadOnlyHeap:
      return AllocationType::kReadOnly;
    case SnapshotSpace::kTrusted:
      return AllocationType::kTrusted;
  }
}
}  // namespace

template <typename IsolateT>
Handle<HeapObject> Deserializer<IsolateT>::ReadObject(SnapshotSpace space) {
  const int size_in_tagged = source_.GetUint30();
  const int size_in_bytes = size_in_tagged * kTaggedSize;

  // The map can't be a forward ref. If you want the map to be a forward ref,
  // then you're probably serializing the meta-map, in which case you want to
  // use the kNewContextlessMetaMap/kNewContextfulMetaMap bytecode.
  DCHECK_NE(source()->Peek(), kRegisterPendingForwardRef);
  DirectHandle<Map> map = Cast<Map>(ReadObject());

  AllocationType allocation = SpaceToAllocation(space);

  // When sharing a string table, all in-place internalizable and internalized
  // strings internalized strings are allocated in the shared heap.
  //
  // TODO(12007): When shipping, add a new SharedOld SnapshotSpace.
  if (v8_flags.shared_string_table) {
    InstanceType instance_type = map->instance_type();
    if (InstanceTypeChecker::IsInternalizedString(instance_type) ||
        String::IsInPlaceInternalizable(instance_type)) {
      allocation = isolate()
                       ->factory()
                       ->RefineAllocationTypeForInPlaceInternalizableString(
                           allocation, *map);
    }
  }

  // Filling an object's fields can cause GCs and heap walks, so this object has
  // to be in a 'sufficiently initialised' state by the time the next allocation
  // can happen. For this to be the case, the object is carefully deserialized
  // as follows:
  //   * The space for the object is allocated.
  //   * The map is set on the object so that the GC knows what type the object
  //     has.
  //   * The rest of the object is filled with a fixed Smi value
  //     - This is a Smi so that tagged fields become initialized to a valid
  //       tagged value.
  //     - It's a fixed value, "Smi::uninitialized_deserialization_value()", so
  //       that we can DCHECK for it when reading objects that are assumed to be
  //       partially initialized objects.
  //   * The fields of the object are deserialized in order, under the
  //     assumption that objects are laid out in such a way that any fields
  //     required for object iteration (e.g. length fields) are deserialized
  //     before fields with objects.
  //     - We ensure this is the case by DCHECKing on object allocation that the
  //       previously allocated object has a valid size (see `Allocate`).
  Tagged<HeapObject> raw_obj =
      Allocate(allocation, size_in_bytes, HeapObject::RequiredAlignment(*map));
  raw_obj->set_map_after_allocation(isolate_, *map);
  MemsetTagged(raw_obj->RawField(kTaggedSize),
               Smi::uninitialized_deserialization_value(), size_in_tagged - 1);
  DCHECK(raw_obj->CheckRequiredAlignment(isolate()));

  // Make sure BytecodeArrays have a valid age, so that the marker doesn't
  // break when making them older.
  if (IsSharedFunctionInfo(raw_obj, isolate())) {
    Cast<SharedFunctionInfo>(raw_obj)->set_age(0);
  } else if (IsEphemeronHashTable(raw_obj)) {
    // Make sure EphemeronHashTables have valid HeapObject keys, so that the
    // marker does not break when marki
```