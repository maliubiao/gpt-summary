Response:
Let's break down the thought process for analyzing the provided C++ code and generating the requested information.

**1. Understanding the Core Task:**

The request asks for an analysis of `read-only-serializer.cc`. The key is to understand what its purpose is within the V8 JavaScript engine. The name itself, "read-only serializer," strongly suggests it's involved in saving the state of the read-only portion of the V8 heap.

**2. Initial Skimming and Keyword Recognition:**

I'd start by quickly reading through the code, looking for recurring terms and concepts. Some initial observations would include:

* **Namespaces:** `v8::internal`, `v8::internal::ro` (likely "read-only").
* **Classes:** `ReadOnlySerializer`, `ReadOnlyHeapImageSerializer`, `ObjectPreProcessor`, `ReadOnlySegmentForSerialization`, `EncodeRelocationsVisitor`. These names provide clues about the modularity and steps involved.
* **Data Structures:** `std::vector<MemoryRegion>`, `ro::BitSet`.
* **Key V8 Concepts:** `Isolate`, `Heap`, `ReadOnlyHeap`, `Code`, `Map`, `Objects`, `Snapshot`, `ExternalReference`.
* **Serialization Primitives:** `SnapshotByteSink`, `Put`, `PutUint30`, `PutRaw`.
* **Looping and Iteration:**  The code iterates over pages and objects in the read-only heap.
* **Preprocessing:** The `ObjectPreProcessor` class indicates modifications before serialization.
* **Relocation:** `EncodeRelocationsVisitor` suggests handling pointers and their adjustments.
* **Static Roots:** The conditional compilation based on `V8_STATIC_ROOTS_BOOL`.

**3. Deeper Dive into Key Classes and Functions:**

Next, I'd focus on the most prominent classes and their methods:

* **`ReadOnlySerializer::Serialize()`:**  This seems like the main entry point. It calls `ReadOnlyHeapImageSerializer::Serialize`. It also iterates through read-only objects for statistics.
* **`ReadOnlyHeapImageSerializer::SerializeImpl()`:** This function outlines the high-level serialization process: allocate pages, serialize page contents, and emit the read-only roots table. The use of `SnapshotByteSink` confirms it's writing data for the snapshot.
* **`ReadOnlySegmentForSerialization`:** This class deals with serializing a *portion* of a read-only page. It copies the content and handles preprocessing and relocation.
* **`ObjectPreProcessor`:**  This class modifies specific object types (`AccessorInfo`, `FunctionTemplateInfo`, `Code`) before serialization, particularly focusing on external pointers. This suggests the read-only snapshot needs to handle external resources.
* **`EncodeRelocationsVisitor`:**  This class is crucial for handling pointers within the read-only heap. It encodes tagged slots and records their locations. This is necessary because the memory addresses might change when the snapshot is loaded.

**4. Inferring Functionality:**

Based on the above observations, I can start inferring the overall functionality:

* **Saving the Read-Only Heap:** The primary goal is to create a snapshot of the read-only portion of the V8 heap. This includes built-in objects, constant values, and compiled code.
* **Efficiency:** Serializing the read-only heap separately is an optimization, as it doesn't change during runtime. This avoids redundant serialization of these stable parts.
* **Relocation:**  Since memory addresses can change between V8 instances, the serializer needs to record information to adjust pointers when the snapshot is deserialized.
* **External References:** The handling of external pointers suggests the read-only heap might contain references to resources outside the heap, like native functions.
* **Preprocessing for Stability:**  The `ObjectPreProcessor` hints that certain object fields need to be transformed or encoded to ensure the snapshot is consistent and valid across different runs.

**5. Addressing Specific Questions in the Prompt:**

Now, I can specifically address each part of the prompt:

* **Functionality:** Summarize the inferred functionality clearly.
* **Torque:** Check the file extension. It's `.cc`, not `.tq`, so it's not Torque.
* **JavaScript Relationship:** Consider how the read-only heap connects to JavaScript. It holds built-in objects and compiled code, both essential for executing JavaScript. Provide examples of how these are used (e.g., `Array.prototype.push`).
* **Code Logic and Input/Output:**  Focus on a specific part of the logic, like `EncodeRelocationsVisitor`. Hypothesize an input (a read-only object with pointers) and the expected output (the object's data with encoded pointers and the relocation table). Keep it simple for demonstration.
* **Common Programming Errors:** Think about the implications of read-only memory. Attempting to modify it would be an error. Provide a simple JavaScript example that would trigger this within the context of built-in objects.

**6. Refining and Organizing the Output:**

Finally, structure the information logically, using clear headings and formatting. Explain technical terms where necessary. Ensure the JavaScript examples are concise and illustrate the points effectively. Double-check for accuracy and consistency. The goal is to provide a comprehensive and easy-to-understand explanation of the code's purpose and mechanics.

**(Self-Correction during the process):**

* **Initial thought:**  Maybe the preprocessing is about compression. **Correction:**  Looking closer, it's more about encoding external references and clearing non-essential data for serialization.
* **Assumption:** The relocation is purely about addresses. **Correction:**  It also handles encoding tagged pointers for efficiency.
* **Overly complex example:** Initially considered a very complex JavaScript example. **Correction:** Simplified to a basic illustration of using built-in objects.

By following this structured approach, breaking down the code into smaller parts, and focusing on understanding the core concepts, it's possible to effectively analyze even relatively complex C++ code and generate a meaningful explanation.
好的，让我们来分析一下 `v8/src/snapshot/read-only-serializer.cc` 这个 V8 源代码文件的功能。

**主要功能:**

`v8/src/snapshot/read-only-serializer.cc` 的主要功能是**将 V8 引擎的只读堆（read-only heap）序列化到快照中**。

更具体地说，它负责以下任务：

1. **遍历只读堆:**  它会遍历 V8 引擎的只读堆中的所有对象。只读堆包含了在 V8 引擎启动后不会被修改的对象，例如内置对象（`Array.prototype`，`Object.prototype` 等）、一些常量以及编译后的代码。
2. **预处理对象:** 在序列化之前，会对某些特定类型的对象进行预处理，以确保它们能够正确地被反序列化。这可能包括：
    * **编码外部指针:**  对于包含外部指针（指向 V8 堆外部内存的指针）的对象，会将其编码为可以在反序列化时重新构建的格式。这涉及到 `ExternalReferenceEncoder`。
    * **清除不必要的元数据:** 例如，对于 `Code` 对象（编译后的 JavaScript 代码），会清除一些在序列化后不需要的信息，例如指令起始位置和调试信息。
3. **创建只读堆镜像:**  它会将只读堆的内容复制到一个临时的、用于序列化的内存区域中。
4. **记录重定位信息:**  由于只读堆中的对象可能包含指向其他只读堆对象的指针，这些指针在反序列化时可能需要调整。该文件会记录这些需要重定位的指针的位置和目标。
5. **将数据写入快照:**  最终，序列化后的数据（包括对象的内容和重定位信息）会被写入到 `SnapshotByteSink` 中，形成快照的一部分。这个快照可以被保存到磁盘，并在 V8 引擎启动时加载，从而加速启动过程。

**关于文件扩展名和 Torque:**

您提供的信息是正确的。如果 `v8/src/snapshot/read-only-serializer.cc` 的文件名以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是一种用于在 V8 中定义内置函数和类型的领域特定语言。然而，由于该文件以 `.cc` 结尾，它是一个标准的 C++ 源代码文件。

**与 JavaScript 的关系 (及 JavaScript 示例):**

`v8/src/snapshot/read-only-serializer.cc`  直接关系到 V8 引擎如何高效地启动和运行 JavaScript 代码。只读堆中包含的许多对象是 JavaScript 运行的基础。

以下是一些 JavaScript 示例，它们的操作依赖于只读堆中序列化的对象：

```javascript
// 访问内置对象
console.log(Array.prototype.push); // Array 的原型方法存储在只读堆中

// 使用字面量创建对象和数组
const obj = {}; // Object 的原型（Object.prototype）存储在只读堆中
const arr = []; // Array 的原型（Array.prototype）存储在只读堆中

// 调用内置函数
parseInt("10"); // parseInt 这样的全局函数及其相关的对象可能部分或全部在只读堆中

// 使用模板字面量
const name = "World";
const greeting = `Hello, ${name}!`; // 模板字面量的处理逻辑依赖于只读堆中的代码

// 错误处理
try {
  throw new Error("Something went wrong");
} catch (e) {
  console.error(e.message); // Error 对象及其原型存储在只读堆中
}
```

**代码逻辑推理 (假设输入与输出):**

假设输入是一个包含以下只读堆对象的简单场景：

* 一个 `Array` 构造函数对象。
* `Array.prototype` 对象，包含 `push` 方法。`push` 方法可能是一个 `Code` 对象（编译后的代码）。
* 一个字符串常量 "hello"。

**预期的序列化过程和输出（简化描述）：**

1. **`ReadOnlyHeapImageSerializer::SerializeImpl`** 会开始遍历只读堆。
2. **`ReadOnlySegmentForSerialization`** 可能会处理包含 `Array` 构造函数和 `Array.prototype` 的内存段。
3. **`ObjectPreProcessor`** 可能会处理 `Code` 对象 (如果 `push` 方法是编译后的)，清除一些调试信息。
4. **指针编码:** 如果 `Array.prototype` 的内部槽位指向 `push` 方法的 `Code` 对象，`EncodeRelocationsVisitor` 会记录这个指针，以便反序列化时可以正确恢复。
5. **输出:**  `SnapshotByteSink` 会接收如下类型的数据（概念性表示）：

   ```
   Bytecode::kAllocatePage  // 分配页
   PageIndex: 0
   PageSize: ...

   Bytecode::kSegment      // 开始段
   PageIndex: 0
   SegmentOffset: ...
   SegmentSize: ...
   RawData: [Array 构造函数的二进制数据, Array.prototype 的二进制数据, ...]
   Bytecode::kRelocateSegment // 重定位段
   RelocationData: [OffsetOf(Array.prototype.push_pointer), TargetIndex(Code_Object_Index)]

   Bytecode::kSegment      // 开始另一个段 (可能包含字符串 "hello")
   PageIndex: 0
   SegmentOffset: ...
   SegmentSize: ...
   RawData: [字符串 "hello" 的二进制数据]

   Bytecode::kReadOnlyRootsTable // 只读根表
   // ... 编码后的只读根对象 ...

   Bytecode::kFinalizeReadOnlySpace
   ```

**涉及的用户常见编程错误 (举例说明):**

虽然用户无法直接修改只读堆中的对象，但了解其存在可以帮助理解一些潜在的错误：

1. **意外地修改内置对象的原型:**  虽然技术上可以修改内置对象的原型，但这通常被认为是糟糕的实践，可能会导致难以调试的问题。只读堆的存在强调了这些内置对象是引擎的基础，不应随意更改。

   ```javascript
   // 这是一个糟糕的实践！
   Array.prototype.myCustomMethod = function() {
     console.log("Custom method called!");
   };

   const arr = [1, 2, 3];
   arr.myCustomMethod(); // 这会工作，但可能会有副作用
   ```

   只读堆序列化的是引擎的原始状态，不包括这些运行时修改。因此，在不同的 V8 实例或快照加载后，这些修改可能不会持久存在。

2. **过度依赖全局变量或常量:** 如果你的代码过度依赖全局变量或常量，而这些变量或常量本应在 V8 的只读堆中，那么在某些特殊情况下（例如，使用了不同的 V8 版本或快照），可能会遇到意想不到的行为。

**总结:**

`v8/src/snapshot/read-only-serializer.cc` 是 V8 引擎启动优化的关键组件，它负责将引擎中不变的部分状态持久化，以便快速恢复，从而加速 JavaScript 代码的执行。它处理了对象的遍历、预处理、数据复制和重定位信息的记录，确保了只读堆可以在反序列化后被正确地重建。

### 提示词
```
这是目录为v8/src/snapshot/read-only-serializer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/snapshot/read-only-serializer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/snapshot/read-only-serializer.h"

#include "src/heap/heap-inl.h"
#include "src/heap/read-only-heap.h"
#include "src/heap/visit-object.h"
#include "src/objects/objects-inl.h"
#include "src/objects/slots.h"
#include "src/snapshot/read-only-serializer-deserializer.h"

namespace v8 {
namespace internal {

namespace {

// Preprocess an object to prepare it for serialization.
class ObjectPreProcessor final {
 public:
  explicit ObjectPreProcessor(Isolate* isolate)
      : isolate_(isolate), extref_encoder_(isolate) {}

#define PRE_PROCESS_TYPE_LIST(V) \
  V(AccessorInfo)                \
  V(FunctionTemplateInfo)        \
  V(Code)

  void PreProcessIfNeeded(Tagged<HeapObject> o) {
    const InstanceType itype = o->map(isolate_)->instance_type();
#define V(TYPE)                               \
  if (InstanceTypeChecker::Is##TYPE(itype)) { \
    return PreProcess##TYPE(Cast<TYPE>(o));   \
  }
    PRE_PROCESS_TYPE_LIST(V)
#undef V
    // If we reach here, no preprocessing is needed for this object.
  }
#undef PRE_PROCESS_TYPE_LIST

 private:
  void EncodeExternalPointerSlot(ExternalPointerSlot slot) {
    Address value = slot.load(isolate_);
    EncodeExternalPointerSlot(slot, value);
  }

  void EncodeExternalPointerSlot(ExternalPointerSlot slot, Address value) {
    // Note it's possible that `value != slot.load(...)`, e.g. for
    // AccessorInfo::remove_getter_indirection.
    ExternalReferenceEncoder::Value encoder_value =
        extref_encoder_.Encode(value);
    DCHECK_LT(encoder_value.index(),
              1UL << ro::EncodedExternalReference::kIndexBits);
    ro::EncodedExternalReference encoded{encoder_value.is_from_api(),
                                         encoder_value.index()};
    // Constructing no_gc here is not the intended use pattern (instead we
    // should pass it along the entire callchain); but there's little point of
    // doing that here - all of the code in this file relies on GC being
    // disabled, and that's guarded at entry points.
    DisallowGarbageCollection no_gc;
    slot.ReplaceContentWithIndexForSerialization(no_gc, encoded.ToUint32());
  }
  void PreProcessAccessorInfo(Tagged<AccessorInfo> o) {
    EncodeExternalPointerSlot(
        o->RawExternalPointerField(AccessorInfo::kMaybeRedirectedGetterOffset,
                                   kAccessorInfoGetterTag),
        o->getter(isolate_));  // Pass the non-redirected value.
    EncodeExternalPointerSlot(o->RawExternalPointerField(
        AccessorInfo::kSetterOffset, kAccessorInfoSetterTag));
  }
  void PreProcessFunctionTemplateInfo(Tagged<FunctionTemplateInfo> o) {
    EncodeExternalPointerSlot(
        o->RawExternalPointerField(
            FunctionTemplateInfo::kMaybeRedirectedCallbackOffset,
            kFunctionTemplateInfoCallbackTag),
        o->callback(isolate_));  // Pass the non-redirected value.
  }
  void PreProcessCode(Tagged<Code> o) {
    o->ClearInstructionStartForSerialization(isolate_);
    DCHECK(!o->has_source_position_table_or_bytecode_offset_table());
    DCHECK(!o->has_deoptimization_data_or_interpreter_data());
  }

  Isolate* const isolate_;
  ExternalReferenceEncoder extref_encoder_;
};

struct ReadOnlySegmentForSerialization {
  ReadOnlySegmentForSerialization(Isolate* isolate,
                                  const ReadOnlyPageMetadata* page,
                                  Address segment_start, size_t segment_size,
                                  ObjectPreProcessor* pre_processor)
      : page(page),
        segment_start(segment_start),
        segment_size(segment_size),
        segment_offset(segment_start - page->area_start()),
        contents(new uint8_t[segment_size]),
        tagged_slots(segment_size / kTaggedSize) {
    // .. because tagged_slots records a bit for each slot:
    DCHECK(IsAligned(segment_size, kTaggedSize));
    // Ensure incoming pointers to this page are representable.
    CHECK_LT(isolate->read_only_heap()->read_only_space()->IndexOf(page),
             1UL << ro::EncodedTagged::kPageIndexBits);

    MemCopy(contents.get(), reinterpret_cast<void*>(segment_start),
            segment_size);
    PreProcessSegment(pre_processor);
    if (!V8_STATIC_ROOTS_BOOL) EncodeTaggedSlots(isolate);
  }

  void PreProcessSegment(ObjectPreProcessor* pre_processor) {
    // Iterate the RO page and the contents copy in lockstep, preprocessing
    // objects as we go along.
    //
    // See also ObjectSerializer::OutputRawData.
    DCHECK_GE(segment_start, page->area_start());
    const Address segment_end = segment_start + segment_size;
    ReadOnlyPageObjectIterator it(page, segment_start);
    for (Tagged<HeapObject> o = it.Next(); !o.is_null(); o = it.Next()) {
      if (o.address() >= segment_end) break;
      size_t o_offset = o.ptr() - segment_start;
      Address o_dst = reinterpret_cast<Address>(contents.get()) + o_offset;
      pre_processor->PreProcessIfNeeded(
          Cast<HeapObject>(Tagged<Object>(o_dst)));
    }
  }

  void EncodeTaggedSlots(Isolate* isolate);

  const ReadOnlyPageMetadata* const page;
  const Address segment_start;
  const size_t segment_size;
  const size_t segment_offset;
  // The (mutated) off-heap copy of the on-heap segment.
  std::unique_ptr<uint8_t[]> contents;
  // The relocation table.
  ro::BitSet tagged_slots;

  friend class EncodeRelocationsVisitor;
};

ro::EncodedTagged Encode(Isolate* isolate, Tagged<HeapObject> o) {
  Address o_address = o.address();
  MemoryChunkMetadata* chunk = MemoryChunkMetadata::FromAddress(o_address);

  ReadOnlySpace* ro_space = isolate->read_only_heap()->read_only_space();
  int index = static_cast<int>(ro_space->IndexOf(chunk));
  uint32_t offset = static_cast<int>(chunk->Offset(o_address));
  DCHECK(IsAligned(offset, kTaggedSize));

  return ro::EncodedTagged(index, offset / kTaggedSize);
}

// If relocations are needed, this class
// - encodes all tagged slots s.t. valid pointers can be reconstructed during
//   deserialization, and
// - records the location of all tagged slots in a table.
class EncodeRelocationsVisitor final : public ObjectVisitor {
 public:
  EncodeRelocationsVisitor(Isolate* isolate,
                           ReadOnlySegmentForSerialization* segment)
      : isolate_(isolate), segment_(segment) {
    DCHECK(!V8_STATIC_ROOTS_BOOL);
  }

  void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                     ObjectSlot end) override {
    VisitPointers(host, MaybeObjectSlot(start), MaybeObjectSlot(end));
  }

  void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                     MaybeObjectSlot end) override {
    for (MaybeObjectSlot slot = start; slot < end; slot++) {
      ProcessSlot(slot);
    }
  }

  void VisitMapPointer(Tagged<HeapObject> host) override {
    ProcessSlot(host->RawMaybeWeakField(HeapObject::kMapOffset));
  }

  // Sanity-checks:
  void VisitInstructionStreamPointer(Tagged<Code> host,
                                     InstructionStreamSlot slot) override {
    // RO space contains only builtin Code objects.
    DCHECK(!host->has_instruction_stream());
  }
  void VisitCodeTarget(Tagged<InstructionStream>, RelocInfo*) override {
    UNREACHABLE();
  }
  void VisitEmbeddedPointer(Tagged<InstructionStream>, RelocInfo*) override {
    UNREACHABLE();
  }
  void VisitExternalReference(Tagged<InstructionStream>, RelocInfo*) override {
    UNREACHABLE();
  }
  void VisitInternalReference(Tagged<InstructionStream>, RelocInfo*) override {
    UNREACHABLE();
  }
  void VisitOffHeapTarget(Tagged<InstructionStream>, RelocInfo*) override {
    UNREACHABLE();
  }
  void VisitExternalPointer(Tagged<HeapObject>,
                            ExternalPointerSlot slot) override {
    // This slot was encoded in a previous pass, see EncodeExternalPointerSlot.
#ifdef DEBUG
    ExternalPointerSlot slot_in_segment{
        reinterpret_cast<Address>(segment_->contents.get() +
                                  SegmentOffsetOf(slot)),
        slot.tag()};
    // Constructing no_gc here is not the intended use pattern (instead we
    // should pass it along the entire callchain); but there's little point of
    // doing that here - all of the code in this file relies on GC being
    // disabled, and that's guarded at entry points.
    DisallowGarbageCollection no_gc;
    auto encoded = ro::EncodedExternalReference::FromUint32(
        slot_in_segment.GetContentAsIndexAfterDeserialization(no_gc));
    if (encoded.is_api_reference) {
      // Can't validate these since we don't know how many entries
      // api_external_references contains.
    } else {
      CHECK_LT(encoded.index, ExternalReferenceTable::kSize);
    }
#endif  // DEBUG
  }

 private:
  void ProcessSlot(MaybeObjectSlot slot) {
    Tagged<MaybeObject> o = *slot;
    if (!o.IsStrongOrWeak()) return;  // Smis don't need relocation.
    DCHECK(o.IsStrong());

    int slot_offset = SegmentOffsetOf(slot);
    DCHECK(IsAligned(slot_offset, kTaggedSize));

    // Encode:
    ro::EncodedTagged encoded = Encode(isolate_, o.GetHeapObject());
    memcpy(segment_->contents.get() + slot_offset, &encoded,
           ro::EncodedTagged::kSize);

    // Record:
    segment_->tagged_slots.set(AsSlot(slot_offset));
  }

  template <class SlotT>
  int SegmentOffsetOf(SlotT slot) const {
    Address addr = slot.address();
    DCHECK_GE(addr, segment_->segment_start);
    DCHECK_LT(addr, segment_->segment_start + segment_->segment_size);
    return static_cast<int>(addr - segment_->segment_start);
  }

  static constexpr int AsSlot(int byte_offset) {
    return byte_offset / kTaggedSize;
  }

  Isolate* const isolate_;
  ReadOnlySegmentForSerialization* const segment_;
};

void ReadOnlySegmentForSerialization::EncodeTaggedSlots(Isolate* isolate) {
  DCHECK(!V8_STATIC_ROOTS_BOOL);
  EncodeRelocationsVisitor v(isolate, this);
  PtrComprCageBase cage_base(isolate);

  DCHECK_GE(segment_start, page->area_start());
  const Address segment_end = segment_start + segment_size;
  ReadOnlyPageObjectIterator it(page, segment_start,
                                SkipFreeSpaceOrFiller::kNo);
  for (Tagged<HeapObject> o = it.Next(); !o.is_null(); o = it.Next()) {
    if (o.address() >= segment_end) break;
    VisitObject(isolate, o, &v);
  }
}

class ReadOnlyHeapImageSerializer {
 public:
  struct MemoryRegion {
    Address start;
    size_t size;
  };

  static void Serialize(Isolate* isolate, SnapshotByteSink* sink,
                        const std::vector<MemoryRegion>& unmapped_regions) {
    ReadOnlyHeapImageSerializer{isolate, sink}.SerializeImpl(unmapped_regions);
  }

 private:
  using Bytecode = ro::Bytecode;

  ReadOnlyHeapImageSerializer(Isolate* isolate, SnapshotByteSink* sink)
      : isolate_(isolate), sink_(sink), pre_processor_(isolate) {}

  void SerializeImpl(const std::vector<MemoryRegion>& unmapped_regions) {
    DCHECK_EQ(sink_->Position(), 0);

    ReadOnlySpace* ro_space = isolate_->read_only_heap()->read_only_space();

    // Allocate all pages first s.t. the deserializer can easily handle forward
    // references (e.g.: an object on page i points at an object on page i+1).
    for (const ReadOnlyPageMetadata* page : ro_space->pages()) {
      EmitAllocatePage(page, unmapped_regions);
    }

    // Now write the page contents.
    for (const ReadOnlyPageMetadata* page : ro_space->pages()) {
      SerializePage(page, unmapped_regions);
    }

    EmitReadOnlyRootsTable();
    sink_->Put(Bytecode::kFinalizeReadOnlySpace, "space end");
  }

  uint32_t IndexOf(const ReadOnlyPageMetadata* page) {
    ReadOnlySpace* ro_space = isolate_->read_only_heap()->read_only_space();
    return static_cast<uint32_t>(ro_space->IndexOf(page));
  }

  void EmitAllocatePage(const ReadOnlyPageMetadata* page,
                        const std::vector<MemoryRegion>& unmapped_regions) {
    if (V8_STATIC_ROOTS_BOOL) {
      sink_->Put(Bytecode::kAllocatePageAt, "fixed page begin");
    } else {
      sink_->Put(Bytecode::kAllocatePage, "page begin");
    }
    sink_->PutUint30(IndexOf(page), "page index");
    sink_->PutUint30(
        static_cast<uint32_t>(page->HighWaterMark() - page->area_start()),
        "area size in bytes");
    if (V8_STATIC_ROOTS_BOOL) {
      auto page_addr = page->ChunkAddress();
      sink_->PutUint32(V8HeapCompressionScheme::CompressAny(page_addr),
                       "page start offset");
    }
  }

  void SerializePage(const ReadOnlyPageMetadata* page,
                     const std::vector<MemoryRegion>& unmapped_regions) {
    Address pos = page->area_start();

    // If this page contains unmapped regions split it into multiple segments.
    for (auto r = unmapped_regions.begin(); r != unmapped_regions.end(); ++r) {
      // Regions must be sorted and non-overlapping.
      if (r + 1 != unmapped_regions.end()) {
        CHECK(r->start < (r + 1)->start);
        CHECK(r->start + r->size < (r + 1)->start);
      }
      if (base::IsInRange(r->start, pos, page->HighWaterMark())) {
        size_t segment_size = r->start - pos;
        ReadOnlySegmentForSerialization segment(isolate_, page, pos,
                                                segment_size, &pre_processor_);
        EmitSegment(&segment);
        pos += segment_size + r->size;
      }
    }

    // Pages are shrunk, but memory at the end of the area is still
    // uninitialized and we do not want to include it in the snapshot.
    size_t segment_size = page->HighWaterMark() - pos;
    ReadOnlySegmentForSerialization segment(isolate_, page, pos, segment_size,
                                            &pre_processor_);
    EmitSegment(&segment);
  }

  void EmitSegment(const ReadOnlySegmentForSerialization* segment) {
    sink_->Put(Bytecode::kSegment, "segment begin");
    sink_->PutUint30(IndexOf(segment->page), "page index");
    sink_->PutUint30(static_cast<uint32_t>(segment->segment_offset),
                     "segment start offset");
    sink_->PutUint30(static_cast<uint32_t>(segment->segment_size),
                     "segment byte size");
    sink_->PutRaw(segment->contents.get(),
                  static_cast<int>(segment->segment_size), "page");
    if (!V8_STATIC_ROOTS_BOOL) {
      sink_->Put(Bytecode::kRelocateSegment, "relocate segment");
      sink_->PutRaw(segment->tagged_slots.data(),
                    static_cast<int>(segment->tagged_slots.size_in_bytes()),
                    "tagged_slots");
    }
  }

  void EmitReadOnlyRootsTable() {
    sink_->Put(Bytecode::kReadOnlyRootsTable, "read only roots table");
    if (!V8_STATIC_ROOTS_BOOL) {
      ReadOnlyRoots roots(isolate_);
      for (size_t i = 0; i < ReadOnlyRoots::kEntriesCount; i++) {
        RootIndex rudi = static_cast<RootIndex>(i);
        Tagged<HeapObject> rudolf = Cast<HeapObject>(roots.object_at(rudi));
        ro::EncodedTagged encoded = Encode(isolate_, rudolf);
        sink_->PutUint32(encoded.ToUint32(), "read only roots entry");
      }
    }
  }

  Isolate* const isolate_;
  SnapshotByteSink* const sink_;
  ObjectPreProcessor pre_processor_;
};

std::vector<ReadOnlyHeapImageSerializer::MemoryRegion> GetUnmappedRegions(
    Isolate* isolate) {
#ifdef V8_STATIC_ROOTS
  // WasmNull's payload is aligned to the OS page and consists of
  // WasmNull::kPayloadSize bytes of unmapped memory. To avoid inflating the
  // snapshot size and accessing uninitialized and/or unmapped memory, the
  // serializer skips the padding bytes and the payload.
  ReadOnlyRoots ro_roots(isolate);
  Tagged<WasmNull> wasm_null = ro_roots.wasm_null();
  Tagged<HeapObject> wasm_null_padding = ro_roots.wasm_null_padding();
  CHECK(IsFreeSpace(wasm_null_padding));
  Address wasm_null_padding_start =
      wasm_null_padding.address() + FreeSpace::kHeaderSize;
  std::vector<ReadOnlyHeapImageSerializer::MemoryRegion> unmapped;
  if (wasm_null.address() > wasm_null_padding_start) {
    unmapped.push_back({wasm_null_padding_start,
                        wasm_null.address() - wasm_null_padding_start});
  }
  unmapped.push_back({wasm_null->payload(), WasmNull::kPayloadSize});
  return unmapped;
#else
  return {};
#endif  // V8_STATIC_ROOTS
}

}  // namespace

ReadOnlySerializer::ReadOnlySerializer(Isolate* isolate,
                                       Snapshot::SerializerFlags flags)
    : RootsSerializer(isolate, flags, RootIndex::kFirstReadOnlyRoot) {}

ReadOnlySerializer::~ReadOnlySerializer() {
  OutputStatistics("ReadOnlySerializer");
}

void ReadOnlySerializer::Serialize() {
  DisallowGarbageCollection no_gc;
  ReadOnlyHeapImageSerializer::Serialize(isolate(), &sink_,
                                         GetUnmappedRegions(isolate()));

  ReadOnlyHeapObjectIterator it(isolate()->read_only_heap());
  for (Tagged<HeapObject> o = it.Next(); !o.is_null(); o = it.Next()) {
    CheckRehashability(o);
    if (v8_flags.serialization_statistics) {
      CountAllocation(o->map(), o->Size(), SnapshotSpace::kReadOnlyHeap);
    }
  }
}

}  // namespace internal
}  // namespace v8
```