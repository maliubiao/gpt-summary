Response:
The user wants to understand the functionality of the `v8/src/heap/object-stats.cc` file. The request asks for:

1. **Functionality Summary:** What does this code do?
2. **Torque Source Check:**  Does it look like a Torque file (`.tq` extension)?
3. **JavaScript Relationship:** If related to JavaScript, provide examples.
4. **Code Logic and I/O:** If there's reasoning, show input and output.
5. **Common Programming Errors:**  Does it relate to typical mistakes?
6. **Concise Summary (Part 1):** A brief overview of the file's purpose based on the provided code.

**Plan:**

1. **Analyze the code:** Read through the code, paying attention to class names, function names, and included headers. Identify the core purpose of the code.
2. **Torque Check:** Inspect the file extension.
3. **JavaScript Connection:** Determine if the code interacts with JavaScript concepts (like objects, arrays, functions, etc.). Provide examples if applicable.
4. **Logic and I/O:** Look for functions that perform calculations or data manipulation. Since this is statistics gathering, think about what data is being collected and how it might be structured.
5. **Programming Errors:** Consider if the code relates to memory management, object handling, or other common issues in JavaScript or C++.
6. **Summarize Part 1:**  Condense the findings into a brief description.```
这是目录为v8/src/heap/object-stats.cc的一个v8源代码， 请列举一下它的功能,
```

根据提供的代码，`v8/src/heap/object-stats.cc` 的主要功能是**收集和统计 V8 堆中各种对象的数量、大小以及其他相关信息**。它用于深入了解堆的结构和内存使用情况，这对于性能分析、内存泄漏检测和垃圾回收优化至关重要。

具体功能包括：

1. **跟踪对象数量和大小:**  统计不同类型的 V8 堆对象的实例数量和总大小。例如，它可以跟踪有多少个 `JSObject`、`JSArray`、`Code` 对象等，以及它们分别占用了多少内存。
2. **记录过度分配的内存:**  对于某些对象（例如 `JSObject`），它会记录分配的总内存与实际使用内存之间的差额，即过度分配的内存。
3. **创建大小直方图:**  为不同类型的对象创建大小分布的直方图，帮助了解对象大小的分布情况。
4. **统计字段类型:** 统计对象内部字段的类型，例如 tagged pointers（指向其他 V8 对象的指针）、embedder fields（宿主环境提供的字段）、Smi（小整数）字段、boxed doubles（包装后的双精度浮点数）字段、字符串数据等。这有助于分析对象内部结构的组成。
5. **提供 JSON 输出:**  可以将收集到的统计信息以 JSON 格式输出，方便外部工具进行分析和可视化。
6. **支持虚拟对象统计:**  它还跟踪一些“虚拟”对象的统计信息，这些对象不是直接的堆对象，而是其他堆对象的组成部分或属性，例如属性数组、元素数组、反馈向量的槽等。这提供了更细粒度的内存使用视图。
7. **支持快照比较:**  通过 `CheckpointObjectStats` 函数，可以保存当前的统计数据，以便与后续的统计数据进行比较，从而分析堆对象的变化趋势。

```
如果v8/src/heap/object-stats.cc以.tq结尾，那它是个v8 torque源代码，
```

提供的文件名为 `v8/src/heap/object-stats.cc`，**以 `.cc` 结尾，这意味着它是一个 C++ 源代码文件，而不是 Torque 源代码文件。** Torque 文件的扩展名是 `.tq`。

```
如果它与javascript的功能有关系，请用javascript举例说明,
```

`v8/src/heap/object-stats.cc` 的功能直接与 JavaScript 的对象和内存管理相关，因为它深入分析了 V8 引擎内部表示 JavaScript 对象的结构和内存占用。

例如，当你在 JavaScript 中创建一个对象或数组时：

```javascript
const obj = { a: 1, b: 'hello' };
const arr = [1, 2, 3];
```

`object-stats.cc` 就会记录下 `obj` 和 `arr` 这两个 `JSObject` 实例的信息，包括它们的大小、内部字段的类型（例如 `a` 是一个 Smi，`b` 指向一个字符串对象）、以及它们包含的元素（对于 `arr` 而言）。

再比如，当你创建一个函数时：

```javascript
function myFunction() {
  // ...
}
```

`object-stats.cc` 会记录下对应的 `JSFunction` 对象、它的 `SharedFunctionInfo` 对象（包含函数元数据）、以及关联的 `BytecodeArray` 对象（包含函数的字节码）等信息。

当你使用 Map 或 Set 等集合时：

```javascript
const map = new Map();
map.set('key', 'value');
```

`object-stats.cc` 会跟踪 `JSMap` 对象以及其内部用于存储键值对的哈希表结构的信息。

```
如果有代码逻辑推理，请给出假设输入与输出，
```

假设在垃圾回收周期后，堆中存在以下对象：

* 一个 `JSObject`，包含两个 tagged pointer 字段和一个 Smi 字段。假设其大小为 48 字节。
* 一个包含 3 个元素的 `JSArray`，每个元素都是 Smi。假设其大小为 64 字节。
* 一个长度为 5 的 `String` 对象。假设其数据占用 10 字节（假设是双字节字符串）。

当 `ObjectStatsCollectorImpl::CollectStatistics` 被调用遍历这些对象时，`ObjectStats` 会累积以下信息（简化输出）：

**输入:**  遍历堆中的上述对象。

**输出 (部分):**

* `object_counts_[JS_OBJECT_TYPE]` 会增加 1。
* `object_sizes_[JS_OBJECT_TYPE]` 会增加 48。
* `tagged_fields_count_` 会增加 2（来自 JSObject 的 tagged pointer 字段）。
* `inobject_smi_fields_count_` 会增加 1（来自 JSObject 的 Smi 字段）。
* `object_counts_[JS_ARRAY_TYPE]` 会增加 1。
* `object_sizes_[JS_ARRAY_TYPE]` 会增加 64。
* `object_counts_[STRING_TYPE]` 会增加 1。
* `object_sizes_[STRING_TYPE]` 会增加  `String` 对象头大小 + 10。
* `string_data_count_` 会增加 `10 / kTaggedSize` (假设 `kTaggedSize` 为 8，则增加 1)。

更具体地，`FieldStatsCollector` 会分析每个对象，并更新 `tagged_fields_count_`、`embedder_fields_count_`、`inobject_smi_fields_count_`、`boxed_double_fields_count_`、`string_data_count_` 和 `raw_fields_count_` 等计数器。例如，对于 `JSObject`，它会根据其 Map 信息判断字段类型并更新相应的计数器。

```
如果涉及用户常见的编程错误，请举例说明
```

虽然 `object-stats.cc` 本身不直接处理用户代码的错误，但它提供的统计信息可以帮助诊断与用户编程相关的内存问题，例如：

1. **内存泄漏:** 如果统计信息显示某种类型的对象数量持续增长，但程序逻辑上不应该出现这种情况，那么可能存在内存泄漏。例如，如果 `JSObject` 的数量不断增加，但程序并没有持续创建新的对象，则可能存在某些对象无法被垃圾回收。
2. **意外的对象创建:**  统计信息可以揭示一些意外的对象创建行为。例如，如果发现创建了大量临时字符串或数组，可能表明代码中存在不必要的对象创建，可以进行优化。
3. **过度使用某种数据结构:**  如果统计信息显示某种特定类型的对象占用了大量的内存，可能意味着程序过度使用了该数据结构，可以考虑使用更高效的替代方案。例如，如果 `OBJECT_PROPERTY_DICTIONARY_TYPE` 的大小异常大，可能意味着对象属性过多，可以考虑使用 `Map` 等更适合大量动态属性的结构。
4. **字符串拼接导致的内存消耗:**  如果 `string_data_count_` 很高，可能表明程序中存在大量的字符串拼接操作，导致创建了许多临时的字符串对象。

例如，一个常见的 JavaScript 编程错误是**在循环中进行大量的字符串拼接**：

```javascript
let result = '';
for (let i = 0; i < 10000; i++) {
  result += 'some text ' + i; // 每次循环都会创建新的字符串
}
```

`object-stats.cc` 可能会显示出大量的 `String` 对象被创建和回收，以及较高的 `string_data_count_`，这可以提示开发者这种写法效率低下，应该使用数组的 `join` 方法来优化：

```javascript
const parts = [];
for (let i = 0; i < 10000; i++) {
  parts.push('some text ' + i);
}
const result = parts.join('');
```

```
这是第1部分，共2部分，请归纳一下它的功能
```

**总结 `v8/src/heap/object-stats.cc` (第 1 部分):**

`v8/src/heap/object-stats.cc` 的主要功能是作为 V8 引擎的一部分，**收集和维护关于堆中对象数量、大小和内部结构的详细统计信息**。它通过遍历堆中的对象，并利用 `FieldStatsCollector` 来分析对象的字段类型，从而生成各种统计数据，包括对象计数、大小总和、过度分配的内存、大小直方图以及字段类型分布。这些统计信息可以以 JSON 格式导出，用于性能分析、内存泄漏检测和垃圾回收优化。该文件处理了多种 V8 堆对象的统计，并支持跟踪一些虚拟对象的统计信息。虽然不直接处理用户代码错误，但其提供的统计数据可以帮助开发者识别潜在的内存使用问题。

### 提示词
```
这是目录为v8/src/heap/object-stats.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/object-stats.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/object-stats.h"

#include <unordered_set>

#include "src/base/bits.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/compilation-cache.h"
#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/heap/combined-heap.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/mark-compact.h"
#include "src/heap/marking-state-inl.h"
#include "src/heap/visit-object.h"
#include "src/logging/counters.h"
#include "src/objects/compilation-cache-table-inl.h"
#include "src/objects/heap-object.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-collection-inl.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/prototype-info.h"
#include "src/objects/slots.h"
#include "src/objects/templates.h"
#include "src/objects/visitors.h"
#include "src/utils/memcopy.h"
#include "src/utils/ostreams.h"

namespace v8 {
namespace internal {

static base::LazyMutex object_stats_mutex = LAZY_MUTEX_INITIALIZER;

class FieldStatsCollector : public ObjectVisitorWithCageBases {
 public:
  FieldStatsCollector(Heap* heap, size_t* tagged_fields_count,
                      size_t* embedder_fields_count,
                      size_t* inobject_smi_fields_count,
                      size_t* boxed_double_fields_count,
                      size_t* string_data_count, size_t* raw_fields_count)
      : ObjectVisitorWithCageBases(heap),
        heap_(heap),
        tagged_fields_count_(tagged_fields_count),
        embedder_fields_count_(embedder_fields_count),
        inobject_smi_fields_count_(inobject_smi_fields_count),
        boxed_double_fields_count_(boxed_double_fields_count),
        string_data_count_(string_data_count),
        raw_fields_count_(raw_fields_count) {}

  void RecordStats(Tagged<HeapObject> host) {
    size_t old_pointer_fields_count = *tagged_fields_count_;
    VisitObject(heap_->isolate(), host, this);
    size_t tagged_fields_count_in_object =
        *tagged_fields_count_ - old_pointer_fields_count;

    int object_size_in_words = host->Size(cage_base()) / kTaggedSize;
    DCHECK_LE(tagged_fields_count_in_object, object_size_in_words);
    size_t raw_fields_count_in_object =
        object_size_in_words - tagged_fields_count_in_object;

    if (IsJSObject(host, cage_base())) {
      JSObjectFieldStats field_stats = GetInobjectFieldStats(host->map());
      // Embedder fields are already included into pointer words.
      DCHECK_LE(field_stats.embedded_fields_count_,
                tagged_fields_count_in_object);
      tagged_fields_count_in_object -= field_stats.embedded_fields_count_;
      *tagged_fields_count_ -= field_stats.embedded_fields_count_;
      *embedder_fields_count_ += field_stats.embedded_fields_count_;

      // Smi fields are also included into pointer words.
      tagged_fields_count_in_object -= field_stats.smi_fields_count_;
      *tagged_fields_count_ -= field_stats.smi_fields_count_;
      *inobject_smi_fields_count_ += field_stats.smi_fields_count_;
    } else if (IsHeapNumber(host, cage_base())) {
      DCHECK_LE(kDoubleSize / kTaggedSize, raw_fields_count_in_object);
      raw_fields_count_in_object -= kDoubleSize / kTaggedSize;
      *boxed_double_fields_count_ += 1;
    } else if (IsSeqString(host, cage_base())) {
      int string_data =
          Cast<SeqString>(host)->length(kAcquireLoad) *
          (Cast<String>(host)->IsOneByteRepresentation() ? 1 : 2) / kTaggedSize;
      DCHECK_LE(string_data, raw_fields_count_in_object);
      raw_fields_count_in_object -= string_data;
      *string_data_count_ += string_data;
    }
    *raw_fields_count_ += raw_fields_count_in_object;
  }

  void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                     ObjectSlot end) override {
    *tagged_fields_count_ += (end - start);
  }
  void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                     MaybeObjectSlot end) override {
    *tagged_fields_count_ += (end - start);
  }

  V8_INLINE void VisitInstructionStreamPointer(
      Tagged<Code> host, InstructionStreamSlot slot) override {
    *tagged_fields_count_ += 1;
  }

  void VisitCodeTarget(Tagged<InstructionStream> host,
                       RelocInfo* rinfo) override {
    // InstructionStream target is most likely encoded as a relative 32-bit
    // offset and not as a full tagged value, so there's nothing to count.
  }

  void VisitEmbeddedPointer(Tagged<InstructionStream> host,
                            RelocInfo* rinfo) override {
    *tagged_fields_count_ += 1;
  }

  void VisitMapPointer(Tagged<HeapObject> host) override {
    // Just do nothing, but avoid the inherited UNREACHABLE implementation.
  }

 private:
  struct JSObjectFieldStats {
    JSObjectFieldStats() : embedded_fields_count_(0), smi_fields_count_(0) {}

    unsigned embedded_fields_count_ : kDescriptorIndexBitCount;
    unsigned smi_fields_count_ : kDescriptorIndexBitCount;
  };
  std::unordered_map<Tagged<Map>, JSObjectFieldStats, Object::Hasher>
      field_stats_cache_;

  JSObjectFieldStats GetInobjectFieldStats(Tagged<Map> map);

  Heap* const heap_;
  size_t* const tagged_fields_count_;
  size_t* const embedder_fields_count_;
  size_t* const inobject_smi_fields_count_;
  size_t* const boxed_double_fields_count_;
  size_t* const string_data_count_;
  size_t* const raw_fields_count_;
};

FieldStatsCollector::JSObjectFieldStats
FieldStatsCollector::GetInobjectFieldStats(Tagged<Map> map) {
  auto iter = field_stats_cache_.find(map);
  if (iter != field_stats_cache_.end()) {
    return iter->second;
  }
  // Iterate descriptor array and calculate stats.
  JSObjectFieldStats stats;
  stats.embedded_fields_count_ = JSObject::GetEmbedderFieldCount(map);
  if (!map->is_dictionary_map()) {
    Tagged<DescriptorArray> descriptors = map->instance_descriptors();
    for (InternalIndex descriptor : map->IterateOwnDescriptors()) {
      PropertyDetails details = descriptors->GetDetails(descriptor);
      if (details.location() == PropertyLocation::kField) {
        FieldIndex index = FieldIndex::ForDetails(map, details);
        // Stop on first out-of-object field.
        if (!index.is_inobject()) break;
        if (details.representation().IsSmi()) {
          ++stats.smi_fields_count_;
        }
      }
    }
  }
  field_stats_cache_.insert(std::make_pair(map, stats));
  return stats;
}

void ObjectStats::ClearObjectStats(bool clear_last_time_stats) {
  memset(object_counts_, 0, sizeof(object_counts_));
  memset(object_sizes_, 0, sizeof(object_sizes_));
  memset(over_allocated_, 0, sizeof(over_allocated_));
  memset(size_histogram_, 0, sizeof(size_histogram_));
  memset(over_allocated_histogram_, 0, sizeof(over_allocated_histogram_));
  if (clear_last_time_stats) {
    memset(object_counts_last_time_, 0, sizeof(object_counts_last_time_));
    memset(object_sizes_last_time_, 0, sizeof(object_sizes_last_time_));
  }
  tagged_fields_count_ = 0;
  embedder_fields_count_ = 0;
  inobject_smi_fields_count_ = 0;
  boxed_double_fields_count_ = 0;
  string_data_count_ = 0;
  raw_fields_count_ = 0;
}

// Tell the compiler to never inline this: occasionally, the optimizer will
// decide to inline this and unroll the loop, making the compiled code more than
// 100KB larger.
V8_NOINLINE static void PrintJSONArray(size_t* array, const int len) {
  PrintF("[ ");
  for (int i = 0; i < len; i++) {
    PrintF("%zu", array[i]);
    if (i != (len - 1)) PrintF(", ");
  }
  PrintF(" ]");
}

V8_NOINLINE static void DumpJSONArray(std::stringstream& stream, size_t* array,
                                      const int len) {
  stream << PrintCollection(base::Vector<size_t>(array, len));
}

void ObjectStats::PrintKeyAndId(const char* key, int gc_count) {
  PrintF("\"isolate\": \"%p\", \"id\": %d, \"key\": \"%s\", ",
         reinterpret_cast<void*>(isolate()), gc_count, key);
}

void ObjectStats::PrintInstanceTypeJSON(const char* key, int gc_count,
                                        const char* name, int index) {
  PrintF("{ ");
  PrintKeyAndId(key, gc_count);
  PrintF("\"type\": \"instance_type_data\", ");
  PrintF("\"instance_type\": %d, ", index);
  PrintF("\"instance_type_name\": \"%s\", ", name);
  PrintF("\"overall\": %zu, ", object_sizes_[index]);
  PrintF("\"count\": %zu, ", object_counts_[index]);
  PrintF("\"over_allocated\": %zu, ", over_allocated_[index]);
  PrintF("\"histogram\": ");
  PrintJSONArray(size_histogram_[index], kNumberOfBuckets);
  PrintF(",");
  PrintF("\"over_allocated_histogram\": ");
  PrintJSONArray(over_allocated_histogram_[index], kNumberOfBuckets);
  PrintF(" }\n");
}

void ObjectStats::PrintJSON(const char* key) {
  double time = isolate()->time_millis_since_init();
  int gc_count = heap()->gc_count();

  // gc_descriptor
  PrintF("{ ");
  PrintKeyAndId(key, gc_count);
  PrintF("\"type\": \"gc_descriptor\", \"time\": %f }\n", time);
  // field_data
  PrintF("{ ");
  PrintKeyAndId(key, gc_count);
  PrintF("\"type\": \"field_data\"");
  PrintF(", \"tagged_fields\": %zu", tagged_fields_count_ * kTaggedSize);
  PrintF(", \"embedder_fields\": %zu",
         embedder_fields_count_ * kEmbedderDataSlotSize);
  PrintF(", \"inobject_smi_fields\": %zu",
         inobject_smi_fields_count_ * kTaggedSize);
  PrintF(", \"boxed_double_fields\": %zu",
         boxed_double_fields_count_ * kDoubleSize);
  PrintF(", \"string_data\": %zu", string_data_count_ * kTaggedSize);
  PrintF(", \"other_raw_fields\": %zu", raw_fields_count_ * kSystemPointerSize);
  PrintF(" }\n");
  // bucket_sizes
  PrintF("{ ");
  PrintKeyAndId(key, gc_count);
  PrintF("\"type\": \"bucket_sizes\", \"sizes\": [ ");
  for (int i = 0; i < kNumberOfBuckets; i++) {
    PrintF("%d", 1 << (kFirstBucketShift + i));
    if (i != (kNumberOfBuckets - 1)) PrintF(", ");
  }
  PrintF(" ] }\n");

#define INSTANCE_TYPE_WRAPPER(name) \
  PrintInstanceTypeJSON(key, gc_count, #name, name);

#define VIRTUAL_INSTANCE_TYPE_WRAPPER(name) \
  PrintInstanceTypeJSON(key, gc_count, #name, FIRST_VIRTUAL_TYPE + name);

  INSTANCE_TYPE_LIST(INSTANCE_TYPE_WRAPPER)
  VIRTUAL_INSTANCE_TYPE_LIST(VIRTUAL_INSTANCE_TYPE_WRAPPER)

#undef INSTANCE_TYPE_WRAPPER
#undef VIRTUAL_INSTANCE_TYPE_WRAPPER
}

void ObjectStats::DumpInstanceTypeData(std::stringstream& stream,
                                       const char* name, int index) {
  stream << "\"" << name << "\":{";
  stream << "\"type\":" << static_cast<int>(index) << ",";
  stream << "\"overall\":" << object_sizes_[index] << ",";
  stream << "\"count\":" << object_counts_[index] << ",";
  stream << "\"over_allocated\":" << over_allocated_[index] << ",";
  stream << "\"histogram\":";
  DumpJSONArray(stream, size_histogram_[index], kNumberOfBuckets);
  stream << ",\"over_allocated_histogram\":";
  DumpJSONArray(stream, over_allocated_histogram_[index], kNumberOfBuckets);
  stream << "},";
}

void ObjectStats::Dump(std::stringstream& stream) {
  double time = isolate()->time_millis_since_init();
  int gc_count = heap()->gc_count();

  stream << "{";
  stream << "\"isolate\":\"" << reinterpret_cast<void*>(isolate()) << "\",";
  stream << "\"id\":" << gc_count << ",";
  stream << "\"time\":" << time << ",";

  // field_data
  stream << "\"field_data\":{";
  stream << "\"tagged_fields\":" << (tagged_fields_count_ * kTaggedSize);
  stream << ",\"embedder_fields\":"
         << (embedder_fields_count_ * kEmbedderDataSlotSize);
  stream << ",\"inobject_smi_fields\": "
         << (inobject_smi_fields_count_ * kTaggedSize);
  stream << ",\"boxed_double_fields\": "
         << (boxed_double_fields_count_ * kDoubleSize);
  stream << ",\"string_data\": " << (string_data_count_ * kTaggedSize);
  stream << ",\"other_raw_fields\":"
         << (raw_fields_count_ * kSystemPointerSize);
  stream << "}, ";

  stream << "\"bucket_sizes\":[";
  for (int i = 0; i < kNumberOfBuckets; i++) {
    stream << (1 << (kFirstBucketShift + i));
    if (i != (kNumberOfBuckets - 1)) stream << ",";
  }
  stream << "],";
  stream << "\"type_data\":{";

#define INSTANCE_TYPE_WRAPPER(name) DumpInstanceTypeData(stream, #name, name);

#define VIRTUAL_INSTANCE_TYPE_WRAPPER(name) \
  DumpInstanceTypeData(stream, #name, FIRST_VIRTUAL_TYPE + name);

  INSTANCE_TYPE_LIST(INSTANCE_TYPE_WRAPPER);
  VIRTUAL_INSTANCE_TYPE_LIST(VIRTUAL_INSTANCE_TYPE_WRAPPER)
  stream << "\"END\":{}}}";

#undef INSTANCE_TYPE_WRAPPER
#undef VIRTUAL_INSTANCE_TYPE_WRAPPER
}

void ObjectStats::CheckpointObjectStats() {
  base::MutexGuard lock_guard(object_stats_mutex.Pointer());
  MemCopy(object_counts_last_time_, object_counts_, sizeof(object_counts_));
  MemCopy(object_sizes_last_time_, object_sizes_, sizeof(object_sizes_));
  ClearObjectStats();
}

namespace {

int Log2ForSize(size_t size) {
  DCHECK_GT(size, 0);
  return kSizetSize * 8 - 1 - base::bits::CountLeadingZeros(size);
}

}  // namespace

int ObjectStats::HistogramIndexFromSize(size_t size) {
  if (size == 0) return 0;
  return std::min({std::max(Log2ForSize(size) + 1 - kFirstBucketShift, 0),
                   kLastValueBucketIndex});
}

void ObjectStats::RecordObjectStats(InstanceType type, size_t size,
                                    size_t over_allocated) {
  DCHECK_LE(type, LAST_TYPE);
  object_counts_[type]++;
  object_sizes_[type] += size;
  size_histogram_[type][HistogramIndexFromSize(size)]++;
  over_allocated_[type] += over_allocated;
  over_allocated_histogram_[type][HistogramIndexFromSize(size)]++;
}

void ObjectStats::RecordVirtualObjectStats(VirtualInstanceType type,
                                           size_t size, size_t over_allocated) {
  DCHECK_LE(type, LAST_VIRTUAL_TYPE);
  object_counts_[FIRST_VIRTUAL_TYPE + type]++;
  object_sizes_[FIRST_VIRTUAL_TYPE + type] += size;
  size_histogram_[FIRST_VIRTUAL_TYPE + type][HistogramIndexFromSize(size)]++;
  over_allocated_[FIRST_VIRTUAL_TYPE + type] += over_allocated;
  over_allocated_histogram_[FIRST_VIRTUAL_TYPE + type]
                           [HistogramIndexFromSize(size)]++;
}

Isolate* ObjectStats::isolate() { return heap()->isolate(); }

class ObjectStatsCollectorImpl {
 public:
  enum Phase {
    kPhase1,
    kPhase2,
  };
  static const int kNumberOfPhases = kPhase2 + 1;

  ObjectStatsCollectorImpl(Heap* heap, ObjectStats* stats);

  void CollectGlobalStatistics();

  enum class CollectFieldStats { kNo, kYes };
  void CollectStatistics(Tagged<HeapObject> obj, Phase phase,
                         CollectFieldStats collect_field_stats);

 private:
  enum CowMode {
    kCheckCow,
    kIgnoreCow,
  };

  Isolate* isolate() { return heap_->isolate(); }

  bool RecordVirtualObjectStats(Tagged<HeapObject> parent,
                                Tagged<HeapObject> obj,
                                ObjectStats::VirtualInstanceType type,
                                size_t size, size_t over_allocated,
                                CowMode check_cow_array = kCheckCow);
  void RecordExternalResourceStats(Address resource,
                                   ObjectStats::VirtualInstanceType type,
                                   size_t size);
  // Gets size from |ob| and assumes no over allocating.
  bool RecordSimpleVirtualObjectStats(Tagged<HeapObject> parent,
                                      Tagged<HeapObject> obj,
                                      ObjectStats::VirtualInstanceType type);
  // For HashTable it is possible to compute over allocated memory.
  template <typename Dictionary>
  void RecordHashTableVirtualObjectStats(Tagged<HeapObject> parent,
                                         Tagged<Dictionary> hash_table,
                                         ObjectStats::VirtualInstanceType type);

  bool SameLiveness(Tagged<HeapObject> obj1, Tagged<HeapObject> obj2);
  bool CanRecordFixedArray(Tagged<FixedArrayBase> array);
  bool IsCowArray(Tagged<FixedArrayBase> array);

  // Blocklist for objects that should not be recorded using
  // VirtualObjectStats and RecordSimpleVirtualObjectStats. For recording those
  // objects dispatch to the low level ObjectStats::RecordObjectStats manually.
  bool ShouldRecordObject(Tagged<HeapObject> object, CowMode check_cow_array);

  void RecordObjectStats(
      Tagged<HeapObject> obj, InstanceType type, size_t size,
      size_t over_allocated = ObjectStats::kNoOverAllocation);

  // Specific recursion into constant pool or embedded code objects. Records
  // FixedArrays and Tuple2.
  void RecordVirtualObjectsForConstantPoolOrEmbeddedObjects(
      Tagged<HeapObject> parent, Tagged<HeapObject> object,
      ObjectStats::VirtualInstanceType type);

  // Details.
  void RecordVirtualAllocationSiteDetails(Tagged<AllocationSite> site);
  void RecordVirtualBytecodeArrayDetails(Tagged<BytecodeArray> bytecode);
  void RecordVirtualCodeDetails(Tagged<InstructionStream> code);
  void RecordVirtualContext(Tagged<Context> context);
  void RecordVirtualFeedbackVectorDetails(Tagged<FeedbackVector> vector);
  void RecordVirtualFixedArrayDetails(Tagged<FixedArray> array);
  void RecordVirtualFunctionTemplateInfoDetails(
      Tagged<FunctionTemplateInfo> fti);
  void RecordVirtualJSGlobalObjectDetails(Tagged<JSGlobalObject> object);
  void RecordVirtualJSObjectDetails(Tagged<JSObject> object);
  void RecordVirtualMapDetails(Tagged<Map> map);
  void RecordVirtualScriptDetails(Tagged<Script> script);
  void RecordVirtualExternalStringDetails(Tagged<ExternalString> script);
  void RecordVirtualSharedFunctionInfoDetails(Tagged<SharedFunctionInfo> info);

  void RecordVirtualArrayBoilerplateDescription(
      Tagged<ArrayBoilerplateDescription> description);

  PtrComprCageBase cage_base() const {
    return field_stats_collector_.cage_base();
  }

  Heap* const heap_;
  ObjectStats* const stats_;
  NonAtomicMarkingState* const marking_state_;
  std::unordered_set<Tagged<HeapObject>, Object::Hasher, Object::KeyEqualSafe>
      virtual_objects_;
  std::unordered_set<Address> external_resources_;
  FieldStatsCollector field_stats_collector_;
};

ObjectStatsCollectorImpl::ObjectStatsCollectorImpl(Heap* heap,
                                                   ObjectStats* stats)
    : heap_(heap),
      stats_(stats),
      marking_state_(heap->non_atomic_marking_state()),
      field_stats_collector_(
          heap_, &stats->tagged_fields_count_, &stats->embedder_fields_count_,
          &stats->inobject_smi_fields_count_,
          &stats->boxed_double_fields_count_, &stats->string_data_count_,
          &stats->raw_fields_count_) {}

bool ObjectStatsCollectorImpl::ShouldRecordObject(Tagged<HeapObject> obj,
                                                  CowMode check_cow_array) {
  if (IsFixedArrayExact(obj)) {
    Tagged<FixedArray> fixed_array = Cast<FixedArray>(obj);
    bool cow_check = check_cow_array == kIgnoreCow || !IsCowArray(fixed_array);
    return CanRecordFixedArray(fixed_array) && cow_check;
  }
  if (obj.SafeEquals(ReadOnlyRoots(heap_).empty_property_array())) return false;
  return true;
}

template <typename Dictionary>
void ObjectStatsCollectorImpl::RecordHashTableVirtualObjectStats(
    Tagged<HeapObject> parent, Tagged<Dictionary> hash_table,
    ObjectStats::VirtualInstanceType type) {
  size_t over_allocated =
      (hash_table->Capacity() - (hash_table->NumberOfElements() +
                                 hash_table->NumberOfDeletedElements())) *
      Dictionary::kEntrySize * kTaggedSize;
  RecordVirtualObjectStats(parent, hash_table, type, hash_table->Size(),
                           over_allocated);
}

bool ObjectStatsCollectorImpl::RecordSimpleVirtualObjectStats(
    Tagged<HeapObject> parent, Tagged<HeapObject> obj,
    ObjectStats::VirtualInstanceType type) {
  return RecordVirtualObjectStats(parent, obj, type, obj->Size(cage_base()),
                                  ObjectStats::kNoOverAllocation, kCheckCow);
}

bool ObjectStatsCollectorImpl::RecordVirtualObjectStats(
    Tagged<HeapObject> parent, Tagged<HeapObject> obj,
    ObjectStats::VirtualInstanceType type, size_t size, size_t over_allocated,
    CowMode check_cow_array) {
  CHECK_LT(over_allocated, size);
  if (!SameLiveness(parent, obj) || !ShouldRecordObject(obj, check_cow_array)) {
    return false;
  }

  if (virtual_objects_.find(obj) == virtual_objects_.end()) {
    virtual_objects_.insert(obj);
    stats_->RecordVirtualObjectStats(type, size, over_allocated);
    return true;
  }
  return false;
}

void ObjectStatsCollectorImpl::RecordExternalResourceStats(
    Address resource, ObjectStats::VirtualInstanceType type, size_t size) {
  if (external_resources_.find(resource) == external_resources_.end()) {
    external_resources_.insert(resource);
    stats_->RecordVirtualObjectStats(type, size, 0);
  }
}

void ObjectStatsCollectorImpl::RecordVirtualAllocationSiteDetails(
    Tagged<AllocationSite> site) {
  if (!site->PointsToLiteral()) return;
  Tagged<JSObject> boilerplate = site->boilerplate();
  if (IsJSArray(boilerplate)) {
    RecordSimpleVirtualObjectStats(site, boilerplate,
                                   ObjectStats::JS_ARRAY_BOILERPLATE_TYPE);
    // Array boilerplates cannot have properties.
  } else {
    RecordVirtualObjectStats(
        site, boilerplate, ObjectStats::JS_OBJECT_BOILERPLATE_TYPE,
        boilerplate->Size(), ObjectStats::kNoOverAllocation);
    if (boilerplate->HasFastProperties()) {
      // We'll mis-classify the empty_property_array here. Given that there is a
      // single instance, this is negligible.
      Tagged<PropertyArray> properties = boilerplate->property_array();
      RecordSimpleVirtualObjectStats(
          site, properties, ObjectStats::BOILERPLATE_PROPERTY_ARRAY_TYPE);
    } else {
      Tagged<NameDictionary> properties = boilerplate->property_dictionary();
      RecordSimpleVirtualObjectStats(
          site, properties, ObjectStats::BOILERPLATE_PROPERTY_DICTIONARY_TYPE);
    }
  }
  Tagged<FixedArrayBase> elements = boilerplate->elements();
  RecordSimpleVirtualObjectStats(site, elements,
                                 ObjectStats::BOILERPLATE_ELEMENTS_TYPE);
}

void ObjectStatsCollectorImpl::RecordVirtualFunctionTemplateInfoDetails(
    Tagged<FunctionTemplateInfo> fti) {
  // named_property_handler and indexed_property_handler are recorded as
  // INTERCEPTOR_INFO_TYPE.
  if (!IsUndefined(fti->GetInstanceCallHandler(), isolate())) {
    RecordSimpleVirtualObjectStats(
        fti, Cast<FunctionTemplateInfo>(fti->GetInstanceCallHandler()),
        ObjectStats::FUNCTION_TEMPLATE_INFO_ENTRIES_TYPE);
  }
}

void ObjectStatsCollectorImpl::RecordVirtualJSGlobalObjectDetails(
    Tagged<JSGlobalObject> object) {
  // Properties.
  Tagged<GlobalDictionary> properties = object->global_dictionary(kAcquireLoad);
  RecordHashTableVirtualObjectStats(object, properties,
                                    ObjectStats::GLOBAL_PROPERTIES_TYPE);
  // Elements.
  Tagged<FixedArrayBase> elements = object->elements();
  RecordSimpleVirtualObjectStats(object, elements,
                                 ObjectStats::GLOBAL_ELEMENTS_TYPE);
}

void ObjectStatsCollectorImpl::RecordVirtualJSObjectDetails(
    Tagged<JSObject> object) {
  // JSGlobalObject is recorded separately.
  if (IsJSGlobalObject(object)) return;

  // Uncompiled JSFunction has a separate type.
  if (IsJSFunction(object) &&
      !Cast<JSFunction>(object)->is_compiled(isolate())) {
    RecordSimpleVirtualObjectStats(HeapObject(), object,
                                   ObjectStats::JS_UNCOMPILED_FUNCTION_TYPE);
  }

  // Properties.
  if (object->HasFastProperties()) {
    Tagged<PropertyArray> properties = object->property_array();
    if (properties != ReadOnlyRoots(heap_).empty_property_array()) {
      size_t over_allocated =
          object->map()->UnusedPropertyFields() * kTaggedSize;
      RecordVirtualObjectStats(object, properties,
                               object->map()->is_prototype_map()
                                   ? ObjectStats::PROTOTYPE_PROPERTY_ARRAY_TYPE
                                   : ObjectStats::OBJECT_PROPERTY_ARRAY_TYPE,
                               properties->Size(), over_allocated);
    }
  } else {
    Tagged<NameDictionary> properties = object->property_dictionary();
    RecordHashTableVirtualObjectStats(
        object, properties,
        object->map()->is_prototype_map()
            ? ObjectStats::PROTOTYPE_PROPERTY_DICTIONARY_TYPE
            : ObjectStats::OBJECT_PROPERTY_DICTIONARY_TYPE);
  }

  // Elements.
  Tagged<FixedArrayBase> elements = object->elements();
  if (object->HasDictionaryElements()) {
    RecordHashTableVirtualObjectStats(
        object, Cast<NumberDictionary>(elements),
        IsJSArray(object) ? ObjectStats::ARRAY_DICTIONARY_ELEMENTS_TYPE
                          : ObjectStats::OBJECT_DICTIONARY_ELEMENTS_TYPE);
  } else if (IsJSArray(object)) {
    if (elements != ReadOnlyRoots(heap_).empty_fixed_array()) {
      size_t element_size =
          (elements->Size() - FixedArrayBase::kHeaderSize) / elements->length();
      uint32_t length = Object::NumberValue(Cast<JSArray>(object)->length());
      size_t over_allocated = (elements->length() - length) * element_size;
      RecordVirtualObjectStats(object, elements,
                               ObjectStats::ARRAY_ELEMENTS_TYPE,
                               elements->Size(), over_allocated);
    }
  } else {
    RecordSimpleVirtualObjectStats(object, elements,
                                   ObjectStats::OBJECT_ELEMENTS_TYPE);
  }

  // JSCollections.
  if (IsJSCollection(object)) {
    Tagged<Object> maybe_table = Cast<JSCollection>(object)->table();
    if (!IsUndefined(maybe_table, isolate())) {
      DCHECK(IsFixedArray(maybe_table, isolate()));
      // TODO(bmeurer): Properly compute over-allocation here.
      RecordSimpleVirtualObjectStats(object, Cast<HeapObject>(maybe_table),
                                     ObjectStats::JS_COLLECTION_TABLE_TYPE);
    }
  }
}

static ObjectStats::VirtualInstanceType GetFeedbackSlotType(
    Tagged<MaybeObject> maybe_obj, FeedbackSlotKind kind, Isolate* isolate) {
  if (maybe_obj.IsCleared())
    return ObjectStats::FEEDBACK_VECTOR_SLOT_OTHER_TYPE;
  Tagged<Object> obj = maybe_obj.GetHeapObjectOrSmi();
  switch (kind) {
    case FeedbackSlotKind::kCall:
      if (obj == *isolate->factory()->uninitialized_symbol()) {
        return ObjectStats::FEEDBACK_VECTOR_SLOT_CALL_UNUSED_TYPE;
      }
      return ObjectStats::FEEDBACK_VECTOR_SLOT_CALL_TYPE;

    case FeedbackSlotKind::kLoadProperty:
    case FeedbackSlotKind::kLoadGlobalInsideTypeof:
    case FeedbackSlotKind::kLoadGlobalNotInsideTypeof:
    case FeedbackSlotKind::kLoadKeyed:
    case FeedbackSlotKind::kHasKeyed:
      if (obj == *isolate->factory()->uninitialized_symbol()) {
        return ObjectStats::FEEDBACK_VECTOR_SLOT_LOAD_UNUSED_TYPE;
      }
      return ObjectStats::FEEDBACK_VECTOR_SLOT_LOAD_TYPE;

    case FeedbackSlotKind::kSetNamedSloppy:
    case FeedbackSlotKind::kSetNamedStrict:
    case FeedbackSlotKind::kDefineNamedOwn:
    case FeedbackSlotKind::kStoreGlobalSloppy:
    case FeedbackSlotKind::kStoreGlobalStrict:
    case FeedbackSlotKind::kSetKeyedSloppy:
    case FeedbackSlotKind::kSetKeyedStrict:
      if (obj == *isolate->factory()->uninitialized_symbol()) {
        return ObjectStats::FEEDBACK_VECTOR_SLOT_STORE_UNUSED_TYPE;
      }
      return ObjectStats::FEEDBACK_VECTOR_SLOT_STORE_TYPE;

    case FeedbackSlotKind::kBinaryOp:
    case FeedbackSlotKind::kCompareOp:
      return ObjectStats::FEEDBACK_VECTOR_SLOT_ENUM_TYPE;

    default:
      return ObjectStats::FEEDBACK_VECTOR_SLOT_OTHER_TYPE;
  }
}

void ObjectStatsCollectorImpl::RecordVirtualFeedbackVectorDetails(
    Tagged<FeedbackVector> vector) {
  if (virtual_objects_.find(vector) != virtual_objects_.end()) return;
  // Manually insert the feedback vector into the virtual object list, since
  // we're logging its component parts separately.
  virtual_objects_.insert(vector);

  size_t calculated_size = 0;

  // Log the feedback vector's header (fixed fields).
  size_t header_size = vector->slots_start().address() - vector.address();
  stats_->RecordVirtualObjectStats(ObjectStats::FEEDBACK_VECTOR_HEADER_TYPE,
                                   header_size, ObjectStats::kNoOverAllocation);
  calculated_size += header_size;

  // Iterate over the feedback slots and log each one.
  if (!vector->shared_function_info()->HasFeedbackMetadata()) return;

  FeedbackMetadataIterator it(vector->metadata());
  while (it.HasNext()) {
    FeedbackSlot slot = it.Next();
    // Log the entry (or entries) taken up by this slot.
    size_t slot_size = it.entry_size() * kTaggedSize;
    stats_->RecordVirtualObjectStats(
        GetFeedbackSlotType(vector->Get(slot), it.kind(), heap_->isolate()),
        slot_size, ObjectStats::kNoOverAllocation);
    calculated_size += slot_size;

    // Log the monomorphic/polymorphic helper objects that this slot owns.
    for (int i = 0; i < it.entry_size(); i++) {
      Tagged<MaybeObject> raw_object = vector->Get(slot.WithOffset(i));
      Tagged<HeapObject> object;
      if (raw_object.GetHeapObject(&object)) {
        if (IsCell(object, cage_base()) ||
            IsWeakFixedArray(object, cage_base())) {
          RecordSimpleVirtualObjectStats(
              vector, object, ObjectStats::FEEDBACK_VECTOR_ENTRY_TYPE);
        }
      }
    }
  }

  CHECK_EQ(calculated_size, vector->Size());
}

void ObjectStatsCollectorImpl::RecordVirtualFixedArrayDetails(
    Tagged<FixedArray> array) {
  if (IsCowArray(array)) {
    RecordVirtualObjectStats(HeapObject(), array, ObjectStats::COW_ARRAY_TYPE,
                             array->Size(), ObjectStats::kNoOverAllocation,
                             kIgnoreCow);
  }
}

void ObjectStatsCollectorImpl::CollectStatistics(
    Tagged<HeapObject> obj, Phase phase,
    CollectFieldStats collect_field_stats) {
  DisallowGarbageCollection no_gc;
  Tagged<Map> map = obj->map(cage_base());
  InstanceType instance_type = map->instance_type();
  switch (phase) {
    case kPhase1:
      if (InstanceTypeChecker::IsFeedbackVector(instance_type)) {
        RecordVirtualFeedbackVectorDetails(Cast<FeedbackVector>(obj));
      } else if (InstanceTypeChecker::IsMap(instance_type)) {
        RecordVirtualMapDetails(Cast<Map>(obj));
      } else if (InstanceTypeChecker::IsBytecodeArray(instance_type)) {
        RecordVirtualBytecodeArrayDetails(Cast<BytecodeArray>(obj));
      } else if (InstanceTypeChecker::IsInstructionStream(instance_type)) {
        RecordVirtualCodeDetails(Cast<InstructionStream>(obj));
      } else if (InstanceTypeChecker::IsFunctionTemplateInfo(instance_type)) {
        RecordVirtualFunctionTemplateInfoDetails(
            Cast<FunctionTemplateInfo>(obj));
      } else if (InstanceTypeChecker::IsJSGlobalObject(instance_type)) {
        RecordVirtualJSGlobalObjectDetails(Cast<JSGlobalObject>(obj));
      } else if (InstanceTypeChecker::IsJSObject(instance_type)) {
        // This phase needs to come after RecordVirtualAllocationSiteDetails
        // to properly split among boilerplates.
        RecordVirtualJSObjectDetails(Cast<JSObject>(obj));
      } else if (InstanceTypeChecker::IsSharedFunctionInfo(instance_type)) {
        RecordVirtualSharedFunctionInfoDetails(Cast<SharedFunctionInfo>(obj));
      } else if (InstanceTypeChecker::IsContext(instance_type)) {
        RecordVirtualContext(Cast<Context>(obj));
      } else if (InstanceTypeChecker::IsScript(instance_type)) {
        RecordVirtualScriptDetails(Cast<Script>(obj));
      } else if (InstanceTypeChecker::IsArrayBoilerplateDescription(
                     instance_type)) {
        RecordVirtualArrayBoilerplateDescription(
            Cast<ArrayBoilerplateDescription>(obj));
      } else if (InstanceTypeChecker::IsFixedArrayExact(instance_type)) {
        // Has to go last as it triggers too eagerly.
        RecordVirtualFixedArrayDetails(Cast<FixedArray>(obj));
      }
      break;
    case kPhase2:
      if (InstanceTypeChecker::IsExternalString(instance_type)) {
        // This has to be in Phase2 to avoid conflicting with recording Script
        // sources. We still want to run RecordObjectStats after though.
        RecordVirtualExternalStringDetails(Cast<ExternalString>(obj));
      }
      size_t over_allocated = ObjectStats::kNoOverAllocation;
      if (InstanceTypeChecker::IsJSObject(instance_type)) {
        over_allocated = map->instance_size() - map->UsedInstanceSize();
      }
      RecordObjectStats(obj, instance_type, obj->Size(cage_base()),
                        over_allocated);
      if (collect_field_stats == CollectFieldSt
```