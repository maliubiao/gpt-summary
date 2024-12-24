Response: Let's break down the thought process for analyzing this C++ code and explaining its functionality in relation to JavaScript.

1. **Understand the Goal:** The primary request is to understand the *purpose* of this C++ file (`object-stats.cc`) within the V8 JavaScript engine. A secondary request is to illustrate its connection to JavaScript using examples.

2. **Initial Scan for Keywords:** Quickly read through the code, looking for recurring keywords and patterns. Keywords like `stats`, `count`, `size`, `histogram`, `object`, `field`, `type`, `instance`, `Heap`, and JSON-related terms (`PrintJSON`, `Dump`, etc.) stand out. The file header mentioning "V8 project" and "heap" immediately hints at memory management and object tracking.

3. **Identify Core Data Structures:**  Notice the `ObjectStats` class and its member variables: `object_counts_`, `object_sizes_`, `size_histogram_`, etc. These strongly suggest that the file is about collecting and storing statistics about different types of objects in the V8 heap.

4. **Trace the Data Flow:** Focus on how these statistics are being populated. The `ObjectStatsCollectorImpl` class and its `CollectStatistics` method are key. The `Visit` methods (inheriting from `ObjectVisitorWithCageBases`) indicate a traversal of the heap. The code seems to iterate through objects and, based on their `InstanceType`, increment counters and update size information.

5. **Focus on the `CollectStatistics` Method:** This method appears to be the heart of the data collection. Notice the two phases (`kPhase1`, `kPhase2`). This likely signifies different stages of analysis. The conditional logic based on `instance_type` shows how different object types are handled.

6. **Analyze the `FieldStatsCollector`:** This inner class specifically deals with field-level statistics. It calculates the number of tagged pointers, embedder data, SMI fields, etc., within objects. This detail is important for understanding V8's internal object layout and memory usage.

7. **Connect to JavaScript Concepts:**  Now, the crucial step: relating this C++ code to JavaScript.

    * **Objects and Types:**  JavaScript is dynamically typed, but V8 internally represents JavaScript values as objects with specific types. The `InstanceType` enum in the C++ code directly corresponds to these internal representations (e.g., `JS_OBJECT_TYPE`, `JS_ARRAY_TYPE`, `STRING_TYPE`).

    * **Heap:** JavaScript objects are allocated on the heap. This file is clearly concerned with the V8 heap's structure and contents.

    * **Memory Usage:** The counters for object counts, sizes, and field types directly reflect how much memory different kinds of JavaScript objects are consuming.

    * **Garbage Collection:** The mention of `gc_count` and the `CheckpointObjectStats` function strongly suggest that these statistics are used to understand the impact of garbage collection and memory management strategies.

    * **Optimization:** The analysis of `FeedbackVector` and `Code` objects hints at the statistics being used for performance optimization. V8 uses feedback to optimize code execution.

8. **Develop JavaScript Examples:** Create simple JavaScript code snippets that directly lead to the creation of the object types being tracked in the C++ code. Examples should be clear and demonstrate the link between the JavaScript action and the underlying V8 object. For instance:

    * `let obj = {};` -> `JS_OBJECT_TYPE`
    * `let arr = [];` -> `JS_ARRAY_TYPE`
    * `function foo() {}` -> `JS_FUNCTION_TYPE`
    * `"hello"` -> `STRING_TYPE`

9. **Explain the Connection:** Clearly articulate *how* the C++ code relates to the JavaScript examples. Explain that when the JavaScript code is executed, V8 creates internal representations of these values, and this C++ code is responsible for tracking the characteristics of these internal representations.

10. **Structure the Explanation:** Organize the findings into a coherent explanation. Start with a high-level summary, then delve into specifics, and finally provide the JavaScript examples. Use clear and concise language, avoiding excessive jargon.

11. **Refine and Review:** Review the explanation for accuracy and clarity. Ensure that the JavaScript examples are relevant and easy to understand. Double-check the connection between the C++ concepts and their JavaScript counterparts. For example, make sure to explain *why* tracking `FeedbackVector` is related to optimization (because it stores information used for adaptive optimization).

This iterative process of scanning, identifying, tracing, connecting, and illustrating helps to systematically understand the purpose and significance of the given C++ code within the larger context of the V8 JavaScript engine.
这个 C++ 源代码文件 `v8/src/heap/object-stats.cc` 的主要功能是 **收集和记录 V8 堆中各种对象的统计信息**。这些统计信息用于了解堆的组成、内存使用情况以及对象分布情况。

具体来说，它做了以下几件事情：

**1. 跟踪不同类型的对象数量和大小:**

   - 代码定义了一个 `ObjectStats` 类，其中包含数组 `object_counts_` 和 `object_sizes_`，用于存储每种对象类型（例如 `JSObject`, `String`, `Code` 等）的实例数量和总大小。
   - 它还维护了 `over_allocated_` 数组，用于记录由于分配粒度导致的额外内存占用。
   - `size_histogram_` 和 `over_allocated_histogram_` 用于记录对象大小的分布情况，将对象大小划分到不同的桶中进行统计。

**2. 收集对象字段的统计信息:**

   - `FieldStatsCollector` 类用于遍历堆中的对象并统计不同类型的字段：
     - `tagged_fields_count_`: 指向其他 V8 堆对象的指针字段。
     - `embedder_fields_count_`: 嵌入器数据字段（例如，由 Node.js 或 Chromium 提供的）。
     - `inobject_smi_fields_count_`: 直接存储 Small Integer (Smi) 的字段。
     - `boxed_double_fields_count_`: 存储 Boxed Double（双精度浮点数）的字段。
     - `string_data_count_`: 字符串数据占用的空间。
     - `raw_fields_count_`: 其他原始数据字段。

**3. 提供 JSON 输出功能:**

   - `PrintJSON()` 和 `Dump()` 方法可以将收集到的统计信息以 JSON 格式输出，方便分析和监控。这些 JSON 数据包含了各种对象类型的数量、大小、内存占用以及字段类型的分布情况。

**4. 实现统计信息的快照功能:**

   - `CheckpointObjectStats()` 方法可以将当前的统计信息复制到 `object_counts_last_time_` 和 `object_sizes_last_time_` 中，用于比较不同时间点的堆状态。

**5. 使用 `ObjectStatsCollector` 进行实际收集:**

   - `ObjectStatsCollector` 类负责遍历整个堆，并使用 `ObjectStatsCollectorImpl` 来记录每个对象的统计信息。
   - `ObjectStatsCollectorImpl` 区分了两个阶段 (Phase)，可能用于更细粒度的统计或者处理依赖关系。
   - 它还维护了一个 `virtual_objects_` 集合，用于跟踪已经统计过的“虚拟对象”，避免重复计算。这些虚拟对象通常是逻辑上的分组，而不是直接的堆对象。

**与 JavaScript 的关系：**

这个文件是 V8 引擎内部实现的一部分，直接关系到 JavaScript 对象的内存管理和性能分析。当 JavaScript 代码运行时，V8 会在堆上创建各种对象来表示 JavaScript 的值和结构，例如：

- **JS Objects:** JavaScript 中的普通对象 (e.g., `{ a: 1, b: "hello" }`)
- **JS Arrays:** JavaScript 中的数组 (e.g., `[1, 2, 3]`)
- **Strings:** JavaScript 中的字符串 (e.g., `"world"`)
- **Functions:** JavaScript 中的函数 (e.g., `function foo() {}`)
- **Numbers:** JavaScript 中的数字
- **Maps and Sets:** JavaScript 中的 Map 和 Set 对象
- **Promises:** JavaScript 中的 Promise 对象
- **Closures:** 函数的闭包

`object-stats.cc` 的功能就是跟踪这些内部表示的 JavaScript 对象，并提供关于它们的内存使用情况和结构的信息。这些信息对于以下方面非常有用：

- **性能调优:** 了解哪些类型的对象占用了最多的内存，可以帮助开发者优化 JavaScript 代码，减少内存消耗。
- **内存泄漏检测:** 通过比较不同时间点的对象统计信息，可以帮助识别潜在的内存泄漏。
- **垃圾回收分析:**  统计信息可以帮助理解垃圾回收器的行为，例如哪些对象更容易被回收，哪些对象存活时间更长。
- **V8 引擎开发:**  对于 V8 引擎的开发者来说，这些统计信息是分析堆结构和内存管理策略的重要工具。

**JavaScript 示例:**

以下是一些 JavaScript 代码示例，它们会在 V8 堆上创建不同类型的对象，而 `object-stats.cc` 中的代码会跟踪这些对象的统计信息：

```javascript
// 创建一个普通对象
let obj = { a: 1, b: "hello" };

// 创建一个数组
let arr = [1, 2, 3];

// 创建一个字符串
let str = "world";

// 创建一个函数
function foo() {
  console.log("hello");
}

// 创建一个 Map
let map = new Map();
map.set("key", "value");

// 创建一个 Set
let set = new Set();
set.add(1);

// 创建一个 Promise
let promise = new Promise((resolve, reject) => {
  setTimeout(resolve, 100);
});
```

当 V8 执行这些 JavaScript 代码时，会在堆上分配相应的对象。`object-stats.cc` 中的代码会记录 `JS_OBJECT_TYPE` 的数量增加了一个，记录 `JS_ARRAY_TYPE` 的数量增加了一个，记录 `STRING_TYPE` 的数量增加了一个，等等。同时，也会记录这些对象的具体大小以及内部字段的统计信息。

**总结:**

`v8/src/heap/object-stats.cc` 是 V8 引擎中一个关键的组成部分，它负责收集 JavaScript 运行时堆中各种对象的统计信息，帮助理解内存使用、进行性能分析和优化，并支持 V8 引擎自身的开发和调试。它直接关联着 JavaScript 代码的执行和内存管理。

Prompt: 
```
这是目录为v8/src/heap/object-stats.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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
      if (collect_field_stats == CollectFieldStats::kYes) {
        field_stats_collector_.RecordStats(obj);
      }
      break;
  }
}

void ObjectStatsCollectorImpl::CollectGlobalStatistics() {
  // Iterate boilerplates first to disambiguate them from regular JS objects.
  Tagged<Object> list = heap_->allocation_sites_list();
  while (IsAllocationSite(list, cage_base())) {
    Tagged<AllocationSite> site = Cast<AllocationSite>(list);
    RecordVirtualAllocationSiteDetails(site);
    list = site->weak_next();
  }

  // FixedArray.
  RecordSimpleVirtualObjectStats(HeapObject(), heap_->serialized_objects(),
                                 ObjectStats::SERIALIZED_OBJECTS_TYPE);
  RecordSimpleVirtualObjectStats(HeapObject(), heap_->number_string_cache(),
                                 ObjectStats::NUMBER_STRING_CACHE_TYPE);
  RecordSimpleVirtualObjectStats(
      HeapObject(), heap_->single_character_string_table(),
      ObjectStats::SINGLE_CHARACTER_STRING_TABLE_TYPE);
  RecordSimpleVirtualObjectStats(HeapObject(), heap_->string_split_cache(),
                                 ObjectStats::STRING_SPLIT_CACHE_TYPE);
  RecordSimpleVirtualObjectStats(HeapObject(), heap_->regexp_multiple_cache(),
                                 ObjectStats::REGEXP_MULTIPLE_CACHE_TYPE);

  // WeakArrayList.
  RecordSimpleVirtualObjectStats(HeapObject(),
                                 Cast<WeakArrayList>(heap_->script_list()),
                                 ObjectStats::SCRIPT_LIST_TYPE);
}

void ObjectStatsCollectorImpl::RecordObjectStats(Tagged<HeapObject> obj,
                                                 InstanceType type, size_t size,
                                                 size_t over_allocated) {
  if (virtual_objects_.find(obj) == virtual_objects_.end()) {
    stats_->RecordObjectStats(type, size, over_allocated);
  }
}

bool ObjectStatsCollectorImpl::CanRecordFixedArray(
    Tagged<FixedArrayBase> array) {
  ReadOnlyRoots roots(heap_);
  return array != roots.empty_fixed_array() &&
         array != roots.empty_slow_element_dictionary() &&
         array != roots.empty_property_dictionary();
}

bool ObjectStatsCollectorImpl::IsCowArray(Tagged<FixedArrayBase> array) {
  return array->map() == ReadOnlyRoots(heap_).fixed_cow_array_map();
}

bool ObjectStatsCollectorImpl::SameLiveness(Tagged<HeapObject> obj1,
                                            Tagged<HeapObject> obj2) {
  if (obj1.is_null() || obj2.is_null()) return true;
  const auto obj1_marked =
      HeapLayout::InReadOnlySpace(obj1) || marking_state_->IsMarked(obj1);
  const auto obj2_marked =
      HeapLayout::InReadOnlySpace(obj2) || marking_state_->IsMarked(obj2);
  return obj1_marked == obj2_marked;
}

void ObjectStatsCollectorImpl::RecordVirtualMapDetails(Tagged<Map> map) {
  // TODO(mlippautz): map->dependent_code(): DEPENDENT_CODE_TYPE.

  // For Map we want to distinguish between various different states
  // to get a better picture of what's going on in MapSpace. This
  // method computes the virtual instance type to use for a given map,
  // using MAP_TYPE for regular maps that aren't special in any way.
  if (map->is_prototype_map()) {
    if (map->is_dictionary_map()) {
      RecordSimpleVirtualObjectStats(
          HeapObject(), map, ObjectStats::MAP_PROTOTYPE_DICTIONARY_TYPE);
    } else if (map->is_abandoned_prototype_map()) {
      RecordSimpleVirtualObjectStats(HeapObject(), map,
                                     ObjectStats::MAP_ABANDONED_PROTOTYPE_TYPE);
    } else {
      RecordSimpleVirtualObjectStats(HeapObject(), map,
                                     ObjectStats::MAP_PROTOTYPE_TYPE);
    }
  } else if (map->is_deprecated()) {
    RecordSimpleVirtualObjectStats(HeapObject(), map,
                                   ObjectStats::MAP_DEPRECATED_TYPE);
  } else if (map->is_dictionary_map()) {
    RecordSimpleVirtualObjectStats(HeapObject(), map,
                                   ObjectStats::MAP_DICTIONARY_TYPE);
  } else if (map->is_stable()) {
    RecordSimpleVirtualObjectStats(HeapObject(), map,
                                   ObjectStats::MAP_STABLE_TYPE);
  } else {
    // This will be logged as MAP_TYPE in Phase2.
  }

  Tagged<DescriptorArray> array = map->instance_descriptors(cage_base());
  if (map->owns_descriptors() &&
      array != ReadOnlyRoots(heap_).empty_descriptor_array()) {
    // Generally DescriptorArrays have their own instance type already
    // (DESCRIPTOR_ARRAY_TYPE), but we'd like to be able to tell which
    // of those are for (abandoned) prototypes, and which of those are
    // owned by deprecated maps.
    if (map->is_prototype_map()) {
      RecordSimpleVirtualObjectStats(
          map, array, ObjectStats::PROTOTYPE_DESCRIPTOR_ARRAY_TYPE);
    } else if (map->is_deprecated()) {
      RecordSimpleVirtualObjectStats(
          map, array, ObjectStats::DEPRECATED_DESCRIPTOR_ARRAY_TYPE);
    }

    Tagged<EnumCache> enum_cache = array->enum_cache();
    RecordSimpleVirtualObjectStats(array, enum_cache->keys(),
                                   ObjectStats::ENUM_KEYS_CACHE_TYPE);
    RecordSimpleVirtualObjectStats(array, enum_cache->indices(),
                                   ObjectStats::ENUM_INDICES_CACHE_TYPE);
  }

  if (map->is_prototype_map()) {
    Tagged<PrototypeInfo> prototype_info;
    if (map->TryGetPrototypeInfo(&prototype_info)) {
      Tagged<Object> users = prototype_info->prototype_users();
      if (IsWeakFixedArray(users, cage_base())) {
        RecordSimpleVirtualObjectStats(map, Cast<WeakArrayList>(users),
                                       ObjectStats::PROTOTYPE_USERS_TYPE);
      }
    }
  }
}

void ObjectStatsCollectorImpl::RecordVirtualScriptDetails(
    Tagged<Script> script) {
  RecordSimpleVirtualObjectStats(script, script->infos(),
                                 ObjectStats::SCRIPT_INFOS_TYPE);

  // Log the size of external source code.
  Tagged<Object> raw_source = script->source();
  if (IsExternalString(raw_source, cage_base())) {
    // The contents of external strings aren't on the heap, so we have to record
    // them manually. The on-heap String object is recorded independently in
    // the normal pass.
    Tagged<ExternalString> string = Cast<ExternalString>(raw_source);
    Address resource = string->resource_as_address();
    size_t off_heap_size = string->ExternalPayloadSize();
    RecordExternalResourceStats(
        resource,
        string->IsOneByteRepresentation()
            ? ObjectStats::SCRIPT_SOURCE_EXTERNAL_ONE_BYTE_TYPE
            : ObjectStats::SCRIPT_SOURCE_EXTERNAL_TWO_BYTE_TYPE,
        off_heap_size);
  } else if (IsString(raw_source, cage_base())) {
    Tagged<String> source = Cast<String>(raw_source);
    RecordSimpleVirtualObjectStats(
        script, source,
        source->IsOneByteRepresentation()
            ? ObjectStats::SCRIPT_SOURCE_NON_EXTERNAL_ONE_BYTE_TYPE
            : ObjectStats::SCRIPT_SOURCE_NON_EXTERNAL_TWO_BYTE_TYPE);
  }
}

void ObjectStatsCollectorImpl::RecordVirtualExternalStringDetails(
    Tagged<ExternalString> string) {
  // Track the external string resource size in a separate category.

  Address resource = string->resource_as_address();
  size_t off_heap_size = string->ExternalPayloadSize();
  RecordExternalResourceStats(
      resource,
      string->IsOneByteRepresentation()
          ? ObjectStats::STRING_EXTERNAL_RESOURCE_ONE_BYTE_TYPE
          : ObjectStats::STRING_EXTERNAL_RESOURCE_TWO_BYTE_TYPE,
      off_heap_size);
}

void ObjectStatsCollectorImpl::RecordVirtualSharedFunctionInfoDetails(
    Tagged<SharedFunctionInfo> info) {
  // Uncompiled SharedFunctionInfo gets its own category.
  if (!info->is_compiled()) {
    RecordSimpleVirtualObjectStats(
        HeapObject(), info, ObjectStats::UNCOMPILED_SHARED_FUNCTION_INFO_TYPE);
  }
}

void ObjectStatsCollectorImpl::RecordVirtualArrayBoilerplateDescription(
    Tagged<ArrayBoilerplateDescription> description) {
  RecordVirtualObjectsForConstantPoolOrEmbeddedObjects(
      description, description->constant_elements(),
      ObjectStats::ARRAY_BOILERPLATE_DESCRIPTION_ELEMENTS_TYPE);
}

void ObjectStatsCollectorImpl::
    RecordVirtualObjectsForConstantPoolOrEmbeddedObjects(
        Tagged<HeapObject> parent, Tagged<HeapObject> object,
        ObjectStats::VirtualInstanceType type) {
  if (!RecordSimpleVirtualObjectStats(parent, object, type)) return;
  if (IsFixedArrayExact(object, cage_base())) {
    Tagged<FixedArray> array = Cast<FixedArray>(object);
    for (int i = 0; i < array->length(); i++) {
      Tagged<Object> entry = array->get(i);
      if (!IsHeapObject(entry)) continue;
      RecordVirtualObjectsForConstantPoolOrEmbeddedObjects(
          array, Cast<HeapObject>(entry), type);
    }
  }
}

void ObjectStatsCollectorImpl::RecordVirtualBytecodeArrayDetails(
    Tagged<BytecodeArray> bytecode) {
  RecordSimpleVirtualObjectStats(
      bytecode, bytecode->constant_pool(),
      ObjectStats::BYTECODE_ARRAY_CONSTANT_POOL_TYPE);
  // FixedArrays on constant pool are used for holding descriptor information.
  // They are shared with optimized code.
  Tagged<TrustedFixedArray> constant_pool =
      Cast<TrustedFixedArray>(bytecode->constant_pool());
  for (int i = 0; i < constant_pool->length(); i++) {
    Tagged<Object> entry = constant_pool->get(i);
    if (IsFixedArrayExact(entry)) {
      RecordVirtualObjectsForConstantPoolOrEmbeddedObjects(
          constant_pool, Cast<HeapObject>(entry),
          ObjectStats::EMBEDDED_OBJECT_TYPE);
    }
  }
  RecordSimpleVirtualObjectStats(
      bytecode, bytecode->handler_table(),
      ObjectStats::BYTECODE_ARRAY_HANDLER_TABLE_TYPE);
  if (bytecode->HasSourcePositionTable()) {
    RecordSimpleVirtualObjectStats(bytecode, bytecode->SourcePositionTable(),
                                   ObjectStats::SOURCE_POSITION_TABLE_TYPE);
  }
}

namespace {

ObjectStats::VirtualInstanceType CodeKindToVirtualInstanceType(CodeKind kind) {
  switch (kind) {
#define CODE_KIND_CASE(type) \
  case CodeKind::type:       \
    return ObjectStats::type;
    CODE_KIND_LIST(CODE_KIND_CASE)
#undef CODE_KIND_CASE
  }
  UNREACHABLE();
}

}  // namespace

void ObjectStatsCollectorImpl::RecordVirtualCodeDetails(
    Tagged<InstructionStream> istream) {
  Tagged<Code> code;
  if (!istream->TryGetCode(&code, kAcquireLoad)) return;
  RecordSimpleVirtualObjectStats(HeapObject(), istream,
                                 CodeKindToVirtualInstanceType(code->kind()));
  RecordSimpleVirtualObjectStats(istream, istream->relocation_info(),
                                 ObjectStats::RELOC_INFO_TYPE);
  if (CodeKindIsOptimizedJSFunction(code->kind())) {
    Tagged<Object> source_position_table = code->source_position_table();
    if (IsHeapObject(source_position_table)) {
      RecordSimpleVirtualObjectStats(istream,
                                     Cast<HeapObject>(source_position_table),
                                     ObjectStats::SOURCE_POSITION_TABLE_TYPE);
    }
    RecordSimpleVirtualObjectStats(istream, code->deoptimization_data(),
                                   ObjectStats::DEOPTIMIZATION_DATA_TYPE);
    Tagged<DeoptimizationData> input_data =
        Cast<DeoptimizationData>(code->deoptimization_data());
    if (input_data->length() > 0) {
      RecordSimpleVirtualObjectStats(code->deoptimization_data(),
                                     input_data->LiteralArray(),
                                     ObjectStats::OPTIMIZED_CODE_LITERALS_TYPE);
    }
  }
  int const mode_mask = RelocInfo::EmbeddedObjectModeMask();
  for (RelocIterator it(code, mode_mask); !it.done(); it.next()) {
    DCHECK(RelocInfo::IsEmbeddedObjectMode(it.rinfo()->rmode()));
    Tagged<Object> target = it.rinfo()->target_object(cage_base());
    if (IsFixedArrayExact(target, cage_base())) {
      RecordVirtualObjectsForConstantPoolOrEmbeddedObjects(
          istream, Cast<HeapObject>(target), ObjectStats::EMBEDDED_OBJECT_TYPE);
    }
  }
}

void ObjectStatsCollectorImpl::RecordVirtualContext(Tagged<Context> context) {
  if (IsNativeContext(context)) {
    RecordObjectStats(context, NATIVE_CONTEXT_TYPE, context->Size());
    if (IsWeakArrayList(context->retained_maps(), cage_base())) {
      RecordSimpleVirtualObjectStats(
          context, Cast<WeakArrayList>(context->retained_maps()),
          ObjectStats::RETAINED_MAPS_TYPE);
    }

  } else if (context->IsFunctionContext()) {
    RecordObjectStats(context, FUNCTION_CONTEXT_TYPE, context->Size());
  } else {
    RecordSimpleVirtualObjectStats(HeapObject(), context,
                                   ObjectStats::OTHER_CONTEXT_TYPE);
  }
}

class ObjectStatsVisitor {
 public:
  ObjectStatsVisitor(Heap* heap, ObjectStatsCollectorImpl* live_collector,
                     ObjectStatsCollectorImpl* dead_collector,
                     ObjectStatsCollectorImpl::Phase phase)
      : live_collector_(live_collector),
        dead_collector_(dead_collector),
        marking_state_(heap->non_atomic_marking_state()),
        phase_(phase) {}

  void Visit(Tagged<HeapObject> obj) {
    if (HeapLayout::InReadOnlySpace(obj) || marking_state_->IsMarked(obj)) {
      live_collector_->CollectStatistics(
          obj, phase_, ObjectStatsCollectorImpl::CollectFieldStats::kYes);
    } else {
      dead_collector_->CollectStatistics(
          obj, phase_, ObjectStatsCollectorImpl::CollectFieldStats::kNo);
    }
  }

 private:
  ObjectStatsCollectorImpl* const live_collector_;
  ObjectStatsCollectorImpl* const dead_collector_;
  NonAtomicMarkingState* const marking_state_;
  ObjectStatsCollectorImpl::Phase phase_;
};

namespace {

void IterateHeap(Heap* heap, ObjectStatsVisitor* visitor) {
  // We don't perform a GC while collecting object stats but need this scope for
  // the nested SafepointScope inside CombinedHeapObjectIterator.
  AllowGarbageCollection allow_gc;
  CombinedHeapObjectIterator iterator(heap);
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    visitor->Visit(obj);
  }
}

}  // namespace

void ObjectStatsCollector::Collect() {
  ObjectStatsCollectorImpl live_collector(heap_, live_);
  ObjectStatsCollectorImpl dead_collector(heap_, dead_);
  live_collector.CollectGlobalStatistics();
  for (int i = 0; i < ObjectStatsCollectorImpl::kNumberOfPhases; i++) {
    ObjectStatsVisitor visitor(heap_, &live_collector, &dead_collector,
                               static_cast<ObjectStatsCollectorImpl::Phase>(i));
    IterateHeap(heap_, &visitor);
  }
}

}  // namespace internal
}  // namespace v8

"""

```