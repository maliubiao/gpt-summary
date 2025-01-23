Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Initial Scan and Purpose Identification:** The first step is a quick read-through to grasp the general purpose. Keywords like "object stats," "heap," "instance types," "counts," "sizes," "histogram," and "JSON" immediately suggest this file is about collecting and reporting statistics on objects within the V8 JavaScript engine's heap. The copyright notice at the top confirms this is indeed V8 code.

2. **File Extension Check:** The prompt specifically asks about the `.tq` extension. The analysis correctly notes that this is a `.h` file (header file in C++), *not* a `.tq` file. This means it's standard C++ and not Torque.

3. **Core Functionality Identification - The `ObjectStats` Class:**  The core of the file is the `ObjectStats` class. The analysis should focus on its members and methods:
    * **Constructor (`ObjectStats(Heap* heap)`):**  Takes a `Heap*` as input, suggesting it's tied to a specific heap instance. The `ClearObjectStats(true)` call indicates initialization.
    * **`VirtualInstanceType` enum:**  This is a key part. The `#define VIRTUAL_INSTANCE_TYPE_LIST(V)` macro is used to generate a list of "virtual" instance types. The comment explicitly states these are for object stats tracing and not necessarily types used elsewhere in V8. This is important to distinguish from regular `InstanceType`.
    * **`OBJECT_STATS_COUNT` constant:**  Calculates the total number of stats being tracked. Understanding how this is calculated (based on `LAST_TYPE` and `LAST_VIRTUAL_TYPE`) is crucial.
    * **`ClearObjectStats`:** Resets the counters.
    * **`PrintJSON`, `Dump`:**  These clearly indicate functionality for outputting the collected statistics in different formats.
    * **`CheckpointObjectStats`:**  Suggests capturing the current stats for comparison later.
    * **`RecordObjectStats`, `RecordVirtualObjectStats`:**  These are the core methods for *collecting* the statistics. They take the instance type, size, and optionally over-allocated size as input.
    * **`object_count_last_gc`, `object_size_last_gc`:** Provide access to the stats from the last garbage collection.
    * **`HistogramIndexFromSize`:** Converts an object size into an index for the size histogram.
    * **Data Members:**  The arrays (`object_counts_`, `object_sizes_`, `over_allocated_`, `size_histogram_`, `over_allocated_histogram_`) are where the actual statistics are stored. The individual counters (`tagged_fields_count_`, etc.) track specific low-level details.

4. **Core Functionality Identification - The `ObjectStatsCollector` Class:** This class is responsible for *driving* the collection process.
    * **Constructor:** Takes pointers to the `Heap` and two `ObjectStats` objects (`live_` and `dead_`). This separation into live and dead objects is a common pattern in garbage collectors.
    * **`Collect()`:** The main method that performs the actual collection. The comment mentions "mark bits," linking this to the garbage collection process.

5. **Relationship to JavaScript:**  The prompt specifically asks about JavaScript relevance. The key link is that V8 *executes* JavaScript. The objects being tracked by `ObjectStats` are the *internal representations* of JavaScript objects, strings, functions, etc., within the V8 engine. The analysis correctly identifies this indirect relationship and provides examples of JavaScript code that would lead to the creation of these internal objects.

6. **Code Logic and Assumptions:**  The prompt asks for code logic and assumptions. The main logic here is the mapping of instance types and sizes to counters and histograms. The assumption is that the `RecordObjectStats` and `RecordVirtualObjectStats` methods are called appropriately during object allocation and garbage collection. The size bucketing logic in `HistogramIndexFromSize` is also an example of internal logic. The analysis explains this bucketing.

7. **Common Programming Errors (from a V8 perspective):**  This requires thinking about how *misuse* or issues *within V8 itself* related to these statistics could manifest. The analysis correctly identifies memory leaks and unexpected object growth as potential problems that this kind of monitoring can help diagnose. While the *user* doesn't directly interact with these classes, understanding these internal issues helps in debugging performance problems in JavaScript applications.

8. **Javascript Examples:**  Providing concrete JavaScript examples that would lead to the creation of the tracked object types is crucial for illustrating the connection to the user-facing language. The examples for arrays, functions, objects, and strings are appropriate.

9. **Structure and Clarity:** Organize the information logically. Start with the basic function, then delve into the classes, their members, and methods. Clearly separate the explanation of each part. Use headings and bullet points for better readability.

10. **Refinement and Review:**  After drafting the initial analysis, review it for clarity, accuracy, and completeness. Ensure all parts of the prompt have been addressed. For instance, double-checking the `.tq` point and clarifying the "virtual" instance types are important refinements.

This structured approach, starting with a high-level understanding and progressively diving into details, helps in thoroughly analyzing and explaining the functionality of a complex code file like this.
## 功能列举

`v8/src/heap/object-stats.h` 文件定义了用于跟踪和统计 V8 堆中对象信息的类 `ObjectStats` 和 `ObjectStatsCollector`。其主要功能包括：

1. **记录对象数量和大小:**  能够针对不同的对象类型（`InstanceType` 和自定义的 `VirtualInstanceType`）记录其创建的数量和占用的内存大小。
2. **跟踪虚拟对象类型:**  定义了一系列 `VirtualInstanceType`，这些类型并非实际存在的对象类型，而是为了更细粒度地统计某些内部数据结构或对象属性（例如，代码的不同种类、数组的不同形态、反馈向量的各种槽位等）。
3. **统计对象内存分配的额外开销:** 可以记录对象分配时产生的额外开销 (`over_allocated`)，这有助于分析内存碎片和分配效率。
4. **生成对象统计直方图:**  可以根据对象大小生成直方图，用于分析不同大小对象的分布情况。
5. **支持 JSON 和文本格式的统计信息输出:**  提供了将统计数据输出为 JSON 格式 (`PrintJSON`) 和文本格式 (`Dump`) 的方法，方便分析和可视化。
6. **记录上次垃圾回收后的对象统计信息:**  能够记录上次垃圾回收后的对象数量和大小，用于比较和分析内存增长趋势。
7. **提供对象统计的快照功能:**  `CheckpointObjectStats` 方法可以创建一个当前对象统计信息的快照，以便后续比较。
8. **对象统计收集:**  `ObjectStatsCollector` 类负责遍历堆，收集存活和死亡对象的类型信息，并更新 `ObjectStats` 对象。

**总结来说，`v8/src/heap/object-stats.h` 的核心功能是提供一种机制，用于深入了解 V8 堆中各种对象的分布、大小和内存分配情况，这对于性能分析、内存泄漏检测以及理解 V8 内部工作原理至关重要。**

## 关于 `.tq` 扩展名

如果 `v8/src/heap/object-stats.h` 的文件扩展名是 `.tq`，那么它就是一个 **V8 Torque 源代码**文件。 Torque 是 V8 使用的一种领域特定语言 (DSL)，用于安全地编写 V8 的内部运行时代码，特别是类型安全的 C++ 代码生成。

**当前的文件扩展名是 `.h`，表明它是一个标准的 C++ 头文件，而不是 Torque 文件。**

## 与 JavaScript 的关系及示例

`v8/src/heap/object-stats.h` 中跟踪的许多对象类型都直接或间接地与 JavaScript 的功能有关。  当我们执行 JavaScript 代码时，V8 引擎会在堆上创建各种内部对象来表示 JavaScript 的数据结构和执行上下文。

以下是一些 JavaScript 代码示例，以及它们可能导致 `ObjectStats` 中记录的某些对象类型：

**1. 创建数组:**

```javascript
const arr = [1, 2, 3];
```

这会导致在 V8 堆上分配 `JSArray` 对象来存储数组，以及可能分配以下相关的虚拟类型：

* `ARRAY_ELEMENTS_TYPE`:  存储数组元素的区域。
* `ARRAY_BOILERPLATE_DESCRIPTION_ELEMENTS_TYPE`: 用于快速创建类似数组的优化结构。

**2. 创建对象:**

```javascript
const obj = { a: 1, b: 'hello' };
```

这会导致在 V8 堆上分配 `JSObject` 对象，以及可能分配以下相关的虚拟类型：

* `OBJECT_PROPERTY_ARRAY_TYPE`:  用于存储对象属性的数组（在属性数量较少时）。
* `OBJECT_PROPERTY_DICTIONARY_TYPE`: 用于存储对象属性的哈希表（在属性数量较多时）。
* `MAP_TYPE`:  描述对象的布局和属性信息的对象。

**3. 定义函数:**

```javascript
function add(x, y) {
  return x + y;
}
```

这会导致在 V8 堆上分配 `JSFunction` 对象，以及可能分配以下相关的虚拟类型：

* `BYTECODE_ARRAY_CONSTANT_POOL_TYPE`: 存储函数字节码中使用的常量。
* `BYTECODE_ARRAY_HANDLER_TABLE_TYPE`: 存储异常处理信息。
* `FEEDBACK_VECTOR_TYPE`:  用于存储函数执行的反馈信息，帮助 V8 进行优化。

**4. 使用字符串:**

```javascript
const str = "world";
```

这会导致在 V8 堆上分配 `String` 对象，以及可能分配以下相关的虚拟类型：

* `SINGLE_CHARACTER_STRING_TABLE_TYPE`:  用于缓存单个字符的字符串。
* `STRING_EXTERNAL_RESOURCE_ONE_BYTE_TYPE` / `STRING_EXTERNAL_RESOURCE_TWO_BYTE_TYPE`:  当字符串内容来自外部资源时使用。

**总而言之，`ObjectStats` 跟踪的很多内部对象类型都是 JavaScript 代码执行的底层支撑。通过分析这些统计信息，我们可以更好地理解 JavaScript 代码在 V8 引擎中的内存使用情况和性能特征。**

## 代码逻辑推理 (假设输入与输出)

假设在 V8 引擎运行一段时间后，堆中存在以下情况：

* 创建了 100 个普通的 JavaScript 对象，每个对象大小约为 64 字节。
* 创建了 50 个数组，每个数组包含 10 个整数，数组元素区域大小约为 40 字节。
* 编译了一个 JavaScript 函数，其字节码数组大小为 128 字节。

**假设输入 (调用 `RecordObjectStats` 或 `RecordVirtualObjectStats` 的场景):**

1. **创建 JavaScript 对象:**
   * 调用 `RecordObjectStats(JS_OBJECT_TYPE, 64)` 100 次。
2. **创建数组元素区域:**
   * 调用 `RecordVirtualObjectStats(ARRAY_ELEMENTS_TYPE, 40)` 50 次。
3. **编译函数字节码:**
   * 调用 `RecordVirtualObjectStats(BYTECODE_ARRAY_CONSTANT_POOL_TYPE, 128)` 1 次 (假设常量池与字节码数组一起分配)。

**预期输出 (部分 `ObjectStats` 成员变量的值):**

* `object_counts_[JS_OBJECT_TYPE]`: 100
* `object_sizes_[JS_OBJECT_TYPE]`: 6400 (100 * 64)
* `object_counts_[FIRST_VIRTUAL_TYPE + ARRAY_ELEMENTS_TYPE]`: 50  (假设 `ARRAY_ELEMENTS_TYPE` 在 `VirtualInstanceType` 中的索引)
* `object_sizes_[FIRST_VIRTUAL_TYPE + ARRAY_ELEMENTS_TYPE]`: 2000 (50 * 40)
* `object_counts_[FIRST_VIRTUAL_TYPE + BYTECODE_ARRAY_CONSTANT_POOL_TYPE]`: 1
* `object_sizes_[FIRST_VIRTUAL_TYPE + BYTECODE_ARRAY_CONSTANT_POOL_TYPE]`: 128

**假设调用 `PrintJSON` 后的 JSON 片段：**

```json
{
  "JS_OBJECT": {
    "count": 100,
    "size": 6400
    // ... 其他统计信息
  },
  "ARRAY_ELEMENTS": {
    "count": 50,
    "size": 2000
    // ... 其他统计信息
  },
  "BYTECODE_ARRAY_CONSTANT_POOL": {
    "count": 1,
    "size": 128
    // ... 其他统计信息
  }
  // ... 其他对象类型的统计信息
}
```

**注意:** 这只是一个简化的示例，实际的统计信息会更复杂，并且受到 V8 引擎内部实现细节的影响。

## 涉及用户常见的编程错误

虽然用户通常不会直接操作 `v8/src/heap/object-stats.h` 中的代码，但该文件统计的信息可以帮助诊断由用户代码引起的常见编程错误，例如：

**1. 内存泄漏:**

* **现象:** 如果用户代码不断创建对象，但没有正确释放（例如，忘记取消事件监听器，闭包引用导致对象无法回收），会导致 `ObjectStats` 中某些对象类型的 `count` 和 `size` 持续增长，即使进行了垃圾回收。
* **`ObjectStats` 的帮助:** 通过比较多次垃圾回收前后的统计信息，可以发现哪些类型的对象数量增长异常，从而定位可能发生内存泄漏的代码。例如，`JS_OBJECT_TYPE` 或自定义的对象类型的数量持续增加。

**示例 (JavaScript - 导致内存泄漏的常见模式):**

```javascript
let leakedObjects = [];
setInterval(() => {
  let obj = { data: new Array(1000).fill(0) }; // 创建大对象
  leakedObjects.push(obj); // 无意中持有对象的引用，阻止垃圾回收
}, 1000);
```

**2. 创建过多的临时对象:**

* **现象:**  用户代码在循环或频繁调用的函数中创建大量短暂使用的对象，会导致频繁的垃圾回收，影响性能。
* **`ObjectStats` 的帮助:**  可以观察到某些对象类型的创建和销毁非常频繁，特别是在垃圾回收前后数量变化很大。例如，短生命周期的字符串或小对象的数量波动剧烈。

**示例 (JavaScript - 创建过多临时对象):**

```javascript
function processData(data) {
  for (let i = 0; i < data.length; i++) {
    const temp = data[i].toString(); // 每次循环都创建新的字符串
    // ... 对 temp 进行一些操作
  }
}
```

**3. 意外地创建了大量的某种特定类型的对象:**

* **现象:** 由于用户代码的逻辑错误，导致意外地创建了大量的某种特定类型的对象，消耗大量内存。
* **`ObjectStats` 的帮助:**  可以快速发现某些对象类型的数量或大小异常增长，从而提醒开发者检查相关代码逻辑。例如，错误地在循环中创建了大量的函数或闭包。

**示例 (JavaScript - 意外创建大量闭包):**

```javascript
function createHandlers() {
  let handlers = [];
  for (var i = 0; i < 1000; i++) { // 使用 var 导致闭包问题
    handlers.push(function() {
      console.log(i);
    });
  }
  return handlers;
}
const handlers = createHandlers(); // 创建了 1000 个闭包，每个闭包都引用了 i
```

**总结:**  尽管用户不直接编写或修改 `v8/src/heap/object-stats.h`，但通过 V8 提供的工具（如 Chrome 开发者工具的 Memory 面板，其底层就使用了类似的统计信息）来分析 `ObjectStats` 中记录的数据，可以帮助开发者识别和解决常见的 JavaScript 编程错误，特别是与内存管理和性能相关的问题。

### 提示词
```
这是目录为v8/src/heap/object-stats.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/object-stats.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_HEAP_OBJECT_STATS_H_
#define V8_HEAP_OBJECT_STATS_H_

#include "src/objects/code.h"
#include "src/objects/objects.h"

// These instance types do not exist for actual use but are merely introduced
// for object stats tracing. In contrast to InstructionStream and FixedArray sub
// types these types are not known to other counters outside of object stats
// tracing.
//
// Update LAST_VIRTUAL_TYPE below when changing this macro.
#define VIRTUAL_INSTANCE_TYPE_LIST(V)            \
  CODE_KIND_LIST(V)                              \
  V(ARRAY_BOILERPLATE_DESCRIPTION_ELEMENTS_TYPE) \
  V(ARRAY_DICTIONARY_ELEMENTS_TYPE)              \
  V(ARRAY_ELEMENTS_TYPE)                         \
  V(BOILERPLATE_ELEMENTS_TYPE)                   \
  V(BOILERPLATE_PROPERTY_ARRAY_TYPE)             \
  V(BOILERPLATE_PROPERTY_DICTIONARY_TYPE)        \
  V(BYTECODE_ARRAY_CONSTANT_POOL_TYPE)           \
  V(BYTECODE_ARRAY_HANDLER_TABLE_TYPE)           \
  V(COW_ARRAY_TYPE)                              \
  V(DEOPTIMIZATION_DATA_TYPE)                    \
  V(DEPENDENT_CODE_TYPE)                         \
  V(DEPRECATED_DESCRIPTOR_ARRAY_TYPE)            \
  V(EMBEDDED_OBJECT_TYPE)                        \
  V(ENUM_KEYS_CACHE_TYPE)                        \
  V(ENUM_INDICES_CACHE_TYPE)                     \
  V(FEEDBACK_VECTOR_ENTRY_TYPE)                  \
  V(FEEDBACK_VECTOR_HEADER_TYPE)                 \
  V(FEEDBACK_VECTOR_SLOT_CALL_TYPE)              \
  V(FEEDBACK_VECTOR_SLOT_CALL_UNUSED_TYPE)       \
  V(FEEDBACK_VECTOR_SLOT_ENUM_TYPE)              \
  V(FEEDBACK_VECTOR_SLOT_LOAD_TYPE)              \
  V(FEEDBACK_VECTOR_SLOT_LOAD_UNUSED_TYPE)       \
  V(FEEDBACK_VECTOR_SLOT_OTHER_TYPE)             \
  V(FEEDBACK_VECTOR_SLOT_STORE_TYPE)             \
  V(FEEDBACK_VECTOR_SLOT_STORE_UNUSED_TYPE)      \
  V(FUNCTION_TEMPLATE_INFO_ENTRIES_TYPE)         \
  V(GLOBAL_ELEMENTS_TYPE)                        \
  V(GLOBAL_PROPERTIES_TYPE)                      \
  V(JS_ARRAY_BOILERPLATE_TYPE)                   \
  V(JS_COLLECTION_TABLE_TYPE)                    \
  V(JS_OBJECT_BOILERPLATE_TYPE)                  \
  V(JS_UNCOMPILED_FUNCTION_TYPE)                 \
  V(MAP_ABANDONED_PROTOTYPE_TYPE)                \
  V(MAP_DEPRECATED_TYPE)                         \
  V(MAP_DICTIONARY_TYPE)                         \
  V(MAP_PROTOTYPE_DICTIONARY_TYPE)               \
  V(MAP_PROTOTYPE_TYPE)                          \
  V(MAP_STABLE_TYPE)                             \
  V(NUMBER_STRING_CACHE_TYPE)                    \
  V(OBJECT_DICTIONARY_ELEMENTS_TYPE)             \
  V(OBJECT_ELEMENTS_TYPE)                        \
  V(OBJECT_PROPERTY_ARRAY_TYPE)                  \
  V(OBJECT_PROPERTY_DICTIONARY_TYPE)             \
  V(OBJECT_TO_CODE_TYPE)                         \
  V(OPTIMIZED_CODE_LITERALS_TYPE)                \
  V(OTHER_CONTEXT_TYPE)                          \
  V(PROTOTYPE_DESCRIPTOR_ARRAY_TYPE)             \
  V(PROTOTYPE_PROPERTY_ARRAY_TYPE)               \
  V(PROTOTYPE_PROPERTY_DICTIONARY_TYPE)          \
  V(PROTOTYPE_USERS_TYPE)                        \
  V(REGEXP_MULTIPLE_CACHE_TYPE)                  \
  V(RELOC_INFO_TYPE)                             \
  V(RETAINED_MAPS_TYPE)                          \
  V(SCRIPT_LIST_TYPE)                            \
  V(SCRIPT_INFOS_TYPE)                           \
  V(SCRIPT_SOURCE_EXTERNAL_ONE_BYTE_TYPE)        \
  V(SCRIPT_SOURCE_EXTERNAL_TWO_BYTE_TYPE)        \
  V(SCRIPT_SOURCE_NON_EXTERNAL_ONE_BYTE_TYPE)    \
  V(SCRIPT_SOURCE_NON_EXTERNAL_TWO_BYTE_TYPE)    \
  V(SERIALIZED_OBJECTS_TYPE)                     \
  V(SINGLE_CHARACTER_STRING_TABLE_TYPE)          \
  V(STRING_SPLIT_CACHE_TYPE)                     \
  V(STRING_EXTERNAL_RESOURCE_ONE_BYTE_TYPE)      \
  V(STRING_EXTERNAL_RESOURCE_TWO_BYTE_TYPE)      \
  V(SOURCE_POSITION_TABLE_TYPE)                  \
  V(UNCOMPILED_SHARED_FUNCTION_INFO_TYPE)        \
  V(WEAK_NEW_SPACE_OBJECT_TO_CODE_TYPE)

namespace v8 {
namespace internal {

class Heap;
class Isolate;

class ObjectStats {
 public:
  static const size_t kNoOverAllocation = 0;

  explicit ObjectStats(Heap* heap) : heap_(heap) { ClearObjectStats(true); }

  // See description on VIRTUAL_INSTANCE_TYPE_LIST.
  enum VirtualInstanceType {
#define DEFINE_VIRTUAL_INSTANCE_TYPE(type) type,
    VIRTUAL_INSTANCE_TYPE_LIST(DEFINE_VIRTUAL_INSTANCE_TYPE)
#undef DEFINE_FIXED_ARRAY_SUB_INSTANCE_TYPE
        LAST_VIRTUAL_TYPE = WEAK_NEW_SPACE_OBJECT_TO_CODE_TYPE,
  };

  // ObjectStats are kept in two arrays, counts and sizes. Related stats are
  // stored in a contiguous linear buffer. Stats groups are stored one after
  // another.
  static constexpr int FIRST_VIRTUAL_TYPE = LAST_TYPE + 1;
  static constexpr int OBJECT_STATS_COUNT =
      FIRST_VIRTUAL_TYPE + LAST_VIRTUAL_TYPE + 1;

  void ClearObjectStats(bool clear_last_time_stats = false);

  void PrintJSON(const char* key);
  void Dump(std::stringstream& stream);

  void CheckpointObjectStats();
  void RecordObjectStats(InstanceType type, size_t size,
                         size_t over_allocated = kNoOverAllocation);
  void RecordVirtualObjectStats(VirtualInstanceType type, size_t size,
                                size_t over_allocated);

  size_t object_count_last_gc(size_t index) {
    return object_counts_last_time_[index];
  }

  size_t object_size_last_gc(size_t index) {
    return object_sizes_last_time_[index];
  }

  Isolate* isolate();
  Heap* heap() { return heap_; }

 private:
  static const int kFirstBucketShift = 5;  // <32
  static const int kLastBucketShift = 20;  // >=1M
  static const int kFirstBucket = 1 << kFirstBucketShift;
  static const int kLastBucket = 1 << kLastBucketShift;
  static const int kNumberOfBuckets = kLastBucketShift - kFirstBucketShift + 1;
  static const int kLastValueBucketIndex = kLastBucketShift - kFirstBucketShift;

  void PrintKeyAndId(const char* key, int gc_count);
  // The following functions are excluded from inline to reduce the overall
  // binary size of VB. On x64 this save around 80KB.
  V8_NOINLINE void PrintInstanceTypeJSON(const char* key, int gc_count,
                                         const char* name, int index);
  V8_NOINLINE void DumpInstanceTypeData(std::stringstream& stream,
                                        const char* name, int index);

  int HistogramIndexFromSize(size_t size);

  Heap* heap_;
  // Object counts and used memory by InstanceType.
  size_t object_counts_[OBJECT_STATS_COUNT];
  size_t object_counts_last_time_[OBJECT_STATS_COUNT];
  size_t object_sizes_[OBJECT_STATS_COUNT];
  size_t object_sizes_last_time_[OBJECT_STATS_COUNT];
  // Approximation of overallocated memory by InstanceType.
  size_t over_allocated_[OBJECT_STATS_COUNT];
  // Detailed histograms by InstanceType.
  size_t size_histogram_[OBJECT_STATS_COUNT][kNumberOfBuckets];
  size_t over_allocated_histogram_[OBJECT_STATS_COUNT][kNumberOfBuckets];

  size_t tagged_fields_count_;
  size_t embedder_fields_count_;
  size_t inobject_smi_fields_count_;
  size_t boxed_double_fields_count_;
  size_t string_data_count_;
  size_t raw_fields_count_;

  friend class ObjectStatsCollectorImpl;
};

class ObjectStatsCollector {
 public:
  ObjectStatsCollector(Heap* heap, ObjectStats* live, ObjectStats* dead)
      : heap_(heap), live_(live), dead_(dead) {
    DCHECK_NOT_NULL(heap_);
    DCHECK_NOT_NULL(live_);
    DCHECK_NOT_NULL(dead_);
  }

  // Collects type information of live and dead objects. Requires mark bits to
  // be present.
  void Collect();

 private:
  Heap* const heap_;
  ObjectStats* const live_;
  ObjectStats* const dead_;
};

}  // namespace internal
}  // namespace v8

#endif  // V8_HEAP_OBJECT_STATS_H_
```