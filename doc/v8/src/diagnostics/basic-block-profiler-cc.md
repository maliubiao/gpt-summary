Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request asks for the functionality of `v8/src/diagnostics/basic-block-profiler.cc`. This immediately tells me it's related to collecting information about the execution of code, specifically focusing on "basic blocks."

2. **Initial Scan for Keywords and Structure:** I'd quickly scan the code for important keywords and structural elements:
    * `#include`:  Indicates dependencies. Notice `<algorithm>`, `<numeric>`, `<sstream>` (standard C++), and then V8-specific headers like `"src/base/lazy-instance.h"`, `"src/builtins/profile-data-reader.h"`, `"src/heap/heap-inl.h"`, `"src/objects/shared-function-info-inl.h"`. These suggest interactions with V8's internals, memory management, built-ins, and object representation.
    * `namespace v8 { namespace internal { ... } }`: This confirms it's part of the V8 engine's internal implementation.
    * `class BasicBlockProfiler`, `class BasicBlockProfilerData`, `class BuiltinsCallGraph`: These are the main actors. I'll need to figure out their roles and how they interact.
    * `DEFINE_LAZY_LEAKY_OBJECT_GETTER`: This macro likely provides a singleton pattern for `BasicBlockProfiler` and `BuiltinsCallGraph`.
    * Constructor and method names (e.g., `NewData`, `SetCode`, `ResetCounts`, `CopyToJSHeap`, `Log`, `Print`, `AddBuiltinCall`, `GetCoverageBitmap`): These provide clues about the actions each class performs.

3. **Focus on Core Functionality (BasicBlockProfilerData):** This class seems central to storing the profiling information.
    * **Data Members:**  `block_ids_`, `counts_`, `code_`, `function_name_`, `schedule_`, `branches_`, `hash_`. These suggest it's tracking the IDs of basic blocks, how many times they're executed, the source code, function name, execution schedule (likely for optimization), branch information, and a hash.
    * **Key Methods:**
        * `BasicBlockProfilerData(size_t n_blocks)`: Constructor taking the number of blocks.
        * `Set...`: Methods for setting the various data members.
        * `ResetCounts()`:  Clears the execution counts.
        * `AddBranch()`: Records information about conditional branches.
        * `CopyToJSHeap()`:  Crucial!  It copies data *to* the JavaScript heap. This strongly suggests a connection to JavaScript and making the profiling data accessible there.
        * `CopyFromJSHeap()`: The reverse of the above. It loads data *from* the JavaScript heap. This implies the data can be persisted or shared.
        * `Log()`:  Formats data for logging, using specific markers (`kBlockCounterMarker`, `kBlockHintMarker`, `kBuiltinHashMarker`).
        * `operator<<`: Overloads the output stream operator, providing a human-readable representation of the data.

4. **Focus on the Profiler (BasicBlockProfiler):** This class seems to manage the `BasicBlockProfilerData` objects.
    * **Data Members:** `data_list_`, `data_list_mutex_`. Suggests it maintains a list of profiling data, likely one per function. The mutex indicates thread safety.
    * **Key Methods:**
        * `NewData(size_t n_blocks)`: Creates a new `BasicBlockProfilerData` object.
        * `ResetCounts(Isolate*)`: Resets the counters for all tracked functions. The `Isolate*` argument signifies interaction with V8's isolated execution environments.
        * `HasData(Isolate*)`: Checks if any profiling data exists.
        * `Print(Isolate*, std::ostream&)`: Prints the profiling data to an output stream.
        * `Log(Isolate*, std::ostream&)`: Logs the profiling data in a specific format.
        * `GetCoverageBitmap(Isolate*)`:  Generates a boolean vector indicating which basic blocks have been executed.

5. **Focus on Call Graph (BuiltinsCallGraph):**  This class is about tracking calls between built-in functions.
    * **Data Members:** `builtin_call_map_`, `all_hash_matched_`.
    * **Key Methods:**
        * `AddBuiltinCall(Builtin caller, Builtin callee, int32_t block_id)`: Records a call from one built-in to another within a specific basic block.
        * `GetBuiltinCallees(Builtin builtin)`: Retrieves the callees of a given built-in.

6. **Connecting to JavaScript:** The `CopyToJSHeap` and `CopyFromJSHeap` methods are the key connections. They tell me that the profiling data can be moved between the C++ world of V8's internals and the JavaScript heap. This allows JavaScript code to access and potentially use this profiling information.

7. **Answering the Specific Questions:** Now I can address the prompts directly:

    * **Functionality:** Summarize the roles of the classes and their methods.
    * **`.tq` Extension:**  Explain that `.tq` signifies Torque code, which is different from C++.
    * **Relationship to JavaScript:** Focus on the heap transfer methods and how this makes the profiling data accessible in JavaScript. Provide a simple JavaScript example demonstrating how one might access or use such data (even if the exact API isn't shown in the C++ code).
    * **Logic Inference:** Choose a simple method like `SetBlockId` and provide a clear input and output example.
    * **Common Programming Errors:** Think about potential issues related to profiling, like performance overhead or incorrect interpretation of the data.

8. **Refinement and Clarity:** Review the explanation for clarity, accuracy, and completeness. Ensure the JavaScript example is illustrative and easy to understand. Use precise terminology (e.g., "basic block," "JavaScript heap").

This structured approach, starting with understanding the overall goal and drilling down into the details of each class and its methods, is crucial for comprehending complex C++ code like this. The key is to look for patterns, relationships between classes, and connections to the broader system (in this case, the V8 JavaScript engine).
这个 C++ 源代码文件 `v8/src/diagnostics/basic-block-profiler.cc` 实现了 V8 引擎中的基本块分析器 (Basic Block Profiler)。 它的主要功能是 **收集和管理代码执行过程中基本块的执行信息，用于性能分析和优化**。

下面列举一下它的具体功能：

**核心功能：**

1. **基本块计数:** 记录每个基本块被执行的次数。
2. **分支信息记录:**  记录基本块之间的分支信息，例如条件跳转的目标。
3. **函数信息存储:** 存储与基本块相关联的函数名、代码以及调度信息。
4. **数据存储:**  将收集到的基本块执行数据存储在 `BasicBlockProfilerData` 对象中。
5. **JavaScript 堆集成:**  能够将收集到的基本块数据复制到 JavaScript 堆中，以便 JavaScript 代码可以访问和使用这些信息。反之，也可以从 JavaScript 堆中加载数据。
6. **数据输出:**  提供方法将收集到的数据打印到标准输出或日志中。
7. **覆盖率计算:** 可以生成一个位图，指示哪些基本块被执行过，用于代码覆盖率分析。
8. **内置函数调用图:**  维护一个内置函数之间的调用图，记录哪些内置函数在哪些基本块中被调用。

**详细功能分解：**

* **`BasicBlockProfilerData` 类:**
    * **存储基本块信息:**  `block_ids_` 存储基本块的 ID，`counts_` 存储每个基本块的执行次数。
    * **存储函数元数据:** `function_name_` 存储函数名，`code_` 存储函数代码，`schedule_` 存储调度信息，`hash_` 存储函数的哈希值。
    * **记录分支:** `branches_` 存储分支目标的基本块 ID。
    * **提供操作方法:**  `SetCode`, `SetFunctionName`, `SetSchedule`, `SetBlockId`, `SetHash`, `ResetCounts`, `AddBranch` 用于设置和操作这些数据。
    * **与 JavaScript 堆交互:** `CopyToJSHeap` 将数据复制到 JavaScript 堆中的 `OnHeapBasicBlockProfilerData` 对象，`CopyFromJSHeap` 从 JavaScript 堆对象中读取数据。
    * **提供输出和日志方法:** `operator<<` 用于格式化输出数据，`Log` 用于生成特定格式的日志。

* **`BasicBlockProfiler` 类:**
    * **单例模式:** 使用 `DEFINE_LAZY_LEAKY_OBJECT_GETTER` 实现单例模式，确保只有一个 `BasicBlockProfiler` 实例。
    * **管理 `BasicBlockProfilerData`:**  维护一个 `data_list_` 来存储所有收集到的 `BasicBlockProfilerData` 对象。
    * **创建新的数据对象:** `NewData` 方法用于为新的函数创建 `BasicBlockProfilerData` 对象。
    * **全局操作:** 提供 `ResetCounts` 方法来重置所有已收集数据的计数器。
    * **检查数据存在性:** `HasData` 方法检查是否有收集到任何数据。
    * **数据输出和日志:** 提供 `Print` 和 `Log` 方法来输出或记录所有收集到的数据。
    * **获取覆盖率位图:** `GetCoverageBitmap` 方法生成代码覆盖率位图。

* **`BuiltinsCallGraph` 类:**
    * **记录内置函数调用:**  `AddBuiltinCall` 方法记录内置函数之间的调用关系以及调用发生的基本块 ID。
    * **查询调用关系:** `GetBuiltinCallees` 方法根据调用者内置函数查找被调用者。

**如果 `v8/src/diagnostics/basic-block-profiler.cc` 以 `.tq` 结尾：**

如果文件名是 `basic-block-profiler.tq`，那么它将是一个 **V8 Torque 源代码文件**。 Torque 是一种 V8 特有的类型化的汇编语言，用于定义 V8 的内置函数和运行时代码。  在这种情况下，该文件将包含使用 Torque 语法编写的、用于实现基本块分析器功能的代码。

**与 JavaScript 的关系及举例：**

`basic-block-profiler.cc` 的功能与 JavaScript 的性能分析和优化密切相关。  V8 可以将收集到的基本块执行数据暴露给 JavaScript，以便开发者可以使用这些数据进行性能分析，例如：

```javascript
// 假设 V8 提供了一个全局对象或 API 来访问基本块分析器数据
if (v8.basicBlockProfiler) {
  const profilingData = v8.basicBlockProfiler.getData();
  profilingData.forEach(function(data) {
    console.log(`Function: ${data.functionName}`);
    console.log("Block Counts:");
    for (const blockId in data.counts) {
      console.log(`  Block ${blockId}: ${data.counts[blockId]}`);
    }
    // ... 可以进一步分析分支信息等
  });
}
```

**这个 JavaScript 示例展示了以下概念：**

* **访问分析器数据:** 假设 V8 提供了一个 `v8.basicBlockProfiler` 对象，可以获取收集到的数据。
* **遍历函数数据:**  遍历每个函数的分析数据。
* **查看基本块计数:**  访问每个基本块的执行次数。

**代码逻辑推理及假设输入输出：**

**方法:** `BasicBlockProfilerData::SetBlockId(size_t offset, int32_t id)`

**假设输入：**

* `offset`: 0
* `id`: 5

**假设初始状态 (在调用 `SetBlockId` 之前):**

* `block_ids_`:  一个大小至少为 1 的 `std::vector<int32_t>`，初始值可能为 `[-1, -1, ...]`

**代码逻辑：**

`DCHECK(offset < n_blocks());`  会检查 `offset` 是否在有效范围内。假设 `n_blocks()` 大于 0，则断言通过。

`block_ids_[offset] = id;`  将 `block_ids_` 向量中索引为 `offset` 的元素设置为 `id`。

**输出（调用 `SetBlockId` 之后）：**

* `block_ids_` 的第一个元素（索引为 0）将被设置为 5。 例如，如果初始 `block_ids_` 是 `[-1, 2, 3]`，那么调用后将变为 `[5, 2, 3]`。

**涉及用户常见的编程错误及举例：**

基本块分析器本身主要在 V8 引擎内部使用，用户通常不会直接编写代码来操作它。 但是，如果开发者试图基于基本块分析数据进行性能优化，可能会犯以下错误：

1. **过早优化:**  在没有充分数据支持的情况下，基于猜测进行优化，可能导致代码更复杂但性能提升不大，甚至下降。

   ```javascript
   // 错误示例：基于猜测进行优化，可能与实际热点不符
   function processData(arr) {
     // 假设开发者认为这个循环是性能瓶颈，但实际可能不是
     for (let i = 0; i < arr.length; i++) {
       // ... 一些复杂的逻辑
     }
     return arr.map(item => item * 2);
   }
   ```

2. **忽略上下文:**  基本块的执行次数只是一个指标，还需要结合函数调用的上下文、输入数据等信息进行综合分析。 高频执行的基本块不一定是性能瓶颈，可能是必然执行的代码。

3. **过度依赖局部信息:**  只关注单个函数或基本块的性能，而忽略了整个应用程序的性能瓶颈。瓶颈可能出现在其他模块或 I/O 操作上。

4. **错误地解释数据:**  不理解基本块分析数据的含义，例如将执行次数高的基本块误认为需要优化的热点，而忽略了该基本块内部的耗时操作可能很短。

5. **修改了优化器依赖的代码结构:** 有些优化器会依赖特定的代码结构进行优化。如果开发者为了“优化”而改变了这些结构，反而可能导致性能下降。例如，过度地手动展开循环，可能反而会让 V8 的优化器失效。

总之，`v8/src/diagnostics/basic-block-profiler.cc` 是 V8 引擎中一个重要的组成部分，它为性能分析和优化提供了底层的执行信息，这些信息可以帮助 V8 自身进行代码优化，也可以通过一定的方式暴露给开发者进行更深入的性能分析。

### 提示词
```
这是目录为v8/src/diagnostics/basic-block-profiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/diagnostics/basic-block-profiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/diagnostics/basic-block-profiler.h"

#include <algorithm>
#include <numeric>
#include <sstream>

#include "src/base/lazy-instance.h"
#include "src/builtins/profile-data-reader.h"
#include "src/heap/heap-inl.h"
#include "src/objects/shared-function-info-inl.h"

namespace v8 {
namespace internal {

DEFINE_LAZY_LEAKY_OBJECT_GETTER(BasicBlockProfiler, BasicBlockProfiler::Get)
DEFINE_LAZY_LEAKY_OBJECT_GETTER(BuiltinsCallGraph, BuiltinsCallGraph::Get)

BasicBlockProfilerData::BasicBlockProfilerData(size_t n_blocks)
    : block_ids_(n_blocks), counts_(n_blocks, 0) {}

void BasicBlockProfilerData::SetCode(const std::ostringstream& os) {
  code_ = os.str();
}

void BasicBlockProfilerData::SetFunctionName(std::unique_ptr<char[]> name) {
  function_name_ = name.get();
}

void BasicBlockProfilerData::SetSchedule(const std::ostringstream& os) {
  schedule_ = os.str();
}

void BasicBlockProfilerData::SetBlockId(size_t offset, int32_t id) {
  DCHECK(offset < n_blocks());
  block_ids_[offset] = id;
}

void BasicBlockProfilerData::SetHash(int hash) { hash_ = hash; }

void BasicBlockProfilerData::ResetCounts() {
  for (size_t i = 0; i < n_blocks(); ++i) {
    counts_[i] = 0;
  }
}

void BasicBlockProfilerData::AddBranch(int32_t true_block_id,
                                       int32_t false_block_id) {
  branches_.emplace_back(true_block_id, false_block_id);
}

BasicBlockProfilerData* BasicBlockProfiler::NewData(size_t n_blocks) {
  base::MutexGuard lock(&data_list_mutex_);
  auto data = std::make_unique<BasicBlockProfilerData>(n_blocks);
  BasicBlockProfilerData* data_ptr = data.get();
  data_list_.push_back(std::move(data));
  return data_ptr;
}

namespace {
Handle<String> CopyStringToJSHeap(const std::string& source, Isolate* isolate) {
  return isolate->factory()->NewStringFromAsciiChecked(source.c_str(),
                                                       AllocationType::kOld);
}

constexpr int kBlockIdSlotSize = kInt32Size;
constexpr int kBlockCountSlotSize = kInt32Size;
}  // namespace

BasicBlockProfilerData::BasicBlockProfilerData(
    DirectHandle<OnHeapBasicBlockProfilerData> js_heap_data, Isolate* isolate) {
  DisallowHeapAllocation no_gc;
  CopyFromJSHeap(*js_heap_data);
}

BasicBlockProfilerData::BasicBlockProfilerData(
    Tagged<OnHeapBasicBlockProfilerData> js_heap_data) {
  CopyFromJSHeap(js_heap_data);
}

void BasicBlockProfilerData::CopyFromJSHeap(
    Tagged<OnHeapBasicBlockProfilerData> js_heap_data) {
  function_name_ = js_heap_data->name()->ToCString().get();
  schedule_ = js_heap_data->schedule()->ToCString().get();
  code_ = js_heap_data->code()->ToCString().get();
  Tagged<FixedUInt32Array> counts =
      Cast<FixedUInt32Array>(js_heap_data->counts());
  for (int i = 0; i < counts->length() / kBlockCountSlotSize; ++i) {
    counts_.push_back(counts->get(i));
  }
  Tagged<FixedInt32Array> block_ids(js_heap_data->block_ids());
  for (int i = 0; i < block_ids->length() / kBlockIdSlotSize; ++i) {
    block_ids_.push_back(block_ids->get(i));
  }
  Tagged<PodArray<std::pair<int32_t, int32_t>>> branches =
      js_heap_data->branches();
  for (int i = 0; i < branches->length(); ++i) {
    branches_.push_back(branches->get(i));
  }
  CHECK_EQ(block_ids_.size(), counts_.size());
  hash_ = js_heap_data->hash();
}

Handle<OnHeapBasicBlockProfilerData> BasicBlockProfilerData::CopyToJSHeap(
    Isolate* isolate) {
  int id_array_size_in_bytes = static_cast<int>(n_blocks() * kBlockIdSlotSize);
  CHECK(id_array_size_in_bytes >= 0 &&
        static_cast<size_t>(id_array_size_in_bytes) / kBlockIdSlotSize ==
            n_blocks());  // Overflow
  DirectHandle<FixedInt32Array> block_ids = FixedInt32Array::New(
      isolate, id_array_size_in_bytes, AllocationType::kOld);
  for (int i = 0; i < static_cast<int>(n_blocks()); ++i) {
    block_ids->set(i, block_ids_[i]);
  }

  int counts_array_size_in_bytes =
      static_cast<int>(n_blocks() * kBlockCountSlotSize);
  CHECK(counts_array_size_in_bytes >= 0 &&
        static_cast<size_t>(counts_array_size_in_bytes) / kBlockCountSlotSize ==
            n_blocks());  // Overflow
  DirectHandle<FixedUInt32Array> counts = FixedUInt32Array::New(
      isolate, counts_array_size_in_bytes, AllocationType::kOld);
  for (int i = 0; i < static_cast<int>(n_blocks()); ++i) {
    counts->set(i, counts_[i]);
  }

  DirectHandle<PodArray<std::pair<int32_t, int32_t>>> branches =
      PodArray<std::pair<int32_t, int32_t>>::New(
          isolate, static_cast<int>(branches_.size()), AllocationType::kOld);
  for (int i = 0; i < static_cast<int>(branches_.size()); ++i) {
    branches->set(i, branches_[i]);
  }
  DirectHandle<String> name = CopyStringToJSHeap(function_name_, isolate);
  DirectHandle<String> schedule = CopyStringToJSHeap(schedule_, isolate);
  DirectHandle<String> code = CopyStringToJSHeap(code_, isolate);

  return isolate->factory()->NewOnHeapBasicBlockProfilerData(
      block_ids, counts, branches, name, schedule, code, hash_,
      AllocationType::kOld);
}

void BasicBlockProfiler::ResetCounts(Isolate* isolate) {
  for (const auto& data : data_list_) {
    data->ResetCounts();
  }
  HandleScope scope(isolate);
  DirectHandle<ArrayList> list(isolate->heap()->basic_block_profiling_data(),
                               isolate);
  for (int i = 0; i < list->length(); ++i) {
    DirectHandle<FixedUInt32Array> counts(
        Cast<OnHeapBasicBlockProfilerData>(list->get(i))->counts(), isolate);
    for (int j = 0; j < counts->length() / kBlockCountSlotSize; ++j) {
      counts->set(j, 0);
    }
  }
}

bool BasicBlockProfiler::HasData(Isolate* isolate) {
  return !data_list_.empty() ||
         isolate->heap()->basic_block_profiling_data()->length() > 0;
}

void BasicBlockProfiler::Print(Isolate* isolate, std::ostream& os) {
  os << "---- Start Profiling Data ----" << '\n';
  for (const auto& data : data_list_) {
    os << *data;
  }
  HandleScope scope(isolate);
  DirectHandle<ArrayList> list(isolate->heap()->basic_block_profiling_data(),
                               isolate);
  std::unordered_set<std::string> builtin_names;
  for (int i = 0; i < list->length(); ++i) {
    BasicBlockProfilerData data(
        handle(Cast<OnHeapBasicBlockProfilerData>(list->get(i)), isolate),
        isolate);
    os << data;
    // Ensure that all builtin names are unique; otherwise profile-guided
    // optimization might get confused.
    CHECK(builtin_names.insert(data.function_name_).second);
  }
  os << "---- End Profiling Data ----" << '\n';
}

void BasicBlockProfiler::Log(Isolate* isolate, std::ostream& os) {
  HandleScope scope(isolate);
  DirectHandle<ArrayList> list(isolate->heap()->basic_block_profiling_data(),
                               isolate);
  std::unordered_set<std::string> builtin_names;
  for (int i = 0; i < list->length(); ++i) {
    BasicBlockProfilerData data(
        handle(Cast<OnHeapBasicBlockProfilerData>(list->get(i)), isolate),
        isolate);
    data.Log(isolate, os);
    // Ensure that all builtin names are unique; otherwise profile-guided
    // optimization might get confused.
    CHECK(builtin_names.insert(data.function_name_).second);
  }
}

std::vector<bool> BasicBlockProfiler::GetCoverageBitmap(Isolate* isolate) {
  DisallowGarbageCollection no_gc;
  Tagged<ArrayList> list(isolate->heap()->basic_block_profiling_data());
  std::vector<bool> out;
  int list_length = list->length();
  for (int i = 0; i < list_length; ++i) {
    BasicBlockProfilerData data(
        Cast<OnHeapBasicBlockProfilerData>(list->get(i)));
    for (size_t j = 0; j < data.n_blocks(); ++j) {
      out.push_back(data.counts_[j] > 0);
    }
  }
  return out;
}

void BasicBlockProfilerData::Log(Isolate* isolate, std::ostream& os) {
  bool any_nonzero_counter = false;
  constexpr char kNext[] = "\t";
  for (size_t i = 0; i < n_blocks(); ++i) {
    if (counts_[i] > 0) {
      any_nonzero_counter = true;
      os << ProfileDataFromFileConstants::kBlockCounterMarker << kNext
         << function_name_.c_str() << kNext << block_ids_[i] << kNext
         << counts_[i] << '\n';
    }
  }
  if (any_nonzero_counter) {
    for (size_t i = 0; i < branches_.size(); ++i) {
      os << ProfileDataFromFileConstants::kBlockHintMarker << kNext
         << function_name_.c_str() << kNext << branches_[i].first << kNext
         << branches_[i].second << '\n';
    }
    os << ProfileDataFromFileConstants::kBuiltinHashMarker << kNext
       << function_name_.c_str() << kNext << hash_ << '\n';
  }
}

std::ostream& operator<<(std::ostream& os, const BasicBlockProfilerData& d) {
  if (std::all_of(d.counts_.cbegin(), d.counts_.cend(),
                  [](uint32_t count) { return count == 0; })) {
    // No data was collected for this function.
    return os;
  }
  const char* name = "unknown function";
  if (!d.function_name_.empty()) {
    name = d.function_name_.c_str();
  }
  if (!d.schedule_.empty()) {
    os << "schedule for " << name << " (B0 entered " << d.counts_[0]
       << " times)" << '\n';
    os << d.schedule_.c_str() << '\n';
  }
  os << "block counts for " << name << ":" << '\n';
  std::vector<std::pair<size_t, uint32_t>> pairs;
  pairs.reserve(d.n_blocks());
  for (size_t i = 0; i < d.n_blocks(); ++i) {
    pairs.push_back(std::make_pair(i, d.counts_[i]));
  }
  std::sort(
      pairs.begin(), pairs.end(),
      [=](std::pair<size_t, uint32_t> left, std::pair<size_t, uint32_t> right) {
        if (right.second == left.second) return left.first < right.first;
        return right.second < left.second;
      });
  for (auto it : pairs) {
    if (it.second == 0) break;
    os << "block B" << it.first << " : " << it.second << '\n';
  }
  os << '\n';
  if (!d.code_.empty()) {
    os << d.code_.c_str() << '\n';
  }
  return os;
}

BuiltinsCallGraph::BuiltinsCallGraph() : all_hash_matched_(true) {}

void BuiltinsCallGraph::AddBuiltinCall(Builtin caller, Builtin callee,
                                       int32_t block_id) {
  if (builtin_call_map_.count(caller) == 0) {
    builtin_call_map_.emplace(caller, BuiltinCallees());
  }
  BuiltinCallees& callees = builtin_call_map_.at(caller);
  if (callees.count(block_id) == 0) {
    callees.emplace(block_id, BlockCallees());
  }
  BlockCallees& block_callees = callees.at(block_id);
  if (block_callees.count(callee) == 0) {
    block_callees.emplace(callee);
  }
}

const BuiltinCallees* BuiltinsCallGraph::GetBuiltinCallees(Builtin builtin) {
  if (builtin_call_map_.count(builtin) == 0) return nullptr;
  return &builtin_call_map_.at(builtin);
}

}  // namespace internal
}  // namespace v8
```