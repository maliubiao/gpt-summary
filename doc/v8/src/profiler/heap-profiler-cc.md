Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Initial Skim and Identify Core Purpose:**  The filename `heap-profiler.cc` immediately suggests this code is about analyzing the JavaScript heap. The copyright notice confirms it's part of the V8 project. Skimming through the includes reveals dependencies on heap management, object representation (`JSObject`, `HeapObject`), and profiling related headers. This reinforces the initial understanding.

2. **High-Level Functionality Identification (Keywords and Class Structure):** I start looking for keywords related to profiling: "snapshot", "sampling", "allocation", "tracking", "embedder graph". The class `HeapProfiler` is the central entity. Its constructor, destructor, and methods provide clues about its responsibilities.

3. **Detailed Method Analysis (Function by Function):** I go through the methods, grouping them by their apparent functionality:

    * **Snapshotting:**  Methods like `TakeSnapshot`, `WriteSnapshotToDiskAfterGC`, `TakeSnapshotToFile`, `DeleteAllSnapshots`, `RemoveSnapshot`, `GetSnapshot`, `GetSnapshotsCount`, `IsTakingSnapshot`, and related helper functions like `CopyNameForHeapSnapshot` clearly relate to creating and managing heap snapshots.

    * **Sampling:** `StartSamplingHeapProfiler`, `StopSamplingHeapProfiler`, `GetAllocationProfile` are obviously for sampling heap activity.

    * **Object Tracking:** `StartHeapObjectsTracking`, `StopHeapObjectsTracking`, `PushHeapObjectsStats`, `GetSnapshotObjectId`, `FindHeapObjectById`, `ClearHeapObjectMap`, `ObjectMoveEvent`, `AllocationEvent`, `UpdateObjectSizeEvent`. These deal with tracking individual object allocations and movements.

    * **Embedder Integration:** `AddBuildEmbedderGraphCallback`, `RemoveBuildEmbedderGraphCallback`, `BuildEmbedderGraph`, `SetGetDetachednessCallback`, `GetDetachedness`, `GetDetachedJSWrapperObjects`. This points to the ability for embedders (like Chrome) to integrate their own object information into the heap profiling process.

    * **Utilities:** `MaybeClearStringsStorage`, `heap()`, `isolate()`, `QueryObjects`. These are helper functions for internal management and providing access to core V8 components.

4. **Inferring Functionality from Method Names and Parameters:**  Even without deep knowledge of V8 internals, method names like `TakeSnapshot(options)`, `StartSamplingHeapProfiler(interval, depth)`, and `GetAllocationProfile()` are quite descriptive. The parameters provide further context.

5. **Identifying Connections to JavaScript:**  The presence of `v8::Local<v8::Value>`, `v8::Object`, `Utils::ToLocal`, and the context of detachedness for "JSWrapperObjects" directly links this code to JavaScript objects and their lifecycle within V8. The `QueryObjects` method taking a `v8::QueryObjectPredicate` also strongly suggests interaction with JavaScript object properties.

6. **Checking for `.tq` Extension:** The prompt specifically asks about the `.tq` extension. A quick search within the code for files ending in `.tq` reveals none. This leads to the conclusion that it's not a Torque file.

7. **Generating JavaScript Examples:** Based on the identified functionalities, I brainstorm common scenarios where these features would be used. Taking a snapshot is the most direct example. Sampling can be illustrated with a simple allocation loop. The embedder graph is more abstract but can be exemplified by imagining custom C++ objects held by JavaScript. Detachedness relates to garbage collection and the lifetime of native resources.

8. **Considering Code Logic and Assumptions:**  For the snapshotting process, the code uses a `HeapSnapshotGenerator`. I can infer a likely flow:  create a snapshot object, use a generator to populate it, and then potentially serialize it. The `SetMarkerIfNeededAndCallback` function suggests a need for synchronization or consistent state during the snapshotting process, likely related to garbage collection.

9. **Identifying Common Programming Errors:**  Considering the context of heap profiling, common errors relate to memory management, specifically memory leaks and unexpected object retention. The "detachedness" concept hints at issues where native resources aren't properly released when JavaScript objects are garbage collected. The example with closures and external references fits this scenario.

10. **Structuring the Output:** Finally, I organize the findings into clear sections as requested by the prompt: functionality list, Torque file check, JavaScript examples, code logic inference, and common programming errors. This makes the information easy to understand.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe some methods are for low-level heap manipulation.
* **Correction:**  While it interacts with the heap, the primary purpose is *profiling* and *analysis*, not direct manipulation.

* **Initial thought:**  The embedder graph is highly complex, and I need to understand all its nuances.
* **Correction:** Focus on the *purpose* – allowing external information to be included in the snapshot – rather than the intricate details of its implementation. A simple illustrative example suffices.

* **Initial thought:**  The code might directly handle serialization.
* **Correction:** It uses a `HeapSnapshotJSONSerializer`, indicating a separation of concerns. The core profiler focuses on data collection, and a separate class handles output formatting.

By following this iterative process of skimming, detailed analysis, inference, example generation, and self-correction, I can effectively understand and explain the functionality of the provided C++ code.
好的，让我们来分析一下 `v8/src/profiler/heap-profiler.cc` 这个 V8 源代码文件的功能。

**文件功能概述**

`v8/src/profiler/heap-profiler.cc` 文件实现了 V8 引擎的 **堆快照（Heap Snapshot）** 和 **抽样堆分析（Sampling Heap Profiling）** 功能。它允许开发者捕获 JavaScript 堆在特定时刻的状态，并分析内存分配情况，帮助识别内存泄漏和性能瓶颈。

**具体功能点列举**

1. **堆快照 (Heap Snapshot):**
   - **创建堆快照：**  `TakeSnapshot` 方法负责生成堆的快照。它可以配置不同的选项，例如快照模式（`HeapSnapshotMode`）和数值模式（`numerics_mode`）。
   - **将快照写入文件：** `TakeSnapshotToFile` 方法将生成的堆快照序列化为 JSON 格式并写入指定的文件。
   - **在 GC 后写入快照：** `WriteSnapshotToDiskAfterGC` 方法在垃圾回收完成后自动生成并保存堆快照。
   - **管理多个快照：**  使用 `snapshots_` 成员变量存储已生成的快照，并提供 `DeleteAllSnapshots` 和 `RemoveSnapshot` 方法进行管理。
   - **获取快照信息：** 提供 `GetSnapshotsCount` 和 `GetSnapshot` 方法来获取快照的数量和指定索引的快照对象。
   - **获取对象 ID：** `GetSnapshotObjectId` 方法根据 V8 对象或原生对象获取其在快照中的唯一 ID。
   - **根据 ID 查找对象：** `FindHeapObjectById` 方法根据快照中的 ID 查找对应的 V8 堆对象。

2. **抽样堆分析 (Sampling Heap Profiling):**
   - **启动抽样分析：** `StartSamplingHeapProfiler` 方法启动抽样堆分析器，可以设置采样间隔和堆栈深度。
   - **停止抽样分析：** `StopSamplingHeapProfiler` 方法停止抽样堆分析器。
   - **获取分配 Profile：** `GetAllocationProfile` 方法返回一个 `v8::AllocationProfile` 对象，其中包含抽样分析收集的分配信息。

3. **堆对象追踪 (Heap Object Tracking):**
   - **开始追踪：** `StartHeapObjectsTracking` 方法开始追踪堆对象的分配和移动。可以选择是否追踪详细的分配信息。
   - **停止追踪：** `StopHeapObjectsTracking` 方法停止堆对象追踪。
   - **推送堆对象统计信息：** `PushHeapObjectsStats` 方法将当前堆对象的统计信息推送到指定的输出流。
   - **对象移动事件处理：** `ObjectMoveEvent` 方法处理堆对象移动的事件，更新内部映射。
   - **分配事件处理：** `AllocationEvent` 方法处理堆对象分配的事件，记录分配信息。
   - **更新对象大小事件处理：** `UpdateObjectSizeEvent` 方法处理堆对象大小更新的事件。
   - **清除对象映射：** `ClearHeapObjectMap` 方法清除内部用于跟踪堆对象的映射。

4. **与 Embedder 集成 (Embedder Integration):**
   - **添加/移除 Embedder Graph 回调：** `AddBuildEmbedderGraphCallback` 和 `RemoveBuildEmbedderGraphCallback` 方法允许外部代码注册回调函数，以便在生成堆快照时构建自定义的 Embedder Graph。
   - **构建 Embedder Graph：** `BuildEmbedderGraph` 方法调用已注册的回调函数来构建 Embedder Graph。
   - **设置/获取 Detachedness 回调：** `SetGetDetachednessCallback` 和 `GetDetachedness` 方法允许外部代码提供判断对象是否“分离”（detached）的回调函数。分离的对象通常指的是原生对象的包装器，其原生资源已被释放。
   - **获取分离的 JS 包装器对象：** `GetDetachedJSWrapperObjects` 方法查找并返回所有分离的 JavaScript 包装器对象。

5. **其他辅助功能:**
   - **管理字符串存储：** 使用 `StringsStorage` 来存储快照中使用的字符串，以避免重复存储。
   - **查询对象：** `QueryObjects` 方法允许用户通过谓词函数查询堆中的对象。

**关于文件扩展名 `.tq`**

`v8/src/profiler/heap-profiler.cc` 的扩展名是 `.cc`，这表明它是一个 **C++ 源代码文件**。`.tq` 扩展名用于 V8 的 **Torque** 语言，Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。因此，`v8/src/profiler/heap-profiler.cc` 不是一个 Torque 源代码文件。

**与 JavaScript 的关系及示例**

`v8/src/profiler/heap-profiler.cc` 提供的功能直接与 JavaScript 的内存管理和性能分析相关。开发者可以使用 V8 提供的 Profiler API（通常在 Node.js 的 `v8` 模块中暴露）来触发这些功能。

**JavaScript 示例：获取堆快照**

```javascript
const v8 = require('v8');
const fs = require('fs');

// 启动堆快照
const snapshot1 = v8.getHeapSnapshot();

// ... 执行一些 JavaScript 代码，分配一些内存 ...

// 再次获取堆快照
const snapshot2 = v8.getHeapSnapshot();

// 将快照写入文件
const fileName1 = 'heap-snapshot-1.heapsnapshot';
const fileStream1 = fs.createWriteStream(fileName1);
snapshot1.pipe(fileStream1);

const fileName2 = 'heap-snapshot-2.heapsnapshot';
const fileStream2 = fs.createWriteStream(fileName2);
snapshot2.pipe(fileStream2);

console.log(`Heap snapshots written to ${fileName1} and ${fileName2}`);
```

**JavaScript 示例：启动抽样堆分析**

```javascript
const v8 = require('v8');

// 启动抽样堆分析，采样间隔 1000 微秒，堆栈深度 10
v8.startSamplingHeapProfiling('profile', 1000, 10);

// ... 执行一些 JavaScript 代码，进行内存分配 ...

// 停止抽样堆分析
const profile = v8.stopSamplingHeapProfiling('profile');

// profile 对象包含了内存分配的抽样信息，可以进一步分析
console.log(profile);
```

**代码逻辑推理及假设输入输出**

假设我们调用 `TakeSnapshot` 方法，并且堆中存在一些 JavaScript 对象。

**假设输入：**

- V8 引擎的堆中包含以下对象：
    - 一个字符串 "hello"
    - 一个包含数字 `[1, 2, 3]` 的数组
    - 一个用户自定义的对象 `{ a: 1, b: "test" }`
- `TakeSnapshot` 方法被调用，使用默认的 `HeapSnapshotOptions`。

**可能输出（堆快照的一部分，简化表示）：**

快照数据通常是 JSON 格式，包含节点（对象）和边（引用关系）。

```json
{
  "nodes": [
    // ... 其他节点 ...
    { "id": 10, "type": "string", "name": "hello", "self_size": 10 },
    { "id": 15, "type": "array", "name": "Array", "self_size": 24 },
    { "id": 20, "type": "object", "name": "Object", "self_size": 16 }
    // ... 其他节点 ...
  ],
  "edges": [
    // ... 其他边 ...
    { "type": "property", "name_or_index": 0, "from_node": 15, "to_node": /* 指向数字 1 的节点 ID */ },
    { "type": "property", "name_or_index": 1, "from_node": 15, "to_node": /* 指向数字 2 的节点 ID */ },
    { "type": "property", "name_or_index": 2, "from_node": 15, "to_node": /* 指向数字 3 的节点 ID */ },
    { "type": "property", "name_or_index": "a", "from_node": 20, "to_node": /* 指向数字 1 的节点 ID */ },
    { "type": "property", "name_or_index": "b", "from_node": 20, "to_node": 10 } // 指向字符串 "hello" 的节点 ID
    // ... 其他边 ...
  ]
}
```

**涉及用户常见的编程错误**

`v8/src/profiler/heap-profiler.cc` 的功能旨在帮助开发者发现与内存相关的编程错误，例如：

1. **内存泄漏（Memory Leaks）：**
   - **错误示例：** 在 JavaScript 中创建了对象，但忘记释放对其的引用，导致垃圾回收器无法回收这些对象，最终导致内存占用持续增加。

     ```javascript
     let leakedObjects = [];
     setInterval(() => {
       let obj = { data: new Array(10000).fill('large') };
       leakedObjects.push(obj); // 忘记释放引用
     }, 100);
     ```

   - **如何通过 Heap Profiler 发现：** 通过对比多次堆快照，可以看到某些类型的对象实例数量持续增加，并且这些对象没有被回收。

2. **意外的对象保留（Unintended Object Retention）：**
   - **错误示例：**  闭包不小心捕获了不需要的大型对象，导致这些对象在预期之外被保留在内存中。

     ```javascript
     function createCounter() {
       let largeData = new Array(100000).fill('big');
       let count = 0;
       return function() {
         count++;
         console.log(largeData.length); // 意外地捕获了 largeData
         return count;
       };
     }

     const counter = createCounter();
     counter();
     ```

   - **如何通过 Heap Profiler 发现：** 堆快照会显示 `largeData` 仍然被 `counter` 函数的作用域链引用，即使它可能不再需要。

3. **DOM 泄漏（DOM Leaks）：**
   - **错误示例：**  JavaScript 代码持有对已从 DOM 树中移除的 DOM 元素的引用，导致浏览器无法回收这些元素占用的内存。

     ```javascript
     let detachedElement;
     const button = document.getElementById('myButton');
     button.addEventListener('click', () => {
       detachedElement = document.getElementById('someElement');
       document.body.removeChild(detachedElement);
     });
     // detachedElement 仍然持有对已移除元素的引用
     ```

   - **如何通过 Heap Profiler 发现：**  在堆快照中查找 detached 的 DOM 元素节点，这些节点本应被回收。

4. **原生资源泄漏（Native Resource Leaks）：**
   - **错误示例：**  在 Node.js 中，如果 JavaScript 代码创建了与原生资源（如文件句柄、网络连接等）关联的对象，但忘记显式释放这些资源，即使 JavaScript 对象被回收，原生资源可能仍然泄漏。

   - **如何通过 Heap Profiler 发现：**  结合 Embedder Graph 的功能，可以追踪到 JavaScript 对象与原生资源的关联，并发现哪些原生资源没有被正确释放。`GetDetachedJSWrapperObjects` 方法可以帮助识别这类问题。

总结来说，`v8/src/profiler/heap-profiler.cc` 是 V8 引擎中负责堆分析的核心组件，它提供了强大的工具来帮助开发者理解 JavaScript 程序的内存使用情况，并诊断和修复与内存相关的错误。

### 提示词
```
这是目录为v8/src/profiler/heap-profiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/profiler/heap-profiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2009-2010 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/profiler/heap-profiler.h"

#include <fstream>
#include <optional>

#include "include/v8-profiler.h"
#include "src/api/api-inl.h"
#include "src/debug/debug.h"
#include "src/heap/combined-heap.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/profiler/allocation-tracker.h"
#include "src/profiler/heap-snapshot-generator-inl.h"
#include "src/profiler/sampling-heap-profiler.h"

namespace v8::internal {

HeapProfiler::HeapProfiler(Heap* heap)
    : ids_(new HeapObjectsMap(heap)),
      names_(new StringsStorage()),
      is_tracking_object_moves_(false),
      is_taking_snapshot_(false) {}

HeapProfiler::~HeapProfiler() = default;

void HeapProfiler::DeleteAllSnapshots() {
  snapshots_.clear();
  MaybeClearStringsStorage();
}

void HeapProfiler::MaybeClearStringsStorage() {
  if (snapshots_.empty() && !sampling_heap_profiler_ && !allocation_tracker_ &&
      !is_taking_snapshot_) {
    names_.reset(new StringsStorage());
  }
}

void HeapProfiler::RemoveSnapshot(HeapSnapshot* snapshot) {
  snapshots_.erase(
      std::find_if(snapshots_.begin(), snapshots_.end(),
                   [&](const std::unique_ptr<HeapSnapshot>& entry) {
                     return entry.get() == snapshot;
                   }));
}

std::vector<v8::Local<v8::Value>> HeapProfiler::GetDetachedJSWrapperObjects() {
  heap()->CollectAllAvailableGarbage(GarbageCollectionReason::kHeapProfiler);

  std::vector<v8::Local<v8::Value>> js_objects_found;
  HeapObjectIterator iterator(heap());
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    if (HeapLayout::InCodeSpace(obj)) continue;
    if (!IsJSApiWrapperObject(obj)) continue;
    // Ensure object is wrappable, otherwise GetDetachedness() can crash
    JSApiWrapper wrapper = JSApiWrapper(Cast<JSObject>(obj));
    if (!wrapper.GetCppHeapWrappable(isolate(), kAnyCppHeapPointer)) continue;

    v8::Local<v8::Value> data(
        Utils::ToLocal(handle(Cast<JSObject>(obj), isolate())));
    v8::EmbedderGraph::Node::Detachedness detachedness =
        GetDetachedness(data, 0);

    if (detachedness != v8::EmbedderGraph::Node::Detachedness::kDetached)
      continue;

    js_objects_found.push_back(data);
  }

  return js_objects_found;
}

void HeapProfiler::AddBuildEmbedderGraphCallback(
    v8::HeapProfiler::BuildEmbedderGraphCallback callback, void* data) {
  build_embedder_graph_callbacks_.push_back({callback, data});
}

void HeapProfiler::RemoveBuildEmbedderGraphCallback(
    v8::HeapProfiler::BuildEmbedderGraphCallback callback, void* data) {
  auto it = std::find(build_embedder_graph_callbacks_.begin(),
                      build_embedder_graph_callbacks_.end(),
                      std::make_pair(callback, data));
  if (it != build_embedder_graph_callbacks_.end())
    build_embedder_graph_callbacks_.erase(it);
}

void HeapProfiler::BuildEmbedderGraph(Isolate* isolate,
                                      v8::EmbedderGraph* graph) {
  for (const auto& cb : build_embedder_graph_callbacks_) {
    cb.first(reinterpret_cast<v8::Isolate*>(isolate), graph, cb.second);
  }
}

void HeapProfiler::SetGetDetachednessCallback(
    v8::HeapProfiler::GetDetachednessCallback callback, void* data) {
  get_detachedness_callback_ = {callback, data};
}

v8::EmbedderGraph::Node::Detachedness HeapProfiler::GetDetachedness(
    const v8::Local<v8::Value> v8_value, uint16_t class_id) {
  DCHECK(HasGetDetachednessCallback());
  return get_detachedness_callback_.first(
      reinterpret_cast<v8::Isolate*>(heap()->isolate()), v8_value, class_id,
      get_detachedness_callback_.second);
}

const char* HeapProfiler::CopyNameForHeapSnapshot(const char* name) {
  CHECK(is_taking_snapshot_);
  return names_->GetCopy(name);
}

HeapSnapshot* HeapProfiler::TakeSnapshot(
    const v8::HeapProfiler::HeapSnapshotOptions options) {
  is_taking_snapshot_ = true;
  HeapSnapshot* result =
      new HeapSnapshot(this, options.snapshot_mode, options.numerics_mode);

  // We need a stack marker here to allow deterministic passes over the stack.
  // The garbage collection and the filling of references in GenerateSnapshot
  // should scan the same part of the stack.
  heap()->stack().SetMarkerIfNeededAndCallback([this, &options, &result]() {
    std::optional<CppClassNamesAsHeapObjectNameScope> use_cpp_class_name;
    if (result->expose_internals() && heap()->cpp_heap()) {
      use_cpp_class_name.emplace(heap()->cpp_heap());
    }

    HeapSnapshotGenerator generator(result, options.control,
                                    options.global_object_name_resolver, heap(),
                                    options.stack_state);
    if (!generator.GenerateSnapshot()) {
      delete result;
      result = nullptr;
    } else {
      snapshots_.emplace_back(result);
    }
  });
  ids_->RemoveDeadEntries();
  if (native_move_listener_) {
    native_move_listener_->StartListening();
  }
  is_tracking_object_moves_ = true;
  heap()->isolate()->UpdateLogObjectRelocation();
  is_taking_snapshot_ = false;

  return result;
}

class FileOutputStream : public v8::OutputStream {
 public:
  explicit FileOutputStream(const char* filename) : os_(filename) {}
  ~FileOutputStream() override { os_.close(); }

  WriteResult WriteAsciiChunk(char* data, int size) override {
    os_.write(data, size);
    return kContinue;
  }

  void EndOfStream() override { os_.close(); }

 private:
  std::ofstream os_;
};

// Precondition: only call this if you have just completed a full GC cycle.
void HeapProfiler::WriteSnapshotToDiskAfterGC(HeapSnapshotMode snapshot_mode) {
  // We need to set a stack marker for the stack walk performed by the
  // snapshot generator to work.
  heap()->stack().SetMarkerIfNeededAndCallback([this, snapshot_mode]() {
    int64_t time = V8::GetCurrentPlatform()->CurrentClockTimeMilliseconds();
    std::string filename = "v8-heap-" + std::to_string(time) + ".heapsnapshot";
    v8::HeapProfiler::HeapSnapshotOptions options;
    std::unique_ptr<HeapSnapshot> result(
        new HeapSnapshot(this, snapshot_mode, options.numerics_mode));
    HeapSnapshotGenerator generator(result.get(), options.control,
                                    options.global_object_name_resolver, heap(),
                                    options.stack_state);
    if (!generator.GenerateSnapshotAfterGC()) return;
    FileOutputStream stream(filename.c_str());
    HeapSnapshotJSONSerializer serializer(result.get());
    serializer.Serialize(&stream);
    PrintF("Wrote heap snapshot to %s.\n", filename.c_str());
  });
}

void HeapProfiler::TakeSnapshotToFile(
    const v8::HeapProfiler::HeapSnapshotOptions options, std::string filename) {
  HeapSnapshot* snapshot = TakeSnapshot(options);
  FileOutputStream stream(filename.c_str());
  HeapSnapshotJSONSerializer serializer(snapshot);
  serializer.Serialize(&stream);
}

bool HeapProfiler::StartSamplingHeapProfiler(
    uint64_t sample_interval, int stack_depth,
    v8::HeapProfiler::SamplingFlags flags) {
  if (sampling_heap_profiler_) return false;
  sampling_heap_profiler_.reset(new SamplingHeapProfiler(
      heap(), names_.get(), sample_interval, stack_depth, flags));
  return true;
}

void HeapProfiler::StopSamplingHeapProfiler() {
  sampling_heap_profiler_.reset();
  MaybeClearStringsStorage();
}

v8::AllocationProfile* HeapProfiler::GetAllocationProfile() {
  if (sampling_heap_profiler_) {
    return sampling_heap_profiler_->GetAllocationProfile();
  } else {
    return nullptr;
  }
}

void HeapProfiler::StartHeapObjectsTracking(bool track_allocations) {
  ids_->UpdateHeapObjectsMap();
  if (native_move_listener_) {
    native_move_listener_->StartListening();
  }
  is_tracking_object_moves_ = true;
  heap()->isolate()->UpdateLogObjectRelocation();
  DCHECK(!allocation_tracker_);
  if (track_allocations) {
    allocation_tracker_.reset(new AllocationTracker(ids_.get(), names_.get()));
    heap()->AddHeapObjectAllocationTracker(this);
  }
}

SnapshotObjectId HeapProfiler::PushHeapObjectsStats(OutputStream* stream,
                                                    int64_t* timestamp_us) {
  return ids_->PushHeapObjectsStats(stream, timestamp_us);
}

void HeapProfiler::StopHeapObjectsTracking() {
  ids_->StopHeapObjectsTracking();
  if (allocation_tracker_) {
    allocation_tracker_.reset();
    MaybeClearStringsStorage();
    heap()->RemoveHeapObjectAllocationTracker(this);
  }
}

int HeapProfiler::GetSnapshotsCount() const {
  return static_cast<int>(snapshots_.size());
}

bool HeapProfiler::IsTakingSnapshot() const { return is_taking_snapshot_; }

HeapSnapshot* HeapProfiler::GetSnapshot(int index) {
  return snapshots_.at(index).get();
}

SnapshotObjectId HeapProfiler::GetSnapshotObjectId(DirectHandle<Object> obj) {
  if (!IsHeapObject(*obj)) return v8::HeapProfiler::kUnknownObjectId;
  return ids_->FindEntry(Cast<HeapObject>(*obj).address());
}

SnapshotObjectId HeapProfiler::GetSnapshotObjectId(NativeObject obj) {
  // Try to find id of regular native node first.
  SnapshotObjectId id = ids_->FindEntry(reinterpret_cast<Address>(obj));
  // In case no id has been found, check whether there exists an entry where the
  // native objects has been merged into a V8 entry.
  if (id == v8::HeapProfiler::kUnknownObjectId) {
    id = ids_->FindMergedNativeEntry(obj);
  }
  return id;
}

void HeapProfilerNativeMoveListener::ObjectMoveEvent(Address from, Address to,
                                                     int size) {
  profiler_->ObjectMoveEvent(from, to, size, /*is_native_object=*/true);
}

void HeapProfiler::ObjectMoveEvent(Address from, Address to, int size,
                                   bool is_native_object) {
  base::MutexGuard guard(&profiler_mutex_);
  bool known_object = ids_->MoveObject(from, to, size);
  if (!known_object && allocation_tracker_ && !is_native_object) {
    allocation_tracker_->address_to_trace()->MoveObject(from, to, size);
  }
}

void HeapProfiler::AllocationEvent(Address addr, int size) {
  DisallowGarbageCollection no_gc;
  if (allocation_tracker_) {
    allocation_tracker_->AllocationEvent(addr, size);
  }
}

void HeapProfiler::UpdateObjectSizeEvent(Address addr, int size) {
  ids_->UpdateObjectSize(addr, size);
}

Handle<HeapObject> HeapProfiler::FindHeapObjectById(SnapshotObjectId id) {
  CombinedHeapObjectIterator iterator(heap(),
                                      HeapObjectIterator::kFilterUnreachable);
  // Make sure that the object with the given id is still reachable.
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    if (ids_->FindEntry(obj.address()) == id)
      return Handle<HeapObject>(obj, isolate());
  }
  return Handle<HeapObject>();
}

void HeapProfiler::ClearHeapObjectMap() {
  ids_.reset(new HeapObjectsMap(heap()));
  if (!allocation_tracker_) {
    if (native_move_listener_) {
      native_move_listener_->StopListening();
    }
    is_tracking_object_moves_ = false;
    heap()->isolate()->UpdateLogObjectRelocation();
  }
}

Heap* HeapProfiler::heap() const { return ids_->heap(); }

Isolate* HeapProfiler::isolate() const { return heap()->isolate(); }

void HeapProfiler::QueryObjects(DirectHandle<Context> context,
                                v8::QueryObjectPredicate* predicate,
                                std::vector<v8::Global<v8::Object>>* objects) {
  // We need a stack marker here to allow deterministic passes over the stack.
  // The garbage collection and the two object heap iterators should scan the
  // same part of the stack.
  heap()->stack().SetMarkerIfNeededAndCallback([this, predicate, objects]() {
    {
      HandleScope handle_scope(isolate());
      std::vector<Handle<JSTypedArray>> on_heap_typed_arrays;
      CombinedHeapObjectIterator heap_iterator(
          heap(), HeapObjectIterator::kFilterUnreachable);
      for (Tagged<HeapObject> heap_obj = heap_iterator.Next();
           !heap_obj.is_null(); heap_obj = heap_iterator.Next()) {
        if (IsFeedbackVector(heap_obj)) {
          Cast<FeedbackVector>(heap_obj)->ClearSlots(isolate());
        } else if (IsJSTypedArray(heap_obj) &&
                   Cast<JSTypedArray>(heap_obj)->is_on_heap()) {
          // Cannot call typed_array->GetBuffer() here directly because it may
          // trigger GC. Defer that call by collecting the object in a vector.
          on_heap_typed_arrays.push_back(
              handle(Cast<JSTypedArray>(heap_obj), isolate()));
        }
      }
      for (auto& typed_array : on_heap_typed_arrays) {
        // Convert the on-heap typed array into off-heap typed array, so that
        // its ArrayBuffer becomes valid and can be returned in the result.
        typed_array->GetBuffer();
      }
    }
    // We should return accurate information about live objects, so we need to
    // collect all garbage first.
    heap()->CollectAllAvailableGarbage(GarbageCollectionReason::kHeapProfiler);
    CombinedHeapObjectIterator heap_iterator(
        heap(), HeapObjectIterator::kFilterUnreachable);
    PtrComprCageBase cage_base(isolate());
    for (Tagged<HeapObject> heap_obj = heap_iterator.Next();
         !heap_obj.is_null(); heap_obj = heap_iterator.Next()) {
      if (!IsJSObject(heap_obj, cage_base) ||
          IsJSExternalObject(heap_obj, cage_base))
        continue;
      v8::Local<v8::Object> v8_obj(
          Utils::ToLocal(handle(Cast<JSObject>(heap_obj), isolate())));
      if (!predicate->Filter(v8_obj)) continue;
      objects->emplace_back(reinterpret_cast<v8::Isolate*>(isolate()), v8_obj);
    }
  });
}

}  // namespace v8::internal
```