Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/profiler/heap-snapshot-generator.cc`. I need to break down the code into logical sections, explain what each section does, and identify any connections to JavaScript functionality.

Here's a plan:
1. **Identify the main classes and their roles**:  `HeapSnapshotGenerator` and `HeapSnapshotJSONSerializer` seem to be the key players.
2. **Analyze `HeapSnapshotGenerator` methods**:
    - `hot()`: This looks like the main function to generate a heap snapshot.
    - `GenerateSnapshotAfterGC()`: A variation of `hot()` likely used after garbage collection.
    - `ProgressStep()` and `ProgressReport()`:  Related to reporting progress during snapshot generation.
    - `InitProgressCounter()`: Initializes the progress tracking.
    - `FillReferences()`:  Extracts references between objects in the heap.
3. **Analyze `HeapSnapshotJSONSerializer` methods**:
    - `Serialize()` and `SerializeImpl()`:  Responsible for serializing the heap snapshot data into JSON format.
    - `GetStringId()`:  Manages a cache of strings for efficient serialization.
    - `SerializeEdge()`, `SerializeEdges()`, `SerializeNode()`, `SerializeNodes()`: Serialize the graph structure (nodes and edges).
    - `SerializeSnapshot()`: Serializes metadata about the snapshot.
    - `SerializeTraceTree()`, `SerializeTraceNode()`, `SerializeTraceNodeInfos()`: Serialize allocation tracking information.
    - `SerializeSamples()`: Serializes information about when objects were allocated.
    - `SerializeStrings()`: Serializes the string table.
    - `SerializeLocation()`, `SerializeLocations()`: Serializes source code location information.
4. **Check for Torque**: The filename ends with `.cc`, so it's not a Torque file.
5. **Identify JavaScript connections**: Heap snapshots are used in JavaScript debugging and profiling.
6. **Provide JavaScript examples**: Demonstrate how heap snapshots are triggered and used in a JavaScript context.
7. **Look for code logic and infer inputs/outputs**:  For methods like `hot()` and `Serialize()`, the input is the internal state of the V8 heap, and the output is a heap snapshot in a specific format (likely JSON).
8. **Identify common programming errors**:  Although the C++ code itself doesn't directly relate to user JavaScript errors, the process of taking and analyzing heap snapshots helps developers debug memory leaks and other performance issues.
9. **Summarize the functionality**: Provide a concise overview of the file's purpose.
`v8/src/profiler/heap-snapshot-generator.cc` 是 V8 引擎中负责生成堆快照的 C++ 源代码文件。

**主要功能:**

该文件的主要功能是**生成 V8 堆的快照，用于内存分析和性能调试**。它遍历堆中的对象，记录它们之间的引用关系，并将这些信息序列化成特定的格式（通常是 JSON），以便开发者工具（如 Chrome DevTools）或其他分析工具进行分析。

**功能分解:**

1. **`HeapSnapshotGenerator` 类:**
   - **`hot()` 方法:** 这是生成堆快照的主要入口点。
     - 它首先启动一个计时器来衡量快照生成的时间。
     - 进入安全点，确保在快照过程中不会发生重要的堆变化。
     - 收集临时全局对象的标签。
     - 强制执行一次垃圾回收 (`heap_->CollectAllAvailableGarbage`)，以便在快照中包含已清除但尚未完全释放的对象的信息。
     - 禁止在接下来的操作中触发垃圾回收，以保证快照的一致性。
     - 设置一个空上下文，这可能与快照的特定需求有关。
     - 创建全局对象标签的映射。
     - 初始化进度计数器。
     - 添加一些人为创建的根节点到快照中，这些根节点不是实际的堆对象，但有助于理解引用关系。
     - 填充对象的行尾信息。
     - **调用 `FillReferences()` 来遍历堆并提取对象之间的引用关系。** 这是生成快照的核心步骤。
     - 填充子节点的引用信息。
     - 记录最后一个 JavaScript 对象的 ID。
     - 更新进度计数器。
     - 如果启用了堆快照分析的标志，则打印生成快照所用的时间。
     - 报告快照生成的进度。
   - **`GenerateSnapshotAfterGC()` 方法:**  这个方法与 `hot()` 类似，但它假设已经执行了垃圾回收，因此不需要再次执行。它跳过了垃圾回收和进度报告的步骤，专注于提取引用和构建快照结构。
   - **`ProgressStep()` 方法:** 用于增加快照生成过程的进度计数器，以便向用户界面报告进度。它确保在最终完成之前不会报告完成状态。
   - **`ProgressReport()` 方法:**  根据一定的粒度或强制要求，向用户界面报告当前的快照生成进度。
   - **`InitProgressCounter()` 方法:**  初始化进度计数器，估计堆中对象的总数。
   - **`FillReferences()` 方法:**  **这是核心方法，用于遍历 V8 堆和 DOM 树（如果有），并提取对象之间的引用关系。** 它使用 `v8_heap_explorer_` 和 `dom_explorer_` 对象来完成这个任务。
   - **成员变量:** 包含堆信息、快照对象、进度控制等。

2. **`HeapSnapshotJSONSerializer` 类:**
   - **`Serialize()` 方法:**  序列化堆快照到指定的输出流。它也负责测量序列化所用的时间。
   - **`SerializeImpl()` 方法:**  实际执行 JSON 序列化的方法。它按照预定义的 JSON 结构，将快照的元数据、节点、边、跟踪信息、采样信息、位置信息和字符串等数据写入输出流。
   - **`GetStringId()` 方法:**  维护一个字符串缓存，用于避免重复序列化相同的字符串，提高效率。
   - **`SerializeEdge()` 和 `SerializeEdges()` 方法:**  序列化对象之间的引用关系（边）。每条边包含类型、名称或索引以及目标节点的 ID。
   - **`SerializeNode()` 和 `SerializeNodes()` 方法:**  序列化堆中的对象（节点）。每个节点包含类型、名称、ID、自身大小、子节点数量、跟踪节点 ID 和分离状态等信息。
   - **`SerializeSnapshot()` 方法:**  序列化快照的元数据，包括节点和边的字段定义、类型定义以及计数信息。
   - **`SerializeTraceTree()`, `SerializeTraceNode()`, `SerializeTraceNodeInfos()` 方法:** 序列化分配跟踪信息，这允许开发者查看对象的分配调用栈。
   - **`SerializeSamples()` 方法:** 序列化堆中对象的采样信息，记录了对象分配的时间戳和 ID。
   - **`SerializeStrings()` 方法:**  序列化所有在快照中用到的字符串。
   - **`SerializeLocation()` 和 `SerializeLocations()` 方法:** 序列化对象的源代码位置信息。
   - **成员变量:**  包含快照数据、输出流写入器、字符串缓存等。

**关于 Torque:**

根据您的描述，如果 `v8/src/profiler/heap-snapshot-generator.cc` 以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码文件。由于它以 `.cc` 结尾，所以它是一个 **C++** 源代码文件，而不是 Torque 文件。

**与 JavaScript 的关系:**

`heap-snapshot-generator.cc` 的功能与 JavaScript 的性能调试密切相关。在 Chrome DevTools 中，当你执行 "Take heap snapshot" 时，V8 引擎就会调用类似这里的代码来生成当前的堆快照。这个快照随后会被 DevTools 解析和展示，帮助开发者分析内存使用情况、查找内存泄漏等问题。

**JavaScript 示例:**

虽然你不能直接在 JavaScript 中调用 `heap-snapshot-generator.cc` 中的 C++ 代码，但你可以通过 Chrome DevTools 触发堆快照的生成，这在底层会使用到这些代码。

```javascript
// 在 Chrome DevTools 的 "Memory" 面板中点击 "Take heap snapshot" 按钮

// 或者，在代码中使用 console.profile() 和 console.profileEnd() 可以生成性能分析文件，
// 其中也可能包含堆快照信息（取决于具体的配置和分析类型）。
console.profile('My Profile');
// ... 你的 JavaScript 代码 ...
console.profileEnd('My Profile');
```

当你在 DevTools 中查看堆快照时，你看到的信息（例如对象类型、大小、引用关系等）就是由 `heap-snapshot-generator.cc` 生成并序列化的。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**  一个包含各种 JavaScript 对象（包括普通对象、数组、字符串、函数等）的 V8 堆。

**`hot()` 方法的输出:**
- **成功时:** 返回 `true`，并且内部的 `snapshot_` 成员变量将被填充，包含堆中所有对象及其引用关系的完整表示。
- **失败时:** 返回 `false`，可能由于内存分配失败或其他错误导致。

**`Serialize()` 方法的输出:**
- 一个符合特定 JSON 格式的字符串流，其中包含了堆快照的所有信息。这个 JSON 结构包括：
    - `snapshot`:  元数据，描述了节点和边的结构。
    - `nodes`:  一个数组，包含堆中所有对象的详细信息。
    - `edges`:  一个数组，包含对象之间的引用关系。
    - `trace_function_infos`:  一个数组，包含函数调用的信息，用于分配跟踪。
    - `trace_tree`:  一个表示分配调用树的数组。
    - `samples`:  一个数组，包含对象分配的时间戳和 ID。
    - `locations`:  一个数组，包含对象的源代码位置信息。
    - `strings`:  一个数组，包含所有在快照中用到的字符串。

**涉及用户常见的编程错误:**

虽然 `heap-snapshot-generator.cc` 本身不处理用户的 JavaScript 代码错误，但它生成的堆快照可以帮助开发者诊断由 JavaScript 代码引起的常见编程错误，例如：

1. **内存泄漏:**  通过比较不同时间点的堆快照，可以发现不再被引用的对象仍然存在于堆中，这通常是内存泄漏的迹象。例如，忘记移除事件监听器或闭包意外捕获了大量资源。

   ```javascript
   // 潜在的内存泄漏示例
   let largeData = [];
   function createLeak() {
     let element = document.createElement('div');
     element.onclick = function() {
       largeData.push(new Array(10000).fill('some data')); // 闭包捕获了 largeData
     };
     document.body.appendChild(element);
   }

   createLeak(); // 每次调用 createLeak 都会增加 largeData 的大小，即使 div 被移除。
   ```

2. **意外的全局变量:**  全局变量会一直存在于堆中，如果意外创建了全局变量，可能会占用不必要的内存。

   ```javascript
   function myFunction() {
     // 忘记使用 var/let/const，意外创建了全局变量 myGlobal
     myGlobal = 'This is a global variable';
   }
   myFunction();
   ```

3. **大量缓存或数据积累:**  如果程序中缓存了大量数据但没有及时清理，或者数据结构不断增长而没有限制，会导致内存占用过高。

   ```javascript
   let cache = {};
   function fetchData(key) {
     if (!cache[key]) {
       cache[key] = new Array(10000).fill('cached data for ' + key);
     }
     return cache[key];
   }

   for (let i = 0; i < 1000; i++) {
     fetchData('item_' + i); // cache 会不断增长
   }
   ```

**归纳一下它的功能 (作为第 5 部分的总结):**

`v8/src/profiler/heap-snapshot-generator.cc` 是 V8 引擎中**至关重要的组件**，负责**生成当前 JavaScript 堆的详细快照**。这个过程包括遍历堆中的所有对象，记录它们的类型、大小、引用关系以及其他元数据（如分配跟踪信息和源代码位置）。最终，这些信息被序列化成 JSON 格式，供开发者工具或其他分析工具使用，以帮助开发者**理解 JavaScript 程序的内存使用情况，诊断内存泄漏和性能问题**。它通过 `HeapSnapshotGenerator` 类执行快照的创建和信息提取，并通过 `HeapSnapshotJSONSerializer` 类将这些信息转换为易于解析的 JSON 格式。虽然这是一个 C++ 文件，但它的功能直接服务于 JavaScript 开发者，是 JavaScript 运行时环境的关键组成部分。

### 提示词
```
这是目录为v8/src/profiler/heap-snapshot-generator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/profiler/heap-snapshot-generator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
hot() {
  v8::base::ElapsedTimer timer;
  timer.Start();

  IsolateSafepointScope scope(heap_);

  Isolate* isolate = heap_->isolate();
  auto temporary_global_object_tags =
      v8_heap_explorer_.CollectTemporaryGlobalObjectsTags();

  EmbedderStackStateScope stack_scope(
      heap_, EmbedderStackStateOrigin::kImplicitThroughTask, stack_state_);
  heap_->CollectAllAvailableGarbage(GarbageCollectionReason::kHeapProfiler);

  // No allocation that could trigger GC from here onwards. We cannot use a
  // DisallowGarbageCollection scope as the HeapObjectIterator used during
  // snapshot creation enters a safepoint as well. However, in practice we
  // already enter a safepoint above so that should never trigger a GC.
  DisallowPositionInfoSlow no_position_info_slow;

  NullContextForSnapshotScope null_context_scope(isolate);

  v8_heap_explorer_.MakeGlobalObjectTagMap(
      std::move(temporary_global_object_tags));

  InitProgressCounter();

  snapshot_->AddSyntheticRootEntries();

  v8_heap_explorer_.PopulateLineEnds();
  if (!FillReferences()) return false;

  snapshot_->FillChildren();
  snapshot_->RememberLastJSObjectId();

  progress_counter_ = progress_total_;

  if (i::v8_flags.profile_heap_snapshot) {
    base::OS::PrintError("[Heap snapshot took %0.3f ms]\n",
                         timer.Elapsed().InMillisecondsF());
  }
  timer.Stop();
  if (!ProgressReport(true)) return false;
  return true;
}

bool HeapSnapshotGenerator::GenerateSnapshotAfterGC() {
  // Same as above, but no allocations, no GC run, and no progress report.
  IsolateSafepointScope scope(heap_);
  auto temporary_global_object_tags =
      v8_heap_explorer_.CollectTemporaryGlobalObjectsTags();
  NullContextForSnapshotScope null_context_scope(heap_->isolate());
  v8_heap_explorer_.MakeGlobalObjectTagMap(
      std::move(temporary_global_object_tags));
  snapshot_->AddSyntheticRootEntries();
  v8_heap_explorer_.PopulateLineEnds();
  if (!FillReferences()) return false;
  snapshot_->FillChildren();
  snapshot_->RememberLastJSObjectId();
  return true;
}

void HeapSnapshotGenerator::ProgressStep() {
  // Only increment the progress_counter_ until
  // equal to progress_total -1 == progress_counter.
  // This ensures that intermediate ProgressReport calls will never signal
  // that the work is finished (i.e. progress_counter_ == progress_total_).
  // Only the forced ProgressReport() at the end of GenerateSnapshot() should,
  // after setting progress_counter_ = progress_total_, signal that the
  // work is finished because signalling finished twice
  // breaks the DevTools frontend.
  if (control_ != nullptr && progress_total_ > progress_counter_ + 1) {
    ++progress_counter_;
  }
}

bool HeapSnapshotGenerator::ProgressReport(bool force) {
  const int kProgressReportGranularity = 10000;
  if (control_ != nullptr &&
      (force || progress_counter_ % kProgressReportGranularity == 0)) {
    return control_->ReportProgressValue(progress_counter_, progress_total_) ==
           v8::ActivityControl::kContinue;
  }
  return true;
}

void HeapSnapshotGenerator::InitProgressCounter() {
  if (control_ == nullptr) return;
  progress_total_ = v8_heap_explorer_.EstimateObjectsCount();
  progress_counter_ = 0;
}

bool HeapSnapshotGenerator::FillReferences() {
  return v8_heap_explorer_.IterateAndExtractReferences(this) &&
         dom_explorer_.IterateAndExtractReferences(this);
}

// type, name, id, self_size, edge_count, trace_node_id, detachedness.
const int HeapSnapshotJSONSerializer::kNodeFieldsCountWithTraceNodeId = 7;
const int HeapSnapshotJSONSerializer::kNodeFieldsCountWithoutTraceNodeId = 6;

void HeapSnapshotJSONSerializer::Serialize(v8::OutputStream* stream) {
  v8::base::ElapsedTimer timer;
  timer.Start();
  DCHECK_NULL(writer_);
  writer_ = new OutputStreamWriter(stream);
  trace_function_count_ = 0;
  if (AllocationTracker* tracker =
          snapshot_->profiler()->allocation_tracker()) {
    trace_function_count_ =
        static_cast<uint32_t>(tracker->function_info_list().size());
  }
  SerializeImpl();
  delete writer_;
  writer_ = nullptr;

  if (i::v8_flags.profile_heap_snapshot) {
    base::OS::PrintError("[Serialization of heap snapshot took %0.3f ms]\n",
                         timer.Elapsed().InMillisecondsF());
  }
  timer.Stop();
}

void HeapSnapshotJSONSerializer::SerializeImpl() {
  DCHECK_EQ(0, snapshot_->root()->index());
  writer_->AddCharacter('{');
  writer_->AddString("\"snapshot\":{");
  SerializeSnapshot();
  if (writer_->aborted()) return;
  writer_->AddString("},\n");
  writer_->AddString("\"nodes\":[");
  SerializeNodes();
  if (writer_->aborted()) return;
  writer_->AddString("],\n");
  writer_->AddString("\"edges\":[");
  SerializeEdges();
  if (writer_->aborted()) return;
  writer_->AddString("],\n");

  writer_->AddString("\"trace_function_infos\":[");
  SerializeTraceNodeInfos();
  if (writer_->aborted()) return;
  writer_->AddString("],\n");
  writer_->AddString("\"trace_tree\":[");
  SerializeTraceTree();
  if (writer_->aborted()) return;
  writer_->AddString("],\n");

  writer_->AddString("\"samples\":[");
  SerializeSamples();
  if (writer_->aborted()) return;
  writer_->AddString("],\n");

  writer_->AddString("\"locations\":[");
  SerializeLocations();
  if (writer_->aborted()) return;
  writer_->AddString("],\n");

  writer_->AddString("\"strings\":[");
  SerializeStrings();
  if (writer_->aborted()) return;
  writer_->AddCharacter(']');
  writer_->AddCharacter('}');
  writer_->Finalize();
}

int HeapSnapshotJSONSerializer::GetStringId(const char* s) {
  base::HashMap::Entry* cache_entry =
      strings_.LookupOrInsert(const_cast<char*>(s), StringHash(s));
  if (cache_entry->value == nullptr) {
    cache_entry->value = reinterpret_cast<void*>(next_string_id_++);
  }
  return static_cast<int>(reinterpret_cast<intptr_t>(cache_entry->value));
}

namespace {

template <size_t size>
struct ToUnsigned;

template <>
struct ToUnsigned<1> {
  using Type = uint8_t;
};

template <>
struct ToUnsigned<4> {
  using Type = uint32_t;
};

template <>
struct ToUnsigned<8> {
  using Type = uint64_t;
};

}  // namespace

template <typename T>
static int utoa_impl(T value, base::Vector<char> buffer, int buffer_pos) {
  static_assert(static_cast<T>(-1) > 0);  // Check that T is unsigned
  int number_of_digits = 0;
  T t = value;
  do {
    ++number_of_digits;
  } while (t /= 10);

  buffer_pos += number_of_digits;
  int result = buffer_pos;
  do {
    int last_digit = static_cast<int>(value % 10);
    buffer[--buffer_pos] = '0' + last_digit;
    value /= 10;
  } while (value);
  return result;
}

template <typename T>
static int utoa(T value, base::Vector<char> buffer, int buffer_pos) {
  typename ToUnsigned<sizeof(value)>::Type unsigned_value = value;
  static_assert(sizeof(value) == sizeof(unsigned_value));
  return utoa_impl(unsigned_value, buffer, buffer_pos);
}

void HeapSnapshotJSONSerializer::SerializeEdge(HeapGraphEdge* edge,
                                               bool first_edge) {
  // The buffer needs space for 3 unsigned ints, 3 commas, \n and \0
  static const int kBufferSize =
      MaxDecimalDigitsIn<sizeof(unsigned)>::kUnsigned * 3 + 3 + 2;
  base::EmbeddedVector<char, kBufferSize> buffer;
  int edge_name_or_index = edge->type() == HeapGraphEdge::kElement ||
                                   edge->type() == HeapGraphEdge::kHidden
                               ? edge->index()
                               : GetStringId(edge->name());
  int buffer_pos = 0;
  if (!first_edge) {
    buffer[buffer_pos++] = ',';
  }
  buffer_pos = utoa(edge->type(), buffer, buffer_pos);
  buffer[buffer_pos++] = ',';
  buffer_pos = utoa(edge_name_or_index, buffer, buffer_pos);
  buffer[buffer_pos++] = ',';
  buffer_pos = utoa(to_node_index(edge->to()), buffer, buffer_pos);
  buffer[buffer_pos++] = '\n';
  buffer[buffer_pos++] = '\0';
  writer_->AddString(buffer.begin());
}

void HeapSnapshotJSONSerializer::SerializeEdges() {
  std::vector<HeapGraphEdge*>& edges = snapshot_->children();
  for (size_t i = 0; i < edges.size(); ++i) {
    DCHECK(i == 0 ||
           edges[i - 1]->from()->index() <= edges[i]->from()->index());
    SerializeEdge(edges[i], i == 0);
    if (writer_->aborted()) return;
  }
}

void HeapSnapshotJSONSerializer::SerializeNode(const HeapEntry* entry) {
  // The buffer needs space for 5 unsigned ints, 1 size_t, 1 uint8_t, 7 commas,
  // \n and \0
  static const int kBufferSize =
      5 * MaxDecimalDigitsIn<sizeof(unsigned)>::kUnsigned +
      MaxDecimalDigitsIn<sizeof(size_t)>::kUnsigned +
      MaxDecimalDigitsIn<sizeof(uint8_t)>::kUnsigned + 7 + 1 + 1;
  base::EmbeddedVector<char, kBufferSize> buffer;
  int buffer_pos = 0;
  if (to_node_index(entry) != 0) {
    buffer[buffer_pos++] = ',';
  }
  buffer_pos = utoa(entry->type(), buffer, buffer_pos);
  buffer[buffer_pos++] = ',';
  buffer_pos = utoa(GetStringId(entry->name()), buffer, buffer_pos);
  buffer[buffer_pos++] = ',';
  buffer_pos = utoa(entry->id(), buffer, buffer_pos);
  buffer[buffer_pos++] = ',';
  buffer_pos = utoa(entry->self_size(), buffer, buffer_pos);
  buffer[buffer_pos++] = ',';
  buffer_pos = utoa(entry->children_count(), buffer, buffer_pos);
  buffer[buffer_pos++] = ',';
  if (trace_function_count_) {
    buffer_pos = utoa(entry->trace_node_id(), buffer, buffer_pos);
    buffer[buffer_pos++] = ',';
  } else {
    CHECK_EQ(0, entry->trace_node_id());
  }
  buffer_pos = utoa(entry->detachedness(), buffer, buffer_pos);
  buffer[buffer_pos++] = '\n';
  buffer[buffer_pos++] = '\0';
  writer_->AddString(buffer.begin());
}

void HeapSnapshotJSONSerializer::SerializeNodes() {
  const std::deque<HeapEntry>& entries = snapshot_->entries();
  for (const HeapEntry& entry : entries) {
    SerializeNode(&entry);
    if (writer_->aborted()) return;
  }
}

void HeapSnapshotJSONSerializer::SerializeSnapshot() {
  writer_->AddString("\"meta\":");
  // The object describing node serialization layout.
  // We use a set of macros to improve readability.

  // clang-format off
#define JSON_A(s) "[" s "]"
#define JSON_S(s) "\"" s "\""
  writer_->AddString("{"
    JSON_S("node_fields") ":["
        JSON_S("type") ","
        JSON_S("name") ","
        JSON_S("id") ","
        JSON_S("self_size") ","
        JSON_S("edge_count") ",");
  if (trace_function_count_) writer_->AddString(JSON_S("trace_node_id") ",");
  writer_->AddString(
        JSON_S("detachedness")
    "],"
    JSON_S("node_types") ":" JSON_A(
        JSON_A(
            JSON_S("hidden") ","
            JSON_S("array") ","
            JSON_S("string") ","
            JSON_S("object") ","
            JSON_S("code") ","
            JSON_S("closure") ","
            JSON_S("regexp") ","
            JSON_S("number") ","
            JSON_S("native") ","
            JSON_S("synthetic") ","
            JSON_S("concatenated string") ","
            JSON_S("sliced string") ","
            JSON_S("symbol") ","
            JSON_S("bigint") ","
            JSON_S("object shape")) ","
        JSON_S("string") ","
        JSON_S("number") ","
        JSON_S("number") ","
        JSON_S("number") ","
        JSON_S("number") ","
        JSON_S("number")) ","
    JSON_S("edge_fields") ":" JSON_A(
        JSON_S("type") ","
        JSON_S("name_or_index") ","
        JSON_S("to_node")) ","
    JSON_S("edge_types") ":" JSON_A(
        JSON_A(
            JSON_S("context") ","
            JSON_S("element") ","
            JSON_S("property") ","
            JSON_S("internal") ","
            JSON_S("hidden") ","
            JSON_S("shortcut") ","
            JSON_S("weak")) ","
        JSON_S("string_or_number") ","
        JSON_S("node")) ","
    JSON_S("trace_function_info_fields") ":" JSON_A(
        JSON_S("function_id") ","
        JSON_S("name") ","
        JSON_S("script_name") ","
        JSON_S("script_id") ","
        JSON_S("line") ","
        JSON_S("column")) ","
    JSON_S("trace_node_fields") ":" JSON_A(
        JSON_S("id") ","
        JSON_S("function_info_index") ","
        JSON_S("count") ","
        JSON_S("size") ","
        JSON_S("children")) ","
    JSON_S("sample_fields") ":" JSON_A(
        JSON_S("timestamp_us") ","
        JSON_S("last_assigned_id")) ","
    JSON_S("location_fields") ":" JSON_A(
        JSON_S("object_index") ","
        JSON_S("script_id") ","
        JSON_S("line") ","
        JSON_S("column"))
  "}");
// clang-format on
#undef JSON_S
#undef JSON_A
  writer_->AddString(",\"node_count\":");
  writer_->AddNumber(static_cast<unsigned>(snapshot_->entries().size()));
  writer_->AddString(",\"edge_count\":");
  writer_->AddNumber(static_cast<double>(snapshot_->edges().size()));
  writer_->AddString(",\"trace_function_count\":");
  writer_->AddNumber(trace_function_count_);
}

static void WriteUChar(OutputStreamWriter* w, unibrow::uchar u) {
  static const char hex_chars[] = "0123456789ABCDEF";
  w->AddString("\\u");
  w->AddCharacter(hex_chars[(u >> 12) & 0xF]);
  w->AddCharacter(hex_chars[(u >> 8) & 0xF]);
  w->AddCharacter(hex_chars[(u >> 4) & 0xF]);
  w->AddCharacter(hex_chars[u & 0xF]);
}

void HeapSnapshotJSONSerializer::SerializeTraceTree() {
  AllocationTracker* tracker = snapshot_->profiler()->allocation_tracker();
  if (!tracker) return;
  AllocationTraceTree* traces = tracker->trace_tree();
  SerializeTraceNode(traces->root());
}

void HeapSnapshotJSONSerializer::SerializeTraceNode(AllocationTraceNode* node) {
  // The buffer needs space for 4 unsigned ints, 4 commas, [ and \0
  const int kBufferSize =
      4 * MaxDecimalDigitsIn<sizeof(unsigned)>::kUnsigned + 4 + 1 + 1;
  base::EmbeddedVector<char, kBufferSize> buffer;
  int buffer_pos = 0;
  buffer_pos = utoa(node->id(), buffer, buffer_pos);
  buffer[buffer_pos++] = ',';
  buffer_pos = utoa(node->function_info_index(), buffer, buffer_pos);
  buffer[buffer_pos++] = ',';
  buffer_pos = utoa(node->allocation_count(), buffer, buffer_pos);
  buffer[buffer_pos++] = ',';
  buffer_pos = utoa(node->allocation_size(), buffer, buffer_pos);
  buffer[buffer_pos++] = ',';
  buffer[buffer_pos++] = '[';
  buffer[buffer_pos++] = '\0';
  writer_->AddString(buffer.begin());

  int i = 0;
  for (AllocationTraceNode* child : node->children()) {
    if (i++ > 0) {
      writer_->AddCharacter(',');
    }
    SerializeTraceNode(child);
  }
  writer_->AddCharacter(']');
}

// 0-based position is converted to 1-based during the serialization.
static int SerializePosition(int position, base::Vector<char> buffer,
                             int buffer_pos) {
  if (position == -1) {
    buffer[buffer_pos++] = '0';
  } else {
    DCHECK_GE(position, 0);
    buffer_pos = utoa(static_cast<unsigned>(position + 1), buffer, buffer_pos);
  }
  return buffer_pos;
}

void HeapSnapshotJSONSerializer::SerializeTraceNodeInfos() {
  AllocationTracker* tracker = snapshot_->profiler()->allocation_tracker();
  if (!tracker) return;
  // The buffer needs space for 6 unsigned ints, 6 commas, \n and \0
  const int kBufferSize =
      6 * MaxDecimalDigitsIn<sizeof(unsigned)>::kUnsigned + 6 + 1 + 1;
  base::EmbeddedVector<char, kBufferSize> buffer;
  int i = 0;
  for (AllocationTracker::FunctionInfo* info : tracker->function_info_list()) {
    int buffer_pos = 0;
    if (i++ > 0) {
      buffer[buffer_pos++] = ',';
    }
    buffer_pos = utoa(info->function_id, buffer, buffer_pos);
    buffer[buffer_pos++] = ',';
    buffer_pos = utoa(GetStringId(info->name), buffer, buffer_pos);
    buffer[buffer_pos++] = ',';
    buffer_pos = utoa(GetStringId(info->script_name), buffer, buffer_pos);
    buffer[buffer_pos++] = ',';
    // The cast is safe because script id is a non-negative Smi.
    buffer_pos =
        utoa(static_cast<unsigned>(info->script_id), buffer, buffer_pos);
    buffer[buffer_pos++] = ',';
    buffer_pos = SerializePosition(info->line, buffer, buffer_pos);
    buffer[buffer_pos++] = ',';
    buffer_pos = SerializePosition(info->column, buffer, buffer_pos);
    buffer[buffer_pos++] = '\n';
    buffer[buffer_pos++] = '\0';
    writer_->AddString(buffer.begin());
  }
}

void HeapSnapshotJSONSerializer::SerializeSamples() {
  const std::vector<HeapObjectsMap::TimeInterval>& samples =
      snapshot_->profiler()->heap_object_map()->samples();
  if (samples.empty()) return;
  base::TimeTicks start_time = samples[0].timestamp;
  // The buffer needs space for 2 unsigned ints, 2 commas, \n and \0
  const int kBufferSize = MaxDecimalDigitsIn<sizeof(
                              base::TimeDelta().InMicroseconds())>::kUnsigned +
                          MaxDecimalDigitsIn<sizeof(samples[0].id)>::kUnsigned +
                          2 + 1 + 1;
  base::EmbeddedVector<char, kBufferSize> buffer;
  int i = 0;
  for (const HeapObjectsMap::TimeInterval& sample : samples) {
    int buffer_pos = 0;
    if (i++ > 0) {
      buffer[buffer_pos++] = ',';
    }
    base::TimeDelta time_delta = sample.timestamp - start_time;
    buffer_pos = utoa(time_delta.InMicroseconds(), buffer, buffer_pos);
    buffer[buffer_pos++] = ',';
    buffer_pos = utoa(sample.last_assigned_id(), buffer, buffer_pos);
    buffer[buffer_pos++] = '\n';
    buffer[buffer_pos++] = '\0';
    writer_->AddString(buffer.begin());
  }
}

void HeapSnapshotJSONSerializer::SerializeString(const unsigned char* s) {
  writer_->AddCharacter('\n');
  writer_->AddCharacter('\"');
  for (; *s != '\0'; ++s) {
    switch (*s) {
      case '\b':
        writer_->AddString("\\b");
        continue;
      case '\f':
        writer_->AddString("\\f");
        continue;
      case '\n':
        writer_->AddString("\\n");
        continue;
      case '\r':
        writer_->AddString("\\r");
        continue;
      case '\t':
        writer_->AddString("\\t");
        continue;
      case '\"':
      case '\\':
        writer_->AddCharacter('\\');
        writer_->AddCharacter(*s);
        continue;
      default:
        if (*s > 31 && *s < 128) {
          writer_->AddCharacter(*s);
        } else if (*s <= 31) {
          // Special character with no dedicated literal.
          WriteUChar(writer_, *s);
        } else {
          // Convert UTF-8 into \u UTF-16 literal.
          size_t length = 1, cursor = 0;
          for (; length <= 4 && *(s + length) != '\0'; ++length) {
          }
          unibrow::uchar c = unibrow::Utf8::CalculateValue(s, length, &cursor);
          if (c != unibrow::Utf8::kBadChar) {
            WriteUChar(writer_, c);
            DCHECK_NE(cursor, 0);
            s += cursor - 1;
          } else {
            writer_->AddCharacter('?');
          }
        }
    }
  }
  writer_->AddCharacter('\"');
}

void HeapSnapshotJSONSerializer::SerializeStrings() {
  base::ScopedVector<const unsigned char*> sorted_strings(strings_.occupancy() +
                                                          1);
  for (base::HashMap::Entry* entry = strings_.Start(); entry != nullptr;
       entry = strings_.Next(entry)) {
    int index = static_cast<int>(reinterpret_cast<uintptr_t>(entry->value));
    sorted_strings[index] = reinterpret_cast<const unsigned char*>(entry->key);
  }
  writer_->AddString("\"<dummy>\"");
  for (int i = 1; i < sorted_strings.length(); ++i) {
    writer_->AddCharacter(',');
    SerializeString(sorted_strings[i]);
    if (writer_->aborted()) return;
  }
}

void HeapSnapshotJSONSerializer::SerializeLocation(
    const EntrySourceLocation& location) {
  // The buffer needs space for 4 unsigned ints, 3 commas, \n and \0
  static const int kBufferSize =
      MaxDecimalDigitsIn<sizeof(unsigned)>::kUnsigned * 4 + 3 + 2;
  base::EmbeddedVector<char, kBufferSize> buffer;
  int buffer_pos = 0;
  buffer_pos = utoa(to_node_index(location.entry_index), buffer, buffer_pos);
  buffer[buffer_pos++] = ',';
  buffer_pos = utoa(location.scriptId, buffer, buffer_pos);
  buffer[buffer_pos++] = ',';
  buffer_pos = utoa(location.line, buffer, buffer_pos);
  buffer[buffer_pos++] = ',';
  buffer_pos = utoa(location.col, buffer, buffer_pos);
  buffer[buffer_pos++] = '\n';
  buffer[buffer_pos++] = '\0';
  writer_->AddString(buffer.begin());
}

void HeapSnapshotJSONSerializer::SerializeLocations() {
  const std::vector<EntrySourceLocation>& locations = snapshot_->locations();
  for (size_t i = 0; i < locations.size(); i++) {
    if (i > 0) writer_->AddCharacter(',');
    SerializeLocation(locations[i]);
    if (writer_->aborted()) return;
  }
}

}  // namespace v8::internal
```