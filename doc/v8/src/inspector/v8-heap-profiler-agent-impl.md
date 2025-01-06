Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality and, if related to JavaScript, a JavaScript example demonstrating that connection. The key is to understand how this C++ code interacts with the V8 engine and exposes profiling features.

2. **Initial Skim and Keyword Spotting:**  Read through the code, looking for familiar terms and patterns. Keywords like "HeapProfiler," "Snapshot," "Sampling," "Allocation," "Garbage Collection," and "Inspector" immediately stand out. The file path itself, `v8/src/inspector/v8-heap-profiler-agent-impl.cc`, strongly suggests this code is part of the DevTools integration for heap profiling.

3. **Identify Core Data Structures and Classes:** Notice the various internal classes (`HeapSnapshotProgress`, `GlobalObjectNameResolver`, `HeapSnapshotOutputStream`, `HeapStatsStream`, etc.) and how they interact with V8's `v8::HeapProfiler`. This indicates a layer of abstraction and adaptation between the raw V8 profiling API and the DevTools protocol.

4. **Trace the Control Flow and Key Methods:** Focus on the public methods of `V8HeapProfilerAgentImpl`. Methods like `enable`, `disable`, `startTrackingHeapObjects`, `stopTrackingHeapObjects`, `takeHeapSnapshot`, `startSampling`, and `stopSampling` are the primary entry points for interacting with the heap profiler.

5. **Connect to the DevTools Protocol:**  Observe the inclusion of `<src/inspector/protocol/Protocol.h>`. The use of `protocol::HeapProfiler::Frontend` strongly indicates that this code implements the backend logic for the "Heap Profiler" tab in Chrome DevTools (or other V8-based debuggers). The `m_frontend->...` calls are sending messages to the DevTools frontend.

6. **Analyze Key Functionalities and Data Flow:**

   * **Enabling/Disabling:** The `enable` and `disable` methods manage the overall state of the heap profiler.
   * **Heap Snapshots:** The `takeHeapSnapshot` methods (both the immediate and asynchronous versions) are crucial. Notice the `HeapSnapshotOutputStream` which writes the snapshot data in chunks. The `GlobalObjectNameResolver` suggests customization of how object names are obtained.
   * **Heap Object Tracking:**  The `startTrackingHeapObjects` and `stopTrackingHeapObjects` methods enable tracking live objects and allocations. The timer mechanism (`onTimerImpl`, `requestHeapStatsUpdate`) suggests periodic updates being sent to the frontend.
   * **Sampling Heap Profiler:** The `startSampling` and `stopSampling` methods implement statistical profiling based on sampling allocations. The `getSamplingProfile` method retrieves the collected data in a structured format.
   * **Object Inspection:** `getObjectByHeapObjectId` and `addInspectedHeapObject` relate to inspecting specific objects identified in a heap snapshot.
   * **Garbage Collection:** The `collectGarbage` method triggers a garbage collection cycle.

7. **Identify Interactions with JavaScript:** The core functionality revolves around analyzing the JavaScript heap. Methods like `getObjectByHeapObjectId` directly deal with JavaScript objects. The heap snapshots themselves are representations of the JavaScript object graph. The sampling profiler tracks allocations made by JavaScript code.

8. **Formulate the Summary:** Based on the above analysis, synthesize a concise summary of the file's purpose. Highlight the key responsibilities: implementing the DevTools Heap Profiler backend, providing functionality for snapshots, live object tracking, and sampling.

9. **Construct the JavaScript Example:**  The challenge here is to provide a *simple* example that demonstrates the *impact* of this C++ code, even though the C++ itself isn't directly callable from JavaScript. The DevTools Protocol is the bridge.

   * **Focus on the *effect*:** The heap profiler helps understand memory usage. A basic JavaScript example showing object creation and potential memory growth is a good starting point.
   * **Demonstrate the *tool's* use:** The example should then explain how to use the Chrome DevTools Heap Profiler to *observe* the behavior demonstrated in the code. This directly links the C++ implementation (which powers the DevTools) to observable JavaScript behavior.
   * **Key DevTools actions:**  Highlight taking snapshots and comparing them, as this is a fundamental use case for the heap profiler.

10. **Refine and Review:** Ensure the summary is accurate and comprehensive. Check the JavaScript example for clarity and correctness. Make sure the connection between the C++ code and the JavaScript example is well-explained. For instance, explicitly stating that the C++ code *enables* the DevTools functionality that the JavaScript example demonstrates.

Self-Correction/Refinement During the Process:

* **Initial thought:** Maybe provide a complex example using `performance.measureUserAgentSpecificMemory()`. **Correction:** That's too low-level and not directly related to the *Heap Profiler* features. A simpler object allocation example is better.
* **Initial thought:** Focus only on the C++ API interactions. **Correction:**  The request specifically asks about the *relationship* to JavaScript. The DevTools interaction is the crucial link.
* **Initial thought:**  Go into deep technical details of the C++ implementation. **Correction:** The goal is a high-level summary. Avoid getting bogged down in implementation specifics unless they are directly relevant to the functionality. Focus on *what* it does, not *how* it does it in extreme detail.

By following this process of skimming, identifying key components, tracing control flow, connecting to the DevTools protocol, and then focusing on the observable effects in JavaScript, a comprehensive and relevant answer can be generated.
这个C++源代码文件 `v8-heap-profiler-agent-impl.cc` 是 **V8 JavaScript 引擎中用于实现 Chrome DevTools 协议中堆（Heap）分析器功能的后端实现**。

**功能归纳:**

1. **提供堆快照（Heap Snapshot）功能:**
   - 允许开发者捕获 JavaScript 堆的快照，记录当时存在的对象、它们的属性、大小以及对象之间的引用关系。
   - 支持同步和异步两种方式获取堆快照。
   - 可以配置快照的详细程度，例如是否报告进度、是否将全局对象视为根节点、是否捕获数值类型的值等。
   - 将生成的堆快照数据以流式方式发送到前端（Chrome DevTools）。

2. **支持堆对象跟踪（Heap Object Tracking）:**
   - 能够跟踪 JavaScript 堆中对象的生命周期和分配情况。
   - 可以选择是否跟踪具体的分配信息（trackAllocations）。
   - 定期（通过定时器）更新堆统计信息，并将增量更新发送到前端。

3. **实现采样堆分析器（Sampling Heap Profiler）:**
   - 允许开发者进行基于采样的堆内存分析，以统计不同代码路径上的内存分配情况。
   - 可以配置采样的时间间隔以及是否包含被垃圾回收的对象。
   - 提供启动和停止采样的接口，并返回采样得到的堆配置文件。

4. **提供与 JavaScript 堆对象的交互能力:**
   - 可以根据堆快照中的对象 ID 获取对应的 JavaScript 对象。
   - 可以将指定的堆对象添加到“检查对象”列表，以便在 DevTools 中进一步查看。
   - 可以根据 JavaScript 对象的 ID 获取其在堆快照中的 ID。

5. **控制垃圾回收（Garbage Collection）:**
   - 提供触发垃圾回收的接口，用于在分析堆内存之前清理不再使用的对象。

6. **状态管理:**
   - 维护堆分析器的状态，例如是否已启用、是否正在跟踪堆对象、采样分析器是否已启动等，并在 Inspector 会话恢复时还原这些状态。

**与 JavaScript 的关系及 JavaScript 示例:**

这个 C++ 代码直接服务于 JavaScript 的运行时环境。它通过 V8 引擎提供的 API 来访问和分析 JavaScript 堆。Chrome DevTools 的 "Memory" 面板中的 "Heap snapshot" 和 "Allocation instrumentation on timeline" 等功能，其背后的核心逻辑就是由这个 C++ 文件中的代码实现的。

**JavaScript 示例:**

虽然我们不能直接调用这个 C++ 文件中的函数，但我们可以通过 Chrome DevTools 的 JavaScript API 或者直接在浏览器中执行 JavaScript 代码，来触发这个 C++ 代码的功能。

例如，以下 JavaScript 代码演示了如何创建一个对象并可能导致内存分配，然后我们可以使用 Chrome DevTools 的 "Take heap snapshot" 功能来观察这个对象的存在和内存占用：

```javascript
function createLargeObject() {
  let largeArray = [];
  for (let i = 0; i < 100000; i++) {
    largeArray.push({ index: i, data: new Array(100).fill('*') });
  }
  return largeArray;
}

let myObject = createLargeObject();
console.log("Large object created. Take a heap snapshot in DevTools to see it.");

// 你可以在这里保持对 myObject 的引用，或者在稍后取消引用，
// 然后再次拍摄快照，观察垃圾回收的影响。
// myObject = null;
```

**操作步骤 (结合 DevTools):**

1. 打开 Chrome 开发者工具 (F12)。
2. 切换到 "Memory" (内存) 面板。
3. 执行上述 JavaScript 代码。
4. 点击 "Take heap snapshot" (拍摄堆快照) 按钮。
5. 在生成的快照中，你可以搜索 `createLargeObject` 或者检查对象的结构，找到 `myObject` 创建的数组及其包含的对象。

**其他示例 (使用 DevTools 的 Allocation instrumentation on timeline):**

```javascript
function allocateMemory() {
  for (let i = 0; i < 100; i++) {
    let tempObject = new Array(1000);
  }
}

console.time("allocation");
allocateMemory();
console.timeEnd("allocation");
```

**操作步骤 (结合 DevTools):**

1. 打开 Chrome 开发者工具 (F12)。
2. 切换到 "Memory" (内存) 面板。
3. 选择 "Allocation instrumentation on timeline" (时间轴上的分配检测)。
4. 点击 "Start" (开始) 按钮。
5. 执行上述 JavaScript 代码。
6. 点击 "Stop" (停止) 按钮。
7. DevTools 会显示内存分配的时间线，你可以看到 `allocateMemory` 函数调用期间的内存分配情况。

**总结:**

`v8-heap-profiler-agent-impl.cc` 作为一个底层的 C++ 实现，为开发者提供了强大的 JavaScript 堆分析能力，这些能力通过 Chrome DevTools 的界面暴露出来，帮助开发者理解 JavaScript 代码的内存使用情况、发现内存泄漏等问题。JavaScript 代码本身不能直接调用这个 C++ 文件中的函数，但其运行结果可以通过 DevTools 工具观察和分析，而这些工具的背后就是这个 C++ 文件的实现。

Prompt: 
```
这是目录为v8/src/inspector/v8-heap-profiler-agent-impl.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/inspector/v8-heap-profiler-agent-impl.h"

#include "include/v8-context.h"
#include "include/v8-inspector.h"
#include "include/v8-platform.h"
#include "include/v8-profiler.h"
#include "src/base/platform/mutex.h"
#include "src/base/platform/time.h"
#include "src/inspector/injected-script.h"
#include "src/inspector/inspected-context.h"
#include "src/inspector/protocol/Protocol.h"
#include "src/inspector/string-util.h"
#include "src/inspector/v8-debugger.h"
#include "src/inspector/v8-inspector-impl.h"
#include "src/inspector/v8-inspector-session-impl.h"

namespace v8_inspector {

namespace {

namespace HeapProfilerAgentState {
static const char heapProfilerEnabled[] = "heapProfilerEnabled";
static const char heapObjectsTrackingEnabled[] = "heapObjectsTrackingEnabled";
static const char allocationTrackingEnabled[] = "allocationTrackingEnabled";
static const char samplingHeapProfilerEnabled[] = "samplingHeapProfilerEnabled";
static const char samplingHeapProfilerInterval[] =
    "samplingHeapProfilerInterval";
static const char samplingHeapProfilerFlags[] = "samplingHeapProfilerFlags";
}  // namespace HeapProfilerAgentState

class HeapSnapshotProgress final : public v8::ActivityControl {
 public:
  explicit HeapSnapshotProgress(protocol::HeapProfiler::Frontend* frontend)
      : m_frontend(frontend) {}
  ControlOption ReportProgressValue(uint32_t done, uint32_t total) override {
    m_frontend->reportHeapSnapshotProgress(done, total,
                                           protocol::Maybe<bool>());
    if (done >= total) {
      m_frontend->reportHeapSnapshotProgress(total, total, true);
    }
    m_frontend->flush();
    return kContinue;
  }

 private:
  protocol::HeapProfiler::Frontend* m_frontend;
};

class GlobalObjectNameResolver final
    : public v8::HeapProfiler::ObjectNameResolver {
 public:
  explicit GlobalObjectNameResolver(V8InspectorSessionImpl* session)
      : m_offset(0), m_strings(10000), m_session(session) {}

  const char* GetName(v8::Local<v8::Object> object) override {
    v8::Local<v8::Context> creationContext;
    if (!object->GetCreationContext(m_session->inspector()->isolate())
             .ToLocal(&creationContext)) {
      return "";
    }
    InspectedContext* context = m_session->inspector()->getContext(
        m_session->contextGroupId(),
        InspectedContext::contextId(creationContext));
    if (!context) return "";
    String16 name = context->origin();
    size_t length = name.length();
    if (m_offset + length + 1 >= m_strings.size()) return "";
    for (size_t i = 0; i < length; ++i) {
      UChar ch = name[i];
      m_strings[m_offset + i] = ch > 0xFF ? '?' : static_cast<char>(ch);
    }
    m_strings[m_offset + length] = '\0';
    char* result = &*m_strings.begin() + m_offset;
    m_offset += length + 1;
    return result;
  }

 private:
  size_t m_offset;
  std::vector<char> m_strings;
  V8InspectorSessionImpl* m_session;
};

class HeapSnapshotOutputStream final : public v8::OutputStream {
 public:
  explicit HeapSnapshotOutputStream(protocol::HeapProfiler::Frontend* frontend)
      : m_frontend(frontend) {}
  void EndOfStream() override {}
  int GetChunkSize() override { return 1 * v8::internal::MB; }
  WriteResult WriteAsciiChunk(char* data, int size) override {
    m_frontend->addHeapSnapshotChunk(String16(data, size));
    m_frontend->flush();
    return kContinue;
  }

 private:
  protocol::HeapProfiler::Frontend* m_frontend;
};

v8::Local<v8::Object> objectByHeapObjectId(v8::Isolate* isolate, int id) {
  v8::HeapProfiler* profiler = isolate->GetHeapProfiler();
  v8::Local<v8::Value> value = profiler->FindObjectById(id);
  if (value.IsEmpty() || !value->IsObject()) return v8::Local<v8::Object>();
  return value.As<v8::Object>();
}

class InspectableHeapObject final : public V8InspectorSession::Inspectable {
 public:
  explicit InspectableHeapObject(int heapObjectId)
      : m_heapObjectId(heapObjectId) {}
  v8::Local<v8::Value> get(v8::Local<v8::Context> context) override {
    return objectByHeapObjectId(context->GetIsolate(), m_heapObjectId);
  }

 private:
  int m_heapObjectId;
};

class HeapStatsStream final : public v8::OutputStream {
 public:
  explicit HeapStatsStream(protocol::HeapProfiler::Frontend* frontend)
      : m_frontend(frontend) {}

  void EndOfStream() override {}

  WriteResult WriteAsciiChunk(char* data, int size) override {
    DCHECK(false);
    return kAbort;
  }

  WriteResult WriteHeapStatsChunk(v8::HeapStatsUpdate* updateData,
                                  int count) override {
    DCHECK_GT(count, 0);
    auto statsDiff = std::make_unique<protocol::Array<int>>();
    for (int i = 0; i < count; ++i) {
      statsDiff->emplace_back(updateData[i].index);
      statsDiff->emplace_back(updateData[i].count);
      statsDiff->emplace_back(updateData[i].size);
    }
    m_frontend->heapStatsUpdate(std::move(statsDiff));
    return kContinue;
  }

 private:
  protocol::HeapProfiler::Frontend* m_frontend;
};

}  // namespace

struct V8HeapProfilerAgentImpl::AsyncCallbacks {
  v8::base::Mutex m_mutex;
  bool m_canceled = false;
  std::vector<std::unique_ptr<CollectGarbageCallback>> m_gcCallbacks;
  std::vector<V8HeapProfilerAgentImpl::HeapSnapshotTask*> m_heapSnapshotTasks;
};

class V8HeapProfilerAgentImpl::GCTask : public v8::Task {
 public:
  GCTask(v8::Isolate* isolate, std::shared_ptr<AsyncCallbacks> asyncCallbacks)
      : m_isolate(isolate), m_asyncCallbacks(asyncCallbacks) {}

  void Run() override {
    std::shared_ptr<AsyncCallbacks> asyncCallbacks = m_asyncCallbacks.lock();
    if (!asyncCallbacks) return;
    v8::base::MutexGuard lock(&asyncCallbacks->m_mutex);
    if (asyncCallbacks->m_canceled) return;
    v8::debug::ForceGarbageCollection(m_isolate,
                                      v8::StackState::kNoHeapPointers);
    for (auto& callback : asyncCallbacks->m_gcCallbacks) {
      callback->sendSuccess();
    }
    asyncCallbacks->m_gcCallbacks.clear();
  }

 private:
  v8::Isolate* m_isolate;
  std::weak_ptr<AsyncCallbacks> m_asyncCallbacks;
};

struct V8HeapProfilerAgentImpl::HeapSnapshotProtocolOptions {
  HeapSnapshotProtocolOptions(Maybe<bool> reportProgress,
                              Maybe<bool> treatGlobalObjectsAsRoots,
                              Maybe<bool> captureNumericValue,
                              Maybe<bool> exposeInternals)
      : m_reportProgress(reportProgress.value_or(false)),
        m_treatGlobalObjectsAsRoots(treatGlobalObjectsAsRoots.value_or(true)),
        m_captureNumericValue(captureNumericValue.value_or(false)),
        m_exposeInternals(exposeInternals.value_or(false)) {}
  bool m_reportProgress;
  bool m_treatGlobalObjectsAsRoots;
  bool m_captureNumericValue;
  bool m_exposeInternals;
};

class V8HeapProfilerAgentImpl::HeapSnapshotTask : public v8::Task {
 public:
  HeapSnapshotTask(V8HeapProfilerAgentImpl* agent,
                   std::shared_ptr<AsyncCallbacks> asyncCallbacks,
                   HeapSnapshotProtocolOptions protocolOptions,
                   std::unique_ptr<TakeHeapSnapshotCallback> callback)
      : m_agent(agent),
        m_asyncCallbacks(asyncCallbacks),
        m_protocolOptions(protocolOptions),
        m_callback(std::move(callback)) {}

  void Run() override { Run(cppgc::EmbedderStackState::kNoHeapPointers); }

  void Run(cppgc::EmbedderStackState stackState) {
    Response response = Response::Success();
    {
      // If the async callbacks object still exists and is not canceled, then
      // the V8HeapProfilerAgentImpl still exists, so we can safely take a
      // snapshot.
      std::shared_ptr<AsyncCallbacks> asyncCallbacks = m_asyncCallbacks.lock();
      if (!asyncCallbacks) return;
      v8::base::MutexGuard lock(&asyncCallbacks->m_mutex);
      if (asyncCallbacks->m_canceled) return;

      auto& heapSnapshotTasks = asyncCallbacks->m_heapSnapshotTasks;
      auto it =
          std::find(heapSnapshotTasks.begin(), heapSnapshotTasks.end(), this);
      if (it == heapSnapshotTasks.end()) {
        // This task must have already been run. This can happen because the
        // task was queued with PostNonNestableTask but then got run early by
        // takePendingHeapSnapshots.
        return;
      }
      heapSnapshotTasks.erase(it);

      response = m_agent->takeHeapSnapshotNow(m_protocolOptions, stackState);
    }

    // The rest of this function runs without the mutex, because Node expects to
    // be able to dispose the profiler agent during the callback, which would
    // deadlock if this function still held the mutex. It's safe to call the
    // callback without the mutex; the internal implementation of the callback
    // uses weak pointers to avoid doing anything dangerous if other components
    // have been disposed (see DomainDispatcher::Callback::sendIfActive).
    if (response.IsSuccess()) {
      m_callback->sendSuccess();
    } else {
      m_callback->sendFailure(std::move(response));
    }
  }

 private:
  V8HeapProfilerAgentImpl* m_agent;
  std::weak_ptr<AsyncCallbacks> m_asyncCallbacks;
  HeapSnapshotProtocolOptions m_protocolOptions;
  std::unique_ptr<TakeHeapSnapshotCallback> m_callback;
};

V8HeapProfilerAgentImpl::V8HeapProfilerAgentImpl(
    V8InspectorSessionImpl* session, protocol::FrontendChannel* frontendChannel,
    protocol::DictionaryValue* state)
    : m_session(session),
      m_isolate(session->inspector()->isolate()),
      m_frontend(frontendChannel),
      m_state(state),
      m_hasTimer(false),
      m_asyncCallbacks(std::make_shared<AsyncCallbacks>()) {}

V8HeapProfilerAgentImpl::~V8HeapProfilerAgentImpl() {
  v8::base::MutexGuard lock(&m_asyncCallbacks->m_mutex);
  m_asyncCallbacks->m_canceled = true;
  m_asyncCallbacks->m_gcCallbacks.clear();
  m_asyncCallbacks->m_heapSnapshotTasks.clear();
}

void V8HeapProfilerAgentImpl::restore() {
  if (m_state->booleanProperty(HeapProfilerAgentState::heapProfilerEnabled,
                               false))
    m_frontend.resetProfiles();
  if (m_state->booleanProperty(
          HeapProfilerAgentState::heapObjectsTrackingEnabled, false))
    startTrackingHeapObjectsInternal(m_state->booleanProperty(
        HeapProfilerAgentState::allocationTrackingEnabled, false));
  if (m_state->booleanProperty(
          HeapProfilerAgentState::samplingHeapProfilerEnabled, false)) {
    double samplingInterval = m_state->doubleProperty(
        HeapProfilerAgentState::samplingHeapProfilerInterval, -1);
    DCHECK_GE(samplingInterval, 0);
    int flags = m_state->integerProperty(
        HeapProfilerAgentState::samplingHeapProfilerFlags, 0);
    startSampling(
        Maybe<double>(samplingInterval),
        Maybe<bool>(
            flags &
            v8::HeapProfiler::kSamplingIncludeObjectsCollectedByMajorGC),
        Maybe<bool>(
            flags &
            v8::HeapProfiler::kSamplingIncludeObjectsCollectedByMinorGC));
  }
}

void V8HeapProfilerAgentImpl::collectGarbage(
    std::unique_ptr<CollectGarbageCallback> callback) {
  v8::base::MutexGuard lock(&m_asyncCallbacks->m_mutex);
  m_asyncCallbacks->m_gcCallbacks.push_back(std::move(callback));
  v8::debug::GetCurrentPlatform()
      ->GetForegroundTaskRunner(m_isolate)
      ->PostNonNestableTask(
          std::make_unique<GCTask>(m_isolate, m_asyncCallbacks));
}

Response V8HeapProfilerAgentImpl::startTrackingHeapObjects(
    Maybe<bool> trackAllocations) {
  m_state->setBoolean(HeapProfilerAgentState::heapObjectsTrackingEnabled, true);
  bool allocationTrackingEnabled = trackAllocations.value_or(false);
  m_state->setBoolean(HeapProfilerAgentState::allocationTrackingEnabled,
                      allocationTrackingEnabled);
  startTrackingHeapObjectsInternal(allocationTrackingEnabled);
  return Response::Success();
}

Response V8HeapProfilerAgentImpl::stopTrackingHeapObjects(
    Maybe<bool> reportProgress, Maybe<bool> treatGlobalObjectsAsRoots,
    Maybe<bool> captureNumericValue, Maybe<bool> exposeInternals) {
  requestHeapStatsUpdate();
  takeHeapSnapshotNow(
      HeapSnapshotProtocolOptions(
          std::move(reportProgress), std::move(treatGlobalObjectsAsRoots),
          std::move(captureNumericValue), std::move(exposeInternals)),
      cppgc::EmbedderStackState::kMayContainHeapPointers);
  stopTrackingHeapObjectsInternal();
  return Response::Success();
}

Response V8HeapProfilerAgentImpl::enable() {
  m_state->setBoolean(HeapProfilerAgentState::heapProfilerEnabled, true);
  return Response::Success();
}

Response V8HeapProfilerAgentImpl::disable() {
  stopTrackingHeapObjectsInternal();
  if (m_state->booleanProperty(
          HeapProfilerAgentState::samplingHeapProfilerEnabled, false)) {
    v8::HeapProfiler* profiler = m_isolate->GetHeapProfiler();
    if (profiler) profiler->StopSamplingHeapProfiler();
  }
  m_isolate->GetHeapProfiler()->ClearObjectIds();
  m_state->setBoolean(HeapProfilerAgentState::heapProfilerEnabled, false);
  return Response::Success();
}

void V8HeapProfilerAgentImpl::takeHeapSnapshot(
    Maybe<bool> reportProgress, Maybe<bool> treatGlobalObjectsAsRoots,
    Maybe<bool> captureNumericValue, Maybe<bool> exposeInternals,
    std::unique_ptr<TakeHeapSnapshotCallback> callback) {
  HeapSnapshotProtocolOptions protocolOptions(
      std::move(reportProgress), std::move(treatGlobalObjectsAsRoots),
      std::move(captureNumericValue), std::move(exposeInternals));
  std::shared_ptr<v8::TaskRunner> task_runner =
      v8::debug::GetCurrentPlatform()->GetForegroundTaskRunner(m_isolate);

  // Heap snapshots can be more accurate if we wait until the stack is empty and
  // run the garbage collector without conservative stack scanning, as done in
  // V8HeapProfilerAgentImpl::collectGarbage. However, heap snapshots can also
  // be requested while paused in the debugger, in which case the snapshot must
  // be taken immediately with conservative stack scanning enabled.
  if (m_session->inspector()->debugger()->isPaused() ||
      !task_runner->NonNestableTasksEnabled()) {
    Response response = takeHeapSnapshotNow(
        protocolOptions, cppgc::EmbedderStackState::kMayContainHeapPointers);
    if (response.IsSuccess()) {
      callback->sendSuccess();
    } else {
      callback->sendFailure(std::move(response));
    }
    return;
  }

  std::unique_ptr<HeapSnapshotTask> task = std::make_unique<HeapSnapshotTask>(
      this, m_asyncCallbacks, protocolOptions, std::move(callback));
  m_asyncCallbacks->m_heapSnapshotTasks.push_back(task.get());
  task_runner->PostNonNestableTask(std::move(task));
}

Response V8HeapProfilerAgentImpl::takeHeapSnapshotNow(
    const HeapSnapshotProtocolOptions& protocolOptions,
    cppgc::EmbedderStackState stackState) {
  v8::HeapProfiler* profiler = m_isolate->GetHeapProfiler();
  if (!profiler) return Response::ServerError("Cannot access v8 heap profiler");
  std::unique_ptr<HeapSnapshotProgress> progress;
  if (protocolOptions.m_reportProgress)
    progress.reset(new HeapSnapshotProgress(&m_frontend));

  GlobalObjectNameResolver resolver(m_session);
  v8::HeapProfiler::HeapSnapshotOptions options;
  options.global_object_name_resolver = &resolver;
  options.control = progress.get();
  options.snapshot_mode =
      protocolOptions.m_exposeInternals ||
              // Not treating global objects as roots results into exposing
              // internals.
              !protocolOptions.m_treatGlobalObjectsAsRoots
          ? v8::HeapProfiler::HeapSnapshotMode::kExposeInternals
          : v8::HeapProfiler::HeapSnapshotMode::kRegular;
  options.numerics_mode =
      protocolOptions.m_captureNumericValue
          ? v8::HeapProfiler::NumericsMode::kExposeNumericValues
          : v8::HeapProfiler::NumericsMode::kHideNumericValues;
  options.stack_state = stackState;
  const v8::HeapSnapshot* snapshot = profiler->TakeHeapSnapshot(options);
  if (!snapshot) return Response::ServerError("Failed to take heap snapshot");
  HeapSnapshotOutputStream stream(&m_frontend);
  snapshot->Serialize(&stream);
  const_cast<v8::HeapSnapshot*>(snapshot)->Delete();
  return Response::Success();
}

Response V8HeapProfilerAgentImpl::getObjectByHeapObjectId(
    const String16& heapSnapshotObjectId, Maybe<String16> objectGroup,
    std::unique_ptr<protocol::Runtime::RemoteObject>* result) {
  bool ok;
  int id = heapSnapshotObjectId.toInteger(&ok);
  if (!ok) return Response::ServerError("Invalid heap snapshot object id");

  v8::HandleScope handles(m_isolate);
  v8::Local<v8::Object> heapObject = objectByHeapObjectId(m_isolate, id);
  if (heapObject.IsEmpty())
    return Response::ServerError("Object is not available");

  if (!m_session->inspector()->client()->isInspectableHeapObject(heapObject))
    return Response::ServerError("Object is not available");

  v8::Local<v8::Context> creationContext;
  if (!heapObject->GetCreationContext(m_isolate).ToLocal(&creationContext)) {
    return Response::ServerError("Object is not available");
  }
  *result = m_session->wrapObject(creationContext, heapObject,
                                  objectGroup.value_or(""), false);
  if (!*result) return Response::ServerError("Object is not available");
  return Response::Success();
}

void V8HeapProfilerAgentImpl::takePendingHeapSnapshots() {
  // Each task will remove itself from m_heapSnapshotTasks.
  while (!m_asyncCallbacks->m_heapSnapshotTasks.empty()) {
    m_asyncCallbacks->m_heapSnapshotTasks.front()->Run(
        cppgc::EmbedderStackState::kMayContainHeapPointers);
  }
}

Response V8HeapProfilerAgentImpl::addInspectedHeapObject(
    const String16& inspectedHeapObjectId) {
  bool ok;
  int id = inspectedHeapObjectId.toInteger(&ok);
  if (!ok) return Response::ServerError("Invalid heap snapshot object id");

  v8::HandleScope handles(m_isolate);
  v8::Local<v8::Object> heapObject = objectByHeapObjectId(m_isolate, id);
  if (heapObject.IsEmpty())
    return Response::ServerError("Object is not available");

  if (!m_session->inspector()->client()->isInspectableHeapObject(heapObject))
    return Response::ServerError("Object is not available");
  m_session->addInspectedObject(
      std::unique_ptr<InspectableHeapObject>(new InspectableHeapObject(id)));
  return Response::Success();
}

Response V8HeapProfilerAgentImpl::getHeapObjectId(
    const String16& objectId, String16* heapSnapshotObjectId) {
  v8::HandleScope handles(m_isolate);
  v8::Local<v8::Value> value;
  v8::Local<v8::Context> context;
  Response response =
      m_session->unwrapObject(objectId, &value, &context, nullptr);
  if (!response.IsSuccess()) return response;
  if (value->IsUndefined()) return Response::InternalError();

  v8::SnapshotObjectId id = m_isolate->GetHeapProfiler()->GetObjectId(value);
  *heapSnapshotObjectId = String16::fromInteger(static_cast<size_t>(id));
  return Response::Success();
}

void V8HeapProfilerAgentImpl::requestHeapStatsUpdate() {
  HeapStatsStream stream(&m_frontend);
  v8::SnapshotObjectId lastSeenObjectId =
      m_isolate->GetHeapProfiler()->GetHeapStats(&stream);
  m_frontend.lastSeenObjectId(
      lastSeenObjectId, m_session->inspector()->client()->currentTimeMS());
}

// static
void V8HeapProfilerAgentImpl::onTimer(void* data) {
  reinterpret_cast<V8HeapProfilerAgentImpl*>(data)->onTimerImpl();
}

static constexpr v8::base::TimeDelta kDefaultTimerDelay =
    v8::base::TimeDelta::FromMilliseconds(50);

void V8HeapProfilerAgentImpl::onTimerImpl() {
  v8::base::TimeTicks start = v8::base::TimeTicks::Now();
  requestHeapStatsUpdate();
  v8::base::TimeDelta elapsed = v8::base::TimeTicks::Now() - start;
  if (m_hasTimer) {
    // requestHeapStatsUpdate can take a long time on large heaps. To ensure
    // that there is still some time for the thread to make progress on running
    // JavaScript or doing other useful work, we'll adjust the timer delay here.
    const v8::base::TimeDelta minAcceptableDelay =
        std::max(elapsed * 2, kDefaultTimerDelay);
    const v8::base::TimeDelta idealDelay =
        std::max(elapsed * 3, kDefaultTimerDelay);
    const v8::base::TimeDelta maxAcceptableDelay =
        std::max(elapsed * 4, kDefaultTimerDelay);
    if (m_timerDelayInSeconds < minAcceptableDelay.InSecondsF() ||
        m_timerDelayInSeconds > maxAcceptableDelay.InSecondsF()) {
      // The existing timer's speed is not very close to ideal, so cancel it and
      // start a new timer.
      m_session->inspector()->client()->cancelTimer(
          reinterpret_cast<void*>(this));
      m_timerDelayInSeconds = idealDelay.InSecondsF();
      m_session->inspector()->client()->startRepeatingTimer(
          m_timerDelayInSeconds, &V8HeapProfilerAgentImpl::onTimer,
          reinterpret_cast<void*>(this));
    }
  }
}

void V8HeapProfilerAgentImpl::startTrackingHeapObjectsInternal(
    bool trackAllocations) {
  m_isolate->GetHeapProfiler()->StartTrackingHeapObjects(trackAllocations);
  if (!m_hasTimer) {
    m_hasTimer = true;
    m_timerDelayInSeconds = kDefaultTimerDelay.InSecondsF();
    m_session->inspector()->client()->startRepeatingTimer(
        m_timerDelayInSeconds, &V8HeapProfilerAgentImpl::onTimer,
        reinterpret_cast<void*>(this));
  }
}

void V8HeapProfilerAgentImpl::stopTrackingHeapObjectsInternal() {
  if (m_hasTimer) {
    m_session->inspector()->client()->cancelTimer(
        reinterpret_cast<void*>(this));
    m_hasTimer = false;
  }
  m_isolate->GetHeapProfiler()->StopTrackingHeapObjects();
  m_state->setBoolean(HeapProfilerAgentState::heapObjectsTrackingEnabled,
                      false);
  m_state->setBoolean(HeapProfilerAgentState::allocationTrackingEnabled, false);
}

Response V8HeapProfilerAgentImpl::startSampling(
    Maybe<double> samplingInterval,
    Maybe<bool> includeObjectsCollectedByMajorGC,
    Maybe<bool> includeObjectsCollectedByMinorGC) {
  v8::HeapProfiler* profiler = m_isolate->GetHeapProfiler();
  if (!profiler) return Response::ServerError("Cannot access v8 heap profiler");
  const unsigned defaultSamplingInterval = 1 << 15;
  double samplingIntervalValue =
      samplingInterval.value_or(defaultSamplingInterval);
  if (samplingIntervalValue <= 0.0) {
    return Response::ServerError("Invalid sampling interval");
  }
  m_state->setDouble(HeapProfilerAgentState::samplingHeapProfilerInterval,
                     samplingIntervalValue);
  m_state->setBoolean(HeapProfilerAgentState::samplingHeapProfilerEnabled,
                      true);
  int flags = v8::HeapProfiler::kSamplingForceGC;
  if (includeObjectsCollectedByMajorGC.value_or(false)) {
    flags |= v8::HeapProfiler::kSamplingIncludeObjectsCollectedByMajorGC;
  }
  if (includeObjectsCollectedByMinorGC.value_or(false)) {
    flags |= v8::HeapProfiler::kSamplingIncludeObjectsCollectedByMinorGC;
  }
  m_state->setInteger(HeapProfilerAgentState::samplingHeapProfilerFlags, flags);
  profiler->StartSamplingHeapProfiler(
      static_cast<uint64_t>(samplingIntervalValue), 128,
      static_cast<v8::HeapProfiler::SamplingFlags>(flags));
  return Response::Success();
}

namespace {
std::unique_ptr<protocol::HeapProfiler::SamplingHeapProfileNode>
buildSampingHeapProfileNode(v8::Isolate* isolate,
                            const v8::AllocationProfile::Node* node) {
  auto children = std::make_unique<
      protocol::Array<protocol::HeapProfiler::SamplingHeapProfileNode>>();
  for (const auto* child : node->children)
    children->emplace_back(buildSampingHeapProfileNode(isolate, child));
  size_t selfSize = 0;
  for (const auto& allocation : node->allocations)
    selfSize += allocation.size * allocation.count;
  std::unique_ptr<protocol::Runtime::CallFrame> callFrame =
      protocol::Runtime::CallFrame::create()
          .setFunctionName(toProtocolString(isolate, node->name))
          .setScriptId(String16::fromInteger(node->script_id))
          .setUrl(toProtocolString(isolate, node->script_name))
          .setLineNumber(node->line_number - 1)
          .setColumnNumber(node->column_number - 1)
          .build();
  std::unique_ptr<protocol::HeapProfiler::SamplingHeapProfileNode> result =
      protocol::HeapProfiler::SamplingHeapProfileNode::create()
          .setCallFrame(std::move(callFrame))
          .setSelfSize(selfSize)
          .setChildren(std::move(children))
          .setId(node->node_id)
          .build();
  return result;
}
}  // namespace

Response V8HeapProfilerAgentImpl::stopSampling(
    std::unique_ptr<protocol::HeapProfiler::SamplingHeapProfile>* profile) {
  Response result = getSamplingProfile(profile);
  if (result.IsSuccess()) {
    m_isolate->GetHeapProfiler()->StopSamplingHeapProfiler();
    m_state->setBoolean(HeapProfilerAgentState::samplingHeapProfilerEnabled,
                        false);
  }
  return result;
}

Response V8HeapProfilerAgentImpl::getSamplingProfile(
    std::unique_ptr<protocol::HeapProfiler::SamplingHeapProfile>* profile) {
  v8::HeapProfiler* profiler = m_isolate->GetHeapProfiler();
  // Need a scope as v8::AllocationProfile contains Local handles.
  v8::HandleScope scope(m_isolate);
  std::unique_ptr<v8::AllocationProfile> v8Profile(
      profiler->GetAllocationProfile());
  if (!v8Profile)
    return Response::ServerError("V8 sampling heap profiler was not started.");
  v8::AllocationProfile::Node* root = v8Profile->GetRootNode();
  auto samples = std::make_unique<
      protocol::Array<protocol::HeapProfiler::SamplingHeapProfileSample>>();
  for (const auto& sample : v8Profile->GetSamples()) {
    samples->emplace_back(
        protocol::HeapProfiler::SamplingHeapProfileSample::create()
            .setSize(sample.size * sample.count)
            .setNodeId(sample.node_id)
            .setOrdinal(static_cast<double>(sample.sample_id))
            .build());
  }
  *profile = protocol::HeapProfiler::SamplingHeapProfile::create()
                 .setHead(buildSampingHeapProfileNode(m_isolate, root))
                 .setSamples(std::move(samples))
                 .build();
  return Response::Success();
}

}  // namespace v8_inspector

"""

```