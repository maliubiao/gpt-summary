Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

1. **Understand the Goal:** The request asks for the functionality of the `v8-heap-profiler-agent-impl.cc` file, along with connections to JavaScript, code logic, and common errors.

2. **Initial Scan for Key Terms:** I quickly scan the code for recognizable terms related to heap profiling, debugging, and V8 internals. Keywords like "HeapProfiler," "snapshot," "sampling," "tracking," "garbage collection," "inspector," "protocol," "frontend," and "callback" jump out. This gives me a high-level idea of the domain.

3. **Identify the Core Class:** The presence of `class V8HeapProfilerAgentImpl` and its methods strongly suggest this is the central class responsible for implementing the heap profiler agent within the V8 Inspector.

4. **Analyze Key Methods and their Interactions:** I start examining the public methods of `V8HeapProfilerAgentImpl` as they likely represent the main functionalities exposed to the debugger/profiler frontend. I pay attention to:
    * **Methods related to enabling/disabling:** `enable()`, `disable()`
    * **Methods related to tracking:** `startTrackingHeapObjects()`, `stopTrackingHeapObjects()`
    * **Methods related to snapshots:** `takeHeapSnapshot()`, `takeHeapSnapshotNow()`
    * **Methods related to sampling:** `startSampling()`, `stopSampling()`, `getSamplingProfile()`
    * **Methods related to garbage collection:** `collectGarbage()`
    * **Methods for object inspection:** `getObjectByHeapObjectId()`, `addInspectedHeapObject()`, `getHeapObjectId()`
    * **Methods for stats:** `requestHeapStatsUpdate()`

5. **Trace Data Flow and Internal Structures:** I look for how data is processed within these methods. I notice the use of:
    * **`protocol::HeapProfiler::Frontend`:** This indicates communication with the debugger frontend.
    * **`v8::HeapProfiler`:** This is the core V8 API for heap profiling.
    * **`v8::OutputStream` (derived classes):**  Used for streaming heap snapshot data.
    * **`v8::Task` (derived classes):** Used for asynchronous operations, particularly for garbage collection and heap snapshots.
    * **`protocol::DictionaryValue` (m_state):**  Used to store the agent's state.
    * **Helper classes:** `HeapSnapshotProgress`, `GlobalObjectNameResolver`, `InspectableHeapObject`, `HeapStatsStream`.

6. **Connect to JavaScript Functionality:**  I consider how the actions performed by the C++ code are triggered or reflected in JavaScript. The methods for taking snapshots, tracking objects, and sampling directly correspond to functionalities exposed in browser developer tools' memory profiling features. I think about the `console.profile()` and memory panel interactions.

7. **Consider Code Logic and Asynchronous Operations:**  The presence of `v8::Task` and the `AsyncCallbacks` structure clearly indicates asynchronous operations. I analyze the locking mechanisms (`v8::base::Mutex`) and how tasks are posted to the foreground task runner. The `takePendingHeapSnapshots()` method is also important here.

8. **Identify Potential User Errors:**  Based on the functionalities, I brainstorm common mistakes developers might make when using memory profiling tools. Examples include:
    * Forgetting to stop profiling.
    * Misinterpreting snapshot data.
    * Not understanding the impact of garbage collection.

9. **Construct Examples (especially JavaScript):**  For the JavaScript connection, I create concise examples that demonstrate how the underlying C++ functionality is used from a developer's perspective. `console.profile()` and the DevTools memory panel are key here.

10. **Infer Input/Output for Code Logic:**  For methods with clear logic (like object ID conversion), I define hypothetical inputs and the expected outputs to illustrate the function's behavior.

11. **Structure the Response:**  I organize the information logically using headings and bullet points to make it easy to read and understand. I follow the order requested in the prompt.

12. **Refine and Review:** I reread the code and my response to ensure accuracy and completeness. I double-check that the JavaScript examples are correct and that the explanations are clear. I make sure to explicitly address all parts of the original request.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe the `.cc` extension automatically means it's not Torque. **Correction:** The prompt explicitly states to check the extension if we *don't* know.
* **Initial thought:** Focus heavily on the V8 API. **Correction:**  Balance this with the Inspector protocol interaction and the user-facing JavaScript aspects.
* **Initial thought:**  Just list the methods. **Correction:**  Group related methods by functionality (tracking, snapshots, etc.) for better clarity.
* **Initial thought:** Overcomplicate the code logic examples. **Correction:** Keep them simple and focused on the core functionality.
* **Initial thought:**  Forget to mention potential memory leaks. **Correction:** Include it as a common user error related to heap profiling.

By following these steps, I could systematically analyze the C++ code and generate a comprehensive and informative response that addresses all the requirements of the prompt.
这个 C++ 源代码文件 `v8/src/inspector/v8-heap-profiler-agent-impl.cc` 是 V8 引擎中 **Inspector** 组件的一部分，专门负责实现 **堆快照 (Heap Snapshot)** 和 **内存分配跟踪 (Allocation Tracking)** 的功能。它作为连接 V8 引擎的底层堆分析能力和 Chrome DevTools 等前端调试工具的桥梁。

以下是它的主要功能：

1. **管理堆分析会话状态:**
   - 维护堆分析器的启用/禁用状态 (`heapProfilerEnabled`).
   - 跟踪堆对象跟踪是否启用 (`heapObjectsTrackingEnabled`) 以及是否启用分配跟踪 (`allocationTrackingEnabled`).
   - 管理采样堆分析器的状态，包括是否启用 (`samplingHeapProfilerEnabled`)、采样间隔 (`samplingHeapProfilerInterval`) 和相关标志 (`samplingHeapProfilerFlags`).

2. **拍摄堆快照 (Taking Heap Snapshots):**
   - 提供 `takeHeapSnapshot` 方法，允许前端请求生成当前 JavaScript 堆的快照。
   - 使用 V8 的 `HeapProfiler` API 来执行快照操作。
   - 支持报告快照进度 (`HeapSnapshotProgress`) 到前端。
   - 可以配置是否将全局对象视为根节点，以及是否捕获数值类型的值。
   - 使用 `HeapSnapshotOutputStream` 将快照数据以 chunk 的形式发送到前端。

3. **跟踪堆对象 (Tracking Heap Objects):**
   - 提供 `startTrackingHeapObjects` 和 `stopTrackingHeapObjects` 方法来启动和停止对堆中对象分配的跟踪。
   - 可以选择是否跟踪每个对象的分配信息 (`trackAllocations`)。
   - 定期通过 `requestHeapStatsUpdate` 发送堆统计信息更新到前端，使用 `HeapStatsStream` 格式化数据。
   - 使用定时器 (`onTimerImpl`) 来定期触发堆统计更新。

4. **采样堆分析 (Sampling Heap Profiling):**
   - 提供 `startSampling` 方法来启动采样堆分析，这是一种性能开销较低的内存分析方法。
   - 可以设置采样间隔，并配置是否包含由 Major GC 或 Minor GC 回收的对象。
   - 提供 `stopSampling` 和 `getSamplingProfile` 方法来获取采样分析的结果，结果以树状结构 (`SamplingHeapProfileNode`) 呈现。

5. **对象检查和访问:**
   - 提供 `getObjectByHeapObjectId` 方法，根据堆快照中的对象 ID 获取对应的 JavaScript 对象，以便在调试器中检查。
   - 使用 `objectByHeapObjectId` 辅助函数根据 ID 在 V8 堆中查找对象。
   - 提供 `addInspectedHeapObject` 方法将堆快照中的对象添加到 Inspector 的检查对象列表中。
   - 提供 `getHeapObjectId` 方法，根据 Inspector 的对象 ID 获取对应的堆快照对象 ID。

6. **垃圾回收 (Garbage Collection):**
   - 提供 `collectGarbage` 方法，允许前端请求执行垃圾回收。这是一个异步操作。

7. **与 Inspector 前端通信:**
   - 使用 `protocol::HeapProfiler::Frontend` 接口与 Chrome DevTools 或其他 Inspector 前端进行通信，发送快照数据、进度信息、统计更新等。

8. **内部状态管理:**
   - 使用 `protocol::DictionaryValue` (`m_state`) 来持久化一些状态，例如堆分析器是否启用，以便在 Inspector 会话恢复时恢复状态。

**关于代码特性：**

- **不是 Torque 代码:** 文件名以 `.cc` 结尾，表明它是 C++ 源代码，而不是以 `.tq` 结尾的 V8 Torque 源代码。Torque 用于定义 V8 的内置函数和类型系统。

- **与 JavaScript 的关系：** 这个文件直接关联到 JavaScript 的内存分析功能。当你在 Chrome DevTools 的 "Memory" 面板中执行以下操作时，这个文件中的代码就会被触发：
    - **拍摄堆快照 (Take heap snapshot):**  调用 `takeHeapSnapshot`。
    - **启动/停止分配跟踪 (Allocation instrumentation on timeline):** 调用 `startTrackingHeapObjects` 和 `stopTrackingHeapObjects`。
    - **启动/停止采样 (Allocation sampling):** 调用 `startSampling` 和 `stopSampling`。
    - **强制垃圾回收 (Collect garbage):** 调用 `collectGarbage`。
    - **检查堆快照中的对象:** 调用 `getObjectByHeapObjectId`。

**JavaScript 示例说明：**

```javascript
// 在 Chrome DevTools 控制台中或通过 JavaScript API 使用 Inspector

// 1. 拍摄堆快照
console.profile(); // 开始记录性能分析信息（隐式地可能包含堆快照）
// ... 你的代码 ...
console.profileEnd(); // 结束记录

// 或者使用 Memory 面板的 "Take heap snapshot" 按钮。

// 2. 启动和停止分配跟踪
console.time('allocationTracking'); // 开始计时，并可能触发分配跟踪
let myObject = {};
// ... 分配更多对象 ...
console.timeEnd('allocationTracking'); // 结束计时，并可能停止分配跟踪

// 或者在 Memory 面板中使用 "Allocation instrumentation on timeline" 功能。

// 3. 启动和停止采样
// 在 Memory 面板中使用 "Allocation sampling" 功能。

// 4. 强制垃圾回收
// 在 Memory 面板中使用 "Collect garbage" 按钮。

// 5. 检查堆快照中的对象 (通常在 Memory 面板中完成)
// 当你查看堆快照时，DevTools 会使用 Inspector 协议与 V8 通信，
// 并可能调用 `getObjectByHeapObjectId` 来获取特定对象的信息。
```

**代码逻辑推理 (假设输入与输出)：**

**场景：** 前端请求获取一个堆快照对象。

**假设输入：**
- `heapSnapshotObjectId`: "12345" (表示堆快照中某个对象的 ID)
- `objectGroup`: "myObjects" (可选的对象分组名称)

**代码逻辑（简化）：**
1. `getObjectByHeapObjectId` 方法被调用，传入 `heapSnapshotObjectId` 和 `objectGroup`。
2. `heapSnapshotObjectId` 被转换为整数 ID (12345)。
3. 使用 `objectByHeapObjectId` 函数，通过该 ID 在 V8 堆中查找对应的 `v8::Object`。
4. 如果找到对象，并且该对象是可检查的 (满足 `isInspectableHeapObject` 条件)，则获取其创建上下文。
5. 使用 `m_session->wrapObject` 将 V8 对象包装成 Inspector 的 `RemoteObject` 协议对象，并设置 `objectGroup`。

**假设输出：**
- 如果 ID 为 "12345" 的对象存在且可检查，则 `result` 指针将指向一个 `protocol::Runtime::RemoteObject` 对象，该对象描述了堆中的 JavaScript 对象，并属于 "myObjects" 分组。
- 如果对象不存在或不可检查，则返回一个 `Response::ServerError`，并且 `result` 为空。

**用户常见的编程错误示例：**

1. **内存泄漏 (Memory Leaks):** 开发者可能会创建大量的对象，但忘记释放它们的引用，导致这些对象一直存在于堆中，无法被垃圾回收。堆分析工具可以帮助识别这些泄漏。
   ```javascript
   let leakedObjects = [];
   function createLeak() {
     let obj = { data: new Array(10000) };
     leakedObjects.push(obj); // 忘记移除引用，导致 obj 无法被回收
   }

   setInterval(createLeak, 100); // 每 100 毫秒创建一个泄漏
   ```
   使用堆快照，你可以观察到 `leakedObjects` 数组的大小不断增长，以及堆中对象的数量持续增加。

2. **意外持有大对象 (Unintentional Retention of Large Objects):** 开发者可能在某个作用域意外地持有对大型对象的引用，导致这些对象在不应该存在的时候仍然存活。
   ```javascript
   function processData(largeData) {
     let tempResult = largeData.map(item => item * 2);
     // ... 使用 tempResult ...
     return tempResult; // 返回了对大数组的引用
   }

   let globalResult;
   function main() {
     let hugeArray = new Array(1000000).fill(0);
     globalResult = processData(hugeArray); // globalResult 持有对 hugeArray 结果的引用
     // 即使 main 函数执行完毕，globalResult 仍然指向一个大数组，阻止其被回收。
   }

   main();
   ```
   堆快照可以显示 `globalResult` 仍然引用着一个很大的数组，即使它可能不再需要了。

3. **闭包引起的意外对象存活 (Closure-Related Retention):** 闭包可以捕获外部作用域的变量，如果这些变量引用了大型对象，即使外部作用域已经结束，这些对象仍然可能存活。
   ```javascript
   function createCounter() {
     let count = 0;
     let largeObject = new ArrayBuffer(10 * 1024 * 1024); // 10MB
     return function() {
       count++;
       console.log(count);
       // largeObject 仍然被闭包捕获，即使 counter 函数本身已经返回。
     };
   }

   let myCounter = createCounter();
   myCounter();
   // largeObject 仍然存在于堆中，因为 myCounter 函数保持了对它的引用。
   ```
   堆分析可以揭示 `myCounter` 函数的闭包仍然持有对 `largeObject` 的引用。

通过使用 V8 的堆分析工具，开发者可以诊断这些常见的内存问题，并优化他们的 JavaScript 代码以提高性能和减少内存占用。`v8-heap-profiler-agent-impl.cc` 正是实现这些分析能力的关键组件。

### 提示词
```
这是目录为v8/src/inspector/v8-heap-profiler-agent-impl.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/v8-heap-profiler-agent-impl.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```