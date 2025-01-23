Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Scan and High-Level Understanding:**

* **Goal:** Understand the functionality of `v8/src/inspector/v8-debugger.cc`.
* **Keywords:** Immediately spot keywords related to debugging, like "Breakpoint," "Pause," "Continue," "Step," "Exception," "Async," "Stack."  This strongly suggests the file is central to V8's debugging capabilities exposed through the inspector.
* **Includes:** Examine the included headers. These provide clues about dependencies and functionalities:
    * `include/v8-*`:  Basic V8 API (context, function, microtask, profiler, util).
    * `src/inspector/*`:  Other inspector components (agents, protocol, utility functions).
    * `src/tracing/trace-event.h`:  Suggests involvement in tracing or logging.
* **Namespace:**  The code is within the `v8_inspector` namespace, confirming its role in the inspector framework.

**2. Deeper Dive into Core Components:**

* **Class `V8Debugger`:**  This is the main class. Its constructor and destructor are important starting points. The members give a sense of its state: `m_enableCount`, `m_pauseOnExceptionsState`, `m_pausedContextGroupId`, etc.
* **`enable()` and `disable()`:** These methods manage the debugger's lifecycle. Notice `v8::debug::SetDebugDelegate`,  `AddNearHeapLimitCallback`, and the handling of WebAssembly debugging.
* **Breakpoints:**  Look for methods related to breakpoints: `setBreakpointsActive`, `removeBreakpoint`.
* **Pausing and Continuing:**  Identify methods like `breakProgram`, `continueProgram`, `stepIntoStatement`, `stepOverStatement`, `stepOutOfFunction`. These are fundamental debugging actions.
* **Exceptions:**  Find `setPauseOnExceptionsState`, `handleProgramBreak` (which handles exceptions too), and `ExceptionThrown`.
* **Async Operations:** The presence of `AsyncEventOccurred`, `asyncTaskScheduledForStack`, etc., indicates support for debugging asynchronous JavaScript code.
* **Call Stack:** `V8StackTraceImpl` and methods like `capture` suggest handling of call stack information.
* **Contexts and Groups:**  Notice the frequent use of `contextGroupId`. This hints at how the debugger operates in a multi-context environment.

**3. Analyzing Key Methods and Logic:**

* **`handleProgramBreak()`:** This seems like the central point where the debugger pauses execution. Observe how it interacts with `V8InspectorSessionImpl` to notify debugger agents.
* **`nearHeapLimitCallback()`:**  This is interesting. It triggers a break when the heap is nearing its limit, useful for diagnosing memory issues.
* **`ScriptCompiled()`:**  This method informs debugger agents when new scripts are compiled.
* **`AsyncEventOccurred()`:** Understand how different Promise-related events trigger actions within the debugger.

**4. Identifying Potential JavaScript Connections:**

* **Direct Mapping:**  Many of the C++ methods have direct counterparts in JavaScript debugging APIs (e.g., setting breakpoints, stepping).
* **Inspector Protocol:** The mention of `protocol::Debugger::Location` hints at the communication mechanism between the browser's DevTools and V8.

**5. Anticipating Common Programming Errors:**

* **Uncaught Exceptions:** The `ExceptionThrown` method directly relates to this.
* **Asynchronous Issues:** The async event handling points to debugging problems in asynchronous code (callbacks, Promises, `async`/`await`).
* **Memory Leaks:** The `nearHeapLimitCallback` is relevant here.
* **Incorrect Breakpoint Placement/Conditions:**  Although not explicitly in the provided snippet, the existence of breakpoint-related functions implies these potential errors.

**6. Structuring the Output (Following the Prompt's Instructions):**

* **Functionality Listing:** Summarize the key functionalities based on the analyzed methods. Use clear and concise language.
* **Torque Check:** Verify the file extension.
* **JavaScript Relationship and Examples:**  Connect the C++ functionality to JavaScript debugging concepts and provide concrete JavaScript examples. Focus on demonstrating the *effect* of the C++ code.
* **Code Logic Reasoning (Hypothetical Input/Output):** Choose a specific scenario (like setting a breakpoint) and describe the expected flow, including hypothetical input and output.
* **Common Programming Errors:**  Provide practical examples of how the debugger features help in finding and fixing common JavaScript errors.
* **Summary:**  A brief overall summary of the file's purpose.

**Self-Correction/Refinement During the Process:**

* **Initial Over-Simplification:**  Avoid making overly simplistic statements early on. As you delve deeper, refine your understanding.
* **Focusing on the Core:**  Prioritize the most important functionalities. Don't get bogged down in every detail of every method.
* **Connecting the Dots:** Actively look for connections between different parts of the code and how they relate to the overall debugging process.
* **Using the Prompt as a Guide:** Ensure you address all the specific questions and requests in the prompt.

By following this structured approach, you can effectively analyze a piece of complex C++ code like the V8 debugger source and extract its core functionality and relevance to JavaScript debugging.
好的，让我们来分析一下 `v8/src/inspector/v8-debugger.cc` 这个 V8 源代码文件的功能。

**功能归纳:**

`v8/src/inspector/v8-debugger.cc` 是 V8 JavaScript 引擎中负责实现调试器核心逻辑的关键组件。它主要负责以下功能：

1. **管理调试器的生命周期:**  包括启用 (`enable`) 和禁用 (`disable`) 调试器，以及跟踪调试器是否激活的状态 (`enabled`).
2. **处理断点:**  允许设置、激活、停用和移除断点 (`setBreakpointsActive`, `removeBreakpoint`)。
3. **控制执行流程:**  提供单步执行 (`stepIntoStatement`, `stepOverStatement`, `stepOutOfFunction`)、继续执行 (`continueProgram`)、跳过函数执行 (`IsFunctionBlackboxed`) 等功能。
4. **处理异常:**  允许设置在异常发生时暂停执行 (`setPauseOnExceptionsState`)，并处理捕获到的异常 (`ExceptionThrown`).
5. **程序暂停:**  支持主动暂停程序执行 (`breakProgram`, `interruptAndBreak`)。
6. **异步操作调试:**  跟踪和管理异步事件（例如 Promise）的执行，以便进行调试 (`AsyncEventOccurred`, `asyncTaskScheduledForStack`, 等等)。
7. **调用栈管理:**  捕获和管理调用栈信息 (`V8StackTraceImpl`).
8. **处理 "继续到此处" 功能:**  允许用户在特定位置继续执行代码 (`continueToLocation`).
9. **帧重启:**  支持在调用栈中重启特定帧 (`restartFrame`).
10. **处理内存相关事件:**  响应堆内存限制即将到达的事件，并触发断点 (`nearHeapLimitCallback`)。
11. **脚本编译事件:**  监听脚本编译完成的事件，并通知调试器代理 (`ScriptCompiled`).
12. **插桩（Instrumentation）支持:**  处理与代码插桩相关的断点和暂停 (`BreakOnInstrumentation`).
13. **作用域管理:**  获取指定函数或生成器的作用域信息 (`getTargetScopes`, `functionScopes`).
14. **终止执行:**  允许终止当前正在执行的 JavaScript 代码 (`terminateExecution`).
15. **与调试器代理通信:**  与 `V8DebuggerAgentImpl` 协同工作，将调试事件通知到 Inspector 前端。

**关于文件类型:**

根据您的描述，如果 `v8/src/inspector/v8-debugger.cc` 以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码文件。由于这里的文件名是 `.cc`，所以它是一个 C++ 源代码文件。

**与 JavaScript 的关系 (以及 JavaScript 示例):**

`v8/src/inspector/v8-debugger.cc` 中的功能直接支持了我们在浏览器开发者工具 (DevTools) 中使用的 JavaScript 调试功能。以下是一些 JavaScript 示例，展示了 `v8-debugger.cc` 中相应功能的体现：

1. **设置断点:**

   ```javascript
   // 在 JavaScript 代码中设置断点 (实际上会触发 v8-debugger.cc 中的逻辑)
   function myFunction() {
     debugger; // 代码执行到这里会暂停
     console.log("Hello");
   }
   myFunction();
   ```

2. **单步执行 (Step Over, Step Into, Step Out):**

   在 DevTools 中点击相应的按钮（或者使用快捷键），会调用 `v8-debugger.cc` 中的 `stepOverStatement`, `stepIntoStatement`, `stepOutOfFunction` 等方法。

3. **继续执行:**

   在 DevTools 中点击 "继续执行" 按钮，会触发 `v8-debugger.cc` 中的 `continueProgram` 方法。

4. **在异常处暂停:**

   在 DevTools 的 "Sources" 面板中勾选 "Pause on caught exceptions" 或 "Pause on uncaught exceptions"，这会设置 `v8-debugger.cc` 中的 `m_pauseOnExceptionsState`。

   ```javascript
   try {
     throw new Error("Something went wrong!");
   } catch (e) {
     console.error("Caught an error:", e); // 如果设置了 "Pause on caught exceptions"，这里会暂停
   }

   // 未捕获的异常
   function willThrow() {
     throw new Error("Uncaught error!"); // 如果设置了 "Pause on uncaught exceptions"，这里会暂停
   }
   willThrow();
   ```

5. **异步操作调试:**

   当使用 DevTools 观察 Promise 或 `async/await` 代码的执行流程时，`v8-debugger.cc` 中的 `AsyncEventOccurred` 和相关的异步处理逻辑在幕后工作，帮助你理解异步操作的执行顺序和状态。

   ```javascript
   async function fetchData() {
     console.log("Fetching data...");
     const response = await fetch('https://example.com/data');
     const data = await response.json();
     console.log("Data fetched:", data);
     return data;
   }

   fetchData();
   ```

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

* 用户在 DevTools 中，在 `myScript.js` 的第 5 行设置了一个断点。
* JavaScript 代码执行到 `myScript.js` 的第 5 行。

**`v8-debugger.cc` 中的处理流程 (简化):**

1. V8 执行引擎遇到 `myScript.js` 的第 5 行。
2. `v8-debugger.cc` 中的断点管理逻辑检测到该行设置了断点。
3. `handleProgramBreak` 方法被调用。
4. `handleProgramBreak` 方法会：
   * 获取当前执行上下文的信息。
   * 通知相关的 `V8InspectorSessionImpl` (与 DevTools 的连接)。
   * `V8DebuggerAgentImpl::didPause` 方法被调用，将暂停事件和相关信息发送到 DevTools 前端。

**预期输出:**

* JavaScript 代码执行暂停。
* DevTools 前端显示代码执行到了 `myScript.js` 的第 5 行，并高亮显示该行。
* DevTools 允许用户查看作用域、调用栈等信息。

**用户常见的编程错误举例说明:**

`v8-debugger.cc` 的功能可以帮助开发者调试各种常见的编程错误，例如：

1. **逻辑错误:**  通过断点和单步执行，开发者可以跟踪代码的执行流程，观察变量的值，从而发现程序逻辑上的错误。

   ```javascript
   function calculateSum(a, b) {
     // 错误地使用了减法
     return a - b;
   }

   let result = calculateSum(5, 3); // 期望得到 8，实际得到 2
   console.log(result); // 通过断点观察到 result 的值不正确
   ```

2. **异步操作中的错误:**  调试异步代码（例如 Promise、`async/await`）的执行顺序和状态，例如：

   ```javascript
   async function fetchData() {
     try {
       const response = await fetch('invalid-url'); // 故意使用无效的 URL
       const data = await response.json();
       console.log(data);
     } catch (error) {
       console.error("Error fetching data:", error); // 通过在 catch 块中设置断点，可以检查错误信息
     }
   }
   fetchData();
   ```

3. **未捕获的异常:**  当程序抛出未捕获的异常时，调试器可以暂停执行，让开发者查看异常信息和调用栈，快速定位错误发生的位置。

   ```javascript
   function divide(a, b) {
     if (b === 0) {
       throw new Error("Cannot divide by zero");
     }
     return a / b;
   }

   let result = divide(10, 0); // 会抛出异常，如果设置了 "Pause on uncaught exceptions"，会在此处暂停
   console.log(result);
   ```

**总结一下 `v8/src/inspector/v8-debugger.cc` 的功能:**

总而言之，`v8/src/inspector/v8-debugger.cc` 是 V8 引擎中实现 JavaScript 调试功能的核心 C++ 源代码文件。它负责管理调试器的状态、处理断点、控制代码执行流程、处理异常、支持异步调试，并与 Inspector 前端进行通信，为开发者提供了强大的调试能力。

### 提示词
```
这是目录为v8/src/inspector/v8-debugger.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/v8-debugger.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/inspector/v8-debugger.h"

#include <algorithm>

#include "include/v8-container.h"
#include "include/v8-context.h"
#include "include/v8-function.h"
#include "include/v8-microtask-queue.h"
#include "include/v8-profiler.h"
#include "include/v8-util.h"
#include "src/inspector/inspected-context.h"
#include "src/inspector/protocol/Protocol.h"
#include "src/inspector/string-util.h"
#include "src/inspector/v8-debugger-agent-impl.h"
#include "src/inspector/v8-heap-profiler-agent-impl.h"
#include "src/inspector/v8-inspector-impl.h"
#include "src/inspector/v8-inspector-session-impl.h"
#include "src/inspector/v8-runtime-agent-impl.h"
#include "src/inspector/v8-stack-trace-impl.h"
#include "src/inspector/v8-value-utils.h"
#include "src/tracing/trace-event.h"

namespace v8_inspector {

namespace {

static const size_t kMaxAsyncTaskStacks = 8 * 1024;
static const size_t kMaxExternalParents = 1 * 1024;
static const int kNoBreakpointId = 0;

template <typename Map>
void cleanupExpiredWeakPointers(Map& map) {
  for (auto it = map.begin(); it != map.end();) {
    if (it->second.expired()) {
      it = map.erase(it);
    } else {
      ++it;
    }
  }
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
START_ALLOW_USE_DEPRECATED()

class MatchPrototypePredicate : public v8::QueryObjectPredicate {
 public:
  MatchPrototypePredicate(V8InspectorImpl* inspector,
                          v8::Local<v8::Context> context,
                          v8::Local<v8::Object> prototype)
      : m_inspector(inspector), m_context(context), m_prototype(prototype) {}

  bool Filter(v8::Local<v8::Object> object) override {
    if (object->IsModuleNamespaceObject()) return false;
    v8::Local<v8::Context> objectContext;
    if (!v8::debug::GetCreationContext(object).ToLocal(&objectContext)) {
      return false;
    }
    if (objectContext != m_context) return false;
    if (!m_inspector->client()->isInspectableHeapObject(object)) return false;
    // Get prototype chain for current object until first visited prototype.
    for (v8::Local<v8::Value> prototype = object->GetPrototype();
         prototype->IsObject();
         prototype = prototype.As<v8::Object>()->GetPrototype()) {
      if (m_prototype == prototype) return true;
    }
    return false;
  }

 private:
  V8InspectorImpl* m_inspector;
  v8::Local<v8::Context> m_context;
  v8::Local<v8::Value> m_prototype;
};

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
END_ALLOW_USE_DEPRECATED()

}  // namespace

V8Debugger::V8Debugger(v8::Isolate* isolate, V8InspectorImpl* inspector)
    : m_isolate(isolate),
      m_inspector(inspector),
      m_enableCount(0),
      m_ignoreScriptParsedEventsCounter(0),
      m_continueToLocationBreakpointId(kNoBreakpointId),
      m_maxAsyncCallStacks(kMaxAsyncTaskStacks),
      m_maxAsyncCallStackDepth(0),
      m_maxCallStackSizeToCapture(
          V8StackTraceImpl::kDefaultMaxCallStackSizeToCapture),
      m_pauseOnExceptionsState(v8::debug::NoBreakOnException) {}

V8Debugger::~V8Debugger() {
  m_isolate->RemoveCallCompletedCallback(
      &V8Debugger::terminateExecutionCompletedCallback);
  if (!m_terminateExecutionCallbackContext.IsEmpty()) {
    v8::HandleScope handles(m_isolate);
    v8::MicrotaskQueue* microtask_queue =
        m_terminateExecutionCallbackContext.Get(m_isolate)->GetMicrotaskQueue();
    microtask_queue->RemoveMicrotasksCompletedCallback(
        &V8Debugger::terminateExecutionCompletedCallbackIgnoringData,
        microtask_queue);
  }
}

void V8Debugger::enable() {
  if (m_enableCount++) return;
  v8::HandleScope scope(m_isolate);
  v8::debug::SetDebugDelegate(m_isolate, this);
  m_isolate->AddNearHeapLimitCallback(&V8Debugger::nearHeapLimitCallback, this);
  v8::debug::ChangeBreakOnException(m_isolate, v8::debug::NoBreakOnException);
  m_pauseOnExceptionsState = v8::debug::NoBreakOnException;
#if V8_ENABLE_WEBASSEMBLY
  v8::debug::EnterDebuggingForIsolate(m_isolate);
#endif  // V8_ENABLE_WEBASSEMBLY
}

void V8Debugger::disable() {
  if (isPaused()) {
    bool scheduledOOMBreak = m_scheduledOOMBreak;
    bool hasAgentAcceptsPause = false;

    if (m_instrumentationPause) {
      quitMessageLoopIfAgentsFinishedInstrumentation();
    } else {
      m_inspector->forEachSession(
          m_pausedContextGroupId, [&scheduledOOMBreak, &hasAgentAcceptsPause](
                                      V8InspectorSessionImpl* session) {
            if (session->debuggerAgent()->acceptsPause(scheduledOOMBreak)) {
              hasAgentAcceptsPause = true;
            }
          });
      if (!hasAgentAcceptsPause)
        m_inspector->client()->quitMessageLoopOnPause();
    }
  }
  if (--m_enableCount) return;
  clearContinueToLocation();
  m_taskWithScheduledBreak = nullptr;
  m_externalAsyncTaskPauseRequested = false;
  m_taskWithScheduledBreakPauseRequested = false;
  m_pauseOnNextCallRequested = false;
  m_pauseOnAsyncCall = false;
#if V8_ENABLE_WEBASSEMBLY
  v8::debug::LeaveDebuggingForIsolate(m_isolate);
#endif  // V8_ENABLE_WEBASSEMBLY
  v8::debug::SetDebugDelegate(m_isolate, nullptr);
  m_isolate->RemoveNearHeapLimitCallback(&V8Debugger::nearHeapLimitCallback,
                                         m_originalHeapLimit);
  m_originalHeapLimit = 0;
}

bool V8Debugger::isPausedInContextGroup(int contextGroupId) const {
  return isPaused() && m_pausedContextGroupId == contextGroupId;
}

bool V8Debugger::enabled() const { return m_enableCount > 0; }

std::vector<std::unique_ptr<V8DebuggerScript>> V8Debugger::getCompiledScripts(
    int contextGroupId, V8DebuggerAgentImpl* agent) {
  std::vector<std::unique_ptr<V8DebuggerScript>> result;
  v8::HandleScope scope(m_isolate);
  std::vector<v8::Global<v8::debug::Script>> scripts;
  v8::debug::GetLoadedScripts(m_isolate, scripts);
  for (size_t i = 0; i < scripts.size(); ++i) {
    v8::Local<v8::debug::Script> script = scripts[i].Get(m_isolate);
    if (!script->WasCompiled()) continue;
    if (!script->IsEmbedded()) {
      int contextId;
      if (!script->ContextId().To(&contextId)) continue;
      if (m_inspector->contextGroupId(contextId) != contextGroupId) continue;
    }
    result.push_back(V8DebuggerScript::Create(m_isolate, script, false, agent,
                                              m_inspector->client()));
  }
  return result;
}

void V8Debugger::setBreakpointsActive(bool active) {
  if (!enabled()) {
    UNREACHABLE();
  }
  m_breakpointsActiveCount += active ? 1 : -1;
  DCHECK_GE(m_breakpointsActiveCount, 0);
  v8::debug::SetBreakPointsActive(m_isolate, m_breakpointsActiveCount);
}

void V8Debugger::removeBreakpoint(v8::debug::BreakpointId id) {
  v8::debug::RemoveBreakpoint(m_isolate, id);
}

v8::debug::ExceptionBreakState V8Debugger::getPauseOnExceptionsState() {
  DCHECK(enabled());
  return m_pauseOnExceptionsState;
}

void V8Debugger::setPauseOnExceptionsState(
    v8::debug::ExceptionBreakState pauseOnExceptionsState) {
  DCHECK(enabled());
  if (m_pauseOnExceptionsState == pauseOnExceptionsState) return;
  v8::debug::ChangeBreakOnException(m_isolate, pauseOnExceptionsState);
  m_pauseOnExceptionsState = pauseOnExceptionsState;
}

void V8Debugger::setPauseOnNextCall(bool pause, int targetContextGroupId) {
  if (isPaused()) return;
  DCHECK(targetContextGroupId);
  if (!pause && m_targetContextGroupId &&
      m_targetContextGroupId != targetContextGroupId) {
    return;
  }
  if (pause) {
    bool didHaveBreak = hasScheduledBreakOnNextFunctionCall();
    m_pauseOnNextCallRequested = true;
    if (!didHaveBreak) {
      m_targetContextGroupId = targetContextGroupId;
      v8::debug::SetBreakOnNextFunctionCall(m_isolate);
    }
  } else {
    m_pauseOnNextCallRequested = false;
    if (!hasScheduledBreakOnNextFunctionCall()) {
      v8::debug::ClearBreakOnNextFunctionCall(m_isolate);
    }
  }
}

bool V8Debugger::canBreakProgram() {
  return v8::debug::CanBreakProgram(m_isolate);
}

bool V8Debugger::isInInstrumentationPause() const {
  return m_instrumentationPause;
}

void V8Debugger::breakProgram(int targetContextGroupId) {
  DCHECK(canBreakProgram());
  // Don't allow nested breaks.
  if (isPaused()) return;
  DCHECK(targetContextGroupId);
  m_targetContextGroupId = targetContextGroupId;
  v8::debug::BreakRightNow(m_isolate);
}

void V8Debugger::interruptAndBreak(int targetContextGroupId) {
  // Don't allow nested breaks.
  if (isPaused()) return;
  DCHECK(targetContextGroupId);
  m_targetContextGroupId = targetContextGroupId;
  m_isolate->RequestInterrupt(
      [](v8::Isolate* isolate, void*) {
        v8::debug::BreakRightNow(
            isolate,
            v8::debug::BreakReasons({v8::debug::BreakReason::kScheduled}));
      },
      nullptr);
}

void V8Debugger::requestPauseAfterInstrumentation() {
  m_requestedPauseAfterInstrumentation = true;
}

void V8Debugger::quitMessageLoopIfAgentsFinishedInstrumentation() {
  bool allAgentsFinishedInstrumentation = true;
  m_inspector->forEachSession(
      m_pausedContextGroupId,
      [&allAgentsFinishedInstrumentation](V8InspectorSessionImpl* session) {
        if (!session->debuggerAgent()->instrumentationFinished()) {
          allAgentsFinishedInstrumentation = false;
        }
      });
  if (allAgentsFinishedInstrumentation) {
    m_inspector->client()->quitMessageLoopOnPause();
  }
}

void V8Debugger::continueProgram(int targetContextGroupId,
                                 bool terminateOnResume) {
  if (m_pausedContextGroupId != targetContextGroupId) return;
  if (isPaused()) {
    if (m_instrumentationPause) {
      quitMessageLoopIfAgentsFinishedInstrumentation();
    } else if (terminateOnResume) {
      v8::debug::SetTerminateOnResume(m_isolate);

      v8::HandleScope handles(m_isolate);
      v8::Local<v8::Context> context =
          m_inspector->client()->ensureDefaultContextInGroup(
              targetContextGroupId);
      installTerminateExecutionCallbacks(context);

      m_inspector->client()->quitMessageLoopOnPause();
    } else {
      m_inspector->client()->quitMessageLoopOnPause();
    }
  }
}

void V8Debugger::breakProgramOnAssert(int targetContextGroupId) {
  if (!enabled()) return;
  if (m_pauseOnExceptionsState == v8::debug::NoBreakOnException) return;
  // Don't allow nested breaks.
  if (isPaused()) return;
  if (!canBreakProgram()) return;
  DCHECK(targetContextGroupId);
  m_targetContextGroupId = targetContextGroupId;
  v8::debug::BreakRightNow(
      m_isolate, v8::debug::BreakReasons({v8::debug::BreakReason::kAssert}));
}

void V8Debugger::stepIntoStatement(int targetContextGroupId,
                                   bool breakOnAsyncCall) {
  DCHECK(isPaused());
  DCHECK(targetContextGroupId);
  m_targetContextGroupId = targetContextGroupId;
  m_pauseOnAsyncCall = breakOnAsyncCall;
  v8::debug::PrepareStep(m_isolate, v8::debug::StepInto);
  continueProgram(targetContextGroupId);
}

void V8Debugger::stepOverStatement(int targetContextGroupId) {
  DCHECK(isPaused());
  DCHECK(targetContextGroupId);
  m_targetContextGroupId = targetContextGroupId;
  v8::debug::PrepareStep(m_isolate, v8::debug::StepOver);
  continueProgram(targetContextGroupId);
}

void V8Debugger::stepOutOfFunction(int targetContextGroupId) {
  DCHECK(isPaused());
  DCHECK(targetContextGroupId);
  m_targetContextGroupId = targetContextGroupId;
  v8::debug::PrepareStep(m_isolate, v8::debug::StepOut);
  continueProgram(targetContextGroupId);
}

void V8Debugger::terminateExecution(
    v8::Local<v8::Context> context,
    std::unique_ptr<TerminateExecutionCallback> callback) {
  if (!m_terminateExecutionReported) {
    if (callback) {
      callback->sendFailure(Response::ServerError(
          "There is current termination request in progress"));
    }
    return;
  }
  m_terminateExecutionCallback = std::move(callback);
  installTerminateExecutionCallbacks(context);
  m_isolate->TerminateExecution();
}

void V8Debugger::installTerminateExecutionCallbacks(
    v8::Local<v8::Context> context) {
  m_isolate->AddCallCompletedCallback(
      &V8Debugger::terminateExecutionCompletedCallback);

  if (!context.IsEmpty()) {
    m_terminateExecutionCallbackContext.Reset(m_isolate, context);
    m_terminateExecutionCallbackContext.SetWeak();
    v8::MicrotaskQueue* microtask_queue = context->GetMicrotaskQueue();
    microtask_queue->AddMicrotasksCompletedCallback(
        &V8Debugger::terminateExecutionCompletedCallbackIgnoringData,
        microtask_queue);
  }

  DCHECK(m_terminateExecutionReported);
  m_terminateExecutionReported = false;
}

void V8Debugger::reportTermination() {
  if (m_terminateExecutionReported) {
    DCHECK(m_terminateExecutionCallbackContext.IsEmpty());
    return;
  }
  v8::HandleScope handles(m_isolate);
  m_isolate->RemoveCallCompletedCallback(
      &V8Debugger::terminateExecutionCompletedCallback);
  if (!m_terminateExecutionCallbackContext.IsEmpty()) {
    v8::MicrotaskQueue* microtask_queue =
        m_terminateExecutionCallbackContext.Get(m_isolate)->GetMicrotaskQueue();
    if (microtask_queue) {
      microtask_queue->RemoveMicrotasksCompletedCallback(
          &V8Debugger::terminateExecutionCompletedCallbackIgnoringData,
          microtask_queue);
    }
  }
  m_isolate->CancelTerminateExecution();
  if (m_terminateExecutionCallback) {
    m_terminateExecutionCallback->sendSuccess();
    m_terminateExecutionCallback.reset();
  }
  m_terminateExecutionCallbackContext.Reset();
  m_terminateExecutionReported = true;
}

void V8Debugger::terminateExecutionCompletedCallback(v8::Isolate* isolate) {
  V8InspectorImpl* inspector =
      static_cast<V8InspectorImpl*>(v8::debug::GetInspector(isolate));
  V8Debugger* debugger = inspector->debugger();
  debugger->reportTermination();
}

void V8Debugger::terminateExecutionCompletedCallbackIgnoringData(
    v8::Isolate* isolate, void* data) {
  DCHECK(data);
  // Ensure that after every microtask completed callback we remove the
  // callback regardless of how `terminateExecutionCompletedCallback` behaves.
  static_cast<v8::MicrotaskQueue*>(data)->RemoveMicrotasksCompletedCallback(
      &V8Debugger::terminateExecutionCompletedCallbackIgnoringData, data);
  terminateExecutionCompletedCallback(isolate);
}

Response V8Debugger::continueToLocation(
    int targetContextGroupId, V8DebuggerScript* script,
    std::unique_ptr<protocol::Debugger::Location> location,
    const String16& targetCallFrames) {
  DCHECK(isPaused());
  DCHECK(targetContextGroupId);
  m_targetContextGroupId = targetContextGroupId;
  v8::debug::Location v8Location(location->getLineNumber(),
                                 location->getColumnNumber(0));
  if (script->setBreakpoint(String16(), &v8Location,
                            &m_continueToLocationBreakpointId)) {
    m_continueToLocationTargetCallFrames = targetCallFrames;
    if (m_continueToLocationTargetCallFrames !=
        protocol::Debugger::ContinueToLocation::TargetCallFramesEnum::Any) {
      m_continueToLocationStack = V8StackTraceImpl::capture(
          this, V8StackTraceImpl::kDefaultMaxCallStackSizeToCapture);
      DCHECK(m_continueToLocationStack);
    }
    continueProgram(targetContextGroupId);
    // TODO(kozyatinskiy): Return actual line and column number.
    return Response::Success();
  } else {
    return Response::ServerError("Cannot continue to specified location");
  }
}

bool V8Debugger::restartFrame(int targetContextGroupId, int callFrameOrdinal) {
  DCHECK(isPaused());
  DCHECK(targetContextGroupId);
  m_targetContextGroupId = targetContextGroupId;

  if (v8::debug::PrepareRestartFrame(m_isolate, callFrameOrdinal)) {
    continueProgram(targetContextGroupId);
    return true;
  }
  return false;
}

bool V8Debugger::shouldContinueToCurrentLocation() {
  if (m_continueToLocationTargetCallFrames ==
      protocol::Debugger::ContinueToLocation::TargetCallFramesEnum::Any) {
    return true;
  }
  std::unique_ptr<V8StackTraceImpl> currentStack = V8StackTraceImpl::capture(
      this, V8StackTraceImpl::kDefaultMaxCallStackSizeToCapture);
  if (m_continueToLocationTargetCallFrames ==
      protocol::Debugger::ContinueToLocation::TargetCallFramesEnum::Current) {
    return m_continueToLocationStack->isEqualIgnoringTopFrame(
        currentStack.get());
  }
  return true;
}

void V8Debugger::clearContinueToLocation() {
  if (m_continueToLocationBreakpointId == kNoBreakpointId) return;
  v8::debug::RemoveBreakpoint(m_isolate, m_continueToLocationBreakpointId);
  m_continueToLocationBreakpointId = kNoBreakpointId;
  m_continueToLocationTargetCallFrames = String16();
  m_continueToLocationStack.reset();
}

void V8Debugger::handleProgramBreak(
    v8::Local<v8::Context> pausedContext, v8::Local<v8::Value> exception,
    const std::vector<v8::debug::BreakpointId>& breakpointIds,
    v8::debug::BreakReasons breakReasons,
    v8::debug::ExceptionType exceptionType, bool isUncaught) {
  // Don't allow nested breaks.
  if (isPaused()) return;

  int contextGroupId = m_inspector->contextGroupId(pausedContext);
  if (m_targetContextGroupId && contextGroupId != m_targetContextGroupId) {
    v8::debug::PrepareStep(m_isolate, v8::debug::StepOut);
    return;
  }

  DCHECK(hasScheduledBreakOnNextFunctionCall() ==
         (m_taskWithScheduledBreakPauseRequested ||
          m_externalAsyncTaskPauseRequested || m_pauseOnNextCallRequested));
  if (m_taskWithScheduledBreakPauseRequested ||
      m_externalAsyncTaskPauseRequested)
    breakReasons.Add(v8::debug::BreakReason::kAsyncStep);
  if (m_pauseOnNextCallRequested)
    breakReasons.Add(v8::debug::BreakReason::kAgent);

  m_targetContextGroupId = 0;
  m_pauseOnNextCallRequested = false;
  m_pauseOnAsyncCall = false;
  m_taskWithScheduledBreak = nullptr;
  m_externalAsyncTaskPauseRequested = false;
  m_taskWithScheduledBreakPauseRequested = false;

  bool scheduledOOMBreak = m_scheduledOOMBreak;
  DCHECK(scheduledOOMBreak ==
         breakReasons.contains(v8::debug::BreakReason::kOOM));
  bool hasAgents = false;

  m_inspector->forEachSession(
      contextGroupId,
      [&scheduledOOMBreak, &hasAgents](V8InspectorSessionImpl* session) {
        if (session->debuggerAgent()->acceptsPause(scheduledOOMBreak))
          hasAgents = true;
      });
  if (!hasAgents) return;

  if (breakpointIds.size() == 1 &&
      breakpointIds[0] == m_continueToLocationBreakpointId) {
    v8::Context::Scope contextScope(pausedContext);
    if (!shouldContinueToCurrentLocation()) return;
  }
  clearContinueToLocation();

  DCHECK(contextGroupId);
  m_pausedContextGroupId = contextGroupId;

  m_inspector->forEachSession(
      contextGroupId,
      [&pausedContext, &exception, &breakpointIds, &exceptionType, &isUncaught,
       &scheduledOOMBreak, &breakReasons](V8InspectorSessionImpl* session) {
        if (session->debuggerAgent()->acceptsPause(scheduledOOMBreak)) {
          session->debuggerAgent()->didPause(
              InspectedContext::contextId(pausedContext), exception,
              breakpointIds, exceptionType, isUncaught, breakReasons);
        }
      });
  {
    v8::Context::Scope scope(pausedContext);

    m_inspector->forEachSession(
        contextGroupId, [](V8InspectorSessionImpl* session) {
          if (session->heapProfilerAgent()) {
            session->heapProfilerAgent()->takePendingHeapSnapshots();
          }
        });

    m_inspector->client()->runMessageLoopOnPause(contextGroupId);
    m_pausedContextGroupId = 0;
  }
  m_inspector->forEachSession(contextGroupId,
                              [](V8InspectorSessionImpl* session) {
                                if (session->debuggerAgent()->enabled()) {
                                  session->debuggerAgent()->clearBreakDetails();
                                  session->debuggerAgent()->didContinue();
                                }
                              });

  if (m_scheduledOOMBreak) m_isolate->RestoreOriginalHeapLimit();
  m_scheduledOOMBreak = false;
}

namespace {

size_t HeapLimitForDebugging(size_t initial_heap_limit) {
  const size_t kDebugHeapSizeFactor = 4;
  size_t max_limit = std::numeric_limits<size_t>::max() / 4;
  return std::min(max_limit, initial_heap_limit * kDebugHeapSizeFactor);
}

}  // anonymous namespace

size_t V8Debugger::nearHeapLimitCallback(void* data, size_t current_heap_limit,
                                         size_t initial_heap_limit) {
  V8Debugger* thisPtr = static_cast<V8Debugger*>(data);
  thisPtr->m_originalHeapLimit = current_heap_limit;
  thisPtr->m_scheduledOOMBreak = true;
  v8::Local<v8::Context> context =
      thisPtr->m_isolate->GetEnteredOrMicrotaskContext();
  thisPtr->m_targetContextGroupId =
      context.IsEmpty() ? 0 : thisPtr->m_inspector->contextGroupId(context);
  thisPtr->m_isolate->RequestInterrupt(
      [](v8::Isolate* isolate, void*) {
        // There's a redundancy  between setting `m_scheduledOOMBreak` and
        // passing the reason along in `BreakRightNow`. The
        // `m_scheduledOOMBreak` is used elsewhere, so we cannot remove it. And
        // for being explicit, we still pass the break reason along.
        v8::debug::BreakRightNow(
            isolate, v8::debug::BreakReasons({v8::debug::BreakReason::kOOM}));
      },
      nullptr);
  return HeapLimitForDebugging(initial_heap_limit);
}

void V8Debugger::ScriptCompiled(v8::Local<v8::debug::Script> script,
                                bool is_live_edited, bool has_compile_error) {
  if (m_ignoreScriptParsedEventsCounter != 0) return;

  int contextId;
  if (!script->ContextId().To(&contextId)) return;

  v8::Isolate* isolate = m_isolate;
  V8InspectorClient* client = m_inspector->client();

  m_inspector->forEachSession(
      m_inspector->contextGroupId(contextId),
      [isolate, &script, has_compile_error, is_live_edited,
       client](V8InspectorSessionImpl* session) {
        auto agent = session->debuggerAgent();
        if (!agent->enabled()) return;
        agent->didParseSource(
            V8DebuggerScript::Create(isolate, script, is_live_edited, agent,
                                     client),
            !has_compile_error);
      });
}

V8Debugger::ActionAfterInstrumentation V8Debugger::BreakOnInstrumentation(
    v8::Local<v8::Context> pausedContext,
    v8::debug::BreakpointId instrumentationId) {
  // Don't allow nested breaks.
  if (isPaused()) return ActionAfterInstrumentation::kPauseIfBreakpointsHit;

  int contextGroupId = m_inspector->contextGroupId(pausedContext);
  bool hasAgents = false;
  m_inspector->forEachSession(
      contextGroupId, [&hasAgents](V8InspectorSessionImpl* session) {
        if (session->debuggerAgent()->acceptsPause(false /* isOOMBreak */))
          hasAgents = true;
      });
  if (!hasAgents) return ActionAfterInstrumentation::kPauseIfBreakpointsHit;

  m_pausedContextGroupId = contextGroupId;
  m_instrumentationPause = true;
  m_inspector->forEachSession(
      contextGroupId, [instrumentationId](V8InspectorSessionImpl* session) {
        if (session->debuggerAgent()->acceptsPause(false /* isOOMBreak */)) {
          session->debuggerAgent()->didPauseOnInstrumentation(
              instrumentationId);
        }
      });
  {
    v8::Context::Scope scope(pausedContext);
    m_inspector->client()->runMessageLoopOnInstrumentationPause(contextGroupId);
  }
  bool requestedPauseAfterInstrumentation =
      m_requestedPauseAfterInstrumentation;

  m_requestedPauseAfterInstrumentation = false;
  m_pausedContextGroupId = 0;
  m_instrumentationPause = false;

  hasAgents = false;
  m_inspector->forEachSession(
      contextGroupId, [&hasAgents](V8InspectorSessionImpl* session) {
        if (session->debuggerAgent()->enabled())
          session->debuggerAgent()->didContinue();
        if (session->debuggerAgent()->acceptsPause(false /* isOOMBreak */))
          hasAgents = true;
      });
  if (!hasAgents) {
    return ActionAfterInstrumentation::kContinue;
  } else if (requestedPauseAfterInstrumentation) {
    return ActionAfterInstrumentation::kPause;
  } else {
    return ActionAfterInstrumentation::kPauseIfBreakpointsHit;
  }
}

void V8Debugger::BreakProgramRequested(
    v8::Local<v8::Context> pausedContext,
    const std::vector<v8::debug::BreakpointId>& break_points_hit,
    v8::debug::BreakReasons reasons) {
  handleProgramBreak(pausedContext, v8::Local<v8::Value>(), break_points_hit,
                     reasons);
}

void V8Debugger::ExceptionThrown(v8::Local<v8::Context> pausedContext,
                                 v8::Local<v8::Value> exception,
                                 v8::Local<v8::Value> promise, bool isUncaught,
                                 v8::debug::ExceptionType exceptionType) {
  std::vector<v8::debug::BreakpointId> break_points_hit;
  handleProgramBreak(
      pausedContext, exception, break_points_hit,
      v8::debug::BreakReasons({v8::debug::BreakReason::kException}),
      exceptionType, isUncaught);
}

bool V8Debugger::IsFunctionBlackboxed(v8::Local<v8::debug::Script> script,
                                      const v8::debug::Location& start,
                                      const v8::debug::Location& end) {
  int contextId;
  if (!script->ContextId().To(&contextId)) return false;
  bool hasAgents = false;
  bool allBlackboxed = true;
  String16 scriptId = String16::fromInteger(script->Id());
  m_inspector->forEachSession(
      m_inspector->contextGroupId(contextId),
      [&hasAgents, &allBlackboxed, &scriptId, &start,
       &end](V8InspectorSessionImpl* session) {
        V8DebuggerAgentImpl* agent = session->debuggerAgent();
        if (!agent->enabled()) return;
        hasAgents = true;
        allBlackboxed &= agent->isFunctionBlackboxed(scriptId, start, end);
      });
  return hasAgents && allBlackboxed;
}

bool V8Debugger::ShouldBeSkipped(v8::Local<v8::debug::Script> script, int line,
                                 int column) {
  int contextId;
  if (!script->ContextId().To(&contextId)) return false;

  bool hasAgents = false;
  bool allShouldBeSkipped = true;
  String16 scriptId = String16::fromInteger(script->Id());
  m_inspector->forEachSession(
      m_inspector->contextGroupId(contextId),
      [&hasAgents, &allShouldBeSkipped, &scriptId, line,
       column](V8InspectorSessionImpl* session) {
        V8DebuggerAgentImpl* agent = session->debuggerAgent();
        if (!agent->enabled()) return;
        hasAgents = true;
        const bool skip = agent->shouldBeSkipped(scriptId, line, column);
        allShouldBeSkipped &= skip;
      });
  return hasAgents && allShouldBeSkipped;
}

void V8Debugger::BreakpointConditionEvaluated(
    v8::Local<v8::Context> context, v8::debug::BreakpointId breakpoint_id,
    bool exception_thrown, v8::Local<v8::Value> exception) {
  if (!exception_thrown || exception.IsEmpty()) return;

  v8::Local<v8::Message> message =
      v8::debug::CreateMessageFromException(isolate(), exception);
  v8::ScriptOrigin origin = message->GetScriptOrigin();
  String16 url;
  if (origin.ResourceName()->IsString()) {
    url = toProtocolString(isolate(), origin.ResourceName().As<v8::String>());
  }
  // The message text is prepended to the exception text itself so we don't
  // need to get it from the v8::Message.
  StringView messageText;
  StringView detailedMessage;
  m_inspector->exceptionThrown(
      context, messageText, exception, detailedMessage, toStringView(url),
      message->GetLineNumber(context).FromMaybe(0),
      message->GetStartColumn() + 1, createStackTrace(message->GetStackTrace()),
      origin.ScriptId());
}

void V8Debugger::AsyncEventOccurred(v8::debug::DebugAsyncActionType type,
                                    int id, bool isBlackboxed) {
  // Async task events from Promises are given misaligned pointers to prevent
  // from overlapping with other Blink task identifiers.
  void* task = reinterpret_cast<void*>(id * 2 + 1);
  switch (type) {
    case v8::debug::kDebugPromiseThen:
      asyncTaskScheduledForStack(toStringView("Promise.then"), task, false);
      if (!isBlackboxed) asyncTaskCandidateForStepping(task);
      break;
    case v8::debug::kDebugPromiseCatch:
      asyncTaskScheduledForStack(toStringView("Promise.catch"), task, false);
      if (!isBlackboxed) asyncTaskCandidateForStepping(task);
      break;
    case v8::debug::kDebugPromiseFinally:
      asyncTaskScheduledForStack(toStringView("Promise.finally"), task, false);
      if (!isBlackboxed) asyncTaskCandidateForStepping(task);
      break;
    case v8::debug::kDebugWillHandle:
      asyncTaskStartedForStack(task);
      asyncTaskStartedForStepping(task);
      break;
    case v8::debug::kDebugDidHandle:
      asyncTaskFinishedForStack(task);
      asyncTaskFinishedForStepping(task);
      break;
    case v8::debug::kDebugAwait:
      asyncTaskScheduledForStack(toStringView("await"), task, false, true);
      break;
    case v8::debug::kDebugStackTraceCaptured:
      asyncStackTraceCaptured(id);
      break;
  }
}

std::shared_ptr<AsyncStackTrace> V8Debugger::currentAsyncParent() {
  return m_currentAsyncParent.empty() ? nullptr : m_currentAsyncParent.back();
}

V8StackTraceId V8Debugger::currentExternalParent() {
  return m_currentExternalParent.empty() ? V8StackTraceId()
                                         : m_currentExternalParent.back();
}

v8::MaybeLocal<v8::Value> V8Debugger::getTargetScopes(
    v8::Local<v8::Context> context, v8::Local<v8::Value> value,
    ScopeTargetKind kind) {
  std::unique_ptr<v8::debug::ScopeIterator> iterator;
  switch (kind) {
    case FUNCTION:
      iterator = v8::debug::ScopeIterator::CreateForFunction(
          m_isolate, value.As<v8::Function>());
      break;
    case GENERATOR:
      v8::Local<v8::debug::GeneratorObject> generatorObject =
          v8::debug::GeneratorObject::Cast(value);
      if (!generatorObject->IsSuspended()) return v8::MaybeLocal<v8::Value>();

      iterator = v8::debug::ScopeIterator::CreateForGeneratorObject(
          m_isolate, value.As<v8::Object>());
      break;
  }
  if (!iterator) return v8::MaybeLocal<v8::Value>();
  v8::Local<v8::Array> result = v8::Array::New(m_isolate);
  if (!result->SetPrototypeV2(context, v8::Null(m_isolate)).FromMaybe(false)) {
    return v8::MaybeLocal<v8::Value>();
  }

  for (; !iterator->Done(); iterator->Advance()) {
    v8::Local<v8::Object> scope = v8::Object::New(m_isolate);
    if (!addInternalObject(context, scope, V8InternalValueType::kScope))
      return v8::MaybeLocal<v8::Value>();
    String16 nameSuffix = toProtocolStringWithTypeCheck(
        m_isolate, iterator->GetFunctionDebugName());
    String16 description;
    if (nameSuffix.length()) nameSuffix = " (" + nameSuffix + ")";
    switch (iterator->GetType()) {
      case v8::debug::ScopeIterator::ScopeTypeGlobal:
        description = "Global" + nameSuffix;
        break;
      case v8::debug::ScopeIterator::ScopeTypeLocal:
        description = "Local" + nameSuffix;
        break;
      case v8::debug::ScopeIterator::ScopeTypeWith:
        description = "With Block" + nameSuffix;
        break;
      case v8::debug::ScopeIterator::ScopeTypeClosure:
        description = "Closure" + nameSuffix;
        break;
      case v8::debug::ScopeIterator::ScopeTypeCatch:
        description = "Catch" + nameSuffix;
        break;
      case v8::debug::ScopeIterator::ScopeTypeBlock:
        description = "Block" + nameSuffix;
        break;
      case v8::debug::ScopeIterator::ScopeTypeScript:
        description = "Script" + nameSuffix;
        break;
      case v8::debug::ScopeIterator::ScopeTypeEval:
        description = "Eval" + nameSuffix;
        break;
      case v8::debug::ScopeIterator::ScopeTypeModule:
        description = "Module" + nameSuffix;
        break;
      case v8::debug::ScopeIterator::ScopeTypeWasmExpressionStack:
        description = "Wasm Expression Stack" + nameSuffix;
        break;
    }
    v8::Local<v8::Object> object = iterator->GetObject();
    createDataProperty(context, scope,
                       toV8StringInternalized(m_isolate, "description"),
                       toV8String(m_isolate, description));
    createDataProperty(context, scope,
                       toV8StringInternalized(m_isolate, "object"), object);
    createDataProperty(context, result, result->Length(), scope);
  }
  if (!addInternalObject(context, result, V8InternalValueType::kScopeList))
    return v8::MaybeLocal<v8::Value>();
  return result;
}

v8::MaybeLocal<v8::Value> V8Debugger::functionScopes(
    v8::Local<v8::Context> context, v8::Local<v8::Function> function) {
  return getTargetScopes(context, function, FU
```