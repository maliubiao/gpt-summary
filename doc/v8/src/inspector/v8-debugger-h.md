Response:
Let's break down the thought process for analyzing this V8 debugger header file.

1. **Understand the Context:** The first step is to recognize that this is a header file (`.h`) for the V8 JavaScript engine's debugger within the `v8/src/inspector` directory. This immediately tells us it's related to debugging JavaScript code running in V8. The "inspector" part suggests it's likely used by developer tools like Chrome DevTools.

2. **Initial Scan for Keywords and Structures:**  Quickly scan the code for prominent keywords and structures. Things that jump out are:
    * `#ifndef`, `#define`, `#include`: Standard C++ header file guards and inclusions.
    * `namespace v8_inspector`:  Indicates the code belongs to the V8 inspector subsystem.
    * `class V8Debugger`: The central class we need to analyze.
    * Inheritance: `: public v8::debug::DebugDelegate, public v8::debug::AsyncEventDelegate`. This signifies that `V8Debugger` interacts with V8's internal debugging mechanisms.
    * `enum class WrapMode`:  Suggests different ways of representing values for debugging.
    * `struct WrapSerializationOptions`, `struct WrapOptions`: Configuration for value wrapping.
    * `using protocol::Response`, `using TerminateExecutionCallback`:  Indicates communication with a debugger protocol (likely the Chrome DevTools Protocol).
    * Lots of methods starting with `set`, `get`, `enable`, `disable`, `break`, `continue`, `step`:  These are strong indicators of debugger functionality.
    * Data members (variables):  Look for member variables to understand the state managed by the class (e.g., `m_pausedContextGroupId`, `m_breakpointsActiveCount`).
    * Use of standard containers: `std::deque`, `std::list`, `std::memory`, `std::unordered_map`, `std::unordered_set`, `std::vector`.

3. **Categorize Functionality by Public Methods:**  The public methods of `V8Debugger` reveal its main responsibilities. Go through them and try to group them logically:

    * **Basic State:** `enabled()`, `isolate()`
    * **Breakpoint Management:** `setBreakpointsActive()`, `removeBreakpoint()`, `getPauseOnExceptionsState()`, `setPauseOnExceptionsState()`
    * **Program Control (Pausing/Resuming):** `canBreakProgram()`, `isInInstrumentationPause()`, `breakProgram()`, `interruptAndBreak()`, `requestPauseAfterInstrumentation()`, `continueProgram()`, `breakProgramOnAssert()`
    * **Stepping:** `setPauseOnNextCall()`, `stepIntoStatement()`, `stepOverStatement()`, `stepOutOfFunction()`
    * **Termination:** `terminateExecution()`
    * **Continuing to a Location:** `continueToLocation()`
    * **Frame Restart:** `restartFrame()`
    * **Script Management:** `getCompiledScripts()`, `enable()`, `disable()`
    * **Pause Status:** `isPaused()`, `isPausedInContextGroup()`
    * **Async Call Stack Depth:** `maxAsyncCallChainDepth()`, `setAsyncCallStackDepth()`
    * **Call Stack Size:** `maxCallStackSizeToCapture()`, `setMaxCallStackSizeToCapture()`
    * **Stack Trace Handling:** `currentAsyncParent()`, `currentExternalParent()`, `symbolize()`, `createStackTrace()`, `captureStackTrace()`, `storeCurrentStackTrace()`, `externalAsyncTaskStarted()`, `externalAsyncTaskFinished()`, `storeStackTrace()`
    * **Object Inspection:** `internalProperties()`, `queryObjects()`
    * **Async Task Tracking:**  Methods like `asyncTaskScheduled()`, `asyncTaskCanceled()`, `asyncTaskStarted()`, `asyncTaskFinished()`, `allAsyncTasksCanceled()`
    * **Testing/Internal:** `setMaxAsyncTaskStacksForTest()`, `dumpAsyncTaskStacksStateForTest()`, `asyncParentFor()`, `debuggerIdFor()`, `stackTraceFor()`, `reportTermination()`
    * **Muting Events:** `muteScriptParsedEvents()`, `unmuteScriptParsedEvents()`
    * **Inspector Access:** `inspector()`

4. **Analyze Relationships and Data Flow:** Consider how the different parts interact:

    * The `V8Debugger` likely uses V8's internal debugging APIs (`v8::debug`) to control execution.
    * The "inspector" part suggests it communicates with an external debugger (like DevTools) using a protocol (likely through classes like `V8DebuggerAgentImpl`).
    * The `AsyncStackTrace` and related methods indicate support for debugging asynchronous operations.
    * The "WrapMode" and "WrapSerializationOptions" suggest mechanisms for formatting data sent to the debugger.

5. **Address Specific Instructions:** Now, go through the specific instructions in the prompt:

    * **Functionality Listing:** Summarize the categorized functionalities in clear, concise points.
    * **Torque Source:** Check the file extension. `.h` is a C++ header, *not* `.tq` (Torque). State this clearly.
    * **JavaScript Relationship and Examples:** For functionalities related to JavaScript debugging, provide simple JavaScript code snippets that demonstrate the debugger feature (e.g., setting breakpoints, stepping).
    * **Code Logic and Assumptions:** Look for methods that seem to involve processing or transforming data. Since there aren't complex algorithms directly exposed in the header, focus on the *purpose* of the methods and make reasonable assumptions about inputs and outputs based on their names (e.g., `getCompiledScripts` takes a context ID and likely returns script information).
    * **Common Programming Errors:** Think about common errors developers make that debugging helps with. Examples include uncaught exceptions, incorrect variable values, and issues with asynchronous code flow.

6. **Review and Refine:** Read through the analysis to ensure clarity, accuracy, and completeness. Make sure the language is understandable and the examples are relevant. Double-check the assumptions made about code logic.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Maybe `WrapMode` is about how breakpoints are stored."  **Correction:** Looking at the enum values (`kJson`, `kIdOnly`, `kPreview`, `kDeep`) suggests it's more about how *values* are represented in the debugger output.
* **Initial thought:** "The `handleProgramBreak` method probably has complex logic." **Refinement:**  While the implementation might be complex, the *header* only declares the interface. Focus on what the method *does* (handles program breaks) and the information it receives.
* **Realization:** The header file primarily *declares* the interface. The actual implementation details are in the `.cc` file. Adjust the analysis to focus on the exposed functionality rather than internal workings.

By following these steps, combining code analysis with an understanding of debugging concepts and the V8 architecture, one can effectively analyze the provided header file and generate a comprehensive explanation.
好的，让我们来分析一下 `v8/src/inspector/v8-debugger.h` 这个 V8 源代码文件。

**文件功能列表:**

`v8/src/inspector/v8-debugger.h` 文件定义了 `v8_inspector::V8Debugger` 类，这个类是 V8 Inspector 模块中负责 JavaScript 代码调试的核心组件。其主要功能包括：

1. **断点管理:**
   - 设置和移除断点 (`setBreakpointsActive`, `removeBreakpoint`).
   - 管理异常断点状态 (`getPauseOnExceptionsState`, `setPauseOnExceptionsState`).
   - 处理断点命中事件 (`BreakProgramRequested`, `BreakOnInstrumentation`).
   - 评估断点条件 (`BreakpointConditionEvaluated`).

2. **程序执行控制:**
   - 暂停程序执行 (`breakProgram`, `interruptAndBreak`, `requestPauseAfterInstrumentation`).
   - 继续程序执行 (`continueProgram`).
   - 单步执行 (`setPauseOnNextCall`, `stepIntoStatement`, `stepOverStatement`, `stepOutOfFunction`).
   - 继续执行到指定位置 (`continueToLocation`).
   - 重启当前帧 (`restartFrame`).
   - 终止执行 (`terminateExecution`).

3. **脚本管理:**
   - 获取已编译的脚本信息 (`getCompiledScripts`).
   - 启用和禁用调试器 (`enable`, `disable`).
   - 处理脚本编译事件 (`ScriptCompiled`).
   - 确定是否跳过特定代码行 (`ShouldBeSkipped`).
   - 管理脚本解析事件的静音状态 (`muteScriptParsedEvents`, `unmuteScriptParsedEvents`).

4. **调用栈和异步调用栈管理:**
   - 获取和设置最大异步调用栈深度 (`maxAsyncCallChainDepth`, `setAsyncCallStackDepth`).
   - 获取和设置捕获的最大调用栈大小 (`maxCallStackSizeToCapture`, `setMaxCallStackSizeToCapture`).
   - 获取当前的异步父级栈帧 (`currentAsyncParent`).
   - 获取当前外部父级栈帧 ID (`currentExternalParent`).
   - 符号化 V8 栈帧 (`symbolize`).
   - 创建和捕获栈跟踪信息 (`createStackTrace`, `captureStackTrace`).
   - 存储栈跟踪信息 (`storeCurrentStackTrace`, `storeStackTrace`).
   - 管理异步父级栈信息 (`asyncParentFor`, `stackTraceFor`).

5. **对象检查:**
   - 获取内部属性 (`internalProperties`).
   - 查询指定原型链的对象 (`queryObjects`).
   - 获取集合类型的条目 (`collectionsEntries`).
   - 获取私有方法 (`privateMethods`).

6. **异步任务跟踪:**
   - 记录异步任务的调度、取消、开始和完成 (`asyncTaskScheduled`, `asyncTaskCanceled`, `asyncTaskStarted`, `asyncTaskFinished`, `allAsyncTasksCanceled`).
   - 记录外部异步任务的开始和完成 (`externalAsyncTaskStarted`, `externalAsyncTaskFinished`).

7. **异常处理:**
   - 处理异常抛出事件 (`ExceptionThrown`).

8. **黑盒代码管理:**
   - 判断函数是否被黑盒 (`IsFunctionBlackboxed`).

9. **内部状态管理:**
   - 跟踪调试器的启用状态 (`enabled`).
   - 跟踪暂停状态 (`isPaused`, `isPausedInContextGroup`).
   - 管理与 Inspector 的关联 (`inspector`).

**关于是否为 Torque 源代码:**

`v8/src/inspector/v8-debugger.h` 以 `.h` 结尾，这表明它是一个 C++ 头文件，而不是 Torque 源代码文件。Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`V8Debugger` 的核心功能是为 JavaScript 代码提供调试能力。它响应来自调试客户端（如 Chrome DevTools）的指令，并在 JavaScript 执行过程中进行控制和检查。

以下是一些 JavaScript 代码示例，展示了 `V8Debugger` 类所支持的调试功能：

**1. 设置断点:**

```javascript
// 在第 5 行设置断点
debugger; // 或者通过 DevTools 设置断点
function myFunction() {
  console.log("Line 1");
  console.log("Line 2");
  console.log("Line 3"); // 断点会停在这里
  console.log("Line 4");
}
myFunction();
```

`V8Debugger` 的 `BreakProgramRequested` 方法会处理 `debugger;` 语句或 DevTools 设置的断点，暂停 JavaScript 执行。

**2. 单步执行:**

```javascript
function add(a, b) {
  let sum = a + b; // 在这里设置断点
  return sum;
}
let result = add(5, 3);
console.log(result);
```

当程序在断点处暂停时，可以使用 DevTools 的单步跳过（Step Over）、单步进入（Step Into）、单步跳出（Step Out）功能，这些功能分别对应 `V8Debugger` 的 `stepOverStatement`、`stepIntoStatement` 和 `stepOutOfFunction` 方法。

**3. 异常断点:**

```javascript
function divide(a, b) {
  if (b === 0) {
    throw new Error("Cannot divide by zero");
  }
  return a / b;
}

try {
  divide(10, 0);
} catch (e) {
  console.error("Caught an error:", e);
}
```

通过 DevTools 设置 "Pause on caught exceptions" 或 "Pause on uncaught exceptions"，当代码抛出异常时，`V8Debugger` 的 `ExceptionThrown` 方法会暂停程序执行。

**代码逻辑推理及假设输入输出:**

考虑 `getCompiledScripts` 方法：

**假设输入:**
- `contextGroupId`: 一个整数，表示要获取脚本的上下文组 ID。假设输入为 `1`。
- `agent`: 一个指向 `V8DebuggerAgentImpl` 的指针。假设它是一个有效的指针。

**代码逻辑:**
`getCompiledScripts` 方法会遍历 V8 引擎中与 `contextGroupId` 匹配的所有已编译的 JavaScript 脚本，并为每个脚本创建一个 `V8DebuggerScript` 对象。

**预期输出:**
- 一个 `std::vector<std::unique_ptr<V8DebuggerScript>>`，其中包含了在上下文组 ID 为 `1` 中编译的所有脚本的 `V8DebuggerScript` 对象。如果该上下文组没有任何已编译的脚本，则返回一个空向量。每个 `V8DebuggerScript` 对象会包含脚本的元数据，例如脚本 ID、URL、开始行号等。

**涉及用户常见的编程错误及示例:**

调试器最常用于帮助开发者定位和解决编程错误。以下是一些常见的编程错误，调试器可以帮助发现：

**1. 逻辑错误:**

```javascript
function calculateDiscountedPrice(price, discountPercentage) {
  let discountedPrice = price + (price * discountPercentage); // 错误地使用了加法
  return discountedPrice;
}

let finalPrice = calculateDiscountedPrice(100, 0.1);
console.log(finalPrice); // 期望输出 90，实际输出 110
```

通过单步执行，开发者可以观察变量 `discountedPrice` 的值，从而发现逻辑上的错误。

**2. 作用域错误:**

```javascript
function outer() {
  let x = 10;
  function inner() {
    console.log(x); // 可以访问外部作用域的 x
    let y = 20;
  }
  inner();
  console.log(y); // 错误！y 在 inner 函数内部定义，外部无法访问
}
outer();
```

在调试器中，可以查看不同作用域中的变量，从而理解作用域规则，找出访问未定义变量的错误。

**3. 异步编程错误:**

```javascript
function fetchData() {
  setTimeout(() => {
    let data = "Data fetched!";
    console.log(data);
  }, 1000);
  console.log(data); // 错误！ data 在 setTimeout 的回调函数中定义，这里访问不到
}

fetchData();
```

调试器的异步调用栈功能可以帮助开发者理解异步操作的执行顺序，从而找出由于对异步结果的错误假设而导致的错误。`V8Debugger` 中的异步任务跟踪功能就为此提供了支持。

**4. 类型错误:**

```javascript
function multiply(a, b) {
  return a * b;
}

let result = multiply("5", 2); // 字符串 "5" 会被隐式转换为数字
console.log(result); // 输出 10，但可能不是预期的行为，需要检查类型
```

通过在调试器中检查变量类型，开发者可以发现意外的类型转换，从而避免潜在的错误。

总而言之，`v8/src/inspector/v8-debugger.h` 定义的 `V8Debugger` 类是 V8 调试功能的核心，它提供了丰富的接口来控制 JavaScript 代码的执行，检查程序状态，并帮助开发者诊断和解决各种编程错误。

### 提示词
```
这是目录为v8/src/inspector/v8-debugger.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/v8-debugger.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_INSPECTOR_V8_DEBUGGER_H_
#define V8_INSPECTOR_V8_DEBUGGER_H_

#include <deque>
#include <list>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "include/v8-inspector.h"
#include "src/base/macros.h"
#include "src/inspector/inspected-context.h"
#include "src/inspector/protocol/Debugger.h"
#include "src/inspector/protocol/Forward.h"
#include "src/inspector/protocol/Runtime.h"
#include "src/inspector/v8-debugger-id.h"
#include "src/inspector/v8-debugger-script.h"

namespace v8_inspector {

class AsyncStackTrace;
class StackFrame;
class V8Debugger;
class V8DebuggerAgentImpl;
class V8InspectorImpl;
class V8RuntimeAgentImpl;
class V8StackTraceImpl;
struct V8StackTraceId;

enum class WrapMode { kJson, kIdOnly, kPreview, kDeep };

struct WrapSerializationOptions {
  int maxDepth = v8::internal::kMaxInt;
  v8::Global<v8::Object> additionalParameters;
};

struct WrapOptions {
  WrapMode mode;
  WrapSerializationOptions serializationOptions = {};
};

using protocol::Response;
using TerminateExecutionCallback =
    protocol::Runtime::Backend::TerminateExecutionCallback;

class V8Debugger : public v8::debug::DebugDelegate,
                   public v8::debug::AsyncEventDelegate {
 public:
  V8Debugger(v8::Isolate*, V8InspectorImpl*);
  ~V8Debugger() override;
  V8Debugger(const V8Debugger&) = delete;
  V8Debugger& operator=(const V8Debugger&) = delete;

  bool enabled() const;
  v8::Isolate* isolate() const { return m_isolate; }

  void setBreakpointsActive(bool);
  void removeBreakpoint(v8::debug::BreakpointId id);

  v8::debug::ExceptionBreakState getPauseOnExceptionsState();
  void setPauseOnExceptionsState(v8::debug::ExceptionBreakState);
  bool canBreakProgram();
  bool isInInstrumentationPause() const;
  void breakProgram(int targetContextGroupId);
  void interruptAndBreak(int targetContextGroupId);
  void requestPauseAfterInstrumentation();
  void continueProgram(int targetContextGroupId,
                       bool terminateOnResume = false);
  void breakProgramOnAssert(int targetContextGroupId);

  void setPauseOnNextCall(bool, int targetContextGroupId);
  void stepIntoStatement(int targetContextGroupId, bool breakOnAsyncCall);
  void stepOverStatement(int targetContextGroupId);
  void stepOutOfFunction(int targetContextGroupId);

  void terminateExecution(v8::Local<v8::Context> context,
                          std::unique_ptr<TerminateExecutionCallback> callback);

  Response continueToLocation(int targetContextGroupId,
                              V8DebuggerScript* script,
                              std::unique_ptr<protocol::Debugger::Location>,
                              const String16& targetCallFramess);
  bool restartFrame(int targetContextGroupId, int callFrameOrdinal);

  // Each script inherits debug data from v8::Context where it has been
  // compiled.
  // Only scripts whose debug data matches |contextGroupId| will be reported.
  // Passing 0 will result in reporting all scripts.
  std::vector<std::unique_ptr<V8DebuggerScript>> getCompiledScripts(
      int contextGroupId, V8DebuggerAgentImpl* agent);
  void enable();
  void disable();

  bool isPaused() const { return m_pausedContextGroupId; }
  bool isPausedInContextGroup(int contextGroupId) const;

  int maxAsyncCallChainDepth() { return m_maxAsyncCallStackDepth; }
  void setAsyncCallStackDepth(V8DebuggerAgentImpl*, int);

  int maxCallStackSizeToCapture() const { return m_maxCallStackSizeToCapture; }
  void setMaxCallStackSizeToCapture(V8RuntimeAgentImpl*, int);

  std::shared_ptr<AsyncStackTrace> currentAsyncParent();
  V8StackTraceId currentExternalParent();

  std::shared_ptr<StackFrame> symbolize(v8::Local<v8::StackFrame> v8Frame);

  std::unique_ptr<V8StackTraceImpl> createStackTrace(v8::Local<v8::StackTrace>);
  std::unique_ptr<V8StackTraceImpl> captureStackTrace(bool fullStack);

  v8::MaybeLocal<v8::Array> internalProperties(v8::Local<v8::Context>,
                                               v8::Local<v8::Value>);

  v8::Local<v8::Array> queryObjects(v8::Local<v8::Context> context,
                                    v8::Local<v8::Object> prototype);

  void asyncTaskScheduled(const StringView& taskName, void* task,
                          bool recurring);
  void asyncTaskCanceled(void* task);
  void asyncTaskStarted(void* task);
  void asyncTaskFinished(void* task);
  void allAsyncTasksCanceled();

  V8StackTraceId storeCurrentStackTrace(const StringView& description);
  void externalAsyncTaskStarted(const V8StackTraceId& parent);
  void externalAsyncTaskFinished(const V8StackTraceId& parent);

  uintptr_t storeStackTrace(std::shared_ptr<AsyncStackTrace> stack);

  void muteScriptParsedEvents();
  void unmuteScriptParsedEvents();

  V8InspectorImpl* inspector() { return m_inspector; }

  void setMaxAsyncTaskStacksForTest(int limit);
  void dumpAsyncTaskStacksStateForTest();

  void asyncParentFor(int stackTraceId,
                      std::shared_ptr<AsyncStackTrace>* asyncParent,
                      V8StackTraceId* externalParent) const;

  internal::V8DebuggerId debuggerIdFor(int contextGroupId);
  std::shared_ptr<AsyncStackTrace> stackTraceFor(int contextGroupId,
                                                 const V8StackTraceId& id);

  void reportTermination();

 private:
  bool addInternalObject(v8::Local<v8::Context> context,
                         v8::Local<v8::Object> object,
                         V8InternalValueType type);

  void clearContinueToLocation();
  bool shouldContinueToCurrentLocation();

  static size_t nearHeapLimitCallback(void* data, size_t current_heap_limit,
                                      size_t initial_heap_limit);
  static void terminateExecutionCompletedCallback(v8::Isolate* isolate);
  static void terminateExecutionCompletedCallbackIgnoringData(
      v8::Isolate* isolate, void*);
  void installTerminateExecutionCallbacks(v8::Local<v8::Context> context);

  void handleProgramBreak(
      v8::Local<v8::Context> pausedContext, v8::Local<v8::Value> exception,
      const std::vector<v8::debug::BreakpointId>& hitBreakpoints,
      v8::debug::BreakReasons break_reasons,
      v8::debug::ExceptionType exception_type = v8::debug::kException,
      bool isUncaught = false);

  enum ScopeTargetKind {
    FUNCTION,
    GENERATOR,
  };
  v8::MaybeLocal<v8::Value> getTargetScopes(v8::Local<v8::Context>,
                                            v8::Local<v8::Value>,
                                            ScopeTargetKind);

  v8::MaybeLocal<v8::Value> functionScopes(v8::Local<v8::Context>,
                                           v8::Local<v8::Function>);
  v8::MaybeLocal<v8::Value> generatorScopes(v8::Local<v8::Context>,
                                            v8::Local<v8::Value>);
  v8::MaybeLocal<v8::Array> collectionsEntries(v8::Local<v8::Context> context,
                                               v8::Local<v8::Value> value);
  v8::MaybeLocal<v8::Array> privateMethods(v8::Local<v8::Context> context,
                                           v8::Local<v8::Value> value);

  void asyncTaskScheduledForStack(const StringView& taskName, void* task,
                                  bool recurring, bool skipTopFrame = false);
  void asyncTaskCanceledForStack(void* task);
  void asyncTaskStartedForStack(void* task);
  void asyncTaskFinishedForStack(void* task);

  void asyncTaskCandidateForStepping(void* task);
  void asyncTaskStartedForStepping(void* task);
  void asyncTaskFinishedForStepping(void* task);
  void asyncTaskCanceledForStepping(void* task);
  void asyncStackTraceCaptured(int id);

  // v8::debug::DebugEventListener implementation.
  void AsyncEventOccurred(v8::debug::DebugAsyncActionType type, int id,
                          bool isBlackboxed) override;
  void ScriptCompiled(v8::Local<v8::debug::Script> script, bool is_live_edited,
                      bool has_compile_error) override;
  void BreakProgramRequested(
      v8::Local<v8::Context> paused_context,
      const std::vector<v8::debug::BreakpointId>& break_points_hit,
      v8::debug::BreakReasons break_reasons) override;
  ActionAfterInstrumentation BreakOnInstrumentation(
      v8::Local<v8::Context> paused_context, v8::debug::BreakpointId) override;
  void ExceptionThrown(v8::Local<v8::Context> paused_context,
                       v8::Local<v8::Value> exception,
                       v8::Local<v8::Value> promise, bool is_uncaught,
                       v8::debug::ExceptionType exception_type) override;
  bool IsFunctionBlackboxed(v8::Local<v8::debug::Script> script,
                            const v8::debug::Location& start,
                            const v8::debug::Location& end) override;

  bool ShouldBeSkipped(v8::Local<v8::debug::Script> script, int line,
                       int column) override;
  void BreakpointConditionEvaluated(v8::Local<v8::Context> context,
                                    v8::debug::BreakpointId breakpoint_id,
                                    bool exception_thrown,
                                    v8::Local<v8::Value> exception) override;

  int currentContextGroupId();

  bool hasScheduledBreakOnNextFunctionCall() const;

  void quitMessageLoopIfAgentsFinishedInstrumentation();

  v8::Isolate* m_isolate;
  V8InspectorImpl* m_inspector;
  int m_enableCount;

  int m_breakpointsActiveCount = 0;
  int m_ignoreScriptParsedEventsCounter;
  size_t m_originalHeapLimit = 0;
  bool m_scheduledOOMBreak = false;
  int m_targetContextGroupId = 0;
  int m_pausedContextGroupId = 0;
  bool m_instrumentationPause = false;
  bool m_requestedPauseAfterInstrumentation = false;
  int m_continueToLocationBreakpointId;
  String16 m_continueToLocationTargetCallFrames;
  std::unique_ptr<V8StackTraceImpl> m_continueToLocationStack;

  // We cache symbolized stack frames by (scriptId,lineNumber,columnNumber)
  // to reduce memory pressure for huge web apps with lots of deep async
  // stacks.
  struct CachedStackFrameKey {
    int scriptId;
    int lineNumber;
    int columnNumber;

    struct Equal {
      bool operator()(CachedStackFrameKey const& a,
                      CachedStackFrameKey const& b) const {
        return a.scriptId == b.scriptId && a.lineNumber == b.lineNumber &&
               a.columnNumber == b.columnNumber;
      }
    };

    struct Hash {
      size_t operator()(CachedStackFrameKey const& key) const {
        size_t code = 0;
        code = code * 31 + key.scriptId;
        code = code * 31 + key.lineNumber;
        code = code * 31 + key.columnNumber;
        return code;
      }
    };
  };
  std::unordered_map<CachedStackFrameKey, std::weak_ptr<StackFrame>,
                     CachedStackFrameKey::Hash, CachedStackFrameKey::Equal>
      m_cachedStackFrames;

  using AsyncTaskToStackTrace =
      std::unordered_map<void*, std::weak_ptr<AsyncStackTrace>>;
  AsyncTaskToStackTrace m_asyncTaskStacks;
  std::unordered_set<void*> m_recurringTasks;

  size_t m_maxAsyncCallStacks;
  int m_maxAsyncCallStackDepth;
  int m_maxCallStackSizeToCapture;

  std::vector<void*> m_currentTasks;
  std::vector<std::shared_ptr<AsyncStackTrace>> m_currentAsyncParent;
  std::vector<V8StackTraceId> m_currentExternalParent;

  // Maps v8::StackTrace IDs to async parents.
  using StackTraceToAsyncParent =
      std::unordered_map<int, std::weak_ptr<AsyncStackTrace>>;
  using StackTraceToExternalParent = std::deque<std::pair<int, V8StackTraceId>>;
  StackTraceToAsyncParent m_asyncParents;
  StackTraceToExternalParent m_externalParents;

  void collectOldAsyncStacksIfNeeded();
  // V8Debugger owns all the async stacks, while most of the other references
  // are weak, which allows to collect some stacks when there are too many.
  std::list<std::shared_ptr<AsyncStackTrace>> m_allAsyncStacks;

  std::unordered_map<V8DebuggerAgentImpl*, int> m_maxAsyncCallStackDepthMap;
  std::unordered_map<V8RuntimeAgentImpl*, int> m_maxCallStackSizeToCaptureMap;
  void* m_taskWithScheduledBreak = nullptr;

  // If any of the following three is true, we schedule pause on next JS
  // execution using SetBreakOnNextFunctionCall.
  bool m_externalAsyncTaskPauseRequested = false;       // External async task.
  bool m_taskWithScheduledBreakPauseRequested = false;  // Local async task.
  bool m_pauseOnNextCallRequested = false;  // setPauseOnNextCall API call.

  v8::debug::ExceptionBreakState m_pauseOnExceptionsState;
  // Whether we should pause on async call execution (if any) while stepping in.
  // See Debugger.stepInto for details.
  bool m_pauseOnAsyncCall = false;

  using StoredStackTraces =
      std::unordered_map<uintptr_t, std::weak_ptr<AsyncStackTrace>>;
  StoredStackTraces m_storedStackTraces;
  uintptr_t m_lastStackTraceId = 0;

  std::unordered_map<int, internal::V8DebuggerId> m_contextGroupIdToDebuggerId;

  std::unique_ptr<TerminateExecutionCallback> m_terminateExecutionCallback;
  v8::Global<v8::Context> m_terminateExecutionCallbackContext;
  bool m_terminateExecutionReported = true;
};

}  // namespace v8_inspector

#endif  // V8_INSPECTOR_V8_DEBUGGER_H_
```