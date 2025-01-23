Response:
Let's break down the thought process for analyzing the `v8-inspector-impl.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of this specific V8 source file. The prompt also has specific constraints (Torque, JavaScript relation, logic, common errors).

2. **Initial Scan and High-Level Purpose:**
   - Quickly read the copyright notice – it confirms it's a Google/V8 file related to debugging.
   - Look at the `#include` directives. These are crucial for understanding dependencies and hinted functionality. We see includes for:
     - `v8.h` (core V8 API)
     - `v8-context.h`, `v8-local-handle.h`, `v8-microtask-queue.h`, `v8-platform.h` (V8 concepts)
     - `mutex.h` (threading)
     - `debug-interface.h` (debugging related)
     - Files within the `inspector` directory (self-referential and key to the purpose)
   - Based on the includes, the file likely deals with the *implementation* of the V8 inspector.

3. **Class Structure:**
   - The core class is `V8InspectorImpl`. The `create` static method suggests a factory pattern for instantiation.
   - Note the private member variables. They offer direct insights into the state the class manages:
     - `m_isolate`:  Pointer to the V8 isolate.
     - `m_client`:  A `V8InspectorClient` (likely an interface for the embedder to interact).
     - `m_debugger`:  A `V8Debugger` object (central to debugging).
     - `m_lastExceptionId`, `m_lastContextId`, `m_isolateId`: Counters and IDs.
     - `m_contextIdToGroupIdMap`, `m_uniqueIdToContextId`: Maps for context management.
     - `m_consoleStorageMap`:  Handles console messages.
     - `m_muteExceptionsMap`: Controls exception reporting.
     - `m_sessions`:  Manages inspector sessions.
     - `m_contexts`:  Stores information about inspected contexts.
     - `m_debuggerBarriers`: For managing breakpoints during connection.
     - `m_regexContext`, `m_exceptionMetaDataContext`:  Special contexts.
     - `m_exceptionMetaData`:  For associating data with exceptions.
     - `m_console`:  A `V8Console` object.

4. **Method Analysis - Grouping by Functionality:**  Go through the methods and try to categorize them:

   - **Initialization and Teardown:** `V8InspectorImpl`, `~V8InspectorImpl`.
   - **Context Management:** `contextGroupId`, `resolveUniqueContextId`, `contextCreated`, `contextDestroyed`, `contextCollected`, `resetContextGroup`, `getContext`, `contextById`, `uniqueDebuggerId`, `discardInspectedContext`, `forEachContext`. These clearly manage the lifecycle and organization of JavaScript contexts being inspected.
   - **Session Management:** `connect`, `disconnect`, `sessionById`, `forEachSession`. Deals with connecting and disconnecting debugging clients.
   - **Script Execution:** `compileAndRunInternalScript`, `compileScript`. Allows running code within the inspected environment.
   - **Exception Handling:** `muteExceptions`, `unmuteExceptions`, `exceptionThrown`, `exceptionRevoked`, `associateExceptionData`, `getAssociatedExceptionData`, `getAssociatedExceptionDataForProtocol`. Handles reporting and associating data with exceptions.
   - **Stack Traces:** `createStackTrace`, `captureStackTrace`, `storeCurrentStackTrace`.
   - **Asynchronous Operations:** `externalAsyncTaskStarted`, `externalAsyncTaskFinished`, `asyncTaskScheduled`, `asyncTaskCanceled`, `asyncTaskStarted`, `asyncTaskFinished`, `allAsyncTasksCanceled`. Crucial for debugging asynchronous JavaScript code.
   - **Console API:** `ensureConsoleMessageStorage`, `hasConsoleMessageStorage`, `console`.
   - **Id Generation:** `generateUniqueId`.
   - **Internal Utilities:** `regexContext`, `exceptionMetaDataContext`.
   - **Evaluation Scope:** `EvaluateScope` (likely related to evaluating expressions in the debugger).

5. **Answering Specific Prompt Questions:**

   - **Functionality Listing:**  Summarize the categorized methods.
   - **Torque:** Check the file extension. `.cc` indicates C++, *not* Torque.
   - **JavaScript Relation and Examples:** Look for methods that directly interact with V8 contexts or JavaScript concepts. Examples like `compileAndRunInternalScript`, `exceptionThrown`, and methods dealing with console messages are good candidates. Devise simple JavaScript examples to illustrate these.
   - **Code Logic Reasoning:**  Focus on methods that involve decision-making or state changes. `connect` with `debuggerBarrier` logic is a good example. Create hypothetical scenarios for input and expected output.
   - **Common Programming Errors:** Think about how the inspector helps developers. Common errors include unhandled exceptions, incorrect asynchronous code, and console logging issues. Relate these to the inspector's functionality.

6. **Refinement and Organization:** Structure the answer clearly with headings and bullet points. Ensure the JavaScript examples are concise and relevant. Review for accuracy and completeness. For example, initially, I might have just said "manages contexts," but a better explanation involves listing the specific actions like creation, destruction, and grouping.

7. **Self-Correction/Double-Checking:**
   - Did I miss any major functional areas?  (Reviewing the method list helps here.)
   - Are my JavaScript examples accurate and easy to understand?
   - Is the logic reasoning clear and well-justified?
   - Have I addressed all parts of the prompt?

By following these steps, we can systematically analyze the C++ source code and provide a comprehensive and accurate answer to the prompt's questions. The key is to start with a high-level understanding and then delve into the details, connecting the code to its intended purpose and the broader V8 ecosystem.
好的，让我们来分析一下 `v8/src/inspector/v8-inspector-impl.cc` 这个文件。

**主要功能:**

`v8-inspector-impl.cc` 文件是 V8 引擎中 Inspector 功能的核心实现部分。它负责管理和协调 Inspector 的各种组件，使得开发者可以通过 Chrome DevTools 等工具来调试和分析 JavaScript 代码。 其主要功能可以归纳为以下几点：

1. **管理 Inspector 的生命周期:**  创建、初始化和销毁 Inspector 实例。`V8Inspector::create` 是创建实例的入口。
2. **管理调试会话 (Sessions):**  处理客户端（例如 Chrome DevTools）的连接和断开，每个连接对应一个 `V8InspectorSessionImpl` 实例。
3. **管理 JavaScript 上下文 (Contexts):** 跟踪和管理 V8 引擎中创建的 JavaScript 执行上下文。它维护了上下文 ID 和上下文组 ID 的映射关系。
4. **提供与调试器 (Debugger) 的接口:**  与 `V8Debugger` 类交互，实现断点设置、代码执行控制、调用堆栈查看等调试功能。
5. **提供与性能分析器 (Profiler) 的接口:**  虽然代码中没有直接看到 `V8ProfilerAgentImpl` 的直接调用，但它负责协调性能分析数据的收集和报告。
6. **处理控制台 (Console) 消息:**  接收并存储来自 JavaScript 代码的 `console.log` 等消息，并将其发送给调试客户端。
7. **处理异常 (Exceptions):**  捕获 JavaScript 运行时抛出的异常，并将其报告给调试客户端，包括异常信息和堆栈跟踪。
8. **执行脚本:**  提供编译和运行 JavaScript 代码的能力，这在调试器进行表达式求值或执行代码片段时使用。
9. **管理异步任务:**  跟踪和管理 JavaScript 中的异步操作，例如 `setTimeout`、`setInterval` 和 Promise 等，以便在调试时可以更好地理解异步流程。
10. **关联异常数据:**  允许将元数据与异常关联，以便在调试过程中提供更丰富的信息。

**是否为 Torque 代码:**

文件名以 `.cc` 结尾，这表明它是一个 C++ 源文件，而不是 Torque (`.tq`) 文件。 Torque 是 V8 用于生成高效运行时代码的特定领域语言。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`v8-inspector-impl.cc` 的核心职责是为 JavaScript 开发者提供调试和分析工具。它直接关联到许多常用的 JavaScript 功能和开发者可能遇到的问题。

**示例 1: 控制台消息 (Console Messages)**

当 JavaScript 代码中使用 `console.log()` 等方法时，`V8InspectorImpl` 会接收到这些消息并将其转发到连接的调试客户端（例如 Chrome DevTools 的 Console 面板）。

```javascript
// JavaScript 代码
console.log("Hello, Inspector!");
console.warn("This is a warning.");
console.error("An error occurred!");
```

`V8InspectorImpl` 中的 `ensureConsoleMessageStorage` 和 `addMessage` 等方法负责处理这些消息。

**示例 2: 异常处理 (Exception Handling)**

当 JavaScript 代码抛出未捕获的异常时，`V8InspectorImpl` 会捕获这些异常，并提供异常信息和堆栈跟踪。

```javascript
// JavaScript 代码
function divide(a, b) {
  if (b === 0) {
    throw new Error("Division by zero!");
  }
  return a / b;
}

divide(10, 0); // 这将抛出一个异常
```

`V8InspectorImpl` 中的 `exceptionThrown` 方法会被调用，将异常信息传递给调试客户端。

**示例 3: 断点调试 (Breakpoint Debugging)**

开发者可以在 Chrome DevTools 中设置断点。当 JavaScript 代码执行到断点时，`V8InspectorImpl` 会暂停执行，并通知调试客户端。

```javascript
// JavaScript 代码
function add(a, b) {
  debugger; // 设置断点
  return a + b;
}

let result = add(5, 3);
console.log(result);
```

当代码执行到 `debugger;` 语句时，`V8Debugger` 会介入，并通过 `V8InspectorImpl` 通知调试客户端，允许开发者查看当前状态。

**代码逻辑推理及假设输入与输出:**

让我们看一个关于 `connect` 方法的简化逻辑推理：

**假设输入:**

* `contextGroupId`: 1 (表示连接到第一个上下文组)
* `channel`: 一个指向调试通信通道的指针
* `state`:  "{}" (初始状态为空)
* `client_trust_level`: `kFullyTrusted`
* `pause_state`: `kNoPause`

**代码逻辑 (简化):**

1. `sessionId` 自增，假设当前 `m_lastSessionId` 为 0，则 `sessionId` 变为 1。
2. `debuggerBarrier`：由于 `pause_state` 不是 `kWaitingForDebugger`，所以 `debuggerBarrier` 为空。
3. 创建一个新的 `V8InspectorSessionImpl` 实例，使用提供的参数。
4. 将新的会话存储到 `m_sessions` map 中，键为 `contextGroupId` 和 `sessionId`。

**预期输出:**

* 创建一个新的 `V8InspectorSessionImpl` 实例。
* `m_sessions[1][1]` 将指向新创建的会话实例。

**涉及用户常见的编程错误及示例:**

Inspector 的存在是为了帮助开发者定位和解决编程错误。以下是一些常见的编程错误，Inspector 可以帮助诊断：

**示例 1:  未捕获的异常 (Uncaught Exceptions)**

```javascript
// 错误的代码
function fetchData() {
  // 假设这里有一个网络请求，可能会失败
  throw new Error("Failed to fetch data");
}

fetchData(); // 没有 try...catch 包裹
```

**Inspector 的帮助:** 当这段代码执行时，Inspector 会捕获 `Error: Failed to fetch data` 异常，并在 Console 面板中显示错误信息和堆栈跟踪，帮助开发者快速定位错误发生的位置。

**示例 2:  异步操作中的错误 (Errors in Asynchronous Operations)**

```javascript
// 错误的代码
setTimeout(() => {
  console.log(nonExistentVariable); // 引用了一个不存在的变量
}, 1000);
```

**Inspector 的帮助:**  即使错误发生在 `setTimeout` 的回调函数中，Inspector 也能捕获这个错误，并提供堆栈跟踪，帮助开发者理解异步操作的执行流程和错误发生的上下文。

**示例 3:  逻辑错误导致的不期望的结果 (Logical Errors Leading to Unexpected Results)**

```javascript
// 错误的代码
function calculateTotal(price, quantity) {
  // 错误地使用了加法而不是乘法
  return price + quantity;
}

let totalPrice = calculateTotal(10, 5);
console.log(totalPrice); // 输出 15，期望输出 50
```

**Inspector 的帮助:** 开发者可以使用断点功能，逐步执行 `calculateTotal` 函数，查看变量的值，从而发现逻辑错误。例如，在 `return price + quantity;` 这一行设置断点，可以看到 `price` 和 `quantity` 的值，从而意识到应该使用乘法。

总而言之，`v8-inspector-impl.cc` 是 V8 Inspector 功能的核心，它连接了 V8 引擎和调试客户端，使得开发者可以有效地调试和分析 JavaScript 代码，从而解决各种编程错误。

### 提示词
```
这是目录为v8/src/inspector/v8-inspector-impl.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/v8-inspector-impl.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (c) 2010-2011 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "src/inspector/v8-inspector-impl.h"

#include <vector>

#include "include/v8-context.h"
#include "include/v8-local-handle.h"
#include "include/v8-microtask-queue.h"
#include "include/v8-platform.h"
#include "src/base/platform/mutex.h"
#include "src/debug/debug-interface.h"
#include "src/inspector/inspected-context.h"
#include "src/inspector/string-util.h"
#include "src/inspector/v8-console-agent-impl.h"
#include "src/inspector/v8-console-message.h"
#include "src/inspector/v8-console.h"
#include "src/inspector/v8-debugger-agent-impl.h"
#include "src/inspector/v8-debugger-barrier.h"
#include "src/inspector/v8-debugger-id.h"
#include "src/inspector/v8-debugger.h"
#include "src/inspector/v8-inspector-session-impl.h"
#include "src/inspector/v8-profiler-agent-impl.h"
#include "src/inspector/v8-runtime-agent-impl.h"
#include "src/inspector/v8-stack-trace-impl.h"
#include "src/inspector/value-mirror.h"

namespace v8_inspector {

std::unique_ptr<V8Inspector> V8Inspector::create(v8::Isolate* isolate,
                                                 V8InspectorClient* client) {
  return std::unique_ptr<V8Inspector>(new V8InspectorImpl(isolate, client));
}

V8InspectorImpl::V8InspectorImpl(v8::Isolate* isolate,
                                 V8InspectorClient* client)
    : m_isolate(isolate),
      m_client(client),
      m_debugger(new V8Debugger(isolate, this)),
      m_lastExceptionId(0),
      m_lastContextId(0),
      m_isolateId(generateUniqueId()) {
  v8::debug::SetInspector(m_isolate, this);
  v8::debug::SetConsoleDelegate(m_isolate, console());
}

V8InspectorImpl::~V8InspectorImpl() {
  v8::debug::SetInspector(m_isolate, nullptr);
  v8::debug::SetConsoleDelegate(m_isolate, nullptr);
}

int V8InspectorImpl::contextGroupId(v8::Local<v8::Context> context) const {
  return contextGroupId(InspectedContext::contextId(context));
}

int V8InspectorImpl::contextGroupId(int contextId) const {
  auto it = m_contextIdToGroupIdMap.find(contextId);
  return it != m_contextIdToGroupIdMap.end() ? it->second : 0;
}

int V8InspectorImpl::resolveUniqueContextId(
    internal::V8DebuggerId uniqueId) const {
  auto it = m_uniqueIdToContextId.find(uniqueId.pair());
  return it == m_uniqueIdToContextId.end() ? 0 : it->second;
}

v8::MaybeLocal<v8::Value> V8InspectorImpl::compileAndRunInternalScript(
    v8::Local<v8::Context> context, v8::Local<v8::String> source) {
  v8::Local<v8::UnboundScript> unboundScript;
  if (!v8::debug::CompileInspectorScript(m_isolate, source)
           .ToLocal(&unboundScript))
    return v8::MaybeLocal<v8::Value>();
  v8::MicrotasksScope microtasksScope(context,
                                      v8::MicrotasksScope::kDoNotRunMicrotasks);
  v8::Context::Scope contextScope(context);
  return unboundScript->BindToCurrentContext()->Run(context);
}

v8::MaybeLocal<v8::Script> V8InspectorImpl::compileScript(
    v8::Local<v8::Context> context, const String16& code,
    const String16& fileName) {
  v8::ScriptOrigin origin(toV8String(m_isolate, fileName), 0, 0, false);
  v8::ScriptCompiler::Source source(toV8String(m_isolate, code), origin);
  return v8::ScriptCompiler::Compile(context, &source,
                                     v8::ScriptCompiler::kNoCompileOptions);
}

void V8InspectorImpl::muteExceptions(int contextGroupId) {
  m_muteExceptionsMap[contextGroupId]++;
}

void V8InspectorImpl::unmuteExceptions(int contextGroupId) {
  m_muteExceptionsMap[contextGroupId]--;
}

V8ConsoleMessageStorage* V8InspectorImpl::ensureConsoleMessageStorage(
    int contextGroupId) {
  auto storageIt = m_consoleStorageMap.find(contextGroupId);
  if (storageIt == m_consoleStorageMap.end())
    storageIt = m_consoleStorageMap
                    .insert(std::make_pair(
                        contextGroupId,
                        std::unique_ptr<V8ConsoleMessageStorage>(
                            new V8ConsoleMessageStorage(this, contextGroupId))))
                    .first;
  return storageIt->second.get();
}

bool V8InspectorImpl::hasConsoleMessageStorage(int contextGroupId) {
  auto storageIt = m_consoleStorageMap.find(contextGroupId);
  return storageIt != m_consoleStorageMap.end();
}

std::unique_ptr<V8StackTrace> V8InspectorImpl::createStackTrace(
    v8::Local<v8::StackTrace> stackTrace) {
  return m_debugger->createStackTrace(stackTrace);
}

std::unique_ptr<V8InspectorSession> V8InspectorImpl::connect(
    int contextGroupId, V8Inspector::Channel* channel, StringView state,
    ClientTrustLevel client_trust_level, SessionPauseState pause_state) {
  int sessionId = ++m_lastSessionId;
  std::shared_ptr<V8DebuggerBarrier> debuggerBarrier;
  if (pause_state == kWaitingForDebugger) {
    auto it = m_debuggerBarriers.find(contextGroupId);
    if (it != m_debuggerBarriers.end()) {
      // Note this will be empty in case a pre-existent barrier is already
      // released. This is by design, as a released throttle is no longer
      // efficient.
      debuggerBarrier = it->second.lock();
    } else {
      debuggerBarrier =
          std::make_shared<V8DebuggerBarrier>(m_client, contextGroupId);
      m_debuggerBarriers.insert(it, {contextGroupId, debuggerBarrier});
    }
  }
  std::unique_ptr<V8InspectorSessionImpl> session =
      V8InspectorSessionImpl::create(this, contextGroupId, sessionId, channel,
                                     state, client_trust_level,
                                     std::move(debuggerBarrier));
  m_sessions[contextGroupId][sessionId] = session.get();
  return std::move(session);
}

void V8InspectorImpl::disconnect(V8InspectorSessionImpl* session) {
  auto& map = m_sessions[session->contextGroupId()];
  map.erase(session->sessionId());
  if (map.empty()) {
    m_sessions.erase(session->contextGroupId());
    m_debuggerBarriers.erase(session->contextGroupId());
  }
}

InspectedContext* V8InspectorImpl::getContext(int groupId,
                                              int contextId) const {
  if (!groupId || !contextId) return nullptr;

  auto contextGroupIt = m_contexts.find(groupId);
  if (contextGroupIt == m_contexts.end()) return nullptr;

  auto contextIt = contextGroupIt->second->find(contextId);
  if (contextIt == contextGroupIt->second->end()) return nullptr;

  return contextIt->second.get();
}

InspectedContext* V8InspectorImpl::getContext(int contextId) const {
  return getContext(contextGroupId(contextId), contextId);
}

v8::MaybeLocal<v8::Context> V8InspectorImpl::contextById(int contextId) {
  InspectedContext* context = getContext(contextId);
  return context ? context->context() : v8::MaybeLocal<v8::Context>();
}

V8DebuggerId V8InspectorImpl::uniqueDebuggerId(int contextId) {
  InspectedContext* context = getContext(contextId);
  internal::V8DebuggerId unique_id;
  if (context) unique_id = m_debugger->debuggerIdFor(context->contextGroupId());

  return unique_id.toV8DebuggerId();
}

void V8InspectorImpl::contextCreated(const V8ContextInfo& info) {
  int contextId = ++m_lastContextId;
  auto* context = new InspectedContext(this, info, contextId);
  m_contextIdToGroupIdMap[contextId] = info.contextGroupId;

  DCHECK(m_uniqueIdToContextId.find(context->uniqueId().pair()) ==
         m_uniqueIdToContextId.end());
  m_uniqueIdToContextId.insert(
      std::make_pair(context->uniqueId().pair(), contextId));

  auto contextIt = m_contexts.find(info.contextGroupId);
  if (contextIt == m_contexts.end())
    contextIt = m_contexts
                    .insert(std::make_pair(
                        info.contextGroupId,
                        std::unique_ptr<ContextByIdMap>(new ContextByIdMap())))
                    .first;
  const auto& contextById = contextIt->second;

  DCHECK(contextById->find(contextId) == contextById->cend());
  (*contextById)[contextId].reset(context);
  forEachSession(
      info.contextGroupId, [&context](V8InspectorSessionImpl* session) {
        session->runtimeAgent()->addBindings(context);
        session->runtimeAgent()->reportExecutionContextCreated(context);
      });
}

void V8InspectorImpl::contextDestroyed(v8::Local<v8::Context> context) {
  int contextId = InspectedContext::contextId(context);
  int groupId = contextGroupId(context);
  contextCollected(groupId, contextId);
}

void V8InspectorImpl::contextCollected(int groupId, int contextId) {
  m_contextIdToGroupIdMap.erase(contextId);

  auto storageIt = m_consoleStorageMap.find(groupId);
  if (storageIt != m_consoleStorageMap.end())
    storageIt->second->contextDestroyed(contextId);

  InspectedContext* inspectedContext = getContext(groupId, contextId);
  if (!inspectedContext) return;

  forEachSession(groupId, [&inspectedContext](V8InspectorSessionImpl* session) {
    session->runtimeAgent()->reportExecutionContextDestroyed(inspectedContext);
  });
  discardInspectedContext(groupId, contextId);
}

void V8InspectorImpl::resetContextGroup(int contextGroupId) {
  m_consoleStorageMap.erase(contextGroupId);
  m_muteExceptionsMap.erase(contextGroupId);
  auto contextsIt = m_contexts.find(contextGroupId);
  // Context might have been removed already by discardContextScript()
  if (contextsIt != m_contexts.end()) {
    for (const auto& map_entry : *contextsIt->second)
      m_uniqueIdToContextId.erase(map_entry.second->uniqueId().pair());
    m_contexts.erase(contextsIt);
  }
  forEachSession(contextGroupId,
                 [](V8InspectorSessionImpl* session) { session->reset(); });
}

void V8InspectorImpl::idleStarted() { m_isolate->SetIdle(true); }

void V8InspectorImpl::idleFinished() { m_isolate->SetIdle(false); }

unsigned V8InspectorImpl::exceptionThrown(
    v8::Local<v8::Context> context, StringView message,
    v8::Local<v8::Value> exception, StringView detailedMessage, StringView url,
    unsigned lineNumber, unsigned columnNumber,
    std::unique_ptr<V8StackTrace> stackTrace, int scriptId) {
  int groupId = contextGroupId(context);
  if (!groupId || m_muteExceptionsMap[groupId]) return 0;
  std::unique_ptr<V8StackTraceImpl> stackTraceImpl(
      static_cast<V8StackTraceImpl*>(stackTrace.release()));
  unsigned exceptionId = nextExceptionId();
  std::unique_ptr<V8ConsoleMessage> consoleMessage =
      V8ConsoleMessage::createForException(
          m_client->currentTimeMS(), toString16(detailedMessage),
          toString16(url), lineNumber, columnNumber, std::move(stackTraceImpl),
          scriptId, m_isolate, toString16(message),
          InspectedContext::contextId(context), exception, exceptionId);
  ensureConsoleMessageStorage(groupId)->addMessage(std::move(consoleMessage));
  return exceptionId;
}

void V8InspectorImpl::exceptionRevoked(v8::Local<v8::Context> context,
                                       unsigned exceptionId,
                                       StringView message) {
  int groupId = contextGroupId(context);
  if (!groupId) return;

  std::unique_ptr<V8ConsoleMessage> consoleMessage =
      V8ConsoleMessage::createForRevokedException(
          m_client->currentTimeMS(), toString16(message), exceptionId);
  ensureConsoleMessageStorage(groupId)->addMessage(std::move(consoleMessage));
}

std::unique_ptr<V8StackTrace> V8InspectorImpl::captureStackTrace(
    bool fullStack) {
  return m_debugger->captureStackTrace(fullStack);
}

V8StackTraceId V8InspectorImpl::storeCurrentStackTrace(StringView description) {
  return m_debugger->storeCurrentStackTrace(description);
}

void V8InspectorImpl::externalAsyncTaskStarted(const V8StackTraceId& parent) {
  m_debugger->externalAsyncTaskStarted(parent);
}

void V8InspectorImpl::externalAsyncTaskFinished(const V8StackTraceId& parent) {
  m_debugger->externalAsyncTaskFinished(parent);
}

void V8InspectorImpl::asyncTaskScheduled(StringView taskName, void* task,
                                         bool recurring) {
  if (!task) return;
  m_debugger->asyncTaskScheduled(taskName, task, recurring);
}

void V8InspectorImpl::asyncTaskCanceled(void* task) {
  if (!task) return;
  m_debugger->asyncTaskCanceled(task);
}

void V8InspectorImpl::asyncTaskStarted(void* task) {
  if (!task) return;
  m_debugger->asyncTaskStarted(task);
}

void V8InspectorImpl::asyncTaskFinished(void* task) {
  if (!task) return;
  m_debugger->asyncTaskFinished(task);
}

void V8InspectorImpl::allAsyncTasksCanceled() {
  m_debugger->allAsyncTasksCanceled();
}

v8::MaybeLocal<v8::Context> V8InspectorImpl::regexContext() {
  if (m_regexContext.IsEmpty()) {
    m_regexContext.Reset(m_isolate, v8::Context::New(m_isolate));
    if (m_regexContext.IsEmpty()) {
      DCHECK(m_isolate->IsExecutionTerminating());
      return {};
    }
  }
  return m_regexContext.Get(m_isolate);
}

v8::MaybeLocal<v8::Context> V8InspectorImpl::exceptionMetaDataContext() {
  if (m_exceptionMetaDataContext.IsEmpty()) {
    m_exceptionMetaDataContext.Reset(m_isolate, v8::Context::New(m_isolate));
    if (m_exceptionMetaDataContext.IsEmpty()) {
      DCHECK(m_isolate->IsExecutionTerminating());
      return {};
    }
  }
  return m_exceptionMetaDataContext.Get(m_isolate);
}

void V8InspectorImpl::discardInspectedContext(int contextGroupId,
                                              int contextId) {
  auto* context = getContext(contextGroupId, contextId);
  if (!context) return;
  m_uniqueIdToContextId.erase(context->uniqueId().pair());
  m_contexts[contextGroupId]->erase(contextId);
  if (m_contexts[contextGroupId]->empty()) m_contexts.erase(contextGroupId);
}

V8InspectorSessionImpl* V8InspectorImpl::sessionById(int contextGroupId,
                                                     int sessionId) {
  auto it = m_sessions.find(contextGroupId);
  if (it == m_sessions.end()) return nullptr;
  auto it2 = it->second.find(sessionId);
  return it2 == it->second.end() ? nullptr : it2->second;
}

V8Console* V8InspectorImpl::console() {
  if (!m_console) m_console.reset(new V8Console(this));
  return m_console.get();
}

void V8InspectorImpl::forEachContext(
    int contextGroupId,
    const std::function<void(InspectedContext*)>& callback) {
  auto it = m_contexts.find(contextGroupId);
  if (it == m_contexts.end()) return;
  std::vector<int> ids;
  ids.reserve(it->second->size());
  for (auto& contextIt : *(it->second)) ids.push_back(contextIt.first);

  // Retrieve by ids each time since |callback| may destroy some contexts.
  for (auto& contextId : ids) {
    it = m_contexts.find(contextGroupId);
    if (it == m_contexts.end()) continue;
    auto contextIt = it->second->find(contextId);
    if (contextIt != it->second->end()) callback(contextIt->second.get());
  }
}

void V8InspectorImpl::forEachSession(
    int contextGroupId,
    const std::function<void(V8InspectorSessionImpl*)>& callback) {
  auto it = m_sessions.find(contextGroupId);
  if (it == m_sessions.end()) return;
  std::vector<int> ids;
  ids.reserve(it->second.size());
  for (auto& sessionIt : it->second) ids.push_back(sessionIt.first);

  // Retrieve by ids each time since |callback| may destroy some contexts.
  for (auto& sessionId : ids) {
    it = m_sessions.find(contextGroupId);
    if (it == m_sessions.end()) continue;
    auto sessionIt = it->second.find(sessionId);
    if (sessionIt != it->second.end()) callback(sessionIt->second);
  }
}

int64_t V8InspectorImpl::generateUniqueId() {
  int64_t id = m_client->generateUniqueId();
  if (!id) id = v8::debug::GetNextRandomInt64(m_isolate);
  if (!id) id = 1;
  return id;
}

V8InspectorImpl::EvaluateScope::EvaluateScope(
    const InjectedScript::Scope& scope)
    : m_scope(scope), m_isolate(scope.inspector()->isolate()) {}

struct V8InspectorImpl::EvaluateScope::CancelToken {
  v8::base::Mutex m_mutex;
  bool m_canceled = false;
};

V8InspectorImpl::EvaluateScope::~EvaluateScope() {
  if (m_scope.tryCatch().HasTerminated()) {
    m_scope.inspector()->debugger()->reportTermination();
  }
  if (m_cancelToken) {
    v8::base::MutexGuard lock(&m_cancelToken->m_mutex);
    m_cancelToken->m_canceled = true;
    m_isolate->CancelTerminateExecution();
  }
}

class V8InspectorImpl::EvaluateScope::TerminateTask : public v8::Task {
 public:
  TerminateTask(v8::Isolate* isolate, std::shared_ptr<CancelToken> token)
      : m_isolate(isolate), m_token(std::move(token)) {}

  void Run() override {
    // CancelToken contains m_canceled bool which may be changed from main
    // thread, so lock mutex first.
    v8::base::MutexGuard lock(&m_token->m_mutex);
    if (m_token->m_canceled) return;
    m_isolate->TerminateExecution();
  }

 private:
  v8::Isolate* m_isolate;
  std::shared_ptr<CancelToken> m_token;
};

protocol::Response V8InspectorImpl::EvaluateScope::setTimeout(double timeout) {
  if (m_isolate->IsExecutionTerminating()) {
    return protocol::Response::ServerError("Execution was terminated");
  }
  m_cancelToken.reset(new CancelToken());
  v8::debug::GetCurrentPlatform()->CallDelayedOnWorkerThread(
      std::make_unique<TerminateTask>(m_isolate, m_cancelToken), timeout);
  return protocol::Response::Success();
}

bool V8InspectorImpl::associateExceptionData(v8::Local<v8::Context>,
                                             v8::Local<v8::Value> exception,
                                             v8::Local<v8::Name> key,
                                             v8::Local<v8::Value> value) {
  if (!exception->IsObject()) {
    return false;
  }
  v8::Local<v8::Context> context;
  if (!exceptionMetaDataContext().ToLocal(&context)) return false;
  v8::TryCatch tryCatch(m_isolate);
  v8::Context::Scope contextScope(context);
  v8::HandleScope handles(m_isolate);
  if (m_exceptionMetaData.IsEmpty())
    m_exceptionMetaData.Reset(m_isolate,
                              v8::debug::EphemeronTable::New(m_isolate));

  v8::Local<v8::debug::EphemeronTable> map = m_exceptionMetaData.Get(m_isolate);
  v8::MaybeLocal<v8::Value> entry = map->Get(m_isolate, exception);
  v8::Local<v8::Object> object;
  if (entry.IsEmpty() || !entry.ToLocalChecked()->IsObject()) {
    object =
        v8::Object::New(m_isolate, v8::Null(m_isolate), nullptr, nullptr, 0);
    m_exceptionMetaData.Reset(m_isolate,
                              map->Set(m_isolate, exception, object));
  } else {
    object = entry.ToLocalChecked().As<v8::Object>();
  }
  CHECK(object->IsObject());
  v8::Maybe<bool> result = object->CreateDataProperty(context, key, value);
  return result.FromMaybe(false);
}

v8::MaybeLocal<v8::Object> V8InspectorImpl::getAssociatedExceptionData(
    v8::Local<v8::Value> exception) {
  if (!exception->IsObject()) {
    return v8::MaybeLocal<v8::Object>();
  }
  v8::EscapableHandleScope scope(m_isolate);
  v8::Local<v8::Context> context;
  if (m_exceptionMetaData.IsEmpty() ||
      !exceptionMetaDataContext().ToLocal(&context)) {
    return v8::MaybeLocal<v8::Object>();
  }
  v8::Local<v8::debug::EphemeronTable> map = m_exceptionMetaData.Get(m_isolate);
  auto entry = map->Get(m_isolate, exception);
  v8::Local<v8::Value> object;
  if (!entry.ToLocal(&object) || !object->IsObject())
    return v8::MaybeLocal<v8::Object>();
  return scope.Escape(object.As<v8::Object>());
}

std::unique_ptr<protocol::DictionaryValue>
V8InspectorImpl::getAssociatedExceptionDataForProtocol(
    v8::Local<v8::Value> exception) {
  v8::MaybeLocal<v8::Object> maybeData = getAssociatedExceptionData(exception);
  v8::Local<v8::Object> data;
  if (!maybeData.ToLocal(&data)) return nullptr;

  v8::Local<v8::Context> context;
  if (!exceptionMetaDataContext().ToLocal(&context)) return nullptr;

  v8::TryCatch tryCatch(m_isolate);
  v8::MicrotasksScope microtasksScope(context,
                                      v8::MicrotasksScope::kDoNotRunMicrotasks);
  v8::Context::Scope contextScope(context);
  std::unique_ptr<protocol::DictionaryValue> jsonObject;
  objectToProtocolValue(context, data, 2, &jsonObject);
  return jsonObject;
}

}  // namespace v8_inspector
```