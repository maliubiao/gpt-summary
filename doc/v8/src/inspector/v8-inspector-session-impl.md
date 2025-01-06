Response: Let's break down the thought process for summarizing the C++ file `v8-inspector-session-impl.cc`.

1. **Understand the Goal:** The primary goal is to summarize the functionality of the given C++ file and explain its relationship with JavaScript.

2. **Initial Scan and Keyword Recognition:**  I'd quickly scan the file, looking for familiar terms and patterns related to debugging, profiling, and the V8 engine. Keywords like "inspector," "session," "debugger," "profiler," "runtime," "context," "JSON," "CBOR," "protocol," "evaluate," "pause," "resume,"  "RemoteObject" stand out. These give strong clues about the file's purpose.

3. **Identify Core Classes and Their Roles:**  The presence of `V8InspectorSessionImpl` suggests this is the main class implementing the core functionality. The `Impl` suffix often indicates an implementation detail. Other class names like `V8RuntimeAgentImpl`, `V8DebuggerAgentImpl`, `V8HeapProfilerAgentImpl`, `V8ProfilerAgentImpl`, `V8ConsoleAgentImpl`, and `V8SchemaAgentImpl` strongly suggest a modular design, with each agent responsible for a specific aspect of the inspection protocol.

4. **Trace the Flow of Information:** I'd look for how data comes in and goes out. The `dispatchProtocolMessage` function is crucial here, indicating how messages from the debugger frontend are processed. The `SendProtocolResponse` and `SendProtocolNotification` functions point to how responses and notifications are sent back. The conversion between JSON and CBOR also catches my eye as a potential performance optimization or protocol detail.

5. **Focus on Key Functionality:** Based on the keywords and class names, I would start grouping functionalities:

    * **Session Management:** Creating, destroying, and managing inspector sessions (`create`, destructor, `reset`).
    * **Message Handling:** Receiving and dispatching messages (`dispatchProtocolMessage`, `m_dispatcher`).
    * **Communication:** Sending responses and notifications (`SendProtocolResponse`, `SendProtocolNotification`).
    * **Debugger Integration:** Handling breakpoints, stepping, pausing, resuming (`m_debuggerAgent`, `schedulePauseOnNextStatement`, `resume`, `stepOver`).
    * **Runtime Evaluation:** Executing JavaScript code within the inspected context (`evaluate`).
    * **Object Inspection:**  Wrapping and unwrapping JavaScript objects for inspection (`wrapObject`, `unwrapObject`). The concept of `RemoteObjectId` also becomes relevant here.
    * **Profiling:**  Heap and CPU profiling capabilities (`m_heapProfilerAgent`, `m_profilerAgent`).
    * **Console Integration:** Handling console messages (`m_consoleAgent`).
    * **Context Management:**  Tracking and accessing JavaScript execution contexts (`m_inspector->forEachContext`, `findInjectedScript`).
    * **State Management:** Saving and restoring the state of the inspector session (`state`, constructor with `state` argument).
    * **Protocol Support:** Handling different protocol versions and formats (JSON/CBOR conversion).

6. **Identify Connections to JavaScript:**  The most direct connection is the `evaluate` function, which directly executes JavaScript code. The `wrapObject` and `unwrapObject` functions demonstrate how the C++ code interacts with JavaScript objects in the V8 heap. The concepts of "context" and the ability to "pause" and "debug" JavaScript code are fundamental links.

7. **Construct the Summary:** I'd start writing the summary, organizing it logically based on the identified functionalities. It's good to start with a high-level overview and then delve into specifics.

8. **Provide JavaScript Examples:**  For the JavaScript connection, the `evaluate` function naturally leads to examples of using the `evaluate` command in the DevTools console. The `wrapObject` and `unwrapObject` functionality relates to how objects are represented in the debugger, which can be illustrated with inspecting variables in the debugger. Debugging-related features like breakpoints and stepping also make good examples.

9. **Refine and Review:** After drafting the summary and examples, I would review it for clarity, accuracy, and completeness. Are there any ambiguities? Is the language clear and concise? Are the JavaScript examples relevant and easy to understand?  I might re-read parts of the code to ensure my understanding is correct. For instance, initially, I might just say "handles debugging," but upon review, I'd refine it to mention specific debugging actions like "setting breakpoints," "stepping through code," etc.

10. **Consider the Audience:** The prompt doesn't specify the audience, but assuming a developer familiar with JavaScript and potentially interested in the internals of V8's debugger, I would use appropriate technical terms without being overly jargonistic.

By following these steps, focusing on the key functionalities and the interactions with JavaScript, a comprehensive and accurate summary of the `v8-inspector-session-impl.cc` file can be constructed.
这个 C++ 源代码文件 `v8-inspector-session-impl.cc` 是 V8 JavaScript 引擎中 **Inspector (调试器)** 功能的核心实现之一。它的主要功能是 **管理一个调试会话 (Inspector Session)**，处理来自调试客户端（例如 Chrome DevTools）的调试协议消息，并协调 V8 引擎的各个组件以执行调试操作。

以下是对其功能的详细归纳：

**核心职责和功能:**

1. **会话管理:**
   - 创建和销毁 Inspector 会话 (`V8InspectorSessionImpl::create`, `~V8InspectorSessionImpl`).
   - 维护会话的唯一 ID (`m_sessionId`) 和所属的上下文组 (`m_contextGroupId`).
   - 存储和恢复会话状态 (`m_state`, 构造函数中使用 `savedState`).
   - 管理客户端的信任级别 (`m_clientTrustLevel`).

2. **消息处理和路由:**
   - 接收来自调试客户端的调试协议消息 (通常是 Chrome DevTools Protocol, CDP)。
   - 使用 `v8_crdtp::Dispatcher` 将接收到的消息分发到相应的 Agent 处理。
   - 支持 JSON 和 CBOR 两种消息格式的接收和发送，并进行相互转换 (`IsCBORMessage`, `ConvertToCBOR`, `ConvertCBORToJSON`).
   - 实现了 `V8Inspector::Channel` 接口，用于向客户端发送响应和通知 (`SendProtocolResponse`, `SendProtocolNotification`).

3. **与 Inspector Agents 的交互:**
   - 创建和管理各种 Inspector Agents 的实例，例如：
     - `V8RuntimeAgentImpl`:  处理与 JavaScript 运行时相关的调试功能，如代码执行、异常处理、全局对象访问等。
     - `V8DebuggerAgentImpl`: 处理断点、单步执行、调用栈查看等调试功能。
     - `V8HeapProfilerAgentImpl`: 处理堆快照、内存分析等功能。
     - `V8ProfilerAgentImpl`: 处理 CPU 分析、性能分析等功能。
     - `V8ConsoleAgentImpl`: 处理 `console` API 调用，将日志消息转发到客户端。
     - `V8SchemaAgentImpl`:  提供调试协议的元数据信息。
   - 将接收到的协议消息转发给相应的 Agent 进行处理。
   - 从 Agent 接收结果并发送回客户端。

4. **JavaScript 上下文管理:**
   - 跟踪与会话关联的 JavaScript 执行上下文 (`m_contextGroupId`).
   - 查找和创建与特定上下文关联的 `InjectedScript` 对象，用于在 JavaScript 上下文中执行代码和操作对象。

5. **对象检查和操作:**
   - 提供了将 V8 的 `v8::Value` 对象包装成调试协议中 `RemoteObject` 的功能，以便在调试客户端中展示 (`wrapObject`).
   - 提供了将调试协议中的 `RemoteObjectId` 解析回 V8 的 `v8::Value` 对象的功能 (`unwrapObject`).
   - 管理对象分组 (`releaseObjectGroup`)，用于在调试器中组织和释放对象。

6. **断点和代码执行控制:**
   - 实现暂停执行的功能 (`schedulePauseOnNextStatement`, `breakProgram`).
   - 实现恢复执行的功能 (`resume`).
   - 实现单步执行的功能 (`stepOver`).
   - 设置是否跳过所有断点 (`setSkipAllPauses`).

7. **代码评估:**
   - 提供了在指定的 JavaScript 上下文中执行代码片段的功能 (`evaluate`).

8. **搜索功能:**
   - 实现了在文本中按行搜索的功能 (`searchInTextByLines`).

9. **覆盖率信息:**
   - 触发精确覆盖率增量更新 (`triggerPreciseCoverageDeltaUpdate`).

**与 JavaScript 的关系和示例:**

该文件是 V8 Inspector 功能的 C++ 实现，直接服务于 JavaScript 的调试和分析。 它允许开发者通过调试客户端 (例如 Chrome DevTools) 来观察和控制 JavaScript 代码的执行。

以下是一些与 JavaScript 功能相关的示例，以 JavaScript 代码和其在 Inspector 中的行为来解释：

**1. 断点 (Breakpoints):**

   - **JavaScript:** 在 JavaScript 代码中设置断点。
     ```javascript
     function myFunction() {
       console.log("开始执行"); // 这里设置了一个断点
       let x = 10;
       x++;
       console.log("执行结束", x);
     }
     myFunction();
     ```
   - **C++ (`V8DebuggerAgentImpl` 和 `V8InspectorSessionImpl` 协同工作):** 当 JavaScript 引擎执行到断点时，`V8DebuggerAgentImpl` 会通知 `V8InspectorSessionImpl`，后者会通过调试协议向客户端发送暂停通知，使得 Chrome DevTools 停止 JavaScript 的执行，允许开发者查看变量值、调用栈等。

**2. 代码评估 (Evaluation):**

   - **JavaScript (在 Chrome DevTools Console 中):** 在调试过程中，可以在 Console 中输入 JavaScript 代码并执行。
     ```javascript
     x + 5 // 假设当前作用域中存在变量 x
     ```
   - **C++ (`V8InspectorSessionImpl::evaluate`):**  当开发者在 Console 中输入代码时，Chrome DevTools 将评估请求发送给 `V8InspectorSessionImpl`，`evaluate` 函数会将该代码传递给 V8 引擎执行，并将结果封装成 `RemoteObject` 返回给客户端显示。

**3. 对象检查 (Object Inspection):**

   - **JavaScript:** 观察 JavaScript 对象的值。
     ```javascript
     let myObject = { a: 1, b: "hello" };
     ```
   - **C++ (`V8InspectorSessionImpl::wrapObject`):** 当你在 Chrome DevTools 的 "Sources" 或 "Console" 中查看 `myObject` 时，V8 会使用 `wrapObject` 将 `myObject` 包装成 `RemoteObject`，以便在调试协议中传输其属性和值，并在 DevTools 中呈现。

**4. 调用栈 (Call Stack):**

   - **JavaScript:** 查看当前执行的函数调用链。
     ```javascript
     function a() {
       b();
     }
     function b() {
       debugger; // 手动触发断点
     }
     a();
     ```
   - **C++ (`V8DebuggerAgentImpl`):** 当代码执行到 `debugger` 语句或断点时，`V8DebuggerAgentImpl` 会收集当前的调用栈信息，并通过 `V8InspectorSessionImpl` 发送给 Chrome DevTools，显示当前的函数调用顺序。

**总结:**

`v8-inspector-session-impl.cc` 文件是 V8 Inspector 功能的关键组成部分，它充当调试客户端和 V8 引擎之间的桥梁，负责处理调试协议消息，协调各种 Inspector Agents，并提供与 JavaScript 运行时交互的能力，使得开发者可以通过调试工具有效地调试和分析 JavaScript 代码。它背后的 C++ 代码直接支撑着我们在 Chrome DevTools 中使用的各种强大的 JavaScript 调试功能。

Prompt: 
```
这是目录为v8/src/inspector/v8-inspector-session-impl.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/inspector/v8-inspector-session-impl.h"

#include "../../third_party/inspector_protocol/crdtp/cbor.h"
#include "../../third_party/inspector_protocol/crdtp/dispatch.h"
#include "../../third_party/inspector_protocol/crdtp/json.h"
#include "include/v8-context.h"
#include "include/v8-microtask-queue.h"
#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/inspector/injected-script.h"
#include "src/inspector/inspected-context.h"
#include "src/inspector/protocol/Protocol.h"
#include "src/inspector/remote-object-id.h"
#include "src/inspector/search-util.h"
#include "src/inspector/string-util.h"
#include "src/inspector/v8-console-agent-impl.h"
#include "src/inspector/v8-debugger-agent-impl.h"
#include "src/inspector/v8-debugger-barrier.h"
#include "src/inspector/v8-debugger.h"
#include "src/inspector/v8-heap-profiler-agent-impl.h"
#include "src/inspector/v8-inspector-impl.h"
#include "src/inspector/v8-profiler-agent-impl.h"
#include "src/inspector/v8-runtime-agent-impl.h"
#include "src/inspector/v8-schema-agent-impl.h"

namespace v8_inspector {
namespace {
using v8_crdtp::span;
using v8_crdtp::SpanFrom;
using v8_crdtp::Status;
using v8_crdtp::cbor::CheckCBORMessage;
using v8_crdtp::json::ConvertCBORToJSON;
using v8_crdtp::json::ConvertJSONToCBOR;

bool IsCBORMessage(StringView msg) {
  if (!msg.is8Bit() || msg.length() < 3) return false;
  const uint8_t* bytes = msg.characters8();
  return bytes[0] == 0xd8 &&
         (bytes[1] == 0x5a || (bytes[1] == 0x18 && bytes[2] == 0x5a));
}

Status ConvertToCBOR(StringView state, std::vector<uint8_t>* cbor) {
  return state.is8Bit()
             ? ConvertJSONToCBOR(
                   span<uint8_t>(state.characters8(), state.length()), cbor)
             : ConvertJSONToCBOR(
                   span<uint16_t>(state.characters16(), state.length()), cbor);
}

std::unique_ptr<protocol::DictionaryValue> ParseState(StringView state) {
  std::vector<uint8_t> converted;
  span<uint8_t> cbor;
  if (IsCBORMessage(state))
    cbor = span<uint8_t>(state.characters8(), state.length());
  else if (ConvertToCBOR(state, &converted).ok())
    cbor = SpanFrom(converted);
  if (!cbor.empty()) {
    std::unique_ptr<protocol::Value> value =
        protocol::Value::parseBinary(cbor.data(), cbor.size());
    std::unique_ptr<protocol::DictionaryValue> dictionaryValue =
        protocol::DictionaryValue::cast(std::move(value));
    if (dictionaryValue) return dictionaryValue;
  }
  return protocol::DictionaryValue::create();
}
}  // namespace

// static
bool V8InspectorSession::canDispatchMethod(StringView method) {
  return stringViewStartsWith(method,
                              protocol::Runtime::Metainfo::commandPrefix) ||
         stringViewStartsWith(method,
                              protocol::Debugger::Metainfo::commandPrefix) ||
         stringViewStartsWith(method,
                              protocol::Profiler::Metainfo::commandPrefix) ||
         stringViewStartsWith(
             method, protocol::HeapProfiler::Metainfo::commandPrefix) ||
         stringViewStartsWith(method,
                              protocol::Console::Metainfo::commandPrefix) ||
         stringViewStartsWith(method,
                              protocol::Schema::Metainfo::commandPrefix);
}

// static
int V8ContextInfo::executionContextId(v8::Local<v8::Context> context) {
  return InspectedContext::contextId(context);
}

std::unique_ptr<V8InspectorSessionImpl> V8InspectorSessionImpl::create(
    V8InspectorImpl* inspector, int contextGroupId, int sessionId,
    V8Inspector::Channel* channel, StringView state,
    V8Inspector::ClientTrustLevel clientTrustLevel,
    std::shared_ptr<V8DebuggerBarrier> debuggerBarrier) {
  return std::unique_ptr<V8InspectorSessionImpl>(new V8InspectorSessionImpl(
      inspector, contextGroupId, sessionId, channel, state, clientTrustLevel,
      std::move(debuggerBarrier)));
}

V8InspectorSessionImpl::V8InspectorSessionImpl(
    V8InspectorImpl* inspector, int contextGroupId, int sessionId,
    V8Inspector::Channel* channel, StringView savedState,
    V8Inspector::ClientTrustLevel clientTrustLevel,
    std::shared_ptr<V8DebuggerBarrier> debuggerBarrier)
    : m_contextGroupId(contextGroupId),
      m_sessionId(sessionId),
      m_inspector(inspector),
      m_channel(channel),
      m_customObjectFormatterEnabled(false),
      m_dispatcher(this),
      m_state(ParseState(savedState)),
      m_runtimeAgent(nullptr),
      m_debuggerAgent(nullptr),
      m_heapProfilerAgent(nullptr),
      m_profilerAgent(nullptr),
      m_consoleAgent(nullptr),
      m_schemaAgent(nullptr),
      m_clientTrustLevel(clientTrustLevel) {
  m_state->getBoolean("use_binary_protocol", &use_binary_protocol_);

  m_runtimeAgent.reset(new V8RuntimeAgentImpl(
      this, this, agentState(protocol::Runtime::Metainfo::domainName),
      std::move(debuggerBarrier)));
  protocol::Runtime::Dispatcher::wire(&m_dispatcher, m_runtimeAgent.get());

  m_debuggerAgent.reset(new V8DebuggerAgentImpl(
      this, this, agentState(protocol::Debugger::Metainfo::domainName)));
  protocol::Debugger::Dispatcher::wire(&m_dispatcher, m_debuggerAgent.get());

  m_consoleAgent.reset(new V8ConsoleAgentImpl(
      this, this, agentState(protocol::Console::Metainfo::domainName)));
  protocol::Console::Dispatcher::wire(&m_dispatcher, m_consoleAgent.get());

  m_profilerAgent.reset(new V8ProfilerAgentImpl(
      this, this, agentState(protocol::Profiler::Metainfo::domainName)));
  protocol::Profiler::Dispatcher::wire(&m_dispatcher, m_profilerAgent.get());

  if (m_clientTrustLevel == V8Inspector::kFullyTrusted) {
    m_heapProfilerAgent.reset(new V8HeapProfilerAgentImpl(
        this, this, agentState(protocol::HeapProfiler::Metainfo::domainName)));
    protocol::HeapProfiler::Dispatcher::wire(&m_dispatcher,
                                             m_heapProfilerAgent.get());

    m_schemaAgent.reset(new V8SchemaAgentImpl(
        this, this, agentState(protocol::Schema::Metainfo::domainName)));
    protocol::Schema::Dispatcher::wire(&m_dispatcher, m_schemaAgent.get());
  }
  if (savedState.length()) {
    m_runtimeAgent->restore();
    m_debuggerAgent->restore();
    if (m_heapProfilerAgent) m_heapProfilerAgent->restore();
    m_profilerAgent->restore();
    m_consoleAgent->restore();
  }
}

V8InspectorSessionImpl::~V8InspectorSessionImpl() {
  v8::Isolate::Scope scope(m_inspector->isolate());
  discardInjectedScripts();
  m_consoleAgent->disable();
  m_profilerAgent->disable();
  if (m_heapProfilerAgent) m_heapProfilerAgent->disable();
  m_debuggerAgent->disable();
  m_runtimeAgent->disable();
  m_inspector->disconnect(this);
}

protocol::DictionaryValue* V8InspectorSessionImpl::agentState(
    const String16& name) {
  protocol::DictionaryValue* state = m_state->getObject(name);
  if (!state) {
    std::unique_ptr<protocol::DictionaryValue> newState =
        protocol::DictionaryValue::create();
    state = newState.get();
    m_state->setObject(name, std::move(newState));
  }
  return state;
}

std::unique_ptr<StringBuffer> V8InspectorSessionImpl::serializeForFrontend(
    std::unique_ptr<protocol::Serializable> message) {
  std::vector<uint8_t> cbor = message->Serialize();
  DCHECK(CheckCBORMessage(SpanFrom(cbor)).ok());
  if (use_binary_protocol_) return StringBufferFrom(std::move(cbor));
  std::vector<uint8_t> json;
  Status status = ConvertCBORToJSON(SpanFrom(cbor), &json);
  DCHECK(status.ok());
  USE(status);
  // TODO(johannes): It should be OK to make a StringBuffer from |json|
  // directly, since it's 7 Bit US-ASCII with anything else escaped.
  // However it appears that the Node.js tests (or perhaps even production)
  // assume that the StringBuffer is 16 Bit. It probably accesses
  // characters16() somehwere without checking is8Bit. Until it's fixed
  // we take a detour via String16 which makes the StringBuffer 16 bit.
  String16 string16(reinterpret_cast<const char*>(json.data()), json.size());
  return StringBufferFrom(std::move(string16));
}

void V8InspectorSessionImpl::SendProtocolResponse(
    int callId, std::unique_ptr<protocol::Serializable> message) {
  m_channel->sendResponse(callId, serializeForFrontend(std::move(message)));
}

void V8InspectorSessionImpl::SendProtocolNotification(
    std::unique_ptr<protocol::Serializable> message) {
  m_channel->sendNotification(serializeForFrontend(std::move(message)));
}

void V8InspectorSessionImpl::FallThrough(int callId,
                                         const v8_crdtp::span<uint8_t> method,
                                         v8_crdtp::span<uint8_t> message) {
  // There's no other layer to handle the command.
  UNREACHABLE();
}

void V8InspectorSessionImpl::FlushProtocolNotifications() {
  m_channel->flushProtocolNotifications();
}

void V8InspectorSessionImpl::reset() {
  m_debuggerAgent->reset();
  m_runtimeAgent->reset();
  discardInjectedScripts();
}

void V8InspectorSessionImpl::discardInjectedScripts() {
  m_inspectedObjects.clear();
  int sessionId = m_sessionId;
  m_inspector->forEachContext(m_contextGroupId,
                              [&sessionId](InspectedContext* context) {
                                context->discardInjectedScript(sessionId);
                              });
}

Response V8InspectorSessionImpl::findInjectedScript(
    int contextId, InjectedScript*& injectedScript) {
  injectedScript = nullptr;
  InspectedContext* context =
      m_inspector->getContext(m_contextGroupId, contextId);
  if (!context)
    return Response::ServerError("Cannot find context with specified id");
  injectedScript = context->getInjectedScript(m_sessionId);
  if (!injectedScript) {
    injectedScript = context->createInjectedScript(m_sessionId);
    if (m_customObjectFormatterEnabled)
      injectedScript->setCustomObjectFormatterEnabled(true);
  }
  return Response::Success();
}

Response V8InspectorSessionImpl::findInjectedScript(
    RemoteObjectIdBase* objectId, InjectedScript*& injectedScript) {
  if (objectId->isolateId() != m_inspector->isolateId())
    return Response::ServerError("Cannot find context with specified id");
  return findInjectedScript(objectId->contextId(), injectedScript);
}

void V8InspectorSessionImpl::releaseObjectGroup(StringView objectGroup) {
  releaseObjectGroup(toString16(objectGroup));
}

void V8InspectorSessionImpl::releaseObjectGroup(const String16& objectGroup) {
  int sessionId = m_sessionId;
  m_inspector->forEachContext(
      m_contextGroupId, [&objectGroup, &sessionId](InspectedContext* context) {
        InjectedScript* injectedScript = context->getInjectedScript(sessionId);
        if (injectedScript) injectedScript->releaseObjectGroup(objectGroup);
      });
}

bool V8InspectorSessionImpl::unwrapObject(
    std::unique_ptr<StringBuffer>* error, StringView objectId,
    v8::Local<v8::Value>* object, v8::Local<v8::Context>* context,
    std::unique_ptr<StringBuffer>* objectGroup) {
  String16 objectGroupString;
  Response response = unwrapObject(toString16(objectId), object, context,
                                   objectGroup ? &objectGroupString : nullptr);
  if (response.IsError()) {
    if (error) {
      const std::string& msg = response.Message();
      *error = StringBufferFrom(String16::fromUTF8(msg.data(), msg.size()));
    }
    return false;
  }
  if (objectGroup)
    *objectGroup = StringBufferFrom(std::move(objectGroupString));
  return true;
}

Response V8InspectorSessionImpl::unwrapObject(const String16& objectId,
                                              v8::Local<v8::Value>* object,
                                              v8::Local<v8::Context>* context,
                                              String16* objectGroup) {
  std::unique_ptr<RemoteObjectId> remoteId;
  Response response = RemoteObjectId::parse(objectId, &remoteId);
  if (!response.IsSuccess()) return response;
  InjectedScript* injectedScript = nullptr;
  response = findInjectedScript(remoteId.get(), injectedScript);
  if (!response.IsSuccess()) return response;
  response = injectedScript->findObject(*remoteId, object);
  if (!response.IsSuccess()) return response;
  *context = injectedScript->context()->context();
  if (objectGroup) *objectGroup = injectedScript->objectGroupName(*remoteId);
  return Response::Success();
}

std::unique_ptr<protocol::Runtime::API::RemoteObject>
V8InspectorSessionImpl::wrapObject(v8::Local<v8::Context> context,
                                   v8::Local<v8::Value> value,
                                   StringView groupName, bool generatePreview) {
  return wrapObject(context, value, toString16(groupName), generatePreview);
}

std::unique_ptr<protocol::Runtime::RemoteObject>
V8InspectorSessionImpl::wrapObject(v8::Local<v8::Context> context,
                                   v8::Local<v8::Value> value,
                                   const String16& groupName,
                                   bool generatePreview) {
  InjectedScript* injectedScript = nullptr;
  findInjectedScript(InspectedContext::contextId(context), injectedScript);
  if (!injectedScript) return nullptr;
  std::unique_ptr<protocol::Runtime::RemoteObject> result;
  injectedScript->wrapObject(value, groupName,
                             generatePreview ? WrapOptions({WrapMode::kPreview})
                                             : WrapOptions({WrapMode::kIdOnly}),
                             &result);
  return result;
}

std::unique_ptr<protocol::Runtime::RemoteObject>
V8InspectorSessionImpl::wrapTable(v8::Local<v8::Context> context,
                                  v8::Local<v8::Object> table,
                                  v8::MaybeLocal<v8::Array> columns) {
  InjectedScript* injectedScript = nullptr;
  findInjectedScript(InspectedContext::contextId(context), injectedScript);
  if (!injectedScript) return nullptr;
  return injectedScript->wrapTable(table, columns);
}

void V8InspectorSessionImpl::setCustomObjectFormatterEnabled(bool enabled) {
  m_customObjectFormatterEnabled = enabled;
  int sessionId = m_sessionId;
  m_inspector->forEachContext(
      m_contextGroupId, [&enabled, &sessionId](InspectedContext* context) {
        InjectedScript* injectedScript = context->getInjectedScript(sessionId);
        if (injectedScript)
          injectedScript->setCustomObjectFormatterEnabled(enabled);
      });
}

void V8InspectorSessionImpl::reportAllContexts(V8RuntimeAgentImpl* agent) {
  m_inspector->forEachContext(m_contextGroupId,
                              [&agent](InspectedContext* context) {
                                agent->reportExecutionContextCreated(context);
                              });
}

void V8InspectorSessionImpl::dispatchProtocolMessage(StringView message) {
  using v8_crdtp::span;
  using v8_crdtp::SpanFrom;
  span<uint8_t> cbor;
  std::vector<uint8_t> converted_cbor;
  if (IsCBORMessage(message)) {
    use_binary_protocol_ = true;
    m_state->setBoolean("use_binary_protocol", true);
    cbor = span<uint8_t>(message.characters8(), message.length());
  } else {
    // We're ignoring the return value of the conversion function
    // intentionally. It means the |parsed_message| below will be nullptr.
    auto status = ConvertToCBOR(message, &converted_cbor);
    if (!status.ok()) {
      m_channel->sendNotification(
          serializeForFrontend(v8_crdtp::CreateErrorNotification(
              v8_crdtp::DispatchResponse::ParseError(status.ToASCIIString()))));
      return;
    }
    cbor = SpanFrom(converted_cbor);
  }
  v8_crdtp::Dispatchable dispatchable(cbor);
  if (!dispatchable.ok()) {
    if (!dispatchable.HasCallId()) {
      m_channel->sendNotification(serializeForFrontend(
          v8_crdtp::CreateErrorNotification(dispatchable.DispatchError())));
    } else {
      m_channel->sendResponse(
          dispatchable.CallId(),
          serializeForFrontend(v8_crdtp::CreateErrorResponse(
              dispatchable.CallId(), dispatchable.DispatchError())));
    }
    return;
  }
  m_dispatcher.Dispatch(dispatchable).Run();
}

std::vector<uint8_t> V8InspectorSessionImpl::state() {
  return m_state->Serialize();
}

std::vector<std::unique_ptr<protocol::Schema::API::Domain>>
V8InspectorSessionImpl::supportedDomains() {
  std::vector<std::unique_ptr<protocol::Schema::Domain>> domains =
      supportedDomainsImpl();
  std::vector<std::unique_ptr<protocol::Schema::API::Domain>> result;
  for (size_t i = 0; i < domains.size(); ++i)
    result.push_back(std::move(domains[i]));
  return result;
}

std::vector<std::unique_ptr<protocol::Schema::Domain>>
V8InspectorSessionImpl::supportedDomainsImpl() {
  std::vector<std::unique_ptr<protocol::Schema::Domain>> result;
  result.push_back(protocol::Schema::Domain::create()
                       .setName(protocol::Runtime::Metainfo::domainName)
                       .setVersion(protocol::Runtime::Metainfo::version)
                       .build());
  result.push_back(protocol::Schema::Domain::create()
                       .setName(protocol::Debugger::Metainfo::domainName)
                       .setVersion(protocol::Debugger::Metainfo::version)
                       .build());
  result.push_back(protocol::Schema::Domain::create()
                       .setName(protocol::Profiler::Metainfo::domainName)
                       .setVersion(protocol::Profiler::Metainfo::version)
                       .build());
  result.push_back(protocol::Schema::Domain::create()
                       .setName(protocol::HeapProfiler::Metainfo::domainName)
                       .setVersion(protocol::HeapProfiler::Metainfo::version)
                       .build());
  result.push_back(protocol::Schema::Domain::create()
                       .setName(protocol::Schema::Metainfo::domainName)
                       .setVersion(protocol::Schema::Metainfo::version)
                       .build());
  return result;
}

void V8InspectorSessionImpl::addInspectedObject(
    std::unique_ptr<V8InspectorSession::Inspectable> inspectable) {
  m_inspectedObjects.insert(m_inspectedObjects.begin(), std::move(inspectable));
  if (m_inspectedObjects.size() > kInspectedObjectBufferSize)
    m_inspectedObjects.resize(kInspectedObjectBufferSize);
}

V8InspectorSession::Inspectable* V8InspectorSessionImpl::inspectedObject(
    unsigned num) {
  if (num >= m_inspectedObjects.size()) return nullptr;
  return m_inspectedObjects[num].get();
}

void V8InspectorSessionImpl::schedulePauseOnNextStatement(
    StringView breakReason, StringView breakDetails) {
  std::vector<uint8_t> cbor;
  ConvertToCBOR(breakDetails, &cbor);
  m_debuggerAgent->schedulePauseOnNextStatement(
      toString16(breakReason),
      protocol::DictionaryValue::cast(
          protocol::Value::parseBinary(cbor.data(), cbor.size())));
}

void V8InspectorSessionImpl::cancelPauseOnNextStatement() {
  m_debuggerAgent->cancelPauseOnNextStatement();
}

void V8InspectorSessionImpl::breakProgram(StringView breakReason,
                                          StringView breakDetails) {
  std::vector<uint8_t> cbor;
  ConvertToCBOR(breakDetails, &cbor);
  m_debuggerAgent->breakProgram(
      toString16(breakReason),
      protocol::DictionaryValue::cast(
          protocol::Value::parseBinary(cbor.data(), cbor.size())));
}

void V8InspectorSessionImpl::setSkipAllPauses(bool skip) {
  m_debuggerAgent->setSkipAllPauses(skip);
}

void V8InspectorSessionImpl::resume(bool terminateOnResume) {
  m_debuggerAgent->resume(terminateOnResume);
}

void V8InspectorSessionImpl::stepOver() { m_debuggerAgent->stepOver({}); }

std::vector<std::unique_ptr<protocol::Debugger::API::SearchMatch>>
V8InspectorSessionImpl::searchInTextByLines(StringView text, StringView query,
                                            bool caseSensitive, bool isRegex) {
  // TODO(dgozman): search may operate on StringView and avoid copying |text|.
  std::vector<std::unique_ptr<protocol::Debugger::SearchMatch>> matches =
      searchInTextByLinesImpl(this, toString16(text), toString16(query),
                              caseSensitive, isRegex);
  std::vector<std::unique_ptr<protocol::Debugger::API::SearchMatch>> result;
  for (size_t i = 0; i < matches.size(); ++i)
    result.push_back(std::move(matches[i]));
  return result;
}

void V8InspectorSessionImpl::triggerPreciseCoverageDeltaUpdate(
    StringView occasion) {
  m_profilerAgent->triggerPreciseCoverageDeltaUpdate(toString16(occasion));
}

V8InspectorSession::EvaluateResult V8InspectorSessionImpl::evaluate(
    v8::Local<v8::Context> context, StringView expression,
    bool includeCommandLineAPI) {
  v8::EscapableHandleScope handleScope(m_inspector->isolate());
  InjectedScript::ContextScope scope(this,
                                     InspectedContext::contextId(context));
  if (!scope.initialize().IsSuccess()) {
    return {EvaluateResult::ResultType::kNotRun, v8::Local<v8::Value>()};
  }

  // Temporarily allow eval.
  scope.allowCodeGenerationFromStrings();
  scope.setTryCatchVerbose();
  if (includeCommandLineAPI) {
    scope.installCommandLineAPI();
  }
  v8::MaybeLocal<v8::Value> maybeResultValue;
  {
    v8::MicrotasksScope microtasksScope(scope.context(),
                                        v8::MicrotasksScope::kRunMicrotasks);
    const v8::Local<v8::String> source =
        toV8String(m_inspector->isolate(), expression);
    maybeResultValue = v8::debug::EvaluateGlobal(
        m_inspector->isolate(), source, v8::debug::EvaluateGlobalMode::kDefault,
        /*repl_mode=*/false);
  }

  if (scope.tryCatch().HasCaught()) {
    return {EvaluateResult::ResultType::kException,
            handleScope.Escape(scope.tryCatch().Exception())};
  }
  v8::Local<v8::Value> result;
  CHECK(maybeResultValue.ToLocal(&result));
  return {EvaluateResult::ResultType::kSuccess, handleScope.Escape(result)};
}

void V8InspectorSessionImpl::stop() { m_debuggerAgent->stop(); }

}  // namespace v8_inspector

"""

```