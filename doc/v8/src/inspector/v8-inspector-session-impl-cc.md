Response:
Let's break down the thought process for analyzing this C++ file and generating the answer.

1. **Initial Scan and Keyword Spotting:**  The first step is to quickly scan the file for recognizable keywords and patterns. Things that jump out include: `#include`, `namespace v8_inspector`, class names like `V8InspectorSessionImpl`,  method names that look like protocol commands (`SendProtocolResponse`, `dispatchProtocolMessage`), and mentions of "inspector," "debugger," "profiler," etc. This gives a high-level indication of the file's purpose.

2. **Identify the Core Class:** The name `V8InspectorSessionImpl` strongly suggests this class represents a single debugging/inspection session. The "Impl" suffix often indicates a concrete implementation of an interface (likely `V8InspectorSession`).

3. **Analyze `#include` Statements:**  The included headers provide valuable clues about dependencies and functionality. For example:
    * `"src/inspector/v8-inspector-impl.h"`:  This suggests `V8InspectorSessionImpl` is part of a larger inspector framework.
    * `"../../third_party/inspector_protocol/crdtp/...`": This clearly points to the use of the Chrome Remote Debugging Protocol (CRDP), indicating communication with a debugging client. The presence of both JSON and CBOR suggests support for both text-based and binary protocols.
    * `"src/inspector/v8-console-agent-impl.h"`, `"src/inspector/v8-debugger-agent-impl.h"`, etc.:  These strongly suggest that the session manages various debugging/profiling agents.

4. **Examine the Constructor and `create` Method:**  The constructor and the static `create` method reveal how a `V8InspectorSessionImpl` is instantiated. Key parameters like `contextGroupId`, `sessionId`, `channel`, and `state` provide information about the session's context and initialization. The `state` parameter suggests the ability to restore previous session data.

5. **Focus on Key Methods:**  Start analyzing the core functionalities exposed by the class's methods:
    * **`dispatchProtocolMessage`**: This is a critical method responsible for handling incoming messages from the debugging client. The logic involving JSON and CBOR conversion is important.
    * **`SendProtocolResponse` and `SendProtocolNotification`**: These methods handle sending messages back to the client. The serialization logic (to CBOR or JSON) is relevant.
    * **Methods related to agents (`m_runtimeAgent`, `m_debuggerAgent`, etc.)**:  Note how these agents are created, wired to the dispatcher, and have methods like `restore`, `disable`, and domain-specific actions.
    * **Methods related to object handling (`wrapObject`, `unwrapObject`, `releaseObjectGroup`)**:  These are fundamental for inspecting JavaScript objects.
    * **Methods related to debugging control (`schedulePauseOnNextStatement`, `resume`, `stepOver`, `breakProgram`)**:  These directly interact with the V8 debugger.
    * **`evaluate`**:  This method allows evaluating JavaScript code within a specific context.

6. **Identify Key Data Members:**  Pay attention to the member variables:
    * `m_channel`:  The communication channel to the client.
    * `m_state`:  Stores the session's state.
    * Agent pointers (`m_runtimeAgent`, etc.):  Represent the different debugging/profiling components.
    * `m_inspectedObjects`:  Manages a history of inspected objects.
    * `use_binary_protocol_`:  Indicates the communication protocol.

7. **Look for Patterns and Relationships:** Observe how different parts of the class interact. For example, how `dispatchProtocolMessage` uses the dispatcher to invoke methods on the agent classes.

8. **Address Specific Requirements of the Prompt:** Now, systematically address each point in the prompt:
    * **Functionality Listing:**  Summarize the identified functionalities in clear bullet points.
    * **Torque Check:**  Look for the `.tq` extension in the filename. If absent, state that it's not a Torque file.
    * **JavaScript Relationship and Example:** Focus on methods that directly interact with JavaScript concepts (like evaluating code, wrapping/unwrapping objects). Create a simple JavaScript example demonstrating a relevant interaction.
    * **Code Logic Reasoning (Hypothetical Input/Output):** Choose a method with clear input and output, like `unwrapObject`. Define a hypothetical input (an object ID) and the expected output (the corresponding JavaScript value and context).
    * **Common Programming Errors:** Think about common mistakes developers make when working with debugging tools (e.g., incorrect object IDs, trying to access objects from the wrong context).

9. **Refine and Organize:**  Review the generated answer for clarity, accuracy, and completeness. Organize the information logically. Use clear and concise language.

**Self-Correction/Refinement during the Process:**

* **Initial Thought:**  Maybe the file just handles basic session management.
* **Correction:**  The presence of multiple agent classes and protocol dispatching indicates a much broader responsibility, encompassing various debugging and profiling features.
* **Initial Thought:** The `state` parameter is just for storing simple settings.
* **Correction:** The parsing logic for both JSON and CBOR suggests it's used to persist a more complex session state, potentially including breakpoints, settings, etc.
* **Initial Thought:** The JavaScript example should be very complex.
* **Correction:** A simple example demonstrating the basic interaction with the debugger (like setting a breakpoint) is sufficient to illustrate the concept.

By following this structured approach, including initial scanning, detailed analysis of key components, and systematic addressing of the prompt's requirements, it's possible to generate a comprehensive and accurate answer.
This C++ source file, `v8/src/inspector/v8-inspector-session-impl.cc`, implements the core logic for a debugging/inspection session within the V8 JavaScript engine's inspector framework. Here's a breakdown of its functionalities:

**Core Functionalities:**

* **Session Management:**
    * **Creation and Destruction:** Creates and manages a single inspector session (`V8InspectorSessionImpl`) associated with a specific context group and session ID.
    * **Communication Channel:**  Handles communication with the debugging client (e.g., Chrome DevTools) through a `V8Inspector::Channel`.
    * **State Management:**  Stores and restores the session's state, including settings and agent-specific configurations. This allows the debugger to resume its state after disconnection.
    * **Disconnection Handling:**  Handles the disconnection of the debugging session.

* **Message Dispatching:**
    * **Protocol Message Handling:** Receives and dispatches messages from the debugging client, adhering to the Chrome DevTools Protocol (CDP). It supports both JSON and CBOR (binary) formats for message encoding.
    * **Command Routing:** Routes incoming commands to the appropriate domain agents (e.g., Runtime, Debugger, Profiler, HeapProfiler, Console, Schema).
    * **Response and Notification Sending:** Sends responses to commands and pushes notifications to the debugging client.

* **Integration with V8:**
    * **Context Awareness:**  Operates within the context of V8 JavaScript contexts.
    * **Object Wrapping and Unwrapping:** Provides mechanisms to wrap V8 JavaScript objects into remote objects that can be inspected by the client and to unwrap remote object IDs back into V8 objects.
    * **Code Evaluation:** Allows evaluating JavaScript code within a specific V8 context on behalf of the debugging client.
    * **Microtask Integration:** Executes microtasks during evaluation.

* **Debugging Capabilities (through Agents):**
    * **Debugger Agent Integration (`V8DebuggerAgentImpl`):** Enables debugging features like setting breakpoints, stepping through code, pausing execution, and inspecting call stacks and scopes.
    * **Runtime Agent Integration (`V8RuntimeAgentImpl`):**  Provides runtime inspection features, such as inspecting variables, calling functions, and managing execution contexts.
    * **Profiler Agent Integration (`V8ProfilerAgentImpl`):**  Handles CPU profiling.
    * **Heap Profiler Agent Integration (`V8HeapProfilerAgentImpl`):** Manages heap snapshotting and analysis (only enabled for fully trusted clients).
    * **Console Agent Integration (`V8ConsoleAgentImpl`):**  Captures and forwards console messages to the debugging client.
    * **Schema Agent Integration (`V8SchemaAgentImpl`):**  Provides information about the supported debugging protocol (only enabled for fully trusted clients).

* **Object Inspection:**
    * **Object Grouping:**  Allows grouping of remote objects for coordinated release.
    * **Custom Object Formatting:** Supports custom formatting of objects displayed in the debugger.
    * **Inspected Object History:** Maintains a buffer of recently inspected objects.

* **Search Functionality:**
    * **Text Searching:** Implements line-by-line text searching within scripts (delegated to `search-util.h`).

**Is it a Torque file?**

No, the filename `v8-inspector-session-impl.cc` ends with `.cc`, which is the standard extension for C++ source files. If it were a Torque source file, it would end with `.tq`.

**Relationship with JavaScript and Example:**

This file is deeply related to JavaScript debugging. It provides the underlying infrastructure that allows developers to interact with the JavaScript runtime through debugging tools.

**JavaScript Example:**

Imagine a simple JavaScript code snippet:

```javascript
function myFunction(a, b) {
  console.log("Adding numbers");
  let sum = a + b;
  debugger; // Sets a breakpoint
  return sum;
}

myFunction(5, 10);
```

When this code is executed in an environment where the inspector is active (like a web browser with DevTools open or Node.js with the `--inspect` flag), the `V8InspectorSessionImpl` plays a crucial role when the `debugger;` statement is encountered:

1. **Pause Execution:** The `V8DebuggerAgentImpl`, managed by the `V8InspectorSessionImpl`, receives a notification from the V8 engine about hitting the breakpoint.
2. **Send Notification:**  The `V8InspectorSessionImpl` uses its communication channel to send a "Debugger.paused" notification to the debugging client (DevTools). This notification includes information about the current location in the code, the call stack, and the available scopes.
3. **Client Interaction:** The developer in DevTools can then use commands like "step over," "step into," "continue," or inspect variables.
4. **Command Dispatch:** When the developer clicks "step over," DevTools sends a "Debugger.stepOver" command back to V8.
5. **Action Execution:** The `V8InspectorSessionImpl`'s `dispatchProtocolMessage` method receives this command and routes it to the `V8DebuggerAgentImpl`, which then instructs the V8 engine to step over the current line.
6. **Response:**  V8 executes the step, and the `V8DebuggerAgentImpl` (via `V8InspectorSessionImpl`) sends a "Debugger.resumed" or another "Debugger.paused" notification back to DevTools, updating the debugging UI.

**Code Logic Reasoning (Hypothetical Input & Output):**

Let's consider the `unwrapObject` method.

**Hypothetical Input:**

* `objectId`:  A string representing a remote object ID, e.g., `"{\"injectedScriptId\":1,\"id\":2}"`. This ID refers to an object previously wrapped and sent to the debugger client.
* Context: A valid V8 JavaScript context.

**Assumptions:**

* The remote object ID is valid and corresponds to an object that exists within the provided context's injected script.
* An `InjectedScript` instance exists for the given context and session.

**Expected Output:**

* `object`: A `v8::Local<v8::Value>` representing the actual JavaScript object in the V8 heap.
* `context`: The same input V8 JavaScript context.
* The method returns `Response::Success()`.

**Reasoning:**

1. The `unwrapObject` method will parse the `objectId` to extract the injected script ID and object ID.
2. It will find the corresponding `InjectedScript` instance associated with the context.
3. The `InjectedScript` will use its internal mapping to retrieve the original V8 object based on the provided object ID.
4. The method will then populate the `object` parameter with this retrieved V8 object and return success.

**If the `objectId` were invalid (e.g., incorrect format or non-existent ID):**

* The method would return `Response::ServerError` with an appropriate error message.
* The `object` parameter would likely be left unchanged or set to an invalid value.

**User-Common Programming Errors:**

* **Incorrect Object IDs:**  Users might try to use an `objectId` from a different debugging session or one that has become invalid (e.g., after garbage collection if not properly retained by the debugger). The `unwrapObject` method would fail in this case.
* **Accessing Objects from the Wrong Context:** Trying to `unwrapObject` in a V8 context where the object doesn't exist (e.g., after navigating to a different page in a browser). The `findInjectedScript` method would likely fail, leading to an error.
* **Releasing Object Groups Prematurely:**  A user might release an object group that still contains objects they intend to inspect later. This would invalidate the remote object IDs within that group.
* **Misunderstanding Asynchronous Operations:** In a Node.js environment, for example, a developer might set a breakpoint within an asynchronous callback and try to inspect variables from the outer scope *after* the outer scope has already completed and its variables are no longer accessible. The inspector provides tools to help with this, but incorrect assumptions can lead to confusion.

**Example of Incorrect Object ID:**

```javascript
// Assume you have a valid remote object ID "{\"injectedScriptId\":1,\"id\":5}"
// from a previous debugging session.

// ... later, in a completely different debugging session or after the object
// has been garbage collected ...

// Trying to unwrap the old ID would fail.
// (This is a conceptual example; you wouldn't directly call unwrapObject from JS)
```

In summary, `v8/src/inspector/v8-inspector-session-impl.cc` is a crucial component in V8's debugging infrastructure, responsible for managing individual debugging sessions, handling communication with clients, and orchestrating the various debugging agents to provide a rich set of inspection and debugging capabilities for JavaScript code.

Prompt: 
```
这是目录为v8/src/inspector/v8-inspector-session-impl.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/v8-inspector-session-impl.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

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