Response:
Let's break down the thought process for analyzing this `DevToolsSession.cc` file.

1. **Understand the Core Purpose:**  The filename and the `DevToolsSession` class name immediately suggest this file is central to how the browser communicates with DevTools. DevTools needs to inspect and control the browser, so this class likely handles the session-level management of that interaction.

2. **Identify Key Dependencies and Included Headers:**  The `#include` directives are crucial for understanding the file's scope and functionality. I'd look for:
    * **Fundamental C++:** `<string>`, `<utility>`, `<vector>` for basic data structures.
    * **Threading/Concurrency:** `base/task/sequenced_task_runner.h`, `base/task/single_thread_task_runner.h`, `third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h`. These indicate the class interacts with different threads.
    * **Blink-Specific:** Headers in `third_party/blink/renderer/...` are essential. Specifically:
        * `core/frame/local_frame.h`: Suggests interaction with web page frames.
        * `core/inspector/...`:  Lots of inspector-related headers! `DevToolsAgent`, `InspectedFrames`, `InspectorBaseAgent`, `InspectorSessionState`, `InspectorTaskRunner`, `protocol/protocol.h`. These confirm the file's central role in DevTools.
        * `bindings/core/v8/script_controller.h`: Hints at interaction with JavaScript via V8.
    * **Mojo:**  Headers like `third_party/blink/renderer/platform/wtf/cross_thread_copier_mojo.h` and the `mojom::blink::DevToolsSession` mentions indicate communication using Mojo IPC.
    * **Tracing/Debugging:** `base/trace_event/trace_event.h`.
    * **Protocol Handling:** `third_party/inspector_protocol/crdtp/...`. Crucial for understanding how DevTools commands and responses are structured.

3. **Analyze Class Structure and Key Methods:**  The `DevToolsSession` class is the main focus. I'd look at:
    * **Constructor:** How is it initialized? What parameters does it take?  The parameters reveal key associations (e.g., with `DevToolsAgent`, Mojo interfaces).
    * **Destructor:**  What cleanup happens?
    * **`ConnectToV8`:**  Clearly establishes the connection with the V8 JavaScript engine's inspector.
    * **`DispatchProtocolCommand` and `DispatchProtocolCommandImpl`:**  These are the core methods for receiving and handling commands from DevTools. Note the threading considerations (posting tasks).
    * **`SendProtocolResponse` and `SendProtocolNotification`:**  These handle sending data back to DevTools.
    * **`Attach`, `Detach`, `DetachFromV8`:** Methods for managing the session lifecycle.
    * **Methods related to page loading:** `DidStartProvisionalLoad`, `DidFailProvisionalLoad`, `DidCommitLoad`. These link the DevTools session to the lifecycle of web pages.
    * **The nested `IOSession` class:**  Recognize that this handles the Mojo IPC on a separate thread.

4. **Identify Key Functionality Areas (and relate to web technologies):**  Based on the methods and dependencies, I can categorize the functionality:
    * **Communication with DevTools Frontend:**  This is primary. Mojo is the mechanism. The `DispatchProtocolCommand` and `SendProtocol...` methods are central. This relates to *all* DevTools features.
    * **JavaScript Debugging/Inspection:** The interaction with `v8_inspector::V8Inspector` and methods like `ConnectToV8`, and the handling of commands related to `Debugger.*` and `Runtime.*` directly involve JavaScript.
    * **Page Lifecycle Integration:** The `DidStart...`, `DidCommitLoad` methods tie the DevTools session to the loading and navigation of web pages (HTML).
    * **Protocol Handling:** The use of `crdtp` (Chrome Remote Debugging Protocol) indicates how commands and responses are serialized and deserialized. This is the underlying mechanism for all DevTools communication.
    * **Threading and Concurrency:** The file explicitly manages tasks across different threads (IO, Inspector).
    * **Session Management:**  Attaching, detaching, and potentially reattaching sessions.

5. **Look for Specific Code Patterns and Logic:**
    * **`ShouldInterruptForMethod`:** This function highlights which DevTools commands require interrupting the main thread immediately. This is crucial for debugging.
    * **CBOR and JSON handling:** The file explicitly deals with converting between CBOR (binary) and JSON formats for communication.
    * **The `IOSession` class:** Its purpose as a bridge on the IO thread.
    * **The use of `CrossThreadWeakHandle`:**  Essential for safe cross-thread communication.
    * **The `session_state_` and `v8_session_state_`:** These manage persistent state across session reattachments.

6. **Consider Potential Issues and Edge Cases:**
    * **Detachment:** The code explicitly handles scenarios where the session is detached.
    * **Error Handling:**  The `CHECK` statements and the `FinalizeMessage` logic indicate some basic error handling related to protocol conversion.
    * **Threading Issues:**  The cross-thread communication adds complexity and potential for errors if not handled correctly.

7. **Structure the Explanation:**  Organize the findings into logical sections: Core Functionality, Relation to Web Technologies, Logic and Assumptions, Common Errors. Provide concrete examples where possible. For logic and assumptions, create simple "input/output" scenarios.

8. **Refine and Review:**  Read through the explanation to ensure clarity, accuracy, and completeness. Are there any ambiguities?  Are the examples clear?  Have I covered the key aspects of the file?

By following this structured approach, I can systematically analyze the code and generate a comprehensive explanation of its functionality and significance within the Chromium/Blink architecture. The key is to start with the high-level purpose and gradually drill down into the details, focusing on the relationships between different parts of the code and its interaction with other components.
这个文件 `devtools_session.cc` 是 Chromium Blink 引擎中负责管理 DevTools 会话的核心组件。它充当了 DevTools 前端（例如 Chrome 开发者工具）和渲染器内部逻辑之间的桥梁。

以下是它的一些主要功能：

**1. 会话生命周期管理:**
   - **创建和销毁:**  `DevToolsSession` 类负责创建和管理一个 DevTools 会话的生命周期。当 DevTools 前端连接到渲染器时，会创建一个新的 `DevToolsSession` 实例。当连接断开时，会销毁该实例。
   - **连接和断开 V8 调试器:** 它负责与 V8 JavaScript 引擎的调试器建立和断开连接 (`ConnectToV8`, `DetachFromV8`)。这是 DevTools 能够进行 JavaScript 调试、分析等操作的关键。
   - **会话状态管理:** 它管理会话的状态 (`session_state_`, `v8_session_state_`)，允许在会话重新连接时恢复之前的状态。

**2. 消息路由和分发:**
   - **接收 DevTools 命令:** 它通过 Mojo IPC 接收来自 DevTools 前端的协议命令 (`DispatchProtocolCommand`, `DispatchProtocolCommandImpl`)。
   - **分发命令到相应的处理器:**  它使用 `inspector_backend_dispatcher_` 将接收到的协议命令分发到负责处理这些命令的 Inspector Agent（例如，PageAgent 处理页面相关的命令，DOMAgent 处理 DOM 相关的命令）。
   - **发送 DevTools 响应:**  在 Inspector Agent 处理完命令后，`DevToolsSession` 负责将响应发送回 DevTools 前端 (`SendProtocolResponse`)。
   - **发送 DevTools 通知:** 它也负责发送来自渲染器的通知到 DevTools 前端，例如新的 DOM 节点被添加、页面加载完成等 (`SendProtocolNotification`, `sendNotification`)。

**3. 与 V8 Inspector 的交互:**
   - **连接到 V8 Inspector:**  `ConnectToV8` 方法使用 V8 Inspector API 将 DevTools 会话连接到特定上下文组的 V8 Inspector。
   - **分发协议消息到 V8 Inspector:** 对于 JavaScript 相关的命令（例如 `Debugger.evaluateOnCallFrame`, `Runtime.evaluate`），`DevToolsSession` 将这些命令转发到 V8 Inspector (`v8_session_->dispatchProtocolMessage`)。
   - **接收来自 V8 Inspector 的响应和通知:**  虽然代码中没有显式展示接收的逻辑，但 `DevToolsSession` 实现了 `v8_inspector::V8Inspector::Channel` 接口，以便接收来自 V8 Inspector 的响应和通知。

**4. 多线程处理:**
   - **IO 线程处理:** 它使用嵌套的 `IOSession` 类在 IO 线程上处理与 DevTools 前端的 Mojo 通信，以避免阻塞渲染主线程。
   - **Inspector 线程处理:**  大部分的 DevTools 逻辑在 Inspector 线程上执行，通过 `agent_->inspector_task_runner_` 进行调度。

**5. 与 Blink 核心功能的集成:**
   - **监听页面加载事件:** 它监听页面加载相关的事件 (`DidStartProvisionalLoad`, `DidFailProvisionalLoad`, `DidCommitLoad`)，以便在页面导航时更新调试状态。
   - **触发精确覆盖率更新:**  在特定的页面事件（如 `PaintTiming`, `DomContentLoadedEventFired`) 时，它可以触发 V8 Inspector 进行代码覆盖率的增量更新。

**与 JavaScript, HTML, CSS 功能的关系及举例说明:**

`DevToolsSession` 是 DevTools 能够与 JavaScript, HTML, CSS 功能交互的核心。

* **JavaScript:**
    - **调试:** 当 DevTools 前端发送 `Debugger.setBreakpointByUrl` 命令时，`DevToolsSession` 会将其转发给 V8 Inspector，V8 Inspector 会在相应的 JavaScript 代码中设置断点。当代码执行到断点时，V8 Inspector 会发送通知回 `DevToolsSession`，`DevToolsSession` 再将该通知转发到 DevTools 前端，从而暂停代码执行并显示当前状态。
    - **执行代码:** 当 DevTools 前端发送 `Runtime.evaluate` 命令时，`DevToolsSession` 会将其发送到 V8 Inspector，V8 Inspector 会在当前的 JavaScript 上下文中执行该表达式，并将结果返回给 `DevToolsSession`，最终返回给 DevTools 前端。
    - **性能分析:**  DevTools 的性能分析功能依赖于 `Profiler.*` 等命令，这些命令也是通过 `DevToolsSession` 传递给 V8 Inspector 进行处理。

* **HTML:**
    - **元素检查:** 当 DevTools 前端请求查看某个 HTML 元素时，会发送 `DOM.getDocument` 和 `DOM.querySelector` 等命令。`DevToolsSession` 将这些命令路由到 `DOMAgent`，`DOMAgent` 会查询 Blink 的 DOM 树，并将结果返回给 DevTools 前端，显示 HTML 结构。
    - **样式检查:** 当 DevTools 前端请求查看某个元素的 CSS 样式时，会发送 `CSS.getComputedStyleForNode` 等命令。`DevToolsSession` 将这些命令路由到 `CSSAgent`，`CSSAgent` 会计算元素的样式并返回给 DevTools 前端。

* **CSS:**
    - **样式修改:** 当 DevTools 前端尝试修改元素的 CSS 样式时，会发送 `CSS.setStyleTexts` 等命令。`DevToolsSession` 将这些命令路由到 `CSSAgent`，`CSSAgent` 会修改 Blink 内部的样式规则，从而改变页面的渲染效果。

**逻辑推理及假设输入与输出:**

假设输入一个来自 DevTools 前端的命令：

```json
{
  "id": 1,
  "method": "DOM.getDocument",
  "params": {}
}
```

**逻辑推理:**

1. `DevToolsSession::DispatchProtocolCommand` 被调用，`call_id` 为 1，`method` 为 "DOM.getDocument"。
2. `ShouldInterruptForMethod` 返回 `true`（假设 `DOM.getDocument` 不在排除列表中）。
3. `inspector_task_runner_->AppendTask` 将一个任务添加到 Inspector 线程的任务队列中，该任务会调用 `DevToolsSession::DispatchProtocolCommandImpl`。
4. 在 Inspector 线程上，`DevToolsSession::DispatchProtocolCommandImpl` 被执行。
5. `crdtp::Dispatchable` 解析消息。
6. `inspector_backend_dispatcher_->Dispatch` 将该命令分发到 `DOMAgent`。
7. `DOMAgent` 处理该命令，查询 Blink 的 DOM 树并构建响应。
8. `DOMAgent` 调用 `DevToolsSession::SendProtocolResponse` 发送响应。
9. `DevToolsSession::SendProtocolResponse` 将响应通过 Mojo 发送回 DevTools 前端。

**假设输出 (简化):**

```json
{
  "id": 1,
  "result": {
    "root": {
      "nodeId": 1,
      "nodeType": 9,
      "nodeName": "#document",
      // ... 其他 DOM 节点信息
    }
  }
}
```

**用户或编程常见的使用错误及举例说明:**

* **在错误的线程上调用方法:**  例如，直接在 IO 线程上访问 Blink 的核心数据结构（如 DOM 树），而不是通过 Inspector 线程的代理方法。这会导致线程安全问题。
* **不正确地处理异步操作:** DevTools 的很多操作是异步的。如果 Inspector Agent 没有正确处理异步回调，可能会导致数据不一致或程序崩溃。
    * **例子:**  在 `Debugger.pause` 后，如果 Inspector Agent 没有等待 V8 Inspector 的暂停通知就尝试执行其他操作，可能会导致错误。
* **忘记处理会话断开:** 如果 DevTools 前端断开连接，Inspector Agent 需要能够优雅地处理这种情况，释放资源，避免内存泄漏。
    * **例子:**  如果一个 Inspector Agent 在会话断开后仍然持有对 `DevToolsSession` 的引用，可能会导致悬空指针。
* **协议版本不匹配:**  DevTools 前端和 Blink 引擎使用的调试协议版本需要兼容。如果版本不匹配，可能会导致命令无法识别或解析错误。
    * **例子:**  DevTools 前端使用了新的协议特性，但 Blink 引擎的版本不支持，那么相关的命令将无法执行。

总而言之，`devtools_session.cc` 文件是 Blink 引擎中 DevTools 功能的关键入口点，负责协调 DevTools 前端和渲染器内部的各种组件，使得开发者能够对网页进行检查、调试和性能分析。它与 JavaScript, HTML, CSS 的功能都有着密切的关系，是实现这些 DevTools 功能的基础。

### 提示词
```
这是目录为blink/renderer/core/inspector/devtools_session.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/inspector/devtools_session.h"

#include <string>
#include <utility>
#include <vector>

#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/trace_event/trace_event.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/devtools_agent.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/inspector/inspector_base_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_session_state.h"
#include "third_party/blink/renderer/core/inspector/inspector_task_runner.h"
#include "third_party/blink/renderer/core/inspector/protocol/protocol.h"
#include "third_party/blink/renderer/core/inspector/v8_inspector_string.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/web_test_support.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_mojo.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/inspector_protocol/crdtp/cbor.h"
#include "third_party/inspector_protocol/crdtp/dispatch.h"
#include "third_party/inspector_protocol/crdtp/json.h"

namespace blink {

namespace {
const char kV8StateKey[] = "v8";
const char kSessionId[] = "sessionId";

bool ShouldInterruptForMethod(const String& method) {
  return method != "Debugger.evaluateOnCallFrame" &&
         method != "Runtime.evaluate" && method != "Runtime.callFunctionOn" &&
         method != "Runtime.getProperties" && method != "Runtime.runScript";
}

std::vector<uint8_t> Get8BitStringFrom(v8_inspector::StringBuffer* msg) {
  const v8_inspector::StringView& s = msg->string();
  DCHECK(s.is8Bit());
  return std::vector<uint8_t>(s.characters8(), s.characters8() + s.length());
}
}  // namespace

// Created and stored in unique_ptr on UI.
// Binds request, receives messages and destroys on IO.
class DevToolsSession::IOSession : public mojom::blink::DevToolsSession {
 public:
  IOSession(scoped_refptr<base::SingleThreadTaskRunner> io_task_runner,
            scoped_refptr<InspectorTaskRunner> inspector_task_runner,
            CrossThreadWeakHandle<::blink::DevToolsSession> session,
            mojo::PendingReceiver<mojom::blink::DevToolsSession> receiver)
      : io_task_runner_(io_task_runner),
        inspector_task_runner_(inspector_task_runner),
        session_(std::move(session)) {
    PostCrossThreadTask(
        *io_task_runner, FROM_HERE,
        CrossThreadBindOnce(&IOSession::BindInterface,
                            CrossThreadUnretained(this), std::move(receiver)));
  }

  IOSession(const IOSession&) = delete;
  IOSession& operator=(const IOSession&) = delete;

  ~IOSession() override = default;

  void BindInterface(
      mojo::PendingReceiver<mojom::blink::DevToolsSession> receiver) {
    receiver_.Bind(std::move(receiver), io_task_runner_);

    // We set the disconnect handler for the IO session to detach the devtools
    // session from its V8 session. This is necessary to unpause and detach
    // the main thread session if the main thread is blocked in
    // an instrumentation pause.
    receiver_.set_disconnect_handler(WTF::BindOnce(
        [](scoped_refptr<InspectorTaskRunner> inspector_task_runner,
           CrossThreadWeakHandle<::blink::DevToolsSession> session) {
          inspector_task_runner->AppendTask(CrossThreadBindOnce(
              &::blink::DevToolsSession::DetachFromV8,
              MakeUnwrappingCrossThreadWeakHandle(session)));
        },
        inspector_task_runner_, session_));
  }

  void DeleteSoon() { io_task_runner_->DeleteSoon(FROM_HERE, this); }

  // mojom::blink::DevToolsSession implementation.
  void DispatchProtocolCommand(int call_id,
                               const String& method,
                               base::span<const uint8_t> message) override {
    TRACE_EVENT_WITH_FLOW1("devtools", "IOSession::DispatchProtocolCommand",
                           call_id,
                           TRACE_EVENT_FLAG_FLOW_OUT | TRACE_EVENT_FLAG_FLOW_IN,
                           "call_id", call_id);
    // Crash renderer.
    if (method == "Page.crash")
      CHECK(false);
    // Post a task to the worker or main renderer thread that will interrupt V8
    // and be run immediately. Only methods that do not run JS code are safe.
    Vector<uint8_t> message_copy;
    message_copy.AppendSpan(message);
    if (ShouldInterruptForMethod(method)) {
      inspector_task_runner_->AppendTask(CrossThreadBindOnce(
          &::blink::DevToolsSession::DispatchProtocolCommandImpl,
          MakeUnwrappingCrossThreadWeakHandle(session_), call_id, method,
          std::move(message_copy)));
    } else {
      inspector_task_runner_->AppendTaskDontInterrupt(CrossThreadBindOnce(
          &::blink::DevToolsSession::DispatchProtocolCommandImpl,
          MakeUnwrappingCrossThreadWeakHandle(session_), call_id, method,
          std::move(message_copy)));
    }
  }

 private:
  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner_;
  scoped_refptr<InspectorTaskRunner> inspector_task_runner_;
  CrossThreadWeakHandle<::blink::DevToolsSession> session_;
  mojo::Receiver<mojom::blink::DevToolsSession> receiver_{this};
};

DevToolsSession::DevToolsSession(
    DevToolsAgent* agent,
    mojo::PendingAssociatedRemote<mojom::blink::DevToolsSessionHost>
        host_remote,
    mojo::PendingAssociatedReceiver<mojom::blink::DevToolsSession>
        main_receiver,
    mojo::PendingReceiver<mojom::blink::DevToolsSession> io_receiver,
    mojom::blink::DevToolsSessionStatePtr reattach_session_state,
    bool client_expects_binary_responses,
    bool client_is_trusted,
    const String& session_id,
    bool session_waits_for_debugger,
    scoped_refptr<base::SequencedTaskRunner> mojo_task_runner)
    : agent_(agent),
      inspector_backend_dispatcher_(new protocol::UberDispatcher(this)),
      session_state_(std::move(reattach_session_state)),
      client_expects_binary_responses_(client_expects_binary_responses),
      client_is_trusted_(client_is_trusted),
      v8_session_state_(kV8StateKey),
      v8_session_state_cbor_(&v8_session_state_, /*default_value=*/{}),
      session_id_(session_id),
      session_waits_for_debugger_(session_waits_for_debugger) {
  receiver_.Bind(std::move(main_receiver), mojo_task_runner);

  io_session_ =
      new IOSession(agent_->io_task_runner_, agent_->inspector_task_runner_,
                    MakeCrossThreadWeakHandle(this), std::move(io_receiver));

  host_remote_.Bind(std::move(host_remote), mojo_task_runner);
  host_remote_.set_disconnect_handler(
      WTF::BindOnce(&DevToolsSession::Detach, WrapWeakPersistent(this)));

  bool restore = !!session_state_.ReattachState();
  v8_session_state_.InitFrom(&session_state_);
  agent_->client_->AttachSession(this, restore);
  agent_->probe_sink_->AddDevToolsSession(this);
  if (restore) {
    for (wtf_size_t i = 0; i < agents_.size(); i++)
      agents_[i]->Restore();
  }
}

DevToolsSession::~DevToolsSession() {
  DCHECK(IsDetached());
}

void DevToolsSession::ConnectToV8(v8_inspector::V8Inspector* inspector,
                                  int context_group_id) {
  const auto& cbor = v8_session_state_cbor_.Get();
  v8_session_ = inspector->connect(
      context_group_id, this,
      v8_inspector::StringView(cbor.data(), cbor.size()),
      client_is_trusted_ ? v8_inspector::V8Inspector::kFullyTrusted
                         : v8_inspector::V8Inspector::kUntrusted,
      session_waits_for_debugger_
          ? v8_inspector::V8Inspector::kWaitingForDebugger
          : v8_inspector::V8Inspector::kNotWaitingForDebugger);
}

bool DevToolsSession::IsDetached() {
  return !io_session_;
}

void DevToolsSession::Append(InspectorAgent* agent) {
  agents_.push_back(agent);
  agent->Init(agent_->probe_sink_.Get(), inspector_backend_dispatcher_.get(),
              &session_state_);
}

void DevToolsSession::Detach() {
  agent_->client_->DebuggerTaskStarted();
  agent_->client_->DetachSession(this);
  agent_->DetachDevToolsSession(this);
  receiver_.reset();
  host_remote_.reset();
  CHECK(io_session_);
  io_session_->DeleteSoon();
  io_session_ = nullptr;
  agent_->probe_sink_->RemoveDevToolsSession(this);
  inspector_backend_dispatcher_.reset();
  for (wtf_size_t i = agents_.size(); i > 0; i--)
    agents_[i - 1]->Dispose();
  agents_.clear();
  v8_session_.reset();
  agent_->client_->DebuggerTaskFinished();
}

void DevToolsSession::DetachFromV8() {
  if (v8_session_) {
    v8_session_->stop();
  }
}

void DevToolsSession::DispatchProtocolCommand(
    int call_id,
    const String& method,
    base::span<const uint8_t> message) {
  TRACE_EVENT_WITH_FLOW1(
      "devtools", "DevToolsSession::DispatchProtocolCommand", call_id,
      TRACE_EVENT_FLAG_FLOW_OUT | TRACE_EVENT_FLAG_FLOW_IN, "call_id", call_id);
  return DispatchProtocolCommandImpl(call_id, method, message);
}

void DevToolsSession::DispatchProtocolCommandImpl(
    int call_id,
    const String& method,
    base::span<const uint8_t> data) {
  DCHECK(crdtp::cbor::IsCBORMessage(
      crdtp::span<uint8_t>(data.data(), data.size())));
  TRACE_EVENT_WITH_FLOW1(
      "devtools", "DevToolsSession::DispatchProtocolCommandImpl", call_id,
      TRACE_EVENT_FLAG_FLOW_OUT | TRACE_EVENT_FLAG_FLOW_IN, "call_id", call_id);
  TRACE_EVENT1("devtools", "api_call", "method_name", method);

  // IOSession does not provide ordering guarantees relative to
  // Session, so a command may come to IOSession after Session is detached,
  // and get posted to main thread to this method.
  //
  // At the same time, Session may not be garbage collected yet
  // (even though already detached), and CrossThreadWeakHandle<Session>
  // will still be valid.
  //
  // Both these factors combined may lead to this method being called after
  // detach, so we have to check it here.
  if (IsDetached())
    return;
  agent_->client_->DebuggerTaskStarted();
  if (v8_inspector::V8InspectorSession::canDispatchMethod(
          ToV8InspectorStringView(method))) {
    // Binary protocol messages are passed using 8-bit StringView.
    v8_session_->dispatchProtocolMessage(
        v8_inspector::StringView(data.data(), data.size()));
  } else {
    crdtp::Dispatchable dispatchable(crdtp::SpanFrom(data));
    // This message has already been checked by content::DevToolsSession.
    DCHECK(dispatchable.ok());
    inspector_backend_dispatcher_->Dispatch(dispatchable).Run();
  }
  agent_->client_->DebuggerTaskFinished();
}

void DevToolsSession::DidStartProvisionalLoad(LocalFrame* frame) {
  if (v8_session_ && agent_->inspected_frames_->Root() == frame) {
    v8_session_->setSkipAllPauses(true);
    v8_session_->resume(true /* terminate on resume */);
  }
}

void DevToolsSession::DidFailProvisionalLoad(LocalFrame* frame) {
  if (v8_session_ && agent_->inspected_frames_->Root() == frame)
    v8_session_->setSkipAllPauses(false);
}

void DevToolsSession::DidCommitLoad(LocalFrame* frame, DocumentLoader*) {
  for (wtf_size_t i = 0; i < agents_.size(); i++)
    agents_[i]->DidCommitLoadForLocalFrame(frame);
  if (v8_session_ && agent_->inspected_frames_->Root() == frame)
    v8_session_->setSkipAllPauses(false);
}

void DevToolsSession::PaintTiming(Document* document,
                                  const char* name,
                                  double timestamp) {
  if (v8_session_ &&
      agent_->inspected_frames_->Root()->GetDocument() == document) {
    v8_session_->triggerPreciseCoverageDeltaUpdate(
        ToV8InspectorStringView(name));
  }
}

void DevToolsSession::DomContentLoadedEventFired(LocalFrame* local_frame) {
  if (v8_session_ && agent_->inspected_frames_->Root() == local_frame) {
    v8_session_->triggerPreciseCoverageDeltaUpdate(
        ToV8InspectorStringView("DomContentLoaded"));
  }
}

void DevToolsSession::SendProtocolResponse(
    int call_id,
    std::unique_ptr<protocol::Serializable> message) {
  SendProtocolResponse(call_id, message->Serialize());
}

void DevToolsSession::FallThrough(int call_id,
                                  crdtp::span<uint8_t> method,
                                  crdtp::span<uint8_t> message) {
  // There's no other layer to handle the command.
  NOTREACHED();
}

void DevToolsSession::sendResponse(
    int call_id,
    std::unique_ptr<v8_inspector::StringBuffer> message) {
  SendProtocolResponse(call_id, Get8BitStringFrom(message.get()));
}

void DevToolsSession::SendProtocolResponse(int call_id,
                                           std::vector<uint8_t> message) {
  TRACE_EVENT_WITH_FLOW1(
      "devtools", "DevToolsSession::SendProtocolResponse", call_id,
      TRACE_EVENT_FLAG_FLOW_OUT | TRACE_EVENT_FLAG_FLOW_IN, "call_id", call_id);
  if (IsDetached())
    return;
  flushProtocolNotifications();
  if (v8_session_)
    v8_session_state_cbor_.Set(v8_session_->state());
  // Make tests more predictable by flushing all sessions before sending
  // protocol response in any of them.
  if (WebTestSupport::IsRunningWebTest())
    agent_->FlushProtocolNotifications();

  host_remote_->DispatchProtocolResponse(
      FinalizeMessage(std::move(message), call_id), call_id,
      session_state_.TakeUpdates());
}

void DevToolsSession::SendProtocolNotification(
    std::unique_ptr<protocol::Serializable> notification) {
  if (IsDetached())
    return;
  notification_queue_.push_back(WTF::BindOnce(
      [](std::unique_ptr<protocol::Serializable> notification) {
        return notification->Serialize();
      },
      std::move(notification)));
}

void DevToolsSession::sendNotification(
    std::unique_ptr<v8_inspector::StringBuffer> notification) {
  if (IsDetached())
    return;
  notification_queue_.push_back(WTF::BindOnce(
      [](std::unique_ptr<v8_inspector::StringBuffer> notification) {
        return Get8BitStringFrom(notification.get());
      },
      std::move(notification)));
}

void DevToolsSession::flushProtocolNotifications() {
  FlushProtocolNotifications();
}

void DevToolsSession::FlushProtocolNotifications() {
  if (IsDetached())
    return;
  for (wtf_size_t i = 0; i < agents_.size(); i++)
    agents_[i]->FlushPendingProtocolNotifications();
  if (!notification_queue_.size())
    return;
  if (v8_session_)
    v8_session_state_cbor_.Set(v8_session_->state());
  for (wtf_size_t i = 0; i < notification_queue_.size(); ++i) {
    host_remote_->DispatchProtocolNotification(
        FinalizeMessage(std::move(notification_queue_[i]).Run(), std::nullopt),
        session_state_.TakeUpdates());
  }
  notification_queue_.clear();
}

void DevToolsSession::Trace(Visitor* visitor) const {
  visitor->Trace(receiver_);
  visitor->Trace(host_remote_);
  visitor->Trace(agent_);
  visitor->Trace(agents_);
}

blink::mojom::blink::DevToolsMessagePtr DevToolsSession::FinalizeMessage(
    std::vector<uint8_t> message,
    std::optional<int> call_id) const {
  std::vector<uint8_t> message_to_send = std::move(message);
  if (!session_id_.empty()) {
    crdtp::Status status = crdtp::cbor::AppendString8EntryToCBORMap(
        crdtp::SpanFrom(kSessionId), crdtp::SpanFrom(session_id_.Ascii()),
        &message_to_send);
    CHECK(status.ok()) << status.ToASCIIString();
  }
  if (!client_expects_binary_responses_) {
    std::vector<uint8_t> json;
    crdtp::Status status =
        crdtp::json::ConvertCBORToJSON(crdtp::SpanFrom(message_to_send), &json);
    if (status.error == crdtp::Error::CBOR_STACK_LIMIT_EXCEEDED &&
        call_id.has_value()) {
      return FinalizeMessage(
          crdtp::CreateErrorResponse(
              call_id.value(), crdtp::DispatchResponse::ServerError(
                                   "Failed to convert response to JSON: " +
                                   status.ToASCIIString()))
              ->Serialize(),
          std::nullopt);
    }
    CHECK(status.ok()) << status.ToASCIIString();
    message_to_send = std::move(json);
  }
  auto mojo_msg = mojom::blink::DevToolsMessage::New();
  mojo_msg->data = {message_to_send};
  return mojo_msg;
}

}  // namespace blink
```