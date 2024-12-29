Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Understanding - The Goal:**

The request asks for a functional analysis of the `SmartCardContext.cc` file within the Chromium Blink rendering engine. The key is to identify what it *does*, how it interacts with web technologies (JS, HTML, CSS), potential user errors, debugging strategies, and any logical inferences we can make.

**2. Core Functionality Identification (The "What"):**

* **Keywords and Structure:**  I immediately scan for class names, method names, and included headers. The class `SmartCardContext` is central. Methods like `listReaders`, `getStatusChange`, and `connect` strongly suggest it manages interactions with smart card readers. The inclusion of V8-related headers (`v8_smart_card_...`) confirms its role in exposing smart card functionality to JavaScript. The `mojo` namespace indicates inter-process communication.
* **Data Structures:**  I note the use of `ScriptPromise`, `HeapVector`, `Member`, and Mojo-related types like `device::mojom::blink::SmartCard...Ptr`. These hint at asynchronous operations, collections of data, and communication with other Chromium components.
* **Mojo Interaction:**  The initialization (`mojo::PendingRemote<device::mojom::blink::SmartCardContext>`) and the `scard_context_` member variable clearly establish this class as a client interacting with a Smart Card service over Mojo.
* **Asynchronous Operations:** The use of `ScriptPromise` in methods like `listReaders`, `getStatusChange`, and `connect` immediately signals asynchronous operations, which are crucial for non-blocking behavior in web applications. The "Done" callback methods (`OnListReadersDone`, `OnGetStatusChangeDone`, `OnConnectDone`) reinforce this.
* **Error Handling:**  The presence of `ExceptionState` arguments and checks for `result->is_error()` indicate error handling mechanisms. The `SmartCardError::MaybeReject` function suggests a standardized way to propagate errors to the JavaScript Promise.
* **State Management:** The `request_` member variable and related methods (`SetOperationInProgress`, `ClearOperationInProgress`) suggest a mechanism to prevent concurrent operations within the same `SmartCardContext`.
* **Connection Management:** The `connections_` member and the `SmartCardConnection` class point to the management of active connections to smart cards.

**3. Interaction with Web Technologies (The "How"):**

* **JavaScript:**  The V8-related headers and the use of `ScriptPromise` are the strongest indicators. The methods directly map to JavaScript API calls. The conversion functions between Blink's internal representations and V8 types (e.g., `ToV8ReaderStateFlagsOut`) are crucial for this interaction.
* **HTML/CSS:**  While the core logic doesn't directly manipulate HTML or CSS, the functionality it enables *can* be triggered by user interactions within a web page. For example, a button click might initiate a JavaScript call to `navigator.smartCard.getContext().listReaders()`. Therefore, the connection is indirect but essential for the feature to be useful.

**4. Logical Inferences and Assumptions (The "Why" and "If/Then"):**

* **Asynchronous Nature:**  The use of promises implies that UI won't freeze while waiting for smart card operations.
* **Security:**  The inter-process communication via Mojo likely has security implications, preventing direct access to hardware from the rendering process.
* **Error Handling:**  The detailed error reporting (using `SmartCardError`) allows web developers to handle various smart card issues gracefully.
* **Concurrency Control:** The `request_` mechanism prevents race conditions and ensures orderly processing of smart card operations.

**5. User and Programming Errors (The "Gotchas"):**

* **Incorrect Usage:**  Calling methods in the wrong order or without checking for context availability are prime candidates.
* **Permission Issues:**  Although not explicitly in this file, smart card access likely requires user permission.
* **Smart Card Errors:**  Problems with the smart card itself (wrong PIN, damaged card) will propagate through this code.
* **Asynchronous Handling:**  Forgetting to handle promise rejections is a common JavaScript error.

**6. Debugging Clues (The "Where to Look"):**

* **Mojo Communication:**  Tools for inspecting Mojo messages are crucial.
* **Logging:**  The `LOG(WARNING)` statement provides a potential debugging point.
* **Breakpoints:**  Setting breakpoints in the C++ code itself, especially in the "Done" callbacks and error handling sections.
* **JavaScript Console:**  Looking for errors and using `console.log` in the JavaScript that calls these APIs.

**7. Structuring the Answer:**

I organize the information into logical sections based on the prompt's requests:

* **Functionality:**  A high-level summary of what the file does.
* **Relationship to Web Technologies:** Concrete examples of how it connects to JavaScript, HTML, and CSS.
* **Logical Inferences:**  Deductions based on the code's structure and purpose.
* **User and Programming Errors:** Practical examples of common mistakes.
* **User Operations and Debugging:** A step-by-step scenario and debugging tips.

**Self-Correction/Refinement during the Thought Process:**

* **Initial thought:** "This file just handles the Mojo interface."  **Correction:** While Mojo is central, it also manages the state of operations and converts data to and from JavaScript types.
* **Initial thought:** "HTML/CSS are irrelevant." **Correction:**  They are indirectly related as the UI triggers the JavaScript that uses this code.
* **Focus on the "Why":**  Constantly asking "Why is this code here?" helps uncover the underlying purpose and design decisions. For example, "Why are promises used?" -> Asynchronous operations. "Why is there a `request_` variable?" -> To prevent concurrent operations.

By following this structured approach, analyzing keywords, understanding data flow, and considering the broader context of the Chromium rendering engine, I can generate a comprehensive and accurate answer to the given prompt.
这个 `blink/renderer/modules/smart_card/smart_card_context.cc` 文件是 Chromium Blink 引擎中，用于实现 Web Smart Card API 的核心组件之一。它负责管理与智能卡读卡器的上下文交互，并将其暴露给 JavaScript。

**功能列表:**

1. **创建和管理 Smart Card Context:**
   -  当网页请求访问智能卡功能时，会创建一个 `SmartCardContext` 实例。
   -  它维护着一个与底层智能卡服务（通过 Mojo IPC 通信）的连接 (`scard_context_`)。
   -  它负责管理正在进行的智能卡操作，防止并发操作冲突。

2. **列出可用的智能卡读卡器 (`listReaders`)**:
   -  接收来自 JavaScript 的请求，通过 Mojo 向底层服务查询可用的读卡器列表。
   -  将底层服务返回的读卡器名称列表转换为 JavaScript 可用的 `Array<String>` 并通过 Promise 返回。

3. **获取读卡器状态变化 (`getStatusChange`)**:
   -  接收来自 JavaScript 的请求，监听指定读卡器的状态变化（例如，是否有卡插入、卡是否被移除）。
   -  接收一个读卡器状态输入列表 (`SmartCardReaderStateIn`)，描述了当前想要监听的读卡器及其期望的状态。
   -  将这些输入转换为 Mojo 消息发送给底层服务。
   -  底层服务会等待指定读卡器状态发生变化或超时。
   -  将底层服务返回的状态变化信息 (`SmartCardReaderStateOut`) 转换为 JavaScript 可用的对象列表，并通过 Promise 返回。
   -  支持通过 `AbortSignal` 取消正在进行的 `getStatusChange` 操作。

4. **连接到智能卡 (`connect`)**:
   -  接收来自 JavaScript 的请求，尝试连接到指定的智能卡读卡器。
   -  接收读卡器名称、访问模式（共享或独占）以及可选的协议列表。
   -  将这些信息转换为 Mojo 消息发送给底层服务。
   -  如果连接成功，底层服务会返回一个 `SmartCardConnection` 对象和一个激活的协议。
   -  `SmartCardContext` 创建一个 `SmartCardConnection` 的 Blink 侧表示，并将其包装在 `SmartCardConnectResult` 对象中，通过 Promise 返回给 JavaScript。

5. **取消当前操作 (`Cancel`)**:
   -  允许取消当前正在进行的智能卡操作。
   -  通过 Mojo 向底层服务发送取消请求。

6. **处理 Mojo 连接断开**:
   -  当与底层智能卡服务的 Mojo 连接断开时，会清理资源并通知 JavaScript 当前上下文不可用。

7. **错误处理**:
   -  将底层服务返回的错误代码转换为 JavaScript 可理解的 `DOMException` 并通过 Promise 的 reject 回调返回。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个 C++ 文件本身不直接操作 HTML 或 CSS。它的主要作用是作为 Web Smart Card API 的底层实现，与 JavaScript 进行交互，从而使得网页可以通过 JavaScript 代码访问智能卡功能。

**JavaScript:**

- **`navigator.smartCard.getContext()`:**  JavaScript 代码会首先调用这个方法来获取一个 `SmartCardContext` 的实例。这个 C++ 文件中的 `SmartCardContext` 类就是这个接口的实现。
- **`context.listReaders()`:** JavaScript 调用这个方法会最终调用到 C++ 端的 `SmartCardContext::listReaders` 方法，获取读卡器列表。
  ```javascript
  navigator.smartCard.getContext()
    .then(context => context.listReaders())
    .then(readers => console.log("Available readers:", readers))
    .catch(error => console.error("Failed to list readers:", error));
  ```
- **`context.getStatusChange(readerStates, options)`:** JavaScript 调用这个方法会最终调用到 C++ 端的 `SmartCardContext::getStatusChange` 方法，监听读卡器状态变化。
  ```javascript
  navigator.smartCard.getContext()
    .then(context => context.getStatusChange([{ readerName: 'ACS ACR122U PICC Interface' }], {}))
    .then(states => console.log("Reader states changed:", states))
    .catch(error => console.error("Failed to get status change:", error));
  ```
- **`context.connect(readerName, { shareMode: 'shared', protocol: ['T0', 'T1'] })`:** JavaScript 调用这个方法会最终调用到 C++ 端的 `SmartCardContext::connect` 方法，连接到智能卡。
  ```javascript
  navigator.smartCard.getContext()
    .then(context => context.connect('ACS ACR122U PICC Interface', { shareMode: 'shared' }))
    .then(result => {
      console.log("Connected to card, protocol:", result.activeProtocol);
      // 使用 result.connection 进行后续的智能卡操作
    })
    .catch(error => console.error("Failed to connect:", error));
  ```

**HTML:**

- HTML 中通常会包含触发智能卡操作的元素，例如按钮。当用户点击按钮时，会执行相应的 JavaScript 代码，而这些 JavaScript 代码最终会调用到 `SmartCardContext` 的方法。
  ```html
  <button id="listReadersBtn">List Readers</button>
  <script>
    document.getElementById('listReadersBtn').addEventListener('click', () => {
      navigator.smartCard.getContext()
        .then(context => context.listReaders())
        .then(readers => console.log("Available readers:", readers));
    });
  </script>
  ```

**CSS:**

- CSS 与此文件没有直接关系。

**逻辑推理、假设输入与输出:**

**假设输入:** 用户在网页上点击了一个按钮，该按钮的 JavaScript 代码调用了 `navigator.smartCard.getContext().then(context => context.listReaders())`.

**C++ 代码执行流程 (简化):**

1. JavaScript 调用 `navigator.smartCard.getContext()` 会返回一个 Promise，该 Promise resolve 的值是 `SmartCardContext` 的一个实例（或创建一个新的实例）。
2. JavaScript 接着调用 `context.listReaders()`，这会调用到 C++ 的 `SmartCardContext::listReaders` 方法。
3. **C++ 假设输入:**  Mojo 连接正常，底层智能卡服务响应及时。
4. `SmartCardContext::listReaders` 内部：
   - 检查当前是否没有其他操作正在进行。
   - 创建一个 `ScriptPromiseResolver` 用于处理异步结果。
   - 通过 `scard_context_->ListReaders` 发送 Mojo 消息给底层智能卡服务。
   - 设置一个回调函数 `SmartCardContext::OnListReadersDone` 来处理底层服务的响应。
5. **假设底层服务输出:** 底层智能卡服务返回一个包含两个读卡器名称的列表：`["Reader A", "Reader B"]`。
6. `SmartCardContext::OnListReadersDone` 被调用，接收到包含读卡器列表的 Mojo 消息。
7. `SmartCardContext::OnListReadersDone` 将读卡器名称列表转换为 `Vector<String>`。
8. `resolver->Resolve(std::move(result->get_readers()))` 将结果传递给 JavaScript 的 Promise。
9. **JavaScript 输出:** `console.log("Available readers:", ["Reader A", "Reader B"])` 会在控制台中打印出来。

**用户或编程常见的使用错误:**

1. **未检查 `navigator.smartCard` 的可用性:**  在某些浏览器或环境下，Smart Card API 可能不可用。直接使用可能导致错误。
   ```javascript
   if ('smartCard' in navigator) {
     navigator.smartCard.getContext()
       // ...
   } else {
     console.error("Smart Card API is not available in this browser.");
   }
   ```

2. **并发调用 `SmartCardContext` 的方法:**  `SmartCardContext` 内部有机制防止并发操作。如果在前一个操作完成之前发起新的操作，会抛出 `InvalidStateError`。
   ```javascript
   navigator.smartCard.getContext()
     .then(context => {
       context.listReaders();
       context.connect('reader1', {}); // 可能会抛出错误，因为 listReaders 可能还在进行中
     });
   ```

3. **忘记处理 Promise 的 rejection:**  智能卡操作可能失败，例如读卡器未连接、卡片错误等。需要正确处理 Promise 的 `catch` 回调。
   ```javascript
   navigator.smartCard.getContext()
     .then(context => context.listReaders())
     .then(readers => console.log("Readers:", readers))
     .catch(error => console.error("An error occurred:", error)); // 必须处理错误
   ```

4. **在 Context 不可用时调用方法:** 如果与底层服务的连接断开，尝试调用 `SmartCardContext` 的方法会抛出 `InvalidStateError`。这通常发生在底层服务崩溃或用户拔掉读卡器后。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户想要在一个网页上读取智能卡的信息：

1. **用户打开网页:** 网页加载了包含智能卡相关 JavaScript 代码的 HTML 文件。
2. **用户点击按钮或触发事件:**  例如，用户点击了一个 "读取卡信息" 的按钮。
3. **JavaScript 代码执行:**  按钮的点击事件监听器触发，执行相应的 JavaScript 代码。
4. **获取 SmartCardContext:** JavaScript 代码调用 `navigator.smartCard.getContext()`。
   - **调试线索:** 检查 `navigator.smartCard` 是否存在。如果不存在，说明浏览器不支持或未启用该功能。
5. **列出读卡器 (可选):** JavaScript 代码可能先调用 `context.listReaders()` 来显示可用的读卡器列表。
   - **调试线索:** 在 C++ 代码的 `SmartCardContext::listReaders` 方法中设置断点，查看 Mojo 消息是否发送成功，底层服务是否有响应。
6. **选择读卡器 (如果需要):** 用户可能需要从列表中选择一个读卡器。
7. **连接到智能卡:** JavaScript 代码调用 `context.connect(selectedReader, options)`。
   - **调试线索:** 在 C++ 代码的 `SmartCardContext::connect` 方法中设置断点，查看传入的参数是否正确，Mojo 连接是否正常。
8. **进行智能卡操作 (不在本文件范围内):** 连接成功后，会创建一个 `SmartCardConnection` 对象，后续的操作（例如发送 APDU 命令）将通过 `SmartCardConnection` 进行。
9. **处理结果或错误:** JavaScript 代码根据 Promise 的 resolve 或 reject 回调处理智能卡操作的结果或错误。

**调试线索总结:**

- **JavaScript 控制台:** 查看是否有 JavaScript 错误，例如 `undefined is not an object (reading 'getContext')` 或 Promise 的 rejection 信息。
- **Chromium 的 `chrome://inspect/#devices`:**  可以查看设备的 Mojo 服务连接状态。
- **C++ 代码断点:** 在 `SmartCardContext` 的关键方法（例如 `listReaders`, `getStatusChange`, `connect`, `OnListReadersDone` 等）设置断点，查看代码执行流程、变量值、Mojo 消息的发送和接收。
- **底层智能卡服务日志:** 如果可以访问底层智能卡服务的日志，可以查看是否有相关的错误或信息。
- **Mojo Inspector 工具:** Chromium 提供了可以检查 Mojo 消息的工具，可以用于调试 Mojo 通信过程。

总而言之，`blink/renderer/modules/smart_card/smart_card_context.cc` 是 Web Smart Card API 在 Blink 渲染引擎中的关键桥梁，它连接了 JavaScript 和底层的智能卡服务，并负责管理智能卡操作的上下文。 理解其功能和与 JavaScript 的交互方式对于开发和调试 Web 智能卡应用至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/smart_card/smart_card_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/smart_card/smart_card_context.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_smart_card_connect_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_smart_card_connect_result.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_smart_card_get_status_change_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_smart_card_reader_state_flags_in.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_smart_card_reader_state_flags_out.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_smart_card_reader_state_in.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_smart_card_reader_state_out.h"
#include "third_party/blink/renderer/modules/smart_card/smart_card_cancel_algorithm.h"
#include "third_party/blink/renderer/modules/smart_card/smart_card_connection.h"
#include "third_party/blink/renderer/modules/smart_card/smart_card_error.h"
#include "third_party/blink/renderer/modules/smart_card/smart_card_util.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"

namespace blink {
namespace {
constexpr char kContextUnavailable[] = "Context unavailable.";
constexpr char kContextBusy[] =
    "An operation is already in progress in this smart card context.";

device::mojom::blink::SmartCardReaderStateFlagsPtr ToMojomStateFlags(
    const SmartCardReaderStateFlagsIn& flags) {
  auto mojom_flags = device::mojom::blink::SmartCardReaderStateFlags::New();
  mojom_flags->unaware = flags.unaware();
  mojom_flags->ignore = flags.ignore();
  mojom_flags->unavailable = flags.unavailable();
  mojom_flags->empty = flags.empty();
  mojom_flags->present = flags.present();
  mojom_flags->exclusive = flags.exclusive();
  mojom_flags->inuse = flags.inuse();
  mojom_flags->mute = flags.mute();
  mojom_flags->unpowered = flags.unpowered();
  return mojom_flags;
}

Vector<device::mojom::blink::SmartCardReaderStateInPtr> ToMojomReaderStatesIn(
    const HeapVector<Member<SmartCardReaderStateIn>>& reader_states) {
  Vector<device::mojom::blink::SmartCardReaderStateInPtr> mojom_reader_states;
  mojom_reader_states.reserve(reader_states.size());

  for (const Member<SmartCardReaderStateIn>& state_in : reader_states) {
    mojom_reader_states.push_back(
        device::mojom::blink::SmartCardReaderStateIn::New(
            state_in->readerName(),
            ToMojomStateFlags(*state_in->currentState()),
            state_in->getCurrentCountOr(0)));
  }

  return mojom_reader_states;
}

SmartCardReaderStateFlagsOut* ToV8ReaderStateFlagsOut(
    const device::mojom::blink::SmartCardReaderStateFlags& mojom_state_flags) {
  auto* state_flags = SmartCardReaderStateFlagsOut::Create();
  state_flags->setIgnore(mojom_state_flags.ignore);
  state_flags->setChanged(mojom_state_flags.changed);
  state_flags->setUnknown(mojom_state_flags.unknown);
  state_flags->setUnavailable(mojom_state_flags.unavailable);
  state_flags->setEmpty(mojom_state_flags.empty);
  state_flags->setPresent(mojom_state_flags.present);
  state_flags->setExclusive(mojom_state_flags.exclusive);
  state_flags->setInuse(mojom_state_flags.inuse);
  state_flags->setMute(mojom_state_flags.mute);
  state_flags->setUnpowered(mojom_state_flags.unpowered);
  return state_flags;
}

HeapVector<Member<SmartCardReaderStateOut>> ToV8ReaderStatesOut(
    Vector<device::mojom::blink::SmartCardReaderStateOutPtr>&
        mojom_reader_states) {
  HeapVector<Member<SmartCardReaderStateOut>> reader_states;
  reader_states.reserve(mojom_reader_states.size());

  for (auto& mojom_state_out : mojom_reader_states) {
    auto* state_out = SmartCardReaderStateOut::Create();
    state_out->setReaderName(mojom_state_out->reader);
    state_out->setEventState(
        ToV8ReaderStateFlagsOut(*mojom_state_out->event_state));
    state_out->setEventCount(mojom_state_out->event_count);
    state_out->setAnswerToReset(
        DOMArrayBuffer::Create(mojom_state_out->answer_to_reset));
    reader_states.push_back(state_out);
  }

  return reader_states;
}

}  // anonymous namespace

SmartCardContext::SmartCardContext(
    mojo::PendingRemote<device::mojom::blink::SmartCardContext> pending_context,
    ExecutionContext* execution_context)
    : ExecutionContextClient(execution_context),
      scard_context_(execution_context),
      feature_handle_for_scheduler_(
          execution_context->GetScheduler()->RegisterFeature(
              SchedulingPolicy::Feature::kSmartCard,
              SchedulingPolicy{SchedulingPolicy::DisableBackForwardCache()})) {
  scard_context_.Bind(
      std::move(pending_context),
      execution_context->GetTaskRunner(TaskType::kMiscPlatformAPI));
  scard_context_.set_disconnect_handler(WTF::BindOnce(
      &SmartCardContext::CloseMojoConnection, WrapWeakPersistent(this)));
}

ScriptPromise<IDLSequence<IDLString>> SmartCardContext::listReaders(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!EnsureMojoConnection(exception_state) ||
      !EnsureNoOperationInProgress(exception_state)) {
    return ScriptPromise<IDLSequence<IDLString>>();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<IDLString>>>(
          script_state, exception_state.GetContext());

  SetOperationInProgress(resolver);
  scard_context_->ListReaders(
      WTF::BindOnce(&SmartCardContext::OnListReadersDone, WrapPersistent(this),
                    WrapPersistent(resolver)));

  return resolver->Promise();
}

ScriptPromise<IDLSequence<SmartCardReaderStateOut>>
SmartCardContext::getStatusChange(
    ScriptState* script_state,
    const HeapVector<Member<SmartCardReaderStateIn>>& reader_states,
    SmartCardGetStatusChangeOptions* options,
    ExceptionState& exception_state) {
  if (!EnsureMojoConnection(exception_state) ||
      !EnsureNoOperationInProgress(exception_state)) {
    return ScriptPromise<IDLSequence<SmartCardReaderStateOut>>();
  }

  AbortSignal* signal = options->getSignalOr(nullptr);
  if (signal && signal->aborted()) {
    return ScriptPromise<IDLSequence<SmartCardReaderStateOut>>::Reject(
        script_state, signal->reason(script_state));
  }

  base::TimeDelta timeout = base::TimeDelta::Max();
  if (options->hasTimeout()) {
    timeout = base::Milliseconds(options->timeout());
  }

  AbortSignal::AlgorithmHandle* abort_handle = nullptr;
  if (signal) {
    abort_handle = signal->AddAlgorithm(
        MakeGarbageCollected<SmartCardCancelAlgorithm>(this));
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLSequence<SmartCardReaderStateOut>>>(
      script_state, exception_state.GetContext());

  SetOperationInProgress(resolver);
  scard_context_->GetStatusChange(
      timeout, ToMojomReaderStatesIn(reader_states),
      WTF::BindOnce(&SmartCardContext::OnGetStatusChangeDone,
                    WrapPersistent(this), WrapPersistent(resolver),
                    WrapPersistent(signal), WrapPersistent(abort_handle)));

  return resolver->Promise();
}

ScriptPromise<SmartCardConnectResult> SmartCardContext::connect(
    ScriptState* script_state,
    const String& reader_name,
    V8SmartCardAccessMode access_mode,
    SmartCardConnectOptions* options,
    ExceptionState& exception_state) {
  if (!EnsureMojoConnection(exception_state) ||
      !EnsureNoOperationInProgress(exception_state)) {
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<SmartCardConnectResult>>(
          script_state, exception_state.GetContext());

  Vector<V8SmartCardProtocol> preferred_protocols =
      options->getPreferredProtocolsOr(Vector<V8SmartCardProtocol>());

  SetOperationInProgress(resolver);
  scard_context_->Connect(
      reader_name, ToMojoSmartCardShareMode(access_mode),
      ToMojoSmartCardProtocols(preferred_protocols),
      WTF::BindOnce(&SmartCardContext::OnConnectDone, WrapPersistent(this),
                    WrapPersistent(resolver)));

  return resolver->Promise();
}

void SmartCardContext::Trace(Visitor* visitor) const {
  visitor->Trace(scard_context_);
  visitor->Trace(request_);
  visitor->Trace(connections_);
  ScriptWrappable::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
}

void SmartCardContext::Cancel() {
  if (!scard_context_.is_bound()) {
    return;
  }
  scard_context_->Cancel(
      WTF::BindOnce(&SmartCardContext::OnCancelDone, WrapPersistent(this)));
}

bool SmartCardContext::EnsureNoOperationInProgress(
    ExceptionState& exception_state) const {
  if (request_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kContextBusy);
    return false;
  }
  return true;
}

void SmartCardContext::SetConnectionOperationInProgress(
    ScriptPromiseResolverBase* resolver) {
  SetOperationInProgress(resolver);
  is_connection_request_ = true;
}

void SmartCardContext::SetOperationInProgress(
    ScriptPromiseResolverBase* resolver) {
  if (request_ == resolver) {
    // NOOP
    return;
  }

  CHECK_EQ(request_, nullptr);
  CHECK(!is_connection_request_);

  request_ = resolver;
}

void SmartCardContext::ClearConnectionOperationInProgress(
    ScriptPromiseResolverBase* resolver) {
  CHECK(is_connection_request_);
  is_connection_request_ = false;
  ClearOperationInProgress(resolver);
}

void SmartCardContext::ClearOperationInProgress(
    ScriptPromiseResolverBase* resolver) {
  CHECK_EQ(request_, resolver);
  CHECK(!is_connection_request_);
  request_ = nullptr;

  for (auto& connection : connections_) {
    connection->OnOperationInProgressCleared();
    // If that connection started a new operation, refrain from notifying the
    // others.
    if (request_) {
      break;
    }
  }
}

bool SmartCardContext::IsOperationInProgress() const {
  return request_ != nullptr;
}

void SmartCardContext::CloseMojoConnection() {
  scard_context_.reset();

  if (!request_ || is_connection_request_) {
    return;
  }

  ScriptState* script_state = request_->GetScriptState();
  if (!IsInParallelAlgorithmRunnable(request_->GetExecutionContext(),
                                     script_state)) {
    return;
  }

  ScriptState::Scope script_state_scope(script_state);
  request_->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                   kContextUnavailable);

  ClearOperationInProgress(request_);
}

bool SmartCardContext::EnsureMojoConnection(
    ExceptionState& exception_state) const {
  if (!scard_context_.is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kContextUnavailable);
    return false;
  }
  return true;
}

void SmartCardContext::OnListReadersDone(
    ScriptPromiseResolver<IDLSequence<IDLString>>* resolver,
    device::mojom::blink::SmartCardListReadersResultPtr result) {
  ClearOperationInProgress(resolver);

  if (result->is_error()) {
    auto mojom_error = result->get_error();
    // If there are no readers available, PCSC API returns a kNoReadersAvailable
    // error. In web API we want to return an empty list of readers instead.
    if (mojom_error ==
        device::mojom::blink::SmartCardError::kNoReadersAvailable) {
      resolver->Resolve(Vector<String>());
      return;
    }

    SmartCardError::MaybeReject(resolver, mojom_error);
    return;
  }

  resolver->Resolve(std::move(result->get_readers()));
}

void SmartCardContext::OnGetStatusChangeDone(
    ScriptPromiseResolver<IDLSequence<SmartCardReaderStateOut>>* resolver,
    AbortSignal* signal,
    AbortSignal::AlgorithmHandle* abort_handle,
    device::mojom::blink::SmartCardStatusChangeResultPtr result) {
  ClearOperationInProgress(resolver);

  if (signal && abort_handle) {
    signal->RemoveAlgorithm(abort_handle);
  }

  if (result->is_error()) {
    if (signal && signal->aborted() &&
        result->get_error() ==
            device::mojom::blink::SmartCardError::kCancelled) {
      RejectWithAbortionReason(resolver, signal);
    } else {
      SmartCardError::MaybeReject(resolver, result->get_error());
    }
    return;
  }

  resolver->Resolve(ToV8ReaderStatesOut(result->get_reader_states()));
}

void SmartCardContext::OnCancelDone(
    device::mojom::blink::SmartCardResultPtr result) {
  if (result->is_error()) {
    LOG(WARNING) << "Cancel operation failed: " << result->get_error();
  }
}

void SmartCardContext::OnConnectDone(
    ScriptPromiseResolver<SmartCardConnectResult>* resolver,
    device::mojom::blink::SmartCardConnectResultPtr result) {
  ClearOperationInProgress(resolver);

  if (result->is_error()) {
    SmartCardError::MaybeReject(resolver, result->get_error());
    return;
  }

  device::mojom::blink::SmartCardConnectSuccessPtr& success =
      result->get_success();

  auto* connection = MakeGarbageCollected<SmartCardConnection>(
      std::move(success->connection), success->active_protocol, this,
      GetExecutionContext());
  // Being a weak member, it will be automatically removed from the set when
  // garbage-collected.
  connections_.insert(connection);

  auto* blink_result = SmartCardConnectResult::Create();
  blink_result->setConnection(connection);

  switch (success->active_protocol) {
    case device::mojom::blink::SmartCardProtocol::kUndefined:
      // NOOP: Do not set an activeProtocol.
      break;
    case device::mojom::blink::SmartCardProtocol::kT0:
      blink_result->setActiveProtocol(V8SmartCardProtocol::Enum::kT0);
      break;
    case device::mojom::blink::SmartCardProtocol::kT1:
      blink_result->setActiveProtocol(V8SmartCardProtocol::Enum::kT1);
      break;
    case device::mojom::blink::SmartCardProtocol::kRaw:
      blink_result->setActiveProtocol(V8SmartCardProtocol::Enum::kRaw);
      break;
  }

  resolver->Resolve(blink_result);
}

}  // namespace blink

"""

```