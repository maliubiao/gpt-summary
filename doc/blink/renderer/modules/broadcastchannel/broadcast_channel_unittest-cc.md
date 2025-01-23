Response:
Let's break down the thought process for analyzing the given C++ unit test file for Chromium's Blink engine.

**1. Initial Understanding - The Big Picture**

The first thing I notice is the filename: `broadcast_channel_unittest.cc`. The `_unittest.cc` suffix strongly indicates this is a file containing unit tests. The `broadcast_channel` part tells me it's testing the `BroadcastChannel` feature. The path `blink/renderer/modules/broadcastchannel/` confirms this is part of Blink's rendering engine, specifically related to a module for `BroadcastChannel`.

**2. Examining the Includes - Identifying Key Dependencies**

I scan the `#include` directives. These are crucial for understanding what the code interacts with:

* `"third_party/blink/renderer/modules/broadcastchannel/broadcast_channel.h"`:  This is the header file for the class being tested. It's the core of the functionality.
* `<iterator>`: Standard C++ library, likely for iterating over collections.
* `"base/run_loop.h"`:  From Chromium's base library, used for asynchronous testing. This tells me the tests will involve waiting for events.
* `"base/task/sequenced_task_runner.h"`: Also from Chromium's base, likely for managing tasks on a specific thread.
* `"base/test/bind.h"`: For creating bound function objects, common in asynchronous programming.
* `"testing/gtest/include/gtest/gtest.h"`:  The Google Test framework, the standard for C++ unit testing in Chromium.
* `"third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"`:  Indicates interaction with V8, the JavaScript engine. This is a key connection to JavaScript.
* `"third_party/blink/renderer/core/dom/events/event.h"`, etc.:  Includes related to DOM events, suggesting the `BroadcastChannel` uses events to communicate.
* `"third_party/blink/renderer/core/execution_context/execution_context.h"`:  Fundamental concept in Blink, representing the environment where scripts run.
* `"third_party/blink/renderer/core/frame/local_dom_window.h"`, `"third_party/blink/renderer/core/frame/local_frame.h"`:  Parts of Blink's frame structure, essential for representing web pages.
* `"third_party/blink/renderer/core/messaging/blink_cloneable_message.h"`:  Suggests messages are being passed, and they can be cloned.
* `"third_party/blink/renderer/core/testing/dummy_page_holder.h"`:  A test utility for creating a minimal page environment.
* `"third_party/blink/renderer/platform/heap/...`", `"third_party/blink/renderer/platform/mojo/...`": These include platform-level utilities, hinting at the underlying implementation details, possibly using Mojo for inter-process communication.
* `"third_party/blink/renderer/platform/testing/task_environment.h"`: Another testing utility for managing the environment.
* `"v8/include/v8.h"`: Direct inclusion of the V8 API.

**3. Analyzing the `BroadcastChannelTester` Class - The Test Fixture**

This class is the core of the testing setup. I go through its members and methods:

* **Inheritance:** `GarbageCollected` and `mojom::blink::BroadcastChannelClient`. This suggests memory management and interaction with a Mojo interface.
* **Constructor:** Initializes Mojo receivers and remotes, creates a `BroadcastChannel` instance, and adds event listeners for `message` and `messageerror`. This reveals how the test sets up communication channels.
* **`channel()`:** Returns the `BroadcastChannel` being tested.
* **`received_events()` and `sent_messages()`:**  Used to inspect the results of message passing.
* **`AwaitNextUpdate()`:** Crucial for asynchronous testing, waiting for a message to be processed.
* **`PostMessage()`:** Sends a message through the Mojo interface.
* **`OnMessage()`:**  The implementation of the `BroadcastChannelClient` interface, called when a message is received *on the remote side* (not the `BroadcastChannel` instance being tested directly). It stores the sent message.
* **`EventListener` inner class:**  Handles `message` and `messageerror` events on the `BroadcastChannel` instance. It stores received events. The key takeaway here is that the test sets up a "loopback" where it sends messages and observes the events triggered on the same channel.

**4. Examining the Test Cases - Specific Scenarios**

I go through each `TEST_F` function:

* **`DispatchMessageEvent`:** Sends a simple message and verifies a `message` event is received.
* **`AgentClusterLockedMatch`:** Sends a message locked to the sender's agent cluster and checks if a `message` event is received when the receiver is in the same cluster.
* **`AgentClusterLockedMismatch`:** Sends a message locked to the sender's agent cluster and verifies a `messageerror` event is received when the receiver is in a different cluster (implicitly, since it's a new `BroadcastChannelTester`).
* **`MessageCannotDeserialize`:**  Simulates a deserialization failure and checks for a `messageerror` event. It uses a scoped override to force deserialization to fail.
* **`OutgoingMessagesMarkedWithAgentClusterId`:**  Sends a message via the JavaScript API (`postMessage`) and verifies the outgoing message is tagged with the sender's agent cluster ID.
* **`OutgoingAgentClusterLockedMessage`:** Sends a WebAssembly module (which is inherently agent-cluster locked) and verifies the outgoing message is marked as locked.

**5. Connecting to JavaScript, HTML, CSS**

Based on the analysis, I identify the connections:

* **JavaScript:** The `BroadcastChannel` API is a JavaScript API. The tests demonstrate sending and receiving messages using JavaScript values (null, WebAssembly modules). The `postMessage` calls within the tests use `ScriptValue`, which directly represents JavaScript values in Blink's C++ code.
* **HTML:** While this specific test file doesn't directly involve HTML parsing or rendering, the `BroadcastChannel` API is used within the context of web pages loaded in a browser. The `DummyPageHolder` simulates a basic page environment.
* **CSS:**  There's no direct connection to CSS functionality in these tests. `BroadcastChannel` is about inter-context communication, not styling.

**6. Logical Reasoning and Examples**

For each test case, I consider the input and expected output:

* **Input:** What data is being sent, what configuration is set up.
* **Output:** What events are expected, what properties of the messages are verified.

I also think about potential user errors.

**7. Debugging Scenario**

I consider how a developer might end up looking at this test file during debugging. This involves thinking about the steps a user might take that would lead to issues with `BroadcastChannel`.

**Self-Correction/Refinement during the Process:**

* **Initially, I might have focused too much on the Mojo details.**  While important for understanding the underlying mechanism, the key is to connect it back to the user-facing JavaScript API. I need to balance the level of detail.
* **I need to ensure I clearly explain the purpose of the `BroadcastChannelTester` class.** It's not a standard part of the browser; it's a test fixture.
* **The connection to JavaScript needs to be explicit.** Mentioning `ScriptValue`, `postMessage`, and the V8 integration is essential.
* **For the "user operation" scenario, I should think about concrete user actions in a browser that would trigger `BroadcastChannel` usage.** Opening multiple tabs or windows from the same origin is the most common scenario.

By following these steps, I can systematically analyze the C++ unit test file and provide a comprehensive explanation of its functionality, its relationship to web technologies, and its role in testing the `BroadcastChannel` feature.
好的，让我们来详细分析一下 `blink/renderer/modules/broadcastchannel/broadcast_channel_unittest.cc` 这个文件。

**文件功能概述**

这个文件是 Chromium Blink 引擎中 `BroadcastChannel` 模块的单元测试文件。它的主要功能是：

1. **测试 `BroadcastChannel` 类的核心功能**:  验证 `BroadcastChannel` 对象能否正确地发送和接收消息。
2. **测试事件派发**: 验证当消息被接收时，`BroadcastChannel` 对象能否正确地派发 `message` 和 `messageerror` 事件。
3. **测试 Agent Cluster Lock 机制**: 验证 `BroadcastChannel` 在涉及 Agent Cluster Lock 时的行为，包括匹配和不匹配的情况。
4. **测试消息反序列化失败的情况**: 模拟消息反序列化失败的场景，并验证是否会派发 `messageerror` 事件。
5. **验证发送消息时 Agent Cluster ID 的标记**: 确保通过 `BroadcastChannel` 发送的消息会被正确地标记上发送者的 Agent Cluster ID。
6. **验证发送 Agent Cluster Locked 消息**: 测试发送诸如 WebAssembly 模块这种天生 Agent Cluster Locked 的消息时，`BroadcastChannel` 的行为。

**与 JavaScript, HTML, CSS 的关系**

`BroadcastChannel` 是一个 Web API，主要用于同一源（origin）下的不同浏览上下文（例如，不同的标签页、iframe）之间的简单单向通信。因此，这个测试文件与 JavaScript 和 HTML 有着密切的关系：

* **JavaScript**:
    * **API 测试**:  该测试文件最终要验证的是 JavaScript 中 `BroadcastChannel` API 的行为是否符合预期。测试用例中会模拟 JavaScript 调用 `postMessage` 方法发送消息，并监听 `message` 和 `messageerror` 事件。
    * **数据传递**: `BroadcastChannel` 传递的消息本质上是可以在 JavaScript 中表示的数据类型。测试用例中使用了 `SerializedScriptValue` 来模拟 JavaScript 中的值。
    * **事件机制**: `BroadcastChannel` 的通信基于事件驱动，测试验证了 `message` 和 `messageerror` 事件的正确派发。

    **举例说明**:

    假设在 JavaScript 中有以下代码：

    ```javascript
    const bc = new BroadcastChannel('my_channel');

    bc.onmessage = function(event) {
      console.log('Received message:', event.data);
    };

    bc.postMessage('Hello from tab 1');
    ```

    该测试文件中的某些测试用例，例如 `DispatchMessageEvent`，就是为了验证当一个 `BroadcastChannel` 实例通过 Mojo 接收到消息时，是否会在内部触发 `message` 事件，最终导致 JavaScript 的 `onmessage` 回调被执行。

* **HTML**:
    * **浏览上下文**: `BroadcastChannel` 用于在不同的浏览上下文之间通信，而浏览上下文通常对应于 HTML 页面中的不同标签页或 iframe。虽然这个测试文件没有直接创建 HTML 元素，但它使用了 `DummyPageHolder` 来模拟一个基本的页面环境，其中包含了 `LocalDOMWindow` 和 `LocalFrame`，这些都是 HTML 页面加载和渲染的基础。

    **举例说明**:

    如果用户在浏览器中打开了两个属于同一源的 HTML 页面，并且这两个页面都使用了相同的 `BroadcastChannel` 名称，那么一个页面通过 `postMessage` 发送的消息应该能被另一个页面接收到。这个测试文件中的测试用例模拟了这种跨浏览上下文的消息传递。

* **CSS**:
    * **无直接关系**: `BroadcastChannel` 主要负责通信，与页面的样式和布局（CSS 的作用）没有直接关系。

**逻辑推理和假设输入/输出**

让我们以 `DispatchMessageEvent` 测试用例为例进行逻辑推理：

**假设输入**:

1. 创建一个 `BroadcastChannelTester` 实例，它内部会创建一个 `BroadcastChannel` 对象，并监听 `message` 事件。
2. 通过 `tester->PostMessage(MakeNullMessage())` 模拟从另一个 `BroadcastChannel` 实例（或者其他进程）发送一个空消息。

**逻辑推理**:

1. `BroadcastChannelTester::PostMessage` 方法会调用 Mojo 接口 `remote_->OnMessage`，将消息传递给 `BroadcastChannel` 对象。
2. `BroadcastChannel` 对象接收到消息后，会创建一个 `MessageEvent` 对象。
3. 由于在 `BroadcastChannelTester` 的构造函数中已经添加了 `message` 事件的监听器，这个事件监听器会被触发。
4. `BroadcastChannelTester::EventListener::Invoke` 方法会被调用，它会将接收到的 `MessageEvent` 存储到 `received_events_` 列表中，并调用 `ReportUpdate`。
5. `ReportUpdate` 会执行之前通过 `tester->AwaitNextUpdate` 设置的回调函数，即 `run_loop.QuitClosure()`，从而结束 `run_loop.Run()` 的阻塞。

**预期输出**:

1. `tester->received_events().size()` 的值为 1，表示接收到了一个事件。
2. `tester->received_events()[0]->type()` 的值为 `event_type_names::kMessage`，表示接收到的事件类型是 `message`。

**用户或编程常见的使用错误**

1. **跨域通信错误**: `BroadcastChannel` 只能在同一源下的浏览上下文之间通信。如果开发者尝试在不同源的页面之间使用 `BroadcastChannel`，消息将无法传递。

   **示例**:  如果一个页面在 `https://example.com`，另一个页面在 `https://different.com`，即使它们使用了相同的频道名称，消息也无法互通。

2. **频道名称拼写错误**: 如果不同的浏览上下文使用了不同的频道名称（即使只有一个字母的差异），它们将无法互相通信。

   **示例**:  一个页面使用 `new BroadcastChannel('my-channel')`，另一个页面使用 `new BroadcastChannel('my_channel')`，消息将不会互通。

3. **忘记添加事件监听器**: 如果接收方忘记添加 `message` 事件监听器，即使消息被成功发送和接收，也无法在 JavaScript 中处理该消息。

   **示例**:  如果一个页面创建了 `BroadcastChannel` 但没有设置 `bc.onmessage` 回调，那么它将无法响应接收到的消息。

4. **消息序列化/反序列化错误**: 虽然 `BroadcastChannel` 可以传递复杂的数据结构，但这些数据需要能够被正确地序列化和反序列化。如果传递了无法序列化的数据，或者接收方无法反序列化接收到的数据，将会导致错误。

   **示例**:  尝试传递包含循环引用的对象可能会导致序列化/反序列化错误。

**用户操作到达此处的调试线索**

一个开发者在开发或调试使用了 `BroadcastChannel` 的网页时，可能会因为以下原因需要查看这个单元测试文件：

1. **功能不符合预期**:  开发者发现自己的 `BroadcastChannel` 代码没有按预期工作（例如，消息没有被传递，或者收到了错误的事件），他们可能会怀疑是 Blink 引擎的实现有问题。这时，查看相关的单元测试可以帮助他们了解 Blink 引擎是如何测试这个功能的，从而更好地理解问题的根源。

2. **Blink 引擎代码修改**: 如果有开发者正在修改 Blink 引擎中 `BroadcastChannel` 模块的代码，他们需要运行这些单元测试来确保他们的修改没有引入新的 bug，或者破坏现有的功能。

3. **理解实现细节**:  开发者可能想要深入了解 `BroadcastChannel` 在 Blink 引擎中的具体实现方式，查看单元测试可以帮助他们理解内部的事件派发机制、Agent Cluster Lock 的处理方式等。

**用户操作步骤示例 (导致需要查看测试代码的情况)**

1. **开发者 A** 创建了一个网页 `page1.html`，其中使用了 `BroadcastChannel` 发送消息。
2. **开发者 B** 创建了另一个网页 `page2.html`（与 `page1.html` 同源），其中使用了相同的 `BroadcastChannel` 名称来接收消息。
3. **开发者 B** 在浏览器中打开了 `page1.html` 和 `page2.html`。
4. **开发者 A** 在 `page1.html` 中执行了发送消息的操作（例如，点击一个按钮）。
5. **开发者 B** 发现 `page2.html` 没有收到消息，或者收到了错误的数据。
6. **开发者 B** 开始调试 `page2.html` 的 JavaScript 代码，检查事件监听器是否正确设置，以及接收到的数据是否符合预期。
7. **开发者 B** 怀疑可能是浏览器底层的 `BroadcastChannel` 实现有问题，或者对 Agent Cluster Lock 的理解有误。
8. **开发者 B** 查看 Chromium 源代码，找到了 `blink/renderer/modules/broadcastchannel/broadcast_channel_unittest.cc` 这个文件，希望通过查看测试用例来了解 `BroadcastChannel` 的预期行为和实现细节，例如 Agent Cluster Lock 的匹配规则。他们会仔细阅读测试用例，例如 `AgentClusterLockedMatch` 和 `AgentClusterLockedMismatch`，来验证自己的理解是否正确。

总而言之，`blink/renderer/modules/broadcastchannel/broadcast_channel_unittest.cc` 是一个关键的测试文件，用于验证 `BroadcastChannel` Web API 在 Blink 引擎中的实现是否正确。它通过模拟各种场景，包括正常的消息传递、错误情况和涉及 Agent Cluster Lock 的情况，来确保这个 API 的稳定性和可靠性。对于开发者来说，查看这个文件可以帮助他们更好地理解 `BroadcastChannel` 的工作原理，并排查在使用过程中遇到的问题。

### 提示词
```
这是目录为blink/renderer/modules/broadcastchannel/broadcast_channel_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/broadcastchannel/broadcast_channel.h"

#include <iterator>

#include "base/run_loop.h"
#include "base/task/sequenced_task_runner.h"
#include "base/test/bind.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/messaging/blink_cloneable_message.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_associated_receiver.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_associated_remote.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "v8/include/v8.h"

namespace blink {

class BroadcastChannelTester : public GarbageCollected<BroadcastChannelTester>,
                               public mojom::blink::BroadcastChannelClient {
 public:
  explicit BroadcastChannelTester(ExecutionContext* execution_context)
      : receiver_(this, execution_context), remote_(execution_context) {
    // Ideally, these would share a pipe. This is more convenient.
    mojo::PendingAssociatedReceiver<mojom::blink::BroadcastChannelClient>
        receiver0;
    mojo::PendingAssociatedRemote<mojom::blink::BroadcastChannelClient>
        remote0 = receiver0.InitWithNewEndpointAndPassRemote();
    receiver0.EnableUnassociatedUsage();
    mojo::PendingAssociatedReceiver<mojom::blink::BroadcastChannelClient>
        receiver1;
    mojo::PendingAssociatedRemote<mojom::blink::BroadcastChannelClient>
        remote1 = receiver1.InitWithNewEndpointAndPassRemote();
    receiver1.EnableUnassociatedUsage();

    scoped_refptr<base::SequencedTaskRunner> task_runner =
        execution_context->GetTaskRunner(TaskType::kInternalTest);
    receiver_.Bind(std::move(receiver0), task_runner);
    remote_.Bind(std::move(remote1), task_runner);
    channel_ = MakeGarbageCollected<BroadcastChannel>(
        base::PassKey<BroadcastChannelTester>(), execution_context,
        "BroadcastChannelTester", std::move(receiver1), std::move(remote0));

    auto* listener = MakeGarbageCollected<EventListener>(this);
    channel_->addEventListener(event_type_names::kMessage, listener);
    channel_->addEventListener(event_type_names::kMessageerror, listener);
  }

  BroadcastChannel* channel() const { return channel_.Get(); }
  const HeapVector<Member<MessageEvent>>& received_events() const {
    return received_events_;
  }
  const Vector<BlinkCloneableMessage>& sent_messages() const {
    return sent_messages_;
  }

  void AwaitNextUpdate(base::OnceClosure closure) {
    on_next_update_.push_back(std::move(closure));
  }

  void PostMessage(BlinkCloneableMessage message) {
    remote_->OnMessage(std::move(message));
  }

  void Trace(Visitor* visitor) const {
    visitor->Trace(channel_);
    visitor->Trace(received_events_);
    visitor->Trace(receiver_);
    visitor->Trace(remote_);
  }

  // BroadcastChannelClient
  void OnMessage(BlinkCloneableMessage message) override {
    sent_messages_.push_back(std::move(message));
    ReportUpdate();
  }

 private:
  class EventListener : public NativeEventListener {
   public:
    explicit EventListener(BroadcastChannelTester* tester) : tester_(tester) {}
    void Trace(Visitor* visitor) const override {
      NativeEventListener::Trace(visitor);
      visitor->Trace(tester_);
    }

    void Invoke(ExecutionContext*, Event* event) override {
      tester_->received_events_.push_back(static_cast<MessageEvent*>(event));
      tester_->ReportUpdate();
    }

   private:
    Member<BroadcastChannelTester> tester_;
  };

  void ReportUpdate() {
    Vector<base::OnceClosure> closures = std::move(on_next_update_);
    for (auto& closure : closures)
      std::move(closure).Run();
  }

  Member<BroadcastChannel> channel_;
  HeapVector<Member<MessageEvent>> received_events_;
  Vector<BlinkCloneableMessage> sent_messages_;
  Vector<base::OnceClosure> on_next_update_;
  HeapMojoAssociatedReceiver<mojom::blink::BroadcastChannelClient,
                             BroadcastChannelTester>
      receiver_;
  HeapMojoAssociatedRemote<mojom::blink::BroadcastChannelClient> remote_;
};

namespace {

BlinkCloneableMessage MakeNullMessage() {
  BlinkCloneableMessage message;
  message.message = SerializedScriptValue::NullValue();
  message.sender_agent_cluster_id = base::UnguessableToken::Create();
  return message;
}

TEST(BroadcastChannelTest, DispatchMessageEvent) {
  test::TaskEnvironment task_environment;
  DummyPageHolder holder;
  ExecutionContext* execution_context = holder.GetFrame().DomWindow();
  auto* tester =
      MakeGarbageCollected<BroadcastChannelTester>(execution_context);

  base::RunLoop run_loop;
  tester->AwaitNextUpdate(run_loop.QuitClosure());
  tester->PostMessage(MakeNullMessage());
  run_loop.Run();

  ASSERT_EQ(tester->received_events().size(), 1u);
  EXPECT_EQ(tester->received_events()[0]->type(), event_type_names::kMessage);
}

TEST(BroadcastChannelTest, AgentClusterLockedMatch) {
  test::TaskEnvironment task_environment;
  DummyPageHolder holder;
  ExecutionContext* execution_context = holder.GetFrame().DomWindow();
  auto* tester =
      MakeGarbageCollected<BroadcastChannelTester>(execution_context);

  base::RunLoop run_loop;
  tester->AwaitNextUpdate(run_loop.QuitClosure());
  BlinkCloneableMessage message = MakeNullMessage();
  message.sender_agent_cluster_id = execution_context->GetAgentClusterID();
  message.locked_to_sender_agent_cluster = true;
  tester->PostMessage(std::move(message));
  run_loop.Run();

  ASSERT_EQ(tester->received_events().size(), 1u);
  EXPECT_EQ(tester->received_events()[0]->type(), event_type_names::kMessage);
}

TEST(BroadcastChannelTest, AgentClusterLockedMismatch) {
  test::TaskEnvironment task_environment;
  DummyPageHolder holder;
  ExecutionContext* execution_context = holder.GetFrame().DomWindow();
  auto* tester =
      MakeGarbageCollected<BroadcastChannelTester>(execution_context);

  base::RunLoop run_loop;
  tester->AwaitNextUpdate(run_loop.QuitClosure());
  BlinkCloneableMessage message = MakeNullMessage();
  message.locked_to_sender_agent_cluster = true;
  tester->PostMessage(std::move(message));
  run_loop.Run();

  ASSERT_EQ(tester->received_events().size(), 1u);
  EXPECT_EQ(tester->received_events()[0]->type(),
            event_type_names::kMessageerror);
}

TEST(BroadcastChannelTest, MessageCannotDeserialize) {
  test::TaskEnvironment task_environment;
  DummyPageHolder holder;
  LocalDOMWindow* window = holder.GetFrame().DomWindow();
  auto* tester = MakeGarbageCollected<BroadcastChannelTester>(window);

  SerializedScriptValue::ScopedOverrideCanDeserializeInForTesting
      override_can_deserialize_in(base::BindLambdaForTesting(
          [&](const SerializedScriptValue& value,
              ExecutionContext* execution_context, bool can_deserialize) {
            EXPECT_EQ(execution_context, window);
            EXPECT_TRUE(can_deserialize);
            return false;
          }));

  base::RunLoop run_loop;
  tester->AwaitNextUpdate(run_loop.QuitClosure());
  tester->PostMessage(MakeNullMessage());
  run_loop.Run();

  ASSERT_EQ(tester->received_events().size(), 1u);
  EXPECT_EQ(tester->received_events()[0]->type(),
            event_type_names::kMessageerror);
}

TEST(BroadcastChannelTest, OutgoingMessagesMarkedWithAgentClusterId) {
  test::TaskEnvironment task_environment;
  DummyPageHolder holder;
  ExecutionContext* execution_context = holder.GetFrame().DomWindow();
  ScriptState* script_state = ToScriptStateForMainWorld(&holder.GetFrame());
  auto* tester =
      MakeGarbageCollected<BroadcastChannelTester>(execution_context);

  base::RunLoop run_loop;
  tester->AwaitNextUpdate(run_loop.QuitClosure());
  {
    ScriptState::Scope scope(script_state);
    tester->channel()->postMessage(
        ScriptValue::CreateNull(script_state->GetIsolate()),
        ASSERT_NO_EXCEPTION);
  }
  run_loop.Run();

  ASSERT_EQ(tester->sent_messages().size(), 1u);
  EXPECT_EQ(tester->sent_messages()[0].sender_agent_cluster_id,
            execution_context->GetAgentClusterID());
  EXPECT_FALSE(tester->sent_messages()[0].locked_to_sender_agent_cluster);
}

// TODO(crbug.com/1413818): iOS doesn't support WebAssembly yet.
#if BUILDFLAG(IS_IOS)
#define MAYBE_OutgoingAgentClusterLockedMessage \
  DISABLED_OutgoingAgentClusterLockedMessage
#else
#define MAYBE_OutgoingAgentClusterLockedMessage \
  OutgoingAgentClusterLockedMessage
#endif

TEST(BroadcastChannelTest, MAYBE_OutgoingAgentClusterLockedMessage) {
  test::TaskEnvironment task_environment;
  DummyPageHolder holder;
  ExecutionContext* execution_context = holder.GetFrame().DomWindow();
  ScriptState* script_state = ToScriptStateForMainWorld(&holder.GetFrame());
  v8::Isolate* isolate = script_state->GetIsolate();
  auto* tester =
      MakeGarbageCollected<BroadcastChannelTester>(execution_context);

  base::RunLoop run_loop;
  tester->AwaitNextUpdate(run_loop.QuitClosure());
  {
    // WebAssembly modules are always agent cluster locked. This is a trivial
    // one with no functionality, just the minimal magic and version.
    static constexpr uint8_t kTrivialModuleBytes[] = {0x00, 0x61, 0x73, 0x6d,
                                                      0x01, 0x00, 0x00, 0x00};
    ScriptState::Scope scope(script_state);
    v8::Local<v8::WasmModuleObject> trivial_module =
        v8::WasmModuleObject::Compile(isolate, {std::data(kTrivialModuleBytes),
                                                std::size(kTrivialModuleBytes)})
            .ToLocalChecked();
    tester->channel()->postMessage(ScriptValue(isolate, trivial_module),
                                   ASSERT_NO_EXCEPTION);
  }
  run_loop.Run();

  ASSERT_EQ(tester->sent_messages().size(), 1u);
  EXPECT_EQ(tester->sent_messages()[0].sender_agent_cluster_id,
            execution_context->GetAgentClusterID());
  EXPECT_TRUE(tester->sent_messages()[0].locked_to_sender_agent_cluster);
}

}  // namespace
}  // namespace blink
```