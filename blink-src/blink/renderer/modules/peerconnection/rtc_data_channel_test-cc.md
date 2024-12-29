Response:
My thinking process to analyze the `rtc_data_channel_test.cc` file went something like this:

1. **Understand the Purpose:** The filename itself, `rtc_data_channel_test.cc`, strongly suggests this file contains tests for the `RTCDataChannel` functionality within the Blink rendering engine. The `.cc` extension confirms it's a C++ source file.

2. **Identify Key Includes:**  Scanning the `#include` directives reveals the core components involved:
    * `rtc_data_channel.h`: This is the header file for the class being tested, `RTCDataChannel`.
    * Standard C++ libraries (`memory`, `string`, `utility`).
    * Chromium base libraries (`memory`, `run_loop`, `task`). These indicate asynchronous operations and event handling are likely involved.
    * `testing/gtest/include/gtest/gtest.h`: This confirms the use of Google Test framework for unit testing.
    * Blink-specific headers (`bindings/core/v8`, `bindings/modules/v8`, `core/dom/events`, `core/fileapi`, `core/frame`, `core/testing`, `modules/peerconnection`, `platform/heap`, `platform/scheduler`, `platform/testing`, `platform/wtf`). These highlight interactions with JavaScript (V8), DOM events, file handling (Blobs), frame management, the PeerConnection module itself, and Blink's threading and memory management.

3. **Analyze the Test Structure:** The presence of `namespace blink { namespace { ... } }` and the `TEST_F(RTCDataChannelTest, ...)` macros clearly indicate the use of Google Test. The `RTCDataChannelTest` class likely sets up the test environment.

4. **Examine Helper Classes:**  The code defines `MockEventListener`, `MockPeerConnectionHandler`, and `MockDataChannel`. These are *mock objects*, crucial for isolating the `RTCDataChannel` being tested. They simulate the behavior of external dependencies.
    * `MockEventListener`:  Used to check if events (like `message` or `bufferedamountlow`) are being fired correctly. The `MOCK_METHOD` macro is a strong indicator of mocking.
    * `MockPeerConnectionHandler`: Simulates the underlying PeerConnection handler, likely managing the signaling thread.
    * `MockDataChannel`: The most important mock. It mimics the `webrtc::DataChannelInterface` from the WebRTC library, allowing the tests to control the state and behavior of the underlying data channel without relying on a real WebRTC implementation. Key methods like `ChangeState`, `Send`, `RegisterObserver` are present.

5. **Decipher Individual Tests:**  Each `TEST_F` function tests a specific aspect of `RTCDataChannel` functionality:
    * `ChangeStateEarly`: Tests how the `RTCDataChannel` handles state changes happening *before* its creation.
    * `BufferedAmount`: Checks if the `bufferedAmount` property reflects sent data.
    * `BufferedAmountLow`: Verifies the `bufferedamountlow` event.
    * `Open`, `Close`: Tests state transitions.
    * `Message`: Checks if incoming messages are handled and trigger the `message` event.
    * `SendAfterContextDestroyed`, `CloseAfterContextDestroyed`: Tests behavior after the associated browsing context is destroyed.
    * `StopsThrottling`: Examines the interaction with Blink's background throttling mechanism.
    * `TransfersDisabled`, `TransferableInCreationScopeOnly`, `TransferAllowedOnlyOnce`, `SendPreventsTransfers`: Focuses on the (optional) transferability feature of `RTCDataChannel`.
    * `NoSendAfterClose`: Ensures sending data is prohibited after the channel is closed.

6. **Identify Connections to Web Technologies:**
    * **JavaScript:** The inclusion of V8 binding headers (`v8/v8.h`, `V8RTCDataChannelState.h`) directly links this code to the JavaScript API exposed to web developers. The tests likely verify that the C++ implementation correctly reflects the JavaScript API behavior.
    * **HTML:** While not directly included, the `RTCDataChannel` is a key component of the WebRTC API, which is used within web pages (HTML documents) to establish peer-to-peer communication. The tests indirectly ensure that the JavaScript API used in HTML works correctly.
    * **CSS:**  Less direct connection to CSS. However, the overall functionality of WebRTC (and thus `RTCDataChannel`) can influence the user experience in web applications, which might be styled with CSS.

7. **Infer Logical Reasoning and Assumptions:**  The tests operate under the assumption that the mock objects accurately represent the behavior of the real WebRTC components. The tests are designed to cover various state transitions and interactions, demonstrating a logical approach to verifying the correctness of the `RTCDataChannel` implementation.

8. **Consider User and Programming Errors:** The tests involving `ContextDestroyed` and `NoSendAfterClose` directly address common scenarios where developers might misuse the API (e.g., trying to send data after closing the channel or after the associated context is gone).

9. **Trace User Operations (Debugging Context):** To reach this code during debugging, a user would typically be interacting with a web page that uses the WebRTC API, specifically `RTCDataChannel`. The steps might involve:
    * Opening a web page that initiates a WebRTC connection.
    * This might involve clicking buttons, entering information, or the page automatically starting the connection process.
    * JavaScript code on the page would create an `RTCPeerConnection` and then an `RTCDataChannel`.
    * The JavaScript code might then send or receive data through the data channel.
    * If something goes wrong, a developer might use browser developer tools to inspect the state of the `RTCDataChannel` or step through the JavaScript code. For deeper issues, they might need to delve into the Blink source code, potentially setting breakpoints in files like `rtc_data_channel.cc` or its test file.

10. **Structure the Output:**  Finally, I organized the information gathered in the previous steps into a clear and structured format, addressing each point of the prompt. This involved summarizing the functionality, explaining the relationships to web technologies, providing examples, outlining logical reasoning, and addressing potential errors and debugging scenarios.
这个文件 `blink/renderer/modules/peerconnection/rtc_data_channel_test.cc` 是 Chromium Blink 引擎中用于测试 `RTCDataChannel` 类的单元测试文件。 `RTCDataChannel` 是 WebRTC API 的一部分，用于在浏览器之间建立点对点的数据通道。

以下是该文件的功能列表：

1. **单元测试 `RTCDataChannel` 类:** 该文件包含了针对 `RTCDataChannel` 类的各种功能的单元测试。这些测试旨在验证 `RTCDataChannel` 的行为是否符合预期，包括状态管理、消息发送和接收、事件处理等。

2. **模拟 WebRTC 依赖:** 为了进行隔离测试，该文件使用了 mock 对象 (`MockDataChannel`, `MockPeerConnectionHandler`, `MockEventListener`) 来模拟 `RTCDataChannel` 所依赖的 WebRTC 组件和事件监听器。这使得测试可以在不需要真实 WebRTC 环境的情况下进行。

3. **测试状态管理:** 文件中的测试用例，例如 `ChangeStateEarly`, `Open`, `Close`,  验证了 `RTCDataChannel` 在不同状态之间的转换是否正确，以及状态变化是否触发了相应的事件。

4. **测试消息发送和接收:**  `BufferedAmount`, `Message` 等测试用例检查了消息发送后缓冲区的状态，以及接收消息时是否触发了 `message` 事件。

5. **测试异常处理:** `SendAfterContextDestroyed`, `CloseAfterContextDestroyed` 等测试用例验证了在特定异常情况下，例如关联的上下文被销毁后，`RTCDataChannel` 的行为是否符合预期。

6. **测试节流控制:** `StopsThrottling` 测试用例检查了 `RTCDataChannel` 的状态变化是否会影响 Blink 的后台节流机制。

7. **测试传输能力:**  `TransfersDisabled`, `TransferableInCreationScopeOnly`, `TransferAllowedOnlyOnce`, `SendPreventsTransfers` 等测试用例验证了 `RTCDataChannel` 在跨线程传输时的行为和限制。

8. **测试关闭后的行为:** `NoSendAfterClose` 测试用例验证了在 `RTCDataChannel` 关闭后尝试发送消息是否会抛出异常。

**与 JavaScript, HTML, CSS 的关系：**

该文件主要测试的是 Blink 引擎中 `RTCDataChannel` 的 C++ 实现，但它直接关系到 WebRTC API 在 JavaScript 中的行为，从而影响到使用了 WebRTC 的 HTML 页面。

* **JavaScript:**  `RTCDataChannel` 是 JavaScript WebRTC API 的一部分。JavaScript 代码可以使用 `RTCPeerConnection.createDataChannel()` 方法创建一个 `RTCDataChannel` 对象，并使用其 `send()` 方法发送数据，监听 `onmessage`, `onopen`, `onclose`, `onerror` 等事件。该测试文件确保了 JavaScript 中使用的这些 API 在 Blink 引擎中的 C++ 实现是正确的。

   **举例说明:**

   在 JavaScript 中，你可以创建一个数据通道并发送消息：

   ```javascript
   let pc = new RTCPeerConnection();
   let dataChannel = pc.createDataChannel("myLabel");

   dataChannel.onopen = function(event) {
     console.log("Data channel opened");
     dataChannel.send("Hello from JavaScript!");
   };

   dataChannel.onmessage = function(event) {
     console.log("Received message:", event.data);
   };

   dataChannel.onclose = function(event) {
     console.log("Data channel closed");
   };
   ```

   `rtc_data_channel_test.cc` 中的 `Message` 测试用例模拟了底层 C++ 代码接收到数据，并验证了是否触发了 JavaScript 中 `onmessage` 事件。

* **HTML:** HTML 页面是 JavaScript 代码的载体。用户通过与 HTML 页面上的元素交互，例如点击按钮，可能触发 JavaScript 代码来创建和使用 `RTCDataChannel`。

* **CSS:** CSS 主要负责页面的样式和布局，与 `RTCDataChannel` 的功能本身没有直接关系。然而，使用了 WebRTC 的应用程序的用户界面可能使用 CSS 进行美化。

**逻辑推理 (假设输入与输出):**

以 `BufferedAmount` 测试用例为例：

* **假设输入:**
    * 创建一个 `RTCDataChannel` 对象。
    * 将其状态设置为 `open`。
    * 通过 `send()` 方法发送一个 100 字节的消息。
* **逻辑推理:** `bufferedAmount` 属性应该反映出当前尚未发送完成的字节数。在消息刚刚发送后，这个值应该等于消息的长度。
* **预期输出:** `channel->bufferedAmount()` 的值应该为 `100U`。

以 `NoSendAfterClose` 测试用例为例：

* **假设输入:**
    * 创建一个 `RTCDataChannel` 对象。
    * 调用 `close()` 方法关闭数据通道。
    * 尝试使用 `send()` 方法发送不同类型的数据（字符串、ArrayBuffer、Blob）。
* **逻辑推理:**  一旦数据通道关闭，尝试发送数据应该失败并抛出异常。
* **预期输出:**  调用 `send()` 方法后，`exception_state.HadException()` 应该返回 `true`。

**用户或编程常见的使用错误举例说明:**

1. **在数据通道关闭后尝试发送数据:**  这是 `NoSendAfterClose` 测试用例覆盖的场景。开发者可能会在错误的时机调用 `send()` 方法，例如在 `onclose` 事件触发后。

   ```javascript
   dataChannel.onclose = function(event) {
     console.log("Data channel closed, but I'll try to send anyway...");
     dataChannel.send("This will fail!"); // 错误的使用
   };
   ```

2. **在 `RTCDataChannel` 对象销毁后尝试操作:**  `SendAfterContextDestroyed` 和 `CloseAfterContextDestroyed` 测试用例模拟了这种情况。如果关联的浏览上下文被销毁，继续使用 `RTCDataChannel` 对象会导致错误。

3. **没有正确监听 `onopen` 事件就尝试发送数据:** 虽然 `send()` 方法在通道未打开时不会立即报错，但数据可能无法发送。开发者应该在 `onopen` 事件触发后才开始发送数据。

   ```javascript
   let dataChannel = pc.createDataChannel("myLabel");
   dataChannel.send("Trying to send before open..."); // 可能不会成功

   dataChannel.onopen = function(event) {
     console.log("Data channel opened");
     dataChannel.send("Now it should work.");
   };
   ```

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户打开一个使用 WebRTC 的网页:** 用户在浏览器中访问一个使用了 WebRTC API 的网站。

2. **网页 JavaScript 代码尝试建立点对点连接:**  网页的 JavaScript 代码会创建 `RTCPeerConnection` 对象，并可能调用 `createDataChannel()` 创建数据通道。

3. **用户在网页上执行某些操作，触发数据发送:**  例如，用户在聊天框中输入消息并点击发送按钮，或者进行文件共享操作。

4. **JavaScript 代码调用 `dataChannel.send()`:**  JavaScript 代码会使用 `RTCDataChannel` 对象的 `send()` 方法将数据发送给对等端。

5. **Blink 引擎处理 `send()` 调用:**  浏览器底层的 Blink 引擎会接收到 JavaScript 的 `send()` 调用，并调用相应的 C++ 代码（即 `blink/renderer/modules/peerconnection/rtc_data_channel.cc` 中的实现）。

6. **如果出现问题，开发者可能会调试 Blink 引擎:**
   * **设置断点:** 开发者可能会在 `rtc_data_channel.cc` 或其测试文件 `rtc_data_channel_test.cc` 中设置断点，以便跟踪代码执行流程，查看变量的值，分析问题原因。
   * **查看日志:**  Chromium 提供了丰富的日志输出，开发者可以查看 WebRTC 相关的日志，了解数据通道的状态和事件。
   * **使用开发者工具:** 浏览器开发者工具的网络面板可以查看 WebRTC 连接的状态和 ICE 候选者交换等信息。

通过查看 `rtc_data_channel_test.cc` 文件，开发者可以了解 `RTCDataChannel` 的预期行为，并编写新的测试用例来重现和修复 bug。当用户在使用 WebRTC 功能时遇到问题，例如数据发送失败、连接断开等，开发者可能会通过分析这些测试用例和相关代码来定位问题所在。这个测试文件本身就是一种重要的调试和验证工具。

Prompt: 
```
这是目录为blink/renderer/modules/peerconnection/rtc_data_channel_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/peerconnection/rtc_data_channel.h"

#include <memory>
#include <string>
#include <utility>

#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/test_simple_task_runner.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_data_channel_state.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/modules/peerconnection/mock_rtc_peer_connection_handler_platform.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/page_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {
namespace {

using testing::_;

void RunSynchronous(base::TestSimpleTaskRunner* thread,
                    CrossThreadOnceClosure closure) {
  if (thread->BelongsToCurrentThread()) {
    std::move(closure).Run();
    return;
  }

  base::WaitableEvent waitable_event(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  PostCrossThreadTask(
      *thread, FROM_HERE,
      CrossThreadBindOnce(
          [](CrossThreadOnceClosure closure, base::WaitableEvent* event) {
            std::move(closure).Run();
            event->Signal();
          },
          std::move(closure), CrossThreadUnretained(&waitable_event)));
  waitable_event.Wait();
}

class MockEventListener final : public NativeEventListener {
 public:
  MOCK_METHOD(void, Invoke, (ExecutionContext * executionContext, Event*));
};

class MockPeerConnectionHandler : public MockRTCPeerConnectionHandlerPlatform {
 public:
  MockPeerConnectionHandler(
      scoped_refptr<base::TestSimpleTaskRunner> signaling_thread)
      : signaling_thread_(signaling_thread) {}

  MockPeerConnectionHandler(const MockPeerConnectionHandler&) = delete;
  MockPeerConnectionHandler& operator=(const MockPeerConnectionHandler&) =
      delete;

  scoped_refptr<base::SingleThreadTaskRunner> signaling_thread()
      const override {
    return signaling_thread_;
  }

 private:
  void RunOnceClosure() {
    DCHECK(signaling_thread_->BelongsToCurrentThread());
    std::move(closure_).Run();
  }

  scoped_refptr<base::TestSimpleTaskRunner> signaling_thread_;
  CrossThreadOnceClosure closure_;
};

class MockDataChannel : public webrtc::DataChannelInterface {
 public:
  explicit MockDataChannel(
      scoped_refptr<base::TestSimpleTaskRunner> signaling_thread)
      : signaling_thread_(signaling_thread),
        buffered_amount_(0),
        observer_(nullptr),
        state_(webrtc::DataChannelInterface::kConnecting) {}

  MockDataChannel(const MockDataChannel&) = delete;
  MockDataChannel& operator=(const MockDataChannel&) = delete;

  std::string label() const override { return std::string(); }
  bool reliable() const override { return false; }
  bool ordered() const override { return false; }
  std::optional<int> maxPacketLifeTime() const override { return std::nullopt; }
  std::optional<int> maxRetransmitsOpt() const override { return std::nullopt; }
  std::string protocol() const override { return std::string(); }
  bool negotiated() const override { return false; }
  int id() const override { return 0; }
  uint32_t messages_sent() const override { return 0; }
  uint64_t bytes_sent() const override { return 0; }
  uint32_t messages_received() const override { return 0; }
  uint64_t bytes_received() const override { return 0; }
  void Close() override {}

  void RegisterObserver(webrtc::DataChannelObserver* observer) override {
    RunSynchronous(
        signaling_thread_.get(),
        CrossThreadBindOnce(&MockDataChannel::RegisterObserverOnSignalingThread,
                            CrossThreadUnretained(this),
                            CrossThreadUnretained(observer)));
  }

  void UnregisterObserver() override {
    RunSynchronous(signaling_thread_.get(),
                   CrossThreadBindOnce(
                       &MockDataChannel::UnregisterObserverOnSignalingThread,
                       CrossThreadUnretained(this)));
  }

  uint64_t buffered_amount() const override {
    uint64_t buffered_amount;
    RunSynchronous(signaling_thread_.get(),
                   CrossThreadBindOnce(
                       &MockDataChannel::GetBufferedAmountOnSignalingThread,
                       CrossThreadUnretained(this),
                       CrossThreadUnretained(&buffered_amount)));
    return buffered_amount;
  }

  DataState state() const override {
    DataState state;
    RunSynchronous(
        signaling_thread_.get(),
        CrossThreadBindOnce(&MockDataChannel::GetStateOnSignalingThread,
                            CrossThreadUnretained(this),
                            CrossThreadUnretained(&state)));
    return state;
  }

  bool Send(const webrtc::DataBuffer& buffer) override {
    RunSynchronous(
        signaling_thread_.get(),
        CrossThreadBindOnce(&MockDataChannel::SendOnSignalingThread,
                            CrossThreadUnretained(this), buffer.size()));
    return true;
  }

  void SendAsync(
      webrtc::DataBuffer buffer,
      absl::AnyInvocable<void(webrtc::RTCError) &&> on_complete) override {
    base::WaitableEvent waitable_event(
        base::WaitableEvent::ResetPolicy::MANUAL,
        base::WaitableEvent::InitialState::NOT_SIGNALED);
    auto* adapter = new absl::AnyInvocable<void(webrtc::RTCError) &&>(
        std::move(on_complete));

    PostCrossThreadTask(
        *signaling_thread_.get(), FROM_HERE,
        CrossThreadBindOnce(
            [](MockDataChannel* channel, uint64_t buffer_size,
               absl::AnyInvocable<void(webrtc::RTCError) &&>* adapter) {
              channel->SendOnSignalingThread(buffer_size);
              if (*adapter) {
                std::move (*adapter)(webrtc::RTCError::OK());
              }
              delete adapter;
            },
            CrossThreadUnretained(this), buffer.size(),
            CrossThreadUnretained(adapter)));
  }

  // For testing.
  void ChangeState(DataState state) {
    RunSynchronous(
        signaling_thread_.get(),
        CrossThreadBindOnce(&MockDataChannel::ChangeStateOnSignalingThread,
                            CrossThreadUnretained(this), state));
    // The observer posts the state change from the signaling thread to the main
    // thread. Wait for the posted task to be executed.
    base::RunLoop().RunUntilIdle();
  }

 protected:
  ~MockDataChannel() override = default;

 private:
  void RegisterObserverOnSignalingThread(
      webrtc::DataChannelObserver* observer) {
    DCHECK(signaling_thread_->BelongsToCurrentThread());
    observer_ = observer;
  }

  void UnregisterObserverOnSignalingThread() {
    DCHECK(signaling_thread_->BelongsToCurrentThread());
    observer_ = nullptr;
  }

  void GetBufferedAmountOnSignalingThread(uint64_t* buffered_amount) const {
    DCHECK(signaling_thread_->BelongsToCurrentThread());
    *buffered_amount = buffered_amount_;
  }

  void GetStateOnSignalingThread(DataState* state) const {
    DCHECK(signaling_thread_->BelongsToCurrentThread());
    *state = state_;
  }

  void SendOnSignalingThread(uint64_t buffer_size) {
    DCHECK(signaling_thread_->BelongsToCurrentThread());
    buffered_amount_ += buffer_size;
  }

  void ChangeStateOnSignalingThread(DataState state) {
    DCHECK(signaling_thread_->BelongsToCurrentThread());
    state_ = state;
    if (observer_) {
      observer_->OnStateChange();
    }
  }

  scoped_refptr<base::TestSimpleTaskRunner> signaling_thread_;

  // Accessed on signaling thread.
  uint64_t buffered_amount_;
  raw_ptr<webrtc::DataChannelObserver> observer_;
  webrtc::DataChannelInterface::DataState state_;
};

class RTCDataChannelTest : public ::testing::Test {
 public:
  RTCDataChannelTest() : signaling_thread_(new base::TestSimpleTaskRunner()) {}

  RTCDataChannelTest(const RTCDataChannelTest&) = delete;
  RTCDataChannelTest& operator=(const RTCDataChannelTest&) = delete;

  ~RTCDataChannelTest() override {
    execution_context_->NotifyContextDestroyed();
  }

  scoped_refptr<base::TestSimpleTaskRunner> signaling_thread() {
    return signaling_thread_;
  }

  void VerifyNoTransfersAfterSend(
      base::OnceCallback<void(RTCDataChannel*)> send_data_callback) {
    V8TestingScope scope;
    ScopedTransferableRTCDataChannelForTest scoped_feature(/*enabled=*/true);

    rtc::scoped_refptr<MockDataChannel> webrtc_channel(
        new rtc::RefCountedObject<MockDataChannel>(signaling_thread()));
    auto* channel = MakeGarbageCollected<RTCDataChannel>(
        scope.GetExecutionContext(), webrtc_channel);

    EXPECT_TRUE(channel->IsTransferable());

    // Perform a `send()` operation. We do not care that `channel` is in the
    // "opening" state and that the `send()` operation will throw.
    std::move(send_data_callback).Run(channel);

    // The channel should no longer be transferable after `send()` has been
    // called.
    EXPECT_FALSE(channel->IsTransferable());
  }

 protected:
  test::TaskEnvironment task_environment_;
  Persistent<NullExecutionContext> execution_context_ =
      MakeGarbageCollected<NullExecutionContext>();

 private:
  scoped_refptr<base::TestSimpleTaskRunner> signaling_thread_;
};

}  // namespace

TEST_F(RTCDataChannelTest, ChangeStateEarly) {
  rtc::scoped_refptr<MockDataChannel> webrtc_channel(
      new rtc::RefCountedObject<MockDataChannel>(signaling_thread()));

  // Change state on the webrtc channel before creating the blink channel.
  webrtc_channel->ChangeState(webrtc::DataChannelInterface::kOpen);

  auto* channel =
      MakeGarbageCollected<RTCDataChannel>(execution_context_, webrtc_channel);

  // In RTCDataChannel::Create, the state change update is posted from the
  // signaling thread to the main thread. Wait for posted the task to be
  // executed.
  base::RunLoop().RunUntilIdle();

  // Verify that the early state change was not lost.
  EXPECT_EQ(V8RTCDataChannelState::Enum::kOpen, channel->readyState());
}

TEST_F(RTCDataChannelTest, BufferedAmount) {
  rtc::scoped_refptr<MockDataChannel> webrtc_channel(
      new rtc::RefCountedObject<MockDataChannel>(signaling_thread()));
  auto* channel =
      MakeGarbageCollected<RTCDataChannel>(execution_context_, webrtc_channel);
  webrtc_channel->ChangeState(webrtc::DataChannelInterface::kOpen);

  String message(std::string(100, 'A').c_str());
  channel->send(message, IGNORE_EXCEPTION_FOR_TESTING);
  EXPECT_EQ(100U, channel->bufferedAmount());
  // The actual send operation is posted to the signaling thread; wait for it
  // to run to avoid a memory leak.
  signaling_thread()->RunUntilIdle();
}

TEST_F(RTCDataChannelTest, BufferedAmountLow) {
  rtc::scoped_refptr<MockDataChannel> webrtc_channel(
      new rtc::RefCountedObject<MockDataChannel>(signaling_thread()));
  auto* onbufferedamountlow_handler = MakeGarbageCollected<MockEventListener>();
  auto* channel =
      MakeGarbageCollected<RTCDataChannel>(execution_context_, webrtc_channel);
  channel->addEventListener(event_type_names::kBufferedamountlow,
                            onbufferedamountlow_handler);
  EXPECT_CALL(*onbufferedamountlow_handler, Invoke(_, _));
  webrtc_channel->ChangeState(webrtc::DataChannelInterface::kOpen);

  channel->setBufferedAmountLowThreshold(1);
  channel->send("TEST", IGNORE_EXCEPTION_FOR_TESTING);
  EXPECT_EQ(4U, channel->bufferedAmount());
  channel->OnBufferedAmountChange(4);

  // The actual send operation is posted to the signaling thread; wait for it
  // to run to avoid a memory leak.
  signaling_thread()->RunUntilIdle();
}

TEST_F(RTCDataChannelTest, Open) {
  rtc::scoped_refptr<MockDataChannel> webrtc_channel(
      new rtc::RefCountedObject<MockDataChannel>(signaling_thread()));
  auto* channel =
      MakeGarbageCollected<RTCDataChannel>(execution_context_, webrtc_channel);
  channel->OnStateChange(webrtc::DataChannelInterface::kOpen);
  EXPECT_EQ(V8RTCDataChannelState::Enum::kOpen, channel->readyState());
}

TEST_F(RTCDataChannelTest, Close) {
  rtc::scoped_refptr<MockDataChannel> webrtc_channel(
      new rtc::RefCountedObject<MockDataChannel>(signaling_thread()));
  auto* channel =
      MakeGarbageCollected<RTCDataChannel>(execution_context_, webrtc_channel);
  channel->OnStateChange(webrtc::DataChannelInterface::kClosed);
  EXPECT_EQ(V8RTCDataChannelState::Enum::kClosed, channel->readyState());
}

TEST_F(RTCDataChannelTest, Message) {
  rtc::scoped_refptr<MockDataChannel> webrtc_channel(
      new rtc::RefCountedObject<MockDataChannel>(signaling_thread()));
  auto* onmessage_handler = MakeGarbageCollected<MockEventListener>();
  auto* channel =
      MakeGarbageCollected<RTCDataChannel>(execution_context_, webrtc_channel);
  channel->addEventListener(event_type_names::kMessage, onmessage_handler);
  EXPECT_CALL(*onmessage_handler, Invoke(_, _));

  channel->OnMessage(webrtc::DataBuffer("A"));
}

TEST_F(RTCDataChannelTest, SendAfterContextDestroyed) {
  rtc::scoped_refptr<MockDataChannel> webrtc_channel(
      new rtc::RefCountedObject<MockDataChannel>(signaling_thread()));
  auto* channel =
      MakeGarbageCollected<RTCDataChannel>(execution_context_, webrtc_channel);
  webrtc_channel->ChangeState(webrtc::DataChannelInterface::kOpen);

  channel->ContextDestroyed();

  String message(std::string(100, 'A').c_str());
  DummyExceptionStateForTesting exception_state;
  channel->send(message, exception_state);

  EXPECT_TRUE(exception_state.HadException());
}

TEST_F(RTCDataChannelTest, CloseAfterContextDestroyed) {
  rtc::scoped_refptr<MockDataChannel> webrtc_channel(
      new rtc::RefCountedObject<MockDataChannel>(signaling_thread()));
  auto* channel =
      MakeGarbageCollected<RTCDataChannel>(execution_context_, webrtc_channel);
  webrtc_channel->ChangeState(webrtc::DataChannelInterface::kOpen);

  channel->ContextDestroyed();
  channel->close();
  EXPECT_EQ(V8RTCDataChannelState::Enum::kClosed, channel->readyState());
}

TEST_F(RTCDataChannelTest, StopsThrottling) {
  V8TestingScope scope;

  auto* scheduler = scope.GetFrame().GetFrameScheduler()->GetPageScheduler();
  EXPECT_FALSE(scheduler->OptedOutFromAggressiveThrottlingForTest());

  // Creating an RTCDataChannel doesn't enable the opt-out.
  rtc::scoped_refptr<MockDataChannel> webrtc_channel(
      new rtc::RefCountedObject<MockDataChannel>(signaling_thread()));
  auto* channel = MakeGarbageCollected<RTCDataChannel>(
      scope.GetExecutionContext(), webrtc_channel);
  EXPECT_EQ(V8RTCDataChannelState::Enum::kConnecting, channel->readyState());
  EXPECT_FALSE(scheduler->OptedOutFromAggressiveThrottlingForTest());

  // Transitioning to 'open' enables the opt-out.
  webrtc_channel->ChangeState(webrtc::DataChannelInterface::kOpen);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(V8RTCDataChannelState::Enum::kOpen, channel->readyState());
  EXPECT_TRUE(scheduler->OptedOutFromAggressiveThrottlingForTest());

  // Transitioning to 'closing' keeps the opt-out enabled.
  webrtc_channel->ChangeState(webrtc::DataChannelInterface::kClosing);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(V8RTCDataChannelState::Enum::kClosing, channel->readyState());
  EXPECT_TRUE(scheduler->OptedOutFromAggressiveThrottlingForTest());

  // Transitioning to 'closed' stops the opt-out.
  webrtc_channel->ChangeState(webrtc::DataChannelInterface::kClosed);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(V8RTCDataChannelState::Enum::kClosed, channel->readyState());
  EXPECT_FALSE(scheduler->OptedOutFromAggressiveThrottlingForTest());
}

TEST_F(RTCDataChannelTest, TransfersDisabled) {
  V8TestingScope scope;
  ScopedTransferableRTCDataChannelForTest scoped_feature(/*enabled=*/false);

  rtc::scoped_refptr<MockDataChannel> webrtc_channel(
      new rtc::RefCountedObject<MockDataChannel>(signaling_thread()));
  auto* channel = MakeGarbageCollected<RTCDataChannel>(
      scope.GetExecutionContext(), webrtc_channel);

  EXPECT_FALSE(channel->IsTransferable());
}

TEST_F(RTCDataChannelTest, TransferableInCreationScopeOnly) {
  V8TestingScope scope;
  ScopedTransferableRTCDataChannelForTest scoped_feature(/*enabled=*/true);

  rtc::scoped_refptr<MockDataChannel> webrtc_channel(
      new rtc::RefCountedObject<MockDataChannel>(signaling_thread()));
  auto* channel = MakeGarbageCollected<RTCDataChannel>(
      scope.GetExecutionContext(), webrtc_channel);

  EXPECT_TRUE(channel->IsTransferable());

  // RTCDataChannel cannot be transferred once it has connected to
  // `webrtc_channel`, as we could lose incoming messages during the transfer.
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(channel->IsTransferable());
}

TEST_F(RTCDataChannelTest, TransferAllowedOnlyOnce) {
  V8TestingScope scope;
  ScopedTransferableRTCDataChannelForTest scoped_feature(/*enabled=*/true);

  rtc::scoped_refptr<MockDataChannel> webrtc_channel(
      new rtc::RefCountedObject<MockDataChannel>(signaling_thread()));
  auto* channel = MakeGarbageCollected<RTCDataChannel>(
      scope.GetExecutionContext(), webrtc_channel);

  EXPECT_TRUE(channel->IsTransferable());
  EXPECT_NE(channel->TransferUnderlyingChannel(), nullptr);

  // The channel should no longer be transferable.
  EXPECT_FALSE(channel->IsTransferable());
}

TEST_F(RTCDataChannelTest, SendPreventsTransfers) {
  {
    SCOPED_TRACE("RTCDataChannel::send(const string&)");
    VerifyNoTransfersAfterSend(WTF::BindOnce([](RTCDataChannel* channel) {
      String message(std::string(100, 'A').c_str());
      channel->send(message, IGNORE_EXCEPTION_FOR_TESTING);
    }));
  }

  {
    SCOPED_TRACE("RTCDataChannel::send(DOMArrayBuffer*)");
    VerifyNoTransfersAfterSend(WTF::BindOnce([](RTCDataChannel* channel) {
      DOMArrayBuffer* buffer = DOMArrayBuffer::Create(10, 4);
      channel->send(buffer, IGNORE_EXCEPTION_FOR_TESTING);
    }));
  }

  {
    SCOPED_TRACE("RTCDataChannel::send(NotShared<DOMArrayBufferView>)");
    VerifyNoTransfersAfterSend(WTF::BindOnce([](RTCDataChannel* channel) {
      DOMArrayBuffer* buffer = DOMArrayBuffer::Create(10, 4);
      channel->send(
          NotShared<DOMArrayBufferView>(DOMDataView::Create(buffer, 0, 10)),
          IGNORE_EXCEPTION_FOR_TESTING);
    }));
  }

  {
    SCOPED_TRACE("RTCDataChannel::send(Blob*)");
    VerifyNoTransfersAfterSend(WTF::BindOnce([](RTCDataChannel* channel) {
      const char kHelloWorld[] = "Hello world!";
      Blob* blob = Blob::Create(
          base::as_bytes(base::span_with_nul_from_cstring(kHelloWorld)),
          "text/plain");
      channel->send(blob, IGNORE_EXCEPTION_FOR_TESTING);
    }));
  }
}

TEST_F(RTCDataChannelTest, NoSendAfterClose) {
  V8TestingScope scope;

  rtc::scoped_refptr<MockDataChannel> webrtc_channel(
      new rtc::RefCountedObject<MockDataChannel>(signaling_thread()));
  auto* channel = MakeGarbageCollected<RTCDataChannel>(
      scope.GetExecutionContext(), webrtc_channel);
  channel->close();

  {
    SCOPED_TRACE("RTCDataChannel::send(const string&)");
    String message(std::string(100, 'A').c_str());
    DummyExceptionStateForTesting exception_state;
    channel->send(message, exception_state);
    EXPECT_TRUE(exception_state.HadException());
  }

  {
    SCOPED_TRACE("RTCDataChannel::send(DOMArrayBuffer*)");
    DOMArrayBuffer* buffer = DOMArrayBuffer::Create(10, 4);
    DummyExceptionStateForTesting exception_state;
    channel->send(buffer, exception_state);
    EXPECT_TRUE(exception_state.HadException());
  }

  {
    SCOPED_TRACE("RTCDataChannel::send(NotShared<DOMArrayBufferView>)");
    DOMArrayBuffer* buffer = DOMArrayBuffer::Create(10, 4);
    DummyExceptionStateForTesting exception_state;
    channel->send(
        NotShared<DOMArrayBufferView>(DOMDataView::Create(buffer, 0, 10)),
        exception_state);
    EXPECT_TRUE(exception_state.HadException());
  }

  {
    SCOPED_TRACE("RTCDataChannel::send(Blob*)");
    const char kHelloWorld[] = "Hello world!";
    Blob* blob = Blob::Create(
        base::as_bytes(base::span_with_nul_from_cstring(kHelloWorld)),
        "text/plain");
    DummyExceptionStateForTesting exception_state;
    channel->send(blob, exception_state);
    EXPECT_TRUE(exception_state.HadException());
  }
}

}  // namespace blink

"""

```