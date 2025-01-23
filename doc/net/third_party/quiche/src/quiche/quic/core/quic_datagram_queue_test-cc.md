Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding - Filename and Imports:**

* **Filename:** `net/third_party/quiche/src/quiche/quic/core/quic_datagram_queue_test.cc`  Immediately tells us this is a test file (`_test.cc`) for the `QuicDatagramQueue` class, part of the QUIC implementation within Chromium's network stack (using the Quiche library).
* **Imports:**  Skimming the `#include` directives reveals core QUIC concepts:
    * `quic_datagram_queue.h`: The header file for the class being tested.
    * `crypto/null_encrypter.h`: Hints at testing scenarios without actual encryption.
    * `quic_time.h`, `quic_types.h`: Basic QUIC primitives.
    * `platform/api/quic_test.h`:  The testing framework being used (likely Google Test).
    * `test_tools/quic_test_utils.h`: Utilities for setting up mock QUIC environments.
    * `common/platform/api/quiche_mem_slice.h`, `common/platform/api/quiche_reference_counted.h`, `common/quiche_buffer_allocator.h`: Memory management related to QUIC.
    * Standard C++ libraries (`memory`, `optional`, `string`, `utility`, `vector`).
    * `absl/strings/string_view.h`: Efficient string handling.

**2. Core Class Under Test - `QuicDatagramQueue`:**

The filename and the inclusion of its header are the biggest clues. This test file focuses on verifying the behavior of the `QuicDatagramQueue` class. It likely manages the queuing of QUIC datagrams (UDP-like messages) before they are sent.

**3. Test Structure - Google Test Framework:**

* **`namespace quic { namespace test { namespace {`:**  Standard practice in Chromium to encapsulate test code.
* **`using testing::...`:**  Imports elements from the Google Test framework (e.g., `TEST_F`, `EXPECT_EQ`, `EXPECT_CALL`, `Return`, `ElementsAre`).
* **Test Fixtures (`QuicDatagramQueueTestBase`, `QuicDatagramQueueTest`, `QuicDatagramQueueWithObserverTest`):**  These set up common environments for different sets of tests, reducing code duplication. `QuicDatagramQueueTestBase` seems to provide mock QUIC components, while the other two specialize for testing specific aspects of the queue.
* **Individual Tests (`TEST_F(...)`):**  Each `TEST_F` represents a specific test case for a particular function or scenario of the `QuicDatagramQueue`.

**4. Analyzing Individual Tests - Understanding Functionality:**

Now, we go through each `TEST_F` and try to understand its purpose:

* **`SendDatagramImmediately`:**  Tests sending a datagram when the connection is ready. Expects `SendMessage` to be called immediately and return success.
* **`SendDatagramAfterBuffering`:**  Tests the queuing behavior when sending is initially blocked. Verifies the datagram remains in the queue and is sent later when the connection is ready.
* **`EmptyBuffer`:** Tests the behavior when trying to send from an empty queue.
* **`MultipleDatagrams`:**  Tests sending multiple datagrams, likely to verify queuing and batching behavior.
* **`DefaultMaxTimeInQueue`:**  Checks the default timeout for datagrams in the queue and how it's influenced by RTT.
* **`Expiry`:** Tests the scenario where datagrams are dropped from the queue due to exceeding the maximum time in the queue.
* **`ExpireAll`:** Tests the scenario where all datagrams in the queue expire.
* **`QuicDatagramQueueWithObserverTest` (and its tests):** Introduces an observer to track the status of sent datagrams. Tests scenarios of immediate success, immediate failure, blocking, success after buffering, and expiry, all while observing the status changes.

**5. Identifying Key Functionality:**

Based on the tests, we can deduce the core functionalities of `QuicDatagramQueue`:

* **Queueing:**  Stores datagrams when they cannot be sent immediately.
* **Sending:**  Attempts to send queued datagrams.
* **Buffering:**  Holds datagrams until the connection allows sending.
* **Expiry:**  Drops datagrams that have been in the queue for too long.
* **Observation:**  Provides a mechanism to be notified about the success or failure of datagram delivery.

**6. Relationship to JavaScript (If Any):**

This is a tricky part. Directly, this C++ code doesn't interact with JavaScript. However:

* **WebTransport:** QUIC datagrams are a fundamental part of the WebTransport API, which *is* exposed to JavaScript. WebTransport allows bidirectional, unreliable data transfer between a browser and a server. The `QuicDatagramQueue` would be part of the underlying implementation of WebTransport in Chromium.
* **Example:** If a JavaScript application uses the WebTransport API to send data:
   ```javascript
   const transport = new WebTransport("https://example.com/webtransport");
   await transport.ready;
   const writer = transport.datagrams.writable.getWriter();
   writer.write(new TextEncoder().encode("Hello from JS!"));
   writer.close();
   ```
   Internally, Chromium's network stack (including the code in this test file) would be responsible for taking that "Hello from JS!" data and queuing it as a QUIC datagram for transmission.

**7. Logical Reasoning (Hypothetical Input/Output):**

* **Scenario:** The connection is initially blocked.
* **Input:** `queue_.SendOrQueueDatagram(CreateMemSlice("data1"))`;  `queue_.SendOrQueueDatagram(CreateMemSlice("data2"))`;  The connection later becomes unblocked.
* **Output:** The first `SendOrQueueDatagram` returns `MESSAGE_STATUS_BLOCKED`. The second also *might* return `MESSAGE_STATUS_BLOCKED` (depending on internal logic - the test seems to imply it would). When `SendDatagrams()` is called after the connection is unblocked, it will attempt to send "data1" and "data2", and the number of successfully sent datagrams will be returned.

**8. User/Programming Errors:**

* **Sending Too Much Data Too Quickly:**  If the application sends datagrams faster than the network can handle, the queue might fill up. While this specific test doesn't explicitly cover queue limits, it's a potential error in real-world usage.
* **Incorrect Configuration:**  While not directly testable here, misconfiguring QUIC parameters could lead to unexpected blocking or expiry.
* **Not Handling `MESSAGE_STATUS_BLOCKED`:** A programmer might ignore the `MESSAGE_STATUS_BLOCKED` return value and assume the data was sent, leading to lost data.

**9. User Steps to Reach This Code (Debugging Clues):**

1. **User opens a website or web application that uses WebTransport.**
2. **The JavaScript code in the web application uses the WebTransport API to send data.**  Specifically, using `transport.datagrams.writable.getWriter().write(...)`.
3. **The browser's network stack initiates a QUIC connection to the server.**
4. **When the JavaScript code attempts to send a datagram, the browser's implementation of the WebTransport API will interact with the underlying QUIC implementation.**
5. **The `QuicDatagramQueue` will be involved in managing the outgoing datagram.** If the connection is congested or not yet fully established for datagrams, the `SendOrQueueDatagram` function might be called, leading to the datagram being queued.
6. **If the developer is debugging network issues or WebTransport specifically, they might set breakpoints in the QUIC code, including `quic_datagram_queue_test.cc` (to understand the queuing behavior) or the actual `quic_datagram_queue.cc` implementation.** They might examine the queue size, the status of the connection, and the timestamps of the queued datagrams.

By following these steps, we can systematically dissect the C++ test file and understand its purpose, its relationship to other technologies, and how it fits into the broader context of a web browser's network stack.
这个C++源代码文件 `quic_datagram_queue_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，专门用于测试 `QuicDatagramQueue` 类的功能。 `QuicDatagramQueue` 的主要作用是管理 QUIC 连接中用户数据报（datagrams）的发送和缓冲。

以下是该文件测试的主要功能：

**1. 数据报的立即发送:**
   - 测试在连接状态允许的情况下，数据报是否能立即被发送出去。
   - **假设输入:** 创建一个包含 "test" 字符串的 `QuicheMemSlice`，并调用 `SendOrQueueDatagram`。
   - **预期输出:** `SendMessage` 被调用且返回 `MESSAGE_STATUS_SUCCESS`，队列大小为 0。

**2. 数据报的缓冲和后续发送:**
   - 测试当连接暂时阻塞（例如，拥塞控制限制发送速率）时，数据报是否会被正确地缓冲起来。
   - 测试当连接恢复后，缓冲的数据报是否能被成功发送。
   - **假设输入:**
     - 第一次调用 `SendOrQueueDatagram` 时，`SendMessage` 返回 `MESSAGE_STATUS_BLOCKED`。
     - 之后调用 `TrySendingNextDatagram`，如果连接仍然阻塞，则返回 `MESSAGE_STATUS_BLOCKED`。
     - 最后调用 `TrySendingNextDatagram`，如果连接不再阻塞，则 `SendMessage` 返回 `MESSAGE_STATUS_SUCCESS`。
   - **预期输出:** 第一次调用后队列大小为 1，后续调用根据连接状态返回不同的状态，最终成功发送后队列大小为 0。

**3. 空缓冲区的处理:**
   - 测试在没有数据报需要发送时，`TrySendingNextDatagram` 和 `SendDatagrams` 的行为。
   - **假设输入:** 直接调用 `TrySendingNextDatagram` 或 `SendDatagrams`。
   - **预期输出:** `TrySendingNextDatagram` 返回 `std::nullopt`， `SendDatagrams` 返回 0。

**4. 发送多个数据报:**
   - 测试当有多个数据报需要发送时，`QuicDatagramQueue` 的处理能力。
   - **假设输入:** 连续调用 `SendOrQueueDatagram` 添加多个数据报，然后调用 `SendDatagrams`。
   - **预期输出:** `SendDatagrams` 调用 `SendMessage` 的次数与成功发送的数据报数量一致。

**5. 默认最大排队时间:**
   - 测试数据报在队列中的默认最大存活时间，以及这个时间如何受到 RTT (Round-Trip Time) 的影响。
   - **假设输入:** 初始状态下检查 `GetMaxTimeInQueue` 的返回值。更新 RTT 后再次检查。
   - **预期输出:** 默认值为 4 毫秒，更新 RTT 后，最大排队时间会根据 RTT 进行调整 (例如，1.25 倍的 RTT)。

**6. 数据报的过期机制:**
   - 测试数据报在队列中超过最大存活时间后被丢弃的机制。
   - **假设输入:**
     - 设置一个较小的最大排队时间。
     - 连续添加多个数据报，并在添加过程中推进模拟时间。
     - 调用 `SendDatagrams`。
   - **预期输出:** 只有在调用 `SendDatagrams` 时尚未过期的数据报才会被发送。

**7. 数据报全部过期:**
   - 测试当队列中的所有数据报都过期时，`SendDatagrams` 的行为。
   - **假设输入:**
     - 设置一个最大排队时间。
     - 添加多个数据报。
     - 大幅推进模拟时间，使得所有数据报都过期。
     - 调用 `SendDatagrams`。
   - **预期输出:** `SendDatagrams` 不会调用 `SendMessage`，并返回 0。

**8. 使用观察者模式 (`QuicDatagramQueueObserver`):**
   - 测试当使用观察者时，数据报发送成功、失败或过期时，观察者是否能收到相应的通知。
   - **假设输入/输出 (根据不同的测试用例):**
     - **立即成功:** `SendMessage` 返回成功，观察者收到 `MESSAGE_STATUS_SUCCESS`。
     - **立即失败:** `SendMessage` 返回失败 (例如 `MESSAGE_STATUS_TOO_LARGE`)，观察者收到对应的错误状态。
     - **阻塞:** `SendMessage` 返回阻塞，观察者不会立即收到通知。
     - **缓冲后成功:** 数据报先被缓冲，后续发送成功，观察者收到 `MESSAGE_STATUS_SUCCESS`。
     - **过期:** 数据报过期，观察者收到 `std::nullopt`。

**与 JavaScript 的关系:**

`QuicDatagramQueue` 本身是用 C++ 实现的，与 JavaScript 没有直接的交互。然而，它在支持 WebTransport API 中扮演着关键角色。WebTransport 允许 JavaScript 代码通过 QUIC 协议发送和接收任意二进制数据。

**举例说明:**

当 JavaScript 代码使用 WebTransport API 发送数据报时，浏览器底层的 QUIC 实现会使用 `QuicDatagramQueue` 来管理这些数据报。

```javascript
// JavaScript 代码 (在支持 WebTransport 的浏览器中)
const transport = new WebTransport("https://example.com/webtransport");
await transport.ready;

const encoder = new TextEncoder();
const data = encoder.encode("Hello, WebTransport!");
const writableStreamClosed = transport.datagrams.writable.getWriter().write(data);
```

在这个例子中，当 `writer.write(data)` 被调用时，浏览器会将 `data` 传递给底层的 QUIC 实现。如果连接状态允许，`QuicDatagramQueue` 可能会立即发送这个数据报。如果连接被阻塞，这个数据报会被加入到 `QuicDatagramQueue` 中等待后续发送。

**逻辑推理的假设输入与输出:**

**场景:**  连接的发送缓冲区已满，导致 `SendMessage` 返回 `MESSAGE_STATUS_BLOCKED`。

**假设输入:**
1. 调用 `queue_.SendOrQueueDatagram(CreateMemSlice("message1"))`。
2. 调用 `queue_.SendOrQueueDatagram(CreateMemSlice("message2"))`。
3. 稍后，连接的发送缓冲区有空间了。
4. 调用 `queue_.TrySendingNextDatagram()`。
5. 再次调用 `queue_.TrySendingNextDatagram()`。

**预期输出:**
1. 第一次调用 `SendOrQueueDatagram`，`SendMessage` 返回 `MESSAGE_STATUS_BLOCKED`，队列中包含 "message1"。
2. 第二次调用 `SendOrQueueDatagram`，`SendMessage` 也会返回 `MESSAGE_STATUS_BLOCKED`，队列中包含 "message1" 和 "message2"。
3. 调用 `TrySendingNextDatagram()`，`SendMessage` 成功发送 "message1"，返回 `MESSAGE_STATUS_SUCCESS`。
4. 再次调用 `TrySendingNextDatagram()`，`SendMessage` 成功发送 "message2"，返回 `MESSAGE_STATUS_SUCCESS`。

**用户或编程常见的使用错误:**

1. **没有处理 `MESSAGE_STATUS_BLOCKED`:**  程序员可能会忽略 `SendOrQueueDatagram` 返回的 `MESSAGE_STATUS_BLOCKED`，并错误地认为数据已经发送。正确的做法是，当收到 `MESSAGE_STATUS_BLOCKED` 时，应该等待连接状态变化后再尝试发送。

   ```c++
   // 错误的做法
   MessageStatus status = queue_.SendOrQueueDatagram(CreateMemSlice("data"));
   // 假设 status 是 MESSAGE_STATUS_SUCCESS，但实际上可能是 BLOCKED

   // 正确的做法 (通常 QUIC 栈会处理阻塞的情况，但理解这个状态很重要)
   MessageStatus status = queue_.SendOrQueueDatagram(CreateMemSlice("data"));
   if (status == MESSAGE_STATUS_BLOCKED) {
       // 等待连接通知可以发送数据后重试
   }
   ```

2. **过度依赖数据报的可靠性或顺序性:** QUIC 数据报是不可靠的、无序的。依赖于数据报的可靠传输或特定顺序可能会导致问题。程序员应该在应用层处理数据报的丢失或乱序。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户正在使用一个基于 WebTransport 的在线游戏：

1. **用户启动游戏并连接到服务器。** 这会触发 JavaScript 代码使用 WebTransport API 建立连接。
2. **用户在游戏中执行操作，例如移动角色或发送消息。**  这些操作可能会导致 JavaScript 代码通过 WebTransport 的数据报接口发送数据。
3. **网络拥塞或服务器负载过高导致 QUIC 连接的发送受到限制。**  这时，当 JavaScript 尝试发送数据报时，底层的 `QuicDatagramQueue` 会收到发送请求。
4. **`QuicDatagramQueue::SendOrQueueDatagram` 被调用。** 由于连接被阻塞，`SendMessage` 返回 `MESSAGE_STATUS_BLOCKED`。
5. **数据报被添加到 `QuicDatagramQueue` 的队列中。**
6. **（在调试时）开发者可能在 `quic_datagram_queue_test.cc` 或相关的实现代码中设置断点。**  当用户执行导致数据报被缓冲的操作时，断点会被命中，开发者可以检查队列的状态、数据报的内容以及连接的状态。
7. **随着网络状况的改善，QUIC 连接允许发送更多数据。** `QuicDatagramQueue::SendDatagrams` 或 `QuicDatagramQueue::TrySendingNextDatagram` 被调用。
8. **队列中的数据报被发送出去。**
9. **游戏服务器接收到用户操作的数据，并更新游戏状态。**

通过调试 `quic_datagram_queue_test.cc` 中的测试用例，开发者可以确保 `QuicDatagramQueue` 在各种网络条件下都能正确地管理和发送数据报，从而保证 WebTransport 应用的稳定性和性能。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_datagram_queue_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_datagram_queue.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/null_encrypter.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/platform/api/quiche_mem_slice.h"
#include "quiche/common/platform/api/quiche_reference_counted.h"
#include "quiche/common/quiche_buffer_allocator.h"

namespace quic {
namespace test {
namespace {

using testing::_;
using testing::ElementsAre;
using testing::Return;

class EstablishedCryptoStream : public MockQuicCryptoStream {
 public:
  using MockQuicCryptoStream::MockQuicCryptoStream;

  bool encryption_established() const override { return true; }
};

class QuicDatagramQueueObserver final : public QuicDatagramQueue::Observer {
 public:
  class Context : public quiche::QuicheReferenceCounted {
   public:
    std::vector<std::optional<MessageStatus>> statuses;
  };

  QuicDatagramQueueObserver() : context_(new Context()) {}
  QuicDatagramQueueObserver(const QuicDatagramQueueObserver&) = delete;
  QuicDatagramQueueObserver& operator=(const QuicDatagramQueueObserver&) =
      delete;

  void OnDatagramProcessed(std::optional<MessageStatus> status) override {
    context_->statuses.push_back(std::move(status));
  }

  const quiche::QuicheReferenceCountedPointer<Context>& context() {
    return context_;
  }

 private:
  quiche::QuicheReferenceCountedPointer<Context> context_;
};

class QuicDatagramQueueTestBase : public QuicTest {
 protected:
  QuicDatagramQueueTestBase()
      : connection_(new MockQuicConnection(&helper_, &alarm_factory_,
                                           Perspective::IS_CLIENT)),
        session_(connection_) {
    session_.SetCryptoStream(new EstablishedCryptoStream(&session_));
    connection_->SetEncrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<NullEncrypter>(connection_->perspective()));
  }

  ~QuicDatagramQueueTestBase() = default;

  quiche::QuicheMemSlice CreateMemSlice(absl::string_view data) {
    return quiche::QuicheMemSlice(quiche::QuicheBuffer::Copy(
        helper_.GetStreamSendBufferAllocator(), data));
  }

  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  MockQuicConnection* connection_;  // Owned by |session_|.
  MockQuicSession session_;
};

class QuicDatagramQueueTest : public QuicDatagramQueueTestBase {
 public:
  QuicDatagramQueueTest() : queue_(&session_) {}

 protected:
  QuicDatagramQueue queue_;
};

TEST_F(QuicDatagramQueueTest, SendDatagramImmediately) {
  EXPECT_CALL(*connection_, SendMessage(_, _, _))
      .WillOnce(Return(MESSAGE_STATUS_SUCCESS));
  MessageStatus status = queue_.SendOrQueueDatagram(CreateMemSlice("test"));
  EXPECT_EQ(MESSAGE_STATUS_SUCCESS, status);
  EXPECT_EQ(0u, queue_.queue_size());
}

TEST_F(QuicDatagramQueueTest, SendDatagramAfterBuffering) {
  EXPECT_CALL(*connection_, SendMessage(_, _, _))
      .WillOnce(Return(MESSAGE_STATUS_BLOCKED));
  MessageStatus initial_status =
      queue_.SendOrQueueDatagram(CreateMemSlice("test"));
  EXPECT_EQ(MESSAGE_STATUS_BLOCKED, initial_status);
  EXPECT_EQ(1u, queue_.queue_size());

  // Verify getting write blocked does not remove the datagram from the queue.
  EXPECT_CALL(*connection_, SendMessage(_, _, _))
      .WillOnce(Return(MESSAGE_STATUS_BLOCKED));
  std::optional<MessageStatus> status = queue_.TrySendingNextDatagram();
  ASSERT_TRUE(status.has_value());
  EXPECT_EQ(MESSAGE_STATUS_BLOCKED, *status);
  EXPECT_EQ(1u, queue_.queue_size());

  EXPECT_CALL(*connection_, SendMessage(_, _, _))
      .WillOnce(Return(MESSAGE_STATUS_SUCCESS));
  status = queue_.TrySendingNextDatagram();
  ASSERT_TRUE(status.has_value());
  EXPECT_EQ(MESSAGE_STATUS_SUCCESS, *status);
  EXPECT_EQ(0u, queue_.queue_size());
}

TEST_F(QuicDatagramQueueTest, EmptyBuffer) {
  std::optional<MessageStatus> status = queue_.TrySendingNextDatagram();
  EXPECT_FALSE(status.has_value());

  size_t num_messages = queue_.SendDatagrams();
  EXPECT_EQ(0u, num_messages);
}

TEST_F(QuicDatagramQueueTest, MultipleDatagrams) {
  // Note that SendMessage() is called only once here, since all the remaining
  // messages are automatically queued due to the queue being non-empty.
  EXPECT_CALL(*connection_, SendMessage(_, _, _))
      .WillOnce(Return(MESSAGE_STATUS_BLOCKED));
  queue_.SendOrQueueDatagram(CreateMemSlice("a"));
  queue_.SendOrQueueDatagram(CreateMemSlice("b"));
  queue_.SendOrQueueDatagram(CreateMemSlice("c"));
  queue_.SendOrQueueDatagram(CreateMemSlice("d"));
  queue_.SendOrQueueDatagram(CreateMemSlice("e"));

  EXPECT_CALL(*connection_, SendMessage(_, _, _))
      .Times(5)
      .WillRepeatedly(Return(MESSAGE_STATUS_SUCCESS));
  size_t num_messages = queue_.SendDatagrams();
  EXPECT_EQ(5u, num_messages);
}

TEST_F(QuicDatagramQueueTest, DefaultMaxTimeInQueue) {
  EXPECT_EQ(QuicTime::Delta::Zero(),
            connection_->sent_packet_manager().GetRttStats()->min_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(4), queue_.GetMaxTimeInQueue());

  RttStats* stats =
      const_cast<RttStats*>(connection_->sent_packet_manager().GetRttStats());
  stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(100),
                   QuicTime::Delta::Zero(), helper_.GetClock()->Now());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(125), queue_.GetMaxTimeInQueue());
}

TEST_F(QuicDatagramQueueTest, Expiry) {
  constexpr QuicTime::Delta expiry = QuicTime::Delta::FromMilliseconds(100);
  queue_.SetMaxTimeInQueue(expiry);

  EXPECT_CALL(*connection_, SendMessage(_, _, _))
      .WillOnce(Return(MESSAGE_STATUS_BLOCKED));
  queue_.SendOrQueueDatagram(CreateMemSlice("a"));
  helper_.AdvanceTime(0.6 * expiry);
  queue_.SendOrQueueDatagram(CreateMemSlice("b"));
  helper_.AdvanceTime(0.6 * expiry);
  queue_.SendOrQueueDatagram(CreateMemSlice("c"));

  std::vector<std::string> messages;
  EXPECT_CALL(*connection_, SendMessage(_, _, _))
      .WillRepeatedly([&messages](QuicMessageId /*id*/,
                                  absl::Span<quiche::QuicheMemSlice> message,
                                  bool /*flush*/) {
        messages.push_back(std::string(message[0].AsStringView()));
        return MESSAGE_STATUS_SUCCESS;
      });
  EXPECT_EQ(2u, queue_.SendDatagrams());
  EXPECT_THAT(messages, ElementsAre("b", "c"));
}

TEST_F(QuicDatagramQueueTest, ExpireAll) {
  constexpr QuicTime::Delta expiry = QuicTime::Delta::FromMilliseconds(100);
  queue_.SetMaxTimeInQueue(expiry);

  EXPECT_CALL(*connection_, SendMessage(_, _, _))
      .WillOnce(Return(MESSAGE_STATUS_BLOCKED));
  queue_.SendOrQueueDatagram(CreateMemSlice("a"));
  queue_.SendOrQueueDatagram(CreateMemSlice("b"));
  queue_.SendOrQueueDatagram(CreateMemSlice("c"));

  helper_.AdvanceTime(100 * expiry);
  EXPECT_CALL(*connection_, SendMessage(_, _, _)).Times(0);
  EXPECT_EQ(0u, queue_.SendDatagrams());
}

class QuicDatagramQueueWithObserverTest : public QuicDatagramQueueTestBase {
 public:
  QuicDatagramQueueWithObserverTest()
      : observer_(std::make_unique<QuicDatagramQueueObserver>()),
        context_(observer_->context()),
        queue_(&session_, std::move(observer_)) {}

 protected:
  // This is moved out immediately.
  std::unique_ptr<QuicDatagramQueueObserver> observer_;

  quiche::QuicheReferenceCountedPointer<QuicDatagramQueueObserver::Context>
      context_;
  QuicDatagramQueue queue_;
};

TEST_F(QuicDatagramQueueWithObserverTest, ObserveSuccessImmediately) {
  EXPECT_TRUE(context_->statuses.empty());

  EXPECT_CALL(*connection_, SendMessage(_, _, _))
      .WillOnce(Return(MESSAGE_STATUS_SUCCESS));

  EXPECT_EQ(MESSAGE_STATUS_SUCCESS,
            queue_.SendOrQueueDatagram(CreateMemSlice("a")));

  EXPECT_THAT(context_->statuses, ElementsAre(MESSAGE_STATUS_SUCCESS));
}

TEST_F(QuicDatagramQueueWithObserverTest, ObserveFailureImmediately) {
  EXPECT_TRUE(context_->statuses.empty());

  EXPECT_CALL(*connection_, SendMessage(_, _, _))
      .WillOnce(Return(MESSAGE_STATUS_TOO_LARGE));

  EXPECT_EQ(MESSAGE_STATUS_TOO_LARGE,
            queue_.SendOrQueueDatagram(CreateMemSlice("a")));

  EXPECT_THAT(context_->statuses, ElementsAre(MESSAGE_STATUS_TOO_LARGE));
}

TEST_F(QuicDatagramQueueWithObserverTest, BlockingShouldNotBeObserved) {
  EXPECT_TRUE(context_->statuses.empty());

  EXPECT_CALL(*connection_, SendMessage(_, _, _))
      .WillRepeatedly(Return(MESSAGE_STATUS_BLOCKED));

  EXPECT_EQ(MESSAGE_STATUS_BLOCKED,
            queue_.SendOrQueueDatagram(CreateMemSlice("a")));
  EXPECT_EQ(0u, queue_.SendDatagrams());

  EXPECT_TRUE(context_->statuses.empty());
}

TEST_F(QuicDatagramQueueWithObserverTest, ObserveSuccessAfterBuffering) {
  EXPECT_TRUE(context_->statuses.empty());

  EXPECT_CALL(*connection_, SendMessage(_, _, _))
      .WillOnce(Return(MESSAGE_STATUS_BLOCKED));

  EXPECT_EQ(MESSAGE_STATUS_BLOCKED,
            queue_.SendOrQueueDatagram(CreateMemSlice("a")));

  EXPECT_TRUE(context_->statuses.empty());

  EXPECT_CALL(*connection_, SendMessage(_, _, _))
      .WillOnce(Return(MESSAGE_STATUS_SUCCESS));

  EXPECT_EQ(1u, queue_.SendDatagrams());
  EXPECT_THAT(context_->statuses, ElementsAre(MESSAGE_STATUS_SUCCESS));
}

TEST_F(QuicDatagramQueueWithObserverTest, ObserveExpiry) {
  constexpr QuicTime::Delta expiry = QuicTime::Delta::FromMilliseconds(100);
  queue_.SetMaxTimeInQueue(expiry);

  EXPECT_TRUE(context_->statuses.empty());

  EXPECT_CALL(*connection_, SendMessage(_, _, _))
      .WillOnce(Return(MESSAGE_STATUS_BLOCKED));

  EXPECT_EQ(MESSAGE_STATUS_BLOCKED,
            queue_.SendOrQueueDatagram(CreateMemSlice("a")));

  EXPECT_TRUE(context_->statuses.empty());

  EXPECT_CALL(*connection_, SendMessage(_, _, _)).Times(0);
  helper_.AdvanceTime(100 * expiry);

  EXPECT_TRUE(context_->statuses.empty());

  EXPECT_EQ(0u, queue_.SendDatagrams());
  EXPECT_THAT(context_->statuses, ElementsAre(std::nullopt));
}

}  // namespace
}  // namespace test
}  // namespace quic
```