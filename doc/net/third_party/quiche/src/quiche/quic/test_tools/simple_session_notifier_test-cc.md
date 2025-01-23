Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding - The Basics:**

* **File Path:** `net/third_party/quiche/src/quiche/quic/test_tools/simple_session_notifier_test.cc` - This immediately tells me it's a *test file* within the QUIC implementation in Chromium. The `test_tools` part suggests it's testing a specific utility or component.
* **Includes:**  Looking at the `#include` statements reveals the core components being tested: `simple_session_notifier.h`, and various QUIC core and test utilities like `quic_connection_peer.h`, `quic_test_utils.h`, `simple_data_producer.h`. This confirms the focus is on testing `SimpleSessionNotifier`.
* **Namespaces:** `quic::test` is a strong indicator this is a unit test.

**2. Core Subject - `SimpleSessionNotifier`:**

* The file name and the primary include point directly to `SimpleSessionNotifier`. I need to understand its purpose. The name suggests it "notifies" about session-related events.

**3. Test Structure - Google Test:**

* The presence of `TEST_F` macros immediately identifies this as using the Google Test framework. This means each `TEST_F` function is an independent test case.
* The `SimpleSessionNotifierTest` class is a test fixture, providing setup and teardown for the individual tests.

**4. Key Components and Interactions:**

* **`MockQuicConnection`:** The tests heavily rely on a mock QUIC connection (`MockQuicConnectionWithSendStreamData`). This is crucial for isolating the `SimpleSessionNotifier` and controlling the connection's behavior. The `MOCK_METHOD` macro shows the interactions being tested (e.g., `SendStreamData`, `SendControlFrame`).
* **`SimpleSessionNotifier notifier_`:** This is the instance of the class being tested.
* **`MockQuicConnectionVisitor visitor_`:**  A mock visitor is likely used to observe events happening on the connection.
* **`MockQuicConnectionHelper helper_`, `MockAlarmFactory alarm_factory_`:** These are dependencies of `MockQuicConnection`, also mocked for isolation.

**5. Analyzing Individual Tests - Functionality Discovery:**

I go through each `TEST_F` method, understanding what aspects of `SimpleSessionNotifier` are being verified:

* **`WriteOrBufferData`:** Tests how `SimpleSessionNotifier` handles sending stream data, including buffering when the connection is blocked.
* **`WriteOrBufferRstStream`:** Checks how stream resets are handled.
* **`WriteOrBufferPing`:**  Verifies ping frame handling and interaction with connection blocking.
* **`NeuterUnencryptedData`:** Focuses on a specific security aspect – preventing unencrypted data from being sent or retransmitted. The comment about `QuicVersionUsesCryptoFrames` is important; it highlights a conditional behavior based on QUIC version.
* **`OnCanWrite`:**  Tests the `OnCanWrite` callback, which is triggered when the connection becomes writable again. This test examines retransmission of lost data and sending buffered data.
* **`OnCanWriteCryptoFrames`:** Similar to `OnCanWrite`, but specifically for QUIC versions using crypto frames. This involves the `SimpleDataProducer` for managing crypto data.
* **`RetransmitFrames`:**  Verifies the retransmission logic when frames are lost, including handling different frame types.

**6. Identifying JavaScript Relevance (and the Lack Thereof):**

* I look for concepts or functionalities that directly map to JavaScript. While QUIC is used by web browsers (which execute JavaScript), this specific test file deals with the *internal implementation* of QUIC in C++. There's no direct interaction or analogous feature in JavaScript exposed to web developers. The connection is managed at a lower level. Therefore, the relationship is indirect – JavaScript uses QUIC through the browser's networking stack.

**7. Logical Reasoning (Input/Output Examples):**

For each test, I consider the actions taken on the `notifier_` and the expected outcomes (interactions with the `connection_`). For example, in `WriteOrBufferData`:

* **Input:** Calls to `notifier_.WriteOrBufferData` with different stream IDs, data sizes, and FIN flags.
* **Expected Output:** Calls to `connection_.SendStreamData` with specific parameters, changes in `notifier_`'s internal state (`StreamBytesToSend`, `WillingToWrite`, `HasBufferedStreamData`).

**8. Common Usage Errors (Conceptual):**

Since this is a test file, the "users" are primarily the developers of the QUIC implementation. Potential errors might include:

* Incorrectly tracking buffered data.
* Failing to retransmit data after loss.
* Not handling connection blocking correctly.
* Issues related to different encryption levels.

**9. Debugging Scenario (User Operation to Code):**

This is where I connect the low-level C++ code to a high-level user action. The path is indirect:

1. **User Action (JavaScript):**  A user clicks a link or a web application initiates an XMLHttpRequest/fetch request.
2. **Browser API:** The JavaScript interacts with browser networking APIs.
3. **Network Stack:** The browser's network stack decides to use QUIC for this connection (if negotiated).
4. **QUIC Implementation:** The browser's QUIC implementation (which includes the code being tested) handles the connection setup, data transfer, and error handling.
5. **`SimpleSessionNotifier` Role:**  When the application layer (e.g., a HTTP/3 implementation built on QUIC) needs to send data, it might interact with a component like `SimpleSessionNotifier` to manage the sending process, buffering, and retransmissions.
6. **This Test File:** This file tests the correctness of `SimpleSessionNotifier`'s logic. If this test fails, it indicates a bug in the QUIC implementation that could lead to data loss, incorrect error handling, or performance issues for the user's web request.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps there's a direct JavaScript API related to QUIC.
* **Correction:**  While browser APIs expose features that *use* QUIC under the hood, the fine-grained control and the specific functionalities tested here are within the browser's internal implementation, not directly accessible to typical JavaScript.

By following this structured analysis, I can systematically understand the purpose and functionality of the given C++ test file and connect it to broader concepts like user actions and potential errors.
这是 Chromium 网络栈中 QUIC 协议测试工具的一部分，文件 `simple_session_notifier_test.cc` 主要用于测试 `SimpleSessionNotifier` 类的功能。`SimpleSessionNotifier` 的作用是作为一个简化的会话通知器，用于在测试场景中模拟 QUIC 会话的行为，尤其是在发送数据、控制帧以及处理连接状态变化时。

**功能列表:**

1. **数据发送与缓冲 (`WriteOrBufferData`):**
   - 测试 `SimpleSessionNotifier` 如何处理发送流数据的请求。
   - 验证当连接可以写入时，数据是否能立即发送。
   - 验证当连接被阻塞时，数据是否会被正确缓冲。
   - 检查已发送和待发送的字节数是否被正确跟踪。
   - 验证是否能正确判断是否有缓冲的流数据。

2. **RST_STREAM 帧发送 (`WriteOrBufferRstStream`):**
   - 测试 `SimpleSessionNotifier` 如何处理发送 RST_STREAM 帧以中止流的请求。
   - 验证在发送 RST_STREAM 帧后，是否能正确跟踪流的状态（例如，是否等待 ACK）。
   - 验证是否能正确判断是否有未确认的流数据。

3. **PING 帧发送 (`WriteOrBufferPing`):**
   - 测试 `SimpleSessionNotifier` 如何处理发送 PING 帧的请求。
   - 验证是否能在连接未阻塞时发送 PING 帧。
   - 验证在连接阻塞时，是否会避免发送 PING 帧。

4. **处理未加密数据 (`NeuterUnencryptedData`):**
   - 测试 `SimpleSessionNotifier` 如何处理在握手早期阶段发送的未加密数据。
   - 验证当需要清除未加密数据时，是否能正确地清除并停止等待其 ACK。

5. **处理连接变为可写 (`OnCanWrite`):**
   - 测试当连接从阻塞状态变为可写状态时，`SimpleSessionNotifier` 的行为。
   - 验证是否会重新发送丢失的数据。
   - 验证是否会发送之前缓冲的控制帧和流数据。

6. **处理 Crypto 帧 (`OnCanWriteCryptoFrames`):**
   - 专门针对使用 Crypto 帧的 QUIC 版本进行测试（与使用 Crypto 流的版本不同）。
   - 验证如何发送和重传 Crypto 帧。
   - 测试与 `SimpleDataProducer` 的交互，用于提供 Crypto 数据。

7. **帧的重传 (`RetransmitFrames`):**
   - 测试 `SimpleSessionNotifier` 如何处理帧的重传请求。
   - 验证是否能根据 ACK 信息正确识别需要重传的帧。
   - 验证重传时是否能正确处理不同类型的帧（流数据帧、RST_STREAM 帧）。

**与 JavaScript 功能的关系:**

这个 C++ 文件本身不直接涉及 JavaScript 代码的编写。然而，它测试的网络协议 QUIC 是现代 Web 技术的基础，并且与 JavaScript 的一些功能有间接关系：

* **Fetch API 和 WebSocket:**  当 JavaScript 使用 `fetch` API 发起网络请求，或者使用 WebSocket 建立持久连接时，底层的网络层可能会使用 QUIC 协议（如果浏览器和服务器都支持）。`SimpleSessionNotifier` 测试了 QUIC 连接中数据发送和控制的机制，这直接影响了 `fetch` 和 WebSocket 的性能和可靠性。

**举例说明:**

假设一个 JavaScript 应用使用 `fetch` API 下载一个大文件：

```javascript
fetch('https://example.com/large_file.zip')
  .then(response => response.blob())
  .then(blob => {
    // 处理下载的文件
    console.log('文件下载完成', blob);
  });
```

在这个过程中，如果底层的 HTTP/3 使用了 QUIC，那么 `SimpleSessionNotifier` 测试的功能就起着关键作用：

* **数据发送与缓冲:**  `SimpleSessionNotifier` 确保文件数据能够高效地分段发送，并在网络拥塞或连接受限时进行缓冲，避免数据丢失。
* **帧的重传:** 如果在传输过程中发生丢包，`SimpleSessionNotifier` 相关的逻辑会确保丢失的数据包被重新发送，保证文件下载的完整性。

**逻辑推理 (假设输入与输出):**

以 `WriteOrBufferData` 测试为例：

**假设输入:**

1. 调用 `notifier_.WriteOrBufferData(3, 1024, NO_FIN)`，尝试发送 1024 字节数据到流 ID 3，不带 FIN 标志。
2. 假设此时连接状态允许写入。

**预期输出:**

1. `connection_.SendStreamData(3, 1024, 0, NO_FIN)` 会被调用，模拟数据发送。
2. `notifier_.StreamBytesToSend()` 返回 0，因为数据已发送。
3. `notifier_.WillingToWrite()` 返回 false，如果连接在发送后被阻塞。

**假设输入 (连接阻塞):**

1. 再次调用 `notifier_.WriteOrBufferData(5, 512, NO_FIN)`，尝试发送 512 字节数据到流 ID 5。
2. 假设此时连接状态已被阻塞。

**预期输出:**

1. `connection_.SendStreamData` 不会被立即调用。
2. 数据会被缓冲在 `notifier_` 中。
3. `notifier_.StreamBytesToSend()` 返回 512，表示有待发送的数据。
4. `notifier_.WillingToWrite()` 返回 true，表示有缓冲的数据等待发送。
5. `notifier_.HasBufferedStreamData()` 返回 true。

**用户或编程常见的使用错误 (针对 QUIC 开发者):**

1. **未正确处理连接阻塞:** 如果开发者在实现 QUIC 功能时，没有正确使用类似 `SimpleSessionNotifier` 提供的机制来判断连接是否可写，可能会导致数据发送失败或过早尝试发送数据。
   ```c++
   // 错误示例：没有检查连接是否可写就尝试发送
   if (connection_ != nullptr) {
     connection_->SendStreamData(stream_id, data.size(), offset, has_fin);
   }
   ```
   正确的做法应该使用通知器提供的接口，或者监听连接状态变化的回调。

2. **帧的重复发送或丢失处理不当:**  如果重传逻辑不正确，可能会导致帧被重复发送，浪费带宽；或者在丢包时没有正确触发重传，导致数据丢失。`SimpleSessionNotifier` 的测试帮助验证这部分逻辑的正确性。

3. **忽略加密状态:**  在 QUIC 握手的不同阶段，加密状态是不同的。如果代码没有考虑到这一点，可能会尝试在不合适的加密级别发送数据，导致连接错误。`NeuterUnencryptedData` 相关的测试就旨在防止这类错误。

**用户操作是如何一步步的到达这里 (作为调试线索):**

虽然普通用户不会直接操作这个 C++ 文件，但当用户在 Chrome 浏览器中进行网络操作时，如果遇到了与 QUIC 协议相关的错误，调试过程可能会涉及到这些底层代码：

1. **用户在浏览器中访问一个网站 (例如，使用 HTTP/3):**
   - 用户在地址栏输入网址或点击链接。
   - 浏览器发起网络请求。

2. **浏览器网络栈尝试建立 QUIC 连接:**
   - 如果服务器支持，浏览器会尝试与服务器建立 QUIC 连接。
   - 这涉及到握手过程，包括发送和接收各种 QUIC 数据包。

3. **数据传输阶段:**
   - 一旦连接建立，浏览器和服务器之间开始通过 QUIC 流传输数据。
   - 当 JavaScript 代码（例如，通过 `fetch`）请求资源时，请求和响应数据会通过这些 QUIC 流发送。

4. **可能出现的问题:**
   - **连接失败:**  握手过程中可能因为各种原因失败（例如，加密协商失败）。
   - **数据传输错误:** 数据包可能丢失、乱序或损坏。
   - **连接中断:** 连接可能因为网络问题或其他原因中断。

5. **开发者或工程师进行调试:**
   - 如果用户报告了网络问题，Chrome 开发者或网络工程师可能会查看 Chrome 的内部日志，这些日志可能会指出 QUIC 连接的错误。
   - 为了定位问题，他们可能会深入到 QUIC 的实现代码中，包括像 `simple_session_notifier_test.cc` 这样的测试文件，以理解和验证 QUIC 各个组件的行为是否符合预期。
   - 例如，如果怀疑是数据发送或重传机制有问题，相关的测试案例就会成为分析的起点。

总而言之，`simple_session_notifier_test.cc` 是 QUIC 协议实现的关键测试文件，它确保了 QUIC 会话管理和数据传输的核心逻辑的正确性，间接地保障了用户在使用基于 QUIC 的网络服务时的体验。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/test_tools/simple_session_notifier_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/test_tools/simple_session_notifier.h"

#include <memory>
#include <string>
#include <utility>

#include "quiche/quic/core/crypto/null_encrypter.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/simple_data_producer.h"

using testing::_;
using testing::InSequence;
using testing::Return;
using testing::StrictMock;

namespace quic {
namespace test {
namespace {

class MockQuicConnectionWithSendStreamData : public MockQuicConnection {
 public:
  MockQuicConnectionWithSendStreamData(MockQuicConnectionHelper* helper,
                                       MockAlarmFactory* alarm_factory,
                                       Perspective perspective)
      : MockQuicConnection(helper, alarm_factory, perspective) {}

  MOCK_METHOD(QuicConsumedData, SendStreamData,
              (QuicStreamId id, size_t write_length, QuicStreamOffset offset,
               StreamSendingState state),
              (override));
};

class SimpleSessionNotifierTest : public QuicTest {
 public:
  SimpleSessionNotifierTest()
      : connection_(&helper_, &alarm_factory_, Perspective::IS_CLIENT),
        notifier_(&connection_) {
    connection_.set_visitor(&visitor_);
    connection_.SetSessionNotifier(&notifier_);
    EXPECT_FALSE(notifier_.WillingToWrite());
    EXPECT_EQ(0u, notifier_.StreamBytesSent());
    EXPECT_FALSE(notifier_.HasBufferedStreamData());
  }

  bool ControlFrameConsumed(const QuicFrame& frame) {
    DeleteFrame(&const_cast<QuicFrame&>(frame));
    return true;
  }

  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  MockQuicConnectionVisitor visitor_;
  StrictMock<MockQuicConnectionWithSendStreamData> connection_;
  SimpleSessionNotifier notifier_;
};

TEST_F(SimpleSessionNotifierTest, WriteOrBufferData) {
  InSequence s;
  EXPECT_CALL(connection_, SendStreamData(3, 1024, 0, NO_FIN))
      .WillOnce(Return(QuicConsumedData(1024, false)));
  notifier_.WriteOrBufferData(3, 1024, NO_FIN);
  EXPECT_EQ(0u, notifier_.StreamBytesToSend());
  EXPECT_CALL(connection_, SendStreamData(5, 512, 0, NO_FIN))
      .WillOnce(Return(QuicConsumedData(512, false)));
  notifier_.WriteOrBufferData(5, 512, NO_FIN);
  EXPECT_FALSE(notifier_.WillingToWrite());
  // Connection is blocked.
  EXPECT_CALL(connection_, SendStreamData(5, 512, 512, FIN))
      .WillOnce(Return(QuicConsumedData(256, false)));
  notifier_.WriteOrBufferData(5, 512, FIN);
  EXPECT_TRUE(notifier_.WillingToWrite());
  EXPECT_EQ(1792u, notifier_.StreamBytesSent());
  EXPECT_EQ(256u, notifier_.StreamBytesToSend());
  EXPECT_TRUE(notifier_.HasBufferedStreamData());

  // New data cannot be sent as connection is blocked.
  EXPECT_CALL(connection_, SendStreamData(7, 1024, 0, FIN)).Times(0);
  notifier_.WriteOrBufferData(7, 1024, FIN);
  EXPECT_EQ(1792u, notifier_.StreamBytesSent());
}

TEST_F(SimpleSessionNotifierTest, WriteOrBufferRstStream) {
  InSequence s;
  EXPECT_CALL(connection_, SendStreamData(5, 1024, 0, FIN))
      .WillOnce(Return(QuicConsumedData(1024, true)));
  notifier_.WriteOrBufferData(5, 1024, FIN);
  EXPECT_TRUE(notifier_.StreamIsWaitingForAcks(5));
  EXPECT_TRUE(notifier_.HasUnackedStreamData());

  // Reset stream 5 with no error.
  EXPECT_CALL(connection_, SendControlFrame(_))
      .WillRepeatedly(
          Invoke(this, &SimpleSessionNotifierTest::ControlFrameConsumed));
  notifier_.WriteOrBufferRstStream(5, QUIC_STREAM_NO_ERROR, 1024);
  // Verify stream 5 is waiting for acks.
  EXPECT_TRUE(notifier_.StreamIsWaitingForAcks(5));
  EXPECT_TRUE(notifier_.HasUnackedStreamData());

  // Reset stream 5 with error.
  notifier_.WriteOrBufferRstStream(5, QUIC_ERROR_PROCESSING_STREAM, 1024);
  EXPECT_FALSE(notifier_.StreamIsWaitingForAcks(5));
  EXPECT_FALSE(notifier_.HasUnackedStreamData());
}

TEST_F(SimpleSessionNotifierTest, WriteOrBufferPing) {
  InSequence s;
  // Write ping when connection is not write blocked.
  EXPECT_CALL(connection_, SendControlFrame(_))
      .WillRepeatedly(
          Invoke(this, &SimpleSessionNotifierTest::ControlFrameConsumed));
  notifier_.WriteOrBufferPing();
  EXPECT_EQ(0u, notifier_.StreamBytesToSend());
  EXPECT_FALSE(notifier_.WillingToWrite());

  // Write stream data and cause the connection to be write blocked.
  EXPECT_CALL(connection_, SendStreamData(3, 1024, 0, NO_FIN))
      .WillOnce(Return(QuicConsumedData(1024, false)));
  notifier_.WriteOrBufferData(3, 1024, NO_FIN);
  EXPECT_EQ(0u, notifier_.StreamBytesToSend());
  EXPECT_CALL(connection_, SendStreamData(5, 512, 0, NO_FIN))
      .WillOnce(Return(QuicConsumedData(256, false)));
  notifier_.WriteOrBufferData(5, 512, NO_FIN);
  EXPECT_TRUE(notifier_.WillingToWrite());

  // Connection is blocked.
  EXPECT_CALL(connection_, SendControlFrame(_)).Times(0);
  notifier_.WriteOrBufferPing();
}

TEST_F(SimpleSessionNotifierTest, NeuterUnencryptedData) {
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    // This test writes crypto data through crypto streams. It won't work when
    // crypto frames are used instead.
    return;
  }
  InSequence s;
  // Send crypto data [0, 1024) in ENCRYPTION_INITIAL.
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  EXPECT_CALL(connection_, SendStreamData(QuicUtils::GetCryptoStreamId(
                                              connection_.transport_version()),
                                          1024, 0, NO_FIN))
      .WillOnce(Return(QuicConsumedData(1024, false)));
  notifier_.WriteOrBufferData(
      QuicUtils::GetCryptoStreamId(connection_.transport_version()), 1024,
      NO_FIN);
  // Send crypto data [1024, 2048) in ENCRYPTION_ZERO_RTT.
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  EXPECT_CALL(connection_, SendStreamData(QuicUtils::GetCryptoStreamId(
                                              connection_.transport_version()),
                                          1024, 1024, NO_FIN))
      .WillOnce(Return(QuicConsumedData(1024, false)));
  notifier_.WriteOrBufferData(
      QuicUtils::GetCryptoStreamId(connection_.transport_version()), 1024,
      NO_FIN);
  // Ack [1024, 2048).
  QuicStreamFrame stream_frame(
      QuicUtils::GetCryptoStreamId(connection_.transport_version()), false,
      1024, 1024);
  notifier_.OnFrameAcked(QuicFrame(stream_frame), QuicTime::Delta::Zero(),
                         QuicTime::Zero());
  EXPECT_TRUE(notifier_.StreamIsWaitingForAcks(
      QuicUtils::GetCryptoStreamId(connection_.transport_version())));
  EXPECT_TRUE(notifier_.HasUnackedStreamData());

  // Neuters unencrypted data.
  notifier_.NeuterUnencryptedData();
  EXPECT_FALSE(notifier_.StreamIsWaitingForAcks(
      QuicUtils::GetCryptoStreamId(connection_.transport_version())));
  EXPECT_FALSE(notifier_.HasUnackedStreamData());
}

TEST_F(SimpleSessionNotifierTest, OnCanWrite) {
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    // This test writes crypto data through crypto streams. It won't work when
    // crypto frames are used instead.
    return;
  }
  InSequence s;
  // Send crypto data [0, 1024) in ENCRYPTION_INITIAL.
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  EXPECT_CALL(connection_, SendStreamData(QuicUtils::GetCryptoStreamId(
                                              connection_.transport_version()),
                                          1024, 0, NO_FIN))
      .WillOnce(Return(QuicConsumedData(1024, false)));
  notifier_.WriteOrBufferData(
      QuicUtils::GetCryptoStreamId(connection_.transport_version()), 1024,
      NO_FIN);

  // Send crypto data [1024, 2048) in ENCRYPTION_ZERO_RTT.
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  EXPECT_CALL(connection_, SendStreamData(QuicUtils::GetCryptoStreamId(
                                              connection_.transport_version()),
                                          1024, 1024, NO_FIN))
      .WillOnce(Return(QuicConsumedData(1024, false)));
  notifier_.WriteOrBufferData(
      QuicUtils::GetCryptoStreamId(connection_.transport_version()), 1024,
      NO_FIN);
  // Send stream 3 [0, 1024) and connection is blocked.
  EXPECT_CALL(connection_, SendStreamData(3, 1024, 0, FIN))
      .WillOnce(Return(QuicConsumedData(512, false)));
  notifier_.WriteOrBufferData(3, 1024, FIN);
  // Send stream 5 [0, 1024).
  EXPECT_CALL(connection_, SendStreamData(5, _, _, _)).Times(0);
  notifier_.WriteOrBufferData(5, 1024, NO_FIN);
  // Reset stream 5 with error.
  EXPECT_CALL(connection_, SendControlFrame(_)).Times(0);
  notifier_.WriteOrBufferRstStream(5, QUIC_ERROR_PROCESSING_STREAM, 1024);

  // Lost crypto data [500, 1500) and stream 3 [0, 512).
  QuicStreamFrame frame1(
      QuicUtils::GetCryptoStreamId(connection_.transport_version()), false, 500,
      1000);
  QuicStreamFrame frame2(3, false, 0, 512);
  notifier_.OnFrameLost(QuicFrame(frame1));
  notifier_.OnFrameLost(QuicFrame(frame2));

  // Connection becomes writable.
  // Lost crypto data gets retransmitted as [500, 1024) and [1024, 1500), as
  // they are in different encryption levels.
  EXPECT_CALL(connection_, SendStreamData(QuicUtils::GetCryptoStreamId(
                                              connection_.transport_version()),
                                          524, 500, NO_FIN))
      .WillOnce(Return(QuicConsumedData(524, false)));
  EXPECT_CALL(connection_, SendStreamData(QuicUtils::GetCryptoStreamId(
                                              connection_.transport_version()),
                                          476, 1024, NO_FIN))
      .WillOnce(Return(QuicConsumedData(476, false)));
  // Lost stream 3 data gets retransmitted.
  EXPECT_CALL(connection_, SendStreamData(3, 512, 0, NO_FIN))
      .WillOnce(Return(QuicConsumedData(512, false)));
  // Buffered control frames get sent.
  EXPECT_CALL(connection_, SendControlFrame(_))
      .WillOnce(Invoke(this, &SimpleSessionNotifierTest::ControlFrameConsumed));
  // Buffered stream 3 data [512, 1024) gets sent.
  EXPECT_CALL(connection_, SendStreamData(3, 512, 512, FIN))
      .WillOnce(Return(QuicConsumedData(512, true)));
  notifier_.OnCanWrite();
  EXPECT_FALSE(notifier_.WillingToWrite());
}

TEST_F(SimpleSessionNotifierTest, OnCanWriteCryptoFrames) {
  if (!QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    return;
  }
  SimpleDataProducer producer;
  connection_.SetDataProducer(&producer);
  InSequence s;
  // Send crypto data [0, 1024) in ENCRYPTION_INITIAL.
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  EXPECT_CALL(connection_, SendCryptoData(ENCRYPTION_INITIAL, 1024, 0))
      .WillOnce(Invoke(&connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  EXPECT_CALL(connection_, CloseConnection(QUIC_PACKET_WRITE_ERROR, _, _));
  std::string crypto_data1(1024, 'a');
  producer.SaveCryptoData(ENCRYPTION_INITIAL, 0, crypto_data1);
  std::string crypto_data2(524, 'a');
  producer.SaveCryptoData(ENCRYPTION_INITIAL, 500, crypto_data2);
  notifier_.WriteCryptoData(ENCRYPTION_INITIAL, 1024, 0);
  // Send crypto data [1024, 2048) in ENCRYPTION_ZERO_RTT.
  connection_.SetEncrypter(ENCRYPTION_ZERO_RTT, std::make_unique<NullEncrypter>(
                                                    Perspective::IS_CLIENT));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  EXPECT_CALL(connection_, SendCryptoData(ENCRYPTION_ZERO_RTT, 1024, 0))
      .WillOnce(Invoke(&connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  std::string crypto_data3(1024, 'a');
  producer.SaveCryptoData(ENCRYPTION_ZERO_RTT, 0, crypto_data3);
  notifier_.WriteCryptoData(ENCRYPTION_ZERO_RTT, 1024, 0);
  // Send stream 3 [0, 1024) and connection is blocked.
  EXPECT_CALL(connection_, SendStreamData(3, 1024, 0, FIN))
      .WillOnce(Return(QuicConsumedData(512, false)));
  notifier_.WriteOrBufferData(3, 1024, FIN);
  // Send stream 5 [0, 1024).
  EXPECT_CALL(connection_, SendStreamData(5, _, _, _)).Times(0);
  notifier_.WriteOrBufferData(5, 1024, NO_FIN);
  // Reset stream 5 with error.
  EXPECT_CALL(connection_, SendControlFrame(_)).Times(0);
  notifier_.WriteOrBufferRstStream(5, QUIC_ERROR_PROCESSING_STREAM, 1024);

  // Lost crypto data [500, 1500) and stream 3 [0, 512).
  QuicCryptoFrame crypto_frame1(ENCRYPTION_INITIAL, 500, 524);
  QuicCryptoFrame crypto_frame2(ENCRYPTION_ZERO_RTT, 0, 476);
  QuicStreamFrame stream3_frame(3, false, 0, 512);
  notifier_.OnFrameLost(QuicFrame(&crypto_frame1));
  notifier_.OnFrameLost(QuicFrame(&crypto_frame2));
  notifier_.OnFrameLost(QuicFrame(stream3_frame));

  // Connection becomes writable.
  // Lost crypto data gets retransmitted as [500, 1024) and [1024, 1500), as
  // they are in different encryption levels.
  EXPECT_CALL(connection_, SendCryptoData(ENCRYPTION_INITIAL, 524, 500))
      .WillOnce(Invoke(&connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  EXPECT_CALL(connection_, SendCryptoData(ENCRYPTION_ZERO_RTT, 476, 0))
      .WillOnce(Invoke(&connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  // Lost stream 3 data gets retransmitted.
  EXPECT_CALL(connection_, SendStreamData(3, 512, 0, NO_FIN))
      .WillOnce(Return(QuicConsumedData(512, false)));
  // Buffered control frames get sent.
  EXPECT_CALL(connection_, SendControlFrame(_))
      .WillOnce(Invoke(this, &SimpleSessionNotifierTest::ControlFrameConsumed));
  // Buffered stream 3 data [512, 1024) gets sent.
  EXPECT_CALL(connection_, SendStreamData(3, 512, 512, FIN))
      .WillOnce(Return(QuicConsumedData(512, true)));
  notifier_.OnCanWrite();
  EXPECT_FALSE(notifier_.WillingToWrite());
}

TEST_F(SimpleSessionNotifierTest, RetransmitFrames) {
  InSequence s;
  connection_.SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<NullEncrypter>(Perspective::IS_CLIENT));
  // Send stream 3 data [0, 10) and fin.
  EXPECT_CALL(connection_, SendStreamData(3, 10, 0, FIN))
      .WillOnce(Return(QuicConsumedData(10, true)));
  notifier_.WriteOrBufferData(3, 10, FIN);
  QuicStreamFrame frame1(3, true, 0, 10);
  // Send stream 5 [0, 10) and fin.
  EXPECT_CALL(connection_, SendStreamData(5, 10, 0, FIN))
      .WillOnce(Return(QuicConsumedData(10, true)));
  notifier_.WriteOrBufferData(5, 10, FIN);
  QuicStreamFrame frame2(5, true, 0, 10);
  // Reset stream 5 with no error.
  EXPECT_CALL(connection_, SendControlFrame(_))
      .WillOnce(Invoke(this, &SimpleSessionNotifierTest::ControlFrameConsumed));
  notifier_.WriteOrBufferRstStream(5, QUIC_STREAM_NO_ERROR, 10);

  // Ack stream 3 [3, 7), and stream 5 [8, 10).
  QuicStreamFrame ack_frame1(3, false, 3, 4);
  QuicStreamFrame ack_frame2(5, false, 8, 2);
  notifier_.OnFrameAcked(QuicFrame(ack_frame1), QuicTime::Delta::Zero(),
                         QuicTime::Zero());
  notifier_.OnFrameAcked(QuicFrame(ack_frame2), QuicTime::Delta::Zero(),
                         QuicTime::Zero());
  EXPECT_FALSE(notifier_.WillingToWrite());

  // Force to send.
  QuicRstStreamFrame rst_stream(1, 5, QUIC_STREAM_NO_ERROR, 10);
  QuicFrames frames;
  frames.push_back(QuicFrame(frame2));
  frames.push_back(QuicFrame(&rst_stream));
  frames.push_back(QuicFrame(frame1));
  // stream 5 data [0, 8), fin only are retransmitted.
  EXPECT_CALL(connection_, SendStreamData(5, 8, 0, NO_FIN))
      .WillOnce(Return(QuicConsumedData(8, false)));
  EXPECT_CALL(connection_, SendStreamData(5, 0, 10, FIN))
      .WillOnce(Return(QuicConsumedData(0, true)));
  // rst_stream is retransmitted.
  EXPECT_CALL(connection_, SendControlFrame(_))
      .WillOnce(Invoke(this, &SimpleSessionNotifierTest::ControlFrameConsumed));
  // stream 3 data [0, 3) is retransmitted and connection is blocked.
  EXPECT_CALL(connection_, SendStreamData(3, 3, 0, NO_FIN))
      .WillOnce(Return(QuicConsumedData(2, false)));
  notifier_.RetransmitFrames(frames, PTO_RETRANSMISSION);
  EXPECT_FALSE(notifier_.WillingToWrite());
}

}  // namespace
}  // namespace test
}  // namespace quic
```