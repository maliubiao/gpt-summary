Response:
The user wants to understand the functionality of the C++ source code file `encapsulated_web_transport_test.cc`. They are particularly interested in:

1. **Functionality:** A general overview of what the code does.
2. **JavaScript Relationship:**  If and how it relates to JavaScript.
3. **Logic Inference:** Examples of input and output if the code performs logical operations.
4. **Common Errors:**  Examples of errors users or programmers might make when using related functionalities.
5. **Debugging:** Steps a user might take in the browser that lead to this code being executed, serving as debugging clues.

**Plan:**

1. **High-level Summary:**  Start by explaining that this is a C++ unit test file for the `EncapsulatedWebTransport` class in Chromium's network stack. Its primary function is to verify the correct behavior of this class.

2. **Detailed Functionality Breakdown:**  Go through the test cases, grouping them by the aspects of `EncapsulatedWebTransport` they are testing (e.g., session setup, closing, datagrams, streams, error handling).

3. **JavaScript Connection:** Explain that while this is C++ code, WebTransport is an API accessible from JavaScript in browsers. Provide examples of JavaScript code that would utilize the underlying C++ logic being tested here.

4. **Logic Inference (with Assumptions):**  Identify test cases that involve decision-making or state transitions. For each, create a simple scenario with a specific input and the expected outcome based on the code.

5. **Common Errors:**  Infer potential user or programmer errors based on the test cases that demonstrate error handling or boundary conditions. Frame these as actions someone might take while using the WebTransport API from JavaScript.

6. **User Operations/Debugging:**  Describe the steps a user would take in a web browser to trigger the WebTransport functionality, ultimately leading to the execution of the C++ code. This will involve actions like opening a website that uses WebTransport and sending/receiving data.

**Pre-computation/Analysis of the Code:**

* **Test Fixture (`EncapsulatedWebTransportTest`):** Note the setup including mock objects (`MockSessionVisitor`, `MockWriteStream`) and the capsule parser.
* **Key Classes Under Test:**  Focus on `EncapsulatedSession` and its interaction with the visitor and underlying streams.
* **Core WebTransport Concepts:** Identify the tests related to sessions, datagrams, bidirectional/unidirectional streams, closing, resetting, and stopping.
* **Capsule Format:** Recognize that the tests manipulate and verify the structure of WebTransport capsules.
* **Error Handling:** Pay attention to tests that use `fatal_error_callback_` and assert on specific error messages.

By following this plan, I can provide a comprehensive and informative answer that addresses all aspects of the user's request.
这是一个名为 `encapsulated_web_transport_test.cc` 的 C++ 源代码文件，位于 Chromium 网络栈的 `net/third_party/quiche/src/quiche/web_transport/encapsulated/` 目录下。  它的主要功能是**对 `EncapsulatedWebTransport` 类进行单元测试**。

更具体地说，这个文件通过各种测试用例来验证 `EncapsulatedWebTransport` 类的以下方面：

**主要功能点:**

1. **会话管理 (Session Management):**
   - **会话的创建和初始化:** 测试客户端和服务端如何初始化 `EncapsulatedSession` 对象，包括设置 `SessionVisitor`，交换 HTTP 头部信息。
   - **会话状态的转换:** 验证会话在不同阶段（未初始化、等待头部、打开、关闭中、已关闭）的正确状态。
   - **会话的关闭:** 测试客户端和服务端如何发起和处理会话关闭，包括发送 `CLOSE_WEBTRANSPORT_SESSION` capsule，以及处理对方发送的关闭请求。
   - **会话的优雅关闭 (Draining):** 测试会话进入 draining 状态，并发送/接收 `DRAIN_WEBTRANSPORT_SESSION` capsule。

2. **数据报 (Datagrams):**
   - **发送数据报:** 测试 `SendOrQueueDatagram` 方法，验证数据报 capsule 的生成和发送。
   - **接收数据报:** 测试 `OnCanRead` 方法处理接收到的数据报 capsule，并通知 `SessionVisitor`。
   - **数据报大小限制:** 测试发送超过最大大小的数据报时的处理。

3. **流 (Streams):**
   - **双向流 (Bidirectional Streams) 和单向流 (Unidirectional Streams) 的创建和接受:**  模拟接收到创建新流的 capsule，并通知 `SessionVisitor`。
   - **流数据的发送和接收:** 测试通过 `WT_STREAM` 和 `WT_STREAM_WITH_FIN` capsule 发送和接收流数据。
   - **流的 FIN (结束标志) 处理:**  测试发送和接收 FIN 标志，表示流的结束。
   - **流的复位 (Reset):** 测试发送和接收 `WT_RESET_STREAM` capsule，表示流被异常终止。
   - **停止发送 (Stop Sending):** 测试发送和接收 `WT_STOP_SENDING` capsule，表示不再接收来自对端的流数据。
   - **流的缓存 (Buffering):** 测试当底层写入受阻时，流数据的缓存行为。
   - **流的垃圾回收 (Garbage Collection):** 测试当流不再需要时，如何被清理。

4. **底层传输交互:**
   - **写入 Capsule:** 通过 mock `MockWriteStream` 模拟向底层传输写入 capsule 的过程，并验证生成的 capsule 内容。
   - **读取 Capsule:** 通过 mock `ReadStreamFromString` 模拟从底层传输读取 capsule 的过程，并触发 `EncapsulatedSession` 的处理。
   - **处理底层传输的 FIN:** 测试接收到底层传输的 FIN 时的会话行为。

5. **错误处理:**
   - **处理 malformed 数据:** 测试接收到格式错误的数据时的错误处理逻辑。
   - **处理写入错误:** 测试在写入底层传输时发生错误时的处理逻辑。
   - **处理重复的 FIN:** 测试在已经收到 FIN 的流上再次收到 FIN 时的处理。

**与 JavaScript 的关系及举例说明:**

`EncapsulatedWebTransport` 是 WebTransport API 在 Chromium 中的底层实现之一。 JavaScript 代码通过浏览器提供的 WebTransport API 与服务端建立连接并进行数据传输，最终会调用到这里 C++ 代码实现的逻辑。

**举例说明:**

假设你在一个网页的 JavaScript 中使用了 WebTransport API：

```javascript
const wt = new WebTransport("https://example.com/webtransport");

wt.ready.then(() => {
  console.log("WebTransport connection ready");

  // 发送数据报
  const encoder = new TextEncoder();
  const datagram = encoder.encode("Hello from JavaScript!");
  wt.sendDatagram(datagram);

  // 打开一个双向流
  const bidiStream = wt.createBidirectionalStream();
  const writer = bidiStream.writable.getWriter();
  writer.write(encoder.encode("Data from bidi stream"));
  writer.close();

  // 监听接收到的数据报
  wt.datagrams.readable.getReader().read().then(({ value, done }) => {
    if (!done) {
      const decoder = new TextDecoder();
      console.log("Received datagram:", decoder.decode(value));
    }
  });

  // 监听接收到的双向流
  wt.incomingBidirectionalStreams.getReader().read().then(({ value, done }) => {
    if (!done) {
      const reader = value.readable.getReader();
      reader.read().then(({ value, done }) => {
        if (!done) {
          console.log("Received data on bidi stream:", decoder.decode(value));
        }
      });
    }
  });

  // 关闭连接
  wt.close();
});

wt.catch(error => {
  console.error("WebTransport connection failed:", error);
});
```

当这段 JavaScript 代码执行时，浏览器底层会调用到 `EncapsulatedWebTransport` 类及其相关方法来处理这些操作，例如：

- `wt.sendDatagram(datagram)`  会触发 `EncapsulatedSession::SendOrQueueDatagram`，最终导致生成并发送一个 `DATAGRAM` capsule。相关的测试用例是 `SendDatagrams`。
- `wt.createBidirectionalStream()` 会触发 `EncapsulatedSession::OpenOutgoingBidirectionalStream`，创建一个新的流并分配 ID。相关的逻辑在测试用例中通过模拟接收到创建流的 capsule 来进行测试。
- 接收到服务端发送的数据报或流数据时，底层会解析 capsule，并调用 `EncapsulatedSession::OnCanRead`，然后通知 `SessionVisitor`。相关的测试用例是 `ReceiveDatagrams` 和 `SimpleRead` 等。
- `wt.close()` 会触发 `EncapsulatedSession::CloseSession`，生成并发送一个 `CLOSE_WEBTRANSPORT_SESSION` capsule。相关的测试用例是 `CloseSession`。

**逻辑推理的假设输入与输出举例:**

**假设输入:** 客户端发送一个包含流数据的 `WT_STREAM` capsule，流 ID 为 1，数据为 "hello"。

**预期输出:**
- `EncapsulatedSession::OnCanRead` 被调用，解析 capsule。
- `EncapsulatedSession` 内部根据流 ID 找到对应的流对象（如果存在），或者创建一个新的流。
- `SessionVisitor::OnIncomingBidirectionalStreamAvailable` (如果是一个新的双向流) 或 `SessionVisitor` 中该流对应的 visitor 的 `OnCanRead` 方法被调用。
- 接收到的数据 "hello" 被添加到流的接收缓冲区中。
- 如果 JavaScript 代码正在监听该流，它会接收到 "hello" 数据。

**涉及用户或者编程常见的使用错误举例说明:**

1. **尝试在会话未就绪前发送数据报:**
   - **用户操作:** JavaScript 代码在 `wt.ready` Promise resolve 之前就调用 `wt.sendDatagram()`。
   - **C++ 层面:** `EncapsulatedSession::SendOrQueueDatagram` 在会话状态不正确时可能会将数据报排队或直接丢弃，测试用例 `SendDatagramsBeforeInitialization` 验证了这种情况。

2. **发送超过最大大小的数据报:**
   - **用户操作:** JavaScript 代码尝试发送一个非常大的 ArrayBuffer 通过 `wt.sendDatagram()`。
   - **C++ 层面:** `EncapsulatedSession::SendOrQueueDatagram` 会检查数据报大小，如果超过限制会返回错误码 `DatagramStatusCode::kTooBig`，测试用例 `SendDatagramsTooBig` 模拟了这种情况。

3. **在流的另一端已经关闭后继续向该流写入数据:**
   - **用户操作:** JavaScript 代码尝试向一个已经被对端发送了 FIN 的流的 `WritableStream` 写入数据。
   - **C++ 层面:**  `EncapsulatedSession` 会检测到这种情况，并可能触发错误处理或者直接忽略写入操作。虽然这个测试文件没有直接测试这个场景，但相关的流状态管理和 FIN 处理的测试用例 (如 `FinRead`) 为理解这个行为提供了基础。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设开发者在调试一个 WebTransport 连接问题，并且怀疑 `EncapsulatedWebTransport` 的行为异常。以下是可能的操作步骤以及如何到达这个 C++ 代码：

1. **用户在浏览器中访问一个使用了 WebTransport 的网页。** 网页的 JavaScript 代码会尝试建立 WebTransport 连接。
2. **JavaScript 代码创建 `WebTransport` 对象，指定服务端 URL。**  这会触发浏览器底层的网络栈开始握手过程。
3. **浏览器底层与服务端建立连接，并完成 HTTP/3 握手。**
4. **在 HTTP/3 连接建立后，WebTransport 协商开始。**  这涉及到发送和接收特定的 HTTP 头部信息。
5. **一旦 WebTransport 会话建立，JavaScript 代码可以开始发送和接收数据报或创建流。**
6. **当 JavaScript 代码调用 `wt.sendDatagram()` 或向流的 `WritableStream` 写入数据时，** 数据会被编码成 WebTransport capsule。
7. **这些 capsule 会被传递到 `EncapsulatedWebTransport` 类的实例进行处理。** 例如，`EncapsulatedSession::SendOrQueueDatagram` 会被调用来处理发送数据报的请求。
8. **当服务端发送数据时，** 底层网络栈接收到数据，并将其解析成 WebTransport capsule。
9. **接收到的 capsule 会被传递到 `EncapsulatedWebTransport::OnCanRead()` 方法进行处理。** 这个方法会根据 capsule 类型调用相应的处理逻辑，例如创建新的流，或者将数据添加到现有流的接收缓冲区。

**调试线索:**

- 如果开发者在浏览器的开发者工具的网络面板中看到 WebTransport 连接建立失败或者数据传输异常，他们可能会怀疑 `EncapsulatedWebTransport` 的初始化或数据处理逻辑有问题。
- 如果开发者观察到发送的数据没有被正确地封装成 capsule，或者接收到的 capsule 没有被正确地解析，他们可能会查看 `EncapsulatedWebTransport::Writev` 的调用或 capsule 解析相关的代码。
- 如果涉及到流的管理问题（例如，流没有被正确地创建、关闭或复位），开发者可能会查看 `EncapsulatedSession` 中管理流的逻辑，以及 `WT_RESET_STREAM` 和 `WT_STOP_SENDING` capsule 的处理。
- 通过查看 Chromium 的网络日志 (net-internals)，开发者可以获取更详细的 WebTransport 事件信息，例如 capsule 的发送和接收，以及连接的状态转换，这可以帮助他们定位问题并最终追踪到 `encapsulated_web_transport_test.cc` 中相关的测试用例，以理解预期的行为。

总而言之，`encapsulated_web_transport_test.cc` 是确保 Chromium 中 WebTransport 功能正确性的关键组成部分，它通过各种测试用例覆盖了 `EncapsulatedWebTransport` 类的核心功能和边界情况。理解这个文件的内容有助于理解 WebTransport API 在浏览器底层的实现方式。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/web_transport/encapsulated/encapsulated_web_transport_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/web_transport/encapsulated/encapsulated_web_transport.h"

#include <array>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/common/capsule.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_stream.h"
#include "quiche/common/simple_buffer_allocator.h"
#include "quiche/common/test_tools/mock_streams.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"
#include "quiche/web_transport/web_transport.h"

namespace webtransport::test {
namespace {

using ::quiche::Capsule;
using ::quiche::CapsuleType;
using ::quiche::test::StatusIs;
using ::testing::_;
using ::testing::ElementsAre;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Return;
using ::testing::StrEq;

class EncapsulatedWebTransportTest : public quiche::test::QuicheTest,
                                     public quiche::CapsuleParser::Visitor {
 public:
  EncapsulatedWebTransportTest() : parser_(this), reader_(&read_buffer_) {
    ON_CALL(fatal_error_callback_, Call(_))
        .WillByDefault([](absl::string_view error) {
          ADD_FAILURE() << "Fatal session error: " << error;
        });
    ON_CALL(writer_, Writev(_, _))
        .WillByDefault([&](absl::Span<const absl::string_view> data,
                           const quiche::StreamWriteOptions& options) {
          for (absl::string_view fragment : data) {
            parser_.IngestCapsuleFragment(fragment);
          }
          writer_.ProcessOptions(options);
          return absl::OkStatus();
        });
  }

  std::unique_ptr<EncapsulatedSession> CreateTransport(
      Perspective perspective) {
    auto transport = std::make_unique<EncapsulatedSession>(
        perspective, fatal_error_callback_.AsStdFunction());
    session_ = transport.get();
    return transport;
  }

  std::unique_ptr<SessionVisitor> CreateAndStoreVisitor() {
    auto visitor = std::make_unique<testing::StrictMock<MockSessionVisitor>>();
    visitor_ = visitor.get();
    return visitor;
  }

  MOCK_METHOD(bool, OnCapsule, (const Capsule&), (override));

  void OnCapsuleParseFailure(absl::string_view error_message) override {
    ADD_FAILURE() << "Written an invalid capsule: " << error_message;
  }

  void ProcessIncomingCapsule(const Capsule& capsule) {
    quiche::QuicheBuffer buffer =
        quiche::SerializeCapsule(capsule, quiche::SimpleBufferAllocator::Get());
    read_buffer_.append(buffer.data(), buffer.size());
    session_->OnCanRead();
  }

  template <typename CapsuleType>
  void ProcessIncomingCapsule(const CapsuleType& capsule) {
    quiche::QuicheBuffer buffer = quiche::SerializeCapsule(
        quiche::Capsule(capsule), quiche::SimpleBufferAllocator::Get());
    read_buffer_.append(buffer.data(), buffer.size());
    session_->OnCanRead();
  }

  void DefaultHandshakeForClient(EncapsulatedSession& session) {
    quiche::HttpHeaderBlock outgoing_headers, incoming_headers;
    session.InitializeClient(CreateAndStoreVisitor(), outgoing_headers,
                             &writer_, &reader_);
    EXPECT_CALL(*visitor_, OnSessionReady());
    session.ProcessIncomingServerHeaders(incoming_headers);
  }

 protected:
  quiche::CapsuleParser parser_;
  quiche::test::MockWriteStream writer_;
  std::string read_buffer_;
  quiche::test::ReadStreamFromString reader_;
  MockSessionVisitor* visitor_ = nullptr;
  EncapsulatedSession* session_ = nullptr;
  testing::MockFunction<void(absl::string_view)> fatal_error_callback_;
};

TEST_F(EncapsulatedWebTransportTest, IsOpenedBy) {
  EXPECT_EQ(IsIdOpenedBy(0x00, Perspective::kClient), true);
  EXPECT_EQ(IsIdOpenedBy(0x01, Perspective::kClient), false);
  EXPECT_EQ(IsIdOpenedBy(0x02, Perspective::kClient), true);
  EXPECT_EQ(IsIdOpenedBy(0x03, Perspective::kClient), false);

  EXPECT_EQ(IsIdOpenedBy(0x00, Perspective::kServer), false);
  EXPECT_EQ(IsIdOpenedBy(0x01, Perspective::kServer), true);
  EXPECT_EQ(IsIdOpenedBy(0x02, Perspective::kServer), false);
  EXPECT_EQ(IsIdOpenedBy(0x03, Perspective::kServer), true);
}

TEST_F(EncapsulatedWebTransportTest, SetupClientSession) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  quiche::HttpHeaderBlock outgoing_headers, incoming_headers;
  EXPECT_EQ(session->state(), EncapsulatedSession::kUninitialized);
  session->InitializeClient(CreateAndStoreVisitor(), outgoing_headers, &writer_,
                            &reader_);
  EXPECT_EQ(session->state(), EncapsulatedSession::kWaitingForHeaders);
  EXPECT_CALL(*visitor_, OnSessionReady());
  session->ProcessIncomingServerHeaders(incoming_headers);
  EXPECT_EQ(session->state(), EncapsulatedSession::kSessionOpen);
}

TEST_F(EncapsulatedWebTransportTest, SetupServerSession) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kServer);
  quiche::HttpHeaderBlock outgoing_headers, incoming_headers;
  EXPECT_EQ(session->state(), EncapsulatedSession::kUninitialized);
  std::unique_ptr<SessionVisitor> visitor = CreateAndStoreVisitor();
  EXPECT_CALL(*visitor_, OnSessionReady());
  session->InitializeServer(std::move(visitor), outgoing_headers,
                            incoming_headers, &writer_, &reader_);
  EXPECT_EQ(session->state(), EncapsulatedSession::kSessionOpen);
}

TEST_F(EncapsulatedWebTransportTest, CloseSession) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*this, OnCapsule(_)).WillOnce([](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), CapsuleType::CLOSE_WEBTRANSPORT_SESSION);
    EXPECT_EQ(capsule.close_web_transport_session_capsule().error_code, 0x1234);
    EXPECT_EQ(capsule.close_web_transport_session_capsule().error_message,
              "test close");
    return true;
  });
  EXPECT_EQ(session->state(), EncapsulatedSession::kSessionOpen);
  EXPECT_CALL(*visitor_, OnSessionClosed(0x1234, StrEq("test close")));
  session->CloseSession(0x1234, "test close");
  EXPECT_EQ(session->state(), EncapsulatedSession::kSessionClosed);
  EXPECT_TRUE(writer_.fin_written());

  EXPECT_CALL(fatal_error_callback_, Call(_))
      .WillOnce([](absl::string_view error) {
        EXPECT_THAT(error, HasSubstr("close a session that is already closed"));
      });
  session->CloseSession(0x1234, "test close");
}

TEST_F(EncapsulatedWebTransportTest, CloseSessionWriteBlocked) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(writer_, CanWrite()).WillOnce(Return(false));
  EXPECT_CALL(*this, OnCapsule(_)).Times(0);
  EXPECT_EQ(session->state(), EncapsulatedSession::kSessionOpen);
  session->CloseSession(0x1234, "test close");
  EXPECT_EQ(session->state(), EncapsulatedSession::kSessionClosing);

  EXPECT_CALL(*this, OnCapsule(_)).WillOnce([](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), CapsuleType::CLOSE_WEBTRANSPORT_SESSION);
    EXPECT_EQ(capsule.close_web_transport_session_capsule().error_code, 0x1234);
    EXPECT_EQ(capsule.close_web_transport_session_capsule().error_message,
              "test close");
    return true;
  });
  EXPECT_CALL(writer_, CanWrite()).WillOnce(Return(true));
  EXPECT_CALL(*visitor_, OnSessionClosed(0x1234, StrEq("test close")));
  session->OnCanWrite();
  EXPECT_EQ(session->state(), EncapsulatedSession::kSessionClosed);
  EXPECT_TRUE(writer_.fin_written());
}

TEST_F(EncapsulatedWebTransportTest, ReceiveFin) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);

  EXPECT_CALL(*visitor_, OnSessionClosed(0, IsEmpty()));
  reader_.set_fin();
  session->OnCanRead();
  EXPECT_TRUE(writer_.fin_written());
}

TEST_F(EncapsulatedWebTransportTest, ReceiveCloseSession) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);

  EXPECT_CALL(*visitor_, OnSessionClosed(0x1234, StrEq("test")));
  ProcessIncomingCapsule(Capsule::CloseWebTransportSession(0x1234, "test"));
  EXPECT_TRUE(writer_.fin_written());
  reader_.set_fin();
  session->OnCanRead();
}

TEST_F(EncapsulatedWebTransportTest, ReceiveMalformedData) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);

  EXPECT_CALL(fatal_error_callback_, Call(HasSubstr("too much capsule data")))
      .WillOnce([] {});
  read_buffer_ = std::string(2 * 1024 * 1024, '\xff');
  session->OnCanRead();
}

TEST_F(EncapsulatedWebTransportTest, SendDatagrams) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*this, OnCapsule(_)).WillOnce([](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), quiche::CapsuleType::DATAGRAM);
    EXPECT_EQ(capsule.datagram_capsule().http_datagram_payload, "test");
    return true;
  });
  DatagramStatus status = session->SendOrQueueDatagram("test");
  EXPECT_EQ(status.code, DatagramStatusCode::kSuccess);
}

TEST_F(EncapsulatedWebTransportTest, SendDatagramsEarly) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  quiche::HttpHeaderBlock outgoing_headers;
  session->InitializeClient(CreateAndStoreVisitor(), outgoing_headers, &writer_,
                            &reader_);
  EXPECT_CALL(*this, OnCapsule(_)).WillOnce([](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), quiche::CapsuleType::DATAGRAM);
    EXPECT_EQ(capsule.datagram_capsule().http_datagram_payload, "test");
    return true;
  });
  ASSERT_EQ(session->state(), EncapsulatedSession::kWaitingForHeaders);
  session->SendOrQueueDatagram("test");
}

TEST_F(EncapsulatedWebTransportTest, SendDatagramsBeforeInitialization) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  quiche::HttpHeaderBlock outgoing_headers;
  EXPECT_CALL(*this, OnCapsule(_)).Times(0);
  ASSERT_EQ(session->state(), EncapsulatedSession::kUninitialized);
  session->SendOrQueueDatagram("test");

  EXPECT_CALL(*this, OnCapsule(_)).WillOnce([](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), CapsuleType::DATAGRAM);
    EXPECT_EQ(capsule.datagram_capsule().http_datagram_payload, "test");
    return true;
  });
  DefaultHandshakeForClient(*session);
}

TEST_F(EncapsulatedWebTransportTest, SendDatagramsTooBig) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*this, OnCapsule(_)).Times(0);
  std::string long_string(16 * 1024, 'a');
  DatagramStatus status = session->SendOrQueueDatagram(long_string);
  EXPECT_EQ(status.code, DatagramStatusCode::kTooBig);
}

TEST_F(EncapsulatedWebTransportTest, ReceiveDatagrams) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*visitor_, OnDatagramReceived(_))
      .WillOnce([](absl::string_view data) { EXPECT_EQ(data, "test"); });
  ProcessIncomingCapsule(Capsule::Datagram("test"));
}

TEST_F(EncapsulatedWebTransportTest, SendDraining) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*this, OnCapsule(_)).WillOnce([](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), CapsuleType::DRAIN_WEBTRANSPORT_SESSION);
    return true;
  });
  session->NotifySessionDraining();
}

TEST_F(EncapsulatedWebTransportTest, ReceiveDraining) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  testing::MockFunction<void()> callback;
  session->SetOnDraining(callback.AsStdFunction());
  EXPECT_CALL(callback, Call());
  ProcessIncomingCapsule(Capsule(quiche::DrainWebTransportSessionCapsule()));
}

TEST_F(EncapsulatedWebTransportTest, WriteErrorDatagram) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(writer_, Writev(_, _))
      .WillOnce(Return(absl::InternalError("Test write error")));
  EXPECT_CALL(fatal_error_callback_, Call(_))
      .WillOnce([](absl::string_view error) {
        EXPECT_THAT(error, HasSubstr("Test write error"));
      });
  DatagramStatus status = session->SendOrQueueDatagram("test");
  EXPECT_EQ(status.code, DatagramStatusCode::kInternalError);
}

TEST_F(EncapsulatedWebTransportTest, WriteErrorControlCapsule) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(writer_, Writev(_, _))
      .WillOnce(Return(absl::InternalError("Test write error")));
  EXPECT_CALL(fatal_error_callback_, Call(_))
      .WillOnce([](absl::string_view error) {
        EXPECT_THAT(error, HasSubstr("Test write error"));
      });
  session->NotifySessionDraining();
}

TEST_F(EncapsulatedWebTransportTest, SimpleRead) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  bool stream_received = false;
  EXPECT_CALL(*visitor_, OnIncomingBidirectionalStreamAvailable())
      .WillOnce([&] { stream_received = true; });
  std::string data = "test";
  ProcessIncomingCapsule(quiche::WebTransportStreamDataCapsule{1, data, false});
  // Make sure data gets copied.
  data[0] = 'q';
  EXPECT_TRUE(stream_received);
  Stream* stream = session->AcceptIncomingBidirectionalStream();
  ASSERT_TRUE(stream != nullptr);
  EXPECT_EQ(stream->GetStreamId(), 1u);
  EXPECT_EQ(stream->visitor(), nullptr);
  EXPECT_EQ(stream->ReadableBytes(), 4u);

  quiche::ReadStream::PeekResult peek = stream->PeekNextReadableRegion();
  EXPECT_EQ(peek.peeked_data, "test");
  EXPECT_FALSE(peek.fin_next);
  EXPECT_FALSE(peek.all_data_received);

  std::string buffer;
  quiche::ReadStream::ReadResult read = stream->Read(&buffer);
  EXPECT_EQ(read.bytes_read, 4);
  EXPECT_FALSE(read.fin);
  EXPECT_EQ(buffer, "test");
  EXPECT_EQ(stream->ReadableBytes(), 0u);
}

class MockStreamVisitorWithDestructor : public MockStreamVisitor {
 public:
  ~MockStreamVisitorWithDestructor() { OnDelete(); }

  MOCK_METHOD(void, OnDelete, (), ());
};

MockStreamVisitorWithDestructor* SetupVisitor(Stream& stream) {
  auto visitor = std::make_unique<MockStreamVisitorWithDestructor>();
  MockStreamVisitorWithDestructor* result = visitor.get();
  stream.SetVisitor(std::move(visitor));
  return result;
}

TEST_F(EncapsulatedWebTransportTest, ImmediateRead) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*visitor_, OnIncomingBidirectionalStreamAvailable());
  ProcessIncomingCapsule(
      quiche::WebTransportStreamDataCapsule{1, "abcd", false});
  Stream* stream = session->AcceptIncomingBidirectionalStream();
  ASSERT_TRUE(stream != nullptr);
  EXPECT_EQ(stream->ReadableBytes(), 4u);

  MockStreamVisitor* visitor = SetupVisitor(*stream);
  EXPECT_CALL(*visitor, OnCanRead()).WillOnce([&] {
    std::string output;
    (void)stream->Read(&output);
    EXPECT_EQ(output, "abcdef");
  });
  ProcessIncomingCapsule(quiche::WebTransportStreamDataCapsule{1, "ef", false});
}

TEST_F(EncapsulatedWebTransportTest, FinPeek) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*visitor_, OnIncomingBidirectionalStreamAvailable());
  ProcessIncomingCapsule(
      quiche::WebTransportStreamDataCapsule{1, "abcd", false});
  Stream* stream = session->AcceptIncomingBidirectionalStream();
  ASSERT_TRUE(stream != nullptr);
  EXPECT_EQ(stream->ReadableBytes(), 4u);

  ProcessIncomingCapsule(quiche::WebTransportStreamDataCapsule{1, "ef", true});

  quiche::ReadStream::PeekResult peek = stream->PeekNextReadableRegion();
  EXPECT_EQ(peek.peeked_data, "abcd");
  EXPECT_FALSE(peek.fin_next);
  EXPECT_TRUE(peek.all_data_received);

  EXPECT_FALSE(stream->SkipBytes(2));
  peek = stream->PeekNextReadableRegion();
  EXPECT_FALSE(peek.fin_next);
  EXPECT_TRUE(peek.all_data_received);

  EXPECT_FALSE(stream->SkipBytes(2));
  peek = stream->PeekNextReadableRegion();
  EXPECT_EQ(peek.peeked_data, "ef");
  EXPECT_TRUE(peek.fin_next);
  EXPECT_TRUE(peek.all_data_received);

  EXPECT_TRUE(stream->SkipBytes(2));
}

TEST_F(EncapsulatedWebTransportTest, FinRead) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*visitor_, OnIncomingBidirectionalStreamAvailable());
  ProcessIncomingCapsule(
      quiche::WebTransportStreamDataCapsule{1, "abcdef", true});
  Stream* stream = session->AcceptIncomingBidirectionalStream();
  ASSERT_TRUE(stream != nullptr);
  EXPECT_EQ(stream->ReadableBytes(), 6u);

  std::array<char, 3> buffer;
  quiche::ReadStream::ReadResult read = stream->Read(absl::MakeSpan(buffer));
  EXPECT_THAT(buffer, ElementsAre('a', 'b', 'c'));
  EXPECT_EQ(read.bytes_read, 3);
  EXPECT_FALSE(read.fin);

  read = stream->Read(absl::MakeSpan(buffer));
  EXPECT_THAT(buffer, ElementsAre('d', 'e', 'f'));
  EXPECT_EQ(read.bytes_read, 3);
  EXPECT_TRUE(read.fin);
}

TEST_F(EncapsulatedWebTransportTest, LargeRead) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*visitor_, OnIncomingBidirectionalStreamAvailable());
  ProcessIncomingCapsule(quiche::WebTransportStreamDataCapsule{
      1, std::string(64 * 1024, 'a'), true});
  Stream* stream = session->AcceptIncomingBidirectionalStream();
  ASSERT_TRUE(stream != nullptr);
  EXPECT_EQ(stream->ReadableBytes(), 65536u);

  for (int i = 0; i < 64; i++) {
    std::array<char, 1024> buffer;
    quiche::ReadStream::ReadResult read = stream->Read(absl::MakeSpan(buffer));
    EXPECT_EQ(read.bytes_read, 1024);
    EXPECT_EQ(read.fin, i == 63);
  }
}

TEST_F(EncapsulatedWebTransportTest, DoubleFinReceived) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*visitor_, OnIncomingBidirectionalStreamAvailable());
  ProcessIncomingCapsule(quiche::WebTransportStreamDataCapsule{1, "abc", true});
  Stream* stream = session->AcceptIncomingBidirectionalStream();
  ASSERT_TRUE(stream != nullptr);

  EXPECT_CALL(fatal_error_callback_, Call(_))
      .WillOnce([](absl::string_view error) {
        EXPECT_THAT(error, HasSubstr("has already received a FIN"));
      });
  ProcessIncomingCapsule(quiche::WebTransportStreamDataCapsule{1, "def", true});
}

TEST_F(EncapsulatedWebTransportTest, CanWriteUnidiBidi) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*visitor_, OnIncomingBidirectionalStreamAvailable());
  EXPECT_CALL(*visitor_, OnIncomingUnidirectionalStreamAvailable());
  ProcessIncomingCapsule(quiche::WebTransportStreamDataCapsule{1, "abc", true});
  ProcessIncomingCapsule(quiche::WebTransportStreamDataCapsule{3, "abc", true});

  Stream* stream = session->AcceptIncomingBidirectionalStream();
  ASSERT_TRUE(stream != nullptr);
  EXPECT_TRUE(stream->CanWrite());

  stream = session->AcceptIncomingUnidirectionalStream();
  ASSERT_TRUE(stream != nullptr);
  EXPECT_FALSE(stream->CanWrite());

  stream = session->OpenOutgoingBidirectionalStream();
  ASSERT_TRUE(stream != nullptr);
  EXPECT_TRUE(stream->CanWrite());

  stream = session->OpenOutgoingUnidirectionalStream();
  ASSERT_TRUE(stream != nullptr);
  EXPECT_TRUE(stream->CanWrite());
}

TEST_F(EncapsulatedWebTransportTest, ReadOnlyGarbageCollection) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*visitor_, OnIncomingUnidirectionalStreamAvailable());
  ProcessIncomingCapsule(quiche::WebTransportStreamDataCapsule{3, "abc", true});

  Stream* stream = session->AcceptIncomingUnidirectionalStream();
  ASSERT_TRUE(stream != nullptr);
  EXPECT_TRUE(stream->SkipBytes(3));

  MockStreamVisitorWithDestructor* visitor = SetupVisitor(*stream);
  bool deleted = false;
  EXPECT_CALL(*visitor, OnDelete()).WillOnce([&] { deleted = true; });
  session->GarbageCollectStreams();
  EXPECT_TRUE(deleted);
}

TEST_F(EncapsulatedWebTransportTest, WriteOnlyGarbageCollection) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);

  Stream* stream = session->OpenOutgoingUnidirectionalStream();
  ASSERT_TRUE(stream != nullptr);

  MockStreamVisitorWithDestructor* visitor = SetupVisitor(*stream);
  bool deleted = false;
  EXPECT_CALL(*visitor, OnDelete()).WillOnce([&] { deleted = true; });
  EXPECT_CALL(*this, OnCapsule(_)).WillOnce(Return(true));

  quiche::StreamWriteOptions options;
  options.set_send_fin(true);
  EXPECT_THAT(stream->Writev(absl::Span<const absl::string_view>(), options),
              StatusIs(absl::StatusCode::kOk));
  session->GarbageCollectStreams();
  EXPECT_TRUE(deleted);
}

TEST_F(EncapsulatedWebTransportTest, SimpleWrite) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*visitor_, OnIncomingBidirectionalStreamAvailable());
  ProcessIncomingCapsule(quiche::WebTransportStreamDataCapsule{1, "", true});
  Stream* stream = session->AcceptIncomingBidirectionalStream();
  ASSERT_TRUE(stream != nullptr);

  EXPECT_CALL(*this, OnCapsule(_)).WillOnce([](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), CapsuleType::WT_STREAM);
    EXPECT_EQ(capsule.web_transport_stream_data().stream_id, 1u);
    EXPECT_EQ(capsule.web_transport_stream_data().fin, false);
    EXPECT_EQ(capsule.web_transport_stream_data().data, "test");
    return true;
  });
  absl::Status status = quiche::WriteIntoStream(*stream, "test");
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kOk));
}

TEST_F(EncapsulatedWebTransportTest, WriteWithFin) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  Stream* stream = session->OpenOutgoingUnidirectionalStream();
  ASSERT_TRUE(stream != nullptr);

  EXPECT_CALL(*this, OnCapsule(_)).WillOnce([](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), CapsuleType::WT_STREAM_WITH_FIN);
    EXPECT_EQ(capsule.web_transport_stream_data().stream_id, 2u);
    EXPECT_EQ(capsule.web_transport_stream_data().fin, true);
    EXPECT_EQ(capsule.web_transport_stream_data().data, "test");
    return true;
  });
  quiche::StreamWriteOptions options;
  options.set_send_fin(true);
  EXPECT_TRUE(stream->CanWrite());
  absl::Status status = quiche::WriteIntoStream(*stream, "test", options);
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kOk));
  EXPECT_FALSE(stream->CanWrite());
}

TEST_F(EncapsulatedWebTransportTest, FinOnlyWrite) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  Stream* stream = session->OpenOutgoingUnidirectionalStream();
  ASSERT_TRUE(stream != nullptr);

  EXPECT_CALL(*this, OnCapsule(_)).WillOnce([](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), CapsuleType::WT_STREAM_WITH_FIN);
    EXPECT_EQ(capsule.web_transport_stream_data().stream_id, 2u);
    EXPECT_EQ(capsule.web_transport_stream_data().fin, true);
    EXPECT_EQ(capsule.web_transport_stream_data().data, "");
    return true;
  });
  quiche::StreamWriteOptions options;
  options.set_send_fin(true);
  EXPECT_TRUE(stream->CanWrite());
  absl::Status status =
      stream->Writev(absl::Span<const absl::string_view>(), options);
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kOk));
  EXPECT_FALSE(stream->CanWrite());
}

TEST_F(EncapsulatedWebTransportTest, BufferedWriteThenUnbuffer) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  Stream* stream = session->OpenOutgoingUnidirectionalStream();
  ASSERT_TRUE(stream != nullptr);

  EXPECT_CALL(writer_, CanWrite()).WillOnce(Return(false));
  absl::Status status = quiche::WriteIntoStream(*stream, "abc");
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kOk));

  // While the stream cannot be written right now, we should be still able to
  // buffer data into it.
  EXPECT_TRUE(stream->CanWrite());
  EXPECT_CALL(writer_, CanWrite()).WillRepeatedly(Return(true));
  status = quiche::WriteIntoStream(*stream, "def");
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kOk));

  EXPECT_CALL(*this, OnCapsule(_)).WillOnce([](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), CapsuleType::WT_STREAM);
    EXPECT_EQ(capsule.web_transport_stream_data().stream_id, 2u);
    EXPECT_EQ(capsule.web_transport_stream_data().data, "abcdef");
    return true;
  });
  session_->OnCanWrite();
}

TEST_F(EncapsulatedWebTransportTest, BufferedWriteThenFlush) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  Stream* stream = session->OpenOutgoingUnidirectionalStream();
  ASSERT_TRUE(stream != nullptr);

  EXPECT_CALL(writer_, CanWrite()).Times(2).WillRepeatedly(Return(false));
  absl::Status status = quiche::WriteIntoStream(*stream, "abc");
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kOk));
  status = quiche::WriteIntoStream(*stream, "def");
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kOk));

  EXPECT_CALL(writer_, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(*this, OnCapsule(_)).WillOnce([](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), CapsuleType::WT_STREAM);
    EXPECT_EQ(capsule.web_transport_stream_data().stream_id, 2u);
    EXPECT_EQ(capsule.web_transport_stream_data().data, "abcdef");
    return true;
  });
  session_->OnCanWrite();
}

TEST_F(EncapsulatedWebTransportTest, BufferedStreamBlocksAnother) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  Stream* stream1 = session->OpenOutgoingUnidirectionalStream();
  Stream* stream2 = session->OpenOutgoingUnidirectionalStream();
  ASSERT_TRUE(stream1 != nullptr);
  ASSERT_TRUE(stream2 != nullptr);

  EXPECT_CALL(*this, OnCapsule(_)).Times(0);
  EXPECT_CALL(writer_, CanWrite()).WillOnce(Return(false));
  absl::Status status = quiche::WriteIntoStream(*stream1, "abc");
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kOk));
  // ShouldYield will return false here, causing the write to get buffered.
  EXPECT_CALL(writer_, CanWrite()).WillRepeatedly(Return(true));
  status = quiche::WriteIntoStream(*stream2, "abc");
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kOk));

  std::vector<StreamId> writes;
  EXPECT_CALL(*this, OnCapsule(_)).WillRepeatedly([&](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), CapsuleType::WT_STREAM);
    writes.push_back(capsule.web_transport_stream_data().stream_id);
    return true;
  });
  session_->OnCanWrite();
  EXPECT_THAT(writes, ElementsAre(2, 6));
}

TEST_F(EncapsulatedWebTransportTest, SendReset) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  Stream* stream = session->OpenOutgoingUnidirectionalStream();
  ASSERT_TRUE(stream != nullptr);

  MockStreamVisitorWithDestructor* visitor = SetupVisitor(*stream);
  EXPECT_CALL(*this, OnCapsule(_)).WillOnce([&](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), CapsuleType::WT_RESET_STREAM);
    EXPECT_EQ(capsule.web_transport_reset_stream().stream_id, 2u);
    EXPECT_EQ(capsule.web_transport_reset_stream().error_code, 1234u);
    return true;
  });
  stream->ResetWithUserCode(1234u);

  bool deleted = false;
  EXPECT_CALL(*visitor, OnDelete()).WillOnce([&] { deleted = true; });
  session->GarbageCollectStreams();
  EXPECT_TRUE(deleted);
}

TEST_F(EncapsulatedWebTransportTest, ReceiveReset) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*visitor_, OnIncomingUnidirectionalStreamAvailable());
  ProcessIncomingCapsule(quiche::WebTransportStreamDataCapsule{3, "", true});
  Stream* stream = session->AcceptIncomingUnidirectionalStream();
  ASSERT_TRUE(stream != nullptr);

  MockStreamVisitorWithDestructor* visitor = SetupVisitor(*stream);
  EXPECT_CALL(*visitor, OnResetStreamReceived(1234u));
  EXPECT_TRUE(session->GetStreamById(3) != nullptr);
  ProcessIncomingCapsule(quiche::WebTransportResetStreamCapsule{3u, 1234u});
  // Reading from the underlying transport automatically triggers garbage
  // collection.
  EXPECT_TRUE(session->GetStreamById(3) == nullptr);
}

TEST_F(EncapsulatedWebTransportTest, SendStopSending) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*visitor_, OnIncomingUnidirectionalStreamAvailable());
  ProcessIncomingCapsule(quiche::WebTransportStreamDataCapsule{3, "", true});
  Stream* stream = session->AcceptIncomingUnidirectionalStream();
  ASSERT_TRUE(stream != nullptr);

  MockStreamVisitorWithDestructor* visitor = SetupVisitor(*stream);
  EXPECT_CALL(*this, OnCapsule(_)).WillOnce([&](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), CapsuleType::WT_STOP_SENDING);
    EXPECT_EQ(capsule.web_transport_stop_sending().stream_id, 3u);
    EXPECT_EQ(capsule.web_transport_stop_sending().error_code, 1234u);
    return true;
  });
  stream->SendStopSending(1234u);

  bool deleted = false;
  EXPECT_CALL(*visitor, OnDelete()).WillOnce([&] { deleted = true; });
  session->GarbageCollectStreams();
  EXPECT_TRUE(deleted);
}

TEST_F(EncapsulatedWebTransportTest, ReceiveStopSending) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  Stream* stream = session->OpenOutgoingUnidirectionalStream();
  ASSERT_TRUE(stream != nullptr);

  MockStreamVisitorWithDestructor* visitor = SetupVisitor(*stream);
  EXPECT_CALL(*visitor, OnStopSendingReceived(1234u));
  EXPECT_TRUE(session->GetStreamById(2) != nullptr);
  ProcessIncomingCapsule(quiche::WebTransportStopSendingCapsule{2u, 1234u});
  // Reading from the underlying transport automatically triggers garbage
  // collection.
  EXPECT_TRUE(session->GetStreamById(2) == nullptr);
}

}  // namespace
}  // namespace webtransport::test

"""

```