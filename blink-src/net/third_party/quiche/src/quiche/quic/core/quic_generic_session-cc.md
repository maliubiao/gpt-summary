Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

1. **Understand the Goal:** The request asks for an analysis of `quic_generic_session.cc`, focusing on its functionality, relationship to JavaScript (if any), logical reasoning with examples, common usage errors, and debugging information.

2. **Initial Code Scan (High-Level):**
   - Recognize the Chromium/QUIC namespace.
   - Identify key class names: `QuicGenericSessionBase`, `QuicGenericClientSession`, `QuicGenericServerSession`, `QuicGenericStream`.
   - Notice includes related to WebTransport (`web_transport/web_transport.h`, `WebTransportStreamAdapter`). This immediately suggests the file is about implementing WebTransport over QUIC.
   - Spot the `GetQuicVersionsForGenericSession` function, indicating the QUIC versions supported.
   - See the `NoOpProofHandler` and `NoOpServerCryptoHelper` – these seem like default or placeholder implementations for crypto.

3. **Deep Dive into Key Classes:**

   - **`QuicGenericStream`:**  This class inherits from `QuicStream` and has a `WebTransportStreamAdapter`. This confirms it represents a WebTransport stream within the QUIC session. The `OnDataAvailable` and `OnCanWriteNewData` methods delegate to the adapter, further solidifying this.

   - **`QuicGenericSessionBase`:**  This is the core class. Note its inheritance from `QuicSession`.
     - **Constructor:** Takes `WebTransportVisitor`, ALPN (Application-Layer Protocol Negotiation), and handles ownership. This strongly suggests it's a base class for both client and server sessions using WebTransport.
     - **`CreateIncomingStream`:**  Handles creation of `QuicGenericStream` for incoming streams and notifies the `WebTransportVisitor`. The logic separates bidirectional and unidirectional streams.
     - **`OnTlsHandshakeComplete`:**  Notifies the `WebTransportVisitor` that the session is ready.
     - **`AcceptIncomingBidirectionalStream` and `AcceptIncomingUnidirectionalStream`:**  Provide a way for the `WebTransportVisitor` to retrieve incoming streams.
     - **`OpenOutgoingBidirectionalStream` and `OpenOutgoingUnidirectionalStream`:** Allow opening new outgoing streams, with flow control checks.
     - **`CreateStream`:**  The internal method for creating `QuicGenericStream` instances.
     - **`OnMessageReceived`:**  Handles datagrams and forwards them to the `WebTransportVisitor`.
     - **`OnCanCreateNewOutgoingStream`:**  Informs the `WebTransportVisitor` when new outgoing streams can be created.
     - **`GetStreamById`:** Retrieves a stream by its ID.
     - **`SendOrQueueDatagram`:**  Sends WebTransport datagrams.
     - **`OnConnectionClosed`:**  Handles connection closure and notifies the `WebTransportVisitor`.

   - **`QuicGenericClientSession` and `QuicGenericServerSession`:** These inherit from `QuicGenericSessionBase`. They handle the client-side and server-side specifics, including crypto setup. The constructors take relevant crypto configuration objects. The presence of `CreateWebTransportSessionVisitorCallback` suggests a flexible way to instantiate the visitor.

4. **Identify Functionality:** Based on the class structure and methods, the core functionality is clearly to provide a QUIC-based implementation of WebTransport. Key aspects are stream management (creation, acceptance, opening), datagram handling, and session lifecycle management.

5. **Relationship to JavaScript:**  WebTransport is a web standard, making the connection to JavaScript obvious. The key is to explain *how* the C++ code interacts with JavaScript. The `WebTransportVisitor` acts as the bridge. JavaScript uses WebTransport APIs, which in the browser translate to calls that eventually reach this C++ code (via Chromium's internals). The examples should illustrate these JavaScript APIs and their likely impact on the C++ side.

6. **Logical Reasoning (Hypothetical Inputs/Outputs):**  Choose specific methods and illustrate their behavior with concrete inputs and outputs. For example, `AcceptIncomingBidirectionalStream` will return a stream object if there's an available incoming stream, and `nullptr` otherwise. Similarly, `SendOrQueueDatagram` returns success or failure based on the input.

7. **Common Usage Errors:** Think about how a developer using the WebTransport API or interacting with the underlying QUIC implementation might make mistakes. Examples include trying to open too many streams, sending too much data without respecting flow control, or incorrect handling of session closure.

8. **Debugging Information (User Journey):**  Trace a typical user action (like opening a WebTransport connection) and outline the steps that lead to this specific C++ file. This helps understand where this code fits within the larger system and provides context for debugging. Consider browser address bar input, JavaScript API calls, and the underlying network stack.

9. **Structure and Refine:** Organize the findings into clear sections as requested (Functionality, JavaScript Relation, Logical Reasoning, Usage Errors, Debugging). Use clear and concise language. Provide specific code examples where relevant. Review and refine for accuracy and completeness. For instance, initially, I might just say "manages streams," but refining would involve listing the specific actions: creating, accepting, opening, etc.

10. **Consider the Audience:**  The explanation should be understandable to someone familiar with networking concepts and possibly some C++, but doesn't necessarily require deep expertise in QUIC internals. Avoid overly technical jargon where possible.

By following these steps, systematically analyzing the code, and thinking about its role within the larger context of WebTransport and the Chromium network stack, it's possible to generate a comprehensive and informative explanation like the example provided.
这个文件 `net/third_party/quiche/src/quiche/quic/core/quic_generic_session.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，专注于提供一个通用的 QUIC 会话，特别是用于支持 WebTransport 协议。

以下是其主要功能：

**1. 提供 WebTransport 的 QUIC 会话基础:**

* **`QuicGenericSessionBase` 类:** 这是核心类，它继承自 `QuicSession` 并实现了 WebTransport 会话的基础功能。它管理 QUIC 连接的生命周期，处理流的创建、接收和管理，以及数据报的发送和接收。
* **ALPN 支持:**  会话使用 Application-Layer Protocol Negotiation (ALPN) 来协商使用 WebTransport 协议。
* **`WebTransportVisitor` 接口:**  它使用 `WebTransportVisitor` 接口来通知上层 WebTransport 实现会话状态的变化，例如新流的到来、会话就绪、数据报的接收以及会话关闭。

**2. 流管理:**

* **`QuicGenericStream` 类:**  这是一个继承自 `QuicStream` 的类，专门用于 WebTransport 流。它包含一个 `WebTransportStreamAdapter`，用于将底层的 QUIC 流事件转换为 WebTransport 流的事件。
* **创建和接受流:**  `QuicGenericSessionBase` 负责创建和接受双向和单向的 `QuicGenericStream`。
* **流的缓冲和排序:**  底层的 QUIC 协议负责流的可靠传输、缓冲和排序。
* **流的优先级:**  `QuicGenericStream` 使用 `WebTransportStreamAdapter` 来设置流的优先级。

**3. 数据报支持:**

* **发送和接收数据报:**  `QuicGenericSessionBase` 允许发送和接收 WebTransport 数据报。它使用 `QuicDatagramQueue` 来管理数据报的发送。
* **`OnMessageReceived` 方法:**  当接收到 QUIC 数据报时，此方法会被调用，并将数据传递给 `WebTransportVisitor`。

**4. 连接生命周期管理:**

* **TLS 握手完成:**  `OnTlsHandshakeComplete` 方法在 TLS 握手完成后被调用，并通知 `WebTransportVisitor` 会话已就绪。
* **连接关闭:**  `OnConnectionClosed` 方法处理 QUIC 连接的关闭，并将关闭原因通知 `WebTransportVisitor`。

**5. 客户端和服务器端实现:**

* **`QuicGenericClientSession` 类:**  继承自 `QuicGenericSessionBase`，提供了 WebTransport 客户端会话的具体实现，包括与 `QuicCryptoClientStream` 的集成以处理客户端的加密握手。
* **`QuicGenericServerSession` 类:**  继承自 `QuicGenericSessionBase`，提供了 WebTransport 服务器会话的具体实现，包括与 `QuicCryptoServerStream` 的集成以处理服务器端的加密握手。

**与 JavaScript 功能的关系:**

这个 C++ 文件直接支持了浏览器中 JavaScript WebTransport API 的底层实现。

**举例说明:**

当 JavaScript 代码使用 WebTransport API 创建一个新的双向流时：

```javascript
const transport = new WebTransport("https://example.com");
await transport.ready;
const stream = await transport.createBidirectionalStream();
const writer = stream.writable.getWriter();
writer.write(new TextEncoder().encode("Hello from JavaScript!"));
```

这个 JavaScript 操作最终会触发浏览器底层的网络栈操作，最终会在 `QuicGenericClientSession` 中调用 `OpenOutgoingBidirectionalStream()` 方法来创建一个新的 `QuicGenericStream`。这个新的流将用于发送 JavaScript 发送的数据。

类似地，当服务器通过 WebTransport 发送数据给客户端时，服务器端的 `QuicGenericServerSession` 会调用相应的方法发送数据，浏览器接收到数据后，会触发 JavaScript 中对应 WebTransport 流的 `readable` 属性上的事件，使得 JavaScript 能够读取数据。

**逻辑推理和假设输入/输出:**

**假设输入 (客户端):**  JavaScript 代码调用 `transport.createUnidirectionalStream()`

**逻辑推理:**
1. JavaScript 调用 WebTransport API 的 `createUnidirectionalStream()` 方法。
2. 浏览器网络栈接收到请求。
3. 对于基于 QUIC 的 WebTransport 连接，`QuicGenericClientSession::OpenOutgoingUnidirectionalStream()` 方法会被调用。
4. 如果连接有足够的资源（例如，未超出流的最大数量限制），则会创建一个新的 `QuicGenericStream` (单向)。
5. 返回一个 `webtransport::Stream` 对象，该对象封装了 `QuicGenericStream` 的 `WebTransportStreamAdapter`。

**输出 (客户端):** 返回一个代表新创建的单向 WebTransport 流的 JavaScript 对象，允许 JavaScript 代码向该流写入数据。

**假设输入 (服务器):**  QUIC 连接上接收到一个新的流创建请求。

**逻辑推理:**
1. QUIC 连接接收到一个新的流创建帧。
2. `QuicGenericServerSession::CreateIncomingStream()` 方法被调用。
3. 根据流 ID 判断是双向流还是单向流。
4. 创建一个新的 `QuicGenericStream` 对象。
5. 如果是双向流，将其添加到 `incoming_bidirectional_streams_` 队列，并调用 `visitor_->OnIncomingBidirectionalStreamAvailable()`。
6. 如果是单向流，将其添加到 `incoming_unidirectional_streams_` 队列，并调用 `visitor_->OnIncomingUnidirectionalStreamAvailable()`。

**输出 (服务器):**  新的 `QuicGenericStream` 被创建并激活。`WebTransportVisitor` 会收到通知，表明有新的流可以被接受。

**用户或编程常见的使用错误:**

1. **过早调用流操作:**  在 WebTransport 会话的 `ready` promise resolve 之前尝试创建或操作流。这可能导致连接尚未建立或握手未完成，从而引发错误。
   * **例子 (JavaScript):**
     ```javascript
     const transport = new WebTransport("https://example.com");
     const stream = transport.createBidirectionalStream(); // 错误：可能在 ready 之前调用
     await transport.ready;
     const writer = await stream.writable.getWriter();
     ```
   * **调试线索 (C++):**  可能会在 `QuicGenericClientSession` 中看到尝试创建流但在 TLS 握手完成之前的情况，导致资源未就绪。

2. **未正确处理流的关闭:**  在一方关闭流后，另一方继续尝试写入或读取该流。这会导致错误或未定义的行为。
   * **例子 (JavaScript):**
     ```javascript
     // 客户端关闭流
     writer.close();
     // 服务器端尝试继续写入
     serverStream.writable.getWriter().write("More data"); // 错误：流已关闭
     ```
   * **调试线索 (C++):**  可能会在 `QuicGenericStream` 的 `adapter_` 中看到尝试在已关闭的流上进行读写操作。

3. **超出流控制限制:**  尝试发送超过连接或流的流量控制限制的数据。QUIC 具有流量控制机制以防止连接被大量数据淹没。
   * **例子 (JavaScript):**  向一个流写入大量数据而没有等待背压信号。
   * **调试线索 (C++):**  可能会在 `QuicGenericSessionBase` 或底层的 QUIC 连接实现中看到流量控制相关的错误或阻塞。

4. **错误处理连接关闭:**  未正确处理 `transport.closed` promise，导致程序在连接意外关闭时无法正常清理或重连。
   * **例子 (JavaScript):**  没有监听 `transport.closed` 事件并采取适当的行动。
   * **调试线索 (C++):**  可能会在 `QuicGenericSessionBase::OnConnectionClosed` 中看到连接关闭，但上层 WebTransport 代码没有得到适当的通知或处理。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在 Chrome 浏览器中访问了一个支持 WebTransport 的网站 `https://example.com:4433/webtransport`。

1. **用户在浏览器地址栏输入 URL 并回车。**
2. **DNS 解析:** 浏览器进行 DNS 查询解析 `example.com` 的 IP 地址。
3. **TCP 连接建立 (可能):**  虽然 WebTransport 基于 UDP 的 QUIC，但初始阶段可能涉及 HTTP/3 的协商，这可能在 TCP 上进行。
4. **QUIC 连接建立:** 浏览器尝试与服务器建立 QUIC 连接。这包括 TLS 握手，其中会协商使用 WebTransport 的 ALPN。
5. **`QuicGenericClientSession` 创建:** 如果协商成功，Chrome 网络栈会创建一个 `QuicGenericClientSession` 对象来管理这个 QUIC 连接。这个对象对应于 `net/third_party/quiche/src/quiche/quic/core/quic_generic_session.cc` 中的代码。
6. **JavaScript 代码执行:** 网页加载后，JavaScript 代码开始执行，并可能使用 WebTransport API。
   * **`new WebTransport("https://example.com:4433/webtransport")`:**  这个 JavaScript 代码会触发浏览器创建一个新的 WebTransport 连接。
   * **`transport.createBidirectionalStream()`:**  当 JavaScript 代码尝试创建一个新的双向流时，会调用 `QuicGenericClientSession::OpenOutgoingBidirectionalStream()`。
   * **`stream.writable.getWriter().write(...)`:**  当 JavaScript 代码尝试向流写入数据时，数据会通过 `WebTransportStreamAdapter` 最终传递到底层的 QUIC 流，由 `QuicGenericStream` 处理。
   * **服务器发送数据:** 如果服务器发送数据，`QuicGenericServerSession` 接收到数据后，会通过 `WebTransportVisitor` 通知 JavaScript 代码。

**调试线索:**

* **网络抓包 (如 Wireshark):**  可以查看 QUIC 连接的握手过程，确认 ALPN 协商是否成功。可以查看流的创建和数据传输。
* **Chrome 的 `net-internals` (chrome://net-internals/#quic):**  提供了关于 QUIC 连接的详细信息，包括会话状态、流信息、错误信息等。可以查看特定连接的 `QuicGenericSessionBase` 的状态。
* **断点调试:**  在 `QuicGenericSessionBase` 和相关的类中设置断点，可以跟踪流的创建、数据的发送和接收过程，以及错误处理逻辑。
* **日志输出:**  QUIC 库通常会有详细的日志输出，可以帮助理解连接和流的状态变化。查看 `QUIC_DVLOG` 宏输出的日志信息。

总而言之，`quic_generic_session.cc` 是 Chromium 中实现 WebTransport over QUIC 的关键组成部分，它负责管理 QUIC 连接和流，并将底层的 QUIC 事件映射到 WebTransport API 的抽象概念上。理解这个文件的功能对于调试 WebTransport 相关的网络问题至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_generic_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_generic_session.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/http/web_transport_stream_adapter.h"
#include "quiche/quic/core/quic_crypto_client_stream.h"
#include "quiche/quic/core/quic_session.h"
#include "quiche/quic/core/quic_stream_priority.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/simple_buffer_allocator.h"
#include "quiche/web_transport/web_transport.h"

namespace quic {

namespace {

class NoOpProofHandler : public QuicCryptoClientStream::ProofHandler {
 public:
  void OnProofValid(const QuicCryptoClientConfig::CachedState&) override {}
  void OnProofVerifyDetailsAvailable(const ProofVerifyDetails&) override {}
};

class NoOpServerCryptoHelper : public QuicCryptoServerStreamBase::Helper {
 public:
  bool CanAcceptClientHello(const CryptoHandshakeMessage& /*message*/,
                            const QuicSocketAddress& /*client_address*/,
                            const QuicSocketAddress& /*peer_address*/,
                            const QuicSocketAddress& /*self_address*/,
                            std::string* /*error_details*/) const override {
    return true;
  }
};

}  // namespace

ParsedQuicVersionVector GetQuicVersionsForGenericSession() {
  return {ParsedQuicVersion::RFCv1()};
}

// QuicGenericStream is a stream that provides a general-purpose implementation
// of a webtransport::Stream interface.
class QUICHE_EXPORT QuicGenericStream : public QuicStream {
 public:
  QuicGenericStream(QuicStreamId id, QuicSession* session)
      : QuicStream(id, session, /*is_static=*/false,
                   QuicUtils::GetStreamType(
                       id, session->connection()->perspective(),
                       session->IsIncomingStream(id), session->version())),
        adapter_(session, this, sequencer(), std::nullopt) {
    adapter_.SetPriority(webtransport::StreamPriority{0, 0});
  }

  WebTransportStreamAdapter* adapter() { return &adapter_; }

  // QuicSession method implementations.
  void OnDataAvailable() override { adapter_.OnDataAvailable(); }
  void OnCanWriteNewData() override { adapter_.OnCanWriteNewData(); }

 private:
  WebTransportStreamAdapter adapter_;
};

QuicGenericSessionBase::QuicGenericSessionBase(
    QuicConnection* connection, bool owns_connection, Visitor* owner,
    const QuicConfig& config, std::string alpn, WebTransportVisitor* visitor,
    bool owns_visitor,
    std::unique_ptr<QuicDatagramQueue::Observer> datagram_observer)
    : QuicSession(connection, owner, config, GetQuicVersionsForGenericSession(),
                  /*num_expected_unidirectional_static_streams=*/0,
                  std::move(datagram_observer),
                  QuicPriorityType::kWebTransport),
      alpn_(std::move(alpn)),
      visitor_(visitor),
      owns_connection_(owns_connection),
      owns_visitor_(owns_visitor) {}

QuicGenericSessionBase::~QuicGenericSessionBase() {
  if (owns_connection_) {
    DeleteConnection();
  }
  if (owns_visitor_) {
    delete visitor_;
    visitor_ = nullptr;
  }
}

QuicStream* QuicGenericSessionBase::CreateIncomingStream(QuicStreamId id) {
  QUIC_DVLOG(1) << "Creating incoming QuicGenricStream " << id;
  QuicGenericStream* stream = CreateStream(id);
  if (stream->type() == BIDIRECTIONAL) {
    incoming_bidirectional_streams_.push_back(id);
    visitor_->OnIncomingBidirectionalStreamAvailable();
  } else {
    incoming_unidirectional_streams_.push_back(id);
    visitor_->OnIncomingUnidirectionalStreamAvailable();
  }
  return stream;
}

void QuicGenericSessionBase::OnTlsHandshakeComplete() {
  QuicSession::OnTlsHandshakeComplete();
  visitor_->OnSessionReady();
}

webtransport::Stream*
QuicGenericSessionBase::AcceptIncomingBidirectionalStream() {
  while (!incoming_bidirectional_streams_.empty()) {
    webtransport::Stream* stream =
        GetStreamById(incoming_bidirectional_streams_.front());
    incoming_bidirectional_streams_.pop_front();
    if (stream != nullptr) {
      return stream;
    }
  }
  return nullptr;
}

webtransport::Stream*
QuicGenericSessionBase::AcceptIncomingUnidirectionalStream() {
  while (!incoming_unidirectional_streams_.empty()) {
    webtransport::Stream* stream =
        GetStreamById(incoming_unidirectional_streams_.front());
    incoming_unidirectional_streams_.pop_front();
    if (stream != nullptr) {
      return stream;
    }
  }
  return nullptr;
}

webtransport::Stream*
QuicGenericSessionBase::OpenOutgoingBidirectionalStream() {
  if (!CanOpenNextOutgoingBidirectionalStream()) {
    QUIC_BUG(QuicGenericSessionBase_flow_control_violation_bidi)
        << "Attempted to open a stream in violation of flow control";
    return nullptr;
  }
  return CreateStream(GetNextOutgoingBidirectionalStreamId())->adapter();
}

webtransport::Stream*
QuicGenericSessionBase::OpenOutgoingUnidirectionalStream() {
  if (!CanOpenNextOutgoingUnidirectionalStream()) {
    QUIC_BUG(QuicGenericSessionBase_flow_control_violation_unidi)
        << "Attempted to open a stream in violation of flow control";
    return nullptr;
  }
  return CreateStream(GetNextOutgoingUnidirectionalStreamId())->adapter();
}

QuicGenericStream* QuicGenericSessionBase::CreateStream(QuicStreamId id) {
  auto stream = std::make_unique<QuicGenericStream>(id, this);
  QuicGenericStream* stream_ptr = stream.get();
  ActivateStream(std::move(stream));
  return stream_ptr;
}

void QuicGenericSessionBase::OnMessageReceived(absl::string_view message) {
  visitor_->OnDatagramReceived(message);
}

void QuicGenericSessionBase::OnCanCreateNewOutgoingStream(bool unidirectional) {
  if (unidirectional) {
    visitor_->OnCanCreateNewOutgoingUnidirectionalStream();
  } else {
    visitor_->OnCanCreateNewOutgoingBidirectionalStream();
  }
}

webtransport::Stream* QuicGenericSessionBase::GetStreamById(
    webtransport::StreamId id) {
  QuicStream* stream = GetActiveStream(id);
  if (stream == nullptr) {
    return nullptr;
  }
  return static_cast<QuicGenericStream*>(stream)->adapter();
}

webtransport::DatagramStatus QuicGenericSessionBase::SendOrQueueDatagram(
    absl::string_view datagram) {
  quiche::QuicheBuffer buffer = quiche::QuicheBuffer::Copy(
      quiche::SimpleBufferAllocator::Get(), datagram);
  return MessageStatusToWebTransportStatus(
      datagram_queue()->SendOrQueueDatagram(
          quiche::QuicheMemSlice(std::move(buffer))));
}

void QuicGenericSessionBase::OnConnectionClosed(
    const QuicConnectionCloseFrame& frame, ConnectionCloseSource source) {
  QuicSession::OnConnectionClosed(frame, source);
  visitor_->OnSessionClosed(static_cast<webtransport::SessionErrorCode>(
                                frame.transport_close_frame_type),
                            frame.error_details);
}

QuicGenericClientSession::QuicGenericClientSession(
    QuicConnection* connection, bool owns_connection, Visitor* owner,
    const QuicConfig& config, std::string host, uint16_t port, std::string alpn,
    webtransport::SessionVisitor* visitor, bool owns_visitor,
    std::unique_ptr<QuicDatagramQueue::Observer> datagram_observer,
    QuicCryptoClientConfig* crypto_config)
    : QuicGenericSessionBase(connection, owns_connection, owner, config,
                             std::move(alpn), visitor, owns_visitor,
                             std::move(datagram_observer)) {
  static NoOpProofHandler* handler = new NoOpProofHandler();
  crypto_stream_ = std::make_unique<QuicCryptoClientStream>(
      QuicServerId(std::move(host), port), this,
      crypto_config->proof_verifier()->CreateDefaultContext(), crypto_config,
      /*proof_handler=*/handler, /*has_application_state=*/false);
}

QuicGenericClientSession::QuicGenericClientSession(
    QuicConnection* connection, bool owns_connection, Visitor* owner,
    const QuicConfig& config, std::string host, uint16_t port, std::string alpn,
    CreateWebTransportSessionVisitorCallback create_visitor_callback,
    std::unique_ptr<QuicDatagramQueue::Observer> datagram_observer,
    QuicCryptoClientConfig* crypto_config)
    : QuicGenericClientSession(
          connection, owns_connection, owner, config, std::move(host), port,
          std::move(alpn), std::move(create_visitor_callback)(*this).release(),
          /*owns_visitor=*/true, std::move(datagram_observer), crypto_config) {}

QuicGenericServerSession::QuicGenericServerSession(
    QuicConnection* connection, bool owns_connection, Visitor* owner,
    const QuicConfig& config, std::string alpn,
    webtransport::SessionVisitor* visitor, bool owns_visitor,
    std::unique_ptr<QuicDatagramQueue::Observer> datagram_observer,
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache)
    : QuicGenericSessionBase(connection, owns_connection, owner, config,
                             std::move(alpn), visitor, owns_visitor,
                             std::move(datagram_observer)) {
  static NoOpServerCryptoHelper* helper = new NoOpServerCryptoHelper();
  crypto_stream_ = CreateCryptoServerStream(
      crypto_config, compressed_certs_cache, this, helper);
}

QuicGenericServerSession::QuicGenericServerSession(
    QuicConnection* connection, bool owns_connection, Visitor* owner,
    const QuicConfig& config, std::string alpn,
    CreateWebTransportSessionVisitorCallback create_visitor_callback,
    std::unique_ptr<QuicDatagramQueue::Observer> datagram_observer,
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache)
    : QuicGenericServerSession(
          connection, owns_connection, owner, config, std::move(alpn),
          std::move(create_visitor_callback)(*this).release(),
          /*owns_visitor=*/true, std::move(datagram_observer), crypto_config,
          compressed_certs_cache) {}

}  // namespace quic

"""

```