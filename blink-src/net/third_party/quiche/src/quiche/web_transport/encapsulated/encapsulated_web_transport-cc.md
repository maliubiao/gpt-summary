Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

**1. Initial Skim and Goal Identification:**

* **Skim:** Quickly read through the code to get a general sense of its purpose. Keywords like "WebTransport," "Encapsulated," "Capsule," "Stream," and methods like `SendOrQueueDatagram`, `OpenOutgoingStream`, `ProcessIncomingServerHeaders` jump out.
* **Goal:** The prompt asks for the file's functionality, relationship to JavaScript, logical reasoning (input/output), common errors, and debugging context.

**2. Deeper Dive and Functional Analysis:**

* **Core Functionality:**  Identify the main class, `EncapsulatedSession`, and its role. It manages a WebTransport session over an "encapsulated" transport (likely TCP, as noted in a comment). This involves:
    * **Session Lifecycle:**  Initialization, opening, closing, draining.
    * **Stream Management:** Creating, accepting, reading from, and writing to bidirectional and unidirectional streams.
    * **Datagram Handling:** Sending and receiving unreliable data.
    * **Capsule Processing:** Parsing and handling various control messages and stream data.
    * **Error Handling:**  Managing fatal errors and write errors.
* **Key Components:**
    * `Perspective`:  Client or Server role.
    * `SessionVisitor`:  An interface for notifying the application layer about events.
    * `quiche::WriteStream`/`quiche::ReadStream`: Underlying transport for sending and receiving raw bytes.
    * `CapsuleParser`:  Parses incoming byte streams into WebTransport capsules.
    * `Stream`:  Represents an individual WebTransport stream.
    * `Scheduler`: Manages the order in which streams can write data.
    * Queues (`incoming_bidirectional_streams_`, `incoming_unidirectional_streams_`, `control_capsule_queue_`):  Used for managing incoming streams and outgoing control messages.
* **Identify Key Methods and Their Actions:**
    * `InitializeClient/Server`: Sets up the session based on the perspective.
    * `ProcessIncomingServerHeaders`: Handles initial server headers.
    * `CloseSession`: Initiates the session closing process.
    * `AcceptIncoming...Stream`: Provides streams to the application.
    * `OpenOutgoing...Stream`: Creates new outgoing streams.
    * `SendOrQueueDatagram`: Sends or buffers datagrams.
    * `OnCanWrite/Read`:  Handles I/O readiness events.
    * `OnCapsule`: Processes received WebTransport capsules.
    * `ProcessStreamCapsule`:  Handles capsules related to individual streams.
    * `InnerStream::Read/Writev`:  Manages reading and writing on individual streams.

**3. Connecting to JavaScript (Conceptual):**

* **WebTransport API:**  Recall that WebTransport is an API exposed to JavaScript in browsers.
* **Mapping Concepts:**  Think about how the C++ code implements the features that JavaScript developers interact with:
    * `new WebTransport(...)` in JS corresponds to the creation of an `EncapsulatedSession`.
    * `transport.createBidirectionalStream()` maps to `OpenOutgoingBidirectionalStream()`.
    * `transport.datagrams.send(...)` maps to `SendOrQueueDatagram()`.
    * Event listeners on `transport.incomingUnidirectionalStreams` and `transport.incomingBidirectionalStreams` are triggered by the `visitor_->OnIncoming...StreamAvailable()` calls.
    * Data received on a stream in JS corresponds to the data buffered in `InnerStream::incoming_reads_`.
    * Sending data on a stream in JS uses the `InnerStream::Writev()` method.
* **Focus on the Interface:**  The key connection is that this C++ code *implements* the underlying transport mechanisms that the JavaScript WebTransport API uses.

**4. Logical Reasoning (Input/Output Examples):**

* **Choose Simple, Illustrative Examples:** Don't try to cover all edge cases. Focus on basic scenarios.
* **Example 1 (Datagram):** Sending a simple datagram. Show the input (string) and the expected action (queuing or writing). Mention potential blocking.
* **Example 2 (Opening Stream):**  Illustrate the stream ID allocation based on the client/server perspective.

**5. Common Errors and User Actions:**

* **Identify Obvious Mistakes:** Think about common programming errors and how they might manifest in this context.
* **Examples:**
    * Closing an already closed session.
    * Writing to a closed stream.
    * Sending datagrams exceeding the limit.
* **Relate to User Actions:**  Connect these errors to actions a user (developer) might take when using the JavaScript API (which then translates to calls in this C++ code).

**6. Debugging Context (User Journey):**

* **Start at the User Interface:**  Begin with the user's interaction in the browser (JavaScript).
* **Trace the Call Stack:**  Imagine the sequence of events:
    1. User opens a webpage with WebTransport code.
    2. JavaScript WebTransport API calls are made.
    3. These calls interact with the browser's networking stack.
    4. Eventually, these actions reach the C++ implementation, including this file.
* **Illustrate with a Specific Example:**  Walk through a scenario like sending a datagram, showing how it progresses from the JS `send()` call to the `EncapsulatedSession::SendOrQueueDatagram()` method.
* **Highlight Key Information for Debugging:**  Mention log messages, breakpoints, and the role of the `SessionVisitor`.

**7. Structuring the Response:**

* **Organize by Prompt Requirements:** Address each point of the prompt (functionality, JS relationship, logic, errors, debugging).
* **Use Clear Headings and Bullet Points:**  Make the information easy to read and understand.
* **Provide Code Snippets (where relevant):**  Illustrate the concepts with relevant parts of the code.
* **Use Precise Language:**  Avoid ambiguity and technical jargon where simpler terms suffice.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe focus heavily on the QUIC aspects. **Correction:**  The file emphasizes "encapsulated," suggesting TCP as the primary underlying transport, so focus there and mention QUIC as a possibility but not the central point.
* **Initial thought:** List all possible error conditions. **Correction:** Focus on the *common* errors a user might encounter.
* **Initial thought:** Provide extremely detailed input/output scenarios. **Correction:** Keep the examples simple and focused on illustrating core concepts.
* **Review and Clarity:** After drafting the response, reread it to ensure it's clear, concise, and accurately answers the prompt. Ensure the JavaScript connections are logical and easy to grasp.
这个 C++ 文件 `encapsulated_web_transport.cc` 是 Chromium 网络栈中 `quiche` 库的一部分，负责实现 **封装的 WebTransport 会话**。  WebTransport 是一种在客户端和服务器之间进行双向、低延迟通信的网络协议，通常基于 HTTP/3 (QUIC)。 然而，这个文件实现了一种在 **非 QUIC 的连接上** 封装 WebTransport 的方式，很可能是在 TCP 连接上。

以下是该文件的主要功能：

**1. 封装 WebTransport 协议:**

* **Capsule 处理:**  该文件定义了 `EncapsulatedSession` 类，它负责将 WebTransport 的数据帧（称为 "Capsules"）封装到下层连接（例如 TCP）的数据流中，并从下层数据流中解析出 Capsules。
* **流管理:** 它管理着 WebTransport 会话中的双向流（bidirectional streams）和单向流（unidirectional streams）。这包括创建新的流，接收和发送流数据，以及处理流的关闭和重置。
* **数据报支持:** 它支持通过 `SendOrQueueDatagram` 发送和接收 WebTransport 数据报，这是一种不可靠的、无序的消息传递方式。
* **会话管理:**  它处理 WebTransport 会话的生命周期，包括建立连接、正常关闭和异常关闭。

**2. 与底层传输的交互:**

* **读写操作:** `EncapsulatedSession` 使用 `quiche::WriteStream` 和 `quiche::ReadStream` 接口与底层的传输层进行交互，进行数据的发送和接收。在 TCP 封装的情况下，这些流对象会操作 TCP 套接字。
* **事件驱动:** 它通过 `OnCanWrite` 和 `OnCanRead` 方法响应底层传输层的可写和可读事件，以便发送和接收数据。

**3. WebTransport 协议的具体实现:**

* **控制 Capsule 处理:** 它处理各种 WebTransport 控制 Capsule，例如会话关闭 (`CLOSE_WEBTRANSPORT_SESSION`)、会话排空 (`DRAIN_WEBTRANSPORT_SESSION`)、流重置 (`WT_RESET_STREAM`)、停止发送 (`WT_STOP_SENDING`) 等。
* **流 Capsule 处理:**  它处理包含流数据的 Capsule (`WT_STREAM`, `WT_STREAM_WITH_FIN`)，将数据传递给相应的流对象。

**4. 流量控制和调度 (部分实现):**

* **流调度:** 使用 `scheduler_` 对象来管理流的写入优先级，以决定哪些流应该优先发送数据。但代码中有 TODO 注释表明流量控制尚未完全实现。

**与 JavaScript 的关系及举例说明:**

这个 C++ 文件本身并不直接包含 JavaScript 代码，但它是浏览器网络栈的一部分，负责实现 WebTransport 协议的核心逻辑。  JavaScript 代码通过浏览器提供的 WebTransport API 与这个 C++ 代码进行交互。

**举例说明:**

假设一个网页中的 JavaScript 代码创建了一个 WebTransport 连接，并创建了一个双向流：

**JavaScript 代码:**

```javascript
const transport = new WebTransport("https://example.com");
await transport.ready;
const stream = await transport.createBidirectionalStream();
const writer = stream.writable.getWriter();
writer.write("Hello from JavaScript!");
await writer.close();
```

**C++ (encapsulated_web_transport.cc) 中的对应操作:**

1. **`new WebTransport(...)`:**  当 JavaScript 代码创建 `WebTransport` 对象时，浏览器会建立与服务器的连接（在封装的情况下可能是 TCP）。这个 C++ 文件中的 `EncapsulatedSession::InitializeClient` 或 `EncapsulatedSession::InitializeServer` 方法会被调用，根据客户端或服务器的角色进行初始化。
2. **`transport.createBidirectionalStream()`:**  这个 JavaScript 调用会触发 C++ 代码中的 `EncapsulatedSession::OpenOutgoingBidirectionalStream()` 方法。
    *  `OpenOutgoingBidirectionalStream()` 会分配一个新的流 ID (`next_outgoing_bidi_stream_`)。
    *  它会创建一个 `InnerStream` 对象来表示这个流。
    *  它可能会向底层连接发送一个指示新流的 Capsule（虽然在封装的场景下，流的创建可能不显式地在协议层面指示，而是通过发送数据来隐式创建）。
3. **`writer.write("Hello from JavaScript!")`:**  当 JavaScript 向流写入数据时，会调用 `InnerStream::Writev()` 方法。
    *  `Writev()` 会将数据封装到一个 `WT_STREAM` Capsule 中。
    *  `EncapsulatedSession::OnCanWrite()` 方法被触发后，会将这个 Capsule 通过 `writer_` (底层的 `quiche::WriteStream`) 发送到服务器。
4. **服务器接收数据:**  服务器端的 `EncapsulatedSession` 接收到数据后，`OnCanRead()` 方法被调用，`capsule_parser_` 解析出 `WT_STREAM` Capsule，并调用 `ProcessStreamCapsule()` 将数据传递给相应的 `InnerStream` 对象。服务器端的 JavaScript 可以通过监听流的 `readable` 事件来读取数据。

**逻辑推理，假设输入与输出:**

**假设输入:**

1. **接收到包含流数据的 Capsule:**  一个 TCP 数据包到达，解码后得到一个 `WT_STREAM` Capsule，`stream_id` 为 4，包含数据 "World!"。
2. **调用 `AcceptIncomingBidirectionalStream()`:** 应用程序层请求接收一个传入的双向流。

**逻辑推理过程:**

*   `EncapsulatedSession::OnCanRead()` 被调用，读取并解析 TCP 数据。
*   `EncapsulatedSession::OnCapsule()` 被调用，识别出 `WT_STREAM` Capsule。
*   `EncapsulatedSession::ProcessStreamCapsule()` 被调用，`stream_id` 为 4。
*   检查 `streams_` 中是否存在 ID 为 4 的流。如果不存在，并且这是一个由对方打开的流 ID，则会创建一个新的 `InnerStream` 对象。
*   数据 "World!" 被添加到 `InnerStream` 的 `incoming_reads_` 队列中。
*   如果这是一个新的流，并且是双向流，`incoming_bidirectional_streams_` 会被更新，并且 `visitor_->OnIncomingBidirectionalStreamAvailable()` 会被调用，通知应用程序层有新的传入流可用。
*   当应用程序层调用 `AcceptIncomingBidirectionalStream()` 时，它会从 `incoming_bidirectional_streams_` 队列中取出一个流 ID (4)，并返回 `GetStreamById(4)` 得到的 `InnerStream` 对象。
*   应用程序层可以通过调用返回的 `InnerStream` 对象的 `Read()` 方法来读取数据 "World!"。

**输出:**

*   `AcceptIncomingBidirectionalStream()` 返回指向 `InnerStream` 对象的指针，该对象代表 ID 为 4 的流。
*   对该 `InnerStream` 对象调用 `Read()` 方法会返回包含 "World!" 的数据。

**用户或编程常见的使用错误及举例说明:**

1. **尝试在会话关闭后发送数据:**
    *   **用户操作:**  JavaScript 代码在调用 `transport.close()` 或收到 `transport.closed` 事件后，仍然尝试调用 `stream.writable.getWriter().write(...)` 或 `transport.datagrams.send(...)`。
    *   **C++ 错误:**  `EncapsulatedSession::SendOrQueueDatagram()` 或 `InnerStream::Writev()` 会检查会话状态 (`state_`)，如果会话处于 `kSessionClosing` 或 `kSessionClosed` 状态，会返回一个错误状态或直接忽略发送请求。`OnFatalError` 可能被调用记录错误。
    *   **例子:** JavaScript 开发者没有正确监听 `transport.closed` 事件，并在连接关闭后继续尝试发送数据。

2. **尝试关闭已经关闭的会话:**
    *   **用户操作:** JavaScript 代码多次调用 `transport.close()`。
    *   **C++ 错误:** `EncapsulatedSession::CloseSession()` 会检查会话状态。如果会话已经处于 `kSessionClosing` 或 `kSessionClosed` 状态，会调用 `OnFatalError` 记录错误，并可能忽略后续的关闭请求。
    *   **例子:**  JavaScript 开发者在不同的地方调用了 `transport.close()`，没有进行互斥或状态检查。

3. **发送超过最大数据报大小的数据报:**
    *   **用户操作:** JavaScript 代码尝试通过 `transport.datagrams.send(largeBuffer)` 发送一个超过 `EncapsulatedSession::kEncapsulatedMaxDatagramSize` (默认为 9000 字节) 的数据报。
    *   **C++ 错误:** `EncapsulatedSession::SendOrQueueDatagram()` 会检查数据报的大小，如果超过限制，会返回 `DatagramStatus`，状态码为 `kTooBig`，并包含错误消息。数据不会被发送。
    *   **例子:** JavaScript 开发者没有了解 WebTransport 数据报的大小限制，或者在没有分片的情况下发送了较大的数据。

4. **在流的读取侧或写入侧关闭后尝试操作:**
    *   **用户操作:**  JavaScript 代码在调用 `stream.readable.getReader().cancel()` 或 `stream.writable.getWriter().close()` 后，仍然尝试读取或写入该流。
    *   **C++ 错误:** `InnerStream::Read()` 或 `InnerStream::Writev()` 会检查 `read_side_closed_` 和 `write_side_closed_` 标志。如果相应的侧已关闭，会返回错误状态 (例如 `absl::FailedPreconditionError`)。
    *   **例子:**  JavaScript 开发者在关闭流的写入侧后，仍然尝试向该流写入数据。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设开发者在 JavaScript 中遇到了一个问题，即他们发送的 WebTransport 数据报没有被服务器收到。以下是如何追踪到 `encapsulated_web_transport.cc` 的一些调试线索：

1. **JavaScript 代码检查:** 开发者首先检查他们的 JavaScript 代码，确认 `transport.datagrams.send(data)` 被正确调用，并且 `data` 的内容是他们期望的。

2. **浏览器开发者工具:** 使用浏览器的开发者工具（例如 Chrome 的 "Network" 标签），开发者可能会看到与服务器建立的连接。如果使用的是封装的 WebTransport，他们可能看到的是普通的 TCP 连接。

3. **WebTransport API 事件:**  开发者可以监听 WebTransport API 的事件，例如 `transport.stateChange` 和 `transport.closed`，以了解连接的状态。

4. **C++ 日志 (如果可用):**  如果开发者可以访问 Chromium 的内部日志，他们可能会看到与 `encapsulated_web_transport.cc` 相关的日志消息。例如，如果数据报太大，可能会有类似 "Datagram is ... bytes long, while the specified maximum size is ..." 的日志。`QUICHE_DLOG` 宏用于输出这些日志。

5. **设置断点:**  如果开发者可以构建 Chromium 或运行调试版本的浏览器，他们可以在 `encapsulated_web_transport.cc` 中设置断点，例如在 `EncapsulatedSession::SendOrQueueDatagram()` 方法的开头。

6. **单步调试:**  当 JavaScript 代码执行到 `transport.datagrams.send(data)` 时，如果设置了断点，执行会暂停在 C++ 代码中。开发者可以单步执行代码，查看变量的值，例如 `datagram.size()`，以及 `state_` 的值，来了解数据报是否被成功发送，或者是否因为某些条件（例如会话已关闭，数据报过大）而被阻止。

7. **检查 `writer_` 的状态:**  在 `EncapsulatedSession::SendOrQueueDatagram()` 中，开发者可以检查 `writer_->CanWrite()` 的返回值，以了解底层的传输层是否可以接受数据。

8. **分析 Capsule 的序列化:**  开发者可以检查数据报是如何被封装成 WebTransport Capsule 的，以及 Capsule 的头部信息是否正确。这涉及到查看 `quiche::SerializeCapsule(Capsule::Datagram(datagram), allocator_)` 的执行过程。

通过以上步骤，开发者可以逐步深入到 `encapsulated_web_transport.cc` 的代码中，了解 WebTransport 数据报的发送流程，并找出问题所在。例如，他们可能会发现数据报的大小超过了限制，或者在尝试发送数据报时会话已经关闭。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/web_transport/encapsulated/encapsulated_web_transport.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/web_transport/encapsulated/encapsulated_web_transport.h"

#include <stdbool.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/container/node_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "quiche/common/capsule.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_callbacks.h"
#include "quiche/common/quiche_circular_deque.h"
#include "quiche/common/quiche_status_utils.h"
#include "quiche/common/quiche_stream.h"
#include "quiche/web_transport/web_transport.h"

namespace webtransport {

namespace {

using ::quiche::Capsule;
using ::quiche::CapsuleType;
using ::quiche::CloseWebTransportSessionCapsule;

// This is arbitrary, since we don't have any real MTU restriction when running
// over TCP.
constexpr uint64_t kEncapsulatedMaxDatagramSize = 9000;

constexpr StreamPriority kDefaultPriority = StreamPriority{0, 0};

}  // namespace

EncapsulatedSession::EncapsulatedSession(
    Perspective perspective, FatalErrorCallback fatal_error_callback)
    : perspective_(perspective),
      fatal_error_callback_(std::move(fatal_error_callback)),
      capsule_parser_(this),
      next_outgoing_bidi_stream_(perspective == Perspective::kClient ? 0 : 1),
      next_outgoing_unidi_stream_(perspective == Perspective::kClient ? 2 : 3) {
  QUICHE_DCHECK(IsIdOpenedBy(next_outgoing_bidi_stream_, perspective));
  QUICHE_DCHECK(IsIdOpenedBy(next_outgoing_unidi_stream_, perspective));
}

void EncapsulatedSession::InitializeClient(
    std::unique_ptr<SessionVisitor> visitor,
    quiche::HttpHeaderBlock& /*outgoing_headers*/, quiche::WriteStream* writer,
    quiche::ReadStream* reader) {
  if (state_ != kUninitialized) {
    OnFatalError("Called InitializeClient() in an invalid state");
    return;
  }
  if (perspective_ != Perspective::kClient) {
    OnFatalError("Called InitializeClient() on a server session");
    return;
  }

  visitor_ = std::move(visitor);
  writer_ = writer;
  reader_ = reader;
  state_ = kWaitingForHeaders;
}

void EncapsulatedSession::InitializeServer(
    std::unique_ptr<SessionVisitor> visitor,
    const quiche::HttpHeaderBlock& /*incoming_headers*/,
    quiche::HttpHeaderBlock& /*outgoing_headers*/, quiche::WriteStream* writer,
    quiche::ReadStream* reader) {
  if (state_ != kUninitialized) {
    OnFatalError("Called InitializeServer() in an invalid state");
    return;
  }
  if (perspective_ != Perspective::kServer) {
    OnFatalError("Called InitializeServer() on a client session");
    return;
  }

  visitor_ = std::move(visitor);
  writer_ = writer;
  reader_ = reader;
  OpenSession();
}
void EncapsulatedSession::ProcessIncomingServerHeaders(
    const quiche::HttpHeaderBlock& /*headers*/) {
  if (state_ != kWaitingForHeaders) {
    OnFatalError("Called ProcessIncomingServerHeaders() in an invalid state");
    return;
  }
  OpenSession();
}

void EncapsulatedSession::CloseSession(SessionErrorCode error_code,
                                       absl::string_view error_message) {
  switch (state_) {
    case kUninitialized:
    case kWaitingForHeaders:
      OnFatalError(absl::StrCat(
          "Attempted to close a session before it opened with error 0x",
          absl::Hex(error_code), ": ", error_message));
      return;
    case kSessionClosing:
    case kSessionClosed:
      OnFatalError(absl::StrCat(
          "Attempted to close a session that is already closed with error 0x",
          absl::Hex(error_code), ": ", error_message));
      return;
    case kSessionOpen:
      break;
  }
  state_ = kSessionClosing;
  buffered_session_close_ =
      BufferedClose{error_code, std::string(error_message)};
  OnCanWrite();
}

Stream* EncapsulatedSession::AcceptIncomingStream(
    quiche::QuicheCircularDeque<StreamId>& queue) {
  while (!queue.empty()) {
    StreamId id = queue.front();
    queue.pop_front();
    Stream* stream = GetStreamById(id);
    if (stream == nullptr) {
      // Stream got reset and garbage collected before the peer ever had a
      // chance to look at it.
      continue;
    }
    return stream;
  }
  return nullptr;
}

Stream* EncapsulatedSession::AcceptIncomingBidirectionalStream() {
  return AcceptIncomingStream(incoming_bidirectional_streams_);
}
Stream* EncapsulatedSession::AcceptIncomingUnidirectionalStream() {
  return AcceptIncomingStream(incoming_unidirectional_streams_);
}
bool EncapsulatedSession::CanOpenNextOutgoingBidirectionalStream() {
  // TODO: implement flow control.
  return true;
}
bool EncapsulatedSession::CanOpenNextOutgoingUnidirectionalStream() {
  // TODO: implement flow control.
  return true;
}
Stream* EncapsulatedSession::OpenOutgoingStream(StreamId& counter) {
  StreamId stream_id = counter;
  counter += 4;
  auto [it, inserted] = streams_.emplace(
      std::piecewise_construct, std::forward_as_tuple(stream_id),
      std::forward_as_tuple(this, stream_id));
  QUICHE_DCHECK(inserted);
  return &it->second;
}
Stream* EncapsulatedSession::OpenOutgoingBidirectionalStream() {
  if (!CanOpenNextOutgoingBidirectionalStream()) {
    return nullptr;
  }
  return OpenOutgoingStream(next_outgoing_bidi_stream_);
}
Stream* EncapsulatedSession::OpenOutgoingUnidirectionalStream() {
  if (!CanOpenNextOutgoingUnidirectionalStream()) {
    return nullptr;
  }
  return OpenOutgoingStream(next_outgoing_unidi_stream_);
}

Stream* EncapsulatedSession::GetStreamById(StreamId id) {
  auto it = streams_.find(id);
  if (it == streams_.end()) {
    return nullptr;
  }
  return &it->second;
}

DatagramStats EncapsulatedSession::GetDatagramStats() {
  DatagramStats stats;
  stats.expired_outgoing = 0;
  stats.lost_outgoing = 0;
  return stats;
}

SessionStats EncapsulatedSession::GetSessionStats() {
  // We could potentially get stats via tcp_info and similar mechanisms, but
  // that would require us knowing what the underlying socket is.
  return SessionStats();
}

void EncapsulatedSession::NotifySessionDraining() {
  SendControlCapsule(quiche::DrainWebTransportSessionCapsule());
  OnCanWrite();
}
void EncapsulatedSession::SetOnDraining(
    quiche::SingleUseCallback<void()> callback) {
  draining_callback_ = std::move(callback);
}

DatagramStatus EncapsulatedSession::SendOrQueueDatagram(
    absl::string_view datagram) {
  if (datagram.size() > GetMaxDatagramSize()) {
    return DatagramStatus{
        DatagramStatusCode::kTooBig,
        absl::StrCat("Datagram is ", datagram.size(),
                     " bytes long, while the specified maximum size is ",
                     GetMaxDatagramSize())};
  }

  bool write_blocked;
  switch (state_) {
    case kUninitialized:
      write_blocked = true;
      break;
    // We can send datagrams before receiving any headers from the peer, since
    // datagrams are not subject to queueing.
    case kWaitingForHeaders:
    case kSessionOpen:
      write_blocked = !writer_->CanWrite();
      break;
    case kSessionClosing:
    case kSessionClosed:
      return DatagramStatus{DatagramStatusCode::kInternalError,
                            "Writing into an already closed session"};
  }

  if (write_blocked) {
    // TODO: this *may* be useful to split into a separate queue.
    control_capsule_queue_.push_back(
        quiche::SerializeCapsule(Capsule::Datagram(datagram), allocator_));
    return DatagramStatus{DatagramStatusCode::kSuccess, ""};
  }

  // We could always write via OnCanWrite() above, but the optimistic path below
  // allows us to avoid a copy.
  quiche::QuicheBuffer buffer =
      quiche::SerializeDatagramCapsuleHeader(datagram.size(), allocator_);
  std::array spans = {buffer.AsStringView(), datagram};
  absl::Status write_status =
      writer_->Writev(absl::MakeConstSpan(spans), quiche::StreamWriteOptions());
  if (!write_status.ok()) {
    OnWriteError(write_status);
    return DatagramStatus{
        DatagramStatusCode::kInternalError,
        absl::StrCat("Write error for datagram: ", write_status.ToString())};
  }
  return DatagramStatus{DatagramStatusCode::kSuccess, ""};
}

uint64_t EncapsulatedSession::GetMaxDatagramSize() const {
  return kEncapsulatedMaxDatagramSize;
}

void EncapsulatedSession::SetDatagramMaxTimeInQueue(
    absl::Duration /*max_time_in_queue*/) {
  // TODO(b/264263113): implement this (requires having a mockable clock).
}

void EncapsulatedSession::OnCanWrite() {
  if (state_ == kUninitialized || !writer_) {
    OnFatalError("Trying to write before the session is initialized");
    return;
  }
  if (state_ == kSessionClosed) {
    OnFatalError("Trying to write before the session is closed");
    return;
  }

  if (state_ == kSessionClosing) {
    if (writer_->CanWrite()) {
      CloseWebTransportSessionCapsule capsule{
          buffered_session_close_.error_code,
          buffered_session_close_.error_message};
      quiche::QuicheBuffer buffer =
          quiche::SerializeCapsule(Capsule(std::move(capsule)), allocator_);
      absl::Status write_status = SendFin(buffer.AsStringView());
      if (!write_status.ok()) {
        OnWriteError(quiche::AppendToStatus(write_status,
                                            " while writing WT_CLOSE_SESSION"));
        return;
      }
      OnSessionClosed(buffered_session_close_.error_code,
                      buffered_session_close_.error_message);
    }
    return;
  }

  while (writer_->CanWrite() && !control_capsule_queue_.empty()) {
    absl::Status write_status = quiche::WriteIntoStream(
        *writer_, control_capsule_queue_.front().AsStringView());
    if (!write_status.ok()) {
      OnWriteError(write_status);
      return;
    }
    control_capsule_queue_.pop_front();
  }

  while (writer_->CanWrite()) {
    absl::StatusOr<StreamId> next_id = scheduler_.PopFront();
    if (!next_id.ok()) {
      QUICHE_DCHECK_EQ(next_id.status().code(), absl::StatusCode::kNotFound);
      return;
    }
    auto it = streams_.find(*next_id);
    if (it == streams_.end()) {
      QUICHE_BUG(WT_H2_NextStreamNotInTheMap);
      OnFatalError("Next scheduled stream is not in the map");
      return;
    }
    QUICHE_DCHECK(it->second.HasPendingWrite());
    it->second.FlushPendingWrite();
  }
}

void EncapsulatedSession::OnCanRead() {
  if (state_ == kSessionClosed || state_ == kSessionClosing) {
    return;
  }
  bool has_fin = quiche::ProcessAllReadableRegions(
      *reader_, [&](absl::string_view fragment) {
        capsule_parser_.IngestCapsuleFragment(fragment);
      });
  if (has_fin) {
    capsule_parser_.ErrorIfThereIsRemainingBufferedData();
    OnSessionClosed(0, "");
  }
  if (state_ == kSessionOpen) {
    GarbageCollectStreams();
  }
}

bool EncapsulatedSession::OnCapsule(const quiche::Capsule& capsule) {
  switch (capsule.capsule_type()) {
    case CapsuleType::DATAGRAM:
      visitor_->OnDatagramReceived(
          capsule.datagram_capsule().http_datagram_payload);
      break;
    case CapsuleType::DRAIN_WEBTRANSPORT_SESSION:
      if (draining_callback_) {
        std::move(draining_callback_)();
      }
      break;
    case CapsuleType::CLOSE_WEBTRANSPORT_SESSION:
      OnSessionClosed(
          capsule.close_web_transport_session_capsule().error_code,
          std::string(
              capsule.close_web_transport_session_capsule().error_message));
      break;
    case CapsuleType::WT_STREAM:
    case CapsuleType::WT_STREAM_WITH_FIN:
      ProcessStreamCapsule(capsule,
                           capsule.web_transport_stream_data().stream_id);
      break;
    case CapsuleType::WT_RESET_STREAM:
      ProcessStreamCapsule(capsule,
                           capsule.web_transport_reset_stream().stream_id);
      break;
    case CapsuleType::WT_STOP_SENDING:
      ProcessStreamCapsule(capsule,
                           capsule.web_transport_stop_sending().stream_id);
      break;
    default:
      break;
  }
  return state_ != kSessionClosed;
}

void EncapsulatedSession::OnCapsuleParseFailure(
    absl::string_view error_message) {
  if (state_ == kSessionClosed) {
    return;
  }
  OnFatalError(absl::StrCat("Stream parse error: ", error_message));
}

void EncapsulatedSession::ProcessStreamCapsule(const quiche::Capsule& capsule,
                                               StreamId stream_id) {
  bool new_stream_created = false;
  auto it = streams_.find(stream_id);
  if (it == streams_.end()) {
    if (IsOutgoing(stream_id)) {
      // Ignore this frame, as it is possible that it refers to an outgoing
      // stream that has been closed.
      return;
    }
    // TODO: check flow control here.
    it = streams_.emplace_hint(it, std::piecewise_construct,
                               std::forward_as_tuple(stream_id),
                               std::forward_as_tuple(this, stream_id));
    new_stream_created = true;
  }
  InnerStream& stream = it->second;
  stream.ProcessCapsule(capsule);
  if (new_stream_created) {
    if (IsBidirectionalId(stream_id)) {
      incoming_bidirectional_streams_.push_back(stream_id);
      visitor_->OnIncomingBidirectionalStreamAvailable();
    } else {
      incoming_unidirectional_streams_.push_back(stream_id);
      visitor_->OnIncomingUnidirectionalStreamAvailable();
    }
  }
}

void EncapsulatedSession::InnerStream::ProcessCapsule(
    const quiche::Capsule& capsule) {
  switch (capsule.capsule_type()) {
    case CapsuleType::WT_STREAM:
    case CapsuleType::WT_STREAM_WITH_FIN: {
      if (fin_received_) {
        session_->OnFatalError(
            "Received stream data for a stream that has already received a "
            "FIN");
        return;
      }
      if (read_side_closed_) {
        // It is possible that we sent STOP_SENDING but it has not been received
        // yet. Ignore.
        return;
      }
      fin_received_ = capsule.capsule_type() == CapsuleType::WT_STREAM_WITH_FIN;
      const quiche::WebTransportStreamDataCapsule& data =
          capsule.web_transport_stream_data();
      if (!data.data.empty()) {
        incoming_reads_.push_back(IncomingRead{data.data, std::string()});
      }
      // Fast path: if the visitor consumes all of the incoming reads, we don't
      // need to copy data from the capsule parser.
      if (visitor_ != nullptr) {
        visitor_->OnCanRead();
      }
      // Slow path: copy all data that the visitor have not consumed.
      for (IncomingRead& read : incoming_reads_) {
        QUICHE_DCHECK(!read.data.empty());
        if (read.storage.empty()) {
          read.storage = std::string(read.data);
          read.data = read.storage;
        }
      }
      return;
    }
    case CapsuleType::WT_RESET_STREAM:
      CloseReadSide(capsule.web_transport_reset_stream().error_code);
      return;
    case CapsuleType::WT_STOP_SENDING:
      CloseWriteSide(capsule.web_transport_stop_sending().error_code);
      return;
    default:
      QUICHE_BUG(WT_H2_ProcessStreamCapsule_Unknown)
          << "Unexpected capsule dispatched to InnerStream: " << capsule;
      session_->OnFatalError(
          "Internal error: Unexpected capsule dispatched to InnerStream");
      return;
  }
}

void EncapsulatedSession::OpenSession() {
  state_ = kSessionOpen;
  visitor_->OnSessionReady();
  OnCanWrite();
  OnCanRead();
}

absl::Status EncapsulatedSession::SendFin(absl::string_view data) {
  QUICHE_DCHECK(!fin_sent_);
  fin_sent_ = true;
  quiche::StreamWriteOptions options;
  options.set_send_fin(true);
  return quiche::WriteIntoStream(*writer_, data, options);
}

void EncapsulatedSession::OnSessionClosed(SessionErrorCode error_code,
                                          const std::string& error_message) {
  if (!fin_sent_) {
    absl::Status status = SendFin("");
    if (!status.ok()) {
      OnWriteError(status);
      return;
    }
  }

  if (session_close_notified_) {
    QUICHE_DCHECK_EQ(state_, kSessionClosed);
    return;
  }
  state_ = kSessionClosed;
  session_close_notified_ = true;

  if (visitor_ != nullptr) {
    visitor_->OnSessionClosed(error_code, error_message);
  }
}

void EncapsulatedSession::OnFatalError(absl::string_view error_message) {
  QUICHE_DLOG(ERROR) << "Fatal error in encapsulated WebTransport: "
                     << error_message;
  state_ = kSessionClosed;
  if (fatal_error_callback_) {
    std::move(fatal_error_callback_)(error_message);
    fatal_error_callback_ = nullptr;
  }
}

void EncapsulatedSession::OnWriteError(absl::Status error) {
  OnFatalError(absl::StrCat(
      error, " while trying to write encapsulated WebTransport data"));
}

EncapsulatedSession::InnerStream::InnerStream(EncapsulatedSession* session,
                                              StreamId id)
    : session_(session),
      id_(id),
      read_side_closed_(IsUnidirectionalId(id) &&
                        IsIdOpenedBy(id, session->perspective_)),
      write_side_closed_(IsUnidirectionalId(id) &&
                         !IsIdOpenedBy(id, session->perspective_)) {
  if (!write_side_closed_) {
    absl::Status status = session_->scheduler_.Register(id_, kDefaultPriority);
    if (!status.ok()) {
      QUICHE_BUG(WT_H2_FailedToRegisterNewStream) << status;
      session_->OnFatalError(
          "Failed to register new stream with the scheduler");
      return;
    }
  }
}

quiche::ReadStream::ReadResult EncapsulatedSession::InnerStream::Read(
    absl::Span<char> output) {
  const size_t total_size = output.size();
  for (const IncomingRead& read : incoming_reads_) {
    size_t size_to_read = std::min(read.size(), output.size());
    if (size_to_read == 0) {
      break;
    }
    memcpy(output.data(), read.data.data(), size_to_read);
    output = output.subspan(size_to_read);
  }
  bool fin_consumed = SkipBytes(total_size);
  return ReadResult{total_size, fin_consumed};
}
quiche::ReadStream::ReadResult EncapsulatedSession::InnerStream::Read(
    std::string* output) {
  const size_t total_size = ReadableBytes();
  const size_t initial_offset = output->size();
  output->resize(initial_offset + total_size);
  return Read(absl::Span<char>(&((*output)[initial_offset]), total_size));
}
size_t EncapsulatedSession::InnerStream::ReadableBytes() const {
  size_t total_size = 0;
  for (const IncomingRead& read : incoming_reads_) {
    total_size += read.size();
  }
  return total_size;
}
quiche::ReadStream::PeekResult
EncapsulatedSession::InnerStream::PeekNextReadableRegion() const {
  if (incoming_reads_.empty()) {
    return PeekResult{absl::string_view(), fin_received_, fin_received_};
  }
  return PeekResult{incoming_reads_.front().data,
                    fin_received_ && incoming_reads_.size() == 1,
                    fin_received_};
}

bool EncapsulatedSession::InnerStream::SkipBytes(size_t bytes) {
  size_t remaining = bytes;
  while (remaining > 0) {
    if (incoming_reads_.empty()) {
      QUICHE_BUG(WT_H2_SkipBytes_toomuch)
          << "Requested to skip " << remaining
          << " bytes that are not present in the read buffer.";
      return false;
    }
    IncomingRead& current = incoming_reads_.front();
    if (remaining < current.size()) {
      current.data = current.data.substr(remaining);
      return false;
    }
    remaining -= current.size();
    incoming_reads_.pop_front();
  }
  if (incoming_reads_.empty() && fin_received_) {
    fin_consumed_ = true;
    CloseReadSide(std::nullopt);
    return true;
  }
  return false;
}

absl::Status EncapsulatedSession::InnerStream::Writev(
    const absl::Span<const absl::string_view> data,
    const quiche::StreamWriteOptions& options) {
  if (write_side_closed_) {
    return absl::FailedPreconditionError(
        "Trying to write into an already-closed stream");
  }
  if (fin_buffered_) {
    return absl::FailedPreconditionError("FIN already buffered");
  }
  if (!CanWrite()) {
    return absl::FailedPreconditionError(
        "Trying to write into a stream when CanWrite() = false");
  }

  const absl::StatusOr<bool> should_yield =
      session_->scheduler_.ShouldYield(id_);
  if (!should_yield.ok()) {
    QUICHE_BUG(WT_H2_Writev_NotRegistered) << should_yield.status();
    session_->OnFatalError("Stream not registered with the scheduler");
    return absl::InternalError("Stream not registered with the scheduler");
  }
  const bool write_blocked = !session_->writer_->CanWrite() || *should_yield ||
                             !pending_write_.empty();
  if (write_blocked) {
    fin_buffered_ = options.send_fin();
    for (absl::string_view chunk : data) {
      absl::StrAppend(&pending_write_, chunk);
    }
    absl::Status status = session_->scheduler_.Schedule(id_);
    if (!status.ok()) {
      QUICHE_BUG(WT_H2_Writev_CantSchedule) << status;
      session_->OnFatalError("Could not schedule a write-blocked stream");
      return absl::InternalError("Could not schedule a write-blocked stream");
    }
    return absl::OkStatus();
  }

  size_t bytes_written = WriteInner(data, options.send_fin());
  // TODO: handle partial writes when flow control requires those.
  QUICHE_DCHECK(bytes_written == 0 ||
                bytes_written == quiche::TotalStringViewSpanSize(data));
  if (bytes_written == 0) {
    for (absl::string_view chunk : data) {
      absl::StrAppend(&pending_write_, chunk);
    }
  }

  if (options.send_fin()) {
    CloseWriteSide(std::nullopt);
  }
  return absl::OkStatus();
}

bool EncapsulatedSession::InnerStream::CanWrite() const {
  return session_->state_ != EncapsulatedSession::kSessionClosed &&
         !write_side_closed_ &&
         (pending_write_.size() <= session_->max_stream_data_buffered_);
}

void EncapsulatedSession::InnerStream::FlushPendingWrite() {
  QUICHE_DCHECK(!write_side_closed_);
  QUICHE_DCHECK(session_->writer_->CanWrite());
  QUICHE_DCHECK(!pending_write_.empty());
  absl::string_view to_write = pending_write_;
  size_t bytes_written =
      WriteInner(absl::MakeSpan(&to_write, 1), fin_buffered_);
  if (bytes_written < to_write.size()) {
    pending_write_ = pending_write_.substr(bytes_written);
    return;
  }
  pending_write_.clear();
  if (fin_buffered_) {
    CloseWriteSide(std::nullopt);
  }
  if (!write_side_closed_ && visitor_ != nullptr) {
    visitor_->OnCanWrite();
  }
}

size_t EncapsulatedSession::InnerStream::WriteInner(
    absl::Span<const absl::string_view> data, bool fin) {
  size_t total_size = quiche::TotalStringViewSpanSize(data);
  if (total_size == 0 && !fin) {
    session_->OnFatalError("Attempted to make an empty write with fin=false");
    return 0;
  }
  quiche::QuicheBuffer header =
      quiche::SerializeWebTransportStreamCapsuleHeader(id_, fin, total_size,
                                                       session_->allocator_);
  std::vector<absl::string_view> views_to_write;
  views_to_write.reserve(data.size() + 1);
  views_to_write.push_back(header.AsStringView());
  absl::c_copy(data, std::back_inserter(views_to_write));
  absl::Status write_status = session_->writer_->Writev(
      views_to_write, quiche::kDefaultStreamWriteOptions);
  if (!write_status.ok()) {
    session_->OnWriteError(write_status);
    return 0;
  }
  return total_size;
}

void EncapsulatedSession::InnerStream::AbruptlyTerminate(absl::Status error) {
  QUICHE_DLOG(INFO) << "Abruptly terminating the stream due to error: "
                    << error;
  ResetDueToInternalError();
}

void EncapsulatedSession::InnerStream::ResetWithUserCode(
    StreamErrorCode error) {
  if (reset_frame_sent_) {
    return;
  }
  reset_frame_sent_ = true;

  session_->SendControlCapsule(
      quiche::WebTransportResetStreamCapsule{id_, error});
  CloseWriteSide(std::nullopt);
}

void EncapsulatedSession::InnerStream::SendStopSending(StreamErrorCode error) {
  if (stop_sending_sent_) {
    return;
  }
  stop_sending_sent_ = true;

  session_->SendControlCapsule(
      quiche::WebTransportStopSendingCapsule{id_, error});
  CloseReadSide(std::nullopt);
}

void EncapsulatedSession::InnerStream::CloseReadSide(
    std::optional<StreamErrorCode> error) {
  if (read_side_closed_) {
    return;
  }
  read_side_closed_ = true;
  incoming_reads_.clear();
  if (error.has_value() && visitor_ != nullptr) {
    visitor_->OnResetStreamReceived(*error);
  }
  if (CanBeGarbageCollected()) {
    session_->streams_to_garbage_collect_.push_back(id_);
  }
}

void EncapsulatedSession::InnerStream::CloseWriteSide(
    std::optional<StreamErrorCode> error) {
  if (write_side_closed_) {
    return;
  }
  write_side_closed_ = true;
  pending_write_.clear();
  absl::Status status = session_->scheduler_.Unregister(id_);
  if (!status.ok()) {
    session_->OnFatalError("Failed to unregister closed stream");
    return;
  }
  if (error.has_value() && visitor_ != nullptr) {
    visitor_->OnStopSendingReceived(*error);
  }
  if (CanBeGarbageCollected()) {
    session_->streams_to_garbage_collect_.push_back(id_);
  }
}

void EncapsulatedSession::GarbageCollectStreams() {
  for (StreamId id : streams_to_garbage_collect_) {
    streams_.erase(id);
  }
  streams_to_garbage_collect_.clear();
}

void EncapsulatedSession::InnerStream::SetPriority(
    const StreamPriority& priority) {
  absl::Status status;
  status = session_->scheduler_.UpdateSendGroup(id_, priority.send_group_id);
  QUICHE_BUG_IF(EncapsulatedWebTransport_SetPriority_group, !status.ok())
      << status;
  status = session_->scheduler_.UpdateSendOrder(id_, priority.send_order);
  QUICHE_BUG_IF(EncapsulatedWebTransport_SetPriority_order, !status.ok())
      << status;
}
}  // namespace webtransport

"""

```