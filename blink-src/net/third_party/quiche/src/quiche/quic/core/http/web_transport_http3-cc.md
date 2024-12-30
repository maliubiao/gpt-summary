Response:
My thinking process to answer the request goes through these stages:

1. **Understand the Goal:** The request asks for a breakdown of the `web_transport_http3.cc` file's functionality within the Chromium network stack. It specifically asks for connections to JavaScript, logical reasoning examples, common usage errors, and debugging information.

2. **High-Level Analysis:**  I first scan the code for key elements:
    * Includes: Identify core QUIC and WebTransport components. This tells me the file is responsible for the WebTransport protocol over HTTP/3 using QUIC.
    * Class Declaration: The `WebTransportHttp3` class is central. I note its relationship to `QuicSpdySession` and `QuicSpdyStream`, indicating its integration into the QUIC stack.
    * Methods: I quickly skim the public methods like `CloseSession`, `AcceptIncomingBidirectionalStream`, `SendOrQueueDatagram`, etc. These provide hints about the core actions this class manages.
    * Visitor Pattern: The presence of `WebTransportVisitor` suggests a callback mechanism for notifying higher layers about events.
    * Datagram Handling:  The interaction with `Http3DatagramVisitor` points to datagram functionality.
    * Stream Management: Methods for accepting and opening streams are present.
    * Error Handling: The handling of `error_code` and `error_message` is evident in methods like `CloseSession` and `OnCloseReceived`.
    * Preamble for Unidirectional Streams: The `WebTransportHttp3UnidirectionalStream` class and its `WritePreamble` method stand out.
    * Error Code Mapping: The functions `Http3ErrorToWebTransport` and `WebTransportErrorToHttp3` indicate a translation layer between HTTP/3 and WebTransport error codes.

3. **Detailed Functionality Breakdown:** I go through the code more carefully, method by method, to understand the specific purpose of each function:

    * **Initialization (`WebTransportHttp3` constructor):**  Sets up the connection with a QUIC session and connect stream.
    * **Stream Association (`AssociateStream`):**  Keeps track of streams belonging to the WebTransport session and notifies the visitor about incoming streams.
    * **Session Closing (`OnConnectStreamClosing`, `CloseSession`, `OnCloseReceived`, `OnConnectStreamFinReceived`):** Handles different scenarios of session closure, including sending and receiving close signals. The logic around `close_sent_` and `close_received_` is crucial for avoiding redundant actions.
    * **Session Readiness (`HeadersReceived`):**  Processes the HTTP headers of the connect stream to determine if the WebTransport handshake was successful. Crucially, it notifies the visitor via `OnSessionReady`.
    * **Stream Acceptance (`AcceptIncomingBidirectionalStream`, `AcceptIncomingUnidirectionalStream`):**  Provides a way for the application to get newly established incoming streams.
    * **Stream Opening (`CanOpenNextOutgoingBidirectionalStream`, `CanOpenNextOutgoingUnidirectionalStream`, `OpenOutgoingBidirectionalStream`, `OpenOutgoingUnidirectionalStream`):** Allows the application to create new outgoing streams.
    * **Stream Retrieval (`GetStreamById`):**  Provides a way to retrieve a stream based on its ID.
    * **Datagram Handling (`SendOrQueueDatagram`, `GetMaxDatagramSize`, `SetDatagramMaxTimeInQueue`, `OnHttp3Datagram`):** Manages the sending and receiving of WebTransport datagrams.
    * **Draining (`NotifySessionDraining`, `OnGoAwayReceived`, `OnDrainSessionReceived`):** Handles the process of gracefully shutting down the session.
    * **Visitor Notifications (`MaybeNotifyClose`):** Ensures the visitor is notified about session closure exactly once.
    * **Unidirectional Stream Handling (`WebTransportHttp3UnidirectionalStream`):**  Deals with the specifics of unidirectional streams, including sending and receiving the preamble that identifies the associated WebTransport session.
    * **Error Code Mapping:**  The utility functions convert error codes between the HTTP/3 and WebTransport layers.

4. **Connecting to JavaScript:**  I consider how this C++ code interacts with the browser's JavaScript APIs. The `WebTransport` API in JavaScript directly corresponds to the functionality implemented in this file. I identify key mappings:
    * JavaScript `WebTransport` object corresponds to `WebTransportHttp3`.
    * JavaScript `send()` on a `WebTransportDatagramDuplexStream` maps to `SendOrQueueDatagram`.
    * JavaScript `WebTransportBidirectionalStream` and `WebTransportUnidirectionalStream` map to the corresponding C++ stream classes.
    * Events like `session.ready`, `session.closed`, `datagrams.readable`, and `incomingUnidirectionalStreams.readable` are triggered via the `WebTransportVisitor` interface.

5. **Logical Reasoning Examples (Input/Output):** I think about specific method calls and their effects:
    * **`CloseSession`:** Input: `error_code`, `error_message`. Output: Sends a `CLOSE_WEBTRANSPORT_SESSION` capsule on the connect stream.
    * **`AcceptIncomingBidirectionalStream`:** Input: New incoming bidirectional stream arrives. Output: Returns a `WebTransportStream` object if available, otherwise `nullptr`.
    * **`SendOrQueueDatagram`:** Input: `datagram` data. Output: Returns a `DatagramStatus` indicating success or failure.

6. **Common Usage Errors:** I consider common mistakes a developer might make when using the WebTransport API, and how they could relate to the C++ implementation:
    * Closing the session multiple times.
    * Trying to open too many streams.
    * Sending data after the session is closed.
    * Not handling incoming streams or datagrams.

7. **Debugging Clues (User Actions):** I trace a typical user interaction that might lead to this code being executed:
    * Opening a webpage that uses the WebTransport API.
    * The JavaScript code initiates a `new WebTransport(...)` call.
    * The browser then negotiates an HTTP/3 connection and sends a CONNECT request for WebTransport.
    * The server responds with success headers.
    * This `web_transport_http3.cc` code is involved in handling the connect stream, creating WebTransport streams, and managing datagrams. Errors in this flow would involve checks within this file.

8. **Refine and Structure:**  I organize the information logically, using headings and bullet points to make it clear and easy to read. I ensure the language is precise and avoids jargon where possible. I double-check that I've addressed all parts of the original request.

By following these steps, I can systematically analyze the C++ code and provide a comprehensive answer that addresses all aspects of the user's request. The key is to understand the overall purpose, dissect the individual components, and then connect those components back to the user-facing aspects of the technology.
This C++ source file, `web_transport_http3.cc`, is a core component of Chromium's network stack responsible for implementing the **WebTransport protocol over HTTP/3**. It provides the underlying logic for managing WebTransport sessions and streams within a QUIC connection.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **WebTransport Session Management:**
   - **Creation and Initialization:**  It creates and initializes `WebTransportHttp3` objects, associating them with a specific QUIC session (`QuicSpdySession`) and the HTTP/3 CONNECT stream used for establishing the WebTransport session.
   - **Session ID Handling:**  It manages WebTransport session IDs to distinguish between different concurrent WebTransport sessions.
   - **Session Closure:**  Handles both initiating and responding to WebTransport session closure, including sending and receiving `CLOSE_WEBTRANSPORT_SESSION` capsules with optional error codes and messages.
   - **Session Readiness:**  Determines when a WebTransport session is ready for use after the initial handshake.
   - **Session Draining (Graceful Shutdown):** Implements logic for the "draining" process, allowing a session to finish ongoing operations before being fully closed.

2. **Bidirectional and Unidirectional Stream Management:**
   - **Accepting Incoming Streams:**  Provides mechanisms to accept new bidirectional and unidirectional streams initiated by the remote endpoint.
   - **Opening Outgoing Streams:**  Allows the local endpoint to create new outgoing bidirectional and unidirectional streams.
   - **Stream Association:**  Keeps track of all QUIC streams that belong to a specific WebTransport session.
   - **Stream ID Retrieval:** Provides a way to get a `webtransport::Stream` object given its `webtransport::StreamId`.

3. **Datagram Handling:**
   - **Sending Datagrams:** Enables sending WebTransport datagrams over the associated CONNECT stream.
   - **Receiving Datagrams:**  Handles incoming WebTransport datagrams.
   - **Datagram Queue Management:** Allows setting maximum time datagrams can stay in a queue before being discarded.
   - **Retrieving Max Datagram Size:** Provides the maximum size of datagrams that can be sent.

4. **Error Handling:**
   - **Error Code Mapping:** Includes functions to map HTTP/3 error codes to WebTransport-specific error codes and vice-versa. This ensures consistent error reporting across different layers.
   - **Rejection Handling:**  Handles cases where the WebTransport session establishment is rejected by the server (e.g., due to incorrect status codes).

5. **Integration with QUIC:**
   - It relies heavily on QUIC's stream multiplexing and reliable transport features.
   - It uses QUIC capsules for sending WebTransport-specific control messages like `CLOSE_WEBTRANSPORT_SESSION` and `DRAIN_WEBTRANSPORT_SESSION`.
   - It interacts with `QuicSpdySession` and `QuicSpdyStream` (for bidirectional streams) and `QuicStream` (for unidirectional streams).

6. **Visitor Pattern:**
   - It employs the `WebTransportVisitor` interface to notify higher-level code about important WebTransport session events (e.g., session ready, session closed, new streams available, datagram received). This decouples the core WebTransport logic from the specific application using it.

**Relationship with JavaScript Functionality:**

This C++ code directly underpins the **WebTransport API available in JavaScript**. When JavaScript code in a browser uses the `WebTransport` API, the underlying implementation in Chromium relies on this `web_transport_http3.cc` file.

Here are some examples of how JavaScript actions relate to the C++ code:

* **`const transport = new WebTransport('https://example.com');` (JavaScript):**  This initiates a WebTransport connection. In the C++ code, this would eventually lead to the creation of a `WebTransportHttp3` object, likely within the context of handling a new QUIC connection and a corresponding HTTP/3 CONNECT request with the appropriate protocol.

* **`await transport.ready;` (JavaScript):** This waits for the WebTransport session to be established. In the C++ code, this corresponds to the `HeadersReceived` method being called when the server sends the success headers for the CONNECT request, which then sets the `ready_` flag and calls `visitor_->OnSessionReady()`.

* **`transport.close();` (JavaScript):** This closes the WebTransport session. This would trigger the `CloseSession` method in the C++ code, potentially sending a `CLOSE_WEBTRANSPORT_SESSION` capsule to the remote endpoint.

* **`const stream = await transport.createBidirectionalStream();` (JavaScript):** This creates a new bidirectional WebTransport stream. This would call the `OpenOutgoingBidirectionalStream` method in the C++ code, which in turn interacts with the QUIC session to create a new QUIC stream and associate it with the WebTransport session.

* **`transport.datagrams.readable.getReader().read();` (JavaScript):** This reads incoming WebTransport datagrams. This is handled by the `OnHttp3Datagram` method in the C++ code when a datagram arrives on the CONNECT stream.

* **`transport.send(new Uint8Array([1, 2, 3]));` (JavaScript):** This sends a WebTransport datagram. This calls the `SendOrQueueDatagram` method in the C++ code.

**Logical Reasoning Examples (Hypothetical Input and Output):**

Let's consider the `CloseSession` method:

**Hypothetical Input:**

* `error_code`: `WebTransportSessionError::kNoError`
* `error_message`: "Closing the session gracefully."

**Logical Reasoning:**

The `CloseSession` method is called. Since `close_sent_` is likely false initially, the following happens:

1. `close_sent_` is set to `true`.
2. It checks if `close_received_` is true. If not (meaning the local endpoint is initiating the closure), it proceeds.
3. A `CLOSE_WEBTRANSPORT_SESSION` capsule is created with the provided `error_code` and `error_message`.
4. This capsule is written to the `connect_stream_` with the `fin=true` flag, indicating the end of the stream.

**Hypothetical Output:**

* A QUIC frame containing a `CLOSE_WEBTRANSPORT_SESSION` capsule with error code `0` and message "Closing the session gracefully." is sent on the QUIC connection associated with the `connect_stream_`.
* The `connect_stream_` is closed.

**Common Usage Errors and Examples:**

1. **Closing the session multiple times:**
   - **User Action (JavaScript):** Calling `transport.close()` multiple times.
   - **C++ Handling:** The `CloseSession` method has a check for `close_sent_`. If called again, it will trigger a `QUIC_BUG` because it's an unexpected state.
   - **Error Indication:**  Potentially no immediate visible error in JavaScript, but might lead to unexpected behavior or resource leaks if the underlying QUIC connection isn't handled correctly.

2. **Trying to open streams after closing the session:**
   - **User Action (JavaScript):** Calling `transport.createBidirectionalStream()` after `transport.close()` has been called.
   - **C++ Handling:**  Methods like `OpenOutgoingBidirectionalStream` would likely check if the session is still active. If `close_sent_` is true, these methods would likely return `nullptr` or an error, indicating that no new streams can be created.
   - **Error Indication (JavaScript):** The promise returned by `createBidirectionalStream()` would likely reject with an error indicating the session is closed.

3. **Not handling incoming streams or datagrams:**
   - **User Action (JavaScript):** Not attaching listeners to `transport.incomingBidirectionalStreams`, `transport.incomingUnidirectionalStreams`, or `transport.datagrams.readable`.
   - **C++ Handling:** The `WebTransportHttp3` object will still receive notifications about new streams and datagrams. The `visitor_->OnIncomingBidirectionalStreamAvailable()` and `visitor_->OnDatagramReceived()` methods will be called.
   - **Error Indication:** Data might be buffered indefinitely, potentially leading to memory issues or eventually being dropped if buffers fill up. From a user's perspective, the application might not function correctly as it's not processing incoming data.

**User Operations Leading to this Code (Debugging Clues):**

To reach this code during debugging, a user would typically be interacting with a web page that utilizes the WebTransport API. Here's a step-by-step scenario:

1. **User navigates to a website:** The user opens a website in their Chromium-based browser.
2. **Website uses WebTransport:** The website's JavaScript code attempts to establish a WebTransport connection using `new WebTransport('https://...');`.
3. **QUIC connection establishment:** The browser initiates a QUIC connection to the server if one doesn't already exist.
4. **HTTP/3 CONNECT request:** The browser sends an HTTP/3 CONNECT request to the server, indicating the intention to establish a WebTransport session. This request is handled by Chromium's networking stack.
5. **`WebTransportHttp3` creation:** If the server accepts the CONNECT request, the Chromium network stack creates a `WebTransportHttp3` object, associating it with the relevant QUIC session and the CONNECT stream. This is where the code in `web_transport_http3.cc` starts to become active.
6. **Handling control messages:**  The `WebTransportHttp3` object handles incoming and outgoing WebTransport control messages (capsules) on the CONNECT stream.
7. **Stream creation and management:** When the JavaScript code creates or receives WebTransport streams, the methods in `web_transport_http3.cc` (like `OpenOutgoingBidirectionalStream`, `AcceptIncomingUnidirectionalStream`, etc.) are invoked.
8. **Datagram sending and receiving:** When the JavaScript code sends or receives datagrams, the `SendOrQueueDatagram` and `OnHttp3Datagram` methods are used.
9. **Session closure:** When the JavaScript code closes the connection or the server initiates closure, the methods related to session closure in this file are executed.

**Debugging Entry Points:**

A debugger could be attached to the Chromium process, and breakpoints could be set in `web_transport_http3.cc` at key points like:

* The `WebTransportHttp3` constructor.
* `HeadersReceived` to see when the session becomes ready.
* `CloseSession` to understand the session closure process.
* `OnIncomingBidirectionalStreamAvailable` or `OnHttp3Datagram` to inspect incoming data.
* `SendOrQueueDatagram` to examine outgoing data.

By tracing the execution flow through these methods, developers can understand how the WebTransport session is being managed and debug any issues related to their WebTransport application.

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/web_transport_http3.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/web_transport_http3.h"

#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>


#include "absl/strings/string_view.h"
#include "quiche/quic/core/http/quic_spdy_session.h"
#include "quiche/quic/core/http/quic_spdy_stream.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_stream.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/common/capsule.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/web_transport/web_transport.h"

#define ENDPOINT \
  (session_->perspective() == Perspective::IS_SERVER ? "Server: " : "Client: ")

namespace quic {

namespace {
class NoopWebTransportVisitor : public WebTransportVisitor {
  void OnSessionReady() override {}
  void OnSessionClosed(WebTransportSessionError /*error_code*/,
                       const std::string& /*error_message*/) override {}
  void OnIncomingBidirectionalStreamAvailable() override {}
  void OnIncomingUnidirectionalStreamAvailable() override {}
  void OnDatagramReceived(absl::string_view /*datagram*/) override {}
  void OnCanCreateNewOutgoingBidirectionalStream() override {}
  void OnCanCreateNewOutgoingUnidirectionalStream() override {}
};
}  // namespace

WebTransportHttp3::WebTransportHttp3(QuicSpdySession* session,
                                     QuicSpdyStream* connect_stream,
                                     WebTransportSessionId id)
    : session_(session),
      connect_stream_(connect_stream),
      id_(id),
      visitor_(std::make_unique<NoopWebTransportVisitor>()) {
  QUICHE_DCHECK(session_->SupportsWebTransport());
  QUICHE_DCHECK(IsValidWebTransportSessionId(id, session_->version()));
  QUICHE_DCHECK_EQ(connect_stream_->id(), id);
  connect_stream_->RegisterHttp3DatagramVisitor(this);
}

void WebTransportHttp3::AssociateStream(QuicStreamId stream_id) {
  streams_.insert(stream_id);

  ParsedQuicVersion version = session_->version();
  if (QuicUtils::IsOutgoingStreamId(version, stream_id,
                                    session_->perspective())) {
    return;
  }
  if (QuicUtils::IsBidirectionalStreamId(stream_id, version)) {
    incoming_bidirectional_streams_.push_back(stream_id);
    visitor_->OnIncomingBidirectionalStreamAvailable();
  } else {
    incoming_unidirectional_streams_.push_back(stream_id);
    visitor_->OnIncomingUnidirectionalStreamAvailable();
  }
}

void WebTransportHttp3::OnConnectStreamClosing() {
  // Copy the stream list before iterating over it, as calls to ResetStream()
  // can potentially mutate the |session_| list.
  std::vector<QuicStreamId> streams(streams_.begin(), streams_.end());
  streams_.clear();
  for (QuicStreamId id : streams) {
    session_->ResetStream(id, QUIC_STREAM_WEBTRANSPORT_SESSION_GONE);
  }
  connect_stream_->UnregisterHttp3DatagramVisitor();

  MaybeNotifyClose();
}

void WebTransportHttp3::CloseSession(WebTransportSessionError error_code,
                                     absl::string_view error_message) {
  if (close_sent_) {
    QUIC_BUG(WebTransportHttp3 close sent twice)
        << "Calling WebTransportHttp3::CloseSession() more than once is not "
           "allowed.";
    return;
  }
  close_sent_ = true;

  // There can be a race between us trying to send our close and peer sending
  // one.  If we received a close, however, we cannot send ours since we already
  // closed the stream in response.
  if (close_received_) {
    QUIC_DLOG(INFO) << "Not sending CLOSE_WEBTRANSPORT_SESSION as we've "
                       "already sent one from peer.";
    return;
  }

  error_code_ = error_code;
  error_message_ = std::string(error_message);
  QuicConnection::ScopedPacketFlusher flusher(
      connect_stream_->spdy_session()->connection());
  connect_stream_->WriteCapsule(
      quiche::Capsule::CloseWebTransportSession(error_code, error_message),
      /*fin=*/true);
}

void WebTransportHttp3::OnCloseReceived(WebTransportSessionError error_code,
                                        absl::string_view error_message) {
  if (close_received_) {
    QUIC_BUG(WebTransportHttp3 notified of close received twice)
        << "WebTransportHttp3::OnCloseReceived() may be only called once.";
  }
  close_received_ = true;

  // If the peer has sent a close after we sent our own, keep the local error.
  if (close_sent_) {
    QUIC_DLOG(INFO) << "Ignoring received CLOSE_WEBTRANSPORT_SESSION as we've "
                       "already sent our own.";
    return;
  }

  error_code_ = error_code;
  error_message_ = std::string(error_message);
  connect_stream_->WriteOrBufferBody("", /*fin=*/true);
  MaybeNotifyClose();
}

void WebTransportHttp3::OnConnectStreamFinReceived() {
  // If we already received a CLOSE_WEBTRANSPORT_SESSION capsule, we don't need
  // to do anything about receiving a FIN, since we already sent one in
  // response.
  if (close_received_) {
    return;
  }
  close_received_ = true;
  if (close_sent_) {
    QUIC_DLOG(INFO) << "Ignoring received FIN as we've already sent our close.";
    return;
  }

  connect_stream_->WriteOrBufferBody("", /*fin=*/true);
  MaybeNotifyClose();
}

void WebTransportHttp3::CloseSessionWithFinOnlyForTests() {
  QUICHE_DCHECK(!close_sent_);
  close_sent_ = true;
  if (close_received_) {
    return;
  }

  connect_stream_->WriteOrBufferBody("", /*fin=*/true);
}

void WebTransportHttp3::HeadersReceived(
    const quiche::HttpHeaderBlock& headers) {
  if (session_->perspective() == Perspective::IS_CLIENT) {
    int status_code;
    if (!QuicSpdyStream::ParseHeaderStatusCode(headers, &status_code)) {
      QUIC_DVLOG(1) << ENDPOINT
                    << "Received WebTransport headers from server without "
                       "a valid status code, rejecting.";
      rejection_reason_ = WebTransportHttp3RejectionReason::kNoStatusCode;
      return;
    }
    bool valid_status = status_code >= 200 && status_code <= 299;
    if (!valid_status) {
      QUIC_DVLOG(1) << ENDPOINT
                    << "Received WebTransport headers from server with "
                       "status code "
                    << status_code << ", rejecting.";
      rejection_reason_ = WebTransportHttp3RejectionReason::kWrongStatusCode;
      return;
    }
  }

  QUIC_DVLOG(1) << ENDPOINT << "WebTransport session " << id_ << " ready.";
  ready_ = true;
  visitor_->OnSessionReady();
  session_->ProcessBufferedWebTransportStreamsForSession(this);
}

WebTransportStream* WebTransportHttp3::AcceptIncomingBidirectionalStream() {
  while (!incoming_bidirectional_streams_.empty()) {
    QuicStreamId id = incoming_bidirectional_streams_.front();
    incoming_bidirectional_streams_.pop_front();
    QuicSpdyStream* stream = session_->GetOrCreateSpdyDataStream(id);
    if (stream == nullptr) {
      // Skip the streams that were reset in between the time they were
      // receieved and the time the client has polled for them.
      continue;
    }
    return stream->web_transport_stream();
  }
  return nullptr;
}

WebTransportStream* WebTransportHttp3::AcceptIncomingUnidirectionalStream() {
  while (!incoming_unidirectional_streams_.empty()) {
    QuicStreamId id = incoming_unidirectional_streams_.front();
    incoming_unidirectional_streams_.pop_front();
    QuicStream* stream = session_->GetOrCreateStream(id);
    if (stream == nullptr) {
      // Skip the streams that were reset in between the time they were
      // receieved and the time the client has polled for them.
      continue;
    }
    return static_cast<WebTransportHttp3UnidirectionalStream*>(stream)
        ->interface();
  }
  return nullptr;
}

bool WebTransportHttp3::CanOpenNextOutgoingBidirectionalStream() {
  return session_->CanOpenOutgoingBidirectionalWebTransportStream(id_);
}
bool WebTransportHttp3::CanOpenNextOutgoingUnidirectionalStream() {
  return session_->CanOpenOutgoingUnidirectionalWebTransportStream(id_);
}
WebTransportStream* WebTransportHttp3::OpenOutgoingBidirectionalStream() {
  QuicSpdyStream* stream =
      session_->CreateOutgoingBidirectionalWebTransportStream(this);
  if (stream == nullptr) {
    // If stream cannot be created due to flow control or other errors, return
    // nullptr.
    return nullptr;
  }
  return stream->web_transport_stream();
}

WebTransportStream* WebTransportHttp3::OpenOutgoingUnidirectionalStream() {
  WebTransportHttp3UnidirectionalStream* stream =
      session_->CreateOutgoingUnidirectionalWebTransportStream(this);
  if (stream == nullptr) {
    // If stream cannot be created due to flow control, return nullptr.
    return nullptr;
  }
  return stream->interface();
}

webtransport::Stream* WebTransportHttp3::GetStreamById(
    webtransport::StreamId id) {
  if (!streams_.contains(id)) {
    return nullptr;
  }
  QuicStream* stream = session_->GetActiveStream(id);
  const bool bidi = QuicUtils::IsBidirectionalStreamId(
      id, ParsedQuicVersion::RFCv1());  // Assume IETF QUIC for WebTransport
  if (bidi) {
    return static_cast<QuicSpdyStream*>(stream)->web_transport_stream();
  } else {
    return static_cast<WebTransportHttp3UnidirectionalStream*>(stream)
        ->interface();
  }
}

webtransport::DatagramStatus WebTransportHttp3::SendOrQueueDatagram(
    absl::string_view datagram) {
  return MessageStatusToWebTransportStatus(
      connect_stream_->SendHttp3Datagram(datagram));
}

QuicByteCount WebTransportHttp3::GetMaxDatagramSize() const {
  return connect_stream_->GetMaxDatagramSize();
}

void WebTransportHttp3::SetDatagramMaxTimeInQueue(
    absl::Duration max_time_in_queue) {
  connect_stream_->SetMaxDatagramTimeInQueue(QuicTimeDelta(max_time_in_queue));
}

void WebTransportHttp3::NotifySessionDraining() {
  if (!drain_sent_) {
    connect_stream_->WriteCapsule(
        quiche::Capsule(quiche::DrainWebTransportSessionCapsule()));
    drain_sent_ = true;
  }
}

void WebTransportHttp3::OnHttp3Datagram(QuicStreamId stream_id,
                                        absl::string_view payload) {
  QUICHE_DCHECK_EQ(stream_id, connect_stream_->id());
  visitor_->OnDatagramReceived(payload);
}

void WebTransportHttp3::MaybeNotifyClose() {
  if (close_notified_) {
    return;
  }
  close_notified_ = true;
  visitor_->OnSessionClosed(error_code_, error_message_);
}

void WebTransportHttp3::OnGoAwayReceived() {
  if (drain_callback_ != nullptr) {
    std::move(drain_callback_)();
    drain_callback_ = nullptr;
  }
}

void WebTransportHttp3::OnDrainSessionReceived() { OnGoAwayReceived(); }

WebTransportHttp3UnidirectionalStream::WebTransportHttp3UnidirectionalStream(
    PendingStream* pending, QuicSpdySession* session)
    : QuicStream(pending, session, /*is_static=*/false),
      session_(session),
      adapter_(session, this, sequencer(), std::nullopt),
      needs_to_send_preamble_(false) {
  sequencer()->set_level_triggered(true);
}

WebTransportHttp3UnidirectionalStream::WebTransportHttp3UnidirectionalStream(
    QuicStreamId id, QuicSpdySession* session, WebTransportSessionId session_id)
    : QuicStream(id, session, /*is_static=*/false, WRITE_UNIDIRECTIONAL),
      session_(session),
      adapter_(session, this, sequencer(), session_id),
      session_id_(session_id),
      needs_to_send_preamble_(true) {}

void WebTransportHttp3UnidirectionalStream::WritePreamble() {
  if (!needs_to_send_preamble_ || !session_id_.has_value()) {
    QUIC_BUG(WebTransportHttp3UnidirectionalStream duplicate preamble)
        << ENDPOINT << "Sending preamble on stream ID " << id()
        << " at the wrong time.";
    OnUnrecoverableError(QUIC_INTERNAL_ERROR,
                         "Attempting to send a WebTransport unidirectional "
                         "stream preamble at the wrong time.");
    return;
  }

  QuicConnection::ScopedPacketFlusher flusher(session_->connection());
  char buffer[sizeof(uint64_t) * 2];  // varint62, varint62
  QuicDataWriter writer(sizeof(buffer), buffer);
  bool success = true;
  success = success && writer.WriteVarInt62(kWebTransportUnidirectionalStream);
  success = success && writer.WriteVarInt62(*session_id_);
  QUICHE_DCHECK(success);
  WriteOrBufferData(absl::string_view(buffer, writer.length()), /*fin=*/false,
                    /*ack_listener=*/nullptr);
  QUIC_DVLOG(1) << ENDPOINT << "Sent stream type and session ID ("
                << *session_id_ << ") on WebTransport stream " << id();
  needs_to_send_preamble_ = false;
}

bool WebTransportHttp3UnidirectionalStream::ReadSessionId() {
  iovec iov;
  if (!sequencer()->GetReadableRegion(&iov)) {
    return false;
  }
  QuicDataReader reader(static_cast<const char*>(iov.iov_base), iov.iov_len);
  WebTransportSessionId session_id;
  uint8_t session_id_length = reader.PeekVarInt62Length();
  if (!reader.ReadVarInt62(&session_id)) {
    // If all of the data has been received, and we still cannot associate the
    // stream with a session, consume all of the data so that the stream can
    // be closed.
    if (sequencer()->IsAllDataAvailable()) {
      QUIC_DLOG(WARNING)
          << ENDPOINT << "Failed to associate WebTransport stream " << id()
          << " with a session because the stream ended prematurely.";
      sequencer()->MarkConsumed(sequencer()->NumBytesBuffered());
    }
    return false;
  }
  sequencer()->MarkConsumed(session_id_length);
  session_id_ = session_id;
  adapter_.SetSessionId(session_id);
  session_->AssociateIncomingWebTransportStreamWithSession(session_id, id());
  return true;
}

void WebTransportHttp3UnidirectionalStream::OnDataAvailable() {
  if (!session_id_.has_value()) {
    if (!ReadSessionId()) {
      return;
    }
  }

  adapter_.OnDataAvailable();
}

void WebTransportHttp3UnidirectionalStream::OnCanWriteNewData() {
  adapter_.OnCanWriteNewData();
}

void WebTransportHttp3UnidirectionalStream::OnClose() {
  QuicStream::OnClose();

  if (!session_id_.has_value()) {
    return;
  }
  WebTransportHttp3* session = session_->GetWebTransportSession(*session_id_);
  if (session == nullptr) {
    QUIC_DLOG(WARNING) << ENDPOINT << "WebTransport stream " << id()
                       << " attempted to notify parent session " << *session_id_
                       << ", but the session could not be found.";
    return;
  }
  session->OnStreamClosed(id());
}

void WebTransportHttp3UnidirectionalStream::OnStreamReset(
    const QuicRstStreamFrame& frame) {
  if (adapter_.visitor() != nullptr) {
    adapter_.visitor()->OnResetStreamReceived(
        Http3ErrorToWebTransportOrDefault(frame.ietf_error_code));
  }
  QuicStream::OnStreamReset(frame);
}
bool WebTransportHttp3UnidirectionalStream::OnStopSending(
    QuicResetStreamError error) {
  if (adapter_.visitor() != nullptr) {
    adapter_.visitor()->OnStopSendingReceived(
        Http3ErrorToWebTransportOrDefault(error.ietf_application_code()));
  }
  return QuicStream::OnStopSending(error);
}
void WebTransportHttp3UnidirectionalStream::OnWriteSideInDataRecvdState() {
  if (adapter_.visitor() != nullptr) {
    adapter_.visitor()->OnWriteSideInDataRecvdState();
  }

  QuicStream::OnWriteSideInDataRecvdState();
}

namespace {
constexpr uint64_t kWebTransportMappedErrorCodeFirst = 0x52e4a40fa8db;
constexpr uint64_t kWebTransportMappedErrorCodeLast = 0x52e5ac983162;
constexpr WebTransportStreamError kDefaultWebTransportError = 0;
}  // namespace

std::optional<WebTransportStreamError> Http3ErrorToWebTransport(
    uint64_t http3_error_code) {
  // Ensure the code is within the valid range.
  if (http3_error_code < kWebTransportMappedErrorCodeFirst ||
      http3_error_code > kWebTransportMappedErrorCodeLast) {
    return std::nullopt;
  }
  // Exclude GREASE codepoints.
  if ((http3_error_code - 0x21) % 0x1f == 0) {
    return std::nullopt;
  }

  uint64_t shifted = http3_error_code - kWebTransportMappedErrorCodeFirst;
  uint64_t result = shifted - shifted / 0x1f;
  QUICHE_DCHECK_LE(result,
                   std::numeric_limits<webtransport::StreamErrorCode>::max());
  return static_cast<WebTransportStreamError>(result);
}

WebTransportStreamError Http3ErrorToWebTransportOrDefault(
    uint64_t http3_error_code) {
  std::optional<WebTransportStreamError> result =
      Http3ErrorToWebTransport(http3_error_code);
  return result.has_value() ? *result : kDefaultWebTransportError;
}

uint64_t WebTransportErrorToHttp3(
    WebTransportStreamError webtransport_error_code) {
  return kWebTransportMappedErrorCodeFirst + webtransport_error_code +
         webtransport_error_code / 0x1e;
}

}  // namespace quic

"""

```