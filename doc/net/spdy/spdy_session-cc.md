Response:
The user wants to understand the functionality of the `spdy_session.cc` file in the Chromium network stack. I need to extract the key functionalities, explain its relation to JavaScript (if any), provide examples of logical reasoning with input/output, illustrate common user/programming errors, describe how a user operation leads to this code, and summarize its purpose.

**Functionality Breakdown:**

1. **Session Management:** Handling HTTP/2 (and potentially SPDY) sessions, including creation, initialization, and teardown.
2. **Stream Management:** Creating, managing, and closing individual HTTP/2 streams within a session.
3. **Frame Handling:**  Processing incoming and outgoing HTTP/2 frames (HEADERS, DATA, SETTINGS, etc.). This includes serialization and deserialization.
4. **Settings Management:** Handling HTTP/2 settings negotiation and application.
5. **Flow Control:** Implementing HTTP/2 flow control mechanisms to manage data transfer rates.
6. **Error Handling:**  Dealing with various network and protocol errors.
7. **Priority Handling:** Managing stream priorities.
8. **Connection Pooling:** Determining if sessions can be reused for different hosts.
9. **Logging and Metrics:** Using NetLog and UMA histograms for debugging and performance monitoring.
10. **Integration with other Network Components:** Interacting with `HttpServerProperties`, `TransportSecurityState`, `SSLConfigService`, `NetworkQualityEstimator`, etc.

**JavaScript Relation:**

HTTP/2 sessions are the underlying transport mechanism for fetching resources requested by JavaScript code in a web browser. When JavaScript makes an HTTP request, the browser's network stack (including this `spdy_session.cc` code) handles the communication with the server.

**Logical Reasoning Examples:**

*   **Input:**  A HEADERS frame is received with a new stream ID.
    *   **Output:** A new `SpdyStream` object is created and associated with that stream ID.
*   **Input:** A DATA frame is received for an existing stream.
    *   **Output:** The data is passed to the corresponding `SpdyStream`.
*   **Input:** A SETTINGS frame is received from the server.
    *   **Output:** The session's internal settings are updated, and notifications might be sent to streams.

**User/Programming Errors:**

*   **Incorrect Header Format in JavaScript:** While the `spdy_session.cc` doesn't directly handle JavaScript, if a JavaScript application generates malformed HTTP headers (e.g., using `fetch` with invalid header values), this could lead to parsing errors within the HTTP/2 stack, potentially triggering error handling within `spdy_session.cc`.
*   **Exceeding Concurrent Stream Limits:** If a JavaScript application makes too many concurrent requests, it might hit the `max_concurrent_streams` limit, and the `spdy_session.cc` would need to handle queuing or rejecting new stream requests.

**User Operation to Reach This Code:**

1. User types a URL in the browser's address bar or clicks a link.
2. The browser resolves the DNS for the domain.
3. The browser checks if there's an existing HTTP/2 connection to the server.
4. If no connection exists, or an existing connection cannot be reused, a new `SpdySession` is created.
5. The browser initiates a TLS handshake (if HTTPS).
6. During the handshake, ALPN negotiation might indicate the use of HTTP/2.
7. The `SpdySession` object is initialized with the underlying socket.
8. When the browser needs to fetch resources (HTML, CSS, JavaScript, images), it creates HTTP/2 streams using this `SpdySession`.

**Summary of Functionality (Part 1):**

This part of `spdy_session.cc` focuses on the fundamental aspects of managing an HTTP/2 session. It defines the `SpdySession` class and its core responsibilities, including handling stream creation requests (`SpdyStreamRequest`), managing session-level settings, and dealing with the underlying socket connection. It also includes utilities for mapping errors and logging events. The code lays the groundwork for the more complex operations involved in sending and receiving HTTP/2 frames, which will likely be covered in subsequent parts of the file.
This is the first part of the `net/spdy/spdy_session.cc` file, which is responsible for managing an HTTP/2 session in Chromium's network stack. Here's a breakdown of its functionalities as presented in this section:

**Core Functionalities:**

1. **HTTP/2 Session Management:**
    *   Defines the `SpdySession` class, the central entity for managing an HTTP/2 connection.
    *   Handles the lifecycle of an HTTP/2 session, from initialization to termination.
    *   Manages session-level settings received from the server (e.g., `SETTINGS_MAX_CONCURRENT_STREAMS`, `SETTINGS_INITIAL_WINDOW_SIZE`).
    *   Stores the session key (`SpdySessionKey`) which identifies the origin and proxy of the connection.
    *   Keeps track of active streams within the session.
    *   Manages the next available stream ID.

2. **Stream Creation and Management:**
    *   Provides the `SpdyStreamRequest` class for requesting the creation of new HTTP/2 streams. This acts as an intermediary before a stream is fully established.
    *   Handles requests to create new streams (`TryCreateStream`).
    *   Manages the maximum number of concurrent streams allowed for the session.
    *   Allows for prioritization of stream requests.

3. **Socket and Network Interaction:**
    *   Holds a pointer to the underlying `Socket` object used for the connection.
    *   Manages read operations from the socket.
    *   Handles connection closure and disconnection.

4. **Settings Handling:**
    *   Stores the initial settings provided during session creation.
    *   Manages the application of received `SETTINGS` frames from the server.
    *   Includes logic for greasing HTTP/2 settings to improve interoperability.

5. **Flow Control:**
    *   Manages the session-level flow control window.
    *   Tracks the last time a window update was received.

6. **Error Handling:**
    *   Maps framer errors to `SpdyProtocolErrorDetails` and `net::Error` codes.
    *   Provides functions to map RST_STREAM error codes to `SpdyProtocolErrorDetails`.
    *   Maps `net::Error` codes to GOAWAY status codes.

7. **Logging and Metrics:**
    *   Uses Chromium's NetLog system to log various events related to the HTTP/2 session (e.g., session creation, settings exchange, frame sending/receiving).
    *   Emits UMA histograms to track metrics like the usage of Accept-CH headers and session creation initiators.

8. **Connection Pooling Logic:**
    *   Implements the `CanPool` static method to determine if an existing HTTP/2 session can be reused for a new request to a different hostname. This considers certificate validity, client certificates, and Public Key Pinning.

**Relationship with JavaScript:**

While this C++ code doesn't directly execute JavaScript, it plays a crucial role in fulfilling network requests initiated by JavaScript in a web browser.

*   **Fetching Resources:** When JavaScript code uses `fetch()` or `XMLHttpRequest` to request resources over HTTP/2, the browser's network stack (including this `spdy_session.cc` code) handles the underlying communication.
*   **Headers and Data Transfer:** The JavaScript makes requests with specific headers, and this code is responsible for packaging those headers into HTTP/2 frames and sending them. Similarly, when the server responds, this code receives the HTTP/2 frames and makes the data available to the browser, which then delivers it to the JavaScript.
*   **Prioritization:** The priority hints that can sometimes be set in `fetch()` requests might be translated into HTTP/2 priority settings managed by this code.

**Logical Reasoning Examples:**

*   **Hypothetical Input:** The session receives a `SETTINGS` frame with `SETTINGS_MAX_CONCURRENT_STREAMS` set to 100.
    *   **Output:** The `max_concurrent_streams_` member variable in the `SpdySession` object will be updated to 100. Any subsequent attempts to create more than 100 concurrent streams will be managed according to this limit (likely queued or rejected).

*   **Hypothetical Input:** A `HEADERS` frame is received for a new stream ID that is within the valid range and hasn't been used yet.
    *   **Output:** A new `SpdyStream` object will be created and associated with this stream ID. The stream will be added to the session's collection of active streams.

**User or Programming Common Usage Errors (Indirect):**

Users and programmers don't directly interact with this C++ code. However, their actions can lead to scenarios handled here.

*   **Too Many Concurrent Requests:** If a web page (through JavaScript) makes an excessive number of concurrent requests to the same server, it might hit the `max_concurrent_streams` limit enforced by the `SpdySession`. The code would then need to queue or reject new stream requests. This could manifest as delays in loading resources or failed requests.
*   **Server-Side Errors:** If the server sends an invalid HTTP/2 frame or violates the protocol, this code will detect the error, potentially close the connection, and report an error to the browser. This might result in a "connection reset" error or a partially loaded page for the user.

**User Operation to Reach This Code (Debugging Clue):**

1. **User opens a website that uses HTTP/2:**  The browser negotiates HTTP/2 during the TLS handshake.
2. **The browser needs to fetch resources:** When the browser encounters `<script>`, `<img>`, `<link>` tags, or when JavaScript initiates `fetch()` calls, it needs to download these resources.
3. **The network stack checks for an existing HTTP/2 session:** If a suitable session exists, it might be reused. Otherwise, a new `SpdySession` is created.
4. **The browser requests a new stream:**  For each resource to be fetched, a `SpdyStreamRequest` is initiated, ultimately leading to the `TryCreateStream` method in `spdy_session.cc`.
5. **Incoming data or control frames arrive:**  As the server sends data and control frames (like `HEADERS`, `DATA`, `SETTINGS`), this code processes them, updating the session state and forwarding data to the appropriate `SpdyStream` objects.

**Summary of Functionality (Part 1):**

The first part of `net/spdy/spdy_session.cc` lays the foundation for managing an HTTP/2 connection. It defines the core `SpdySession` class and its responsibilities for session lifecycle, stream creation, socket management, settings handling, basic flow control, error mapping, and logging. It provides the necessary infrastructure for the more complex tasks of sending and receiving HTTP/2 frames, which will likely be the focus of the subsequent parts of the file.

### 提示词
```
这是目录为net/spdy/spdy_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/spdy/spdy_session.h"

#include <limits>
#include <map>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#include "base/containers/contains.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/rand_util.h"
#include "base/ranges/algorithm.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/trace_event/memory_usage_estimator.h"
#include "base/values.h"
#include "net/base/features.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_string_util.h"
#include "net/base/tracing.h"
#include "net/base/url_util.h"
#include "net/cert/asn1_util.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/ct_policy_status.h"
#include "net/http/http_network_session.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_util.h"
#include "net/http/http_vary_data.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source_type.h"
#include "net/log/net_log_with_source.h"
#include "net/nqe/network_quality_estimator.h"
#include "net/quic/quic_http_utils.h"
#include "net/socket/socket.h"
#include "net/socket/ssl_client_socket.h"
#include "net/spdy/alps_decoder.h"
#include "net/spdy/header_coalescer.h"
#include "net/spdy/spdy_buffer_producer.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/spdy/spdy_log_util.h"
#include "net/spdy/spdy_session_pool.h"
#include "net/spdy/spdy_stream.h"
#include "net/ssl/ssl_cipher_suite_names.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_frame_builder.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_protocol.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

namespace net {

namespace {

constexpr net::NetworkTrafficAnnotationTag
    kSpdySessionCommandsTrafficAnnotation =
        net::DefineNetworkTrafficAnnotation("spdy_session_control", R"(
        semantics {
          sender: "Spdy Session"
          description:
            "Sends commands to control an HTTP/2 session."
          trigger:
            "Required control commands like initiating stream, requesting "
            "stream reset, changing priorities, etc."
          data: "No user data."
          destination: OTHER
          destination_other:
            "Any destination the HTTP/2 session is connected to."
        }
        policy {
          cookies_allowed: NO
          setting: "This feature cannot be disabled in settings."
          policy_exception_justification: "Essential for network access."
        }
    )");

const int kReadBufferSize = 8 * 1024;
const int kDefaultConnectionAtRiskOfLossSeconds = 10;
const int kHungIntervalSeconds = 10;

// Default initial value for HTTP/2 SETTINGS.
const uint32_t kDefaultInitialHeaderTableSize = 4096;
const uint32_t kDefaultInitialEnablePush = 1;
const uint32_t kDefaultInitialInitialWindowSize = 65535;
const uint32_t kDefaultInitialMaxFrameSize = 16384;

// These values are persisted to logs. Entries should not be renumbered, and
// numeric values should never be reused.
enum class SpdyAcceptChEntries {
  kNoEntries = 0,
  kOnlyValidEntries = 1,
  kOnlyInvalidEntries = 2,
  kBothValidAndInvalidEntries = 3,
  kMaxValue = kBothValidAndInvalidEntries,
};

// A SpdyBufferProducer implementation that creates an HTTP/2 frame by adding
// stream ID to greased frame parameters.
class GreasedBufferProducer : public SpdyBufferProducer {
 public:
  GreasedBufferProducer() = delete;
  GreasedBufferProducer(
      base::WeakPtr<SpdyStream> stream,
      const SpdySessionPool::GreasedHttp2Frame* greased_http2_frame,
      BufferedSpdyFramer* buffered_spdy_framer)
      : stream_(stream),
        greased_http2_frame_(greased_http2_frame),
        buffered_spdy_framer_(buffered_spdy_framer) {}

  ~GreasedBufferProducer() override = default;

  std::unique_ptr<SpdyBuffer> ProduceBuffer() override {
    const spdy::SpdyStreamId stream_id = stream_ ? stream_->stream_id() : 0;
    spdy::SpdyUnknownIR frame(stream_id, greased_http2_frame_->type,
                              greased_http2_frame_->flags,
                              greased_http2_frame_->payload);
    auto serialized_frame = std::make_unique<spdy::SpdySerializedFrame>(
        buffered_spdy_framer_->SerializeFrame(frame));
    return std::make_unique<SpdyBuffer>(std::move(serialized_frame));
  }

 private:
  base::WeakPtr<SpdyStream> stream_;
  const raw_ptr<const SpdySessionPool::GreasedHttp2Frame> greased_http2_frame_;
  raw_ptr<BufferedSpdyFramer> buffered_spdy_framer_;
};

bool IsSpdySettingAtDefaultInitialValue(spdy::SpdySettingsId setting_id,
                                        uint32_t value) {
  switch (setting_id) {
    case spdy::SETTINGS_HEADER_TABLE_SIZE:
      return value == kDefaultInitialHeaderTableSize;
    case spdy::SETTINGS_ENABLE_PUSH:
      return value == kDefaultInitialEnablePush;
    case spdy::SETTINGS_MAX_CONCURRENT_STREAMS:
      // There is no initial limit on the number of concurrent streams.
      return false;
    case spdy::SETTINGS_INITIAL_WINDOW_SIZE:
      return value == kDefaultInitialInitialWindowSize;
    case spdy::SETTINGS_MAX_FRAME_SIZE:
      return value == kDefaultInitialMaxFrameSize;
    case spdy::SETTINGS_MAX_HEADER_LIST_SIZE:
      // There is no initial limit on the size of the header list.
      return false;
    case spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL:
      return value == 0;
    default:
      // Undefined parameters have no initial value.
      return false;
  }
}

void LogSpdyAcceptChForOriginHistogram(bool value) {
  base::UmaHistogramBoolean("Net.SpdySession.AcceptChForOrigin", value);
}

void LogSessionCreationInitiatorToHistogram(
    MultiplexedSessionCreationInitiator session_creation,
    bool is_used) {
  std::string histogram_name =
      base::StrCat({"Net.SpdySession.GoogleSearch.SessionCreationInitiator",
                    is_used ? ".Used" : ".Unused"});

  base::UmaHistogramEnumeration(histogram_name, session_creation);
}

base::Value::Dict NetLogSpdyHeadersSentParams(
    const quiche::HttpHeaderBlock* headers,
    bool fin,
    spdy::SpdyStreamId stream_id,
    bool has_priority,
    int weight,
    spdy::SpdyStreamId parent_stream_id,
    bool exclusive,
    NetLogSource source_dependency,
    NetLogCaptureMode capture_mode) {
  auto dict =
      base::Value::Dict()
          .Set("headers", ElideHttpHeaderBlockForNetLog(*headers, capture_mode))
          .Set("fin", fin)
          .Set("stream_id", static_cast<int>(stream_id))
          .Set("has_priority", has_priority);
  if (has_priority) {
    dict.Set("parent_stream_id", static_cast<int>(parent_stream_id));
    dict.Set("weight", weight);
    dict.Set("exclusive", exclusive);
  }
  if (source_dependency.IsValid()) {
    source_dependency.AddToEventParameters(dict);
  }
  return dict;
}

base::Value::Dict NetLogSpdyHeadersReceivedParams(
    const quiche::HttpHeaderBlock* headers,
    bool fin,
    spdy::SpdyStreamId stream_id,
    NetLogCaptureMode capture_mode) {
  return base::Value::Dict()
      .Set("headers", ElideHttpHeaderBlockForNetLog(*headers, capture_mode))
      .Set("fin", fin)
      .Set("stream_id", static_cast<int>(stream_id));
}

base::Value::Dict NetLogSpdySessionCloseParams(int net_error,
                                               const std::string& description) {
  return base::Value::Dict()
      .Set("net_error", net_error)
      .Set("description", description);
}

base::Value::Dict NetLogSpdySessionParams(const HostPortProxyPair& host_pair) {
  return base::Value::Dict()
      .Set("host", host_pair.first.ToString())
      .Set("proxy", host_pair.second.ToDebugString());
}

base::Value::Dict NetLogSpdyInitializedParams(NetLogSource source) {
  base::Value::Dict dict;
  if (source.IsValid()) {
    source.AddToEventParameters(dict);
  }
  dict.Set("protocol", NextProtoToString(kProtoHTTP2));
  return dict;
}

base::Value::Dict NetLogSpdySendSettingsParams(
    const spdy::SettingsMap* settings) {
  base::Value::List settings_list;
  for (const auto& setting : *settings) {
    const spdy::SpdySettingsId id = setting.first;
    const uint32_t value = setting.second;
    settings_list.Append(
        base::StringPrintf("[id:%u (%s) value:%u]", id,
                           spdy::SettingsIdToString(id).c_str(), value));
  }

  return base::Value::Dict().Set("settings", std::move(settings_list));
}

base::Value::Dict NetLogSpdyRecvAcceptChParams(
    spdy::AcceptChOriginValuePair entry) {
  return base::Value::Dict()
      .Set("origin", entry.origin)
      .Set("accept_ch", entry.value);
}

base::Value::Dict NetLogSpdyRecvSettingParams(spdy::SpdySettingsId id,
                                              uint32_t value) {
  return base::Value::Dict()
      .Set("id", base::StringPrintf("%u (%s)", id,
                                    spdy::SettingsIdToString(id).c_str()))
      .Set("value", static_cast<int>(value));
}

base::Value::Dict NetLogSpdyWindowUpdateFrameParams(
    spdy::SpdyStreamId stream_id,
    uint32_t delta) {
  return base::Value::Dict()
      .Set("stream_id", static_cast<int>(stream_id))
      .Set("delta", static_cast<int>(delta));
}

base::Value::Dict NetLogSpdySessionWindowUpdateParams(int32_t delta,
                                                      int32_t window_size) {
  return base::Value::Dict()
      .Set("delta", delta)
      .Set("window_size", window_size);
}

base::Value::Dict NetLogSpdyDataParams(spdy::SpdyStreamId stream_id,
                                       int size,
                                       bool fin) {
  return base::Value::Dict()
      .Set("stream_id", static_cast<int>(stream_id))
      .Set("size", size)
      .Set("fin", fin);
}

base::Value::Dict NetLogSpdyRecvRstStreamParams(
    spdy::SpdyStreamId stream_id,
    spdy::SpdyErrorCode error_code) {
  return base::Value::Dict()
      .Set("stream_id", static_cast<int>(stream_id))
      .Set("error_code", base::StringPrintf("%u (%s)", error_code,
                                            ErrorCodeToString(error_code)));
}

base::Value::Dict NetLogSpdySendRstStreamParams(
    spdy::SpdyStreamId stream_id,
    spdy::SpdyErrorCode error_code,
    const std::string& description) {
  return base::Value::Dict()
      .Set("stream_id", static_cast<int>(stream_id))
      .Set("error_code", base::StringPrintf("%u (%s)", error_code,
                                            ErrorCodeToString(error_code)))
      .Set("description", description);
}

base::Value::Dict NetLogSpdyPingParams(spdy::SpdyPingId unique_id,
                                       bool is_ack,
                                       const char* type) {
  return base::Value::Dict()
      .Set("unique_id", static_cast<int>(unique_id))
      .Set("type", type)
      .Set("is_ack", is_ack);
}

base::Value::Dict NetLogSpdyRecvGoAwayParams(spdy::SpdyStreamId last_stream_id,
                                             int active_streams,
                                             spdy::SpdyErrorCode error_code,
                                             std::string_view debug_data,
                                             NetLogCaptureMode capture_mode) {
  return base::Value::Dict()
      .Set("last_accepted_stream_id", static_cast<int>(last_stream_id))
      .Set("active_streams", active_streams)
      .Set("error_code", base::StringPrintf("%u (%s)", error_code,
                                            ErrorCodeToString(error_code)))
      .Set("debug_data",
           ElideGoAwayDebugDataForNetLog(capture_mode, debug_data));
}

base::Value::Dict NetLogSpdySessionStalledParams(size_t num_active_streams,
                                                 size_t num_created_streams,
                                                 size_t max_concurrent_streams,
                                                 const std::string& url) {
  return base::Value::Dict()
      .Set("num_active_streams", static_cast<int>(num_active_streams))
      .Set("num_created_streams", static_cast<int>(num_created_streams))
      .Set("max_concurrent_streams", static_cast<int>(max_concurrent_streams))
      .Set("url", url);
}

base::Value::Dict NetLogSpdyPriorityParams(spdy::SpdyStreamId stream_id,
                                           spdy::SpdyStreamId parent_stream_id,
                                           int weight,
                                           bool exclusive) {
  return base::Value::Dict()
      .Set("stream_id", static_cast<int>(stream_id))
      .Set("parent_stream_id", static_cast<int>(parent_stream_id))
      .Set("weight", weight)
      .Set("exclusive", exclusive);
}

base::Value::Dict NetLogSpdyGreasedFrameParams(spdy::SpdyStreamId stream_id,
                                               uint8_t type,
                                               uint8_t flags,
                                               size_t length,
                                               RequestPriority priority) {
  return base::Value::Dict()
      .Set("stream_id", static_cast<int>(stream_id))
      .Set("type", type)
      .Set("flags", flags)
      .Set("length", static_cast<int>(length))
      .Set("priority", RequestPriorityToString(priority));
}

// Helper function to return the total size of an array of objects
// with .size() member functions.
template <typename T, size_t N>
size_t GetTotalSize(const T (&arr)[N]) {
  size_t total_size = 0;
  for (size_t i = 0; i < N; ++i) {
    total_size += arr[i].size();
  }
  return total_size;
}

// The maximum number of concurrent streams we will ever create.  Even if
// the server permits more, we will never exceed this limit.
const size_t kMaxConcurrentStreamLimit = 256;

}  // namespace

SpdyProtocolErrorDetails MapFramerErrorToProtocolError(
    http2::Http2DecoderAdapter::SpdyFramerError err) {
  switch (err) {
    case http2::Http2DecoderAdapter::SPDY_NO_ERROR:
      return SPDY_ERROR_NO_ERROR;
    case http2::Http2DecoderAdapter::SPDY_INVALID_STREAM_ID:
      return SPDY_ERROR_INVALID_STREAM_ID;
    case http2::Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME:
      return SPDY_ERROR_INVALID_CONTROL_FRAME;
    case http2::Http2DecoderAdapter::SPDY_CONTROL_PAYLOAD_TOO_LARGE:
      return SPDY_ERROR_CONTROL_PAYLOAD_TOO_LARGE;
    case http2::Http2DecoderAdapter::SPDY_DECOMPRESS_FAILURE:
      return SPDY_ERROR_DECOMPRESS_FAILURE;
    case http2::Http2DecoderAdapter::SPDY_INVALID_PADDING:
      return SPDY_ERROR_INVALID_PADDING;
    case http2::Http2DecoderAdapter::SPDY_INVALID_DATA_FRAME_FLAGS:
      return SPDY_ERROR_INVALID_DATA_FRAME_FLAGS;
    case http2::Http2DecoderAdapter::SPDY_UNEXPECTED_FRAME:
      return SPDY_ERROR_UNEXPECTED_FRAME;
    case http2::Http2DecoderAdapter::SPDY_INTERNAL_FRAMER_ERROR:
      return SPDY_ERROR_INTERNAL_FRAMER_ERROR;
    case http2::Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME_SIZE:
      return SPDY_ERROR_INVALID_CONTROL_FRAME_SIZE;
    case http2::Http2DecoderAdapter::SPDY_OVERSIZED_PAYLOAD:
      return SPDY_ERROR_OVERSIZED_PAYLOAD;
    case http2::Http2DecoderAdapter::SPDY_HPACK_INDEX_VARINT_ERROR:
      return SPDY_ERROR_HPACK_INDEX_VARINT_ERROR;
    case http2::Http2DecoderAdapter::SPDY_HPACK_NAME_LENGTH_VARINT_ERROR:
      return SPDY_ERROR_HPACK_NAME_LENGTH_VARINT_ERROR;
    case http2::Http2DecoderAdapter::SPDY_HPACK_VALUE_LENGTH_VARINT_ERROR:
      return SPDY_ERROR_HPACK_VALUE_LENGTH_VARINT_ERROR;
    case http2::Http2DecoderAdapter::SPDY_HPACK_NAME_TOO_LONG:
      return SPDY_ERROR_HPACK_NAME_TOO_LONG;
    case http2::Http2DecoderAdapter::SPDY_HPACK_VALUE_TOO_LONG:
      return SPDY_ERROR_HPACK_VALUE_TOO_LONG;
    case http2::Http2DecoderAdapter::SPDY_HPACK_NAME_HUFFMAN_ERROR:
      return SPDY_ERROR_HPACK_NAME_HUFFMAN_ERROR;
    case http2::Http2DecoderAdapter::SPDY_HPACK_VALUE_HUFFMAN_ERROR:
      return SPDY_ERROR_HPACK_VALUE_HUFFMAN_ERROR;
    case http2::Http2DecoderAdapter::
        SPDY_HPACK_MISSING_DYNAMIC_TABLE_SIZE_UPDATE:
      return SPDY_ERROR_HPACK_MISSING_DYNAMIC_TABLE_SIZE_UPDATE;
    case http2::Http2DecoderAdapter::SPDY_HPACK_INVALID_INDEX:
      return SPDY_ERROR_HPACK_INVALID_INDEX;
    case http2::Http2DecoderAdapter::SPDY_HPACK_INVALID_NAME_INDEX:
      return SPDY_ERROR_HPACK_INVALID_NAME_INDEX;
    case http2::Http2DecoderAdapter::
        SPDY_HPACK_DYNAMIC_TABLE_SIZE_UPDATE_NOT_ALLOWED:
      return SPDY_ERROR_HPACK_DYNAMIC_TABLE_SIZE_UPDATE_NOT_ALLOWED;
    case http2::Http2DecoderAdapter::
        SPDY_HPACK_INITIAL_DYNAMIC_TABLE_SIZE_UPDATE_IS_ABOVE_LOW_WATER_MARK:
      return SPDY_ERROR_HPACK_INITIAL_DYNAMIC_TABLE_SIZE_UPDATE_IS_ABOVE_LOW_WATER_MARK;
    case http2::Http2DecoderAdapter::
        SPDY_HPACK_DYNAMIC_TABLE_SIZE_UPDATE_IS_ABOVE_ACKNOWLEDGED_SETTING:
      return SPDY_ERROR_HPACK_DYNAMIC_TABLE_SIZE_UPDATE_IS_ABOVE_ACKNOWLEDGED_SETTING;
    case http2::Http2DecoderAdapter::SPDY_HPACK_TRUNCATED_BLOCK:
      return SPDY_ERROR_HPACK_TRUNCATED_BLOCK;
    case http2::Http2DecoderAdapter::SPDY_HPACK_FRAGMENT_TOO_LONG:
      return SPDY_ERROR_HPACK_FRAGMENT_TOO_LONG;
    case http2::Http2DecoderAdapter::
        SPDY_HPACK_COMPRESSED_HEADER_SIZE_EXCEEDS_LIMIT:
      return SPDY_ERROR_HPACK_COMPRESSED_HEADER_SIZE_EXCEEDS_LIMIT;
    case http2::Http2DecoderAdapter::SPDY_STOP_PROCESSING:
      return SPDY_ERROR_STOP_PROCESSING;

    case http2::Http2DecoderAdapter::LAST_ERROR:
      NOTREACHED();
  }
  NOTREACHED();
}

Error MapFramerErrorToNetError(
    http2::Http2DecoderAdapter::SpdyFramerError err) {
  switch (err) {
    case http2::Http2DecoderAdapter::SPDY_NO_ERROR:
      return OK;
    case http2::Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME:
      return ERR_HTTP2_PROTOCOL_ERROR;
    case http2::Http2DecoderAdapter::SPDY_CONTROL_PAYLOAD_TOO_LARGE:
      return ERR_HTTP2_FRAME_SIZE_ERROR;
    case http2::Http2DecoderAdapter::SPDY_DECOMPRESS_FAILURE:
    case http2::Http2DecoderAdapter::SPDY_HPACK_INDEX_VARINT_ERROR:
    case http2::Http2DecoderAdapter::SPDY_HPACK_NAME_LENGTH_VARINT_ERROR:
    case http2::Http2DecoderAdapter::SPDY_HPACK_VALUE_LENGTH_VARINT_ERROR:
    case http2::Http2DecoderAdapter::SPDY_HPACK_NAME_TOO_LONG:
    case http2::Http2DecoderAdapter::SPDY_HPACK_VALUE_TOO_LONG:
    case http2::Http2DecoderAdapter::SPDY_HPACK_NAME_HUFFMAN_ERROR:
    case http2::Http2DecoderAdapter::SPDY_HPACK_VALUE_HUFFMAN_ERROR:
    case http2::Http2DecoderAdapter::
        SPDY_HPACK_MISSING_DYNAMIC_TABLE_SIZE_UPDATE:
    case http2::Http2DecoderAdapter::SPDY_HPACK_INVALID_INDEX:
    case http2::Http2DecoderAdapter::SPDY_HPACK_INVALID_NAME_INDEX:
    case http2::Http2DecoderAdapter::
        SPDY_HPACK_DYNAMIC_TABLE_SIZE_UPDATE_NOT_ALLOWED:
    case http2::Http2DecoderAdapter::
        SPDY_HPACK_INITIAL_DYNAMIC_TABLE_SIZE_UPDATE_IS_ABOVE_LOW_WATER_MARK:
    case http2::Http2DecoderAdapter::
        SPDY_HPACK_DYNAMIC_TABLE_SIZE_UPDATE_IS_ABOVE_ACKNOWLEDGED_SETTING:
    case http2::Http2DecoderAdapter::SPDY_HPACK_TRUNCATED_BLOCK:
    case http2::Http2DecoderAdapter::SPDY_HPACK_FRAGMENT_TOO_LONG:
    case http2::Http2DecoderAdapter::
        SPDY_HPACK_COMPRESSED_HEADER_SIZE_EXCEEDS_LIMIT:
      return ERR_HTTP2_COMPRESSION_ERROR;
    case http2::Http2DecoderAdapter::SPDY_STOP_PROCESSING:
      return ERR_HTTP2_COMPRESSION_ERROR;
    case http2::Http2DecoderAdapter::SPDY_INVALID_PADDING:
      return ERR_HTTP2_PROTOCOL_ERROR;
    case http2::Http2DecoderAdapter::SPDY_INVALID_DATA_FRAME_FLAGS:
      return ERR_HTTP2_PROTOCOL_ERROR;
    case http2::Http2DecoderAdapter::SPDY_UNEXPECTED_FRAME:
      return ERR_HTTP2_PROTOCOL_ERROR;
    case http2::Http2DecoderAdapter::SPDY_INTERNAL_FRAMER_ERROR:
      return ERR_HTTP2_PROTOCOL_ERROR;
    case http2::Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME_SIZE:
      return ERR_HTTP2_FRAME_SIZE_ERROR;
    case http2::Http2DecoderAdapter::SPDY_INVALID_STREAM_ID:
      return ERR_HTTP2_PROTOCOL_ERROR;
    case http2::Http2DecoderAdapter::SPDY_OVERSIZED_PAYLOAD:
      return ERR_HTTP2_FRAME_SIZE_ERROR;
    case http2::Http2DecoderAdapter::LAST_ERROR:
      NOTREACHED();
  }
  NOTREACHED();
}

SpdyProtocolErrorDetails MapRstStreamStatusToProtocolError(
    spdy::SpdyErrorCode error_code) {
  switch (error_code) {
    case spdy::ERROR_CODE_NO_ERROR:
      return STATUS_CODE_NO_ERROR;
    case spdy::ERROR_CODE_PROTOCOL_ERROR:
      return STATUS_CODE_PROTOCOL_ERROR;
    case spdy::ERROR_CODE_INTERNAL_ERROR:
      return STATUS_CODE_INTERNAL_ERROR;
    case spdy::ERROR_CODE_FLOW_CONTROL_ERROR:
      return STATUS_CODE_FLOW_CONTROL_ERROR;
    case spdy::ERROR_CODE_SETTINGS_TIMEOUT:
      return STATUS_CODE_SETTINGS_TIMEOUT;
    case spdy::ERROR_CODE_STREAM_CLOSED:
      return STATUS_CODE_STREAM_CLOSED;
    case spdy::ERROR_CODE_FRAME_SIZE_ERROR:
      return STATUS_CODE_FRAME_SIZE_ERROR;
    case spdy::ERROR_CODE_REFUSED_STREAM:
      return STATUS_CODE_REFUSED_STREAM;
    case spdy::ERROR_CODE_CANCEL:
      return STATUS_CODE_CANCEL;
    case spdy::ERROR_CODE_COMPRESSION_ERROR:
      return STATUS_CODE_COMPRESSION_ERROR;
    case spdy::ERROR_CODE_CONNECT_ERROR:
      return STATUS_CODE_CONNECT_ERROR;
    case spdy::ERROR_CODE_ENHANCE_YOUR_CALM:
      return STATUS_CODE_ENHANCE_YOUR_CALM;
    case spdy::ERROR_CODE_INADEQUATE_SECURITY:
      return STATUS_CODE_INADEQUATE_SECURITY;
    case spdy::ERROR_CODE_HTTP_1_1_REQUIRED:
      return STATUS_CODE_HTTP_1_1_REQUIRED;
  }
  NOTREACHED();
}

spdy::SpdyErrorCode MapNetErrorToGoAwayStatus(Error err) {
  switch (err) {
    case OK:
      return spdy::ERROR_CODE_NO_ERROR;
    case ERR_HTTP2_PROTOCOL_ERROR:
      return spdy::ERROR_CODE_PROTOCOL_ERROR;
    case ERR_HTTP2_FLOW_CONTROL_ERROR:
      return spdy::ERROR_CODE_FLOW_CONTROL_ERROR;
    case ERR_HTTP2_FRAME_SIZE_ERROR:
      return spdy::ERROR_CODE_FRAME_SIZE_ERROR;
    case ERR_HTTP2_COMPRESSION_ERROR:
      return spdy::ERROR_CODE_COMPRESSION_ERROR;
    case ERR_HTTP2_INADEQUATE_TRANSPORT_SECURITY:
      return spdy::ERROR_CODE_INADEQUATE_SECURITY;
    default:
      return spdy::ERROR_CODE_PROTOCOL_ERROR;
  }
}

SpdyStreamRequest::SpdyStreamRequest() {
  Reset();
}

SpdyStreamRequest::~SpdyStreamRequest() {
  CancelRequest();
}

int SpdyStreamRequest::StartRequest(
    SpdyStreamType type,
    const base::WeakPtr<SpdySession>& session,
    const GURL& url,
    bool can_send_early,
    RequestPriority priority,
    const SocketTag& socket_tag,
    const NetLogWithSource& net_log,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& traffic_annotation,
    bool detect_broken_connection,
    base::TimeDelta heartbeat_interval) {
  DCHECK(session);
  DCHECK(!session_);
  DCHECK(!stream_);
  DCHECK(callback_.is_null());
  DCHECK(url.is_valid()) << url.possibly_invalid_spec();

  type_ = type;
  session_ = session;
  url_ = SimplifyUrlForRequest(url);
  priority_ = priority;
  socket_tag_ = socket_tag;
  net_log_ = net_log;
  callback_ = std::move(callback);
  traffic_annotation_ = MutableNetworkTrafficAnnotationTag(traffic_annotation);
  detect_broken_connection_ = detect_broken_connection;
  heartbeat_interval_ = heartbeat_interval;

  // If early data is not allowed, confirm the handshake first.
  int rv = OK;
  if (!can_send_early) {
    rv = session_->ConfirmHandshake(
        base::BindOnce(&SpdyStreamRequest::OnConfirmHandshakeComplete,
                       weak_ptr_factory_.GetWeakPtr()));
  }
  if (rv != OK) {
    // If rv is ERR_IO_PENDING, OnConfirmHandshakeComplete() will call
    // TryCreateStream() later.
    return rv;
  }

  base::WeakPtr<SpdyStream> stream;
  rv = session->TryCreateStream(weak_ptr_factory_.GetWeakPtr(), &stream);
  if (rv != OK) {
    // If rv is ERR_IO_PENDING, the SpdySession will call
    // OnRequestCompleteSuccess() or OnRequestCompleteFailure() later.
    return rv;
  }

  Reset();
  stream_ = stream;
  return OK;
}

void SpdyStreamRequest::CancelRequest() {
  if (session_)
    session_->CancelStreamRequest(weak_ptr_factory_.GetWeakPtr());
  Reset();
  // Do this to cancel any pending CompleteStreamRequest() and
  // OnConfirmHandshakeComplete() tasks.
  weak_ptr_factory_.InvalidateWeakPtrs();
}

base::WeakPtr<SpdyStream> SpdyStreamRequest::ReleaseStream() {
  DCHECK(!session_);
  base::WeakPtr<SpdyStream> stream = stream_;
  DCHECK(stream);
  Reset();
  return stream;
}

void SpdyStreamRequest::SetPriority(RequestPriority priority) {
  if (priority_ == priority)
    return;

  if (stream_)
    stream_->SetPriority(priority);
  if (session_)
    session_->ChangeStreamRequestPriority(weak_ptr_factory_.GetWeakPtr(),
                                          priority);
  priority_ = priority;
}

void SpdyStreamRequest::OnRequestCompleteSuccess(
    const base::WeakPtr<SpdyStream>& stream) {
  DCHECK(session_);
  DCHECK(!stream_);
  DCHECK(!callback_.is_null());
  CompletionOnceCallback callback = std::move(callback_);
  Reset();
  DCHECK(stream);
  stream_ = stream;
  std::move(callback).Run(OK);
}

void SpdyStreamRequest::OnRequestCompleteFailure(int rv) {
  DCHECK(session_);
  DCHECK(!stream_);
  DCHECK(!callback_.is_null());
  CompletionOnceCallback callback = std::move(callback_);
  Reset();
  DCHECK_NE(rv, OK);
  std::move(callback).Run(rv);
}

void SpdyStreamRequest::Reset() {
  type_ = SPDY_BIDIRECTIONAL_STREAM;
  session_.reset();
  stream_.reset();
  url_ = GURL();
  priority_ = MINIMUM_PRIORITY;
  socket_tag_ = SocketTag();
  net_log_ = NetLogWithSource();
  callback_.Reset();
  traffic_annotation_.reset();
}

void SpdyStreamRequest::OnConfirmHandshakeComplete(int rv) {
  DCHECK_NE(ERR_IO_PENDING, rv);
  if (!session_)
    return;

  if (rv != OK) {
    OnRequestCompleteFailure(rv);
    return;
  }

  // ConfirmHandshake() completed asynchronously. Record the time so the caller
  // can adjust LoadTimingInfo.
  confirm_handshake_end_ = base::TimeTicks::Now();

  if (!session_) {
    OnRequestCompleteFailure(ERR_CONNECTION_CLOSED);
    return;
  }

  base::WeakPtr<SpdyStream> stream;
  rv = session_->TryCreateStream(weak_ptr_factory_.GetWeakPtr(), &stream);
  if (rv == OK) {
    OnRequestCompleteSuccess(stream);
  } else if (rv != ERR_IO_PENDING) {
    // If rv is ERR_IO_PENDING, the SpdySession will call
    // OnRequestCompleteSuccess() or OnRequestCompleteFailure() later.
    OnRequestCompleteFailure(rv);
  }
}

// static
bool SpdySession::CanPool(TransportSecurityState* transport_security_state,
                          const SSLInfo& ssl_info,
                          const SSLConfigService& ssl_config_service,
                          std::string_view old_hostname,
                          std::string_view new_hostname) {
  // Pooling is prohibited if the server cert is not valid for the new domain,
  // and for connections on which client certs were sent. It is also prohibited
  // when channel ID was sent if the hosts are from different eTLDs+1.
  if (IsCertStatusError(ssl_info.cert_status))
    return false;

  if (ssl_info.client_cert_sent &&
      !(ssl_config_service.CanShareConnectionWithClientCerts(old_hostname) &&
        ssl_config_service.CanShareConnectionWithClientCerts(new_hostname))) {
    return false;
  }

  if (!ssl_info.cert->VerifyNameMatch(new_hostname))
    return false;

  // Port is left at 0 as it is never used.
  if (transport_security_state->CheckPublicKeyPins(
          HostPortPair(new_hostname, 0), ssl_info.is_issued_by_known_root,
          ssl_info.public_key_hashes) ==
      TransportSecurityState::PKPStatus::VIOLATED) {
    return false;
  }

  switch (transport_security_state->CheckCTRequirements(
      HostPortPair(new_hostname, 0), ssl_info.is_issued_by_known_root,
      ssl_info.public_key_hashes, ssl_info.cert.get(),
      ssl_info.ct_policy_compliance)) {
    case TransportSecurityState::CT_REQUIREMENTS_NOT_MET:
      return false;
    case TransportSecurityState::CT_REQUIREMENTS_MET:
    case TransportSecurityState::CT_NOT_REQUIRED:
      // Intentional fallthrough; this case is just here to make sure that all
      // possible values of CheckCTRequirements() are handled.
      break;
  }

  return true;
}

SpdySession::SpdySession(
    const SpdySessionKey& spdy_session_key,
    HttpServerProperties* http_server_properties,
    TransportSecurityState* transport_security_state,
    SSLConfigService* ssl_config_service,
    const quic::ParsedQuicVersionVector& quic_supported_versions,
    bool enable_sending_initial_data,
    bool enable_ping_based_connection_checking,
    bool is_http2_enabled,
    bool is_quic_enabled,
    size_t session_max_recv_window_size,
    int session_max_queued_capped_frames,
    const spdy::SettingsMap& initial_settings,
    bool enable_http2_settings_grease,
    const std::optional<SpdySessionPool::GreasedHttp2Frame>&
        greased_http2_frame,
    bool http2_end_stream_with_data_frame,
    bool enable_priority_update,
    TimeFunc time_func,
    NetworkQualityEstimator* network_quality_estimator,
    NetLog* net_log,
    MultiplexedSessionCreationInitiator session_creation_initiator)
    : spdy_session_key_(spdy_session_key),
      http_server_properties_(http_server_properties),
      transport_security_state_(transport_security_state),
      ssl_config_service_(ssl_config_service),
      stream_hi_water_mark_(kFirstStreamId),
      initial_settings_(initial_settings),
      enable_http2_settings_grease_(enable_http2_settings_grease),
      greased_http2_frame_(greased_http2_frame),
      http2_end_stream_with_data_frame_(http2_end_stream_with_data_frame),
      enable_priority_update_(enable_priority_update),
      max_concurrent_streams_(kInitialMaxConcurrentStreams),
      last_read_time_(time_func()),
      session_max_recv_window_size_(session_max_recv_window_size),
      session_max_queued_capped_frames_(session_max_queued_capped_frames),
      last_recv_window_update_(base::TimeTicks::Now()),
      time_to_buffer_small_window_updates_(
          kDefaultTimeToBufferSmallWindowUpdates),
      stream_initial_send_window_size_(kDefaultInitialWindowSize),
      max_header_table_size_(
          initial_settings.at(spdy::SETTINGS_HEADER_TABLE_SIZE)),
      stream_max_recv_window_size_(
          initial_settings.at(spdy::SETTINGS_INITIAL_WINDOW_SIZE)),
      net_log_(
          NetLogWithSource::Make(net_log, NetLogSourceType::HTTP2_SESSION)),
      quic_supported_versions_(quic_supported_versions),
      enable_sending_initial_data_(enable_sending_initial_data),
      enable_ping_based_connection_checking_(
          enable_ping_based_connection_checking),
      is_http2_enabled_(is_http2_enabled),
      is_quic_enabled_(is_quic_enabled),
      connection_at_risk_of_loss_time_(
          base::Seconds(kDefaultConnectionAtRiskOfLossSeconds)),
      hung_interval_(base::Seconds(kHungIntervalSeconds)),
      time_func_(time_func),
      network_quality_estimator_(network_quality_estimator),
      session_creation_initiator_(session_creation_initiator) {
  net_log_.BeginEvent(NetLogEventType::HTTP2_SESSION, [&] {
    return NetLogSpdySessionParams(host_port_proxy_pair());
  });

  DCHECK(base::Contains(initial_settings_, spdy::SETTINGS_HEADER_TABLE_SIZE));
  DCHECK(base::Contains(initial_settings_, spdy::SETTINGS_INITIAL_WINDOW_SIZE));

  if (greased_http2_frame_) {
    // See https://tools.ietf.org/html/draft-bishop-httpbis-grease-00
    // for reserved frame types.
    DCHECK_EQ(0x0b, greased_http2_frame_.value().type % 0x1f);
  }

  // TODO(mbelshe): consider randomization of the stream_hi_water_mark.
}

SpdySession::~SpdySession() {
  CHECK(!in_io_loop_);
  DcheckDraining();

  DCHECK(waiting_for_confirmation_callbacks_.empty());

  DCHECK_EQ(broken_connection_detection_requests_, 0);

  // TODO(akalin): Check connection->is_initialized().
  DCHECK(socket_);
  // With SPDY we can't recycle sockets.
  socket_->Disconnect();

  RecordHistograms();

  net_log_.EndEvent(NetLogEventType::HTTP2_SESSION);
}

void SpdySession::InitializeWithSocketHandle(
    std::unique_ptr<S
```