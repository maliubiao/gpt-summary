Response:
Let's break down the thought process for analyzing the `quic_http3_logger.cc` file.

**1. Understanding the Core Purpose:**

The filename `quic_http3_logger.cc` immediately suggests its primary function: logging events related to HTTP/3 over QUIC. The `logger` suffix is a strong indicator. The presence of `net/quic` in the path reinforces this.

**2. Identifying Key Components and Concepts:**

* **`NetLogWithSource`:** This is a fundamental networking logging mechanism in Chromium. The logger takes this as input, indicating it's writing to this central logging system.
* **`quic::*`:**  This namespace signifies interaction with the QUIC protocol implementation. We see things like `quic::SettingsFrame`, `quic::GoAwayFrame`, `quic::QuicStreamId`, `quic::QuicHeaderList`, etc. These are the core data structures and concepts of QUIC and HTTP/3.
* **`NetLogEventType::HTTP3_*`:**  The numerous `NetLogEventType` constants prefixed with `HTTP3_` clearly define the types of events being logged.
* **`base::Value::Dict` and `base::Value::List`:** These are used to construct structured log data in JSON-like format.
* **`UMA_HISTOGRAM_*`:**  This indicates that the logger also collects and reports metrics.
* **`Elide*ForNetLog` functions:**  These functions suggest that the logger is careful about what data is included in the logs, likely for privacy or performance reasons.

**3. Analyzing the Individual Functions:**

For each function, the analysis follows a pattern:

* **Check `net_log_.IsCapturing()`:** This is the first step in almost every function. It's a performance optimization – if logging isn't enabled, don't do any of the logging work.
* **Identify the Triggering Event:** What QUIC/HTTP3 event causes this function to be called?  (e.g., `OnSettingsFrameReceived` is called when a settings frame is received).
* **Determine the Logged Event Type:** What `NetLogEventType::HTTP3_*` event is being recorded?
* **Examine the Logged Parameters:** What information from the triggering event is extracted and added to the log?  Notice how the `NetLog*Params` helper functions structure this data.
* **Note any UMA Histograms:** Are there any metrics being recorded alongside the log event? What data are they tracking?
* **Look for any special handling:**  For example, the handling of reserved settings identifiers in `OnSettingsFrameReceived`.

**4. Inferring Functionality and Relationships:**

* **Centralized Logging:** The logger acts as a central point for recording significant HTTP/3 events within the QUIC stack.
* **Debugging and Monitoring:** The logged information is valuable for debugging connection issues, analyzing performance, and understanding protocol behavior.
* **Metrics Collection:** The UMA histograms provide insights into the frequency and characteristics of certain HTTP/3 events.

**5. Addressing Specific Questions in the Prompt:**

* **Javascript Relationship:**  The key is to understand that while this C++ code doesn't *directly* interact with Javascript, the logged events are crucial for browser developers (often using Javascript) to understand network behavior. The browser's developer tools use this kind of logging information.
* **Logical Reasoning (Hypothetical Input/Output):** Focus on a single function and a specific event. Trace the input data to the logged output structure.
* **User/Programming Errors:** Think about scenarios where the logged events could indicate a problem. Incorrectly configured settings, unexpected frame types, or failures in header decoding are good examples.
* **User Operations and Debugging:**  Consider how user actions in the browser (navigating, downloading, etc.) would trigger the underlying network activity that this logger records. Then, explain how a developer would use the logs to trace these actions.

**6. Structuring the Output:**

Organize the information logically:

* Start with a high-level summary of the file's purpose.
* Detail the functionalities by analyzing the key functions.
* Address the specific questions from the prompt with clear examples.
* Conclude with a summary of the file's importance.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:** "This just logs things."
* **Refinement:** "It logs *specific* HTTP/3 events with *structured* data and also collects *metrics*."
* **Initial thought:** "Javascript doesn't interact with this C++ code."
* **Refinement:** "While direct interaction is absent, the *results* of this logging are used by Javascript-based developer tools for debugging, creating an indirect but important relationship."
* **Ensure clarity:** Use precise language (e.g., "NetLog events," "UMA histograms") and avoid jargon where possible. Provide concrete examples.

By following these steps, we can systematically analyze the code and provide a comprehensive and accurate explanation of its functionality. The process involves understanding the core concepts, examining individual components, inferring relationships, and addressing specific requirements of the prompt.
这个文件 `net/quic/quic_http3_logger.cc` 是 Chromium 网络栈中负责记录与 HTTP/3 协议相关的事件的日志记录器。它使用 Chromium 的 `NetLog` 系统来记录这些事件，以便进行调试、性能分析和监控。

以下是它的功能列表：

**核心功能：**

1. **记录 HTTP/3 控制流事件:**
   - 创建本地和对端控制流 (`OnControlStreamCreated`, `OnPeerControlStreamCreated`).
   - 创建本地和对端 QPACK 编码器/解码器流 (`OnQpackEncoderStreamCreated`, `OnQpackDecoderStreamCreated`, `OnPeerQpackEncoderStreamCreated`, `OnPeerQpackDecoderStreamCreated`).

2. **记录 HTTP/3 帧的接收和发送:**
   - 接收到的 SETTINGS 帧 (`OnSettingsFrameReceived`).
   - 接收到的 GOAWAY 帧 (`OnGoAwayFrameReceived`).
   - 接收到的 PRIORITY_UPDATE 帧 (`OnPriorityUpdateFrameReceived`).
   - 接收到的 DATA 帧 (`OnDataFrameReceived`).
   - 接收到的 HEADERS 帧 (`OnHeadersFrameReceived`).
   - 解码后的头部信息 (`OnHeadersDecoded`).
   - 接收到的未知帧 (`OnUnknownFrameReceived`).
   - 发送的 SETTINGS 帧 (`OnSettingsFrameSent`, `OnSettingsFrameResumed`).
   - 发送的 GOAWAY 帧 (`OnGoAwayFrameSent`).
   - 发送的 PRIORITY_UPDATE 帧 (`OnPriorityUpdateFrameSent`).
   - 发送的 DATA 帧 (`OnDataFrameSent`).
   - 发送的 HEADERS 帧 (`OnHeadersFrameSent`).

3. **记录帧的详细信息:**
   - 对于 SETTINGS 帧，记录各个设置项的键值对。
   - 对于 PRIORITY_UPDATE 帧，记录被优先处理的元素 ID 和优先级字段值。
   - 对于 DATA 和 HEADERS 帧，记录流 ID 和 payload/头部的长度。
   - 对于 HEADERS 帧，记录解码后的头部键值对。
   - 对于未知帧，记录流 ID、帧类型和 payload 长度。

4. **使用 UMA 记录指标:**
   - 接收到的 SETTINGS 帧的数量 (`Net.QuicSession.ReceivedSettings.CountPlusOne`).
   - 接收到的 SETTINGS 帧中特定设置项的值 (例如 `SETTINGS_QPACK_MAX_TABLE_CAPACITY`, `SETTINGS_MAX_FIELD_SECTION_SIZE`, `SETTINGS_QPACK_BLOCKED_STREAMS`).
   - 接收到的 SETTINGS 帧中保留的标识符的数量 (`Net.QuicSession.ReceivedSettings.ReservedCountPlusOne`).

5. **格式化日志输出:**
   - 使用 `base::Value::Dict` 和 `base::Value::List` 构建结构化的 JSON 格式的日志信息。
   - 使用 `net::NetLogStringValue` 和 `net::NetLogNumberValue` 等辅助函数来安全地记录字符串和数字。
   - 使用 `ElideQuicHeaderListForNetLog` 和 `ElideHttpHeaderBlockForNetLog` 函数来省略敏感的头部信息，取决于 NetLog 的捕获模式。

**与 Javascript 的关系：**

`quic_http3_logger.cc` 本身是用 C++ 编写的，直接与 Javascript 没有代码级别的交互。然而，它记录的事件对于在浏览器中运行的 Javascript 代码的开发者来说非常重要，可以通过以下方式关联：

1. **开发者工具 (DevTools):** Chrome 的开发者工具中的 "Network" 面板可以显示 HTTP/3 连接的详细信息，包括从 `NetLog` 中捕获的事件。开发者可以使用这些信息来调试他们的 Web 应用的网络问题，例如：
   - 查看收发的 HTTP/3 头部信息。
   - 检查是否收到了预期的 SETTINGS 帧。
   - 监控流的创建和关闭。
   - 分析性能瓶颈，例如大的数据帧传输。

2. **`chrome://net-export/`:**  用户可以使用 `chrome://net-export/` 页面导出包含 NetLog 事件的 JSON 文件。这些文件可以被开发者用于离线分析网络行为，包括 HTTP/3 相关的事件。 Javascript 开发者可能会使用各种工具来解析和分析这些 JSON 数据，以了解其应用的网络交互情况。

**举例说明 Javascript 如何间接利用这些信息：**

假设一个 Javascript 应用发起了一个 HTTP/3 请求，但请求失败了。开发者可以：

1. 打开 Chrome 开发者工具的 "Network" 面板。
2. 重新加载页面或再次触发该请求。
3. 在 "Network" 面板中找到该请求，并查看其详细信息。
4. 在请求的 "Headers" 或 "Timing" 标签中，可能会看到与 HTTP/3 相关的事件信息，这些信息正是由 `quic_http3_logger.cc` 记录的，例如：
   -  如果 `OnSettingsFrameReceived` 记录了对端发送的 SETTINGS 帧，开发者可以检查对端是否支持必要的 HTTP/3 功能。
   -  如果 `OnGoAwayFrameReceived` 记录了服务端发送的 GOAWAY 帧，开发者可以了解服务端是否主动断开了连接以及原因。
   -  如果 `OnHeadersDecoded` 记录了接收到的头部信息，开发者可以检查返回的状态码和头部是否正确。

**逻辑推理，假设输入与输出：**

**假设输入：**  服务端发送了一个包含以下设置的 SETTINGS 帧：

```
SETTINGS_MAX_CONCURRENT_STREAMS: 100
SETTINGS_MAX_HEADER_LIST_SIZE: 8192
```

**处理过程：** `QuicHttp3Logger::OnSettingsFrameReceived` 函数会被调用，参数 `frame` 包含上述设置。

**输出 (NetLog 事件):**  会产生一个 `NetLogEventType::HTTP3_SETTINGS_RECEIVED` 事件，其关联的参数会是类似以下的 JSON 结构：

```json
{
  "SETTINGS_MAX_CONCURRENT_STREAMS": 100,
  "SETTINGS_MAX_HEADER_LIST_SIZE": 8192
}
```

**输出 (UMA 指标):**

- `Net.QuicSession.ReceivedSettings.CountPlusOne` 会增加 1（因为收到了一个非空的 SETTINGS 帧）。
- `Net.QuicSession.ReceivedSettings.MaxHeaderListSize2` 可能会记录值 8192。

**涉及用户或编程常见的使用错误：**

1. **依赖于未记录的事件进行调试:**  开发者可能会错误地假设某个 HTTP/3 事件会被记录，但实际上 `QuicHttp3Logger` 并未记录该事件。这会导致调试信息不完整。例如，如果开发者期望看到每个 HPACK 解码的细节，但 `QuicHttp3Logger` 只记录了最终解码的头部列表。

2. **错误地解析 NetLog 输出:**  开发者可能会手动解析 `chrome://net-export/` 导出的 JSON 文件，但由于对 NetLog 的结构或字段的含义理解不足，导致错误地分析了网络行为。例如，错误地认为某个事件的发生顺序或参数值表示了特定的问题。

3. **过度依赖日志进行性能分析:**  虽然日志可以提供有用的性能信息（例如，大的数据帧），但过度依赖日志进行精确的性能分析可能会引入偏差。日志记录本身会消耗一定的资源，可能会影响实际的性能表现。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户报告一个网页加载缓慢的问题。作为调试线索，可以按照以下步骤查看 `QuicHttp3Logger` 记录的事件：

1. **用户操作:** 用户在 Chrome 浏览器中输入一个 URL 并按下回车键，或者点击一个链接。

2. **网络请求发起:** Chrome 的网络栈开始处理该请求，如果服务器支持 HTTP/3，则会尝试建立 QUIC 连接并使用 HTTP/3 协议进行通信。

3. **HTTP/3 连接建立和数据传输:**
   - 在连接建立阶段，会交换 SETTINGS 帧，`QuicHttp3Logger` 的 `OnSettingsFrameSent` 和 `OnSettingsFrameReceived` 会记录这些信息。
   - 请求的头部信息会以 HEADERS 帧发送，`OnHeadersFrameSent` 会记录。
   - 服务器返回的响应头部信息会被接收，`OnHeadersFrameReceived` 和 `OnHeadersDecoded` 会记录。
   - 响应的数据会以 DATA 帧传输，`OnDataFrameReceived` 会记录。

4. **如果出现问题 (例如加载缓慢):**
   - 开发者可以打开 `chrome://net-export/` 并开始捕获网络日志。
   - 用户复现加载缓慢的问题。
   - 开发者停止捕获并保存日志文件。
   - 开发者可以分析导出的 JSON 文件，查找与目标网页相关的 QUIC 连接和 HTTP/3 事件。

5. **分析 `QuicHttp3Logger` 的输出作为调试线索:**
   - **检查 SETTINGS 帧:** 确保客户端和服务端都协商了必要的 HTTP/3 功能。
   - **检查 HEADERS 帧的大小和内容:** 看看是否有异常大的头部导致延迟。
   - **检查 DATA 帧的接收情况:**  是否有大量的 DATA 帧，或者帧的传输速率是否缓慢。
   - **检查是否有 GOAWAY 帧:**  如果服务端发送了 GOAWAY 帧，可以了解连接是否被意外终止。
   - **查看时间戳 (NetLog 中包含):**  可以分析不同事件之间的时间间隔，找出潜在的瓶颈。例如，从发送请求到接收到第一个 DATA 帧的时间间隔可能很长。

通过分析 `QuicHttp3Logger` 记录的这些事件，开发者可以更深入地了解 HTTP/3 连接的建立和数据传输过程，从而定位导致网页加载缓慢的具体原因。

Prompt: 
```
这是目录为net/quic/quic_http3_logger.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/quic/quic_http3_logger.h"

#include <algorithm>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

#include "base/metrics/histogram_macros.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "net/http/http_log_util.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_values.h"
#include "net/spdy/spdy_log_util.h"

namespace net {

namespace {

base::Value::Dict NetLogSettingsParams(const quic::SettingsFrame& frame) {
  base::Value::Dict dict;
  for (auto setting : frame.values) {
    dict.Set(
        quic::H3SettingsToString(
            static_cast<quic::Http3AndQpackSettingsIdentifiers>(setting.first)),
        static_cast<int>(setting.second));
  }
  return dict;
}

base::Value::Dict NetLogPriorityUpdateParams(
    const quic::PriorityUpdateFrame& frame) {
  return base::Value::Dict()
      .Set("prioritized_element_id",
           NetLogNumberValue(frame.prioritized_element_id))
      .Set("priority_field_value", frame.priority_field_value);
}

base::Value::Dict NetLogTwoIntParams(std::string_view name1,
                                     uint64_t value1,
                                     std::string_view name2,
                                     uint64_t value2) {
  return base::Value::Dict()
      .Set(name1, NetLogNumberValue(value1))
      .Set(name2, NetLogNumberValue(value2));
}

base::Value::Dict NetLogThreeIntParams(std::string_view name1,
                                       uint64_t value1,
                                       std::string_view name2,
                                       uint64_t value2,
                                       std::string_view name3,
                                       uint64_t value3) {
  return base::Value::Dict()
      .Set(name1, NetLogNumberValue(value1))
      .Set(name2, NetLogNumberValue(value2))
      .Set(name3, NetLogNumberValue(value3));
}

base::Value::List ElideQuicHeaderListForNetLog(
    const quic::QuicHeaderList& headers,
    NetLogCaptureMode capture_mode) {
  base::Value::List headers_list;
  for (const auto& header : headers) {
    std::string_view key = header.first;
    std::string_view value = header.second;
    headers_list.Append(NetLogStringValue(
        base::StrCat({key, ": ",
                      ElideHeaderValueForNetLog(capture_mode, std::string(key),
                                                std::string(value))})));
  }
  return headers_list;
}

}  // namespace

QuicHttp3Logger::QuicHttp3Logger(const NetLogWithSource& net_log)
    : net_log_(net_log) {}

QuicHttp3Logger::~QuicHttp3Logger() = default;

void QuicHttp3Logger::OnControlStreamCreated(quic::QuicStreamId stream_id) {
  if (!net_log_.IsCapturing()) {
    return;
  }
  net_log_.AddEventWithIntParams(
      NetLogEventType::HTTP3_LOCAL_CONTROL_STREAM_CREATED, "stream_id",
      stream_id);
}

void QuicHttp3Logger::OnQpackEncoderStreamCreated(
    quic::QuicStreamId stream_id) {
  if (!net_log_.IsCapturing()) {
    return;
  }
  net_log_.AddEventWithIntParams(
      NetLogEventType::HTTP3_LOCAL_QPACK_ENCODER_STREAM_CREATED, "stream_id",
      stream_id);
}

void QuicHttp3Logger::OnQpackDecoderStreamCreated(
    quic::QuicStreamId stream_id) {
  if (!net_log_.IsCapturing()) {
    return;
  }
  net_log_.AddEventWithIntParams(
      NetLogEventType::HTTP3_LOCAL_QPACK_DECODER_STREAM_CREATED, "stream_id",
      stream_id);
}

void QuicHttp3Logger::OnPeerControlStreamCreated(quic::QuicStreamId stream_id) {
  if (!net_log_.IsCapturing())
    return;
  net_log_.AddEventWithIntParams(
      NetLogEventType::HTTP3_PEER_CONTROL_STREAM_CREATED, "stream_id",
      stream_id);
}

void QuicHttp3Logger::OnPeerQpackEncoderStreamCreated(
    quic::QuicStreamId stream_id) {
  if (!net_log_.IsCapturing())
    return;
  net_log_.AddEventWithIntParams(
      NetLogEventType::HTTP3_PEER_QPACK_ENCODER_STREAM_CREATED, "stream_id",
      stream_id);
}

void QuicHttp3Logger::OnPeerQpackDecoderStreamCreated(
    quic::QuicStreamId stream_id) {
  if (!net_log_.IsCapturing())
    return;
  net_log_.AddEventWithIntParams(
      NetLogEventType::HTTP3_PEER_QPACK_DECODER_STREAM_CREATED, "stream_id",
      stream_id);
}

void QuicHttp3Logger::OnSettingsFrameReceived(
    const quic::SettingsFrame& frame) {
  // Increment value by one because empty SETTINGS frames are allowed,
  // but histograms do not support the value zero.
  UMA_HISTOGRAM_CUSTOM_COUNTS("Net.QuicSession.ReceivedSettings.CountPlusOne",
                              frame.values.size() + 1, /* min = */ 1,
                              /* max = */ 10, /* buckets = */ 10);
  int reserved_identifier_count = 0;
  for (const auto& value : frame.values) {
    if (value.first == quic::SETTINGS_QPACK_MAX_TABLE_CAPACITY) {
      UMA_HISTOGRAM_COUNTS_1M(
          "Net.QuicSession.ReceivedSettings.MaxTableCapacity2", value.second);
    } else if (value.first == quic::SETTINGS_MAX_FIELD_SECTION_SIZE) {
      UMA_HISTOGRAM_COUNTS_1M(
          "Net.QuicSession.ReceivedSettings.MaxHeaderListSize2", value.second);
    } else if (value.first == quic::SETTINGS_QPACK_BLOCKED_STREAMS) {
      UMA_HISTOGRAM_COUNTS_1000(
          "Net.QuicSession.ReceivedSettings.BlockedStreams", value.second);
    } else if (value.first >= 0x21 && value.first % 0x1f == 2) {
      // Reserved setting identifiers are defined at
      // https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-defined-settings-parameters.
      // These should not be treated specially on the receive side, because they
      // are sent to exercise the requirement that unknown identifiers are
      // ignored.  Here an exception is made for logging only, to understand
      // what kind of identifiers are received.
      reserved_identifier_count++;
    }
  }
  UMA_HISTOGRAM_CUSTOM_COUNTS(
      "Net.QuicSession.ReceivedSettings.ReservedCountPlusOne",
      reserved_identifier_count + 1, /* min = */ 1,
      /* max = */ 5, /* buckets = */ 5);

  if (!net_log_.IsCapturing())
    return;
  net_log_.AddEvent(NetLogEventType::HTTP3_SETTINGS_RECEIVED,
                    [&frame] { return NetLogSettingsParams(frame); });
}

void QuicHttp3Logger::OnGoAwayFrameReceived(const quic::GoAwayFrame& frame) {
  if (!net_log_.IsCapturing()) {
    return;
  }
  net_log_.AddEventWithIntParams(NetLogEventType::HTTP3_GOAWAY_RECEIVED,
                                 "stream_id", frame.id);
}

void QuicHttp3Logger::OnPriorityUpdateFrameReceived(
    const quic::PriorityUpdateFrame& frame) {
  if (!net_log_.IsCapturing()) {
    return;
  }
  net_log_.AddEvent(NetLogEventType::HTTP3_PRIORITY_UPDATE_RECEIVED,
                    [&frame] { return NetLogPriorityUpdateParams(frame); });
}

void QuicHttp3Logger::OnDataFrameReceived(quic::QuicStreamId stream_id,
                                          quic::QuicByteCount payload_length) {
  if (!net_log_.IsCapturing()) {
    return;
  }
  net_log_.AddEvent(
      NetLogEventType::HTTP3_DATA_FRAME_RECEIVED, [stream_id, payload_length] {
        return NetLogTwoIntParams("stream_id", stream_id, "payload_length",
                                  payload_length);
      });
}

void QuicHttp3Logger::OnHeadersFrameReceived(
    quic::QuicStreamId stream_id,
    quic::QuicByteCount compressed_headers_length) {
  if (!net_log_.IsCapturing()) {
    return;
  }
  net_log_.AddEvent(NetLogEventType::HTTP3_HEADERS_RECEIVED,
                    [stream_id, compressed_headers_length] {
                      return NetLogTwoIntParams("stream_id", stream_id,
                                                "compressed_headers_length",
                                                compressed_headers_length);
                    });
}

void QuicHttp3Logger::OnHeadersDecoded(quic::QuicStreamId stream_id,
                                       quic::QuicHeaderList headers) {
  if (!net_log_.IsCapturing()) {
    return;
  }
  net_log_.AddEvent(
      NetLogEventType::HTTP3_HEADERS_DECODED,
      [stream_id, &headers](NetLogCaptureMode capture_mode) {
        return base::Value::Dict()
            .Set("stream_id",
                 NetLogNumberValue(static_cast<uint64_t>(stream_id)))
            .Set("headers",
                 ElideQuicHeaderListForNetLog(headers, capture_mode));
      });
}

void QuicHttp3Logger::OnUnknownFrameReceived(
    quic::QuicStreamId stream_id,
    uint64_t frame_type,
    quic::QuicByteCount payload_length) {
  if (!net_log_.IsCapturing()) {
    return;
  }
  net_log_.AddEvent(NetLogEventType::HTTP3_UNKNOWN_FRAME_RECEIVED,
                    [stream_id, frame_type, payload_length] {
                      return NetLogThreeIntParams(
                          "stream_id", stream_id, "frame_type", frame_type,
                          "payload_length", payload_length);
                    });
}

void QuicHttp3Logger::OnSettingsFrameSent(const quic::SettingsFrame& frame) {
  if (!net_log_.IsCapturing())
    return;
  net_log_.AddEvent(NetLogEventType::HTTP3_SETTINGS_SENT,
                    [&frame] { return NetLogSettingsParams(frame); });
}

void QuicHttp3Logger::OnSettingsFrameResumed(const quic::SettingsFrame& frame) {
  if (!net_log_.IsCapturing())
    return;
  net_log_.AddEvent(NetLogEventType::HTTP3_SETTINGS_RESUMED,
                    [&frame] { return NetLogSettingsParams(frame); });
}

void QuicHttp3Logger::OnGoAwayFrameSent(quic::QuicStreamId stream_id) {
  if (!net_log_.IsCapturing()) {
    return;
  }
  net_log_.AddEventWithIntParams(NetLogEventType::HTTP3_GOAWAY_SENT,
                                 "stream_id", stream_id);
}

void QuicHttp3Logger::OnPriorityUpdateFrameSent(
    const quic::PriorityUpdateFrame& frame) {
  if (!net_log_.IsCapturing()) {
    return;
  }
  net_log_.AddEvent(NetLogEventType::HTTP3_PRIORITY_UPDATE_SENT,
                    [&frame] { return NetLogPriorityUpdateParams(frame); });
}

void QuicHttp3Logger::OnDataFrameSent(quic::QuicStreamId stream_id,
                                      quic::QuicByteCount payload_length) {
  if (!net_log_.IsCapturing()) {
    return;
  }
  net_log_.AddEvent(
      NetLogEventType::HTTP3_DATA_SENT, [stream_id, payload_length] {
        return NetLogTwoIntParams("stream_id", stream_id, "payload_length",
                                  payload_length);
      });
}

void QuicHttp3Logger::OnHeadersFrameSent(
    quic::QuicStreamId stream_id,
    const quiche::HttpHeaderBlock& header_block) {
  if (!net_log_.IsCapturing()) {
    return;
  }
  net_log_.AddEvent(
      NetLogEventType::HTTP3_HEADERS_SENT,
      [stream_id, &header_block](NetLogCaptureMode capture_mode) {
        return base::Value::Dict()
            .Set("stream_id",
                 NetLogNumberValue(static_cast<uint64_t>(stream_id)))
            .Set("headers",
                 ElideHttpHeaderBlockForNetLog(header_block, capture_mode));
      });
}

}  // namespace net

"""

```