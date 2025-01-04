Response:
The user is asking for the functionality of the provided C++ code snippet from Chromium's Blink engine. This is the second part of a two-part file. The primary goal of this code is to convert WebRTC statistics received from the underlying platform into a format usable by JavaScript in the browser.

Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The presence of `ToV8Stat` functions and `RTCStatsToIDL` immediately suggests a data conversion process. The file name `rtc_stats_report.cc` further reinforces that this is about handling WebRTC statistics. The `V8` in the function names hints at interaction with the V8 JavaScript engine.

2. **Analyze the `ToV8Stat` Functions:**  Each `ToV8Stat` function corresponds to a specific type of WebRTC statistic (e.g., `RTCCodecStats`, `RTCIceCandidatePairStats`). These functions take a `webrtc::` stat structure as input and create a corresponding `blink::` stat object. The `set...` calls within these functions indicate mapping fields from the `webrtc::` structure to the `blink::` structure. The use of `String::FromUTF8` confirms the conversion to JavaScript strings.

3. **Analyze the `RTCStatsToIDL` Function:** This function acts as a central dispatcher. It takes a generic `webrtc::RTCStats` object and determines its specific type using `strcmp(stat.type(), ...)`. Based on the type, it calls the appropriate `ToV8Stat` function. This suggests a polymorphic handling of different stat types. The function also sets the `id`, `timestamp`, and `type` properties of the resulting `RTCStats` object. The timestamp calculation involving `DocumentLoadTiming` indicates integration with the browser's internal timing mechanisms.

4. **Analyze the `RTCStatsReportIterationSource` Class:** This class implements an iterator for the `RTCStatsReport`. The `FetchNextItem` function retrieves the next raw WebRTC stat, converts it to a V8-compatible format using `RTCStatsToIDL`, and returns the stat's ID as the key and the converted stat as the value. This structure is consistent with how JavaScript iterates over maps.

5. **Analyze the `RTCStatsReport` Class:** This class appears to be a wrapper around a platform-specific `RTCStatsReportPlatform`. The `size()` method simply returns the size from the platform object. The `CreateIterationSource` method creates the iterator. The `GetMapEntryIdl` and `GetMapEntry` methods allow accessing individual stats by their ID.

6. **Infer the Relationship with JavaScript/HTML/CSS:** The use of `ScriptState`, the creation of `blink::` objects (which are likely exposed to JavaScript), and the conversion to UTF8 strings strongly imply interaction with JavaScript. The `RTCStatsReport` is accessed by JavaScript to get information about the WebRTC connection. HTML and CSS are involved indirectly as they are the means through which the user interacts with the web page that uses WebRTC.

7. **Consider User Actions and Debugging:** To trigger the generation of these statistics, a user would need to be engaged in a WebRTC session (e.g., a video call). Debugging would involve inspecting the values of the `webrtc::` stats before and after conversion, potentially using browser developer tools to examine the JavaScript representation of the stats.

8. **Identify Potential User Errors:**  Misinterpreting the statistics or relying on non-standard stats are possible errors.

9. **Formulate Assumptions for Input/Output:** Based on the structure, it's reasonable to assume that the input is a `webrtc::RTCStats` object with various fields populated. The output is a corresponding `blink::RTCStats` object with the same information, ready for use in JavaScript.

10. **Address the "Part 2" Request:**  The final instruction asks to summarize the functionality of *this part* of the code. The focus should be on the conversion of individual stats and the iteration mechanism, building upon the general overview from Part 1 (if available).

By following these steps, it's possible to arrive at a comprehensive explanation of the code's functionality and its relation to web technologies.
这是`blink/renderer/modules/peerconnection/rtc_stats_report.cc`文件的第二部分，延续了第一部分的功能，主要负责将底层的WebRTC统计信息（`webrtc::RTCStats`）转换为Blink引擎中可供JavaScript访问的统计信息对象（例如`RTCCodecStats`, `RTCInboundRtpStreamStats`等）。

**本部分的功能归纳：**

1. **类型转换函数 (`ToV8Stat`)**:
   - 针对各种具体的WebRTC统计信息类型（如编解码器、ICE候选对、证书等），提供专门的转换函数。
   - 这些函数接收一个`webrtc::RTCStats`的子类对象作为输入，并创建一个对应的Blink引擎中的统计信息对象（以`RTCCodecStats*`，`RTCIceCandidatePairStats*`等命名）。
   - 函数内部会将`webrtc::`对象中的数据成员逐个映射到Blink引擎的对应对象中，例如将`webrtc_stat.packets_sent`的值赋给`v8_stat->setPacketsSent()`。
   - 对于字符串类型的数据，会使用`String::FromUTF8()`进行转换，使其能在V8 JavaScript引擎中使用。
   - 某些统计信息可能是可选的（`has_value()`），代码会进行检查，只在存在时才进行赋值。
   - 代码中还处理了一些非标准或已过时的统计信息字段。

2. **通用转换函数 (`RTCStatsToIDL`)**:
   - 这是一个核心的转换调度函数，接收一个通用的`webrtc::RTCStats`对象。
   - 它首先通过比较`stat.type()`的字符串值，来判断统计信息的具体类型（例如 "codec", "inbound-rtp", "candidate-pair" 等）。
   - 然后，它会根据判断结果，将`webrtc::RTCStats`对象强制转换为对应的子类类型（例如 `stat.cast_to<webrtc::RTCCodecStats>()`），并调用相应的`ToV8Stat`函数进行转换。
   - 对于 `media-source` 类型的统计信息，会进一步根据其 `kind` 属性（"audio" 或 "video"）来选择合适的转换函数。
   - 转换完成后，它还会设置通用统计信息对象的 `id`、`timestamp` 和 `type` 属性。
     - `id` 直接从 `stat.id()` 获取并转换为 UTF8 字符串。
     - `timestamp` 需要进行时间转换，从单调时间转换为伪墙时间，并以毫秒为单位。这涉及到 `DocumentLoadTiming` 类，表明时间戳是相对于页面加载时间的。
     - `type` 直接从 `stat.type()` 获取并转换为 UTF8 字符串。
   - 如果遇到未处理的统计信息类型，会输出日志信息。

3. **迭代器支持 (`RTCStatsReportIterationSource`)**:
   - 该类实现了用于迭代 `RTCStatsReport` 的迭代器。
   - `FetchNextItem` 和 `FetchNextItemIdl` 方法负责获取报告中的下一个统计信息。
   - 它会调用 `report_->NextStats()` 从底层平台获取下一个 `webrtc::RTCStats` 对象。
   - 然后，它调用 `RTCStatsToIDL` 将其转换为 Blink 的 `RTCStats` 对象。
   - 如果转换成功，将统计信息的 `id` 作为键，转换后的对象作为值返回。
   - 迭代器会跳过无法成功转换的统计信息。

4. **`RTCStatsReport` 类的实现**:
   - `RTCStatsReport` 类是 Blink 中表示统计信息报告的类，它包装了一个平台相关的 `RTCStatsReportPlatform` 对象。
   - `size()` 方法返回报告中统计信息的数量。
   - `CreateIterationSource()` 方法创建并返回一个用于迭代报告的 `RTCStatsReportIterationSource` 对象。
   - `GetMapEntryIdl` 和 `GetMapEntry` 方法允许通过统计信息的 `id` 来获取特定的统计信息对象。它们首先从底层平台获取对应的 `webrtc::RTCStats`，然后使用 `RTCStatsToIDL` 进行转换。

**与 JavaScript, HTML, CSS 的关系：**

- **JavaScript**:  `RTCStatsReport` 对象最终会被暴露给 JavaScript，通过 `RTCPeerConnection.getStats()` 方法获取。JavaScript 代码可以遍历这个报告，访问各种统计信息，例如：
  ```javascript
  pc.getStats().then(report => {
    report.forEach(stat => {
      console.log(stat.type, stat.id, stat.timestamp);
      if (stat.type === 'inbound-rtp') {
        console.log('Packets received:', stat.packetsReceived);
      }
    });
  });
  ```
  这里的 `report` 就是一个 `RTCStatsReport` 对象，它的 `forEach` 方法依赖于 `RTCStatsReportIterationSource` 提供的迭代能力。`stat` 对象则是 `RTCStats` 或其子类的实例，其属性值来源于 `ToV8Stat` 函数的映射。

- **HTML**: HTML 提供了用户界面，用户通过 HTML 元素（例如按钮）触发 JavaScript 代码来建立和管理 WebRTC 连接。`getStats()` 的调用通常是用户交互或者应用程序逻辑的一部分。

- **CSS**: CSS 负责页面的样式，与 `RTCStatsReport` 的功能没有直接关系。但统计信息的结果可能会被 JavaScript 用于动态更新页面上的元素，而这些元素的样式由 CSS 控制。例如，根据网络质量统计信息，JavaScript 可能会改变某个表示连接状态的图标的颜色。

**逻辑推理的假设输入与输出：**

**假设输入 (针对 `RTCStatsToIDL`):**

```c++
webrtc::RTCCodecStats webrtc_codec_stat;
webrtc_codec_stat.timestamp_us_ = 1678886400000000; // 假设的时间戳
webrtc_codec_stat.ssrc_ = 12345;
webrtc_codec_stat.payload_type_ = 100;
webrtc_codec_stat.mime_type_ = "video/VP8";
webrtc_codec_stat.clock_rate_ = 90000;
webrtc_codec_stat.channels_ = 1;
webrtc_codec_stat.id_ = "codec-1";
```

**假设输出 (对应的 JavaScript 可访问对象，由 `ToV8Stat` 生成):**

```javascript
{
  type: "codec",
  id: "codec-1",
  timestamp: /* 经过 DocumentLoadTiming 转换后的时间戳 (毫秒) */,
  payloadType: 100,
  mimeType: "video/VP8",
  clockRate: 90000,
  channels: 1,
  // ... 其他属性
}
```

**用户或编程常见的使用错误：**

1. **假设统计信息总是存在**: 开发者可能会假设某个特定的统计信息字段总是存在，而没有考虑到它是可选的。例如，假设 `inbound-rtp` 总是包含 `firCount`，但实际上可能在某些情况下不存在。这会导致 JavaScript 代码尝试访问 `undefined` 属性而出错。

   ```javascript
   pc.getStats().then(report => {
     report.forEach(stat => {
       if (stat.type === 'inbound-rtp') {
         console.log('FIR Count:', stat.firCount); // 如果 firCount 不存在，会报错
       }
     });
   });
   ```
   **修正**: 应该先检查属性是否存在：
   ```javascript
   if (stat.firCount !== undefined) {
     console.log('FIR Count:', stat.firCount);
   }
   ```

2. **误解统计信息的含义**: 开发者可能没有完全理解某些统计信息的具体含义和单位，导致错误的分析或展示。例如，将 `bytesSent` 误认为是比特数，或者不理解 `currentRoundTripTime` 的波动范围。

3. **依赖非标准统计信息**: 代码中提到了非标准和已过时的统计信息。开发者如果依赖这些信息，可能会在浏览器更新或切换浏览器时遇到兼容性问题。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户打开一个包含 WebRTC 功能的网页**: 用户在浏览器中访问一个使用了 WebRTC API 的网站，例如一个视频会议应用。
2. **网页 JavaScript 代码建立 `RTCPeerConnection`**: 网页的 JavaScript 代码会创建一个 `RTCPeerConnection` 对象，这是 WebRTC 连接的核心。
3. **建立 WebRTC 连接**:  JavaScript 代码会通过信令服务器交换会话描述（SDP）和 ICE 候选信息，最终建立起与其他用户的 WebRTC 连接。
4. **用户进行媒体通信**: 用户开始通过 WebRTC 连接发送和接收音频、视频或数据。
5. **网页 JavaScript 代码调用 `pc.getStats()`**:  为了监控连接状态或进行性能分析，网页的 JavaScript 代码会调用 `RTCPeerConnection` 对象的 `getStats()` 方法。
6. **浏览器引擎处理 `getStats()` 调用**: 浏览器引擎接收到 `getStats()` 的调用，会触发 Blink 引擎中相应的 C++ 代码来获取底层的 WebRTC 统计信息。
7. **`RTCStatsReportPlatform` 获取统计信息**: 底层的 `RTCStatsReportPlatform` 类会调用 WebRTC 库的接口来获取实时的统计数据。
8. **`RTCStatsReport` 和转换过程**:  Blink 引擎的 `RTCStatsReport` 类会接收到这些原始的统计数据，然后通过 `RTCStatsToIDL` 和 `ToV8Stat` 等函数将其转换为 JavaScript 可访问的格式。
9. **JavaScript 接收到 `RTCStatsReport` 对象**: 转换后的统计信息以 `RTCStatsReport` 对象的形式返回给 JavaScript 的 `getStats()` Promise 的 `then` 回调中。
10. **JavaScript 处理和展示统计信息**:  JavaScript 代码可以遍历这个 `RTCStatsReport` 对象，提取需要的统计信息，并在网页上展示出来，或者用于其他的逻辑判断。

在调试过程中，如果发现 JavaScript 获取到的统计信息不正确或缺失，可以从以下几个方面排查：

- **检查 `RTCStatsReportPlatform` 的实现**: 确认底层平台是否正确地获取了 WebRTC 库的统计信息。
- **断点调试 `RTCStatsToIDL` 和 `ToV8Stat`**:  检查转换过程中是否存在数据映射错误或类型转换问题。
- **查看 WebRTC 库的日志**:  确认 WebRTC 库本身是否产生了预期的统计数据。
- **检查 JavaScript 代码**:  确认 JavaScript 代码是否正确地解析和使用了返回的 `RTCStatsReport` 对象。

总而言之，这部分代码在 Chromium Blink 引擎中扮演着关键的角色，它将底层的、与平台相关的 WebRTC 统计信息桥接到上层的 JavaScript 环境，使得开发者能够监控和分析 WebRTC 连接的状态和性能。

Prompt: 
```
这是目录为blink/renderer/modules/peerconnection/rtc_stats_report.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""

  }
  return v8_stat;
}

// https://w3c.github.io/webrtc-stats/#candidatepair-dict*
RTCIceCandidatePairStats* ToV8Stat(
    ScriptState* script_state,
    const webrtc::RTCIceCandidatePairStats& webrtc_stat) {
  RTCIceCandidatePairStats* v8_stat =
      MakeGarbageCollected<RTCIceCandidatePairStats>(
          script_state->GetIsolate());
  if (webrtc_stat.transport_id.has_value()) {
    v8_stat->setTransportId(String::FromUTF8(*webrtc_stat.transport_id));
  }
  if (webrtc_stat.local_candidate_id.has_value()) {
    v8_stat->setLocalCandidateId(
        String::FromUTF8(*webrtc_stat.local_candidate_id));
  }
  if (webrtc_stat.remote_candidate_id.has_value()) {
    v8_stat->setRemoteCandidateId(
        String::FromUTF8(*webrtc_stat.remote_candidate_id));
  }
  if (webrtc_stat.state.has_value()) {
    v8_stat->setState(String::FromUTF8(*webrtc_stat.state));
  }
  if (webrtc_stat.nominated.has_value()) {
    v8_stat->setNominated(*webrtc_stat.nominated);
  }
  if (webrtc_stat.packets_sent.has_value()) {
    v8_stat->setPacketsSent(*webrtc_stat.packets_sent);
  }
  if (webrtc_stat.packets_received.has_value()) {
    v8_stat->setPacketsReceived(*webrtc_stat.packets_received);
  }
  if (webrtc_stat.bytes_sent.has_value()) {
    v8_stat->setBytesSent(*webrtc_stat.bytes_sent);
  }
  if (webrtc_stat.bytes_received.has_value()) {
    v8_stat->setBytesReceived(*webrtc_stat.bytes_received);
  }
  if (webrtc_stat.last_packet_sent_timestamp.has_value()) {
    v8_stat->setLastPacketSentTimestamp(
        *webrtc_stat.last_packet_sent_timestamp);
  }
  if (webrtc_stat.last_packet_received_timestamp.has_value()) {
    v8_stat->setLastPacketReceivedTimestamp(
        *webrtc_stat.last_packet_received_timestamp);
  }
  if (webrtc_stat.total_round_trip_time.has_value()) {
    v8_stat->setTotalRoundTripTime(*webrtc_stat.total_round_trip_time);
  }
  if (webrtc_stat.current_round_trip_time.has_value()) {
    v8_stat->setCurrentRoundTripTime(*webrtc_stat.current_round_trip_time);
  }
  if (webrtc_stat.available_outgoing_bitrate.has_value()) {
    v8_stat->setAvailableOutgoingBitrate(
        *webrtc_stat.available_outgoing_bitrate);
  }
  if (webrtc_stat.available_incoming_bitrate.has_value()) {
    v8_stat->setAvailableIncomingBitrate(
        *webrtc_stat.available_incoming_bitrate);
  }
  if (webrtc_stat.requests_received.has_value()) {
    v8_stat->setRequestsReceived(*webrtc_stat.requests_received);
  }
  if (webrtc_stat.requests_sent.has_value()) {
    v8_stat->setRequestsSent(*webrtc_stat.requests_sent);
  }
  if (webrtc_stat.responses_received.has_value()) {
    v8_stat->setResponsesReceived(*webrtc_stat.responses_received);
  }
  if (webrtc_stat.responses_sent.has_value()) {
    v8_stat->setResponsesSent(*webrtc_stat.responses_sent);
  }
  if (webrtc_stat.consent_requests_sent.has_value()) {
    v8_stat->setConsentRequestsSent(*webrtc_stat.consent_requests_sent);
  }
  if (webrtc_stat.packets_discarded_on_send.has_value()) {
    v8_stat->setPacketsDiscardedOnSend(
        base::saturated_cast<uint32_t>(*webrtc_stat.packets_discarded_on_send));
  }
  if (webrtc_stat.bytes_discarded_on_send.has_value()) {
    v8_stat->setBytesDiscardedOnSend(*webrtc_stat.bytes_discarded_on_send);
  }
  // Non-standard and obsolete stats.
  if (webrtc_stat.writable.has_value()) {
    v8_stat->setWritable(*webrtc_stat.writable);
  }
  if (webrtc_stat.priority.has_value()) {
    v8_stat->setPriority(*webrtc_stat.priority);
  }
  return v8_stat;
}

// https://w3c.github.io/webrtc-stats/#certificatestats-dict*
RTCCertificateStats* ToV8Stat(ScriptState* script_state,
                              const webrtc::RTCCertificateStats& webrtc_stat) {
  RTCCertificateStats* v8_stat =
      MakeGarbageCollected<RTCCertificateStats>(script_state->GetIsolate());
  if (webrtc_stat.fingerprint.has_value()) {
    v8_stat->setFingerprint(String::FromUTF8(*webrtc_stat.fingerprint));
  }
  if (webrtc_stat.fingerprint_algorithm.has_value()) {
    v8_stat->setFingerprintAlgorithm(
        String::FromUTF8(*webrtc_stat.fingerprint_algorithm));
  }
  if (webrtc_stat.base64_certificate.has_value()) {
    v8_stat->setBase64Certificate(
        String::FromUTF8(*webrtc_stat.base64_certificate));
  }
  if (webrtc_stat.issuer_certificate_id.has_value()) {
    v8_stat->setIssuerCertificateId(
        String::FromUTF8(*webrtc_stat.issuer_certificate_id));
  }
  return v8_stat;
}

RTCStats* RTCStatsToIDL(ScriptState* script_state,
                        const webrtc::RTCStats& stat,
                        bool expose_hardware_caps) {
  RTCStats* v8_stats = nullptr;
  if (strcmp(stat.type(), "codec") == 0) {
    v8_stats = ToV8Stat(script_state, stat.cast_to<webrtc::RTCCodecStats>());
  } else if (strcmp(stat.type(), "inbound-rtp") == 0) {
    v8_stats =
        ToV8Stat(script_state, stat.cast_to<webrtc::RTCInboundRtpStreamStats>(),
                 expose_hardware_caps);
  } else if (strcmp(stat.type(), "outbound-rtp") == 0) {
    v8_stats = ToV8Stat(script_state,
                        stat.cast_to<webrtc::RTCOutboundRtpStreamStats>(),
                        expose_hardware_caps);
  } else if (strcmp(stat.type(), "remote-inbound-rtp") == 0) {
    v8_stats = ToV8Stat(script_state,
                        stat.cast_to<webrtc::RTCRemoteInboundRtpStreamStats>());
  } else if (strcmp(stat.type(), "remote-outbound-rtp") == 0) {
    v8_stats = ToV8Stat(
        script_state, stat.cast_to<webrtc::RTCRemoteOutboundRtpStreamStats>());
  } else if (strcmp(stat.type(), "media-source") == 0) {
    // Type media-source indicates a parent type. The actual stats are based on
    // the kind.
    const auto& media_source =
        static_cast<const webrtc::RTCMediaSourceStats&>(stat);
    DCHECK(media_source.kind.has_value());
    std::string kind = media_source.kind.value_or("");
    if (kind == "audio") {
      v8_stats =
          ToV8Stat(script_state, stat.cast_to<webrtc::RTCAudioSourceStats>());
    } else if (kind == "video") {
      v8_stats =
          ToV8Stat(script_state, stat.cast_to<webrtc::RTCVideoSourceStats>());
    } else {
      NOTIMPLEMENTED() << "Unhandled media source stat type: " << kind;
      return nullptr;
    }
  } else if (strcmp(stat.type(), "media-playout") == 0) {
    v8_stats =
        ToV8Stat(script_state, stat.cast_to<webrtc::RTCAudioPlayoutStats>());
  } else if (strcmp(stat.type(), "peer-connection") == 0) {
    v8_stats =
        ToV8Stat(script_state, stat.cast_to<webrtc::RTCPeerConnectionStats>());
  } else if (strcmp(stat.type(), "data-channel") == 0) {
    v8_stats =
        ToV8Stat(script_state, stat.cast_to<webrtc::RTCDataChannelStats>());
  } else if (strcmp(stat.type(), "transport") == 0) {
    v8_stats =
        ToV8Stat(script_state, stat.cast_to<webrtc::RTCTransportStats>());
  } else if (strcmp(stat.type(), "candidate-pair") == 0) {
    v8_stats = ToV8Stat(script_state,
                        stat.cast_to<webrtc::RTCIceCandidatePairStats>());
  } else if (strcmp(stat.type(), "local-candidate") == 0) {
    v8_stats = ToV8Stat(script_state,
                        stat.cast_to<webrtc::RTCLocalIceCandidateStats>());
  } else if (strcmp(stat.type(), "remote-candidate") == 0) {
    v8_stats = ToV8Stat(script_state,
                        stat.cast_to<webrtc::RTCRemoteIceCandidateStats>());
  } else if (strcmp(stat.type(), "certificate") == 0) {
    v8_stats =
        ToV8Stat(script_state, stat.cast_to<webrtc::RTCCertificateStats>());
  } else {
    DVLOG(2) << "Unhandled stat-type " << stat.type();
    return nullptr;
  }

  v8_stats->setId(String::FromUTF8(stat.id()));
  LocalDOMWindow* window = LocalDOMWindow::From(script_state);
  DocumentLoadTiming& time_converter =
      window->GetFrame()->Loader().GetDocumentLoader()->GetTiming();
  v8_stats->setTimestamp(time_converter
                             .MonotonicTimeToPseudoWallTime(
                                 ConvertToBaseTimeTicks(stat.timestamp()))
                             .InMillisecondsF());
  v8_stats->setType(String::FromUTF8(stat.type()));
  return v8_stats;
}

class RTCStatsReportIterationSource final
    : public PairSyncIterable<RTCStatsReport>::IterationSource {
 public:
  explicit RTCStatsReportIterationSource(
      std::unique_ptr<RTCStatsReportPlatform> report)
      : report_(std::move(report)) {}

  bool FetchNextItem(ScriptState* script_state,
                     String& key,
                     ScriptValue& value,
                     ExceptionState& exception_state) override {
    return FetchNextItemIdl(script_state, key, value, exception_state);
  }

  bool FetchNextItemIdl(ScriptState* script_state,
                        String& key,
                        ScriptValue& value,
                        ExceptionState& exception_state) {
    const bool expose_hardware_caps =
        ExposeHardwareCapabilityStats(script_state);
    const webrtc::RTCStats* rtc_stats = report_->NextStats();
    RTCStats* v8_stat = nullptr;
    // Loop until a stat can be converted.
    while (rtc_stats) {
      v8_stat = RTCStatsToIDL(script_state, *rtc_stats, expose_hardware_caps);
      if (v8_stat) {
        break;
      }
      rtc_stats = report_->NextStats();
    }
    if (!rtc_stats) {
      return false;
    }
    key = String::FromUTF8(rtc_stats->id());
    value = ScriptValue::From(script_state, v8_stat);
    return true;
  }

 private:
  std::unique_ptr<RTCStatsReportPlatform> report_;
};

}  // namespace

RTCStatsReport::RTCStatsReport(std::unique_ptr<RTCStatsReportPlatform> report)
    : report_(std::move(report)) {}

uint32_t RTCStatsReport::size() const {
  return base::saturated_cast<uint32_t>(report_->Size());
}

PairSyncIterable<RTCStatsReport>::IterationSource*
RTCStatsReport::CreateIterationSource(ScriptState*, ExceptionState&) {
  return MakeGarbageCollected<RTCStatsReportIterationSource>(
      report_->CopyHandle());
}

bool RTCStatsReport::GetMapEntryIdl(ScriptState* script_state,
                                    const String& key,
                                    ScriptValue& value,
                                    ExceptionState&) {
  const webrtc::RTCStats* stats = report_->stats_report().Get(key.Utf8());
  if (!stats) {
    return false;
  }

  RTCStats* v8_stats = RTCStatsToIDL(
      script_state, *stats, ExposeHardwareCapabilityStats(script_state));
  if (!v8_stats) {
    return false;
  }
  value = ScriptValue::From(script_state, v8_stats);
  return true;
}

bool RTCStatsReport::GetMapEntry(ScriptState* script_state,
                                 const String& key,
                                 ScriptValue& value,
                                 ExceptionState& exception_state) {
  return GetMapEntryIdl(script_state, key, value, exception_state);
}

}  // namespace blink

"""


```