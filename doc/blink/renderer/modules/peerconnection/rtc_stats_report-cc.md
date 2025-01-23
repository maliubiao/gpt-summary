Response:
Let's break down the thought process for analyzing this C++ code snippet.

**1. Initial Scan and Keyword Spotting:**

The first step is to quickly scan the code, looking for recognizable keywords and structures. Things that immediately jump out are:

* `#include`:  Indicates dependencies on other files. The filenames give clues about the purpose (e.g., `rtc_stats_report.h`, various `v8_rtc_*_stats.h`, `webrtc/api/stats/...`).
* `namespace blink`:  Confirms this is within the Blink rendering engine.
* Class names starting with `RTC...Stats`:  These strongly suggest this code deals with collecting and reporting statistics related to WebRTC.
* Function names like `ToV8Stat`:  This hints at converting data structures to a format understandable by the V8 JavaScript engine.
* `ScriptState*`: This confirms interaction with the JavaScript environment.
* `v8::Local<v8::Value>`, `V8ObjectBuilder`: These are clearly related to building JavaScript objects.
* Comments like "// https://w3c.github.io/webrtc-stats/..." : These are crucial for understanding the specification context and the intent of the code.

**2. Identifying Core Functionality:**

Based on the keywords, the core functionality becomes apparent: This code is responsible for taking WebRTC statistics data (likely from the underlying WebRTC engine) and transforming it into JavaScript objects that can be accessed by web developers. The various `ToV8Stat` functions are the primary mechanism for this transformation.

**3. Analyzing `ToV8Stat` Functions:**

Focusing on the `ToV8Stat` functions reveals the specific types of statistics being handled: `RTCCodecStats`, `RTCInboundRtpStreamStats`, `RTCOutboundRtpStreamStats`, etc. Each function takes a `webrtc::...Stats` object and populates a corresponding `blink::...Stats` object. The `blink::...Stats` objects likely have a structure that directly maps to the properties exposed in the JavaScript `RTCStatsReport` API.

**4. Tracing the Connection to JavaScript/Web:**

The presence of `ScriptState*`, `v8::Local<v8::Value>`, and the use of `V8ObjectBuilder` directly link this code to the JavaScript environment. The `ToV8Stat` functions are the bridges. The code is effectively serializing WebRTC statistics into JavaScript-accessible objects.

**5. Considering User Interaction and Debugging:**

How does a user trigger this code? The key is the `getStats()` method on `RTCPeerConnection`. When a web developer calls this method in their JavaScript, it initiates a process that eventually leads to the generation of these statistics. Therefore, a debugging scenario would involve setting breakpoints within these `ToV8Stat` functions to inspect the raw WebRTC stats and the resulting JavaScript objects.

**6. Identifying Potential Issues/Edge Cases:**

The code handles optional values (`has_value()`). This immediately brings up the question of what happens if a value *doesn't* have a value. The code appears to handle this gracefully by simply not setting the corresponding property on the V8 object. This suggests a possible user-side misunderstanding – expecting a property to always be present.

The `ExposeHardwareCapabilityStats` function and its dependency on capturing state are also important. This highlights that the availability of certain statistics can depend on the user's permissions and the browser's security model.

**7. Structuring the Output:**

Finally, the information needs to be organized logically. The request asks for functionality, relation to web technologies, logical reasoning, user errors, and debugging. A good structure would be:

* **Core Functionality:**  Start with the high-level purpose.
* **Relationship to JavaScript/HTML/CSS:** Explain how the C++ code manifests in the web environment, specifically focusing on the `getStats()` API and the structure of the returned objects.
* **Logical Reasoning:**  Use a specific example of a `ToV8Stat` function to illustrate the input-to-output transformation. Clearly state the assumptions.
* **User Errors:** Provide practical examples of common mistakes related to interpreting the statistics.
* **Debugging:** Outline the steps a developer might take to reach this code during debugging.
* **Summary:**  Concisely reiterate the main function of the code.

**Self-Correction/Refinement During the Process:**

* Initially, one might focus too much on the individual statistics types. It's important to zoom out and see the overarching purpose of *converting* these stats to JavaScript.
* The connection to HTML and CSS is less direct. It's important to clarify that this C++ code is *behind the scenes* and not directly manipulated by HTML or CSS. The interaction is via JavaScript APIs.
* When providing the logical reasoning example, be specific about the input and output data types to make it clear.
* For user errors, focus on common misunderstandings *about the data itself*, not just general programming errors.

By following this structured approach, combining keyword spotting, functional analysis, tracing connections, and considering practical use cases, it becomes possible to effectively analyze and explain the purpose and significance of this C++ code within the larger context of the Chromium browser and WebRTC.
好的，这是对提供的C++源代码文件 `blink/renderer/modules/peerconnection/rtc_stats_report.cc` 的功能归纳（第1部分）。

**文件功能归纳 (第1部分)**

该C++文件的核心功能是**将底层的 WebRTC 引擎产生的统计数据 (以 `webrtc::RTCStatsReport` 的形式存在) 转换成 Blink 渲染引擎中可用的 `RTCStatsReport` 对象，并进一步转换成 JavaScript 可以访问的 `RTCStatsReport` 对象**。

更具体地说，该文件定义了一系列 `ToV8Stat` 函数，每个函数负责将特定类型的 WebRTC 统计信息结构（例如 `webrtc::RTCCodecStats`, `webrtc::RTCInboundRtpStreamStats` 等）转换为相应的 Blink 内部的统计信息对象（例如 `RTCCodecStats`, `RTCInboundRtpStreamStats` 等），这些 Blink 内部的对象是为 JavaScript 暴露 API 而设计的。

**与 JavaScript, HTML, CSS 的关系及举例说明**

该文件直接与 **JavaScript** 功能密切相关，因为它负责将 C++ 数据桥接到 JavaScript 环境。它与 HTML 和 CSS 的关系较为间接，因为它是 WebRTC API 实现的一部分，而 WebRTC API 可以被 JavaScript 代码调用，从而影响网页的行为和展示。

* **与 JavaScript 的关系：**
    * **功能举例：** 当 JavaScript 代码调用 `RTCPeerConnection.getStats()` 方法时，底层的 C++ 代码（包括这个文件）会被触发，从 WebRTC 引擎获取实时的连接状态和性能统计数据。这个文件中的 `ToV8Stat` 函数会将这些底层的 C++ 统计数据转换为 JavaScript 可以理解的对象。
    * **代码示例：**
      ```javascript
      const pc = new RTCPeerConnection();
      pc.getStats().then(report => {
        report.forEach(stats => {
          console.log(stats.type, stats.id, stats);
          // 这里的 stats 对象就是由该文件中的代码转换而来的
        });
      });
      ```
    * **数据转换：** 例如，`ToV8Stat(ScriptState* script_state, const webrtc::RTCInboundRtpStreamStats& webrtc_stat, bool expose_hardware_caps)` 函数会将 `webrtc::RTCInboundRtpStreamStats` 中的 `packets_lost` 转换为 `RTCInboundRtpStreamStats` 对象的 `packetsLost` 属性，最终在 JavaScript 中可以通过 `stats.packetsLost` 访问。

* **与 HTML 的关系：**
    * **功能举例：**  HTML 提供了创建交互式 Web 内容的结构，而 WebRTC 功能允许在网页上进行音视频通信和数据传输。该文件提供的统计数据可以用于监控和调试 WebRTC 连接的质量，从而帮助开发者优化用户体验。例如，如果统计数据显示丢包率很高，开发者可能会调整编码参数或网络设置。
    * **使用场景：** 一个在线视频会议应用可以使用 `getStats()` 获取网络质量数据，并在 HTML 页面上显示连接状态图标或者向用户提示网络问题。

* **与 CSS 的关系：**
    * **功能举例：** CSS 负责网页的样式和布局。虽然该文件本身不直接操作 CSS，但通过 JavaScript 获取的 WebRTC 统计数据可以用来动态地改变网页的样式。
    * **使用场景：** 例如，如果 `getStats()` 返回的音频电平 (audio level) 很低，JavaScript 代码可以动态地添加或修改 CSS 类，从而在用户界面上显示麦克风静音的指示。

**逻辑推理 (假设输入与输出)**

假设 WebRTC 引擎报告了一个入站 RTP 流的统计信息，其中：

* `webrtc_stat.ssrc` 的值为 12345
* `webrtc_stat.packets_lost` 的值为 10
* `webrtc_stat.jitter` 的值为 0.015

**假设输入:** 一个 `webrtc::RTCInboundRtpStreamStats` 对象 `webrtc_stat`，其部分成员变量的值如上所述。

**处理过程:** `ToV8Stat(ScriptState* script_state, const webrtc::RTCInboundRtpStreamStats& webrtc_stat, bool expose_hardware_caps)` 函数被调用，并将 `webrtc_stat` 作为参数传入。函数内部会将 `webrtc_stat` 的各个成员变量的值赋值给新创建的 `RTCInboundRtpStreamStats` 对象。

**预期输出:** 一个 `RTCInboundRtpStreamStats` 对象 `v8_stat`，其部分属性的值如下：

* `v8_stat->ssrc()` 的值为 12345
* `v8_stat->packetsLost()` 的值为 10
* `v8_stat->jitter()` 的值为 0.015

**用户或编程常见的使用错误 (举例说明)**

* **错误理解统计数据的含义：** 开发者可能不理解某些统计指标的含义，例如，将 "jitter" 理解为丢包率，或者对 "roundTripTime" 的单位理解错误。这会导致基于错误理解的统计数据做出错误的判断和优化。
* **频繁调用 `getStats()` 导致性能问题：**  `getStats()` 操作会触发底层的统计信息收集，如果过于频繁地调用此方法，可能会对性能产生负面影响，尤其是在资源受限的设备上。开发者应该根据实际需要合理地设置调用频率。
* **假设所有统计属性都存在：**  某些统计属性是可选的，或者只在特定的条件下才会被报告。如果开发者在代码中直接访问某个可能不存在的属性，而没有进行检查，可能会导致错误。例如，某些旧版本的浏览器可能不提供某些新的统计指标。

**用户操作是如何一步步到达这里的 (作为调试线索)**

1. **用户在浏览器中打开一个使用了 WebRTC 功能的网页。** 例如，一个在线视频会议网站。
2. **网页上的 JavaScript 代码创建了一个 `RTCPeerConnection` 对象，用于建立音视频连接。**
3. **在连接建立或者通信过程中，JavaScript 代码调用了 `pc.getStats()` 方法。**
4. **浏览器接收到 `getStats()` 的调用，并将请求传递给 Blink 渲染引擎。**
5. **Blink 渲染引擎中的 PeerConnection 模块接收到请求，并触发底层的 WebRTC 引擎收集统计信息。**
6. **WebRTC 引擎生成 `webrtc::RTCStatsReport` 对象，其中包含了各种统计信息。**
7. **Blink 渲染引擎的 PeerConnection 模块调用该文件中的代码，特别是 `RTCStatsReport::create` 或类似的方法，并遍历 `webrtc::RTCStatsReport` 中的各个统计信息对象。**
8. **对于每种类型的统计信息对象，会调用相应的 `ToV8Stat` 函数将其转换为 Blink 内部的 `RTCStats` 对象。**
9. **这些 Blink 内部的 `RTCStats` 对象最终会被转换为 V8 JavaScript 对象，并作为 `Promise` 的 resolve 值返回给 JavaScript 代码。**
10. **开发者可以在浏览器的开发者工具中查看 `console.log(stats)` 的输出，从而看到由该文件代码转换后的统计数据。**

**总结 (第1部分)**

总而言之，`blink/renderer/modules/peerconnection/rtc_stats_report.cc` 文件的主要职责是将 WebRTC 引擎产生的原生统计数据转换为 Blink 渲染引擎可以处理并最终暴露给 JavaScript 的格式，使得 Web 开发者能够通过 `RTCPeerConnection.getStats()` API 监控和分析 WebRTC 连接的状态和性能。它在 WebRTC 功能的实现中扮演着至关重要的桥梁角色，连接了底层的 C++ 实现和上层的 JavaScript API。

### 提示词
```
这是目录为blink/renderer/modules/peerconnection/rtc_stats_report.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/peerconnection/rtc_stats_report.h"

#include "base/feature_list.h"
#include "base/notreached.h"
#include "base/numerics/safe_conversions.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_object_builder.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_audio_playout_stats.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_audio_source_stats.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_certificate_stats.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_codec_stats.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_data_channel_stats.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_ice_candidate_pair_stats.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_ice_candidate_stats.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_inbound_rtp_stream_stats.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_media_source_stats.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_outbound_rtp_stream_stats.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_peer_connection_stats.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_received_rtp_stream_stats.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_remote_inbound_rtp_stream_stats.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_remote_outbound_rtp_stream_stats.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_sent_rtp_stream_stats.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_transport_stats.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_video_source_stats.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/modules/mediastream/user_media_client.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_stats.h"
#include "third_party/blink/renderer/platform/peerconnection/webrtc_util.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/webrtc/api/stats/rtc_stats.h"
#include "third_party/webrtc/api/stats/rtc_stats_report.h"
#include "third_party/webrtc/api/stats/rtcstats_objects.h"
#include "v8/include/v8-local-handle.h"
#include "v8/include/v8-object.h"

namespace blink {

namespace {

template <typename T>
v8::Local<v8::Value> HashMapToValue(ScriptState* script_state,
                                    HashMap<String, T>&& map) {
  V8ObjectBuilder builder(script_state);
  for (auto& it : map) {
    builder.Add(it.key, it.value);
  }
  v8::Local<v8::Object> v8_object = builder.V8Value();
  if (v8_object.IsEmpty()) {
    NOTREACHED();
  }
  return v8_object;
}

bool IsCapturing(LocalDOMWindow* window) {
  UserMediaClient* user_media_client = UserMediaClient::From(window);
  return user_media_client && user_media_client->IsCapturing();
}

bool ExposeHardwareCapabilityStats(ScriptState* script_state) {
  // According the the spec description at
  // https://w3c.github.io/webrtc-stats/#dfn-exposing-hardware-is-allowed,
  // hardware capabilities may be exposed if the context capturing state is
  // true.
  ExecutionContext* ctx = ExecutionContext::From(script_state);
  LocalDOMWindow* window = DynamicTo<LocalDOMWindow>(ctx);
  return window && IsCapturing(window);
}

RTCCodecStats* ToV8Stat(ScriptState* script_state,
                        const webrtc::RTCCodecStats& webrtc_stat) {
  RTCCodecStats* v8_codec =
      MakeGarbageCollected<RTCCodecStats>(script_state->GetIsolate());
  if (webrtc_stat.transport_id.has_value()) {
    v8_codec->setTransportId(String::FromUTF8(*webrtc_stat.transport_id));
  }
  if (webrtc_stat.payload_type.has_value()) {
    v8_codec->setPayloadType(*webrtc_stat.payload_type);
  }
  if (webrtc_stat.channels.has_value()) {
    v8_codec->setChannels(*webrtc_stat.channels);
  }
  if (webrtc_stat.mime_type.has_value()) {
    v8_codec->setMimeType(String::FromUTF8(*webrtc_stat.mime_type));
  }
  if (webrtc_stat.clock_rate.has_value()) {
    v8_codec->setClockRate(*webrtc_stat.clock_rate);
  }
  if (webrtc_stat.sdp_fmtp_line.has_value()) {
    v8_codec->setSdpFmtpLine(String::FromUTF8(*webrtc_stat.sdp_fmtp_line));
  }
  return v8_codec;
}

RTCInboundRtpStreamStats* ToV8Stat(
    ScriptState* script_state,
    const webrtc::RTCInboundRtpStreamStats& webrtc_stat,
    bool expose_hardware_caps) {
  RTCInboundRtpStreamStats* v8_stat =
      MakeGarbageCollected<RTCInboundRtpStreamStats>(
          script_state->GetIsolate());
  // RTCRtpStreamStats
  if (webrtc_stat.ssrc.has_value()) {
    v8_stat->setSsrc(*webrtc_stat.ssrc);
  }
  if (webrtc_stat.kind.has_value()) {
    v8_stat->setKind(String::FromUTF8(*webrtc_stat.kind));
    // mediaType is a legacy alias for kind.
    v8_stat->setMediaType(String::FromUTF8(*webrtc_stat.kind));
  }
  if (webrtc_stat.transport_id.has_value()) {
    v8_stat->setTransportId(String::FromUTF8(*webrtc_stat.transport_id));
  }
  if (webrtc_stat.codec_id.has_value()) {
    v8_stat->setCodecId(String::FromUTF8(*webrtc_stat.codec_id));
  }
  // RTCReceivedRtpStreamStats
  if (webrtc_stat.packets_lost.has_value()) {
    v8_stat->setPacketsLost(*webrtc_stat.packets_lost);
  }
  if (webrtc_stat.jitter.has_value()) {
    v8_stat->setJitter(*webrtc_stat.jitter);
  }
  // RTCInboundRtpStreamStats
  if (webrtc_stat.track_identifier.has_value()) {
    v8_stat->setTrackIdentifier(
        String::FromUTF8(*webrtc_stat.track_identifier));
  }
  if (webrtc_stat.mid.has_value()) {
    v8_stat->setMid(String::FromUTF8(*webrtc_stat.mid));
  }
  if (webrtc_stat.remote_id.has_value()) {
    v8_stat->setRemoteId(String::FromUTF8(*webrtc_stat.remote_id));
  }
  if (webrtc_stat.frames_decoded.has_value()) {
    v8_stat->setFramesDecoded(*webrtc_stat.frames_decoded);
  }
  if (webrtc_stat.key_frames_decoded.has_value()) {
    v8_stat->setKeyFramesDecoded(*webrtc_stat.key_frames_decoded);
  }
  if (webrtc_stat.frames_dropped.has_value()) {
    v8_stat->setFramesDropped(*webrtc_stat.frames_dropped);
  }
  if (webrtc_stat.frame_width.has_value()) {
    v8_stat->setFrameWidth(*webrtc_stat.frame_width);
  }
  if (webrtc_stat.frame_height.has_value()) {
    v8_stat->setFrameHeight(*webrtc_stat.frame_height);
  }
  if (webrtc_stat.frames_per_second.has_value()) {
    v8_stat->setFramesPerSecond(*webrtc_stat.frames_per_second);
  }
  if (webrtc_stat.qp_sum.has_value()) {
    v8_stat->setQpSum(*webrtc_stat.qp_sum);
  }
  if (webrtc_stat.total_corruption_probability.has_value()) {
    v8_stat->setTotalCorruptionProbability(
        *webrtc_stat.total_corruption_probability);
  }
  if (webrtc_stat.total_squared_corruption_probability.has_value()) {
    v8_stat->setTotalSquaredCorruptionProbability(
        *webrtc_stat.total_squared_corruption_probability);
  }
  if (webrtc_stat.corruption_measurements.has_value()) {
    v8_stat->setCorruptionMeasurements(*webrtc_stat.corruption_measurements);
  }
  if (webrtc_stat.total_decode_time.has_value()) {
    v8_stat->setTotalDecodeTime(*webrtc_stat.total_decode_time);
  }
  if (webrtc_stat.total_inter_frame_delay.has_value()) {
    v8_stat->setTotalInterFrameDelay(*webrtc_stat.total_inter_frame_delay);
  }
  if (webrtc_stat.total_squared_inter_frame_delay.has_value()) {
    v8_stat->setTotalSquaredInterFrameDelay(
        *webrtc_stat.total_squared_inter_frame_delay);
  }
  if (webrtc_stat.pause_count.has_value()) {
    v8_stat->setPauseCount(*webrtc_stat.pause_count);
  }
  if (webrtc_stat.total_pauses_duration.has_value()) {
    v8_stat->setTotalPausesDuration(*webrtc_stat.total_pauses_duration);
  }
  if (webrtc_stat.freeze_count.has_value()) {
    v8_stat->setFreezeCount(*webrtc_stat.freeze_count);
  }
  if (webrtc_stat.total_freezes_duration.has_value()) {
    v8_stat->setTotalFreezesDuration(*webrtc_stat.total_freezes_duration);
  }
  if (webrtc_stat.last_packet_received_timestamp.has_value()) {
    v8_stat->setLastPacketReceivedTimestamp(
        *webrtc_stat.last_packet_received_timestamp);
  }
  if (webrtc_stat.header_bytes_received.has_value()) {
    v8_stat->setHeaderBytesReceived(*webrtc_stat.header_bytes_received);
  }
  if (webrtc_stat.packets_discarded.has_value()) {
    v8_stat->setPacketsDiscarded(*webrtc_stat.packets_discarded);
  }
  if (webrtc_stat.packets_received.has_value()) {
    v8_stat->setPacketsReceived(*webrtc_stat.packets_received);
  }
  if (webrtc_stat.fec_packets_received.has_value()) {
    v8_stat->setFecPacketsReceived(*webrtc_stat.fec_packets_received);
  }
  if (webrtc_stat.fec_packets_discarded.has_value()) {
    v8_stat->setFecPacketsDiscarded(*webrtc_stat.fec_packets_discarded);
  }
  if (webrtc_stat.fec_bytes_received.has_value()) {
    v8_stat->setFecBytesReceived(*webrtc_stat.fec_bytes_received);
  }
  if (webrtc_stat.fec_ssrc.has_value()) {
    v8_stat->setFecSsrc(*webrtc_stat.fec_ssrc);
  }
  if (webrtc_stat.bytes_received.has_value()) {
    v8_stat->setBytesReceived(*webrtc_stat.bytes_received);
  }
  if (webrtc_stat.nack_count.has_value()) {
    v8_stat->setNackCount(*webrtc_stat.nack_count);
  }
  if (webrtc_stat.fir_count.has_value()) {
    v8_stat->setFirCount(*webrtc_stat.fir_count);
  }
  if (webrtc_stat.pli_count.has_value()) {
    v8_stat->setPliCount(*webrtc_stat.pli_count);
  }
  if (webrtc_stat.total_processing_delay.has_value()) {
    v8_stat->setTotalProcessingDelay(*webrtc_stat.total_processing_delay);
  }
  if (webrtc_stat.estimated_playout_timestamp.has_value()) {
    v8_stat->setEstimatedPlayoutTimestamp(
        *webrtc_stat.estimated_playout_timestamp);
  }
  if (webrtc_stat.jitter_buffer_delay.has_value()) {
    v8_stat->setJitterBufferDelay(*webrtc_stat.jitter_buffer_delay);
  }
  if (webrtc_stat.jitter_buffer_target_delay.has_value()) {
    v8_stat->setJitterBufferTargetDelay(
        *webrtc_stat.jitter_buffer_target_delay);
  }
  if (webrtc_stat.jitter_buffer_emitted_count.has_value()) {
    v8_stat->setJitterBufferEmittedCount(
        *webrtc_stat.jitter_buffer_emitted_count);
  }
  if (webrtc_stat.jitter_buffer_minimum_delay.has_value()) {
    v8_stat->setJitterBufferMinimumDelay(
        *webrtc_stat.jitter_buffer_minimum_delay);
  }
  if (webrtc_stat.total_samples_received.has_value()) {
    v8_stat->setTotalSamplesReceived(*webrtc_stat.total_samples_received);
  }
  if (webrtc_stat.concealed_samples.has_value()) {
    v8_stat->setConcealedSamples(*webrtc_stat.concealed_samples);
  }
  if (webrtc_stat.silent_concealed_samples.has_value()) {
    v8_stat->setSilentConcealedSamples(*webrtc_stat.silent_concealed_samples);
  }
  if (webrtc_stat.concealment_events.has_value()) {
    v8_stat->setConcealmentEvents(*webrtc_stat.concealment_events);
  }
  if (webrtc_stat.inserted_samples_for_deceleration.has_value()) {
    v8_stat->setInsertedSamplesForDeceleration(
        *webrtc_stat.inserted_samples_for_deceleration);
  }
  if (webrtc_stat.removed_samples_for_acceleration.has_value()) {
    v8_stat->setRemovedSamplesForAcceleration(
        *webrtc_stat.removed_samples_for_acceleration);
  }
  if (webrtc_stat.audio_level.has_value()) {
    v8_stat->setAudioLevel(*webrtc_stat.audio_level);
  }
  if (webrtc_stat.total_audio_energy.has_value()) {
    v8_stat->setTotalAudioEnergy(*webrtc_stat.total_audio_energy);
  }
  if (webrtc_stat.total_samples_duration.has_value()) {
    v8_stat->setTotalSamplesDuration(*webrtc_stat.total_samples_duration);
  }
  if (webrtc_stat.frames_received.has_value()) {
    v8_stat->setFramesReceived(*webrtc_stat.frames_received);
  }
  if (webrtc_stat.playout_id.has_value()) {
    v8_stat->setPlayoutId(String::FromUTF8(*webrtc_stat.playout_id));
  }
  if (webrtc_stat.frames_assembled_from_multiple_packets.has_value()) {
    v8_stat->setFramesAssembledFromMultiplePackets(
        *webrtc_stat.frames_assembled_from_multiple_packets);
  }
  if (webrtc_stat.total_assembly_time.has_value()) {
    v8_stat->setTotalAssemblyTime(*webrtc_stat.total_assembly_time);
  }
  if (expose_hardware_caps) {
    if (webrtc_stat.power_efficient_decoder.has_value()) {
      v8_stat->setPowerEfficientDecoder(*webrtc_stat.power_efficient_decoder);
    }
    if (webrtc_stat.decoder_implementation.has_value()) {
      v8_stat->setDecoderImplementation(
          String::FromUTF8(*webrtc_stat.decoder_implementation));
    }
  }
  // https://w3c.github.io/webrtc-provisional-stats/#dom-rtcinboundrtpstreamstats-contenttype
  if (webrtc_stat.content_type.has_value()) {
    v8_stat->setContentType(String::FromUTF8(*webrtc_stat.content_type));
  }
  // https://github.com/w3c/webrtc-provisional-stats/issues/40
  if (webrtc_stat.goog_timing_frame_info.has_value()) {
    v8_stat->setGoogTimingFrameInfo(
        String::FromUTF8(*webrtc_stat.goog_timing_frame_info));
  }
  if (webrtc_stat.retransmitted_packets_received.has_value()) {
    v8_stat->setRetransmittedPacketsReceived(
        *webrtc_stat.retransmitted_packets_received);
  }
  if (webrtc_stat.retransmitted_bytes_received.has_value()) {
    v8_stat->setRetransmittedBytesReceived(
        *webrtc_stat.retransmitted_bytes_received);
  }
  if (webrtc_stat.rtx_ssrc.has_value()) {
    v8_stat->setRtxSsrc(*webrtc_stat.rtx_ssrc);
  }
  return v8_stat;
}

RTCRemoteInboundRtpStreamStats* ToV8Stat(
    ScriptState* script_state,
    const webrtc::RTCRemoteInboundRtpStreamStats& webrtc_stat) {
  RTCRemoteInboundRtpStreamStats* v8_stat =
      MakeGarbageCollected<RTCRemoteInboundRtpStreamStats>(
          script_state->GetIsolate());
  // RTCRtpStreamStats
  if (webrtc_stat.ssrc.has_value()) {
    v8_stat->setSsrc(*webrtc_stat.ssrc);
  }
  if (webrtc_stat.kind.has_value()) {
    v8_stat->setKind(String::FromUTF8(*webrtc_stat.kind));
    // mediaType is a legacy alias for kind.
    v8_stat->setMediaType(String::FromUTF8(*webrtc_stat.kind));
  }
  if (webrtc_stat.transport_id.has_value()) {
    v8_stat->setTransportId(String::FromUTF8(*webrtc_stat.transport_id));
  }
  if (webrtc_stat.codec_id.has_value()) {
    v8_stat->setCodecId(String::FromUTF8(*webrtc_stat.codec_id));
  }
  // RTCReceivedRtpStreamStats
  if (webrtc_stat.packets_lost.has_value()) {
    v8_stat->setPacketsLost(*webrtc_stat.packets_lost);
  }
  if (webrtc_stat.jitter.has_value()) {
    v8_stat->setJitter(*webrtc_stat.jitter);
  }
  // RTCRemoteInboundRtpStreamStats
  if (webrtc_stat.local_id.has_value()) {
    v8_stat->setLocalId(String::FromUTF8(*webrtc_stat.local_id));
  }
  if (webrtc_stat.round_trip_time.has_value()) {
    v8_stat->setRoundTripTime(*webrtc_stat.round_trip_time);
  }
  if (webrtc_stat.total_round_trip_time.has_value()) {
    v8_stat->setTotalRoundTripTime(*webrtc_stat.total_round_trip_time);
  }
  if (webrtc_stat.fraction_lost.has_value()) {
    v8_stat->setFractionLost(*webrtc_stat.fraction_lost);
  }
  if (webrtc_stat.round_trip_time_measurements.has_value()) {
    v8_stat->setRoundTripTimeMeasurements(
        *webrtc_stat.round_trip_time_measurements);
  }
  return v8_stat;
}

RTCOutboundRtpStreamStats* ToV8Stat(
    ScriptState* script_state,
    const webrtc::RTCOutboundRtpStreamStats& webrtc_stat,
    bool expose_hardware_caps) {
  RTCOutboundRtpStreamStats* v8_stat =
      MakeGarbageCollected<RTCOutboundRtpStreamStats>(
          script_state->GetIsolate());
  // RTCRtpStreamStats
  if (webrtc_stat.ssrc.has_value()) {
    v8_stat->setSsrc(*webrtc_stat.ssrc);
  }
  if (webrtc_stat.kind.has_value()) {
    v8_stat->setKind(String::FromUTF8(*webrtc_stat.kind));
    // mediaType is a legacy alias for kind.
    v8_stat->setMediaType(String::FromUTF8(*webrtc_stat.kind));
  }
  if (webrtc_stat.transport_id.has_value()) {
    v8_stat->setTransportId(String::FromUTF8(*webrtc_stat.transport_id));
  }
  if (webrtc_stat.codec_id.has_value()) {
    v8_stat->setCodecId(String::FromUTF8(*webrtc_stat.codec_id));
  }
  // RTCSentRtpStreamStats
  if (webrtc_stat.packets_sent.has_value()) {
    v8_stat->setPacketsSent(*webrtc_stat.packets_sent);
  }
  if (webrtc_stat.bytes_sent.has_value()) {
    v8_stat->setBytesSent(*webrtc_stat.bytes_sent);
  }
  // RTCOutboundRtpStreamStats
  if (webrtc_stat.mid.has_value()) {
    v8_stat->setMid(String::FromUTF8(*webrtc_stat.mid));
  }
  if (webrtc_stat.media_source_id.has_value()) {
    v8_stat->setMediaSourceId(String::FromUTF8(*webrtc_stat.media_source_id));
  }
  if (webrtc_stat.remote_id.has_value()) {
    v8_stat->setRemoteId(String::FromUTF8(*webrtc_stat.remote_id));
  }
  if (webrtc_stat.rid.has_value()) {
    v8_stat->setRid(String::FromUTF8(*webrtc_stat.rid));
  }
  if (webrtc_stat.header_bytes_sent.has_value()) {
    v8_stat->setHeaderBytesSent(*webrtc_stat.header_bytes_sent);
  }
  if (webrtc_stat.retransmitted_packets_sent.has_value()) {
    v8_stat->setRetransmittedPacketsSent(
        *webrtc_stat.retransmitted_packets_sent);
  }
  if (webrtc_stat.retransmitted_bytes_sent.has_value()) {
    v8_stat->setRetransmittedBytesSent(*webrtc_stat.retransmitted_bytes_sent);
  }
  if (webrtc_stat.rtx_ssrc.has_value()) {
    v8_stat->setRtxSsrc(*webrtc_stat.rtx_ssrc);
  }
  if (webrtc_stat.target_bitrate.has_value()) {
    v8_stat->setTargetBitrate(*webrtc_stat.target_bitrate);
  }
  if (webrtc_stat.total_encoded_bytes_target.has_value()) {
    v8_stat->setTotalEncodedBytesTarget(
        *webrtc_stat.total_encoded_bytes_target);
  }
  if (webrtc_stat.frame_width.has_value()) {
    v8_stat->setFrameWidth(*webrtc_stat.frame_width);
  }
  if (webrtc_stat.frame_height.has_value()) {
    v8_stat->setFrameHeight(*webrtc_stat.frame_height);
  }
  if (webrtc_stat.frames_per_second.has_value()) {
    v8_stat->setFramesPerSecond(*webrtc_stat.frames_per_second);
  }
  if (webrtc_stat.frames_sent.has_value()) {
    v8_stat->setFramesSent(*webrtc_stat.frames_sent);
  }
  if (webrtc_stat.huge_frames_sent.has_value()) {
    v8_stat->setHugeFramesSent(*webrtc_stat.huge_frames_sent);
  }
  if (webrtc_stat.frames_encoded.has_value()) {
    v8_stat->setFramesEncoded(*webrtc_stat.frames_encoded);
  }
  if (webrtc_stat.key_frames_encoded.has_value()) {
    v8_stat->setKeyFramesEncoded(*webrtc_stat.key_frames_encoded);
  }
  if (webrtc_stat.qp_sum.has_value()) {
    v8_stat->setQpSum(*webrtc_stat.qp_sum);
  }
  if (webrtc_stat.total_encode_time.has_value()) {
    v8_stat->setTotalEncodeTime(*webrtc_stat.total_encode_time);
  }
  if (webrtc_stat.total_packet_send_delay.has_value()) {
    v8_stat->setTotalPacketSendDelay(*webrtc_stat.total_packet_send_delay);
  }
  if (webrtc_stat.quality_limitation_reason.has_value()) {
    v8_stat->setQualityLimitationReason(
        String::FromUTF8(*webrtc_stat.quality_limitation_reason));
  }
  if (webrtc_stat.quality_limitation_durations.has_value()) {
    Vector<std::pair<String, double>> quality_durations;
    for (const auto& [key, value] : *webrtc_stat.quality_limitation_durations) {
      quality_durations.emplace_back(String::FromUTF8(key), value);
    }
    v8_stat->setQualityLimitationDurations(std::move(quality_durations));
  }
  if (webrtc_stat.quality_limitation_resolution_changes.has_value()) {
    v8_stat->setQualityLimitationResolutionChanges(
        *webrtc_stat.quality_limitation_resolution_changes);
  }
  if (webrtc_stat.nack_count.has_value()) {
    v8_stat->setNackCount(*webrtc_stat.nack_count);
  }
  if (webrtc_stat.fir_count.has_value()) {
    v8_stat->setFirCount(*webrtc_stat.fir_count);
  }
  if (webrtc_stat.pli_count.has_value()) {
    v8_stat->setPliCount(*webrtc_stat.pli_count);
  }
  if (webrtc_stat.active.has_value()) {
    v8_stat->setActive(*webrtc_stat.active);
  }
  if (webrtc_stat.scalability_mode.has_value()) {
    v8_stat->setScalabilityMode(
        String::FromUTF8(*webrtc_stat.scalability_mode));
  }
  if (expose_hardware_caps) {
    if (webrtc_stat.encoder_implementation.has_value()) {
      v8_stat->setEncoderImplementation(
          String::FromUTF8(*webrtc_stat.encoder_implementation));
    }
    if (webrtc_stat.power_efficient_encoder.has_value()) {
      v8_stat->setPowerEfficientEncoder(*webrtc_stat.power_efficient_encoder);
    }
  }
  // https://w3c.github.io/webrtc-provisional-stats/#dom-rtcoutboundrtpstreamstats-contenttype
  if (webrtc_stat.content_type.has_value()) {
    v8_stat->setContentType(String::FromUTF8(*webrtc_stat.content_type));
  }
  return v8_stat;
}

RTCRemoteOutboundRtpStreamStats* ToV8Stat(
    ScriptState* script_state,
    const webrtc::RTCRemoteOutboundRtpStreamStats& webrtc_stat) {
  RTCRemoteOutboundRtpStreamStats* v8_stat =
      MakeGarbageCollected<RTCRemoteOutboundRtpStreamStats>(
          script_state->GetIsolate());
  // RTCRtpStreamStats
  if (webrtc_stat.ssrc.has_value()) {
    v8_stat->setSsrc(*webrtc_stat.ssrc);
  }
  if (webrtc_stat.kind.has_value()) {
    v8_stat->setKind(String::FromUTF8(*webrtc_stat.kind));
    // mediaType is a legacy alias for kind.
    v8_stat->setMediaType(String::FromUTF8(*webrtc_stat.kind));
  }
  if (webrtc_stat.transport_id.has_value()) {
    v8_stat->setTransportId(String::FromUTF8(*webrtc_stat.transport_id));
  }
  if (webrtc_stat.codec_id.has_value()) {
    v8_stat->setCodecId(String::FromUTF8(*webrtc_stat.codec_id));
  }
  // RTCSendRtpStreamStats
  if (webrtc_stat.packets_sent.has_value()) {
    v8_stat->setPacketsSent(*webrtc_stat.packets_sent);
  }
  if (webrtc_stat.bytes_sent.has_value()) {
    v8_stat->setBytesSent(*webrtc_stat.bytes_sent);
  }
  // RTCRemoteOutboundRtpStreamStats
  if (webrtc_stat.local_id.has_value()) {
    v8_stat->setLocalId(String::FromUTF8(*webrtc_stat.local_id));
  }
  if (webrtc_stat.remote_timestamp.has_value()) {
    v8_stat->setRemoteTimestamp(*webrtc_stat.remote_timestamp);
  }
  if (webrtc_stat.reports_sent.has_value()) {
    v8_stat->setReportsSent(*webrtc_stat.reports_sent);
  }
  if (webrtc_stat.round_trip_time.has_value()) {
    v8_stat->setRoundTripTime(*webrtc_stat.round_trip_time);
  }
  if (webrtc_stat.total_round_trip_time.has_value()) {
    v8_stat->setTotalRoundTripTime(*webrtc_stat.total_round_trip_time);
  }
  if (webrtc_stat.round_trip_time_measurements.has_value()) {
    v8_stat->setRoundTripTimeMeasurements(
        *webrtc_stat.round_trip_time_measurements);
  }
  return v8_stat;
}

RTCAudioSourceStats* ToV8Stat(ScriptState* script_state,
                              const webrtc::RTCAudioSourceStats& webrtc_stat) {
  RTCAudioSourceStats* v8_stat =
      MakeGarbageCollected<RTCAudioSourceStats>(script_state->GetIsolate());
  // RTCMediaSourceStats
  if (webrtc_stat.track_identifier.has_value()) {
    v8_stat->setTrackIdentifier(
        String::FromUTF8(*webrtc_stat.track_identifier));
  }
  if (webrtc_stat.kind.has_value()) {
    v8_stat->setKind(String::FromUTF8(*webrtc_stat.kind));
  }
  // RTCAudioSourceStats
  if (webrtc_stat.audio_level.has_value()) {
    v8_stat->setAudioLevel(*webrtc_stat.audio_level);
  }
  if (webrtc_stat.total_audio_energy.has_value()) {
    v8_stat->setTotalAudioEnergy(*webrtc_stat.total_audio_energy);
  }
  if (webrtc_stat.total_samples_duration.has_value()) {
    v8_stat->setTotalSamplesDuration(*webrtc_stat.total_samples_duration);
  }
  if (webrtc_stat.echo_return_loss.has_value()) {
    v8_stat->setEchoReturnLoss(*webrtc_stat.echo_return_loss);
  }
  if (webrtc_stat.echo_return_loss_enhancement.has_value()) {
    v8_stat->setEchoReturnLossEnhancement(
        *webrtc_stat.echo_return_loss_enhancement);
  }
  return v8_stat;
}

// https://w3c.github.io/webrtc-stats/#videosourcestats-dict*
RTCVideoSourceStats* ToV8Stat(ScriptState* script_state,
                              const webrtc::RTCVideoSourceStats& webrtc_stat) {
  RTCVideoSourceStats* v8_stat =
      MakeGarbageCollected<RTCVideoSourceStats>(script_state->GetIsolate());
  // RTCMediaSourceStats
  if (webrtc_stat.track_identifier.has_value()) {
    v8_stat->setTrackIdentifier(
        String::FromUTF8(*webrtc_stat.track_identifier));
  }
  if (webrtc_stat.kind.has_value()) {
    v8_stat->setKind(String::FromUTF8(*webrtc_stat.kind));
  }
  // RTCVideoSourceStats
  if (webrtc_stat.width.has_value()) {
    v8_stat->setWidth(*webrtc_stat.width);
  }
  if (webrtc_stat.height.has_value()) {
    v8_stat->setHeight(*webrtc_stat.height);
  }
  if (webrtc_stat.frames.has_value()) {
    v8_stat->setFrames(*webrtc_stat.frames);
  }
  if (webrtc_stat.frames_per_second.has_value()) {
    v8_stat->setFramesPerSecond(*webrtc_stat.frames_per_second);
  }
  return v8_stat;
}

// https://w3c.github.io/webrtc-stats/#playoutstats-dict*
RTCAudioPlayoutStats* ToV8Stat(
    ScriptState* script_state,
    const webrtc::RTCAudioPlayoutStats& webrtc_stat) {
  RTCAudioPlayoutStats* v8_stat =
      MakeGarbageCollected<RTCAudioPlayoutStats>(script_state->GetIsolate());

  if (webrtc_stat.kind.has_value()) {
    v8_stat->setKind(String::FromUTF8(*webrtc_stat.kind));
  }
  if (webrtc_stat.synthesized_samples_duration.has_value()) {
    v8_stat->setSynthesizedSamplesDuration(
        *webrtc_stat.synthesized_samples_duration);
  }
  if (webrtc_stat.synthesized_samples_events.has_value()) {
    v8_stat->setSynthesizedSamplesEvents(base::saturated_cast<uint32_t>(
        *webrtc_stat.synthesized_samples_events));
  }
  if (webrtc_stat.total_samples_duration.has_value()) {
    v8_stat->setTotalSamplesDuration(*webrtc_stat.total_samples_duration);
  }
  if (webrtc_stat.total_playout_delay.has_value()) {
    v8_stat->setTotalPlayoutDelay(*webrtc_stat.total_playout_delay);
  }
  if (webrtc_stat.total_samples_count.has_value()) {
    v8_stat->setTotalSamplesCount(*webrtc_stat.total_samples_count);
  }
  return v8_stat;
}

// https://w3c.github.io/webrtc-stats/#pcstats-dict*
RTCPeerConnectionStats* ToV8Stat(
    ScriptState* script_state,
    const webrtc::RTCPeerConnectionStats& webrtc_stat) {
  RTCPeerConnectionStats* v8_stat =
      MakeGarbageCollected<RTCPeerConnectionStats>(script_state->GetIsolate());

  if (webrtc_stat.data_channels_opened.has_value()) {
    v8_stat->setDataChannelsOpened(*webrtc_stat.data_channels_opened);
  }
  if (webrtc_stat.data_channels_closed.has_value()) {
    v8_stat->setDataChannelsClosed(*webrtc_stat.data_channels_closed);
  }
  return v8_stat;
}

// https://w3c.github.io/webrtc-stats/#dcstats-dict*
RTCDataChannelStats* ToV8Stat(ScriptState* script_state,
                              const webrtc::RTCDataChannelStats& webrtc_stat) {
  RTCDataChannelStats* v8_stat =
      MakeGarbageCollected<RTCDataChannelStats>(script_state->GetIsolate());

  if (webrtc_stat.label.has_value()) {
    v8_stat->setLabel(String::FromUTF8(*webrtc_stat.label));
  }
  if (webrtc_stat.protocol.has_value()) {
    v8_stat->setProtocol(String::FromUTF8(*webrtc_stat.protocol));
  }
  if (webrtc_stat.data_channel_identifier.has_value()) {
    v8_stat->setDataChannelIdentifier(*webrtc_stat.data_channel_identifier);
  }
  if (webrtc_stat.state.has_value()) {
    v8_stat->setState(String::FromUTF8(*webrtc_stat.state));
  }
  if (webrtc_stat.messages_sent.has_value()) {
    v8_stat->setMessagesSent(*webrtc_stat.messages_sent);
  }
  if (webrtc_stat.bytes_sent.has_value()) {
    v8_stat->setBytesSent(*webrtc_stat.bytes_sent);
  }
  if (webrtc_stat.messages_received.has_value()) {
    v8_stat->setMessagesReceived(*webrtc_stat.messages_received);
  }
  if (webrtc_stat.bytes_received.has_value()) {
    v8_stat->setBytesReceived(*webrtc_stat.bytes_received);
  }
  return v8_stat;
}

// https://w3c.github.io/webrtc-stats/#transportstats-dict*
RTCTransportStats* ToV8Stat(ScriptState* script_state,
                            const webrtc::RTCTransportStats& webrtc_stat) {
  RTCTransportStats* v8_stat =
      MakeGarbageCollected<RTCTransportStats>(script_state->GetIsolate());

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
  if (webrtc_stat.ice_role.has_value()) {
    v8_stat->setIceRole(String::FromUTF8(*webrtc_stat.ice_role));
  }
  if (webrtc_stat.ice_local_username_fragment.has_value()) {
    v8_stat->setIceLocalUsernameFragment(
        String::FromUTF8(*webrtc_stat.ice_local_username_fragment));
  }
  if (webrtc_stat.dtls_state.has_value()) {
    v8_stat->setDtlsState(String::FromUTF8(*webrtc_stat.dtls_state));
  }
  if (webrtc_stat.ice_state.has_value()) {
    v8_stat->setIceState(String::FromUTF8(*webrtc_stat.ice_state));
  }
  if (webrtc_stat.selected_candidate_pair_id.has_value()) {
    v8_stat->setSelectedCandidatePairId(
        String::FromUTF8(*webrtc_stat.selected_candidate_pair_id));
  }
  if (webrtc_stat.local_certificate_id.has_value()) {
    v8_stat->setLocalCertificateId(
        String::FromUTF8(*webrtc_stat.local_certificate_id));
  }
  if (webrtc_stat.remote_certificate_id.has_value()) {
    v8_stat->setRemoteCertificateId(
        String::FromUTF8(*webrtc_stat.remote_certificate_id));
  }
  if (webrtc_stat.tls_version.has_value()) {
    v8_stat->setTlsVersion(String::FromUTF8(*webrtc_stat.tls_version));
  }
  if (webrtc_stat.dtls_cipher.has_value()) {
    v8_stat->setDtlsCipher(String::FromUTF8(*webrtc_stat.dtls_cipher));
  }
  if (webrtc_stat.dtls_role.has_value()) {
    v8_stat->setDtlsRole(String::FromUTF8(*webrtc_stat.dtls_role));
  }
  if (webrtc_stat.srtp_cipher.has_value()) {
    v8_stat->setSrtpCipher(String::FromUTF8(*webrtc_stat.srtp_cipher));
  }
  if (webrtc_stat.selected_candidate_pair_changes.has_value()) {
    v8_stat->setSelectedCandidatePairChanges(
        *webrtc_stat.selected_candidate_pair_changes);
  }
  // https://w3c.github.io/webrtc-provisional-stats/#dom-rtctransportstats-rtcptransportstatsid
  if (webrtc_stat.rtcp_transport_stats_id.has_value()) {
    v8_stat->setRtcpTransportStatsId(
        String::FromUTF8(*webrtc_stat.rtcp_transport_stats_id));
  }
  return v8_stat;
}

// https://w3c.github.io/webrtc-stats/#icecandidate-dict*
RTCIceCandidateStats* ToV8Stat(
    ScriptState* script_state,
    const webrtc::RTCIceCandidateStats& webrtc_stat) {
  RTCIceCandidateStats* v8_stat =
      MakeGarbageCollected<RTCIceCandidateStats>(script_state->GetIsolate());
  if (webrtc_stat.transport_id.has_value()) {
    v8_stat->setTransportId(String::FromUTF8(*webrtc_stat.transport_id));
  }
  if (webrtc_stat.address.has_value()) {
    v8_stat->setAddress(String::FromUTF8(*webrtc_stat.address));
  }
  if (webrtc_stat.port.has_value()) {
    v8_stat->setPort(*webrtc_stat.port);
  }
  if (webrtc_stat.protocol.has_value()) {
    v8_stat->setProtocol(String::FromUTF8(*webrtc_stat.protocol));
  }
  if (webrtc_stat.candidate_type.has_value()) {
    v8_stat->setCandidateType(String::FromUTF8(*webrtc_stat.candidate_type));
  }
  if (webrtc_stat.priority.has_value()) {
    v8_stat->setPriority(*webrtc_stat.priority);
  }
  if (webrtc_stat.url.has_value()) {
    v8_stat->setUrl(String::FromUTF8(*webrtc_stat.url));
  }
  if (webrtc_stat.relay_protocol.has_value()) {
    v8_stat->setRelayProtocol(String::FromUTF8(*webrtc_stat.relay_protocol));
  }
  if (webrtc_stat.foundation.has_value()) {
    v8_stat->setFoundation(String::FromUTF8(*webrtc_stat.foundation));
  }
  if (webrtc_stat.related_address.has_value()) {
    v8_stat->setRelatedAddress(String::FromUTF8(*webrtc_stat.related_address));
  }
  if (webrtc_stat.related_port.has_value()) {
    v8_stat->setRelatedPort(*webrtc_stat.related_port);
  }
  if (webrtc_stat.username_fragment.has_value()) {
    v8_stat->setUsernameFragment(
        String::FromUTF8(*webrtc_stat.username_fragment));
  }
  if (webrtc_stat.tcp_type.has_value()) {
    v8_stat->setTcpType(String::FromUTF8(*webrtc_stat.tcp_type));
  }
  // https://w3c.github.io/webrtc-provisional-stats/#dom-rtcicecandidatestats-networktype
  // Note: additional work needed to reach consensus on the privacy model.
  if (webrtc_stat.network_type.has_value()) {
    v8_stat->setNetworkType(String::FromUTF8(*webrtc_stat.network_type));
  }
  // Non-standard and obsolete stats.
  if (webrtc_stat.is_remote.has_value()) {
    v8_stat->setIsRemote(*webrtc_stat.is_remote);
  }
  if (webrtc_stat.ip.has_value()) {
    v8_stat->setIp(String::FromUTF8(*webrtc_stat.ip));
```