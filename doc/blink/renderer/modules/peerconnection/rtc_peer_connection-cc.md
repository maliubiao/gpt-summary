Response:
The user wants me to analyze a C++ source code file from the Chromium Blink engine, specifically `rtc_peer_connection.cc`. They are asking for:

1. **Functionality:** What does this code do?
2. **Relationship to web technologies:** How does it interact with JavaScript, HTML, and CSS?
3. **Logic and I/O:**  Provide examples of input and output if the code performs logical operations.
4. **Common errors:**  What mistakes do users or programmers make when using this code?
5. **User journey:** How does a user's actions lead to this code being executed (debugging context)?
6. **Summary:** Provide a high-level overview of the file's purpose.

This is part 1 of a 4-part analysis, so I need to focus on the initial aspects of the code.

**Plan:**

1. **Scan the code for keywords and class names:** Identify core functionalities related to WebRTC.
2. **Analyze included headers:** Understand the dependencies and what functionalities are being utilized.
3. **Examine the `RTCPeerConnection` class:** Focus on its methods and data members as they reveal the primary purpose of the file.
4. **Relate the code to WebRTC APIs:** Connect the C++ code to the corresponding JavaScript APIs.
5. **Formulate examples for user interaction, errors, and logic based on the observed functionalities.**
6. **Summarize the identified functionalities for this first part.**
这是 `blink/renderer/modules/peerconnection/rtc_peer_connection.cc` 文件的第一部分，它主要负责 **RTCPeerConnection** 接口的实现。`RTCPeerConnection` 是 WebRTC API 的核心组件，用于在浏览器之间建立点对点连接，进行音频、视频和任意数据的传输。

**功能归纳:**

1. **RTCPeerConnection 对象的创建和初始化:**  这部分代码包含了 `RTCPeerConnection` 类的构造函数 `RTCPeerConnection::RTCPeerConnection` 和静态工厂方法 `RTCPeerConnection::Create`。它负责创建 `RTCPeerConnection` 的实例，并根据传入的 `RTCConfiguration` 对象进行初始化，例如设置 ICE 服务器、证书等。

2. **处理 RTCPeerConnection 的配置:**  代码中包含了 `ParseConfiguration` 函数，它将 JavaScript 传递的 `RTCConfiguration` 对象转换为 WebRTC 引擎内部使用的配置结构 `webrtc::PeerConnectionInterface::RTCConfiguration`。这个过程包括验证和解析各种配置选项，例如 ICE 服务器的 URL、ICE 传输策略、bundle 策略、RTCP 多路复用策略等等。

3. **管理 RTCPeerConnection 的状态:** 代码中定义和使用了多个表示 `RTCPeerConnection` 状态的成员变量，例如 `signaling_state_`（信令状态）、`ice_gathering_state_`（ICE 收集状态）、`ice_connection_state_`（ICE 连接状态）和 `peer_connection_state_`（连接状态）。  同时包含了一些辅助函数，如 `ThrowExceptionIfSignalingStateClosed` 和 `CallErrorCallbackIfSignalingStateClosed`，用于在信令状态为 'closed' 时抛出异常或调用错误回调。

4. **处理 SDP（Session Description Protocol）：**  虽然这部分代码尚未涉及到 `createOffer` 的完整实现，但它已经包含了一些与 SDP 相关的辅助函数，例如 `SdpMismatch`、`IceUfragPwdMismatch`、`FingerprintMismatch`、`ContainsLegacySimulcast`、`ContainsLegacyRtpDataChannel`、`ContainsCandidate` 和 `ContainsOpusStereo`。这些函数用于比较和检查 SDP 的内容，以确保在会话协商过程中 SDP 的有效性和一致性。

5. **管理 RTCPeerConnectionHandler:** 代码中创建和管理了一个 `RTCPeerConnectionHandler` 的实例 `peer_handler_`。 `RTCPeerConnectionHandler` 是一个内部类，负责与底层的 WebRTC 引擎交互，执行实际的连接建立、媒体协商和数据传输操作。

6. **防止过度创建 RTCPeerConnection:** 代码中使用了 `InstanceCounters` 来限制同时存在的 `RTCPeerConnection` 对象的数量，防止资源耗尽。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** `RTCPeerConnection` 是一个 JavaScript API，开发者通过 JavaScript 代码来创建和操作 `RTCPeerConnection` 对象。这个 C++ 文件中的代码是该 API 在 Blink 渲染引擎中的具体实现。例如，JavaScript 代码 `new RTCPeerConnection(configuration)` 会最终调用到 `RTCPeerConnection::Create` 这个 C++ 方法。

* **HTML:**  HTML 用于构建网页结构，而 WebRTC 通常用于增强网页的实时通信能力。HTML 中可能包含触发 WebRTC 连接建立的按钮或其他交互元素。当用户与这些元素交互时，会执行相应的 JavaScript 代码来创建和操作 `RTCPeerConnection`。

* **CSS:** CSS 用于控制网页的样式，与 `RTCPeerConnection` 的核心功能没有直接关系。但是，CSS 可以用来美化用户界面，例如控制视频流的显示样式。

**举例说明:**

**JavaScript 交互:**

```javascript
// JavaScript 代码
const configuration = {
  iceServers: [{ urls: 'stun:stun.example.org' }]
};
const pc = new RTCPeerConnection(configuration);
```

当这段 JavaScript 代码执行时，Blink 引擎会调用 `rtc_peer_connection.cc` 中的 `RTCPeerConnection::Create` 方法，并将 `configuration` 对象作为参数传递给 `ParseConfiguration` 函数进行解析。

**假设输入与输出 (针对 `ParseConfiguration`):**

**假设输入 (JavaScript 的 `configuration` 对象转换而来):**

```cpp
RTCConfiguration configuration;
RTCIceServer ice_server;
ice_server.setUrls(V8UnionStringOrStringSequence::From("stun:stun.example.org"));
HeapVector<Member<RTCIceServer>> ice_servers;
ice_servers.push_back(MakeGarbageCollected<RTCIceServer>(ice_server));
configuration.setIceServers(ice_servers);
```

**输出 (解析后的 WebRTC 内部配置):**

```cpp
webrtc::PeerConnectionInterface::RTCConfiguration web_configuration;
webrtc::PeerConnectionInterface::IceServer parsed_ice_server;
parsed_ice_server.urls.push_back("stun:stun.example.org");
web_configuration.servers.push_back(parsed_ice_server);
```

**用户或编程常见的使用错误:**

1. **未配置 ICE 服务器:** 用户忘记在 `RTCConfiguration` 中指定 ICE 服务器，导致无法进行 NAT 穿透，连接建立失败。

   ```javascript
   // 错误示例：缺少 iceServers 配置
   const pc = new RTCPeerConnection();
   ```
   Blink 引擎在尝试进行 ICE 协商时会失败。

2. **使用了过期的证书:** 如果在 `RTCConfiguration` 中指定的证书已经过期，`RTCPeerConnection::Create` 会抛出 `InvalidAccessError` 异常。

   ```javascript
   const configuration = {
     certificates: [expiredCertificate] // expiredCertificate 是一个过期的 RTCCertificate 对象
   };
   // 创建 RTCPeerConnection 会抛出异常
   const pc = new RTCPeerConnection(configuration);
   ```

**用户操作如何一步步到达这里 (调试线索):**

1. 用户在浏览器中打开一个包含 WebRTC 功能的网页。
2. 网页的 JavaScript 代码执行，创建了一个 `RTCPeerConnection` 对象，例如 `new RTCPeerConnection(config)`。
3. 浏览器内核接收到创建 `RTCPeerConnection` 的请求。
4. Blink 渲染引擎调用 `blink/renderer/modules/peerconnection/rtc_peer_connection.cc` 文件中的 `RTCPeerConnection::Create` 静态方法。
5. `RTCPeerConnection::Create` 方法会解析 JavaScript 传递的配置信息 (通过 `ParseConfiguration`)，并创建 `RTCPeerConnection` 的 C++ 对象。
6. 如果配置有错误（例如过期的证书），则会在 `RTCPeerConnection::Create` 中抛出异常，并在 JavaScript 中捕获。

这是 `rtc_peer_connection.cc` 文件的第一部分的功能归纳。接下来的部分很可能会涉及更多关于信令交换、媒体协商、数据通道管理等方面的功能实现。

### 提示词
```
这是目录为blink/renderer/modules/peerconnection/rtc_peer_connection.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of Google Inc. nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/peerconnection/rtc_peer_connection.h"

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "base/feature_list.h"
#include "base/lazy_instance.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/numerics/safe_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool.h"
#include "build/build_config.h"
#include "build/buildflag.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_crypto_algorithm_params.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/renderer/bindings/core/v8/dictionary.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_object_string.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_string_stringsequence.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_void_function.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_stream_track.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_answer_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_certificate.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_configuration.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_data_channel_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_data_channel_state.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_ice_candidate_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_ice_connection_state.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_ice_gathering_state.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_ice_server.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_offer_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_peer_connection_error_callback.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_peer_connection_state.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_rtp_transceiver_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_session_description_callback.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_session_description_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_signaling_state.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_mediastreamtrack_string.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/dom_time_stamp.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/modules/crypto/crypto_result_impl.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints_impl.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_event.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track_impl.h"
#include "third_party/blink/renderer/modules/peerconnection/peer_connection_dependency_factory.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_certificate.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_certificate_generator.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_data_channel.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_data_channel_event.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_dtls_transport.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_dtmf_sender.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_error_util.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_ice_transport.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_peer_connection_handler.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_peer_connection_ice_error_event.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_peer_connection_ice_event.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_rtp_receiver.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_rtp_sender.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_rtp_transceiver.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_sctp_transport.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_session_description.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_session_description_request_impl.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_session_description_request_promise_impl.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_stats_report.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_track_event.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_void_request_impl.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_void_request_promise_impl.h"
#include "third_party/blink/renderer/modules/peerconnection/web_rtc_stats_report_callback_resolver.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/instance_counters.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_answer_options_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_ice_candidate_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_offer_options_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_session_description_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_stats.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_void_request.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/scheduler/public/scheduling_policy.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/webrtc/api/data_channel_interface.h"
#include "third_party/webrtc/api/dtls_transport_interface.h"
#include "third_party/webrtc/api/jsep.h"
#include "third_party/webrtc/api/peer_connection_interface.h"
#include "third_party/webrtc/api/priority.h"
#include "third_party/webrtc/rtc_base/ssl_identity.h"

namespace blink {

namespace {

const char kSignalingStateClosedMessage[] =
    "The RTCPeerConnection's signalingState is 'closed'.";
const char kModifiedSdpMessage[] =
    "The SDP does not match the previously generated SDP for this type";

base::LazyInstance<RTCPeerConnection::RtcPeerConnectionHandlerFactoryCallback>::
    Leaky g_create_rpc_peer_connection_handler_callback_ =
        LAZY_INSTANCE_INITIALIZER;

// The maximum number of PeerConnections that can exist simultaneously.
const int64_t kMaxPeerConnections = 500;

bool ThrowExceptionIfSignalingStateClosed(
    webrtc::PeerConnectionInterface::SignalingState state,
    ExceptionState* exception_state) {
  if (state == webrtc::PeerConnectionInterface::SignalingState::kClosed) {
    exception_state->ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                       kSignalingStateClosedMessage);
    return true;
  }

  return false;
}

void AsyncCallErrorCallback(ExecutionContext* context,
                            V8RTCPeerConnectionErrorCallback* error_callback,
                            DOMException* exception) {
  DCHECK(error_callback);
  context->GetAgent()->event_loop()->EnqueueMicrotask(WTF::BindOnce(
      &V8RTCPeerConnectionErrorCallback::InvokeAndReportException,
      WrapPersistent(error_callback), nullptr, WrapPersistent(exception)));
}

bool CallErrorCallbackIfSignalingStateClosed(
    ExecutionContext* context,
    webrtc::PeerConnectionInterface::SignalingState state,
    V8RTCPeerConnectionErrorCallback* error_callback) {
  if (state == webrtc::PeerConnectionInterface::SignalingState::kClosed) {
    if (error_callback) {
      AsyncCallErrorCallback(context, error_callback,
                             MakeGarbageCollected<DOMException>(
                                 DOMExceptionCode::kInvalidStateError,
                                 kSignalingStateClosedMessage));
    }
    return true;
  }

  return false;
}

bool IsIceCandidateMissingSdpMidAndMLineIndex(
    const RTCIceCandidateInit* candidate) {
  return (candidate->sdpMid().IsNull() &&
          !candidate->hasSdpMLineIndexNonNull());
}

RTCOfferOptionsPlatform* ConvertToRTCOfferOptionsPlatform(
    const RTCOfferOptions* options) {
  if (!options)
    return nullptr;
  return MakeGarbageCollected<RTCOfferOptionsPlatform>(
      options->hasOfferToReceiveVideo()
          ? std::max(options->offerToReceiveVideo(), 0)
          : -1,
      options->hasOfferToReceiveAudio()
          ? std::max(options->offerToReceiveAudio(), 0)
          : -1,
      options->hasVoiceActivityDetection() ? options->voiceActivityDetection()
                                           : true,
      options->hasIceRestart() ? options->iceRestart() : false);
}

RTCAnswerOptionsPlatform* ConvertToRTCAnswerOptionsPlatform(
    const RTCAnswerOptions* options) {
  if (!options)
    return nullptr;
  return MakeGarbageCollected<RTCAnswerOptionsPlatform>(
      options->hasVoiceActivityDetection() ? options->voiceActivityDetection()
                                           : true);
}

RTCIceCandidatePlatform* ConvertToRTCIceCandidatePlatform(
    ExecutionContext* context,
    const RTCIceCandidateInit* candidate) {
  // TODO(guidou): Change default value to -1. crbug.com/614958.
  uint16_t sdp_m_line_index = 0;
  if (candidate->hasSdpMLineIndexNonNull()) {
    sdp_m_line_index = candidate->sdpMLineIndexNonNull();
  } else {
    UseCounter::Count(context,
                      WebFeature::kRTCIceCandidateDefaultSdpMLineIndex);
  }
  return MakeGarbageCollected<RTCIceCandidatePlatform>(
      candidate->candidate(), candidate->sdpMid(), sdp_m_line_index,
      candidate->usernameFragment(),
      /*url can not be reconstruncted*/ std::nullopt);
}

webrtc::PeerConnectionInterface::IceTransportsType IceTransportPolicyFromEnum(
    V8RTCIceTransportPolicy::Enum policy) {
  switch (policy) {
    case V8RTCIceTransportPolicy::Enum::kRelay:
      return webrtc::PeerConnectionInterface::kRelay;
    case V8RTCIceTransportPolicy::Enum::kAll:
      return webrtc::PeerConnectionInterface::kAll;
  }
  NOTREACHED();
}

bool IsValidStunURL(const KURL& url) {
  if (!url.ProtocolIs("stun") && !url.ProtocolIs("stuns")) {
    return false;
  }
  if (!url.Query().empty()) {
    return false;
  }
  return true;
}

bool IsValidTurnURL(const KURL& url) {
  if (!url.ProtocolIs("turn") && !url.ProtocolIs("turns")) {
    return false;
  }
  if (!url.Query().empty()) {
    Vector<String> query_parts;
    url.Query().ToString().Split("=", query_parts);
    if (query_parts.size() < 2 || query_parts[0] != "transport") {
      return false;
    }
  }
  return true;
}

webrtc::PeerConnectionInterface::RTCConfiguration ParseConfiguration(
    ExecutionContext* context,
    const RTCConfiguration* configuration,
    ExceptionState* exception_state) {
  DCHECK(context);

  webrtc::PeerConnectionInterface::RTCConfiguration web_configuration;

  if (configuration->hasIceTransportPolicy()) {
    UseCounter::Count(context, WebFeature::kRTCConfigurationIceTransportPolicy);
    web_configuration.type = IceTransportPolicyFromEnum(
        configuration->iceTransportPolicy().AsEnum());
  } else if (configuration->hasIceTransports()) {
    UseCounter::Count(context, WebFeature::kRTCConfigurationIceTransports);
    web_configuration.type =
        IceTransportPolicyFromEnum(configuration->iceTransports().AsEnum());
  }

  if (configuration->bundlePolicy() == "max-compat") {
    web_configuration.bundle_policy =
        webrtc::PeerConnectionInterface::kBundlePolicyMaxCompat;
  } else if (configuration->bundlePolicy() == "max-bundle") {
    web_configuration.bundle_policy =
        webrtc::PeerConnectionInterface::kBundlePolicyMaxBundle;
  } else {
    DCHECK_EQ(configuration->bundlePolicy(), "balanced");
  }

  if (configuration->rtcpMuxPolicy() == "negotiate") {
    web_configuration.rtcp_mux_policy =
        webrtc::PeerConnectionInterface::kRtcpMuxPolicyNegotiate;
    Deprecation::CountDeprecation(context, WebFeature::kRtcpMuxPolicyNegotiate);
  } else {
    DCHECK_EQ(configuration->rtcpMuxPolicy(), "require");
  }

  if (configuration->hasIceServers()) {
    WebVector<webrtc::PeerConnectionInterface::IceServer> ice_servers;
    for (const RTCIceServer* ice_server : configuration->iceServers()) {
      Vector<String> url_strings;
      std::vector<std::string> converted_urls;
      if (ice_server->hasUrls()) {
        UseCounter::Count(context, WebFeature::kRTCIceServerURLs);
        switch (ice_server->urls()->GetContentType()) {
          case V8UnionStringOrStringSequence::ContentType::kString:
            url_strings.push_back(ice_server->urls()->GetAsString());
            break;
          case V8UnionStringOrStringSequence::ContentType::kStringSequence:
            url_strings = ice_server->urls()->GetAsStringSequence();
            break;
        }
      } else if (ice_server->hasUrl()) {
        UseCounter::Count(context, WebFeature::kRTCIceServerURL);
        url_strings.push_back(ice_server->url());
      } else {
        exception_state->ThrowTypeError("Malformed RTCIceServer");
        return {};
      }

      for (const String& url_string : url_strings) {
        KURL url(NullURL(), url_string);
        if (!url.IsValid()) {
          exception_state->ThrowDOMException(
              DOMExceptionCode::kSyntaxError,
              "'" + url_string + "' is not a valid URL.");
          return {};
        }
        bool is_valid_turn = IsValidTurnURL(url);
        if (!is_valid_turn && !IsValidStunURL(url)) {
          exception_state->ThrowDOMException(
              DOMExceptionCode::kSyntaxError,
              "'" + url_string + "' is not a valid stun or turn URL.");
          return {};
        }
        if (is_valid_turn &&
            (!ice_server->hasUsername() || !ice_server->hasCredential())) {
          exception_state->ThrowDOMException(
              DOMExceptionCode::kInvalidAccessError,
              "Both username and credential are "
              "required when the URL scheme is "
              "\"turn\" or \"turns\".");
        }

        converted_urls.push_back(String(url).Utf8());
      }

      auto converted_ice_server = webrtc::PeerConnectionInterface::IceServer();
      converted_ice_server.urls = std::move(converted_urls);
      if (ice_server->hasUsername()) {
        converted_ice_server.username = ice_server->username().Utf8();
      }
      if (ice_server->hasCredential()) {
        converted_ice_server.password = ice_server->credential().Utf8();
      }
      ice_servers.emplace_back(std::move(converted_ice_server));
    }
    web_configuration.servers = ice_servers.ReleaseVector();
  }

  if (configuration->hasCertificates()) {
    const HeapVector<Member<RTCCertificate>>& certificates =
        configuration->certificates();
    WebVector<rtc::scoped_refptr<rtc::RTCCertificate>> certificates_copy(
        certificates.size());
    for (wtf_size_t i = 0; i < certificates.size(); ++i) {
      certificates_copy[i] = certificates[i]->Certificate();
    }
    web_configuration.certificates = certificates_copy.ReleaseVector();
  }

  web_configuration.ice_candidate_pool_size =
      configuration->iceCandidatePoolSize();

  if (configuration->hasRtcAudioJitterBufferMaxPackets()) {
    UseCounter::Count(context, WebFeature::kRTCMaxAudioBufferSize);
    web_configuration.audio_jitter_buffer_max_packets =
        static_cast<int>(configuration->rtcAudioJitterBufferMaxPackets());
  }

  if (configuration->hasRtcAudioJitterBufferFastAccelerate()) {
    UseCounter::Count(context, WebFeature::kRTCMaxAudioBufferSize);
    web_configuration.audio_jitter_buffer_fast_accelerate =
        configuration->hasRtcAudioJitterBufferFastAccelerate();
  }

  if (configuration->hasRtcAudioJitterBufferMinDelayMs()) {
    UseCounter::Count(context, WebFeature::kRTCMaxAudioBufferSize);
    web_configuration.audio_jitter_buffer_min_delay_ms =
        static_cast<int>(configuration->rtcAudioJitterBufferMinDelayMs());
  }

  return web_configuration;
}

bool SdpMismatch(String old_sdp, String new_sdp, String attribute) {
  // Look for an attribute that is present in both old and new SDP
  // and is modified which is not allowed.
  String attribute_with_prefix = "\na=" + attribute + ":";
  const wtf_size_t new_attribute_pos = new_sdp.Find(attribute_with_prefix);
  if (new_attribute_pos == kNotFound) {
    return true;
  }
  const wtf_size_t old_attribute_pos = old_sdp.Find(attribute_with_prefix);
  if (old_attribute_pos == kNotFound) {
    return true;
  }
  wtf_size_t old_attribute_end = old_sdp.Find("\r\n", old_attribute_pos + 1);
  if (old_attribute_end == kNotFound) {
    old_attribute_end = old_sdp.Find("\n", old_attribute_pos + 1);
  }
  wtf_size_t new_attribute_end = new_sdp.Find("\r\n", new_attribute_pos + 1);
  if (new_attribute_end == kNotFound) {
    new_attribute_end = new_sdp.Find("\n", new_attribute_pos + 1);
  }
  return old_sdp.Substring(old_attribute_pos,
                           old_attribute_end - old_attribute_pos) !=
         new_sdp.Substring(new_attribute_pos,
                           new_attribute_end - new_attribute_pos);
}

bool IceUfragPwdMismatch(String old_sdp, String new_sdp) {
  return SdpMismatch(old_sdp, new_sdp, "ice-ufrag") ||
         SdpMismatch(old_sdp, new_sdp, "ice-pwd");
}

bool FingerprintMismatch(String old_sdp, String new_sdp) {
  // Check special case of externally generated SDP without fingerprints.
  // It's impossible to generate a valid fingerprint without createOffer
  // or createAnswer, so this only applies when there are no fingerprints.
  // This is allowed.
  const wtf_size_t new_fingerprint_pos = new_sdp.Find("\na=fingerprint:");
  if (new_fingerprint_pos == kNotFound) {
    return false;
  }
  // Look for fingerprint having been added. Not allowed.
  const wtf_size_t old_fingerprint_pos = old_sdp.Find("\na=fingerprint:");
  if (old_fingerprint_pos == kNotFound) {
    return true;
  }
  // Look for fingerprint being modified. Not allowed.  Handle differences in
  // line endings ('\r\n' vs, '\n' when looking for the end of the fingerprint).
  wtf_size_t old_fingerprint_end =
      old_sdp.Find("\r\n", old_fingerprint_pos + 1);
  if (old_fingerprint_end == kNotFound) {
    old_fingerprint_end = old_sdp.Find("\n", old_fingerprint_pos + 1);
  }
  wtf_size_t new_fingerprint_end =
      new_sdp.Find("\r\n", new_fingerprint_pos + 1);
  if (new_fingerprint_end == kNotFound) {
    new_fingerprint_end = new_sdp.Find("\n", new_fingerprint_pos + 1);
  }
  return old_sdp.Substring(old_fingerprint_pos,
                           old_fingerprint_end - old_fingerprint_pos) !=
         new_sdp.Substring(new_fingerprint_pos,
                           new_fingerprint_end - new_fingerprint_pos);
}

bool ContainsLegacySimulcast(String sdp) {
  // Looks for the non-spec simulcast that іs enabled via SDP munging.
  return sdp.Find("\na=ssrc-group:SIM") != kNotFound;
}

bool ContainsLegacyRtpDataChannel(String sdp) {
  // Looks for the non-spec legacy RTP data channel.
  return sdp.Find("google-data/90000") != kNotFound;
}

bool ContainsCandidate(String sdp) {
  return sdp.Find("\na=candidate") != kNotFound;
}

bool ContainsOpusStereo(String sdp) {
  return sdp.Find("stereo=1") != kNotFound;
}

// Keep in sync with tools/metrics/histograms/metadata/web_rtc/enums.xml
// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class GenerateCertificateAlgorithms {
  kEcDsaP256 = 0,
  kRsa1024,
  kRsa2048,
  kRsa4096,
  kRsa8192,
  kRsaOther,
  kMaxValue = kRsaOther,
};

void MeasureGenerateCertificateKeyType(
    const std::optional<rtc::KeyParams>& key_params) {
  if (!key_params.has_value()) {
    return;
  }
  GenerateCertificateAlgorithms bucket =
      GenerateCertificateAlgorithms::kEcDsaP256;
  if (key_params->type() == rtc::KT_RSA) {
    switch (key_params->rsa_params().mod_size) {
      case 1024:
        bucket = GenerateCertificateAlgorithms::kRsa1024;
        break;
      case 2048:
        bucket = GenerateCertificateAlgorithms::kRsa2048;
        break;
      case 4096:
        bucket = GenerateCertificateAlgorithms::kRsa4096;
        break;
      case 8192:
        bucket = GenerateCertificateAlgorithms::kRsa8192;
        break;
      default:
        bucket = GenerateCertificateAlgorithms::kRsaOther;
        break;
    }
  }
  UMA_HISTOGRAM_ENUMERATION(
      "WebRTC.PeerConnection.GenerateCertificate.Algorithms", bucket,
      GenerateCertificateAlgorithms::kMaxValue);
}

}  // namespace

RTCPeerConnection::EventWrapper::EventWrapper(Event* event,
                                              BoolFunction function)
    : event_(event), setup_function_(std::move(function)) {}

bool RTCPeerConnection::EventWrapper::Setup() {
  if (setup_function_) {
    return std::move(setup_function_).Run();
  }
  return true;
}

void RTCPeerConnection::EventWrapper::Trace(Visitor* visitor) const {
  visitor->Trace(event_);
}

RTCPeerConnection* RTCPeerConnection::Create(
    ExecutionContext* context,
    const RTCConfiguration* rtc_configuration,
    ExceptionState& exception_state) {
  if (context->IsContextDestroyed()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "PeerConnections may not be created in detached documents.");
    return nullptr;
  }

  // Count number of PeerConnections that could potentially be impacted by CSP
  auto* content_security_policy = context->GetContentSecurityPolicy();
  if (content_security_policy &&
      content_security_policy->IsActiveForConnections()) {
    UseCounter::Count(context, WebFeature::kRTCPeerConnectionWithActiveCsp);
    // Count number of PeerConnections that would be blocked by CSP connect-src
    // or one of the directive it inherits from.
    // This is intended for evaluating whether introducing a "webrtc-src"
    // on-off switch that inherits from connect-csp would be harmful or not.
    // TODO(crbug.com/1225968): Remove code when decision is made.
    if (!content_security_policy->AllowConnectToSource(
            KURL("https://example.org"), KURL("https://example.org"),
            RedirectStatus::kNoRedirect,
            ReportingDisposition::kSuppressReporting)) {
      UseCounter::Count(context, WebFeature::kRTCPeerConnectionWithBlockingCsp);
    }
  }
  // TODO(https://crbug.com/1318448): figure out if this counter should be
  // retired - the other alternative is removed.
  UseCounter::Count(context,
                    WebFeature::kRTCPeerConnectionConstructorCompliant);

  webrtc::PeerConnectionInterface::RTCConfiguration configuration =
      ParseConfiguration(context, rtc_configuration, &exception_state);
  if (exception_state.HadException())
    return nullptr;

  // Make sure no certificates have expired.
  if (!configuration.certificates.empty()) {
    DOMTimeStamp now = ConvertSecondsToDOMTimeStamp(
        base::Time::Now().InSecondsFSinceUnixEpoch());
    for (const rtc::scoped_refptr<rtc::RTCCertificate>& certificate :
         configuration.certificates) {
      DOMTimeStamp expires = certificate->Expires();
      if (expires <= now) {
        exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                          "Expired certificate(s).");
        return nullptr;
      }
    }
  }

  RTCPeerConnection* peer_connection = MakeGarbageCollected<RTCPeerConnection>(
      context, std::move(configuration),
      rtc_configuration->encodedInsertableStreams(), exception_state);
  if (exception_state.HadException())
    return nullptr;
  return peer_connection;
}

RTCPeerConnection::RTCPeerConnection(
    ExecutionContext* context,
    webrtc::PeerConnectionInterface::RTCConfiguration configuration,
    bool encoded_insertable_streams,
    ExceptionState& exception_state)
    : ActiveScriptWrappable<RTCPeerConnection>({}),
      ExecutionContextLifecycleObserver(context),
      pending_local_description_(nullptr),
      current_local_description_(nullptr),
      pending_remote_description_(nullptr),
      current_remote_description_(nullptr),
      signaling_state_(
          webrtc::PeerConnectionInterface::SignalingState::kStable),
      ice_gathering_state_(webrtc::PeerConnectionInterface::kIceGatheringNew),
      ice_connection_state_(webrtc::PeerConnectionInterface::kIceConnectionNew),
      peer_connection_state_(
          webrtc::PeerConnectionInterface::PeerConnectionState::kNew),
      peer_handler_unregistered_(true),
      closed_(true),
      suppress_events_(true),
      encoded_insertable_streams_(encoded_insertable_streams),
      rtp_transport_(RuntimeEnabledFeatures::RTCRtpTransportEnabled(context)
                         ? MakeGarbageCollected<RTCRtpTransport>(context)
                         : nullptr) {
  LocalDOMWindow* window = To<LocalDOMWindow>(context);

  // WebRTC peer connections are not allowed in fenced frames.
  // Given the complex scaffolding for setting up fenced frames testing, this
  // is tested in the following locations:
  // * third_party/blink/web_tests/external/wpt/fenced-frame/webrtc-peer-connection.https.html
  // * content/browser/fenced_frame/fenced_frame_browsertest.cc
  if (RuntimeEnabledFeatures::
          FencedFramesLocalUnpartitionedDataAccessEnabled() &&
      window->GetFrame()->IsInFencedFrameTree()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "RTCPeerConnection is not allowed in fenced frames.");
    return;
  }

  InstanceCounters::IncrementCounter(
      InstanceCounters::kRTCPeerConnectionCounter);
  // If we fail, set |m_closed| and |m_stopped| to true, to avoid hitting the
  // assert in the destructor.
  if (InstanceCounters::CounterValue(
          InstanceCounters::kRTCPeerConnectionCounter) > kMaxPeerConnections) {
    exception_state.ThrowDOMException(DOMExceptionCode::kUnknownError,
                                      "Cannot create so many PeerConnections");
    return;
  }

  // Tests might need a custom RtcPeerConnectionHandler implementation.
  PeerConnectionDependencyFactory& dependency_factory =
      PeerConnectionDependencyFactory::From(*context);
  if (!g_create_rpc_peer_connection_handler_callback_.Get().is_null()) {
    peer_handler_ =
        std::move(g_create_rpc_peer_connection_handler_callback_.Get()).Run();
  } else {
    peer_handler_ = dependency_factory.CreateRTCPeerConnectionHandler(
        this, window->GetTaskRunner(TaskType::kInternalMedia),
        encoded_insertable_streams_);
  }

  if (!peer_handler_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "No PeerConnection handler can be "
                                      "created, perhaps WebRTC is disabled?");
    return;
  }

  auto* web_frame =
      static_cast<WebLocalFrame*>(WebFrame::FromCoreFrame(window->GetFrame()));
  if (!peer_handler_->Initialize(context, configuration, web_frame,
                                 exception_state, rtp_transport_)) {
    DCHECK(exception_state.HadException());
    return;
  }
  // After Initialize() with a real `peer_handler_`, WebRTC threads exist.
  scoped_refptr<base::SingleThreadTaskRunner> worker_thread =
      dependency_factory.GetWebRtcWorkerTaskRunner();
  if (!worker_thread) {
    // This path is only used in some unit test environments with a fake
    // `peer_handler_` that does not ensure WebRTC threads exist.
    worker_thread =
        base::ThreadPool::CreateSingleThreadTaskRunner({base::MayBlock()});
  }
  rtp_contributing_source_cache_.emplace(this, std::move(worker_thread));
  // The RTCPeerConnection was successfully constructed.
  closed_ = false;
  peer_handler_unregistered_ = false;
  suppress_events_ = false;
}

RTCPeerConnection::~RTCPeerConnection() {
  // This checks that close() or stop() is called before the destructor.
  // We are assuming that a wrapper is always created when RTCPeerConnection is
  // created.
  DCHECK(closed_ || peer_handler_unregistered_);
  InstanceCounters::DecrementCounter(
      InstanceCounters::kRTCPeerConnectionCounter);
  DCHECK_GE(InstanceCounters::CounterValue(
                InstanceCounters::kRTCPeerConnectionCounter),
            0);
}

void RTCPeerConnection::Dispose() {
  // Promptly clears the handler so that content doesn't access it in a lazy
  // sweeping phase. Other references to the handler use a weak pointer,
  // preventing access.
  if (peer_handler_) {
    peer_handler_.reset();
  }
  // Memory owned by RTCPeerConnection must not be touched after Dispose().
  // Shut down the cache to cancel any in-flight tasks that may otherwise have
  // used the cache.
  if (rtp_contributing_source_cache_.has_value()) {
    rtp_contributing_source_cache_.value().Shutdown();
  }
}

ScriptPromise<RTCSessionDescriptionInit> RTCPeerConnection::createOffer(
    ScriptState* script_state,
    const RTCOfferOptions* options,
    ExceptionState& exception_state) {
  if (signaling_state_ ==
      webrtc::PeerConnectionInterface::SignalingState::kClosed) {
```