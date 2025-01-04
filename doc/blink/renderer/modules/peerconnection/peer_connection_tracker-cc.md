Response:
The user wants me to analyze the provided C++ source code file `peer_connection_tracker.cc` from the Chromium Blink engine. I need to:

1. **List its functionalities:** What does this code do?
2. **Relate to web technologies (JavaScript, HTML, CSS):** How does this code interact with the front-end? Provide examples.
3. **Illustrate logic with input/output:** Give examples of function calls and their likely effects.
4. **Point out common user/programming errors:** What mistakes could developers make when using related APIs?
5. **Explain user interaction leading to this code:**  How does a user's actions in a web browser eventually trigger this code?
6. **Summarize the file's purpose:** Provide a concise overview of its function.

Based on the header and the included files, this code seems to be responsible for tracking the state and activities of `RTCPeerConnection` objects within the Blink rendering engine. This tracking is likely for debugging and monitoring purposes, potentially feeding data to tools like `chrome://webrtc-internals`.

Here's a breakdown of the functionality I can identify from the code snippet:

* **Registration and Unregistration of Peer Connections:** The code manages a list of active `RTCPeerConnectionHandler` objects.
* **Tracking Configuration Changes:** It records changes to the `RTCConfiguration` of peer connections, like ICE servers.
* **Monitoring Session Description (SDP) Exchange:** It tracks when local and remote session descriptions are set.
* **Tracking ICE Candidate Generation and Addition:** It logs when ICE candidates are generated and added, including errors.
* **Managing RTCRtpTransceivers:** It monitors the addition, modification, and state of transceivers.
* **Gathering Statistics:** It interfaces with WebRTC's statistics gathering mechanism and provides data for tools like `chrome://webrtc-internals`.
* **Event Logging:** It can start and stop detailed event logging for specific peer connections.
* **Interaction with Browser Process:** It uses Mojo to communicate with the browser process, sending updates about peer connection state.

Now I will construct the response based on these observations, providing examples and explanations for each point.
```cpp
DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  int id = GetLocalIDForHandler(pc_handler);
  if (id == -1)
    return;

  StringBuilder value;
  value.Append("reason:");
  value.Append("'");
  value.Append(GetTransceiverUpdatedReasonString(reason));
  value.Append("'");
  value.Append(",\n");
  value.Append("index:");
  value.AppendNumber(transceiver_index);
  value.Append(",\n");
  value.Append("transceiver:");
  value.Append(SerializeTransceiver(transceiver));

  String event_name = String::Format("transceiver%s", callback_type_ending);
  SendPeerConnectionUpdate(id, event_name, value.ToString());
}

void PeerConnectionTracker::TrackRemoveTrack(
    RTCPeerConnectionHandler* pc_handler,
    const RTCRtpSenderPlatform& sender) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  int id = GetLocalIDForHandler(pc_handler);
  if (id == -1)
    return;

  StringBuilder value;
  value.Append("sender:{\n");
  value.Append("  track:'");
  if (sender.Track())
    value.Append(sender.Track()->Id());
  value.Append("',\n");
  value.Append("  streams:");
  value.Append(SerializeMediaStreamIds(sender.StreamIds()));
  value.Append("},\n");

  SendPeerConnectionUpdate(id, "removeTrack", value.ToString());
}

void PeerConnectionTracker::TrackAddTrack(
    RTCPeerConnectionHandler* pc_handler,
    const RTCRtpSenderPlatform& sender) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  int id = GetLocalIDForHandler(pc_handler);
  if (id == -1)
    return;

  StringBuilder value;
  value.Append("sender:{\n");
  value.Append("  track:'");
  if (sender.Track())
    value.Append(sender.Track()->Id());
  value.Append("',\n");
  value.Append("  streams:");
  value.Append(SerializeMediaStreamIds(sender.StreamIds()));
  value.Append("},\n");

  SendPeerConnectionUpdate(id, "addTrack", value.ToString());
}

void PeerConnectionTracker::TrackAddStream(RTCPeerConnectionHandler* pc_handler,
                                           const WebMediaStream& stream) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  int id = GetLocalIDForHandler(pc_handler);
  if (id == -1)
    return;
  SendPeerConnectionUpdate(id, "addstream",
                           "streamId: '" + stream.Id() + "'");
}

void PeerConnectionTracker::TrackRemoveStream(
    RTCPeerConnectionHandler* pc_handler,
    const WebMediaStream& stream) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  int id = GetLocalIDForHandler(pc_handler);
  if (id == -1)
    return;
  SendPeerConnectionUpdate(id, "removestream",
                           "streamId: '" + stream.Id() + "'");
}

void PeerConnectionTracker::TrackIceConnectionStateChange(
    RTCPeerConnectionHandler* pc_handler,
    webrtc::PeerConnectionInterface::IceConnectionState state) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  int id = GetLocalIDForHandler(pc_handler);
  if (id == -1)
    return;
  SendPeerConnectionUpdate(id, "iceconnectionstatechange",
                           "newState: " + String::FromUTF8(
                                              webrtc::IceConnectionStateToString(
                                                  state)));
}

void PeerConnectionTracker::TrackIceGatheringStateChange(
    RTCPeerConnectionHandler* pc_handler,
    webrtc::PeerConnectionInterface::IceGatheringState state) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  int id = GetLocalIDForHandler(pc_handler);
  if (id == -1)
    return;
  SendPeerConnectionUpdate(id, "icegatheringstatechange",
                           "newState: " + String::FromUTF8(
                                              webrtc::IceGatheringStateToString(
                                                  state)));
}

void PeerConnectionTracker::TrackSignalingStateChange(
    RTCPeerConnectionHandler* pc_handler,
    webrtc::PeerConnectionInterface::SignalingState state) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  int id = GetLocalIDForHandler(pc_handler);
  if (id == -1)
    return;
  SendPeerConnectionUpdate(id, "signalingstatechange",
                           "newState: " + String::FromUTF8(
                                              webrtc::SignalingStateToString(
                                                  state)));
}

void PeerConnectionTracker::TrackConnectionStateChange(
    RTCPeerConnectionHandler* pc_handler,
    webrtc::PeerConnectionInterface::PeerConnectionState state) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  int id = GetLocalIDForHandler(pc_handler);
  if (id == -1)
    return;
  SendPeerConnectionUpdate(id, "connectionstatechange",
                           "newState: " + String::FromUTF8(
                                              webrtc::PeerConnectionStateToString(
                                                  state)));
}

void PeerConnectionTracker::TrackNegotiationNeeded(
    RTCPeerConnectionHandler* pc_handler) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  int id = GetLocalIDForHandler(pc_handler);
  if (id == -1)
    return;
  SendPeerConnectionUpdate(id, "negotiationneeded", "");
}

void PeerConnectionTracker::TrackDataChannelCreated(
    RTCPeerConnectionHandler* pc_handler,
    const String& label,
    const std::optional<int>& id) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  int lid = GetLocalIDForHandler(pc_handler);
  if (lid == -1)
    return;
  String value = "label: '" + label + "'";
  if (id.has_value())
    value += ", id: " + String::Number(id.value());
  SendPeerConnectionUpdate(lid, "datachannelcreated", value);
}

void PeerConnectionTracker::AddStandardStats(int lid,
                                             base::Value::List stats) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  peer_connection_tracker_host_->AddStandardStats(lid, std::move(stats));
}

void PeerConnectionTracker::EmitCurrentStateForTracker(
    int peer_connection_local_id,
    const String& ice_connection_state,
    const String& ice_gathering_state,
    const String& signaling_state,
    const String& connection_state) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  peer_connection_tracker_host_->EmitCurrentState(
      peer_connection_local_id, ice_connection_state, ice_gathering_state,
      signaling_state, connection_state);
}

int PeerConnectionTracker::GetLocalIDForHandler(
    RTCPeerConnectionHandler* pc_handler) const {
  for (const auto& it : peer_connection_local_id_map_) {
    if (it.key == pc_handler)
      return it.value;
  }
  return -1;
}

void PeerConnectionTracker::SendPeerConnectionUpdate(int id,
                                                    const char* type,
                                                    const String& value) {
  auto info = blink::mojom::blink::PeerConnectionUpdate::New();
  info->type = type;
  info->value = value;
  peer_connection_tracker_host_->UpdatePeerConnection(id, std::move(info));
}

}  // namespace blink
```

**PeerConnectionTracker.cc 功能归纳（第 1 部分）**

`peer_connection_tracker.cc` 的主要功能是**追踪和记录 WebRTC `RTCPeerConnection` 对象的生命周期和状态变化，用于调试和监控目的**。 它充当一个中心枢纽，收集有关 PeerConnection 的各种事件和配置信息，并通过 Mojo 接口将这些信息报告给浏览器的其他组件。

**详细功能点：**

1. **PeerConnection 的注册与注销:**  当创建一个新的 `RTCPeerConnection` 对象时，会调用 `RegisterPeerConnection` 进行注册，并为其分配一个唯一的本地 ID。当 PeerConnection 被销毁时，会调用 `UnregisterPeerConnection` 将其从追踪列表中移除。
2. **配置信息的追踪:** 记录 `RTCPeerConnection` 初始化时的配置信息，例如 ICE 服务器配置 (`iceServers`)、ICE 传输策略 (`iceTransportPolicy`)、捆绑策略 (`bundlePolicy`) 和 RTCP 多路复用策略 (`rtcpMuxPolicy`)。
3. **信令过程的追踪:**  记录信令协商的关键步骤，例如 `createOffer`（创建 Offer）、`createAnswer`（创建 Answer）、`setLocalDescription`（设置本地 SDP）和 `setRemoteDescription`（设置远端 SDP）。
4. **ICE 候选者的追踪:** 监控 ICE (Interactive Connectivity Establishment) 过程，记录本地生成的 ICE 候选者 (`icecandidate`) 以及通过 `addIceCandidate` 添加的远端候选者。 还会记录 ICE 候选者收集过程中出现的错误 (`icecandidateerror`).
5. **RTCRtpTransceiver 的追踪:**  跟踪 `RTCRtpTransceiver` 对象的添加 (`addTransceiver`) 和修改 (`modifyTransceiver`)， 包括其媒体类型 (`kind`)、方向 (`direction`)、Sender 和 Receiver 的信息。
6. **MediaStreamTrack 的追踪:** 记录通过 `addTrack` 添加到 PeerConnection 以及通过 `removeTrack` 移除的 MediaStreamTrack。
7. **WebMediaStream 的追踪:**  记录通过 `addStream` 添加到 PeerConnection 以及通过 `removeStream` 移除的 WebMediaStream。
8. **连接状态的追踪:**  监控 PeerConnection 的各种连接状态变化，包括 ICE 连接状态 (`iceconnectionstatechange`)、ICE 收集状态 (`icegatheringstatechange`)、信令状态 (`signalingstatechange`) 和整体连接状态 (`connectionstatechange`).
9. **协商需求追踪:** 记录何时触发 `negotiationneeded` 事件，表明需要进行信令协商。
10. **DataChannel 的追踪:**  记录 `DataChannel` 的创建 (`datachannelcreated`)，包括其标签和 ID。
11. **标准统计信息的获取:**  响应请求，收集 `RTCPeerConnection` 的标准 WebRTC 统计信息，并将这些信息发送给浏览器的其他组件 (通常用于 `chrome://webrtc-internals`)。
12. **当前状态的获取:** 响应请求，获取并报告 `RTCPeerConnection` 的当前状态。
13. **事件日志的控制:** 允许启动和停止特定 PeerConnection 的详细事件日志记录。
14. **热状态和速度限制的接收:**  接收来自浏览器的设备热状态和网络速度限制信息，并将这些信息传递给相应的 `RTCPeerConnectionHandler`。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`peer_connection_tracker.cc` 位于 Blink 渲染引擎中，它与 JavaScript API (特别是 WebRTC API) 有着直接的联系。当 JavaScript 代码调用 WebRTC API 时，例如创建 `RTCPeerConnection` 对象或调用其方法，会触发此文件中相应的 C++ 代码执行。

* **JavaScript 创建 PeerConnection:**
   ```javascript
   const pc = new RTCPeerConnection(configuration);
   ```
   这个 JavaScript 代码会在 Blink 引擎中创建一个 `RTCPeerConnection` 对象，并最终调用 `peer_connection_tracker.cc` 中的 `RegisterPeerConnection` 方法。

* **JavaScript 设置本地描述:**
   ```javascript
   pc.setLocalDescription(await pc.createOffer());
   ```
   这个 JavaScript 代码会调用 `RTCPeerConnection` 的 `setLocalDescription` 方法，这会触发 `peer_connection_tracker.cc` 中的 `TrackSetSessionDescription` 方法，记录 SDP 信息和类型。

* **JavaScript 添加 ICE 候选者:**
   ```javascript
   pc.onicecandidate = event => {
     if (event.candidate) {
       // Send the candidate to the remote peer
     }
   };
   ```
   当 ICE 框架生成本地候选者时，会触发 JavaScript 的 `onicecandidate` 事件。虽然这个事件在 JavaScript 中处理，但当远端通过信令发送 ICE 候选者过来后，使用 `pc.addIceCandidate(candidate)` 添加时，会触发 `peer_connection_tracker.cc` 中的 `TrackAddIceCandidate` 方法。

* **JavaScript 获取统计信息:**
   ```javascript
   pc.getStats().then(stats => {
     // Process the stats
   });
   ```
   虽然 JavaScript 的 `getStats()` 方法返回的是实时的统计信息，但 `peer_connection_tracker.cc` 中的 `GetStandardStats` 方法是为了支持 `chrome://webrtc-internals` 等调试工具，定期或按需收集统计信息。

HTML 和 CSS 本身不直接与 `peer_connection_tracker.cc` 交互。然而，WebRTC 应用通常在 HTML 页面中运行，并通过 JavaScript 操作 WebRTC API。因此，用户在 HTML 页面上的操作（例如点击按钮发起通话）可能会间接地触发 `peer_connection_tracker.cc` 中的代码执行。

**逻辑推理及假设输入与输出：**

假设 JavaScript 代码执行以下操作：

```javascript
const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.example.org' }] });
pc.createOffer()
  .then(offer => pc.setLocalDescription(offer));
```

**假设输入：**

* `RegisterPeerConnection` 被调用，传入包含 `iceServers` 配置的 `RTCConfiguration` 对象。
* `TrackCreateOffer` 被调用，可能传入 `RTCOfferOptionsPlatform` 对象 (如果指定了选项)。
* `TrackSetSessionDescription` 被调用，传入生成的 SDP 字符串和类型 "offer"。

**预期输出 (通过 Mojo 发送给浏览器进程的信息):**

* `AddPeerConnection` Mojo 调用，包含 PeerConnection 的本地 ID、URL 和序列化后的配置信息：
  ```json
  {
    "lid": 1, // 假设分配的本地 ID 为 1
    "rtc_configuration": "{ iceServers: [\"stun:stun.example.org\"], iceTransportPolicy: none, bundlePolicy: balanced, rtcpMuxPolicy: negotiate, iceCandidatePoolSize: 0 }",
    "url": "当前页面的 URL"
  }
  ```
* `UpdatePeerConnection` Mojo 调用，类型为 "createOffer"，包含序列化后的 Offer 选项。
* `UpdatePeerConnection` Mojo 调用，类型为 "setLocalDescription"，包含 SDP 内容和类型 "offer"。

**用户或编程常见的使用错误及举例说明：**

* **未正确配置 ICE 服务器:** 用户或开发者可能忘记在 `RTCConfiguration` 中提供有效的 STUN 或 TURN 服务器地址。这会导致 ICE 连接失败，`peer_connection_tracker.cc` 会记录相关的状态变化，如 `iceconnectionstatechange` 为 "failed"。
* **在错误的时机调用 WebRTC API:** 例如，在 `signalingState` 不正确时尝试创建 Offer 或 Answer。这会导致状态不一致，`peer_connection_tracker.cc` 会记录信令状态的变化，有助于诊断问题。
* **处理 ICE 候选者时的错误:**  开发者可能在信令通道中传输 ICE 候选者时出错，导致远端无法正确添加候选者。虽然 `peer_connection_tracker.cc` 主要追踪本地行为，但通过分析 `icecandidateerror` 事件，可以帮助定位问题。
* **误用 `addTrack` 和 `addStream`:**  开发者可能不理解 `addTrack` 和 `addStream` 的区别，导致媒体流的添加方式不正确。`peer_connection_tracker.cc` 会记录这些操作，有助于理解媒体流的添加过程。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户打开一个包含 WebRTC 应用的网页。**
2. **网页的 JavaScript 代码创建了一个 `RTCPeerConnection` 对象。** 这触发了 `PeerConnectionTracker::RegisterPeerConnection`。
3. **用户点击页面上的 "发起通话" 按钮。**
4. **JavaScript 代码调用 `pc.createOffer()`。** 这触发了 `PeerConnectionTracker::TrackCreateOffer`.
5. **JavaScript 代码调用 `pc.setLocalDescription(offer)`。** 这触发了 `PeerConnectionTracker::TrackSetSessionDescription`.
6. **ICE 框架开始收集 ICE 候选者。** 每个本地生成的候选者都会导致 `PeerConnectionTracker::TrackAddIceCandidate` 被调用 (source 为 `kSourceLocal`).
7. **信令通道将本地 ICE 候选者发送到远端，并接收远端的 ICE 候选者。**
8. **JavaScript 代码调用 `pc.addIceCandidate(remoteCandidate)`。** 这触发了 `PeerConnectionTracker::TrackAddIceCandidate` (source 为 `kSourceRemote`).
9. **PeerConnection 的 ICE 连接状态发生变化 (例如，"checking", "connected")。** 这触发了 `PeerConnectionTracker::TrackIceConnectionStateChange`.

通过查看 `peer_connection_tracker.cc` 记录的这些事件和状态变化，开发者可以逐步了解 WebRTC 连接的建立过程，并定位问题发生的环节。例如，如果 `iceconnectionstatechange` 一直停留在 "checking" 状态，可能意味着 ICE 服务器配置有问题，或者网络存在阻碍。

**功能归纳（第 1 部分）:**

总而言之，`peer_connection_tracker.cc` 的主要功能是作为 Blink 引擎中 WebRTC `RTCPeerConnection` 的监控和追踪器。它记录关键的生命周期事件、配置信息、信令过程、ICE 交互和连接状态变化，并将这些信息通过 Mojo 发送给浏览器的其他部分，主要用于调试和监控目的，例如支持 `chrome://webrtc-internals` 工具。

Prompt: 
```
这是目录为blink/renderer/modules/peerconnection/peer_connection_tracker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/peerconnection/peer_connection_tracker.h"

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "base/containers/contains.h"
#include "base/task/single_thread_task_runner.h"
#include "base/types/pass_key.h"
#include "base/values.h"
#include "build/build_config.h"
#include "build/buildflag.h"
#include "build/chromecast_buildflags.h"
#include "third_party/blink/public/mojom/peerconnection/peer_connection_tracker.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/interface_registry.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints.h"
#include "third_party/blink/renderer/modules/mediastream/user_media_request.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_peer_connection_handler.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/platform/mojo/mojo_binding_context.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_answer_options_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_ice_candidate_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_offer_options_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_peer_connection_handler_client.h"
#include "third_party/blink/renderer/platform/peerconnection/webrtc_util.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/webrtc/api/stats/rtcstats_objects.h"

using webrtc::StatsReport;
using webrtc::StatsReports;

namespace blink {
class InternalStandardStatsObserver;
}

namespace WTF {

template <>
struct CrossThreadCopier<scoped_refptr<blink::InternalStandardStatsObserver>>
    : public CrossThreadCopierPassThrough<
          scoped_refptr<blink::InternalStandardStatsObserver>> {
  STATIC_ONLY(CrossThreadCopier);
};

template <typename T>
struct CrossThreadCopier<rtc::scoped_refptr<T>> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = rtc::scoped_refptr<T>;
  static Type Copy(Type pointer) { return pointer; }
};

template <>
struct CrossThreadCopier<base::Value::List>
    : public CrossThreadCopierByValuePassThrough<base::Value::List> {
  STATIC_ONLY(CrossThreadCopier);
};

}  // namespace WTF

namespace blink {

// TODO(hta): This module should be redesigned to reduce string copies.

namespace {

String SerializeBoolean(bool value) {
  return value ? "true" : "false";
}

String SerializeServers(
    const std::vector<webrtc::PeerConnectionInterface::IceServer>& servers) {
  StringBuilder result;
  result.Append("[");

  bool following = false;
  for (const auto& server : servers) {
    for (const auto& url : server.urls) {
      if (following)
        result.Append(", ");
      else
        following = true;

      result.Append(String::FromUTF8(url));
    }
  }
  result.Append("]");
  return result.ToString();
}

String SerializeGetUserMediaMediaConstraints(
    const MediaConstraints& constraints) {
  return String(constraints.ToString());
}

String SerializeOfferOptions(blink::RTCOfferOptionsPlatform* options) {
  if (!options)
    return "null";

  StringBuilder result;
  result.Append("offerToReceiveVideo: ");
  result.AppendNumber(options->OfferToReceiveVideo());
  result.Append(", offerToReceiveAudio: ");
  result.AppendNumber(options->OfferToReceiveAudio());
  result.Append(", voiceActivityDetection: ");
  result.Append(SerializeBoolean(options->VoiceActivityDetection()));
  result.Append(", iceRestart: ");
  result.Append(SerializeBoolean(options->IceRestart()));
  return result.ToString();
}

String SerializeAnswerOptions(blink::RTCAnswerOptionsPlatform* options) {
  if (!options)
    return "null";

  StringBuilder result;
  result.Append(", voiceActivityDetection: ");
  result.Append(SerializeBoolean(options->VoiceActivityDetection()));
  return result.ToString();
}

String SerializeMediaStreamIds(const Vector<String>& stream_ids) {
  if (!stream_ids.size())
    return "[]";
  StringBuilder result;
  result.Append("[");
  for (const auto& stream_id : stream_ids) {
    if (result.length() > 2u)
      result.Append(",");
    result.Append("'");
    result.Append(stream_id);
    result.Append("'");
  }
  result.Append("]");
  return result.ToString();
}

String SerializeDirection(webrtc::RtpTransceiverDirection direction) {
  switch (direction) {
    case webrtc::RtpTransceiverDirection::kSendRecv:
      return "'sendrecv'";
    case webrtc::RtpTransceiverDirection::kSendOnly:
      return "'sendonly'";
    case webrtc::RtpTransceiverDirection::kRecvOnly:
      return "'recvonly'";
    case webrtc::RtpTransceiverDirection::kInactive:
      return "'inactive'";
    case webrtc::RtpTransceiverDirection::kStopped:
      return "'stopped'";
    default:
      NOTREACHED();
  }
}

String SerializeOptionalDirection(
    const std::optional<webrtc::RtpTransceiverDirection>& direction) {
  return direction ? SerializeDirection(*direction) : "null";
}

String SerializeTransceiverKind(const String& indent,
                                const RTCRtpTransceiverPlatform& transceiver) {
  DCHECK(transceiver.Receiver());
  DCHECK(transceiver.Receiver()->Track());

  auto kind = transceiver.Receiver()->Track()->GetSourceType();
  StringBuilder result;
  result.Append(indent);
  result.Append("kind:");
  if (kind == MediaStreamSource::StreamType::kTypeAudio) {
    result.Append("'audio'");
  } else if (kind == MediaStreamSource::StreamType::kTypeVideo) {
    result.Append("'video'");
  } else {
    NOTREACHED();
  }
  result.Append(",\n");
  return result.ToString();
}

String SerializeEncodingParameters(
    const String& indent,
    const std::vector<webrtc::RtpEncodingParameters>& encodings) {
  StringBuilder result;
  if (encodings.empty()) {
    return result.ToString();
  }
  result.Append(indent);
  result.Append("encodings: [\n");
  for (const auto& encoding : encodings) {
    result.Append(indent);
    result.Append("    {");
    result.Append("active: ");
    result.Append(encoding.active ? "true" : "false");
    result.Append(", ");
    if (encoding.max_bitrate_bps) {
      result.Append("maxBitrate: ");
      result.AppendNumber(*encoding.max_bitrate_bps);
      result.Append(", ");
    }
    if (encoding.scale_resolution_down_by) {
      result.Append("scaleResolutionDownBy: ");
      result.AppendNumber(*encoding.scale_resolution_down_by);
      result.Append(", ");
    }
    if (!encoding.rid.empty()) {
      result.Append("rid: ");
      result.Append(String(encoding.rid));
      result.Append(", ");
    }
    if (encoding.max_framerate) {
      result.Append("maxFramerate: ");
      result.AppendNumber(*encoding.max_framerate);
      result.Append(", ");
    }
    if (encoding.adaptive_ptime) {
      result.Append("adaptivePtime: true, ");
    }
    if (encoding.scalability_mode) {
      result.Append("scalabilityMode: ");
      result.Append(String(*encoding.scalability_mode));
    }
    result.Append("},\n");
  }
  result.Append(indent);
  result.Append("  ],\n");
  result.Append(indent);
  return result.ToString();
}

String SerializeSender(const String& indent,
                       const blink::RTCRtpSenderPlatform& sender) {
  StringBuilder result;
  result.Append(indent);
  result.Append("sender:{\n");
  // track:'id',
  result.Append(indent);
  result.Append("  track:");
  if (!sender.Track()) {
    result.Append("null");
  } else {
    result.Append("'");
    result.Append(sender.Track()->Id());
    result.Append("'");
  }
  result.Append(",\n");
  // streams:['id,'id'],
  result.Append(indent);
  result.Append("  streams:");
  result.Append(SerializeMediaStreamIds(sender.StreamIds()));
  result.Append(",\n");
  result.Append(indent);
  result.Append(
      SerializeEncodingParameters(indent, sender.GetParameters()->encodings));
  result.Append("},\n");

  return result.ToString();
}

String SerializeReceiver(const String& indent,
                         const RTCRtpReceiverPlatform& receiver) {
  StringBuilder result;
  result.Append(indent);
  result.Append("receiver:{\n");
  // track:'id',
  DCHECK(receiver.Track());
  result.Append(indent);
  result.Append("  track:'");
  result.Append(receiver.Track()->Id());
  result.Append("',\n");
  // streams:['id,'id'],
  result.Append(indent);
  result.Append("  streams:");
  result.Append(SerializeMediaStreamIds(receiver.StreamIds()));
  result.Append(",\n");
  result.Append(indent);
  result.Append("},\n");
  return result.ToString();
}

String SerializeTransceiver(const RTCRtpTransceiverPlatform& transceiver) {
  StringBuilder result;
  result.Append("{\n");
  // mid:'foo',
  if (transceiver.Mid().IsNull()) {
    result.Append("  mid:null,\n");
  } else {
    result.Append("  mid:'");
    result.Append(String(transceiver.Mid()));
    result.Append("',\n");
  }
  // kind:audio|video
  result.Append(SerializeTransceiverKind("  ", transceiver));
  // sender:{...},
  result.Append(SerializeSender("  ", *transceiver.Sender()));
  // receiver:{...},
  result.Append(SerializeReceiver("  ", *transceiver.Receiver()));
  // direction:'sendrecv',
  result.Append("  direction:");
  result.Append(SerializeDirection(transceiver.Direction()));
  result.Append(",\n");
  // currentDirection:null,
  result.Append("  currentDirection:");
  result.Append(SerializeOptionalDirection(transceiver.CurrentDirection()));
  result.Append(",\n");
  result.Append("}");
  return result.ToString();
}

String SerializeIceTransportType(
    webrtc::PeerConnectionInterface::IceTransportsType type) {
  String transport_type("");
  switch (type) {
    case webrtc::PeerConnectionInterface::kNone:
      transport_type = "none";
      break;
    case webrtc::PeerConnectionInterface::kRelay:
      transport_type = "relay";
      break;
    case webrtc::PeerConnectionInterface::kAll:
      transport_type = "all";
      break;
    case webrtc::PeerConnectionInterface::kNoHost:
      transport_type = "noHost";
      break;
    default:
      NOTREACHED();
  }
  return transport_type;
}

String SerializeBundlePolicy(
    webrtc::PeerConnectionInterface::BundlePolicy policy) {
  String policy_str("");
  switch (policy) {
    case webrtc::PeerConnectionInterface::kBundlePolicyBalanced:
      policy_str = "balanced";
      break;
    case webrtc::PeerConnectionInterface::kBundlePolicyMaxBundle:
      policy_str = "max-bundle";
      break;
    case webrtc::PeerConnectionInterface::kBundlePolicyMaxCompat:
      policy_str = "max-compat";
      break;
    default:
      NOTREACHED();
  }
  return policy_str;
}

String SerializeRtcpMuxPolicy(
    webrtc::PeerConnectionInterface::RtcpMuxPolicy policy) {
  String policy_str("");
  switch (policy) {
    case webrtc::PeerConnectionInterface::kRtcpMuxPolicyNegotiate:
      policy_str = "negotiate";
      break;
    case webrtc::PeerConnectionInterface::kRtcpMuxPolicyRequire:
      policy_str = "require";
      break;
    default:
      NOTREACHED();
  }
  return policy_str;
}

// Serializes things that are of interest from the RTCConfiguration.
String SerializeConfiguration(
    const webrtc::PeerConnectionInterface::RTCConfiguration& config,
    bool usesInsertableStreams) {
  StringBuilder result;
  // TODO(hbos): Add serialization of certificate.
  result.Append("{ iceServers: ");
  result.Append(SerializeServers(config.servers));
  result.Append(", iceTransportPolicy: ");
  result.Append(SerializeIceTransportType(config.type));
  result.Append(", bundlePolicy: ");
  result.Append(SerializeBundlePolicy(config.bundle_policy));
  result.Append(", rtcpMuxPolicy: ");
  result.Append(SerializeRtcpMuxPolicy(config.rtcp_mux_policy));
  result.Append(", iceCandidatePoolSize: ");
  result.AppendNumber(config.ice_candidate_pool_size);
  if (usesInsertableStreams) {
    result.Append(", encodedInsertableStreams: true");
  }
  result.Append(" }");
  return result.ToString();
}

const char* GetTransceiverUpdatedReasonString(
    PeerConnectionTracker::TransceiverUpdatedReason reason) {
  switch (reason) {
    case PeerConnectionTracker::TransceiverUpdatedReason::kAddTransceiver:
      return "addTransceiver";
    case PeerConnectionTracker::TransceiverUpdatedReason::kAddTrack:
      return "addTrack";
    case PeerConnectionTracker::TransceiverUpdatedReason::kRemoveTrack:
      return "removeTrack";
    case PeerConnectionTracker::TransceiverUpdatedReason::kSetLocalDescription:
      return "setLocalDescription";
    case PeerConnectionTracker::TransceiverUpdatedReason::kSetRemoteDescription:
      return "setRemoteDescription";
  }
  NOTREACHED();
}

int GetNextProcessLocalID() {
  static int next_local_id = 1;
  return next_local_id++;
}

}  // namespace

// chrome://webrtc-internals displays stats and stats graphs. The call path
// involves thread and process hops (IPC). This is the stats observer that is
// used when webrtc-internals wants standard stats. It starts in
// webrtc_internals.js performing requestStandardStats and the result gets
// asynchronously delivered to webrtc_internals.js at addStandardStats.
class InternalStandardStatsObserver : public webrtc::RTCStatsCollectorCallback {
 public:
  InternalStandardStatsObserver(
      const base::WeakPtr<RTCPeerConnectionHandler> pc_handler,
      int lid,
      scoped_refptr<base::SingleThreadTaskRunner> main_thread,
      Vector<std::unique_ptr<blink::RTCRtpSenderPlatform>> senders,
      CrossThreadOnceFunction<void(int, base::Value::List)> completion_callback)
      : pc_handler_(pc_handler),
        lid_(lid),
        main_thread_(std::move(main_thread)),
        senders_(std::move(senders)),
        completion_callback_(std::move(completion_callback)) {}

  void OnStatsDelivered(
      const rtc::scoped_refptr<const webrtc::RTCStatsReport>& report) override {
    // We're on the signaling thread.
    DCHECK(!main_thread_->BelongsToCurrentThread());
    PostCrossThreadTask(
        *main_thread_.get(), FROM_HERE,
        CrossThreadBindOnce(
            &InternalStandardStatsObserver::OnStatsDeliveredOnMainThread,
            scoped_refptr<InternalStandardStatsObserver>(this), report));
  }

 protected:
  ~InternalStandardStatsObserver() override {}

 private:
  void OnStatsDeliveredOnMainThread(
      rtc::scoped_refptr<const webrtc::RTCStatsReport> report) {
    std::move(completion_callback_).Run(lid_, ReportToList(report));
  }

  base::Value::List ReportToList(
      const rtc::scoped_refptr<const webrtc::RTCStatsReport>& report) {
    std::map<std::string, MediaStreamTrackPlatform*> tracks_by_id;
    for (const auto& sender : senders_) {
      MediaStreamComponent* track_component = sender->Track();
      if (!track_component) {
        continue;
      }
      tracks_by_id.insert(std::make_pair(track_component->Id().Utf8(),
                                         track_component->GetPlatformTrack()));
    }

    base::Value::List result_list;

    if (!pc_handler_) {
      return result_list;
    }
    auto* local_frame = To<WebLocalFrameImpl>(*pc_handler_->frame()).GetFrame();
    DocumentLoadTiming& time_converter =
        local_frame->Loader().GetDocumentLoader()->GetTiming();
    // Used for string comparisons with const char* below.
    const std::string kTypeMediaSource = "media-source";
    for (const auto& stats : *report) {
      // The format of "stats_subdictionary" is:
      // {timestamp:<milliseconds>, values: [<key-value pairs>]}
      // The timestamp unit is milliseconds but we want decimal
      // precision so we convert ourselves.
      base::Value::Dict stats_subdictionary;
      base::TimeDelta monotonic_time =
          time_converter.MonotonicTimeToPseudoWallTime(
              ConvertToBaseTimeTicks(stats.timestamp()));
      stats_subdictionary.Set(
          "timestamp",
          monotonic_time.InMicrosecondsF() /
              static_cast<double>(base::Time::kMicrosecondsPerMillisecond));
      // Values are reported as
      // "values": ["attribute1", value, "attribute2", value...]
      base::Value::List name_value_pairs;
      for (const auto& attribute : stats.Attributes()) {
        if (!attribute.has_value()) {
          continue;
        }
        name_value_pairs.Append(attribute.name());
        name_value_pairs.Append(AttributeToValue(attribute));
      }
      // Modify "media-source" to also contain the result of the
      // MediaStreamTrack Statistics API, if applicable.
      if (stats.type() == kTypeMediaSource) {
        const webrtc::RTCMediaSourceStats& media_source =
            static_cast<const webrtc::RTCMediaSourceStats&>(stats);
        if (media_source.kind.has_value() && *media_source.kind == "video" &&
            media_source.track_identifier.has_value()) {
          auto it = tracks_by_id.find(*media_source.track_identifier);
          if (it != tracks_by_id.end()) {
            MediaStreamTrackPlatform::VideoFrameStats video_frame_stats =
                it->second->GetVideoFrameStats();
            name_value_pairs.Append("track.deliveredFrames");
            name_value_pairs.Append(base::Value(
                static_cast<int>(video_frame_stats.deliverable_frames)));
            name_value_pairs.Append("track.discardedFrames");
            name_value_pairs.Append(base::Value(
                static_cast<int>(video_frame_stats.discarded_frames)));
            name_value_pairs.Append("track.totalFrames");
            name_value_pairs.Append(base::Value(
                static_cast<int>(video_frame_stats.deliverable_frames +
                                 video_frame_stats.discarded_frames +
                                 video_frame_stats.dropped_frames)));
          }
        }
      }
      stats_subdictionary.Set("values", std::move(name_value_pairs));

      // The format of "stats_dictionary" is:
      // {id:<string>, stats:<stats_subdictionary>, type:<string>}
      base::Value::Dict stats_dictionary;
      stats_dictionary.Set("stats", std::move(stats_subdictionary));
      stats_dictionary.Set("id", stats.id());
      stats_dictionary.Set("type", stats.type());
      result_list.Append(std::move(stats_dictionary));
    }
    return result_list;
  }

  base::Value AttributeToValue(const webrtc::Attribute& attribute) {
    // Types supported by `base::Value` are passed as the appropriate type.
    if (attribute.holds_alternative<bool>()) {
      return base::Value(attribute.get<bool>());
    }
    if (attribute.holds_alternative<int32_t>()) {
      return base::Value(attribute.get<int32_t>());
    }
    if (attribute.holds_alternative<std::string>()) {
      return base::Value(attribute.get<std::string>());
    }
    if (attribute.holds_alternative<double>()) {
      return base::Value(attribute.get<double>());
    }
    // Types not supported by `base::Value` are converted to string.
    return base::Value(attribute.ToString());
  }

  const base::WeakPtr<RTCPeerConnectionHandler> pc_handler_;
  const int lid_;
  const scoped_refptr<base::SingleThreadTaskRunner> main_thread_;
  const Vector<std::unique_ptr<blink::RTCRtpSenderPlatform>> senders_;
  CrossThreadOnceFunction<void(int, base::Value::List)> completion_callback_;
};

// static
const char PeerConnectionTracker::kSupplementName[] = "PeerConnectionTracker";

PeerConnectionTracker& PeerConnectionTracker::From(LocalDOMWindow& window) {
  PeerConnectionTracker* tracker =
      Supplement<LocalDOMWindow>::From<PeerConnectionTracker>(window);
  if (!tracker) {
    tracker = MakeGarbageCollected<PeerConnectionTracker>(
        window, window.GetTaskRunner(TaskType::kNetworking),
        base::PassKey<PeerConnectionTracker>());
    ProvideTo(window, tracker);
  }
  return *tracker;
}

PeerConnectionTracker* PeerConnectionTracker::From(LocalFrame& frame) {
  auto* window = frame.DomWindow();
  return window ? &From(*window) : nullptr;
}

PeerConnectionTracker* PeerConnectionTracker::From(WebLocalFrame& frame) {
  auto* local_frame = To<WebLocalFrameImpl>(frame).GetFrame();
  return local_frame ? From(*local_frame) : nullptr;
}

void PeerConnectionTracker::BindToFrame(
    LocalFrame* frame,
    mojo::PendingReceiver<blink::mojom::blink::PeerConnectionManager>
        receiver) {
  if (!frame)
    return;

  if (auto* tracker = From(*frame))
    tracker->Bind(std::move(receiver));
}

PeerConnectionTracker::PeerConnectionTracker(
    LocalDOMWindow& window,
    scoped_refptr<base::SingleThreadTaskRunner> main_thread_task_runner,
    base::PassKey<PeerConnectionTracker>)
    : Supplement<LocalDOMWindow>(window),
      // Do not set a lifecycle notifier for `peer_connection_tracker_host_` to
      // ensure that its mojo pipe stays alive until the execution context is
      // destroyed. `RTCPeerConnection`, which owns a `RTCPeerConnectionHandler`
      // which keeps `this` alive, will to close and unregister the peer
      // connection when the execution context is destroyed. For this to happen,
      // the mojo pipe _must_ be alive to relay. See https://crbug.com/1426377
      // for details.
      peer_connection_tracker_host_(nullptr),
      receiver_(this, &window),
      main_thread_task_runner_(std::move(main_thread_task_runner)) {
  window.GetBrowserInterfaceBroker().GetInterface(
      peer_connection_tracker_host_.BindNewPipeAndPassReceiver(
          main_thread_task_runner_));
}

// Constructor used for testing. Note that receiver_ doesn't have a context
// notifier in this case.
PeerConnectionTracker::PeerConnectionTracker(
    mojo::PendingRemote<blink::mojom::blink::PeerConnectionTrackerHost> host,
    scoped_refptr<base::SingleThreadTaskRunner> main_thread_task_runner)
    : Supplement(nullptr),
      peer_connection_tracker_host_(nullptr),
      receiver_(this, nullptr),
      main_thread_task_runner_(std::move(main_thread_task_runner)) {
  peer_connection_tracker_host_.Bind(std::move(host), main_thread_task_runner_);
}

PeerConnectionTracker::~PeerConnectionTracker() {}

void PeerConnectionTracker::Bind(
    mojo::PendingReceiver<blink::mojom::blink::PeerConnectionManager>
        receiver) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  receiver_.Bind(std::move(receiver), GetSupplementable()->GetTaskRunner(
                                          TaskType::kMiscPlatformAPI));
}

void PeerConnectionTracker::OnSuspend() {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  // Closing peer connections fires events. If JavaScript triggers the creation
  // or garbage collection of more peer connections, this would invalidate the
  // |peer_connection_local_id_map_| iterator. Therefor we iterate on a copy.
  PeerConnectionLocalIdMap peer_connection_map_copy =
      peer_connection_local_id_map_;
  for (const auto& pair : peer_connection_map_copy) {
    RTCPeerConnectionHandler* peer_connection_handler = pair.key;
    if (!base::Contains(peer_connection_local_id_map_,
                        peer_connection_handler)) {
      // Skip peer connections that have been unregistered during this method
      // call. Avoids use-after-free.
      continue;
    }
    peer_connection_handler->CloseClientPeerConnection();
  }
}

void PeerConnectionTracker::OnThermalStateChange(
    mojom::blink::DeviceThermalState thermal_state) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  current_thermal_state_ = thermal_state;
  for (auto& entry : peer_connection_local_id_map_) {
    entry.key->OnThermalStateChange(current_thermal_state_);
  }
}

void PeerConnectionTracker::OnSpeedLimitChange(int32_t speed_limit) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  current_speed_limit_ = speed_limit;
  for (auto& entry : peer_connection_local_id_map_) {
    entry.key->OnSpeedLimitChange(speed_limit);
  }
}

void PeerConnectionTracker::StartEventLog(int peer_connection_local_id,
                                          int output_period_ms) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  for (auto& it : peer_connection_local_id_map_) {
    if (it.value == peer_connection_local_id) {
      it.key->StartEventLog(output_period_ms);
      return;
    }
  }
}

void PeerConnectionTracker::StopEventLog(int peer_connection_local_id) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  for (auto& it : peer_connection_local_id_map_) {
    if (it.value == peer_connection_local_id) {
      it.key->StopEventLog();
      return;
    }
  }
}

void PeerConnectionTracker::GetStandardStats() {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);

  for (const auto& pair : peer_connection_local_id_map_) {
    Vector<std::unique_ptr<blink::RTCRtpSenderPlatform>> senders =
        pair.key->GetPlatformSenders();
    rtc::scoped_refptr<InternalStandardStatsObserver> observer(
        new rtc::RefCountedObject<InternalStandardStatsObserver>(
            pair.key->GetWeakPtr(), pair.value, main_thread_task_runner_,
            std::move(senders),
            CrossThreadBindOnce(&PeerConnectionTracker::AddStandardStats,
                                WrapCrossThreadWeakPersistent(this))));
    pair.key->GetStandardStatsForTracker(observer);
  }
}

void PeerConnectionTracker::GetCurrentState() {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);

  for (const auto& pair : peer_connection_local_id_map_) {
    pair.key->EmitCurrentStateForTracker();
  }
}

void PeerConnectionTracker::RegisterPeerConnection(
    RTCPeerConnectionHandler* pc_handler,
    const webrtc::PeerConnectionInterface::RTCConfiguration& config,
    const blink::WebLocalFrame* frame) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  DCHECK(pc_handler);
  DCHECK_EQ(GetLocalIDForHandler(pc_handler), -1);
  DVLOG(1) << "PeerConnectionTracker::RegisterPeerConnection()";
  auto info = blink::mojom::blink::PeerConnectionInfo::New();

  info->lid = GetNextLocalID();
  info->rtc_configuration =
      SerializeConfiguration(config, pc_handler->encoded_insertable_streams());

  if (frame)
    info->url = frame->GetDocument().Url().GetString();
  else
    info->url = "test:testing";

  int32_t lid = info->lid;
  peer_connection_tracker_host_->AddPeerConnection(std::move(info));

  peer_connection_local_id_map_.insert(pc_handler, lid);

  if (current_thermal_state_ != mojom::blink::DeviceThermalState::kUnknown) {
    pc_handler->OnThermalStateChange(current_thermal_state_);
  }
}

void PeerConnectionTracker::UnregisterPeerConnection(
    RTCPeerConnectionHandler* pc_handler) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  DVLOG(1) << "PeerConnectionTracker::UnregisterPeerConnection()";

  auto it = peer_connection_local_id_map_.find(pc_handler);

  if (it == peer_connection_local_id_map_.end()) {
    // The PeerConnection might not have been registered if its initialization
    // failed.
    return;
  }

  peer_connection_tracker_host_->RemovePeerConnection(it->value);

  peer_connection_local_id_map_.erase(it);
}

void PeerConnectionTracker::TrackCreateOffer(
    RTCPeerConnectionHandler* pc_handler,
    RTCOfferOptionsPlatform* options) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  int id = GetLocalIDForHandler(pc_handler);
  if (id == -1)
    return;
  SendPeerConnectionUpdate(id, "createOffer",
                           "options: {" + SerializeOfferOptions(options) + "}");
}

void PeerConnectionTracker::TrackCreateAnswer(
    RTCPeerConnectionHandler* pc_handler,
    RTCAnswerOptionsPlatform* options) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  int id = GetLocalIDForHandler(pc_handler);
  if (id == -1)
    return;
  SendPeerConnectionUpdate(
      id, "createAnswer", "options: {" + SerializeAnswerOptions(options) + "}");
}

void PeerConnectionTracker::TrackSetSessionDescription(
    RTCPeerConnectionHandler* pc_handler,
    const String& sdp,
    const String& type,
    Source source) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  int id = GetLocalIDForHandler(pc_handler);
  if (id == -1)
    return;
  String value = "type: " + type + ", sdp: " + sdp;
  SendPeerConnectionUpdate(
      id,
      source == kSourceLocal ? "setLocalDescription" : "setRemoteDescription",
      value);
}

void PeerConnectionTracker::TrackSetSessionDescriptionImplicit(
    RTCPeerConnectionHandler* pc_handler) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  int id = GetLocalIDForHandler(pc_handler);
  if (id == -1)
    return;
  SendPeerConnectionUpdate(id, "setLocalDescription", "");
}

void PeerConnectionTracker::TrackSetConfiguration(
    RTCPeerConnectionHandler* pc_handler,
    const webrtc::PeerConnectionInterface::RTCConfiguration& config) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  int id = GetLocalIDForHandler(pc_handler);
  if (id == -1)
    return;

  SendPeerConnectionUpdate(
      id, "setConfiguration",
      SerializeConfiguration(config, pc_handler->encoded_insertable_streams()));
}

void PeerConnectionTracker::TrackAddIceCandidate(
    RTCPeerConnectionHandler* pc_handler,
    RTCIceCandidatePlatform* candidate,
    Source source,
    bool succeeded) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  int id = GetLocalIDForHandler(pc_handler);
  if (id == -1)
    return;
  std::optional<String> relay_protocol = candidate->RelayProtocol();
  std::optional<String> url = candidate->Url();
  String value =
      "sdpMid: " + String(candidate->SdpMid()) + ", " + "sdpMLineIndex: " +
      (candidate->SdpMLineIndex() ? String::Number(*candidate->SdpMLineIndex())
                                  : "null") +
      ", candidate: " + String(candidate->Candidate()) +
      (url ? ", url: " + *url : String()) +
      (relay_protocol ? ", relayProtocol: " + *relay_protocol : String());

  // OnIceCandidate always succeeds as it's a callback from the browser.
  DCHECK(source != kSourceLocal || succeeded);

  const char* event =
      (source == kSourceLocal)
          ? "icecandidate"
          : (succeeded ? "addIceCandidate" : "addIceCandidateFailed");

  SendPeerConnectionUpdate(id, event, value);
}

void PeerConnectionTracker::TrackIceCandidateError(
    RTCPeerConnectionHandler* pc_handler,
    const String& address,
    std::optional<uint16_t> port,
    const String& host_candidate,
    const String& url,
    int error_code,
    const String& error_text) {
  DCHECK_CALLED_ON_VALID_THREAD(main_thread_);
  int id = GetLocalIDForHandler(pc_handler);
  if (id == -1)
    return;
  String address_string = address ? "address: " + address + "\n" : String();
  String port_string =
      port.has_value() ? String::Format("port: %d\n", port.value()) : "";
  String value = "url: " + url + "\n" + address_string + port_string +
                 "host_candidate: " + host_candidate + "\n" +
                 "error_text: " + error_text + "\n" +
                 "error_code: " + String::Number(error_code);
  SendPeerConnectionUpdate(id, "icecandidateerror", value);
}

void PeerConnectionTracker::TrackAddTransceiver(
    RTCPeerConnectionHandler* pc_handler,
    PeerConnectionTracker::TransceiverUpdatedReason reason,
    const RTCRtpTransceiverPlatform& transceiver,
    size_t transceiver_index) {
  TrackTransceiver("Added", pc_handler, reason, transceiver, transceiver_index);
}

void PeerConnectionTracker::TrackModifyTransceiver(
    RTCPeerConnectionHandler* pc_handler,
    PeerConnectionTracker::TransceiverUpdatedReason reason,
    const RTCRtpTransceiverPlatform& transceiver,
    size_t transceiver_index) {
  TrackTransceiver("Modified", pc_handler, reason, transceiver,
                   transceiver_index);
}

void PeerConnectionTracker::TrackTransceiver(
    const char* callback_type_ending,
    RTCPeerConnectionHandler* pc_handler,
    PeerConnectionTracker::TransceiverUpdatedReason reason,
    const RTCRtpTransceiverPlatform& transceiver,
    size_t transceiver_index) {
  DCHECK_
"""


```