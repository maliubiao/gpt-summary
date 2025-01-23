Response:
My thinking process to analyze the provided code snippet and answer the prompt went through these stages:

1. **Understand the Goal:** The primary goal is to analyze a specific Chromium Blink source file (`rtc_peer_connection_handler.cc`) and explain its functionality, especially its relationships with web technologies, internal logic, potential errors, debugging steps, and provide a summary of its core function.

2. **Initial Scan and Keyword Identification:**  I quickly scanned the code looking for prominent keywords and structures. Things that jumped out were:
    * `#include` statements:  These indicate dependencies and give clues about the file's purpose (e.g., `peerconnection`, `mediastream`, `platform/peerconnection`, `bindings/modules/v8`).
    * Class names: `RTCPeerConnectionHandler`, `Observer`, `ParsedSessionDescription`, `CreateSessionDescriptionRequest`, `WebRtcSetDescriptionObserverImpl`. These are key entities within the file.
    * WebRTC related namespaces and types: `webrtc::...`, `RTCSessionDescription...`, `RTCIceCandidate...`, `RTCRtpSender...`, `RTCRtpReceiver...`.
    * Threading and task management related elements: `base::SingleThreadTaskRunner`, `PostCrossThreadTask`, `base::WaitableEvent`.
    * Callbacks and observers:  The presence of `Observer` class and methods like `OnSuccess`, `OnFailure`, and various `On...Change` methods.
    * DOM/Blink specific types: `ExecutionContext`, `WebLocalFrame`.

3. **Deduce Core Functionality (Based on Keywords and Class Names):** From the initial scan, I could infer the following:
    * **Central Role:**  `RTCPeerConnectionHandler` is likely the core class, handling the main logic for WebRTC peer connections within the Blink rendering engine.
    * **WebRTC Interaction:** The file heavily interacts with the WebRTC native library (`third_party/webrtc`).
    * **Session Management:**  Classes like `ParsedSessionDescription`, `CreateSessionDescriptionRequest`, and `WebRtcSetDescriptionObserverImpl` suggest handling SDP (Session Description Protocol) for session negotiation (offers and answers).
    * **Event Handling:** The `Observer` class seems responsible for reacting to events from the native WebRTC layer and forwarding them to the Blink layer.
    * **Threading:** The code explicitly deals with threading, indicating that WebRTC operations might occur on a separate thread, and synchronization is necessary.

4. **Examine Key Classes and Methods in Detail:** I started to look at the purpose of the major classes and their key methods:
    * **`RTCPeerConnectionHandler`:** Its constructor, destructor, `Initialize`, `CreateOffer`, `CreateAnswer`, `SetLocalDescription`, `SetRemoteDescription`, `AddIceCandidate`, and methods related to adding/removing tracks and data channels. These methods directly map to the WebRTC API exposed to JavaScript.
    * **`Observer`:** Its role in receiving WebRTC native events and posting them to the main thread. The specific `On...` methods reveal the types of events handled (signaling changes, ICE candidate generation, data channel events, etc.).
    * **SDP related classes:** How they handle the creation, parsing, and application of session descriptions.

5. **Identify Relationships with Web Technologies:**  I looked for connections to JavaScript, HTML, and CSS:
    * **JavaScript:** The mention of `bindings/modules/v8` strongly suggests a direct interface with JavaScript APIs. The methods in `RTCPeerConnectionHandler` likely correspond to methods exposed in the JavaScript `RTCPeerConnection` interface.
    * **HTML:** While not directly manipulating HTML, the `RTCPeerConnection` functionality is triggered and used within the context of a web page loaded in an HTML document. The media streams involved could be connected to `<video>` or `<audio>` elements.
    * **CSS:**  Indirectly related. CSS can style the video elements displaying the media streams, but the `rtc_peer_connection_handler.cc` file doesn't directly deal with CSS.

6. **Infer Logic and Provide Examples:** I tried to reason about the internal logic:
    * **Offer/Answer flow:** How `CreateOffer` and `CreateAnswer` result in SDP, and how `SetLocalDescription` and `SetRemoteDescription` apply that SDP.
    * **ICE candidate handling:** How ICE candidates are generated and exchanged.
    * **Threading model:** The interaction between the main thread and the WebRTC signaling thread.
    * **Error handling:**  The use of `RTCError` and how failures are communicated back to JavaScript.

7. **Consider User/Programming Errors:** I thought about common mistakes developers might make when using the WebRTC API, such as incorrect SDP format, calling methods in the wrong order, or issues with media constraints.

8. **Trace User Operations:**  I traced back how a user action might lead to this code being executed, starting from a JavaScript call to `RTCPeerConnection`.

9. **Structure the Answer:** I organized my findings into the categories requested by the prompt: functionality, relationship with web technologies (with examples), logical reasoning (with hypothetical inputs/outputs), common errors, debugging clues, and a summary.

10. **Refine and Summarize:** I reviewed my analysis, ensuring clarity and accuracy. The summary focused on the core responsibility of the file: managing the lifecycle and operations of a WebRTC peer connection within the Blink rendering engine.

By following this systematic approach, I could effectively dissect the provided code snippet, even without having the complete file, and address all aspects of the prompt. The process involves a combination of code analysis, domain knowledge (WebRTC and Chromium), and logical deduction.
这是 `blink/renderer/modules/peerconnection/rtc_peer_connection_handler.cc` 文件的第一部分，主要负责 **管理和协调 WebRTC PeerConnection 的生命周期和核心功能**。 它的主要职责是作为 Blink 渲染引擎中 `RTCPeerConnection` JavaScript API 的底层实现，与底层的 WebRTC 本地库进行交互。

以下是它的功能归纳：

**核心功能：**

1. **WebRTC PeerConnection 生命周期管理:**
   - **初始化:** 负责创建和初始化底层的 WebRTC `PeerConnectionInterface` 对象。
   - **关闭和清理:**  提供关闭 PeerConnection 并释放相关资源的功能。
   - **事件监听:**  设置和处理来自底层 WebRTC 库的各种事件，例如：
     - 对等连接状态变化 (连接、断开等)
     - ICE 协商状态变化 (收集、完成等)
     - 新增/移除媒体流
     - 数据通道事件
     - 需要重新协商事件
     - ICE 候选者生成事件
     - ICE 候选者错误事件
   - **与 JavaScript 层交互:**  接收来自 JavaScript 的请求，并调用底层的 WebRTC 方法。

2. **SDP (Session Description Protocol) 处理:**
   - **创建 Offer 和 Answer:**  实现 `createOffer` 和 `createAnswer` 方法，调用底层 WebRTC 生成 SDP。
   - **设置本地和远端描述:** 实现 `setLocalDescription` 和 `setRemoteDescription` 方法，将 SDP 应用到本地和远端 PeerConnection。
   - **SDP 解析和转换:**  负责将 Blink 的 `RTCSessionDescription` 对象转换为底层 WebRTC 可以理解的格式，反之亦然。

3. **ICE (Interactive Connectivity Establishment) 处理:**
   - **添加 ICE 候选者:**  实现 `addIceCandidate` 方法，将远端收集到的 ICE 候选者添加到本地 PeerConnection。

4. **媒体流和轨道管理:**
   - **添加/移除媒体流和轨道:**  提供添加和移除本地媒体流和轨道的功能。
   - **RTP Sender 和 Receiver 管理:**  创建和管理 `RTCRtpSenderImpl` 和 `RTCRtpReceiverImpl` 对象，用于发送和接收媒体数据。
   - **RTP Transceiver 管理:**  创建和管理 `RTCRtpTransceiverPlatform` 对象，用于双向媒体传输。

5. **数据通道管理:**
   - **创建数据通道:**  实现 `createDataChannel` 方法，创建用于传输任意数据的通道。
   - **处理数据通道事件:**  接收并转发底层 WebRTC 数据通道的事件。

6. **统计信息获取:**
   - **获取统计信息:**  实现获取 PeerConnection 统计信息的功能。

7. **线程管理:**
   - **主线程和信令线程交互:**  由于 WebRTC 的某些操作需要在特定的线程上执行（例如信令线程），该文件负责在 Blink 的主线程和 WebRTC 的信令线程之间安全地传递任务和数据。

8. **功能开关和实验特性控制:**
   -  代码中包含一些 `#ifdef` 和特性开关，用于控制某些实验性功能或在特定构建配置下启用/禁用某些行为。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  `rtc_peer_connection_handler.cc` 是 `RTCPeerConnection` JavaScript API 的底层实现。当 JavaScript 代码调用 `RTCPeerConnection` 的方法（如 `createOffer()`, `setLocalDescription()`, `addTrack()` 等）时，这些调用最终会路由到 `rtc_peer_connection_handler.cc` 中的相应方法。

   **举例:**
   - **JavaScript 输入:**
     ```javascript
     const pc = new RTCPeerConnection();
     pc.createOffer()
       .then(offer => pc.setLocalDescription(offer));
     ```
   - **对应的 `rtc_peer_connection_handler.cc` 功能:**  `CreateOffer` 方法会被调用生成 SDP，然后 `SetLocalDescription` 方法会被调用来设置本地描述。

* **HTML:**  HTML 主要负责网页的结构。WebRTC 通常用于在网页中实现音视频通信或数据传输。HTML 中可以使用 `<video>` 或 `<audio>` 元素来显示接收到的媒体流。

   **举例:**
   - **HTML 元素:**
     ```html
     <video id="remoteVideo" autoplay></video>
     ```
   - **对应的 `rtc_peer_connection_handler.cc` 功能:**  当远端用户发送媒体流过来时，`rtc_peer_connection_handler.cc` 会创建 `RTCRtpReceiverImpl` 对象来接收数据，并将接收到的媒体轨道关联到 JavaScript 的 `MediaStreamTrack` 对象，JavaScript 代码可以将该轨道赋值给 `<video>` 元素的 `srcObject` 属性进行播放。

* **CSS:** CSS 用于网页的样式。虽然 CSS 不直接与 `rtc_peer_connection_handler.cc` 交互，但它可以用于美化显示 WebRTC 媒体流的 `<video>` 或 `<audio>` 元素。

**逻辑推理 (假设输入与输出):**

假设 JavaScript 代码调用 `createOffer()` 方法，并指定了一些约束：

* **假设输入:**  JavaScript 调用 `pc.createOffer({ offerToReceiveAudio: true, offerToReceiveVideo: true })`
* **对应的 `rtc_peer_connection_handler.cc` 内部处理:**
    1. `CreateOffer` 方法被调用。
    2. 根据提供的约束 (`offerToReceiveAudio: true`, `offerToReceiveVideo: true`)，配置底层的 WebRTC `PeerConnectionInterface` 的参数。
    3. 调用底层的 WebRTC `CreateOffer` 方法生成 SDP。
    4. 将生成的 SDP 转换为 Blink 的 `RTCSessionDescriptionPlatform` 对象。
* **假设输出:**  一个包含音视频媒体信息的 SDP 字符串，例如：
   ```sdp
   v=0
   o=- 12345 2 IN IP4 127.0.0.1
   s=
   c=IN IP4 0.0.0.0
   t=0 0
   m=audio 9 UDP/TLS/RTP/SAVPF 111
   a=rtpmap:111 opus/48000/2
   a=rtcp-fb:111 transport-cc
   m=video 9 UDP/TLS/RTP/SAVPF 96
   a=rtpmap:96 VP8/90000
   a=rtcp-fb:96 goog-remb
   ```
   这个 SDP 会通过 Promise 返回给 JavaScript。

**用户或编程常见的使用错误 (举例说明):**

1. **在 `setLocalDescription` 或 `setRemoteDescription` 中提供格式错误的 SDP:**
   - **错误场景:** JavaScript 代码尝试设置一个语法不正确的 SDP 字符串。
   - **`rtc_peer_connection_handler.cc` 中的处理:** `ParsedSessionDescription::Parse` 会尝试解析 SDP，如果解析失败，会触发错误回调，最终导致 JavaScript 的 Promise 被拒绝。
   - **用户错误信息:**  通常会收到一个错误信息，指示 SDP 的格式不正确。

2. **在 ICE 协商完成之前尝试发送数据:**
   - **错误场景:**  在 `iceConnectionState` 变为 'connected' 或 'completed' 之前，JavaScript 代码尝试通过数据通道发送数据。
   - **`rtc_peer_connection_handler.cc` 中的处理:** 底层的 WebRTC 可能会拒绝发送数据，或者数据可能会丢失。
   - **用户错误:**  数据发送可能失败，或者远端无法接收到数据。

3. **尝试添加与现有轨道具有相同 ID 的轨道:**
   - **错误场景:** JavaScript 代码尝试添加一个 `MediaStreamTrack`，其 ID 与已经添加到 PeerConnection 的轨道 ID 相同。
   - **`rtc_peer_connection_handler.cc` 中的处理:**  可能会阻止添加重复 ID 的轨道，并抛出错误或警告。

**用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户在网页上发起音视频通话或数据传输操作。** 例如，点击一个 "开始通话" 按钮。
2. **JavaScript 代码创建 `RTCPeerConnection` 对象。** `const pc = new RTCPeerConnection(configuration);`
3. **JavaScript 代码调用 `createOffer()` 或 `createAnswer()` 方法。** 这会导致 `RTCPeerConnectionHandler::CreateOffer` 或 `RTCPeerConnectionHandler::CreateAnswer` 方法被调用。
4. **JavaScript 代码调用 `setLocalDescription()` 或 `setRemoteDescription()` 方法，并传入 SDP。** 这会导致 `RTCPeerConnectionHandler::SetLocalDescription` 或 `RTCPeerConnectionHandler::SetRemoteDescription` 方法被调用。
5. **如果需要传输媒体，JavaScript 代码会调用 `addTrack()` 方法。** 这会导致 `RTCPeerConnectionHandler::AddTrack` 方法被调用。
6. **如果需要传输任意数据，JavaScript 代码会调用 `createDataChannel()` 方法。** 这会导致 `RTCPeerConnectionHandler::CreateDataChannel` 方法被调用。
7. **在 ICE 协商过程中，当本地收集到 ICE 候选者时，`Observer::OnIceCandidate` 方法会被调用。**
8. **当收到远端的 ICE 候选者时，JavaScript 代码会调用 `addIceCandidate()` 方法。** 这会导致 `RTCPeerConnectionHandler::AddIceCandidate` 方法被调用。
9. **当 PeerConnection 的状态发生变化时（例如，连接状态），`Observer` 类中的相应 `On...Change` 方法会被调用，并将事件传递回 JavaScript。**

在调试 WebRTC 相关问题时，开发者可以通过以下方式来追踪代码执行到 `rtc_peer_connection_handler.cc`：

* **设置断点:**  在 Chrome 的开发者工具中，可以在 `rtc_peer_connection_handler.cc` 的关键方法（例如 `CreateOffer`, `SetLocalDescription`, `AddIceCandidate` 等）设置断点，以便在代码执行到这些位置时暂停。
* **使用 `console.trace()`:** 在 JavaScript 代码中调用 `console.trace()` 可以打印出当前的调用栈，帮助开发者理解 JavaScript 代码是如何调用到 WebRTC API 的。
* **查看 `chrome://webrtc-internals/`:**  这个 Chrome 内部页面提供了详细的 WebRTC 运行状态信息，包括 PeerConnection 的事件日志、SDP 信息、ICE 候选者等，可以帮助理解 WebRTC 的内部工作流程。

**总结 (第 1 部分功能):**

`rtc_peer_connection_handler.cc` 的第一部分主要负责 `RTCPeerConnection` 的初始化、关闭、SDP 的创建和设置，以及 ICE 候选者的处理。它建立了 JavaScript `RTCPeerConnection` API 与底层 WebRTC 库之间的桥梁，是实现 WebRTC 功能的核心组件之一。它还负责处理一些基本的错误情况，并将状态变化通知给 JavaScript 层。

### 提示词
```
这是目录为blink/renderer/modules/peerconnection/rtc_peer_connection_handler.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/peerconnection/rtc_peer_connection_handler.h"

#include <string.h>

#include <functional>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "base/containers/contains.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/safe_conversions.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/thread_checker.h"
#include "base/trace_event/trace_event.h"
#include "build/chromecast_buildflags.h"
#include "media/base/media_switches.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_session_description_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_boolean_constrainbooleanparameters.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util.h"
#include "third_party/blink/renderer/modules/peerconnection/adapters/web_rtc_cross_thread_copier.h"
#include "third_party/blink/renderer/modules/peerconnection/peer_connection_dependency_factory.h"
#include "third_party/blink/renderer/modules/peerconnection/peer_connection_features.h"
#include "third_party/blink/renderer/modules/peerconnection/peer_connection_tracker.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_rtp_receiver_impl.h"
#include "third_party/blink/renderer/modules/peerconnection/speed_limit_uma_listener.h"
#include "third_party/blink/renderer/modules/peerconnection/webrtc_set_description_observer.h"
#include "third_party/blink/renderer/modules/webrtc/webrtc_audio_device_impl.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_track_platform.h"
#include "third_party/blink/renderer/platform/mediastream/webrtc_uma_histograms.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_answer_options_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_event_log_output_sink.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_event_log_output_sink_proxy.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_ice_candidate_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_offer_options_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_rtp_sender_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_rtp_transceiver_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_scoped_refptr_cross_thread_copier.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_session_description_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_session_description_request.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_stats.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_void_request.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/thread_safe_ref_counted.h"
#include "third_party/webrtc/api/data_channel_interface.h"
#include "third_party/webrtc/api/rtc_event_log_output.h"
#include "third_party/webrtc/api/units/time_delta.h"
#include "third_party/webrtc/pc/session_description.h"

using webrtc::DataChannelInterface;
using webrtc::IceCandidateInterface;
using webrtc::MediaStreamInterface;
using webrtc::PeerConnectionInterface;
using webrtc::PeerConnectionObserver;
using webrtc::StatsReport;
using webrtc::StatsReports;

namespace WTF {

template <>
struct CrossThreadCopier<scoped_refptr<DataChannelInterface>>
    : public CrossThreadCopierPassThrough<scoped_refptr<DataChannelInterface>> {
  STATIC_ONLY(CrossThreadCopier);
};

template <>
struct CrossThreadCopier<scoped_refptr<PeerConnectionInterface>>
    : public CrossThreadCopierPassThrough<
          scoped_refptr<PeerConnectionInterface>> {
  STATIC_ONLY(CrossThreadCopier);
};

template <>
struct CrossThreadCopier<rtc::scoped_refptr<webrtc::StatsObserver>>
    : public CrossThreadCopierPassThrough<
          rtc::scoped_refptr<webrtc::StatsObserver>> {
  STATIC_ONLY(CrossThreadCopier);
};

}  // namespace WTF

namespace blink {
namespace {

// Used to back histogram value of "WebRTC.PeerConnection.RtcpMux",
// so treat as append-only.
enum class RtcpMux { kDisabled, kEnabled, kNoMedia, kMax };

RTCSessionDescriptionPlatform* CreateWebKitSessionDescription(
    const std::string& sdp,
    const std::string& type) {
  return MakeGarbageCollected<RTCSessionDescriptionPlatform>(
      String::FromUTF8(type), String::FromUTF8(sdp));
}

RTCSessionDescriptionPlatform* CreateWebKitSessionDescription(
    const webrtc::SessionDescriptionInterface* native_desc) {
  if (!native_desc) {
    LOG(ERROR) << "Native session description is null.";
    return nullptr;
  }

  std::string sdp;
  if (!native_desc->ToString(&sdp)) {
    LOG(ERROR) << "Failed to get SDP string of native session description.";
    return nullptr;
  }

  return CreateWebKitSessionDescription(sdp, native_desc->type());
}

void RunClosureWithTrace(CrossThreadOnceClosure closure,
                         const char* trace_event_name) {
  TRACE_EVENT0("webrtc", trace_event_name);
  std::move(closure).Run();
}

void RunSynchronousOnceClosure(base::OnceClosure closure,
                               const char* trace_event_name,
                               base::WaitableEvent* event) {
  {
    TRACE_EVENT0("webrtc", trace_event_name);
    std::move(closure).Run();
  }
  event->Signal();
}

// Converter functions from Blink types to WebRTC types.

// Class mapping responses from calls to libjingle CreateOffer/Answer and
// the blink::RTCSessionDescriptionRequest.
class CreateSessionDescriptionRequest
    : public webrtc::CreateSessionDescriptionObserver {
 public:
  explicit CreateSessionDescriptionRequest(
      const scoped_refptr<base::SingleThreadTaskRunner>& main_thread,
      blink::RTCSessionDescriptionRequest* request,
      const base::WeakPtr<RTCPeerConnectionHandler>& handler,
      PeerConnectionTracker* tracker,
      PeerConnectionTracker::Action action)
      : main_thread_(main_thread),
        webkit_request_(request),
        handler_(handler),
        tracker_(tracker),
        action_(action) {}

  void OnSuccess(webrtc::SessionDescriptionInterface* desc) override {
    if (!main_thread_->BelongsToCurrentThread()) {
      PostCrossThreadTask(
          *main_thread_.get(), FROM_HERE,
          CrossThreadBindOnce(
              &CreateSessionDescriptionRequest::OnSuccess,
              rtc::scoped_refptr<CreateSessionDescriptionRequest>(this),
              CrossThreadUnretained(desc)));
      return;
    }

    auto tracker = tracker_.Lock();
    if (tracker && handler_) {
      std::string value;
      if (desc) {
        desc->ToString(&value);
        value = "type: " + desc->type() + ", sdp: " + value;
      }
      tracker->TrackSessionDescriptionCallback(
          handler_.get(), action_, "OnSuccess", String::FromUTF8(value));
      tracker->TrackSessionId(handler_.get(),
                              String::FromUTF8(desc->session_id()));
    }
    webkit_request_->RequestSucceeded(CreateWebKitSessionDescription(desc));
    webkit_request_ = nullptr;
    delete desc;
  }
  void OnFailure(webrtc::RTCError error) override {
    if (!main_thread_->BelongsToCurrentThread()) {
      PostCrossThreadTask(
          *main_thread_.get(), FROM_HERE,
          CrossThreadBindOnce(
              &CreateSessionDescriptionRequest::OnFailure,
              rtc::scoped_refptr<CreateSessionDescriptionRequest>(this),
              std::move(error)));
      return;
    }

    auto tracker = tracker_.Lock();
    if (handler_ && tracker) {
      tracker->TrackSessionDescriptionCallback(
          handler_.get(), action_, "OnFailure",
          String::FromUTF8(error.message()));
    }
    // TODO(hta): Convert CreateSessionDescriptionRequest.OnFailure
    webkit_request_->RequestFailed(error);
    webkit_request_ = nullptr;
  }

 protected:
  ~CreateSessionDescriptionRequest() override {
    // This object is reference counted and its callback methods |OnSuccess| and
    // |OnFailure| will be invoked on libjingle's signaling thread and posted to
    // the main thread. Since the main thread may complete before the signaling
    // thread has deferenced this object there is no guarantee that this object
    // is destructed on the main thread.
    DLOG_IF(ERROR, webkit_request_)
        << "CreateSessionDescriptionRequest not completed. Shutting down?";
  }

  const scoped_refptr<base::SingleThreadTaskRunner> main_thread_;
  Persistent<RTCSessionDescriptionRequest> webkit_request_;
  const base::WeakPtr<RTCPeerConnectionHandler> handler_;
  const CrossThreadWeakPersistent<PeerConnectionTracker> tracker_;
  PeerConnectionTracker::Action action_;
};

using RTCStatsReportCallbackInternal =
    CrossThreadOnceFunction<void(std::unique_ptr<RTCStatsReportPlatform>)>;

void GetRTCStatsOnSignalingThread(
    const scoped_refptr<base::SingleThreadTaskRunner>& main_thread,
    rtc::scoped_refptr<webrtc::PeerConnectionInterface> native_peer_connection,
    RTCStatsReportCallbackInternal callback) {
  TRACE_EVENT0("webrtc", "GetRTCStatsOnSignalingThread");
  native_peer_connection->GetStats(
      CreateRTCStatsCollectorCallback(
          main_thread, ConvertToBaseOnceCallback(std::move(callback)))
          .get());
}

std::set<RTCPeerConnectionHandler*>* GetPeerConnectionHandlers() {
  static std::set<RTCPeerConnectionHandler*>* handlers =
      new std::set<RTCPeerConnectionHandler*>();
  return handlers;
}

// Counts the number of senders that have |stream_id| as an associated stream.
size_t GetLocalStreamUsageCount(
    const Vector<std::unique_ptr<blink::RTCRtpSenderImpl>>& rtp_senders,
    const std::string& stream_id) {
  size_t usage_count = 0;
  for (const auto& sender : rtp_senders) {
    for (const auto& sender_stream_id : sender->state().stream_ids()) {
      if (sender_stream_id == stream_id) {
        ++usage_count;
        break;
      }
    }
  }
  return usage_count;
}

MediaStreamTrackMetrics::Kind MediaStreamTrackMetricsKind(
    const MediaStreamComponent* component) {
  return component->GetSourceType() == MediaStreamSource::kTypeAudio
             ? MediaStreamTrackMetrics::Kind::kAudio
             : MediaStreamTrackMetrics::Kind::kVideo;
}

}  // namespace

// Implementation of ParsedSessionDescription
ParsedSessionDescription::ParsedSessionDescription(const String& sdp_type,
                                                   const String& sdp)
    : type_(sdp_type), sdp_(sdp) {}

// static
ParsedSessionDescription ParsedSessionDescription::Parse(
    const RTCSessionDescriptionInit* session_description_init) {
  ParsedSessionDescription temp(
      session_description_init->hasType()
          ? session_description_init->type().AsString()
          : String(),
      session_description_init->sdp());
  temp.DoParse();
  return temp;
}

// static
ParsedSessionDescription ParsedSessionDescription::Parse(
    const RTCSessionDescriptionPlatform* session_description_platform) {
  ParsedSessionDescription temp(session_description_platform->GetType(),
                                session_description_platform->Sdp());
  temp.DoParse();
  return temp;
}

// static
ParsedSessionDescription ParsedSessionDescription::Parse(const String& sdp_type,
                                                         const String& sdp) {
  ParsedSessionDescription temp(sdp_type, sdp);
  temp.DoParse();
  return temp;
}

void ParsedSessionDescription::DoParse() {
  std::optional<webrtc::SdpType> maybe_type =
      webrtc::SdpTypeFromString(type_.Utf8().c_str());
  if (!maybe_type.has_value()) {
    description_.reset();
    return;
  }
  description_ = webrtc::CreateSessionDescription(*maybe_type,
                                                  sdp_.Utf8().c_str(), &error_);
}

// Processes the resulting state changes of a SetLocalDescription() or
// SetRemoteDescription() call.
class RTCPeerConnectionHandler::WebRtcSetDescriptionObserverImpl
    : public WebRtcSetDescriptionObserver {
 public:
  WebRtcSetDescriptionObserverImpl(
      base::WeakPtr<RTCPeerConnectionHandler> handler,
      blink::RTCVoidRequest* web_request,
      PeerConnectionTracker* tracker,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      PeerConnectionTracker::Action action,
      bool is_rollback)
      : handler_(handler),
        main_thread_(task_runner),
        web_request_(web_request),
        tracker_(tracker),
        action_(action),
        is_rollback_(is_rollback) {}

  void OnSetDescriptionComplete(
      webrtc::RTCError error,
      WebRtcSetDescriptionObserver::States states) override {
    auto tracker = tracker_.Lock();
    if (!error.ok()) {
      if (tracker && handler_) {
        tracker->TrackSessionDescriptionCallback(
            handler_.get(), action_, "OnFailure",
            String::FromUTF8(error.message()));
      }
      web_request_->RequestFailed(error);
      web_request_ = nullptr;
      return;
    }

    // Copy/move some of the states to be able to use them after moving
    // |state| below.
    webrtc::PeerConnectionInterface::SignalingState signaling_state =
        states.signaling_state;
    auto pending_local_description =
        std::move(states.pending_local_description);
    auto current_local_description =
        std::move(states.current_local_description);
    auto pending_remote_description =
        std::move(states.pending_remote_description);
    auto current_remote_description =
        std::move(states.current_remote_description);

    // Track result in chrome://webrtc-internals/.
    if (tracker && handler_) {
      StringBuilder value;
      if (action_ ==
          PeerConnectionTracker::kActionSetLocalDescriptionImplicit) {
        webrtc::SessionDescriptionInterface* created_session_description =
            nullptr;
        // Deduce which SDP was created based on signaling state.
        if (signaling_state ==
                webrtc::PeerConnectionInterface::kHaveLocalOffer &&
            pending_local_description) {
          created_session_description = pending_local_description.get();
        } else if (signaling_state ==
                       webrtc::PeerConnectionInterface::kStable &&
                   current_local_description) {
          created_session_description = current_local_description.get();
        }
        RTC_DCHECK(created_session_description);
        std::string sdp;
        created_session_description->ToString(&sdp);
        value.Append("type: ");
        value.Append(
            webrtc::SdpTypeToString(created_session_description->GetType()));
        value.Append(", sdp: ");
        value.Append(sdp.c_str());
      }
      tracker->TrackSessionDescriptionCallback(handler_.get(), action_,
                                               "OnSuccess", value.ToString());
      handler_->TrackSignalingChange(signaling_state);
    }

    if (handler_) {
      handler_->OnSessionDescriptionsUpdated(
          std::move(pending_local_description),
          std::move(current_local_description),
          std::move(pending_remote_description),
          std::move(current_remote_description));
    }

    // This fires JS events and could cause |handler_| to become null.
    ProcessStateChanges(std::move(states));
    ResolvePromise();
  }

 private:
  ~WebRtcSetDescriptionObserverImpl() override {}

  void ResolvePromise() {
    web_request_->RequestSucceeded();
    web_request_ = nullptr;
  }

  void ProcessStateChanges(WebRtcSetDescriptionObserver::States states) {
    if (handler_) {
      handler_->OnModifySctpTransport(std::move(states.sctp_transport_state));
    }
    // Since OnSessionDescriptionsUpdated can fire events, it may cause
    // garbage collection. Ensure that handler_ is still valid.
    if (handler_ && !handler_->is_unregistered_) {
      handler_->OnModifyTransceivers(
          states.signaling_state, std::move(states.transceiver_states),
          action_ == PeerConnectionTracker::kActionSetRemoteDescription,
          is_rollback_);
    }
  }

  base::WeakPtr<RTCPeerConnectionHandler> handler_;
  scoped_refptr<base::SequencedTaskRunner> main_thread_;
  Persistent<blink::RTCVoidRequest> web_request_;
  CrossThreadWeakPersistent<PeerConnectionTracker> tracker_;
  PeerConnectionTracker::Action action_;
  bool is_rollback_;
};

// Receives notifications from a PeerConnection object about state changes. The
// callbacks we receive here come on the webrtc signaling thread, so this class
// takes care of delivering them to an RTCPeerConnectionHandler instance on the
// main thread. In order to do safe PostTask-ing, the class is reference counted
// and checks for the existence of the RTCPeerConnectionHandler instance before
// delivering callbacks on the main thread.
class RTCPeerConnectionHandler::Observer
    : public GarbageCollected<RTCPeerConnectionHandler::Observer>,
      public PeerConnectionObserver,
      public RtcEventLogOutputSink {
 public:
  Observer(const base::WeakPtr<RTCPeerConnectionHandler>& handler,
           scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : handler_(handler), main_thread_(task_runner) {}
  ~Observer() override {
    // `signaling_thread_` may be null in some testing-only environments.
    if (!signaling_thread_) {
      return;
    }
    // To avoid a PROXY block-invoke to ~webrtc::PeerConnection in the event
    // that `native_peer_connection_` was the last reference, we move it to the
    // signaling thread in a PostTask.
    signaling_thread_->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](rtc::scoped_refptr<webrtc::PeerConnectionInterface> pc) {
              // The binding releases `pc` on the signaling thread as
              // this method goes out of scope.
            },
            std::move(native_peer_connection_)));
  }

  void Initialize(
      scoped_refptr<base::SingleThreadTaskRunner> signaling_thread) {
    DCHECK(main_thread_->BelongsToCurrentThread());
    DCHECK(!native_peer_connection_);
    DCHECK(handler_);
    native_peer_connection_ = handler_->native_peer_connection_;
    DCHECK(native_peer_connection_);
    signaling_thread_ = std::move(signaling_thread);
  }

  // When an RTC event log is sent back from PeerConnection, it arrives here.
  void OnWebRtcEventLogWrite(const WTF::Vector<uint8_t>& output) override {
    if (!main_thread_->BelongsToCurrentThread()) {
      PostCrossThreadTask(
          *main_thread_.get(), FROM_HERE,
          CrossThreadBindOnce(
              &RTCPeerConnectionHandler::Observer::OnWebRtcEventLogWrite,
              WrapCrossThreadPersistent(this), output));
    } else if (handler_) {
      handler_->OnWebRtcEventLogWrite(output);
    }
  }

  void Trace(Visitor* visitor) const override {}

 protected:
  // TODO(hbos): Remove once no longer mandatory to implement.
  void OnSignalingChange(PeerConnectionInterface::SignalingState) override {}
  void OnAddStream(rtc::scoped_refptr<MediaStreamInterface>) override {}
  void OnRemoveStream(rtc::scoped_refptr<MediaStreamInterface>) override {}

  void OnDataChannel(
      rtc::scoped_refptr<DataChannelInterface> data_channel) override {
    PostCrossThreadTask(
        *main_thread_.get(), FROM_HERE,
        CrossThreadBindOnce(
            &RTCPeerConnectionHandler::Observer::OnDataChannelImpl,
            WrapCrossThreadPersistent(this), data_channel));
  }

  void OnNegotiationNeededEvent(uint32_t event_id) override {
    if (!main_thread_->BelongsToCurrentThread()) {
      PostCrossThreadTask(
          *main_thread_.get(), FROM_HERE,
          CrossThreadBindOnce(
              &RTCPeerConnectionHandler::Observer::OnNegotiationNeededEvent,
              WrapCrossThreadPersistent(this), event_id));
    } else if (handler_) {
      handler_->OnNegotiationNeededEvent(event_id);
    }
  }

  void OnIceConnectionChange(
      PeerConnectionInterface::IceConnectionState new_state) override {}
  void OnStandardizedIceConnectionChange(
      PeerConnectionInterface::IceConnectionState new_state) override {
    if (!main_thread_->BelongsToCurrentThread()) {
      PostCrossThreadTask(
          *main_thread_.get(), FROM_HERE,
          CrossThreadBindOnce(&RTCPeerConnectionHandler::Observer::
                                  OnStandardizedIceConnectionChange,
                              WrapCrossThreadPersistent(this), new_state));
    } else if (handler_) {
      handler_->OnIceConnectionChange(new_state);
    }
  }

  void OnConnectionChange(
      PeerConnectionInterface::PeerConnectionState new_state) override {
    if (!main_thread_->BelongsToCurrentThread()) {
      PostCrossThreadTask(
          *main_thread_.get(), FROM_HERE,
          CrossThreadBindOnce(
              &RTCPeerConnectionHandler::Observer::OnConnectionChange,
              WrapCrossThreadPersistent(this), new_state));
    } else if (handler_) {
      handler_->OnConnectionChange(new_state);
    }
  }

  void OnIceGatheringChange(
      PeerConnectionInterface::IceGatheringState new_state) override {
    if (!main_thread_->BelongsToCurrentThread()) {
      PostCrossThreadTask(
          *main_thread_.get(), FROM_HERE,
          CrossThreadBindOnce(
              &RTCPeerConnectionHandler::Observer::OnIceGatheringChange,
              WrapCrossThreadPersistent(this), new_state));
    } else if (handler_) {
      handler_->OnIceGatheringChange(new_state);
    }
  }

  void OnIceCandidate(const IceCandidateInterface* candidate) override {
    DCHECK(native_peer_connection_);
    std::string sdp;
    if (!candidate->ToString(&sdp)) {
      NOTREACHED() << "OnIceCandidate: Could not get SDP string.";
    }
    // The generated candidate may have been added to the pending or current
    // local description, take a snapshot and surface them to the main thread.
    // Remote descriptions are also surfaced because
    // OnSessionDescriptionsUpdated() requires all four as arguments.
    std::unique_ptr<webrtc::SessionDescriptionInterface>
        pending_local_description = CopySessionDescription(
            native_peer_connection_->pending_local_description());
    std::unique_ptr<webrtc::SessionDescriptionInterface>
        current_local_description = CopySessionDescription(
            native_peer_connection_->current_local_description());
    std::unique_ptr<webrtc::SessionDescriptionInterface>
        pending_remote_description = CopySessionDescription(
            native_peer_connection_->pending_remote_description());
    std::unique_ptr<webrtc::SessionDescriptionInterface>
        current_remote_description = CopySessionDescription(
            native_peer_connection_->current_remote_description());

    PostCrossThreadTask(
        *main_thread_.get(), FROM_HERE,
        CrossThreadBindOnce(
            &RTCPeerConnectionHandler::Observer::OnIceCandidateImpl,
            WrapCrossThreadPersistent(this), String::FromUTF8(sdp),
            String::FromUTF8(candidate->sdp_mid()),
            candidate->sdp_mline_index(), candidate->candidate().component(),
            candidate->candidate().address().family(),
            String::FromUTF8(candidate->candidate().username()),
            String::FromUTF8(candidate->server_url()),
            std::move(pending_local_description),
            std::move(current_local_description),
            std::move(pending_remote_description),
            std::move(current_remote_description)));
  }

  void OnIceCandidateError(const std::string& address,
                           int port,
                           const std::string& url,
                           int error_code,
                           const std::string& error_text) override {
    PostCrossThreadTask(
        *main_thread_.get(), FROM_HERE,
        CrossThreadBindOnce(
            &RTCPeerConnectionHandler::Observer::OnIceCandidateErrorImpl,
            WrapCrossThreadPersistent(this),
            port ? String::FromUTF8(address) : String(),
            static_cast<uint16_t>(port),
            String::Format("%s:%d", address.c_str(), port),
            String::FromUTF8(url), error_code, String::FromUTF8(error_text)));
  }

  void OnDataChannelImpl(rtc::scoped_refptr<DataChannelInterface> channel) {
    DCHECK(main_thread_->BelongsToCurrentThread());
    if (handler_)
      handler_->OnDataChannel(channel);
  }

  void OnIceCandidateImpl(const String& sdp,
                          const String& sdp_mid,
                          int sdp_mline_index,
                          int component,
                          int address_family,
                          const String& username_fragment,
                          const String& url,
                          std::unique_ptr<webrtc::SessionDescriptionInterface>
                              pending_local_description,
                          std::unique_ptr<webrtc::SessionDescriptionInterface>
                              current_local_description,
                          std::unique_ptr<webrtc::SessionDescriptionInterface>
                              pending_remote_description,
                          std::unique_ptr<webrtc::SessionDescriptionInterface>
                              current_remote_description) {
    DCHECK(main_thread_->BelongsToCurrentThread());
    if (handler_) {
      handler_->OnSessionDescriptionsUpdated(
          std::move(pending_local_description),
          std::move(current_local_description),
          std::move(pending_remote_description),
          std::move(current_remote_description));
    }
    // Since OnSessionDescriptionsUpdated can fire events, it may cause
    // garbage collection. Ensure that handler_ is still valid.
    if (handler_) {
      handler_->OnIceCandidate(sdp, sdp_mid, sdp_mline_index, component,
                               address_family, username_fragment, url);
    }
  }

  void OnIceCandidateErrorImpl(const String& address,
                               int port,
                               const String& host_candidate,
                               const String& url,
                               int error_code,
                               const String& error_text) {
    DCHECK(main_thread_->BelongsToCurrentThread());
    if (handler_) {
      handler_->OnIceCandidateError(
          address,
          port ? std::optional<uint16_t>(static_cast<uint16_t>(port))
               : std::nullopt,
          host_candidate, url, error_code, error_text);
    }
  }

  void OnInterestingUsage(int usage_pattern) override {
    PostCrossThreadTask(
        *main_thread_.get(), FROM_HERE,
        CrossThreadBindOnce(
            &RTCPeerConnectionHandler::Observer::OnInterestingUsageImpl,
            WrapCrossThreadPersistent(this), usage_pattern));
  }

  void OnInterestingUsageImpl(int usage_pattern) {
    DCHECK(main_thread_->BelongsToCurrentThread());
    if (handler_) {
      handler_->OnInterestingUsage(usage_pattern);
    }
  }

 private:
  const base::WeakPtr<RTCPeerConnectionHandler> handler_;
  const scoped_refptr<base::SingleThreadTaskRunner> main_thread_;
  // The rest of the members are set at Initialize() but are otherwise constant
  // until destruction.
  scoped_refptr<base::SingleThreadTaskRunner> signaling_thread_;
  // A copy of |handler_->native_peer_connection_| for use on the WebRTC
  // signaling thread.
  rtc::scoped_refptr<webrtc::PeerConnectionInterface> native_peer_connection_;
};

RTCPeerConnectionHandler::RTCPeerConnectionHandler(
    RTCPeerConnectionHandlerClient* client,
    blink::PeerConnectionDependencyFactory* dependency_factory,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    bool encoded_insertable_streams)
    : client_(client),
      dependency_factory_(dependency_factory),
      track_adapter_map_(
          base::MakeRefCounted<blink::WebRtcMediaStreamTrackAdapterMap>(
              dependency_factory_,
              task_runner)),
      encoded_insertable_streams_(encoded_insertable_streams),
      task_runner_(std::move(task_runner)) {
  CHECK(client_);

  GetPeerConnectionHandlers()->insert(this);
}

// Constructor to be used for creating mocks only.
RTCPeerConnectionHandler::RTCPeerConnectionHandler(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : is_unregistered_(true),  // Avoid CloseAndUnregister in destructor
      task_runner_(std::move(task_runner)) {}

RTCPeerConnectionHandler::~RTCPeerConnectionHandler() {
  if (!is_unregistered_) {
    CloseAndUnregister();
  }
  // Delete RTP Media API objects that may have references to the native peer
  // connection.
  rtp_senders_.clear();
  rtp_receivers_.clear();
  rtp_transceivers_.clear();
  // `signaling_thread_` may be null in some testing-only environments.
  if (!signaling_thread_) {
    return;
  }
  // To avoid a PROXY block-invoke to ~webrtc::PeerConnection in the event
  // that `native_peer_connection_` was the last reference, we move it to the
  // signaling thread in a PostTask.
  signaling_thread_->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](rtc::scoped_refptr<webrtc::PeerConnectionInterface> pc) {
            // The binding releases `pc` on the signaling thread as
            // this method goes out of scope.
          },
          std::move(native_peer_connection_)));
}

void RTCPeerConnectionHandler::CloseAndUnregister() {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  Close();

  GetPeerConnectionHandlers()->erase(this);
  if (peer_connection_tracker_)
    peer_connection_tracker_->UnregisterPeerConnection(this);

  // Clear the pointer to client_ so that it does not interfere with
  // garbage collection.
  client_ = nullptr;
  is_unregistered_ = true;

  // Reset the `PeerConnectionDependencyFactory` so we don't prevent it from
  // being garbage-collected.
  dependency_factory_ = nullptr;
}

bool RTCPeerConnectionHandler::Initialize(
    ExecutionContext* context,
    const webrtc::PeerConnectionInterface::RTCConfiguration&
        server_configuration,
    WebLocalFrame* frame,
    ExceptionState& exception_state,
    RTCRtpTransport* rtp_transport) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  DCHECK(dependency_factory_);

  CHECK(!initialize_called_);
  initialize_called_ = true;

  // Prevent garbage collection of client_ during processing.
  auto* client_on_stack = client_.Get();
  if (!client_on_stack) {
    return false;
  }

  DCHECK(frame);
  frame_ = frame;
  peer_connection_tracker_ = PeerConnectionTracker::From(*frame);

  configuration_ = server_configuration;

  // Choose between RTC smoothness algorithm and prerenderer smoothing.
  // Prerenderer smoothing is turned on if RTC smoothness is turned off.
  configuration_.set_prerenderer_smoothing(
      !blink::Platform::Current()->RTCSmoothnessAlgorithmEnabled());

  configuration_.set_experiment_cpu_load_estimator(true);

  // Configure optional SRTP configurations enabled via the command line.
  configuration_.crypto_options = webrtc::CryptoOptions{};
  configuration_.crypto_options->srtp.enable_gcm_crypto_suites = true;
  configuration_.crypto_options->srtp.enable_encrypted_rtp_header_extensions =
      base::FeatureList::IsEnabled(kWebRtcEncryptedRtpHeaderExtensions);
  configuration_.enable
```