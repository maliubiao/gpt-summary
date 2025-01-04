Response:
Let's break down the thought process for analyzing this C++ file and generating the answer.

1. **Understand the Goal:** The core request is to understand the functionality of `rtc_rtp_sender_impl.cc` within the Chromium Blink engine, particularly its connections to JavaScript, HTML, and CSS, potential errors, and debugging context.

2. **Initial Scan and Keywords:** Quickly skim the file, looking for key terms related to WebRTC, like "RTP," "sender," "track," "DTMF," "parameters," "stats," "stream," "audio," "video," "transformer," "PeerConnection," and the namespaces (`blink`, `webrtc`). This gives a high-level idea of the file's purpose.

3. **Identify Core Classes:** Notice the primary class `RTCRtpSenderImpl` and its internal implementation class `RTCRtpSenderImpl::RTCRtpSenderInternal`. This suggests a pattern of public interface and internal workings. Also, observe the `RtpSenderState` class, which likely manages the state of the RTP sender.

4. **Analyze `RTCRtpSenderImpl`'s Public Methods:** Go through the public methods of `RTCRtpSenderImpl` and try to infer their functionality from their names and parameters:
    * `ShallowCopy()`: Likely creates a copy of the object.
    * `Id()`: Returns an identifier, probably for internal tracking.
    * `DtlsTransport()` and `DtlsTransportInformation()`: Deal with DTLS transport information, related to secure communication.
    * `Track()`: Returns the associated media track.
    * `StreamIds()`: Returns the IDs of the associated media streams.
    * `ReplaceTrack()`:  Changes the media track being sent.
    * `GetDtmfSender()`:  Provides access to a DTMF sender (for sending telephone tones).
    * `GetParameters()`: Retrieves the current RTP parameters (like codecs, bitrate).
    * `SetParameters()`: Modifies the RTP parameters.
    * `GetStats()`:  Fetches statistics about the RTP stream.
    * `SetStreams()`:  Associates the sender with specific media streams.
    * `RemoveFromPeerConnection()`: Stops the sender and removes it from the peer connection.
    * `GetEncodedAudioStreamTransformer()` and `GetEncodedVideoStreamTransformer()`: Access interfaces for processing encoded audio/video.

5. **Analyze `RTCRtpSenderImpl::RTCRtpSenderInternal`:** This class seems to handle the actual WebRTC API calls. Notice the use of `webrtc::RtpSenderInterface`. Pay attention to how methods are dispatched to the signaling thread using `PostCrossThreadTask`. This is crucial for understanding the threading model.

6. **Focus on Interactions with Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** Recognize that `RTCRtpSenderImpl` is a C++ implementation of a WebRTC API component. JavaScript uses this API. Think about which JavaScript APIs would interact with it: `RTCPeerConnection.addTrack()`, `RTCPeerConnection.removeTrack()`, `RTCRtpSender.replaceTrack()`, `RTCRtpSender.getStats()`, `RTCRtpSender.getParameters()`, `RTCRtpSender.setParameters()`, `RTCRtpSender.getDtmfSender()`.
    * **HTML:**  HTML provides the `<video>` and `<audio>` elements where the received media streams are rendered. The *source* of the media being sent by `RTCRtpSenderImpl` often comes from user interaction with the browser (e.g., webcam access).
    * **CSS:** CSS styles the presentation of the `<video>` and `<audio>` elements. While `rtc_rtp_sender_impl.cc` doesn't directly *interact* with CSS, its output (the media stream) *is* displayed based on CSS rules.

7. **Identify Potential User/Programming Errors:** Think about common mistakes developers make when using the WebRTC API. This often involves incorrect usage of asynchronous operations, trying to modify things at the wrong time, or providing invalid parameters. Focus on the methods that involve user interaction or configuration (like `ReplaceTrack` and `SetParameters`).

8. **Consider the Debugging Context:**  Imagine a scenario where something goes wrong with a WebRTC application. How might a developer end up looking at this specific file?  Think about the sequence of user actions and the corresponding API calls that would lead to this code being executed. Focus on user actions that initiate media sending or modify the media stream.

9. **Structure the Answer:** Organize the findings into clear sections as requested:
    * **Functionality:**  Provide a concise overview of the file's purpose.
    * **Relationship to Web Technologies:**  Give specific examples of how the C++ code relates to JavaScript, HTML, and CSS.
    * **Logical Reasoning (if applicable):**  While this file doesn't contain complex *business logic*,  the threading model and the passing of data between threads can be considered a form of logical flow. Demonstrate how a JavaScript call might trigger actions in this C++ code.
    * **User/Programming Errors:**  Provide concrete examples of common mistakes.
    * **User Operations and Debugging:**  Describe a step-by-step user scenario that could lead to investigating this file.

10. **Refine and Review:** Read through the generated answer, ensuring clarity, accuracy, and completeness. Check for any missing information or areas that could be explained better. For instance, explicitly mention the signaling thread and its role in WebRTC. Ensure the examples are relevant and easy to understand. Make sure to connect the C++ code to the higher-level JavaScript API.

This structured approach, starting with a broad overview and progressively diving into details, helps to effectively analyze complex source code and address the specific requirements of the request. The key is to connect the low-level implementation details to the higher-level concepts of web development and user interaction.
好的，让我们来分析一下 `blink/renderer/modules/peerconnection/rtc_rtp_sender_impl.cc` 这个文件。

**功能概述:**

`rtc_rtp_sender_impl.cc` 文件实现了 Chromium Blink 引擎中 `RTCRtpSender` 接口的具体功能。 `RTCRtpSender` 接口代表了一个 **WebRTC RTP 发送器**，负责将本地的媒体流（音频或视频）通过 RTP 协议发送到远程的 PeerConnection 对等端。

更具体地说，这个文件主要负责以下几个方面：

1. **管理 RTP 发送器的状态:**  维护发送器的内部状态，例如关联的媒体轨道（`MediaStreamTrack`）、RTP 参数（编解码器、比特率等）、以及所属的媒体流 ID。`RtpSenderState` 类负责存储这些状态。
2. **与 WebRTC 底层交互:**  通过 `webrtc::RtpSenderInterface` 与底层的 WebRTC 引擎进行通信，执行诸如替换发送的媒体轨道、获取和设置 RTP 参数、获取统计信息等操作。
3. **处理媒体轨道:**  管理与发送器关联的 `MediaStreamTrack`。当需要替换发送的轨道时，它会更新内部状态并通知底层的 WebRTC 引擎。
4. **管理 DTMF 发送:**  支持通过 `RtcDtmfSenderHandler` 发送 DTMF（双音多频）信号，这通常用于电话呼叫场景。
5. **处理 RTP 参数:**  允许 JavaScript 代码获取和设置 RTP 发送器的参数，例如编解码器配置、比特率控制等。这些操作最终会传递到底层的 WebRTC 引擎。
6. **获取统计信息:**  提供获取 RTP 发送器相关统计信息的能力，例如发送的包数量、字节数、丢包率等。这些信息对于监控和调试 WebRTC 连接非常重要。
7. **管理媒体流 ID:**  维护与发送器关联的媒体流 ID 列表。
8. **处理可插入的媒体流 (Encoded Transform):**  支持通过 `RTCEncodedAudioStreamTransformer` 和 `RTCEncodedVideoStreamTransformer` 对发送前的编码后的音频和视频流进行自定义处理。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`rtc_rtp_sender_impl.cc` 文件本身是用 C++ 编写的，属于浏览器引擎的底层实现。它不直接涉及 HTML 和 CSS 的解析和渲染。但是，它与 JavaScript 的 WebRTC API 有着密切的联系。JavaScript 代码通过 WebRTC API 来操作 RTP 发送器，而这些操作最终会调用到这个文件中的 C++ 代码。

**JavaScript 交互举例:**

假设有一个 JavaScript 代码片段，用于通过 `RTCPeerConnection` 发送本地视频流：

```javascript
navigator.mediaDevices.getUserMedia({ video: true })
  .then(stream => {
    const pc = new RTCPeerConnection();
    const videoTrack = stream.getVideoTracks()[0];
    const sender = pc.addTrack(videoTrack, stream); //  这里会创建一个 RTCRtpSenderImpl 实例

    // 获取 RTP 发送器的参数
    sender.getParameters().then(params => {
      console.log("RTP Parameters:", params);
    });

    // 替换发送的视频轨道
    navigator.mediaDevices.getUserMedia({ video: true })
      .then(newStream => {
        const newVideoTrack = newStream.getVideoTracks()[0];
        sender.replaceTrack(newVideoTrack); //  这个操作会调用 rtc_rtp_sender_impl.cc 中的 ReplaceTrack 方法
      });

    // 设置 RTP 发送器的参数 (例如修改编码器的最大比特率)
    const newParams = sender.getParameters();
    newParams.encodings[0].maxBitrate = 1000000; // 1 Mbps
    sender.setParameters(newParams); // 这个操作会调用 rtc_rtp_sender_impl.cc 中的 SetParameters 方法

    // 获取 RTP 发送器的统计信息
    pc.getStats(sender).then(stats => {
      stats.forEach(report => {
        if (report.type === 'outbound-rtp') {
          console.log("Outbound RTP Stats:", report);
        }
      });
    });
  });
```

在这个例子中：

* `pc.addTrack(videoTrack, stream)`:  当 JavaScript 调用 `addTrack` 方法时，Blink 引擎会创建一个与该轨道关联的 `RTCRtpSenderImpl` 实例。
* `sender.getParameters()`:  JavaScript 调用 `getParameters` 方法会最终调用 `rtc_rtp_sender_impl.cc` 中的 `GetParameters` 方法，获取当前的 RTP 参数。
* `sender.replaceTrack(newVideoTrack)`:  JavaScript 调用 `replaceTrack` 方法会触发 `rtc_rtp_sender_impl.cc` 中的 `ReplaceTrack` 方法，替换正在发送的媒体轨道。
* `sender.setParameters(newParams)`: JavaScript 调用 `setParameters` 方法会调用 `rtc_rtp_sender_impl.cc` 中的 `SetParameters` 方法，更新 RTP 参数。
* `pc.getStats(sender)`: JavaScript 调用 `getStats` 方法并传入 `RTCRtpSender` 对象，会导致 `rtc_rtp_sender_impl.cc` 中的 `GetStats` 方法被调用，从而获取发送器的统计信息。

**HTML 和 CSS 关系举例:**

HTML 中的 `<video>` 或 `<audio>` 元素用于展示接收到的媒体流。虽然 `rtc_rtp_sender_impl.cc` 负责 *发送* 媒体，但它发送的媒体最终会在远程对等端的浏览器中被解码并渲染到 HTML 元素上。CSS 则用于控制这些元素的样式和布局。

例如，一个简单的 HTML 结构：

```html
<!DOCTYPE html>
<html>
<head>
  <title>WebRTC Example</title>
  <style>
    video {
      width: 640px;
      height: 480px;
      border: 1px solid black;
    }
  </style>
</head>
<body>
  <video id="remoteVideo" autoplay playsinline></video>
  <script src="webrtc_script.js"></script>
</body>
</html>
```

在这个例子中，`rtc_rtp_sender_impl.cc` 负责发送本地媒体流。当远程对等端接收到这个流并通过 `RTCPeerConnection` 将其绑定到 `<video id="remoteVideo">` 元素时，这个视频元素就会显示发送端的视频内容。 CSS 中定义的 `video` 样式会决定视频元素的尺寸和边框。

**逻辑推理和假设输入输出:**

假设 JavaScript 代码调用了 `sender.replaceTrack(newVideoTrack)`：

* **假设输入:**
    * `this`: 指向当前的 `RTCRtpSenderImpl` 对象。
    * `with_track`: 指向 `newVideoTrack` 对应的 `MediaStreamComponent` 实例的指针。
    * `request`: 指向一个 `RTCVoidRequest` 对象，用于异步操作的回调。
* **逻辑推理:**
    1. `ReplaceTrack` 方法首先会将 `MediaStreamComponent` 转换为底层的 `webrtc::MediaStreamTrackInterface`。
    2. 然后，它会调用 `webrtc_sender_->SetTrack(webrtc_track)`，将新的轨道设置到底层的 WebRTC 发送器。这个操作通常发生在信令线程。
    3. 操作完成后，会调用回调函数 `OnReplaceTrackCompleted`，并将操作结果（成功或失败）传递给它。
* **预期输出:**
    * 如果替换成功，`request->RequestSucceeded()` 会被调用。
    * 如果替换失败（例如，发送器已经停止），`request->RequestFailed()` 会被调用，并带有 `webrtc::RTCError` 对象，指示错误类型。

**用户或编程常见的使用错误:**

1. **在连接建立之前或之后错误地调用 `replaceTrack`:** 用户可能会在 `RTCPeerConnection` 的连接状态不合适的时候尝试替换轨道，导致操作失败。例如，在 `iceGatheringState` 为 "gathering" 状态时进行替换可能导致问题。
2. **尝试替换为不兼容的轨道类型:**  例如，尝试用音频轨道替换视频轨道。
3. **在 `setParameters` 中提供无效的参数值:**  例如，设置超出范围的比特率或不支持的编解码器参数。这会导致底层的 WebRTC 引擎返回错误。
4. **在修改参数后没有正确处理 `setParameters` 的异步结果:**  `setParameters` 是一个异步操作，用户需要通过 Promise 或回调来处理成功或失败的情况。忽略错误可能会导致意外的行为。
5. **尝试在发送器停止后调用方法:**  一旦 `RTCRtpSender` 关联的轨道被移除或 PeerConnection 关闭，尝试调用其上的方法可能会导致错误。

**用户操作如何一步步到达这里，作为调试线索:**

假设用户在使用一个基于 WebRTC 的视频会议应用时，遇到了视频流切换失败的问题。以下是可能导致开发者查看 `rtc_rtp_sender_impl.cc` 的步骤：

1. **用户操作:** 用户在视频会议界面点击了“切换摄像头”按钮。
2. **JavaScript 事件处理:** 按钮点击事件触发 JavaScript 代码。
3. **获取新的媒体流:** JavaScript 代码调用 `navigator.mediaDevices.getUserMedia` 获取新的摄像头视频流。
4. **调用 `replaceTrack`:** JavaScript 代码获取到新的视频轨后，调用 `RTCRtpSender` 对象的 `replaceTrack` 方法，尝试替换当前的视频轨道。
5. **Blink 引擎处理:** 浏览器 Blink 引擎接收到 `replaceTrack` 的调用，并将其路由到 `blink/renderer/modules/peerconnection/rtc_rtp_sender_impl.cc` 文件中的 `RTCRtpSenderImpl::ReplaceTrack` 方法。
6. **底层 WebRTC 调用:** `ReplaceTrack` 方法进一步调用底层的 WebRTC 引擎的 `SetTrack` 方法。
7. **问题发生 (假设):**  由于某种原因（例如新的摄像头初始化失败，或者在错误的时机调用），底层的 `SetTrack` 方法返回失败。
8. **回调处理:** `OnReplaceTrackCompleted` 被调用，指示操作失败。
9. **JavaScript 错误处理 (可能):** JavaScript 代码中可能存在错误处理逻辑，会捕获到替换失败的事件或 Promise rejection。
10. **开发者调试:**  开发者可能会通过浏览器开发者工具查看控制台的错误信息，或者使用 WebRTC 内部的日志记录功能。如果错误信息指示与 RTP 发送器或轨道替换相关的问题，开发者可能会查看 `rtc_rtp_sender_impl.cc` 的源代码，以了解 `ReplaceTrack` 方法的实现细节，以及可能导致失败的原因。他们可能会设置断点，查看变量的值，以确定问题所在。

**调试线索:**

* **查看日志:** WebRTC 提供了详细的日志记录功能。查看 `chrome://webrtc-internals/` 可以获取实时的 WebRTC 事件和日志，其中可能包含关于 `RTCRtpSender` 状态和操作的详细信息。
* **设置断点:** 在 `rtc_rtp_sender_impl.cc` 的 `ReplaceTrack`、`SetParameters` 等关键方法中设置断点，可以观察代码执行流程和变量值，帮助定位问题。
* **检查 `webrtc::RTCError`:**  当操作失败时，会返回 `webrtc::RTCError` 对象。检查这个对象的类型和消息可以提供关于失败原因的线索。
* **分析 `RTCPeerConnection` 的状态:**  确保在调用 `replaceTrack` 等方法时，`RTCPeerConnection` 处于合适的状态。
* **检查媒体流和轨道的有效性:**  确保要替换的媒体流和轨道是有效的，并且类型正确。

希望以上分析能够帮助你理解 `blink/renderer/modules/peerconnection/rtc_rtp_sender_impl.cc` 文件的功能和作用。

Prompt: 
```
这是目录为blink/renderer/modules/peerconnection/rtc_rtp_sender_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/peerconnection/rtc_rtp_sender_impl.h"

#include <memory>
#include <utility>

#include "base/check_op.h"
#include "base/notreached.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_dtmf_sender_handler.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_encoded_audio_stream_transformer.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_encoded_video_stream_transformer.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_stats.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_void_request.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/thread_safe_ref_counted.h"

namespace WTF {

template <>
struct CrossThreadCopier<webrtc::RtpParameters>
    : public CrossThreadCopierPassThrough<webrtc::RtpParameters> {
  STATIC_ONLY(CrossThreadCopier);
};

template <>
struct CrossThreadCopier<webrtc::RTCError>
    : public CrossThreadCopierPassThrough<webrtc::RTCError> {
  STATIC_ONLY(CrossThreadCopier);
};

}  // namespace WTF

namespace blink {

namespace {

// TODO(hbos): Replace RTCVoidRequest with something resolving promises based
// on RTCError, as to surface both exception type and error message.
// https://crbug.com/790007
void OnReplaceTrackCompleted(blink::RTCVoidRequest* request, bool result) {
  if (result) {
    request->RequestSucceeded();
  } else {
    request->RequestFailed(
        webrtc::RTCError(webrtc::RTCErrorType::INVALID_MODIFICATION));
  }
}

void OnSetParametersCompleted(blink::RTCVoidRequest* request,
                              webrtc::RTCError result) {
  if (result.ok())
    request->RequestSucceeded();
  else
    request->RequestFailed(result);
}

}  // namespace

RtpSenderState::RtpSenderState(
    scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> signaling_task_runner,
    rtc::scoped_refptr<webrtc::RtpSenderInterface> webrtc_sender,
    std::unique_ptr<blink::WebRtcMediaStreamTrackAdapterMap::AdapterRef>
        track_ref,
    std::vector<std::string> stream_ids)
    : main_task_runner_(std::move(main_task_runner)),
      signaling_task_runner_(std::move(signaling_task_runner)),
      webrtc_sender_(std::move(webrtc_sender)),
      webrtc_dtls_transport_(webrtc_sender_->dtls_transport()),
      webrtc_dtls_transport_information_(webrtc::DtlsTransportState::kNew),
      is_initialized_(false),
      track_ref_(std::move(track_ref)),
      stream_ids_(std::move(stream_ids)) {
  DCHECK(main_task_runner_);
  DCHECK(signaling_task_runner_);
  DCHECK(webrtc_sender_);
  if (webrtc_dtls_transport_) {
    webrtc_dtls_transport_information_ = webrtc_dtls_transport_->Information();
  }
}

RtpSenderState::RtpSenderState(RtpSenderState&& other)
    : main_task_runner_(other.main_task_runner_),
      signaling_task_runner_(other.signaling_task_runner_),
      webrtc_sender_(std::move(other.webrtc_sender_)),
      webrtc_dtls_transport_(std::move(other.webrtc_dtls_transport_)),
      webrtc_dtls_transport_information_(
          other.webrtc_dtls_transport_information_),
      is_initialized_(other.is_initialized_),
      track_ref_(std::move(other.track_ref_)),
      stream_ids_(std::move(other.stream_ids_)) {
  other.main_task_runner_ = nullptr;
  other.signaling_task_runner_ = nullptr;
}

RtpSenderState::~RtpSenderState() {
  // It's OK to not be on the main thread if this state has been moved, in which
  // case |main_task_runner_| is null.
  DCHECK(!main_task_runner_ || main_task_runner_->BelongsToCurrentThread());
}

RtpSenderState& RtpSenderState::operator=(RtpSenderState&& other) {
  DCHECK_EQ(main_task_runner_, other.main_task_runner_);
  DCHECK_EQ(signaling_task_runner_, other.signaling_task_runner_);
  other.main_task_runner_ = nullptr;
  other.signaling_task_runner_ = nullptr;
  webrtc_sender_ = std::move(other.webrtc_sender_);
  webrtc_dtls_transport_ = std::move(other.webrtc_dtls_transport_);
  webrtc_dtls_transport_information_ = other.webrtc_dtls_transport_information_;
  is_initialized_ = other.is_initialized_;
  track_ref_ = std::move(other.track_ref_);
  stream_ids_ = std::move(other.stream_ids_);
  return *this;
}

bool RtpSenderState::is_initialized() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return is_initialized_;
}

void RtpSenderState::Initialize() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  if (track_ref_)
    track_ref_->InitializeOnMainThread();
  is_initialized_ = true;
}

scoped_refptr<base::SingleThreadTaskRunner> RtpSenderState::main_task_runner()
    const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return main_task_runner_;
}

scoped_refptr<base::SingleThreadTaskRunner>
RtpSenderState::signaling_task_runner() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return signaling_task_runner_;
}

rtc::scoped_refptr<webrtc::RtpSenderInterface> RtpSenderState::webrtc_sender()
    const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return webrtc_sender_;
}

rtc::scoped_refptr<webrtc::DtlsTransportInterface>
RtpSenderState::webrtc_dtls_transport() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return webrtc_dtls_transport_;
}

webrtc::DtlsTransportInformation
RtpSenderState::webrtc_dtls_transport_information() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return webrtc_dtls_transport_information_;
}

const std::unique_ptr<blink::WebRtcMediaStreamTrackAdapterMap::AdapterRef>&
RtpSenderState::track_ref() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return track_ref_;
}

void RtpSenderState::set_track_ref(
    std::unique_ptr<blink::WebRtcMediaStreamTrackAdapterMap::AdapterRef>
        track_ref) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  DCHECK(!is_initialized_ || !track_ref || track_ref->is_initialized());
  track_ref_ = std::move(track_ref);
}

std::vector<std::string> RtpSenderState::stream_ids() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return stream_ids_;
}

class RTCRtpSenderImpl::RTCRtpSenderInternal
    : public WTF::ThreadSafeRefCounted<
          RTCRtpSenderImpl::RTCRtpSenderInternal,
          RTCRtpSenderImpl::RTCRtpSenderInternalTraits> {
 public:
  RTCRtpSenderInternal(
      rtc::scoped_refptr<webrtc::PeerConnectionInterface>
          native_peer_connection,
      scoped_refptr<blink::WebRtcMediaStreamTrackAdapterMap> track_map,
      RtpSenderState state,
      bool require_encoded_insertable_streams)
      : native_peer_connection_(std::move(native_peer_connection)),
        track_map_(std::move(track_map)),
        main_task_runner_(state.main_task_runner()),
        signaling_task_runner_(state.signaling_task_runner()),
        webrtc_sender_(state.webrtc_sender()),
        state_(std::move(state)) {
    DCHECK(track_map_);
    DCHECK(state_.is_initialized());
    if (webrtc_sender_->media_type() == cricket::MEDIA_TYPE_AUDIO) {
      encoded_audio_transformer_ =
          std::make_unique<RTCEncodedAudioStreamTransformer>(main_task_runner_);
      webrtc_sender_->SetEncoderToPacketizerFrameTransformer(
          encoded_audio_transformer_->Delegate());
    } else {
      CHECK(webrtc_sender_->media_type() == cricket::MEDIA_TYPE_VIDEO);
      encoded_video_transformer_ =
          std::make_unique<RTCEncodedVideoStreamTransformer>(
              main_task_runner_, /*metronome=*/nullptr);
      webrtc_sender_->SetEncoderToPacketizerFrameTransformer(
          encoded_video_transformer_->Delegate());
    }
  }

  const RtpSenderState& state() const {
    DCHECK(main_task_runner_->BelongsToCurrentThread());
    return state_;
  }

  void set_state(RtpSenderState state) {
    DCHECK(main_task_runner_->BelongsToCurrentThread());
    DCHECK_EQ(state.main_task_runner(), main_task_runner_);
    DCHECK_EQ(state.signaling_task_runner(), signaling_task_runner_);
    DCHECK(state.webrtc_sender() == webrtc_sender_);
    DCHECK(state.is_initialized());
    state_ = std::move(state);
  }

  void ReplaceTrack(MediaStreamComponent* with_track,
                    base::OnceCallback<void(bool)> callback) {
    DCHECK(main_task_runner_->BelongsToCurrentThread());
    std::unique_ptr<blink::WebRtcMediaStreamTrackAdapterMap::AdapterRef>
        track_ref;
    webrtc::MediaStreamTrackInterface* webrtc_track = nullptr;
    if (with_track) {
      track_ref = track_map_->GetOrCreateLocalTrackAdapter(with_track);
      webrtc_track = track_ref->webrtc_track().get();
    }
    PostCrossThreadTask(
        *signaling_task_runner_.get(), FROM_HERE,
        CrossThreadBindOnce(&RTCRtpSenderImpl::RTCRtpSenderInternal::
                                ReplaceTrackOnSignalingThread,
                            WrapRefCounted(this), std::move(track_ref),
                            CrossThreadUnretained(webrtc_track),
                            CrossThreadBindOnce(std::move(callback))));
  }

  std::unique_ptr<blink::RtcDtmfSenderHandler> GetDtmfSender() const {
    // The webrtc_sender() is a proxy, so this is a blocking call to the
    // webrtc signalling thread.
    DCHECK(main_task_runner_->BelongsToCurrentThread());
    auto dtmf_sender = webrtc_sender_->GetDtmfSender();
    return std::make_unique<RtcDtmfSenderHandler>(main_task_runner_,
                                                  dtmf_sender.get());
  }

  std::unique_ptr<webrtc::RtpParameters> GetParameters() {
    // The webrtc_sender() is a proxy, so this is a blocking call to the
    // webrtc signalling thread.
    parameters_ = webrtc_sender_->GetParameters();
    return std::make_unique<webrtc::RtpParameters>(parameters_);
  }

  void SetParameters(
      Vector<webrtc::RtpEncodingParameters> encodings,
      std::optional<webrtc::DegradationPreference> degradation_preference,
      base::OnceCallback<void(webrtc::RTCError)> callback) {
    DCHECK(main_task_runner_->BelongsToCurrentThread());

    webrtc::RtpParameters new_parameters = parameters_;

    new_parameters.degradation_preference = degradation_preference;

    for (WTF::wtf_size_t i = 0; i < new_parameters.encodings.size(); ++i) {
      // Encodings have other parameters in the native layer that aren't exposed
      // to the blink layer. So instead of copying the new struct over the old
      // one, we copy the members one by one over the old struct, effectively
      // patching the changes done by the user.
      const auto& encoding = encodings[i];
      new_parameters.encodings[i].active = encoding.active;
      new_parameters.encodings[i].bitrate_priority = encoding.bitrate_priority;
      new_parameters.encodings[i].network_priority = encoding.network_priority;
      new_parameters.encodings[i].max_bitrate_bps = encoding.max_bitrate_bps;
      new_parameters.encodings[i].max_framerate = encoding.max_framerate;
      new_parameters.encodings[i].rid = encoding.rid;
      new_parameters.encodings[i].scale_resolution_down_by =
          encoding.scale_resolution_down_by;
      new_parameters.encodings[i].scale_resolution_down_to =
          encoding.scale_resolution_down_to;
      new_parameters.encodings[i].scalability_mode = encoding.scalability_mode;
      new_parameters.encodings[i].adaptive_ptime = encoding.adaptive_ptime;
      new_parameters.encodings[i].codec = encoding.codec;
      new_parameters.encodings[i].request_key_frame =
          encoding.request_key_frame;
    }

    PostCrossThreadTask(
        *signaling_task_runner_.get(), FROM_HERE,
        CrossThreadBindOnce(&RTCRtpSenderImpl::RTCRtpSenderInternal::
                                SetParametersOnSignalingThread,
                            WrapRefCounted(this), std::move(new_parameters),
                            CrossThreadBindOnce(std::move(callback))));
  }

  void GetStats(RTCStatsReportCallback callback) {
    PostCrossThreadTask(
        *signaling_task_runner_.get(), FROM_HERE,
        CrossThreadBindOnce(
            &RTCRtpSenderImpl::RTCRtpSenderInternal::GetStatsOnSignalingThread,
            WrapRefCounted(this), CrossThreadBindOnce(std::move(callback))));
  }

  bool RemoveFromPeerConnection(webrtc::PeerConnectionInterface* pc) {
    DCHECK(main_task_runner_->BelongsToCurrentThread());
    if (!pc->RemoveTrackOrError(webrtc_sender_).ok())
      return false;
    // TODO(hbos): Removing the track should null the sender's track, or we
    // should do |webrtc_sender_->SetTrack(null)| but that is not allowed on a
    // stopped sender. In the meantime, there is a discrepancy between layers.
    // https://crbug.com/webrtc/7945
    state_.set_track_ref(nullptr);
    return true;
  }

  void SetStreams(const Vector<String>& stream_ids) {
    DCHECK(main_task_runner_->BelongsToCurrentThread());
    PostCrossThreadTask(
        *signaling_task_runner_.get(), FROM_HERE,
        CrossThreadBindOnce(&RTCRtpSenderImpl::RTCRtpSenderInternal::
                                SetStreamsOnSignalingThread,
                            WrapRefCounted(this), stream_ids));
  }

  RTCEncodedAudioStreamTransformer* GetEncodedAudioStreamTransformer() const {
    return encoded_audio_transformer_.get();
  }

  RTCEncodedVideoStreamTransformer* GetEncodedVideoStreamTransformer() const {
    return encoded_video_transformer_.get();
  }

 private:
  friend class WTF::ThreadSafeRefCounted<RTCRtpSenderInternal,
                                         RTCRtpSenderInternalTraits>;
  friend struct RTCRtpSenderImpl::RTCRtpSenderInternalTraits;

  ~RTCRtpSenderInternal() {
    // Ensured by destructor traits.
    DCHECK(main_task_runner_->BelongsToCurrentThread());
  }

  // |webrtc_track| is passed as an argument because |track_ref->webrtc_track()|
  // cannot be accessed on the signaling thread. https://crbug.com/756436
  void ReplaceTrackOnSignalingThread(
      std::unique_ptr<WebRtcMediaStreamTrackAdapterMap::AdapterRef> track_ref,
      webrtc::MediaStreamTrackInterface* webrtc_track,
      CrossThreadOnceFunction<void(bool)> callback) {
    DCHECK(signaling_task_runner_->BelongsToCurrentThread());
    bool result = webrtc_sender_->SetTrack(webrtc_track);
    PostCrossThreadTask(
        *main_task_runner_.get(), FROM_HERE,
        CrossThreadBindOnce(
            &RTCRtpSenderImpl::RTCRtpSenderInternal::ReplaceTrackCallback,
            WrapRefCounted(this), result, std::move(track_ref),
            std::move(callback)));
  }

  void ReplaceTrackCallback(
      bool result,
      std::unique_ptr<blink::WebRtcMediaStreamTrackAdapterMap::AdapterRef>
          track_ref,
      CrossThreadOnceFunction<void(bool)> callback) {
    DCHECK(main_task_runner_->BelongsToCurrentThread());
    if (result)
      state_.set_track_ref(std::move(track_ref));
    std::move(callback).Run(result);
  }

  using RTCStatsReportCallbackInternal =
      CrossThreadOnceFunction<void(std::unique_ptr<RTCStatsReportPlatform>)>;

  void GetStatsOnSignalingThread(RTCStatsReportCallbackInternal callback) {
    native_peer_connection_->GetStats(
        rtc::scoped_refptr<webrtc::RtpSenderInterface>(webrtc_sender_.get()),
        CreateRTCStatsCollectorCallback(
            main_task_runner_, ConvertToBaseOnceCallback(std::move(callback))));
  }

  void SetParametersOnSignalingThread(
      webrtc::RtpParameters parameters,
      CrossThreadOnceFunction<void(webrtc::RTCError)> callback) {
    DCHECK(signaling_task_runner_->BelongsToCurrentThread());

    webrtc_sender_->SetParametersAsync(
        parameters,
        [callback = std::move(callback),
         task_runner = main_task_runner_](webrtc::RTCError error) mutable {
          PostCrossThreadTask(
              *task_runner.get(), FROM_HERE,
              CrossThreadBindOnce(std::move(callback), std::move(error)));
        });
  }

  void SetStreamsOnSignalingThread(const Vector<String>& stream_ids) {
    DCHECK(signaling_task_runner_->BelongsToCurrentThread());
    std::vector<std::string> ids;
    for (auto stream_id : stream_ids)
      ids.emplace_back(stream_id.Utf8());

    webrtc_sender_->SetStreams(std::move(ids));
  }

  const rtc::scoped_refptr<webrtc::PeerConnectionInterface>
      native_peer_connection_;
  const scoped_refptr<blink::WebRtcMediaStreamTrackAdapterMap> track_map_;
  // Task runners and webrtc sender: Same information as stored in
  // |state_| but const and safe to touch on the signaling thread to
  // avoid race with set_state().
  const scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;
  const scoped_refptr<base::SingleThreadTaskRunner> signaling_task_runner_;
  const rtc::scoped_refptr<webrtc::RtpSenderInterface> webrtc_sender_;
  std::unique_ptr<RTCEncodedAudioStreamTransformer> encoded_audio_transformer_;
  std::unique_ptr<RTCEncodedVideoStreamTransformer> encoded_video_transformer_;
  RtpSenderState state_;
  webrtc::RtpParameters parameters_;
};

struct RTCRtpSenderImpl::RTCRtpSenderInternalTraits {
  static void Destruct(const RTCRtpSenderInternal* sender) {
    // RTCRtpSenderInternal owns AdapterRefs which have to be destroyed on the
    // main thread, this ensures delete always happens there.
    if (!sender->main_task_runner_->BelongsToCurrentThread()) {
      PostCrossThreadTask(
          *sender->main_task_runner_.get(), FROM_HERE,
          CrossThreadBindOnce(
              &RTCRtpSenderImpl::RTCRtpSenderInternalTraits::Destruct,
              CrossThreadUnretained(sender)));
      return;
    }
    delete sender;
  }
};

uintptr_t RTCRtpSenderImpl::getId(
    const webrtc::RtpSenderInterface* webrtc_sender) {
  return reinterpret_cast<uintptr_t>(webrtc_sender);
}

RTCRtpSenderImpl::RTCRtpSenderImpl(
    rtc::scoped_refptr<webrtc::PeerConnectionInterface> native_peer_connection,
    scoped_refptr<blink::WebRtcMediaStreamTrackAdapterMap> track_map,
    RtpSenderState state,
    bool require_encoded_insertable_streams)
    : internal_(base::MakeRefCounted<RTCRtpSenderInternal>(
          std::move(native_peer_connection),
          std::move(track_map),
          std::move(state),
          require_encoded_insertable_streams)) {}

RTCRtpSenderImpl::RTCRtpSenderImpl(const RTCRtpSenderImpl& other)
    : internal_(other.internal_) {}

RTCRtpSenderImpl::~RTCRtpSenderImpl() {}

RTCRtpSenderImpl& RTCRtpSenderImpl::operator=(const RTCRtpSenderImpl& other) {
  internal_ = other.internal_;
  return *this;
}

const RtpSenderState& RTCRtpSenderImpl::state() const {
  return internal_->state();
}

void RTCRtpSenderImpl::set_state(RtpSenderState state) {
  internal_->set_state(std::move(state));
}

std::unique_ptr<blink::RTCRtpSenderPlatform> RTCRtpSenderImpl::ShallowCopy()
    const {
  return std::make_unique<RTCRtpSenderImpl>(*this);
}

uintptr_t RTCRtpSenderImpl::Id() const {
  return getId(internal_->state().webrtc_sender().get());
}

rtc::scoped_refptr<webrtc::DtlsTransportInterface>
RTCRtpSenderImpl::DtlsTransport() {
  return internal_->state().webrtc_dtls_transport();
}

webrtc::DtlsTransportInformation RTCRtpSenderImpl::DtlsTransportInformation() {
  return internal_->state().webrtc_dtls_transport_information();
}

MediaStreamComponent* RTCRtpSenderImpl::Track() const {
  const auto& track_ref = internal_->state().track_ref();
  return track_ref ? track_ref->track() : nullptr;
}

Vector<String> RTCRtpSenderImpl::StreamIds() const {
  const auto& stream_ids = internal_->state().stream_ids();
  Vector<String> wtf_stream_ids(
      static_cast<WTF::wtf_size_t>(stream_ids.size()));
  for (WTF::wtf_size_t i = 0; i < stream_ids.size(); ++i)
    wtf_stream_ids[i] = String::FromUTF8(stream_ids[i]);
  return wtf_stream_ids;
}

void RTCRtpSenderImpl::ReplaceTrack(MediaStreamComponent* with_track,
                                    RTCVoidRequest* request) {
  internal_->ReplaceTrack(with_track, WTF::BindOnce(&OnReplaceTrackCompleted,
                                                    WrapPersistent(request)));
}

std::unique_ptr<blink::RtcDtmfSenderHandler> RTCRtpSenderImpl::GetDtmfSender()
    const {
  return internal_->GetDtmfSender();
}

std::unique_ptr<webrtc::RtpParameters> RTCRtpSenderImpl::GetParameters() const {
  return internal_->GetParameters();
}

void RTCRtpSenderImpl::SetParameters(
    Vector<webrtc::RtpEncodingParameters> encodings,
    std::optional<webrtc::DegradationPreference> degradation_preference,
    blink::RTCVoidRequest* request) {
  internal_->SetParameters(
      std::move(encodings), degradation_preference,
      WTF::BindOnce(&OnSetParametersCompleted, WrapPersistent(request)));
}

void RTCRtpSenderImpl::GetStats(RTCStatsReportCallback callback) {
  internal_->GetStats(std::move(callback));
}

void RTCRtpSenderImpl::SetStreams(const Vector<String>& stream_ids) {
  internal_->SetStreams(stream_ids);
}

void RTCRtpSenderImpl::ReplaceTrack(MediaStreamComponent* with_track,
                                    base::OnceCallback<void(bool)> callback) {
  internal_->ReplaceTrack(with_track, std::move(callback));
}

bool RTCRtpSenderImpl::RemoveFromPeerConnection(
    webrtc::PeerConnectionInterface* pc) {
  return internal_->RemoveFromPeerConnection(pc);
}

RTCEncodedAudioStreamTransformer*
RTCRtpSenderImpl::GetEncodedAudioStreamTransformer() const {
  return internal_->GetEncodedAudioStreamTransformer();
}

RTCEncodedVideoStreamTransformer*
RTCRtpSenderImpl::GetEncodedVideoStreamTransformer() const {
  return internal_->GetEncodedVideoStreamTransformer();
}

}  // namespace blink

"""

```