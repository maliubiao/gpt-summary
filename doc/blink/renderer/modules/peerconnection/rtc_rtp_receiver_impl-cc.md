Response:
Let's break down the thought process for analyzing this C++ file and answering the prompt.

1. **Understand the Goal:** The primary goal is to analyze the given C++ source code file (`rtc_rtp_receiver_impl.cc`) and explain its functionality in the context of a web browser's rendering engine (Blink/Chromium). The explanation needs to cover its relationship to web technologies (JavaScript, HTML, CSS), provide examples, handle logical reasoning with input/output, discuss common user/programming errors, and trace the user's path to this code.

2. **Initial Code Scan & Keyword Identification:**  Start by scanning the code for key terms and structures. Immediately, terms like `RtpReceiver`, `PeerConnection`, `webrtc`, `audio`, `video`, `transformer`, `stats`, `DTLS`, `streams`, and `track` stand out. The file structure, including `#include` directives, namespaces (`blink`), classes (`RTCRtpReceiverImpl`, `RtpReceiverState`), and methods, provides a structural overview.

3. **Identify Core Functionality (High-Level):** Based on the keywords, it becomes clear that this file is about *receiving* Real-time Transport Protocol (RTP) media streams within a WebRTC context. It manages the incoming audio and video data.

4. **Dissect Key Classes and their Roles:**
    * **`RtpReceiverState`:** This seems to hold the state information for an RTP receiver. It manages things like the underlying WebRTC receiver object, DTLS transport information, and the associated media stream track. The constructor and move semantics indicate it's designed for efficient state management.
    * **`RTCRtpReceiverImpl`:** This is the main class, the "implementation." It holds an internal object (`RTCRtpReceiverInternal`) for thread-safe operations and provides the public interface for interacting with the RTP receiver.
    * **`RTCRtpReceiverInternal`:** This class handles the more complex operations, potentially involving multiple threads. It interacts directly with the WebRTC API, manages audio and video transformers, and handles statistics reporting.
    * **`RTCEncodedAudioStreamTransformer` and `RTCEncodedVideoStreamTransformer`:** These classes are responsible for processing the *encoded* audio and video data. The presence of `SetDepacketizerToDecoderFrameTransformer` confirms their role in the media processing pipeline.

5. **Establish Relationships to Web Technologies:**
    * **JavaScript:** WebRTC is a JavaScript API. This C++ code *implements* the underlying functionality that JavaScript code interacts with. Methods like `GetStats`, `GetParameters`, `SetJitterBufferMinimumDelay` would have corresponding JavaScript methods exposed via the WebRTC API (e.g., `RTCRtpReceiver.getStats()`).
    * **HTML:** The `<video>` and `<audio>` HTML elements are where the received media streams are ultimately displayed or played. The `RTCRtpReceiverImpl` is responsible for getting the data to these elements.
    * **CSS:** CSS styles the presentation of the `<video>` and `<audio>` elements. While `RTCRtpReceiverImpl` doesn't directly manipulate CSS, its work enables the media to be presented, which CSS then styles.

6. **Develop Examples:**  Based on the understanding of the functionality, create concrete examples of how JavaScript interacts with the concepts in the C++ code. Showing how to get stats, access parameters, and set jitter buffer delay clarifies the connection. Illustrating how media streams are attached to HTML elements is also crucial.

7. **Consider Logical Reasoning and Input/Output:**  Think about specific methods and their behavior. For example, `GetSources()` retrieves information about the sources of the RTP stream. Consider a simple scenario: a single sender sending one video track. The input would be the active `RTCRtpReceiver`, and the output would be an `RTCRtpSource` object containing information about that sender. For more complex scenarios (multiple senders, different codecs), describe how the output would change.

8. **Identify Common Errors:**  Think about typical mistakes developers make when working with WebRTC:
    * Incorrectly handling asynchronous operations (promises, callbacks).
    * Not checking for errors (e.g., failing to connect).
    * Misunderstanding the state machine of WebRTC.
    * Incorrectly configuring SDP (Session Description Protocol).

9. **Trace the User Path (Debugging Clues):**  Imagine a user making a WebRTC call. Outline the steps that would lead to this specific C++ code being executed:
    * User initiates a call (clicks a button).
    * JavaScript uses the WebRTC API (`getUserMedia`, `RTCPeerConnection`).
    * SDP negotiation occurs.
    * Once a connection is established and media is being received, the browser's engine (Blink) will instantiate the `RTCRtpReceiverImpl` to handle the incoming RTP packets. This involves parsing the packets, potentially transforming the data, and delivering it to the appropriate media track.

10. **Structure and Refine the Answer:** Organize the information logically, using headings and bullet points for clarity. Ensure that the examples are clear and the explanations are concise and accurate. Review the answer for completeness and correctness. Make sure all aspects of the prompt are addressed. For example, explicitly mentioning the thread safety mechanisms (`ThreadSafeRefCounted`) and the role of task runners is important for demonstrating a deeper understanding.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file just receives RTP."  **Correction:**  It's not just about *receiving*; it also handles decoding, potentially applying transformations, and reporting statistics.
* **Initial thought:** "The JavaScript connection is obvious." **Refinement:** Provide specific examples of the JavaScript API calls that relate to the C++ code.
* **Initial thought:** "Focus heavily on the low-level WebRTC details." **Correction:** Balance the low-level details with a clear explanation of how this code relates to the higher-level web technologies that developers interact with. The prompt specifically asks for connections to JavaScript, HTML, and CSS.
* **Initial thought:**  "Just list potential errors." **Refinement:** Provide specific, actionable examples of common errors that relate to the functionality of this particular file.

By following this systematic approach, breaking down the code, and constantly considering the context of web development, a comprehensive and accurate answer to the prompt can be generated.
好的，让我们来分析一下 `blink/renderer/modules/peerconnection/rtc_rtp_receiver_impl.cc` 文件的功能。

**主要功能:**

这个文件实现了 `RTCRtpReceiverImpl` 类，它是 Chromium Blink 引擎中用于处理接收到的媒体 RTP (Real-time Transport Protocol) 数据的核心组件。 它的主要职责是管理和控制接收到的音视频数据流。

**更详细的功能点:**

1. **RTP 接收管理:**  `RTCRtpReceiverImpl` 封装了 WebRTC 底层的 `webrtc::RtpReceiverInterface`，负责接收和处理来自远端的 RTP 数据包。
2. **状态管理:**  通过 `RtpReceiverState` 类来管理接收器的各种状态，例如所属的线程、底层的 WebRTC 接收器对象、DTLS 传输信息、关联的媒体轨道 (track) 以及流 ID 等。
3. **媒体轨道关联:**  将接收到的 RTP 数据与特定的 `MediaStreamTrack` 对象关联起来，使得接收到的数据可以被浏览器渲染和播放。
4. **统计信息获取:** 提供 `GetStats` 方法，用于获取关于接收到的 RTP 流的各种统计信息，例如丢包率、延迟、抖动等。这些信息对于监控和调试 WebRTC 连接质量至关重要。
5. **RTP 参数获取:**  提供 `GetParameters` 方法，用于获取当前接收器的 RTP 参数，例如编解码器、有效载荷类型等。
6. **抖动缓冲区控制:**  提供 `SetJitterBufferMinimumDelay` 方法，允许设置抖动缓冲区的最小延迟，用于平滑网络抖动带来的影响。
7. **RTP 源管理:** 提供 `GetSources` 方法，用于获取与该接收器关联的 RTP 源 (RTCRtpSource) 信息，这有助于识别不同的发送方。
8. **可插入流 (Insertable Streams) 支持 (Encoded Transforms):**
   - 提供了 `GetEncodedAudioStreamTransformer` 和 `GetEncodedVideoStreamTransformer` 方法，用于获取用于处理接收到的 *编码后* 音视频数据的转换器 (Transformer)。
   - 这与 WebRTC 的 "可插入流" 功能相关，允许开发者在 JavaScript 中拦截和处理编码后的音视频帧，实现自定义的媒体处理逻辑（例如加密、水印、自定义编码等）。
9. **线程安全:** 使用 `ThreadSafeRefCounted` 来确保 `RTCRtpReceiverInternal` 对象的线程安全访问。涉及到在不同的线程（例如主线程和信令线程）之间传递和操作数据。

**与 JavaScript, HTML, CSS 的关系及举例:**

`RTCRtpReceiverImpl.cc` 文件中的代码是浏览器引擎的底层实现，它直接与 WebRTC 的 C++ API 交互。 然而，它的功能直接支撑着 WebRTC 的 JavaScript API，并最终影响着 HTML 中展示的音视频内容。

**JavaScript 交互:**

* **获取接收器对象:** 在 JavaScript 中，通过 `RTCPeerConnection.getReceivers()` 方法可以获取到 `RTCRtpReceiver` 对象（在 Blink 引擎中由 `RTCRtpReceiverImpl` 实现）。
  ```javascript
  pc.getReceivers().forEach(receiver => {
    console.log("Receiver ID:", receiver.id);
    receiver.getStats().then(stats => console.log("Receiver Stats:", stats));
    console.log("Receiver Track:", receiver.track);
  });
  ```
* **获取统计信息:** JavaScript 的 `RTCRtpReceiver.getStats()` 方法会最终调用到 `RTCRtpReceiverImpl::GetStats`。
* **获取 RTP 参数:** JavaScript 的 `RTCRtpReceiver.getParameters()` 方法会最终调用到 `RTCRtpReceiverImpl::GetParameters`。
* **设置抖动缓冲区:** JavaScript 的 `RTCRtpReceiver.jitterBufferMinimumDelay` 属性的设置会最终调用到 `RTCRtpReceiverImpl::SetJitterBufferMinimumDelay`。
* **处理可插入流:** JavaScript 中通过 `RTCRtpReceiver.transform` 属性设置的 `TransformStream` 对象，会与 `RTCEncodedAudioStreamTransformer` 或 `RTCEncodedVideoStreamTransformer` 关联，从而在 C++ 层进行编码后数据的处理。
  ```javascript
  receiver.transform = new TransformStream({
    transform(chunk, controller) {
      // 处理接收到的编码后的音/视频数据 (chunk)
      controller.enqueue(chunk);
    }
  });
  ```

**HTML 交互:**

* 接收到的媒体数据最终会被渲染到 HTML 的 `<video>` 或 `<audio>` 元素中。 `RTCRtpReceiverImpl` 负责接收数据，并将其传递给与轨道关联的渲染管道，最终呈现在 HTML 元素上。
  ```html
  <video id="remoteVideo" autoplay playsinline></video>
  ```
  在 JavaScript 中，通常会将接收到的远程流的轨道赋值给 HTML 元素的 `srcObject` 属性。
  ```javascript
  pc.ontrack = (event) => {
    if (event.track.kind === 'video') {
      document.getElementById('remoteVideo').srcObject = event.streams[0];
    }
  };
  ```

**CSS 交互:**

* CSS 用于控制 `<video>` 和 `<audio>` 元素的样式和布局。 `RTCRtpReceiverImpl` 本身不直接与 CSS 交互，但它接收到的媒体数据使得这些元素能够显示内容，从而可以应用 CSS 样式。

**逻辑推理、假设输入与输出:**

**假设输入:**

1. **接收到 RTP 数据包:**  假设远端发送了一个包含视频帧数据的 RTP 包，其 SSRC (Synchronization Source) 与当前 `RTCRtpReceiverImpl` 关联。
2. **可插入流已配置:** 假设 JavaScript 中已经为该接收器配置了一个 `TransformStream` 来处理编码后的视频数据。

**逻辑推理:**

1. `RTCRtpReceiverImpl` 的底层 `webrtc::RtpReceiverInterface` 接收到 RTP 包。
2. 数据包经过解包、解码 (如果未配置可插入流)。
3. **如果配置了可插入流:**
   - 编码后的数据 (chunk) 会被传递给 `RTCEncodedVideoStreamTransformer`。
   - `RTCEncodedVideoStreamTransformer` 会将数据传递到与 JavaScript `TransformStream` 关联的处理逻辑中。
   - JavaScript 代码可以修改或处理数据，然后通过 `controller.enqueue()` 将数据返回。
   - 经过 JavaScript 处理后的数据 (或者原始数据，如果 JavaScript 未修改) 继续后续的处理流程。
4. 解码后的视频帧数据被传递到与该接收器关联的 `MediaStreamTrack` 对象。
5. `MediaStreamTrack` 将数据传递给渲染管道，最终在 HTML 的 `<video>` 元素中显示出来。

**输出:**

* 在配置了可插入流的情况下，JavaScript `TransformStream` 的 `transform` 方法会被调用，接收到包含编码后视频数据的 `chunk` 对象。
* 最终，远端的视频画面会显示在本地浏览器的 `<video>` 元素中。

**用户或编程常见的使用错误:**

1. **未正确处理 `ontrack` 事件:** 用户可能忘记监听 `RTCPeerConnection` 的 `ontrack` 事件，或者在事件处理程序中没有正确地将接收到的轨道赋值给 HTML 元素的 `srcObject`，导致无法显示远端媒体。
   ```javascript
   // 错误示例
   pc.ontrack = (event) => {
     console.log("Track received"); // 但没有设置 srcObject
   };

   // 正确示例
   pc.ontrack = (event) => {
     if (event.track.kind === 'video') {
       document.getElementById('remoteVideo').srcObject = event.streams[0];
     }
   };
   ```
2. **误解可插入流的工作方式:**  开发者可能认为可插入流可以直接操作解码后的帧数据，但实际上它处理的是 *编码后* 的数据。对编码格式的理解不足可能导致处理逻辑错误。
3. **在可插入流中阻塞操作:** 在 JavaScript 的 `transform` 方法中执行耗时的同步操作会阻塞渲染线程，导致卡顿。应该使用异步操作或将耗时操作移至 Web Worker。
4. **没有正确处理异步操作:**  例如，在调用 `getStats()` 后没有正确处理返回的 Promise，可能导致无法获取到统计信息。
   ```javascript
   // 错误示例
   pc.getReceivers()[0].getStats(); // 没有 .then()

   // 正确示例
   pc.getReceivers()[0].getStats().then(stats => {
     console.log("Stats:", stats);
   });
   ```
5. **尝试在不兼容的浏览器上使用可插入流:**  可插入流是相对较新的 WebRTC 功能，需要在支持的浏览器版本上才能使用。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户发起或接收 WebRTC 通话:** 用户在网页上点击一个按钮，或者通过其他方式触发建立 WebRTC 连接的过程。
2. **`RTCPeerConnection` 对象创建:** JavaScript 代码会创建一个 `RTCPeerConnection` 对象。
3. **SDP 协商:** 浏览器会进行 SDP (Session Description Protocol) 协商，确定媒体的格式和传输方式。
4. **添加远程流和轨道:**  当远端发送媒体流时，本地浏览器会接收到 `addstream` (旧 API) 或 `track` 事件。
5. **`RTCRtpReceiver` 对象创建:**  当接收到来自远端的媒体轨道时，Blink 引擎会在底层创建一个 `RTCRtpReceiverImpl` 对象来处理该轨道的 RTP 数据。
6. **接收 RTP 数据包:** 远端发送的音视频数据被封装成 RTP 包通过网络传输到本地浏览器。
7. **`RTCRtpReceiverImpl` 处理数据:**  `RTCRtpReceiverImpl` 的底层 WebRTC 组件接收到这些 RTP 包，并进行解包、解码等处理。
8. **可插入流处理 (如果配置):** 如果 JavaScript 代码配置了可插入流，那么在解码前，编码后的数据会传递给相应的 Transformer 进行处理。
9. **数据传递到 `MediaStreamTrack`:** 解码后的数据 (或经过可插入流处理后的数据) 被传递到与该接收器关联的 `MediaStreamTrack` 对象。
10. **渲染到 HTML 元素:** `MediaStreamTrack` 对象的数据最终被渲染到 HTML 的 `<video>` 或 `<audio>` 元素中，用户就能看到或听到远端的内容。

**调试线索:**

* **查看 `chrome://webrtc-internals`:**  这是一个非常有用的 Chromium 工具，可以查看 WebRTC 连接的各种内部状态，包括 `RTCRtpReceiver` 的信息、统计数据、SDP 信息等。
* **在 JavaScript 中打印 `RTCRtpReceiver` 对象:**  可以在 JavaScript 中打印 `RTCPeerConnection.getReceivers()` 返回的 `RTCRtpReceiver` 对象，查看其属性和方法。
* **使用 Chrome 开发者工具的网络面板:**  可以查看网络请求，虽然 RTP 数据本身不直接显示在网络面板中，但可以查看信令 (SDP) 的交换过程。
* **在 C++ 代码中添加日志:** 如果需要深入调试 Blink 引擎的内部行为，可以在 `rtc_rtp_receiver_impl.cc` 文件中添加 `LOG` 语句来输出关键信息，例如接收到的 RTP 包的数量、时间戳等。这需要重新编译 Chromium。

总而言之，`blink/renderer/modules/peerconnection/rtc_rtp_receiver_impl.cc` 是 Blink 引擎中负责接收和管理 WebRTC 接收到的媒体数据的核心组件，它连接了底层的 WebRTC C++ API 和上层的 JavaScript WebRTC API，最终使得用户能够在浏览器中看到和听到来自远端的音视频内容。

Prompt: 
```
这是目录为blink/renderer/modules/peerconnection/rtc_rtp_receiver_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/peerconnection/rtc_rtp_receiver_impl.h"

#include "base/check_op.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/notreached.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_encoded_audio_stream_transformer.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_encoded_video_stream_transformer.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_rtp_sender_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_rtp_source.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_stats.h"
#include "third_party/blink/renderer/platform/wtf/thread_safe_ref_counted.h"
#include "third_party/webrtc/api/scoped_refptr.h"

namespace blink {

BASE_FEATURE(kRTCAlignReceivedEncodedVideoTransforms,
             "RTCAlignReceivedEncodedVideoTransforms",
             base::FEATURE_ENABLED_BY_DEFAULT);

RtpReceiverState::RtpReceiverState(
    scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> signaling_task_runner,
    scoped_refptr<webrtc::RtpReceiverInterface> webrtc_receiver,
    std::unique_ptr<blink::WebRtcMediaStreamTrackAdapterMap::AdapterRef>
        track_ref,
    std::vector<std::string> stream_id)
    : main_task_runner_(std::move(main_task_runner)),
      signaling_task_runner_(std::move(signaling_task_runner)),
      webrtc_receiver_(std::move(webrtc_receiver)),
      webrtc_dtls_transport_(webrtc_receiver_->dtls_transport()),
      webrtc_dtls_transport_information_(webrtc::DtlsTransportState::kNew),
      is_initialized_(false),
      track_ref_(std::move(track_ref)),
      stream_ids_(std::move(stream_id)) {
  DCHECK(main_task_runner_);
  DCHECK(signaling_task_runner_);
  DCHECK(webrtc_receiver_);
  DCHECK(track_ref_);
  if (webrtc_dtls_transport_) {
    webrtc_dtls_transport_information_ = webrtc_dtls_transport_->Information();
  }
}

RtpReceiverState::RtpReceiverState(RtpReceiverState&& other)
    : main_task_runner_(other.main_task_runner_),
      signaling_task_runner_(other.signaling_task_runner_),
      webrtc_receiver_(std::move(other.webrtc_receiver_)),
      webrtc_dtls_transport_(std::move(other.webrtc_dtls_transport_)),
      webrtc_dtls_transport_information_(
          other.webrtc_dtls_transport_information_),
      is_initialized_(other.is_initialized_),
      track_ref_(std::move(other.track_ref_)),
      stream_ids_(std::move(other.stream_ids_)) {
  // Explicitly null |other|'s task runners for use in destructor.
  other.main_task_runner_ = nullptr;
  other.signaling_task_runner_ = nullptr;
}

RtpReceiverState::~RtpReceiverState() {
  // It's OK to not be on the main thread if this state has been moved, in which
  // case |main_task_runner_| is null.
  DCHECK(!main_task_runner_ || main_task_runner_->BelongsToCurrentThread());
}

RtpReceiverState& RtpReceiverState::operator=(RtpReceiverState&& other) {
  DCHECK_EQ(main_task_runner_, other.main_task_runner_);
  DCHECK_EQ(signaling_task_runner_, other.signaling_task_runner_);
  // Explicitly null |other|'s task runners for use in destructor.
  other.main_task_runner_ = nullptr;
  other.signaling_task_runner_ = nullptr;
  webrtc_receiver_ = std::move(other.webrtc_receiver_);
  webrtc_dtls_transport_ = std::move(other.webrtc_dtls_transport_);
  webrtc_dtls_transport_information_ = other.webrtc_dtls_transport_information_;
  track_ref_ = std::move(other.track_ref_);
  stream_ids_ = std::move(other.stream_ids_);
  return *this;
}

bool RtpReceiverState::is_initialized() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return is_initialized_;
}

void RtpReceiverState::Initialize() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  if (is_initialized_)
    return;
  track_ref_->InitializeOnMainThread();
  is_initialized_ = true;
}

scoped_refptr<base::SingleThreadTaskRunner> RtpReceiverState::main_task_runner()
    const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return main_task_runner_;
}

scoped_refptr<base::SingleThreadTaskRunner>
RtpReceiverState::signaling_task_runner() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return signaling_task_runner_;
}

scoped_refptr<webrtc::RtpReceiverInterface> RtpReceiverState::webrtc_receiver()
    const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return webrtc_receiver_;
}

rtc::scoped_refptr<webrtc::DtlsTransportInterface>
RtpReceiverState::webrtc_dtls_transport() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return webrtc_dtls_transport_;
}

webrtc::DtlsTransportInformation
RtpReceiverState::webrtc_dtls_transport_information() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return webrtc_dtls_transport_information_;
}

const std::unique_ptr<blink::WebRtcMediaStreamTrackAdapterMap::AdapterRef>&
RtpReceiverState::track_ref() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return track_ref_;
}

const std::vector<std::string>& RtpReceiverState::stream_ids() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return stream_ids_;
}

class RTCRtpReceiverImpl::RTCRtpReceiverInternal
    : public WTF::ThreadSafeRefCounted<
          RTCRtpReceiverImpl::RTCRtpReceiverInternal,
          RTCRtpReceiverImpl::RTCRtpReceiverInternalTraits> {
 public:
  RTCRtpReceiverInternal(rtc::scoped_refptr<webrtc::PeerConnectionInterface>
                             native_peer_connection,
                         RtpReceiverState state,
                         bool require_encoded_insertable_streams,
                         std::unique_ptr<webrtc::Metronome> decode_metronome)
      : native_peer_connection_(std::move(native_peer_connection)),
        main_task_runner_(state.main_task_runner()),
        signaling_task_runner_(state.signaling_task_runner()),
        webrtc_receiver_(state.webrtc_receiver()),
        state_(std::move(state)) {
    DCHECK(native_peer_connection_);
    DCHECK(state_.is_initialized());
    if (webrtc_receiver_->media_type() == cricket::MEDIA_TYPE_AUDIO) {
      encoded_audio_transformer_ =
          std::make_unique<RTCEncodedAudioStreamTransformer>(main_task_runner_);
      webrtc_receiver_->SetDepacketizerToDecoderFrameTransformer(
          encoded_audio_transformer_->Delegate());
    } else {
      CHECK(webrtc_receiver_->media_type() == cricket::MEDIA_TYPE_VIDEO);
      encoded_video_transformer_ =
          std::make_unique<RTCEncodedVideoStreamTransformer>(
              main_task_runner_, base::FeatureList::IsEnabled(
                                     kRTCAlignReceivedEncodedVideoTransforms)
                                     ? std::move(decode_metronome)
                                     : nullptr);
      webrtc_receiver_->SetDepacketizerToDecoderFrameTransformer(
          encoded_video_transformer_->Delegate());
    }
    DCHECK(!encoded_audio_transformer_ || !encoded_video_transformer_);
  }

  const RtpReceiverState& state() const {
    DCHECK(main_task_runner_->BelongsToCurrentThread());
    return state_;
  }

  void set_state(RtpReceiverState state) {
    DCHECK(main_task_runner_->BelongsToCurrentThread());
    DCHECK(state.main_task_runner() == main_task_runner_);
    DCHECK(state.signaling_task_runner() == signaling_task_runner_);
    DCHECK(state.webrtc_receiver() == webrtc_receiver_);
    DCHECK(state.is_initialized());
    state_ = std::move(state);
  }

  Vector<std::unique_ptr<RTCRtpSource>> GetSources() {
    // The `webrtc_recever_` is a PROXY and GetSources block-invokes to its
    // secondary thread, which is the WebRTC worker thread.
    auto webrtc_sources = webrtc_receiver_->GetSources();
    Vector<std::unique_ptr<RTCRtpSource>> sources(
        static_cast<WTF::wtf_size_t>(webrtc_sources.size()));
    for (WTF::wtf_size_t i = 0; i < webrtc_sources.size(); ++i) {
      sources[i] = std::make_unique<RTCRtpSource>(webrtc_sources[i]);
    }
    return sources;
  }

  void GetStats(RTCStatsReportCallback callback) {
    signaling_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&RTCRtpReceiverInternal::GetStatsOnSignalingThread, this,
                       std::move(callback)));
  }

  std::unique_ptr<webrtc::RtpParameters> GetParameters() {
    return std::make_unique<webrtc::RtpParameters>(
        webrtc_receiver_->GetParameters());
  }

  void SetJitterBufferMinimumDelay(std::optional<double> delay_seconds) {
    webrtc_receiver_->SetJitterBufferMinimumDelay(delay_seconds);
  }

  RTCEncodedAudioStreamTransformer* GetEncodedAudioStreamTransformer() const {
    return encoded_audio_transformer_.get();
  }

  RTCEncodedVideoStreamTransformer* GetEncodedVideoStreamTransformer() const {
    return encoded_video_transformer_.get();
  }

 private:
  friend class WTF::ThreadSafeRefCounted<RTCRtpReceiverInternal,
                                         RTCRtpReceiverInternalTraits>;
  friend struct RTCRtpReceiverImpl::RTCRtpReceiverInternalTraits;

  ~RTCRtpReceiverInternal() {
    DCHECK(main_task_runner_->BelongsToCurrentThread());
  }

  void GetStatsOnSignalingThread(RTCStatsReportCallback callback) {
    native_peer_connection_->GetStats(
        rtc::scoped_refptr<webrtc::RtpReceiverInterface>(
            webrtc_receiver_.get()),
        CreateRTCStatsCollectorCallback(main_task_runner_,
                                        std::move(callback)));
  }

  const rtc::scoped_refptr<webrtc::PeerConnectionInterface>
      native_peer_connection_;
  // Task runners and webrtc receiver: Same information as stored in
  // |state_| but const and safe to touch on the signaling thread to
  // avoid race with set_state().
  const scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;
  const scoped_refptr<base::SingleThreadTaskRunner> signaling_task_runner_;
  const scoped_refptr<webrtc::RtpReceiverInterface> webrtc_receiver_;
  std::unique_ptr<RTCEncodedAudioStreamTransformer> encoded_audio_transformer_;
  std::unique_ptr<RTCEncodedVideoStreamTransformer> encoded_video_transformer_;
  RtpReceiverState state_;
};

struct RTCRtpReceiverImpl::RTCRtpReceiverInternalTraits {
  static void Destruct(const RTCRtpReceiverInternal* receiver) {
    // RTCRtpReceiverInternal owns AdapterRefs which have to be destroyed on the
    // main thread, this ensures delete always happens there.
    if (!receiver->main_task_runner_->BelongsToCurrentThread()) {
      receiver->main_task_runner_->PostTask(
          FROM_HERE,
          base::BindOnce(
              &RTCRtpReceiverImpl::RTCRtpReceiverInternalTraits::Destruct,
              base::Unretained(receiver)));
      return;
    }
    delete receiver;
  }
};

uintptr_t RTCRtpReceiverImpl::getId(
    const webrtc::RtpReceiverInterface* webrtc_rtp_receiver) {
  return reinterpret_cast<uintptr_t>(webrtc_rtp_receiver);
}

RTCRtpReceiverImpl::RTCRtpReceiverImpl(
    rtc::scoped_refptr<webrtc::PeerConnectionInterface> native_peer_connection,
    RtpReceiverState state,
    bool require_encoded_insertable_streams,
    std::unique_ptr<webrtc::Metronome> decode_metronome)
    : internal_(base::MakeRefCounted<RTCRtpReceiverInternal>(
          std::move(native_peer_connection),
          std::move(state),
          require_encoded_insertable_streams,
          std::move(decode_metronome))) {}

RTCRtpReceiverImpl::RTCRtpReceiverImpl(const RTCRtpReceiverImpl& other)
    : internal_(other.internal_) {}

RTCRtpReceiverImpl::~RTCRtpReceiverImpl() {}

RTCRtpReceiverImpl& RTCRtpReceiverImpl::operator=(
    const RTCRtpReceiverImpl& other) {
  internal_ = other.internal_;
  return *this;
}

const RtpReceiverState& RTCRtpReceiverImpl::state() const {
  return internal_->state();
}

void RTCRtpReceiverImpl::set_state(RtpReceiverState state) {
  internal_->set_state(std::move(state));
}

std::unique_ptr<RTCRtpReceiverPlatform> RTCRtpReceiverImpl::ShallowCopy()
    const {
  return std::make_unique<RTCRtpReceiverImpl>(*this);
}

uintptr_t RTCRtpReceiverImpl::Id() const {
  return getId(internal_->state().webrtc_receiver().get());
}

rtc::scoped_refptr<webrtc::DtlsTransportInterface>
RTCRtpReceiverImpl::DtlsTransport() {
  return internal_->state().webrtc_dtls_transport();
}

webrtc::DtlsTransportInformation
RTCRtpReceiverImpl::DtlsTransportInformation() {
  return internal_->state().webrtc_dtls_transport_information();
}

MediaStreamComponent* RTCRtpReceiverImpl::Track() const {
  return internal_->state().track_ref()->track();
}

Vector<String> RTCRtpReceiverImpl::StreamIds() const {
  const auto& stream_ids = internal_->state().stream_ids();
  Vector<String> wtf_stream_ids(
      static_cast<WTF::wtf_size_t>(stream_ids.size()));
  for (WTF::wtf_size_t i = 0; i < stream_ids.size(); ++i)
    wtf_stream_ids[i] = String::FromUTF8(stream_ids[i]);
  return wtf_stream_ids;
}

Vector<std::unique_ptr<RTCRtpSource>> RTCRtpReceiverImpl::GetSources() {
  return internal_->GetSources();
}

void RTCRtpReceiverImpl::GetStats(RTCStatsReportCallback callback) {
  internal_->GetStats(std::move(callback));
}

std::unique_ptr<webrtc::RtpParameters> RTCRtpReceiverImpl::GetParameters()
    const {
  return internal_->GetParameters();
}

void RTCRtpReceiverImpl::SetJitterBufferMinimumDelay(
    std::optional<double> delay_seconds) {
  internal_->SetJitterBufferMinimumDelay(delay_seconds);
}

RTCEncodedAudioStreamTransformer*
RTCRtpReceiverImpl::GetEncodedAudioStreamTransformer() const {
  return internal_->GetEncodedAudioStreamTransformer();
}

RTCEncodedVideoStreamTransformer*
RTCRtpReceiverImpl::GetEncodedVideoStreamTransformer() const {
  return internal_->GetEncodedVideoStreamTransformer();
}
}  // namespace blink

"""

```