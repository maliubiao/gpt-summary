Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the `RTCRtpReceiver.cc` file, specifically focusing on its functionality, relationship with web technologies (JavaScript, HTML, CSS), logical reasoning, common usage errors, and debugging insights.

**2. Initial Skim and Keyword Identification:**

The first step is to quickly skim the code, looking for key terms and patterns. This involves identifying:

* **Class Name:** `RTCRtpReceiver` - This immediately tells us it's related to receiving RTP data.
* **Includes:**  Look at the included header files. These provide clues about dependencies and functionalities. For example, `rtc_rtp_receiver.h`, `rtc_rtp_sender.h`, `rtc_peer_connection.h`, `media_stream_track.h`, `readable_stream.h`, `writable_stream.h`,  `v8_rtc_...`, `identifiability_...`. This suggests it's part of the WebRTC implementation within Blink, deals with media tracks and streams, and interacts with JavaScript through V8 bindings. The `identifiability` headers indicate privacy-related features.
* **Member Variables:**  Variables like `receiver_`, `track_`, `streams_`, `encoded_audio_transformer_`, `encoded_video_transformer_`, `encoded_streams_`, `transform_`. These represent the internal state and connections of the receiver.
* **Methods:**  Focus on public methods like `track()`, `transport()`, `getStats()`, `createEncodedStreams()`, `getParameters()`, `setTransform()`, `getCapabilities()`. These are the entry points for interacting with this class.
* **Namespaces:** The code is within the `blink` namespace, confirming it's part of the Blink rendering engine.
* **Comments:** Look for comments like the copyright notice and any `TODO`s, which might offer insights.
* **Feature Flags:** The code checks for `kWebRtcEncodedTransformDirectCallback`, indicating feature toggles and potentially different implementation paths.
* **Locks:** The use of `base::AutoLock` suggests thread safety considerations.

**3. Deductive Reasoning about Functionality:**

Based on the identified keywords and structure, we can deduce the core functionalities:

* **Receiving RTP:**  The name `RTCRtpReceiver` and the inclusion of `RTCRtpReceiverPlatform` strongly indicate its primary role is to handle incoming RTP (Real-time Transport Protocol) packets.
* **Media Track Association:** The `track_` member and methods like `track()` clearly link the receiver to a specific media track (audio or video).
* **Media Streams:** The `streams_` member and the way it's initialized suggest the receiver is associated with one or more `MediaStream` objects.
* **Encoded Transforms (Insertable Streams):** The presence of `encoded_audio_transformer_`, `encoded_video_transformer_`, `encoded_streams_`, and methods like `createEncodedStreams()` points to the "Insertable Streams" feature, allowing JavaScript to access and manipulate raw encoded audio and video data.
* **RTCP Handling:** The `transport()` and `rtcpTransport()` methods suggest it interacts with the underlying transport layer (DTLS) for both RTP and RTCP (RTP Control Protocol).
* **Statistics Reporting:** The `getStats()` method indicates the ability to retrieve statistics about the receiver's performance.
* **Capabilities and Parameters:** The `getCapabilities()` and `getParameters()` methods deal with querying and obtaining codec and other configuration details.
* **Playout Delay and Jitter Buffer:**  The `playoutDelayHint` and `jitterBufferTarget` members and their corresponding setters suggest control over buffering and latency.
* **Synchronization and Contributing Sources (SSRC/CSRC):** The `getSynchronizationSources()` and `getContributingSources()` methods relate to identifying the sources of the media streams.
* **Transforms (Generic):** The `setTransform()` method indicates a more general mechanism for applying transformations to the received media.
* **Privacy:** The inclusion of `identifiability_...` headers suggests mechanisms for tracking and potentially limiting information leakage related to WebRTC usage.

**4. Connecting to Web Technologies:**

Now, consider how these functionalities relate to JavaScript, HTML, and CSS:

* **JavaScript:** The V8 bindings (`v8_rtc_...`) are the key. JavaScript uses the WebRTC API (e.g., `RTCPeerConnection`, `RTCRtpReceiver`) which are backed by these C++ classes. Methods like `getStats()`, `createEncodedStreams()`, `getParameters()`, `getCapabilities()`, and setters for playout delay and jitter buffer are directly exposed to JavaScript.
* **HTML:** While the core logic isn't directly manipulating the DOM, HTML plays a crucial role in setting up the WebRTC communication. The `<video>` and `<audio>` elements are where the received media is eventually rendered. JavaScript uses the `srcObject` property of these elements to bind the received `MediaStream` to the HTML elements.
* **CSS:** CSS has no direct impact on the functionality of `RTCRtpReceiver`. It's used for styling the video and audio elements, but the data processing happens independently.

**5. Logical Reasoning and Examples:**

Think about how the methods interact and what the inputs and outputs would be. For example, consider `setPlayoutDelayHint()`:

* **Input:** A JavaScript call with a numeric value for the hint.
* **Internal Processing:** The C++ code validates the input (non-negative) and then calls the platform-specific receiver (`receiver_->SetJitterBufferMinimumDelay()`).
* **Output:**  Potentially an exception thrown in JavaScript if the input is invalid. Internally, it affects the jitter buffer behavior.

Similarly, for `createEncodedStreams()`:

* **Assumptions:** The `RTCRtpReceiver` is for audio or video.
* **Input:** A JavaScript call to this method.
* **Internal Processing:**  The code checks if streams already exist or if it's too late to create them. If valid, it creates `ReadableStream` and `WritableStream` objects backed by C++ underlying sources and sinks that interact with the encoded data.
* **Output:** An `RTCInsertableStreams` object in JavaScript containing the readable and writable streams.

**6. Common Usage Errors:**

Consider what mistakes a developer might make when using this API:

* Calling `createEncodedStreams()` multiple times.
* Calling `createEncodedStreams()` after the short-circuiting has occurred.
* Providing invalid values for playout delay or jitter buffer target.
* Trying to attach a transform that is already in use.

**7. Debugging Clues:**

Think about how a developer might end up inspecting this code during debugging:

* **Scenario:**  Audio or video is not playing correctly, or there are issues with encoded transforms.
* **Steps:** The developer might:
    * Set breakpoints in JavaScript where WebRTC API calls are made.
    * Step through the JavaScript code and see calls to methods like `getStats()`, `createEncodedStreams()`, `setTransform()`.
    * Realize the issue might be in the native implementation and then look at the C++ code.
    * Examine logs (the `WebRtcLogMessage` calls are helpful here).
    * Inspect the values of member variables to understand the state of the receiver.

**8. Structuring the Answer:**

Finally, organize the information logically, using clear headings and examples. The prompt provides a good structure to follow. Start with a summary of the file's purpose, then delve into specific functionalities, web technology relationships, logical reasoning, common errors, and debugging tips. Use code snippets where relevant to illustrate points.

This methodical approach, starting with a high-level overview and progressively diving into details, ensures a comprehensive and accurate understanding of the code. It also focuses on addressing all aspects of the prompt.
Based on the provided C++ source code for `blink/renderer/modules/peerconnection/rtc_rtp_receiver.cc`, here's a breakdown of its functionality, relationships with web technologies, logical reasoning, potential user errors, and debugging insights:

**Functionality of `RTCRtpReceiver.cc`:**

This file implements the `RTCRtpReceiver` class in the Chromium Blink rendering engine. The core responsibility of this class is to **receive and process incoming Real-time Transport Protocol (RTP) streams** within a WebRTC PeerConnection. Here's a more detailed breakdown:

* **Receiving Media Data:** It handles the reception of RTP packets containing audio or video data. This involves interacting with the underlying platform-specific `RTCRtpReceiverPlatform` interface.
* **Associating with a Media Track:** Each `RTCRtpReceiver` is associated with a specific `MediaStreamTrack` (either audio or video). This track represents the logical media stream being received.
* **Managing Media Streams:** It keeps track of the `MediaStream`s that the received track belongs to.
* **DTLS Transport Information:** It holds a reference to the `RTCDtlsTransport` object responsible for the secure transport of the RTP stream.
* **Statistics Reporting:** It provides methods to retrieve statistics about the received RTP stream (`getStats()`), allowing monitoring of quality and performance.
* **Encoded Transform (Insertable Streams):**  It implements the "Insertable Streams" feature, allowing JavaScript to intercept and manipulate raw encoded audio and video frames. This involves:
    * Creating `ReadableStream` and `WritableStream` objects (`createEncodedStreams()`) that expose the encoded data.
    * Managing `RTCEncodedAudioUnderlyingSource/Sink` and `RTCEncodedVideoUnderlyingSource/Sink` to handle the flow of encoded data between the native receiver and the JavaScript streams.
    * Using `RTCEncodedAudioStreamTransformer` and `RTCEncodedVideoStreamTransformer` to bridge the gap between the native RTP processing and the JavaScript streams.
* **Generic Transforms:** It supports applying generic `RTCRtpScriptTransform` to the received media, allowing custom processing in JavaScript.
* **Synchronization and Contributing Sources (SSRC/CSRC):** It interacts with the `RtpContributingSourceCache` to provide information about the synchronization source (SSRC) and contributing sources (CSRC) of the received media.
* **Setting Playout Delay and Jitter Buffer:** It allows setting hints for the playout delay and target for the jitter buffer to manage latency and smoothness.
* **Capabilities and Parameters:** It provides methods to retrieve the capabilities (`getCapabilities()`) and parameters (`getParameters()`) of the RTP receiver, such as supported codecs and header extensions.
* **Privacy Considerations:** The inclusion of `identifiability_metrics.h` and related headers suggests mechanisms for tracking and potentially mitigating privacy risks associated with WebRTC usage.

**Relationship with JavaScript, HTML, and CSS:**

This C++ code is a fundamental part of the WebRTC implementation in the browser and has a direct relationship with JavaScript APIs.

* **JavaScript:**
    * **`RTCPeerConnection` API:**  The `RTCRtpReceiver` is created and managed by the `RTCPeerConnection` object in JavaScript. When a remote peer sends media, the `RTCPeerConnection` creates an `RTCRtpReceiver` to handle the incoming stream.
    * **`MediaStreamTrack` API:** The `track()` method returns the `MediaStreamTrack` associated with this receiver. This track is exposed to JavaScript and can be added to `<video>` or `<audio>` elements to render the media.
    * **`getStats()` method:**  JavaScript can call this method to retrieve statistics about the receiver, such as jitter, packet loss, and round-trip time.
    * **Insertable Streams API (`createEncodedStreams()`):**  JavaScript can call this method to obtain `ReadableStream` and `WritableStream` objects for intercepting and manipulating encoded audio and video frames. This allows advanced use cases like applying custom codecs, encryption, or analysis.
    * **`setTransform()` method:** JavaScript can use this method to set an `RTCRtpScriptTransform` object, enabling custom processing of the received media data in a JavaScript worker.
    * **`getCapabilities()` and `getParameters()` methods:** JavaScript can retrieve information about the receiver's capabilities and current settings.
    * **`playoutDelayHint` and `jitterBufferTarget` properties:** JavaScript can set these properties to influence the receiver's buffering behavior.

    **Example:**

    ```javascript
    // JavaScript code
    const peerConnection = new RTCPeerConnection();

    peerConnection.ontrack = (event) => {
      const receiver = event.receiver;
      const track = receiver.track;
      videoElement.srcObject = event.streams[0]; // Display received video

      receiver.getStats().then(stats => {
        stats.forEach(report => {
          if (report.type === 'inbound-rtp') {
            console.log('Received packets:', report.packetsReceived);
          }
        });
      });

      // Using Insertable Streams
      if (track.kind === 'video') {
        const encodedStreams = receiver.createEncodedStreams();
        encodedStreams.readable.pipeTo(new WritableStream({
          write(chunk) {
            // Process encoded video chunk
            console.log('Received encoded video frame:', chunk);
          }
        }));
      }
    };
    ```

* **HTML:**
    * **`<video>` and `<audio>` elements:**  The `MediaStreamTrack` obtained from the `RTCRtpReceiver` is typically assigned to the `srcObject` property of these HTML elements to display or play the received media.

* **CSS:** CSS has no direct functional relationship with `RTCRtpReceiver`. It's used for styling the `<video>` and `<audio>` elements.

**Logical Reasoning (Assumptions and Outputs):**

Let's consider a few examples of logical flow within this code:

1. **Setting Playout Delay Hint:**
   * **Assumption (Input):** JavaScript calls `receiver.playoutDelayHint = 0.1;` (setting a 100ms hint).
   * **Logical Steps:**
      * The `setPlayoutDelayHint` method in `RTCRtpReceiver.cc` is called.
      * It checks if the provided value (0.1) is non-negative.
      * If valid, it updates the internal `playout_delay_hint_` member.
      * It then calls `receiver_->SetJitterBufferMinimumDelay(0.1)` on the platform-specific receiver implementation.
   * **Output:** The underlying WebRTC engine attempts to maintain a jitter buffer of at least 100ms, influencing the playback smoothness and latency.

2. **Creating Encoded Video Streams:**
   * **Assumption (Input):** JavaScript calls `receiver.createEncodedStreams();` on a video receiver.
   * **Logical Steps:**
      * The `createEncodedVideoStreams` method is called.
      * It checks if encoded streams have already been created.
      * It creates an `RTCInsertableStreams` object.
      * It creates an `RTCEncodedVideoUnderlyingSource` which will receive encoded frames from the native receiver.
      * It creates a `ReadableStream` in JavaScript, backed by the underlying source.
      * It creates an `RTCEncodedVideoUnderlyingSink` which will send processed encoded frames back to the native decoder.
      * It creates a `WritableStream` in JavaScript, backed by the underlying sink.
      * It associates the readable and writable streams with the `RTCInsertableStreams` object.
   * **Output:** An `RTCInsertableStreams` object is returned to JavaScript, allowing access to the raw encoded video data.

3. **Receiving an Encoded Audio Frame (with Insertable Streams):**
   * **Assumption (Input):** The underlying WebRTC engine receives an encoded audio frame.
   * **Logical Steps:**
      * The platform receiver implementation notifies the `RTCEncodedAudioStreamTransformer`.
      * The transformer (if the feature flag is not enabled for direct callback) calls the `OnAudioFrameFromDepacketizer` method.
      * This method, in turn, pushes the encoded frame to the `RTCEncodedAudioUnderlyingSource`.
      * The underlying source's queue becomes non-empty, and the associated JavaScript `ReadableStream` can read the chunk.
   * **Output:** The encoded audio frame becomes available as a chunk in the JavaScript `ReadableStream`.

**User or Programming Common Usage Errors:**

* **Calling `createEncodedStreams()` multiple times:** The code explicitly checks for this and throws an `InvalidStateError`.
* **Calling `createEncodedStreams()` after a transform has been set or the short-circuit mechanism has activated:** This will also result in an `InvalidStateError`. The "short-circuit" is an optimization where, if JavaScript doesn't create encoded streams quickly, the native pipeline processes the media directly.
* **Providing negative values for `playoutDelayHint`:** The code validates this and throws a `TypeError`.
* **Providing out-of-range values for `jitterBufferTarget`:** The code validates this and throws a `RangeError`.
* **Trying to set a transform that is already in use:** The `setTransform()` method checks if the transform is attached and throws an `InvalidStateError`.
* **Incorrectly handling the `ReadableStream` and `WritableStream` obtained from `createEncodedStreams()`:**  For example, not properly piping the streams or introducing errors in the processing logic within the streams.
* **Forgetting to check the `track.kind` before calling audio or video specific methods like `createEncodedAudioStreams()` or `createEncodedVideoStreams()` implicitly.**

**User Operation Steps to Reach This Code (Debugging Clues):**

A developer might end up looking at this code when debugging issues related to receiving media in a WebRTC application. Here's a possible sequence of user actions:

1. **User opens a web page with WebRTC functionality.**
2. **The JavaScript code on the page establishes a `RTCPeerConnection` with a remote peer.**
3. **The remote peer starts sending audio or video data.**
4. **The browser's networking stack receives the RTP packets.**
5. **The browser's WebRTC implementation within Blink creates an `RTCRtpReceiver` object to handle the incoming stream.**
6. **The developer observes issues such as:**
   * **No audio or video playback:** This could indicate a problem in the receiver or the associated track.
   * **Choppy or delayed playback (jitter):** This might point to issues with the jitter buffer or network conditions.
   * **Errors when using Insertable Streams:** This could involve issues in the `createEncodedStreams()` call or the handling of the resulting streams.
   * **Problems with custom transforms:**  If a transform is set, errors in the transform's logic might lead to unexpected behavior.
7. **To debug, the developer might:**
   * **Inspect the `RTCPeerConnection` and its `getReceivers()` in the browser's developer tools.**
   * **Use `getStats()` in JavaScript to examine the receiver's statistics for packet loss, jitter, etc.**
   * **Set breakpoints in their JavaScript code where they interact with the `RTCRtpReceiver` API (e.g., `ontrack` handler, `createEncodedStreams`, `setTransform`).**
   * **If they suspect an issue in the browser's internal implementation, they might:**
     * **Enable WebRTC internal logging (e.g., using `chrome://webrtc-internals`).**  The `LogMessage` calls in this C++ code would appear in these logs.
     * **Attach a debugger to the browser process and set breakpoints in `rtc_rtp_receiver.cc` to examine the state of the `RTCRtpReceiver` object, the received packets, or the flow of data through the encoded streams or transforms.**  They might look at variables like `receiver_`, `track_`, the contents of the encoded stream queues, or the state of the transformers.

In essence, understanding the functionality of `RTCRtpReceiver.cc` is crucial for debugging any issues related to receiving and processing media streams within a WebRTC application. It's a key component that bridges the gap between the network and the JavaScript API, handling the complex task of managing incoming RTP data.

### 提示词
```
这是目录为blink/renderer/modules/peerconnection/rtc_rtp_receiver.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/peerconnection/rtc_rtp_receiver.h"

#include "base/numerics/safe_conversions.h"
#include "base/synchronization/lock.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_metric_builder.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_study_settings.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_surface.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_token_builder.h"
#include "third_party/blink/public/platform/modules/webrtc/webrtc_logging.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_insertable_streams.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_rtcp_parameters.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_rtp_capabilities.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_rtp_codec_parameters.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_rtp_decoding_parameters.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_rtp_header_extension_capability.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_rtp_header_extension_parameters.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/modules/peerconnection/identifiability_metrics.h"
#include "third_party/blink/renderer/modules/peerconnection/peer_connection_dependency_factory.h"
#include "third_party/blink/renderer/modules/peerconnection/peer_connection_features.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_dtls_transport.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_audio_receiver_sink_optimizer.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_audio_receiver_source_optimizer.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_audio_underlying_sink.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_audio_underlying_source.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_video_receiver_sink_optimizer.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_video_receiver_source_optimizer.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_video_underlying_sink.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_video_underlying_source.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_peer_connection.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_rtp_script_transform.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_rtp_sender.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_stats_report.h"
#include "third_party/blink/renderer/modules/peerconnection/web_rtc_stats_report_callback_resolver.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_encoded_video_stream_transformer.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_stats.h"
#include "third_party/blink/renderer/platform/privacy_budget/identifiability_digest_helpers.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/webrtc/api/rtp_parameters.h"

namespace blink {

RTCRtpReceiver::RTCRtpReceiver(RTCPeerConnection* pc,
                               std::unique_ptr<RTCRtpReceiverPlatform> receiver,
                               MediaStreamTrack* track,
                               MediaStreamVector streams,
                               bool require_encoded_insertable_streams,
                               scoped_refptr<base::SequencedTaskRunner>
                                   encoded_transform_shortcircuit_runner)
    : ExecutionContextLifecycleObserver(pc->GetExecutionContext()),
      pc_(pc),
      receiver_(std::move(receiver)),
      track_(track),
      streams_(std::move(streams)),
      encoded_audio_transformer_(
          track_->kind() == "audio"
              ? receiver_->GetEncodedAudioStreamTransformer()->GetBroker()
              : nullptr),
      encoded_video_transformer_(
          track_->kind() == "video"
              ? receiver_->GetEncodedVideoStreamTransformer()->GetBroker()
              : nullptr) {
  DCHECK(pc_);
  DCHECK(receiver_);
  DCHECK(track_);
  if (!base::FeatureList::IsEnabled(kWebRtcEncodedTransformDirectCallback)) {
    if (encoded_audio_transformer_) {
      RegisterEncodedAudioStreamCallback();
    } else if (encoded_video_transformer_) {
      CHECK(encoded_video_transformer_);
      RegisterEncodedVideoStreamCallback();
    }
  }

  if (!require_encoded_insertable_streams) {
    // We're not requiring JS to create encoded streams itself, so schedule a
    // task to shortcircuit the encoded transform if JS doesn't synchronously
    // create them - implementing
    // https://www.w3.org/TR/2023/WD-webrtc-encoded-transform-20231012/#stream-creation
    // step 12.

    encoded_transform_shortcircuit_runner->PostTask(
        FROM_HERE,
        WTF::BindOnce(&RTCRtpReceiver::MaybeShortCircuitEncodedStreams,
                      WrapPersistent(this)));
  }
}

MediaStreamTrack* RTCRtpReceiver::track() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return track_.Get();
}

RTCDtlsTransport* RTCRtpReceiver::transport() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return transport_.Get();
}

RTCDtlsTransport* RTCRtpReceiver::rtcpTransport() {
  // Chrome does not support turning off RTCP-mux.
  return nullptr;
}

std::optional<double> RTCRtpReceiver::playoutDelayHint() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return playout_delay_hint_;
}

void RTCRtpReceiver::setPlayoutDelayHint(std::optional<double> hint,
                                         ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (hint.has_value() && hint.value() < 0.0) {
    exception_state.ThrowTypeError("playoutDelayHint can't be negative");
    return;
  }

  playout_delay_hint_ = hint;
  receiver_->SetJitterBufferMinimumDelay(playout_delay_hint_);
}

std::optional<double> RTCRtpReceiver::jitterBufferTarget() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return jitter_buffer_target_;
}

void RTCRtpReceiver::setJitterBufferTarget(std::optional<double> target,
                                           ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (target.has_value() && (target.value() < 0.0 || target.value() > 4000.0)) {
    exception_state.ThrowRangeError(
        "jitterBufferTarget is out of expected range 0 to 4000 ms");
    return;
  }

  jitter_buffer_target_ = target;
  if (jitter_buffer_target_.has_value()) {
    receiver_->SetJitterBufferMinimumDelay(jitter_buffer_target_.value() /
                                           1000.0);
  } else {
    receiver_->SetJitterBufferMinimumDelay(std::nullopt);
  }
}

HeapVector<Member<RTCRtpSynchronizationSource>>
RTCRtpReceiver::getSynchronizationSources(ScriptState* script_state,
                                          ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return pc_->GetRtpContributingSourceCache().getSynchronizationSources(
      script_state, exception_state, this);
}

HeapVector<Member<RTCRtpContributingSource>>
RTCRtpReceiver::getContributingSources(ScriptState* script_state,
                                       ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return pc_->GetRtpContributingSourceCache().getContributingSources(
      script_state, exception_state, this);
}

ScriptPromise<RTCStatsReport> RTCRtpReceiver::getStats(
    ScriptState* script_state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<RTCStatsReport>>(script_state);
  auto promise = resolver->Promise();
  receiver_->GetStats(WTF::BindOnce(WebRTCStatsReportCallbackResolver,
                                    WrapPersistent(resolver)));
  return promise;
}

RTCInsertableStreams* RTCRtpReceiver::createEncodedStreams(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  LogMessage(base::StringPrintf("%s({transform_shortcircuited_=%s})", __func__,
                                transform_shortcircuited_ ? "true" : "false"));
  if (transform_shortcircuited_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Too late to create encoded streams");
    return nullptr;
  }
  if (encoded_streams_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Encoded streams already created");
    return nullptr;
  }

  if (kind() == MediaKind::kAudio) {
    return CreateEncodedAudioStreams(script_state);
  }
  CHECK_EQ(kind(), MediaKind::kVideo);
  return CreateEncodedVideoStreams(script_state);
}

RTCRtpReceiverPlatform* RTCRtpReceiver::platform_receiver() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return receiver_.get();
}

RTCRtpReceiver::MediaKind RTCRtpReceiver::kind() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (track_->kind() == "audio")
    return MediaKind::kAudio;
  DCHECK_EQ(track_->kind(), "video");
  return MediaKind::kVideo;
}

MediaStreamVector RTCRtpReceiver::streams() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return streams_;
}

void RTCRtpReceiver::set_streams(MediaStreamVector streams) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  streams_ = std::move(streams);
}

void RTCRtpReceiver::set_transceiver(RTCRtpTransceiver* transceiver) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  transceiver_ = transceiver;
}

void RTCRtpReceiver::set_transport(RTCDtlsTransport* transport) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  transport_ = transport;
}

V8RTCRtpTransceiverDirection RTCRtpReceiver::TransceiverDirection() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // `transceiver_` is always initialized to a valid value.
  return transceiver_->direction();
}

std::optional<V8RTCRtpTransceiverDirection>
RTCRtpReceiver::TransceiverCurrentDirection() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // `transceiver_` is always initialized to a valid value.
  return transceiver_->currentDirection();
}

void RTCRtpReceiver::ContextDestroyed() {
  {
    base::AutoLock locker(audio_underlying_source_lock_);
    audio_from_depacketizer_underlying_source_.Clear();
  }
  {
    base::AutoLock locker(audio_underlying_sink_lock_);
    audio_to_decoder_underlying_sink_.Clear();
  }
  {
    base::AutoLock locker(video_underlying_source_lock_);
    video_from_depacketizer_underlying_source_.Clear();
  }
  {
    base::AutoLock locker(video_underlying_sink_lock_);
    video_to_decoder_underlying_sink_.Clear();
  }
}

void RTCRtpReceiver::Trace(Visitor* visitor) const {
  visitor->Trace(pc_);
  visitor->Trace(track_);
  visitor->Trace(transport_);
  visitor->Trace(streams_);
  visitor->Trace(transceiver_);
  visitor->Trace(encoded_streams_);
  visitor->Trace(transform_);
  ScriptWrappable::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

RTCRtpCapabilities* RTCRtpReceiver::getCapabilities(ScriptState* state,
                                                    const String& kind) {
  if (kind != "audio" && kind != "video")
    return nullptr;

  RTCRtpCapabilities* capabilities = RTCRtpCapabilities::Create();
  capabilities->setCodecs(HeapVector<Member<RTCRtpCodecCapability>>());
  capabilities->setHeaderExtensions(
      HeapVector<Member<RTCRtpHeaderExtensionCapability>>());

  std::unique_ptr<webrtc::RtpCapabilities> rtc_capabilities =
      PeerConnectionDependencyFactory::From(*ExecutionContext::From(state))
          .GetReceiverCapabilities(kind);

  HeapVector<Member<RTCRtpCodecCapability>> codecs;
  codecs.ReserveInitialCapacity(
      base::checked_cast<wtf_size_t>(rtc_capabilities->codecs.size()));
  for (const auto& rtc_codec : rtc_capabilities->codecs) {
    auto* codec = RTCRtpCodecCapability::Create();
    codec->setMimeType(WTF::String::FromUTF8(rtc_codec.mime_type()));
    if (rtc_codec.clock_rate)
      codec->setClockRate(rtc_codec.clock_rate.value());
    if (rtc_codec.num_channels)
      codec->setChannels(rtc_codec.num_channels.value());
    if (!rtc_codec.parameters.empty()) {
      std::string sdp_fmtp_line;
      for (const auto& parameter : rtc_codec.parameters) {
        if (!sdp_fmtp_line.empty())
          sdp_fmtp_line += ";";
        if (parameter.first.empty()) {
          sdp_fmtp_line += parameter.second;
        } else {
          sdp_fmtp_line += parameter.first + "=" + parameter.second;
        }
      }
      codec->setSdpFmtpLine(sdp_fmtp_line.c_str());
    }
    codecs.push_back(codec);
  }
  capabilities->setCodecs(codecs);

  HeapVector<Member<RTCRtpHeaderExtensionCapability>> header_extensions;
  header_extensions.ReserveInitialCapacity(base::checked_cast<wtf_size_t>(
      rtc_capabilities->header_extensions.size()));
  for (const auto& rtc_header_extension : rtc_capabilities->header_extensions) {
    auto* header_extension = RTCRtpHeaderExtensionCapability::Create();
    header_extension->setUri(WTF::String::FromUTF8(rtc_header_extension.uri));
    header_extensions.push_back(header_extension);
  }
  capabilities->setHeaderExtensions(header_extensions);

  if (IdentifiabilityStudySettings::Get()->ShouldSampleType(
          IdentifiableSurface::Type::kRtcRtpReceiverGetCapabilities)) {
    IdentifiableTokenBuilder builder;
    IdentifiabilityAddRTCRtpCapabilitiesToBuilder(builder, *capabilities);
    IdentifiabilityMetricBuilder(ExecutionContext::From(state)->UkmSourceID())
        .Add(IdentifiableSurface::FromTypeAndToken(
                 IdentifiableSurface::Type::kRtcRtpReceiverGetCapabilities,
                 IdentifiabilityBenignStringToken(kind)),
             builder.GetToken())
        .Record(ExecutionContext::From(state)->UkmRecorder());
  }
  return capabilities;
}

RTCRtpReceiveParameters* RTCRtpReceiver::getParameters() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  RTCRtpReceiveParameters* parameters = RTCRtpReceiveParameters::Create();
  std::unique_ptr<webrtc::RtpParameters> webrtc_parameters =
      receiver_->GetParameters();

  RTCRtcpParameters* rtcp = RTCRtcpParameters::Create();
  rtcp->setReducedSize(webrtc_parameters->rtcp.reduced_size);
  parameters->setRtcp(rtcp);

  HeapVector<Member<RTCRtpDecodingParameters>> encodings;
  encodings.reserve(
      base::checked_cast<wtf_size_t>(webrtc_parameters->encodings.size()));
  for (const auto& webrtc_encoding : webrtc_parameters->encodings) {
    RTCRtpDecodingParameters* encoding = RTCRtpDecodingParameters::Create();
    if (!webrtc_encoding.rid.empty()) {
      // TODO(orphis): Add rid when supported by WebRTC
    }
    encodings.push_back(encoding);
  }
  parameters->setEncodings(encodings);

  HeapVector<Member<RTCRtpHeaderExtensionParameters>> headers;
  headers.reserve(base::checked_cast<wtf_size_t>(
      webrtc_parameters->header_extensions.size()));
  for (const auto& webrtc_header : webrtc_parameters->header_extensions) {
    headers.push_back(ToRtpHeaderExtensionParameters(webrtc_header));
  }
  parameters->setHeaderExtensions(headers);

  HeapVector<Member<RTCRtpCodecParameters>> codecs;
  codecs.reserve(
      base::checked_cast<wtf_size_t>(webrtc_parameters->codecs.size()));
  for (const auto& webrtc_codec : webrtc_parameters->codecs) {
    codecs.push_back(ToRtpCodecParameters(webrtc_codec));
  }
  parameters->setCodecs(codecs);

  return parameters;
}

void RTCRtpReceiver::RegisterEncodedAudioStreamCallback() {
  CHECK(!base::FeatureList::IsEnabled(kWebRtcEncodedTransformDirectCallback));
  // TODO(crbug.com/347915599): Delete this method once
  // kWebRtcEncodedTransformDirectCallback is fully launched.
  encoded_audio_transformer_->SetTransformerCallback(
      WTF::CrossThreadBindRepeating(
          &RTCRtpReceiver::OnAudioFrameFromDepacketizer,
          WrapCrossThreadWeakPersistent(this)));
}

void RTCRtpReceiver::UnregisterEncodedAudioStreamCallback() {
  // Threadsafe as this might be called from the realm to which a stream has
  // been transferred.
  encoded_audio_transformer_->ResetTransformerCallback();
}

void RTCRtpReceiver::SetAudioUnderlyingSource(
    RTCEncodedAudioUnderlyingSource* new_underlying_source,
    scoped_refptr<base::SingleThreadTaskRunner> new_source_task_runner) {
  if (!GetExecutionContext()) {
    // If our context is destroyed, then the RTCRtpReceiver, underlying
    // source(s), and transformer are about to be garbage collected, so there's
    // no reason to continue.
    return;
  }
  {
    base::AutoLock locker(audio_underlying_source_lock_);
    audio_from_depacketizer_underlying_source_->OnSourceTransferStarted();
    audio_from_depacketizer_underlying_source_ = new_underlying_source;
    if (base::FeatureList::IsEnabled(kWebRtcEncodedTransformDirectCallback)) {
      encoded_audio_transformer_->SetTransformerCallback(
          WTF::CrossThreadBindRepeating(
              &RTCEncodedAudioUnderlyingSource::OnFrameFromSource,
              audio_from_depacketizer_underlying_source_));
    }
  }

  encoded_audio_transformer_->SetSourceTaskRunner(
      std::move(new_source_task_runner));
}

void RTCRtpReceiver::SetAudioUnderlyingSink(
    RTCEncodedAudioUnderlyingSink* new_underlying_sink) {
  if (!GetExecutionContext()) {
    // If our context is destroyed, then the RTCRtpReceiver and underlying
    // sink(s) are about to be garbage collected, so there's no reason to
    // continue.
    return;
  }
  base::AutoLock locker(audio_underlying_sink_lock_);
  audio_to_decoder_underlying_sink_ = new_underlying_sink;
}

RTCInsertableStreams* RTCRtpReceiver::CreateEncodedAudioStreams(
    ScriptState* script_state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  CHECK(!encoded_streams_);

  encoded_streams_ = RTCInsertableStreams::Create();

  {
    base::AutoLock locker(audio_underlying_source_lock_);
    DCHECK(!audio_from_depacketizer_underlying_source_);

    // Set up readable.
    audio_from_depacketizer_underlying_source_ =
        MakeGarbageCollected<RTCEncodedAudioUnderlyingSource>(
            script_state,
            WTF::CrossThreadBindOnce(
                &RTCRtpReceiver::UnregisterEncodedAudioStreamCallback,
                WrapCrossThreadWeakPersistent(this)));

    auto set_underlying_source =
        WTF::CrossThreadBindRepeating(&RTCRtpReceiver::SetAudioUnderlyingSource,
                                      WrapCrossThreadWeakPersistent(this));
    auto disconnect_callback = WTF::CrossThreadBindOnce(
        &RTCRtpReceiver::UnregisterEncodedAudioStreamCallback,
        WrapCrossThreadWeakPersistent(this));
    // The high water mark for the readable stream is set to 0 so that frames
    // are removed from the queue right away, without introducing a new buffer.
    ReadableStream* readable_stream =
        ReadableStream::CreateWithCountQueueingStrategy(
            script_state, audio_from_depacketizer_underlying_source_,
            /*high_water_mark=*/0, AllowPerChunkTransferring(false),
            std::make_unique<RtcEncodedAudioReceiverSourceOptimizer>(
                std::move(set_underlying_source),
                std::move(disconnect_callback)));
    encoded_streams_->setReadable(readable_stream);

    if (base::FeatureList::IsEnabled(kWebRtcEncodedTransformDirectCallback)) {
      encoded_audio_transformer_->SetTransformerCallback(
          WTF::CrossThreadBindRepeating(
              &RTCEncodedAudioUnderlyingSource::OnFrameFromSource,
              audio_from_depacketizer_underlying_source_));
    }
  }

  WritableStream* writable_stream;
  {
    base::AutoLock locker(audio_underlying_sink_lock_);
    DCHECK(!audio_to_decoder_underlying_sink_);

    // Set up writable.
    audio_to_decoder_underlying_sink_ =
        MakeGarbageCollected<RTCEncodedAudioUnderlyingSink>(
            script_state, encoded_audio_transformer_,
            /*detach_frame_data_on_write=*/false);

    auto set_underlying_sink =
        WTF::CrossThreadBindOnce(&RTCRtpReceiver::SetAudioUnderlyingSink,
                                 WrapCrossThreadWeakPersistent(this));

    // The high water mark for the stream is set to 1 so that the stream seems
    // ready to write, but without queuing frames.
    writable_stream = WritableStream::CreateWithCountQueueingStrategy(
        script_state, audio_to_decoder_underlying_sink_,
        /*high_water_mark=*/1,
        std::make_unique<RtcEncodedAudioReceiverSinkOptimizer>(
            std::move(set_underlying_sink), encoded_audio_transformer_));
  }

  encoded_streams_->setWritable(writable_stream);
  return encoded_streams_;
}

void RTCRtpReceiver::setTransform(RTCRtpScriptTransform* transform,
                                  ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (transform_ == transform) {
    return;
  }
  if (!transform) {
    transform_->Detach();
    transform_ = nullptr;
    return;
  }
  if (transform->IsAttached()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Transform is already in use");
    return;
  }
  if (transform_) {
    transform_->Detach();
  }
  transform_ = transform;
  transform_->AttachToReceiver(this);

  if (kind() == MediaKind::kAudio) {
    transform_->CreateAudioUnderlyingSourceAndSink(
        WTF::CrossThreadBindOnce(
            &RTCRtpReceiver::UnregisterEncodedAudioStreamCallback,
            WrapCrossThreadWeakPersistent(this)),
        encoded_audio_transformer_);
    return;
  }
  CHECK(kind() == MediaKind::kVideo);
  transform_->CreateVideoUnderlyingSourceAndSink(
      WTF::CrossThreadBindOnce(
          &RTCRtpReceiver::UnregisterEncodedVideoStreamCallback,
          WrapCrossThreadWeakPersistent(this)),
      encoded_video_transformer_);
}

void RTCRtpReceiver::OnAudioFrameFromDepacketizer(
    std::unique_ptr<webrtc::TransformableAudioFrameInterface>
        encoded_audio_frame) {
  // TODO(crbug.com/347915599): Delete this method once
  // kWebRtcEncodedTransformDirectCallback is fully launched.
  CHECK(!base::FeatureList::IsEnabled(kWebRtcEncodedTransformDirectCallback));

  base::AutoLock locker(audio_underlying_source_lock_);
  if (audio_from_depacketizer_underlying_source_) {
    audio_from_depacketizer_underlying_source_->OnFrameFromSource(
        std::move(encoded_audio_frame));
  }
}

void RTCRtpReceiver::RegisterEncodedVideoStreamCallback() {
  CHECK(!base::FeatureList::IsEnabled(kWebRtcEncodedTransformDirectCallback));
  // TODO(crbug.com/347915599): Delete this method once
  // kWebRtcEncodedTransformDirectCallback is fully launched.
  encoded_video_transformer_->SetTransformerCallback(
      WTF::CrossThreadBindRepeating(
          &RTCRtpReceiver::OnVideoFrameFromDepacketizer,
          WrapCrossThreadWeakPersistent(this)));
}

void RTCRtpReceiver::UnregisterEncodedVideoStreamCallback() {
  // Threadsafe as this might be called from the realm to which a stream has
  // been transferred.
  encoded_video_transformer_->ResetTransformerCallback();
}

void RTCRtpReceiver::SetVideoUnderlyingSource(
    RTCEncodedVideoUnderlyingSource* new_underlying_source,
    scoped_refptr<base::SingleThreadTaskRunner> new_source_task_runner) {
  if (!GetExecutionContext()) {
    // If our context is destroyed, then the RTCRtpReceiver, underlying
    // source(s), and transformer are about to be garbage collected, so there's
    // no reason to continue.
    return;
  }
  {
    base::AutoLock locker(video_underlying_source_lock_);
    video_from_depacketizer_underlying_source_->OnSourceTransferStarted();
    video_from_depacketizer_underlying_source_ = new_underlying_source;
    if (base::FeatureList::IsEnabled(kWebRtcEncodedTransformDirectCallback)) {
      encoded_video_transformer_->SetTransformerCallback(
          WTF::CrossThreadBindRepeating(
              &RTCEncodedVideoUnderlyingSource::OnFrameFromSource,
              video_from_depacketizer_underlying_source_));
    }
  }

  encoded_video_transformer_->SetSourceTaskRunner(
      std::move(new_source_task_runner));
}

void RTCRtpReceiver::SetVideoUnderlyingSink(
    RTCEncodedVideoUnderlyingSink* new_underlying_sink) {
  if (!GetExecutionContext()) {
    // If our context is destroyed, then the RTCRtpReceiver and underlying
    // sink(s) are about to be garbage collected, so there's no reason to
    // continue.
    return;
  }
  base::AutoLock locker(video_underlying_sink_lock_);
  video_to_decoder_underlying_sink_ = new_underlying_sink;
}

void RTCRtpReceiver::MaybeShortCircuitEncodedStreams() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!encoded_streams_ && !transform_) {
    transform_shortcircuited_ = true;
    LogMessage("Starting short circuiting of transform");
    if (kind() == MediaKind::kVideo) {
      encoded_video_transformer_->StartShortCircuiting();
    } else {
      CHECK_EQ(kind(), MediaKind::kAudio);
      encoded_audio_transformer_->StartShortCircuiting();
    }
  }
}

RTCInsertableStreams* RTCRtpReceiver::CreateEncodedVideoStreams(
    ScriptState* script_state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  CHECK(!encoded_streams_);

  encoded_streams_ = RTCInsertableStreams::Create();

  {
    base::AutoLock locker(video_underlying_source_lock_);
    DCHECK(!video_from_depacketizer_underlying_source_);

    // Set up readable.
    video_from_depacketizer_underlying_source_ =
        MakeGarbageCollected<RTCEncodedVideoUnderlyingSource>(
            script_state,
            WTF::CrossThreadBindOnce(
                &RTCRtpReceiver::UnregisterEncodedVideoStreamCallback,
                WrapCrossThreadWeakPersistent(this)));

    auto set_underlying_source =
        WTF::CrossThreadBindRepeating(&RTCRtpReceiver::SetVideoUnderlyingSource,
                                      WrapCrossThreadWeakPersistent(this));
    auto disconnect_callback = WTF::CrossThreadBindOnce(
        &RTCRtpReceiver::UnregisterEncodedVideoStreamCallback,
        WrapCrossThreadWeakPersistent(this));
    // The high water mark for the readable stream is set to 0 so that frames
    // are removed from the queue right away, without introducing a new buffer.
    ReadableStream* readable_stream =
        ReadableStream::CreateWithCountQueueingStrategy(
            script_state, video_from_depacketizer_underlying_source_,
            /*high_water_mark=*/0, AllowPerChunkTransferring(false),
            std::make_unique<RtcEncodedVideoReceiverSourceOptimizer>(
                std::move(set_underlying_source),
                std::move(disconnect_callback)));
    encoded_streams_->setReadable(readable_stream);

    if (base::FeatureList::IsEnabled(kWebRtcEncodedTransformDirectCallback)) {
      encoded_video_transformer_->SetTransformerCallback(
          WTF::CrossThreadBindRepeating(
              &RTCEncodedVideoUnderlyingSource::OnFrameFromSource,
              video_from_depacketizer_underlying_source_));
    }
  }

  WritableStream* writable_stream;
  {
    base::AutoLock locker(video_underlying_sink_lock_);
    DCHECK(!video_to_decoder_underlying_sink_);

    // Set up writable.
    video_to_decoder_underlying_sink_ =
        MakeGarbageCollected<RTCEncodedVideoUnderlyingSink>(
            script_state, encoded_video_transformer_,
            /*detach_frame_data_on_write=*/false);

    auto set_underlying_sink =
        WTF::CrossThreadBindOnce(&RTCRtpReceiver::SetVideoUnderlyingSink,
                                 WrapCrossThreadWeakPersistent(this));

    // The high water mark for the stream is set to 1 so that the stream seems
    // ready to write, but without queuing frames.
    writable_stream = WritableStream::CreateWithCountQueueingStrategy(
        script_state, video_to_decoder_underlying_sink_,
        /*high_water_mark=*/1,
        std::make_unique<RtcEncodedVideoReceiverSinkOptimizer>(
            std::move(set_underlying_sink), encoded_video_transformer_));
  }

  encoded_streams_->setWritable(writable_stream);
  return encoded_streams_;
}

void RTCRtpReceiver::OnVideoFrameFromDepacketizer(
    std::unique_ptr<webrtc::TransformableVideoFrameInterface>
        encoded_video_frame) {
  // TODO(crbug.com/347915599): Delete this method once
  // kWebRtcEncodedTransformDirectCallback is fully launched.
  CHECK(!base::FeatureList::IsEnabled(kWebRtcEncodedTransformDirectCallback));

  base::AutoLock locker(video_underlying_source_lock_);
  if (video_from_depacketizer_underlying_source_) {
    video_from_depacketizer_underlying_source_->OnFrameFromSource(
        std::move(encoded_video_frame));
  }
}

void RTCRtpReceiver::LogMessage(const std::string& message) {
  blink::WebRtcLogMessage(
      base::StringPrintf("RtpRcvr::%s [this=0x%" PRIXPTR "]", message.c_str(),
                         reinterpret_cast<uintptr_t>(this)));
}

}  // namespace blink
```