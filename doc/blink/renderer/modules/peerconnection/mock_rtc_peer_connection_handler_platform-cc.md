Response:
Let's break down the thought process to analyze the provided C++ code.

1. **Understand the Goal:** The request asks for an analysis of `mock_rtc_peer_connection_handler_platform.cc`. The key is to identify its *purpose*, how it interacts with web technologies, and potential usage scenarios, especially for debugging.

2. **Initial Scan for Keywords and Structure:**  I'd first skim the code, looking for familiar terms related to WebRTC and testing. Keywords like "mock," "test," "dummy," "RTCPeerConnection," "RtpSender," "RtpReceiver," "MediaStream," "audio," "video," "transformer," "configuration," and "stats" immediately stand out. The `#include` directives also give clues about dependencies. The namespace `blink` confirms it's part of the Chromium rendering engine. The overall structure appears to define a class `MockRTCPeerConnectionHandlerPlatform` and several supporting "Dummy" classes.

3. **Identify the Core Class:** The name `MockRTCPeerConnectionHandlerPlatform` is highly suggestive. The "Mock" prefix usually indicates a class used for testing or simulation. The "RTCPeerConnectionHandlerPlatform" part implies it's a platform-specific implementation or abstraction for handling WebRTC peer connections.

4. **Analyze the "Dummy" Classes:** The presence of `DummyRTCRtpSenderPlatform`, `DummyRTCRtpReceiverPlatform`, and `DummyRTCRtpTransceiverPlatform` reinforces the "mocking" aspect. These classes likely provide simplified, simulated implementations of their real counterparts, without involving actual network communication or device interaction.

5. **Pinpoint Key Functionality by Examining Methods:**  I'd go through the methods of `MockRTCPeerConnectionHandlerPlatform`:

    * `Initialize`:  Suggests setup, but the implementation is trivial (`return true;`).
    * `CreateOffer`, `CreateAnswer`, `SetLocalDescription`, `SetRemoteDescription`: These are standard WebRTC API methods related to session negotiation. Their empty or trivial implementations in the mock suggest they don't perform real SDP handling.
    * `GetConfiguration`, `SetConfiguration`:  Manage configuration, but the mock uses a default configuration.
    * `AddIceCandidate`, `RestartIce`:  Related to ICE negotiation. The mock versions are empty.
    * `GetStats`:  Retrieves statistics. The mock version does nothing.
    * `AddTransceiverWithTrack`, `AddTransceiverWithKind`, `AddTrack`, `RemoveTrack`: These are core WebRTC methods for adding and removing media tracks. The mock implementations create instances of the "Dummy" transceiver classes.
    * `CreateDataChannel`: Creates data channels. The mock returns `nullptr`.
    * `Close`:  Closes the connection. The mock version does nothing.
    * `NativePeerConnection`: Returns a `webrtc::MockPeerConnectionInterface`. This is a strong indicator of its testing purpose.

6. **Analyze the "Dummy" Class Internals:**  Examining the methods of the `Dummy` classes:

    * They have simple constructors and destructors.
    * They often have an internal state (e.g., `DummyRtpSenderInternal`).
    * Methods like `Id()`, `Track()`, `StreamIds()` provide access to simulated data.
    * Methods like `ReplaceTrack()` and `SetParameters()` in `DummyRTCRtpSenderPlatform` indicate some level of simulated functionality.
    * The presence of `RTCEncodedAudioStreamTransformer` and `RTCEncodedVideoStreamTransformer` (even if seemingly unused) hints at potential future extensions for testing media processing.

7. **Identify Relationships to Web Technologies:**  Think about how the WebRTC API (JavaScript) interacts with the underlying browser implementation.

    * **JavaScript:** The `RTCPeerConnection` API in JavaScript is the primary entry point for using WebRTC. This mock class would be used in tests to simulate the behavior of the native peer connection handler when JavaScript code calls these APIs.
    * **HTML:**  HTML provides the `<video>` and `<audio>` elements where media streams are displayed. While this mock doesn't directly manipulate HTML, it simulates the creation and management of the underlying media tracks that would eventually be associated with these elements.
    * **CSS:** CSS styles the appearance of HTML elements. There's no direct interaction with CSS in this mock.

8. **Infer Use Cases and Debugging Relevance:**

    * **Testing:** The primary function is clearly for testing the Blink rendering engine's WebRTC implementation *without* requiring actual network connections or media devices.
    * **Isolation:**  It allows developers to isolate specific parts of the WebRTC stack and test their logic in a controlled environment.
    * **Predictable Behavior:** Mock objects provide predictable responses, making tests more reliable.
    * **Debugging:** If a bug occurs when using the real WebRTC implementation, using this mock can help determine if the issue lies within the core WebRTC logic or in the platform-specific handling.

9. **Construct Examples and Scenarios:**  Based on the analysis, create illustrative examples:

    * **JavaScript Interaction:** Show how a JavaScript call to `addTrack()` would interact with the mock, resulting in the creation of a `DummyRTCRtpTransceiverPlatform`.
    * **Logic Inference:** Demonstrate how the `RemoveTrack` method finds the relevant transceiver and updates its internal state.
    * **User Errors:** Think about common mistakes developers make when using the WebRTC API and how this mock might expose those issues during testing.
    * **Debugging Steps:**  Outline the steps a developer might take to reach this mock class while debugging a WebRTC issue.

10. **Review and Refine:** Read through the analysis, ensuring it's clear, accurate, and addresses all aspects of the original request. Check for any missing connections or potential misunderstandings. For instance, ensure the distinction between the "Mock" and the "Dummy" classes is clear.

This systematic approach, combining code analysis with knowledge of WebRTC and testing principles, leads to a comprehensive understanding of the `mock_rtc_peer_connection_handler_platform.cc` file.
这个文件 `mock_rtc_peer_connection_handler_platform.cc` 是 Chromium Blink 引擎中用于 **模拟 (mock)** `RTCPeerConnectionHandlerPlatform` 接口的实现。  `RTCPeerConnectionHandlerPlatform` 本身是一个抽象类，它定义了与底层平台 WebRTC 实现交互的接口。  这个 mock 版本主要用于 **单元测试** 和 **集成测试** Blink 引擎的 WebRTC 相关代码，而无需依赖真实的 WebRTC 平台实现或网络连接。

**主要功能：**

1. **模拟 WebRTC PeerConnection 的行为:**  它提供了一系列方法的空实现或简单实现，模拟了 `RTCPeerConnection` 的各种操作，例如创建 offer/answer、设置描述 (SDP)、添加 ICE candidate、添加/移除 track、创建 data channel 等。

2. **提供可控的测试环境:**  由于是 mock 实现，测试人员可以精确控制这些方法的行为和返回值，从而隔离被测试代码，更容易发现问题。

3. **方便单元测试:**  测试代码可以直接使用这个 mock 类，而不需要设置复杂的 WebRTC 环境或连接。

4. **模拟 RTP Sender/Receiver/Transceiver:**  文件中定义了 `DummyRTCRtpSenderPlatform`, `DummyRTCRtpReceiverPlatform`, 和 `DummyRTCRtpTransceiverPlatform` 等 "Dummy" 类，用于模拟 RTP 发送器、接收器和收发器。这些 dummy 类拥有基本的属性和方法，但不会进行真正的媒体传输或编解码。

5. **模拟媒体轨道 (MediaStreamTrack):**  在 `DummyRTCRtpReceiverPlatform` 中，可以看到它会创建 `MediaStreamComponentImpl` 和 `MediaStreamAudioTrack`/`MediaStreamVideoTrack` 的实例，但这些是模拟的本地或远程媒体轨道。

**与 JavaScript, HTML, CSS 的关系：**

这个 mock 文件本身是用 C++ 编写的，不直接包含 JavaScript, HTML 或 CSS 代码。 但是，它模拟的 `RTCPeerConnectionHandlerPlatform`  接口是 Blink 引擎中连接 JavaScript WebRTC API (例如 `RTCPeerConnection`) 和底层 C++ WebRTC 实现的关键桥梁。

* **JavaScript:** 当 JavaScript 代码调用 `RTCPeerConnection` 的方法（例如 `createOffer()`, `addTrack()`, `setRemoteDescription()`），Blink 引擎会将这些调用转换为对 `RTCPeerConnectionHandlerPlatform` 相应方法的调用。  在测试环境下，如果使用的是这个 mock 版本，那么 JavaScript 的调用最终会到达 `MockRTCPeerConnectionHandlerPlatform` 的方法。

    **举例:**
    * **假设输入 (JavaScript):**
      ```javascript
      const pc = new RTCPeerConnection();
      const stream = ...; // 获取一个 MediaStream
      const track = stream.getVideoTracks()[0];
      pc.addTrack(track, stream);
      ```
    * **对应 Mock 行为:**  `MockRTCPeerConnectionHandlerPlatform::AddTrack` 方法会被调用，它会创建一个 `DummyRTCRtpTransceiverPlatform` 实例并返回。  虽然没有真正的媒体流处理，但测试代码可以验证这个方法是否被调用，以及创建的 transceiver 是否符合预期。

* **HTML:**  HTML 中的 `<video>` 和 `<audio>` 元素用于显示媒体流。  虽然 mock 类不直接操作 HTML，但它模拟了媒体轨道的创建和管理，这些轨道最终会被传递给渲染引擎以在 HTML 元素中显示。

    **举例:**  当 JavaScript 通过 `pc.ontrack` 事件接收到远程轨道时，这个轨道在 Blink 内部对应着 `MediaStreamTrack` 和 `MediaStreamComponent` 等 C++ 对象。  在 mock 环境下，`DummyRTCRtpReceiverPlatform` 会创建模拟的这些对象，测试可以验证这些对象的属性。

* **CSS:** CSS 用于样式化 HTML 元素，与这个 mock 类的功能没有直接关系。

**逻辑推理与假设输入/输出：**

大部分方法都是空的或者返回预设值，逻辑推理较少。但一些方法涉及到对象创建和状态管理。

**假设输入 (C++):**  调用 `MockRTCPeerConnectionHandlerPlatform::AddTransceiverWithTrack` 方法，并传入一个代表视频轨道的 `MediaStreamComponent*` 指针。

**逻辑推理:**  `AddTransceiverWithTrack` 方法会创建一个 `DummyRTCRtpTransceiverPlatform` 对象，其内部的 `DummyTransceiverInternal` 会根据传入的 `MediaStreamComponent` 的类型 (视频) 初始化 sender 和 receiver。

**输出 (C++):** 返回一个指向新创建的 `DummyRTCRtpTransceiverPlatform` 对象的 `std::unique_ptr`。  这个 dummy transceiver 内部会有一个模拟的 sender 和 receiver，类型与输入的 track 相匹配。

**用户或编程常见的使用错误：**

由于这是一个 mock 类，它本身不太容易引起用户的直接使用错误。 然而，理解它的作用有助于避免在测试 WebRTC 代码时犯错：

1. **误以为 mock 类会进行真实的网络通信:**  新手可能会错误地认为使用了这个 mock 类就能进行真正的 WebRTC 通信，这是不可能的。 Mock 类只是为了测试本地逻辑，不涉及网络。

2. **过度依赖 mock 类的行为:**  如果 mock 类的实现与真实平台的行为有差异，过度依赖 mock 测试可能会导致在真实环境中出现问题。  因此，除了 mock 测试，还需要进行集成测试和端到端测试。

3. **没有正确理解 mock 类的局限性:**  Mock 类通常只模拟了部分功能，可能没有覆盖所有边缘情况或复杂的交互。测试人员需要清楚 mock 类的能力边界。

**用户操作如何一步步到达这里 (调试线索)：**

假设开发者正在调试一个使用 WebRTC 的网页应用，发现视频轨道无法正确添加或渲染。以下是可能的调试路径，最终可能会涉及到这个 mock 文件：

1. **用户操作:** 用户在网页上点击一个按钮，触发了添加本地视频轨道的 JavaScript 代码。
2. **JavaScript 代码执行:**  JavaScript 代码创建 `RTCPeerConnection` 对象，并调用 `addTrack()` 方法。
3. **Blink 引擎处理:** Blink 引擎接收到 JavaScript 的 `addTrack()` 调用。
4. **选择 `RTCPeerConnectionHandlerPlatform` 实现:** 在测试环境下，Blink 引擎可能会配置为使用 `MockRTCPeerConnectionHandlerPlatform` 而不是真实的平台实现。
5. **调用 `MockRTCPeerConnectionHandlerPlatform::AddTrack`:** JavaScript 的 `addTrack()` 调用最终会路由到这个 mock 类的 `AddTrack` 方法。
6. **Mock 行为:** `AddTrack` 方法创建了一个 `DummyRTCRtpTransceiverPlatform` 对象。
7. **测试断点 (如果设置):** 开发者可能在 `MockRTCPeerConnectionHandlerPlatform::AddTrack` 方法中设置了断点，以便检查调用参数和返回值，以及验证 mock 类的行为是否符合预期。

**作为调试线索，开发者可以：**

* **验证 `AddTrack` 是否被调用:** 通过断点或日志，确认 JavaScript 的 `addTrack()` 操作是否成功触发了 mock 类的对应方法。
* **检查传入的参数:** 查看传递给 `AddTrack` 的 `MediaStreamComponent` 是否正确，例如 track 的类型是否为视频。
* **了解 mock 类的行为:** 理解 mock 类创建的 `DummyRTCRtpTransceiverPlatform` 的特性，例如它不会进行真实的媒体协商或传输。
* **对比 mock 环境和真实环境:** 如果在 mock 测试中没有问题，但在真实环境中出现问题，这可能表明问题出在平台特定的 WebRTC 实现或网络交互部分，而不是 Blink 的核心逻辑。

总而言之，`mock_rtc_peer_connection_handler_platform.cc` 是一个测试工具，它通过提供一个可控的 `RTCPeerConnectionHandlerPlatform` 实现，帮助 Blink 引擎的开发者测试和验证其 WebRTC 相关代码的正确性。理解它的功能和局限性对于进行有效的 WebRTC 开发和调试至关重要。

### 提示词
```
这是目录为blink/renderer/modules/peerconnection/mock_rtc_peer_connection_handler_platform.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/peerconnection/mock_rtc_peer_connection_handler_platform.h"

#include <memory>
#include <utility>

#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_source.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_track.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component_impl.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_dtmf_sender_handler.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_encoded_audio_stream_transformer.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_encoded_video_stream_transformer.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_ice_candidate_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_rtp_sender_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_rtp_source.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_rtp_transceiver_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_session_description_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_stats.h"
#include "third_party/blink/renderer/platform/wtf/thread_safe_ref_counted.h"
#include "third_party/webrtc/api/stats/rtc_stats.h"

namespace blink {

namespace {

webrtc::PeerConnectionInterface::RTCConfiguration DefaultConfiguration() {
  webrtc::PeerConnectionInterface::RTCConfiguration config;
  config.sdp_semantics = webrtc::SdpSemantics::kUnifiedPlan;
  return config;
}

// Having a refcounted helper class allows multiple DummyRTCRtpSenderPlatform to
// share the same internal states.
class DummyRtpSenderInternal
    : public WTF::ThreadSafeRefCounted<DummyRtpSenderInternal> {
 private:
  static uintptr_t last_id_;

 public:
  explicit DummyRtpSenderInternal(MediaStreamComponent* component)
      : id_(++last_id_), component_(component) {}

  uintptr_t id() const { return id_; }
  MediaStreamComponent* track() const { return component_; }
  void set_track(MediaStreamComponent* component) { component_ = component; }

 private:
  const uintptr_t id_;
  Persistent<MediaStreamComponent> component_;
};

uintptr_t DummyRtpSenderInternal::last_id_ = 0;

class DummyRTCRtpSenderPlatform : public RTCRtpSenderPlatform {
 public:
  explicit DummyRTCRtpSenderPlatform(MediaStreamComponent* component)
      : internal_(base::MakeRefCounted<DummyRtpSenderInternal>(component)),
        audio_transformer_(std::make_unique<RTCEncodedAudioStreamTransformer>(
            blink::scheduler::GetSingleThreadTaskRunnerForTesting())),
        video_transformer_(std::make_unique<RTCEncodedVideoStreamTransformer>(
            blink::scheduler::GetSingleThreadTaskRunnerForTesting(),
            nullptr)) {}
  DummyRTCRtpSenderPlatform(const DummyRTCRtpSenderPlatform& other)
      : internal_(other.internal_),
        audio_transformer_(std::make_unique<RTCEncodedAudioStreamTransformer>(
            blink::scheduler::GetSingleThreadTaskRunnerForTesting())),
        video_transformer_(std::make_unique<RTCEncodedVideoStreamTransformer>(
            blink::scheduler::GetSingleThreadTaskRunnerForTesting(),
            nullptr)) {}
  ~DummyRTCRtpSenderPlatform() override = default;

  scoped_refptr<DummyRtpSenderInternal> internal() const { return internal_; }

  std::unique_ptr<RTCRtpSenderPlatform> ShallowCopy() const override {
    return nullptr;
  }
  uintptr_t Id() const override { return internal_->id(); }
  rtc::scoped_refptr<webrtc::DtlsTransportInterface> DtlsTransport() override {
    return nullptr;
  }
  webrtc::DtlsTransportInformation DtlsTransportInformation() override {
    static const webrtc::DtlsTransportInformation dummy(
        webrtc::DtlsTransportState::kNew);
    return dummy;
  }
  MediaStreamComponent* Track() const override { return internal_->track(); }
  Vector<String> StreamIds() const override {
    return Vector<String>({String::FromUTF8("DummyStringId")});
  }
  void ReplaceTrack(MediaStreamComponent*, RTCVoidRequest*) override {}
  std::unique_ptr<RtcDtmfSenderHandler> GetDtmfSender() const override {
    return nullptr;
  }
  std::unique_ptr<webrtc::RtpParameters> GetParameters() const override {
    return std::unique_ptr<webrtc::RtpParameters>();
  }
  void SetParameters(Vector<webrtc::RtpEncodingParameters>,
                     std::optional<webrtc::DegradationPreference>,
                     RTCVoidRequest*) override {}
  void GetStats(RTCStatsReportCallback) override {}
  void SetStreams(const Vector<String>& stream_ids) override {}

  RTCEncodedAudioStreamTransformer* GetEncodedAudioStreamTransformer()
      const override {
    return audio_transformer_.get();
  }

  RTCEncodedVideoStreamTransformer* GetEncodedVideoStreamTransformer()
      const override {
    return video_transformer_.get();
  }

 private:
  scoped_refptr<DummyRtpSenderInternal> internal_;
  std::unique_ptr<RTCEncodedAudioStreamTransformer> audio_transformer_;
  std::unique_ptr<RTCEncodedVideoStreamTransformer> video_transformer_;
};

class DummyRTCRtpReceiverPlatform : public RTCRtpReceiverPlatform {
 private:
  static uintptr_t last_id_;

 public:
  explicit DummyRTCRtpReceiverPlatform(MediaStreamSource::StreamType type)
      : id_(++last_id_),
        audio_transformer_(std::make_unique<RTCEncodedAudioStreamTransformer>(
            blink::scheduler::GetSingleThreadTaskRunnerForTesting())),
        video_transformer_(std::make_unique<RTCEncodedVideoStreamTransformer>(
            blink::scheduler::GetSingleThreadTaskRunnerForTesting(),
            nullptr)) {
    if (type == MediaStreamSource::StreamType::kTypeAudio) {
      auto* source = MakeGarbageCollected<MediaStreamSource>(
          String::FromUTF8("remoteAudioId"),
          MediaStreamSource::StreamType::kTypeAudio,
          String::FromUTF8("remoteAudioName"), /*remote=*/true,
          /*platform_source=*/nullptr);
      component_ = MakeGarbageCollected<MediaStreamComponentImpl>(
          source->Id(), source,
          std::make_unique<MediaStreamAudioTrack>(/*is_local_track=*/false));
    } else {
      DCHECK_EQ(type, MediaStreamSource::StreamType::kTypeVideo);
      auto platform_source = std::make_unique<MockMediaStreamVideoSource>();
      auto* platform_source_ptr = platform_source.get();
      auto* source = MakeGarbageCollected<MediaStreamSource>(
          String::FromUTF8("remoteVideoId"),
          MediaStreamSource::StreamType::kTypeVideo,
          String::FromUTF8("remoteVideoName"), /*remote=*/true,
          std::move(platform_source));
      component_ = MakeGarbageCollected<MediaStreamComponentImpl>(
          source->Id(), source,
          std::make_unique<MediaStreamVideoTrack>(
              platform_source_ptr,
              MediaStreamVideoSource::ConstraintsOnceCallback(),
              /*enabled=*/true));
    }
  }
  DummyRTCRtpReceiverPlatform(const DummyRTCRtpReceiverPlatform& other)
      : id_(other.id_),
        component_(other.component_),
        audio_transformer_(std::make_unique<RTCEncodedAudioStreamTransformer>(
            blink::scheduler::GetSingleThreadTaskRunnerForTesting())),
        video_transformer_(std::make_unique<RTCEncodedVideoStreamTransformer>(
            blink::scheduler::GetSingleThreadTaskRunnerForTesting(),
            nullptr)) {}
  ~DummyRTCRtpReceiverPlatform() override = default;

  std::unique_ptr<RTCRtpReceiverPlatform> ShallowCopy() const override {
    return nullptr;
  }
  uintptr_t Id() const override { return id_; }
  rtc::scoped_refptr<webrtc::DtlsTransportInterface> DtlsTransport() override {
    return nullptr;
  }
  webrtc::DtlsTransportInformation DtlsTransportInformation() override {
    static const webrtc::DtlsTransportInformation dummy(
        webrtc::DtlsTransportState::kNew);
    return dummy;
  }
  MediaStreamComponent* Track() const override { return component_; }
  Vector<String> StreamIds() const override { return Vector<String>(); }
  Vector<std::unique_ptr<RTCRtpSource>> GetSources() override {
    return Vector<std::unique_ptr<RTCRtpSource>>();
  }
  void GetStats(RTCStatsReportCallback) override {}
  std::unique_ptr<webrtc::RtpParameters> GetParameters() const override {
    return nullptr;
  }

  void SetJitterBufferMinimumDelay(
      std::optional<double> delay_seconds) override {}

  RTCEncodedAudioStreamTransformer* GetEncodedAudioStreamTransformer()
      const override {
    return audio_transformer_.get();
  }

  RTCEncodedVideoStreamTransformer* GetEncodedVideoStreamTransformer()
      const override {
    return video_transformer_.get();
  }

 private:
  const uintptr_t id_;
  Persistent<MediaStreamComponent> component_;
  std::unique_ptr<RTCEncodedAudioStreamTransformer> audio_transformer_;
  std::unique_ptr<RTCEncodedVideoStreamTransformer> video_transformer_;
};

uintptr_t DummyRTCRtpReceiverPlatform::last_id_ = 0;

// Having a refcounted helper class allows multiple
// DummyRTCRtpTransceiverPlatforms to share the same internal states.
class DummyTransceiverInternal
    : public WTF::ThreadSafeRefCounted<DummyTransceiverInternal> {
 private:
  static uintptr_t last_id_;

 public:
  DummyTransceiverInternal(MediaStreamSource::StreamType type,
                           MediaStreamComponent* sender_component)
      : id_(++last_id_),
        sender_(sender_component),
        receiver_(type),
        direction_(webrtc::RtpTransceiverDirection::kSendRecv) {
    DCHECK(!sender_.Track() ||
           sender_.Track()->GetSourceType() ==
               static_cast<MediaStreamSource::StreamType>(type));
  }

  uintptr_t id() const { return id_; }
  DummyRTCRtpSenderPlatform* sender() { return &sender_; }
  std::unique_ptr<DummyRTCRtpSenderPlatform> Sender() const {
    return std::make_unique<DummyRTCRtpSenderPlatform>(sender_);
  }
  DummyRTCRtpReceiverPlatform* receiver() { return &receiver_; }
  std::unique_ptr<DummyRTCRtpReceiverPlatform> Receiver() const {
    return std::make_unique<DummyRTCRtpReceiverPlatform>(receiver_);
  }
  webrtc::RtpTransceiverDirection direction() const { return direction_; }
  webrtc::RTCError set_direction(webrtc::RtpTransceiverDirection direction) {
    direction_ = direction;
    return webrtc::RTCError::OK();
  }

 private:
  const uintptr_t id_;
  DummyRTCRtpSenderPlatform sender_;
  DummyRTCRtpReceiverPlatform receiver_;
  webrtc::RtpTransceiverDirection direction_;
};

uintptr_t DummyTransceiverInternal::last_id_ = 0;

}  // namespace

class MockRTCPeerConnectionHandlerPlatform::DummyRTCRtpTransceiverPlatform
    : public RTCRtpTransceiverPlatform {
 public:
  DummyRTCRtpTransceiverPlatform(MediaStreamSource::StreamType type,
                                 MediaStreamComponent* component)
      : internal_(
            base::MakeRefCounted<DummyTransceiverInternal>(type, component)) {}
  DummyRTCRtpTransceiverPlatform(const DummyRTCRtpTransceiverPlatform& other)
      : internal_(other.internal_) {}
  ~DummyRTCRtpTransceiverPlatform() override {}

  scoped_refptr<DummyTransceiverInternal> internal() const { return internal_; }

  uintptr_t Id() const override { return internal_->id(); }
  String Mid() const override { return String(); }
  std::unique_ptr<RTCRtpSenderPlatform> Sender() const override {
    return internal_->Sender();
  }
  std::unique_ptr<RTCRtpReceiverPlatform> Receiver() const override {
    return internal_->Receiver();
  }
  webrtc::RtpTransceiverDirection Direction() const override {
    return internal_->direction();
  }
  webrtc::RTCError SetDirection(
      webrtc::RtpTransceiverDirection direction) override {
    return internal_->set_direction(direction);
  }
  std::optional<webrtc::RtpTransceiverDirection> CurrentDirection()
      const override {
    return std::nullopt;
  }
  std::optional<webrtc::RtpTransceiverDirection> FiredDirection()
      const override {
    return std::nullopt;
  }
  webrtc::RTCError Stop() override { return webrtc::RTCError::OK(); }
  webrtc::RTCError SetCodecPreferences(
      Vector<webrtc::RtpCodecCapability>) override {
    return webrtc::RTCError::OK();
  }
  webrtc::RTCError SetHeaderExtensionsToNegotiate(
      Vector<webrtc::RtpHeaderExtensionCapability> header_extensions) override {
    return webrtc::RTCError(webrtc::RTCErrorType::UNSUPPORTED_OPERATION);
  }
  Vector<webrtc::RtpHeaderExtensionCapability> GetNegotiatedHeaderExtensions()
      const override {
    return {};
  }
  Vector<webrtc::RtpHeaderExtensionCapability> GetHeaderExtensionsToNegotiate()
      const override {
    return {};
  }

 private:
  scoped_refptr<DummyTransceiverInternal> internal_;
};

MockRTCPeerConnectionHandlerPlatform::MockRTCPeerConnectionHandlerPlatform()
    : RTCPeerConnectionHandler(
          scheduler::GetSingleThreadTaskRunnerForTesting()),
      native_peer_connection_(webrtc::MockPeerConnectionInterface::Create()) {}

MockRTCPeerConnectionHandlerPlatform::~MockRTCPeerConnectionHandlerPlatform() =
    default;

bool MockRTCPeerConnectionHandlerPlatform::Initialize(
    ExecutionContext*,
    const webrtc::PeerConnectionInterface::RTCConfiguration&,
    WebLocalFrame*,
    ExceptionState&,
    RTCRtpTransport*) {
  return true;
}

Vector<std::unique_ptr<RTCRtpTransceiverPlatform>>
MockRTCPeerConnectionHandlerPlatform::CreateOffer(RTCSessionDescriptionRequest*,
                                                  RTCOfferOptionsPlatform*) {
  return {};
}

void MockRTCPeerConnectionHandlerPlatform::CreateAnswer(
    RTCSessionDescriptionRequest*,
    RTCAnswerOptionsPlatform*) {}

void MockRTCPeerConnectionHandlerPlatform::SetLocalDescription(
    RTCVoidRequest*) {}

void MockRTCPeerConnectionHandlerPlatform::SetLocalDescription(
    RTCVoidRequest*,
    ParsedSessionDescription) {}

void MockRTCPeerConnectionHandlerPlatform::SetRemoteDescription(
    RTCVoidRequest*,
    ParsedSessionDescription) {}

const webrtc::PeerConnectionInterface::RTCConfiguration&
MockRTCPeerConnectionHandlerPlatform::GetConfiguration() const {
  static const webrtc::PeerConnectionInterface::RTCConfiguration configuration =
      DefaultConfiguration();
  return configuration;
}

webrtc::RTCErrorType MockRTCPeerConnectionHandlerPlatform::SetConfiguration(
    const webrtc::PeerConnectionInterface::RTCConfiguration&) {
  return webrtc::RTCErrorType::NONE;
}

void MockRTCPeerConnectionHandlerPlatform::AddIceCandidate(
    RTCVoidRequest*,
    RTCIceCandidatePlatform*) {}

void MockRTCPeerConnectionHandlerPlatform::RestartIce() {}

void MockRTCPeerConnectionHandlerPlatform::GetStats(RTCStatsReportCallback) {}

webrtc::RTCErrorOr<std::unique_ptr<RTCRtpTransceiverPlatform>>
MockRTCPeerConnectionHandlerPlatform::AddTransceiverWithTrack(
    MediaStreamComponent* component,
    const webrtc::RtpTransceiverInit&) {
  transceivers_.push_back(std::make_unique<DummyRTCRtpTransceiverPlatform>(
      component->GetSourceType(), component));
  std::unique_ptr<DummyRTCRtpTransceiverPlatform> copy(
      new DummyRTCRtpTransceiverPlatform(*transceivers_.back()));
  return std::unique_ptr<RTCRtpTransceiverPlatform>(std::move(copy));
}

webrtc::RTCErrorOr<std::unique_ptr<RTCRtpTransceiverPlatform>>
MockRTCPeerConnectionHandlerPlatform::AddTransceiverWithKind(
    const String& kind,
    const webrtc::RtpTransceiverInit&) {
  transceivers_.push_back(std::make_unique<DummyRTCRtpTransceiverPlatform>(
      kind == "audio" ? MediaStreamSource::StreamType::kTypeAudio
                      : MediaStreamSource::StreamType::kTypeVideo,
      nullptr /*MediaStreamComponent*/));
  std::unique_ptr<DummyRTCRtpTransceiverPlatform> copy(
      new DummyRTCRtpTransceiverPlatform(*transceivers_.back()));
  return std::unique_ptr<RTCRtpTransceiverPlatform>(std::move(copy));
}

webrtc::RTCErrorOr<std::unique_ptr<RTCRtpTransceiverPlatform>>
MockRTCPeerConnectionHandlerPlatform::AddTrack(
    MediaStreamComponent* component,
    const MediaStreamDescriptorVector&) {
  transceivers_.push_back(std::make_unique<DummyRTCRtpTransceiverPlatform>(
      component->GetSourceType(), component));
  std::unique_ptr<DummyRTCRtpTransceiverPlatform> copy(
      new DummyRTCRtpTransceiverPlatform(*transceivers_.back()));
  return std::unique_ptr<RTCRtpTransceiverPlatform>(std::move(copy));
}

webrtc::RTCErrorOr<std::unique_ptr<RTCRtpTransceiverPlatform>>
MockRTCPeerConnectionHandlerPlatform::RemoveTrack(
    RTCRtpSenderPlatform* sender) {
  const DummyRTCRtpTransceiverPlatform* transceiver_of_sender = nullptr;
  for (const auto& transceiver : transceivers_) {
    if (transceiver->Sender()->Id() == sender->Id()) {
      transceiver_of_sender = transceiver.get();
      break;
    }
  }
  transceiver_of_sender->internal()->sender()->internal()->set_track(nullptr);
  std::unique_ptr<DummyRTCRtpTransceiverPlatform> copy(
      new DummyRTCRtpTransceiverPlatform(*transceiver_of_sender));
  return std::unique_ptr<RTCRtpTransceiverPlatform>(std::move(copy));
}

rtc::scoped_refptr<webrtc::DataChannelInterface>
MockRTCPeerConnectionHandlerPlatform::CreateDataChannel(
    const String& label,
    const webrtc::DataChannelInit&) {
  return nullptr;
}

void MockRTCPeerConnectionHandlerPlatform::Close() {}
void MockRTCPeerConnectionHandlerPlatform::CloseAndUnregister() {}

webrtc::PeerConnectionInterface*
MockRTCPeerConnectionHandlerPlatform::NativePeerConnection() {
  return native_peer_connection_.get();
}

void MockRTCPeerConnectionHandlerPlatform::
    RunSynchronousOnceClosureOnSignalingThread(base::OnceClosure closure,
                                               const char* trace_event_name) {}

void MockRTCPeerConnectionHandlerPlatform::TrackIceConnectionStateChange(
    webrtc::PeerConnectionInterface::IceConnectionState state) {}

}  // namespace blink
```