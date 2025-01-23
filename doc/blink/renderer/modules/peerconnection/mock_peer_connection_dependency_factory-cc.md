Response:
Let's break down the thought process for analyzing this C++ file.

1. **Understand the Goal:** The request asks for the functionalities of `mock_peer_connection_dependency_factory.cc`, its relationship to web technologies, and common errors/debugging.

2. **Identify the Core Class:** The filename itself is a huge clue: `MockPeerConnectionDependencyFactory`. The word "Mock" strongly suggests this is for testing or a controlled environment, not production code. "DependencyFactory" implies it creates and manages dependencies, likely related to WebRTC's peer connection functionality.

3. **Scan for Key WebRTC Concepts:** Look for familiar WebRTC terms and their corresponding C++ classes from the `third_party/webrtc` directory. We see:
    * `PeerConnectionInterface`
    * `MediaStreamInterface`
    * `AudioTrackInterface`, `VideoTrackInterface`
    * `AudioSourceInterface`, `VideoTrackSourceInterface`
    * `IceCandidateInterface`
    * `SessionDescriptionInterface` (implicitly through `SetFailToCreateSessionDescription`)
    * `Metronome`

4. **Analyze the Mock Implementations:**  For each of the key WebRTC interfaces, notice the corresponding "Mock" classes in this file (e.g., `MockPeerConnectionImpl`, `MockMediaStream`, `MockWebRtcAudioTrack`, etc.). This confirms the purpose of the file: to provide controllable, simplified implementations for testing.

5. **Examine the Functionality of Each Mock Class:** Go through each mock class and understand its core purpose and how it deviates from a real implementation.
    * **`FakeMetronome`:** Immediately obvious – a simplified metronome that calls the callback directly.
    * **`MockWebRtcAudioSource`:**  Simple state management (`kLive`, `remote`).
    * **`MockMediaStream`:**  Manages lists of audio and video tracks. Key methods are `AddTrack`, `RemoveTrack`, and finding tracks. The `NotifyObservers` pattern is typical in WebRTC.
    * **`MockWebRtcAudioTrack`:**  Manages enabled state and a simple "ended" state. Holds a reference to a `MockWebRtcAudioSource`.
    * **`MockWebRtcVideoTrack`:** Similar to `MockWebRtcAudioTrack`, but with added sink management (`AddOrUpdateSink`, `RemoveSink`).
    * **`MockWebRtcVideoTrackSource`:**  Simple state and a flag for encoded output support.
    * **`MockIceCandidate`:**  Holds basic ICE candidate information (sdp_mid, sdp_mline_index, sdp).

6. **Focus on `MockPeerConnectionDependencyFactory`:**  This is the central class. Its primary function is to *create* instances of the mock WebRTC components. Notice the `Create...` methods for each type. The `SetFailToCreateSessionDescription` method stands out as a way to control error conditions in tests. The thread management for signaling and networking is also important.

7. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:**  The most direct link. WebRTC APIs are exposed through JavaScript. This factory provides the *underlying* implementation used when JavaScript calls `new RTCPeerConnection()`, `createMediaStreamTrack()`, etc. The examples should show how JavaScript actions lead to the use of these mock objects.
    * **HTML:**  HTML provides the structure for web pages. Media elements (`<video>`, `<audio>`) are used to display media from WebRTC. Permissions UI, triggered by JavaScript WebRTC calls, is also relevant.
    * **CSS:**  While CSS styles the presentation, it doesn't directly interact with the core logic of WebRTC provided by this factory. The connection is indirect: CSS affects the appearance of the video/audio elements that *display* the media.

8. **Consider Logical Reasoning and Input/Output:**  For the mock classes, think about how they would behave in a simplified scenario. For example, adding a track to a `MockMediaStream` should result in that track being found. Setting the "ended" state of a track should trigger observer notifications.

9. **Identify Potential Usage Errors:** Think about common mistakes developers make when using WebRTC and how these mocks might expose or prevent those errors. For example, trying to remove a non-existent track, incorrect observer registration/unregistration, or assuming a synchronous behavior when WebRTC is generally asynchronous.

10. **Trace User Actions to the Code:**  Think about the steps a user takes that would lead to the execution of WebRTC code and potentially the use of these mocks (especially in testing). This involves:
    * Opening a web page with WebRTC functionality.
    * Granting media permissions.
    * JavaScript calling WebRTC APIs.
    * The browser's internal implementation (Blink) using the dependency factory.

11. **Structure the Answer:** Organize the information logically with clear headings. Start with the high-level purpose, then detail the functionalities, connections to web technologies, logical reasoning, potential errors, and finally the user action tracing. Use bullet points and examples for clarity.

12. **Refine and Review:**  Read through the generated answer and ensure it's accurate, comprehensive, and easy to understand. Check for any missing connections or areas that could be explained more clearly. For example, initially, I might have missed the nuance of *how* this factory is used in testing. Emphasizing its role in providing controlled environments is crucial.

By following these steps, we can systematically analyze the C++ code and provide a detailed and informative answer that addresses all aspects of the request.
这个文件 `mock_peer_connection_dependency_factory.cc` 是 Chromium Blink 渲染引擎中，专门为 **WebRTC PeerConnection 功能提供模拟 (mock) 依赖项** 的一个文件。它的主要目的是为了方便进行单元测试和集成测试，在不需要真实的网络和设备的情况下，模拟 WebRTC 相关的各种组件的行为。

以下是该文件的详细功能列表：

**核心功能：提供 Mock 对象以替代真实的 WebRTC 实现**

* **`MockPeerConnectionDependencyFactory` 类:**
    * **作为工厂类:** 它的主要职责是创建和提供各种 WebRTC 接口的模拟实现。
    * **线程管理:**  它内部创建并管理一个模拟的信令和网络线程 (`thread_`)，用于模拟 WebRTC 的异步操作。
    * **控制模拟行为:**  例如，提供了 `SetFailToCreateSessionDescription` 方法来模拟创建 Session Description 失败的情况。

* **模拟 PeerConnection:**
    * **`MockPeerConnectionImpl`:**  模拟 `webrtc::PeerConnectionInterface` 的行为，用于测试 PeerConnection 的生命周期、信令交换等逻辑。

* **模拟 MediaStream 和 Track:**
    * **`MockMediaStream`:** 模拟 `webrtc::MediaStreamInterface`，包含添加、删除音视频轨道的逻辑。
    * **`MockWebRtcAudioTrack`:** 模拟 `webrtc::AudioTrackInterface`，包含启用/禁用、设置结束状态等功能。
    * **`MockWebRtcVideoTrack`:** 模拟 `webrtc::VideoTrackInterface`，除了基本功能外，还模拟了 Sink 的添加和移除。
    * **`MockWebRtcAudioSource`:** 模拟 `webrtc::AudioSourceInterface`。
    * **`MockWebRtcVideoTrackSource`:** 模拟 `webrtc::VideoTrackSourceInterface`，可以设置是否支持编码输出。

* **模拟 ICE Candidate:**
    * **`MockIceCandidate`:** 模拟 `webrtc::IceCandidateInterface`，用于测试 ICE 协商过程。

* **模拟 Metronome:**
    * **`FakeMetronome`:** 模拟 `webrtc::Metronome`，用于控制某些定时操作，在模拟环境中通常直接执行回调。

**与 JavaScript, HTML, CSS 的关系：**

这个文件本身是 C++ 代码，并不直接与 JavaScript, HTML, CSS 代码交互。但是，它所模拟的 WebRTC 功能是通过 JavaScript API 暴露给 web 开发者的。

* **JavaScript:**
    * 当 JavaScript 代码调用 `new RTCPeerConnection()` 创建一个 PeerConnection 对象时，在 Chromium 内部，`MockPeerConnectionDependencyFactory` 可以被配置为提供 `MockPeerConnectionImpl` 的实例，而不是真实的 WebRTC 实现。
    * 当 JavaScript 代码调用 `createMediaStreamTrack()` 创建音视频轨道时，可以使用 `MockWebRtcAudioTrack` 或 `MockWebRtcVideoTrack` 的实例进行测试。
    * 当 JavaScript 代码处理 ICE Candidate 或者 Session Description 时，可以使用 `MockIceCandidate` 来模拟不同的候选者信息。

* **HTML:**
    * HTML 中的 `<video>` 和 `<audio>` 元素用于展示来自 WebRTC 的媒体流。在测试中，可以使用 Mock 的 MediaStream 和 Track 来模拟这些媒体流，而无需真实的摄像头和麦克风。

* **CSS:**
    * CSS 用于控制 HTML 元素的样式，与这个 mock 工厂的直接关系较弱。但 CSS 可以影响 `<video>` 和 `<audio>` 元素的显示效果，从而间接影响用户对 WebRTC 功能的感知。

**举例说明：**

**假设输入 (在测试代码中)：**

```c++
// 在测试代码中配置使用 Mock 工厂
MockPeerConnectionDependencyFactory mock_factory;
ScopedTestingWebFrame testing_web_frame;

// 创建一个 PeerConnection 的配置
webrtc::PeerConnectionInterface::RTCConfiguration config;

// 创建一个模拟的 PeerConnection 对象
rtc::scoped_refptr<webrtc::PeerConnectionInterface> pc =
    mock_factory.CreatePeerConnection(
        config, testing_web_frame.GetFrame(), nullptr, exception_state);

// 创建一个模拟的本地 MediaStream
scoped_refptr<webrtc::MediaStreamInterface> local_stream =
    mock_factory.CreateLocalMediaStream("localStream");

// 创建一个模拟的音频 Track
scoped_refptr<webrtc::AudioTrackInterface> audio_track =
    MockWebRtcAudioTrack::Create("audioTrack");

local_stream->AddTrack(audio_track);
```

**输出 (模拟的行为)：**

* `mock_factory.CreatePeerConnection` 会返回一个 `MockPeerConnectionImpl` 的实例。
* `mock_factory.CreateLocalMediaStream` 会返回一个 `MockMediaStream` 的实例，其 ID 为 "localStream"。
* `MockWebRtcAudioTrack::Create` 会创建一个模拟的音频轨道对象。
* `local_stream->AddTrack(audio_track)` 会将模拟的音频轨道添加到模拟的媒体流中。

**用户或编程常见的使用错误举例：**

* **错误地假设 Mock 对象与真实对象的行为完全一致:**  Mock 对象是为了简化测试，可能只实现了真实对象的部分功能。开发者不能假设 Mock 对象的行为与真实 WebRTC 组件完全相同，需要在测试用例中明确模拟所需的行为。例如，Mock 的 ICE 协商可能非常简单，与真实的 ICE 协商过程有很大差异。
* **过度依赖 Mock 对象进行测试:**  虽然 Mock 对象方便单元测试，但过度依赖 Mock 对象可能导致忽略真实环境中的问题。集成测试和端到端测试仍然很重要，以确保在真实网络和设备条件下 WebRTC 功能的正确性。
* **没有正确配置 Mock 工厂:**  如果在测试代码中没有正确地将 `MockPeerConnectionDependencyFactory` 注入到需要使用 WebRTC 功能的组件中，那么实际使用的仍然是真实的 WebRTC 实现，导致测试没有达到预期的 Mock 效果。

**用户操作如何一步步到达这里 (调试线索)：**

假设用户在使用一个包含 WebRTC 功能的网页：

1. **用户打开网页:** 浏览器加载 HTML、CSS 和 JavaScript 代码。
2. **JavaScript 代码执行:** JavaScript 代码调用 WebRTC API，例如 `navigator.mediaDevices.getUserMedia()` 获取本地媒体流，或者 `new RTCPeerConnection()` 创建 PeerConnection 对象。
3. **Blink 引擎处理 WebRTC API 调用:** 当 JavaScript 调用 WebRTC API 时，Blink 引擎会负责处理这些调用。
4. **PeerConnection 的创建:** 如果是创建 `RTCPeerConnection`，Blink 引擎会使用 `PeerConnectionDependencyFactory` 来创建底层的 WebRTC 组件。
5. **在测试环境下使用 Mock 工厂:**  在运行单元测试或集成测试时，测试框架会配置 Blink 引擎使用 `MockPeerConnectionDependencyFactory` 而不是默认的工厂。
6. **`MockPeerConnectionDependencyFactory` 创建 Mock 对象:** 当 Blink 引擎需要创建例如 `PeerConnectionInterface` 或 `MediaStreamInterface` 的实例时，`MockPeerConnectionDependencyFactory` 会返回相应的 Mock 对象，例如 `MockPeerConnectionImpl` 或 `MockMediaStream`。

**作为调试线索：**

* **检查测试配置:** 如果在测试 WebRTC 相关功能时遇到问题，首先要确认测试环境是否正确配置了 `MockPeerConnectionDependencyFactory`。
* **查看 Mock 对象的实现:**  如果测试结果与预期不符，可以查看 `MockPeerConnectionDependencyFactory` 中 Mock 对象的具体实现，了解它们模拟了哪些行为，是否与测试用例的需求一致。
* **断点调试 Mock 对象:** 可以在 `MockPeerConnectionDependencyFactory` 和其创建的 Mock 对象的代码中设置断点，跟踪代码的执行流程，查看 Mock 对象的内部状态，帮助理解测试过程中的行为。
* **对比 Mock 对象和真实对象的行为:**  在调试过程中，可以将 Mock 对象的行为与真实 WebRTC 组件的行为进行对比，找出差异，从而定位问题所在。这可能涉及到查看真实的 WebRTC 实现代码。

总而言之，`mock_peer_connection_dependency_factory.cc` 是一个关键的测试辅助文件，它通过提供可控的模拟对象，使得 WebRTC 相关的代码更容易进行单元测试和集成测试，而无需依赖真实的硬件和网络环境。理解其功能对于进行 Chromium Blink 引擎中 WebRTC 模块的开发和调试至关重要。

### 提示词
```
这是目录为blink/renderer/modules/peerconnection/mock_peer_connection_dependency_factory.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/peerconnection/mock_peer_connection_dependency_factory.h"

#include <stddef.h>

#include "base/containers/contains.h"
#include "base/not_fatal_until.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/renderer/modules/peerconnection/mock_peer_connection_impl.h"
#include "third_party/blink/renderer/modules/peerconnection/mock_rtc_peer_connection_handler_platform.h"
#include "third_party/webrtc/api/media_stream_interface.h"
#include "third_party/webrtc/api/metronome/metronome.h"
#include "third_party/webrtc/api/scoped_refptr.h"
#include "third_party/webrtc/api/units/time_delta.h"

using webrtc::AudioSourceInterface;
using webrtc::AudioTrackInterface;
using webrtc::AudioTrackVector;
using webrtc::IceCandidateCollection;
using webrtc::IceCandidateInterface;
using webrtc::MediaStreamInterface;
using webrtc::ObserverInterface;
using webrtc::SessionDescriptionInterface;
using webrtc::VideoTrackInterface;
using webrtc::VideoTrackSourceInterface;
using webrtc::VideoTrackVector;

namespace blink {

namespace {
// TODO(crbug.com/1502070): Migrate to webrtc::FakeMetronome once it's
// exported.
class FakeMetronome : public webrtc::Metronome {
 public:
  void RequestCallOnNextTick(absl::AnyInvocable<void() &&> callback) override {
    std::move(callback)();
  }
  webrtc::TimeDelta TickPeriod() const override {
    return webrtc::TimeDelta::Seconds(0);
  }
};

}  // namespace

template <class V>
static typename V::iterator FindTrack(V* vector, const std::string& track_id) {
  auto it = vector->begin();
  for (; it != vector->end(); ++it) {
    if ((*it)->id() == track_id) {
      break;
    }
  }
  return it;
}

MockWebRtcAudioSource::MockWebRtcAudioSource(bool is_remote)
    : is_remote_(is_remote) {}
void MockWebRtcAudioSource::RegisterObserver(ObserverInterface* observer) {}
void MockWebRtcAudioSource::UnregisterObserver(ObserverInterface* observer) {}

MockWebRtcAudioSource::SourceState MockWebRtcAudioSource::state() const {
  return SourceState::kLive;
}

bool MockWebRtcAudioSource::remote() const {
  return is_remote_;
}

MockMediaStream::MockMediaStream(const std::string& id) : id_(id) {}

bool MockMediaStream::AddTrack(rtc::scoped_refptr<AudioTrackInterface> track) {
  audio_track_vector_.emplace_back(track);
  NotifyObservers();
  return true;
}

bool MockMediaStream::AddTrack(rtc::scoped_refptr<VideoTrackInterface> track) {
  video_track_vector_.emplace_back(track);
  NotifyObservers();
  return true;
}

bool MockMediaStream::RemoveTrack(
    rtc::scoped_refptr<AudioTrackInterface> track) {
  auto it = FindTrack(&audio_track_vector_, track->id());
  if (it == audio_track_vector_.end())
    return false;
  audio_track_vector_.erase(it);
  NotifyObservers();
  return true;
}

bool MockMediaStream::RemoveTrack(
    rtc::scoped_refptr<VideoTrackInterface> track) {
  auto it = FindTrack(&video_track_vector_, track->id());
  if (it == video_track_vector_.end())
    return false;
  video_track_vector_.erase(it);
  NotifyObservers();
  return true;
}

std::string MockMediaStream::id() const {
  return id_;
}

AudioTrackVector MockMediaStream::GetAudioTracks() {
  return audio_track_vector_;
}

VideoTrackVector MockMediaStream::GetVideoTracks() {
  return video_track_vector_;
}

rtc::scoped_refptr<AudioTrackInterface> MockMediaStream::FindAudioTrack(
    const std::string& track_id) {
  auto it = FindTrack(&audio_track_vector_, track_id);
  return it == audio_track_vector_.end() ? nullptr : *it;
}

rtc::scoped_refptr<VideoTrackInterface> MockMediaStream::FindVideoTrack(
    const std::string& track_id) {
  auto it = FindTrack(&video_track_vector_, track_id);
  return it == video_track_vector_.end() ? nullptr : *it;
}

void MockMediaStream::RegisterObserver(ObserverInterface* observer) {
  DCHECK(!base::Contains(observers_, observer));
  observers_.insert(observer);
}

void MockMediaStream::UnregisterObserver(ObserverInterface* observer) {
  auto it = observers_.find(observer);
  CHECK(it != observers_.end(), base::NotFatalUntil::M130);
  observers_.erase(it);
}

void MockMediaStream::NotifyObservers() {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnChanged();
  }
}

MockMediaStream::~MockMediaStream() {}

scoped_refptr<MockWebRtcAudioTrack> MockWebRtcAudioTrack::Create(
    const std::string& id) {
  return new rtc::RefCountedObject<MockWebRtcAudioTrack>(id);
}

MockWebRtcAudioTrack::MockWebRtcAudioTrack(const std::string& id)
    : id_(id),
      source_(new rtc::RefCountedObject<MockWebRtcAudioSource>(true)),
      enabled_(true),
      state_(webrtc::MediaStreamTrackInterface::kLive) {}

MockWebRtcAudioTrack::~MockWebRtcAudioTrack() {}

std::string MockWebRtcAudioTrack::kind() const {
  return kAudioKind;
}

webrtc::AudioSourceInterface* MockWebRtcAudioTrack::GetSource() const {
  return source_.get();
}

std::string MockWebRtcAudioTrack::id() const {
  return id_;
}

bool MockWebRtcAudioTrack::enabled() const {
  return enabled_;
}

MockWebRtcVideoTrack::TrackState MockWebRtcAudioTrack::state() const {
  return state_;
}

bool MockWebRtcAudioTrack::set_enabled(bool enable) {
  enabled_ = enable;
  return true;
}

void MockWebRtcAudioTrack::RegisterObserver(ObserverInterface* observer) {
  DCHECK(!base::Contains(observers_, observer));
  observers_.insert(observer);
}

void MockWebRtcAudioTrack::UnregisterObserver(ObserverInterface* observer) {
  DCHECK(base::Contains(observers_, observer));
  observers_.erase(observer);
}

void MockWebRtcAudioTrack::SetEnded() {
  DCHECK_EQ(webrtc::MediaStreamTrackInterface::kLive, state_);
  state_ = webrtc::MediaStreamTrackInterface::kEnded;
  for (auto* o : observers_)
    o->OnChanged();
}

MockWebRtcVideoTrack::MockWebRtcVideoTrack(
    const std::string& id,
    webrtc::VideoTrackSourceInterface* source)
    : id_(id),
      source_(source),
      enabled_(true),
      state_(webrtc::MediaStreamTrackInterface::kLive),
      sink_(nullptr) {}

MockWebRtcVideoTrack::~MockWebRtcVideoTrack() {}

scoped_refptr<MockWebRtcVideoTrack> MockWebRtcVideoTrack::Create(
    const std::string& id,
    scoped_refptr<webrtc::VideoTrackSourceInterface> source) {
  return new rtc::RefCountedObject<MockWebRtcVideoTrack>(id, source.get());
}

void MockWebRtcVideoTrack::AddOrUpdateSink(
    rtc::VideoSinkInterface<webrtc::VideoFrame>* sink,
    const rtc::VideoSinkWants& wants) {
  DCHECK(!sink_);
  sink_ = sink;
}

void MockWebRtcVideoTrack::RemoveSink(
    rtc::VideoSinkInterface<webrtc::VideoFrame>* sink) {
  DCHECK(sink_ == sink);
  sink_ = nullptr;
}

VideoTrackSourceInterface* MockWebRtcVideoTrack::GetSource() const {
  return source_.get();
}

std::string MockWebRtcVideoTrack::kind() const {
  return kVideoKind;
}

std::string MockWebRtcVideoTrack::id() const {
  return id_;
}

bool MockWebRtcVideoTrack::enabled() const {
  return enabled_;
}

MockWebRtcVideoTrack::TrackState MockWebRtcVideoTrack::state() const {
  return state_;
}

bool MockWebRtcVideoTrack::set_enabled(bool enable) {
  enabled_ = enable;
  return true;
}

void MockWebRtcVideoTrack::RegisterObserver(ObserverInterface* observer) {
  DCHECK(!base::Contains(observers_, observer));
  observers_.insert(observer);
}

void MockWebRtcVideoTrack::UnregisterObserver(ObserverInterface* observer) {
  DCHECK(base::Contains(observers_, observer));
  observers_.erase(observer);
}

void MockWebRtcVideoTrack::SetEnded() {
  DCHECK_EQ(webrtc::MediaStreamTrackInterface::kLive, state_);
  state_ = webrtc::MediaStreamTrackInterface::kEnded;
  for (auto* o : observers_)
    o->OnChanged();
}

scoped_refptr<MockWebRtcVideoTrackSource> MockWebRtcVideoTrackSource::Create(
    bool supports_encoded_output) {
  return new rtc::RefCountedObject<MockWebRtcVideoTrackSource>(
      supports_encoded_output);
}

MockWebRtcVideoTrackSource::MockWebRtcVideoTrackSource(
    bool supports_encoded_output)
    : supports_encoded_output_(supports_encoded_output) {}

bool MockWebRtcVideoTrackSource::is_screencast() const {
  return false;
}

std::optional<bool> MockWebRtcVideoTrackSource::needs_denoising() const {
  return std::nullopt;
}

bool MockWebRtcVideoTrackSource::GetStats(Stats* stats) {
  return false;
}

bool MockWebRtcVideoTrackSource::SupportsEncodedOutput() const {
  return supports_encoded_output_;
}

void MockWebRtcVideoTrackSource::GenerateKeyFrame() {}

void MockWebRtcVideoTrackSource::AddEncodedSink(
    rtc::VideoSinkInterface<webrtc::RecordableEncodedFrame>* sink) {}

void MockWebRtcVideoTrackSource::RemoveEncodedSink(
    rtc::VideoSinkInterface<webrtc::RecordableEncodedFrame>* sink) {}

void MockWebRtcVideoTrackSource::RegisterObserver(
    webrtc::ObserverInterface* observer) {}

void MockWebRtcVideoTrackSource::UnregisterObserver(
    webrtc::ObserverInterface* observer) {}

webrtc::MediaSourceInterface::SourceState MockWebRtcVideoTrackSource::state()
    const {
  return webrtc::MediaSourceInterface::kLive;
}

bool MockWebRtcVideoTrackSource::remote() const {
  return supports_encoded_output_;
}

void MockWebRtcVideoTrackSource::AddOrUpdateSink(
    rtc::VideoSinkInterface<webrtc::VideoFrame>* sink,
    const rtc::VideoSinkWants& wants) {}

void MockWebRtcVideoTrackSource::RemoveSink(
    rtc::VideoSinkInterface<webrtc::VideoFrame>* sink) {}


class MockIceCandidate : public IceCandidateInterface {
 public:
  MockIceCandidate(const std::string& sdp_mid,
                   int sdp_mline_index,
                   const std::string& sdp)
      : sdp_mid_(sdp_mid), sdp_mline_index_(sdp_mline_index), sdp_(sdp) {
    // Assign an valid address to |candidate_| to pass assert in code.
    candidate_.set_address(rtc::SocketAddress("127.0.0.1", 5000));
  }
  ~MockIceCandidate() override {}
  std::string sdp_mid() const override { return sdp_mid_; }
  int sdp_mline_index() const override { return sdp_mline_index_; }
  const cricket::Candidate& candidate() const override { return candidate_; }
  bool ToString(std::string* out) const override {
    *out = sdp_;
    return true;
  }

 private:
  std::string sdp_mid_;
  int sdp_mline_index_;
  std::string sdp_;
  cricket::Candidate candidate_;
};

MockPeerConnectionDependencyFactory::MockPeerConnectionDependencyFactory()
    : thread_("MockPCFactory WebRtc Signaling/Networking Thread") {
  EnsureWebRtcAudioDeviceImpl();
  CHECK(thread_.Start());
}

MockPeerConnectionDependencyFactory::~MockPeerConnectionDependencyFactory() {}

rtc::scoped_refptr<webrtc::PeerConnectionInterface>
MockPeerConnectionDependencyFactory::CreatePeerConnection(
    const webrtc::PeerConnectionInterface::RTCConfiguration& config,
    blink::WebLocalFrame* frame,
    webrtc::PeerConnectionObserver* observer,
    ExceptionState& exception_state,
    RTCRtpTransport*) {
  return rtc::make_ref_counted<MockPeerConnectionImpl>(this, observer);
}

scoped_refptr<webrtc::VideoTrackSourceInterface>
MockPeerConnectionDependencyFactory::CreateVideoTrackSourceProxy(
    webrtc::VideoTrackSourceInterface* source) {
  return source;
}

scoped_refptr<webrtc::MediaStreamInterface>
MockPeerConnectionDependencyFactory::CreateLocalMediaStream(
    const String& label) {
  return new rtc::RefCountedObject<MockMediaStream>(label.Utf8());
}

scoped_refptr<webrtc::VideoTrackInterface>
MockPeerConnectionDependencyFactory::CreateLocalVideoTrack(
    const String& id,
    webrtc::VideoTrackSourceInterface* source) {
  scoped_refptr<webrtc::VideoTrackInterface> track(
      new rtc::RefCountedObject<MockWebRtcVideoTrack>(id.Utf8(), source));
  return track;
}

webrtc::IceCandidateInterface*
MockPeerConnectionDependencyFactory::CreateIceCandidate(const String& sdp_mid,
                                                        int sdp_mline_index,
                                                        const String& sdp) {
  return new MockIceCandidate(sdp_mid.Utf8(), sdp_mline_index, sdp.Utf8());
}

scoped_refptr<base::SingleThreadTaskRunner>
MockPeerConnectionDependencyFactory::GetWebRtcSignalingTaskRunner() {
  return thread_.task_runner();
}

scoped_refptr<base::SingleThreadTaskRunner>
MockPeerConnectionDependencyFactory::GetWebRtcNetworkTaskRunner() {
  return thread_.task_runner();
}

std::unique_ptr<webrtc::Metronome>
MockPeerConnectionDependencyFactory::CreateDecodeMetronome() {
  return std::make_unique<FakeMetronome>();
}

void MockPeerConnectionDependencyFactory::SetFailToCreateSessionDescription(
    bool fail) {
  fail_to_create_session_description_ = fail;
}

}  // namespace blink
```