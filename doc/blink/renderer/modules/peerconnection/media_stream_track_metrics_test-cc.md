Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Initial Understanding of the File's Purpose:**

The filename itself, `media_stream_track_metrics_test.cc`, gives a strong hint. It's likely a test file for a class or component named `MediaStreamTrackMetrics`. The `.cc` extension confirms it's C++ source code.

**2. Examining Includes and Namespaces:**

* **Includes:**  The `#include` directives reveal dependencies. We see:
    * Standard C++ headers (`<stddef.h>`, `<memory>`).
    * `base/functional/bind.h`, `base/run_loop.h`, `base/threading/thread.h`: These are Chromium base library components suggesting asynchronous operations and threading.
    * `testing/gmock/include/gmock/gmock.h`, `testing/gtest/include/gtest/gtest.h`:  This confirms it's a unit test file using Google Mock and Google Test frameworks.
    * `third_party/blink/renderer/modules/peerconnection/mock_peer_connection_dependency_factory.h`:  Indicates interaction with the PeerConnection module and the use of mocking for dependencies.
    * `third_party/blink/renderer/platform/testing/task_environment.h`:  Suggests a testing environment that helps manage asynchronous tasks.
    * `third_party/webrtc/api/media_stream_interface.h`:  Crucially, this shows interaction with the WebRTC API, particularly related to media streams.

* **Namespace:** The `namespace blink {` indicates this code is part of the Blink rendering engine.

**3. Identifying Key Classes and Mocks:**

The code defines several classes:

* `MockAudioTrackInterface`, `MockVideoTrackInterface`: These are mock implementations of WebRTC's `AudioTrackInterface` and `VideoTrackInterface`. They are used to isolate the `MediaStreamTrackMetrics` class during testing. The mocks primarily focus on the `id()` method.
* `MockMediaStreamTrackMetrics`: This is a mock of the class being tested. It allows us to verify that specific methods (`SendLifetimeMessage`, `MakeUniqueIdImpl`) are called with the expected arguments.
* `MediaStreamTrackMetricsTest`: This is the main test fixture, inheriting from `testing::Test`, which sets up and tears down the test environment.

**4. Analyzing Test Cases (Functions starting with `TEST_F`):**

Each `TEST_F` function represents a specific test scenario for the `MediaStreamTrackMetrics` class. By examining the names and the code within each test, we can deduce the functionalities being tested:

* `MakeUniqueId`: Tests the uniqueness of generated IDs based on PeerConnection pointer, track ID, and direction (send/receive).
* `BasicRemoteStreams`, `BasicLocalStreams`: Test the sending of "connected" and "disconnected" lifetime messages for remote and local tracks upon ICE connection state changes.
* `LocalStreamAddedAferIceConnect`, `RemoteStreamAddedAferIceConnect`: Verify that lifetime messages are sent when tracks are added after the ICE connection is established.
* `LocalStreamTrackRemoved`: Checks if "disconnected" messages are sent when a local track is removed.
* `RemoveAfterDisconnect`:  Confirms that no lifetime message is sent if a track is removed after disconnection.
* `RemoteStreamMultipleDisconnects`: Tests handling of multiple disconnect events.
* `RemoteStreamConnectDisconnectTwice`: Verifies correct behavior when a connection and disconnection cycle occurs multiple times.
* `LocalStreamRemovedNoDisconnect`: Checks behavior when tracks are removed without an explicit disconnect.
* `LocalStreamLargerTest`: A more complex scenario involving adding and removing local tracks with ICE connection state changes.

**5. Connecting to Web Technologies (JavaScript, HTML, CSS):**

The core connection lies with WebRTC. The `MediaStreamTrackMetrics` class is designed to collect data about media tracks used in WebRTC peer-to-peer connections. Here's how it relates:

* **JavaScript:**  JavaScript code uses the WebRTC API (`getUserMedia`, `RTCPeerConnection`, `MediaStreamTrack`) to capture audio/video, establish connections, and manage media tracks. This test indirectly relates to the JavaScript API because it's testing the underlying metrics collection within the browser engine triggered by JavaScript WebRTC calls.
* **HTML:**  HTML provides the structure for web pages. WebRTC functionalities are often initiated through JavaScript within an HTML page (e.g., button clicks to start a call).
* **CSS:** CSS is for styling. It has no direct functional relationship with `MediaStreamTrackMetrics`. However, the user interface styled by CSS can trigger JavaScript events that lead to WebRTC interactions.

**6. Identifying Logic and Assumptions:**

The tests make assumptions about how `MediaStreamTrackMetrics` should behave based on ICE connection state changes and track addition/removal. The core logic being tested is the tracking of media track "lifetimes" (connected and disconnected) based on these events.

**7. Thinking about User/Programming Errors and Debugging:**

* **User Errors:** A user might experience a dropped call or a failure to connect. The metrics collected by `MediaStreamTrackMetrics` can help developers diagnose if the issue is related to track management.
* **Programming Errors:**  A developer might incorrectly add or remove tracks, leading to unexpected behavior. The tests help ensure the `MediaStreamTrackMetrics` class correctly tracks these actions.

**8. Simulating User Actions (Debugging Clues):**

To reach the code being tested, a user would likely:

1. Open a web page that uses WebRTC.
2. The JavaScript code on that page would:
   * Use `navigator.mediaDevices.getUserMedia()` to get audio/video tracks.
   * Create an `RTCPeerConnection`.
   * Add the tracks to the `RTCPeerConnection`.
   * Initiate the signaling process (ICE negotiation).
   * Potentially remove tracks during the call.
   * The ICE connection state would change throughout the call (connecting, connected, disconnected, failed).

The `MediaStreamTrackMetrics` class would be invoked internally by the Blink engine as a result of these JavaScript API calls and the underlying WebRTC implementation.

**Self-Correction/Refinement:**

Initially, I might have focused too much on the mocking details. However, the core purpose is to test the *logic* of tracking track lifetimes. The mocks are just a tool to achieve that in isolation. It's important to shift the focus to *what* the tests are verifying about the `MediaStreamTrackMetrics` class's behavior. Also, realizing the indirect relationship with JavaScript/HTML through the WebRTC API is crucial.

By following this detailed examination process, we can thoroughly understand the purpose, functionality, and context of the given C++ test file.
这是目录为 `blink/renderer/modules/peerconnection/media_stream_track_metrics_test.cc` 的 Chromium Blink 引擎源代码文件。从文件名和内容来看，它的主要功能是：

**功能：测试 `MediaStreamTrackMetrics` 类的功能。**

`MediaStreamTrackMetrics` 类很可能用于收集和报告关于 `MediaStreamTrack` 对象（音频或视频轨道）的指标数据，特别是在 WebRTC PeerConnection 上下文中。这些指标可能包括轨道的生命周期事件（例如，何时添加、何时连接、何时断开连接）以及其他相关信息。

这个测试文件通过使用 Google Test 和 Google Mock 框架，模拟各种场景来验证 `MediaStreamTrackMetrics` 类的行为是否符合预期。

**与 JavaScript, HTML, CSS 的关系：**

虽然这个 C++ 文件本身不包含 JavaScript, HTML 或 CSS 代码，但它所测试的功能是 WebRTC API 的一部分，而 WebRTC API 是通过 JavaScript 在网页中使用的。

* **JavaScript:**  JavaScript 代码使用 WebRTC API（例如 `getUserMedia`, `RTCPeerConnection`, `MediaStreamTrack` 等）来获取媒体流、创建 PeerConnection 连接、添加和移除轨道。`MediaStreamTrackMetrics` 类在 Blink 引擎内部运行，当 JavaScript 代码操作这些 WebRTC API 时，它会收集相关的指标。

   **举例说明:**  当 JavaScript 代码调用 `peerConnection.addTrack(audioTrack, mediaStream)` 将一个音频轨道添加到 PeerConnection 时，Blink 引擎内部会创建或更新相应的 `MediaStreamTrackMetrics` 对象，并记录轨道添加的事件。当连接建立或断开时，`MediaStreamTrackMetrics` 也会记录相应的状态变化。

* **HTML:** HTML 用于构建网页的结构。包含 WebRTC 功能的网页会使用 HTML 元素（例如按钮）来触发 JavaScript 代码，从而间接地影响 `MediaStreamTrackMetrics` 的行为。

   **举例说明:**  一个 HTML 按钮的 `onclick` 事件可能触发一个 JavaScript 函数，该函数会调用 `navigator.mediaDevices.getUserMedia()` 获取用户摄像头和麦克风的媒体流。这个操作最终会触发 `MediaStreamTrackMetrics` 开始跟踪这些媒体流中的轨道。

* **CSS:** CSS 用于网页的样式。它与 `MediaStreamTrackMetrics` 的功能没有直接的关系。CSS 不会直接影响 WebRTC API 的行为或触发 `MediaStreamTrackMetrics` 的指标收集。

**逻辑推理（假设输入与输出）：**

假设我们有以下场景：

**假设输入：**

1. **添加本地音频轨道：** 调用 `metrics_->AddTrack(MediaStreamTrackMetrics::Direction::kSend, MediaStreamTrackMetrics::Kind::kAudio, "audio_track_id");`
2. **ICE 连接状态变为已连接：** 调用 `metrics_->IceConnectionChange(PeerConnectionInterface::kIceConnectionConnected);`
3. **ICE 连接状态变为已断开连接：** 调用 `metrics_->IceConnectionChange(PeerConnectionInterface::kIceConnectionDisconnected);`
4. **移除本地音频轨道：** 调用 `metrics_->RemoveTrack(MediaStreamTrackMetrics::Direction::kSend, MediaStreamTrackMetrics::Kind::kAudio, "audio_track_id");`

**预期输出（基于测试代码的逻辑）：**

1. 当添加轨道时，`MediaStreamTrackMetrics` 会记录该轨道，但不会立即发送生命周期消息。
2. 当 ICE 连接状态变为已连接时，`MediaStreamTrackMetrics` 应该调用 `SendLifetimeMessage` 方法，并携带以下信息：
   * track_id: "audio_track_id"
   * kind: `MediaStreamTrackMetrics::Kind::kAudio`
   * event: `MediaStreamTrackMetrics::LifetimeEvent::kConnected`
   * direction: `MediaStreamTrackMetrics::Direction::kSend`
3. 当 ICE 连接状态变为已断开连接时，`MediaStreamTrackMetrics` 应该调用 `SendLifetimeMessage` 方法，并携带以下信息：
   * track_id: "audio_track_id"
   * kind: `MediaStreamTrackMetrics::Kind::kAudio`
   * event: `MediaStreamTrackMetrics::LifetimeEvent::kDisconnected`
   * direction: `MediaStreamTrackMetrics::Direction::kSend`
4. 当移除轨道时，如果连接已经断开，则可能不会发送额外的生命周期消息（取决于具体的实现逻辑，但从测试用例 `RemoveAfterDisconnect` 可以推断出这一点）。

**用户或编程常见的使用错误：**

1. **未正确处理 ICE 连接状态变化：**  如果 `MediaStreamTrackMetrics` 依赖于 ICE 连接状态来判断轨道的生命周期，那么在实现中未正确监听和处理 ICE 连接状态的变化可能会导致指标数据不准确。
   * **举例：**  开发者可能忘记在 ICE 连接状态变为 `connected` 时通知 `MediaStreamTrackMetrics`，导致连接事件没有被记录。

2. **在错误的时机添加或移除轨道：**  如果在连接建立之前或之后添加/移除轨道，可能会导致 `MediaStreamTrackMetrics` 记录的生命周期事件与实际情况不符。
   * **举例：**  在 ICE 连接断开后，错误地认为轨道仍然处于连接状态。

3. **重复添加或移除相同的轨道 ID：**  `MediaStreamTrackMetrics` 需要能够正确处理重复的操作，避免数据混乱。
   * **举例：**  多次调用 `AddTrack` 使用相同的轨道 ID，应该只被视为一次添加，或者根据具体实现更新状态。

**用户操作是如何一步步的到达这里，作为调试线索：**

要调试 `MediaStreamTrackMetrics` 的行为，开发者可能会按照以下步骤操作，最终可能需要查看这个测试文件：

1. **用户报告 WebRTC 相关问题：** 用户可能会遇到视频或音频无法正常传输、连接不稳定、通话中断等问题。
2. **开发者尝试重现问题：** 开发者会尝试在本地环境或测试环境中重现用户报告的问题。
3. **查看 WebRTC 日志和指标：** 开发者会查看浏览器提供的 WebRTC 内部日志和指标，尝试找出问题的原因。这可能会涉及到查看与媒体轨道相关的指标数据。
4. **怀疑 `MediaStreamTrackMetrics` 的数据准确性：** 如果开发者怀疑收集到的媒体轨道指标数据不准确，或者认为指标收集逻辑存在问题，他们可能会查看 `MediaStreamTrackMetrics` 类的实现代码。
5. **查看 `media_stream_track_metrics_test.cc`：** 为了理解 `MediaStreamTrackMetrics` 类的预期行为以及如何进行测试，开发者会查看相关的测试文件。这个测试文件展示了各种场景下 `MediaStreamTrackMetrics` 应该如何响应，可以帮助开发者理解和调试该类的行为。

**调试线索：**

* 测试用例的名称可以提供关于被测试功能的线索，例如 `BasicRemoteStreams`, `LocalStreamAddedAferIceConnect`, `LocalStreamTrackRemoved` 等。
* 测试用例中使用的 `EXPECT_CALL` 宏可以帮助理解在特定场景下，`MediaStreamTrackMetrics` 的哪些方法会被调用以及调用时携带的参数。
* 通过阅读测试用例的逻辑，可以推断出 `MediaStreamTrackMetrics` 如何处理不同的 ICE 连接状态和轨道生命周期事件。

总而言之，`media_stream_track_metrics_test.cc` 是一个关键的测试文件，用于确保 Chromium Blink 引擎中负责收集媒体轨道指标的 `MediaStreamTrackMetrics` 类能够正确地工作，这对于 WebRTC 功能的稳定性和可调试性至关重要。

### 提示词
```
这是目录为blink/renderer/modules/peerconnection/media_stream_track_metrics_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/peerconnection/media_stream_track_metrics.h"

#include <stddef.h>

#include <memory>

#include "base/functional/bind.h"
#include "base/run_loop.h"
#include "base/threading/thread.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/modules/peerconnection/mock_peer_connection_dependency_factory.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/webrtc/api/media_stream_interface.h"

using webrtc::AudioSourceInterface;
using webrtc::AudioTrackInterface;
using webrtc::AudioTrackSinkInterface;
using webrtc::MediaStreamInterface;
using webrtc::ObserverInterface;
using webrtc::PeerConnectionInterface;
using webrtc::VideoTrackInterface;
using webrtc::VideoTrackSourceInterface;

namespace blink {

// A very simple mock that implements only the id() method.
class MockAudioTrackInterface : public AudioTrackInterface {
 public:
  explicit MockAudioTrackInterface(const std::string& id) : id_(id) {}
  ~MockAudioTrackInterface() override {}

  std::string id() const override { return id_; }

  MOCK_METHOD1(RegisterObserver, void(ObserverInterface*));
  MOCK_METHOD1(UnregisterObserver, void(ObserverInterface*));
  MOCK_CONST_METHOD0(kind, std::string());
  MOCK_CONST_METHOD0(enabled, bool());
  MOCK_CONST_METHOD0(state, TrackState());
  MOCK_METHOD1(set_enabled, bool(bool));
  MOCK_METHOD1(set_state, bool(TrackState));
  MOCK_CONST_METHOD0(GetSource, AudioSourceInterface*());
  MOCK_METHOD1(AddSink, void(AudioTrackSinkInterface*));
  MOCK_METHOD1(RemoveSink, void(AudioTrackSinkInterface*));

 private:
  std::string id_;
};

// A very simple mock that implements only the id() method.
class MockVideoTrackInterface : public VideoTrackInterface {
 public:
  explicit MockVideoTrackInterface(const std::string& id) : id_(id) {}
  ~MockVideoTrackInterface() override {}

  std::string id() const override { return id_; }

  MOCK_METHOD1(RegisterObserver, void(ObserverInterface*));
  MOCK_METHOD1(UnregisterObserver, void(ObserverInterface*));
  MOCK_CONST_METHOD0(kind, std::string());
  MOCK_CONST_METHOD0(enabled, bool());
  MOCK_CONST_METHOD0(state, TrackState());
  MOCK_METHOD1(set_enabled, bool(bool));
  MOCK_METHOD1(set_state, bool(TrackState));
  MOCK_METHOD2(AddOrUpdateSink,
               void(rtc::VideoSinkInterface<webrtc::VideoFrame>*,
                    const rtc::VideoSinkWants&));
  MOCK_METHOD1(RemoveSink, void(rtc::VideoSinkInterface<webrtc::VideoFrame>*));
  MOCK_CONST_METHOD0(GetSource, VideoTrackSourceInterface*());

 private:
  std::string id_;
};

class MockMediaStreamTrackMetrics : public MediaStreamTrackMetrics {
 public:
  virtual ~MockMediaStreamTrackMetrics() {}

  MOCK_METHOD4(SendLifetimeMessage,
               void(const std::string&, Kind, LifetimeEvent, Direction));
  using MediaStreamTrackMetrics::MakeUniqueIdImpl;
};

class MediaStreamTrackMetricsTest : public testing::Test {
 public:
  MediaStreamTrackMetricsTest() : signaling_thread_("signaling_thread") {}

  void SetUp() override {
    metrics_ = std::make_unique<MockMediaStreamTrackMetrics>();
    stream_ = new rtc::RefCountedObject<blink::MockMediaStream>("stream");
    signaling_thread_.Start();
  }

  void TearDown() override {
    signaling_thread_.Stop();
    metrics_.reset();
    stream_ = nullptr;
  }

  scoped_refptr<MockAudioTrackInterface> MakeAudioTrack(const std::string& id) {
    return new rtc::RefCountedObject<MockAudioTrackInterface>(id);
  }

  scoped_refptr<MockVideoTrackInterface> MakeVideoTrack(const std::string& id) {
    return new rtc::RefCountedObject<MockVideoTrackInterface>(id);
  }

  test::TaskEnvironment task_environment_;
  std::unique_ptr<MockMediaStreamTrackMetrics> metrics_;
  scoped_refptr<MediaStreamInterface> stream_;

  base::Thread signaling_thread_;
};

TEST_F(MediaStreamTrackMetricsTest, MakeUniqueId) {
  // The important testable properties of the unique ID are that it
  // should differ when any of the three constituents differ
  // (PeerConnection pointer, track ID, remote or not. Also, testing
  // that the implementation does not discard the upper 32 bits of the
  // PeerConnection pointer is important.
  //
  // The important hard-to-test property is that the ID be generated
  // using a hash function with virtually zero chance of
  // collisions. We don't test this, we rely on MD5 having this
  // property.

  // Lower 32 bits the same, upper 32 differ.
  EXPECT_NE(
      metrics_->MakeUniqueIdImpl(0x1000000000000001, "x",
                                 MediaStreamTrackMetrics::Direction::kReceive),
      metrics_->MakeUniqueIdImpl(0x2000000000000001, "x",
                                 MediaStreamTrackMetrics::Direction::kReceive));

  // Track ID differs.
  EXPECT_NE(metrics_->MakeUniqueIdImpl(
                42, "x", MediaStreamTrackMetrics::Direction::kReceive),
            metrics_->MakeUniqueIdImpl(
                42, "y", MediaStreamTrackMetrics::Direction::kReceive));

  // Remove vs. local track differs.
  EXPECT_NE(metrics_->MakeUniqueIdImpl(
                42, "x", MediaStreamTrackMetrics::Direction::kReceive),
            metrics_->MakeUniqueIdImpl(
                42, "x", MediaStreamTrackMetrics::Direction::kSend));
}

TEST_F(MediaStreamTrackMetricsTest, BasicRemoteStreams) {
  metrics_->AddTrack(MediaStreamTrackMetrics::Direction::kReceive,
                     MediaStreamTrackMetrics::Kind::kAudio, "audio");
  metrics_->AddTrack(MediaStreamTrackMetrics::Direction::kReceive,
                     MediaStreamTrackMetrics::Kind::kVideo, "video");

  EXPECT_CALL(*metrics_, SendLifetimeMessage(
                             "audio", MediaStreamTrackMetrics::Kind::kAudio,
                             MediaStreamTrackMetrics::LifetimeEvent::kConnected,
                             MediaStreamTrackMetrics::Direction::kReceive));
  EXPECT_CALL(*metrics_, SendLifetimeMessage(
                             "video", MediaStreamTrackMetrics::Kind::kVideo,
                             MediaStreamTrackMetrics::LifetimeEvent::kConnected,
                             MediaStreamTrackMetrics::Direction::kReceive));
  metrics_->IceConnectionChange(
      PeerConnectionInterface::kIceConnectionConnected);

  EXPECT_CALL(
      *metrics_,
      SendLifetimeMessage("audio", MediaStreamTrackMetrics::Kind::kAudio,
                          MediaStreamTrackMetrics::LifetimeEvent::kDisconnected,
                          MediaStreamTrackMetrics::Direction::kReceive));
  EXPECT_CALL(
      *metrics_,
      SendLifetimeMessage("video", MediaStreamTrackMetrics::Kind::kVideo,
                          MediaStreamTrackMetrics::LifetimeEvent::kDisconnected,
                          MediaStreamTrackMetrics::Direction::kReceive));
  metrics_->IceConnectionChange(
      PeerConnectionInterface::kIceConnectionDisconnected);
}

TEST_F(MediaStreamTrackMetricsTest, BasicLocalStreams) {
  metrics_->AddTrack(MediaStreamTrackMetrics::Direction::kSend,
                     MediaStreamTrackMetrics::Kind::kAudio, "audio");
  metrics_->AddTrack(MediaStreamTrackMetrics::Direction::kSend,
                     MediaStreamTrackMetrics::Kind::kVideo, "video");

  EXPECT_CALL(*metrics_, SendLifetimeMessage(
                             "audio", MediaStreamTrackMetrics::Kind::kAudio,
                             MediaStreamTrackMetrics::LifetimeEvent::kConnected,
                             MediaStreamTrackMetrics::Direction::kSend));
  EXPECT_CALL(*metrics_, SendLifetimeMessage(
                             "video", MediaStreamTrackMetrics::Kind::kVideo,
                             MediaStreamTrackMetrics::LifetimeEvent::kConnected,
                             MediaStreamTrackMetrics::Direction::kSend));
  metrics_->IceConnectionChange(
      PeerConnectionInterface::kIceConnectionConnected);

  EXPECT_CALL(
      *metrics_,
      SendLifetimeMessage("audio", MediaStreamTrackMetrics::Kind::kAudio,
                          MediaStreamTrackMetrics::LifetimeEvent::kDisconnected,
                          MediaStreamTrackMetrics::Direction::kSend));
  EXPECT_CALL(
      *metrics_,
      SendLifetimeMessage("video", MediaStreamTrackMetrics::Kind::kVideo,
                          MediaStreamTrackMetrics::LifetimeEvent::kDisconnected,
                          MediaStreamTrackMetrics::Direction::kSend));
  metrics_->IceConnectionChange(PeerConnectionInterface::kIceConnectionFailed);
}

TEST_F(MediaStreamTrackMetricsTest, LocalStreamAddedAferIceConnect) {
  metrics_->IceConnectionChange(
      PeerConnectionInterface::kIceConnectionConnected);

  EXPECT_CALL(*metrics_, SendLifetimeMessage(
                             "audio", MediaStreamTrackMetrics::Kind::kAudio,
                             MediaStreamTrackMetrics::LifetimeEvent::kConnected,
                             MediaStreamTrackMetrics::Direction::kSend));
  EXPECT_CALL(*metrics_, SendLifetimeMessage(
                             "video", MediaStreamTrackMetrics::Kind::kVideo,
                             MediaStreamTrackMetrics::LifetimeEvent::kConnected,
                             MediaStreamTrackMetrics::Direction::kSend));

  metrics_->AddTrack(MediaStreamTrackMetrics::Direction::kSend,
                     MediaStreamTrackMetrics::Kind::kAudio, "audio");
  metrics_->AddTrack(MediaStreamTrackMetrics::Direction::kSend,
                     MediaStreamTrackMetrics::Kind::kVideo, "video");
}

TEST_F(MediaStreamTrackMetricsTest, RemoteStreamAddedAferIceConnect) {
  metrics_->IceConnectionChange(
      PeerConnectionInterface::kIceConnectionConnected);

  EXPECT_CALL(*metrics_, SendLifetimeMessage(
                             "audio", MediaStreamTrackMetrics::Kind::kAudio,
                             MediaStreamTrackMetrics::LifetimeEvent::kConnected,
                             MediaStreamTrackMetrics::Direction::kReceive));
  EXPECT_CALL(*metrics_, SendLifetimeMessage(
                             "video", MediaStreamTrackMetrics::Kind::kVideo,
                             MediaStreamTrackMetrics::LifetimeEvent::kConnected,
                             MediaStreamTrackMetrics::Direction::kReceive));

  metrics_->AddTrack(MediaStreamTrackMetrics::Direction::kReceive,
                     MediaStreamTrackMetrics::Kind::kAudio, "audio");
  metrics_->AddTrack(MediaStreamTrackMetrics::Direction::kReceive,
                     MediaStreamTrackMetrics::Kind::kVideo, "video");
}

TEST_F(MediaStreamTrackMetricsTest, LocalStreamTrackRemoved) {
  metrics_->AddTrack(MediaStreamTrackMetrics::Direction::kSend,
                     MediaStreamTrackMetrics::Kind::kAudio, "first");
  metrics_->AddTrack(MediaStreamTrackMetrics::Direction::kSend,
                     MediaStreamTrackMetrics::Kind::kAudio, "second");

  EXPECT_CALL(*metrics_, SendLifetimeMessage(
                             "first", MediaStreamTrackMetrics::Kind::kAudio,
                             MediaStreamTrackMetrics::LifetimeEvent::kConnected,
                             MediaStreamTrackMetrics::Direction::kSend));
  EXPECT_CALL(*metrics_, SendLifetimeMessage(
                             "second", MediaStreamTrackMetrics::Kind::kAudio,
                             MediaStreamTrackMetrics::LifetimeEvent::kConnected,
                             MediaStreamTrackMetrics::Direction::kSend));
  metrics_->IceConnectionChange(
      PeerConnectionInterface::kIceConnectionConnected);

  EXPECT_CALL(
      *metrics_,
      SendLifetimeMessage("first", MediaStreamTrackMetrics::Kind::kAudio,
                          MediaStreamTrackMetrics::LifetimeEvent::kDisconnected,
                          MediaStreamTrackMetrics::Direction::kSend));
  metrics_->RemoveTrack(MediaStreamTrackMetrics::Direction::kSend,
                        MediaStreamTrackMetrics::Kind::kAudio, "first");

  EXPECT_CALL(
      *metrics_,
      SendLifetimeMessage("second", MediaStreamTrackMetrics::Kind::kAudio,
                          MediaStreamTrackMetrics::LifetimeEvent::kDisconnected,
                          MediaStreamTrackMetrics::Direction::kSend));
  metrics_->IceConnectionChange(PeerConnectionInterface::kIceConnectionFailed);
}

TEST_F(MediaStreamTrackMetricsTest, RemoveAfterDisconnect) {
  metrics_->AddTrack(MediaStreamTrackMetrics::Direction::kSend,
                     MediaStreamTrackMetrics::Kind::kAudio, "audio");

  EXPECT_CALL(*metrics_, SendLifetimeMessage(
                             "audio", MediaStreamTrackMetrics::Kind::kAudio,
                             MediaStreamTrackMetrics::LifetimeEvent::kConnected,
                             MediaStreamTrackMetrics::Direction::kSend));
  metrics_->IceConnectionChange(
      PeerConnectionInterface::kIceConnectionConnected);

  EXPECT_CALL(
      *metrics_,
      SendLifetimeMessage("audio", MediaStreamTrackMetrics::Kind::kAudio,
                          MediaStreamTrackMetrics::LifetimeEvent::kDisconnected,
                          MediaStreamTrackMetrics::Direction::kSend));
  metrics_->IceConnectionChange(PeerConnectionInterface::kIceConnectionFailed);

  // This happens after the call is disconnected so no lifetime
  // message should be sent.
  metrics_->RemoveTrack(MediaStreamTrackMetrics::Direction::kSend,
                        MediaStreamTrackMetrics::Kind::kAudio, "audio");
}

TEST_F(MediaStreamTrackMetricsTest, RemoteStreamMultipleDisconnects) {
  metrics_->AddTrack(MediaStreamTrackMetrics::Direction::kReceive,
                     MediaStreamTrackMetrics::Kind::kAudio, "audio");

  EXPECT_CALL(*metrics_, SendLifetimeMessage(
                             "audio", MediaStreamTrackMetrics::Kind::kAudio,
                             MediaStreamTrackMetrics::LifetimeEvent::kConnected,
                             MediaStreamTrackMetrics::Direction::kReceive));
  metrics_->IceConnectionChange(
      PeerConnectionInterface::kIceConnectionConnected);

  EXPECT_CALL(
      *metrics_,
      SendLifetimeMessage("audio", MediaStreamTrackMetrics::Kind::kAudio,
                          MediaStreamTrackMetrics::LifetimeEvent::kDisconnected,
                          MediaStreamTrackMetrics::Direction::kReceive));
  metrics_->IceConnectionChange(
      PeerConnectionInterface::kIceConnectionDisconnected);
  metrics_->IceConnectionChange(PeerConnectionInterface::kIceConnectionFailed);
  metrics_->RemoveTrack(MediaStreamTrackMetrics::Direction::kReceive,
                        MediaStreamTrackMetrics::Kind::kAudio, "audio");
}

TEST_F(MediaStreamTrackMetricsTest, RemoteStreamConnectDisconnectTwice) {
  metrics_->AddTrack(MediaStreamTrackMetrics::Direction::kReceive,
                     MediaStreamTrackMetrics::Kind::kAudio, "audio");

  for (size_t i = 0; i < 2; ++i) {
    EXPECT_CALL(
        *metrics_,
        SendLifetimeMessage("audio", MediaStreamTrackMetrics::Kind::kAudio,
                            MediaStreamTrackMetrics::LifetimeEvent::kConnected,
                            MediaStreamTrackMetrics::Direction::kReceive));
    metrics_->IceConnectionChange(
        PeerConnectionInterface::kIceConnectionConnected);

    EXPECT_CALL(*metrics_,
                SendLifetimeMessage(
                    "audio", MediaStreamTrackMetrics::Kind::kAudio,
                    MediaStreamTrackMetrics::LifetimeEvent::kDisconnected,
                    MediaStreamTrackMetrics::Direction::kReceive));
    metrics_->IceConnectionChange(
        PeerConnectionInterface::kIceConnectionDisconnected);
  }

  metrics_->RemoveTrack(MediaStreamTrackMetrics::Direction::kReceive,
                        MediaStreamTrackMetrics::Kind::kAudio, "audio");
}

TEST_F(MediaStreamTrackMetricsTest, LocalStreamRemovedNoDisconnect) {
  metrics_->AddTrack(MediaStreamTrackMetrics::Direction::kSend,
                     MediaStreamTrackMetrics::Kind::kAudio, "audio");
  metrics_->AddTrack(MediaStreamTrackMetrics::Direction::kSend,
                     MediaStreamTrackMetrics::Kind::kVideo, "video");

  EXPECT_CALL(*metrics_, SendLifetimeMessage(
                             "audio", MediaStreamTrackMetrics::Kind::kAudio,
                             MediaStreamTrackMetrics::LifetimeEvent::kConnected,
                             MediaStreamTrackMetrics::Direction::kSend));
  EXPECT_CALL(*metrics_, SendLifetimeMessage(
                             "video", MediaStreamTrackMetrics::Kind::kVideo,
                             MediaStreamTrackMetrics::LifetimeEvent::kConnected,
                             MediaStreamTrackMetrics::Direction::kSend));
  metrics_->IceConnectionChange(
      PeerConnectionInterface::kIceConnectionConnected);

  EXPECT_CALL(
      *metrics_,
      SendLifetimeMessage("audio", MediaStreamTrackMetrics::Kind::kAudio,
                          MediaStreamTrackMetrics::LifetimeEvent::kDisconnected,
                          MediaStreamTrackMetrics::Direction::kSend));
  EXPECT_CALL(
      *metrics_,
      SendLifetimeMessage("video", MediaStreamTrackMetrics::Kind::kVideo,
                          MediaStreamTrackMetrics::LifetimeEvent::kDisconnected,
                          MediaStreamTrackMetrics::Direction::kSend));
  metrics_->RemoveTrack(MediaStreamTrackMetrics::Direction::kSend,
                        MediaStreamTrackMetrics::Kind::kAudio, "audio");
  metrics_->RemoveTrack(MediaStreamTrackMetrics::Direction::kSend,
                        MediaStreamTrackMetrics::Kind::kVideo, "video");
}

TEST_F(MediaStreamTrackMetricsTest, LocalStreamLargerTest) {
  metrics_->AddTrack(MediaStreamTrackMetrics::Direction::kSend,
                     MediaStreamTrackMetrics::Kind::kAudio, "audio");
  metrics_->AddTrack(MediaStreamTrackMetrics::Direction::kSend,
                     MediaStreamTrackMetrics::Kind::kVideo, "video");

  EXPECT_CALL(*metrics_, SendLifetimeMessage(
                             "audio", MediaStreamTrackMetrics::Kind::kAudio,
                             MediaStreamTrackMetrics::LifetimeEvent::kConnected,
                             MediaStreamTrackMetrics::Direction::kSend));
  EXPECT_CALL(*metrics_, SendLifetimeMessage(
                             "video", MediaStreamTrackMetrics::Kind::kVideo,
                             MediaStreamTrackMetrics::LifetimeEvent::kConnected,
                             MediaStreamTrackMetrics::Direction::kSend));
  metrics_->IceConnectionChange(
      PeerConnectionInterface::kIceConnectionConnected);

  EXPECT_CALL(
      *metrics_,
      SendLifetimeMessage("audio", MediaStreamTrackMetrics::Kind::kAudio,
                          MediaStreamTrackMetrics::LifetimeEvent::kDisconnected,
                          MediaStreamTrackMetrics::Direction::kSend));
  metrics_->RemoveTrack(MediaStreamTrackMetrics::Direction::kSend,
                        MediaStreamTrackMetrics::Kind::kAudio, "audio");

  // Add back audio
  EXPECT_CALL(*metrics_, SendLifetimeMessage(
                             "audio", MediaStreamTrackMetrics::Kind::kAudio,
                             MediaStreamTrackMetrics::LifetimeEvent::kConnected,
                             MediaStreamTrackMetrics::Direction::kSend));
  metrics_->AddTrack(MediaStreamTrackMetrics::Direction::kSend,
                     MediaStreamTrackMetrics::Kind::kAudio, "audio");

  EXPECT_CALL(
      *metrics_,
      SendLifetimeMessage("audio", MediaStreamTrackMetrics::Kind::kAudio,
                          MediaStreamTrackMetrics::LifetimeEvent::kDisconnected,
                          MediaStreamTrackMetrics::Direction::kSend));
  metrics_->RemoveTrack(MediaStreamTrackMetrics::Direction::kSend,
                        MediaStreamTrackMetrics::Kind::kAudio, "audio");
  EXPECT_CALL(
      *metrics_,
      SendLifetimeMessage("video", MediaStreamTrackMetrics::Kind::kVideo,
                          MediaStreamTrackMetrics::LifetimeEvent::kDisconnected,
                          MediaStreamTrackMetrics::Direction::kSend));
  metrics_->RemoveTrack(MediaStreamTrackMetrics::Direction::kSend,
                        MediaStreamTrackMetrics::Kind::kVideo, "video");
}

}  // namespace blink
```