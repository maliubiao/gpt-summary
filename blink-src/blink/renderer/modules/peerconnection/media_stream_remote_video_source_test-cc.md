Response:
The user wants to understand the functionality of the `media_stream_remote_video_source_test.cc` file in the Chromium Blink engine. I need to analyze the code and identify its purpose, its relation to web technologies (JavaScript, HTML, CSS), and provide examples of logical reasoning, common user errors, and debugging steps.

**Plan:**

1. **Identify the core purpose:** The file name and its content clearly indicate it's a unit test file for `MediaStreamRemoteVideoSource`.
2. **Explain the functionality:** Describe how `MediaStreamRemoteVideoSource` handles remote video streams.
3. **Relate to web technologies:** Explain how this component is related to WebRTC and its JavaScript APIs.
4. **Provide examples of logical reasoning:**  Analyze a test case and break down the input and expected output.
5. **Illustrate common user errors:**  Think about how incorrect usage of WebRTC APIs could relate to the functionalities being tested.
6. **Outline debugging steps:** Explain how a developer would reach this part of the code during debugging.
这个文件 `media_stream_remote_video_source_test.cc` 是 Chromium Blink 引擎中的一个单元测试文件，专门用于测试 `MediaStreamRemoteVideoSource` 类的功能。 `MediaStreamRemoteVideoSource` 的主要职责是**处理来自远程 `MediaStreamTrack` 的视频数据**。

具体来说，这个测试文件会涵盖以下方面的功能：

1. **接收和处理远程视频帧:**  测试 `MediaStreamRemoteVideoSource` 是否能正确接收来自 WebRTC 层（通过 `TrackObserver`）的 `webrtc::VideoFrame`。
2. **向 `MediaStreamVideoTrack` 传递视频帧:** 测试接收到的视频帧是否能正确传递给关联的 `MediaStreamVideoTrack`，以便渲染到页面上。
3. **处理视频帧的元数据:**  测试是否能正确处理和传递视频帧的元数据，例如时间戳、色彩空间、RTP 包信息等。
4. **处理 `MediaStreamTrack` 的生命周期:**  测试当远程 `MediaStreamTrack` 结束时，`MediaStreamRemoteVideoSource` 是否能正确地更新状态并通知相关的 `MediaStreamVideoSink`。
5. **支持编码后的视频帧:** 测试是否能够处理和传递编码后的视频帧。
6. **处理色彩空间信息:** 验证对于接收到的视频帧，如何处理和传递色彩空间信息。
7. **处理时间戳:** 验证如何处理和传递视频帧的时间戳，包括同步问题。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件直接位于 Blink 渲染引擎的底层，它并不直接处理 JavaScript、HTML 或 CSS。然而，它所测试的功能是 WebRTC API 的核心组成部分，而 WebRTC API 是通过 JavaScript 暴露给 web 开发者的。

*   **JavaScript:**  Web 开发者使用 JavaScript 中的 `getUserMedia()` 或 `RTCPeerConnection` 等 API 来获取和处理音视频流。当一个远程 PeerConnection 接收到视频流时，这个视频流会通过底层的 WebRTC 实现传递到 Blink 引擎的 `MediaStreamRemoteVideoSource` 进行处理。`MediaStreamTrack` 对象在 JavaScript 中表示视频轨道，而 `MediaStreamRemoteVideoSource` 就是这个 `MediaStreamTrack` 在 Blink 引擎中的具体实现之一。
    *   **例子:** 当 JavaScript 代码调用 `peerConnection.ontrack` 事件处理函数来接收远程视频轨道时，Blink 引擎内部会创建 `MediaStreamRemoteVideoSource` 来处理这个轨道的数据。接收到的每一帧视频数据最终会触发 JavaScript 中与该轨道关联的 `MediaStreamTrack` 的 `onended` 事件（当远程轨道结束时）或者通过添加到轨道的 `MediaStreamVideoSink` 来渲染。

*   **HTML:**  HTML 中的 `<video>` 元素通常用于显示视频流。当一个 `MediaStreamTrack`（其底层由 `MediaStreamRemoteVideoSource` 支持）被设置为 `<video>` 元素的 `srcObject` 时，`MediaStreamRemoteVideoSource` 处理的视频帧最终会被渲染到这个 `<video>` 元素上。
    *   **例子:**
        ```html
        <video id="remoteVideo" autoplay playsinline></video>
        <script>
          const remoteVideoElement = document.getElementById('remoteVideo');
          peerConnection.ontrack = (event) => {
            if (event.track.kind === 'video') {
              remoteVideoElement.srcObject = event.streams[0];
            }
          };
        </script>
        ```
        在这个例子中，当 `peerConnection.ontrack` 接收到视频轨道时，`MediaStreamRemoteVideoSource` 会处理这个轨道的视频帧，最终这些帧会显示在 `remoteVideo` 元素中。

*   **CSS:** CSS 可以用来控制 `<video>` 元素的样式和布局，但它不直接影响 `MediaStreamRemoteVideoSource` 的功能。

**逻辑推理的例子 (基于 `TEST_F(MediaStreamRemoteVideoSourceTest, StartTrack)`):**

*   **假设输入:**
    1. 创建了一个 `MediaStreamRemoteVideoSource` 对象。
    2. 创建了一个与该 `MediaStreamRemoteVideoSource` 关联的 `MediaStreamVideoTrack`。
    3. 向该 `MediaStreamVideoTrack` 添加了一个 `MockMediaStreamVideoSink` 作为接收器。
    4. 通过 `source()->SinkInterfaceForTesting()->OnFrame()` 方法向 `MediaStreamRemoteVideoSource` 输入一个黑色的 `webrtc::VideoFrame`。
*   **预期输出:**
    1. `NumberOfSuccessConstraintsCallbacks()` 应该返回 1，表示轨道成功启动。
    2. `MockMediaStreamVideoSink` 的 `OnVideoFrame` 方法应该被调用一次。
    3. `sink.number_of_frames()` 应该返回 1，表示接收到一个视频帧。

**用户或编程常见的使用错误举例：**

1. **未正确处理 `MediaStreamTrack` 的 `onended` 事件:**  如果开发者没有监听并处理远程视频轨道的结束事件，可能会导致 UI 上仍然显示已结束的视频，或者程序逻辑出现错误。`MediaStreamRemoteVideoSource` 在底层负责检测远程轨道的结束，并通过 `MediaStreamSource` 通知上层。
    *   **错误示例 (JavaScript):**
        ```javascript
        peerConnection.ontrack = (event) => {
          if (event.track.kind === 'video') {
            remoteVideoTrack = event.track;
            remoteVideoElement.srcObject = event.streams[0];
            // 忘记监听 onended 事件
          }
        };
        ```

2. **过早地移除视频接收器 (Sink):**  如果在视频流仍在播放时，就从 `MediaStreamVideoTrack` 中移除了接收器 (`MediaStreamVideoSink`)，可能会导致视频无法显示，但底层的数据仍然在传输，造成资源浪费。`MediaStreamRemoteVideoSource` 会继续接收和处理数据，直到没有接收器或者轨道结束。
    *   **错误示例 (JavaScript):**
        ```javascript
        const sink = new MediaStreamVideoSink(remoteVideoTrack);
        // ... 一段时间后 ...
        remoteVideoTrack.removeSink(sink); // 可能过早移除
        ```

3. **假设视频帧总是按顺序到达:** 虽然 `MediaStreamRemoteVideoSource` 会尽力按时间戳排序处理帧，但在网络不稳定的情况下，帧可能会乱序到达。如果应用逻辑依赖于严格的帧顺序，可能会出现问题。

**用户操作是如何一步步到达这里的作为调试线索：**

1. **用户发起或接收 WebRTC 通话:** 用户可能点击了一个按钮发起视频通话，或者接受了一个来电。
2. **建立 PeerConnection:**  JavaScript 代码会使用 `RTCPeerConnection` API 来建立与远程用户的连接。
3. **协商媒体流:**  通过 SDP 协商，确定双方的音视频能力。
4. **接收远程视频轨道:**  远程用户的视频流数据开始通过网络传输。本地的 `peerConnection` 对象会触发 `ontrack` 事件，其中包含远程的 `MediaStreamTrack`。
5. **Blink 创建 `MediaStreamRemoteVideoSource`:** 当接收到远程视频轨道时，Blink 引擎会创建一个 `MediaStreamRemoteVideoSource` 对象来处理这个轨道的数据。
6. **接收和处理视频帧:** 底层的 WebRTC 实现接收到视频数据包后，会解码并将其转换为 `webrtc::VideoFrame`，然后通过 `TrackObserver` 传递给 `MediaStreamRemoteVideoSource`。
7. **调试线索:** 如果在视频通话过程中出现以下问题，开发者可能会需要查看 `media_stream_remote_video_source_test.cc` 相关的代码或进行断点调试：
    *   **远程视频画面显示异常 (例如，卡顿、花屏、黑屏):**  可能涉及到视频帧的接收、处理或渲染环节的问题。
    *   **远程视频不同步:**  可能涉及到时间戳处理的问题。
    *   **远程视频轨道结束但本地没有正确处理:**  可能涉及到生命周期管理的问题。

通过阅读 `media_stream_remote_video_source_test.cc` 中的测试用例，开发者可以更好地理解 `MediaStreamRemoteVideoSource` 的预期行为，并根据测试用例提供的场景进行调试，例如：

*   检查 `OnFrame` 方法是否被正确调用。
*   查看接收到的视频帧的元数据是否正确。
*   验证在轨道结束时，相关的回调函数是否被触发。

总而言之，`media_stream_remote_video_source_test.cc` 是一个确保 Chromium Blink 引擎能够正确处理远程视频流的关键测试文件，它间接地支撑了 WebRTC 在浏览器中的功能，而 WebRTC 又直接服务于 web 开发者构建实时的音视频应用。

Prompt: 
```
这是目录为blink/renderer/modules/peerconnection/media_stream_remote_video_source_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/peerconnection/media_stream_remote_video_source.h"

#include <memory>
#include <utility>

#include "base/functional/bind.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/gmock_callback_support.h"
#include "base/test/scoped_feature_list.h"
#include "base/time/time.h"
#include "media/base/video_frame.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom-blink.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_sink.h"
#include "third_party/blink/renderer/modules/peerconnection/adapters/web_rtc_cross_thread_copier.h"
#include "third_party/blink/renderer/modules/peerconnection/mock_peer_connection_dependency_factory.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/webrtc/track_observer.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/webrtc/api/rtp_packet_infos.h"
#include "third_party/webrtc/api/video/color_space.h"
#include "third_party/webrtc/api/video/i420_buffer.h"
#include "third_party/webrtc/system_wrappers/include/clock.h"
#include "ui/gfx/color_space.h"

namespace blink {

namespace {
using base::test::RunOnceClosure;
using ::testing::_;
using ::testing::Gt;
using ::testing::SaveArg;
using ::testing::Sequence;
}  // namespace

webrtc::VideoFrame::Builder CreateBlackFrameBuilder() {
  rtc::scoped_refptr<webrtc::I420Buffer> buffer =
      webrtc::I420Buffer::Create(8, 8);
  webrtc::I420Buffer::SetBlack(buffer.get());
  return webrtc::VideoFrame::Builder().set_video_frame_buffer(buffer);
}

class MediaStreamRemoteVideoSourceUnderTest
    : public blink::MediaStreamRemoteVideoSource {
 public:
  explicit MediaStreamRemoteVideoSourceUnderTest(
      std::unique_ptr<blink::TrackObserver> observer)
      : MediaStreamRemoteVideoSource(
            scheduler::GetSingleThreadTaskRunnerForTesting(),
            std::move(observer)) {}
  using MediaStreamRemoteVideoSource::EncodedSinkInterfaceForTesting;
  using MediaStreamRemoteVideoSource::SinkInterfaceForTesting;
  using MediaStreamRemoteVideoSource::StartSourceImpl;
};

class MediaStreamRemoteVideoSourceTest : public ::testing::Test {
 public:
  MediaStreamRemoteVideoSourceTest()
      : mock_factory_(
            MakeGarbageCollected<MockPeerConnectionDependencyFactory>()),
        webrtc_video_source_(blink::MockWebRtcVideoTrackSource::Create(
            /*supports_encoded_output=*/true)),
        webrtc_video_track_(
            blink::MockWebRtcVideoTrack::Create("test", webrtc_video_source_)) {
  }

  void SetUp() override {
    scoped_refptr<base::SingleThreadTaskRunner> main_thread =
        blink::scheduler::GetSingleThreadTaskRunnerForTesting();

    base::WaitableEvent waitable_event(
        base::WaitableEvent::ResetPolicy::MANUAL,
        base::WaitableEvent::InitialState::NOT_SIGNALED);

    std::unique_ptr<blink::TrackObserver> track_observer;
    mock_factory_->GetWebRtcSignalingTaskRunner()->PostTask(
        FROM_HERE,
        ConvertToBaseOnceCallback(CrossThreadBindOnce(
            [](scoped_refptr<base::SingleThreadTaskRunner> main_thread,
               webrtc::MediaStreamTrackInterface* webrtc_track,
               std::unique_ptr<blink::TrackObserver>* track_observer,
               base::WaitableEvent* waitable_event) {
              *track_observer = std::make_unique<blink::TrackObserver>(
                  main_thread, webrtc_track);
              waitable_event->Signal();
            },
            main_thread, CrossThreadUnretained(webrtc_video_track_.get()),
            CrossThreadUnretained(&track_observer),
            CrossThreadUnretained(&waitable_event))));
    waitable_event.Wait();

    auto remote_source =
        std::make_unique<MediaStreamRemoteVideoSourceUnderTest>(
            std::move(track_observer));
    remote_source_ = remote_source.get();
    source_ = MakeGarbageCollected<MediaStreamSource>(
        "dummy_source_id", MediaStreamSource::kTypeVideo, "dummy_source_name",
        true /* remote */, std::move(remote_source));
  }

  void TearDown() override {
    remote_source_->OnSourceTerminated();
    source_ = nullptr;
    blink::WebHeap::CollectAllGarbageForTesting();
  }

  MediaStreamRemoteVideoSourceUnderTest* source() { return remote_source_; }

  blink::MediaStreamVideoTrack* CreateTrack() {
    bool enabled = true;
    return new blink::MediaStreamVideoTrack(
        source(),
        ConvertToBaseOnceCallback(CrossThreadBindOnce(
            &MediaStreamRemoteVideoSourceTest::OnTrackStarted,
            CrossThreadUnretained(this))),
        enabled);
  }

  int NumberOfSuccessConstraintsCallbacks() const {
    return number_of_successful_track_starts_;
  }

  int NumberOfFailedConstraintsCallbacks() const {
    return number_of_failed_track_starts_;
  }

  void StopWebRtcTrack() {
    base::WaitableEvent waitable_event(
        base::WaitableEvent::ResetPolicy::MANUAL,
        base::WaitableEvent::InitialState::NOT_SIGNALED);
    mock_factory_->GetWebRtcSignalingTaskRunner()->PostTask(
        FROM_HERE,
        ConvertToBaseOnceCallback(CrossThreadBindOnce(
            [](blink::MockWebRtcVideoTrack* video_track,
               base::WaitableEvent* waitable_event) {
              video_track->SetEnded();
              waitable_event->Signal();
            },
            CrossThreadUnretained(static_cast<blink::MockWebRtcVideoTrack*>(
                webrtc_video_track_.get())),
            CrossThreadUnretained(&waitable_event))));
    waitable_event.Wait();
  }

  MediaStreamSource* Source() const { return source_.Get(); }

  const base::TimeDelta& time_diff() const { return time_diff_; }

 private:
  void OnTrackStarted(blink::WebPlatformMediaStreamSource* source,
                      blink::mojom::MediaStreamRequestResult result,
                      const blink::WebString& result_name) {
    ASSERT_EQ(source, remote_source_);
    if (result == blink::mojom::MediaStreamRequestResult::OK)
      ++number_of_successful_track_starts_;
    else
      ++number_of_failed_track_starts_;
  }

  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;
  Persistent<blink::MockPeerConnectionDependencyFactory> mock_factory_;
  scoped_refptr<webrtc::VideoTrackSourceInterface> webrtc_video_source_;
  scoped_refptr<webrtc::VideoTrackInterface> webrtc_video_track_;
  // |remote_source_| is owned by |source_|.
  raw_ptr<MediaStreamRemoteVideoSourceUnderTest, DanglingUntriaged>
      remote_source_ = nullptr;
  Persistent<MediaStreamSource> source_;
  int number_of_successful_track_starts_ = 0;
  int number_of_failed_track_starts_ = 0;
  // WebRTC Chromium timestamp diff
  const base::TimeDelta time_diff_;
};

TEST_F(MediaStreamRemoteVideoSourceTest, StartTrack) {
  std::unique_ptr<blink::MediaStreamVideoTrack> track(CreateTrack());
  EXPECT_EQ(1, NumberOfSuccessConstraintsCallbacks());

  blink::MockMediaStreamVideoSink sink;
  track->AddSink(&sink, sink.GetDeliverFrameCB(),
                 MediaStreamVideoSink::IsSecure::kNo,
                 MediaStreamVideoSink::UsesAlpha::kDefault);
  base::RunLoop run_loop;
  base::RepeatingClosure quit_closure = run_loop.QuitClosure();
  EXPECT_CALL(sink, OnVideoFrame)
      .WillOnce(RunOnceClosure(std::move(quit_closure)));
  rtc::scoped_refptr<webrtc::I420Buffer> buffer(
      new rtc::RefCountedObject<webrtc::I420Buffer>(320, 240));

  webrtc::I420Buffer::SetBlack(buffer.get());

  source()->SinkInterfaceForTesting()->OnFrame(
      webrtc::VideoFrame::Builder()
          .set_video_frame_buffer(buffer)
          .set_timestamp_us(1000)
          .build());
  run_loop.Run();

  EXPECT_EQ(1, sink.number_of_frames());
  track->RemoveSink(&sink);
}

TEST_F(MediaStreamRemoteVideoSourceTest,
       SourceTerminationWithEncodedSinkAdded) {
  std::unique_ptr<blink::MediaStreamVideoTrack> track(CreateTrack());
  blink::MockMediaStreamVideoSink sink;
  track->AddEncodedSink(&sink, sink.GetDeliverEncodedVideoFrameCB());
  source()->OnSourceTerminated();
  track->RemoveEncodedSink(&sink);
}

TEST_F(MediaStreamRemoteVideoSourceTest,
       SourceTerminationBeforeEncodedSinkAdded) {
  std::unique_ptr<blink::MediaStreamVideoTrack> track(CreateTrack());
  blink::MockMediaStreamVideoSink sink;
  source()->OnSourceTerminated();
  track->AddEncodedSink(&sink, sink.GetDeliverEncodedVideoFrameCB());
  track->RemoveEncodedSink(&sink);
}

TEST_F(MediaStreamRemoteVideoSourceTest,
       SourceTerminationBeforeRequestRefreshFrame) {
  source()->OnSourceTerminated();
  source()->RequestRefreshFrame();
}

TEST_F(MediaStreamRemoteVideoSourceTest, SurvivesSourceTermination) {
  std::unique_ptr<blink::MediaStreamVideoTrack> track(CreateTrack());

  blink::MockMediaStreamVideoSink sink;
  track->AddSink(&sink, sink.GetDeliverFrameCB(),
                 MediaStreamVideoSink::IsSecure::kNo,
                 MediaStreamVideoSink::UsesAlpha::kDefault);
  EXPECT_EQ(blink::WebMediaStreamSource::kReadyStateLive, sink.state());
  EXPECT_EQ(MediaStreamSource::kReadyStateLive, Source()->GetReadyState());
  StopWebRtcTrack();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(MediaStreamSource::kReadyStateEnded, Source()->GetReadyState());
  EXPECT_EQ(blink::WebMediaStreamSource::kReadyStateEnded, sink.state());

  track->RemoveSink(&sink);
}

TEST_F(MediaStreamRemoteVideoSourceTest, PreservesColorSpace) {
  std::unique_ptr<blink::MediaStreamVideoTrack> track(CreateTrack());
  blink::MockMediaStreamVideoSink sink;
  track->AddSink(&sink, sink.GetDeliverFrameCB(),
                 MediaStreamVideoSink::IsSecure::kNo,
                 MediaStreamVideoSink::UsesAlpha::kDefault);

  base::RunLoop run_loop;
  EXPECT_CALL(sink, OnVideoFrame)
      .WillOnce(RunOnceClosure(run_loop.QuitClosure()));
  rtc::scoped_refptr<webrtc::I420Buffer> buffer(
      new rtc::RefCountedObject<webrtc::I420Buffer>(320, 240));
  webrtc::ColorSpace kColorSpace(webrtc::ColorSpace::PrimaryID::kSMPTE240M,
                                 webrtc::ColorSpace::TransferID::kSMPTE240M,
                                 webrtc::ColorSpace::MatrixID::kSMPTE240M,
                                 webrtc::ColorSpace::RangeID::kLimited);
  const webrtc::VideoFrame& input_frame = webrtc::VideoFrame::Builder()
                                              .set_video_frame_buffer(buffer)
                                              .set_color_space(kColorSpace)
                                              .build();
  source()->SinkInterfaceForTesting()->OnFrame(input_frame);
  run_loop.Run();

  EXPECT_EQ(1, sink.number_of_frames());
  scoped_refptr<media::VideoFrame> output_frame = sink.last_frame();
  EXPECT_TRUE(output_frame);
  EXPECT_TRUE(output_frame->ColorSpace() ==
              gfx::ColorSpace(gfx::ColorSpace::PrimaryID::SMPTE240M,
                              gfx::ColorSpace::TransferID::SMPTE240M,
                              gfx::ColorSpace::MatrixID::SMPTE240M,
                              gfx::ColorSpace::RangeID::LIMITED));
  track->RemoveSink(&sink);
}

TEST_F(MediaStreamRemoteVideoSourceTest,
       UnspecifiedColorSpaceIsTreatedAsBt709) {
  std::unique_ptr<blink::MediaStreamVideoTrack> track(CreateTrack());
  blink::MockMediaStreamVideoSink sink;
  track->AddSink(&sink, sink.GetDeliverFrameCB(),
                 MediaStreamVideoSink::IsSecure::kNo,
                 MediaStreamVideoSink::UsesAlpha::kDefault);

  base::RunLoop run_loop;
  EXPECT_CALL(sink, OnVideoFrame)
      .WillOnce(RunOnceClosure(run_loop.QuitClosure()));
  rtc::scoped_refptr<webrtc::I420Buffer> buffer(
      new rtc::RefCountedObject<webrtc::I420Buffer>(320, 240));
  webrtc::ColorSpace kColorSpace(webrtc::ColorSpace::PrimaryID::kUnspecified,
                                 webrtc::ColorSpace::TransferID::kUnspecified,
                                 webrtc::ColorSpace::MatrixID::kUnspecified,
                                 webrtc::ColorSpace::RangeID::kLimited);
  const webrtc::VideoFrame& input_frame = webrtc::VideoFrame::Builder()
                                              .set_video_frame_buffer(buffer)
                                              .set_color_space(kColorSpace)
                                              .build();
  source()->SinkInterfaceForTesting()->OnFrame(input_frame);
  run_loop.Run();

  EXPECT_EQ(1, sink.number_of_frames());
  scoped_refptr<media::VideoFrame> output_frame = sink.last_frame();
  EXPECT_TRUE(output_frame);
  EXPECT_TRUE(output_frame->ColorSpace() ==
              gfx::ColorSpace(gfx::ColorSpace::PrimaryID::BT709,
                              gfx::ColorSpace::TransferID::BT709,
                              gfx::ColorSpace::MatrixID::BT709,
                              gfx::ColorSpace::RangeID::LIMITED));
  track->RemoveSink(&sink);
}

TEST_F(MediaStreamRemoteVideoSourceTest, UnspecifiedColorSpaceIsIgnored) {
  base::test::ScopedFeatureList scoped_feauture_list;
  scoped_feauture_list.InitAndEnableFeature(
      blink::features::kWebRtcIgnoreUnspecifiedColorSpace);
  std::unique_ptr<blink::MediaStreamVideoTrack> track(CreateTrack());
  blink::MockMediaStreamVideoSink sink;
  track->AddSink(&sink, sink.GetDeliverFrameCB(),
                 MediaStreamVideoSink::IsSecure::kNo,
                 MediaStreamVideoSink::UsesAlpha::kDefault);

  base::RunLoop run_loop;
  EXPECT_CALL(sink, OnVideoFrame)
      .WillOnce(RunOnceClosure(run_loop.QuitClosure()));
  rtc::scoped_refptr<webrtc::I420Buffer> buffer(
      new rtc::RefCountedObject<webrtc::I420Buffer>(320, 240));
  webrtc::ColorSpace kColorSpace(webrtc::ColorSpace::PrimaryID::kUnspecified,
                                 webrtc::ColorSpace::TransferID::kUnspecified,
                                 webrtc::ColorSpace::MatrixID::kUnspecified,
                                 webrtc::ColorSpace::RangeID::kLimited);
  const webrtc::VideoFrame& input_frame = webrtc::VideoFrame::Builder()
                                              .set_video_frame_buffer(buffer)
                                              .set_color_space(kColorSpace)
                                              .build();
  source()->SinkInterfaceForTesting()->OnFrame(input_frame);
  run_loop.Run();

  EXPECT_EQ(1, sink.number_of_frames());
  scoped_refptr<media::VideoFrame> output_frame = sink.last_frame();
  EXPECT_TRUE(output_frame);
  EXPECT_TRUE(output_frame->ColorSpace() ==
              gfx::ColorSpace(gfx::ColorSpace::PrimaryID::INVALID,
                              gfx::ColorSpace::TransferID::INVALID,
                              gfx::ColorSpace::MatrixID::INVALID,
                              gfx::ColorSpace::RangeID::INVALID));
  track->RemoveSink(&sink);
}

TEST_F(MediaStreamRemoteVideoSourceTest,
       PopulateRequestAnimationFrameMetadata) {
  std::unique_ptr<blink::MediaStreamVideoTrack> track(CreateTrack());
  blink::MockMediaStreamVideoSink sink;
  track->AddSink(&sink, sink.GetDeliverFrameCB(),
                 MediaStreamVideoSink::IsSecure::kNo,
                 MediaStreamVideoSink::UsesAlpha::kDefault);

  base::RunLoop run_loop;
  EXPECT_CALL(sink, OnVideoFrame)
      .WillOnce(RunOnceClosure(run_loop.QuitClosure()));
  rtc::scoped_refptr<webrtc::I420Buffer> buffer(
      new rtc::RefCountedObject<webrtc::I420Buffer>(320, 240));

  uint32_t kSsrc = 0;
  const std::vector<uint32_t> kCsrcs;
  uint32_t kRtpTimestamp = 123456;
  float kProcessingTime = 0.014;

  const webrtc::Timestamp kProcessingFinish =
      webrtc::Timestamp::Millis(rtc::TimeMillis());
  const webrtc::Timestamp kProcessingStart =
      kProcessingFinish - webrtc::TimeDelta::Millis(1.0e3 * kProcessingTime);
  const webrtc::Timestamp kCaptureTime =
      kProcessingStart - webrtc::TimeDelta::Millis(20.0);
  webrtc::Clock* clock = webrtc::Clock::GetRealTimeClock();
  const int64_t ntp_offset =
      clock->CurrentNtpInMilliseconds() - clock->TimeInMilliseconds();
  const webrtc::Timestamp kCaptureTimeNtp =
      kCaptureTime + webrtc::TimeDelta::Millis(ntp_offset);
  // Expected capture time.
  base::TimeTicks kExpectedCaptureTime =
      base::TimeTicks() + base::Milliseconds(kCaptureTime.ms());

  webrtc::RtpPacketInfos::vector_type packet_infos;
  for (int i = 0; i < 4; ++i) {
    webrtc::Timestamp receive_time =
        kProcessingStart - webrtc::TimeDelta::Micros(10000 - i * 30);
    packet_infos.emplace_back(kSsrc, kCsrcs, kRtpTimestamp, receive_time);
  }
  // Expected receive time should be the same as the last arrival time.
  base::TimeTicks kExpectedReceiveTime =
      base::TimeTicks() +
      base::Microseconds(kProcessingStart.us() - (10000 - 3 * 30));

  webrtc::VideoFrame input_frame =
      webrtc::VideoFrame::Builder()
          .set_video_frame_buffer(buffer)
          .set_rtp_timestamp(kRtpTimestamp)
          .set_ntp_time_ms(kCaptureTimeNtp.ms())
          .set_packet_infos(webrtc::RtpPacketInfos(packet_infos))
          .build();

  input_frame.set_processing_time({kProcessingStart, kProcessingFinish});
  source()->SinkInterfaceForTesting()->OnFrame(input_frame);
  run_loop.Run();

  EXPECT_EQ(1, sink.number_of_frames());
  scoped_refptr<media::VideoFrame> output_frame = sink.last_frame();
  EXPECT_TRUE(output_frame);

  EXPECT_FLOAT_EQ(output_frame->metadata().processing_time->InSecondsF(),
                  kProcessingTime);

  // The NTP offset is estimated both here and in the code that is tested.
  // Therefore, we cannot exactly determine what capture_begin_time will be set
  // to.
  // TODO(kron): Find a lower tolerance without causing the test to be flaky or
  // make the clock injectable so that a fake clock can be used in the test.
  constexpr float kNtpOffsetToleranceMs = 40.0;
  EXPECT_NEAR(
      (*output_frame->metadata().capture_begin_time - kExpectedCaptureTime)
          .InMillisecondsF(),
      0.0f, kNtpOffsetToleranceMs);

  EXPECT_FLOAT_EQ(
      (*output_frame->metadata().receive_time - kExpectedReceiveTime)
          .InMillisecondsF(),
      0.0f);

  EXPECT_EQ(static_cast<uint32_t>(*output_frame->metadata().rtp_timestamp),
            kRtpTimestamp);

  track->RemoveSink(&sink);
}

TEST_F(MediaStreamRemoteVideoSourceTest, ReferenceTimeEqualsTimestampUs) {
  std::unique_ptr<blink::MediaStreamVideoTrack> track(CreateTrack());
  blink::MockMediaStreamVideoSink sink;
  track->AddSink(&sink, sink.GetDeliverFrameCB(),
                 MediaStreamVideoSink::IsSecure::kNo,
                 MediaStreamVideoSink::UsesAlpha::kDefault);

  base::RunLoop run_loop;
  EXPECT_CALL(sink, OnVideoFrame)
      .WillOnce(RunOnceClosure(run_loop.QuitClosure()));
  rtc::scoped_refptr<webrtc::I420Buffer> buffer(
      new rtc::RefCountedObject<webrtc::I420Buffer>(320, 240));

  int64_t kTimestampUs = rtc::TimeMicros();
  webrtc::VideoFrame input_frame = webrtc::VideoFrame::Builder()
                                       .set_video_frame_buffer(buffer)
                                       .set_timestamp_us(kTimestampUs)
                                       .build();

  source()->SinkInterfaceForTesting()->OnFrame(input_frame);
  run_loop.Run();

  EXPECT_EQ(1, sink.number_of_frames());
  scoped_refptr<media::VideoFrame> output_frame = sink.last_frame();
  EXPECT_TRUE(output_frame);

  EXPECT_FLOAT_EQ((*output_frame->metadata().reference_time -
                   (base::TimeTicks() + base::Microseconds(kTimestampUs)))
                      .InMillisecondsF(),
                  0.0f);
  track->RemoveSink(&sink);
}

TEST_F(MediaStreamRemoteVideoSourceTest, BaseTimeTicksAndRtcMicrosAreTheSame) {
  base::TimeTicks first_chromium_timestamp = base::TimeTicks::Now();
  base::TimeTicks webrtc_timestamp =
      base::TimeTicks() + base::Microseconds(rtc::TimeMicros());
  base::TimeTicks second_chromium_timestamp = base::TimeTicks::Now();

  // Test that the timestamps are correctly ordered, which they can only be if
  // the clocks are the same (assuming at least one of the clocks is functioning
  // correctly).
  EXPECT_GE((webrtc_timestamp - first_chromium_timestamp).InMillisecondsF(),
            0.0f);
  EXPECT_GE((second_chromium_timestamp - webrtc_timestamp).InMillisecondsF(),
            0.0f);
}

// This is a special case that is used to signal "render immediately".
TEST_F(MediaStreamRemoteVideoSourceTest, NoTimestampUsMeansNoReferenceTime) {
  std::unique_ptr<blink::MediaStreamVideoTrack> track(CreateTrack());
  blink::MockMediaStreamVideoSink sink;
  track->AddSink(&sink, sink.GetDeliverFrameCB(),
                 MediaStreamVideoSink::IsSecure::kNo,
                 MediaStreamVideoSink::UsesAlpha::kDefault);

  base::RunLoop run_loop;
  EXPECT_CALL(sink, OnVideoFrame)
      .WillOnce(RunOnceClosure(run_loop.QuitClosure()));
  rtc::scoped_refptr<webrtc::I420Buffer> buffer(
      new rtc::RefCountedObject<webrtc::I420Buffer>(320, 240));

  webrtc::VideoFrame input_frame =
      webrtc::VideoFrame::Builder().set_video_frame_buffer(buffer).build();
  input_frame.set_render_parameters({.use_low_latency_rendering = true});

  source()->SinkInterfaceForTesting()->OnFrame(input_frame);
  run_loop.Run();

  EXPECT_EQ(1, sink.number_of_frames());
  scoped_refptr<media::VideoFrame> output_frame = sink.last_frame();
  EXPECT_TRUE(output_frame);

  EXPECT_FALSE(output_frame->metadata().reference_time.has_value());

  track->RemoveSink(&sink);
}

class TestEncodedVideoFrame : public webrtc::RecordableEncodedFrame {
 public:
  explicit TestEncodedVideoFrame(webrtc::Timestamp timestamp)
      : timestamp_(timestamp) {}

  rtc::scoped_refptr<const webrtc::EncodedImageBufferInterface> encoded_buffer()
      const override {
    return nullptr;
  }
  std::optional<webrtc::ColorSpace> color_space() const override {
    return std::nullopt;
  }
  webrtc::VideoCodecType codec() const override {
    return webrtc::kVideoCodecVP8;
  }
  bool is_key_frame() const override { return true; }
  EncodedResolution resolution() const override {
    return EncodedResolution{0, 0};
  }
  webrtc::Timestamp render_time() const override { return timestamp_; }

 private:
  webrtc::Timestamp timestamp_;
};

TEST_F(MediaStreamRemoteVideoSourceTest, ForwardsEncodedVideoFrames) {
  std::unique_ptr<blink::MediaStreamVideoTrack> track(CreateTrack());
  blink::MockMediaStreamVideoSink sink;
  track->AddEncodedSink(&sink, sink.GetDeliverEncodedVideoFrameCB());
  base::RunLoop run_loop;
  base::RepeatingClosure quit_closure = run_loop.QuitClosure();
  EXPECT_CALL(sink, OnEncodedVideoFrame)
      .WillOnce(RunOnceClosure(std::move(quit_closure)));
  source()->EncodedSinkInterfaceForTesting()->OnFrame(
      TestEncodedVideoFrame(webrtc::Timestamp::Millis(0)));
  run_loop.Run();
  track->RemoveEncodedSink(&sink);
}

TEST_F(MediaStreamRemoteVideoSourceTest,
       ForwardsFramesWithIncreasingTimestampsWithNullSourceTimestamp) {
  std::unique_ptr<blink::MediaStreamVideoTrack> track(CreateTrack());
  blink::MockMediaStreamVideoSink sink;
  track->AddSink(&sink, sink.GetDeliverFrameCB(),
                 MediaStreamVideoSink::IsSecure::kNo,
                 MediaStreamVideoSink::UsesAlpha::kDefault);
  base::RunLoop run_loop;
  base::RepeatingClosure quit_closure = run_loop.QuitClosure();

  base::TimeTicks frame_timestamp1;
  Sequence s;
  EXPECT_CALL(sink, OnVideoFrame)
      .InSequence(s)
      .WillOnce(SaveArg<0>(&frame_timestamp1));
  EXPECT_CALL(sink, OnVideoFrame(Gt(frame_timestamp1)))
      .InSequence(s)
      .WillOnce(RunOnceClosure(std::move(quit_closure)));
  source()->SinkInterfaceForTesting()->OnFrame(
      CreateBlackFrameBuilder().set_timestamp_ms(0).build());
  // Spin until the time counter changes.
  base::TimeTicks now = base::TimeTicks::Now();
  while (base::TimeTicks::Now() == now) {
  }
  source()->SinkInterfaceForTesting()->OnFrame(
      CreateBlackFrameBuilder().set_timestamp_ms(0).build());
  run_loop.Run();
  track->RemoveSink(&sink);
}

TEST_F(MediaStreamRemoteVideoSourceTest,
       ForwardsFramesWithIncreasingTimestampsWithSourceTimestamp) {
  std::unique_ptr<blink::MediaStreamVideoTrack> track(CreateTrack());
  blink::MockMediaStreamVideoSink sink;
  track->AddSink(&sink, sink.GetDeliverFrameCB(),
                 MediaStreamVideoSink::IsSecure::kNo,
                 MediaStreamVideoSink::UsesAlpha::kDefault);
  base::RunLoop run_loop;
  base::RepeatingClosure quit_closure = run_loop.QuitClosure();

  base::TimeTicks frame_timestamp1;
  Sequence s;
  EXPECT_CALL(sink, OnVideoFrame)
      .InSequence(s)
      .WillOnce(SaveArg<0>(&frame_timestamp1));
  EXPECT_CALL(sink, OnVideoFrame(Gt(frame_timestamp1)))
      .InSequence(s)
      .WillOnce(RunOnceClosure(std::move(quit_closure)));
  source()->SinkInterfaceForTesting()->OnFrame(
      CreateBlackFrameBuilder().set_timestamp_ms(4711).build());
  source()->SinkInterfaceForTesting()->OnFrame(
      CreateBlackFrameBuilder().set_timestamp_ms(4712).build());
  run_loop.Run();
  track->RemoveSink(&sink);
}

TEST_F(MediaStreamRemoteVideoSourceTest,
       ForwardsEncodedFramesWithIncreasingTimestampsWithNullSourceTimestamp) {
  std::unique_ptr<blink::MediaStreamVideoTrack> track(CreateTrack());
  blink::MockMediaStreamVideoSink sink;
  track->AddEncodedSink(&sink, sink.GetDeliverEncodedVideoFrameCB());
  base::RunLoop run_loop;
  base::RepeatingClosure quit_closure = run_loop.QuitClosure();

  base::TimeTicks frame_timestamp1;
  Sequence s;
  EXPECT_CALL(sink, OnEncodedVideoFrame)
      .InSequence(s)
      .WillOnce(SaveArg<0>(&frame_timestamp1));
  EXPECT_CALL(sink, OnEncodedVideoFrame(Gt(frame_timestamp1)))
      .InSequence(s)
      .WillOnce(RunOnceClosure(std::move(quit_closure)));
  source()->EncodedSinkInterfaceForTesting()->OnFrame(
      TestEncodedVideoFrame(webrtc::Timestamp::Millis(0)));
  // Spin until the time counter changes.
  base::TimeTicks now = base::TimeTicks::Now();
  while (base::TimeTicks::Now() == now) {
  }
  source()->EncodedSinkInterfaceForTesting()->OnFrame(
      TestEncodedVideoFrame(webrtc::Timestamp::Millis(0)));
  run_loop.Run();
  track->RemoveEncodedSink(&sink);
}

TEST_F(MediaStreamRemoteVideoSourceTest,
       ForwardsEncodedFramesWithIncreasingTimestampsWithSourceTimestamp) {
  std::unique_ptr<blink::MediaStreamVideoTrack> track(CreateTrack());
  blink::MockMediaStreamVideoSink sink;
  track->AddEncodedSink(&sink, sink.GetDeliverEncodedVideoFrameCB());
  base::RunLoop run_loop;
  base::RepeatingClosure quit_closure = run_loop.QuitClosure();

  base::TimeTicks frame_timestamp1;
  Sequence s;
  EXPECT_CALL(sink, OnEncodedVideoFrame)
      .InSequence(s)
      .WillOnce(SaveArg<0>(&frame_timestamp1));
  EXPECT_CALL(sink, OnEncodedVideoFrame(Gt(frame_timestamp1)))
      .InSequence(s)
      .WillOnce(RunOnceClosure(std::move(quit_closure)));
  source()->EncodedSinkInterfaceForTesting()->OnFrame(
      TestEncodedVideoFrame(webrtc::Timestamp::Millis(42)));
  source()->EncodedSinkInterfaceForTesting()->OnFrame(
      TestEncodedVideoFrame(webrtc::Timestamp::Millis(43)));
  run_loop.Run();
  track->RemoveEncodedSink(&sink);
}

}  // namespace blink

"""

```