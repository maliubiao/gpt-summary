Response:
The user wants a summary of the C++ code provided. I need to analyze the code and identify its main functionalities. The code is a unit test file for `MediaStreamVideoTrack` in the Chromium Blink engine. This means it tests various aspects of how video tracks in a media stream behave.

Here's a breakdown of what the code seems to be testing:

- **Adding and removing sinks:** How video frames are delivered to consumers (sinks) and how connecting/disconnecting works.
- **Enabling/disabling the track:**  How the `enabled` state affects frame delivery.
- **Source lifecycle:** How the track reacts when the underlying video source starts, stops, or is detached.
- **Requesting frames:** How the track can request new frames from the source.
- **Getting track settings:**  Retrieving information about the video track like width, height, and frame rate.
- **Frame statistics:** Tracking the number of delivered, discarded, and dropped frames.
- **Frame dropping and logging:**  Testing how dropped frames are recorded and logged, including mechanisms to prevent excessive logging.
- **Content hints:**  Testing if content hints set on the track are propagated.
- **Sub-capture target version:** Testing how the track handles frames with different sub-capture target versions.
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include <utility>

#include "base/functional/callback.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/histogram_macros.h"
#include "base/run_loop.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/bind.h"
#include "base/test/gmock_callback_support.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/threading/thread_checker.h"
#include "media/base/video_frame.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom-blink.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/mock_encoded_video_frame.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_sink.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_source.h"
#include "third_party/blink/renderer/modules/mediastream/video_track_adapter_settings.h"
#include "third_party/blink/renderer/modules/peerconnection/media_stream_video_webrtc_sink.h"
#include "third_party/blink/renderer/modules/peerconnection/mock_peer_connection_dependency_factory.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

// To avoid symbol collisions in jumbo builds.
namespace media_stream_video_track_test {

using base::test::RunOnceClosure;
using ::testing::_;
using ::testing::Eq;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Optional;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::Values;

using ContentHintType = WebMediaStreamTrack::ContentHintType;

const uint8_t kBlackValue = 0x00;
const uint8_t kColorValue = 0xAB;
const int kMockSourceWidth = 640;
const int kMockSourceHeight = 480;
const double kMinFrameRate = 30.0;

class MockEmitLogMessageCb {
 public:
  MOCK_METHOD1(EmitLogMessage, void(const std::string&));

  base::RepeatingCallback<void(const std::string&)> Callback() {
    return base::BindRepeating(base::BindLambdaForTesting(
        [this](const std::string& message) { EmitLogMessage(message); }));
  }
};

class MediaStreamVideoTrackTest
    : public testing::TestWithParam<ContentHintType> {
 public:
  MediaStreamVideoTrackTest() : mock_source_(nullptr) {}

  ~MediaStreamVideoTrackTest() override {}

  void TearDown() override {
    mock_source_ = nullptr;
    source_ = nullptr;
    WebHeap::CollectAllGarbageForTesting();
  }

  void DeliverVideoFrameAndWaitForRenderer(
      scoped_refptr<media::VideoFrame> frame,
      MockMediaStreamVideoSink* sink) {
    base::RunLoop run_loop;
    base::RepeatingClosure quit_closure = run_loop.QuitClosure();
    EXPECT_CALL(*sink, OnVideoFrame)
        .WillOnce(RunOnceClosure(std::move(quit_closure)));
    mock_source()->DeliverVideoFrame(std::move(frame));
    run_loop.Run();
  }

  void DeliverEncodedVideoFrameAndWait(scoped_refptr<EncodedVideoFrame> frame,
                                       MockMediaStreamVideoSink* sink) {
    base::RunLoop run_loop;
    base::RepeatingClosure quit_closure = run_loop.QuitClosure();
    EXPECT_CALL(*sink, OnEncodedVideoFrame)
        .WillOnce(
            Invoke([&](base::TimeTicks) { std::move(quit_closure).Run(); }));
    mock_source()->DeliverEncodedVideoFrame(frame);
    run_loop.Run();
  }

  void DeliverDefaultSizeVideoFrameAndWaitForRenderer(
      MockMediaStreamVideoSink* sink) {
    const scoped_refptr<media::VideoFrame> frame =
        media::VideoFrame::CreateColorFrame(
            gfx::Size(MediaStreamVideoSource::kDefaultWidth,
                      MediaStreamVideoSource::kDefaultHeight),
            kColorValue, kColorValue, kColorValue, base::TimeDelta());
    DeliverVideoFrameAndWaitForRenderer(frame, sink);
  }

 protected:
  virtual void InitializeSource() {
    source_ = nullptr;
    auto mock_source = std::make_unique<MockMediaStreamVideoSource>(
        media::VideoCaptureFormat(
            gfx::Size(kMockSourceWidth, kMockSourceHeight), 30.0,
            media::PIXEL_FORMAT_I420),
        false);
    mock_source_ = mock_source.get();
    MediaStreamDevice device = mock_source_->device();
    device.type = mojom::blink::MediaStreamType::DEVICE_VIDEO_CAPTURE;
    mock_source_->SetDevice(device);
    source_ = MakeGarbageCollected<MediaStreamSource>(
        "dummy_source_id", MediaStreamSource::kTypeVideo, "dummy_source_name",
        false /* remote */, std::move(mock_source));
  }

  // Create a track that's associated with |mock_source_|.
  WebMediaStreamTrack CreateTrack() {
    const bool enabled = true;
    WebMediaStreamTrack track = MediaStreamVideoTrack::CreateVideoTrack(
        mock_source_, WebPlatformMediaStreamSource::ConstraintsOnceCallback(),
        enabled);
    if (!source_started_) {
      mock_source_->StartMockedSource();
      source_started_ = true;
    }
    return track;
  }

  // Create a track that's associated with |mock_source_| and has the given
  // |adapter_settings|.
  WebMediaStreamTrack CreateTrackWithSettings(
      const VideoTrackAdapterSettings& adapter_settings) {
    const bool enabled = true;
    WebMediaStreamTrack track = MediaStreamVideoTrack::CreateVideoTrack(
        mock_source_, adapter_settings, std::optional<bool>(), false, 0.0,
        nullptr, false, WebPlatformMediaStreamSource::ConstraintsOnceCallback(),
        enabled);
    if (!source_started_) {
      mock_source_->StartMockedSource();
      source_started_ = true;
    }
    return track;
  }

  void UpdateVideoSourceToRespondToRequestRefreshFrame() {
    source_ = nullptr;
    auto mock_source = std::make_unique<MockMediaStreamVideoSource>(
        media::VideoCaptureFormat(
            gfx::Size(kMockSourceWidth, kMockSourceHeight), 30.0,
            media::PIXEL_FORMAT_I420),
        true);
    mock_source_ = mock_source.get();
    source_ = MakeGarbageCollected<MediaStreamSource>(
        "dummy_source_id", MediaStreamSource::kTypeVideo, "dummy_source_name",
        false /* remote */, std::move(mock_source));
  }

  void DepleteIOCallbacks() {
    base::RunLoop run_loop;
    base::RepeatingClosure quit_closure = run_loop.QuitClosure();
    mock_source()->video_task_runner()->PostTask(
        FROM_HERE,
        base::BindLambdaForTesting([&] { std::move(quit_closure).Run(); }));
    run_loop.Run();
  }

  MockMediaStreamVideoSource* mock_source() { return mock_source_; }
  MediaStreamSource* stream_source() const { return source_; }

 private:
  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;
  Persistent<MediaStreamSource> source_;
  // |mock_source_| is owned by |source_|.
  raw_ptr<MockMediaStreamVideoSource> mock_source_;
  bool source_started_ = false;
};

TEST_F(MediaStreamVideoTrackTest, AddAndRemoveSink) {
  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectToTrack(track);

  DeliverDefaultSizeVideoFrameAndWaitForRenderer(&sink);
  EXPECT_EQ(1, sink.number_of_frames());

  DeliverDefaultSizeVideoFrameAndWaitForRenderer(&sink);

  sink.DisconnectFromTrack();

  scoped_refptr<media::VideoFrame> frame = media::VideoFrame::CreateBlackFrame(
      gfx::Size(MediaStreamVideoSource::kDefaultWidth,
                MediaStreamVideoSource::kDefaultHeight));
  mock_source()->DeliverVideoFrame(frame);
  // Wait for the video task runner to complete delivering frames.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(2, sink.number_of_frames());
}

class CheckThreadHelper {
 public:
  CheckThreadHelper(base::OnceClosure callback, bool* correct)
      : callback_(std::move(callback)), correct_(correct) {}

  ~CheckThreadHelper() {
    DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
    *correct_ = true;
    std::move(callback_).Run();
  }

 private:
  base::OnceClosure callback_;
  raw_ptr<bool> correct_;
  THREAD_CHECKER(thread_checker_);
};

void CheckThreadVideoFrameReceiver(
    CheckThreadHelper* helper,
    scoped_refptr<media::VideoFrame> frame,
    base::TimeTicks estimated_capture_time) {
  // Do nothing.
}

// Checks that the callback given to the track is reset on the right thread.
TEST_F(MediaStreamVideoTrackTest, ResetCallbackOnThread) {
  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();

  base::RunLoop run_loop;
  bool correct = false;
  sink.ConnectToTrackWithCallback(
      track, WTF::BindRepeating(&CheckThreadVideoFrameReceiver,
                                base::Owned(new CheckThreadHelper(
                                    run_loop.QuitClosure(), &correct))));
  sink.DisconnectFromTrack();
  run_loop.Run();
  EXPECT_TRUE(correct) << "Not called on correct thread.";
}

TEST_F(MediaStreamVideoTrackTest, SetEnabled) {
  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectToTrack(track);

  MediaStreamVideoTrack* video_track = MediaStreamVideoTrack::From(track);

  DeliverDefaultSizeVideoFrameAndWaitForRenderer(&sink);
  EXPECT_EQ(1, sink.number_of_frames());
  EXPECT_EQ(kColorValue,
            *sink.last_frame()->data(media::VideoFrame::Plane::kY));

  video_track->SetEnabled(false);
  EXPECT_FALSE(sink.enabled());

  DeliverDefaultSizeVideoFrameAndWaitForRenderer(&sink);
  EXPECT_EQ(2, sink.number_of_frames());
  EXPECT_EQ(kBlackValue,
            *sink.last_frame()->data(media::VideoFrame::Plane::kY));

  video_track->SetEnabled(true);
  EXPECT_TRUE(sink.enabled());
  DeliverDefaultSizeVideoFrameAndWaitForRenderer(&sink);
  EXPECT_EQ(3, sink.number_of_frames());
  EXPECT_EQ(kColorValue,
            *sink.last_frame()->data(media::VideoFrame::Plane::kY));
  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoTrackTest, SourceDetached) {
  InitializeSource();
  WebMediaStreamTrack track = CreateTrack();
  MockMediaStreamVideoSink sink;
  auto* video_track = MediaStreamVideoTrack::From(track);
  video_track->StopAndNotify(base::DoNothing());
  sink.ConnectToTrack(track);
  sink.ConnectEncodedToTrack(track);
  video_track->SetEnabled(true);
  video_track->SetEnabled(false);
  MediaStreamTrackPlatform::Settings settings;
  video_track->GetSettings(settings);
  sink.DisconnectFromTrack();
  sink.DisconnectEncodedFromTrack();
}

TEST_F(MediaStreamVideoTrackTest, SourceStopped) {
  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectToTrack(track);
  EXPECT_EQ(WebMediaStreamSource::kReadyStateLive, sink.state());

  mock_source()->StopSource();
  EXPECT_EQ(WebMediaStreamSource::kReadyStateEnded, sink.state());
  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoTrackTest, StopLastTrack) {
  InitializeSource();
  MockMediaStreamVideoSink sink1;
  WebMediaStreamTrack track1 = CreateTrack();
  sink1.ConnectToTrack(track1);
  EXPECT_EQ(WebMediaStreamSource::kReadyStateLive, sink1.state());

  EXPECT_EQ(MediaStreamSource::kReadyStateLive,
            stream_source()->GetReadyState());

  MockMediaStreamVideoSink sink2;
  WebMediaStreamTrack track2 = CreateTrack();
  sink2.ConnectToTrack(track2);
  EXPECT_EQ(WebMediaStreamSource::kReadyStateLive, sink2.state());

  MediaStreamVideoTrack* const native_track1 =
      MediaStreamVideoTrack::From(track1);
  native_track1->Stop();
  EXPECT_EQ(WebMediaStreamSource::kReadyStateEnded, sink1.state());
  EXPECT_EQ(MediaStreamSource::kReadyStateLive,
            stream_source()->GetReadyState());
  sink1.DisconnectFromTrack();

  MediaStreamVideoTrack* const native_track2 =
      MediaStreamVideoTrack::From(track2);
  native_track2->Stop();
  EXPECT_EQ(WebMediaStreamSource::kReadyStateEnded, sink2.state());
  EXPECT_EQ(MediaStreamSource::kReadyStateEnded,
            stream_source()->GetReadyState());
  sink2.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoTrackTest, CheckTrackRequestsFrame) {
  InitializeSource();
  UpdateVideoSourceToRespondToRequestRefreshFrame();
  WebMediaStreamTrack track = CreateTrack();

  // Add sink and expect to get a frame.
  MockMediaStreamVideoSink sink;
  base::RunLoop run_loop;
  base::RepeatingClosure quit_closure = run_loop.QuitClosure();
  EXPECT_CALL(sink, OnVideoFrame)
      .WillOnce(RunOnceClosure(std::move(quit_closure)));
  sink.ConnectToTrack(track);
  run_loop.Run();
  EXPECT_EQ(1, sink.number_of_frames());

  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoTrackTest, GetSettings) {
  InitializeSource();
  WebMediaStreamTrack track = CreateTrack();
  MediaStreamVideoTrack* const native_track =
      MediaStreamVideoTrack::From(track);
  MediaStreamTrackPlatform::Settings settings;
  native_track->GetSettings(settings);
  // These values come straight from the mock video track implementation.
  EXPECT_EQ(640, settings.width);
  EXPECT_EQ(480, settings.height);
  EXPECT_EQ(30.0, settings.frame_rate);
  EXPECT_EQ(MediaStreamTrackPlatform::FacingMode::kNone, settings.facing_mode);
}

TEST_F(MediaStreamVideoTrackTest, GetSettingsWithAdjustment) {
  InitializeSource();
  const int kAdjustedWidth = 600;
  const int kAdjustedHeight = 400;
  const double kAdjustedFrameRate = 20.0;
  VideoTrackAdapterSettings adapter_settings(
      gfx::Size(kAdjustedWidth, kAdjustedHeight), 0.0, 10000.0,
      kAdjustedFrameRate);
  WebMediaStreamTrack track = CreateTrackWithSettings(adapter_settings);
  MediaStreamVideoTrack* const native_track =
      MediaStreamVideoTrack::From(track);
  MediaStreamTrackPlatform::Settings settings;
  native_track->GetSettings(settings);
  EXPECT_EQ(kAdjustedWidth, settings.width);
  EXPECT_EQ(kAdjustedHeight, settings.height);
  EXPECT_EQ(kAdjustedFrameRate, settings.frame_rate);
  EXPECT_EQ(MediaStreamTrackPlatform::FacingMode::kNone, settings.facing_mode);
}

TEST_F(MediaStreamVideoTrackTest, GetSettingsStopped) {
  InitializeSource();
  WebMediaStreamTrack track = CreateTrack();
  MediaStreamVideoTrack* const native_track =
      MediaStreamVideoTrack::From(track);
  native_track->Stop();
  MediaStreamTrackPlatform::Settings settings;
  native_track->GetSettings(settings);
  EXPECT_EQ(-1, settings.width);
  EXPECT_EQ(-1, settings.height);
  EXPECT_EQ(-1, settings.frame_rate);
  EXPECT_EQ(MediaStreamTrackPlatform::FacingMode::kNone, settings.facing_mode);
  EXPECT_TRUE(settings.device_id.IsNull());
}

TEST_F(MediaStreamVideoTrackTest, DeliverFramesAndGetSettings) {
  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectToTrack(track);
  MediaStreamVideoTrack* const native_track =
      MediaStreamVideoTrack::From(track);
  EXPECT_FALSE(native_track->max_frame_rate().has_value());
  MediaStreamTrackPlatform::Settings settings;

  auto frame1 = media::VideoFrame::CreateBlackFrame(gfx::Size(600, 400));
  DeliverVideoFrameAndWaitForRenderer(std::move(frame1), &sink);
  native_track->GetSettings(settings);
  EXPECT_EQ(600, settings.width);
  EXPECT_EQ(400, settings.height);

  auto frame2 = media::VideoFrame::CreateBlackFrame(gfx::Size(200, 300));
  DeliverVideoFrameAndWaitForRenderer(std::move(frame2), &sink);
  native_track->GetSettings(settings);
  EXPECT_EQ(200, settings.width);
  EXPECT_EQ(300, settings.height);

  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoTrackTest, FrameStatsIncrementsForEnabledTracks) {
  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectToTrack(track);
  MediaStreamVideoTrack* const native_track =
      MediaStreamVideoTrack::From(track);
  EXPECT_FALSE(native_track->max_frame_rate().has_value());

  // Initially, no fames have been delivered.
  MediaStreamTrackPlatform::VideoFrameStats stats =
      native_track->GetVideoFrameStats();
  EXPECT_EQ(stats.deliverable_frames, 0u);
  EXPECT_EQ(stats.discarded_frames, 0u);
  EXPECT_EQ(stats.dropped_frames, 0u);

  // Deliver a frame an expect counter to increment to 1.
  DeliverVideoFrameAndWaitForRenderer(
      media::VideoFrame::CreateBlackFrame(gfx::Size(600, 400)), &sink);
  stats = native_track->GetVideoFrameStats();
  EXPECT_EQ(stats.deliverable_frames, 1u);
  EXPECT_EQ(stats.discarded_frames, 0u);
  EXPECT_EQ(stats.dropped_frames, 0u);

  // Discard one frame (due to frame rate decimation) and drop two frames (other
  // reasons);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::
          kResolutionAdapterFrameRateIsHigherThanRequested);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kGpuMemoryBufferMapFailed);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kGpuMemoryBufferMapFailed);
  DepleteIOCallbacks();
  stats = native_track->GetVideoFrameStats();
  EXPECT_EQ(stats.deliverable_frames, 1u);
  EXPECT_EQ(stats.discarded_frames, 1u);
  EXPECT_EQ(stats.dropped_frames, 2u);

  // And some more...
  DeliverVideoFrameAndWaitForRenderer(
      media::VideoFrame::CreateBlackFrame(gfx::Size(600, 400)), &sink);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::
          kResolutionAdapterFrameRateIsHigherThanRequested);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::
          kResolutionAdapterFrameRateIsHigherThanRequested);
  DepleteIOCallbacks();
  stats = native_track->GetVideoFrameStats();
  EXPECT_EQ(stats.deliverable_frames, 2u);
  EXPECT_EQ(stats.discarded_frames, 3u);
  EXPECT_EQ(stats.dropped_frames, 2u);

  // Disable the track and verify the frame counters do NOT increment, even as
  // frame delivery and dropped callbacks are invoked.
  native_track->SetEnabled(false);
  DeliverVideoFrameAndWaitForRenderer(
      media::VideoFrame::CreateBlackFrame(gfx::Size(600, 400)), &sink);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::
          kResolutionAdapterFrameRateIsHigherThanRequested);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kGpuMemoryBufferMapFailed);
  DepleteIOCallbacks();
  stats = native_track->GetVideoFrameStats();
  EXPECT_EQ(stats.deliverable_frames, 2u);
  EXPECT_EQ(stats.discarded_frames, 3u);
  EXPECT_EQ(stats.dropped_frames, 2u);

  // Enable it again, and business as usual...
  native_track->SetEnabled(true);
  DeliverVideoFrameAndWaitForRenderer(
      media::VideoFrame::CreateBlackFrame(gfx::Size(600, 400)), &sink);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::
          kResolutionAdapterFrameRateIsHigherThanRequested);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kGpuMemoryBufferMapFailed);
  DepleteIOCallbacks();
  stats = native_track->GetVideoFrameStats();
  EXPECT_EQ(stats.deliverable_frames, 3u);
  EXPECT_EQ(stats.discarded_frames, 4u);
  EXPECT_EQ(stats.dropped_frames, 3u);

  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoTrackTest, DroppedFramesGetLoggedInUMA) {
  base::HistogramTester histogram_tester;

  InitializeSource();
  CreateTrack();
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kBufferPoolMaxBufferCountExceeded);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  DepleteIOCallbacks();

  histogram_tester.ExpectBucketCount(
      "Media.VideoCapture.Track.FrameDrop.DeviceCapture",
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat,
      2);
  histogram_tester.ExpectBucketCount(
      "Media.VideoCapture.Track.FrameDrop.DeviceCapture",
      media::VideoCaptureFrameDropReason::kBufferPoolMaxBufferCountExceeded, 1);
}

// Tests that too many frames dropped for the same reason emits a special UMA
// log and disables further logging
TEST_F(MediaStreamVideoTrackTest,
       DroppedFrameLoggingGetsDisabledIfTooManyConsecutiveDropsForSameReason) {
  base::HistogramTester histogram_tester;

  InitializeSource();
  CreateTrack();
  for (int i = 0;
       i < MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount;
       i++) {
    mock_source()->DropFrame(
        media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  }
  DepleteIOCallbacks();
  histogram_tester.ExpectBucketCount(
      "Media.VideoCapture.Track.FrameDrop.DeviceCapture",
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat,
      MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount);

  // Add one more count after already having reached the max allowed.
  // This should not get counted.
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  DepleteIOCallbacks();
  histogram_tester.ExpectBucketCount(
      "Media.VideoCapture.Track.FrameDrop.DeviceCapture",
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat,
      MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount);
}

TEST_F(MediaStreamVideoTrackTest,
       DeliveredFrameInBetweenDroppedFramesResetsCounter) {
  base::HistogramTester histogram_tester;

  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectToTrack(track);
  for (int i = 0;
       i <
       MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount - 1;
       i++) {
    mock_source()->DropFrame(
        media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  }
  DeliverVideoFrameAndWaitForRenderer(
      media::VideoFrame::CreateBlackFrame(gfx::Size(600, 400)), &sink);

  for (int i = 0;
       i < MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount;
       i++) {
    mock_source()->DropFrame(
        media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  }
  DepleteIOCallbacks();
  histogram_tester.ExpectBucketCount(
      "Media.VideoCapture.Track.FrameDrop.DeviceCapture",
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat,
      2 * MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount -
          1);
}

TEST_F(MediaStreamVideoTrackTest, DeliveredFrameReenablesDroppedFrameLogging) {
  base::HistogramTester histogram_tester;

  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectToTrack(track);
  // Drop enough frames to disable logging
  for (int i = 0;
       i <
       MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount + 1;
       i++) {
    mock_source()->DropFrame(
        media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  }
  DeliverVideoFrameAndWaitForRenderer(
      media::VideoFrame::CreateBlackFrame(gfx::Size(600, 400)), &sink);

  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  DepleteIOCallbacks();
  histogram_tester.ExpectBucketCount(
      "Media.VideoCapture.Track.FrameDrop.DeviceCapture",
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat,
      MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount + 1);
}

TEST_F(MediaStreamVideoTrackTest,
       ChangeInDropReasonReenablesDroppedFrameLogging) {
  base::HistogramTester histogram_tester;

  InitializeSource();
  CreateTrack();
  // Drop enough frames to disable logging
  for (int i = 0;
       i <
       MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount + 1;
       i++) {
    mock_source()->DropFrame(
        media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  }

  // Drop for a different reason
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kBufferPoolMaxBufferCountExceeded);

  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  DepleteIOCallbacks();
  histogram_tester.ExpectBucketCount(
      "Media.VideoCapture.Track.FrameDrop.DeviceCapture",
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat,
      MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount + 1);
  histogram_tester.ExpectBucketCount(
      "Media.VideoCapture.Track.FrameDrop.DeviceCapture",
      media::VideoCaptureFrameDropReason::kBufferPoolMaxBufferCountExceeded, 1);
}

TEST_F(MediaStreamVideoTrackTest, DroppedFrameCausesLogToBeEmitted) {
  constexpr media::VideoCaptureFrameDropReason kReason1 =
      static_cast<media::VideoCaptureFrameDropReason>(1);

  NiceMock<MockEmitLogMessageCb> emit_log_message_mock_;
  InitializeSource();
  auto* video_track = MediaStreamVideoTrack::From(CreateTrack());
  video_track->SetEmitLogMessageForTesting(emit_log_message_mock_.Callback());

  EXPECT_CALL(emit_log_message_mock_,
              EmitLogMessage(StrEq("Frame dropped with reason code 1.")))
      .Times(1);
  mock_source()->DropFrame(kReason1);
  DepleteIOCallbacks();
}

TEST_F(MediaStreamVideoTrackTest, DroppedFrameEmittedLogEventuallySuppressed) {
  constexpr media::VideoCaptureFrameDropReason kReason1 =
      static_cast<media::VideoCaptureFrameDropReason>(1);
  constexpr int kBeforeSuppressing =
      MediaStreamVideoTrack::kMaxEmittedLogsForDroppedFramesBeforeSuppressing;

  NiceMock<MockEmitLogMessageCb> emit_log_message_mock_;
  InitializeSource();
  auto* video_track = MediaStreamVideoTrack::From(CreateTrack());
  video_track->SetEmitLogMessageForTesting(emit_log_message_mock_.Callback());

  InSequence s;
  EXPECT_CALL(emit_log_message_mock_,
              EmitLogMessage(StrEq("Frame dropped with reason code 1.")))
      .Times(kBeforeSuppressing - 1);
  EXPECT_CALL(
      emit_log_message_mock_,
      EmitLogMessage(StrEq("Frame dropped with reason code 1. Additional logs "
                           "will be partially suppressed.")))
      .Times(1);
  EXPECT_CALL(emit_log_message_mock_, EmitLogMessage(_)).Times(0);

  // (Note that we drop N+1 times, and the last time is suppressed.)
  for (int i = 0; i < kBeforeSuppressing + 1; ++i) {
    mock_source()->DropFrame(kReason1);
  }
  DepleteIOCallbacks();
}

TEST_F(MediaStreamVideoTrackTest,
       DroppedFrameEmittedLogSuppressionOverOneReasonDoesNotAffectAnother) {
  constexpr media::VideoCaptureFrameDropReason kReason1 =
      static_cast<media::VideoCaptureFrameDropReason>(1);
  constexpr media::VideoCaptureFrameDropReason kReason2 =
      static_cast<media::VideoCaptureFrameDropReason>(2);
  constexpr int kBeforeSuppressing =
      MediaStreamVideoTrack::kMaxEmittedLogsForDroppedFramesBeforeSuppressing;

  NiceMock<MockEmitLogMessageCb> emit_log_message_mock_;
  InitializeSource();
  auto* video_track = MediaStreamVideoTrack::From(CreateTrack());
  video_track->SetEmitLogMessageForTesting(emit_log_message_mock_.Callback());

  // Emit reason-1 until it becomes suppressed.
  for (int i = 0; i < kBeforeSuppressing; ++i)
Prompt: 
```
这是目录为blink/renderer/modules/mediastream/media_stream_video_track_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include <utility>

#include "base/functional/callback.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/histogram_macros.h"
#include "base/run_loop.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/bind.h"
#include "base/test/gmock_callback_support.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/threading/thread_checker.h"
#include "media/base/video_frame.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom-blink.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/mock_encoded_video_frame.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_sink.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_source.h"
#include "third_party/blink/renderer/modules/mediastream/video_track_adapter_settings.h"
#include "third_party/blink/renderer/modules/peerconnection/media_stream_video_webrtc_sink.h"
#include "third_party/blink/renderer/modules/peerconnection/mock_peer_connection_dependency_factory.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

// To avoid symbol collisions in jumbo builds.
namespace media_stream_video_track_test {

using base::test::RunOnceClosure;
using ::testing::_;
using ::testing::Eq;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Optional;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::Values;

using ContentHintType = WebMediaStreamTrack::ContentHintType;

const uint8_t kBlackValue = 0x00;
const uint8_t kColorValue = 0xAB;
const int kMockSourceWidth = 640;
const int kMockSourceHeight = 480;
const double kMinFrameRate = 30.0;

class MockEmitLogMessageCb {
 public:
  MOCK_METHOD1(EmitLogMessage, void(const std::string&));

  base::RepeatingCallback<void(const std::string&)> Callback() {
    return base::BindRepeating(base::BindLambdaForTesting(
        [this](const std::string& message) { EmitLogMessage(message); }));
  }
};

class MediaStreamVideoTrackTest
    : public testing::TestWithParam<ContentHintType> {
 public:
  MediaStreamVideoTrackTest() : mock_source_(nullptr) {}

  ~MediaStreamVideoTrackTest() override {}

  void TearDown() override {
    mock_source_ = nullptr;
    source_ = nullptr;
    WebHeap::CollectAllGarbageForTesting();
  }

  void DeliverVideoFrameAndWaitForRenderer(
      scoped_refptr<media::VideoFrame> frame,
      MockMediaStreamVideoSink* sink) {
    base::RunLoop run_loop;
    base::RepeatingClosure quit_closure = run_loop.QuitClosure();
    EXPECT_CALL(*sink, OnVideoFrame)
        .WillOnce(RunOnceClosure(std::move(quit_closure)));
    mock_source()->DeliverVideoFrame(std::move(frame));
    run_loop.Run();
  }

  void DeliverEncodedVideoFrameAndWait(scoped_refptr<EncodedVideoFrame> frame,
                                       MockMediaStreamVideoSink* sink) {
    base::RunLoop run_loop;
    base::RepeatingClosure quit_closure = run_loop.QuitClosure();
    EXPECT_CALL(*sink, OnEncodedVideoFrame)
        .WillOnce(
            Invoke([&](base::TimeTicks) { std::move(quit_closure).Run(); }));
    mock_source()->DeliverEncodedVideoFrame(frame);
    run_loop.Run();
  }

  void DeliverDefaultSizeVideoFrameAndWaitForRenderer(
      MockMediaStreamVideoSink* sink) {
    const scoped_refptr<media::VideoFrame> frame =
        media::VideoFrame::CreateColorFrame(
            gfx::Size(MediaStreamVideoSource::kDefaultWidth,
                      MediaStreamVideoSource::kDefaultHeight),
            kColorValue, kColorValue, kColorValue, base::TimeDelta());
    DeliverVideoFrameAndWaitForRenderer(frame, sink);
  }

 protected:
  virtual void InitializeSource() {
    source_ = nullptr;
    auto mock_source = std::make_unique<MockMediaStreamVideoSource>(
        media::VideoCaptureFormat(
            gfx::Size(kMockSourceWidth, kMockSourceHeight), 30.0,
            media::PIXEL_FORMAT_I420),
        false);
    mock_source_ = mock_source.get();
    MediaStreamDevice device = mock_source_->device();
    device.type = mojom::blink::MediaStreamType::DEVICE_VIDEO_CAPTURE;
    mock_source_->SetDevice(device);
    source_ = MakeGarbageCollected<MediaStreamSource>(
        "dummy_source_id", MediaStreamSource::kTypeVideo, "dummy_source_name",
        false /* remote */, std::move(mock_source));
  }

  // Create a track that's associated with |mock_source_|.
  WebMediaStreamTrack CreateTrack() {
    const bool enabled = true;
    WebMediaStreamTrack track = MediaStreamVideoTrack::CreateVideoTrack(
        mock_source_, WebPlatformMediaStreamSource::ConstraintsOnceCallback(),
        enabled);
    if (!source_started_) {
      mock_source_->StartMockedSource();
      source_started_ = true;
    }
    return track;
  }

  // Create a track that's associated with |mock_source_| and has the given
  // |adapter_settings|.
  WebMediaStreamTrack CreateTrackWithSettings(
      const VideoTrackAdapterSettings& adapter_settings) {
    const bool enabled = true;
    WebMediaStreamTrack track = MediaStreamVideoTrack::CreateVideoTrack(
        mock_source_, adapter_settings, std::optional<bool>(), false, 0.0,
        nullptr, false, WebPlatformMediaStreamSource::ConstraintsOnceCallback(),
        enabled);
    if (!source_started_) {
      mock_source_->StartMockedSource();
      source_started_ = true;
    }
    return track;
  }

  void UpdateVideoSourceToRespondToRequestRefreshFrame() {
    source_ = nullptr;
    auto mock_source = std::make_unique<MockMediaStreamVideoSource>(
        media::VideoCaptureFormat(
            gfx::Size(kMockSourceWidth, kMockSourceHeight), 30.0,
            media::PIXEL_FORMAT_I420),
        true);
    mock_source_ = mock_source.get();
    source_ = MakeGarbageCollected<MediaStreamSource>(
        "dummy_source_id", MediaStreamSource::kTypeVideo, "dummy_source_name",
        false /* remote */, std::move(mock_source));
  }

  void DepleteIOCallbacks() {
    base::RunLoop run_loop;
    base::RepeatingClosure quit_closure = run_loop.QuitClosure();
    mock_source()->video_task_runner()->PostTask(
        FROM_HERE,
        base::BindLambdaForTesting([&] { std::move(quit_closure).Run(); }));
    run_loop.Run();
  }

  MockMediaStreamVideoSource* mock_source() { return mock_source_; }
  MediaStreamSource* stream_source() const { return source_; }

 private:
  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;
  Persistent<MediaStreamSource> source_;
  // |mock_source_| is owned by |source_|.
  raw_ptr<MockMediaStreamVideoSource> mock_source_;
  bool source_started_ = false;
};

TEST_F(MediaStreamVideoTrackTest, AddAndRemoveSink) {
  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectToTrack(track);

  DeliverDefaultSizeVideoFrameAndWaitForRenderer(&sink);
  EXPECT_EQ(1, sink.number_of_frames());

  DeliverDefaultSizeVideoFrameAndWaitForRenderer(&sink);

  sink.DisconnectFromTrack();

  scoped_refptr<media::VideoFrame> frame = media::VideoFrame::CreateBlackFrame(
      gfx::Size(MediaStreamVideoSource::kDefaultWidth,
                MediaStreamVideoSource::kDefaultHeight));
  mock_source()->DeliverVideoFrame(frame);
  // Wait for the video task runner to complete delivering frames.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(2, sink.number_of_frames());
}

class CheckThreadHelper {
 public:
  CheckThreadHelper(base::OnceClosure callback, bool* correct)
      : callback_(std::move(callback)), correct_(correct) {}

  ~CheckThreadHelper() {
    DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
    *correct_ = true;
    std::move(callback_).Run();
  }

 private:
  base::OnceClosure callback_;
  raw_ptr<bool> correct_;
  THREAD_CHECKER(thread_checker_);
};

void CheckThreadVideoFrameReceiver(
    CheckThreadHelper* helper,
    scoped_refptr<media::VideoFrame> frame,
    base::TimeTicks estimated_capture_time) {
  // Do nothing.
}

// Checks that the callback given to the track is reset on the right thread.
TEST_F(MediaStreamVideoTrackTest, ResetCallbackOnThread) {
  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();

  base::RunLoop run_loop;
  bool correct = false;
  sink.ConnectToTrackWithCallback(
      track, WTF::BindRepeating(&CheckThreadVideoFrameReceiver,
                                base::Owned(new CheckThreadHelper(
                                    run_loop.QuitClosure(), &correct))));
  sink.DisconnectFromTrack();
  run_loop.Run();
  EXPECT_TRUE(correct) << "Not called on correct thread.";
}

TEST_F(MediaStreamVideoTrackTest, SetEnabled) {
  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectToTrack(track);

  MediaStreamVideoTrack* video_track = MediaStreamVideoTrack::From(track);

  DeliverDefaultSizeVideoFrameAndWaitForRenderer(&sink);
  EXPECT_EQ(1, sink.number_of_frames());
  EXPECT_EQ(kColorValue,
            *sink.last_frame()->data(media::VideoFrame::Plane::kY));

  video_track->SetEnabled(false);
  EXPECT_FALSE(sink.enabled());

  DeliverDefaultSizeVideoFrameAndWaitForRenderer(&sink);
  EXPECT_EQ(2, sink.number_of_frames());
  EXPECT_EQ(kBlackValue,
            *sink.last_frame()->data(media::VideoFrame::Plane::kY));

  video_track->SetEnabled(true);
  EXPECT_TRUE(sink.enabled());
  DeliverDefaultSizeVideoFrameAndWaitForRenderer(&sink);
  EXPECT_EQ(3, sink.number_of_frames());
  EXPECT_EQ(kColorValue,
            *sink.last_frame()->data(media::VideoFrame::Plane::kY));
  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoTrackTest, SourceDetached) {
  InitializeSource();
  WebMediaStreamTrack track = CreateTrack();
  MockMediaStreamVideoSink sink;
  auto* video_track = MediaStreamVideoTrack::From(track);
  video_track->StopAndNotify(base::DoNothing());
  sink.ConnectToTrack(track);
  sink.ConnectEncodedToTrack(track);
  video_track->SetEnabled(true);
  video_track->SetEnabled(false);
  MediaStreamTrackPlatform::Settings settings;
  video_track->GetSettings(settings);
  sink.DisconnectFromTrack();
  sink.DisconnectEncodedFromTrack();
}

TEST_F(MediaStreamVideoTrackTest, SourceStopped) {
  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectToTrack(track);
  EXPECT_EQ(WebMediaStreamSource::kReadyStateLive, sink.state());

  mock_source()->StopSource();
  EXPECT_EQ(WebMediaStreamSource::kReadyStateEnded, sink.state());
  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoTrackTest, StopLastTrack) {
  InitializeSource();
  MockMediaStreamVideoSink sink1;
  WebMediaStreamTrack track1 = CreateTrack();
  sink1.ConnectToTrack(track1);
  EXPECT_EQ(WebMediaStreamSource::kReadyStateLive, sink1.state());

  EXPECT_EQ(MediaStreamSource::kReadyStateLive,
            stream_source()->GetReadyState());

  MockMediaStreamVideoSink sink2;
  WebMediaStreamTrack track2 = CreateTrack();
  sink2.ConnectToTrack(track2);
  EXPECT_EQ(WebMediaStreamSource::kReadyStateLive, sink2.state());

  MediaStreamVideoTrack* const native_track1 =
      MediaStreamVideoTrack::From(track1);
  native_track1->Stop();
  EXPECT_EQ(WebMediaStreamSource::kReadyStateEnded, sink1.state());
  EXPECT_EQ(MediaStreamSource::kReadyStateLive,
            stream_source()->GetReadyState());
  sink1.DisconnectFromTrack();

  MediaStreamVideoTrack* const native_track2 =
      MediaStreamVideoTrack::From(track2);
  native_track2->Stop();
  EXPECT_EQ(WebMediaStreamSource::kReadyStateEnded, sink2.state());
  EXPECT_EQ(MediaStreamSource::kReadyStateEnded,
            stream_source()->GetReadyState());
  sink2.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoTrackTest, CheckTrackRequestsFrame) {
  InitializeSource();
  UpdateVideoSourceToRespondToRequestRefreshFrame();
  WebMediaStreamTrack track = CreateTrack();

  // Add sink and expect to get a frame.
  MockMediaStreamVideoSink sink;
  base::RunLoop run_loop;
  base::RepeatingClosure quit_closure = run_loop.QuitClosure();
  EXPECT_CALL(sink, OnVideoFrame)
      .WillOnce(RunOnceClosure(std::move(quit_closure)));
  sink.ConnectToTrack(track);
  run_loop.Run();
  EXPECT_EQ(1, sink.number_of_frames());

  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoTrackTest, GetSettings) {
  InitializeSource();
  WebMediaStreamTrack track = CreateTrack();
  MediaStreamVideoTrack* const native_track =
      MediaStreamVideoTrack::From(track);
  MediaStreamTrackPlatform::Settings settings;
  native_track->GetSettings(settings);
  // These values come straight from the mock video track implementation.
  EXPECT_EQ(640, settings.width);
  EXPECT_EQ(480, settings.height);
  EXPECT_EQ(30.0, settings.frame_rate);
  EXPECT_EQ(MediaStreamTrackPlatform::FacingMode::kNone, settings.facing_mode);
}

TEST_F(MediaStreamVideoTrackTest, GetSettingsWithAdjustment) {
  InitializeSource();
  const int kAdjustedWidth = 600;
  const int kAdjustedHeight = 400;
  const double kAdjustedFrameRate = 20.0;
  VideoTrackAdapterSettings adapter_settings(
      gfx::Size(kAdjustedWidth, kAdjustedHeight), 0.0, 10000.0,
      kAdjustedFrameRate);
  WebMediaStreamTrack track = CreateTrackWithSettings(adapter_settings);
  MediaStreamVideoTrack* const native_track =
      MediaStreamVideoTrack::From(track);
  MediaStreamTrackPlatform::Settings settings;
  native_track->GetSettings(settings);
  EXPECT_EQ(kAdjustedWidth, settings.width);
  EXPECT_EQ(kAdjustedHeight, settings.height);
  EXPECT_EQ(kAdjustedFrameRate, settings.frame_rate);
  EXPECT_EQ(MediaStreamTrackPlatform::FacingMode::kNone, settings.facing_mode);
}

TEST_F(MediaStreamVideoTrackTest, GetSettingsStopped) {
  InitializeSource();
  WebMediaStreamTrack track = CreateTrack();
  MediaStreamVideoTrack* const native_track =
      MediaStreamVideoTrack::From(track);
  native_track->Stop();
  MediaStreamTrackPlatform::Settings settings;
  native_track->GetSettings(settings);
  EXPECT_EQ(-1, settings.width);
  EXPECT_EQ(-1, settings.height);
  EXPECT_EQ(-1, settings.frame_rate);
  EXPECT_EQ(MediaStreamTrackPlatform::FacingMode::kNone, settings.facing_mode);
  EXPECT_TRUE(settings.device_id.IsNull());
}

TEST_F(MediaStreamVideoTrackTest, DeliverFramesAndGetSettings) {
  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectToTrack(track);
  MediaStreamVideoTrack* const native_track =
      MediaStreamVideoTrack::From(track);
  EXPECT_FALSE(native_track->max_frame_rate().has_value());
  MediaStreamTrackPlatform::Settings settings;

  auto frame1 = media::VideoFrame::CreateBlackFrame(gfx::Size(600, 400));
  DeliverVideoFrameAndWaitForRenderer(std::move(frame1), &sink);
  native_track->GetSettings(settings);
  EXPECT_EQ(600, settings.width);
  EXPECT_EQ(400, settings.height);

  auto frame2 = media::VideoFrame::CreateBlackFrame(gfx::Size(200, 300));
  DeliverVideoFrameAndWaitForRenderer(std::move(frame2), &sink);
  native_track->GetSettings(settings);
  EXPECT_EQ(200, settings.width);
  EXPECT_EQ(300, settings.height);

  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoTrackTest, FrameStatsIncrementsForEnabledTracks) {
  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectToTrack(track);
  MediaStreamVideoTrack* const native_track =
      MediaStreamVideoTrack::From(track);
  EXPECT_FALSE(native_track->max_frame_rate().has_value());

  // Initially, no fames have been delivered.
  MediaStreamTrackPlatform::VideoFrameStats stats =
      native_track->GetVideoFrameStats();
  EXPECT_EQ(stats.deliverable_frames, 0u);
  EXPECT_EQ(stats.discarded_frames, 0u);
  EXPECT_EQ(stats.dropped_frames, 0u);

  // Deliver a frame an expect counter to increment to 1.
  DeliverVideoFrameAndWaitForRenderer(
      media::VideoFrame::CreateBlackFrame(gfx::Size(600, 400)), &sink);
  stats = native_track->GetVideoFrameStats();
  EXPECT_EQ(stats.deliverable_frames, 1u);
  EXPECT_EQ(stats.discarded_frames, 0u);
  EXPECT_EQ(stats.dropped_frames, 0u);

  // Discard one frame (due to frame rate decimation) and drop two frames (other
  // reasons);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::
          kResolutionAdapterFrameRateIsHigherThanRequested);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kGpuMemoryBufferMapFailed);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kGpuMemoryBufferMapFailed);
  DepleteIOCallbacks();
  stats = native_track->GetVideoFrameStats();
  EXPECT_EQ(stats.deliverable_frames, 1u);
  EXPECT_EQ(stats.discarded_frames, 1u);
  EXPECT_EQ(stats.dropped_frames, 2u);

  // And some more...
  DeliverVideoFrameAndWaitForRenderer(
      media::VideoFrame::CreateBlackFrame(gfx::Size(600, 400)), &sink);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::
          kResolutionAdapterFrameRateIsHigherThanRequested);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::
          kResolutionAdapterFrameRateIsHigherThanRequested);
  DepleteIOCallbacks();
  stats = native_track->GetVideoFrameStats();
  EXPECT_EQ(stats.deliverable_frames, 2u);
  EXPECT_EQ(stats.discarded_frames, 3u);
  EXPECT_EQ(stats.dropped_frames, 2u);

  // Disable the track and verify the frame counters do NOT increment, even as
  // frame delivery and dropped callbacks are invoked.
  native_track->SetEnabled(false);
  DeliverVideoFrameAndWaitForRenderer(
      media::VideoFrame::CreateBlackFrame(gfx::Size(600, 400)), &sink);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::
          kResolutionAdapterFrameRateIsHigherThanRequested);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kGpuMemoryBufferMapFailed);
  DepleteIOCallbacks();
  stats = native_track->GetVideoFrameStats();
  EXPECT_EQ(stats.deliverable_frames, 2u);
  EXPECT_EQ(stats.discarded_frames, 3u);
  EXPECT_EQ(stats.dropped_frames, 2u);

  // Enable it again, and business as usual...
  native_track->SetEnabled(true);
  DeliverVideoFrameAndWaitForRenderer(
      media::VideoFrame::CreateBlackFrame(gfx::Size(600, 400)), &sink);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::
          kResolutionAdapterFrameRateIsHigherThanRequested);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kGpuMemoryBufferMapFailed);
  DepleteIOCallbacks();
  stats = native_track->GetVideoFrameStats();
  EXPECT_EQ(stats.deliverable_frames, 3u);
  EXPECT_EQ(stats.discarded_frames, 4u);
  EXPECT_EQ(stats.dropped_frames, 3u);

  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoTrackTest, DroppedFramesGetLoggedInUMA) {
  base::HistogramTester histogram_tester;

  InitializeSource();
  CreateTrack();
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kBufferPoolMaxBufferCountExceeded);
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  DepleteIOCallbacks();

  histogram_tester.ExpectBucketCount(
      "Media.VideoCapture.Track.FrameDrop.DeviceCapture",
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat,
      2);
  histogram_tester.ExpectBucketCount(
      "Media.VideoCapture.Track.FrameDrop.DeviceCapture",
      media::VideoCaptureFrameDropReason::kBufferPoolMaxBufferCountExceeded, 1);
}

// Tests that too many frames dropped for the same reason emits a special UMA
// log and disables further logging
TEST_F(MediaStreamVideoTrackTest,
       DroppedFrameLoggingGetsDisabledIfTooManyConsecutiveDropsForSameReason) {
  base::HistogramTester histogram_tester;

  InitializeSource();
  CreateTrack();
  for (int i = 0;
       i < MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount;
       i++) {
    mock_source()->DropFrame(
        media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  }
  DepleteIOCallbacks();
  histogram_tester.ExpectBucketCount(
      "Media.VideoCapture.Track.FrameDrop.DeviceCapture",
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat,
      MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount);

  // Add one more count after already having reached the max allowed.
  // This should not get counted.
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  DepleteIOCallbacks();
  histogram_tester.ExpectBucketCount(
      "Media.VideoCapture.Track.FrameDrop.DeviceCapture",
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat,
      MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount);
}

TEST_F(MediaStreamVideoTrackTest,
       DeliveredFrameInBetweenDroppedFramesResetsCounter) {
  base::HistogramTester histogram_tester;

  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectToTrack(track);
  for (int i = 0;
       i <
       MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount - 1;
       i++) {
    mock_source()->DropFrame(
        media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  }
  DeliverVideoFrameAndWaitForRenderer(
      media::VideoFrame::CreateBlackFrame(gfx::Size(600, 400)), &sink);

  for (int i = 0;
       i < MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount;
       i++) {
    mock_source()->DropFrame(
        media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  }
  DepleteIOCallbacks();
  histogram_tester.ExpectBucketCount(
      "Media.VideoCapture.Track.FrameDrop.DeviceCapture",
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat,
      2 * MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount -
          1);
}

TEST_F(MediaStreamVideoTrackTest, DeliveredFrameReenablesDroppedFrameLogging) {
  base::HistogramTester histogram_tester;

  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectToTrack(track);
  // Drop enough frames to disable logging
  for (int i = 0;
       i <
       MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount + 1;
       i++) {
    mock_source()->DropFrame(
        media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  }
  DeliverVideoFrameAndWaitForRenderer(
      media::VideoFrame::CreateBlackFrame(gfx::Size(600, 400)), &sink);

  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  DepleteIOCallbacks();
  histogram_tester.ExpectBucketCount(
      "Media.VideoCapture.Track.FrameDrop.DeviceCapture",
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat,
      MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount + 1);
}

TEST_F(MediaStreamVideoTrackTest,
       ChangeInDropReasonReenablesDroppedFrameLogging) {
  base::HistogramTester histogram_tester;

  InitializeSource();
  CreateTrack();
  // Drop enough frames to disable logging
  for (int i = 0;
       i <
       MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount + 1;
       i++) {
    mock_source()->DropFrame(
        media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  }

  // Drop for a different reason
  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kBufferPoolMaxBufferCountExceeded);

  mock_source()->DropFrame(
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat);
  DepleteIOCallbacks();
  histogram_tester.ExpectBucketCount(
      "Media.VideoCapture.Track.FrameDrop.DeviceCapture",
      media::VideoCaptureFrameDropReason::kDeviceClientFrameHasInvalidFormat,
      MediaStreamVideoTrack::kMaxConsecutiveFrameDropForSameReasonCount + 1);
  histogram_tester.ExpectBucketCount(
      "Media.VideoCapture.Track.FrameDrop.DeviceCapture",
      media::VideoCaptureFrameDropReason::kBufferPoolMaxBufferCountExceeded, 1);
}

TEST_F(MediaStreamVideoTrackTest, DroppedFrameCausesLogToBeEmitted) {
  constexpr media::VideoCaptureFrameDropReason kReason1 =
      static_cast<media::VideoCaptureFrameDropReason>(1);

  NiceMock<MockEmitLogMessageCb> emit_log_message_mock_;
  InitializeSource();
  auto* video_track = MediaStreamVideoTrack::From(CreateTrack());
  video_track->SetEmitLogMessageForTesting(emit_log_message_mock_.Callback());

  EXPECT_CALL(emit_log_message_mock_,
              EmitLogMessage(StrEq("Frame dropped with reason code 1.")))
      .Times(1);
  mock_source()->DropFrame(kReason1);
  DepleteIOCallbacks();
}

TEST_F(MediaStreamVideoTrackTest, DroppedFrameEmittedLogEventuallySuppressed) {
  constexpr media::VideoCaptureFrameDropReason kReason1 =
      static_cast<media::VideoCaptureFrameDropReason>(1);
  constexpr int kBeforeSuppressing =
      MediaStreamVideoTrack::kMaxEmittedLogsForDroppedFramesBeforeSuppressing;

  NiceMock<MockEmitLogMessageCb> emit_log_message_mock_;
  InitializeSource();
  auto* video_track = MediaStreamVideoTrack::From(CreateTrack());
  video_track->SetEmitLogMessageForTesting(emit_log_message_mock_.Callback());

  InSequence s;
  EXPECT_CALL(emit_log_message_mock_,
              EmitLogMessage(StrEq("Frame dropped with reason code 1.")))
      .Times(kBeforeSuppressing - 1);
  EXPECT_CALL(
      emit_log_message_mock_,
      EmitLogMessage(StrEq("Frame dropped with reason code 1. Additional logs "
                           "will be partially suppressed.")))
      .Times(1);
  EXPECT_CALL(emit_log_message_mock_, EmitLogMessage(_)).Times(0);

  // (Note that we drop N+1 times, and the last time is suppressed.)
  for (int i = 0; i < kBeforeSuppressing + 1; ++i) {
    mock_source()->DropFrame(kReason1);
  }
  DepleteIOCallbacks();
}

TEST_F(MediaStreamVideoTrackTest,
       DroppedFrameEmittedLogSuppressionOverOneReasonDoesNotAffectAnother) {
  constexpr media::VideoCaptureFrameDropReason kReason1 =
      static_cast<media::VideoCaptureFrameDropReason>(1);
  constexpr media::VideoCaptureFrameDropReason kReason2 =
      static_cast<media::VideoCaptureFrameDropReason>(2);
  constexpr int kBeforeSuppressing =
      MediaStreamVideoTrack::kMaxEmittedLogsForDroppedFramesBeforeSuppressing;

  NiceMock<MockEmitLogMessageCb> emit_log_message_mock_;
  InitializeSource();
  auto* video_track = MediaStreamVideoTrack::From(CreateTrack());
  video_track->SetEmitLogMessageForTesting(emit_log_message_mock_.Callback());

  // Emit reason-1 until it becomes suppressed.
  for (int i = 0; i < kBeforeSuppressing; ++i) {
    mock_source()->DropFrame(kReason1);
  }
  DepleteIOCallbacks();

  // As per a previous test, log emission for reason-1 will now be suppressed.
  // However, this does not affect reason-2, which is counted separately.
  InSequence s;
  EXPECT_CALL(emit_log_message_mock_,
              EmitLogMessage(StrEq("Frame dropped with reason code 2.")))
      .Times(kBeforeSuppressing - 1);
  EXPECT_CALL(
      emit_log_message_mock_,
      EmitLogMessage(StrEq("Frame dropped with reason code 2. Additional logs "
                           "will be partially suppressed.")))
      .Times(1);
  EXPECT_CALL(emit_log_message_mock_, EmitLogMessage(_)).Times(0);

  // (Note that we drop N+1 times, and the last time is suppressed.)
  for (int i = 0; i < kBeforeSuppressing; ++i) {
    mock_source()->DropFrame(kReason2);
  }
  DepleteIOCallbacks();
}

TEST_F(MediaStreamVideoTrackTest,
       DroppedFrameEmittedLogEmittedAtReducedFrequencyIfSuppressed) {
  constexpr media::VideoCaptureFrameDropReason kReason1 =
      static_cast<media::VideoCaptureFrameDropReason>(1);
  constexpr int kBeforeSuppressing =
      MediaStreamVideoTrack::kMaxEmittedLogsForDroppedFramesBeforeSuppressing;
  constexpr int kSuppressedFrequency =
      MediaStreamVideoTrack::kFrequencyForSuppressedLogs;

  NiceMock<MockEmitLogMessageCb> emit_log_message_mock_;
  InitializeSource();
  auto* video_track = MediaStreamVideoTrack::From(CreateTrack());
  video_track->SetEmitLogMessageForTesting(emit_log_message_mock_.Callback());

  // Emit reason-1 until it becomes suppressed.
  int drops = 0;
  for (; drops < kBeforeSuppressing; ++drops) {
    mock_source()->DropFrame(kReason1);
  }
  DepleteIOCallbacks();

  // Logs stay suppressed until we reach kSuppressedFrequency.
  EXPECT_CALL(emit_log_message_mock_, EmitLogMessage(_)).Times(0);
  for (; drops < kSuppressedFrequency - 1; ++drops) {
    mock_source()->DropFrame(kReason1);
  }

  // Suppressed logs still emitted, but at reduced frequency.
  EXPECT_CALL(emit_log_message_mock_,
              EmitLogMessage(StrEq("Frame dropped with reason code 1.")))
      .Times(1);
  mock_source()->DropFrame(kReason1);
  DepleteIOCallbacks();
}

TEST_P(MediaStreamVideoTrackTest, PropagatesContentHintType) {
  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectToTrack(track);
  MediaStreamVideoTrack::From(track)->SetContentHint(GetParam());
  EXPECT_EQ(sink.content_hint(), GetParam());
  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoTrackTest,
       DeliversFramesWithCurrentSubCaptureTargetVersion) {
  InitializeSource();
  MockMediaStreamVideoSink sink;

  // Track is initialized with sub-capture-target version 5.
  EXPECT_CALL(*mock_source(), GetSubCaptureTargetVersion).WillOnce(Return(5));
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectToTrack(track);
  MediaStreamVideoTrack::From(track)->SetSinkNotifyFrameDroppedCallback(
      &sink, sink.GetNotifyFrameDroppedCB());

  scoped_refptr<media::VideoFrame> frame =
      media::VideoFrame::CreateBlackFrame(gfx::Size(600, 400));
  // Frame with current sub-capture-target version should be delivered.
  frame->metadata().sub_capture_target_version = 5;
  EXPECT_CALL(sink, OnNotifyFrameDropped).Times(0);
  DeliverVideoFrameAndWaitForRenderer(std::move(frame), &sink);

  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoTrackTest,
       DropsOldFramesWhenInitializedWithNewerSubCaptureTargetVersion) {
  InitializeSource();
  MockMediaStreamVideoSink sink;

  // Track is initialized with sub-capture-target version 5.
  EXPECT_CALL(*mock_source(), GetSubCaptureTargetVersion).WillOnce(Return(5));
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectToTrack(track);
  MediaStreamVideoTrack::From(track)->SetSinkNotifyFrameDroppedCallback(
      &sink, sink.GetNotifyFrameDroppedCB());

  scoped_refptr<media::VideoFrame> frame =
      media::VideoFrame::CreateBlackFrame(gfx::Size(600, 400));
  // Old sub-capture-target version delivered after construction.
  frame->metadata().sub_capture_target_version = 4;
  base::RunLoop run_loop;
  EXPECT_CALL(sink,
              OnNotifyFrameDropped(media::VideoCaptureFrameDropReason::
                                       kSubCaptureTargetVersionNotCurrent))
      .WillOnce(RunOnceClosure(run_loop.QuitClosure()));
  mock_source()->DeliverVideoFrame(std::move(frame));
  run_loop.Run();

  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoTrackTest,
       DropsOldFramesAfterSubCaptureTargetVersionChanges) {
  InitializeSource();
  MockMediaStreamVideoSink sink;

  // Track is initialized with sub-capture-target version 5.
  EXPECT_CALL(*mock_source(), GetSubCaptureTargetVersion).WillOnce(Return(5));
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectToTrack(track);
  MediaStreamVideoTrack::From(track)->SetSinkNotifyFrameDroppedCallback(
      &sink, sink.GetNotifyFrameDroppedCB());

  // Crop version updated to 6.
  mock_source()->DeliverNewSubCaptureTargetVersion(6);

  scoped_refptr<media::VideoFrame> frame =
      media::VideoFrame::CreateBlackFrame(gfx::Size(600, 400));
  frame->metadata().sub_capture_targe
"""


```