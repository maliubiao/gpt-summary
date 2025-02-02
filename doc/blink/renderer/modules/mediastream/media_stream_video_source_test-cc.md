Response:
The user wants to understand the functionality of the `media_stream_video_source_test.cc` file in the Chromium Blink engine.

Here's a breakdown of how to address each point:

1. **List its functionalities:** Identify the primary purpose of the file. Based on the name and the included headers (like `testing/gtest/include/gtest/gtest.h` and `third_party/blink/renderer/modules/mediastream/mock_media_stream_video_source.h`), it's clearly a unit test file. The tests likely focus on the `MediaStreamVideoSource` class.

2. **Relationship with Javascript, HTML, CSS:**  Consider how `MediaStreamVideoSource` interacts with web technologies. It's part of the implementation for media streams, which are exposed to Javascript through the `getUserMedia` API. Think about how these tests might relate to user actions in a web page.

3. **Logic Inference (Assumptions, Inputs, Outputs):**  Since it's a test file, the "logic inference" revolves around the setup and assertions within each test. For example, a test might *assume* a certain behavior of `MediaStreamVideoSource` when a track is added, then *input* an action like starting the source, and *output* a check on the number of callbacks.

4. **Common Usage Errors:** Think about how developers might misuse the `MediaStream` API or how the underlying implementation could have flaws. Examples could involve incorrect constraint settings, race conditions related to starting/stopping, etc.

5. **User Steps to Reach the Code (Debugging):** Trace back how a user interacting with a web page might trigger the code being tested. This involves the `getUserMedia` API, media stream tracks, and potentially rendering video.

6. **Summarize Functionality (for part 1):** Condense the findings into a concise summary of the file's purpose.

**Mental Sandbox Simulation:**

* **Functionality:**  The core is testing `MediaStreamVideoSource`. What aspects? Starting, stopping, adding tracks, handling constraints, frame processing, rotation, muting, reconfiguring, and restarting.
* **JS/HTML/CSS:**  `getUserMedia` in JS gets media. This test file is *behind the scenes*, validating that the C++ logic that powers video streams works correctly when JS interacts with it. HTML `<video>` element displays the result. CSS can style it.
* **Logic Inference:** A test adding a track and starting the source *assumes* a success callback. *Input*: `StartMockedSource()`. *Output*: Check the callback count. Another test might *assume* frame cropping happens. *Input*: Deliver a large frame. *Output*: Check the sink's frame size.
* **Usage Errors:**  A developer might expect a restart to work on a source that doesn't support it. This test has cases for that.
* **User Steps:** User visits a page -> Javascript calls `navigator.mediaDevices.getUserMedia({ video: true })` ->  Blink creates `MediaStreamVideoSource` -> This test verifies its behavior.
* **Summary for Part 1:** Focus on the core testing aspect and the range of functionalities covered so far.

Strategizing complete. Proceeding with response generation.
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "media/base/limits.h"
#include "media/base/video_frame.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom-blink.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/mock_constraint_factory.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_sink.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_source.h"
#include "third_party/blink/renderer/modules/mediastream/video_track_adapter.h"
#include "third_party/blink/renderer/modules/mediastream/video_track_adapter_settings.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::InSequence;
using ::testing::Mock;
using ::testing::Return;
using ::testing::SaveArg;

namespace blink {

const double kSourceFrameRate = 500.0;

class MediaStreamVideoSourceTest : public testing::Test {
 public:
  MediaStreamVideoSourceTest()
      : number_of_successful_constraints_applied_(0),
        number_of_failed_constraints_applied_(0),
        result_(mojom::MediaStreamRequestResult::OK),
        result_name_(""),
        mock_stream_video_source_(new MockMediaStreamVideoSource(
            media::VideoCaptureFormat(gfx::Size(1280, 720),
                                      kSourceFrameRate,
                                      media::PIXEL_FORMAT_I420),
            false)) {
    mock_stream_video_source_->DisableStopForRestart();
    stream_source_ = MakeGarbageCollected<MediaStreamSource>(
        String::FromUTF8("dummy_source_id"), MediaStreamSource::kTypeVideo,
        String::FromUTF8("dummy_source_name"), false /* remote */,
        base::WrapUnique(mock_stream_video_source_.get()));
    ON_CALL(*mock_stream_video_source_, OnSourceCanDiscardAlpha)
        .WillByDefault(Return());
    ON_CALL(*mock_stream_video_source_, SupportsEncodedOutput)
        .WillByDefault(Return(true));
  }

  void TearDown() override {
    stream_source_ = nullptr;
    WebHeap::CollectAllGarbageForTesting();
  }

  MOCK_METHOD0(MockNotification, void());

 protected:
  MediaStreamVideoSource* source() { return mock_stream_video_source_; }

  // Create a track that's associated with |stream_source_|.
  WebMediaStreamTrack CreateTrack(const String& id) {
    bool enabled = true;
    return MediaStreamVideoTrack::CreateVideoTrack(
        mock_stream_video_source_,
        WTF::BindOnce(&MediaStreamVideoSourceTest::OnConstraintsApplied,
                      base::Unretained(this)),
        enabled);
  }

  WebMediaStreamTrack CreateTrack(
      const String& id,
      const VideoTrackAdapterSettings& adapter_settings,
      const std::optional<bool>& noise_reduction,
      bool is_screencast,
      double min_frame_rate) {
    bool enabled = true;
    return MediaStreamVideoTrack::CreateVideoTrack(
        mock_stream_video_source_, adapter_settings, noise_reduction,
        is_screencast, min_frame_rate, nullptr, false,
        WTF::BindOnce(&MediaStreamVideoSourceTest::OnConstraintsApplied,
                      base::Unretained(this)),
        enabled);
  }

  WebMediaStreamTrack CreateTrack() {
    return CreateTrack("123",
                       VideoTrackAdapterSettings(gfx::Size(100, 100), 30.0),
                       std::optional<bool>(), false, 0.0);
  }

  WebMediaStreamTrack CreateTrackAndStartSource(
      int width,
      int height,
      std::optional<double> frame_rate,
      bool detect_rotation = false) {
    WebMediaStreamTrack track = CreateTrack(
        "123", VideoTrackAdapterSettings(gfx::Size(width, height), frame_rate),
        std::optional<bool>(), false, 0.0);

    EXPECT_EQ(0, NumberOfSuccessConstraintsCallbacks());
    mock_stream_video_source_->StartMockedSource();
    // Once the source has started successfully we expect that the
    // ConstraintsOnceCallback in WebPlatformMediaStreamSource::AddTrack
    // completes.
    EXPECT_EQ(1, NumberOfSuccessConstraintsCallbacks());
    return track;
  }

  int NumberOfSuccessConstraintsCallbacks() const {
    return number_of_successful_constraints_applied_;
  }

  int NumberOfFailedConstraintsCallbacks() const {
    return number_of_failed_constraints_applied_;
  }

  mojom::MediaStreamRequestResult error_type() const { return result_; }
  WebString error_name() const { return result_name_; }

  MockMediaStreamVideoSource* mock_source() {
    return mock_stream_video_source_;
  }

  MediaStreamSource* stream_source() { return stream_source_.Get(); }

  void TestSourceCropFrame(int capture_width,
                           int capture_height,
                           int expected_width,
                           int expected_height) {
    // Configure the track to crop to the expected resolution.
    WebMediaStreamTrack track =
        CreateTrackAndStartSource(expected_width, expected_height, 30.0);

    // Produce frames at the capture resolution.
    MockMediaStreamVideoSink sink;
    sink.ConnectToTrack(track);
    DeliverVideoFrameAndWaitForRenderer(capture_width, capture_height, &sink);
    EXPECT_EQ(1, sink.number_of_frames());

    // Expect the delivered frame to be cropped.
    EXPECT_EQ(expected_height, sink.frame_size().height());
    EXPECT_EQ(expected_width, sink.frame_size().width());
    sink.DisconnectFromTrack();
  }

  void DeliverVideoFrame(int width, int height, base::TimeDelta timestamp) {
    scoped_refptr<media::VideoFrame> frame =
        media::VideoFrame::CreateBlackFrame(gfx::Size(width, height));
    frame->set_timestamp(timestamp);
    mock_source()->DeliverVideoFrame(frame);
  }

  void DeliverVideoFrameAndWaitForRenderer(int width,
                                           int height,
                                           MockMediaStreamVideoSink* sink) {
    base::RunLoop run_loop;
    base::OnceClosure quit_closure = run_loop.QuitClosure();
    EXPECT_CALL(*sink, OnVideoFrame).WillOnce([&](base::TimeTicks) {
      std::move(quit_closure).Run();
    });
    scoped_refptr<media::VideoFrame> frame =
        media::VideoFrame::CreateBlackFrame(gfx::Size(width, height));
    mock_source()->DeliverVideoFrame(frame);
    run_loop.Run();
  }

  void DeliverVideoFrameAndWaitForRenderer(int width,
                                           int height,
                                           base::TimeDelta timestamp,
                                           MockMediaStreamVideoSink* sink) {
    base::RunLoop run_loop;
    base::OnceClosure quit_closure = run_loop.QuitClosure();
    EXPECT_CALL(*sink, OnVideoFrame).WillOnce([&](base::TimeTicks) {
      std::move(quit_closure).Run();
    });
    scoped_refptr<media::VideoFrame> frame =
        media::VideoFrame::CreateBlackFrame(gfx::Size(width, height));
    frame->set_timestamp(timestamp);
    mock_source()->DeliverVideoFrame(frame);
    run_loop.Run();
  }

  void DeliverRotatedVideoFrameAndWaitForRenderer(
      int width,
      int height,
      MockMediaStreamVideoSink* sink) {
    DeliverVideoFrameAndWaitForRenderer(height, width, sink);
  }

  void DeliverVideoFrameAndWaitForTwoRenderers(
      int width,
      int height,
      MockMediaStreamVideoSink* sink1,
      MockMediaStreamVideoSink* sink2) {
    base::RunLoop run_loop;
    base::OnceClosure quit_closure = run_loop.QuitClosure();
    EXPECT_CALL(*sink1, OnVideoFrame);
    EXPECT_CALL(*sink2, OnVideoFrame).WillOnce([&](base::TimeTicks) {
      std::move(quit_closure).Run();
    });
    scoped_refptr<media::VideoFrame> frame =
        media::VideoFrame::CreateBlackFrame(gfx::Size(width, height));
    mock_source()->DeliverVideoFrame(frame);
    run_loop.Run();
  }

  void TestTwoTracksWithDifferentSettings(int capture_width,
                                          int capture_height,
                                          int expected_width1,
                                          int expected_height1,
                                          int expected_width2,
                                          int expected_height2) {
    WebMediaStreamTrack track1 =
        CreateTrackAndStartSource(expected_width1, expected_height1,
                                  MediaStreamVideoSource::kDefaultFrameRate);

    WebMediaStreamTrack track2 = CreateTrack(
        "dummy",
        VideoTrackAdapterSettings(gfx::Size(expected_width2, expected_height2),
                                  MediaStreamVideoSource::kDefaultFrameRate),
        std::optional<bool>(), false, 0.0);

    MockMediaStreamVideoSink sink1;
    sink1.ConnectToTrack(track1);
    EXPECT_EQ(0, sink1.number_of_frames());

    MockMediaStreamVideoSink sink2;
    sink2.ConnectToTrack(track2);
    EXPECT_EQ(0, sink2.number_of_frames());

    DeliverVideoFrameAndWaitForTwoRenderers(capture_width, capture_height,
                                            &sink1, &sink2);

    EXPECT_EQ(1, sink1.number_of_frames());
    EXPECT_EQ(expected_width1, sink1.frame_size().width());
    EXPECT_EQ(expected_height1, sink1.frame_size().height());

    EXPECT_EQ(1, sink2.number_of_frames());
    EXPECT_EQ(expected_width2, sink2.frame_size().width());
    EXPECT_EQ(expected_height2, sink2.frame_size().height());

    sink1.DisconnectFromTrack();
    sink2.DisconnectFromTrack();
  }

  void ReleaseTrackAndSourceOnAddTrackCallback(
      const WebMediaStreamTrack& track_to_release) {
    track_to_release_ = track_to_release;
  }

 private:
  void OnConstraintsApplied(WebPlatformMediaStreamSource* source,
                            mojom::MediaStreamRequestResult result,
                            const WebString& result_name) {
    ASSERT_EQ(source, stream_source()->GetPlatformSource());

    if (result == mojom::MediaStreamRequestResult::OK) {
      ++number_of_successful_constraints_applied_;
    } else {
      result_ = result;
      result_name_ = result_name;
      ++number_of_failed_constraints_applied_;
    }

    if (!track_to_release_.IsNull()) {
      mock_stream_video_source_ = nullptr;
      stream_source_ = nullptr;
      track_to_release_.Reset();
    }
  }
  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;
  WebMediaStreamTrack track_to_release_;
  int number_of_successful_constraints_applied_;
  int number_of_failed_constraints_applied_;
  mojom::MediaStreamRequestResult result_;
  WebString result_name_;
  Persistent<MediaStreamSource> stream_source_;
  // |mock_stream_video_source_| is owned by |stream_source_|.
  raw_ptr<MockMediaStreamVideoSource, DanglingUntriaged>
      mock_stream_video_source_;
};

TEST_F(MediaStreamVideoSourceTest, AddTrackAndStartSource) {
  WebMediaStreamTrack track = CreateTrack("123");
  mock_source()->StartMockedSource();
  EXPECT_EQ(1, NumberOfSuccessConstraintsCallbacks());
}

TEST_F(MediaStreamVideoSourceTest, AddTwoTracksBeforeSourceStarts) {
  WebMediaStreamTrack track1 = CreateTrack("123");
  WebMediaStreamTrack track2 = CreateTrack("123");
  EXPECT_EQ(0, NumberOfSuccessConstraintsCallbacks());
  mock_source()->StartMockedSource();
  EXPECT_EQ(2, NumberOfSuccessConstraintsCallbacks());
}

TEST_F(MediaStreamVideoSourceTest, AddTrackAfterSourceStarts) {
  WebMediaStreamTrack track1 = CreateTrack("123");
  mock_source()->StartMockedSource();
  EXPECT_EQ(1, NumberOfSuccessConstraintsCallbacks());
  WebMediaStreamTrack track2 = CreateTrack("123");
  EXPECT_EQ(2, NumberOfSuccessConstraintsCallbacks());
}

TEST_F(MediaStreamVideoSourceTest, AddTrackAndFailToStartSource) {
  WebMediaStreamTrack track = CreateTrack("123");
  mock_source()->FailToStartMockedSource();
  EXPECT_EQ(1, NumberOfFailedConstraintsCallbacks());
}

TEST_F(MediaStreamVideoSourceTest, MandatoryAspectRatio4To3) {
  TestSourceCropFrame(1280, 720, 960, 720);
}

TEST_F(MediaStreamVideoSourceTest, ReleaseTrackAndSourceOnSuccessCallBack) {
  WebMediaStreamTrack track = CreateTrack("123");
  ReleaseTrackAndSourceOnAddTrackCallback(track);
  mock_source()->StartMockedSource();
  EXPECT_EQ(1, NumberOfSuccessConstraintsCallbacks());
}

TEST_F(MediaStreamVideoSourceTest, TwoTracksWithVGAAndWVGA) {
  TestTwoTracksWithDifferentSettings(640, 480, 640, 480, 640, 360);
}

TEST_F(MediaStreamVideoSourceTest, TwoTracksWith720AndWVGA) {
  TestTwoTracksWithDifferentSettings(1280, 720, 1280, 720, 640, 360);
}

TEST_F(MediaStreamVideoSourceTest, SourceChangeFrameSize) {
  // Expect the source to start capture with the supported resolution.
  // Disable frame-rate adjustment in spec-compliant mode to ensure no frames
  // are dropped.
  WebMediaStreamTrack track = CreateTrackAndStartSource(800, 700, std::nullopt);

  MockMediaStreamVideoSink sink;
  sink.ConnectToTrack(track);
  EXPECT_EQ(0, sink.number_of_frames());
  DeliverVideoFrameAndWaitForRenderer(320, 240, &sink);
  EXPECT_EQ(1, sink.number_of_frames());
  // Expect the delivered frame to be passed unchanged since its smaller than
  // max requested.
  EXPECT_EQ(320, sink.frame_size().width());
  EXPECT_EQ(240, sink.frame_size().height());

  DeliverVideoFrameAndWaitForRenderer(640, 480, &sink);
  EXPECT_EQ(2, sink.number_of_frames());
  // Expect the delivered frame to be passed unchanged since its smaller than
  // max requested.
  EXPECT_EQ(640, sink.frame_size().width());
  EXPECT_EQ(480, sink.frame_size().height());

  DeliverVideoFrameAndWaitForRenderer(1280, 720, &sink);
  EXPECT_EQ(3, sink.number_of_frames());
  // Expect a frame to be cropped since its larger than max requested.
  EXPECT_EQ(800, sink.frame_size().width());
  EXPECT_EQ(700, sink.frame_size().height());

  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoSourceTest, RotatedSourceDetectionDisabled) {
  source()->SetDeviceRotationDetection(false /* enabled */);

  // Expect the source to start capture with the supported resolution.
  // Disable frame-rate adjustment in spec-compliant mode to ensure no frames
  // are dropped.
  WebMediaStreamTrack track =
      CreateTrackAndStartSource(1280, 720, std::nullopt, true);

  MockMediaStreamVideoSink sink;
  sink.ConnectToTrack(track);
  EXPECT_EQ(0, sink.number_of_frames());
  DeliverVideoFrameAndWaitForRenderer(1280, 720, &sink);
  EXPECT_EQ(1, sink.number_of_frames());
  // Expect the delivered frame to be passed unchanged since it is the same size
  // as the source native format.
  EXPECT_EQ(1280, sink.frame_size().width());
  EXPECT_EQ(720, sink.frame_size().height());

  DeliverRotatedVideoFrameAndWaitForRenderer(1280, 720, &sink);
  EXPECT_EQ(2, sink.number_of_frames());
  // Expect the delivered frame to be cropped because the rotation is not
  // detected.
  EXPECT_EQ(720, sink.frame_size().width());
  EXPECT_EQ(720, sink.frame_size().height());

  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoSourceTest, RotatedSourceDetectionEnabled) {
  source()->SetDeviceRotationDetection(true /* enabled */);

  // Expect the source to start capture with the supported resolution.
  // Disable frame-rate adjustment in spec-compliant mode to ensure no frames
  // are dropped.
  WebMediaStreamTrack track =
      CreateTrackAndStartSource(1280, 720, std::nullopt, true);

  MockMediaStreamVideoSink sink;
  sink.ConnectToTrack(track);
  EXPECT_EQ(0, sink.number_of_frames());
  DeliverVideoFrameAndWaitForRenderer(1280, 720, &sink);
  EXPECT_EQ(1, sink.number_of_frames());
  // Expect the delivered frame to be passed unchanged since it is the same size
  // as the source native format.
  EXPECT_EQ(1280, sink.frame_size().width());
  EXPECT_EQ(720, sink.frame_size().height());

  DeliverRotatedVideoFrameAndWaitForRenderer(1280, 720, &sink);
  EXPECT_EQ(2, sink.number_of_frames());
  // Expect the delivered frame to be passed unchanged since it is detected as
  // a valid frame on a rotated device.
  EXPECT_EQ(720, sink.frame_size().width());
  EXPECT_EQ(1280, sink.frame_size().height());

  sink.DisconnectFromTrack();
}

// Test that a source producing no frames change the source ReadyState to muted.
// that in a reasonable time frame the muted state turns to false.
TEST_F(MediaStreamVideoSourceTest, MutedSource) {
  // Setup the source for support a frame rate of 999 fps in order to test
  // the muted event faster. This is since the frame monitoring uses
  // PostDelayedTask that is dependent on the source frame rate.
  // Note that media::limits::kMaxFramesPerSecond is 1000.
  WebMediaStreamTrack track = CreateTrackAndStartSource(
      640, 480, media::limits::kMaxFramesPerSecond - 2);
  MockMediaStreamVideoSink sink;
  sink.ConnectToTrack(track);
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  base::RunLoop run_loop;
  base::OnceClosure quit_closure = run_loop.QuitClosure();
  bool muted_state = false;
  EXPECT_CALL(*mock_source(), DoSetMutedState(_))
      .WillOnce(DoAll(SaveArg<0>(&muted_state),
                      [&](auto) { std::move(quit_closure).Run(); }));
  run_loop.Run();
  EXPECT_EQ(muted_state, true);

  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateMuted);

  base::RunLoop run_loop2;
  base::OnceClosure quit_closure2 = run_loop2.QuitClosure();
  EXPECT_CALL(*mock_source(), DoSetMutedState(_))
      .WillOnce(DoAll(SaveArg<0>(&muted_state),
                      [&](auto) { std::move(quit_closure2).Run(); }));
  DeliverVideoFrameAndWaitForRenderer(640, 480, &sink);
  run_loop2.Run();

  EXPECT_EQ(muted_state, false);
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  sink.DisconnectFromTrack();
}

// This test ensures that the filter used by the VideoTrackAdapter to estimate
// the frame rate is initialized correctly and does not drop any frames from
// start but forwards all as intended.
TEST_F(MediaStreamVideoSourceTest,
       SendAtMaxRateAndExpectAllFramesToBeDelivered) {
  constexpr int kMaxFps = 10;
  WebMediaStreamTrack track = CreateTrackAndStartSource(640, 480, kMaxFps);
  MockMediaStreamVideoSink sink;
  sink.ConnectToTrack(track);

  // Drive five frames through at approximately the specified max frame rate
  // and expect all frames to be delivered.
  DeliverVideoFrameAndWaitForRenderer(100, 100, base::Milliseconds(100 + 10),
                                      &sink);
  DeliverVideoFrameAndWaitForRenderer(100, 100, base::Milliseconds(200 - 10),
                                      &sink);
  DeliverVideoFrameAndWaitForRenderer(100, 100, base::Milliseconds(300 + 5),
                                      &sink);
  DeliverVideoFrameAndWaitForRenderer(100, 100, base::Milliseconds(400 - 5),
                                      &sink);
  DeliverVideoFrameAndWaitForRenderer(100, 100, base::Milliseconds(500 + 20),
                                      &sink);
  EXPECT_EQ(5, sink.number_of_frames());

  sink.DisconnectFromTrack();
}

// This test verifies that a too high input frame rate triggers an
// OnNotifyFrameDropped() notification on the sink.
TEST_F(MediaStreamVideoSourceTest, NotifyFrameDroppedWhenStartAtTooHighRate) {
  constexpr int kMaxFps = 10;
  WebMediaStreamTrack track = CreateTrackAndStartSource(640, 480, kMaxFps);
  MockMediaStreamVideoSink sink;
  sink.ConnectToTrack(track);
  MediaStreamVideoTrack* native_track = MediaStreamVideoTrack::From(track);
  native_track->SetSinkNotifyFrameDroppedCallback(
      &sink, sink.GetNotifyFrameDroppedCB());

  // Drive two frames through whose timestamps are spaced way too close for
  // the max frame rate. The EMA filter inside the VideoTrackAdapter starts at
  // `kMaxFps` and will quickly measure a too high frame rate since the input
  // rate is ten times the max rate. The second frame should be dropped and
  // cause a notification.
  base::RunLoop run_loop;
  base::OnceClosure quit_closure = run_loop.QuitClosure();
  EXPECT_CALL(sink, OnNotifyFrameDropped).WillOnce([&] {
    std::move(quit_closure).Run();
  });

  DeliverVideoFrame(100, 100, base::Milliseconds(10));
  DeliverVideoFrame(100, 100, base::Milliseconds(20));
  run_loop.Run();
  sink.DisconnectFromTrack();
}

// This test verifies that all frames are forwarded when sending starts at the
// specified max rate and that a frame sent too close in time related to the
// previous frame is dropped but that forwarding is then restored as soon as the
// spacing is normal again.
TEST_F(MediaStreamVideoSourceTest, ForwardsAtMaxFrameRateAndDropsWhenTooClose) {
  constexpr int kMaxFps = 10;
  WebMediaStreamTrack track = CreateTrackAndStartSource(640, 480, kMaxFps);
  MockMediaStreamVideoSink sink;
  sink.ConnectToTrack(track);
  MediaStreamVideoTrack* native_track = MediaStreamVideoTrack::From(track);
  native_track->SetSinkNotifyFrameDroppedCallback(
      &sink, sink.GetNotifyFrameDroppedCB());

  // Drive three frames through at the specified max frame rate and expect all
  // three to be delivered since the EMA filter inside the VideoTrackAdapter
  // (VTA) should be initialized to `kMaxFps` and therefore forward these frames
  // from the start. The fourth frame is sent too close to the third and should
  // be dropped with `TimestampTooCloseToPrevious`.
  base::RunLoop run_loop;
  base::OnceClosure quit_closure = run_loop.QuitClosure();

  EXPECT_CALL(sink, OnVideoFrame).Times(3).WillRepeatedly(Return());
  EXPECT_CALL(sink, OnNotifyFrameDropped(
                        media::VideoCaptureFrameDropReason::
                            kResolutionAdapterFrameRateIsHigherThanRequested))
      .Times(1)
      .WillOnce([&] { std::move(quit_closure).Run(); });

  DeliverVideoFrame(100, 100, base::Milliseconds(100));
  DeliverVideoFrame(100, 100, base::Milliseconds(200));
  DeliverVideoFrame(100, 100, base::Milliseconds(300));
  DeliverVideoFrame(100, 100, base::Milliseconds(304));
  run_loop.Run();
  EXPECT_EQ(3, sink.number_of_frames());

  // The dropped frame should not affect any state in the VTA and additional
  // frames sent at max rate should pass as before.
  DeliverVideoFrameAndWaitForRenderer(100, 100, base::Milliseconds(400), &sink);
  DeliverVideoFrameAndWaitForRenderer(100, 100, base::Milliseconds(500), &sink);
  EXPECT_EQ(5, sink.number_of_frames());

  sink.DisconnectFromTrack();
}

// This test verifies that a frame sent directly after a dropped frame will
// pass even if it is sent with a slightly too high rate related to the frame
// that was dropped. The frame should pass since the frame-rate calculation
// is be based on the last forwarded frame and not the dropped frame.
TEST_F(MediaStreamVideoSourceTest, DropFrameAtTooHighRateAndThenStopDropping) {
  constexpr int kMaxFps = 10;
  WebMediaStreamTrack track = CreateTrackAndStartSource(640, 480, kMaxFps);
  MockMediaStreamVideoSink sink;
  sink.ConnectToTrack(track);
  MediaStreamVideoTrack* native_track = MediaStreamVideoTrack::From(track);
  native_track->SetSinkNotifyFrameDroppedCallback(
      &sink, sink.GetNotifyFrameDroppedCB());

  base::RunLoop run_loop;
  base::OnceClosure quit_closure = run_loop.QuitClosure();
  EXPECT_CALL(sink, OnNotifyFrameDropped).WillOnce([&] {
    std::move(quit_closure).Run();
  });

  // Start by sending frames at a slightly too high rate (12.5 fps). Given the
  // current EMA filter in the VideoFrameAdapter, it takes four frames until the
  // frame rate is detected as too high and the first frame is dropped.
  constexpr base::TimeDelta kDeltaTimestampSlightlyTooHighRateDuration =
      base::Milliseconds(80);
  base::TimeDelta timestamp =
      base::TimeDelta() + kDeltaTimestampSlightlyTooHighRateDuration;
  for (int i = 0; i < 4; ++i) {
    DeliverVideoFrame(100, 100, timestamp);
    timestamp += kDeltaTimestampSlightlyTooHighRateDuration;
  }
  run_loop.Run();

  // Given that a frame was just dropped, send yet another at the same rate.
  // This time it should pass since the rate should be derived based on frames
  // that are actually delivered. In this case, the last forwarded packet had
  // a timestamp which is 160 ms less than `timestamp`; hence the sending rate
  // should be seen as ~6.2 fps which is lower than max fps (10). The last
  // frame will cause the filtered frame rate estimate to go from ~10.7 fps
  // (=> dropped) to ~10.2 fps (=> forwarded).
  DeliverVideoFrameAndWaitForRenderer(100, 100, timestamp, &sink);

  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoSourceTest, ReconfigureTrack) {
  WebMediaStreamTrack track =
      CreateTrackAndStartSource(640, 480, kSourceFrameRate - 2);
  MockMediaStreamVideoSink sink;
  sink.ConnectToTrack(track);
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  MediaStreamVideoTrack* native_track = MediaStreamVideoTrack::From(track);
  MediaStreamTrackPlatform::Settings settings;
  native_track->GetSettings(settings);
  EXPECT_EQ(settings.width, 640);
  EXPECT_EQ(settings.height, 480);
  EXPECT_EQ(settings.frame_rate, kSourceFrameRate - 2);
  EXPECT_EQ(settings.aspect_ratio, 640.0 / 4
### 提示词
```
这是目录为blink/renderer/modules/mediastream/media_stream_video_source_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "media/base/limits.h"
#include "media/base/video_frame.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom-blink.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/mock_constraint_factory.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_sink.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_source.h"
#include "third_party/blink/renderer/modules/mediastream/video_track_adapter.h"
#include "third_party/blink/renderer/modules/mediastream/video_track_adapter_settings.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::InSequence;
using ::testing::Mock;
using ::testing::Return;
using ::testing::SaveArg;

namespace blink {

const double kSourceFrameRate = 500.0;

class MediaStreamVideoSourceTest : public testing::Test {
 public:
  MediaStreamVideoSourceTest()
      : number_of_successful_constraints_applied_(0),
        number_of_failed_constraints_applied_(0),
        result_(mojom::MediaStreamRequestResult::OK),
        result_name_(""),
        mock_stream_video_source_(new MockMediaStreamVideoSource(
            media::VideoCaptureFormat(gfx::Size(1280, 720),
                                      kSourceFrameRate,
                                      media::PIXEL_FORMAT_I420),
            false)) {
    mock_stream_video_source_->DisableStopForRestart();
    stream_source_ = MakeGarbageCollected<MediaStreamSource>(
        String::FromUTF8("dummy_source_id"), MediaStreamSource::kTypeVideo,
        String::FromUTF8("dummy_source_name"), false /* remote */,
        base::WrapUnique(mock_stream_video_source_.get()));
    ON_CALL(*mock_stream_video_source_, OnSourceCanDiscardAlpha)
        .WillByDefault(Return());
    ON_CALL(*mock_stream_video_source_, SupportsEncodedOutput)
        .WillByDefault(Return(true));
  }

  void TearDown() override {
    stream_source_ = nullptr;
    WebHeap::CollectAllGarbageForTesting();
  }

  MOCK_METHOD0(MockNotification, void());

 protected:
  MediaStreamVideoSource* source() { return mock_stream_video_source_; }

  // Create a track that's associated with |stream_source_|.
  WebMediaStreamTrack CreateTrack(const String& id) {
    bool enabled = true;
    return MediaStreamVideoTrack::CreateVideoTrack(
        mock_stream_video_source_,
        WTF::BindOnce(&MediaStreamVideoSourceTest::OnConstraintsApplied,
                      base::Unretained(this)),
        enabled);
  }

  WebMediaStreamTrack CreateTrack(
      const String& id,
      const VideoTrackAdapterSettings& adapter_settings,
      const std::optional<bool>& noise_reduction,
      bool is_screencast,
      double min_frame_rate) {
    bool enabled = true;
    return MediaStreamVideoTrack::CreateVideoTrack(
        mock_stream_video_source_, adapter_settings, noise_reduction,
        is_screencast, min_frame_rate, nullptr, false,
        WTF::BindOnce(&MediaStreamVideoSourceTest::OnConstraintsApplied,
                      base::Unretained(this)),
        enabled);
  }

  WebMediaStreamTrack CreateTrack() {
    return CreateTrack("123",
                       VideoTrackAdapterSettings(gfx::Size(100, 100), 30.0),
                       std::optional<bool>(), false, 0.0);
  }

  WebMediaStreamTrack CreateTrackAndStartSource(
      int width,
      int height,
      std::optional<double> frame_rate,
      bool detect_rotation = false) {
    WebMediaStreamTrack track = CreateTrack(
        "123", VideoTrackAdapterSettings(gfx::Size(width, height), frame_rate),
        std::optional<bool>(), false, 0.0);

    EXPECT_EQ(0, NumberOfSuccessConstraintsCallbacks());
    mock_stream_video_source_->StartMockedSource();
    // Once the source has started successfully we expect that the
    // ConstraintsOnceCallback in WebPlatformMediaStreamSource::AddTrack
    // completes.
    EXPECT_EQ(1, NumberOfSuccessConstraintsCallbacks());
    return track;
  }

  int NumberOfSuccessConstraintsCallbacks() const {
    return number_of_successful_constraints_applied_;
  }

  int NumberOfFailedConstraintsCallbacks() const {
    return number_of_failed_constraints_applied_;
  }

  mojom::MediaStreamRequestResult error_type() const { return result_; }
  WebString error_name() const { return result_name_; }

  MockMediaStreamVideoSource* mock_source() {
    return mock_stream_video_source_;
  }

  MediaStreamSource* stream_source() { return stream_source_.Get(); }

  void TestSourceCropFrame(int capture_width,
                           int capture_height,
                           int expected_width,
                           int expected_height) {
    // Configure the track to crop to the expected resolution.
    WebMediaStreamTrack track =
        CreateTrackAndStartSource(expected_width, expected_height, 30.0);

    // Produce frames at the capture resolution.
    MockMediaStreamVideoSink sink;
    sink.ConnectToTrack(track);
    DeliverVideoFrameAndWaitForRenderer(capture_width, capture_height, &sink);
    EXPECT_EQ(1, sink.number_of_frames());

    // Expect the delivered frame to be cropped.
    EXPECT_EQ(expected_height, sink.frame_size().height());
    EXPECT_EQ(expected_width, sink.frame_size().width());
    sink.DisconnectFromTrack();
  }

  void DeliverVideoFrame(int width, int height, base::TimeDelta timestamp) {
    scoped_refptr<media::VideoFrame> frame =
        media::VideoFrame::CreateBlackFrame(gfx::Size(width, height));
    frame->set_timestamp(timestamp);
    mock_source()->DeliverVideoFrame(frame);
  }

  void DeliverVideoFrameAndWaitForRenderer(int width,
                                           int height,
                                           MockMediaStreamVideoSink* sink) {
    base::RunLoop run_loop;
    base::OnceClosure quit_closure = run_loop.QuitClosure();
    EXPECT_CALL(*sink, OnVideoFrame).WillOnce([&](base::TimeTicks) {
      std::move(quit_closure).Run();
    });
    scoped_refptr<media::VideoFrame> frame =
        media::VideoFrame::CreateBlackFrame(gfx::Size(width, height));
    mock_source()->DeliverVideoFrame(frame);
    run_loop.Run();
  }

  void DeliverVideoFrameAndWaitForRenderer(int width,
                                           int height,
                                           base::TimeDelta timestamp,
                                           MockMediaStreamVideoSink* sink) {
    base::RunLoop run_loop;
    base::OnceClosure quit_closure = run_loop.QuitClosure();
    EXPECT_CALL(*sink, OnVideoFrame).WillOnce([&](base::TimeTicks) {
      std::move(quit_closure).Run();
    });
    scoped_refptr<media::VideoFrame> frame =
        media::VideoFrame::CreateBlackFrame(gfx::Size(width, height));
    frame->set_timestamp(timestamp);
    mock_source()->DeliverVideoFrame(frame);
    run_loop.Run();
  }

  void DeliverRotatedVideoFrameAndWaitForRenderer(
      int width,
      int height,
      MockMediaStreamVideoSink* sink) {
    DeliverVideoFrameAndWaitForRenderer(height, width, sink);
  }

  void DeliverVideoFrameAndWaitForTwoRenderers(
      int width,
      int height,
      MockMediaStreamVideoSink* sink1,
      MockMediaStreamVideoSink* sink2) {
    base::RunLoop run_loop;
    base::OnceClosure quit_closure = run_loop.QuitClosure();
    EXPECT_CALL(*sink1, OnVideoFrame);
    EXPECT_CALL(*sink2, OnVideoFrame).WillOnce([&](base::TimeTicks) {
      std::move(quit_closure).Run();
    });
    scoped_refptr<media::VideoFrame> frame =
        media::VideoFrame::CreateBlackFrame(gfx::Size(width, height));
    mock_source()->DeliverVideoFrame(frame);
    run_loop.Run();
  }

  void TestTwoTracksWithDifferentSettings(int capture_width,
                                          int capture_height,
                                          int expected_width1,
                                          int expected_height1,
                                          int expected_width2,
                                          int expected_height2) {
    WebMediaStreamTrack track1 =
        CreateTrackAndStartSource(expected_width1, expected_height1,
                                  MediaStreamVideoSource::kDefaultFrameRate);

    WebMediaStreamTrack track2 = CreateTrack(
        "dummy",
        VideoTrackAdapterSettings(gfx::Size(expected_width2, expected_height2),
                                  MediaStreamVideoSource::kDefaultFrameRate),
        std::optional<bool>(), false, 0.0);

    MockMediaStreamVideoSink sink1;
    sink1.ConnectToTrack(track1);
    EXPECT_EQ(0, sink1.number_of_frames());

    MockMediaStreamVideoSink sink2;
    sink2.ConnectToTrack(track2);
    EXPECT_EQ(0, sink2.number_of_frames());

    DeliverVideoFrameAndWaitForTwoRenderers(capture_width, capture_height,
                                            &sink1, &sink2);

    EXPECT_EQ(1, sink1.number_of_frames());
    EXPECT_EQ(expected_width1, sink1.frame_size().width());
    EXPECT_EQ(expected_height1, sink1.frame_size().height());

    EXPECT_EQ(1, sink2.number_of_frames());
    EXPECT_EQ(expected_width2, sink2.frame_size().width());
    EXPECT_EQ(expected_height2, sink2.frame_size().height());

    sink1.DisconnectFromTrack();
    sink2.DisconnectFromTrack();
  }

  void ReleaseTrackAndSourceOnAddTrackCallback(
      const WebMediaStreamTrack& track_to_release) {
    track_to_release_ = track_to_release;
  }

 private:
  void OnConstraintsApplied(WebPlatformMediaStreamSource* source,
                            mojom::MediaStreamRequestResult result,
                            const WebString& result_name) {
    ASSERT_EQ(source, stream_source()->GetPlatformSource());

    if (result == mojom::MediaStreamRequestResult::OK) {
      ++number_of_successful_constraints_applied_;
    } else {
      result_ = result;
      result_name_ = result_name;
      ++number_of_failed_constraints_applied_;
    }

    if (!track_to_release_.IsNull()) {
      mock_stream_video_source_ = nullptr;
      stream_source_ = nullptr;
      track_to_release_.Reset();
    }
  }
  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;
  WebMediaStreamTrack track_to_release_;
  int number_of_successful_constraints_applied_;
  int number_of_failed_constraints_applied_;
  mojom::MediaStreamRequestResult result_;
  WebString result_name_;
  Persistent<MediaStreamSource> stream_source_;
  // |mock_stream_video_source_| is owned by |stream_source_|.
  raw_ptr<MockMediaStreamVideoSource, DanglingUntriaged>
      mock_stream_video_source_;
};

TEST_F(MediaStreamVideoSourceTest, AddTrackAndStartSource) {
  WebMediaStreamTrack track = CreateTrack("123");
  mock_source()->StartMockedSource();
  EXPECT_EQ(1, NumberOfSuccessConstraintsCallbacks());
}

TEST_F(MediaStreamVideoSourceTest, AddTwoTracksBeforeSourceStarts) {
  WebMediaStreamTrack track1 = CreateTrack("123");
  WebMediaStreamTrack track2 = CreateTrack("123");
  EXPECT_EQ(0, NumberOfSuccessConstraintsCallbacks());
  mock_source()->StartMockedSource();
  EXPECT_EQ(2, NumberOfSuccessConstraintsCallbacks());
}

TEST_F(MediaStreamVideoSourceTest, AddTrackAfterSourceStarts) {
  WebMediaStreamTrack track1 = CreateTrack("123");
  mock_source()->StartMockedSource();
  EXPECT_EQ(1, NumberOfSuccessConstraintsCallbacks());
  WebMediaStreamTrack track2 = CreateTrack("123");
  EXPECT_EQ(2, NumberOfSuccessConstraintsCallbacks());
}

TEST_F(MediaStreamVideoSourceTest, AddTrackAndFailToStartSource) {
  WebMediaStreamTrack track = CreateTrack("123");
  mock_source()->FailToStartMockedSource();
  EXPECT_EQ(1, NumberOfFailedConstraintsCallbacks());
}

TEST_F(MediaStreamVideoSourceTest, MandatoryAspectRatio4To3) {
  TestSourceCropFrame(1280, 720, 960, 720);
}

TEST_F(MediaStreamVideoSourceTest, ReleaseTrackAndSourceOnSuccessCallBack) {
  WebMediaStreamTrack track = CreateTrack("123");
  ReleaseTrackAndSourceOnAddTrackCallback(track);
  mock_source()->StartMockedSource();
  EXPECT_EQ(1, NumberOfSuccessConstraintsCallbacks());
}

TEST_F(MediaStreamVideoSourceTest, TwoTracksWithVGAAndWVGA) {
  TestTwoTracksWithDifferentSettings(640, 480, 640, 480, 640, 360);
}

TEST_F(MediaStreamVideoSourceTest, TwoTracksWith720AndWVGA) {
  TestTwoTracksWithDifferentSettings(1280, 720, 1280, 720, 640, 360);
}

TEST_F(MediaStreamVideoSourceTest, SourceChangeFrameSize) {
  // Expect the source to start capture with the supported resolution.
  // Disable frame-rate adjustment in spec-compliant mode to ensure no frames
  // are dropped.
  WebMediaStreamTrack track = CreateTrackAndStartSource(800, 700, std::nullopt);

  MockMediaStreamVideoSink sink;
  sink.ConnectToTrack(track);
  EXPECT_EQ(0, sink.number_of_frames());
  DeliverVideoFrameAndWaitForRenderer(320, 240, &sink);
  EXPECT_EQ(1, sink.number_of_frames());
  // Expect the delivered frame to be passed unchanged since its smaller than
  // max requested.
  EXPECT_EQ(320, sink.frame_size().width());
  EXPECT_EQ(240, sink.frame_size().height());

  DeliverVideoFrameAndWaitForRenderer(640, 480, &sink);
  EXPECT_EQ(2, sink.number_of_frames());
  // Expect the delivered frame to be passed unchanged since its smaller than
  // max requested.
  EXPECT_EQ(640, sink.frame_size().width());
  EXPECT_EQ(480, sink.frame_size().height());

  DeliverVideoFrameAndWaitForRenderer(1280, 720, &sink);
  EXPECT_EQ(3, sink.number_of_frames());
  // Expect a frame to be cropped since its larger than max requested.
  EXPECT_EQ(800, sink.frame_size().width());
  EXPECT_EQ(700, sink.frame_size().height());

  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoSourceTest, RotatedSourceDetectionDisabled) {
  source()->SetDeviceRotationDetection(false /* enabled */);

  // Expect the source to start capture with the supported resolution.
  // Disable frame-rate adjustment in spec-compliant mode to ensure no frames
  // are dropped.
  WebMediaStreamTrack track =
      CreateTrackAndStartSource(1280, 720, std::nullopt, true);

  MockMediaStreamVideoSink sink;
  sink.ConnectToTrack(track);
  EXPECT_EQ(0, sink.number_of_frames());
  DeliverVideoFrameAndWaitForRenderer(1280, 720, &sink);
  EXPECT_EQ(1, sink.number_of_frames());
  // Expect the delivered frame to be passed unchanged since it is the same size
  // as the source native format.
  EXPECT_EQ(1280, sink.frame_size().width());
  EXPECT_EQ(720, sink.frame_size().height());

  DeliverRotatedVideoFrameAndWaitForRenderer(1280, 720, &sink);
  EXPECT_EQ(2, sink.number_of_frames());
  // Expect the delivered frame to be cropped because the rotation is not
  // detected.
  EXPECT_EQ(720, sink.frame_size().width());
  EXPECT_EQ(720, sink.frame_size().height());

  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoSourceTest, RotatedSourceDetectionEnabled) {
  source()->SetDeviceRotationDetection(true /* enabled */);

  // Expect the source to start capture with the supported resolution.
  // Disable frame-rate adjustment in spec-compliant mode to ensure no frames
  // are dropped.
  WebMediaStreamTrack track =
      CreateTrackAndStartSource(1280, 720, std::nullopt, true);

  MockMediaStreamVideoSink sink;
  sink.ConnectToTrack(track);
  EXPECT_EQ(0, sink.number_of_frames());
  DeliverVideoFrameAndWaitForRenderer(1280, 720, &sink);
  EXPECT_EQ(1, sink.number_of_frames());
  // Expect the delivered frame to be passed unchanged since it is the same size
  // as the source native format.
  EXPECT_EQ(1280, sink.frame_size().width());
  EXPECT_EQ(720, sink.frame_size().height());

  DeliverRotatedVideoFrameAndWaitForRenderer(1280, 720, &sink);
  EXPECT_EQ(2, sink.number_of_frames());
  // Expect the delivered frame to be passed unchanged since it is detected as
  // a valid frame on a rotated device.
  EXPECT_EQ(720, sink.frame_size().width());
  EXPECT_EQ(1280, sink.frame_size().height());

  sink.DisconnectFromTrack();
}

// Test that a source producing no frames change the source ReadyState to muted.
// that in a reasonable time frame the muted state turns to false.
TEST_F(MediaStreamVideoSourceTest, MutedSource) {
  // Setup the source for support a frame rate of 999 fps in order to test
  // the muted event faster. This is since the frame monitoring uses
  // PostDelayedTask that is dependent on the source frame rate.
  // Note that media::limits::kMaxFramesPerSecond is 1000.
  WebMediaStreamTrack track = CreateTrackAndStartSource(
      640, 480, media::limits::kMaxFramesPerSecond - 2);
  MockMediaStreamVideoSink sink;
  sink.ConnectToTrack(track);
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  base::RunLoop run_loop;
  base::OnceClosure quit_closure = run_loop.QuitClosure();
  bool muted_state = false;
  EXPECT_CALL(*mock_source(), DoSetMutedState(_))
      .WillOnce(DoAll(SaveArg<0>(&muted_state),
                      [&](auto) { std::move(quit_closure).Run(); }));
  run_loop.Run();
  EXPECT_EQ(muted_state, true);

  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateMuted);

  base::RunLoop run_loop2;
  base::OnceClosure quit_closure2 = run_loop2.QuitClosure();
  EXPECT_CALL(*mock_source(), DoSetMutedState(_))
      .WillOnce(DoAll(SaveArg<0>(&muted_state),
                      [&](auto) { std::move(quit_closure2).Run(); }));
  DeliverVideoFrameAndWaitForRenderer(640, 480, &sink);
  run_loop2.Run();

  EXPECT_EQ(muted_state, false);
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  sink.DisconnectFromTrack();
}

// This test ensures that the filter used by the VideoTrackAdapter to estimate
// the frame rate is initialized correctly and does not drop any frames from
// start but forwards all as intended.
TEST_F(MediaStreamVideoSourceTest,
       SendAtMaxRateAndExpectAllFramesToBeDelivered) {
  constexpr int kMaxFps = 10;
  WebMediaStreamTrack track = CreateTrackAndStartSource(640, 480, kMaxFps);
  MockMediaStreamVideoSink sink;
  sink.ConnectToTrack(track);

  // Drive five frames through at approximately the specified max frame rate
  // and expect all frames to be delivered.
  DeliverVideoFrameAndWaitForRenderer(100, 100, base::Milliseconds(100 + 10),
                                      &sink);
  DeliverVideoFrameAndWaitForRenderer(100, 100, base::Milliseconds(200 - 10),
                                      &sink);
  DeliverVideoFrameAndWaitForRenderer(100, 100, base::Milliseconds(300 + 5),
                                      &sink);
  DeliverVideoFrameAndWaitForRenderer(100, 100, base::Milliseconds(400 - 5),
                                      &sink);
  DeliverVideoFrameAndWaitForRenderer(100, 100, base::Milliseconds(500 + 20),
                                      &sink);
  EXPECT_EQ(5, sink.number_of_frames());

  sink.DisconnectFromTrack();
}

// This test verifies that a too high input frame rate triggers an
// OnNotifyFrameDropped() notification on the sink.
TEST_F(MediaStreamVideoSourceTest, NotifyFrameDroppedWhenStartAtTooHighRate) {
  constexpr int kMaxFps = 10;
  WebMediaStreamTrack track = CreateTrackAndStartSource(640, 480, kMaxFps);
  MockMediaStreamVideoSink sink;
  sink.ConnectToTrack(track);
  MediaStreamVideoTrack* native_track = MediaStreamVideoTrack::From(track);
  native_track->SetSinkNotifyFrameDroppedCallback(
      &sink, sink.GetNotifyFrameDroppedCB());

  // Drive two frames through whose timestamps are spaced way too close for
  // the max frame rate. The EMA filter inside the VideoTrackAdapter starts at
  // `kMaxFps` and will quickly measure a too high frame rate since the input
  // rate is ten times the max rate. The second frame should be dropped and
  // cause a notification.
  base::RunLoop run_loop;
  base::OnceClosure quit_closure = run_loop.QuitClosure();
  EXPECT_CALL(sink, OnNotifyFrameDropped).WillOnce([&] {
    std::move(quit_closure).Run();
  });

  DeliverVideoFrame(100, 100, base::Milliseconds(10));
  DeliverVideoFrame(100, 100, base::Milliseconds(20));
  run_loop.Run();
  sink.DisconnectFromTrack();
}

// This test verifies that all frames are forwarded when sending starts at the
// specified max rate and that a frame sent too close in time related to the
// previous frame is dropped but that forwarding is then restored as soon as the
// spacing is normal again.
TEST_F(MediaStreamVideoSourceTest, ForwardsAtMaxFrameRateAndDropsWhenTooClose) {
  constexpr int kMaxFps = 10;
  WebMediaStreamTrack track = CreateTrackAndStartSource(640, 480, kMaxFps);
  MockMediaStreamVideoSink sink;
  sink.ConnectToTrack(track);
  MediaStreamVideoTrack* native_track = MediaStreamVideoTrack::From(track);
  native_track->SetSinkNotifyFrameDroppedCallback(
      &sink, sink.GetNotifyFrameDroppedCB());

  // Drive three frames through at the specified max frame rate and expect all
  // three to be delivered since the EMA filter inside the VideoTrackAdapter
  // (VTA) should be initialized to `kMaxFps` and therefore forward these frames
  // from the start. The fourth frame is sent too close to the third and should
  // be dropped with `TimestampTooCloseToPrevious`.
  base::RunLoop run_loop;
  base::OnceClosure quit_closure = run_loop.QuitClosure();

  EXPECT_CALL(sink, OnVideoFrame).Times(3).WillRepeatedly(Return());
  EXPECT_CALL(sink, OnNotifyFrameDropped(
                        media::VideoCaptureFrameDropReason::
                            kResolutionAdapterFrameRateIsHigherThanRequested))
      .Times(1)
      .WillOnce([&] { std::move(quit_closure).Run(); });

  DeliverVideoFrame(100, 100, base::Milliseconds(100));
  DeliverVideoFrame(100, 100, base::Milliseconds(200));
  DeliverVideoFrame(100, 100, base::Milliseconds(300));
  DeliverVideoFrame(100, 100, base::Milliseconds(304));
  run_loop.Run();
  EXPECT_EQ(3, sink.number_of_frames());

  // The dropped frame should not affect any state in the VTA and additional
  // frames sent at max rate should pass as before.
  DeliverVideoFrameAndWaitForRenderer(100, 100, base::Milliseconds(400), &sink);
  DeliverVideoFrameAndWaitForRenderer(100, 100, base::Milliseconds(500), &sink);
  EXPECT_EQ(5, sink.number_of_frames());

  sink.DisconnectFromTrack();
}

// This test verifies that a frame sent directly after a dropped frame will
// pass even if it is sent with a slightly too high rate related to the frame
// that was dropped. The frame should pass since the frame-rate calculation
// is be based on the last forwarded frame and not the dropped frame.
TEST_F(MediaStreamVideoSourceTest, DropFrameAtTooHighRateAndThenStopDropping) {
  constexpr int kMaxFps = 10;
  WebMediaStreamTrack track = CreateTrackAndStartSource(640, 480, kMaxFps);
  MockMediaStreamVideoSink sink;
  sink.ConnectToTrack(track);
  MediaStreamVideoTrack* native_track = MediaStreamVideoTrack::From(track);
  native_track->SetSinkNotifyFrameDroppedCallback(
      &sink, sink.GetNotifyFrameDroppedCB());

  base::RunLoop run_loop;
  base::OnceClosure quit_closure = run_loop.QuitClosure();
  EXPECT_CALL(sink, OnNotifyFrameDropped).WillOnce([&] {
    std::move(quit_closure).Run();
  });

  // Start by sending frames at a slightly too high rate (12.5 fps). Given the
  // current EMA filter in the VideoFrameAdapter, it takes four frames until the
  // frame rate is detected as too high and the first frame is dropped.
  constexpr base::TimeDelta kDeltaTimestampSlightlyTooHighRateDuration =
      base::Milliseconds(80);
  base::TimeDelta timestamp =
      base::TimeDelta() + kDeltaTimestampSlightlyTooHighRateDuration;
  for (int i = 0; i < 4; ++i) {
    DeliverVideoFrame(100, 100, timestamp);
    timestamp += kDeltaTimestampSlightlyTooHighRateDuration;
  }
  run_loop.Run();

  // Given that a frame was just dropped, send yet another at the same rate.
  // This time it should pass since the rate should be derived based on frames
  // that are actually delivered. In this case, the last forwarded packet had
  // a timestamp which is 160 ms less than `timestamp`; hence the sending rate
  // should be seen as ~6.2 fps which is lower than max fps (10). The last
  // frame will cause the filtered frame rate estimate to go from ~10.7 fps
  // (=> dropped) to ~10.2 fps (=> forwarded).
  DeliverVideoFrameAndWaitForRenderer(100, 100, timestamp, &sink);

  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoSourceTest, ReconfigureTrack) {
  WebMediaStreamTrack track =
      CreateTrackAndStartSource(640, 480, kSourceFrameRate - 2);
  MockMediaStreamVideoSink sink;
  sink.ConnectToTrack(track);
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  MediaStreamVideoTrack* native_track = MediaStreamVideoTrack::From(track);
  MediaStreamTrackPlatform::Settings settings;
  native_track->GetSettings(settings);
  EXPECT_EQ(settings.width, 640);
  EXPECT_EQ(settings.height, 480);
  EXPECT_EQ(settings.frame_rate, kSourceFrameRate - 2);
  EXPECT_EQ(settings.aspect_ratio, 640.0 / 480.0);

  source()->ReconfigureTrack(
      native_track, VideoTrackAdapterSettings(gfx::Size(630, 470), 30.0));
  native_track->GetSettings(settings);
  EXPECT_EQ(settings.width, 630);
  EXPECT_EQ(settings.height, 470);
  EXPECT_EQ(settings.frame_rate, 30.0);
  EXPECT_EQ(settings.aspect_ratio, 630.0 / 470.0);

  // Produce a frame in the source native format and expect the delivered frame
  // to have the new track format.
  DeliverVideoFrameAndWaitForRenderer(640, 480, &sink);
  EXPECT_EQ(1, sink.number_of_frames());
  EXPECT_EQ(630, sink.frame_size().width());
  EXPECT_EQ(470, sink.frame_size().height());
}

TEST_F(MediaStreamVideoSourceTest, ReconfigureStoppedTrack) {
  WebMediaStreamTrack track =
      CreateTrackAndStartSource(640, 480, kSourceFrameRate - 2);
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  MediaStreamVideoTrack* native_track = MediaStreamVideoTrack::From(track);
  MediaStreamTrackPlatform::Settings settings;
  native_track->GetSettings(settings);
  EXPECT_EQ(settings.width, 640);
  EXPECT_EQ(settings.height, 480);
  EXPECT_EQ(settings.frame_rate, kSourceFrameRate - 2);
  EXPECT_EQ(settings.aspect_ratio, 640.0 / 480.0);

  // Reconfiguring a stopped track should have no effect since it is no longer
  // associated with the source.
  native_track->Stop();
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateEnded);

  source()->ReconfigureTrack(
      native_track, VideoTrackAdapterSettings(gfx::Size(630, 470), 30.0));
  MediaStreamTrackPlatform::Settings stopped_settings;
  native_track->GetSettings(stopped_settings);
  EXPECT_EQ(stopped_settings.width, -1);
  EXPECT_EQ(stopped_settings.height, -1);
  EXPECT_EQ(stopped_settings.frame_rate, -1);
  EXPECT_EQ(stopped_settings.aspect_ratio, -1);
}

// Test that restart fails on a source without restart support.
TEST_F(MediaStreamVideoSourceTest, FailedRestart) {
  WebMediaStreamTrack track = CreateTrack("123");
  mock_source()->StartMockedSource();
  EXPECT_EQ(1, NumberOfSuccessConstraintsCallbacks());
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  // The source does not support Restart/StopForRestart.
  mock_source()->StopForRestart(
      WTF::BindOnce([](MediaStreamVideoSource::RestartResult result) {
        EXPECT_EQ(result, MediaStreamVideoSource::RestartResult::IS_RUNNING);
      }));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  // Verify that Restart() fails with INVALID_STATE when not called after a
  // successful StopForRestart().
  mock_source()->Restart(
      media::VideoCaptureFormat(),
      WTF::BindOnce([](MediaStreamVideoSource::RestartResult result) {
        EXPECT_EQ(result, MediaStreamVideoSource::RestartResult::INVALID_STATE);
      }));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  mock_source()->StopSource();
  // Verify that StopForRestart() fails with INVALID_STATE when called when the
  // source is not running.
  mock_source()->StopForRestart(
      WTF::BindOnce([](MediaStreamVideoSource::RestartResult result) {
        EXPECT_EQ(result, MediaStreamVideoSource::RestartResult::INVALID_STATE);
      }));
}

// Test that restart succeeds on a source with restart support.
TEST_F(MediaStreamVideoSourceTest, SuccessfulRestart) {
  WebMediaStreamTrack track = CreateTrack("123");
  mock_source()->EnableStopForRestart();
  mock_source()->EnableRestart();
  mock_source()->StartMockedSource();
  EXPECT_EQ(NumberOfSuccessConstraintsCallbacks(), 1);
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  mock_source()->StopForRestart(
      WTF::BindOnce([](MediaStreamVideoSource::RestartResult result) {
        EXPECT_EQ(result, MediaStreamVideoSource::RestartResult::IS_STOPPED);
      }));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  // Verify that StopForRestart() fails with INVALID_STATE called after the
  // source is already stopped.
  mock_source()->StopForRestart(
      WTF::BindOnce([](MediaStreamVideoSource::RestartResult result) {
        EXPECT_EQ(result, MediaStreamVideoSource::RestartResult::INVALID_STATE);
      }));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  mock_source()->Restart(
      media::VideoCaptureFormat(),
      WTF::BindOnce([](MediaStreamVideoSource::RestartResult result) {
        EXPECT_EQ(result, MediaStreamVideoSource::RestartResult::IS_RUNNING);
      }));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  // Verify that Restart() fails with INVALID_STATE if the source has already
  // started.
  mock_source()->Restart(
      media::VideoCaptureFormat(),
      WTF::BindOnce([](MediaStreamVideoSource::RestartResult result) {
        EXPECT_EQ(result, MediaStreamVideoSource::RestartResult::INVALID_STATE);
      }));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  mock_source()->StopSource();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateEnded);
}

// Test that restart fails on a source without restart support.
TEST_F(MediaStreamVideoSourceTest, FailedRestartAfterStopForRestart) {
  WebMediaStreamTrack track = CreateTrack("123");
  mock_source()->EnableStopForRestart();
  mock_source()->DisableRestart();
  mock_source()->StartMockedSource();
  EXPECT_EQ(NumberOfSuccessConstraintsCallbacks(), 1);
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  mock_source()->StopForRestart(
      WTF::BindOnce([](MediaStreamVideoSource::RestartResult result) {
        EXPECT_EQ(result, MediaStreamVideoSource::RestartResult::IS_STOPPED);
      }));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  mock_source()->Restart(
      media::VideoCaptureFormat(),
      WTF::BindOnce([](MediaStreamVideoSource::RestartResult result) {
        EXPECT_EQ(result, MediaStreamVideoSource::RestartResult::IS_STOPPED);
      }));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  // Another failed attempt to verify that the source remains in the correct
  // state.
  mock_source()->Restart(
      media::VideoCaptureFormat(),
      WTF::BindOnce([](MediaStreamVideoSource::RestartResult result) {
        EXPECT_EQ(res
```