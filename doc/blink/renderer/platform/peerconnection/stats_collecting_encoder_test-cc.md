Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The file name `stats_collecting_encoder_test.cc` immediately suggests it's testing something related to video encoding and collecting statistics. The `StatsCollectingEncoder` class mentioned in the `#include` confirms this.

2. **Understand the Testing Framework:** The presence of `#include "testing/gmock/include/gmock/gmock.h"` and `#include "testing/gtest/include/gtest/gtest.h"` indicates the use of Google Test and Google Mock frameworks for unit testing. This tells us we'll find `TEST_F` macros defining individual test cases and potentially `EXPECT_...` macros for assertions, and `MOCK_METHOD` for mocking dependencies.

3. **Analyze the Includes:**
    * `third_party/blink/...`: This confirms we're in the Chromium Blink rendering engine codebase, specifically within the peer connection module.
    * `third_party/webrtc/...`:  This is a crucial inclusion. It tells us this code interacts heavily with the WebRTC library, particularly its video encoding components (`webrtc::VideoEncoder`, `webrtc::VideoFrame`, etc.).
    * `base/...`:  Includes related to Chromium's base library, like `base::memory::raw_ptr` for raw pointers, `base::notreached` for unreachable code, and `base::test::task_environment` for controlling the test environment's time.

4. **Examine Helper Classes/Functions:**
    * `FakeVideoFrameBuffer`: This is a mock implementation of a video frame buffer. Its purpose is to provide a basic video frame without needing to create a real one, making tests faster and more isolated. It simply creates a black I420 buffer.
    * `CreateMockFrame`:  A helper function to easily create `webrtc::VideoFrame` objects using the `FakeVideoFrameBuffer`.
    * `MockEncoder`: This is a *key* element. It's a mock implementation of `webrtc::VideoEncoder`. This allows the tests to control the behavior of the underlying encoder, simulating different encoding times, keyframe generation, and hardware acceleration status without relying on a real encoder implementation. The `MOCK_METHOD` macros define the expected calls to the mock encoder.
    * `FakeEncodedImageCallback`:  A simple callback to simulate receiving encoded video frames. It primarily counts the number of encoded frames.

5. **Focus on the Test Fixture (`StatsCollectingEncoderTest`):**
    * **Setup (`StatsCollectingEncoderTest()`):**  This is where the test environment is initialized. It creates an instance of the `MockEncoder` and wraps it within a `StatsCollectingEncoder`. It also sets up a callback (`StoreProcessingStatsCB`) to capture the collected statistics.
    * **TearDown (`TearDown()`):** Cleans up resources after each test.
    * **`StoreProcessingStatsCB`:** This method is called by the `StatsCollectingEncoder` when it has collected a set of statistics. It stores the key and the stats for later verification in the tests.
    * **`CreateAndEncodeFrames` (two versions):** This is a utility method to generate and encode a sequence of video frames. It controls frame rate, keyframe interval, resolution, and whether hardware acceleration is enabled. The second version allows encoding with a specific `StatsCollectingEncoder` instance.

6. **Analyze Individual Test Cases (`TEST_F`):**  Each `TEST_F` focuses on a specific aspect of the `StatsCollectingEncoder`'s functionality.
    * **`StoreProcessingStatsCallbackHdSw` and `StoreProcessingStatsCallbackFullHdHw`:** Test the basic functionality of collecting statistics for different resolutions and hardware acceleration settings. They verify the content of the `last_stats_key_` and `last_video_stats_` variables after encoding a sequence of frames. They check things like codec profile, pixel size, hardware acceleration flag, frame count, keyframe count, and the p99 processing time.
    * **`StoreProcessingStatsCallbackFullHdSwSpatialLayers`:** Checks statistics collection when using spatial layers (SVC).
    * **`CollectionStopsIfThereAreMultipleEncodersActive`:** Tests the scenario where multiple `StatsCollectingEncoder` instances are active. It ensures that statistics collection is paused to avoid interference or incorrect data.
    * **`CollectionStartsAgainIfOneEncoderIsActive`:** Verifies that statistics collection resumes when all but one `StatsCollectingEncoder` are released.
    * **`NoCollectionAfter40000Frames`:** Checks the limit on the number of frames for which statistics are collected.
    * **`MethodCallsForwardedToInternalEncoder`:**  Crucially tests that calls to methods of the `StatsCollectingEncoder` are correctly forwarded to the underlying `MockEncoder`. This is verified using `EXPECT_CALL` and actions like `WillOnce` to check the parameters and return values.

7. **Identify Relationships with Web Technologies:**
    * **JavaScript/WebRTC API:** The `StatsCollectingEncoder` is part of the Blink rendering engine's implementation of the WebRTC API. JavaScript code using the `RTCPeerConnection` API to send video would indirectly use this encoder.
    * **HTML:** The `<video>` element in HTML is used to display video streams, including those received through WebRTC. The encoding process tested here is essential for getting video data that can be sent and eventually displayed in the `<video>` element.
    * **CSS:**  CSS can style the `<video>` element, but it doesn't directly interact with the encoding process itself. The encoding happens before the video frames are rendered.

8. **Logical Inferences (Assumptions and Outputs):**
    * **Assumption:** The mock encoder accurately simulates the encoding process for the purposes of statistics gathering.
    * **Input (for `StoreProcessingStatsCallback...` tests):**  Number of frames, resolution, hardware acceleration flag, spatial layers.
    * **Output:** The `StoreProcessingStatsCB` will be called once (in these basic tests), and the `last_stats_key_` and `last_video_stats_` variables will contain the expected values reflecting the input parameters. For instance, if `is_hw_accelerated` is true, `last_stats_key_.hw_accelerated` should also be true. The p99 encoding time should be close to the simulated value.
    * **Input (for `CollectionStopsIfThereAreMultipleEncodersActive`):** Creation of a second active encoder.
    * **Output:**  The callback `StoreProcessingStatsCB` for the first encoder will stop being called.

9. **Common User/Programming Errors:**
    * **Incorrectly interpreting statistics:**  A developer might misunderstand the meaning of `p99_processing_time_ms` or other metrics and draw incorrect conclusions about encoder performance.
    * **Not accounting for multiple active encoders:** If a web application creates multiple `RTCPeerConnection` objects sending video, and the developer is trying to track encoder statistics, they need to be aware that the global collection mechanism might pause.
    * **Assuming immediate statistics:** The statistics are collected over a period of time. A developer might try to access statistics immediately after starting encoding and find that they are not yet available or representative.

By following these steps, we can systematically analyze the code and understand its purpose, its relationship to web technologies, and potential pitfalls.
这个文件 `blink/renderer/platform/peerconnection/stats_collecting_encoder_test.cc` 是 Chromium Blink 引擎中用于测试 `StatsCollectingEncoder` 类的单元测试文件。 `StatsCollectingEncoder` 的主要功能是**封装一个视频编码器，并在编码过程中收集性能统计数据**。

下面是该测试文件的功能分解：

**1. 测试 `StatsCollectingEncoder` 的基本功能:**

* **统计收集:** 测试 `StatsCollectingEncoder` 是否能够正确地收集视频编码过程中的各种统计信息，例如：
    * 编码的帧数 (`frame_count`)
    * 关键帧的数量 (`key_frame_count`)
    * 99 百分位的处理时间 (`p99_processing_time_ms`)
    * 编解码器配置 (`codec_profile`)
    * 图像尺寸 (`pixel_size`)
    * 是否使用硬件加速 (`hw_accelerated`)
* **回调机制:** 测试当收集到一定量的统计数据后，是否能够通过预定义的回调函数 (`StoreProcessingStatsCB`) 将这些数据传递出来。

**2. 模拟不同的编码场景:**

* **不同的视频分辨率:** 测试在高分辨率（例如 Full HD）和低分辨率（例如 HD）下统计数据的收集是否正确。
* **是否使用硬件加速:** 测试在软件编码和硬件加速编码两种情况下，统计数据中的 `hw_accelerated` 标志是否正确设置。
* **是否使用空间分层 (Spatial Layers):** 测试在使用 SVC (Scalable Video Coding) 等技术进行多层编码时，统计数据的收集是否正确。
* **不同的帧率和关键帧间隔:** 虽然测试中没有显式地针对帧率进行大量测试，但通过调整 `CreateAndEncodeFrames` 函数中的参数，可以模拟不同的帧率和关键帧间隔对统计数据的影响。

**3. 测试多编码器场景:**

* **避免干扰:**  测试在存在多个 `StatsCollectingEncoder` 实例同时工作时，统计收集机制是否能够避免互相干扰，只针对其中一个编码器进行统计。
* **暂停和恢复:** 测试当有多个编码器激活时，统计收集会暂停，而当只剩下一个编码器激活时，统计收集是否能够恢复。

**4. 测试统计收集的停止条件:**

* **达到帧数上限:** 测试当编码帧数达到预设的上限（例如 40000 帧）后，统计收集是否会停止。

**5. 测试方法调用的转发:**

* **内部编码器交互:** 测试 `StatsCollectingEncoder` 是否能够正确地将诸如 `SetFecControllerOverride`, `InitEncode`, `SetRates`, `OnPacketLossRateUpdate`, `OnRttUpdate`, `OnLossNotification` 等方法调用转发给内部的实际视频编码器 (`MockEncoder`)。

**与 JavaScript, HTML, CSS 的关系：**

`StatsCollectingEncoder` 本身是一个底层的 C++ 类，直接服务于 WebRTC 的实现。它不直接与 JavaScript, HTML, CSS 代码交互，但它的功能对这些技术在 WebRTC 场景下的性能表现至关重要。

* **JavaScript:** JavaScript 代码通过 WebRTC API (例如 `RTCPeerConnection`) 使用视频编码器。`StatsCollectingEncoder` 收集的统计数据可以被 JavaScript 代码间接获取，用于监控和诊断视频编码的性能。例如，开发者可以通过 `getStats()` API 获取 WebRTC 的统计信息，其中可能包含与编码相关的指标，而这些指标的计算可能依赖于类似 `StatsCollectingEncoder` 的组件。
* **HTML:** HTML 中的 `<video>` 元素用于展示视频流。`StatsCollectingEncoder` 的目标是确保视频能够被有效地编码，从而保证 `<video>` 元素能够流畅地播放视频内容。
* **CSS:** CSS 用于样式化 HTML 元素，与视频编码过程本身没有直接关系。

**逻辑推理 (假设输入与输出):**

以 `StoreProcessingStatsCallbackHdSw` 测试为例：

* **假设输入:**
    * 视频分辨率：`kHdWidth` (1280), `kHdHeight` (720)
    * 硬件加速：`false` (软件编码)
    * 编码帧数：`kFrames` (200)
    * 关键帧间隔：`kKeyframeInterval` (25)
* **预期输出:**
    * `stats_callbacks_` 的值应该为 1 (表示统计回调被调用了一次)。
    * `last_stats_key_.is_decode` 应该为 `false` (表示是编码统计)。
    * `last_stats_key_.codec_profile` 应该为 `kCodecProfile` (`VP9PROFILE_PROFILE0`)。
    * `last_stats_key_.pixel_size` 应该为 `kHdWidth * kHdHeight` (1280 * 720)。
    * `last_stats_key_.hw_accelerated` 应该为 `false`。
    * `last_video_stats_.frame_count` 应该接近 `kFrames` (因为不是所有帧都触发统计回调)。
    * `last_video_stats_.key_frame_count` 应该接近 `kFrames / kKeyframeInterval`。
    * `last_video_stats_.p99_processing_time_ms` 应该接近 `kExpectedP99ProcessingTimeMs` (12.0ms)。
    * `encoded_image_callback_.get_frame_counter()` 应该等于 `kFrames` (表示成功编码了所有帧)。

**用户或编程常见的使用错误 (举例说明):**

虽然用户或前端开发者不直接使用 `StatsCollectingEncoder`，但与 WebRTC 相关的编程中可能会遇到以下错误，而 `StatsCollectingEncoder` 这样的组件有助于诊断这些问题：

1. **误解性能瓶颈:** 开发者可能认为视频卡顿是网络问题，但通过 `StatsCollectingEncoder` 收集的统计数据可能会显示编码耗时过长，从而指出性能瓶颈在于编码器。例如，`p99_processing_time_ms` 过高可能表明编码器性能不足。

2. **不合理的编码参数配置:** 开发者可能设置了过高的分辨率或帧率，导致编码器负载过大。通过统计数据，可以观察到编码耗时增加，从而促使开发者调整编码参数。

3. **硬件加速问题:**  开发者期望使用硬件加速，但实际并未生效。`StatsCollectingEncoder` 的 `hw_accelerated` 标志可以帮助诊断这种情况。如果该标志为 `false`，则表示当前使用的是软件编码，开发者需要检查硬件加速是否正确启用。

4. **多 PeerConnection 导致的资源竞争:**  如果开发者在同一个页面中创建了过多的 `RTCPeerConnection` 对象，每个连接都需要编码资源。`StatsCollectingEncoder` 的多编码器测试场景模拟了这种情况，并展示了统计收集可能会受到影响，这可以提醒开发者注意资源管理。

5. **统计数据延迟解读:** 开发者可能需要在编码过程稳定一段时间后才能获取到有意义的统计数据。如果在编码开始的几秒钟内就尝试获取统计数据，可能无法得到准确的性能评估。

总而言之，`blink/renderer/platform/peerconnection/stats_collecting_encoder_test.cc` 这个文件通过一系列的单元测试，确保了 `StatsCollectingEncoder` 能够可靠地收集视频编码的性能数据，这对于 WebRTC 的性能监控、问题诊断和优化至关重要。虽然前端开发者不直接操作这个类，但它所提供的功能最终会影响到 WebRTC 应用的稳定性和用户体验。

Prompt: 
```
这是目录为blink/renderer/platform/peerconnection/stats_collecting_encoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "third_party/blink/renderer/platform/peerconnection/stats_collecting_encoder.h"

#include <optional>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "base/notreached.h"
#include "base/test/task_environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/webrtc/api/make_ref_counted.h"
#include "third_party/webrtc/api/video/i420_buffer.h"
#include "third_party/webrtc/api/video/video_bitrate_allocation.h"
#include "third_party/webrtc/api/video/video_frame.h"
#include "third_party/webrtc/api/video/video_frame_buffer.h"
#include "third_party/webrtc/api/video_codecs/video_encoder.h"
#include "third_party/webrtc/modules/video_coding/include/video_error_codes.h"

namespace blink {

namespace {
constexpr float kMinEncodingTimeMs = 1.0f;
constexpr float kExpectedP99ProcessingTimeMs = 12.0f;
constexpr float kP99ToleranceMs = 0.5f;
const webrtc::SdpVideoFormat kFormatVp9{"VP9"};
constexpr media::VideoCodecProfile kCodecProfile =
    media::VideoCodecProfile::VP9PROFILE_PROFILE0;
constexpr int kHdWidth = 1280;
constexpr int kHdHeight = 720;
constexpr int kFullHdWidth = 1920;
constexpr int kFullHdHeight = 1080;
constexpr int kFramerate = 30;
constexpr int kFramesPerMinute = kFramerate * 60;
constexpr int kKeyframeInterval = 25;

class FakeVideoFrameBuffer : public webrtc::VideoFrameBuffer {
 public:
  FakeVideoFrameBuffer(int width, int height)
      : width_(width), height_(height) {}
  Type type() const override { return Type::kNative; }
  int width() const override { return width_; }
  int height() const override { return height_; }

  rtc::scoped_refptr<webrtc::I420BufferInterface> ToI420() override {
    rtc::scoped_refptr<webrtc::I420Buffer> buffer =
        webrtc::I420Buffer::Create(width_, height_);
    webrtc::I420Buffer::SetBlack(buffer.get());
    return buffer;
  }

 private:
  int width_;
  int height_;
};

webrtc::VideoFrame CreateMockFrame(int width, int height, uint32_t timestamp) {
  return webrtc::VideoFrame::Builder()
      .set_video_frame_buffer(
          rtc::make_ref_counted<FakeVideoFrameBuffer>(width, height))
      .set_rtp_timestamp(timestamp)
      .build();
}

class MockEncoder : public webrtc::VideoEncoder {
 public:
  explicit MockEncoder(base::test::TaskEnvironment* task_environment,
                       int* spatial_layers,
                       bool* is_hw_accelerated)
      : task_environment_(task_environment),
        spatial_layers_(spatial_layers),
        is_hw_accelerated_(is_hw_accelerated) {}

  // Implementation of webrtc::VideoEncoder.
  int32_t RegisterEncodeCompleteCallback(
      webrtc::EncodedImageCallback* callback) override {
    callback_ = callback;
    return WEBRTC_VIDEO_CODEC_OK;
  }
  int32_t Encode(
      const webrtc::VideoFrame& frame,
      const std::vector<webrtc::VideoFrameType>* frame_types) override {
    webrtc::EncodedImage encoded_frame;
    encoded_frame.SetRtpTimestamp(frame.rtp_timestamp());
    encoded_frame._frameType = frame_types && !frame_types->empty()
                                   ? frame_types->at(0)
                                   : webrtc::VideoFrameType::kVideoFrameDelta;

    base::TimeDelta encode_time = base::Milliseconds(
        frame_counter_++ % 100 < 90 ? kMinEncodingTimeMs
                                    : kExpectedP99ProcessingTimeMs);
    task_environment_->AdvanceClock(encode_time);
    for (int i = 0; i < *spatial_layers_; ++i) {
      encoded_frame._encodedWidth =
          frame.width() / (1 << (*spatial_layers_ - i - 1));
      encoded_frame._encodedHeight =
          frame.height() / (1 << (*spatial_layers_ - i - 1));
      encoded_frame.SetSpatialIndex(i);
      callback_->OnEncodedImage(encoded_frame, /*codec_specific_info=*/nullptr);
    }

    return WEBRTC_VIDEO_CODEC_OK;
  }
  int32_t Release() override { return WEBRTC_VIDEO_CODEC_OK; }
  EncoderInfo GetEncoderInfo() const override {
    EncoderInfo info;
    info.is_hardware_accelerated = *is_hw_accelerated_;
    return info;
  }

  MOCK_METHOD1(SetFecControllerOverride,
               void(webrtc::FecControllerOverride* fec_controller_override));
  MOCK_METHOD2(InitEncode,
               int(const webrtc::VideoCodec* codec_settings,
                   const webrtc::VideoEncoder::Settings& settings));
  MOCK_METHOD1(SetRates, void(const RateControlParameters& parameters));
  MOCK_METHOD1(OnPacketLossRateUpdate, void(float packet_loss_rate));
  MOCK_METHOD1(OnRttUpdate, void(int64_t rtt_ms));
  MOCK_METHOD1(OnLossNotification,
               void(const LossNotification& loss_notification));

 private:
  int frame_counter_ = 0;
  raw_ptr<base::test::TaskEnvironment> task_environment_;
  raw_ptr<int> spatial_layers_;
  const raw_ptr<bool> is_hw_accelerated_;
  raw_ptr<webrtc::EncodedImageCallback> callback_;
};

class FakeEncodedImageCallback : public webrtc::EncodedImageCallback {
 public:
  Result OnEncodedImage(
      const webrtc::EncodedImage& encoded_image,
      const webrtc::CodecSpecificInfo* codec_specific_info) override {
    ++frame_counter_;
    return {Result::OK, encoded_image.RtpTimestamp()};
  }
  void OnDroppedFrame(DropReason reason) override { ; }
  int get_frame_counter() const { return frame_counter_; }

 private:
  int frame_counter_ = 0;
};

class StatsCollectingEncoderTest : public ::testing::Test {
 public:
  StatsCollectingEncoderTest()
      : internal_encoder_(new MockEncoder(&task_environment_,
                                          &spatial_layers_,
                                          &is_hw_accelerated_)),
        stats_encoder_(kFormatVp9,
                       std::unique_ptr<MockEncoder>(internal_encoder_),
                       base::BindRepeating(
                           &StatsCollectingEncoderTest::StoreProcessingStatsCB,
                           base::Unretained(this))) {
    stats_encoder_.RegisterEncodeCompleteCallback(&encoded_image_callback_);
  }

  void TearDown() override {
    internal_encoder_ = nullptr;
    stats_encoder_.Release();
  }

  void StoreProcessingStatsCB(const StatsCollector::StatsKey& stats_key,
                              const StatsCollector::VideoStats& video_stats) {
    ++stats_callbacks_;
    last_stats_key_ = stats_key;
    last_video_stats_ = video_stats;
  }

  void CreateAndEncodeFrames(int width,
                             int height,
                             int spatial_layers,
                             bool is_hw_accelerated,
                             int frames,
                             int key_frame_interval,
                             int frame_rate) {
    CreateAndEncodeFrames(&stats_encoder_, width, height, spatial_layers,
                          is_hw_accelerated, frames, key_frame_interval,
                          frame_rate);
  }

  void CreateAndEncodeFrames(StatsCollectingEncoder* encoder,
                             int width,
                             int height,
                             int spatial_layers,
                             bool is_hw_accelerated,
                             int frames,
                             int key_frame_interval,
                             int frame_rate) {
    spatial_layers_ = spatial_layers;
    is_hw_accelerated_ = is_hw_accelerated;
    base::TimeDelta frame_interval = base::Microseconds(1000000 / frame_rate);
    for (int i = 0; i < frames; ++i) {
      base::TimeTicks begin_encode = base::TimeTicks::Now();
      webrtc::VideoFrame video_frame =
          CreateMockFrame(width, height, 90000 * frame_counter_ / frame_rate);
      std::vector<webrtc::VideoFrameType> video_frame_types = {
          frame_counter_ % key_frame_interval == 0
              ? webrtc::VideoFrameType::kVideoFrameKey
              : webrtc::VideoFrameType::kVideoFrameDelta};
      ++frame_counter_;

      encoder->Encode(video_frame, &video_frame_types);
      base::TimeTicks end_encode = base::TimeTicks::Now();
      if (begin_encode + frame_interval > end_encode) {
        task_environment_.AdvanceClock(frame_interval + begin_encode -
                                       end_encode);
      }
    }
  }

 protected:
  // Needed to mock time.
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  int spatial_layers_{1};
  bool is_hw_accelerated_{false};
  FakeEncodedImageCallback encoded_image_callback_;
  raw_ptr<MockEncoder> internal_encoder_;
  StatsCollectingEncoder stats_encoder_;

  uint32_t frame_counter_{0};

  int stats_callbacks_{0};
  StatsCollector::StatsKey last_stats_key_;
  StatsCollector::VideoStats last_video_stats_;
};

TEST_F(StatsCollectingEncoderTest, StoreProcessingStatsCallbackHdSw) {
  // P99 not meaningful for less than 100 frames.
  constexpr int kMinimumNumberOfFrames = 100;
  constexpr int kFrames = 200;
  EXPECT_EQ(stats_callbacks_, 0);
  CreateAndEncodeFrames(kHdWidth, kHdHeight, /*spatial_layers=*/1,
                        /*is_hw_accelerated=*/false, kFrames, kKeyframeInterval,
                        kFramerate);
  // Verify that there's been one stats callback and that the numbers are
  // reasonable.
  EXPECT_EQ(stats_callbacks_, 1);
  EXPECT_FALSE(last_stats_key_.is_decode);
  EXPECT_EQ(last_stats_key_.codec_profile, kCodecProfile);
  EXPECT_EQ(last_stats_key_.pixel_size, kHdWidth * kHdHeight);
  EXPECT_FALSE(last_stats_key_.hw_accelerated);
  EXPECT_GE(last_video_stats_.frame_count, kMinimumNumberOfFrames);
  EXPECT_LT(last_video_stats_.frame_count, kFrames);
  EXPECT_NEAR(last_video_stats_.key_frame_count,
              last_video_stats_.frame_count / kKeyframeInterval, 1);
  EXPECT_NEAR(last_video_stats_.p99_processing_time_ms,
              kExpectedP99ProcessingTimeMs, kP99ToleranceMs);
  EXPECT_EQ(encoded_image_callback_.get_frame_counter(), kFrames);
}

TEST_F(StatsCollectingEncoderTest, StoreProcessingStatsCallbackFullHdHw) {
  // P99 not meaningful for less than 100 frames.
  constexpr int kMinimumNumberOfFrames = 100;
  constexpr int kFrames = 200;
  EXPECT_EQ(stats_callbacks_, 0);
  CreateAndEncodeFrames(kFullHdWidth, kFullHdHeight, /*spatial_layers=*/1,
                        /*is_hw_accelerated=*/true, kFrames, kKeyframeInterval,
                        kFramerate);
  // Verify that there's been one stats callback and that the numbers are
  // reasonable.
  EXPECT_EQ(stats_callbacks_, 1);
  EXPECT_FALSE(last_stats_key_.is_decode);
  EXPECT_EQ(last_stats_key_.codec_profile, kCodecProfile);
  EXPECT_EQ(last_stats_key_.pixel_size, kFullHdWidth * kFullHdHeight);
  EXPECT_TRUE(last_stats_key_.hw_accelerated);
  EXPECT_GE(last_video_stats_.frame_count, kMinimumNumberOfFrames);
  EXPECT_LT(last_video_stats_.frame_count, kFrames);
  EXPECT_NEAR(last_video_stats_.key_frame_count,
              last_video_stats_.frame_count / kKeyframeInterval, 1);
  EXPECT_NEAR(last_video_stats_.p99_processing_time_ms,
              kExpectedP99ProcessingTimeMs, kP99ToleranceMs);
  EXPECT_EQ(encoded_image_callback_.get_frame_counter(), kFrames);
}

TEST_F(StatsCollectingEncoderTest,
       StoreProcessingStatsCallbackFullHdSwSpatialLayers) {
  // P99 not meaningful for less than 100 frames.
  constexpr int kMinimumNumberOfFrames = 100;
  constexpr int kFrames = 200;
  constexpr int kSpatialLayers = 3;
  EXPECT_EQ(stats_callbacks_, 0);
  CreateAndEncodeFrames(kFullHdWidth, kFullHdHeight, kSpatialLayers,
                        /*is_hw_accelerated=*/true, kFrames, kKeyframeInterval,
                        kFramerate);
  // Verify that there's been one stats callback and that the numbers are
  // reasonable.
  EXPECT_EQ(stats_callbacks_, 1);
  EXPECT_FALSE(last_stats_key_.is_decode);
  EXPECT_EQ(last_stats_key_.codec_profile, kCodecProfile);
  EXPECT_EQ(last_stats_key_.pixel_size, kFullHdWidth * kFullHdHeight);
  EXPECT_TRUE(last_stats_key_.hw_accelerated);
  EXPECT_GE(last_video_stats_.frame_count, kMinimumNumberOfFrames);
  EXPECT_LT(last_video_stats_.frame_count, kFrames);
  EXPECT_NEAR(last_video_stats_.key_frame_count,
              last_video_stats_.frame_count / kKeyframeInterval, 1);
  EXPECT_NEAR(last_video_stats_.p99_processing_time_ms,
              kExpectedP99ProcessingTimeMs, kP99ToleranceMs);
  EXPECT_EQ(encoded_image_callback_.get_frame_counter(),
            kFrames * kSpatialLayers);
}

TEST_F(StatsCollectingEncoderTest,
       CollectionStopsIfThereAreMultipleEncodersActive) {
  constexpr int kMinutesToRun = 10;
  EXPECT_EQ(stats_callbacks_, 0);
  CreateAndEncodeFrames(kHdWidth, kHdHeight, /*spatial_layers=*/1,
                        /*is_hw_accelerated=*/false, kFramesPerMinute,
                        kKeyframeInterval, kFramerate);
  int last_stats_callbacks = stats_callbacks_;

  // Create another encoder.
  FakeEncodedImageCallback second_encoded_image_callback;
  int second_encoder_spatial_layers = 1;
  bool second_encoder_is_hw_accelerated = false;
  StatsCollectingEncoder second_stats_encoder(
      kFormatVp9,
      std::make_unique<MockEncoder>(&task_environment_,
                                    &second_encoder_spatial_layers,
                                    &second_encoder_is_hw_accelerated),
      base::DoNothing());
  second_stats_encoder.RegisterEncodeCompleteCallback(
      &second_encoded_image_callback);
  // Encode one frame to make it an active encoder.
  CreateAndEncodeFrames(
      &second_stats_encoder, kHdWidth, kHdHeight, /*spatial_layers=*/1,
      /*is_hw_accelerated=*/false, 1, kKeyframeInterval, kFramerate);

  // Run for a few minutes and verify that no new callbacks are made.
  for (int minute = 0; minute < kMinutesToRun; ++minute) {
    CreateAndEncodeFrames(kHdWidth, kHdHeight, /*spatial_layers=*/1,
                          /*is_hw_accelerated=*/false, kFramesPerMinute,
                          kKeyframeInterval, kFramerate);
    // The expectation could be relaxed to allow for one callback to happen.
    EXPECT_EQ(stats_callbacks_, last_stats_callbacks);
  }
  second_stats_encoder.Release();
}

TEST_F(StatsCollectingEncoderTest, CollectionStartsAgainIfOneEncoderIsActive) {
  constexpr int kMinutesToRun = 10;
  EXPECT_EQ(stats_callbacks_, 0);

  // Create another encoder.
  FakeEncodedImageCallback second_encoded_image_callback;
  int second_encoder_spatial_layers = 1;
  bool second_encoder_is_hw_accelerated = false;
  StatsCollectingEncoder second_stats_encoder(
      kFormatVp9,
      std::make_unique<MockEncoder>(&task_environment_,
                                    &second_encoder_spatial_layers,
                                    &second_encoder_is_hw_accelerated),
      base::DoNothing());
  second_stats_encoder.RegisterEncodeCompleteCallback(
      &second_encoded_image_callback);
  // Encode one frame to make it an active encoder.
  CreateAndEncodeFrames(
      &second_stats_encoder, kHdWidth, kHdHeight, /*spatial_layers=*/1,
      /*is_hw_accelerated=*/false, 1, kKeyframeInterval, kFramerate);

  int last_stats_callbacks = stats_callbacks_;
  // Run for a few minutes and verify that no callbacks are made.
  for (int minute = 0; minute < kMinutesToRun; ++minute) {
    CreateAndEncodeFrames(kHdWidth, kHdHeight, /*spatial_layers=*/1,
                          /*is_hw_accelerated=*/false, kFramesPerMinute,
                          kKeyframeInterval, kFramerate);
    EXPECT_EQ(stats_callbacks_, last_stats_callbacks);
  }

  // Release the other encoder and verify that collection starts again.
  second_stats_encoder.Release();

  // Run for a few minutes and verify that no callbacks are made.
  for (int minute = 0; minute < kMinutesToRun; ++minute) {
    CreateAndEncodeFrames(kHdWidth, kHdHeight, /*spatial_layers=*/1,
                          /*is_hw_accelerated=*/false, kFramesPerMinute,
                          kKeyframeInterval, kFramerate);
    EXPECT_GT(stats_callbacks_, last_stats_callbacks);
    last_stats_callbacks = stats_callbacks_;
  }
}

TEST_F(StatsCollectingEncoderTest, NoCollectionAfter40000Frames) {
  constexpr int kMinutesToRun = 10;
  constexpr int kFrames = 40000;
  EXPECT_EQ(stats_callbacks_, 0);
  CreateAndEncodeFrames(kHdWidth, kHdHeight, /*spatial_layers=*/1,
                        /*is_hw_accelerated=*/false, kFrames, kKeyframeInterval,
                        kFramerate);
  EXPECT_GT(stats_callbacks_, 0);
  int last_stats_callbacks = stats_callbacks_;

  // Run for a few minutes and verify that no new callbacks are made.
  for (int minute = 0; minute < kMinutesToRun; ++minute) {
    CreateAndEncodeFrames(kHdWidth, kHdHeight, /*spatial_layers=*/1,
                          /*is_hw_accelerated=*/false, kFramesPerMinute,
                          kKeyframeInterval, kFramerate);
    // The expectation could be relaxed to allow for one callback to happen.
    EXPECT_EQ(stats_callbacks_, last_stats_callbacks);
  }
}

TEST_F(StatsCollectingEncoderTest, MethodCallsForwardedToInternalEncoder) {
  // We don't are about the object itself, only that the pointer is forwarded
  // correctly.
  webrtc::FecControllerOverride* fec_controller_override =
      reinterpret_cast<webrtc::FecControllerOverride*>(0x123456);
  EXPECT_CALL(*internal_encoder_,
              SetFecControllerOverride(fec_controller_override));
  stats_encoder_.SetFecControllerOverride(fec_controller_override);

  webrtc::VideoCodec* codec_settings_ptr =
      reinterpret_cast<webrtc::VideoCodec*>(0x123456);
  webrtc::VideoEncoder::Capabilities capabilities(/*loss_notification=*/true);
  webrtc::VideoEncoder::Settings kSettings{capabilities, /*number_of_cores=*/2,
                                           /*max_payload_size=*/2400};
  constexpr int kExpectedInitReturnValue = 13;
  EXPECT_CALL(*internal_encoder_, InitEncode)
      .WillOnce([codec_settings_ptr, &kSettings](
                    const webrtc::VideoCodec* codec_settings,
                    const webrtc::VideoEncoder::Settings& settings) {
        EXPECT_EQ(codec_settings_ptr, codec_settings);
        EXPECT_EQ(kSettings.capabilities.loss_notification,
                  settings.capabilities.loss_notification);
        EXPECT_EQ(kSettings.number_of_cores, settings.number_of_cores);
        EXPECT_EQ(kSettings.max_payload_size, settings.max_payload_size);
        return kExpectedInitReturnValue;
      });
  EXPECT_EQ(stats_encoder_.InitEncode(codec_settings_ptr, kSettings),
            kExpectedInitReturnValue);

  const webrtc::VideoBitrateAllocation kVideoBitrateAllocation;
  const webrtc::VideoEncoder::RateControlParameters kParameters = {
      kVideoBitrateAllocation, /*framerate_fps=*/24.0};
  EXPECT_CALL(*internal_encoder_, SetRates(kParameters));
  stats_encoder_.SetRates(kParameters);

  constexpr float kPacketLossRate = 0.012;
  EXPECT_CALL(*internal_encoder_, OnPacketLossRateUpdate(kPacketLossRate));
  stats_encoder_.OnPacketLossRateUpdate(kPacketLossRate);

  constexpr int64_t kRttMs = 12345;
  EXPECT_CALL(*internal_encoder_, OnRttUpdate(kRttMs));
  stats_encoder_.OnRttUpdate(kRttMs);

  const webrtc::VideoEncoder::LossNotification kLossNotification{
      /*timestamp_of_last_decodable=*/7u, /*timestamp_of_last_received=*/9u};
  EXPECT_CALL(*internal_encoder_, OnLossNotification)
      .WillOnce(
          [&kLossNotification](
              const webrtc::VideoEncoder::LossNotification& loss_notification) {
            EXPECT_EQ(loss_notification.timestamp_of_last_decodable,
                      kLossNotification.timestamp_of_last_decodable);
            EXPECT_EQ(loss_notification.timestamp_of_last_received,
                      kLossNotification.timestamp_of_last_received);
          });
  stats_encoder_.OnLossNotification(kLossNotification);
}

}  // namespace
}  // namespace blink

"""

```