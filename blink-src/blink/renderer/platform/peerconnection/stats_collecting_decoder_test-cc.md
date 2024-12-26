Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Subject:** The filename `stats_collecting_decoder_test.cc` immediately suggests that this file contains tests for something called `StatsCollectingDecoder`. The inclusion of `third_party/blink/renderer/platform/peerconnection/stats_collecting_decoder.h` confirms this. The word "decoder" also strongly implies involvement with video or audio processing.

2. **Understand the Purpose of Testing:**  Test files in software projects serve to verify the correctness and functionality of specific components. The goal is to ensure that the `StatsCollectingDecoder` class behaves as expected under various conditions.

3. **Analyze Includes:**  The included headers provide clues about the dependencies and context:
    * `<optional>`, `<vector>`: Standard C++ containers, likely used for data structures within the tests or the tested class.
    * `"base/memory/raw_ptr.h"`:  Indicates raw pointers are used, suggesting manual memory management might be involved in some way, though `raw_ptr` itself isn't owning.
    * `"base/notreached.h"`:  Used for marking code paths that should never be executed, helpful for catching unexpected behavior.
    * `"base/test/task_environment.h"`: Crucial for testing asynchronous or time-dependent code, hinting that the decoder's behavior might be related to timing.
    * `"testing/gtest/include/gtest/gtest.h"`:  Confirms this is a unit test file using the Google Test framework.
    * `"third_party/webrtc/api/...`", `"third_party/webrtc/modules/video_coding/...`": These imports strongly indicate that the `StatsCollectingDecoder` is related to WebRTC's video processing pipeline. Terms like `VideoFrame`, `VideoDecoder`, `EncodedImage` are key here.

4. **Examine the Test Structure:** The code defines a test fixture `StatsCollectingDecoderTest` inheriting from `::testing::Test`. This is standard Google Test practice. The `SetUp` and `TearDown` methods suggest initialization and cleanup tasks.

5. **Analyze Helper Classes and Functions:**  Several helper classes are defined:
    * `MockVideoFrameBuffer`:  A simplified implementation of `webrtc::VideoFrameBuffer`, likely used to create dummy video frames for testing without needing full video decoding. The `SetBlack` function hints at its simplified nature.
    * `CreateMockFrame`: A utility function to create `webrtc::VideoFrame` instances using the `MockVideoFrameBuffer`.
    * `MockDecoder`:  A *mock* object implementing the `webrtc::VideoDecoder` interface. Mock objects are essential for isolating the component under test. This mock doesn't perform actual decoding; it simply creates a dummy decoded frame and calls the registered callback. The `is_hw_accelerated_` member suggests testing different hardware acceleration scenarios.
    * `MockDecodedImageCallback`: Another mock, this time for the `webrtc::DecodedImageCallback`. It simulates varying decoding times, which is relevant for collecting performance statistics.

6. **Understand the Test Cases:** The `TEST_F` macros define individual test cases:
    * `StoreProcessingStatsCallbackHdSw`, `StoreProcessingStatsCallbackFullHdHw`: These tests seem to verify that processing statistics are correctly collected for different video resolutions (HD, Full HD) and hardware acceleration settings (software, hardware). The assertions check the values of `last_stats_key_` and `last_video_stats_`.
    * `CollectionStopsIfThereAreMultipleDecodersActive`, `CollectionStartsAgainIfOneDecoderIsActive`: These tests focus on how the statistics collection behaves when multiple decoders are involved. This likely relates to preventing over-reporting or interference.
    * `NoCollectionAfter40000Frames`: This suggests a limit on the number of frames for which statistics are collected, potentially for performance or storage reasons.

7. **Trace the Logic in `CreateAndDecodeFrames`:** This method is central to the tests. It simulates the process of encoding and decoding video frames. Key observations:
    * It takes parameters for width, height, hardware acceleration, number of frames, keyframe interval, and frame rate.
    * It creates dummy `webrtc::EncodedImage` objects.
    * It simulates the progression of time using `task_environment_.AdvanceClock(delta)`. This is crucial for the time-based statistics.
    * It calls the `Decode` method of the `StatsCollectingDecoder`.

8. **Infer the Functionality of `StatsCollectingDecoder`:** Based on the tests, we can infer that `StatsCollectingDecoder`:
    * Wraps an underlying `webrtc::VideoDecoder`.
    * Collects statistics about video decoding, including processing time.
    * Tracks whether hardware acceleration is used.
    * Associates statistics with video resolution.
    * Has logic to stop and start collecting statistics based on the number of active decoders.
    * May have a limit on the total number of frames for which statistics are collected.

9. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:**  The `StatsCollectingDecoder` is part of the Blink rendering engine, which powers Chromium-based browsers. WebRTC APIs are exposed to JavaScript, allowing web applications to perform real-time communication. This decoder is likely used internally when a JavaScript application uses WebRTC to receive video. The statistics collected could potentially be used for debugging, performance monitoring, or adaptive streaming logic within the browser or even exposed (in a limited and privacy-preserving way) to the JavaScript application.
    * **HTML:**  HTML provides the `<video>` element where the decoded video frames are eventually rendered. The performance of the decoder directly impacts the smoothness and quality of the video displayed in the `<video>` element.
    * **CSS:**  CSS is used for styling the `<video>` element, but it doesn't directly interact with the decoding process. However, performance issues with decoding *could* indirectly lead to visual glitches that users might try to address with CSS (though the root cause lies deeper).

10. **Identify Potential Errors:**
    * **Incorrect Mock Implementation:** If the `MockDecoder` or `MockDecodedImageCallback` don't accurately simulate real-world behavior, the tests might pass even if the `StatsCollectingDecoder` has bugs.
    * **Timing Issues in Tests:**  If the simulated time in the tests doesn't align with the real-world timing of decoding, the statistics collected might not be representative.
    * **Edge Cases Not Covered:** The tests might not cover all possible edge cases or error scenarios in video decoding.

By following these steps, we can systematically analyze the C++ test file and understand its purpose, the functionality of the tested component, and its relationship to web technologies.
这个C++源代码文件 `stats_collecting_decoder_test.cc` 是 Chromium Blink 引擎中用于测试 `StatsCollectingDecoder` 类的单元测试。 `StatsCollectingDecoder` 的作用是**收集视频解码过程中的统计信息**，例如解码时间和硬件加速情况。

下面详细列举其功能以及与 JavaScript, HTML, CSS 的关系、逻辑推理和常见使用错误：

**功能：**

1. **测试 `StatsCollectingDecoder` 类的核心功能：**
   - 验证 `StatsCollectingDecoder` 能否正确地收集解码统计信息。
   - 验证统计信息是否包含了关键指标，例如解码耗时、是否使用硬件加速、视频分辨率等。
   - 验证在不同场景下统计信息的准确性。

2. **模拟视频解码过程：**
   - 使用 `MockDecoder` 模拟一个简单的视频解码器，这个模拟解码器并不进行真正的解码操作，而是模拟解码完成并提供解码后的帧。
   - 使用 `MockDecodedImageCallback` 模拟解码完成后的回调，用于设置模拟的解码处理时间。
   - 创建并解码一系列模拟的视频帧，控制帧的尺寸、关键帧间隔等属性。

3. **验证统计信息的收集和存储：**
   - 通过 `StoreProcessingStatsCB` 回调函数来接收 `StatsCollectingDecoder` 收集到的统计信息。
   - 断言接收到的统计信息是否符合预期，例如解码耗时是否在合理范围内，是否正确识别了硬件加速状态等。

4. **测试多解码器场景下的行为：**
   - 验证当存在多个活跃的解码器时，统计信息的收集是否会停止，以避免重复或错误的统计。
   - 验证当其他解码器释放后，统计信息的收集是否会重新开始。

5. **测试帧数限制：**
   - 验证在解码大量帧之后，统计信息的收集是否会停止，这可能是为了防止无限增长的统计数据占用过多资源。

**与 JavaScript, HTML, CSS 的关系：**

`StatsCollectingDecoder` 本身是一个 C++ 类，直接运行在浏览器的渲染进程中，与 JavaScript, HTML, CSS 没有直接的代码级别的交互。然而，它收集的统计信息对于理解和优化 WebRTC 在浏览器中的性能至关重要，而 WebRTC 功能是通过 JavaScript API 暴露给网页的。

* **JavaScript:**
    - Web 开发者可以使用 WebRTC API (例如 `RTCPeerConnection`) 来进行实时的音视频通信。
    - 当通过 WebRTC 接收到视频流时，浏览器内部会使用 `StatsCollectingDecoder` 或类似的组件来解码视频帧。
    - 虽然 JavaScript 代码不能直接访问 `StatsCollectingDecoder` 的内部数据，但浏览器可能会将部分解码统计信息暴露给 JavaScript，用于性能监控或诊断目的。例如，`RTCPeerConnection.getStats()` 方法返回的统计信息中可能包含与解码相关的指标。
    - **举例说明：**  假设一个 WebRTC 应用遇到了视频卡顿问题。开发者可以通过 `getStats()` 获取解码相关的统计信息，例如解码延迟是否过高，是否频繁出现丢帧等，从而帮助定位问题可能出在网络传输还是本地解码性能上。

* **HTML:**
    - HTML 的 `<video>` 元素用于展示解码后的视频。
    - `StatsCollectingDecoder` 的性能直接影响到 `<video>` 元素中视频播放的流畅度和质量。
    - **举例说明：** 如果 `StatsCollectingDecoder` 收集到大量的解码延迟过高的统计信息，那么用户在 HTML 页面上看到的视频很可能会出现卡顿或画面撕裂。

* **CSS:**
    - CSS 用于控制 HTML 元素的样式，包括 `<video>` 元素的外观。
    - `StatsCollectingDecoder` 的功能与 CSS 没有直接关系。CSS 不能影响视频的解码过程或访问解码统计信息。
    - **举例说明：** 即使使用 CSS 将 `<video>` 元素设置为全屏或添加滤镜效果，也不会影响 `StatsCollectingDecoder` 的解码性能和统计收集。

**逻辑推理（假设输入与输出）：**

假设 `CreateAndDecodeFrames` 函数被调用，模拟解码 100 帧 1280x720 的 VP9 视频，且不使用硬件加速：

* **假设输入：**
    - `width = 1280`
    - `height = 720`
    - `is_hw_accelerated = false`
    - `frames = 100`
    - `key_frame_interval = 25`
    - `frame_rate = 30`

* **逻辑推理过程：**
    1. `StatsCollectingDecoder` 会包装一个 `MockDecoder` 实例。
    2. 循环 100 次，每次模拟解码一帧。
    3. 每隔 `key_frame_interval` (25 帧) 会模拟一个关键帧。
    4. `MockDecoder` 的 `Decode` 方法会被调用，并模拟解码完成，调用 `MockDecodedImageCallback`。
    5. `MockDecodedImageCallback` 会设置模拟的解码处理时间。
    6. `StatsCollectingDecoder` 会收集每帧的解码信息，包括处理时间、帧类型、分辨率等。
    7. 当解码完成一定数量的帧后，`StatsCollectingDecoder` 会调用 `StoreProcessingStatsCB` 回调函数。

* **可能的输出 (由 `StoreProcessingStatsCB` 接收)：**
    - `stats_callbacks_` 的值会增加 1。
    - `last_stats_key_` 的值可能为：
        - `is_decode = true`
        - `codec_profile = media::VideoCodecProfile::VP9PROFILE_PROFILE0`
        - `pixel_size = 1280 * 720`
        - `hw_accelerated = false`
    - `last_video_stats_` 的值可能为：
        - `frame_count` 接近 100。
        - `key_frame_count` 接近 100 / 25 = 4。
        - `p99_processing_time_ms` 接近 `kExpectedP99ProcessingTimeMs` (12.0f)。

**涉及用户或编程常见的使用错误：**

虽然 `stats_collecting_decoder_test.cc` 是测试代码，不涉及用户直接操作，但可以推断出 `StatsCollectingDecoder` 在实际使用中可能遇到的一些问题或开发者需要注意的点：

1. **过度依赖统计信息进行实时决策：**  `StatsCollectingDecoder` 收集的是历史统计信息。如果开发者错误地认为这些信息能完全反映当前的瞬时解码性能，并基于此做出实时的自适应调整，可能会导致错误的判断。例如，过去一段时间解码很快，不代表现在一定很快。

2. **忽略统计信息的上下文：** 解码性能受到多种因素影响，例如网络状况、CPU 负载、视频内容复杂度等。开发者需要结合这些上下文信息来分析解码统计数据，而不是孤立地看待。例如，在网络不佳的情况下解码延迟升高是正常的，不能简单地归咎于解码器性能问题。

3. **在不稳定的测试环境中进行性能测试：** 如果运行集成测试的环境不稳定（例如 CPU 负载波动大），那么 `StatsCollectingDecoder` 收集到的解码时间可能会有偏差，导致测试结果不可靠。这也是为什么单元测试通常会使用 mock 对象来隔离被测试的组件，减少外部因素的干扰。

4. **误解 P99 等统计指标的含义：**  P99 (第 99 百分位数) 表示 99% 的解码耗时低于该值。开发者需要理解这些统计指标的含义，才能正确分析解码性能。如果误认为 P99 是最大解码时间，可能会做出错误的结论。

5. **在多解码器场景下未考虑统计收集的机制：**  测试代码中展示了当存在多个活跃解码器时，统计收集可能会停止。开发者在设计和调试 WebRTC 应用时，需要了解这种机制，避免因统计信息缺失而困惑。

总而言之，`stats_collecting_decoder_test.cc` 通过一系列单元测试，验证了 `StatsCollectingDecoder` 收集视频解码统计信息的功能，这对于理解和优化 WebRTC 的性能至关重要，虽然它与前端技术没有直接代码交互，但其结果会影响到用户在网页上体验到的音视频质量。

Prompt: 
```
这是目录为blink/renderer/platform/peerconnection/stats_collecting_decoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "third_party/blink/renderer/platform/peerconnection/stats_collecting_decoder.h"

#include <optional>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "base/notreached.h"
#include "base/test/task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/webrtc/api/make_ref_counted.h"
#include "third_party/webrtc/api/video/i420_buffer.h"
#include "third_party/webrtc/api/video/video_frame.h"
#include "third_party/webrtc/api/video/video_frame_buffer.h"
#include "third_party/webrtc/api/video_codecs/video_decoder.h"
#include "third_party/webrtc/modules/video_coding/include/video_error_codes.h"

namespace blink {

namespace {
constexpr float kMinDecodingTimeMs = 1.0f;
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

class MockVideoFrameBuffer : public webrtc::VideoFrameBuffer {
 public:
  MockVideoFrameBuffer(int width, int height)
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
          rtc::make_ref_counted<MockVideoFrameBuffer>(width, height))
      .set_rtp_timestamp(timestamp)
      .build();
}

class MockDecoder : public webrtc::VideoDecoder {
 public:
  explicit MockDecoder(bool* is_hw_accelerated)
      : is_hw_accelerated_(is_hw_accelerated) {}

  // Implementation of webrtc::VideoDecoder.
  bool Configure(const Settings& settings) override { return true; }
  int32_t Decode(const webrtc::EncodedImage& input_image,
                 bool missing_frames,
                 int64_t render_time_ms) override {
    webrtc::VideoFrame video_frame =
        CreateMockFrame(input_image._encodedWidth, input_image._encodedHeight,
                        input_image.RtpTimestamp());
    callback_->Decoded(video_frame, std::nullopt, std::nullopt);
    return WEBRTC_VIDEO_CODEC_OK;
  }

  int32_t RegisterDecodeCompleteCallback(
      webrtc::DecodedImageCallback* callback) override {
    callback_ = callback;
    return WEBRTC_VIDEO_CODEC_OK;
  }

  int32_t Release() override { return WEBRTC_VIDEO_CODEC_OK; }

  DecoderInfo GetDecoderInfo() const override {
    DecoderInfo info;
    info.is_hardware_accelerated = *is_hw_accelerated_;
    return info;
  }

 private:
  const raw_ptr<bool> is_hw_accelerated_;
  raw_ptr<webrtc::DecodedImageCallback> callback_;
};

class MockDecodedImageCallback : public webrtc::DecodedImageCallback {
 public:
  MockDecodedImageCallback(float min_decode_time_ms, float p90_decode_time_ms)
      : min_decode_time_ms_(min_decode_time_ms),
        p90_decode_time_ms_(p90_decode_time_ms) {}

  // Implementation of webrtc::DecodedImageCallback.
  int32_t Decoded(webrtc::VideoFrame& decodedImage) override { NOTREACHED(); }
  void Decoded(webrtc::VideoFrame& decodedImage,
               std::optional<int32_t> decode_time_ms,
               std::optional<uint8_t> qp) override {
    // Set the processing time. Start time is set to a fixed nonzero time since
    // we're only interested in the delta.
    webrtc::Timestamp start_time = webrtc::Timestamp::Seconds(1234);
    webrtc::TimeDelta decode_time = webrtc::TimeDelta::Millis(
        frame_counter_ % 100 < 90 ? min_decode_time_ms_ : p90_decode_time_ms_);
    decodedImage.set_processing_time({start_time, start_time + decode_time});

    ++frame_counter_;
  }

 private:
  int frame_counter_{0};
  float min_decode_time_ms_;
  float p90_decode_time_ms_;
};

class StatsCollectingDecoderTest : public ::testing::Test {
 protected:
  StatsCollectingDecoderTest()
      : decoded_image_callback_(kMinDecodingTimeMs,
                                kExpectedP99ProcessingTimeMs),
        stats_decoder_(kFormatVp9,
                       std::make_unique<MockDecoder>(&is_hw_accelerated_),
                       base::BindRepeating(
                           &StatsCollectingDecoderTest::StoreProcessingStatsCB,
                           base::Unretained(this))) {
    stats_decoder_.RegisterDecodeCompleteCallback(&decoded_image_callback_);
  }

  void TearDown() override { stats_decoder_.Release(); }

  void StoreProcessingStatsCB(const StatsCollector::StatsKey& stats_key,
                              const StatsCollector::VideoStats& video_stats) {
    ++stats_callbacks_;
    last_stats_key_ = stats_key;
    last_video_stats_ = video_stats;
  }

  void CreateAndDecodeFrames(int width,
                             int height,
                             bool is_hw_accelerated,
                             int frames,
                             int key_frame_interval,
                             int frame_rate) {
    CreateAndDecodeFrames(&stats_decoder_, width, height, is_hw_accelerated,
                          frames, key_frame_interval, frame_rate);
  }

  void CreateAndDecodeFrames(StatsCollectingDecoder* decoder,
                             int width,
                             int height,
                             bool is_hw_accelerated,
                             int frames,
                             int key_frame_interval,
                             int frame_rate) {
    is_hw_accelerated_ = is_hw_accelerated;
    for (int i = 0; i < frames; ++i) {
      webrtc::EncodedImage encoded_frame;
      encoded_frame._encodedWidth = width;
      encoded_frame._encodedHeight = height;
      encoded_frame.SetRtpTimestamp(
          90000 * frame_counter /
          frame_rate);  // RTP timestamp using 90 kHz clock.
      encoded_frame._frameType = frame_counter % key_frame_interval == 0
                                     ? webrtc::VideoFrameType::kVideoFrameKey
                                     : webrtc::VideoFrameType::kVideoFrameDelta;
      ++frame_counter;
      base::TimeDelta delta = base::Milliseconds(1000 / frame_rate);
      task_environment_.AdvanceClock(delta);
      decoder->Decode(encoded_frame, /*missing_frames=*/false,
                      /*render_time_ms=*/0);
    }
  }

  // Needed to mock time.
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  bool is_hw_accelerated_{false};
  MockDecodedImageCallback decoded_image_callback_;
  StatsCollectingDecoder stats_decoder_;

  uint32_t frame_counter{0};

  int stats_callbacks_{0};
  StatsCollector::StatsKey last_stats_key_;
  StatsCollector::VideoStats last_video_stats_;
};

TEST_F(StatsCollectingDecoderTest, StoreProcessingStatsCallbackHdSw) {
  // P99 not meaningful for less than 100 frames.
  constexpr int kMinimumNumberOfFrames = 100;
  constexpr int kFrames = 200;
  EXPECT_EQ(stats_callbacks_, 0);
  CreateAndDecodeFrames(kHdWidth, kHdHeight, /*is_hw_accelerated=*/false,
                        kFrames, kKeyframeInterval, kFramerate);
  // Verify that there's been one stats callback and that the numbers are
  // reasonable.
  EXPECT_EQ(stats_callbacks_, 1);
  EXPECT_TRUE(last_stats_key_.is_decode);
  EXPECT_EQ(last_stats_key_.codec_profile, kCodecProfile);
  EXPECT_EQ(last_stats_key_.pixel_size, kHdWidth * kHdHeight);
  EXPECT_FALSE(last_stats_key_.hw_accelerated);
  EXPECT_GE(last_video_stats_.frame_count, kMinimumNumberOfFrames);
  EXPECT_LT(last_video_stats_.frame_count, kFrames);
  EXPECT_NEAR(last_video_stats_.key_frame_count,
              last_video_stats_.frame_count / kKeyframeInterval, 1);
  EXPECT_NEAR(last_video_stats_.p99_processing_time_ms,
              kExpectedP99ProcessingTimeMs, kP99ToleranceMs);
}

TEST_F(StatsCollectingDecoderTest, StoreProcessingStatsCallbackFullHdHw) {
  // P99 not meaningful for less than 100 frames.
  constexpr int kMinimumNumberOfFrames = 100;
  constexpr int kFrames = 200;
  EXPECT_EQ(stats_callbacks_, 0);
  CreateAndDecodeFrames(kFullHdWidth, kFullHdHeight, /*is_hw_accelerated=*/true,
                        kFrames, kKeyframeInterval, kFramerate);
  // Verify that there's been one stats callback and that the numbers are
  // reasonable.
  EXPECT_EQ(stats_callbacks_, 1);
  EXPECT_TRUE(last_stats_key_.is_decode);
  EXPECT_EQ(last_stats_key_.codec_profile, kCodecProfile);
  EXPECT_EQ(last_stats_key_.pixel_size, kFullHdWidth * kFullHdHeight);
  EXPECT_TRUE(last_stats_key_.hw_accelerated);
  EXPECT_GE(last_video_stats_.frame_count, kMinimumNumberOfFrames);
  EXPECT_LT(last_video_stats_.frame_count, kFrames);
  EXPECT_NEAR(last_video_stats_.key_frame_count,
              last_video_stats_.frame_count / kKeyframeInterval, 1);
  EXPECT_NEAR(last_video_stats_.p99_processing_time_ms,
              kExpectedP99ProcessingTimeMs, kP99ToleranceMs);
}

TEST_F(StatsCollectingDecoderTest,
       CollectionStopsIfThereAreMultipleDecodersActive) {
  constexpr int kMinutesToRun = 10;
  EXPECT_EQ(stats_callbacks_, 0);
  CreateAndDecodeFrames(kHdWidth, kHdHeight, /*is_hw_accelerated=*/false,
                        kFramesPerMinute, kKeyframeInterval, kFramerate);
  int last_stats_callbacks = stats_callbacks_;

  // Create another decoder.
  MockDecodedImageCallback second_decoded_image_callback(
      kMinDecodingTimeMs, kExpectedP99ProcessingTimeMs);
  bool second_decoder_is_hw_accelerated = false;
  StatsCollectingDecoder second_stats_decoder(
      kFormatVp9,
      std::make_unique<MockDecoder>(&second_decoder_is_hw_accelerated),
      base::DoNothing());
  second_stats_decoder.RegisterDecodeCompleteCallback(
      &second_decoded_image_callback);
  // Decode one frame to make it an active decoder.
  CreateAndDecodeFrames(&second_stats_decoder, kHdWidth, kHdHeight,
                        /*is_hw_accelerated=*/false, 1, kKeyframeInterval,
                        kFramerate);

  // Run for a few minutes and verify that no new callbacks are made.
  for (int minute = 0; minute < kMinutesToRun; ++minute) {
    CreateAndDecodeFrames(kHdWidth, kHdHeight, /*is_hw_accelerated=*/false,
                          kFramesPerMinute, kKeyframeInterval, kFramerate);
    // The expectation could be relaxed to allow for one callback to happen.
    EXPECT_EQ(stats_callbacks_, last_stats_callbacks);
  }
  second_stats_decoder.Release();
}

TEST_F(StatsCollectingDecoderTest, CollectionStartsAgainIfOneDecoderIsActive) {
  constexpr int kMinutesToRun = 10;
  EXPECT_EQ(stats_callbacks_, 0);

  // Create another decoder.
  MockDecodedImageCallback second_decoded_image_callback(
      kMinDecodingTimeMs, kExpectedP99ProcessingTimeMs);
  bool second_decoder_is_hw_accelerated = false;
  StatsCollectingDecoder second_stats_decoder(
      kFormatVp9,
      std::make_unique<MockDecoder>(&second_decoder_is_hw_accelerated),
      base::DoNothing());
  second_stats_decoder.RegisterDecodeCompleteCallback(
      &second_decoded_image_callback);
  // Decode one frame to make it an active decoder.
  CreateAndDecodeFrames(&second_stats_decoder, kHdWidth, kHdHeight,
                        /*is_hw_accelerated=*/false, 1, kKeyframeInterval,
                        kFramerate);

  int last_stats_callbacks = stats_callbacks_;
  // Run for a few minutes and verify that no callbacks are made.
  for (int minute = 0; minute < kMinutesToRun; ++minute) {
    CreateAndDecodeFrames(kHdWidth, kHdHeight, /*is_hw_accelerated=*/false,
                          kFramesPerMinute, kKeyframeInterval, kFramerate);
    EXPECT_EQ(stats_callbacks_, last_stats_callbacks);
  }

  // Release the other decoder and verify that collection starts again.
  second_stats_decoder.Release();

  // Run for a few minutes and verify that no callbacks are made.
  for (int minute = 0; minute < kMinutesToRun; ++minute) {
    CreateAndDecodeFrames(kHdWidth, kHdHeight, /*is_hw_accelerated=*/false,
                          kFramesPerMinute, kKeyframeInterval, kFramerate);
    EXPECT_GT(stats_callbacks_, last_stats_callbacks);
    last_stats_callbacks = stats_callbacks_;
  }
}

TEST_F(StatsCollectingDecoderTest, NoCollectionAfter40000Frames) {
  constexpr int kMinutesToRun = 10;
  constexpr int kFrames = 40000;
  EXPECT_EQ(stats_callbacks_, 0);
  CreateAndDecodeFrames(kHdWidth, kHdHeight, /*is_hw_accelerated=*/false,
                        kFrames, kKeyframeInterval, kFramerate);
  EXPECT_GT(stats_callbacks_, 0);
  int last_stats_callbacks = stats_callbacks_;

  // Run for a few minutes and verify that no new callbacks are made.
  for (int minute = 0; minute < kMinutesToRun; ++minute) {
    CreateAndDecodeFrames(kHdWidth, kHdHeight, /*is_hw_accelerated=*/false,
                          kFramesPerMinute, kKeyframeInterval, kFramerate);
    // The expectation could be relaxed to allow for one callback to happen.
    EXPECT_EQ(stats_callbacks_, last_stats_callbacks);
  }
}

}  // namespace
}  // namespace blink

"""

```