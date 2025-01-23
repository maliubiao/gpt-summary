Response: The user wants to understand the functionality of the C++ unit test file `video_decode_stats_reporter_unittest.cc`. I need to analyze the code to identify its purpose and how it tests the `VideoDecodeStatsReporter` class. Specifically, I should look for:

1. **Core Functionality:** What aspects of `VideoDecodeStatsReporter` are being tested?
2. **Relationship to Web Technologies:** Does the test code interact with concepts related to JavaScript, HTML, or CSS?
3. **Logic and Scenarios:** Can I infer test scenarios based on the code, including inputs and expected outputs?
4. **Common Usage Errors:**  Does the test code reveal potential mistakes users or developers might make when using `VideoDecodeStatsReporter`?

**Plan:**

1. Read through the code to understand the test setup, mock objects, and individual test cases.
2. Identify the key functionalities of `VideoDecodeStatsReporter` being exercised by the tests.
3. Analyze if the tested functionalities have any direct or indirect connection to JavaScript, HTML, or CSS.
4. For each test case, determine the assumed input (state of the `VideoDecodeStatsReporter`, mocked dependencies, etc.) and the expected output (interactions with the mock `VideoDecodeStatsRecorder`, state changes of the reporter, etc.).
5. Based on the test logic, identify potential usage errors that the tests are designed to prevent or detect.
这个C++文件 `video_decode_stats_reporter_unittest.cc` 是 Chromium Blink 引擎中用于测试 `VideoDecodeStatsReporter` 类的单元测试。它的主要功能是验证 `VideoDecodeStatsReporter` 类在各种场景下是否能正确地收集和报告视频解码统计信息。

以下是该文件的具体功能分解：

**1. 模拟依赖项 (Mocking Dependencies):**

* **`RecordInterceptor` 类:**  这是一个模拟 (mock) `media::mojom::VideoDecodeStatsRecorder` 接口的类。`VideoDecodeStatsReporter` 类使用这个接口来向外部报告解码统计信息。`RecordInterceptor` 允许测试用例捕获和验证 `VideoDecodeStatsReporter` 何时以及如何调用 `VideoDecodeStatsRecorder` 的方法，例如 `StartNewRecord` 和 `UpdateRecord`。

**2. 测试用例 (Test Cases):**

该文件包含多个独立的测试用例，每个测试用例都针对 `VideoDecodeStatsReporter` 的特定功能或行为：

* **`RecordWhilePlaying`:** 测试在视频播放过程中，解码统计信息是否按预期记录和更新。
* **`RecordingStopsWhenPaused`:** 测试当视频暂停时，统计信息的记录是否停止，并在恢复播放后重新开始。
* **`RecordingStopsWhenHidden`:** 测试当包含视频的页面被隐藏时（例如，切换到其他标签页），统计信息的记录是否停止，并在页面重新显示后重新开始。当页面隐藏时，会启动一个新的记录。
* **`RecordingStopsWhenNoDecodeProgress`:** 测试当视频解码没有进展时（例如，网络缓冲），统计信息的记录是否会暂停，并在解码恢复后继续。
* **`NewRecordStartsForFpsChange`:** 测试当视频的帧率 (FPS) 发生显著变化时，是否会启动一个新的统计记录。
* **`FpsStabilizationFailed`:** 测试当帧率持续不稳定，无法确定稳定值时，报告器是否会停止报告。
* **`FpsStabilizationFailed_TinyWindows`:** 测试当帧率频繁快速变化，导致产生大量很短的统计窗口时，报告器是否会停止报告。
* **`ThrottleFpsTimerIfNoDecodeProgress`:** 测试当解码没有进展时，用于稳定帧率的定时器是否会降低频率，以避免不必要的资源消耗。
* **`FpsBucketing`:** 测试帧率的微小变化是否会被忽略，只有当变化超过一定阈值时才会开始新的记录。同时测试对于非标准帧率是否会将其归类到附近的常用帧率桶中。
* **`ResolutionBucketing`:** 测试视频分辨率的微小变化是否会被忽略，只有当变化足够大，进入不同的分辨率桶时才会开始新的记录。同时测试对于正好落在桶边界上的分辨率，稍微增大一点会开始新的记录。
* **`ResolutionTooSmall`:** 测试当视频分辨率非常小时，报告器是否会停止报告。当分辨率恢复到可接受范围时，会开始新的记录。
* **`VaryEmeProperties`:** 测试当使用加密媒体扩展 (EME) 时，`VideoDecodeStatsReporter` 是否能正确处理不同的密钥系统和硬件安全编解码器设置。
* **`SanitizeFrameCounts`:** 测试当报告的丢帧数或高效解码帧数超过总解码帧数时，报告器是否会进行数据清理，防止上报不合理的数据。

**3. 功能与 JavaScript, HTML, CSS 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript、HTML 或 CSS 代码，但它测试的 `VideoDecodeStatsReporter` 类与这些技术有密切关系：

* **`<video>` 标签 (HTML):**  `VideoDecodeStatsReporter` 负责收集通过 HTML `<video>` 标签播放的视频的解码统计信息。这些统计信息可以帮助开发者了解视频播放的性能，例如卡顿、丢帧等。
* **Media Source Extensions (MSE) / Encrypted Media Extensions (EME) (JavaScript API):**  JavaScript 代码可以使用 MSE API 来动态地构建视频流，或者使用 EME API 来处理加密视频。`VideoDecodeStatsReporter` 需要能够处理这些场景下的解码统计。例如，`VaryEmeProperties` 测试用例就直接关注 EME 相关的属性。
* **用户体验 (所有):**  `VideoDecodeStatsReporter` 收集的统计信息最终是为了提升用户的视频播放体验。通过监控解码性能，开发者可以优化视频编码、网络传输或解码器实现，从而减少卡顿和丢帧，提供更流畅的观看体验。

**举例说明:**

假设一个网页使用 `<video>` 标签播放一个 720p 的视频。`VideoDecodeStatsReporter` 会在后台收集以下信息：

* **假设输入:**
    * 视频正在播放。
    * 解码器正在解码视频帧。
    * 帧率稳定在 30fps。
    * 分辨率为 1280x720。
* **预期 `RecordInterceptor` 的输出 (调用 `StartNewRecord`):**
    * `profile`: 视频的编码 profile (例如 `VP9PROFILE_PROFILE0`)
    * `natural_size`: `gfx::Size(1280, 720)`
    * `frames_per_sec`: 30
    * `key_system`:  如果使用 EME，则为密钥系统名称 (例如 "org.w3.clearkey")，否则可能为空字符串。
    * `use_hw_secure_codecs`:  是否使用硬件安全解码器。
* **预期 `RecordInterceptor` 的输出 (调用 `UpdateRecord`):**
    * `frames_decoded`: 自上次更新以来的解码帧数 (例如 20)。
    * `frames_dropped`: 自上次更新以来的丢帧数 (例如 1)。
    * `frames_power_efficient`: 自上次更新以来的高效解码帧数 (例如 1)。

**逻辑推理的假设输入与输出:**

考虑 `NewRecordStartsForFpsChange` 测试用例：

* **假设输入:**
    1. 视频开始播放，帧率稳定在 30fps。
    2. `VideoDecodeStatsReporter` 已经向 `RecordInterceptor` 发送了 `StartNewRecord`，并且正在定期发送 `UpdateRecord`。
    3. 视频的帧率突然变为 60fps。
* **预期输出:**
    1. 在检测到帧率变化后，`VideoDecodeStatsReporter` 会再次调用 `RecordInterceptor` 的 `StartNewRecord` 方法，这次 `frames_per_sec` 参数为 60。
    2. 之前的统计记录会被认为是完成，可能会调用 `FinalizeRecord` (虽然在这个测试文件中没有直接验证 `FinalizeRecord`)。
    3. `UpdateRecord` 的调用会基于新的帧率开始新的统计。

**涉及用户或编程常见的使用错误:**

虽然这个文件是测试代码，但它可以帮助我们理解可能出现的使用错误：

* **误解统计信息的含义:** 开发者可能不清楚 `frames_decoded`、`frames_dropped` 和 `frames_power_efficient` 的具体含义，导致对统计数据的错误分析。测试用例通过模拟不同的场景，帮助开发者理解这些指标的变化。
* **未考虑页面隐藏/暂停的影响:** 开发者可能没有意识到当页面被隐藏或视频暂停时，统计信息会被暂停或重新开始。测试用例 `RecordingStopsWhenHidden` 和 `RecordingStopsWhenPaused` 强调了这一点。
* **对帧率变化的敏感性:** 开发者可能没有意识到帧率的显著变化会触发新的统计记录。测试用例 `NewRecordStartsForFpsChange` 演示了这种行为。
* **假设统计信息总是连续的:**  由于各种原因（例如，网络问题导致解码停顿），统计信息的收集可能不是连续的。`RecordingStopsWhenNoDecodeProgress` 测试用例模拟了这种情况。
* **硬件加速和安全解码的配置错误:**  对于使用了 EME 的视频，密钥系统和硬件安全解码的配置会影响解码统计。`VaryEmeProperties` 测试用例验证了报告器对这些配置的处理。

总而言之，`video_decode_stats_reporter_unittest.cc` 是一个重要的测试文件，它确保了 `VideoDecodeStatsReporter` 能够可靠地收集和报告视频解码统计信息，这对于理解和优化 Web 上的视频播放体验至关重要。这些统计信息最终会帮助开发者提供更流畅、更高效的视频播放体验。

### 提示词
```
这是目录为blink/renderer/platform/media/video_decode_stats_reporter_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/media/video_decode_stats_reporter.h"

#include <memory>
#include <optional>

#include "base/functional/bind.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/memory/scoped_refptr.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "media/base/cdm_config.h"
#include "media/base/media_util.h"
#include "media/base/video_codecs.h"
#include "media/base/video_types.h"
#include "media/capabilities/bucket_utility.h"
#include "media/mojo/mojom/media_types.mojom.h"
#include "media/mojo/mojom/video_decode_stats_recorder.mojom.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "ui/gfx/geometry/rect.h"

namespace blink {

using ::testing::Invoke;
using ::testing::Return;
using ::testing::_;

const media::VideoCodecProfile kDefaultProfile = media::VP9PROFILE_PROFILE0;
const int kDefaultHeight = 480;
const int kDefaultWidth = 640;
const char kDefaultKeySystem[] = "org.w3.clearkey";
const bool kDefaultUseHwSecureCodecs = true;
const media::CdmConfig kDefaultCdmConfig = {kDefaultKeySystem, false, false,
                                            kDefaultUseHwSecureCodecs};
const double kDefaultFps = 30;
const int kDecodeCountIncrement = 20;
const int kDroppedCountIncrement = 1;
const int kDecodePowerEfficientCountIncrement = 1;

media::VideoDecoderConfig MakeVideoConfig(media::VideoCodec codec,
                                          media::VideoCodecProfile profile,
                                          gfx::Size natural_size) {
  gfx::Size coded_size = natural_size;
  gfx::Rect visible_rect(coded_size.width(), coded_size.height());
  return media::VideoDecoderConfig(
      codec, profile, media::VideoDecoderConfig::AlphaMode::kIsOpaque,
      media::VideoColorSpace::JPEG(), media::kNoTransformation, coded_size,
      visible_rect, natural_size, media::EmptyExtraData(),
      media::EncryptionScheme::kUnencrypted);
}

media::PipelineStatistics MakeStats(int frames_decoded,
                                    int frames_dropped,
                                    int power_efficient_decoded_frames,
                                    double fps) {
  // Will initialize members with reasonable defaults.
  media::PipelineStatistics stats;
  stats.video_frames_decoded = frames_decoded;
  stats.video_frames_dropped = frames_dropped;
  stats.video_frames_decoded_power_efficient = power_efficient_decoded_frames;
  stats.video_frame_duration_average = base::Seconds(1.0 / fps);
  return stats;
}

// Mock VideoDecodeStatsRecorder to verify reporter/recorder interactions.
class RecordInterceptor : public media::mojom::VideoDecodeStatsRecorder {
 public:
  RecordInterceptor() = default;
  ~RecordInterceptor() override = default;

  // Until move-only types work.
  void StartNewRecord(media::mojom::PredictionFeaturesPtr features) override {
    MockStartNewRecord(features->profile, features->video_size,
                       features->frames_per_sec, features->key_system,
                       features->use_hw_secure_codecs);
  }

  MOCK_METHOD5(MockStartNewRecord,
               void(media::VideoCodecProfile profile,
                    const gfx::Size& natural_size,
                    int frames_per_sec,
                    std::string key_system,
                    bool use_hw_secure_codecs));

  void UpdateRecord(media::mojom::PredictionTargetsPtr targets) override {
    MockUpdateRecord(targets->frames_decoded, targets->frames_dropped,
                     targets->frames_power_efficient);
  }

  MOCK_METHOD3(MockUpdateRecord,
               void(uint32_t frames_decoded,
                    uint32_t frames_dropped,
                    uint32_t frames_power_efficient));

  MOCK_METHOD0(FinalizeRecord, void());
};

class VideoDecodeStatsReporterTest : public ::testing::Test {
 public:
  VideoDecodeStatsReporterTest()
      : kDefaultSize_(kDefaultWidth, kDefaultHeight) {}
  ~VideoDecodeStatsReporterTest() override = default;

  void SetUp() override {
    // Make reporter with default configuration. Connects RecordInterceptor as
    // remote mojo VideoDecodeStatsRecorder.
    MakeReporter();

    // Start each test with no decodes, no drops, and steady framerate.
    pipeline_decoded_frames_ = 0;
    pipeline_dropped_frames_ = 0;
    pipeline_power_efficient_frames_ = 0;
    pipeline_framerate_ = kDefaultFps;
  }

  void TearDown() override {
    // Depends on `reporter_` so must be cleared before it is destroyed.
    interceptor_ = nullptr;

    // Break the IPC connection if reporter still around.
    reporter_.reset();

    // Run task runner to have Mojo cleanup interceptor_.
    task_environment_.RunUntilIdle();
  }

  media::PipelineStatistics MakeAdvancingDecodeStats() {
    pipeline_decoded_frames_ += kDecodeCountIncrement;
    pipeline_dropped_frames_ += kDroppedCountIncrement;
    pipeline_power_efficient_frames_ += kDecodePowerEfficientCountIncrement;
    return MakeStats(pipeline_decoded_frames_, pipeline_dropped_frames_,
                     pipeline_power_efficient_frames_, pipeline_framerate_);
  }

  // Peek at what MakeAdvancingDecodeStats() will return next without advancing
  // the tracked counts.
  media::PipelineStatistics PeekNextDecodeStats() const {
    return MakeStats(
        pipeline_decoded_frames_ + kDecodeCountIncrement,
        pipeline_dropped_frames_ + kDroppedCountIncrement,
        pipeline_power_efficient_frames_ + kDecodePowerEfficientCountIncrement,
        pipeline_framerate_);
  }

 protected:
  // Indicates expectations about rate of timer firing during FPS stabilization.
  enum FpsStabiliaztionSpeed {
    // Timer is expected to fire at rate of 3 * last observed average frame
    // duration. This is the default for framerate detection.
    FAST_STABILIZE_FPS,
    // Timer is expected to fire at a rate of kRecordingInterval. This will
    // occur
    // when decode progress stalls during framerate detection.
    SLOW_STABILIZE_FPS,
  };

  // Return mojo::PendingRemote<media::mojom::VideoDecodeStatsRecorder>
  // after binding the RecordInterceptor to the receiver for a
  // VideoDecodeStatsRecorder. The interceptor serves as a mock recorder to
  // verify reporter/recorder interactions.
  mojo::PendingRemote<media::mojom::VideoDecodeStatsRecorder>
  SetupRecordInterceptor(raw_ptr<RecordInterceptor>* interceptor_ptr) {
    // Capture a the interceptor pointer for verifying recorder calls. Lifetime
    // will be managed by the |recorder_remote|.
    auto interceptor = std::make_unique<RecordInterceptor>();
    *interceptor_ptr = interceptor.get();
    mojo::PendingRemote<media::mojom::VideoDecodeStatsRecorder> recorder_remote;
    mojo::MakeSelfOwnedReceiver(
        std::move(interceptor),
        recorder_remote.InitWithNewPipeAndPassReceiver());
    EXPECT_TRUE(recorder_remote.is_valid());
    return recorder_remote;
  }

  // Inject mock objects and create a new |reporter_| to test.
  void MakeReporter(
      media::VideoCodecProfile profile = kDefaultProfile,
      const gfx::Size& natural_size = gfx::Size(kDefaultWidth, kDefaultHeight),
      const std::optional<media::CdmConfig> cdm_config = kDefaultCdmConfig) {
    reporter_ = std::make_unique<VideoDecodeStatsReporter>(
        SetupRecordInterceptor(&interceptor_),
        base::BindRepeating(&VideoDecodeStatsReporterTest::GetPipelineStatsCB,
                            base::Unretained(this)),
        profile, natural_size, cdm_config,
        task_environment_.GetMainThreadTaskRunner(),
        task_environment_.GetMockTickClock());
  }

  // Fast forward the task runner (and associated tick clock) by |milliseconds|.
  void FastForward(base::TimeDelta delta) {
    task_environment_.FastForwardBy(delta);
  }

  bool ShouldBeReporting() const { return reporter_->ShouldBeReporting(); }

  base::TimeDelta CurrentStatsCbInterval() const {
    return reporter_->stats_cb_timer_.GetCurrentDelay();
  }

  int CurrentStableFpsSamples() const {
    return reporter_->num_stable_fps_samples_;
  }

  // Call at the start of tests to stabilize framerate.
  // Preconditions:
  //  1) Reporter should not already be in playing state
  //  2) Playing should unblock the reporter to begin reporting (e.g. not in
  //     hidden state)
  //  3) No progress made yet toward stabilizing framerate.
  void StartPlayingAndStabilizeFramerate(
      media::VideoCodecProfile expected_profile = kDefaultProfile,
      gfx::Size expected_natural_size = gfx::Size(kDefaultWidth,
                                                  kDefaultHeight),
      int expected_fps = kDefaultFps,
      std::string expected_key_system = kDefaultKeySystem,
      bool expected_use_hw_secure_codecs = kDefaultUseHwSecureCodecs) {
    DCHECK(!reporter_->is_playing_);
    DCHECK_EQ(reporter_->num_stable_fps_samples_, 0);

    // Setup stats callback to provide steadily advancing decode stats with a
    // constant framerate.
    ON_CALL(*this, GetPipelineStatsCB())
        .WillByDefault(Invoke(
            this, &VideoDecodeStatsReporterTest::MakeAdvancingDecodeStats));

    // On playing should start timer at recording interval. Expect first stats
    // CB when that interval has elapsed.
    reporter_->OnPlaying();
    DCHECK(ShouldBeReporting());
    EXPECT_CALL(*this, GetPipelineStatsCB());
    FastForward(kRecordingInterval);

    StabilizeFramerateAndStartNewRecord(expected_profile, expected_natural_size,
                                        expected_fps, expected_key_system,
                                        expected_use_hw_secure_codecs);
  }

  // Call just after detecting a change to framerate. |expected_profile|,
  // |expected_natural_size|, and |expected_fps| will be verified against
  // intercepted call to StartNewRecord(...) once the framerate is stabilized.
  // |fps_timer_speed| indicates the expected timer interval to be used during
  // stabilization (see FpsStabiliaztionSpeed definition).
  // Preconditions:
  //  1. Do not call if framerate already stable (know what you're testing).
  //  2. Only call with GetPipelineStatsCB configured to return
  //     progressing decode stats with a steady framerate.
  void StabilizeFramerateAndStartNewRecord(
      media::VideoCodecProfile expected_profile,
      gfx::Size expected_natural_size,
      int expected_fps,
      std::string expected_key_system,
      bool expected_use_hw_secure_codecs,
      FpsStabiliaztionSpeed fps_timer_speed = FAST_STABILIZE_FPS) {
    ASSERT_TRUE(ShouldBeReporting());

    base::TimeDelta last_frame_duration = media::kNoTimestamp;
    uint32_t last_decoded_frames = 0;

    while (CurrentStableFpsSamples() < kRequiredStableFpsSamples) {
      media::PipelineStatistics next_stats = PeekNextDecodeStats();

      // Sanity check that the stats callback is progressing decode.
      DCHECK_GT(next_stats.video_frames_decoded, last_decoded_frames);
      last_decoded_frames = next_stats.video_frames_decoded;

      // Sanity check that the stats callback is providing steady fps.
      if (last_frame_duration != media::kNoTimestamp) {
        DCHECK_EQ(next_stats.video_frame_duration_average, last_frame_duration);
      }
      last_frame_duration = next_stats.video_frame_duration_average;

      // The final iteration stabilizes framerate and starts a new record.
      if (CurrentStableFpsSamples() == kRequiredStableFpsSamples - 1) {
        EXPECT_CALL(*interceptor_,
                    MockStartNewRecord(expected_profile, expected_natural_size,
                                       expected_fps, expected_key_system,
                                       expected_use_hw_secure_codecs));
      }

      if (fps_timer_speed == FAST_STABILIZE_FPS) {
        // Generally FPS is stabilized with a timer of ~3x the average frame
        // duration.
        base::TimeDelta frame_druation =
            base::Seconds(1.0 / pipeline_framerate_);
        EXPECT_EQ(CurrentStatsCbInterval(), frame_druation * 3);
      } else {
        // If the playback is struggling we will do it more slowly to avoid
        // firing high frequency timers indefinitely. Store constant as a local
        // to workaround linking confusion.
        DCHECK_EQ(fps_timer_speed, SLOW_STABILIZE_FPS);

        // fixme
        EXPECT_EQ(CurrentStatsCbInterval(), kRecordingInterval);
      }

      EXPECT_CALL(*this, GetPipelineStatsCB());
      FastForward(CurrentStatsCbInterval());
    }
  }

  // Advances the task runner by a single recording interval and verifies that
  // the record is updated. The values provided to UpdateRecord(...)
  // should match values from PeekNextDecodeStates(...), minus the offsets of
  // |decoded_frames_offset|, |dropped_frames_offset| and
  // |decoded_power_efficient_offset|.
  // Preconditions:
  // - Should only be called during regular reporting (framerate stable,
  //   not in background, not paused).
  void AdvanceTimeAndVerifyRecordUpdate(int decoded_frames_offset,
                                        int dropped_frames_offset,
                                        int decoded_power_efficient_offset) {
    DCHECK(ShouldBeReporting());

    // Record updates should always occur at recording interval. Store to local
    // variable to workaround linker confusion with test macros.
    EXPECT_EQ(kRecordingInterval, CurrentStatsCbInterval());

    media::PipelineStatistics next_stats = PeekNextDecodeStats();

    // Decode stats must be advancing for record updates to be expected. Dropped
    // frames should at least not move backward.
    EXPECT_GT(next_stats.video_frames_decoded, pipeline_decoded_frames_);
    EXPECT_GT(next_stats.video_frames_decoded_power_efficient,
              pipeline_power_efficient_frames_);
    EXPECT_GE(next_stats.video_frames_dropped, pipeline_dropped_frames_);

    // Verify that UpdateRecord calls come at the recording interval with
    // correct values.
    EXPECT_CALL(*this, GetPipelineStatsCB());
    EXPECT_CALL(*interceptor_,
                MockUpdateRecord(
                    next_stats.video_frames_decoded - decoded_frames_offset,
                    next_stats.video_frames_dropped - dropped_frames_offset,
                    next_stats.video_frames_decoded_power_efficient -
                        decoded_power_efficient_offset));
    FastForward(kRecordingInterval);
    testing::Mock::VerifyAndClearExpectations(this);
    testing::Mock::VerifyAndClearExpectations(interceptor_);
  }

  // Injected callback for fetching statistics. Each test will manage
  // expectations and return behavior.
  MOCK_METHOD0(GetPipelineStatsCB, media::PipelineStatistics());

  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  // These track the last values returned by MakeAdvancingDecodeStats(). See
  // SetUp() for initialization.
  uint32_t pipeline_decoded_frames_;
  uint32_t pipeline_dropped_frames_;
  uint32_t pipeline_power_efficient_frames_;
  double pipeline_framerate_;

  // Placed as a class member to avoid static initialization costs.
  const gfx::Size kDefaultSize_;

  // Points to the interceptor that acts as a VideoDecodeStatsRecorder. The
  // object is owned by mojo::Remote<VideoDecodeStatsRecorder>, which is itself
  // owned by |reporter_|.
  raw_ptr<RecordInterceptor> interceptor_ = nullptr;

  // The VideoDecodeStatsReporter being tested.
  std::unique_ptr<VideoDecodeStatsReporter> reporter_;

  // Redefined constants in fixture for easy access from tests. See
  // video_decode_stats_reporter.h for documentation.
  static const base::TimeDelta kRecordingInterval;
  static const base::TimeDelta kTinyFpsWindowDuration;
  static const int kRequiredStableFpsSamples =
      VideoDecodeStatsReporter::kRequiredStableFpsSamples;
  static const int kMaxUnstableFpsChanges =
      VideoDecodeStatsReporter::kMaxUnstableFpsChanges;
  static const int kMaxTinyFpsWindows =
      VideoDecodeStatsReporter::kMaxTinyFpsWindows;
};

const base::TimeDelta VideoDecodeStatsReporterTest::kRecordingInterval =
    base::Milliseconds(VideoDecodeStatsReporter::kRecordingIntervalMs);
const base::TimeDelta VideoDecodeStatsReporterTest::kTinyFpsWindowDuration =
    base::Milliseconds(VideoDecodeStatsReporter::kTinyFpsWindowMs);

TEST_F(VideoDecodeStatsReporterTest, RecordWhilePlaying) {
  StartPlayingAndStabilizeFramerate();

  // Framerate is now stable! Recorded stats should be offset by the values
  // last provided to GetPipelineStatsCB.
  uint32_t decoded_offset = pipeline_decoded_frames_;
  uint32_t dropped_offset = pipeline_dropped_frames_;
  uint32_t decoded_power_efficient_offset = pipeline_power_efficient_frames_;

  // Verify that UpdateRecord calls come at the recording interval with
  // correct values.
  AdvanceTimeAndVerifyRecordUpdate(decoded_offset, dropped_offset,
                                   decoded_power_efficient_offset);

  // Once more for good measure.
  AdvanceTimeAndVerifyRecordUpdate(decoded_offset, dropped_offset,
                                   decoded_power_efficient_offset);
}

TEST_F(VideoDecodeStatsReporterTest, RecordingStopsWhenPaused) {
  StartPlayingAndStabilizeFramerate();

  // Framerate is now stable! Recorded stats should be offset by the values
  // last provided to GetPipelineStatsCB.
  uint32_t decoded_offset = pipeline_decoded_frames_;
  uint32_t dropped_offset = pipeline_dropped_frames_;
  uint32_t decoded_power_efficient_offset = pipeline_power_efficient_frames_;

  AdvanceTimeAndVerifyRecordUpdate(decoded_offset, dropped_offset,
                                   decoded_power_efficient_offset);

  // When paused, expect no stats callbacks and no record updates.
  reporter_->OnPaused();
  EXPECT_FALSE(ShouldBeReporting());
  EXPECT_CALL(*this, GetPipelineStatsCB()).Times(0);
  EXPECT_CALL(*interceptor_, MockUpdateRecord(_, _, _)).Times(0);
  // Advance a few recording intervals just to be sure.
  FastForward(kRecordingInterval * 3);

  // Verify callbacks and record updates resume when playing again. No changes
  // to the stream during pause, so no need to re-stabilize framerate. Offsets
  // for stats count are still valid.
  reporter_->OnPlaying();
  AdvanceTimeAndVerifyRecordUpdate(decoded_offset, dropped_offset,
                                   decoded_power_efficient_offset);
}

TEST_F(VideoDecodeStatsReporterTest, RecordingStopsWhenHidden) {
  StartPlayingAndStabilizeFramerate();

  // Framerate is now stable! Recorded stats should be offset by the values
  // last provided to GetPipelineStatsCB.
  uint32_t decoded_offset = pipeline_decoded_frames_;
  uint32_t dropped_offset = pipeline_dropped_frames_;
  uint32_t decoded_power_efficient_offset = pipeline_power_efficient_frames_;

  AdvanceTimeAndVerifyRecordUpdate(decoded_offset, dropped_offset,
                                   decoded_power_efficient_offset);

  // When hidden, expect no stats callbacks and no record updates.
  reporter_->OnHidden();
  EXPECT_FALSE(ShouldBeReporting());
  EXPECT_CALL(*this, GetPipelineStatsCB()).Times(0);
  EXPECT_CALL(*interceptor_, MockUpdateRecord(_, _, _)).Times(0);
  // Advance a few recording intervals just to be sure.
  FastForward(kRecordingInterval * 3);

  // Verify updates resume when visible again. Dropped frame stats are not valid
  // while hidden, so expect a new record to begin. GetPipelineStatsCB will be
  // called to update offsets to ignore stats while hidden.
  EXPECT_CALL(*this, GetPipelineStatsCB());
  EXPECT_CALL(*interceptor_,
              MockStartNewRecord(kDefaultProfile, kDefaultSize_, kDefaultFps,
                                 kDefaultKeySystem, kDefaultUseHwSecureCodecs));
  reporter_->OnShown();

  // Update offsets for new record and verify updates resume as time advances.
  decoded_offset = pipeline_decoded_frames_;
  dropped_offset = pipeline_dropped_frames_;
  decoded_power_efficient_offset = pipeline_power_efficient_frames_;
  AdvanceTimeAndVerifyRecordUpdate(decoded_offset, dropped_offset,
                                   decoded_power_efficient_offset);
}

TEST_F(VideoDecodeStatsReporterTest, RecordingStopsWhenNoDecodeProgress) {
  StartPlayingAndStabilizeFramerate();

  // Framerate is now stable! Recorded stats should be offset by the values
  // last provided to GetPipelineStatsCB.
  uint32_t decoded_offset = pipeline_decoded_frames_;
  uint32_t dropped_offset = pipeline_dropped_frames_;
  uint32_t decoded_power_efficient_offset = pipeline_power_efficient_frames_;

  AdvanceTimeAndVerifyRecordUpdate(decoded_offset, dropped_offset,
                                   decoded_power_efficient_offset);

  // Freeze decode stats at current values, simulating network underflow.
  ON_CALL(*this, GetPipelineStatsCB())
      .WillByDefault(Return(
          MakeStats(pipeline_decoded_frames_, pipeline_dropped_frames_,
                    pipeline_power_efficient_frames_, pipeline_framerate_)));

  // Verify record updates stop while decode is not progressing. Fast forward
  // through several recording intervals to be sure we never call UpdateRecord.
  EXPECT_CALL(*this, GetPipelineStatsCB()).Times(3);
  EXPECT_CALL(*interceptor_, MockUpdateRecord(_, _, _)).Times(0);
  FastForward(kRecordingInterval * 3);

  // Resume progressing decode!
  ON_CALL(*this, GetPipelineStatsCB())
      .WillByDefault(Invoke(
          this, &VideoDecodeStatsReporterTest::MakeAdvancingDecodeStats));

  // Verify record updates resume.
  AdvanceTimeAndVerifyRecordUpdate(decoded_offset, dropped_offset,
                                   decoded_power_efficient_offset);
}

TEST_F(VideoDecodeStatsReporterTest, NewRecordStartsForFpsChange) {
  StartPlayingAndStabilizeFramerate();

  // Framerate is now stable! Recorded stats should be offset by the values
  // last provided to GetPipelineStatsCB.
  uint32_t decoded_offset = pipeline_decoded_frames_;
  uint32_t dropped_offset = pipeline_dropped_frames_;
  uint32_t decoded_power_efficient_offset = pipeline_power_efficient_frames_;

  AdvanceTimeAndVerifyRecordUpdate(decoded_offset, dropped_offset,
                                   decoded_power_efficient_offset);

  // Change FPS to 2x current rate. Future calls to GetPipelineStats will
  // use this to compute frame duration.
  EXPECT_EQ(pipeline_framerate_, static_cast<uint32_t>(kDefaultFps));
  pipeline_framerate_ *= 2;

  // Next stats update will not cause a record update. It will instead begin
  // detection of the new framerate.
  EXPECT_CALL(*this, GetPipelineStatsCB());
  EXPECT_CALL(*interceptor_, MockUpdateRecord(_, _, _)).Times(0);
  FastForward(kRecordingInterval);

  // A new record is started with the latest frames per second as soon as the
  // framerate is confirmed (re-stabilized).
  StabilizeFramerateAndStartNewRecord(kDefaultProfile, kDefaultSize_,
                                      kDefaultFps * 2, kDefaultKeySystem,
                                      kDefaultUseHwSecureCodecs);

  // Offsets should be adjusted so the new record starts at zero.
  decoded_offset = pipeline_decoded_frames_;
  dropped_offset = pipeline_dropped_frames_;
  decoded_power_efficient_offset = pipeline_power_efficient_frames_;

  // Stats callbacks and record updates should proceed as usual.
  AdvanceTimeAndVerifyRecordUpdate(decoded_offset, dropped_offset,
                                   decoded_power_efficient_offset);
}

TEST_F(VideoDecodeStatsReporterTest, FpsStabilizationFailed) {
  // Setup stats callback to provide steadily advancing decode stats with a
  // constant framerate.
  ON_CALL(*this, GetPipelineStatsCB())
      .WillByDefault(Invoke(
          this, &VideoDecodeStatsReporterTest::MakeAdvancingDecodeStats));

  // On playing should start timer.
  reporter_->OnPlaying();
  EXPECT_TRUE(ShouldBeReporting());

  // OnPlaying starts the timer at the recording interval. Expect first stats
  // CB when that interval has elapsed. This stats callback provides the first
  // fps sample.
  EXPECT_CALL(*this, GetPipelineStatsCB());

  // We should not start nor update a record while failing to detect fps.
  EXPECT_CALL(*interceptor_, MockUpdateRecord(_, _, _)).Times(0);
  EXPECT_CALL(*interceptor_, MockStartNewRecord(_, _, _, _, _)).Times(0);
  FastForward(kRecordingInterval);
  int num_fps_samples = 1;

  // With FPS stabilization in-progress, keep alternating framerate to thwart
  // stabilization.
  for (; num_fps_samples < kMaxUnstableFpsChanges; num_fps_samples++) {
    pipeline_framerate_ =
        (pipeline_framerate_ == kDefaultFps) ? 2 * kDefaultFps : kDefaultFps;
    EXPECT_CALL(*this, GetPipelineStatsCB());
    FastForward(CurrentStatsCbInterval());
  }

  // Stabilization has now failed, so fast forwarding  by any amount will not
  // trigger new stats update callbacks.
  EXPECT_CALL(*this, GetPipelineStatsCB()).Times(0);
  FastForward(kRecordingInterval * 10);

  // Pausing then playing does not kickstart reporting. We assume framerate is
  // still variable.
  reporter_->OnPaused();
  reporter_->OnPlaying();
  FastForward(kRecordingInterval * 10);

  // Hidden then shown does not kickstart reporting. We assume framerate is
  // still variable.
  reporter_->OnHidden();
  reporter_->OnShown();
  FastForward(kRecordingInterval * 10);
}

TEST_F(VideoDecodeStatsReporterTest, FpsStabilizationFailed_TinyWindows) {
  uint32_t decoded_offset = 0;
  uint32_t dropped_offset = 0;
  uint32_t decoded_power_efficient_offset = 0;

  // Setup stats callback to provide steadily advancing decode stats.
  ON_CALL(*this, GetPipelineStatsCB())
      .WillByDefault(Invoke(
          this, &VideoDecodeStatsReporterTest::MakeAdvancingDecodeStats));

  // On playing should start timer at recording interval. Expect first stats
  // CB when that interval has elapsed.
  reporter_->OnPlaying();
  DCHECK(ShouldBeReporting());
  EXPECT_CALL(*this, GetPipelineStatsCB());
  FastForward(kRecordingInterval);

  // Repeatedly stabilize, then change the FPS after single record updates to
  // create tiny windows.
  for (int i = 0; i < kMaxTinyFpsWindows; i++) {
    StabilizeFramerateAndStartNewRecord(kDefaultProfile, kDefaultSize_,
                                        pipeline_framerate_, kDefaultKeySystem,
                                        kDefaultUseHwSecureCodecs);

    // Framerate is now stable! Recorded stats should be offset by the values
    // last provided to GetPipelineStatsCB.
    decoded_offset = pipeline_decoded_frames_;
    dropped_offset = pipeline_dropped_frames_;
    decoded_power_efficient_offset = pipeline_power_efficient_frames_;

    AdvanceTimeAndVerifyRecordUpdate(decoded_offset, dropped_offset,
                                     decoded_power_efficient_offset);

    // Changing the framerate and fast forward to detect the change.
    pipeline_framerate_ =
        (pipeline_framerate_ == kDefaultFps) ? 2 * kDefaultFps : kDefaultFps;
    EXPECT_CALL(*this, GetPipelineStatsCB());
    FastForward(kRecordingInterval);
  }

  // Verify no further stats updates are made because we've hit the maximum
  // number of tiny framerate windows.
  EXPECT_CALL(*this, GetPipelineStatsCB()).Times(0);
  EXPECT_CALL(*interceptor_, MockUpdateRecord(_, _, _)).Times(0);
  FastForward(kRecordingInterval);

  // Pausing then playing does not kickstart reporting. We assume framerate is
  // still variable.
  reporter_->OnPaused();
  reporter_->OnPlaying();
  FastForward(kRecordingInterval * 10);

  // Hidden then shown does not kickstart reporting. We assume framerate is
  // still variable.
  reporter_->OnHidden();
  reporter_->OnShown();
  FastForward(kRecordingInterval * 10);
}

TEST_F(VideoDecodeStatsReporterTest, ThrottleFpsTimerIfNoDecodeProgress) {
  // Setup stats callback to provide steadily advancing decode stats with a
  // constant framerate.
  ON_CALL(*this, GetPipelineStatsCB())
      .WillByDefault(Invoke(
          this, &VideoDecodeStatsReporterTest::MakeAdvancingDecodeStats));

  // On playing should start timer at recording interval.
  reporter_->OnPlaying();
  EXPECT_TRUE(ShouldBeReporting());

  // OnPlaying starts the timer at the recording interval. Expect first stats
  // CB when that interval has elapsed. This stats callback provides the first
  // fps sample.
  EXPECT_CALL(*this, GetPipelineStatsCB());
  FastForward(kRecordingInterval);
  int stable_fps_samples = 1;

  // Now advance time to make it half way through framerate stabilization.
  base::TimeDelta frame_duration = base::Seconds(1.0 / pipeline_framerate_);
  for (; stable_fps_samples < kRequiredStableFpsSamples / 2;
       stable_fps_samples++) {
    // The timer runs at 3x the frame duration when detecting framerate to
    // quickly stabilize.
    EXPECT_CALL(*this, GetPipelineStatsCB());
    FastForward(frame_duration * 3);
  }

  // With stabilization still ongoing, freeze decode progress by repeatedly
  // returning the same stats from before.
  ON_CALL(*this, GetPipelineStatsCB())
      .WillByDefault(Return(
          MakeStats(pipeline_decoded_frames_, pipeline_dropped_frames_,
                    pipeline_power_efficient_frames_, pipeline_framerate_)));

  // Advance another fps detection interval to detect that no progress was made.
  // Verify this decreases timer frequency to standard reporting interval.
  EXPECT_LT(CurrentStatsCbInterval(), kRecordingInterval);
  EXPECT_CALL(*this, GetPipelineStatsCB());
  FastForward(frame_duration * 3);
  EXPECT_EQ(CurrentStatsCbInterval(), kRecordingInterval);

  // Verify stats updates continue to come in at recording interval. Verify no
  // calls to UpdateRecord because decode progress is still frozen. Fast forward
  // through several recording intervals to be sure nothing changes.
  EXPECT_CALL(*this, GetPipelineStatsCB()).Times(3);
  EXPECT_CALL(*interceptor_, MockUpdateRecord(_, _, _)).Times(0);
  FastForward(kRecordingInterval * 3);

  // Un-freeze decode stats!
  ON_CALL(*this, GetPipelineStatsCB())
      .WillByDefault(Invoke(
          this, &VideoDecodeStatsReporterTest::MakeAdvancingDecodeStats));

  // Finish framerate stabilization with a slower timer frequency. The slower
  // timer is used to avoid firing high frequency timers indefinitely for
  // machines/networks that are struggling to keep up.
  StabilizeFramerateAndStartNewRecord(
      kDefaultProfile, kDefaultSize_, kDefaultFps, kDefaultKeySystem,
      kDefaultUseHwSecureCodecs, SLOW_STABILIZE_FPS);

  // Framerate is now stable! Recorded stats should be offset by the values
  // last provided to GetPipelineStatsCB.
  uint32_t decoded_offset = pipeline_decoded_frames_;
  uint32_t dropped_offset = pipeline_dropped_frames_;
  uint32_t decoded_power_efficient_offset = pipeline_power_efficient_frames_;

  AdvanceTimeAndVerifyRecordUpdate(decoded_offset, dropped_offset,
                                   decoded_power_efficient_offset);
}


TEST_F(VideoDecodeStatsReporterTest, FpsBucketing) {
  StartPlayingAndStabilizeFramerate();
  EXPECT_EQ(kDefaultFps, pipeline_framerate_);

  // Framerate is now stable! Recorded stats should be offset by the values
  // last provided to GetPipelineStatsCB.
  uint32_t decoded_offset = pipeline_decoded_frames_;
  uint32_t dropped_offset = pipeline_dropped_frames_;
  uint32_t decoded_power_efficient_offset = pipeline_power_efficient_frames_;

  // Verify that UpdateRecord calls come at the recording interval with
  // correct values.
  AdvanceTimeAndVerifyRecordUpdate(decoded_offset, dropped_offset,
                                   decoded_power_efficient_offset);

  // Small changes to framerate should not trigger a new record.
  pipeline_framerate_ = kDefaultFps + .5;
  EXPECT_CALL(*interceptor_, MockStartNewRecord(_, _, _, _, _)).Times(0);
  AdvanceTimeAndVerifyRecordUpdate(decoded_offset, dropped_offset,
                                   decoded_power_efficient_offset);

  // Small changes in the other direction should also not trigger a new record.
  pipeline_framerate_ = kDefaultFps - .5;
  EXPECT_CALL(*interceptor_, MockStartNewRecord(_, _, _, _, _)).Times(0);
  AdvanceTimeAndVerifyRecordUpdate(decoded_offset, dropped_offset,
                                   decoded_power_efficient_offset);

  // Big changes in framerate should trigger a new record.
  pipeline_framerate_ = kDefaultFps * 2;

  // Fast forward by one interval to detect framerate change.
  EXPECT_CALL(*this, GetPipelineStatsCB());
  FastForward(kRecordingInterval);

  // Stabilize new framerate.
  StabilizeFramerateAndStartNewRecord(kDefaultProfile, kDefaultSize_,
                                      kDefaultFps * 2, kDefaultKeySystem,
                                      kDefaultUseHwSecureCodecs);

  // Update offsets for new record and verify recording.
  decoded_offset = pipeline_decoded_frames_;
  dropped_offset = pipeline_dropped_frames_;
  decoded_power_efficient_offset = pipeline_power_efficient_frames_;
  AdvanceTimeAndVerifyRecordUpdate(decoded_offset, dropped_offset,
                                   decoded_power_efficient_offset);

  // Whacky framerates should be bucketed to a more common nearby value.
  pipeline_framerate_ = 123.4;

  // Fast forward by one interval to detect framerate change.
  EXPECT_CALL(*this, GetPipelineStatsCB());
  FastForward(kRecordingInterval);

  // Verify new record uses bucketed framerate.
  int bucketed_fps = media::GetFpsBucket(pipeline_framerate_);
  EXPECT_NE(bucketed_fps, pipeline_framerate_);
  StabilizeFramerateAndStartNewRecord(kDefaultProfile, kDefaultSize_,
                                      bucketed_fps, kDefaultKeySystem,
                                      kDefaultUseHwSecureCodecs);

  // Update offsets for new record and verify recording.
  decoded_offset = pipeline_decoded_frames_;
  dropped_offset = pipeline_dropped_frames_;
  decoded_power_efficient_offset = pipeline_power_efficient_frames_;
  AdvanceTimeAndVerifyRecordUpdate(decoded_offset, dropped_offset,
                                   decoded_power_efficient_offset);
}

TEST_F(VideoDecodeStatsReporterTest, ResolutionBucketing) {
  MakeReporter();
  EXPECT_TRUE(reporter_->MatchesBucketedNaturalSize(kDefaultSize_));

  // Note that our current size fits perfectly into known buckets...
  EXPECT_EQ(media::GetSizeBucket(kDefaultSize_), kDefaultSize_);

  // A slightly smaller size should fall into the same size bucket as before.
  gfx::Size slightly_smaller_size(kDefaultWidth - 2, kDefaultHeight - 2);
  EXPECT_TRUE(reporter_->MatchesBucketedNaturalSize(slightly_smaller_size));

  // Since the original size perfectly fits a known size bucket, any small
  // increase should cause the next larger bucket should be chosen. This is done
  // to surface cut off resolutions in hardware decoders. HW acceleration can be
  // critical to smooth decode at higher resolutions.
  gfx::Size slightly_larger_size(kDefaultWidth + 1, kDefaultHeight + 1);
  EXPECT_FALSE(reporter_->MatchesBucketedNaturalSize(slightly_larger_size));

  MakeReporter(kDefaultProfile, slightly_larger_size);
  EXPECT_TRUE(reporter_->MatchesBucketedNaturalSize(slightly_larger_size));

  // With |slightly_larger_size| describing the bottom of its bucket, we should
  // have of room to increase a little further within this bucket, without
  // triggering the start of a new record.
  slightly_larger_size = gfx::Size(slightly_larger_size.width() + 1,
                                   slightly_larger_size.height() + 1);
  EXPECT_TRUE(reporter_->MatchesBucketedNaturalSize(slightly_larger_size));

  // Big changes in resolution should fall into a different bucket
  gfx::Size big_resolution(kDefaultWidth * 2, kDefaultHeight * 2);
  EXPECT_FALSE(reporter_->MatchesBucketedNaturalSize(big_resolution));
}

TEST_F(VideoDecodeStatsReporterTest, ResolutionTooSmall) {
  // Initialize the natural size to something tiny.
  gfx::Size tiny_size(10, 15);
  MakeReporter(kDefaultProfile, tiny_size);

  // Tiny size should "bucket" to empty.
  EXPECT_TRUE(reporter_->MatchesBucketedNaturalSize(gfx::Size()));

  // Verify reporting has stopped because because resolution is so small. Fast
  // forward through several intervals to verify no callbacks are made while the
  // tiny size is in effect.
  EXPECT_FALSE(ShouldBeReporting());
  EXPECT_CALL(*this, GetPipelineStatsCB()).Times(0);
  EXPECT_CALL(*interceptor_, MockUpdateRecord(_, _, _)).Times(0);
  FastForward(kRecordingInterval * 3);

  // Change the size to something small, but reasonable.
  const gfx::Size small_size(75, 75);
  MakeReporter(kDefaultProfile, small_size);

  // Stabilize new framerate and verify record updates come with new offsets.
  StartPlayingAndStabilizeFramerate(kDefaultProfile,
                                    media::GetSizeBucket(small_size));

  // Framerate is now stable! Recorded stats should be offset by the values
  // last provided to GetPipelineStatsCB.
  uint32_t decoded_offset = pipeline_decoded_frames_;
  uint32_t dropped_offset = pipeline_dropped_frames_;
  uint32_t decoded_power_efficient_offset = pipeline_power_efficient_frames_;
  AdvanceTimeAndVerifyRecordUpdate(decoded_offset, dropped_offset,
                                   decoded_power_efficient_offset);
}

TEST_F(VideoDecodeStatsReporterTest, VaryEmeProperties) {
  // Readability helpers
  const gfx::Size kDefaultSize(kDefaultWidth, kDefaultHeight);
  const char kEmptyKeySystem[] = "";
  const bool kNonDefaultHwSecureCodecs = !kDefaultUseHwSecureCodecs;
  const char kFooKeySystem[] = "fookeysytem";
  const media::CdmConfig kNonDefaultCdmConfig = {kFooKeySystem, false, false,
                                                 kNonDefaultHwSecureCodecs};

  // Make reporter with no EME properties.
  MakeReporter(kDefaultProfile, kDefaultSize, std::nullopt);
  // Verify the empty key system and non-default hw_secure_codecs.
  StartPlayingAndStabilizeFramerate(kDefaultProfile, kDefaultSize, kDefaultFps,
                                    kEmptyKeySystem, kNonDefaultHwSecureCodecs);

  // Make a new reporter with a non-default, non-empty key system.
  MakeReporter(kDefaultProfile, kDefaultSize, kNonDefaultCdmConfig);
  // Verify non-default key system
  StartPlayingAndStabilizeFramerate(kDefaultProfile, kDefaultSize, kDefaultFps,
                                    kFooKeySystem, kNonDefaultHwSecureCodecs);
}

TEST_F(VideoDecodeStatsReporterTest, SanitizeFrameCounts) {
  StartPlayingAndStabilizeFramerate();

  // Framerate is now stable! Recorded stats should be offset by the values
  // last provided to GetPipelineStatsCB.
  uint32_t decoded_offset = pipeline_decoded_frames_;
  uint32_t dropped_offset = pipeline_dropped_frames_;
  uint32_t decoded_power_efficient_offset = pipeline_power_efficient_frames_;

  // Verify that UpdateRecord calls come at the recording interval with
  // correct values.
  AdvanceTimeAndVerifyRecordUpdate(decoded_offset, dropped_offset,
                                   decoded_power_efficient_offset);

  // On next call for stats, advance decoded count a little and advance dropped
  // and power efficient counts beyond the decoded count.
  pipeline_decoded_frames_ += 10;
  pipeline_dropped_frames_ = pipeline_decoded_frames_ + 1;
  pipeline_power_efficient_frames_ = pipeline_decoded_frames_ + 2;
  EXPECT_CALL(*this, GetPipelineStatsCB())
      .WillOnce(Return(
          MakeStats(pipeline_decoded_frames_, pipeline_dropped_frames_,
                    pipeline_power_efficient_frames_, pipeline_framerate_)));

  // Expect that record update caps dropped and power efficient counts to the
  // offset decoded count.
  EXPECT_CALL(*interceptor_,
              MockUpdateRecord(pipeline_decoded_frames_ - decoded_offset,
                               pipeline_decoded_frames_ - decoded_offset,
                               pipeline_decoded_frames_ - decoded_offset));
  FastForward(kRecordingInterval);
  testing::Mock::VerifyAndClearExpectations(this);
  testing::Mock::VerifyAndClearExpectations(interceptor_);

  // Dropped and efficient counts should record correctly if subsequent updates
  // cease to exceed decoded frame count.
  pipeline_decoded_frames_ += 1000;
  EXPECT_CALL(*this, GetPipelineStatsCB())
      .WillOnce(Return(
          MakeStats(pipeline_decoded_frames_, pipeline_dropped_frames_,
                    pipeline_power_efficient_frames_, pipeline_framerate_)));

  EXPECT_CALL(*interceptor_,
              MockUpdateRecord(pipeline_decoded_frames_ - decoded_offset,
                               pipeline_dropped_frames_ - dropped_offset,
                               pipeline_power_efficient_frames_ -
                                   decoded_power_efficient_offset));
  FastForward(kRecordingInterval);
}

}  // namespace blink
```