Response: The user wants a summary of the functionality of the C++ unit test file `watch_time_reporter_unittest.cc`. I need to identify the main purpose of this file and how it achieves it.

Here's a breakdown of the file's functionality:

1. **Testing the `WatchTimeReporter` class:** The file contains numerous test cases for the `WatchTimeReporter` class.
2. **Verifying watch time tracking:** The tests check if the `WatchTimeReporter` correctly records the time spent watching media under various conditions.
3. **Simulating different playback states:** The tests simulate different playback states like playing, pausing, seeking, underflow, and changes in visibility (shown/hidden).
4. **Testing different media configurations:** The tests cover scenarios with and without audio and video.
5. **Checking interactions with other components:** The tests verify how the `WatchTimeReporter` interacts with components like `MediaMetricsProvider` and how it handles power state and native controls.
6. **Using mock objects:** The file uses Google Mock (`gmock`) to create mock objects for dependencies, enabling isolated testing.
7. **Defining helper macros:** The file defines macros like `EXPECT_WATCH_TIME` to simplify the assertion of expected watch time updates.
这是对 Chromium Blink 引擎中 `blink/renderer/platform/media/watch_time_reporter_unittest.cc` 文件功能的归纳：

**主要功能：**

该文件包含了对 `WatchTimeReporter` 类的单元测试。`WatchTimeReporter` 的主要职责是跟踪用户观看媒体（音频和/或视频）的时长，并将这些数据上报用于分析。这个单元测试文件的目的是验证 `WatchTimeReporter` 类在各种不同场景下的行为是否符合预期，确保其能够准确地记录和上报观看时长。

**具体功能点：**

1. **测试 `WatchTimeReporter` 的启用和禁用逻辑：**  验证在不同的媒体配置（是否有音频、是否有视频、视频尺寸是否足够大）下，`WatchTimeReporter` 是否正确地启动或停止计时。
2. **测试基本的观看时长记录：** 验证在正常播放情况下，`WatchTimeReporter` 是否能够记录观看时长，并根据音频和视频的存在，更新相应的统计键值（例如 `kAudioVideoAll`, `kVideoAll`, `kAudioAll` 等）。
3. **测试各种播放状态下的时长记录：**  模拟播放、暂停、缓冲（underflow）、seek 等操作，验证 `WatchTimeReporter` 在这些状态变化时，是否正确地停止、恢复或重置计时。
4. **测试后台播放时的时长记录：** 模拟页面被隐藏（进入后台）的情况，验证 `WatchTimeReporter` 是否能够记录后台播放时长，并使用不同的统计键值（例如 `kAudioVideoBackgroundAll`）。
5. **测试静音状态下的时长记录：** 模拟音频静音的情况，验证 `WatchTimeReporter` 是否能够记录静音状态下的观看时长，并使用特定的统计键值（例如 `kAudioVideoMutedAll`）。
6. **测试电源状态变化的影响：** 模拟设备电源状态（电池或交流电源）的切换，验证 `WatchTimeReporter` 是否能够根据电源状态分别记录观看时长，并使用不同的统计键值（例如 `kAudioVideoBattery`, `kAudioVideoAc`）。
7. **测试原生控件显示/隐藏的影响：** 模拟原生媒体控件的显示和隐藏，验证 `WatchTimeReporter` 是否能够根据控件状态分别记录观看时长。
8. **测试显示类型变化的影响：** 模拟显示类型（例如全屏、内联、画中画）的变化，验证 `WatchTimeReporter` 是否能够根据显示类型分别记录观看时长。
9. **测试 `MediaMetricsProvider` 的交互：**  验证 `WatchTimeReporter` 是否正确地与 `MediaMetricsProvider` 交互，通过 `WatchTimeRecorder` 上报观看时长数据。
10. **测试 `SecondaryPlaybackProperties` 的更新：** 验证当媒体的二级属性（例如编解码器、分辨率）发生变化时，`WatchTimeReporter` 是否能够正确处理。
11. **测试自动播放启动状态的记录：** 验证 `WatchTimeReporter` 是否能够记录播放是否由自动播放启动。
12. **测试 Underflow 事件的处理：** 验证 `WatchTimeReporter` 是否能够记录 Underflow 事件的发生次数和持续时间。
13. **测试视频解码统计信息的记录：** 验证 `WatchTimeReporter` 是否能够记录视频解码的帧数和丢帧数。

**与 JavaScript, HTML, CSS 的关系 (间接关系):**

该文件是 C++ 代码，直接与 JavaScript, HTML, CSS 没有直接的代码关系。然而，`WatchTimeReporter` 最终收集的数据是用于衡量用户在网页上观看媒体的行为，这与网页的呈现和用户交互密切相关。

*   **JavaScript:**  JavaScript 代码通常负责控制媒体元素的播放、暂停、seek 等操作，这些操作会触发 `WatchTimeReporter` 内部状态的变化，从而影响其记录的时长数据。例如，当 JavaScript 调用 `video.play()` 时，`WatchTimeReporter` 会开始计时。
*   **HTML:** HTML 中的 `<video>` 和 `<audio>` 标签定义了媒体元素，`WatchTimeReporter` 监控的是这些元素的播放行为。
*   **CSS:** CSS 可能会影响媒体元素的显示状态（例如是否全屏），这会触发 `WatchTimeReporter` 记录不同显示类型下的观看时长。

**逻辑推理 (假设输入与输出):**

假设输入：

*   用户在一个包含视频的网页上点击了“播放”按钮。
*   视频播放了 5 秒。
*   用户点击了“暂停”按钮。

预期输出（通过单元测试验证）：

*   `WatchTimeReporter` 会记录 5 秒的 `kAudioVideoAll`（假设有音频）。
*   如果页面在前台，还会记录 5 秒的 `kAudioVideoAc` (假设使用交流电源) 和 `kAudioVideoNativeControlsOff` (假设没有显示原生控件)。
*   如果视频尺寸足够大，还会记录 5 秒的 `kAudioVideoDisplayInline` (假设是内联播放)。

**用户或编程常见的使用错误 (通过测试避免):**

1. **错误地假设在所有情况下都会记录观看时长：**  `WatchTimeReporter` 有一些启动条件（例如视频尺寸），测试可以确保在不满足条件时不会错误地记录时长。
2. **在后台或静音状态下错误地计算前台或非静音时长：** 测试确保后台和静音状态的时长被记录到不同的指标中。
3. **未能正确处理播放状态的切换：**  测试确保在播放、暂停等状态切换时，计时器能够正确地启动和停止。
4. **在电源状态或显示类型变化时未能分别记录时长：** 测试确保 `WatchTimeReporter` 能够根据这些变化使用不同的统计键值进行记录。

**总结归纳 (第1部分功能):**

`blink/renderer/platform/media/watch_time_reporter_unittest.cc` 文件的主要功能是全面地测试 `WatchTimeReporter` 类在各种媒体播放场景下的行为，包括播放状态变化、后台播放、静音、电源状态变化、显示类型变化等，确保其能够准确、可靠地记录用户观看媒体的时长并上报相关数据。 这些测试用例覆盖了 `WatchTimeReporter` 的核心逻辑和各种边界情况，旨在预防和发现潜在的错误，保证媒体观看时长统计的准确性。

Prompt: 
```
这是目录为blink/renderer/platform/media/watch_time_reporter_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "media/base/mock_media_log.h"
#include "media/base/pipeline_status.h"
#include "media/base/test_helpers.h"
#include "media/base/watch_time_keys.h"
#include "media/mojo/mojom/media_metrics_provider.mojom.h"
#include "media/mojo/mojom/watch_time_recorder.mojom.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/media/display_type.h"
#include "third_party/blink/public/common/media/watch_time_component.h"
#include "third_party/blink/public/common/media/watch_time_reporter.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"

namespace blink {

using ::media::WatchTimeKey;
using ::testing::_;

constexpr gfx::Size kSizeTooSmall = gfx::Size(101, 101);
constexpr gfx::Size kSizeJustRight = gfx::Size(201, 201);

#define EXPECT_WATCH_TIME(key, value)                                          \
  do {                                                                         \
    EXPECT_CALL(                                                               \
        *this, OnWatchTimeUpdate((has_video_ && has_audio_)                    \
                                     ? WatchTimeKey::kAudioVideo##key          \
                                     : has_audio_ ? WatchTimeKey::kAudio##key  \
                                                  : WatchTimeKey::kVideo##key, \
                                 value))                                       \
        .RetiresOnSaturation();                                                \
  } while (0)

#define EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(key, value)                     \
  do {                                                                         \
    if (!has_video_ || !has_audio_)                                            \
      break;                                                                   \
    EXPECT_CALL(*this,                                                         \
                OnWatchTimeUpdate(WatchTimeKey::kAudioVideoMuted##key, value)) \
        .RetiresOnSaturation();                                                \
  } while (0)

#define EXPECT_WATCH_TIME_IF_VIDEO(key, value)                                \
  do {                                                                        \
    if (!has_video_)                                                          \
      break;                                                                  \
    EXPECT_CALL(*this,                                                        \
                OnWatchTimeUpdate(has_audio_ ? WatchTimeKey::kAudioVideo##key \
                                             : WatchTimeKey::kVideo##key,     \
                                  value))                                     \
        .RetiresOnSaturation();                                               \
  } while (0)

#define EXPECT_BACKGROUND_WATCH_TIME(key, value)                            \
  do {                                                                      \
    EXPECT_CALL(*this,                                                      \
                OnWatchTimeUpdate(                                          \
                    (has_video_ && has_audio_)                              \
                        ? WatchTimeKey::kAudioVideoBackground##key          \
                        : has_audio_ ? WatchTimeKey::kAudioBackground##key  \
                                     : WatchTimeKey::kVideoBackground##key, \
                    value))                                                 \
        .RetiresOnSaturation();                                             \
  } while (0)

#define EXPECT_WATCH_TIME_IF_AUDIO_VIDEO_MEDIAFOUNDATION(key, value)       \
  do {                                                                     \
    if (!has_video_ || !has_audio_)                                        \
      break;                                                               \
    EXPECT_CALL(*this,                                                     \
                OnWatchTimeUpdate(                                         \
                    WatchTimeKey::kAudioVideoMediaFoundation##key, value)) \
        .RetiresOnSaturation();                                            \
  } while (0)

#define EXPECT_WATCH_TIME_FINALIZED() \
  EXPECT_CALL(*this, OnWatchTimeFinalized()).RetiresOnSaturation();

// The following macros have .Times() values equal to the number of keys that a
// finalize event is expected to finalize.
#define EXPECT_POWER_WATCH_TIME_FINALIZED()       \
  EXPECT_CALL(*this, OnPowerWatchTimeFinalized()) \
      .Times(2)                                   \
      .RetiresOnSaturation();

#define EXPECT_CONTROLS_WATCH_TIME_FINALIZED()       \
  EXPECT_CALL(*this, OnControlsWatchTimeFinalized()) \
      .Times(2)                                      \
      .RetiresOnSaturation();

#define EXPECT_DISPLAY_WATCH_TIME_FINALIZED()       \
  EXPECT_CALL(*this, OnDisplayWatchTimeFinalized()) \
      .Times(3)                                     \
      .RetiresOnSaturation();

using WatchTimeReporterTestData = std::tuple<bool, bool>;
class WatchTimeReporterTest
    : public testing::TestWithParam<WatchTimeReporterTestData> {
 public:
  class WatchTimeInterceptor : public media::mojom::WatchTimeRecorder {
   public:
    WatchTimeInterceptor(WatchTimeReporterTest* parent) : parent_(parent) {}
    WatchTimeInterceptor(const WatchTimeInterceptor&) = delete;
    WatchTimeInterceptor& operator=(const WatchTimeInterceptor&) = delete;
    ~WatchTimeInterceptor() override = default;

    // mojom::WatchTimeRecorder implementation:
    void RecordWatchTime(WatchTimeKey key, base::TimeDelta value) override {
      parent_->OnWatchTimeUpdate(key, value);
    }

    void FinalizeWatchTime(
        const std::vector<WatchTimeKey>& watch_time_keys) override {
      if (watch_time_keys.empty()) {
        parent_->OnWatchTimeFinalized();
      } else {
        for (auto key : watch_time_keys) {
          switch (key) {
            case WatchTimeKey::kAudioBattery:
            case WatchTimeKey::kAudioAc:
            case WatchTimeKey::kAudioBackgroundBattery:
            case WatchTimeKey::kAudioBackgroundAc:
            case WatchTimeKey::kAudioVideoBattery:
            case WatchTimeKey::kAudioVideoAc:
            case WatchTimeKey::kAudioVideoMutedBattery:
            case WatchTimeKey::kAudioVideoMutedAc:
            case WatchTimeKey::kAudioVideoBackgroundBattery:
            case WatchTimeKey::kAudioVideoBackgroundAc:
            case WatchTimeKey::kVideoBattery:
            case WatchTimeKey::kVideoAc:
            case WatchTimeKey::kVideoBackgroundBattery:
            case WatchTimeKey::kVideoBackgroundAc:
              parent_->OnPowerWatchTimeFinalized();
              break;

            case WatchTimeKey::kAudioNativeControlsOn:
            case WatchTimeKey::kAudioNativeControlsOff:
            case WatchTimeKey::kAudioVideoNativeControlsOn:
            case WatchTimeKey::kAudioVideoNativeControlsOff:
            case WatchTimeKey::kAudioVideoMutedNativeControlsOn:
            case WatchTimeKey::kAudioVideoMutedNativeControlsOff:
            case WatchTimeKey::kVideoNativeControlsOn:
            case WatchTimeKey::kVideoNativeControlsOff:
              parent_->OnControlsWatchTimeFinalized();
              break;

            case WatchTimeKey::kAudioVideoDisplayFullscreen:
            case WatchTimeKey::kAudioVideoDisplayInline:
            case WatchTimeKey::kAudioVideoDisplayPictureInPicture:
            case WatchTimeKey::kAudioVideoMutedDisplayFullscreen:
            case WatchTimeKey::kAudioVideoMutedDisplayInline:
            case WatchTimeKey::kAudioVideoMutedDisplayPictureInPicture:
            case WatchTimeKey::kVideoDisplayFullscreen:
            case WatchTimeKey::kVideoDisplayInline:
            case WatchTimeKey::kVideoDisplayPictureInPicture:
              parent_->OnDisplayWatchTimeFinalized();
              break;

            case WatchTimeKey::kAudioAll:
            case WatchTimeKey::kAudioMse:
            case WatchTimeKey::kAudioEme:
            case WatchTimeKey::kAudioSrc:
            case WatchTimeKey::kAudioEmbeddedExperience:
            case WatchTimeKey::kAudioBackgroundAll:
            case WatchTimeKey::kAudioBackgroundMse:
            case WatchTimeKey::kAudioBackgroundEme:
            case WatchTimeKey::kAudioBackgroundSrc:
            case WatchTimeKey::kAudioBackgroundEmbeddedExperience:
            case WatchTimeKey::kAudioVideoAll:
            case WatchTimeKey::kAudioVideoMse:
            case WatchTimeKey::kAudioVideoEme:
            case WatchTimeKey::kAudioVideoSrc:
            case WatchTimeKey::kAudioVideoEmbeddedExperience:
            case WatchTimeKey::kAudioVideoMutedAll:
            case WatchTimeKey::kAudioVideoMutedMse:
            case WatchTimeKey::kAudioVideoMutedEme:
            case WatchTimeKey::kAudioVideoMutedSrc:
            case WatchTimeKey::kAudioVideoMutedEmbeddedExperience:
            case WatchTimeKey::kAudioVideoBackgroundAll:
            case WatchTimeKey::kAudioVideoBackgroundMse:
            case WatchTimeKey::kAudioVideoBackgroundEme:
            case WatchTimeKey::kAudioVideoBackgroundSrc:
            case WatchTimeKey::kAudioVideoBackgroundEmbeddedExperience:
            case WatchTimeKey::kVideoAll:
            case WatchTimeKey::kVideoMse:
            case WatchTimeKey::kVideoEme:
            case WatchTimeKey::kVideoSrc:
            case WatchTimeKey::kVideoEmbeddedExperience:
            case WatchTimeKey::kVideoBackgroundAll:
            case WatchTimeKey::kVideoBackgroundMse:
            case WatchTimeKey::kVideoBackgroundEme:
            case WatchTimeKey::kVideoBackgroundSrc:
            case WatchTimeKey::kVideoBackgroundEmbeddedExperience:
            case WatchTimeKey::kAudioVideoMediaFoundationAll:
            case WatchTimeKey::kAudioVideoMediaFoundationEme:
              // These keys do not support partial finalization.
              FAIL();
          };
        }
      }
    }

    void OnError(const media::PipelineStatus& status) override {
      parent_->OnError(status);
    }

    void UpdateSecondaryProperties(media::mojom::SecondaryPlaybackPropertiesPtr
                                       secondary_properties) override {
      parent_->OnUpdateSecondaryProperties(std::move(secondary_properties));
    }

    void UpdateUnderflowCount(int32_t count) override {
      parent_->OnUnderflowUpdate(count);
    }

    void UpdateUnderflowDuration(int32_t total_completed_count,
                                 base::TimeDelta total_duration) override {
      parent_->OnUnderflowDurationUpdate(total_completed_count, total_duration);
    }

    void SetAutoplayInitiated(bool value) override {
      parent_->OnSetAutoplayInitiated(value);
    }

    void OnDurationChanged(base::TimeDelta duration) override {
      parent_->OnDurationChanged(duration);
    }

    void UpdateVideoDecodeStats(uint32_t video_frames_decoded,
                                uint32_t video_frames_dropped) override {
      parent_->OnUpdateVideoDecodeStats(video_frames_decoded,
                                        video_frames_dropped);
    }

   private:
    raw_ptr<WatchTimeReporterTest> parent_;
  };

  class FakeMediaMetricsProvider : public media::mojom::MediaMetricsProvider {
   public:
    explicit FakeMediaMetricsProvider(WatchTimeReporterTest* parent)
        : parent_(parent) {}
    ~FakeMediaMetricsProvider() override {}

    // mojom::WatchTimeRecorderProvider implementation:
    void AcquireWatchTimeRecorder(
        media::mojom::PlaybackPropertiesPtr properties,
        mojo::PendingReceiver<media::mojom::WatchTimeRecorder> receiver)
        override {
      mojo::MakeSelfOwnedReceiver(
          std::make_unique<WatchTimeInterceptor>(parent_), std::move(receiver));
    }
    void AcquireVideoDecodeStatsRecorder(
        mojo::PendingReceiver<media::mojom::VideoDecodeStatsRecorder> receiver)
        override {
      FAIL();
    }
    void AcquireLearningTaskController(
        const std::string& taskName,
        mojo::PendingReceiver<media::learning::mojom::LearningTaskController>
            receiver) override {}
    void AcquirePlaybackEventsRecorder(
        mojo::PendingReceiver<media::mojom::PlaybackEventsRecorder> receiver)
        override {}
    void Initialize(bool is_mse,
                    media::mojom::MediaURLScheme url_scheme,
                    media::mojom::MediaStreamType media_stream_type) override {}
    void OnStarted(const media::PipelineStatus& status) override {}
    void OnError(const media::PipelineStatus& status) override {}
    void OnFallback(const media::PipelineStatus& status) override {}
    void SetIsEME() override {}
    void SetTimeToMetadata(base::TimeDelta elapsed) override {}
    void SetTimeToFirstFrame(base::TimeDelta elapsed) override {}
    void SetTimeToPlayReady(base::TimeDelta elapsed) override {}
    void SetContainerName(
        media::container_names::MediaContainerName container_name) override {}
    void SetRendererType(media::RendererType renderer_type) override {}
    void SetKeySystem(const std::string& key_system) override {}
    void SetHasWaitingForKey() override {}
    void SetIsHardwareSecure() override {}
    void SetHasPlayed() override {}
    void SetHaveEnough() override {}
    void SetHasAudio(media::AudioCodec audio_codec) override {}
    void SetHasVideo(media::VideoCodec video_codec) override {}
    void SetVideoPipelineInfo(const media::VideoPipelineInfo& info) override {}
    void SetAudioPipelineInfo(const media::AudioPipelineInfo& info) override {}

   private:
    raw_ptr<WatchTimeReporterTest> parent_;
  };

  WatchTimeReporterTest()
      : has_video_(std::get<0>(GetParam())),
        has_audio_(std::get<1>(GetParam())),
        fake_metrics_provider_(this) {}

  WatchTimeReporterTest(const WatchTimeReporterTest&) = delete;
  WatchTimeReporterTest& operator=(const WatchTimeReporterTest&) = delete;

  ~WatchTimeReporterTest() override {
    CycleReportingTimer();
  }

  void TearDown() override {
    // Reset the reporter to ensure orderly cleanup.
    wtr_.reset();
  }

 protected:
  void Initialize(
      bool is_mse,
      bool is_encrypted,
      const gfx::Size& initial_video_size,
      media::RendererType renderer_type = media::RendererType::kRendererImpl) {
    if (wtr_ && IsMonitoring())
      EXPECT_WATCH_TIME_FINALIZED();

    wtr_ = std::make_unique<WatchTimeReporter>(
        media::mojom::PlaybackProperties::New(
            has_audio_, has_video_, false, false, is_mse, is_encrypted, false,
            media::mojom::MediaStreamType::kNone, renderer_type),
        initial_video_size,
        base::BindRepeating(&WatchTimeReporterTest::GetCurrentMediaTime,
                            base::Unretained(this)),
        base::BindRepeating(&WatchTimeReporterTest::GetPipelineStatistics,
                            base::Unretained(this)),
        &fake_metrics_provider_, scheduler::GetSequencedTaskRunnerForTesting(),
        task_environment_.GetMockTickClock());
    reporting_interval_ = wtr_->reporting_interval_;

    // Most tests don't care about this.
    EXPECT_CALL(*this, GetPipelineStatistics())
        .WillRepeatedly(testing::Return(media::PipelineStatistics()));
    EXPECT_CALL(*this, OnUpdateVideoDecodeStats(_, _))
        .Times(testing::AnyNumber());
  }

  void CycleReportingTimer() {
    task_environment_.FastForwardBy(reporting_interval_);
  }

  bool IsMonitoring() const { return wtr_->reporting_timer_.IsRunning(); }

  bool IsBackgroundMonitoring() const {
    return wtr_->background_reporter_->reporting_timer_.IsRunning();
  }

  bool IsMutedMonitoring() const {
    return wtr_->muted_reporter_ &&
           wtr_->muted_reporter_->reporting_timer_.IsRunning();
  }

  void DisableMutedReporting() { wtr_->muted_reporter_.reset(); }

  // We call directly into the reporter for this instead of using an actual
  // PowerMonitorTestSource since that results in a posted tasks which interfere
  // with our ability to test the timer.
  void SetOnBatteryPower(bool on_battery_power) {
    wtr_->power_component_->SetCurrentValue(on_battery_power);
  }

  bool IsOnBatteryPower() const {
    return wtr_->power_component_->current_value_for_testing();
  }

  void OnPowerStateChange(bool on_battery_power) {
    base::PowerStateObserver::BatteryPowerStatus battery_power_status_ =
        on_battery_power
            ? base::PowerStateObserver::BatteryPowerStatus::kBatteryPower
            : base::PowerStateObserver::BatteryPowerStatus::kExternalPower;
    wtr_->OnBatteryPowerStatusChange(battery_power_status_);
    if (wtr_->background_reporter_) {
      wtr_->background_reporter_->OnBatteryPowerStatusChange(
          battery_power_status_);
    }
    if (wtr_->muted_reporter_)
      wtr_->muted_reporter_->OnBatteryPowerStatusChange(battery_power_status_);
  }

  void OnNativeControlsEnabled(bool enabled) {
    enabled ? wtr_->OnNativeControlsEnabled()
            : wtr_->OnNativeControlsDisabled();
  }

  void OnDisplayTypeChanged(DisplayType display_type) {
    wtr_->OnDisplayTypeChanged(display_type);
  }

  enum {
    // After |test_callback_func| is executed, should watch time continue to
    // accumulate?
    kAccumulationContinuesAfterTest = 1,

    // |test_callback_func| for hysteresis tests enters and exits finalize mode
    // for watch time, not all exits require a new current time update.
    kFinalizeExitDoesNotRequireCurrentTime = 2,

    // During finalize the watch time should not continue on the starting power
    // metric. By default this means the AC metric will be finalized, but if
    // used with |kStartOnBattery| it will be the battery metric.
    kFinalizePowerWatchTime = 4,

    // During finalize the power watch time should continue on the metric
    // opposite the starting metric (by default it's AC, it's battery if
    // |kStartOnBattery| is specified.
    kTransitionPowerWatchTime = 8,

    // Indicates that power watch time should be reported to the battery metric.
    kStartOnBattery = 16,

    // Indicates an extra start event may be generated during test execution.
    kFinalizeInterleavedStartEvent = 32,

    // During finalize the watch time should not continue on the starting
    // controls metric. By default this means the NativeControsOff metric will
    // be finalized, but if used with |kStartWithNativeControls| it will be the
    // NativeControlsOn metric.
    kFinalizeControlsWatchTime = 64,

    // During finalize the controls watch time should continue on the metric
    // opposite the starting metric (by default it's non-native controls, it's
    // native controls if |kStartWithNativeControls| is specified.
    kTransitionControlsWatchTime = 128,

    // Indicates that controls watch time should be reported to the native
    // controls metric.
    kStartWithNativeControls = 256,

    // During finalize the watch time should not continue on the starting
    // display metric. By default this means the DisplayInline metric will be
    // finalized, but if used with |kStartWithDisplayFullscreen| it will be the
    // DisplayFullscreen metric.
    kFinalizeDisplayWatchTime = 1024,

    // During finalize the display watch time should continue on the metric
    // opposite the starting metric (by default it's inline, it's fullscreen if
    // |kStartWithDisplayFullscreen| is specified.
    kTransitionDisplayWatchTime = 2048,

    // Indicates that the watch time should be reporter to the fullscreen
    // display metric.
    kStartWithDisplayFullscreen = 4096,
  };

  template <int TestFlags = 0, typename HysteresisTestCallback>
  void RunHysteresisTest(HysteresisTestCallback test_callback_func) {
    Initialize(false, false, kSizeJustRight);

    // Disable nested reporters for the hysteresis tests.
    wtr_->background_reporter_.reset();
    wtr_->muted_reporter_.reset();

    if (TestFlags & kStartWithNativeControls)
      OnNativeControlsEnabled(true);
    if (TestFlags & kStartWithDisplayFullscreen)
      OnDisplayTypeChanged(DisplayType::kFullscreen);

    // Setup all current time expectations first since they need to use the
    // InSequence macro for ease of use, but we don't want the watch time
    // expectations to be in sequence (or expectations would depend on sorted
    // order of histogram names).
    constexpr base::TimeDelta kWatchTime1 = base::Seconds(10);
    constexpr base::TimeDelta kWatchTime2 = base::Seconds(12);
    constexpr base::TimeDelta kWatchTime3 = base::Seconds(15);
    constexpr base::TimeDelta kWatchTime4 = base::Seconds(30);
    {
      testing::InSequence s;

      EXPECT_CALL(*this, GetCurrentMediaTime())
          .WillOnce(testing::Return(base::TimeDelta()))
          .WillOnce(testing::Return(kWatchTime1));

      // Setup conditions depending on if the test will not resume watch time
      // accumulation or not; i.e. the finalize criteria will not be undone
      // within the hysteresis time.
      if (TestFlags & kAccumulationContinuesAfterTest) {
        EXPECT_CALL(*this, GetCurrentMediaTime())
            .Times(TestFlags & (kFinalizeExitDoesNotRequireCurrentTime |
                                kFinalizePowerWatchTime |
                                kFinalizeControlsWatchTime |
                                kFinalizeDisplayWatchTime)
                       ? 1
                       : 2)
            .WillRepeatedly(testing::Return(kWatchTime2));
        EXPECT_CALL(*this, GetCurrentMediaTime())
            .WillOnce(testing::Return(kWatchTime3));
      } else {
        // Current time should be requested when entering the finalize state.
        EXPECT_CALL(*this, GetCurrentMediaTime())
            .Times(TestFlags & kFinalizeInterleavedStartEvent ? 2 : 1)
            .WillRepeatedly(testing::Return(kWatchTime2));
      }

      if (TestFlags & kTransitionPowerWatchTime) {
        EXPECT_CALL(*this, GetCurrentMediaTime())
            .WillOnce(testing::Return(kWatchTime4));
      }

      if (TestFlags & kTransitionControlsWatchTime) {
        EXPECT_CALL(*this, GetCurrentMediaTime())
            .WillOnce(testing::Return(kWatchTime4));
      }

      if (TestFlags & kTransitionDisplayWatchTime) {
        EXPECT_CALL(*this, GetCurrentMediaTime())
            .WillOnce(testing::Return(kWatchTime4));
      }
    }

    wtr_->OnPlaying();
    EXPECT_TRUE(IsMonitoring());
    if (TestFlags & kStartOnBattery)
      SetOnBatteryPower(true);
    else
      ASSERT_FALSE(IsOnBatteryPower());

    EXPECT_WATCH_TIME(All, kWatchTime1);
    EXPECT_WATCH_TIME(Src, kWatchTime1);
    if (TestFlags & kStartOnBattery)
      EXPECT_WATCH_TIME(Battery, kWatchTime1);
    else
      EXPECT_WATCH_TIME(Ac, kWatchTime1);
    if (TestFlags & kStartWithNativeControls)
      EXPECT_WATCH_TIME(NativeControlsOn, kWatchTime1);
    else
      EXPECT_WATCH_TIME(NativeControlsOff, kWatchTime1);
    if (TestFlags & kStartWithDisplayFullscreen)
      EXPECT_WATCH_TIME_IF_VIDEO(DisplayFullscreen, kWatchTime1);
    else
      EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTime1);

    CycleReportingTimer();

    // Invoke the test.
    test_callback_func();

    const base::TimeDelta kExpectedWatchTime =
        TestFlags & kAccumulationContinuesAfterTest ? kWatchTime3 : kWatchTime2;

    EXPECT_WATCH_TIME(All, kExpectedWatchTime);
    EXPECT_WATCH_TIME(Src, kExpectedWatchTime);
    const base::TimeDelta kExpectedPowerWatchTime =
        TestFlags & kFinalizePowerWatchTime ? kWatchTime2 : kExpectedWatchTime;
    const base::TimeDelta kExpectedContolsWatchTime =
        TestFlags & kFinalizeControlsWatchTime ? kWatchTime2
                                               : kExpectedWatchTime;
    const base::TimeDelta kExpectedDisplayWatchTime =
        TestFlags & kFinalizeDisplayWatchTime ? kWatchTime2
                                              : kExpectedWatchTime;

    if (TestFlags & kStartOnBattery)
      EXPECT_WATCH_TIME(Battery, kExpectedPowerWatchTime);
    else
      EXPECT_WATCH_TIME(Ac, kExpectedPowerWatchTime);

    if (TestFlags & kStartWithNativeControls)
      EXPECT_WATCH_TIME(NativeControlsOn, kExpectedContolsWatchTime);
    else
      EXPECT_WATCH_TIME(NativeControlsOff, kExpectedContolsWatchTime);

    if (TestFlags & kStartWithDisplayFullscreen)
      EXPECT_WATCH_TIME_IF_VIDEO(DisplayFullscreen, kExpectedDisplayWatchTime);
    else
      EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kExpectedDisplayWatchTime);

    // Special case when testing battery watch time.
    if (TestFlags & kTransitionPowerWatchTime) {
      ASSERT_TRUE(TestFlags & kAccumulationContinuesAfterTest)
          << "kTransitionPowerWatchTime tests must be done with "
             "kAccumulationContinuesAfterTest";

      EXPECT_POWER_WATCH_TIME_FINALIZED();
      CycleReportingTimer();

      // Run one last cycle that is long enough to trigger a new watch time
      // entry on the opposite of the current power watch time graph; i.e. if we
      // started on battery we'll now record one for ac and vice versa.
      EXPECT_WATCH_TIME(All, kWatchTime4);
      EXPECT_WATCH_TIME(Src, kWatchTime4);
      EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTime4);
      EXPECT_WATCH_TIME(NativeControlsOff, kWatchTime4);
      if (TestFlags & kStartOnBattery)
        EXPECT_WATCH_TIME(Ac, kWatchTime4 - kWatchTime2);
      else
        EXPECT_WATCH_TIME(Battery, kWatchTime4 - kWatchTime2);
    } else if (TestFlags & kTransitionControlsWatchTime) {
      ASSERT_TRUE(TestFlags & kAccumulationContinuesAfterTest)
          << "kTransitionControlsWatchTime tests must be done with "
             "kAccumulationContinuesAfterTest";

      EXPECT_CONTROLS_WATCH_TIME_FINALIZED();
      CycleReportingTimer();

      // Run one last cycle that is long enough to trigger a new watch time
      // entry on the opposite of the current power watch time graph; i.e. if we
      // started on battery we'll now record one for ac and vice versa.
      EXPECT_WATCH_TIME(All, kWatchTime4);
      EXPECT_WATCH_TIME(Src, kWatchTime4);
      EXPECT_WATCH_TIME(Ac, kWatchTime4);
      EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTime4);
      if (TestFlags & kStartWithNativeControls)
        EXPECT_WATCH_TIME(NativeControlsOff, kWatchTime4 - kWatchTime2);
      else
        EXPECT_WATCH_TIME(NativeControlsOn, kWatchTime4 - kWatchTime2);
    } else if (TestFlags & kTransitionDisplayWatchTime) {
      ASSERT_TRUE(TestFlags & kAccumulationContinuesAfterTest)
          << "kTransitionDisplayWatchTime tests must be done with "
             "kAccumulationContinuesAfterTest";

      EXPECT_DISPLAY_WATCH_TIME_FINALIZED();
      CycleReportingTimer();

      // Run one last cycle that is long enough to trigger a new watch time
      // entry on the opposite of the current power watch time graph; i.e. if we
      // started on battery we'll now record one for ac and vice versa.
      EXPECT_WATCH_TIME(All, kWatchTime4);
      EXPECT_WATCH_TIME(Src, kWatchTime4);
      EXPECT_WATCH_TIME(Ac, kWatchTime4);
      EXPECT_WATCH_TIME(NativeControlsOff, kWatchTime4);
      if (TestFlags & kStartWithDisplayFullscreen) {
        EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTime4 - kWatchTime2);
      } else {
        EXPECT_WATCH_TIME_IF_VIDEO(DisplayFullscreen,
                                   kWatchTime4 - kWatchTime2);
      }
    }

    EXPECT_WATCH_TIME_FINALIZED();
    wtr_.reset();
  }

  MOCK_METHOD0(GetCurrentMediaTime, base::TimeDelta());
  MOCK_METHOD0(GetPipelineStatistics, media::PipelineStatistics());

  MOCK_METHOD0(OnWatchTimeFinalized, void(void));
  MOCK_METHOD0(OnPowerWatchTimeFinalized, void(void));
  MOCK_METHOD0(OnControlsWatchTimeFinalized, void(void));
  MOCK_METHOD0(OnDisplayWatchTimeFinalized, void(void));
  MOCK_METHOD2(OnWatchTimeUpdate, void(WatchTimeKey, base::TimeDelta));
  MOCK_METHOD1(OnUnderflowUpdate, void(int));
  MOCK_METHOD2(OnUnderflowDurationUpdate, void(int, base::TimeDelta));
  MOCK_METHOD1(OnError, void(media::PipelineStatus));
  MOCK_METHOD1(OnUpdateSecondaryProperties,
               void(media::mojom::SecondaryPlaybackPropertiesPtr));
  MOCK_METHOD1(OnSetAutoplayInitiated, void(bool));
  MOCK_METHOD1(OnDurationChanged, void(base::TimeDelta));
  MOCK_METHOD2(OnUpdateVideoDecodeStats, void(uint32_t, uint32_t));

  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  const bool has_video_;
  const bool has_audio_;

  FakeMediaMetricsProvider fake_metrics_provider_;
  std::unique_ptr<WatchTimeReporter> wtr_;
  base::TimeDelta reporting_interval_;
};

class DisplayTypeWatchTimeReporterTest : public WatchTimeReporterTest {};

// Tests that watch time reporting is appropriately enabled or disabled.
TEST_P(WatchTimeReporterTest, WatchTimeReporter) {
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillRepeatedly(testing::Return(base::TimeDelta()));

  Initialize(true, true, gfx::Size());
  wtr_->OnPlaying();
  EXPECT_EQ(!has_video_, IsMonitoring());

  Initialize(true, true, gfx::Size());
  wtr_->OnPlaying();
  EXPECT_EQ(!has_video_, IsMonitoring());

  Initialize(true, true, kSizeTooSmall);
  wtr_->OnPlaying();
  EXPECT_EQ(!has_video_, IsMonitoring());

  Initialize(true, true, kSizeJustRight);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());

  Initialize(false, false, kSizeJustRight);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());

  Initialize(true, false, kSizeJustRight);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());

  EXPECT_CALL(*this,
              OnError(media::HasStatusCode(media::PIPELINE_ERROR_DECODE)))
      .Times((has_audio_ && has_video_) ? 3 : 2);
  wtr_->OnError(media::PIPELINE_ERROR_DECODE);

  Initialize(true, true, gfx::Size());
  wtr_->OnPlaying();
  EXPECT_EQ(!has_video_, IsMonitoring());

  Initialize(false, false, gfx::Size());
  wtr_->OnPlaying();
  EXPECT_EQ(!has_video_, IsMonitoring());

  Initialize(true, false, gfx::Size());
  wtr_->OnPlaying();
  EXPECT_EQ(!has_video_, IsMonitoring());

  if (!has_video_)
    EXPECT_WATCH_TIME_FINALIZED();
}

TEST_P(WatchTimeReporterTest, WatchTimeReporterInfiniteStartTime) {
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillRepeatedly(testing::Return(media::kInfiniteDuration));
  Initialize(false, false, kSizeJustRight);
  wtr_->OnPlaying();
  EXPECT_FALSE(IsMonitoring());
}

TEST_P(WatchTimeReporterTest, WatchTimeReporterBasic) {
  constexpr base::TimeDelta kWatchTimeEarly = base::Seconds(5);
  constexpr base::TimeDelta kWatchTimeLate = base::Seconds(10);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTimeEarly))
      .WillRepeatedly(testing::Return(kWatchTimeLate));
  Initialize(true, true, kSizeJustRight);

  media::PipelineStatistics stats;
  stats.video_frames_decoded = 10;
  stats.video_frames_dropped = 2;
  if (has_video_) {
    EXPECT_CALL(*this, GetPipelineStatistics())
        .WillOnce(testing::Return(media::PipelineStatistics()))
        .WillRepeatedly(testing::Return(stats));
    EXPECT_CALL(*this, OnUpdateVideoDecodeStats(stats.video_frames_decoded,
                                                stats.video_frames_dropped));
  }

  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());

  EXPECT_WATCH_TIME(Ac, kWatchTimeEarly);
  EXPECT_WATCH_TIME(All, kWatchTimeEarly);
  EXPECT_WATCH_TIME(Eme, kWatchTimeEarly);
  EXPECT_WATCH_TIME(Mse, kWatchTimeEarly);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTimeEarly);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTimeEarly);
  CycleReportingTimer();

  wtr_->OnUnderflow();
  constexpr base::TimeDelta kUnderflowDuration = base::Milliseconds(250);
  wtr_->OnUnderflowComplete(kUnderflowDuration);
  wtr_->OnUnderflow();
  EXPECT_WATCH_TIME(Ac, kWatchTimeLate);
  EXPECT_WATCH_TIME(All, kWatchTimeLate);
  EXPECT_WATCH_TIME(Eme, kWatchTimeLate);
  EXPECT_WATCH_TIME(Mse, kWatchTimeLate);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTimeLate);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTimeLate);
  EXPECT_CALL(*this, OnUnderflowUpdate(2));
  EXPECT_CALL(*this, OnUnderflowDurationUpdate(1, kUnderflowDuration));
  CycleReportingTimer();

  EXPECT_WATCH_TIME_FINALIZED();
}

TEST_P(WatchTimeReporterTest, WatchTimeReporterStatsOffsetCorrectly) {
  constexpr base::TimeDelta kWatchTimeEarly = base::Seconds(5);
  constexpr base::TimeDelta kWatchTimeLate = base::Seconds(10);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTimeEarly))
      .WillRepeatedly(testing::Return(kWatchTimeLate));
  Initialize(true, true, kSizeJustRight);

  media::PipelineStatistics initial_stats;
  initial_stats.video_frames_decoded = 10;
  initial_stats.video_frames_dropped = 2;

  media::PipelineStatistics stats;
  stats.video_frames_decoded = 17;
  stats.video_frames_dropped = 7;
  if (has_video_) {
    EXPECT_CALL(*this, GetPipelineStatistics())
        .WillOnce(testing::Return(initial_stats))
        .WillRepeatedly(testing::Return(stats));
    EXPECT_CALL(
        *this,
        OnUpdateVideoDecodeStats(
            stats.video_frames_decoded - initial_stats.video_frames_decoded,
            stats.video_frames_dropped - initial_stats.video_frames_dropped));
  }

  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());

  EXPECT_WATCH_TIME(Ac, kWatchTimeEarly);
  EXPECT_WATCH_TIME(All, kWatchTimeEarly);
  EXPECT_WATCH_TIME(Eme, kWatchTimeEarly);
  EXPECT_WATCH_TIME(Mse, kWatchTimeEarly);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTimeEarly);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTimeEarly);
  CycleReportingTimer();

  wtr_->OnUnderflow();
  constexpr base::TimeDelta kUnderflowDuration = base::Milliseconds(250);
  wtr_->OnUnderflowComplete(kUnderflowDuration);
  wtr_->OnUnderflow();
  EXPECT_WATCH_TIME(Ac, kWatchTimeLate);
  EXPECT_WATCH_TIME(All, kWatchTimeLate);
  EXPECT_WATCH_TIME(Eme, kWatchTimeLate);
  EXPECT_WATCH_TIME(Mse, kWatchTimeLate);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTimeLate);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTimeLate);
  EXPECT_CALL(*this, OnUnderflowUpdate(2));
  EXPECT_CALL(*this, OnUnderflowDurationUpdate(1, kUnderflowDuration));
  CycleReportingTimer();

  EXPECT_WATCH_TIME_FINALIZED();
}

TEST_P(WatchTimeReporterTest, WatchTimeReporterDuration) {
  constexpr base::TimeDelta kDuration1 = base::Seconds(5);
  constexpr base::TimeDelta kDuration2 = base::Seconds(10);
  Initialize(true, true, kSizeJustRight);

  EXPECT_CALL(*this, OnDurationChanged(kDuration1))
      .Times((has_audio_ && has_video_) ? 3 : 2);
  wtr_->OnDurationChanged(kDuration1);
  CycleReportingTimer();

  EXPECT_CALL(*this, OnDurationChanged(kDuration2))
      .Times((has_audio_ && has_video_) ? 3 : 2);
  wtr_->OnDurationChanged(kDuration2);
  CycleReportingTimer();
}

TEST_P(WatchTimeReporterTest, WatchTimeReporterUnderflow) {
  constexpr base::TimeDelta kWatchTimeFirst = base::Seconds(5);
  constexpr base::TimeDelta kWatchTimeEarly = base::Seconds(10);
  constexpr base::TimeDelta kWatchTimeLate = base::Seconds(15);
  if (has_audio_ && has_video_) {
    EXPECT_CALL(*this, GetCurrentMediaTime())
        .WillOnce(testing::Return(base::TimeDelta()))
        .WillOnce(testing::Return(kWatchTimeFirst))
        .WillOnce(testing::Return(kWatchTimeEarly))
        .WillOnce(testing::Return(kWatchTimeEarly))
        .WillOnce(testing::Return(kWatchTimeEarly))  // Extra 2 for muted.
        .WillOnce(testing::Return(kWatchTimeEarly))
        .WillRepeatedly(testing::Return(kWatchTimeLate));
  } else {
    EXPECT_CALL(*this, GetCurrentMediaTime())
        .WillOnce(testing::Return(base::TimeDelta()))
        .WillOnce(testing::Return(kWatchTimeFirst))
        .WillOnce(testing::Return(kWatchTimeEarly))
        .WillOnce(testing::Return(kWatchTimeEarly))
        .WillRepeatedly(testing::Return(kWatchTimeLate));
  }
  Initialize(true, true, kSizeJustRight);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());

  EXPECT_WATCH_TIME(Ac, kWatchTimeFirst);
  EXPECT_WATCH_TIME(All, kWatchTimeFirst);
  EXPECT_WATCH_TIME(Eme, kWatchTimeFirst);
  EXPECT_WATCH_TIME(Mse, kWatchTimeFirst);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTimeFirst);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTimeFirst);
  CycleReportingTimer();

  wtr_->OnUnderflow();
  wtr_->OnVolumeChange(0);

  constexpr base::TimeDelta kUnderflowDuration = base::Milliseconds(250);
  wtr_->OnUnderflowComplete(kUnderflowDuration);

  // This underflow call should be ignored since it happens after the finalize.
  // Note: We use a muted call above to trigger finalize instead of say a pause
  // since media time will be the same in the event of a pause and no underflow
  // should trigger after a pause in any case.
  wtr_->OnUnderflow();

  EXPECT_WATCH_TIME(Ac, kWatchTimeEarly);
  EXPECT_WATCH_TIME(All, kWatchTimeEarly);
  EXPECT_WATCH_TIME(Eme, kWatchTimeEarly);
  EXPECT_WATCH_TIME(Mse, kWatchTimeEarly);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTimeEarly);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTimeEarly);
  EXPECT_WATCH_TIME_FINALIZED();

  // Since we're using a mute event above, we'll have some muted watch time.
  const base::TimeDelta kWatchTime = kWatchTimeLate - kWatchTimeEarly;
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Ac, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(All, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Eme, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Mse, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(NativeControlsOff, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(DisplayInline, kWatchTime);

  EXPECT_CALL(*this, OnUnderflowUpdate(1))
      .Times((has_audio_ && has_video_) ? 2 : 1);
  EXPECT_CALL(*this, OnUnderflowDurationUpdate(1, kUnderflowDuration));
  CycleReportingTimer();

  // Muted watch time shouldn't finalize until destruction.
  if (has_audio_ && has_video_)
    EXPECT_WATCH_TIME_FINALIZED();
}

TEST_P(WatchTimeReporterTest, WatchTimeReporterUnderflowSpansFinalize) {
  constexpr base::TimeDelta kWatchTimeFirst = base::Seconds(5);
  constexpr base::TimeDelta kWatchTimeEarly = base::Seconds(10);
  constexpr base::TimeDelta kWatchTimeLate = base::Seconds(15);
  if (has_audio_ && has_video_) {
    EXPECT_CALL(*this, GetCurrentMediaTime())
        .WillOnce(testing::Return(base::TimeDelta()))
        .WillOnce(testing::Return(kWatchTimeFirst))
        .WillOnce(testing::Return(kWatchTimeEarly))
        .WillOnce(testing::Return(kWatchTimeEarly))
        .WillOnce(testing::Return(kWatchTimeEarly))  // Extra 2 for muted.
        .WillOnce(testing::Return(kWatchTimeEarly))
        .WillRepeatedly(testing::Return(kWatchTimeLate));
  } else {
    EXPECT_CALL(*this, GetCurrentMediaTime())
        .WillOnce(testing::Return(base::TimeDelta()))
        .WillOnce(testing::Return(kWatchTimeFirst))
        .WillOnce(testing::Return(kWatchTimeEarly))
        .WillOnce(testing::Return(kWatchTimeEarly))
        .WillRepeatedly(testing::Return(kWatchTimeLate));
  }
  Initialize(true, true, kSizeJustRight);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());

  EXPECT_WATCH_TIME(Ac, kWatchTimeFirst);
  EXPECT_WATCH_TIME(All, kWatchTimeFirst);
  EXPECT_WATCH_TIME(Eme, kWatchTimeFirst);
  EXPECT_WATCH_TIME(Mse, kWatchTimeFirst);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTimeFirst);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTimeFirst);
  CycleReportingTimer();

  wtr_->OnUnderflow();
  wtr_->OnVolumeChange(0);

  EXPECT_WATCH_TIME(Ac, kWatchTimeEarly);
  EXPECT_WATCH_TIME(All, kWatchTimeEarly);
  EXPECT_WATCH_TIME(Eme, kWatchTimeEarly);
  EXPECT_WATCH_TIME(Mse, kWatchTimeEarly);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTimeEarly);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTimeEarly);
  EXPECT_WATCH_TIME_FINALIZED();

  // Since we're using a mute event above, we'll have some muted watch time.
  const base::TimeDelta kWatchTime = kWatchTimeLate - kWatchTimeEarly;
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Ac, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(All, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Eme, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Mse, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(NativeControlsOff, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(DisplayInline, kWatchTime);
  EXPECT_CALL(*this, OnUnderflowUpdate(1));
  CycleReportingTimer();

  // Muted watch time shouldn't finalize until destruction.
  if (has_audio_ && has_video_)
    EXPECT_WATCH_TIME_FINALIZED();

  // This underflow completion should be dropped since we've lost the original
  // underflow it corresponded to in the finalize.
  constexpr base::TimeDelta kUnderflowDuration = base::Milliseconds(250);
  wtr_->OnUnderflowComplete(kUnderflowDuration);
}

TEST_P(WatchTimeReporterTest, WatchTimeReporterUnderflowTooLong) {
  constexpr base::TimeDelta kWatchTimeFirst = base::Seconds(5);
  constexpr base::TimeDelta kWatchTimeEarly = base::Seconds(10);
  constexpr base::TimeDelta kWatchTimeLate = base::Seconds(15);
  if (has_audio_ && has_video_) {
    EXPECT_CALL(*this, GetCurrentMediaTime())
        .WillOnce(testing::Return(base::TimeDelta()))
        .WillOnce(testing::Return(kWatchTimeFirst))
        .WillOnce(testing::Return(kWatchTimeEarly))
        .WillOnce(testing::Return(kWatchTimeEarly))
        .WillOnce(testing::Return(kWatchTimeEarly))  // Extra 2 for muted.
        .WillOnce(testing::Return(kWatchTimeEarly))
        .WillRepeatedly(testing::Return(kWatchTimeLate));
  } else {
    EXPECT_CALL(*this, GetCurrentMediaTime())
        .WillOnce(testing::Return(base::TimeDelta()))
        .WillOnce(testing::Return(kWatchTimeFirst))
        .WillOnce(testing::Return(kWatchTimeEarly))
        .WillOnce(testing::Return(kWatchTimeEarly))
        .WillRepeatedly(testing::Return(kWatchTimeLate));
  }
  Initialize(true, true, kSizeJustRight);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());

  EXPECT_WATCH_TIME(Ac, kWatchTimeFirst);
  EXPECT_WATCH_TIME(All, kWatchTimeFirst);
  EXPECT_WATCH_TIME(Eme, kWatchTimeFirst);
  EXPECT_WATCH_TIME(Mse, kWatchTimeFirst);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTimeFirst);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTimeFirst);
  CycleReportingTimer();

  wtr_->OnUnderflow();
  wtr_->OnVolumeChange(0);

  // This underflow took too long to complete so is dropped.
  constexpr base::TimeDelta kUnderflowDuration = base::Minutes(2);
  wtr_->OnUnderflowComplete(kUnderflowDuration);

  EXPECT_WATCH_TIME(Ac, kWatchTimeEarly);
  EXPECT_WATCH_TIME(All, kWatchTimeEarly);
  EXPECT_WATCH_TIME(Eme, kWatchTimeEarly);
  EXPECT_WATCH_TIME(Mse, kWatchTimeEarly);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTimeEarly);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTimeEarly);
  EXPECT_WATCH_TIME_FINALIZED();

  // Since we're using a mute event above, we'll have some muted watch time.
  const base::TimeDelta kWatchTime = kWatchTimeLate - kWatchTimeEarly;
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Ac, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(All, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Eme, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Mse, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(NativeControlsOff, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(DisplayInline, kWatchTime);
  EXPECT_CALL(*this, OnUnderflowUpdate(1));
  CycleReportingTimer();

  // Muted watch time shouldn't finalize until destruction.
  if (has_audio_ && has_video_)
    EXPECT_WATCH_TIME_FINALIZED();
}

TEST_P(WatchTimeReporterTest, WatchTimeReporterNoUnderflowDoubleReport) {
  constexpr base::TimeDelta kWatchTimeFirst = base::Seconds(5);
  constexpr base::TimeDelta kWatchTimeEarly = base::Seconds(10);
  constexpr base::TimeDelta kWatchTimeLate = base::Seconds(15);
  if (has_audio_ && has_video_) {
    EXPECT_CALL(*this, GetCurrentMediaTime())
        .WillOnce(testing::Return(base::TimeDelta()))
        .WillOnce(testing::Return(kWatchTimeFirst))
        .WillOnce(testing::Return(kWatchTimeFirst))
        .WillOnce(testing::Return(kWatchTimeEarly))
        .WillOnce(testing::Return(kWatchTimeEarly))
        .WillRepeatedly(testing::Return(kWatchTimeLate));
  } else {
    EXPECT_CALL(*this, GetCurrentMediaTime())
        .WillOnce(testing::Return(base::TimeDelta()))
        .WillOnce(testing::Return(kWatchTimeFirst))
        .WillOnce(testing::Return(kWatchTimeFirst))
        .WillOnce(testing::Return(kWatchTimeEarly))
        .WillOnce(testing::Return(kWatchTimeEarly))
        .WillRepeatedly(testing::Return(kWatchTimeLate));
  }
  Initialize(true, true, kSizeJustRight);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());

  EXPECT_WATCH_TIME(Ac, kWatchTimeFirst);
  EXPECT_WATCH_TIME(All, kWatchTimeFirst);
  EXPECT_WATCH_TIME(Eme, kWatchTimeFirst);
  EXPECT_WATCH_TIME(Mse, kWatchTimeFirst);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTimeFirst);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTimeFirst);
  EXPECT_CALL(*this, OnUnderflowUpdate(1));
  wtr_->OnUnderflow();
  CycleReportingTimer();

  EXPECT_WATCH_TIME(Ac, kWatchTimeEarly);
  EXPECT_WATCH_TIME(All, kWatchTimeEarly);
  EXPECT_WATCH_TIME(Eme, kWatchTimeEarly);
  EXPECT_WATCH_TIME(Mse, kWatchTimeEarly);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTimeEarly);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTimeEarly);

  // This cycle should not report another underflow.
  CycleReportingTimer();

  constexpr base::TimeDelta kUnderflowDuration = base::Milliseconds(250);
  wtr_->OnUnderflowComplete(kUnderflowDuration);
  EXPECT_CALL(*this, OnUnderflowDurationUpdate(1, kUnderflowDuration));

  EXPECT_WATCH_TIME_FINALIZED();
}

// Verify secondary properties pass through correctly.
TEST_P(WatchTimeReporterTest, WatchTimeReporterSecondaryProperties) {
  Initialize(true, true, kSizeJustRight);

  auto properties = media::mojom::SecondaryPlaybackProperties::New(
      has_audio_ ? media::AudioCodec::kAAC : media::AudioCodec::kUnknown,
      has_video_ ? media::VideoCodec::kH264 : media::VideoCodec::kUnknown,
      has_audio_ ? media::AudioCodecProfile::kXHE_AAC
                 : media::AudioCodecProfile::kUnknown,
      has_video_ ? media::H264PROFILE_MAIN : media::VIDEO_CODEC_PROFILE_UNKNOWN,
      has_audio_ ? media::AudioDecoderType::kMojo
                 : media::AudioDecoderType::kUnknown,
      has_video_ ? media::VideoDecoderType::kMojo
                 : media::VideoDecoderType::kUnknown,
      has_audio_ ? media::EncryptionScheme::kCenc
                 : media::EncryptionScheme::kUnencrypted,
      has_video_ ? media::EncryptionScheme::kCbcs
                 : media::EncryptionScheme::kUnencrypted,
      has_video_ ? gfx::Size(800, 600) : gfx::Size());

  // Get a pointer to our original properties since we're not allowed to use
  // lambda capture for movable types in Chromium C++ yet.
  auto* properies_ptr = properties.get();

  // Muted watch time is only reported for audio+video.
  EXPECT_CALL(*this, OnUpdateSecondaryProperties(_))
      .Times((has_audio_ && has_video_) ? 3 : 2)
      .WillRepeatedly([properies_ptr](auto secondary_properties) {
        ASSERT_TRUE(properies_ptr->Equals(*secondary_properties));
      });
  wtr_->UpdateSecondaryProperties(properties.Clone());
  CycleReportingTimer();

  // Ensure expectations are met before |properies| goes out of scope.
  testing::Mock::VerifyAndClearExpectations(this);
}

TEST_P(WatchTimeReporterTest, SecondaryProperties_SizeIncreased) {
  if (!has_video_)
    return;

  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillRepeatedly(testing::Return(base::TimeDelta()));
  Initialize(false, false, kSizeTooSmall);
  wtr_->OnPlaying();
  EXPECT_FALSE(IsMonitoring());

  EXPECT_CALL(*this, OnUpdateSecondaryProperties(_))
      .Times((has_audio_ && has_video_) ? 3 : 2);
  wtr_->UpdateSecondaryProperties(
      media::mojom::SecondaryPlaybackProperties::New(
          media::AudioCodec::kUnknown, media::VideoCodec::kUnknown,
          media::AudioCodecProfile::kUnknown,
          media::VIDEO_CODEC_PROFILE_UNKNOWN, media::AudioDecoderType::kUnknown,
          media::VideoDecoderType::kUnknown,
          media::EncryptionScheme::kUnencrypted,
          media::EncryptionScheme::kUnencrypted, kSizeJustRight));
  EXPECT_TRUE(IsMonitoring());

  EXPECT_WATCH_TIME_FINALIZED();
}

TEST_P(WatchTimeReporterTest, SecondaryProperties_SizeDecreased) {
  if (!has_video_)
    return;

  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillRepeatedly(testing::Return(base::TimeDelta()));
  Initialize(false, false, kSizeJustRight);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());

  EXPECT_CALL(*this, OnUpdateSecondaryProperties(_))
      .Times((has_audio_ && has_video_) ? 3 : 2);
  wtr_->UpdateSecondaryProperties(
      media::mojom::SecondaryPlaybackProperties::New(
          media::AudioCodec::kUnknown, media::VideoCodec::kUnknown,
          media::AudioCodecProfile::kUnknown,
          media::VIDEO_CODEC_PROFILE_UNKNOWN, media::AudioDecoderType::kUnknown,
          media::VideoDecoderType::kUnknown,
          media::EncryptionScheme::kUnencrypted,
          media::EncryptionScheme::kUnencrypted, kSizeTooSmall));
  EXPECT_WATCH_TIME_FINALIZED();
  CycleReportingTimer();

  EXPECT_FALSE(IsMonitoring());
}

TEST_P(WatchTimeReporterTest, WatchTimeReporterAutoplayInitiated) {
  Initialize(true, true, kSizeJustRight);

  EXPECT_CALL(*this, OnSetAutoplayInitiated(true))
      .Times((has_audio_ && has_video_) ? 3 : 2);
  wtr_->SetAutoplayInitiated(true);
}

TEST_P(WatchTimeReporterTest, WatchTimeReporterShownHidden) {
  constexpr base::TimeDelta kWatchTimeEarly = base::Seconds(8);
  constexpr base::TimeDelta kWatchTimeLate = base::Seconds(25);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTimeEarly))
      .WillOnce(testing::Return(kWatchTimeEarly))
      .WillRepeatedly(testing::Return(kWatchTimeLate));
  Initialize(true, true, kSizeJustRight);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());

  wtr_->OnHidden();
  const base::TimeDelta kExpectedWatchTime = kWatchTimeLate - kWatchTimeEarly;
  EXPECT_BACKGROUND_WATCH_TIME(Ac, kExpectedWatchTime);
  EXPECT_BACKGROUND_WATCH_TIME(All, kExpectedWatchTime);
  EXPECT_BACKGROUND_WATCH_TIME(Eme, kExpectedWatchTime);
  EXPECT_BACKGROUND_WATCH_TIME(Mse, kExpectedWatchTime);
  EXPECT_WATCH_TIME_FINALIZED();

  // One call for the background, one for the foreground, and one for the muted
  // reporter if we have audio+video.
  EXPECT_CALL(*this,
              OnError(media::HasStatusCode(media::PIPELINE_ERROR_DECODE)))
      .Times((has_audio_ && has_video_) ? 3 : 2);
  wtr_->OnError(media::PIPELINE_ERROR_DECODE);

  const base::TimeDelta kExpectedForegroundWatchTime = kWatchTimeEarly;
  EXPECT_WATCH_TIME(Ac, kExpectedForegroundWatchTime);
  EXPECT_WATCH_TIME(All, kExpectedForegroundWatchTime);
  EXPECT_WATCH_TIME(Eme, kExpectedForegroundWatchTime);
  EXPECT_WATCH_TIME(Mse, kExpectedForegroundWatchTime);
  EXPECT_WATCH_TIME(NativeControlsOff, kExpectedForegroundWatchTime);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kExpectedForegroundWatchTime);
  EXPECT_WATCH_TIME_FINALIZED();
}

TEST_P(WatchTimeReporterTest, WatchTimeReporterBackgroundHysteresis) {
  constexpr base::TimeDelta kWatchTimeEarly = base::Seconds(8);
  constexpr base::TimeDelta kWatchTimeLate = base::Seconds(10);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))  // 2x for playing
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTimeEarly))  // 2x for shown
      .WillOnce(testing::Return(kWatchTimeEarly))
      .WillOnce(testing::Return(kWatchTimeEarly))  // 2x for hidden
      .WillOnce(testing::Return(kWatchTimeEarly))
      .WillOnce(testing::Return(kWatchTimeEarly))  // 1x for timer cycle.
      .WillRepeatedly(testing::Return(kWatchTimeLate));
  Initialize(true, true, kSizeJustRight);
  DisableMutedReporting();  // Just complicates this test.

  wtr_->OnHidden();
  wtr_->OnPlaying();
  EXPECT_TRUE(IsBackgroundMonitoring());
  EXPECT_FALSE(IsMonitoring());

  wtr_->OnShown();
  wtr_->OnHidden();
  EXPECT_BACKGROUND_WATCH_TIME(Ac, kWatchTimeEarly);
  EXPECT_BACKGROUND_WATCH_TIME(All, kWatchTimeEarly);
  EXPECT_BACKGROUND_WATCH_TIME(Eme, kWatchTimeEarly);
  EXPECT_BACKGROUND_WATCH_TIME(Mse, kWatchTimeEarly);
  EXPECT_TRUE(IsBackgroundMonitoring());
  EXPECT_TRUE(IsMonitoring());
  EXPECT_WATCH_TIME_FINALIZED();
  CycleReportingTimer();

  EXPECT_TRUE(IsBackgroundMonitoring());
  EXPECT_FALSE(IsMonitoring());

  EXPECT_BACKGROUND_WATCH_TIME(Ac, kWatchTimeLate);
  EXPECT_BACKGROUND_WATCH_TIME(All, kWatchTimeLate);
  EXPECT_BACKGROUND_WATCH_TIME(Eme, kWatchTimeLate);
  EXPECT_BACKGROUND_WATCH_TIME(Mse, kWatchTimeLate);
  EXPECT_WATCH_TIME_FINALIZED();
}

TEST_P(WatchTimeReporterTest, WatchTimeReporterShownHiddenBackground) {
  constexpr base::TimeDelta kWatchTimeEarly = base::Seconds(8);
  constexpr base::TimeDelta kWatchTimeLate = base::Seconds(10);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTimeEarly))
      .WillOnce(testing::Return(kWatchTimeEarly))
      .WillRepeatedly(testing::Return(kWatchTimeLate));

  Initialize(true, true, kSizeJustRight);
  DisableMutedReporting();  // Just complicates this test.

  wtr_->OnHidden();
  wtr_->OnPlaying();
  EXPECT_TRUE(IsBackgroundMonitoring());
  EXPECT_FALSE(IsMonitoring());

  wtr_->OnShown();
  EXPECT_BACKGROUND_WATCH_TIME(Ac, kWatchTimeEarly);
  EXPECT_BACKGROUND_WATCH_TIME(All, kWatchTimeEarly);
  EXPECT_BACKGROUND_WATCH_TIME(Eme, kWatchTimeEarly);
  EXPECT_BACKGROUND_WATCH_TIME(Mse, kWatchTimeEarly);
  EXPECT_WATCH_TIME_FINALIZED();

  const base::TimeDelta kExpectedForegroundWatchTime =
      kWatchTimeLate - kWatchTimeEarly;
  EXPECT_WATCH_TIME(Ac, kExpectedForegroundWatchTime);
  EXPECT_WATCH_TIME(All, kExpectedForegroundWatchTime);
  EXPECT_WATCH_TIME(Eme, kExpectedForegroundWatchTime);
  EXPECT_WATCH_TIME(Mse, kExpectedForegroundWatchTime);
  EXPECT_WATCH_TIME(NativeControlsOff, kExpectedForegroundWatchTime);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kExpectedForegroundWatchTime);
  CycleReportingTimer();

  EXPECT_WATCH_TIME_FINALIZED();
}

TEST_P(WatchTimeReporterTest, WatchTimeReporterHiddenPausedBackground) {
  constexpr base::TimeDelta kWatchTime = base::Seconds(8);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillRepeatedly(testing::Return(kWatchTime));
  Initialize(true, true, kSizeJustRight);
  wtr_->OnHidden();
  wtr_->OnPlaying();
  EXPECT_TRUE(IsBackgroundMonitoring());
  EXPECT_FALSE(IsMonitoring());

  wtr_->OnPaused();
  EXPECT_BACKGROUND_WATCH_TIME(Ac, kWatchTime);
  EXPECT_BACKGROUND_WATCH_TIME(All, kWatchTime);
  EXPECT_BACKGROUND_WATCH_TIME(Eme, kWatchTime);
  EXPECT_BACKGROUND_WATCH_TIME(Mse, kWatchTime);
  EXPECT_WATCH_TIME_FINALIZED();
  CycleReportingTimer();

  EXPECT_FALSE(IsBackgroundMonitoring());
  EXPECT_FALSE(IsMonitoring());
}

TEST_P(WatchTimeReporterTest, WatchTimeReporterHiddenSeekedBackground) {
  constexpr base::TimeDelta kWatchTime = base::Seconds(8);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillRepeatedly(testing::Return(kWatchTime));
  Initialize(false, true, kSizeJustRight);
  wtr_->OnHidden();
  wtr_->OnPlaying();
  EXPECT_TRUE(IsBackgroundMonitoring());
  EXPECT_FALSE(IsMonitoring());

  EXPECT_BACKGROUND_WATCH_TIME(Ac, kWatchTime);
  EXPECT_BACKGROUND_WATCH_TIME(All, kWatchTime);
  EXPECT_BACKGROUND_WATCH_TIME(Eme, kWatchTime);
  EXPECT_BACKGROUND_WATCH_TIME(Src, kWatchTime);
  EXPECT_WATCH_TIME_FINALIZED();
  wtr_->OnSeeking();

  EXPECT_FALSE(IsBackgroundMonitoring());
  EXPECT_FALSE(IsMonitoring());
}

TEST_P(WatchTimeReporterTest, WatchTimeReporterHiddenPowerBackground) {
  constexpr base::TimeDelta kWatchTime1 = base::Seconds(8);
  constexpr base::TimeDelta kWatchTime2 = base::Seconds(16);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTime1))
      .WillOnce(testing::Return(kWatchTime1))
      .WillRepeatedly(testing::Return(kWatchTime2));
  Initialize(true, true, kSizeJustRight);
  wtr_->OnHidden();
  wtr_->OnPlaying();
  EXPECT_TRUE(IsBackgroundMonitoring());
  EXPECT_FALSE(IsMonitoring());

  OnPowerStateChange(true);
  EXPECT_BACKGROUND_WATCH_TIME(Ac, kWatchTime1);
  EXPECT_BACKGROUND_WATCH_TIME(All, kWatchTime1);
  EXPECT_BACKGROUND_WATCH_TIME(Eme, kWatchTime1);
  EXPECT_BACKGROUND_WATCH_TIME(Mse, kWatchTime1);
  EXPECT_POWER_WATCH_TIME_FINALIZED();
  CycleReportingTimer();

  wtr_->OnPaused();
  EXPECT_BACKGROUND_WATCH_TIME(Battery, kWatchTime2 - kWatchTime1);
  EXPECT_BACKGROUND_WATCH_TIME(All, kWatchTime2);
  EXPECT_BACKGROUND_WATCH_TIME(Eme, kWatchTime2);
  EXPECT_BACKGROUND_WATCH_TIME(Mse, kWatchTime2);
  EXPECT_WATCH_TIME_FINALIZED();
  CycleReportingTimer();

  EXPECT_FALSE(IsBackgroundMonitoring());
  EXPECT_FALSE(IsMonitoring());
}

TEST_P(WatchTimeReporterTest, WatchTimeReporterHiddenControlsBackground) {
  constexpr base::TimeDelta kWatchTime1 = base::Seconds(8);
  constexpr base::TimeDelta kWatchTime2 = base::Seconds(16);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTime1))
      .WillOnce(testing::Return(kWatchTime2));
  Initialize(true, true, kSizeJustRight);
  wtr_->OnHidden();
  wtr_->OnPlaying();
  EXPECT_TRUE(IsBackgroundMonitoring());
  EXPECT_FALSE(IsMonitoring());

  OnNativeControlsEnabled(true);

  EXPECT_BACKGROUND_WATCH_TIME(Ac, kWatchTime1);
  EXPECT_BACKGROUND_WATCH_TIME(All, kWatchTime1);
  EXPECT_BACKGROUND_WATCH_TIME(Eme, kWatchTime1);
  EXPECT_BACKGROUND_WATCH_TIME(Mse, kWatchTime1);
  CycleReportingTimer();

  wtr_->OnPaused();
  EXPECT_BACKGROUND_WATCH_TIME(Ac, kWatchTime2);
  EXPECT_BACKGROUND_WATCH_TIME(All, kWatchTime2);
  EXPECT_BACKGROUND_WATCH_TIME(Eme, kWatchTime2);
  EXPECT_BACKGROUND_WATCH_TIME(Mse, kWatchTime2);
  EXPECT_WATCH_TIME_FINALIZED();
  CycleReportingTimer();

  EXPECT_FALSE(IsBackgroundMonitoring());
  EXPECT_FALSE(IsMonitoring());
}

TEST_P(DisplayTypeWatchTimeReporterTest,
       WatchTimeReporterHiddenDisplayTypeBackground) {
  constexpr base::TimeDelta kWatchTime1 = base::Seconds(8);
  constexpr base::TimeDelta kWatchTime2 = base::Seconds(16);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTime1))
      .WillOnce(testing::Return(kWatchTime2));
  Initialize(true, true, kSizeJustRight);
  wtr_->OnHidden();
  wtr_->OnPlaying();
  EXPECT_TRUE(IsBackgroundMonitoring());
  EXPECT_FALSE(IsMonitoring());

  OnDisplayTypeChanged(DisplayType::kFullscreen);

  EXPECT_BACKGROUND_WATCH_TIME(Ac, kWatchTime1);
  EXPECT_BACKGROUND_WATCH_TIME(All, kWatchTime1);
  EXPECT_BACKGROUND_WATCH_TIME(Eme, kWatchTime1);
  EXPECT_BACKGROUND_WATCH_TIME(Mse, kWatchTime1);
  CycleReportingTimer();

  wtr_->OnPaused();
  EXPECT_BACKGROUND_WATCH_TIME(Ac, kWatchTime2);
  EXPECT_BACKGROUND_WATCH_TIME(All, kWatchTime2);
  EXPECT_BACKGROUND_WATCH_TIME(Eme, kWatchTime2);
  EXPECT_BACKGROUND_WATCH_TIME(Mse, kWatchTime2);
  EXPECT_WATCH_TIME_FINALIZED();
  CycleReportingTimer();

  EXPECT_FALSE(IsBackgroundMonitoring());
  EXPECT_FALSE(IsMonitoring());
}

TEST_P(WatchTimeReporterTest, WatchTimeReporterHiddenMuted) {
  constexpr base::TimeDelta kWatchTime1 = base::Seconds(8);
  constexpr base::TimeDelta kWatchTime2 = base::Seconds(25);

  // Expectations for when muted watch time is recorded and when it isn't.
  if (has_audio_ && has_video_) {
    EXPECT_CALL(*this, GetCurrentMediaTime())
        .WillOnce(testing::Return(base::TimeDelta()))  // 2x playing.
        .WillOnce(testing::Return(base::TimeDelta()))
        .WillOnce(testing::Return(kWatchTime1))  // 2x muted.
        .WillOnce(testing::Return(kWatchTime1))
        .WillOnce(testing::Return(kWatchTime1))  // 2x shown.
        .WillOnce(testing::Return(kWatchTime1))
        .WillRepeatedly(testing::Return(kWatchTime2));
  } else {
    EXPECT_CALL(*this, GetCurrentMediaTime())
        .WillOnce(testing::Return(base::TimeDelta()))  // 2x playing.
        .WillOnce(testing::Return(base::TimeDelta()))
        .WillOnce(testing::Return(kWatchTime1))  // 1x muted.
        .WillOnce(testing::Return(kWatchTime1))  // 1x shown.
        .WillRepeatedly(testing::Return(kWatchTime2));
  }

  Initialize(true, true, kSizeJustRight);
  wtr_->OnHidden();
  wtr_->OnPlaying();
  EXPECT_TRUE(IsBackgroundMonitoring());
  EXPECT_FALSE(IsMutedMonitoring());
  EXPECT_FALSE(IsMonitoring());

  wtr_->OnVolumeChange(0);
  EXPECT_TRUE(IsBackgroundMonitoring());
  EXPECT_FALSE(IsMutedMonitoring());

  EXPECT_BACKGROUND_WATCH_TIME(Ac, kWatchTime1);
  EXPECT_BACKGROUND_WATCH_TIME(All, kWatchTime1);
  EXPECT_BACKGROUND_WATCH_TIME(Eme, kWatchTime1);
  EXPECT_BACKGROUND_WATCH_TIME(Mse, kWatchTime1);
  EXPECT_WATCH_TIME_FINALIZED();
  CycleReportingTimer();

  wtr_->OnShown();
  EXPECT_FALSE(IsBackgroundMonitoring());
  EXPECT_FALSE(IsMonitoring());
  EXPECT_EQ(has_audio_ && has_video_, IsMutedMonitoring());

  const base::TimeDelta kWatchTime = kWatchTime2 - kWatchTime1;
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Ac, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(All, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Eme, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Mse, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(DisplayInline, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(NativeControlsOff, kWatchTime);
  if (has_audio_ && has_video_)
    EXPECT_WATCH_TIME_FINALIZED();
}

TEST_P(WatchTimeReporterTest, WatchTimeReporterMultiplePartialFinalize) {
  constexpr base::TimeDelta kWatchTime1 = base::Seconds(8);
  constexpr base::TimeDelta kWatchTime2 = base::Seconds(16);

  // Transition controls and battery.
  {
    EXPECT_CALL(*this, GetCurrentMediaTime())
        .WillOnce(testing::Return(base::TimeDelta()))
        .WillOnce(testing::Return(kWatchTime1))
        .WillOnce(testing::Return(kWatchTime1))
        .WillOnce(testing::Return(kWatchTime1))
        .WillOnce(testing::Return(kWatchTime2));
    Initialize(true, true, kSizeJustRight);
    wtr_->OnPlaying();
    EXPECT_TRUE(IsMonitoring());

    OnNativeControlsEnabled(true);
    OnPowerStateChange(true);

    EXPECT_WATCH_TIME(Ac, kWatchTime1);
    EXPECT_WATCH_TIME(All, kWatchTime1);
    EXPECT_WATCH_TIME(Eme, kWatchTime1);
    EXPECT_WATCH_TIME(Mse, kWatchTime1);
    EXPECT_WATCH_TIME(NativeControlsOff, kWatchTime1);
    EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTime1);
    EXPECT_CONTROLS_WATCH_TIME_FINALIZED();
    EXPECT_POWER_WATCH_TIME_FINALIZED();
    CycleReportingTimer();

    wtr_->OnPaused();
    EXPECT_WATCH_TIME(All, kWatchTime2);
    EXPECT_WATCH_TIME(Eme, kWatchTime2);
    EXPECT_WATCH_TIME(Mse, kWatchTime2);
    EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTime2);
    EXPECT_WATCH_TIME(NativeControlsOn, kWatchTime2 - kWatchTime1);
    EXPECT_WATCH_TIME(Battery, kWatchTime2 - kWatchTime1);
    EXPECT_WATCH_TIME_FINALIZED();
    CycleReportingTimer();

    EXPECT_FALSE(IsMonitoring());
  }

  // Transition display type and battery. Test only works with video.
  if (has_video_) {
    EXPECT_CALL(*this, GetCurrentMediaTime())
        .WillOnce(testing::Return(base::TimeDelta()))
        .WillOnce(testing::Return(kWatchTime1))
        .WillOnce(testing::Return(kWatchTime1))
        .WillOnce(testing::Return(kWatchTime1))
        .WillOnce(testing::Return(kWatchTime2));
    Initialize(true, true, kSizeJustRight);
    wtr_->OnPlaying();
    EXPECT_TRUE(IsMonitoring());

    OnDisplayTypeChanged(DisplayType::kFullscreen);
    OnPowerStateChange(true);

    EXPECT_WATCH_TIME(Ac, kWatchTime1);
    EXPECT_WATCH_TIME(All, kWatchTime1);
    EXPECT_WATCH_TIME(Eme, kWatchTime1);
    EXPECT_WATCH_TIME(Mse, kWatchTime1);
    EXPECT_WATCH_TIME(NativeControlsOff, kWatchTime1);
    EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTime1);
    EXPECT_DISPLAY_WATCH_TIME_FINALIZED();
    EXPECT_POWER_WATCH_TIME_FINALIZED();
    CycleReportingTimer();

    wtr_->OnPaused();
    EXPECT_WATCH_TIME(All, kWatchTime2);
    EXPECT_WATCH_TIME(Eme, kWatchTime2);
    EXPECT_WATCH_TIME(Mse, kWatchTime2);
    EXPECT_WATCH_TIME(NativeControlsOff, kWatchTime2);

"""


```