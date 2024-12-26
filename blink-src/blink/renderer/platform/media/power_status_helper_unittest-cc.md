Response: Let's break down the thought process for analyzing this C++ unittest file.

**1. Initial Understanding of the File's Purpose:**

The file name `power_status_helper_unittest.cc` immediately suggests that it contains unit tests for a class or component named `PowerStatusHelper`. The location `blink/renderer/platform/media/` indicates that this helper is part of the Blink rendering engine and likely related to media playback and platform-specific functionalities.

**2. Identifying Key Components and Dependencies:**

Scanning the `#include` directives reveals the core dependencies:

*   `power_status_helper.h`:  The header file for the class being tested. This will contain the definition of `PowerStatusHelper`.
*   Standard C++ headers: `<memory>`, `<tuple>`, `<utility>`, `<vector>` for memory management, data structures, etc.
*   `base/run_loop.h`, `base/test/metrics/histogram_tester.h`, `base/test/mock_callback.h`, `base/test/task_environment.h`: These are part of Chromium's testing infrastructure, used for controlling the execution environment, testing metrics, and mocking callbacks.
*   `media/base/pipeline_metadata.h`: This suggests that `PowerStatusHelper` interacts with media playback information.
*   `mojo/public/cpp/bindings/receiver.h`:  Mojo is Chromium's inter-process communication system. This implies `PowerStatusHelper` likely communicates with other processes or services.
*   `services/device/public/mojom/battery_status.mojom-blink.h`: This is a strong indicator that `PowerStatusHelper` interacts with the device's battery status information. `mojom` signifies a Mojo interface definition.
*   `testing/gmock/include/gmock/gmock.h`, `testing/gtest/include/gtest/gtest.h`: These are the Google Mock and Google Test frameworks used for writing the unit tests.

**3. Deciphering the `PowerStatusHelperTest` Class:**

This class sets up the testing environment for `PowerStatusHelper`. Key observations:

*   `MockBatteryMonitor`: This inner class is a *mock implementation* of the `device::mojom::blink::BatteryMonitor` interface. This is crucial for isolating `PowerStatusHelper` during testing and controlling the battery status data it receives. The `MOCK_METHOD0` macros indicate that this class will use Google Mock to define expected calls to its methods (`DidGetBatteryMonitor`, `DidQueryNextStatus`, `DidDisconnect`).
*   `SetUp()`: This method is a standard Google Test fixture setup method. It instantiates the `PowerStatusHelper` using the mock battery monitor's callback.
*   `MakeRecordable()`: This method puts the `PowerStatusHelper` into a state where it should start recording power consumption data. It manipulates properties like `IsPlaying`, `Metadata`, `AverageFrameRate`, and `IsFullscreen`. It also calls `UpdatePowerExperimentState(true)`. This hints at an experimental feature related to power monitoring.
*   `histogram_tester_`:  An instance of `base::HistogramTester` is used to verify that certain events are recorded as histograms, which is a common way to track metrics in Chromium.

**4. Analyzing Individual Test Cases:**

Each `TEST_F` function focuses on testing a specific aspect of `PowerStatusHelper`'s behavior:

*   **Error Handling (Empty/Unbound Remote):**  Tests how the helper reacts when the battery monitor connection fails.
*   **Basic Reporting:** Tests the core functionality of receiving battery updates and presumably calculating power consumption. The mention of "fractional amounts" suggests the helper needs to handle partial battery changes.
*   **Charging Behavior:** Tests that the baseline for power consumption calculations is reset when the device starts charging.
*   **Experiment Control:** Verifies that the `UpdatePowerExperimentState` method correctly starts and stops the power monitoring process.
*   **Configuration Changes:** Tests how the helper handles changes in video playback parameters (like switching to video with different characteristics) and whether it correctly starts/stops recording based on these changes.

**5. Understanding `PowerStatusHelperBucketTest`:**

This test suite focuses specifically on the logic within `PowerStatusHelper::BucketFor`.

*   `BucketFor()`:  This static method in `PowerStatusHelper` seems responsible for categorizing video playback scenarios into "buckets" based on codec, resolution, frame rate, and fullscreen status. This is likely used for aggregating power consumption data for similar playback conditions.
*   `PlaybackParamsTuple`: A tuple is used to represent different combinations of playback parameters for testing.
*   `INSTANTIATE_TEST_SUITE_P`: This Google Test macro automatically generates test cases for all combinations of parameters defined in the `Combine` call. This ensures comprehensive testing of the bucketing logic.

**6. Connecting to JavaScript, HTML, and CSS:**

The connection here is indirect but fundamental:

*   **JavaScript:**  JavaScript code running in a web page can trigger media playback (using the `<video>` element or the Media Source Extensions API). This playback, in turn, would engage the media pipeline within the Blink engine, potentially involving `PowerStatusHelper`. JavaScript wouldn't directly call `PowerStatusHelper`, but its actions would lead to its use.
*   **HTML:** The `<video>` element in HTML is the primary way to embed video content. When a `<video>` element is playing, the browser's rendering engine (Blink) handles the media decoding and rendering, and `PowerStatusHelper` might be involved in monitoring power usage during this process.
*   **CSS:** CSS can style the `<video>` element, including making it fullscreen. The `PowerStatusHelper` considers the fullscreen state when categorizing playback for power monitoring.

**7. Logical Reasoning and Assumptions:**

The tests rely on the assumption that:

*   The `device::mojom::blink::BatteryMonitor` interface provides accurate battery status updates.
*   The bucketing logic in `PowerStatusHelper::BucketFor` correctly categorizes different playback scenarios.
*   The histograms recorded by `PowerStatusHelper` provide valuable insights into power consumption patterns.

**8. Identifying Potential User/Programming Errors:**

While this is a *unittest* file, understanding the underlying code can hint at potential errors:

*   **Incorrect Metadata:** If the media metadata (codec, resolution, frame rate) provided to `PowerStatusHelper` is inaccurate, the power consumption data might be categorized incorrectly.
*   **Race Conditions (Hypothetical):**  While not explicitly tested here, in a real-world scenario, there might be race conditions if battery status updates arrive at the same time as playback state changes. The design of `PowerStatusHelper` needs to be robust against such situations.
*   **Forgetting to Enable the Experiment:** If the power monitoring experiment is not enabled (`UpdatePowerExperimentState(true)`), no data will be collected.

By following these steps, we can gain a comprehensive understanding of the purpose, functionality, and context of this Chromium Blink engine unittest file. The process involves examining the file structure, dependencies, test cases, and considering the broader interaction with web technologies.
这个文件 `power_status_helper_unittest.cc` 是 Chromium Blink 引擎中 `PowerStatusHelper` 类的单元测试文件。它的主要功能是 **验证 `PowerStatusHelper` 类的各种功能和行为是否符合预期。**

以下是更详细的功能列举和相关说明：

**1. 验证 PowerStatusHelper 的初始化和资源管理:**

*   **测试 `EmptyPendingRemoteIsOkay`:** 验证即使在没有有效的 `device::mojom::blink::BatteryMonitor` (电池监控器) 的情况下，`PowerStatusHelper` 也能正常初始化，避免崩溃或错误。这模拟了设备可能没有电池信息的情况。
*   **测试 `UnboundPendingRemoteIsOkay`:**  验证即使获取到的 `BatteryMonitor` 是未绑定的 (连接断开)，`PowerStatusHelper` 也能妥善处理，不会崩溃。

**2. 验证 PowerStatusHelper 的核心电池状态监控和报告功能:**

*   **测试 `BasicReportingWithFractionalAmounts`:**  验证 `PowerStatusHelper` 能够接收来自 `BatteryMonitor` 的电池状态更新，并能处理非整数的电量变化。这模拟了电池电量逐渐下降的情况。
    *   **假设输入:**  模拟 `BatteryMonitor` 依次提供电量更新，例如从 0.9 到较低的值。
    *   **预期输出:** `PowerStatusHelper` 会记录电量变化。由于是单元测试，这里主要验证它是否调用了 `DidQueryNextStatus` 来请求下一次更新。在实际运行中，它会将电量变化记录到直方图中。
*   **测试 `ChargingResetsBaseline`:** 验证当设备开始充电时，`PowerStatusHelper` 会重置其内部的电量基线。这是因为充电期间的电量变化不应被计入正常播放的功耗。
    *   **假设输入:** 模拟 `BatteryMonitor` 先提供一些电量下降的更新，然后提供一个充电状态的更新。
    *   **预期输出:**  `PowerStatusHelper` 会在接收到充电状态后，在请求下一次电量更新时，将当前的电量值作为新的基线。

**3. 验证 PowerStatusHelper 基于播放状态和元数据的功耗记录控制:**

*   **测试 `ExperimentStateStopsRecording`:** 验证当关闭功耗实验时 (`UpdatePowerExperimentState(false)`)，`PowerStatusHelper` 会停止记录功耗数据，并断开与 `BatteryMonitor` 的连接。
    *   **假设输入:** 先将 `PowerStatusHelper` 置于可记录状态 (`MakeRecordable()`)，然后调用 `UpdatePowerExperimentState(false)`。
    *   **预期输出:**  `PowerStatusHelper` 不会再请求新的电池状态，并且会断开与 `BatteryMonitor` 的连接。
*   **测试 `ChangingBucketsWorks`:**  验证当播放的视频特性发生变化，导致需要切换到不同的功耗记录 "bucket" (例如，从非全屏到全屏)，`PowerStatusHelper` 能够正确处理，并使用新的基线进行记录。
    *   **假设输入:**  先以一种视频状态 (`MakeRecordable(false)`) 开始记录，然后改变视频状态 (`MakeRecordable(true)`)，模拟切换到另一个需要单独记录功耗的场景。
    *   **预期输出:** `PowerStatusHelper` 会识别出 bucket 的变化，并开始使用新的基线进行功耗记录。
*   **测试 `UnbucketedVideoStopsRecording`:** 验证当播放的视频没有对应的功耗记录 "bucket" 时 (例如，停止播放视频)，`PowerStatusHelper` 会停止记录功耗数据。
    *   **假设输入:**  先以可记录的视频状态开始 (`MakeRecordable()`)，然后设置 `IsPlaying(false)`。
    *   **预期输出:** `PowerStatusHelper` 会断开与 `BatteryMonitor` 的连接，停止功耗记录。
*   **测试 `UnbucketedFrameRateStopsRecording`:** 验证当播放的视频帧率不在预定义的 "bucket" 中时，`PowerStatusHelper` 会停止记录功耗数据。
    *   **假设输入:** 先以可记录的视频状态开始 (`MakeRecordable()`)，然后设置一个未知的帧率 (`SetAverageFrameRate({})`)。
    *   **预期输出:** `PowerStatusHelper` 会断开与 `BatteryMonitor` 的连接，停止功耗记录。

**4. 验证 `PowerStatusHelper::BucketFor` 方法的 bucketing 逻辑:**

*   **`PowerStatusHelperBucketTest` 和 `TEST_P`:**  这是一个参数化测试，用于全面验证 `PowerStatusHelper::BucketFor` 静态方法，该方法根据视频的播放状态、是否有视频、编解码器、分辨率、帧率和是否全屏等信息，将播放场景归类到不同的 "bucket" 中。这些 bucket 用于区分不同类型的播放，以便进行更精细的功耗分析。
    *   **假设输入:**  `PlaybackParamsTuple` 定义了各种播放参数的组合，例如是否正在播放、是否有视频、使用的编解码器 (H.264, VP9 等)、分辨率 (360p, 720p, 1080p 等)、帧率 (30fps, 60fps) 和是否全屏。
    *   **预期输出:**  对于每种参数组合，`BucketFor` 方法应该返回正确的 bucket 值，或者在无法归类时返回空值。`INSTANTIATE_TEST_SUITE_P` 宏会生成大量的测试用例，覆盖各种可能的组合。

**与 JavaScript, HTML, CSS 的关系 (间接关系):**

`PowerStatusHelper` 本身是一个 C++ 类，不直接与 JavaScript, HTML, CSS 交互。然而，它服务于 Blink 渲染引擎的媒体播放功能，而这些功能通常是由 Web 技术触发的：

*   **JavaScript:**  网页中的 JavaScript 代码可以使用 `<video>` 标签或者 Media Source Extensions (MSE) API 来控制视频的播放。当 JavaScript 发起播放时，Blink 引擎会处理视频的解码、渲染等操作，这时 `PowerStatusHelper` 可能会被用来监控播放过程中的功耗。
*   **HTML:** HTML 的 `<video>` 标签用于嵌入视频内容。当浏览器渲染包含 `<video>` 标签的网页并开始播放视频时，`PowerStatusHelper` 就有可能参与到功耗监控中。
*   **CSS:** CSS 可以用来控制 `<video>` 元素的样式，例如设置全屏播放。`PowerStatusHelper` 的 bucketing 逻辑会考虑是否全屏，这与 CSS 的设置有关。

**逻辑推理的假设输入与输出 (针对 `PowerStatusHelper::BucketFor`):**

| 假设输入 (PlaybackParamsTuple)                                                                 | 预期输出 (BucketFor 返回值)                                                                                                |
| -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `is_playing = true`, `has_video = true`, `codec = kH264`, `resolution = 360p`, `frame_rate = 60`, `fullscreen = false` | `PowerStatusHelper::kCodecBitsH264 | PowerStatusHelper::kResolution360p | PowerStatusHelper::kFrameRate60 | PowerStatusHelper::kFullScreenNo` |
| `is_playing = true`, `has_video = true`, `codec = kVP9Profile0`, `resolution = 720p`, `frame_rate = 30`, `fullscreen = true` | `PowerStatusHelper::kCodecBitsVP9Profile0 | PowerStatusHelper::kResolution720p | PowerStatusHelper::kFrameRate30 | PowerStatusHelper::kFullScreenYes` |
| `is_playing = false`, `has_video = true`, ... (其他参数)                                      | `std::nullopt` (因为没有播放)                                                                                                |
| `is_playing = true`, `has_video = false`, ... (其他参数)                                      | `std::nullopt` (因为没有视频)                                                                                                |
| `is_playing = true`, `has_video = true`, `codec = 未知`, ... (其他参数)                       | `std::nullopt` (因为编解码器不在 bucket 中)                                                                                    |
| `is_playing = true`, `has_video = true`, `resolution = 非常规`, ... (其他参数)               | `std::nullopt` (因为分辨率不在 bucket 中)                                                                                    |
| `is_playing = true`, `has_video = true`, `frame_rate = 任意非 30 或 60`, ... (其他参数)           | `std::nullopt` (因为帧率不在 bucket 中)                                                                                    |

**涉及用户或者编程常见的使用错误 (间接体现):**

虽然这是单元测试，但可以推断出一些潜在的使用错误：

*   **未能正确设置播放状态:** 如果在视频播放时，相关的 `PowerStatusHelper` 没有被告知正在播放 (`SetIsPlaying(true)` 没有被调用)，那么功耗数据可能不会被正确记录。
*   **未能提供正确的视频元数据:** 如果 `SetMetadata` 方法没有提供准确的视频编解码器、分辨率等信息，`PowerStatusHelper` 可能会将功耗数据归类到错误的 bucket 中，导致分析结果不准确。
*   **在不需要记录时仍然保持记录状态:**  如果在视频播放结束后，没有及时通知 `PowerStatusHelper` 停止记录 (`UpdatePowerExperimentState(false)` 或其他导致停止记录的操作)，可能会浪费资源并记录不必要的功耗数据。
*   **假设设备总是支持电池信息:**  编程时需要考虑到设备可能没有电池或无法获取电池信息的情况，`PowerStatusHelper` 的设计需要能够优雅地处理这种情况，就像 `EmptyPendingRemoteIsOkay` 测试所验证的那样。

总而言之，`power_status_helper_unittest.cc` 通过各种测试用例，细致地检验了 `PowerStatusHelper` 类的功能，确保它能够在不同的播放场景下正确地监控和记录功耗信息，为 Chromium 引擎的功耗优化提供基础。

Prompt: 
```
这是目录为blink/renderer/platform/media/power_status_helper_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/media/power_status_helper.h"

#include <memory>
#include <tuple>
#include <utility>
#include <vector>

#include "base/run_loop.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/mock_callback.h"
#include "base/test/task_environment.h"
#include "media/base/pipeline_metadata.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "services/device/public/mojom/battery_status.mojom-blink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace blink {

using ::testing::Bool;
using ::testing::Combine;
using ::testing::Values;

class PowerStatusHelperTest : public testing::Test {
 public:
  class MockBatteryMonitor : public device::mojom::blink::BatteryMonitor {
   public:
    MOCK_METHOD0(DidGetBatteryMonitor, void());
    MOCK_METHOD0(DidQueryNextStatus, void());
    MOCK_METHOD0(DidDisconnect, void());

    ~MockBatteryMonitor() override {
      // Mojo gets mad if we don't finish up outstanding callbacks.
      if (callback_)
        ProvidePowerUpdate(false, 0);
    }

    // device::mojom::blink::BatteryMonitor
    void QueryNextStatus(QueryNextStatusCallback callback) override {
      DidQueryNextStatus();
      callback_ = std::move(callback);
    }

    // Would be nice to use a MockCallback for this, but a move-only return type
    // doesn't seem to work.
    mojo::PendingRemote<device::mojom::blink::BatteryMonitor>
    GetBatteryMonitor() {
      DidGetBatteryMonitor();
      switch (remote_type_) {
        case RemoteType::kConnected:
        case RemoteType::kDisconnected: {
          auto pending = receiver_.BindNewPipeAndPassRemote();
          receiver_.set_disconnect_handler(base::BindOnce(
              &MockBatteryMonitor::DidDisconnect, base::Unretained(this)));
          if (remote_type_ == RemoteType::kDisconnected)
            receiver_.reset();
          base::RunLoop().RunUntilIdle();
          return pending;
        }
        case RemoteType::kEmpty:
          return mojo::PendingRemote<device::mojom::blink::BatteryMonitor>();
      }
    }

    // Would be nice if this were base::MockCallback, but move-only types don't
    // seem to work.
    PowerStatusHelper::CreateBatteryMonitorCB cb() {
      return base::BindRepeating(&MockBatteryMonitor::GetBatteryMonitor,
                                 base::Unretained(this));
    }

    // Provide a battery update via |callback_|.
    void ProvidePowerUpdate(bool is_charging, float current_level) {
      EXPECT_TRUE(callback_);
      device::mojom::blink::BatteryStatusPtr status =
          device::mojom::blink::BatteryStatus::New(is_charging,
                                                   /*charging_time=*/0,
                                                   /*discharging_time=*/0,
                                                   current_level);
      std::move(callback_).Run(std::move(status));
      base::RunLoop().RunUntilIdle();
    }

    mojo::Receiver<device::mojom::blink::BatteryMonitor> receiver_{this};

    // If false, then GetBatteryMonitor will not return a monitor.
    enum class RemoteType {
      // Provide a connected remote.
      kConnected,
      // Provide an empty PendingRemote
      kEmpty,
      // Provide a PendingRemote to a disconnected remote.
      kDisconnected
    };
    RemoteType remote_type_ = RemoteType::kConnected;

    // Most recently provided callback.
    QueryNextStatusCallback callback_;
  };

  void SetUp() override {
    helper_ = std::make_unique<PowerStatusHelper>(monitor_.cb());
  }

  // Set up |helper_| to be in a state that should record. Returns the bucket.
  // |alternate| just causes us to create a different recordable bucket.
  int MakeRecordable(bool alternate = false) {
    helper_->SetIsPlaying(true);
    media::PipelineMetadata metadata;
    metadata.has_video = true;
    metadata.video_decoder_config = media::VideoDecoderConfig(
        media::VideoCodec::kH264, media::H264PROFILE_MAIN,
        media::VideoDecoderConfig::AlphaMode::kIsOpaque,
        media::VideoColorSpace(), media::VideoTransformation(),
        gfx::Size(0, 0),        /* coded_size */
        gfx::Rect(0, 0),        /* visible rect */
        gfx::Size(640, 360),    /* natural size */
        std::vector<uint8_t>(), /* extra_data */
        media::EncryptionScheme::kUnencrypted);
    helper_->SetMetadata(metadata);
    helper_->SetAverageFrameRate(60);
    // Use |alternate| to set fullscreen state, since that should still be
    // recordable but in a different bucket.
    helper_->SetIsFullscreen(alternate);
    base::RunLoop().RunUntilIdle();
    helper_->UpdatePowerExperimentState(true);
    base::RunLoop().RunUntilIdle();

    return PowerStatusHelper::kCodecBitsH264 |
           PowerStatusHelper::kResolution360p |
           PowerStatusHelper::kFrameRate60 |
           (alternate ? PowerStatusHelper::kFullScreenYes
                      : PowerStatusHelper::kFullScreenNo);
  }

 protected:
  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  // Previous total histogram counts.  Note that we record the total in msec,
  // rather than as a TimeDelta, so that we round the same way as the helper.
  int total_battery_delta = 0;
  int total_time_delta = 0;  // msec

  MockBatteryMonitor monitor_;

  // Helper under test
  std::unique_ptr<PowerStatusHelper> helper_;

  base::HistogramTester histogram_tester_;
};

TEST_F(PowerStatusHelperTest, EmptyPendingRemoteIsOkay) {
  // Enable power monitoring, but have the callback fail to provide a remote.
  // This should be handled gracefully.

  // Ask |monitor_| not to provide a remote, and expect that |helper_| asks.
  monitor_.remote_type_ = MockBatteryMonitor::RemoteType::kEmpty;
  EXPECT_CALL(monitor_, DidGetBatteryMonitor()).Times(1);
  MakeRecordable();
}

TEST_F(PowerStatusHelperTest, UnboundPendingRemoteIsOkay) {
  // TODO: this doesn't run the "is bound" part.  maybe we should just delete
  // the "is bound" part, or switch to a disconnection handler, etc.
  monitor_.remote_type_ = MockBatteryMonitor::RemoteType::kDisconnected;
  EXPECT_CALL(monitor_, DidGetBatteryMonitor()).Times(1);
  MakeRecordable();
}

TEST_F(PowerStatusHelperTest, BasicReportingWithFractionalAmounts) {
  // Send three power updates, and verify that an update is called for the
  // last two.  The update should be fractional, so that some of it is rolled
  // over to the next call.
  EXPECT_CALL(monitor_, DidGetBatteryMonitor()).Times(1);
  EXPECT_CALL(monitor_, DidQueryNextStatus()).Times(1);
  MakeRecordable();

  const float baseline_level = 0.9;

  // This should be the baseline.
  EXPECT_CALL(monitor_, DidQueryNextStatus()).Times(1);
  monitor_.ProvidePowerUpdate(false, baseline_level);
}

TEST_F(PowerStatusHelperTest, ChargingResetsBaseline) {
  // Send some power updates, then send an update that's marked as 'charging'.
  // Make sure that the baseline resets.
  EXPECT_CALL(monitor_, DidGetBatteryMonitor()).Times(1);
  EXPECT_CALL(monitor_, DidQueryNextStatus()).Times(1);
  MakeRecordable();

  const float fake_baseline_level = 0.95;
  const float baseline_level = 0.9;
  const float second_level = baseline_level - 0.10;

  // Send the fake baseline.
  EXPECT_CALL(monitor_, DidQueryNextStatus()).Times(1);
  monitor_.ProvidePowerUpdate(false, fake_baseline_level);

  // Send an update that's marked as charging.
  EXPECT_CALL(monitor_, DidQueryNextStatus()).Times(1);
  monitor_.ProvidePowerUpdate(true, second_level);

  // This should be the correct baseline.
  EXPECT_CALL(monitor_, DidQueryNextStatus()).Times(1);
  monitor_.ProvidePowerUpdate(false, baseline_level);
}

TEST_F(PowerStatusHelperTest, ExperimentStateStopsRecording) {
  // Verify that stopping the power experiment stops recording.
  EXPECT_CALL(monitor_, DidGetBatteryMonitor()).Times(1);
  EXPECT_CALL(monitor_, DidQueryNextStatus()).Times(1);
  MakeRecordable();

  EXPECT_CALL(monitor_, DidDisconnect()).Times(1);
  EXPECT_CALL(monitor_, DidQueryNextStatus()).Times(0);
  helper_->UpdatePowerExperimentState(false);
  base::RunLoop().RunUntilIdle();

  // Call the callback to make sure nothing bad happens.  It should be ignored,
  // since it shouldn't use battery updates after the experiment stops.
  monitor_.ProvidePowerUpdate(false, 1.0);
}

TEST_F(PowerStatusHelperTest, ChangingBucketsWorks) {
  // Switch buckets mid-recording, and make sure that we get a new bucket and
  // use a new baseline.
  EXPECT_CALL(monitor_, DidGetBatteryMonitor()).Times(1);
  EXPECT_CALL(monitor_, DidQueryNextStatus()).Times(1);
  auto first_bucket = MakeRecordable(false);

  const float fake_baseline_level = 0.95;
  const float baseline_level = 0.9;

  // Send the fake baseline.
  EXPECT_CALL(monitor_, DidQueryNextStatus()).Times(1);
  monitor_.ProvidePowerUpdate(false, fake_baseline_level);

  // Switch buckets.
  auto second_bucket = MakeRecordable(true);
  ASSERT_NE(first_bucket, second_bucket);

  // This should be the correct baseline.
  EXPECT_CALL(monitor_, DidQueryNextStatus()).Times(1);
  monitor_.ProvidePowerUpdate(false, baseline_level);
}

TEST_F(PowerStatusHelperTest, UnbucketedVideoStopsRecording) {
  // If we switch to video that doesn't have a bucket, then recording should
  // stop too.
  EXPECT_CALL(monitor_, DidGetBatteryMonitor()).Times(1);
  EXPECT_CALL(monitor_, DidQueryNextStatus()).Times(1);
  MakeRecordable();

  // Should disconnect when we send bad params.
  EXPECT_CALL(monitor_, DidDisconnect()).Times(1);
  EXPECT_CALL(monitor_, DidQueryNextStatus()).Times(0);
  helper_->SetIsPlaying(false);
  base::RunLoop().RunUntilIdle();
}

TEST_F(PowerStatusHelperTest, UnbucketedFrameRateStopsRecording) {
  // If we switch to an unbucketed frame rate, then it should stop recording.
  EXPECT_CALL(monitor_, DidGetBatteryMonitor()).Times(1);
  EXPECT_CALL(monitor_, DidQueryNextStatus()).Times(1);
  MakeRecordable();

  // Should disconnect when we send bad params.
  EXPECT_CALL(monitor_, DidDisconnect()).Times(1);
  EXPECT_CALL(monitor_, DidQueryNextStatus()).Times(0);
  helper_->SetAverageFrameRate({});
  base::RunLoop().RunUntilIdle();
}

using PlaybackParamsTuple = std::tuple<bool,                    /* is_playing */
                                       bool,                    /* has_video */
                                       PowerStatusHelper::Bits, /* codec */
                                       PowerStatusHelper::Bits, /* resolution */
                                       PowerStatusHelper::Bits, /* frame rate */
                                       PowerStatusHelper::Bits /* full screen */
                                       >;

class PowerStatusHelperBucketTest
    : public testing::TestWithParam<PlaybackParamsTuple> {
 public:
  std::optional<int> BucketFor(bool is_playing,
                               bool has_video,
                               media::VideoCodec codec,
                               media::VideoCodecProfile profile,
                               gfx::Size coded_size,
                               bool is_fullscreen,
                               std::optional<int> average_fps) {
    return PowerStatusHelper::BucketFor(is_playing, has_video, codec, profile,
                                        coded_size, is_fullscreen, average_fps);
  }
};

TEST_P(PowerStatusHelperBucketTest, TestBucket) {
  // Construct a params that should end up in the bucket specified by the test
  // parameter, if one exists.
  bool expect_bucket = true;

  bool is_playing = std::get<0>(GetParam());
  bool has_video = std::get<1>(GetParam());

  // We must be playing video to get a bucket.
  if (!is_playing || !has_video)
    expect_bucket = false;

  auto codec_bits = std::get<2>(GetParam());
  media::VideoCodec codec;
  media::VideoCodecProfile profile;
  if (codec_bits == PowerStatusHelper::Bits::kCodecBitsH264) {
    codec = media::VideoCodec::kH264;
    profile = media::H264PROFILE_MAIN;
  } else if (codec_bits == PowerStatusHelper::Bits::kCodecBitsVP9Profile0) {
    codec = media::VideoCodec::kVP9;
    profile = media::VP9PROFILE_PROFILE0;
  } else if (codec_bits == PowerStatusHelper::Bits::kCodecBitsVP9Profile2) {
    codec = media::VideoCodec::kVP9;
    profile = media::VP9PROFILE_PROFILE2;
  } else {
    // Some unsupported codec.
    codec = media::VideoCodec::kVP8;
    profile = media::VIDEO_CODEC_PROFILE_UNKNOWN;
    expect_bucket = false;
  }

  auto res = std::get<3>(GetParam());
  gfx::Size coded_size;
  if (res == PowerStatusHelper::Bits::kResolution360p) {
    coded_size = gfx::Size(640, 360);
  } else if (res == PowerStatusHelper::Bits::kResolution720p) {
    coded_size = gfx::Size(1280, 720);
  } else if (res == PowerStatusHelper::Bits::kResolution1080p) {
    coded_size = gfx::Size(1920, 1080);
  } else {
    coded_size = gfx::Size(1234, 5678);
    expect_bucket = false;
  }

  auto fps = std::get<4>(GetParam());
  std::optional<int> average_fps;
  if (fps == PowerStatusHelper::Bits::kFrameRate30) {
    average_fps = 30;
  } else if (fps == PowerStatusHelper::Bits::kFrameRate60) {
    average_fps = 60;
  } else {
    average_fps = 90;
    expect_bucket = false;
  }

  bool is_fullscreen =
      (std::get<5>(GetParam()) == PowerStatusHelper::Bits::kFullScreenYes);

  auto bucket = BucketFor(is_playing, has_video, codec, profile, coded_size,
                          is_fullscreen, average_fps);
  if (!expect_bucket) {
    EXPECT_FALSE(bucket);
  } else {
    EXPECT_EQ(*bucket, std::get<2>(GetParam()) | std::get<3>(GetParam()) |
                           std::get<4>(GetParam()) | std::get<5>(GetParam()));
  }
}

// Instantiate all valid combinations, plus some that aren't.
INSTANTIATE_TEST_SUITE_P(
    All,
    PowerStatusHelperBucketTest,
    Combine(Bool(),
            Bool(),
            Values(PowerStatusHelper::Bits::kCodecBitsH264,
                   PowerStatusHelper::Bits::kCodecBitsVP9Profile0,
                   PowerStatusHelper::Bits::kCodecBitsVP9Profile2,
                   PowerStatusHelper::Bits::kNotAValidBitForTesting),
            Values(PowerStatusHelper::Bits::kResolution360p,
                   PowerStatusHelper::Bits::kResolution720p,
                   PowerStatusHelper::Bits::kResolution1080p,
                   PowerStatusHelper::Bits::kNotAValidBitForTesting),
            Values(PowerStatusHelper::Bits::kFrameRate30,
                   PowerStatusHelper::Bits::kFrameRate60,
                   PowerStatusHelper::Bits::kNotAValidBitForTesting),
            Values(PowerStatusHelper::Bits::kFullScreenNo,
                   PowerStatusHelper::Bits::kFullScreenYes)));

}  // namespace blink

"""

```