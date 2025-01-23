Response:
The user wants to understand the functionality of the provided C++ source code file, which is a unit test file for the Chromium Blink engine.

Here's a breakdown of the thought process to answer the user's request:

1. **Identify the core purpose:** The file name `media_stream_constraints_util_video_device_test.cc` and the inclusion of `<gtest/gtest.h>` strongly suggest this is a unit test file. The name also hints that it's testing functionality related to video device constraints within the media stream.

2. **Examine the includes:** The included headers provide clues about the tested functionalities:
    * `media_stream_constraints_util_video_device.h`: This is likely the main code being tested. It probably contains functions to select video capture settings based on constraints.
    * `<algorithm>`, `<optional>`, `<utility>`: Standard C++ utilities used in the test logic.
    * `"base/memory/raw_ptr.h"`: Indicates the use of raw pointers (with potential ownership considerations).
    * `"media/base/limits.h"`: Defines limits related to media, potentially video resolution, frame rate, etc.
    * `"third_party/blink/public/platform/web_string.h"`: Blink's string type.
    * `"third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"`:  Defines the `MediaStreamVideoSource` class, which likely represents a video source in the media stream API.
    * `"third_party/blink/renderer/modules/mediastream/media_constraints.h"`: Defines the `MediaConstraints` class, which is crucial for understanding how video settings are selected.
    * `"third_party/blink/renderer/modules/mediastream/mock_constraint_factory.h"`: A mock object for creating `MediaConstraints` for testing.
    * `"third_party/blink/renderer/platform/testing/task_environment.h"`: Used for setting up the testing environment within Blink's context.
    * `"third_party/blink/renderer/platform/wtf/vector.h"`: Blink's vector implementation.

3. **Analyze the test setup (`SetUp` method):**  This method initializes test data. It creates several `VideoInputDeviceCapabilities` objects, each representing a different virtual video device with specific supported formats (resolutions and frame rates), facing modes, and control capabilities. This setup is crucial for simulating different hardware scenarios.

4. **Examine the helper functions:** Functions like `CheckTrackAdapterSettingsEqualsResolution`, `CheckTrackAdapterSettingsEqualsFrameRate`, `CheckTrackAdapterSettingsEqualsFormat`, `AspectRatio`, and `SelectSettingsVideoDeviceCapture` provide insights into the testing methodology. They are used to assert the correctness of the selected video settings based on different constraint scenarios.

5. **Analyze the test cases:**  The `TEST_F` macros define individual test cases. The names of the test cases (e.g., `Unconstrained`, `OverconstrainedOnDeviceID`, `MandatoryDeviceID`) clearly indicate the type of constraint being tested.

6. **Connect to Web APIs (JavaScript/HTML/CSS):**  Think about how the tested functionality relates to the WebRTC API in browsers. The constraints tested in this file directly correspond to constraints that can be specified in JavaScript when calling `getUserMedia()` to access the user's camera.

7. **Infer Logic and Scenarios:**  By analyzing the test cases, infer the logic being tested. For example, the "Overconstrained" tests verify that if a mandatory constraint cannot be met, no suitable device or format is selected. The "Mandatory" and "Ideal" tests check how the selection algorithm behaves when specific constraints are applied.

8. **Consider User Errors:** Think about common mistakes developers might make when using the WebRTC API. For instance, specifying an impossible resolution or frame rate.

9. **Trace User Operations (Debugging Clues):** Imagine how a user's interaction with a webpage might lead to this code being executed. A user granting camera access via `getUserMedia()` triggers the constraint evaluation logic.

10. **Synthesize the information:**  Organize the findings into a clear and concise summary, addressing all aspects of the user's request (functionality, relation to web technologies, logical reasoning, user errors, debugging).

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Maybe this is about encoding or decoding video.
* **Correction:** The file path `modules/mediastream` and the presence of `MediaConstraints` strongly point to the WebRTC/getUserMedia API and device selection.

* **Initial thought:** Focus only on the C++ code.
* **Refinement:** Explicitly connect the C++ code to its counterpart in JavaScript (the `getUserMedia()` API and its constraint options) for better understanding.

* **Initial thought:** Just list the test cases.
* **Refinement:** Group the test cases by the type of constraint being tested (unconstrained, overconstrained, mandatory, ideal) to provide a more structured explanation of the file's functionality.
好的，让我们来分析一下 `blink/renderer/modules/mediastream/media_stream_constraints_util_video_device_test.cc` 这个文件的功能。

**文件功能归纳:**

这个 C++ 文件是 Chromium Blink 引擎中用于测试 **视频设备约束处理逻辑** 的单元测试文件。 它的主要功能是：

1. **测试 `MediaStreamConstraintsUtil` 中与视频设备相关的约束选择和应用逻辑。**  具体来说，它测试了当给定的视频设备能力集合和用户指定的媒体约束时，系统如何选择最佳的视频设备和配置（例如分辨率、帧率等）。

2. **模拟各种视频设备的能力。**  文件中创建了多个 `VideoInputDeviceCapabilities` 对象，每个对象代表一个具有不同特性（例如支持的分辨率、帧率、是否支持缩放等）的虚拟视频设备。

3. **模拟各种媒体约束条件。**  使用 `MockConstraintFactory` 来创建不同的 `MediaConstraints` 对象，这些对象代表了用户在 JavaScript 中通过 `getUserMedia` API 设定的各种约束条件，例如指定设备 ID、分组 ID、朝向模式、分辨率、帧率等。

4. **验证在不同约束条件下，系统是否能够正确选择合适的视频设备和配置。**  通过一系列的 `TEST_F` 测试用例，该文件验证了在各种约束组合下，`SelectSettingsVideoDeviceCapture` 函数是否返回了预期的结果，包括选择的设备 ID、配置参数以及 track adapter 设置。

5. **测试约束的优先级和匹配逻辑。**  通过区分 "Mandatory"（强制）和 "Ideal"（理想）约束，测试系统如何满足强制约束，并在满足强制约束的前提下，尽可能地满足理想约束。

6. **测试当约束无法满足时，系统是否能够正确识别并报告失败的约束。** "Overconstrained" 测试用例专门用于验证当给定的设备能力无法满足所有强制约束时，系统会报告哪个约束无法满足。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件直接关联到 Web 开发者可以通过 JavaScript 使用的 `getUserMedia` API。

* **JavaScript `getUserMedia()` API:** Web 开发者可以使用 `getUserMedia()` 来请求用户的摄像头和麦克风权限。在 `getUserMedia()` 的参数中，开发者可以指定各种约束条件，例如：
    ```javascript
    navigator.mediaDevices.getUserMedia({
      video: {
        deviceId: "some-device-id",
        width: { min: 640, ideal: 1280 },
        frameRate: { ideal: 30 }
      }
    })
    .then(function(stream) { /* 使用 stream */ })
    .catch(function(error) { /* 处理错误 */ });
    ```
    这些 JavaScript 中指定的约束最终会被传递到 Blink 引擎中进行处理，而 `media_stream_constraints_util_video_device_test.cc` 正是测试 Blink 引擎如何解析和应用这些约束的。

* **HTML 和 CSS:** HTML 用于构建网页结构，CSS 用于设置网页样式。 虽然这个 C++ 文件本身不直接涉及 HTML 和 CSS 的渲染，但它所测试的功能是实现 WebRTC 功能的基础，而 WebRTC 通常用于在 HTML 页面上显示视频流。 例如，一个 HTML 元素 `<video>` 可以用来显示从 `getUserMedia()` 获取的视频流。

**逻辑推理示例 (假设输入与输出):**

**假设输入:**

* **设备能力:** 包含两个虚拟摄像头：
    * 摄像头 A: 支持分辨率 640x480, 1280x720
    * 摄像头 B: 支持分辨率 320x240, 640x480
* **用户约束:**  `{ video: { width: { exact: 640 } } }` (要求视频宽度必须是 640)

**逻辑推理过程:**

1. `SelectSettingsVideoDeviceCapture` 函数会遍历可用的视频设备。
2. 对于摄像头 A，检查其支持的格式。 发现 640x480 满足宽度为 640 的约束。
3. 对于摄像头 B，检查其支持的格式。 发现 640x480 也满足宽度为 640 的约束。
4. 由于两个摄像头都满足强制约束，系统可能会根据其他因素（例如默认偏好）来选择。 在没有其他约束的情况下，通常会选择第一个满足条件的设备。

**假设输出:**

* 选择摄像头 A (因为它是第一个满足条件的设备)。
* 选择的配置为 640x480。

**用户或编程常见的使用错误举例:**

1. **指定了设备不存在的 `deviceId`:**  用户在 JavaScript 中指定了一个不存在的摄像头 ID。 测试用例 `OverconstrainedOnDeviceID` 就是模拟这种情况，验证系统是否能正确报告错误。
    ```javascript
    navigator.mediaDevices.getUserMedia({ video: { deviceId: "non-existent-id" } })
    .catch(error => console.error(error.name)); // 应该会捕获到 OverconstrainedError
    ```

2. **指定了设备不支持的分辨率或帧率:** 用户在 JavaScript 中指定了某个摄像头根本不支持的分辨率。 例如，某个摄像头只支持 720p，但用户要求 4K 分辨率。  测试用例如 `OverconstrainedOnHeight` 和 `OverconstrainedOnWidth` 就是模拟这种情况。
    ```javascript
    navigator.mediaDevices.getUserMedia({ video: { width: { exact: 4096 } } })
    .catch(error => console.error(error.name)); // 可能会捕获到 OverconstrainedError
    ```

3. **约束条件冲突:** 用户设置了相互冲突的约束，例如同时要求最小宽度和最大宽度为一个不可能达到的值。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户访问一个网页:** 用户在浏览器中打开一个使用了 WebRTC 功能的网页。
2. **网页 JavaScript 代码请求摄像头权限:** 网页的 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia()` 并传入包含视频约束的对象。
3. **浏览器处理 `getUserMedia()` 请求:** 浏览器接收到请求后，会根据用户设置的约束以及当前可用的视频设备能力，开始进行设备选择和配置匹配。
4. **Blink 引擎执行约束处理逻辑:**  Blink 引擎中的 `MediaStreamConstraintsUtil` 类及其相关的视频设备处理逻辑会被调用，其中 `SelectSettingsVideoDeviceCapture` 函数会被执行。
5. **执行到 `media_stream_constraints_util_video_device_test.cc` 中测试的代码:** 在开发和测试阶段，开发者会运行这些单元测试来验证 `SelectSettingsVideoDeviceCapture` 函数在各种场景下的行为是否符合预期。 如果在实际使用中出现问题，开发者可能会通过调试器单步执行相关代码，甚至回溯到这些单元测试来理解问题的根源。

**总结（第一部分功能归纳）:**

`blink/renderer/modules/mediastream/media_stream_constraints_util_video_device_test.cc` 文件的主要功能是 **测试 Blink 引擎中处理视频设备约束的核心逻辑**。 它通过模拟各种设备能力和用户约束，验证系统是否能够正确选择合适的视频设备和配置，并能在约束无法满足时报告错误。  这直接关系到 Web 开发者使用 `getUserMedia()` API 获取用户摄像头权限的功能。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_video_device_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_video_device.h"

#include <algorithm>
#include <optional>
#include <utility>

#include "base/memory/raw_ptr.h"
#include "media/base/limits.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints.h"
#include "third_party/blink/renderer/modules/mediastream/mock_constraint_factory.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

const char kDeviceID1[] = "fake_device_1";
const char kDeviceID2[] = "fake_device_2";
const char kDeviceID3[] = "fake_device_3";
const char kDeviceID4[] = "fake_device_4";
const char kDeviceID5[] = "fake_device_5";

const char kGroupID1[] = "fake_group_1";
const char kGroupID2[] = "fake_group_2";
const char kGroupID3[] = "fake_group_3";
const char kGroupID4[] = "fake_group_4";
const char kGroupID5[] = "fake_group_5";

void CheckTrackAdapterSettingsEqualsResolution(
    const VideoCaptureSettings& settings) {
  EXPECT_FALSE(settings.track_adapter_settings().target_size());
  EXPECT_EQ(1.0 / settings.Format().frame_size.height(),
            settings.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(settings.Format().frame_size.width(),
            settings.track_adapter_settings().max_aspect_ratio());
}

void CheckTrackAdapterSettingsEqualsFrameRate(
    const VideoCaptureSettings& settings,
    std::optional<double> value = std::nullopt) {
  EXPECT_EQ(value, settings.track_adapter_settings().max_frame_rate());
}

void CheckTrackAdapterSettingsEqualsFormat(
    const VideoCaptureSettings& settings) {
  CheckTrackAdapterSettingsEqualsResolution(settings);
  CheckTrackAdapterSettingsEqualsFrameRate(settings);
}

double AspectRatio(const media::VideoCaptureFormat& format) {
  return static_cast<double>(format.frame_size.width()) /
         static_cast<double>(format.frame_size.height());
}

VideoCaptureSettings SelectSettingsVideoDeviceCapture(
    const VideoDeviceCaptureCapabilities& capabilities,
    const MediaConstraints& constraints) {
  return SelectSettingsVideoDeviceCapture(
      capabilities, constraints, MediaStreamVideoSource::kDefaultWidth,
      MediaStreamVideoSource::kDefaultHeight,
      MediaStreamVideoSource::kDefaultFrameRate);
}

}  // namespace

class MediaStreamConstraintsUtilVideoDeviceTest : public testing::Test {
 public:
  void SetUp() override {
    // Default device. It is default because it is the first in the enumeration.
    VideoInputDeviceCapabilities device;
    device.device_id = kDeviceID1;
    device.group_id = kGroupID1;
    device.facing_mode = mojom::blink::FacingMode::kNone;
    device.formats = {
        media::VideoCaptureFormat(gfx::Size(200, 200), 40.0f,
                                  media::PIXEL_FORMAT_I420),
        // This entry is is the closest to defaults.
        media::VideoCaptureFormat(gfx::Size(500, 500), 40.0f,
                                  media::PIXEL_FORMAT_I420),
        media::VideoCaptureFormat(gfx::Size(1000, 1000), 20.0f,
                                  media::PIXEL_FORMAT_I420),
    };
    device.control_support.pan = false;
    device.control_support.tilt = false;
    device.control_support.zoom = false;
    capabilities_.device_capabilities.push_back(std::move(device));

    // A low-resolution device.
    device.device_id = kDeviceID2;
    device.group_id = kGroupID2;
    device.facing_mode = mojom::blink::FacingMode::kEnvironment;
    device.formats = {
        media::VideoCaptureFormat(gfx::Size(40, 30), 20.0f,
                                  media::PIXEL_FORMAT_I420),
        media::VideoCaptureFormat(gfx::Size(320, 240), 30.0f,
                                  media::PIXEL_FORMAT_I420),
        // This format has defaults for all settings
        media::VideoCaptureFormat(
            gfx::Size(MediaStreamVideoSource::kDefaultWidth,
                      MediaStreamVideoSource::kDefaultHeight),
            MediaStreamVideoSource::kDefaultFrameRate,
            media::PIXEL_FORMAT_I420),
        media::VideoCaptureFormat(gfx::Size(800, 600), 20.0f,
                                  media::PIXEL_FORMAT_I420),
    };
    device.control_support.pan = true;
    device.control_support.tilt = true;
    device.control_support.zoom = true;
    capabilities_.device_capabilities.push_back(std::move(device));

    // A high-resolution device.
    device.device_id = kDeviceID3;
    device.group_id = kGroupID3;
    device.facing_mode = mojom::blink::FacingMode::kUser;
    device.formats = {
        media::VideoCaptureFormat(gfx::Size(600, 400), 10.0f,
                                  media::PIXEL_FORMAT_I420),
        media::VideoCaptureFormat(gfx::Size(640, 480), 10.0f,
                                  media::PIXEL_FORMAT_I420),
        // This format has default for all settings, except that the resolution
        // is inverted.
        media::VideoCaptureFormat(
            gfx::Size(MediaStreamVideoSource::kDefaultHeight,
                      MediaStreamVideoSource::kDefaultWidth),
            MediaStreamVideoSource::kDefaultFrameRate,
            media::PIXEL_FORMAT_I420),
        // This format has defaults for all settings
        media::VideoCaptureFormat(
            gfx::Size(MediaStreamVideoSource::kDefaultWidth,
                      MediaStreamVideoSource::kDefaultHeight),
            MediaStreamVideoSource::kDefaultFrameRate,
            media::PIXEL_FORMAT_I420),
        media::VideoCaptureFormat(gfx::Size(1280, 720), 60.0f,
                                  media::PIXEL_FORMAT_I420),
        media::VideoCaptureFormat(gfx::Size(1920, 1080), 60.0f,
                                  media::PIXEL_FORMAT_I420),
        media::VideoCaptureFormat(gfx::Size(2304, 1536), 10.0f,
                                  media::PIXEL_FORMAT_I420),
    };
    device.control_support.pan = true;
    device.control_support.tilt = true;
    device.control_support.zoom = true;
    capabilities_.device_capabilities.push_back(std::move(device));

    // A depth capture device.
    device.device_id = kDeviceID4;
    device.group_id = kGroupID4;
    device.facing_mode = mojom::blink::FacingMode::kEnvironment;
    device.formats = {media::VideoCaptureFormat(gfx::Size(640, 480), 30.0f,
                                                media::PIXEL_FORMAT_Y16)};
    device.control_support.pan = true;
    device.control_support.tilt = true;
    device.control_support.zoom = true;
    capabilities_.device_capabilities.push_back(std::move(device));

    // A device that reports invalid frame rates. These devices exist and should
    // be supported if no constraints are placed on the frame rate.
    device.device_id = kDeviceID5;
    device.group_id = kGroupID5;
    device.facing_mode = mojom::blink::FacingMode::kNone;
    device.formats = {
        media::VideoCaptureFormat(
            gfx::Size(MediaStreamVideoSource::kDefaultWidth,
                      MediaStreamVideoSource::kDefaultHeight),
            0.0f, media::PIXEL_FORMAT_I420),
        media::VideoCaptureFormat(gfx::Size(500, 500), 0.1f,
                                  media::PIXEL_FORMAT_I420),
    };
    device.control_support.pan = true;
    device.control_support.tilt = true;
    device.control_support.zoom = true;
    capabilities_.device_capabilities.push_back(std::move(device));

    capabilities_.noise_reduction_capabilities = {
        std::optional<bool>(),
        std::optional<bool>(true),
        std::optional<bool>(false),
    };

    default_device_ = &capabilities_.device_capabilities[0];
    low_res_device_ = &capabilities_.device_capabilities[1];
    high_res_device_ = &capabilities_.device_capabilities[2];
    invalid_frame_rate_device_ = &capabilities_.device_capabilities[4];
    default_closest_format_ = &default_device_->formats[1];
    low_res_closest_format_ = &low_res_device_->formats[2];
    high_res_closest_format_ = &high_res_device_->formats[3];
    high_res_highest_format_ = &high_res_device_->formats[6];
  }

 protected:
  VideoCaptureSettings SelectSettings() {
    MediaConstraints constraints = constraint_factory_.CreateMediaConstraints();
    return SelectSettingsVideoDeviceCapture(capabilities_, constraints);
  }

  base::expected<Vector<VideoCaptureSettings>, std::string>
  SelectEligibleSettings() {
    MediaConstraints constraints = constraint_factory_.CreateMediaConstraints();
    return SelectEligibleSettingsVideoDeviceCapture(
        capabilities_, constraints, MediaStreamVideoSource::kDefaultWidth,
        MediaStreamVideoSource::kDefaultHeight,
        MediaStreamVideoSource::kDefaultFrameRate);
  }

  static WTF::Vector<BooleanConstraint MediaTrackConstraintSetPlatform::*>
  BooleanImageCaptureConstraints() {
    return {
        &MediaTrackConstraintSetPlatform::torch,
        &MediaTrackConstraintSetPlatform::background_blur,
        &MediaTrackConstraintSetPlatform::background_segmentation_mask,
        &MediaTrackConstraintSetPlatform::eye_gaze_correction,
        &MediaTrackConstraintSetPlatform::face_framing,
    };
  }

  static WTF::Vector<DoubleConstraint MediaTrackConstraintSetPlatform::*>
  DoubleImageCaptureConstraints() {
    return {
        &MediaTrackConstraintSetPlatform::exposure_compensation,
        &MediaTrackConstraintSetPlatform::exposure_time,
        &MediaTrackConstraintSetPlatform::color_temperature,
        &MediaTrackConstraintSetPlatform::iso,
        &MediaTrackConstraintSetPlatform::brightness,
        &MediaTrackConstraintSetPlatform::contrast,
        &MediaTrackConstraintSetPlatform::saturation,
        &MediaTrackConstraintSetPlatform::sharpness,
        &MediaTrackConstraintSetPlatform::focus_distance,
    };
  }

  static WTF::Vector<DoubleConstraint MediaTrackConstraintSetPlatform::*>
  PanTiltZoomConstraints() {
    return {
        &MediaTrackConstraintSetPlatform::pan,
        &MediaTrackConstraintSetPlatform::tilt,
        &MediaTrackConstraintSetPlatform::zoom,
    };
  }

  test::TaskEnvironment task_environment_;
  VideoDeviceCaptureCapabilities capabilities_;
  raw_ptr<const VideoInputDeviceCapabilities> default_device_;
  raw_ptr<const VideoInputDeviceCapabilities> low_res_device_;
  raw_ptr<const VideoInputDeviceCapabilities> high_res_device_;
  raw_ptr<const VideoInputDeviceCapabilities> invalid_frame_rate_device_;
  // Closest formats to the default settings.
  raw_ptr<const media::VideoCaptureFormat> default_closest_format_;
  raw_ptr<const media::VideoCaptureFormat> low_res_closest_format_;
  raw_ptr<const media::VideoCaptureFormat> high_res_closest_format_;
  raw_ptr<const media::VideoCaptureFormat> high_res_highest_format_;

  MockConstraintFactory constraint_factory_;
};

// The Unconstrained test checks the default selection criteria.
TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, Unconstrained) {
  constraint_factory_.Reset();
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // Should select the default device with closest-to-default settings.
  EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(*default_closest_format_, result.Format());
  // Should select default settings for other constraints.
  EXPECT_EQ(std::optional<bool>(), result.noise_reduction());
}

// The "Overconstrained" tests verify that failure of any single required
// constraint results in failure to select a candidate.
TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, OverconstrainedOnDeviceID) {
  constraint_factory_.Reset();
  constraint_factory_.basic().device_id.SetExact("NONEXISTING");
  auto result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().device_id.GetName(),
            result.failed_constraint_name());
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, OverconstrainedOnGroupID) {
  constraint_factory_.Reset();
  constraint_factory_.basic().group_id.SetExact("NONEXISTING");
  auto result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().group_id.GetName(),
            result.failed_constraint_name());
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, OverconstrainedOnFacingMode) {
  constraint_factory_.Reset();
  // No device in |capabilities_| has facing mode equal to LEFT.
  constraint_factory_.basic().facing_mode.SetExact("left");
  auto result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().facing_mode.GetName(),
            result.failed_constraint_name());
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       OverconstrainedOnEmptyFacingMode) {
  constraint_factory_.Reset();
  // Empty is not a valid facingMode value.
  constraint_factory_.basic().facing_mode.SetExact("");
  auto result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().facing_mode.GetName(),
            result.failed_constraint_name());
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       OverconstrainedOnInvalidResizeMode) {
  constraint_factory_.Reset();
  constraint_factory_.basic().resize_mode.SetExact("invalid");
  auto result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().resize_mode.GetName(),
            result.failed_constraint_name());
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       OverconstrainedOnEmptyResizeMode) {
  constraint_factory_.Reset();
  constraint_factory_.basic().resize_mode.SetExact("");
  auto result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().resize_mode.GetName(),
            result.failed_constraint_name());
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, OverconstrainedOnHeight) {
  constraint_factory_.Reset();
  constraint_factory_.basic().height.SetExact(123467890);
  auto result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().height.GetName(),
            result.failed_constraint_name());

  constraint_factory_.Reset();
  constraint_factory_.basic().height.SetMin(123467890);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().height.GetName(),
            result.failed_constraint_name());

  constraint_factory_.Reset();
  constraint_factory_.basic().height.SetMax(0);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().height.GetName(),
            result.failed_constraint_name());
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, OverconstrainedOnWidth) {
  constraint_factory_.Reset();
  constraint_factory_.basic().width.SetExact(123467890);
  auto result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().width.GetName(),
            result.failed_constraint_name());

  constraint_factory_.Reset();
  constraint_factory_.basic().width.SetMin(123467890);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().width.GetName(),
            result.failed_constraint_name());

  constraint_factory_.Reset();
  constraint_factory_.basic().width.SetMax(0);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().width.GetName(),
            result.failed_constraint_name());
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       OverconstrainedOnAspectRatio) {
  constraint_factory_.Reset();
  constraint_factory_.basic().aspect_ratio.SetExact(123467890.0);
  auto result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().aspect_ratio.GetName(),
            result.failed_constraint_name());

  constraint_factory_.Reset();
  constraint_factory_.basic().aspect_ratio.SetMin(123467890.0);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().aspect_ratio.GetName(),
            result.failed_constraint_name());

  constraint_factory_.Reset();
  // This value is lower than the minimum supported by the test devices.
  const double kLowAspectRatio = 0.00001;
  constraint_factory_.basic().aspect_ratio.SetMax(kLowAspectRatio);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().aspect_ratio.GetName(),
            result.failed_constraint_name());
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, OverconstrainedOnFrameRate) {
  constraint_factory_.Reset();
  constraint_factory_.basic().frame_rate.SetExact(123467890.0);
  auto result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().frame_rate.GetName(),
            result.failed_constraint_name());

  constraint_factory_.Reset();
  constraint_factory_.basic().frame_rate.SetMin(123467890.0);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().frame_rate.GetName(),
            result.failed_constraint_name());

  constraint_factory_.Reset();
  constraint_factory_.basic().frame_rate.SetMax(0.0);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().frame_rate.GetName(),
            result.failed_constraint_name());
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       OverconstrainedOnNoiseReduction) {
  // Simulate a system that does not support noise reduction.
  // Manually adding device capabilities because VideoDeviceCaptureCapabilities
  // is move only.
  VideoDeviceCaptureCapabilities capabilities;
  VideoInputDeviceCapabilities device;
  device.device_id = kDeviceID1;
  device.facing_mode = mojom::blink::FacingMode::kNone;
  device.formats = {
      media::VideoCaptureFormat(gfx::Size(200, 200), 40.0f,
                                media::PIXEL_FORMAT_I420),
  };
  capabilities.device_capabilities.push_back(std::move(device));
  capabilities.noise_reduction_capabilities = {std::optional<bool>(false)};

  constraint_factory_.Reset();
  constraint_factory_.basic().goog_noise_reduction.SetExact(true);
  auto constraints = constraint_factory_.CreateMediaConstraints();
  auto result = SelectSettingsVideoDeviceCapture(capabilities, constraints);
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().goog_noise_reduction.GetName(),
            result.failed_constraint_name());
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       OverconstrainedOnMandatoryPanTiltZoom) {
  for (auto& constraint : PanTiltZoomConstraints()) {
    constraint_factory_.Reset();
    constraint_factory_.basic().device_id.SetExact(default_device_->device_id);
    (constraint_factory_.basic().*constraint).SetMin(1);
    auto result = SelectSettings();
    EXPECT_FALSE(result.HasValue());
    EXPECT_EQ(constraint_factory_.basic().device_id.GetName(),
              result.failed_constraint_name());

    constraint_factory_.Reset();
    constraint_factory_.basic().device_id.SetExact(default_device_->device_id);
    (constraint_factory_.basic().*constraint).SetMax(1);
    result = SelectSettings();
    EXPECT_FALSE(result.HasValue());
    EXPECT_EQ(constraint_factory_.basic().device_id.GetName(),
              result.failed_constraint_name());

    constraint_factory_.Reset();
    constraint_factory_.basic().device_id.SetExact(default_device_->device_id);
    (constraint_factory_.basic().*constraint).SetExact(1);
    result = SelectSettings();
    EXPECT_FALSE(result.HasValue());
    EXPECT_EQ(constraint_factory_.basic().device_id.GetName(),
              result.failed_constraint_name());
  }
}

// The "Mandatory" and "Ideal" tests check that various selection criteria work
// for each individual constraint in the basic constraint set.
TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryDeviceID) {
  constraint_factory_.Reset();
  constraint_factory_.basic().device_id.SetExact(default_device_->device_id);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(*default_closest_format_, result.Format());
  CheckTrackAdapterSettingsEqualsFormat(result);

  constraint_factory_.basic().device_id.SetExact(low_res_device_->device_id);
  result = SelectSettings();
  EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(*low_res_closest_format_, result.Format());
  CheckTrackAdapterSettingsEqualsFormat(result);

  constraint_factory_.basic().device_id.SetExact(high_res_device_->device_id);
  result = SelectSettings();
  EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(*high_res_closest_format_, result.Format());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryGroupID) {
  constraint_factory_.Reset();
  constraint_factory_.basic().group_id.SetExact(default_device_->group_id);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(*default_closest_format_, result.Format());
  CheckTrackAdapterSettingsEqualsFormat(result);

  constraint_factory_.basic().group_id.SetExact(low_res_device_->group_id);
  result = SelectSettings();
  EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(*low_res_closest_format_, result.Format());
  CheckTrackAdapterSettingsEqualsFormat(result);

  constraint_factory_.basic().group_id.SetExact(high_res_device_->group_id);
  result = SelectSettings();
  EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(*high_res_closest_format_, result.Format());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryFacingMode) {
  constraint_factory_.Reset();
  constraint_factory_.basic().facing_mode.SetExact("environment");
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // Only the low-res device supports kEnvironment facing mode. Should select
  // default settings for everything else.
  EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(mojom::blink::FacingMode::kEnvironment,
            low_res_device_->facing_mode);
  EXPECT_EQ(*low_res_closest_format_, result.Format());
  CheckTrackAdapterSettingsEqualsFormat(result);

  constraint_factory_.basic().facing_mode.SetExact("user");
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // Only the high-res device supports kUser facing mode. Should select default
  // settings for everything else.
  EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(mojom::blink::FacingMode::kUser, high_res_device_->facing_mode);
  EXPECT_EQ(*high_res_closest_format_, result.Format());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryNoiseReduction) {
  constraint_factory_.Reset();
  const bool kNoiseReductionValues[] = {true, false};
  for (auto noise_reduction : kNoiseReductionValues) {
    constraint_factory_.basic().goog_noise_reduction.SetExact(noise_reduction);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(noise_reduction, result.noise_reduction());
    // The default device and settings closest to the default should be
    // selected.
    EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(*default_closest_format_, result.Format());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryExactHeight) {
  constraint_factory_.Reset();
  const int kHeight = MediaStreamVideoSource::kDefaultHeight;
  constraint_factory_.basic().height.SetExact(kHeight);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // All devices in |capabilities_| support the requested height. The algorithm
  // should prefer the first device that supports the requested height natively,
  // which is the low-res device.
  EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(kHeight, result.Height());
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());

  const int kLargeHeight = 1500;
  constraint_factory_.basic().height.SetExact(kLargeHeight);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // Only the high-res device at the highest resolution supports the requested
  // height, even if not natively.
  EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(*high_res_highest_format_, result.Format());
  EXPECT_EQ(kLargeHeight, result.track_adapter_settings().target_height());
  EXPECT_EQ(std::round(kLargeHeight * AspectRatio(*high_res_highest_format_)),
            result.track_adapter_settings().target_width());
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryMinHeight) {
  constraint_factory_.Reset();
  const int kHeight = MediaStreamVideoSource::kDefaultHeight;
  constraint_factory_.basic().height.SetMin(kHeight);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // All devices in |capabilities_| support the requested height range. The
  // algorithm should prefer the default device.
  EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
  EXPECT_LE(kHeight, result.Height());
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(static_cast<double>(result.Width()) / kHeight,
            result.track_adapter_settings().max_aspect_ratio());
  EXPECT_EQ(1.0 / result.Height(),
            result.track_adapter_settings().min_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);

  const int kLargeHeight = 1500;
  constraint_factory_.basic().height.SetMin(kLargeHeight);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // Only the high-res device at the highest resolution supports the requested
  // height range.
  EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(*high_res_highest_format_, result.Format());
  EXPECT_LE(kHeight, result.Height());
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(static_cast<double>(result.Width()) / kLargeHeight,
            result.track_adapter_settings().max_aspect_ratio());
  EXPECT_EQ(1.0 / result.Height(),
            result.track_adapter_settings().min_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryMaxHeight) {
  constraint_factory_.Reset();
  const int kLowHeight = 20;
  constraint_factory_.basic().height.SetMax(kLowHeight);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // All devices in |capabilities_| support the requested height range. The
  // algorithm should prefer the settings that natively exceed the requested
  // maximum by the lowest amount. In this case it is the low-res device.
  EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(low_res_device_->formats[0], result.Format());
  EXPECT_EQ(kLowHeight, result.track_adapter_settings().target_height());
  EXPECT_EQ(std::round(kLowHeight * AspectRatio(result.Format())),
            result.track_adapter_settings().target_width());
  EXPECT_EQ(static_cast<double>(result.Width()),
            result.track_adapter_settings().max_aspect_ratio());
  EXPECT_EQ(1.0 / kLowHeight,
            result.track_adapter_settings().min_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryHeightRange) {
  constraint_factory_.Reset();
  {
    const int kMinHeight = 480;
    const int kMaxHeight = 720;
    constraint_factory_.basic().height.SetMin(kMinHeight);
    constraint_factory_.basic().height.SetMax(kMaxHeight);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_GE(result.Height(), kMinHeight);
    EXPECT_LE(result.Height(), kMaxHeight);
    // All devices in |capabilities_| support the constraint range. The
    // algorithm should prefer the default device since it has at least one
    // native format (the closest-to-default format) included in the requested
    // range.
    EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(*default_closest_format_, result.Format());
    EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
    EXPECT_EQ(static_cast<double>(result.Width()) / kMinHeight,
              result.track_adapter_settings().max_aspect_ratio());
    EXPECT_EQ(1.0 / result.Height(),
              result.track_adapter_settings().min_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }

  {
    const int kMinHeight = 550;
    const int kMaxHeight = 650;
    constraint_factory_.basic().height.SetMin(kMinHeight);
    constraint_factory_.basic().height.SetMax(kMaxHeight);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_GE(result.Height(), kMinHeight);
    EXPECT_LE(result.Height(), kMaxHeight);
    // In this case, the algorithm should prefer the low-res device since it is
    // the first device with a native format (800x600) included in the requested
    // range.
    EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(800, result.Width());
    EXPECT_EQ(600, result.Height());
    EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
    EXPECT_EQ(static_cast<double>(result.Width()) / kMinHeight,
              result.track_adapter_settings().max_aspect_ratio());
    EXPECT_EQ(1.0 / result.Height(),
              result.track_adapter_settings().min_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }

  {
    const int kMinHeight = 700;
    const int kMaxHeight = 800;
    constraint_factory_.basic().height.SetMin(kMinHeight);
    constraint_factory_.basic().height.SetMax(kMaxHeight);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_GE(result.Height(), kMinHeight);
    EXPECT_LE(result.Height(), kMaxHeight);
    // In this case, the algorithm should prefer the high-res device since it is
    // the only device with a native format (1280x720) included in the requested
    // range.
    EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(1280, result.Width());
    EXPECT_EQ(720, result.Height());
    EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
    EXPECT_EQ(static_cast<double>(result.Width()) / kMinHeight,
              result.track_adapter_settings().max_aspect_ratio());
    EXPECT_EQ(1.0 / result.Height(),
              result.track_adapter_settings().min_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, IdealHeight) {
  constraint_factory_.Reset();
  {
    const int kIdealHeight = 480;
    constraint_factory_.basic().height.SetIdeal(kIdealHeight);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The algorithm should select the first device that supports the ideal
    // height natively.
    EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(kIdealHeight, result.Height());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  {
    const int kIdealHeight = 481;
    constraint_factory_.basic().height.SetIdeal(kIdealHeight);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // In this case, the default device is selected because it can satisfy the
    // ideal at a lower cost than the other devices (500 vs 600 or 720).
    // Note that a native resolution of 480 is further from the ideal than
    // 500 cropped to 480.
    EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(*default_closest_format_, result.Format());
    // The track is cropped to the ideal height, maintaining the source aspect
    // ratio.
    EXPECT_EQ(kIdealHeight, result.track_adapter_settings().target_height());
    EXPECT_EQ(std::round(kIdealHeight * AspectRatio(result.Format())),
              result.track_adapter_settings().target_width());
    EXPECT_EQ(result.Width(),
              result.track_adapter_settings().max_aspect_ratio());
    EXPECT_EQ(1.0 / result.Height(),
              result.track_adapter_settings().min_aspect_ratio());
    Ch
```