Response:
My goal is to analyze the given C++ code snippet and provide a comprehensive description of its functionality, focusing on its relation to web technologies, logical inferences, potential errors, debugging clues, and finally, a summary of its purpose.

Here's a breakdown of the thinking process:

1. **Understand the Code's Context:** The code is located within the `blink` rendering engine of Chromium, specifically in the `mediastream` module. The filename `media_stream_constraints_util_video_content_test.cc` strongly suggests it's a unit test file for functionalities related to video content constraints within media streams.

2. **Identify Key Components:** I started by looking for the most important elements:
    * **Includes:**  Headers like `media_stream_constraints_util_video_content.h`, `media_constraints.h`, and `mock_constraint_factory.h` point to the core functionality being tested and the testing infrastructure. The inclusion of `<cmath>`, `<string>`, and `testing/gtest/include/gtest/gtest.h` provides further context about mathematical operations, string handling, and the Google Test framework.
    * **Namespaces:**  The `blink` namespace is fundamental. The nested namespace `media_stream_constraints_util_video_content_test` is a common practice to avoid symbol collisions in large projects.
    * **Constants:**  `kDefaultScreenCastAspectRatio`, `kDefaultScreenCastWidth`, `kDefaultScreenCastHeight`, etc., suggest default or maximum/minimum values for screen capture settings.
    * **Helper Functions:**  Functions like `CheckNonResolutionDefaults`, `CheckNonFrameRateDefaults`, `CheckTrackAdapterSettingsEqualsFormat`, and `CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio` clearly perform assertions or checks on `VideoCaptureSettings` objects. These are likely used to verify expected behavior in tests.
    * **Test Fixture:** The `MediaStreamConstraintsUtilVideoContentTest` class, inheriting from `testing::Test`, sets up the environment for running tests. The `SelectSettings` method within this class is crucial, as it's likely the function under test, taking constraints and stream type as input.
    * **Individual Test Cases:**  The `TEST_F` macros define individual test scenarios. The names of these tests (e.g., `Unconstrained`, `OverconstrainedOnHeight`, `MandatoryDeviceID`, `IdealHeight`) provide strong hints about what aspects of the constraint handling are being tested.

3. **Infer Functionality from Test Names and Code:**
    * **`Unconstrained`:**  Tests the default behavior when no specific constraints are applied.
    * **`OverconstrainedOn...`:** Checks scenarios where constraints are set in a way that no valid settings can satisfy them. This helps ensure the constraint validation logic works correctly.
    * **`Mandatory...`:** Tests the behavior when specific constraints are explicitly required (using "exact" or "min/max" values).
    * **`Ideal...`:** Tests how "ideal" constraints (preferences) influence the selection of settings.
    * **Focus on Video Content Capture:** The use of terms like "screen cast," "height," "width," "aspect ratio," and "frame rate" clearly indicates the tests are focused on video-related constraints in content capture scenarios.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript API:** The tested functionality directly relates to the JavaScript MediaStream API, specifically `getUserMedia()` or `getDisplayMedia()`. Constraints passed to these functions influence the media tracks obtained.
    * **HTML `<video>` Element:** The output of these APIs (MediaStreams) is often displayed in `<video>` elements. The constraints tested here impact the characteristics of the video stream that can be played.
    * **No Direct CSS Relation:**  While CSS can style the `<video>` element, the core logic of constraint negotiation is handled in the JavaScript/browser engine level, so direct CSS relationships are less prominent.

5. **Logical Inferences and Hypothetical Inputs/Outputs:**
    * **`SelectSettings` Function:** This function likely takes a `MediaConstraints` object and potentially a `MediaStreamType` as input. It processes these constraints and returns a `VideoCaptureSettings` object representing the best matching configuration, or an indication of failure.
    * **Example: `MandatoryExactHeight`:**
        * **Input:** A `MediaConstraints` object with an exact `height` constraint set to 1000.
        * **Output:** A `VideoCaptureSettings` object with `Height()` equal to 1000 and `Width()` calculated to maintain the default aspect ratio, along with default values for other settings.
    * **Example: `OverconstrainedOnHeight`:**
        * **Input:** A `MediaConstraints` object with an exact `height` constraint set to a value outside the allowed range.
        * **Output:** An invalid `VideoCaptureSettings` object (indicated by `HasValue()` being false) and the name of the failed constraint.

6. **User and Programming Errors:**
    * **User Error (via JavaScript):**  Providing conflicting or impossible constraints in JavaScript's `getUserMedia()` or `getDisplayMedia()` calls (e.g., requiring a height of 10 and a height of 1000 simultaneously). This would lead to the "overconstrained" scenarios tested.
    * **Programming Error (in Blink):** Bugs in the constraint selection algorithm itself, where valid combinations of constraints are not handled correctly or where default values are not applied appropriately. The tests aim to prevent these errors.

7. **Debugging Clues and User Actions:**
    * **User Action:** A user might try to share their screen or camera in a web application.
    * **JavaScript Call:** The web application uses `navigator.mediaDevices.getDisplayMedia({ video: { height: 1000 } })`.
    * **Blink Processing:** The browser's rendering engine (Blink) receives these constraints. The code being tested in this file is part of the logic that attempts to find suitable video capture settings based on these constraints.
    * **Debugging:** If the user reports an issue (e.g., the screen sharing resolution is incorrect), developers might look at the constraints being passed, step through the `SelectSettingsVideoContentCapture` function (which `SelectSettings` calls), and use these unit tests to understand how different constraints influence the outcome. The test names and assertions provide valuable clues about expected behavior.

8. **Summary of Functionality (Part 1):** Based on the analysis of the first part of the code, its primary function is to test the logic within the Blink rendering engine for selecting appropriate video capture settings when capturing screen content, based on various mandatory and ideal constraints provided by the user (via JavaScript). It focuses on verifying default behaviors, handling overconstrained scenarios, and validating how individual constraints (like height, width, aspect ratio, frame rate, and device ID) are applied during the selection process. The tests also cover the configuration of track adapter settings, which are related to how the video track is adapted or scaled.

By following this systematic approach, I was able to break down the code, understand its purpose, connect it to web technologies, infer its behavior, and identify potential errors and debugging scenarios, culminating in a comprehensive summary.
这是对 Chromium Blink 引擎中 `blink/renderer/modules/mediastream/media_stream_constraints_util_video_content_test.cc` 文件的功能进行的分析。根据提供的代码片段，可以归纳出以下功能：

**功能归纳：**

该文件包含了用于测试 `media_stream_constraints_util_video_content.h` 中关于视频内容捕获的约束处理逻辑的单元测试。具体来说，它测试了在屏幕共享或桌面捕获等场景下，如何根据不同的约束条件（例如高度、宽度、宽高比、帧率等）选择合适的视频捕获设置 (`VideoCaptureSettings`)。

**更详细的功能点：**

1. **测试默认行为 (Unconstrained):**  测试在没有施加任何约束的情况下，系统如何选择默认的视频捕获设置。
2. **测试约束冲突 (Overconstrained):**  测试当约束条件相互冲突，导致无法找到满足所有约束的设置时，系统如何处理并报告失败的约束。
3. **测试强制约束 (Mandatory):**  测试当指定了强制性的约束条件时，系统如何选择满足这些约束的设置。涵盖了各种视频属性的强制约束，例如：
    * 设备 ID (`device_id`)
    * 降噪 (`noise_reduction`)
    * 高度 (`height`)
    * 宽度 (`width`)
    * 宽高比 (`aspect_ratio`)
    * 帧率 (`frame_rate`)
    * 缩放模式 (`resize_mode`)
4. **测试理想约束 (Ideal):** 测试当指定了理想的约束条件时，系统如何尽力选择最接近理想值的设置，同时仍然满足任何强制性约束。
5. **测试不同类型的视频源:** 虽然代码片段中主要关注桌面视频捕获 (`GUM_DESKTOP_VIDEO_CAPTURE`)，但 `SelectSettings` 方法的参数 `stream_type` 表明它可以用于测试不同类型的视频源。
6. **测试 `TrackAdapterSettings`:**  测试与视频轨道适配器相关的设置，这些设置用于在捕获后调整视频流的大小和帧率等属性。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个 C++ 代码文件本身不直接包含 JavaScript, HTML 或 CSS 代码。然而，它测试的功能是 WebRTC API 的核心部分，而 WebRTC API 主要在 JavaScript 中使用，并影响 HTML 页面中 `<video>` 元素的显示。

* **JavaScript:**  Web 开发者可以使用 `navigator.mediaDevices.getUserMedia()` 或 `navigator.mediaDevices.getDisplayMedia()` 来请求访问用户的摄像头或屏幕。在这些方法中，可以传递一个 `constraints` 对象来指定期望的媒体流属性。例如：

   ```javascript
   navigator.mediaDevices.getDisplayMedia({
       video: {
           width: { min: 640, ideal: 1280 },
           height: { min: 480, ideal: 720 },
           frameRate: { ideal: 30 }
       }
   })
   .then(stream => {
       // 使用 stream
   })
   .catch(error => {
       console.error('无法获取屏幕共享:', error);
   });
   ```

   在这个例子中，`width`, `height`, 和 `frameRate` 的约束会传递到 Blink 引擎，而 `media_stream_constraints_util_video_content_test.cc` 中测试的逻辑就是处理这些约束并选择合适的视频捕获设置。

* **HTML:**  获取到的 `MediaStream` 对象通常会赋值给一个 `<video>` 元素的 `srcObject` 属性，以便在页面上显示视频流。例如：

   ```html
   <video id="myVideo" autoplay playsinline></video>
   <script>
       navigator.mediaDevices.getDisplayMedia({...})
       .then(stream => {
           document.getElementById('myVideo').srcObject = stream;
       });
   </script>
   ```

   `media_stream_constraints_util_video_content_test.cc` 中测试的约束处理逻辑直接影响最终传递给 `<video>` 元素的视频流的分辨率、帧率等属性。

* **CSS:** CSS 可以用于样式化 `<video>` 元素，例如设置其大小、边框等。但是，CSS 不会影响视频流本身的属性，例如分辨率或帧率。这些属性是由 `getUserMedia()` 或 `getDisplayMedia()` 的约束以及 Blink 引擎的约束处理逻辑决定的，而 `media_stream_constraints_util_video_content_test.cc` 正是测试这部分逻辑。

**逻辑推理、假设输入与输出：**

假设 `SelectSettings` 函数接收以下输入：

* **`constraints`:** 一个 `MediaConstraints` 对象，包含以下约束：
    * `width`: { `min`: 800, `max`: 1200 }
    * `height`: { `exact`: 720 }
* **`stream_type`:** `mojom::MediaStreamType::GUM_DESKTOP_VIDEO_CAPTURE`
* **`kDefaultScreenCastWidth`:** 1920
* **`kDefaultScreenCastHeight`:** 1080

**逻辑推理：**

1. 强制要求高度为 720。
2. 宽度必须在 800 到 1200 之间。
3. 默认的屏幕共享宽高比会影响宽度的选择。

**可能的输出 (`VideoCaptureSettings`):**

* `Height()`: 720
* `Width()`:  可能会选择一个接近默认宽高比并且在 800 到 1200 之间的值。例如，如果默认宽高比接近 1.77，则宽度可能被计算为 `round(720 * 1.77)`，结果可能在约束范围内。 假设计算结果是 1274，由于 `max` 约束是 1200，所以宽度会被限制为 1200。
* 其他属性（帧率、降噪等）可能会使用默认值，除非有其他约束指定。

**用户或编程常见的使用错误：**

* **用户错误 (通过 JavaScript):**
    * **提供冲突的约束:**  例如，同时要求 `width: { exact: 640 }` 和 `width: { min: 800 }`。这会导致无法满足所有约束，类似于测试用例中的 "Overconstrained" 场景。
    * **提供超出硬件能力的约束:** 例如，请求一个非常高的分辨率或帧率，而用户的摄像头或屏幕不支持。
* **编程错误 (在 Blink 引擎的实现中):**
    * **约束处理逻辑错误:**  例如，没有正确地处理 `min` 和 `max` 约束的组合，或者在计算理想值时出现偏差。 `media_stream_constraints_util_video_content_test.cc` 中的测试用例旨在发现这类错误。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户打开一个网页，该网页需要获取屏幕共享。**
2. **网页的 JavaScript 代码调用 `navigator.mediaDevices.getDisplayMedia()`，并传递包含视频约束的参数。** 例如：
   ```javascript
   navigator.mediaDevices.getDisplayMedia({ video: { width: { ideal: 1920 } } });
   ```
3. **浏览器接收到这个请求和约束。**
4. **Blink 引擎的媒体流模块开始处理这个请求。**
5. **`media_stream_constraints_util_video_content.h` 中定义的 `SelectSettingsVideoContentCapture` 函数（或其相关的逻辑）被调用，负责根据约束选择合适的视频捕获参数。**
6. **为了确保 `SelectSettingsVideoContentCapture` 函数的逻辑正确，开发者会编写像 `media_stream_constraints_util_video_content_test.cc` 这样的单元测试。** 这些测试模拟各种约束场景，并验证 `SelectSettingsVideoContentCapture` 函数的输出是否符合预期。
7. **如果用户报告屏幕共享的分辨率不正确，或者无法满足某些约束，开发者可能会查看这些单元测试，并编写新的测试用例来复现和修复问题。**  他们可能会调试 `SelectSettingsVideoContentCapture` 函数的实现，以找出约束处理逻辑中的错误。

**总结 (针对第 1 部分):**

`blink/renderer/modules/mediastream/media_stream_constraints_util_video_content_test.cc` 文件的主要功能是测试 Blink 引擎中用于处理视频内容捕获约束的核心逻辑。它通过各种单元测试用例，验证在不同约束条件下，系统能否正确选择合适的视频捕获设置，包括默认行为、约束冲突、强制约束和理想约束的处理。这些测试直接关系到 WebRTC API 的功能，影响着 JavaScript 中 `getUserMedia` 和 `getDisplayMedia` 等方法的使用，以及最终在 HTML `<video>` 元素中显示的视频流的属性。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_video_content_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_video_content.h"

#include <cmath>
#include <string>

#include "media/base/limits.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/modules/mediastream/web_platform_media_stream_source.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util.h"
#include "third_party/blink/renderer/modules/mediastream/mock_constraint_factory.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

// To avoid symbol collisions in jumbo builds.
namespace media_stream_constraints_util_video_content_test {

namespace {

const double kDefaultScreenCastAspectRatio =
    static_cast<double>(kDefaultScreenCastWidth) / kDefaultScreenCastHeight;

void CheckNonResolutionDefaults(const VideoCaptureSettings& result) {
  EXPECT_EQ(kDefaultScreenCastFrameRate, result.FrameRate());
  EXPECT_EQ(std::optional<double>(), result.min_frame_rate());
  EXPECT_EQ(std::optional<double>(), result.max_frame_rate());
  EXPECT_EQ(std::optional<bool>(), result.noise_reduction());
  EXPECT_EQ(std::string(), result.device_id());
  EXPECT_FALSE(result.min_frame_rate().has_value());
}

void CheckNonFrameRateDefaults(const VideoCaptureSettings& result) {
  EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
  EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
  EXPECT_EQ(std::optional<bool>(), result.noise_reduction());
  EXPECT_EQ(std::string(), result.device_id());
}

void CheckTrackAdapterSettingsEqualsFormat(
    const VideoCaptureSettings& result,
    std::optional<double> frame_rate = std::nullopt) {
  // For content capture, resolution and frame rate should always be the same
  // for source and track.
  EXPECT_TRUE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(result.Width(), result.track_adapter_settings().target_width());
  EXPECT_EQ(result.Height(), result.track_adapter_settings().target_height());
  EXPECT_EQ(frame_rate, result.track_adapter_settings().max_frame_rate());
}

void CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(
    const VideoCaptureSettings& result,
    std::optional<double> frame_rate = std::nullopt) {
  EXPECT_EQ(
      static_cast<double>(kMinScreenCastDimension) / kMaxScreenCastDimension,
      result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(
      static_cast<double>(kMaxScreenCastDimension) / kMinScreenCastDimension,
      result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result, frame_rate);
}

}  // namespace

class MediaStreamConstraintsUtilVideoContentTest : public testing::Test {
 protected:
  VideoCaptureSettings SelectSettings(
      mojom::MediaStreamType stream_type =
          mojom::MediaStreamType::GUM_DESKTOP_VIDEO_CAPTURE) {
    MediaConstraints constraints = constraint_factory_.CreateMediaConstraints();
    return SelectSettingsVideoContentCapture(constraints, stream_type,
                                             kDefaultScreenCastWidth,
                                             kDefaultScreenCastHeight);
  }

  test::TaskEnvironment task_environment_;
  MockConstraintFactory constraint_factory_;
};

// The Unconstrained test checks the default selection criteria.
TEST_F(MediaStreamConstraintsUtilVideoContentTest, Unconstrained) {
  constraint_factory_.Reset();
  auto result = SelectSettings();

  // All settings should have default values.
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
  EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
  CheckNonResolutionDefaults(result);
  CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
}

// The "Overconstrained" tests verify that failure of any single required
// constraint results in failure to select a candidate.
TEST_F(MediaStreamConstraintsUtilVideoContentTest, OverconstrainedOnHeight) {
  constraint_factory_.Reset();
  constraint_factory_.basic().height.SetExact(kMaxScreenCastDimension + 1);
  auto result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().height.GetName(),
            result.failed_constraint_name());

  constraint_factory_.Reset();
  constraint_factory_.basic().height.SetMin(kMaxScreenCastDimension + 1);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().height.GetName(),
            result.failed_constraint_name());

  constraint_factory_.Reset();
  constraint_factory_.basic().height.SetMax(kMinScreenCastDimension - 1);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().height.GetName(),
            result.failed_constraint_name());
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, OverconstrainedOnWidth) {
  constraint_factory_.Reset();
  constraint_factory_.basic().width.SetExact(kMaxScreenCastDimension + 1);
  auto result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().width.GetName(),
            result.failed_constraint_name());

  constraint_factory_.Reset();
  constraint_factory_.basic().width.SetMin(kMaxScreenCastDimension + 1);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().width.GetName(),
            result.failed_constraint_name());

  constraint_factory_.Reset();
  constraint_factory_.basic().width.SetMax(kMinScreenCastDimension - 1);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().width.GetName(),
            result.failed_constraint_name());
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest,
       OverconstrainedOnAspectRatio) {
  constraint_factory_.Reset();
  constraint_factory_.basic().aspect_ratio.SetExact(123467890);
  auto result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().aspect_ratio.GetName(),
            result.failed_constraint_name());

  constraint_factory_.Reset();
  constraint_factory_.basic().aspect_ratio.SetMin(123467890);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().aspect_ratio.GetName(),
            result.failed_constraint_name());

  constraint_factory_.Reset();
  constraint_factory_.basic().aspect_ratio.SetMax(0.00001);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().aspect_ratio.GetName(),
            result.failed_constraint_name());
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, OverconstrainedOnFrameRate) {
  constraint_factory_.Reset();
  constraint_factory_.basic().frame_rate.SetExact(kMaxScreenCastFrameRate +
                                                  0.1);
  auto result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().frame_rate.GetName(),
            result.failed_constraint_name());

  constraint_factory_.Reset();
  constraint_factory_.basic().frame_rate.SetMin(kMaxScreenCastFrameRate + 0.1);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().frame_rate.GetName(),
            result.failed_constraint_name());

  constraint_factory_.Reset();
  constraint_factory_.basic().frame_rate.SetMax(-0.1);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().frame_rate.GetName(),
            result.failed_constraint_name());
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest,
       OverconstrainedOnInvalidResizeMode) {
  constraint_factory_.Reset();
  constraint_factory_.basic().resize_mode.SetExact("invalid");
  auto result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().resize_mode.GetName(),
            result.failed_constraint_name());
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest,
       OverconstrainedOnEmptyResizeMode) {
  constraint_factory_.Reset();
  constraint_factory_.basic().resize_mode.SetExact("");
  auto result = SelectSettings();
  EXPECT_FALSE(result.HasValue());
  EXPECT_EQ(constraint_factory_.basic().resize_mode.GetName(),
            result.failed_constraint_name());
}

// The "Mandatory" and "Ideal" tests check that various selection criteria work
// for each individual constraint in the basic constraint set.
TEST_F(MediaStreamConstraintsUtilVideoContentTest, MandatoryDeviceID) {
  const String kDeviceID = "Some ID";
  constraint_factory_.Reset();
  constraint_factory_.basic().device_id.SetExact(kDeviceID);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(kDeviceID.Utf8(), result.device_id());
  // Other settings should have default values.
  EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
  EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
  EXPECT_EQ(kDefaultScreenCastFrameRate, result.FrameRate());
  EXPECT_EQ(std::optional<bool>(), result.noise_reduction());
  CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, IdealDeviceID) {
  const String kDeviceID = "Some ID";
  const String kIdealID = "Ideal ID";
  Vector<String> device_ids(static_cast<size_t>(2));
  device_ids[0] = kDeviceID;
  device_ids[1] = kIdealID;
  constraint_factory_.Reset();
  constraint_factory_.basic().device_id.SetExact(device_ids);

  Vector<String> ideal_id(static_cast<size_t>(1));
  ideal_id[0] = kIdealID;
  constraint_factory_.basic().device_id.SetIdeal(ideal_id);

  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(kIdealID.Utf8(), result.device_id());
  // Other settings should have default values.
  EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
  EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
  EXPECT_EQ(kDefaultScreenCastFrameRate, result.FrameRate());
  EXPECT_EQ(std::optional<bool>(), result.noise_reduction());
  CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, MandatoryNoiseReduction) {
  constraint_factory_.Reset();
  const bool kNoiseReductionValues[] = {true, false};
  for (auto noise_reduction : kNoiseReductionValues) {
    constraint_factory_.basic().goog_noise_reduction.SetExact(noise_reduction);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(noise_reduction, result.noise_reduction());
    // Other settings should have default values.
    EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
    EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
    EXPECT_EQ(kDefaultScreenCastFrameRate, result.FrameRate());
    EXPECT_EQ(std::string(), result.device_id());
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, IdealNoiseReduction) {
  constraint_factory_.Reset();
  const bool kNoiseReductionValues[] = {true, false};
  for (auto noise_reduction : kNoiseReductionValues) {
    constraint_factory_.basic().goog_noise_reduction.SetIdeal(noise_reduction);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(noise_reduction, result.noise_reduction());
    // Other settings should have default values.
    EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
    EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
    EXPECT_EQ(kDefaultScreenCastFrameRate, result.FrameRate());
    EXPECT_EQ(std::string(), result.device_id());
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, MandatoryExactHeight) {
  constraint_factory_.Reset();
  const int kHeight = 1000;
  constraint_factory_.basic().height.SetExact(kHeight);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(kHeight, result.Height());
  // The algorithm tries to preserve the default aspect ratio.
  EXPECT_EQ(std::round(kHeight * kDefaultScreenCastAspectRatio),
            result.Width());
  CheckNonResolutionDefaults(result);
  EXPECT_EQ(1.0 / kHeight, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(static_cast<double>(kMaxScreenCastDimension) / kHeight,
            result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, MandatoryMinHeight) {
  constraint_factory_.Reset();
  const int kHeight = 2000;
  constraint_factory_.basic().height.SetMin(kHeight);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // kHeight is greater that the default, so expect kHeight.
  EXPECT_EQ(kHeight, result.Height());
  EXPECT_EQ(std::round(kHeight * kDefaultScreenCastAspectRatio),
            result.Width());
  CheckNonResolutionDefaults(result);
  EXPECT_EQ(1.0 / kMaxScreenCastDimension,
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(static_cast<double>(kMaxScreenCastDimension) / kHeight,
            result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result);

  const int kSmallHeight = 100;
  constraint_factory_.basic().height.SetMin(kSmallHeight);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // kSmallHeight is less that the default, so expect the default.
  EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
  EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
  CheckNonResolutionDefaults(result);
  EXPECT_EQ(1.0 / kMaxScreenCastDimension,
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(static_cast<double>(kMaxScreenCastDimension) / kSmallHeight,
            result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, MandatoryMaxHeight) {
  // kMaxHeight smaller than the default.
  {
    constraint_factory_.Reset();
    const int kMaxHeight = kDefaultScreenCastHeight - 100;
    constraint_factory_.basic().height.SetMax(kMaxHeight);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kMaxHeight, result.Height());
    EXPECT_EQ(std::round(kMaxHeight * kDefaultScreenCastAspectRatio),
              result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1.0 / kMaxHeight,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(kMaxScreenCastDimension,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // kMaxHeight greater than the default.
  {
    constraint_factory_.Reset();
    const int kMaxHeight = kDefaultScreenCastHeight + 100;
    constraint_factory_.basic().height.SetMax(kMaxHeight);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kMaxHeight, result.Height());
    EXPECT_EQ(std::round(kMaxHeight * kDefaultScreenCastAspectRatio),
              result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1.0 / kMaxHeight,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(kMaxScreenCastDimension,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // kMaxHeight greater than the maximum allowed.
  {
    constraint_factory_.Reset();
    constraint_factory_.basic().height.SetMax(kMaxScreenCastDimension + 1);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
    EXPECT_EQ(
        std::round(kDefaultScreenCastHeight * kDefaultScreenCastAspectRatio),
        result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1.0 / kMaxScreenCastDimension,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(kMaxScreenCastDimension,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // kMaxHeight equal to the maximum allowed.
  {
    constraint_factory_.Reset();
    const int kMaxHeight = kMaxScreenCastDimension;
    constraint_factory_.basic().height.SetMax(kMaxHeight);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kMaxHeight, result.Height());
    // Since the given max is too large, the default aspect ratio cannot be
    // used and the width is clamped to the maximum.
    EXPECT_EQ(kMaxScreenCastDimension, result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1.0 / kMaxHeight,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(kMaxScreenCastDimension,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, MandatoryHeightRange) {
  // Range includes the default.
  {
    constraint_factory_.Reset();
    const int kMinHeight = kDefaultScreenCastHeight - 100;
    const int kMaxHeight = kDefaultScreenCastHeight + 100;
    constraint_factory_.basic().height.SetMin(kMinHeight);
    constraint_factory_.basic().height.SetMax(kMaxHeight);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kMaxHeight, result.Height());
    EXPECT_EQ(std::round(kMaxHeight * kDefaultScreenCastAspectRatio),
              result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1.0 / kMaxHeight,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(static_cast<double>(kMaxScreenCastDimension) / kMinHeight,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // The whole range is greater than the default.
  {
    constraint_factory_.Reset();
    const int kMinHeight = kDefaultScreenCastHeight + 100;
    const int kMaxHeight = kDefaultScreenCastHeight + 200;
    constraint_factory_.basic().height.SetMin(kMinHeight);
    constraint_factory_.basic().height.SetMax(kMaxHeight);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kMaxHeight, result.Height());
    EXPECT_EQ(std::round(kMaxHeight * kDefaultScreenCastAspectRatio),
              result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1.0 / kMaxHeight,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(static_cast<double>(kMaxScreenCastDimension) / kMinHeight,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // The whole range is less than the default.
  {
    constraint_factory_.Reset();
    const int kMinHeight = kDefaultScreenCastHeight - 200;
    const int kMaxHeight = kDefaultScreenCastHeight - 100;
    constraint_factory_.basic().height.SetMin(kMinHeight);
    constraint_factory_.basic().height.SetMax(kMaxHeight);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kMaxHeight, result.Height());
    EXPECT_EQ(std::round(kMaxHeight * kDefaultScreenCastAspectRatio),
              result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1.0 / kMaxHeight,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(static_cast<double>(kMaxScreenCastDimension) / kMinHeight,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, IdealHeight) {
  // Unconstrained.
  {
    constraint_factory_.Reset();
    const int kIdealHeight = 1000;
    constraint_factory_.basic().height.SetIdeal(kIdealHeight);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kIdealHeight, result.Height());
    // When ideal height is given, the algorithm returns a width that is closest
    // to height * kDefaultScreenCastAspectRatio.
    EXPECT_EQ(std::round(kIdealHeight * kDefaultScreenCastAspectRatio),
              result.Width());
    CheckNonResolutionDefaults(result);
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
  }

  // Ideal greater than maximum.
  {
    constraint_factory_.Reset();
    const int kIdealHeight = 1000;
    const int kMaxHeight = 800;
    constraint_factory_.basic().height.SetIdeal(kIdealHeight);
    constraint_factory_.basic().height.SetMax(kMaxHeight);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // Ideal height is greater than the maximum, expect maximum.
    EXPECT_EQ(kMaxHeight, result.Height());
    // Expect closest to kMaxHeight * kDefaultScreenCastAspectRatio.
    EXPECT_EQ(std::round(kMaxHeight * kDefaultScreenCastAspectRatio),
              result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1.0 / kMaxHeight,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(kMaxScreenCastDimension,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // Ideal less than minimum.
  {
    constraint_factory_.Reset();
    const int kIdealHeight = 1000;
    const int kMinHeight = 1200;
    constraint_factory_.basic().height.SetIdeal(kIdealHeight);
    constraint_factory_.basic().height.SetMin(kMinHeight);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // Ideal height is less than the minimum, expect minimum.
    EXPECT_EQ(kMinHeight, result.Height());
    // Expect closest to kMinHeight * kDefaultScreenCastAspectRatio.
    EXPECT_EQ(std::round(kMinHeight * kDefaultScreenCastAspectRatio),
              result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1.0 / kMaxScreenCastDimension,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(static_cast<double>(kMaxScreenCastDimension) / kMinHeight,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // Ideal intersects a box.
  {
    constraint_factory_.Reset();
    constraint_factory_.basic().height.SetMin(500);
    constraint_factory_.basic().height.SetMax(1000);
    constraint_factory_.basic().width.SetMin(100);
    constraint_factory_.basic().width.SetMax(500);
    const int kIdealHeight = 750;
    constraint_factory_.basic().height.SetIdeal(kIdealHeight);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // Ideal height is included in the bounding box.
    EXPECT_EQ(kIdealHeight, result.Height());
    double default_aspect_ratio =
        static_cast<double>(constraint_factory_.basic().width.Max()) /
        constraint_factory_.basic().height.Max();
    // Expect width closest to kIdealHeight * default aspect ratio.
    EXPECT_EQ(std::round(kIdealHeight * default_aspect_ratio), result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(100.0 / 1000.0,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(500.0 / 500.0,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // Ideal outside the box, closest to the side coinciding with max height.
  {
    const int kMaxHeight = 1000;
    constraint_factory_.Reset();
    constraint_factory_.basic().height.SetMin(500);
    constraint_factory_.basic().height.SetMax(kMaxHeight);
    constraint_factory_.basic().width.SetMin(100);
    constraint_factory_.basic().width.SetMax(500);
    constraint_factory_.basic().height.SetIdeal(1200);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kMaxHeight, result.Height());
    // Expect width closest to kMaxHeight * default aspect ratio, which is
    // outside the box. Closest it max width.
    EXPECT_EQ(constraint_factory_.basic().width.Max(), result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(100.0 / kMaxHeight,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(500.0 / 500.0,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // Ideal outside the constrained set, closest to a single point.
  {
    constraint_factory_.Reset();
    constraint_factory_.basic().height.SetMin(500);
    constraint_factory_.basic().height.SetMax(1000);
    constraint_factory_.basic().width.SetMin(500);
    constraint_factory_.basic().width.SetMax(1000);
    constraint_factory_.basic().aspect_ratio.SetMin(1.0);
    constraint_factory_.basic().height.SetIdeal(1200);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // (max-height, max-width) is the single point closest to the ideal line.
    EXPECT_EQ(constraint_factory_.basic().height.Max(), result.Height());
    EXPECT_EQ(constraint_factory_.basic().width.Max(), result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1.0, result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(1000.0 / 500.0,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, MandatoryExactWidth) {
  constraint_factory_.Reset();
  const int kWidth = 1000;
  constraint_factory_.basic().width.SetExact(kWidth);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(kWidth, result.Width());
  EXPECT_EQ(std::round(kWidth / kDefaultScreenCastAspectRatio),
            result.Height());
  CheckNonResolutionDefaults(result);
  EXPECT_EQ(static_cast<double>(kWidth) / kMaxScreenCastDimension,
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(static_cast<double>(kWidth) / kMinScreenCastDimension,
            result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, MandatoryMinWidth) {
  constraint_factory_.Reset();
  const int kWidth = 3000;
  constraint_factory_.basic().width.SetMin(kWidth);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // kWidth is greater that the default, so expect kWidth.
  EXPECT_EQ(kWidth, result.Width());
  EXPECT_EQ(std::round(kWidth / kDefaultScreenCastAspectRatio),
            result.Height());
  CheckNonResolutionDefaults(result);
  EXPECT_EQ(static_cast<double>(kWidth) / kMaxScreenCastDimension,
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(
      static_cast<double>(kMaxScreenCastDimension) / kMinScreenCastDimension,
      result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result);

  const int kSmallWidth = 100;
  constraint_factory_.basic().width.SetMin(kSmallWidth);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // kSmallWidth is less that the default, so expect the default.
  EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
  EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
  CheckNonResolutionDefaults(result);
  EXPECT_EQ(static_cast<double>(kSmallWidth) / kMaxScreenCastDimension,
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(
      static_cast<double>(kMaxScreenCastDimension) / kMinScreenCastDimension,
      result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, MandatoryMaxWidth) {
  // kMaxWidth less than the default.
  {
    constraint_factory_.Reset();
    const int kMaxWidth = kDefaultScreenCastWidth - 100;
    constraint_factory_.basic().width.SetMax(kMaxWidth);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // If max is provided, max is used as default.
    EXPECT_EQ(kMaxWidth, result.Width());
    EXPECT_EQ(std::round(kMaxWidth / kDefaultScreenCastAspectRatio),
              result.Height());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1.0 / kMaxScreenCastDimension,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(static_cast<double>(kMaxWidth) / kMinScreenCastDimension,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // kMaxWidth greater than the default.
  {
    constraint_factory_.Reset();
    const int kMaxWidth = kDefaultScreenCastWidth + 100;
    constraint_factory_.basic().width.SetMax(kMaxWidth);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // If max is provided, max is used as default.
    EXPECT_EQ(kMaxWidth, result.Width());
    EXPECT_EQ(std::round(kMaxWidth / kDefaultScreenCastAspectRatio),
              result.Height());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1.0 / kMaxScreenCastDimension,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(static_cast<double>(kMaxWidth) / kMinScreenCastDimension,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // kMaxWidth greater than the maximum allowed (gets ignored).
  {
    constraint_factory_.Reset();
    constraint_factory_.basic().width.SetMax(kMaxScreenCastDimension + 1);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // Expect the default, since the given max value cannot be used as default.
    EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
    EXPECT_EQ(
        std::round(kDefaultScreenCastWidth / kDefaultScreenCastAspectRatio),
        result.Height());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1.0 / kMaxScreenCastDimension,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(
        static_cast<double>(kMaxScreenCastDimension) / kMinScreenCastDimension,
        result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // kMaxWidth equal to the maximum allowed.
  {
    constraint_factory_.Reset();
    const int kMaxWidth = kMaxScreenCastDimension;
    constraint_factory_.basic().width.SetMax(kMaxWidth);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kMaxWidth, result.Width());
    EXPECT_EQ(std::round(kMaxWidth / kDefaultScreenCastAspectRatio),
              result.Height());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1.0 / kMaxScreenCastDimension,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(static_cast<double>(kMaxWidth) / kMinScreenCastDimension,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, MandatoryWidthRange) {
  // The whole range is less than the default.
  {
    constraint_factory_.Reset();
    const int kMinWidth = kDefaultScreenCastWidth - 200;
    const int kMaxWidth = kDefaultScreenCastWidth - 100;
    constraint_factory_.basic().width.SetMin(kMinWidth);
    constraint_factory_.basic().width.SetMax(kMaxWidth);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kMaxWidth, result.Width());
    EXPECT_EQ(std::round(kMaxWidth / kDefaultScreenCastAspectRatio),
              result.Height());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(static_cast<double>(kMinWidth) / kMaxScreenCastDimension,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(static_cast<double>(kMaxWidth) / kMinScreenCastDimension,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // The range includes the default.
  {
    constraint_factory_.Reset();
    const int kMinWidth = kDefaultScreenCastWidth - 100;
    const int kMaxWidth = kDefaultScreenCastWidth + 100;
    constraint_factory_.basic().width.SetMin(kMinWidth);
    constraint_factory_.basic().width.SetMax(kMaxWidth);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kMaxWidth, result.Width());
    EXPECT_EQ(std::round(kMaxWidth / kDefaultScreenCastAspectRatio),
              result.Height());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(static_cast<double>(kMinWidth) / kMaxScreenCastDimension,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(static_cast<double>(kMaxWidth) / kMinScreenCastDimension,
              result.tr
```