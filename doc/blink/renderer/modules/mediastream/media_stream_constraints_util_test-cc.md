Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Identify the Core Purpose:** The file name `media_stream_constraints_util_test.cc` immediately suggests it's a test file for something related to media stream constraints. The `_test.cc` suffix is a common convention in C++ testing frameworks.

2. **Look for Key Includes:** The `#include` directives reveal the major components being tested:
    * `media_stream_constraints_util.h`: This is likely the header file for the utility functions being tested.
    * `media_stream_constraints_util_sets.h`:  Suggests that constraints are organized into sets of some kind.
    * `mock_constraint_factory.h`: Indicates the use of mock objects for setting up test scenarios with specific constraint configurations.
    * `gtest/gtest.h`:  Confirms the use of Google Test as the testing framework.

3. **Examine the Test Structure:**  The `TEST_F` macro is a telltale sign of Google Test. It indicates test cases within a test fixture. The fixture, `MediaStreamConstraintsUtilTest`, sets up common data or helper functions.

4. **Analyze Individual Test Cases:**  Go through each `TEST_F` case, understanding its purpose:
    * **`BooleanConstraints`:** Tests how boolean constraints (like `echo_cancellation`) are handled, especially the interaction between mandatory and optional (advanced) constraints.
    * **`DoubleConstraints`:**  Focuses on retrieving double-valued constraints (like `aspect_ratio`).
    * **`IntConstraints`:** Tests retrieving integer constraints (like `width`) and verifies that exact values are reflected in both min and max.
    * **`VideoTrackAdapterSettingsUnconstrained`:** Explores the behavior of `SelectVideoTrackAdapterSettings` when no specific constraints (beyond "ideal" values) are provided. It checks how ideal width, height, aspect ratio, and frame rate are applied.
    * **`VideoTrackAdapterSettingsConstrained`:**  Examines the same function but with specific minimum and maximum constraints defined. It verifies how "ideal" values interact with these hard limits.
    * **`VideoTrackAdapterSettingsExpectedNativeSize`:**  Seems similar to `Unconstrained`, possibly focusing on cases where the desired output matches the source dimensions.
    * **`VideoTrackAdapterSettingsRescalingDisabledUnconstrained`:** Tests the behavior when rescaling is disabled. It checks that target resolutions are not set and that constraints are handled differently.
    * **`VideoTrackAdapterSettingsRescalingDisabledConstrained`:**  Combines the "rescaling disabled" scenario with explicit constraints.

5. **Identify the Core Functionality Under Test:** Based on the test cases, the key functions being tested are:
    * `GetConstraintValueAsBoolean`
    * `GetConstraintValueAsDouble`
    * `GetConstraintValueAsInteger`
    * `GetConstraintMaxAsInteger`
    * `GetConstraintMinAsInteger`
    * `SelectVideoTrackAdapterSettings`

6. **Infer Function Purpose:** By looking at the test names and the assertions within them, deduce what each function likely does. For example, `SelectVideoTrackAdapterSettings` seems responsible for determining the optimal video track settings (resolution, frame rate, aspect ratio) based on provided constraints and the source media's capabilities.

7. **Relate to Web Technologies (JavaScript, HTML, CSS):** Think about how these concepts map to web development:
    * **JavaScript:** The `getUserMedia()` API in JavaScript is where media stream constraints are specified by web developers. The C++ code is likely part of the browser's implementation that processes these constraints.
    * **HTML:**  While not directly related to the *logic* of constraints, HTML elements like `<video>` are where the resulting media stream is displayed. The constraints affect the *characteristics* of that stream.
    * **CSS:**  CSS can style the `<video>` element, but it doesn't influence the *media stream constraints themselves*. The resolution determined by the C++ code will affect how the video *looks*, which CSS can then style further.

8. **Consider Logic and Assumptions:**  For the `SelectVideoTrackAdapterSettings` tests, try to follow the logic of how ideal values and constraints interact. What happens if an ideal value is outside the allowed range?  What if rescaling is disabled?  Formulate hypothetical inputs and expected outputs to understand the code's behavior.

9. **Think About User Errors:**  What mistakes might a web developer make when using the `getUserMedia()` API?  Providing conflicting constraints, requesting impossible resolutions, etc. The tests implicitly validate how the underlying C++ code handles such scenarios.

10. **Trace User Actions:**  Imagine a user interacting with a webpage that uses `getUserMedia()`. How does the user's action (e.g., clicking a "Start Camera" button) lead to this C++ code being executed? This helps establish the debugging context.

11. **Organize the Findings:**  Structure the analysis clearly, as demonstrated in the example answer, with sections for functionality, relationship to web technologies, logical reasoning, user errors, and debugging context.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This tests media streams."  *Refinement:*  "More specifically, it tests the *constraint handling* for media streams."
* **Assumption:** "The `SelectTrackSettings` function just picks the ideal values." *Correction:* "No, it also considers the *constraints* and the *source format*."
* **Overlooking:**  Initially, I might focus too much on individual tests and miss the broader purpose of the `MediaStreamConstraintsUtil`. *Correction:* Step back and consider the overall role of this utility in the media stream pipeline.

By following these steps, systematically analyzing the code and its context, a comprehensive understanding of the test file's functionality can be achieved.
这个文件 `media_stream_constraints_util_test.cc` 是 Chromium Blink 引擎中用于测试 `media_stream_constraints_util.h` 中定义的媒体流约束相关功能的单元测试文件。它的主要功能是：

**1. 测试媒体流约束工具函数的正确性:**

   - 该文件包含了多个测试用例 (使用 Google Test 框架)，用于验证 `media_stream_constraints_util.h` 中提供的工具函数是否按照预期工作。
   - 这些工具函数主要负责解析、处理和应用媒体流的约束条件，例如音频的降噪、视频的分辨率、帧率等。

**2. 覆盖不同类型的约束:**

   - 测试用例覆盖了不同类型的约束，包括：
     - **布尔型约束 (Boolean Constraints):** 例如 `echo_cancellation` (回声消除)。
     - **浮点型约束 (Double Constraints):** 例如 `aspect_ratio` (宽高比)。
     - **整型约束 (Int Constraints):** 例如 `width` (宽度), `height` (高度)。
     - **范围约束 (Range Constraints):**  通过 `media_constraints::ResolutionSet` 和 `media_constraints::NumericRangeSet` 来表示分辨率和帧率的范围。

**3. 模拟不同的约束场景:**

   - 测试用例使用了 `MockConstraintFactory` 来创建具有不同约束条件的 `MediaConstraints` 对象，从而模拟各种可能的约束组合。
   - 包括强制约束 (mandatory constraints) 和可选约束 (optional/advanced constraints) 的测试。

**4. 测试 `SelectVideoTrackAdapterSettings` 函数:**

   - 重点测试了 `SelectVideoTrackAdapterSettings` 函数，该函数根据给定的约束条件和源视频格式，选择合适的视频轨道适配器设置 (`VideoTrackAdapterSettings`)。
   - 测试了在有理想值 (ideal values) 和范围约束 (constrained values) 的情况下，该函数的行为。
   - 测试了禁用重缩放 (rescaling disabled) 的情况下，该函数的行为。

**与 JavaScript, HTML, CSS 的关系:**

该文件中的代码与 JavaScript, HTML, CSS 的功能有密切关系，因为它测试的是浏览器引擎中处理 Web API `getUserMedia()` 传递的约束条件的部分。

**举例说明:**

1. **JavaScript `getUserMedia()`:**  当 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ video: { width: { min: 640, ideal: 1280 }, frameRate: { ideal: 30 } } })` 时，这段 JavaScript 代码定义了请求视频流的约束条件。这些约束条件会被传递到浏览器引擎的底层实现中，而 `media_stream_constraints_util.h` 中定义的函数就负责解析和应用这些约束。

   - **`BooleanConstraints` 测试:**  模拟 JavaScript 设置了 `echoCancellation: true` 或 `echoCancellation: false` 的情况，验证 C++ 代码能否正确解析并获取这些布尔值。
   - **`DoubleConstraints` 测试:**  模拟 JavaScript 设置了 `aspectRatio: 1.777` 的情况，验证 C++ 代码能否正确解析并获取该浮点数值。
   - **`IntConstraints` 测试:**  模拟 JavaScript 设置了 `width: 1280` 的情况，验证 C++ 代码能否正确解析并获取该整数值。
   - **`VideoTrackAdapterSettings` 测试:** 模拟 JavaScript 设置了不同的分辨率和帧率约束 (包括 `min`, `max`, `ideal`)，验证 C++ 代码能否根据这些约束和摄像头提供的原始视频格式，选择最佳的输出分辨率和帧率。

2. **HTML `<video>` 元素:**  虽然该 C++ 代码本身不直接操作 HTML 元素，但 `getUserMedia()` 获取的媒体流最终会显示在 HTML 的 `<video>` 元素中。该 C++ 代码的测试确保了媒体流的属性 (例如分辨率、帧率) 符合 JavaScript 中设置的约束，从而影响 `<video>` 元素呈现的内容。

3. **CSS:** CSS 可以用来设置 `<video>` 元素的样式 (例如大小、边框等)，但不能直接影响 `getUserMedia()` 的约束条件。然而，`media_stream_constraints_util` 的测试保证了视频流的分辨率等属性符合预期，这会影响 CSS 样式的最终呈现效果。例如，如果 JavaScript 约束要求较高的分辨率，那么即使 CSS 将 `<video>` 元素缩小显示，其内部的视频内容也会是高分辨率的。

**逻辑推理、假设输入与输出:**

**示例：`TEST_F(MediaStreamConstraintsUtilTest, VideoTrackAdapterSettingsConstrained)`**

**假设输入:**

- **源视频格式:** 宽度 1500，高度 1000，帧率 100fps。
- **约束条件 (通过 `ResolutionSet` 和 `DoubleRangeSet` 定义):**
    - 最小高度: 500, 最大高度: 1200
    - 最小宽度: 1000, 最大宽度: 2000
    - 最小宽高比: 1.0, 最大宽高比: 2.0
    - 最小帧率: 20fps, 最大帧率: 44fps
- **理想值 (通过 `MockConstraintFactory` 设置):** 例如，理想高度 1100。

**逻辑推理:**

`SelectVideoTrackAdapterSettings` 函数会根据以下逻辑进行选择：

1. **考虑理想值:** 如果设置了理想值，函数会尝试尽可能接近理想值，但必须在约束范围内。
2. **应用约束:** 最终选择的宽度、高度、宽高比和帧率必须满足所有指定的最小值和最大值约束。
3. **考虑源视频格式:**  最终选择的设置也要考虑到源视频的实际能力，例如不能选择高于源视频的帧率。
4. **处理冲突:** 如果理想值与约束冲突，约束优先。

**假设输出 (基于理想高度 1100 的子测试):**

- `target_height()`: 1100 (理想值在约束范围内)
- `target_width()`:  `round(1100 * 1.5)` = 1650 (根据源视频宽高比计算，且在约束范围内)
- `min_aspect_ratio()`: 1.0
- `max_aspect_ratio()`: 2.0
- `max_frame_rate()`: 44.0 (最大帧率约束)

**用户或编程常见的使用错误:**

1. **设置冲突的约束:** 用户可能在 JavaScript 中设置了相互矛盾的约束，例如 `minWidth: 1000, maxWidth: 500`。`media_stream_constraints_util` 的测试会验证浏览器引擎如何处理这些错误，通常会忽略或调整其中一些约束。

2. **请求超出设备能力的约束:** 用户可能请求了摄像头不支持的分辨率或帧率。测试可以验证引擎是否会选择最接近的可用设置，或者返回错误。

3. **误解 `ideal` 值的含义:**  开发者可能认为 `ideal` 值是强制性的，但实际上它只是一个偏好。测试验证了引擎会尽力满足 `ideal` 值，但如果与约束冲突，约束优先。

4. **忘记处理 `getUserMedia()` 的 Promise rejection:**  如果约束条件无法满足，`getUserMedia()` 返回的 Promise 会被 reject。开发者需要正确处理这种情况，例如向用户显示错误信息。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户访问网页:** 用户在浏览器中打开一个使用了 `getUserMedia()` API 的网页。
2. **网页 JavaScript 代码请求访问媒体设备:** 网页的 JavaScript 代码执行，调用 `navigator.mediaDevices.getUserMedia()` 并传递包含各种约束条件的对象。
3. **浏览器处理 `getUserMedia()` 请求:**
   - 浏览器接收到 JavaScript 的请求，并开始处理。
   - 浏览器会检查用户的权限设置，看是否允许该网页访问摄像头和麦克风。
   - **约束条件传递:** JavaScript 中指定的约束条件会被传递到 Blink 渲染引擎的 C++ 代码中。
4. **Blink 引擎解析和应用约束:**
   - `media_stream_constraints_util.h` 中的函数 (例如 `GetConstraintValueAsBoolean`, `SelectVideoTrackAdapterSettings`) 会被调用，用于解析和处理这些约束条件。
   - **`media_stream_constraints_util_test.cc` 中测试的代码就在这个阶段被间接执行到 (通过测试运行)。**  在实际用户操作中，这些函数会被真实的数据调用。
5. **浏览器尝试匹配约束条件:** 浏览器会尝试找到满足所有 (或尽可能满足) 约束条件的媒体设备和配置。
6. **成功或失败回调:**
   - **成功:** 如果找到匹配的设备和配置，`getUserMedia()` 的 Promise 会 resolve，返回一个 `MediaStream` 对象，该对象包含了根据约束条件配置的音视频轨道。网页可以将这个 `MediaStream` 对象赋值给 `<video>` 或 `<audio>` 元素的 `srcObject` 属性进行显示或播放。
   - **失败:** 如果无法找到满足约束条件的设备或配置，`getUserMedia()` 的 Promise 会 reject，并返回一个错误对象。网页的 JavaScript 代码需要捕获这个错误并进行处理。

**作为调试线索:**

- 如果用户反馈摄像头画面不符合预期 (例如分辨率太低)，开发者可以检查 JavaScript 代码中设置的约束条件是否正确。
- 可以使用浏览器的开发者工具查看 `getUserMedia()` 请求的详细信息，包括传递的约束条件和最终选择的媒体轨道配置。
- 如果怀疑是浏览器引擎处理约束的逻辑有问题，可以参考 `media_stream_constraints_util_test.cc` 中的测试用例，了解不同约束场景下的预期行为，并尝试在本地环境中运行这些测试进行验证。
- 如果开发者修改了 `media_stream_constraints_util.h` 中的代码，那么运行 `media_stream_constraints_util_test.cc` 中的测试是确保修改没有引入 bug 的重要步骤。

总而言之，`media_stream_constraints_util_test.cc` 是确保 Chromium Blink 引擎正确处理 Web API `getUserMedia()` 中媒体流约束的关键组成部分，它通过大量的测试用例覆盖了各种可能的约束场景，保证了 Web 开发者可以通过 JavaScript 灵活地控制媒体流的属性。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_sets.h"
#include "third_party/blink/renderer/modules/mediastream/mock_constraint_factory.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_processor_options.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

const int kSourceHeight = 1000;
const int kSourceWidth = 1500;
constexpr double kSourceAspectRatio =
    static_cast<double>(kSourceWidth) / static_cast<double>(kSourceHeight);
constexpr double kSourceFrameRate = 100.0;

VideoTrackAdapterSettings SelectTrackSettings(
    const MediaTrackConstraintSetPlatform& basic_constraint_set,
    const media_constraints::ResolutionSet& resolution_set,
    const media_constraints::NumericRangeSet<double>& frame_rate_set,
    bool enable_rescale = true) {
  media::VideoCaptureFormat source_format(
      gfx::Size(kSourceWidth, kSourceHeight), kSourceFrameRate,
      media::PIXEL_FORMAT_I420);
  return SelectVideoTrackAdapterSettings(basic_constraint_set, resolution_set,
                                         frame_rate_set, source_format,
                                         enable_rescale);
}

}  // namespace

class MediaStreamConstraintsUtilTest : public testing::Test {
 protected:
  using DoubleRangeSet = media_constraints::NumericRangeSet<double>;
  using ResolutionSet = media_constraints::ResolutionSet;
  test::TaskEnvironment task_environment_;
};

TEST_F(MediaStreamConstraintsUtilTest, BooleanConstraints) {
  static const String kValueTrue = "true";
  static const String kValueFalse = "false";

  MockConstraintFactory constraint_factory;
  // Mandatory constraints.
  constraint_factory.basic().echo_cancellation.SetExact(true);
  MediaConstraints constraints = constraint_factory.CreateMediaConstraints();
  bool constrain_value = false;
  EXPECT_TRUE(GetConstraintValueAsBoolean(
      constraints, &MediaTrackConstraintSetPlatform::echo_cancellation,
      &constrain_value));
  EXPECT_TRUE(constrain_value);

  // Optional constraints, represented as "advanced"
  constraint_factory.Reset();
  constraint_factory.AddAdvanced().echo_cancellation.SetExact(false);
  constraints = constraint_factory.CreateMediaConstraints();
  EXPECT_TRUE(GetConstraintValueAsBoolean(
      constraints, &MediaTrackConstraintSetPlatform::echo_cancellation,
      &constrain_value));
  EXPECT_FALSE(constrain_value);

  // A mandatory constraint should override an optional one.
  constraint_factory.Reset();
  constraint_factory.AddAdvanced().echo_cancellation.SetExact(false);
  constraint_factory.basic().echo_cancellation.SetExact(true);
  constraints = constraint_factory.CreateMediaConstraints();
  EXPECT_TRUE(GetConstraintValueAsBoolean(
      constraints, &MediaTrackConstraintSetPlatform::echo_cancellation,
      &constrain_value));
  EXPECT_TRUE(constrain_value);
}

TEST_F(MediaStreamConstraintsUtilTest, DoubleConstraints) {
  MockConstraintFactory constraint_factory;
  const double test_value = 0.01f;

  constraint_factory.basic().aspect_ratio.SetExact(test_value);
  MediaConstraints constraints = constraint_factory.CreateMediaConstraints();

  double value;
  EXPECT_FALSE(GetConstraintValueAsDouble(
      constraints, &MediaTrackConstraintSetPlatform::frame_rate, &value));
  EXPECT_TRUE(GetConstraintValueAsDouble(
      constraints, &MediaTrackConstraintSetPlatform::aspect_ratio, &value));
  EXPECT_EQ(test_value, value);
}

TEST_F(MediaStreamConstraintsUtilTest, IntConstraints) {
  MockConstraintFactory constraint_factory;
  const int test_value = 327;

  constraint_factory.basic().width.SetExact(test_value);
  MediaConstraints constraints = constraint_factory.CreateMediaConstraints();

  int value;
  EXPECT_TRUE(GetConstraintValueAsInteger(
      constraints, &MediaTrackConstraintSetPlatform::width, &value));
  EXPECT_EQ(test_value, value);

  // An exact value should also be reflected as min and max.
  EXPECT_TRUE(GetConstraintMaxAsInteger(
      constraints, &MediaTrackConstraintSetPlatform::width, &value));
  EXPECT_EQ(test_value, value);
  EXPECT_TRUE(GetConstraintMinAsInteger(
      constraints, &MediaTrackConstraintSetPlatform::width, &value));
  EXPECT_EQ(test_value, value);
}

TEST_F(MediaStreamConstraintsUtilTest, VideoTrackAdapterSettingsUnconstrained) {
  ResolutionSet resolution_set;
  DoubleRangeSet frame_rate_set;

  // No ideal values.
  {
    MockConstraintFactory constraint_factory;
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(kSourceHeight, result.target_height());
    EXPECT_EQ(kSourceWidth, result.target_width());
    EXPECT_EQ(0.0, result.min_aspect_ratio());
    EXPECT_EQ(HUGE_VAL, result.max_aspect_ratio());
    EXPECT_EQ(std::nullopt, result.max_frame_rate());
  }

  // Ideal height.
  {
    const int kIdealHeight = 400;
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().height.SetIdeal(kIdealHeight);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(kIdealHeight, result.target_height());
    EXPECT_EQ(std::round(kIdealHeight * kSourceAspectRatio),
              result.target_width());
    EXPECT_EQ(0.0, result.min_aspect_ratio());
    EXPECT_EQ(HUGE_VAL, result.max_aspect_ratio());
    EXPECT_EQ(std::nullopt, result.max_frame_rate());
  }

  // Ideal width.
  {
    const int kIdealWidth = 400;
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().width.SetIdeal(kIdealWidth);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(std::round(kIdealWidth / kSourceAspectRatio),
              result.target_height());
    EXPECT_EQ(kIdealWidth, result.target_width());
    EXPECT_EQ(0.0, result.min_aspect_ratio());
    EXPECT_EQ(HUGE_VAL, result.max_aspect_ratio());
    EXPECT_EQ(std::nullopt, result.max_frame_rate());
  }

  // Ideal aspect ratio.
  {
    const double kIdealAspectRatio = 2.0;
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(kSourceHeight, result.target_height());
    EXPECT_EQ(std::round(kSourceHeight * kIdealAspectRatio),
              result.target_width());
    EXPECT_EQ(0.0, result.min_aspect_ratio());
    EXPECT_EQ(HUGE_VAL, result.max_aspect_ratio());
    EXPECT_EQ(std::nullopt, result.max_frame_rate());
  }

  // Ideal frame rate.
  {
    const double kIdealFrameRate = 33;
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().frame_rate.SetIdeal(kIdealFrameRate);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(kSourceHeight, result.target_height());
    EXPECT_EQ(kSourceWidth, result.target_width());
    EXPECT_EQ(0.0, result.min_aspect_ratio());
    EXPECT_EQ(HUGE_VAL, result.max_aspect_ratio());
    EXPECT_EQ(kIdealFrameRate, result.max_frame_rate());
  }

  // All ideals supplied.
  {
    const int kIdealHeight = 400;
    const int kIdealWidth = 600;
    const int kIdealAspectRatio = 2.0;
    const double kIdealFrameRate = 33;
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().height.SetIdeal(kIdealHeight);
    constraint_factory.basic().width.SetIdeal(kIdealWidth);
    // Ideal aspect ratio is ignored if ideal width and height are supplied.
    constraint_factory.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    constraint_factory.basic().frame_rate.SetIdeal(kIdealFrameRate);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(kIdealHeight, result.target_height());
    EXPECT_EQ(kIdealWidth, result.target_width());
    EXPECT_EQ(0.0, result.min_aspect_ratio());
    EXPECT_EQ(HUGE_VAL, result.max_aspect_ratio());
    EXPECT_EQ(kIdealFrameRate, result.max_frame_rate());
  }
}

TEST_F(MediaStreamConstraintsUtilTest, VideoTrackAdapterSettingsConstrained) {
  // Constraints are expressed by the limits in |resolution_set| and
  // |frame_rate_set|. WebMediaTrackConstraints objects in this test are used
  // only to express ideal values.
  const int kMinHeight = 500;
  const int kMaxHeight = 1200;
  const int kMinWidth = 1000;
  const int kMaxWidth = 2000;
  constexpr double kMinAspectRatio = 1.0;
  constexpr double kMaxAspectRatio = 2.0;
  constexpr double kMinFrameRate = 20.0;
  constexpr double kMaxFrameRate = 44.0;
  ResolutionSet resolution_set(kMinHeight, kMaxHeight, kMinWidth, kMaxWidth,
                               kMinAspectRatio, kMaxAspectRatio);
  DoubleRangeSet frame_rate_set(kMinFrameRate, kMaxFrameRate);

  // No ideal values.
  {
    MockConstraintFactory constraint_factory;
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(kSourceHeight, result.target_height());
    EXPECT_EQ(kSourceWidth, result.target_width());
    EXPECT_EQ(kMinAspectRatio, result.min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio, result.max_aspect_ratio());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
  }

  // Ideal height < min.
  {
    const int kIdealHeight = 400;
    static_assert(kIdealHeight < kMinHeight,
                  "kIdealHeight must be less than kMinHeight");
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().height.SetIdeal(kIdealHeight);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(kMinHeight, result.target_height());
    // kMinWidth > kMinHeight * kNativeAspectRatio
    EXPECT_EQ(kMinWidth, result.target_width());
    EXPECT_EQ(kMinAspectRatio, result.min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio, result.max_aspect_ratio());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
  }

  // min < Ideal height < max.
  {
    const int kIdealHeight = 1100;
    static_assert(kIdealHeight > kMinHeight,
                  "kIdealHeight must be greater than kMinHeight");
    static_assert(kIdealHeight < kMaxHeight,
                  "kIdealHeight must be less than kMaxHeight");
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().height.SetIdeal(kIdealHeight);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(kIdealHeight, result.target_height());
    EXPECT_EQ(std::round(kIdealHeight * kSourceAspectRatio),
              result.target_width());
    EXPECT_EQ(kMinAspectRatio, result.min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio, result.max_aspect_ratio());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
  }

  // Ideal height > max.
  {
    const int kIdealHeight = 2000;
    static_assert(kIdealHeight > kMaxHeight,
                  "kIdealHeight must be greater than kMaxHeight");
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().height.SetIdeal(kIdealHeight);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(kMaxHeight, result.target_height());
    EXPECT_EQ(std::round(kMaxHeight * kSourceAspectRatio),
              result.target_width());
    EXPECT_EQ(kMinAspectRatio, result.min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio, result.max_aspect_ratio());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
  }

  // Ideal width < min.
  {
    const int kIdealWidth = 800;
    static_assert(kIdealWidth < kMinWidth,
                  "kIdealWidth must be less than kMinWidth");
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().width.SetIdeal(kIdealWidth);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(std::round(kMinWidth / kSourceAspectRatio),
              result.target_height());
    EXPECT_EQ(kMinWidth, result.target_width());
    EXPECT_EQ(kMinAspectRatio, result.min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio, result.max_aspect_ratio());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
  }

  // min < Ideal width < max.
  {
    const int kIdealWidth = 1800;
    static_assert(kIdealWidth > kMinWidth,
                  "kIdealWidth must be greater than kMinWidth");
    static_assert(kIdealWidth < kMaxWidth,
                  "kIdealWidth must be less than kMaxWidth");
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().width.SetIdeal(kIdealWidth);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(std::round(kIdealWidth / kSourceAspectRatio),
              result.target_height());
    EXPECT_EQ(kIdealWidth, result.target_width());
    EXPECT_EQ(kMinAspectRatio, result.min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio, result.max_aspect_ratio());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
  }

  // Ideal width > max.
  {
    const int kIdealWidth = 3000;
    static_assert(kIdealWidth > kMaxWidth,
                  "kIdealWidth must be greater than kMaxWidth");
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().width.SetIdeal(kIdealWidth);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    // kMaxHeight < kMaxWidth / kNativeAspectRatio
    EXPECT_EQ(kMaxHeight, result.target_height());
    EXPECT_EQ(kMaxWidth, result.target_width());
    EXPECT_EQ(kMinAspectRatio, result.min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio, result.max_aspect_ratio());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
  }

  // Ideal aspect ratio < min.
  {
    constexpr double kIdealAspectRatio = 0.5;
    static_assert(kIdealAspectRatio < kMinAspectRatio,
                  "kIdealAspectRatio must be less than kMinAspectRatio");
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    // Desired point is (kNativeWidth/kMinAspectRatio, kNativeWidth), but it
    // is outside the size constraints. Closest to that while maintaining the
    // same aspect ratio is (kMaxHeight, kMaxHeight * kMinAspectRatio).
    EXPECT_EQ(kMaxHeight, result.target_height());
    EXPECT_EQ(std::round(kMaxHeight * kMinAspectRatio), result.target_width());
    EXPECT_EQ(kMinAspectRatio, result.min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio, result.max_aspect_ratio());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
  }

  // min < Ideal aspect ratio < max.
  {
    constexpr double kIdealAspectRatio = 1.25;
    static_assert(kIdealAspectRatio > kMinAspectRatio,
                  "kIdealAspectRatio must be greater than kMinAspectRatio");
    static_assert(kIdealAspectRatio < kMaxAspectRatio,
                  "kIdealAspectRatio must be less than kMaxAspectRatio");
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(std::round(kSourceWidth / kIdealAspectRatio),
              result.target_height());
    EXPECT_EQ(kSourceWidth, result.target_width());
    EXPECT_EQ(kMinAspectRatio, result.min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio, result.max_aspect_ratio());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
  }

  // Ideal aspect ratio > max.
  {
    constexpr double kIdealAspectRatio = 3.0;
    static_assert(kIdealAspectRatio > kMaxAspectRatio,
                  "kIdealAspectRatio must be greater than kMaxAspectRatio");
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(kSourceHeight, result.target_height());
    EXPECT_EQ(std::round(kSourceHeight * kMaxAspectRatio),
              result.target_width());
    EXPECT_EQ(kMinAspectRatio, result.min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio, result.max_aspect_ratio());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
  }

  // Ideal frame rate < min.
  {
    constexpr double kIdealFrameRate = 3.0;
    static_assert(kIdealFrameRate < kMinFrameRate,
                  "kIdealFrameRate must be less than kMinFrameRate");
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().frame_rate.SetIdeal(kIdealFrameRate);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(kSourceHeight, result.target_height());
    EXPECT_EQ(kSourceWidth, result.target_width());
    EXPECT_EQ(kMinAspectRatio, result.min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio, result.max_aspect_ratio());
    EXPECT_EQ(kMinFrameRate, result.max_frame_rate());
  }

  // min < Ideal frame rate < max.
  {
    constexpr double kIdealFrameRate = 31.0;
    static_assert(kIdealFrameRate > kMinFrameRate,
                  "kIdealFrameRate must be greater than kMinFrameRate");
    static_assert(kIdealFrameRate < kMaxFrameRate,
                  "kIdealFrameRate must be less than kMaxFrameRate");
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().frame_rate.SetIdeal(kIdealFrameRate);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(kSourceHeight, result.target_height());
    EXPECT_EQ(kSourceWidth, result.target_width());
    EXPECT_EQ(kMinAspectRatio, result.min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio, result.max_aspect_ratio());
    EXPECT_EQ(kIdealFrameRate, result.max_frame_rate());
  }

  // Ideal frame rate > max.
  {
    constexpr double kIdealFrameRate = 1000.0;
    static_assert(kIdealFrameRate > kMaxFrameRate,
                  "kIdealFrameRate must be greater than kMaxFrameRate");
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().frame_rate.SetIdeal(kIdealFrameRate);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(kSourceHeight, result.target_height());
    EXPECT_EQ(kSourceWidth, result.target_width());
    EXPECT_EQ(kMinAspectRatio, result.min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio, result.max_aspect_ratio());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
  }

  // Ideal values inside constraints.
  {
    const int kIdealHeight = 900;
    const int kIdealWidth = 1600;
    constexpr double kIdealFrameRate = 35.0;
    static_assert(kIdealHeight > kMinHeight,
                  "kMinHeight must be greater than kMinHeight");
    static_assert(kIdealHeight < kMaxHeight,
                  "kMinHeight must be less than kMaxHeight");
    static_assert(kIdealWidth > kMinWidth,
                  "kIdealWidth must be greater than kMinWidth");
    static_assert(kIdealWidth < kMaxWidth,
                  "kIdealWidth must be less than kMaxHeight");
    static_assert(kIdealFrameRate > kMinFrameRate,
                  "kIdealFrameRate must be greater than kMinFrameRate");
    static_assert(kIdealFrameRate < kMaxFrameRate,
                  "kIdealFrameRate must be less than kMaxFrameRate");
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().height.SetIdeal(kIdealHeight);
    constraint_factory.basic().width.SetIdeal(kIdealWidth);
    constraint_factory.basic().frame_rate.SetIdeal(kIdealFrameRate);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(kIdealHeight, result.target_height());
    EXPECT_EQ(kIdealWidth, result.target_width());
    EXPECT_EQ(kMinAspectRatio, result.min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio, result.max_aspect_ratio());
    EXPECT_EQ(kIdealFrameRate, result.max_frame_rate());
  }

  // Ideal values outside constraints.
  {
    const int kIdealHeight = 2900;
    const int kIdealWidth = 3600;
    constexpr double kIdealFrameRate = 350.0;
    static_assert(kIdealHeight > kMaxHeight,
                  "kMinHeight must be greater than kMaxHeight");
    static_assert(kIdealWidth > kMaxWidth,
                  "kIdealWidth must be greater than kMaxHeight");
    static_assert(kIdealFrameRate > kMaxFrameRate,
                  "kIdealFrameRate must be greater than kMaxFrameRate");
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().height.SetIdeal(kIdealHeight);
    constraint_factory.basic().width.SetIdeal(kIdealWidth);
    constraint_factory.basic().frame_rate.SetIdeal(kIdealFrameRate);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(kMaxHeight, result.target_height());
    EXPECT_EQ(kMaxWidth, result.target_width());
    EXPECT_EQ(kMinAspectRatio, result.min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio, result.max_aspect_ratio());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
  }

  // Source frame rate.
  {
    DoubleRangeSet source_frame_rate_set(kMinFrameRate, kSourceFrameRate);
    MockConstraintFactory constraint_factory;
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, source_frame_rate_set);
    EXPECT_EQ(kSourceHeight, result.target_height());
    EXPECT_EQ(kSourceWidth, result.target_width());
    EXPECT_EQ(kMinAspectRatio, result.min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio, result.max_aspect_ratio());
    EXPECT_EQ(kSourceFrameRate, result.max_frame_rate());
  }

  // High frame rate.
  {
    constexpr double kHighFrameRate = 400.0;  // Greater than source.
    DoubleRangeSet high_frame_rate_set(kMinFrameRate, kHighFrameRate);
    static_assert(kHighFrameRate > kSourceFrameRate,
                  "kIdealFrameRate must be greater than kSourceFrameRate");
    MockConstraintFactory constraint_factory;
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, high_frame_rate_set);
    EXPECT_EQ(kSourceHeight, result.target_height());
    EXPECT_EQ(kSourceWidth, result.target_width());
    EXPECT_EQ(kMinAspectRatio, result.min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio, result.max_aspect_ratio());
    EXPECT_EQ(kHighFrameRate, result.max_frame_rate());
  }
}

TEST_F(MediaStreamConstraintsUtilTest,
       VideoTrackAdapterSettingsExpectedNativeSize) {
  ResolutionSet resolution_set;
  DoubleRangeSet frame_rate_set;

  {
    MockConstraintFactory constraint_factory;
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(kSourceHeight, result.target_height());
    EXPECT_EQ(kSourceWidth, result.target_width());
    EXPECT_EQ(0.0, result.min_aspect_ratio());
    EXPECT_EQ(HUGE_VAL, result.max_aspect_ratio());
    EXPECT_EQ(std::nullopt, result.max_frame_rate());
  }

  {
    MockConstraintFactory constraint_factory;
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(kSourceHeight, result.target_height());
    EXPECT_EQ(kSourceWidth, result.target_width());
    EXPECT_EQ(0.0, result.min_aspect_ratio());
    EXPECT_EQ(HUGE_VAL, result.max_aspect_ratio());
    EXPECT_EQ(std::nullopt, result.max_frame_rate());
  }

  // Ideals supplied.
  {
    const int kIdealHeight = 400;
    const int kIdealWidth = 600;
    const int kIdealAspectRatio = 2.0;
    const double kIdealFrameRate = 33;
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().height.SetIdeal(kIdealHeight);
    constraint_factory.basic().width.SetIdeal(kIdealWidth);
    // Ideal aspect ratio is ignored if ideal width and height are supplied.
    constraint_factory.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    constraint_factory.basic().frame_rate.SetIdeal(kIdealFrameRate);
    auto result =
        SelectTrackSettings(constraint_factory.CreateMediaConstraints().Basic(),
                            resolution_set, frame_rate_set);
    EXPECT_EQ(kIdealHeight, result.target_height());
    EXPECT_EQ(kIdealWidth, result.target_width());
    EXPECT_EQ(0.0, result.min_aspect_ratio());
    EXPECT_EQ(HUGE_VAL, result.max_aspect_ratio());
    EXPECT_EQ(kIdealFrameRate, result.max_frame_rate());
  }
}

TEST_F(MediaStreamConstraintsUtilTest,
       VideoTrackAdapterSettingsRescalingDisabledUnconstrained) {
  ResolutionSet resolution_set;
  DoubleRangeSet frame_rate_set;

  // No ideal values.
  {
    MockConstraintFactory constraint_factory;
    auto result = SelectTrackSettings(
        constraint_factory.CreateMediaConstraints().Basic(), resolution_set,
        frame_rate_set, false /* enable_rescale */);
    // No target resolution since rescaling is disabled.
    EXPECT_FALSE(result.target_size());
    // Min/Max aspect ratio are the system limits.
    EXPECT_EQ(0.0, result.min_aspect_ratio());
    EXPECT_EQ(HUGE_VAL, result.max_aspect_ratio());
    // No max frame rate since there is no ideal or max value.
    EXPECT_EQ(std::nullopt, result.max_frame_rate());
  }

  // Ideals supplied.
  {
    const int kIdealHeight = 400;
    const int kIdealWidth = 600;
    const int kIdealAspectRatio = 2.0;
    const double kIdealFrameRate = 33;
    MockConstraintFactory constraint_factory;
    // Ideal height, width and aspectRatio are ignored if rescaling is disabled.
    constraint_factory.basic().height.SetIdeal(kIdealHeight);
    constraint_factory.basic().width.SetIdeal(kIdealWidth);
    constraint_factory.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    constraint_factory.basic().frame_rate.SetIdeal(kIdealFrameRate);
    auto result = SelectTrackSettings(
        constraint_factory.CreateMediaConstraints().Basic(), resolution_set,
        frame_rate_set, false /* enable_rescale */);
    // No target resolution since rescaling is disabled.
    EXPECT_FALSE(result.target_size());
    // Min/Max aspect ratio are the system limits.
    EXPECT_EQ(0.0, result.min_aspect_ratio());
    EXPECT_EQ(HUGE_VAL, result.max_aspect_ratio());
    // Max frame rate corresponds to the ideal value.
    EXPECT_EQ(kIdealFrameRate, result.max_frame_rate());
  }
}

TEST_F(MediaStreamConstraintsUtilTest,
       VideoTrackAdapterSettingsRescalingDisabledConstrained) {
  // Constraints are expressed by the limits in |resolution_set| and
  // |frame_rate_set|. WebMediaTrackConstraints objects in this test are used
  // only to express ideal values.
  const int kMinHeight = 500;
  const int kMaxHeight = 1200;
  const int kMinWidth = 1000;
  const int kMaxWidth = 2000;
  constexpr double kMinAspectRatio = 1.0;
  constexpr double kMaxAspectRatio = 2.0;
  constexpr double kMinFrameRate = 20.0;
  constexpr double kMaxFrameRate = 44.0;
  ResolutionSet resolution_set(kMinHeight, kMaxHeight, kMinWidth, kMaxWidth,
                               kMinAspectRatio, kMaxAspectRatio);
  DoubleRangeSet frame_rate_set(kMinFrameRate, kMaxFrameRate);

  // No ideal values.
  {
    MockConstraintFactory constraint_factory;
    auto result = SelectTrackSettings(
        constraint_factory.CreateMediaConstraints().Basic(), resolution_set,
        frame_rate_set, false /* enable_rescale */);
    // No target size since rescaling is disabled.
    EXPECT_FALSE(result.target_size());
    // Min/Max aspect ratio and max frame rate come from the constraints
    // expressed in |resolution_set| and |frame_rate_set|.
    EXPECT_EQ(kMinAspectRatio, result.min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio, result.max_aspect_ratio());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
  }

  // Ideal values supplied.
  {
    const int kIdealHeight = 900;
    const int kIdealWidth = 1600;
    constexpr double kIdealFrameRate = 35.0;
    MockConstraintFactory constraint_factory;
    constraint_factory.basic().height.SetIdeal(kIdealHeight);
    constraint_factory.basic().width.SetIdeal(kIdealWidth);
    constraint_factory.basic().frame_rate.SetIdeal(kIdealFrameRate);
    auto result = SelectTrackSettings(
        constraint_factory.CreateMediaConstraints().Basic(), resolution_set,
        frame_rate_set, false /* enable_rescale */);
    // No target size since rescaling is disabled, despite ideal values.
    EXPECT_FALSE(result.target_size());
    // Min/Max aspect ratio and max frame rate come from the constraints
    // expressed in |resolution_set| and |frame_rate_set|.
    EXPECT_EQ(kMinAspectRatio, result.min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio, result.max_aspect_ratio());
    EXPECT_EQ(kIdealFrameRate, result.max_frame_rate());
  }
}

}  // namespace blink
```