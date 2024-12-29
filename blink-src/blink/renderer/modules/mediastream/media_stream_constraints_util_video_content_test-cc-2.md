Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is part of a larger test file for the Chromium Blink engine. The code deals with video constraints for media streams.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core purpose:** The code is within a `TEST_F` block in C++, suggesting it's a unit test. The test suite name `MediaStreamConstraintsUtilVideoContentTest` indicates the code tests the utility for handling video content constraints within media streams. The function names within the tests (like `MandatoryFrameRate`, `AdvancedMinMaxResolutionFrameRate`, `AdvancedExactResolution`, etc.) clearly point to testing different types of video constraints.

2. **Analyze individual test cases:**  Each `TEST_F` function represents a specific scenario being tested. Look for common patterns and themes in the test names and the assertions (`EXPECT_TRUE`, `EXPECT_EQ`, `EXPECT_FALSE`).

    * **Basic Constraints:** Tests like `MandatoryFrameRate` check how basic constraints (like `min`, `max`, `ideal` frame rate) are handled.
    * **Advanced Constraints:** Tests with "Advanced" in their name explore how more complex constraint sets (using `AddAdvanced()`) are evaluated and how conflicts between them are resolved.
    * **Resolution and Aspect Ratio:** Many tests deal with `width`, `height`, and `aspect_ratio` constraints, examining how the system selects the best video settings based on these constraints.
    * **Frame Rate:** Several tests focus specifically on frame rate constraints.
    * **`resize_mode`:** The `MandatoryResizeMode` test looks at how the `resize_mode` constraint affects the final video settings and the use of `track_adapter_settings`.
    * **`noise_reduction`:** Tests like `AdvancedNoiseReduction` and `AdvancedContradictoryNoiseReduction` verify how the `noise_reduction` constraint is handled, including when advanced constraints conflict.
    * **`device_id`:** Tests involving "DeviceID" confirm that the correct video device is selected based on the constraints.
    * **`ResolutionChangePolicy`:**  This test verifies how the system determines if the video resolution can be adjusted after the initial selection based on the provided constraints.

3. **Identify connections to web technologies:**  The code is part of the Blink engine, which renders web pages. This means the constraints being tested directly relate to the WebRTC API used in JavaScript, and the `<video>` element in HTML. Constraints specified in JavaScript using `getUserMedia()` directly influence the outcome of these tests.

4. **Infer logical reasoning:** The tests involve setting up various combinations of constraints and then asserting the *expected* output. This implies a logical selection process within the `SelectSettings()` function (which is not fully shown but is used in the tests). The code implicitly tests prioritization of constraints (e.g., `exact` over `ideal`, advanced constraints).

5. **Identify potential user errors:**  The tests with "Contradictory" in their name are specifically designed to check how the system handles conflicting constraints. This suggests that users providing incompatible constraints via JavaScript are a potential source of errors.

6. **Trace user actions (debugging perspective):** To reach this code, a developer would likely be working on the media stream implementation in Chromium. They might be adding a new feature, fixing a bug related to constraint handling, or simply ensuring the existing logic works correctly. The tests serve as a way to verify these scenarios. A user wouldn't directly interact with this C++ code, but their actions in a web browser (like granting camera access with specific constraints) would trigger the underlying logic that this code tests.

7. **Synthesize the information:** Combine the observations from the above steps into a concise summary, focusing on the core functionalities and relationships to web technologies, logic, and potential errors.

8. **Address the "Part 3" instruction:** Since this is part 3, focus on summarizing the accumulated knowledge from the previous parts (even though the previous parts weren't provided in this specific prompt, the idea is to synthesize the understanding of the file).

By following these steps, one can arrive at a comprehensive and accurate summary of the provided code snippet.
这是对 `blink/renderer/modules/mediastream/media_stream_constraints_util_video_content_test.cc` 文件功能的总结，基于提供的代码片段。由于这是第 3 部分，我将尝试归纳其核心功能，并结合前两部分的理解（即使我没有看到前两部分，但我可以根据这一部分的测试内容推断）。

**功能归纳:**

这个代码片段所在的测试文件主要功能是 **测试 Chromium Blink 引擎中用于处理和解析视频媒体流约束的核心逻辑**。  它通过一系列单元测试，验证了 `MediaStreamConstraintsUtil` 类在处理不同类型的视频约束条件（包括基本约束和高级约束）时的行为是否符合预期。  这些约束条件来源于 Web API（例如 `getUserMedia`）中用户或应用程序设置的参数。

具体来说，从这段代码可以看出，它专注于测试以下方面的功能：

* **帧率约束 (Frame Rate Constraints):** 测试 `min`, `max`, 和 `ideal` 帧率约束如何被解析和应用，以及在存在冲突或范围约束时如何选择合适的帧率。
* **分辨率约束 (Resolution Constraints):**  测试 `minWidth`, `maxWidth`, `minHeight`, `maxHeight`, `exactWidth`, `exactHeight`, `aspectRatio` 等约束如何影响最终选择的视频分辨率。  包括在指定 `ideal` 分辨率时，如何根据其他约束进行调整。
* **调整模式约束 (Resize Mode Constraint):** 测试 `resizeMode` 约束（例如 "none" 或 "crop-and-scale"）如何影响视频的缩放行为，以及是否会启用 `track_adapter_settings` 进行进一步的调整。
* **高级约束 (Advanced Constraints):**  重点测试如何处理包含多个约束集合的 "高级" 约束。  验证当多个高级约束集合存在冲突时，哪个集合会被采纳，哪个会被忽略。
* **噪声抑制约束 (Noise Reduction Constraint):** 测试 `googNoiseReduction` 约束如何被处理，以及在高级约束中发生冲突时的处理方式。
* **设备 ID 约束 (Device ID Constraint):**  测试如何根据指定的设备 ID 约束（`exact` 或 `ideal`）选择特定的视频输入设备。
* **分辨率变化策略 (Resolution Change Policy):** 测试根据不同的约束条件，最终媒体流是否允许动态调整分辨率 (`ANY_WITHIN_LIMIT` 或 `FIXED_RESOLUTION` 或 `FIXED_ASPECT_RATIO`)。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

虽然这段代码是 C++，但它直接支撑了 Web 标准中与媒体流相关的 JavaScript API，特别是 `getUserMedia()`。

* **JavaScript (getUserMedia):**  开发者在 JavaScript 中使用 `getUserMedia()` 请求访问用户的摄像头或屏幕共享时，可以传入一个 `constraints` 对象来指定所需的媒体流属性。 例如：

```javascript
navigator.mediaDevices.getUserMedia({
  video: {
    width: { ideal: 1280 },
    height: { ideal: 720 },
    frameRate: { min: 30 }
  }
})
.then(function(stream) {
  // 使用 stream
})
.catch(function(err) {
  // 处理错误
});
```

这段 JavaScript 代码中的 `width`, `height`, `frameRate` 等约束，最终会被 Blink 引擎解析，并由类似这段 C++ 代码进行测试，以确保约束被正确理解和应用。

* **HTML (`<video>` 元素):**  获取到的媒体流通常会被绑定到 HTML 的 `<video>` 元素上进行显示。  约束的选择会直接影响 `<video>` 元素中呈现的视频的分辨率、帧率等属性。例如，如果约束中指定了固定的分辨率，那么 `<video>` 元素显示的视频分辨率将尽可能接近该值。

* **CSS (间接关系):** CSS 可以控制 `<video>` 元素的显示尺寸和缩放方式，但这发生在媒体流被成功获取之后。  约束的选择发生在获取媒体流的阶段，它决定了媒体流本身的属性，而 CSS 决定了如何在页面上 *显示* 这个媒体流。  虽然 CSS 不直接参与约束的处理，但用户可能会通过调整浏览器窗口大小或应用 CSS 样式来观察到不同约束带来的效果（例如，固定分辨率的视频在不同尺寸的 `<video>` 元素中可能会出现黑边或被裁剪）。

**逻辑推理的假设输入与输出:**

让我们以 `TEST_F(MediaStreamConstraintsUtilVideoContentTest, AdvancedMinMaxResolutionFrameRate)` 中的一个场景为例：

**假设输入 (基于代码)：**

* **基本约束:**  无（通过 `constraint_factory_.Reset()` 清空）
* **高级约束 1:** `minWidth = 2000000000`, `minHeight = 2000000000`
* **高级约束 2:** `maxWidth = 500`, `maxHeight = 400`, `exactAspectRatio = 5.0 / 4.0`
* **高级约束 3:** `maxFrameRate = 10.0`

**预期输出 (基于 `EXPECT_EQ` 断言):**

* `result.Height()`: `400`
* `result.Width()`: `500`
* `result.FrameRate()`: `10.0`
* `result.track_adapter_settings().min_aspect_ratio()`: `5.0 / 4.0`
* `result.track_adapter_settings().max_aspect_ratio()`: `5.0 / 4.0`

**推理过程:**

1. 高级约束 1 由于要求极高的最小分辨率，无法被满足，因此被忽略。
2. 高级约束 2 可以被满足，它限定了最大分辨率和固定的宽高比。
3. 高级约束 3 进一步限制了最大帧率。
4. 因此，最终选择的设置会满足高级约束 2 和 3 的要求。分辨率为 500x400（符合 5:4 的宽高比），帧率不超过 10.0。

**用户或编程常见的使用错误举例说明:**

* **矛盾的约束:** 用户在 JavaScript 中设置了相互矛盾的约束，例如：

```javascript
{
  video: {
    width: { exact: 640, min: 1280 }
  }
}
```

这里 `exact` 要求宽度必须是 640，而 `min` 要求宽度至少是 1280，这两个约束无法同时满足。  这段测试代码中的 "AdvancedContradictory..." 相关的测试用例就是为了验证引擎如何处理这类错误，通常会忽略后面的冲突约束或选择一个默认值。

* **超出硬件能力的约束:** 用户设置了超出摄像头或屏幕硬件能力的约束，例如请求 4K 分辨率的旧摄像头。  虽然测试代码不直接模拟硬件限制，但它验证了在无法满足所有约束的情况下，引擎会如何回退到可行的配置。

* **对 `resizeMode` 理解不足:** 开发者可能错误地理解 `resizeMode` 的作用，例如在不希望进行任何缩放的情况下，错误地设置了 "crop-and-scale"。  `MandatoryResizeMode` 的测试用例验证了不同 `resizeMode` 的行为，帮助开发者理解其效果。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户打开一个网页或 Web 应用，该应用需要访问用户的摄像头或屏幕。**
2. **JavaScript 代码使用 `navigator.mediaDevices.getUserMedia()` 发起请求，并传递包含视频约束的 `constraints` 对象。**
3. **浏览器（Chromium）接收到这个请求，并将约束传递给 Blink 渲染引擎。**
4. **Blink 引擎中的 `MediaStreamConstraintsUtil` 类会解析这些约束。**
5. **在开发或调试过程中，开发者可能会运行 `media_stream_constraints_util_video_content_test.cc` 中的单元测试，以验证约束解析和选择逻辑的正确性。**
6. **如果测试失败，开发者会检查相关的 C++ 代码（例如 `MediaStreamConstraintsUtil::SelectSettings()` 方法），查看约束是如何被评估和选择的。**
7. **开发者可能会使用调试器来跟踪约束解析的流程，查看哪些约束被满足，哪些被忽略，以及最终选择了什么样的媒体轨道设置。**
8. **错误日志或断点可能会指向 `media_stream_constraints_util_video_content_test.cc` 文件中的特定测试用例，帮助开发者定位问题。**

总之，这个测试文件是确保 Chromium Blink 引擎能够正确、有效地处理视频媒体流约束的关键组成部分，它保证了 Web 开发者通过 `getUserMedia()` 设置的视频需求能够被合理地转化为底层的媒体流配置。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_video_content_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
c().frame_rate.SetMin(kMinFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kMinFrameRate, result.FrameRate());
    EXPECT_EQ(std::optional<double>(), result.max_frame_rate());
    CheckNonFrameRateDefaults(result);
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result,
                                                            kMinFrameRate);
  }

  // Ideal within range.
  {
    constraint_factory_.Reset();
    const double kIdealFrameRate = 45.0;
    const double kMinFrameRate = 35.0;
    const double kMaxFrameRate = 50.0;
    constraint_factory_.basic().frame_rate.SetIdeal(kIdealFrameRate);
    constraint_factory_.basic().frame_rate.SetMin(kMinFrameRate);
    constraint_factory_.basic().frame_rate.SetMax(kMaxFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kIdealFrameRate, result.FrameRate());
    EXPECT_EQ(kMinFrameRate, result.min_frame_rate());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
    CheckNonFrameRateDefaults(result);
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result,
                                                            kIdealFrameRate);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, MandatoryResizeMode) {
  const int kIdealWidth = 641;
  const int kIdealHeight = 480;
  constraint_factory_.Reset();
  constraint_factory_.basic().width.SetIdeal(kIdealWidth);
  constraint_factory_.basic().height.SetIdeal(kIdealHeight);
  constraint_factory_.basic().resize_mode.SetExact("none");
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // Screen capture will proceed at 641x480, which will be considered "native".
  // No rescaling will occur since it is explicitly disabled.
  EXPECT_EQ(result.Width(), kIdealWidth);
  EXPECT_EQ(result.Height(), kIdealHeight);
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());

  constraint_factory_.basic().resize_mode.SetExact("crop-and-scale");
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(result.Width(), kIdealWidth);
  EXPECT_EQ(result.Height(), kIdealHeight);
  EXPECT_EQ(result.track_adapter_settings().target_width(), kIdealWidth);
  EXPECT_EQ(result.track_adapter_settings().target_height(), kIdealHeight);
}

// The "Advanced" tests check selection criteria involving advanced constraint
// sets.
TEST_F(MediaStreamConstraintsUtilVideoContentTest,
       AdvancedMinMaxResolutionFrameRate) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.width.SetMin(2000000000);
  advanced1.height.SetMin(2000000000);
  // The first advanced set cannot be satisfied and is therefore ignored in all
  // calls to SelectSettings().
  // In this case, default settings must be selected.
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
  EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
  CheckNonResolutionDefaults(result);
  CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);

  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.height.SetMax(400);
  advanced2.width.SetMax(500);
  advanced2.aspect_ratio.SetExact(5.0 / 4.0);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(400, result.Height());
  EXPECT_EQ(500, result.Width());
  CheckNonResolutionDefaults(result);
  EXPECT_EQ(5.0 / 4.0, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(5.0 / 4.0, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result);

  MediaTrackConstraintSetPlatform& advanced3 =
      constraint_factory_.AddAdvanced();
  advanced3.frame_rate.SetMax(10.0);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // The third advanced set is supported in addition to the previous set.
  EXPECT_EQ(400, result.Height());
  EXPECT_EQ(500, result.Width());
  EXPECT_EQ(10.0, result.FrameRate());
  EXPECT_EQ(std::optional<bool>(), result.noise_reduction());
  EXPECT_EQ(std::string(), result.device_id());
  EXPECT_EQ(5.0 / 4.0, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(5.0 / 4.0, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result, 10.0);

  MediaTrackConstraintSetPlatform& advanced4 =
      constraint_factory_.AddAdvanced();
  advanced4.width.SetExact(1000);
  advanced4.height.SetExact(1000);
  result = SelectSettings();
  // The fourth advanced set cannot be supported in combination with the
  // previous two sets, so it must be ignored.
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(400, result.Height());
  EXPECT_EQ(500, result.Width());
  EXPECT_EQ(10.0, result.FrameRate());
  EXPECT_EQ(std::optional<bool>(), result.noise_reduction());
  EXPECT_EQ(std::string(), result.device_id());
  EXPECT_EQ(5.0 / 4.0, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(5.0 / 4.0, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result, 10.0);

  constraint_factory_.basic().width.SetIdeal(100);
  constraint_factory_.basic().height.SetIdeal(100);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // The closest point to (100, 100) that satisfies all previous constraint
  // sets is its projection on the aspect-ratio line 5.0/4.0.
  // This is a point m*(4, 5) such that Dot((4,5), (100 - m(4,5))) == 0.
  // This works out to be m = 900/41.
  EXPECT_EQ(std::round(4.0 * 900.0 / 41.0), result.Height());
  EXPECT_EQ(std::round(5.0 * 900.0 / 41.0), result.Width());
  EXPECT_EQ(10.0, result.FrameRate());
  EXPECT_EQ(std::optional<bool>(), result.noise_reduction());
  EXPECT_EQ(std::string(), result.device_id());
  EXPECT_EQ(5.0 / 4.0, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(5.0 / 4.0, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result, 10.0);

  constraint_factory_.basic().width.SetIdeal(2000);
  constraint_factory_.basic().height.SetIdeal(1500);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // The projection of (2000,1500) on the aspect-ratio line 5.0/4.0 is beyond
  // the maximum of (400, 500), so use the maximum allowed resolution.
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(400, result.Height());
  EXPECT_EQ(500, result.Width());
  EXPECT_EQ(10.0, result.FrameRate());
  EXPECT_EQ(std::optional<bool>(), result.noise_reduction());
  EXPECT_EQ(std::string(), result.device_id());
  EXPECT_EQ(5.0 / 4.0, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(5.0 / 4.0, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result, 10.0);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, AdvancedExactResolution) {
  {
    constraint_factory_.Reset();
    MediaTrackConstraintSetPlatform& advanced1 =
        constraint_factory_.AddAdvanced();
    advanced1.width.SetExact(40000000);
    advanced1.height.SetExact(40000000);
    MediaTrackConstraintSetPlatform& advanced2 =
        constraint_factory_.AddAdvanced();
    advanced2.width.SetExact(300000000);
    advanced2.height.SetExact(300000000);
    auto result = SelectSettings();
    // None of the constraint sets can be satisfied. Default resolution should
    // be selected.
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
    EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
    CheckNonResolutionDefaults(result);
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);

    MediaTrackConstraintSetPlatform& advanced3 =
        constraint_factory_.AddAdvanced();
    advanced3.width.SetExact(1920);
    advanced3.height.SetExact(1080);
    result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(1920, result.Width());
    EXPECT_EQ(1080, result.Height());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1920.0 / 1080.0,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(1920.0 / 1080.0,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);

    MediaTrackConstraintSetPlatform& advanced4 =
        constraint_factory_.AddAdvanced();
    advanced4.width.SetExact(640);
    advanced4.height.SetExact(480);
    result = SelectSettings();
    // The fourth constraint set contradicts the third set. The fourth set
    // should be ignored.
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(1920, result.Width());
    EXPECT_EQ(1080, result.Height());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1920.0 / 1080.0,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(1920.0 / 1080.0,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);

    constraint_factory_.basic().width.SetIdeal(800);
    constraint_factory_.basic().height.SetIdeal(600);
    result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The exact constraints has priority over ideal.
    EXPECT_EQ(1920, result.Width());
    EXPECT_EQ(1080, result.Height());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1920.0 / 1080.0,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(1920.0 / 1080.0,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest,
       AdvancedResolutionAndFrameRate) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.width.SetExact(1920);
  advanced1.height.SetExact(1080);
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.frame_rate.SetExact(60.0);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(1920, result.Width());
  EXPECT_EQ(1080, result.Height());
  EXPECT_EQ(60.0, result.FrameRate());
  EXPECT_EQ(1920.0 / 1080.0,
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(1920.0 / 1080.0,
            result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result, 60.0);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, AdvancedNoiseReduction) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.width.SetMin(640);
  advanced1.height.SetMin(480);
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  const int kMinWidth = 4000;
  const int kMinHeight = 2000;
  advanced2.width.SetMin(kMinWidth);
  advanced2.height.SetMin(kMinHeight);
  advanced2.goog_noise_reduction.SetExact(false);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(kMinWidth, result.Width());
  // Preserves default aspect ratio.
  EXPECT_EQ(static_cast<int>(
                std::round(result.Width() / kDefaultScreenCastAspectRatio)),
            result.Height());
  EXPECT_TRUE(result.noise_reduction() && !*result.noise_reduction());
  EXPECT_EQ(kMinWidth / static_cast<double>(kMaxScreenCastDimension),
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(static_cast<double>(kMaxScreenCastDimension) / kMinHeight,
            result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

// The "AdvancedContradictory" tests check that advanced constraint sets that
// contradict previous constraint sets are ignored.
TEST_F(MediaStreamConstraintsUtilVideoContentTest,
       AdvancedContradictoryNoiseReduction) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.width.SetExact(640);
  advanced1.height.SetExact(480);
  advanced1.goog_noise_reduction.SetExact(true);
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.width.SetExact(1920);
  advanced2.height.SetExact(1080);
  advanced2.goog_noise_reduction.SetExact(false);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(640, result.Width());
  EXPECT_EQ(480, result.Height());
  EXPECT_TRUE(result.noise_reduction() && *result.noise_reduction());
  EXPECT_EQ(640.0 / 480.0, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(640.0 / 480.0, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest,
       AdvancedContradictoryExactResolution) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.width.SetExact(640);
  advanced1.height.SetExact(480);
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.width.SetExact(1920);
  advanced2.height.SetExact(1080);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(640, result.Width());
  EXPECT_EQ(480, result.Height());
  CheckNonResolutionDefaults(result);
  EXPECT_EQ(640.0 / 480.0, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(640.0 / 480.0, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest,
       AdvancedContradictoryMaxMinResolutionFrameRate) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.width.SetMax(640);
  advanced1.height.SetMax(480);
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.width.SetMin(1920);
  advanced2.height.SetMin(1080);
  advanced2.frame_rate.SetExact(60.0);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(640, result.Width());
  EXPECT_EQ(480, result.Height());
  // Resolution cannot exceed the requested resolution.
  EXPECT_EQ(kDefaultScreenCastFrameRate, result.FrameRate());
  EXPECT_EQ(kMinScreenCastDimension / 480.0,
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(640.0 / kMinScreenCastDimension,
            result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest,
       AdvancedContradictoryMinMaxResolutionFrameRate) {
  const int kMinHeight = 2600;
  const int kMinWidth = 2800;
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.width.SetMin(kMinWidth);
  advanced1.height.SetMin(kMinHeight);
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.width.SetMax(640);
  advanced2.height.SetMax(480);
  advanced2.frame_rate.SetExact(60.0);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(std::round(kMinHeight * kDefaultScreenCastAspectRatio),
            result.Width());
  EXPECT_EQ(kMinHeight, result.Height());
  EXPECT_EQ(kDefaultScreenCastFrameRate, result.FrameRate());
  EXPECT_EQ(static_cast<double>(kMinWidth) / kMaxScreenCastDimension,
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(static_cast<double>(kMaxScreenCastDimension) / kMinHeight,
            result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest,
       AdvancedContradictoryExactAspectRatio) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  const double kMinAspectRatio = 5.0;
  advanced1.aspect_ratio.SetExact(kMinAspectRatio);
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.aspect_ratio.SetExact(3.0);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(std::round(kDefaultScreenCastHeight * kMinAspectRatio),
            result.Width());
  EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
  CheckNonResolutionDefaults(result);
  EXPECT_EQ(kMinAspectRatio,
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(kMinAspectRatio,
            result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest,
       AdvancedContradictoryAspectRatioRange) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  const double kMinAspectRatio = 5.0;
  advanced1.aspect_ratio.SetMin(kMinAspectRatio);
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.aspect_ratio.SetMax(3.0);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(std::round(kDefaultScreenCastHeight * kMinAspectRatio),
            result.Width());
  EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
  CheckNonResolutionDefaults(result);
  EXPECT_EQ(kMinAspectRatio,
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(
      kMaxScreenCastDimension / static_cast<double>(kMinScreenCastDimension),
      result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest,
       AdvancedContradictoryExactFrameRate) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.frame_rate.SetExact(40.0);
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.frame_rate.SetExact(45.0);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(40.0, result.FrameRate());
  CheckNonFrameRateDefaults(result);
  CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result, 40.0);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest,
       AdvancedContradictoryFrameRateRange) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.frame_rate.SetMin(40.0);
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.frame_rate.SetMax(35.0);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_LE(40.0, result.FrameRate());
  CheckNonFrameRateDefaults(result);
  CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest,
       AdvancedContradictoryWidthFrameRate) {
  const int kMaxWidth = 1920;
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.width.SetMax(kMaxWidth);
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.width.SetMin(2000);
  advanced2.frame_rate.SetExact(10.0);
  MediaTrackConstraintSetPlatform& advanced3 =
      constraint_factory_.AddAdvanced();
  advanced3.frame_rate.SetExact(90.0);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(kMaxWidth, result.Width());
  EXPECT_EQ(std::round(kMaxWidth / kDefaultScreenCastAspectRatio),
            result.Height());
  EXPECT_EQ(90.0, result.FrameRate());
  EXPECT_EQ(
      static_cast<double>(kMinScreenCastDimension) / kMaxScreenCastDimension,
      result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(static_cast<double>(kMaxWidth) / kMinScreenCastDimension,
            result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result, 90.0);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest,
       AdvancedContradictoryHeightFrameRate) {
  const int kMaxHeight = 2000;
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.height.SetMax(kMaxHeight);
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.height.SetMin(4500);
  advanced2.frame_rate.SetExact(10.0);
  MediaTrackConstraintSetPlatform& advanced3 =
      constraint_factory_.AddAdvanced();
  advanced3.frame_rate.SetExact(60.0);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(kMaxHeight * kDefaultScreenCastAspectRatio, result.Width());
  // Height defaults to explicitly given max constraint.
  EXPECT_EQ(kMaxHeight, result.Height());
  EXPECT_EQ(60.0, result.FrameRate());
  EXPECT_EQ(static_cast<double>(kMinScreenCastDimension) / kMaxHeight,
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(
      static_cast<double>(kMaxScreenCastDimension) / kMinScreenCastDimension,
      result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result, 60.0);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, AdvancedDeviceID) {
  const String kDeviceID1 = "fake_device_1";
  const String kDeviceID2 = "fake_device_2";
  const String kDeviceID3 = "fake_device_3";
  const String kDeviceID4 = "fake_device_4";
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  Vector<String> id_vector1 = {kDeviceID1, kDeviceID2};
  advanced1.device_id.SetExact(id_vector1);
  Vector<String> id_vector2 = {kDeviceID2, kDeviceID3};
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.device_id.SetExact(id_vector2);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // kDeviceID2 must be selected because it is the only one that satisfies both
  // advanced sets.
  EXPECT_EQ(kDeviceID2.Utf8(), result.device_id());
  CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest,
       AdvancedContradictoryDeviceID) {
  const String kDeviceID1 = "fake_device_1";
  const String kDeviceID2 = "fake_device_2";
  const String kDeviceID3 = "fake_device_3";
  const String kDeviceID4 = "fake_device_4";
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  Vector<String> id_vector1 = {kDeviceID1, kDeviceID2};
  advanced1.device_id.SetExact(id_vector1);
  Vector<String> id_vector2 = {kDeviceID3, kDeviceID4};
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.device_id.SetExact(id_vector2);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // The second advanced set must be ignored because it contradicts the first
  // set.
  EXPECT_EQ(kDeviceID1.Utf8(), result.device_id());
  CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, AdvancedIdealDeviceID) {
  const String kDeviceID1 = "fake_device_1";
  const String kDeviceID2 = "fake_device_2";
  const String kDeviceID3 = "fake_device_3";
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced = constraint_factory_.AddAdvanced();
  Vector<String> id_vector1 = {kDeviceID1, kDeviceID2};
  advanced.device_id.SetExact(id_vector1);

  Vector<String> id_vector2 = {kDeviceID2, kDeviceID3};
  constraint_factory_.basic().device_id.SetIdeal(id_vector2);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // Should select kDeviceID2, which appears in ideal and satisfies the advanced
  // set.
  EXPECT_EQ(kDeviceID2.Utf8(), result.device_id());
  CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, AdvancedResizeMode) {
  const int kIdealWidth = 641;
  const int kIdealHeight = 480;
  constraint_factory_.Reset();
  constraint_factory_.basic().width.SetIdeal(kIdealWidth);
  constraint_factory_.basic().height.SetIdeal(kIdealHeight);
  MediaTrackConstraintSetPlatform& advanced = constraint_factory_.AddAdvanced();
  advanced.resize_mode.SetExact("none");
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // Screen capture will proceed at 641x480, which will be considered "native".
  // No rescaling will occur since it is explicitly disabled in the advanced
  // constraint set.
  EXPECT_EQ(result.Width(), kIdealWidth);
  EXPECT_EQ(result.Height(), kIdealHeight);
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());

  advanced.resize_mode.SetExact("crop-and-scale");
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // Screen capture will proceed at 641x480, which will be considered "native".
  // No rescaling will occur since it is explicitly disabled in the advanced
  // constraint set.
  EXPECT_EQ(result.Width(), kIdealWidth);
  EXPECT_EQ(result.Height(), kIdealHeight);
  EXPECT_TRUE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(result.track_adapter_settings().target_width(), kIdealWidth);
  EXPECT_EQ(result.track_adapter_settings().target_height(), kIdealHeight);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, ResolutionChangePolicy) {
  {
    constraint_factory_.Reset();
    auto result = SelectSettings();
    EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
    EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
    // Resolution can be adjusted.
    EXPECT_EQ(media::ResolutionChangePolicy::ANY_WITHIN_LIMIT,
              result.ResolutionChangePolicy());
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
  }
  {
    constraint_factory_.Reset();
    auto result = SelectSettings(mojom::MediaStreamType::GUM_TAB_VIDEO_CAPTURE);
    EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
    EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
    // Default policy for tab capture is fixed resolution.
    EXPECT_EQ(media::ResolutionChangePolicy::FIXED_RESOLUTION,
              result.ResolutionChangePolicy());
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
  }
  {
    constraint_factory_.Reset();
    constraint_factory_.basic().width.SetIdeal(630);
    constraint_factory_.basic().height.SetIdeal(470);
    auto result = SelectSettings();
    EXPECT_EQ(630, result.Width());
    EXPECT_EQ(470, result.Height());
    // Resolution can be adjusted because ideal was used to select the
    // resolution.
    EXPECT_EQ(media::ResolutionChangePolicy::ANY_WITHIN_LIMIT,
              result.ResolutionChangePolicy());
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
  }
  {
    constraint_factory_.Reset();
    constraint_factory_.basic().width.SetExact(640);
    constraint_factory_.basic().height.SetExact(480);
    auto result = SelectSettings();
    EXPECT_EQ(640, result.Width());
    EXPECT_EQ(480, result.Height());
    EXPECT_EQ(media::ResolutionChangePolicy::FIXED_RESOLUTION,
              result.ResolutionChangePolicy());
    EXPECT_EQ(640.0 / 480.0,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(640.0 / 480.0,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }
  {
    constraint_factory_.Reset();
    constraint_factory_.basic().width.SetExact(1000);
    constraint_factory_.basic().height.SetExact(500);
    auto result = SelectSettings();
    EXPECT_EQ(1000, result.Width());
    EXPECT_EQ(500, result.Height());
    EXPECT_EQ(media::ResolutionChangePolicy::FIXED_RESOLUTION,
              result.ResolutionChangePolicy());
    EXPECT_EQ(1000.0 / 500.0,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(1000.0 / 500.0,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }
  {
    constraint_factory_.Reset();
    constraint_factory_.basic().width.SetExact(630);
    constraint_factory_.basic().height.SetExact(470);
    auto result = SelectSettings();
    EXPECT_EQ(630, result.Width());
    EXPECT_EQ(470, result.Height());
    EXPECT_EQ(media::ResolutionChangePolicy::FIXED_RESOLUTION,
              result.ResolutionChangePolicy());
    EXPECT_EQ(630.0 / 470.0,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(630.0 / 470.0,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }
  {
    constraint_factory_.Reset();
    constraint_factory_.basic().width.SetMax(800);
    constraint_factory_.basic().height.SetMax(600);
    constraint_factory_.basic().width.SetMin(400);
    constraint_factory_.basic().height.SetMin(300);
    auto result = SelectSettings();
    EXPECT_EQ(800, result.Width());
    EXPECT_EQ(600, result.Height());
    // When the aspect ratio of the max resolution equals the aspect ratio of
    // the min resolution, the algorithm sets fixed aspect ratio policy.
    EXPECT_EQ(media::ResolutionChangePolicy::FIXED_ASPECT_RATIO,
              result.ResolutionChangePolicy());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }
  {
    constraint_factory_.Reset();
    constraint_factory_.basic().width.SetMax(800);
    constraint_factory_.basic().height.SetMax(600);
    constraint_factory_.basic().width.SetMin(400);
    constraint_factory_.basic().height.SetMin(400);
    auto result = SelectSettings();
    EXPECT_EQ(800, result.Width());
    EXPECT_EQ(600, result.Height());
    // When the aspect ratio of the max resolution differs from the aspect ratio
    // of the min resolution, the algorithm sets any-within-limit policy.
    EXPECT_EQ(media::ResolutionChangePolicy::ANY_WITHIN_LIMIT,
              result.ResolutionChangePolicy());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }
  {
    constraint_factory_.Reset();
    constraint_factory_.basic().height.SetMax(4000);
    constraint_factory_.basic().width.SetMax(4000);
    auto result = SelectSettings();
    EXPECT_EQ(4000, result.Width());
    EXPECT_EQ(4000, result.Height());
    // Only specifying a maximum resolution allows resolution adjustment.
    EXPECT_EQ(media::ResolutionChangePolicy::ANY_WITHIN_LIMIT,
              result.ResolutionChangePolicy());
    EXPECT_EQ(1.0 / 4000, result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(4000.0, result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }
}

}  // namespace media_stream_constraints_util_video_content_test
}  // namespace blink

"""


```