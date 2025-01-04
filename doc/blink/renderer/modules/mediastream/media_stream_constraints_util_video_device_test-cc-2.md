Response:
The user wants a summary of the provided C++ code, which is a test file for video device constraints in the Chromium Blink engine.

Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The file name clearly indicates it's a test suite (`_test.cc`). The path (`blink/renderer/modules/mediastream/`) and the term "constraints" point to the WebRTC/Media Streams API within the browser's rendering engine. The "video_device" part narrows it down to testing how video device selection and configuration are influenced by user-specified constraints.

2. **Analyze the Test Structure:** The code uses the Google Test framework (`TEST_F`). Each `TEST_F` represents a specific test case focusing on a particular constraint or combination of constraints. The setup within each test generally involves:
    * Resetting the constraint factory (`constraint_factory_.Reset()`).
    * Setting up constraints using `constraint_factory_.basic()` (and sometimes `constraint_factory_.AddAdvanced()`). These constraints represent what a web application might request from a video device.
    * Calling `SelectSettings()` (or `SelectSettingsVideoDeviceCapture()`). This is the core function being tested, simulating the browser's logic for choosing a suitable video device and its settings based on the applied constraints.
    * Using `EXPECT_EQ`, `EXPECT_TRUE`, `ASSERT_TRUE`, etc., to verify the selected device, format, and track adapter settings match the expected outcome based on the applied constraints.

3. **Identify Key Concepts:** The code frequently mentions:
    * **Constraints:** These are user-defined requirements for the video stream (e.g., minimum width, ideal aspect ratio, specific device ID).
    * **Capabilities:** These are the properties of the available video input devices (e.g., supported resolutions, frame rates, hardware features like pan/tilt/zoom).
    * **Device Selection:** The core function of the code is to test how the browser selects the *best* video device given the constraints and the available device capabilities.
    * **Format Selection:** Once a device is chosen, the browser needs to select the best video *format* (resolution, frame rate) offered by that device.
    * **Track Adapter Settings:** These settings describe how the browser might need to *adapt* the video stream from the selected device and format to perfectly match the constraints (e.g., cropping, scaling).
    * **`MediaStreamConstraintsUtilVideoDeviceTest`:** This is the main test fixture class, indicating the scope of the tests.
    * **`constraint_factory_`:** This object is used to build the constraint sets.
    * **`default_device_`, `high_res_device_`, `low_res_device_`:** These seem to represent simulated video input devices with different capabilities.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):** The code directly relates to the JavaScript Media Streams API (part of WebRTC). A web application uses `getUserMedia()` to request access to the user's camera. The `constraints` parameter passed to `getUserMedia()` is what this C++ code is designed to test.

    * **JavaScript Example:**  A JavaScript code snippet like `navigator.mediaDevices.getUserMedia({ video: { width: { min: 640, ideal: 1280 } } })` directly translates into the kinds of constraints being tested in the C++ code.

5. **Infer Logic and Scenarios:** The test cases systematically explore different constraint combinations. For example:
    * Testing mandatory (`SetExact`, `SetMin`, `SetMax`) vs. ideal (`SetIdeal`) constraints.
    * Testing constraints on resolution (width, height), aspect ratio, frame rate, and advanced features like pan, tilt, and zoom.
    * Testing the `resizeMode` constraint ("none" vs. "crop-and-scale").
    * Testing the interaction of basic and advanced constraint sets.

6. **Identify Potential User Errors:**  The tests implicitly highlight potential user errors in JavaScript constraint specification. For instance, specifying contradictory constraints or requesting features not supported by the available hardware. The tests demonstrate how the browser *should* behave in such cases (e.g., selecting the closest match, ignoring unsatisfiable advanced constraints).

7. **Trace User Operations (Debugging):**  If a web developer encounters unexpected camera behavior, understanding how the browser interprets constraints is crucial for debugging. The test cases provide concrete examples of how different constraint combinations affect device and format selection. A developer can use these examples to understand why a particular camera or resolution was chosen. The test structure also suggests a logical flow for how the browser processes constraints.

8. **Synthesize a Summary (Part 3):**  Focus on the functionality covered in the provided code snippet (lines 1-781). This section primarily tests various aspects of aspect ratio constraints (`MandatoryMinAspectRatio`, `MandatoryMaxAspectRatio`, `MandatoryAspectRatioRange`, `IdealAspectRatio`). It also starts exploring `resizeMode` constraints. The summary should highlight these specific constraint types and how the tests verify the selection logic for them.

By following these steps, we can construct a comprehensive and accurate summary of the provided C++ test code.
这是 `blink/renderer/modules/mediastream/media_stream_constraints_util_video_device_test.cc` 文件的第三部分，主要关注视频设备选择过程中 **宽高比 (aspect ratio)** 和 **缩放模式 (resize mode)** 约束的处理逻辑。

**功能归纳 (Part 3):**

这部分代码主要测试了在 `getUserMedia` 请求中，各种关于视频轨道宽高比 (`aspectRatio`) 和缩放模式 (`resizeMode`) 的约束条件如何影响最终选择的视频设备及其设置。 具体来说，它验证了以下功能：

* **强制最小宽高比 (`MandatoryMinAspectRatio`)**:
    * 当指定了最小宽高比时，系统会选择能够满足此要求的设备和格式。
    * 如果所有设备都支持，则优先选择默认设备。
    * 如果默认设备不能满足，则选择能够满足且 penalty 最小的设备。
    * 测试了当同时存在最小宽高比和分辨率约束时的情况。
* **强制最大宽高比 (`MandatoryMaxAspectRatio`)**:
    * 当指定了最大宽高比时，系统会选择能够满足此要求的设备和格式。
    * 同样考虑了设备支持情况和 penalty 最小原则。
    * 测试了当同时存在最大宽高比和分辨率约束时的情况，以及当默认设备无法满足时的选择逻辑。
* **强制宽高比范围 (`MandatoryAspectRatioRange`)**:
    * 当指定了最小和最大宽高比时，系统会选择能够支持这个范围的设备和格式。
    * 确保约束的宽高比范围与设备支持的范围有交集。
    * 测试了当只有部分设备能满足宽高比和分辨率约束时的选择逻辑。
* **理想宽高比 (`IdealAspectRatio`)**:
    * 当指定了理想宽高比时，系统会尝试选择最接近此比例的设备和格式。
    * 如果多个设备都支持理想宽高比，则优先选择默认设备。
    * 探讨了在理想宽高比难以精确匹配时，系统如何通过裁剪 (cropping) 来接近理想值。
    * 考虑了理想宽高比非常极端的情况，以及与精确高度约束结合时的选择逻辑。
* **强制缩放模式 (`MandatoryResizeMode`)**:
    * 测试了当 `resizeMode` 被强制设置为 "none" 时，系统会选择最接近理想分辨率的**原生**分辨率。
    * 测试了当 `resizeMode` 被强制设置为 "crop-and-scale" 时，系统会选择大于等于理想分辨率的 native 分辨率，并通过裁剪和缩放来达到理想分辨率。
* **理想缩放模式 (`IdealResizeMode`)**:
    * 测试了当 `resizeMode` 被设置为 "crop-and-scale" 的理想值时，即使没有其他约束，也会启用缩放功能。
    * 测试了当理想分辨率略大于或小于最接近的 native 分辨率时，`resizeMode` 为 "none" 和 "crop-and-scale" 时的选择行为。
* **理想缩放模式与原生分辨率差距较大 (`IdealResizeFarFromNative`)**:
    * 探讨了当理想分辨率与任何 native 分辨率都相差甚远时，即使 `resizeMode` 的理想值是 "none"，系统也可能为了更好地匹配理想分辨率而选择启用缩放。
* **多个理想缩放模式值 (`TwoIdealResizeValues`)**:
    * 测试了当 `resizeMode` 存在多个理想值时 (例如 "none" 和 "crop-and-scale")，系统如何选择设备和是否启用缩放。

**与 JavaScript, HTML, CSS 的关系:**

这部分代码直接对应了 WebRTC API 中 `getUserMedia` 方法中 `video` 约束对象的 `aspectRatio` 和 `resizeMode` 属性。

* **JavaScript 例子:**
   ```javascript
   navigator.mediaDevices.getUserMedia({ video: {
       aspectRatio: { min: 1.333, max: 1.777 }, // 设置最小和最大宽高比
       resizeMode: 'crop-and-scale'            // 设置缩放模式为裁剪和缩放
   }})
   .then(function(stream) { /* 使用 stream */ })
   .catch(function(err) { /* 处理错误 */ });
   ```
   这段 JavaScript 代码设置了视频轨道的宽高比范围以及强制使用裁剪和缩放的模式。 后端 C++ 代码中的测试就是验证 Blink 引擎如何根据这些约束来选择合适的视频设备和设置。

* **HTML/CSS 关系:**  虽然 HTML 和 CSS 本身不直接参与 `getUserMedia` 的约束设置，但最终获取到的视频流可能会在 HTML `<video>` 元素中展示，并可以使用 CSS 进行样式控制 (例如，调整视频元素的宽高比以适应流的实际宽高比)。

**逻辑推理示例:**

**假设输入:**

* **设备能力:** 包含一个默认设备 (500x500) 和一个高分辨率设备 (1280x720, 1920x1080, 2304x1536)。
* **约束:**  `aspectRatio: { min: 3.0, max: 4.0 }, height: { min: 600 }`

**逻辑推理:**

1. **宽高比约束:** 要求宽高比在 3.0 到 4.0 之间。
2. **高度约束:** 要求最小高度为 600 像素。
3. **评估默认设备:** 默认设备的宽高比是 1.0，不满足宽高比约束。
4. **评估高分辨率设备:**
    * 1280x720 的宽高比约为 1.78，不满足宽高比约束。
    * 1920x1080 的宽高比约为 1.78，不满足宽高比约束。
    * 2304x1536 的宽高比约为 1.5，不满足宽高比约束。
5. **考虑裁剪:** 为了满足最小宽高比 3.0，需要进行裁剪。例如，对于 1920x1080，裁剪后的目标高度可以是 `1920 / 3.0 = 640`。 这满足了最小高度 600 的约束。
6. **选择:** 高分辨率设备可以通过裁剪来满足约束，因此会被选中。

**预期输出:**

* 选择高分辨率设备。
* 选择 1920x1080 的格式。
* `track_adapter_settings` 将包含裁剪信息，例如 `target_height` 将被设置为 `round(1920 / 3.0) = 640`，`target_width` 为 1920。

**用户或编程常见使用错误:**

* **设置了互相矛盾的宽高比约束:** 例如，`aspectRatio: { min: 2.0, max: 1.0 }`。这会导致没有设备能够满足要求。
* **假设所有设备都支持特定的宽高比或缩放模式:**  开发者应该考虑到不同设备的 capabilities 是不同的，并做好相应的处理。
* **在 `resizeMode: 'none'` 的情况下，期望获得非 native 的分辨率:**  当 `resizeMode` 为 'none' 时，系统只会选择设备提供的原生分辨率，不会进行缩放。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户打开一个网页，该网页使用了 `getUserMedia` API 请求访问摄像头。**
2. **网页的 JavaScript 代码在调用 `getUserMedia` 时，指定了 `video` 约束，包括 `aspectRatio` 和/或 `resizeMode`。**
3. **浏览器接收到请求后，会调用 Blink 引擎中的相关代码，包括 `media_stream_constraints_util_video_device_test.cc` 所测试的逻辑。**
4. **Blink 引擎会根据用户指定的约束，以及当前系统中可用摄像头设备的 capabilities，进行设备选择和格式选择。**
5. **如果用户报告摄像头选择不符合预期，或者获取到的视频流的宽高比或分辨率与期望不符，开发者可以检查 `getUserMedia` 调用中设置的约束条件。**
6. **开发者可以使用浏览器的开发者工具 (例如 Chrome 的 `chrome://webrtc-internals/`) 来查看详细的媒体请求和协商过程，包括约束条件和最终选择的设备信息。**
7. **理解 `media_stream_constraints_util_video_device_test.cc` 中测试的逻辑，可以帮助开发者更好地理解浏览器是如何处理这些约束的，从而排查问题。** 例如，如果用户反馈设置了理想宽高比，但实际的宽高比与理想值有偏差，开发者可以参考 `IdealAspectRatio` 相关的测试用例，理解浏览器在无法精确匹配时的选择策略。

总而言之，这部分测试代码专注于验证 Blink 引擎在处理视频轨道宽高比和缩放模式约束时的正确性和合理性，确保 `getUserMedia` API 能够按照预期选择合适的视频设备和配置。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_video_device_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
pect ratio equals the minimum aspect ratio.
  EXPECT_EQ(kAspectRatio, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(max_aspect_ratio,
            result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryMaxAspectRatio) {
  constraint_factory_.Reset();
  const double kAspectRatio = 0.5;
  constraint_factory_.basic().aspect_ratio.SetMax(kAspectRatio);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  double min_width = 1.0;
  double max_height = result.Height();
  double min_aspect_ratio = min_width / max_height;
  // Minimum constraint aspect ratio must be less than or equal to the maximum
  // supported by the source.
  EXPECT_GE(kAspectRatio, min_aspect_ratio);
  // All devices in |capabilities_| support the requested aspect-ratio range.
  // The algorithm should prefer the first device that supports the requested
  // aspect-ratio range, which in this case is the default device.
  EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(*default_closest_format_, result.Format());
  // The track's aspect ratio is adjusted to the maximum, which is lower than
  // the source's native aspect ratio.
  EXPECT_EQ(result.Height(), result.track_adapter_settings().target_height());
  EXPECT_EQ(std::round(result.Height() * kAspectRatio),
            result.track_adapter_settings().target_width());
  EXPECT_EQ(min_aspect_ratio,
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(kAspectRatio, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);

  const int kExactWidth = 360;
  const int kMinHeight = 360;
  const int kMaxHeight = 720;
  constraint_factory_.basic().width.SetExact(kExactWidth);
  constraint_factory_.basic().height.SetMin(kMinHeight);
  constraint_factory_.basic().height.SetMax(kMaxHeight);
  constraint_factory_.basic().aspect_ratio.SetMax(kAspectRatio);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  min_width = std::max(1, kExactWidth);
  max_height = std::min(result.Height(), kMaxHeight);
  min_aspect_ratio = min_width / max_height;
  // Minimum constraint aspect ratio must be less than or equal to the minimum
  // supported by the source.
  EXPECT_GE(kAspectRatio, min_aspect_ratio);
  // Given resolution constraints, the default device with closest-to-default
  // settings cannot satisfy the required maximum aspect ratio (maximum would
  // be 360/500).
  // The high-res device with a native resolution of 1280x720 can support
  // 360x720 with cropping with less penalty than the default device at
  // 1000x1000.
  EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(1280, result.Width());
  EXPECT_EQ(720, result.Height());
  // The track's aspect ratio is adjusted to the maximum, which is lower than
  // the source's native aspect ratio.
  EXPECT_EQ(result.Height(), result.track_adapter_settings().target_height());
  EXPECT_EQ(std::round(result.Height() * kAspectRatio),
            result.track_adapter_settings().target_width());
  EXPECT_EQ(min_aspect_ratio,
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(kAspectRatio, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryAspectRatioRange) {
  constraint_factory_.Reset();
  {
    const double kMinAspectRatio = 0.5;
    const double kMaxAspectRatio = 1.0;

    constraint_factory_.basic().aspect_ratio.SetMin(kMinAspectRatio);
    constraint_factory_.basic().aspect_ratio.SetMax(kMaxAspectRatio);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    double min_width = 1.0;
    double max_width = result.Width();
    double min_height = 1.0;
    double max_height = result.Height();
    double min_aspect_ratio = min_width / max_height;
    double max_aspect_ratio = max_width / min_height;
    // Constraint aspect-ratio range must have nonempty intersection with
    // supported range.
    EXPECT_LE(kMinAspectRatio, max_aspect_ratio);
    EXPECT_GE(kMaxAspectRatio, min_aspect_ratio);
    // All devices in |capabilities_| support the requested aspect-ratio range.
    // The algorithm should prefer the first device that supports the requested
    // aspect-ratio range, which in this case is the default device.
    EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(*default_closest_format_, result.Format());
    // The source's aspect ratio matches the maximum aspect ratio. No adjustment
    // is required.
    EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
    EXPECT_EQ(kMinAspectRatio,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }

  {
    const double kMinAspectRatio = 3.0;
    const double kMaxAspectRatio = 4.0;

    const int kMinHeight = 600;
    constraint_factory_.Reset();
    constraint_factory_.basic().height.SetMin(kMinHeight);
    constraint_factory_.basic().aspect_ratio.SetMin(kMinAspectRatio);
    constraint_factory_.basic().aspect_ratio.SetMax(kMaxAspectRatio);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    double min_width = 1.0;
    double max_width = result.Width();
    double min_height = 1.0;
    double max_height = result.Height();
    double min_aspect_ratio = min_width / max_height;
    double max_aspect_ratio = max_width / min_height;
    // Constraint aspect-ratio range must have nonempty intersection with
    // supported range.
    EXPECT_LE(kMinAspectRatio, max_aspect_ratio);
    EXPECT_GE(kMaxAspectRatio, min_aspect_ratio);
    // The only device that supports the resolution and aspect ratio constraint
    // is the high-res device. The 1920x1080 is the least expensive format.
    EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(1920, result.Width());
    EXPECT_EQ(1080, result.Height());
    // The track is cropped to support the minimum aspect ratio.
    EXPECT_EQ(std::round(result.Width() / kMinAspectRatio),
              result.track_adapter_settings().target_height());
    EXPECT_EQ(result.Width(), result.track_adapter_settings().target_width());
    EXPECT_EQ(kMinAspectRatio,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(static_cast<double>(result.Width()) / kMinHeight,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, IdealAspectRatio) {
  constraint_factory_.Reset();
  {
    const double kIdealAspectRatio = 0.5;
    constraint_factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    double min_width = 1.0;
    double max_width = result.Width();
    double min_height = 1.0;
    double max_height = result.Height();
    double min_aspect_ratio = min_width / max_height;
    double max_aspect_ratio = max_width / min_height;
    // All devices in |capabilities_| support the ideal aspect-ratio.
    // The algorithm should prefer the default device with closest-to-default
    // settings.
    EXPECT_LE(kIdealAspectRatio, max_aspect_ratio);
    EXPECT_GE(kIdealAspectRatio, min_aspect_ratio);
    EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(*default_closest_format_, result.Format());
    // The track is cropped to support the ideal aspect ratio.
    EXPECT_EQ(result.Height(), result.track_adapter_settings().target_height());
    EXPECT_EQ(std::round(result.Height() * kIdealAspectRatio),
              result.track_adapter_settings().target_width());
    EXPECT_EQ(min_aspect_ratio,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(max_aspect_ratio,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }

  {
    const double kIdealAspectRatio = 1500.0;
    constraint_factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The only device that supports the ideal aspect ratio is the high-res
    // device.
    EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(1280, result.Width());
    EXPECT_EQ(720, result.Height());
    // The most exact way to support the ideal aspect ratio would be to crop to
    // 1920x1080 to 1500x1. However, with 1920x1080 the algorithm tries to crop
    // to 1920x1.28 and rounds to 1920x1. Since the aspect ratio of 1280x1 is
    // closer to ideal than 1920x1, 1280x1 is selected instead.
    // In this case, the effect of rounding is noticeable because of the
    // resulting low value for height. For more typical aspect-ratio values,
    // the 1-pixel error caused by rounding one dimension does not translate to
    // a absolute error on the other dimension.
    EXPECT_EQ(std::round(result.Width() / kIdealAspectRatio),
              result.track_adapter_settings().target_height());
    EXPECT_EQ(result.Width(), result.track_adapter_settings().target_width());
    EXPECT_EQ(1.0 / result.Height(),
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(result.Width(),
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }

  {
    const double kIdealAspectRatio = 2000.0;
    constraint_factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The best way to support this ideal aspect ratio would be to rescale
    // 2304x1536 to 2000x1, but the algorithm would try to rescale to 2304x1.15
    // and then round. Since 1920x1 has an aspect ratio closer to 2000, it is
    // selected over 2304x1. The only device that supports this resolution is
    // the high-res device open at 1920x1080.
    EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(1920, result.Width());
    EXPECT_EQ(1080, result.Height());
    EXPECT_EQ(std::round(result.Width() / kIdealAspectRatio),
              result.track_adapter_settings().target_height());
    EXPECT_EQ(result.Width(), result.track_adapter_settings().target_width());
    EXPECT_EQ(1.0 / result.Height(),
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(result.Width(),
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }

  {
    const double kIdealAspectRatio = 4000.0;
    constraint_factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The configuration closest to the ideal aspect ratio is is the high-res
    // device with its highest resolution, cropped to 2304x1.
    EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(*high_res_highest_format_, result.Format());
    // In this case there is no rounding error.
    EXPECT_EQ(1, result.track_adapter_settings().target_height());
    EXPECT_EQ(result.Width(), result.track_adapter_settings().target_width());
    EXPECT_EQ(1.0 / result.Height(),
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(result.Width(),
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }

  {
    const double kIdealAspectRatio = 2.0;
    const int kExactHeight = 400;
    constraint_factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    constraint_factory_.basic().height.SetExact(kExactHeight);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The first device to support the ideal aspect ratio and the resolution
    // constraint is the low-res device. The 800x600 format cropped to 800x400
    // is the lest expensive way to achieve it.
    EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(800, result.Width());
    EXPECT_EQ(600, result.Height());
    EXPECT_EQ(kExactHeight, result.track_adapter_settings().target_height());
    EXPECT_EQ(kExactHeight * kIdealAspectRatio,
              result.track_adapter_settings().target_width());
    EXPECT_EQ(1.0 / kExactHeight,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(static_cast<double>(result.Width()) / kExactHeight,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }

  {
    const double kIdealAspectRatio = 3.0;
    const int kExactHeight = 400;
    constraint_factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    constraint_factory_.basic().height.SetExact(kExactHeight);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The only device that supports the ideal aspect ratio and the resolution
    // constraint is the high-res device. The 1280x720 cropped to 1200x400 is
    // the lest expensive way to achieve it.
    EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(1280, result.Width());
    EXPECT_EQ(720, result.Height());
    EXPECT_EQ(kExactHeight, result.track_adapter_settings().target_height());
    EXPECT_EQ(kExactHeight * kIdealAspectRatio,
              result.track_adapter_settings().target_width());
    EXPECT_EQ(1.0 / kExactHeight,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(static_cast<double>(result.Width()) / kExactHeight,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryResizeMode) {
  const int kIdealWidth = 641;
  const int kIdealHeight = 480;
  constraint_factory_.Reset();
  constraint_factory_.basic().width.SetIdeal(kIdealWidth);
  constraint_factory_.basic().height.SetIdeal(kIdealHeight);
  constraint_factory_.basic().resize_mode.SetExact("none");
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // A native mode of 640x480 should be selected since it is closest native mode
  // to the ideal values.
  EXPECT_EQ(result.Width(), 640);
  EXPECT_EQ(result.Height(), 480);
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());

  constraint_factory_.basic().resize_mode.SetExact("crop-and-scale");
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_GE(result.Width(), kIdealWidth);
  EXPECT_GE(result.Height(), kIdealHeight);
  EXPECT_EQ(result.track_adapter_settings().target_width(), kIdealWidth);
  EXPECT_EQ(result.track_adapter_settings().target_height(), kIdealHeight);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, IdealResizeMode) {
  constraint_factory_.Reset();
  constraint_factory_.basic().resize_mode.SetIdeal("crop-and-scale");
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // Since no constraints are given, the default device with resolution closest
  // to default is selected. However, rescaling is enabled due to the ideal
  // resize mode.
  EXPECT_EQ(result.device_id(), default_device_->device_id.Utf8());
  EXPECT_EQ(result.Width(), 500);
  EXPECT_EQ(result.Height(), 500);
  EXPECT_TRUE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(result.track_adapter_settings().target_width(), 500);
  EXPECT_EQ(result.track_adapter_settings().target_height(), 500);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       IdealResizeModeResolutionGreaterThanNative) {
  // Ideal resolution is slightly greater than the closest native resolution.
  const int kIdealWidth = 641;
  const int kIdealHeight = 480;
  constraint_factory_.Reset();
  constraint_factory_.basic().width.SetIdeal(kIdealWidth);
  constraint_factory_.basic().height.SetIdeal(kIdealHeight);
  constraint_factory_.basic().resize_mode.SetIdeal(
      WebString::FromASCII("none"));
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // A native mode of 640x480 should be selected since it is the closest native
  // mode to the ideal resolution values.
  EXPECT_EQ(result.Width(), 640);
  EXPECT_EQ(result.Height(), 480);
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());

  constraint_factory_.basic().resize_mode.SetIdeal("crop-and-scale");
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_GE(result.Width(), kIdealWidth);
  EXPECT_GE(result.Height(), kIdealHeight);
  EXPECT_EQ(result.track_adapter_settings().target_width(), kIdealWidth);
  EXPECT_EQ(result.track_adapter_settings().target_height(), kIdealHeight);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       IdealResizeModeResolutionLessThanNative) {
  // Ideal resolution is slightly less than the closest native resolution.
  const int kIdealWidth = 639;
  const int kIdealHeight = 479;
  constraint_factory_.Reset();
  constraint_factory_.basic().width.SetIdeal(kIdealWidth);
  constraint_factory_.basic().height.SetIdeal(kIdealHeight);
  constraint_factory_.basic().resize_mode.SetIdeal(
      WebString::FromASCII("none"));
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // A native mode of 640x480 should be selected since it is the closest native
  // mode to the ideal values.
  EXPECT_EQ(result.Width(), 640);
  EXPECT_EQ(result.Height(), 480);
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());

  constraint_factory_.basic().resize_mode.SetIdeal("crop-and-scale");
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // Rescaling is preferred, therefore a native mode greater than the ideal
  // resolution is chosen.
  EXPECT_GE(result.Width(), kIdealWidth);
  EXPECT_GE(result.Height(), kIdealHeight);
  EXPECT_EQ(result.track_adapter_settings().target_width(), kIdealWidth);
  EXPECT_EQ(result.track_adapter_settings().target_height(), kIdealHeight);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, IdealResizeFarFromNative) {
  constraint_factory_.Reset();
  constraint_factory_.basic().width.SetIdeal(1);
  constraint_factory_.basic().height.SetIdeal(1);
  constraint_factory_.basic().resize_mode.SetIdeal(
      WebString::FromASCII("none"));
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // The native mode closest to 1x1 is 40x30 with the low-res device.
  EXPECT_EQ(result.device_id(), low_res_device_->device_id.Utf8());
  EXPECT_EQ(result.Width(), 40);
  EXPECT_EQ(result.Height(), 30);
  // Despite resize_mode being ideal "none", SelectSettings opts for rescaling
  // since the fitness distance of 40x30 with respect to the ideal 1x1 is larger
  // than the fitness distance for resize_mode not being "none"
  // (29/30 + 39/40 > 1.0)
  EXPECT_TRUE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(result.track_adapter_settings().target_width(), 1);
  EXPECT_EQ(result.track_adapter_settings().target_height(), 1);

  constraint_factory_.Reset();
  constraint_factory_.basic().width.SetIdeal(1);
  constraint_factory_.basic().resize_mode.SetIdeal(
      WebString::FromASCII("none"));
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // The native mode closest to 1x1 is 40x30 with the low-res device.
  EXPECT_EQ(result.device_id(), low_res_device_->device_id.Utf8());
  EXPECT_EQ(result.Width(), 40);
  EXPECT_EQ(result.Height(), 30);
  // In this case, SelectSettings opts for not rescaling since the fitness
  // distance of width 40 with respect to the ideal 1 is larger than the
  // fitness distance for resize_mode not being "none" (39/40 < 1.0)
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, TwoIdealResizeValues) {
  constraint_factory_.Reset();
  constraint_factory_.basic().width.SetIdeal(641);
  constraint_factory_.basic().height.SetIdeal(481);
  constraint_factory_.basic().resize_mode.SetIdeal({"none", "crop-and-scale"});
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // 800x600 rescaled to 641x481 is closest to the specified ideal values.
  EXPECT_EQ(result.device_id(), low_res_device_->device_id.Utf8());
  EXPECT_EQ(result.Width(), 800);
  EXPECT_EQ(result.Height(), 600);
  // Since both resize modes are considered ideal, rescaling is preferred
  // because of the penalty due to deviating from the ideal reo
  EXPECT_TRUE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(result.track_adapter_settings().target_width(), 641);
  EXPECT_EQ(result.track_adapter_settings().target_height(), 481);

  constraint_factory_.Reset();
  constraint_factory_.basic().resize_mode.SetIdeal({"none", "crop-and-scale"});
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // Given that both resize modes are ideal, the default device with the
  // resolution closest to the default without rescaling is selected.
  EXPECT_EQ(result.device_id(), default_device_->device_id.Utf8());
  EXPECT_EQ(result.Width(), 500);
  EXPECT_EQ(result.Height(), 500);
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryExactPanTiltZoom) {
  for (auto& constraint : PanTiltZoomConstraints()) {
    constraint_factory_.Reset();
    (constraint_factory_.basic().*constraint).SetExact(3);
    auto result = SelectSettings();
    ASSERT_TRUE(result.HasValue());
    // The algorithm should prefer the first device that supports PTZ natively,
    // which is the low-res device.
    EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
    ASSERT_TRUE(result.image_capture_device_settings().has_value());
    if (constraint == &MediaTrackConstraintSetPlatform::pan) {
      EXPECT_EQ(3, result.image_capture_device_settings()->pan.value());
    } else if (constraint == &MediaTrackConstraintSetPlatform::tilt) {
      EXPECT_EQ(3, result.image_capture_device_settings()->tilt.value());
    } else if (constraint == &MediaTrackConstraintSetPlatform::zoom) {
      EXPECT_EQ(3, result.image_capture_device_settings()->zoom.value());
    }
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryMinPanTiltZoom) {
  for (auto& constraint : PanTiltZoomConstraints()) {
    constraint_factory_.Reset();
    (constraint_factory_.basic().*constraint).SetMin(2);
    auto result = SelectSettings();
    ASSERT_TRUE(result.HasValue());
    // The algorithm should prefer the first device that supports PTZ
    // natively, which is the low-res device.
    EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
    ASSERT_TRUE(result.image_capture_device_settings().has_value());
    if (constraint == &MediaTrackConstraintSetPlatform::pan) {
      EXPECT_EQ(2, result.image_capture_device_settings()->pan.value());
    } else if (constraint == &MediaTrackConstraintSetPlatform::tilt) {
      EXPECT_EQ(2, result.image_capture_device_settings()->tilt.value());
    } else if (constraint == &MediaTrackConstraintSetPlatform::zoom) {
      EXPECT_EQ(2, result.image_capture_device_settings()->zoom.value());
    }
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryMaxPanTiltZoom) {
  for (auto& constraint : PanTiltZoomConstraints()) {
    constraint_factory_.Reset();
    (constraint_factory_.basic().*constraint).SetMax(4);
    auto result = SelectSettings();
    ASSERT_TRUE(result.HasValue());
    // The algorithm should prefer the first device that supports PTZ
    // natively, which is the low-res device.
    EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
    ASSERT_TRUE(result.image_capture_device_settings().has_value());
    if (constraint == &MediaTrackConstraintSetPlatform::pan) {
      EXPECT_EQ(4, result.image_capture_device_settings()->pan.value());
    } else if (constraint == &MediaTrackConstraintSetPlatform::tilt) {
      EXPECT_EQ(4, result.image_capture_device_settings()->tilt.value());
    } else if (constraint == &MediaTrackConstraintSetPlatform::zoom) {
      EXPECT_EQ(4, result.image_capture_device_settings()->zoom.value());
    }
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryPanTiltZoomRange) {
  for (auto& constraint : PanTiltZoomConstraints()) {
    constraint_factory_.Reset();
    (constraint_factory_.basic().*constraint).SetMin(2);
    (constraint_factory_.basic().*constraint).SetMax(4);
    auto result = SelectSettings();
    ASSERT_TRUE(result.HasValue());
    // The algorithm should prefer the first device that supports PTZ
    // natively, which is the low-res device.
    EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
    ASSERT_TRUE(result.image_capture_device_settings().has_value());
    if (constraint == &MediaTrackConstraintSetPlatform::pan) {
      EXPECT_EQ(2, result.image_capture_device_settings()->pan.value());
    } else if (constraint == &MediaTrackConstraintSetPlatform::tilt) {
      EXPECT_EQ(2, result.image_capture_device_settings()->tilt.value());
    } else if (constraint == &MediaTrackConstraintSetPlatform::zoom) {
      EXPECT_EQ(2, result.image_capture_device_settings()->zoom.value());
    }
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, IdealPanTiltZoom) {
  for (auto& constraint : PanTiltZoomConstraints()) {
    constraint_factory_.Reset();
    (constraint_factory_.basic().*constraint).SetIdeal(3);
    auto result = SelectSettings();
    ASSERT_TRUE(result.HasValue());
    // The algorithm should select the first device that supports the ideal PTZ
    // constraint natively, which is the low-res device.
    EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
    ASSERT_TRUE(result.image_capture_device_settings().has_value());
    if (constraint == &MediaTrackConstraintSetPlatform::pan) {
      EXPECT_EQ(3, result.image_capture_device_settings()->pan.value());
    } else if (constraint == &MediaTrackConstraintSetPlatform::tilt) {
      EXPECT_EQ(3, result.image_capture_device_settings()->tilt.value());
    } else if (constraint == &MediaTrackConstraintSetPlatform::zoom) {
      EXPECT_EQ(3, result.image_capture_device_settings()->zoom.value());
    }
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, PresentPanTiltZoom) {
  for (auto& constraint : PanTiltZoomConstraints()) {
    constraint_factory_.Reset();
    (constraint_factory_.basic().*constraint).SetIsPresent(true);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The algorithm should select the first device that supports the boolean
    // PTZ constraint natively, which is the low-res device.
    EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       PresentPanTiltZoomOnSystemWithoutPanTiltZoomCamera) {
  // Simulate a system with camera that does not support PTZ.
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
  device.control_support.pan = false;
  device.control_support.tilt = false;
  device.control_support.zoom = false;
  capabilities.device_capabilities.push_back(std::move(device));
  capabilities.noise_reduction_capabilities = {
      std::optional<bool>(),
      std::optional<bool>(true),
      std::optional<bool>(false),
  };

  for (auto& constraint : PanTiltZoomConstraints()) {
    constraint_factory_.Reset();
    (constraint_factory_.basic().*constraint).SetIsPresent(true);
    auto constraints = constraint_factory_.CreateMediaConstraints();
    auto result = SelectSettingsVideoDeviceCapture(capabilities, constraints);
    EXPECT_TRUE(result.HasValue());
    // The algorithm should select one device, even if it doesn't support PTZ.
    EXPECT_EQ(std::string(kDeviceID1), result.device_id());
  }
}

// The "Advanced" tests check selection criteria involving advanced constraint
// sets.
TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       AdvancedMinMaxResolutionFrameRate) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.width.SetMin(4000);
  advanced1.height.SetMin(4000);
  // No device supports the first advanced set. This first advanced constraint
  // set is therefore ignored in all calls to SelectSettings().
  // Tie-breaker rule that applies is closeness to default settings.
  auto result = SelectSettings();
  EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(*default_closest_format_, result.Format());
  CheckTrackAdapterSettingsEqualsFormat(result);

  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.width.SetMin(320);
  advanced2.height.SetMin(240);
  advanced2.width.SetMax(640);
  advanced2.height.SetMax(480);
  result = SelectSettings();
  // The device that best supports this advanced set is the low-res device,
  // which natively supports the maximum resolution.
  EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(640, result.Width());
  EXPECT_EQ(480, result.Height());
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(320.0 / 480.0, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(640.0 / 240.0, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);

  MediaTrackConstraintSetPlatform& advanced3 =
      constraint_factory_.AddAdvanced();
  advanced3.frame_rate.SetMax(10.0);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // The high-res device natively supports the third advanced set in addition
  // to the previous set and should be selected.
  EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(640, result.Width());
  EXPECT_EQ(480, result.Height());
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(320.0 / 480.0, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(640.0 / 240.0, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result, 10.0);

  MediaTrackConstraintSetPlatform& advanced4 =
      constraint_factory_.AddAdvanced();
  advanced4.width.SetMax(1000);
  advanced4.height.SetMax(1000);
  result = SelectSettings();
  // The fourth advanced set does not change the allowed range set by previous
  // sets, so the selection is the same as in the previous case.
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(640, result.Width());
  EXPECT_EQ(480, result.Height());
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(320.0 / 480.0, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(640.0 / 240.0, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result, 10.0);

  constraint_factory_.basic().width.SetIdeal(100);
  constraint_factory_.basic().height.SetIdeal(100);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // The allowed resolution range set by constraints is [320x240-640x480], but
  // since the ideal resolution is 100x100, the preferred resolution in the
  // allowed range is 320x240.
  // With regards to frame rate, the maximum allowed is 10Hz.
  // This means that the track should be configured as 320x240@10Hz.
  // The low-res device at 320x240@30Hz is selected over the high-res device
  // at 640x400@10Hz because the distance between 320x240@30Hz and 320x240@10Hz
  // is lower than the distance between 640x400@10Hz and 320x240@10Hz.
  // Both candidates support standard fitness distance equally, since both can
  // use adjusments to produce 320x240@10Hz.
  EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(320, result.Width());
  EXPECT_EQ(240, result.Height());
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(320.0 / 240.0, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(320.0 / 240.0, result.track_adapter_settings().max_aspect_ratio());
  Chec
"""


```