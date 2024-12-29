Response:
The user wants to understand the functionality of a Chromium Blink engine source code file, specifically `media_stream_constraints_util_video_device_test.cc`. They've provided a snippet of the code and asked for several things:

1. **List the file's functions:**  The file is a test file, so its primary function is to test another part of the system. The tests are focused on how video device constraints are handled.
2. **Relationship to JavaScript/HTML/CSS:**  Video constraints are a core part of the WebRTC API, which is exposed to JavaScript.
3. **Logic and Examples:** The code uses `EXPECT_TRUE`, `EXPECT_EQ`, etc., which are assertions in the test framework. I can infer logic and provide example inputs/outputs based on these assertions.
4. **User/Programming Errors:** Incorrectly specified constraints in JavaScript would lead to these scenarios.
5. **User Actions for Debugging:**  The user likely interacts with a web page that uses `getUserMedia()` and provides constraints.
6. **Summarize Functionality (Part 4 of 5):** Based on the code provided, this part focuses heavily on testing the "advanced" constraints, especially when they contradict each other.

**Mental Sandbox:**

* **Core Idea:** The file tests the logic for selecting the best video device and its settings based on user-provided constraints.
* **Constraint Types:**  The code deals with basic constraints (like `ideal` resolution) and advanced constraints (specified in arrays, allowing for alternatives). It also handles contradictions between advanced constraints.
* **Testing Logic:**  The `TEST_F` macros define individual test cases. Each test sets up simulated video devices and constraints, then calls a `SelectSettings()` function (not shown but implied) and uses `EXPECT_*` to verify the outcome.
* **Contradictions:**  A significant portion of the provided code tests scenarios where advanced constraints conflict (e.g., two `exact` values for the same property). This tests the robustness of the constraint resolution logic.
* **Image Capture and Pan/Tilt/Zoom:** The later parts of the code also test constraints related to image capture settings (like torch, blur) and camera controls (pan, tilt, zoom).

**Plan:**

1. State that it's a test file.
2. Describe the core function: testing video device constraint handling.
3. Explain the relationship to WebRTC and JavaScript.
4. Provide examples of JavaScript constraints that correspond to the tests.
5. For the logic examples, select a few illustrative test cases and explain the setup, assumptions, and expected outcomes.
6. Describe common user errors (misconfigured constraints).
7. Explain the user flow leading to constraint evaluation.
8. Summarize the functionality of this part (focus on advanced and contradictory constraints).
这是 `blink/renderer/modules/mediastream/media_stream_constraints_util_video_device_test.cc` 文件的第 4 部分，该文件是 Chromium Blink 引擎的源代码，专门用于测试视频设备约束的工具函数 (`MediaStreamConstraintsUtil`)。

**本部分（第 4 部分）的功能归纳：**

这部分代码主要集中在测试 **高级约束 (Advanced Constraints)** 的处理逻辑，特别是当这些高级约束之间存在 **矛盾 (Contradictory)** 时，系统如何选择合适的视频设备和设置。  它涵盖了各种可能发生冲突的约束组合，包括：

* **分辨率 (Resolution):** `width`, `height`, `minWidth`, `maxWidth`, `minHeight`, `maxHeight`, `exact width`, `exact height`。
* **帧率 (Frame Rate):** `frameRate`, `minFrameRate`, `maxFrameRate`, `exact frameRate`。
* **宽高比 (Aspect Ratio):** `aspectRatio`, `minAspectRatio`, `maxAspectRatio`, `exact aspectRatio`。
* **降噪 (Noise Reduction):** `googNoiseReduction`。
* **设备 ID 和组 ID (Device ID and Group ID):** `deviceId`, `groupId`。
* **图像捕获属性 (Image Capture Properties):**  如 `torch`, `backgroundBlur`, `exposureCompensation` 等。
* **平移/倾斜/缩放 (Pan/Tilt/Zoom):** `pan`, `tilt`, `zoom`。
* **调整大小模式 (Resize Mode):** `resizeMode`。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件直接关联到 WebRTC API 中 `getUserMedia()` 方法使用的约束 (constraints)。  开发者在 JavaScript 中调用 `getUserMedia()` 时，可以传递一个包含 `video` 属性的对象来指定视频流的约束条件。

**举例说明：**

* **JavaScript:**
  ```javascript
  navigator.mediaDevices.getUserMedia({
    video: {
      width: { ideal: 1920 },
      height: { ideal: 1080 },
      advanced: [
        { frameRate: { exact: 60 } },
        { width: { exact: 2304 }, height: { exact: 1536 } }
      ]
    }
  })
  .then(function(stream) { /* 使用视频流 */ })
  .catch(function(err) { /* 处理错误 */ });
  ```
  在这个 JavaScript 例子中，`width` 和 `height` 是基本约束，而 `advanced` 数组中包含了两个高级约束集合。  第一个集合要求帧率精确为 60，第二个集合要求分辨率精确为 2304x1536。  `media_stream_constraints_util_video_device_test.cc` 中的 `AdvancedResolutionAndFrameRate` 测试用例就是为了测试这种场景下的设备选择逻辑。

* **HTML/CSS:**  HTML 用于创建网页结构，CSS 用于样式化。  虽然 HTML 和 CSS 本身不直接参与约束的解析和设备选择，但它们定义了用户与网页交互的方式，最终触发 JavaScript 代码的执行，从而调用 `getUserMedia()` 并传递约束。

**逻辑推理、假设输入与输出：**

以 `TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, AdvancedResolutionAndFrameRate)` 为例：

**假设输入：**

* **可用的视频设备:**
    * `default_device_`: 具有格式 1000x1000@20Hz 和 200x200@40Hz。
    * `low_res_device_`: 具有格式 640x480@10Hz 和 320x240@30Hz。
    * `high_res_device_`: 具有格式 2304x1536@10Hz, 1920x1080@60Hz, 1280x768@60Hz, 640x480@10Hz。
* **高级约束:**
    * 集合 1: `width: { exact: 1920 }, height: { exact: 1080 }`
    * 集合 2: `frameRate: { exact: 60 }`
    * 集合 3: `width: { exact: 2304 }, height: { exact: 1536 }`

**逻辑推理：**

1. 代码会尝试找到满足所有高级约束集合的设备和格式。
2. `high_res_device_` 的 `1920x1080@60Hz` 格式满足集合 1 和集合 2。
3. `high_res_device_` 的 `2304x1536@10Hz` 格式满足集合 1 和集合 3。
4. 由于 `1920x1080@60Hz` 同时满足集合 1 和 2，即使 `2304x1536@10Hz` 也满足其他集合，但会优先选择能同时满足更多集合的选项。

**预期输出：**

* 选择 `high_res_device_`。
* 选择格式 `1920x1080@60Hz`。
* `result.Width()` 等于 1920。
* `result.Height()` 等于 1080。
* `result.FrameRate()` 等于 60.0。
* `track_adapter_settings` 的 `min_aspect_ratio` 和 `max_aspect_ratio` 都等于 1920.0 / 1080.0。

**用户或编程常见的使用错误：**

* **高级约束冲突导致无法选择设备：**  用户在 JavaScript 中设置了互相矛盾的高级约束，例如：
  ```javascript
  advanced: [
    { width: { exact: 640 } },
    { width: { exact: 1920 } }
  ]
  ```
  在这种情况下，没有设备能同时满足宽度精确为 640 和 1920，会导致设备选择失败或者回退到基本约束或默认设置。`AdvancedContradictoryExactResolution` 测试用例模拟了这种情况。

* **对 `exact` 约束理解不足：**  开发者可能错误地认为 `exact` 约束只是一个偏好，但实际上它是一个强制要求。如果指定的精确值与任何可用设备的能力不匹配，则该约束将无法满足。

* **忽略了 `advanced` 约束的优先级：** 高级约束比基本约束具有更高的优先级。如果高级约束无法满足，即使基本约束可以满足，也可能导致意想不到的结果。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户打开一个网页。**
2. **网页上的 JavaScript 代码尝试获取用户的摄像头权限和视频流，调用 `navigator.mediaDevices.getUserMedia()`。**
3. **在 `getUserMedia()` 的 `video` 约束中，包含了 `advanced` 属性，指定了复杂或特定的视频设备要求。**
4. **Blink 引擎接收到这些约束。**
5. **`MediaStreamConstraintsUtil::SelectSettings()` 函数（或者其内部调用的函数）被调用，开始根据约束条件筛选和选择合适的视频设备及其格式。**
6. **`media_stream_constraints_util_video_device_test.cc` 中的测试用例模拟了各种可能的约束组合和设备情况，用于验证 `SelectSettings()` 函数的逻辑正确性。**
7. **如果在测试过程中发现 `EXPECT_TRUE` 或 `EXPECT_EQ` 等断言失败，则表明 `SelectSettings()` 函数在处理特定类型的约束时存在缺陷。**  这为开发者提供了调试线索，需要检查 `MediaStreamConstraintsUtil` 的实现，找出约束处理逻辑中的错误。

**总结来说，这部分测试代码的核心功能是验证当 JavaScript 代码通过 `getUserMedia()` 的 `advanced` 约束请求特定的视频设备能力时，Blink 引擎能否正确地选择最合适的设备和设置，并处理高级约束之间可能存在的冲突。** 它通过大量的测试用例覆盖了各种约束组合，确保了 WebRTC API 在处理复杂视频约束时的稳定性和可靠性。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_video_device_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能

"""
kTrackAdapterSettingsEqualsFrameRate(result, 10.0);

  constraint_factory_.basic().width.SetIdeal(2000);
  constraint_factory_.basic().height.SetIdeal(1500);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // The high-res device at 640x480@10Hz is closer to the large ideal
  // resolution.
  EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(640, result.Width());
  EXPECT_EQ(480, result.Height());
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(320.0 / 480.0, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(640.0 / 240.0, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result, 10.0);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       AdvancedResolutionAndFrameRate) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.width.SetExact(1920);
  advanced1.height.SetExact(1080);
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.frame_rate.SetExact(60.0);
  MediaTrackConstraintSetPlatform& advanced3 =
      constraint_factory_.AddAdvanced();
  advanced3.width.SetExact(2304);
  advanced3.height.SetExact(1536);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // The high-res device is the only one that satisfies the first advanced
  // set. 2304x1536x10.0 satisfies sets 1 and 3, while 1920x1080x60.0
  // satisfies sets 1, and 2. The latter must be selected, regardless of
  // any other criteria.
  EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(1920, result.Width());
  EXPECT_EQ(1080, result.Height());
  EXPECT_EQ(60.0, result.FrameRate());
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(1920.0 / 1080.0,
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(1920.0 / 1080.0,
            result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result, 60.0);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, AdvancedNoiseReduction) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.width.SetMin(640);
  advanced1.height.SetMin(480);
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.width.SetMin(1920);
  advanced2.height.SetMin(1080);
  advanced2.goog_noise_reduction.SetExact(false);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_LE(1920, result.Width());
  EXPECT_LE(1080, result.Height());
  EXPECT_TRUE(result.noise_reduction() && !*result.noise_reduction());
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(1920.0 / result.Height(),
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(result.Width() / 1080.0,
            result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       AdvancedContradictoryNoiseReduction) {
  {
    constraint_factory_.Reset();
    MediaTrackConstraintSetPlatform& advanced1 =
        constraint_factory_.AddAdvanced();
    advanced1.width.SetMin(640);
    advanced1.height.SetMin(480);
    advanced1.goog_noise_reduction.SetExact(true);
    MediaTrackConstraintSetPlatform& advanced2 =
        constraint_factory_.AddAdvanced();
    advanced2.width.SetMin(1920);
    advanced2.height.SetMin(1080);
    advanced2.goog_noise_reduction.SetExact(false);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The second advanced set cannot be satisfied because it contradicts the
    // first set. The default device supports the first set and should be
    // selected.
    EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
    EXPECT_LE(640, result.Width());
    EXPECT_LE(480, result.Height());
    EXPECT_TRUE(result.noise_reduction() && *result.noise_reduction());
    EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
    EXPECT_EQ(640.0 / result.Height(),
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(result.Width() / 480.0,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }

  // Same test without noise reduction
  {
    constraint_factory_.Reset();
    MediaTrackConstraintSetPlatform& advanced1 =
        constraint_factory_.AddAdvanced();
    advanced1.width.SetMin(640);
    advanced1.height.SetMin(480);
    MediaTrackConstraintSetPlatform& advanced2 =
        constraint_factory_.AddAdvanced();
    advanced2.width.SetMin(1920);
    advanced2.height.SetMin(1080);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // Only the high-res device can satisfy the second advanced set.
    EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_LE(1920, result.Width());
    EXPECT_LE(1080, result.Height());
    // Should select default noise reduction setting.
    EXPECT_TRUE(!result.noise_reduction());
    EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
    EXPECT_EQ(1920.0 / result.Height(),
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(result.Width() / 1080.0,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
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
  // The second advanced set must be ignored because it contradicts the first
  // set. The low-res device is the one that best supports the requested
  // resolution.
  EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(640, result.Width());
  EXPECT_EQ(480, result.Height());
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(640.0 / 480.0, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(640.0 / 480.0, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
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
  // The second advanced set must be ignored because it contradicts the first
  // set. The default device with the 200x200@40Hz format should be selected.
  // That format satisfies the first advanced set as well as any other, so the
  // tie breaker rule that applies is default device ID.
  EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(200, result.Width());
  EXPECT_EQ(200, result.Height());
  EXPECT_EQ(40, result.FrameRate());
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(1.0 / result.Height(),
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(result.Width(), result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       AdvancedContradictoryMinMaxResolutionFrameRate) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.width.SetMin(800);
  advanced1.height.SetMin(600);
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.width.SetMax(640);
  advanced2.height.SetMax(480);
  advanced2.frame_rate.SetExact(60.0);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // The second advanced set must be ignored because it contradicts the first
  // set. The default device with the 1000x1000@20Hz format should be selected.
  // That format satisfies the first advanced set as well as any other, so the
  // tie breaker rule that applies is default device ID.
  EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(1000, result.Width());
  EXPECT_EQ(1000, result.Height());
  EXPECT_EQ(20, result.FrameRate());
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(800.0 / result.Height(),
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(result.Width() / 600.0,
            result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       AdvancedContradictoryExactAspectRatio) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.aspect_ratio.SetExact(2300.0);
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.aspect_ratio.SetExact(3.0);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // The second advanced set must be ignored because it contradicts the first
  // set. Only the high-res device in the highest-resolution format supports the
  // requested aspect ratio.
  EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(*high_res_highest_format_, result.Format());
  // The track is cropped to support the exact aspect ratio.
  EXPECT_EQ(result.Width(), result.track_adapter_settings().target_width());
  EXPECT_EQ(std::round(result.Height() / 2300.0),
            result.track_adapter_settings().target_height());
  EXPECT_EQ(2300.0, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(2300.0, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       AdvancedContradictoryAspectRatioRange) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.aspect_ratio.SetMin(2300.0);
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.aspect_ratio.SetMax(3.0);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // The second advanced set must be ignored because it contradicts the first
  // set. Only the high-res device in the highest-resolution format supports the
  // requested aspect ratio.
  EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(*high_res_highest_format_, result.Format());
  // The track is cropped to support the min aspect ratio.
  EXPECT_EQ(result.Width(), result.track_adapter_settings().target_width());
  EXPECT_EQ(std::round(result.Height() / 2300.0),
            result.track_adapter_settings().target_height());
  EXPECT_EQ(2300.0, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(result.Width(), result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
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
  // The second advanced set must be ignored because it contradicts the first
  // set.
  EXPECT_EQ(40.0, result.FrameRate());
  CheckTrackAdapterSettingsEqualsResolution(result);
  CheckTrackAdapterSettingsEqualsFrameRate(result, 40.0);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
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
  // The second advanced set must be ignored because it contradicts the first
  // set.
  EXPECT_LE(40.0, result.FrameRate());
  CheckTrackAdapterSettingsEqualsResolution(result);
  CheckTrackAdapterSettingsEqualsFrameRate(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       AdvancedContradictoryWidthFrameRate) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.width.SetMax(1920);
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.width.SetMin(2000);
  advanced2.frame_rate.SetExact(10.0);
  MediaTrackConstraintSetPlatform& advanced3 =
      constraint_factory_.AddAdvanced();
  advanced3.frame_rate.SetExact(30.0);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // The low-res device at 320x240@30Hz satisfies advanced sets 1 and 3.
  // The high-res device at 2304x1536@10.0f can satisfy sets 1 and 2, but not
  // both at the same time. Thus, low-res device must be preferred.
  EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(30.0, result.FrameRate());
  EXPECT_GE(1920, result.Width());
  CheckTrackAdapterSettingsEqualsResolution(result);
  CheckTrackAdapterSettingsEqualsFrameRate(result, 30.0);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       AdvancedContradictoryHeightFrameRate) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.height.SetMax(1080);
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.height.SetMin(1500);
  advanced2.frame_rate.SetExact(10.0);
  MediaTrackConstraintSetPlatform& advanced3 =
      constraint_factory_.AddAdvanced();
  advanced3.frame_rate.SetExact(60.0);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // The high-res device at 1280x768@60Hz and 1920x1080@60Hz satisfies advanced
  // sets 1 and 3. The same device at 2304x1536@10.0f can satisfy sets 1 and 2,
  // but not both at the same time. Thus, the format closest to default that
  // satisfies sets 1 and 3 must be chosen.
  EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(60.0, result.FrameRate());
  EXPECT_GE(1080, result.Height());
  CheckTrackAdapterSettingsEqualsResolution(result);
  CheckTrackAdapterSettingsEqualsFrameRate(result, 60.0);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, AdvancedDeviceID) {
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
  EXPECT_EQ(std::string(kDeviceID2), result.device_id());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, AdvancedGroupID) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  Vector<String> id_vector1 = {kGroupID1, kGroupID2};
  advanced1.group_id.SetExact(id_vector1);
  Vector<String> id_vector2 = {kGroupID2, kGroupID3};
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.group_id.SetExact(id_vector2);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // The device with group_id kGroupID2 must be selected because it is the only
  // one that satisfies both advanced sets.
  EXPECT_EQ(std::string(kDeviceID2), result.device_id());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       AdvancedContradictoryDeviceID) {
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
  EXPECT_EQ(std::string(kDeviceID1), result.device_id());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       AdvancedContradictoryDeviceIDAndResolution) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  advanced1.device_id.SetExact({low_res_device_->device_id});

  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.device_id.SetExact({high_res_device_->device_id});
  advanced2.width.SetMax(50);
  advanced2.height.SetMax(50);

  MediaTrackConstraintSetPlatform& advanced3 =
      constraint_factory_.AddAdvanced();
  advanced3.width.SetExact(800);
  advanced3.height.SetExact(600);

  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // The second advanced set must be ignored because it contradicts the first
  // set, but the third set must be applied.
  EXPECT_EQ(result.device_id(), low_res_device_->device_id.Utf8());
  EXPECT_EQ(result.Width(), 800);
  EXPECT_EQ(result.Height(), 600);
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       AdvancedContradictoryGroupID) {
  constraint_factory_.Reset();
  MediaTrackConstraintSetPlatform& advanced1 =
      constraint_factory_.AddAdvanced();
  Vector<String> id_vector1 = {kGroupID1, kGroupID2};
  advanced1.group_id.SetExact(id_vector1);
  Vector<String> id_vector2 = {kGroupID3, kGroupID4};
  MediaTrackConstraintSetPlatform& advanced2 =
      constraint_factory_.AddAdvanced();
  advanced2.group_id.SetExact(id_vector2);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // The second advanced set must be ignored because it contradicts the first
  // set.
  EXPECT_EQ(std::string(kDeviceID1), result.device_id());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       AdvancedContradictoryAspectRatioWidth) {
  {
    constraint_factory_.Reset();
    MediaTrackConstraintSetPlatform& advanced1 =
        constraint_factory_.AddAdvanced();
    advanced1.aspect_ratio.SetMin(17);
    MediaTrackConstraintSetPlatform& advanced2 =
        constraint_factory_.AddAdvanced();
    advanced2.width.SetMax(1);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The second advanced set cannot be satisfied because it contradicts the
    // second set. The default device supports the first set and should be
    // selected.
    EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(*default_closest_format_, result.Format());
    EXPECT_EQ(result.Width(), result.track_adapter_settings().target_width());
    EXPECT_EQ(std::round(result.Width() / 17.0),
              result.track_adapter_settings().target_height());
    EXPECT_EQ(17, result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(result.Width(),
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       AdvancedContradictoryImageCapture) {
  for (auto& constraint : BooleanImageCaptureConstraints()) {
    constraint_factory_.Reset();

    MediaTrackConstraintSetPlatform& advanced1 =
        constraint_factory_.AddAdvanced();
    advanced1.device_id.SetExact({low_res_device_->device_id});

    MediaTrackConstraintSetPlatform& advanced2 =
        constraint_factory_.AddAdvanced();
    advanced2.device_id.SetExact({default_device_->device_id});
    (advanced2.*constraint).SetExact(true);

    MediaTrackConstraintSetPlatform& advanced3 =
        constraint_factory_.AddAdvanced();
    (advanced3.*constraint).SetExact(false);

    MediaTrackConstraintSetPlatform& advanced4 =
        constraint_factory_.AddAdvanced();
    (advanced4.*constraint).SetExact(true);

    auto result = SelectSettings();
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
    ASSERT_TRUE(result.image_capture_device_settings().has_value());
    // The second advanced set must be ignored because it contradicts the first
    // set. The third advanced set must be applied. The fourth advanced must be
    // ignored because it contradicts the third set.
    EXPECT_EQ(result.image_capture_device_settings()->torch.has_value(),
              constraint == &MediaTrackConstraintSetPlatform::torch);
    if (result.image_capture_device_settings()->torch.has_value()) {
      EXPECT_FALSE(result.image_capture_device_settings()->torch.value());
    }
    EXPECT_EQ(
        result.image_capture_device_settings()->background_blur.has_value(),
        constraint == &MediaTrackConstraintSetPlatform::background_blur);
    if (result.image_capture_device_settings()->background_blur.has_value()) {
      EXPECT_FALSE(
          result.image_capture_device_settings()->background_blur.value());
    }
    EXPECT_EQ(
        result.image_capture_device_settings()
            ->background_segmentation_mask.has_value(),
        constraint ==
            &MediaTrackConstraintSetPlatform::background_segmentation_mask);
    if (result.image_capture_device_settings()
            ->background_segmentation_mask.has_value()) {
      EXPECT_FALSE(result.image_capture_device_settings()
                       ->background_segmentation_mask.value());
    }
    EXPECT_EQ(
        result.image_capture_device_settings()->eye_gaze_correction.has_value(),
        constraint == &MediaTrackConstraintSetPlatform::eye_gaze_correction);
    if (result.image_capture_device_settings()
            ->eye_gaze_correction.has_value()) {
      EXPECT_FALSE(
          result.image_capture_device_settings()->eye_gaze_correction.value());
    }
    EXPECT_EQ(result.image_capture_device_settings()->face_framing.has_value(),
              constraint == &MediaTrackConstraintSetPlatform::face_framing);
    if (result.image_capture_device_settings()->face_framing.has_value()) {
      EXPECT_FALSE(
          result.image_capture_device_settings()->face_framing.value());
    }
  }

  int value = 0;
  for (auto& constraint : DoubleImageCaptureConstraints()) {
    constraint_factory_.Reset();

    MediaTrackConstraintSetPlatform& advanced1 =
        constraint_factory_.AddAdvanced();
    advanced1.device_id.SetExact({low_res_device_->device_id});

    MediaTrackConstraintSetPlatform& advanced2 =
        constraint_factory_.AddAdvanced();
    advanced2.device_id.SetExact({default_device_->device_id});
    switch (++value % 4) {
      case 0:
        (advanced2.*constraint).SetExact(value + 1.0);
        break;
      case 1:
        (advanced2.*constraint).SetExact(value + 1.0);
        break;
      case 2:
        (advanced2.*constraint).SetExact(value - 1.0);
        break;
      case 3:
        (advanced2.*constraint).SetExact(value + 1.0);
        break;
    }

    MediaTrackConstraintSetPlatform& advanced3 =
        constraint_factory_.AddAdvanced();
    switch (value % 4) {
      case 0:
        (advanced3.*constraint).SetExact(value);
        break;
      case 1:
        (advanced3.*constraint).SetMin(value);
        break;
      case 2:
        (advanced3.*constraint).SetMax(value);
        break;
      case 3:
        (advanced3.*constraint).SetMin(value - 2.0);
        (advanced3.*constraint).SetMax(value + 2.0);
        break;
    }

    MediaTrackConstraintSetPlatform& advanced4 =
        constraint_factory_.AddAdvanced();
    switch (value % 4) {
      case 0:
        (advanced4.*constraint).SetExact(value - 1.0);
        break;
      case 1:
        (advanced4.*constraint).SetExact(value - 1.0);
        break;
      case 2:
        (advanced4.*constraint).SetExact(value + 1.0);
        break;
      case 3:
        (advanced4.*constraint).SetExact(value + 3.0);
        break;
    }

    auto result = SelectSettings();
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
    ASSERT_TRUE(result.image_capture_device_settings().has_value());
    // The second advanced set must be ignored because it contradicts the first
    // set. The third advanced set must be applied. The fourth advanced must be
    // ignored because it contradicts the third set.
    EXPECT_EQ(
        result.image_capture_device_settings()
            ->exposure_compensation.has_value(),
        constraint == &MediaTrackConstraintSetPlatform::exposure_compensation);
    if (result.image_capture_device_settings()
            ->exposure_compensation.has_value()) {
      EXPECT_EQ(1.0, result.image_capture_device_settings()
                         ->exposure_compensation.value());
    }
    EXPECT_EQ(result.image_capture_device_settings()->exposure_time.has_value(),
              constraint == &MediaTrackConstraintSetPlatform::exposure_time);
    if (result.image_capture_device_settings()->exposure_time.has_value()) {
      EXPECT_EQ(2.0,
                result.image_capture_device_settings()->exposure_time.value());
    }
    EXPECT_EQ(
        result.image_capture_device_settings()->color_temperature.has_value(),
        constraint == &MediaTrackConstraintSetPlatform::color_temperature);
    if (result.image_capture_device_settings()->color_temperature.has_value()) {
      EXPECT_EQ(
          3.0,
          result.image_capture_device_settings()->color_temperature.value());
    }
    EXPECT_EQ(result.image_capture_device_settings()->iso.has_value(),
              constraint == &MediaTrackConstraintSetPlatform::iso);
    if (result.image_capture_device_settings()->iso.has_value()) {
      EXPECT_EQ(4.0, result.image_capture_device_settings()->iso.value());
    }
    EXPECT_EQ(result.image_capture_device_settings()->brightness.has_value(),
              constraint == &MediaTrackConstraintSetPlatform::brightness);
    if (result.image_capture_device_settings()->brightness.has_value()) {
      EXPECT_EQ(5.0,
                result.image_capture_device_settings()->brightness.value());
    }
    EXPECT_EQ(result.image_capture_device_settings()->contrast.has_value(),
              constraint == &MediaTrackConstraintSetPlatform::contrast);
    if (result.image_capture_device_settings()->contrast.has_value()) {
      EXPECT_EQ(6.0, result.image_capture_device_settings()->contrast.value());
    }
    EXPECT_EQ(result.image_capture_device_settings()->saturation.has_value(),
              constraint == &MediaTrackConstraintSetPlatform::saturation);
    if (result.image_capture_device_settings()->saturation.has_value()) {
      EXPECT_EQ(7.0,
                result.image_capture_device_settings()->saturation.value());
    }
    EXPECT_EQ(result.image_capture_device_settings()->sharpness.has_value(),
              constraint == &MediaTrackConstraintSetPlatform::sharpness);
    if (result.image_capture_device_settings()->sharpness.has_value()) {
      EXPECT_EQ(8.0, result.image_capture_device_settings()->sharpness.value());
    }
    EXPECT_EQ(
        result.image_capture_device_settings()->focus_distance.has_value(),
        constraint == &MediaTrackConstraintSetPlatform::focus_distance);
    if (result.image_capture_device_settings()->focus_distance.has_value()) {
      EXPECT_EQ(9.0,
                result.image_capture_device_settings()->focus_distance.value());
    }
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       AdvancedContradictoryPanTiltZoom) {
  for (auto& constraint : PanTiltZoomConstraints()) {
    constraint_factory_.Reset();

    MediaTrackConstraintSetPlatform& advanced1 =
        constraint_factory_.AddAdvanced();
    advanced1.device_id.SetExact({low_res_device_->device_id});

    MediaTrackConstraintSetPlatform& advanced2 =
        constraint_factory_.AddAdvanced();
    advanced2.device_id.SetExact({default_device_->device_id});
    (advanced2.*constraint).SetExact(4);

    MediaTrackConstraintSetPlatform& advanced3 =
        constraint_factory_.AddAdvanced();
    (advanced3.*constraint).SetMin(4);
    (advanced3.*constraint).SetMax(2);

    MediaTrackConstraintSetPlatform& advanced4 =
        constraint_factory_.AddAdvanced();
    (advanced4.*constraint).SetExact(3);

    auto result = SelectSettings();
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
    ASSERT_TRUE(result.image_capture_device_settings().has_value());
    // The second advanced set must be ignored because it contradicts the first
    // set. The third advanced must be ignored because it is invalid. The fourth
    // advanced set must be applied.
    if (constraint == &MediaTrackConstraintSetPlatform::pan) {
      EXPECT_EQ(3, result.image_capture_device_settings()->pan.value());
    } else if (constraint == &MediaTrackConstraintSetPlatform::tilt) {
      EXPECT_EQ(3, result.image_capture_device_settings()->tilt.value());
    } else if (constraint == &MediaTrackConstraintSetPlatform::zoom) {
      EXPECT_EQ(3, result.image_capture_device_settings()->zoom.value());
    }
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, AdvancedResize) {
  constraint_factory_.Reset();
  constraint_factory_.basic().width.SetIdeal(1);
  constraint_factory_.basic().height.SetIdeal(1);
  MediaTrackConstraintSetPlatform& advanced = constraint_factory_.AddAdvanced();

  advanced.resize_mode.SetExact("none");
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // The native mode closest to 1x1 is 40x30 with the low-res device.
  EXPECT_EQ(result.device_id(), low_res_device_->device_id.Utf8());
  EXPECT_EQ(result.Width(), 40);
  EXPECT_EQ(result.Height(), 30);
  // No rescaling occurs due to the advanced constraint specifying resizeMode
  // equal to "none".
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest,
       AdvancedResolutionResizeFrameRate) {
  constraint_factory_.Reset();
  constraint_factory_.basic().width.SetExact(639);

  // This advanced set must be ignored because there are no native resolutions
  // with width equal to 639.
  MediaTrackConstraintSetPlatform& advanced = constraint_factory_.AddAdvanced();
  advanced.resize_mode.SetExact("none");
  advanced.frame_rate.SetExact(19.0);

  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // Rescaling is enabled to satisfy the required resolution.
  EXPECT_TRUE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(result.track_adapter_settings().target_width(), 639);
  // Height gets adjusted as well to maintain the aspect ratio.
  EXPECT_EQ(result.track_adapter_settings().target_height(), 479);
  // Using native frame rate because the advanced set is ignored.
  EXPECT_EQ(result.track_adapter_settings().max_frame_rate(), std::nullopt);

  // The low-res device at 640x480@30Hz is the
  EXPECT_EQ(result.device_id(), low_res_device_->device_id.Utf8());
  EXPECT_EQ(result.Width(), 640);
  EXPECT_EQ(result.Height(), 480);
  EXPECT_EQ(result.FrameRate(), 30.0);
}

TEST_F(MediaStreamConstraintsUtilVideoDe
"""


```