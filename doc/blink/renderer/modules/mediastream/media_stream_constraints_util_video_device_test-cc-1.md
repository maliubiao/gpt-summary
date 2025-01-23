Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is part of a larger test file for the Chromium Blink engine, specifically for selecting video device settings based on constraints.

To summarize, I need to identify the core purpose of the tests, which is to verify the logic for choosing the best video device and its settings when given various constraints on resolution, frame rate, and aspect ratio.

The code demonstrates different test cases that exercise the `SelectSettings()` function with different combinations of constraints, including:
- Ideal, exact, minimum, and maximum values for height, width, and frame rate.
- Ranges for width and frame rate.
- Exact and minimum aspect ratio.

Each test case sets up constraints, calls `SelectSettings()`, and then uses `EXPECT_TRUE/FALSE` and `EXPECT_EQ/LE` to assert the correctness of the selected device, resolution, frame rate, and track adapter settings.

I need to highlight that this code is testing a specific utility function within the media stream module and that its behavior relates to how web pages can request specific video capture characteristics.
这个C++代码片段是`MediaStreamConstraintsUtilVideoDeviceTest` 测试类的一部分，主要功能是测试在设置了 **理想高度 (Ideal Height) 约束** 时，视频设备选择和配置逻辑是否正确。

**具体功能归纳:**

1. **测试理想高度约束下的设备选择：**  验证当指定 `ideal` 的视频高度时，系统能否正确选择最符合条件的摄像头设备和分辨率。
2. **测试基于理想值的分辨率选择：**  验证当有多个设备或同一设备有多个分辨率能满足理想高度时，系统如何选择最合适的那个。这里的“合适”通常指原生支持该分辨率或者调整后最接近理想值的分辨率。
3. **测试 `TrackAdapterSettings` 的生成：**  验证在设置理想高度约束后，生成的 `TrackAdapterSettings` 是否正确反映了目标高度、宽度以及相关的宽高比约束。`TrackAdapterSettings` 用于在后续处理中调整视频流以匹配约束。

**与 JavaScript, HTML, CSS 的关系 (间接):**

这段C++代码的测试目标是 Chromium 浏览器引擎中处理媒体流约束的核心逻辑。这些约束通常来源于 Web 开发者在 JavaScript 中通过 `getUserMedia` API 发起的请求。

**举例说明:**

* **JavaScript:**  Web 开发者可以使用 `getUserMedia` 来请求用户摄像头，并指定理想的视频高度：

```javascript
navigator.mediaDevices.getUserMedia({ video: { height: { ideal: 1080 } } })
  .then(function(stream) {
    // 使用 stream
  })
  .catch(function(err) {
    // 处理错误
  });
```

* **HTML (间接):**  虽然 HTML 本身不直接参与媒体流约束的设置，但它提供了展示视频流的 `<video>` 标签。`getUserMedia` 获取的视频流最终可能会被渲染到这个标签中。

* **CSS (间接):**  CSS 可以用来控制 `<video>` 标签的显示大小和比例，但它不直接影响 `getUserMedia` 的约束处理逻辑。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* 有两个摄像头设备：
    * 低分辨率设备 (low_res_device_)：支持 320x240, 640x480 等分辨率。
    * 高分辨率设备 (high_res_device_)：支持 480x360, 1280x720, 1920x1080, 2304x1536 等分辨率。
* 设置了理想高度约束：`constraint_factory_.basic().height.SetIdeal(kIdealHeight);`

**输出示例 (基于代码中的测试用例):**

* **假设 `kIdealHeight` 为 1079:**
    * **输出:** 选择高分辨率设备，分辨率为 1920x1080。 `TrackAdapterSettings` 的目标高度为 1079，目标宽度会根据 1079 和 1920x1080 的宽高比计算。
* **假设 `kIdealHeight` 为 1200:**
    * **输出:** 选择高分辨率设备，分辨率为 2304x1536 (高分辨率设备中能满足理想高度的最高分辨率)。 `TrackAdapterSettings` 的目标高度为 1200，目标宽度会根据 1200 和 2304x1536 的宽高比计算。

**用户或编程常见的使用错误 (与测试代码相关的):**

这个测试文件主要关注引擎内部逻辑，不太直接涉及用户的操作错误。编程错误方面，开发者可能会：

* **误解理想约束的含义：**  认为 `ideal` 约束会强制使用指定的数值，但实际上它是指系统会尽力找到最接近的匹配项。测试用例展示了即使没有完全匹配的分辨率，系统也会选择最接近的。
* **错误配置约束组合：**  例如，设置了互相冲突的 `minHeight` 和 `maxHeight` 约束，导致无法找到满足条件的设备。虽然这个测试文件没有直接测试冲突的约束，但其目的是验证在各种约束下的选择逻辑。

**用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户打开一个网页:** 用户通过浏览器访问一个包含使用 `getUserMedia` 请求摄像头功能的网页。
2. **网页 JavaScript 代码请求摄像头:**  网页的 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia`，并设置了包含理想高度约束的 `video` 约束对象。
3. **浏览器处理 `getUserMedia` 请求:** 浏览器接收到请求，并开始枚举可用的摄像头设备和它们支持的各种能力（分辨率、帧率等）。
4. **Blink 引擎的约束处理逻辑:**  Blink 引擎的 `MediaStreamConstraintsUtil` 类（这个测试文件测试的核心组件）会根据用户设置的约束，以及摄像头设备的 Capabilities 信息，来选择最佳的摄像头设备和分辨率。 这部分逻辑就是这个测试文件要验证的。
5. **设备选择和配置:**  `SelectSettings()` 函数会被调用，根据约束条件从可用的设备和格式中选择最佳匹配项。
6. **返回媒体流:**  选定的设备和配置信息会被用来初始化一个 `MediaStreamTrack` 对象，并返回给网页的 JavaScript 代码。

**第 2 部分功能归纳:**

这部分代码主要测试了 `MediaStreamConstraintsUtil` 在处理 **理想高度 (Ideal Height)** 约束时的设备选择和配置逻辑。它验证了在不同理想高度值的情况下，系统能够正确选择合适的摄像头设备和分辨率，并生成相应的 `TrackAdapterSettings` 以便后续处理。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_video_device_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
eckTrackAdapterSettingsEqualsFrameRate(result);
  }

  {
    const int kIdealHeight = 1079;
    constraint_factory_.basic().height.SetIdeal(kIdealHeight);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // In this case, the high-res device has two configurations that satisfy
    // the ideal value (1920x1080 and 2304x1536). Select the one with shortest
    // native distance to the ideal value (1920x1080).
    EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(1920, result.Width());
    EXPECT_EQ(1080, result.Height());
    EXPECT_EQ(kIdealHeight, result.track_adapter_settings().target_height());
    EXPECT_EQ(std::round(kIdealHeight * AspectRatio(result.Format())),
              result.track_adapter_settings().target_width());
    EXPECT_EQ(result.Width(),
              result.track_adapter_settings().max_aspect_ratio());
    EXPECT_EQ(1.0 / result.Height(),
              result.track_adapter_settings().min_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }

  {
    const int kIdealHeight = 1200;
    constraint_factory_.basic().height.SetIdeal(kIdealHeight);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The algorithm must the select the only device that can satisfy the ideal,
    // which is the high-res device at the highest resolution.
    EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(*high_res_highest_format_, result.Format());
    EXPECT_EQ(kIdealHeight, result.track_adapter_settings().target_height());
    EXPECT_EQ(std::round(kIdealHeight * AspectRatio(result.Format())),
              result.track_adapter_settings().target_width());
    EXPECT_EQ(result.Width(),
              result.track_adapter_settings().max_aspect_ratio());
    EXPECT_EQ(1.0 / result.Height(),
              result.track_adapter_settings().min_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryExactWidth) {
  constraint_factory_.Reset();
  const int kWidth = 640;
  constraint_factory_.basic().width.SetExact(kWidth);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // All devices in |capabilities_| support the requested width. The algorithm
  // should prefer the first device that supports the requested width natively,
  // which is the low-res device.
  EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(kWidth, result.Width());
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(kWidth, result.track_adapter_settings().max_aspect_ratio());
  EXPECT_EQ(static_cast<double>(kWidth) / result.Height(),
            result.track_adapter_settings().min_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);

  const int kLargeWidth = 2000;
  constraint_factory_.basic().width.SetExact(kLargeWidth);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_LE(kLargeWidth, result.Width());
  // Only the high-res device at the highest resolution supports the requested
  // width, even if not natively.
  EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(*high_res_highest_format_, result.Format());
  EXPECT_EQ(std::round(kLargeWidth / AspectRatio(result.Format())),
            result.track_adapter_settings().target_height());
  EXPECT_EQ(kLargeWidth, result.track_adapter_settings().target_width());
  EXPECT_EQ(kLargeWidth, result.track_adapter_settings().max_aspect_ratio());
  EXPECT_EQ(static_cast<double>(kLargeWidth) / result.Height(),
            result.track_adapter_settings().min_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryMinWidth) {
  constraint_factory_.Reset();
  const int kWidth = 640;
  constraint_factory_.basic().width.SetMin(kWidth);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // All devices in |capabilities_| support the requested width range. The
  // algorithm should prefer the default device at 1000x1000, which is the
  // first configuration that satisfies the minimum width.
  EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
  EXPECT_LE(kWidth, result.Width());
  EXPECT_EQ(1000, result.Width());
  EXPECT_EQ(1000, result.Height());
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(result.Width(), result.track_adapter_settings().max_aspect_ratio());
  EXPECT_EQ(static_cast<double>(kWidth) / result.Height(),
            result.track_adapter_settings().min_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);

  const int kLargeWidth = 2000;
  constraint_factory_.basic().width.SetMin(kLargeWidth);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // Only the high-res device at the highest resolution supports the requested
  // minimum width.
  EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_LE(kLargeWidth, result.Width());
  EXPECT_EQ(*high_res_highest_format_, result.Format());
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(result.Width(), result.track_adapter_settings().max_aspect_ratio());
  EXPECT_EQ(static_cast<double>(kLargeWidth) / result.Height(),
            result.track_adapter_settings().min_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryMaxWidth) {
  constraint_factory_.Reset();
  const int kLowWidth = 30;
  constraint_factory_.basic().width.SetMax(kLowWidth);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // All devices in |capabilities_| support the requested width range. The
  // algorithm should prefer the settings that natively exceed the requested
  // maximum by the lowest amount. In this case it is the low-res device at its
  // lowest resolution.
  EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(low_res_device_->formats[0], result.Format());
  // The track is cropped to kLowWidth and keeps the source aspect ratio.
  EXPECT_EQ(std::round(kLowWidth / AspectRatio(result.Format())),
            result.track_adapter_settings().target_height());
  EXPECT_EQ(kLowWidth, result.track_adapter_settings().target_width());
  EXPECT_EQ(kLowWidth, result.track_adapter_settings().max_aspect_ratio());
  EXPECT_EQ(1.0 / result.Height(),
            result.track_adapter_settings().min_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryWidthRange) {
  constraint_factory_.Reset();
  {
    const int kMinWidth = 640;
    const int kMaxWidth = 1280;
    constraint_factory_.basic().width.SetMin(kMinWidth);
    constraint_factory_.basic().width.SetMax(kMaxWidth);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_GE(result.Width(), kMinWidth);
    EXPECT_LE(result.Width(), kMaxWidth);
    // All devices in |capabilities_| support the constraint range. The
    // algorithm should prefer the default device since it has at least one
    // native format (1000x1000) included in the requested range.
    EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(1000, result.Width());
    EXPECT_EQ(1000, result.Height());
    EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
    EXPECT_EQ(result.Width(),
              result.track_adapter_settings().max_aspect_ratio());
    EXPECT_EQ(static_cast<double>(kMinWidth) / result.Height(),
              result.track_adapter_settings().min_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }

  {
    const int kMinWidth = 750;
    const int kMaxWidth = 850;
    constraint_factory_.basic().width.SetMin(kMinWidth);
    constraint_factory_.basic().width.SetMax(kMaxWidth);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_GE(result.Width(), kMinWidth);
    EXPECT_LE(result.Width(), kMaxWidth);
    // In this case, the algorithm should prefer the low-res device since it is
    // the first device with a native format (800x600) included in the requested
    // range.
    EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(800, result.Width());
    EXPECT_EQ(600, result.Height());
    EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
    EXPECT_EQ(result.Width(),
              result.track_adapter_settings().max_aspect_ratio());
    EXPECT_EQ(static_cast<double>(kMinWidth) / result.Height(),
              result.track_adapter_settings().min_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }

  {
    const int kMinWidth = 1900;
    const int kMaxWidth = 2000;
    constraint_factory_.basic().width.SetMin(kMinWidth);
    constraint_factory_.basic().width.SetMax(kMaxWidth);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_GE(result.Width(), kMinWidth);
    EXPECT_LE(result.Width(), kMaxWidth);
    // In this case, the algorithm should prefer the high-res device since it is
    // the only device with a native format (1920x1080) included in the
    // requested range.
    EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(1920, result.Width());
    EXPECT_EQ(1080, result.Height());
    EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
    EXPECT_EQ(result.Width(),
              result.track_adapter_settings().max_aspect_ratio());
    EXPECT_EQ(static_cast<double>(kMinWidth) / result.Height(),
              result.track_adapter_settings().min_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, IdealWidth) {
  constraint_factory_.Reset();
  {
    const int kIdealWidth = 320;
    constraint_factory_.basic().width.SetIdeal(kIdealWidth);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The algorithm should select the first device that supports the ideal
    // width natively, which is the low-res device at 320x240.
    EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(kIdealWidth, result.Width());
    // The ideal value is satisfied with a native resolution, so no rescaling.
    EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
    EXPECT_EQ(kIdealWidth, result.track_adapter_settings().max_aspect_ratio());
    EXPECT_EQ(1.0 / result.Height(),
              result.track_adapter_settings().min_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }

  {
    const int kIdealWidth = 321;
    constraint_factory_.basic().width.SetIdeal(kIdealWidth);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // In this case, the high_res device is selected because it has a mode that
    // can satisfy the ideal at a lower cost than other devices (480 vs 500).
    // Note that a native resolution of 320 is further from the ideal value of
    // 321 than 480 cropped to 321.
    EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(480, result.Width());
    // The track is cropped to kIdealWidth and keeps the source aspect ratio.
    EXPECT_EQ(std::round(kIdealWidth / AspectRatio(result.Format())),
              result.track_adapter_settings().target_height());
    EXPECT_EQ(kIdealWidth, result.track_adapter_settings().target_width());
    EXPECT_EQ(result.Width(),
              result.track_adapter_settings().max_aspect_ratio());
    EXPECT_EQ(1.0 / result.Height(),
              result.track_adapter_settings().min_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }

  {
    const int kIdealWidth = 2000;
    constraint_factory_.basic().width.SetIdeal(kIdealWidth);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The algorithm must the select the only device that can satisfy the ideal.
    EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(*high_res_highest_format_, result.Format());
    // The track is cropped to kIdealWidth and keeps the source aspect ratio.
    EXPECT_EQ(std::round(kIdealWidth / AspectRatio(result.Format())),
              result.track_adapter_settings().target_height());
    EXPECT_EQ(kIdealWidth, result.track_adapter_settings().target_width());
    EXPECT_EQ(result.Width(),
              result.track_adapter_settings().max_aspect_ratio());
    EXPECT_EQ(1.0 / result.Height(),
              result.track_adapter_settings().min_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFrameRate(result);
  }

  {
    const int kIdealWidth = 3000;
    constraint_factory_.basic().width.SetIdeal(kIdealWidth);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The algorithm must the select the device and setting with less distance
    // to the ideal.
    EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(*high_res_highest_format_, result.Format());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryExactFrameRate) {
  constraint_factory_.Reset();
  const double kFrameRate = MediaStreamVideoSource::kDefaultFrameRate;
  constraint_factory_.basic().frame_rate.SetExact(kFrameRate);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // All devices in |capabilities_| support the requested frame rate. The
  // algorithm should prefer the first device that supports the requested frame
  // rate natively, which is the low-res device at 640x480x30Hz.
  EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(kFrameRate, result.FrameRate());
  EXPECT_EQ(640, result.Width());
  EXPECT_EQ(480, result.Height());
  CheckTrackAdapterSettingsEqualsResolution(result);
  CheckTrackAdapterSettingsEqualsFrameRate(result, kFrameRate);

  const double kLargeFrameRate = 50;
  constraint_factory_.basic().frame_rate.SetExact(kLargeFrameRate);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // Only the high-res device supports the requested frame rate, even if not
  // natively. The least expensive configuration that supports the requested
  // frame rate is 1280x720x60Hz.
  EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(60.0, result.FrameRate());
  EXPECT_EQ(1280, result.Width());
  EXPECT_EQ(720, result.Height());
  CheckTrackAdapterSettingsEqualsResolution(result);
  CheckTrackAdapterSettingsEqualsFrameRate(result, kLargeFrameRate);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryMinFrameRate) {
  // MinFrameRate equal to default frame rate.
  {
    constraint_factory_.Reset();
    const double kMinFrameRate = MediaStreamVideoSource::kDefaultFrameRate;
    constraint_factory_.basic().frame_rate.SetMin(kMinFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // All devices in |capabilities_| support the requested frame-rate range.
    // The algorithm should prefer the default device.
    EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
    // The format closest to the default satisfies the constraint.
    EXPECT_EQ(*default_closest_format_, result.Format());
    CheckTrackAdapterSettingsEqualsFormat(result);
    EXPECT_TRUE(result.min_frame_rate().has_value());
    EXPECT_EQ(result.min_frame_rate(), kMinFrameRate);
    EXPECT_FALSE(result.max_frame_rate().has_value());
  }

  // MinFrameRate greater than default frame rate.
  {
    const double kMinFrameRate = 50;
    constraint_factory_.basic().frame_rate.SetMin(kMinFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // Only the high-res device supports the requested frame-rate range.
    // The least expensive configuration is 1280x720x60Hz.
    EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_LE(kMinFrameRate, result.FrameRate());
    EXPECT_EQ(1280, result.Width());
    EXPECT_EQ(720, result.Height());
    CheckTrackAdapterSettingsEqualsFormat(result);
    EXPECT_TRUE(result.min_frame_rate().has_value());
    EXPECT_EQ(result.min_frame_rate(), kMinFrameRate);
    EXPECT_FALSE(result.max_frame_rate().has_value());
  }

  // MinFrameRate lower than the minimum allowed value.
  {
    const double kMinFrameRate = -0.01;
    constraint_factory_.basic().frame_rate.SetMin(kMinFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The minimum frame rate is ignored. Default settings should be used.
    EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(*default_closest_format_, result.Format());
    EXPECT_FALSE(result.min_frame_rate().has_value());
    EXPECT_FALSE(result.max_frame_rate().has_value());
  }

  // MinFrameRate equal to the minimum allowed value.
  {
    const double kMinFrameRate = 0.0;
    constraint_factory_.basic().frame_rate.SetMin(kMinFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_TRUE(result.min_frame_rate().has_value());
    EXPECT_EQ(result.min_frame_rate(), kMinFrameRate);
    EXPECT_FALSE(result.max_frame_rate().has_value());
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryMaxFrameRate) {
  // MaxFrameRate within valid range.
  {
    constraint_factory_.Reset();
    const double kMaxFrameRate = 10;
    constraint_factory_.basic().frame_rate.SetMax(kMaxFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // All devices in |capabilities_| support the requested frame-rate range.
    // The algorithm should prefer the settings that natively exceed the
    // requested maximum by the lowest amount. In this case it is the high-res
    // device with default resolution .
    EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(kMaxFrameRate, result.FrameRate());
    EXPECT_EQ(MediaStreamVideoSource::kDefaultHeight, result.Height());
    EXPECT_EQ(MediaStreamVideoSource::kDefaultWidth, result.Width());
    EXPECT_FALSE(result.min_frame_rate().has_value());
    EXPECT_TRUE(result.max_frame_rate().has_value());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
    CheckTrackAdapterSettingsEqualsResolution(result);
    CheckTrackAdapterSettingsEqualsFrameRate(result, kMaxFrameRate);
  }

  // MaxFrameRate greater than the maximum allowed.
  {
    constraint_factory_.Reset();
    const double kMaxFrameRate =
        static_cast<double>(media::limits::kMaxFramesPerSecond) + 0.1;
    constraint_factory_.basic().frame_rate.SetMax(kMaxFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The maximum frame rate should be ignored. Default settings apply.
    EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(*default_closest_format_, result.Format());
    EXPECT_FALSE(result.min_frame_rate().has_value());
    EXPECT_FALSE(result.max_frame_rate().has_value());
  }

  // MaxFrameRate equal to the maximum and minimum allowed MaxFrameRate.
  {
    const double kMaxFrameRates[] = {1.0, media::limits::kMaxFramesPerSecond};
    for (double max_frame_rate : kMaxFrameRates) {
      constraint_factory_.Reset();
      constraint_factory_.basic().frame_rate.SetMax(max_frame_rate);
      auto result = SelectSettings();
      EXPECT_TRUE(result.HasValue());
      EXPECT_TRUE(result.max_frame_rate().has_value());
      EXPECT_FALSE(result.min_frame_rate().has_value());
      EXPECT_EQ(result.max_frame_rate(), max_frame_rate);
    }
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryFrameRateRange) {
  constraint_factory_.Reset();
  {
    const double kMinFrameRate = 10;
    const double kMaxFrameRate = 40;
    constraint_factory_.basic().frame_rate.SetMin(kMinFrameRate);
    constraint_factory_.basic().frame_rate.SetMax(kMaxFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_LE(kMinFrameRate, result.FrameRate());
    EXPECT_GE(kMaxFrameRate, result.FrameRate());
    // All devices in |capabilities_| support the constraint range. The
    // algorithm should prefer the default device since its closest-to-default
    // format has a frame rate included in the requested range.
    EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(*default_closest_format_, result.Format());
    CheckTrackAdapterSettingsEqualsResolution(result);
    CheckTrackAdapterSettingsEqualsFrameRate(result, kMaxFrameRate);
  }

  {
    const double kMinFrameRate = 25;
    const double kMaxFrameRate = 35;
    constraint_factory_.basic().frame_rate.SetMin(kMinFrameRate);
    constraint_factory_.basic().frame_rate.SetMax(kMaxFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_GE(result.FrameRate(), kMinFrameRate);
    EXPECT_LE(result.FrameRate(), kMaxFrameRate);
    // In this case, the algorithm should prefer the low-res device since it is
    // the first device with a native frame rate included in the requested
    // range. The default resolution should be preferred as secondary criterion.
    EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(*low_res_closest_format_, result.Format());
    CheckTrackAdapterSettingsEqualsResolution(result);
    CheckTrackAdapterSettingsEqualsFrameRate(result, kMaxFrameRate);
  }

  {
    const double kMinFrameRate = 50;
    const double kMaxFrameRate = 70;
    constraint_factory_.basic().frame_rate.SetMin(kMinFrameRate);
    constraint_factory_.basic().frame_rate.SetMax(kMaxFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_GE(result.FrameRate(), kMinFrameRate);
    EXPECT_LE(result.FrameRate(), kMaxFrameRate);
    // In this case, the algorithm should prefer the high-res device since it is
    // the only device with a native format included in the requested range.
    // The 1280x720 resolution should be selected due to closeness to default
    // settings, which is the second tie-breaker criterion that applies.
    EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(1280, result.Width());
    EXPECT_EQ(720, result.Height());
    CheckTrackAdapterSettingsEqualsResolution(result);
    CheckTrackAdapterSettingsEqualsFrameRate(result, kMaxFrameRate);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, IdealFrameRate) {
  constraint_factory_.Reset();
  {
    const double kIdealFrameRate = MediaStreamVideoSource::kDefaultFrameRate;
    constraint_factory_.basic().frame_rate.SetIdeal(kIdealFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The algorithm should select the first configuration that supports the
    // ideal frame rate natively, which is the low-res device. Default
    // resolution should be selected as secondary criterion.
    EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(*low_res_closest_format_, result.Format());
    CheckTrackAdapterSettingsEqualsResolution(result);
    CheckTrackAdapterSettingsEqualsFrameRate(result, kIdealFrameRate);
  }

  {
    const double kIdealFrameRate = 31;
    constraint_factory_.basic().frame_rate.SetIdeal(kIdealFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // In this case, the default device is selected because it can satisfy the
    // ideal at a lower cost than the other devices (40 vs 60).
    // Note that a native frame rate of 30 is further from the ideal than
    // 31 adjusted to 30.
    EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(*default_closest_format_, result.Format());
    CheckTrackAdapterSettingsEqualsResolution(result);
    CheckTrackAdapterSettingsEqualsFrameRate(result, kIdealFrameRate);
  }

  {
    const double kIdealFrameRate = 55;
    constraint_factory_.basic().frame_rate.SetIdeal(kIdealFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The high-res device format 1280x720x60.0 must be selected because its
    // frame rate can satisfy the ideal frame rate and has resolution closest
    // to the default.
    EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(1280, result.Width());
    EXPECT_EQ(720, result.Height());
    EXPECT_EQ(60, result.FrameRate());
    CheckTrackAdapterSettingsEqualsResolution(result);
    CheckTrackAdapterSettingsEqualsFrameRate(result, kIdealFrameRate);
  }

  {
    const double kIdealFrameRate = 100;
    constraint_factory_.basic().frame_rate.SetIdeal(kIdealFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The algorithm must select settings with frame rate closest to the ideal.
    // The high-res device format 1280x720x60.0 must be selected because its
    // frame rate it closest to the ideal value and it has resolution closest to
    // the default.
    EXPECT_EQ(high_res_device_->device_id.Utf8(), result.device_id());
    EXPECT_EQ(1280, result.Width());
    EXPECT_EQ(720, result.Height());
    EXPECT_EQ(60, result.FrameRate());
    CheckTrackAdapterSettingsEqualsResolution(result);
    CheckTrackAdapterSettingsEqualsFrameRate(result, kIdealFrameRate);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryExactAspectRatio) {
  constraint_factory_.Reset();
  const double kAspectRatio = 4.0 / 3.0;
  constraint_factory_.basic().aspect_ratio.SetExact(kAspectRatio);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  double min_width = 1.0;
  double max_width = result.Width();
  double min_height = 1.0;
  double max_height = result.Height();
  double min_aspect_ratio = min_width / max_height;
  double max_aspect_ratio = max_width / min_height;
  // The requested aspect ratio must be within the supported range.
  EXPECT_GE(kAspectRatio, min_aspect_ratio);
  EXPECT_LE(kAspectRatio, max_aspect_ratio);
  // All devices in |capabilities_| support the requested aspect ratio.
  // The algorithm should prefer the first device that supports the requested
  // aspect ratio.
  EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(*default_closest_format_, result.Format());
  EXPECT_EQ(std::round(result.Width() / kAspectRatio),
            result.track_adapter_settings().target_height());
  EXPECT_EQ(result.Width(), result.track_adapter_settings().target_width());
  EXPECT_EQ(kAspectRatio, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(kAspectRatio, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);

  const int kMinWidth = 500;
  const int kMaxWidth = 1000;
  const int kMaxHeight = 500;
  constraint_factory_.basic().height.SetMax(kMaxHeight);
  constraint_factory_.basic().width.SetMin(kMinWidth);
  constraint_factory_.basic().width.SetMax(kMaxWidth);
  constraint_factory_.basic().aspect_ratio.SetExact(kAspectRatio);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  min_width = std::max(1, kMinWidth);
  max_width = std::min(result.Width(), kMaxWidth);
  min_height = 1.0;
  max_height = std::min(result.Height(), kMaxHeight);
  min_aspect_ratio = min_width / max_height;
  max_aspect_ratio = max_width / min_height;
  // The requested aspect ratio must be within the supported range.
  EXPECT_GE(kAspectRatio, min_aspect_ratio);
  EXPECT_LE(kAspectRatio, max_aspect_ratio);
  // The default device can support the requested aspect ratio with the default
  // settings (500x500) using cropping.
  EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(*default_closest_format_, result.Format());
  EXPECT_EQ(std::round(result.Width() / kAspectRatio),
            result.track_adapter_settings().target_height());
  EXPECT_EQ(result.Width(), result.track_adapter_settings().target_width());
  EXPECT_EQ(kAspectRatio, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(kAspectRatio, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);

  const int kMinHeight = 480;
  constraint_factory_.basic().height.SetMin(kMinHeight);
  constraint_factory_.basic().height.SetMax(kMaxHeight);
  constraint_factory_.basic().width.SetMin(kMinWidth);
  constraint_factory_.basic().width.SetMax(kMaxWidth);
  constraint_factory_.basic().aspect_ratio.SetExact(kAspectRatio);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  min_width = std::max(1, kMinWidth);
  max_width = std::min(result.Width(), kMaxWidth);
  min_height = std::max(1, kMinHeight);
  max_height = std::min(result.Height(), kMaxHeight);
  min_aspect_ratio = min_width / max_height;
  max_aspect_ratio = max_width / min_height;
  // The requested aspect ratio must be within the supported range.
  EXPECT_GE(kAspectRatio, min_aspect_ratio);
  EXPECT_LE(kAspectRatio, max_aspect_ratio);
  // Given resolution constraints, the default device with closest-to-default
  // settings cannot satisfy the required aspect ratio.
  // The first device that can do it is the low-res device with a native
  // resolution of 640x480. Higher resolutions for the default device are more
  // penalized by the constraints than the default native resolution of the
  // low-res device.
  EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(*low_res_closest_format_, result.Format());
  // Native resolution, so no rescaling.
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
  EXPECT_EQ(kAspectRatio, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(kAspectRatio, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);
}

TEST_F(MediaStreamConstraintsUtilVideoDeviceTest, MandatoryMinAspectRatio) {
  constraint_factory_.Reset();
  const double kAspectRatio = 4.0 / 3.0;
  constraint_factory_.basic().aspect_ratio.SetMin(kAspectRatio);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  double max_width = result.Width();
  double min_height = 1.0;
  double max_aspect_ratio = max_width / min_height;
  // Minimum constraint aspect ratio must be less than or equal to the maximum
  // supported by the source.
  EXPECT_LE(kAspectRatio, max_aspect_ratio);
  // All devices in |capabilities_| support the requested aspect-ratio range.
  // The algorithm should prefer the first device that supports the requested
  // aspect-ratio range, which in this case is the default device.
  EXPECT_EQ(default_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(*default_closest_format_, result.Format());
  // Adjust the track resolution to use the minimum aspect ratio, which is
  // greater than the source's aspect ratio.
  EXPECT_EQ(std::round(result.Width() / kAspectRatio),
            result.track_adapter_settings().target_height());
  EXPECT_EQ(result.Width(), result.track_adapter_settings().target_width());
  EXPECT_EQ(kAspectRatio, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(result.Width(), result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFrameRate(result);

  const int kMinWidth = 500;
  const int kMaxWidth = 1000;
  const int kMinHeight = 480;
  const int kMaxHeight = 500;
  constraint_factory_.basic().width.SetMin(kMinWidth);
  constraint_factory_.basic().width.SetMax(kMaxWidth);
  constraint_factory_.basic().height.SetMin(kMinHeight);
  constraint_factory_.basic().height.SetMax(kMaxHeight);
  constraint_factory_.basic().aspect_ratio.SetMin(kAspectRatio);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  max_width = std::min(result.Width(), kMaxWidth);
  min_height = std::max(1, kMinHeight);
  max_aspect_ratio = max_width / min_height;
  // Minimum constraint aspect ratio must be less than or equal to the minimum
  // supported by the source.
  EXPECT_LE(kAspectRatio, max_aspect_ratio);
  // Given resolution constraints, the default device with closest-to-default
  // settings cannot satisfy the required minimum aspect ratio (maximum would
  // be 500/480).  The first device that can is the low-res device with a native
  // resolution of 640x480.
  // Higher resolutions for the default device are more penalized by the
  // constraints than the default native resolution of the low-res device.
  EXPECT_EQ(low_res_device_->device_id.Utf8(), result.device_id());
  EXPECT_EQ(*low_res_closest_format_, result.Format());
  EXPECT_FALSE(result.track_adapter_settings().target_size().has_value());
  // The source's native as
```