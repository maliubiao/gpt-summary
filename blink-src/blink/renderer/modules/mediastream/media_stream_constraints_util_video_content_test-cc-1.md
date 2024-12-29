Response:
The user wants me to summarize the functionality of the provided C++ code snippet. This code is part of a larger test file in the Chromium project, specifically for testing video constraints in the mediastream module.

The code defines a series of test cases within a Google Test framework. Each test case focuses on evaluating how different video constraints (like width, height, aspect ratio, and frame rate) are handled by the `MediaStreamConstraintsUtil` class when selecting the best video settings.

I need to identify the core purpose of each test function and generalize the behavior being tested.
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_video_content_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

基于提供的代码片段，这是 `blink/renderer/modules/mediastream/media_stream_constraints_util_video_content_test.cc` 文件的一部分，专门用于测试视频内容相关的约束处理逻辑。

**归纳一下它的功能 (基于第2部分):**

这部分代码主要测试了 `MediaStreamConstraintsUtil` 类在处理以下视频约束时的行为：

* **理想宽度 (Ideal Width):**  测试当设置了 `ideal` 宽度约束时，选择算法如何确定最终的宽度和高度，并考虑与其他约束（如 `minWidth`, `maxWidth`, `minHeight`, `maxHeight`）的交互。测试了理想宽度在约束范围内、超出约束范围等各种情况。
* **强制要求的精确宽高比 (Mandatory Exact Aspect Ratio):** 测试当设置了精确的 `aspectRatio` 约束时，选择算法如何确定最终的宽度和高度，特别是在默认宽高比无法满足的情况下，会尝试保留默认的高度或宽度，以获得最大的面积。
* **强制要求的最小宽高比 (Mandatory Min Aspect Ratio):** 测试当设置了最小 `aspectRatio` 约束时，选择算法如何确定最终的宽度和高度。会考虑默认宽高比以及设置的最小值。
* **强制要求的最大宽高比 (Mandatory Max Aspect Ratio):** 测试当设置了最大 `aspectRatio` 约束时，选择算法如何确定最终的宽度和高度。会考虑默认宽高比以及设置的最大值。
* **强制要求的宽高比范围 (Mandatory Range Aspect Ratio):** 测试当设置了 `minAspectRatio` 和 `maxAspectRatio` 范围约束时，选择算法如何确定最终的宽度和高度，涵盖了范围包含默认值、大于默认值、小于默认值等情况。
* **理想宽高比 (Ideal Aspect Ratio):** 测试当设置了 `ideal` 宽高比约束时，选择算法如何确定最终的宽度和高度，并考虑与其他约束（如 `minWidth`, `maxWidth`, `minHeight`, `maxHeight`) 的交互。测试了理想宽高比在约束范围内、超出约束范围、以及与边界相交等各种情况。
* **强制要求的精确帧率 (Mandatory Exact Frame Rate):** 测试当设置了精确的 `frameRate` 约束时，选择算法如何确定最终的帧率。
* **强制要求的最小帧率 (Mandatory Min Frame Rate):** 测试当设置了最小 `frameRate` 约束时，选择算法如何确定最终的帧率，涵盖了最小值大于默认值、小于默认值、小于允许最小值以及等于允许最小值的情况。
* **强制要求的最大帧率 (Mandatory Max Frame Rate):** 测试当设置了最大 `frameRate` 约束时，选择算法如何确定最终的帧率，涵盖了最大值大于默认值、小于默认值、大于允许最大值以及等于允许最大值的情况。
* **强制要求的帧率范围 (Mandatory Range Frame Rate):** 测试当设置了 `minFrameRate` 和 `maxFrameRate` 范围约束时，选择算法如何确定最终的帧率。
* **理想帧率 (Ideal Frame Rate):** 测试当设置了 `ideal` 帧率约束时，选择算法如何确定最终的帧率，并考虑与其他约束（如 `maxFrameRate`, `minFrameRate`）的交互。测试了理想帧率在约束范围内、超出约束范围等各种情况。

**功能总结:**

总而言之，这部分测试代码专注于验证 `MediaStreamConstraintsUtil` 类在处理各种视频尺寸（宽度、高度、宽高比）和帧率的约束条件时的正确性，确保其能够根据给定的约束选择最合适的视频设置。它覆盖了各种边界情况和组合情况，以确保代码的健壮性。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_video_content_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
ack_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // The whole range is greater than the default.
  {
    constraint_factory_.Reset();
    const int kMinWidth = kDefaultScreenCastWidth + 100;
    const int kMaxWidth = kDefaultScreenCastWidth + 200;
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
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, IdealWidth) {
  // Unconstrained
  {
    constraint_factory_.Reset();
    const int kIdealWidth = 1000;
    constraint_factory_.basic().width.SetIdeal(kIdealWidth);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kIdealWidth, result.Width());
    // When ideal width is given, the algorithm returns a height that is closest
    // to width / kDefaultScreenCastAspectRatio.
    EXPECT_EQ(std::round(kIdealWidth / kDefaultScreenCastAspectRatio),
              result.Height());
    CheckNonResolutionDefaults(result);
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
  }

  // Ideal greater than maximum.
  {
    constraint_factory_.Reset();
    const int kIdealWidth = 1000;
    const int kMaxWidth = 800;
    constraint_factory_.basic().width.SetIdeal(kIdealWidth);
    constraint_factory_.basic().width.SetMax(kMaxWidth);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kMaxWidth, result.Width());
    // Expect closest to kMaxWidth / kDefaultScreenCastAspectRatio.
    EXPECT_EQ(std::round(kMaxWidth / kDefaultScreenCastAspectRatio),
              result.Height());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1.0 / kMaxScreenCastDimension,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(static_cast<double>(kMaxWidth) / kMinScreenCastDimension,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // Ideal less than minimum.
  {
    constraint_factory_.Reset();
    const int kIdealWidth = 1000;
    const int kMinWidth = 1200;
    constraint_factory_.basic().width.SetIdeal(kIdealWidth);
    constraint_factory_.basic().width.SetMin(kMinWidth);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kMinWidth, result.Width());
    // Expect closest to kMinWidth / kDefaultScreenCastAspectRatio.
    EXPECT_EQ(std::round(kMinWidth / kDefaultScreenCastAspectRatio),
              result.Height());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(static_cast<double>(kMinWidth) / kMaxScreenCastDimension,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(
        static_cast<double>(kMaxScreenCastDimension) / kMinScreenCastDimension,
        result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // Ideal intersects a box.
  {
    constraint_factory_.Reset();
    constraint_factory_.basic().width.SetMin(500);
    constraint_factory_.basic().width.SetMax(1000);
    constraint_factory_.basic().height.SetMin(100);
    constraint_factory_.basic().height.SetMax(500);
    const int kIdealWidth = 750;
    constraint_factory_.basic().width.SetIdeal(kIdealWidth);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // Ideal width is included in the bounding box.
    EXPECT_EQ(kIdealWidth, result.Width());
    // Expect height closest to kIdealWidth / default aspect ratio.
    double default_aspect_ratio =
        static_cast<double>(constraint_factory_.basic().width.Max()) /
        constraint_factory_.basic().height.Max();
    EXPECT_EQ(std::round(kIdealWidth / default_aspect_ratio), result.Height());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(500.0 / 500.0,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(1000.0 / 100.0,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // Ideal outside the box, closest to the side coinciding with max width.
  {
    const int kMaxWidth = 1000;
    constraint_factory_.Reset();
    constraint_factory_.basic().width.SetMin(500);
    constraint_factory_.basic().width.SetMax(kMaxWidth);
    constraint_factory_.basic().height.SetMin(100);
    constraint_factory_.basic().height.SetMax(500);
    constraint_factory_.basic().width.SetIdeal(1200);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kMaxWidth, result.Width());
    // kMaxWidth / kDefaultScreenCastAspectRatio is outside the box. Closest is
    // max height.
    EXPECT_EQ(constraint_factory_.basic().height.Max(), result.Height());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(500.0 / 500.0,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(static_cast<double>(kMaxWidth) / 100.0,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // Ideal outside the constrained set, closest to a single point.
  {
    constraint_factory_.Reset();
    constraint_factory_.basic().width.SetMin(100);
    constraint_factory_.basic().width.SetMax(500);
    constraint_factory_.basic().height.SetMin(100);
    constraint_factory_.basic().height.SetMax(500);
    constraint_factory_.basic().aspect_ratio.SetMax(1.0);
    constraint_factory_.basic().width.SetIdeal(1200);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // (max-width, max-height) is the single point closest to the ideal line.
    EXPECT_EQ(constraint_factory_.basic().width.Max(), result.Width());
    EXPECT_EQ(constraint_factory_.basic().height.Max(), result.Height());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(100.0 / 500.0,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(1.0, result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, MandatoryExactAspectRatio) {
  constraint_factory_.Reset();
  const double kAspectRatio = 2.0;
  constraint_factory_.basic().aspect_ratio.SetExact(kAspectRatio);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // Given that the default aspect ratio cannot be preserved, the algorithm
  // tries to preserve, among the default height or width, the one that leads
  // to highest area. In this case, height is preserved.
  EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
  EXPECT_EQ(std::round(kDefaultScreenCastHeight * kAspectRatio),
            result.Width());
  CheckNonResolutionDefaults(result);
  EXPECT_EQ(kAspectRatio, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(kAspectRatio, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, MandatoryMinAspectRatio) {
  constraint_factory_.Reset();
  const double kAspectRatio = 2.0;
  constraint_factory_.basic().aspect_ratio.SetMin(kAspectRatio);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // kAspectRatio is greater that the default, so expect kAspectRatio.
  EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
  EXPECT_EQ(std::round(kDefaultScreenCastHeight * kAspectRatio),
            result.Width());
  CheckNonResolutionDefaults(result);
  EXPECT_EQ(kAspectRatio, result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(static_cast<double>(kMaxScreenCastDimension) /
                static_cast<double>(kMinScreenCastDimension),
            result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result);

  const double kSmallAspectRatio = 0.5;
  constraint_factory_.basic().aspect_ratio.SetMin(kSmallAspectRatio);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // kSmallAspectRatio is less that the default, so expect the default.
  EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
  EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
  CheckNonResolutionDefaults(result);
  EXPECT_EQ(kSmallAspectRatio,
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(static_cast<double>(kMaxScreenCastDimension) /
                static_cast<double>(kMinScreenCastDimension),
            result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, MandatoryMaxAspectRatio) {
  constraint_factory_.Reset();
  const double kAspectRatio = 2.0;
  constraint_factory_.basic().aspect_ratio.SetMax(kAspectRatio);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // kAspectRatio is greater that the default, so expect the default.
  EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
  EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
  CheckNonResolutionDefaults(result);
  EXPECT_EQ(static_cast<double>(kMinScreenCastDimension) /
                static_cast<double>(kMaxScreenCastDimension),
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(kAspectRatio, result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result);

  const double kSmallAspectRatio = 0.5;
  constraint_factory_.basic().aspect_ratio.SetMax(kSmallAspectRatio);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // kSmallAspectRatio is less that the default, so expect kSmallAspectRatio.
  // Prefer to preserve default width since that leads to larger area than
  // preserving default height.
  EXPECT_EQ(std::round(kDefaultScreenCastWidth / kSmallAspectRatio),
            result.Height());
  EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
  CheckNonResolutionDefaults(result);
  EXPECT_EQ(static_cast<double>(kMinScreenCastDimension) /
                static_cast<double>(kMaxScreenCastDimension),
            result.track_adapter_settings().min_aspect_ratio());
  EXPECT_EQ(kSmallAspectRatio,
            result.track_adapter_settings().max_aspect_ratio());
  CheckTrackAdapterSettingsEqualsFormat(result);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, MandatoryRangeAspectRatio) {
  constraint_factory_.Reset();
  {
    const double kMinAspectRatio = 0.5;
    const double kMaxAspectRatio = 2.0;
    constraint_factory_.basic().aspect_ratio.SetMin(kMinAspectRatio);
    constraint_factory_.basic().aspect_ratio.SetMax(kMaxAspectRatio);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // Range includes default, so expect the default.
    EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
    EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(kMinAspectRatio,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  {
    const double kMinAspectRatio = 2.0;
    const double kMaxAspectRatio = 3.0;
    constraint_factory_.basic().aspect_ratio.SetMin(kMinAspectRatio);
    constraint_factory_.basic().aspect_ratio.SetMax(kMaxAspectRatio);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The whole range is greater than the default. Expect the minimum.
    EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
    EXPECT_EQ(std::round(kDefaultScreenCastHeight * kMinAspectRatio),
              result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(kMinAspectRatio,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  {
    const double kMinAspectRatio = 0.5;
    const double kMaxAspectRatio = 1.0;
    constraint_factory_.basic().aspect_ratio.SetMin(kMinAspectRatio);
    constraint_factory_.basic().aspect_ratio.SetMax(kMaxAspectRatio);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // The whole range is less than the default. Expect the maximum.
    EXPECT_EQ(std::round(kDefaultScreenCastWidth / kMaxAspectRatio),
              result.Height());
    EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(kMinAspectRatio,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, IdealAspectRatio) {
  // Unconstrained.
  {
    constraint_factory_.Reset();
    const double kIdealAspectRatio = 2.0;
    constraint_factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
    EXPECT_EQ(std::round(kDefaultScreenCastHeight * kIdealAspectRatio),
              result.Width());
    CheckNonResolutionDefaults(result);
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
  }

  // Ideal greater than maximum.
  {
    constraint_factory_.Reset();
    const double kIdealAspectRatio = 2.0;
    const double kMaxAspectRatio = 1.5;
    constraint_factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    constraint_factory_.basic().aspect_ratio.SetMax(kMaxAspectRatio);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // Ideal aspect ratio is greater than the maximum, expect maximum.
    EXPECT_EQ(std::round(kDefaultScreenCastWidth / kMaxAspectRatio),
              result.Height());
    EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(
        static_cast<double>(kMinScreenCastDimension) / kMaxScreenCastDimension,
        result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // Ideal less than minimum.
  {
    constraint_factory_.Reset();
    const double kIdealAspectRatio = 1.0;
    const double kMinAspectRatio = 1.5;
    constraint_factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    constraint_factory_.basic().aspect_ratio.SetMin(kMinAspectRatio);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // Ideal aspect ratio is less than the maximum, expect minimum.
    EXPECT_EQ(std::round(kDefaultScreenCastWidth / kMinAspectRatio),
              result.Height());
    EXPECT_EQ(kDefaultScreenCastWidth, result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(kMinAspectRatio,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(
        static_cast<double>(kMaxScreenCastDimension) / kMinScreenCastDimension,
        result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // Ideal intersects a box.
  {
    constraint_factory_.Reset();
    constraint_factory_.basic().height.SetMin(100);
    constraint_factory_.basic().height.SetMax(500);
    constraint_factory_.basic().width.SetMin(100);
    constraint_factory_.basic().width.SetMax(500);
    const double kIdealAspectRatio = 2.0;
    constraint_factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // Ideal aspect-ratio is included in the bounding box, with the value
    // closest to a standard width or height being the cut with the maximum
    // width.
    EXPECT_EQ(
        std::round(constraint_factory_.basic().width.Max() / kIdealAspectRatio),
        result.Height());
    EXPECT_EQ(constraint_factory_.basic().width.Max(), result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(100.0 / 500.0,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(500.0 / 100.0,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);

    constraint_factory_.basic().height.SetMin(1000);
    constraint_factory_.basic().height.SetMax(5000);
    constraint_factory_.basic().width.SetMin(1000);
    constraint_factory_.basic().width.SetMax(5000);
    result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // Ideal aspect-ratio is included in the bounding box.
    EXPECT_EQ(
        std::round(constraint_factory_.basic().width.Max() / kIdealAspectRatio),
        result.Height());
    EXPECT_EQ(constraint_factory_.basic().width.Max(), result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1000.0 / 5000.0,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(5000.0 / 1000.0,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);

    constraint_factory_.Reset();
    constraint_factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    constraint_factory_.basic().height.SetMin(250);
    constraint_factory_.basic().width.SetMin(250);
    result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // Ideal aspect-ratio is included in the bounding box. Preserving default
    // height leads to larger area than preserving default width.
    EXPECT_EQ(kDefaultScreenCastHeight, result.Height());
    EXPECT_EQ(kDefaultScreenCastHeight * kIdealAspectRatio, result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(250.0 / kMaxScreenCastDimension,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(kMaxScreenCastDimension / 250.0,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // Ideal outside the constrained area, closest to min or max aspect ratio.
  {
    const double kMinAspectRatio = 0.5;
    const double kMaxAspectRatio = 2.0;
    constraint_factory_.Reset();
    constraint_factory_.basic().height.SetMin(100);
    constraint_factory_.basic().height.SetMax(500);
    constraint_factory_.basic().width.SetMin(100);
    constraint_factory_.basic().width.SetMax(500);
    constraint_factory_.basic().aspect_ratio.SetMin(kMinAspectRatio);
    constraint_factory_.basic().aspect_ratio.SetMax(kMaxAspectRatio);
    constraint_factory_.basic().aspect_ratio.SetIdeal(3.0);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // Ideal is closest to kMaxAspectRatio.
    EXPECT_EQ(
        std::round(constraint_factory_.basic().width.Max() / kMaxAspectRatio),
        result.Height());
    EXPECT_EQ(constraint_factory_.basic().width.Max(), result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(kMinAspectRatio,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);

    constraint_factory_.basic().aspect_ratio.SetIdeal(0.3);
    result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // Ideal is closest to kMinAspectRatio.
    EXPECT_EQ(constraint_factory_.basic().height.Max(), result.Height());
    EXPECT_EQ(
        std::round(constraint_factory_.basic().height.Max() * kMinAspectRatio),
        result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(kMinAspectRatio,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);

    // Use a box that is bigger and further from the origin to force closeness
    // to a different default dimension.
    constraint_factory_.Reset();
    constraint_factory_.basic().aspect_ratio.SetMin(kMinAspectRatio);
    constraint_factory_.basic().aspect_ratio.SetMax(kMaxAspectRatio);
    constraint_factory_.basic().height.SetMin(3000);
    constraint_factory_.basic().width.SetMin(3000);
    constraint_factory_.basic().aspect_ratio.SetIdeal(3.0);
    result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // Ideal is closest to kMaxAspectRatio.
    EXPECT_EQ(constraint_factory_.basic().height.Min(), result.Height());
    EXPECT_EQ(
        std::round(constraint_factory_.basic().height.Min() * kMaxAspectRatio),
        result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(kMinAspectRatio,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);

    constraint_factory_.basic().aspect_ratio.SetIdeal(0.3);
    result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // Ideal is closest to kMinAspectRatio.
    EXPECT_EQ(
        std::round(constraint_factory_.basic().width.Min() / kMinAspectRatio),
        result.Height());
    EXPECT_EQ(constraint_factory_.basic().width.Min(), result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(kMinAspectRatio,
              result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(kMaxAspectRatio,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }

  // Ideal outside the constrained area, closest to a single point.
  {
    constraint_factory_.Reset();
    constraint_factory_.basic().height.SetMin(100);
    constraint_factory_.basic().height.SetMax(500);
    constraint_factory_.basic().width.SetMin(100);
    constraint_factory_.basic().width.SetMax(500);
    constraint_factory_.basic().aspect_ratio.SetMin(1.0);
    constraint_factory_.basic().aspect_ratio.SetIdeal(10.0);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // Ideal is closest to the min height and max width.
    EXPECT_EQ(constraint_factory_.basic().height.Min(), result.Height());
    EXPECT_EQ(constraint_factory_.basic().width.Max(), result.Width());
    CheckNonResolutionDefaults(result);
    EXPECT_EQ(1.0, result.track_adapter_settings().min_aspect_ratio());
    EXPECT_EQ(500.0 / 100.0,
              result.track_adapter_settings().max_aspect_ratio());
    CheckTrackAdapterSettingsEqualsFormat(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, MandatoryExactFrameRate) {
  constraint_factory_.Reset();
  const double kFrameRate = 45.0;
  constraint_factory_.basic().frame_rate.SetExact(kFrameRate);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(kFrameRate, result.FrameRate());
  EXPECT_EQ(kFrameRate, result.min_frame_rate());
  EXPECT_EQ(kFrameRate, result.max_frame_rate());
  CheckNonFrameRateDefaults(result);
  CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result, kFrameRate);
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, MandatoryMinFrameRate) {
  // MinFrameRate greater than the default frame rate.
  {
    constraint_factory_.Reset();
    const double kMinFrameRate = 45.0;
    constraint_factory_.basic().frame_rate.SetMin(kMinFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // kMinFrameRate is greater that the default, so expect kMinFrameRate.
    EXPECT_EQ(kMinFrameRate, result.FrameRate());
    EXPECT_TRUE(result.min_frame_rate().has_value());
    EXPECT_EQ(kMinFrameRate, result.min_frame_rate());
    EXPECT_FALSE(result.max_frame_rate().has_value());
    CheckNonFrameRateDefaults(result);
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
  }

  // MinFrameRate less than the default frame rate.
  {
    const double kMinFrameRate = 5.0;
    constraint_factory_.basic().frame_rate.SetMin(kMinFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // No ideal or maximum frame rate given, expect default.
    EXPECT_EQ(kDefaultScreenCastFrameRate, result.FrameRate());
    EXPECT_TRUE(result.min_frame_rate().has_value());
    EXPECT_EQ(kMinFrameRate, result.min_frame_rate());
    EXPECT_FALSE(result.max_frame_rate().has_value());
    CheckNonFrameRateDefaults(result);
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
  }

  // MinFrameRate less than the minimum allowed.
  {
    const double kMinFrameRate = -0.01;
    constraint_factory_.basic().frame_rate.SetMin(kMinFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // No ideal or maximum frame rate given, expect default.
    EXPECT_EQ(kDefaultScreenCastFrameRate, result.FrameRate());
    // kMinFrameRate should be ignored.
    EXPECT_FALSE(result.min_frame_rate().has_value());
    EXPECT_FALSE(result.max_frame_rate().has_value());
    CheckNonFrameRateDefaults(result);
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
  }

  // MinFrameRate equal to the minimum allowed.
  {
    const double kMinFrameRate = 0.0;
    constraint_factory_.basic().frame_rate.SetMin(kMinFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // No ideal or maximum frame rate given, expect default.
    EXPECT_EQ(kDefaultScreenCastFrameRate, result.FrameRate());
    EXPECT_TRUE(result.min_frame_rate().has_value());
    EXPECT_EQ(kMinFrameRate, result.min_frame_rate());
    EXPECT_FALSE(result.max_frame_rate().has_value());
    CheckNonFrameRateDefaults(result);
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, MandatoryMaxFrameRate) {
  constraint_factory_.Reset();
  // kMaxFrameRate greater than default
  {
    const double kMaxFrameRate = 45.0;
    constraint_factory_.basic().frame_rate.SetMax(kMaxFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // If max frame rate is provided, it is used as default.
    EXPECT_EQ(kMaxFrameRate, result.FrameRate());
    EXPECT_EQ(std::optional<double>(), result.min_frame_rate());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
    CheckNonFrameRateDefaults(result);
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result,
                                                            kMaxFrameRate);
  }

  // kMaxFrameRate less than default
  {
    const double kMaxFrameRate = 5.0;
    constraint_factory_.basic().frame_rate.SetMax(kMaxFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // If max frame rate is provided, it is used as default.
    EXPECT_EQ(kMaxFrameRate, result.FrameRate());
    EXPECT_EQ(std::optional<double>(), result.min_frame_rate());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
    CheckNonFrameRateDefaults(result);
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result,
                                                            kMaxFrameRate);
  }

  // kMaxFrameRate greater than the maximum allowed
  {
    const double kMaxFrameRate = kMaxScreenCastFrameRate + 0.1;
    constraint_factory_.basic().frame_rate.SetMax(kMaxFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // Expect the default, since the given maximum is invalid.
    EXPECT_EQ(kDefaultScreenCastFrameRate, result.FrameRate());
    EXPECT_EQ(std::optional<double>(), result.min_frame_rate());
    EXPECT_EQ(std::optional<double>(), result.max_frame_rate());
    CheckNonFrameRateDefaults(result);
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result);
  }

  // kMaxFrameRate equal to the maximum allowed
  {
    const double kMaxFrameRate = kMaxScreenCastFrameRate;
    constraint_factory_.basic().frame_rate.SetMax(kMaxFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // If max frame rate is provided, it is used as default.
    EXPECT_EQ(kMaxFrameRate, result.FrameRate());
    EXPECT_EQ(std::optional<double>(), result.min_frame_rate());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
    CheckNonFrameRateDefaults(result);
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result,
                                                            kMaxFrameRate);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, MandatoryRangeFrameRate) {
  constraint_factory_.Reset();
  {
    const double kMinFrameRate = 15.0;
    const double kMaxFrameRate = 45.0;
    constraint_factory_.basic().frame_rate.SetMin(kMinFrameRate);
    constraint_factory_.basic().frame_rate.SetMax(kMaxFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // If max frame rate is provided, it is used as default.
    EXPECT_EQ(kMaxFrameRate, result.FrameRate());
    EXPECT_EQ(kMinFrameRate, result.min_frame_rate());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
    CheckNonFrameRateDefaults(result);
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result,
                                                            kMaxFrameRate);
  }

  {
    const double kMinFrameRate = 45.0;
    const double kMaxFrameRate = 55.0;
    constraint_factory_.basic().frame_rate.SetMin(kMinFrameRate);
    constraint_factory_.basic().frame_rate.SetMax(kMaxFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // If max frame rate is provided, it is used as default.
    EXPECT_EQ(kMaxFrameRate, result.FrameRate());
    EXPECT_EQ(kMinFrameRate, result.min_frame_rate());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
    CheckNonFrameRateDefaults(result);
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result,
                                                            kMaxFrameRate);
  }

  {
    const double kMinFrameRate = 10.0;
    const double kMaxFrameRate = 15.0;
    constraint_factory_.basic().frame_rate.SetMin(kMinFrameRate);
    constraint_factory_.basic().frame_rate.SetMax(kMaxFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    // If max frame rate is provided, it is used as default.
    EXPECT_EQ(kMaxFrameRate, result.FrameRate());
    EXPECT_EQ(kMinFrameRate, result.min_frame_rate());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
    CheckNonFrameRateDefaults(result);
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result,
                                                            kMaxFrameRate);
  }
}

TEST_F(MediaStreamConstraintsUtilVideoContentTest, IdealFrameRate) {
  // Unconstrained.
  {
    constraint_factory_.Reset();
    const double kIdealFrameRate = 45.0;
    constraint_factory_.basic().frame_rate.SetIdeal(kIdealFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kIdealFrameRate, result.FrameRate());
    EXPECT_EQ(std::optional<double>(), result.min_frame_rate());
    EXPECT_EQ(std::optional<double>(), result.max_frame_rate());
    CheckNonFrameRateDefaults(result);
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result,
                                                            kIdealFrameRate);
  }

  // Ideal greater than maximum.
  {
    constraint_factory_.Reset();
    const double kIdealFrameRate = 45.0;
    const double kMaxFrameRate = 30.0;
    constraint_factory_.basic().frame_rate.SetIdeal(kIdealFrameRate);
    constraint_factory_.basic().frame_rate.SetMax(kMaxFrameRate);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kMaxFrameRate, result.FrameRate());
    EXPECT_EQ(std::optional<double>(), result.min_frame_rate());
    EXPECT_EQ(kMaxFrameRate, result.max_frame_rate());
    CheckNonFrameRateDefaults(result);
    CheckTrackAdapterSettingsEqualsFormatDefaultAspectRatio(result,
                                                            kMaxFrameRate);
  }

  // Ideal less than minimum.
  {
    constraint_factory_.Reset();
    const double kIdealFrameRate = 45.0;
    const double kMinFrameRate = 50.0;
    constraint_factory_.basic().frame_rate.SetIdeal(kIdealFrameRate);
    constraint_factory_.basi
"""


```