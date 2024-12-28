Response:
Let's break down the thought process to analyze the C++ unittest file.

1. **Identify the Core Purpose:** The file name `scrollbar_theme_fluent_unittest.cc` immediately signals that this is a unit test file. The "fluent" part suggests it's testing the "fluent" style of scrollbars in the Chromium browser. The `_unittest.cc` suffix is a standard convention.

2. **Understand the Tested Class:** The inclusion of `#include "third_party/blink/renderer/core/scroll/scrollbar_theme_fluent.h"` tells us the primary class under test is `ScrollbarThemeFluent`.

3. **Examine Included Headers:**  Looking at the other `#include` statements gives clues about what functionalities are being tested and what supporting infrastructure is used:
    * `<memory>`:  Indicates the use of smart pointers (like `std::unique_ptr`).
    * `"base/gtest_prod_util.h"` and `"testing/gtest/include/gtest/gtest.h"`:  Confirms this is using the Google Test framework for unit testing.
    * `"base/test/scoped_feature_list.h"`:  Suggests testing features that can be enabled/disabled via feature flags.
    * `"third_party/blink/renderer/core/scroll/scroll_types.h"` and `"third_party/blink/renderer/core/scroll/scrollbar.h"`: Shows interaction with core scrolling concepts and the `Scrollbar` class.
    * `"third_party/blink/renderer/core/scroll/scrollbar_test_suite.h"`: Implies leveraging a common test setup or utilities for scrollbar testing.
    * `"third_party/blink/renderer/core/testing/scoped_mock_overlay_scrollbars.h"`:  Points to tests specifically for overlay scrollbar behavior.
    * `"third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"`: Another hint about testing features that can be toggled.
    * `"third_party/blink/renderer/platform/testing/task_environment.h"`: Indicates potential asynchronous operations or the need for a specific test environment.
    * `"ui/gfx/geometry/rect.h"` and `"ui/native_theme/native_theme_features.h"`:  Relates to UI drawing and theme-related settings.

4. **Analyze the Test Structure:** The file contains several test classes:
    * `ScrollbarThemeFluentMock`:  A mock class inheriting from `ScrollbarThemeFluent`. This is a common pattern for unit testing, allowing specific behaviors to be overridden or inspected. The public methods reveal what aspects of `ScrollbarThemeFluent` are being probed (e.g., `ButtonLength`, `ThumbOffset`, `ThumbRect`, etc.).
    * `ScrollbarThemeFluentTest`: The main test fixture for non-overlay scrollbars. It uses `::testing::TestWithParam` to run tests with different scale factors.
    * `OverlayScrollbarThemeFluentTest`:  A derived test fixture specifically for overlay scrollbars. It enables the overlay scrollbar feature.

5. **Examine Individual Tests:**  Each `TEST_P` macro defines a specific test case. The test names and the assertions within them reveal what properties are being verified:
    * `ScrollbarThicknessScalesProperly`: Checks if the scrollbar thickness scales correctly with the device pixel ratio (DPR).
    * `VerticalScrollbarPartsSizes` and `HorizontalScrollbarPartsSizes`: Verify the correct sizing and positioning of different scrollbar components (track, thumb, buttons) for both vertical and horizontal orientations.
    * `ScrollbarBackgroundInvalidationTest`: Tests whether thumb position changes incorrectly trigger background repaints (a performance consideration).
    * `OverlaySetsCorrectTrackAndInsetSize`:  Checks specific sizing and insetting for overlay scrollbars.
    * `TestVerticalInsetTrackRect` and `TestHorizontalInsetTrackRect`: Verifies the correct insets applied to the scrollbar track.
    * `TestVerticalInsetButtonRect` and `TestHorizontalInsetButtonRect`:  Verifies the correct insets applied to the scrollbar buttons.

6. **Identify Relationships with Web Technologies:** Based on the tested properties (sizing, positioning, visibility, interaction), we can infer the connections to HTML, CSS, and JavaScript:
    * **HTML:** The scrollbar is a UI element associated with scrollable containers in HTML. The tests implicitly cover how these scrollbars are rendered within the HTML layout.
    * **CSS:** CSS styles can influence the appearance of scrollbars (though the "fluent" theme likely aims for a consistent look). The scaling tests are relevant to how scrollbars adapt to different device pixel ratios, which is important for consistent rendering across devices. The insets and dimensions are directly related to CSS layout properties.
    * **JavaScript:** JavaScript can trigger scrolling, and these tests, particularly the background invalidation test, touch on how the scrollbar updates in response to scrolling events initiated by JavaScript.

7. **Consider Potential Errors:** The tests implicitly reveal potential errors:
    * Incorrect sizing of scrollbar parts.
    * Inaccurate scaling with DPR.
    * Unnecessary repaints that could impact performance.
    * Incorrect insets leading to visual glitches.

8. **Infer User Actions and Debugging:** To reach this code during debugging, a developer would likely be investigating issues related to:
    * The visual appearance of scrollbars on different platforms or with specific feature flags enabled.
    * Performance problems related to excessive repainting during scrolling.
    * Layout bugs where scrollbars are not positioned or sized correctly.
    * Differences in scrollbar behavior between "fluent" and other themes.

9. **Structure the Analysis:** Finally, organize the findings into clear categories as requested: functionality, relationships to web technologies, logical reasoning (input/output), common errors, and debugging. This involves synthesizing the information gleaned from the code into a comprehensive explanation.
这个文件 `scrollbar_theme_fluent_unittest.cc` 是 Chromium Blink 引擎中用于测试 **Fluent 风格滚动条主题** 的单元测试文件。它主要测试 `blink::ScrollbarThemeFluent` 类的各项功能，确保 Fluent 滚动条在不同缩放比例下能够正确渲染和工作。

以下是该文件的功能详细说明：

**1. 单元测试框架：**

* 该文件使用 Google Test (gtest) 框架进行单元测试，通过 `TEST_P` 宏定义了多个测试用例。
* 每个测试用例都针对 `ScrollbarThemeFluent` 类的特定功能进行验证。

**2. 测试 `ScrollbarThemeFluent` 类的核心功能：**

* **滚动条尺寸和位置计算：** 测试 Fluent 主题下滚动条各个组成部分（例如：轨道、滑块、按钮）的尺寸和位置计算是否正确，包括水平和垂直滚动条。
* **缩放比例适配：**  使用 `::testing::Values(1.f, 1.25f, 1.5f, 1.75f, 2.f)` 为不同的设备像素比 (DPR) 运行相同的测试，确保滚动条在不同缩放比例下显示正确。
* **滑块和轨道的间距和厚度：** 测试滑块在轨道中的偏移量 (`ThumbOffset`)、滑块的厚度 (`ThumbThickness`)、轨道的厚度 (`scrollbar_track_thickness`) 和内边距 (`scrollbar_track_inset`) 等属性的计算是否正确。
* **按钮尺寸：** 测试滚动条两端的按钮尺寸 (`ButtonSize`) 是否计算正确。
* **背景重绘优化：**  测试当滑块位置改变时，是否不必要地触发背景重绘，这是为了保证性能。Fluent 滚动条的目标是不像某些旧的滚动条那样在滚动到顶部/底部时改变箭头按钮的颜色而触发重绘。
* **Overlay 滚动条支持：** 专门测试当启用 Overlay 滚动条特性时，Fluent 主题下的滚动条尺寸、轨道内边距和按钮内边距的计算是否正确。
* **轨道和按钮的内边距 (Inset)：** 测试在 Overlay 模式下，轨道和按钮的内边距 (`InsetTrackRect`, `InsetButtonRect`) 计算是否正确。

**与 JavaScript, HTML, CSS 的关系：**

虽然这是一个 C++ 的单元测试文件，但它直接关系到浏览器如何渲染滚动条，这与 Web 前端技术紧密相关：

* **CSS：** CSS 可以控制滚动条的显示与否 (`overflow: auto`, `overflow: scroll`)，以及一些基本的样式，但浏览器底层的滚动条渲染是由类似 `ScrollbarThemeFluent` 这样的 C++ 类控制的。这个测试文件验证了 Fluent 滚动条主题在底层实现上的正确性，最终会影响到 CSS 样式应用于滚动条的效果。例如，CSS 中设置的滚动条颜色等样式，会与 Fluent 主题提供的默认样式结合起来渲染。
* **HTML：** HTML 结构中如果内容超出容器大小，浏览器会自动显示滚动条。`ScrollbarThemeFluent` 负责渲染这些自动出现的滚动条。
* **JavaScript：** JavaScript 可以通过修改元素的 `scrollLeft` 和 `scrollTop` 属性来控制滚动行为。测试文件中 `mock_scrollable_area()->SetScrollOffset()` 模拟了 JavaScript 触发的滚动，并验证了滚动条在滚动过程中的行为（例如，背景是否不必要地重绘）。

**举例说明：**

* **CSS 影响：** 假设一个网站使用了以下 CSS 来设置滚动条的样式：
  ```css
  ::-webkit-scrollbar {
    width: 10px;
  }
  ::-webkit-scrollbar-thumb {
    background-color: blue;
  }
  ```
  `ScrollbarThemeFluent` 的测试确保了在 Fluent 主题下，即使设置了 CSS 样式，滚动条的尺寸计算 (例如 `ScrollbarThickness()`) 仍然是正确的，并且滑块的位置和大小也会根据 Fluent 主题的规则来计算。
* **HTML 触发：**  如果一个 `<div>` 元素的 CSS 设置了 `overflow: auto` 并且内容超出了 `<div>` 的边界，浏览器会显示滚动条。`ScrollbarThemeFluent` 的代码负责渲染这个滚动条的视觉外观。测试用例中的 `Scrollbar::CreateForTesting` 模拟了这种场景。
* **JavaScript 触发滚动：** 假设 JavaScript 代码通过 `element.scrollTop = 100;` 来滚动一个元素。`ScrollbarBackgroundInvalidationTest` 测试确保了当这种滚动发生时，Fluent 滚动条不会因为滑块位置变化而触发不必要的背景重绘，从而提高性能。

**逻辑推理、假设输入与输出：**

许多测试用例都基于对滚动条尺寸和位置的逻辑推理。以下是一个例子：

* **假设输入：**
    * 垂直滚动条
    * 滚动条长度 `kScrollbarLength = 200`
    * 距视口的偏移量 `kOffsetFromViewport = 100`
    * 设备像素比 `ScaleFromDIP() = 1.0f`
* **逻辑推理：**
    * 轨道矩形的 Y 坐标应该等于向上按钮的长度。
    * 轨道矩形的宽度应该等于滚动条的厚度。
    * 轨道矩形的高度应该是滚动条长度减去两个按钮的长度。
* **预期输出（对应 `VerticalScrollbarPartsSizes` 测试用例）：**
    * `track_rect` 应该等于 `gfx::Rect(100, theme_->ButtonLength(*vertical_scrollbar), ScrollbarThickness(), 200 - 2 * theme_->ButtonLength(*vertical_scrollbar))`

**用户或编程常见的使用错误：**

虽然这个文件是测试代码，但它间接反映了一些用户或开发者在使用滚动条时可能遇到的问题：

* **滚动条样式不一致：**  不同的浏览器或操作系统可能有不同的默认滚动条样式。Fluent 主题旨在提供一种跨平台的统一风格。如果开发者过度依赖 CSS 来自定义滚动条样式，可能会导致在不同平台上显示效果不一致。这个测试确保了 Fluent 主题的基础渲染是正确的，为一致性打下基础。
* **滚动性能问题：**  某些老旧的滚动条实现可能在滚动时触发大量的重绘，导致性能下降。`ScrollbarBackgroundInvalidationTest` 验证了 Fluent 滚动条在这方面的优化。
* **Overlay 滚动条显示问题：** Overlay 滚动条（不占用布局空间，覆盖在内容之上）的实现比传统滚动条更复杂。测试用例专门针对 Overlay 滚动条的尺寸和内边距计算，防止出现显示错误。

**用户操作如何一步步到达这里，作为调试线索：**

一个开发者可能会因为以下用户操作而需要调试到 `scrollbar_theme_fluent_unittest.cc` 相关的代码：

1. **用户报告滚动条显示异常：** 用户可能在特定的网站或应用中发现滚动条的尺寸不对劲、位置偏移、或者视觉样式错误（例如，滑块太小、按钮重叠等）。
2. **用户报告滚动性能问题：** 用户可能会感觉到在滚动某些内容时页面卡顿，开发者怀疑是滚动条的重绘导致了性能瓶颈。
3. **开发者启用或禁用了 Fluent 滚动条特性：** Chromium 中某些特性可以通过 flag 进行控制。开发者可能在测试启用或禁用 Fluent 滚动条特性后的效果，并发现了问题。
4. **开发者修改了与滚动条相关的代码：** 开发者可能修改了 `ScrollbarThemeFluent.cc` 或相关的代码，为了确保修改没有引入 bug，需要运行单元测试。

**作为调试线索，开发者可能会：**

* **查看用户使用的操作系统和浏览器版本：**  不同的平台可能有不同的滚动条默认行为。
* **检查相关的 CSS 样式：**  确认是否有 CSS 样式干扰了 Fluent 滚动条的渲染。
* **使用 Chromium 的开发者工具：**  检查元素的布局信息，查看滚动条的实际尺寸和位置。
* **运行相关的单元测试：**  例如 `scrollbar_theme_fluent_unittest`，来验证底层的滚动条渲染逻辑是否正确。
* **使用断点调试 `ScrollbarThemeFluent` 的代码：**  跟踪滚动条尺寸和位置的计算过程，找出错误的原因。

总而言之，`scrollbar_theme_fluent_unittest.cc` 是 Chromium 引擎中保证 Fluent 风格滚动条正确实现的关键组成部分，它通过各种测试用例覆盖了滚动条的渲染逻辑，与 Web 前端技术息息相关，并能帮助开发者诊断和解决与滚动条相关的各种问题。

Prompt: 
```
这是目录为blink/renderer/core/scroll/scrollbar_theme_fluent_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/scroll/scrollbar_theme_fluent.h"

#include <memory>

#include "base/gtest_prod_util.h"
#include "base/test/scoped_feature_list.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/scroll/scroll_types.h"
#include "third_party/blink/renderer/core/scroll/scrollbar.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_test_suite.h"
#include "third_party/blink/renderer/core/testing/scoped_mock_overlay_scrollbars.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/native_theme/native_theme_features.h"

namespace blink {

using ::testing::Return;

namespace {

// Const values for unit tests.
constexpr int kScrollbarLength = 200;
constexpr int kOffsetFromViewport = 100;

}  // namespace

class ScrollbarThemeFluentMock : public ScrollbarThemeFluent {
 public:
  int ButtonLength(const Scrollbar& scrollbar) const {
    gfx::Size size = ButtonSize(scrollbar);
    return scrollbar.Orientation() == kVerticalScrollbar ? size.height()
                                                         : size.width();
  }

  // Margin between the thumb and the edge of the scrollbars.
  int ThumbOffset(float scale_from_dip) const {
    int scrollbar_thumb_offset =
        (scrollbar_track_thickness() - scrollbar_thumb_thickness()) / 2;
    return base::ClampRound(scrollbar_thumb_offset * scale_from_dip);
  }

  int scrollbar_thumb_thickness() const { return scrollbar_thumb_thickness_; }
  int scrollbar_track_thickness() const { return scrollbar_track_thickness_; }
  int scrollbar_track_inset() const { return scrollbar_track_inset_; }

  using ScrollbarThemeFluent::ButtonSize;
  using ScrollbarThemeFluent::InsetButtonRect;
  using ScrollbarThemeFluent::InsetTrackRect;
  using ScrollbarThemeFluent::ScrollbarTrackInsetPx;
  using ScrollbarThemeFluent::ThumbRect;
  using ScrollbarThemeFluent::ThumbThickness;
  using ScrollbarThemeFluent::TrackRect;
};

class ScrollbarThemeFluentTest : public ::testing::TestWithParam<float> {
 protected:
  void SetUp() override {
    feature_list_.InitAndEnableFeature(::features::kFluentScrollbar);
    ScrollbarThemeSettings::SetFluentScrollbarsEnabled(true);
    mock_scrollable_area_ = MakeGarbageCollected<MockScrollableArea>(
        /*maximum_scroll_offset=*/ScrollOffset(0, 1000));
    mock_scrollable_area_->SetScaleFromDIP(GetParam());
    // ScrollbarThemeFluent Needs to be instantiated after feature flag and
    // scrollbar settings have been set.
    theme_ = std::make_unique<ScrollbarThemeFluentMock>();
  }

  void TearDown() override { theme_.reset(); }

  int TrackLength(const Scrollbar& scrollbar) const {
    return kScrollbarLength - 2 * theme_->ButtonLength(scrollbar);
  }

  int ScrollbarThickness() const {
    return theme_->ScrollbarThickness(ScaleFromDIP(), EScrollbarWidth::kAuto);
  }
  int ThumbThickness() const {
    return theme_->ThumbThickness(ScaleFromDIP(), EScrollbarWidth::kAuto);
  }
  int ThumbOffset() const { return theme_->ThumbOffset(ScaleFromDIP()); }
  int ScrollbarTrackInsetPx() const {
    return theme_->ScrollbarTrackInsetPx(ScaleFromDIP());
  }
  float ScaleFromDIP() const { return GetParam(); }

  Persistent<MockScrollableArea> mock_scrollable_area() const {
    return mock_scrollable_area_;
  }

  test::TaskEnvironment task_environment_;
  std::unique_ptr<ScrollbarThemeFluentMock> theme_;

 private:
  base::test::ScopedFeatureList feature_list_;
  Persistent<MockScrollableArea> mock_scrollable_area_;
};

class OverlayScrollbarThemeFluentTest : public ScrollbarThemeFluentTest {
 protected:
  void SetUp() override {
    ScrollbarThemeFluentTest::SetUp();
    feature_list_.InitAndEnableFeature(::features::kFluentOverlayScrollbar);
    // Re-instantiate ScrollbarThemeFluent with the overlay scrollbar flag on.
    theme_ = std::make_unique<ScrollbarThemeFluentMock>();
  }

 private:
  base::test::ScopedFeatureList feature_list_;
  ScopedMockOverlayScrollbars mock_overlay_scrollbar_;
};

// Test that the scrollbar's thickness scales appropriately with the thumb's
// thickness and always maintains proportion with the DIP scale.
TEST_P(ScrollbarThemeFluentTest, ScrollbarThicknessScalesProperly) {
  int scrollbar_thickness = ScrollbarThickness();
  int thumb_thickness = ThumbThickness();
  EXPECT_EQ((scrollbar_thickness - thumb_thickness) % 2, 0);
  EXPECT_EQ(theme_->scrollbar_track_thickness(),
            base::ClampRound(scrollbar_thickness / ScaleFromDIP()));
}

// Test that Scrollbar objects are correctly sized with Fluent theme parts.
TEST_P(ScrollbarThemeFluentTest, VerticalScrollbarPartsSizes) {
  Scrollbar* vertical_scrollbar = Scrollbar::CreateForTesting(
      mock_scrollable_area(), kVerticalScrollbar, &(theme_->GetInstance()));
  int scrollbar_thickness = ScrollbarThickness();
  vertical_scrollbar->SetFrameRect(
      gfx::Rect(kOffsetFromViewport, 0, scrollbar_thickness, kScrollbarLength));

  // Check that ThumbOffset() calculation is correct.
  EXPECT_EQ(ThumbThickness() + 2 * ThumbOffset(), scrollbar_thickness);

  const gfx::Rect track_rect = theme_->TrackRect(*vertical_scrollbar);
  EXPECT_EQ(
      track_rect,
      gfx::Rect(kOffsetFromViewport, theme_->ButtonLength(*vertical_scrollbar),
                scrollbar_thickness, TrackLength(*vertical_scrollbar)));

  const gfx::Rect thumb_rect = theme_->ThumbRect(*vertical_scrollbar);
  EXPECT_EQ(thumb_rect, gfx::Rect(kOffsetFromViewport + ThumbOffset(),
                                  theme_->ButtonLength(*vertical_scrollbar),
                                  ThumbThickness(),
                                  theme_->ThumbLength(*vertical_scrollbar)));

  const gfx::Size button_size = theme_->ButtonSize(*vertical_scrollbar);
  EXPECT_EQ(button_size, gfx::Size(scrollbar_thickness,
                                   theme_->ButtonLength(*vertical_scrollbar)));
}

// Test that Scrollbar objects are correctly sized with Fluent theme parts.
TEST_P(ScrollbarThemeFluentTest, HorizontalScrollbarPartsSizes) {
  Scrollbar* horizontal_scrollbar = Scrollbar::CreateForTesting(
      mock_scrollable_area(), kHorizontalScrollbar, &(theme_->GetInstance()));
  int scrollbar_thickness = ScrollbarThickness();
  horizontal_scrollbar->SetFrameRect(
      gfx::Rect(0, kOffsetFromViewport, kScrollbarLength, scrollbar_thickness));

  // Check that ThumbOffset() calculation is correct.
  EXPECT_EQ(ThumbThickness() + 2 * ThumbOffset(), scrollbar_thickness);

  const gfx::Rect track_rect = theme_->TrackRect(*horizontal_scrollbar);
  EXPECT_EQ(track_rect,
            gfx::Rect(theme_->ButtonLength(*horizontal_scrollbar),
                      kOffsetFromViewport, TrackLength(*horizontal_scrollbar),
                      scrollbar_thickness));

  const gfx::Rect thumb_rect = theme_->ThumbRect(*horizontal_scrollbar);
  EXPECT_EQ(thumb_rect, gfx::Rect(theme_->ButtonLength(*horizontal_scrollbar),
                                  kOffsetFromViewport + ThumbOffset(),
                                  theme_->ThumbLength(*horizontal_scrollbar),
                                  ThumbThickness()));

  const gfx::Size button_size = theme_->ButtonSize(*horizontal_scrollbar);
  EXPECT_EQ(button_size, gfx::Size(theme_->ButtonLength(*horizontal_scrollbar),
                                   scrollbar_thickness));
}

// The test verifies that the background paint is not invalidated when
// the thumb position changes. Aura scrollbars change arrow buttons color
// when the scroll offset changes from and to the min/max scroll offset.
// Fluent scrollbars do not change the arrow buttons color in this case.
TEST_P(ScrollbarThemeFluentTest, ScrollbarBackgroundInvalidationTest) {
  Scrollbar* scrollbar = Scrollbar::CreateForTesting(
      mock_scrollable_area(), kVerticalScrollbar, &(theme_->GetInstance()));
  ON_CALL(*mock_scrollable_area(), VerticalScrollbar())
      .WillByDefault(Return(scrollbar));

  scrollbar->SetFrameRect(
      gfx::Rect(0, 0, ScrollbarThickness(), kScrollbarLength));
  scrollbar->ClearTrackAndButtonsNeedRepaint();

  // Verifies that when the thumb position changes from min offset, the
  // background invalidation is not triggered.
  mock_scrollable_area()->SetScrollOffset(
      ScrollOffset(0, 10), mojom::blink::ScrollType::kCompositor);
  EXPECT_FALSE(scrollbar->TrackAndButtonsNeedRepaint());

  // Verifies that when the thumb position changes from a non-zero offset,
  // the background invalidation is not triggered.
  mock_scrollable_area()->SetScrollOffset(
      ScrollOffset(0, 20), mojom::blink::ScrollType::kCompositor);
  EXPECT_FALSE(scrollbar->TrackAndButtonsNeedRepaint());

  // Verifies that when the thumb position changes back to 0 (min) offset,
  // the background invalidation is not triggered.
  mock_scrollable_area()->SetScrollOffset(
      ScrollOffset(0, 0), mojom::blink::ScrollType::kCompositor);
  EXPECT_FALSE(scrollbar->TrackAndButtonsNeedRepaint());
}

// Test that Scrollbar objects are correctly sized with Overlay Fluent theme
// parts.
TEST_P(OverlayScrollbarThemeFluentTest, OverlaySetsCorrectTrackAndInsetSize) {
  // Some OSes keep fluent scrollbars disabled even if the feature flag is set
  // to enable them.
  if (!ui::IsFluentScrollbarEnabled()) {
    EXPECT_FALSE(theme_->UsesOverlayScrollbars());
    return;
  }

  EXPECT_TRUE(theme_->UsesOverlayScrollbars());
  Scrollbar* horizontal_scrollbar = Scrollbar::CreateForTesting(
      mock_scrollable_area(), kHorizontalScrollbar, &(theme_->GetInstance()));
  int scrollbar_thickness = ScrollbarThickness();
  horizontal_scrollbar->SetFrameRect(
      gfx::Rect(0, kOffsetFromViewport, kScrollbarLength, scrollbar_thickness));

  // Check that ThumbOffset() calculation is correct.
  EXPECT_EQ(ThumbThickness() + 2 * ThumbOffset(), scrollbar_thickness);

  const gfx::Rect track_rect = theme_->TrackRect(*horizontal_scrollbar);
  EXPECT_EQ(track_rect,
            gfx::Rect(theme_->ButtonLength(*horizontal_scrollbar),
                      kOffsetFromViewport, TrackLength(*horizontal_scrollbar),
                      scrollbar_thickness));
}

// Same as ScrollbarThemeFluentTest.ScrollbarThicknessScalesProperly, but for
// Overlay Scrollbars.
TEST_P(OverlayScrollbarThemeFluentTest, ScrollbarThicknessScalesProperly) {
  int scrollbar_thickness = ScrollbarThickness();
  int thumb_thickness = ThumbThickness();
  EXPECT_EQ((scrollbar_thickness - thumb_thickness) % 2, 0);
  EXPECT_EQ(theme_->scrollbar_track_thickness(),
            base::ClampRound(scrollbar_thickness / ScaleFromDIP()));
}

TEST_P(OverlayScrollbarThemeFluentTest, TestVerticalInsetTrackRect) {
  int scrollbar_thickness = ScrollbarThickness();
  Scrollbar* vertical_scrollbar = Scrollbar::CreateForTesting(
      mock_scrollable_area(), kVerticalScrollbar, &(theme_->GetInstance()));
  vertical_scrollbar->SetFrameRect(
      gfx::Rect(kOffsetFromViewport, 0, scrollbar_thickness, kScrollbarLength));
  gfx::Rect track_rect(kOffsetFromViewport, 0, scrollbar_thickness,
                       kScrollbarLength);

  // Vertical scrollbars should be inset from the left and right.
  gfx::Rect expected_rect(kOffsetFromViewport + ScrollbarTrackInsetPx(), 0,
                          scrollbar_thickness - 2 * ScrollbarTrackInsetPx(),
                          kScrollbarLength);
  EXPECT_EQ(expected_rect,
            theme_->InsetTrackRect(*vertical_scrollbar, track_rect));
}

TEST_P(OverlayScrollbarThemeFluentTest, TestHorizontalInsetTrackRect) {
  int scrollbar_thickness = ScrollbarThickness();
  Scrollbar* horizontal_scrollbar = Scrollbar::CreateForTesting(
      mock_scrollable_area(), kHorizontalScrollbar, &(theme_->GetInstance()));
  horizontal_scrollbar->SetFrameRect(
      gfx::Rect(0, kOffsetFromViewport, kScrollbarLength, scrollbar_thickness));
  gfx::Rect track_rect(0, kOffsetFromViewport, kScrollbarLength,
                       scrollbar_thickness);

  // Horizontal scrollbars should be inset from the top and the bottom.
  gfx::Rect expected_rect(0, kOffsetFromViewport + ScrollbarTrackInsetPx(),
                          kScrollbarLength,
                          scrollbar_thickness - 2 * ScrollbarTrackInsetPx());
  EXPECT_EQ(expected_rect,
            theme_->InsetTrackRect(*horizontal_scrollbar, track_rect));
}

TEST_P(OverlayScrollbarThemeFluentTest, TestVerticalInsetButtonRect) {
  int scrollbar_thickness = ScrollbarThickness();
  Scrollbar* vertical_scrollbar = Scrollbar::CreateForTesting(
      mock_scrollable_area(), kVerticalScrollbar, &(theme_->GetInstance()));
  vertical_scrollbar->SetFrameRect(
      gfx::Rect(kOffsetFromViewport, 0, scrollbar_thickness, kScrollbarLength));
  int inset = ScrollbarTrackInsetPx();
  int button_length = theme_->ButtonLength(*vertical_scrollbar);
  gfx::Rect button_rect(0, 0, scrollbar_thickness, button_length);

  // Up arrow button should be inset from every part except the bottom.
  gfx::Rect expected_up_rect(inset, inset, scrollbar_thickness - inset * 2,
                             button_length - inset);
  EXPECT_EQ(expected_up_rect,
            theme_->InsetButtonRect(*vertical_scrollbar, button_rect,
                                    kBackButtonStartPart));
  // Down arrow button should be inset from every part except the top.
  gfx::Rect expected_down_rect(inset, 0, scrollbar_thickness - inset * 2,
                               button_length - inset);
  EXPECT_EQ(expected_down_rect,
            theme_->InsetButtonRect(*vertical_scrollbar, button_rect,
                                    kForwardButtonStartPart));
}

TEST_P(OverlayScrollbarThemeFluentTest, TestHorizontalInsetButtonRect) {
  int scrollbar_thickness = ScrollbarThickness();
  Scrollbar* horizontal_scrollbar = Scrollbar::CreateForTesting(
      mock_scrollable_area(), kHorizontalScrollbar, &(theme_->GetInstance()));
  horizontal_scrollbar->SetFrameRect(
      gfx::Rect(0, kOffsetFromViewport, kScrollbarLength, scrollbar_thickness));
  int inset = ScrollbarTrackInsetPx();
  int button_length = theme_->ButtonLength(*horizontal_scrollbar);
  gfx::Rect button_rect(0, 0, button_length, scrollbar_thickness);

  // Left arrow button should be inset from every part except the right.
  gfx::Rect expected_left_rect(inset, inset, button_length - inset,
                               scrollbar_thickness - inset * 2);
  EXPECT_EQ(expected_left_rect,
            theme_->InsetButtonRect(*horizontal_scrollbar, button_rect,
                                    kBackButtonStartPart));
  // Right arrow button should be inset from every part except the left.
  gfx::Rect expected_right_rect(0, inset, button_length - inset,
                                scrollbar_thickness - inset * 2);
  EXPECT_EQ(expected_right_rect,
            theme_->InsetButtonRect(*horizontal_scrollbar, button_rect,
                                    kForwardButtonStartPart));
}

INSTANTIATE_TEST_SUITE_P(All,
                         ScrollbarThemeFluentTest,
                         ::testing::Values(1.f, 1.25f, 1.5f, 1.75f, 2.f));
INSTANTIATE_TEST_SUITE_P(All,
                         OverlayScrollbarThemeFluentTest,
                         ::testing::Values(1.f, 1.25f, 1.5f, 1.75f, 2.f));

}  // namespace blink

"""

```