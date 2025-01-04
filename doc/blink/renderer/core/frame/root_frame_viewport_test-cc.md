Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The file name `root_frame_viewport_test.cc` immediately suggests it's a test file specifically for the `RootFrameViewport` class. The `#include` statements confirm this, particularly the inclusion of `root_frame_viewport.h`. The `testing/gtest/include/gtest/gtest.h` header strongly indicates unit tests.

2. **Understand the Class Under Test:** The `RootFrameViewport` is likely a crucial class in Blink's rendering pipeline, managing the overall viewport of the main frame. It probably interacts with concepts like scrolling, zooming (page scale), and how different parts of the content are displayed.

3. **Examine Included Headers:**  The included headers provide valuable clues about the functionality being tested:
    * `base/task/single_thread_task_runner.h`:  Indicates asynchronous operations and task management.
    * `third_party/blink/public/mojom/scroll/scroll_into_view_params.mojom-blink.h`: Deals with the "scroll into view" functionality. `mojom` suggests an interface definition language, likely for inter-process communication.
    * `third_party/blink/public/platform/platform.h`:  Platform-specific abstractions.
    * `third_party/blink/public/platform/scheduler/...`: Hints at thread management and scheduling.
    * `third_party/blink/renderer/core/frame/visual_viewport.h`: Directly related to the visual viewport, a key component interacting with `RootFrameViewport`.
    * `third_party/blink/renderer/core/scroll/...`:  Various classes related to scrolling mechanics.
    * `third_party/blink/renderer/core/testing/...`:  Testing utilities within Blink.
    * `ui/gfx/geometry/...`:  Geometric data structures like points, sizes, and rectangles.

4. **Analyze the Test Structure:** The file uses Google Test (gtest). Key elements are:
    * `namespace blink { ... }`:  The code resides within the `blink` namespace.
    * Stub Classes (`ScrollableAreaStub`, `RootLayoutViewportStub`, `VisualViewportStub`): These are mock implementations of related classes. They allow testing `RootFrameViewport` in isolation without relying on the full complexity of the real implementations. Note the inheritance relationships between these stubs.
    * Test Fixtures (`RootFrameViewportTest`, `RootFrameViewportRenderTest`): These classes group related tests and provide setup/teardown logic (though in this case, `SetUp` is empty).
    * `TEST_F(FixtureName, TestName) { ... }`:  The individual test cases.

5. **Deconstruct Individual Tests:** For each `TEST_F`, try to understand its purpose:
    * **`UserInputScrollable`:**  Focuses on how `RootFrameViewport` behaves when the layout viewport's scrollability is restricted (like `overflow: hidden`). It checks if the visual viewport can still scroll independently.
    * **`TestScrollAnimatorUpdatedBeforeScroll`:**  Verifies that internal scroll state is correctly updated before an actual scroll operation, preventing incorrect behavior.
    * **`ScrollIntoView`:**  Tests the `ScrollIntoView` functionality, ensuring elements are correctly scrolled into the visible area, considering scaling and viewport size changes.
    * **`SetScrollOffset`:** Examines how `RootFrameViewport` handles setting the scroll offset, ensuring it propagates correctly to the visual and layout viewports.
    * **`VisibleContentRect`:** Checks if the visible content rectangle is calculated accurately, considering both viewports and scaling.
    * **`ViewportScrollOrder`:**  Confirms the order in which the visual and layout viewports are scrolled.
    * **`SetAlternateLayoutViewport`:** Tests the ability to switch the underlying layout viewport.
    * **`DistributeScrollOrder`:**  Examines the scroll distribution when explicitly using `DistributeScrollBetweenViewports`.
    * **`ApplyPendingHistoryRestoreScrollOffsetTwice`:**  (In `RootFrameViewportRenderTest`) Tests a specific scenario related to history restoration and page scaling.

6. **Identify Relationships with Web Technologies:**  As you analyze the tests, think about how the tested functionality maps to web development concepts:
    * **JavaScript:**  JavaScript can trigger scrolling using methods like `scrollTo()`, `scrollBy()`, and `scrollIntoView()`. The tests for `ScrollIntoView` and `SetScrollOffset` are directly relevant here.
    * **HTML:** The structure of the HTML document determines the scrollable content. The tests implicitly deal with how the `RootFrameViewport` manages the scrolling of this content.
    * **CSS:**  CSS properties like `overflow`, `zoom`, and viewport meta tags directly influence the behavior of the viewport. The `UserInputScrollable` test specifically addresses the `overflow: hidden` case. The scaling factor tested relates to CSS zoom or the viewport meta tag.

7. **Infer Logic and Assumptions:**  The tests make certain assumptions about how the `RootFrameViewport` should behave. For example, when scaling is involved, scrolling needs to be adjusted accordingly. The tests with `SetUserInputScrollable` assume that disabling scrollability on one viewport shouldn't completely prevent scrolling if the other is still scrollable.

8. **Identify Potential User/Programming Errors:**  Consider how a developer might misuse or misunderstand the viewport concepts:
    * Incorrectly assuming the layout viewport and visual viewport are always synchronized.
    * Not accounting for page scaling when calculating scroll offsets.
    * Problems with `overflow: hidden` and unexpected scrolling behavior.
    * Issues when trying to restore scroll positions from history.

9. **Structure the Output:** Organize the findings into clear categories (Functionality, Relationship to Web Technologies, Logic/Assumptions, Common Errors) with specific examples from the code.

10. **Refine and Review:**  Read through the analysis, ensuring clarity, accuracy, and completeness. Check if all parts of the request are addressed. For instance, ensure assumptions and input/output examples are provided where logical reasoning is involved.

By following these steps, you can effectively analyze a C++ test file like this and extract the relevant information, even without being an expert in the specific codebase. The key is to use the available clues (file names, includes, test structure) and connect them to broader software engineering and web development concepts.
这个C++源代码文件 `root_frame_viewport_test.cc` 是 Chromium Blink 引擎中的一个单元测试文件，专门用于测试 `blink::RootFrameViewport` 类的功能。 `RootFrameViewport` 类在 Blink 渲染引擎中扮演着管理主框架视口的关键角色，它协调着布局视口 (layout viewport) 和视觉视口 (visual viewport) 的行为。

以下是该文件测试的主要功能及其与 JavaScript、HTML、CSS 的关系，以及逻辑推理和常见错误的示例：

**文件功能列表:**

1. **视口滚动管理 (Viewport Scrolling Management):**
   - 测试当布局视口不可滚动时（例如，设置了 `overflow:hidden`），视觉视口是否能够独立滚动。
   - 测试用户触发的滚动 (`UserScroll`) 和程序触发的滚动 (`SetScrollOffset`) 是否正确地作用于视觉视口和布局视口。
   - 测试滚动动画器 (scroll animator) 的状态是否在滚动操作前正确更新。
   - 测试 `ScrollIntoView` 功能，确保元素能够正确滚动到视口中央或边缘，并考虑到页面缩放。
   - 测试 `SetScrollOffset` 方法是否能正确地设置视觉视口和布局视口的滚动偏移。
   - 测试获取可视内容矩形 (`VisibleContentRect`) 的功能，确保它能正确反映视觉视口的大小和位置，并考虑页面缩放。
   - 测试滚动事件的执行顺序，确保视觉视口在布局视口之前滚动。
   - 测试设置备用布局视口 (`SetAlternateLayoutViewport`) 的功能，确保滚动操作会作用于备用的布局视口。
   - 测试直接调用 `DistributeScrollBetweenViewports` 方法时的滚动顺序。

2. **历史记录恢复 (History Restoration):**
   - 测试在历史记录恢复时设置滚动偏移和页面缩放的功能，并确保重复调用不会产生错误。

**与 JavaScript, HTML, CSS 的关系:**

`RootFrameViewport` 的功能直接影响到网页的滚动和缩放行为，这些行为通常可以通过 JavaScript、HTML 和 CSS 来控制：

* **JavaScript:**
    * **`window.scrollTo(x, y)` 或 `element.scrollTo(x, y)`:**  `SetScrollOffset` 测试模拟了 JavaScript 代码设置滚动偏移的行为。
        * **假设输入:** JavaScript 调用 `window.scrollTo(100, 200)`。
        * **预期输出:** `RootFrameViewport` 会将视觉视口和/或布局视口的滚动偏移设置为 (100, 200)，具体取决于当前的缩放和视口状态。
    * **`element.scrollIntoView()`:** `ScrollIntoView` 测试模拟了 JavaScript 调用 `scrollIntoView()` 方法将元素滚动到可见区域的行为。
        * **假设输入:** JavaScript 调用 `document.getElementById('myElement').scrollIntoView()`。
        * **预期输出:** `RootFrameViewport` 会计算必要的滚动偏移，使 'myElement' 可见，并相应地滚动视觉视口和布局视口。
    * **事件监听 (例如 `scroll` 事件):** 虽然这个测试文件没有直接测试事件，但 `RootFrameViewport` 的滚动行为会触发 `scroll` 事件，JavaScript 可以监听这些事件来执行自定义操作。

* **HTML:**
    * **`<html>` 元素的滚动:**  `RootFrameViewport` 管理着主框架的滚动，这直接对应于 HTML 文档的滚动。
    * **`<iframe>` 元素的嵌套:** 虽然这个测试文件主要关注主框架，但视口的管理也与 `<iframe>` 元素的滚动相关。

* **CSS:**
    * **`overflow: auto`, `overflow: scroll`, `overflow: hidden`:** `UserInputScrollable` 测试直接关联到 CSS 的 `overflow` 属性。当一个元素的 `overflow` 设置为 `hidden` 时，它的内容溢出不会产生滚动条。这个测试验证了在这种情况下，视觉视口是否仍然可以滚动。
        * **假设输入:** CSS 设置 `body { overflow: hidden; }`。
        * **预期输出:**  `RootFrameViewport` 检测到布局视口不可水平滚动，但视觉视口仍然可以响应用户的滚动操作。
    * **`zoom` 属性或 viewport meta tag:** `ScrollIntoView` 和 `VisibleContentRect` 测试考虑了页面缩放的影响。CSS 的 `zoom` 属性或者 HTML 的 `<meta name="viewport" content="initial-scale=...">` 标签会影响页面的缩放级别，`RootFrameViewport` 需要正确处理这些缩放。
        * **假设输入:** HTML 中设置 `<meta name="viewport" content="initial-scale=2.0">` 或 CSS 设置 `body { zoom: 2.0; }`。
        * **预期输出:** `RootFrameViewport` 在计算滚动偏移和可视区域时，会将缩放因子考虑在内，确保在缩放后的页面上元素能正确滚动到视图中。

**逻辑推理和假设输入/输出:**

* **假设输入 (UserInputScrollable 测试):**
    * 布局视口的大小为 100x150，内容大小为 200x300。
    * 视觉视口的大小为 100x150。
    * 页面缩放为 2。
    * 布局视口的水平滚动被禁用 (`layout_viewport->SetUserInputScrollable(false, true)`).
    * 用户尝试水平滚动 300 像素。
* **预期输出 (UserInputScrollable 测试):**
    * 布局视口的水平滚动偏移保持为 0，因为它被禁用。
    * 视觉视口的水平滚动偏移变为 50 (因为缩放为 2，300 像素的页面内容对应 150 像素的视觉视口滚动，但视口宽度只有 100，所以最大滚动 50)。
    * `RootFrameViewport` 的水平滚动偏移也为 50。

* **假设输入 (ScrollIntoView 测试):**
    * 布局视口大小 100x150，内容大小 200x300。
    * 视觉视口大小 100x100，页面缩放 2。
    * 需要滚动到文档坐标 (50, 75) 大小为 50x75 的矩形。
* **预期输出 (ScrollIntoView 测试):**
    * 视觉视口的滚动偏移会变为 (50, 75)，使得目标矩形在视觉视口中居中或可见。
    * 布局视口的滚动偏移会保持不变，因为目标矩形在未缩放的布局视口中是可见的。

**涉及用户或编程常见的使用错误:**

1. **假设布局视口和视觉视口总是同步滚动:** 开发者可能会错误地认为设置一个视口的滚动偏移会自动影响另一个视口。例如，在设置了页面缩放的情况下，直接设置布局视口的滚动偏移可能不会得到预期的视觉效果，因为视觉视口有自己的滚动偏移。`RootFrameViewport` 负责协调这两个视口，但理解它们的独立性很重要。

2. **未考虑页面缩放的影响:**  在进行滚动操作或计算可视区域时，如果没有考虑到页面缩放，可能会导致计算错误，例如将元素错误地滚动到视口外。`ScrollIntoView` 测试中就包含了对缩放场景的测试。

3. **错误地假设 `overflow: hidden` 完全阻止滚动:** 开发者可能认为设置了 `overflow: hidden` 的元素就完全无法滚动。但 `RootFrameViewport` 的测试表明，即使布局视口设置了 `overflow: hidden`，视觉视口仍然可以滚动，这在某些高级滚动效果中可能会被用到。

4. **在历史记录恢复时处理滚动位置的错误:**  浏览器在前进/后退时需要恢复之前的滚动位置和页面缩放。如果 `RootFrameViewport` 的历史记录恢复逻辑有误，可能会导致页面跳转后滚动位置不正确。 `ApplyPendingHistoryRestoreScrollOffsetTwice` 测试覆盖了这方面的场景，确保重复应用历史记录恢复不会导致问题。

总而言之，`root_frame_viewport_test.cc` 文件通过一系列单元测试，细致地验证了 `RootFrameViewport` 类的各种功能，确保 Blink 引擎能够正确地管理和协调布局视口和视觉视口，从而为用户提供流畅和一致的网页浏览体验。 这些测试覆盖了与 JavaScript、HTML 和 CSS 相关的关键场景，帮助开发者避免常见的与视口管理相关的错误。

Prompt: 
```
这是目录为blink/renderer/core/frame/root_frame_viewport_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/root_frame_viewport.h"

#include "base/task/single_thread_task_runner.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/scroll/scroll_into_view_params.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/scroll/scroll_alignment.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/core/scroll/scroll_types.h"
#include "third_party/blink/renderer/core/scroll/scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme_overlay_mock.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "ui/gfx/geometry/point_conversions.h"
#include "ui/gfx/geometry/size_conversions.h"
#include "ui/gfx/geometry/vector2d_conversions.h"

namespace blink {

class ScrollableAreaStub : public GarbageCollected<ScrollableAreaStub>,
                           public ScrollableArea {
 public:
  ScrollableAreaStub(const gfx::Size& viewport_size,
                     const gfx::Size& contents_size)
      : ScrollableArea(blink::scheduler::GetSingleThreadTaskRunnerForTesting()),
        user_input_scrollable_x_(true),
        user_input_scrollable_y_(true),
        viewport_size_(viewport_size),
        contents_size_(contents_size),
        timer_task_runner_(
            blink::scheduler::GetSingleThreadTaskRunnerForTesting()) {}

  void SetViewportSize(const gfx::Size& viewport_size) {
    viewport_size_ = viewport_size;
  }

  gfx::Size ViewportSize() const { return viewport_size_; }

  // ScrollableArea Impl
  int ScrollSize(ScrollbarOrientation orientation) const override {
    gfx::Vector2d scroll_dimensions =
        MaximumScrollOffsetInt() - MinimumScrollOffsetInt();

    return (orientation == kHorizontalScrollbar) ? scroll_dimensions.x()
                                                 : scroll_dimensions.y();
  }

  void SetUserInputScrollable(bool x, bool y) {
    user_input_scrollable_x_ = x;
    user_input_scrollable_y_ = y;
  }

  gfx::Vector2d ScrollOffsetInt() const override {
    return SnapScrollOffsetToPhysicalPixels(scroll_offset_);
  }
  ScrollOffset GetScrollOffset() const override { return scroll_offset_; }
  gfx::Vector2d MinimumScrollOffsetInt() const override {
    return gfx::Vector2d();
  }
  ScrollOffset MinimumScrollOffset() const override { return ScrollOffset(); }
  gfx::Vector2d MaximumScrollOffsetInt() const override {
    return gfx::ToFlooredVector2d(MaximumScrollOffset());
  }

  gfx::Rect VisibleContentRect(
      IncludeScrollbarsInRect = kExcludeScrollbars) const override {
    return gfx::Rect(
        gfx::ToFlooredPoint(gfx::PointAtOffsetFromOrigin(scroll_offset_)),
        viewport_size_);
  }

  gfx::Size ContentsSize() const override { return contents_size_; }
  void SetContentSize(const gfx::Size& contents_size) {
    contents_size_ = contents_size;
  }

  scoped_refptr<base::SingleThreadTaskRunner> GetTimerTaskRunner() const final {
    return timer_task_runner_;
  }

  ScrollbarTheme& GetPageScrollbarTheme() const override {
    DEFINE_STATIC_LOCAL(ScrollbarThemeOverlayMock, theme, ());
    return theme;
  }
  bool ScrollAnimatorEnabled() const override { return true; }

  void Trace(Visitor* visitor) const override {
    ScrollableArea::Trace(visitor);
  }

 protected:
  CompositorElementId GetScrollElementId() const override {
    return CompositorElementId();
  }
  void UpdateScrollOffset(const ScrollOffset& offset,
                          mojom::blink::ScrollType) override {
    scroll_offset_ = offset;
  }
  bool ShouldUseIntegerScrollOffset() const override { return true; }
  bool IsThrottled() const override { return false; }
  bool IsActive() const override { return true; }
  bool IsScrollCornerVisible() const override { return true; }
  gfx::Rect ScrollCornerRect() const override { return gfx::Rect(); }
  bool ScrollbarsCanBeActive() const override { return true; }
  bool ShouldPlaceVerticalScrollbarOnLeft() const override { return true; }
  void ScrollControlWasSetNeedsPaintInvalidation() override {}
  bool UsesCompositedScrolling() const override { NOTREACHED(); }
  bool UserInputScrollable(ScrollbarOrientation orientation) const override {
    return orientation == kHorizontalScrollbar ? user_input_scrollable_x_
                                               : user_input_scrollable_y_;
  }
  bool ScheduleAnimation() override { return true; }
  mojom::blink::ColorScheme UsedColorSchemeScrollbars() const override {
    return mojom::blink::ColorScheme::kLight;
  }

  ScrollOffset ClampedScrollOffset(const ScrollOffset& offset) {
    ScrollOffset min_offset = MinimumScrollOffset();
    ScrollOffset max_offset = MaximumScrollOffset();
    float width =
        std::min(std::max(offset.x(), min_offset.x()), max_offset.x());
    float height =
        std::min(std::max(offset.y(), min_offset.y()), max_offset.y());
    return ScrollOffset(width, height);
  }

  bool user_input_scrollable_x_;
  bool user_input_scrollable_y_;
  ScrollOffset scroll_offset_;
  gfx::Size viewport_size_;
  gfx::Size contents_size_;
  scoped_refptr<base::SingleThreadTaskRunner> timer_task_runner_;
};

class RootLayoutViewportStub : public ScrollableAreaStub {
 public:
  RootLayoutViewportStub(const gfx::Size& viewport_size,
                         const gfx::Size& contents_size)
      : ScrollableAreaStub(viewport_size, contents_size) {}

  ScrollOffset MaximumScrollOffset() const override {
    gfx::Size diff = ContentsSize() - ViewportSize();
    return ScrollOffset(diff.width(), diff.height());
  }

  PhysicalRect DocumentToFrame(const PhysicalRect& rect) const {
    PhysicalRect ret = rect;
    ret.Move(-PhysicalOffset::FromVector2dFRound(GetScrollOffset()));
    return ret;
  }

  PhysicalOffset LocalToScrollOriginOffset() const override { return {}; }

 private:
  int VisibleWidth() const override { return viewport_size_.width(); }
  int VisibleHeight() const override { return viewport_size_.height(); }
};

class VisualViewportStub : public ScrollableAreaStub {
 public:
  VisualViewportStub(const gfx::Size& viewport_size,
                     const gfx::Size& contents_size)
      : ScrollableAreaStub(viewport_size, contents_size), scale_(1) {}

  ScrollOffset MaximumScrollOffset() const override {
    gfx::Size diff =
        ContentsSize() - gfx::ScaleToFlooredSize(ViewportSize(), 1 / scale_);
    return ScrollOffset(diff.width(), diff.height());
  }

  PhysicalOffset LocalToScrollOriginOffset() const override { return {}; }

  void SetScale(float scale) { scale_ = scale; }

 private:
  int VisibleWidth() const override { return viewport_size_.width() / scale_; }
  int VisibleHeight() const override {
    return viewport_size_.height() / scale_;
  }
  gfx::Rect VisibleContentRect(IncludeScrollbarsInRect) const override {
    return gfx::Rect(gfx::ToFlooredPoint(ScrollPosition()),
                     gfx::ToCeiledSize(gfx::ScaleSize(
                         gfx::SizeF(viewport_size_), 1 / scale_)));
  }

  float scale_;
};

class RootFrameViewportTest : public testing::Test {
 public:
  RootFrameViewportTest() = default;

 protected:
  void SetUp() override {}

 private:
  test::TaskEnvironment task_environment_;
};

// Tests that scrolling the viewport when the layout viewport is
// !userInputScrollable (as happens when overflow:hidden is set) works
// correctly, that is, the visual viewport can scroll, but not the layout.
TEST_F(RootFrameViewportTest, UserInputScrollable) {
  gfx::Size viewport_size(100, 150);
  auto* layout_viewport = MakeGarbageCollected<RootLayoutViewportStub>(
      viewport_size, gfx::Size(200, 300));
  auto* visual_viewport =
      MakeGarbageCollected<VisualViewportStub>(viewport_size, viewport_size);

  auto* root_frame_viewport = MakeGarbageCollected<RootFrameViewport>(
      *visual_viewport, *layout_viewport);

  visual_viewport->SetScale(2);

  // Disable just the layout viewport's horizontal scrolling, the
  // RootFrameViewport should remain scrollable overall.
  layout_viewport->SetUserInputScrollable(false, true);
  visual_viewport->SetUserInputScrollable(true, true);

  EXPECT_TRUE(root_frame_viewport->UserInputScrollable(kHorizontalScrollbar));
  EXPECT_TRUE(root_frame_viewport->UserInputScrollable(kVerticalScrollbar));

  // Layout viewport shouldn't scroll since it's not horizontally scrollable,
  // but visual viewport should.
  root_frame_viewport->UserScroll(ui::ScrollGranularity::kScrollByPrecisePixel,
                                  ScrollOffset(300, 0),
                                  ScrollableArea::ScrollCallback());
  EXPECT_EQ(ScrollOffset(0, 0), layout_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(50, 0), visual_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(50, 0), root_frame_viewport->GetScrollOffset());

  // Vertical scrolling should be unaffected.
  root_frame_viewport->UserScroll(ui::ScrollGranularity::kScrollByPrecisePixel,
                                  ScrollOffset(0, 300),
                                  ScrollableArea::ScrollCallback());
  EXPECT_EQ(ScrollOffset(0, 150), layout_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(50, 75), visual_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(50, 225), root_frame_viewport->GetScrollOffset());

  // Try the same checks as above but for the vertical direction.
  // ===============================================

  root_frame_viewport->SetScrollOffset(
      ScrollOffset(), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kInstant, ScrollableArea::ScrollCallback());

  // Disable just the layout viewport's vertical scrolling, the
  // RootFrameViewport should remain scrollable overall.
  layout_viewport->SetUserInputScrollable(true, false);
  visual_viewport->SetUserInputScrollable(true, true);

  EXPECT_TRUE(root_frame_viewport->UserInputScrollable(kHorizontalScrollbar));
  EXPECT_TRUE(root_frame_viewport->UserInputScrollable(kVerticalScrollbar));

  // Layout viewport shouldn't scroll since it's not vertically scrollable,
  // but visual viewport should.
  root_frame_viewport->UserScroll(ui::ScrollGranularity::kScrollByPrecisePixel,
                                  ScrollOffset(0, 300),
                                  ScrollableArea::ScrollCallback());
  EXPECT_EQ(ScrollOffset(0, 0), layout_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(0, 75), visual_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(0, 75), root_frame_viewport->GetScrollOffset());

  // Horizontal scrolling should be unaffected.
  root_frame_viewport->UserScroll(ui::ScrollGranularity::kScrollByPrecisePixel,
                                  ScrollOffset(300, 0),
                                  ScrollableArea::ScrollCallback());
  EXPECT_EQ(ScrollOffset(100, 0), layout_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(50, 75), visual_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(150, 75), root_frame_viewport->GetScrollOffset());
}

// Make sure scrolls using the scroll animator (scroll(), setScrollOffset())
// work correctly when one of the subviewports is explicitly scrolled without
// using the // RootFrameViewport interface.
TEST_F(RootFrameViewportTest, TestScrollAnimatorUpdatedBeforeScroll) {
  gfx::Size viewport_size(100, 150);
  auto* layout_viewport = MakeGarbageCollected<RootLayoutViewportStub>(
      viewport_size, gfx::Size(200, 300));
  auto* visual_viewport =
      MakeGarbageCollected<VisualViewportStub>(viewport_size, viewport_size);

  auto* root_frame_viewport = MakeGarbageCollected<RootFrameViewport>(
      *visual_viewport, *layout_viewport);

  visual_viewport->SetScale(2);

  visual_viewport->SetScrollOffset(ScrollOffset(50, 75),
                                   mojom::blink::ScrollType::kProgrammatic);
  EXPECT_EQ(ScrollOffset(50, 75), root_frame_viewport->GetScrollOffset());

  // If the scroll animator doesn't update, it will still think it's at (0, 0)
  // and so it may early exit.
  root_frame_viewport->SetScrollOffset(
      ScrollOffset(0, 0), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kInstant, ScrollableArea::ScrollCallback());
  EXPECT_EQ(ScrollOffset(0, 0), root_frame_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(0, 0), visual_viewport->GetScrollOffset());

  // Try again for userScroll()
  visual_viewport->SetScrollOffset(ScrollOffset(50, 75),
                                   mojom::blink::ScrollType::kProgrammatic);
  EXPECT_EQ(ScrollOffset(50, 75), root_frame_viewport->GetScrollOffset());

  root_frame_viewport->UserScroll(ui::ScrollGranularity::kScrollByPrecisePixel,
                                  ScrollOffset(-50, 0),
                                  ScrollableArea::ScrollCallback());
  EXPECT_EQ(ScrollOffset(0, 75), root_frame_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(0, 75), visual_viewport->GetScrollOffset());

  // Make sure the layout viewport is also accounted for.
  root_frame_viewport->SetScrollOffset(
      ScrollOffset(0, 0), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kInstant, ScrollableArea::ScrollCallback());
  layout_viewport->SetScrollOffset(ScrollOffset(100, 150),
                                   mojom::blink::ScrollType::kProgrammatic);
  EXPECT_EQ(ScrollOffset(100, 150), root_frame_viewport->GetScrollOffset());

  root_frame_viewport->UserScroll(ui::ScrollGranularity::kScrollByPrecisePixel,
                                  ScrollOffset(-100, 0),
                                  ScrollableArea::ScrollCallback());
  EXPECT_EQ(ScrollOffset(0, 150), root_frame_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(0, 150), layout_viewport->GetScrollOffset());
}

// Test that the scrollIntoView correctly scrolls the main frame
// and visual viewport such that the given rect is centered in the viewport.
TEST_F(RootFrameViewportTest, ScrollIntoView) {
  gfx::Size viewport_size(100, 150);
  auto* layout_viewport = MakeGarbageCollected<RootLayoutViewportStub>(
      viewport_size, gfx::Size(200, 300));
  auto* visual_viewport =
      MakeGarbageCollected<VisualViewportStub>(viewport_size, viewport_size);

  auto* root_frame_viewport = MakeGarbageCollected<RootFrameViewport>(
      *visual_viewport, *layout_viewport);

  // Test that the visual viewport is scrolled if the viewport has been
  // resized (as is the case when the ChromeOS keyboard comes up) but not
  // scaled.
  visual_viewport->SetViewportSize(gfx::Size(100, 100));
  root_frame_viewport->ScrollIntoView(
      layout_viewport->DocumentToFrame(PhysicalRect(100, 250, 50, 50)),
      PhysicalBoxStrut(),
      scroll_into_view_util::CreateScrollIntoViewParams(
          ScrollAlignment::ToEdgeIfNeeded(), ScrollAlignment::ToEdgeIfNeeded(),
          mojom::blink::ScrollType::kProgrammatic, true,
          mojom::blink::ScrollBehavior::kInstant));
  EXPECT_EQ(ScrollOffset(50, 150), layout_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(0, 50), visual_viewport->GetScrollOffset());

  root_frame_viewport->ScrollIntoView(
      layout_viewport->DocumentToFrame(PhysicalRect(25, 75, 50, 50)),
      PhysicalBoxStrut(),
      scroll_into_view_util::CreateScrollIntoViewParams(
          ScrollAlignment::ToEdgeIfNeeded(), ScrollAlignment::ToEdgeIfNeeded(),
          mojom::blink::ScrollType::kProgrammatic, true,
          mojom::blink::ScrollBehavior::kInstant));
  EXPECT_EQ(ScrollOffset(25, 75), layout_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(0, 0), visual_viewport->GetScrollOffset());

  // Reset the visual viewport's size, scale the page, and repeat the test
  visual_viewport->SetViewportSize(gfx::Size(100, 150));
  visual_viewport->SetScale(2);
  root_frame_viewport->SetScrollOffset(
      ScrollOffset(), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kInstant, ScrollableArea::ScrollCallback());

  root_frame_viewport->ScrollIntoView(
      layout_viewport->DocumentToFrame(PhysicalRect(50, 75, 50, 75)),
      PhysicalBoxStrut(),
      scroll_into_view_util::CreateScrollIntoViewParams(
          ScrollAlignment::ToEdgeIfNeeded(), ScrollAlignment::ToEdgeIfNeeded(),
          mojom::blink::ScrollType::kProgrammatic, true,
          mojom::blink::ScrollBehavior::kInstant));
  EXPECT_EQ(ScrollOffset(0, 0), layout_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(50, 75), visual_viewport->GetScrollOffset());

  root_frame_viewport->ScrollIntoView(
      layout_viewport->DocumentToFrame(PhysicalRect(190, 290, 10, 10)),
      PhysicalBoxStrut(),
      scroll_into_view_util::CreateScrollIntoViewParams(
          ScrollAlignment::ToEdgeIfNeeded(), ScrollAlignment::ToEdgeIfNeeded(),
          mojom::blink::ScrollType::kProgrammatic, true,
          mojom::blink::ScrollBehavior::kInstant));
  EXPECT_EQ(ScrollOffset(100, 150), layout_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(50, 75), visual_viewport->GetScrollOffset());

  // Scrolling into view the viewport rect itself should be a no-op.
  visual_viewport->SetViewportSize(gfx::Size(100, 100));
  visual_viewport->SetScale(1.5f);
  visual_viewport->SetScrollOffset(ScrollOffset(0, 10),
                                   mojom::blink::ScrollType::kProgrammatic);
  layout_viewport->SetScrollOffset(ScrollOffset(50, 50),
                                   mojom::blink::ScrollType::kProgrammatic);
  root_frame_viewport->SetScrollOffset(root_frame_viewport->GetScrollOffset(),
                                       mojom::blink::ScrollType::kProgrammatic,
                                       mojom::blink::ScrollBehavior::kInstant,
                                       ScrollableArea::ScrollCallback());

  root_frame_viewport->ScrollIntoView(
      layout_viewport->DocumentToFrame(PhysicalRect(
          root_frame_viewport->VisibleContentRect(kExcludeScrollbars))),
      PhysicalBoxStrut(),
      scroll_into_view_util::CreateScrollIntoViewParams(
          ScrollAlignment::ToEdgeIfNeeded(), ScrollAlignment::ToEdgeIfNeeded(),
          mojom::blink::ScrollType::kProgrammatic, true,
          mojom::blink::ScrollBehavior::kInstant));
  EXPECT_EQ(ScrollOffset(50, 50), layout_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(0, 10), visual_viewport->GetScrollOffset());

  root_frame_viewport->ScrollIntoView(
      layout_viewport->DocumentToFrame(PhysicalRect(
          root_frame_viewport->VisibleContentRect(kExcludeScrollbars))),
      PhysicalBoxStrut(),
      scroll_into_view_util::CreateScrollIntoViewParams(
          ScrollAlignment::CenterAlways(), ScrollAlignment::CenterAlways(),
          mojom::blink::ScrollType::kProgrammatic, true,
          mojom::blink::ScrollBehavior::kInstant));
  EXPECT_EQ(ScrollOffset(50, 50), layout_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(0, 10), visual_viewport->GetScrollOffset());

  root_frame_viewport->ScrollIntoView(
      layout_viewport->DocumentToFrame(PhysicalRect(
          root_frame_viewport->VisibleContentRect(kExcludeScrollbars))),
      PhysicalBoxStrut(),
      scroll_into_view_util::CreateScrollIntoViewParams(
          ScrollAlignment::TopAlways(), ScrollAlignment::TopAlways(),
          mojom::blink::ScrollType::kProgrammatic, true,
          mojom::blink::ScrollBehavior::kInstant));
  EXPECT_EQ(ScrollOffset(50, 50), layout_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(0, 10), visual_viewport->GetScrollOffset());
}

// Tests that the setScrollOffset method works correctly with both viewports.
TEST_F(RootFrameViewportTest, SetScrollOffset) {
  gfx::Size viewport_size(500, 500);
  auto* layout_viewport = MakeGarbageCollected<RootLayoutViewportStub>(
      viewport_size, gfx::Size(1000, 2000));
  auto* visual_viewport =
      MakeGarbageCollected<VisualViewportStub>(viewport_size, viewport_size);

  auto* root_frame_viewport = MakeGarbageCollected<RootFrameViewport>(
      *visual_viewport, *layout_viewport);

  visual_viewport->SetScale(2);

  // Ensure that the visual viewport scrolls first.
  root_frame_viewport->SetScrollOffset(
      ScrollOffset(100, 100), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kInstant, ScrollableArea::ScrollCallback());
  EXPECT_EQ(ScrollOffset(100, 100), visual_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(0, 0), layout_viewport->GetScrollOffset());

  // Scroll to the visual viewport's extent, the layout viewport should scroll
  // the remainder.
  root_frame_viewport->SetScrollOffset(
      ScrollOffset(300, 400), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kInstant, ScrollableArea::ScrollCallback());
  EXPECT_EQ(ScrollOffset(250, 250), visual_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(50, 150), layout_viewport->GetScrollOffset());

  // Only the layout viewport should scroll further. Make sure it doesn't scroll
  // out of bounds.
  root_frame_viewport->SetScrollOffset(
      ScrollOffset(780, 1780), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kInstant, ScrollableArea::ScrollCallback());
  EXPECT_EQ(ScrollOffset(250, 250), visual_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(500, 1500), layout_viewport->GetScrollOffset());

  // Scroll all the way back.
  root_frame_viewport->SetScrollOffset(
      ScrollOffset(0, 0), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kInstant, ScrollableArea::ScrollCallback());
  EXPECT_EQ(ScrollOffset(0, 0), visual_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(0, 0), layout_viewport->GetScrollOffset());
}

// Tests that the visible rect (i.e. visual viewport rect) is correctly
// calculated, taking into account both viewports and page scale.
TEST_F(RootFrameViewportTest, VisibleContentRect) {
  gfx::Size viewport_size(500, 401);
  auto* layout_viewport = MakeGarbageCollected<RootLayoutViewportStub>(
      viewport_size, gfx::Size(1000, 2000));
  auto* visual_viewport =
      MakeGarbageCollected<VisualViewportStub>(viewport_size, viewport_size);

  auto* root_frame_viewport = MakeGarbageCollected<RootFrameViewport>(
      *visual_viewport, *layout_viewport);

  root_frame_viewport->SetScrollOffset(
      ScrollOffset(100, 75), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kInstant, ScrollableArea::ScrollCallback());

  EXPECT_EQ(gfx::Point(100, 75),
            root_frame_viewport->VisibleContentRect().origin());
  EXPECT_EQ(gfx::Size(500, 401),
            root_frame_viewport->VisibleContentRect().size());

  visual_viewport->SetScale(2);

  EXPECT_EQ(gfx::Point(100, 75),
            root_frame_viewport->VisibleContentRect().origin());
  EXPECT_EQ(gfx::Size(250, 201),
            root_frame_viewport->VisibleContentRect().size());
}

// Tests that scrolls on the root frame scroll the visual viewport before
// trying to scroll the layout viewport.
TEST_F(RootFrameViewportTest, ViewportScrollOrder) {
  gfx::Size viewport_size(100, 100);
  auto* layout_viewport = MakeGarbageCollected<RootLayoutViewportStub>(
      viewport_size, gfx::Size(200, 300));
  auto* visual_viewport =
      MakeGarbageCollected<VisualViewportStub>(viewport_size, viewport_size);

  auto* root_frame_viewport = MakeGarbageCollected<RootFrameViewport>(
      *visual_viewport, *layout_viewport);

  visual_viewport->SetScale(2);

  root_frame_viewport->SetScrollOffset(
      ScrollOffset(40, 40), mojom::blink::ScrollType::kUser,
      mojom::blink::ScrollBehavior::kInstant,
      ScrollableArea::ScrollCallback(WTF::BindOnce(
          [](ScrollableArea* visual_viewport, ScrollableArea* layout_viewport,
             ScrollableArea::ScrollCompletionMode) {
            EXPECT_EQ(ScrollOffset(40, 40), visual_viewport->GetScrollOffset());
            EXPECT_EQ(ScrollOffset(0, 0), layout_viewport->GetScrollOffset());
          },
          WrapWeakPersistent(visual_viewport),
          WrapWeakPersistent(layout_viewport))));
  EXPECT_EQ(ScrollOffset(40, 40), visual_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(0, 0), layout_viewport->GetScrollOffset());

  root_frame_viewport->SetScrollOffset(
      ScrollOffset(60, 60), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kInstant,
      ScrollableArea::ScrollCallback(WTF::BindOnce(
          [](ScrollableArea* visual_viewport, ScrollableArea* layout_viewport,
             ScrollableArea::ScrollCompletionMode) {
            EXPECT_EQ(ScrollOffset(50, 50), visual_viewport->GetScrollOffset());
            EXPECT_EQ(ScrollOffset(10, 10), layout_viewport->GetScrollOffset());
          },
          WrapWeakPersistent(visual_viewport),
          WrapWeakPersistent(layout_viewport))));
  EXPECT_EQ(ScrollOffset(50, 50), visual_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(10, 10), layout_viewport->GetScrollOffset());
}

// Tests that setting an alternate layout viewport scrolls the alternate
// instead of the original.
TEST_F(RootFrameViewportTest, SetAlternateLayoutViewport) {
  gfx::Size viewport_size(100, 100);
  auto* layout_viewport = MakeGarbageCollected<RootLayoutViewportStub>(
      viewport_size, gfx::Size(200, 300));
  auto* visual_viewport =
      MakeGarbageCollected<VisualViewportStub>(viewport_size, viewport_size);

  auto* alternate_scroller = MakeGarbageCollected<RootLayoutViewportStub>(
      viewport_size, gfx::Size(600, 500));

  auto* root_frame_viewport = MakeGarbageCollected<RootFrameViewport>(
      *visual_viewport, *layout_viewport);

  visual_viewport->SetScale(2);

  root_frame_viewport->SetScrollOffset(
      ScrollOffset(100, 100), mojom::blink::ScrollType::kUser,
      mojom::blink::ScrollBehavior::kInstant, ScrollableArea::ScrollCallback());
  EXPECT_EQ(ScrollOffset(50, 50), visual_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(50, 50), layout_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(100, 100), root_frame_viewport->GetScrollOffset());

  root_frame_viewport->SetLayoutViewport(*alternate_scroller);
  EXPECT_EQ(ScrollOffset(50, 50), visual_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(0, 0), alternate_scroller->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(50, 50), root_frame_viewport->GetScrollOffset());

  root_frame_viewport->SetScrollOffset(
      ScrollOffset(200, 200), mojom::blink::ScrollType::kUser,
      mojom::blink::ScrollBehavior::kInstant, ScrollableArea::ScrollCallback());
  EXPECT_EQ(ScrollOffset(50, 50), visual_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(150, 150), alternate_scroller->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(200, 200), root_frame_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(50, 50), layout_viewport->GetScrollOffset());

  EXPECT_EQ(ScrollOffset(550, 450), root_frame_viewport->MaximumScrollOffset());
}

// Tests that scrolls on the root frame scroll the visual viewport before
// trying to scroll the layout viewport when using
// DistributeScrollBetweenViewports directly.
TEST_F(RootFrameViewportTest, DistributeScrollOrder) {
  gfx::Size viewport_size(100, 100);
  auto* layout_viewport = MakeGarbageCollected<RootLayoutViewportStub>(
      viewport_size, gfx::Size(200, 300));
  auto* visual_viewport =
      MakeGarbageCollected<VisualViewportStub>(viewport_size, viewport_size);

  auto* root_frame_viewport = MakeGarbageCollected<RootFrameViewport>(
      *visual_viewport, *layout_viewport);

  visual_viewport->SetScale(2);

  root_frame_viewport->DistributeScrollBetweenViewports(
      ScrollOffset(60, 60), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kSmooth, RootFrameViewport::kVisualViewport,
      ScrollableArea::ScrollCallback(WTF::BindOnce(
          [](ScrollableArea* visual_viewport, ScrollableArea* layout_viewport,
             ScrollableArea::ScrollCompletionMode) {
            EXPECT_EQ(ScrollOffset(50, 50), visual_viewport->GetScrollOffset());
            EXPECT_EQ(ScrollOffset(10, 10), layout_viewport->GetScrollOffset());
          },
          WrapWeakPersistent(visual_viewport),
          WrapWeakPersistent(layout_viewport))));
  root_frame_viewport->UpdateCompositorScrollAnimations();
  root_frame_viewport->ServiceScrollAnimations(1);
  EXPECT_EQ(ScrollOffset(0, 0), visual_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(0, 0), layout_viewport->GetScrollOffset());
  root_frame_viewport->ServiceScrollAnimations(1000000);
  EXPECT_EQ(ScrollOffset(50, 50), visual_viewport->GetScrollOffset());
  EXPECT_EQ(ScrollOffset(10, 10), layout_viewport->GetScrollOffset());
}

class RootFrameViewportRenderTest : public RenderingTest {
 public:
  RootFrameViewportRenderTest()
      : RenderingTest(MakeGarbageCollected<EmptyLocalFrameClient>()) {}
};

TEST_F(RootFrameViewportRenderTest,
       ApplyPendingHistoryRestoreScrollOffsetTwice) {
  HistoryItem::ViewState view_state;
  view_state.page_scale_factor_ = 1.5;
  RootFrameViewport* root_frame_viewport = static_cast<RootFrameViewport*>(
      GetDocument().View()->GetScrollableArea());
  root_frame_viewport->SetPendingHistoryRestoreScrollOffset(
      view_state, false, mojom::blink::ScrollBehavior::kAuto);
  root_frame_viewport->ApplyPendingHistoryRestoreScrollOffset();

  // Override the 1.5 scale with 1.0.
  GetDocument().GetPage()->GetVisualViewport().SetScale(1.0f);

  // The second call to ApplyPendingHistoryRestoreScrollOffset should
  // do nothing, since the history was already restored.
  root_frame_viewport->ApplyPendingHistoryRestoreScrollOffset();
  EXPECT_EQ(1.0f, GetDocument().GetPage()->GetVisualViewport().Scale());
}

}  // namespace blink

"""

```