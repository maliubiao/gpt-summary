Response:
Let's break down the thought process for analyzing the `scrollable_area_test.cc` file.

1. **Understand the Purpose:** The filename `scrollable_area_test.cc` immediately suggests this is a test file for the `ScrollableArea` class. Test files are designed to verify the functionality of a specific piece of code.

2. **Identify Key Imports:** Look at the `#include` directives. This reveals the dependencies and what aspects of the `ScrollableArea` are being tested. Key imports here are:
    * `scrollable_area.h`:  The header file for the class being tested. This is the most crucial import.
    * `testing/gmock/...` and `testing/gtest/...`: Indicates the use of Google Mock and Google Test frameworks for creating and running tests. This tells us we're dealing with unit tests.
    * `platform/...`:  A lot of platform-specific headers (geometry, graphics, heap, testing, etc.). This hints that `ScrollableArea` interacts with the underlying rendering platform.
    * `core/scroll/...`:  Other scroll-related classes, suggesting `ScrollableArea` interacts with scrollbars, animators, and themes.
    * `core/style/...`:  The presence of `scroll_start_data.h` indicates testing of CSS scroll behavior.

3. **Examine Test Structure:** Notice the `namespace blink { namespace { ... } namespace blink {` structure. The inner anonymous namespace is common in C++ test files to keep test-specific helper classes and functions local.

4. **Analyze Helper Classes/Mocks:**
    * `MockAnimatingScrollableArea`:  A mock class derived from `MockScrollableArea`. Mock objects are used to isolate the unit under test and control its dependencies. This mock allows for verifying interactions like `ScrollAnimatorEnabled()` and `ScheduleAnimation()`.
    * `ScrollbarThemeWithMockInvalidation`: Another mock, this time for the scrollbar theme. It allows testing how `ScrollableArea` interacts with the theme when scrollbar parts need repainting.

5. **Go Through Individual Tests (the `TEST_P` macros):** Each `TEST_P` block focuses on a specific aspect of `ScrollableArea`'s functionality. Read the test names and the code within each test.

    * **`ScrollAnimatorCurrentPositionShouldBeSync`:** Checks if the current scroll position is updated immediately for compositor scrolls.
    * **`ScrollbarBackgroundAndThumbRepaint`:** Tests how `ScrollableArea` interacts with the scrollbar theme regarding repainting different scrollbar parts.
    * **`InvalidatesNonCompositedScrollbarsWhenThumbMoves`:** Focuses on ensuring non-composited scrollbars are invalidated when the thumb position changes.
    * **`ScrollableAreaDidScroll`:** Verifies that the scroll offset is updated correctly when `DidCompositorScroll` is called.
    * **`ProgrammaticScrollRespectAnimatorEnabled`:** Checks if programmatic scrolling respects whether the animator is enabled (smooth vs. instant scroll).
    * **`PopupOverlayScrollbarShouldNotFadeOut`:** Addresses a specific behavior for overlay scrollbars in popups.
    * **`ScrollAnimatorCallbackFiresOn...`:** Several tests verifying that scroll animation callbacks are fired correctly in different scenarios (cancel, instant scroll, finish).
    * **`ScrollBackToInitialPosition`:** Tests the behavior when a new scroll animation is started while another is in progress.
    * **`ScrollOffsetFromScrollStartDataAllCombinations` and `ScrollOffsetFromScrollStartDataNonZeroMin`:**  These are critical for understanding how CSS `scroll-start` properties are handled. They test various combinations of `scroll-start` values (keywords and lengths/percentages) and edge cases.
    * **`FilterIncomingScrollDuringSmoothUserScroll`:**  Tests a mechanism to filter incoming scroll events during an active smooth user scroll.

6. **Relate to Web Technologies (JavaScript, HTML, CSS):**

    * **JavaScript:** The programmatic scrolling tests (`ProgrammaticScrollRespectAnimatorEnabled`, `ScrollAnimatorCallbackFiresOn...`) directly relate to JavaScript methods like `scrollTo()`, `scrollBy()`, and the `scroll` event.
    * **HTML:**  The existence of scrollable areas is fundamental to HTML. Elements with `overflow: auto`, `overflow: scroll`, etc., can create scrollable areas. The tests touch upon how these areas behave.
    * **CSS:** The tests involving `ScrollOffsetFromScrollStartData` directly map to the CSS `scroll-start` property, which controls the initial scroll position of an element. The scrollbar repaint tests relate to CSS styling of scrollbars (though Blink's default styling is often overridden by the OS or custom CSS).

7. **Identify Logic and Assumptions:**  For tests involving calculations (like `ScrollOffsetFromScrollStartData`), analyze the input values (different `ScrollStartValueType` and `Length` combinations) and the expected output (the calculated `ScrollOffset`). The assumptions are based on how the CSS `scroll-start` property is defined to work.

8. **Consider User/Programming Errors:**  Think about common mistakes developers make when dealing with scrolling:
    * Incorrectly calculating scroll offsets.
    * Not understanding the difference between smooth and instant scrolling.
    * Expecting scroll events to behave in a certain way during animations.
    * Misunderstanding how `scroll-start` affects initial scroll positions.

9. **Trace User Actions (Debugging Clues):** Consider how a user interaction might lead to the execution of this code:
    * **Scrolling with the mouse wheel or scrollbars:** This triggers events that can lead to updates in the `ScrollableArea`'s scroll offset.
    * **Using touch gestures to scroll:** Similar to mouse wheel scrolling.
    * **JavaScript calls to `scrollTo()` or `scrollBy()`:** These directly interact with the programmatic scrolling functionality being tested.
    * **Page load and initial rendering:** The `scroll-start` property is applied during the initial layout, which is covered by the `ScrollOffsetFromScrollStartData` tests.

10. **Synthesize and Organize:** Finally, organize the findings into a clear and structured explanation, covering the functionality, relationships to web technologies, logic/assumptions, potential errors, and debugging clues. Use examples to illustrate the points.
这个文件 `blink/renderer/core/scroll/scrollable_area_test.cc` 是 Chromium Blink 引擎中用于测试 `ScrollableArea` 类的单元测试文件。`ScrollableArea` 类是 Blink 渲染引擎中处理滚动逻辑的核心组件。

以下是该文件的功能，以及它与 JavaScript、HTML、CSS 的关系，逻辑推理，常见错误和调试线索：

**文件功能:**

1. **测试 `ScrollableArea` 类的核心功能:**  该文件包含了多个测试用例，用于验证 `ScrollableArea` 类的各种方法和行为是否符合预期。
2. **测试滚动动画:** 验证平滑滚动动画的启动、取消和完成，以及相关的回调函数是否正确执行。
3. **测试滚动条行为:**  测试滚动条的重绘逻辑，包括当滚动条的 thumb 位置改变时是否会触发重绘。
4. **测试不同类型的滚动:**  测试程序触发的滚动 (programmatic scroll) 和用户交互触发的滚动 (user scroll) 的行为差异，以及它们与滚动动画的交互。
5. **测试 `scroll-start` CSS 属性:** 验证 `ScrollableArea` 如何根据 CSS 的 `scroll-start` 属性计算初始滚动偏移量。
6. **使用 Mock 对象进行隔离测试:**  文件中使用了 Google Mock 框架来创建 `MockScrollableArea` 和 `ScrollbarThemeOverlayMock` 等模拟对象，以便在隔离的环境中测试 `ScrollableArea` 的功能，避免依赖其他复杂的组件。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**
    * **示例:** JavaScript 可以通过 `scrollTo()` 或 `scrollBy()` 等方法来控制元素的滚动位置。测试用例 `ProgrammaticScrollRespectAnimatorEnabled` 验证了当 JavaScript 代码调用 `scrollTo()` 或 `scrollBy()` 并指定平滑滚动行为 (`behavior: 'smooth'`) 时，`ScrollableArea` 如何处理滚动动画。
    * **假设输入与输出:**
        * **假设输入:** JavaScript 调用 `element.scrollTo({ top: 100, behavior: 'smooth' })`，并且 `ScrollableArea` 的动画功能已启用。
        * **输出:**  `ScrollableArea` 的 `ScheduleAnimation()` 方法会被调用，启动平滑滚动动画，最终元素的滚动位置会变为 100。如果动画功能未启用，则会立即滚动到目标位置。
* **HTML:**
    * **示例:**  HTML 元素，如 `<div>`，可以通过 CSS 的 `overflow` 属性 (例如 `overflow: auto`, `overflow: scroll`) 变为可滚动区域。`ScrollableArea` 类负责管理这些可滚动区域的滚动行为。
    * **用户操作:** 当用户通过鼠标滚轮、拖动滚动条或使用键盘方向键与可滚动元素交互时，最终会触发 `ScrollableArea` 的相关逻辑。
* **CSS:**
    * **示例:** CSS 的 `scroll-start` 属性可以设置元素初始滚动位置。测试用例 `ScrollOffsetFromScrollStartDataAllCombinations` 和 `ScrollOffsetFromScrollStartDataNonZeroMin`  验证了 `ScrollableArea` 如何解析和应用 `scroll-start` 的各种值 (例如 `auto`, `start`, `center`, `end`, `top`, `bottom`, `left`, `right`，以及长度或百分比值)。
    * **假设输入与输出:**
        * **假设输入:**  一个 `<div>` 元素的 CSS 样式为 `scroll-start: top left;`。
        * **输出:**  在元素渲染时，`ScrollableArea` 会计算出初始的滚动偏移量，使其内容从顶部和左侧开始显示。
        * **假设输入:** 一个 `<div>` 元素的 CSS 样式为 `scroll-start: 50% 25%;`，假设该元素的内容宽度为 200px，高度为 100px。
        * **输出:** `ScrollableArea` 会计算出水平方向的初始偏移量为 100px (200px * 50%)，垂直方向的初始偏移量为 25px (100px * 25%)。

**逻辑推理 (假设输入与输出):**

* **测试滚动动画取消:**
    * **假设输入:**  JavaScript 代码触发一个平滑滚动动画，然后立即调用 `cancelProgrammaticScrollAnimation()` 取消该动画。
    * **输出:** `ScrollableArea` 会停止动画，并触发与该动画关联的回调函数，回调函数的参数 `ScrollCompletionMode` 会指示动画是被取消而不是自然完成。测试用例 `ScrollAnimatorCallbackFiresOnAnimationCancel` 验证了这个行为。

**用户或编程常见的使用错误:**

* **错误地假设平滑滚动是同步的:** 开发者可能错误地认为调用 `scrollTo()` 并指定 `behavior: 'smooth'` 会立即改变滚动位置。实际上，这是异步操作，会启动一个动画。测试用例 `ProgrammaticScrollRespectAnimatorEnabled`  通过禁用动画来展示同步滚动的行为。
* **未能正确处理滚动完成后的操作:**  如果需要在滚动动画完成后执行某些操作，开发者需要使用回调函数。忘记设置或错误地设置回调函数会导致预期之外的行为。测试用例 `ScrollAnimatorCallbackFiresOnAnimationFinish` 演示了如何使用回调函数。
* **误解 `scroll-start` 的工作方式:**  开发者可能不清楚 `scroll-start` 的不同取值的含义，或者在动态改变元素内容后，没有意识到 `scroll-start` 只在初始布局时生效。测试用例 `ScrollOffsetFromScrollStartDataAllCombinations` 覆盖了 `scroll-start` 的各种取值，帮助开发者理解其行为。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户访问一个包含可滚动内容的网页:**  例如，一个 `<div>` 元素设置了 `overflow: auto` 并包含了超出其显示范围的内容。
2. **用户尝试滚动该内容:**
    * **使用鼠标滚轮:**  鼠标滚轮事件会被浏览器捕获，并传递给渲染引擎。
    * **拖动滚动条:**  用户点击并拖动滚动条的 thumb，浏览器会根据鼠标移动计算出新的滚动位置。
    * **使用触摸手势 (在触摸设备上):**  用户滑动或捏合手势会被转换为滚动操作。
    * **使用键盘 (例如 Page Up/Down, 方向键):**  键盘事件也会触发滚动。
3. **浏览器渲染引擎接收到滚动事件:**  渲染引擎会确定哪个 `ScrollableArea` 对象负责处理该滚动事件。
4. **`ScrollableArea` 对象更新滚动位置:**  根据用户操作的类型和幅度，`ScrollableArea` 会更新其内部的滚动偏移量。
5. **如果涉及到平滑滚动:**  如果用户交互或 JavaScript 代码触发了平滑滚动，`ScrollableArea` 会启动滚动动画，并可能调用 `ScheduleAnimation()`。
6. **滚动条的更新和重绘:**  `ScrollableArea` 会通知相关的滚动条对象 (例如 `HorizontalScrollbar` 和 `VerticalScrollbar`) 更新其状态和外观，可能涉及到调用 `SetNeedsPaintInvalidation()` 来触发重绘。测试用例 `ScrollbarBackgroundAndThumbRepaint` 和 `InvalidatesNonCompositedScrollbarsWhenThumbMoves` 模拟了这个过程。
7. **CSS `scroll-start` 的应用:** 当页面加载和渲染时，如果元素设置了 `scroll-start` 属性，渲染引擎会调用 `ScrollableArea::ScrollOffsetFromScrollStartData()` 来计算初始滚动偏移量。测试用例 `ScrollOffsetFromScrollStartDataAllCombinations` 等模拟了这种场景。

**作为调试线索，你可以关注以下几点:**

* **断点设置:** 在 `ScrollableArea` 的关键方法 (例如 `SetScrollOffset`, `ScheduleAnimation`, `DidCompositorScroll`, `ScrollOffsetFromScrollStartData`) 设置断点，观察滚动事件是如何被处理的。
* **查看滚动偏移量:**  使用开发者工具查看元素的滚动偏移量 (例如 `element.scrollTop`, `element.scrollLeft`)，确认是否与预期一致。
* **检查滚动条状态:**  检查滚动条是否可见，thumb 的位置是否正确。
* **分析 CSS 样式:**  确认元素的 `overflow` 和 `scroll-start` 等相关 CSS 属性是否设置正确。
* **监控滚动事件:**  使用 JavaScript 监听 `scroll` 事件，查看事件的触发频率和相关信息。
* **使用 Paint 调试工具:**  Chromium 提供了 Paint 调试工具，可以帮助你了解哪些区域需要重绘，这对于调试滚动条的重绘问题很有帮助。

总而言之，`scrollable_area_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎中滚动功能的正确性和稳定性，涵盖了从基本的滚动操作到复杂的滚动动画和 CSS 属性处理等多个方面。理解这个文件的内容可以帮助开发者更好地理解 Blink 的滚动机制，并有效地调试与滚动相关的 bug。

Prompt: 
```
这是目录为blink/renderer/core/scroll/scrollable_area_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/scroll/scrollable_area.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/core/scroll/scroll_animator_base.h"
#include "third_party/blink/renderer/core/scroll/scroll_types.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_test_suite.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme_overlay_mock.h"
#include "third_party/blink/renderer/core/style/scroll_start_data.h"
#include "third_party/blink/renderer/core/testing/scoped_mock_overlay_scrollbars.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support_with_mock_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

using testing::_;
using testing::Mock;
using testing::Return;

class MockAnimatingScrollableArea : public MockScrollableArea {
 public:
  static MockAnimatingScrollableArea* Create() {
    return MakeGarbageCollected<MockAnimatingScrollableArea>();
  }
  static MockAnimatingScrollableArea* Create(
      const ScrollOffset& maximum_scroll_offset) {
    MockAnimatingScrollableArea* mock = Create();
    mock->SetMaximumScrollOffset(maximum_scroll_offset);
    return mock;
  }
  Scrollbar* HorizontalScrollbar() const override { return nullptr; }
  Scrollbar* VerticalScrollbar() const override { return nullptr; }
  MOCK_CONST_METHOD0(ScrollAnimatorEnabled, bool());
  MOCK_METHOD0(ScheduleAnimation, bool());
};

class ScrollbarThemeWithMockInvalidation : public ScrollbarThemeOverlayMock {
 public:
  MOCK_CONST_METHOD0(ShouldRepaintAllPartsOnInvalidation, bool());
  MOCK_CONST_METHOD3(PartsToInvalidateOnThumbPositionChange,
                     ScrollbarPart(const Scrollbar&, float, float));
};

}  // namespace

class ScrollableAreaTest : public testing::Test,
                           public PaintTestConfigurations {
 private:
  test::TaskEnvironment task_environment_;
};

INSTANTIATE_PAINT_TEST_SUITE_P(ScrollableAreaTest);

TEST_P(ScrollableAreaTest, ScrollAnimatorCurrentPositionShouldBeSync) {
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform;

  MockScrollableArea* scrollable_area =
      MockScrollableArea::Create(ScrollOffset(0, 100));
  scrollable_area->SetScrollOffset(ScrollOffset(0, 10000),
                                   mojom::blink::ScrollType::kCompositor);
  EXPECT_EQ(100.0, scrollable_area->GetScrollAnimator().CurrentOffset().y());
}

TEST_P(ScrollableAreaTest, ScrollbarBackgroundAndThumbRepaint) {
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform;

  ScrollbarThemeWithMockInvalidation theme;
  MockScrollableArea* scrollable_area =
      MockScrollableArea::Create(ScrollOffset(0, 100));
  Scrollbar* scrollbar = Scrollbar::CreateForTesting(
      scrollable_area, kHorizontalScrollbar, &theme);

  EXPECT_CALL(theme, ShouldRepaintAllPartsOnInvalidation())
      .WillRepeatedly(Return(true));
  EXPECT_TRUE(scrollbar->TrackAndButtonsNeedRepaint());
  EXPECT_TRUE(scrollbar->ThumbNeedsRepaint());
  scrollbar->SetNeedsPaintInvalidation(kNoPart);
  EXPECT_TRUE(scrollbar->TrackAndButtonsNeedRepaint());
  EXPECT_TRUE(scrollbar->ThumbNeedsRepaint());

  scrollbar->ClearTrackAndButtonsNeedRepaint();
  scrollbar->ClearThumbNeedsRepaint();
  EXPECT_FALSE(scrollbar->TrackAndButtonsNeedRepaint());
  EXPECT_FALSE(scrollbar->ThumbNeedsRepaint());
  scrollbar->SetNeedsPaintInvalidation(kThumbPart);
  EXPECT_TRUE(scrollbar->TrackAndButtonsNeedRepaint());
  EXPECT_TRUE(scrollbar->ThumbNeedsRepaint());

  // When not all parts are repainted on invalidation,
  // setNeedsPaintInvalidation sets repaint bits only on the requested parts.
  EXPECT_CALL(theme, ShouldRepaintAllPartsOnInvalidation())
      .WillRepeatedly(Return(false));
  scrollbar->ClearTrackAndButtonsNeedRepaint();
  scrollbar->ClearThumbNeedsRepaint();
  EXPECT_FALSE(scrollbar->TrackAndButtonsNeedRepaint());
  EXPECT_FALSE(scrollbar->ThumbNeedsRepaint());
  scrollbar->SetNeedsPaintInvalidation(kThumbPart);
  EXPECT_FALSE(scrollbar->TrackAndButtonsNeedRepaint());
  EXPECT_TRUE(scrollbar->ThumbNeedsRepaint());

  // Forced GC in order to finalize objects depending on the mock object.
  ThreadState::Current()->CollectAllGarbageForTesting();
}

TEST_P(ScrollableAreaTest, InvalidatesNonCompositedScrollbarsWhenThumbMoves) {
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform;

  ScrollbarThemeWithMockInvalidation theme;
  MockScrollableArea* scrollable_area =
      MockScrollableArea::Create(ScrollOffset(100, 100));
  Scrollbar* horizontal_scrollbar = Scrollbar::CreateForTesting(
      scrollable_area, kHorizontalScrollbar, &theme);
  Scrollbar* vertical_scrollbar =
      Scrollbar::CreateForTesting(scrollable_area, kVerticalScrollbar, &theme);
  EXPECT_CALL(*scrollable_area, HorizontalScrollbar())
      .WillRepeatedly(Return(horizontal_scrollbar));
  EXPECT_CALL(*scrollable_area, VerticalScrollbar())
      .WillRepeatedly(Return(vertical_scrollbar));

  // Regardless of whether the theme invalidates any parts, non-composited
  // scrollbars have to be repainted if the thumb moves.
  EXPECT_CALL(*scrollable_area, LayerForHorizontalScrollbar())
      .WillRepeatedly(Return(nullptr));
  EXPECT_CALL(*scrollable_area, LayerForVerticalScrollbar())
      .WillRepeatedly(Return(nullptr));
  ASSERT_FALSE(scrollable_area->HasLayerForVerticalScrollbar());
  ASSERT_FALSE(scrollable_area->HasLayerForHorizontalScrollbar());
  EXPECT_CALL(theme, ShouldRepaintAllPartsOnInvalidation())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(theme, PartsToInvalidateOnThumbPositionChange(_, _, _))
      .WillRepeatedly(Return(kNoPart));

  // A scroll in each direction should only invalidate one scrollbar.
  scrollable_area->SetScrollOffset(ScrollOffset(0, 50),
                                   mojom::blink::ScrollType::kProgrammatic);
  EXPECT_FALSE(scrollable_area->HorizontalScrollbarNeedsPaintInvalidation());
  EXPECT_TRUE(scrollable_area->VerticalScrollbarNeedsPaintInvalidation());
  scrollable_area->ClearNeedsPaintInvalidationForScrollControls();
  scrollable_area->SetScrollOffset(ScrollOffset(50, 50),
                                   mojom::blink::ScrollType::kProgrammatic);
  EXPECT_TRUE(scrollable_area->HorizontalScrollbarNeedsPaintInvalidation());
  EXPECT_FALSE(scrollable_area->VerticalScrollbarNeedsPaintInvalidation());
  scrollable_area->ClearNeedsPaintInvalidationForScrollControls();

  // Forced GC in order to finalize objects depending on the mock object.
  ThreadState::Current()->CollectAllGarbageForTesting();
}

TEST_P(ScrollableAreaTest, ScrollableAreaDidScroll) {
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform;

  MockScrollableArea* scrollable_area =
      MockScrollableArea::Create(ScrollOffset(100, 100));
  scrollable_area->DidCompositorScroll(gfx::PointF(40, 51));

  EXPECT_EQ(40, scrollable_area->ScrollOffsetInt().x());
  EXPECT_EQ(51, scrollable_area->ScrollOffsetInt().y());
}

TEST_P(ScrollableAreaTest, ProgrammaticScrollRespectAnimatorEnabled) {
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform;
  MockAnimatingScrollableArea* scrollable_area =
      MockAnimatingScrollableArea::Create(ScrollOffset(0, 100));
  // Disable animations. Make sure an explicitly smooth programmatic scroll is
  // instantly scrolled.
  {
    EXPECT_CALL(*scrollable_area, ScrollAnimatorEnabled())
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*scrollable_area, ScheduleAnimation()).Times(0);
    scrollable_area->SetScrollOffset(ScrollOffset(0, 100),
                                     mojom::blink::ScrollType::kProgrammatic,
                                     mojom::blink::ScrollBehavior::kSmooth);
    EXPECT_EQ(100, scrollable_area->GetScrollOffset().y());
  }
  Mock::VerifyAndClearExpectations(scrollable_area);
  // Enable animations. A smooth programmatic scroll should now schedule an
  // animation rather than immediately mutating the offset.
  {
    EXPECT_CALL(*scrollable_area, ScrollAnimatorEnabled())
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*scrollable_area, ScheduleAnimation()).WillOnce(Return(true));
    scrollable_area->SetScrollOffset(ScrollOffset(0, 50),
                                     mojom::blink::ScrollType::kProgrammatic,
                                     mojom::blink::ScrollBehavior::kSmooth);
    // Offset is unchanged.
    EXPECT_EQ(100, scrollable_area->GetScrollOffset().y());
  }
}

// Scrollbars in popups shouldn't fade out since they aren't composited and thus
// they don't appear on hover so users without a wheel can't scroll if they fade
// out.
TEST_P(ScrollableAreaTest, PopupOverlayScrollbarShouldNotFadeOut) {
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform;

  ScopedMockOverlayScrollbars mock_overlay_scrollbars;

  MockScrollableArea* scrollable_area =
      MockScrollableArea::Create(ScrollOffset(0, 100));
  EXPECT_CALL(*scrollable_area, UsesCompositedScrolling())
      .WillRepeatedly(Return(false));
  scrollable_area->SetIsPopup();

  ScrollbarThemeOverlayMock& theme =
      (ScrollbarThemeOverlayMock&)scrollable_area->GetPageScrollbarTheme();
  theme.SetOverlayScrollbarFadeOutDelay(base::Seconds(1));
  Scrollbar* scrollbar = Scrollbar::CreateForTesting(
      scrollable_area, kHorizontalScrollbar, &theme);

  DCHECK(scrollbar->IsOverlayScrollbar());
  DCHECK(scrollbar->Enabled());

  scrollable_area->ShowNonMacOverlayScrollbars();

  // No fade out animation should be posted.
  EXPECT_FALSE(scrollable_area->fade_overlay_scrollbars_timer_);

  // Forced GC in order to finalize objects depending on the mock object.
  ThreadState::Current()->CollectAllGarbageForTesting();
}

TEST_P(ScrollableAreaTest, ScrollAnimatorCallbackFiresOnAnimationCancel) {
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform;

  MockScrollableArea* scrollable_area =
      MockScrollableArea::Create(ScrollOffset(0, 100));
  EXPECT_CALL(*scrollable_area, ScheduleAnimation())
      .WillRepeatedly(Return(true));
  bool finished = false;
  scrollable_area->SetScrollOffset(
      ScrollOffset(0, 10000), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kSmooth,
      ScrollableArea::ScrollCallback(WTF::BindOnce(
          [](bool* finished, ScrollableArea::ScrollCompletionMode) {
            *finished = true;
          },
          WTF::Unretained(&finished))));
  EXPECT_EQ(0.0, scrollable_area->GetScrollAnimator().CurrentOffset().y());
  EXPECT_FALSE(finished);
  scrollable_area->CancelProgrammaticScrollAnimation();
  EXPECT_EQ(0.0, scrollable_area->GetScrollAnimator().CurrentOffset().y());
  EXPECT_TRUE(finished);
}

TEST_P(ScrollableAreaTest, ScrollAnimatorCallbackFiresOnInstantScroll) {
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform;

  MockScrollableArea* scrollable_area =
      MockScrollableArea::Create(ScrollOffset(0, 100));
  EXPECT_CALL(*scrollable_area, ScheduleAnimation())
      .WillRepeatedly(Return(true));
  bool finished = false;
  scrollable_area->SetScrollOffset(
      ScrollOffset(0, 10000), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kInstant,
      ScrollableArea::ScrollCallback(WTF::BindOnce(
          [](bool* finished, ScrollableArea::ScrollCompletionMode) {
            *finished = true;
          },
          WTF::Unretained(&finished))));
  EXPECT_EQ(100, scrollable_area->GetScrollAnimator().CurrentOffset().y());
  EXPECT_TRUE(finished);
}

TEST_P(ScrollableAreaTest, ScrollAnimatorCallbackFiresOnAnimationFinish) {
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform;

  MockScrollableArea* scrollable_area =
      MockScrollableArea::Create(ScrollOffset(0, 100));
  EXPECT_CALL(*scrollable_area, ScheduleAnimation())
      .WillRepeatedly(Return(true));
  bool finished = false;
  scrollable_area->SetScrollOffset(
      ScrollOffset(0, 9), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kSmooth,
      ScrollableArea::ScrollCallback(WTF::BindOnce(
          [](bool* finished, ScrollableArea::ScrollCompletionMode) {
            *finished = true;
          },
          WTF::Unretained(&finished))));
  EXPECT_EQ(0.0, scrollable_area->GetScrollAnimator().CurrentOffset().y());
  EXPECT_FALSE(finished);
  scrollable_area->UpdateCompositorScrollAnimations();
  scrollable_area->ServiceScrollAnimations(1);
  EXPECT_EQ(0.0, scrollable_area->GetScrollAnimator().CurrentOffset().y());
  EXPECT_FALSE(finished);
  scrollable_area->ServiceScrollAnimations(1000000);
  EXPECT_EQ(9.0, scrollable_area->GetScrollAnimator().CurrentOffset().y());
  EXPECT_TRUE(finished);
}

TEST_P(ScrollableAreaTest, ScrollBackToInitialPosition) {
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform;

  MockScrollableArea* scrollable_area =
      MockScrollableArea::Create(ScrollOffset(0, 100));
  EXPECT_CALL(*scrollable_area, ScheduleAnimation())
      .WillRepeatedly(Return(true));
  bool finished = false;
  scrollable_area->SetScrollOffset(
      ScrollOffset(0, 50), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kSmooth,
      ScrollableArea::ScrollCallback(WTF::BindOnce(
          [](bool* finished, ScrollableArea::ScrollCompletionMode) {
            *finished = true;
          },
          WTF::Unretained(&finished))));
  scrollable_area->SetScrollOffset(ScrollOffset(0, 0),
                                   mojom::blink::ScrollType::kProgrammatic,
                                   mojom::blink::ScrollBehavior::kSmooth);
  scrollable_area->UpdateCompositorScrollAnimations();
  scrollable_area->ServiceScrollAnimations(1);
  scrollable_area->ServiceScrollAnimations(1000000);
  EXPECT_EQ(0, scrollable_area->GetScrollOffset().y());
  EXPECT_TRUE(finished);
}

void VerifyOffsetFromScrollStart(ScrollableArea* scrollable_area,
                                 ScrollStartValueType y_type,
                                 ScrollStartValueType x_type,
                                 const Length& y_length,
                                 const Length& x_length,
                                 const ScrollOffset& offset) {
  switch (y_type) {
    case blink::ScrollStartValueType::kAuto:
    case blink::ScrollStartValueType::kStart:
    case blink::ScrollStartValueType::kTop:
    case blink::ScrollStartValueType::kLeft: {
      EXPECT_EQ(offset.y(), scrollable_area->MinimumScrollOffset().y());
      break;
    }
    case blink::ScrollStartValueType::kCenter: {
      EXPECT_EQ(offset.y(),
                scrollable_area->MinimumScrollOffset().y() +
                    0.5 * scrollable_area->ScrollSize(kVerticalScrollbar));
      break;
    }
    case blink::ScrollStartValueType::kEnd:
    case blink::ScrollStartValueType::kBottom: {
      EXPECT_EQ(offset.y(), scrollable_area->MaximumScrollOffset().y());
      break;
    }
    case blink::ScrollStartValueType::kRight: {
      EXPECT_EQ(offset.y(), scrollable_area->MinimumScrollOffset().y());
      break;
    }
    case blink::ScrollStartValueType::kLengthOrPercentage: {
      float expected_offset =
          scrollable_area->MinimumScrollOffset().y() +
          FloatValueForLength(y_length,
                              scrollable_area->ScrollSize(kVerticalScrollbar));
      EXPECT_EQ(offset.y(), expected_offset);
      break;
    }
  }

  switch (x_type) {
    case blink::ScrollStartValueType::kAuto:
    case blink::ScrollStartValueType::kStart:
    case blink::ScrollStartValueType::kTop:
    case blink::ScrollStartValueType::kLeft: {
      EXPECT_EQ(offset.x(), scrollable_area->MinimumScrollOffset().x());
      break;
    }
    case blink::ScrollStartValueType::kCenter: {
      EXPECT_EQ(offset.x(),
                scrollable_area->MinimumScrollOffset().x() +
                    0.5 * scrollable_area->ScrollSize(kHorizontalScrollbar));
      break;
    }
    case blink::ScrollStartValueType::kEnd:
    case blink::ScrollStartValueType::kRight: {
      EXPECT_EQ(offset.x(), scrollable_area->MaximumScrollOffset().x());
      break;
    }
    case blink::ScrollStartValueType::kBottom: {
      EXPECT_EQ(offset.x(), scrollable_area->MinimumScrollOffset().x());
      break;
    }
    case blink::ScrollStartValueType::kLengthOrPercentage: {
      float expected_offset =
          scrollable_area->MinimumScrollOffset().x() +
          FloatValueForLength(
              x_length, scrollable_area->ScrollSize(kHorizontalScrollbar));
      EXPECT_EQ(offset.x(), expected_offset);
      break;
    }
  }
}

void test_scroll_start_combination(ScrollableArea* scrollable_area,
                                   ScrollStartValueType y_type,
                                   ScrollStartValueType x_type,
                                   const Length& y_length,
                                   const Length& x_length) {
  ScrollStartData y_data;
  ScrollStartData x_data;

  y_data.value_type = y_type;
  y_data.value = y_length;
  x_data.value_type = x_type;
  x_data.value = x_length;

  ScrollOffset offset =
      scrollable_area->ScrollOffsetFromScrollStartData(y_data, x_data);
  VerifyOffsetFromScrollStart(scrollable_area, y_type, x_type, y_length,
                              x_length, offset);
}

TEST_P(ScrollableAreaTest, ScrollOffsetFromScrollStartDataAllCombinations) {
  const Vector<ScrollStartValueType> scroll_start_values = {
      ScrollStartValueType::kAuto,   ScrollStartValueType::kLengthOrPercentage,
      ScrollStartValueType::kStart,  ScrollStartValueType::kCenter,
      ScrollStartValueType::kEnd,    ScrollStartValueType::kTop,
      ScrollStartValueType::kBottom, ScrollStartValueType::kLeft,
      ScrollStartValueType::kRight};
  const int max_horizontal_scroll_offset = 500;
  const int max_vertical_scroll_offset = 500;
  MockScrollableArea* scrollable_area = MockScrollableArea::Create(
      ScrollOffset(max_horizontal_scroll_offset, max_vertical_scroll_offset));
  ON_CALL(*scrollable_area, ScrollSize(kHorizontalScrollbar))
      .WillByDefault(Return(max_horizontal_scroll_offset));
  ON_CALL(*scrollable_area, ScrollSize(kVerticalScrollbar))
      .WillByDefault(Return(max_vertical_scroll_offset));

  for (auto y_type : scroll_start_values) {
    Length y_length = y_type == ScrollStartValueType::kLengthOrPercentage
                          ? Length(100, Length::Type::kFixed)
                          : Length();
    for (auto x_type : scroll_start_values) {
      Length x_length = x_type == ScrollStartValueType::kLengthOrPercentage
                            ? Length(100, Length::Type::kFixed)
                            : Length();
      test_scroll_start_combination(scrollable_area, y_type, x_type, y_length,
                                    x_length);
    }
  }
}

TEST_P(ScrollableAreaTest, ScrollOffsetFromScrollStartDataNonZeroMin) {
  const int max_horizontal_scroll_offset = 500;
  const int min_horizontal_scroll_offset = -10;
  const int max_vertical_scroll_offset = 500;
  const int min_vertical_scroll_offset = -10;
  const int horizontal_scroll_size =
      max_horizontal_scroll_offset - min_horizontal_scroll_offset;
  const int vertical_scroll_size =
      max_vertical_scroll_offset - min_vertical_scroll_offset;
  MockScrollableArea* scrollable_area = MockScrollableArea::Create(
      ScrollOffset(max_horizontal_scroll_offset, max_vertical_scroll_offset),
      ScrollOffset(min_horizontal_scroll_offset, min_vertical_scroll_offset));
  ScrollOffset offset;
  ScrollStartData y_data;
  ScrollStartData x_data;

  ON_CALL(*scrollable_area, ScrollSize(kHorizontalScrollbar))
      .WillByDefault(Return(horizontal_scroll_size));
  ON_CALL(*scrollable_area, ScrollSize(kVerticalScrollbar))
      .WillByDefault(Return(vertical_scroll_size));

  // Test that scroll-start greater than max scroll offset is clamped to max.
  y_data.value = Length(600, Length::Type::kFixed);
  y_data.value_type = ScrollStartValueType::kLengthOrPercentage;
  x_data.value = Length(600, Length::Type::kFixed);
  x_data.value_type = ScrollStartValueType::kLengthOrPercentage;
  offset = scrollable_area->ScrollOffsetFromScrollStartData(y_data, x_data);
  EXPECT_EQ(offset.y(), max_vertical_scroll_offset);
  EXPECT_EQ(offset.x(), max_horizontal_scroll_offset);

  // Test that scroll-start less than min scroll offset is clamped to min
  y_data.value = Length(0, Length::Type::kFixed);
  y_data.value_type = ScrollStartValueType::kLengthOrPercentage;
  x_data.value = Length(0, Length::Type::kFixed);
  x_data.value_type = ScrollStartValueType::kLengthOrPercentage;
  offset = scrollable_area->ScrollOffsetFromScrollStartData(y_data, x_data);
  EXPECT_EQ(offset.y(), min_vertical_scroll_offset);
  EXPECT_EQ(offset.x(), min_horizontal_scroll_offset);

  // Test that scroll-start: <percentage> is relative to ScrollSize().
  y_data.value = Length(50, Length::Type::kPercent);
  y_data.value_type = ScrollStartValueType::kLengthOrPercentage;
  x_data.value = Length(50, Length::Type::kPercent);
  x_data.value_type = ScrollStartValueType::kLengthOrPercentage;
  offset = scrollable_area->ScrollOffsetFromScrollStartData(y_data, x_data);
  EXPECT_EQ(offset.y(), scrollable_area->MinimumScrollOffset().y() +
                            0.5 * vertical_scroll_size);
  EXPECT_EQ(offset.x(), scrollable_area->MinimumScrollOffset().x() +
                            0.5 * horizontal_scroll_size);

  // Test that scroll-start: end scrolls to MaximumScrollOffset.
  y_data.value_type = ScrollStartValueType::kEnd;
  x_data.value_type = ScrollStartValueType::kEnd;
  offset = scrollable_area->ScrollOffsetFromScrollStartData(y_data, x_data);
  EXPECT_EQ(offset.y(), max_vertical_scroll_offset);
  EXPECT_EQ(offset.x(), max_horizontal_scroll_offset);
}

TEST_P(ScrollableAreaTest, FilterIncomingScrollDuringSmoothUserScroll) {
  using mojom::blink::ScrollType;
  MockScrollableArea* area =
      MockScrollableArea::Create(ScrollOffset(100, 100), ScrollOffset(0, 0));
  area->set_active_smooth_scroll_type_for_testing(ScrollType::kUser);
  const std::vector<mojom::blink::ScrollType> scroll_types = {
      ScrollType::kUser,       ScrollType::kProgrammatic,
      ScrollType::kClamping,   ScrollType::kCompositor,
      ScrollType::kAnchoring,  ScrollType::kSequenced,
      ScrollType::kScrollStart};

  // ScrollTypes which we do not filter even if there is an active
  // kUser smooth scroll.
  std::set<mojom::blink::ScrollType> exempted_types = {
      ScrollType::kUser,
      ScrollType::kCompositor,
      ScrollType::kClamping,
      ScrollType::kAnchoring,
  };

  for (const auto& incoming_type : scroll_types) {
    const bool should_filter = !exempted_types.contains(incoming_type);
    EXPECT_EQ(area->ShouldFilterIncomingScroll(incoming_type), should_filter);
  }
}

}  // namespace blink

"""

```