Response:
The user wants to understand the functionality of the `scroll_test.cc` file in the Chromium Blink engine. I need to analyze the code and identify its purpose, relate it to web technologies like JavaScript, HTML, and CSS, provide examples with hypothetical inputs and outputs, point out common usage errors, and describe how a user's actions can lead to this code being executed during debugging.

Here's a breakdown of the analysis:

1. **Purpose of the file:** Identify the core functionality tested in this file. It appears to be testing scrolling-related features in Blink.

2. **Relationship to JavaScript, HTML, CSS:** Look for code that interacts with or tests features exposed through these web technologies.

3. **Logical Reasoning with Input/Output:**  For specific test cases, describe what the test sets up (input) and what it expects as a result (output).

4. **Common Usage Errors:** Think about how developers might misuse the scrolling APIs or encounter issues that these tests are designed to prevent or detect.

5. **Debugging Path:** Outline a typical user interaction scenario that triggers scrolling and how a developer might end up investigating this specific test file during debugging.
好的，您提供的是 Chromium Blink 引擎中 `blink/renderer/core/scroll/scroll_test.cc` 文件的内容。这个文件是一个 **C++ 单元测试文件**，专门用于测试 Blink 引擎中与 **滚动 (scrolling)** 功能相关的代码。

以下是该文件的功能及其与 JavaScript、HTML、CSS 的关系，以及一些使用示例和调试线索：

**文件功能：**

* **测试 `ScrollAnimator` 类:**  文件中包含了针对 `ScrollAnimator` 类的测试，特别是关于用户触发滚动动画及其回调函数的执行时机。
* **测试分数像素滚动 (Fractional Scrolling):**  部分测试用例（以 `FractionalScrollSimTest` 命名）专注于测试在处理分数像素滚动时的各种行为，例如 `getBoundingClientRect` 的计算、避免不必要的重绘以及粘性定位 (sticky positioning) 的正确性。
* **测试滚动接口的使用计数 (Use Counter):** `ScrollInfacesUseCounterSimTest` 类下的测试旨在验证在特定的滚动行为发生时，Blink 引擎是否正确地记录了相关特性的使用情况 (use counter)。这对于了解 Web 平台的特性使用情况非常重要。
* **测试非默认书写模式下的滚动位置:** `ScrollPositionsInNonDefaultWritingModeSimTest` 测试了在非默认书写模式（例如 `direction: rtl` 或 `writing-mode: vertical-rl`）下，滚动相关的行为是否符合预期，特别是 `scrollIntoView()` 的行为以及是否会错误地触发某些 use counter。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个测试文件主要测试的是 Blink 引擎内部的实现，但它直接关系到开发者通过 JavaScript、HTML 和 CSS 操作页面滚动时的行为。

* **JavaScript:**
    * **示例 1 (`TestRootFrameLayoutViewportUserScrollCallBack`):**  模拟用户滚动操作（尽管在测试中是程序控制的），验证当滚动动画完成后，通过 JavaScript 设置的回调函数是否会被执行。
        * **假设输入:** 用户通过鼠标滚轮或触摸板滚动页面。
        * **预期输出:** 页面平滑滚动到目标位置，并且之前通过 JavaScript 注册的滚动完成回调函数被调用。
    * **示例 2 (`TestDivUserScrollCallBack`):** 测试针对特定 `div` 元素的滚动。开发者通常会使用 JavaScript 来监听或控制特定元素的滚动行为。
        * **假设输入:** JavaScript 代码使用 `element.scrollTo()` 或修改 `element.scrollTop` 和 `element.scrollLeft` 来滚动一个设置了 `overflow: auto` 的 `div` 元素。
        * **预期输出:** `div` 元素滚动到指定位置，如果启用了滚动动画，则会产生平滑滚动的效果，并且回调函数会被执行。
    * **示例 3 (`ScrollInfacesUseCounterSimTest`):** 测试了 JavaScript 中与滚动相关的属性和方法（如 `scrollLeft`, `scrollTop`, `scrollTo`, `scroll`) 是否会正确触发 use counter。
        * **假设输入:** JavaScript 代码读取或设置元素的 `scrollLeft` 属性。例如：`document.getElementById('scroller').scrollLeft;` 或 `document.getElementById('scroller').scrollLeft = 10;`
        * **预期输出:** 如果元素的滚动方向与文档的书写模式 (direction 和 writing-mode) 组合符合特定的条件（例如，RTL 布局中读取 `scrollLeft`），则对应的 use counter 会被记录。
* **HTML:**
    * **示例 1 (`FractionalScrollSimTest`, `GetBoundingClientRectAtFractional`):** 测试了在页面包含不同定位方式的元素时，滚动后使用 JavaScript 的 `element.getBoundingClientRect()` 方法获取元素位置是否准确，特别是在存在分数像素滚动偏移的情况下。
        * **假设输入:**  HTML 结构中包含一个绝对定位的 `div` 元素，并且页面被滚动了一个非整数的像素值（例如 700.5px）。
        * **预期输出:** `div` 元素的 `left` 和 `top` 属性值会准确反映出滚动偏移带来的影响，即使偏移是分数像素。
    * **示例 2 (`ScrollPositionsInNonDefaultWritingModeSimTest`):** 测试了在 `direction: rtl` 的布局中，使用 `scrollIntoView()` 方法将一个元素滚动到可见区域时的行为。
        * **假设输入:**  HTML 结构中包含一个设置了 `direction: rtl` 的容器，容器内部包含需要滚动到可见区域的元素。
        * **预期输出:** 元素被滚动到可见区域，并且浏览器的控制台输出了 "decreasing" 和 "nonpositive"，表明在 RTL 布局中，向左滚动会导致 `scrollLeft` 值减小，且最左侧位置的 `scrollLeft` 值为非正数。
* **CSS:**
    * **示例 1 (`FractionalScrollSimTest`, `StickyDoesntOscillate`):** 测试了 CSS `position: sticky` 属性在存在分数像素滚动偏移时是否能正常工作，避免出现抖动等问题。
        * **假设输入:** HTML 中包含一个 `position: sticky` 的元素，并且页面被滚动了接近但未达到使其吸顶的位置的分数像素值。
        * **预期输出:** 粘性元素的位置保持固定，不会因为分数像素的滚动而发生不必要的移动。
    * **示例 2 (`TestDivUserScrollCallBack`):**  测试依赖于 CSS 的 `overflow: auto` 属性来创建可滚动区域。
        * **假设输入:**  HTML 中包含一个设置了 `overflow: auto` 的 `div` 元素，并且其内容超出其尺寸。
        * **预期输出:**  该 `div` 元素会出现滚动条，并且可以通过用户操作或 JavaScript 代码进行滚动。

**逻辑推理与假设输入/输出:**

大部分测试用例都围绕着模拟滚动操作和验证预期结果。上面的一些例子已经包含了假设输入和输出。再举一个更偏向内部逻辑的例子：

* **测试用例:** `TestRootFrameUserScrollCallBackCancelAnimation`
    * **假设输入:**
        1. 用户开始滚动页面（`UserScroll` 被调用）。
        2. 在滚动动画进行中，JavaScript 代码调用 `scrollableArea->SetScrollOffset()` 执行程序化滚动。
    * **预期输出:**
        1. 用户发起的滚动动画被取消。
        2. 与用户滚动操作关联的回调函数会被立即执行。
        3. 页面最终滚动到 `SetScrollOffset` 指定的位置。

**用户或编程常见的使用错误:**

* **未考虑分数像素滚动:** 开发者在计算元素位置或进行动画时，可能没有充分考虑到分数像素滚动带来的细微差异，导致布局或动画出现不精确的情况。`FractionalScrollSimTest` 中的测试可以帮助发现这类问题。
* **滚动回调函数的误解:**  开发者可能错误地认为滚动回调函数会在每次滚动位置变化时立即执行，而实际上，对于用户触发的动画滚动，回调通常在动画结束后执行。`TestRootFrameLayoutViewportUserScrollCallBack` 等测试用例强调了这一点。
* **在滚动动画过程中进行程序化滚动:**  开发者可能没有意识到在用户触发的滚动动画进行时，执行程序化滚动会取消当前的动画。`TestRootFrameUserScrollCallBackCancelAnimation` 模拟了这种情况，并验证了回调函数的行为。
* **对 RTL 或垂直书写模式下滚动行为的假设:**  开发者可能会错误地假设 `scrollLeft` 总是表示向右滚动的距离，而没有考虑到 RTL 或垂直书写模式下 `scrollLeft` 的含义可能不同。`ScrollInfacesUseCounterSimTest` 和 `ScrollPositionsInNonDefaultWritingModeSimTest` 关注了这些情况。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用 Chrome 浏览器浏览网页时遇到了滚动相关的 Bug，例如：

1. **现象：** 在某个特定的网页上，使用鼠标滚轮滚动时，页面滚动不流畅，或者某个粘性定位的元素出现抖动。
2. **开发者开始调试：**
    * 使用开发者工具查看元素的 CSS 属性，确认是否存在与滚动相关的 CSS 属性（例如 `overflow`, `position: sticky`）。
    * 使用 JavaScript 代码监听 `scroll` 事件，尝试分析滚动过程中发生的行为。
    * 如果怀疑是分数像素滚动导致的问题，可能会尝试获取元素的 `getBoundingClientRect()` 值来观察其变化。
3. **深入 Blink 引擎调试：** 如果开发者怀疑是浏览器引擎本身的问题，可能会开始阅读 Blink 引擎的源代码。
4. **定位到 `scroll_test.cc`：**
    * 开发者可能会搜索与滚动动画 (`ScrollAnimator`) 或粘性定位相关的代码。
    * 开发者可能会查看 `blink/renderer/core/scroll/` 目录下与滚动相关的源文件。
    * 看到 `scroll_test.cc` 文件名，意识到这是一个测试文件，其中包含了各种滚动场景的测试用例。
5. **分析测试用例：** 开发者可以阅读 `scroll_test.cc` 中的测试用例，找到与他们遇到的 Bug 相似的场景，例如测试分数像素滚动的用例，或者测试粘性定位的用例。
6. **运行测试或添加断点：** 开发者可以在本地编译 Blink 引擎，并运行 `scroll_test.cc` 中的特定测试用例，或者在相关的源代码中添加断点，以便更深入地了解滚动功能的内部实现和问题所在。

总而言之，`scroll_test.cc` 是 Blink 引擎中至关重要的一个测试文件，它覆盖了各种与滚动相关的场景，确保了滚动功能的正确性和稳定性。理解这个文件的内容可以帮助开发者更好地理解 Blink 引擎的滚动机制，并为调试滚动相关的 Bug 提供线索。

### 提示词
```
这是目录为blink/renderer/core/scroll/scroll_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/scroll/scroll_animator.h"

#include "base/test/bind.h"
#include "cc/base/features.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/web/web_script_source.h"
#include "third_party/blink/renderer/core/css/css_style_declaration.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/root_frame_viewport.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/paint/paint_and_raster_invalidation_test.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scroll_animator_base.h"
#include "third_party/blink/renderer/core/scroll/scrollable_area.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

namespace {
double ScrollAnimationDuration() {
  return ::features::IsImpulseScrollAnimationEnabled() ? 1.5 : 0.5;
}
}  // namespace

class FractionalScrollSimTest : public SimTest, public PaintTestConfigurations {
 public:
  FractionalScrollSimTest() : fractional_scroll_offsets_for_test_(true) {}

 private:
  ScopedFractionalScrollOffsetsForTest fractional_scroll_offsets_for_test_;
};

INSTANTIATE_PAINT_TEST_SUITE_P(FractionalScrollSimTest);

TEST_P(FractionalScrollSimTest, GetBoundingClientRectAtFractional) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body, html {
        margin: 0;
        height: 2000px;
        width: 2000px;
      }
      div {
        position: absolute;
        left: 800px;
        top: 600px;
        width: 100px;
        height: 100px;
      }
    </style>
    <body>
      <div id="target"></div>
    </body>
  )HTML");
  Compositor().BeginFrame();

  // Scroll on the layout viewport.
  GetDocument().View()->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(700.5f, 500.6f), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kInstant);

  Compositor().BeginFrame();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  DOMRect* rect = target->GetBoundingClientRect();
  const float kOneLayoutUnit = 1.f / LayoutUnit::kFixedPointDenominator;
  EXPECT_NEAR(LayoutUnit(800.f - 700.5f), rect->left(), kOneLayoutUnit);
  EXPECT_NEAR(LayoutUnit(600.f - 500.6f), rect->top(), kOneLayoutUnit);
}

TEST_P(FractionalScrollSimTest, NoRepaintOnScrollFromSubpixel) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 4000px;
      }

      #container {
        will-change:transform;
        margin-top: 300px;
      }

      #child {
        height: 100px;
        width: 100px;
        transform: translateY(-0.5px);
        background-color: coral;
      }

      #fixed {
        position: fixed;
        top: 0;
        width: 100px;
        height: 20px;
        background-color: dodgerblue
      }
    </style>

    <!-- This test no longer tests the code path when the test was added
         because the fixed element no longer triggers compositing update on
         scroll. We still keep this test to ensure no paint invalidation. -->
    <div id="fixed"></div>
    <div id="container">
        <div id="child">Child</div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  GetDocument().View()->SetTracksRasterInvalidations(true);

  // Scroll on the layout viewport.
  GetDocument().View()->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(0.f, 100.5f), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kInstant);

  Compositor().BeginFrame();
  EXPECT_FALSE(
      GetRasterInvalidationTracking(*GetDocument().View(), 0, "container")
          ->HasInvalidations());
  GetDocument().View()->SetTracksRasterInvalidations(false);
}

// Verifies that the sticky constraints are correctly computed when the scroll
// offset is fractional. Ensures any kind of layout unit snapping is
// consistent.
TEST_P(FractionalScrollSimTest, StickyDoesntOscillate) {
  WebView().MainFrameWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #sticky {
        position: sticky; top: 0; width: 100px; height: 100px;
      }
      body {
        margin: 0;
        height: 300vh;
      }
      #padding {
        height: 8px;
        width: 100%;
      }
    </style>
    <div id='padding'></div>
    <div id='sticky'></div>
  )HTML");
  Compositor().BeginFrame();

  const float kOneLayoutUnitF = LayoutUnit::Epsilon();
  Element* sticky = GetDocument().getElementById(AtomicString("sticky"));

  // Try sub-layout-unit scroll offsets. The sticky box shouldn't move.
  for (int i = 0; i < 3; ++i) {
    GetDocument().View()->GetScrollableArea()->ScrollBy(
        ScrollOffset(0.f, kOneLayoutUnitF / 4.f),
        mojom::blink::ScrollType::kProgrammatic);
    Compositor().BeginFrame();
    EXPECT_EQ(8, sticky->GetBoundingClientRect()->top());
  }

  // This offset is specifically chosen since it doesn't land on a LayoutUnit
  // boundary and reproduced https://crbug.com/1010961.
  GetDocument().View()->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(0.f, 98.8675308f), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kInstant);
  Compositor().BeginFrame();
  EXPECT_EQ(0, sticky->GetBoundingClientRect()->top());

  // Incrementally scroll from here, making sure the sticky position remains
  // fixed.
  for (int i = 0; i < 4; ++i) {
    GetDocument().View()->GetScrollableArea()->ScrollBy(
        ScrollOffset(0.f, kOneLayoutUnitF / 3.f),
        mojom::blink::ScrollType::kProgrammatic);
    Compositor().BeginFrame();
    EXPECT_EQ(0, sticky->GetBoundingClientRect()->top());
  }
}

class ScrollAnimatorSimTest : public SimTest, public PaintTestConfigurations {};

INSTANTIATE_PAINT_TEST_SUITE_P(ScrollAnimatorSimTest);

// Test that the callback of user scroll will be executed when the animation
// finishes at ScrollAnimator::TickAnimation for root frame user scroll at the
// layout viewport.
TEST_P(ScrollAnimatorSimTest, TestRootFrameLayoutViewportUserScrollCallBack) {
  GetDocument().GetFrame()->GetSettings()->SetScrollAnimatorEnabled(true);
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 500));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body, html {
        margin: 0;
        height: 500vh;
      }
    </style>
    <body>
    </body>
  )HTML");
  Compositor().BeginFrame();

  WebView().MainFrameWidget()->SetFocus(true);
  WebView().SetIsActive(true);

  // Scroll on the layout viewport.
  bool finished = false;
  GetDocument().View()->GetScrollableArea()->UserScroll(
      ui::ScrollGranularity::kScrollByLine, ScrollOffset(100, 300),
      ScrollableArea::ScrollCallback(base::BindLambdaForTesting(
          [&](ScrollableArea::ScrollCompletionMode) { finished = true; })));
  // Sync time with ScrollAnimator.
  Compositor().ResetLastFrameTime();

  Compositor().BeginFrame();
  ASSERT_FALSE(finished);

  // The callback is executed when the animation finishes at
  // ScrollAnimator::TickAnimation.
  Compositor().BeginFrame();
  Compositor().BeginFrame(ScrollAnimationDuration());
  ASSERT_TRUE(finished);
}

// Test that the callback of user scroll will be executed when the animation
// finishes at ScrollAnimator::TickAnimation for root frame user scroll at the
// visual viewport.
TEST_P(ScrollAnimatorSimTest, TestRootFrameVisualViewporUserScrollCallBack) {
  GetDocument().GetFrame()->GetSettings()->SetScrollAnimatorEnabled(true);
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 500));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body, html {
        margin: 0;
        height: 500vh;
      }
    </style>
    <body>
    </body>
  )HTML");
  Compositor().BeginFrame();

  WebView().MainFrameWidget()->SetFocus(true);
  WebView().SetIsActive(true);
  WebView().SetPageScaleFactor(2);

  // Scroll on the visual viewport.
  bool finished = false;
  GetDocument().View()->GetScrollableArea()->UserScroll(
      ui::ScrollGranularity::kScrollByLine, ScrollOffset(100, 300),
      ScrollableArea::ScrollCallback(base::BindLambdaForTesting(
          [&](ScrollableArea::ScrollCompletionMode) { finished = true; })));
  // Sync time with ScrollAnimator.
  Compositor().ResetLastFrameTime();

  Compositor().BeginFrame();
  ASSERT_FALSE(finished);

  // The callback is executed when the animation finishes at
  // ScrollAnimator::TickAnimation.
  Compositor().BeginFrame();
  Compositor().BeginFrame(ScrollAnimationDuration());
  ASSERT_TRUE(finished);
}

// Test that the callback of user scroll will be executed when the animation
// finishes at ScrollAnimator::TickAnimation for root frame user scroll at both
// the layout and visual viewport.
TEST_P(ScrollAnimatorSimTest, TestRootFrameBothViewportsUserScrollCallBack) {
  GetDocument().GetFrame()->GetSettings()->SetScrollAnimatorEnabled(true);
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 500));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body, html {
        margin: 0;
        height: 500vh;
      }
    </style>
    <body>
    </body>
  )HTML");
  Compositor().BeginFrame();

  WebView().MainFrameWidget()->SetFocus(true);
  WebView().SetIsActive(true);
  WebView().SetPageScaleFactor(2);

  // Scroll on both the layout and visual viewports.
  bool finished = false;
  GetDocument().View()->GetScrollableArea()->UserScroll(
      ui::ScrollGranularity::kScrollByLine, ScrollOffset(0, 1000),
      ScrollableArea::ScrollCallback(base::BindLambdaForTesting(
          [&](ScrollableArea::ScrollCompletionMode) { finished = true; })));
  // Sync time with ScrollAnimator.
  Compositor().ResetLastFrameTime();

  Compositor().BeginFrame();
  ASSERT_FALSE(finished);

  // The callback is executed when the animation finishes at
  // ScrollAnimator::TickAnimation.
  Compositor().BeginFrame();
  Compositor().BeginFrame(ScrollAnimationDuration());
  ASSERT_TRUE(finished);
}

// Test that the callback of user scroll will be executed when the animation
// finishes at ScrollAnimator::TickAnimation for div user scroll.
TEST_P(ScrollAnimatorSimTest, TestDivUserScrollCallBack) {
  GetDocument().GetSettings()->SetScrollAnimatorEnabled(true);
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 500));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #scroller {
        width: 100px;
        height: 100px;
        overflow: auto;
      }
      #overflow {
        height: 500px;
        width: 500px;
      }
    </style>
    <div id="scroller">
      <div id="overflow"></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  WebView().MainFrameWidget()->SetFocus(true);
  WebView().SetIsActive(true);

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));

  bool finished = false;
  PaintLayerScrollableArea* scrollable_area =
      To<LayoutBox>(scroller->GetLayoutObject())->GetScrollableArea();
  scrollable_area->UserScroll(
      ui::ScrollGranularity::kScrollByLine, ScrollOffset(0, 100),
      ScrollableArea::ScrollCallback(base::BindLambdaForTesting(
          [&](ScrollableArea::ScrollCompletionMode) { finished = true; })));
  // Sync time with ScrollAnimator.
  Compositor().ResetLastFrameTime();

  Compositor().BeginFrame();
  ASSERT_FALSE(finished);

  // The callback is executed when the animation finishes at
  // ScrollAnimator::TickAnimation.
  Compositor().BeginFrame(ScrollAnimationDuration());
  ASSERT_TRUE(finished);
}

// Test that the callback of user scroll will be executed in
// ScrollAnimatorBase::UserScroll when animation is disabled.
TEST_P(ScrollAnimatorSimTest, TestUserScrollCallBackAnimatorDisabled) {
  GetDocument().GetFrame()->GetSettings()->SetScrollAnimatorEnabled(false);
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 500));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body, html {
        margin: 0;
        height: 500vh;
      }
    </style>
    <body>
    </body>
  )HTML");
  Compositor().BeginFrame();

  WebView().MainFrameWidget()->SetFocus(true);
  WebView().SetIsActive(true);

  bool finished = false;
  GetDocument().View()->GetScrollableArea()->UserScroll(
      ui::ScrollGranularity::kScrollByLine, ScrollOffset(0, 300),
      ScrollableArea::ScrollCallback(base::BindLambdaForTesting(
          [&](ScrollableArea::ScrollCompletionMode) { finished = true; })));
  // Sync time with ScrollAnimator.
  Compositor().ResetLastFrameTime();

  Compositor().BeginFrame();
  ASSERT_TRUE(finished);
}

// Test that the callback of user scroll will be executed when the animation is
// canceled because performing a programmatic scroll in the middle of a user
// scroll will cancel the animation.
TEST_P(ScrollAnimatorSimTest, TestRootFrameUserScrollCallBackCancelAnimation) {
  GetDocument().GetFrame()->GetSettings()->SetScrollAnimatorEnabled(true);
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 500));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body, html {
        margin: 0;
        height: 500vh;
      }
    </style>
    <body>
    </body>
  )HTML");
  Compositor().BeginFrame();

  WebView().MainFrameWidget()->SetFocus(true);
  WebView().SetIsActive(true);

  // Scroll on the layout viewport.
  bool finished = false;
  GetDocument().View()->GetScrollableArea()->UserScroll(
      ui::ScrollGranularity::kScrollByLine, ScrollOffset(100, 300),
      ScrollableArea::ScrollCallback(base::BindLambdaForTesting(
          [&](ScrollableArea::ScrollCompletionMode) { finished = true; })));
  // Sync time with ScrollAnimator.
  Compositor().ResetLastFrameTime();

  Compositor().BeginFrame();
  ASSERT_FALSE(finished);

  // Programmatic scroll will cancel the current user scroll animation and the
  // callback will be executed.
  GetDocument().View()->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(0, 300), mojom::blink::ScrollType::kProgrammatic,
      mojom::blink::ScrollBehavior::kSmooth, ScrollableArea::ScrollCallback());
  Compositor().BeginFrame();
  ASSERT_TRUE(finished);
}

class ScrollInfacesUseCounterSimTest : public SimTest,
                                       public PaintTestConfigurations {
 public:
  // Reload the page, set direction and writing-mode, then check the initial
  // useCounted status.
  void Reset(const String& direction, const String& writing_mode) {
    SimRequest request("https://example.com/test.html", "text/html");
    LoadURL("https://example.com/test.html");
    request.Complete(R"HTML(
            <!DOCTYPE html>
            <style>
              #scroller {
                width: 100px;
                height: 100px;
                overflow: scroll;
              }
              #content {
                width: 300;
                height: 300;
              }
            </style>
            <div id="scroller"><div id="content"></div></div>
        )HTML");
    auto& document = GetDocument();
    auto* style = document.getElementById(AtomicString("scroller"))->style();
    style->setProperty(&Window(), "direction", direction, String(),
                       ASSERT_NO_EXCEPTION);
    style->setProperty(&Window(), "writing-mode", writing_mode, String(),
                       ASSERT_NO_EXCEPTION);
    Compositor().BeginFrame();
    EXPECT_FALSE(document.IsUseCounted(
        WebFeature::
            kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTop));
    EXPECT_FALSE(document.IsUseCounted(
        WebFeature::
            kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTopSetPositive));
  }

  // Check if Element.scrollLeft/Top could trigger useCounter as expected.
  void CheckScrollLeftOrTop(const String& command, bool exppected_use_counted) {
    String scroll_command =
        "document.querySelector('#scroller')." + command + ";";
    MainFrame().ExecuteScriptAndReturnValue(WebScriptSource(scroll_command));
    auto& document = GetDocument();
    EXPECT_EQ(
        exppected_use_counted,
        document.IsUseCounted(
            WebFeature::
                kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTop));
    EXPECT_FALSE(document.IsUseCounted(
        WebFeature::
            kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTopSetPositive));
  }

  // Check if Element.setScrollLeft/Top could trigger useCounter as expected.
  void CheckSetScrollLeftOrTop(const String& command,
                               bool exppected_use_counted) {
    String scroll_command =
        "document.querySelector('#scroller')." + command + " = -1;";
    MainFrame().ExecuteScriptAndReturnValue(WebScriptSource(scroll_command));
    auto& document = GetDocument();
    EXPECT_EQ(
        exppected_use_counted,
        document.IsUseCounted(
            WebFeature::
                kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTop));
    EXPECT_FALSE(document.IsUseCounted(
        WebFeature::
            kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTopSetPositive));
    scroll_command = "document.querySelector('#scroller')." + command + " = 1;";
    MainFrame().ExecuteScriptAndReturnValue(WebScriptSource(scroll_command));
    EXPECT_EQ(
        exppected_use_counted,
        document.IsUseCounted(
            WebFeature::
                kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTopSetPositive));
  }

  // Check if Element.scrollTo/scroll could trigger useCounter as expected.
  void CheckScrollTo(const String& command, bool exppected_use_counted) {
    String scroll_command =
        "document.querySelector('#scroller')." + command + "(-1, -1);";
    MainFrame().ExecuteScriptAndReturnValue(WebScriptSource(scroll_command));
    auto& document = GetDocument();
    EXPECT_EQ(
        exppected_use_counted,
        document.IsUseCounted(
            WebFeature::
                kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTop));
    EXPECT_FALSE(document.IsUseCounted(
        WebFeature::
            kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTopSetPositive));
    scroll_command =
        "document.querySelector('#scroller')." + command + "(1, 1);";
    MainFrame().ExecuteScriptAndReturnValue(WebScriptSource(scroll_command));
    EXPECT_EQ(
        exppected_use_counted,
        document.IsUseCounted(
            WebFeature::
                kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTopSetPositive));
  }
};

INSTANTIATE_PAINT_TEST_SUITE_P(ScrollInfacesUseCounterSimTest);

struct TestCase {
  String direction;
  String writingMode;
  bool scrollLeftUseCounted;
  bool scrollTopUseCounted;
};

TEST_P(ScrollInfacesUseCounterSimTest, ScrollTestAll) {
  v8::HandleScope handle_scope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  const Vector<TestCase> test_cases = {
      {"ltr", "horizontal-tb", false, false},
      {"rtl", "horizontal-tb", true, false},
      {"ltr", "vertical-lr", false, false},
      {"rtl", "vertical-lr", false, true},
      {"ltr", "vertical-rl", true, false},
      {"rtl", "vertical-rl", true, true},
  };

  for (const TestCase& test_case : test_cases) {
    Reset(test_case.direction, test_case.writingMode);
    CheckScrollLeftOrTop("scrollLeft", test_case.scrollLeftUseCounted);

    Reset(test_case.direction, test_case.writingMode);
    CheckSetScrollLeftOrTop("scrollLeft", test_case.scrollLeftUseCounted);

    Reset(test_case.direction, test_case.writingMode);
    CheckScrollLeftOrTop("scrollTop", test_case.scrollTopUseCounted);

    Reset(test_case.direction, test_case.writingMode);
    CheckSetScrollLeftOrTop("scrollTop", test_case.scrollTopUseCounted);

    bool expectedScrollUseCounted =
        test_case.scrollLeftUseCounted || test_case.scrollTopUseCounted;
    Reset(test_case.direction, test_case.writingMode);
    CheckScrollTo("scrollTo", expectedScrollUseCounted);

    Reset(test_case.direction, test_case.writingMode);
    CheckScrollTo("scroll", expectedScrollUseCounted);

    Reset(test_case.direction, test_case.writingMode);
    CheckScrollTo("scrollBy", false);
  }
}

class ScrollPositionsInNonDefaultWritingModeSimTest
    : public SimTest,
      public PaintTestConfigurations {};

INSTANTIATE_PAINT_TEST_SUITE_P(ScrollPositionsInNonDefaultWritingModeSimTest);

// Verify that scrollIntoView() does not trigger the use counter
// kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTopSetPositive
// and can be used to feature detect the convention of scroll coordinates.
TEST_P(ScrollPositionsInNonDefaultWritingModeSimTest,
       ScrollIntoViewAndCounters) {
  SimRequest main_resource("https://example.com/", "text/html");
  SimRequest child_frame_resource("https://example.com/subframe.html",
                                  "text/html");
  LoadURL("https://example.com/");
  // Load a page that performs feature detection of scroll behavior by relying
  // on scrollIntoView().
  main_resource.Complete(
      R"HTML(
        <body>
             <div style="direction: rtl; position: fixed; left: 0; top: 0; overflow: hidden; width: 1px; height: 1px;"><div style="width: 2px; height: 1px;"><div style="display: inline-block; width: 1px;"></div><div style="display: inline-block; width: 1px;"></div></div></div>
             <script>
               var scroller = document.body.firstElementChild;
               scroller.firstElementChild.children[0].scrollIntoView();
               var right = scroller.scrollLeft;
               scroller.firstElementChild.children[1].scrollIntoView();
               var left = scroller.scrollLeft;
               if (left < right)
                   console.log("decreasing");
               if (left < 0)
                   console.log("nonpositive");
             </script>
        </body>)HTML");
  Compositor().BeginFrame();
  test::RunPendingTasks();
  // Per the CSSOM specification, the standard behavior is:
  // - decreasing coordinates when scrolling leftward.
  // - nonpositive coordinates for leftward scroller.
  EXPECT_TRUE(ConsoleMessages().Contains("decreasing"));
  EXPECT_TRUE(ConsoleMessages().Contains("nonpositive"));
  // Reading scrollLeft triggers the first counter:
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::
          kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTop));
  // However, calling scrollIntoView() should not trigger the second counter:
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::
          kElementWithLeftwardOrUpwardOverflowDirection_ScrollLeftOrTopSetPositive));
}

}  // namespace blink
```