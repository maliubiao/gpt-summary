Response:
My thought process for analyzing the provided C++ test file goes like this:

1. **Understand the Goal:** The request asks for a summary of the file's functionality, its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, and potential user/programming errors. It's also explicitly stated to be part 1 of 3. Therefore, the summary should focus on the content within *this specific part*.

2. **Identify Key Components:** I scanned the code for important classes, functions, and patterns. The filename `layout_box_model_object_test.cc` immediately suggests that the tests are focused on the `LayoutBoxModelObject` class. The inclusion of gmock and gtest confirms it's a unit test file. Looking at the includes, I see:
    * `LayoutBoxModelObject.h`:  The main class under test.
    * DOM-related headers (`DocumentLifecycle.h`, `DOMTokenList.h`, `LocalDOMWindow.h`, `HTMLElement.h`):  This indicates interaction with the Document Object Model.
    * Layout-related headers (`PhysicalBoxFragment.h`): Further confirms the focus on layout.
    * Paint-related headers (`PaintLayer.h`, `PaintLayerScrollableArea.h`): Hints at testing aspects related to rendering and scrolling.
    * Testing utilities (`core_unit_test_helper.h`, `paint_test_configurations.h`): Standard Blink testing infrastructure.

3. **Analyze the Test Fixture:** The `LayoutBoxModelObjectTest` class inherits from `RenderingTest` and `PaintTestConfigurations`. This tells me the tests will involve setting up a rendering environment and likely performing visual verifications (although this specific part doesn't show explicit visual checks). The helper function `GetLayoutBoxModelObjectByElementId` clearly indicates the tests are designed to interact with elements in an HTML structure. The `HasStickyLayer` function signals tests related to sticky positioning.

4. **Examine Individual Tests:** I went through each `TEST_P` block and noted its name and the core functionality it seems to be testing:
    * `LocalCaretRectForEmptyElementVertical`:  Testing caret positioning in elements with vertical writing modes.
    * `BorderAndPaddingLogicalLeftRight`:  Verifying how border and padding are applied in different writing modes.
    * `StickyPositionConstraints`:  Testing the calculation of sticky positioning constraints. This is a recurring theme with several variations.
    * `StickyPositionVerticalRLConstraints`: Sticky positioning in vertical-rl writing mode.
    * `StickyPositionInlineConstraints`: Sticky positioning for inline elements.
    * `StickyPositionVerticalRLInlineConstraints`: Sticky positioning for inline elements with vertical writing mode.
    * `StickyPositionTransforms`: Impact of CSS transforms on sticky positioning.
    * `StickyPositionPercentageStyles`: Sticky positioning with percentage-based styles.
    * `StickyPositionContainerIsScroller`: Sticky element when its container is the scroller.
    * `StickyPositionAnonymousContainer`: Sticky element within an anonymous container.
    * `StickyPositionTableContainers`: Sticky elements within table structures.
    * `StickyPositionConstraintInvalidation`: Testing when sticky constraints need to be recalculated.
    * `StickyPositionStatusChange`: Testing how sticky behavior changes when CSS properties are modified.
    * `StickyPositionFindsCorrectStickyBoxShiftingAncestor`: Testing the logic for finding the correct ancestor for sticky positioning.
    * `StickyPositionFindsCorrectContainingBlockShiftingAncestor`:  Testing the logic for finding the correct containing block ancestor for sticky positioning.

5. **Identify Relationships with Web Technologies:**  Based on the test names and the included headers, the connection to HTML, CSS, and (implicitly) JavaScript became clear:
    * **HTML:** The tests load HTML snippets using `SetBodyInnerHTML`. They use element IDs to target specific elements (`GetLayoutBoxByElementId`).
    * **CSS:** The tests manipulate CSS properties like `writing-mode`, `border`, `padding`, `position: sticky`, `top`, `width`, `height`, `transform`, `display`, etc. They verify how these properties affect layout and sticky positioning.
    * **JavaScript (Implicit):** While no explicit JavaScript code is shown in *this part*, the tests are verifying the *results* of CSS properties which are often manipulated or interacted with via JavaScript in a web browser. The DOM manipulation (`classList().Add`) also points to JavaScript interaction.

6. **Look for Logical Reasoning and Examples:** The tests themselves are examples of logical reasoning. They set up specific scenarios (HTML structure and CSS styles) and then assert expected outcomes. For instance, in `BorderAndPaddingLogicalLeftRight`, the test reasons about how logical properties map to physical properties based on writing mode. I looked for specific examples of assumptions and outputs within the test code.

7. **Consider Potential Errors:**  I considered what mistakes developers might make that these tests are designed to catch. These include:
    * Incorrect calculation of border and padding in different writing modes.
    * Errors in computing sticky positioning constraints.
    * Incorrect handling of sticky positioning with transforms or percentage-based styles.
    * Issues with sticky positioning in complex layout scenarios (tables, anonymous containers).
    * Not invalidating sticky constraints when relevant changes occur.
    * Memory leaks or dangling pointers when sticky status changes.
    * Incorrectly identifying ancestor elements for sticky positioning.

8. **Synthesize the Summary (Part 1):**  Based on the analysis above, I formulated the summary, focusing on:
    * Testing `LayoutBoxModelObject`.
    * Verifying layout calculations (caret position, border/padding).
    * Thoroughly testing sticky positioning constraints in various scenarios (writing modes, inline elements, transforms, percentages, container relationships, table elements).
    * Checking constraint invalidation and status changes.
    * Emphasizing the connection to HTML and CSS through the manipulation of elements and styles.
    * Providing concrete examples from the tests to illustrate the logical reasoning and potential errors.
    * Acknowledging the "Part 1" designation.

This methodical approach allowed me to dissect the code, understand its purpose, and generate a comprehensive summary addressing all aspects of the request.
```
功能归纳：

这个C++源代码文件 `layout_box_model_object_test.cc` 是 Chromium Blink 引擎的一部分，专门用于测试 `LayoutBoxModelObject` 类的功能。`LayoutBoxModelObject` 是 Blink 渲染引擎中负责处理盒子模型布局的核心类之一。

**主要功能可以归纳为：**

1. **测试 `LayoutBoxModelObject` 的各种布局计算和属性处理。**  这包括但不限于：
    * 计算光标在空元素中的位置（`LocalCaretRectForEmptyElementVertical`）。
    * 根据书写模式（`writing-mode`）计算边框和内边距的逻辑起始和结束位置（`BorderAndPaddingLogicalLeftRight`）。
    * 计算粘性定位（`position: sticky`）元素的约束条件（`StickyPositionConstraints` 系列测试）。这包括在不同书写模式、内联元素、包含块、变换、百分比样式、以及表格等复杂场景下的测试。
    * 测试粘性定位约束的失效机制（`StickyPositionConstraintInvalidation`）。
    * 测试粘性定位状态改变时的行为，例如从 sticky 变为 static 或 relative（`StickyPositionStatusChange`）。
    * 测试寻找正确的粘性定位盒模型移动祖先和包含块移动祖先的逻辑（`StickyPositionFindsCorrectStickyBoxShiftingAncestor` 和 `StickyPositionFindsCorrectContainingBlockShiftingAncestor`）。

2. **验证 `LayoutBoxModelObject` 与其他 Blink 渲染引擎组件的交互。**  例如，它会涉及到与 `PaintLayer` (绘制层) 和 `PaintLayerScrollableArea` (可滚动区域的绘制层) 的交互，尤其是在测试粘性定位时。

3. **提供单元测试用例，确保 `LayoutBoxModelObject` 类的稳定性和正确性。** 这些测试用例覆盖了各种可能的输入和场景，帮助开发者在修改代码后及时发现潜在的 bug。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件直接关系到 HTML 和 CSS 的渲染和布局，JavaScript 通过操作 DOM 和 CSSOM 来影响这些过程。

* **HTML:**  测试用例中会使用 `SetBodyInnerHTML()` 方法加载 HTML 代码片段，这些 HTML 代码定义了不同的元素结构和属性，用于测试 `LayoutBoxModelObject` 在不同 HTML 结构下的行为。
    * **举例:**  `<div id='target-rl' class="target"></div>`  这个 HTML `div` 元素被用于测试在 `writing-mode: vertical-rl` 下的光标位置。

* **CSS:** 测试用例会使用 CSS 样式来控制元素的布局属性，例如 `writing-mode`, `border`, `padding`, `position: sticky`, `top`, `width`, `height` 等。测试会验证 `LayoutBoxModelObject` 是否正确地解释和应用这些 CSS 样式。
    * **举例:**
        ```css
        .target {
          border-color: red;
          border-style: solid;
          border-width: 2px 4px 11px 13px;
          padding: 1px 3px 5px 7px;
          block-size: 40px;
          inline-size: 33px;
        }
        #target-htb {
          writing-mode: horizontal-tb;
        }
        ```
        这段 CSS 代码定义了一个名为 `target` 的类的样式，并为 id 为 `target-htb` 的元素设置了 `writing-mode`。测试 `BorderAndPaddingLogicalLeftRight` 会验证在这个样式下，边框和内边距的逻辑起始和结束位置是否计算正确。

* **JavaScript:** 虽然这个文件本身是 C++ 代码，但它测试的是 Blink 引擎中负责渲染和布局的部分，而这些部分最终会受到 JavaScript 的影响。JavaScript 可以通过 DOM API 修改 HTML 结构和 CSS 样式，从而触发 Blink 引擎重新布局和渲染。这个测试文件确保了当 JavaScript 操作影响布局时，Blink 引擎的行为是正确的。
    * **举例:**  在 `StickyPositionStatusChange` 测试中，使用了 JavaScript 风格的 `sticky->setAttribute(html_names::kStyleAttr, ...)` 来动态修改元素的 style 属性，模拟 JavaScript 对 CSS 的修改，并测试 `LayoutBoxModelObject` 对这些修改的响应。

**逻辑推理的假设输入与输出：**

* **假设输入 (针对 `BorderAndPaddingLogicalLeftRight` 测试):**
    * HTML: `<div id='target-vrl' class="target"></div>`
    * CSS:
        ```css
        .target {
          border-width: 2px 4px 11px 13px; /* top right bottom left */
          padding: 1px 3px 5px 7px;      /* top right bottom left */
        }
        #target-vrl {
          writing-mode: vertical-rl;
        }
        ```
* **逻辑推理:**  当 `writing-mode` 为 `vertical-rl` 时，元素的逻辑内联起始边对应物理上的顶部边，逻辑内联结束边对应物理上的底部边。因此，`BorderAndPaddingInlineStart()` 应该返回顶部边框加顶部内边距的值，`BorderAndPaddingInlineEnd()` 应该返回底部边框加底部内边距的值。
* **预期输出:**
    * `target->BorderAndPaddingInlineStart()`  等于 `2 + 1 = 3` (kTop)
    * `target->BorderAndPaddingInlineEnd()` 等于 `11 + 5 = 16` (kBottom)

* **假设输入 (针对 `StickyPositionConstraints` 测试):**
    * HTML 和 CSS 如测试用例中所示，定义了一个包含粘性定位元素的滚动容器。
* **逻辑推理:**  粘性定位元素的约束条件取决于其包含块、滚动容器以及自身的布局属性。测试会计算出粘性元素在滚动容器中的相对位置和约束矩形。
* **预期输出:**  测试会断言 `constraints->scroll_container_relative_containing_block_rect` 和 `constraints->scroll_container_relative_sticky_box_rect` 等属性的值与预期一致，这些值代表了在特定滚动位置下，包含块和粘性元素相对于滚动容器的矩形区域。

**涉及用户或编程常见的使用错误：**

* **CSS 书写模式与边框/内边距的混淆:**  开发者可能会错误地认为在任何书写模式下，`border-left` 总是对应物理上的左边。但实际上，在垂直书写模式下，逻辑上的 `inline-start` 和 `inline-end` 会映射到不同的物理边。测试 `BorderAndPaddingLogicalLeftRight` 帮助验证 Blink 引擎是否正确处理了这种情况。
    * **错误示例:**  开发者可能在 `writing-mode: vertical-rl` 的元素上设置 `border-left` 并期望它出现在元素的左侧，但实际上它会出现在顶部。

* **粘性定位的包含块理解错误:**  开发者可能不清楚粘性定位元素的“粘性”是相对于哪个包含块生效的。如果包含块的尺寸不正确或者没有正确设置滚动容器，粘性定位可能不会按预期工作。`StickyPositionConstraints` 系列的测试用例覆盖了各种包含块和滚动容器的场景，以确保 Blink 引擎的实现符合规范。
    * **错误示例:**  开发者可能在一个没有设置 `overflow: auto` 或 `overflow: scroll` 的父元素内使用粘性定位，导致粘性效果失效。

* **动态修改样式导致粘性定位状态不一致:**  JavaScript 动态修改元素的 `position` 或其他影响粘性定位的 CSS 属性时，如果 Blink 引擎没有正确更新布局和约束条件，可能会导致渲染错误。`StickyPositionStatusChange` 测试验证了 Blink 引擎在这些场景下的行为。
    * **错误示例:**  JavaScript 先将元素的 `position` 设置为 `sticky`，然后在滚动事件中将其动态修改为 `fixed` 或 `relative`，开发者需要确保这种切换不会导致渲染问题。

**总结 (第 1 部分功能):**

这部分测试代码主要集中在对 `LayoutBoxModelObject` 类中关于基本布局属性计算（如光标位置、边框内边距）以及粘性定位功能的测试。它通过创建各种 HTML 和 CSS 场景，验证了 Blink 引擎在处理这些布局特性时的正确性，并覆盖了多种可能的用户使用场景和潜在的错误情况。这些测试对于确保 Blink 引擎的布局功能符合 Web 标准至关重要。
```
Prompt: 
```
这是目录为blink/renderer/core/layout/layout_box_model_object_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/document_lifecycle.h"
#include "third_party/blink/renderer/core/dom/dom_token_list.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/page/scrolling/sticky_position_scrolling_constraints.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"

namespace blink {

class LayoutBoxModelObjectTest : public RenderingTest,
                                 public PaintTestConfigurations {
 protected:
  LayoutBoxModelObject* GetLayoutBoxModelObjectByElementId(const char* id) {
    return To<LayoutBoxModelObject>(GetLayoutObjectByElementId(id));
  }

  bool HasStickyLayer(const PaintLayerScrollableArea* scrollable_area,
                      const LayoutBoxModelObject* sticky) {
    for (const auto& fragment :
         scrollable_area->GetLayoutBox()->PhysicalFragments()) {
      if (auto* sticky_descendants = fragment.StickyDescendants()) {
        if (sticky_descendants->Contains(sticky)) {
          return true;
        }
      }
    }
    return false;
  }
};

INSTANTIATE_PAINT_TEST_SUITE_P(LayoutBoxModelObjectTest);

// This test doesn't need to be a parameterized test.
TEST_P(LayoutBoxModelObjectTest, LocalCaretRectForEmptyElementVertical) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
    body {
      font: 10px Ahem;
    }
    .target {
      padding: 1px 3px 5px 7px;
      block-size: 40px;
      inline-size: 33px;
    }
    #target-rl {
      writing-mode: vertical-rl;
    }
    #target-lr {
      writing-mode: vertical-lr;
    }
    </style>
    <div id='target-rl' class="target"></div>
    <div id='target-lr' class="target"></div>

    <div style="writing-mode:vertical-rl;">
    <br>
    <span id="target-inline-rl" class="target"></span>
    </div>

    <div style="writing-mode:vertical-lr;">
    <br>
    <span id="target-inline-lr" class="target"></span>
    </div>
  })HTML");

  constexpr LayoutUnit kPaddingTop = LayoutUnit(1);
  constexpr LayoutUnit kPaddingRight = LayoutUnit(3);
  constexpr LayoutUnit kPaddingLeft = LayoutUnit(7);
  constexpr LayoutUnit kFontHeight = LayoutUnit(10);
  constexpr LayoutUnit kCaretWidth = LayoutUnit(1);

  {
    auto* rl = GetLayoutBoxByElementId("target-rl");
    EXPECT_EQ(PhysicalRect(rl->Size().width - kPaddingRight - kFontHeight,
                           kPaddingTop, kFontHeight, kCaretWidth),
              rl->LocalCaretRect(0));
  }
  {
    auto* lr = GetLayoutBoxByElementId("target-lr");
    EXPECT_EQ(PhysicalRect(kPaddingLeft, kPaddingTop, kFontHeight, kCaretWidth),
              lr->LocalCaretRect(0));
  }
  {
    auto* inline_rl =
        To<LayoutInline>(GetLayoutObjectByElementId("target-inline-rl"));
    EXPECT_EQ(PhysicalRect(LayoutUnit(), kPaddingTop - kCaretWidth, kFontHeight,
                           kCaretWidth),
              inline_rl->LocalCaretRect(0));
  }
  {
    auto* inline_lr =
        To<LayoutInline>(GetLayoutObjectByElementId("target-inline-lr"));
    EXPECT_EQ(PhysicalRect(kFontHeight, kPaddingTop - kCaretWidth, kFontHeight,
                           kCaretWidth),
              inline_lr->LocalCaretRect(0));
  }
}

TEST_P(LayoutBoxModelObjectTest, BorderAndPaddingLogicalLeftRight) {
  SetBodyInnerHTML(R"HTML(
    <style>
    .target {
      border-color: red;
      border-style: solid;
      border-width: 2px 4px 11px 13px;
      padding: 1px 3px 5px 7px;
      block-size: 40px;
      inline-size: 33px;
    }
    #target-htb {
      writing-mode: horizontal-tb;
    }
    #target-vrl {
      writing-mode: vertical-rl;
    }
    #target-vlr {
      writing-mode: vertical-lr;
    }
    #target-srl {
      writing-mode: sideways-rl;
    }
    #target-slr {
      writing-mode: sideways-lr;
    }
    </style>
    <div id='target-htb' class="target"></div>
    <div id='target-vrl' class="target"></div>
    <div id='target-vlr' class="target"></div>
    <div id='target-srl' class="target"></div>
    <div id='target-slr' class="target"></div>
  })HTML");

  constexpr LayoutUnit kTop = LayoutUnit(2 + 1);
  constexpr LayoutUnit kRight = LayoutUnit(4 + 3);
  constexpr LayoutUnit kBottom = LayoutUnit(11 + 5);
  constexpr LayoutUnit kLeft = LayoutUnit(13 + 7);

  {
    auto* target = GetLayoutBoxByElementId("target-htb");
    EXPECT_EQ(kLeft, target->BorderAndPaddingInlineStart());
    EXPECT_EQ(kRight, target->BorderAndPaddingInlineEnd());
  }
  {
    auto* target = GetLayoutBoxByElementId("target-vrl");
    EXPECT_EQ(kTop, target->BorderAndPaddingInlineStart());
    EXPECT_EQ(kBottom, target->BorderAndPaddingInlineEnd());
  }
  {
    auto* target = GetLayoutBoxByElementId("target-vlr");
    EXPECT_EQ(kTop, target->BorderAndPaddingInlineStart());
    EXPECT_EQ(kBottom, target->BorderAndPaddingInlineEnd());
  }
  {
    auto* target = GetLayoutBoxByElementId("target-srl");
    EXPECT_EQ(kTop, target->BorderAndPaddingInlineStart());
    EXPECT_EQ(kBottom, target->BorderAndPaddingInlineEnd());
  }
  {
    auto* target = GetLayoutBoxByElementId("target-slr");
    EXPECT_EQ(kBottom, target->BorderAndPaddingInlineStart());
    EXPECT_EQ(kTop, target->BorderAndPaddingInlineEnd());
  }
}

// Verifies that the sticky constraints are correctly computed.
TEST_P(LayoutBoxModelObjectTest, StickyPositionConstraints) {
  SetBodyInnerHTML(R"HTML(
    <style>#sticky { position: sticky; top: 0; width: 100px; height: 100px;
    }
    #container { box-sizing: border-box; position: relative; top: 100px;
    height: 400px; width: 200px; padding: 10px; border: 5px solid black; }
    #scroller { width: 400px; height: 100px; overflow: auto;
    position: relative; top: 200px; border: 2px solid black; }
    .spacer { height: 1000px; }</style>
    <div id='scroller'><div id='container'><div
    id='sticky'></div></div><div class='spacer'></div></div>
  )HTML");
  auto* scroller = GetLayoutBoxModelObjectByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollOffsetInt().x(), 50));
  ASSERT_EQ(50.0, scrollable_area->ScrollPosition().y());
  auto* sticky = GetLayoutBoxModelObjectByElementId("sticky");
  ASSERT_EQ(scroller->Layer(),
            sticky->Layer()->ContainingScrollContainerLayer());

  const auto* constraints = sticky->StickyConstraints();
  ASSERT_TRUE(constraints);
  EXPECT_TRUE(HasStickyLayer(scrollable_area, sticky));
  ASSERT_EQ(0.f, constraints->top_inset->ToFloat());

  // The coordinates of the constraint rects should all be with respect to the
  // unscrolled scroller.
  ASSERT_EQ(gfx::Rect(15, 115, 170, 370),
            ToEnclosingRect(
                constraints->scroll_container_relative_containing_block_rect));
  ASSERT_EQ(
      gfx::Rect(15, 115, 100, 100),
      ToEnclosingRect(constraints->scroll_container_relative_sticky_box_rect));

  // The sticky constraining rect also doesn't include the border offset.
  ASSERT_EQ(gfx::Rect(0, 0, 400, 100),
            ToEnclosingRect(constraints->constraining_rect));
}

// Verifies that the sticky constraints are correctly computed in right to left.
TEST_P(LayoutBoxModelObjectTest, StickyPositionVerticalRLConstraints) {
  SetBodyInnerHTML(R"HTML(
    <style> html { -webkit-writing-mode: vertical-rl; }
    #sticky { position: sticky; top: 0; width: 100px; height: 100px;
    }
    #container { box-sizing: border-box; position: relative; top: 100px;
    height: 400px; width: 200px; padding: 10px; border: 5px solid black; }
    #scroller { width: 400px; height: 100px; overflow: auto;
    position: relative; top: 200px; border: 2px solid black; }
    .spacer { height: 1000px; }</style>
    <div id='scroller'><div id='container'><div
    id='sticky'></div></div><div class='spacer'></div></div>
  )HTML");
  auto* scroller = GetLayoutBoxModelObjectByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollOffsetInt().x(), 50));
  ASSERT_EQ(50.0, scrollable_area->ScrollPosition().y());
  auto* sticky = GetLayoutBoxModelObjectByElementId("sticky");
  ASSERT_EQ(scroller->Layer(),
            sticky->Layer()->ContainingScrollContainerLayer());

  const auto* constraints = sticky->StickyConstraints();
  ASSERT_TRUE(constraints);
  EXPECT_TRUE(HasStickyLayer(scrollable_area, sticky));

  // The coordinates of the constraint rects should all be with respect to the
  // unscrolled scroller.
  ASSERT_EQ(gfx::Rect(215, 115, 170, 370),
            ToEnclosingRect(
                constraints->scroll_container_relative_containing_block_rect));
  ASSERT_EQ(
      gfx::Rect(285, 115, 100, 100),
      ToEnclosingRect(constraints->scroll_container_relative_sticky_box_rect));

  // The sticky constraining rect also doesn't include the border offset.
  ASSERT_EQ(gfx::Rect(0, 0, 400, 100),
            ToEnclosingRect(constraints->constraining_rect));
}

// Verifies that the sticky constraints are correctly computed for inline.
TEST_P(LayoutBoxModelObjectTest, StickyPositionInlineConstraints) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      .scroller { overflow: scroll; width: 100px; height: 100px; top: 100px;
          position: absolute; }
      .container { position: relative; top: 100px; height: 400px;
        width: 200px; }
      .sticky_box { width: 10px; height: 10px; top: 10px; position: sticky; }
      .inline { display: inline-block; }
      .spacer { height: 2000px; }
    </style>
    <div class='scroller' id='scroller'>
      <div class='container'>
        <div class='inline sticky_box' id='sticky'></div>
      </div>
      <div class='spacer'></div>
    </div>
  )HTML");

  auto* scroller = GetLayoutBoxModelObjectByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollOffsetInt().x(), 50));
  EXPECT_EQ(50.f, scrollable_area->ScrollPosition().y());
  auto* sticky = GetLayoutBoxModelObjectByElementId("sticky");


  EXPECT_EQ(scroller->Layer(),
            sticky->Layer()->ContainingScrollContainerLayer());

  const auto* constraints = sticky->StickyConstraints();
  ASSERT_TRUE(constraints);
  EXPECT_TRUE(HasStickyLayer(scrollable_area, sticky));
  EXPECT_EQ(10.f, constraints->top_inset->ToFloat());

  // The coordinates of the constraint rects should all be with respect to the
  // unscrolled scroller.
  EXPECT_EQ(gfx::Rect(0, 100, 200, 400),
            ToEnclosingRect(
                constraints->scroll_container_relative_containing_block_rect));
  EXPECT_EQ(
      gfx::Rect(0, 100, 10, 10),
      ToEnclosingRect(constraints->scroll_container_relative_sticky_box_rect));
  EXPECT_EQ(gfx::Rect(0, 0, 100, 100),
            ToEnclosingRect(constraints->constraining_rect));
}

// Verifies that the sticky constraints are correctly computed for sticky with
// writing mode.
TEST_P(LayoutBoxModelObjectTest, StickyPositionVerticalRLInlineConstraints) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
      .scroller { writing-mode: vertical-rl; overflow: scroll; width: 100px;
          height: 100px; top: 100px; position: absolute; }
      .container { position: relative; top: 100px; height: 400px;
        width: 200px; }
      .sticky_box { width: 10px; height: 10px; top: 10px; position: sticky; }
      .inline { display: inline-block; }
      .spacer { width: 2000px; height: 2000px; }
    </style>
    <div class='scroller' id='scroller'>
      <div class='container'>
        <div class='inline sticky_box' id='sticky'></div>
      </div>
      <div class='spacer'></div>
    </div>
  )HTML");
  // Initial layout:
  // 0---------------2000----2200
  // -----spacer-----
  //                 container---
  //                 ----2100----
  //                     scroller
  //                     ----2190
  //                         sticky
  auto* scroller = GetLayoutBoxModelObjectByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollPosition().x(), 50));
  EXPECT_EQ(50.f, scrollable_area->ScrollPosition().y());
  auto* sticky = GetLayoutBoxModelObjectByElementId("sticky");

  EXPECT_EQ(scroller->Layer(),
            sticky->Layer()->ContainingScrollContainerLayer());

  const auto* constraints = sticky->StickyConstraints();
  ASSERT_TRUE(constraints);
  EXPECT_TRUE(HasStickyLayer(scrollable_area, sticky));
  EXPECT_EQ(10.f, constraints->top_inset->ToFloat());

  // The coordinates of the constraint rects should all be with respect to the
  // unscrolled scroller.
  EXPECT_EQ(gfx::Rect(2000, 100, 200, 400),
            ToEnclosingRect(
                constraints->scroll_container_relative_containing_block_rect));
  EXPECT_EQ(
      gfx::Rect(2190, 100, 10, 10),
      ToEnclosingRect(constraints->scroll_container_relative_sticky_box_rect));
  EXPECT_EQ(gfx::Rect(0, 0, 100, 100),
            ToEnclosingRect(constraints->constraining_rect));
}

// Verifies that the sticky constraints are not affected by transforms
TEST_P(LayoutBoxModelObjectTest, StickyPositionTransforms) {
  SetBodyInnerHTML(R"HTML(
    <style>#sticky { position: sticky; top: 0; width: 100px; height: 100px;
    transform: scale(2); transform-origin: top left; }
    #container { box-sizing: border-box; position: relative; top: 100px;
    height: 400px; width: 200px; padding: 10px; border: 5px solid black;
    transform: scale(2); transform-origin: top left; }
    #scroller { height: 100px; overflow: auto; position: relative; top:
    200px; }
    .spacer { height: 1000px; }</style>
    <div id='scroller'><div id='container'><div
    id='sticky'></div></div><div class='spacer'></div></div>
  )HTML");
  auto* scroller = GetLayoutBoxModelObjectByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollOffsetInt().x(), 50));
  ASSERT_EQ(50.0, scrollable_area->ScrollPosition().y());
  auto* sticky = GetLayoutBoxModelObjectByElementId("sticky");
  ASSERT_EQ(scroller->Layer(),
            sticky->Layer()->ContainingScrollContainerLayer());

  const auto* constraints = sticky->StickyConstraints();
  ASSERT_TRUE(constraints);
  EXPECT_TRUE(HasStickyLayer(scrollable_area, sticky));
  ASSERT_EQ(0.f, constraints->top_inset->ToFloat());

  // The coordinates of the constraint rects should all be with respect to the
  // unscrolled scroller.
  ASSERT_EQ(gfx::Rect(15, 115, 170, 370),
            ToEnclosingRect(
                constraints->scroll_container_relative_containing_block_rect));
  ASSERT_EQ(
      gfx::Rect(15, 115, 100, 100),
      ToEnclosingRect(constraints->scroll_container_relative_sticky_box_rect));
}

// Verifies that the sticky constraints are correctly computed.
TEST_P(LayoutBoxModelObjectTest, StickyPositionPercentageStyles) {
  SetBodyInnerHTML(R"HTML(
    <style>#sticky { position: sticky; margin-top: 10%; top: 0; width:
    100px; height: 100px; }
    #container { box-sizing: border-box; position: relative; top: 100px;
    height: 400px; width: 250px; padding: 5%; border: 5px solid black; }
    #scroller { width: 400px; height: 100px; overflow: auto; position:
    relative; top: 200px; }
    .spacer { height: 1000px; }</style>
    <div id='scroller'><div id='container'><div
    id='sticky'></div></div><div class='spacer'></div></div>
  )HTML");
  auto* scroller = GetLayoutBoxModelObjectByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollPosition().x(), 50));
  ASSERT_EQ(50.0, scrollable_area->ScrollPosition().y());
  auto* sticky = GetLayoutBoxModelObjectByElementId("sticky");
  ASSERT_EQ(scroller->Layer(),
            sticky->Layer()->ContainingScrollContainerLayer());

  const auto* constraints = sticky->StickyConstraints();
  ASSERT_TRUE(constraints);
  EXPECT_TRUE(HasStickyLayer(scrollable_area, sticky));
  ASSERT_EQ(0.f, constraints->top_inset->ToFloat());

  if (RuntimeEnabledFeatures::LayoutIgnoreMarginsForStickyEnabled()) {
    ASSERT_EQ(
        gfx::Rect(25, 125, 200, 350),
        ToEnclosingRect(
            constraints->scroll_container_relative_containing_block_rect));
  } else {
    ASSERT_EQ(
        gfx::Rect(25, 145, 200, 330),
        ToEnclosingRect(
            constraints->scroll_container_relative_containing_block_rect));
  }
  ASSERT_EQ(
      gfx::Rect(25, 145, 100, 100),
      ToEnclosingRect(constraints->scroll_container_relative_sticky_box_rect));
}

// Verifies that the sticky constraints are correct when the sticky position
// container is also the ancestor scroller.
TEST_P(LayoutBoxModelObjectTest, StickyPositionContainerIsScroller) {
  SetBodyInnerHTML(R"HTML(
    <style>#sticky { position: sticky; top: 0; width: 100px; height: 100px;
    }
    #scroller { height: 100px; width: 400px; overflow: auto; position:
    relative; top: 200px; border: 2px solid black; }
    .spacer { height: 1000px; }</style>
    <div id='scroller'><div id='sticky'></div><div
    class='spacer'></div></div>
  )HTML");
  auto* scroller = GetLayoutBoxModelObjectByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollPosition().x(), 50));
  ASSERT_EQ(50.0, scrollable_area->ScrollPosition().y());
  auto* sticky = GetLayoutBoxModelObjectByElementId("sticky");
  ASSERT_EQ(scroller->Layer(),
            sticky->Layer()->ContainingScrollContainerLayer());

  const auto* constraints = sticky->StickyConstraints();
  ASSERT_TRUE(constraints);
  EXPECT_TRUE(HasStickyLayer(scrollable_area, sticky));
  ASSERT_EQ(gfx::Rect(0, 0, 400, 1100),
            ToEnclosingRect(
                constraints->scroll_container_relative_containing_block_rect));
  ASSERT_EQ(
      gfx::Rect(0, 0, 100, 100),
      ToEnclosingRect(constraints->scroll_container_relative_sticky_box_rect));
}

// Verifies that the sticky constraints are correct when the sticky position
// object has an anonymous containing block.
TEST_P(LayoutBoxModelObjectTest, StickyPositionAnonymousContainer) {
  SetBodyInnerHTML(R"HTML(
    <style>#sticky { display: inline-block; position: sticky; top: 0;
    width: 100px; height: 100px; }
    #container { box-sizing: border-box; position: relative; top: 100px;
    height: 400px; width: 200px; padding: 10px; border: 5px solid black; }
    #scroller { height: 100px; overflow: auto; position: relative; top:
    200px; }
    .header { height: 50px; }
    .spacer { height: 1000px; }</style>
    <div id='scroller'><div id='container'><div class='header'></div><div
    id='sticky'></div></div><div class='spacer'></div></div>
  )HTML");
  auto* scroller = GetLayoutBoxModelObjectByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->ScrollToAbsolutePosition(
      gfx::PointF(scrollable_area->ScrollPosition().x(), 50));
  ASSERT_EQ(50.0, scrollable_area->ScrollPosition().y());
  auto* sticky = GetLayoutBoxModelObjectByElementId("sticky");
  ASSERT_EQ(scroller->Layer(),
            sticky->Layer()->ContainingScrollContainerLayer());

  const auto* constraints = sticky->StickyConstraints();
  ASSERT_TRUE(constraints);
  EXPECT_TRUE(HasStickyLayer(scrollable_area, sticky));

  ASSERT_EQ(gfx::Rect(15, 115, 170, 370),
            ToEnclosingRect(
                constraints->scroll_container_relative_containing_block_rect));
  ASSERT_EQ(
      gfx::Rect(15, 165, 100, 100),
      ToEnclosingRect(constraints->scroll_container_relative_sticky_box_rect));
}

TEST_P(LayoutBoxModelObjectTest, StickyPositionTableContainers) {
  SetBodyInnerHTML(R"HTML(
    <style> td, th { height: 50px; width: 50px; }
    #sticky { position: sticky; left: 0; will-change: transform; }
    table {border: none; }
    #scroller { overflow: auto; }
    </style>
    <div id='scroller'>
    <table cellspacing='0' cellpadding='0'>
        <thead><tr><td></td></tr></thead>
        <tr><td id='sticky'></td></tr>
    </table></div>
  )HTML");
  auto* scroller = GetLayoutBoxModelObjectByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  auto* sticky = GetLayoutBoxModelObjectByElementId("sticky");

  const auto* constraints = sticky->StickyConstraints();
  ASSERT_TRUE(constraints);
  EXPECT_TRUE(HasStickyLayer(scrollable_area, sticky));

  EXPECT_EQ(gfx::Rect(0, 0, 50, 100),
            ToEnclosingRect(
                constraints->scroll_container_relative_containing_block_rect));
  EXPECT_EQ(
      gfx::Rect(0, 50, 50, 50),
      ToEnclosingRect(constraints->scroll_container_relative_sticky_box_rect));
}

// Tests that when a non-layer changes size it invalidates the constraints for
// sticky position elements within the same scroller.
TEST_P(LayoutBoxModelObjectTest, StickyPositionConstraintInvalidation) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #scroller { overflow: auto; display: flex; width: 200px; }
    #target { width: 50px; }
    #sticky { position: sticky; top: 0; }
    .container { width: 100px; margin-left: auto; margin-right: auto; }
    .hide { display: none; }
    </style>
    <div id='scroller'>
      <div style='flex: 1'>
        <div class='container'><div id='sticky'></div>
      </div>
    </div>
    <div class='spacer' id='target'></div>
    </div>
  )HTML");
  auto* scroller = GetLayoutBoxModelObjectByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  auto* sticky = GetLayoutBoxModelObjectByElementId("sticky");
  auto* target = GetLayoutBoxModelObjectByElementId("target");

  const auto* constraints = sticky->StickyConstraints();
  ASSERT_TRUE(constraints);
  EXPECT_TRUE(HasStickyLayer(scrollable_area, sticky));

  EXPECT_EQ(
      25.f,
      constraints->scroll_container_relative_sticky_box_rect.X().ToFloat());
  To<HTMLElement>(target->GetNode())->classList().Add(AtomicString("hide"));
  // After updating layout we should have the updated position.
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_EQ(50.f, sticky->StickyConstraints()
                      ->scroll_container_relative_sticky_box_rect.X()
                      .ToFloat());
}

TEST_P(LayoutBoxModelObjectTest, StickyPositionStatusChange) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller { overflow: auto; height: 200px; }
      #sticky { position: sticky; top: 0; }
    </style>
    <div id='scroller'>
      <div id='sticky'></div>
      <div style='height: 500px'></div>
    </div>
  )HTML");
  auto* scrollable_area =
      GetLayoutBoxModelObjectByElementId("scroller")->GetScrollableArea();
  auto* sticky = GetElementById("sticky");
  const auto* sticky_box = sticky->GetLayoutBox();
  auto* sticky_layer = sticky_box->Layer();
  ASSERT_TRUE(sticky_layer);
  EXPECT_TRUE(HasStickyLayer(scrollable_area, sticky_box));
  EXPECT_TRUE(sticky_box->StickyConstraints());

  // Change top to auto which effectively makes the object no longer sticky
  // constrained and removed from the scrollable area's sticky constraints map.
  sticky->setAttribute(html_names::kStyleAttr, AtomicString("top: auto"));
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_FALSE(sticky_box->StyleRef().HasStickyConstrainedPosition());
  ASSERT_EQ(sticky_layer, sticky_box->Layer());
  EXPECT_FALSE(HasStickyLayer(scrollable_area, sticky_box));
  EXPECT_FALSE(sticky_box->StickyConstraints());

  // Change top back to 0. |sticky| should be back to sticky constrained.
  sticky->setAttribute(html_names::kStyleAttr, g_empty_atom);
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_TRUE(sticky_box->StyleRef().HasStickyConstrainedPosition());
  ASSERT_EQ(sticky_layer, sticky_box->Layer());
  EXPECT_TRUE(HasStickyLayer(scrollable_area, sticky_box));
  EXPECT_TRUE(sticky_box->StickyConstraints());

  // Change position to relative. The sticky layer should be removed from the
  // scrollable area's sticky constraints map.
  sticky->setAttribute(html_names::kStyleAttr,
                       AtomicString("position: relative"));
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  ASSERT_EQ(sticky_layer, sticky_box->Layer());
  EXPECT_FALSE(HasStickyLayer(scrollable_area, sticky_box));
  EXPECT_FALSE(sticky_box->StickyConstraints());

  // Change position back to sticky.
  sticky->setAttribute(html_names::kStyleAttr, g_empty_atom);
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  ASSERT_EQ(sticky_layer, sticky_box->Layer());
  EXPECT_TRUE(HasStickyLayer(scrollable_area, sticky_box));
  EXPECT_TRUE(sticky_box->StickyConstraints());

  // Change position to static, which removes the layer. There should be no
  // dangling pointer in the sticky constraints map.
  sticky->setAttribute(html_names::kStyleAttr,
                       AtomicString("position: static"));
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  ASSERT_FALSE(sticky_box->Layer());
  EXPECT_FALSE(HasStickyLayer(scrollable_area, sticky_box));
  EXPECT_FALSE(sticky_box->StickyConstraints());

  // Change position back to sticky.
  sticky->setAttribute(html_names::kStyleAttr, g_empty_atom);
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_TRUE(HasStickyLayer(scrollable_area, sticky_box));
  EXPECT_TRUE(sticky_box->StickyConstraints());

  // Remove the layout object. There should be no dangling pointer in the
  // sticky constraints map.
  sticky->setAttribute(html_names::kStyleAttr, AtomicString("display: none"));
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  ASSERT_FALSE(sticky->GetLayoutObject());
  EXPECT_FALSE(HasStickyLayer(scrollable_area, sticky_box));
}

// Verifies that the correct sticky-box shifting ancestor is found when
// computing the sticky constraints. Any such ancestor is the first sticky
// element between you and your containing block (exclusive).
//
// In most cases, this pointer should be null since your parent is normally your
// containing block. However there are cases where this is not true, including
// inline blocks and tables. The latter is currently irrelevant since only table
// cells can be sticky in CSS2.1, but we can test the former.
TEST_P(LayoutBoxModelObjectTest,
       StickyPositionFindsCorrectStickyBoxShiftingAncestor) {
  SetBodyInnerHTML(R"HTML(
    <style>#stickyOuterDiv { position: sticky; top: 0;}
    #stickyOuterInline { position: sticky; top: 0; display: inline; }
    #unanchoredSticky { position: sticky; display: inline; }
    .inline { display: inline; }
    #stickyInnerInline { position: sticky; top: 0; display: inline;
    }</style>
    <div id='stickyOuterDiv'>
      <div id='stickyOuterInline'>
       <div id='unanchoredSticky'>
          <div class='inline'>
            <div id='stickyInnerInline'></div>
          </div>
        </div>
      </div>
    </div>
  )HTML");

  PaintLayer* sticky_outer_div = GetPaintLayerByElementId("stickyOuterDiv");
  LayoutBoxModelObject* sticky_outer_inline =
      GetLayoutBoxModelObjectByElementId("stickyOuterInline");
  LayoutBoxModelObject* unanchored_sticky =
      GetLayoutBoxModelObjectByElementId("unanchoredSticky");
  LayoutBoxModelObject* sticky_inner_inline =
      GetLayoutBoxModelObjectByElementId("stickyInnerInline");

  PaintLayerScrollableArea* scrollable_area =
      sticky_outer_div->ContainingScrollContainerLayer()->GetScrollableArea();
  ASSERT_TRUE(scrollable_area);

  ASSERT_TRUE(
      HasStickyLayer(scrollable_area, sticky_outer_div->GetLayoutBox()));
  auto* outer_div_constraints =
      sticky_outer_div->GetLayoutObject().StickyConstraints();
  ASSERT_TRUE(outer_div_constraints);

  ASSERT_TRUE(HasStickyLayer(scrollable_area, sticky_outer_inline));
  auto* outer_inline_constraints = sticky_outer_inline->StickyConstraints();
  ASSERT_TRUE(outer_inline_constraints);

  ASSERT_FALSE(HasStickyLayer(scrollable_area, unanchored_sticky));
  EXPECT_FALSE(unanchored_sticky->StickyConstraints());

  ASSERT_TRUE(HasStickyLayer(scrollable_area, sticky_inner_inline));
  auto* inner_inline_constraints = sticky_inner_inline->StickyConstraints();
  ASSERT_TRUE(inner_inline_constraints);

  // The outer block element trivially has no sticky-box shifting ancestor.
  EXPECT_FALSE(outer_div_constraints->nearest_sticky_layer_shifting_sticky_box);

  // Neither does the outer inline element, as its parent element is also its
  // containing block.
  EXPECT_FALSE(
      outer_inline_constraints->nearest_sticky_layer_shifting_sticky_box);

  // However the inner inline element does have a sticky-box shifting ancestor,
  // as its containing block is the ancestor block element, above its ancestor
  // sticky element.
  EXPECT_EQ(sticky_outer_inline,
            inner_inline_constraints->nearest_sticky_layer_shifting_sticky_box);
}

// Verifies that the correct containing-block shifting ancestor is found when
// computing the sticky constraints. Any such ancestor is the first sticky
// element between your containing block (inclusive) and your ancestor overflow
// layer (exclusive).
TEST_P(LayoutBoxModelObjectTest,
       StickyPositionFindsCorrectContainingBlockShiftingAncestor) {
  // We make the scroller itself sticky in order to check that elements do not
  // detect it as their containing-block shifting ancestor.
  SetBodyInnerHTML(R"HTML(
    <style>#scroller { overflow-y: scroll; position: sticky; top: 0;}
    #stickyParent { position: sticky; top: 0;}
    #stickyChild { position: sticky; top: 0;}
    #unanchoredSticky { position: sticky; }
    #stickyNestedChild { position: sticky; top: 0;}</style>
    <div id='scroller'>
      <div id='stickyParent'>
        <div id='unanchoredSticky'>
          <div id='stickyChild'></div>
          <div><div id='stickyNestedChild'></div></div>
        </div>
      </div>
    </div>
  )HTML");

  LayoutBox* scroller = GetLayoutBoxByElementId("scroller");
  LayoutBox* sticky_parent = GetLayoutBoxByElementId("stickyParent");
  LayoutBox* sticky_child = GetLayoutBoxByElementId("stickyChild");
  LayoutBox* sticky_nested_child = GetLayoutBoxByElementId("stickyNestedChild");

  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  ASSERT_TRUE(scrollable_area);
  ASSERT_FALSE(HasStickyLayer(scrollable_area, scroller));
  EXPECT_TRUE(HasStickyLayer(GetLayoutView().GetScrollableArea(), scroller));
  EXPECT_TRUE(scroller->StickyConstraints());

  ASSERT_TRUE(HasStickyLayer(scrollable_area, sticky_parent));
  auto* parent_constraints = sticky_parent->StickyConstraints();
  ASSERT_TRUE(parent_constraints);

  ASSERT_TRUE(HasStickyLayer(scrollable_area, sticky_child));
  auto* child_constraints = sticky_child->StickyConstraints();
  ASSERT_TRUE(child_constraints);

  ASSERT_TRUE(HasStickyLayer(scrollable_area, sticky_nested_child));
  auto* nested_child_constraints = sticky_nested_child->StickyConstraints();
  ASSERT_TRUE(nested_child_constraints);

  // The outer <div> should not detect the scroller as its containing-block
  // shifting ancestor.
  EXPECT_FALSE(
      parent_constraints->nearest_sticky_layer_shifting_containing_block);

  // Both inner children should detect the parent <div> as their
  // containing-block shifting ancestor. They skip past unanchored sticky
  // because it will never have a non-zero offset.
  EXPECT_EQ(sticky_parent,
            child_constraints->nearest_sticky_layer_shifting_containing_block);
  EXPECT_EQ(
      sticky_parent,
      nested_child_constraints->nearest_sticky_layer_shifting_cont
"""


```