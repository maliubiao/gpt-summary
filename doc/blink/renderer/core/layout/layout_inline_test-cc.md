Response:
Let's break down the thought process for analyzing the provided C++ test file for Chromium's Blink rendering engine.

**1. Initial Scan and Goal Identification:**

* **Keywords:** "test", "layout_inline", "cc", "blink", "chromium". This immediately signals that this file contains unit tests for the `LayoutInline` class in the Blink rendering engine.
* **File Path:** `blink/renderer/core/layout/layout_inline_test.cc`. This confirms the location within the Blink codebase and reinforces the focus on layout functionality.
* **Copyright Notice:**  Indicates ownership and licensing (BSD-style). This is standard boilerplate.
* **Includes:**  These are crucial. They tell us what other parts of the engine `LayoutInline` interacts with:
    * `layout_inline.h`: The header file for the class being tested.
    * `gmock/gmock.h`, `gtest/gtest.h`:  Indicate the use of Google Test and Google Mock frameworks for writing tests.
    * Layout-related headers (`hit_test_location.h`, `inline_cursor.h`, `layout_block_flow.h`, `physical_box_fragment.h`). This highlights the core responsibility of `LayoutInline`: positioning and rendering inline elements within a layout.
    * `box_fragment_painter.h`:  Suggests interaction with the painting process.
    * `core_unit_test_helper.h`:  Provides utilities for setting up the testing environment.

* **Overall Goal:** The primary goal of this file is to verify the correct behavior of the `LayoutInline` class, which is responsible for laying out inline-level elements (like `<span>`, `<a>`, text nodes) within a block-level container.

**2. Deconstructing the Test Structure:**

* **Namespace:** `blink`. This is the standard namespace for Blink code.
* **Test Fixture:** `class LayoutInlineTest : public RenderingTest`. This sets up a test environment by inheriting from `RenderingTest`, which provides necessary infrastructure for rendering and layout tests (like creating a document, setting HTML content, and updating layout).
* **Helper Function:** `HitTestAllPhases`. This is a utility function within the test fixture to simplify hit-testing on layout objects. It handles the case of `LayoutBox` specifically, indicating that inline layout often interacts with how boxes are hit-tested.
* **`TEST_F` Macros:** These define individual test cases. The naming convention (e.g., `PhysicalLinesBoundingBox`, `SimpleContinuation`, `RegionHitTest`) gives a strong indication of what each test verifies.

**3. Analyzing Individual Test Cases (Iterative Process):**

For each `TEST_F`, the thought process involves:

* **Understanding the Setup:**  Look at `SetBodyInnerHTML`. This reveals the HTML structure being tested. Pay attention to IDs, styles, and attributes.
* **Identifying the Action:**  What is the test *doing*?  Is it:
    * Checking bounding boxes (`PhysicalLinesBoundingBox`).
    * Verifying the structure of the layout tree (`SimpleContinuation`, `BlockInInlineRemove`).
    * Performing hit-testing (`RegionHitTest`, `RelativePositionedHitTest`, etc.).
    * Testing focus ring calculations (`FocusRingRecursiveContinuations`, etc.).
    * Checking the behavior of specific methods like `AbsoluteBoundingBoxRectHandlingEmptyInline` or `AddDraggableRegions`.
    * Examining visual overflow (`VisualOverflowRecalcLegacyLayout`, `VisualOverflowRecalcLayoutNG`).
* **Analyzing the Assertions/Expectations:**  What is the test expecting the outcome to be?  `EXPECT_EQ`, `ASSERT_TRUE`, `EXPECT_FALSE`, `EXPECT_THAT` (with matchers like `UnorderedElementsAre`) are used to verify the correctness of the code.
* **Connecting to Web Technologies:**  How does this test relate to HTML, CSS, and JavaScript?
    * **HTML:** The structure defined in `SetBodyInnerHTML` is directly HTML.
    * **CSS:**  Styles applied via `<style>` tags or inline styles (`style` attribute) are CSS. The tests often check how CSS properties (like `width`, `height`, `line-height`, `writing-mode`, `position`, `white-space`, `-webkit-app-region`, `outline`) affect the layout of inline elements.
    * **JavaScript:** While this specific file doesn't *execute* JavaScript, the functionality being tested (layout) is crucial for how JavaScript interacts with the DOM and rendering. For example, JavaScript might manipulate the DOM, causing layout changes that these tests help validate. The `contenteditable` attribute, although HTML, often involves complex interactions with JavaScript for editing.

**4. Identifying Logical Inferences and Assumptions:**

* When a test manipulates the DOM (e.g., `block_element->remove()`, `insertBefore()`), it assumes that the underlying DOM manipulation logic is correct and focuses on the layout consequences.
* Tests using `LoadAhem()` assume that the Ahem font (a predictable fixed-width font) is correctly loaded and behaves as expected.
* Hit-testing tests make assumptions about how coordinates map to elements based on the rendering.

**5. Spotting Potential Usage Errors:**

* **Incorrect CSS:**  Many tests implicitly check how different CSS properties interact. Incorrect CSS could lead to unexpected layout, which these tests aim to catch. For example, a user might set `display: block` on an element they expect to be inline, leading to a different layout than intended.
* **DOM Manipulation Issues:**  JavaScript manipulating the DOM in unexpected ways could break assumptions made by the layout engine. Tests like `BlockInInlineRemove` help ensure the layout handles these scenarios gracefully.
* **Hit-Testing Logic:**  Incorrectly calculating hit-test coordinates or making wrong assumptions about which element should be hit are common errors. The hit-testing tests directly address this.

**6. Addressing the "TODO" Comments:**

The "TODO(crbug.com/...) The test is broken for LayoutNG." comments are significant. They indicate that these specific tests expose issues or inconsistencies between the legacy layout engine and the newer LayoutNG engine. This highlights the ongoing development and refinement of the rendering engine. It suggests potential areas where developers might encounter different behavior depending on which layout engine is active.

**7. Structuring the Answer:**

Finally, the information gathered through this analysis needs to be organized into a clear and informative answer, covering the requested points: functionality, relationship to web technologies, logical inferences, and potential errors. Using examples from the test code is crucial for illustrating these points.
这个文件 `blink/renderer/core/layout/layout_inline_test.cc` 是 Chromium Blink 引擎中用于测试 `LayoutInline` 类的单元测试文件。`LayoutInline` 类负责处理 HTML 中内联级别元素的布局，例如 `<span>`, `<a>`, 文本节点等等。

以下是该文件的功能及其与 JavaScript, HTML, CSS 的关系、逻辑推理和常见错误：

**文件功能:**

1. **测试 `LayoutInline` 类的核心功能:**  该文件包含了多个测试用例（以 `TEST_F` 宏定义），用于验证 `LayoutInline` 类的各种方法和行为是否符合预期。
2. **验证内联元素的布局计算:** 测试用例会创建包含内联元素的 HTML 结构，并断言布局计算的结果，例如元素的尺寸、位置、边界框等。
3. **测试与 Hit Testing 相关的逻辑:**  部分测试用例涉及到点击测试（Hit Testing），验证在特定坐标点击时，是否能正确识别到内联元素。
4. **测试包含块级子元素的内联元素:**  验证内联元素内部包含块级元素（例如 `<div>`）时的布局处理，以及 DOM 结构变化时的更新。
5. **测试焦点环（Focus Ring）的绘制:**  部分被标记为 `DISABLED_` 的测试用例（在 LayoutNG 下有问题）用于验证在内联元素上绘制焦点环时的正确性，避免重复绘制。
6. **测试可拖拽区域（Draggable Regions）:**  验证带有 `-webkit-app-region: drag` 和 `-webkit-app-region: no-drag` CSS 属性的内联元素如何生成可拖拽区域。
7. **测试视觉溢出（Visual Overflow）的计算:**  验证内联元素的视觉溢出边界计算，特别是当应用了 `outline` 等属性时。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:** 该文件通过 `SetBodyInnerHTML` 方法动态生成 HTML 结构，用于测试各种内联布局场景。例如：
    ```c++
    SetBodyInnerHTML(R"HTML(
      <p><span id=ltr1>abc<br>xyz</span></p>
    )HTML");
    ```
    这个 HTML 片段创建了一个段落 `<p>`，其中包含一个 `<span>` 元素，其 `id` 为 `ltr1`，内容为 "abc" 和一个换行符 `<br>`，然后是 "xyz"。测试会基于这个 HTML 结构进行布局计算。

* **CSS:** 测试用例会应用 CSS 样式来模拟不同的布局环境，并验证 `LayoutInline` 在这些环境下的行为。例如：
    ```c++
    SetBodyInnerHTML(R"HTML(
      <style>
        html { font-family: Ahem; font-size: 10px; line-height: 10px; }
        p { width: 300px; height: 100px; }
        .vertical { writing-mode: vertical-rl; }
      </style>
      <p class=vertical><span id=vertical>abc<br>xyz</span></p>
    )HTML");
    ```
    这段代码设置了字体、字号、行高等全局样式，以及段落的宽高。`.vertical` 类应用了 `writing-mode: vertical-rl`，这会改变文本的排版方向，测试会验证在这种情况下 `LayoutInline` 的表现。

* **JavaScript:** 虽然这个测试文件本身是用 C++ 编写的，用于测试 Blink 引擎的内部逻辑，但它测试的功能直接影响 JavaScript 与 DOM 和渲染的交互。例如：
    * **DOM 操作:** 测试用例中会进行 DOM 节点的添加和删除 (`block_element->remove()`, `insertBefore()`)，以验证布局的动态更新。JavaScript 经常会操作 DOM，这些测试确保了 `LayoutInline` 能正确处理这些变化。
    * **事件处理 (Hit Testing):**  Hit Testing 是浏览器处理用户交互（例如点击事件）的关键部分。测试用例模拟点击操作，验证是否能正确命中内联元素。JavaScript 的事件监听器依赖于这种命中测试的准确性。
    * **获取元素尺寸和位置:** JavaScript 可以通过 `getBoundingClientRect()` 等方法获取元素的尺寸和位置信息。`LayoutInline` 的测试确保了这些信息的准确性。

**逻辑推理及假设输入与输出:**

* **假设输入:** 一个包含内联元素的 HTML 结构，可能带有特定的 CSS 样式。
* **预期输出:**  `LayoutInline` 类计算出的内联元素的各种属性，例如：
    * **`PhysicalLinesBoundingBox()`:**  内联元素所有文本行的外包矩形。
        * **假设输入:** `<p><span id=ltr1>abc<br>xyz</span></p>`，字体大小 10px，行高 10px。
        * **预期输出:** `PhysicalRect(0, 0, 30, 20)` (abc 一行高 10px，xyz 一行高 10px，总高 20px，abc 宽度 3 * 10px = 30px)。
    * **Hit Testing:**  在特定坐标点击时，是否能正确命中内联元素。
        * **假设输入:**  包含 `<span>` 元素的 HTML，以及一个点击坐标 `(18, 15)`。
        * **预期输出:**  Hit Testing 结果指示命中了 `<span>` 元素或其内部的文本节点。
    * **焦点环的边界:**  内联元素被选中时，焦点环的绘制区域。
        * **假设输入:**  包含嵌套 `<span>` 和 `<div>` 的 HTML 结构。
        * **预期输出:**  一组 `PhysicalRect` 对象，表示焦点环的各个组成部分，避免重复绘制连续的内联元素。

**涉及用户或编程常见的使用错误及举例说明:**

* **误用块级元素在内联元素中:**  HTML 中，将块级元素直接放在内联元素中可能会导致非预期的布局行为。测试用例 `BlockInInlineRemove` 验证了 Blink 如何处理这种情况，以及在 DOM 结构变化时的更新。
    ```html
    <span>before<div></div>after</span>
    ```
    用户可能会错误地认为 `<div>` 会像内联元素一样排列，但实际上它会创建一个匿名块级容器。
* **对 `white-space` 属性理解不足:** `white-space: pre-wrap` 会保留空格和换行符。测试用例 `HitTestCulledInlinePreWrap` 验证了在这种情况下 Hit Testing 的行为。用户如果对 `white-space` 的各种取值不熟悉，可能会导致文本的布局与预期不符。
* **相对定位元素的 Hit Testing:** 当内联元素使用 `position: relative` 时，其渲染位置会发生偏移，但其布局盒模型仍然占据原始位置。测试用例 `RelativePositionedHitTest` 验证了在这种情况下 Hit Testing 能否正确工作。开发者可能会错误地认为点击原始位置就能命中相对定位的元素。
* **对 `-webkit-app-region` 属性的误用:**  `-webkit-app-region` 用于创建可拖拽的窗口区域。测试用例 `AddDraggableRegions` 验证了该属性的正确处理。开发者可能会错误地认为所有元素都可以通过该属性变为可拖拽，而没有考虑到其对布局的影响。
* **视觉溢出的计算错误:**  开发者可能会忽略 `outline` 等属性对元素视觉尺寸的影响，导致在处理溢出或进行布局计算时出现错误。测试用例 `VisualOverflowRecalcLegacyLayout` 和 `VisualOverflowRecalcLayoutNG` 验证了 Blink 能否正确计算包含 `outline` 的元素的视觉溢出。

总而言之，`layout_inline_test.cc` 是一个关键的测试文件，它通过各种测试用例来确保 Blink 引擎在处理内联元素布局时的正确性和健壮性。这些测试覆盖了与 HTML 结构、CSS 样式以及 JavaScript 交互相关的各种场景，帮助开发者避免常见的布局错误。

Prompt: 
```
这是目录为blink/renderer/core/layout/layout_inline_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/layout_inline.h"

#include "build/build_config.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/paint/box_fragment_painter.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {

using ::testing::UnorderedElementsAre;

class LayoutInlineTest : public RenderingTest {
 protected:
  bool HitTestAllPhases(LayoutObject& object,
                        HitTestResult& result,
                        const HitTestLocation& location,
                        const PhysicalOffset& offset) {
    if (!object.IsBox()) {
      return object.HitTestAllPhases(result, location, offset);
    }
    const LayoutBox& box = To<LayoutBox>(object);
    DCHECK_EQ(box.PhysicalFragmentCount(), 1u);
    const PhysicalBoxFragment& fragment = *box.GetPhysicalFragment(0);
    return BoxFragmentPainter(fragment).HitTestAllPhases(result, location,
                                                         offset);
  }
};

TEST_F(LayoutInlineTest, PhysicalLinesBoundingBox) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      html { font-family: Ahem; font-size: 10px; line-height: 10px; }
      p { width: 300px; height: 100px; }
      .vertical { writing-mode: vertical-rl; }
    </style>
    <p><span id=ltr1>abc<br>xyz</span></p>
    <p><span id=ltr2>12 345 6789</span></p>
    <p dir=rtl><span id=rtl1>abc<br>xyz</span></p>
    <p dir=rtl><span id=rtl2>12 345 6789</span></p>
    <p class=vertical><span id=vertical>abc<br>xyz</span></p>
  )HTML");
  EXPECT_EQ(PhysicalRect(0, 0, 30, 20),
            To<LayoutInline>(GetLayoutObjectByElementId("ltr1"))
                ->PhysicalLinesBoundingBox());
  EXPECT_EQ(PhysicalRect(0, 0, 110, 10),
            To<LayoutInline>(GetLayoutObjectByElementId("ltr2"))
                ->PhysicalLinesBoundingBox());
  EXPECT_EQ(PhysicalRect(270, 0, 30, 20),
            To<LayoutInline>(GetLayoutObjectByElementId("rtl1"))
                ->PhysicalLinesBoundingBox());
  EXPECT_EQ(PhysicalRect(190, 0, 110, 10),
            To<LayoutInline>(GetLayoutObjectByElementId("rtl2"))
                ->PhysicalLinesBoundingBox());
  EXPECT_EQ(PhysicalRect(280, 0, 20, 30),
            To<LayoutInline>(GetLayoutObjectByElementId("vertical"))
                ->PhysicalLinesBoundingBox());
}

TEST_F(LayoutInlineTest, SimpleContinuation) {
  SetBodyInnerHTML(
      "<span id='splitInline'>"
      "<i id='before'></i>"
      "<h1 id='blockChild'></h1>"
      "<i id='after'></i>"
      "</span>");

  auto* split_inline_part1 =
      To<LayoutInline>(GetLayoutObjectByElementId("splitInline"));
  ASSERT_TRUE(split_inline_part1);
  ASSERT_TRUE(split_inline_part1->FirstChild());
  auto* before = GetLayoutObjectByElementId("before");
  EXPECT_EQ(split_inline_part1->FirstChild(), before);
  auto* block_child = GetLayoutObjectByElementId("blockChild");
  auto* after = GetLayoutObjectByElementId("after");
  EXPECT_EQ(split_inline_part1->FirstChild(), before);
  LayoutObject* anonymous = block_child->Parent();
  EXPECT_TRUE(anonymous->IsBlockInInline());
  EXPECT_EQ(before->NextSibling(), anonymous);
  EXPECT_EQ(anonymous->NextSibling(), after);
  EXPECT_FALSE(after->NextSibling());
}

TEST_F(LayoutInlineTest, BlockInInlineRemove) {
  SetBodyInnerHTML(R"HTML(
    <div>
      <span id="span">before
        <div id="block"></div>
      after</span>
    </div>
  )HTML");

  // Check `#block` is in an anonymous block.
  const auto* span = GetLayoutObjectByElementId("span");
  Element* block_element = GetElementById("block");
  const auto* block = block_element->GetLayoutObject();
  EXPECT_FALSE(block->IsInline());
  EXPECT_TRUE(block->Parent()->IsBlockInInline());
  EXPECT_EQ(block->Parent()->Parent(), span);

  // Remove `#block`. All children are now inline.
  // Check if the |IsBlockInInline| anonymous block was removed.
  Node* after_block = block_element->nextSibling();
  block_element->remove();
  UpdateAllLifecyclePhasesForTest();
  for (const auto* child = span->SlowFirstChild(); child;
       child = child->NextSibling()) {
    EXPECT_TRUE(child->IsInline());
    EXPECT_FALSE(child->IsBlockInInline());
  }

  // Re-insert `#block`.
  after_block->parentNode()->insertBefore(block_element, after_block);
  UpdateAllLifecyclePhasesForTest();
  block = block_element->GetLayoutObject();
  EXPECT_FALSE(block->IsInline());
  EXPECT_TRUE(block->Parent()->IsBlockInInline());
  EXPECT_EQ(block->Parent()->Parent(), span);

  // Insert another block before the "after" text node.
  // This should be in the existing anonymous block, next to the `#block`.
  Document& document = GetDocument();
  Element* block2_element =
      document.CreateElementForBinding(AtomicString("div"));
  after_block->parentNode()->insertBefore(block2_element, after_block);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(block2_element->GetLayoutObject(), block->NextSibling());
}

TEST_F(LayoutInlineTest, RegionHitTest) {
  SetBodyInnerHTML(R"HTML(
    <div><span id='lotsOfBoxes'>
    This is a test line<br>This is a test line<br>This is a test line<br>
    This is a test line<br>This is a test line<br>This is a test line<br>
    This is a test line<br>This is a test line<br>This is a test line<br>
    This is a test line<br>This is a test line<br>This is a test line<br>
    This is a test line<br>This is a test line<br>This is a test line<br>
    This is a test line<br>This is a test line<br>This is a test line<br>
    </span></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  auto* lots_of_boxes =
      To<LayoutInline>(GetLayoutObjectByElementId("lotsOfBoxes"));
  ASSERT_TRUE(lots_of_boxes);

  HitTestRequest hit_request(HitTestRequest::kTouchEvent |
                             HitTestRequest::kListBased);

  PhysicalRect hit_rect(1, 3, 2, 4);
  HitTestLocation location(hit_rect);
  HitTestResult hit_result(hit_request, location);
  PhysicalOffset hit_offset;

  // The return value of HitTestCulledInline() indicates whether the hit test
  // rect is completely contained by the part of |lots_of_boxes| being hit-
  // tested. Legacy hit tests the entire LayoutObject all at once while NG hit
  // tests line by line. Therefore, legacy returns true while NG is false.
  //
  // Note: The legacy behavior seems wrong. In a full list-based hit testing,
  // after testing the node in the last intersecting line, the |true| return
  // value of HitTestCulledInline() terminates the hit test process, and nodes
  // in the previous lines are not tested.
  //
  // TODO(xiaochengh): Expose this issue in a real Chrome use case.

  ASSERT_TRUE(lots_of_boxes->IsInLayoutNGInlineFormattingContext());

  const auto* div = To<LayoutBlockFlow>(lots_of_boxes->Parent());
  InlineCursor cursor(*div);
  for (cursor.MoveToFirstLine(); cursor; cursor.MoveToNextLine()) {
    DCHECK(cursor.Current().IsLineBox());
    InlineCursor line_cursor = cursor.CursorForDescendants();
    bool hit_outcome = lots_of_boxes->HitTestCulledInline(
        hit_result, location, hit_offset, line_cursor);
    EXPECT_FALSE(hit_outcome);
  }
  // Make sure that the inline is hit
  const Node* span = lots_of_boxes->GetNode();
  EXPECT_EQ(span, hit_result.InnerNode());
}

// crbug.com/844746
TEST_F(LayoutInlineTest, RelativePositionedHitTest) {
  LoadAhem();
  SetBodyInnerHTML(
      "<div style='font: 10px/10px Ahem'>"
      "  <span style='position: relative'>XXX</span>"
      "</div>");

  HitTestRequest hit_request(HitTestRequest::kReadOnly |
                             HitTestRequest::kActive);
  const PhysicalOffset container_offset(8, 8);
  const PhysicalOffset hit_location(18, 15);
  HitTestLocation location(hit_location);

  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Element* span = GetDocument().QuerySelector(AtomicString("span"));
  Node* text = span->firstChild();

  // Shouldn't hit anything in SPAN as it's in another paint layer
  {
    LayoutObject* layout_div = div->GetLayoutObject();
    HitTestResult hit_result(hit_request, location);
    bool hit_outcome =
        HitTestAllPhases(*layout_div, hit_result, location, container_offset);
    EXPECT_TRUE(hit_outcome);
    EXPECT_EQ(div, hit_result.InnerNode());
  }

  // SPAN and its descendants can be hit only with a hit test that starts from
  // the SPAN itself.
  {
    LayoutObject* layout_span = span->GetLayoutObject();
    HitTestResult hit_result(hit_request, location);
    bool hit_outcome =
        HitTestAllPhases(*layout_span, hit_result, location, container_offset);
    EXPECT_TRUE(hit_outcome);
    EXPECT_EQ(text, hit_result.InnerNode());
  }

  // Hit test from LayoutView to verify that everything works together.
  {
    HitTestResult hit_result(hit_request, location);
    bool hit_outcome = GetLayoutView().HitTest(location, hit_result);
    EXPECT_TRUE(hit_outcome);
    EXPECT_EQ(text, hit_result.InnerNode());
  }
}

TEST_F(LayoutInlineTest, MultilineRelativePositionedHitTest) {
  LoadAhem();
  SetBodyInnerHTML(
      "<div style='font: 10px/10px Ahem; width: 30px'>"
      "  <span id=span style='position: relative'>"
      "    XXX"
      "    <span id=line2 style='background-color: red'>YYY</span>"
      "    <img style='width: 10px; height: 10px; vertical-align: bottom'>"
      "  </span>"
      "</div>");

  LayoutObject* layout_span = GetLayoutObjectByElementId("span");
  HitTestRequest hit_request(HitTestRequest::kReadOnly |
                             HitTestRequest::kActive |
                             HitTestRequest::kIgnorePointerEventsNone);
  const PhysicalOffset container_offset(8, 8);

  // Hit test first line
  {
    PhysicalOffset hit_location(13, 13);
    HitTestLocation location(hit_location);
    Node* target = GetElementById("span")->firstChild();

    HitTestResult hit_result(hit_request, location);
    bool hit_outcome =
        HitTestAllPhases(*layout_span, hit_result, location, container_offset);
    EXPECT_TRUE(hit_outcome);
    EXPECT_EQ(target, hit_result.InnerNode());

    // Initiate a hit test from LayoutView to verify the "natural" process.
    HitTestResult layout_view_hit_result(hit_request, location);
    bool layout_view_hit_outcome =
        GetLayoutView().HitTest(location, layout_view_hit_result);
    EXPECT_TRUE(layout_view_hit_outcome);
    EXPECT_EQ(target, layout_view_hit_result.InnerNode());
  }

  // Hit test second line
  {
    PhysicalOffset hit_location(13, 23);
    HitTestLocation location(hit_location);
    Node* target = GetElementById("line2")->firstChild();

    HitTestResult hit_result(hit_request, location);
    bool hit_outcome =
        HitTestAllPhases(*layout_span, hit_result, location, container_offset);
    EXPECT_TRUE(hit_outcome);
    EXPECT_EQ(target, hit_result.InnerNode());

    // Initiate a hit test from LayoutView to verify the "natural" process.
    HitTestResult layout_view_hit_result(hit_request, location);
    bool layout_view_hit_outcome =
        GetLayoutView().HitTest(location, layout_view_hit_result);
    EXPECT_TRUE(layout_view_hit_outcome);
    EXPECT_EQ(target, layout_view_hit_result.InnerNode());
  }

  // Hit test image in third line
  {
    PhysicalOffset hit_location(13, 33);
    HitTestLocation location(hit_location);
    Node* target = GetDocument().QuerySelector(AtomicString("img"));

    HitTestResult hit_result(hit_request, location);
    bool hit_outcome =
        HitTestAllPhases(*layout_span, hit_result, location, container_offset);
    EXPECT_TRUE(hit_outcome);
    EXPECT_EQ(target, hit_result.InnerNode());

    // Initiate a hit test from LayoutView to verify the "natural" process.
    HitTestResult layout_view_hit_result(hit_request, location);
    bool layout_view_hit_outcome =
        GetLayoutView().HitTest(location, layout_view_hit_result);
    EXPECT_TRUE(layout_view_hit_outcome);
    EXPECT_EQ(target, layout_view_hit_result.InnerNode());
  }
}

TEST_F(LayoutInlineTest, HitTestCulledInlinePreWrap) {
  SetBodyInnerHTML(R"HTML(
    <style>
      html, body { margin: 0; }
      body {
        width: 250px;
      }
      span {
        white-space: pre-wrap;
        font: 30px serif;
      }
    </style>
    <div id="container">
      <span id="span">The quick brown fox jumps over the lazy dog.</span>
    </div>
  )HTML");
  HitTestRequest hit_request(HitTestRequest::kReadOnly);
  PhysicalOffset hit_location(100, 15);
  HitTestLocation location(hit_location);
  HitTestResult hit_result(hit_request, location);
  LayoutObject* container = GetLayoutObjectByElementId("container");
  HitTestAllPhases(*container, hit_result, location, PhysicalOffset());

  Element* span = GetElementById("span");
  Node* text_node = span->firstChild();
  EXPECT_EQ(hit_result.InnerNode(), text_node);
}

// When adding focus ring rects, we should avoid adding duplicated rect for
// continuations.
// TODO(crbug.com/835484): The test is broken for LayoutNG.
TEST_F(LayoutInlineTest, DISABLED_FocusRingRecursiveContinuations) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 0;
        font: 20px/20px Ahem;
      }
    </style>
    <span id="target">SPAN0
      <div>DIV1
        <span>SPAN1
          <div>DIV2</div>
        </span>
      </div>
    </span>
  )HTML");

  auto rects = GetLayoutObjectByElementId("target")->OutlineRects(
      nullptr, PhysicalOffset(), OutlineType::kIncludeBlockInkOverflow);

  EXPECT_THAT(
      rects, UnorderedElementsAre(PhysicalRect(0, 0, 100, 20),   // 'SPAN0'
                                  PhysicalRect(0, 20, 800, 40),  // div DIV1
                                  PhysicalRect(0, 20, 200, 20),  // 'DIV1 SPAN1'
                                  PhysicalRect(0, 40, 800, 20),  // div DIV2
                                  PhysicalRect(0, 40, 80, 20)));  // 'DIV2'
}

// When adding focus ring rects, we should avoid adding line box rects of
// recursive inlines repeatedly.
// TODO(crbug.com/835484): The test is broken for LayoutNG.
TEST_F(LayoutInlineTest, DISABLED_FocusRingRecursiveInlinesVerticalRL) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 0;
        font: 20px/20px Ahem;
      }
    </style>
    <div style="width: 200px; height: 200px; writing-mode: vertical-rl">
      <span id="target">
        <b><b><b><i><i><i>INLINE</i></i> <i><i>TEXT</i></i>
        <div style="position: relative; top: -5px">
          <b><b>BLOCK</b> <i>CONTENTS</i></b>
        </div>
        </i></b></b></b>
      </span>
    </div>
  )HTML");

  auto* target = GetLayoutObjectByElementId("target");
  auto rects =
      target->OutlineRects(nullptr, target->FirstFragment().PaintOffset(),
                           OutlineType::kIncludeBlockInkOverflow);
  EXPECT_THAT(rects, UnorderedElementsAre(
                         PhysicalRect(180, 0, 20, 120),     // 'INLINE'
                         PhysicalRect(160, 0, 20, 80),      // 'TEXT'
                         PhysicalRect(120, -5, 40, 200),    // the inner div
                         PhysicalRect(140, -5, 20, 100),    // 'BLOCK'
                         PhysicalRect(120, -5, 20, 160)));  // 'CONTENTS'
}

// When adding focus ring rects, we should avoid adding duplicated rect for
// continuations.
// TODO(crbug.com/835484): The test is broken for LayoutNG.
TEST_F(LayoutInlineTest, DISABLED_FocusRingRecursiveContinuationsVerticalRL) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 0;
        font: 20px/20px Ahem;
      }
    </style>
    <div style="width: 200px; height: 400px; writing-mode: vertical-rl">
      <span id="target">SPAN0
        <div>DIV1
          <span>SPAN1
            <div>DIV2</div>
          </span>
        </div>
      </span>
    </div>
  )HTML");

  auto* target = GetLayoutObjectByElementId("target");
  auto rects =
      target->OutlineRects(nullptr, target->FirstFragment().PaintOffset(),
                           OutlineType::kIncludeBlockInkOverflow);
  EXPECT_THAT(rects, UnorderedElementsAre(
                         PhysicalRect(180, 0, 20, 100),   // 'SPAN0'
                         PhysicalRect(140, 0, 40, 400),   // div DIV1
                         PhysicalRect(160, 0, 20, 200),   // 'DIV1 SPAN1'
                         PhysicalRect(140, 0, 20, 400),   // div DIV2
                         PhysicalRect(140, 0, 20, 80)));  // 'DIV2'
}

// When adding focus ring rects, we should avoid adding line box rects of
// recursive inlines repeatedly.
// TODO(crbug.com/835484): The test is broken for LayoutNG.
TEST_F(LayoutInlineTest, DISABLED_FocusRingRecursiveInlines) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 0;
        font: 20px/20px Ahem;
      }
    </style>
    <div style="width: 200px">
      <span id="target">
        <b><b><b><i><i><i>INLINE</i></i> <i><i>TEXT</i></i>
        <div style="position: relative; top: -5px">
          <b><b>BLOCK</b> <i>CONTENTS</i></b>
        </div>
        </i></b></b></b>
      </span>
    </div>
  )HTML");

  auto rects = GetLayoutObjectByElementId("target")->OutlineRects(
      nullptr, PhysicalOffset(), OutlineType::kIncludeBlockInkOverflow);

  EXPECT_THAT(rects, UnorderedElementsAre(
                         PhysicalRect(0, 0, 120, 20),     // 'INLINE'
                         PhysicalRect(0, 20, 80, 20),     // 'TEXT'
                         PhysicalRect(0, 35, 200, 40),    // the inner div
                         PhysicalRect(0, 35, 100, 20),    // 'BLOCK'
                         PhysicalRect(0, 55, 160, 20)));  // 'CONTENTS'
}

TEST_F(LayoutInlineTest, AbsoluteBoundingBoxRectHandlingEmptyInline) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 30px 50px;
        font: 20px/20px Ahem;
        width: 400px;
      }
    </style>
    <br><br>
    <span id="target1"></span><br>
    <span id="target2"></span>after<br>
    <span id="target3"></span><span>after</span><br>
    <span id="target4"></span><img style="width: 16px; height: 16px"><br>
    <span><span><span id="target5"></span></span></span><span>after</span><br>
    <span id="target6">
      <img style="width: 30px; height: 30px">
      <div style="width: 100px; height: 100px"></div>
      <img style="width: 30px; height: 30px">
    </span>
  )HTML");

  EXPECT_EQ(PhysicalRect(50, 70, 0, 0),
            GetLayoutObjectByElementId("target1")
                ->AbsoluteBoundingBoxRectHandlingEmptyInline());
  EXPECT_EQ(PhysicalRect(50, 90, 0, 0),
            GetLayoutObjectByElementId("target2")
                ->AbsoluteBoundingBoxRectHandlingEmptyInline());
  EXPECT_EQ(PhysicalRect(50, 110, 0, 0),
            GetLayoutObjectByElementId("target3")
                ->AbsoluteBoundingBoxRectHandlingEmptyInline());
  EXPECT_EQ(PhysicalRect(50, 130, 0, 0),
            GetLayoutObjectByElementId("target4")
                ->AbsoluteBoundingBoxRectHandlingEmptyInline());
  EXPECT_EQ(PhysicalRect(50, 150, 0, 0),
            GetLayoutObjectByElementId("target5")
                ->AbsoluteBoundingBoxRectHandlingEmptyInline());
  // This rect covers the overflowing images and continuations.
  // 168 = (30 + 4) * 2 + 100. 4 is the descent of the font.
  const int width = 400;
  EXPECT_EQ(PhysicalRect(50, 170, width, 168),
            GetLayoutObjectByElementId("target6")
                ->AbsoluteBoundingBoxRectHandlingEmptyInline());
}

TEST_F(LayoutInlineTest, AbsoluteBoundingBoxRectHandlingEmptyInlineVerticalRL) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 30px 50px;
        font: 20px/20px Ahem;
      }
    </style>
    <br><br>
    <div style="width: 600px; height: 400px; writing-mode: vertical-rl">
      <span id="target1"></span><br>
      <span id="target2"></span>after<br>
      <span id="target3"></span><span>after</span><br>
      <span id="target4"></span><img style="width: 20px; height: 20px"><br>
      <span><span><span id="target5"></span></span></span><span>after</span><br>
      <span id="target6">
        <img style="width: 30px; height: 30px">
        <div style="width: 100px; height: 100px"></div>
        <img style="width: 30px; height: 30px">
      </span>
    </div>
  )HTML");

  EXPECT_EQ(PhysicalRect(630, 70, 0, 0),
            GetLayoutObjectByElementId("target1")
                ->AbsoluteBoundingBoxRectHandlingEmptyInline());
  EXPECT_EQ(PhysicalRect(610, 70, 0, 0),
            GetLayoutObjectByElementId("target2")
                ->AbsoluteBoundingBoxRectHandlingEmptyInline());
  EXPECT_EQ(PhysicalRect(590, 70, 0, 0),
            GetLayoutObjectByElementId("target3")
                ->AbsoluteBoundingBoxRectHandlingEmptyInline());
  EXPECT_EQ(PhysicalRect(570, 70, 0, 0),
            GetLayoutObjectByElementId("target4")
                ->AbsoluteBoundingBoxRectHandlingEmptyInline());
  EXPECT_EQ(PhysicalRect(550, 70, 0, 0),
            GetLayoutObjectByElementId("target5")
                ->AbsoluteBoundingBoxRectHandlingEmptyInline());
  // This rect covers the overflowing images and continuations.
  const int height = 400;
  EXPECT_EQ(PhysicalRect(390, 70, 160, height),
            GetLayoutObjectByElementId("target6")
                ->AbsoluteBoundingBoxRectHandlingEmptyInline());
}

TEST_F(LayoutInlineTest, AddDraggableRegions) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 0;
        font: 10px/10px Ahem;
      }
    </style>
    <div style="width: 600px; height: 400px">
      A<br>B
      <span id="target1" style="-webkit-app-region: drag">CDE<br>FGH</span>
      <span id="target2" style="-webkit-app-region: no-drag">IJK<br>LMN</span>
      <span id="target3">OPQ<br>RST</span>
    </div>
  )HTML");

  Vector<DraggableRegionValue> regions1;
  GetLayoutObjectByElementId("target1")->AddDraggableRegions(regions1);
  ASSERT_EQ(1u, regions1.size());
  EXPECT_EQ(PhysicalRect(0, 10, 50, 20), regions1[0].bounds);
  EXPECT_TRUE(regions1[0].draggable);

  Vector<DraggableRegionValue> regions2;
  GetLayoutObjectByElementId("target2")->AddDraggableRegions(regions2);
  ASSERT_EQ(1u, regions2.size());
  EXPECT_EQ(PhysicalRect(0, 20, 70, 20), regions2[0].bounds);
  EXPECT_FALSE(regions2[0].draggable);

  Vector<DraggableRegionValue> regions3;
  GetLayoutObjectByElementId("target3")->AddDraggableRegions(regions3);
  EXPECT_TRUE(regions3.empty());
}

TEST_F(LayoutInlineTest, AddDraggableRegionsVerticalRL) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 0;
        font: 10px/10px Ahem;
      }
    </style>
    <div style="width: 600px; height: 400px; writing-mode: vertical-rl">
      A<br>B
      <span id="target1" style="-webkit-app-region: drag">CDE<br>FGH</span>
      <span id="target2" style="-webkit-app-region: no-drag">IJK<br>LMN</span>
      <span id="target3">OPQ<br>RST</span>
    </div>
  )HTML");

  Vector<DraggableRegionValue> regions1;
  GetLayoutObjectByElementId("target1")->AddDraggableRegions(regions1);
  ASSERT_EQ(1u, regions1.size());
  EXPECT_EQ(PhysicalRect(570, 0, 20, 50), regions1[0].bounds);
  EXPECT_TRUE(regions1[0].draggable);

  Vector<DraggableRegionValue> regions2;
  GetLayoutObjectByElementId("target2")->AddDraggableRegions(regions2);
  ASSERT_EQ(1u, regions2.size());
  EXPECT_EQ(PhysicalRect(560, 0, 20, 70), regions2[0].bounds);
  EXPECT_FALSE(regions2[0].draggable);

  Vector<DraggableRegionValue> regions3;
  GetLayoutObjectByElementId("target3")->AddDraggableRegions(regions3);
  EXPECT_TRUE(regions3.empty());
}

TEST_F(LayoutInlineTest, VisualOverflowRecalcLegacyLayout) {
  // "contenteditable" forces us to use legacy layout, other options could be
  // using "display: -webkit-box", ruby, etc.
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 0;
        font: 20px/20px Ahem;
      }
      target {
        outline: 50px solid red;
      }
    </style>
    <div contenteditable>
      <span id="span">SPAN1</span>
      <span id="span2">SPAN2</span>
    </div>
  )HTML");

  auto* span = To<LayoutInline>(GetLayoutObjectByElementId("span"));
  auto* span_element = GetElementById("span");
  auto* span2_element = GetElementById("span2");

  span_element->setAttribute(html_names::kStyleAttr,
                             AtomicString("outline: 50px solid red"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(PhysicalRect(-50, -50, 200, 120), span->VisualOverflowRect());

  span_element->setAttribute(html_names::kStyleAttr, g_empty_atom);
  span2_element->setAttribute(html_names::kStyleAttr,
                              AtomicString("outline: 50px solid red"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(PhysicalRect(0, 0, 100, 20), span->VisualOverflowRect());

  span2_element->setAttribute(html_names::kStyleAttr, g_empty_atom);
  span_element->setAttribute(html_names::kStyleAttr,
                             AtomicString("outline: 50px solid red"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(PhysicalRect(-50, -50, 200, 120), span->VisualOverflowRect());

  span_element->setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(PhysicalRect(0, 0, 100, 20), span->VisualOverflowRect());
}

TEST_F(LayoutInlineTest, VisualOverflowRecalcLayoutNG) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 0;
        font: 20px/20px Ahem;
      }
      target {
        outline: 50px solid red;
      }
    </style>
    <div>
      <span id="span">SPAN1</span>
      <span id="span2">SPAN2</span>
    </div>
  )HTML");

  auto* span = To<LayoutInline>(GetLayoutObjectByElementId("span"));
  auto* span_element = GetElementById("span");
  auto* span2_element = GetElementById("span2");

  span_element->setAttribute(html_names::kStyleAttr,
                             AtomicString("outline: 50px solid red"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(PhysicalRect(-50, -50, 200, 120), span->VisualOverflowRect());

  span_element->setAttribute(html_names::kStyleAttr, g_empty_atom);
  span2_element->setAttribute(html_names::kStyleAttr,
                              AtomicString("outline: 50px solid red"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(PhysicalRect(0, 0, 100, 20), span->VisualOverflowRect());

  span2_element->setAttribute(html_names::kStyleAttr, g_empty_atom);
  span_element->setAttribute(html_names::kStyleAttr,
                             AtomicString("outline: 50px solid red"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(PhysicalRect(-50, -50, 200, 120), span->VisualOverflowRect());

  span_element->setAttribute(html_names::kStyleAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(PhysicalRect(0, 0, 100, 20), span->VisualOverflowRect());
}

TEST_F(LayoutInlineTest, VisualOverflowRecalcLegacyLayoutPositionRelative) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 0;
        font: 20px/20px Ahem;
      }
      span {
        position: relative;
      }
    </style>
    <span id="span">SPAN</span>
  )HTML");

  auto* span = To<LayoutInline>(GetLayoutObjectByElementId("span"));
  auto* span_element = GetElementById("span");

  span_element->setAttribute(html_names::kStyleAttr,
                             AtomicString("outline: 50px solid red"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(PhysicalRect(-50, -50, 180, 120), span->VisualOverflowRect());
}

}  // namespace blink

"""

```