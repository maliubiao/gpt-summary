Response:
The user wants a summary of the functionality of the C++ source code file `local_caret_rect_test.cc`. I need to analyze the code to understand its purpose.

The file contains a series of C++ unit tests. These tests seem to be specifically designed to verify the behavior of the `LocalCaretRect` class in various scenarios. `LocalCaretRect` likely represents the visual position and dimensions of the text input cursor (caret) within a rendered web page.

The tests cover different aspects of text rendering and layout, including:

*   **DOM and Shadow DOM:** How the caret position is calculated in both normal DOM and Shadow DOM trees.
*   **Inline Flexbox:** Caret positioning within and around inline-flex containers.
*   **Basic Text:** Caret positioning in simple text content.
*   **Mixed Height Text:** Caret positioning in text with different character heights.
*   **Right-to-Left (RTL) Text:** Caret positioning in RTL text.
*   **Clamping and Rounding:** How caret positions are handled near subpixel boundaries.
*   **Text Overflow:** Caret positioning when text overflows its container.
*   **Vertical Writing Modes:** Caret positioning in vertical text layouts (top-to-bottom and bottom-to-top).
*   **Line Wrapping:** Caret positioning at line breaks and soft wraps.
*   **Images:** Caret positioning before and after images.
*   **Floating Elements:** Caret positioning around floating elements (specifically `::first-letter`).
*   **Line Breaks (`<br>`):** Caret positioning at line break elements.

The tests use a testing framework (`EditingTestBase`) and assertions (`EXPECT_EQ`, `EXPECT_FALSE`) to compare the expected `LocalCaretRect` with the actual calculated value.

**Relationship to JavaScript, HTML, CSS:**

This code directly relates to how HTML content is rendered based on CSS styling. The tests use HTML snippets to set up different layout scenarios and CSS to control the appearance and behavior of the elements. The `LocalCaretRect` is a visual representation derived from this rendering process, which is crucial for text editing and selection, functionalities often interacted with via JavaScript.

**Example Scenarios:**

*   **HTML:** `<div id='text'>Hello</div>` - The tests calculate where the caret should be within this div at different character positions.
*   **CSS:** `div { width: 50px; }` - This CSS rule influences where a line break occurs and thus affects the caret position on the next line.
*   **JavaScript:**  Imagine a JavaScript function that moves the text cursor. This code tests the underlying logic that determines where that cursor *should* be visually.

**User/Programming Errors:**

A common user error could be placing the text cursor in an unexpected location in complex layouts. These tests help ensure the browser handles these cases correctly. A programming error in the rendering engine could lead to incorrect caret positioning, which these tests aim to catch.

**User Steps to Reach Here:**

1. A user opens a web page in a Chromium-based browser.
2. The page contains editable content (e.g., a `<textarea>` or an element with `contenteditable`).
3. The user clicks within the editable content to place the text cursor.
4. The browser's rendering engine calculates the exact visual position of the caret, which is what the `LocalCaretRect` represents. This calculation happens internally within the Blink engine.

**Summary of Functionality (Part 1):**

This C++ source code file (`local_caret_rect_test.cc`) defines unit tests for the `LocalCaretRect` class within the Chromium Blink rendering engine. These tests verify the correct calculation of the caret's position and dimensions in various layout scenarios involving HTML content and CSS styling, including different writing modes, text directions, line wrapping, and the presence of inline elements and images. These tests are crucial for ensuring accurate text editing and selection behavior in web browsers.

这个C++源代码文件 `local_caret_rect_test.cc` 是 Chromium Blink 引擎的一部分，专门用于测试 `LocalCaretRect` 类的功能。 `LocalCaretRect` 类很可能负责计算和表示编辑器中光标（caret）在局部坐标系中的矩形区域。

**功能归纳:**

该文件的主要功能是：**验证 `LocalCaretRect` 类在各种布局场景下是否能正确计算出光标的矩形位置。** 这些场景涵盖了不同的 HTML 结构、CSS 样式以及文本方向等情况。

**与 JavaScript, HTML, CSS 的关系及举例:**

`LocalCaretRect` 的功能与网页的渲染和用户交互密切相关，因此与 JavaScript, HTML, CSS 都有着联系：

*   **HTML (结构):**  测试用例会创建不同的 HTML 结构，例如包含文本节点、内联元素 (`<b>`, `<span>`, `<i>`)、块级元素 (`<div>`)、换行符 (`<br>`)、图片 (`<img>`) 以及 Shadow DOM 的结构。`LocalCaretRect` 需要能够正确处理这些不同的结构，计算出光标在这些元素内部或边缘的正确位置。

    *   **例子:**  测试用例中使用了 `<div id='host'><b slot='#one' id='one'>1</b></div>` 和 `<img id=img width=10px height=10px>` 这样的 HTML 结构来测试光标在这些元素前后的位置。

*   **CSS (样式):**  CSS 样式会影响元素的布局和渲染，从而影响光标的位置。测试用例会设置不同的 CSS 属性，例如 `font-size`, `width`, `height`, `display`, `direction`, `writing-mode`, `word-break`, `vertical-align`, `float` 等，来测试 `LocalCaretRect` 在不同样式下的计算结果。

    *   **例子:** 测试用例中使用了 `style='font: 10px/10px Ahem; width: 30px'` 来设置文本的字体和容器宽度，测试光标在不同字符位置的坐标。 使用 `style='writing-mode: vertical-rl'` 来测试垂直书写模式下的光标位置。

*   **JavaScript (交互):**  虽然这个文件本身是 C++ 代码，但 `LocalCaretRect` 的计算结果会被用于浏览器的编辑功能，这些功能通常会暴露给 JavaScript。 例如，当用户使用 JavaScript 操作光标位置时，浏览器内部会使用 `LocalCaretRect` 来确定光标的视觉位置。

    *   **例子:**  假设一个 JavaScript 代码实现了点击某个位置将光标移动到该位置的功能。浏览器就需要使用类似 `LocalCaretRect` 的机制来确定点击位置对应的文本节点和偏移量，并计算出光标应该显示在哪里。

**逻辑推理 (假设输入与输出):**

测试用例通过 `LocalCaretRectOfPosition` 函数来获取指定位置的光标矩形。

*   **假设输入:**  一个 `Position` 对象，指向 HTML 结构中的某个特定位置（例如，某个文本节点的第几个字符之前或之后，或者某个元素之前或之后）。
*   **预期输出:** 一个 `LocalCaretRect` 对象，包含光标所在的 `layout_object` 指针以及一个 `rect` 矩形，该矩形表示光标在该 `layout_object` 局部坐标系中的位置和大小。

    *   **例子:**  在 `TEST_F(LocalCaretRectTest, SimpleText)` 中，输入 `Position(foo, 0)`，预期输出是 `LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(0, 0, 1, 10))`。这意味着在 `foo` 文本节点的开头，光标的矩形在 `foo` 的布局对象局部坐标系中，起始于 (0, 0)，宽度为 1，高度为 10。

**用户或编程常见的使用错误 (举例说明):**

虽然这个文件是测试代码，但它间接反映了用户在使用浏览器时可能遇到的与光标相关的错误，以及开发者在实现文本编辑功能时可能犯的错误：

*   **用户错误:** 用户可能在复杂的布局中发现光标跳到意想不到的位置，或者光标的显示大小不正确。 这些测试用例旨在预防这种情况。
*   **编程错误:** 渲染引擎的开发者可能会在处理复杂的布局、不同的书写模式或 RTL 文本时，错误地计算光标的位置。 这些测试用例可以帮助开发者尽早发现这些错误。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户打开一个网页:**  用户在 Chromium 浏览器中加载一个包含可编辑内容的网页 (例如，使用了 `contenteditable` 属性的元素或 `<textarea>` 元素)。
2. **用户点击或使用键盘导航:** 用户通过鼠标点击或使用键盘方向键在可编辑内容中移动光标。
3. **浏览器触发光标位置计算:** 当光标位置发生变化时，浏览器内部的渲染引擎需要重新计算光标的视觉位置。
4. **`LocalCaretRect` 被调用:**  渲染引擎会调用 `LocalCaretRect` 相关的代码来获取当前光标在页面上的准确位置和大小。 这个过程是发生在浏览器内部的，用户无法直接感知，但是如果 `LocalCaretRect` 的计算有误，用户就会看到光标显示异常。
5. **测试用例模拟用户操作:**  `local_caret_rect_test.cc` 中的测试用例正是通过模拟各种 HTML 结构和 CSS 样式，以及设定不同的 `Position`，来验证 `LocalCaretRect` 在这些模拟的用户操作场景下是否能正确工作。

**功能归纳 (第1部分):**

总而言之，`blink/renderer/core/editing/local_caret_rect_test.cc` 文件的主要功能是 **作为单元测试，细致地检验 `LocalCaretRect` 类在处理各种网页布局和文本特性时，能否精确地计算出文本光标的局部矩形位置。** 这对于确保用户在网页上进行文本编辑时的良好体验至关重要。

### 提示词
```
这是目录为blink/renderer/core/editing/local_caret_rect_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/local_caret_rect.h"

#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {

bool operator==(const LocalCaretRect& rect1, const LocalCaretRect& rect2) {
  return rect1.layout_object == rect2.layout_object && rect1.rect == rect2.rect;
}

std::ostream& operator<<(std::ostream& out, const LocalCaretRect& caret_rect) {
  return out << "layout_object = " << caret_rect.layout_object
             << ", rect = " << caret_rect.rect;
}

class LocalCaretRectTest : public EditingTestBase {
 protected:
  LocalCaretRect LocalCaretRectOf(
      const Position& position,
      EditingBoundaryCrossingRule rule = kCanCrossEditingBoundary) {
    return LocalCaretRectOfPosition(PositionWithAffinity(position), rule);
  }
};

TEST_F(LocalCaretRectTest, DOMAndFlatTrees) {
  const char* body_content =
      "<p id='host'><b slot='#one' id='one'>1</b></p><b id='two'>22</b>";
  const char* shadow_content =
      "<b id='two'>22</b><slot name=#one></slot><b id='three'>333</b>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");

  Element* one = GetDocument().getElementById(AtomicString("one"));

  const LocalCaretRect& caret_rect_from_dom_tree = LocalCaretRectOfPosition(
      PositionWithAffinity(Position(one->firstChild(), 0)));

  const LocalCaretRect& caret_rect_from_flat_tree = LocalCaretRectOfPosition(
      PositionInFlatTreeWithAffinity(PositionInFlatTree(one->firstChild(), 0)));

  EXPECT_FALSE(caret_rect_from_dom_tree.IsEmpty());
  EXPECT_EQ(caret_rect_from_dom_tree, caret_rect_from_flat_tree);
}

// http://crbug.com/1174101
TEST_F(LocalCaretRectTest, EmptyInlineFlex) {
  LoadAhem();
  InsertStyleElement(R"CSS(
    div { font: 10px/15px Ahem; width: 100px; }
    i {
        display: inline-flex;
        width: 30px; height: 30px;
        border: solid 10px red;
    })CSS");
  // |ComputeInlinePosition(AfterChildren:<div>)=AfterChildren:<b>
  // When removing <i>, we have <b>@0
  SetBodyContent(
      "<div id=target contenteditable>"
      "ab<i contenteditable=false><b></b></i></div>");
  const auto& target = *GetElementById("target");
  const auto& ab = *To<Text>(target.firstChild());
  const auto& inline_flex = *ab.nextSibling();
  const LocalCaretRect before_ab =
      LocalCaretRect(ab.GetLayoutObject(), {0, 32, 1, 10});
  const LocalCaretRect before_inline_flex =
      LocalCaretRect(ab.GetLayoutObject(), {20, 32, 1, 10});
  const LocalCaretRect after_inline_flex =
      LocalCaretRect(inline_flex.GetLayoutObject(), {49, 0, 1, 50});

  EXPECT_EQ(before_ab, LocalCaretRectOf(Position(target, 0)));
  EXPECT_EQ(before_inline_flex, LocalCaretRectOf(Position(target, 1)));
  EXPECT_EQ(after_inline_flex, LocalCaretRectOf(Position(target, 2)));
  EXPECT_EQ(before_ab, LocalCaretRectOf(Position::BeforeNode(target)));
  EXPECT_EQ(after_inline_flex, LocalCaretRectOf(Position::AfterNode(target)));
  EXPECT_EQ(after_inline_flex,
            LocalCaretRectOf(Position::LastPositionInNode(target)));
}

TEST_F(LocalCaretRectTest, SimpleText) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<div id=div style='font: 10px/10px Ahem; width: 30px'>XXX</div>");
  const Node* foo = GetElementById("div")->firstChild();

  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(0, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 0), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(10, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 1), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(20, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 2), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(29, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 3), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, MixedHeightText) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<div id=div style='font: 10px/10px Ahem; width: 30px'>Xpp</div>");
  const Node* foo = GetElementById("div")->firstChild();

  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(0, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 0), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(10, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 1), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(20, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 2), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(29, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 3), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, RtlText) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<bdo dir=rtl id=bdo style='display: block; "
      "font: 10px/10px Ahem; width: 30px'>XXX</bdo>");
  const Node* foo = GetElementById("bdo")->firstChild();

  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(29, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 0), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(20, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 1), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(10, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 2), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(0, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 3), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, ClampingAndRounding) {
  // crbug.com/1228620
  LoadAhem();
  SetBodyContent(R"HTML(
      <style>
      #root {
        margin-left: 0.6px;
        width: 150.6px;
        text-align: right;
        font: 30px/30px Ahem;
      }
      </style>
      <div id=root>def</div>)HTML");
  const Node* text = GetElementById("root")->firstChild();
  EXPECT_EQ(
      LocalCaretRect(text->GetLayoutObject(), PhysicalRect(149, 0, 1, 30)),
      LocalCaretRectOfPosition(
          PositionWithAffinity(Position(text, 3), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, OverflowTextLtr) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<div id=root style='font: 10px/10px Ahem; width: 30px'>"
      "XXXX"
      "</div>");
  const Node* text = GetElementById("root")->firstChild();
  EXPECT_EQ(LocalCaretRect(text->GetLayoutObject(), PhysicalRect(0, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(text, 0), TextAffinity::kDownstream)));
  // LocalCaretRect may be outside the containing block.
  EXPECT_EQ(LocalCaretRect(text->GetLayoutObject(), PhysicalRect(39, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(text, 4), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, UnderflowTextLtr) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<div id=root style='font: 10px/10px Ahem; width: 30px'>"
      "XX"
      "</div>");
  const Node* text = GetElementById("root")->firstChild();
  EXPECT_EQ(LocalCaretRect(text->GetLayoutObject(), PhysicalRect(0, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(text, 0), TextAffinity::kDownstream)));
  // LocalCaretRect may be outside the containing block.
  EXPECT_EQ(LocalCaretRect(text->GetLayoutObject(), PhysicalRect(20, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(text, 2), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, OverflowTextRtl) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<bdo id=root style='display:block; font: 10px/10px Ahem; width: 30px' "
      "dir=rtl>"
      "XXXX"
      "</bdo>");
  const Node* text = GetElementById("root")->firstChild();
  EXPECT_EQ(LocalCaretRect(text->GetLayoutObject(), PhysicalRect(29, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(text, 0), TextAffinity::kDownstream)));
  // LocalCaretRect may be outside the containing block.
  EXPECT_EQ(
      LocalCaretRect(text->GetLayoutObject(), PhysicalRect(-10, 0, 1, 10)),
      LocalCaretRectOfPosition(
          PositionWithAffinity(Position(text, 4), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, UnderflowTextRtl) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<bdo id=root style='display:block; font: 10px/10px Ahem; width: 30px' "
      "dir=rtl>"
      "XX"
      "</bdo>");
  const Node* text = GetElementById("root")->firstChild();
  EXPECT_EQ(LocalCaretRect(text->GetLayoutObject(), PhysicalRect(29, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(text, 0), TextAffinity::kDownstream)));
  // LocalCaretRect may be outside the containing block.
  EXPECT_EQ(LocalCaretRect(text->GetLayoutObject(), PhysicalRect(10, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(text, 2), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, VerticalRLText) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<div id=div style='writing-mode: vertical-rl; word-break: break-all; "
      "font: 10px/10px Ahem; width: 30px; height: 30px'>XXXYYYZZZ</div>");
  const Node* foo = GetElementById("div")->firstChild();

  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(20, 0, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 0), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(20, 10, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 1), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(20, 20, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 2), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(20, 29, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 3), TextAffinity::kUpstream)));

  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(10, 0, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 3), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(10, 10, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 4), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(10, 20, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 5), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(10, 29, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 6), TextAffinity::kUpstream)));

  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(0, 0, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 6), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(0, 10, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 7), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(0, 20, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 8), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(0, 29, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 9), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, VerticalLRText) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<div id=div style='writing-mode: vertical-lr; word-break: break-all; "
      "font: 10px/10px Ahem; width: 30px; height: 30px'>XXXYYYZZZ</div>");
  const Node* foo = GetElementById("div")->firstChild();

  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(0, 0, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 0), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(0, 10, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 1), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(0, 20, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 2), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(0, 29, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 3), TextAffinity::kUpstream)));

  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(10, 0, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 3), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(10, 10, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 4), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(10, 20, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 5), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(10, 29, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 6), TextAffinity::kUpstream)));

  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(20, 0, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 6), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(20, 10, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 7), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(20, 20, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 8), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(20, 29, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 9), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, OverflowTextVerticalLtr) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<div id=root style='font: 10px/10px Ahem; height: 30px; writing-mode: "
      "vertical-lr'>"
      "XXXX"
      "</div>");
  const Node* text = GetElementById("root")->firstChild();
  EXPECT_EQ(LocalCaretRect(text->GetLayoutObject(), PhysicalRect(0, 0, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(text, 0), TextAffinity::kDownstream)));
  // LocalCaretRect may be outside the containing block.
  EXPECT_EQ(LocalCaretRect(text->GetLayoutObject(), PhysicalRect(0, 39, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(text, 4), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, UnderflowTextVerticalLtr) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<div id=root style='font: 10px/10px Ahem; height: 30px; writing-mode: "
      "vertical-lr'>"
      "XX"
      "</div>");
  const Node* text = GetElementById("root")->firstChild();
  EXPECT_EQ(LocalCaretRect(text->GetLayoutObject(), PhysicalRect(0, 0, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(text, 0), TextAffinity::kDownstream)));
  // LocalCaretRect may be outside the containing block.
  EXPECT_EQ(LocalCaretRect(text->GetLayoutObject(), PhysicalRect(0, 20, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(text, 2), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, OverflowTextVerticalRtl) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<bdo id=root style='display:block; font: 10px/10px Ahem; height: 30px; "
      "writing-mode: vertical-lr' dir=rtl>"
      "XXXX"
      "</bdo>");
  const Node* text = GetElementById("root")->firstChild();
  EXPECT_EQ(LocalCaretRect(text->GetLayoutObject(), PhysicalRect(0, 29, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(text, 0), TextAffinity::kDownstream)));
  // LocalCaretRect may be outside the containing block.
  EXPECT_EQ(
      LocalCaretRect(text->GetLayoutObject(), PhysicalRect(0, -10, 10, 1)),
      LocalCaretRectOfPosition(
          PositionWithAffinity(Position(text, 4), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, UnderflowTextVerticalRtl) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<bdo id=root style='display:block; font: 10px/10px Ahem; height: 30px; "
      "writing-mode: vertical-lr' dir=rtl>"
      "XX"
      "</bdo>");
  const Node* text = GetElementById("root")->firstChild();
  EXPECT_EQ(LocalCaretRect(text->GetLayoutObject(), PhysicalRect(0, 29, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(text, 0), TextAffinity::kDownstream)));
  // LocalCaretRect may be outside the containing block.
  EXPECT_EQ(LocalCaretRect(text->GetLayoutObject(), PhysicalRect(0, 10, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(text, 2), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, TwoLinesOfTextWithSoftWrap) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<div id=div style='font: 10px/10px Ahem; width: 30px; "
      "word-break: break-all'>XXXXXX</div>");
  const Node* foo = GetElementById("div")->firstChild();

  // First line
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(0, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 0), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(10, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 1), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(20, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 2), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(29, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 3), TextAffinity::kUpstream)));

  // Second line
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(0, 10, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 3), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(10, 10, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 4), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(20, 10, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 5), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(29, 10, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 6), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, SoftLineWrapBetweenMultipleTextNodes) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<div style='font: 10px/10px Ahem; width: 30px; word-break: break-all'>"
      "<span>A</span>"
      "<span>B</span>"
      "<span id=span-c>C</span>"
      "<span id=span-d>D</span>"
      "<span>E</span>"
      "<span>F</span>"
      "</div>");
  const Node* text_c = GetElementById("span-c")->firstChild();
  const Node* text_d = GetElementById("span-d")->firstChild();

  const Position after_c(text_c, 1);
  EXPECT_EQ(
      LocalCaretRect(text_c->GetLayoutObject(), PhysicalRect(29, 0, 1, 10)),
      LocalCaretRectOfPosition(
          PositionWithAffinity(after_c, TextAffinity::kUpstream)));
  EXPECT_EQ(
      LocalCaretRect(text_d->GetLayoutObject(), PhysicalRect(0, 10, 1, 10)),
      LocalCaretRectOfPosition(
          PositionWithAffinity(after_c, TextAffinity::kDownstream)));

  const Position before_d(text_d, 0);
  EXPECT_EQ(
      LocalCaretRect(text_d->GetLayoutObject(), PhysicalRect(0, 10, 1, 10)),
      LocalCaretRectOfPosition(
          PositionWithAffinity(before_d, TextAffinity::kUpstream)));
  EXPECT_EQ(
      LocalCaretRect(text_d->GetLayoutObject(), PhysicalRect(0, 10, 1, 10)),
      LocalCaretRectOfPosition(
          PositionWithAffinity(before_d, TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, SoftLineWrapBetweenMultipleTextNodesRtl) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<bdo dir=rtl style='font: 10px/10px Ahem; width: 30px; "
      "word-break: break-all; display: block'>"
      "<span>A</span>"
      "<span>B</span>"
      "<span id=span-c>C</span>"
      "<span id=span-d>D</span>"
      "<span>E</span>"
      "<span>F</span>"
      "</bdo>");
  const Node* text_c = GetElementById("span-c")->firstChild();
  const Node* text_d = GetElementById("span-d")->firstChild();

  const Position after_c(text_c, 1);
  EXPECT_EQ(
      LocalCaretRect(text_c->GetLayoutObject(), PhysicalRect(0, 0, 1, 10)),
      LocalCaretRectOfPosition(
          PositionWithAffinity(after_c, TextAffinity::kUpstream)));
  EXPECT_EQ(
      LocalCaretRect(text_d->GetLayoutObject(), PhysicalRect(29, 10, 1, 10)),
      LocalCaretRectOfPosition(
          PositionWithAffinity(after_c, TextAffinity::kDownstream)));

  const Position before_d(text_d, 0);
  EXPECT_EQ(
      LocalCaretRect(text_d->GetLayoutObject(), PhysicalRect(29, 10, 1, 10)),
      LocalCaretRectOfPosition(
          PositionWithAffinity(before_d, TextAffinity::kUpstream)));
  EXPECT_EQ(
      LocalCaretRect(text_d->GetLayoutObject(), PhysicalRect(29, 10, 1, 10)),
      LocalCaretRectOfPosition(
          PositionWithAffinity(before_d, TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, CaretRectAtBR) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<div style='font: 10px/10px Ahem; width: 30px'><br>foo</div>");
  const Element& br = *GetDocument().QuerySelector(AtomicString("br"));

  EXPECT_EQ(LocalCaretRect(br.GetLayoutObject(), PhysicalRect(0, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position::BeforeNode(br), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, CaretRectAtRtlBR) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<bdo dir=rtl style='display: block; font: 10px/10px Ahem; width: 30px'>"
      "<br>foo</bdo>");
  const Element& br = *GetDocument().QuerySelector(AtomicString("br"));

  EXPECT_EQ(LocalCaretRect(br.GetLayoutObject(), PhysicalRect(29, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position::BeforeNode(br), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, Images) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<div id=div style='font: 10px/10px Ahem; width: 30px'>"
      "<img id=img1 width=10px height=10px>"
      "<img id=img2 width=10px height=10px>"
      "</div>");

  const Element& img1 = *GetElementById("img1");

  EXPECT_EQ(LocalCaretRect(img1.GetLayoutObject(), PhysicalRect(0, 0, 1, 12)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position::BeforeNode(img1), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(img1.GetLayoutObject(), PhysicalRect(9, 0, 1, 12)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position::AfterNode(img1), TextAffinity::kDownstream)));

  const Element& img2 = *GetElementById("img2");

  // Box-anchored LocalCaretRect is local to the box itself, instead of its
  // containing block.
  EXPECT_EQ(LocalCaretRect(img1.GetLayoutObject(), PhysicalRect(9, 0, 1, 12)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position::BeforeNode(img2), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(img2.GetLayoutObject(), PhysicalRect(9, 0, 1, 12)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position::AfterNode(img2), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, RtlImages) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<bdo dir=rtl style='font: 10px/10px Ahem; width: 30px; display: block'>"
      "<img id=img1 width=10px height=10px>"
      "<img id=img2 width=10px height=10px>"
      "</bdo>");

  const Element& img1 = *GetElementById("img1");
  const Element& img2 = *GetElementById("img2");

  // Box-anchored LocalCaretRect is local to the box itself, instead of its
  // containing block.
  EXPECT_EQ(LocalCaretRect(img1.GetLayoutObject(), PhysicalRect(9, 0, 1, 12)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position::BeforeNode(img1), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(img2.GetLayoutObject(), PhysicalRect(9, 0, 1, 12)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position::AfterNode(img1), TextAffinity::kDownstream)));

  EXPECT_EQ(LocalCaretRect(img2.GetLayoutObject(), PhysicalRect(9, 0, 1, 12)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position::BeforeNode(img2), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(img2.GetLayoutObject(), PhysicalRect(0, 0, 1, 12)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position::AfterNode(img2), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, VerticalImage) {
  // This test only records the current behavior. Future changes are allowed.

  SetBodyContent(
      "<div style='writing-mode: vertical-rl'>"
      "<img id=img width=10px height=20px>"
      "</div>");

  const Element& img = *GetElementById("img");

  // Box-anchored LocalCaretRect is local to the box itself, instead of its
  // containing block.
  EXPECT_EQ(LocalCaretRect(img.GetLayoutObject(), PhysicalRect(0, 0, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position::BeforeNode(img), TextAffinity::kDownstream)));

  EXPECT_EQ(LocalCaretRect(img.GetLayoutObject(), PhysicalRect(0, 19, 10, 1)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position::AfterNode(img), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, TextAndImageMixedHeight) {
  // This test only records the current behavior. Future changes are allowed.

  LoadAhem();
  SetBodyContent(
      "<div id=div style='font: 10px/10px Ahem; width: 30px'>"
      "X"
      "<img id=img width=10px height=5px style='vertical-align: text-bottom'>"
      "p</div>");

  const Element& img = *GetElementById("img");
  const Node* text1 = img.previousSibling();
  const Node* text2 = img.nextSibling();

  EXPECT_EQ(LocalCaretRect(text1->GetLayoutObject(), PhysicalRect(0, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(text1, 0), TextAffinity::kDownstream)));
  EXPECT_EQ(
      LocalCaretRect(text1->GetLayoutObject(), PhysicalRect(10, 0, 1, 10)),
      LocalCaretRectOfPosition(
          PositionWithAffinity(Position(text1, 1), TextAffinity::kDownstream)));

  EXPECT_EQ(
      LocalCaretRect(text1->GetLayoutObject(), PhysicalRect(10, 0, 1, 10)),
      LocalCaretRectOfPosition(PositionWithAffinity(
          Position::BeforeNode(img), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(img.GetLayoutObject(), PhysicalRect(9, -5, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position::AfterNode(img), TextAffinity::kDownstream)));

  EXPECT_EQ(
      LocalCaretRect(text2->GetLayoutObject(), PhysicalRect(20, 0, 1, 10)),
      LocalCaretRectOfPosition(
          PositionWithAffinity(Position(text2, 0), TextAffinity::kDownstream)));
  EXPECT_EQ(
      LocalCaretRect(text2->GetLayoutObject(), PhysicalRect(29, 0, 1, 10)),
      LocalCaretRectOfPosition(
          PositionWithAffinity(Position(text2, 1), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, FloatFirstLetter) {
  LoadAhem();
  InsertStyleElement("#container::first-letter{float:right}");
  SetBodyContent(
      "<div id=container style='font: 10px/10px Ahem; width: 40px'>foo</div>");
  const Node* foo = GetElementById("container")->firstChild();
  const LayoutObject* first_letter = AssociatedLayoutObjectOf(*foo, 0);
  const LayoutObject* remaining_text = AssociatedLayoutObjectOf(*foo, 1);

  EXPECT_EQ(LocalCaretRect(first_letter, PhysicalRect(0, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 0), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(remaining_text, PhysicalRect(0, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 1), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(remaining_text, PhysicalRect(10, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 2), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(remaining_text, PhysicalRect(20, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 3), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, AfterLineBreak) {
  LoadAhem();
  SetBodyContent("<div style='font: 10px/10px Ahem;'>foo<br><br></div>");
  const Node* div = GetDocument().body()->firstChild();
  const Node* foo = div->firstChild();
  const Node* first_br = foo->nextSibling();
  const Node* second_br = first_br->nextSibling();
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(30, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position::AfterNode(*foo), TextAffinity::kDownstream)));
  EXPECT_EQ(
      LocalCaretRect(second_br->GetLayoutObject(), PhysicalRect(0, 10, 1, 10)),
      LocalCaretRe
```