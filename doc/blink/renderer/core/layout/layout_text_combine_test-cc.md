Response:
The user has provided the first part of a Chromium Blink engine source code file (`layout_text_combine_test.cc`) and asked for a summary of its functionality.

Here's a breakdown of the thinking process to generate the response:

1. **Identify the Core Purpose:** The file name `layout_text_combine_test.cc` strongly suggests that it contains tests related to the `LayoutTextCombine` functionality. The presence of `#include "third_party/blink/renderer/core/layout/layout_text_combine.h"` confirms this.

2. **Recognize the Testing Framework:** The `#include "testing/gmock/include/gmock/gmock.h"` and the use of `TEST_F` macros indicate that this file uses the Google Test (gtest) framework, often extended with Google Mock (gmock) for more advanced assertions. The base class `RenderingTest` further implies that these tests focus on the rendering aspects of the engine.

3. **Analyze the Included Headers:**  The included headers provide clues about the areas being tested:
    * `v8_binding_for_testing.h`: Interaction with the V8 JavaScript engine.
    * `css_style_declaration.h`: Testing how CSS properties like `text-combine-upright` are handled.
    * `dom/text.h`, `html/html_br_element.h`: Testing interactions with DOM elements and nodes.
    * `inline/fragment_item.h`, `inline/inline_cursor.h`, `physical_box_fragment.h`:  Focus on the internal layout structure and how combined text is represented in the rendering tree.
    * `core_unit_test_helper.h`: Standard Blink testing utilities.

4. **Examine the Test Fixture:** The `LayoutTextCombineTest` class inherits from `RenderingTest`, setting up the environment for rendering tests. The `AsInkOverflowString` and `ContentsInkOverflow` methods suggest that a significant part of the testing involves examining the ink overflow of elements, particularly those with combined text. Ink overflow is how the rendering engine tracks the area occupied by an element and its decorations, even if they extend beyond its content box.

5. **Go Through Each Test Case:** Each `TEST_F` function represents a specific test scenario. Analyzing the code within each test helps to understand the detailed functionality being verified. Look for:
    * **Setup:** `InsertStyleElement` (injecting CSS), `SetBodyInnerHTML` (setting up the HTML structure).
    * **Actions:** DOM manipulations like `appendChild`, `deleteData`, `insertBefore`, `remove`, setting style properties (`setProperty`).
    * **Assertions:** `EXPECT_EQ` with `ToSimpleLayoutTree` (comparing the generated layout tree with an expected structure), and checks on ink overflow using `AsInkOverflowString`.

6. **Identify Key CSS Properties:** The frequent use of `text-combine-upright` and `writing-mode` is crucial. These CSS properties directly control the text combination feature being tested and the direction of text flow.

7. **Look for Specific Bug Fixes:** The comments like `// http://crbug.com/1228058` indicate that some tests are designed to prevent regressions of specific previously reported bugs. This gives insight into potential edge cases or issues that the `LayoutTextCombine` functionality might have faced.

8. **Synthesize the Functionality:** Based on the analysis of the tests, identify the core functionalities being tested:
    * Correct creation and structure of the layout tree when `text-combine-upright` is used.
    * Handling of DOM manipulations (adding, deleting, inserting nodes) within elements with combined text.
    * Calculation of ink overflow for elements with combined text, including decorations like underlines, overlines, and emphasis marks.
    * Interactions with other layout features like line breaks (`<br>`), word breaks (`<wbr>`), list markers, and details elements.
    * Handling of writing modes and their propagation.
    * Correctness in various scenarios, including nested elements and multiple text nodes.

9. **Connect to Web Technologies (JavaScript, HTML, CSS):** Explicitly link the observed behavior in the tests to how these technologies interact. For example:
    * **CSS:** `text-combine-upright` is the central CSS property being tested. `writing-mode` influences the layout of combined text. Text decorations and emphasis marks also play a role.
    * **HTML:** The tests use various HTML elements (`<div>`, `<c>`, `<br>`, `<p>`, `<li>`, `<details>`, `<summary>`) to create different layout scenarios.
    * **JavaScript:** DOM manipulation methods like `appendChild`, `insertBefore`, `remove`, and accessing element styles are used to trigger layout changes, reflecting how JavaScript interacts with the layout engine.

10. **Infer Logic and Assumptions:**  When possible, deduce the underlying logic being tested. For example, tests involving adding or removing nodes implicitly test the logic for updating the layout tree when the DOM changes. The ink overflow tests verify the logic for calculating bounding boxes.

11. **Consider User/Programming Errors:** Think about common mistakes developers might make when working with `text-combine-upright` and how the tests might implicitly cover or expose these. For example, incorrect nesting or unexpected behavior when combining with other CSS properties.

12. **Structure the Summary:** Organize the findings into a coherent summary, starting with the main purpose and then detailing the specific aspects being tested, linking them back to web technologies and potential errors. Use clear and concise language.
```
功能归纳：

这个C++源代码文件 `layout_text_combine_test.cc` 是 Chromium Blink 渲染引擎的一部分，专门用于测试 `LayoutTextCombine` 类的功能。`LayoutTextCombine` 负责处理文本的“组合竖排”效果，这是一种将多个字符组合成一个竖排字形的功能，常用于东亚语言排版。

具体来说，这个测试文件旨在验证在各种场景下 `LayoutTextCombine` 的行为是否正确，包括：

1. **DOM 操作:** 测试在包含 `text-combine-upright` 属性的元素中添加、删除、插入子节点（包括文本节点和其他元素节点）时，布局树的结构是否正确更新。
2. **边界情况:** 测试当 `text-combine-upright` 应用于包含其他内联或块级元素的复杂结构时，布局树的构建是否正确。
3. **删除数据:** 测试当通过 JavaScript 删除 `text-combine-upright` 元素中的文本数据，直到为空时，布局树的更新是否正确。
4. **样式重算:** 测试当 `text-combine-upright` 元素或其子元素的样式发生变化时，布局树是否能正确重新计算。
5. **应用于 HTML 根元素:** 测试当 `text-combine-upright` 应用于 `<html>` 元素时，是否能正确处理。
6. **墨水溢出 (Ink Overflow):**  详细测试了在应用 `text-combine-upright` 的元素中，各种情况下（包括添加 emphasis marks, overline, underline, `<wbr>` 标签等）墨水溢出区域的计算是否正确。墨水溢出指的是元素绘制内容超出其布局边界的区域，例如文本装饰线。
7. **滚动溢出:** 测试在垂直书写模式下，包含 `text-combine-upright` 元素的容器是否正确报告滚动溢出。
8. **列表项标记:** 测试当 `text-combine-upright` 应用于列表项时，列表标记的布局和样式变化（例如使用图片作为标记）是否正确处理。
9. **多个文本节点:** 测试在 `text-combine-upright` 元素中存在多个相邻文本节点时，布局是否正确。
10. **嵌套:** 测试 `text-combine-upright` 元素的嵌套使用是否能正确构建布局树。
11. **轮廓 (Outline):** 测试应用 `text-combine-upright` 的元素在绘制轮廓时的边界计算是否正确。
12. **书写模式传播:** 测试 `text-combine-upright` 与 `writing-mode` 属性的相互作用，以及书写模式从 `<body>` 元素向 `<html>` 元素的传播。
13. **Details 元素:** 测试 `text-combine-upright` 应用于 `<details>` 元素时的布局更新机制。
14. **移除块级子元素:** 测试当移除包含在应用 `text-combine-upright` 的元素中的块级子元素时，布局树的更新是否正确。
15. **移除组合元素:** 测试直接移除应用了 `text-combine-upright` 的元素时，布局树的更新是否正确。
16. **移除子节点至空:** 测试当移除 `text-combine-upright` 元素的子节点直到该元素为空时，布局树的更新是否正确。

总而言之，这个测试文件全面覆盖了 `LayoutTextCombine` 类在各种DOM结构、样式变化和用户交互下的行为，确保了“组合竖排”功能在 Blink 引擎中的正确实现。
```

**与 JavaScript, HTML, CSS 的关系和举例说明:**

这个测试文件直接测试了 CSS 属性 `text-combine-upright` 的渲染效果，该属性通常与 `writing-mode` 属性结合使用。它通过 JavaScript 操作 DOM 来模拟各种场景，并使用 Blink 引擎的内部 API 来检查最终的布局结果。

* **CSS:**
    * **`text-combine-upright: all;`**:  这是测试的核心 CSS 属性。它指示将元素内的文本组合成竖排形式。例如，在测试用例中，会插入这样的 CSS 规则来激活组合竖排效果：
      ```cpp
      InsertStyleElement("c { text-combine-upright: all; }");
      ```
    * **`writing-mode: vertical-rl;` 或 `writing-mode: vertical-lr;`**: 这些属性定义了文本的阅读方向是垂直的，从右到左或从左到右。 这与 `text-combine-upright` 结合使用，以指定组合后的文本如何排列。例如：
      ```cpp
      InsertStyleElement("div { writing-mode: vertical-rl; }");
      ```
    * **其他 CSS 属性:** 测试还涉及到其他 CSS 属性对组合竖排文本的影响，例如 `color`, `list-style-image`, `text-decoration`, `-webkit-text-emphasis`。

* **HTML:**
    * 测试用例通过 `SetBodyInnerHTML()` 函数动态创建 HTML 结构，以模拟不同的布局场景。例如：
      ```cpp
      SetBodyInnerHTML("<div id=root>ab<c id=combine>XY</c>de</div>");
      ```
      这里的 `<c>` 元素很可能被 CSS 选择器选中并应用了 `text-combine-upright` 属性。
    * 使用了各种 HTML 元素，如 `<div>`, `<span>` (虽然代码中用 `<c>`，但逻辑上是内联元素), `<br>`, `<p>`, `<li>`, `<details>`, `<summary>`, `<wbr>` 等，来测试 `LayoutTextCombine` 在不同 HTML 结构下的表现。

* **JavaScript:**
    * 测试代码使用 Blink 引擎提供的 JavaScript 绑定接口（例如 `GetElementById()`, `appendChild()`, `insertBefore()`, `remove()`, `style()->setProperty()`, `firstChild()`, `deleteData()`) 来模拟 JavaScript 对 DOM 的操作。这些操作会导致布局树的更新，而测试会验证更新后的布局是否符合预期。例如：
      ```cpp
      GetElementById("combine")->appendChild(Text::Create(GetDocument(), "Z"));
      ```
      这行代码模拟了通过 JavaScript 向组合竖排元素中添加新的文本节点。
      ```cpp
      To<Text>(GetElementById("combine")->firstChild())->deleteData(0, 2, ASSERT_NO_EXCEPTION);
      ```
      这行代码模拟了通过 JavaScript 删除组合竖排元素中第一个文本节点的部分内容。
      ```cpp
      root.style()->setProperty(GetDocument().GetExecutionContext(), "color", "red", "", ASSERT_NO_EXCEPTION);
      ```
      这行代码模拟了通过 JavaScript 修改元素的样式。

**逻辑推理的假设输入与输出:**

**示例 1：`AppendChild` 测试**

* **假设输入:**
    * HTML: `<div id=root>ab<c id=combine>XY</c>de</div>`
    * CSS: `c { text-combine-upright: all; } div { writing-mode: vertical-rl; }`
    * JavaScript 操作:  `GetElementById("combine")->appendChild(Text::Create(GetDocument(), "Z"));`
* **逻辑推理:**  当向应用了 `text-combine-upright` 的元素中添加新的文本节点时，新的文本节点应该被包含在已有的 `LayoutTextCombine` 对象中。
* **预期输出 (布局树):**
```
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "XY"
  |  |  +--LayoutText #text "Z"
  +--LayoutText #text "de"
```

**示例 2：`InkOverflow` 测试**

* **假设输入:**
    * HTML: `<div id=root>a<c id=combine>0123456789</c>b</div>`
    * CSS: `body { font: 100px/110px Ahem; } c { text-combine-upright: all; } div { writing-mode: vertical-rl; }`
* **逻辑推理:**  对于组合竖排的文本，其墨水溢出区域需要覆盖组合后的字符所占的空间。
* **预期输出 (部分墨水溢出信息):**
```
{Box #descendants=2 Standard}
                 Rect "5,100 100x100"
          InkOverflow "-5,0 110x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "-5,0 110x100"
```
这里 `InkOverflow` 的宽度为 110px，比 `Rect` 的宽度 100px 大，这是因为墨水溢出需要考虑组合字符的实际绘制宽度。

**涉及用户或者编程常见的使用错误举例:**

1. **错误地将 `text-combine-upright` 应用于块级元素并期望其子元素组合:** 用户可能会错误地认为将 `text-combine-upright` 应用于 `<div>` 等块级元素会自动将其所有子元素的内容组合起来。实际上，`text-combine-upright` 主要影响应用该属性的元素内的文本内容。
   ```html
   <style>
     #container { text-combine-upright: all; }
   </style>
   <div id="container">
     <span>一</span><span>二</span>
   </div>
   ```
   在这个例子中，`<span>` 元素的内容不会被组合成一个竖排的“一二”，而是每个 `<span>` 的内容可能会单独进行竖排（如果其内部文本满足组合条件）。

2. **忘记设置 `writing-mode`:**  `text-combine-upright` 通常与 `writing-mode` 结合使用。如果只设置了 `text-combine-upright` 而没有设置 `writing-mode: vertical-rl;` 或 `writing-mode: vertical-lr;`，那么组合竖排的效果可能不会如预期显示，因为默认的书写模式是水平的。

3. **在不适合组合的文本上使用 `text-combine-upright`:**  `text-combine-upright` 主要用于处理少量字符的组合。将其应用于大量文本可能会导致意想不到的布局问题或性能问题。

4. **与某些 CSS 属性的冲突:** 某些 CSS 属性可能与 `text-combine-upright` 的效果相互影响，导致不期望的渲染结果。例如，过度使用 `letter-spacing` 或复杂的文本装饰可能会使组合竖排的效果难以辨认。

5. **动态修改 DOM 或样式后未正确触发重排:** 在 JavaScript 中动态添加、删除或修改元素的样式时，如果没有正确触发浏览器的重排（reflow），可能会导致 `text-combine-upright` 的效果没有及时更新。

这个测试文件通过覆盖各种场景，有助于开发者理解 `text-combine-upright` 的行为，并避免在使用过程中出现这些常见的错误。

### 提示词
```
这是目录为blink/renderer/core/layout/layout_text_combine_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/layout_text_combine.h"

#include <sstream>
#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/css/css_style_declaration.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {

using ::testing::ElementsAre;

class LayoutTextCombineTest : public RenderingTest {
 protected:
  std::string AsInkOverflowString(const LayoutBlockFlow& root) {
    std::ostringstream ostream;
    ostream << std::endl;
    for (InlineCursor cursor(root); cursor; cursor.MoveToNext()) {
      ostream << cursor.CurrentItem() << std::endl;
      ostream << "                 Rect "
              << cursor.CurrentItem()->RectInContainerFragment() << std::endl;
      ostream << "          InkOverflow "
              << cursor.CurrentItem()->InkOverflowRect() << std::endl;
      ostream << "      SelfInkOverflow "
              << cursor.CurrentItem()->SelfInkOverflowRect() << std::endl;
      ostream << "  ContentsInkOverflow "
              << ContentsInkOverflow(*cursor.CurrentItem()) << std::endl;
    }
    return ostream.str();
  }

  static PhysicalRect ContentsInkOverflow(const FragmentItem& item) {
    if (const PhysicalBoxFragment* box_fragment = item.BoxFragment()) {
      return box_fragment->ContentsInkOverflowRect();
    }
    if (!item.HasInkOverflow()) {
      return PhysicalRect();
    }
    return item.ink_overflow_.Contents(item.InkOverflowType(), item.Size());
  }
};

TEST_F(LayoutTextCombineTest, AppendChild) {
  InsertStyleElement(
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine>XY</c>de</div>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));

  GetElementById("combine")->appendChild(Text::Create(GetDocument(), "Z"));
  RunDocumentLifecycle();
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "XY"
  |  |  +--LayoutText #text "Z"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

TEST_F(LayoutTextCombineTest, BoxBoundary) {
  InsertStyleElement(
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine>X<b>Y</b></c>de</div>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "X"
  |  +--LayoutInline B
  |  |  +--LayoutTextCombine (anonymous)
  |  |  |  +--LayoutText #text "Y"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

TEST_F(LayoutTextCombineTest, DeleteDataToEmpty) {
  InsertStyleElement(
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine>XY</c>de</div>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));

  To<Text>(GetElementById("combine")->firstChild())
      ->deleteData(0, 2, ASSERT_NO_EXCEPTION);
  RunDocumentLifecycle();
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

// http://crbug.com/1228058
TEST_F(LayoutTextCombineTest, ElementRecalcOwnStyle) {
  InsertStyleElement(
      "#root { text-combine-upright: all; writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root><br id=target></div>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutTextCombine (anonymous)
  |  +--LayoutBR BR id="target"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));

  // Call |Element::RecalcOwnStyle()| for <br>
  auto& target = *GetElementById("target");
  target.style()->setProperty(GetDocument().GetExecutionContext(), "color",
                              "red", "", ASSERT_NO_EXCEPTION);
  RunDocumentLifecycle();

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutTextCombine (anonymous)
  |  +--LayoutBR BR id="target" style="color: red;"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

// http://crbug.com/1241194
TEST_F(LayoutTextCombineTest, HtmlElement) {
  InsertStyleElement(
      "html {"
      "text-combine-upright: all;"
      "writing-mode: vertical-lr;"
      "}");

  // Make |Text| node child in <html> element to call
  // |HTMLHtmlElement::PropagateWritingModeAndDirectionFromBody()|
  GetDocument().documentElement()->appendChild(
      Text::Create(GetDocument(), "X"));

  RunDocumentLifecycle();

  EXPECT_EQ(
      R"DUMP(
LayoutBlockFlow HTML
  +--LayoutBlockFlow BODY
  +--LayoutBlockFlow (anonymous)
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "X"
)DUMP",
      ToSimpleLayoutTree(*GetDocument().documentElement()->GetLayoutObject()));
}

TEST_F(LayoutTextCombineTest, InkOverflow) {
  LoadAhem();
  InsertStyleElement(
      "body { font: 100px/110px Ahem; }"
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>a<c id=combine>0123456789</c>b</div>");
  const auto& root =
      *To<LayoutBlockFlow>(GetElementById("root")->GetLayoutObject());

  EXPECT_EQ(R"DUMP(
{Line #descendants=5 LTR Standard}
                 Rect "0,0 110x300"
          InkOverflow "0,0 110x300"
      SelfInkOverflow "0,0 110x300"
  ContentsInkOverflow "0,0 0x0"
{Text 0-1 LTR Standard}
                 Rect "5,0 100x100"
          InkOverflow "0,0 100x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "0,0 0x0"
{Box #descendants=2 Standard}
                 Rect "5,100 100x100"
          InkOverflow "-5,0 110x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "-5,0 110x100"
{Box #descendants=1 AtomicInlineLTR Standard}
                 Rect "5,100 100x100"
          InkOverflow "-5,0 110x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "-5,0 110x100"
{Text 2-3 LTR Standard}
                 Rect "5,200 100x100"
          InkOverflow "0,0 100x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "0,0 0x0"
)DUMP",
            AsInkOverflowString(root));

  // Note: text item rect has non-scaled size.
  const auto& text_combine = *To<LayoutTextCombine>(
      GetElementById("combine")->GetLayoutObject()->SlowFirstChild());
  EXPECT_EQ(R"DUMP(
{Line #descendants=2 LTR Standard}
                 Rect "0,0 100x100"
          InkOverflow "-5,0 110x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "-5,0 110x100"
{Text 0-10 LTR Standard}
                 Rect "0,0 1000x100"
          InkOverflow "0,0 1000x100"
      SelfInkOverflow "0,0 1000x100"
  ContentsInkOverflow "0,0 0x0"
)DUMP",
            AsInkOverflowString(text_combine));
}

TEST_F(LayoutTextCombineTest, InkOverflowEmphasisMark) {
  LoadAhem();
  InsertStyleElement(
      "body { font: 100px/110px Ahem; }"
      "c { text-combine-upright: all; }"
      "div { -webkit-text-emphasis: dot; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>a<c id=combine>0123456789</c>b</div>");
  const auto& root =
      *To<LayoutBlockFlow>(GetElementById("root")->GetLayoutObject());

  EXPECT_EQ(R"DUMP(
{Line #descendants=5 LTR Standard}
                 Rect "0,0 155x300"
          InkOverflow "0,0 155x300"
      SelfInkOverflow "0,0 155x300"
  ContentsInkOverflow "0,0 0x0"
{Text 0-1 LTR Standard}
                 Rect "5,0 100x100"
          InkOverflow "0,0 150x100"
      SelfInkOverflow "0,0 150x100"
  ContentsInkOverflow "0,0 0x0"
{Box #descendants=2 Standard}
                 Rect "5,100 100x100"
          InkOverflow "-5,0 155x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "-5,0 155x100"
{Box #descendants=1 AtomicInlineLTR Standard}
                 Rect "5,100 100x100"
          InkOverflow "-5,0 155x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "-5,0 155x100"
{Text 2-3 LTR Standard}
                 Rect "5,200 100x100"
          InkOverflow "0,0 150x100"
      SelfInkOverflow "0,0 150x100"
  ContentsInkOverflow "0,0 0x0"
)DUMP",
            AsInkOverflowString(root));

  // Note: Emphasis mark is part of text-combine box instead of combined text.
  // Note: text item rect has non-scaled size.
  const auto& text_combine = *To<LayoutTextCombine>(
      GetElementById("combine")->GetLayoutObject()->SlowFirstChild());
  EXPECT_EQ(R"DUMP(
{Line #descendants=2 LTR Standard}
                 Rect "0,0 100x100"
          InkOverflow "-5,0 110x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "-5,0 110x100"
{Text 0-10 LTR Standard}
                 Rect "0,0 1000x100"
          InkOverflow "0,0 1000x100"
      SelfInkOverflow "0,0 1000x100"
  ContentsInkOverflow "0,0 0x0"
)DUMP",
            AsInkOverflowString(text_combine));
}

TEST_F(LayoutTextCombineTest, InkOverflowOverline) {
  LoadAhem();
  InsertStyleElement(
      "body { font: 100px/110px Ahem; }"
      "c { text-combine-upright: all; }"
      "div { text-decoration: overline; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>a<c id=combine>0123456789</c>b</div>");
  const auto& root =
      *To<LayoutBlockFlow>(GetElementById("root")->GetLayoutObject());

  EXPECT_EQ(R"DUMP(
{Line #descendants=5 LTR Standard}
                 Rect "0,0 110x300"
          InkOverflow "0,0 115x300"
      SelfInkOverflow "0,0 110x300"
  ContentsInkOverflow "0,0 115x300"
{Text 0-1 LTR Standard}
                 Rect "5,0 100x100"
          InkOverflow "0,0 110x100"
      SelfInkOverflow "0,0 110x100"
  ContentsInkOverflow "0,0 0x0"
{Box #descendants=2 Standard}
                 Rect "5,100 100x100"
          InkOverflow "0,0 110x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "0,0 110x100"
{Box #descendants=1 AtomicInlineLTR Standard}
                 Rect "5,100 100x100"
          InkOverflow "0,0 110x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "0,0 110x100"
{Text 2-3 LTR Standard}
                 Rect "5,200 100x100"
          InkOverflow "0,0 110x100"
      SelfInkOverflow "0,0 110x100"
  ContentsInkOverflow "0,0 0x0"
)DUMP",
            AsInkOverflowString(root));

  const auto& text_combine = *To<LayoutTextCombine>(
      GetElementById("combine")->GetLayoutObject()->SlowFirstChild());
  EXPECT_EQ(R"DUMP(
{Line #descendants=2 LTR Standard}
                 Rect "0,0 100x100"
          InkOverflow "0,0 100x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "0,0 0x0"
{Text 0-10 LTR Standard}
                 Rect "0,0 1000x100"
          InkOverflow "0,0 1000x100"
      SelfInkOverflow "0,0 1000x100"
  ContentsInkOverflow "0,0 0x0"
)DUMP",
            AsInkOverflowString(text_combine));
}

TEST_F(LayoutTextCombineTest, InkOverflowUnderline) {
  LoadAhem();
  InsertStyleElement(
      "body { font: 100px/110px Ahem; }"
      "c { text-combine-upright: all; }"
      "div { text-decoration: underline; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>a<c id=combine>0123456789</c>b</div>");
  const auto& root =
      *To<LayoutBlockFlow>(GetElementById("root")->GetLayoutObject());

  EXPECT_EQ(R"DUMP(
{Line #descendants=5 LTR Standard}
                 Rect "0,0 110x300"
          InkOverflow "-6,0 116x300"
      SelfInkOverflow "0,0 110x300"
  ContentsInkOverflow "-6,0 116x300"
{Text 0-1 LTR Standard}
                 Rect "5,0 100x100"
          InkOverflow "-11,0 111x100"
      SelfInkOverflow "-11,0 111x100"
  ContentsInkOverflow "0,0 0x0"
{Box #descendants=2 Standard}
                 Rect "5,100 100x100"
          InkOverflow "-11,0 111x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "-11,0 111x100"
{Box #descendants=1 AtomicInlineLTR Standard}
                 Rect "5,100 100x100"
          InkOverflow "-11,0 111x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "-11,0 111x100"
{Text 2-3 LTR Standard}
                 Rect "5,200 100x100"
          InkOverflow "-11,0 111x100"
      SelfInkOverflow "-11,0 111x100"
  ContentsInkOverflow "0,0 0x0"
)DUMP",
            AsInkOverflowString(root));

  const auto& text_combine = *To<LayoutTextCombine>(
      GetElementById("combine")->GetLayoutObject()->SlowFirstChild());
  EXPECT_EQ(R"DUMP(
{Line #descendants=2 LTR Standard}
                 Rect "0,0 100x100"
          InkOverflow "0,0 100x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "0,0 0x0"
{Text 0-10 LTR Standard}
                 Rect "0,0 1000x100"
          InkOverflow "0,0 1000x100"
      SelfInkOverflow "0,0 1000x100"
  ContentsInkOverflow "0,0 0x0"
)DUMP",
            AsInkOverflowString(text_combine));
}

TEST_F(LayoutTextCombineTest, InkOverflowWBR) {
  LoadAhem();
  InsertStyleElement(
      "body { font: 100px/110px Ahem; }"
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>a<c id=combine>01234<wbr>56789</c>b</div>");
  const auto& root =
      *To<LayoutBlockFlow>(GetElementById("root")->GetLayoutObject());

  EXPECT_EQ(R"DUMP(
{Line #descendants=5 LTR Standard}
                 Rect "0,0 110x300"
          InkOverflow "0,0 110x300"
      SelfInkOverflow "0,0 110x300"
  ContentsInkOverflow "0,0 0x0"
{Text 0-1 LTR Standard}
                 Rect "5,0 100x100"
          InkOverflow "0,0 100x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "0,0 0x0"
{Box #descendants=2 Standard}
                 Rect "5,100 100x100"
          InkOverflow "-5,0 110x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "-5,0 110x100"
{Box #descendants=1 AtomicInlineLTR Standard}
                 Rect "5,100 100x100"
          InkOverflow "-5,0 110x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "-5,0 110x100"
{Text 2-3 LTR Standard}
                 Rect "5,200 100x100"
          InkOverflow "0,0 100x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "0,0 0x0"
)DUMP",
            AsInkOverflowString(root));

  // Note: text item rect has non-scaled size.
  const auto& text_combine = *To<LayoutTextCombine>(
      GetElementById("combine")->GetLayoutObject()->SlowFirstChild());
  EXPECT_EQ(R"DUMP(
{Line #descendants=4 LTR Standard}
                 Rect "0,0 100x100"
          InkOverflow "-5,0 110x100"
      SelfInkOverflow "0,0 100x100"
  ContentsInkOverflow "-5,0 110x100"
{Text 0-5 LTR Standard}
                 Rect "0,0 500x100"
          InkOverflow "0,0 500x100"
      SelfInkOverflow "0,0 500x100"
  ContentsInkOverflow "0,0 0x0"
{Text 5-6 LTR Standard}
                 Rect "500,0 0x100"
          InkOverflow "0,0 0x100"
      SelfInkOverflow "0,0 0x100"
  ContentsInkOverflow "0,0 0x0"
{Text 6-11 LTR Standard}
                 Rect "500,0 500x100"
          InkOverflow "0,0 500x100"
      SelfInkOverflow "0,0 500x100"
  ContentsInkOverflow "0,0 0x0"
)DUMP",
            AsInkOverflowString(text_combine));
}

TEST_F(LayoutTextCombineTest, InsertBefore) {
  InsertStyleElement(
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine>XY</c>de</div>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));

  auto& combine = *GetElementById("combine");
  combine.insertBefore(Text::Create(GetDocument(), "Z"), combine.firstChild());
  RunDocumentLifecycle();
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "Z"
  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

// http://crbug.com/1258331
// See also VerticalWritingModeByWBR
TEST_F(LayoutTextCombineTest, InsertBR) {
  InsertStyleElement(
      "br { text-combine-upright: all; writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>x</div>");
  auto& root = *GetElementById("root");
  root.insertBefore(MakeGarbageCollected<HTMLBRElement>(GetDocument()),
                    root.lastChild());
  RunDocumentLifecycle();

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutBR BR
  +--LayoutText #text "x"
)DUMP",
            ToSimpleLayoutTree(*root.GetLayoutObject()));
}

TEST_F(LayoutTextCombineTest, ScrollableOverflow) {
  LoadAhem();
  InsertStyleElement(
      "div {"
      "  writing-mode: vertical-lr;"
      "  font: 100px/150px Ahem;"
      "}"
      "tcy { text-combine-upright: all; }");
  SetBodyInnerHTML(
      "<div id=t1><tcy>abcefgh</tcy>X</div>"
      "<div id=t2>aX</div>");

  // Layout tree is
  //    LayoutBlockFlow {DIV} at (0,0) size 100x200
  //      LayoutInline {TCY} at (0,0) size 100x100
  //        LayoutTextCombine (anonymous) at (0,0) size 100x100
  //          LayoutText {#text} at (0,0) size 110x100
  //            text run at (0,0) width 700: "abcefgh"
  //      LayoutText {#text} at (0,100) size 100x100
  //        text run at (0,100) width 100: "X"
  //   LayoutBlockFlow {DIV} at (0,200) size 100x200
  //     LayoutText {#text} at (0,0) size 100x200
  //       text run at (0,0) width 200: "aX"

  const auto& sample1 = *To<LayoutBlockFlow>(GetLayoutObjectByElementId("t1"));
  ASSERT_EQ(sample1.PhysicalFragmentCount(), 1u);
  const auto& sample_fragment1 = *sample1.GetPhysicalFragment(0);
  EXPECT_FALSE(sample_fragment1.HasScrollableOverflow());
  EXPECT_EQ(PhysicalSize(150, 200), sample_fragment1.Size());
  EXPECT_EQ(PhysicalRect(PhysicalOffset(), PhysicalSize(150, 200)),
            sample_fragment1.ScrollableOverflow());

  const auto& sample2 = *To<LayoutBlockFlow>(GetLayoutObjectByElementId("t2"));
  ASSERT_EQ(sample2.PhysicalFragmentCount(), 1u);
  const auto& sample_fragment2 = *sample2.GetPhysicalFragment(0);
  EXPECT_FALSE(sample_fragment2.HasScrollableOverflow());
  EXPECT_EQ(PhysicalSize(150, 200), sample_fragment2.Size());
  EXPECT_EQ(PhysicalRect(PhysicalOffset(), PhysicalSize(150, 200)),
            sample_fragment2.ScrollableOverflow());
}

// http://crbug.com/1223015
TEST_F(LayoutTextCombineTest, ListItemStyleToImage) {
  InsertStyleElement(
      "li { text-combine-upright: all; }"
      "ol { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<ol id=root><li></li></ol>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow OL id="root"
  +--LayoutListItem LI
  |  +--LayoutOutsideListMarker ::marker
  |  |  +--LayoutTextCombine (anonymous)
  |  |  |  +--LayoutTextFragment (anonymous) ("1. ")
)DUMP",
            ToSimpleLayoutTree(root_layout_object));

  // Change list-marker to use image
  root.style()->setProperty(
      GetDocument().GetExecutionContext(), "list-style-image",
      "url(data:image/"
      "gif;base64,R0lGODlhEAAQAMQAAORHHOVSKudfOulrSOp3WOyDZu6QdvCchPGolfO0o/"
      "XBs/fNwfjZ0frl3/zy7////"
      "wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAkAA"
      "BAALAAAAAAQABAAAAVVICSOZGlCQAosJ6mu7fiyZeKqNKToQGDsM8hBADgUXoGAiqhSvp5QA"
      "nQKGIgUhwFUYLCVDFCrKUE1lBavAViFIDlTImbKC5Gm2hB0SlBCBMQiB0UjIQA7)",
      "", ASSERT_NO_EXCEPTION);
  RunDocumentLifecycle();

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow OL id="root" style="list-style-image: url(\"data:image/gif;base64,R0lGODlhEAAQAMQAAORHHOVSKudfOulrSOp3WOyDZu6QdvCchPGolfO0o/XBs/fNwfjZ0frl3/zy7////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAkAABAALAAAAAAQABAAAAVVICSOZGlCQAosJ6mu7fiyZeKqNKToQGDsM8hBADgUXoGAiqhSvp5QAnQKGIgUhwFUYLCVDFCrKUE1lBavAViFIDlTImbKC5Gm2hB0SlBCBMQiB0UjIQA7\");"
  +--LayoutListItem LI
  |  +--LayoutOutsideListMarker ::marker
  |  |  +--LayoutImage (anonymous)
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

// http://crbug.com/1342520
TEST_F(LayoutTextCombineTest, ListMarkerWidthOfSymbol) {
  InsertStyleElement(
      "#root {"
      " text-combine-upright: all;"
      " writing-mode: vertical-lr;"
      " font-size: 1e-7px;"
      "}");
  SetBodyInnerHTML("<li id=root>ab</li>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutListItem LI id="root"
  +--LayoutInsideListMarker ::marker
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutTextFragment (anonymous) ("\u2022 ")
  +--LayoutTextCombine (anonymous)
  |  +--LayoutText #text "ab"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

TEST_F(LayoutTextCombineTest, MultipleTextNode) {
  InsertStyleElement(
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine>X<!-- -->Y</c>de</div>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "X"
  |  |  +--LayoutText #text "Y"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

TEST_F(LayoutTextCombineTest, Nested) {
  InsertStyleElement(
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine><b>XY</b></c>de</div>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutInline B
  |  |  +--LayoutTextCombine (anonymous)
  |  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

TEST_F(LayoutTextCombineTest, Outline) {
  LoadAhem();
  InsertStyleElement(
      "div {"
      "  writing-mode: vertical-lr;"
      "  text-combine-upright: all;"
      "  font: 100px/150px Ahem;"
      "}"
      "tcy { text-combine-upright: all; }");
  SetBodyInnerHTML(
      "<div id=t1><tcy>abcefgh</tcy>X</div>"
      "<div id=t2>aX</div>");

  // Layout tree is
  //    LayoutBlockFlow {DIV} at (0,0) size 100x200
  //      LayoutInline {TCY} at (0,0) size 100x100
  //        LayoutTextCombine (anonymous) at (0,0) size 100x100
  //          LayoutText {#text} at (0,0) size 110x100
  //            text run at (0,0) width 700: "abcefgh"
  //      LayoutText {#text} at (0,100) size 100x100
  //        text run at (0,100) width 100: "X"
  //   LayoutBlockFlow {DIV} at (0,200) size 100x200
  //     LayoutText {#text} at (0,0) size 100x200
  //       text run at (0,0) width 200: "aX"

  // Sample 1 with text-combine-upright:all
  const auto& sample1 = *GetLayoutObjectByElementId("t1");
  VectorOutlineRectCollector collector;
  sample1.AddOutlineRects(collector, nullptr, PhysicalOffset(),
                          OutlineType::kDontIncludeBlockInkOverflow);
  Vector<PhysicalRect> standard_outlines1 = collector.TakeRects();
  EXPECT_THAT(
      standard_outlines1,
      ElementsAre(PhysicalRect(PhysicalOffset(0, 0), PhysicalSize(150, 200))));

  sample1.AddOutlineRects(collector, nullptr, PhysicalOffset(),
                          OutlineType::kIncludeBlockInkOverflow);
  Vector<PhysicalRect> focus_outlines1 = collector.TakeRects();
  EXPECT_THAT(
      focus_outlines1,
      ElementsAre(
          PhysicalRect(PhysicalOffset(0, 0), PhysicalSize(150, 200)),
          // tcy
          PhysicalRect(PhysicalOffset(25, 0), PhysicalSize(100, 100)),
          PhysicalRect(PhysicalOffset(20, 0), PhysicalSize(110, 100)),
          // "X"
          PhysicalRect(PhysicalOffset(25, 100), PhysicalSize(100, 100)),
          PhysicalRect(PhysicalOffset(25, 100), PhysicalSize(100, 100))));

  // Sample 1 without text-combine-upright:all
  const auto& sample2 = *GetLayoutObjectByElementId("t2");
  sample2.AddOutlineRects(collector, nullptr, PhysicalOffset(),
                          OutlineType::kDontIncludeBlockInkOverflow);
  Vector<PhysicalRect> standard_outlines2 = collector.TakeRects();
  EXPECT_THAT(
      standard_outlines2,
      ElementsAre(PhysicalRect(PhysicalOffset(0, 0), PhysicalSize(150, 100))));

  sample1.AddOutlineRects(collector, nullptr, PhysicalOffset(),
                          OutlineType::kIncludeBlockInkOverflow);
  Vector<PhysicalRect> focus_outlines2 = collector.TakeRects();
  EXPECT_THAT(
      focus_outlines2,
      ElementsAre(
          PhysicalRect(PhysicalOffset(0, 0), PhysicalSize(150, 200)),
          // "a"
          PhysicalRect(PhysicalOffset(25, 0), PhysicalSize(100, 100)),
          PhysicalRect(PhysicalOffset(20, 0), PhysicalSize(110, 100)),
          // "X"
          PhysicalRect(PhysicalOffset(25, 100), PhysicalSize(100, 100)),
          PhysicalRect(PhysicalOffset(25, 100), PhysicalSize(100, 100))));
}

// http://crbug.com/1256783
TEST_F(LayoutTextCombineTest, PropageWritingModeFromBodyToHorizontal) {
  InsertStyleElement(
      "body { writing-mode: horizontal-tb; }"
      "html {"
      "text-combine-upright: all;"
      "writing-mode: vertical-lr;"
      "}");

  // Make |Text| node child in <html> element to call
  // |HTMLHtmlElement::PropagateWritingModeAndDirectionFromBody()|
  GetDocument().documentElement()->insertBefore(
      Text::Create(GetDocument(), "X"), GetDocument().body());

  RunDocumentLifecycle();

  EXPECT_EQ(
      R"DUMP(
LayoutBlockFlow HTML
  +--LayoutBlockFlow (anonymous)
  |  +--LayoutText #text "X"
  +--LayoutBlockFlow BODY
)DUMP",
      ToSimpleLayoutTree(*GetDocument().documentElement()->GetLayoutObject()));
}

TEST_F(LayoutTextCombineTest, PropageWritingModeFromBodyToVertical) {
  InsertStyleElement(
      "body { writing-mode: vertical-rl; }"
      "html {"
      "text-combine-upright: all;"
      "writing-mode: horizontal-tb;"
      "}");

  // Make |Text| node child in <html> element to call
  // |HTMLHtmlElement::PropagateWritingModeAndDirectionFromBody()|
  GetDocument().documentElement()->insertBefore(
      Text::Create(GetDocument(), "X"), GetDocument().body());

  RunDocumentLifecycle();

  EXPECT_EQ(
      R"DUMP(
LayoutBlockFlow HTML
  +--LayoutBlockFlow (anonymous)
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "X"
  +--LayoutBlockFlow BODY
)DUMP",
      ToSimpleLayoutTree(*GetDocument().documentElement()->GetLayoutObject()));
}

// http://crbug.com/1222160
TEST_F(LayoutTextCombineTest, RebuildLayoutTreeForDetails) {
  InsertStyleElement(
      "details { text-combine-upright: all; writing-mode: vertical-rl;  }");
  SetBodyInnerHTML("<details id=root open>ab<summary>XY</summary>cd</details>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DETAILS id="root"
  +--LayoutListItem SUMMARY
  |  +--LayoutInsideListMarker ::marker
  |  |  +--LayoutTextCombine (anonymous)
  |  |  |  +--LayoutTextFragment (anonymous) ("\u25BE ")
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "XY"
  +--LayoutBlockFlow SLOT ::details-content id="details-content" style="display: block;"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "ab"
  |  |  +--LayoutText #text "cd"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));

  // Rebuild layout tree of <details>
  root.style()->setProperty(GetDocument().GetExecutionContext(), "color", "red",
                            "important", ASSERT_NO_EXCEPTION);
  RunDocumentLifecycle();

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DETAILS id="root" style="color: red !important;"
  +--LayoutListItem SUMMARY
  |  +--LayoutInsideListMarker ::marker
  |  |  +--LayoutTextCombine (anonymous)
  |  |  |  +--LayoutTextFragment (anonymous) ("\u25BE ")
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "XY"
  +--LayoutBlockFlow SLOT ::details-content id="details-content" style="display: block;"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "ab"
  |  |  +--LayoutText #text "cd"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

// http;//crbug.com/1233432
TEST_F(LayoutTextCombineTest, RemoveBlockChild) {
  InsertStyleElement(
      "div { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<p id=block>XY</p>de</div>");
  auto& root = *GetElementById("root");

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutBlockFlow (anonymous)
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "ab"
  +--LayoutBlockFlow P id="block"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "XY"
  +--LayoutBlockFlow (anonymous)
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(*root.GetLayoutObject()));

  GetElementById("block")->remove();
  RunDocumentLifecycle();
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutTextCombine (anonymous)
  |  +--LayoutText #text "ab"
  |  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(*root.GetLayoutObject()));
}

TEST_F(LayoutTextCombineTest, RemoveChildCombine) {
  InsertStyleElement(
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine>XY</c>de</div>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));

  GetElementById("combine")->remove();
  RunDocumentLifecycle();
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

TEST_F(LayoutTextCombineTest, RemoveChildToEmpty) {
  InsertStyleElement(
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine>XY</c>de</div>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));

  GetElementById("combine")->firstChild()->remove();
  RunDocumentLifecycle();
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

// http://cr
```