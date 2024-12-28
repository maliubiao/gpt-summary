Response:
My thinking process to analyze the provided code snippet and answer the request goes like this:

1. **Understand the Goal:** The main goal is to describe the functionality of `inline_node_test.cc`, focusing on its connection to HTML, CSS, and JavaScript, logical reasoning (input/output), common user errors, and finally summarizing its core function for this part.

2. **Initial Scan for Clues:** I first scanned the `#include` directives and the class names within the code. This immediately tells me it's a testing file (`*_test.cc`) for the `InlineNode` class. The included headers like `DOMTokenList.h`, `ElementTraversal.h`, `PseudoElement.h`, `Text.h`, `html_names.h`, `computed_style.h`, and especially the headers in the `inline/` subdirectory (`inline_node.h`, `inline_child_layout_context.h`, etc.) strongly suggest that this file is testing the layout and structure of inline elements.

3. **Identify Key Classes and Methods:** I noted the core class being tested: `InlineNode`. The test class `InlineNodeTest` confirms this. I also observed helper classes like `InlineNodeForTest` (likely for easier testing access to internal methods) and the use of Google Test (`TEST_F`, `EXPECT_EQ`, etc.). I looked for methods within `InlineNodeForTest` that expose or manipulate internal state, such as `Text()`, `Items()`, `Append()`, `SegmentText()`, `CollectInlines()`, and `ShapeText()`.

4. **Connect to HTML, CSS, and JavaScript:**
    * **HTML:** The code uses `SetupHtml()` to create HTML structures for testing. The test cases directly manipulate HTML elements and attributes (e.g., `<div>`, `<span>`, `<br>`, `dir="rtl"`, styles). The tests involving `<br>`, floats, inline-blocks, and text combination directly relate to how HTML elements are rendered inline.
    * **CSS:**  The `SetupHtml()` function often includes inline styles or inserts `<style>` blocks. Tests like `CollectInlinesFloat`, `CollectInlinesInlineBlock`, `CollectInlinesTextCombineBR`, and the `MinMaxTest` suite explicitly test how CSS properties affect the inline layout. The `StyleChangeTest` further emphasizes the connection by testing how CSS changes trigger updates in the inline layout.
    * **JavaScript:** While this specific file doesn't *directly* execute JavaScript, it tests the underlying layout engine that JavaScript interacts with. When JavaScript manipulates the DOM or CSS styles, the code being tested here is part of how those changes are reflected in the visual rendering.

5. **Analyze Logical Reasoning (Input/Output):** The tests provide many examples of input (HTML structures, text content) and expected output (the structure of `InlineItem`s, the resulting text content, minimum and maximum sizes). For instance:
    * **Input:** `"<div id=t>Hello <span>inline</span> world.</div>"`
    * **Output:** A sequence of `InlineItem`s representing the text nodes and the open/close tags of the `<span>`.
    * **Input:**  Various HTML snippets with different CSS styles in the `MinMaxTest` suite.
    * **Output:** The calculated minimum and maximum widths of the inline content.

6. **Identify Potential User/Programming Errors:** The tests implicitly highlight potential errors. For example, the tests around bidirectional text (`CollectInlinesRtl`, `SegmentBidiOverride`) show the complexity of handling different text directions. A developer might incorrectly assume LTR behavior for all text, leading to rendering issues with RTL languages. The tests related to floats and inline-blocks demonstrate how these CSS properties affect the flow of inline content, and misunderstandings can lead to unexpected layout results. The tests around `NeedsCollectInlinesOnSetText` and `NeedsCollectInlinesOnStyle` are important for ensuring the rendering engine correctly invalidates and updates the layout when content or styles change, and neglecting these mechanisms in custom rendering logic could lead to stale or incorrect displays.

7. **Focus on the "First Part" Request:** The prompt specifically asks for a summary of the *first part* of the file's functionality. This means I should prioritize the tests and code that appear earlier in the provided snippet. The initial tests like `CollectInlinesText`, `CollectInlinesBR`, `CollectInlinesFloat`, `CollectInlinesInlineBlock`, and the basic segmentation tests (`SegmentASCII`, `SegmentHebrew`, etc.) are foundational. The later tests, while still relevant to the overall file, become secondary when summarizing the *first part*.

8. **Synthesize the Summary:**  Based on the above analysis, I formulated the summary by highlighting the core function: testing the `InlineNode` class, its ability to collect and segment inline content, and how it handles basic HTML structures. I also mentioned its relevance to HTML and CSS through the examples provided in the tests.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on the C++ internals.
* **Correction:** Realized the prompt explicitly asks for connections to web technologies (HTML, CSS, JavaScript) and user errors, so I needed to shift the focus to how these tests relate to the web development context.
* **Initial thought:** List *every* test case individually in the summary.
* **Correction:**  Recognized the need for a higher-level summary for the "first part," grouping similar functionalities (like the different `CollectInlines` tests).
* **Initial thought:** Assume the user is familiar with Chromium's rendering architecture.
* **Correction:** Explained concepts like "inline items" and "layout objects" briefly, assuming a broader audience might be reading this.
好的，让我们来分析一下 `blink/renderer/core/layout/inline/inline_node_test.cc` 文件的功能。

**文件功能归纳 (第 1 部分):**

这个 `inline_node_test.cc` 文件的主要功能是**对 Blink 渲染引擎中负责处理内联布局的核心类 `InlineNode` 进行单元测试**。  它通过一系列的测试用例，验证 `InlineNode` 类的各种功能是否按照预期工作，尤其关注以下几个方面：

* **内联元素的收集 (Collecting Inlines):** 测试 `InlineNode` 如何识别和收集不同类型的内联内容，例如文本、内联元素、浮动元素、inline-block 元素、换行符 `<br>` 等，并将它们转换为内部的 `InlineItem` 结构。
* **文本分割和分段 (Text Segmentation):** 测试 `InlineNode` 如何将文本内容根据不同的语言和双向文本规则进行分割成不同的片段，并赋予每个片段相应的文本方向 (LTR 或 RTL)。
* **最小/最大尺寸计算 (Min/Max Sizes Computation):** 测试 `InlineNode` 如何计算其所包含的内联内容的最小和最大宽度，这对于布局引擎进行换行、空间分配等操作至关重要。
* **布局状态管理 (Layout State Management):** 测试 `InlineNode` 如何管理其布局状态，例如当文本内容或样式发生变化时，是否正确地标记需要重新收集内联信息。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`InlineNode` 类是 Blink 渲染引擎中处理内联内容布局的关键组件，它直接影响着网页上文本和内联元素的呈现效果。因此，对 `InlineNode` 的测试与 JavaScript、HTML 和 CSS 的功能都有着密切的关系：

* **HTML:**  测试用例中会创建各种 HTML 结构来模拟不同的内联布局场景。例如：
    * **`TEST_F(InlineNodeTest, CollectInlinesText)`:** 测试当 HTML 中包含 `<span>` 等内联元素时，`InlineNode` 如何将文本和标签信息正确地收集到 `InlineItem` 中。
    * **假设输入 HTML:** `<div>Hello <span>inline</span> world.</div>`
    * **预期输出:**  创建包含文本项 "Hello "， openTag 项 `<span>`， 文本项 "inline"， closeTag 项 `</span>`， 文本项 " world." 的 `InlineItem` 列表。
    * **`TEST_F(InlineNodeTest, CollectInlinesBR)`:** 测试 `<br>` 标签如何被识别并表示为控制项 (`kControl`)，从而在布局中产生换行效果。
    * **假设输入 HTML:** `<div>Hello<br>World</div>`
    * **预期输出:** 创建包含文本项 "Hello"， 控制项 (代表 `<br>`)， 文本项 "World" 的 `InlineItem` 列表。
* **CSS:** CSS 样式直接影响着内联元素的布局和渲染。测试用例会使用 CSS 属性来验证 `InlineNode` 的行为：
    * **`TEST_F(InlineNodeTest, CollectInlinesFloat)`:** 测试带有 `float: right` 或 `float: left` 样式的元素如何被识别为浮动项 (`kFloating`)，并用特殊字符 (U+FFFC) 表示。
    * **假设输入 HTML 和 CSS:** `<div id=t>abc<span style='float:right'>DEF</span>ghi</div>`
    * **预期输出:** 创建包含文本项 "abc"， 浮动项 (代表 `<span>`)， 文本项 "ghi" 的 `InlineItem` 列表。
    * **`TEST_F(InlineNodeTest, CollectInlinesInlineBlock)`:** 测试 `display: inline-block` 样式的元素如何被识别为原子内联项 (`kAtomicInline`)。
    * **`TEST_P(MinMaxTest, Data)`:** 这个参数化测试使用大量的 HTML 和 CSS 组合来测试 `InlineNode` 计算最小和最大尺寸的功能，例如 `white-space`, `word-break`, `text-indent`, `hyphens` 等 CSS 属性。
* **JavaScript:** 虽然这个测试文件本身不包含 JavaScript 代码，但它测试的是 Blink 渲染引擎的核心逻辑，而 JavaScript 可以通过 DOM API 操作 HTML 结构和 CSS 样式。当 JavaScript 修改了影响内联布局的内容或样式时，`InlineNode` 的相关功能会被触发，而这些功能正是这个测试文件所覆盖的。例如，JavaScript 修改元素的 `textContent` 或 `style` 属性后，可能会导致 `InlineNode` 需要重新收集内联信息。

**逻辑推理的假设输入与输出:**

在很多测试用例中，都包含了逻辑推理。例如，在文本分割的测试中：

* **`TEST_F(InlineNodeTest, SegmentSplit1To2)`:**
    * **假设输入文本:** "Hello עברית" (包含英文和希伯来文)
    * **预期输出:** 将文本分割成两个 `InlineItem`，第一个包含 "Hello " (LTR 方向)，第二个包含 "עברית" (RTL 方向)。
* **`TEST_F(InlineNodeTest, SegmentBidiOverride)`:**
    * **假设输入文本:** "Hello ًABC‍" (包含 LRO 和 PDF 控制字符)
    * **预期输出:** 将文本分割成四个 `InlineItem`，分别对应 "Hello " (LTR)， LRO 控制字符 (RTL)， "ABC" (RTL，因为 LRO 的影响)， 和 PDF 控制字符 (LTR)。

**涉及用户或编程常见的使用错误及举例说明:**

虽然这个测试文件主要面向开发者，但它也间接反映了一些用户或编程中可能出现的与内联布局相关的错误：

* **不理解双向文本 (BiDi) 的处理:**  用户或开发者可能不了解浏览器如何处理从右向左 (RTL) 的语言，导致在混合使用 LTR 和 RTL 文本时出现显示错误。例如，错误地假设所有文本都是从左向右排列。测试用例如 `CollectInlinesRtlWithSpan` 和 `CollectInlinesMixedText` 就覆盖了这种情况。
* **错误地使用浮动和 inline-block:** 开发者可能不清楚 `float` 和 `display: inline-block` 的布局行为，导致内联元素的排列不符合预期。例如，错误地认为浮动元素仍然会像普通内联元素一样占据空间。测试用例 `CollectInlinesFloat` 和 `CollectInlinesInlineBlock` 可以帮助理解这些行为。
* **对文本换行和空白符处理的误解:**  开发者可能对 CSS 的 `white-space` 属性如何影响文本的换行和空白符处理理解不足，导致预期的文本格式没有正确显示。`MinMaxTest` 中针对 `white-space: pre-wrap` 的测试就与此相关。
* **忽略字符编码问题:** 虽然在这个文件的测试中没有直接体现，但在实际开发中，字符编码不一致可能导致文本显示错误，尤其是在处理特殊字符或非 ASCII 字符时。

总而言之，`inline_node_test.cc` (第 1 部分) 专注于测试 `InlineNode` 类收集内联内容、分割文本以及计算尺寸的核心功能，这直接关联到 HTML 结构、CSS 样式在内联布局中的呈现，并间接反映了处理复杂文本布局时可能遇到的问题。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/inline_node_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/inline/inline_node.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/dom_token_list.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/inline/inline_child_layout_context.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item_span.h"
#include "third_party/blink/renderer/core/layout/inline/inline_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/inline/physical_line_box_fragment.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/layout_text_combine.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_text.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/mock_hyphenation.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_spacing.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

// The spec turned into a discussion that may change. Put this logic on hold
// until CSSWG resolves the issue.
// https://github.com/w3c/csswg-drafts/issues/337
#define SEGMENT_BREAK_TRANSFORMATION_FOR_EAST_ASIAN_WIDTH 0

using ::testing::ElementsAre;

class InlineNodeForTest : public InlineNode {
 public:
  using InlineNode::InlineNode;

  std::string Text() const { return Data().text_content.Utf8(); }
  HeapVector<InlineItem>& Items() { return MutableData()->items; }
  static HeapVector<InlineItem>& Items(InlineNodeData& data) {
    return data.items;
  }
  bool IsNGShapeCacheAllowed(const String& text_content,
                             const Font* override_font,
                             const HeapVector<InlineItem>& items,
                             ShapeResultSpacing<String>& spacing) const {
    return InlineNode::IsNGShapeCacheAllowed(text_content, override_font, items,
                                             spacing);
  }

  void Append(const String& text, LayoutObject* layout_object) {
    InlineNodeData* data = MutableData();
    unsigned start = data->text_content.length();
    data->text_content = data->text_content + text;
    data->items.push_back(InlineItem(InlineItem::kText, start,
                                     start + text.length(), layout_object));
  }

  void Append(UChar character) {
    InlineNodeData* data = MutableData();
    data->text_content = data->text_content + character;
    unsigned end = data->text_content.length();
    data->items.push_back(
        InlineItem(InlineItem::kBidiControl, end - 1, end, nullptr));
    data->is_bidi_enabled_ = true;
  }

  void ClearText() {
    InlineNodeData* data = MutableData();
    data->text_content = String();
    data->items.clear();
  }

  void SegmentText() {
    InlineNodeData* data = MutableData();
    data->is_bidi_enabled_ = true;
    InlineNode::SegmentText(data, nullptr);
  }

  void CollectInlines() { InlineNode::CollectInlines(MutableData()); }
  void ShapeText() { InlineNode::ShapeText(MutableData()); }
};

class InlineNodeTest : public RenderingTest {
 protected:
  void SetupHtml(const char* id, String html) {
    SetBodyInnerHTML(html);
    layout_block_flow_ = To<LayoutBlockFlow>(GetLayoutObjectByElementId(id));
    layout_object_ = layout_block_flow_->FirstChild();
  }

  void UseLayoutObjectAndAhem() {
    // Get Ahem from document. Loading "Ahem.woff" using |createTestFont| fails
    // on linux_chromium_asan_rel_ng.
    LoadAhem();
    SetupHtml("t", "<div id=t style='font:10px Ahem'>test</div>");
  }

  InlineNodeForTest CreateInlineNode(
      LayoutBlockFlow* layout_block_flow = nullptr) {
    if (layout_block_flow)
      layout_block_flow_ = layout_block_flow;
    if (!layout_block_flow_)
      SetupHtml("t", "<div id=t style='font:10px'>test</div>");
    InlineNodeForTest node(layout_block_flow_);
    node.InvalidatePrepareLayoutForTest();
    return node;
  }

  MinMaxSizes ComputeMinMaxSizes(InlineNode node) {
    const auto space =
        ConstraintSpaceBuilder(node.Style().GetWritingMode(),
                               node.Style().GetWritingDirection(),
                               /* is_new_fc */ false)
            .ToConstraintSpace();

    return node
        .ComputeMinMaxSizes(node.Style().GetWritingMode(), space,
                            MinMaxSizesFloatInput())
        .sizes;
  }

  const String& GetText() const {
    InlineNodeData* data = layout_block_flow_->GetInlineNodeData();
    CHECK(data);
    return data->text_content;
  }

  HeapVector<InlineItem>& Items() {
    InlineNodeData* data = layout_block_flow_->GetInlineNodeData();
    CHECK(data);
    return InlineNodeForTest::Items(*data);
  }

  void ForceLayout() { GetDocument().body()->OffsetTop(); }

  Vector<unsigned> ToEndOffsetList(
      InlineItemSegments::const_iterator segments) {
    Vector<unsigned> end_offsets;
    for (const RunSegmenter::RunSegmenterRange& segment : segments)
      end_offsets.push_back(segment.end);
    return end_offsets;
  }

  void TestAnyItemsAreDirty(const LayoutBlockFlow& block_flow, bool expected) {
    FragmentItems::DirtyLinesFromNeedsLayout(block_flow);
    for (const PhysicalBoxFragment& fragment : block_flow.PhysicalFragments()) {
      if (const FragmentItems* items = fragment.Items()) {
        // Check |FragmentItem::IsDirty| directly without using
        // |EndOfReusableItems|. This is different from the line cache logic,
        // but some items may not be reusable even if |!IsDirty()|.
        for (const FragmentItem& item : items->Items()) {
          if (item.IsDirty()) {
            EXPECT_TRUE(expected);
            return;
          }
        }
      }
    }
    EXPECT_FALSE(expected);
  }

  // "Google Sans" has ligatures, e.g. "fi", "tt", etc.
  void LoadGoogleSans() {
    LoadFontFromFile(GetFrame(),
                     test::CoreTestDataPath("GoogleSans-Regular.ttf"),
                     AtomicString("Google Sans"));
  }

  Persistent<LayoutBlockFlow> layout_block_flow_;
  Persistent<LayoutObject> layout_object_;
  FontCachePurgePreventer purge_preventer_;
};

#define TEST_ITEM_TYPE_OFFSET(item, type, start, end) \
  EXPECT_EQ(InlineItem::type, item.Type());           \
  EXPECT_EQ(start, item.StartOffset());               \
  EXPECT_EQ(end, item.EndOffset())

#define TEST_ITEM_TYPE_OFFSET_LEVEL(item, type, start, end, level) \
  EXPECT_EQ(InlineItem::type, item.Type());                        \
  EXPECT_EQ(start, item.StartOffset());                            \
  EXPECT_EQ(end, item.EndOffset());                                \
  EXPECT_EQ(level, item.BidiLevel())

#define TEST_ITEM_OFFSET_DIR(item, start, end, direction) \
  EXPECT_EQ(start, item.StartOffset());                   \
  EXPECT_EQ(end, item.EndOffset());                       \
  EXPECT_EQ(direction, item.Direction())

TEST_F(InlineNodeTest, CollectInlinesText) {
  SetupHtml("t", "<div id=t>Hello <span>inline</span> world.</div>");
  InlineNodeForTest node = CreateInlineNode();
  node.CollectInlines();
  EXPECT_FALSE(node.IsBidiEnabled());
  HeapVector<InlineItem>& items = node.Items();
  TEST_ITEM_TYPE_OFFSET(items[0], kText, 0u, 6u);
  TEST_ITEM_TYPE_OFFSET(items[1], kOpenTag, 6u, 6u);
  TEST_ITEM_TYPE_OFFSET(items[2], kText, 6u, 12u);
  TEST_ITEM_TYPE_OFFSET(items[3], kCloseTag, 12u, 12u);
  TEST_ITEM_TYPE_OFFSET(items[4], kText, 12u, 19u);
  EXPECT_EQ(5u, items.size());
}

TEST_F(InlineNodeTest, CollectInlinesBR) {
  SetupHtml("t", u"<div id=t>Hello<br>World</div>");
  InlineNodeForTest node = CreateInlineNode();
  node.CollectInlines();
  EXPECT_EQ("Hello\nWorld", node.Text());
  EXPECT_FALSE(node.IsBidiEnabled());
  HeapVector<InlineItem>& items = node.Items();
  TEST_ITEM_TYPE_OFFSET(items[0], kText, 0u, 5u);
  TEST_ITEM_TYPE_OFFSET(items[1], kControl, 5u, 6u);
  TEST_ITEM_TYPE_OFFSET(items[2], kText, 6u, 11u);
  EXPECT_EQ(3u, items.size());
}

TEST_F(InlineNodeTest, CollectInlinesFloat) {
  SetupHtml("t",
            "<div id=t>"
            "abc"
            "<span style='float:right'>DEF</span>"
            "ghi"
            "<span style='float:left'>JKL</span>"
            "mno"
            "</div>");
  InlineNodeForTest node = CreateInlineNode();
  node.CollectInlines();
  EXPECT_EQ("abc\uFFFCghi\uFFFCmno", node.Text())
      << "floats are appeared as an object replacement character";
  HeapVector<InlineItem>& items = node.Items();
  ASSERT_EQ(5u, items.size());
  TEST_ITEM_TYPE_OFFSET(items[0], kText, 0u, 3u);
  TEST_ITEM_TYPE_OFFSET(items[1], kFloating, 3u, 4u);
  TEST_ITEM_TYPE_OFFSET(items[2], kText, 4u, 7u);
  TEST_ITEM_TYPE_OFFSET(items[3], kFloating, 7u, 8u);
  TEST_ITEM_TYPE_OFFSET(items[4], kText, 8u, 11u);
}

TEST_F(InlineNodeTest, CollectInlinesInlineBlock) {
  SetupHtml("t",
            "<div id=t>"
            "abc<span style='display:inline-block'>DEF</span>jkl"
            "</div>");
  InlineNodeForTest node = CreateInlineNode();
  node.CollectInlines();
  EXPECT_EQ("abc\uFFFCjkl", node.Text())
      << "inline-block is appeared as an object replacement character";
  HeapVector<InlineItem>& items = node.Items();
  ASSERT_EQ(3u, items.size());
  TEST_ITEM_TYPE_OFFSET(items[0], kText, 0u, 3u);
  TEST_ITEM_TYPE_OFFSET(items[1], kAtomicInline, 3u, 4u);
  TEST_ITEM_TYPE_OFFSET(items[2], kText, 4u, 7u);
}

TEST_F(InlineNodeTest, CollectInlinesUTF16) {
  SetupHtml("t", u"<div id=t>Hello \u3042</div>");
  InlineNodeForTest node = CreateInlineNode();
  node.CollectInlines();
  EXPECT_FALSE(node.IsBidiEnabled());
  node.SegmentText();
  EXPECT_FALSE(node.IsBidiEnabled());
}

TEST_F(InlineNodeTest, CollectInlinesMaybeRtl) {
  // U+10000 "LINEAR B SYLLABLE B008 A" is strong LTR.
  SetupHtml("t", u"<div id=t>Hello \U00010000</div>");
  InlineNodeForTest node = CreateInlineNode();
  node.CollectInlines();
  // |CollectInlines()| sets |IsBidiEnabled()| for any surrogate pairs.
  EXPECT_TRUE(node.IsBidiEnabled());
  // |SegmentText()| analyzes the string and resets |IsBidiEnabled()| if all
  // characters are LTR.
  node.SegmentText();
  EXPECT_FALSE(node.IsBidiEnabled());
}

TEST_F(InlineNodeTest, CollectInlinesRtl) {
  SetupHtml("t", u"<div id=t>Hello \u05E2</div>");
  InlineNodeForTest node = CreateInlineNode();
  node.CollectInlines();
  EXPECT_TRUE(node.IsBidiEnabled());
  node.SegmentText();
  EXPECT_TRUE(node.IsBidiEnabled());
}

TEST_F(InlineNodeTest, CollectInlinesRtlWithSpan) {
  SetupHtml("t", u"<div id=t dir=rtl>\u05E2 <span>\u05E2</span> \u05E2</div>");
  InlineNodeForTest node = CreateInlineNode();
  node.CollectInlines();
  EXPECT_TRUE(node.IsBidiEnabled());
  node.SegmentText();
  EXPECT_TRUE(node.IsBidiEnabled());
  HeapVector<InlineItem>& items = node.Items();
  TEST_ITEM_TYPE_OFFSET_LEVEL(items[0], kText, 0u, 2u, 1u);
  TEST_ITEM_TYPE_OFFSET_LEVEL(items[1], kOpenTag, 2u, 2u, 1u);
  TEST_ITEM_TYPE_OFFSET_LEVEL(items[2], kText, 2u, 3u, 1u);
  TEST_ITEM_TYPE_OFFSET_LEVEL(items[3], kCloseTag, 3u, 3u, 1u);
  TEST_ITEM_TYPE_OFFSET_LEVEL(items[4], kText, 3u, 5u, 1u);
  EXPECT_EQ(5u, items.size());
}

TEST_F(InlineNodeTest, CollectInlinesMixedText) {
  SetupHtml("t", u"<div id=t>Hello, \u05E2 <span>\u05E2</span></div>");
  InlineNodeForTest node = CreateInlineNode();
  node.CollectInlines();
  EXPECT_TRUE(node.IsBidiEnabled());
  node.SegmentText();
  EXPECT_TRUE(node.IsBidiEnabled());
  HeapVector<InlineItem>& items = node.Items();
  TEST_ITEM_TYPE_OFFSET_LEVEL(items[0], kText, 0u, 7u, 0u);
  TEST_ITEM_TYPE_OFFSET_LEVEL(items[1], kText, 7u, 9u, 1u);
  TEST_ITEM_TYPE_OFFSET_LEVEL(items[2], kOpenTag, 9u, 9u, 1u);
  TEST_ITEM_TYPE_OFFSET_LEVEL(items[3], kText, 9u, 10u, 1u);
  TEST_ITEM_TYPE_OFFSET_LEVEL(items[4], kCloseTag, 10u, 10u, 1u);
  EXPECT_EQ(5u, items.size());
}

TEST_F(InlineNodeTest, CollectInlinesMixedTextEndWithON) {
  SetupHtml("t", u"<div id=t>Hello, \u05E2 <span>\u05E2!</span></div>");
  InlineNodeForTest node = CreateInlineNode();
  node.CollectInlines();
  EXPECT_TRUE(node.IsBidiEnabled());
  node.SegmentText();
  EXPECT_TRUE(node.IsBidiEnabled());
  HeapVector<InlineItem>& items = node.Items();
  TEST_ITEM_TYPE_OFFSET_LEVEL(items[0], kText, 0u, 7u, 0u);
  TEST_ITEM_TYPE_OFFSET_LEVEL(items[1], kText, 7u, 9u, 1u);
  TEST_ITEM_TYPE_OFFSET_LEVEL(items[2], kOpenTag, 9u, 9u, 1u);
  TEST_ITEM_TYPE_OFFSET_LEVEL(items[3], kText, 9u, 10u, 1u);
  TEST_ITEM_TYPE_OFFSET_LEVEL(items[4], kText, 10u, 11u, 0u);
  TEST_ITEM_TYPE_OFFSET_LEVEL(items[5], kCloseTag, 11u, 11u, 0u);
  EXPECT_EQ(6u, items.size());
}

TEST_F(InlineNodeTest, CollectInlinesTextCombineBR) {
  InsertStyleElement(
      "#t { text-combine-upright: all; writing-mode: vertical-rl; }");
  SetupHtml("t", u"<div id=t>a<br>z</div>");
  InlineNodeForTest node =
      CreateInlineNode(To<LayoutBlockFlow>(layout_object_.Get()));
  node.CollectInlines();
  EXPECT_EQ("a z", node.Text());
  HeapVector<InlineItem>& items = node.Items();
  ASSERT_EQ(3u, items.size());
  TEST_ITEM_TYPE_OFFSET(items[0], kText, 0u, 1u);
  TEST_ITEM_TYPE_OFFSET(items[1], kText, 1u, 2u) << "<br> isn't control";
  TEST_ITEM_TYPE_OFFSET(items[2], kText, 2u, 3u);
}

// http://crbug.com/1222633
TEST_F(InlineNodeTest, CollectInlinesTextCombineListItemMarker) {
  InsertStyleElement(
      "#t { text-combine-upright: all; writing-mode: vertical-rl; }");
  SetupHtml("t", u"<li id=t>ab</li>");
  // LayoutListItem {LI}
  //   LayoutOutsideListMarker {::marker}
  //      LayoutTextCombine (anonymous)
  //        LayoutText (anonymous) "\x{2022} "
  //   LayoutTextCombine (anonymous)
  //     LayoutText {#text} "a"
  InlineNodeForTest node =
      CreateInlineNode(To<LayoutTextCombine>(layout_object_->SlowFirstChild()));
  node.CollectInlines();
  EXPECT_EQ("\u2022", node.Text());
  HeapVector<InlineItem>& items = node.Items();
  ASSERT_EQ(1u, items.size());
  TEST_ITEM_TYPE_OFFSET(items[0], kText, 0u, 1u);
  EXPECT_TRUE(items[0].IsSymbolMarker());
}

TEST_F(InlineNodeTest, CollectInlinesTextCombineNewline) {
  InsertStyleElement(
      "#t { text-combine-upright: all; writing-mode: vertical-rl; }");
  SetupHtml("t", u"<pre id=t>a\nz</pre>");
  InlineNodeForTest node =
      CreateInlineNode(To<LayoutBlockFlow>(layout_object_.Get()));
  node.CollectInlines();
  EXPECT_EQ("a z", node.Text());
  HeapVector<InlineItem>& items = node.Items();
  ASSERT_EQ(3u, items.size());
  TEST_ITEM_TYPE_OFFSET(items[0], kText, 0u, 1u);
  TEST_ITEM_TYPE_OFFSET(items[1], kText, 1u, 2u) << "newline isn't control";
  TEST_ITEM_TYPE_OFFSET(items[2], kText, 2u, 3u);
}

TEST_F(InlineNodeTest, CollectInlinesTextCombineWBR) {
  InsertStyleElement(
      "#t { text-combine-upright: all; writing-mode: vertical-rl; }");
  SetupHtml("t", u"<div id=t>a<wbr>z</div>");
  InlineNodeForTest node =
      CreateInlineNode(To<LayoutBlockFlow>(layout_object_.Get()));
  node.CollectInlines();
  EXPECT_EQ("a\u200Bz", node.Text());
  HeapVector<InlineItem>& items = node.Items();
  ASSERT_EQ(3u, items.size());
  TEST_ITEM_TYPE_OFFSET(items[0], kText, 0u, 1u);
  TEST_ITEM_TYPE_OFFSET(items[1], kText, 1u, 2u) << "<wbr> isn't control";
  TEST_ITEM_TYPE_OFFSET(items[2], kText, 2u, 3u);
}

TEST_F(InlineNodeTest, SegmentASCII) {
  InlineNodeForTest node = CreateInlineNode();
  node.Append("Hello", layout_object_);
  node.SegmentText();
  HeapVector<InlineItem>& items = node.Items();
  ASSERT_EQ(1u, items.size());
  TEST_ITEM_OFFSET_DIR(items[0], 0u, 5u, TextDirection::kLtr);
}

TEST_F(InlineNodeTest, SegmentHebrew) {
  InlineNodeForTest node = CreateInlineNode();
  node.Append(u"\u05E2\u05D1\u05E8\u05D9\u05EA", layout_object_);
  node.SegmentText();
  ASSERT_EQ(1u, node.Items().size());
  HeapVector<InlineItem>& items = node.Items();
  ASSERT_EQ(1u, items.size());
  TEST_ITEM_OFFSET_DIR(items[0], 0u, 5u, TextDirection::kRtl);
}

TEST_F(InlineNodeTest, SegmentSplit1To2) {
  InlineNodeForTest node = CreateInlineNode();
  node.Append(u"Hello \u05E2\u05D1\u05E8\u05D9\u05EA", layout_object_);
  node.SegmentText();
  HeapVector<InlineItem>& items = node.Items();
  ASSERT_EQ(2u, items.size());
  TEST_ITEM_OFFSET_DIR(items[0], 0u, 6u, TextDirection::kLtr);
  TEST_ITEM_OFFSET_DIR(items[1], 6u, 11u, TextDirection::kRtl);
}

TEST_F(InlineNodeTest, SegmentSplit3To4) {
  InlineNodeForTest node = CreateInlineNode();
  node.Append("Hel", layout_object_);
  node.Append(u"lo \u05E2", layout_object_);
  node.Append(u"\u05D1\u05E8\u05D9\u05EA", layout_object_);
  node.SegmentText();
  HeapVector<InlineItem>& items = node.Items();
  ASSERT_EQ(4u, items.size());
  TEST_ITEM_OFFSET_DIR(items[0], 0u, 3u, TextDirection::kLtr);
  TEST_ITEM_OFFSET_DIR(items[1], 3u, 6u, TextDirection::kLtr);
  TEST_ITEM_OFFSET_DIR(items[2], 6u, 7u, TextDirection::kRtl);
  TEST_ITEM_OFFSET_DIR(items[3], 7u, 11u, TextDirection::kRtl);
}

TEST_F(InlineNodeTest, SegmentBidiOverride) {
  InlineNodeForTest node = CreateInlineNode();
  node.Append("Hello ", layout_object_);
  node.Append(kRightToLeftOverrideCharacter);
  node.Append("ABC", layout_object_);
  node.Append(kPopDirectionalFormattingCharacter);
  node.SegmentText();
  HeapVector<InlineItem>& items = node.Items();
  ASSERT_EQ(4u, items.size());
  TEST_ITEM_OFFSET_DIR(items[0], 0u, 6u, TextDirection::kLtr);
  TEST_ITEM_OFFSET_DIR(items[1], 6u, 7u, TextDirection::kRtl);
  TEST_ITEM_OFFSET_DIR(items[2], 7u, 10u, TextDirection::kRtl);
  TEST_ITEM_OFFSET_DIR(items[3], 10u, 11u, TextDirection::kLtr);
}

static InlineNodeForTest CreateBidiIsolateNode(InlineNodeForTest node,
                                               LayoutObject* layout_object) {
  node.Append("Hello ", layout_object);
  node.Append(kRightToLeftIsolateCharacter);
  node.Append(u"\u05E2\u05D1\u05E8\u05D9\u05EA ", layout_object);
  node.Append(kLeftToRightIsolateCharacter);
  node.Append("A", layout_object);
  node.Append(kPopDirectionalIsolateCharacter);
  node.Append(u"\u05E2\u05D1\u05E8\u05D9\u05EA", layout_object);
  node.Append(kPopDirectionalIsolateCharacter);
  node.Append(" World", layout_object);
  node.SegmentText();
  return node;
}

TEST_F(InlineNodeTest, SegmentBidiIsolate) {
  InlineNodeForTest node = CreateInlineNode();
  node = CreateBidiIsolateNode(node, layout_object_);
  HeapVector<InlineItem>& items = node.Items();
  EXPECT_EQ(9u, items.size());
  TEST_ITEM_OFFSET_DIR(items[0], 0u, 6u, TextDirection::kLtr);
  TEST_ITEM_OFFSET_DIR(items[1], 6u, 7u, TextDirection::kLtr);
  TEST_ITEM_OFFSET_DIR(items[2], 7u, 13u, TextDirection::kRtl);
  TEST_ITEM_OFFSET_DIR(items[3], 13u, 14u, TextDirection::kRtl);
  TEST_ITEM_OFFSET_DIR(items[4], 14u, 15u, TextDirection::kLtr);
  TEST_ITEM_OFFSET_DIR(items[5], 15u, 16u, TextDirection::kRtl);
  TEST_ITEM_OFFSET_DIR(items[6], 16u, 21u, TextDirection::kRtl);
  TEST_ITEM_OFFSET_DIR(items[7], 21u, 22u, TextDirection::kLtr);
  TEST_ITEM_OFFSET_DIR(items[8], 22u, 28u, TextDirection::kLtr);
}

struct MinMaxData {
  const char* content;
  std::array<int, 2> min_max;
  const char* target_style = "";
  const char* style = "";
  const char* lang = nullptr;
} min_max_data[] = {
    {"AB CDEF", {40, 70}},
    // Element boundary is at the middle of a word.
    {"A B<span>C D</span>", {20, 60}},
    // A close tag after a forced break.
    {"<span>12<br></span>", {80, 80}, "", "span { border: 30px solid blue; }"},
    // `pre-wrap` with trailing spaces.
    {"12345 6789 ", {50, 110}, "white-space: pre-wrap;"},
    // `word-break: break-word` can break a space run.
    {"M):\n<span>    </span>p",
     {10, 90},
     "white-space: pre-wrap; word-break: break-word;",
     "span { font-size: 200%; }"},
    // Tabulation characters with `break-word`.
    {"&#9;&#9;<span>X</span>",
     {10, 170},
     "white-space: pre-wrap; word-break: break-word;"},
    // Soft Hyphens.
    {"abcd&shy;ef xx", {50, 90}},
    {"abcd&shy;ef xx", {60, 90}, "hyphens: none;"},
    {"abcd&shy; ef xx", {50, 100}, "hyphens: none;"},
    // Hyphenations.
    {"zz hyphenation xx", {50, 170}, "hyphens: auto;", "", "en-us"},
    // Atomic inlines.
    {"Hello <img>.", {50, 80}, "", "img { width: 1em; }"},
    {"Hello <img>.", {50, 120}, "", "img { width: 5em; }"},
    {"Hello <img>.", {60, 130}, "", "img { width: 6em; }"},
    // `text-indent`.
    {"6 12345 12", {60, 150}, "text-indent: 5em"},
    {"6 1234567 12", {70, 170}, "text-indent: 5em"},
    // `text-indent` with hyphenations.
    // The "hy-" with the indent should be longest.
    {"hyphenation a", {60, 160}, "hyphens: auto; text-indent: 3em", "", "en"},
    {"hhhhh a", {80, 100}, "hyphens: auto; text-indent: 3em", "", "en"},
    // Negative `text-indent`.
    {"43210123 1234 12", {40, 110}, "text-indent: -5em"},
    {"4321012345 1234 12", {50, 130}, "text-indent: -5em"},
    {"432 012 1", {30, 40}, "text-indent: -5em"},
    {"432 01 12", {20, 40}, "text-indent: -5em"},
    // Floats.
    {"XXX <div id=left></div> XXXX",
     {50, 130},
     "",
     "#left { float: left; width: 50px; }"},
    // Floats with clearances.
    {"XXX <div id=left></div><div id=right></div><div id=left></div> XXX",
     {50, 160},
     "",
     "#left { float: left; width: 40px; }"
     "#right { float: right; clear: left; width: 50px; }"},
};

std::ostream& operator<<(std::ostream& os, const MinMaxData& data) {
  return os << data.content << std::endl << data.style;
}

class MinMaxTest : public InlineNodeTest,
                   public testing::WithParamInterface<MinMaxData> {};

INSTANTIATE_TEST_SUITE_P(InlineNodeTest,
                         MinMaxTest,
                         testing::ValuesIn(min_max_data));

TEST_P(MinMaxTest, Data) {
  const MinMaxData& data = GetParam();
  LoadAhem();
  StringBuilder html;
  html.AppendFormat(R"HTML("
    <!DOCTYPE html>
    <style>
    #target { font: 10px Ahem;%s }
    %s
    </style>
    <div id="target")HTML",
                    data.target_style, data.style);
  if (data.lang) {
    html.AppendFormat(" lang='%s'", data.lang);
    LayoutLocale::SetHyphenationForTesting(AtomicString(data.lang),
                                           MockHyphenation::Create());
  }
  html.AppendFormat(">%s</div>", data.content);
  SetupHtml("target", html.ToString());
  InlineNodeForTest node = CreateInlineNode();
  const MinMaxSizes actual_sizes = ComputeMinMaxSizes(node);
  const MinMaxSizes expected_sizezs{LayoutUnit(data.min_max[0]),
                                    LayoutUnit(data.min_max[1])};
  EXPECT_EQ(actual_sizes, expected_sizezs);
}

// For http://crbug.com/1112560
TEST_F(InlineNodeTest, MinMaxSizesSaturated) {
  LoadAhem();
  SetupHtml("t", R"HTML(
    <style>
    b {
        display: inline-block;
        border-inline-start: groove;
        width:1e8px;
    }
    #t {
        float: left;
        font: 10px Ahem;
    }
    </style>
    <div id=t><b></b> <img></div>)HTML");

  InlineNodeForTest node = CreateInlineNode();
  MinMaxSizes sizes = ComputeMinMaxSizes(node);
  EXPECT_EQ(LayoutUnit(33554431), sizes.min_size.Round());
  // Note: |sizes.max_size.Round()| isn't |LayoutUnit::Max()| on some platform.
}

// For http://crbug.com/1116713
TEST_F(InlineNodeTest, MinMaxSizesNeedsLayout) {
  LoadAhem();
  SetupHtml("t",
            "<style>#t { width: 2ch; }</style>"
            "<div id=t> a <b>b</b></div>");

  auto& text = To<Text>(*GetElementById("t")->firstChild());
  LayoutText& layout_text = *text.GetLayoutObject();
  EXPECT_FALSE(layout_text.NeedsLayout());

  text.replaceData(0, 1, u"X", ASSERT_NO_EXCEPTION);
  EXPECT_TRUE(layout_text.NeedsLayout());

  InlineNodeForTest node = CreateInlineNode();
  ComputeMinMaxSizes(node);
  EXPECT_TRUE(layout_text.NeedsLayout());
}

TEST_F(InlineNodeTest, AssociatedItemsWithControlItem) {
  SetBodyInnerHTML(
      "<pre id=t style='-webkit-rtl-ordering:visual'>ab\nde</pre>");
  auto* const layout_text =
      To<LayoutText>(GetElementById("t")->firstChild()->GetLayoutObject());
  ASSERT_TRUE(layout_text->HasValidInlineItems());
  Vector<const InlineItem*> items;
  for (const InlineItem& item : layout_text->InlineItems()) {
    items.push_back(&item);
  }
  ASSERT_EQ(5u, items.size());
  TEST_ITEM_TYPE_OFFSET((*items[0]), kText, 1u, 3u);
  TEST_ITEM_TYPE_OFFSET((*items[1]), kBidiControl, 3u, 4u);
  TEST_ITEM_TYPE_OFFSET((*items[2]), kControl, 4u, 5u);
  TEST_ITEM_TYPE_OFFSET((*items[3]), kBidiControl, 5u, 6u);
  TEST_ITEM_TYPE_OFFSET((*items[4]), kText, 6u, 8u);
}

TEST_F(InlineNodeTest, NeedsCollectInlinesOnSetText) {
  SetBodyInnerHTML(R"HTML(
    <div id="container">
      <span id="previous"></span>
      <span id="parent">old</span>
      <span id="next"></span>
    </div>
  )HTML");

  Element* container = GetElementById("container");
  Element* parent = GetElementById("parent");
  auto* text = To<Text>(parent->firstChild());
  EXPECT_FALSE(text->GetLayoutObject()->NeedsCollectInlines());
  EXPECT_FALSE(parent->GetLayoutObject()->NeedsCollectInlines());
  EXPECT_FALSE(container->GetLayoutObject()->NeedsCollectInlines());

  text->setData("new");
  GetDocument().UpdateStyleAndLayoutTree();

  // The text and ancestors up to the container should be marked.
  EXPECT_TRUE(text->GetLayoutObject()->NeedsCollectInlines());
  EXPECT_TRUE(parent->GetLayoutObject()->NeedsCollectInlines());
  EXPECT_TRUE(container->GetLayoutObject()->NeedsCollectInlines());

  // Siblings of |parent| should stay clean.
  Element* previous = GetElementById("previous");
  Element* next = GetElementById("next");
  EXPECT_FALSE(previous->GetLayoutObject()->NeedsCollectInlines());
  EXPECT_FALSE(next->GetLayoutObject()->NeedsCollectInlines());
}

// crbug.com/325306591
// We had a crash in OffsetMapping building during SetTextWithOffset().
TEST_F(InlineNodeTest, SetTextWithOffsetWithTextTransform) {
  SetBodyInnerHTML(R"HTML(
    <div id="container" style="text-transform:uppercase">&#xdf;X</div>)HTML");

  Element* container = GetElementById("container");
  auto* text = To<Text>(container->firstChild());

  text->deleteData(1, 1, ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();
  // Pass if no crash in InlineItemsBuilder.
}

struct StyleChangeData {
  const char* css;
  enum ChangedElements {
    kText = 1,
    kParent = 2,
    kContainer = 4,

    kNone = 0,
    kTextAndParent = kText | kParent,
    kParentAndAbove = kParent | kContainer,
    kAll = kText | kParentAndAbove,
  };
  unsigned needs_collect_inlines;
  std::optional<bool> is_line_dirty;
  std::optional<bool> invalidate_ink_overflow;
} style_change_data[] = {
    // Changing color, text-decoration, outline, etc. should not re-run
    // |CollectInlines()|.
    {"#parent.after { color: red; }", StyleChangeData::kNone, false},
    {"#parent.after { text-decoration-line: underline; }",
     StyleChangeData::kNone, false, true},
    {"#parent { background: orange; }"  // Make sure it's not culled.
     "#parent.after { outline: auto; }",
     StyleChangeData::kNone, false, false},
    // Changing fonts should re-run |CollectInlines()|.
    {"#parent.after { font-size: 200%; }", StyleChangeData::kAll, true},
    // Changing from/to out-of-flow should re-rerun |CollectInlines()|.
    {"#parent.after { position: absolute; }", StyleChangeData::kContainer,
     true},
    {"#parent { position: absolute; }"
     "#parent.after { position: initial; }",
     StyleChangeData::kContainer, true},
    // List markers are captured in |InlineItem|.
    {"#parent.after { display: list-item; }", StyleChangeData::kContainer},
    {"#parent { display: list-item; list-style-type: none; }"
     "#parent.after { list-style-type: disc; }",
     StyleChangeData::kParent},
    {"#parent { display: list-item; }"
     "#container.after { list-style-type: none; }",
     StyleChangeData::kParent},
    // Changing properties related with bidi resolution should re-run
    // |CollectInlines()|.
    {"#parent.after { unicode-bidi: bidi-override; }",
     StyleChangeData::kParentAndAbove, true},
    {"#container.after { unicode-bidi: bidi-override; }",
     StyleChangeData::kContainer, false},
};

std::ostream& operator<<(std::ostream& os, const StyleChangeData& data) {
  return os << data.css;
}

class StyleChangeTest : public InlineNodeTest,
                        public testing::WithParamInterface<StyleChangeData> {};

INSTANTIATE_TEST_SUITE_P(InlineNodeTest,
                         StyleChangeTest,
                         testing::ValuesIn(style_change_data));

TEST_P(StyleChangeTest, NeedsCollectInlinesOnStyle) {
  auto data = GetParam();
  SetBodyInnerHTML(String(R"HTML(
    <style>
    )HTML") + data.css +
                   R"HTML(
    </style>
    <div id="container">
      <span id="previous"></span>
      <span id="parent">text</span>
      <span id="next"></span>
    </div>
  )HTML");

  Element* container = GetElementById("container");
  Element* parent = GetElementById("parent");
  auto* text = To<Text>(parent->firstChild());
  EXPECT_FALSE(text->GetLayoutObject()->NeedsCollectInlines());
  EXPECT_FALSE(parent->GetLayoutObject()->NeedsCollectInlines());
  EXPECT_FALSE(container->GetLayoutObject()->NeedsCollectInlines());

  container->classList().Add(AtomicString("after"));
  parent->classList().Add(AtomicString("after"));
  GetDocument().UpdateStyleAndLayoutTree();

  // The text and ancestors up to the container should be marked.
  unsigned changes = StyleChangeData::kNone;
  if (text->GetLayoutObject()->NeedsCollectInlines())
    changes |= StyleChangeData::kText;
  if (parent->GetLayoutObject()->NeedsCollectInlines())
    changes |= StyleChangeData::kParent;
  if (container->GetLayoutObject()->NeedsCollectInlines())
    changes |= StyleChangeData::kContainer;
  EXPECT_EQ(changes, data.needs_collect_inlines);

  // Siblings of |parent| should stay clean.
  Element* previous = GetElementById("previous");
  Element* next = GetElementById("next");
  EXPECT_FALSE(previous->GetLayoutObject()->NeedsCollectInlines());
  EXPECT_FALSE(next->GetLayoutObject()->NeedsCollectInlines());

  if (data.is_line_dirty) {
    TestAnyItemsAreDirty(*To<LayoutBlockFlow>(container->GetLayoutObject()),
                         *data.is_line_dirty);
  }

  if (data.invalidate_ink_overflow) {
    const LayoutObject* parent_layout_object = parent->GetLayoutObject();
    for (const LayoutObject* child = parent_layout_object->SlowFirstChild();
         child; child = child->NextInPreOrder(parent_layout_object)) {
      if (child->IsText()) {
        InlineCursor cursor;
        for (cursor.MoveTo(*child); cursor;
             cursor.MoveToNextForSameLayoutObject()) {
          const FragmentItem* item = cursor.CurrentItem();
          EXPECT_EQ(item->IsInkOverflowComputed(),
                    !*data.invalidate_ink_overflow);
        }
      }
    }
  }

  ForceLayout();  // Ensure running layout does not crash.
}

using CreateNode = Node* (*)(Document&);
static CreateNode node_creators[] = {
    [](Document& document) -> Node* { return document.createTextNode("new"); },
    [](Document& document) -> Node* {
      return document.CreateRawElement(html_names::kSpanTag);
    },
    [](Document& document) -> Node* {
      Element* element = document.CreateRawElement(html_names::kSpanTag);
      element->classList().Add(AtomicString("abspos"));
      return element;
    },
    [](Document& document) -> Node* {
      Element* element = document.CreateRawElement(html_names::kSpanTag);
      element->classList().Add(AtomicString("float"));
      return element;
    }};

class NodeInsertTest : public InlineNodeTest,
                       public testing::WithParamInterface<CreateNode> {};

INSTANTIATE_TEST_SUITE_P(InlineNodeTest,
                         NodeInsertTest,
                         testing::ValuesIn(node_creators));

TEST_P(NodeInsertTest, NeedsCollectInlinesOnInsert) {
  SetBodyInnerHTML(R"HTML(
    <style>
    .abspos { position: absolute; }
    .float { float: left; }
    </style>
 
"""


```