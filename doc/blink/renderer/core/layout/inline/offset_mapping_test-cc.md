Response:
The user wants a summary of the functionality of the provided C++ code snippet. I need to identify the purpose of the code, how it relates to web technologies (JavaScript, HTML, CSS), illustrate logical reasoning with examples, highlight potential usage errors, and finally provide a concise summary of its core function.

**Plan:**

1. **Identify the core purpose:** The code defines tests for the `OffsetMapping` class. This class seems to be responsible for mapping DOM offsets to text content offsets, considering whitespace collapsing and other transformations.

2. **Relate to web technologies:** This functionality is crucial for text editing, selection, and rendering in the browser. It bridges the gap between the DOM structure and the rendered text content influenced by CSS `white-space` property.

3. **Illustrate logical reasoning:**  Examples of whitespace collapsing and how `OffsetMapping` tracks these changes are key here. I'll need to devise simple scenarios with expected input and output for the `GetOffsetMapping()` function.

4. **Identify common usage errors:** Incorrectly assuming a direct 1:1 mapping between DOM offsets and text content offsets when dealing with whitespace is a common mistake.

5. **Summarize the functionality:**  Focus on the core purpose of the `OffsetMapping` and its role in the rendering engine.
这是对 `blink/renderer/core/layout/inline/offset_mapping_test.cc` 文件第一部分的分析和功能归纳。

**功能列举:**

该代码文件是 Chromium Blink 引擎中 `OffsetMapping` 类的单元测试文件。其主要功能是测试 `OffsetMapping` 类的各种功能，包括：

1. **测试空格和制表符的折叠 (Collapsing Spaces and Tabs):**  验证在不同的 `white-space` CSS 属性下，连续的空格和制表符是否被正确折叠成一个空格或被保留。
2. **测试换行符的折叠 (Collapsing New Lines):** 验证在不同的 `white-space` CSS 属性下，换行符是否被折叠成空格、被移除或被保留。
3. **测试跨元素的空格和换行符折叠 (Collapsing Across Elements):** 验证空格和换行符在不同的 HTML 元素之间是否被正确折叠。
4. **测试前导和尾随空格/换行符的折叠 (Leading/Trailing Spaces/Newlines):** 验证文本节点开头和结尾的空格和换行符是否被正确折叠。
5. **测试零宽空格的影响 (Collapse Zero Width Spaces):** 验证零宽空格 (`\u200B`) 如何影响换行符的折叠。
6. **测试 `OffsetMapping` 对象的存储和获取 (Stored Result):** 验证 `OffsetMapping` 对象是否在需要时被计算并存储。
7. **测试获取内联格式化上下文 (NGInlineFormattingContextOf):**  测试根据给定的位置，是否能正确获取到所属的内联格式化上下文对象。
8. **测试 `OffsetMapping` 类的核心 API:**  测试 `OffsetMapping` 类提供的各种方法，例如：
    - `GetText()`: 获取所有文本内容的字符串。
    - `GetUnits()`: 获取 `OffsetMappingUnit` 对象的向量，每个对象代表一段映射关系。
    - `GetRanges()`: 获取 DOM 节点到 `OffsetMappingUnit` 索引范围的映射。
    - `GetUnitForPosition()`:  根据 DOM 中的 `Position` 获取对应的 `OffsetMappingUnit`。
    - `GetTextContentOffset()`: 根据 DOM 中的 `Position` 获取其在文本内容中的偏移量。
    - `GetFirstPosition()`: 根据文本内容偏移量获取对应的第一个 DOM `Position`。
    - `GetLastPosition()`: 根据文本内容偏移量获取对应的最后一个 DOM `Position`。
    - `StartOfNextNonCollapsedContent()`: 获取给定 `Position` 之后第一个非折叠内容的起始 `Position`。
    - `EndOfLastNonCollapsedContent()`: 获取给定 `Position` 之前最后一个非折叠内容的结束 `Position`。
    - `IsBeforeNonCollapsedContent()`: 判断给定的 `Position` 是否在一个非折叠内容之前。
    - `IsAfterNonCollapsedContent()`: 判断给定的 `Position` 是否在一个非折叠内容之后。

**与 JavaScript, HTML, CSS 的关系和举例说明:**

`OffsetMapping` 类是 Blink 引擎内部用于处理文本布局的关键组件，它直接受到 HTML 结构和 CSS 样式的 (`white-space` 属性) 影响。

* **HTML:** HTML 定义了文本内容的结构。`OffsetMapping` 需要遍历 HTML 结构中的文本节点和行分隔符 (`<br>`) 来构建映射关系。例如，`<div id=t>foo<br>bar</div>` 会被解析成两个文本节点和一个 `<br>` 元素，`OffsetMapping` 需要将这些 DOM 结构映射到 "foo\nbar" 这样的文本内容。
* **CSS:** CSS 的 `white-space` 属性决定了如何处理元素内的空白符。`OffsetMapping` 的测试用例中大量使用了不同的 `white-space` 属性值（如 `normal`, `nowrap`, `pre`, `pre-wrap`, `pre-line`）来验证空格、制表符和换行符的折叠逻辑是否正确。例如：
    ```html
    <div id=t style="white-space: normal">text  text</div>
    ```
    在这种情况下，CSS `white-space: normal` 会将连续的空格折叠成一个空格。`OffsetMapping` 需要能够正确地将 DOM 中两个空格的偏移量映射到文本内容中一个空格的偏移量。
* **JavaScript:** 虽然这段代码是 C++，但 `OffsetMapping` 的功能对 JavaScript API (例如 Selection API, Range API) 的实现至关重要。JavaScript 可以通过这些 API 获取和操作文本内容的选择范围。`OffsetMapping` 确保了 JavaScript 获取到的 DOM 偏移量和实际渲染的文本内容偏移量之间的一致性。例如，当用户在浏览器中选中 "text  text" 中的两个空格时，JavaScript 的 Selection API 依赖于 `OffsetMapping` 来确定这两个空格在 DOM 中的起始和结束位置，以及它们在渲染文本内容中的对应位置（可能合并成一个空格）。

**逻辑推理的假设输入与输出:**

假设有以下 HTML 和 CSS:

```html
<div id="test" style="white-space: normal;">Hello  World</div>
```

**假设输入:**  对 id 为 "test" 的 `LayoutBlockFlow` 对象调用 `GetOffsetMapping()` 方法。

**逻辑推理:**

1. `OffsetMapping` 会遍历 "Hello  World" 这个文本节点。
2. 由于 `white-space: normal;`，连续的两个空格会被折叠成一个空格。
3. `OffsetMapping` 会创建 `OffsetMappingUnit` 对象来表示这种映射关系。

**可能的输出 (部分):**

* `GetText()` 返回: "Hello World"
* `GetUnits()` 可能包含多个 `OffsetMappingUnit`，其中一个可能如下所示（简化表示）：
    * 类型: `kIdentity` (对于 "Hello")
    * DOM 起始: 0, DOM 结束: 5, 文本内容起始: 0, 文本内容结束: 5
    * 类型: `kCollapsed` (对于连续的空格)
    * DOM 起始: 5, DOM 结束: 7, 文本内容起始: 5, 文本内容结束: 5
    * 类型: `kIdentity` (对于 "World")
    * DOM 起始: 7, DOM 结束: 12, 文本内容起始: 5, 文本内容结束: 10

**用户或编程常见的使用错误:**

* **错误地假设 DOM 偏移量与文本内容偏移量一一对应:**  开发者可能会错误地认为 DOM 中文本的第 N 个字符一定对应于渲染后文本的第 N 个字符。但像空格折叠这样的 CSS 行为会打破这种假设。
    * **举例:** 在 "Hello  World" 的例子中，DOM 偏移量 6 指向第二个空格，但文本内容偏移量 6 指向的是 "W"。如果开发者没有考虑到空格折叠，直接使用 DOM 偏移量来操作文本内容，可能会导致错误的结果。
* **没有考虑到 `white-space` 属性的影响:**  开发者在处理文本时，如果没有意识到 `white-space` 属性的不同取值会如何影响空白符的处理，就可能出现意料之外的布局或文本操作结果。

**功能归纳 (第1部分):**

该代码文件的第一部分主要专注于测试 `OffsetMapping` 类在处理不同类型的空白符（空格、制表符、换行符、零宽空格）以及在不同的 `white-space` CSS 属性下的折叠行为。它验证了 `OffsetMapping` 能够正确地建立 DOM 结构和最终渲染的文本内容之间的映射关系，包括那些被 CSS 规则折叠或移除的空白符。此外，它还初步测试了 `OffsetMapping` 对象的存储和获取，以及获取内联格式化上下文的功能。 这部分测试是确保 Blink 引擎正确渲染和处理文本的基础。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/offset_mapping_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/inline/offset_mapping.h"

#include "testing/gtest/include/gtest/gtest-death-test.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/first_letter_pseudo_element.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"

namespace blink {

// The spec turned into a discussion that may change. Put this logic on hold
// until CSSWG resolves the issue.
// https://github.com/w3c/csswg-drafts/issues/337
#define SEGMENT_BREAK_TRANSFORMATION_FOR_EAST_ASIAN_WIDTH 0

// Helper functions to use |EXPECT_EQ()| for |OffsetMappingUnit| and its span.
HeapVector<OffsetMappingUnit> ToVector(
    const base::span<const OffsetMappingUnit>& range) {
  HeapVector<OffsetMappingUnit> units;
  for (const auto& unit : range)
    units.push_back(unit);
  return units;
}

bool operator==(const OffsetMappingUnit& unit, const OffsetMappingUnit& other) {
  return unit.GetType() == other.GetType() &&
         unit.GetLayoutObject() == other.GetLayoutObject() &&
         unit.DOMStart() == other.DOMStart() &&
         unit.DOMEnd() == other.DOMEnd() &&
         unit.TextContentStart() == other.TextContentStart() &&
         unit.TextContentEnd() == other.TextContentEnd();
}

bool operator!=(const OffsetMappingUnit& unit, const OffsetMappingUnit& other) {
  return !operator==(unit, other);
}

void PrintTo(const OffsetMappingUnit& unit, std::ostream* ostream) {
  static const std::array<const char*, 3> kTypeNames = {"Identity", "Collapsed",
                                                        "Expanded"};
  *ostream << "{" << kTypeNames[static_cast<unsigned>(unit.GetType())] << " "
           << unit.GetLayoutObject() << " dom=" << unit.DOMStart() << "-"
           << unit.DOMEnd() << " tc=" << unit.TextContentStart() << "-"
           << unit.TextContentEnd() << "}";
}

void PrintTo(const HeapVector<OffsetMappingUnit>& units,
             std::ostream* ostream) {
  *ostream << "[";
  const char* comma = "";
  for (const auto& unit : units) {
    *ostream << comma;
    PrintTo(unit, ostream);
    comma = ", ";
  }
  *ostream << "]";
}

void PrintTo(const base::span<const OffsetMappingUnit>& range,
             std::ostream* ostream) {
  PrintTo(ToVector(range), ostream);
}

class OffsetMappingTest : public RenderingTest {
 protected:
  static const auto kCollapsed = OffsetMappingUnitType::kCollapsed;
  static const auto kIdentity = OffsetMappingUnitType::kIdentity;

  void SetupHtml(const char* id, String html) {
    SetBodyInnerHTML(html);
    layout_block_flow_ = To<LayoutBlockFlow>(GetLayoutObjectByElementId(id));
    DCHECK(layout_block_flow_->IsLayoutNGObject());
    layout_object_ = layout_block_flow_->FirstChild();
  }

  const OffsetMapping& GetOffsetMapping() const {
    const OffsetMapping* map =
        InlineNode(layout_block_flow_).ComputeOffsetMappingIfNeeded();
    CHECK(map);
    return *map;
  }

  String GetCollapsedIndexes() const {
    const OffsetMapping& mapping = GetOffsetMapping();
    const EphemeralRange block_range =
        EphemeralRange::RangeOfContents(*layout_block_flow_->GetNode());

    StringBuilder result;
    for (const Node& node : block_range.Nodes()) {
      if (!node.IsTextNode())
        continue;

      Vector<unsigned> collapsed_indexes;
      for (const auto& unit : mapping.GetMappingUnitsForDOMRange(
               EphemeralRange::RangeOfContents(node))) {
        if (unit.GetType() != OffsetMappingUnitType::kCollapsed) {
          continue;
        }
        for (unsigned i = unit.DOMStart(); i < unit.DOMEnd(); ++i)
          collapsed_indexes.push_back(i);
      }

      result.Append('{');
      bool first = true;
      for (unsigned index : collapsed_indexes) {
        if (!first)
          result.Append(", ");
        result.AppendNumber(index);
        first = false;
      }
      result.Append('}');
    }
    return result.ToString();
  }

  HeapVector<OffsetMappingUnit> GetFirstLast(const std::string& caret_text) {
    const unsigned offset = static_cast<unsigned>(caret_text.find('|'));
    return {*GetOffsetMapping().GetFirstMappingUnit(offset),
            *GetOffsetMapping().GetLastMappingUnit(offset)};
  }

  HeapVector<OffsetMappingUnit> GetUnits(wtf_size_t index1, wtf_size_t index2) {
    const auto& units = GetOffsetMapping().GetUnits();
    return {units[index1], units[index2]};
  }

  String TestCollapsingWithCSSWhiteSpace(String text, String whitespace) {
    StringBuilder html;
    html.Append("<div id=t style=\"white-space:");
    html.Append(whitespace);
    html.Append("\">");
    html.Append(text);
    html.Append("</div>");
    SetupHtml("t", html.ToString());
    return GetCollapsedIndexes();
  }

  String TestCollapsing(Vector<String> text) {
    StringBuilder html;
    html.Append("<div id=t>");
    for (unsigned i = 0; i < text.size(); ++i) {
      if (i)
        html.Append("<!---->");
      html.Append(text[i]);
    }
    html.Append("</div>");
    SetupHtml("t", html.ToString());
    return GetCollapsedIndexes();
  }

  String TestCollapsing(String text) {
    return TestCollapsing(Vector<String>({text}));
  }

  String TestCollapsing(String text, String text2) {
    return TestCollapsing(Vector<String>({text, text2}));
  }

  String TestCollapsing(String text, String text2, String text3) {
    return TestCollapsing(Vector<String>({text, text2, text3}));
  }

  bool IsOffsetMappingStored() const {
    return layout_block_flow_->GetInlineNodeData()->offset_mapping != nullptr;
  }

  const LayoutText* GetLayoutTextUnder(const char* parent_id) {
    Element* parent = GetElementById(parent_id);
    return To<LayoutText>(parent->firstChild()->GetLayoutObject());
  }

  const OffsetMappingUnit* GetUnitForPosition(const Position& position) const {
    return GetOffsetMapping().GetMappingUnitForPosition(position);
  }

  std::optional<unsigned> GetTextContentOffset(const Position& position) const {
    return GetOffsetMapping().GetTextContentOffset(position);
  }

  Position StartOfNextNonCollapsedContent(const Position& position) const {
    return GetOffsetMapping().StartOfNextNonCollapsedContent(position);
  }

  Position EndOfLastNonCollapsedContent(const Position& position) const {
    return GetOffsetMapping().EndOfLastNonCollapsedContent(position);
  }

  bool IsBeforeNonCollapsedContent(const Position& position) const {
    return GetOffsetMapping().IsBeforeNonCollapsedContent(position);
  }

  bool IsAfterNonCollapsedContent(const Position& position) const {
    return GetOffsetMapping().IsAfterNonCollapsedContent(position);
  }

  Position GetFirstPosition(unsigned offset) const {
    return GetOffsetMapping().GetFirstPosition(offset);
  }

  Position GetLastPosition(unsigned offset) const {
    return GetOffsetMapping().GetLastPosition(offset);
  }

  Persistent<LayoutBlockFlow> layout_block_flow_;
  Persistent<LayoutObject> layout_object_;
  FontCachePurgePreventer purge_preventer_;
};

TEST_F(OffsetMappingTest, CollapseSpaces) {
  String input("text text  text   text");
  EXPECT_EQ("{10, 16, 17}", TestCollapsingWithCSSWhiteSpace(input, "normal"));
  EXPECT_EQ("{10, 16, 17}", TestCollapsingWithCSSWhiteSpace(input, "nowrap"));
  EXPECT_EQ("{10, 16, 17}",
            TestCollapsingWithCSSWhiteSpace(input, "-webkit-nowrap"));
  EXPECT_EQ("{10, 16, 17}", TestCollapsingWithCSSWhiteSpace(input, "pre-line"));
  EXPECT_EQ("{}", TestCollapsingWithCSSWhiteSpace(input, "pre"));
  EXPECT_EQ("{}", TestCollapsingWithCSSWhiteSpace(input, "pre-wrap"));
}

TEST_F(OffsetMappingTest, CollapseTabs) {
  String input("text text \ttext \t\ttext");
  EXPECT_EQ("{10, 16, 17}", TestCollapsingWithCSSWhiteSpace(input, "normal"));
  EXPECT_EQ("{10, 16, 17}", TestCollapsingWithCSSWhiteSpace(input, "nowrap"));
  EXPECT_EQ("{10, 16, 17}",
            TestCollapsingWithCSSWhiteSpace(input, "-webkit-nowrap"));
  EXPECT_EQ("{10, 16, 17}", TestCollapsingWithCSSWhiteSpace(input, "pre-line"));
  EXPECT_EQ("{}", TestCollapsingWithCSSWhiteSpace(input, "pre"));
  EXPECT_EQ("{}", TestCollapsingWithCSSWhiteSpace(input, "pre-wrap"));
}

TEST_F(OffsetMappingTest, CollapseNewLines) {
  String input("text\ntext \n text\n\ntext");
  EXPECT_EQ("{10, 11, 17}", TestCollapsingWithCSSWhiteSpace(input, "normal"));
  EXPECT_EQ("{10, 11, 17}", TestCollapsingWithCSSWhiteSpace(input, "nowrap"));
  EXPECT_EQ("{10, 11, 17}",
            TestCollapsingWithCSSWhiteSpace(input, "-webkit-nowrap"));
  EXPECT_EQ("{9, 11}", TestCollapsingWithCSSWhiteSpace(input, "pre-line"));
  EXPECT_EQ("{}", TestCollapsingWithCSSWhiteSpace(input, "pre"));
  EXPECT_EQ("{}", TestCollapsingWithCSSWhiteSpace(input, "pre-wrap"));
}

TEST_F(OffsetMappingTest, CollapseNewlinesAsSpaces) {
  EXPECT_EQ("{}", TestCollapsing("text\ntext"));
  EXPECT_EQ("{5}", TestCollapsing("text\n\ntext"));
  EXPECT_EQ("{5, 6, 7}", TestCollapsing("text \n\n text"));
  EXPECT_EQ("{5, 6, 7, 8}", TestCollapsing("text \n \n text"));
}

TEST_F(OffsetMappingTest, CollapseAcrossElements) {
  EXPECT_EQ("{}{0}", TestCollapsing("text ", " text"))
      << "Spaces are collapsed even when across elements.";
}

TEST_F(OffsetMappingTest, CollapseLeadingSpaces) {
  EXPECT_EQ("{0, 1}", TestCollapsing("  text"));
  // TODO(xiaochengh): Currently, LayoutText of trailing whitespace nodes are
  // omitted, so we can't verify the following cases. Get around it and make the
  // following tests work. EXPECT_EQ("{0}{}", TestCollapsing(" ", "text"));
  // EXPECT_EQ("{0}{0}", TestCollapsing(" ", " text"));
}

TEST_F(OffsetMappingTest, CollapseTrailingSpaces) {
  EXPECT_EQ("{4, 5}", TestCollapsing("text  "));
  EXPECT_EQ("{}{0}", TestCollapsing("text", " "));
  // TODO(xiaochengh): Get around whitespace LayoutText omission, and make the
  // following test cases work.
  // EXPECT_EQ("{4}{0}", TestCollapsing("text ", " "));
}

// TODO(xiaochengh): Get around whitespace LayoutText omission, and make the
// following test cases work.
TEST_F(OffsetMappingTest, DISABLED_CollapseAllSpaces) {
  EXPECT_EQ("{0, 1}", TestCollapsing("  "));
  EXPECT_EQ("{0, 1}{0, 1}", TestCollapsing("  ", "  "));
  EXPECT_EQ("{0, 1}{0}", TestCollapsing("  ", "\n"));
  EXPECT_EQ("{0}{0, 1}", TestCollapsing("\n", "  "));
}

TEST_F(OffsetMappingTest, CollapseLeadingNewlines) {
  EXPECT_EQ("{0}", TestCollapsing("\ntext"));
  EXPECT_EQ("{0, 1}", TestCollapsing("\n\ntext"));
  // TODO(xiaochengh): Get around whitespace LayoutText omission, and make the
  // following test cases work.
  // EXPECT_EQ("{0}{}", TestCollapsing("\n", "text"));
  // EXPECT_EQ("{0, 1}{}", TestCollapsing("\n\n", "text"));
  // EXPECT_EQ("{0, 1}{}", TestCollapsing(" \n", "text"));
  // EXPECT_EQ("{0}{0}", TestCollapsing("\n", " text"));
  // EXPECT_EQ("{0, 1}{0}", TestCollapsing("\n\n", " text"));
  // EXPECT_EQ("{0, 1}{0}", TestCollapsing(" \n", " text"));
  // EXPECT_EQ("{0}{0}", TestCollapsing("\n", "\ntext"));
  // EXPECT_EQ("{0, 1}{0}", TestCollapsing("\n\n", "\ntext"));
  // EXPECT_EQ("{0, 1}{0}", TestCollapsing(" \n", "\ntext"));
}

TEST_F(OffsetMappingTest, CollapseTrailingNewlines) {
  EXPECT_EQ("{4}", TestCollapsing("text\n"));
  EXPECT_EQ("{}{0}", TestCollapsing("text", "\n"));
  // TODO(xiaochengh): Get around whitespace LayoutText omission, and make the
  // following test cases work.
  // EXPECT_EQ("{4}{0}", TestCollapsing("text\n", "\n"));
  // EXPECT_EQ("{4}{0}", TestCollapsing("text\n", " "));
  // EXPECT_EQ("{4}{0}", TestCollapsing("text ", "\n"));
}

TEST_F(OffsetMappingTest, CollapseNewlineAcrossElements) {
  EXPECT_EQ("{}{0}", TestCollapsing("text ", "\ntext"));
  EXPECT_EQ("{}{0, 1}", TestCollapsing("text ", "\n text"));
  EXPECT_EQ("{}{}{0}", TestCollapsing("text", " ", "\ntext"));
}

TEST_F(OffsetMappingTest, CollapseBeforeAndAfterNewline) {
  EXPECT_EQ("{4, 5, 7, 8}",
            TestCollapsingWithCSSWhiteSpace("text  \n  text", "pre-line"))
      << "Spaces before and after newline are removed.";
}

TEST_F(OffsetMappingTest,
       CollapsibleSpaceAfterNonCollapsibleSpaceAcrossElements) {
  SetupHtml("t",
            "<div id=t>"
            "<span style=\"white-space:pre-wrap\">text </span>"
            " text"
            "</div>");
  EXPECT_EQ("{}{}", GetCollapsedIndexes())
      << "The whitespace in constructions like '<span style=\"white-space: "
         "pre-wrap\">text <span><span> text</span>' does not collapse.";
}

TEST_F(OffsetMappingTest, CollapseZeroWidthSpaces) {
  EXPECT_EQ("{5}", TestCollapsing(u"text\u200B\ntext"))
      << "Newline is removed if the character before is ZWS.";
  EXPECT_EQ("{4}", TestCollapsing(u"text\n\u200Btext"))
      << "Newline is removed if the character after is ZWS.";
  EXPECT_EQ("{5}", TestCollapsing(u"text\u200B\n\u200Btext"))
      << "Newline is removed if the character before/after is ZWS.";

  EXPECT_EQ("{4}{}", TestCollapsing(u"text\n", u"\u200Btext"))
      << "Newline is removed if the character after across elements is ZWS.";
  EXPECT_EQ("{}{0}", TestCollapsing(u"text\u200B", u"\ntext"))
      << "Newline is removed if the character before is ZWS even across "
         "elements.";

  EXPECT_EQ("{4, 5}{}", TestCollapsing(u"text \n", u"\u200Btext"))
      << "Collapsible space before newline does not affect the result.";
  EXPECT_EQ("{5}{}", TestCollapsing(u"text\u200B\n", u" text"))
      << "Collapsible space after newline is removed even when the "
         "newline was removed.";
  EXPECT_EQ("{5}{0}", TestCollapsing(u"text\u200B ", u"\ntext"))
      << "A white space sequence containing a segment break before or after "
         "a zero width space is collapsed to a zero width space.";
}

#if SEGMENT_BREAK_TRANSFORMATION_FOR_EAST_ASIAN_WIDTH
TEST_F(OffsetMappingTest, CollapseEastAsianWidth) {
  EXPECT_EQ("{1}", TestCollapsing(u"\u4E00\n\u4E00"))
      << "Newline is removed when both sides are Wide.";

  EXPECT_EQ("{}", TestCollapsing(u"\u4E00\nA"))
      << "Newline is not removed when after is Narrow.";
  EXPECT_EQ("{}", TestCollapsing(u"A\n\u4E00"))
      << "Newline is not removed when before is Narrow.";

  EXPECT_EQ("{1}{}", TestCollapsing(u"\u4E00\n", u"\u4E00"))
      << "Newline at the end of elements is removed when both sides are Wide.";
  EXPECT_EQ("{}{0}", TestCollapsing(u"\u4E00", u"\n\u4E00"))
      << "Newline at the beginning of elements is removed "
         "when both sides are Wide.";
}
#endif

#define TEST_UNIT(unit, type, owner, dom_start, dom_end, text_content_start, \
                  text_content_end)                                          \
  EXPECT_EQ(type, unit.GetType());                                           \
  EXPECT_EQ(owner, &unit.GetOwner());                                        \
  EXPECT_EQ(dom_start, unit.DOMStart());                                     \
  EXPECT_EQ(dom_end, unit.DOMEnd());                                         \
  EXPECT_EQ(text_content_start, unit.TextContentStart());                    \
  EXPECT_EQ(text_content_end, unit.TextContentEnd())

#define TEST_RANGE(ranges, owner, start, end) \
  ASSERT_TRUE(ranges.Contains(owner));        \
  EXPECT_EQ(start, ranges.at(owner).first);   \
  EXPECT_EQ(end, ranges.at(owner).second)

TEST_F(OffsetMappingTest, StoredResult) {
  SetupHtml("t", "<div id=t>foo</div>");
  EXPECT_FALSE(IsOffsetMappingStored());
  GetOffsetMapping();
  EXPECT_TRUE(IsOffsetMappingStored());
}

TEST_F(OffsetMappingTest, NGInlineFormattingContextOf) {
  SetBodyInnerHTML(
      "<div id=container>"
      "  foo"
      "  <span id=inline-block style='display:inline-block'>blah</span>"
      "  <span id=inline-span>bar</span>"
      "</div>");

  const Element* container = GetElementById("container");
  const Element* inline_block = GetElementById("inline-block");
  const Element* inline_span = GetElementById("inline-span");
  const Node* blah = inline_block->firstChild();
  const Node* foo = inline_block->previousSibling();
  const Node* bar = inline_span->firstChild();

  EXPECT_EQ(nullptr,
            NGInlineFormattingContextOf(Position::BeforeNode(*container)));
  EXPECT_EQ(nullptr,
            NGInlineFormattingContextOf(Position::AfterNode(*container)));

  const LayoutObject* container_object = container->GetLayoutObject();
  EXPECT_EQ(container_object, NGInlineFormattingContextOf(Position(foo, 0)));
  EXPECT_EQ(container_object, NGInlineFormattingContextOf(Position(bar, 0)));
  EXPECT_EQ(container_object,
            NGInlineFormattingContextOf(Position::BeforeNode(*inline_block)));
  EXPECT_EQ(container_object,
            NGInlineFormattingContextOf(Position::AfterNode(*inline_block)));

  const LayoutObject* inline_block_object = inline_block->GetLayoutObject();
  EXPECT_EQ(inline_block_object,
            NGInlineFormattingContextOf(Position(blah, 0)));
}

TEST_F(OffsetMappingTest, OneTextNode) {
  SetupHtml("t", "<div id=t>foo</div>");
  const Node* foo_node = layout_object_->GetNode();
  const OffsetMapping& result = GetOffsetMapping();

  EXPECT_EQ("foo", result.GetText());

  ASSERT_EQ(1u, result.GetUnits().size());
  TEST_UNIT(result.GetUnits()[0], OffsetMappingUnitType::kIdentity, foo_node,
            0u, 3u, 0u, 3u);

  ASSERT_EQ(1u, result.GetRanges().size());
  TEST_RANGE(result.GetRanges(), foo_node, 0u, 1u);

  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 0)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 1)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 2)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 3)));

  EXPECT_EQ(0u, *GetTextContentOffset(Position(foo_node, 0)));
  EXPECT_EQ(1u, *GetTextContentOffset(Position(foo_node, 1)));
  EXPECT_EQ(2u, *GetTextContentOffset(Position(foo_node, 2)));
  EXPECT_EQ(3u, *GetTextContentOffset(Position(foo_node, 3)));

  EXPECT_EQ(Position(foo_node, 0), GetFirstPosition(0));
  EXPECT_EQ(Position(foo_node, 1), GetFirstPosition(1));
  EXPECT_EQ(Position(foo_node, 2), GetFirstPosition(2));
  EXPECT_EQ(Position(foo_node, 3), GetFirstPosition(3));

  EXPECT_EQ(Position(foo_node, 0), GetLastPosition(0));
  EXPECT_EQ(Position(foo_node, 1), GetLastPosition(1));
  EXPECT_EQ(Position(foo_node, 2), GetLastPosition(2));
  EXPECT_EQ(Position(foo_node, 3), GetLastPosition(3));

  EXPECT_EQ(Position(foo_node, 0),
            StartOfNextNonCollapsedContent(Position(foo_node, 0)));
  EXPECT_EQ(Position(foo_node, 1),
            StartOfNextNonCollapsedContent(Position(foo_node, 1)));
  EXPECT_EQ(Position(foo_node, 2),
            StartOfNextNonCollapsedContent(Position(foo_node, 2)));
  EXPECT_TRUE(StartOfNextNonCollapsedContent(Position(foo_node, 3)).IsNull());

  EXPECT_TRUE(EndOfLastNonCollapsedContent(Position(foo_node, 0)).IsNull());
  EXPECT_EQ(Position(foo_node, 1),
            EndOfLastNonCollapsedContent(Position(foo_node, 1)));
  EXPECT_EQ(Position(foo_node, 2),
            EndOfLastNonCollapsedContent(Position(foo_node, 2)));
  EXPECT_EQ(Position(foo_node, 3),
            EndOfLastNonCollapsedContent(Position(foo_node, 3)));

  EXPECT_TRUE(IsBeforeNonCollapsedContent(Position(foo_node, 0)));
  EXPECT_TRUE(IsBeforeNonCollapsedContent(Position(foo_node, 1)));
  EXPECT_TRUE(IsBeforeNonCollapsedContent(Position(foo_node, 2)));
  EXPECT_FALSE(
      IsBeforeNonCollapsedContent(Position(foo_node, 3)));  // false at node end

  // false at node start
  EXPECT_FALSE(IsAfterNonCollapsedContent(Position(foo_node, 0)));
  EXPECT_TRUE(IsAfterNonCollapsedContent(Position(foo_node, 1)));
  EXPECT_TRUE(IsAfterNonCollapsedContent(Position(foo_node, 2)));
  EXPECT_TRUE(IsAfterNonCollapsedContent(Position(foo_node, 3)));
}

TEST_F(OffsetMappingTest, TwoTextNodes) {
  SetupHtml("t", "<div id=t>foo<span id=s>bar</span></div>");
  const auto* foo = To<LayoutText>(layout_object_.Get());
  const auto* bar = GetLayoutTextUnder("s");
  const Node* foo_node = foo->GetNode();
  const Node* bar_node = bar->GetNode();
  const OffsetMapping& result = GetOffsetMapping();

  EXPECT_EQ("foobar", result.GetText());

  ASSERT_EQ(2u, result.GetUnits().size());
  TEST_UNIT(result.GetUnits()[0], OffsetMappingUnitType::kIdentity, foo_node,
            0u, 3u, 0u, 3u);
  TEST_UNIT(result.GetUnits()[1], OffsetMappingUnitType::kIdentity, bar_node,
            0u, 3u, 3u, 6u);

  ASSERT_EQ(2u, result.GetRanges().size());
  TEST_RANGE(result.GetRanges(), foo_node, 0u, 1u);
  TEST_RANGE(result.GetRanges(), bar_node, 1u, 2u);

  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 0)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 1)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 2)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 3)));
  EXPECT_EQ(&result.GetUnits()[1], GetUnitForPosition(Position(bar_node, 0)));
  EXPECT_EQ(&result.GetUnits()[1], GetUnitForPosition(Position(bar_node, 1)));
  EXPECT_EQ(&result.GetUnits()[1], GetUnitForPosition(Position(bar_node, 2)));
  EXPECT_EQ(&result.GetUnits()[1], GetUnitForPosition(Position(bar_node, 3)));

  EXPECT_EQ(0u, *GetTextContentOffset(Position(foo_node, 0)));
  EXPECT_EQ(1u, *GetTextContentOffset(Position(foo_node, 1)));
  EXPECT_EQ(2u, *GetTextContentOffset(Position(foo_node, 2)));
  EXPECT_EQ(3u, *GetTextContentOffset(Position(foo_node, 3)));
  EXPECT_EQ(3u, *GetTextContentOffset(Position(bar_node, 0)));
  EXPECT_EQ(4u, *GetTextContentOffset(Position(bar_node, 1)));
  EXPECT_EQ(5u, *GetTextContentOffset(Position(bar_node, 2)));
  EXPECT_EQ(6u, *GetTextContentOffset(Position(bar_node, 3)));

  EXPECT_EQ(Position(foo_node, 3), GetFirstPosition(3));
  EXPECT_EQ(Position(bar_node, 0), GetLastPosition(3));

  EXPECT_TRUE(IsBeforeNonCollapsedContent(Position(foo_node, 0)));
  EXPECT_TRUE(IsBeforeNonCollapsedContent(Position(foo_node, 1)));
  EXPECT_TRUE(IsBeforeNonCollapsedContent(Position(foo_node, 2)));
  EXPECT_FALSE(
      IsBeforeNonCollapsedContent(Position(foo_node, 3)));  // false at node end

  EXPECT_TRUE(IsBeforeNonCollapsedContent(Position(bar_node, 0)));
  EXPECT_TRUE(IsBeforeNonCollapsedContent(Position(bar_node, 1)));
  EXPECT_TRUE(IsBeforeNonCollapsedContent(Position(bar_node, 2)));
  EXPECT_FALSE(
      IsBeforeNonCollapsedContent(Position(bar_node, 3)));  // false at node end

  // false at node start
  EXPECT_FALSE(IsAfterNonCollapsedContent(Position(foo_node, 0)));
  EXPECT_TRUE(IsAfterNonCollapsedContent(Position(foo_node, 1)));
  EXPECT_TRUE(IsAfterNonCollapsedContent(Position(foo_node, 2)));
  EXPECT_TRUE(IsAfterNonCollapsedContent(Position(foo_node, 3)));

  // false at node start
  EXPECT_FALSE(IsAfterNonCollapsedContent(Position(bar_node, 0)));
  EXPECT_TRUE(IsAfterNonCollapsedContent(Position(bar_node, 1)));
  EXPECT_TRUE(IsAfterNonCollapsedContent(Position(bar_node, 2)));
  EXPECT_TRUE(IsAfterNonCollapsedContent(Position(bar_node, 3)));
}

TEST_F(OffsetMappingTest, BRBetweenTextNodes) {
  SetupHtml("t", u"<div id=t>foo<br>bar</div>");
  const auto* foo = To<LayoutText>(layout_object_.Get());
  const auto* br = To<LayoutText>(foo->NextSibling());
  const auto* bar = To<LayoutText>(br->NextSibling());
  const Node* foo_node = foo->GetNode();
  const Node* br_node = br->GetNode();
  const Node* bar_node = bar->GetNode();
  const OffsetMapping& result = GetOffsetMapping();

  EXPECT_EQ("foo\nbar", result.GetText());

  ASSERT_EQ(3u, result.GetUnits().size());
  TEST_UNIT(result.GetUnits()[0], OffsetMappingUnitType::kIdentity, foo_node,
            0u, 3u, 0u, 3u);
  TEST_UNIT(result.GetUnits()[1], OffsetMappingUnitType::kIdentity, br_node, 0u,
            1u, 3u, 4u);
  TEST_UNIT(result.GetUnits()[2], OffsetMappingUnitType::kIdentity, bar_node,
            0u, 3u, 4u, 7u);

  ASSERT_EQ(3u, result.GetRanges().size());
  TEST_RANGE(result.GetRanges(), foo_node, 0u, 1u);
  TEST_RANGE(result.GetRanges(), br_node, 1u, 2u);
  TEST_RANGE(result.GetRanges(), bar_node, 2u, 3u);

  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 0)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 1)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 2)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 3)));
  EXPECT_EQ(&result.GetUnits()[1],
            GetUnitForPosition(Position::BeforeNode(*br_node)));
  EXPECT_EQ(&result.GetUnits()[1],
            GetUnitForPosition(Position::AfterNode(*br_node)));
  EXPECT_EQ(&result.GetUnits()[2], GetUnitForPosition(Position(bar_node, 0)));
  EXPECT_EQ(&result.GetUnits()[2], GetUnitForPosition(Position(bar_node, 1)));
  EXPECT_EQ(&result.GetUnits()[2], GetUnitForPosition(Position(bar_node, 2)));
  EXPECT_EQ(&result.GetUnits()[2], GetUnitForPosition(Position(bar_node, 3)));

  EXPECT_EQ(0u, *GetTextContentOffset(Position(foo_node, 0)));
  EXPECT_EQ(1u, *GetTextContentOffset(Position(foo_node, 1)));
  EXPECT_EQ(2u, *GetTextContentOffset(Position(foo_node, 2)));
  EXPECT_EQ(3u, *GetTextContentOffset(Position(foo_node, 3)));
  EXPECT_EQ(3u, *GetTextContentOffset(Position::BeforeNode(*br_node)));
  EXPECT_EQ(4u, *GetTextContentOffset(Position::AfterNode(*br_node)));
  EXPECT_EQ(4u, *GetTextContentOffset(Position(bar_node, 0)));
  EXPECT_EQ(5u, *GetTextContentOffset(Position(bar_node, 1)));
  EXPECT_EQ(6u, *GetTextContentOffset(Position(bar_node, 2)));
  EXPECT_EQ(7u, *GetTextContentOffset(Position(bar_node, 3)));

  EXPECT_EQ(Position(foo_node, 3), GetFirstPosition(3));
  EXPECT_EQ(Position::BeforeNode(*br_node), GetLastPosition(3));
  EXPECT_EQ(Position::AfterNode(*br_node), GetFirstPosition(4));
  EXPECT_EQ(Position(bar_node, 0), GetLastPosition(4));
}

TEST_F(OffsetMappingTest, OneTextNodeWithCollapsedSpace) {
  SetupHtml("t", "<div id=t>foo  bar</div>");
  const Node* node = layout_object_->GetNode();
  const OffsetMapping& result = GetOffsetMapping();

  EXPECT_EQ("foo bar", result.GetText());

  ASSERT_EQ(3u, result.GetUnits().size());
  TEST_UNIT(result.GetUnits()[0], OffsetMappingUnitType::kIdentity, node, 0u,
            4u, 0u, 4u);
  TEST_UNIT(result.GetUnits()[1], OffsetMappingUnitType::kCollapsed, node, 4u,
            5u, 4u, 4u);
  TEST_UNIT(result.GetUnits()[2], OffsetMappingUnitType::kIdentity, node, 5u,
            8u, 4u, 7u);

  ASSERT_EQ(1u, result.GetRanges().size());
  TEST_RANGE(result.GetRanges(), node, 0u, 3u);

  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(node, 0)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(node, 1)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(node, 2)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(node, 3)));
  EXPECT_EQ(&result.GetUnits()[1], GetUnitForPosition(Position(node, 4)));
  EXPECT_EQ(&result.GetUnits()[2], GetUnitForPosition(Position(node, 5)));
  EXPECT_EQ(&result.GetUnits()[2], GetUnitForPosition(Position(node, 6)));
  EXPECT_EQ(&result.GetUnits()[2], GetUnitForPosition(Position(node, 7)));
  EXPECT_EQ(&result.GetUnits()[2], GetUnitForPosition(Position(node, 8)));

  EXPECT_EQ(0u, *GetTextContentOffset(Position(node, 0)));
  EXPECT_EQ(1u, *GetTextContentOffset(Position(node, 1)));
  EXPECT_EQ(2u, *GetTextContentOffset(Position(node, 2)));
  EXPECT_EQ(3u, *GetTextContentOffset(Position(node, 3)));
  EXPECT_EQ(4u, *GetTextContentOffset(Position(node, 4)));
  EXPECT_EQ(4u, *GetTextContentOffset(Position(node, 5)));
  EXPECT_EQ(5u, *GetTextContentOffset(Position(node, 6)));
  EXPECT_EQ(6u, *GetTextContentOffset(Position(node, 7)));
  EXPECT_EQ(7u, *GetTextContentOffset(Position(node, 8)));

  EXPECT_EQ(Position(node, 4), GetFirstPosition(4));
  EXPECT_EQ(Position(node, 5), GetLastPosition(4));

  EXPECT_EQ(Position(node, 3),
            StartOfNextNonCollapsedContent(Position(node, 3)));
  EXPECT_EQ(Position(node, 5),
            StartOfNextNonCollapsedContent(Position(node, 4)));
  EXPECT_EQ(Position(node, 5),
            StartOfNextNonCollapsedContent(Position(node, 5)));

  EXPECT_EQ(Position(node, 3), EndOfLastNonCollapsedContent(Position(node, 3)));
  EXPECT_EQ(Position(node, 4), EndOfLastNonCollapsedContent(Position(node, 4)));
  EXPECT_EQ(Position(node, 4), EndOfLastNonCollapsedContent(Position(node, 5)));

  EXPECT_TRUE(IsBeforeNonCollapsedContent(Position(node, 0)));
  EXPECT_TRUE(IsBeforeNonCollapsedContent(Position(node, 1)));
  EXPECT_TRUE(IsBeforeNonCollapsedContent(Position(node, 2)));
  EXPECT_TRUE(IsBeforeNonCollapsedContent(Position(node, 3)));
  EXPECT_FALSE(IsBeforeNonCollapsedContent(Position(node, 4)));
  EXPECT_TRUE(IsBeforeNonCollapsedContent(Position(node, 5)));
  EXPECT_TRUE(IsBeforeNonCollapsedContent(Position(node, 6)));
  EXPECT_TRUE(IsBeforeNonCollapsedContent(Position(node, 7)));
  EXPECT_FALSE(IsBeforeNonCollapsedContent(Position(node, 8)));

  EXPECT_FALSE(IsAfterNonCollapsedContent(Position(node, 0)));
  EXPECT_TRUE(IsAfterNonCollapsedContent(Position(node, 1)));
  EXPECT_TRUE(IsAfterNonCollapsedContent(Position(node, 2)));
  EXPECT_TRUE(IsAfterNonCollapsedContent(Position(node, 3)));
  EXPECT_TRUE(IsAfterNonCollapsedContent(Position(node, 4)));
  EXPECT_FALSE(IsAfterNonCollapsedContent(Position(node, 5)));
  EXPECT_TRUE(IsAfterNonCollapsedContent(Position(node, 6)));
  EXPECT_TRUE(IsAfterNonCollapsedContent(Position(node, 7)));
  EXPECT_TRUE(IsAfterNonCollapsedContent(Position(node, 8)));
}

TEST_F(OffsetMappingTest, FullyCollapsedWhiteSpaceNode) {
  SetupHtml("t",
            "<div id=t>"
            "<span id=s1>foo </span>"
            " "
            "<span id=s2>bar</span>"
            "</div>");
  const auto* foo = GetLayoutTextUnder("s1");
  const auto* bar = GetLayoutTextUnder("s2");
  const auto* space = To<LayoutText>(layout_object_->NextSibling());
  const Node* foo_node = foo->GetNode();
  const Node* bar_node = bar->GetNode();
  const Node* space_node = space->GetNode();
  const OffsetMapping& result = GetOffsetMapping();

  EXPECT_EQ("foo bar", result.GetText());

  ASSERT_EQ(3u, result.GetUnits().size());
  TEST_UNIT(result.GetUnits()[0], OffsetMappingUnitType::kIdentity, foo_node,
            0u, 4u, 0u, 4u);
  TEST_UNIT(result.GetUnits()[1], OffsetMappingUnitType::kCollapsed, space_node,
            0u, 1u, 4u, 4u);
  TEST_UNIT(result.GetUnits()[2], OffsetMappingUnitType::kIdentity, bar_node,
            0u, 3u, 4u, 7u);

  ASSERT_EQ(3u, result.GetRanges().size());
  TEST_RANGE(result.GetRanges(), foo_node, 0u, 1u);
  TEST_RANGE(result.GetRanges(), space_node, 1u, 2u);
  TEST_RANGE(result.GetRanges(), bar_node, 2u, 3u);

  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 0)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 1)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 2)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 3)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 4)));
  EXPECT_EQ(&result.GetUnits()[1], GetUnitForPosition(Position(space_node, 0)));
  EXPECT_EQ(&result.GetUnits()[1], GetUnitForPosition(Position(space_node, 1)));
  EXPECT_EQ(&result.GetUnits()[2], GetUnitForPosition(Position(bar_node, 0)));
  EXPECT_EQ(&result.GetUnits()[2], GetUnitForPosition(Position(bar_node, 1)));
  EXPECT_EQ(&result.GetUnits()[2], GetUnitForPosition(Position(bar_node, 2)));
  EXPECT_EQ(&result.GetUnits()[2], GetUnitForPosition(Position(bar_node, 3)));

  EXPECT_EQ(0u, *GetTextContentOffset(Position(foo_node, 0)));
  EXPECT_EQ(1u, *GetTextContentOffset(Position(foo_node, 1)));
  EXPECT_EQ(2u, *GetTextContentOffset(Position(foo_node, 2)));
  EXPECT_EQ(3u, *GetTextContentOffset(Position(foo_node, 3)));
  EXPECT_EQ(4u, *GetTextContentOffset(Position(foo_node, 4)));
  EXPECT_EQ(4u, *GetTextContentOffset(Position(space_node, 0)));
  EXPECT_EQ(4u, *GetTextContentOffset(Position(space_node, 1)));
  EXPECT_EQ(4u, *GetTextContentOffset(Position(bar_node, 0)));
  EXPECT_EQ(5u, *GetTextContentOffset(Position(bar_node, 1)));
  EXPECT_EQ(6u, *GetTextContentOffset(Position(bar_node, 2)));
  EXPECT_EQ(7u, *GetTextContentOffset(Position(bar_node, 3)));

  EXPECT_EQ(Position(foo_node, 4), GetFirstPosition(4));
  EXPECT_EQ(Position(bar_node, 0), GetLastPosition(4));

  EXPECT_TRUE(EndOfLastNonCollapsed
"""


```