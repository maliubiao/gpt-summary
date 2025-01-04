Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Understanding the Goal:**

The request asks for the functionalities of `inline_items_builder_test.cc`, its relation to web technologies, logical reasoning examples, and common usage errors (though this is a test file, so the focus shifts to testing edge cases).

**2. Initial Skim and Keyword Recognition:**

A quick glance reveals keywords like `TEST_F`, `EXPECT_EQ`, `InlineItemsBuilder`, `LayoutText`, `LayoutBlockFlow`, `ComputedStyle`, `EWhiteSpace`, "ruby", "bidi". These immediately suggest the file is about testing the `InlineItemsBuilder` class, likely in the context of layout and text rendering. The presence of "whitespace", "ruby", and "bidi" hints at specific areas being tested.

**3. Identifying Core Functionality (The `InlineItemsBuilder`):**

The filename and prominent class name (`InlineItemsBuilder`) are the primary clues. The test setup (`SetUp` method) creating `InlineItemsBuilder`, `LayoutBlockFlow`, and `HeapVector<InlineItem>` reinforces that this class is central. The methods `AppendText`, `AppendAtomicInline`, `AppendBlockInInline`, and `ExitBlock` within the test fixture directly correspond to operations performed by the `InlineItemsBuilder`. The `ToString()` method strongly suggests the builder constructs some kind of string representation of inline content.

**4. Connecting to Web Technologies (HTML, CSS, JavaScript):**

* **HTML:** The concepts of "inline" elements (like `<span>`, `<a>`), replaced elements (`<img>`, `<video>`), and block-level elements within inline context directly map to the methods being tested. The "ruby" tests point to the `<ruby>` HTML element.
* **CSS:** The tests heavily rely on `EWhiteSpace` (CSS `white-space` property). The "bidi" tests relate to CSS properties like `unicode-bidi` and `direction`. The setup uses `ComputedStyle`, a direct representation of CSS styles.
* **JavaScript:** While this C++ code doesn't directly interact with JavaScript *here*, the functionality it tests is crucial for how the browser renders web pages, including dynamic content manipulated by JavaScript. For instance, JavaScript might change the text content of an inline element, and this test file verifies the layout engine handles that correctly.

**5. Analyzing Specific Test Cases (Logical Reasoning Examples):**

This involves looking at individual `TEST_F` functions:

* **Whitespace Collapse:** Tests various `white-space` CSS property values (`normal`, `nowrap`, `pre`, `pre-wrap`, `pre-line`) and how different whitespace sequences (spaces, tabs, newlines) are handled. The assumptions are the input strings and the expected output after whitespace collapsing.
* **Bidi Tests:**  These tests focus on bidirectional text rendering. They manipulate `unicode-bidi` and `direction` properties, testing the insertion of Unicode control characters to ensure correct text ordering. The assumptions involve how these control characters should be inserted based on the CSS properties.
* **Ruby Tests:**  These test the handling of `<ruby>` elements, including the creation of "ruby columns" and placeholders for annotation. The assumptions involve the internal structure the layout engine creates for ruby annotations.
* **Replaced Elements:** Tests how atomic inline elements (like images) are represented. The assumption is they are represented by a single placeholder character (`\uFFFC`).

**6. Identifying Potential Usage Errors (Though in a Test File Context):**

Since it's a test file, the "errors" are more about testing edge cases and ensuring robustness. Examples include:

* **Unexpected Whitespace:**  The whitespace collapse tests highlight how developers might misunderstand how different `white-space` values affect rendering.
* **Incorrect Bidi Handling:**  The bidi tests implicitly show the complexity of handling right-to-left and left-to-right text mixing. Incorrect CSS can lead to garbled text.
* **Ruby Element Structure:** The ruby tests implicitly ensure the layout engine handles nested ruby elements and orphaned `<rt>` tags correctly. Incorrect HTML structure for ruby annotations could lead to unexpected layout.

**7. Structuring the Output:**

Organize the findings into categories as requested:

* **Functionality:** Describe the main purpose of the file and the `InlineItemsBuilder` class.
* **Relationship to Web Technologies:** Explicitly link the test cases to HTML, CSS, and explain the indirect relationship to JavaScript.
* **Logical Reasoning Examples:**  Select a few representative test cases (like whitespace collapsing or bidi) and demonstrate the "input -> operation -> output" logic.
* **Common Usage Errors:**  Frame these as potential developer misunderstandings or edge cases being tested, referencing the relevant test categories.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus solely on the C++ code.
* **Correction:** Realize the context is crucial – it's about rendering web pages, so connecting to HTML, CSS, and JavaScript is essential.
* **Initial thought:** Describe every single test case in detail.
* **Correction:**  Focus on representative examples for logical reasoning to avoid being too verbose. Group similar tests (like all the whitespace tests).
* **Initial thought:**  Strictly interpret "usage errors" as programming errors in the C++ code.
* **Correction:**  Broaden the interpretation to include common mistakes developers make when using the web technologies that this C++ code supports.

By following this iterative process of understanding the code, connecting it to the bigger picture, and providing concrete examples, we can arrive at a comprehensive and accurate analysis of the test file.
这个C++文件 `inline_items_builder_test.cc` 是 Chromium Blink 渲染引擎的一部分，专门用于测试 `InlineItemsBuilder` 类的功能。 `InlineItemsBuilder` 的主要职责是在布局过程中构建表示内联内容的 `InlineItem` 对象的列表。这些 `InlineItem` 描述了内联元素（例如文本、原子内联元素）以及它们之间的空白处理、双向文本 (BiDi) 控制等。

**功能概括:**

该测试文件主要验证 `InlineItemsBuilder` 类在各种场景下是否能正确地将内联内容转换为 `InlineItem` 列表，并验证其对空白符的处理、BiDi 控制字符的插入以及对特定 HTML 元素（如 `<ruby>`）的处理是否符合预期。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`InlineItemsBuilder` 的工作直接关系到浏览器如何渲染 HTML、应用 CSS 样式，并间接地影响 JavaScript 操作 DOM 后的渲染结果。

1. **HTML:**
   - **内联元素:** 测试用例中通过 `AppendText` 添加文本，这对应于 HTML 中的文本节点或者包含在内联元素（如 `<span>`, `<a>`）中的文本。例如，HTML `<span>hello</span>` 中的 "hello" 字符串会被 `AppendText` 处理。
   - **原子内联元素:** `AppendAtomicInline` 用于模拟像 `<img>`, `<video>` 这样的替换元素。在 HTML 中，`<img src="...">` 这样一个元素会被 `AppendAtomicInline` 处理，并生成一个特殊的 `InlineItem`。
   - **块级内联元素:** `AppendBlockInInline` 用于处理 display 属性为 `inline-block` 或 flex/grid 子项等，在内联格式化上下文中呈现为块级的元素。
   - **Ruby 元素:** 测试用例中有专门针对 `<ruby>` 标签的处理，验证 `InlineItemsBuilder` 能否正确地为 ruby 注释（`<rt>`）生成相应的 `InlineItem`，例如 `<ruby>汉<rt>han</rt></ruby>`。

2. **CSS:**
   - **空白符处理 (`white-space` 属性):**  大量的测试用例使用 `SetWhiteSpace` 来设置不同的 `white-space` CSS 属性值（例如 `normal`, `nowrap`, `pre`, `pre-wrap`, `pre-line`），并验证在这些属性下，`InlineItemsBuilder` 是否正确地折叠、保留或转换空白符（空格、制表符、换行符）。
      - 例如，当 `white-space: normal` 时，连续的空格会被折叠成一个，行首和行尾的空格会被移除。测试用例 `TEST_F(InlineItemsBuilderTest, CollapseSpaces)` 就是验证这种情况。
   - **双向文本 (`unicode-bidi`, `direction` 属性):** 测试用例 `TEST_F(InlineItemsBuilderTest, BidiBlockOverride)` 和 `TEST_F(InlineItemsBuilderTest, BidiIsolate)` 模拟了设置 `unicode-bidi` 和 `direction` 属性的情况，验证 `InlineItemsBuilder` 是否正确地插入 BiDi 控制字符（如 `U+202E` (RIGHT-TO-LEFT OVERRIDE), `U+2067` (FIRST STRONG ISOLATE) 等），以确保阿拉伯语或希伯来语等 RTL 文本与英语等 LTR 文本正确混合显示。
   - **`display: ruby` 和 `display: ruby-text`:**  测试用例 `TEST_F(InlineItemsBuilderTest, OpenCloseRubyColumns)` 验证了当元素的 CSS `display` 属性为 `ruby` 或 `ruby-text` 时，`InlineItemsBuilder` 如何生成特定的 `InlineItem` 来表示 ruby 注释的开始和结束。

3. **JavaScript:**
   - 虽然这个 C++ 文件本身不涉及 JavaScript 代码，但 `InlineItemsBuilder` 生成的 `InlineItem` 列表是渲染过程中的关键数据结构。当 JavaScript 通过 DOM API 修改 HTML 结构或 CSS 样式时，渲染引擎会重新运行布局过程，其中包括 `InlineItemsBuilder` 的工作。例如，如果 JavaScript 动态地向一个 `<span>` 标签添加文本，`InlineItemsBuilder` 会相应地生成新的 `InlineItem`。

**逻辑推理及假设输入与输出:**

以 `TEST_F(InlineItemsBuilderTest, CollapseSpaces)` 为例：

- **假设输入:** 字符串 "text text  text   text"，CSS 属性 `white-space: normal`。
- **逻辑推理:** 当 `white-space` 为 `normal` 时，连续的空格应该被折叠成一个。
- **预期输出:**  `InlineItemsBuilder` 生成的 `InlineItem` 列表所表示的最终文本内容应该是 "text text text text"。

以 `TEST_F(InlineItemsBuilderTest, BidiIsolate)` 为例：

- **假设输入:** 字符串 "Hello "，一个包含希伯来语 "עברית" 的内联元素，字符串 " World"，并且希伯来语元素的 CSS 属性为 `unicode-bidi: isolate; direction: rtl;`。
- **逻辑推理:** 当 `unicode-bidi` 为 `isolate` 且 `direction` 为 `rtl` 时，应该在希伯来语文本前后插入 `U+2067` (FIRST STRONG ISOLATE) 和 `U+2069` (POP DIRECTIONAL ISOLATE) 控制字符。
- **预期输出:** `InlineItemsBuilder` 生成的文本内容应该是 "Hello ⁧עברית⁩ World"，其中 `⁧` 代表 `U+2067`，`⁩` 代表 `U+2069`。

**用户或编程常见的使用错误及举例说明:**

虽然 `inline_items_builder_test.cc` 是测试代码，它所测试的场景反映了开发者在使用 HTML 和 CSS 时可能遇到的问题：

1. **不理解 `white-space` 属性的影响:**
   - **错误示例:** 开发者期望在 HTML 中输入多个空格就能在页面上显示多个空格，但忘记设置 `white-space: pre` 或 `white-space: pre-wrap` 等属性。
   - **测试用例关联:** `TEST_F(InlineItemsBuilderTest, CollapseSpaces)` 等测试用例验证了默认情况下（`white-space: normal`）空格是如何被折叠的。

2. **BiDi 文本处理不当:**
   - **错误示例:** 在包含阿拉伯语和英语的文本中，没有正确设置 `unicode-bidi` 和 `direction` 属性，导致文本显示顺序混乱。
   - **测试用例关联:** `TEST_F(InlineItemsBuilderTest, BidiBlockOverride)` 和 `TEST_F(InlineItemsBuilderTest, BidiIsolate)` 等测试用例确保了 `InlineItemsBuilder` 能正确插入 BiDi 控制字符，这有助于开发者理解和正确处理 BiDi 文本。

3. **对行尾空白符的误解:**
   - **错误示例:** 开发者可能认为在内联元素末尾添加空格会一直保留，但默认情况下这些空格可能会被折叠。
   - **测试用例关联:** `TEST_F(InlineItemsBuilderTest, CollapseTrailingSpaces)` 验证了在 `white-space: normal` 等情况下，行尾的空格会被移除。

4. **Ruby 元素结构错误:**
   - **错误示例:** 开发者可能错误地使用了 `<ruby>` 和 `<rt>` 标签，例如 `<rt>` 标签不在 `<ruby>` 标签内部，导致渲染结果不符合预期。
   - **测试用例关联:** `TEST_F(InlineItemsBuilderTest, OpenCloseRubyColumns)` 验证了 `InlineItemsBuilder` 如何处理正确的和“孤立”的 `<rt>` 标签，这可以帮助开发者理解 `<ruby>` 结构的正确用法。

总而言之，`inline_items_builder_test.cc` 通过各种测试用例，细致地检验了 `InlineItemsBuilder` 类在处理各种内联内容和 CSS 样式时的正确性，这对于保证 Chromium 浏览器能准确渲染网页至关重要。这些测试用例也间接地反映了开发者在使用 HTML 和 CSS 时需要注意的一些关键点。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/inline_items_builder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/inline/inline_items_builder.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node_data.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {

// The spec turned into a discussion that may change. Put this logic on hold
// until CSSWG resolves the issue.
// https://github.com/w3c/csswg-drafts/issues/337
#define SEGMENT_BREAK_TRANSFORMATION_FOR_EAST_ASIAN_WIDTH 0

#define EXPECT_ITEM_OFFSET(item, type, start, end) \
  {                                                \
    const auto& item_ref = (item);                 \
    EXPECT_EQ(type, item_ref.Type());              \
    EXPECT_EQ(start, item_ref.StartOffset());      \
    EXPECT_EQ(end, item_ref.EndOffset());          \
  }

class InlineItemsBuilderTest : public RenderingTest {
 protected:
  void SetUp() override {
    RenderingTest::SetUp();
    style_ = &GetDocument().GetStyleResolver().InitialStyle();
    block_flow_ = LayoutBlockFlow::CreateAnonymous(&GetDocument(), style_);
    items_ = MakeGarbageCollected<HeapVector<InlineItem>>();
    anonymous_objects_ =
        MakeGarbageCollected<HeapVector<Member<LayoutObject>>>();
    anonymous_objects_->push_back(block_flow_);
  }

  void TearDown() override {
    for (LayoutObject* anonymous_object : *anonymous_objects_)
      anonymous_object->Destroy();
    RenderingTest::TearDown();
  }

  LayoutBlockFlow* GetLayoutBlockFlow() const { return block_flow_; }

  void SetWhiteSpace(EWhiteSpace whitespace) {
    ComputedStyleBuilder builder(*style_);
    builder.SetWhiteSpace(whitespace);
    style_ = builder.TakeStyle();
    block_flow_->SetStyle(style_, LayoutObject::ApplyStyleChanges::kNo);
  }

  const ComputedStyle* GetStyle(EWhiteSpace whitespace) {
    if (whitespace == EWhiteSpace::kNormal)
      return style_;
    ComputedStyleBuilder builder =
        GetDocument().GetStyleResolver().CreateComputedStyleBuilder();
    builder.SetWhiteSpace(whitespace);
    return builder.TakeStyle();
  }

  bool HasRuby(const InlineItemsBuilder& builder) const {
    return builder.has_ruby_;
  }

  void AppendText(const String& text, InlineItemsBuilder* builder) {
    LayoutText* layout_text =
        LayoutText::CreateEmptyAnonymous(GetDocument(), style_);
    anonymous_objects_->push_back(layout_text);
    builder->AppendText(text, layout_text);
  }

  void AppendAtomicInline(InlineItemsBuilder* builder) {
    LayoutBlockFlow* layout_block_flow =
        LayoutBlockFlow::CreateAnonymous(&GetDocument(), style_);
    anonymous_objects_->push_back(layout_block_flow);
    builder->AppendAtomicInline(layout_block_flow);
  }

  void AppendBlockInInline(InlineItemsBuilder* builder) {
    LayoutBlockFlow* layout_block_flow =
        LayoutBlockFlow::CreateAnonymous(&GetDocument(), style_);
    anonymous_objects_->push_back(layout_block_flow);
    builder->AppendBlockInInline(layout_block_flow);
  }

  struct Input {
    const String text;
    EWhiteSpace whitespace = EWhiteSpace::kNormal;
    Persistent<LayoutText> layout_text;
  };

  const String& TestAppend(Vector<Input> inputs) {
    items_->clear();
    HeapVector<Member<LayoutText>> anonymous_objects;
    InlineItemsBuilder builder(GetLayoutBlockFlow(), items_);
    for (Input& input : inputs) {
      if (!input.layout_text) {
        input.layout_text = LayoutText::CreateEmptyAnonymous(
            GetDocument(), GetStyle(input.whitespace));
        anonymous_objects.push_back(input.layout_text);
      }
      builder.AppendText(input.text, input.layout_text);
    }
    builder.ExitBlock();
    text_ = builder.ToString();
    ValidateItems();
    CheckReuseItemsProducesSameResult(inputs, builder.HasBidiControls());
    for (LayoutObject* anonymous_object : anonymous_objects)
      anonymous_object->Destroy();
    return text_;
  }

  const String& TestAppend(const String& input) {
    return TestAppend({Input{input}});
  }
  const String& TestAppend(const Input& input1, const Input& input2) {
    return TestAppend({input1, input2});
  }
  const String& TestAppend(const String& input1, const String& input2) {
    return TestAppend(Input{input1}, Input{input2});
  }
  const String& TestAppend(const String& input1,
                           const String& input2,
                           const String& input3) {
    return TestAppend({{input1}, {input2}, {input3}});
  }

  void ValidateItems() {
    unsigned current_offset = 0;
    for (unsigned i = 0; i < items_->size(); i++) {
      const InlineItem& item = items_->at(i);
      EXPECT_EQ(current_offset, item.StartOffset());
      EXPECT_LE(item.StartOffset(), item.EndOffset());
      current_offset = item.EndOffset();
    }
    EXPECT_EQ(current_offset, text_.length());
  }

  void CheckReuseItemsProducesSameResult(Vector<Input> inputs,
                                         bool has_bidi_controls) {
    InlineNodeData& fake_data = *MakeGarbageCollected<InlineNodeData>();
    fake_data.text_content = text_;
    fake_data.is_bidi_enabled_ = has_bidi_controls;

    HeapVector<InlineItem> reuse_items;
    InlineItemsBuilder reuse_builder(GetLayoutBlockFlow(), &reuse_items);
    InlineItemsData* data = MakeGarbageCollected<InlineItemsData>();
    data->items = *items_;
    for (Input& input : inputs) {
      // Collect items for this LayoutObject.
      DCHECK(input.layout_text);
      for (wtf_size_t i = 0; i != data->items.size();) {
        if (data->items[i].GetLayoutObject() == input.layout_text) {
          wtf_size_t begin = i;
          i++;
          while (i < data->items.size() &&
                 data->items[i].GetLayoutObject() == input.layout_text)
            i++;
          input.layout_text->SetInlineItems(data, begin, i - begin);
        } else {
          ++i;
        }
      }

      // Try to re-use previous items, or Append if it was not re-usable.
      bool reused =
          input.layout_text->HasValidInlineItems() &&
          reuse_builder.AppendTextReusing(fake_data, input.layout_text);
      if (!reused) {
        reuse_builder.AppendText(input.text, input.layout_text);
      }
    }

    reuse_builder.ExitBlock();
    String reuse_text = reuse_builder.ToString();
    EXPECT_EQ(text_, reuse_text);
  }

  Persistent<LayoutBlockFlow> block_flow_;
  Persistent<HeapVector<InlineItem>> items_;
  String text_;
  Persistent<const ComputedStyle> style_;
  Persistent<HeapVector<Member<LayoutObject>>> anonymous_objects_;
};

#define TestWhitespaceValue(expected_text, input, whitespace) \
  SetWhiteSpace(whitespace);                                  \
  EXPECT_EQ(expected_text, TestAppend(input)) << "white-space: " #whitespace;

TEST_F(InlineItemsBuilderTest, CollapseSpaces) {
  String input("text text  text   text");
  String collapsed("text text text text");
  TestWhitespaceValue(collapsed, input, EWhiteSpace::kNormal);
  TestWhitespaceValue(collapsed, input, EWhiteSpace::kNowrap);
  TestWhitespaceValue(collapsed, input, EWhiteSpace::kPreLine);
  TestWhitespaceValue(input, input, EWhiteSpace::kPre);
  TestWhitespaceValue(input, input, EWhiteSpace::kPreWrap);
}

TEST_F(InlineItemsBuilderTest, CollapseTabs) {
  String input("text text  text   text");
  String collapsed("text text text text");
  TestWhitespaceValue(collapsed, input, EWhiteSpace::kNormal);
  TestWhitespaceValue(collapsed, input, EWhiteSpace::kNowrap);
  TestWhitespaceValue(collapsed, input, EWhiteSpace::kPreLine);
  TestWhitespaceValue(input, input, EWhiteSpace::kPre);
  TestWhitespaceValue(input, input, EWhiteSpace::kPreWrap);
}

TEST_F(InlineItemsBuilderTest, CollapseNewLines) {
  String input("text\ntext \ntext\n\ntext");
  String collapsed("text text text text");
  TestWhitespaceValue(collapsed, input, EWhiteSpace::kNormal);
  TestWhitespaceValue(collapsed, input, EWhiteSpace::kNowrap);
  TestWhitespaceValue("text\ntext\ntext\n\ntext", input, EWhiteSpace::kPreLine);
  TestWhitespaceValue(input, input, EWhiteSpace::kPre);
  TestWhitespaceValue(input, input, EWhiteSpace::kPreWrap);
}

TEST_F(InlineItemsBuilderTest, CollapseNewlinesAsSpaces) {
  EXPECT_EQ("text text", TestAppend("text\ntext"));
  EXPECT_EQ("text text", TestAppend("text\n\ntext"));
  EXPECT_EQ("text text", TestAppend("text \n\n text"));
  EXPECT_EQ("text text", TestAppend("text \n \n text"));
}

TEST_F(InlineItemsBuilderTest, CollapseAcrossElements) {
  EXPECT_EQ("text text", TestAppend("text ", " text"))
      << "Spaces are collapsed even when across elements.";
}

TEST_F(InlineItemsBuilderTest, CollapseLeadingSpaces) {
  EXPECT_EQ("text", TestAppend("  text"));
  EXPECT_EQ("text", TestAppend(" ", "text"));
  EXPECT_EQ("text", TestAppend(" ", " text"));
}

TEST_F(InlineItemsBuilderTest, CollapseTrailingSpaces) {
  EXPECT_EQ("text", TestAppend("text  "));
  EXPECT_EQ("text", TestAppend("text", " "));
  EXPECT_EQ("text", TestAppend("text ", " "));
}

TEST_F(InlineItemsBuilderTest, CollapseAllSpaces) {
  EXPECT_EQ("", TestAppend("  "));
  EXPECT_EQ("", TestAppend("  ", "  "));
  EXPECT_EQ("", TestAppend("  ", "\n"));
  EXPECT_EQ("", TestAppend("\n", "  "));
}

TEST_F(InlineItemsBuilderTest, CollapseLeadingNewlines) {
  EXPECT_EQ("text", TestAppend("\ntext"));
  EXPECT_EQ("text", TestAppend("\n\ntext"));
  EXPECT_EQ("text", TestAppend("\n", "text"));
  EXPECT_EQ("text", TestAppend("\n\n", "text"));
  EXPECT_EQ("text", TestAppend(" \n", "text"));
  EXPECT_EQ("text", TestAppend("\n", " text"));
  EXPECT_EQ("text", TestAppend("\n\n", " text"));
  EXPECT_EQ("text", TestAppend(" \n", " text"));
  EXPECT_EQ("text", TestAppend("\n", "\ntext"));
  EXPECT_EQ("text", TestAppend("\n\n", "\ntext"));
  EXPECT_EQ("text", TestAppend(" \n", "\ntext"));
}

TEST_F(InlineItemsBuilderTest, CollapseTrailingNewlines) {
  EXPECT_EQ("text", TestAppend("text\n"));
  EXPECT_EQ("text", TestAppend("text", "\n"));
  EXPECT_EQ("text", TestAppend("text\n", "\n"));
  EXPECT_EQ("text", TestAppend("text\n", " "));
  EXPECT_EQ("text", TestAppend("text ", "\n"));
}

TEST_F(InlineItemsBuilderTest, CollapseNewlineAcrossElements) {
  EXPECT_EQ("text text", TestAppend("text ", "\ntext"));
  EXPECT_EQ("text text", TestAppend("text ", "\n text"));
  EXPECT_EQ("text text", TestAppend("text", " ", "\ntext"));
}

TEST_F(InlineItemsBuilderTest, CollapseBeforeAndAfterNewline) {
  SetWhiteSpace(EWhiteSpace::kPreLine);
  EXPECT_EQ("text\ntext", TestAppend("text  \n  text"))
      << "Spaces before and after newline are removed.";
}

TEST_F(InlineItemsBuilderTest,
       CollapsibleSpaceAfterNonCollapsibleSpaceAcrossElements) {
  EXPECT_EQ("text  text",
            TestAppend({"text ", EWhiteSpace::kPreWrap}, {" text"}))
      << "The whitespace in constructions like '<span style=\"white-space: "
         "pre-wrap\">text <span><span> text</span>' does not collapse.";
}

TEST_F(InlineItemsBuilderTest, CollapseZeroWidthSpaces) {
  EXPECT_EQ(String(u"text\u200Btext"), TestAppend(u"text\u200B\ntext"))
      << "Newline is removed if the character before is ZWS.";
  EXPECT_EQ(String(u"text\u200Btext"), TestAppend(u"text\n\u200Btext"))
      << "Newline is removed if the character after is ZWS.";
  EXPECT_EQ(String(u"text\u200B\u200Btext"),
            TestAppend(u"text\u200B\n\u200Btext"))
      << "Newline is removed if the character before/after is ZWS.";

  EXPECT_EQ(String(u"text\u200Btext"), TestAppend(u"text\n", u"\u200Btext"))
      << "Newline is removed if the character after across elements is ZWS.";
  EXPECT_EQ(String(u"text\u200Btext"), TestAppend(u"text\u200B", u"\ntext"))
      << "Newline is removed if the character before is ZWS even across "
         "elements.";

  EXPECT_EQ(String(u"text\u200Btext"), TestAppend(u"text \n", u"\u200Btext"))
      << "Collapsible space before newline does not affect the result.";
  EXPECT_EQ(String(u"text\u200B text"), TestAppend(u"text\u200B\n", u" text"))
      << "Collapsible space after newline is removed even when the "
         "newline was removed.";
  EXPECT_EQ(String(u"text\u200Btext"), TestAppend(u"text\u200B ", u"\ntext"))
      << "A white space sequence containing a segment break before or after "
         "a zero width space is collapsed to a zero width space.";
}

TEST_F(InlineItemsBuilderTest, CollapseZeroWidthSpaceAndNewLineAtEnd) {
  EXPECT_EQ(String(u"\u200B"), TestAppend(u"\u200B\n"));
  EXPECT_EQ(InlineItem::kNotCollapsible, items_->at(0).EndCollapseType());
}

#if SEGMENT_BREAK_TRANSFORMATION_FOR_EAST_ASIAN_WIDTH
TEST_F(InlineItemsBuilderTest, CollapseEastAsianWidth) {
  EXPECT_EQ(String(u"\u4E00\u4E00"), TestAppend(u"\u4E00\n\u4E00"))
      << "Newline is removed when both sides are Wide.";

  EXPECT_EQ(String(u"\u4E00 A"), TestAppend(u"\u4E00\nA"))
      << "Newline is not removed when after is Narrow.";
  EXPECT_EQ(String(u"A \u4E00"), TestAppend(u"A\n\u4E00"))
      << "Newline is not removed when before is Narrow.";

  EXPECT_EQ(String(u"\u4E00\u4E00"), TestAppend(u"\u4E00\n", u"\u4E00"))
      << "Newline at the end of elements is removed when both sides are Wide.";
  EXPECT_EQ(String(u"\u4E00\u4E00"), TestAppend(u"\u4E00", u"\n\u4E00"))
      << "Newline at the beginning of elements is removed "
         "when both sides are Wide.";
}
#endif

TEST_F(InlineItemsBuilderTest, OpaqueToSpaceCollapsing) {
  InlineItemsBuilder builder(GetLayoutBlockFlow(), items_);
  AppendText("Hello ", &builder);
  builder.AppendOpaque(InlineItem::kBidiControl, kFirstStrongIsolateCharacter);
  AppendText(" ", &builder);
  builder.AppendOpaque(InlineItem::kBidiControl, kFirstStrongIsolateCharacter);
  AppendText(" World", &builder);
  EXPECT_EQ(String(u"Hello \u2068\u2068World"), builder.ToString());
}

TEST_F(InlineItemsBuilderTest, CollapseAroundReplacedElement) {
  InlineItemsBuilder builder(GetLayoutBlockFlow(), items_);
  AppendText("Hello ", &builder);
  AppendAtomicInline(&builder);
  AppendText(" World", &builder);
  EXPECT_EQ(String(u"Hello \uFFFC World"), builder.ToString());
}

TEST_F(InlineItemsBuilderTest, CollapseNewlineAfterObject) {
  InlineItemsBuilder builder(GetLayoutBlockFlow(), items_);
  AppendAtomicInline(&builder);
  AppendText("\n", &builder);
  AppendAtomicInline(&builder);
  EXPECT_EQ(String(u"\uFFFC \uFFFC"), builder.ToString());
  EXPECT_EQ(3u, items_->size());
  EXPECT_ITEM_OFFSET(items_->at(0), InlineItem::kAtomicInline, 0u, 1u);
  EXPECT_ITEM_OFFSET(items_->at(1), InlineItem::kText, 1u, 2u);
  EXPECT_ITEM_OFFSET(items_->at(2), InlineItem::kAtomicInline, 2u, 3u);
}

TEST_F(InlineItemsBuilderTest, AppendEmptyString) {
  EXPECT_EQ("", TestAppend(""));
  EXPECT_EQ(1u, items_->size());
  EXPECT_ITEM_OFFSET(items_->at(0), InlineItem::kText, 0u, 0u);
}

TEST_F(InlineItemsBuilderTest, NewLines) {
  SetWhiteSpace(EWhiteSpace::kPre);
  EXPECT_EQ("apple\norange\ngrape\n", TestAppend("apple\norange\ngrape\n"));
  EXPECT_EQ(6u, items_->size());
  EXPECT_EQ(InlineItem::kText, items_->at(0).Type());
  EXPECT_EQ(InlineItem::kControl, items_->at(1).Type());
  EXPECT_EQ(InlineItem::kText, items_->at(2).Type());
  EXPECT_EQ(InlineItem::kControl, items_->at(3).Type());
  EXPECT_EQ(InlineItem::kText, items_->at(4).Type());
  EXPECT_EQ(InlineItem::kControl, items_->at(5).Type());
}

TEST_F(InlineItemsBuilderTest, IgnorablePre) {
  SetWhiteSpace(EWhiteSpace::kPre);
  EXPECT_EQ(
      "apple"
      "\x0c"
      "orange"
      "\n"
      "grape",
      TestAppend("apple"
                 "\x0c"
                 "orange"
                 "\n"
                 "grape"));
  EXPECT_EQ(5u, items_->size());
  EXPECT_ITEM_OFFSET(items_->at(0), InlineItem::kText, 0u, 5u);
  EXPECT_ITEM_OFFSET(items_->at(1), InlineItem::kControl, 5u, 6u);
  EXPECT_ITEM_OFFSET(items_->at(2), InlineItem::kText, 6u, 12u);
  EXPECT_ITEM_OFFSET(items_->at(3), InlineItem::kControl, 12u, 13u);
  EXPECT_ITEM_OFFSET(items_->at(4), InlineItem::kText, 13u, 18u);
}

TEST_F(InlineItemsBuilderTest, Empty) {
  HeapVector<InlineItem> items;
  InlineItemsBuilder builder(GetLayoutBlockFlow(), &items);
  const ComputedStyle* block_style =
      &GetDocument().GetStyleResolver().InitialStyle();
  builder.EnterBlock(block_style);
  builder.ExitBlock();

  EXPECT_EQ("", builder.ToString());
}

class CollapsibleSpaceTest : public InlineItemsBuilderTest,
                             public testing::WithParamInterface<UChar> {};

INSTANTIATE_TEST_SUITE_P(InlineItemsBuilderTest,
                         CollapsibleSpaceTest,
                         testing::Values(kSpaceCharacter,
                                         kTabulationCharacter,
                                         kNewlineCharacter));

TEST_P(CollapsibleSpaceTest, CollapsedSpaceAfterNoWrap) {
  UChar space = GetParam();
  EXPECT_EQ(
      String("nowrap "
             u"\u200B"
             "wrap"),
      TestAppend({String("nowrap") + space, EWhiteSpace::kNowrap}, {" wrap"}));
}

TEST_F(InlineItemsBuilderTest, GenerateBreakOpportunityAfterLeadingSpaces) {
  EXPECT_EQ(String(" "
                   u"\u200B"
                   "a"),
            TestAppend({{" a", EWhiteSpace::kPreWrap}}));
  EXPECT_EQ(String("  "
                   u"\u200B"
                   "a"),
            TestAppend({{"  a", EWhiteSpace::kPreWrap}}));
  EXPECT_EQ(String("a\n"
                   u" \u200B"),
            TestAppend({{"a\n ", EWhiteSpace::kPreWrap}}));
}

TEST_F(InlineItemsBuilderTest, BidiBlockOverride) {
  HeapVector<InlineItem> items;
  InlineItemsBuilder builder(GetLayoutBlockFlow(), &items);
  ComputedStyleBuilder block_style_builder(
      GetDocument().GetStyleResolver().InitialStyle());
  block_style_builder.SetUnicodeBidi(UnicodeBidi::kBidiOverride);
  block_style_builder.SetDirection(TextDirection::kRtl);
  const ComputedStyle* block_style = block_style_builder.TakeStyle();
  builder.EnterBlock(block_style);
  AppendText("Hello", &builder);
  builder.ExitBlock();

  // Expected control characters as defined in:
  // https://drafts.csswg.org/css-writing-modes-3/#bidi-control-codes-injection-table
  EXPECT_EQ(String(u"\u202E"
                   u"Hello"
                   u"\u202C"),
            builder.ToString());
}

static LayoutInline* CreateLayoutInline(
    Document* document,
    void (*initialize_style)(ComputedStyleBuilder&)) {
  ComputedStyleBuilder builder =
      document->GetStyleResolver().CreateComputedStyleBuilder();
  initialize_style(builder);
  LayoutInline* const node = LayoutInline::CreateAnonymous(document);
  node->SetStyle(builder.TakeStyle(), LayoutObject::ApplyStyleChanges::kNo);
  node->SetIsInLayoutNGInlineFormattingContext(true);
  return node;
}

TEST_F(InlineItemsBuilderTest, BidiIsolate) {
  HeapVector<InlineItem> items;
  InlineItemsBuilder builder(GetLayoutBlockFlow(), &items);
  AppendText("Hello ", &builder);
  LayoutInline* const isolate_rtl =
      CreateLayoutInline(&GetDocument(), [](ComputedStyleBuilder& builder) {
        builder.SetUnicodeBidi(UnicodeBidi::kIsolate);
        builder.SetDirection(TextDirection::kRtl);
      });
  builder.EnterInline(isolate_rtl);
  AppendText(u"\u05E2\u05D1\u05E8\u05D9\u05EA", &builder);
  builder.ExitInline(isolate_rtl);
  AppendText(" World", &builder);

  // Expected control characters as defined in:
  // https://drafts.csswg.org/css-writing-modes-3/#bidi-control-codes-injection-table
  EXPECT_EQ(String(u"Hello "
                   u"\u2067"
                   u"\u05E2\u05D1\u05E8\u05D9\u05EA"
                   u"\u2069"
                   u" World"),
            builder.ToString());
  isolate_rtl->Destroy();
}

TEST_F(InlineItemsBuilderTest, BidiIsolateOverride) {
  HeapVector<InlineItem> items;
  InlineItemsBuilder builder(GetLayoutBlockFlow(), &items);
  AppendText("Hello ", &builder);
  LayoutInline* const isolate_override_rtl =
      CreateLayoutInline(&GetDocument(), [](ComputedStyleBuilder& builder) {
        builder.SetUnicodeBidi(UnicodeBidi::kIsolateOverride);
        builder.SetDirection(TextDirection::kRtl);
      });
  builder.EnterInline(isolate_override_rtl);
  AppendText(u"\u05E2\u05D1\u05E8\u05D9\u05EA", &builder);
  builder.ExitInline(isolate_override_rtl);
  AppendText(" World", &builder);

  // Expected control characters as defined in:
  // https://drafts.csswg.org/css-writing-modes-3/#bidi-control-codes-injection-table
  EXPECT_EQ(String(u"Hello "
                   u"\u2068\u202E"
                   u"\u05E2\u05D1\u05E8\u05D9\u05EA"
                   u"\u202C\u2069"
                   u" World"),
            builder.ToString());
  isolate_override_rtl->Destroy();
}

TEST_F(InlineItemsBuilderTest, BlockInInline) {
  HeapVector<InlineItem> items;
  InlineItemsBuilder builder(GetLayoutBlockFlow(), &items);
  AppendText("Hello ", &builder);
  AppendBlockInInline(&builder);
  AppendText(" World", &builder);
  // Collapsible spaces before and after block-in-inline should be collapsed.
  EXPECT_EQ(String(u"Hello\uFFFCWorld"), builder.ToString());
}

TEST_F(InlineItemsBuilderTest, OpenCloseRubyColumns) {
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  LayoutInline* ruby =
      CreateLayoutInline(&GetDocument(), [](ComputedStyleBuilder& builder) {
        builder.SetDisplay(EDisplay::kRuby);
      });
  LayoutInline* rt =
      CreateLayoutInline(&GetDocument(), [](ComputedStyleBuilder& builder) {
        builder.SetDisplay(EDisplay::kRubyText);
      });
  ruby->AddChild(rt);
  GetLayoutBlockFlow()->AddChild(ruby);
  LayoutInline* orphan_rt =
      CreateLayoutInline(&GetDocument(), [](ComputedStyleBuilder& builder) {
        builder.SetDisplay(EDisplay::kRubyText);
      });
  GetLayoutBlockFlow()->AddChild(orphan_rt);
  HeapVector<InlineItem> items;
  InlineItemsBuilder builder(GetLayoutBlockFlow(), &items);

  // Input: <ruby>base1<rt>anno1</rt>base2<rt>anno2</ruby><rt>anno3</rt>.
  builder.EnterInline(ruby);
  AppendText("base1", &builder);
  builder.EnterInline(rt);
  AppendText("anno1", &builder);
  builder.ExitInline(rt);
  AppendText("base2", &builder);
  builder.EnterInline(rt);
  AppendText("anno2", &builder);
  builder.ExitInline(rt);
  builder.ExitInline(ruby);
  builder.EnterInline(orphan_rt);
  AppendText("anno3", &builder);
  builder.ExitInline(orphan_rt);

  auto* node_data = MakeGarbageCollected<InlineNodeData>();
  builder.DidFinishCollectInlines(node_data);
  EXPECT_TRUE(node_data->HasRuby());

  wtf_size_t i = 0;
  EXPECT_ITEM_OFFSET(items[i], InlineItem::kOpenTag, 0u, 0u);  // <ruby>
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kOpenRubyColumn, 0u, 1u);
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kRubyLinePlaceholder, 1u, 1u);
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kText, 1u, 6u);  // "base1"
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kRubyLinePlaceholder, 6u, 6u);
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kOpenTag, 6u, 6u);  // <rt>
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kRubyLinePlaceholder, 6u, 6u);
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kText, 6u, 11u);  // "anno1"
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kRubyLinePlaceholder, 11u, 11u);
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kCloseTag, 11u, 11u);  // </rt>
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kCloseRubyColumn, 11u, 12u);
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kOpenRubyColumn, 12u, 13u);
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kRubyLinePlaceholder, 13u, 13u);
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kText, 13u, 18u);  // "base2"
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kRubyLinePlaceholder, 18u, 18u);
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kOpenTag, 18u, 18u);  // <rt>
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kRubyLinePlaceholder, 18u, 18u);
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kText, 18u, 23u);  // "anno2"
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kRubyLinePlaceholder, 23u, 23u);
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kCloseTag, 23u, 23u);  // </rt>
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kCloseRubyColumn, 23u, 24u);
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kCloseTag, 24u, 24u);  // </ruby>

  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kOpenRubyColumn, 24u, 25u);
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kRubyLinePlaceholder, 25u, 25u);
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kOpenTag, 25u, 25u);  // <rt>
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kRubyLinePlaceholder, 25u, 25u);
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kText, 25u, 30u);  // "anno3"
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kRubyLinePlaceholder, 30u, 30u);
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kCloseTag, 30u, 30u);  // </rt>
  EXPECT_ITEM_OFFSET(items[++i], InlineItem::kCloseRubyColumn, 30u, 31u);

  orphan_rt->Destroy();
  rt->Destroy();
  ruby->Destroy();
}

}  // namespace blink

"""

```