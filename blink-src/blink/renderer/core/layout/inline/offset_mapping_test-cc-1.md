Response:
The user wants a summary of the functionality of the `offset_mapping_test.cc` file based on the provided code snippet. I need to analyze the code and identify the main features being tested.

The code snippet consists of a series of test cases within the `OffsetMappingTest` class. These test cases cover various scenarios related to how the offset mapping is generated and how it handles different DOM structures and CSS properties.

Here's a breakdown of the test cases and their apparent focus:

- **SpaceNode**: Tests the handling of space nodes.
- **ReplacedElement**: Tests how replaced elements (like `<img>`) are handled in the offset mapping.
- **FirstLetter**: Tests the impact of the `:first-letter` pseudo-class on offset mapping.
- **FirstLetterWithLeadingSpace**: Similar to `FirstLetter` but with leading spaces.
- **FirstLetterWithoutRemainingText**: Tests `:first-letter` when there's only the first letter and no remaining text.
- **FirstLetterInDifferentBlock**: Tests `:first-letter` when it's rendered in a different block.
- **WhiteSpaceTextNodeWithoutLayoutText**: Tests the handling of whitespace text nodes.
- **ContainerWithGeneratedContent**: Tests offset mapping when using `::before` and `::after` pseudo-elements.
- **ContainerWithGeneratedContentWithCollapsedWhitespace**: Tests generated content with collapsed whitespace.
- **Table**: Tests offset mapping within a table.
- **GetMappingForInlineBlock**: Tests retrieving the offset mapping for inline-block elements.
- **NoWrapSpaceAndCollapsibleSpace**: Tests the interaction of `white-space: nowrap` and collapsible spaces.
- **PreLine**: Tests offset mapping with `white-space: pre-line`.
- **BiDiAroundForcedBreakInPreLine/PreWrap/Pre**: Tests how BiDi (bidirectional) text and forced line breaks are handled in different `white-space` modes.
- **SoftHyphen**: Tests the handling of soft hyphens.
- **PreWrapAndReusing**:  Tests how offset mapping handles text node reuse in `pre-wrap`.
- **RestoreTrailingCollapsibleSpaceReplace/Keep/None/Split/SplitKeep**: Tests how trailing collapsible spaces are handled in various scenarios involving line breaks and element boundaries.
- **TextOverflowEllipsis**: Tests the handling of `text-overflow: ellipsis`.
- **StartOfNextNonCollapsedContentWithPseudo/EndOfLastNonCollapsedContentWithPseudo**: Tests functions related to finding the start/end of non-collapsed content with pseudo-elements.
- **WordBreak**: Tests the handling of the `<wbr>` (word break) element.
- **NoCrashByListStyleTypeChange**: Tests that changing the `list-style-type` doesn't cause a crash during offset mapping.

Based on these observations, the primary function of `offset_mapping_test.cc` is to **verify the correctness of the offset mapping logic in the Blink rendering engine across a wide range of scenarios involving different DOM structures, CSS properties, and text formatting**.
这个 `offset_mapping_test.cc` 文件（第 2 部分）的主要功能是**测试 Blink 引擎中用于处理文本内容偏移映射的 `OffsetMapping` 类的各种功能和边缘情况**。

具体来说，这部分代码涵盖了以下方面的测试：

- **处理被替换元素 (Replaced Element)**：测试当文本中包含像 `<img>` 这样的被替换元素时，`OffsetMapping` 如何正确地映射 DOM 节点和偏移量到文本内容的偏移量。
- **处理 `:first-letter` 伪类**：测试当应用了 `:first-letter` 样式时，`OffsetMapping` 如何将第一个字母与剩余文本分开处理，并正确映射偏移量。包括有前导空格和没有剩余文本的情况。
- **处理在不同块中的 `:first-letter`**：测试当 `:first-letter` 由于样式原因被渲染在不同的布局块中时，`OffsetMapping` 如何为第一个字母和剩余文本生成不同的映射。
- **处理没有 LayoutText 的空白文本节点**：测试当空白文本节点没有对应的 `LayoutText` 对象时，相关函数的行为是否正确。
- **处理带有生成内容 (Generated Content) 的容器**：测试当使用 `::before` 和 `::after` 伪元素生成内容时，`OffsetMapping` 如何将生成的内容也纳入映射。包括处理生成内容中的折叠空格的情况。
- **处理表格 (Table)**：测试在表格元素中，`OffsetMapping` 如何处理文本节点的偏移量映射。
- **获取内联块 (Inline Block) 的映射**：测试如何获取内联块元素的偏移映射，并验证内联块的前后锚点是否返回包含块的映射。
- **处理 `white-space: nowrap` 和可折叠空格**：测试当使用 `white-space: nowrap` 时，`OffsetMapping` 如何处理空格，以及如何处理可折叠的空格。
- **处理 `white-space: pre-line`**：测试当使用 `white-space: pre-line` 时，换行符的处理和偏移量映射。
- **处理 `white-space: pre-line/pre-wrap/pre` 中的双向文本和强制换行**：测试在不同的 `white-space` 属性下，当文本包含双向控制字符和强制换行符时，`OffsetMapping` 如何正确跳过生成的双向控制字符并映射偏移量。
- **处理软连字符 (Soft Hyphen)**：测试软连字符对偏移量映射的影响。
- **处理 `white-space: pre-wrap` 和文本节点的复用**：测试在 `white-space: pre-wrap` 情况下，当文本节点被复用时，`OffsetMapping` 的行为。
- **处理恢复尾部可折叠空格 (Restore Trailing Collapsible Space)**：测试在不同的情况下，尾部的可折叠空格是如何被恢复和处理的，包括替换、保留、无空格和分割等场景。
- **处理文本溢出省略号 (Text Overflow Ellipsis)**：测试当应用 `text-overflow: ellipsis` 时，省略号对偏移量映射的影响。
- **处理带有伪元素的下一个/上一个非折叠内容的起始/结束位置**：测试 `StartOfNextNonCollapsedContent` 和 `EndOfLastNonCollapsedContent` 函数在包含伪元素的情况下的行为。
- **处理换行符 (`<wbr>`)**：测试 `<wbr>` 元素对偏移量映射的影响。
- **处理列表样式类型 (List Style Type) 的改变**：测试改变列表的 `list-style-type` 属性是否会导致偏移量映射的崩溃。

**与 JavaScript, HTML, CSS 的功能关系：**

这些测试直接关系到浏览器如何解析和渲染 HTML 结构，以及如何应用 CSS 样式来控制文本的布局和显示。`OffsetMapping` 的正确性对于以下功能至关重要：

- **文本选择 (Text Selection)**：JavaScript 可以通过 DOM API 获取和操作文本选择，而 `OffsetMapping` 确保了选择的起始和结束位置能够正确映射到 DOM 结构。
    ```javascript
    // 假设用户选择了 "foo" 中的 "o" 和 "bar" 中的 "b" 之间的文本
    const selection = window.getSelection();
    const startNode = selection.anchorNode; // 可能指向 "foo" 的文本节点
    const startOffset = selection.anchorOffset; // 可能为 2
    const endNode = selection.focusNode;   // 可能指向 "bar" 的文本节点
    const endOffset = selection.focusOffset;   // 可能为 1

    // Blink 引擎会使用 OffsetMapping 来确定这些偏移量在整个内容中的位置。
    ```
- **光标定位 (Caret Positioning)**：用户在编辑或浏览网页时，光标的位置需要准确地反映在 DOM 结构中。`OffsetMapping` 帮助确定光标在文本节点中的正确偏移量。
- **范围 (Range) 操作**：JavaScript 的 `Range` 对象允许操作文档的片段。`OffsetMapping` 确保了 `Range` 对象的起始和结束位置能够正确映射。
- **`::first-letter` 等 CSS 伪类的实现**：`OffsetMapping` 需要能够区分和处理 `:first-letter` 伪类影响的文本部分。
- **`white-space` 属性的实现**：不同的 `white-space` 属性值会影响空格和换行符的处理，`OffsetMapping` 需要能够正确反映这些影响。
- **生成内容的处理**：对于 `::before` 和 `::after` 生成的内容，`OffsetMapping` 需要能够将其纳入到整体的文本内容映射中。
- **双向文本 (BiDi) 的处理**：对于包含从右到左文本的文档，`OffsetMapping` 需要能够处理双向控制字符，确保文本选择和光标定位的正确性。
- **`text-overflow: ellipsis` 的实现**：`OffsetMapping` 需要能够处理省略号，即使它不属于 DOM 树的实际内容。

**逻辑推理的假设输入与输出：**

由于这些是测试用例，每个 `TEST_F` 都是一个独立的测试。这里举例说明几个：

**假设输入 1 (ReplacedElement):**

- HTML: `<div id=t>foo <img> bar</div>`
- DOM 结构:  DIV -> Text("foo"), IMG, Text("bar")

**预期输出 1:**

- `OffsetMapping` 应该包含 3 个单元 (units)，分别对应 "foo" 文本节点，`<img>` 元素，和 "bar" 文本节点。
- 每个单元应该有正确的 DOM 节点、起始和结束 DOM 偏移量，以及起始和结束内容偏移量。例如，`<img>` 单元的 DOM 偏移量是 0 到 1（表示整个元素），内容偏移量是 4 到 5（紧跟 "foo" 之后）。
- 可以通过 `GetUnitForPosition` 函数，根据给定的 DOM 位置获取对应的单元。例如，`Position::BeforeNode(*img_node)` 应该返回 `<img>` 对应的单元。
- 可以通过 `GetTextContentOffset` 函数，根据给定的 DOM 位置获取对应的内容偏移量。例如，`Position::BeforeNode(*img_node)` 应该返回 4。
- 可以通过 `GetFirstPosition` 和 `GetLastPosition` 函数，根据给定的内容偏移量获取对应的起始和结束 DOM 位置。例如，内容偏移量 4 的起始位置是 "foo" 的末尾，结束位置是 `<img>` 之前。

**假设输入 2 (FirstLetterWithLeadingSpace):**

- HTML: `<style>div:first-letter{color:red}</style><div id=t>  foo</div>`
- DOM 结构: DIV -> Text("  foo")

**预期输出 2:**

- `OffsetMapping` 应该包含 3 个单元：
    - 第一个单元对应前导空格，类型为 `kCollapsed`，DOM 偏移量 0 到 2，内容偏移量 0 到 0。
    - 第二个单元对应首字母 "f"，类型为 `kIdentity`，DOM 偏移量 2 到 3，内容偏移量 0 到 1。
    - 第三个单元对应剩余文本 "oo"，类型为 `kIdentity`，DOM 偏移量 3 到 5，内容偏移量 1 到 3。
- 可以通过 `GetTextContentOffset` 函数验证偏移量映射。例如，`Position(foo_node, 2)`（指向 "f" 的开始）应该返回内容偏移量 0。

**用户或编程常见的使用错误：**

虽然这个文件是测试代码，但它反映了开发中需要注意的一些问题：

- **错误地假设 DOM 偏移量和内容偏移量总是一致的**：例如，在有被替换元素或应用了 CSS 样式导致文本折叠时，DOM 偏移量和内容偏移量可能会有很大差异。
- **没有考虑到 `:first-letter` 伪类会将文本分割成不同的映射单元**：在处理文本选择或光标定位时，需要考虑到这一点。
- **忽略了 `white-space` 属性对空格和换行符的影响**：例如，在 `white-space: pre` 的情况下，空格和换行符不会被折叠，而在其他情况下可能会被折叠。
- **没有正确处理生成内容**：在涉及到 `::before` 和 `::after` 时，需要将生成的内容也纳入到文本处理的考虑范围。
- **在处理双向文本时没有考虑到双向控制字符**：这些字符虽然不可见，但会影响文本的布局和偏移量。

**功能归纳：**

总而言之，`blink/renderer/core/layout/inline/offset_mapping_test.cc` (第 2 部分) 的功能是**全面测试 `OffsetMapping` 类在各种复杂的文本布局场景下的正确性，确保 Blink 引擎能够准确地在 DOM 结构和渲染后的文本内容之间建立偏移量映射关系，这对于文本选择、光标定位、以及正确实现 CSS 文本相关特性至关重要。** 这些测试覆盖了被替换元素、CSS 伪类、不同的 `white-space` 属性、生成内容、双向文本等多种情况，力求保证 `OffsetMapping` 的鲁棒性和准确性。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/offset_mapping_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
Content(Position(space_node, 1u)).IsNull());
  EXPECT_TRUE(
      StartOfNextNonCollapsedContent(Position(space_node, 0u)).IsNull());
}

TEST_F(OffsetMappingTest, ReplacedElement) {
  SetupHtml("t", "<div id=t>foo <img> bar</div>");
  const auto* foo = To<LayoutText>(layout_object_.Get());
  const LayoutObject* img = foo->NextSibling();
  const auto* bar = To<LayoutText>(img->NextSibling());
  const Node* foo_node = foo->GetNode();
  const Node* img_node = img->GetNode();
  const Node* bar_node = bar->GetNode();
  const OffsetMapping& result = GetOffsetMapping();

  ASSERT_EQ(3u, result.GetUnits().size());
  TEST_UNIT(result.GetUnits()[0], OffsetMappingUnitType::kIdentity, foo_node,
            0u, 4u, 0u, 4u);
  TEST_UNIT(result.GetUnits()[1], OffsetMappingUnitType::kIdentity, img_node,
            0u, 1u, 4u, 5u);
  TEST_UNIT(result.GetUnits()[2], OffsetMappingUnitType::kIdentity, bar_node,
            0u, 4u, 5u, 9u);

  ASSERT_EQ(3u, result.GetRanges().size());
  TEST_RANGE(result.GetRanges(), foo_node, 0u, 1u);
  TEST_RANGE(result.GetRanges(), img_node, 1u, 2u);
  TEST_RANGE(result.GetRanges(), bar_node, 2u, 3u);

  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 0)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 1)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 2)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 3)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 4)));
  EXPECT_EQ(&result.GetUnits()[1],
            GetUnitForPosition(Position::BeforeNode(*img_node)));
  EXPECT_EQ(&result.GetUnits()[1],
            GetUnitForPosition(Position::AfterNode(*img_node)));
  EXPECT_EQ(&result.GetUnits()[2], GetUnitForPosition(Position(bar_node, 0)));
  EXPECT_EQ(&result.GetUnits()[2], GetUnitForPosition(Position(bar_node, 1)));
  EXPECT_EQ(&result.GetUnits()[2], GetUnitForPosition(Position(bar_node, 2)));
  EXPECT_EQ(&result.GetUnits()[2], GetUnitForPosition(Position(bar_node, 3)));
  EXPECT_EQ(&result.GetUnits()[2], GetUnitForPosition(Position(bar_node, 4)));

  EXPECT_EQ(0u, *GetTextContentOffset(Position(foo_node, 0)));
  EXPECT_EQ(1u, *GetTextContentOffset(Position(foo_node, 1)));
  EXPECT_EQ(2u, *GetTextContentOffset(Position(foo_node, 2)));
  EXPECT_EQ(3u, *GetTextContentOffset(Position(foo_node, 3)));
  EXPECT_EQ(4u, *GetTextContentOffset(Position(foo_node, 4)));
  EXPECT_EQ(4u, *GetTextContentOffset(Position::BeforeNode(*img_node)));
  EXPECT_EQ(5u, *GetTextContentOffset(Position::AfterNode(*img_node)));
  EXPECT_EQ(5u, *GetTextContentOffset(Position(bar_node, 0)));
  EXPECT_EQ(6u, *GetTextContentOffset(Position(bar_node, 1)));
  EXPECT_EQ(7u, *GetTextContentOffset(Position(bar_node, 2)));
  EXPECT_EQ(8u, *GetTextContentOffset(Position(bar_node, 3)));
  EXPECT_EQ(9u, *GetTextContentOffset(Position(bar_node, 4)));

  EXPECT_EQ(Position(foo_node, 4), GetFirstPosition(4));
  EXPECT_EQ(Position::BeforeNode(*img_node), GetLastPosition(4));
  EXPECT_EQ(Position::AfterNode(*img_node), GetFirstPosition(5));
  EXPECT_EQ(Position(bar_node, 0), GetLastPosition(5));
}

TEST_F(OffsetMappingTest, FirstLetter) {
  SetupHtml("t",
            "<style>div:first-letter{color:red}</style>"
            "<div id=t>foo</div>");
  Element* div = GetElementById("t");
  const Node* foo_node = div->firstChild();
  const OffsetMapping& result = GetOffsetMapping();

  ASSERT_EQ(2u, result.GetUnits().size());
  TEST_UNIT(result.GetUnits()[0], OffsetMappingUnitType::kIdentity, foo_node,
            0u, 1u, 0u, 1u);
  // first leter and remaining text are always in different mapping units.
  TEST_UNIT(result.GetUnits()[1], OffsetMappingUnitType::kIdentity, foo_node,
            1u, 3u, 1u, 3u);

  ASSERT_EQ(1u, result.GetRanges().size());
  TEST_RANGE(result.GetRanges(), foo_node, 0u, 2u);

  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 0)));
  EXPECT_EQ(&result.GetUnits()[1], GetUnitForPosition(Position(foo_node, 1)));
  EXPECT_EQ(&result.GetUnits()[1], GetUnitForPosition(Position(foo_node, 2)));

  EXPECT_EQ(0u, *GetTextContentOffset(Position(foo_node, 0)));
  EXPECT_EQ(1u, *GetTextContentOffset(Position(foo_node, 1)));
  EXPECT_EQ(2u, *GetTextContentOffset(Position(foo_node, 2)));

  EXPECT_EQ(Position(foo_node, 1), GetFirstPosition(1));
  EXPECT_EQ(Position(foo_node, 1), GetLastPosition(1));
}

TEST_F(OffsetMappingTest, FirstLetterWithLeadingSpace) {
  SetupHtml("t",
            "<style>div:first-letter{color:red}</style>"
            "<div id=t>  foo</div>");
  Element* div = GetElementById("t");
  const Node* foo_node = div->firstChild();
  const OffsetMapping& result = GetOffsetMapping();

  ASSERT_EQ(3u, result.GetUnits().size());
  TEST_UNIT(result.GetUnits()[0], OffsetMappingUnitType::kCollapsed, foo_node,
            0u, 2u, 0u, 0u);
  TEST_UNIT(result.GetUnits()[1], OffsetMappingUnitType::kIdentity, foo_node,
            2u, 3u, 0u, 1u);
  // first leter and remaining text are always in different mapping units.
  TEST_UNIT(result.GetUnits()[2], OffsetMappingUnitType::kIdentity, foo_node,
            3u, 5u, 1u, 3u);

  ASSERT_EQ(1u, result.GetRanges().size());
  TEST_RANGE(result.GetRanges(), foo_node, 0u, 3u);

  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 0)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(foo_node, 1)));
  EXPECT_EQ(&result.GetUnits()[1], GetUnitForPosition(Position(foo_node, 2)));
  EXPECT_EQ(&result.GetUnits()[2], GetUnitForPosition(Position(foo_node, 3)));
  EXPECT_EQ(&result.GetUnits()[2], GetUnitForPosition(Position(foo_node, 4)));

  EXPECT_EQ(0u, *GetTextContentOffset(Position(foo_node, 0)));
  EXPECT_EQ(0u, *GetTextContentOffset(Position(foo_node, 1)));
  EXPECT_EQ(0u, *GetTextContentOffset(Position(foo_node, 2)));
  EXPECT_EQ(1u, *GetTextContentOffset(Position(foo_node, 3)));
  EXPECT_EQ(2u, *GetTextContentOffset(Position(foo_node, 4)));

  EXPECT_EQ(Position(foo_node, 0), GetFirstPosition(0));
  EXPECT_EQ(Position(foo_node, 2), GetLastPosition(0));
}

TEST_F(OffsetMappingTest, FirstLetterWithoutRemainingText) {
  SetupHtml("t",
            "<style>div:first-letter{color:red}</style>"
            "<div id=t>  f</div>");
  Element* div = GetElementById("t");
  const Node* text_node = div->firstChild();
  const OffsetMapping& result = GetOffsetMapping();

  ASSERT_EQ(2u, result.GetUnits().size());
  TEST_UNIT(result.GetUnits()[0], OffsetMappingUnitType::kCollapsed, text_node,
            0u, 2u, 0u, 0u);
  TEST_UNIT(result.GetUnits()[1], OffsetMappingUnitType::kIdentity, text_node,
            2u, 3u, 0u, 1u);

  ASSERT_EQ(1u, result.GetRanges().size());
  TEST_RANGE(result.GetRanges(), text_node, 0u, 2u);

  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(text_node, 0)));
  EXPECT_EQ(&result.GetUnits()[0], GetUnitForPosition(Position(text_node, 1)));
  EXPECT_EQ(&result.GetUnits()[1], GetUnitForPosition(Position(text_node, 2)));
  EXPECT_EQ(&result.GetUnits()[1], GetUnitForPosition(Position(text_node, 3)));

  EXPECT_EQ(0u, *GetTextContentOffset(Position(text_node, 0)));
  EXPECT_EQ(0u, *GetTextContentOffset(Position(text_node, 1)));
  EXPECT_EQ(0u, *GetTextContentOffset(Position(text_node, 2)));
  EXPECT_EQ(1u, *GetTextContentOffset(Position(text_node, 3)));

  EXPECT_EQ(Position(text_node, 0), GetFirstPosition(0));
  EXPECT_EQ(Position(text_node, 2), GetLastPosition(0));
}

TEST_F(OffsetMappingTest, FirstLetterInDifferentBlock) {
  SetupHtml("t",
            "<style>:first-letter{float:right}</style><div id=t>foo</div>");
  Element* div = GetElementById("t");
  const Node* text_node = div->firstChild();

  auto* mapping0 = OffsetMapping::GetFor(Position(text_node, 0));
  auto* mapping1 = OffsetMapping::GetFor(Position(text_node, 1));
  auto* mapping2 = OffsetMapping::GetFor(Position(text_node, 2));
  auto* mapping3 = OffsetMapping::GetFor(Position(text_node, 3));

  ASSERT_TRUE(mapping0);
  ASSERT_TRUE(mapping1);
  ASSERT_TRUE(mapping2);
  ASSERT_TRUE(mapping3);

  // GetNGOffsetmappingFor() returns different mappings for offset 0 and other
  // offsets, because first-letter is laid out in a different block.
  EXPECT_NE(mapping0, mapping1);
  EXPECT_EQ(mapping1, mapping2);
  EXPECT_EQ(mapping2, mapping3);

  const OffsetMapping& first_letter_result = *mapping0;
  ASSERT_EQ(1u, first_letter_result.GetUnits().size());
  TEST_UNIT(first_letter_result.GetUnits()[0], OffsetMappingUnitType::kIdentity,
            text_node, 0u, 1u, 0u, 1u);
  ASSERT_EQ(1u, first_letter_result.GetRanges().size());
  TEST_RANGE(first_letter_result.GetRanges(), text_node, 0u, 1u);

  const OffsetMapping& remaining_text_result = *mapping1;
  ASSERT_EQ(1u, remaining_text_result.GetUnits().size());
  TEST_UNIT(remaining_text_result.GetUnits()[0],
            OffsetMappingUnitType::kIdentity, text_node, 1u, 3u, 1u, 3u);
  ASSERT_EQ(1u, remaining_text_result.GetRanges().size());
  TEST_RANGE(remaining_text_result.GetRanges(), text_node, 0u, 1u);

  EXPECT_EQ(
      &first_letter_result.GetUnits()[0],
      first_letter_result.GetMappingUnitForPosition(Position(text_node, 0)));
  EXPECT_EQ(
      &remaining_text_result.GetUnits()[0],
      remaining_text_result.GetMappingUnitForPosition(Position(text_node, 1)));
  EXPECT_EQ(
      &remaining_text_result.GetUnits()[0],
      remaining_text_result.GetMappingUnitForPosition(Position(text_node, 2)));
  EXPECT_EQ(
      &remaining_text_result.GetUnits()[0],
      remaining_text_result.GetMappingUnitForPosition(Position(text_node, 3)));

  EXPECT_EQ(0u,
            *first_letter_result.GetTextContentOffset(Position(text_node, 0)));
  EXPECT_EQ(
      1u, *remaining_text_result.GetTextContentOffset(Position(text_node, 1)));
  EXPECT_EQ(
      2u, *remaining_text_result.GetTextContentOffset(Position(text_node, 2)));
  EXPECT_EQ(
      3u, *remaining_text_result.GetTextContentOffset(Position(text_node, 3)));

  EXPECT_EQ(Position(text_node, 1), first_letter_result.GetFirstPosition(1));
  EXPECT_EQ(Position(text_node, 1), first_letter_result.GetLastPosition(1));
  EXPECT_EQ(Position(text_node, 1), remaining_text_result.GetFirstPosition(1));
  EXPECT_EQ(Position(text_node, 1), remaining_text_result.GetLastPosition(1));
}

TEST_F(OffsetMappingTest, WhiteSpaceTextNodeWithoutLayoutText) {
  SetupHtml("t", "<div id=t> <span>foo</span></div>");
  Element* div = GetElementById("t");
  const Node* text_node = div->firstChild();

  EXPECT_TRUE(EndOfLastNonCollapsedContent(Position(text_node, 1u)).IsNull());
  EXPECT_TRUE(StartOfNextNonCollapsedContent(Position(text_node, 0u)).IsNull());
}

TEST_F(OffsetMappingTest, ContainerWithGeneratedContent) {
  SetupHtml("t",
            "<style>#s::before{content:'bar'} #s::after{content:'baz'}</style>"
            "<div id=t><span id=s>foo</span></div>");
  const Element* span = GetElementById("s");
  const Node* text = span->firstChild();
  const LayoutObject& before = *span->GetPseudoElement(kPseudoIdBefore)
                                    ->GetLayoutObject()
                                    ->SlowFirstChild();
  const LayoutObject& after = *span->GetPseudoElement(kPseudoIdAfter)
                                   ->GetLayoutObject()
                                   ->SlowFirstChild();
  const OffsetMapping& result = GetOffsetMapping();

  EXPECT_EQ((HeapVector<OffsetMappingUnit>{
                OffsetMappingUnit(kIdentity, before, 0u, 3u, 0u, 3u),
                OffsetMappingUnit(kIdentity, *text->GetLayoutObject(), 0u, 3u,
                                  3u, 6u),
                OffsetMappingUnit(kIdentity, after, 0u, 3u, 6u, 9u)}),
            result.GetUnits());

  // Verify |GetMappingUnitsForLayoutObject()| for ::before and ::after
  EXPECT_EQ((HeapVector<OffsetMappingUnit>{
                OffsetMappingUnit(kIdentity, before, 0u, 3u, 0u, 3u)}),
            result.GetMappingUnitsForLayoutObject(before));
  EXPECT_EQ((HeapVector<OffsetMappingUnit>{
                OffsetMappingUnit(kIdentity, after, 0u, 3u, 6u, 9u)}),
            result.GetMappingUnitsForLayoutObject(after));
}

TEST_F(OffsetMappingTest,
       ContainerWithGeneratedContentWithCollapsedWhitespace) {
  SetupHtml("t",
            "<style>"
            "#t::before { content: '  a   bc'; }"
            "#t::first-letter { font-weight: bold; }"
            "</style><div id=t>def</div>");
  const Element& target = *GetElementById("t");
  const auto& remaining_part =
      *To<LayoutText>(target.GetPseudoElement(kPseudoIdBefore)
                          ->GetLayoutObject()
                          ->SlowLastChild());
  const LayoutObject& first_letter_part = *remaining_part.GetFirstLetterPart();
  const OffsetMapping& result = GetOffsetMapping();
  const auto& target_text =
      To<LayoutText>(*target.firstChild()->GetLayoutObject());

  EXPECT_EQ(
      (HeapVector<OffsetMappingUnit>{
          OffsetMappingUnit(kCollapsed, first_letter_part, 0u, 2u, 0u, 0u),
          OffsetMappingUnit(kIdentity, first_letter_part, 2u, 3u, 0u, 1u),
          OffsetMappingUnit(kIdentity, remaining_part, 0u, 1u, 1u, 2u),
          OffsetMappingUnit(kCollapsed, remaining_part, 1u, 3u, 2u, 2u),
          OffsetMappingUnit(kIdentity, remaining_part, 3u, 5u, 2u, 4u),
          OffsetMappingUnit(kIdentity, target_text, 0u, 3u, 4u, 7u)}),
      result.GetUnits());

  // Verify |GetMappingUnitsForLayoutObject()| for ::first-letter
  EXPECT_EQ(
      (HeapVector<OffsetMappingUnit>{
          OffsetMappingUnit(kCollapsed, first_letter_part, 0u, 2u, 0u, 0u),
          OffsetMappingUnit(kIdentity, first_letter_part, 2u, 3u, 0u, 1u)}),
      result.GetMappingUnitsForLayoutObject(first_letter_part));
  EXPECT_EQ((HeapVector<OffsetMappingUnit>{
                OffsetMappingUnit(kIdentity, remaining_part, 0u, 1u, 1u, 2u),
                OffsetMappingUnit(kCollapsed, remaining_part, 1u, 3u, 2u, 2u),
                OffsetMappingUnit(kIdentity, remaining_part, 3u, 5u, 2u, 4u)}),
            result.GetMappingUnitsForLayoutObject(remaining_part));
}

TEST_F(OffsetMappingTest, Table) {
  SetupHtml("t", "<table><tr><td id=t>  foo  </td></tr></table>");

  const Node* foo_node = layout_object_->GetNode();
  const OffsetMapping& result = GetOffsetMapping();

  EXPECT_EQ("foo", result.GetText());

  ASSERT_EQ(3u, result.GetUnits().size());
  TEST_UNIT(result.GetUnits()[0], OffsetMappingUnitType::kCollapsed, foo_node,
            0u, 2u, 0u, 0u);
  TEST_UNIT(result.GetUnits()[1], OffsetMappingUnitType::kIdentity, foo_node,
            2u, 5u, 0u, 3u);
  TEST_UNIT(result.GetUnits()[2], OffsetMappingUnitType::kCollapsed, foo_node,
            5u, 7u, 3u, 3u);

  ASSERT_EQ(1u, result.GetRanges().size());
  TEST_RANGE(result.GetRanges(), foo_node, 0u, 3u);

  EXPECT_EQ(GetUnits(1, 1), GetFirstLast("|foo"));
  EXPECT_EQ(GetUnits(1, 1), GetFirstLast("f|oo"));
  EXPECT_EQ(GetUnits(2, 2), GetFirstLast("foo|"));
}

TEST_F(OffsetMappingTest, GetMappingForInlineBlock) {
  SetupHtml("t",
            "<div id=t>foo"
            "<span style='display: inline-block' id=span> bar </span>"
            "baz</div>");

  const Element* div = GetElementById("t");
  const Element* span = GetElementById("span");

  const OffsetMapping* div_mapping =
      OffsetMapping::GetFor(Position(div->firstChild(), 0));
  const OffsetMapping* span_mapping =
      OffsetMapping::GetFor(Position(span->firstChild(), 0));

  // OffsetMapping::GetFor for Before/AfterAnchor of an inline block should
  // return the mapping of the containing block, not of the inline block itself.

  const OffsetMapping* span_before_mapping =
      OffsetMapping::GetFor(Position::BeforeNode(*span));
  EXPECT_EQ(div_mapping, span_before_mapping);
  EXPECT_NE(span_mapping, span_before_mapping);

  const OffsetMapping* span_after_mapping =
      OffsetMapping::GetFor(Position::AfterNode(*span));
  EXPECT_EQ(div_mapping, span_after_mapping);
  EXPECT_NE(span_mapping, span_after_mapping);
}

TEST_F(OffsetMappingTest, NoWrapSpaceAndCollapsibleSpace) {
  SetupHtml("t",
            "<div id=t>"
            "<span style='white-space: nowrap' id=span>foo </span>"
            " bar"
            "</div>");

  const Element* span = GetElementById("span");
  const Node* foo = span->firstChild();
  const Node* bar = span->nextSibling();
  const OffsetMapping& mapping = GetOffsetMapping();

  // InlineItemsBuilder inserts a ZWS to indicate break opportunity.
  EXPECT_EQ(String(u"foo \u200Bbar"), mapping.GetText());

  // Should't map any character in DOM to the generated ZWS.
  ASSERT_EQ(3u, mapping.GetUnits().size());
  TEST_UNIT(mapping.GetUnits()[0], OffsetMappingUnitType::kIdentity, foo, 0u,
            4u, 0u, 4u);
  TEST_UNIT(mapping.GetUnits()[1], OffsetMappingUnitType::kCollapsed, bar, 0u,
            1u, 5u, 5u);
  TEST_UNIT(mapping.GetUnits()[2], OffsetMappingUnitType::kIdentity, bar, 1u,
            4u, 5u, 8u);

  EXPECT_EQ(GetUnits(0, 0), GetFirstLast("|foo Xbar"));
  EXPECT_EQ(GetUnits(0, 0), GetFirstLast("foo| Xbar"));
  EXPECT_EQ(GetUnits(0, 0), GetFirstLast("foo |Xbar"));
  EXPECT_EQ(GetUnits(2, 2), GetFirstLast("foo X|bar"));
}

TEST_F(OffsetMappingTest, PreLine) {
  InsertStyleElement("#t { white-space: pre-line; }");
  SetupHtml("t", "<div id=t>ab \n cd</div>");
  const LayoutObject& text_ab_n_cd = *layout_object_;
  const OffsetMapping& result = GetOffsetMapping();

  EXPECT_EQ("ab\ncd", result.GetText());

  EXPECT_EQ((HeapVector<OffsetMappingUnit>{
                OffsetMappingUnit(kIdentity, text_ab_n_cd, 0u, 2u, 0u, 2u),
                OffsetMappingUnit(kCollapsed, text_ab_n_cd, 2u, 3u, 2u, 2u),
                OffsetMappingUnit(kIdentity, text_ab_n_cd, 3u, 4u, 2u, 3u),
                OffsetMappingUnit(kCollapsed, text_ab_n_cd, 4u, 5u, 3u, 3u),
                OffsetMappingUnit(kIdentity, text_ab_n_cd, 5u, 7u, 3u, 5u)}),
            result.GetUnits());

  EXPECT_EQ(GetUnits(0, 0), GetFirstLast("|ab\ncd"));
  EXPECT_EQ(GetUnits(0, 0), GetFirstLast("a|b\ncd"));
  EXPECT_EQ(GetUnits(1, 2), GetFirstLast("ab|\ncd"));
  EXPECT_EQ(GetUnits(3, 4), GetFirstLast("ab\n|cd"));
  EXPECT_EQ(GetUnits(4, 4), GetFirstLast("ab\nc|d"));
  EXPECT_EQ(GetUnits(4, 4), GetFirstLast("ab\ncd|"));
}

TEST_F(OffsetMappingTest, BiDiAroundForcedBreakInPreLine) {
  SetupHtml("t",
            "<div id=t style='white-space: pre-line'>"
            "<bdo dir=rtl id=bdo>foo\nbar</bdo></div>");

  const Node* text = GetElementById("bdo")->firstChild();
  const OffsetMapping& mapping = GetOffsetMapping();

  EXPECT_EQ(String(u"\u2068\u202Efoo\u202C\u2069"
                   u"\n"
                   u"\u2068\u202Ebar\u202C\u2069"),
            mapping.GetText());

  // Offset mapping should skip generated BiDi control characters.
  ASSERT_EQ(3u, mapping.GetUnits().size());
  TEST_UNIT(mapping.GetUnits()[0], OffsetMappingUnitType::kIdentity, text, 0u,
            3u, 2u, 5u);  // "foo"
  TEST_UNIT(mapping.GetUnits()[1], OffsetMappingUnitType::kIdentity, text, 3u,
            4u, 7u, 8u);  // "\n"
  TEST_UNIT(mapping.GetUnits()[2], OffsetMappingUnitType::kIdentity, text, 4u,
            7u, 10u, 13u);  // "bar"
  TEST_RANGE(mapping.GetRanges(), text, 0u, 3u);
}

TEST_F(OffsetMappingTest, BiDiAroundForcedBreakInPreWrap) {
  SetupHtml("t",
            "<div id=t style='white-space: pre-wrap'>"
            "<bdo dir=rtl id=bdo>foo\nbar</bdo></div>");

  const Node* text = GetElementById("bdo")->firstChild();
  const OffsetMapping& mapping = GetOffsetMapping();

  EXPECT_EQ(String(u"\u2068\u202Efoo\u202C\u2069"
                   u"\n"
                   u"\u2068\u202Ebar\u202C\u2069"),
            mapping.GetText());

  // Offset mapping should skip generated BiDi control characters.
  ASSERT_EQ(3u, mapping.GetUnits().size());
  TEST_UNIT(mapping.GetUnits()[0], OffsetMappingUnitType::kIdentity, text, 0u,
            3u, 2u, 5u);  // "foo"
  TEST_UNIT(mapping.GetUnits()[1], OffsetMappingUnitType::kIdentity, text, 3u,
            4u, 7u, 8u);  // "\n"
  TEST_UNIT(mapping.GetUnits()[2], OffsetMappingUnitType::kIdentity, text, 4u,
            7u, 10u, 13u);  // "bar"
  TEST_RANGE(mapping.GetRanges(), text, 0u, 3u);
}

TEST_F(OffsetMappingTest, BiDiAroundForcedBreakInPre) {
  SetupHtml("t",
            "<div id=t style='white-space: pre'>"
            "<bdo dir=rtl id=bdo>foo\nbar</bdo></div>");

  const Node* text = GetElementById("bdo")->firstChild();
  const OffsetMapping& mapping = GetOffsetMapping();

  EXPECT_EQ(String(u"\u2068\u202Efoo\u202C\u2069"
                   u"\n"
                   u"\u2068\u202Ebar\u202C\u2069"),
            mapping.GetText());

  // Offset mapping should skip generated BiDi control characters.
  ASSERT_EQ(3u, mapping.GetUnits().size());
  TEST_UNIT(mapping.GetUnits()[0], OffsetMappingUnitType::kIdentity, text, 0u,
            3u, 2u, 5u);  // "foo"
  TEST_UNIT(mapping.GetUnits()[1], OffsetMappingUnitType::kIdentity, text, 3u,
            4u, 7u, 8u);  // "\n"
  TEST_UNIT(mapping.GetUnits()[2], OffsetMappingUnitType::kIdentity, text, 4u,
            7u, 10u, 13u);  // "bar"
  TEST_RANGE(mapping.GetRanges(), text, 0u, 3u);
}

TEST_F(OffsetMappingTest, SoftHyphen) {
  LoadAhem();
  SetupHtml(
      "t",
      "<div id=t style='font: 10px/10px Ahem; width: 40px'>abc&shy;def</div>");

  const Node* text = GetElementById("t")->firstChild();
  const OffsetMapping& mapping = GetOffsetMapping();

  // Line wrapping and hyphenation are oblivious to offset mapping.
  ASSERT_EQ(1u, mapping.GetUnits().size());
  TEST_UNIT(mapping.GetUnits()[0], OffsetMappingUnitType::kIdentity, text, 0u,
            7u, 0u, 7u);
  TEST_RANGE(mapping.GetRanges(), text, 0u, 1u);
}

// For http://crbug.com/965353
TEST_F(OffsetMappingTest, PreWrapAndReusing) {
  // Note: "white-space: break-space" yields same result.
  SetupHtml("t", "<p id='t' style='white-space: pre-wrap'>abc</p>");
  Element& target = *GetElementById("t");

  // Change to <p id=t>abc xyz</p>
  Text& text = *Text::Create(GetDocument(), " xyz");
  target.appendChild(&text);
  UpdateAllLifecyclePhasesForTest();

  // Change to <p id=t> xyz</p>. We attempt to reuse " xyz".
  target.firstChild()->remove();
  UpdateAllLifecyclePhasesForTest();

  const OffsetMapping& mapping = GetOffsetMapping();
  EXPECT_EQ(String(u" \u200Bxyz"), mapping.GetText())
      << "We have ZWS after leading preserved space.";
  EXPECT_EQ(
      (HeapVector<OffsetMappingUnit>{
          OffsetMappingUnit(kIdentity, *text.GetLayoutObject(), 0u, 1u, 0u, 1u),
          OffsetMappingUnit(kIdentity, *text.GetLayoutObject(), 1u, 4u, 2u, 5u),
      }),
      mapping.GetUnits());
}

TEST_F(OffsetMappingTest, RestoreTrailingCollapsibleSpaceReplace) {
  // A space inside <b> is collapsed by during handling "\n" then it is restored
  // by handling a newline. Restored space is removed at end of block.
  // When RestoreTrailingCollapsibleSpace(), units are:
  //  0: kIdentity text in <a>, dom=0,1 content=0,1
  //  1: kCollapsed text in <b>, dom=0,1, content=2,2
  //  2: kCollapsed "\n", dom=0,1, content=2,2
  // layout_text is a child of <b> and offset is 2
  SetupHtml("t",
            "<div id=t>"
            "<a style='white-space: pre-wrap;'> </a><b> </b>\n<i> </i>"
            "</div>");
  const OffsetMapping& result = GetOffsetMapping();
  const LayoutObject& layout_object_a = *layout_object_;
  const LayoutObject& layout_object_b = *layout_object_a.NextSibling();
  const LayoutObject& newline = *layout_object_b.NextSibling();
  const LayoutObject& layout_object_i = *newline.NextSibling();
  EXPECT_EQ((HeapVector<OffsetMappingUnit>{
                OffsetMappingUnit(kIdentity, *layout_object_a.SlowFirstChild(),
                                  0u, 1u, 0u, 1u),
                OffsetMappingUnit(kCollapsed, *layout_object_b.SlowFirstChild(),
                                  0u, 1u, 2u, 2u),
                OffsetMappingUnit(kCollapsed, newline, 0u, 1u, 2u, 2u),
                OffsetMappingUnit(kCollapsed, *layout_object_i.SlowFirstChild(),
                                  0u, 1u, 2u, 2u),
            }),
            result.GetUnits());
}

TEST_F(OffsetMappingTest, RestoreTrailingCollapsibleSpaceReplaceKeep) {
  // A space inside <b> is collapsed by during handling "\n" then it is restored
  // by handling a newline.
  // When RestoreTrailingCollapsibleSpace(), units are:
  //  0: kIdentity text in <a>, dom=0,1 content=0,1
  //  1: kCollapsed text in <b>, dom=0,1, content=2,2
  //  2: kCollapsed "\n", dom=0,1, content=2,2
  // layout_text is a child of <b> and offset is 2
  SetupHtml("t",
            "<div id=t>"
            "<a style='white-space: pre-wrap;'> </a><b> </b>\n<i>x</i>"
            "</div>");
  const OffsetMapping& result = GetOffsetMapping();
  const LayoutObject& layout_object_a = *layout_object_;
  const LayoutObject& layout_object_b = *layout_object_a.NextSibling();
  const LayoutObject& newline = *layout_object_b.NextSibling();
  const LayoutObject& layout_object_i = *newline.NextSibling();
  EXPECT_EQ((HeapVector<OffsetMappingUnit>{
                OffsetMappingUnit(kIdentity, *layout_object_a.SlowFirstChild(),
                                  0u, 1u, 0u, 1u),
                OffsetMappingUnit(kIdentity, *layout_object_b.SlowFirstChild(),
                                  0u, 1u, 2u, 3u),
                OffsetMappingUnit(kCollapsed, newline, 0u, 1u, 3u, 3u),
                OffsetMappingUnit(kIdentity, *layout_object_i.SlowFirstChild(),
                                  0u, 1u, 3u, 4u),
            }),
            result.GetUnits());
}

TEST_F(OffsetMappingTest, RestoreTrailingCollapsibleSpaceNone) {
  SetupHtml("t",
            "<div id=t>"
            "<a>x</a><b>   </b>\n<i>y</i>"
            "</div>");
  const OffsetMapping& result = GetOffsetMapping();
  const LayoutObject& layout_object_a = *layout_object_;
  const LayoutObject& layout_object_b = *layout_object_a.NextSibling();
  const LayoutObject& newline = *layout_object_b.NextSibling();
  const LayoutObject& layout_object_i = *newline.NextSibling();
  EXPECT_EQ((HeapVector<OffsetMappingUnit>{
                OffsetMappingUnit(kIdentity, *layout_object_a.SlowFirstChild(),
                                  0u, 1u, 0u, 1u),
                // We take the first space character.
                OffsetMappingUnit(kIdentity, *layout_object_b.SlowFirstChild(),
                                  0u, 1u, 1u, 2u),
                OffsetMappingUnit(kCollapsed, *layout_object_b.SlowFirstChild(),
                                  1u, 3u, 2u, 2u),
                OffsetMappingUnit(kCollapsed, newline, 0u, 1u, 2u, 2u),
                OffsetMappingUnit(kIdentity, *layout_object_i.SlowFirstChild(),
                                  0u, 1u, 2u, 3u),
            }),
            result.GetUnits());
}

TEST_F(OffsetMappingTest, RestoreTrailingCollapsibleSpaceSplit) {
  // Spaces inside <b> is collapsed by during handling "\n" then it is restored
  // by handling a newline. Restored space is removed at end of block.
  // When RestoreTrailingCollapsibleSpace(), units are:
  //  0: kIdentity text in <a>, dom=0,1 content=0,1
  //  1: kCollapsed text in <b>, dom=0,3, content=2,2
  //  2: kCollapsed "\n", dom=0,1 content=3,3
  // layout_text is a child of <b> and offset is 2
  SetupHtml("t",
            "<div id=t>"
            "<a style='white-space: pre-wrap;'> </a><b>   </b>\n<i> </i>"
            "</div>");
  const OffsetMapping& result = GetOffsetMapping();
  const LayoutObject& layout_object_a = *layout_object_;
  const LayoutObject& layout_object_b = *layout_object_a.NextSibling();
  const LayoutObject& newline = *layout_object_b.NextSibling();
  const LayoutObject& layout_object_i = *newline.NextSibling();
  EXPECT_EQ((HeapVector<OffsetMappingUnit>{
                OffsetMappingUnit(kIdentity, *layout_object_a.SlowFirstChild(),
                                  0u, 1u, 0u, 1u),
                OffsetMappingUnit(kCollapsed, *layout_object_b.SlowFirstChild(),
                                  0u, 3u, 2u, 2u),
                OffsetMappingUnit(kCollapsed, newline, 0u, 1u, 2u, 2u),
                OffsetMappingUnit(kCollapsed, *layout_object_i.SlowFirstChild(),
                                  0u, 1u, 2u, 2u),
            }),
            result.GetUnits());
}

TEST_F(OffsetMappingTest, RestoreTrailingCollapsibleSpaceSplitKeep) {
  // Spaces inside <b> is collapsed by during handling "\n" then it is restored
  // by handling a space in <i>.
  // When RestoreTrailingCollapsibleSpace(), units are:
  //  0: kIdentity text in <a>, dom=0,1 content=0,1
  //  1: kCollapsed text in <b>, dom=0,3, content=2,2
  //  2: kCollapsed "\n", dom=0,1 content=3,3
  // layout_text is a child of <b> and offset is 2
  SetupHtml("t",
            "<div id=t>"
            "<a style='white-space: pre-wrap;'> </a><b>   </b>\n<i>x</i>"
            "</div>");
  const OffsetMapping& result = GetOffsetMapping();
  const LayoutObject& layout_object_a = *layout_object_;
  const LayoutObject& layout_object_b = *layout_object_a.NextSibling();
  const LayoutObject& newline = *layout_object_b.NextSibling();
  const LayoutObject& layout_object_i = *newline.NextSibling();
  EXPECT_EQ((HeapVector<OffsetMappingUnit>{
                OffsetMappingUnit(kIdentity, *layout_object_a.SlowFirstChild(),
                                  0u, 1u, 0u, 1u),
                OffsetMappingUnit(kIdentity, *layout_object_b.SlowFirstChild(),
                                  0u, 1u, 2u, 3u),
                OffsetMappingUnit(kCollapsed, *layout_object_b.SlowFirstChild(),
                                  1u, 3u, 3u, 3u),
                OffsetMappingUnit(kCollapsed, newline, 0u, 1u, 3u, 3u),
                OffsetMappingUnit(kIdentity, *layout_object_i.SlowFirstChild(),
                                  0u, 1u, 3u, 4u),
            }),
            result.GetUnits());
}

TEST_F(OffsetMappingTest, TextOverflowEllipsis) {
  LoadAhem();
  SetupHtml("t",
            "<div id=t style='font: 10px/10px Ahem; width: 30px; overflow: "
            "hidden; text-overflow: ellipsis'>123456</div>");

  const Node* text = GetElementById("t")->firstChild();
  const OffsetMapping& mapping = GetOffsetMapping();

  // Ellipsis is oblivious to offset mapping.
  ASSERT_EQ(1u, mapping.GetUnits().size());
  TEST_UNIT(mapping.GetUnits()[0], OffsetMappingUnitType::kIdentity, text, 0u,
            6u, 0u, 6u);
  TEST_RANGE(mapping.GetRanges(), text, 0u, 1u);
}

// https://crbug.com/967106
TEST_F(OffsetMappingTest, StartOfNextNonCollapsedContentWithPseudo) {
  // The white spaces are necessary for bug repro. Do not remove them.
  SetupHtml("t", R"HTML(
    <style>span#quote::before { content: '"'}</style>
    <div id=t>
      <span>foo </span>
      <span id=quote>bar</span>
    </div>)HTML");

  const Element* quote = GetElementById("quote");
  const Node* text = quote->previousSibling();
  const Position position = Position::FirstPositionInNode(*text);

  EXPECT_EQ(Position(),
            GetOffsetMapping().StartOfNextNonCollapsedContent(position));
}

// https://crbug.com/967106
TEST_F(OffsetMappingTest, EndOfLastNonCollapsedContentWithPseudo) {
  // The white spaces are necessary for bug repro. Do not remove them.
  SetupHtml("t", R"HTML(
    <style>span#quote::after { content: '" '}</style>
    <div id=t>
      <span id=quote>foo</span>
      <span>bar</span>
    </div>)HTML");

  const Element* quote = GetElementById("quote");
  const Node* text = quote->nextSibling();
  const Position position = Position::LastPositionInNode(*text);

  EXPECT_EQ(Position(),
            GetOffsetMapping().EndOfLastNonCollapsedContent(position));
}

TEST_F(OffsetMappingTest, WordBreak) {
  SetupHtml("t", "<div id=t>a<wbr>b</div>");

  const LayoutObject& text_a = *layout_object_;
  const LayoutObject& wbr = *text_a.NextSibling();
  const LayoutObject& text_b = *wbr.NextSibling();
  const OffsetMapping& result = GetOffsetMapping();

  EXPECT_EQ((HeapVector<OffsetMappingUnit>{
                OffsetMappingUnit(kIdentity, text_a, 0u, 1u, 0u, 1u),
                OffsetMappingUnit(kIdentity, wbr, 0u, 1u, 1u, 2u),
                OffsetMappingUnit(kIdentity, text_b, 0u, 1u, 2u, 3u)}),
            result.GetUnits());

  EXPECT_EQ((HeapVector<OffsetMappingUnit>{
                OffsetMappingUnit(kIdentity, wbr, 0u, 1u, 1u, 2u)}),
            result.GetMappingUnitsForLayoutObject(wbr));
}

// crbug.com/1443193
TEST_F(OffsetMappingTest, NoCrashByListStyleTypeChange) {
  SetupHtml("ifc",
            R"HTML(
      <div id=ifc>
        <span id=t style="display:inline list-item">item</span>
      </div>)HTML");
  Element* target = GetElementById("t");
  target->SetInlineStyleProperty(CSSPropertyID::kListStyleType, "myanmar");
  UpdateAllLifecyclePhasesForTest();
  GetOffsetMapping();
  // Pass if OffsetMapping constructor didn'
"""


```