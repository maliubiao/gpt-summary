Response:
My thinking process to answer the request about the `layout_multi_column_flow_thread_test.cc` file went something like this:

1. **Understand the Core Request:** The user wants to know the function of the provided C++ source code file, specifically in the context of Chromium's Blink rendering engine. They also want to see examples related to HTML, CSS, and JavaScript, and understand potential errors or logical assumptions.

2. **Initial Analysis of the Code Snippet:** I scanned the `#include` directives and the overall structure. Key observations:
    * It's a test file (`_test.cc`). This immediately tells me its primary purpose is *testing*.
    * It includes headers related to layout (`layout_multi_column_flow_thread.h`, `layout_multi_column_set.h`, etc.). This indicates it's testing the functionality of the multi-column layout feature.
    * It uses the `testing/gtest/include/gtest/gtest.h` framework, confirming it's a unit test file.
    * It includes DOM-related headers (`dom/text.h`, `html/html_div_element.h`, etc.), meaning the tests involve creating and manipulating HTML elements within a layout context.

3. **Identify Key Classes and Functions Under Test:**  The `#include "third_party/blink/renderer/core/layout/layout_multi_column_flow_thread.h"` is crucial. This tells me the core class being tested is `LayoutMultiColumnFlowThread`. Other included layout classes like `LayoutMultiColumnSet` and `LayoutMultiColumnSpannerPlaceholder` are also likely involved. The `TEST_F` macros point to specific test cases within the `MultiColumnRenderingTest` class.

4. **Infer Functionality from Test Names and Code:** I examined the names of the test cases (`OneBlockWithInDepthTreeStructureCheck`, `Empty`, `OneBlock`, `Spanner`, `ContentThenSpanner`, etc.). These names provide strong hints about the specific scenarios being tested. For example:
    * `Empty`: Tests the behavior when a multi-column container is empty.
    * `Spanner`: Tests the handling of elements with `column-span: all`.
    * `ContentThenSpanner`: Tests the sequence of column sets and spanner placeholders when content precedes a spanner.

5. **Relate Functionality to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** The tests manipulate HTML elements (`<div>`, `<span>`) and their structure within the multi-column context. The `SetMulticolHTML` function builds HTML strings, demonstrating how the tests set up different scenarios.
    * **CSS:** The `SetMulticolHTML` function includes `<style>` blocks defining CSS properties like `columns: 2` and `column-span: all`. This clearly shows the tests are verifying how CSS properties affect the multi-column layout.
    * **JavaScript:** While this specific test file doesn't *directly* execute JavaScript, the layout engine's behavior it tests is what makes multi-column layouts work when dynamically manipulated by JavaScript. I considered how JavaScript could add or remove elements, and how these tests might indirectly validate those scenarios.

6. **Logical Assumptions and Input/Output:** The tests make assumptions about how the layout engine *should* behave given certain HTML and CSS inputs. The `ColumnSetSignature` function is key here. It acts as a way to verify the *output* of the layout process (the structure of column sets and spanners) based on the *input* HTML. I started thinking about simple examples:
    * *Input:* `<div id='mc'><div>content</div></div>`
    * *Expected Output (Signature):* "c" (one column set)
    * *Input:* `<div id='mc'><div style='column-span: all;'>spanner</div></div>`
    * *Expected Output (Signature):* "s" (one spanner placeholder)

7. **Common Usage Errors:** I considered common mistakes developers might make when working with multi-column layouts:
    * Forgetting to set the `columns` property on the container.
    * Incorrectly assuming `column-span: all` on nested elements within a spanner would create another spanner.
    * Dynamically adding or removing elements without understanding how it affects the column flow.

8. **Structure and Summarization:** Finally, I organized my thoughts into a clear and structured answer, addressing each part of the user's request. I started with a general summary of the file's purpose, then provided specific examples for HTML, CSS, and potential errors. The `ColumnSetSignature` function became a central element in explaining the logical assumptions and input/output. I kept the language clear and avoided overly technical jargon where possible.

9. **Review and Refine:**  I reread my answer to ensure it was accurate, comprehensive, and easy to understand. I double-checked that the examples were relevant and illustrative of the points I was making. I also ensured the final summary accurately captured the essence of the file's functionality.

Essentially, I approached it like reverse-engineering the purpose of the test file by examining its contents and connecting it to my knowledge of web technologies and layout principles. The test names and the `ColumnSetSignature` function were the biggest clues to understanding the underlying logic.```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/layout_multi_column_flow_thread.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/layout/layout_multi_column_set.h"
#include "third_party/blink/renderer/core/layout/layout_multi_column_spanner_placeholder.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

class MultiColumnRenderingTest : public RenderingTest {
 protected:
  LayoutMultiColumnFlowThread* FindFlowThread(const char* id) const;

  // Generate a signature string based on what kind of column boxes the flow
  // thread has established. 'c' is used for regular column content sets, while
  // 's' is used for spanners. '?' is used when there's an unknown box type
  // (which should be considered a failure).
  String ColumnSetSignature(LayoutMultiColumnFlowThread*);
  String ColumnSetSignature(const char* multicol_id);

  void SetMulticolHTML(const String&);
};

LayoutMultiColumnFlowThread* MultiColumnRenderingTest::FindFlowThread(
    const char* id) const {
  if (auto* multicol_container =
          To<LayoutBlockFlow>(GetLayoutObjectByElementId(id)))
    return multicol_container->MultiColumnFlowThread();
  return nullptr;
}

String MultiColumnRenderingTest::ColumnSetSignature(
    LayoutMultiColumnFlowThread* flow_thread) {
  StringBuilder signature;
  for (LayoutBox* column_box = flow_thread->FirstMultiColumnBox(); column_box;
       column_box = column_box->NextSiblingMultiColumnBox()) {
    if (column_box->IsLayoutMultiColumnSpannerPlaceholder())
      signature.Append('s');
    else if (column_box->IsLayoutMultiColumnSet())
      signature.Append('c');
    else
      signature.Append('?');
  }
  return signature.ToString();
}

String MultiColumnRenderingTest::ColumnSetSignature(const char* multicol_id) {
  return ColumnSetSignature(FindFlowThread(multicol_id));
}

void MultiColumnRenderingTest::SetMulticolHTML(const String& html) {
  const char* style =
      "<style>"
      "  #mc { columns:2; }"
      "  .s, #spanner, #spanner1, #spanner2 { column-span:all; }"
      "</style>";
  SetBodyInnerHTML(style + html);
}

TEST_F(MultiColumnRenderingTest, OneBlockWithInDepthTreeStructureCheck) {
  // Examine the layout tree established by a simple multicol container with a
  // block with some text inside.
  SetMulticolHTML("<div id='mc'><div>xxx</div></div>");
  auto* multicol_container =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("mc"));
  ASSERT_TRUE(multicol_container);
  LayoutMultiColumnFlowThread* flow_thread =
      multicol_container->MultiColumnFlowThread();
  ASSERT_TRUE(flow_thread);
  EXPECT_EQ(ColumnSetSignature(flow_thread), "c");
  EXPECT_EQ(flow_thread->Parent(), multicol_container);
  EXPECT_FALSE(flow_thread->PreviousSibling());
  LayoutMultiColumnSet* column_set = flow_thread->FirstMultiColumnSet();
  ASSERT_TRUE(column_set);
  EXPECT_EQ(column_set->PreviousSibling(), flow_thread);
  EXPECT_FALSE(column_set->NextSibling());
  auto* block = To<LayoutBlockFlow>(flow_thread->FirstChild());
  ASSERT_TRUE(block);
  EXPECT_FALSE(block->NextSibling());
  ASSERT_TRUE(block->FirstChild());
  EXPECT_TRUE(block->FirstChild()->IsText());
  EXPECT_FALSE(block->FirstChild()->NextSibling());
}

TEST_F(MultiColumnRenderingTest, Empty) {
  // If there's no column content, there should be no column set.
  SetMulticolHTML("<div id='mc'></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "");
}

TEST_F(MultiColumnRenderingTest, OneBlock) {
  // There is some content, so we should create a column set.
  SetMulticolHTML("<div id='mc'><div id='block'></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  ASSERT_EQ(ColumnSetSignature(flow_thread), "c");
  LayoutMultiColumnSet* column_set = flow_thread->FirstMultiColumnSet();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("block")),
            column_set);
}

TEST_F(MultiColumnRenderingTest, TwoBlocks) {
  // No matter how much content, we should only create one column set (unless
  // there are spanners).
  SetMulticolHTML(
      "<div id='mc'><div id='block1'></div><div id='block2'></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  ASSERT_EQ(ColumnSetSignature(flow_thread), "c");
  LayoutMultiColumnSet* column_set = flow_thread->FirstMultiColumnSet();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("block1")),
            column_set);
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("block2")),
            column_set);
}

TEST_F(MultiColumnRenderingTest, Spanner) {
  // With one spanner and no column content, we should create a spanner set.
  SetMulticolHTML("<div id='mc'><div id='spanner'></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  ASSERT_EQ(ColumnSetSignature(flow_thread), "s");
  LayoutBox* column_box = flow_thread->FirstMultiColumnBox();
  EXPECT_EQ(flow_thread->FirstMultiColumnSet(), nullptr);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner")),
            column_box);
  EXPECT_EQ(GetLayoutObjectByElementId("spanner")->SpannerPlaceholder(),
            column_box);
}

TEST_F(MultiColumnRenderingTest, ContentThenSpanner) {
  // With some column content followed by a spanner, we need a column set
  // followed by a spanner set.
  SetMulticolHTML(
      "<div id='mc'><div id='columnContent'></div><div "
      "id='spanner'></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  ASSERT_EQ(ColumnSetSignature(flow_thread), "cs");
  LayoutBox* column_box = flow_thread->FirstMultiColumnBox();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("columnContent")),
            column_box);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner")),
            column_box);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("columnContent")),
            nullptr);
}

TEST_F(MultiColumnRenderingTest, SpannerThenContent) {
  // With a spanner followed by some column content, we need a spanner set
  // followed by a column set.
  SetMulticolHTML(
      "<div id='mc'><div id='spanner'></div><div "
      "id='columnContent'></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  ASSERT_EQ(ColumnSetSignature(flow_thread), "sc");
  LayoutBox* column_box = flow_thread->FirstMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner")),
            column_box);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("columnContent")),
            column_box);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("columnContent")),
            nullptr);
}

TEST_F(MultiColumnRenderingTest, ContentThenSpannerThenContent) {
  // With column content followed by a spanner followed by some column content,
  // we need a column
  // set followed by a spanner set followed by a column set.
  SetMulticolHTML(
      "<div id='mc'><div id='columnContentBefore'></div><div "
      "id='spanner'></div><div id='columnContentAfter'></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  ASSERT_EQ(ColumnSetSignature(flow_thread), "csc");
  LayoutBox* column_box = flow_thread->FirstMultiColumnSet();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("columnContentBefore")),
            column_box);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("columnContentBefore")),
            nullptr);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner")),
            column_box);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("columnContentAfter")),
            column_box);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("columnContentAfter")),
            nullptr);
}

TEST_F(MultiColumnRenderingTest, TwoSpanners) {
  // With two spanners and no column content, we need two spanner sets.
  SetMulticolHTML(
      "<div id='mc'><div id='spanner1'></div><div id='spanner2'></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  ASSERT_EQ(ColumnSetSignature(flow_thread), "ss");
  LayoutBox* column_box = flow_thread->FirstMultiColumnBox();
  EXPECT_EQ(flow_thread->FirstMultiColumnSet(), nullptr);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner1")),
            column_box);
  EXPECT_EQ(GetLayoutObjectByElementId("spanner1")->SpannerPlaceholder(),
            column_box);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner2")),
            column_box);
  EXPECT_EQ(GetLayoutObjectByElementId("spanner2")->SpannerPlaceholder(),
            column_box);
}

TEST_F(MultiColumnRenderingTest, SpannerThenContentThenSpanner) {
  // With two spanners and some column content in-between, we need a spanner
  // set, a column set and another spanner set.
  SetMulticolHTML(
      "<div id='mc'><div id='spanner1'></div><div "
      "id='columnContent'></div><div id='spanner2'></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  ASSERT_EQ(ColumnSetSignature(flow_thread), "scs");
  LayoutMultiColumnSet* column_set = flow_thread->FirstMultiColumnSet();
  EXPECT_EQ(column_set->NextSiblingMultiColumnSet(), nullptr);
  LayoutBox* column_box = flow_thread->FirstMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner1")),
            column_box);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(column_box, column_set);
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("columnContent")),
            column_set);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("columnContent")),
            nullptr);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner2")),
            column_box);
}

TEST_F(MultiColumnRenderingTest, SpannerWithSpanner) {
  // column-span:all on something inside column-span:all has no effect.
  SetMulticolHTML(
      "<div id='mc'><div id='spanner'><div id='invalidSpanner' "
      "class='s'></div></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  ASSERT_EQ(ColumnSetSignature(flow_thread), "s");
  LayoutBox* column_box = flow_thread->FirstMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner")),
            column_box);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("invalidSpanner")),
            column_box);
  EXPECT_EQ(To<LayoutMultiColumnSpannerPlaceholder>(column_box)
                ->LayoutObjectInFlowThread(),
            GetLayoutObjectByElementId("spanner"));
  EXPECT_EQ(GetLayoutObjectByElementId("spanner")->SpannerPlaceholder(),
            column_box);
  EXPECT_EQ(GetLayoutObjectByElementId("invalidSpanner")->SpannerPlaceholder(),
            nullptr);
}

TEST_F(MultiColumnRenderingTest, SubtreeWithSpanner) {
  SetMulticolHTML(
      "<div id='mc'><div id='outer'><div id='block1'></div><div "
      "id='spanner'></div><div id='block2'></div></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  EXPECT_EQ(ColumnSetSignature(flow_thread), "csc");
  LayoutBox* column_box = flow_thread->FirstMultiColumnBox();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("outer")),
            column_box);
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("block1")),
            column_box);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner")),
            column_box);
  EXPECT_EQ(GetLayoutObjectByElementId("spanner")->SpannerPlaceholder(),
            column_box);
  EXPECT_EQ(To<LayoutMultiColumnSpannerPlaceholder>(column_box)
                ->LayoutObjectInFlowThread(),
            GetLayoutObjectByElementId("spanner"));
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("outer")),
            nullptr);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("block1")),
            nullptr);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("block2")),
            nullptr);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("block2")),
            column_box);
}

TEST_F(MultiColumnRenderingTest, SubtreeWithSpannerAfterSpanner) {
  SetMulticolHTML(
      "<div id='mc'><div id='spanner1'></div><div id='outer'>text<div "
      "id='spanner2'></div><div id='after'></div></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  EXPECT_EQ(ColumnSetSignature(flow_thread), "scsc");
  LayoutBox* column_box = flow_thread->FirstMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner1")),
            column_box);
  EXPECT_EQ(To<LayoutMultiColumnSpannerPlaceholder>(column_box)
                ->LayoutObjectInFlowThread(),
            GetLayoutObjectByElementId("spanner1"));
  EXPECT_EQ(GetLayoutObjectByElementId("spanner1")->SpannerPlaceholder(),
            column_box);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("outer")),
            column_box);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner2")),
            column_box);
  EXPECT_EQ(To<LayoutMultiColumnSpannerPlaceholder>(column_box)
                ->LayoutObjectInFlowThread(),
            GetLayoutObjectByElementId("spanner2"));
  EXPECT_EQ(GetLayoutObjectByElementId("spanner2")->SpannerPlaceholder(),
            column_box);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("outer")),
            nullptr);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("after")),
            nullptr);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("after")),
            column_box);
}

TEST_F(MultiColumnRenderingTest, SubtreeWithSpannerBeforeSpanner) {
  SetMulticolHTML(
      "<div id='mc'><div id='outer'>text<div "
      "id='spanner1'></div>text</div><div id='spanner2'></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  EXPECT_EQ(ColumnSetSignature(flow_thread), "cscs");
  LayoutBox* column_box = flow_thread->FirstMultiColumnSet();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("outer")),
            column_box);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner1")),
            column_box);
  EXPECT_EQ(GetLayoutObjectByElementId("spanner1")->SpannerPlaceholder(),
            column_box);
  EXPECT_EQ(To<LayoutMultiColumnSpannerPlaceholder>(column_box)
                ->LayoutObjectInFlowThread(),
            GetLayoutObjectByElementId("spanner1"));
  column_box =
      column_box->NextSiblingMultiColumnBox()->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner2")),
            column_box);
  EXPECT_EQ(GetLayoutObjectByElementId("spanner2")->SpannerPlaceholder(),
            column_box);
  EXPECT_EQ(To<LayoutMultiColumnSpannerPlaceholder>(column_box)
                ->LayoutObjectInFlowThread(),
            GetLayoutObjectByElementId("spanner2"));
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("outer")),
            nullptr);
}

TEST_F(MultiColumnRenderingTest, columnSetAtBlockOffset) {
  SetMulticolHTML(R"HTML(
      <div id='mc' style='line-height:100px;'>
        text<br>
        text<br>
        text<br>
        text<br>
        text
        <div id='spanner1'>spanner</div>
        text<br>
        text
        <div id='spanner2'>
          text<br>
          text
        </div>
        text
      </div>
  )HTML");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  EXPECT_EQ(ColumnSetSignature(flow_thread), "cscsc");
  LayoutMultiColumnSet* first_row = flow_thread->FirstMultiColumnSet();
  LayoutMultiColumnSet* second_row = first_row->NextSiblingMultiColumnSet();
  LayoutMultiColumnSet* third_row = second_row->NextSiblingMultiColumnSet();
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(-10000), LayoutBox::kAssociateWithFormerPage),
            first_row);  // negative overflow
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(-10000), LayoutBox::kAssociateWithLatterPage),
            first_row);  // negative overflow
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(), LayoutBox::kAssociateWithFormerPage),
            first_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(), LayoutBox::kAssociateWithLatterPage),
            first_row);
  LayoutUnit offset(600);
  // The first column row contains 5 lines, split into two columns, i.e. 3 lines
  // in the first and 2 lines in the second. Line height is 100px. There's 100px
  // of unused space at the end of the second column.
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithFormerPage),
            first_row);  // bottom of last line in first row.
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithLatterPage),
            first_row);  // bottom of last line in first row.
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithFormerPage),
            first_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithLatterPage),
            second_row);
  offset += LayoutUnit(200);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithFormerPage),
            second_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithLatterPage),
            second_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithFormerPage),
            second_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithLatterPage),
            third_row);
  offset += LayoutUnit(100);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithLatterPage),
            third_row);  // bottom of last row
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(10000), LayoutBox::kAssociateWithFormerPage),
            third_row);  // overflow
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(10000), LayoutBox::kAssociateWithLatterPage),
            third_row);  // overflow
}

TEST_F(MultiColumnRenderingTest, columnSetAtBlockOffsetVerticalRl) {
  SetMulticolHTML(R"HTML(
      <div id='mc' style='line-height:100px; writing-mode:vertical-rl;'>
        text<br>
        text<br>
        text<br>
        text<br>
        text
        <div id='spanner1'>spanner</div>
        text<br>
        text
        <div id='spanner2'>
          text<br>
          text
        </div>
        text
      </div>
  )HTML");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  EXPECT_EQ(ColumnSetSignature(flow_thread), "cscsc");
  LayoutMultiColumnSet* first_row = flow_thread->FirstMultiColumnSet();
  LayoutMultiColumnSet* second_row = first_row->NextSiblingMultiColumnSet();
  LayoutMultiColumnSet* third_row = second_row->NextSiblingMultiColumnSet();
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(-10000), LayoutBox::kAssociateWithFormerPage),
            first_row);  // negative overflow
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(-10000), LayoutBox::kAssociateWithLatterPage),
            first_row);  // negative overflow
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(), LayoutBox::kAssociateWithFormerPage),
            first_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(), LayoutBox::kAssociateWithLatterPage),
            first_row);
  LayoutUnit offset(600);
  // The first column row contains 5 lines, split into two columns, i.e. 3 lines
  // in the first and 2 lines in the second. Line height is 100px. There's 100px
  // of unused space at the end of the second column.
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithFormerPage),
            first_row);  // bottom of last line in first row.
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithLatterPage),
            first_row);  // bottom of last line in first row.
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithFormerPage),
            first_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithLatterPage),
            second_row);
  offset += LayoutUnit(200);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithFormerPage),
            second_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithLatterPage),
            second_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithFormerPage),
            second_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithLatterPage),
            third_row);
  offset += LayoutUnit(100);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithLatterPage),
            third_row);  // bottom of last row
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(10000), LayoutBox::kAssociateWithFormerPage),
            third_row);  // overflow
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(10000), LayoutBox::kAssociateWithLatterPage),
            third_row);  // overflow
}

TEST_F(MultiColumnRenderingTest, columnSetAtBlockOffsetVerticalLr) {
  SetMulticolHTML(R"HTML(
      <div id='mc' style='line-height:100px; writing-mode:vertical-lr;'>
        text<br>
        text<br>
        text<br>
        text<br>
        text
        <div id='spanner1'>spanner</div>
        text<br>
        text
        <div id='spanner2'>
          text<br>
          text
        </div>
        text
      </div>
  )HTML");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  EXPECT_EQ(ColumnSetSignature(flow_thread), "cscsc");
  LayoutMultiColumnSet* first_row = flow_thread->FirstMultiColumnSet();
  LayoutMultiColumnSet* second_row = first_row->NextSiblingMultiColumnSet();
  LayoutMultiColumnSet* third_row = second_row->NextSiblingMultiColumnSet();
  EXPECT_EQ(flow_thread->ColumnSetAtBlock
### 提示词
```
这是目录为blink/renderer/core/layout/layout_multi_column_flow_thread_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/layout_multi_column_flow_thread.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/layout/layout_multi_column_set.h"
#include "third_party/blink/renderer/core/layout/layout_multi_column_spanner_placeholder.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

class MultiColumnRenderingTest : public RenderingTest {
 protected:
  LayoutMultiColumnFlowThread* FindFlowThread(const char* id) const;

  // Generate a signature string based on what kind of column boxes the flow
  // thread has established. 'c' is used for regular column content sets, while
  // 's' is used for spanners. '?' is used when there's an unknown box type
  // (which should be considered a failure).
  String ColumnSetSignature(LayoutMultiColumnFlowThread*);
  String ColumnSetSignature(const char* multicol_id);

  void SetMulticolHTML(const String&);
};

LayoutMultiColumnFlowThread* MultiColumnRenderingTest::FindFlowThread(
    const char* id) const {
  if (auto* multicol_container =
          To<LayoutBlockFlow>(GetLayoutObjectByElementId(id)))
    return multicol_container->MultiColumnFlowThread();
  return nullptr;
}

String MultiColumnRenderingTest::ColumnSetSignature(
    LayoutMultiColumnFlowThread* flow_thread) {
  StringBuilder signature;
  for (LayoutBox* column_box = flow_thread->FirstMultiColumnBox(); column_box;
       column_box = column_box->NextSiblingMultiColumnBox()) {
    if (column_box->IsLayoutMultiColumnSpannerPlaceholder())
      signature.Append('s');
    else if (column_box->IsLayoutMultiColumnSet())
      signature.Append('c');
    else
      signature.Append('?');
  }
  return signature.ToString();
}

String MultiColumnRenderingTest::ColumnSetSignature(const char* multicol_id) {
  return ColumnSetSignature(FindFlowThread(multicol_id));
}

void MultiColumnRenderingTest::SetMulticolHTML(const String& html) {
  const char* style =
      "<style>"
      "  #mc { columns:2; }"
      "  .s, #spanner, #spanner1, #spanner2 { column-span:all; }"
      "</style>";
  SetBodyInnerHTML(style + html);
}

TEST_F(MultiColumnRenderingTest, OneBlockWithInDepthTreeStructureCheck) {
  // Examine the layout tree established by a simple multicol container with a
  // block with some text inside.
  SetMulticolHTML("<div id='mc'><div>xxx</div></div>");
  auto* multicol_container =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("mc"));
  ASSERT_TRUE(multicol_container);
  LayoutMultiColumnFlowThread* flow_thread =
      multicol_container->MultiColumnFlowThread();
  ASSERT_TRUE(flow_thread);
  EXPECT_EQ(ColumnSetSignature(flow_thread), "c");
  EXPECT_EQ(flow_thread->Parent(), multicol_container);
  EXPECT_FALSE(flow_thread->PreviousSibling());
  LayoutMultiColumnSet* column_set = flow_thread->FirstMultiColumnSet();
  ASSERT_TRUE(column_set);
  EXPECT_EQ(column_set->PreviousSibling(), flow_thread);
  EXPECT_FALSE(column_set->NextSibling());
  auto* block = To<LayoutBlockFlow>(flow_thread->FirstChild());
  ASSERT_TRUE(block);
  EXPECT_FALSE(block->NextSibling());
  ASSERT_TRUE(block->FirstChild());
  EXPECT_TRUE(block->FirstChild()->IsText());
  EXPECT_FALSE(block->FirstChild()->NextSibling());
}

TEST_F(MultiColumnRenderingTest, Empty) {
  // If there's no column content, there should be no column set.
  SetMulticolHTML("<div id='mc'></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "");
}

TEST_F(MultiColumnRenderingTest, OneBlock) {
  // There is some content, so we should create a column set.
  SetMulticolHTML("<div id='mc'><div id='block'></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  ASSERT_EQ(ColumnSetSignature(flow_thread), "c");
  LayoutMultiColumnSet* column_set = flow_thread->FirstMultiColumnSet();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("block")),
            column_set);
}

TEST_F(MultiColumnRenderingTest, TwoBlocks) {
  // No matter how much content, we should only create one column set (unless
  // there are spanners).
  SetMulticolHTML(
      "<div id='mc'><div id='block1'></div><div id='block2'></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  ASSERT_EQ(ColumnSetSignature(flow_thread), "c");
  LayoutMultiColumnSet* column_set = flow_thread->FirstMultiColumnSet();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("block1")),
            column_set);
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("block2")),
            column_set);
}

TEST_F(MultiColumnRenderingTest, Spanner) {
  // With one spanner and no column content, we should create a spanner set.
  SetMulticolHTML("<div id='mc'><div id='spanner'></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  ASSERT_EQ(ColumnSetSignature(flow_thread), "s");
  LayoutBox* column_box = flow_thread->FirstMultiColumnBox();
  EXPECT_EQ(flow_thread->FirstMultiColumnSet(), nullptr);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner")),
            column_box);
  EXPECT_EQ(GetLayoutObjectByElementId("spanner")->SpannerPlaceholder(),
            column_box);
}

TEST_F(MultiColumnRenderingTest, ContentThenSpanner) {
  // With some column content followed by a spanner, we need a column set
  // followed by a spanner set.
  SetMulticolHTML(
      "<div id='mc'><div id='columnContent'></div><div "
      "id='spanner'></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  ASSERT_EQ(ColumnSetSignature(flow_thread), "cs");
  LayoutBox* column_box = flow_thread->FirstMultiColumnBox();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("columnContent")),
            column_box);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner")),
            column_box);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("columnContent")),
            nullptr);
}

TEST_F(MultiColumnRenderingTest, SpannerThenContent) {
  // With a spanner followed by some column content, we need a spanner set
  // followed by a column set.
  SetMulticolHTML(
      "<div id='mc'><div id='spanner'></div><div "
      "id='columnContent'></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  ASSERT_EQ(ColumnSetSignature(flow_thread), "sc");
  LayoutBox* column_box = flow_thread->FirstMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner")),
            column_box);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("columnContent")),
            column_box);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("columnContent")),
            nullptr);
}

TEST_F(MultiColumnRenderingTest, ContentThenSpannerThenContent) {
  // With column content followed by a spanner followed by some column content,
  // we need a column
  // set followed by a spanner set followed by a column set.
  SetMulticolHTML(
      "<div id='mc'><div id='columnContentBefore'></div><div "
      "id='spanner'></div><div id='columnContentAfter'></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  ASSERT_EQ(ColumnSetSignature(flow_thread), "csc");
  LayoutBox* column_box = flow_thread->FirstMultiColumnSet();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("columnContentBefore")),
            column_box);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("columnContentBefore")),
            nullptr);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner")),
            column_box);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("columnContentAfter")),
            column_box);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("columnContentAfter")),
            nullptr);
}

TEST_F(MultiColumnRenderingTest, TwoSpanners) {
  // With two spanners and no column content, we need two spanner sets.
  SetMulticolHTML(
      "<div id='mc'><div id='spanner1'></div><div id='spanner2'></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  ASSERT_EQ(ColumnSetSignature(flow_thread), "ss");
  LayoutBox* column_box = flow_thread->FirstMultiColumnBox();
  EXPECT_EQ(flow_thread->FirstMultiColumnSet(), nullptr);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner1")),
            column_box);
  EXPECT_EQ(GetLayoutObjectByElementId("spanner1")->SpannerPlaceholder(),
            column_box);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner2")),
            column_box);
  EXPECT_EQ(GetLayoutObjectByElementId("spanner2")->SpannerPlaceholder(),
            column_box);
}

TEST_F(MultiColumnRenderingTest, SpannerThenContentThenSpanner) {
  // With two spanners and some column content in-between, we need a spanner
  // set, a column set and another spanner set.
  SetMulticolHTML(
      "<div id='mc'><div id='spanner1'></div><div "
      "id='columnContent'></div><div id='spanner2'></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  ASSERT_EQ(ColumnSetSignature(flow_thread), "scs");
  LayoutMultiColumnSet* column_set = flow_thread->FirstMultiColumnSet();
  EXPECT_EQ(column_set->NextSiblingMultiColumnSet(), nullptr);
  LayoutBox* column_box = flow_thread->FirstMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner1")),
            column_box);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(column_box, column_set);
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("columnContent")),
            column_set);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("columnContent")),
            nullptr);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner2")),
            column_box);
}

TEST_F(MultiColumnRenderingTest, SpannerWithSpanner) {
  // column-span:all on something inside column-span:all has no effect.
  SetMulticolHTML(
      "<div id='mc'><div id='spanner'><div id='invalidSpanner' "
      "class='s'></div></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  ASSERT_EQ(ColumnSetSignature(flow_thread), "s");
  LayoutBox* column_box = flow_thread->FirstMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner")),
            column_box);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("invalidSpanner")),
            column_box);
  EXPECT_EQ(To<LayoutMultiColumnSpannerPlaceholder>(column_box)
                ->LayoutObjectInFlowThread(),
            GetLayoutObjectByElementId("spanner"));
  EXPECT_EQ(GetLayoutObjectByElementId("spanner")->SpannerPlaceholder(),
            column_box);
  EXPECT_EQ(GetLayoutObjectByElementId("invalidSpanner")->SpannerPlaceholder(),
            nullptr);
}

TEST_F(MultiColumnRenderingTest, SubtreeWithSpanner) {
  SetMulticolHTML(
      "<div id='mc'><div id='outer'><div id='block1'></div><div "
      "id='spanner'></div><div id='block2'></div></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  EXPECT_EQ(ColumnSetSignature(flow_thread), "csc");
  LayoutBox* column_box = flow_thread->FirstMultiColumnBox();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("outer")),
            column_box);
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("block1")),
            column_box);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner")),
            column_box);
  EXPECT_EQ(GetLayoutObjectByElementId("spanner")->SpannerPlaceholder(),
            column_box);
  EXPECT_EQ(To<LayoutMultiColumnSpannerPlaceholder>(column_box)
                ->LayoutObjectInFlowThread(),
            GetLayoutObjectByElementId("spanner"));
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("outer")),
            nullptr);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("block1")),
            nullptr);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("block2")),
            nullptr);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("block2")),
            column_box);
}

TEST_F(MultiColumnRenderingTest, SubtreeWithSpannerAfterSpanner) {
  SetMulticolHTML(
      "<div id='mc'><div id='spanner1'></div><div id='outer'>text<div "
      "id='spanner2'></div><div id='after'></div></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  EXPECT_EQ(ColumnSetSignature(flow_thread), "scsc");
  LayoutBox* column_box = flow_thread->FirstMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner1")),
            column_box);
  EXPECT_EQ(To<LayoutMultiColumnSpannerPlaceholder>(column_box)
                ->LayoutObjectInFlowThread(),
            GetLayoutObjectByElementId("spanner1"));
  EXPECT_EQ(GetLayoutObjectByElementId("spanner1")->SpannerPlaceholder(),
            column_box);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("outer")),
            column_box);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner2")),
            column_box);
  EXPECT_EQ(To<LayoutMultiColumnSpannerPlaceholder>(column_box)
                ->LayoutObjectInFlowThread(),
            GetLayoutObjectByElementId("spanner2"));
  EXPECT_EQ(GetLayoutObjectByElementId("spanner2")->SpannerPlaceholder(),
            column_box);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("outer")),
            nullptr);
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("after")),
            nullptr);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("after")),
            column_box);
}

TEST_F(MultiColumnRenderingTest, SubtreeWithSpannerBeforeSpanner) {
  SetMulticolHTML(
      "<div id='mc'><div id='outer'>text<div "
      "id='spanner1'></div>text</div><div id='spanner2'></div></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  EXPECT_EQ(ColumnSetSignature(flow_thread), "cscs");
  LayoutBox* column_box = flow_thread->FirstMultiColumnSet();
  EXPECT_EQ(flow_thread->MapDescendantToColumnSet(
                GetLayoutObjectByElementId("outer")),
            column_box);
  column_box = column_box->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner1")),
            column_box);
  EXPECT_EQ(GetLayoutObjectByElementId("spanner1")->SpannerPlaceholder(),
            column_box);
  EXPECT_EQ(To<LayoutMultiColumnSpannerPlaceholder>(column_box)
                ->LayoutObjectInFlowThread(),
            GetLayoutObjectByElementId("spanner1"));
  column_box =
      column_box->NextSiblingMultiColumnBox()->NextSiblingMultiColumnBox();
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("spanner2")),
            column_box);
  EXPECT_EQ(GetLayoutObjectByElementId("spanner2")->SpannerPlaceholder(),
            column_box);
  EXPECT_EQ(To<LayoutMultiColumnSpannerPlaceholder>(column_box)
                ->LayoutObjectInFlowThread(),
            GetLayoutObjectByElementId("spanner2"));
  EXPECT_EQ(flow_thread->ContainingColumnSpannerPlaceholder(
                GetLayoutObjectByElementId("outer")),
            nullptr);
}

TEST_F(MultiColumnRenderingTest, columnSetAtBlockOffset) {
  SetMulticolHTML(R"HTML(
      <div id='mc' style='line-height:100px;'>
        text<br>
        text<br>
        text<br>
        text<br>
        text
        <div id='spanner1'>spanner</div>
        text<br>
        text
        <div id='spanner2'>
          text<br>
          text
        </div>
        text
      </div>
  )HTML");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  EXPECT_EQ(ColumnSetSignature(flow_thread), "cscsc");
  LayoutMultiColumnSet* first_row = flow_thread->FirstMultiColumnSet();
  LayoutMultiColumnSet* second_row = first_row->NextSiblingMultiColumnSet();
  LayoutMultiColumnSet* third_row = second_row->NextSiblingMultiColumnSet();
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(-10000), LayoutBox::kAssociateWithFormerPage),
            first_row);  // negative overflow
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(-10000), LayoutBox::kAssociateWithLatterPage),
            first_row);  // negative overflow
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(), LayoutBox::kAssociateWithFormerPage),
            first_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(), LayoutBox::kAssociateWithLatterPage),
            first_row);
  LayoutUnit offset(600);
  // The first column row contains 5 lines, split into two columns, i.e. 3 lines
  // in the first and 2 lines in the second. Line height is 100px. There's 100px
  // of unused space at the end of the second column.
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithFormerPage),
            first_row);  // bottom of last line in first row.
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithLatterPage),
            first_row);  // bottom of last line in first row.
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithFormerPage),
            first_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithLatterPage),
            second_row);
  offset += LayoutUnit(200);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithFormerPage),
            second_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithLatterPage),
            second_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithFormerPage),
            second_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithLatterPage),
            third_row);
  offset += LayoutUnit(100);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithLatterPage),
            third_row);  // bottom of last row
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(10000), LayoutBox::kAssociateWithFormerPage),
            third_row);  // overflow
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(10000), LayoutBox::kAssociateWithLatterPage),
            third_row);  // overflow
}

TEST_F(MultiColumnRenderingTest, columnSetAtBlockOffsetVerticalRl) {
  SetMulticolHTML(R"HTML(
      <div id='mc' style='line-height:100px; writing-mode:vertical-rl;'>
        text<br>
        text<br>
        text<br>
        text<br>
        text
        <div id='spanner1'>spanner</div>
        text<br>
        text
        <div id='spanner2'>
          text<br>
          text
        </div>
        text
      </div>
  )HTML");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  EXPECT_EQ(ColumnSetSignature(flow_thread), "cscsc");
  LayoutMultiColumnSet* first_row = flow_thread->FirstMultiColumnSet();
  LayoutMultiColumnSet* second_row = first_row->NextSiblingMultiColumnSet();
  LayoutMultiColumnSet* third_row = second_row->NextSiblingMultiColumnSet();
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(-10000), LayoutBox::kAssociateWithFormerPage),
            first_row);  // negative overflow
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(-10000), LayoutBox::kAssociateWithLatterPage),
            first_row);  // negative overflow
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(), LayoutBox::kAssociateWithFormerPage),
            first_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(), LayoutBox::kAssociateWithLatterPage),
            first_row);
  LayoutUnit offset(600);
  // The first column row contains 5 lines, split into two columns, i.e. 3 lines
  // in the first and 2 lines in the second. Line height is 100px. There's 100px
  // of unused space at the end of the second column.
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithFormerPage),
            first_row);  // bottom of last line in first row.
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithLatterPage),
            first_row);  // bottom of last line in first row.
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithFormerPage),
            first_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithLatterPage),
            second_row);
  offset += LayoutUnit(200);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithFormerPage),
            second_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithLatterPage),
            second_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithFormerPage),
            second_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithLatterPage),
            third_row);
  offset += LayoutUnit(100);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithLatterPage),
            third_row);  // bottom of last row
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(10000), LayoutBox::kAssociateWithFormerPage),
            third_row);  // overflow
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(10000), LayoutBox::kAssociateWithLatterPage),
            third_row);  // overflow
}

TEST_F(MultiColumnRenderingTest, columnSetAtBlockOffsetVerticalLr) {
  SetMulticolHTML(R"HTML(
      <div id='mc' style='line-height:100px; writing-mode:vertical-lr;'>
        text<br>
        text<br>
        text<br>
        text<br>
        text
        <div id='spanner1'>spanner</div>
        text<br>
        text
        <div id='spanner2'>
          text<br>
          text
        </div>
        text
      </div>
  )HTML");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  EXPECT_EQ(ColumnSetSignature(flow_thread), "cscsc");
  LayoutMultiColumnSet* first_row = flow_thread->FirstMultiColumnSet();
  LayoutMultiColumnSet* second_row = first_row->NextSiblingMultiColumnSet();
  LayoutMultiColumnSet* third_row = second_row->NextSiblingMultiColumnSet();
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(-10000), LayoutBox::kAssociateWithFormerPage),
            first_row);  // negative overflow
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(-10000), LayoutBox::kAssociateWithLatterPage),
            first_row);  // negative overflow
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(), LayoutBox::kAssociateWithFormerPage),
            first_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(), LayoutBox::kAssociateWithLatterPage),
            first_row);
  LayoutUnit offset(600);
  // The first column row contains 5 lines, split into two columns, i.e. 3 lines
  // in the first and 2 lines in the second. Line height is 100px. There's 100px
  // of unused space at the end of the second column.
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithFormerPage),
            first_row);  // bottom of last line in first row.
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithLatterPage),
            first_row);  // bottom of last line in first row.
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithFormerPage),
            first_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithLatterPage),
            second_row);
  offset += LayoutUnit(200);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithFormerPage),
            second_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithLatterPage),
            second_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithFormerPage),
            second_row);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset, LayoutBox::kAssociateWithLatterPage),
            third_row);
  offset += LayoutUnit(100);
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                offset - LayoutUnit(1), LayoutBox::kAssociateWithLatterPage),
            third_row);  // bottom of last row
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(10000), LayoutBox::kAssociateWithFormerPage),
            third_row);  // overflow
  EXPECT_EQ(flow_thread->ColumnSetAtBlockOffset(
                LayoutUnit(10000), LayoutBox::kAssociateWithLatterPage),
            third_row);  // overflow
}

class MultiColumnTreeModifyingTest : public MultiColumnRenderingTest {
 public:
  void SetMulticolHTML(const char*);
  void ReparentLayoutObject(const char* new_parent_id,
                            const char* child_id,
                            const char* insert_before_id = nullptr);
  void DestroyLayoutObject(LayoutObject* child);
  void DestroyLayoutObject(const char* child_id);
};

void MultiColumnTreeModifyingTest::SetMulticolHTML(const char* html) {
  MultiColumnRenderingTest::SetMulticolHTML(html);
  // Allow modifications to the layout tree structure, because that's what we
  // want to test.
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
}

void MultiColumnTreeModifyingTest::ReparentLayoutObject(
    const char* new_parent_id,
    const char* child_id,
    const char* insert_before_id) {
  LayoutObject* new_parent = GetLayoutObjectByElementId(new_parent_id);
  LayoutObject* child = GetLayoutObjectByElementId(child_id);
  LayoutObject* insert_before =
      insert_before_id ? GetLayoutObjectByElementId(insert_before_id) : nullptr;
  child->Remove();
  new_parent->AddChild(child, insert_before);
}

void MultiColumnTreeModifyingTest::DestroyLayoutObject(LayoutObject* child) {
  // Remove and destroy in separate steps, so that we get to test removal of
  // subtrees.
  child->Remove();
  child->GetNode()->DetachLayoutTree();
}

void MultiColumnTreeModifyingTest::DestroyLayoutObject(const char* child_id) {
  DestroyLayoutObject(GetLayoutObjectByElementId(child_id));
}

TEST_F(MultiColumnTreeModifyingTest, InsertFirstContentAndRemove) {
  SetMulticolHTML("<div id='block'></div><div id='mc'></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  auto* block = To<LayoutBlockFlow>(GetLayoutObjectByElementId("block"));
  auto* multicol_container =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("mc"));
  block->Remove();
  multicol_container->AddChild(block);
  EXPECT_EQ(block->Parent(), flow_thread);
  // A set should have appeared, now that the multicol container has content.
  EXPECT_EQ(ColumnSetSignature(flow_thread), "c");

  DestroyLayoutObject(block);
  // The set should be gone again now, since there's nothing inside the multicol
  // container anymore.
  EXPECT_EQ(ColumnSetSignature("mc"), "");
}

TEST_F(MultiColumnTreeModifyingTest, InsertContentBeforeContentAndRemove) {
  SetMulticolHTML(
      "<div id='block'></div><div id='mc'><div id='insertBefore'></div></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
  ReparentLayoutObject("mc", "block", "insertBefore");
  // There was already some content prior to our insertion, so no new set should
  // be inserted.
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
  DestroyLayoutObject("block");
  // There's still some content after the removal, so the set should remain.
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
}

TEST_F(MultiColumnTreeModifyingTest, InsertContentAfterContentAndRemove) {
  SetMulticolHTML("<div id='block'></div><div id='mc'><div></div></div>");
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
  ReparentLayoutObject("mc", "block");
  // There was already some content prior to our insertion, so no new set should
  // be inserted.
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
  DestroyLayoutObject("block");
  // There's still some content after the removal, so the set should remain.
  EXPECT_EQ(ColumnSetSignature("mc"), "c");
}

TEST_F(MultiColumnTreeModifyingTest, InsertSpannerAndRemove) {
  SetMulticolHTML("<div id='spanner'></div><div id='mc'></div>");
  LayoutMultiColumnFlowThread* flow_thread = FindFlowThread("mc");
  auto* spanner = To<LayoutBlockFlow>(GetLayoutObjectByElementId("spanner"));
  auto* multicol_container =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("mc"));
  spanner->Remove();
  multicol_container->AddChild(spanner);
  EXPECT_EQ(spanner->Parent(), flow_thread);
  // We should now have a spanner placeholder, since we just moved a spanner
  // into the multicol container.
  EXPECT_EQ(ColumnSetSignature(flow_thread), "s");
  DestroyLayoutObject(spanner);
  EXPECT_EQ(ColumnSetSignature(flow_thread), "");
}

TEST_F(MultiColumnTreeModifyingTest, InsertTwoSpannersAndRemove) {
  SetMulticolHTML(
      "<div id='block'>ee<div class='s'></div><div class='s'></div></div><div "
      "id='mc'></div>");
  ReparentLayoutObject("mc", "block");
  EXPECT_EQ(ColumnSetSignature("mc"), "css");
  DestroyLayoutObject("block");
  EXPECT_EQ(ColumnSetSignature("mc"), "");
}

TEST_F(MultiColumnTreeModifyingTest, InsertSpannerAfterContentAndRemove) {
  SetMulticolHTML("<div id='spanner'></div><div id='mc'><div></div></div>");
  ReparentLayoutObject("mc", "spanner");
  // We should now have a spanner placeholder, since we just moved a spanner
  // into the multicol container.
  EXPECT_EQ(ColumnSetSignatu
```