Response:
My thinking process to analyze the provided C++ code snippet and fulfill the user's request goes through these stages:

1. **Understanding the Context:** The user explicitly states the code is from `blink/renderer/core/layout/layout_text_test.cc` within the Chromium Blink engine. This immediately tells me it's a test file focused on the `LayoutText` class. Test files are crucial for verifying the functionality of the class they test.

2. **Identifying the Core Class:** The filename and the `#include` directive for `layout_text.h` confirm that the central class being tested is `LayoutText`. I need to infer the purpose of `LayoutText` based on its usage in the tests. The names of the test methods (like `ContainsCaretOffset`, `GetTextBoxInfo`, `ResolvedTextLength`) provide strong clues.

3. **Analyzing Included Headers:**  The other included headers offer further context:
    * `third_party/blink/renderer/core/dom/pseudo_element.h`: Suggests testing how `LayoutText` interacts with pseudo-elements (like `::before`, `::after`).
    * `third_party/blink/renderer/core/editing/...`: Implies testing features related to text editing, selection, and caret positioning.
    * `third_party/blink/renderer/core/layout/inline/inline_node_data.h`:  Points to testing how `LayoutText` handles inline layout and itemization.
    * `third_party/blink/renderer/core/testing/core_unit_test_helper.h` and `third_party/blink/renderer/platform/testing/font_test_helpers.h`: Indicate this is a unit test environment with tools for setting up test conditions (like the DOM) and controlling font behavior.
    * `testing/gmock/include/gmock/gmock.h` and `testing/gtest/include/gtest/gtest.h`:  These are the core testing frameworks used.

4. **Examining the `LayoutTextTest` Class:** This is the main test fixture. Its methods provide direct insights into the functionalities being tested:
    * `SetBasicBody`, `SetAhemBody`:  Methods for setting up the HTML content under test. The `Ahem` font is a common test font in Blink for predictable layout.
    * `GetLayoutTextById`, `GetBasicText`, `FindFirstLayoutText`:  Helpers to locate the specific `LayoutText` object being tested within the DOM tree.
    * `SetSelectionAndUpdateLayoutSelection`, `GetSelectionRectFor`:  Methods for simulating user selection and retrieving the visual rectangle of the selection.
    * `GetSnapCode`:  A crucial method for testing caret positioning logic. It takes a text with a "|" representing the caret and returns a code indicating the caret's position relative to characters (Before, Contains, After). This strongly suggests testing the boundaries of text elements and how the caret interacts with them.
    * `GetItemsAsString`:  A method for inspecting the inline items within a `LayoutText` object. This indicates testing of the internal representation of text during layout.
    * `CountNumberOfGlyphs`:  Focuses on the number of glyphs, suggesting testing of complex text rendering scenarios, possibly involving different fonts or ligatures.

5. **Analyzing Individual Test Cases:**  The names of the `TEST_F` macros are highly informative:
    * `PrewarmFamily`, `PrewarmFontFace`, `PrewarmGenericFamily`:  Related to font prewarming, an optimization technique.
    * `MapDOMOffsetToTextContentOffset`:  Tests the mapping between DOM offsets (character positions in the HTML source) and text content offsets (character positions in the rendered text). This is essential for editing and selection.
    * `CharacterAfterWhitespaceCollapsing`: Focuses on how whitespace collapsing rules in CSS are handled.
    * `CaretMinMaxOffset`, `ResolvedTextLength`: Tests basic properties of `LayoutText`.
    * `ContainsCaretOffset` (and its variations like `InPre`, `InPreLine`, `WithTrailingSpace`): Extensively tests the core logic of caret positioning, especially around whitespace and line breaks.
    * `GetTextBoxInfo`: Tests the ability to retrieve bounding boxes for different parts of the text, crucial for rendering and hit-testing.
    * `GetTextBoxInfoWith...` (e.g., `CollapsedWhiteSpace`, `GeneratedContent`, `Hidden`, `Ellipsis`):  Tests how `GetTextBoxInfo` behaves in specific, often complex, layout scenarios.
    * `PlainTextInPseudo`: Tests how text content is handled within pseudo-elements when there's no associated DOM node.
    * `IsBeforeAfterNonCollapsedCharacterNoLineWrap`:  Further tests the logic behind `IsBeforeNonCollapsedCharacter` and `IsAfterNonCollapsedCharacter`, crucial for accurate caret placement and boundary detection.

6. **Inferring Functionality and Relationships:** Based on the above analysis, I can infer the following about `LayoutText`:
    * It represents a run of text in the layout tree.
    * It's responsible for handling whitespace collapsing according to CSS rules.
    * It manages caret positioning within the text.
    * It provides information about the visual layout of the text (bounding boxes).
    * It interacts with font rendering.
    * It needs to map between the DOM structure and the rendered text content.

7. **Relating to Web Technologies:**  The connection to JavaScript, HTML, and CSS is evident:
    * **HTML:** The tests manipulate HTML content to set up different layout scenarios. The `id` attributes are used to locate specific elements.
    * **CSS:** CSS properties like `font-size`, `font-family`, `white-space`, `overflow`, `text-overflow`, and pseudo-elements are used to create various layout conditions. The tests verify how `LayoutText` behaves under these conditions.
    * **JavaScript:** While not directly used in *this specific test file*, the functionality being tested is critical for JavaScript interactions. For example, JavaScript code that manipulates the selection or moves the caret relies on the accurate information provided by `LayoutText`.

8. **Formulating Examples:**  Based on the test names and logic, I can create illustrative examples for each area, considering both normal cases and edge cases.

9. **Identifying Potential Errors:** By looking at the tested scenarios (whitespace, line breaks, hidden content, ellipsis), I can anticipate common user and programming errors related to text layout and manipulation.

10. **Structuring the Output:** Finally, I organize the information into the requested sections (Functionality, Relationship to Web Technologies, Logical Reasoning, Common Errors, Summary) to provide a clear and comprehensive answer.

By following these steps, I can effectively analyze the code snippet and provide a detailed explanation of its purpose and related concepts, fulfilling the user's request. The key is to use the available information – filenames, includes, class names, method names, and test case names – to infer the underlying functionalities and their connections to the broader context of the Blink rendering engine.
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/layout_text.h"

#include <numeric>

#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/selection_sample.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node_data.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/testing/font_test_helpers.h"

namespace blink {

using testing::ElementsAre;

namespace {

class LayoutTextTest : public RenderingTest {
 public:
  void SetBasicBody(const char* message) {
    SetBodyInnerHTML(String::Format(
        "<div id='target' style='font-size: 10px;'>%s</div>", message));
  }

  void SetAhemBody(const char* message, const unsigned width) {
    SetBodyInnerHTML(String::Format(
        "<div id='target' style='font: 10px Ahem; width: %uem'>%s</div>", width,
        message));
  }

  LayoutText* GetLayoutTextById(const char* id) {
    return To<LayoutText>(GetLayoutObjectByElementId(id)->SlowFirstChild());
  }

  LayoutText* GetBasicText() { return GetLayoutTextById("target"); }

  void SetSelectionAndUpdateLayoutSelection(const std::string& selection_text) {
    const SelectionInDOMTree selection =
        SelectionSample::SetSelectionText(GetDocument().body(), selection_text);
    UpdateAllLifecyclePhasesForTest();
    Selection().SetSelection(selection, SetSelectionOptions());
    Selection().CommitAppearanceIfNeeded();
  }

  const LayoutText* FindFirstLayoutText() {
    for (const Node& node :
         NodeTraversal::DescendantsOf(*GetDocument().body())) {
      if (node.GetLayoutObject() && node.GetLayoutObject()->IsText())
        return To<LayoutText>(node.GetLayoutObject());
    }
    NOTREACHED();
  }

  PhysicalRect GetSelectionRectFor(const std::string& selection_text) {
    std::stringstream stream;
    stream << "<div style='font: 10px/10px Ahem;'>" << selection_text
           << "</div>";
    SetSelectionAndUpdateLayoutSelection(stream.str());
    const Node* target = GetElementById("target");
    const LayoutObject* layout_object =
        target ? target->GetLayoutObject() : FindFirstLayoutText();
    return layout_object->LocalSelectionVisualRect();
  }

  std::string GetSnapCode(const LayoutText& layout_text,
                          const std::string& caret_text) {
    return GetSnapCode(layout_text,
                       static_cast<unsigned>(caret_text.find('|')));
  }

  std::string GetSnapCode(const char* id, const std::string& caret_text) {
    return GetSnapCode(*GetLayoutTextById(id), caret_text);
  }

  std::string GetSnapCode(const std::string& caret_text) {
    return GetSnapCode(*GetBasicText(), caret_text);
  }

  std::string GetSnapCode(const LayoutText& layout_text, unsigned offset) {
    std::string result(3, '_');
    // Note:: |IsBeforeNonCollapsedCharacter()| and |ContainsCaretOffset()|
    // accept out-of-bound offset but |IsAfterNonCollapsedCharacter()| doesn't.
    result[0] = layout_text.IsBeforeNonCollapsedCharacter(offset) ? 'B' : '-';
    result[1] = layout_text.ContainsCaretOffset(offset) ? 'C' : '-';
    if (offset <= layout_text.TransformedTextLength()) {
      result[2] = layout_text.IsAfterNonCollapsedCharacter(offset) ? 'A' : '-';
    }
    return result;
  }
  static constexpr unsigned kIncludeSnappedWidth = 1;

  std::string GetItemsAsString(const LayoutText& layout_text,
                               int num_glyphs = 0,
                               unsigned flags = 0) {
    if (layout_text.NeedsCollectInlines()) {
      return "LayoutText has NeedsCollectInlines";
    }
    if (!layout_text.HasValidInlineItems()) {
      return "No valid inline items in LayoutText";
    }
    const LayoutBlockFlow& block_flow = *layout_text.FragmentItemsContainer();
    if (block_flow.NeedsCollectInlines()) {
      return "LayoutBlockFlow has NeedsCollectInlines";
    }
    const InlineNodeData& data = *block_flow.GetInlineNodeData();
    std::ostringstream stream;
    for (const InlineItem& item : data.items) {
      if (item.Type() != InlineItem::kText) {
        continue;
      }
      if (item.GetLayoutObject() == layout_text) {
        stream << "*";
      }
      stream << "{'"
             << data.text_content.Substring(item.StartOffset(), item.Length())
                    .Utf8()
             << "'";
      if (const auto* shape_result = item.TextShapeResult()) {
        stream << ", ShapeResult=" << shape_result->StartIndex() << "+"
               << shape_result->NumCharacters();
#if BUILDFLAG(IS_WIN)
        if (shape_result->NumCharacters() != shape_result->NumGlyphs()) {
          stream << " #glyphs=" << shape_result->NumGlyphs();
        }
#else
        // Note: |num_glyphs| depends on installed font, we check only for
        // Windows because most of failures are reported on Windows.
        if (num_glyphs) {
          stream << " #glyphs=" << num_glyphs;
        }
#endif
        if (flags & kIncludeSnappedWidth) {
          stream << " width=" << shape_result->SnappedWidth();
        }
      }
      stream << "}" << std::endl;
    }
    return stream.str();
  }

  unsigned CountNumberOfGlyphs(const LayoutText& layout_text) {
    auto* const items = layout_text.GetInlineItems();
    return std::accumulate(items->begin(), items->end(), 0u,
                           [](unsigned sum, const InlineItem& item) {
                             return sum + item.TextShapeResult()->NumGlyphs();
                           });
  }
};

}  // namespace

#if BUILDFLAG(IS_WIN)
TEST_F(LayoutTextTest, PrewarmFamily) {
  test::ScopedTestFontPrewarmer prewarmer;
  SetBodyInnerHTML(R"HTML(
    <style>
    #container { font-family: testfont; }
    </style>
    <div id="container">text</div>
  )HTML");
  EXPECT_THAT(prewarmer.PrewarmedFamilyNames(), ElementsAre("testfont"));
  LayoutObject* container = GetLayoutObjectByElementId("container");
  EXPECT_TRUE(container->StyleRef()
                  .GetFont()
                  .GetFontDescription()
                  .Family()
                  .IsPrewarmed());
}

// Test `@font-face` fonts are NOT prewarmed.
TEST_F(LayoutTextTest, PrewarmFontFace) {
  test::ScopedTestFontPrewarmer prewarmer;
  SetBodyInnerHTML(R"HTML(
    <style>
    @font-face {
      font-family: testfont;
      src: local(Arial);
    }
    #container { font-family: testfont; }
    </style>
    <div id="container">text</div>
  )HTML");
  EXPECT_THAT(prewarmer.PrewarmedFamilyNames(), ElementsAre());
  LayoutObject* container = GetLayoutObjectByElementId("container");
  EXPECT_FALSE(container->StyleRef()
                   .GetFont()
                   .GetFontDescription()
                   .Family()
                   .IsPrewarmed());
}

TEST_F(LayoutTextTest, PrewarmGenericFamily) {
  test::ScopedTestFontPrewarmer prewarmer;
  SetBodyInnerHTML(R"HTML(
    <style>
    #container { font-family: serif; }
    </style>
    <div id="container">text</div>
  )HTML");
  // No prewarms because |GenericFontFamilySettings| is empty.
  EXPECT_THAT(prewarmer.PrewarmedFamilyNames(), ElementsAre());
  LayoutObject* container = GetLayoutObjectByElementId("container");
  EXPECT_TRUE(container->StyleRef()
                  .GetFont()
                  .GetFontDescription()
                  .Family()
                  .IsPrewarmed());
}
#endif

struct OffsetMappingTestData {
  const char* text;
  unsigned dom_start;
  unsigned dom_end;
  bool success;
  unsigned text_start;
  unsigned text_end;
} offset_mapping_test_data[] = {
    {"<div id=target> a  b  </div>", 0, 1, true, 0, 0},
    {"<div id=target> a  b  </div>", 1, 2, true, 0, 1},
    {"<div id=target> a  b  </div>", 2, 3, true, 1, 2},
    {"<div id=target> a  b  </div>", 2, 4, true, 1, 2},
    {"<div id=target> a  b  </div>", 2, 5, true, 1, 3},
    {"<div id=target> a  b  </div>", 3, 4, true, 2, 2},
    {"<div id=target> a  b  </div>", 3, 5, true, 2, 3},
    {"<div id=target> a  b  </div>", 5, 6, true, 3, 3},
    {"<div id=target> a  b  </div>", 5, 7, true, 3, 3},
    {"<div id=target> a  b  </div>", 6, 7, true, 3, 3},
    {"<div>a <span id=target> </span>b</div>", 0, 1, false, 0, 1}};

std::ostream& operator<<(std::ostream& out, OffsetMappingTestData data) {
  return out << "\"" << data.text << "\" " << data.dom_start << ","
             << data.dom_end << " => " << (data.success ? "true " : "false ")
             << data.text_start << "," << data.text_end;
}

class MapDOMOffsetToTextContentOffset
    : public LayoutTextTest,
      public testing::WithParamInterface<OffsetMappingTestData> {};

INSTANTIATE_TEST_SUITE_P(LayoutTextTest,
                         MapDOMOffsetToTextContentOffset,
                         testing::ValuesIn(offset_mapping_test_data));

TEST_P(MapDOMOffsetToTextContentOffset, Basic) {
  const auto data = GetParam();
  SetBodyInnerHTML(data.text);
  LayoutText* layout_text = GetBasicText();
  const OffsetMapping* mapping = layout_text->GetOffsetMapping();
  ASSERT_TRUE(mapping);
  unsigned start = data.dom_start;
  unsigned end = data.dom_end;
  bool success =
      layout_text->MapDOMOffsetToTextContentOffset(*mapping, &start, &end);
  EXPECT_EQ(data.success, success);
  if (success) {
    EXPECT_EQ(data.text_start, start);
    EXPECT_EQ(data.text_end, end);
  }
}

TEST_F(LayoutTextTest, CharacterAfterWhitespaceCollapsing) {
  SetBodyInnerHTML("a<span id=target> b </span>");
  LayoutText* layout_text = GetLayoutTextById("target");
  EXPECT_EQ(' ', layout_text->FirstCharacterAfterWhitespaceCollapsing());
  EXPECT_EQ('b', layout_text->LastCharacterAfterWhitespaceCollapsing());

  SetBodyInnerHTML("a <span id=target> b </span>");
  layout_text = GetLayoutTextById("target");
  EXPECT_EQ('b', layout_text->FirstCharacterAfterWhitespaceCollapsing());
  EXPECT_EQ('b', layout_text->LastCharacterAfterWhitespaceCollapsing());

  SetBodyInnerHTML("a<span id=target> </span>b");
  layout_text = GetLayoutTextById("target");
  EXPECT_EQ(' ', layout_text->FirstCharacterAfterWhitespaceCollapsing());
  EXPECT_EQ(' ', layout_text->LastCharacterAfterWhitespaceCollapsing());

  SetBodyInnerHTML("a <span id=target> </span>b");
  layout_text = GetLayoutTextById("target");
  DCHECK(!layout_text->HasInlineFragments());
  EXPECT_EQ(0, layout_text->FirstCharacterAfterWhitespaceCollapsing());
  EXPECT_EQ(0, layout_text->LastCharacterAfterWhitespaceCollapsing());

  SetBodyInnerHTML(
      "<span style='white-space: pre'>a <span id=target> </span>b</span>");
  layout_text = GetLayoutTextById("target");
  EXPECT_EQ(' ', layout_text->FirstCharacterAfterWhitespaceCollapsing());
  EXPECT_EQ(' ', layout_text->LastCharacterAfterWhitespaceCollapsing());

  SetBodyInnerHTML("<span id=target>Hello </span> <span>world</span>");
  layout_text = GetLayoutTextById("target");
  EXPECT_EQ('H', layout_text->FirstCharacterAfterWhitespaceCollapsing());
  EXPECT_EQ(' ', layout_text->LastCharacterAfterWhitespaceCollapsing());
  layout_text =
      To<LayoutText>(GetLayoutObjectByElementId("target")->NextSibling());
  DCHECK(!layout_text->HasInlineFragments());
  EXPECT_EQ(0, layout_text->FirstCharacterAfterWhitespaceCollapsing());
  EXPECT_EQ(0, layout_text->LastCharacterAfterWhitespaceCollapsing());

  SetBodyInnerHTML("<b id=target>&#x1F34C;_&#x1F34D;</b>");
  layout_text = GetLayoutTextById("target");
  EXPECT_EQ(0x1F34C, layout_text->FirstCharacterAfterWhitespaceCollapsing());
  EXPECT_EQ(0x1F34D, layout_text->LastCharacterAfterWhitespaceCollapsing());
}

TEST_F(LayoutTextTest, CaretMinMaxOffset) {
  SetBasicBody("foo");
  EXPECT_EQ(0, GetBasicText()->CaretMinOffset());
  EXPECT_EQ(3, GetBasicText()->CaretMaxOffset());

  SetBasicBody("  foo");
  EXPECT_EQ(2, GetBasicText()->CaretMinOffset());
  EXPECT_EQ(5, GetBasicText()->CaretMaxOffset());

  SetBasicBody("foo  ");
  EXPECT_EQ(0, GetBasicText()->CaretMinOffset());
  EXPECT_EQ(3, GetBasicText()->CaretMaxOffset());

  SetBasicBody(" foo  ");
  EXPECT_EQ(1, GetBasicText()->CaretMinOffset());
  EXPECT_EQ(4, GetBasicText()->CaretMaxOffset());
}

TEST_F(LayoutTextTest, ResolvedTextLength) {
  SetBasicBody("foo");
  EXPECT_EQ(3u, GetBasicText()->ResolvedTextLength());

  SetBasicBody("  foo");
  EXPECT_EQ(3u, GetBasicText()->ResolvedTextLength());

  SetBasicBody("foo  ");
  EXPECT_EQ(3u, GetBasicText()->ResolvedTextLength());

  SetBasicBody(" foo  ");
  EXPECT_EQ(3u, GetBasicText()->ResolvedTextLength());
}

TEST_F(LayoutTextTest, ContainsCaretOffset) {
  // This test records the behavior introduced in crrev.com/e3eb4e
  SetBasicBody(" foo   bar ");
  // text_content = "foo bar"
  // offset mapping unit:
  //  [0] = C DOM:0-1 TC:0-0
  //  [1] = I DOM:1-5 TC:0-4 "foo "
  //  [2] = C DOM:5-7 TC:4-4
  //  [3] = I DOM:7-10 TC:4-7 "bar"
  //  [4] = C DOM:10-11 TC:7-7
  EXPECT_EQ("---", GetSnapCode("| foo   bar "));
  EXPECT_EQ("BC-", GetSnapCode(" |foo   bar "));
  EXPECT_EQ("BCA", GetSnapCode(" f|oo   bar "));
  EXPECT_EQ("BCA", GetSnapCode(" fo|o   bar "));
  EXPECT_EQ("BCA", GetSnapCode(" foo|   bar "));
  EXPECT_EQ("-CA", GetSnapCode(" foo |  bar "));
  EXPECT_EQ("---", GetSnapCode(" foo  | bar "));
  EXPECT_EQ("BC-", GetSnapCode(" foo   |bar "));
  EXPECT_EQ("BCA", GetSnapCode(" foo   b|ar "));
  EXPECT_EQ("BCA", GetSnapCode(" foo   ba|r "));
  EXPECT_EQ("-CA", GetSnapCode(" foo   bar| "));
  EXPECT_EQ("---", GetSnapCode(" foo   bar |"));
  EXPECT_EQ("--_", GetSnapCode(*GetBasicText(), 12));  // out of range
}

TEST_F(LayoutTextTest, ContainsCaretOffsetInPre) {
  // These tests record the behavior introduced in crrev.com/e3eb4e
  InsertStyleElement("#target {white-space: pre; }");

  SetBasicBody("foo   bar");
  EXPECT_EQ("BC-", GetSnapCode("|foo   bar"));
  EXPECT_EQ("BCA", GetSnapCode("f|oo   bar"));
  EXPECT_EQ("BCA", GetSnapCode("fo|o   bar"));
  EXPECT_EQ("BCA", GetSnapCode("foo|   bar"));
  EXPECT_EQ("BCA", GetSnapCode("foo |  bar"));
  EXPECT_EQ("BCA", GetSnapCode("foo  | bar"));
  EXPECT_EQ("BCA", GetSnapCode("foo   |bar"));
  EXPECT_EQ("BCA", GetSnapCode("foo   b|ar"));
  EXPECT_EQ("BCA", GetSnapCode("foo   ba|r"));
  EXPECT_EQ("-CA", GetSnapCode("foo   bar|"));

  SetBasicBody("abc\n");
  // text_content = "abc\n"
  // offset mapping unit:
  //  [0] I DOM:0-4 TC:0-4 "abc\n"
  EXPECT_EQ("BC-", GetSnapCode("|abc\n"));
  EXPECT_EQ("BCA", GetSnapCode("a|bc\n"));
  EXPECT_EQ("BCA", GetSnapCode("ab|c\n"));
  EXPECT_EQ("BCA", GetSnapCode("abc|\n"));
  EXPECT_EQ("--A", GetSnapCode("abc\n|"));

  SetBasicBody("foo\nbar");
  EXPECT_EQ("BC-", GetSnapCode("|foo\nbar"));
  EXPECT_EQ("BCA", GetSnapCode("f|oo\nbar"));
  EXPECT_EQ("BCA", GetSnapCode("fo|o\nbar"));
  EXPECT_EQ("BCA", GetSnapCode("foo|\nbar"));
  EXPECT_EQ("BCA", GetSnapCode("foo\n|bar"));
  EXPECT_EQ("BCA", GetSnapCode("foo\nb|ar"));
  EXPECT_EQ("BCA", GetSnapCode("foo\nba|r"));
  EXPECT_EQ("-CA", GetSnapCode("foo\nbar|"));
}

TEST_F(LayoutTextTest, ContainsCaretOffsetInPreLine) {
  InsertStyleElement("#target {white-space: pre-line; }");

  SetBasicBody("ab \n cd");
  // text_content = "ab\ncd"
  // offset mapping unit:
  //  [0] I DOM:0-2 TC:0-2 "ab"
  //  [1] C DOM:2-3 TC:2-2
  //  [2] I DOM:3-4 TC:2-3 "\n"
  //  [3] C DOM:4-5 TC:3-3
  //  [4] I DOM:5-7 TC:3-5 "cd"
  EXPECT_EQ("BC-", GetSnapCode("|ab \n cd"));
  EXPECT_EQ("BCA", GetSnapCode("a|b \n cd"));
  // Before collapsed trailing space.
  EXPECT_EQ("-CA", GetSnapCode("ab| \n cd"));
  // After first trailing space.
  EXPECT_EQ("BC-", GetSnapCode("ab |\n cd"));
  // Before collapsed leading space.
  EXPECT_EQ("--A", GetSnapCode("ab \n| cd"));
  // After collapsed leading space.
  EXPECT_EQ("BC-", GetSnapCode("ab \n |cd"));

  SetBasicBody("ab  \n  cd");
  // text_content = "ab\ncd"
  // offset mapping unit:
  //  [0] I DOM:0-2 TC:0-2 "ab"
  //  [1] C DOM:2-4 TC:2-2
  //  [2] I DOM:4-5 TC:2-3 "\n"
  //  [3] C DOM:5-7 TC:3-3
  //  [4] I DOM:7-9 TC:3-5 "cd"
  EXPECT_EQ("BC-", GetSnapCode("|ab  \n  cd"));
  EXPECT_EQ("BCA", GetSnapCode("a|b  \n  cd"));
  // Before collapsed trailing space.
  EXPECT_EQ("-CA", GetSnapCode("ab|  \n  cd"));
  // After first trailing space.
  EXPECT_EQ("---", GetSnapCode("ab | \n  cd"));
  // After collapsed trailing space.
  EXPECT_EQ("BC-", GetSnapCode("ab  |\n  cd"));
  // Before collapsed leading space.
  EXPECT_EQ("--A", GetSnapCode("ab  \n|  cd"));
  // After collapsed leading space.
  EXPECT_EQ("---", GetSnapCode("ab  \n | cd"));
  EXPECT_EQ("BC-", GetSnapCode("ab  \n  |cd"));
  EXPECT_EQ("BCA", GetSnapCode("ab  \n  c|d"));
  EXPECT_EQ("-CA", GetSnapCode("ab  \n  cd|"));

  SetBasicBody("a\n\nb");
  EXPECT_EQ("BC-", GetSnapCode("|a\n\nb"));
  EXPECT_EQ("BCA", GetSnapCode("a|\n\nb"));
  EXPECT_EQ("BCA", GetSnapCode("a\n|\nb"));
  EXPECT_EQ("BCA", GetSnapCode("a\n\n|b"));
  EXPECT_EQ("-CA", GetSnapCode("a\n\nb|"));

  SetBasicBody("a \n \n b");
  // text_content = "a\n\nb"
  // offset mapping unit:
  //  [0] = I DOM:0-1 TC:0-1 "a"
  //  [1] = C DOM:1-2 TC:1-1
  //  [2] = I DOM:2-3 TC:1-2 "\n"
  //  [3] = C DOM:3-4 TC:2-2
  //  [4] = I DOM:4-5 TC:2-3 "\n"
  //  [5] = C DOM:5-6 TC:3-3
  //  [6] = I DOM:6-7 TC:3-4 "b"
  EXPECT_EQ("BC-", GetSnapCode("|a \n \n b"));
  // Before collapsed trailing space.
  EXPECT_EQ("-CA", GetSnapCode("a| \n \n b"));
  // After first trailing space.
  EXPECT_EQ("BC-", GetSnapCode("a |\n \n b"));
  // Before leading collapsed space.
  EXPECT_EQ("--A", GetSnapCode("a \n| \n b"));
  // After first trailing space.
  EXPECT_EQ("BC-", GetSnapCode("a \n |\n b"));
  // Before collapsed leading space.
  EXPECT_EQ("--A", GetSnapCode("a \n \n| b"));
  // After collapsed leading space.
  EXPECT_EQ("BC-", GetSnapCode("a \n \n |b"));
  EXPECT_EQ("-CA", GetSnapCode("a \n \n b|"));

  SetBasicBody("a \n  \n b");
  // text_content = "a\n\nb"
  // offset mapping unit:
  //  [0] = I DOM:0-1 TC:0-1 "a"
  //  [1] = C DOM:1-2 TC:1-1
  //  [2] = I DOM:2-3 TC:1-2 "\n"
  //  [3] = C DOM:3-5 TC:2-2
  //  [4] = I DOM:5-6 TC:2-3 "\n"
  //  [5] = C DOM:6-7 TC:3-3
  //  [6] = I DOM:7-8 TC:3-4 "b"
  EXPECT_EQ("BC-", GetSnapCode("|a \n  \n b"));
  // Before collapsed trailing space.
  EXPECT_EQ("-CA", GetSnapCode("a| \n  \n b"));
  // After first trailing space.
  EXPECT_EQ("BC-", GetSnapCode("a |\n  \n b"));
  // Before collapsed leading space.
  EXPECT_EQ("--A", GetSnapCode("a \n|  \n b"));
  // After first trailing and in leading space.
  EXPECT_EQ("---", GetSnapCode("a \n | \n b"));
  EXPECT_EQ("BC-", GetSnapCode("a \n  |\n b"));
  // before collapsed leading space.
  EXPECT_EQ("--A", GetSnapCode("a \n  \n| b"));
  // After collapsed leading space.
  EXPECT_EQ("BC-", GetSnapCode("a \n  \n |b"));
  EXPECT_EQ("-CA", GetSnapCode("a \n  \n b|"));
}

TEST_F(LayoutTextTest, ContainsCaretOffsetWithTrailingSpace) {
  SetBodyInnerHTML("<div id=target>ab<br>cd</div>");
  const auto& text_ab = *GetLayoutTextById("target");
  const auto& layout_br = *To<LayoutText>(text_ab.NextSibling());
  const auto& text_cd = *To<LayoutText>(layout_br.NextSibling());

  EXPECT_EQ("BC-", GetSnapCode(text_ab, "|ab<br>"));
  EXPECT_EQ("BCA", GetSnapCode(text_ab, "a|b<br>"));
  EXPECT_EQ("-CA", GetSnapCode(text_ab, "ab|<br>"));
  EXPECT_EQ("BC-", GetSnapCode(layout_br, 0));
  EXPECT_EQ("--A", GetSnapCode(layout_br, 1));
  EXPECT_EQ("BC-", GetSnap
### 提示词
```
这是目录为blink/renderer/core/layout/layout_text_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/layout_text.h"

#include <numeric>

#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/selection_sample.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node_data.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/testing/font_test_helpers.h"

namespace blink {

using testing::ElementsAre;

namespace {

class LayoutTextTest : public RenderingTest {
 public:
  void SetBasicBody(const char* message) {
    SetBodyInnerHTML(String::Format(
        "<div id='target' style='font-size: 10px;'>%s</div>", message));
  }

  void SetAhemBody(const char* message, const unsigned width) {
    SetBodyInnerHTML(String::Format(
        "<div id='target' style='font: 10px Ahem; width: %uem'>%s</div>", width,
        message));
  }

  LayoutText* GetLayoutTextById(const char* id) {
    return To<LayoutText>(GetLayoutObjectByElementId(id)->SlowFirstChild());
  }

  LayoutText* GetBasicText() { return GetLayoutTextById("target"); }

  void SetSelectionAndUpdateLayoutSelection(const std::string& selection_text) {
    const SelectionInDOMTree selection =
        SelectionSample::SetSelectionText(GetDocument().body(), selection_text);
    UpdateAllLifecyclePhasesForTest();
    Selection().SetSelection(selection, SetSelectionOptions());
    Selection().CommitAppearanceIfNeeded();
  }

  const LayoutText* FindFirstLayoutText() {
    for (const Node& node :
         NodeTraversal::DescendantsOf(*GetDocument().body())) {
      if (node.GetLayoutObject() && node.GetLayoutObject()->IsText())
        return To<LayoutText>(node.GetLayoutObject());
    }
    NOTREACHED();
  }

  PhysicalRect GetSelectionRectFor(const std::string& selection_text) {
    std::stringstream stream;
    stream << "<div style='font: 10px/10px Ahem;'>" << selection_text
           << "</div>";
    SetSelectionAndUpdateLayoutSelection(stream.str());
    const Node* target = GetElementById("target");
    const LayoutObject* layout_object =
        target ? target->GetLayoutObject() : FindFirstLayoutText();
    return layout_object->LocalSelectionVisualRect();
  }

  std::string GetSnapCode(const LayoutText& layout_text,
                          const std::string& caret_text) {
    return GetSnapCode(layout_text,
                       static_cast<unsigned>(caret_text.find('|')));
  }

  std::string GetSnapCode(const char* id, const std::string& caret_text) {
    return GetSnapCode(*GetLayoutTextById(id), caret_text);
  }

  std::string GetSnapCode(const std::string& caret_text) {
    return GetSnapCode(*GetBasicText(), caret_text);
  }

  std::string GetSnapCode(const LayoutText& layout_text, unsigned offset) {
    std::string result(3, '_');
    // Note:: |IsBeforeNonCollapsedCharacter()| and |ContainsCaretOffset()|
    // accept out-of-bound offset but |IsAfterNonCollapsedCharacter()| doesn't.
    result[0] = layout_text.IsBeforeNonCollapsedCharacter(offset) ? 'B' : '-';
    result[1] = layout_text.ContainsCaretOffset(offset) ? 'C' : '-';
    if (offset <= layout_text.TransformedTextLength()) {
      result[2] = layout_text.IsAfterNonCollapsedCharacter(offset) ? 'A' : '-';
    }
    return result;
  }
  static constexpr unsigned kIncludeSnappedWidth = 1;

  std::string GetItemsAsString(const LayoutText& layout_text,
                               int num_glyphs = 0,
                               unsigned flags = 0) {
    if (layout_text.NeedsCollectInlines()) {
      return "LayoutText has NeedsCollectInlines";
    }
    if (!layout_text.HasValidInlineItems()) {
      return "No valid inline items in LayoutText";
    }
    const LayoutBlockFlow& block_flow = *layout_text.FragmentItemsContainer();
    if (block_flow.NeedsCollectInlines()) {
      return "LayoutBlockFlow has NeedsCollectInlines";
    }
    const InlineNodeData& data = *block_flow.GetInlineNodeData();
    std::ostringstream stream;
    for (const InlineItem& item : data.items) {
      if (item.Type() != InlineItem::kText) {
        continue;
      }
      if (item.GetLayoutObject() == layout_text) {
        stream << "*";
      }
      stream << "{'"
             << data.text_content.Substring(item.StartOffset(), item.Length())
                    .Utf8()
             << "'";
      if (const auto* shape_result = item.TextShapeResult()) {
        stream << ", ShapeResult=" << shape_result->StartIndex() << "+"
               << shape_result->NumCharacters();
#if BUILDFLAG(IS_WIN)
        if (shape_result->NumCharacters() != shape_result->NumGlyphs()) {
          stream << " #glyphs=" << shape_result->NumGlyphs();
        }
#else
        // Note: |num_glyphs| depends on installed font, we check only for
        // Windows because most of failures are reported on Windows.
        if (num_glyphs) {
          stream << " #glyphs=" << num_glyphs;
        }
#endif
        if (flags & kIncludeSnappedWidth) {
          stream << " width=" << shape_result->SnappedWidth();
        }
      }
      stream << "}" << std::endl;
    }
    return stream.str();
  }

  unsigned CountNumberOfGlyphs(const LayoutText& layout_text) {
    auto* const items = layout_text.GetInlineItems();
    return std::accumulate(items->begin(), items->end(), 0u,
                           [](unsigned sum, const InlineItem& item) {
                             return sum + item.TextShapeResult()->NumGlyphs();
                           });
  }
};

}  // namespace

#if BUILDFLAG(IS_WIN)
TEST_F(LayoutTextTest, PrewarmFamily) {
  test::ScopedTestFontPrewarmer prewarmer;
  SetBodyInnerHTML(R"HTML(
    <style>
    #container { font-family: testfont; }
    </style>
    <div id="container">text</div>
  )HTML");
  EXPECT_THAT(prewarmer.PrewarmedFamilyNames(), ElementsAre("testfont"));
  LayoutObject* container = GetLayoutObjectByElementId("container");
  EXPECT_TRUE(container->StyleRef()
                  .GetFont()
                  .GetFontDescription()
                  .Family()
                  .IsPrewarmed());
}

// Test `@font-face` fonts are NOT prewarmed.
TEST_F(LayoutTextTest, PrewarmFontFace) {
  test::ScopedTestFontPrewarmer prewarmer;
  SetBodyInnerHTML(R"HTML(
    <style>
    @font-face {
      font-family: testfont;
      src: local(Arial);
    }
    #container { font-family: testfont; }
    </style>
    <div id="container">text</div>
  )HTML");
  EXPECT_THAT(prewarmer.PrewarmedFamilyNames(), ElementsAre());
  LayoutObject* container = GetLayoutObjectByElementId("container");
  EXPECT_FALSE(container->StyleRef()
                   .GetFont()
                   .GetFontDescription()
                   .Family()
                   .IsPrewarmed());
}

TEST_F(LayoutTextTest, PrewarmGenericFamily) {
  test::ScopedTestFontPrewarmer prewarmer;
  SetBodyInnerHTML(R"HTML(
    <style>
    #container { font-family: serif; }
    </style>
    <div id="container">text</div>
  )HTML");
  // No prewarms because |GenericFontFamilySettings| is empty.
  EXPECT_THAT(prewarmer.PrewarmedFamilyNames(), ElementsAre());
  LayoutObject* container = GetLayoutObjectByElementId("container");
  EXPECT_TRUE(container->StyleRef()
                  .GetFont()
                  .GetFontDescription()
                  .Family()
                  .IsPrewarmed());
}
#endif

struct OffsetMappingTestData {
  const char* text;
  unsigned dom_start;
  unsigned dom_end;
  bool success;
  unsigned text_start;
  unsigned text_end;
} offset_mapping_test_data[] = {
    {"<div id=target> a  b  </div>", 0, 1, true, 0, 0},
    {"<div id=target> a  b  </div>", 1, 2, true, 0, 1},
    {"<div id=target> a  b  </div>", 2, 3, true, 1, 2},
    {"<div id=target> a  b  </div>", 2, 4, true, 1, 2},
    {"<div id=target> a  b  </div>", 2, 5, true, 1, 3},
    {"<div id=target> a  b  </div>", 3, 4, true, 2, 2},
    {"<div id=target> a  b  </div>", 3, 5, true, 2, 3},
    {"<div id=target> a  b  </div>", 5, 6, true, 3, 3},
    {"<div id=target> a  b  </div>", 5, 7, true, 3, 3},
    {"<div id=target> a  b  </div>", 6, 7, true, 3, 3},
    {"<div>a <span id=target> </span>b</div>", 0, 1, false, 0, 1}};

std::ostream& operator<<(std::ostream& out, OffsetMappingTestData data) {
  return out << "\"" << data.text << "\" " << data.dom_start << ","
             << data.dom_end << " => " << (data.success ? "true " : "false ")
             << data.text_start << "," << data.text_end;
}

class MapDOMOffsetToTextContentOffset
    : public LayoutTextTest,
      public testing::WithParamInterface<OffsetMappingTestData> {};

INSTANTIATE_TEST_SUITE_P(LayoutTextTest,
                         MapDOMOffsetToTextContentOffset,
                         testing::ValuesIn(offset_mapping_test_data));

TEST_P(MapDOMOffsetToTextContentOffset, Basic) {
  const auto data = GetParam();
  SetBodyInnerHTML(data.text);
  LayoutText* layout_text = GetBasicText();
  const OffsetMapping* mapping = layout_text->GetOffsetMapping();
  ASSERT_TRUE(mapping);
  unsigned start = data.dom_start;
  unsigned end = data.dom_end;
  bool success =
      layout_text->MapDOMOffsetToTextContentOffset(*mapping, &start, &end);
  EXPECT_EQ(data.success, success);
  if (success) {
    EXPECT_EQ(data.text_start, start);
    EXPECT_EQ(data.text_end, end);
  }
}

TEST_F(LayoutTextTest, CharacterAfterWhitespaceCollapsing) {
  SetBodyInnerHTML("a<span id=target> b </span>");
  LayoutText* layout_text = GetLayoutTextById("target");
  EXPECT_EQ(' ', layout_text->FirstCharacterAfterWhitespaceCollapsing());
  EXPECT_EQ('b', layout_text->LastCharacterAfterWhitespaceCollapsing());

  SetBodyInnerHTML("a <span id=target> b </span>");
  layout_text = GetLayoutTextById("target");
  EXPECT_EQ('b', layout_text->FirstCharacterAfterWhitespaceCollapsing());
  EXPECT_EQ('b', layout_text->LastCharacterAfterWhitespaceCollapsing());

  SetBodyInnerHTML("a<span id=target> </span>b");
  layout_text = GetLayoutTextById("target");
  EXPECT_EQ(' ', layout_text->FirstCharacterAfterWhitespaceCollapsing());
  EXPECT_EQ(' ', layout_text->LastCharacterAfterWhitespaceCollapsing());

  SetBodyInnerHTML("a <span id=target> </span>b");
  layout_text = GetLayoutTextById("target");
  DCHECK(!layout_text->HasInlineFragments());
  EXPECT_EQ(0, layout_text->FirstCharacterAfterWhitespaceCollapsing());
  EXPECT_EQ(0, layout_text->LastCharacterAfterWhitespaceCollapsing());

  SetBodyInnerHTML(
      "<span style='white-space: pre'>a <span id=target> </span>b</span>");
  layout_text = GetLayoutTextById("target");
  EXPECT_EQ(' ', layout_text->FirstCharacterAfterWhitespaceCollapsing());
  EXPECT_EQ(' ', layout_text->LastCharacterAfterWhitespaceCollapsing());

  SetBodyInnerHTML("<span id=target>Hello </span> <span>world</span>");
  layout_text = GetLayoutTextById("target");
  EXPECT_EQ('H', layout_text->FirstCharacterAfterWhitespaceCollapsing());
  EXPECT_EQ(' ', layout_text->LastCharacterAfterWhitespaceCollapsing());
  layout_text =
      To<LayoutText>(GetLayoutObjectByElementId("target")->NextSibling());
  DCHECK(!layout_text->HasInlineFragments());
  EXPECT_EQ(0, layout_text->FirstCharacterAfterWhitespaceCollapsing());
  EXPECT_EQ(0, layout_text->LastCharacterAfterWhitespaceCollapsing());

  SetBodyInnerHTML("<b id=target>&#x1F34C;_&#x1F34D;</b>");
  layout_text = GetLayoutTextById("target");
  EXPECT_EQ(0x1F34C, layout_text->FirstCharacterAfterWhitespaceCollapsing());
  EXPECT_EQ(0x1F34D, layout_text->LastCharacterAfterWhitespaceCollapsing());
}

TEST_F(LayoutTextTest, CaretMinMaxOffset) {
  SetBasicBody("foo");
  EXPECT_EQ(0, GetBasicText()->CaretMinOffset());
  EXPECT_EQ(3, GetBasicText()->CaretMaxOffset());

  SetBasicBody("  foo");
  EXPECT_EQ(2, GetBasicText()->CaretMinOffset());
  EXPECT_EQ(5, GetBasicText()->CaretMaxOffset());

  SetBasicBody("foo  ");
  EXPECT_EQ(0, GetBasicText()->CaretMinOffset());
  EXPECT_EQ(3, GetBasicText()->CaretMaxOffset());

  SetBasicBody(" foo  ");
  EXPECT_EQ(1, GetBasicText()->CaretMinOffset());
  EXPECT_EQ(4, GetBasicText()->CaretMaxOffset());
}

TEST_F(LayoutTextTest, ResolvedTextLength) {
  SetBasicBody("foo");
  EXPECT_EQ(3u, GetBasicText()->ResolvedTextLength());

  SetBasicBody("  foo");
  EXPECT_EQ(3u, GetBasicText()->ResolvedTextLength());

  SetBasicBody("foo  ");
  EXPECT_EQ(3u, GetBasicText()->ResolvedTextLength());

  SetBasicBody(" foo  ");
  EXPECT_EQ(3u, GetBasicText()->ResolvedTextLength());
}

TEST_F(LayoutTextTest, ContainsCaretOffset) {
  // This test records the behavior introduced in crrev.com/e3eb4e
  SetBasicBody(" foo   bar ");
  // text_content = "foo bar"
  // offset mapping unit:
  //  [0] = C DOM:0-1 TC:0-0
  //  [1] = I DOM:1-5 TC:0-4 "foo "
  //  [2] = C DOM:5-7 TC:4-4
  //  [3] = I DOM:7-10 TC:4-7 "bar"
  //  [4] = C DOM:10-11 TC:7-7
  EXPECT_EQ("---", GetSnapCode("| foo   bar "));
  EXPECT_EQ("BC-", GetSnapCode(" |foo   bar "));
  EXPECT_EQ("BCA", GetSnapCode(" f|oo   bar "));
  EXPECT_EQ("BCA", GetSnapCode(" fo|o   bar "));
  EXPECT_EQ("BCA", GetSnapCode(" foo|   bar "));
  EXPECT_EQ("-CA", GetSnapCode(" foo |  bar "));
  EXPECT_EQ("---", GetSnapCode(" foo  | bar "));
  EXPECT_EQ("BC-", GetSnapCode(" foo   |bar "));
  EXPECT_EQ("BCA", GetSnapCode(" foo   b|ar "));
  EXPECT_EQ("BCA", GetSnapCode(" foo   ba|r "));
  EXPECT_EQ("-CA", GetSnapCode(" foo   bar| "));
  EXPECT_EQ("---", GetSnapCode(" foo   bar |"));
  EXPECT_EQ("--_", GetSnapCode(*GetBasicText(), 12));  // out of range
}

TEST_F(LayoutTextTest, ContainsCaretOffsetInPre) {
  // These tests record the behavior introduced in crrev.com/e3eb4e
  InsertStyleElement("#target {white-space: pre; }");

  SetBasicBody("foo   bar");
  EXPECT_EQ("BC-", GetSnapCode("|foo   bar"));
  EXPECT_EQ("BCA", GetSnapCode("f|oo   bar"));
  EXPECT_EQ("BCA", GetSnapCode("fo|o   bar"));
  EXPECT_EQ("BCA", GetSnapCode("foo|   bar"));
  EXPECT_EQ("BCA", GetSnapCode("foo |  bar"));
  EXPECT_EQ("BCA", GetSnapCode("foo  | bar"));
  EXPECT_EQ("BCA", GetSnapCode("foo   |bar"));
  EXPECT_EQ("BCA", GetSnapCode("foo   b|ar"));
  EXPECT_EQ("BCA", GetSnapCode("foo   ba|r"));
  EXPECT_EQ("-CA", GetSnapCode("foo   bar|"));

  SetBasicBody("abc\n");
  // text_content = "abc\n"
  // offset mapping unit:
  //  [0] I DOM:0-4 TC:0-4 "abc\n"
  EXPECT_EQ("BC-", GetSnapCode("|abc\n"));
  EXPECT_EQ("BCA", GetSnapCode("a|bc\n"));
  EXPECT_EQ("BCA", GetSnapCode("ab|c\n"));
  EXPECT_EQ("BCA", GetSnapCode("abc|\n"));
  EXPECT_EQ("--A", GetSnapCode("abc\n|"));

  SetBasicBody("foo\nbar");
  EXPECT_EQ("BC-", GetSnapCode("|foo\nbar"));
  EXPECT_EQ("BCA", GetSnapCode("f|oo\nbar"));
  EXPECT_EQ("BCA", GetSnapCode("fo|o\nbar"));
  EXPECT_EQ("BCA", GetSnapCode("foo|\nbar"));
  EXPECT_EQ("BCA", GetSnapCode("foo\n|bar"));
  EXPECT_EQ("BCA", GetSnapCode("foo\nb|ar"));
  EXPECT_EQ("BCA", GetSnapCode("foo\nba|r"));
  EXPECT_EQ("-CA", GetSnapCode("foo\nbar|"));
}

TEST_F(LayoutTextTest, ContainsCaretOffsetInPreLine) {
  InsertStyleElement("#target {white-space: pre-line; }");

  SetBasicBody("ab \n cd");
  // text_content = "ab\ncd"
  // offset mapping unit:
  //  [0] I DOM:0-2 TC:0-2 "ab"
  //  [1] C DOM:2-3 TC:2-2
  //  [2] I DOM:3-4 TC:2-3 "\n"
  //  [3] C DOM:4-5 TC:3-3
  //  [4] I DOM:5-7 TC:3-5 "cd"
  EXPECT_EQ("BC-", GetSnapCode("|ab \n cd"));
  EXPECT_EQ("BCA", GetSnapCode("a|b \n cd"));
  // Before collapsed trailing space.
  EXPECT_EQ("-CA", GetSnapCode("ab| \n cd"));
  // After first trailing space.
  EXPECT_EQ("BC-", GetSnapCode("ab |\n cd"));
  // Before collapsed leading space.
  EXPECT_EQ("--A", GetSnapCode("ab \n| cd"));
  // After collapsed leading space.
  EXPECT_EQ("BC-", GetSnapCode("ab \n |cd"));

  SetBasicBody("ab  \n  cd");
  // text_content = "ab\ncd"
  // offset mapping unit:
  //  [0] I DOM:0-2 TC:0-2 "ab"
  //  [1] C DOM:2-4 TC:2-2
  //  [2] I DOM:4-5 TC:2-3 "\n"
  //  [3] C DOM:5-7 TC:3-3
  //  [4] I DOM:7-9 TC:3-5 "cd"
  EXPECT_EQ("BC-", GetSnapCode("|ab  \n  cd"));
  EXPECT_EQ("BCA", GetSnapCode("a|b  \n  cd"));
  // Before collapsed trailing space.
  EXPECT_EQ("-CA", GetSnapCode("ab|  \n  cd"));
  // After first trailing space.
  EXPECT_EQ("---", GetSnapCode("ab | \n  cd"));
  // After collapsed trailing space.
  EXPECT_EQ("BC-", GetSnapCode("ab  |\n  cd"));
  // Before collapsed leading space.
  EXPECT_EQ("--A", GetSnapCode("ab  \n|  cd"));
  // After collapsed leading space.
  EXPECT_EQ("---", GetSnapCode("ab  \n | cd"));
  EXPECT_EQ("BC-", GetSnapCode("ab  \n  |cd"));
  EXPECT_EQ("BCA", GetSnapCode("ab  \n  c|d"));
  EXPECT_EQ("-CA", GetSnapCode("ab  \n  cd|"));

  SetBasicBody("a\n\nb");
  EXPECT_EQ("BC-", GetSnapCode("|a\n\nb"));
  EXPECT_EQ("BCA", GetSnapCode("a|\n\nb"));
  EXPECT_EQ("BCA", GetSnapCode("a\n|\nb"));
  EXPECT_EQ("BCA", GetSnapCode("a\n\n|b"));
  EXPECT_EQ("-CA", GetSnapCode("a\n\nb|"));

  SetBasicBody("a \n \n b");
  // text_content = "a\n\nb"
  // offset mapping unit:
  //  [0] = I DOM:0-1 TC:0-1 "a"
  //  [1] = C DOM:1-2 TC:1-1
  //  [2] = I DOM:2-3 TC:1-2 "\n"
  //  [3] = C DOM:3-4 TC:2-2
  //  [4] = I DOM:4-5 TC:2-3 "\n"
  //  [5] = C DOM:5-6 TC:3-3
  //  [6] = I DOM:6-7 TC:3-4 "b"
  EXPECT_EQ("BC-", GetSnapCode("|a \n \n b"));
  // Before collapsed trailing space.
  EXPECT_EQ("-CA", GetSnapCode("a| \n \n b"));
  // After first trailing space.
  EXPECT_EQ("BC-", GetSnapCode("a |\n \n b"));
  // Before leading collapsed space.
  EXPECT_EQ("--A", GetSnapCode("a \n| \n b"));
  // After first trailing space.
  EXPECT_EQ("BC-", GetSnapCode("a \n |\n b"));
  // Before collapsed leading space.
  EXPECT_EQ("--A", GetSnapCode("a \n \n| b"));
  // After collapsed leading space.
  EXPECT_EQ("BC-", GetSnapCode("a \n \n |b"));
  EXPECT_EQ("-CA", GetSnapCode("a \n \n b|"));

  SetBasicBody("a \n  \n b");
  // text_content = "a\n\nb"
  // offset mapping unit:
  //  [0] = I DOM:0-1 TC:0-1 "a"
  //  [1] = C DOM:1-2 TC:1-1
  //  [2] = I DOM:2-3 TC:1-2 "\n"
  //  [3] = C DOM:3-5 TC:2-2
  //  [4] = I DOM:5-6 TC:2-3 "\n"
  //  [5] = C DOM:6-7 TC:3-3
  //  [6] = I DOM:7-8 TC:3-4 "b"
  EXPECT_EQ("BC-", GetSnapCode("|a \n  \n b"));
  // Before collapsed trailing space.
  EXPECT_EQ("-CA", GetSnapCode("a| \n  \n b"));
  // After first trailing space.
  EXPECT_EQ("BC-", GetSnapCode("a |\n  \n b"));
  // Before collapsed leading space.
  EXPECT_EQ("--A", GetSnapCode("a \n|  \n b"));
  // After first trailing and in leading space.
  EXPECT_EQ("---", GetSnapCode("a \n | \n b"));
  EXPECT_EQ("BC-", GetSnapCode("a \n  |\n b"));
  // before collapsed leading space.
  EXPECT_EQ("--A", GetSnapCode("a \n  \n| b"));
  // After collapsed leading space.
  EXPECT_EQ("BC-", GetSnapCode("a \n  \n |b"));
  EXPECT_EQ("-CA", GetSnapCode("a \n  \n b|"));
}

TEST_F(LayoutTextTest, ContainsCaretOffsetWithTrailingSpace) {
  SetBodyInnerHTML("<div id=target>ab<br>cd</div>");
  const auto& text_ab = *GetLayoutTextById("target");
  const auto& layout_br = *To<LayoutText>(text_ab.NextSibling());
  const auto& text_cd = *To<LayoutText>(layout_br.NextSibling());

  EXPECT_EQ("BC-", GetSnapCode(text_ab, "|ab<br>"));
  EXPECT_EQ("BCA", GetSnapCode(text_ab, "a|b<br>"));
  EXPECT_EQ("-CA", GetSnapCode(text_ab, "ab|<br>"));
  EXPECT_EQ("BC-", GetSnapCode(layout_br, 0));
  EXPECT_EQ("--A", GetSnapCode(layout_br, 1));
  EXPECT_EQ("BC-", GetSnapCode(text_cd, "|cd"));
  EXPECT_EQ("BCA", GetSnapCode(text_cd, "c|d"));
  EXPECT_EQ("-CA", GetSnapCode(text_cd, "cd|"));
}

TEST_F(LayoutTextTest, ContainsCaretOffsetWithTrailingSpace1) {
  SetBodyInnerHTML("<div id=target>ab <br> cd</div>");
  const auto& text_ab = *GetLayoutTextById("target");
  const auto& layout_br = *To<LayoutText>(text_ab.NextSibling());
  const auto& text_cd = *To<LayoutText>(layout_br.NextSibling());

  // text_content = "ab\ncd"
  // offset mapping unit:
  //  [0] I DOM:0-2 TC:0-2 "ab"
  //  [1] C DOM:2-3 TC:2-2
  //  [2] I DOM:0-1 TC:2-3 "\n" <br>
  //  [3] C DOM:0-1 TC:3-3
  //  [4] I DOM:1-3 TC:3-5 "cd"
  EXPECT_EQ("BC-", GetSnapCode(text_ab, "|ab <br>"));
  EXPECT_EQ("BCA", GetSnapCode(text_ab, "a|b <br>"));
  // Before after first trailing space.
  EXPECT_EQ("-CA", GetSnapCode(text_ab, "ab| <br>"));
  // After first trailing space.
  EXPECT_EQ("---", GetSnapCode(text_ab, "ab |<br>"));
  EXPECT_EQ("BC-", GetSnapCode(layout_br, 0));
  EXPECT_EQ("--A", GetSnapCode(layout_br, 1));
  EXPECT_EQ("---", GetSnapCode(text_cd, "| cd"));
  EXPECT_EQ("BC-", GetSnapCode(text_cd, " |cd"));
  EXPECT_EQ("BCA", GetSnapCode(text_cd, " c|d"));
  EXPECT_EQ("-CA", GetSnapCode(text_cd, " cd|"));
}

TEST_F(LayoutTextTest, ContainsCaretOffsetWithTrailingSpace2) {
  SetBodyInnerHTML("<div id=target>ab  <br>  cd</div>");
  const auto& text_ab = *GetLayoutTextById("target");
  const auto& layout_br = *To<LayoutText>(text_ab.NextSibling());
  const auto& text_cd = *To<LayoutText>(layout_br.NextSibling());

  // text_content = "ab\ncd"
  // offset mapping unit:
  //  [0] I DOM:0-2 TC:0-2 "ab"
  //  [1] C DOM:2-4 TC:2-2
  //  [2] I DOM:0-1 TC:2-3 "\n" <br>
  //  [3] C DOM:0-2 TC:3-3
  //  [4] I DOM:2-4 TC:3-5 "cd"
  EXPECT_EQ("BC-", GetSnapCode(text_ab, "|ab  <br>"));
  EXPECT_EQ("BCA", GetSnapCode(text_ab, "a|b  <br>"));
  // After first trailing space.
  EXPECT_EQ("-CA", GetSnapCode(text_ab, "ab|  <br>"));
  // After first trailing space.
  EXPECT_EQ("---", GetSnapCode(text_ab, "ab | <br>"));
  EXPECT_EQ("---", GetSnapCode(text_ab, "ab  |<br>"));
  // Before <br>.
  EXPECT_EQ("BC-", GetSnapCode(layout_br, 0));
  // After <br>.
  EXPECT_EQ("--A", GetSnapCode(layout_br, 1));
  EXPECT_EQ("---", GetSnapCode(text_cd, "|  cd"));
  EXPECT_EQ("---", GetSnapCode(text_cd, " | cd"));
  EXPECT_EQ("BC-", GetSnapCode(text_cd, "  |cd"));
  EXPECT_EQ("BCA", GetSnapCode(text_cd, "  c|d"));
  EXPECT_EQ("-CA", GetSnapCode(text_cd, "  cd|"));
}

TEST_F(LayoutTextTest, ContainsCaretOffsetWithTrailingSpace3) {
  SetBodyInnerHTML("<div id=target>a<br>   <br>b<br></div>");
  const auto& text_a = *GetLayoutTextById("target");
  const auto& layout_br1 = *To<LayoutText>(text_a.NextSibling());
  const auto& text_space = *To<LayoutText>(layout_br1.NextSibling());
  EXPECT_EQ(1u, text_space.TransformedTextLength());
  const auto& layout_br2 = *To<LayoutText>(text_space.NextSibling());
  const auto& text_b = *To<LayoutText>(layout_br2.NextSibling());
  // Note: the last <br> doesn't have layout object.

  // text_content = "a\n \nb"
  // offset mapping unit:
  //  [0] I DOM:0-1 TC:0-1 "a"
  EXPECT_EQ("BC-", GetSnapCode(text_a, "|a<br>"));
  EXPECT_EQ("-CA", GetSnapCode(text_a, "a|<br>"));
  EXPECT_EQ("-CA", GetSnapCode(text_a, "a|<br>"));
  EXPECT_EQ("BC-", GetSnapCode(layout_br1, 0));
  EXPECT_EQ("--A", GetSnapCode(layout_br1, 1));
  EXPECT_EQ("BC-", GetSnapCode(text_space, 0));
  EXPECT_EQ("--A", GetSnapCode(text_space, 1));
  EXPECT_EQ("BC-", GetSnapCode(layout_br2, 0));
  EXPECT_EQ("-CA", GetSnapCode(layout_br2, 1));
  EXPECT_EQ("BC-", GetSnapCode(text_b, "|b<br>"));
  EXPECT_EQ("--A", GetSnapCode(text_b, "b|<br>"));
}

TEST_F(LayoutTextTest, GetTextBoxInfoWithCollapsedWhiteSpace) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>pre { font: 10px/1 Ahem; white-space: pre-line; }</style>
    <pre id=target> abc  def
    xyz   </pre>)HTML");
  const LayoutText& layout_text = *GetLayoutTextById("target");

  const auto& results = layout_text.GetTextBoxInfo();

  ASSERT_EQ(4u, results.size());

  EXPECT_EQ(1u, results[0].dom_start_offset);
  EXPECT_EQ(4u, results[0].dom_length);
  EXPECT_EQ(PhysicalRect(0, 0, 40, 10), results[0].local_rect);

  EXPECT_EQ(6u, results[1].dom_start_offset);
  EXPECT_EQ(3u, results[1].dom_length);
  EXPECT_EQ(PhysicalRect(40, 0, 30, 10), results[1].local_rect);

  EXPECT_EQ(9u, results[2].dom_start_offset);
  EXPECT_EQ(1u, results[2].dom_length);
  EXPECT_EQ(PhysicalRect(70, 0, 0, 10), results[2].local_rect);

  EXPECT_EQ(14u, results[3].dom_start_offset);
  EXPECT_EQ(3u, results[3].dom_length);
  EXPECT_EQ(PhysicalRect(0, 10, 30, 10), results[3].local_rect);
}

TEST_F(LayoutTextTest, GetTextBoxInfoWithGeneratedContent) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      div::before { content: '  a   bc'; }
      div::first-letter { font-weight: bold; }
      div { font: 10px/1 Ahem; }
    </style>
    <div id="target">XYZ</div>)HTML");
  const Element& target = *GetElementById("target");
  const Element& before =
      *GetElementById("target")->GetPseudoElement(kPseudoIdBefore);
  const auto& layout_text_xyz =
      *To<LayoutText>(target.firstChild()->GetLayoutObject());
  const auto& layout_text_remaining =
      To<LayoutText>(*before.GetLayoutObject()->SlowLastChild());
  const LayoutText& layout_text_first_letter =
      *layout_text_remaining.GetFirstLetterPart();

  auto boxes_xyz = layout_text_xyz.GetTextBoxInfo();
  EXPECT_EQ(1u, boxes_xyz.size());
  EXPECT_EQ(0u, boxes_xyz[0].dom_start_offset);
  EXPECT_EQ(3u, boxes_xyz[0].dom_length);
  EXPECT_EQ(PhysicalRect(40, 0, 30, 10), boxes_xyz[0].local_rect);

  auto boxes_first_letter = layout_text_first_letter.GetTextBoxInfo();
  EXPECT_EQ(1u, boxes_first_letter.size());
  EXPECT_EQ(2u, boxes_first_letter[0].dom_start_offset);
  EXPECT_EQ(1u, boxes_first_letter[0].dom_length);
  EXPECT_EQ(PhysicalRect(0, 0, 10, 10), boxes_first_letter[0].local_rect);

  auto boxes_remaining = layout_text_remaining.GetTextBoxInfo();
  EXPECT_EQ(2u, boxes_remaining.size());
  EXPECT_EQ(0u, boxes_remaining[0].dom_start_offset);
  EXPECT_EQ(1u, boxes_remaining[0].dom_length) << "two spaces to one space";
  EXPECT_EQ(PhysicalRect(10, 0, 10, 10), boxes_remaining[0].local_rect);
  EXPECT_EQ(3u, boxes_remaining[1].dom_start_offset);
  EXPECT_EQ(2u, boxes_remaining[1].dom_length);
  EXPECT_EQ(PhysicalRect(20, 0, 20, 10), boxes_remaining[1].local_rect);
}

// For http://crbug.com/985488
TEST_F(LayoutTextTest, GetTextBoxInfoWithHidden) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      #target {
        font: 10px/1 Ahem;
        overflow-x: hidden;
        white-space: nowrap;
        width: 9ch;
      }
    </style>
    <div id="target">  abcde  fghij  </div>
  )HTML");
  const Element& target = *GetElementById("target");
  const LayoutText& layout_text =
      *To<Text>(target.firstChild())->GetLayoutObject();

  auto boxes = layout_text.GetTextBoxInfo();
  EXPECT_EQ(2u, boxes.size());

  EXPECT_EQ(2u, boxes[0].dom_start_offset);
  EXPECT_EQ(6u, boxes[0].dom_length);
  EXPECT_EQ(PhysicalRect(0, 0, 60, 10), boxes[0].local_rect);

  EXPECT_EQ(9u, boxes[1].dom_start_offset);
  EXPECT_EQ(5u, boxes[1].dom_length);
  EXPECT_EQ(PhysicalRect(60, 0, 50, 10), boxes[1].local_rect);
}

// For http://crbug.com/985488
TEST_F(LayoutTextTest, GetTextBoxInfoWithEllipsis) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      #target {
        font: 10px/1 Ahem;
        overflow-x: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        width: 9ch;
      }
    </style>
    <div id="target">  abcde  fghij  </div>
  )HTML");
  const Element& target = *GetElementById("target");
  const LayoutText& layout_text =
      *To<Text>(target.firstChild())->GetLayoutObject();

  auto boxes = layout_text.GetTextBoxInfo();
  EXPECT_EQ(2u, boxes.size());

  EXPECT_EQ(2u, boxes[0].dom_start_offset);
  EXPECT_EQ(6u, boxes[0].dom_length);
  EXPECT_EQ(PhysicalRect(0, 0, 60, 10), boxes[0].local_rect);

  EXPECT_EQ(9u, boxes[1].dom_start_offset);
  EXPECT_EQ(5u, boxes[1].dom_length);
  EXPECT_EQ(PhysicalRect(60, 0, 50, 10), boxes[1].local_rect);
}

// For http://crbug.com/1003413
TEST_F(LayoutTextTest, GetTextBoxInfoWithEllipsisForPseudoAfter) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      #sample {
        box-sizing: border-box;
        font: 10px/1 Ahem;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        width: 5ch;
      }
      b::after { content: ","; }
    </style>
    <div id=sample><b id=target>abc</b><b>xyz</b></div>
  )HTML");
  const Element& target = *GetElementById("target");
  const Element& after = *target.GetPseudoElement(kPseudoIdAfter);
  // Set |layout_text| to "," in <pseudo::after>,</pseudo::after>
  const auto& layout_text =
      *To<LayoutText>(after.GetLayoutObject()->SlowFirstChild());

  auto boxes = layout_text.GetTextBoxInfo();
  EXPECT_EQ(1u, boxes.size());

  EXPECT_EQ(0u, boxes[0].dom_start_offset);
  EXPECT_EQ(1u, boxes[0].dom_length);
  EXPECT_EQ(PhysicalRect(30, 0, 10, 10), boxes[0].local_rect);
}

// Test the specialized code path in |PlainText| for when |!GetNode()|.
TEST_F(LayoutTextTest, PlainTextInPseudo) {
  SetBodyInnerHTML(String(R"HTML(
    <style>
    :root {
      font-family: monospace;
      font-size: 10px;
    }
    #before_parent::before {
      display: inline-block;
      width: 5ch;
      content: "123 456";
    }
    #before_parent_cjk::before {
      display: inline-block;
      width: 5ch;
      content: "123)HTML") +
                   String(u"\u4E00") + R"HTML(456";
    }
    </style>
    <div id="before_parent"></div>
    <div id="before_parent_cjk"></div>
  )HTML");

  const auto GetPlainText = [](const LayoutObject* parent) {
    const LayoutObject* before = parent->SlowFirstChild();
    EXPECT_TRUE(before->IsBeforeContent());
    const auto* before_text = To<LayoutText>(before->SlowFirstChild());
    EXPECT_FALSE(before_text->GetNode());
    return before_text->PlainText();
  };

  const LayoutObject* before_parent =
      GetLayoutObjectByElementId("before_parent");
  EXPECT_EQ("123 456", GetPlainText(before_parent));
  const LayoutObject* before_parent_cjk =
      GetLayoutObjectByElementId("before_parent_cjk");
  EXPECT_EQ(String(u"123\u4E00456"), GetPlainText(before_parent_cjk));
}

TEST_F(LayoutTextTest, IsBeforeAfterNonCollapsedCharacterNoLineWrap) {
  // Basic tests
  SetBasicBody("foo");
  EXPECT_EQ("BC-", GetSnapCode("|foo"));
  EXPECT_EQ("BCA", GetSnapCode("f|oo"));
  EXPECT_EQ("BCA", GetSnapCode("fo|o"));
  EXPECT_EQ("-CA", GetSnapCode("foo|"));

  // Consecutive spaces are collapsed into one
  SetBasicBody("f   bar");
  EXPECT_EQ("BC-", GetSnapCode("|f   bar"));
  EXPECT_EQ("BCA", GetSnapCode("f|   bar"));
  EXPECT_EQ("-CA", GetSnapCode("f |  bar"));
  EXPECT_EQ("---", GetSnapCode("f  | bar"));
  EXPECT_EQ("BC-", GetSnapCode("f   |bar"));
  EXPECT_EQ("BCA", GetSnapCode("f   b|ar"));
  EXPECT_EQ("BCA", GetSnapCode("f   ba|r"));
  EXPECT_EQ("-CA", GetSnapCode("f   bar|"));

  // Leading spaces in a block are collapsed
  SetBasicBody("  foo");
  EXPECT_EQ("---", GetSnapCode("|  foo"));
  EXPECT_EQ("---", GetSnapCode(" | foo"));
  EXPECT_EQ("BC-", GetSnapCode("  |foo"));
  EXPECT_EQ("BCA", GetSnapCode("  f|oo"));
  EXPECT_EQ("BCA", GetSnapCode("  fo|o"));
  EXPECT_EQ("-CA", GetSnapCode("  foo|"));

  // Trailing spaces in a block are collapsed
  SetBasicBody("foo  ");
  EXPECT_EQ("BC-", GetSnapCode("|foo  "));
  EXPECT_EQ("BCA", GetSnapCode("f|oo  "));
  EXPECT_EQ("BCA", GetSnapCode("fo|o  "));
  EXPECT_EQ("-CA", GetSnapCode("foo|  "));
  EXPECT_EQ("---", GetSnapCode("foo | "));
  EXPECT_EQ("---", GetSnapCode("foo  |"));

  // Non-collapsed space at node end
  SetBasicBody("foo <span>bar</span>");
  EXPECT_EQ("BC-", GetSnapCode("|foo "));
  EXPECT_EQ("BCA", GetSnapCode("f|oo "));
  EXPECT_EQ("BCA", GetSnapCode("fo|o "));
  EXPECT_EQ("BCA", GetSnapCode("foo| "));
  EXPECT_EQ("-CA", GetSnapCode("foo |"));

  // Non-collapsed space at node start
  SetBasicBody("foo<span id=bar> bar</span>");
  EXPECT_EQ("BC-", GetSnapCode("bar", "| bar"));
  EXPECT_EQ("BCA", GetSnapCode("bar", " |bar"));
  EXPECT_EQ("BCA", GetSnapCode("bar", " b|ar"));
  EXPECT_EQ("BCA", GetSnapCode("bar", " ba|r"));
  EXPECT_EQ("-CA", GetSnapCode("bar", " bar|"));

  // Consecutive spaces across nodes
  SetBasicBody("foo <span id=bar> bar</span>");
  // text_content = "foo bar"
  // [0] I DOM:0-4 TC:0-4 "foo "
  // [1] C DOM:0-1 TC:4-4 " bar"
  // [2] I DOM:1-4 TC:4-7 " bar"
  EXPECT_EQ("BC-", GetSnapCode("|foo "));
  EXPECT_EQ("BCA", GetSnapCode("f|oo "));
  EXPECT_EQ("BCA", GetSnapCode("fo|o "));
  EXPECT_EQ("BCA", GetSnapCode("foo| "));
  EXPECT_EQ("-CA", GetSnapCode("foo |"));
  EXPECT_EQ("---", GetSnapCode("bar", "| bar"));
  EXPECT_EQ("BC-", GetSnapCode("bar", " |bar"));
  EXPECT_EQ("BCA", GetSnapCode("bar", " b|ar"));
  EXPECT_EQ("BCA", GetSnapCode("bar", " ba|r"));
  EXPECT_EQ("-CA", GetSnapCode("bar", " bar|"));

  // Non-collapsed whitespace te
```