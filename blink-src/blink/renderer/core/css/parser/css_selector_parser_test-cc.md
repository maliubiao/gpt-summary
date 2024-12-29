Response:
The user wants me to analyze a C++ source code file for the Chromium Blink engine. Specifically, the file is `css_selector_parser_test.cc`. I need to identify the purpose of this file, explain its relationship to web technologies like JavaScript, HTML, and CSS, provide examples of its behavior, describe common user/programming errors it might catch, and outline how a user's actions could lead to this code being executed.

Here's a breakdown of my plan:

1. **Identify the Core Function:** Based on the file name and included headers, this file contains tests for the `CSSSelectorParser`. This parser is responsible for taking CSS selector strings and converting them into an internal representation that the browser can understand and use for styling.

2. **Relate to Web Technologies:**
    * **CSS:** This is the most direct relationship. The parser's job is to understand CSS selectors. I'll give examples of CSS selectors being parsed.
    * **HTML:** CSS selectors target elements in the HTML document. The parsed selectors are used to match elements in the DOM. I'll explain this connection.
    * **JavaScript:** While this file doesn't directly interact with JavaScript, JavaScript can manipulate the DOM and CSS styles, potentially leading to the CSS parser being invoked. I'll give an example of JavaScript dynamically adding or modifying CSS rules.

3. **Provide Examples (Hypothetical Input/Output):** I'll pick some of the `TEST_P` and `TEST` cases from the code and explain what they are testing. I'll show an example of a valid selector and its expected parsed form, and an example of an invalid selector and the expected failure.

4. **Common Errors:** I'll analyze the negative test cases (those that expect `EXPECT_EQ(vector.size(), 0u)`) and identify common CSS selector syntax errors that users might make, such as invalid combinations of pseudo-elements and other selectors.

5. **User Actions Leading Here (Debugging Clues):** I'll describe the typical user workflow that involves CSS, starting from writing CSS rules in a stylesheet or `<style>` tag, and how the browser's rendering engine uses the `CSSSelectorParser` to apply those styles.

6. **Summarize Functionality (for Part 1):** I'll create a concise summary of the file's purpose as a test suite for the CSS selector parsing logic.```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/parser/css_selector_parser.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_selector.h"
#include "third_party/blink/renderer/core/css/css_selector_list.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

typedef struct {
  const char* input;
  const int a;
  const int b;
} ANPlusBTestCase;

struct SelectorTestCase {
  // The input string to parse as a selector list.
  const char* input;

  // The expected serialization of the parsed selector list. If nullptr, then
  // the expected serialization is the same as the input value.
  //
  // For selector list that are expected to fail parsing, use the empty
  // string "".
  const char* expected = nullptr;
};

class SelectorParseTest : public ::testing::TestWithParam<SelectorTestCase> {};

TEST_P(SelectorParseTest, Parse) {
  auto param = GetParam();
  SCOPED_TRACE(param.input);
  CSSSelectorList* list = css_test_helpers::ParseSelectorList(param.input);
  const char* expected = param.expected ? param.expected : param.input;
  EXPECT_EQ(String(expected), list->SelectorsText());
}

TEST(CSSSelectorParserTest, ValidANPlusB) {
  test::TaskEnvironment task_environment;
  ANPlusBTestCase test_cases[] = {
      {"odd", 2, 1},
      {"OdD", 2, 1},
      {"even", 2, 0},
      {"EveN", 2, 0},
      {"0", 0, 0},
      {"8", 0, 8},
      {"+12", 0, 12},
      {"-14", 0, -14},

      {"0n", 0, 0},
      {"16N", 16, 0},
      {"-19n", -19, 0},
      {"+23n", 23, 0},
      {"n", 1, 0},
      {"N", 1, 0},
      {"+n", 1, 0},
      {"-n", -1, 0},
      {"-N", -1, 0},

      {"6n-3", 6, -3},
      {"-26N-33", -26, -33},
      {"n-18", 1, -18},
      {"+N-5", 1, -5},
      {"-n-7", -1, -7},

      {"0n+0", 0, 0},
      {"10n+5", 10, 5},
      {"10N +5", 10, 5},
      {"10n -5", 10, -5},
      {"N+6", 1, 6},
      {"n +6", 1, 6},
      {"+n -7", 1, -7},
      {"-N -8", -1, -8},
      {"-n+9", -1, 9},

      {"33N- 22", 33, -22},
      {"+n- 25", 1, -25},
      {"N- 46", 1, -46},
      {"n- 0", 1, 0},
      {"-N- 951", -1, -951},
      {"-n- 951", -1, -951},

      {"29N + 77", 29, 77},
      {"29n - 77", 29, -77},
      {"+n + 61", 1, 61},
      {"+N - 63", 1, -63},
      {"+n/**/- 48", 1, -48},
      {"-n + 81", -1, 81},
      {"-N - 88", -1, -88},

      {"3091970736n + 1", std::numeric_limits<int>::max(), 1},
      {"-3091970736n + 1", std::numeric_limits<int>::min(), 1},
      // B is calculated as +ve first, then negated.
      {"N- 3091970736", 1, -std::numeric_limits<int>::max()},
      {"N+ 3091970736", 1, std::numeric_limits<int>::max()},
  };

  for (auto test_case : test_cases) {
    SCOPED_TRACE(test_case.input);

    std::pair<int, int> ab;
    CSSParserTokenStream stream(test_case.input);
    bool passed = CSSSelectorParser::ConsumeANPlusB(stream, ab);
    EXPECT_TRUE(passed);
    EXPECT_EQ(test_case.a, ab.first);
    EXPECT_EQ(test_case.b, ab.second);
  }
}

TEST(CSSSelectorParserTest, InvalidANPlusB) {
  test::TaskEnvironment task_environment;
  // Some of these have token range prefixes which are valid <an+b> and could
  // in theory be valid in consumeANPlusB, but this behaviour isn't needed
  // anywhere and not implemented.
  const char* test_cases[] = {
      " odd",     "+ n",     "3m+4",  "12n--34",  "12n- -34",
      "12n- +34", "23n-+43", "10n 5", "10n + +5", "10n + -5",
  };

  for (String test_case : test_cases) {
    SCOPED_TRACE(test_case);

    std::pair<int, int> ab;
    CSSParserTokenStream stream(test_case);
    bool passed = CSSSelectorParser::ConsumeANPlusB(stream, ab);
    EXPECT_FALSE(passed);
  }
}

TEST(CSSSelectorParserTest, PseudoElementsInCompoundLists) {
  test::TaskEnvironment task_environment;
  const char* test_cases[] = {":not(::before)",
                              ":not(::content)",
                              ":host(::before)",
                              ":host(::content)",
                              ":host-context(::before)",
                              ":host-context(::content)",
                              ":-webkit-any(::after, ::before)",
                              ":-webkit-any(::content, span)"};

  HeapVector<CSSSelector> arena;
  for (StringView test_case : test_cases) {
    CSSParserTokenStream stream(test_case);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream,
        MakeGarbageCollected<CSSParserContext>(
            kHTMLStandardMode, SecureContextMode::kInsecureContext),
        CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
        /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
    EXPECT_EQ(vector.size(), 0u);
  }
}

TEST(CSSSelectorParserTest, ValidSimpleAfterPseudoElementInCompound) {
  test::TaskEnvironment task_environment;
  const char* test_cases[] = {"::-webkit-volume-slider:hover",
                              "::selection:window-inactive",
                              "::search-text:current",
                              "::search-text:not(:current)",
                              "::-webkit-scrollbar:disabled",
                              "::-webkit-volume-slider:not(:hover)",
                              "::-webkit-scrollbar:not(:horizontal)",
                              "::slotted(span)::before",
                              "::slotted(div)::after",
                              "::slotted(div)::view-transition"};

  HeapVector<CSSSelector> arena;
  for (StringView test_case : test_cases) {
    SCOPED_TRACE(test_case);
    CSSParserTokenStream stream(test_case);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream,
        MakeGarbageCollected<CSSParserContext>(
            kHTMLStandardMode, SecureContextMode::kInsecureContext),
        CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
        /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
    EXPECT_GT(vector.size(), 0u);
  }
}

TEST(CSSSelectorParserTest, InvalidSimpleAfterPseudoElementInCompound) {
  test::TaskEnvironment task_environment;
  const char* test_cases[] = {
      "::before#id",
      "::after:hover",
      ".class::content::before",
      "::shadow.class",
      "::selection:window-inactive::before",
      "::search-text.class",
      "::search-text::before",
      "::search-text:hover",
      "::-webkit-volume-slider.class",
      "::before:not(.a)",
      "::shadow:not(::after)",
      "::-webkit-scrollbar:vertical:not(:first-child)",
      "video::-webkit-media-text-track-region-container.scrolling",
      "div ::before.a",
      "::slotted(div):hover",
      "::slotted(div)::slotted(span)",
      "::slotted(div)::before:hover",
      "::slotted(div)::before::slotted(span)",
      "::slotted(*)::first-letter",
      "::slotted(.class)::first-line",
      "::slotted([attr])::-webkit-scrollbar"};

  HeapVector<CSSSelector> arena;
  for (StringView test_case : test_cases) {
    CSSParserTokenStream stream(test_case);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream,
        MakeGarbageCollected<CSSParserContext>(
            kHTMLStandardMode, SecureContextMode::kInsecureContext),
        CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
        /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
    EXPECT_EQ(vector.size(), 0u);
  }
}

TEST(CSSSelectorParserTest, TransitionPseudoStyles) {
  test::TaskEnvironment task_environment;
  struct TestCase {
    const char* selector;
    bool valid;
    const char* argument;
    CSSSelector::PseudoType type;
  };

  TestCase test_cases[] = {
      {"html::view-transition-group(*)", true, nullptr,
       CSSSelector::kPseudoViewTransitionGroup},
      {"html::view-transition-group(foo)", true, "foo",
       CSSSelector::kPseudoViewTransitionGroup},
      {"html::view-transition-image-pair(foo)", true, "foo",
       CSSSelector::kPseudoViewTransitionImagePair},
      {"html::view-transition-old(foo)", true, "foo",
       CSSSelector::kPseudoViewTransitionOld},
      {"html::view-transition-new(foo)", true, "foo",
       CSSSelector::kPseudoViewTransitionNew},
      {"::view-transition-group(foo)", true, "foo",
       CSSSelector::kPseudoViewTransitionGroup},
      {"div::view-transition-group(*)", true, nullptr,
       CSSSelector::kPseudoViewTransitionGroup},
      {"::view-transition-group(*)::before", false, nullptr,
       CSSSelector::kPseudoUnknown},
      {"::view-transition-group(*):hover", false, nullptr,
       CSSSelector::kPseudoUnknown},
  };

  HeapVector<CSSSelector> arena;
  for (const auto& test_case : test_cases) {
    SCOPED_TRACE(test_case.selector);
    CSSParserTokenStream stream(test_case.selector);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream,
        MakeGarbageCollected<CSSParserContext>(
            kHTMLStandardMode, SecureContextMode::kInsecureContext),
        CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
        /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
    EXPECT_EQ(!vector.empty(), test_case.valid);
    if (!test_case.valid) {
      continue;
    }

    CSSSelectorList* list = CSSSelectorList::AdoptSelectorVector(vector);
    ASSERT_TRUE(list->IsSingleComplexSelector());

    auto* selector = list->First();
    while (selector->NextSimpleSelector()) {
      selector = selector->NextSimpleSelector();
    }

    EXPECT_EQ(selector->GetPseudoType(), test_case.type);
    EXPECT_EQ(selector->GetPseudoType() == CSSSelector::kPseudoViewTransition
                  ? selector->Argument()
                  : selector->IdentList()[0],
              test_case.argument);
  }
}

TEST(CSSSelectorParserTest, WorkaroundForInvalidCustomPseudoInUAStyle) {
  test::TaskEnvironment task_environment;
  // See crbug.com/578131
  const char* test_cases[] = {
      "video::-webkit-media-text-track-region-container.scrolling",
      "input[type=\"range\" i]::-webkit-media-slider-container > div"};

  HeapVector<CSSSelector> arena;
  for (StringView test_case : test_cases) {
    CSSParserTokenStream stream(test_case);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream,
        MakeGarbageCollected<CSSParserContext>(
            kUASheetMode, SecureContextMode::kInsecureContext),
        CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
        /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
    EXPECT_GT(vector.size(), 0u);
  }
}

TEST(CSSSelectorParserTest, InvalidPseudoElementInNonRightmostCompound) {
  test::TaskEnvironment task_environment;
  const char* test_cases[] = {"::-webkit-volume-slider *", "::before *",
                              "::-webkit-scrollbar *", "::cue *",
                              "::selection *"};

  HeapVector<CSSSelector> arena;
  for (StringView test_case : test_cases) {
    CSSParserTokenStream stream(test_case);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream,
        MakeGarbageCollected<CSSParserContext>(
            kHTMLStandardMode, SecureContextMode::kInsecureContext),
        CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
        /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
    EXPECT_EQ(vector.size(), 0u);
  }
}

TEST(CSSSelectorParserTest, UnresolvedNamespacePrefix) {
  test::TaskEnvironment task_environment;
  const char* test_cases[] = {"ns|div", "div ns|div", "div ns|div "};

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);

  HeapVector<CSSSelector> arena;
  for (StringView test_case : test_cases) {
    CSSParserTokenStream stream(test_case);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream, context, CSSNestingType::kNone,
        /*parent_rule_for_nesting=*/nullptr, /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, sheet, arena);
    EXPECT_EQ(vector.size(), 0u);
  }
}

TEST(CSSSelectorParserTest, UnexpectedPipe) {
  test::TaskEnvironment task_environment;
  const char* test_cases[] = {"div | .c", "| div", " | div"};

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);

  HeapVector<CSSSelector> arena;
  for (StringView test_case : test_cases) {
    CSSParserTokenStream stream(test_case);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream, context, CSSNestingType::kNone,
        /*parent_rule_for_nesting=*/nullptr, /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, sheet, arena);
    EXPECT_EQ(vector.size(), 0u);
  }
}

TEST(CSSSelectorParserTest, SerializedUniversal) {
  test::TaskEnvironment task_environment;
  struct SerializationTestCase {
    const char* source;
    const char* expected;
  };
  const SerializationTestCase test_cases[] = {
      {"*::-webkit-volume-slider", "::-webkit-volume-slider"},
      {"*::cue(i)", "::cue(i)"},
      {"*:host-context(.x)", "*:host-context(.x)"},
      {"*:host", "*:host"},
      {"|*::-webkit-volume-slider", "|*::-webkit-volume-slider"},
      {"|*::cue(i)", "|*::cue(i)"},
      {"*|*::-webkit-volume-slider", "::-webkit-volume-slider"},
      {"*|*::cue(i)", "::cue(i)"},
      {"ns|*::-webkit-volume-slider", "ns|*::-webkit-volume-slider"},
      {"ns|*::cue(i)", "ns|*::cue(i)"}};

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  sheet->ParserAddNamespace(AtomicString("ns"), AtomicString("http://ns.org"));

  HeapVector<CSSSelector> arena;
  for (const SerializationTestCase& test_case : test_cases) {
    SCOPED_TRACE(test_case.source);
    CSSParserTokenStream stream(test_case.source);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream, context, CSSNestingType::kNone,
        /*parent_rule_for_nesting=*/nullptr, /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, sheet, arena);
    CSSSelectorList* list = CSSSelectorList::AdoptSelectorVector(vector);
    EXPECT_TRUE(list->IsValid());
    EXPECT_EQ(test_case.expected, list->SelectorsText());
  }
}

TEST(CSSSelectorParserTest, AttributeSelectorUniversalInvalid) {
  test::TaskEnvironment task_environment;
  const char* test_cases[] = {"[*]", "[*|*]"};

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);

  HeapVector<CSSSelector> arena;
  for (String test_case : test_cases) {
    SCOPED_TRACE(test_case);
    CSSParserTokenStream stream(test_case);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream, context, CSSNestingType::kNone,
        /*parent_rule_for_nesting=*/nullptr, /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, sheet, arena);
    EXPECT_EQ(vector.size(), 0u);
  }
}

TEST(CSSSelectorParserTest, InternalPseudo) {
  test::TaskEnvironment task_environment;
  const char* test_cases[] = {"::-internal-whatever",
                              "::-internal-media-controls-text-track-list",
                              ":-internal-is-html",
                              ":-internal-list-box",
                              ":-internal-multi-select-focus",
                              ":-internal-shadow-host-has-non-auto-appearance",
                              ":-internal-spatial-navigation-focus",
                              ":-internal-video-persistent",
                              ":-internal-video-persistent-ancestor"};

  HeapVector<CSSSelector> arena;
  for (String test_case : test_cases) {
    SCOPED_TRACE(test_case);
    {
      CSSParserTokenStream stream(test_case);
      base::span<CSSSelector> author_vector = CSSSelectorParser::ParseSelector(
          stream,
          MakeGarbageCollected<CSSParserContext>(
              kHTMLStandardMode, SecureContextMode::kInsecureContext),
          CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
          /*is_within_scope=*/false,
          /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
      EXPECT_EQ(author_vector.size(), 0u);
    }

    {
      CSSParserTokenStream stream(test_case);
      base::span<CSSSelector> ua_vector = CSSSelectorParser::ParseSelector(
          stream,
          MakeGarbageCollected<CSSParserContext>(
              kUASheetMode, SecureContextMode::kInsecureContext),
          CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
          /*is_within_scope=*/false,
          /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
      EXPECT_GT(ua_vector.size(), 0u);
    }
  }
}

TEST(CSSSelectorParserTest, ScrollControlPseudos) {
  test::TaskEnvironment task_environment;
  struct TestCase {
    const char* selector;
    CSSSelector::PseudoType type;
  };

  TestCase test_cases[] = {
      {"ul::scroll-marker-group", CSSSelector::kPseudoScrollMarkerGroup},
      {"li::scroll-marker", CSSSelector::kPseudoScrollMarker},
      {"div::scroll-next-button", CSSSelector::kPseudoScrollNextButton},
      {"div::scroll-prev-button", CSSSelector::kPseudoScrollPrevButton},
  };

  HeapVector<CSSSelector> arena;
  for (const auto& test_case : test_cases) {
    SCOPED_TRACE(test_case.selector);
    CSSParserTokenStream stream(test_case.selector);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream,
        MakeGarbageCollected<CSSParserContext>(
            kHTMLStandardMode, SecureContextMode::kInsecureContext),
        CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
        /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
    EXPECT_TRUE(!vector.empty());

    CSSSelectorList* list = CSSSelectorList::AdoptSelectorVector(vector);
    ASSERT_TRUE(list->IsSingleComplexSelector());

    const CSSSelector* selector = list->First();
    while (selector->NextSimpleSelector()) {
      selector = selector->NextSimpleSelector();
    }

    EXPECT_EQ(selector->GetPseudoType(), test_case.type);
  }
}

TEST(CSSSelectorParserTest, ColumnPseudo) {
  test::TaskEnvironment task_environment;
  struct TestCase {
    const char* selector;
    CSSSelector::PseudoType type;
  };

  TestCase test_cases[] = {
      {".scroller::column", CSSSelector::kPseudoColumn},
      {"#scroller::column", CSSSelector::kPseudoColumn},
      {"div::column", CSSSelector::kPseudoColumn},
      {"div::before::column", CSSSelector::kPseudoUnknown},
      {"div::after::column", CSSSelector::kPseudoUnknown},
  };

  HeapVector<CSSSelector> arena;
  for (const auto& test_case : test_cases) {
    SCOPED_TRACE(test_case.selector);
    CSSParserTokenStream stream(StringView(test_case.selector));
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream,
        MakeGarbageCollected<CSSParserContext>(
            kHTMLStandardMode, SecureContextMode::kInsecureContext),
        CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
        /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, nullptr, arena);

    if (test_case.type == CSSSelector::kPseudoUnknown) {
      EXPECT_TRUE(vector.empty());
      return;
    }

    EXPECT_TRUE(!vector.empty());

    CSSSelectorList* list = CSSSelectorList::AdoptSelectorVector(vector);
    ASSERT_TRUE(list->IsSingleComplexSelector());

    const CSSSelector* selector = list->First();
    while (selector->NextSimpleSelector()) {
      selector = selector->NextSimpleSelector();
    }

    EXPECT_EQ(selector->GetPseudoType(), test_case.type);
  }
}

// Pseudo-elements are not valid within :is() as per the spec:
// https://drafts.csswg.org/selectors-4/#matches
static const SelectorTestCase invalid_pseudo_is_argments_data[] = {
    // clang-format off
    {":is(::-webkit-progress-bar)", ":is()"},
    {":is(::-webkit-progress-value)", ":is()"},
    {":is(::-webkit-slider-runnable-track)", ":is()"},
    {":is(::-webkit-slider-thumb)", ":is()"},
    {":is(::after)", ":is()"},
    {":is(::backdrop)", ":is()"},
    {":is(::before)", ":is()"},
    {":is(::cue)", ":is()"},
    {":is(::first-letter)", ":is()"},
    {":is(::first-line)", ":is()"},
    {":is(::grammar-error)", ":is()"},
    {":is(::marker)", ":is()"},
    {":is(::placeholder)", ":is()"},
    {":is(::selection)", ":is()"},
    {":is(::slotted)", ":is()"},
    {":is(::spelling-error)", ":is()"},
    {":is(:after)", ":is()"},
    {":is(:before)", ":is()"},
    {":is(:cue)", ":is()"},
    {":is(:first-letter)", ":is()"},
    {":is(:first-line)", ":is()"},
    // If the selector is nest-containing, it serializes as-is:
    // https://drafts.csswg.org/css-nesting-1/#syntax
    {":is(:unknown(&))"},
    // clang-format on
};

INSTANTIATE_TEST_SUITE_P(InvalidPseudoIsArguments,
                         SelectorParseTest,
                         testing::ValuesIn(invalid_pseudo_is_argments_data));

static const SelectorTestCase is_where_nesting_data[] = {
    // clang-format off
    // These pseudos only accept compound selectors:
    {"::slotted(:is(.a .b))", "::slotted(:is())"},
    {"::slotted(:is(.a + .b))", "::slotted(:is())"},
    {"::slotted(:is(.a, .b + .c))", "::slotted(:is(.a))"},
    {":host(:is(.a .b))", ":host(:is())"},
    {":host(:is(.a + .b))", ":host(:is())"},
    {":host(:is(.a, .b + .c))", ":host(:is(.a))"},
    {":host-context(:is(.a .b))", ":host-context(:is())"},
    {":host-context(:is(.a + .b))", ":host-context(:is())"},
    {":host-context(:is(.a, .b + .c))", ":host-context(:is(.a))"},
    {"::cue(:is(.a .b))", "::cue(:is())"},
    {"::cue(:is(.a + .b))", "::cue(:is())"},
    {"::cue(:is(.a, .b + .c))", "::cue(:is(.a))"},
    // Structural pseudos are not allowed after ::part().
    {"::part(foo):is(.a)", "::part(foo):is()"},
    {"::part(foo):is(.a:hover)", "::part(foo):is()"},
    {"::part(foo):is(:hover.a)", "::part(foo):is()"},
    {"::part(foo):is(:hover + .a)", "::part(foo):is()"},
    {"::part(foo):is(.a + :hover)", "::part(foo):is()"},
    {"::part(foo):is(:hover:first-child)", "::part(foo):is()"},
    {"::part(foo):is(:first-child:hover)", "::part(foo):is()"},
    {"::part(foo):is(:hover, :where(.a))",
     "::part(foo):is(:hover, :where())"},
    {"::part(foo):is(:hover, .a)", "::part(foo):is(:hover)"},
    {"::part(foo):is(:state(bar), .a)", "::part(foo):is(:state(bar))"},
    {"::part(foo):is(:first-child)", "::part(foo):is()"},
    // Only scrollbar pseudos after kPseudoScrollbar:
    {"::-webkit-scrollbar:is(:focus)", "::-webkit-scrollbar:is()"},
    // Only :window-inactive after kPseudoSelection:
    {"::selection:is(:focus)", "::selection:is()"},
    // Only user-action pseudos after webkit pseudos:
    {"::-webkit-input-placeholder:is(:enabled)",
     "::-webkit-input-placeholder:is()"},
    {"::-webkit-input-placeholder:is(:not(:enabled))",
Prompt: 
```
这是目录为blink/renderer/core/css/parser/css_selector_parser_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/parser/css_selector_parser.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_selector.h"
#include "third_party/blink/renderer/core/css/css_selector_list.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

typedef struct {
  const char* input;
  const int a;
  const int b;
} ANPlusBTestCase;

struct SelectorTestCase {
  // The input string to parse as a selector list.
  const char* input;

  // The expected serialization of the parsed selector list. If nullptr, then
  // the expected serialization is the same as the input value.
  //
  // For selector list that are expected to fail parsing, use the empty
  // string "".
  const char* expected = nullptr;
};

class SelectorParseTest : public ::testing::TestWithParam<SelectorTestCase> {};

TEST_P(SelectorParseTest, Parse) {
  auto param = GetParam();
  SCOPED_TRACE(param.input);
  CSSSelectorList* list = css_test_helpers::ParseSelectorList(param.input);
  const char* expected = param.expected ? param.expected : param.input;
  EXPECT_EQ(String(expected), list->SelectorsText());
}

TEST(CSSSelectorParserTest, ValidANPlusB) {
  test::TaskEnvironment task_environment;
  ANPlusBTestCase test_cases[] = {
      {"odd", 2, 1},
      {"OdD", 2, 1},
      {"even", 2, 0},
      {"EveN", 2, 0},
      {"0", 0, 0},
      {"8", 0, 8},
      {"+12", 0, 12},
      {"-14", 0, -14},

      {"0n", 0, 0},
      {"16N", 16, 0},
      {"-19n", -19, 0},
      {"+23n", 23, 0},
      {"n", 1, 0},
      {"N", 1, 0},
      {"+n", 1, 0},
      {"-n", -1, 0},
      {"-N", -1, 0},

      {"6n-3", 6, -3},
      {"-26N-33", -26, -33},
      {"n-18", 1, -18},
      {"+N-5", 1, -5},
      {"-n-7", -1, -7},

      {"0n+0", 0, 0},
      {"10n+5", 10, 5},
      {"10N +5", 10, 5},
      {"10n -5", 10, -5},
      {"N+6", 1, 6},
      {"n +6", 1, 6},
      {"+n -7", 1, -7},
      {"-N -8", -1, -8},
      {"-n+9", -1, 9},

      {"33N- 22", 33, -22},
      {"+n- 25", 1, -25},
      {"N- 46", 1, -46},
      {"n- 0", 1, 0},
      {"-N- 951", -1, -951},
      {"-n- 951", -1, -951},

      {"29N + 77", 29, 77},
      {"29n - 77", 29, -77},
      {"+n + 61", 1, 61},
      {"+N - 63", 1, -63},
      {"+n/**/- 48", 1, -48},
      {"-n + 81", -1, 81},
      {"-N - 88", -1, -88},

      {"3091970736n + 1", std::numeric_limits<int>::max(), 1},
      {"-3091970736n + 1", std::numeric_limits<int>::min(), 1},
      // B is calculated as +ve first, then negated.
      {"N- 3091970736", 1, -std::numeric_limits<int>::max()},
      {"N+ 3091970736", 1, std::numeric_limits<int>::max()},
  };

  for (auto test_case : test_cases) {
    SCOPED_TRACE(test_case.input);

    std::pair<int, int> ab;
    CSSParserTokenStream stream(test_case.input);
    bool passed = CSSSelectorParser::ConsumeANPlusB(stream, ab);
    EXPECT_TRUE(passed);
    EXPECT_EQ(test_case.a, ab.first);
    EXPECT_EQ(test_case.b, ab.second);
  }
}

TEST(CSSSelectorParserTest, InvalidANPlusB) {
  test::TaskEnvironment task_environment;
  // Some of these have token range prefixes which are valid <an+b> and could
  // in theory be valid in consumeANPlusB, but this behaviour isn't needed
  // anywhere and not implemented.
  const char* test_cases[] = {
      " odd",     "+ n",     "3m+4",  "12n--34",  "12n- -34",
      "12n- +34", "23n-+43", "10n 5", "10n + +5", "10n + -5",
  };

  for (String test_case : test_cases) {
    SCOPED_TRACE(test_case);

    std::pair<int, int> ab;
    CSSParserTokenStream stream(test_case);
    bool passed = CSSSelectorParser::ConsumeANPlusB(stream, ab);
    EXPECT_FALSE(passed);
  }
}

TEST(CSSSelectorParserTest, PseudoElementsInCompoundLists) {
  test::TaskEnvironment task_environment;
  const char* test_cases[] = {":not(::before)",
                              ":not(::content)",
                              ":host(::before)",
                              ":host(::content)",
                              ":host-context(::before)",
                              ":host-context(::content)",
                              ":-webkit-any(::after, ::before)",
                              ":-webkit-any(::content, span)"};

  HeapVector<CSSSelector> arena;
  for (StringView test_case : test_cases) {
    CSSParserTokenStream stream(test_case);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream,
        MakeGarbageCollected<CSSParserContext>(
            kHTMLStandardMode, SecureContextMode::kInsecureContext),
        CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
        /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
    EXPECT_EQ(vector.size(), 0u);
  }
}

TEST(CSSSelectorParserTest, ValidSimpleAfterPseudoElementInCompound) {
  test::TaskEnvironment task_environment;
  const char* test_cases[] = {"::-webkit-volume-slider:hover",
                              "::selection:window-inactive",
                              "::search-text:current",
                              "::search-text:not(:current)",
                              "::-webkit-scrollbar:disabled",
                              "::-webkit-volume-slider:not(:hover)",
                              "::-webkit-scrollbar:not(:horizontal)",
                              "::slotted(span)::before",
                              "::slotted(div)::after",
                              "::slotted(div)::view-transition"};

  HeapVector<CSSSelector> arena;
  for (StringView test_case : test_cases) {
    SCOPED_TRACE(test_case);
    CSSParserTokenStream stream(test_case);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream,
        MakeGarbageCollected<CSSParserContext>(
            kHTMLStandardMode, SecureContextMode::kInsecureContext),
        CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
        /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
    EXPECT_GT(vector.size(), 0u);
  }
}

TEST(CSSSelectorParserTest, InvalidSimpleAfterPseudoElementInCompound) {
  test::TaskEnvironment task_environment;
  const char* test_cases[] = {
      "::before#id",
      "::after:hover",
      ".class::content::before",
      "::shadow.class",
      "::selection:window-inactive::before",
      "::search-text.class",
      "::search-text::before",
      "::search-text:hover",
      "::-webkit-volume-slider.class",
      "::before:not(.a)",
      "::shadow:not(::after)",
      "::-webkit-scrollbar:vertical:not(:first-child)",
      "video::-webkit-media-text-track-region-container.scrolling",
      "div ::before.a",
      "::slotted(div):hover",
      "::slotted(div)::slotted(span)",
      "::slotted(div)::before:hover",
      "::slotted(div)::before::slotted(span)",
      "::slotted(*)::first-letter",
      "::slotted(.class)::first-line",
      "::slotted([attr])::-webkit-scrollbar"};

  HeapVector<CSSSelector> arena;
  for (StringView test_case : test_cases) {
    CSSParserTokenStream stream(test_case);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream,
        MakeGarbageCollected<CSSParserContext>(
            kHTMLStandardMode, SecureContextMode::kInsecureContext),
        CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
        /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
    EXPECT_EQ(vector.size(), 0u);
  }
}

TEST(CSSSelectorParserTest, TransitionPseudoStyles) {
  test::TaskEnvironment task_environment;
  struct TestCase {
    const char* selector;
    bool valid;
    const char* argument;
    CSSSelector::PseudoType type;
  };

  TestCase test_cases[] = {
      {"html::view-transition-group(*)", true, nullptr,
       CSSSelector::kPseudoViewTransitionGroup},
      {"html::view-transition-group(foo)", true, "foo",
       CSSSelector::kPseudoViewTransitionGroup},
      {"html::view-transition-image-pair(foo)", true, "foo",
       CSSSelector::kPseudoViewTransitionImagePair},
      {"html::view-transition-old(foo)", true, "foo",
       CSSSelector::kPseudoViewTransitionOld},
      {"html::view-transition-new(foo)", true, "foo",
       CSSSelector::kPseudoViewTransitionNew},
      {"::view-transition-group(foo)", true, "foo",
       CSSSelector::kPseudoViewTransitionGroup},
      {"div::view-transition-group(*)", true, nullptr,
       CSSSelector::kPseudoViewTransitionGroup},
      {"::view-transition-group(*)::before", false, nullptr,
       CSSSelector::kPseudoUnknown},
      {"::view-transition-group(*):hover", false, nullptr,
       CSSSelector::kPseudoUnknown},
  };

  HeapVector<CSSSelector> arena;
  for (const auto& test_case : test_cases) {
    SCOPED_TRACE(test_case.selector);
    CSSParserTokenStream stream(test_case.selector);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream,
        MakeGarbageCollected<CSSParserContext>(
            kHTMLStandardMode, SecureContextMode::kInsecureContext),
        CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
        /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
    EXPECT_EQ(!vector.empty(), test_case.valid);
    if (!test_case.valid) {
      continue;
    }

    CSSSelectorList* list = CSSSelectorList::AdoptSelectorVector(vector);
    ASSERT_TRUE(list->IsSingleComplexSelector());

    auto* selector = list->First();
    while (selector->NextSimpleSelector()) {
      selector = selector->NextSimpleSelector();
    }

    EXPECT_EQ(selector->GetPseudoType(), test_case.type);
    EXPECT_EQ(selector->GetPseudoType() == CSSSelector::kPseudoViewTransition
                  ? selector->Argument()
                  : selector->IdentList()[0],
              test_case.argument);
  }
}

TEST(CSSSelectorParserTest, WorkaroundForInvalidCustomPseudoInUAStyle) {
  test::TaskEnvironment task_environment;
  // See crbug.com/578131
  const char* test_cases[] = {
      "video::-webkit-media-text-track-region-container.scrolling",
      "input[type=\"range\" i]::-webkit-media-slider-container > div"};

  HeapVector<CSSSelector> arena;
  for (StringView test_case : test_cases) {
    CSSParserTokenStream stream(test_case);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream,
        MakeGarbageCollected<CSSParserContext>(
            kUASheetMode, SecureContextMode::kInsecureContext),
        CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
        /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
    EXPECT_GT(vector.size(), 0u);
  }
}

TEST(CSSSelectorParserTest, InvalidPseudoElementInNonRightmostCompound) {
  test::TaskEnvironment task_environment;
  const char* test_cases[] = {"::-webkit-volume-slider *", "::before *",
                              "::-webkit-scrollbar *", "::cue *",
                              "::selection *"};

  HeapVector<CSSSelector> arena;
  for (StringView test_case : test_cases) {
    CSSParserTokenStream stream(test_case);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream,
        MakeGarbageCollected<CSSParserContext>(
            kHTMLStandardMode, SecureContextMode::kInsecureContext),
        CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
        /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
    EXPECT_EQ(vector.size(), 0u);
  }
}

TEST(CSSSelectorParserTest, UnresolvedNamespacePrefix) {
  test::TaskEnvironment task_environment;
  const char* test_cases[] = {"ns|div", "div ns|div", "div ns|div "};

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);

  HeapVector<CSSSelector> arena;
  for (StringView test_case : test_cases) {
    CSSParserTokenStream stream(test_case);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream, context, CSSNestingType::kNone,
        /*parent_rule_for_nesting=*/nullptr, /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, sheet, arena);
    EXPECT_EQ(vector.size(), 0u);
  }
}

TEST(CSSSelectorParserTest, UnexpectedPipe) {
  test::TaskEnvironment task_environment;
  const char* test_cases[] = {"div | .c", "| div", " | div"};

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);

  HeapVector<CSSSelector> arena;
  for (StringView test_case : test_cases) {
    CSSParserTokenStream stream(test_case);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream, context, CSSNestingType::kNone,
        /*parent_rule_for_nesting=*/nullptr, /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, sheet, arena);
    EXPECT_EQ(vector.size(), 0u);
  }
}

TEST(CSSSelectorParserTest, SerializedUniversal) {
  test::TaskEnvironment task_environment;
  struct SerializationTestCase {
    const char* source;
    const char* expected;
  };
  const SerializationTestCase test_cases[] = {
      {"*::-webkit-volume-slider", "::-webkit-volume-slider"},
      {"*::cue(i)", "::cue(i)"},
      {"*:host-context(.x)", "*:host-context(.x)"},
      {"*:host", "*:host"},
      {"|*::-webkit-volume-slider", "|*::-webkit-volume-slider"},
      {"|*::cue(i)", "|*::cue(i)"},
      {"*|*::-webkit-volume-slider", "::-webkit-volume-slider"},
      {"*|*::cue(i)", "::cue(i)"},
      {"ns|*::-webkit-volume-slider", "ns|*::-webkit-volume-slider"},
      {"ns|*::cue(i)", "ns|*::cue(i)"}};

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  sheet->ParserAddNamespace(AtomicString("ns"), AtomicString("http://ns.org"));

  HeapVector<CSSSelector> arena;
  for (const SerializationTestCase& test_case : test_cases) {
    SCOPED_TRACE(test_case.source);
    CSSParserTokenStream stream(test_case.source);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream, context, CSSNestingType::kNone,
        /*parent_rule_for_nesting=*/nullptr, /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, sheet, arena);
    CSSSelectorList* list = CSSSelectorList::AdoptSelectorVector(vector);
    EXPECT_TRUE(list->IsValid());
    EXPECT_EQ(test_case.expected, list->SelectorsText());
  }
}

TEST(CSSSelectorParserTest, AttributeSelectorUniversalInvalid) {
  test::TaskEnvironment task_environment;
  const char* test_cases[] = {"[*]", "[*|*]"};

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);

  HeapVector<CSSSelector> arena;
  for (String test_case : test_cases) {
    SCOPED_TRACE(test_case);
    CSSParserTokenStream stream(test_case);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream, context, CSSNestingType::kNone,
        /*parent_rule_for_nesting=*/nullptr, /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, sheet, arena);
    EXPECT_EQ(vector.size(), 0u);
  }
}

TEST(CSSSelectorParserTest, InternalPseudo) {
  test::TaskEnvironment task_environment;
  const char* test_cases[] = {"::-internal-whatever",
                              "::-internal-media-controls-text-track-list",
                              ":-internal-is-html",
                              ":-internal-list-box",
                              ":-internal-multi-select-focus",
                              ":-internal-shadow-host-has-non-auto-appearance",
                              ":-internal-spatial-navigation-focus",
                              ":-internal-video-persistent",
                              ":-internal-video-persistent-ancestor"};

  HeapVector<CSSSelector> arena;
  for (String test_case : test_cases) {
    SCOPED_TRACE(test_case);
    {
      CSSParserTokenStream stream(test_case);
      base::span<CSSSelector> author_vector = CSSSelectorParser::ParseSelector(
          stream,
          MakeGarbageCollected<CSSParserContext>(
              kHTMLStandardMode, SecureContextMode::kInsecureContext),
          CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
          /*is_within_scope=*/false,
          /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
      EXPECT_EQ(author_vector.size(), 0u);
    }

    {
      CSSParserTokenStream stream(test_case);
      base::span<CSSSelector> ua_vector = CSSSelectorParser::ParseSelector(
          stream,
          MakeGarbageCollected<CSSParserContext>(
              kUASheetMode, SecureContextMode::kInsecureContext),
          CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
          /*is_within_scope=*/false,
          /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
      EXPECT_GT(ua_vector.size(), 0u);
    }
  }
}

TEST(CSSSelectorParserTest, ScrollControlPseudos) {
  test::TaskEnvironment task_environment;
  struct TestCase {
    const char* selector;
    CSSSelector::PseudoType type;
  };

  TestCase test_cases[] = {
      {"ul::scroll-marker-group", CSSSelector::kPseudoScrollMarkerGroup},
      {"li::scroll-marker", CSSSelector::kPseudoScrollMarker},
      {"div::scroll-next-button", CSSSelector::kPseudoScrollNextButton},
      {"div::scroll-prev-button", CSSSelector::kPseudoScrollPrevButton},
  };

  HeapVector<CSSSelector> arena;
  for (const auto& test_case : test_cases) {
    SCOPED_TRACE(test_case.selector);
    CSSParserTokenStream stream(test_case.selector);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream,
        MakeGarbageCollected<CSSParserContext>(
            kHTMLStandardMode, SecureContextMode::kInsecureContext),
        CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
        /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
    EXPECT_TRUE(!vector.empty());

    CSSSelectorList* list = CSSSelectorList::AdoptSelectorVector(vector);
    ASSERT_TRUE(list->IsSingleComplexSelector());

    const CSSSelector* selector = list->First();
    while (selector->NextSimpleSelector()) {
      selector = selector->NextSimpleSelector();
    }

    EXPECT_EQ(selector->GetPseudoType(), test_case.type);
  }
}

TEST(CSSSelectorParserTest, ColumnPseudo) {
  test::TaskEnvironment task_environment;
  struct TestCase {
    const char* selector;
    CSSSelector::PseudoType type;
  };

  TestCase test_cases[] = {
      {".scroller::column", CSSSelector::kPseudoColumn},
      {"#scroller::column", CSSSelector::kPseudoColumn},
      {"div::column", CSSSelector::kPseudoColumn},
      {"div::before::column", CSSSelector::kPseudoUnknown},
      {"div::after::column", CSSSelector::kPseudoUnknown},
  };

  HeapVector<CSSSelector> arena;
  for (const auto& test_case : test_cases) {
    SCOPED_TRACE(test_case.selector);
    CSSParserTokenStream stream(StringView(test_case.selector));
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream,
        MakeGarbageCollected<CSSParserContext>(
            kHTMLStandardMode, SecureContextMode::kInsecureContext),
        CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
        /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, nullptr, arena);

    if (test_case.type == CSSSelector::kPseudoUnknown) {
      EXPECT_TRUE(vector.empty());
      return;
    }

    EXPECT_TRUE(!vector.empty());

    CSSSelectorList* list = CSSSelectorList::AdoptSelectorVector(vector);
    ASSERT_TRUE(list->IsSingleComplexSelector());

    const CSSSelector* selector = list->First();
    while (selector->NextSimpleSelector()) {
      selector = selector->NextSimpleSelector();
    }

    EXPECT_EQ(selector->GetPseudoType(), test_case.type);
  }
}

// Pseudo-elements are not valid within :is() as per the spec:
// https://drafts.csswg.org/selectors-4/#matches
static const SelectorTestCase invalid_pseudo_is_argments_data[] = {
    // clang-format off
    {":is(::-webkit-progress-bar)", ":is()"},
    {":is(::-webkit-progress-value)", ":is()"},
    {":is(::-webkit-slider-runnable-track)", ":is()"},
    {":is(::-webkit-slider-thumb)", ":is()"},
    {":is(::after)", ":is()"},
    {":is(::backdrop)", ":is()"},
    {":is(::before)", ":is()"},
    {":is(::cue)", ":is()"},
    {":is(::first-letter)", ":is()"},
    {":is(::first-line)", ":is()"},
    {":is(::grammar-error)", ":is()"},
    {":is(::marker)", ":is()"},
    {":is(::placeholder)", ":is()"},
    {":is(::selection)", ":is()"},
    {":is(::slotted)", ":is()"},
    {":is(::spelling-error)", ":is()"},
    {":is(:after)", ":is()"},
    {":is(:before)", ":is()"},
    {":is(:cue)", ":is()"},
    {":is(:first-letter)", ":is()"},
    {":is(:first-line)", ":is()"},
    // If the selector is nest-containing, it serializes as-is:
    // https://drafts.csswg.org/css-nesting-1/#syntax
    {":is(:unknown(&))"},
    // clang-format on
};

INSTANTIATE_TEST_SUITE_P(InvalidPseudoIsArguments,
                         SelectorParseTest,
                         testing::ValuesIn(invalid_pseudo_is_argments_data));

static const SelectorTestCase is_where_nesting_data[] = {
    // clang-format off
    // These pseudos only accept compound selectors:
    {"::slotted(:is(.a .b))", "::slotted(:is())"},
    {"::slotted(:is(.a + .b))", "::slotted(:is())"},
    {"::slotted(:is(.a, .b + .c))", "::slotted(:is(.a))"},
    {":host(:is(.a .b))", ":host(:is())"},
    {":host(:is(.a + .b))", ":host(:is())"},
    {":host(:is(.a, .b + .c))", ":host(:is(.a))"},
    {":host-context(:is(.a .b))", ":host-context(:is())"},
    {":host-context(:is(.a + .b))", ":host-context(:is())"},
    {":host-context(:is(.a, .b + .c))", ":host-context(:is(.a))"},
    {"::cue(:is(.a .b))", "::cue(:is())"},
    {"::cue(:is(.a + .b))", "::cue(:is())"},
    {"::cue(:is(.a, .b + .c))", "::cue(:is(.a))"},
    // Structural pseudos are not allowed after ::part().
    {"::part(foo):is(.a)", "::part(foo):is()"},
    {"::part(foo):is(.a:hover)", "::part(foo):is()"},
    {"::part(foo):is(:hover.a)", "::part(foo):is()"},
    {"::part(foo):is(:hover + .a)", "::part(foo):is()"},
    {"::part(foo):is(.a + :hover)", "::part(foo):is()"},
    {"::part(foo):is(:hover:first-child)", "::part(foo):is()"},
    {"::part(foo):is(:first-child:hover)", "::part(foo):is()"},
    {"::part(foo):is(:hover, :where(.a))",
     "::part(foo):is(:hover, :where())"},
    {"::part(foo):is(:hover, .a)", "::part(foo):is(:hover)"},
    {"::part(foo):is(:state(bar), .a)", "::part(foo):is(:state(bar))"},
    {"::part(foo):is(:first-child)", "::part(foo):is()"},
    // Only scrollbar pseudos after kPseudoScrollbar:
    {"::-webkit-scrollbar:is(:focus)", "::-webkit-scrollbar:is()"},
    // Only :window-inactive after kPseudoSelection:
    {"::selection:is(:focus)", "::selection:is()"},
    // Only user-action pseudos after webkit pseudos:
    {"::-webkit-input-placeholder:is(:enabled)",
     "::-webkit-input-placeholder:is()"},
    {"::-webkit-input-placeholder:is(:not(:enabled))",
     "::-webkit-input-placeholder:is()"},

    // Valid selectors:
    {":is(.a, .b)"},
    {":is(.a\n)", ":is(.a)"},
    {":is(.a .b, .c)"},
    {":is(.a :is(.b .c), .d)"},
    {":is(.a :where(.b .c), .d)"},
    {":where(.a :is(.b .c), .d)"},
    {":not(:is(.a))"},
    {":not(:is(.a, .b))"},
    {":not(:is(.a + .b, .c .d))"},
    {":not(:where(:not(.a)))"},
    {"::slotted(:is(.a))"},
    {"::slotted(:is(div.a))"},
    {"::slotted(:is(.a, .b))"},
    {":host(:is(.a))"},
    {":host(:is(div.a))"},
    {":host(:is(.a, .b))"},
    {":host(:is(.a\n))", ":host(:is(.a))"},
    {":host-context(:is(.a))"},
    {":host-context(:is(div.a))"},
    {":host-context(:is(.a, .b))"},
    {"::cue(:is(.a))"},
    {"::cue(:is(div.a))"},
    {"::cue(:is(.a, .b))"},
    {"::part(foo):is(:hover)"},
    {"::part(foo):is(:hover:focus)"},
    {"::part(foo):is(:is(:hover))"},
    {"::part(foo):is(:focus, :hover)"},
    {"::part(foo):is(:focus, :is(:hover))"},
    {"::part(foo):is(:focus, :state(bar))"},
    {"::-webkit-scrollbar:is(:enabled)"},
    {"::selection:is(:window-inactive)"},
    {"::-webkit-input-placeholder:is(:hover)"},
    {"::-webkit-input-placeholder:is(:not(:hover))"},
    {"::-webkit-input-placeholder:where(:hover)"},
    {"::-webkit-input-placeholder:is()"},
    {"::-webkit-input-placeholder:is(:where(:hover))"},
    // clang-format on
};

INSTANTIATE_TEST_SUITE_P(NestedSelectorValidity,
                         SelectorParseTest,
                         testing::ValuesIn(is_where_nesting_data));

static const SelectorTestCase is_where_forgiving_data[] = {
    // clang-format off
    {":is():where()"},
    {":is(.a, .b):where(.c)"},
    {":is(.a, :unknown, .b)", ":is(.a, .b)"},
    {":where(.a, :unknown, .b)", ":where(.a, .b)"},
    {":is(.a, :unknown)", ":is(.a)"},
    {":is(:unknown, .a)", ":is(.a)"},
    {":is(:unknown)", ":is()"},
    {":is(:unknown, :where(.a))", ":is(:where(.a))"},
    {":is(:unknown, :where(:unknown))", ":is(:where())"},
    {":is(.a, :is(.b, :unknown), .c)", ":is(.a, :is(.b), .c)"},
    {":host(:is(.a, .b + .c, .d))", ":host(:is(.a, .d))"},
    {":is(,,  ,, )", ":is()"},
    {":is(.a,,,,)", ":is(.a)"},
    {":is(,,.a,,)", ":is(.a)"},
    {":is(,,,,.a)", ":is(.a)"},
    {":is(@x {,.b,}, .a)", ":is(.a)"},
    {":is({,.b,} @x, .a)", ":is(.a)"},
    {":is((@x), .a)", ":is(.a)"},
    {":is((.b), .a)", ":is(.a)"},
    // clang-format on
};

INSTANTIATE_TEST_SUITE_P(IsWhereForgiving,
                         SelectorParseTest,
                         testing::ValuesIn(is_where_forgiving_data));
namespace {

AtomicString TagLocalName(const CSSSelector* selector) {
  return selector->TagQName().LocalName();
}

AtomicString AttributeLocalName(const CSSSelector* selector) {
  return selector->Attribute().LocalName();
}

AtomicString SelectorValue(const CSSSelector* selector) {
  return selector->Value();
}

struct ASCIILowerTestCase {
  const char* input;
  const char16_t* expected;
  using GetterFn = AtomicString(const CSSSelector*);
  GetterFn* getter;
};

}  // namespace

TEST(CSSSelectorParserTest, ASCIILowerHTMLStrict) {
  test::TaskEnvironment task_environment;
  const ASCIILowerTestCase test_cases[] = {
      {"\\212a bd", u"\u212abd", TagLocalName},
      {"[\\212alass]", u"\u212alass", AttributeLocalName},
      {".\\212alass", u"\u212alass", SelectorValue},
      {"#\\212alass", u"\u212alass", SelectorValue}};

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);

  HeapVector<CSSSelector> arena;
  for (auto test_case : test_cases) {
    SCOPED_TRACE(test_case.input);
    CSSParserTokenStream stream(test_case.input);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream, context, CSSNestingType::kNone,
        /*parent_rule_for_nesting=*/nullptr, /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, sheet, arena);
    EXPECT_GT(vector.size(), 0u);
    CSSSelectorList* list = CSSSelectorList::AdoptSelectorVector(vector);
    EXPECT_TRUE(list->IsValid());
    const CSSSelector* selector = list->First();
    ASSERT_TRUE(selector);
    EXPECT_EQ(AtomicString(test_case.expected), test_case.getter(selector));
  }
}

TEST(CSSSelectorParserTest, ASCIILowerHTMLQuirks) {
  test::TaskEnvironment task_environment;
  const ASCIILowerTestCase test_cases[] = {
      {"\\212a bd", u"\u212abd", TagLocalName},
      {"[\\212alass]", u"\u212alass", AttributeLocalName},
      {".\\212aLASS", u"\u212alass", SelectorValue},
      {"#\\212aLASS", u"\u212alass", SelectorValue}};

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLQuirksMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);

  HeapVector<CSSSelector> arena;
  for (auto test_case : test_cases) {
    SCOPED_TRACE(test_case.input);
    CSSParserTokenStream stream(test_case.input);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream, context, CSSNestingType::kNone,
        /*parent_rule_for_nesting=*/nullptr, /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, sheet, arena);
    EXPECT_GT(vector.size(), 0u);
    CSSSelectorList* list = CSSSelectorList::AdoptSelectorVector(vector);
    EXPECT_TRUE(list->IsValid());
    const CSSSelector* selector = list->First();
    ASSERT_TRUE(selector);
    EXPECT_EQ(AtomicString(test_case.expected), test_case.getter(selector));
  }
}

TEST(CSSSelectorParserTest, ShadowPartPseudoElementValid) {
  test::TaskEnvironment task_environment;
  const char* test_cases[] = {"::part(ident)", "host::part(ident)",
                              "host::part(ident):hover"};

  HeapVector<CSSSelector> arena;
  for (String test_case : test_cases) {
    SCOPED_TRACE(test_case);
    CSSParserTokenStream stream(test_case);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream,
        MakeGarbageCollected<CSSParserContext>(
            kHTMLStandardMode, SecureContextMode::kInsecureContext),
        CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
        /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
    CSSSelectorList* list = CSSSelectorList::AdoptSelectorVector(vector);
    EXPECT_EQ(test_case, list->SelectorsText());
  }
}

TEST(CSSSelectorParserTest, ShadowPartAndBeforeAfterPseudoElementValid) {
  test::TaskEnvironment task_environment;
  const char* test_cases[] = {
      "::part(ident)::before",       "::part(ident)::after",
      "::part(ident)::placeholder",  "::part(ident)::first-line",
      "::part(ident)::first-letter", "::part(ident)::selection"};

  HeapVector<CSSSelector> arena;
  for (String test_case : test_cases) {
    SCOPED_TRACE(test_case);
    CSSParserTokenStream stream(test_case);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream,
        MakeGarbageCollected<CSSParserContext>(
            kHTMLStandardMode, SecureContextMode::kInsecureContext),
        CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
        /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
    EXPECT_GT(vector.size(), 0u);
    CSSSelectorList* list = CSSSelectorList::AdoptSelectorVector(vector);
    EXPECT_TRUE(list->IsValid());
    EXPECT_EQ(test_case, list->SelectorsText());
  }
}

static bool IsCounted(const char* selector,
                      CSSParserMode mode,
                      WebFeature feature) {
  auto dummy_holder = std::make_unique<DummyPageHolder>(gfx::Size(500, 500));
  Document* doc = &dummy_holder->GetDocument();
  Page::InsertOrdinaryPageForTesting(&dummy_holder->GetPage());
  auto* context = MakeGarbageCollected<CSSParserContext>(
      mode, SecureContextMode::kSecureContext, doc);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);

  DCHECK(!doc->IsUseCounted(feature));

  CSSParserTokenStream stream(selector);
  HeapVector<CSSSelector> arena;
  CSSSelectorParser::ParseSelector(stream, context, CSSNestingType::kNone,
                                   /*parent_rule_for_nesting=*/nullptr,
                                   /*is_within_scope=*/false,
                                   /*semicolon_aborts_nested_selector=*/false,
                                   sheet, arena);

  return doc->IsUseCounted(feature);
}

TEST(CSSSelector
"""


```