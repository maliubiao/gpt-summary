Response:
My thinking process to answer the request about `css_parser_impl_test.cc` goes like this:

1. **Understand the Core Request:** The request asks for the functionality of the given C++ test file, its relation to web technologies (HTML, CSS, JavaScript), examples, logical inferences, common user/programming errors, debugging steps, and a summary of its functionality as the first part of a two-part analysis.

2. **Identify the File's Purpose:** The file name `css_parser_impl_test.cc` strongly suggests it's a test suite for the `CSSParserImpl` class. The `#include` directives confirm this, as it includes the implementation (`css_parser_impl.h`) and testing frameworks (`gtest/gtest.h`).

3. **Analyze the Includes:**  The included headers provide clues about the functionalities being tested:
    * `css_font_family_value.h`, `css_test_helpers.h`, `css_to_length_conversion_data.h`, `css_value_list.h`:  These indicate testing of CSS value parsing.
    * `css_parser_context.h`, `css_parser_observer.h`, `css_parser_token_stream.h`, `css_tokenizer.h`, `css_variable_parser.h`: These point to the core CSS parsing mechanisms being tested.
    * `style_resolver.h`, `style_rule.h`, `style_rule_font_feature_values.h`, `style_rule_font_palette_values.h`, `style_rule_import.h`, `style_rule_nested_declarations.h`, `style_sheet_contents.h`: These suggest the testing involves creating and manipulating CSS rule objects.
    * `document.h`, `execution_context/security_context.h`, `testing/null_execution_context.h`:  This indicates testing within the context of a web page (DOM, security).
    * `platform/testing/runtime_enabled_features_test_helpers.h`, `platform/testing/task_environment.h`: These are for setting up the testing environment, including controlling experimental features.

4. **Examine the Test Structure:** The file uses Google Test (`TEST(...)`). Each `TEST` block focuses on a specific aspect of the CSS parser. I need to go through each test and identify its purpose.

5. **Categorize Test Functionality:** As I examine the individual tests, I can group them by the features they are testing. Initial categories emerge:
    * **Offset Tracking:** Several tests (`AtImportOffsets`, `AtMediaOffsets`, etc.) specifically check the starting and ending offsets of different CSS rules.
    * **Nesting:** Tests like `DirectNesting`, `RuleNotStartingWithAmpersand`, `ImplicitDescendantSelectors`, etc., focus on how nested CSS rules are parsed.
    * **Error Handling:**  `ErrorRecoveryEatsOnlyFirstDeclaration` demonstrates testing the parser's ability to recover from syntax errors.
    * **Specific At-Rules:** Tests like `AtFontFaceOffsets`, `AtKeyframesOffsets`, `AtPageOffsets`, etc., target the parsing of specific CSS at-rules.
    * **CSS Variables:** `ConsumeUnparsedDeclarationRemovesImportantAnnotationIfPresent` focuses on parsing CSS variable declarations.
    * **CSS Layers:** `InvalidLayerRules`, `ValidLayerBlockRule`, `ValidLayerStatementRule`, `NestedLayerRules` are dedicated to testing the new CSS Layers feature.

6. **Connect to Web Technologies:**  Now I link these functionalities back to HTML, CSS, and JavaScript:
    * **CSS:**  The entire file is inherently about CSS parsing. I need to provide examples of CSS syntax that these tests cover (e.g., `@import`, `@media`, selectors, properties).
    * **HTML:**  CSS styles are applied to HTML elements. The parsing process is crucial for the browser to understand how to render HTML. I can mention how CSS rules target HTML elements using selectors.
    * **JavaScript:** JavaScript can dynamically manipulate CSS styles. While this file doesn't directly test JavaScript interaction, I can mention that correct CSS parsing is a prerequisite for JavaScript to work with styles.

7. **Provide Examples and Inferences:**  For each category of tests, I can create simple examples of CSS code and explain what the parser should output (or how it should behave in case of errors). For instance, for the offset tests, I can show the input CSS and the expected start/end positions. For nesting, I can illustrate how the parser creates a hierarchy of rules.

8. **Consider User/Programming Errors:**  Based on the tests, I can identify potential errors developers might make:
    * Incorrect CSS syntax (missing semicolons, colons, braces).
    * Errors in nesting selectors.
    * Misunderstanding how the `!important` flag works.
    * Incorrectly using the `@layer` syntax.

9. **Outline Debugging Steps:**  I need to describe how a developer might end up looking at this test file during debugging. This involves scenarios like:
    * A bug reported related to CSS parsing.
    * A developer working on a new CSS feature.
    * A developer trying to understand how the browser interprets specific CSS syntax.

10. **Write the Summary:**  Finally, I synthesize the information gathered into a concise summary of the file's purpose, focusing on its role in testing the CSS parsing functionality of the Blink rendering engine.

11. **Review and Refine:** I reread my answer to ensure clarity, accuracy, and completeness, making sure it addresses all aspects of the original request. I double-check the examples and explanations for correctness. For example, I made sure to clarify the role of `TestCSSParserObserver` in tracking parsing events. I also ensured that the explanation of the relationship with JavaScript and HTML was clear and concise.
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/parser/css_parser_impl.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_font_family_value.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/css_to_length_conversion_data.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_observer.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/parser/css_variable_parser.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/css/style_rule_font_feature_values.h"
#include "third_party/blink/renderer/core/css/style_rule_font_palette_values.h"
#include "third_party/blink/renderer/core/css/style_rule_import.h"
#include "third_party/blink/renderer/core/css/style_rule_nested_declarations.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

class TestCSSParserObserver : public CSSParserObserver {
 public:
  void StartRuleHeader(StyleRule::RuleType rule_type,
                       unsigned offset) override {
    if (IsAtTargetLevel()) {
      rule_type_ = rule_type;
      rule_header_start_ = offset;
    }
  }
  void EndRuleHeader(unsigned offset) override {
    if (IsAtTargetLevel()) {
      rule_header_end_ = offset;
    }
  }

  void ObserveSelector(unsigned start_offset, unsigned end_offset) override {}
  void StartRuleBody(unsigned offset) override {
    if (IsAtTargetLevel()) {
      rule_body_start_ = offset;
    }
    current_nesting_level_++;
  }
  void EndRuleBody(unsigned offset) override {
    current_nesting_level_--;
    if (IsAtTargetLevel()) {
      rule_body_end_ = offset;
    }
  }
  void ObserveProperty(unsigned start_offset,
                       unsigned end_offset,
                       bool is_important,
                       bool is_parsed) override {
    if (IsAtTargetLevel()) {
      property_start_ = start_offset;
    }
  }
  void ObserveComment(unsigned start_offset, unsigned end_offset) override {}
  void ObserveErroneousAtRule(
      unsigned start_offset,
      CSSAtRuleID id,
      const Vector<CSSPropertyID, 2>& invalid_properties) override {}
  void ObserveNestedDeclarations(wtf_size_t insert_rule_index) override {}

  bool IsAtTargetLevel() const {
    return target_nesting_level_ == kEverything ||
           target_nesting_level_ == current_nesting_level_;
  }

  const int kEverything = -1;

  // Set to >= 0 to only observe events at a certain level. If kEverything, it
  // will observe everything.
  int target_nesting_level_ = kEverything;

  int current_nesting_level_ = 0;

  StyleRule::RuleType rule_type_ = StyleRule::RuleType::kStyle;
  unsigned property_start_ = 0;
  unsigned rule_header_start_ = 0;
  unsigned rule_header_end_ = 0;
  unsigned rule_body_start_ = 0;
  unsigned rule_body_end_ = 0;
};

// Exists solely to access private parts of CSSParserImpl.
class TestCSSParserImpl {
  STACK_ALLOCATED();

 public:
  TestCSSParserImpl()
      : impl_(MakeGarbageCollected<CSSParserContext>(
            kHTMLStandardMode,
            SecureContextMode::kInsecureContext)) {}

  StyleRule* ConsumeStyleRule(CSSParserTokenStream& stream,
                              CSSNestingType nesting_type,
                              StyleRule* parent_rule_for_nesting,
                              bool nested,
                              bool& invalid_rule_error) {
    return impl_.ConsumeStyleRule(stream, nesting_type, parent_rule_for_nesting,
                                  /* is_within_scope */ false, nested,
                                  invalid_rule_error);
  }

 private:
  CSSParserImpl impl_;
};

TEST(CSSParserImplTest, AtImportOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@import 'test.css';";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ImportRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_, StyleRule::RuleType::kImport);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 18u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 18u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 18u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 18u);
}

TEST(CSSParserImplTest, AtMediaOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@media screen { }";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ChildRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_, StyleRule::RuleType::kMedia);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 7u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 14u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 15u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 16u);
}

TEST(CSSParserImplTest, AtSupportsOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@supports (display:none) { }";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ChildRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_,
            StyleRule::RuleType::kSupports);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 10u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 25u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 26u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 27u);
}

TEST(CSSParserImplTest, AtFontFaceOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@font-face { }";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ChildRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_,
            StyleRule::RuleType::kFontFace);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 11u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 11u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 11u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 11u);
}

TEST(CSSParserImplTest, AtKeyframesOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@keyframes test { }";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ChildRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_,
            StyleRule::RuleType::kKeyframes);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 11u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 16u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 17u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 18u);
}

TEST(CSSParserImplTest, AtPageOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@page :first { }";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ChildRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_, StyleRule::RuleType::kPage);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 6u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 13u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 14u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 15u);
}

TEST(CSSParserImplTest, AtPageMarginOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@page :first { @top-left { content: 'A'; } }";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;

  // Ignore @page, look for @top-left.
  test_css_parser_observer.target_nesting_level_ = 1;

  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ChildRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_,
            StyleRule::RuleType::kPageMargin);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 25u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 25u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 26u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 41u);
}

TEST(CSSParserImplTest, AtPropertyOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@property --test { syntax: '*'; inherits: false }";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ChildRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_,
            StyleRule::RuleType::kProperty);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 10u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 17u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 18u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 48u);
}

TEST(CSSParserImplTest, AtCounterStyleOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@counter-style test { }";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ChildRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_,
            StyleRule::RuleType::kCounterStyle);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 15u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 20u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 21u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 22u);
}

TEST(CSSParserImplTest, AtContainerOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@container (max-width: 100px) { }";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ChildRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_,
            StyleRule::RuleType::kContainer);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 11u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 30u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 31u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 32u);
}

TEST(CSSParserImplTest, DirectNesting) {
  test::TaskEnvironment task_environment;
  String sheet_text =
      ".element { color: green; &.other { color: red; margin-left: 10px; }}";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  ASSERT_EQ(1u, sheet->ChildRules().size());
  StyleRule* parent = DynamicTo<StyleRule>(sheet->ChildRules()[0].Get());
  ASSERT_NE(nullptr, parent);
  EXPECT_EQ("color: green;", parent->Properties().AsText());
  EXPECT_EQ(".element", parent->SelectorsText());

  ASSERT_EQ(1u, parent->ChildRules()->size());
  const StyleRule* child =
      DynamicTo<StyleRule>((*parent->ChildRules())[0].Get());
  ASSERT_NE(nullptr, child);
  EXPECT_EQ("color: red; margin-left: 10px;", child->Properties().AsText());
  EXPECT_EQ("&.other", child->SelectorsText());
}

TEST(CSSParserImplTest, RuleNotStartingWithAmpersand) {
  test::TaskEnvironment task_environment;
  String sheet_text = ".element { color: green;  .outer & { color: red; }}";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  ASSERT_EQ(1u, sheet->ChildRules().size());
  StyleRule* parent = DynamicTo<StyleRule>(sheet->ChildRules()[0].Get());
  ASSERT_NE(nullptr, parent);
  EXPECT_EQ("color: green;", parent->Properties().AsText());
  EXPECT_EQ(".element", parent->SelectorsText());

  ASSERT_NE(nullptr, parent->ChildRules());
  ASSERT_EQ(1u, parent->ChildRules()->size());
  const StyleRule* child =
      DynamicTo<StyleRule>((*parent->ChildRules())[0].Get());
  ASSERT_NE(nullptr, child);
  EXPECT_EQ("color: red;", child->Properties().AsText());
  EXPECT_EQ(".outer &", child->SelectorsText());
}

TEST(CSSParserImplTest, ImplicitDescendantSelectors) {
  test::TaskEnvironment task_environment;
  String sheet_text =
      ".element { color: green; .outer, .outer2 { color: red; }}";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  ASSERT_EQ(1u, sheet->ChildRules().size());
  StyleRule* parent = DynamicTo<StyleRule>(sheet->ChildRules()[0].Get());
  ASSERT_NE(nullptr, parent);
  EXPECT_EQ("color: green;", parent->Properties().AsText());
  EXPECT_EQ(".element", parent->SelectorsText());

  ASSERT_NE(nullptr, parent->ChildRules());
  ASSERT_EQ(1u, parent->ChildRules()->size());
  const StyleRule* child =
      DynamicTo<StyleRule>((*parent->ChildRules())[0].Get());
  ASSERT_NE(nullptr, child);
  EXPECT_EQ("color: red;", child->Properties().AsText());
  EXPECT_EQ("& .outer, & .outer2", child->SelectorsText());
}

TEST(CSSParserImplTest, NestedRelativeSelector) {
  test::TaskEnvironment task_environment;
  String sheet_text = ".element { color: green; > .inner { color: red; }}";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  ASSERT_EQ(1u, sheet->ChildRules().size());
  StyleRule* parent = DynamicTo<StyleRule>(sheet->ChildRules()[0].Get());
  ASSERT_NE(nullptr, parent);
  EXPECT_EQ("color: green;", parent->Properties().AsText());
  EXPECT_EQ(".element", parent->SelectorsText());

  ASSERT_NE(nullptr, parent->ChildRules());
  ASSERT_EQ(1u, parent->ChildRules()->size());
  const StyleRule* child =
      DynamicTo<StyleRule>((*parent->ChildRules())[0].Get());
  ASSERT_NE(nullptr, child);
  EXPECT_EQ("color: red;", child->Properties().AsText());
  EXPECT_EQ("& > .inner", child->SelectorsText());
}

TEST(CSSParserImplTest, NestingAtTopLevelIsLegalThoughIsMatchesNothing) {
  test::TaskEnvironment task_environment;
  String sheet_text = "&.element { color: orchid; }";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  ASSERT_EQ(1u, sheet->ChildRules().size());
  const StyleRule* rule = DynamicTo<StyleRule>(sheet->ChildRules()[0].Get());
  EXPECT_EQ("color: orchid;", rule->Properties().AsText());
  EXPECT_EQ("&.element", rule->SelectorsText());
}

TEST(CSSParserImplTest, ErrorRecoveryEatsOnlyFirstDeclaration) {
  test::TaskEnvironment task_environment;
  // Note the colon after the opening bracket.
  String sheet_text = R"CSS(
    .element {:
      color: orchid;
      background-color: plum;
      accent-color: hotpink;
    }
    )CSS";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  ASSERT_EQ(1u, sheet->ChildRules().size());
  const StyleRule* rule = DynamicTo<StyleRule>(sheet->ChildRules()[0].Get());
  EXPECT_EQ("background-color: plum; accent-color: hotpink;",
            rule->Properties().AsText());
  EXPECT_EQ(".element", rule->SelectorsText());
}

TEST(CSSParserImplTest, NestedEmptySelectorCrash) {
  test::TaskEnvironment task_environment;
  String sheet_text = "y{ :is() {} }";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  // We only really care that it doesn't crash.
}

TEST(CSSParserImplTest, NestedRulesInsideMediaQueries) {
  test::TaskEnvironment task_environment;
  String sheet_text = R"CSS(
    .element {
      color: green;
      @media (width < 1000px) {
        color: navy;
        font-size: 12px;
        & + #foo { color: red; }
      }
    }
    )CSS";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  ASSERT_EQ(1u, sheet->ChildRules().size());
  StyleRule* parent = DynamicTo<StyleRule>(sheet->ChildRules()[0].Get());
  ASSERT_NE(nullptr, parent);
  EXPECT_EQ("color: green;", parent->Properties().AsText());
  EXPECT_EQ(".element", parent->SelectorsText());

  ASSERT_NE(nullptr, parent->ChildRules());
  ASSERT_EQ(1u, parent->ChildRules()->size());
  const StyleRuleMedia* media_query =
      DynamicTo<StyleRuleMedia>((*parent->ChildRules())[0].Get());
  ASSERT_NE(nullptr, media_query);

  ASSERT_EQ(2u, media_query->ChildRules().size());

  // Implicit CSSNestedDeclarations rule around the properties.
  const StyleRuleNestedDeclarations* child0 =
      DynamicTo<StyleRuleNestedDeclarations>(
          media_query->ChildRules()[0].Get());
  ASSERT_NE(nullptr, child0);
  EXPECT_EQ("color: navy; font-size: 12px;", child0->Properties().AsText());

  const StyleRule* child1 =
      DynamicTo<StyleRule>(media_query->ChildRules()[1].Get());
  ASSERT_NE(nullptr, child1);
  EXPECT_EQ("color: red;", child1->Properties().AsText());
  EXPECT_EQ("& + #foo", child1->SelectorsText());
}

// A version of NestedRulesInsideMediaQueries where CSSNestedDeclarations
// is disabled. Can be removed when the CSSNestedDeclarations is removed.
TEST(CSSParserImplTest,
     NestedRulesInsideMediaQueries_CSSNestedDeclarationsDisabled) {
  ScopedCSSNestedDeclarationsForTest nested_declarations_enabled(false);

  test::TaskEnvironment task_environment;
  String sheet_text = R"CSS(
    .element {
      color: green;
      @media (width < 1000px) {
        color: navy;
        font-size: 12px;
        & + #foo { color: red; }
      }
    }
    )CSS";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  ASSERT_EQ(1u, sheet->ChildRules().size());
  StyleRule* parent = DynamicTo<StyleRule>(sheet->ChildRules()[0].Get());
  ASSERT_NE(nullptr, parent);
  EXPECT_EQ("color: green;", parent->Properties().AsText());
  EXPECT_EQ(".element", parent->SelectorsText());

  ASSERT_NE(nullptr, parent->ChildRules());
  ASSERT_EQ(1u, parent->ChildRules()->size());
  const StyleRuleMedia* media_query =
      DynamicTo<StyleRuleMedia>((*parent->ChildRules())[0].Get());
  ASSERT_NE(nullptr, media_query);

  ASSERT_EQ(2u, media_query->ChildRules().size());

  // Implicit & {} rule around the properties.
  const StyleRule* child0 =
      Dynamic
### 提示词
```
这是目录为blink/renderer/core/css/parser/css_parser_impl_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/parser/css_parser_impl.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_font_family_value.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/css_to_length_conversion_data.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_observer.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/parser/css_variable_parser.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/css/style_rule_font_feature_values.h"
#include "third_party/blink/renderer/core/css/style_rule_font_palette_values.h"
#include "third_party/blink/renderer/core/css/style_rule_import.h"
#include "third_party/blink/renderer/core/css/style_rule_nested_declarations.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

class TestCSSParserObserver : public CSSParserObserver {
 public:
  void StartRuleHeader(StyleRule::RuleType rule_type,
                       unsigned offset) override {
    if (IsAtTargetLevel()) {
      rule_type_ = rule_type;
      rule_header_start_ = offset;
    }
  }
  void EndRuleHeader(unsigned offset) override {
    if (IsAtTargetLevel()) {
      rule_header_end_ = offset;
    }
  }

  void ObserveSelector(unsigned start_offset, unsigned end_offset) override {}
  void StartRuleBody(unsigned offset) override {
    if (IsAtTargetLevel()) {
      rule_body_start_ = offset;
    }
    current_nesting_level_++;
  }
  void EndRuleBody(unsigned offset) override {
    current_nesting_level_--;
    if (IsAtTargetLevel()) {
      rule_body_end_ = offset;
    }
  }
  void ObserveProperty(unsigned start_offset,
                       unsigned end_offset,
                       bool is_important,
                       bool is_parsed) override {
    if (IsAtTargetLevel()) {
      property_start_ = start_offset;
    }
  }
  void ObserveComment(unsigned start_offset, unsigned end_offset) override {}
  void ObserveErroneousAtRule(
      unsigned start_offset,
      CSSAtRuleID id,
      const Vector<CSSPropertyID, 2>& invalid_properties) override {}
  void ObserveNestedDeclarations(wtf_size_t insert_rule_index) override {}

  bool IsAtTargetLevel() const {
    return target_nesting_level_ == kEverything ||
           target_nesting_level_ == current_nesting_level_;
  }

  const int kEverything = -1;

  // Set to >= 0 to only observe events at a certain level. If kEverything, it
  // will observe everything.
  int target_nesting_level_ = kEverything;

  int current_nesting_level_ = 0;

  StyleRule::RuleType rule_type_ = StyleRule::RuleType::kStyle;
  unsigned property_start_ = 0;
  unsigned rule_header_start_ = 0;
  unsigned rule_header_end_ = 0;
  unsigned rule_body_start_ = 0;
  unsigned rule_body_end_ = 0;
};

// Exists solely to access private parts of CSSParserImpl.
class TestCSSParserImpl {
  STACK_ALLOCATED();

 public:
  TestCSSParserImpl()
      : impl_(MakeGarbageCollected<CSSParserContext>(
            kHTMLStandardMode,
            SecureContextMode::kInsecureContext)) {}

  StyleRule* ConsumeStyleRule(CSSParserTokenStream& stream,
                              CSSNestingType nesting_type,
                              StyleRule* parent_rule_for_nesting,
                              bool nested,
                              bool& invalid_rule_error) {
    return impl_.ConsumeStyleRule(stream, nesting_type, parent_rule_for_nesting,
                                  /* is_within_scope */ false, nested,
                                  invalid_rule_error);
  }

 private:
  CSSParserImpl impl_;
};

TEST(CSSParserImplTest, AtImportOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@import 'test.css';";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ImportRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_, StyleRule::RuleType::kImport);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 18u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 18u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 18u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 18u);
}

TEST(CSSParserImplTest, AtMediaOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@media screen { }";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ChildRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_, StyleRule::RuleType::kMedia);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 7u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 14u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 15u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 16u);
}

TEST(CSSParserImplTest, AtSupportsOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@supports (display:none) { }";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ChildRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_,
            StyleRule::RuleType::kSupports);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 10u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 25u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 26u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 27u);
}

TEST(CSSParserImplTest, AtFontFaceOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@font-face { }";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ChildRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_,
            StyleRule::RuleType::kFontFace);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 11u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 11u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 11u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 11u);
}

TEST(CSSParserImplTest, AtKeyframesOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@keyframes test { }";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ChildRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_,
            StyleRule::RuleType::kKeyframes);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 11u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 16u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 17u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 18u);
}

TEST(CSSParserImplTest, AtPageOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@page :first { }";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ChildRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_, StyleRule::RuleType::kPage);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 6u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 13u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 14u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 15u);
}

TEST(CSSParserImplTest, AtPageMarginOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@page :first { @top-left { content: 'A'; } }";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;

  // Ignore @page, look for @top-left.
  test_css_parser_observer.target_nesting_level_ = 1;

  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ChildRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_,
            StyleRule::RuleType::kPageMargin);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 25u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 25u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 26u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 41u);
}

TEST(CSSParserImplTest, AtPropertyOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@property --test { syntax: '*'; inherits: false }";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ChildRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_,
            StyleRule::RuleType::kProperty);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 10u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 17u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 18u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 48u);
}

TEST(CSSParserImplTest, AtCounterStyleOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@counter-style test { }";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ChildRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_,
            StyleRule::RuleType::kCounterStyle);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 15u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 20u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 21u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 22u);
}

TEST(CSSParserImplTest, AtContainerOffsets) {
  test::TaskEnvironment task_environment;
  String sheet_text = "@container (max-width: 100px) { }";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);
  EXPECT_EQ(style_sheet->ChildRules().size(), 1u);
  EXPECT_EQ(test_css_parser_observer.rule_type_,
            StyleRule::RuleType::kContainer);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 11u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 30u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 31u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 32u);
}

TEST(CSSParserImplTest, DirectNesting) {
  test::TaskEnvironment task_environment;
  String sheet_text =
      ".element { color: green; &.other { color: red; margin-left: 10px; }}";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  ASSERT_EQ(1u, sheet->ChildRules().size());
  StyleRule* parent = DynamicTo<StyleRule>(sheet->ChildRules()[0].Get());
  ASSERT_NE(nullptr, parent);
  EXPECT_EQ("color: green;", parent->Properties().AsText());
  EXPECT_EQ(".element", parent->SelectorsText());

  ASSERT_EQ(1u, parent->ChildRules()->size());
  const StyleRule* child =
      DynamicTo<StyleRule>((*parent->ChildRules())[0].Get());
  ASSERT_NE(nullptr, child);
  EXPECT_EQ("color: red; margin-left: 10px;", child->Properties().AsText());
  EXPECT_EQ("&.other", child->SelectorsText());
}

TEST(CSSParserImplTest, RuleNotStartingWithAmpersand) {
  test::TaskEnvironment task_environment;
  String sheet_text = ".element { color: green;  .outer & { color: red; }}";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  ASSERT_EQ(1u, sheet->ChildRules().size());
  StyleRule* parent = DynamicTo<StyleRule>(sheet->ChildRules()[0].Get());
  ASSERT_NE(nullptr, parent);
  EXPECT_EQ("color: green;", parent->Properties().AsText());
  EXPECT_EQ(".element", parent->SelectorsText());

  ASSERT_NE(nullptr, parent->ChildRules());
  ASSERT_EQ(1u, parent->ChildRules()->size());
  const StyleRule* child =
      DynamicTo<StyleRule>((*parent->ChildRules())[0].Get());
  ASSERT_NE(nullptr, child);
  EXPECT_EQ("color: red;", child->Properties().AsText());
  EXPECT_EQ(".outer &", child->SelectorsText());
}

TEST(CSSParserImplTest, ImplicitDescendantSelectors) {
  test::TaskEnvironment task_environment;
  String sheet_text =
      ".element { color: green; .outer, .outer2 { color: red; }}";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  ASSERT_EQ(1u, sheet->ChildRules().size());
  StyleRule* parent = DynamicTo<StyleRule>(sheet->ChildRules()[0].Get());
  ASSERT_NE(nullptr, parent);
  EXPECT_EQ("color: green;", parent->Properties().AsText());
  EXPECT_EQ(".element", parent->SelectorsText());

  ASSERT_NE(nullptr, parent->ChildRules());
  ASSERT_EQ(1u, parent->ChildRules()->size());
  const StyleRule* child =
      DynamicTo<StyleRule>((*parent->ChildRules())[0].Get());
  ASSERT_NE(nullptr, child);
  EXPECT_EQ("color: red;", child->Properties().AsText());
  EXPECT_EQ("& .outer, & .outer2", child->SelectorsText());
}

TEST(CSSParserImplTest, NestedRelativeSelector) {
  test::TaskEnvironment task_environment;
  String sheet_text = ".element { color: green; > .inner { color: red; }}";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  ASSERT_EQ(1u, sheet->ChildRules().size());
  StyleRule* parent = DynamicTo<StyleRule>(sheet->ChildRules()[0].Get());
  ASSERT_NE(nullptr, parent);
  EXPECT_EQ("color: green;", parent->Properties().AsText());
  EXPECT_EQ(".element", parent->SelectorsText());

  ASSERT_NE(nullptr, parent->ChildRules());
  ASSERT_EQ(1u, parent->ChildRules()->size());
  const StyleRule* child =
      DynamicTo<StyleRule>((*parent->ChildRules())[0].Get());
  ASSERT_NE(nullptr, child);
  EXPECT_EQ("color: red;", child->Properties().AsText());
  EXPECT_EQ("& > .inner", child->SelectorsText());
}

TEST(CSSParserImplTest, NestingAtTopLevelIsLegalThoughIsMatchesNothing) {
  test::TaskEnvironment task_environment;
  String sheet_text = "&.element { color: orchid; }";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  ASSERT_EQ(1u, sheet->ChildRules().size());
  const StyleRule* rule = DynamicTo<StyleRule>(sheet->ChildRules()[0].Get());
  EXPECT_EQ("color: orchid;", rule->Properties().AsText());
  EXPECT_EQ("&.element", rule->SelectorsText());
}

TEST(CSSParserImplTest, ErrorRecoveryEatsOnlyFirstDeclaration) {
  test::TaskEnvironment task_environment;
  // Note the colon after the opening bracket.
  String sheet_text = R"CSS(
    .element {:
      color: orchid;
      background-color: plum;
      accent-color: hotpink;
    }
    )CSS";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  ASSERT_EQ(1u, sheet->ChildRules().size());
  const StyleRule* rule = DynamicTo<StyleRule>(sheet->ChildRules()[0].Get());
  EXPECT_EQ("background-color: plum; accent-color: hotpink;",
            rule->Properties().AsText());
  EXPECT_EQ(".element", rule->SelectorsText());
}

TEST(CSSParserImplTest, NestedEmptySelectorCrash) {
  test::TaskEnvironment task_environment;
  String sheet_text = "y{ :is() {} }";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  // We only really care that it doesn't crash.
}

TEST(CSSParserImplTest, NestedRulesInsideMediaQueries) {
  test::TaskEnvironment task_environment;
  String sheet_text = R"CSS(
    .element {
      color: green;
      @media (width < 1000px) {
        color: navy;
        font-size: 12px;
        & + #foo { color: red; }
      }
    }
    )CSS";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  ASSERT_EQ(1u, sheet->ChildRules().size());
  StyleRule* parent = DynamicTo<StyleRule>(sheet->ChildRules()[0].Get());
  ASSERT_NE(nullptr, parent);
  EXPECT_EQ("color: green;", parent->Properties().AsText());
  EXPECT_EQ(".element", parent->SelectorsText());

  ASSERT_NE(nullptr, parent->ChildRules());
  ASSERT_EQ(1u, parent->ChildRules()->size());
  const StyleRuleMedia* media_query =
      DynamicTo<StyleRuleMedia>((*parent->ChildRules())[0].Get());
  ASSERT_NE(nullptr, media_query);

  ASSERT_EQ(2u, media_query->ChildRules().size());

  // Implicit CSSNestedDeclarations rule around the properties.
  const StyleRuleNestedDeclarations* child0 =
      DynamicTo<StyleRuleNestedDeclarations>(
          media_query->ChildRules()[0].Get());
  ASSERT_NE(nullptr, child0);
  EXPECT_EQ("color: navy; font-size: 12px;", child0->Properties().AsText());

  const StyleRule* child1 =
      DynamicTo<StyleRule>(media_query->ChildRules()[1].Get());
  ASSERT_NE(nullptr, child1);
  EXPECT_EQ("color: red;", child1->Properties().AsText());
  EXPECT_EQ("& + #foo", child1->SelectorsText());
}

// A version of NestedRulesInsideMediaQueries where CSSNestedDeclarations
// is disabled. Can be removed when the CSSNestedDeclarations is removed.
TEST(CSSParserImplTest,
     NestedRulesInsideMediaQueries_CSSNestedDeclarationsDisabled) {
  ScopedCSSNestedDeclarationsForTest nested_declarations_enabled(false);

  test::TaskEnvironment task_environment;
  String sheet_text = R"CSS(
    .element {
      color: green;
      @media (width < 1000px) {
        color: navy;
        font-size: 12px;
        & + #foo { color: red; }
      }
    }
    )CSS";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  CSSParserImpl::ParseStyleSheet(sheet_text, context, sheet);

  ASSERT_EQ(1u, sheet->ChildRules().size());
  StyleRule* parent = DynamicTo<StyleRule>(sheet->ChildRules()[0].Get());
  ASSERT_NE(nullptr, parent);
  EXPECT_EQ("color: green;", parent->Properties().AsText());
  EXPECT_EQ(".element", parent->SelectorsText());

  ASSERT_NE(nullptr, parent->ChildRules());
  ASSERT_EQ(1u, parent->ChildRules()->size());
  const StyleRuleMedia* media_query =
      DynamicTo<StyleRuleMedia>((*parent->ChildRules())[0].Get());
  ASSERT_NE(nullptr, media_query);

  ASSERT_EQ(2u, media_query->ChildRules().size());

  // Implicit & {} rule around the properties.
  const StyleRule* child0 =
      DynamicTo<StyleRule>(media_query->ChildRules()[0].Get());
  ASSERT_NE(nullptr, child0);
  EXPECT_EQ("color: navy; font-size: 12px;", child0->Properties().AsText());
  EXPECT_EQ("&", child0->SelectorsText());

  const StyleRule* child1 =
      DynamicTo<StyleRule>(media_query->ChildRules()[1].Get());
  ASSERT_NE(nullptr, child1);
  EXPECT_EQ("color: red;", child1->Properties().AsText());
  EXPECT_EQ("& + #foo", child1->SelectorsText());
}

TEST(CSSParserImplTest, ObserveNestedMediaQuery) {
  test::TaskEnvironment task_environment;
  String sheet_text = R"CSS(
    .element {
      color: green;
      @media (width < 1000px) {
        color: navy;
      }
    }
    )CSS";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  // Observe the @media rule.
  test_css_parser_observer.target_nesting_level_ = 1;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, sheet,
                                             test_css_parser_observer);

  EXPECT_EQ(test_css_parser_observer.rule_type_, StyleRule::RuleType::kMedia);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 49u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 66u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 67u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 95u);
}

TEST(CSSParserImplTest, ObserveNestedLayer) {
  test::TaskEnvironment task_environment;
  String sheet_text = R"CSS(
    .element {
      color: green;
      @layer foo {
        color: navy;
      }
    }
    )CSS";

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  // Observe the @layer rule.
  test_css_parser_observer.target_nesting_level_ = 1;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, sheet,
                                             test_css_parser_observer);

  EXPECT_EQ(test_css_parser_observer.rule_type_,
            StyleRule::RuleType::kLayerBlock);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 49u);
  EXPECT_EQ(test_css_parser_observer.rule_header_end_, 53u);
  EXPECT_EQ(test_css_parser_observer.rule_body_start_, 54u);
  EXPECT_EQ(test_css_parser_observer.rule_body_end_, 82u);
}

TEST(CSSParserImplTest, NestedIdent) {
  test::TaskEnvironment task_environment;

  String sheet_text = "div { p:hover { } }";
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(context);
  TestCSSParserObserver test_css_parser_observer;
  CSSParserImpl::ParseStyleSheetForInspector(sheet_text, context, style_sheet,
                                             test_css_parser_observer);

  // 'p:hover { }' should be reported both as a failed declaration,
  // and as a style rule (at the same location).
  EXPECT_EQ(test_css_parser_observer.property_start_, 6u);
  EXPECT_EQ(test_css_parser_observer.rule_header_start_, 6u);
}

TEST(CSSParserImplTest,
     ConsumeUnparsedDeclarationRemovesImportantAnnotationIfPresent) {
  test::TaskEnvironment task_environment;
  struct TestCase {
    String input;
    String expected_text;
    bool expected_is_important;
  };
  static const TestCase test_cases[] = {
      {"", "", false},
      {"!important", "", true},
      {" !important", "", true},
      {"!", "PARSE ERROR", false},
      {"1px", "1px", false},
      {"2px!important", "2px", true},
      {"3px !important", "3px", true},
      {"4px ! important", "4px", true},
      {"5px !important ", "5px", true},
      {"6px !!important", "PARSE ERROR", true},
      {"7px !important !important", "PARSE ERROR", true},
      {"8px important", "8px important", false},
  };
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  for (auto current_case : test_cases) {
    SCOPED_TRACE(current_case.input);
    CSSParserTokenStream stream(current_case.input);
    bool is_important;
    CSSVariableData* data = CSSVariableParser::ConsumeUnparsedDeclaration(
        stream, /*allow_important_annotation=*/true,
        /*is_animation_tainted=*/false,
        /*must_contain_variable_reference=*/false,
        /*restricted_value=*/true, /*comma_ends_declaration=*/false,
        is_important, *context);
    if (current_case.expected_text == "PARSE ERROR") {
      EXPECT_FALSE(data);
    } else {
      EXPECT_TRUE(data);
      if (data) {
        EXPECT_EQ(is_important, current_case.expected_is_important);
        EXPECT_EQ(data->OriginalText().ToString(), current_case.expected_text);
      }
    }
  }
}

TEST(CSSParserImplTest, InvalidLayerRules) {
  test::TaskEnvironment task_environment;
  using css_test_helpers::ParseRule;
  ScopedNullExecutionContext execution_context;
  Document* document =
      Document::CreateForTest(execution_context.GetExecutionContext());

  // At most one layer name in an @layer block rule
  EXPECT_FALSE(ParseRule(*document, "@layer foo, bar { }"));

  // Layers must be named in an @layer statement rule
  EXPECT_FALSE(ParseRule(*document, "@layer ;"));
  EXPECT_FALSE(ParseRule(*document, "@layer foo, , bar;"));

  // Invalid layer names
  EXPECT_FALSE(ParseRule(*document, "@layer foo.bar. { }"));
  EXPECT_FALSE(ParseRule(*document, "@layer foo.bar.;"));
  EXPECT_FALSE(ParseRule(*document, "@layer .foo.bar { }"));
  EXPECT_FALSE(ParseRule(*document, "@layer .foo.bar;"));
  EXPECT_FALSE(ParseRule(*document, "@layer foo. bar { }"));
  EXPECT_FALSE(ParseRule(*document, "@layer foo. bar;"));
  EXPECT_FALSE(ParseRule(*document, "@layer foo bar { }"));
  EXPECT_FALSE(ParseRule(*document, "@layer foo bar;"));
  EXPECT_FALSE(ParseRule(*document, "@layer foo/bar { }"));
  EXPECT_FALSE(ParseRule(*document, "@layer foo/bar;"));
}

TEST(CSSParserImplTest, ValidLayerBlockRule) {
  test::TaskEnvironment task_environment;
  using css_test_helpers::ParseRule;
  ScopedNullExecutionContext execution_context;
  Document* document =
      Document::CreateForTest(execution_context.GetExecutionContext());

  // Basic named layer
  {
    String rule = "@layer foo { }";
    auto* parsed = DynamicTo<StyleRuleLayerBlock>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    ASSERT_EQ(1u, parsed->GetName().size());
    EXPECT_EQ("foo", parsed->GetName()[0]);
  }

  // Unnamed layer
  {
    String rule = "@layer { }";
    auto* parsed = DynamicTo<StyleRuleLayerBlock>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    ASSERT_EQ(1u, parsed->GetName().size());
    EXPECT_EQ(g_empty_atom, parsed->GetName()[0]);
  }

  // Sub-layer declared directly
  {
    String rule = "@layer foo.bar { }";
    auto* parsed = DynamicTo<StyleRuleLayerBlock>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    ASSERT_EQ(2u, parsed->GetName().size());
    EXPECT_EQ("foo", parsed->GetName()[0]);
    EXPECT_EQ("bar", parsed->GetName()[1]);
  }
}

TEST(CSSParserImplTest, ValidLayerStatementRule) {
  test::TaskEnvironment task_environment;
  using css_test_helpers::ParseRule;
  ScopedNullExecutionContext execution_context;
  Document* document =
      Document::CreateForTest(execution_context.GetExecutionContext());

  {
    String rule = "@layer foo;";
    auto* parsed =
        DynamicTo<StyleRuleLayerStatement>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    ASSERT_EQ(1u, parsed->GetNames().size());
    ASSERT_EQ(1u, parsed->GetNames()[0].size());
    EXPECT_EQ("foo", parsed->GetNames()[0][0]);
  }

  {
    String rule = "@layer foo, bar;";
    auto* parsed =
        DynamicTo<StyleRuleLayerStatement>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    ASSERT_EQ(2u, parsed->GetNames().size());
    ASSERT_EQ(1u, parsed->GetNames()[0].size());
    EXPECT_EQ("foo", parsed->GetNames()[0][0]);
    ASSERT_EQ(1u, parsed->GetNames()[1].size());
    EXPECT_EQ("bar", parsed->GetNames()[1][0]);
  }

  {
    String rule = "@layer foo, bar.baz;";
    auto* parsed =
        DynamicTo<StyleRuleLayerStatement>(ParseRule(*document, rule));
    ASSERT_TRUE(parsed);
    ASSERT_EQ(2u, parsed->GetNames().size());
    ASSERT_EQ(1u, parsed->GetNames()[0].size());
    EXPECT_EQ("foo", parsed->GetNames()[0][0]);
    ASSERT_EQ(2u, parsed->GetNames()[1].size());
    EXPECT_EQ("bar", parsed->GetNames()[1][0]);
    EXPECT_EQ("baz", parsed->GetNames()[1][1]);
  }
}

TEST(CSSParserImplTest, NestedLayerRules) {
  test::TaskEnvironment task_environment;
  using css_test_helpers::ParseRule;
  ScopedNullExecutionContext execution_context;
  Document* document =
      Document::CreateForTest(execution_context.GetExecutionContext());

  // Block rule as a child rule.
  {
    String rule = "@layer foo { @layer bar { } }";
    auto* foo = DynamicTo<StyleRuleLayerBlock>(ParseRule(*document, rule));
    ASSERT_TRUE(foo);
    ASSERT_EQ(1u, foo->GetName().size());
    EXPECT_EQ("foo", foo->GetName()[0]);
    ASSERT_EQ(1u, foo->ChildRules().size());

    auto* bar = DynamicTo<StyleRuleLayerBlock>(foo->ChildRules()[0].Get());
    ASSERT_TRUE(bar);
    ASSERT_EQ(1u, bar->GetName().size());
    EXPECT_EQ("bar", bar->GetName()[0]);
  }

  // Statement rule as a child rule.
  {
    String rule = "@layer foo { @layer bar, baz; }";
    auto* foo = DynamicTo<StyleRuleLayerBlock>(ParseRule(*document, rule));
    ASSERT_TRUE(foo);
    ASSERT_EQ(1u, foo->GetName().size());
    EXPECT_EQ("foo", foo->GetName()[0]);
    ASSERT_EQ(1u, foo->ChildRules().size());

    auto* barbaz =
        DynamicTo<StyleRuleLayerStatement>(foo->ChildRules()[0].Get());
    ASSERT_TRUE(barbaz);
    ASSE
```