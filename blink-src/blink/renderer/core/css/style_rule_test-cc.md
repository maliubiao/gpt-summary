Response:
Let's break down the thought process to analyze the provided C++ test file.

1. **Understand the Goal:** The request asks for a breakdown of `style_rule_test.cc`, focusing on its functionality, relation to web technologies (HTML, CSS, JavaScript), logical reasoning (with examples), common errors, and debugging context.

2. **Initial Scan and Key Includes:** I first quickly scan the `#include` directives. This immediately tells me the file is about testing:
    * `style_rule.h`: The core subject of the tests.
    * `css_rule_list.h`, `css_scope_rule.h`, `css_style_rule.h`: Specific CSS rule types being tested.
    * `css_test_helpers.h`: Utility functions for creating and parsing CSS. This is a crucial clue about the file's purpose.
    * `document.h`:  Indicates interaction with the DOM.
    * `page_test_base.h`:  Signals that these are integration or functional tests within the Blink rendering engine.
    * `runtime_enabled_features_test_helpers.h`: Likely related to testing features that can be enabled/disabled.
    * `wtf/text/string_builder.h`:  String manipulation utility.

3. **Identify the Test Fixture:**  The line `class StyleRuleTest : public PageTestBase {};` defines a test fixture. This means the tests within this class will have access to the `PageTestBase` functionality, likely including setting up a minimal rendering environment (a "page").

4. **Analyze the Helper Functions:** The anonymous namespace contains several helper functions:
    * `FindPseudoSelector`: This function searches for a specific pseudo-class selector within a `CSSSelector` structure. It handles nested selectors (like those inside `:is()`). This is directly related to CSS selector parsing and matching.
    * `FindParentSelector`: A specialized version of `FindPseudoSelector` looking for the `kPseudoParent` pseudo-class, which is used for the nesting selector (`&`). This hints at testing CSS nesting features.
    * `FindUnparsedSelector`: Similar to the above, but for `kPseudoUnparsed`. The comment mentions this relates to how Blink captures nesting information within unparsed parts of selectors (like inside `:is()`).
    * `FindNestingContext`:  Combines `FindUnparsedSelector` and `FindParentSelector` to get both the nesting type and the parent rule. This confirms a focus on testing CSS nesting behavior.

5. **Examine Individual Tests (Focus on Functionality and Web Technology Relevance):** Now, I go through each `TEST_F` function:
    * `StyleRulePropertyCopy`: Tests the `Copy()` method of `StyleRuleProperty`. This is about the internal representation and manipulation of `@property` rules in CSS.
    * `SetPreludeTextReparentsStyleRules`: This is clearly about how changing the prelude (the part of a rule before the `{}`) of a `@scope` rule affects the parent relationships of nested rules. The use of the `&` selector is a direct link to CSS nesting.
    * `SetPreludeTextWithEscape`:  A simple test ensuring that setting the prelude with escaped characters doesn't cause a crash. This touches on CSS syntax parsing.
    * `SetPreludeTextPreservesNestingContext`: A more involved test. It creates a stylesheet with nested `@scope` rules and uses `:is()` with nesting and `:scope`. It verifies that changing the prelude of a `@scope` rule preserves the understanding of whether it's a nesting context (`&`) or a scope context (`:scope`). This highlights testing complex CSS nesting scenarios.
    * `SetPreludeTextPreservesImplicitScope`, `SetPreludeTextBecomesImplicitScope`, `SetPreludeTextBecomesNonImplicitScope`: These tests focus on how setting the prelude of a `@scope` rule affects whether it's considered an "implicit scope" (i.e., `@scope {}` without specific selectors). This is about the specific semantics of the `@scope` rule.

6. **Identify Relationships to Web Technologies:**  As I examine the tests, I explicitly note the connections to HTML, CSS, and JavaScript:
    * **CSS:** The entire file revolves around testing CSS rules (`@property`, `@scope`, and implicit style rules within them). The tests directly manipulate and parse CSS syntax. The use of selectors, nesting, and specific CSS features like `@property` and `@scope` are central.
    * **HTML:** While not directly creating HTML elements, the tests operate within the context of a `Document`, which represents an HTML document. The CSS rules being tested would eventually be applied to HTML elements.
    * **JavaScript:** Although this specific test file is C++, these tests are part of the Blink rendering engine, which *interprets* and *applies* CSS that is often loaded or manipulated via JavaScript. Changes or bugs in these CSS rule implementations *will* affect how JavaScript interacts with styles on a web page.

7. **Consider Logical Reasoning (Assumptions and Outputs):** For each test, I think about what the *expected outcome* is based on the *input CSS*. For instance:
    * *Input:*  A `@scope` rule with nested rules using `&`.
    * *Action:* Change the prelude of the `@scope` rule.
    * *Assumption:* The `&` selector in the nested rules should now refer to the selectors in the *new* prelude.
    * *Output:* The test verifies that the parent rule associated with the `&` selector is indeed updated.

8. **Think About Common User/Programming Errors:**  Based on the tests, I can infer potential errors:
    * **Incorrect `@property` syntax:**  The `StyleRulePropertyCopy` test, although simple, hints at the importance of correctly defining `@property` rules (syntax, initial value, inheritance).
    * **Misunderstanding CSS Nesting (`&`):** The tests around `SetPreludeTextReparentsStyleRules` and `SetPreludeTextPreservesNestingContext` directly address how developers might misunderstand how the `&` selector works, especially when dynamically changing `@scope` rules. Incorrect assumptions about the parent selector could lead to unexpected styling.
    * **Incorrect `@scope` syntax:** The tests involving implicit and explicit scopes highlight potential errors in defining the prelude of `@scope` rules. For example, forgetting the selectors in `@scope (...)` when intending a specific scope.

9. **Simulate User Operations for Debugging:**  I try to imagine how a user's actions could lead to the code being tested:
    * **Developer writing CSS:** A web developer writing CSS code that includes `@property` or `@scope` rules, especially with nesting, is the primary way this code is exercised.
    * **Dynamic CSS manipulation via JavaScript:** JavaScript code that modifies the text content of style sheets or individual CSS rules can trigger the logic being tested (e.g., setting `sheet.insertRule()` or modifying `rule.selectorText`).
    * **Browser interpreting CSS:** When the browser loads a web page, the CSS parsing and rule application logic (which these tests cover) is executed.

10. **Structure the Answer:** Finally, I organize the information into the requested sections: functionality, relationships to web technologies, logical reasoning, common errors, and debugging context. I use clear examples to illustrate the concepts.
This C++ file, `style_rule_test.cc`, is part of the Blink rendering engine in Chromium. Its primary function is to **test the functionality of various `StyleRule` subclasses** within the Blink core. These `StyleRule` classes represent different types of CSS rules.

Here's a breakdown of its functionalities and their relation to web technologies:

**1. Testing Core `StyleRule` Functionality:**

* **Object Copying (`StyleRulePropertyCopy`):**
    * **Function:** Tests the `Copy()` method of `StyleRuleProperty`, which represents the `@property` at-rule in CSS. It verifies that when a `StyleRuleProperty` object is copied, the new object has the same properties (name, syntax, initial value, inheritance) and is a distinct object in memory.
    * **Relation to CSS:** Directly related to the `@property` at-rule, which allows developers to define custom CSS properties with specific syntax, initial values, and inheritance behavior.
    * **Example:** If a CSS file contains `@property --my-color { syntax: '<color>'; initial-value: red; inherits: false; }`, this test ensures that Blink can correctly copy the internal representation of this rule.
    * **Assumption and Output:**
        * **Input:** A parsed `StyleRuleProperty` object representing `@property --foo { syntax: "<length>"; initial-value: 0px; inherits: false; }`.
        * **Action:** Call the `Copy()` method on this object.
        * **Output:** The test asserts that the copied object is different in memory but has the same name (`--foo`), syntax (`<length>`), initial value (`0px`), and inheritance flag (false).

* **Reparenting Style Rules (`SetPreludeTextReparentsStyleRules`):**
    * **Function:** Focuses on how changing the "prelude text" (the part before the curly braces) of a `@scope` rule affects the parent relationships of nested style rules that use the nesting selector (`&`).
    * **Relation to CSS:** Directly related to the `@scope` at-rule and CSS nesting. The `&` selector within a nested rule refers to the selector of the parent rule.
    * **Example:**
        ```css
        @scope (.a) to (.b &) {
          .c & { color: blue; }
        }
        ```
        Here, the `&` in `.b &` refers to `.a`, and the `&` in `.c &` also refers to `.a`. This test verifies that if the prelude of the `@scope` rule is changed (e.g., to `@scope (.x) to (.b &)`), the `&` selectors in the nested rules now correctly point to the new scope selector (`.x`).
    * **Assumption and Output:**
        * **Input:** A parsed `@scope` rule with nested rules using `&`.
        * **Action:** Change the prelude text of the `@scope` rule using `SetPreludeText`.
        * **Output:** The test asserts that the `ParentRule()` of the `CSSSelector` representing the `&` in the nested rules now points to the `StyleRule` corresponding to the new scope selector.

* **Handling Escaped Characters in Prelude Text (`SetPreludeTextWithEscape`):**
    * **Function:**  A basic test to ensure that setting the prelude text of a `@scope` rule with escaped characters doesn't cause a crash. This checks the robustness of the parsing logic.
    * **Relation to CSS:**  CSS allows for escaped characters in selectors. This test verifies that Blink handles this correctly.
    * **Example:** `@scope (.a) to (.\\1F60A)` where `\1F60A` is the Unicode escape sequence for a smiley face emoji.
    * **Assumption and Output:**
        * **Input:** A `@scope` rule and a prelude text string containing an escaped character.
        * **Action:** Call `SetPreludeText` with the escaped prelude text.
        * **Output:** The test ensures no crash occurs.

* **Preserving Nesting Context (`SetPreludeTextPreservesNestingContext`):**
    * **Function:** Tests that when the prelude text of a `@scope` rule is changed, the information about whether it's acting as a nesting context (`&`) or a scoping context (`:scope`) is preserved, especially when using `:is()` pseudo-classes.
    * **Relation to CSS:**  Crucial for understanding how `@scope` and CSS nesting interact, particularly within complex selectors.
    * **Example:**
        ```css
        div {
          @scope (:is(&, !&)) { /* '&' here signifies nesting context */
            .b {}
          }
        }

        @scope (div) {
          @scope (:is(&, !:scope)) { /* ':scope' here signifies scope context */
            .b {}
          }
        }
        ```
        This test checks that after changing the prelude of the inner `@scope` rules, Blink still correctly identifies whether the `&` refers to the parent rule's selector (nesting) or the scope selector itself.
    * **Assumption and Output:**
        * **Input:** A stylesheet with nested `@scope` rules using `:is(&...)` and `:is(&:scope)`.
        * **Action:** Change the prelude text of the inner `@scope` rules.
        * **Output:** The test verifies that the `NestingType` associated with the selectors remains the same (either `kNesting` for `&` or `kScope` for `:scope`).

* **Managing Implicit Scope (`SetPreludeTextPreservesImplicitScope`, `SetPreludeTextBecomesImplicitScope`, `SetPreludeTextBecomesNonImplicitScope`):**
    * **Function:** Tests the behavior of `@scope` rules when their prelude is set to empty (making them implicit, applying to the entire document) or set to a non-empty value (making them explicit with specific selectors).
    * **Relation to CSS:** Directly related to the syntax and semantics of the `@scope` at-rule, specifically the difference between `@scope { ... }` (implicit) and `@scope (selector) { ... }` (explicit).
    * **Example:**
        * `@scope { .a {} }` is an implicit scope.
        * `@scope (.a) { .b {} }` is an explicit scope.
    * **Assumption and Output:**
        * **Input:** `@scope` rules with or without prelude selectors.
        * **Action:** Use `SetPreludeText` to change the presence or absence of prelude selectors.
        * **Output:** The tests assert whether the `IsImplicit()` method of the `StyleScope` returns `true` or `false` based on the prelude text.

**2. Relationship to JavaScript, HTML, and CSS:**

* **CSS:** This test file is fundamentally about testing the implementation of CSS rules within the Blink engine. It ensures that CSS syntax is parsed correctly and that the behavior of different CSS at-rules (`@property`, `@scope`) and features (nesting) is as specified.
* **HTML:** While this file doesn't directly manipulate HTML elements, the CSS rules being tested will eventually be applied to HTML elements in a web page. The `GetDocument()` method used in the tests provides the context of a Document, which represents an HTML document.
* **JavaScript:** JavaScript can interact with CSS in various ways (e.g., manipulating `style` attributes, accessing and modifying CSSOM). The correct implementation of CSS rules in Blink is crucial for JavaScript to work predictably with styles. For instance, if JavaScript reads the value of a custom property defined by `@property`, this test helps ensure that Blink has parsed that rule correctly. Similarly, if JavaScript dynamically modifies the selector of a `@scope` rule, the reparenting logic tested here is essential.

**3. Logical Reasoning (Assumptions and Outputs):**

The individual test cases demonstrate logical reasoning by setting up specific CSS rule scenarios and then asserting expected outcomes based on the CSS specifications. The examples provided within the "Functionality" section illustrate these assumptions and outputs.

**4. User or Programming Common Usage Errors:**

* **Incorrect `@property` Syntax:**  A common error is defining `@property` rules with incorrect syntax (e.g., missing the `syntax` descriptor, using invalid values). The `StyleRulePropertyCopy` test, while focused on copying, implicitly validates that a correctly formed `@property` rule can be created and copied.
* **Misunderstanding CSS Nesting (`&`):** Developers might incorrectly assume how the `&` selector works in nested rules, especially within `@scope`. They might expect it to always refer to the immediate parent rule, whereas its behavior can be more nuanced, especially with `:is()` and other complex selectors. The `SetPreludeTextReparentsStyleRules` and `SetPreludeTextPreservesNestingContext` tests directly address potential misunderstandings related to this.
* **Incorrect `@scope` Syntax:**  Errors can occur in defining the prelude of `@scope` rules, such as forgetting to include selectors when intending a specific scope or misunderstanding the difference between implicit and explicit scopes. The tests related to implicit scope (`SetPreludeTextPreservesImplicitScope`, etc.) highlight these potential errors.

**5. User Operation as Debugging Clues:**

Here's how user actions can lead to this code being involved and serve as debugging clues:

1. **Developer writes CSS with `@property` or `@scope`:** If a web developer writes CSS code that includes these at-rules, and the browser renders the page incorrectly, the issue might lie in the parsing or application of these rules. This would lead developers or browser engineers to investigate the code responsible for handling these rules, including the logic tested in `style_rule_test.cc`.

2. **JavaScript dynamically modifies CSS:** If JavaScript code manipulates the CSSOM (e.g., using `CSSStyleSheet.insertRule()` or modifying `CSSRule.selectorText` of a `@scope` rule), any bugs in how Blink handles these modifications, particularly regarding reparenting or nesting context, could manifest as rendering issues. This would point to the code tested in files like this one.

3. **Browser rendering a page with complex CSS:** When a user visits a webpage with complex CSS involving `@property`, `@scope`, and nesting, the browser's rendering engine will parse and apply these styles. If the rendering is incorrect, developers investigating the issue might look at the specific CSS rules involved and trace the code execution within Blink that handles those rules. The tests in `style_rule_test.cc` are designed to verify the correctness of this code.

**In summary, `style_rule_test.cc` is a crucial part of ensuring the correct implementation of various CSS rule types within the Blink rendering engine. It plays a vital role in preventing bugs and ensuring that web developers' CSS code behaves as expected across different browsers.**

Prompt: 
```
这是目录为blink/renderer/core/css/style_rule_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/style_rule.h"

#include "third_party/blink/renderer/core/css/css_rule_list.h"
#include "third_party/blink/renderer/core/css/css_scope_rule.h"
#include "third_party/blink/renderer/core/css/css_style_rule.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

using css_test_helpers::ParseRule;

class StyleRuleTest : public PageTestBase {};

namespace {

// Find first occurrence of a simple selector with the given PseudoType,
// traversing into lists (e.g. :is()).
const CSSSelector* FindPseudoSelector(const CSSSelector* selector,
                                      CSSSelector::PseudoType pseudo_type) {
  for (const CSSSelector* s = selector; s; s = s->NextSimpleSelector()) {
    if (s->GetPseudoType() == pseudo_type) {
      return s;
    }
    if (s->SelectorList()) {
      for (const CSSSelector* complex = s->SelectorList()->First(); complex;
           complex = CSSSelectorList::Next(*complex)) {
        if (const CSSSelector* parent =
                FindPseudoSelector(complex, pseudo_type)) {
          return parent;
        }
      }
    }
  }
  return nullptr;
}

const CSSSelector* FindParentSelector(const CSSSelector* selector) {
  return FindPseudoSelector(selector, CSSSelector::kPseudoParent);
}

const CSSSelector* FindUnparsedSelector(const CSSSelector* selector) {
  return FindPseudoSelector(selector, CSSSelector::kPseudoUnparsed);
}

// Finds the CSSNestingType (as captured by the first kPseudoUnparsed selector)
// and the parent rule for nesting (as captured by the first kPseudoParent
// selector).
std::pair<CSSNestingType, const StyleRule*> FindNestingContext(
    const CSSSelector* selector) {
  const CSSSelector* unparsed_selector = FindUnparsedSelector(selector);
  const CSSSelector* parent_selector = FindParentSelector(selector);
  return std::make_pair<CSSNestingType, const StyleRule*>(
      unparsed_selector ? unparsed_selector->GetNestingType()
                        : CSSNestingType::kNone,
      parent_selector ? parent_selector->ParentRule() : nullptr);
}

}  // namespace

TEST_F(StyleRuleTest, StyleRulePropertyCopy) {
  auto* base_rule = css_test_helpers::ParseRule(GetDocument(), R"CSS(
      @property --foo {
        syntax: "<length>";
        initial-value: 0px;
        inherits: false;
      }
    )CSS");

  ASSERT_TRUE(base_rule);
  auto* base_copy = base_rule->Copy();

  EXPECT_NE(base_rule, base_copy);
  EXPECT_EQ(base_rule->GetType(), base_copy->GetType());

  auto* rule = DynamicTo<StyleRuleProperty>(base_rule);
  auto* copy = DynamicTo<StyleRuleProperty>(base_copy);

  ASSERT_TRUE(rule);
  ASSERT_TRUE(copy);

  EXPECT_EQ(rule->GetName(), copy->GetName());
  EXPECT_EQ(rule->GetSyntax(), copy->GetSyntax());
  EXPECT_EQ(rule->Inherits(), copy->Inherits());
  EXPECT_EQ(rule->GetInitialValue(), copy->GetInitialValue());
}

TEST_F(StyleRuleTest, SetPreludeTextReparentsStyleRules) {
  auto* scope_rule = DynamicTo<StyleRuleScope>(
      css_test_helpers::ParseRule(GetDocument(), R"CSS(
      @scope (.a) to (.b &) {
        .c & { }
      }
    )CSS"));

  ASSERT_TRUE(scope_rule);
  ASSERT_EQ(1u, scope_rule->ChildRules().size());
  StyleRule& child_rule = To<StyleRule>(*scope_rule->ChildRules()[0]);

  const StyleScope& scope_before = scope_rule->GetStyleScope();
  StyleRule* rule_before = scope_before.RuleForNesting();
  ASSERT_TRUE(rule_before);
  EXPECT_EQ(".a", rule_before->SelectorsText());

  EXPECT_EQ(rule_before, FindParentSelector(scope_before.To())->ParentRule());
  EXPECT_EQ(rule_before,
            FindParentSelector(child_rule.FirstSelector())->ParentRule());

  // Note that CSSNestingType::kNone here refers to the nesting context outside
  // of `scope_rule` (which in this case has no parent rule).
  scope_rule->SetPreludeText(GetDocument().GetExecutionContext(),
                             "(.x) to (.b &)", CSSNestingType::kNone,
                             /* parent_rule_for_nesting */ nullptr,
                             /* is_within_scope */ false,
                             /* style_sheet */ nullptr);

  const StyleScope& scope_after = scope_rule->GetStyleScope();
  StyleRule* rule_after = scope_after.RuleForNesting();
  ASSERT_TRUE(rule_after);
  EXPECT_EQ(".x", rule_after->SelectorsText());

  // Verify that '&' (in '.b &') now points to `rule_after`.
  EXPECT_EQ(rule_after, FindParentSelector(scope_after.To())->ParentRule());
  // Verify that '&' (in '.c &') now points to `rule_after`.
  EXPECT_EQ(rule_after,
            FindParentSelector(child_rule.FirstSelector())->ParentRule());
}

TEST_F(StyleRuleTest, SetPreludeTextWithEscape) {
  auto* scope_rule = DynamicTo<StyleRuleScope>(
      css_test_helpers::ParseRule(GetDocument(), R"CSS(
      @scope (.a) to (.b &) {
        .c & { }
      }
    )CSS"));

  // Don't crash.
  scope_rule->SetPreludeText(GetDocument().GetExecutionContext(),
                             "(.x) to (.\\1F60A)", CSSNestingType::kNone,
                             /* parent_rule_for_nesting */ nullptr,
                             /* is_within_scope */ false,
                             /* style_sheet */ nullptr);
}

TEST_F(StyleRuleTest, SetPreludeTextPreservesNestingContext) {
  CSSStyleSheet* sheet = css_test_helpers::CreateStyleSheet(GetDocument());
  // Note that this test is making use of the fact that unparsed
  // :is()-arguments that contain either & or :scope *capture* whether they
  // contained & or :scope.
  //
  // See CSSSelector::SetUnparsedPlaceholder and CSSSelector::GetNestingType.
  sheet->SetText(R"CSS(
      div {
        @scope (:is(&, !&)) {
          .b {}
        }
      }

      @scope (div) {
        @scope (:is(&, !:scope)) {
          .b {}
        }
      }
    )CSS",
                 CSSImportRules::kIgnoreWithWarning);

  DummyExceptionStateForTesting exception_state;
  CSSRuleList* rules = sheet->rules(exception_state);
  ASSERT_TRUE(rules && rules->length() == 2u);

  // Nesting case (&).
  {
    auto* style_rule = DynamicTo<CSSStyleRule>(rules->item(0));
    ASSERT_TRUE(style_rule && style_rule->length() == 1u);
    auto* scope_rule = DynamicTo<CSSScopeRule>(style_rule->Item(0));
    ASSERT_TRUE(scope_rule);

    // Verify that SetPreludeText preservers nesting type and parent rule for
    // nesting.
    const auto& [nesting_type_before, parent_rule_before] = FindNestingContext(
        scope_rule->GetStyleRuleScope().GetStyleScope().From());
    EXPECT_EQ(CSSNestingType::kNesting, nesting_type_before);
    EXPECT_TRUE(parent_rule_before);
    scope_rule->SetPreludeText(GetDocument().GetExecutionContext(),
                               "(:is(.x, &, !&))");
    const auto& [nesting_type_after, parent_rule_after] = FindNestingContext(
        scope_rule->GetStyleRuleScope().GetStyleScope().From());
    EXPECT_EQ(nesting_type_before, nesting_type_after);
    EXPECT_EQ(parent_rule_before, parent_rule_after);
  }

  // @scope case
  {
    auto* outer_scope_rule = DynamicTo<CSSScopeRule>(rules->item(1));
    ASSERT_TRUE(outer_scope_rule && outer_scope_rule->length() == 1u);
    auto* inner_scope_rule = DynamicTo<CSSScopeRule>(outer_scope_rule->Item(0));
    ASSERT_TRUE(inner_scope_rule);

    // Verify that SetPreludeText preservers nesting type and parent rule for
    // nesting.
    const auto& [nesting_type_before, parent_rule_before] = FindNestingContext(
        inner_scope_rule->GetStyleRuleScope().GetStyleScope().From());
    EXPECT_EQ(CSSNestingType::kScope, nesting_type_before);
    EXPECT_TRUE(parent_rule_before);
    inner_scope_rule->SetPreludeText(GetDocument().GetExecutionContext(),
                                     "(:is(.x, &, !:scope))");
    const auto& [nesting_type_after, parent_rule_after] = FindNestingContext(
        inner_scope_rule->GetStyleRuleScope().GetStyleScope().From());
    EXPECT_EQ(nesting_type_before, nesting_type_after);
    EXPECT_EQ(parent_rule_before, parent_rule_after);
  }
}

TEST_F(StyleRuleTest, SetPreludeTextPreservesImplicitScope) {
  CSSStyleSheet* sheet = css_test_helpers::CreateStyleSheet(GetDocument());
  sheet->SetText(R"CSS(
      @scope {
        .a {}
      }
    )CSS",
                 CSSImportRules::kIgnoreWithWarning);

  DummyExceptionStateForTesting exception_state;
  CSSRuleList* rules = sheet->rules(exception_state);
  ASSERT_TRUE(rules && rules->length() == 1u);
  auto* scope_rule = DynamicTo<CSSScopeRule>(rules->item(0));
  ASSERT_TRUE(scope_rule);

  EXPECT_TRUE(scope_rule->GetStyleRuleScope().GetStyleScope().IsImplicit());
  scope_rule->SetPreludeText(GetDocument().GetExecutionContext(), "");
  EXPECT_TRUE(scope_rule->GetStyleRuleScope().GetStyleScope().IsImplicit());
}

TEST_F(StyleRuleTest, SetPreludeTextBecomesImplicitScope) {
  CSSStyleSheet* sheet = css_test_helpers::CreateStyleSheet(GetDocument());
  sheet->SetText(R"CSS(
      @scope (.a) {
        .b {}
      }
    )CSS",
                 CSSImportRules::kIgnoreWithWarning);

  DummyExceptionStateForTesting exception_state;
  CSSRuleList* rules = sheet->rules(exception_state);
  ASSERT_TRUE(rules && rules->length() == 1u);
  auto* scope_rule = DynamicTo<CSSScopeRule>(rules->item(0));
  ASSERT_TRUE(scope_rule);

  EXPECT_FALSE(scope_rule->GetStyleRuleScope().GetStyleScope().IsImplicit());
  scope_rule->SetPreludeText(GetDocument().GetExecutionContext(), "");
  EXPECT_TRUE(scope_rule->GetStyleRuleScope().GetStyleScope().IsImplicit());
}

TEST_F(StyleRuleTest, SetPreludeTextBecomesNonImplicitScope) {
  CSSStyleSheet* sheet = css_test_helpers::CreateStyleSheet(GetDocument());
  sheet->SetText(R"CSS(
      @scope {
        .b {}
      }
    )CSS",
                 CSSImportRules::kIgnoreWithWarning);

  DummyExceptionStateForTesting exception_state;
  CSSRuleList* rules = sheet->rules(exception_state);
  ASSERT_TRUE(rules && rules->length() == 1u);
  auto* scope_rule = DynamicTo<CSSScopeRule>(rules->item(0));
  ASSERT_TRUE(scope_rule);

  EXPECT_TRUE(scope_rule->GetStyleRuleScope().GetStyleScope().IsImplicit());
  scope_rule->SetPreludeText(GetDocument().GetExecutionContext(), "(.a)");
  EXPECT_FALSE(scope_rule->GetStyleRuleScope().GetStyleScope().IsImplicit());
}

}  // namespace blink

"""

```