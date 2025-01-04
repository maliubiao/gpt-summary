Response:
Let's break down the thought process to analyze the `selector_checker_test.cc` file.

**1. Understanding the Purpose of Test Files:**

The file name `selector_checker_test.cc` immediately suggests its primary function: testing the `SelectorChecker` class. Test files in software projects are crucial for verifying the correctness and functionality of specific components. Therefore, the core goal is to see how the `SelectorChecker` behaves under various conditions.

**2. Examining the Includes:**

The included headers provide valuable clues about the functionalities being tested:

*   `selector_checker.h`:  This is the primary component being tested.
*   `<bitset>`, `<optional>`: These suggest the test involves checking boolean flags or potentially the presence/absence of values.
*   `css_test_helpers.h`: Indicates the tests will involve parsing CSS selectors and rules.
*   `selector_checker-inl.h`:  Likely contains inline implementations or details relevant to the `SelectorChecker`.
*   `style_rule.h`:  Shows interaction with CSS style rules.
*   `document.h`, `shadow_root.h`, `html_element.h`:  Implies the tests manipulate the DOM structure and involve shadow DOM.
*   `computed_style.h`, `computed_style_constants.h`:  Indicates tests might check how styles are computed based on selector matching.
*   `page_test_base.h`:  Signifies this is a unit test within the larger Blink rendering engine framework.

**3. Analyzing the Test Structures (Key Areas of Functionality):**

The file is organized into several test fixtures and individual tests. This organization reveals different aspects of the `SelectorChecker`'s functionality being tested:

*   **`ScopeProximityTest`:**  The name and the `ScopeProximityTestData` structure clearly point to testing the `@scope` CSS at-rule and how the proximity (distance) to the scoping root is determined. The `html` and `rule` members define the setup, and `proximity` is the expected output.

*   **`MatchFlagsTest`:**  The `MatchFlagsTestData` structure with `selector` and `expected` members suggests testing which "flags" are set when a selector matches. The flag names like `Active`, `Drag`, `FocusWithin`, `Hover` point to dynamic pseudo-classes.

*   **`ImpactTest`:** The setup with nested `div` elements and the `Impact` enum (kSubject, kNonSubject, kBoth) indicates testing how selector matching influences the state of elements and their descendants/ancestors regarding events like hover, drag, focus.

*   **`MatchFlagsShadowTest`:**  This specifically uses shadow DOM (`<template shadowrootmode="open">`) and tests selectors like `:host` and `:host-context`, focusing on how selectors work within shadow DOM.

*   **`MatchFlagsScopeTest`:** This section seems to combine `@scope` rules with dynamic pseudo-classes like `:hover` to test how scoping affects the application of styles based on dynamic states.

*   **`EasySelectorCheckerTest`:**  The name suggests a simpler or optimized path for selector matching. The tests check which selectors are considered "easy" and perform basic matching.

*   **`SelectorCheckerTest`:** This contains a more general test case, likely covering edge cases or scenarios not specifically addressed by the other tests. The "PseudoScopeWithoutScope" test is a good example of testing error handling or default behavior.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

The tests directly manipulate HTML structures (using `SetHtmlInnerHTML` or setting `innerHTML`) and define CSS rules (using `css_test_helpers::ParseRule` or directly in strings). The behavior being tested is how CSS selectors match HTML elements. This is a fundamental aspect of how web pages are styled.

*   **HTML:** The tests use basic HTML elements like `div`, `span`, and attributes like `id` and `class`. The structure of the HTML is key to testing descendant, child, and sibling selectors. Shadow DOM is also used.

*   **CSS:** The tests utilize a wide range of CSS selectors:
    *   Type selectors (`div`)
    *   Class selectors (`.a`)
    *   ID selectors (`#target`)
    *   Attribute selectors (`[attr]`, `[attr="foo"]`)
    *   Pseudo-classes (`:active`, `:hover`, `:focus-within`, `:-webkit-drag`, `:visited`, `:link`, `:root`, `:any-link`, `:scope`, `:host`, `:host-context`)
    *   Pseudo-elements (`::before`, `::slotted`, `::cue`)
    *   Combinators (descendant space, child `>`, sibling `~`)
    *   Logical combinators (`:is`, `:not`, `:where`, `:-webkit-any`, `:has`)
    *   The `@scope` at-rule.

*   **JavaScript:** While this specific test file doesn't directly execute JavaScript code, the underlying functionality being tested is essential for the browser's rendering engine, which interacts with JavaScript through the DOM API. JavaScript can dynamically modify the DOM, and the `SelectorChecker` ensures styles are updated correctly.

**5. Inferring Logic and Examples:**

By examining the test cases, we can deduce the logic being tested and create examples:

*   **Scope Proximity:** The tests verify that the `proximity` value correctly reflects the distance to the *nearest* scoping root defined by the `@scope` rule. Nested scopes are handled correctly.

*   **Match Flags:** The tests check if the correct flags are set based on the presence of dynamic pseudo-classes in the selector. For instance, `:hover` sets the `Hover` flag. It also explores how flags are propagated (or not) through combinators.

*   **Impact:** These tests demonstrate how selectors involving dynamic pseudo-classes affect the `ChildrenOrSiblingsAffectedBy...` flags on elements. This is crucial for performance optimization, as the browser only needs to re-render parts of the page affected by state changes.

*   **Easy Selector Checker:**  The tests show that selectors with simple structures (type, class, ID, basic attribute selectors, and simple combinators) are considered "easy" for faster matching. More complex selectors (pseudo-classes like `:visited`, pseudo-elements, and certain combinator patterns) are not.

**6. Identifying Potential User/Programming Errors:**

The tests implicitly highlight potential errors:

*   **Incorrect `@scope` usage:**  If the proximity calculations are wrong, it suggests an error in how `@scope` rules are being interpreted or applied.

*   **Misunderstanding selector specificity:** While not directly tested here, the `SelectorChecker` is a component of the larger styling process. Errors in selector specificity can lead to unexpected styling.

*   **Incorrect use of dynamic pseudo-classes:**  For example, expecting `:hover` styles to apply when the element is not actually being hovered. The `MatchFlagsTest` and `ImpactTest` help ensure these pseudo-classes work as expected.

*   **Performance implications of complex selectors:** The `EasySelectorCheckerTest` hints at the performance differences between simple and complex selectors. Overusing complex selectors can impact page rendering performance.

**7. Tracing User Operations to the Code:**

While this test file is a unit test and doesn't directly involve user interaction, we can trace how user actions *lead* to this code being executed:

1. **User interacts with a web page:** This could involve hovering the mouse over an element, clicking on an element, focusing an input field, or dragging an element.

2. **Browser detects the interaction:** The browser's event handling mechanism detects these user actions.

3. **Style invalidation:** The browser determines if the user interaction might change the styling of any elements. For instance, hovering triggers a potential change in styles defined with the `:hover` pseudo-class.

4. **Selector matching:** The `SelectorChecker` is invoked to determine which CSS rules now apply to the affected elements based on the updated state (e.g., the element is now being hovered). This involves comparing the selectors in the style rules against the element's properties and the current browser state.

5. **Style recalculation and rendering:** If the selector matching results in a change in applicable styles, the browser recalculates the computed styles for the affected elements and re-renders them on the screen.

Therefore, while a user isn't directly *in* this test file, their interactions drive the browser's rendering engine, which relies on components like the `SelectorChecker` to apply styles correctly. This test file verifies the correctness of that component.
This C++ source code file, `selector_checker_test.cc`, is a unit test file for the `SelectorChecker` class within the Chromium Blink rendering engine. Its primary function is to rigorously test the logic of how CSS selectors are matched against DOM elements.

Here's a breakdown of its functionalities and relationships:

**Core Functionality:**

1. **Testing Selector Matching Logic:** The core purpose is to verify that the `SelectorChecker` class correctly determines if a given CSS selector matches a specific DOM element. This involves testing various types of selectors, combinators, and pseudo-classes.

2. **Testing `@scope` Rule Proximity:** A significant portion of the tests focuses on the `@scope` CSS at-rule. It checks if the `SelectorChecker` correctly calculates the proximity (distance) of a matching element to the nearest scoping root defined by `@scope`.

3. **Testing Match Flags:**  The tests verify that the `SelectorChecker` sets appropriate flags (`MatchFlags`) based on the selectors used. These flags indicate if the matching is influenced by dynamic pseudo-classes like `:hover`, `:active`, `:focus-within`, or `:-webkit-drag`.

4. **Testing Impact of Selectors:** The tests assess how selectors, especially those involving dynamic pseudo-classes, impact the state of elements and their ancestors/descendants. This includes checking flags like `ChildrenOrSiblingsAffectedByHover`, `AffectedBySubjectHas`, etc.

5. **Testing Shadow DOM Scenarios:**  Specific tests are dedicated to evaluating selector matching within the context of Shadow DOM, particularly focusing on the `:host` and `:host-context` pseudo-classes.

6. **Testing "Easy" Selector Optimization:** The file includes tests for `EasySelectorChecker`, which likely represents an optimization for quickly matching simpler selectors. It verifies which selectors are considered "easy" and if the matching logic for them is correct.

7. **Error Handling (Implicit):** While not explicitly a failure test, the structure of unit tests implicitly checks for crashes or unexpected behavior in various scenarios. The "PseudoScopeWithoutScope" test directly tests a potential edge case.

**Relationship to JavaScript, HTML, and CSS:**

This test file is fundamentally related to all three web technologies:

*   **CSS:** The tests directly parse and evaluate CSS selectors and the `@scope` at-rule. It ensures the Blink engine's implementation of CSS selector matching is correct and adheres to CSS specifications.
    *   **Example:** The `@scope` proximity tests use CSS like:
        ```css
        @scope (.a) {
          #target { z-index: 1; }
        }
        ```
        This tests how the selector `#target` within the `@scope` rule matches elements within the scope defined by the class `.a`.

*   **HTML:** The tests create simple HTML structures (using `SetHtmlInnerHTML` or direct string manipulation) to provide the DOM context for selector matching. The selectors target elements within these HTML structures.
    *   **Example:** The HTML in the scope proximity tests defines the element being targeted:
        ```html
        <div class=a>
          <div id=target></div>
        </div>
        ```

*   **JavaScript:** While this specific file is C++, the functionality it tests is crucial for the browser's rendering engine, which interacts heavily with JavaScript. When JavaScript manipulates the DOM or styles, the `SelectorChecker` is used to determine which CSS rules apply to the updated DOM.
    *   **Indirect Relationship:**  If a JavaScript script adds a class to an element, the `SelectorChecker` will be used to see if any CSS rules with that class selector now match the element.

**Logical Reasoning (Hypothetical Input and Output):**

Let's take an example from the `ScopeProximityTest`:

*   **Hypothetical Input:**
    *   **HTML:** `<div class=a><div><div id=target></div></div></div>`
    *   **CSS Rule:** `@scope (.a) { #target { z-index: 1; } }`
*   **Logical Reasoning:** The `#target` element is a descendant of an element with class `.a`, which is the scoping root. The proximity is the number of ancestor elements between the target and the scoping root (exclusive of the scoping root itself). In this case, there's one `div` between `.a` and `#target`.
*   **Expected Output:** `proximity` should be `1`.

Another example from `MatchFlagsTest`:

*   **Hypothetical Input:**
    *   **Selector:** `:hover`
    *   **Element:** A `div` element.
*   **Logical Reasoning:** The `:hover` pseudo-class only matches if the user's mouse is currently over the element. The `SelectorChecker` needs to recognize this and set the appropriate flag.
*   **Expected Output:** The `result.flags` should have the `Hover()` flag set.

**Common User or Programming Errors:**

This test file helps prevent errors like:

*   **Incorrect `@scope` behavior:**  If the proximity calculation is wrong, styles might be applied to elements they shouldn't be, or not applied when they should. This could stem from misunderstandings of how `@scope` boundaries work.
    *   **Example:**  A developer might expect a style to apply based on an outer `@scope`, but due to incorrect proximity calculation, an inner `@scope` takes precedence unexpectedly.

*   **Incorrect interpretation of dynamic pseudo-classes:** If the `MatchFlags` are not set correctly, the browser might not re-render elements when their state changes (e.g., when an element is hovered).
    *   **Example:** A style intended to change on `:hover` might not be applied because the `Hover` flag wasn't correctly identified by the `SelectorChecker`.

*   **Performance issues with complex selectors:** While `EasySelectorCheckerTest` highlights this, incorrect implementation of the main `SelectorChecker` could lead to slow style matching, especially with complex selectors, impacting page performance.

*   **Shadow DOM styling issues:** Incorrect matching of selectors like `:host` can lead to styles not being applied correctly within Shadow DOM components, breaking encapsulation.

**User Operations as Debugging Clues:**

While a user doesn't directly interact with this C++ code, understanding how user actions lead to the execution of the `SelectorChecker` is crucial for debugging:

1. **User Hovers Mouse:** When a user moves their mouse over an element, the browser needs to re-evaluate styles that use the `:hover` pseudo-class. The `SelectorChecker` is invoked to see if any `:hover` rules now match the hovered element. The `ImpactTest` with `HoverSubjectOnly`, `HoverNonSubjectOnly`, etc., directly tests this scenario.

2. **User Clicks (Activates) an Element:** Clicking an element triggers the `:active` pseudo-class. The `SelectorChecker` is used to determine if any `:active` styles should be applied. The `MatchFlagsTest` with `:active` is relevant here.

3. **User Focuses on an Element:** When an element receives focus (e.g., clicking on an input field), the `:focus-within` pseudo-class might apply to the focused element and its ancestors. The `ImpactTest` with `FocusWithinSubjectOnly` tests this.

4. **Drag and Drop Operations:**  When a user drags an element, the `:-webkit-drag` pseudo-class (a Chromium-specific extension) might apply. The tests with `:-webkit-drag` in `MatchFlagsTest` and `ImpactTest` are relevant to debugging issues in drag-and-drop styling.

5. **Web Components and Shadow DOM:** When a user interacts with a web component that uses Shadow DOM, the `SelectorChecker` needs to correctly handle selectors like `:host` and `:host-context`. The `MatchFlagsShadowTest` provides test cases for these scenarios.

By understanding these connections, developers debugging styling issues can trace the problem down to whether the correct CSS rules are being matched by the `SelectorChecker` in response to user interactions. This test file provides the foundation for ensuring that matching process is accurate.

Prompt: 
```
这是目录为blink/renderer/core/css/selector_checker_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/selector_checker.h"

#include <bitset>
#include <optional>

#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/selector_checker-inl.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"

namespace blink {

struct ScopeProximityTestData {
  const char* html;
  const char* rule;
  std::optional<unsigned> proximity;
};

ScopeProximityTestData scope_proximity_test_data[] = {
    // clang-format off

    // Selecting the scoping root.
    {
      R"HTML(
        <div id=target></div>
      )HTML",
      R"CSS(
        @scope (#target) {
          :scope { z-index:1; }
        }
      )CSS",
      0
    },

    // Selecting a child.
    {
      R"HTML(
        <div class=a>
          <div id=target></div>
        </div>
      )HTML",
      R"CSS(
        @scope (.a) {
          #target { z-index: 1; }
        }
      )CSS",
      1
    },

    // Selecting a descendant.
    {
      R"HTML(
        <div class=a>
          <div>
            <div>
              <div>
                <div id=target></div>
              </div>
            </div>
          </div>
        </div>
      )HTML",
      R"CSS(
        @scope (.a) {
          #target { z-index: 1; }
        }
      )CSS",
      4
    },

    // The proximity is determined according to the nearest scoping root.
    // (Nested scopes from same @scope rule).
    {
      R"HTML(
        <div class=a>
          <div>
            <div class=a>
              <div>
                <div id=target></div>
              </div>
            </div>
          </div>
        </div>
      )HTML",
      R"CSS(
        @scope (.a) {
          #target { z-index: 1; }
        }
      )CSS",
      2
    },

    // The proximity is determined according to the nearest scoping root.
    // (#target is the scope itself, selected with :scope).
    {
      R"HTML(
        <div class=a>
          <div>
            <div>
              <div>
                <div id=target class=a></div>
              </div>
            </div>
          </div>
        </div>
      )HTML",
      R"CSS(
        @scope (.a) {
          :scope { z-index: 1; }
        }
      )CSS",
      0
    },

    // The proximity is determined according to the nearest scoping root.
    // (#target is the scope itself, selected with &).
    {
      R"HTML(
        <div class=a>
          <div>
            <div>
              <div>
                <div id=target class=a></div>
              </div>
            </div>
          </div>
        </div>
      )HTML",
      R"CSS(
        @scope (.a) {
          & { z-index: 1; }
        }
      )CSS",
      0
    },

    // The proximity is determined according to the nearest scoping root.
    // (Nested scopes from different @scope rules).
    {
      R"HTML(
        <div class=a>
          <div class=b>
            <div>
              <div>
                <div id=target></div>
              </div>
            </div>
          </div>
        </div>
      )HTML",
      R"CSS(
        @scope (.a) {
          @scope (.b) {
            #target { z-index: 1; }
          }
        }
      )CSS",
      3
    },

    // @scope(.a) creates two scopes, but the selector only matches in the
    // outermost scope.
    {
      R"HTML(
        <div class=b>
          <div class=a>
            <div class=a>
              <div id=target></div>
            </div>
          </div>
        </div>
      )HTML",
      R"CSS(
        @scope (.a) {
          .b > :scope #target { z-index: 1; }
        }
      )CSS",
      2
    },
    // clang-format on
};

class ScopeProximityTest
    : public PageTestBase,
      public testing::WithParamInterface<ScopeProximityTestData> {};

INSTANTIATE_TEST_SUITE_P(SelectorChecker,
                         ScopeProximityTest,
                         testing::ValuesIn(scope_proximity_test_data));

TEST_P(ScopeProximityTest, All) {
  ScopeProximityTestData param = GetParam();
  SCOPED_TRACE(param.html);
  SCOPED_TRACE(param.rule);

  SetHtmlInnerHTML(param.html);
  auto* rule = css_test_helpers::ParseRule(GetDocument(), param.rule);
  ASSERT_TRUE(rule);

  const StyleScope* scope = nullptr;

  // Find the inner StyleRule.
  while (IsA<StyleRuleScope>(rule)) {
    auto& scope_rule = To<StyleRuleScope>(*rule);
    scope = scope_rule.GetStyleScope().CopyWithParent(scope);
    const HeapVector<Member<StyleRuleBase>>& child_rules =
        scope_rule.ChildRules();
    ASSERT_EQ(1u, child_rules.size());
    rule = child_rules[0].Get();
  }

  ASSERT_TRUE(scope);

  auto* style_rule = DynamicTo<StyleRule>(rule);
  ASSERT_TRUE(style_rule);

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);

  SelectorChecker checker(SelectorChecker::kResolvingStyle);
  StyleScopeFrame style_scope_frame(*target, /* parent */ nullptr);
  SelectorChecker::SelectorCheckingContext context{
      ElementResolveContext(*target)};
  context.selector = style_rule->FirstSelector();
  context.style_scope = scope;
  context.style_scope_frame = &style_scope_frame;

  SelectorChecker::MatchResult result;
  bool match = checker.Match(context, result);

  EXPECT_EQ(param.proximity,
            match ? std::optional<unsigned>(result.proximity) : std::nullopt);
}

struct MatchFlagsTestData {
  // If of element to match.
  const char* selector;
  MatchFlags expected;
};

constexpr MatchFlags Active() {
  return static_cast<MatchFlags>(MatchFlag::kAffectedByActive);
}
constexpr MatchFlags Drag() {
  return static_cast<MatchFlags>(MatchFlag::kAffectedByDrag);
}
constexpr MatchFlags FocusWithin() {
  return static_cast<MatchFlags>(MatchFlag::kAffectedByFocusWithin);
}
constexpr MatchFlags Hover() {
  return static_cast<MatchFlags>(MatchFlag::kAffectedByHover);
}

MatchFlagsTestData result_flags_test_data[] = {
    // clang-format off
    { "div", 0 },
    { ".foo", 0 },
    { ":active", Active() },
    { ":-webkit-drag", Drag() },
    { ":focus-within", FocusWithin() },
    { ":hover", Hover() },

    // We never evaluate :hover, since :active fails to match.
    { ":active:hover", Active() },

    // Non-rightmost compound:
    { ":active *", 0 },
    { ":-webkit-drag *", 0 },
    { ":focus-within *", 0 },
    { ":hover *", 0 },
    { ":is(:hover) *", 0 },
    { ":not(:hover) *", 0 },

    // Within pseudo-classes:
    { ":is(:active, :hover)", Active() | Hover() },
    { ":not(:active, :hover)", Active() | Hover() },
    { ":where(:active, :hover)", Active() | Hover() },
    { ":-webkit-any(:active, :hover)", Active() | Hover() },
    // TODO(andruud): Don't over-mark for :has().
    { ":has(:active, :hover)", Active() | Hover() },

    // Within pseudo-elements:
    { "::cue(:hover)", Hover() },
    { "::slotted(:hover)", Hover() },
    // clang-format on
};

class MatchFlagsTest : public PageTestBase,
                       public testing::WithParamInterface<MatchFlagsTestData> {
};

INSTANTIATE_TEST_SUITE_P(SelectorChecker,
                         MatchFlagsTest,
                         testing::ValuesIn(result_flags_test_data));

TEST_P(MatchFlagsTest, All) {
  MatchFlagsTestData param = GetParam();

  GetDocument().body()->setInnerHTML(R"HTML(
    <div id=target>
      <div></div>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* element = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(element);

  CSSSelectorList* selector_list =
      css_test_helpers::ParseSelectorList(param.selector);
  ASSERT_TRUE(selector_list);
  ASSERT_TRUE(selector_list->IsSingleComplexSelector());

  SelectorChecker checker(SelectorChecker::kResolvingStyle);
  SelectorChecker::SelectorCheckingContext context{
      ElementResolveContext(*element)};
  context.selector = selector_list->First();

  SelectorChecker::MatchResult result;
  checker.Match(context, result);

  // Comparing using std::bitset produces error messages that are easier to
  // interpret.
  using Bits = std::bitset<sizeof(MatchFlags) * 8>;

  SCOPED_TRACE(param.selector);
  EXPECT_EQ(Bits(param.expected), Bits(result.flags));
}

class ImpactTest : public PageTestBase {
 public:
  void SetUp() override {
    PageTestBase::SetUp();

    GetDocument().body()->setInnerHTML(R"HTML(
      <div id=outer>
        <div id=middle>
          <div id=inner>
            <div></div>
          </div>
        </div>
      </div>
    )HTML");
    UpdateAllLifecyclePhasesForTest();
  }

  Element& Outer() const {
    return *GetDocument().getElementById(AtomicString("outer"));
  }
  Element& Middle() const {
    return *GetDocument().getElementById(AtomicString("middle"));
  }
  Element& Inner() const {
    return *GetDocument().getElementById(AtomicString("inner"));
  }

  using Impact = SelectorChecker::Impact;

  MatchFlags Match(String selector, Element& element, Impact impact) {
    CSSSelectorList* selector_list =
        css_test_helpers::ParseSelectorList(selector);
    DCHECK(selector_list);
    DCHECK(selector_list->IsSingleComplexSelector());

    SelectorChecker checker(SelectorChecker::kResolvingStyle);
    SelectorChecker::SelectorCheckingContext context{
        ElementResolveContext(element)};
    context.selector = selector_list->First();
    context.impact = impact;

    SelectorChecker::MatchResult result;
    checker.Match(context, result);

    return result.flags;
  }
};

// :hover

TEST_F(ImpactTest, HoverSubjectOnly) {
  MatchFlags flags = Match("#inner:hover", Inner(), Impact::kSubject);
  EXPECT_EQ(Hover(), flags);
  EXPECT_FALSE(Inner().ChildrenOrSiblingsAffectedByHover());
  EXPECT_FALSE(Middle().ChildrenOrSiblingsAffectedByHover());
  EXPECT_FALSE(Outer().ChildrenOrSiblingsAffectedByHover());
}

TEST_F(ImpactTest, HoverNonSubjectOnly) {
  MatchFlags flags = Match("#inner:hover", Inner(), Impact::kNonSubject);
  EXPECT_EQ(0u, flags);
  EXPECT_TRUE(Inner().ChildrenOrSiblingsAffectedByHover());
  EXPECT_FALSE(Middle().ChildrenOrSiblingsAffectedByHover());
  EXPECT_FALSE(Outer().ChildrenOrSiblingsAffectedByHover());
}

TEST_F(ImpactTest, HoverBoth) {
  MatchFlags flags = Match("#inner:hover", Inner(), Impact::kBoth);
  EXPECT_EQ(Hover(), flags);
  EXPECT_TRUE(Inner().ChildrenOrSiblingsAffectedByHover());
  EXPECT_FALSE(Middle().ChildrenOrSiblingsAffectedByHover());
  EXPECT_FALSE(Outer().ChildrenOrSiblingsAffectedByHover());
}

TEST_F(ImpactTest, HoverDescendantCombinatorSubject) {
  MatchFlags flags = Match(":hover #inner", Inner(), Impact::kSubject);
  EXPECT_EQ(0u, flags);
  EXPECT_FALSE(Inner().ChildrenOrSiblingsAffectedByHover());
  EXPECT_TRUE(Middle().ChildrenOrSiblingsAffectedByHover());
  EXPECT_TRUE(Outer().ChildrenOrSiblingsAffectedByHover());
}

// :-webkit-drag

TEST_F(ImpactTest, DragSubjectOnly) {
  MatchFlags flags = Match("#inner:-webkit-drag", Inner(), Impact::kSubject);
  EXPECT_EQ(Drag(), flags);
  EXPECT_FALSE(Inner().ChildrenOrSiblingsAffectedByDrag());
  EXPECT_FALSE(Middle().ChildrenOrSiblingsAffectedByDrag());
  EXPECT_FALSE(Outer().ChildrenOrSiblingsAffectedByDrag());
}

TEST_F(ImpactTest, DragNonSubjectOnly) {
  MatchFlags flags = Match("#inner:-webkit-drag", Inner(), Impact::kNonSubject);
  EXPECT_EQ(0u, flags);
  EXPECT_TRUE(Inner().ChildrenOrSiblingsAffectedByDrag());
  EXPECT_FALSE(Middle().ChildrenOrSiblingsAffectedByDrag());
  EXPECT_FALSE(Outer().ChildrenOrSiblingsAffectedByDrag());
}

TEST_F(ImpactTest, DragBoth) {
  MatchFlags flags = Match("#inner:-webkit-drag", Inner(), Impact::kBoth);
  EXPECT_EQ(Drag(), flags);
  EXPECT_TRUE(Inner().ChildrenOrSiblingsAffectedByDrag());
  EXPECT_FALSE(Middle().ChildrenOrSiblingsAffectedByDrag());
  EXPECT_FALSE(Outer().ChildrenOrSiblingsAffectedByDrag());
}

TEST_F(ImpactTest, DragDescendantCombinatorSubject) {
  MatchFlags flags = Match(":-webkit-drag #inner", Inner(), Impact::kSubject);
  EXPECT_EQ(0u, flags);
  EXPECT_FALSE(Inner().ChildrenOrSiblingsAffectedByDrag());
  EXPECT_TRUE(Middle().ChildrenOrSiblingsAffectedByDrag());
  EXPECT_TRUE(Outer().ChildrenOrSiblingsAffectedByDrag());
}

// :focus-within

TEST_F(ImpactTest, FocusWithinSubjectOnly) {
  MatchFlags flags = Match("#inner:focus-within", Inner(), Impact::kSubject);
  EXPECT_EQ(FocusWithin(), flags);
  EXPECT_FALSE(Inner().ChildrenOrSiblingsAffectedByFocusWithin());
  EXPECT_FALSE(Middle().ChildrenOrSiblingsAffectedByFocusWithin());
  EXPECT_FALSE(Outer().ChildrenOrSiblingsAffectedByFocusWithin());
}

TEST_F(ImpactTest, FocusWithinNonSubjectOnly) {
  MatchFlags flags = Match("#inner:focus-within", Inner(), Impact::kNonSubject);
  EXPECT_EQ(0u, flags);
  EXPECT_TRUE(Inner().ChildrenOrSiblingsAffectedByFocusWithin());
  EXPECT_FALSE(Middle().ChildrenOrSiblingsAffectedByFocusWithin());
  EXPECT_FALSE(Outer().ChildrenOrSiblingsAffectedByFocusWithin());
}

TEST_F(ImpactTest, FocusWithinBoth) {
  MatchFlags flags = Match("#inner:focus-within", Inner(), Impact::kBoth);
  EXPECT_EQ(FocusWithin(), flags);
  EXPECT_TRUE(Inner().ChildrenOrSiblingsAffectedByFocusWithin());
  EXPECT_FALSE(Middle().ChildrenOrSiblingsAffectedByFocusWithin());
  EXPECT_FALSE(Outer().ChildrenOrSiblingsAffectedByFocusWithin());
}

TEST_F(ImpactTest, FocusWithinDescendantCombinatorSubject) {
  MatchFlags flags = Match(":focus-within #inner", Inner(), Impact::kSubject);
  EXPECT_EQ(0u, flags);
  EXPECT_FALSE(Inner().ChildrenOrSiblingsAffectedByFocusWithin());
  EXPECT_TRUE(Middle().ChildrenOrSiblingsAffectedByFocusWithin());
  EXPECT_TRUE(Outer().ChildrenOrSiblingsAffectedByFocusWithin());
}

// :active

TEST_F(ImpactTest, ActiveSubjectOnly) {
  MatchFlags flags = Match("#inner:active", Inner(), Impact::kSubject);
  EXPECT_EQ(Active(), flags);
  EXPECT_FALSE(Inner().ChildrenOrSiblingsAffectedByActive());
  EXPECT_FALSE(Middle().ChildrenOrSiblingsAffectedByActive());
  EXPECT_FALSE(Outer().ChildrenOrSiblingsAffectedByActive());
}

TEST_F(ImpactTest, ActiveNonSubjectOnly) {
  MatchFlags flags = Match("#inner:active", Inner(), Impact::kNonSubject);
  EXPECT_EQ(0u, flags);
  EXPECT_TRUE(Inner().ChildrenOrSiblingsAffectedByActive());
  EXPECT_FALSE(Middle().ChildrenOrSiblingsAffectedByActive());
  EXPECT_FALSE(Outer().ChildrenOrSiblingsAffectedByActive());
}

TEST_F(ImpactTest, ActiveBoth) {
  MatchFlags flags = Match("#inner:active", Inner(), Impact::kBoth);
  EXPECT_EQ(Active(), flags);
  EXPECT_TRUE(Inner().ChildrenOrSiblingsAffectedByActive());
  EXPECT_FALSE(Middle().ChildrenOrSiblingsAffectedByActive());
  EXPECT_FALSE(Outer().ChildrenOrSiblingsAffectedByActive());
}

TEST_F(ImpactTest, ActiveDescendantCombinatorSubject) {
  MatchFlags flags = Match(":active #inner", Inner(), Impact::kSubject);
  EXPECT_EQ(0u, flags);
  EXPECT_FALSE(Inner().ChildrenOrSiblingsAffectedByActive());
  EXPECT_TRUE(Middle().ChildrenOrSiblingsAffectedByActive());
  EXPECT_TRUE(Outer().ChildrenOrSiblingsAffectedByActive());
}

// :focus-visible

TEST_F(ImpactTest, FocusVisibleSubjectOnly) {
  // Note that :focus-visible does not set any flags for Impact::kSubject.
  // (There is no corresponding MatchFlag).
  Match("#inner:focus-visible", Inner(), Impact::kSubject);
  EXPECT_FALSE(Inner().ChildrenOrSiblingsAffectedByFocusVisible());
  EXPECT_FALSE(Middle().ChildrenOrSiblingsAffectedByFocusVisible());
  EXPECT_FALSE(Outer().ChildrenOrSiblingsAffectedByFocusVisible());
}

TEST_F(ImpactTest, FocusVisibleNonSubjectOnly) {
  Match("#inner:focus-visible", Inner(), Impact::kNonSubject);
  EXPECT_TRUE(Inner().ChildrenOrSiblingsAffectedByFocusVisible());
  EXPECT_FALSE(Middle().ChildrenOrSiblingsAffectedByFocusVisible());
  EXPECT_FALSE(Outer().ChildrenOrSiblingsAffectedByFocusVisible());
}

TEST_F(ImpactTest, FocusVisibleBoth) {
  Match("#inner:focus-visible", Inner(), Impact::kBoth);
  EXPECT_TRUE(Inner().ChildrenOrSiblingsAffectedByFocusVisible());
  EXPECT_FALSE(Middle().ChildrenOrSiblingsAffectedByFocusVisible());
  EXPECT_FALSE(Outer().ChildrenOrSiblingsAffectedByFocusVisible());
}

TEST_F(ImpactTest, FocusVisibleDescendantCombinatorSubject) {
  Match(":focus-visible #inner", Inner(), Impact::kSubject);
  EXPECT_FALSE(Inner().ChildrenOrSiblingsAffectedByFocusVisible());
  EXPECT_TRUE(Middle().ChildrenOrSiblingsAffectedByFocusVisible());
  EXPECT_TRUE(Outer().ChildrenOrSiblingsAffectedByFocusVisible());
}

// :has()

TEST_F(ImpactTest, HasSubjectOnly) {
  Match("#inner:has(.foo)", Inner(), Impact::kSubject);

  EXPECT_TRUE(Inner().AffectedBySubjectHas());
  EXPECT_FALSE(Middle().AffectedBySubjectHas());
  EXPECT_FALSE(Outer().AffectedBySubjectHas());

  EXPECT_FALSE(Inner().AffectedByNonSubjectHas());
  EXPECT_FALSE(Middle().AffectedByNonSubjectHas());
  EXPECT_FALSE(Outer().AffectedByNonSubjectHas());
}

TEST_F(ImpactTest, HasNonSubjectOnly) {
  Match("#inner:has(.foo)", Inner(), Impact::kNonSubject);

  EXPECT_FALSE(Inner().AffectedBySubjectHas());
  EXPECT_FALSE(Middle().AffectedBySubjectHas());
  EXPECT_FALSE(Outer().AffectedBySubjectHas());

  EXPECT_TRUE(Inner().AffectedByNonSubjectHas());
  EXPECT_FALSE(Middle().AffectedByNonSubjectHas());
  EXPECT_FALSE(Outer().AffectedByNonSubjectHas());
}

TEST_F(ImpactTest, HasBoth) {
  Match("#inner:has(.foo)", Inner(), Impact::kBoth);

  EXPECT_TRUE(Inner().AffectedBySubjectHas());
  EXPECT_FALSE(Middle().AffectedBySubjectHas());
  EXPECT_FALSE(Outer().AffectedBySubjectHas());

  EXPECT_TRUE(Inner().AffectedByNonSubjectHas());
  EXPECT_FALSE(Middle().AffectedByNonSubjectHas());
  EXPECT_FALSE(Outer().AffectedByNonSubjectHas());
}

TEST_F(ImpactTest, HasDescendantCombinatorSubject) {
  Match(":has(.foo) #inner", Inner(), Impact::kSubject);

  EXPECT_FALSE(Inner().AffectedBySubjectHas());
  EXPECT_FALSE(Middle().AffectedBySubjectHas());
  EXPECT_FALSE(Outer().AffectedBySubjectHas());

  EXPECT_FALSE(Inner().AffectedByNonSubjectHas());
  EXPECT_TRUE(Middle().AffectedByNonSubjectHas());
  EXPECT_TRUE(Outer().AffectedByNonSubjectHas());
}

TEST_F(ImpactTest, HasDescendantCombinatorBoth) {
  Match(":has(.foo) #inner", Inner(), Impact::kBoth);

  EXPECT_FALSE(Inner().AffectedBySubjectHas());
  EXPECT_FALSE(Middle().AffectedBySubjectHas());
  EXPECT_FALSE(Outer().AffectedBySubjectHas());

  EXPECT_FALSE(Inner().AffectedByNonSubjectHas());
  EXPECT_TRUE(Middle().AffectedByNonSubjectHas());
  EXPECT_TRUE(Outer().AffectedByNonSubjectHas());
}

TEST_F(ImpactTest, HasSubjectAndDescendantCombinatorBoth) {
  Match(":has(.foo) #inner:has(div)", Inner(), Impact::kBoth);

  EXPECT_TRUE(Inner().AffectedBySubjectHas());
  EXPECT_FALSE(Middle().AffectedBySubjectHas());
  EXPECT_FALSE(Outer().AffectedBySubjectHas());

  EXPECT_TRUE(Inner().AffectedByNonSubjectHas());
  EXPECT_TRUE(Middle().AffectedByNonSubjectHas());
  EXPECT_TRUE(Outer().AffectedByNonSubjectHas());
}

TEST_F(ImpactTest, HasDescendantCombinatorWithinIsBoth) {
  Match("#inner:is(:has(.foo) *)", Inner(), Impact::kBoth);

  EXPECT_FALSE(Inner().AffectedBySubjectHas());
  EXPECT_FALSE(Middle().AffectedBySubjectHas());
  EXPECT_FALSE(Outer().AffectedBySubjectHas());

  EXPECT_FALSE(Inner().AffectedByNonSubjectHas());
  EXPECT_TRUE(Middle().AffectedByNonSubjectHas());
  EXPECT_TRUE(Outer().AffectedByNonSubjectHas());
}

TEST_F(ImpactTest, HasDescendantCombinatorWithIsBoth) {
  Match(":is(:has(.foo) #middle) #inner", Inner(), Impact::kBoth);

  EXPECT_FALSE(Inner().AffectedBySubjectHas());
  EXPECT_FALSE(Middle().AffectedBySubjectHas());
  EXPECT_FALSE(Outer().AffectedBySubjectHas());

  EXPECT_FALSE(Inner().AffectedByNonSubjectHas());
  EXPECT_FALSE(Middle().AffectedByNonSubjectHas());
  EXPECT_TRUE(Outer().AffectedByNonSubjectHas());
}

// Cases involving :host are special, because we need to call SelectorChecker
// with a non-nullptr scope node.

MatchFlagsTestData result_flags_shadow_test_data[] = {
    // clang-format off
    { ":host(:active)", Active() },
    { ":host-context(:active)", Active() },
    // clang-format on
};

class MatchFlagsShadowTest
    : public PageTestBase,
      public testing::WithParamInterface<MatchFlagsTestData> {};

INSTANTIATE_TEST_SUITE_P(SelectorChecker,
                         MatchFlagsShadowTest,
                         testing::ValuesIn(result_flags_shadow_test_data));

TEST_P(MatchFlagsShadowTest, Host) {
  MatchFlagsTestData param = GetParam();

  GetDocument().body()->setHTMLUnsafe(R"HTML(
    <div id=host>
      <template shadowrootmode="open">
        <div></div>
      </template>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* host = GetDocument().getElementById(AtomicString("host"));
  ASSERT_TRUE(host);
  ASSERT_TRUE(host->GetShadowRoot());

  CSSSelectorList* selector_list =
      css_test_helpers::ParseSelectorList(param.selector);
  ASSERT_TRUE(selector_list);
  ASSERT_TRUE(selector_list->IsSingleComplexSelector());

  SelectorChecker checker(SelectorChecker::kResolvingStyle);
  SelectorChecker::SelectorCheckingContext context{
      ElementResolveContext(*host)};
  context.selector = selector_list->First();
  context.scope = host->GetShadowRoot();

  SelectorChecker::MatchResult result;
  checker.Match(context, result);

  // Comparing using std::bitset produces error messages that are easier to
  // interpret.
  using Bits = std::bitset<sizeof(MatchFlags) * 8>;

  SCOPED_TRACE(param.selector);
  EXPECT_EQ(Bits(param.expected), Bits(result.flags));
}

class MatchFlagsScopeTest : public PageTestBase {
 public:
  void SetUp() override {
    PageTestBase::SetUp();
    GetDocument().body()->setInnerHTML(R"HTML(
      <style id=style>
      </style>
      <div id=outer>
        <div id=inner></div>
      </div>
    )HTML");
    UpdateAllLifecyclePhasesForTest();
  }

  void SetStyle(String text) {
    Element* style = GetDocument().getElementById(AtomicString("style"));
    DCHECK(style);
    style->setTextContent(text);
    UpdateAllLifecyclePhasesForTest();
  }

  Element& Outer() const {
    return *GetDocument().getElementById(AtomicString("outer"));
  }
  Element& Inner() const {
    return *GetDocument().getElementById(AtomicString("inner"));
  }

  bool AffectedByHover(Element& element) {
    return element.ComputedStyleRef().AffectedByHover();
  }
};

TEST_F(MatchFlagsScopeTest, NoHover) {
  SetStyle(R"HTML(
    @scope (#inner) to (.unknown) {
      :scope { --x:1; }
    }
    @scope (#outer) to (.unknown) {
      :scope #inner { --x:1; }
    }
  )HTML");
  EXPECT_FALSE(AffectedByHover(Outer()));
  EXPECT_FALSE(AffectedByHover(Inner()));
}

TEST_F(MatchFlagsScopeTest, HoverSubject) {
  SetStyle(R"HTML(
    @scope (#outer) {
      :scope #inner:hover { --x:1; }
    }
  )HTML");
  EXPECT_FALSE(AffectedByHover(Outer()));
  EXPECT_TRUE(AffectedByHover(Inner()));
}

TEST_F(MatchFlagsScopeTest, HoverNonSubject) {
  SetStyle(R"HTML(
    @scope (#outer) {
      :scope:hover #inner { --x:1; }
    }
  )HTML");
  EXPECT_FALSE(AffectedByHover(Outer()));
  EXPECT_FALSE(AffectedByHover(Inner()));
}

TEST_F(MatchFlagsScopeTest, ScopeSubject) {
  SetStyle(R"HTML(
    @scope (#inner:hover) {
      :scope { --x:1; }
    }
  )HTML");
  EXPECT_FALSE(AffectedByHover(Outer()));
  EXPECT_TRUE(AffectedByHover(Inner()));
}

TEST_F(MatchFlagsScopeTest, ScopeNonSubject) {
  SetStyle(R"HTML(
    @scope (#outer:hover) {
      :scope #inner { --x:1; }
    }
  )HTML");
  EXPECT_FALSE(AffectedByHover(Outer()));
  EXPECT_FALSE(AffectedByHover(Inner()));
}

TEST_F(MatchFlagsScopeTest, ScopeLimit) {
  SetStyle(R"HTML(
    @scope (#inner) to (#inner:hover) {
      :scope { --x:1; }
    }
  )HTML");
  EXPECT_FALSE(AffectedByHover(Outer()));
  EXPECT_TRUE(AffectedByHover(Inner()));
}

TEST_F(MatchFlagsScopeTest, ScopeLimitNonSubject) {
  SetStyle(R"HTML(
    @scope (#middle) to (#middle:hover) {
      :scope #inner { --x:1; }
    }
  )HTML");
  EXPECT_FALSE(AffectedByHover(Outer()));
  EXPECT_FALSE(AffectedByHover(Inner()));
}

class EasySelectorCheckerTest : public PageTestBase {
 protected:
  bool Matches(const String& selector_text, const char* id);
  static bool IsEasy(const String& selector_text);
};

bool EasySelectorCheckerTest::Matches(const String& selector_text,
                                      const char* id) {
  StyleRule* rule = To<StyleRule>(
      css_test_helpers::ParseRule(GetDocument(), selector_text + " {}"));
  CHECK(EasySelectorChecker::IsEasy(rule->FirstSelector()));
  return EasySelectorChecker::Match(rule->FirstSelector(), GetElementById(id));
}

#if DCHECK_IS_ON()  // Requires all_rules_, to find back the rules we add.

// Parse the given selector, buckets it and returns whether it was counted
// as easy or not.
bool EasySelectorCheckerTest::IsEasy(const String& selector_text) {
  css_test_helpers::TestStyleSheet sheet;

  sheet.AddCSSRules(selector_text + " { }");
  RuleSet& rule_set = sheet.GetRuleSet();
  const HeapVector<RuleData>& rules = rule_set.AllRulesForTest();

  wtf_size_t easy_count = 0;
  for (const RuleData& rule_data : rules) {
    if (EasySelectorChecker::IsEasy(&rule_data.Selector())) {
      ++easy_count;
    }
  }

  // Visited-dependent rules are added twice to the RuleSet. This verifies
  // that both RuleData objects have the same easy-status.
  EXPECT_TRUE((easy_count == 0) || (easy_count == rules.size()));

  return easy_count;
}

TEST_F(EasySelectorCheckerTest, IsEasy) {
  EXPECT_TRUE(IsEasy(".a"));
  EXPECT_TRUE(IsEasy(".a.b"));
  EXPECT_TRUE(IsEasy("#id"));
  EXPECT_TRUE(IsEasy("div"));
  EXPECT_FALSE(IsEasy(":visited"));
  EXPECT_FALSE(IsEasy("a:visited"));
  EXPECT_FALSE(IsEasy("a:link"));
  EXPECT_FALSE(IsEasy("::before"));
  EXPECT_FALSE(IsEasy("div::before"));
  EXPECT_FALSE(IsEasy("* .a"));  // Due to the universal selector.
  EXPECT_TRUE(IsEasy(".a *"));   // Due to bucketing.
  EXPECT_TRUE(IsEasy("[attr]"));
  EXPECT_TRUE(IsEasy("[attr=\"foo\"]"));
  EXPECT_TRUE(IsEasy("[attr=\"foo\" i]"));
  EXPECT_TRUE(IsEasy(":root"));       // Due to bucketing.
  EXPECT_TRUE(IsEasy(":any-link"));   // Due to bucketing.
  EXPECT_TRUE(IsEasy("a:any-link"));  // Due to bucketing.
  EXPECT_TRUE(IsEasy(".a .b"));
  EXPECT_TRUE(IsEasy(".a .b.c.d"));
  EXPECT_TRUE(IsEasy(".a > .b"));
  EXPECT_TRUE(IsEasy(".a .b > .c"));
  EXPECT_FALSE(IsEasy(".a > .b .c"));
  EXPECT_FALSE(IsEasy(".a ~ .b"));
  EXPECT_FALSE(IsEasy("&"));
  EXPECT_FALSE(IsEasy(":not(.a)"));
}

#endif  // DCHECK_IS_ON()

TEST_F(EasySelectorCheckerTest, SmokeTest) {
  SetHtmlInnerHTML(
      R"HTML(
        <div id="a"><div id="b"><div id="c" class="cls1" attr="foo"><span id="d"></span></div></div></div>
      )HTML");
  EXPECT_TRUE(Matches("div", "c"));
  EXPECT_FALSE(Matches("div", "d"));
  EXPECT_TRUE(Matches(".cls1", "c"));
  EXPECT_FALSE(Matches(".cls1", "b"));
  EXPECT_TRUE(Matches("div.cls1", "c"));
  EXPECT_TRUE(Matches("*|div.cls1", "c"));
  EXPECT_TRUE(Matches("#b .cls1", "c"));
  EXPECT_TRUE(Matches("#a .cls1", "c"));
  EXPECT_FALSE(Matches("#b .cls1", "a"));
  EXPECT_FALSE(Matches("#a .cls1", "b"));
  EXPECT_TRUE(Matches("[attr]", "c"));
  EXPECT_TRUE(Matches("[attr=\"foo\"]", "c"));
  EXPECT_FALSE(Matches("[attr=\"bar\"]", "c"));
  EXPECT_FALSE(Matches("[attr]", "b"));
  EXPECT_TRUE(Matches("div#a #c.cls1", "c"));
  EXPECT_FALSE(Matches("div#a #c.cls1", "b"));
  EXPECT_FALSE(Matches("#c .cls1", "c"));
  EXPECT_FALSE(Matches("div #a .cls1", "c"));
}

class SelectorCheckerTest : public PageTestBase {};

TEST_F(SelectorCheckerTest, PseudoScopeWithoutScope) {
  GetDocument().body()->setInnerHTML("<div id=foo></div>");
  UpdateAllLifecyclePhasesForTest();

  CSSSelectorList* selector_list =
      css_test_helpers::ParseSelectorList(":scope #foo");
  ASSERT_TRUE(selector_list);
  ASSERT_TRUE(selector_list->First());

  Element* foo = GetDocument().getElementById(AtomicString("foo"));
  ASSERT_TRUE(foo);

  SelectorChecker checker(SelectorChecker::kResolvingStyle);
  SelectorChecker::SelectorCheckingContext context{ElementResolveContext(*foo)};
  context.selector = selector_list->First();
  // We have a selector with :scope, but no context.scope:
  context.scope = nullptr;

  SelectorChecker::MatchResult result;

  // Don't crash.
  EXPECT_FALSE(checker.Match(context, result));
}

}  // namespace blink

"""

```