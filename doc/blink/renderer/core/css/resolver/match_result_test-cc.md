Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understanding the Goal:** The request asks for an explanation of the file's functionality, its relation to web technologies (HTML, CSS, JavaScript), logical reasoning examples, common user errors, and debugging context.

2. **Initial Scan and Identification of Key Components:** The first step is to quickly read through the code, identifying the main classes and functions. Keywords like `TEST_F`, `MatchResult`, `CascadeOrigin`, `CSSPropertyValueSet`, and `TreeScope` stand out. The file name `match_result_test.cc` strongly suggests it's a unit test file for the `MatchResult` class.

3. **Dissecting the `MatchResultTest` Class:**
    * **Inheritance:** It inherits from `PageTestBase`, indicating it's part of a larger testing framework within Blink. This suggests it interacts with a simulated or lightweight rendering environment.
    * **`SetUp()`:**  This is a standard setup function in testing frameworks. It initializes `property_sets`, a vector of `MutableCSSPropertyValueSet`. This immediately tells us the tests involve managing sets of CSS properties.
    * **Helper Functions:** `PropertySet()`, `LengthOf()`, `OriginAt()`, and `TreeScopeAt()` are helper functions to access and inspect the state of a `MatchResult` object. This points towards the core functionalities being tested.

4. **Analyzing the Test Cases (Functions starting with `TEST_F`):**  Each `TEST_F` function focuses on a specific aspect of the `MatchResult` class. The names are quite descriptive:
    * `CascadeOriginUserAgent`, `CascadeOriginUser`, `CascadeOriginAuthor`, `CascadeOriginAll`, etc.:  These clearly test how different origins of CSS rules (User Agent, User, Author) are handled by `MatchResult`. The use of `CascadeOrigin` enum is directly tied to CSS cascading.
    * `CascadeOriginTreeScopes`: This tests how `MatchResult` handles different `TreeScope`s, which is crucial for shadow DOM and iframes.
    * `Reset`: This tests the `Reset()` method, ensuring it clears the internal state correctly.
    * `ResetTreeScope`: This tests resetting the tree scope specifically.

5. **Connecting to Web Technologies:**  Based on the test case names and the data structures involved, the connection to CSS is evident:
    * **`CascadeOrigin`:** Directly relates to the CSS cascade, determining the priority of style rules.
    * **`CSSPropertyValueSet`:** Represents a set of CSS property-value pairs.
    * **`TreeScope`:**  Relates to the DOM tree structure, especially with shadow DOM, a key feature for component-based web development.

6. **Formulating Explanations:**  Now, it's time to synthesize the observations into a clear explanation:
    * **Functionality:**  Focus on the core purpose of `MatchResult`: storing and managing CSS style rules that match a specific element. Emphasize the importance of cascade origin and tree scope.
    * **Relationship to Web Technologies:** Explain how `CascadeOrigin` relates to CSS specificity and the order of application of styles. Connect `TreeScope` to shadow DOM and iframes. Mention that while this is C++, it directly underpins how CSS is applied in the browser.
    * **Logical Reasoning:**  Choose a simple test case (e.g., `CascadeOriginUserAgent`) and explain the input (`AddMatchedProperties` with a specific origin) and expected output (checking the origin using `OriginAt`). This demonstrates the basic logic being tested.
    * **User/Programming Errors:** Think about how a developer might misuse or misunderstand the CSS cascade or shadow DOM, leading to unexpected styling. Examples like incorrect origin or not considering shadow boundaries are good.
    * **Debugging Scenario:**  Describe a common web development scenario where styles aren't being applied as expected. Explain how a developer might end up investigating the CSS matching process, potentially leading them to the `MatchResult` class in the browser's source code.

7. **Refining and Structuring the Answer:** Organize the information logically under the requested headings. Use clear and concise language. Provide concrete examples.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus heavily on the C++ implementation details.
* **Correction:**  Shift focus to the *purpose* and *relevance* to web technologies, as the prompt emphasizes those connections.
* **Initial thought:**  Just list the test cases.
* **Correction:** Explain *why* those test cases are important and what aspects of `MatchResult` they are validating.
* **Initial thought:**  Assume the reader has in-depth knowledge of Blink internals.
* **Correction:** Explain concepts like `CascadeOrigin` and `TreeScope` in a way that is understandable even without deep Blink knowledge. Focus on the *web development* context.

By following this iterative process of understanding, analyzing, connecting, and refining, we arrive at a comprehensive and accurate answer to the prompt.
This C++ file, `match_result_test.cc`, within the Chromium Blink engine, contains **unit tests for the `MatchResult` class**.

**Functionality of `match_result_test.cc`:**

The primary function of this file is to ensure the `MatchResult` class behaves correctly. Specifically, it tests:

* **Storing matched CSS properties:** It verifies that `MatchResult` can correctly store information about CSS properties that match a specific element.
* **Tracking cascade origin:** It tests the ability of `MatchResult` to record the origin of a matched CSS rule (e.g., User-Agent stylesheet, User stylesheet, Author stylesheet). This is crucial for the CSS cascade, which determines which styles apply when multiple rules target the same element.
* **Managing tree scopes:** It checks if `MatchResult` correctly associates matched properties with their corresponding `TreeScope`. `TreeScope` is important for handling shadow DOM and iframes, as they create isolated subtrees within the main document.
* **Resetting state:** It tests the `Reset()` method to ensure it clears all stored information within a `MatchResult` object.
* **Cacheability:** It tests the `IsCacheable()` and `SetIsCacheable()` methods, likely related to optimizing CSS matching by caching results.

**Relationship to JavaScript, HTML, and CSS:**

This file is deeply intertwined with how CSS styles are applied to HTML elements in a web page, which is often controlled or influenced by JavaScript.

* **CSS:** The core purpose of `MatchResult` is to manage the results of CSS matching. The tests directly manipulate and check the `CascadeOrigin` which is a fundamental concept in CSS. The tests also deal with `CSSPropertyValueSet`, which represents a collection of CSS properties and their values.
    * **Example:** The tests that add properties with different `CascadeOrigin` values (e.g., `CascadeOrigin::kUserAgent`, `CascadeOrigin::kAuthor`) directly reflect the CSS cascade rules where styles from different sources have different levels of importance.
* **HTML:**  The tests implicitly interact with the HTML structure through the `TreeScope`. The `GetDocument()` method used in the tests returns the document's tree scope. The tests involving shadow DOM (`ResetTreeScope` test) explicitly create and work with shadow hosts, which are HTML elements.
    * **Example:** The `ResetTreeScope` test demonstrates how `MatchResult` handles different parts of the HTML document tree, specifically the main document and shadow roots attached to elements.
* **JavaScript:** While this file doesn't directly contain JavaScript code, the functionality it tests is essential for how the browser applies styles that might be dynamically changed or influenced by JavaScript. For example, JavaScript can:
    * Add or remove CSS classes, triggering re-matching of CSS rules.
    * Modify inline styles of elements.
    * Interact with the shadow DOM, leading to different style application within shadow roots.
    * Use the CSS Object Model (CSSOM) to inspect and manipulate stylesheets.

**Logical Reasoning with Assumptions:**

Let's consider the `CascadeOriginAuthor` test case:

**Assumption Input:**

1. A `MatchResult` object is created.
2. `AddMatchedProperties` is called twice, each time adding a `PropertySet` (representing a set of CSS properties) with the `CascadeOrigin::kAuthor`.

**Logical Reasoning:**

* The `MatchResult` object should store these two matched property sets.
* When `LengthOf(result)` is called, it should return 2, as two property sets were added.
* When `OriginAt(result, 0)` and `OriginAt(result, 1)` are called, they should both return `CascadeOrigin::kAuthor`, as that was the origin set for both additions.

**Expected Output:**

* `ASSERT_EQ(LengthOf(result), 2u);` will pass (2 equals 2).
* `EXPECT_EQ(OriginAt(result, 0), CascadeOrigin::kAuthor);` will pass.
* `EXPECT_EQ(OriginAt(result, 1), CascadeOrigin::kAuthor);` will pass.

**User or Programming Common Usage Errors (Hypothetical Based on the Tests):**

While this is a testing file and doesn't directly involve user interaction, we can infer potential errors developers working on the Blink engine might make:

* **Incorrectly setting the `CascadeOrigin`:** A developer implementing a new feature that involves applying styles might accidentally assign the wrong `CascadeOrigin` to a matched rule. This could lead to styles having unexpected priority in the cascade.
    * **Example:** A style intended to be applied by the user agent (default styles) might be mistakenly marked as an author style, potentially overriding user-defined styles unexpectedly.
* **Not properly handling `TreeScope`:**  When dealing with shadow DOM or iframes, developers might incorrectly associate matched styles with the wrong `TreeScope`. This could result in styles not applying within the intended scope or leaking into other scopes.
    * **Example:**  Styles defined within a shadow root might unintentionally affect elements outside of it if the `TreeScope` is not handled correctly in the `MatchResult`.
* **Forgetting to reset `MatchResult`:** If a `MatchResult` object is reused without being reset, it might contain stale information from previous matches, leading to incorrect style calculations.
    * **Example:** In a scenario where styles are dynamically updated, failing to reset the `MatchResult` before a new matching process could lead to the old styles being considered alongside the new ones.

**User Operation Steps to Reach This Code (Debugging Clues):**

A user, while browsing a website, might encounter styling issues that lead a Chromium developer to investigate the CSS matching process. Here's a potential path:

1. **User reports a style problem:**  A user might report that a website's layout is broken, text colors are wrong, or certain styles are not being applied as expected.
2. **Developer investigates with DevTools:** The developer might use the browser's developer tools (Inspect Element) to examine the computed styles of the affected element. They might notice unexpected style origins or that certain rules are being overridden incorrectly.
3. **Tracing the style application:** The developer might need to delve deeper into the browser's rendering engine to understand *why* a particular style was applied or not applied. This could involve:
    * **Examining the CSS cascade:** The developer would analyze the different matching CSS rules and their origins to see why a particular rule wins.
    * **Considering shadow DOM boundaries:** If the issue involves elements within shadow roots, the developer would need to investigate how styles are being inherited and applied across those boundaries.
4. **Hypothesizing a bug in CSS matching:** If the DevTools investigation points to an anomaly in how styles are being applied based on the cascade or tree scope, the developer might suspect a bug in the CSS matching logic.
5. **Looking at the relevant Blink source code:**  Based on their hypothesis, the developer might start looking at the source code responsible for CSS matching. Keywords like "CSS resolver," "style matching," "cascade," and "shadow DOM" would guide their search.
6. **Finding `MatchResult`:**  The developer might come across the `MatchResult` class as a key component involved in storing and managing the results of CSS matching.
7. **Examining `match_result_test.cc`:** To understand how `MatchResult` is *supposed* to work and to look for potential bugs in its implementation, the developer would examine the unit tests in `match_result_test.cc`. These tests provide concrete examples of how `MatchResult` is used and what its expected behavior is. They can help identify if the observed behavior in the browser matches the intended behavior as defined by these tests.

In essence, this test file acts as a specification and validation for the `MatchResult` class, a crucial piece in the complex process of rendering web pages with CSS. When things go wrong with styling, understanding the role and correct operation of components like `MatchResult` becomes essential for debugging.

### 提示词
```
这是目录为blink/renderer/core/css/resolver/match_result_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/resolver/match_result.h"

#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

using css_test_helpers::ParseDeclarationBlock;

class MatchResultTest : public PageTestBase {
 protected:
  void SetUp() override;

  const CSSPropertyValueSet* PropertySet(unsigned index) const {
    return property_sets->at(index).Get();
  }

  size_t LengthOf(const MatchResult& result) const {
    return result.GetMatchedProperties().size();
  }

  CascadeOrigin OriginAt(const MatchResult& result, wtf_size_t index) const {
    DCHECK_LT(index, LengthOf(result));
    return result.GetMatchedProperties()[index].data_.origin;
  }

  const TreeScope& TreeScopeAt(const MatchResult& result, wtf_size_t index) {
    DCHECK_EQ(CascadeOrigin::kAuthor, OriginAt(result, index));
    return result.ScopeFromTreeOrder(
        result.GetMatchedProperties()[index].data_.tree_order);
  }

 private:
  Persistent<HeapVector<Member<MutableCSSPropertyValueSet>, 8>> property_sets;
};

void MatchResultTest::SetUp() {
  PageTestBase::SetUp();
  property_sets =
      MakeGarbageCollected<HeapVector<Member<MutableCSSPropertyValueSet>, 8>>();
  for (unsigned i = 0; i < 8; i++) {
    property_sets->push_back(
        MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode));
  }
}

TEST_F(MatchResultTest, CascadeOriginUserAgent) {
  MatchResult result;
  result.AddMatchedProperties(PropertySet(0),
                              {.origin = CascadeOrigin::kUserAgent});
  result.AddMatchedProperties(PropertySet(1),
                              {.origin = CascadeOrigin::kUserAgent});

  ASSERT_EQ(LengthOf(result), 2u);
  EXPECT_EQ(OriginAt(result, 0), CascadeOrigin::kUserAgent);
  EXPECT_EQ(OriginAt(result, 1), CascadeOrigin::kUserAgent);
}

TEST_F(MatchResultTest, CascadeOriginUser) {
  MatchResult result;
  result.AddMatchedProperties(PropertySet(0), {.origin = CascadeOrigin::kUser});
  result.AddMatchedProperties(PropertySet(1), {.origin = CascadeOrigin::kUser});

  ASSERT_EQ(LengthOf(result), 2u);
  EXPECT_EQ(OriginAt(result, 0), CascadeOrigin::kUser);
  EXPECT_EQ(OriginAt(result, 1), CascadeOrigin::kUser);
}

TEST_F(MatchResultTest, CascadeOriginAuthor) {
  MatchResult result;
  result.AddMatchedProperties(PropertySet(0),
                              {.origin = CascadeOrigin::kAuthor});
  result.AddMatchedProperties(PropertySet(1),
                              {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(LengthOf(result), 2u);
  EXPECT_EQ(OriginAt(result, 0), CascadeOrigin::kAuthor);
  EXPECT_EQ(OriginAt(result, 1), CascadeOrigin::kAuthor);
}

TEST_F(MatchResultTest, CascadeOriginAll) {
  MatchResult result;
  result.AddMatchedProperties(PropertySet(0),
                              {.origin = CascadeOrigin::kUserAgent});
  result.AddMatchedProperties(PropertySet(1), {.origin = CascadeOrigin::kUser});
  result.AddMatchedProperties(PropertySet(2), {.origin = CascadeOrigin::kUser});
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(PropertySet(3),
                              {.origin = CascadeOrigin::kAuthor});
  result.AddMatchedProperties(PropertySet(4),
                              {.origin = CascadeOrigin::kAuthor});
  result.AddMatchedProperties(PropertySet(5),
                              {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(LengthOf(result), 6u);
  EXPECT_EQ(OriginAt(result, 0), CascadeOrigin::kUserAgent);
  EXPECT_EQ(OriginAt(result, 1), CascadeOrigin::kUser);
  EXPECT_EQ(OriginAt(result, 2), CascadeOrigin::kUser);
  EXPECT_EQ(OriginAt(result, 3), CascadeOrigin::kAuthor);
  EXPECT_EQ(OriginAt(result, 4), CascadeOrigin::kAuthor);
  EXPECT_EQ(OriginAt(result, 5), CascadeOrigin::kAuthor);
}

TEST_F(MatchResultTest, CascadeOriginAllExceptUserAgent) {
  MatchResult result;
  result.AddMatchedProperties(PropertySet(1), {.origin = CascadeOrigin::kUser});
  result.AddMatchedProperties(PropertySet(2), {.origin = CascadeOrigin::kUser});
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(PropertySet(3),
                              {.origin = CascadeOrigin::kAuthor});
  result.AddMatchedProperties(PropertySet(4),
                              {.origin = CascadeOrigin::kAuthor});
  result.AddMatchedProperties(PropertySet(5),
                              {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(LengthOf(result), 5u);
  EXPECT_EQ(OriginAt(result, 0), CascadeOrigin::kUser);
  EXPECT_EQ(OriginAt(result, 1), CascadeOrigin::kUser);
  EXPECT_EQ(OriginAt(result, 2), CascadeOrigin::kAuthor);
  EXPECT_EQ(OriginAt(result, 3), CascadeOrigin::kAuthor);
  EXPECT_EQ(OriginAt(result, 4), CascadeOrigin::kAuthor);
}

TEST_F(MatchResultTest, CascadeOriginAllExceptUser) {
  MatchResult result;
  result.AddMatchedProperties(PropertySet(0),
                              {.origin = CascadeOrigin::kUserAgent});
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(PropertySet(3),
                              {.origin = CascadeOrigin::kAuthor});
  result.AddMatchedProperties(PropertySet(4),
                              {.origin = CascadeOrigin::kAuthor});
  result.AddMatchedProperties(PropertySet(5),
                              {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(LengthOf(result), 4u);
  EXPECT_EQ(OriginAt(result, 0), CascadeOrigin::kUserAgent);
  EXPECT_EQ(OriginAt(result, 1), CascadeOrigin::kAuthor);
  EXPECT_EQ(OriginAt(result, 2), CascadeOrigin::kAuthor);
  EXPECT_EQ(OriginAt(result, 3), CascadeOrigin::kAuthor);
}

TEST_F(MatchResultTest, CascadeOriginAllExceptAuthor) {
  MatchResult result;
  result.AddMatchedProperties(PropertySet(0),
                              {.origin = CascadeOrigin::kUserAgent});
  result.AddMatchedProperties(PropertySet(1), {.origin = CascadeOrigin::kUser});
  result.AddMatchedProperties(PropertySet(2), {.origin = CascadeOrigin::kUser});

  ASSERT_EQ(LengthOf(result), 3u);
  EXPECT_EQ(OriginAt(result, 0), CascadeOrigin::kUserAgent);
  EXPECT_EQ(OriginAt(result, 1), CascadeOrigin::kUser);
  EXPECT_EQ(OriginAt(result, 2), CascadeOrigin::kUser);
}

TEST_F(MatchResultTest, CascadeOriginTreeScopes) {
  MatchResult result;
  result.AddMatchedProperties(PropertySet(0),
                              {.origin = CascadeOrigin::kUserAgent});
  result.AddMatchedProperties(PropertySet(1), {.origin = CascadeOrigin::kUser});
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(PropertySet(2),
                              {.origin = CascadeOrigin::kAuthor});
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(PropertySet(3),
                              {.origin = CascadeOrigin::kAuthor});
  result.AddMatchedProperties(PropertySet(4),
                              {.origin = CascadeOrigin::kAuthor});
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(PropertySet(5),
                              {.origin = CascadeOrigin::kAuthor});
  result.AddMatchedProperties(PropertySet(6),
                              {.origin = CascadeOrigin::kAuthor});
  result.AddMatchedProperties(PropertySet(7),
                              {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(LengthOf(result), 8u);
  EXPECT_EQ(OriginAt(result, 0), CascadeOrigin::kUserAgent);
  EXPECT_EQ(OriginAt(result, 1), CascadeOrigin::kUser);
  EXPECT_EQ(OriginAt(result, 2), CascadeOrigin::kAuthor);
  EXPECT_EQ(OriginAt(result, 3), CascadeOrigin::kAuthor);
  EXPECT_EQ(OriginAt(result, 4), CascadeOrigin::kAuthor);
  EXPECT_EQ(OriginAt(result, 5), CascadeOrigin::kAuthor);
  EXPECT_EQ(OriginAt(result, 6), CascadeOrigin::kAuthor);
  EXPECT_EQ(OriginAt(result, 7), CascadeOrigin::kAuthor);
}

TEST_F(MatchResultTest, Reset) {
  MatchResult result;
  result.AddMatchedProperties(PropertySet(0),
                              {.origin = CascadeOrigin::kUserAgent});
  result.AddMatchedProperties(PropertySet(1), {.origin = CascadeOrigin::kUser});
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(PropertySet(2),
                              {.origin = CascadeOrigin::kAuthor});
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(PropertySet(3),
                              {.origin = CascadeOrigin::kAuthor});
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(PropertySet(4),
                              {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(LengthOf(result), 5u);
  EXPECT_EQ(OriginAt(result, 0), CascadeOrigin::kUserAgent);
  EXPECT_EQ(OriginAt(result, 1), CascadeOrigin::kUser);
  EXPECT_EQ(OriginAt(result, 2), CascadeOrigin::kAuthor);
  EXPECT_EQ(OriginAt(result, 3), CascadeOrigin::kAuthor);
  EXPECT_EQ(OriginAt(result, 4), CascadeOrigin::kAuthor);

  // Check tree_order of last entry.
  EXPECT_TRUE(result.HasMatchedProperties());
  ASSERT_EQ(5u, result.GetMatchedProperties().size());
  EXPECT_EQ(2u, result.GetMatchedProperties()[4].data_.tree_order);

  EXPECT_TRUE(result.IsCacheable());
  result.SetIsCacheable(false);
  EXPECT_FALSE(result.IsCacheable());

  result.Reset();

  EXPECT_TRUE(result.IsCacheable());
  EXPECT_FALSE(result.GetMatchedProperties().size());
  EXPECT_FALSE(result.HasMatchedProperties());

  // Add same declarations again.
  result.AddMatchedProperties(PropertySet(0),
                              {.origin = CascadeOrigin::kUserAgent});
  result.AddMatchedProperties(PropertySet(1), {.origin = CascadeOrigin::kUser});
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(PropertySet(2),
                              {.origin = CascadeOrigin::kAuthor});
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(PropertySet(3),
                              {.origin = CascadeOrigin::kAuthor});
  result.BeginAddingAuthorRulesForTreeScope(GetDocument());
  result.AddMatchedProperties(PropertySet(4),
                              {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(LengthOf(result), 5u);
  EXPECT_EQ(OriginAt(result, 0), CascadeOrigin::kUserAgent);
  EXPECT_EQ(OriginAt(result, 1), CascadeOrigin::kUser);
  EXPECT_EQ(OriginAt(result, 2), CascadeOrigin::kAuthor);
  EXPECT_EQ(OriginAt(result, 3), CascadeOrigin::kAuthor);
  EXPECT_EQ(OriginAt(result, 4), CascadeOrigin::kAuthor);

  // Check tree_order of last entry.
  EXPECT_TRUE(result.HasMatchedProperties());
  ASSERT_EQ(5u, result.GetMatchedProperties().size());
  EXPECT_EQ(2u, result.GetMatchedProperties()[4].data_.tree_order);

  EXPECT_TRUE(result.IsCacheable());
}

TEST_F(MatchResultTest, ResetTreeScope) {
  SetBodyInnerHTML("<div id=host1></div><div id=host2></div>");
  Element* host1 = GetElementById("host1");
  Element* host2 = GetElementById("host2");
  ASSERT_TRUE(host1);
  ASSERT_TRUE(host2);
  TreeScope& scope1 = host1->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  TreeScope& scope2 = host2->AttachShadowRootForTesting(ShadowRootMode::kOpen);

  MatchResult result;
  result.BeginAddingAuthorRulesForTreeScope(scope1);
  result.AddMatchedProperties(PropertySet(0),
                              {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(LengthOf(result), 1u);
  EXPECT_EQ(&TreeScopeAt(result, 0), &scope1);

  result.Reset();

  result.BeginAddingAuthorRulesForTreeScope(scope2);
  result.AddMatchedProperties(PropertySet(0),
                              {.origin = CascadeOrigin::kAuthor});

  ASSERT_EQ(LengthOf(result), 1u);
  EXPECT_EQ(&TreeScopeAt(result, 0), &scope2);
}

}  // namespace blink
```