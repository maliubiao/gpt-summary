Response:
The user is asking for a summary of the functionality of the C++ code provided, which is a test file for the `RuleFeatureSet` in the Chromium Blink engine. I need to analyze the code and identify its purpose, how it relates to web technologies (JavaScript, HTML, CSS), provide examples of logical reasoning, common user/programming errors, debugging information, and finally, summarize its overall function.

**Plan:**

1. **Identify the core purpose:**  The file tests the `RuleFeatureSet`, likely related to CSS selector matching and invalidation.
2. **Analyze the test structure:**  The code uses the `TEST_F` macro, indicating it's a Google Test fixture. Each test case examines a specific CSS selector or scenario.
3. **Connect to web technologies:**  The tests deal with CSS selectors, so the connection to HTML and CSS is direct. JavaScript interacts with CSS via the DOM, so there's an indirect connection.
4. **Extract logical reasoning:**  Each test case has an `EXPECT_EQ(SelectorPreMatch::kMayMatch, ...)` and a series of `EXPECT_TRUE` calls checking for specific invalidation scenarios. This demonstrates logical reasoning about how CSS selectors trigger invalidations.
5. **Consider user/programming errors:**  Misunderstanding CSS selector specificity or the behavior of pseudo-classes like `:has` can lead to unexpected invalidations.
6. **Explain user steps for debugging:**  Modifying CSS rules in the browser's developer tools can trigger these code paths.
7. **Summarize the functionality:**  Combine the above points into a concise description.
好的，这是对提供的C++源代码文件 `blink/renderer/core/css/rule_feature_set_test.cc` 功能的归纳总结：

**文件功能归纳：**

`rule_feature_set_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 `RuleFeatureSet` 及其相关功能。  `RuleFeatureSet` 的核心作用是分析 CSS 规则（特别是 CSS 选择器），提取出用于优化样式匹配和失效（invalidation）的关键特征。

具体来说，这个测试文件主要关注以下几个方面：

1. **CSS 选择器特征提取:**  测试 `CollectFeatures` 函数，该函数分析 CSS 选择器并识别其中包含的特征。这些特征用于预先判断选择器是否可能匹配某个元素，从而避免不必要的样式计算。
2. **CSS 选择器预匹配 (SelectorPreMatch):**  验证 `CollectFeatures` 函数对于不同类型的 CSS 选择器是否返回了正确的 `SelectorPreMatch` 结果（例如 `kMayMatch`）。
3. **样式失效 (Invalidation):** 重点测试不同 CSS 选择器对样式失效的影响。样式失效是指当 DOM 结构或元素属性发生变化时，浏览器需要重新计算哪些元素的样式。测试主要关注以下几种失效类型：
    *   **自身失效 (Self Invalidation):** 当元素自身发生变化时触发。
    *   **类名失效 (Class Invalidation):** 当元素的类名发生变化时触发。
    *   **ID 失效 (Id Invalidation):** 当元素的 ID 发生变化时触发。
    *   **子树失效 (Whole Subtree Invalidation):** 当元素的后代节点发生变化时触发。
    *   **兄弟节点失效 (Sibling Invalidation):** 当元素的兄弟节点发生变化时触发，又细分为直接相邻兄弟节点和非直接相邻兄弟节点。
4. **`:has()` 伪类测试:**  着重测试了 `:has()` 伪类的各种复杂用法，包括嵌套的 `:is()` 伪类和其他组合选择器，以及它们对样式失效的影响。
5. **CSS 嵌套 (Nesting) 特性测试:**  测试了 CSS 嵌套规则 (`&`) 的行为，以及嵌套选择器如何影响样式匹配和失效。
6. **布隆过滤器 (Bloom Filter) 测试:**  测试了用于优化类名和 ID 选择器匹配的布隆过滤器是否正常工作。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接关联到 CSS 的功能，并通过测试 CSS 选择器对样式失效的影响，间接关联到 HTML 和 JavaScript。

*   **CSS:**  该文件主要测试 CSS 选择器的解析和特征提取，以及这些选择器如何触发样式失效。例如，测试用例 `isPseudoContainingComplexInsideHas9` 测试了复杂 `:has()` 伪类的选择器 `.a:has(:is(:is(.b, .c) .d))`。这个选择器会影响哪些元素需要重新计算样式取决于 `.b`, `.c`, `.d` 的存在和位置。
*   **HTML:**  CSS 选择器的目标是 HTML 元素。测试中通过 `CollectInvalidationSetsForClass` 等函数模拟 HTML 元素类名的变化，从而触发不同的失效场景。例如，在 `isPseudoContainingComplexInsideHas9` 测试中，当 HTML 中存在类名为 `b` 的元素时，如果存在匹配 `.a` 的元素，则该元素的子代需要进行类名失效检查。
*   **JavaScript:** JavaScript 可以动态修改 HTML 结构和元素的属性（包括类名），这些修改会触发 CSS 样式的重新计算。这个测试文件模拟了这种变化，并验证了 Blink 引擎是否正确地识别了需要失效的元素。例如，如果 JavaScript 代码使用 `element.classList.add('b')` 给一个元素添加了类名 `b`，那么在 `isPseudoContainingComplexInsideHas9` 的场景下，可能导致某些元素的样式失效。

**逻辑推理的假设输入与输出:**

以下以 `isPseudoContainingComplexInsideHas9` 测试用例为例进行逻辑推理说明：

**假设输入 (CSS 选择器和 HTML 结构变化):**

*   **CSS 规则:** `.a:has(:is(:is(.b, .c) .d))`
*   **HTML 结构变化:**
    1. 向 DOM 中添加或删除一个类名为 `a` 的元素。
    2. 向 DOM 中添加或删除一个类名为 `b` 的元素，且该元素是某个类名为 `a` 的元素的后代，并且该 `b` 元素的后代存在类名为 `d` 的元素。
    3. 向 DOM 中添加或删除一个类名为 `c` 的元素，且该元素是某个类名为 `a` 的元素的后代，并且该 `c` 元素的后代存在类名为 `d` 的元素。
    4. 向 DOM 中添加或删除一个类名为 `d` 的元素，作为某个类名为 `b` 或 `c` 的元素的后代。

**预期输出 (样式失效行为):**

*   当类名为 `a` 的元素自身发生变化时（例如添加或删除该类名），`HasSelfInvalidation(invalidation_lists.descendants)` 应该为 `true`，意味着该元素的后代需要检查样式是否失效。
*   当类名为 `b` 的元素发生变化时，如果存在类名为 `a` 的祖先元素，且 `b` 的后代存在 `d`，则 `HasClassInvalidation("a", invalidation_lists.descendants)` 应该为 `true`，意味着类名为 `a` 的祖先元素的后代需要检查样式是否失效。
*   当类名为 `c` 的元素发生变化时，如果存在类名为 `a` 的祖先元素，且 `c` 的后代存在 `d`，则 `HasClassInvalidation("a", invalidation_lists.descendants)` 应该为 `true`。
*   当类名为 `d` 的元素发生变化时，不直接触发任何失效 (`HasNoInvalidation`)，因为选择器是从 `.a` 开始判断的。

**涉及用户或编程常见的使用错误及举例说明:**

*   **CSS 选择器理解错误:**  开发者可能不清楚复杂 CSS 选择器（尤其是包含 `:has()` 和 `:is()` 的选择器）的匹配规则和性能影响。例如，错误地认为 `.a:has(.b .c)` 只会在 `.b` 或 `.c` 变化时失效，而忽略了当 `.a` 自身变化时也会触发失效。
*   **过度使用高代价选择器:**  频繁使用像 `:has()` 这样计算成本较高的选择器可能会导致页面性能问题，尤其是在大型动态页面上。开发者可能没有意识到某个 CSS 规则会导致大量的样式重计算。
*   **JavaScript 动态修改类名引发意外失效:**  当 JavaScript 代码动态修改元素的类名时，可能会触发意想不到的样式失效，影响页面性能。例如，开发者可能在不经意间修改了某个元素的类名，导致大量使用了该类名的复杂选择器重新计算。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中加载了一个包含特定 CSS 规则和 HTML 结构的网页。** 例如，网页的 CSS 中包含 `.a:has(:is(:is(.b, .c) .d))` 这样的规则，并且 HTML 中存在相应的元素结构。
2. **用户与网页进行交互，导致 DOM 结构或元素属性发生变化。** 例如：
    *   用户通过 JavaScript 触发了某个元素的类名变化 (例如，添加或删除了 `a`, `b`, `c`, 或 `d` 类名)。
    *   用户通过 JavaScript 动态添加或删除了 DOM 元素，这些元素可能包含相关的类名。
3. **Blink 引擎的样式计算模块接收到 DOM 变化的通知。**
4. **`RuleFeatureSet` 被调用，分析相关的 CSS 规则，确定哪些规则可能受到影响。**  `CollectFeatures` 函数会提取出相关选择器的特征。
5. **根据提取的特征和失效策略，Blink 引擎标记需要重新计算样式的元素。** 例如，如果一个元素的类名从无到有 `a`，则会触发使用了 `.a:has(...)` 选择器的规则的重新评估。
6. **如果开发者正在调试样式问题或性能问题，并设置了断点或启用了追踪，他们可能会进入 `rule_feature_set_test.cc` 中相关的测试用例。** 例如，他们可能想验证某个复杂的 `:has()` 选择器是否按预期触发了失效。通过单步调试，可以观察 `CollectFeatures` 的输出和后续的失效列表。

**总结 (作为第 4 部分):**

作为系列测试的最后一部分，本文件 `rule_feature_set_test.cc` 主要通过大量的单元测试，**系统性地验证了 Blink 引擎中 `RuleFeatureSet` 组件对于各种复杂 CSS 选择器（特别是包含 `:has()`, `:is()` 和 CSS 嵌套的场景）的特征提取和样式失效行为的正确性**。它确保了引擎能够准确地识别出哪些 CSS 规则可能匹配哪些元素，并在 DOM 变化时有效地触发必要的样式重新计算，从而保证页面渲染的正确性和性能。 这些测试覆盖了各种边界情况和复杂的选择器组合，旨在防止因 CSS 选择器解析或失效逻辑错误而导致的渲染问题。

Prompt: 
```
这是目录为blink/renderer/core/css/rule_feature_set_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能

"""
, invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "d");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, isPseudoContainingComplexInsideHas9) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".a:has(:is(:is(.b, .c) .d))"));

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "a");
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "b");
    EXPECT_TRUE(HasClassInvalidation("a", invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "c");
    EXPECT_TRUE(HasClassInvalidation("a", invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "d");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, isPseudoContainingComplexInsideHas10) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".a:has(~ :is(:is(.b, .c) ~ .d))"));

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "a");
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "b");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(
        HasSiblingClassInvalidation(SiblingInvalidationSet::kDirectAdjacentMax,
                                    "a", invalidation_lists.siblings));
    EXPECT_TRUE(
        HasSiblingNoDescendantInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "c");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(
        HasSiblingClassInvalidation(SiblingInvalidationSet::kDirectAdjacentMax,
                                    "a", invalidation_lists.siblings));
    EXPECT_TRUE(
        HasSiblingNoDescendantInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "d");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, isPseudoContainingComplexInsideHas11) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(":has(:is(.a .b))"));

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "a");
    EXPECT_TRUE(HasWholeSubtreeInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "b");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, isPseudoContainingComplexInsideHas12) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(":has(~ :is(.a ~ .b))"));

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "a");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.siblings));
    EXPECT_TRUE(
        HasSiblingNoDescendantInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "b");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, isPseudoContainingComplexInsideHas13) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".a:has(~ :is(.b ~ .c .d ~ .e))"));

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "a");
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "b");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(
        HasSiblingAndSiblingDescendantInvalidationForLogicalCombinationsInHas(
            "a", "c", "a", invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "c");
    EXPECT_TRUE(HasClassInvalidation("a", invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "d");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(
        HasSiblingClassInvalidation(SiblingInvalidationSet::kDirectAdjacentMax,
                                    "a", invalidation_lists.siblings));
    EXPECT_TRUE(
        HasSiblingNoDescendantInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "e");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, isPseudoContainingComplexInsideHas14) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".a:has(~ :is(.b ~ .c)) .d"));

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "b");
    EXPECT_TRUE(HasSiblingDescendantInvalidation(
        SiblingInvalidationSet::kDirectAdjacentMax, "a", "d",
        invalidation_lists.siblings));
    EXPECT_TRUE(HasNoSelfInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "c");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, isPseudoContainingComplexInsideHas15) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".a:has(~ :is(* ~ .b))"));
  {
    InvalidationLists invalidation_lists;
    CollectUniversalSiblingInvalidationSet(invalidation_lists);

    EXPECT_TRUE(
        HasSiblingClassInvalidation(SiblingInvalidationSet::kDirectAdjacentMax,
                                    "a", invalidation_lists.siblings));
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "b");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, isPseudoContainingComplexInsideHas16) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".a:has(~ :is(* ~ .b)) .c"));

  {
    InvalidationLists invalidation_lists;
    CollectUniversalSiblingInvalidationSet(invalidation_lists);

    EXPECT_TRUE(HasSiblingDescendantInvalidation(
        SiblingInvalidationSet::kDirectAdjacentMax, "a", "c",
        invalidation_lists.siblings));
    EXPECT_TRUE(HasNoSelfInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "b");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, isPseudoContainingComplexInsideHas17) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".a :has(:is(.b .c)).d"));

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "a");
    EXPECT_TRUE(HasClassInvalidation("d", invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "b");
    EXPECT_TRUE(HasWholeSubtreeInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "c");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "d");
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, isPseudoContainingComplexInsideHas18) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".a:has(~ :is(.b ~ :is(.c ~ .d)))"));

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "a");
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "b");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(
        HasSiblingClassInvalidation(SiblingInvalidationSet::kDirectAdjacentMax,
                                    "a", invalidation_lists.siblings));
    EXPECT_TRUE(
        HasSiblingNoDescendantInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "c");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(
        HasSiblingClassInvalidation(SiblingInvalidationSet::kDirectAdjacentMax,
                                    "a", invalidation_lists.siblings));
    EXPECT_TRUE(
        HasSiblingNoDescendantInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "d");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, isPseudoContainingComplexInsideHas19) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".a:has(~ :is(:is(.b ~ .c) ~ .d))"));

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "a");
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "b");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(
        HasSiblingClassInvalidation(SiblingInvalidationSet::kDirectAdjacentMax,
                                    "a", invalidation_lists.siblings));
    EXPECT_TRUE(
        HasSiblingNoDescendantInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "c");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(
        HasSiblingClassInvalidation(SiblingInvalidationSet::kDirectAdjacentMax,
                                    "a", invalidation_lists.siblings));
    EXPECT_TRUE(
        HasSiblingNoDescendantInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "d");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, NestedSelector) {
  // Create a parent rule.
  HeapVector<CSSSelector> arena;
  base::span<CSSSelector> selector_vector = CSSParser::ParseSelector(
      StrictCSSParserContext(SecureContextMode::kInsecureContext),
      CSSNestingType::kNone,
      /*parent_rule_for_nesting=*/nullptr, /*is_within_scope=*/false, nullptr,
      ".a, .b", arena);
  auto* parent_rule = StyleRule::Create(
      selector_vector,
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLStandardMode));

  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures("& .c", CSSNestingType::kNesting,
                            /*parent_rule_for_nesting=*/parent_rule));

  for (const char* parent_class : {"a", "b"}) {
    SCOPED_TRACE(parent_class);

    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, parent_class);
    EXPECT_TRUE(HasClassInvalidation("c", invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "c");
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, BloomFilterForClassSelfInvalidation) {
  // Add enough dummy classes that the filter will be created.
  for (unsigned i = 0; i < 100; ++i) {
    CollectFeatures(".dummy");
  }

  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(".p"));

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "p");
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "q");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, BloomFilterForIdSelfInvalidation) {
  // Add enough dummy IDs that the filter will be created.
  for (unsigned i = 0; i < 100; ++i) {
    CollectFeatures("#dummy");
  }

  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures("#foo"));

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForId(invalidation_lists, "foo");
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForId(invalidation_lists, "bar");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, NestingSelectorPointingToScopeInsideHas) {
  Document* document =
      Document::CreateForTest(execution_context_.GetExecutionContext());
  StyleRuleBase* parent_rule_base =
      css_test_helpers::ParseRule(*document, "@scope (.a) { :scope {} }");
  ASSERT_TRUE(parent_rule_base);

  const StyleScope* scope = nullptr;

  auto& scope_rule = To<StyleRuleScope>(*parent_rule_base);
  scope = scope_rule.GetStyleScope().CopyWithParent(scope);
  const HeapVector<Member<StyleRuleBase>>& scope_child_rules =
      scope_rule.ChildRules();
  ASSERT_EQ(1u, scope_child_rules.size());
  parent_rule_base = scope_child_rules[0].Get();

  auto* parent_rule = DynamicTo<StyleRule>(parent_rule_base);
  ASSERT_TRUE(parent_rule);
  CollectFeatures(parent_rule, scope);

  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(":has(&)", CSSNestingType::kNesting,
                            /*parent_rule_for_nesting=*/parent_rule));

  // TODO(crbug.com/40208848): This test currently expects whole-subtree
  // invalidation, because we don't extract any features from :scope.
  // That should be improved.
  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "a");
    EXPECT_TRUE(HasWholeSubtreeInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

}  // namespace blink

"""


```