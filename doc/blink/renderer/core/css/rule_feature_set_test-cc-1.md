Response:
The user wants to understand the functionality of the `rule_feature_set_test.cc` file in the Chromium Blink engine. This is the second part of a four-part breakdown. I need to summarize the functionality covered in this specific snippet of the test file.

The tests in this file primarily focus on verifying how different CSS selectors influence the `InvalidationLists`. This involves checking for different types of invalidations (e.g., class, id, tag name, sibling, descendant) based on the CSS rules defined in the `CollectFeatures` calls. The tests cover various CSS selectors including:

- `:webkit-any()` pseudo-class
- Sibling combinators (`~`, `+`) with and without universal selectors (`*`)
- ID selectors (`#`)
- Attribute selectors (`[]`)
- Pseudo-classes (e.g., `:valid`, `:hover`, `:nth-child`)
- `:host` and `:host-context` pseudo-classes
- `:is()` and `:where()` pseudo-classes
- `:part()` pseudo-element
- `:has()` pseudo-class

The tests also examine scenarios related to self-invalidation and the replacement of self-invalidation sets.
这个 `rule_feature_set_test.cc` 文件（这是第二部分）的主要功能是**测试 Blink 引擎在解析 CSS 规则时，如何识别和记录可能导致渲染更新的“特征” (features) 以及由此产生的失效列表 (invalidation lists)**。

具体来说，这部分测试主要关注以下 CSS 特性和选择器如何影响元素的失效：

**1. `:webkit-any()` 伪类选择器：**

*   **功能：**  测试 `:webkit-any()` 伪类选择器在不同组合下（例如，后代选择器、兄弟选择器）是否能正确触发相应的失效。`:webkit-any()` 允许匹配多个选择器中的任何一个。
*   **与 CSS 的关系：** 这是 CSS 选择器规范的一部分，用于更灵活地选择元素。
*   **假设输入与输出：**
    *   **输入：**  CSS 规则 `.a :-webkit-any(#b, #c)`
    *   **输出：**  如果应用了这条规则，并且元素 `.a` 的后代元素的 id 为 `b` 或 `c` 时，该元素需要失效 (invalidated)。
*   **用户操作与调试线索：** 用户编写包含 `:webkit-any()` 的 CSS 规则，或者浏览器在渲染网页时遇到这样的规则。调试时，需要查看当 `:webkit-any()` 中的任何一个选择器匹配到元素时，是否触发了正确的样式更新。

**2. 兄弟选择器 (`~`) 与 `:webkit-any()` 的组合：**

*   **功能：** 测试兄弟选择器与 `:webkit-any()` 组合使用时，对兄弟元素的影响。
*   **与 CSS 的关系：** CSS 兄弟选择器用于选择具有相同父元素的后续兄弟元素。
*   **假设输入与输出：**
    *   **输入：** CSS 规则 `.v ~ :-webkit-any(.w, .x)`
    *   **输出：**  如果元素 `.v` 之后的兄弟元素具有类名 `w` 或 `x`，这些兄弟元素需要失效。
*   **用户操作与调试线索：** 用户编写包含兄弟选择器和 `:webkit-any()` 的 CSS 规则。调试时，需要验证当满足兄弟关系和 `:webkit-any()` 中任意一个条件时，兄弟元素是否正确地重新渲染。

**3. 包含 ID 和属性选择器的后代选择器：**

*   **功能：**  测试包含 ID 选择器 (`#`) 和属性选择器 (`[]`) 的后代选择器是否能正确触发后代元素的失效。
*   **与 CSS 的关系：**  这是基本的 CSS 选择器，用于根据 ID 和属性选择元素。
*   **假设输入与输出：**
    *   **输入：** CSS 规则 `#a #b`
    *   **输出：**  如果应用了这条规则，并且 id 为 `a` 的元素的后代元素 id 为 `b`，则该后代元素需要失效。
    *   **输入：** CSS 规则 `[c] [d]`
    *   **输出：**  如果应用了这条规则，并且具有属性 `c` 的元素的后代元素具有属性 `d`，则该后代元素需要失效。
*   **用户操作与调试线索：** 用户编写包含 ID 或属性后代选择器的 CSS 规则。调试时，检查当后代元素的 ID 或属性发生变化时，样式是否更新。

**4. 伪类选择器与后代选择器的组合：**

*   **功能：**  测试伪类选择器（例如 `:valid`）与后代选择器组合使用时，是否能正确触发后代元素的失效。
*   **与 CSS 的关系：**  伪类选择器用于选择处于特定状态的元素。
*   **假设输入与输出：**
    *   **输入：** CSS 规则 `:valid e`
    *   **输出：**  如果应用了这条规则，并且当前处于 `:valid` 状态的元素的后代元素是标签名为 `e` 的元素，则该后代元素需要失效。
*   **用户操作与调试线索：** 用户编写包含伪类和后代选择器的 CSS 规则。调试时，观察当元素的伪类状态改变时，后代元素的样式是否更新。

**5. `:host` 和 `:host-context` 伪类的非匹配情况：**

*   **功能：**  测试在特定情况下，`:host` 和 `:host-context` 伪类选择器不会匹配元素，因此不应该触发失效。
*   **与 CSS 的关系：**  `:host` 用于选择 shadow DOM 的宿主元素自身，`:host-context` 用于选择 shadow DOM 的宿主元素及其祖先元素。
*   **假设输入与输出：**
    *   **输入：**  CSS 规则 `.a:host`
    *   **输出：**  由于 `.a` 不能直接修饰 `:host`，该规则不会匹配任何元素，因此不会有失效。
*   **用户操作与调试线索：** 用户在 CSS 中错误地使用了 `:host` 或 `:host-context`。调试时，需要确认这些规则没有意外地影响到任何元素。

**6. `:is()` 和 `:where()` 伪类的空参数情况：**

*   **功能：**  测试当 `:is()` 和 `:where()` 伪类选择器没有参数或者参数无法匹配任何选择器时，不会匹配任何元素，因此不应该触发失效。
*   **与 CSS 的关系：**  `:is()` 和 `:where()` 伪类选择器接收一个选择器列表作为参数，并匹配列表中的任何一个选择器。
*   **假设输入与输出：**
    *   **输入：** CSS 规则 `:is()`
    *   **输出：** 由于 `:is()` 没有参数，不会匹配任何元素，因此不会有失效。
*   **用户操作与调试线索：** 用户在 CSS 中使用了空的 `:is()` 或 `:where()`。调试时，需要确保这些规则不会产生任何影响。

**7. 通用兄弟失效 (`* + .a`, `* ~ .a` 等)：**

*   **功能：**  测试当兄弟选择器 (`+`, `~`) 的前一个选择器是通用选择器 (`*`) 时，如何触发兄弟元素的失效。这涉及到直接相邻兄弟 (`+`) 和后续所有兄弟 (`~`) 的不同情况。
*   **与 CSS 的关系：**  通用选择器匹配任何元素。
*   **假设输入与输出：**
    *   **输入：** CSS 规则 `* + .a`
    *   **输出：** 任何元素直接相邻的下一个兄弟元素，如果类名为 `a`，则该兄弟元素需要失效。
    *   **输入：** CSS 规则 `* ~ .a`
    *   **输出：** 任何元素之后的所有兄弟元素，如果类名为 `a`，则这些兄弟元素需要失效。
*   **用户操作与调试线索：** 用户编写使用了通用兄弟选择器的 CSS 规则。调试时，需要验证当通用选择器匹配到元素时，其兄弟元素是否根据选择器类型正确失效。

**8. `:nth-child()` 相关的失效：**

*   **功能：**  测试 `:nth-child()` 伪类选择器在不同组合下（例如，后代、兄弟、`:not()`、`:any()`）如何触发失效。`:nth-child()` 根据元素在其父元素中的索引位置进行选择。
*   **与 CSS 的关系：**  这是 CSS 中用于根据索引选择元素的强大工具。
*   **假设输入与输出：**
    *   **输入：** CSS 规则 `:nth-child(2n)`
    *   **输出：**  父元素的所有索引为偶数的子元素需要失效。
    *   **输入：** CSS 规则 `.a:nth-child(2n)`
    *   **输出：** 父元素的所有索引为偶数且类名为 `a` 的子元素需要失效。
*   **用户操作与调试线索：** 用户编写使用了 `:nth-child()` 的 CSS 规则。调试时，需要确保当元素的索引位置发生变化时，样式能够正确更新。

**9. 自失效集合 (SelfInvalidationSet)：**

*   **功能：**  测试某些选择器会直接导致匹配元素自身失效，并验证是否正确设置了自失效集合。
*   **与 CSS 的关系：**  当元素的自身属性或状态发生变化时，需要重新评估其样式。
*   **假设输入与输出：**
    *   **输入：** CSS 规则 `.a`
    *   **输出：**  当元素类名包含 `a` 时，该元素自身需要失效。
    *   **输入：** CSS 规则 `:hover`
    *   **输出：** 当元素进入或离开 `hover` 状态时，该元素自身需要失效。
*   **用户操作与调试线索：** 用户编写了直接选择元素的 CSS 规则。调试时，需要确认当元素自身发生变化时，样式是否能够及时更新。

**10. 替换自失效集合：**

*   **功能：**  测试当更复杂的选择器被添加到已经有自失效规则的元素上时，自失效集合是否被正确替换。
*   **与 CSS 的关系：**  更复杂的选择器可能会引入非自失效的依赖关系。
*   **假设输入与输出：**
    *   **输入：** 先有规则 `.a` (导致自失效)，后有规则 `.a div` (不再是纯粹的自失效)。
    *   **输出：**  对于 `.a div`，虽然 `.a` 元素仍然可能失效，但不再仅仅是基于自身的变化，还需要考虑后代元素的变化。
*   **用户操作与调试线索：**  用户逐步添加 CSS 规则，从简单的直接选择器到包含后代选择器的规则。调试时，需要观察失效机制是否随着规则的复杂性而变化。

**11. `:is()` 和 `:where()` 伪类的各种组合：**

*   **功能：** 进一步测试 `:is()` 和 `:where()` 伪类选择器在更复杂的场景下的行为，包括与兄弟选择器、后代选择器以及嵌套的 `:is()`/`:where()` 的组合。
*   **与 CSS 的关系：**  验证这些选择器在复杂场景下的正确性对于保证 CSS 引擎的健壮性至关重要。
*   **假设输入与输出：**  类似于上面 `:webkit-any()` 的例子，但针对 `:is()` 和 `:where()`。
*   **用户操作与调试线索：** 用户编写包含复杂 `:is()` 或 `:where()` 选择器的 CSS 规则。调试时，需要仔细检查在各种嵌套和组合情况下，哪些元素被正确地标记为失效。

**12. `::part()` 伪元素选择器：**

*   **功能：** 测试 `::part()` 伪元素选择器如何触发失效，特别是涉及到跨越 shadow DOM 边界的情况。
*   **与 CSS 的关系：** `::part()` 允许样式化 Web Components 内部 shadow DOM 中的特定部分。
*   **假设输入与输出：**
    *   **输入：** CSS 规则 `.a .b::part(partname)`
    *   **输出：** 当应用到类名为 `a` 的元素的后代类名为 `b` 的元素的 `partname` 部分时，该部分需要失效。
*   **用户操作与调试线索：** 用户编写使用了 `::part()` 的 CSS 规则来样式化 Web Components。调试时，需要确认当 Web Component 的内部结构或 part 发生变化时，样式是否能够正确更新。

**13. `:has()` 伪类选择器：**

*   **功能：**  测试 `:has()` 伪类选择器在不同场景下的失效行为，包括作为终端选择器和非终端选择器，以及在 shadow host 上的应用。
*   **与 CSS 的关系：** `:has()` 允许根据元素是否包含特定的后代元素来选择元素。
*   **假设输入与输出：**
    *   **输入：** CSS 规则 `.a .b:has(.c)`
    *   **输出：** 如果类名为 `a` 的元素的后代类名为 `b` 的元素包含类名为 `c` 的后代元素，则类名为 `b` 的元素需要失效。
    *   **输入：** CSS 规则 `.a .b:has(.c) .d`
    *   **输出：** 如果类名为 `a` 的元素的后代类名为 `b` 的元素包含类名为 `c` 的后代元素，则类名为 `a` 的元素的后代类名为 `d` 的元素需要失效。
*   **用户操作与调试线索：** 用户编写使用了 `:has()` 的 CSS 规则。调试时，需要验证当元素的后代结构满足 `:has()` 的条件时，相应的元素是否被正确地标记为失效。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **开发者编写或修改了 CSS 代码：** 用户可能在他们的网页或 Web Component 的样式表中添加、修改或删除了包含上述各种 CSS 特性和选择器的规则。
2. **浏览器加载并解析 CSS：** 当浏览器加载包含这些 CSS 规则的样式表时，Blink 引擎的 CSS 解析器会解析这些规则。
3. **构建 RuleFeatureSet 和 InvalidationLists：**  在解析过程中，`RuleFeatureSet` 和 `InvalidationLists` 等数据结构会被创建和填充，以记录每个规则的特征以及可能导致哪些元素的失效。 `rule_feature_set_test.cc` 就是用来验证这个构建过程是否正确的。
4. **渲染引擎使用失效信息：** 当 DOM 结构或元素状态发生变化时，渲染引擎会查询这些失效信息，以确定哪些元素需要重新计算样式和重新渲染。

**常见的使用错误以及例子：**

*   **错误地假设 `:host` 可以被普通类选择器修饰：** 例如，`.my-style:host` 是无效的，应该使用 `:host(.my-style)`。测试中的 `nonMatchingHost` 部分就覆盖了这种错误。
*   **在不支持的浏览器中使用 `-webkit-` 前缀的特性：**  虽然本测试针对 Blink 引擎，但在编写跨浏览器兼容的 CSS 时，过度依赖特定引擎的前缀可能导致问题。
*   **过度使用通用选择器 (`*`) 进行兄弟选择：**  例如，`* + .a` 会在每次有元素插入时都检查兄弟关系，可能影响性能。
*   **对 `:nth-child()` 的理解偏差：**  例如，忘记 `:nth-child()` 是基于元素在其父元素中的索引，而不是全局索引。

**总结一下它的功能 (本部分)：**

这部分 `rule_feature_set_test.cc` 文件的主要功能是**针对各种 CSS 选择器（尤其是 `:webkit-any`, 兄弟选择器, ID/属性选择器组合, 伪类, `:host`, `:host-context`, `:is`, `:where`, `:nth-child`, `::part`, `:has`）及其组合，验证 Blink 引擎在解析 CSS 规则时，能否正确地识别出这些选择器可能导致的元素失效，并将其记录在 `InvalidationLists` 中。**  这些测试确保了当这些 CSS 特性被使用时，渲染引擎能够准确地追踪需要更新的元素，从而保证页面的正确渲染和性能。
Prompt: 
```
这是目录为blink/renderer/core/css/rule_feature_set_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能

"""
orPreMatch::kMayMatch,
            CollectFeatures(".a :-webkit-any(#b, #c)"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "a");
  EXPECT_TRUE(HasIdInvalidation("b", "c", invalidation_lists.descendants));
}

TEST_F(RuleFeatureSetTest, repeatedAnyDescendant) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".a :-webkit-any(.v, .w):-webkit-any(.x, .y, .z)"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "a");
  EXPECT_TRUE(HasClassInvalidation("v", "w", invalidation_lists.descendants));
}

TEST_F(RuleFeatureSetTest, anyTagDescendant) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".a :-webkit-any(span, div)"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "a");
  EXPECT_TRUE(
      HasTagNameInvalidation("span", "div", invalidation_lists.descendants));
}

TEST_F(RuleFeatureSetTest, siblingAny) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".v ~ :-webkit-any(.w, .x)"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "v");
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasClassInvalidation("w", "x", invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, descendantSiblingAny) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".u .v ~ :-webkit-any(.w, .x)"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "u");
  EXPECT_TRUE(HasClassInvalidation("w", "x", invalidation_lists.descendants));
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, id) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures("#a #b"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForId(invalidation_lists, "a");
  EXPECT_TRUE(HasIdInvalidation("b", invalidation_lists.descendants));
}

TEST_F(RuleFeatureSetTest, attribute) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures("[c] [d]"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForAttribute(
      invalidation_lists,
      QualifiedName(g_empty_atom, AtomicString("c"), g_empty_atom));
  EXPECT_TRUE(HasAttributeInvalidation("d", invalidation_lists.descendants));
}

TEST_F(RuleFeatureSetTest, pseudoClass) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(":valid"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForPseudoClass(invalidation_lists,
                                        CSSSelector::kPseudoValid);
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
}

TEST_F(RuleFeatureSetTest, tagName) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(":valid e"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForPseudoClass(invalidation_lists,
                                        CSSSelector::kPseudoValid);
  EXPECT_TRUE(HasTagNameInvalidation("e", invalidation_lists.descendants));
}

TEST_F(RuleFeatureSetTest, nonMatchingHost) {
  EXPECT_EQ(SelectorPreMatch::kNeverMatches, CollectFeatures(".a:host"));
  EXPECT_EQ(SelectorPreMatch::kNeverMatches, CollectFeatures("*:host(.a)"));
  EXPECT_EQ(SelectorPreMatch::kNeverMatches, CollectFeatures("*:host .a"));
  EXPECT_EQ(SelectorPreMatch::kNeverMatches, CollectFeatures("div :host .a"));
  EXPECT_EQ(SelectorPreMatch::kNeverMatches, CollectFeatures(":host:hover .a"));
  EXPECT_EQ(SelectorPreMatch::kNeverMatches,
            CollectFeatures(":host:has(.b):hover .a"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "a");
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
}

TEST_F(RuleFeatureSetTest, nonMatchingHostContext) {
  EXPECT_EQ(SelectorPreMatch::kNeverMatches,
            CollectFeatures(".a:host-context(*)"));
  EXPECT_EQ(SelectorPreMatch::kNeverMatches,
            CollectFeatures("*:host-context(.a)"));
  EXPECT_EQ(SelectorPreMatch::kNeverMatches,
            CollectFeatures("*:host-context(*) .a"));
  EXPECT_EQ(SelectorPreMatch::kNeverMatches,
            CollectFeatures("div :host-context(div) .a"));
  EXPECT_EQ(SelectorPreMatch::kNeverMatches,
            CollectFeatures(":host-context(div):hover .a"));
  EXPECT_EQ(SelectorPreMatch::kNeverMatches,
            CollectFeatures(":host-context(div):has(.b):hover .a"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "a");
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
}

TEST_F(RuleFeatureSetTest, emptyIsWhere) {
  EXPECT_EQ(SelectorPreMatch::kNeverMatches, CollectFeatures(":is()"));
  EXPECT_EQ(SelectorPreMatch::kNeverMatches, CollectFeatures(":where()"));

  // We do not support :nonsense, so :is()/:where() end up empty.
  // https://drafts.csswg.org/selectors/#typedef-forgiving-selector-list
  EXPECT_EQ(SelectorPreMatch::kNeverMatches, CollectFeatures(":is(:nonsense)"));
  EXPECT_EQ(SelectorPreMatch::kNeverMatches,
            CollectFeatures(":where(:nonsense)"));
  EXPECT_EQ(SelectorPreMatch::kNeverMatches,
            CollectFeatures(".a:is(:nonsense)"));
  EXPECT_EQ(SelectorPreMatch::kNeverMatches,
            CollectFeatures(".b:where(:nonsense)"));
}

TEST_F(RuleFeatureSetTest, universalSiblingInvalidationDirectAdjacent) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures("* + .a"));

  InvalidationLists invalidation_lists;
  CollectUniversalSiblingInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasSiblingClassInvalidation(1, "a", invalidation_lists.siblings));
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, universalSiblingInvalidationMultipleDirectAdjacent) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures("* + .a + .b"));

  InvalidationLists invalidation_lists;
  CollectUniversalSiblingInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasSiblingClassInvalidation(2, "b", invalidation_lists.siblings));
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest,
       universalSiblingInvalidationDirectAdjacentDescendant) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures("* + .a .b"));

  InvalidationLists invalidation_lists;
  CollectUniversalSiblingInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasSiblingDescendantInvalidation(1, "a", "b",
                                               invalidation_lists.siblings));
  EXPECT_TRUE(HasNoSelfInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, universalSiblingInvalidationIndirectAdjacent) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures("* ~ .a"));

  InvalidationLists invalidation_lists;
  CollectUniversalSiblingInvalidationSet(invalidation_lists);

  EXPECT_TRUE(
      HasSiblingClassInvalidation(SiblingInvalidationSet::kDirectAdjacentMax,
                                  "a", invalidation_lists.siblings));
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest,
       universalSiblingInvalidationMultipleIndirectAdjacent) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures("* ~ .a ~ .b"));

  InvalidationLists invalidation_lists;
  CollectUniversalSiblingInvalidationSet(invalidation_lists);

  EXPECT_TRUE(
      HasSiblingClassInvalidation(SiblingInvalidationSet::kDirectAdjacentMax,
                                  "b", invalidation_lists.siblings));
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest,
       universalSiblingInvalidationIndirectAdjacentDescendant) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures("* ~ .a .b"));

  InvalidationLists invalidation_lists;
  CollectUniversalSiblingInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasSiblingDescendantInvalidation(
      SiblingInvalidationSet::kDirectAdjacentMax, "a", "b",
      invalidation_lists.siblings));
  EXPECT_TRUE(HasNoSelfInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, universalSiblingInvalidationNot) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(":not(.a) + .b"));

  InvalidationLists invalidation_lists;
  CollectUniversalSiblingInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasSiblingClassInvalidation(1, "b", invalidation_lists.siblings));
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, nonUniversalSiblingInvalidationNot) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures("#x:not(.a) + .b"));

  InvalidationLists invalidation_lists;
  CollectUniversalSiblingInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, nonUniversalSiblingInvalidationAny) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures("#x:-webkit-any(.a) + .b"));

  InvalidationLists invalidation_lists;
  CollectUniversalSiblingInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, universalSiblingInvalidationType) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures("div + .a"));

  InvalidationLists invalidation_lists;
  CollectUniversalSiblingInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasSiblingClassInvalidation(1, "a", invalidation_lists.siblings));
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, nonUniversalSiblingInvalidationType) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures("div#x + .a"));

  InvalidationLists invalidation_lists;
  CollectUniversalSiblingInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, universalSiblingInvalidationLink) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(":link + .a"));

  InvalidationLists invalidation_lists;
  CollectUniversalSiblingInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasSiblingClassInvalidation(1, "a", invalidation_lists.siblings));
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, nonUniversalSiblingInvalidationLink) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures("#x:link + .a"));

  InvalidationLists invalidation_lists;
  CollectUniversalSiblingInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, nthInvalidationUniversal) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(":nth-child(2n)"));

  InvalidationLists invalidation_lists;
  CollectNthInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.siblings));
  EXPECT_TRUE(HasWholeSubtreeInvalidation(invalidation_lists.siblings));
  EXPECT_TRUE(HasSiblingNoDescendantInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, nthInvalidationClass) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(".a:nth-child(2n)"));

  InvalidationLists invalidation_lists;
  CollectNthInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.siblings));
  EXPECT_TRUE(
      HasSiblingClassInvalidation(SiblingInvalidationSet::kDirectAdjacentMax,
                                  "a", invalidation_lists.siblings));
  EXPECT_TRUE(HasSiblingNoDescendantInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, nthInvalidationUniversalDescendant) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(":nth-child(2n) *"));

  InvalidationLists invalidation_lists;
  CollectNthInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasNoSelfInvalidation(invalidation_lists.siblings));
  EXPECT_TRUE(HasWholeSubtreeInvalidation(invalidation_lists.siblings));
  EXPECT_TRUE(HasSiblingWholeSubtreeInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, nthInvalidationDescendant) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(":nth-child(2n) .a"));

  InvalidationLists invalidation_lists;
  CollectNthInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasNoSelfInvalidation(invalidation_lists.siblings));
  EXPECT_TRUE(HasWholeSubtreeInvalidation(invalidation_lists.siblings));
  EXPECT_TRUE(HasSiblingDescendantInvalidation(
      SiblingInvalidationSet::kDirectAdjacentMax, "a",
      invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, nthInvalidationSibling) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(":nth-child(2n) + .a"));

  InvalidationLists invalidation_lists;
  CollectNthInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.siblings));
  EXPECT_TRUE(HasClassInvalidation("a", invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, nthInvalidationSiblingDescendant) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(":nth-child(2n) + .a .b"));

  InvalidationLists invalidation_lists;
  CollectNthInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasNoSelfInvalidation(invalidation_lists.siblings));
  EXPECT_TRUE(HasSiblingDescendantInvalidation(
      SiblingInvalidationSet::kDirectAdjacentMax, "a", "b",
      invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, nthInvalidationNot) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(":not(:nth-child(2n))"));

  InvalidationLists invalidation_lists;
  CollectNthInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.siblings));
  EXPECT_TRUE(HasWholeSubtreeInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, nthInvalidationNotClass) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".a:not(:nth-child(2n))"));

  InvalidationLists invalidation_lists;
  CollectNthInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.siblings));
  EXPECT_TRUE(
      HasSiblingClassInvalidation(SiblingInvalidationSet::kDirectAdjacentMax,
                                  "a", invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, nthInvalidationNotDescendant) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".blah:not(:nth-child(2n)) .a"));

  InvalidationLists invalidation_lists;
  CollectNthInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasNoSelfInvalidation(invalidation_lists.siblings));
  EXPECT_TRUE(HasWholeSubtreeInvalidation(invalidation_lists.siblings));
  EXPECT_TRUE(HasSiblingDescendantInvalidation(
      SiblingInvalidationSet::kDirectAdjacentMax, "a",
      invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, nthInvalidationAny) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(":-webkit-any(#nomatch, :nth-child(2n))"));

  InvalidationLists invalidation_lists;
  CollectNthInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.siblings));
  EXPECT_TRUE(HasWholeSubtreeInvalidation(invalidation_lists.siblings));
  EXPECT_TRUE(HasSiblingNoDescendantInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, nthInvalidationAnyClass) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".a:-webkit-any(#nomatch, :nth-child(2n))"));

  InvalidationLists invalidation_lists;
  CollectNthInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.siblings));
  EXPECT_TRUE(HasClassInvalidation("a", invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, nthInvalidationAnyDescendant) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".blah:-webkit-any(#nomatch, :nth-child(2n)) .a"));

  InvalidationLists invalidation_lists;
  CollectNthInvalidationSet(invalidation_lists);

  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasNoSelfInvalidation(invalidation_lists.siblings));
  EXPECT_TRUE(HasSiblingDescendantInvalidation(
      SiblingInvalidationSet::kDirectAdjacentMax, "a",
      invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, SelfInvalidationSet) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(".a"));
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures("div .b"));
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures("#c"));
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures("[d]"));
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(":hover"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "a");
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasSelfInvalidationSet(invalidation_lists.descendants));

  invalidation_lists.descendants.clear();
  CollectInvalidationSetsForClass(invalidation_lists, "b");
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasSelfInvalidationSet(invalidation_lists.descendants));

  invalidation_lists.descendants.clear();
  CollectInvalidationSetsForId(invalidation_lists, "c");
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasSelfInvalidationSet(invalidation_lists.descendants));

  invalidation_lists.descendants.clear();
  CollectInvalidationSetsForAttribute(
      invalidation_lists,
      QualifiedName(g_empty_atom, AtomicString("d"), g_empty_atom));
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasSelfInvalidationSet(invalidation_lists.descendants));

  invalidation_lists.descendants.clear();
  CollectInvalidationSetsForPseudoClass(invalidation_lists,
                                        CSSSelector::kPseudoHover);
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasSelfInvalidationSet(invalidation_lists.descendants));
}

TEST_F(RuleFeatureSetTest, ReplaceSelfInvalidationSet) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(".a"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "a");
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasSelfInvalidationSet(invalidation_lists.descendants));

  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(".a div"));

  invalidation_lists.descendants.clear();
  CollectInvalidationSetsForClass(invalidation_lists, "a");
  EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasNotSelfInvalidationSet(invalidation_lists.descendants));
}

TEST_F(RuleFeatureSetTest, pseudoIsSibling) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(":is(.q, .r) ~ .s .t"));
  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "q");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasSiblingDescendantInvalidation(
        SiblingInvalidationSet::kDirectAdjacentMax, "s", "t",
        invalidation_lists.siblings));
  }
  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "r");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasSiblingDescendantInvalidation(
        SiblingInvalidationSet::kDirectAdjacentMax, "s", "t",
        invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, pseudoIs) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(":is(.w, .x)"));

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "w");
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "x");
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, pseudoIsIdDescendant) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(".a :is(#b, #c)"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "a");
  EXPECT_TRUE(HasIdInvalidation("b", "c", invalidation_lists.descendants));
}

TEST_F(RuleFeatureSetTest, pseudoIsTagDescendant) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(".a :is(span, div)"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "a");
  EXPECT_TRUE(
      HasTagNameInvalidation("span", "div", invalidation_lists.descendants));
}

TEST_F(RuleFeatureSetTest, pseudoIsAnySibling) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(".v ~ :is(.w, .x)"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "v");
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasClassInvalidation("w", "x", invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, pseudoIsDescendantSibling) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".u .v ~ :is(.w, .x)"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "u");
  EXPECT_TRUE(HasClassInvalidation("w", "x", invalidation_lists.descendants));
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, pseudoIsWithComplexSelectors) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".a :is(.w+.b, .x>#c)"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "a");
  EXPECT_TRUE(HasClassInvalidation("b", invalidation_lists.descendants));
  EXPECT_TRUE(HasIdInvalidation("c", invalidation_lists.descendants));
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, pseudoIsNested) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".a :is(.w+.b, .e+:is(.c, #d))"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "a");
  EXPECT_TRUE(HasClassInvalidation("b", "c", invalidation_lists.descendants));
  EXPECT_TRUE(HasIdInvalidation("d", invalidation_lists.descendants));
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, pseudoWhere) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(":where(.w, .x)"));

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "w");
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "x");
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, pseudoWhereSibling) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(":where(.q, .r) ~ .s .t"));
  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "q");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasSiblingDescendantInvalidation(
        SiblingInvalidationSet::kDirectAdjacentMax, "s", "t",
        invalidation_lists.siblings));
  }
  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "r");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasSiblingDescendantInvalidation(
        SiblingInvalidationSet::kDirectAdjacentMax, "s", "t",
        invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, pseudoWhereIdDescendant) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(".a :where(#b, #c)"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "a");
  EXPECT_TRUE(HasIdInvalidation("b", "c", invalidation_lists.descendants));
}

TEST_F(RuleFeatureSetTest, pseudoWhereTagDescendant) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".a :where(span, div)"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "a");
  EXPECT_TRUE(
      HasTagNameInvalidation("span", "div", invalidation_lists.descendants));
}

TEST_F(RuleFeatureSetTest, pseudoWhereAnySibling) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".v ~ :where(.w, .x)"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "v");
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
  EXPECT_TRUE(HasClassInvalidation("w", "x", invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, pseudoWhereDescendantSibling) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".u .v ~ :where(.w, .x)"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "u");
  EXPECT_TRUE(HasClassInvalidation("w", "x", invalidation_lists.descendants));
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, pseudoWhereWithComplexSelectors) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".a :where(.w+.b, .x>#c)"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "a");
  EXPECT_TRUE(HasClassInvalidation("b", invalidation_lists.descendants));
  EXPECT_TRUE(HasIdInvalidation("c", invalidation_lists.descendants));
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, pseudoWhereNested) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".a :where(.w+.b, .e+:where(.c, #d))"));

  InvalidationLists invalidation_lists;
  CollectInvalidationSetsForClass(invalidation_lists, "a");
  EXPECT_TRUE(HasClassInvalidation("b", "c", invalidation_lists.descendants));
  EXPECT_TRUE(HasIdInvalidation("d", invalidation_lists.descendants));
  EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
}

TEST_F(RuleFeatureSetTest, invalidatesParts) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch,
            CollectFeatures(".a .b::part(partname)"));

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "a");
    EXPECT_EQ(1u, invalidation_lists.descendants.size());
    EXPECT_TRUE(HasNoSelfInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(invalidation_lists.descendants[0]->TreeBoundaryCrossing());
    EXPECT_TRUE(invalidation_lists.descendants[0]->InvalidatesParts());
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "b");
    EXPECT_EQ(1u, invalidation_lists.descendants.size());
    EXPECT_TRUE(HasPartsInvalidation(invalidation_lists.descendants));
    EXPECT_FALSE(invalidation_lists.descendants[0]->WholeSubtreeInvalid());
    EXPECT_TRUE(invalidation_lists.descendants[0]->TreeBoundaryCrossing());
    EXPECT_TRUE(invalidation_lists.descendants[0]->InvalidatesParts());
  }

  {
    InvalidationLists invalidation_lists;
    CollectPartInvalidationSet(invalidation_lists);
    EXPECT_EQ(1u, invalidation_lists.descendants.size());
    EXPECT_TRUE(HasPartsInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(invalidation_lists.descendants[0]->TreeBoundaryCrossing());
    EXPECT_TRUE(invalidation_lists.descendants[0]->InvalidatesParts());
  }
}

TEST_F(RuleFeatureSetTest, invalidatesTerminalHas) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(".a .b:has(.c)"));

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "a");
    EXPECT_TRUE(HasClassInvalidation("b", invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
    EXPECT_FALSE(NeedsHasInvalidationForClass("a"));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "b");
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
    EXPECT_FALSE(NeedsHasInvalidationForClass("b"));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "c");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
    EXPECT_TRUE(NeedsHasInvalidationForClass("c"));
  }
}

TEST_F(RuleFeatureSetTest, invalidatesNonTerminalHas) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(".a .b:has(.c) .d"));

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "a");
    EXPECT_TRUE(HasClassInvalidation("d", invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
    EXPECT_FALSE(NeedsHasInvalidationForClass("a"));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "b");
    EXPECT_TRUE(HasClassInvalidation("d", invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
    EXPECT_FALSE(NeedsHasInvalidationForClass("b"));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "c");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
    EXPECT_TRUE(NeedsHasInvalidationForClass("c"));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "d");
    EXPECT_TRUE(HasSelfInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
    EXPECT_FALSE(NeedsHasInvalidationForClass("d"));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForPseudoClass(invalidation_lists,
                                          CSSSelector::kPseudoHas);
    EXPECT_EQ(1u, invalidation_lists.descendants.size());
    EXPECT_TRUE(HasClassInvalidation("d", invalidation_lists.descendants));
    EXPECT_FALSE(invalidation_lists.descendants[0]->TreeBoundaryCrossing());
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, invalidatesHasOnShadowHostAtSubjectPosition) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(":host:has(.a)"));

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "a");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
    EXPECT_TRUE(NeedsHasInvalidationForClass("a"));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForPseudoClass(invalidation_lists,
                                          CSSSelector::kPseudoHas);
    EXPECT_EQ(0u, invalidation_lists.descendants.size());
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
  }
}

TEST_F(RuleFeatureSetTest, invalidatesHasOnShadowHostAtNonSubjectPosition) {
  EXPECT_EQ(SelectorPreMatch::kMayMatch, CollectFeatures(":host:has(.a) .b"));

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForClass(invalidation_lists, "a");
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.descendants));
    EXPECT_TRUE(HasNoInvalidation(invalidation_lists.siblings));
    EXPECT_TRUE(NeedsHasInvalidationForClass("a"));
  }

  {
    InvalidationLists invalidation_lists;
    CollectInvalidationSetsForPseudoClass(invalidation_lists,
                                          CSSSelector::kPseudoHas);
    EXPECT_EQ(1u, invalidation_lists.descendants.size());
    EXPECT_TRUE(HasClassInvalidation("b", invalidation_lists.descendants));
    EXPECT_TRUE(invalidation_lists.descendants[0]->TreeBoundaryCrossing());
    EXPECT_TRUE(HasNoInvalidation(invalidati
"""


```