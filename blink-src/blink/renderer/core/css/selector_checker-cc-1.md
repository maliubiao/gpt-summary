Response:
The user wants to understand the functionality of the provided C++ code snippet from `selector_checker.cc`. This file is part of the Chromium Blink engine and deals with CSS selector matching.

Here's a breakdown of how to address each part of the request:

1. **List the functions:**  Scan the code for function definitions.
2. **Explain the functionality:**  Analyze the code logic, especially the `switch` statements and conditional checks, to describe what each function does. Pay attention to the CSS selector types being checked.
3. **Relate to JavaScript, HTML, CSS:**  Consider how the code interacts with these web technologies. Think about how CSS selectors target elements in the HTML structure and how JavaScript might trigger style recalculations or query element matches.
4. **Provide examples with input/output:**  For the more complex functions, create hypothetical scenarios with example HTML structures and CSS selectors to illustrate how the code would behave and what the expected matching result would be.
5. **Illustrate common usage errors:** Think about how developers might write incorrect CSS selectors that would be handled by this code.
6. **Explain user actions leading to this code:** Trace back how user interactions in a browser might trigger the CSS selector matching process. Consider scenarios like page load, dynamic content updates, and user interactions that change element states.
7. **Summarize the functionality (Part 2):** Condense the information from the previous steps to provide a concise overview of the code's purpose.

**Mental Sandbox:**

* **`AnyAttributeMatches`:** This function seems to iterate through element attributes and compare them against the selector's attribute requirements (name, value, matching type). I'll need to illustrate the different attribute match types (exact, contains, etc.).
* **`CheckOne`:** This appears to be the core matching function, handling different selector types like tag names, classes, IDs, and attributes. The logic around shadow hosts is important to highlight.
* **`CheckPseudoNot` and `MatchesAnyInList`:** These deal with the `:not()` pseudo-class and selector lists. I need to explain how negation works in CSS selectors.
* **`CheckPseudoHas`:** This is complex. It involves traversing the DOM based on the selectors inside `:has()` and caching results. I need to break down the different scenarios and how the caching and fast-reject mechanisms work. The logic around `AffectedByHas` flags is crucial.
* **`CheckPseudoClass`:** This function handles a variety of pseudo-classes. I'll need to provide examples for common ones like `:first-child`, `:last-of-type`, `:empty`, etc.

**Key Considerations:**

* **Performance:**  The code uses `ALWAYS_INLINE` and caching mechanisms, suggesting performance is a concern. I should mention this.
* **Blink-Specific Concepts:**  Terms like "shadow host" and "pseudo ID" are Blink-specific. I need to explain these in the context of web components and internal rendering.
* **Edge Cases:**  Think about unusual scenarios or complex selector combinations to test the robustness of the explanation.

By following these steps and considering the nuances of the code, I can generate a comprehensive and accurate explanation.
好的，让我们来归纳一下这段代码的功能。

这段 `selector_checker.cc` 代码片段主要负责 **检查一个给定的元素是否匹配一个 CSS 选择器**。它是 Blink 渲染引擎中 CSS 选择器匹配的核心组件。

以下是其主要功能点的归纳：

**1. 属性匹配 (`AnyAttributeMatches`)：**

* **功能:**  检查元素是否具有满足给定属性选择器的属性。
* **关系:**
    * **CSS:** 直接对应 CSS 属性选择器，例如 `[attr]`, `[attr=value]`, `[attr~=value]`, `[attr|=value]`, `[attr*=value]`, `[attr^=value]`, `[attr$=value]`, `[attr i=value]` 等。
    * **HTML:**  操作的是 HTML 元素的属性。
* **逻辑推理:**
    * **假设输入:** 一个 `Element` 对象，一个 `CSSSelector` 对象，其 `Match()` 返回属性匹配类型 (如 `kAttributeExact`)。
    * **输出:** `true` 如果元素匹配该属性选择器，否则 `false`。
* **常见错误:**
    * 用户在 CSS 中使用了错误的属性选择器语法，例如属性名拼写错误，或者使用了不存在的匹配符。
* **调试线索:** 当样式没有按预期应用到具有特定属性的元素上时，可以检查这里，确认属性选择器的匹配逻辑是否正确。

**2. 单个选择器检查 (`CheckOne`)：**

* **功能:** 检查元素是否匹配单个 CSS 选择器 (不包含组合器，例如空格、`>`、`+`、`~`)。
* **关系:**
    * **CSS:** 处理各种基本的 CSS 选择器，如类型选择器 (`tag`)、类选择器 (`.class`)、ID 选择器 (`#id`)、属性选择器以及伪类和伪元素。
    * **HTML:**  操作 HTML 元素及其属性。
* **逻辑推理:**
    * **假设输入:** 一个 `SelectorCheckingContext` 对象（包含元素和选择器），一个 `MatchResult` 对象。
    * **输出:** `true` 如果元素匹配该选择器，否则 `false`。对于伪类和伪元素，可能会修改 `MatchResult`。
* **常见错误:**
    * 用户在 CSS 中使用了错误的类名、ID 或标签名。
    * 用户对 Shadow DOM 的 `:host` 等伪类的理解有误，导致选择器无法匹配。
* **调试线索:** 当元素应该匹配某个简单选择器但没有匹配时，可以断点到这里，查看是哪个 `case` 分支没有通过。

**3. `:not` 伪类检查 (`CheckPseudoNot`)：**

* **功能:** 检查元素是否 *不* 匹配 `:not()` 伪类中包含的任何选择器列表。
* **关系:**
    * **CSS:**  对应 CSS 的 `:not()` 伪类。
* **逻辑推理:**
    * **假设输入:** 一个 `SelectorCheckingContext` 对象，其 `selector` 是一个 `:not()` 伪类选择器。
    * **输出:** `true` 如果元素不匹配 `:not()` 中的任何选择器，否则 `false`。
* **常见错误:**
    * 用户在 `:not()` 中使用了过于宽泛的选择器，导致本应匹配的元素也被排除在外。
* **调试线索:** 当元素不应该匹配某个样式，但由于 `:not()` 的作用仍然匹配时，可以检查这里。

**4. 选择器列表匹配 (`MatchesAnyInList`)：**

* **功能:** 检查元素是否匹配给定选择器列表中的任何一个选择器。这是 `:not()` 等伪类实现的基础。
* **关系:**
    * **CSS:**  用于处理逗号分隔的选择器列表。
* **逻辑推理:**
    * **假设输入:** 一个 `SelectorCheckingContext` 对象，一个指向选择器列表头部的 `CSSSelector` 指针。
    * **输出:** `true` 如果元素匹配列表中的任何一个选择器，否则 `false`。

**5. `:has` 伪类检查 (`CheckPseudoHas`)：**

* **功能:** 检查元素是否匹配 `:has()` 伪类，即检查该元素在其后代或兄弟元素中是否 *拥有* 匹配 `:has()` 参数的元素。
* **关系:**
    * **CSS:**  对应 CSS 的 `:has()` 伪类。
    * **JavaScript (间接):**  JavaScript 可能会动态添加或删除元素，影响 `:has()` 的匹配结果。
    * **HTML:**  在 HTML 结构中进行查找匹配。
* **逻辑推理:**  这部分代码非常复杂，涉及遍历 DOM 树，并可能使用缓存来优化性能。
    * **假设输入:** 一个 `SelectorCheckingContext` 对象，其 `selector` 是一个 `:has()` 伪类选择器。
    * **输出:** `true` 如果在指定范围内找到了匹配 `:has()` 参数的元素，否则 `false`。
* **常见错误:**
    * 用户对 `:has()` 的作用域理解有误，例如在 Shadow DOM 中使用时。
    * `:has()` 中使用了过于复杂的选择器，导致性能问题。
* **调试线索:** 当使用了 `:has()` 但样式没有按预期应用时，需要仔细检查 `:has()` 内部选择器的匹配情况，以及遍历的范围是否正确。

**6. 其他伪类检查 (`CheckPseudoClass`)：**

* **功能:** 检查元素是否匹配各种其他的 CSS 伪类，例如 `:empty`, `:first-child`, `:last-of-type` 等。
* **关系:**
    * **CSS:**  对应各种 CSS 伪类。
    * **HTML:**  依赖于 HTML 元素的结构和状态。
* **逻辑推理:** 不同的伪类有不同的匹配逻辑，例如 `:empty` 检查元素是否没有子元素（或只有空白文本节点）。
* **常见错误:**
    * 对伪类的定义理解有误，例如认为 `:empty` 会排除包含空格的元素。
    * 在动态内容加载的情况下，伪类的状态可能会发生变化，导致样式不一致。
* **调试线索:**  当元素应该匹配某个伪类但没有匹配时，需要检查该伪类对应的条件是否满足。

**用户操作如何到达这里 (调试线索)：**

1. **页面加载:** 当浏览器加载 HTML 页面并解析 CSS 样式表时，渲染引擎会遍历 DOM 树，并使用 `selector_checker.cc` 中的代码来确定哪些样式规则应该应用到哪些元素上。
2. **动态样式修改:**  JavaScript 代码可能会修改元素的 `class` 属性、`style` 属性，或者添加/删除元素。这些操作会触发样式的重新计算，从而再次调用 `selector_checker.cc` 中的代码来更新元素的样式。
3. **伪类状态变化:**  用户的交互 (例如鼠标悬停、点击) 或元素自身的状态变化 (例如表单元素的 `:checked` 状态) 会导致伪类状态的改变，进而触发样式重新计算和选择器匹配。
4. **强制样式重排/重绘:**  某些 JavaScript 操作可能会强制浏览器进行样式的重排 (reflow) 或重绘 (repaint)，这也会涉及到选择器匹配。

**总结这段代码的功能：**

这段代码的主要职责是实现 CSS 选择器的匹配逻辑。它接收一个元素和一个 CSS 选择器作为输入，并判断该元素是否符合该选择器的条件。它支持各种类型的选择器，包括类型选择器、类选择器、ID 选择器、属性选择器以及各种伪类（例如 `:not`, `:has`, `:empty`, `:first-child` 等）。这段代码是浏览器渲染引擎中至关重要的一个组成部分，确保了 CSS 样式能够正确地应用到 HTML 元素上。 为了提高性能，代码中也包含了一些优化策略，例如对 `:has()` 伪类的匹配进行缓存和快速拒绝。

希望这个归纳能够帮助你理解这段代码的功能。

Prompt: 
```
这是目录为blink/renderer/core/css/selector_checker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能

"""
te();
  // Should not be possible from the CSS grammar.
  DCHECK_NE(selector_attr.LocalName(), CSSSelector::UniversalSelectorAtom());

  // Synchronize the attribute in case it is lazy-computed.
  // Currently all lazy properties have a null namespace, so only pass
  // localName().
  element.SynchronizeAttribute(selector_attr.LocalName());

  // NOTE: For kAttributeSet, this is a bogus pointer but never used.
  const AtomicString& selector_value = selector.Value();

  // Legacy dictates that values of some attributes should be compared in
  // a case-insensitive manner regardless of whether the case insensitive
  // flag is set or not (but an explicit case sensitive flag will override
  // that, by causing LegacyCaseInsensitiveMatch() never to be set).
  const bool case_insensitive =
      selector.AttributeMatch() ==
          CSSSelector::AttributeMatchType::kCaseInsensitive ||
      (selector.LegacyCaseInsensitiveMatch() &&
       IsA<HTMLDocument>(element.GetDocument()));

  AttributeCollection attributes = element.AttributesWithoutUpdate();
  for (const auto& attribute_item : attributes) {
    if (!attribute_item.Matches(selector_attr)) {
      if (element.IsHTMLElement() ||
          !IsA<HTMLDocument>(element.GetDocument())) {
        continue;
      }
      // Non-html attributes in html documents are normalized to their camel-
      // cased version during parsing if applicable. Yet, attribute selectors
      // are lower-cased for selectors in html documents. Compare the selector
      // and the attribute local name insensitively to e.g. allow matching SVG
      // attributes like viewBox.
      //
      // NOTE: If changing this behavior, be sure to also update the bucketing
      // in ElementRuleCollector::CollectMatchingRules() accordingly.
      if (!attribute_item.MatchesCaseInsensitive(selector_attr)) {
        continue;
      }
    }

    if (AttributeValueMatches(attribute_item, match, selector_value,
                              case_insensitive)) {
      return true;
    }

    if (selector_attr.NamespaceURI() != g_star_atom) {
      return false;
    }
  }

  return false;
}

ALWAYS_INLINE bool SelectorChecker::CheckOne(
    const SelectorCheckingContext& context,
    MatchResult& result) const {
  DCHECK(context.element);
  Element& element = *context.element;
  DCHECK(context.selector);
  const CSSSelector& selector = *context.selector;

  // When considered within its own shadow trees, the shadow host is
  // featureless. Only the :host, :host(), and :host-context() pseudo-classes
  // are allowed to match it. [1]
  //
  // However, the :scope pseudo-class may also match the host if the host is the
  // scoping root. [2]
  //
  // Also, we need to descend into selectors that contain lists instead of
  // just returning false, such that :is(:host, .doesnotmatch) (see [3]),
  // or similar via nesting, is handled correctly. (This also deals with
  // :not().) Such cases will eventually recurse back into CheckOne(),
  // so should do not get false positives from doing this; the featurelessness
  // will be checked on a lower level.
  //
  // [1] https://drafts.csswg.org/css-scoping/#host-element-in-tree
  // [2] https://github.com/w3c/csswg-drafts/issues/9025
  // [3] https://drafts.csswg.org/selectors-4/#data-model
  if (context.scope && context.scope->OwnerShadowHost() == element &&
      (!selector.IsHostPseudoClass() && !selector.SelectorListOrParent() &&
       selector.GetPseudoType() != CSSSelector::kPseudoScope &&
       !context.treat_shadow_host_as_normal_scope &&
       selector.Match() != CSSSelector::kPseudoElement)) {
    return false;
  }

  switch (selector.Match()) {
    case CSSSelector::kTag:
      return MatchesTagName(element, selector.TagQName());
    case CSSSelector::kClass:
      return element.HasClass() &&
             element.ClassNames().Contains(selector.Value());
    case CSSSelector::kId:
      return element.HasID() &&
             element.IdForStyleResolution() == selector.Value();

    // Attribute selectors
    case CSSSelector::kAttributeExact:
    case CSSSelector::kAttributeSet:
    case CSSSelector::kAttributeHyphen:
    case CSSSelector::kAttributeList:
    case CSSSelector::kAttributeContain:
    case CSSSelector::kAttributeBegin:
    case CSSSelector::kAttributeEnd:
      return AnyAttributeMatches(element, selector.Match(), selector);

    case CSSSelector::kPseudoClass:
      return CheckPseudoClass(context, result);
    case CSSSelector::kPseudoElement:
      return CheckPseudoElement(context, result);

    default:
      NOTREACHED();
  }
}

bool SelectorChecker::CheckPseudoNot(const SelectorCheckingContext& context,
                                     MatchResult& result) const {
  return !MatchesAnyInList(context, context.selector->SelectorList()->First(),
                           result);
}

bool SelectorChecker::MatchesAnyInList(const SelectorCheckingContext& context,
                                       const CSSSelector* selector_list,
                                       MatchResult& result) const {
  SelectorCheckingContext sub_context(context);
  sub_context.is_sub_selector = true;
  sub_context.in_nested_complex_selector = true;
  sub_context.pseudo_id = kPseudoIdNone;
  for (sub_context.selector = selector_list; sub_context.selector;
       sub_context.selector = CSSSelectorList::Next(*sub_context.selector)) {
    SubResult sub_result(result);
    if (MatchSelector(sub_context, sub_result) == kSelectorMatches) {
      return true;
    }
  }
  return false;
}

namespace {

Element* TraverseToParentOrShadowHost(Element* element) {
  return element->ParentOrShadowHostElement();
}

Element* TraverseToPreviousSibling(Element* element) {
  return ElementTraversal::PreviousSibling(*element);
}

inline bool CacheMatchedElementsAndReturnMatchedResultForIndirectRelation(
    Element* has_anchor_element,
    HeapVector<Member<Element>>& has_argument_leftmost_compound_matches,
    CheckPseudoHasCacheScope::Context& cache_scope_context,
    Element* (*next)(Element*)) {
  if (cache_scope_context.CacheAllowed()) {
    bool selector_matched = false;
    for (auto leftmost : has_argument_leftmost_compound_matches) {
      for (Element* has_matched_element = next(leftmost); has_matched_element;
           has_matched_element = next(has_matched_element)) {
        if (has_matched_element == has_anchor_element) {
          selector_matched = true;
        }
        uint8_t old_result =
            cache_scope_context.SetMatchedAndGetOldResult(has_matched_element);
        if (old_result == kCheckPseudoHasResultNotCached) {
          continue;
        }
        if (old_result & kCheckPseudoHasResultMatched) {
          break;
        }
      }
    }
    return selector_matched;
  }

  for (auto leftmost : has_argument_leftmost_compound_matches) {
    for (Element* has_matched_element = next(leftmost); has_matched_element;
         has_matched_element = next(has_matched_element)) {
      if (has_matched_element == has_anchor_element) {
        return true;
      }
    }
  }
  return false;
}

inline bool CacheMatchedElementsAndReturnMatchedResultForDirectRelation(
    Element* has_anchor_element,
    HeapVector<Member<Element>>& has_argument_leftmost_compound_matches,
    CheckPseudoHasCacheScope::Context& cache_scope_context,
    Element* (*next)(Element*)) {
  if (cache_scope_context.CacheAllowed()) {
    bool selector_matched = false;
    for (auto leftmost : has_argument_leftmost_compound_matches) {
      if (Element* has_matched_element = next(leftmost)) {
        cache_scope_context.SetMatchedAndGetOldResult(has_matched_element);
        if (has_matched_element == has_anchor_element) {
          selector_matched = true;
        }
      }
    }
    return selector_matched;
  }

  for (auto leftmost : has_argument_leftmost_compound_matches) {
    if (Element* has_matched_element = next(leftmost)) {
      if (has_matched_element == has_anchor_element) {
        return true;
      }
    }
  }
  return false;
}

inline bool CacheMatchedElementsAndReturnMatchedResult(
    CSSSelector::RelationType leftmost_relation,
    Element* has_anchor_element,
    HeapVector<Member<Element>>& has_argument_leftmost_compound_matches,
    CheckPseudoHasCacheScope::Context& cache_scope_context) {
  switch (leftmost_relation) {
    case CSSSelector::kRelativeDescendant:
      return CacheMatchedElementsAndReturnMatchedResultForIndirectRelation(
          has_anchor_element, has_argument_leftmost_compound_matches,
          cache_scope_context, TraverseToParentOrShadowHost);
    case CSSSelector::kRelativeChild:
      return CacheMatchedElementsAndReturnMatchedResultForDirectRelation(
          has_anchor_element, has_argument_leftmost_compound_matches,
          cache_scope_context, TraverseToParentOrShadowHost);
    case CSSSelector::kRelativeDirectAdjacent:
      return CacheMatchedElementsAndReturnMatchedResultForDirectRelation(
          has_anchor_element, has_argument_leftmost_compound_matches,
          cache_scope_context, TraverseToPreviousSibling);
    case CSSSelector::kRelativeIndirectAdjacent:
      return CacheMatchedElementsAndReturnMatchedResultForIndirectRelation(
          has_anchor_element, has_argument_leftmost_compound_matches,
          cache_scope_context, TraverseToPreviousSibling);
    default:
      NOTREACHED();
  }
}

inline bool ContextForSubjectHasInMatchesArgument(
    const SelectorChecker::SelectorCheckingContext& has_checking_context) {
  return has_checking_context.element == has_checking_context.scope &&
         has_checking_context.in_rightmost_compound;
}

uint8_t SetHasAnchorElementAsCheckedAndGetOldResult(
    const SelectorChecker::SelectorCheckingContext& has_checking_context,
    CheckPseudoHasCacheScope::Context& cache_scope_context) {
  DCHECK_EQ(has_checking_context.selector->GetPseudoType(),
            CSSSelector::kPseudoHas);
  Element* has_anchor_element = has_checking_context.element;
  uint8_t previous_result = cache_scope_context.GetResult(has_anchor_element);
  if (previous_result & kCheckPseudoHasResultChecked) {
    return previous_result;
  }

  // If the selector checking context is for the subject :has() in the argument
  // of the JavaScript API 'matches()', skip to check whether the :has() anchor
  // element was already checked or not.
  if (!ContextForSubjectHasInMatchesArgument(has_checking_context) &&
      cache_scope_context.AlreadyChecked(has_anchor_element)) {
    // If the element already have cache item, set the element as checked.
    // Otherwise, skip to set to prevent increasing unnecessary cache item.
    if (previous_result != kCheckPseudoHasResultNotCached) {
      cache_scope_context.SetChecked(has_anchor_element);
    }

    // If the :has() anchor element was already checked previously, return the
    // previous result with the kCheckPseudoHasResultChecked flag set.
    return previous_result | kCheckPseudoHasResultChecked;
  }

  cache_scope_context.SetChecked(has_anchor_element);
  return previous_result;
}

void SetAffectedByHasFlagsForElementAtDepth(
    CheckPseudoHasArgumentContext& argument_context,
    Element* element,
    int depth) {
  if (depth > 0) {
    element->SetAncestorsOrAncestorSiblingsAffectedByHas();
  } else {
    element->SetSiblingsAffectedByHasFlags(
        argument_context.GetSiblingsAffectedByHasFlags());
  }
}

void SetAffectedByHasFlagsForHasAnchorElement(
    CheckPseudoHasArgumentContext& argument_context,
    Element* has_anchor_element) {
  switch (argument_context.LeftmostRelation()) {
    case CSSSelector::kRelativeChild:
    case CSSSelector::kRelativeDescendant:
      has_anchor_element->SetAncestorsOrAncestorSiblingsAffectedByHas();
      break;
    case CSSSelector::kRelativeDirectAdjacent:
    case CSSSelector::kRelativeIndirectAdjacent:
      has_anchor_element->SetSiblingsAffectedByHasFlags(
          argument_context.GetSiblingsAffectedByHasFlags());
      break;
    default:
      NOTREACHED();
  }
}

void SetAffectedByHasFlagsForHasAnchorSiblings(
    CheckPseudoHasArgumentContext& argument_context,
    Element* has_anchor_element) {
  if (argument_context.AdjacentDistanceLimit() == 0) {
    return;
  }
  int distance = 1;
  for (Element* sibling = ElementTraversal::NextSibling(*has_anchor_element);
       sibling && distance <= argument_context.AdjacentDistanceLimit();
       sibling = ElementTraversal::NextSibling(*sibling), distance++) {
    sibling->SetSiblingsAffectedByHasFlags(
        argument_context.GetSiblingsAffectedByHasFlags());
  }
}

void SetAffectedByHasForArgumentMatchedElement(
    CheckPseudoHasArgumentContext& argument_context,
    Element* has_anchor_element,
    Element* argument_matched_element,
    int argument_matched_depth) {
  // Iterator class to traverse siblings, ancestors and ancestor siblings of the
  // CheckPseudoHasArgumentTraversalIterator's current element until reach to
  // the :has() anchor element to set the SiblingsAffectedByHasFlags or
  // AncestorsOrAncestorSiblingsAffectedByHas flag.
  class AffectedByHasIterator {
    STACK_ALLOCATED();

   public:
    AffectedByHasIterator(CheckPseudoHasArgumentContext& argument_context,
                          Element* has_anchor_element,
                          Element* argument_matched_element,
                          int argument_matched_depth)
        : argument_context_(argument_context),
          has_anchor_element_(has_anchor_element),
          argument_matched_depth_(argument_matched_depth),
          current_depth_(argument_matched_depth),
          current_element_(argument_matched_element) {
      DCHECK_GE(current_depth_, 0);
      // affected-by flags of the matched element were already set.
      // So, this iterator traverses from the next of the matched element.
      ++*this;
    }

    Element* CurrentElement() const { return current_element_; }
    bool AtEnd() const {
      DCHECK_GE(current_depth_, 0);
      return current_element_ == has_anchor_element_;
    }
    int CurrentDepth() const { return current_depth_; }
    void operator++() {
      DCHECK(current_element_);

      if (current_depth_ == 0) {
        current_element_ = ElementTraversal::PreviousSibling(*current_element_);
        DCHECK(current_element_);
        return;
      }

      Element* previous = nullptr;
      if (NeedsTraverseSiblings() &&
          (previous = ElementTraversal::PreviousSibling(*current_element_))) {
        current_element_ = previous;
        DCHECK(current_element_);
        return;
      }

      DCHECK_GT(current_depth_, 0);
      current_depth_--;
      current_element_ = current_element_->ParentOrShadowHostElement();
      DCHECK(current_element_);
    }

   private:
    inline bool NeedsTraverseSiblings() {
      // When the current element is at the same depth of the argument selector
      // matched element, we can determine whether the sibling traversal is
      // needed or not by checking whether the rightmost combinator is an
      // adjacent combinator. When the current element is not at the same depth
      // of the argument selector matched element, we can determine whether the
      // sibling traversal is needed or not by checking whether an adjacent
      // combinator is between child or descendant combinator.
      DCHECK_LE(current_depth_, argument_matched_depth_);
      return argument_matched_depth_ == current_depth_
                 ? argument_context_.SiblingCombinatorAtRightmost()
                 : argument_context_
                       .SiblingCombinatorBetweenChildOrDescendantCombinator();
    }

    const CheckPseudoHasArgumentContext& argument_context_;
    Element* has_anchor_element_;
    const int argument_matched_depth_;
    int current_depth_;
    Element* current_element_;
  } affected_by_has_iterator(argument_context, has_anchor_element,
                             argument_matched_element, argument_matched_depth);

  // Set AncestorsOrAncestorSiblingsAffectedByHas flag on the elements at
  // upward (previous siblings, ancestors, ancestors' previous siblings) of the
  // argument matched element.
  for (; !affected_by_has_iterator.AtEnd(); ++affected_by_has_iterator) {
    SetAffectedByHasFlagsForElementAtDepth(
        argument_context, affected_by_has_iterator.CurrentElement(),
        affected_by_has_iterator.CurrentDepth());
  }
}

bool SkipCheckingHasArgument(
    CheckPseudoHasArgumentContext& context,
    CheckPseudoHasArgumentTraversalIterator& iterator) {
  // Siblings of the :has() anchor element cannot be a subject of :has()
  // argument if the argument selector has child or descendant combinator.
  if (context.DepthLimit() > 0 && iterator.CurrentDepth() == 0) {
    return true;
  }

  // The current element of the iterator cannot be a subject of :has() argument
  // if the :has() argument selector only matches on the elements at a fixed
  // depth and the current element of the iterator is not at the certain depth.
  // (e.g. For the style rule '.a:has(> .b > .c) {}', a child of '.a' or a great
  // grand child of '.a' cannot be a subject of the argument '> .b > .c'. Only
  // the grand child of '.a' can be a subject of the argument)
  if (context.DepthFixed() &&
      (iterator.CurrentDepth() != context.DepthLimit())) {
    return true;
  }

  return false;
}

void AddElementIdentifierHashesInTraversalScopeAndSetAffectedByHasFlags(
    CheckPseudoHasFastRejectFilter& fast_reject_filter,
    Element& has_anchor_element,
    CheckPseudoHasArgumentContext& argument_context,
    bool update_affected_by_has_flags) {
  for (CheckPseudoHasArgumentTraversalIterator iterator(has_anchor_element,
                                                        argument_context);
       !iterator.AtEnd(); ++iterator) {
    fast_reject_filter.AddElementIdentifierHashes(*iterator.CurrentElement());
    if (update_affected_by_has_flags) {
      SetAffectedByHasFlagsForElementAtDepth(
          argument_context, iterator.CurrentElement(), iterator.CurrentDepth());
    }
  }
}

void SetAllElementsInTraversalScopeAsChecked(
    Element* has_anchor_element,
    CheckPseudoHasArgumentContext& argument_context,
    CheckPseudoHasCacheScope::Context& cache_scope_context) {
  // Find last element and last depth of the argument traversal iterator.
  Element* last_element = has_anchor_element;
  int last_depth = 0;
  if (argument_context.AdjacentDistanceLimit() > 0) {
    last_element = ElementTraversal::NextSibling(*last_element);
  }
  if (last_element) {
    if (argument_context.DepthLimit() > 0) {
      last_element = ElementTraversal::FirstChild(*last_element);
      last_depth = 1;
    }
  }
  if (!last_element) {
    return;
  }
  cache_scope_context.SetAllTraversedElementsAsChecked(last_element,
                                                       last_depth);
}

enum EarlyBreakOnHasArgumentChecking {
  kBreakEarlyAndReturnAsMatched,
  kBreakEarlyAndMoveToNextArgument,
  kNoEarlyBreak,
};

EarlyBreakOnHasArgumentChecking CheckEarlyBreakForHasArgument(
    const SelectorChecker::SelectorCheckingContext& context,
    Element* has_anchor_element,
    CheckPseudoHasArgumentContext& argument_context,
    CheckPseudoHasCacheScope::Context& cache_scope_context,
    bool& update_affected_by_has_flags) {
  if (!cache_scope_context.CacheAllowed()) {
    return kNoEarlyBreak;
  }

  // Get the cached :has() checking result of the element to skip :has()
  // argument checking.
  //  - If the element was already marked as matched, break :has() argument
  //    checking early and return as matched.
  //  - If the element was already checked but not matched, break :has()
  //    argument checking early and move to the next argument selector.
  //  - Otherwise, check :has() argument.
  uint8_t previous_result =
      SetHasAnchorElementAsCheckedAndGetOldResult(context, cache_scope_context);
  if (previous_result & kCheckPseudoHasResultChecked) {
    if (update_affected_by_has_flags) {
      SetAffectedByHasFlagsForHasAnchorSiblings(argument_context,
                                                has_anchor_element);
    }
    return previous_result & kCheckPseudoHasResultMatched
               ? kBreakEarlyAndReturnAsMatched
               : kBreakEarlyAndMoveToNextArgument;
  }

  // Check fast reject filter to reject :has() argument checking early.

  bool is_new_entry;
  CheckPseudoHasFastRejectFilter& fast_reject_filter =
      cache_scope_context.EnsureFastRejectFilter(has_anchor_element,
                                                 is_new_entry);

  // Filter is not actually created on the first check to avoid unnecessary
  // filter creation overhead. If the :has() anchor element has the
  // AffectedByMultipleHas flag set, use fast reject filter even if on the first
  // check since there can be more checks on the anchor element.
  if (is_new_entry && !has_anchor_element->AffectedByMultipleHas()) {
    return kNoEarlyBreak;
  }

  // The bloom filter in the fast reject filter is allocated and initialized on
  // the second check. We can check fast rejection with the filter after the
  // allocation and initialization.
  if (!fast_reject_filter.BloomFilterAllocated()) {
    if (update_affected_by_has_flags) {
      // Mark the :has() anchor element as affected by multiple :has() pseudo
      // classes so that we can always use fast reject filter for the anchor
      // element.
      has_anchor_element->SetAffectedByMultipleHas();
    }

    fast_reject_filter.AllocateBloomFilter();
    AddElementIdentifierHashesInTraversalScopeAndSetAffectedByHasFlags(
        fast_reject_filter, *has_anchor_element, argument_context,
        update_affected_by_has_flags);
  }

  // affected-by-has flags were already set while adding element identifier
  // hashes (AddElementIdentifierHashesInTraversalScopeAndSetAffectedByHasFlags)
  update_affected_by_has_flags = false;

  if (fast_reject_filter.FastReject(
          argument_context.GetPseudoHasArgumentHashes())) {
    SetAllElementsInTraversalScopeAsChecked(
        has_anchor_element, argument_context, cache_scope_context);
    return kBreakEarlyAndMoveToNextArgument;
  }

  return kNoEarlyBreak;
}

bool MatchesExternalSVGUseTarget(Element& element) {
  const auto* svg_element = DynamicTo<SVGElement>(element);
  return svg_element && svg_element->IsResourceTarget();
}

}  // namespace

bool SelectorChecker::CheckPseudoHas(const SelectorCheckingContext& context,
                                     MatchResult& result) const {
  if (context.element->GetDocument().InPseudoHasChecking()) {
    // :has() within :has() would normally be rejected parse-time, but we can
    // end up in this situation nevertheless, due to nesting. We just return
    // a not-matched for now; it is possible that we should fail the entire rule
    // (consider what happens if it is e.g. within :not()), but we would have to
    // have some way to propagate that up the stack, and consider interactions
    // with the forgiveness of :is().
    return false;
  }
  CheckPseudoHasCacheScope check_pseudo_has_cache_scope(
      &context.element->GetDocument(), /*within_selector_checking=*/true);

  Element* has_anchor_element = context.element;
  Document& document = has_anchor_element->GetDocument();
  DCHECK(document.GetCheckPseudoHasCacheScope());
  SelectorCheckingContext sub_context(has_anchor_element);
  sub_context.scope = context.scope;
  // sub_context.match_visited is false (by default) to disable
  // :visited matching when it is in the :has argument
  sub_context.is_inside_has_pseudo_class = true;
  sub_context.pseudo_has_in_rightmost_compound = context.in_rightmost_compound;
  bool update_affected_by_has_flags = mode_ == kResolvingStyle;
  bool match_in_shadow_tree = context.selector->HasArgumentMatchInShadowTree();

  if (match_in_shadow_tree && !has_anchor_element->GetShadowRoot()) {
    NOTREACHED();
  }

  DCHECK(context.selector->SelectorList());
  for (const CSSSelector* selector = context.selector->SelectorList()->First();
       selector; selector = CSSSelectorList::Next(*selector)) {
    CheckPseudoHasArgumentContext argument_context(selector,
                                                   match_in_shadow_tree);

    // In case of matching a :has() argument on a shadow root subtree, skip
    // matching if the argument contains the sibling relationship to the :has()
    // anchor element because the shadow root cannot have sibling element.
    if (argument_context.TraversalScope() == kInvalidShadowRootTraversalScope) {
      continue;
    }

    CSSSelector::RelationType leftmost_relation =
        argument_context.LeftmostRelation();
    CheckPseudoHasCacheScope::Context cache_scope_context(&document,
                                                          argument_context);

    // In case that the :has() pseudo class checks a relationship to a sibling
    // element at fixed distance (e.g. '.a:has(+ .b)') or a sibling subtree at
    // fixed distance (e.g. '.a:has(+ .b .c)'), set the parent of the :has()
    // anchor element as ChildrenAffectedByDirectAdjacentRules to indicate
    // that removing a child from the parent may affect a :has() testing result
    // on a child of the parent.
    // (e.g. When we have a style rule '.a:has(+ .b) {}' we always need :has()
    // invalidation if the preceding element of '.b' is removed)
    // Please refer the :has() invalidation for element removal:
    //  - StyleEngine::ScheduleInvalidationsForHasPseudoAffectedByRemoval()
    if (argument_context.AdjacentDistanceLimit() > 0 &&
        argument_context.AdjacentDistanceFixed()) {
      if (ContainerNode* parent =
              has_anchor_element->ParentElementOrShadowRoot()) {
        parent->SetChildrenAffectedByDirectAdjacentRules();
      }
    }

    if (update_affected_by_has_flags) {
      SetAffectedByHasFlagsForHasAnchorElement(argument_context,
                                               has_anchor_element);
    }

    EarlyBreakOnHasArgumentChecking early_break = CheckEarlyBreakForHasArgument(
        context, has_anchor_element, argument_context, cache_scope_context,
        update_affected_by_has_flags);
    if (early_break == kBreakEarlyAndReturnAsMatched) {
      return true;
    } else if (early_break == kBreakEarlyAndMoveToNextArgument) {
      continue;
    }

    sub_context.selector = selector;
    sub_context.relative_anchor_element = has_anchor_element;

    bool selector_matched = false;
    Element* last_argument_checked_element = nullptr;
    int last_argument_checked_depth = -1;
    for (CheckPseudoHasArgumentTraversalIterator iterator(*has_anchor_element,
                                                          argument_context);
         !iterator.AtEnd(); ++iterator) {
      if (update_affected_by_has_flags) {
        SetAffectedByHasFlagsForElementAtDepth(argument_context,
                                               iterator.CurrentElement(),
                                               iterator.CurrentDepth());
      }

      if (SkipCheckingHasArgument(argument_context, iterator)) {
        continue;
      }

      sub_context.element = iterator.CurrentElement();
      HeapVector<Member<Element>> has_argument_leftmost_compound_matches;
      SubResult sub_result(result);
      sub_result.has_argument_leftmost_compound_matches =
          &has_argument_leftmost_compound_matches;

      MatchSelector(sub_context, sub_result);

      last_argument_checked_element = iterator.CurrentElement();
      last_argument_checked_depth = iterator.CurrentDepth();

      selector_matched = CacheMatchedElementsAndReturnMatchedResult(
          leftmost_relation, has_anchor_element,
          has_argument_leftmost_compound_matches, cache_scope_context);

      if (selector_matched) {
        break;
      }
    }

    if (cache_scope_context.CacheAllowed() && last_argument_checked_element) {
      cache_scope_context.SetAllTraversedElementsAsChecked(
          last_argument_checked_element, last_argument_checked_depth);
    }

    if (!selector_matched) {
      continue;
    }

    if (update_affected_by_has_flags) {
      SetAffectedByHasForArgumentMatchedElement(
          argument_context, has_anchor_element, last_argument_checked_element,
          last_argument_checked_depth);
    }
    return true;
  }
  return false;
}

bool SelectorChecker::CheckPseudoClass(const SelectorCheckingContext& context,
                                       MatchResult& result) const {
  Element& element =
      context.GetElementForMatching(result.pseudo_ancestor_index);
  const CSSSelector& selector = *context.selector;
  bool force_pseudo_state = false;

  if (context.has_scrollbar_pseudo) {
    // CSS scrollbars match a specific subset of pseudo classes, and they have
    // specialized rules for each
    // (since there are no elements involved).
    return CheckScrollbarPseudoClass(context, result);
  }

  switch (selector.GetPseudoType()) {
    case CSSSelector::kPseudoNot:
      return CheckPseudoNot(context, result);
    case CSSSelector::kPseudoEmpty: {
      bool is_empty = true;
      bool has_whitespace = false;
      for (Node* n = element.firstChild(); n; n = n->nextSibling()) {
        if (n->IsElementNode()) {
          is_empty = false;
          break;
        }
        if (auto* text_node = DynamicTo<Text>(n)) {
          if (!text_node->data().empty()) {
            if (text_node->ContainsOnlyWhitespaceOrEmpty()) {
              has_whitespace = true;
            } else {
              is_empty = false;
              break;
            }
          }
        }
      }
      if (is_empty && has_whitespace) {
        UseCounter::Count(context.element->GetDocument(),
                          WebFeature::kCSSSelectorEmptyWhitespaceOnlyFail);
        is_empty = false;
      }
      if (mode_ == kResolvingStyle) {
        element.SetStyleAffectedByEmpty();
      }
      return is_empty;
    }
    case CSSSelector::kPseudoFirstChild:
      if (mode_ == kResolvingStyle) {
        if (ContainerNode* parent = element.ParentElementOrDocumentFragment()) {
          parent->SetChildrenAffectedByFirstChildRules();
        }
        element.SetAffectedByFirstChildRules();
      }
      return IsFirstChild(element);
    case CSSSelector::kPseudoFirstOfType:
      if (mode_ == kResolvingStyle) {
        if (ContainerNode* parent = element.ParentElementOrDocumentFragment()) {
          parent->SetChildrenAffectedByForwardPositionalRules();
        }
      }
      return IsFirstOfType(element, element.TagQName());
    case CSSSelector::kPseudoLastChild: {
      ContainerNode* parent = element.ParentElementOrDocumentFragment();
      if (mode_ == kResolvingStyle) {
        if (parent) {
          parent->SetChildrenAffectedByLastChildRules();
        }
        element.SetAffectedByLastChildRules();
      }
      if (mode_ != kQueryingRules && parent &&
          !parent->IsFinishedParsingChildren()) {
        return false;
      }
      return IsLastChild(element);
    }
    case CSSSelector::kPseudoLastOfType: {
      ContainerNode* parent = element.ParentElementOrDocumentFragment();
      if (mode_ == kResolvingStyle) {
        if (parent) {
          parent->SetChildrenAffectedByBackwardPositionalRules();
        }
      }
      if (mode_ != kQueryingRules && parent &&
          !parent->IsFinishedParsingChildren()) {
        return false;
      }
      return IsLastOfType(element, element.TagQName());
    }
    case CSSSelector::kPseudoOnlyChild: {
      if (IsTransitionPseudoElement(context.pseudo_id)) {
        DCHECK(element.IsDocumentElement());
        DCHECK(context.pseudo_argument);

        auto* transition =
            ViewTransitionUtils::GetTransition(element.GetDocument());
        DCHECK(transition);
        return transition->MatchForOnlyChild(context.pseudo_id,
                                             *context.pseudo_argument);
      }

      ContainerNode* parent = element.ParentElementOrDocumentFragment();
      if (mode_ == kResolvingStyle) {
        if (parent) {
          parent->SetChildrenAffectedByFirstChildRules();
          parent->SetChildrenAffectedByLastChildRules();
        }
        element.SetAffectedByFirstChildRules();
        element.SetAffectedByLastChildRules();
      }
      if (mode_ != kQueryingRules && parent &&
          !parent->IsFinishedParsingChildren()) {
        return false;
      }
      return IsFirstChild(element) && IsLastChild(element);
    }
    case CSSSelector::kPseudoOnlyOfType: {
      // FIXME: This selector is very slow.
      ContainerNode* parent = element.ParentElementOrDocumentFragment();
      if (mode_ == kResolvingStyle && parent) {
        parent->SetChildrenAffectedByForwardPositionalRules();
        par
"""


```