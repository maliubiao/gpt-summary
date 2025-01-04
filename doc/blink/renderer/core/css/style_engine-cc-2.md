Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `style_engine.cc`. This is part 3 of a 6-part series, implying there are other related code snippets.

Here's a breakdown of how to address the request:

1. **Identify Core Functionality:** Read through the code and identify the main actions being performed. Look for function names and their purpose. The prominent functions seem to be related to invalidating styles based on various changes (attributes, pseudo-states, DOM mutations, etc.).

2. **Relate to Web Technologies (JavaScript, HTML, CSS):**  Consider how the code interacts with the core web technologies.
    * **CSS:** The code heavily deals with CSS selectors, pseudo-classes, and the application of styles.
    * **HTML:** The code operates on `Element` objects, interacts with attributes, and responds to changes in the DOM structure (insertion/removal).
    * **JavaScript:** While not directly apparent in this snippet, style changes often originate from JavaScript interactions. The code prepares the rendering engine to reflect those changes.

3. **Look for Logical Reasoning:** Identify any conditional logic or specific algorithms being used. The code uses `if` statements to determine when invalidations are needed based on various factors.

4. **Identify Potential User/Programming Errors:** Think about common mistakes developers might make that could lead to this code being executed. For example, manipulating attributes or classes via JavaScript can trigger style recalculations.

5. **Trace User Operations:**  Imagine the sequence of user actions that could lead to this code being invoked. Interacting with the webpage, causing changes in the DOM or CSS properties, are key triggers.

6. **Context from "Part 3 of 6":**  Recognize that this is a segment of a larger file. The functionality here likely focuses on *invalidation*, meaning marking elements that need their styles recalculated. Other parts of the file likely handle the actual style calculation.

7. **Synthesize a Summary:**  Combine the identified functionalities into a concise summary that addresses the user's request.
```
归纳一下它的功能
```

这个代码片段主要负责处理由于以下元素变化而触发的样式失效逻辑：

* **ID 属性变化:** 当元素的 `id` 属性发生改变时，会根据 CSS 规则的定义来决定哪些元素需要重新计算样式。
* **伪类状态变化:** 当元素的伪类状态（例如 `:hover`, `:focus`）发生改变时，会根据 CSS 规则的定义来决定哪些元素需要重新计算样式。
* **`part` 属性变化:** 当元素的 `part` 属性发生改变时，会标记该元素需要重新计算样式。
* **`exportparts` 属性变化:** 当元素的 `exportparts` 属性发生改变时，会触发相关元素的样式失效。
* **兄弟节点插入/删除:** 当有兄弟节点插入或删除时，会根据 CSS 相邻选择器规则来决定哪些兄弟节点需要重新计算样式。
* **`:nth-*` 伪类相关的父节点:** 当与 `:nth-*` 伪类相关的父节点发生变化时，会触发其子节点的样式失效。

**核心功能可以归纳为：当元素或其相关的节点的状态发生变化时，根据 CSS 规则的失效策略，精确地标记出需要重新计算样式的元素，从而避免不必要的全局样式重算，提高渲染性能。**

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML:**
    * **假设输入:** 一个 `div` 元素的 `id` 属性从 `"old-id"` 变为 `"new-id"`。
    * **输出:** 代码会查找 CSS 规则中是否有针对 `#old-id` 或 `#new-id` 的选择器，并根据这些规则影响的元素进行样式失效标记。
* **CSS:**
    * **假设输入:**  CSS 规则中存在 `.active:hover { ... }` 这样的规则，并且一个具有 `active` class 的元素进入了 hover 状态。
    * **输出:** `PseudoStateChangedForElement` 函数会被调用，并根据 `:hover` 伪类相关的失效策略，标记该元素需要重新计算样式。
* **JavaScript:**
    * **用户操作:** 用户点击一个按钮，JavaScript 代码修改了该按钮的 `class` 属性，添加了 `:active` 伪类对应的样式。
    * **调试线索:**
        1. 用户点击按钮。
        2. JavaScript 代码执行，修改元素的 `class` 属性。
        3. Blink 引擎监听到属性变化，调用 `AttributeChangedForElement` 函数。
        4. `AttributeChangedForElement` 函数判断是 `class` 属性的修改。
        5. 代码会检查是否有与新的 `class` 值相关的 CSS 规则需要触发样式失效。

**逻辑推理的假设输入与输出:**

* **假设输入:** 一个 CSS 规则为 `.parent > .child:first-child { ... }`，现在向 `.parent` 中插入一个新的子元素在原有的 `.child` 前面。
* **输出:** `ScheduleInvalidationsForInsertedSibling` 函数会被调用。由于插入操作改变了子元素的顺序，原先的 `:first-child` 元素不再是第一个子元素，因此该元素的样式需要重新计算。代码会标记该元素为需要样式重算。

**涉及用户或者编程常见的使用错误举例说明:**

* **错误:** 频繁地使用 JavaScript 修改元素的 `id` 或 `class` 属性，或者频繁地添加/移除 DOM 节点，可能会导致大量的样式失效和重算，影响页面性能。
* **调试:** 如果发现页面性能有问题，可以使用 Chrome DevTools 的 Performance 面板来分析渲染过程，查看是否有大量的样式计算（Recalculate Style）操作。如果发现某个特定的 JavaScript 操作触发了大量的样式重算，可以考虑优化 JavaScript 代码，例如批量更新 DOM 或使用更高效的 CSS 选择器。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户交互:** 用户在网页上进行操作，例如鼠标悬停在一个元素上、点击一个按钮、输入文本等。
2. **DOM 变化或状态改变:** 用户的交互可能导致 DOM 结构发生变化（例如插入、删除节点），或者元素的状态发生改变（例如伪类状态改变、属性值改变）。
3. **Blink 引擎监听事件:** Blink 引擎会监听这些 DOM 变化和状态改变的事件。
4. **触发相应的 StyleEngine 方法:** 当相关的事件发生时，Blink 引擎会调用 `StyleEngine` 中相应的方法，例如：
    * `AttributeChangedForElement`: 当元素属性发生变化时调用。
    * `PseudoStateChangedForElement`: 当元素伪类状态发生变化时调用。
    * `ScheduleInvalidationsForInsertedSibling`/`ScheduleInvalidationsForRemovedSibling`: 当 DOM 节点插入或删除时调用。
5. **执行失效逻辑:** 这些方法会根据 CSS 规则的失效策略，标记需要重新计算样式的元素。

**总结本代码片段的功能:**

这个代码片段是 Chromium Blink 引擎中 `StyleEngine` 的一部分，专门负责处理各种元素状态变化引起的 CSS 样式失效。它的核心目标是精确地找出受影响的元素，并标记它们需要重新计算样式，从而优化渲染性能。它通过分析 CSS 规则和 DOM 结构，对不同类型的变化采取不同的失效策略，避免了全局的样式重算。

Prompt: 
```
这是目录为blink/renderer/core/css/style_engine.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能

"""
ion_data.NeedsHasInvalidationForId(new_id))) {
      InvalidateChangedElementAffectedByLogicalCombinationsInHas(
          element, /* for_element_affected_by_pseudo_in_has */ false);
      InvalidateAncestorsOrSiblingsAffectedByHas(
          PseudoHasInvalidationTraversalContext::
              ForAttributeOrPseudoStateChange(element));
    }
  }

  if (IsSubtreeAndSiblingsStyleDirty(element)) {
    return;
  }

  InvalidationLists invalidation_lists;
  if (!old_id.empty()) {
    rule_invalidation_data.CollectInvalidationSetsForId(invalidation_lists,
                                                        element, old_id);
  }
  if (!new_id.empty()) {
    rule_invalidation_data.CollectInvalidationSetsForId(invalidation_lists,
                                                        element, new_id);
  }
  pending_invalidations_.ScheduleInvalidationSetsForNode(invalidation_lists,
                                                         element);
}

void StyleEngine::PseudoStateChangedForElement(
    CSSSelector::PseudoType pseudo_type,
    Element& element,
    bool invalidate_descendants_or_siblings,
    bool invalidate_ancestors_or_siblings) {
  DCHECK(invalidate_descendants_or_siblings ||
         invalidate_ancestors_or_siblings);

  if (ShouldSkipInvalidationFor(element)) {
    return;
  }

  const RuleInvalidationData& rule_invalidation_data =
      GetRuleFeatureSet().GetRuleInvalidationData();

  if (invalidate_ancestors_or_siblings &&
      rule_invalidation_data.NeedsHasInvalidationForPseudoStateChange() &&
      PossiblyAffectingHasState(element)) {
    if (rule_invalidation_data.NeedsHasInvalidationForPseudoClass(
            pseudo_type)) {
      InvalidateChangedElementAffectedByLogicalCombinationsInHas(
          element, /* for_element_affected_by_pseudo_in_has */ true);
      InvalidateAncestorsOrSiblingsAffectedByHas(
          PseudoHasInvalidationTraversalContext::
              ForAttributeOrPseudoStateChange(element)
                  .SetForElementAffectedByPseudoInHas());
    }
  }

  if (!invalidate_descendants_or_siblings ||
      IsSubtreeAndSiblingsStyleDirty(element)) {
    return;
  }

  InvalidationLists invalidation_lists;
  rule_invalidation_data.CollectInvalidationSetsForPseudoClass(
      invalidation_lists, element, pseudo_type);
  pending_invalidations_.ScheduleInvalidationSetsForNode(invalidation_lists,
                                                         element);
}

void StyleEngine::PartChangedForElement(Element& element) {
  if (ShouldSkipInvalidationFor(element)) {
    return;
  }
  if (IsSubtreeAndSiblingsStyleDirty(element)) {
    return;
  }
  if (element.GetTreeScope() == document_) {
    return;
  }
  if (!GetRuleFeatureSet().GetRuleInvalidationData().InvalidatesParts()) {
    return;
  }
  element.SetNeedsStyleRecalc(
      kLocalStyleChange,
      StyleChangeReasonForTracing::FromAttribute(html_names::kPartAttr));
}

void StyleEngine::ExportpartsChangedForElement(Element& element) {
  if (ShouldSkipInvalidationFor(element)) {
    return;
  }
  if (IsSubtreeAndSiblingsStyleDirty(element)) {
    return;
  }
  if (!element.GetShadowRoot()) {
    return;
  }

  InvalidationLists invalidation_lists;
  GetRuleFeatureSet().GetRuleInvalidationData().CollectPartInvalidationSet(
      invalidation_lists);
  pending_invalidations_.ScheduleInvalidationSetsForNode(invalidation_lists,
                                                         element);
}

void StyleEngine::ScheduleSiblingInvalidationsForElement(
    Element& element,
    ContainerNode& scheduling_parent,
    unsigned min_direct_adjacent) {
  DCHECK(min_direct_adjacent);

  InvalidationLists invalidation_lists;

  const RuleInvalidationData& rule_invalidation_data =
      GetRuleFeatureSet().GetRuleInvalidationData();

  if (element.HasID()) {
    rule_invalidation_data.CollectSiblingInvalidationSetForId(
        invalidation_lists, element, element.IdForStyleResolution(),
        min_direct_adjacent);
  }

  if (element.HasClass()) {
    const SpaceSplitString& class_names = element.ClassNames();
    for (const AtomicString& class_name : class_names) {
      rule_invalidation_data.CollectSiblingInvalidationSetForClass(
          invalidation_lists, element, class_name, min_direct_adjacent);
    }
  }

  for (const Attribute& attribute : element.Attributes()) {
    rule_invalidation_data.CollectSiblingInvalidationSetForAttribute(
        invalidation_lists, element, attribute.GetName(), min_direct_adjacent);
  }

  rule_invalidation_data.CollectUniversalSiblingInvalidationSet(
      invalidation_lists, min_direct_adjacent);

  pending_invalidations_.ScheduleSiblingInvalidationsAsDescendants(
      invalidation_lists, scheduling_parent);
}

void StyleEngine::ScheduleInvalidationsForInsertedSibling(
    Element* before_element,
    Element& inserted_element) {
  unsigned affected_siblings =
      inserted_element.parentNode()->ChildrenAffectedByIndirectAdjacentRules()
          ? SiblingInvalidationSet::kDirectAdjacentMax
          : MaxDirectAdjacentSelectors();

  ContainerNode* scheduling_parent =
      inserted_element.ParentElementOrShadowRoot();
  if (!scheduling_parent) {
    return;
  }

  ScheduleSiblingInvalidationsForElement(inserted_element, *scheduling_parent,
                                         1);

  for (unsigned i = 1; before_element && i <= affected_siblings;
       i++, before_element =
                ElementTraversal::PreviousSibling(*before_element)) {
    ScheduleSiblingInvalidationsForElement(*before_element, *scheduling_parent,
                                           i);
  }
}

void StyleEngine::ScheduleInvalidationsForRemovedSibling(
    Element* before_element,
    Element& removed_element,
    Element& after_element) {
  unsigned affected_siblings =
      after_element.parentNode()->ChildrenAffectedByIndirectAdjacentRules()
          ? SiblingInvalidationSet::kDirectAdjacentMax
          : MaxDirectAdjacentSelectors();

  ContainerNode* scheduling_parent = after_element.ParentElementOrShadowRoot();
  if (!scheduling_parent) {
    return;
  }

  ScheduleSiblingInvalidationsForElement(removed_element, *scheduling_parent,
                                         1);

  for (unsigned i = 1; before_element && i <= affected_siblings;
       i++, before_element =
                ElementTraversal::PreviousSibling(*before_element)) {
    ScheduleSiblingInvalidationsForElement(*before_element, *scheduling_parent,
                                           i);
  }
}

void StyleEngine::ScheduleNthPseudoInvalidations(ContainerNode& nth_parent) {
  InvalidationLists invalidation_lists;
  GetRuleFeatureSet().GetRuleInvalidationData().CollectNthInvalidationSet(
      invalidation_lists);
  pending_invalidations_.ScheduleInvalidationSetsForNode(invalidation_lists,
                                                         nth_parent);
}

// Inserting/changing some types of rules cause invalidation even if they don't
// match, because the very act of evaluating them has side effects for the
// ComputedStyle. For instance, evaluating a rule with :hover will set the
// AffectedByHover() flag on ComputedStyle even if it matches (for
// invalidation). So we need to test for that here, and invalidate the element
// so that such rules are properly evaluated.
//
// We don't need to care specifically about @starting-style, but all other flags
// should probably be covered here.
static bool FlagsCauseInvalidation(const MatchResult& result) {
  return result.HasFlag(MatchFlag::kAffectedByDrag) ||
         result.HasFlag(MatchFlag::kAffectedByFocusWithin) ||
         result.HasFlag(MatchFlag::kAffectedByHover) ||
         result.HasFlag(MatchFlag::kAffectedByActive);
}

static bool AnyRuleCausesInvalidation(const MatchRequest& match_request,
                                      ElementRuleCollector& collector,
                                      bool is_shadow_host) {
  if (collector.CheckIfAnyRuleMatches(match_request) ||
      FlagsCauseInvalidation(collector.MatchedResult())) {
    return true;
  }
  if (is_shadow_host) {
    if (collector.CheckIfAnyShadowHostRuleMatches(match_request) ||
        FlagsCauseInvalidation(collector.MatchedResult())) {
      return true;
    }
  }
  return false;
}

namespace {

bool CanRejectRuleSet(ElementRuleCollector& collector,
                      const RuleSet& rule_set) {
  const StyleScope* scope = rule_set.SingleScope();
  return scope && collector.CanRejectScope(*scope);
}

}  // namespace

// See if a given element needs to be recalculated after RuleSet changes
// (see ApplyRuleSetInvalidation()).
void StyleEngine::ApplyRuleSetInvalidationForElement(
    const TreeScope& tree_scope,
    Element& element,
    SelectorFilter& selector_filter,
    StyleScopeFrame& style_scope_frame,
    const HeapHashSet<Member<RuleSet>>& rule_sets,
    unsigned changed_rule_flags,
    bool is_shadow_host) {
  if ((changed_rule_flags & kFunctionRules) && element.GetComputedStyle() &&
      element.GetComputedStyle()->AffectedByCSSFunction()) {
    // If @function rules have changed, and the style is (was) using a function,
    // we invalidate it unconditionally. We currently do not attempt
    // finer-grained invalidation, since it would also require tracking which
    // functions call other functions on some level.
    element.SetNeedsStyleRecalc(kLocalStyleChange,
                                StyleChangeReasonForTracing::Create(
                                    style_change_reason::kFunctionRuleChange));
    return;
  }
  ElementResolveContext element_resolve_context(element);
  MatchResult match_result;
  EInsideLink inside_link =
      EInsideLink::kNotInsideLink;  // Only used for MatchedProperties, so does
                                    // not matter for us.
  StyleRecalcContext style_recalc_context =
      StyleRecalcContext::FromAncestors(element);
  style_recalc_context.style_scope_frame = &style_scope_frame;
  ElementRuleCollector collector(element_resolve_context, style_recalc_context,
                                 selector_filter, match_result, inside_link);

  MatchRequest match_request{&tree_scope.RootNode()};
  bool matched_any = false;
  for (const Member<RuleSet>& rule_set : rule_sets) {
    if (CanRejectRuleSet(collector, *rule_set)) {
      continue;
    }
    match_request.AddRuleset(rule_set.Get());
    if (match_request.IsFull()) {
      if (AnyRuleCausesInvalidation(match_request, collector, is_shadow_host)) {
        matched_any = true;
        break;
      }
      match_request.ClearAfterMatching();
    }
  }
  if (!match_request.IsEmpty() && !matched_any) {
    matched_any =
        AnyRuleCausesInvalidation(match_request, collector, is_shadow_host);
  }
  if (matched_any) {
    element.SetNeedsStyleRecalc(kLocalStyleChange,
                                StyleChangeReasonForTracing::Create(
                                    style_change_reason::kStyleRuleChange));
  }
}

void StyleEngine::ScheduleCustomElementInvalidations(
    HashSet<AtomicString> tag_names) {
  scoped_refptr<DescendantInvalidationSet> invalidation_set =
      DescendantInvalidationSet::Create();
  for (auto& tag_name : tag_names) {
    invalidation_set->AddTagName(tag_name);
  }
  invalidation_set->SetTreeBoundaryCrossing();
  InvalidationLists invalidation_lists;
  invalidation_lists.descendants.push_back(invalidation_set);
  pending_invalidations_.ScheduleInvalidationSetsForNode(invalidation_lists,
                                                         *document_);
}

void StyleEngine::ScheduleInvalidationsForHasPseudoAffectedByInsertionOrRemoval(
    ContainerNode* parent,
    Node* node_before_change,
    Element& changed_element,
    bool removal) {
  Element* parent_or_shadow_host = nullptr;
  bool insert_or_remove_shadow_root_child = false;
  if (Element* element = DynamicTo<Element>(parent)) {
    parent_or_shadow_host = element;
  } else if (ShadowRoot* shadow_root = DynamicTo<ShadowRoot>(parent)) {
    parent_or_shadow_host = &shadow_root->host();
    insert_or_remove_shadow_root_child = true;
  }

  if (!parent_or_shadow_host) {
    return;
  }

  if (ShouldSkipInvalidationFor(*parent_or_shadow_host)) {
    return;
  }

  if (!GetRuleFeatureSet()
           .GetRuleInvalidationData()
           .NeedsHasInvalidationForInsertionOrRemoval()) {
    return;
  }

  Element* previous_sibling = SelfOrPreviousSibling(node_before_change);

  if (removal) {
    ScheduleInvalidationsForHasPseudoAffectedByRemoval(
        parent_or_shadow_host, previous_sibling, changed_element,
        insert_or_remove_shadow_root_child);
  } else {
    ScheduleInvalidationsForHasPseudoAffectedByInsertion(
        parent_or_shadow_host, previous_sibling, changed_element,
        insert_or_remove_shadow_root_child);
  }
}

void StyleEngine::ScheduleInvalidationsForHasPseudoAffectedByInsertion(
    Element* parent_or_shadow_host,
    Element* previous_sibling,
    Element& inserted_element,
    bool insert_shadow_root_child) {
  bool possibly_affecting_has_state = false;
  bool descendants_possibly_affecting_has_state = false;

  if (InsertionOrRemovalPossiblyAffectHasStateOfPreviousSiblings(
          previous_sibling)) {
    inserted_element.SetSiblingsAffectedByHasFlags(
        previous_sibling->GetSiblingsAffectedByHasFlags());
    possibly_affecting_has_state = true;
    descendants_possibly_affecting_has_state =
        inserted_element.HasSiblingsAffectedByHasFlags(
            SiblingsAffectedByHasFlags::kFlagForSiblingDescendantRelationship);
  }
  if (InsertionOrRemovalPossiblyAffectHasStateOfAncestorsOrAncestorSiblings(
          parent_or_shadow_host)) {
    inserted_element.SetAncestorsOrAncestorSiblingsAffectedByHas();
    possibly_affecting_has_state = true;
    descendants_possibly_affecting_has_state = true;
  }

  if (!possibly_affecting_has_state) {
    return;  // Inserted subtree will not affect :has() state
  }

  const RuleInvalidationData& rule_invalidation_data =
      GetRuleFeatureSet().GetRuleInvalidationData();

  // Always schedule :has() invalidation if the inserted element may affect
  // a match result of a compound after direct adjacent combinator by changing
  // sibling order. (e.g. When we have a style rule '.a:has(+ .b) {}', we always
  // need :has() invalidation if any element is inserted before '.b')
  bool needs_has_invalidation_for_inserted_subtree =
      parent_or_shadow_host->ChildrenAffectedByDirectAdjacentRules();

  if (!needs_has_invalidation_for_inserted_subtree &&
      rule_invalidation_data.NeedsHasInvalidationForInsertedOrRemovedElement(
          inserted_element)) {
    needs_has_invalidation_for_inserted_subtree = true;
  }

  if (descendants_possibly_affecting_has_state) {
    // Do not stop subtree traversal early so that all the descendants have the
    // AncestorsOrAncestorSiblingsAffectedByHas flag set.
    for (Element& element : ElementTraversal::DescendantsOf(inserted_element)) {
      element.SetAncestorsOrAncestorSiblingsAffectedByHas();
      if (!needs_has_invalidation_for_inserted_subtree &&
          rule_invalidation_data
              .NeedsHasInvalidationForInsertedOrRemovedElement(element)) {
        needs_has_invalidation_for_inserted_subtree = true;
      }
    }
  }

  if (needs_has_invalidation_for_inserted_subtree) {
    InvalidateAncestorsOrSiblingsAffectedByHas(
        PseudoHasInvalidationTraversalContext::ForInsertion(
            parent_or_shadow_host, insert_shadow_root_child, previous_sibling));
    return;
  }

  if (rule_invalidation_data.NeedsHasInvalidationForPseudoStateChange()) {
    InvalidateAncestorsOrSiblingsAffectedByHas(
        PseudoHasInvalidationTraversalContext::ForInsertion(
            parent_or_shadow_host, insert_shadow_root_child, previous_sibling)
            .SetForElementAffectedByPseudoInHas());
  }
}

void StyleEngine::ScheduleInvalidationsForHasPseudoAffectedByRemoval(
    Element* parent_or_shadow_host,
    Element* previous_sibling,
    Element& removed_element,
    bool remove_shadow_root_child) {
  if (!InsertionOrRemovalPossiblyAffectHasStateOfAncestorsOrAncestorSiblings(
          parent_or_shadow_host) &&
      !InsertionOrRemovalPossiblyAffectHasStateOfPreviousSiblings(
          previous_sibling)) {
    // Removed element will not affect :has() state
    return;
  }

  // Always schedule :has() invalidation if the removed element may affect
  // a match result of a compound after direct adjacent combinator by changing
  // sibling order. (e.g. When we have a style rule '.a:has(+ .b) {}', we always
  // need :has() invalidation if the preceding element of '.b' is removed)
  if (parent_or_shadow_host->ChildrenAffectedByDirectAdjacentRules()) {
    InvalidateAncestorsOrSiblingsAffectedByHas(
        PseudoHasInvalidationTraversalContext::ForRemoval(
            parent_or_shadow_host, remove_shadow_root_child, previous_sibling,
            removed_element));
    return;
  }

  const RuleInvalidationData& rule_invalidation_data =
      GetRuleFeatureSet().GetRuleInvalidationData();

  for (Element& element :
       ElementTraversal::InclusiveDescendantsOf(removed_element)) {
    if (rule_invalidation_data.NeedsHasInvalidationForInsertedOrRemovedElement(
            element)) {
      InvalidateAncestorsOrSiblingsAffectedByHas(
          PseudoHasInvalidationTraversalContext::ForRemoval(
              parent_or_shadow_host, remove_shadow_root_child, previous_sibling,
              removed_element));
      return;
    }
  }

  if (rule_invalidation_data.NeedsHasInvalidationForPseudoStateChange()) {
    InvalidateAncestorsOrSiblingsAffectedByHas(
        PseudoHasInvalidationTraversalContext::ForRemoval(
            parent_or_shadow_host, remove_shadow_root_child, previous_sibling,
            removed_element)
            .SetForElementAffectedByPseudoInHas());
  }
}

void StyleEngine::ScheduleInvalidationsForHasPseudoWhenAllChildrenRemoved(
    Element& parent) {
  if (ShouldSkipInvalidationFor(parent)) {
    return;
  }

  const RuleInvalidationData& rule_invalidation_data =
      GetRuleFeatureSet().GetRuleInvalidationData();
  if (!rule_invalidation_data.NeedsHasInvalidationForInsertionOrRemoval()) {
    return;
  }

  if (!InsertionOrRemovalPossiblyAffectHasStateOfAncestorsOrAncestorSiblings(
          &parent)) {
    // Removed children will not affect :has() state
    return;
  }

  // Always invalidate elements possibly affected by the removed children.
  InvalidateAncestorsOrSiblingsAffectedByHas(
      PseudoHasInvalidationTraversalContext::ForAllChildrenRemoved(parent));
}

void StyleEngine::InvalidateStyle() {
  StyleInvalidator style_invalidator(
      pending_invalidations_.GetPendingInvalidationMap());
  style_invalidator.Invalidate(GetDocument(),
                               style_invalidation_root_.RootElement());
  style_invalidation_root_.Clear();
}

void StyleEngine::InvalidateSlottedElements(
    HTMLSlotElement& slot,
    const StyleChangeReasonForTracing& reason) {
  for (auto& node : slot.FlattenedAssignedNodes()) {
    if (node->IsElementNode()) {
      node->SetNeedsStyleRecalc(kLocalStyleChange, reason);
    }
  }
}

bool StyleEngine::HasViewportDependentPropertyRegistrations() {
  UpdateActiveStyle();
  const PropertyRegistry* registry = GetDocument().GetPropertyRegistry();
  return registry && registry->GetViewportUnitFlags();
}

// Given a list of RuleSets that have changed (both old and new), see what
// elements in the given TreeScope that could be affected by them and need
// style recalculation.
//
// This generally works by our regular selector matching; if any selector
// in any of the given RuleSets match, it means we need to mark the element
// for style recalc. This could either be because the element is affected
// by a rule where it wasn't before, or because the element used to be
// affected by some rule and isn't anymore, or even that the rule itself
// changed. (It could also be a false positive, e.g. because someone added
// a single new rule to a style sheet, causing a new RuleSet to be created
// that also contains all the old rules, and the element matches one of them.)
//
// There are some twists to this; e.g., for a rule like a:hover, we will need
// to invalidate all <a> elements whether they are currently matching :hover
// or not (see FlagsCauseInvalidation()).
//
// In general, we check all elements in this TreeScope and nothing else.
// There are some exceptions (in both directions); in particular, if an element
// is already marked for subtree recalc, we don't need to go below it. Also,
// if invalidation_scope says so, or if we have rules pertaining to UA shadows,
// we may need to descend into child TreeScopes.
void StyleEngine::ApplyRuleSetInvalidationForTreeScope(
    TreeScope& tree_scope,
    ContainerNode& node,
    SelectorFilter& selector_filter,
    StyleScopeFrame& style_scope_frame,
    const HeapHashSet<Member<RuleSet>>& rule_sets,
    unsigned changed_rule_flags,
    InvalidationScope invalidation_scope) {
  TRACE_EVENT0("blink,blink_style",
               "StyleEngine::scheduleInvalidationsForRuleSets");

  bool invalidate_slotted = false;
  bool invalidate_part = false;
  if (auto* shadow_root = DynamicTo<ShadowRoot>(&node)) {
    Element& host = shadow_root->host();
    // The SelectorFilter stack is set up for invalidating the tree
    // under the host, which includes the host. When invalidating the
    // host itself, we need to take it out so that the stack is consistent.
    selector_filter.PopParent(host);
    ApplyRuleSetInvalidationForElement(tree_scope, host, selector_filter,
                                       style_scope_frame, rule_sets,
                                       changed_rule_flags,
                                       /*is_shadow_host=*/true);
    selector_filter.PushParent(host);
    if (host.GetStyleChangeType() == kSubtreeStyleChange) {
      return;
    }
    for (auto rule_set : rule_sets) {
      if (rule_set->HasSlottedRules()) {
        invalidate_slotted = true;
        break;
      }
      if (rule_set->HasPartPseudoRules()) {
        invalidate_part = true;
        break;
      }
    }
  }

  // If there are any rules that cover UA pseudos, we need to descend into
  // UA shadows so that we can invalidate them. This is pretty crude
  // (it descends into all shadows), but such rules are fairly rare anyway.
  //
  // We do a similar thing for :part(), descending into all shadows.
  if (invalidation_scope != kInvalidateAllScopes) {
    for (auto rule_set : rule_sets) {
      if (rule_set->HasUAShadowPseudoElementRules() ||
          rule_set->HasPartPseudoRules()) {
        invalidation_scope = kInvalidateAllScopes;
        break;
      }
    }
  }

  // Note that there is no need to meddle with the SelectorFilter
  // or StyleScopeFrame here: the caller should already have set up
  // the required state for `node` in both cases.
  for (Element& child : ElementTraversal::ChildrenOf(node)) {
    ApplyRuleSetInvalidationForSubtree(
        tree_scope, child, selector_filter,
        /* parent_style_scope_frame */ style_scope_frame, rule_sets,
        changed_rule_flags, invalidation_scope, invalidate_slotted,
        invalidate_part);
  }
}

void StyleEngine::ApplyRuleSetInvalidationForSubtree(
    TreeScope& tree_scope,
    Element& element,
    SelectorFilter& selector_filter,
    StyleScopeFrame& parent_style_scope_frame,
    const HeapHashSet<Member<RuleSet>>& rule_sets,
    unsigned changed_rule_flags,
    InvalidationScope invalidation_scope,
    bool invalidate_slotted,
    bool invalidate_part) {
  StyleScopeFrame style_scope_frame(element, &parent_style_scope_frame);

  if (invalidate_part && element.hasAttribute(html_names::kPartAttr)) {
    // It's too complicated to try to handle ::part() precisely.
    // If we have any ::part() rules, and the element has a [part]
    // attribute, just invalidate it.
    element.SetNeedsStyleRecalc(kLocalStyleChange,
                                StyleChangeReasonForTracing::Create(
                                    style_change_reason::kStyleRuleChange));
  } else {
    ApplyRuleSetInvalidationForElement(tree_scope, element, selector_filter,
                                       style_scope_frame, rule_sets,
                                       changed_rule_flags,
                                       /*is_shadow_host=*/false);
  }

  auto* html_slot_element = DynamicTo<HTMLSlotElement>(element);
  if (html_slot_element && invalidate_slotted) {
    InvalidateSlottedElements(*html_slot_element,
                              StyleChangeReasonForTracing::Create(
                                  style_change_reason::kStyleRuleChange));
  }

  if (invalidation_scope == kInvalidateAllScopes) {
    if (ShadowRoot* shadow_root = element.GetShadowRoot()) {
      selector_filter.PushParent(element);
      ApplyRuleSetInvalidationForTreeScope(tree_scope, shadow_root->RootNode(),
                                           selector_filter, style_scope_frame,
                                           rule_sets, kInvalidateAllScopes);
      selector_filter.PopParent(element);
    }
  }

  // Skip traversal of the subtree if we're going to update the entire subtree
  // anyway.
  const bool traverse_children =
      (element.GetStyleChangeType() < kSubtreeStyleChange &&
       element.GetComputedStyle());

  if (traverse_children) {
    selector_filter.PushParent(element);

    for (Element& child : ElementTraversal::ChildrenOf(element)) {
      ApplyRuleSetInvalidationForSubtree(
          tree_scope, child, selector_filter,
          /* parent_style_scope_frame */ style_scope_frame, rule_sets,
          changed_rule_flags, invalidation_scope, invalidate_slotted,
          invalidate_part);
    }

    selector_filter.PopParent(element);
  }
}

void StyleEngine::SetStatsEnabled(bool enabled) {
  if (!enabled) {
    style_resolver_stats_ = nullptr;
    return;
  }
  if (!style_resolver_stats_) {
    style_resolver_stats_ = std::make_unique<StyleResolverStats>();
  } else {
    style_resolver_stats_->Reset();
  }
}

void StyleEngine::SetPreferredStylesheetSetNameIfNotSet(const String& name) {
  DCHECK(!name.empty());
  if (!preferred_stylesheet_set_name_.empty()) {
    return;
  }
  preferred_stylesheet_set_name_ = name;
  MarkDocumentDirty();
}

void StyleEngine::SetHttpDefaultStyle(const String& content) {
  if (!content.empty()) {
    SetPreferredStylesheetSetNameIfNotSet(content);
  }
}

void StyleEngine::CollectFeaturesTo(RuleFeatureSet& features) {
  CollectUserStyleFeaturesTo(features);
  CollectScopedStyleFeaturesTo(features);
}

void StyleEngine::EnsureUAStyleForFullscreen(const Element& element) {
  DCHECK(global_rule_set_);
  if (global_rule_set_->HasFullscreenUAStyle()) {
    return;
  }
  CSSDefaultStyleSheets::Instance().EnsureDefaultStyleSheetForFullscreen(
      element);
  global_rule_set_->MarkDirty();
  UpdateActiveStyle();
}

void StyleEngine::EnsureUAStyleForElement(const Element& element) {
  DCHECK(global_rule_set_);
  if (CSSDefaultStyleSheets::Instance().EnsureDefaultStyleSheetsForElement(
          element)) {
    global_rule_set_->MarkDirty();
    UpdateActiveStyle();
  }
}

void StyleEngine::EnsureUAStyleForPseudoElement(PseudoId pseudo_id) {
  DCHECK(global_rule_set_);

  if (CSSDefaultStyleSheets::Instance()
          .EnsureDefaultStyleSheetsForPseudoElement(pseudo_id)) {
    global_rule_set_->MarkDirty();
    UpdateActiveStyle();
  }
}

void StyleEngine::EnsureUAStyleForForcedColors() {
  DCHECK(global_rule_set_);
  if (CSSDefaultStyleSheets::Instance()
          .EnsureDefaultStyleSheetForForcedColors()) {
    global_rule_set_->MarkDirty();
    if (GetDocument().IsActive()) {
      UpdateActiveStyle();
    }
  }
}

RuleSet* StyleEngine::DefaultViewTransitionStyle() const {
  auto* transition = ViewTransitionUtils::GetTransition(GetDocument());
  if (!transition) {
    return nullptr;
  }

  auto* css_style_sheet = transition->UAStyleSheet();
  return &css_style_sheet->Contents()->EnsureRuleSet(
      CSSDefaultStyleSheets::ScreenEval());
}

void StyleEngine::UpdateViewTransitionOptIn() {
  bool cross_document_enabled = false;

  // TODO(https://crbug.com/1463966): This will likely need to change to a
  // CSSValueList if we want to support multiple tokens as a trigger.
  Vector<String> types;
  if (view_transition_rule_) {
    types = view_transition_rule_->GetTypes();
    if (const CSSValue* value = view_transition_rule_->GetNavigation()) {
      cross_document_enabled =
          To<CSSIdentifierValue>(value)->GetValueID() == CSSValueID::kAuto;
    }
  }

  ViewTransitionSupplement::From(GetDocument())
      ->OnViewTransitionsStyleUpdated(cross_document_enabled, types);
}

bool StyleEngine::HasRulesForId(const AtomicString& id) const {
  DCHECK(global_rule_set_);
  return global_rule_set_->GetRuleFeatureSet()
      .GetRuleInvalidationData()
      .HasSelectorForId(id);
}

void StyleEngine::InitialStyleChanged() {
  MarkViewportStyleDirty();
  // We need to update the viewport style immediately because media queries
  // evaluated in MediaQueryAffectingValueChanged() below may rely on the
  // initial font size relative lengths which may have changed.
  UpdateViewportStyle();
  MediaQueryAffectingValueChanged(MediaValueChange::kOther);
  MarkAllElementsForStyleRecalc(
      StyleChangeReasonForTracing::Create(style_change_reason::kSettings));
}

void StyleEngine::ViewportStyleSettingChanged() {
  if (viewport_resolver_) {
    viewport_resolver_->SetNeedsUpdate();
  }

  // When we remove an import link and re-insert it into the document, the
  // import Document and CSSStyleSheet pointers are persisted. That means the
  // comparison of active stylesheets is not able to figure out that the order
  // of the stylesheets have changed after insertion.
  //
  // This is also the case when we import the same document twice where the
  // last inserted document is inserted before the first one in dom order where
  // the last would take precedence.
  //
  // Fall back to re-add all sheets to the scoped resolver and recalculate style
  // for the whole document when we remove or insert an import document.
  if (ScopedStyleResolver* resolver = GetDocument().GetScopedStyleResolver()) {
    MarkDocumentDirty();
    resolver->SetNeedsAppendAllSheets();
    MarkAllElementsForStyleRecalc(StyleChangeReasonForTracing::Create(
        style_change_reason::kActiveStylesheetsUpdate));
  }
}

void StyleEngine::InvalidateForRuleSetChanges(
    TreeScope& tree_scope,
    const HeapHashSet<Member<RuleSet>>& changed_rule_sets,
    unsigned changed_rule_flags,
    InvalidationScope invalidation_scope) {
  if (tree_scope.GetDocument().HasPendingForcedStyleRecalc()) {
    return;
  }
  if (!tree_scope.GetDocument().documentElement()) {
    return;
  }
  if (changed_rule_sets.empty()) {
    return;
  }

  Element& invalidation_root =
      ScopedStyleResolver::InvalidationRootForTreeScope(tree_scope);
  if (invalidation_root.GetStyleChangeType() == kSubtreeStyleChange) {
    return;
  }

  SelectorFilter selector_filter;
  selector_filter.PushAllParentsOf(tree_scope);

  // Note that unlike the SelectorFilter, there is no need to explicitly
  // handle the ancestor chain. It's OK to have a "root" StyleScopeFrame
  // (i.e. a StyleScopeFrame without a parent frame) in the middle of the
  // tree.
  //
  // Note also in the below call to ApplyRuleSetInvalidationForTreeScope,
  // when `tree_scope` is a ShadowRoot, we have special behavior inside
  // which invalidates "up" to the shadow *host*. This is why we use the
  // host (if applicable) as the StyleScopeFrame element here.
  StyleScopeFrame style_scope_frame(
      IsA<ShadowRoot>(tree_scope)
          ? To<ShadowRoot>(tree_scope).host()
          : *tree_scope.GetDocument().documentElement());

  NthIndexCache nth_index_cache(tree_scope.GetDocument());
  ApplyRuleSetInvalidationForTreeScope(
      tree_scope, tree_scope.RootNode(), selector_filter, style_scope_frame,
      changed_rule_sets, changed_rule_flags, invalidation_scope);
}

void StyleEngine::InvalidateInitialData() {
  initial_data_ = nullptr;
}

// A miniature CascadeMap for cascading @property at-rules according to their
// origin, cascade layer order and position.
class StyleEngine::AtRuleCascadeMap {
  STACK_ALLOCATED();

 public:
  explicit AtRuleCascadeMap(Document& document) : document_(document) {}

  // No need to use the full CascadePriority class, since we are not handling UA
  // style, shadow DOM or importance, and rules are inserted in source ordering.
  struct Priority {
    DISALLOW_NEW();
    bool is_user_style;
    uint16_t layer_order;

    bool operator<(const Priority& other) const {

"""


```