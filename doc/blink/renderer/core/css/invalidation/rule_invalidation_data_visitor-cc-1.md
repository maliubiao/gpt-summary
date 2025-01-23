Response:
The user wants a summary of the functionalities of the provided C++ code snippet from `rule_invalidation_data_visitor.cc`.

To achieve this, I will:
1. Identify the main purpose of the code by looking at the class name and the functions it contains.
2. Explain how this code relates to CSS invalidation in the Blink rendering engine.
3. Provide examples of how the code interacts with CSS selectors and properties.
4. Explain any assumptions or logic involved in the code.
5. Highlight potential user errors or debugging scenarios.
6. Summarize the overall functionality of this part of the code.
```
这是目录为blink/renderer/core/css/invalidation/rule_invalidation_data_visitor.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

**功能归纳 (基于提供的代码片段):**

这段代码的主要功能是为 CSS 规则中的选择器收集并添加 “特征 (features)” 到不同的 “失效集合 (invalidation sets)” 中。这些失效集合用于优化在 DOM 树发生变化时需要重新计算样式的元素范围，从而提高渲染性能。 代码主要关注如何提取选择器的特征，并将其分配到合适的失效集合，以便在特定类型的 DOM 变化发生时能够精确地触发样式重新计算，避免不必要的计算。

**更具体的功能点包括:**

1. **处理 `:not()` 伪类:**  区分 `".a :not(.b)"` 和 `":not(.a) .b"` 两种情况下的失效集合处理。前者 `".a"` 的失效集合不应包含 `".b"`，而后者 `":not(.a)"` 的失效集合应该包含 `".a"`。
2. **遍历和分析 CSS 选择器:**  通过 `AddFeaturesToInvalidationSets` 和相关的辅助函数，代码能够递归地分析 CSS 选择器的各个组成部分（简单选择器、复合选择器、组合器）。
3. **识别和处理特征:**  识别选择器中影响失效策略的 “特征”，例如 ID、类名、属性选择器、伪类等。
4. **管理不同类型的失效集合:**  代码涉及多种失效集合，例如：
    * **`descendant_features`:** 用于存储后代选择器的特征。
    * **`sibling_features`:** 用于存储兄弟选择器的特征。
    * **`universal_set`:** 用于存储通用的兄弟失效信息。
    * **类、ID、属性失效集合:**  根据选择器的类型创建和更新相应的失效集合。
5. **处理 `:has()` 伪类:**  这是一个非常复杂的部分，专门处理 `:has()` 伪类的失效逻辑，包括：
    * **收集 `:has()` 参数中的值:**  提取 `:has()` 内部选择器中的类名、属性名、ID 等，用于更精细的失效判断。
    * **处理嵌套的逻辑组合 (`:is`, `:where`, `:not`, `:parent`):**  递归地分析 `:has()` 内部的逻辑组合，并为它们的不同部分添加特征到合适的失效集合。
    * **区分 `:has()` 参数检查范围和主体范围:**  在处理逻辑组合时，需要区分选择器是在 `:has()` 的参数部分还是主体部分，并采取不同的失效策略。
6. **处理 `:nth-child` 等伪类:**  标记与 `:nth-child` 相关的失效集合，以便在子元素数量变化时触发失效。
7. **处理作用域样式 (`@scope`):**  提取 `@scope` 规则中 `from` 和 `to` 选择器的特征。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:** 这段代码直接处理 CSS 选择器，其核心目标是理解 CSS 选择器的结构和语义，并根据这些信息来确定样式失效的范围。
    * **例子:** 当 CSS 规则 `.container .item` 应用于 HTML 时，如果 `.item` 元素的类名发生变化，这段代码会确保只有受影响的 `.container` 下的 `.item` 元素才会重新计算样式，而不是整个页面。
    * **例子 (处理 `:has()`):**  对于 CSS 规则 `.parent:has(.child)`, 当一个 `.child` 元素被添加到 `.parent` 内部时，这段代码负责确保 `.parent` 元素的样式被重新评估。
* **HTML:**  HTML 结构的变化会触发样式失效，而这段代码定义了在哪些 HTML 结构变化的情况下，哪些 CSS 规则需要重新计算。
    * **例子:**  如果一个元素的 ID 从 `#old-id` 变为 `#new-id`，这段代码确保所有包含 `#old-id` 和 `#new-id` 选择器的 CSS 规则都会被重新评估。
* **JavaScript:** JavaScript 可以动态地修改 HTML 结构和元素的属性/类名，这些操作会触发样式失效。这段代码定义了 Blink 引擎如何响应这些 JavaScript 引起的 DOM 变化。
    * **例子:**  JavaScript 代码 `document.querySelector('.my-element').classList.add('active');` 会修改元素的类名，这段代码会根据 `.active` 选择器配置的失效集合来决定哪些样式需要重新计算。

**逻辑推理的假设输入与输出:**

* **假设输入 (CSS 选择器):** `.container > .item.active`
* **逻辑推理:**
    * 识别出组合器 `>` (子选择器)。
    * 识别出 `.container` 和 `.item.active` 两个复合选择器。
    * 在 `.item.active` 中识别出类选择器 `.item` 和 `.active`。
* **输出 (添加到失效集合):**
    * `.container` 的后代失效集合会包含 `.item` 和 `.active` 的特征。
    * 如果存在兄弟失效集合，可能会根据具体的上下文添加相应的特征。

* **假设输入 (CSS 选择器):** `.parent:has(> .child[data-status="ok"])`
* **逻辑推理:**
    * 识别出 `:has()` 伪类。
    * 分析 `:has()` 的参数 `> .child[data-status="ok"]`。
    * 识别出子选择器 `>`，类选择器 `.child`，和属性选择器 `[data-status="ok"]`。
* **输出 (添加到失效集合):**
    * `.parent` 的失效集合会被标记为需要监听其子元素中满足 `.child` 且 `data-status` 属性为 `"ok"` 的元素。
    * 根据具体的实现，可能会将 `.child` 和 `data-status` 的特征添加到特定的失效集合中。

**涉及用户或编程常见的使用错误:**

* **CSS 选择器性能问题:**  过度使用复杂选择器 (例如，嵌套很深的后代选择器，或包含大量逻辑组合的 `:has()` 伪类) 可能导致失效计算的性能下降。这段代码虽然旨在优化失效，但如果选择器本身过于复杂，仍然会影响性能。
    * **例子:**  用户编写了类似 `body > div#content .module .sub-module .item .detail span.name` 这样的选择器，每次 `span.name` 的祖先元素发生变化，都需要进行大量的查找和比较。
* **对失效机制的误解:**  开发者可能对浏览器的失效机制有错误的理解，导致 CSS 编写不当，反而影响性能。
    * **例子:**  开发者认为只要使用了类名选择器，就不会触发大范围的失效，但实际上，如果类名被频繁地添加和删除，仍然会导致大量的样式重计算。
* **在 `:has()` 中使用过于宽泛的选择器:**  在 `:has()` 中使用过于宽泛的选择器（例如 `*` 或标签选择器，没有具体的类名或 ID）可能导致不必要的失效。
    * **例子:**  `.parent:has(*)` 会导致 `.parent` 在其任何子元素变化时都重新计算样式。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中加载网页:**  浏览器开始解析 HTML 和 CSS。
2. **CSS 解析器创建 CSSOM:**  CSS 规则被解析并存储在 CSS 对象模型 (CSSOM) 中。
3. **样式计算:**  浏览器遍历 DOM 树，根据 CSSOM 中的规则计算每个元素的最终样式。
4. **布局:**  计算出每个元素的大小和位置。
5. **绘制:**  将元素渲染到屏幕上。
6. **用户交互或 JavaScript 操作:**  用户进行操作 (例如，鼠标悬停、点击) 或 JavaScript 代码修改了 DOM 结构或元素属性/类名。
7. **触发样式失效:**  DOM 的变化导致某些元素的样式需要重新计算。
8. **`RuleInvalidationDataVisitor` 的使用:**  Blink 引擎内部使用 `RuleInvalidationDataVisitor` 来确定哪些 CSS 规则需要重新评估，以及哪些元素受到了影响。当需要为一个新的或修改过的 CSS 规则构建失效信息时，或者当 DOM 发生变化需要触发失效时，这段代码会被调用。
9. **调试线索:**  如果在调试过程中发现样式更新不符合预期，或者性能出现问题，可以考虑以下线索：
    * **检查 CSS 选择器:**  是否存在过于复杂或宽泛的选择器？
    * **查看性能分析工具:**  例如 Chrome DevTools 的 Performance 面板，查看样式重计算 (Recalculate Style) 的耗时和触发原因。
    * **断点调试 Blink 源代码:**  在 `RuleInvalidationDataVisitor` 相关的代码中设置断点，跟踪选择器特征的提取和失效集合的更新过程。

**第2部分功能归纳:**

总而言之，这部分代码是 Blink 渲染引擎中负责**构建和管理 CSS 规则失效信息**的关键组件。它通过分析 CSS 选择器的结构和特征，将这些信息存储在不同的失效集合中，以便在 DOM 发生变化时能够高效地触发必要的样式重计算，从而优化渲染性能。 重点在于对选择器特征的精确提取和失效集合的正确管理，特别是针对像 `:has()` 这样复杂伪类的处理。

### 提示词
```
这是目录为blink/renderer/core/css/invalidation/rule_invalidation_data_visitor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
still have invalidation sets
  // for the features since we are able to detect when they change.
  // That is, ".a" should not have ".b" in its invalidation set for
  // ".a :not(.b)", but there should be an invalidation set for ".a" in
  // ":not(.a) .b".
  if (pseudo_type != CSSSelector::kPseudoNot) {
    if (all_sub_selectors_have_features) {
      features.NarrowToFeatures(any_features);
    }
  }
}

template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::AddFeaturesToInvalidationSets(
    const CSSSelector& selector,
    bool in_nth_child,
    InvalidationSetFeatures* sibling_features,
    InvalidationSetFeatures& descendant_features) {
  // selector is the selector immediately to the left of the rightmost
  // combinator. descendant_features has the features of the rightmost compound
  // selector.

  InvalidationSetFeatures last_compound_in_sibling_chain_features;
  const CSSSelector* compound = &selector;
  while (compound) {
    const CSSSelector* last_in_compound =
        AddFeaturesToInvalidationSetsForCompoundSelector(
            *compound, in_nth_child, sibling_features, descendant_features);
    DCHECK(last_in_compound);
    UpdateFeaturesFromCombinator(last_in_compound->Relation(), compound,
                                 last_compound_in_sibling_chain_features,
                                 sibling_features, descendant_features,
                                 /* for_logical_combination_in_has */ false,
                                 in_nth_child);
    compound = last_in_compound->NextSimpleSelector();
  }
}

template <RuleInvalidationDataVisitorType VisitorType>
const CSSSelector* RuleInvalidationDataVisitor<VisitorType>::
    AddFeaturesToInvalidationSetsForCompoundSelector(
        const CSSSelector& compound,
        bool in_nth_child,
        InvalidationSetFeatures* sibling_features,
        InvalidationSetFeatures& descendant_features) {
  bool compound_has_features_for_rule_set_invalidation = false;
  const CSSSelector* simple_selector = &compound;
  for (; simple_selector;
       simple_selector = simple_selector->NextSimpleSelector()) {
    base::AutoReset<bool> reset_has_features(
        &descendant_features.has_features_for_rule_set_invalidation, false);
    AddFeaturesToInvalidationSetsForSimpleSelector(
        *simple_selector, compound, in_nth_child, sibling_features,
        descendant_features);
    if (descendant_features.has_features_for_rule_set_invalidation) {
      compound_has_features_for_rule_set_invalidation = true;
    }
    if (simple_selector->Relation() != CSSSelector::kSubSelector) {
      break;
    }
    if (!simple_selector->NextSimpleSelector()) {
      break;
    }
  }

  if (compound_has_features_for_rule_set_invalidation) {
    descendant_features.has_features_for_rule_set_invalidation = true;
  } else if (sibling_features) {
    AddFeaturesToUniversalSiblingInvalidationSet(*sibling_features,
                                                 descendant_features);
  }

  return simple_selector;
}

template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::
    AddFeaturesToInvalidationSetsForSimpleSelector(
        const CSSSelector& simple_selector,
        const CSSSelector& compound,
        bool in_nth_child,
        InvalidationSetFeatures* sibling_features,
        InvalidationSetFeatures& descendant_features) {
  if (simple_selector.IsIdClassOrAttributeSelector()) {
    descendant_features.has_features_for_rule_set_invalidation = true;
  }

  CSSSelector::PseudoType pseudo_type = simple_selector.GetPseudoType();

  if (pseudo_type == CSSSelector::kPseudoHas) {
    CollectValuesInHasArgument(simple_selector);
    AddFeaturesToInvalidationSetsForHasPseudoClass(
        simple_selector, &compound, sibling_features, descendant_features,
        in_nth_child);
    if (simple_selector.HasArgumentMatchInShadowTree()) {
      descendant_features.invalidation_flags.SetTreeBoundaryCrossing(true);
    }
  }

  if (InvalidationSetType* invalidation_set = InvalidationSetForSimpleSelector(
          simple_selector,
          sibling_features ? InvalidationType::kInvalidateSiblings
                           : InvalidationType::kInvalidateDescendants,
          kAncestor, in_nth_child)) {
    if (!sibling_features) {
      if (invalidation_set == rule_invalidation_data_.nth_invalidation_set) {
        // TODO(futhark): We can extract the features from the current compound
        // to optimize this.
        SetWholeSubtreeInvalid(invalidation_set);
        AddFeaturesToInvalidationSet(
            EnsureSiblingDescendantInvalidationSet(
                To<SiblingInvalidationSet>(invalidation_set)),
            descendant_features);
        return;
      } else {
        AddFeaturesToInvalidationSet(invalidation_set, descendant_features);
        return;
      }
    }

    auto* sibling_invalidation_set =
        To<SiblingInvalidationSet>(invalidation_set);
    UpdateMaxDirectAdjacentSelectors(
        sibling_invalidation_set,
        sibling_features->max_direct_adjacent_selectors);
    AddFeaturesToInvalidationSet(invalidation_set, *sibling_features);
    if (sibling_features == &descendant_features) {
      SetInvalidatesSelf(sibling_invalidation_set);
      if (in_nth_child) {
        SetInvalidatesNth(sibling_invalidation_set);
      }
    } else {
      AddFeaturesToInvalidationSet(
          EnsureSiblingDescendantInvalidationSet(sibling_invalidation_set),
          descendant_features);
    }
    return;
  }

  // For the :has pseudo class, we should not extract invalidation set features
  // here because the :has invalidation direction is different with others.
  // (preceding-sibling/ancestors/preceding-sibling-of-ancestors)
  if (pseudo_type == CSSSelector::kPseudoHas) {
    return;
  }

  if (pseudo_type == CSSSelector::kPseudoPart) {
    descendant_features.invalidation_flags.SetInvalidatesParts(true);
  }

  AddFeaturesToInvalidationSetsForSelectorList(
      simple_selector, in_nth_child, sibling_features, descendant_features);
}

template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::
    AddFeaturesToInvalidationSetsForSelectorList(
        const CSSSelector& simple_selector,
        bool in_nth_child,
        InvalidationSetFeatures* sibling_features,
        InvalidationSetFeatures& descendant_features) {
  if (!simple_selector.SelectorListOrParent()) {
    return;
  }

  DCHECK(SupportsInvalidationWithSelectorList(simple_selector.GetPseudoType()));

  bool had_features_for_rule_set_invalidation =
      descendant_features.has_features_for_rule_set_invalidation;
  bool selector_list_contains_universal =
      simple_selector.GetPseudoType() == CSSSelector::kPseudoNot ||
      simple_selector.GetPseudoType() == CSSSelector::kPseudoHostContext;
  in_nth_child |=
      simple_selector.GetPseudoType() == CSSSelector::kPseudoNthChild;
  in_nth_child |=
      simple_selector.GetPseudoType() == CSSSelector::kPseudoNthLastChild;

  for (const CSSSelector* sub_selector = simple_selector.SelectorListOrParent();
       sub_selector; sub_selector = CSSSelectorList::Next(*sub_selector)) {
    AutoRestoreMaxDirectAdjacentSelectors restore_max(sibling_features);
    AutoRestoreDescendantFeaturesDepth restore_depth(&descendant_features);
    AutoRestoreTreeBoundaryCrossingFlag restore_tree_boundary(
        descendant_features);
    AutoRestoreInsertionPointCrossingFlag restore_insertion_point(
        descendant_features);

    if (simple_selector.IsHostPseudoClass()) {
      descendant_features.invalidation_flags.SetTreeBoundaryCrossing(true);
    }

    descendant_features.has_features_for_rule_set_invalidation = false;

    AddFeaturesToInvalidationSets(*sub_selector, in_nth_child, sibling_features,
                                  descendant_features);

    if (!descendant_features.has_features_for_rule_set_invalidation) {
      selector_list_contains_universal = true;
    }
  }

  descendant_features.has_features_for_rule_set_invalidation =
      had_features_for_rule_set_invalidation ||
      !selector_list_contains_universal;
}

// See also UpdateFeaturesFromStyleScope.
template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::
    AddFeaturesToInvalidationSetsForStyleScope(
        const StyleScope& style_scope,
        InvalidationSetFeatures& descendant_features) {
  auto add_features = [this](const CSSSelector& selector_list,
                             InvalidationSetFeatures& features) {
    for (const CSSSelector* selector = &selector_list; selector;
         selector = CSSSelectorList::Next(*selector)) {
      AddFeaturesToInvalidationSets(*selector, /*in_nth_child=*/false,
                                    nullptr /* sibling_features */, features);
    }
  };

  for (const StyleScope* scope = &style_scope; scope; scope = scope->Parent()) {
    if (scope->From()) {
      add_features(*scope->From(), descendant_features);
    }

    if (scope->To()) {
      add_features(*scope->To(), descendant_features);
    }
  }
}

template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::
    AddFeaturesToUniversalSiblingInvalidationSet(
        const InvalidationSetFeatures& sibling_features,
        const InvalidationSetFeatures& descendant_features) {
  SiblingInvalidationSetType* universal_set =
      EnsureUniversalSiblingInvalidationSet();
  AddFeaturesToInvalidationSet(universal_set, sibling_features);
  UpdateMaxDirectAdjacentSelectors(
      universal_set, sibling_features.max_direct_adjacent_selectors);

  if (&sibling_features == &descendant_features) {
    SetInvalidatesSelf(universal_set);
  } else {
    AddFeaturesToInvalidationSet(
        EnsureSiblingDescendantInvalidationSet(universal_set),
        descendant_features);
  }
}

template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::
    AddValuesInComplexSelectorInsideIsWhereNot(
        const CSSSelector* selector_first) {
  for (const CSSSelector* complex = selector_first; complex;
       complex = CSSSelectorList::Next(*complex)) {
    DCHECK(complex);

    for (const CSSSelector* simple = complex; simple;
         simple = simple->NextSimpleSelector()) {
      AddValueOfSimpleSelectorInHasArgument(*simple);
    }
  }
}

template <RuleInvalidationDataVisitorType VisitorType>
bool RuleInvalidationDataVisitor<VisitorType>::
    AddValueOfSimpleSelectorInHasArgument(const CSSSelector& selector) {
  if (selector.Match() == CSSSelector::kClass) {
    if constexpr (is_builder()) {
      rule_invalidation_data_.classes_in_has_argument.insert(selector.Value());
    }
    return true;
  }
  if (selector.IsAttributeSelector()) {
    if constexpr (is_builder()) {
      rule_invalidation_data_.attributes_in_has_argument.insert(
          selector.Attribute().LocalName());
    }
    return true;
  }
  if (selector.Match() == CSSSelector::kId) {
    if constexpr (is_builder()) {
      rule_invalidation_data_.ids_in_has_argument.insert(selector.Value());
    }
    return true;
  }
  if (selector.Match() == CSSSelector::kTag &&
      selector.TagQName().LocalName() != CSSSelector::UniversalSelectorAtom()) {
    if constexpr (is_builder()) {
      rule_invalidation_data_.tag_names_in_has_argument.insert(
          selector.TagQName().LocalName());
    }
    return true;
  }
  if (selector.Match() == CSSSelector::kPseudoClass) {
    CSSSelector::PseudoType pseudo_type = selector.GetPseudoType();

    switch (pseudo_type) {
      case CSSSelector::kPseudoNot:
        if constexpr (is_builder()) {
          rule_invalidation_data_.not_pseudo_in_has_argument = true;
        }
        [[fallthrough]];
      case CSSSelector::kPseudoIs:
      case CSSSelector::kPseudoWhere:
      case CSSSelector::kPseudoParent:
        AddValuesInComplexSelectorInsideIsWhereNot(
            selector.SelectorListOrParent());
        break;
      case CSSSelector::kPseudoVisited:
        // Ignore :visited to prevent history leakage.
        break;
      case CSSSelector::kPseudoScope:
        // Ignore :scope inside :has() because :has() anchor element doesn't
        // have any descendant/sibling/sibling-descendant element that matches
        // document root or scope root.
        break;
      default:
        if constexpr (is_builder()) {
          rule_invalidation_data_.pseudos_in_has_argument.insert(pseudo_type);
        }
        break;
    }
    return true;
  }
  return false;
}

template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::CollectValuesInHasArgument(
    const CSSSelector& has_pseudo_class) {
  DCHECK_EQ(has_pseudo_class.GetPseudoType(), CSSSelector::kPseudoHas);
  const CSSSelectorList* selector_list = has_pseudo_class.SelectorList();
  DCHECK(selector_list);

  for (const CSSSelector* relative_selector = selector_list->First();
       relative_selector;
       relative_selector = CSSSelectorList::Next(*relative_selector)) {
    DCHECK(relative_selector);

    bool value_added = false;
    const CSSSelector* simple = relative_selector;
    while (simple->GetPseudoType() != CSSSelector::kPseudoRelativeAnchor) {
      value_added |= AddValueOfSimpleSelectorInHasArgument(*simple);

      if (simple->Relation() != CSSSelector::kSubSelector) {
        if (!value_added) {
          if constexpr (is_builder()) {
            rule_invalidation_data_.universal_in_has_argument = true;
          }
        }
        value_added = false;
      }

      simple = simple->NextSimpleSelector();
      DCHECK(simple);
    }
  }
}

template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::
    AddFeaturesToInvalidationSetsForHasPseudoClass(
        const CSSSelector& pseudo_has,
        const CSSSelector* compound_containing_has,
        InvalidationSetFeatures* sibling_features,
        InvalidationSetFeatures& descendant_features,
        bool in_nth_child) {
  DCHECK(compound_containing_has);
  DCHECK_EQ(pseudo_has.GetPseudoType(), CSSSelector::kPseudoHas);

  if (in_nth_child) {
    if constexpr (is_builder()) {
      rule_invalidation_data_.uses_has_inside_nth = true;
    }
  }

  // Add features to invalidation sets only when the :has() pseudo class
  // contains logical combinations containing a complex selector as argument.
  if (!pseudo_has.ContainsComplexLogicalCombinationsInsideHasPseudoClass()) {
    return;
  }

  // Set descendant features as WholeSubtreeInvalid if the descendant features
  // haven't been extracted yet. (e.g. '.a :has(:is(.b .c)).d {}')
  AutoRestoreWholeSubtreeInvalid restore_whole_subtree(descendant_features);
  if (!descendant_features.HasFeatures()) {
    descendant_features.invalidation_flags.SetWholeSubtreeInvalid(true);
  }

  // Use descendant features as sibling features if the :has() pseudo class is
  // in subject position.
  if (!sibling_features && descendant_features.descendant_features_depth == 0) {
    sibling_features = &descendant_features;
  }

  DCHECK(pseudo_has.SelectorList());

  for (const CSSSelector* relative = pseudo_has.SelectorList()->First();
       relative; relative = CSSSelectorList::Next(*relative)) {
    for (const CSSSelector* simple = relative;
         simple->GetPseudoType() != CSSSelector::kPseudoRelativeAnchor;
         simple = simple->NextSimpleSelector()) {
      switch (simple->GetPseudoType()) {
        case CSSSelector::kPseudoIs:
        case CSSSelector::kPseudoWhere:
        case CSSSelector::kPseudoNot:
        case CSSSelector::kPseudoParent:
          // Add features for each method to handle sibling descendant
          // relationship in the logical combination.
          // - For '.a:has(:is(.b ~ .c .d))',
          //   -> '.b ~ .c .a' (kForAllNonRightmostCompounds)
          //   -> '.b ~ .a' (kForCompoundImmediatelyFollowsAdjacentRelation)
          AddFeaturesToInvalidationSetsForLogicalCombinationInHas(
              *simple, compound_containing_has, sibling_features,
              descendant_features, CSSSelector::kSubSelector,
              kForAllNonRightmostCompounds);
          AddFeaturesToInvalidationSetsForLogicalCombinationInHas(
              *simple, compound_containing_has, sibling_features,
              descendant_features, CSSSelector::kSubSelector,
              kForCompoundImmediatelyFollowsAdjacentRelation);
          break;
        default:
          break;
      }
    }
  }
}

// Context for adding features for a compound selector in a logical combination
// inside :has(). This struct provides these information so that the features
// can be added correctly for the compound in logical combination.
// - needs_skip_adding_features:
//     - whether adding features needs to be skipped.
// - needs_update_features:
//     - whether updating features is needed.
// - last_compound_in_adjacent_chain:
//     - last compound in adjacent chain used for updating features.
// - use_indirect_adjacent_combinator_for_updating_features:
//     - whether we need to use adjacent combinator for updating features.
// Please check the comments in the constructor for more details.
template <RuleInvalidationDataVisitorType VisitorType>
struct RuleInvalidationDataVisitor<VisitorType>::
    AddFeaturesToInvalidationSetsForLogicalCombinationInHasContext {
  bool needs_skip_adding_features;
  bool needs_update_features;
  const CSSSelector* last_compound_in_adjacent_chain;
  bool use_indirect_adjacent_combinator_for_updating_features;

  AddFeaturesToInvalidationSetsForLogicalCombinationInHasContext(
      const CSSSelector* compound_in_logical_combination,
      const CSSSelector* compound_containing_has,
      CSSSelector::RelationType previous_combinator,
      AddFeaturesMethodForLogicalCombinationInHas add_features_method) {
    last_compound_in_adjacent_chain = nullptr;
    needs_skip_adding_features = false;
    needs_update_features = false;
    use_indirect_adjacent_combinator_for_updating_features = false;

    bool is_in_has_argument_checking_scope =
        previous_combinator == CSSSelector::kSubSelector;
    bool add_features_for_compound_immediately_follows_adjacent_relation =
        add_features_method == kForCompoundImmediatelyFollowsAdjacentRelation;

    if (is_in_has_argument_checking_scope) {
      // If the compound in the logical combination is for the element in the
      // :has() argument checking scope, skip adding features.
      needs_skip_adding_features = true;

      // If the compound in the logical combination is for the element in the
      // :has() argument checking scope, update features before moving to the
      // next compound.
      needs_update_features = true;

      // For the rightmost compound that need to be skipped, use the compound
      // selector containing :has() as last_compound_in_adjacent_chain for
      // updating features so that the features can be added as if the next
      // compounds are prepended to the compound containing :has().
      // (e.g. '.a:has(:is(.b .c ~ .d)) .e' -> '.b .c ~ .a .e')
      // The selector pointer of '.a:has(:is(.b .c ~ .d))' is passed though
      // the argument 'compound_containing_has'.
      last_compound_in_adjacent_chain = compound_containing_has;

      // In case of adding features only for adjacent combinator and its
      // next compound selector, update features as if the relation of the
      // last-in-compound is indirect adjacent combinator ('~').
      if (add_features_for_compound_immediately_follows_adjacent_relation) {
        use_indirect_adjacent_combinator_for_updating_features = true;
      }
    } else {
      // If this method call is for the compound immediately follows an
      // adjacent combinator in the logical combination but the compound
      // doesn't follow any adjacent combinator, skip adding features.
      if (add_features_for_compound_immediately_follows_adjacent_relation &&
          !CSSSelector::IsAdjacentRelation(previous_combinator)) {
        needs_skip_adding_features = true;
      }

      // Update features from the previous combinator when we add features
      // for all non-rightmost compound selectors. In case of adding features
      // only for adjacent combinator and its next compound selector, do not
      // update features so that we can use the same features that was
      // updated at the compound in :has() argument checking scope.
      if (add_features_method == kForAllNonRightmostCompounds) {
        needs_update_features = true;
      }

      last_compound_in_adjacent_chain = compound_in_logical_combination;
    }
  }
};

template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::
    AddFeaturesToInvalidationSetsForLogicalCombinationInHas(
        const CSSSelector& logical_combination,
        const CSSSelector* compound_containing_has,
        InvalidationSetFeatures* sibling_features,
        InvalidationSetFeatures& descendant_features,
        CSSSelector::RelationType previous_combinator,
        AddFeaturesMethodForLogicalCombinationInHas add_features_method) {
  DCHECK(compound_containing_has);

  for (const CSSSelector* complex = logical_combination.SelectorListOrParent();
       complex; complex = CSSSelectorList::Next(*complex)) {
    base::AutoReset<CSSSelector::RelationType> restore_previous_combinator(
        &previous_combinator, previous_combinator);
    AutoRestoreMaxDirectAdjacentSelectors restore_max(sibling_features);
    AutoRestoreDescendantFeaturesDepth restore_depth(&descendant_features);
    AutoRestoreTreeBoundaryCrossingFlag restore_tree_boundary(
        descendant_features);
    AutoRestoreInsertionPointCrossingFlag restore_insertion_point(
        descendant_features);

    const CSSSelector* compound_in_logical_combination = complex;
    InvalidationSetFeatures* inner_sibling_features = sibling_features;
    InvalidationSetFeatures last_compound_in_adjacent_chain_features;
    while (compound_in_logical_combination) {
      AddFeaturesToInvalidationSetsForLogicalCombinationInHasContext context(
          compound_in_logical_combination, compound_containing_has,
          previous_combinator, add_features_method);

      const CSSSelector* last_in_compound;
      if (context.needs_skip_adding_features) {
        last_in_compound =
            SkipAddingAndGetLastInCompoundForLogicalCombinationInHas(
                compound_in_logical_combination, compound_containing_has,
                inner_sibling_features, descendant_features,
                previous_combinator, add_features_method);
      } else {
        last_in_compound =
            AddFeaturesAndGetLastInCompoundForLogicalCombinationInHas(
                compound_in_logical_combination, compound_containing_has,
                inner_sibling_features, descendant_features,
                previous_combinator, add_features_method);
      }

      if (!last_in_compound) {
        break;
      }

      previous_combinator = last_in_compound->Relation();

      if (context.needs_update_features) {
        UpdateFeaturesFromCombinatorForLogicalCombinationInHas(
            context.use_indirect_adjacent_combinator_for_updating_features
                ? CSSSelector::kIndirectAdjacent
                : previous_combinator,
            context.last_compound_in_adjacent_chain,
            last_compound_in_adjacent_chain_features, inner_sibling_features,
            descendant_features);
      }

      compound_in_logical_combination = last_in_compound->NextSimpleSelector();
    }
  }
}

template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::
    UpdateFeaturesFromCombinatorForLogicalCombinationInHas(
        CSSSelector::RelationType combinator,
        const CSSSelector* last_compound_in_adjacent_chain,
        InvalidationSetFeatures& last_compound_in_adjacent_chain_features,
        InvalidationSetFeatures*& sibling_features,
        InvalidationSetFeatures& descendant_features) {
  // Always use indirect relation to add features to invalidation sets for
  // logical combinations inside :has() since it is too difficult to limit
  // invalidation distance by counting successive indirect relations in the
  // logical combinations inside :has().
  // (e.g. '.a:has(:is(:is(.a > .b) .c)) {}', '.a:has(~ :is(.b + .c + .d)) {}'
  switch (combinator) {
    case CSSSelector::CSSSelector::kDescendant:
    case CSSSelector::CSSSelector::kChild:
      combinator = CSSSelector::kDescendant;
      break;
    case CSSSelector::CSSSelector::kDirectAdjacent:
    case CSSSelector::CSSSelector::kIndirectAdjacent:
      combinator = CSSSelector::kIndirectAdjacent;
      break;
    default:
      NOTREACHED();
  }

  UpdateFeaturesFromCombinator(combinator, last_compound_in_adjacent_chain,
                               last_compound_in_adjacent_chain_features,
                               sibling_features, descendant_features,
                               /* for_logical_combination_in_has */ true,
                               /*in_nth_child=*/false);
}

template <RuleInvalidationDataVisitorType VisitorType>
const CSSSelector* RuleInvalidationDataVisitor<VisitorType>::
    SkipAddingAndGetLastInCompoundForLogicalCombinationInHas(
        const CSSSelector* compound_in_logical_combination,
        const CSSSelector* compound_containing_has,
        InvalidationSetFeatures* sibling_features,
        InvalidationSetFeatures& descendant_features,
        CSSSelector::RelationType previous_combinator,
        AddFeaturesMethodForLogicalCombinationInHas add_features_method) {
  const CSSSelector* simple = compound_in_logical_combination;
  for (; simple; simple = simple->NextSimpleSelector()) {
    switch (simple->GetPseudoType()) {
      case CSSSelector::kPseudoIs:
      case CSSSelector::kPseudoWhere:
      case CSSSelector::kPseudoNot:
      case CSSSelector::kPseudoParent:
        // Nested logical combinations in rightmost compound of a first-depth
        // logical combination inside :has()
        // (e.g. '.a:has(.a :is(.b :is(.c .d))) {}')
        AddFeaturesToInvalidationSetsForLogicalCombinationInHas(
            *simple, compound_containing_has, sibling_features,
            descendant_features, previous_combinator, add_features_method);
        break;
      default:
        break;
    }
    if (simple->Relation() != CSSSelector::kSubSelector) {
      break;
    }
  }
  return simple;
}

template <RuleInvalidationDataVisitorType VisitorType>
const CSSSelector* RuleInvalidationDataVisitor<VisitorType>::
    AddFeaturesAndGetLastInCompoundForLogicalCombinationInHas(
        const CSSSelector* compound_in_logical_combination,
        const CSSSelector* compound_containing_has,
        InvalidationSetFeatures* sibling_features,
        InvalidationSetFeatures& descendant_features,
        CSSSelector::RelationType previous_combinator,
        AddFeaturesMethodForLogicalCombinationInHas add_features_method) {
  DCHECK(compound_in_logical_combination);
  bool compound_has_features_for_rule_set_invalidation = false;
  const CSSSelector* simple = compound_in_logical_combination;

  for (; simple; simple = simple->NextSimpleSelector()) {
    base::AutoReset<bool> reset_has_features(
        &descendant_features.has_features_for_rule_set_invalidation, false);
    switch (simple->GetPseudoType()) {
      case CSSSelector::kPseudoIs:
      case CSSSelector::kPseudoWhere:
      case CSSSelector::kPseudoNot:
      case CSSSelector::kPseudoParent:
        // Nested logical combination inside :has()
        // (e.g. '.a:has(:is(:is(.a .b) .c)) {}')
        AddFeaturesToInvalidationSetsForLogicalCombinationInHas(
            *simple, compound_containing_has, sibling_features,
            descendant_features, previous_combinator, add_features_method);
        break;
      default:
        AddFeaturesToInvalidationSetsForSimpleSelector(
            *simple, *compound_in_logical_combination, /*in_nth_child=*/false,
            sibling_features, descendant_features);
        break;
    }
    if (descendant_features.has_features_for_rule_set_invalidation) {
      compound_has_features_for_rule_set_invalidation = true;
    }

    if (simple->Relation() != CSSSelector::kSubSelector) {
      break;
    }
  }

  // If the compound selector has features for invalidation, mark the
  // related flag in the descendant_features.
  // Otherwise add features to universal sibling invalidation set if
  // sibling_features exists. (e.g. '.a:has(:is(* .b)) ~ .c .d {}')
  if (compound_has_features_for_rule_set_invalidation) {
    descendant_features.has_features_for_rule_set_invalidation = true;
  } else if (sibling_features) {
    AddFeaturesToUniversalSiblingInvalidationSet(*sibling_features,
                                                 descendant_features);
  }

  return simple;
}

template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::
    MarkInvalidationSetsWithinNthChild(const CSSSelector& selector,
                                       bool in_nth_child) {
  const CSSSelector* simple_selector = &selector;
  for (; simple_selector;
       simple_selector = simple_selector->NextSimpleSelector()) {
    if (in_nth_child) {
      if (InvalidationSetType* invalidation_set =
              InvalidationSetForSimpleSelector(
                  *simple_selector, InvalidationType::kInvalidateDescendants,
                  kAncestor, in_nth_child)) {
        // This is, strictly speaking, setting the bit on too many classes.
        // If we have a selector like :nth-child(.a .b) .c, there's no reason
        // to set the invalidates_nth_ bit on .a; what we need is that .b
        // has the bit, and that the descendant invalidation set for .a
        // contains .b (so that adding .a to some element causes us to go
        // looking for .b elements in that element's subtree), and we've
        // already done that in AddFeaturesToInvalidationSetsForSelectorList()
        // -- setting the bit on .a is not really doing much. So that would be a
        // potential future optimization if we find it useful. (We still need to
        // traverse the ancestor selectors, though, in case they contain other
        // :nth-child() selectors, recursively.)
        SetInvalidatesNth(invalidation_set);
      }
    }
    if (simple_selector->SelectorList()) {
      bool sub_in_nth_child =
          in_nth_child ||
          simple_selector->GetPseudoType() == CSSSelector::kPseudoNthChild ||
          simple_selector->GetPseudoType() == CSSSelector::kPseudoNthLastChild;
      MarkInvalidationSetsWithinNthChild(
          *simple_selector->SelectorList()->First(), sub_in_nth_child);
    }
  }
}

template <RuleInvalidationDataVisitorType VisitorType>
RuleInvalidationDataVisitor<VisitorType>::InvalidationSetType*
RuleInvalidationDataVisitor<VisitorType>::InvalidationSetForSimpleSelector(
    const CSSSelector& selector,
    InvalidationType type,
    PositionType position,
    bool in_nth_child) {
  if (selector.Match() == CSSSelector::kClass) {
    if (type == InvalidationType::kInvalidateDescendants &&
        position == kSubject && !in_nth_child &&
        InsertIntoSelfInvalidationBloomFilter(
            selector.Value(), RuleInvalidationData::kClassSalt)) {
      // Do not insert self-invalidation sets for classes;
      // see comment on class_invalidation_sets_.
      return nullptr;
    }
    return EnsureClassInvalidationSet(selector.Value(), type, position,
                                      in_nth_child);
  }
  if (selector.IsAttributeSelector()) {
    return EnsureAttributeInvalidationSet(selector.Attribute().LocalName(),
                                          type, position, in_nth_child);
  }
  if (selector.Match() == CSSSelector::kId) {
    if (type == InvalidationType::kInvalidateDescendants &&
        position == kSubject &&
        InsertIntoSelfInvalidationBloomFilter(selector.Value(),
                                              RuleInvalidationData::kIdSalt)) {
      // Do not insert self-invalidation sets for IDs;
      // see comment on class_invalidation_sets_.
      return nullptr;
    }
    return EnsureIdInvalidationSet(selector.Value(), type, position,
                                   in_nth_child);
  }
  if (selector.Match() == CSSSelector::kPseudoClass) {
    switch (selector.GetPseudoType()) {
      case CSSSelector::kPseudoEmpty:
      case CSSSelector::kPseudoFirstChild:
      case CSSSelector::kPseudoLastChild:
      case CSSSelector::kPseudoOnlyChild:
      case CSSSelector::kPseudoLink:
      case CSSSelector::kPseudoVisited:
```