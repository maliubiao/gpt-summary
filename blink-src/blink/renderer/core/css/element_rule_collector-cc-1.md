Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine, specifically the `ElementRuleCollector` class. Since this is the second part of a two-part request, the focus should be on the code provided in this snippet.

Here's a breakdown of the steps to generate the summary:

1. **Identify the Core Purpose:** The code snippet contains methods of the `ElementRuleCollector` class. The class name itself is a strong hint about its purpose: collecting CSS rules that match a given element.

2. **Analyze Individual Methods:** Go through each method in the snippet and understand its role in the rule collection process.
    * `CollectMatchingAttributeRules`:  Focuses on collecting rules based on HTML attributes. Note the special handling for `style` attributes and case sensitivity.
    *  The subsequent `if` blocks (e.g., `if (element.IsLink())`) collect rules based on specific element types or pseudo-classes (like `:link`, `:focus`, `:root`).
    * `CollectMatchingShadowHostRules` and `CheckIfAnyShadowHostRuleMatches`: Deal with rules that apply to shadow hosts.
    * `CollectMatchingSlottedRules`: Collects rules for slotted content in Shadow DOM.
    * `CollectMatchingPartPseudoRules`: Handles rules related to the `::part()` pseudo-element.
    * `FindStyleRule`:  Finds the corresponding CSSOM wrapper (`CSSRule`) for a given internal `StyleRule`. This is crucial for tools like the Inspector.
    * `AppendCSSOMWrapperForRule`: Creates or finds the CSSOM wrapper for a matched rule.
    * `SortAndTransferMatchedRules`:  Sorts the collected rules based on specificity and origin, then transfers them to a list of `StyleRule` pointers or `CSSRule` wrappers, depending on the `mode_`.
    * `DidMatchRule`:  Called when a rule matches an element. It handles different scenarios, including pseudo-elements and tracking statistics.
    * `DumpAndClearRulesPerfMap`:  Outputs performance data related to selector matching.
    * `CompareRules`:  A helper struct for sorting rules.
    * `SortMatchedRules`:  Sorts the collected `MatchedRule` objects.
    * `AddMatchedRulesToTracker`:  Registers the used rules with a tracker.

3. **Identify Key Concepts:** Note the recurrence of concepts like `MatchRequest`, `RuleSet`, `SelectorChecker`, `PseudoId`, `CascadeOrigin`, and the different collection modes.

4. **Infer Relationships to Web Technologies:**  Recognize how the code relates to HTML (attributes, element types), CSS (selectors, specificity, pseudo-classes, shadow DOM, `@part`), and JavaScript (the Inspector interacts with the CSSOM).

5. **Consider User and Programming Errors:**  Think about potential mistakes related to CSS syntax, attribute casing, and the use of Shadow DOM.

6. **Simulate User Interaction (Debugging Context):**  Imagine how a developer might reach this code during debugging, focusing on style application and inspection.

7. **Synthesize a Summary:** Combine the insights from the previous steps to create a concise summary of the code's function, its relation to web technologies, potential errors, and debugging context. Since this is part 2, the summary should primarily focus on the content of this specific code snippet.

8. **Refine and Organize:** Ensure the summary is well-structured, easy to understand, and addresses all aspects of the prompt. Use clear and concise language.
这是 `blink/renderer/core/css/element_rule_collector.cc` 文件 `ElementRuleCollector` 类的部分代码，其主要功能是**收集与特定元素匹配的 CSS 规则**。

以下是该部分代码功能的归纳：

**核心功能：收集匹配的 CSS 规则**

* **收集属性选择器匹配的规则 (`CollectMatchingAttributeRules`)**:  遍历元素的所有属性，并查找与这些属性匹配的 CSS 规则。
    * **处理 HTML 和非 HTML 文档的属性匹配**: 区分 HTML 文档（属性名不区分大小写）和非 HTML 文档（属性名区分大小写）的属性匹配规则。
    * **处理 `style` 属性**:  特别处理 `style` 属性，如果存在 `[style]` 选择器的规则集，则需要同步 `style` 属性后再进行匹配。
    * **处理属性迭代**:  为了避免在迭代属性时，由于同步操作添加新属性导致迭代器失效，使用了基于索引的迭代方式，并在每次迭代后刷新属性列表。
* **收集特定元素类型和伪类匹配的规则**:
    * **链接元素 (`element.IsLink()`)**:  收集与 `:link` 和 `:visited` 伪类匹配的规则。
    * **焦点元素 (`SelectorChecker::MatchesFocusPseudoClass`)**: 收集与 `:focus` 伪类匹配的规则。
    * **片段锚点元素 (`SelectorChecker::MatchesSelectorFragmentAnchorPseudoClass`)**: 收集与 `:target` 伪类匹配的规则。
    * **焦点可见元素 (`SelectorChecker::MatchesFocusVisiblePseudoClass`)**: 收集与 `:focus-visible` 伪类匹配的规则。
    * **根元素 (`element.GetDocument().documentElement() == element`)**: 收集应用于根元素的规则，例如 `html {}`。
    * **标签名匹配 (`bundle.rule_set->TagRules(element_name)`)**:  收集与元素标签名匹配的规则，例如 `div {}`。
    * **通配符匹配 (`bundle.rule_set->UniversalRules()`)**: 收集使用通配符 `*` 匹配的规则。
* **收集 Shadow Host 匹配的规则 (`CollectMatchingShadowHostRules`, `CheckIfAnyShadowHostRuleMatches`)**:  收集应用于 Shadow Host 的规则，包括特定的 Shadow Host 规则和通配符规则。
* **收集 Slotted 元素匹配的规则 (`CollectMatchingSlottedRules`)**: 收集应用于 Shadow DOM 中 `<slot>` 元素的规则，使用 `::slotted()` 伪元素。
* **收集 Part 伪元素匹配的规则 (`CollectMatchingPartPseudoRules`)**: 收集应用于 Shadow DOM 中使用 `::part()` 伪元素定义的部件的规则。

**与 JavaScript, HTML, CSS 的关系：**

* **CSS**: 这是核心功能，代码负责找到与元素相关的 CSS 规则。例如，当解析到 CSS 样式表时，会创建 `RuleSet`，其中包含了各种类型的选择器规则。`ElementRuleCollector` 遍历这些 `RuleSet`，并根据元素的特征（标签名、属性、伪类等）找到匹配的规则。
    * **示例**: 如果 CSS 中有规则 `div.container { color: red; }`，并且页面上有一个 `<div class="container">` 元素，`CollectMatchingAttributeRules` 会找到 `class="container"` 属性匹配的规则。`CollectMatchingTagRules` 会找到 `div` 标签名匹配的规则。
* **HTML**: 代码处理 HTML 元素的属性和结构。
    * **示例**:  对于 `<a href="https://example.com">Link</a>` 元素，`CollectMatchingAttributeRules` 会处理 `href` 属性，而 `CollectMatchingLinkPseudoClassRules` 会处理 `:link` 伪类。
* **JavaScript**: 虽然这段代码是 C++，但它与 JavaScript 通过以下方式关联：
    * **CSSOM (CSS Object Model)**:  `AppendCSSOMWrapperForRule` 方法创建或查找与内部 `StyleRule` 对象对应的 CSSOM 包装器 (`CSSRule`)。这使得 JavaScript 可以通过 CSSOM API 来访问和操作 CSS 规则。
    * **开发者工具 (Inspector)**:  `FindStyleRule` 方法用于在 CSSOM 中查找与 `StyleRule` 对应的 `CSSRule`，这对于开发者工具的功能（例如显示应用于元素的 CSS 规则）至关重要。

**逻辑推理的假设输入与输出：**

假设输入一个 `HTMLDivElement` 元素，其标签名为 "div"，有一个属性 `class="test"`，并且 CSS 中有以下规则：

```css
div { color: black; }
.test { font-size: 16px; }
a:hover { text-decoration: underline; }
```

**假设输入:** 一个 `HTMLDivElement` 实例，具有标签名 "div" 和属性 `class="test"`。

**预期输出 (部分):**

* `CollectMatchingTagRules` 会找到 `div { color: black; }` 规则。
* `CollectMatchingAttributeRules` 会找到 `.test { font-size: 16px; }` 规则。
* `CollectMatchingLinkPseudoClassRules` 不会找到匹配的规则，因为该元素不是链接。

**用户或编程常见的使用错误：**

* **CSS 选择器错误**:  编写了错误的 CSS 选择器，导致规则无法匹配到预期的元素。例如，拼写错误的类名或属性名。
    * **示例**: CSS 中写了 `.teST`，而 HTML 中是 `<div class="test">`，由于大小写不匹配，规则可能无法应用（取决于文档类型）。
* **特异性问题**: 多个 CSS 规则应用于同一个元素，但由于特异性不同，期望的规则没有生效。
* **Shadow DOM 边界问题**:  在 Shadow DOM 中，样式可能不会穿透边界。开发者可能期望外部样式影响 Shadow DOM 内部的元素，但如果没有正确使用 CSS 阴影部分或自定义属性，则可能不会生效。
* **动态添加属性**:  在 JavaScript 中动态添加属性后，如果 CSS 规则依赖于这些属性，需要确保样式的重新计算。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户加载网页**:  当用户在浏览器中打开一个网页时，Blink 引擎会开始解析 HTML 和 CSS。
2. **样式计算**:  在布局之前，Blink 需要计算每个元素的最终样式。
3. **`ElementRuleCollector` 的创建**:  对于页面上的每个元素，Blink 会创建一个 `ElementRuleCollector` 实例来收集与之匹配的 CSS 规则。
4. **规则匹配过程**:
    * 遍历可用的样式表及其中的规则集。
    * 调用 `CollectMatchingAttributeRules` 检查属性选择器。
    * 调用 `CollectMatchingTagRules` 检查标签选择器。
    * 调用其他 `CollectMatching...` 方法检查伪类、伪元素等选择器。
    * `SelectorChecker` 用于实际的规则匹配逻辑。
5. **匹配结果的存储**:  匹配的规则会被存储在 `ElementRuleCollector` 内部。
6. **样式应用的后续阶段**:  收集到的规则会被进一步处理，例如排序、层叠，最终应用于元素。

**作为调试线索**: 当开发者遇到样式问题时，他们可以使用浏览器的开发者工具：

1. **打开开发者工具 (通常按 F12)**。
2. **选择 "Elements" 或 "Inspect" 面板**。
3. **选中页面上的一个元素**。
4. **查看 "Styles" 或 "Computed" 面板**。

开发者工具会显示应用于该元素的 CSS 规则。如果规则没有如预期那样生效，开发者可以：

* **检查 "Styles" 面板**:  查看哪些规则匹配了该元素，哪些规则被覆盖了，以及每个规则的来源和特异性。这可能涉及到查看开发者工具中显示的 CSS 文件和行号，从而追踪到定义规则的位置。
* **使用 "Computed" 面板**: 查看元素最终计算后的样式属性值。

在 Blink 的源代码层面，开发者可能会在 `ElementRuleCollector` 的相关方法中设置断点，例如在 `CollectMatchingAttributeRules` 或 `DidMatchRule` 中，来观察规则是如何被匹配的，以及为什么某个规则被匹配或没有被匹配。  他们可能会检查 `match_request` 的内容，查看哪些规则集正在被评估，以及 `checker` 的状态。

总而言之，这段代码是 Chromium Blink 引擎中负责将 CSS 规则与 HTML 元素关联起来的关键部分，为后续的样式计算和渲染奠定了基础。

Prompt: 
```
这是目录为blink/renderer/core/css/element_rule_collector.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
st.AllRuleSets()) {
    if (bundle.rule_set->HasAnyAttrRules()) {
      has_any_attr_rules = true;
      if (bundle.rule_set->HasBucketForStyleAttribute()) {
        need_style_synchronized = true;
      }
    }
  }
  if (has_any_attr_rules) {
    // HTML documents have case-insensitive attribute matching
    // (so we need to lowercase), non-HTML documents have
    // case-sensitive attribute matching (so we should _not_ lowercase).
    // However, HTML elements already have lowercased their attributes
    // during parsing, so we do not need to do it again.
    const bool lower_attrs_in_default_ns =
        !element.IsHTMLElement() && IsA<HTMLDocument>(element.GetDocument());

    // Due to lazy attributes, this can be a bit tricky. First of all,
    // we need to make sure that if there's a dirty style attribute
    // and there's a ruleset bucket for [style] selectors (which is extremely
    // unusual, but allowed), we check the rules in that bucket.
    // We do this by means of synchronizing the style attribute before
    // iterating, but only if there's actually such a bucket, as it's fairly
    // expensive to do so. (We have a similar issue with SVG attributes,
    // but it is tricky enough to identify if there are any such buckets
    // that we simply always synchronize them if there are any attribute
    // ruleset buckets at all. We can always revisit this if there are any
    // slowdowns from SVG attribute synchronization.)
    //
    // Second, CollectMatchingRulesForList() may call member functions
    // that synchronize the element, adding new attributes to the list
    // while we iterate. These are not relevant for correctness (we
    // would never find any rule buckets matching them anyway),
    // but they may cause reallocation of the vector. For this reason,
    // we cannot use range-based iterators over the attributes here
    // if we don't synchronize before the loop; we need to use
    // simple indexes and then refresh the span after every call.
    base::span<const Attribute> attributes =
        GetAttributes(element, need_style_synchronized);

    for (unsigned attr_idx = 0; attr_idx < attributes.size(); ++attr_idx) {
      const AtomicString& attribute_name = attributes[attr_idx].LocalName();
      // NOTE: Attributes in non-default namespaces are case-sensitive.
      // There is a bug where you can set mixed-cased attributes (in
      // non-default namespaces) with setAttributeNS(), but they never match
      // anything. (The relevant code is in AnyAttributeMatches(), in
      // selector_checker.cc.) What we're doing here doesn't influence that
      // bug.
      const AtomicString& lower_name =
          (lower_attrs_in_default_ns &&
           attributes[attr_idx].NamespaceURI() == g_null_atom)
              ? attribute_name.LowerASCII()
              : attribute_name;
      for (const auto bundle : match_request.AllRuleSets()) {
        if (!bundle.rule_set->HasAnyAttrRules()) {
          continue;
        }
        base::span<const RuleData> list =
            bundle.rule_set->AttrRules(lower_name);
        if (list.empty() ||
            bundle.rule_set->CanIgnoreEntireList(
                list, lower_name, attributes[attr_idx].Value())) {
          continue;
        }
        if (CollectMatchingRulesForList<stop_at_first_match>(
                bundle.rule_set->AttrRules(lower_name), match_request,
                bundle.rule_set, bundle.style_sheet_index, checker,
                context.context) &&
            stop_at_first_match) {
          return true;
        }
      }

      const AttributeCollection collection = element.AttributesWithoutUpdate();
      attributes = base::span(collection);
    }
  }

  if (element.IsLink()) {
    for (const auto bundle : match_request.AllRuleSets()) {
      if (CollectMatchingRulesForList<stop_at_first_match>(
              bundle.rule_set->LinkPseudoClassRules(), match_request,
              bundle.rule_set, bundle.style_sheet_index, checker,
              context.context) &&
          stop_at_first_match) {
        return true;
      }
    }
  }
  if (SelectorChecker::MatchesFocusPseudoClass(element, kPseudoIdNone)) {
    for (const auto bundle : match_request.AllRuleSets()) {
      if (CollectMatchingRulesForList<stop_at_first_match>(
              bundle.rule_set->FocusPseudoClassRules(), match_request,
              bundle.rule_set, bundle.style_sheet_index, checker,
              context.context) &&
          stop_at_first_match) {
        return true;
      }
    }
  }
  if (SelectorChecker::MatchesSelectorFragmentAnchorPseudoClass(element)) {
    for (const auto bundle : match_request.AllRuleSets()) {
      if (CollectMatchingRulesForList<stop_at_first_match>(
              bundle.rule_set->SelectorFragmentAnchorRules(), match_request,
              bundle.rule_set, bundle.style_sheet_index, checker,
              context.context) &&
          stop_at_first_match) {
        return true;
      }
    }
  }
  if (SelectorChecker::MatchesFocusVisiblePseudoClass(element)) {
    for (const auto bundle : match_request.AllRuleSets()) {
      if (CollectMatchingRulesForList<stop_at_first_match>(
              bundle.rule_set->FocusVisiblePseudoClassRules(), match_request,
              bundle.rule_set, bundle.style_sheet_index, checker,
              context.context) &&
          stop_at_first_match) {
        return true;
      }
    }
  }
  if (element.GetDocument().documentElement() == element) {
    for (const auto bundle : match_request.AllRuleSets()) {
      if (CollectMatchingRulesForList<stop_at_first_match>(
              bundle.rule_set->RootElementRules(), match_request,
              bundle.rule_set, bundle.style_sheet_index, checker,
              context.context) &&
          stop_at_first_match) {
        return true;
      }
    }
  }
  AtomicString element_name = matching_ua_rules_
                                  ? element.localName()
                                  : element.LocalNameForSelectorMatching();
  for (const auto bundle : match_request.AllRuleSets()) {
    if (CollectMatchingRulesForList<stop_at_first_match>(
            bundle.rule_set->TagRules(element_name), match_request,
            bundle.rule_set, bundle.style_sheet_index, checker,
            context.context) &&
        stop_at_first_match) {
      return true;
    }
  }
  for (const auto bundle : match_request.AllRuleSets()) {
    if (CollectMatchingRulesForList<stop_at_first_match>(
            bundle.rule_set->UniversalRules(), match_request, bundle.rule_set,
            bundle.style_sheet_index, checker, context.context) &&
        stop_at_first_match) {
      return true;
    }
  }
  return false;
}

void ElementRuleCollector::CollectMatchingShadowHostRules(
    const MatchRequest& match_request) {
  SelectorChecker checker(nullptr, pseudo_style_request_, mode_,
                          matching_ua_rules_);

  ContextWithStyleScopeFrame context(context_, match_request,
                                     &pseudo_style_request_,
                                     style_recalc_context_.style_scope_frame);

  for (const auto bundle : match_request.AllRuleSets()) {
    CollectMatchingRulesForList</*stop_at_first_match=*/false>(
        bundle.rule_set->ShadowHostRules(), match_request, bundle.rule_set,
        bundle.style_sheet_index, checker, context.context);
    if (bundle.rule_set->MustCheckUniversalBucketForShadowHost()) {
      CollectMatchingRulesForList</*stop_at_first_match=*/false>(
          bundle.rule_set->UniversalRules(), match_request, bundle.rule_set,
          bundle.style_sheet_index, checker, context.context);
    }
  }
}

bool ElementRuleCollector::CheckIfAnyShadowHostRuleMatches(
    const MatchRequest& match_request) {
  SelectorChecker checker(nullptr, pseudo_style_request_, mode_,
                          matching_ua_rules_);

  ContextWithStyleScopeFrame context(context_, match_request,
                                     &pseudo_style_request_,
                                     style_recalc_context_.style_scope_frame);

  for (const auto bundle : match_request.AllRuleSets()) {
    if (CollectMatchingRulesForList</*stop_at_first_match=*/true>(
            bundle.rule_set->ShadowHostRules(), match_request, bundle.rule_set,
            bundle.style_sheet_index, checker, context.context)) {
      return true;
    }
    if (bundle.rule_set->MustCheckUniversalBucketForShadowHost()) {
      if (CollectMatchingRulesForList</*stop_at_first_match=*/true>(
              bundle.rule_set->UniversalRules(), match_request, bundle.rule_set,
              bundle.style_sheet_index, checker, context.context)) {
        return true;
      }
    }
  }
  return false;
}

void ElementRuleCollector::CollectMatchingSlottedRules(
    const MatchRequest& match_request) {
  SelectorChecker checker(nullptr, pseudo_style_request_, mode_,
                          matching_ua_rules_);
  ContextWithStyleScopeFrame context(context_, match_request,
                                     &pseudo_style_request_,
                                     style_recalc_context_.style_scope_frame);

  for (const auto bundle : match_request.AllRuleSets()) {
    CollectMatchingRulesForList</*stop_at_first_match=*/false>(
        bundle.rule_set->SlottedPseudoElementRules(), match_request,
        bundle.rule_set, bundle.style_sheet_index, checker, context.context);
  }
}

void ElementRuleCollector::CollectMatchingPartPseudoRules(
    const MatchRequest& match_request,
    PartNames* part_names,
    bool for_shadow_pseudo) {
  PartRequest request{for_shadow_pseudo};
  SelectorChecker checker(part_names, pseudo_style_request_, mode_,
                          matching_ua_rules_);

  ContextWithStyleScopeFrame context(context_, match_request,
                                     &pseudo_style_request_,
                                     style_recalc_context_.style_scope_frame);

  for (const auto bundle : match_request.AllRuleSets()) {
    CollectMatchingRulesForList</*stop_at_first_match=*/false>(
        bundle.rule_set->PartPseudoRules(), match_request, bundle.rule_set,
        bundle.style_sheet_index, checker, context.context, &request);
  }
}

// Find the CSSRule within the CSSRuleCollection that corresponds to the
// incoming StyleRule. This mapping is needed because Inspector needs to
// interact with the CSSOM-wrappers (i.e. CSSRules) of the matched rules, but
// ElementRuleCollector's result is a list of StyleRules.
//
// We also use it as a simple true/false for whether the StyleRule exists
// in the given style sheet, because we don't track which style sheet
// each matched rule came from in normal operation.
template <class CSSRuleCollection>
static CSSRule* FindStyleRule(CSSRuleCollection* css_rules,
                              const StyleRule* style_rule) {
  if (!css_rules) {
    return nullptr;
  }

  for (unsigned i = 0; i < css_rules->length(); ++i) {
    CSSRule* css_rule = css_rules->ItemInternal(i);
    if (auto* css_style_rule = DynamicTo<CSSStyleRule>(css_rule)) {
      if (css_style_rule->GetStyleRule() == style_rule) {
        return css_rule;
      }
      if (CSSRule* result =
              FindStyleRule(css_style_rule->cssRules(), style_rule);
          result) {
        return result;
      }
    } else if (auto* css_import_rule = DynamicTo<CSSImportRule>(css_rule)) {
      if (CSSRule* result =
              FindStyleRule(css_import_rule->styleSheet(), style_rule);
          result) {
        return result;
      }
    } else if (CSSRule* result =
                   FindStyleRule(css_rule->cssRules(), style_rule);
               result) {
      return result;
    } else if (auto* nested_declarations =
                   DynamicTo<CSSNestedDeclarationsRule>(css_rule)) {
      if (nested_declarations->NestedDeclarationsRule()->InnerStyleRule() ==
          style_rule) {
        return nested_declarations->InnerCSSStyleRule();
      }
    }
  }
  return nullptr;
}

void ElementRuleCollector::AppendCSSOMWrapperForRule(
    const TreeScope* tree_scope_containing_rule,
    const RuleData* rule_data,
    wtf_size_t position) {
  // For :visited/:link rules, the question of whether or not a selector
  // matches is delayed until cascade-time (see CascadeExpansion), hence such
  // rules may appear to match from ElementRuleCollector's output. This behavior
  // is not correct for Inspector purposes, hence we explicitly filter out
  // rules that don't match the current link state here.
  if (!(rule_data->LinkMatchType() &
        LinkMatchTypeFromInsideLink(inside_link_))) {
    return;
  }

  CSSRule* css_rule = nullptr;
  StyleRule* rule = rule_data->Rule();
  if (tree_scope_containing_rule) {
    for (const auto& [parent_style_sheet, rule_set] :
         tree_scope_containing_rule->GetScopedStyleResolver()
             ->GetActiveStyleSheets()) {
      css_rule = FindStyleRule(parent_style_sheet.Get(), rule);
      if (css_rule) {
        break;
      }
    }
    DCHECK(css_rule);
  } else {
    // |tree_scope_containing_rule| is nullptr if and only if the |rule| is
    // coming from User Agent. In this case, it is safe to create CSSOM wrappers
    // without parentStyleSheets as they will be used only by inspector which
    // will not try to edit them.
    css_rule = rule->CreateCSSOMWrapper(position);
  }
  EnsureRuleList()->emplace_back(css_rule, rule_data->SelectorIndex());
}

void ElementRuleCollector::SortAndTransferMatchedRules(
    CascadeOrigin origin,
    bool is_vtt_embedded_style,
    StyleRuleUsageTracker* tracker) {
  if (matched_rules_.empty()) {
    return;
  }

  SortMatchedRules();

  if (mode_ == SelectorChecker::kCollectingStyleRules) {
    for (const MatchedRule& matched_rule : matched_rules_) {
      EnsureStyleRuleList()->push_back(matched_rule.GetRuleData()->Rule());
    }
    return;
  }

  if (mode_ == SelectorChecker::kCollectingCSSRules) {
    for (unsigned i = 0; i < matched_rules_.size(); ++i) {
      AppendCSSOMWrapperForRule(current_matching_tree_scope_,
                                matched_rules_[i].GetRuleData(), i);
    }
    return;
  }

  // Now transfer the set of matched rules over to our list of declarations.
  for (const MatchedRule& matched_rule : matched_rules_) {
    const RuleData* rule_data = matched_rule.GetRuleData();
    if (rule_data->IsStartingStyle()) {
      result_.AddFlags(
          static_cast<MatchFlags>(MatchFlag::kAffectedByStartingStyle));
    }
    result_.AddMatchedProperties(
        &rule_data->Rule()->Properties(),
        {.link_match_type = static_cast<uint8_t>(
             AdjustLinkMatchType(inside_link_, rule_data->LinkMatchType())),
         .valid_property_filter = static_cast<uint8_t>(
             rule_data->GetValidPropertyFilter(matching_ua_rules_)),
         .is_inline_style = static_cast<uint8_t>(is_vtt_embedded_style),
         .origin = origin,
         .layer_order = matched_rule.LayerOrder()});
  }

  if (tracker) {
    AddMatchedRulesToTracker(tracker);
  }
}

void ElementRuleCollector::DidMatchRule(
    const RuleData* rule_data,
    uint16_t layer_order,
    const ContainerQuery* container_query,
    unsigned proximity,
    const SelectorChecker::MatchResult& result,
    int style_sheet_index) {
  PseudoId dynamic_pseudo = result.dynamic_pseudo;
  // If we're matching normal rules, set a pseudo bit if we really just
  // matched a pseudo-element.
  if (dynamic_pseudo != kPseudoIdNone &&
      pseudo_style_request_.pseudo_id == kPseudoIdNone) {
    if (mode_ == SelectorChecker::kCollectingCSSRules ||
        mode_ == SelectorChecker::kCollectingStyleRules) {
      return;
    }
    if (dynamic_pseudo > kLastTrackedPublicPseudoId) {
      return;
    }
    if ((dynamic_pseudo == kPseudoIdCheck ||
         dynamic_pseudo == kPseudoIdBefore ||
         dynamic_pseudo == kPseudoIdAfter ||
         dynamic_pseudo == kPseudoIdSelectArrow) &&
        !rule_data->Rule()->Properties().HasProperty(CSSPropertyID::kContent)) {
      return;
    }
    if (rule_data->Rule()->Properties().IsEmpty()) {
      return;
    }

    result_.SetHasPseudoElementStyle(dynamic_pseudo);

    if (IsHighlightPseudoElement(dynamic_pseudo)) {
      // Determine whether the selector definitely matches the highlight pseudo
      // of all elements, without any namespace limits or other conditions.
      bool universal = false;
      const CSSSelector& selector = rule_data->Selector();
      if (CSSSelector::GetPseudoId(selector.GetPseudoType()) ==
          dynamic_pseudo) {
        // When there is no default @namespace, *::selection and *|*::selection
        // are stored without the star, so we are universal if there’s nothing
        // before (e.g. x::selection) and nothing after (e.g. y ::selection).
        universal = selector.IsLastInComplexSelector();
      } else if (const CSSSelector* next = selector.NextSimpleSelector()) {
        // When there is a default @namespace, ::selection and *::selection (not
        // universal) are stored as g_null_atom|*::selection, |*::selection (not
        // universal) is stored as g_empty_atom|*::selection, and *|*::selection
        // (the only universal form) is stored as g_star_atom|*::selection.
        universal =
            next->IsLastInComplexSelector() &&
            CSSSelector::GetPseudoId(next->GetPseudoType()) == dynamic_pseudo &&
            selector.Match() == CSSSelector::kTag &&
            selector.TagQName().LocalName().IsNull() &&
            selector.TagQName().Prefix() == g_star_atom;
      }

      if (!universal || container_query != nullptr) {
        result_.SetHasNonUniversalHighlightPseudoStyles();
      }

      if (!matching_ua_rules_) {
        result_.SetHasNonUaHighlightPseudoStyles();
      }

      if (container_query) {
        result_.SetHighlightsDependOnSizeContainerQueries();
      }

      if (dynamic_pseudo == kPseudoIdHighlight) {
        DCHECK(result.custom_highlight_name);
        result_.AddCustomHighlightName(
            AtomicString(result.custom_highlight_name));
      }
    } else if (dynamic_pseudo == kPseudoIdFirstLine && container_query) {
      result_.SetFirstLineDependsOnSizeContainerQueries();
    }
  } else {
    if (rule_data->Rule()->Properties().ContainsCursorHand()) {
      context_.GetElement().GetDocument().CountUse(
          WebFeature::kQuirksModeCursorHandApplied);
    }
    matched_rules_.emplace_back(rule_data, layer_order, proximity,
                                style_sheet_index);
  }
}

void ElementRuleCollector::DumpAndClearRulesPerfMap() {
  TRACE_EVENT1(
      TRACE_DISABLED_BY_DEFAULT("blink.debug"), "SelectorStats",
      "selector_stats", [&](perfetto::TracedValue context) {
        perfetto::TracedDictionary dict = std::move(context).WriteDictionary();
        {
          perfetto::TracedArray array = dict.AddArray("selector_timings");
          for (auto& it : GetSelectorStatisticsRuleMap()) {
            perfetto::TracedValue item = array.AppendItem();
            perfetto::TracedDictionary item_dict =
                std::move(item).WriteDictionary();
            item_dict.Add("selector", it.key.selector);
            item_dict.Add("style_sheet_id", it.key.style_sheet_id);
            item_dict.Add("elapsed (us)", it.value.elapsed);
            item_dict.Add("match_attempts", it.value.match_attempts);
            item_dict.Add("fast_reject_count", it.value.fast_reject_count);
            item_dict.Add("match_count", it.value.match_count);
          }
        }
      });
  GetSelectorStatisticsRuleMap().clear();
}

struct ElementRuleCollector::CompareRules {
  inline bool operator()(const MatchedRule& matched_rule1,
                         const MatchedRule& matched_rule2) const {
#ifdef __SIZEOF_INT128__
    // https://github.com/llvm/llvm-project/issues/108418
    __uint128_t key1 = (__uint128_t{matched_rule1.SortKey()} << 64) |
                       matched_rule1.GetPosition();
    __uint128_t key2 = (__uint128_t{matched_rule2.SortKey()} << 64) |
                       matched_rule2.GetPosition();
#else
    std::pair key1{matched_rule1.SortKey(), matched_rule1.GetPosition()};
    std::pair key2{matched_rule2.SortKey(), matched_rule2.GetPosition()};
#endif
    return key1 < key2;
  }
};

void ElementRuleCollector::SortMatchedRules() {
  if (matched_rules_.size() > 1) {
    std::sort(matched_rules_.begin(), matched_rules_.end(), CompareRules());
  }
}

void ElementRuleCollector::AddMatchedRulesToTracker(
    StyleRuleUsageTracker* tracker) const {
  for (auto matched_rule : matched_rules_) {
    const StyleRule* rule = matched_rule.GetRuleData()->Rule();
    tracker->Track(
        FindStyleSheet(current_matching_tree_scope_,
                       context_.GetElement().GetDocument().GetStyleEngine(),
                       rule),
        rule);
  }
}

}  // namespace blink

"""


```