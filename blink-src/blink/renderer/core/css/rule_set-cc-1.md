Response:
My thought process for analyzing the provided code snippet goes like this:

1. **Understand the Goal:** The request asks for the *functionality* of the code, its relationship to web technologies (HTML, CSS, JavaScript), examples, debugging implications, and a summary of its overall purpose. Since this is part 2, the summary should synthesize information from both parts.

2. **High-Level Overview (Context from Part 1):**  Recall that Part 1 established `RuleSet` as a core structure for storing and managing CSS rules within the Blink rendering engine. It mentioned how CSS rules are parsed and organized. This context is crucial.

3. **Analyze the Functions:**  Go through each function defined in the snippet and try to understand its role:

    * **`AddChildRules`:**  This function is clearly recursive and handles different types of CSS rules (style, media, font-face, etc.). It seems to be the central logic for processing a list of rules and adding them to the `RuleSet`. Pay attention to how it handles nesting (`media_rule`, `supports_rule`, `container_rule`, `scope_rule`).

    * **`MatchMediaForAddRules`:**  This is about media queries and whether a set of queries matches the current environment. It ties directly into CSS media query functionality.

    * **`AddRulesFromSheet`:**  This function takes a `StyleSheetContents` object (likely the parsed CSS) and iterates through its rules, calling `AddChildRules`. This is the entry point for adding rules from a stylesheet. The handling of `@import` rules and layers is important here.

    * **`FindParentIfUsed`:**  This function looks for references to the parent selector (`&`) within a CSS selector. This is a CSS nesting feature.

    * **`IncludeRule`:**  This determines if a rule should be included in a filtered set, considering parent rule modifications. This is relevant for performance optimizations and incremental updates.

    * **`NewlyAddedFromDifferentRuleSet`:** This seems to track rules moved between `RuleSet` instances. It likely involves some kind of optimization or invalidation mechanism.

    * **`AddFilteredRulesFromOtherBucket` and `AddFilteredRulesFromOtherSet`:** These functions are clearly for copying or merging rules between `RuleSet` instances, applying a filter based on modified rules.

    * **`AddStyleRule`:** This function adds a specific `StyleRule` to the `RuleSet`, iterating through its selectors and calling `AddRule` (from Part 1). It also handles nested rules.

    * **`GetOrAddSubLayer`:** Deals with CSS cascade layers. It ensures a layer exists and returns it.

    * **`RuleMap::Add` and `RuleMap::Compact/Uncompact`:** These functions manage a map of rules, likely optimized for storage and retrieval based on certain keys (like IDs, classes, attributes). The compaction/uncompaction suggests performance optimizations for large rule sets.

    * **`RuleMap::AddFilteredRulesFromOtherSet`:** Similar to the `RuleSet` version, but operating on the `RuleMap` structure.

    * **`GetMinimumRulesetSizeForSubstringMatcher`:**  A heuristic for performance optimization related to attribute selectors.

    * **`CanIgnoreEntireList`:** A performance optimization to avoid checking rules when an attribute value doesn't contain any of the relevant substrings.

    * **`CreateSubstringMatchers`:** Builds a data structure (likely a trie or Aho-Corasick automaton) to efficiently check for substring matches in attribute selectors.

    * **`CompactRules`:**  This function consolidates and optimizes the data structures within the `RuleSet` after rules have been added.

    * **`AssertRuleListsSorted`:**  A debugging aid to ensure internal data structures are in the expected order.

    * **`DidMediaQueryResultsChange`:** Checks if media query evaluation results have changed.

    * **`GetLayerForTest`:**  A test utility to retrieve the cascade layer for a given rule.

    * **`RuleData::Trace` and `RuleSet::Trace`:**  These are part of Blink's tracing infrastructure for debugging and performance analysis.

4. **Identify Relationships with Web Technologies:**

    * **CSS:** The entire file is fundamentally about CSS. Every function relates to parsing, organizing, and managing CSS rules. Specific features like media queries, `@import`, cascade layers, container queries, scope, `@keyframes`, `@font-face`, `@counter-style`, view transitions, and attribute selectors are explicitly handled.

    * **HTML:** CSS rules apply to HTML elements. The selectors within the rules target specific elements based on their tags, classes, IDs, attributes, etc. The concept of a "parent rule" is directly related to the HTML document structure.

    * **JavaScript:** While this specific file doesn't directly execute JavaScript, the information stored in the `RuleSet` is crucial for Blink's rendering process, which *is* affected by JavaScript (e.g., dynamically added styles, style manipulation). The View Transition API (mentioned in `AddViewTransitionRule`) is a more direct link to JavaScript.

5. **Develop Examples (Hypothetical Inputs and Outputs):**  Think about concrete scenarios. For example, when processing a `@media` rule, what would `MatchMediaForAddRules` do?  When adding a rule with a parent selector, how would `FindParentIfUsed` work?  When compacting rules, what changes internally?

6. **Consider User/Programming Errors:** What could go wrong? Incorrect CSS syntax would likely be caught during parsing *before* this stage. However, issues with specificity, cascade order, or incorrect media query logic could lead to unexpected styling, which might necessitate debugging involving this code.

7. **Debugging Clues:** How would a developer end up looking at this code?  Likely when investigating CSS-related rendering bugs. They might be stepping through the style resolution process or examining the contents of a `RuleSet`.

8. **Synthesize the Functionality (Part 2 Summary):**  Focus on the core responsibilities demonstrated in this snippet: processing various CSS rule types, handling nested rules, managing cascade layers, optimizing rule storage and retrieval, and supporting incremental updates.

9. **Review and Refine:**  Read through the analysis to ensure clarity, accuracy, and completeness. Make sure the examples are relevant and the connections to web technologies are clear. Ensure the summary effectively captures the key functionalities. For instance, I initially focused heavily on adding rules but realized the compaction and filtering aspects are also significant and should be highlighted in the summary.

By following these steps, I can break down the complex code into understandable components and build a comprehensive answer that addresses all aspects of the request. The iterative process of analysis, example generation, and synthesis helps to solidify understanding and generate a well-structured response.
这是 `blink/renderer/core/css/rule_set.cc` 文件的第二部分，延续了第一部分关于 `RuleSet` 类的定义。基于提供的代码片段，我们可以归纳一下 `RuleSet` 的功能，并补充说明其与 JavaScript, HTML, CSS 的关系，以及可能的错误和调试线索。

**归纳 `RuleSet` 的功能 (基于第 2 部分的代码):**

这部分代码主要关注于以下 `RuleSet` 的功能：

1. **添加和管理各种类型的 CSS 规则:**  `RuleSet` 不仅管理普通的样式规则 (`StyleRule`)，还能处理各种特殊的 CSS 规则，例如：
    * **媒体查询规则 (`StyleRuleMedia`):**  根据媒体查询条件，有条件地添加子规则。
    * **`@font-face` 规则 (`StyleRuleFontFace`):**  定义自定义字体。
    * **`@page` 规则 (`StyleRulePage`):**  定义打印页面的样式。
    * **`@keyframes` 规则 (`StyleRuleKeyframes`):**  定义 CSS 动画的关键帧。
    * **`@property` 规则 (`StyleRuleProperty`):**  注册自定义 CSS 属性。
    * **`@counter-style` 规则 (`StyleRuleCounterStyle`):**  定义自定义的计数器样式。
    * **`@view-transition` 规则 (`StyleRuleViewTransition`):**  定义视图过渡的样式（这是一个相对较新的 CSS 功能）。
    * **`@position-try` 规则 (`StyleRulePositionTry`):**  处理定位尝试（可能与实验性布局功能相关）。
    * **`@function` 规则 (`StyleRuleFunction`):**  定义自定义 CSS 函数（可能与 CSS Houdini 相关）。
    * **`@supports` 规则 (`StyleRuleSupports`):**  根据浏览器支持的功能有条件地添加子规则。
    * **`@container` 规则 (`StyleRuleContainer`):**  根据容器的尺寸或状态有条件地应用样式。
    * **`@layer` 规则 (`StyleRuleLayerBlock`, `StyleRuleLayerStatement`):**  管理 CSS 级联层。
    * **`@scope` 规则 (`StyleRuleScope`):**  限制选择器的作用域。
    * **`@starting-style` 规则 (`StyleRuleStartingStyle`):**  定义元素动画的起始样式。
    * **`@mixin` 和 `@apply` 规则 (`StyleRuleMixin`, `StyleRuleApplyMixin`):**  支持 CSS 预处理器风格的 mixin 功能。
    * **嵌套声明规则 (`StyleRuleNestedDeclarations`):**  处理 CSS 的嵌套语法。

2. **处理 `@import` 规则:**  `AddRulesFromSheet` 函数递归地处理 `@import` 引入的外部样式表。

3. **管理 CSS 级联层:**  代码中大量使用了 `CascadeLayer`，用于管理不同来源和优先级的样式规则。`GetOrAddSubLayer` 用于获取或创建子层。

4. **高效地存储和检索规则:**  `RuleMap` 类用于存储按特定键（例如，ID、类名、属性）分组的规则，并提供了 `Compact` 和 `Uncompact` 方法进行内存优化。

5. **支持差量更新和过滤:**  `AddFilteredRulesFromOtherSet` 和相关函数允许从另一个 `RuleSet` 中添加满足特定条件的规则，这对于性能优化和样式表的增量更新非常重要。

6. **优化属性选择器匹配:**  `CreateSubstringMatchers` 和 `CanIgnoreEntireList` 函数通过构建 `SubstringSetMatcher` 来优化包含子字符串匹配的属性选择器的性能。

7. **维护规则列表的排序:**  `AssertRuleListsSorted` 在调试模式下检查规则列表是否按照预期排序。

8. **跟踪媒体查询结果的变化:** `DidMediaQueryResultsChange` 用于判断媒体查询的评估结果是否发生了改变。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **CSS:**  `RuleSet` 的核心功能是管理 CSS 规则。代码中处理的各种 `StyleRule` 子类都直接对应于不同的 CSS 语法结构。例如，`AddStyleRule` 处理普通的选择器和属性，`AddMediaQueryRule` 处理 `@media` 块。

* **HTML:** CSS 规则的目标是 HTML 元素。`RuleSet` 中存储的规则最终会应用于匹配 HTML 元素的样式计算。例如，当 HTML 中存在一个 `<div>` 元素并且 CSS 中有 `div { color: blue; }` 规则时，该规则会被添加到 `RuleSet` 中，并在样式计算阶段应用于该 `<div>` 元素。

* **JavaScript:**  JavaScript 可以动态地修改 CSS 样式，或者创建新的样式表。
    * **动态修改样式:**  当 JavaScript 修改元素的 `style` 属性或操作 CSSOM (CSS Object Model) 时，这些修改可能会导致 `RuleSet` 的更新或重新评估。
    * **创建新的样式表:**  JavaScript 可以创建 `<style>` 标签并插入到 HTML 中，或者通过 `CSSStyleSheet` API 创建样式表。这些新添加的样式规则会被解析并添加到相应的 `RuleSet` 中。
    * **View Transitions API:** `AddViewTransitionRule` 函数处理与 View Transitions API 相关的 CSS 规则，这个 API 允许开发者使用 JavaScript 和 CSS 创建平滑的页面过渡效果。

**逻辑推理的假设输入与输出:**

**假设输入:**  解析一个包含以下 CSS 规则的样式表：

```css
.container {
  width: 100%;
}

@media (max-width: 768px) {
  .container {
    width: auto;
  }
}
```

**输出:**

* `AddRulesFromSheet` 会被调用，并遍历样式表中的规则。
* `AddStyleRule` 会被调用来处理 `.container { width: 100%; }` 规则，将其添加到 `class_rules_` 中。
* `AddChildRules` 会被调用来处理 `@media` 规则。
* `MatchMediaForAddRules` 会根据当前的视口宽度评估 `(max-width: 768px)`。
* 如果媒体查询匹配，内部的 `.container { width: auto; }` 规则也会通过 `AddStyleRule` 添加到 `class_rules_` 中，但会与外部的 `.container` 规则关联不同的媒体查询条件。

**用户或编程常见的使用错误举例说明:**

* **在 `@apply` 中引用不存在的 mixin:**

```css
.my-element {
  @apply nonExistentMixin; /* 错误：mixin 不存在 */
  color: red;
}
```

   在这个例子中，`AddChildRules` 在处理 `@apply` 规则时，会在 `mixins_` 中查找 `nonExistentMixin`。如果找不到，样式将不会被应用，开发者可能会感到困惑，不知道为什么颜色没有变成红色。

* **在不支持的浏览器中使用新的 CSS 功能 (例如 `@view-transition`):**

```css
::view-transition-old(root),
::view-transition-new(root) {
  animation-duration: 0.5s;
}
```

   如果浏览器不支持 View Transitions API，`AddViewTransitionRule` 会正常处理这些规则，但它们在样式计算阶段可能不会产生任何效果。开发者需要在支持的浏览器中测试这些新功能。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中打开一个网页。**
2. **浏览器开始解析 HTML 文档。**
3. **浏览器遇到 `<link>` 标签或 `<style>` 标签，指向或包含 CSS 样式表。**
4. **Blink 的 CSS 解析器开始解析这些样式表。**
5. **解析后的 CSS 规则（例如 `StyleRule` 对象）会被创建。**
6. **`RuleSet::AddRulesFromSheet` 函数被调用，开始将解析出的规则添加到 `RuleSet` 对象中。**
7. **`AddRulesFromSheet` 可能会调用 `AddChildRules` 来处理不同类型的规则和嵌套结构。**
8. **根据规则的类型，会调用相应的 `Add...Rule` 函数（例如 `AddStyleRule`, `AddMediaQueryRule` 等）。**
9. **对于包含选择器的规则，`AddRule` (在第一部分中) 会被调用，将规则添加到基于选择器类型（ID、类、标签等）的内部数据结构中。**
10. **在处理 `@apply` 规则时，如果 mixin 不存在，`mixins_.find(apply_mixin_rule->GetName())` 将返回 `mixins_.end()`。**
11. **如果启用了开发者工具，并且设置了断点或者正在进行性能分析，开发者可能会观察到 `RuleSet` 的状态和这些函数的调用过程。**

**总结第 2 部分的功能:**

`RuleSet` 的第二部分代码主要负责 **扩展 `RuleSet` 管理的 CSS 规则类型**，使其能够处理各种现代和实验性的 CSS 功能，例如媒体查询、字体、动画、自定义属性、计数器样式、视图过渡、容器查询、作用域、mixin 等。此外，它还关注 **性能优化**，例如通过 `RuleMap` 进行规则的组织和压缩，以及针对属性选择器的优化。代码还包含了处理 `@import` 规则和管理 CSS 级联层的逻辑。总而言之，这部分代码深化了 `RuleSet` 在 Blink 渲染引擎中作为核心 CSS 规则容器和管理器的作用。

Prompt: 
```
这是目录为blink/renderer/core/css/rule_set.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
 rule) {
  need_compaction_ = true;
  view_transition_rules_.push_back(rule);
}

void RuleSet::AddChildRules(StyleRule* parent_rule,
                            const HeapVector<Member<StyleRuleBase>>& rules,
                            const MediaQueryEvaluator& medium,
                            AddRuleFlags add_rule_flags,
                            const ContainerQuery* container_query,
                            CascadeLayer* cascade_layer,
                            const StyleScope* style_scope,
                            bool within_mixin) {
  for (StyleRuleBase* rule : rules) {
    if (auto* style_rule = DynamicTo<StyleRule>(rule)) {
      AddStyleRule(style_rule, parent_rule, medium, add_rule_flags,
                   within_mixin, container_query, cascade_layer, style_scope);
    } else if (auto* page_rule = DynamicTo<StyleRulePage>(rule)) {
      page_rule->SetCascadeLayer(cascade_layer);
      AddPageRule(page_rule);
    } else if (auto* media_rule = DynamicTo<StyleRuleMedia>(rule)) {
      if (MatchMediaForAddRules(medium, media_rule->MediaQueries())) {
        AddChildRules(parent_rule, media_rule->ChildRules(), medium,
                      add_rule_flags, container_query, cascade_layer,
                      style_scope, within_mixin);
      }
    } else if (auto* font_face_rule = DynamicTo<StyleRuleFontFace>(rule)) {
      font_face_rule->SetCascadeLayer(cascade_layer);
      AddFontFaceRule(font_face_rule);
    } else if (auto* font_palette_values_rule =
                   DynamicTo<StyleRuleFontPaletteValues>(rule)) {
      // TODO(https://crbug.com/1170794): Handle cascade layers for
      // @font-palette-values.
      AddFontPaletteValuesRule(font_palette_values_rule);
    } else if (auto* font_feature_values_rule =
                   DynamicTo<StyleRuleFontFeatureValues>(rule)) {
      font_feature_values_rule->SetCascadeLayer(cascade_layer);
      AddFontFeatureValuesRule(font_feature_values_rule);
    } else if (auto* keyframes_rule = DynamicTo<StyleRuleKeyframes>(rule)) {
      keyframes_rule->SetCascadeLayer(cascade_layer);
      AddKeyframesRule(keyframes_rule);
    } else if (auto* property_rule = DynamicTo<StyleRuleProperty>(rule)) {
      property_rule->SetCascadeLayer(cascade_layer);
      AddPropertyRule(property_rule);
    } else if (auto* counter_style_rule =
                   DynamicTo<StyleRuleCounterStyle>(rule)) {
      counter_style_rule->SetCascadeLayer(cascade_layer);
      AddCounterStyleRule(counter_style_rule);
    } else if (auto* view_transition_rule =
                   DynamicTo<StyleRuleViewTransition>(rule)) {
      view_transition_rule->SetCascadeLayer(cascade_layer);
      AddViewTransitionRule(view_transition_rule);
    } else if (auto* position_try_rule =
                   DynamicTo<StyleRulePositionTry>(rule)) {
      position_try_rule->SetCascadeLayer(cascade_layer);
      AddPositionTryRule(position_try_rule);
    } else if (auto* function_rule = DynamicTo<StyleRuleFunction>(rule)) {
      // TODO(sesse): Set the cascade layer here?
      AddFunctionRule(function_rule);
    } else if (auto* supports_rule = DynamicTo<StyleRuleSupports>(rule)) {
      if (supports_rule->ConditionIsSupported()) {
        AddChildRules(parent_rule, supports_rule->ChildRules(), medium,
                      add_rule_flags, container_query, cascade_layer,
                      style_scope, within_mixin);
      }
    } else if (auto* container_rule = DynamicTo<StyleRuleContainer>(rule)) {
      const ContainerQuery* inner_container_query =
          &container_rule->GetContainerQuery();
      if (container_query) {
        inner_container_query =
            inner_container_query->CopyWithParent(container_query);
      }
      AddChildRules(parent_rule, container_rule->ChildRules(), medium,
                    add_rule_flags, inner_container_query, cascade_layer,
                    style_scope, within_mixin);
    } else if (auto* layer_block_rule = DynamicTo<StyleRuleLayerBlock>(rule)) {
      CascadeLayer* sub_layer =
          GetOrAddSubLayer(cascade_layer, layer_block_rule->GetName());
      AddChildRules(parent_rule, layer_block_rule->ChildRules(), medium,
                    add_rule_flags, container_query, sub_layer, style_scope,
                    within_mixin);
    } else if (auto* layer_statement_rule =
                   DynamicTo<StyleRuleLayerStatement>(rule)) {
      for (const auto& layer_name : layer_statement_rule->GetNames()) {
        GetOrAddSubLayer(cascade_layer, layer_name);
      }
    } else if (auto* scope_rule = DynamicTo<StyleRuleScope>(rule)) {
      const StyleScope* inner_style_scope = &scope_rule->GetStyleScope();
      if (style_scope) {
        inner_style_scope = inner_style_scope->CopyWithParent(style_scope);
      }
      AddChildRules(parent_rule, scope_rule->ChildRules(), medium,
                    add_rule_flags, container_query, cascade_layer,
                    inner_style_scope, within_mixin);
    } else if (auto* starting_style_rule =
                   DynamicTo<StyleRuleStartingStyle>(rule)) {
      AddChildRules(parent_rule, starting_style_rule->ChildRules(), medium,
                    add_rule_flags | kRuleIsStartingStyle, container_query,
                    cascade_layer, style_scope, within_mixin);
    } else if (auto* mixin_rule = DynamicTo<StyleRuleMixin>(rule)) {
      mixins_.Set(mixin_rule->GetName(), mixin_rule);
    } else if (auto* apply_mixin_rule = DynamicTo<StyleRuleApplyMixin>(rule)) {
      // TODO(sesse): This lookup needs to work completely differently
      // if we are to support mixins from different stylesheets.
      // In particular, we need to implement tree-scoped lookups
      // in a situation where we don't have the normal ScopedStyleResolver
      // available, and also take into account that sharing RuleSets
      // won't really work if we cross-reference mixins from other sheets.
      auto it = mixins_.find(apply_mixin_rule->GetName());
      if (it != mixins_.end() && it->value->FakeParentRule().ChildRules()) {
        AddChildRules(parent_rule, *it->value->FakeParentRule().ChildRules(),
                      medium, add_rule_flags, container_query, cascade_layer,
                      style_scope, /*within_mixin=*/true);
      }
    } else if (auto* nested_declarations =
                   DynamicTo<StyleRuleNestedDeclarations>(rule)) {
      AddStyleRule(nested_declarations->InnerStyleRule(), parent_rule, medium,
                   add_rule_flags, within_mixin, container_query, cascade_layer,
                   style_scope);
    }
  }
}

bool RuleSet::MatchMediaForAddRules(const MediaQueryEvaluator& evaluator,
                                    const MediaQuerySet* media_queries) {
  if (!media_queries) {
    return true;
  }
  bool match_media =
      evaluator.Eval(*media_queries, &features_.MutableMediaQueryResultFlags());
  media_query_set_results_.push_back(
      MediaQuerySetResult(*media_queries, match_media));
  return match_media;
}

void RuleSet::AddRulesFromSheet(StyleSheetContents* sheet,
                                const MediaQueryEvaluator& medium,
                                CascadeLayer* cascade_layer,
                                const StyleScope* style_scope) {
  TRACE_EVENT0("blink", "RuleSet::addRulesFromSheet");
  DCHECK(sheet);

  for (const auto& pre_import_layer : sheet->PreImportLayerStatementRules()) {
    for (const auto& name : pre_import_layer->GetNames()) {
      GetOrAddSubLayer(cascade_layer, name);
    }
  }

  const HeapVector<Member<StyleRuleImport>>& import_rules =
      sheet->ImportRules();
  for (unsigned i = 0; i < import_rules.size(); ++i) {
    StyleRuleImport* import_rule = import_rules[i].Get();
    if (!import_rule->IsSupported()) {
      continue;
    }
    if (!MatchMediaForAddRules(medium, import_rule->MediaQueries())) {
      continue;
    }
    CascadeLayer* import_layer = cascade_layer;
    if (import_rule->IsLayered()) {
      import_layer =
          GetOrAddSubLayer(cascade_layer, import_rule->GetLayerName());
    }
    if (import_rule->GetStyleSheet()) {
      AddRulesFromSheet(import_rule->GetStyleSheet(), medium, import_layer,
                        import_rule->GetScope());
    }
  }

  AddChildRules(/*parent_rule=*/nullptr, sheet->ChildRules(), medium,
                kRuleHasNoSpecialState, nullptr /* container_query */,
                cascade_layer, style_scope, /*within_mixin=*/false);
}

// If there's a reference to the parent selector (implicit or explicit)
// somewhere in the selector, use that to find the parent StyleRule.
// If not, it's not relevant what the parent is anyway.
const StyleRule* FindParentIfUsed(const CSSSelector* selector) {
  do {
    if (selector->Match() == CSSSelector::kPseudoClass &&
        selector->GetPseudoType() == CSSSelector::kPseudoParent) {
      return selector->ParentRule();
    }
    if (selector->SelectorList() && selector->SelectorList()->First()) {
      const StyleRule* parent =
          FindParentIfUsed(selector->SelectorList()->First());
      if (parent != nullptr) {
        return parent;
      }
    }
  } while (!(selector++)->IsLastInSelectorList());
  return nullptr;
}

// Whether we should include the given rule (coming from a RuleSet)
// in a diff rule set, based on the list on “only_include” (which are
// the ones that have been modified). This is nominally only a simple
// membership test, but we also need to take into account nested rules;
// if a parent rule of ours has been modified, we need to also include
// this rule.
static bool IncludeRule(const StyleRule* style_rule,
                        const HeapHashSet<Member<StyleRule>>& only_include) {
  if (only_include.Contains(const_cast<StyleRule*>(style_rule))) {
    return true;
  }
  const StyleRule* parent_rule = FindParentIfUsed(style_rule->FirstSelector());
  if (parent_rule != nullptr) {
    return IncludeRule(parent_rule, only_include);
  } else {
    return false;
  }
}

void RuleSet::NewlyAddedFromDifferentRuleSet(const RuleData& old_rule_data,
                                             const StyleScope* style_scope,
                                             const RuleSet& old_rule_set,
                                             RuleData& new_rule_data) {
  new_rule_data.MovedToDifferentRuleSet(old_rule_set.bloom_hash_backing_,
                                        bloom_hash_backing_, rule_count_);
  // We don't bother with container_query_intervals_ and
  // AddRuleToLayerIntervals() here, since they are not checked in diff
  // rulesets.
  AddRuleToIntervals(style_scope, rule_count_, scope_intervals_);
  ++rule_count_;
}

void RuleSet::AddFilteredRulesFromOtherBucket(
    const RuleSet& other,
    const HeapVector<RuleData>& src,
    const HeapHashSet<Member<StyleRule>>& only_include,
    HeapVector<RuleData>* dst) {
  Seeker<StyleScope> scope_seeker(other.scope_intervals_);
  for (const RuleData& rule_data : src) {
    if (IncludeRule(rule_data.Rule(), only_include)) {
      dst->push_back(rule_data);
      NewlyAddedFromDifferentRuleSet(rule_data,
                                     scope_seeker.Seek(rule_data.GetPosition()),
                                     other, dst->back());
    }
  }
}

void RuleSet::AddFilteredRulesFromOtherSet(
    const RuleSet& other,
    const HeapHashSet<Member<StyleRule>>& only_include) {
  if (other.rule_count_ > 0) {
    id_rules_.AddFilteredRulesFromOtherSet(other.id_rules_, only_include, other,
                                           *this);
    class_rules_.AddFilteredRulesFromOtherSet(other.class_rules_, only_include,
                                              other, *this);
    attr_rules_.AddFilteredRulesFromOtherSet(other.attr_rules_, only_include,
                                             other, *this);
    // NOTE: attr_substring_matchers_ will be rebuilt in CompactRules().
    tag_rules_.AddFilteredRulesFromOtherSet(other.tag_rules_, only_include,
                                            other, *this);
    ua_shadow_pseudo_element_rules_.AddFilteredRulesFromOtherSet(
        other.ua_shadow_pseudo_element_rules_, only_include, other, *this);
    AddFilteredRulesFromOtherBucket(other, other.link_pseudo_class_rules_,
                                    only_include, &link_pseudo_class_rules_);
    AddFilteredRulesFromOtherBucket(other, other.cue_pseudo_rules_,
                                    only_include, &cue_pseudo_rules_);
    AddFilteredRulesFromOtherBucket(other, other.focus_pseudo_class_rules_,
                                    only_include, &focus_pseudo_class_rules_);
    AddFilteredRulesFromOtherBucket(
        other, other.focus_visible_pseudo_class_rules_, only_include,
        &focus_visible_pseudo_class_rules_);
    AddFilteredRulesFromOtherBucket(other, other.universal_rules_, only_include,
                                    &universal_rules_);
    AddFilteredRulesFromOtherBucket(other, other.shadow_host_rules_,
                                    only_include, &shadow_host_rules_);
    AddFilteredRulesFromOtherBucket(other, other.part_pseudo_rules_,
                                    only_include, &part_pseudo_rules_);
    AddFilteredRulesFromOtherBucket(other, other.slotted_pseudo_element_rules_,
                                    only_include,
                                    &slotted_pseudo_element_rules_);
    AddFilteredRulesFromOtherBucket(
        other, other.selector_fragment_anchor_rules_, only_include,
        &selector_fragment_anchor_rules_);
    AddFilteredRulesFromOtherBucket(other, other.root_element_rules_,
                                    only_include, &root_element_rules_);

    // We don't care about page_rules_ etc., since having those in a RuleSetDiff
    // would mark it as unrepresentable anyway.

    need_compaction_ = true;
  }

#if EXPENSIVE_DCHECKS_ARE_ON()
  allow_unsorted_ = true;
#endif
}

void RuleSet::AddStyleRule(StyleRule* style_rule,
                           StyleRule* parent_rule,
                           const MediaQueryEvaluator& medium,
                           AddRuleFlags add_rule_flags,
                           bool within_mixin,
                           const ContainerQuery* container_query,
                           CascadeLayer* cascade_layer,
                           const StyleScope* style_scope) {
  if (within_mixin) {
    style_rule = style_rule->Copy();
    style_rule->Reparent(parent_rule);
  }
  for (const CSSSelector* selector = style_rule->FirstSelector(); selector;
       selector = CSSSelectorList::Next(*selector)) {
    wtf_size_t selector_index = style_rule->SelectorIndex(*selector);
    AddRule(style_rule, selector_index, add_rule_flags, container_query,
            cascade_layer, style_scope);
  }

  // Nested rules are taken to be added immediately after their parent rule.
  if (style_rule->ChildRules() != nullptr) {
    AddChildRules(style_rule, *style_rule->ChildRules(), medium, add_rule_flags,
                  container_query, cascade_layer, style_scope, within_mixin);
  }
}

CascadeLayer* RuleSet::GetOrAddSubLayer(CascadeLayer* cascade_layer,
                                        const StyleRuleBase::LayerName& name) {
  if (!cascade_layer) {
    cascade_layer = EnsureImplicitOuterLayer();
  }
  return cascade_layer->GetOrAddSubLayer(name);
}

bool RuleMap::Add(const AtomicString& key, const RuleData& rule_data) {
  RuleMap::Extent* rules = nullptr;
  if (buckets.IsNull()) {
    // First insert.
    buckets = RobinHoodMap<AtomicString, Extent>(8);
  } else {
    // See if we can find an existing entry for this key.
    RobinHoodMap<AtomicString, Extent>::Bucket* bucket = buckets.Find(key);
    if (bucket != nullptr) {
      rules = &bucket->value;
    }
  }
  if (rules == nullptr) {
    RobinHoodMap<AtomicString, Extent>::Bucket* bucket = buckets.Insert(key);
    if (bucket == nullptr) {
      return false;
    }
    rules = &bucket->value;
    rules->bucket_number = num_buckets++;
  }

  RuleData rule_data_copy = rule_data;
  rule_data_copy.ComputeEntirelyCoveredByBucketing();
  bucket_number_.push_back(rules->bucket_number);
  ++rules->length;
  backing.push_back(std::move(rule_data_copy));
  return true;
}

void RuleMap::Compact() {
  if (compacted) {
    return;
  }
  if (backing.empty()) {
    DCHECK(bucket_number_.empty());
    // Nothing to do.
    compacted = true;
    return;
  }

  backing.shrink_to_fit();

  // Order by (bucket_number, order_in_bucket) by way of a simple
  // in-place counting sort (which is O(n), because our highest bucket
  // number is always less than or equal to the number of elements).
  // First, we make an array that contains the number of elements in each
  // bucket, indexed by the bucket number. We also find each element's
  // position within that bucket.
  auto counts =
      base::HeapArray<unsigned>::WithSize(num_buckets);  // Zero-initialized.
  auto order_in_bucket = base::HeapArray<unsigned>::Uninit(backing.size());
  for (wtf_size_t i = 0; i < bucket_number_.size(); ++i) {
    order_in_bucket[i] = counts[bucket_number_[i]]++;
  }

  // Do the prefix sum. After this, counts[i] is the desired start index
  // for the i-th bucket.
  unsigned sum = 0;
  for (wtf_size_t i = 0; i < num_buckets; ++i) {
    DCHECK_GT(counts[i], 0U);
    unsigned new_sum = sum + counts[i];
    counts[i] = sum;
    sum = new_sum;
  }

  // Store that information into each bucket.
  for (auto& [key, value] : buckets) {
    value.start_index = counts[value.bucket_number];
  }

  // Now put each element into its right place. Every iteration, we will
  // either swap an element into its final destination, or, when we
  // encounter one that is already in its correct place (possibly
  // because we put it there earlier), skip to the next array slot.
  // These will happen exactly n times each, giving us our O(n) runtime.
  for (wtf_size_t i = 0; i < backing.size();) {
    wtf_size_t correct_pos = counts[bucket_number_[i]] + order_in_bucket[i];
    if (i == correct_pos) {
      ++i;
    } else {
      using std::swap;
      swap(backing[i], backing[correct_pos]);
      swap(bucket_number_[i], bucket_number_[correct_pos]);
      swap(order_in_bucket[i], order_in_bucket[correct_pos]);
    }
  }

  // We're done with the bucket numbers, so we can release the memory.
  // If we need the bucket numbers again, they will be reconstructed by
  // RuleMap::Uncompact.
  bucket_number_.clear();

  compacted = true;
}

void RuleMap::Uncompact() {
  bucket_number_.resize(backing.size());

  num_buckets = 0;
  for (auto& [key, value] : buckets) {
    for (unsigned& bucket_number : GetBucketNumberFromExtent(value)) {
      bucket_number = num_buckets;
    }
    value.bucket_number = num_buckets++;
    value.length =
        static_cast<unsigned>(GetBucketNumberFromExtent(value).size());
  }
  compacted = false;
}

// See RuleSet::AddFilteredRulesFromOtherSet().
void RuleMap::AddFilteredRulesFromOtherSet(
    const RuleMap& other,
    const HeapHashSet<Member<StyleRule>>& only_include,
    const RuleSet& old_rule_set,
    RuleSet& new_rule_set) {
  if (compacted) {
    Uncompact();
  }
  if (other.compacted) {
    for (const auto& [key, extent] : other.buckets) {
      Seeker<StyleScope> scope_seeker(old_rule_set.scope_intervals_);
      for (const RuleData& rule_data : other.GetRulesFromExtent(extent)) {
        if (IncludeRule(rule_data.Rule(), only_include)) {
          Add(key, rule_data);
          new_rule_set.NewlyAddedFromDifferentRuleSet(
              rule_data, scope_seeker.Seek(rule_data.GetPosition()),
              old_rule_set, backing.back());
        }
      }
    }
  } else {
    // First make a mapping of bucket number to key.
    auto keys = base::HeapArray<const AtomicString*>::Uninit(other.num_buckets);
    for (const auto& [key, src_extent] : other.buckets) {
      keys[src_extent.bucket_number] = &key;
    }

    // Now that we have the mapping, we can just copy over all the relevant
    // RuleDatas.
    Seeker<StyleScope> scope_seeker(old_rule_set.scope_intervals_);
    for (wtf_size_t i = 0; i < other.backing.size(); ++i) {
      const unsigned bucket_number = other.bucket_number_[i];
      const RuleData& rule_data = other.backing[i];
      if (IncludeRule(rule_data.Rule(), only_include)) {
        Add(*keys[bucket_number], rule_data);
        new_rule_set.NewlyAddedFromDifferentRuleSet(
            rule_data, scope_seeker.Seek(rule_data.GetPosition()), old_rule_set,
            backing.back());
      }
    }
  }
}

static wtf_size_t GetMinimumRulesetSizeForSubstringMatcher() {
  // It's not worth going through the Aho-Corasick matcher unless we can
  // reject a reasonable number of rules in one go. Practical ad-hoc testing
  // suggests the break-even point between using the tree and just testing
  // all of the rules individually lies somewhere around 20–40 rules
  // (depending a bit on e.g. how hot the tree is in the cache, the length
  // of the value that we match against, and of course whether we actually
  // have a match). We add a little bit of margin to compensate for the fact
  // that we also need to spend time building the tree, and the extra memory
  // in use.
  return 50;
}

bool RuleSet::CanIgnoreEntireList(base::span<const RuleData> list,
                                  const AtomicString& key,
                                  const AtomicString& value) const {
  DCHECK_EQ(attr_rules_.Find(key).size(), list.size());
  if (!list.empty()) {
    DCHECK_EQ(attr_rules_.Find(key).data(), list.data());
  }
  if (list.size() < GetMinimumRulesetSizeForSubstringMatcher()) {
    // Too small to build up a tree, so always check.
    DCHECK(!base::Contains(attr_substring_matchers_, key));
    return false;
  }

  // See CreateSubstringMatchers().
  if (value.empty()) {
    return false;
  }

  auto it = attr_substring_matchers_.find(key);
  if (it == attr_substring_matchers_.end()) {
    // Building the tree failed, so always check.
    return false;
  }
  return !it->value->AnyMatch(value.LowerASCII().Utf8());
}

void RuleSet::CreateSubstringMatchers(
    RuleMap& attr_map,
    const HeapVector<Interval<StyleScope>>& scope_intervals,
    RuleSet::SubstringMatcherMap& substring_matcher_map) {
  for (const auto& [/*AtomicString*/ attr,
                    /*base::span<const RuleData>*/ ruleset] : attr_map) {
    if (ruleset.size() < GetMinimumRulesetSizeForSubstringMatcher()) {
      continue;
    }
    std::vector<MatcherStringPattern> patterns;
    int rule_index = 0;
    Seeker<StyleScope> scope_seeker(scope_intervals);
    for (const RuleData& rule : ruleset) {
      AtomicString id;
      AtomicString class_name;
      AtomicString attr_name;
      AtomicString attr_value;
      AtomicString custom_pseudo_element_name;
      AtomicString tag_name;
      AtomicString part_name;
      AtomicString picker_name;
      bool is_exact_attr;
      CSSSelector::PseudoType pseudo_type = CSSSelector::kPseudoUnknown;
      const StyleScope* style_scope = scope_seeker.Seek(rule.GetPosition());
      ExtractBestSelectorValues(rule.Selector(), style_scope, id, class_name,
                                attr_name, attr_value, is_exact_attr,
                                custom_pseudo_element_name, tag_name, part_name,
                                picker_name, pseudo_type);
      DCHECK(!attr_name.empty());

      if (attr_value.empty()) {
        if (is_exact_attr) {
          // The empty string would make the entire tree useless
          // (it is a substring of every possible value),
          // so as a special case, we ignore it, and have a separate
          // check in CanIgnoreEntireList().
          continue;
        } else {
          // This rule would indeed match every element containing the
          // given attribute (e.g. [foo] or [foo^=""]), so building a tree
          // would be wrong.
          patterns.clear();
          break;
        }
      }

      std::string pattern = attr_value.LowerASCII().Utf8();

      // SubstringSetMatcher doesn't like duplicates, and since we only
      // use the tree for true/false information anyway, we can remove them.
      bool already_exists =
          any_of(patterns.begin(), patterns.end(),
                 [&pattern](const MatcherStringPattern& existing_pattern) {
                   return existing_pattern.pattern() == pattern;
                 });
      if (!already_exists) {
        patterns.emplace_back(pattern, rule_index);
      }
      ++rule_index;
    }

    if (patterns.empty()) {
      continue;
    }

    auto substring_matcher = std::make_unique<SubstringSetMatcher>();
    if (!substring_matcher->Build(patterns)) {
      // Should never really happen unless there are megabytes and megabytes
      // of such classes, so we just drop out to the slow path.
    } else {
      substring_matcher_map.insert(attr, std::move(substring_matcher));
    }
  }
}

void RuleSet::CompactRules() {
  DCHECK(need_compaction_);
  id_rules_.Compact();
  class_rules_.Compact();
  attr_rules_.Compact();
  CreateSubstringMatchers(attr_rules_, scope_intervals_,
                          attr_substring_matchers_);
  tag_rules_.Compact();
  ua_shadow_pseudo_element_rules_.Compact();
  link_pseudo_class_rules_.shrink_to_fit();
  cue_pseudo_rules_.shrink_to_fit();
  focus_pseudo_class_rules_.shrink_to_fit();
  selector_fragment_anchor_rules_.shrink_to_fit();
  focus_visible_pseudo_class_rules_.shrink_to_fit();
  universal_rules_.shrink_to_fit();
  shadow_host_rules_.shrink_to_fit();
  part_pseudo_rules_.shrink_to_fit();
  slotted_pseudo_element_rules_.shrink_to_fit();
  page_rules_.shrink_to_fit();
  font_face_rules_.shrink_to_fit();
  font_palette_values_rules_.shrink_to_fit();
  keyframes_rules_.shrink_to_fit();
  property_rules_.shrink_to_fit();
  counter_style_rules_.shrink_to_fit();
  position_try_rules_.shrink_to_fit();
  layer_intervals_.shrink_to_fit();
  view_transition_rules_.shrink_to_fit();
  bloom_hash_backing_.shrink_to_fit();

#if EXPENSIVE_DCHECKS_ARE_ON()
  if (!allow_unsorted_) {
    AssertRuleListsSorted();
  }
#endif
  need_compaction_ = false;
}

#if EXPENSIVE_DCHECKS_ARE_ON()

namespace {

// Rules that depend on visited link status may be added twice to the same
// bucket (with different LinkMatchTypes).
bool AllowSamePosition(const RuleData& current, const RuleData& previous) {
  return current.LinkMatchType() != previous.LinkMatchType();
}

template <class RuleList>
bool IsRuleListSorted(const RuleList& rules) {
  const RuleData* last_rule = nullptr;
  for (const RuleData& rule : rules) {
    if (last_rule) {
      if (rule.GetPosition() == last_rule->GetPosition()) {
        if (!AllowSamePosition(rule, *last_rule)) {
          return false;
        }
      }
      if (rule.GetPosition() < last_rule->GetPosition()) {
        return false;
      }
    }
    last_rule = &rule;
  }
  return true;
}

}  // namespace

void RuleSet::AssertRuleListsSorted() const {
  for (const auto& item : id_rules_) {
    DCHECK(IsRuleListSorted(item.value));
  }
  for (const auto& item : class_rules_) {
    DCHECK(IsRuleListSorted(item.value));
  }
  for (const auto& item : tag_rules_) {
    DCHECK(IsRuleListSorted(item.value));
  }
  for (const auto& item : ua_shadow_pseudo_element_rules_) {
    DCHECK(IsRuleListSorted(item.value));
  }
  DCHECK(IsRuleListSorted(link_pseudo_class_rules_));
  DCHECK(IsRuleListSorted(cue_pseudo_rules_));
  DCHECK(IsRuleListSorted(focus_pseudo_class_rules_));
  DCHECK(IsRuleListSorted(selector_fragment_anchor_rules_));
  DCHECK(IsRuleListSorted(focus_visible_pseudo_class_rules_));
  DCHECK(IsRuleListSorted(universal_rules_));
  DCHECK(IsRuleListSorted(shadow_host_rules_));
  DCHECK(IsRuleListSorted(part_pseudo_rules_));
}

#endif  // EXPENSIVE_DCHECKS_ARE_ON()

bool RuleSet::DidMediaQueryResultsChange(
    const MediaQueryEvaluator& evaluator) const {
  return evaluator.DidResultsChange(media_query_set_results_);
}

const CascadeLayer* RuleSet::GetLayerForTest(const RuleData& rule) const {
  if (!layer_intervals_.size() ||
      layer_intervals_[0].start_position > rule.GetPosition()) {
    return implicit_outer_layer_.Get();
  }
  for (unsigned i = 1; i < layer_intervals_.size(); ++i) {
    if (layer_intervals_[i].start_position > rule.GetPosition()) {
      return layer_intervals_[i - 1].value.Get();
    }
  }
  return layer_intervals_.back().value.Get();
}

void RuleData::Trace(Visitor* visitor) const {
  visitor->Trace(rule_);
}

template <class T>
void RuleSet::Interval<T>::Trace(Visitor* visitor) const {
  visitor->Trace(value);
}

void RuleSet::Trace(Visitor* visitor) const {
  visitor->Trace(id_rules_);
  visitor->Trace(class_rules_);
  visitor->Trace(attr_rules_);
  visitor->Trace(tag_rules_);
  visitor->Trace(ua_shadow_pseudo_element_rules_);
  visitor->Trace(link_pseudo_class_rules_);
  visitor->Trace(cue_pseudo_rules_);
  visitor->Trace(focus_pseudo_class_rules_);
  visitor->Trace(selector_fragment_anchor_rules_);
  visitor->Trace(focus_visible_pseudo_class_rules_);
  visitor->Trace(universal_rules_);
  visitor->Trace(shadow_host_rules_);
  visitor->Trace(part_pseudo_rules_);
  visitor->Trace(slotted_pseudo_element_rules_);
  visitor->Trace(page_rules_);
  visitor->Trace(font_face_rules_);
  visitor->Trace(font_palette_values_rules_);
  visitor->Trace(font_feature_values_rules_);
  visitor->Trace(view_transition_rules_);
  visitor->Trace(keyframes_rules_);
  visitor->Trace(property_rules_);
  visitor->Trace(counter_style_rules_);
  visitor->Trace(position_try_rules_);
  visitor->Trace(function_rules_);
  visitor->Trace(root_element_rules_);
  visitor->Trace(media_query_set_results_);
  visitor->Trace(implicit_outer_layer_);
  visitor->Trace(layer_intervals_);
  visitor->Trace(container_query_intervals_);
  visitor->Trace(scope_intervals_);
  visitor->Trace(mixins_);
#if DCHECK_IS_ON()
  visitor->Trace(all_rules_);
#endif  // DCHECK_IS_ON()
}

#if DCHECK_IS_ON()
void RuleSet::Show() const {
  for (const RuleData& rule : all_rules_) {
    rule.Selector().Show();
  }
}
#endif  // DCHECK_IS_ON()

}  // namespace blink

"""


```