Response:
My thought process for analyzing the `element_rule_collector.cc` code snippet goes like this:

1. **Understand the Context:** The file path `blink/renderer/core/css/element_rule_collector.cc` immediately tells me this code is part of the Blink rendering engine, specifically within the CSS module. The name `element_rule_collector` strongly suggests its purpose is to gather CSS rules that apply to a specific element.

2. **Identify Key Data Structures:** I scan the included headers and the code itself for important data structures. I see:
    * `ElementResolveContext`:  Information about the element being styled.
    * `StyleRecalcContext`:  Context for the style recalculation process.
    * `SelectorFilter`:  Used for optimizing rule matching.
    * `MatchResult`:  Stores the collected matching rules and related information.
    * `StyleRuleList`, `RuleIndexList`:  Containers for the matched rules.
    * `CSSStyleSheet`, `CSSStyleRule`, etc.:  Representations of CSS rules and stylesheets.
    * `SelectorChecker`: The core component for determining if a selector matches an element.
    * `RuleData`:  Internal representation of a CSS rule.
    * `MatchRequest`:  Specifies the criteria for matching rules.

3. **Analyze the Core Functionality:** I look for the main functions and their roles:
    * **Constructor:** Takes the element and context information as input, initializing the collector.
    * **`CollectMatchingRules`:**  This is the central function. It iterates through stylesheets and rules, using the `SelectorChecker` to see if a rule applies to the element.
    * **`CheckIfAnyRuleMatches`:** A specialized version of `CollectMatchingRules` that stops after finding the first matching rule.
    * **`AddElementStyleProperties`, `AddTryStyleProperties`, `AddTryTacticsStyleProperties`:** These likely handle inline styles and specific "try" styles used in layout algorithms.
    * **Helper functions (e.g., `FindStyleSheet`, `AdjustLinkMatchType`, `EvaluateAndAddContainerQueries`):** These perform supporting tasks in the rule collection process.

4. **Infer Relationships with Web Technologies:**  Based on the functionality and the included headers, I can infer the relationships with HTML, CSS, and JavaScript:
    * **HTML:** The collector operates on `Element` objects, which are fundamental to the HTML DOM. It needs information about the element's tag, ID, classes, attributes, and parentage in the DOM tree.
    * **CSS:** The core purpose is to process CSS rules (`CSSStyleRule`, `CSSMediaRule`, etc.) and determine which ones apply to an element based on its properties and the selectors in the CSS rules.
    * **JavaScript:** While this specific file might not directly interact with JavaScript, the overall styling process in the browser is influenced by JavaScript. JavaScript can dynamically modify the DOM and CSS styles, triggering style recalculations that involve this collector.

5. **Look for Logic and Decision Points:**  I identify key logic within the code:
    * **Selector Matching:** The `SelectorChecker` is the heart of the matching process, comparing CSS selectors against the element.
    * **Specificity and Cascade:** The order in which rules are collected and the presence of cascade layers (indicated by `CascadeLayerSeeker`) suggest this code is involved in the CSS cascade.
    * **Performance Optimizations:** The use of `SelectorFilter`, "fast reject" mechanisms, and potentially bucketing techniques indicate an effort to optimize the rule matching process.
    * **Container Queries:** The presence of `ContainerQueryEvaluator` shows support for CSS container queries.
    * **Pseudo-elements:** The code handles matching rules for pseudo-elements (e.g., `::before`, `::after`).

6. **Consider Potential Errors and Debugging:**  I think about how a developer might end up in this code during debugging:
    * **Incorrect Styling:**  If an element isn't styled as expected, a developer might trace the style calculation process, potentially stepping into this code.
    * **Performance Issues:** Slow style recalculations could lead to inspecting this code to identify bottlenecks.
    * **Selector Issues:** Problems with CSS selectors not matching correctly would also lead here.

7. **Structure the Explanation:**  I organize my findings into categories like:
    * **Core Functionality:**  A high-level overview of the file's purpose.
    * **Relationship to Web Technologies:** Specific examples of how it interacts with HTML, CSS, and JavaScript.
    * **Logic and Reasoning:**  Explaining the algorithms and decision-making processes.
    * **User/Programming Errors:** Illustrating common mistakes that might lead to issues involving this code.
    * **Debugging:**  Describing how a developer might reach this code while debugging.

8. **Refine and Elaborate:**  I expand on the initial points, providing more detail and specific examples where necessary. For instance, when discussing CSS, I mention different types of CSS rules. When talking about debugging, I provide concrete scenarios.

By following this systematic approach, I can effectively analyze the given code snippet and generate a comprehensive explanation of its functionality and its role within the larger context of the Blink rendering engine.
好的，这是对 `blink/renderer/core/css/element_rule_collector.cc` 文件第一部分的分析和功能归纳：

**功能概述**

`element_rule_collector.cc` 文件的核心功能是**收集适用于特定 HTML 元素的 CSS 规则**。它负责遍历各种来源的 CSS 规则（如样式表、内联样式等），并使用选择器匹配算法来确定哪些规则与当前元素匹配。匹配到的规则会被存储起来，用于后续计算元素的最终样式。

**与 JavaScript, HTML, CSS 的关系及举例**

* **HTML:** 该文件处理的对象是 HTML 元素 (`Element` 类)。它需要访问元素的各种属性（如 id、class、标签名）和它在 DOM 树中的位置，以便进行选择器匹配。
    * **例子:** 当浏览器解析到 `<div id="container" class="main">` 这个 HTML 元素时，`ElementRuleCollector` 会被调用来查找适用于该 div 元素的 CSS 规则。

* **CSS:** 这是该文件最直接关联的技术。它解析和评估 CSS 规则 (`CSSStyleRule`, `CSSMediaRule` 等)，并使用 CSS 选择器 (`CSSSelector`) 来判断规则是否与当前元素匹配。
    * **例子:** 对于 CSS 规则 `#container { width: 100px; }`，`ElementRuleCollector` 会检查当前元素是否具有 `id="container"`。如果匹配，则该规则会被收集。
    * **例子:** 对于 CSS 规则 `.main { color: blue; }`，`ElementRuleCollector` 会检查当前元素是否包含 `class="main"`。如果匹配，则该规则会被收集。

* **JavaScript:** 虽然该文件本身主要是 C++ 代码，但它参与了浏览器渲染引擎的核心流程，而 JavaScript 可以通过 DOM API 和 CSSOM API 来影响元素的样式和 CSS 规则。
    * **例子:** 当 JavaScript 代码使用 `element.style.backgroundColor = 'red'` 修改元素的内联样式时，`ElementRuleCollector` 在收集规则时会考虑这些内联样式。
    * **例子:** 当 JavaScript 代码使用 `document.styleSheets` API 添加或修改样式表时，这些改变会影响 `ElementRuleCollector` 需要遍历的规则集合。

**逻辑推理 (假设输入与输出)**

假设输入一个 `div` 元素，其 `id` 为 "myDiv"，`class` 为 "content"，并且存在以下 CSS 规则：

```css
#myDiv {
  font-size: 16px;
}

.content {
  color: green;
}

div {
  padding: 10px;
}
```

**假设输入:**  一个指向 `div` 元素的指针，该元素的 `id` 为 "myDiv"，`class` 为 "content"。

**预期输出:**  `ElementRuleCollector` 将收集到以下 CSS 规则（或指向这些规则的引用）：

1. `#myDiv { font-size: 16px; }` (因为元素的 `id` 与选择器匹配)
2. `.content { color: green; }` (因为元素的 `class` 与选择器匹配)
3. `div { padding: 10px; }` (因为元素标签名与选择器匹配)

**用户或编程常见的使用错误 (导致问题或需要调试)**

1. **CSS 选择器错误:**  CSS 选择器写得不正确，导致预期的规则没有被匹配到。
    * **例子:** 用户错误地写成 `#myDivv` 而不是 `#myDiv`，导致 `#myDiv` 的样式没有应用。

2. **样式表加载顺序问题:**  样式表的加载顺序会影响层叠规则的应用。如果样式表加载顺序不正确，可能会导致某些规则被覆盖。
    * **例子:** 用户在 HTML 中先引入了一个通用的样式表，然后引入了一个更具体的样式表，但由于加载顺序问题，通用的样式覆盖了更具体的样式。

3. **特异性 (Specificity) 理解错误:**  对 CSS 选择器的特异性理解不足，导致不清楚哪个规则会最终生效。
    * **例子:** 用户同时定义了 `#myDiv { color: red; }` 和 `.content { color: blue; }`，但因为 `#myDiv` 的特异性更高，所以元素最终会显示红色，用户可能期望的是蓝色。

4. **内联样式覆盖:**  不小心使用了内联样式，覆盖了样式表中的规则，但没有意识到。
    * **例子:** 用户在 HTML 中写了 `<div style="color: orange;">`，即使样式表中有针对该 div 的其他颜色定义，内联样式也会生效。

**用户操作如何一步步到达这里 (作为调试线索)**

1. **用户加载网页:** 用户在浏览器中输入网址或点击链接，浏览器开始加载 HTML、CSS 和 JavaScript 资源。
2. **HTML 解析和 DOM 构建:** 浏览器解析 HTML 标记，构建 DOM (文档对象模型) 树。
3. **CSS 解析:** 浏览器解析加载的 CSS 样式表。
4. **样式计算 (Style Calculation):**  当浏览器需要渲染页面或响应样式变化时，会触发样式计算。`ElementRuleCollector` 在这个阶段被调用。
5. **遍历 DOM 树:**  浏览器会遍历 DOM 树中的每个元素。
6. **调用 `ElementRuleCollector`:** 对于每个元素，浏览器会创建或使用 `ElementRuleCollector` 的实例。
7. **规则匹配:** `ElementRuleCollector` 遍历可用的 CSS 规则，并使用选择器匹配算法来判断哪些规则适用于当前元素。
8. **存储匹配的规则:** 匹配到的规则会被存储在 `MatchResult` 或类似的结构中。
9. **计算最终样式:**  基于收集到的规则（以及考虑优先级、层叠等因素），计算出元素的最终样式。
10. **布局和渲染:**  浏览器根据计算出的样式信息对页面进行布局和渲染。

**作为调试线索:**  如果开发者发现某个元素的样式不符合预期，他们可能会使用浏览器的开发者工具来检查：

*   **元素的 computed style (计算样式):**  查看浏览器最终应用到元素上的样式，这反映了 `ElementRuleCollector` 的结果。
*   **元素的 rules (规则):**  查看哪些 CSS 规则匹配到了该元素，以及它们的来源和优先级。这可以帮助开发者理解 `ElementRuleCollector` 的工作过程，并找到错误的规则或匹配逻辑。
*   **断点调试:**  如果开发者需要深入了解 `ElementRuleCollector` 的具体行为，他们可能会在 Blink 渲染引擎的源代码中设置断点，例如在 `CollectMatchingRules` 函数中，来跟踪代码执行流程，查看哪些规则被匹配，哪些被排除。

**功能归纳 (第 1 部分)**

到目前为止的代码主要负责 `ElementRuleCollector` 的初始化、基本数据结构定义、以及一些辅助函数的实现。核心功能是为给定的元素收集匹配的 CSS 规则。 它涉及到：

*   **类定义和构造:** 定义了 `ElementRuleCollector` 类，用于收集规则。
*   **数据成员:** 包含用于存储匹配结果、上下文信息（如 `ElementResolveContext`, `StyleRecalcContext`）以及选择器过滤器的成员变量。
*   **辅助函数:**  定义了一些辅助函数，例如 `FindStyleSheet` (查找规则所属的样式表), `AdjustLinkMatchType` (调整链接匹配类型), `EvaluateAndAddContainerQueries` (评估和添加容器查询结果) 等。
*   **性能优化相关:**  包含一些用于性能统计和优化的代码，例如 `CumulativeRulePerfKey` 和相关的性能数据结构，以及对选择器快速拒绝的初步处理。
*   **与 Web 标准的关联:**  通过引入各种 CSS 相关的类，表明了其与 CSS 规范的紧密联系。

总结来说，这部分代码是 `ElementRuleCollector` 的基础框架，为后续的规则匹配和收集逻辑奠定了基础。

Prompt: 
```
这是目录为blink/renderer/core/css/element_rule_collector.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 2004-2005 Allan Sandfeld Jensen (kde@carewolf.com)
 * Copyright (C) 2006, 2007 Nicholas Shanks (webkit@nickshanks.com)
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013 Apple Inc.
 * All rights reserved.
 * Copyright (C) 2007 Alexey Proskuryakov <ap@webkit.org>
 * Copyright (C) 2007, 2008 Eric Seidel <eric@webkit.org>
 * Copyright (C) 2008, 2009 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
 * Copyright (c) 2011, Code Aurora Forum. All rights reserved.
 * Copyright (C) Research In Motion Limited 2011. All rights reserved.
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */
#include "third_party/blink/renderer/core/css/element_rule_collector.h"

#include <utility>

#include "base/containers/span.h"
#include "base/substring_set_matcher/substring_set_matcher.h"
#include "base/trace_event/common/trace_event_common.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-shared.h"
#include "third_party/blink/renderer/core/css/cascade_layer_map.h"
#include "third_party/blink/renderer/core/css/check_pseudo_has_cache_scope.h"
#include "third_party/blink/renderer/core/css/container_query_evaluator.h"
#include "third_party/blink/renderer/core/css/css_import_rule.h"
#include "third_party/blink/renderer/core/css/css_keyframes_rule.h"
#include "third_party/blink/renderer/core/css/css_media_rule.h"
#include "third_party/blink/renderer/core/css/css_nested_declarations_rule.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_rule_list.h"
#include "third_party/blink/renderer/core/css/css_selector.h"
#include "third_party/blink/renderer/core/css/css_style_rule.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/css_supports_rule.h"
#include "third_party/blink/renderer/core/css/resolver/element_resolve_context.h"
#include "third_party/blink/renderer/core/css/resolver/scoped_style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_stats.h"
#include "third_party/blink/renderer/core/css/resolver/style_rule_usage_tracker.h"
#include "third_party/blink/renderer/core/css/seeker.h"
#include "third_party/blink/renderer/core/css/selector_checker-inl.h"
#include "third_party/blink/renderer/core/css/selector_statistics.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_rule_nested_declarations.h"
#include "third_party/blink/renderer/core/dom/layout_tree_builder_traversal.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/page/scrolling/fragment_anchor.h"
#include "third_party/blink/renderer/core/style/computed_style.h"

namespace blink {
namespace {

struct CumulativeRulePerfKey {
  String selector;
  String style_sheet_id;
  CumulativeRulePerfKey(const String& selector, const String& style_sheet_id)
      : selector(selector), style_sheet_id(style_sheet_id) {}
};

struct ContextWithStyleScopeFrame {
  STACK_ALLOCATED();

 public:
  ContextWithStyleScopeFrame(const ElementResolveContext& element_context,
                             const MatchRequest& match_request,
                             StyleRequest* pseudo_style_request,
                             StyleScopeFrame* parent_frame)
      : style_scope_frame(element_context.GetUltimateOriginatingElementOrSelf(),
                          parent_frame),
        context(element_context) {
    context.style_scope_frame = &style_scope_frame.GetParentFrameOrThis(
        element_context.GetUltimateOriginatingElementOrSelf());
    context.scope = match_request.Scope();
    context.pseudo_id = pseudo_style_request->pseudo_id;
    context.pseudo_argument = &pseudo_style_request->pseudo_argument;
    context.vtt_originating_element = match_request.VTTOriginatingElement();
    switch (pseudo_style_request->search_text_request) {
      case StyleRequest::kNone:
        DCHECK_NE(context.pseudo_id, kPseudoIdSearchText);
        break;
      case StyleRequest::kCurrent:
        context.search_text_request_is_current = true;
        break;
      case StyleRequest::kNotCurrent:
        context.search_text_request_is_current = false;
        break;
      default:
        NOTREACHED();
    }
  }

  // This StyleScopeFrame is effectively ignored if the StyleRecalcContext
  // provides StyleScopeFrame already (see call to GetParentFrameOrThis above).
  // This happens e.g. when we need to collect matching rules for inspector
  // purposes.
  StyleScopeFrame style_scope_frame;
  SelectorChecker::SelectorCheckingContext context;
};

}  // namespace
}  // namespace blink

namespace WTF {
template <>
struct HashTraits<blink::CumulativeRulePerfKey>
    : TwoFieldsHashTraits<blink::CumulativeRulePerfKey,
                          &blink::CumulativeRulePerfKey::selector,
                          &blink::CumulativeRulePerfKey::style_sheet_id> {};
}  // namespace WTF

namespace blink {

template <class CSSRuleCollection>
static CSSRule* FindStyleRule(CSSRuleCollection* css_rules,
                              const StyleRule* style_rule);

namespace {

const CSSStyleSheet* FindStyleSheet(const TreeScope* tree_scope_containing_rule,
                                    const StyleEngine& style_engine,
                                    const StyleRule* rule) {
  if (tree_scope_containing_rule) {
    for (const auto& [sheet, rule_set] :
         tree_scope_containing_rule->GetScopedStyleResolver()
             ->GetActiveStyleSheets()) {
      if (FindStyleRule(sheet.Get(), rule) != nullptr) {
        return sheet.Get();
      }
    }
  }
  for (const auto& [sheet, rule_set] : style_engine.ActiveUserStyleSheets()) {
    if (FindStyleRule(sheet.Get(), rule) != nullptr) {
      return sheet.Get();
    }
  }

  return nullptr;  // Not found (e.g., the rule is from an UA style sheet).
}

unsigned AdjustLinkMatchType(EInsideLink inside_link,
                             unsigned link_match_type) {
  if (inside_link == EInsideLink::kNotInsideLink) {
    return CSSSelector::kMatchLink;
  }
  return link_match_type;
}

unsigned LinkMatchTypeFromInsideLink(EInsideLink inside_link) {
  switch (inside_link) {
    case EInsideLink::kNotInsideLink:
      return CSSSelector::kMatchAll;
    case EInsideLink::kInsideVisitedLink:
      return CSSSelector::kMatchVisited;
    case EInsideLink::kInsideUnvisitedLink:
      return CSSSelector::kMatchLink;
  }
}

bool EvaluateAndAddContainerQueries(
    Element* style_container_candidate,
    const ContainerQuery& container_query,
    const StyleRecalcContext& style_recalc_context,
    ContainerSelectorCache& container_selector_cache,
    MatchResult& result) {
  for (const ContainerQuery* current = &container_query; current;
       current = current->Parent()) {
    if (!ContainerQueryEvaluator::EvalAndAdd(
            style_container_candidate, style_recalc_context, *current,
            container_selector_cache, result)) {
      return false;
    }
  }

  return true;
}

bool AffectsAnimations(const RuleData& rule_data) {
  const CSSPropertyValueSet& properties = rule_data.Rule()->Properties();
  unsigned count = properties.PropertyCount();
  for (unsigned i = 0; i < count; ++i) {
    auto reference = properties.PropertyAt(i);
    CSSPropertyID id = reference.Id();
    if (id == CSSPropertyID::kAll) {
      return true;
    }
    if (id == CSSPropertyID::kVariable) {
      continue;
    }
    if (CSSProperty::Get(id).IsAnimationProperty()) {
      return true;
    }
  }
  return false;
}

// A wrapper around Seeker<CascadeLayer> that also translates through the layer
// map.
class CascadeLayerSeeker {
  STACK_ALLOCATED();

 public:
  CascadeLayerSeeker(const ContainerNode* scope,
                     Element* vtt_originating_element,
                     bool matching_ua_rules,
                     bool matching_rules_from_no_style_sheet,
                     const Document* document,
                     const RuleSet* rule_set)
      : seeker_(rule_set->LayerIntervals()),
        layer_map_(FindLayerMap(scope,
                                vtt_originating_element,
                                matching_ua_rules,
                                matching_rules_from_no_style_sheet,
                                document)) {}

  uint16_t SeekLayerOrder(unsigned rule_position) {
    if (!layer_map_) {
      return CascadeLayerMap::kImplicitOuterLayerOrder;
    }

    const CascadeLayer* layer = seeker_.Seek(rule_position);
    if (layer == nullptr) {
      return CascadeLayerMap::kImplicitOuterLayerOrder;
    } else {
      return layer_map_->GetLayerOrder(*layer);
    }
  }

 private:
  static const CascadeLayerMap* FindLayerMap(
      const ContainerNode* scope,
      Element* vtt_originating_element,
      bool matching_ua_rules,
      bool matching_rules_from_no_style_sheet,
      const Document* document) {
    // VTT embedded style is not in any layer.
    if (vtt_originating_element) {
      return nullptr;
    }
    // Assume there are no UA cascade layers, so we only check user layers.
    if (matching_ua_rules || matching_rules_from_no_style_sheet) {
      return nullptr;
    }
    if (scope) {
      DCHECK(scope->IsInTreeScope());
      DCHECK(scope->GetTreeScope().GetScopedStyleResolver());
      return scope->GetTreeScope()
          .GetScopedStyleResolver()
          ->GetCascadeLayerMap();
    }
    if (!document) {
      return nullptr;
    }
    return document->GetStyleEngine().GetUserCascadeLayerMap();
  }

  Seeker<CascadeLayer> seeker_;
  const CascadeLayerMap* layer_map_ = nullptr;
};

// The below `rule_map` is designed to aggregate the following values per-rule
// between calls to `DumpAndClearRulesPerfMap`. This is currently done at the
// UpdateStyleAndLayoutTreeForThisDocument level, which yields the statistics
// aggregated across each style recalc pass.
struct CumulativeRulePerfData {
  int match_attempts;
  int fast_reject_count;
  int match_count;
  base::TimeDelta elapsed;
};

using SelectorStatisticsRuleMap =
    HashMap<CumulativeRulePerfKey, CumulativeRulePerfData>;
SelectorStatisticsRuleMap& GetSelectorStatisticsRuleMap() {
  DEFINE_STATIC_LOCAL(SelectorStatisticsRuleMap, rule_map, {});
  return rule_map;
}

void AggregateRulePerfData(
    const TreeScope* tree_scope_containing_rule,
    const StyleEngine& style_engine,
    const Vector<RulePerfDataPerRequest>& rules_statistics) {
  SelectorStatisticsRuleMap& map = GetSelectorStatisticsRuleMap();
  for (const auto& rule_stats : rules_statistics) {
    const RuleData* rule = rule_stats.rule;
    const CSSStyleSheet* style_sheet =
        FindStyleSheet(tree_scope_containing_rule, style_engine, rule->Rule());
    CumulativeRulePerfKey key{
        rule->Selector().SelectorText(),
        IdentifiersFactory::IdForCSSStyleSheet(style_sheet)};
    auto it = map.find(key);
    if (it == map.end()) {
      CumulativeRulePerfData data{
          /*match_attempts*/ 1, (rule_stats.fast_reject) ? 1 : 0,
          (rule_stats.did_match) ? 1 : 0, rule_stats.elapsed};
      map.insert(key, data);
    } else {
      it->value.elapsed += rule_stats.elapsed;
      it->value.match_attempts++;
      if (rule_stats.fast_reject) {
        it->value.fast_reject_count++;
      }
      if (rule_stats.did_match) {
        it->value.match_count++;
      }
    }
  }
}

// This global caches a pointer to the trace-enabled state for selector
// statistics gathering. This state is global to the process and comes from the
// tracing subsystem. For performance reasons, we only grab the pointer once -
// the value will be updated as tracing is enabled/disabled, which we read by
// dereferencing this global variable. See comment in the definition of
// `TRACE_EVENT_API_GET_CATEGORY_GROUP_ENABLED` for more details.
static const unsigned char* g_selector_stats_tracing_enabled = nullptr;

}  // namespace

ElementRuleCollector::ElementRuleCollector(
    const ElementResolveContext& context,
    const StyleRecalcContext& style_recalc_context,
    const SelectorFilter& filter,
    MatchResult& result,
    EInsideLink inside_link)
    : context_(context),
      style_recalc_context_(style_recalc_context),
      selector_filter_(filter),
      mode_(SelectorChecker::kResolvingStyle),
      can_use_fast_reject_(selector_filter_.ParentStackIsConsistent(
          context.GetElement().IsPseudoElement()
              ? LayoutTreeBuilderTraversal::ParentElement(
                    *To<PseudoElement>(context.GetElement())
                         .UltimateOriginatingElement())
              : context.ParentElement())),
      matching_ua_rules_(false),
      suppress_visited_(false),
      inside_link_(inside_link),
      result_(result) {
  if (!g_selector_stats_tracing_enabled) {
    g_selector_stats_tracing_enabled =
        TRACE_EVENT_API_GET_CATEGORY_GROUP_ENABLED(
            TRACE_DISABLED_BY_DEFAULT("blink.debug"));
  }
}

ElementRuleCollector::~ElementRuleCollector() = default;

const MatchResult& ElementRuleCollector::MatchedResult() const {
  return result_;
}

StyleRuleList* ElementRuleCollector::MatchedStyleRuleList() {
  DCHECK_EQ(mode_, SelectorChecker::kCollectingStyleRules);
  return style_rule_list_.Release();
}

RuleIndexList* ElementRuleCollector::MatchedCSSRuleList() {
  DCHECK_EQ(mode_, SelectorChecker::kCollectingCSSRules);
  return css_rule_list_.Release();
}

void ElementRuleCollector::ClearMatchedRules() {
  matched_rules_.clear();
}

inline StyleRuleList* ElementRuleCollector::EnsureStyleRuleList() {
  if (!style_rule_list_) {
    style_rule_list_ = MakeGarbageCollected<StyleRuleList>();
  }
  return style_rule_list_.Get();
}

inline RuleIndexList* ElementRuleCollector::EnsureRuleList() {
  if (!css_rule_list_) {
    css_rule_list_ = MakeGarbageCollected<RuleIndexList>();
  }
  return css_rule_list_.Get();
}

void ElementRuleCollector::AddElementStyleProperties(
    const CSSPropertyValueSet* property_set,
    CascadeOrigin origin,
    bool is_cacheable,
    bool is_inline_style) {
  if (!property_set) {
    return;
  }
  auto link_match_type = static_cast<unsigned>(CSSSelector::kMatchAll);
  result_.AddMatchedProperties(
      property_set, {.link_match_type = static_cast<uint8_t>(
                         AdjustLinkMatchType(inside_link_, link_match_type)),
                     .is_inline_style = is_inline_style,
                     .origin = origin});
  if (!is_cacheable) {
    result_.SetIsCacheable(false);
  }
}

void ElementRuleCollector::AddTryStyleProperties() {
  const CSSPropertyValueSet* property_set = style_recalc_context_.try_set;
  if (!property_set) {
    return;
  }
  auto link_match_type = static_cast<unsigned>(CSSSelector::kMatchAll);
  result_.AddMatchedProperties(
      property_set, {.link_match_type = static_cast<uint8_t>(
                         AdjustLinkMatchType(inside_link_, link_match_type)),
                     .valid_property_filter = static_cast<uint8_t>(
                         ValidPropertyFilter::kPositionTry),
                     .is_try_style = true,
                     .origin = CascadeOrigin::kAuthor});
  result_.SetIsCacheable(false);
}

void ElementRuleCollector::AddTryTacticsStyleProperties() {
  const CSSPropertyValueSet* property_set =
      style_recalc_context_.try_tactics_set;
  if (!property_set) {
    return;
  }
  auto link_match_type = static_cast<unsigned>(CSSSelector::kMatchAll);
  result_.AddMatchedProperties(
      property_set, {.link_match_type = static_cast<uint8_t>(
                         AdjustLinkMatchType(inside_link_, link_match_type)),
                     .origin = CascadeOrigin::kAuthor,
                     .is_try_tactics_style = true});
  result_.SetIsCacheable(false);
}

static bool RulesApplicableInCurrentTreeScope(
    const Element* element,
    const ContainerNode* scoping_node) {
  // Check if the rules come from a shadow style sheet in the same tree scope.
  DCHECK(element->IsInTreeScope());
  return !scoping_node ||
         element->GetTreeScope() == scoping_node->GetTreeScope();
}

bool SlowMatchWithNoResultFlags(
    const SelectorChecker& checker,
    SelectorChecker::SelectorCheckingContext& context,
    const CSSSelector& selector,
    const RuleData& rule_data,
    bool suppress_visited,
    unsigned expected_proximity = std::numeric_limits<unsigned>::max()) {
  SelectorChecker::MatchResult result;
  context.selector = &selector;
  context.match_visited = !suppress_visited && rule_data.LinkMatchType() ==
                                                   CSSSelector::kMatchVisited;
  bool match = checker.Match(context, result);
  DCHECK_EQ(0, result.flags);
  DCHECK_EQ(kPseudoIdNone, result.dynamic_pseudo);
  if (match) {
    DCHECK_EQ(expected_proximity, result.proximity);
  }
  return match;
}

template <bool stop_at_first_match, bool perf_trace_enabled>
bool ElementRuleCollector::CollectMatchingRulesForListInternal(
    base::span<const RuleData> rules,
    const MatchRequest& match_request,
    const RuleSet* rule_set,
    int style_sheet_index,
    const SelectorChecker& checker,
    SelectorChecker::SelectorCheckingContext& context,
    PartRequest* part_request) {
  bool reject_starting_styles = style_recalc_context_.is_ensuring_style ||
                                style_recalc_context_.old_style;

  CascadeLayerSeeker layer_seeker(stop_at_first_match ? nullptr : context.scope,
                                  context.vtt_originating_element,
                                  matching_ua_rules_,
                                  matching_rules_from_no_style_sheet_,
                                  &context.element->GetDocument(), rule_set);
  Seeker<ContainerQuery> container_query_seeker(
      rule_set->ContainerQueryIntervals());
  Seeker<StyleScope> scope_seeker(rule_set->ScopeIntervals());

  unsigned fast_rejected = 0;
  unsigned matched = 0;
  SelectorStatisticsCollector selector_statistics_collector;
  if (perf_trace_enabled) {
    selector_statistics_collector.ReserveCapacity(
        static_cast<wtf_size_t>(rules.size()));
  }

  for (const RuleData& rule_data : rules) {
    if (perf_trace_enabled) {
      selector_statistics_collector.EndCollectionForCurrentRule();
      selector_statistics_collector.BeginCollectionForRule(&rule_data);
    }
    if (can_use_fast_reject_ &&
        selector_filter_.FastRejectSelector(
            rule_data.DescendantSelectorIdentifierHashes(
                rule_set->BloomHashBacking()))) {
      fast_rejected++;
      if (perf_trace_enabled) {
        selector_statistics_collector.SetWasFastRejected();
      }
      continue;
    }

    const auto& selector = rule_data.Selector();
    if (part_request && part_request->for_shadow_pseudo) [[unlikely]] {
      if (!selector.IsAllowedAfterPart()) {
        DCHECK_EQ(selector.GetPseudoType(), CSSSelector::kPseudoPart);
        continue;
      }
      DCHECK_EQ(selector.Relation(), CSSSelector::kUAShadow);
    }

    if (reject_starting_styles && rule_data.IsStartingStyle()) {
      continue;
    }

    context.style_scope = scope_seeker.Seek(rule_data.GetPosition());

    // We cannot use easy selector matching for VTT elements.
    // It is also not prepared to deal with the featurelessness
    // of the host (see comment in SelectorChecker::CheckOne()).
    // We also cannot use easy selector matching for real pseudo elements,
    // as we need to match them against an array of ancestors.
    bool can_use_easy_selector_matching =
        !context.pseudo_element && context.vtt_originating_element == nullptr &&
        !(context.scope &&
          context.scope->OwnerShadowHost() == context.element) &&
        !context.style_scope;

    SelectorChecker::MatchResult result;
    if (can_use_easy_selector_matching &&
        rule_data.IsEntirelyCoveredByBucketing()) {
      // Just by seeing this rule, we know that its selector
      // matched, and that we don't get any flags or a match
      // against a pseudo-element. So we can skip the entire test.
      if (pseudo_style_request_.pseudo_id != kPseudoIdNone) {
        continue;
      }
#if DCHECK_IS_ON()
      DCHECK(SlowMatchWithNoResultFlags(checker, context, selector, rule_data,
                                        suppress_visited_, result.proximity));
#endif
    } else if (can_use_easy_selector_matching && rule_data.SelectorIsEasy()) {
      if (pseudo_style_request_.pseudo_id != kPseudoIdNone) {
        continue;
      }
      bool easy_match = EasySelectorChecker::Match(&selector, context.element);
#if DCHECK_IS_ON()
      DCHECK_EQ(easy_match, SlowMatchWithNoResultFlags(
                                checker, context, selector, rule_data,
                                suppress_visited_, result.proximity))
          << "Mismatch for selector " << selector.SelectorText()
          << " on element " << context.element;
#endif
      if (!easy_match) {
        continue;
      }
    } else {
      context.selector = &selector;
      context.match_visited =
          !suppress_visited_ &&
          rule_data.LinkMatchType() == CSSSelector::kMatchVisited;
      bool match = checker.Match(context, result);
      result_.AddFlags(result.flags);
      if (!match) {
        continue;
      }
      // If matching was for pseudo element with ancestors vector,
      // check that we really reached the end of it.
      // E.g. for div::column::scroll-marker, matching for column pseudo,
      // vector would be just [column], index would be 1 (meaning matching
      // found pseudo style ::scroll-marker), and for rule div::column, index
      // would be 0 (meaning matching found actual style).
      // Anything else would mean no match.
      if (context.pseudo_element &&
          (result.pseudo_ancestor_index == kNotFound ||
           result.pseudo_ancestor_index <
               context.pseudo_element_ancestors.size() - 1)) {
        continue;
      }
      if (pseudo_style_request_.pseudo_id != kPseudoIdNone &&
          pseudo_style_request_.pseudo_id != result.dynamic_pseudo) {
        continue;
      }
    }
    if (stop_at_first_match) {
      return true;
    }
    const ContainerQuery* container_query =
        container_query_seeker.Seek(rule_data.GetPosition());
    if (container_query) {
      // If we are matching pseudo elements like a ::before rule when computing
      // the styles of the originating element, we don't know whether the
      // container will be the originating element or not. There is not enough
      // information to evaluate the container query for the existence of the
      // pseudo element, so skip the evaluation and have false positives for
      // HasPseudoElementStyles() instead to make sure we create such pseudo
      // elements when they depend on the originating element.
      if (pseudo_style_request_.pseudo_id != kPseudoIdNone ||
          result.dynamic_pseudo == kPseudoIdNone) {
        Element* style_container_candidate =
            style_recalc_context_.style_container;
        if (!style_container_candidate) {
          if (pseudo_style_request_.pseudo_id == kPseudoIdNone) {
            style_container_candidate =
                ContainerQueryEvaluator::ParentContainerCandidateElement(
                    context_.GetElement());
          } else {
            style_container_candidate = &context_.GetElement();
          }
        }
        if (!EvaluateAndAddContainerQueries(
                style_container_candidate, *container_query,
                style_recalc_context_, container_selector_cache_, result_)) {
          if (AffectsAnimations(rule_data)) {
            result_.SetConditionallyAffectsAnimations();
          }
          continue;
        }
      } else {
        // We are skipping container query matching for pseudo element selectors
        // when not actually matching style for the pseudo element itself. Still
        // we need to keep track of size/style query dependencies since query
        // changes may cause pseudo elements to start being generated.
        bool selects_size = false;
        bool selects_style = false;
        bool selects_scroll_state = false;
        for (const ContainerQuery* current = container_query; current;
             current = current->Parent()) {
          selects_size |= current->Selector().SelectsSizeContainers();
          selects_style |= current->Selector().SelectsStyleContainers();
          selects_scroll_state |=
              current->Selector().SelectsScrollStateContainers();
        }
        if (selects_size) {
          result_.SetDependsOnSizeContainerQueries();
        }
        if (selects_style) {
          result_.SetDependsOnStyleContainerQueries();
        }
        if (selects_scroll_state) {
          result_.SetDependsOnScrollStateContainerQueries();
        }
      }
    }

    matched++;
    if (perf_trace_enabled) {
      selector_statistics_collector.SetDidMatch();
    }
    unsigned layer_order = layer_seeker.SeekLayerOrder(rule_data.GetPosition());
    DidMatchRule(&rule_data, layer_order, container_query, result.proximity,
                 result, style_sheet_index);
  }

  if (perf_trace_enabled) {
    DCHECK_EQ(mode_, SelectorChecker::kResolvingStyle);
    selector_statistics_collector.EndCollectionForCurrentRule();
    AggregateRulePerfData(current_matching_tree_scope_,
                          context_.GetElement().GetDocument().GetStyleEngine(),
                          selector_statistics_collector.PerRuleStatistics());
  }

  StyleEngine& style_engine =
      context_.GetElement().GetDocument().GetStyleEngine();
  if (!style_engine.Stats()) {
    return false;
  }

  size_t rejected = rules.size() - fast_rejected - matched;
  INCREMENT_STYLE_STATS_COUNTER(style_engine, rules_rejected, rejected);
  INCREMENT_STYLE_STATS_COUNTER(style_engine, rules_fast_rejected,
                                fast_rejected);
  INCREMENT_STYLE_STATS_COUNTER(style_engine, rules_matched, matched);
  return false;
}

template <bool stop_at_first_match>
bool ElementRuleCollector::CollectMatchingRulesForList(
    base::span<const RuleData> rules,
    const MatchRequest& match_request,
    const RuleSet* rule_set,
    int style_sheet_index,
    const SelectorChecker& checker,
    SelectorChecker::SelectorCheckingContext& context,
    PartRequest* part_request) {
  // This is a very common case for many style sheets, and by putting it here
  // instead of inside CollectMatchingRulesForListInternal(), we're usually
  // inlined into the caller (which saves on stack setup and call overhead
  // in that common case).
  if (rules.empty()) {
    return false;
  }

  // To reduce branching overhead for the common case, we use a template
  // parameter to eliminate branching in CollectMatchingRulesForListInternal
  // when tracing is not enabled.
  if (!*g_selector_stats_tracing_enabled) {
    return CollectMatchingRulesForListInternal<stop_at_first_match, false>(
        rules, match_request, rule_set, style_sheet_index, checker, context,
        part_request);
  } else {
    return CollectMatchingRulesForListInternal<stop_at_first_match, true>(
        rules, match_request, rule_set, style_sheet_index, checker, context,
        part_request);
  }
}

namespace {

base::span<const Attribute> GetAttributes(const Element& element,
                                          bool need_style_synchronized) {
  if (need_style_synchronized) {
    const AttributeCollection collection = element.Attributes();
    return base::span(collection);
  } else {
    const AttributeCollection collection =
        element.AttributesWithoutStyleUpdate();
    return base::span(collection);
  }
}

}  // namespace

void ElementRuleCollector::CollectMatchingRules(
    const MatchRequest& match_request,
    PartNames* part_names) {
  CollectMatchingRulesInternal</*stop_at_first_match=*/false>(match_request,
                                                              part_names);
}

DISABLE_CFI_PERF
bool ElementRuleCollector::CheckIfAnyRuleMatches(
    const MatchRequest& match_request) {
  return CollectMatchingRulesInternal</*stop_at_first_match=*/true>(
      match_request, /*part_names*/ nullptr);
}

bool ElementRuleCollector::CanRejectScope(const StyleScope& style_scope) {
  if (!style_scope.IsImplicit()) {
    return false;
  }
  StyleScopeFrame* style_scope_frame = style_recalc_context_.style_scope_frame;
  return style_scope_frame &&
         !style_scope_frame->HasSeenImplicitScope(style_scope);
}

template <bool stop_at_first_match>
DISABLE_CFI_PERF bool ElementRuleCollector::CollectMatchingRulesInternal(
    const MatchRequest& match_request,
    PartNames* part_names) {
  DCHECK(!match_request.IsEmpty());

  SelectorChecker checker(part_names, pseudo_style_request_, mode_,
                          matching_ua_rules_);

  ContextWithStyleScopeFrame context(context_, match_request,
                                     &pseudo_style_request_,
                                     style_recalc_context_.style_scope_frame);
  Element& element = *context.context.element;
  const AtomicString& pseudo_id = element.ShadowPseudoId();
  if (!pseudo_id.empty()) {
    DCHECK(element.IsStyledElement());
    for (const auto bundle : match_request.AllRuleSets()) {
      if (CollectMatchingRulesForList<stop_at_first_match>(
              bundle.rule_set->UAShadowPseudoElementRules(pseudo_id),
              match_request, bundle.rule_set, bundle.style_sheet_index, checker,
              context.context) &&
          stop_at_first_match) {
        return true;
      }
    }
  }

  if (element.IsVTTElement()) {
    for (const auto bundle : match_request.AllRuleSets()) {
      if (CollectMatchingRulesForList<stop_at_first_match>(
              bundle.rule_set->CuePseudoRules(), match_request, bundle.rule_set,
              bundle.style_sheet_index, checker, context.context) &&
          stop_at_first_match) {
        return true;
      }
    }
  }
  // Check whether other types of rules are applicable in the current tree
  // scope. Criteria for this:
  // a) the rules are UA rules.
  // b) the rules come from a shadow style sheet in the same tree scope as the
  //    given element.
  // c) is checked in rulesApplicableInCurrentTreeScope.
  if (!matching_ua_rules_ &&
      !RulesApplicableInCurrentTreeScope(&element, match_request.Scope())) {
    return false;
  }

  // We need to collect the rules for id, class, tag, and everything else into a
  // buffer and then sort the buffer.
  if (element.HasID()) {
    for (const auto bundle : match_request.AllRuleSets()) {
      if (CollectMatchingRulesForList<stop_at_first_match>(
              bundle.rule_set->IdRules(element.IdForStyleResolution()),
              match_request, bundle.rule_set, bundle.style_sheet_index, checker,
              context.context) &&
          stop_at_first_match) {
        return true;
      }
    }
  }
  if (element.IsStyledElement() && element.HasClass()) {
    for (const AtomicString& class_name : element.ClassNames()) {
      for (const auto bundle : match_request.AllRuleSets()) {
        if (CollectMatchingRulesForList<stop_at_first_match>(
                bundle.rule_set->ClassRules(class_name), match_request,
                bundle.rule_set, bundle.style_sheet_index, checker,
                context.context) &&
            stop_at_first_match) {
          return true;
        }
      }
    }
  }

  // Collect rules from attribute selector buckets, if we have any.
  bool has_any_attr_rules = false;
  bool need_style_synchronized = false;
  for (const auto bundle : match_reque
"""


```