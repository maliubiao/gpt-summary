Response:
The user wants a summary of the functionality of the provided C++ code file. I need to identify the key tasks performed by this file, its relationship to web technologies like JavaScript, HTML, and CSS, and consider potential usage errors and debugging aspects.

**Plan:**

1. **Identify Core Functionality:** Analyze the code to understand its primary purpose. Keywords like `Invalidation`, `Rule`, `CSSSelector`, and function names will be helpful.
2. **Relate to Web Technologies:** Connect the core functionality to how it impacts the rendering process of web pages involving HTML, CSS, and potentially JavaScript.
3. **Consider Logic and Examples:** If the code makes decisions or transformations based on input, devise hypothetical scenarios to illustrate the input and output.
4. **Identify Potential Errors:** Think about common mistakes developers might make that could lead to this code being executed or behaving unexpectedly.
5. **Outline Debugging Context:**  Describe user actions that would eventually lead to the execution of this code, serving as debugging clues.
6. **Summarize for Part 1:** Condense the findings into a concise summary for the first part of the request.
```
这是目录为blink/renderer/core/css/invalidation/rule_invalidation_data_visitor.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

**功能归纳：**

`rule_invalidation_data_visitor.cc` 的主要功能是 **遍历 CSS 规则，并提取用于优化 CSS 样式失效（invalidation）的信息。**  它分析 CSS 选择器，识别出哪些 HTML 元素的哪些变化会导致该规则重新计算样式。  这个过程是为了提高渲染性能，避免不必要的样式重计算。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个文件直接处理的是 **CSS** 的概念，即 CSS 规则和选择器。它与 HTML 和 JavaScript 的关系在于：

*   **HTML:** CSS 规则是用来选择 HTML 元素的。`rule_invalidation_data_visitor.cc` 的工作是理解 CSS 选择器如何关联到 HTML 元素，并找出当 HTML 结构或属性变化时，哪些 CSS 规则需要重新评估。
    *   **例子:**  假设 CSS 规则是 `.my-class { color: red; }`。 当一个 HTML 元素添加或移除 `my-class` 类时，这个文件负责识别出这个变化需要触发该 CSS 规则的失效。
*   **JavaScript:** JavaScript 可以动态地修改 HTML 结构、属性和类名。这些修改可能会影响 CSS 规则的应用。`rule_invalidation_data_visitor.cc` 负责分析 CSS 规则，以便当 JavaScript 做出这些修改时，系统能够准确地知道哪些样式需要重新计算。
    *   **例子:** JavaScript 代码 `document.getElementById('my-div').classList.add('highlight');` 会给 ID 为 `my-div` 的元素添加 `highlight` 类。如果 CSS 中有规则 `.highlight { background-color: yellow; }`，这个文件会参与到判断这个 JavaScript 操作是否需要触发该背景色样式的重新计算。

**逻辑推理与假设输入输出：**

该代码主要进行的是模式匹配和信息提取，核心的逻辑推理在于判断 CSS 选择器的不同部分（标签名、类名、ID、属性、伪类等）是否支持失效优化，以及哪些类型的变化会触发失效。

*   **假设输入:**  一个简单的 CSS 选择器 `.my-button`。
*   **处理过程:** `RuleInvalidationDataVisitor` 会遍历这个选择器，识别出它是一个类选择器。  函数 `SupportsInvalidation(CSSSelector::kClass)` 返回 `true`，表明类选择器支持失效优化。
*   **假设输出 (提取的信息):**  这个规则的失效依赖于类名为 `my-button` 的元素的添加或移除。

*   **假设输入:** 一个更复杂的 CSS 选择器 `div#container > p.text:hover`.
*   **处理过程:**
    *   识别出 `div` (标签选择器)。
    *   识别出 `#container` (ID 选择器)。
    *   识别出 `>` (子选择器)。
    *   识别出 `p` (标签选择器)。
    *   识别出 `.text` (类选择器)。
    *   识别出 `:hover` (伪类选择器)。
    *   代码会检查每个部分的 `SupportsInvalidation`。对于 `:hover` 这样的动态伪类，其失效机制可能更复杂。
*   **假设输出 (提取的信息):** 这个规则的失效依赖于以下变化：
    *   `div` 标签的添加或移除。
    *   ID 为 `container` 的元素的添加或移除。
    *   `div#container` 子元素中 `p` 标签的添加或移除。
    *   类名为 `text` 的元素的添加或移除。
    *   鼠标悬停在 `p.text` 元素上或离开。

**用户或编程常见的使用错误举例：**

这个文件本身是引擎内部的实现，用户或开发者直接与之交互的可能性很小。 然而，编写不规范或过于复杂的 CSS 可能会影响到这个模块的效率，但这通常不会导致直接的“错误”。

**用户操作如何到达这里（调试线索）：**

作为调试线索，以下用户操作最终可能触发 `rule_invalidation_data_visitor.cc` 的执行：

1. **加载网页:**  当浏览器加载一个包含 CSS 样式的 HTML 页面时，Blink 引擎需要解析 CSS 规则。
2. **修改 HTML/CSS:**
    *   用户通过开发者工具修改元素的属性、类名或样式。
    *   网页上的 JavaScript 代码动态修改 DOM 结构或元素样式。
3. **用户交互:** 用户的鼠标悬停、点击、输入等操作可能会触发 CSS 伪类状态的变化（如 `:hover`, `:focus`）。
4. **浏览器内部操作:**  浏览器进行重排（reflow）或重绘（repaint）时，需要判断哪些样式需要失效和重新计算。

**总结 (针对第 1 部分):**

`rule_invalidation_data_visitor.cc` 的核心功能是 **分析 CSS 规则并提取用于 CSS 样式失效优化的关键信息**。 它深入解析 CSS 选择器的各个组成部分，判断哪些元素的变化会影响这些规则的应用。这个过程是浏览器渲染引擎优化性能的关键环节，确保只在必要时才进行样式重计算，与 HTML 结构和 JavaScript 的动态修改密切相关。
```
Prompt: 
```
这是目录为blink/renderer/core/css/invalidation/rule_invalidation_data_visitor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/invalidation/rule_invalidation_data_visitor.h"

#include "third_party/blink/renderer/core/css/css_selector_list.h"
#include "third_party/blink/renderer/core/css/style_scope.h"
#include "third_party/blink/renderer/core/inspector/invalidation_set_to_selector_map.h"

namespace blink {

namespace {

bool SupportsInvalidation(CSSSelector::MatchType match) {
  switch (match) {
    case CSSSelector::kTag:
    case CSSSelector::kId:
    case CSSSelector::kClass:
    case CSSSelector::kAttributeExact:
    case CSSSelector::kAttributeSet:
    case CSSSelector::kAttributeHyphen:
    case CSSSelector::kAttributeList:
    case CSSSelector::kAttributeContain:
    case CSSSelector::kAttributeBegin:
    case CSSSelector::kAttributeEnd:
      return true;
    case CSSSelector::kUnknown:
    case CSSSelector::kPagePseudoClass:
      // These should not appear in StyleRule selectors.
      NOTREACHED();
    default:
      // New match type added. Figure out if it needs a subtree invalidation or
      // not.
      NOTREACHED();
  }
}

bool SupportsInvalidation(CSSSelector::PseudoType type) {
  switch (type) {
    case CSSSelector::kPseudoEmpty:
    case CSSSelector::kPseudoFirstChild:
    case CSSSelector::kPseudoFirstOfType:
    case CSSSelector::kPseudoLastChild:
    case CSSSelector::kPseudoLastOfType:
    case CSSSelector::kPseudoOnlyChild:
    case CSSSelector::kPseudoOnlyOfType:
    case CSSSelector::kPseudoNthChild:
    case CSSSelector::kPseudoNthOfType:
    case CSSSelector::kPseudoNthLastChild:
    case CSSSelector::kPseudoNthLastOfType:
    case CSSSelector::kPseudoPart:
    case CSSSelector::kPseudoState:
    case CSSSelector::kPseudoStateDeprecatedSyntax:
    case CSSSelector::kPseudoLink:
    case CSSSelector::kPseudoVisited:
    case CSSSelector::kPseudoAny:
    case CSSSelector::kPseudoWebkitAnyLink:
    case CSSSelector::kPseudoAnyLink:
    case CSSSelector::kPseudoAutofill:
    case CSSSelector::kPseudoWebKitAutofill:
    case CSSSelector::kPseudoAutofillPreviewed:
    case CSSSelector::kPseudoAutofillSelected:
    case CSSSelector::kPseudoHover:
    case CSSSelector::kPseudoDrag:
    case CSSSelector::kPseudoFocus:
    case CSSSelector::kPseudoFocusVisible:
    case CSSSelector::kPseudoFocusWithin:
    case CSSSelector::kPseudoActive:
    case CSSSelector::kPseudoChecked:
    case CSSSelector::kPseudoEnabled:
    case CSSSelector::kPseudoFullPageMedia:
    case CSSSelector::kPseudoDefault:
    case CSSSelector::kPseudoDisabled:
    case CSSSelector::kPseudoOptional:
    case CSSSelector::kPseudoPlaceholderShown:
    case CSSSelector::kPseudoRequired:
    case CSSSelector::kPseudoReadOnly:
    case CSSSelector::kPseudoReadWrite:
    case CSSSelector::kPseudoUserInvalid:
    case CSSSelector::kPseudoUserValid:
    case CSSSelector::kPseudoValid:
    case CSSSelector::kPseudoInvalid:
    case CSSSelector::kPseudoIndeterminate:
    case CSSSelector::kPseudoTarget:
    case CSSSelector::kPseudoCurrent:
    case CSSSelector::kPseudoCheck:
    case CSSSelector::kPseudoBefore:
    case CSSSelector::kPseudoAfter:
    case CSSSelector::kPseudoSelectArrow:
    case CSSSelector::kPseudoMarker:
    case CSSSelector::kPseudoModal:
    case CSSSelector::kPseudoSelectorFragmentAnchor:
    case CSSSelector::kPseudoBackdrop:
    case CSSSelector::kPseudoLang:
    case CSSSelector::kPseudoDir:
    case CSSSelector::kPseudoNot:
    case CSSSelector::kPseudoPlaceholder:
    case CSSSelector::kPseudoDetailsContent:
    case CSSSelector::kPseudoFileSelectorButton:
    case CSSSelector::kPseudoResizer:
    case CSSSelector::kPseudoRoot:
    case CSSSelector::kPseudoScope:
    case CSSSelector::kPseudoScrollbar:
    case CSSSelector::kPseudoScrollbarButton:
    case CSSSelector::kPseudoScrollbarCorner:
    case CSSSelector::kPseudoScrollbarThumb:
    case CSSSelector::kPseudoScrollbarTrack:
    case CSSSelector::kPseudoScrollbarTrackPiece:
    case CSSSelector::kPseudoScrollMarkerGroup:
    case CSSSelector::kPseudoScrollMarker:
    case CSSSelector::kPseudoScrollNextButton:
    case CSSSelector::kPseudoScrollPrevButton:
    case CSSSelector::kPseudoColumn:
    case CSSSelector::kPseudoWindowInactive:
    case CSSSelector::kPseudoSelection:
    case CSSSelector::kPseudoCornerPresent:
    case CSSSelector::kPseudoDecrement:
    case CSSSelector::kPseudoIncrement:
    case CSSSelector::kPseudoHorizontal:
    case CSSSelector::kPseudoVertical:
    case CSSSelector::kPseudoStart:
    case CSSSelector::kPseudoEnd:
    case CSSSelector::kPseudoDoubleButton:
    case CSSSelector::kPseudoSingleButton:
    case CSSSelector::kPseudoNoButton:
    case CSSSelector::kPseudoFullScreen:
    case CSSSelector::kPseudoFullScreenAncestor:
    case CSSSelector::kPseudoFullscreen:
    case CSSSelector::kPseudoPaused:
    case CSSSelector::kPseudoPermissionElementInvalidStyle:
    case CSSSelector::kPseudoPermissionElementOccluded:
    case CSSSelector::kPseudoPermissionGranted:
    case CSSSelector::kPseudoPictureInPicture:
    case CSSSelector::kPseudoPlaying:
    case CSSSelector::kPseudoInRange:
    case CSSSelector::kPseudoOutOfRange:
    case CSSSelector::kPseudoWebKitCustomElement:
    case CSSSelector::kPseudoBlinkInternalElement:
    case CSSSelector::kPseudoCue:
    case CSSSelector::kPseudoFutureCue:
    case CSSSelector::kPseudoPastCue:
    case CSSSelector::kPseudoDefined:
    case CSSSelector::kPseudoHost:
    case CSSSelector::kPseudoSpatialNavigationFocus:
    case CSSSelector::kPseudoHasDatalist:
    case CSSSelector::kPseudoIsHtml:
    case CSSSelector::kPseudoListBox:
    case CSSSelector::kPseudoMultiSelectFocus:
    case CSSSelector::kPseudoHostHasNonAutoAppearance:
    case CSSSelector::kPseudoOpen:
    case CSSSelector::kPseudoClosed:
    case CSSSelector::kPseudoDialogInTopLayer:
    case CSSSelector::kPseudoPicker:
    case CSSSelector::kPseudoPopoverInTopLayer:
    case CSSSelector::kPseudoPopoverOpen:
    case CSSSelector::kPseudoSlotted:
    case CSSSelector::kPseudoVideoPersistent:
    case CSSSelector::kPseudoVideoPersistentAncestor:
    case CSSSelector::kPseudoXrOverlay:
    case CSSSelector::kPseudoIs:
    case CSSSelector::kPseudoWhere:
    case CSSSelector::kPseudoParent:  // Same as kPseudoIs.
    case CSSSelector::kPseudoSearchText:
    case CSSSelector::kPseudoTargetText:
    case CSSSelector::kPseudoHighlight:
    case CSSSelector::kPseudoSpellingError:
    case CSSSelector::kPseudoGrammarError:
    case CSSSelector::kPseudoHas:
    case CSSSelector::kPseudoUnparsed:  // Never invalidates.
    case CSSSelector::kPseudoViewTransition:
    case CSSSelector::kPseudoViewTransitionGroup:
    case CSSSelector::kPseudoViewTransitionImagePair:
    case CSSSelector::kPseudoViewTransitionNew:
    case CSSSelector::kPseudoViewTransitionOld:
    case CSSSelector::kPseudoActiveViewTransition:
    case CSSSelector::kPseudoActiveViewTransitionType:
    case CSSSelector::kPseudoHasSlotted:
      return true;
    case CSSSelector::kPseudoUnknown:
    case CSSSelector::kPseudoLeftPage:
    case CSSSelector::kPseudoRightPage:
    case CSSSelector::kPseudoFirstPage:
      // These should not appear in StyleRule selectors.
      NOTREACHED();
    default:
      // New pseudo type added. Figure out if it needs a subtree invalidation or
      // not.
      NOTREACHED();
  }
}

bool SupportsInvalidationWithSelectorList(CSSSelector::PseudoType pseudo) {
  return pseudo == CSSSelector::kPseudoAny ||
         pseudo == CSSSelector::kPseudoCue ||
         pseudo == CSSSelector::kPseudoHost ||
         pseudo == CSSSelector::kPseudoHostContext ||
         pseudo == CSSSelector::kPseudoIs ||
         pseudo == CSSSelector::kPseudoNot ||
         pseudo == CSSSelector::kPseudoSlotted ||
         pseudo == CSSSelector::kPseudoWhere ||
         pseudo == CSSSelector::kPseudoParent ||
         pseudo == CSSSelector::kPseudoNthChild ||
         pseudo == CSSSelector::kPseudoNthLastChild;
}

bool RequiresSubtreeInvalidation(const CSSSelector& selector) {
  if (selector.Match() != CSSSelector::kPseudoElement &&
      selector.Match() != CSSSelector::kPseudoClass) {
    DCHECK(SupportsInvalidation(selector.Match()));
    return false;
  }

  switch (selector.GetPseudoType()) {
    case CSSSelector::kPseudoFirstLine:
    case CSSSelector::kPseudoFirstLetter:
    // FIXME: Most pseudo classes/elements above can be supported and moved
    // to assertSupportedPseudo(). Move on a case-by-case basis. If they
    // require subtree invalidation, document why.
    case CSSSelector::kPseudoHostContext:
      // :host-context matches a shadow host, yet the simple selectors inside
      // :host-context matches an ancestor of the shadow host.
      return true;
    default:
      DCHECK(SupportsInvalidation(selector.GetPseudoType()));
      return false;
  }
}

// Creates a copy of an InvalidationSet by combining an empty InvalidationSet
// (of the same type) with the specified InvalidationSet.
//
// See also InvalidationSet::Combine.
scoped_refptr<InvalidationSet> CopyInvalidationSet(
    const InvalidationSet& invalidation_set) {
  if (invalidation_set.IsSiblingInvalidationSet()) {
    scoped_refptr<InvalidationSet> copy =
        SiblingInvalidationSet::Create(nullptr);
    copy->Combine(invalidation_set);
    return copy;
  }
  if (invalidation_set.IsSelfInvalidationSet()) {
    scoped_refptr<InvalidationSet> copy = DescendantInvalidationSet::Create();
    copy->SetInvalidatesSelf();
    return copy;
  }
  scoped_refptr<InvalidationSet> copy = DescendantInvalidationSet::Create();
  copy->Combine(invalidation_set);
  return copy;
}

bool IsSimpleSelectorValidAfterHost(const CSSSelector* simple_selector) {
  // TODO(blee@igalia.com) Need to support logical combinations after :host
  // (e.g. ':host:not(:has(.a))')
  return simple_selector->Match() == CSSSelector::kPseudoElement ||
         simple_selector->IsHostPseudoClass() ||
         simple_selector->GetPseudoType() == CSSSelector::kPseudoHas;
}

}  // anonymous namespace

template <RuleInvalidationDataVisitorType VisitorType>
RuleInvalidationDataVisitor<VisitorType>::RuleInvalidationDataVisitor(
    RuleInvalidationDataType& rule_invalidation_data)
    : rule_invalidation_data_(rule_invalidation_data) {}

template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::InvalidationSetFeatures::Merge(
    const InvalidationSetFeatures& other) {
  classes.AppendVector(other.classes);
  attributes.AppendVector(other.attributes);
  ids.AppendVector(other.ids);
  // Tag names that have been added to an invalidation set for an ID, a class,
  // or an attribute are called "emitted" tag names. Emitted tag names need to
  // go in a separate vector in order to correctly track which tag names to
  // add to the type rule invalidation set.
  //
  // Example: :is(.a, div) :is(span, .b, ol, .c li)
  //
  // For the above selector, we need span and ol in the type invalidation set,
  // but not li, since that tag name was added to the invalidation set for .c.
  // Hence, when processing the rightmost :is(), we end up with li in the
  // emitted_tag_names vector, and span and ol in the regular tag_names vector.
  if (other.has_features_for_rule_set_invalidation) {
    emitted_tag_names.AppendVector(other.tag_names);
  } else {
    tag_names.AppendVector(other.tag_names);
  }
  emitted_tag_names.AppendVector(other.emitted_tag_names);
  max_direct_adjacent_selectors = std::max(max_direct_adjacent_selectors,
                                           other.max_direct_adjacent_selectors);
  invalidation_flags.Merge(other.invalidation_flags);
  content_pseudo_crossing |= other.content_pseudo_crossing;
  has_nth_pseudo |= other.has_nth_pseudo;
}

template <RuleInvalidationDataVisitorType VisitorType>
bool RuleInvalidationDataVisitor<
    VisitorType>::InvalidationSetFeatures::HasFeatures() const {
  return !classes.empty() || !attributes.empty() || !ids.empty() ||
         !tag_names.empty() || !emitted_tag_names.empty() ||
         invalidation_flags.InvalidateCustomPseudo() ||
         invalidation_flags.InvalidatesParts();
}

template <RuleInvalidationDataVisitorType VisitorType>
bool RuleInvalidationDataVisitor<
    VisitorType>::InvalidationSetFeatures::HasIdClassOrAttribute() const {
  return !classes.empty() || !attributes.empty() || !ids.empty();
}

template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::InvalidationSetFeatures::
    NarrowToFeatures(const InvalidationSetFeatures& other) {
  unsigned size = Size();
  unsigned other_size = other.Size();
  if (size == 0 || (1 <= other_size && other_size < size)) {
    ClearFeatures();
    Merge(other);
  }
}

template <RuleInvalidationDataVisitorType VisitorType>
SelectorPreMatch
RuleInvalidationDataVisitor<VisitorType>::CollectFeaturesFromSelector(
    const CSSSelector& selector,
    const StyleScope* style_scope) {
  FeatureMetadata metadata;
  const unsigned max_direct_adjacent_selectors = 0;
  if (CollectMetadataFromSelector(selector, max_direct_adjacent_selectors,
                                  metadata) ==
      SelectorPreMatch::kNeverMatches) {
    return SelectorPreMatch::kNeverMatches;
  }
  if constexpr (is_builder()) {
    rule_invalidation_data_.uses_first_line_rules |=
        metadata.uses_first_line_rules;
    rule_invalidation_data_.uses_window_inactive_selector |=
        metadata.uses_window_inactive_selector;
    rule_invalidation_data_.max_direct_adjacent_selectors =
        std::max(rule_invalidation_data_.max_direct_adjacent_selectors,
                 metadata.max_direct_adjacent_selectors);
  }

  UpdateInvalidationSets(selector, style_scope);
  return SelectorPreMatch::kMayMatch;
}

template <RuleInvalidationDataVisitorType VisitorType>
SelectorPreMatch
RuleInvalidationDataVisitor<VisitorType>::CollectMetadataFromSelector(
    const CSSSelector& selector,
    unsigned max_direct_adjacent_selectors,
    FeatureMetadata& metadata) {
  CSSSelector::RelationType relation = CSSSelector::kDescendant;
  bool found_host_pseudo = false;

  for (const CSSSelector* current = &selector; current;
       current = current->NextSimpleSelector()) {
    switch (current->GetPseudoType()) {
      case CSSSelector::kPseudoHas:
        if (found_host_pseudo && !current->IsLastInComplexSelector() &&
            !IsSimpleSelectorValidAfterHost(current->NextSimpleSelector())) {
          return SelectorPreMatch::kNeverMatches;
        }
        break;
      case CSSSelector::kPseudoFirstLine:
        metadata.uses_first_line_rules = true;
        break;
      case CSSSelector::kPseudoWindowInactive:
        metadata.uses_window_inactive_selector = true;
        break;
      case CSSSelector::kPseudoHost:
      case CSSSelector::kPseudoHostContext:
        if (!found_host_pseudo && relation == CSSSelector::kSubSelector) {
          return SelectorPreMatch::kNeverMatches;
        }
        if (!current->IsLastInComplexSelector() &&
            !IsSimpleSelectorValidAfterHost(current->NextSimpleSelector())) {
          return SelectorPreMatch::kNeverMatches;
        }
        found_host_pseudo = true;
        // We fall through here to reach the "default" case. Entering the cases
        // for kPseudoIs/Where has no effect, since :host[-context]() can't
        // produce empty argument lists.
        DCHECK(!current->SelectorList() || current->SelectorList()->IsValid());
        [[fallthrough]];
      case CSSSelector::kPseudoIs:
      case CSSSelector::kPseudoWhere:
        if (const CSSSelectorList* selector_list = current->SelectorList()) {
          // An empty list (!IsValid) is possible here because of the forgiving
          // selector list parsing [1], in which empty lists are not syntax
          // errors, but also don't match anything [2].
          //
          // [1]
          // https://drafts.csswg.org/selectors/#typedef-forgiving-selector-list
          // [2] https://drafts.csswg.org/selectors/#matches
          if (!selector_list->IsValid()) {
            return SelectorPreMatch::kNeverMatches;
          }
        }
        [[fallthrough]];
      case CSSSelector::kPseudoParent:
      default:
        for (const CSSSelector* sub_selector = current->SelectorListOrParent();
             sub_selector;
             sub_selector = CSSSelectorList::Next(*sub_selector)) {
          CollectMetadataFromSelector(*sub_selector,
                                      max_direct_adjacent_selectors, metadata);
        }
        break;
    }

    relation = current->Relation();

    if (found_host_pseudo && relation != CSSSelector::kSubSelector) {
      return SelectorPreMatch::kNeverMatches;
    }

    if (relation == CSSSelector::kDirectAdjacent) {
      max_direct_adjacent_selectors++;
    } else if (max_direct_adjacent_selectors &&
               ((relation != CSSSelector::kSubSelector) ||
                current->IsLastInComplexSelector())) {
      if (max_direct_adjacent_selectors >
          metadata.max_direct_adjacent_selectors) {
        metadata.max_direct_adjacent_selectors = max_direct_adjacent_selectors;
      }
      max_direct_adjacent_selectors = 0;
    }
  }

  DCHECK(!max_direct_adjacent_selectors);
  return SelectorPreMatch::kMayMatch;
}

// Update all invalidation sets for a given selector (potentially in the
// given @scope). See UpdateInvalidationSetsForComplex() for details.
template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::UpdateInvalidationSets(
    const CSSSelector& selector,
    const StyleScope* style_scope) {
  STACK_UNINITIALIZED InvalidationSetFeatures features;
  FeatureInvalidationType feature_invalidation_type =
      UpdateInvalidationSetsForComplex(selector, /*in_nth_child=*/false,
                                       style_scope, features, kSubject,
                                       CSSSelector::kPseudoUnknown);
  if (feature_invalidation_type ==
      FeatureInvalidationType::kRequiresSubtreeInvalidation) {
    features.invalidation_flags.SetWholeSubtreeInvalid(true);
  }
  if (style_scope) {
    UpdateFeaturesFromStyleScope(*style_scope, features);
  }
}

// Update all invalidation sets for a given CSS selector; this is usually
// called for the entire selector at top level, but can also end up calling
// itself recursively if any of the selectors contain selector lists
// (e.g. for :not() or :has()).
template <RuleInvalidationDataVisitorType VisitorType>
RuleInvalidationDataVisitor<VisitorType>::FeatureInvalidationType
RuleInvalidationDataVisitor<VisitorType>::UpdateInvalidationSetsForComplex(
    const CSSSelector& complex,
    bool in_nth_child,
    const StyleScope* style_scope,
    InvalidationSetFeatures& features,
    PositionType position,
    CSSSelector::PseudoType pseudo_type) {
  // Given a rule, update the descendant invalidation sets for the features
  // found in its selector. The first step is to extract the features from the
  // rightmost compound selector (ExtractInvalidationSetFeaturesFromCompound).
  // Secondly, add those features to the invalidation sets for the features
  // found in the other compound selectors (AddFeaturesToInvalidationSets).
  // If we find a feature in the right-most compound selector that requires a
  // subtree recalc, next_compound will be the rightmost compound and we will
  // AddFeaturesToInvalidationSets for that one as well.

  InvalidationSetFeatures* sibling_features = nullptr;

  // Step 1. Note that this also, in passing, inserts self-invalidation
  // and nth-child InvalidationSets for the rightmost compound selector.
  // This probably isn't the prettiest, but it's how the structure is
  // at this point.
  const CSSSelector* last_in_compound =
      ExtractInvalidationSetFeaturesFromCompound(
          complex, features, position,
          /* for_logical_combination_in_has */ false, in_nth_child);

  bool was_whole_subtree_invalid =
      features.invalidation_flags.WholeSubtreeInvalid();

  if (features.invalidation_flags.WholeSubtreeInvalid()) {
    features.has_features_for_rule_set_invalidation = false;
  } else if (!features.HasFeatures()) {
    features.invalidation_flags.SetWholeSubtreeInvalid(true);
  }
  // Only check for has_nth_pseudo if this is the top-level complex selector.
  if (pseudo_type == CSSSelector::kPseudoUnknown && features.has_nth_pseudo) {
    // The rightmost compound contains an :nth-* selector.
    // Add the compound features to the NthSiblingInvalidationSet. That is, for
    // '#id:nth-child(even)', add #id to the invalidation set and make sure we
    // invalidate elements matching those features (SetInvalidateSelf()).
    SiblingInvalidationSetType* nth_set = EnsureNthInvalidationSet();
    AddFeaturesToInvalidationSet(nth_set, features);
    SetInvalidatesSelf(nth_set);
  }

  // Step 2.
  const CSSSelector* next_compound =
      last_in_compound ? last_in_compound->NextSimpleSelector() : &complex;

  if (next_compound) {
    if (last_in_compound) {
      UpdateFeaturesFromCombinator(last_in_compound->Relation(), nullptr,
                                   features, sibling_features, features,
                                   /* for_logical_combination_in_has */ false,
                                   in_nth_child);
    }

    AddFeaturesToInvalidationSets(*next_compound, in_nth_child,
                                  sibling_features, features);

    MarkInvalidationSetsWithinNthChild(*next_compound, in_nth_child);
  }

  if (style_scope) {
    AddFeaturesToInvalidationSetsForStyleScope(*style_scope, features);
  }

  if (!next_compound) {
    return kNormalInvalidation;
  }

  // We need to differentiate between no features (HasFeatures()==false)
  // and RequiresSubtreeInvalidation at the callsite. Hence we reset the flag
  // before returning, otherwise the distinction would be lost.
  features.invalidation_flags.SetWholeSubtreeInvalid(was_whole_subtree_invalid);
  return last_in_compound ? kNormalInvalidation : kRequiresSubtreeInvalidation;
}

template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::UpdateFeaturesFromCombinator(
    CSSSelector::RelationType combinator,
    const CSSSelector* last_compound_in_adjacent_chain,
    InvalidationSetFeatures& last_compound_in_adjacent_chain_features,
    InvalidationSetFeatures*& sibling_features,
    InvalidationSetFeatures& descendant_features,
    bool for_logical_combination_in_has,
    bool in_nth_child) {
  if (CSSSelector::IsAdjacentRelation(combinator)) {
    if (!sibling_features) {
      sibling_features = &last_compound_in_adjacent_chain_features;
      if (last_compound_in_adjacent_chain) {
        ExtractInvalidationSetFeaturesFromCompound(
            *last_compound_in_adjacent_chain,
            last_compound_in_adjacent_chain_features, kAncestor,
            for_logical_combination_in_has, in_nth_child);
        if (!last_compound_in_adjacent_chain_features.HasFeatures()) {
          last_compound_in_adjacent_chain_features.invalidation_flags
              .SetWholeSubtreeInvalid(true);
        }
      }
    }
    if (sibling_features->max_direct_adjacent_selectors ==
        SiblingInvalidationSet::kDirectAdjacentMax) {
      return;
    }
    if (combinator == CSSSelector::kDirectAdjacent) {
      ++sibling_features->max_direct_adjacent_selectors;
    } else {
      sibling_features->max_direct_adjacent_selectors =
          SiblingInvalidationSet::kDirectAdjacentMax;
    }
    return;
  }

  descendant_features.descendant_features_depth++;

  if (sibling_features &&
      last_compound_in_adjacent_chain_features.max_direct_adjacent_selectors) {
    last_compound_in_adjacent_chain_features = InvalidationSetFeatures();
  }

  sibling_features = nullptr;

  if (combinator == CSSSelector::kUAShadow) {
    descendant_features.invalidation_flags.SetTreeBoundaryCrossing(true);
  }
  if (combinator == CSSSelector::kShadowSlot) {
    descendant_features.invalidation_flags.SetInsertionPointCrossing(true);
  }
}

// A rule like @scope (.a) { .b {} } needs features equivalent to
// :is (.a .b, .a.b), because the scope established by @scope *includes* the
// scoping root. This function provides .a.b, i.e. the second part of the :is().
// The first part is handled by `AddFeaturesToInvalidationSetsForStyleScope`.
template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::UpdateFeaturesFromStyleScope(
    const StyleScope& style_scope,
    InvalidationSetFeatures& descendant_features) {
  auto add_features = [this](const CSSSelector* selector_list,
                             InvalidationSetFeatures& descendant_features) {
    for (const CSSSelector* selector = selector_list; selector;
         selector = CSSSelectorList::Next(*selector)) {
      InvalidationSetFeatures scope_features;
      ExtractInvalidationSetFeaturesFromCompound(
          *selector, scope_features, kSubject,
          /* for_logical_combination_in_has */ false, /*in_nth_child=*/false);
      descendant_features.Merge(scope_features);
    }
  };

  for (const StyleScope* scope = &style_scope; scope; scope = scope->Parent()) {
    add_features(scope->From(), descendant_features);
    add_features(scope->To(), descendant_features);
  }
}

template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::
    ExtractInvalidationSetFeaturesFromSimpleSelector(
        const CSSSelector& selector,
        InvalidationSetFeatures& features) {
  features.has_features_for_rule_set_invalidation |=
      selector.IsIdClassOrAttributeSelector();

  if (selector.Match() == CSSSelector::kTag &&
      selector.TagQName().LocalName() != CSSSelector::UniversalSelectorAtom()) {
    features.NarrowToTag(selector.TagQName().LocalName());
    return;
  }
  if (selector.Match() == CSSSelector::kId) {
    features.NarrowToId(selector.Value());
    return;
  }
  if (selector.Match() == CSSSelector::kClass) {
    features.NarrowToClass(selector.Value());
    return;
  }
  if (selector.IsAttributeSelector()) {
    features.NarrowToAttribute(selector.Attribute().LocalName());
    return;
  }
  switch (selector.GetPseudoType()) {
    case CSSSelector::kPseudoWebKitCustomElement:
    case CSSSelector::kPseudoBlinkInternalElement:
      features.invalidation_flags.SetInvalidateCustomPseudo(true);
      return;
    case CSSSelector::kPseudoSlotted:
      features.invalidation_flags.SetInvalidatesSlotted(true);
      return;
    case CSSSelector::kPseudoPart:
      features.invalidation_flags.SetInvalidatesParts(true);
      features.invalidation_flags.SetTreeBoundaryCrossing(true);
      return;
    default:
      return;
  }
}

// Extract invalidation set features and return a pointer to the the last
// simple selector of the compound, or nullptr if one of the selectors
// RequiresSubtreeInvalidation().
//
// It also deals with inserting self-invalidation entries for the compound
// itself, so it is not a pure “extract“ despite the name.
template <RuleInvalidationDataVisitorType VisitorType>
const CSSSelector* RuleInvalidationDataVisitor<VisitorType>::
    ExtractInvalidationSetFeaturesFromCompound(
        const CSSSelector& compound,
        InvalidationSetFeatures& features,
        PositionType position,
        bool for_logical_combination_in_has,
        bool in_nth_child) {
  // NOTE: Due to the check at the bottom of the loop, this loop stops
  // once we are at the end of the compound, ie., we see a relation that
  // is not a sub-selector. So for e.g. .a .b.c#d, we will see #d, .c, .b
  // and then stop, returning a pointer to .b.
  const CSSSelector* simple_selector = &compound;
  for (;; simple_selector = simple_selector->NextSimpleSelector()) {
    // Fall back to use subtree invalidations, even for features in the
    // rightmost compound selector. Returning nullptr here will make
    // addFeaturesToInvalidationSets start marking invalidation sets for
    // subtree recalc for features in the rightmost compound selector.
    if (RequiresSubtreeInvalidation(*simple_selector)) {
      features.invalidation_flags.SetWholeSubtreeInvalid(true);
      return nullptr;
    }

    ExtractInvalidationSetFeaturesFromSimpleSelector(*simple_selector,
                                                     features);

    // Initialize the entry in the invalidation set map for self-
    // invalidation, if supported.
    if (InvalidationSetType* invalidation_set =
            InvalidationSetForSimpleSelector(
                *simple_selector, InvalidationType::kInvalidateDescendants,
                position, in_nth_child)) {
      if (invalidation_set == rule_invalidation_data_.nth_invalidation_set) {
        features.has_nth_pseudo = true;
      } else if (position == kSubject) {
        SetInvalidatesSelf(invalidation_set);

        // If we are within :nth-child(), it means we'll need nth-child
        // invalidation for anything within this subject; see RuleFeatureSet
        // class comment.
        if (in_nth_child) {
          SetInvalidatesNth(invalidation_set);
        }
      }
    }

    ExtractInvalidationSetFeaturesFromSelectorList(
        *simple_selector, in_nth_child, features, position);

    if constexpr (is_builder()) {
      if (features.invalidation_flags.InvalidatesParts()) {
        rule_invalidation_data_.invalidates_parts = true;
      }
    }

    // While adding features to invalidation sets for logical combinations
    // inside :has(), ExtractInvalidationSetFeaturesFromCompound() can be
    // called again to extract features from the compound selector containing
    // the :has() pseudo class. (e.g. '.a:has(:is(.b ~ .c)) .d')
    // To avoid infinite recursive call, skip adding features for :has() if
    // ExtractInvalidationSetFeaturesFromCompound() is invoked for the logical
    // combinations inside :has().
    if (simple_selector->GetPseudoType() == CSSSelector::kPseudoHas &&
        !for_logical_combination_in_has) {
      CollectValuesInHasArgument(*simple_selector);
      AddFeaturesToInvalidationSetsForHasPseudoClass(
          *simple_selector, &compound, nullptr, features, in_nth_child);
    }

    if (!simple_selector->NextSimpleSelector() ||
        (simple_selector->Relation() != CSSSelector::kSubSelector)) {
      return simple_selector;
    }
  }
}

template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::
    ExtractInvalidationSetFeaturesFromSelectorList(
        const CSSSelector& simple_selector,
        bool in_nth_child,
        InvalidationSetFeatures& features,
        PositionType position) {
  AutoRestoreMaxDirectAdjacentSelectors restore_max(&features);
  AutoRestoreDescendantFeaturesDepth restore_depth(&features);

  const CSSSelector* sub_selector = simple_selector.SelectorListOrParent();
  if (!sub_selector) {
    return;
  }
  CSSSelector::PseudoType pseudo_type = simple_selector.GetPseudoType();

  // For the :has pseudo class, we should not extract invalidation set features
  // here because the :has invalidation direction is different with others.
  // (preceding-sibling/ancestors/preceding-sibling-of-ancestors)
  if (pseudo_type == CSSSelector::kPseudoHas) {
    return;
  }

  in_nth_child |= pseudo_type == CSSSelector::kPseudoNthChild;
  in_nth_child |= pseudo_type == CSSSelector::kPseudoNthLastChild;

  DCHECK(SupportsInvalidationWithSelectorList(pseudo_type));

  bool all_sub_selectors_have_features = true;
  InvalidationSetFeatures any_features;

  for (; sub_selector; sub_selector = CSSSelectorList::Next(*sub_selector)) {
    InvalidationSetFeatures complex_features;
    if (UpdateInvalidationSetsForComplex(
            *sub_selector, in_nth_child, nullptr /* style_scope */,
            complex_features, position,
            pseudo_type) == kRequiresSubtreeInvalidation) {
      features.invalidation_flags.SetWholeSubtreeInvalid(true);
      continue;
    }
    if (complex_features.has_nth_pseudo) {
      features.has_nth_pseudo = true;
    }
    if (!all_sub_selectors_have_features) {
      continue;
    }
    if (complex_features.HasFeatures()) {
      any_features.Merge(complex_features);
    } else {
      all_sub_selectors_have_features = false;
    }
  }
  // Don't add any features if one of the sub-selectors of does not contain
  // any invalidation set features. E.g. :-webkit-any(*, span).
  //
  // For the :not() pseudo class, we should not use the inner features for
  // invalidation because we should invalidate elements _without_ that
  // feature. On the other hand, we should 
"""


```