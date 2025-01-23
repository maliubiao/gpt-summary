Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided C++ code snippet (`rule_set.cc`), its relation to web technologies (HTML, CSS, JavaScript), examples of logical reasoning and potential errors, debugging hints, and a concise overall function summary.

2. **Initial Code Scan (Keywords and Structure):** I quickly scan the code for keywords like `RuleSet`, `CSSSelector`, `StyleRule`, `AddRule`, `Bucket`, `Filter`, and includes related to CSS and HTML. The copyright notices indicate this is part of a web browser engine (likely Blink/Chromium). The inclusion of headers like `css_selector.h`, `style_rule.h`, and `html_names.h` confirms the CSS and HTML focus.

3. **Core Data Structures Identification:**  I notice the `RuleData` struct, which seems to encapsulate information about individual CSS rules, and the `RuleSet` class, which likely manages collections of these rules. The various `RuleMap` members within `RuleSet` suggest different ways of organizing rules for efficient lookup.

4. **Focus on `RuleSet::AddRule`:** This function appears central to the code's purpose. I see it creates a `RuleData` object and then calls `FindBestRuleSetAndAdd`. This strongly suggests the core function is adding CSS rules and organizing them.

5. **Analyze `FindBestRuleSetAndAdd`:** This function is lengthy, but its logic is key. It extracts various properties from the CSS selector (ID, class, attribute, pseudo-classes/elements, tag name). The `AddToRuleSet` calls based on these extracted values reveal the bucketing strategy for optimizing CSS rule matching. The comments about "covered by bucketing" further confirm this.

6. **Relate to Web Technologies:**
    * **CSS:**  The code directly deals with CSS selectors and rules. Examples of selectors like `#id`, `.class`, `[attribute]`, `::pseudo-element`, `:pseudo-class` are readily apparent in the logic of `FindBestRuleSetAndAdd`.
    * **HTML:**  The inclusion of `html_names.h` and references to tags and attributes (e.g., `html_names::kStyleAttr`) link the code to HTML elements. The handling of shadow DOM (`shadow_element_names.h`) further strengthens this connection.
    * **JavaScript:** While this specific code doesn't directly interact with JavaScript, I know that CSS rules are applied to elements manipulated by JavaScript. Changes in class names or inline styles through JavaScript would trigger the CSS matching process, potentially involving this code.

7. **Identify Logical Reasoning:** The bucketing strategy in `FindBestRuleSetAndAdd` is a prime example of logical reasoning. The code makes assumptions about the frequency of different selector types (IDs are generally unique, classes less so, etc.) to optimize rule matching. The logic to handle `:visited` and `:link` pseudo-classes separately is another instance of specific rule handling.

8. **Consider Potential Errors:** The comments about exceeding the bit limits for `selector_index` and `rule_count` point to potential programming errors or limitations. The comment about attacks leading to the "universal bucket" highlights a robustness consideration. User errors in writing CSS selectors could also lead to unexpected behavior, although the code itself is designed to handle these.

9. **Trace User Operations:** I think about how a user's actions lead to this code being executed. Loading a web page, the browser parsing CSS, and then applying those styles to the HTML elements are the key steps. Developer tools inspections can also lead directly to inspecting the matched CSS rules, providing a debugging path.

10. **Synthesize the Summary:** Based on the above analysis, I formulate the concise functional summary, highlighting the core responsibility of the code: managing and organizing CSS rules for efficient matching.

11. **Structure the Answer:**  I organize the information into the requested categories: functionality, relation to web technologies, logical reasoning, potential errors, debugging hints, and the final summary. This makes the answer clear and easy to understand.

12. **Refine and Elaborate:**  I go back through each section, adding specific examples and details to make the explanation more concrete. For example, providing CSS selector examples for each bucketing case. I also make sure to explicitly mention the implications of the bucketing strategy for performance.

By following these steps, I can systematically analyze the code snippet and generate a comprehensive and accurate answer to the request.
这是提供的 Chromium Blink 引擎源代码文件 `blink/renderer/core/css/rule_set.cc` 的第一部分。 根据你提供的代码片段，以下是它的功能归纳：

**功能归纳：**

`rule_set.cc` 文件的核心功能是**管理和组织 CSS 规则，以便在渲染过程中高效地查找和匹配适用于特定 HTML 元素的 CSS 规则。** 它实现了一个 `RuleSet` 类，该类充当 CSS 规则的容器，并使用多种策略（例如基于选择器的不同部分进行分类，即 "bucketing"）来优化规则的查找效率。

**更详细的功能点：**

1. **存储 CSS 规则:**  `RuleSet` 类负责存储各种类型的 CSS 规则，例如普通的样式规则 (`StyleRule`)，页面规则 (`StyleRulePage`)，字体规则 (`StyleRuleFontFace`) 等。

2. **基于选择器进行组织 (Bucketing):**  这是提高查找效率的关键。 `RuleSet` 实现了将 CSS 规则根据其选择器的特定部分（例如 ID、类名、属性、标签名、伪类/伪元素）放入不同的 "buckets" 的机制。  `FindBestRuleSetAndAdd` 函数是实现这一点的核心，它会分析 CSS 选择器，并决定将规则添加到哪个或哪些 bucket 中。

3. **支持不同类型的选择器:**  代码中可以看到对各种 CSS 选择器的处理，包括：
    * **ID 选择器 (`#id`)**
    * **类选择器 (`.class`)**
    * **标签选择器 (`div`)**
    * **属性选择器 (`[attr]`, `[attr="value"]`)**
    * **伪类选择器 (`:hover`, `:focus`)**
    * **伪元素选择器 (`::before`, `::after`)**
    * **组合选择器 (例如 `div.class`)**
    * **关系选择器 (例如 `div > p`)**
    * **作用域选择器 (`:scope`)**
    * **`::part()` 伪元素**
    * **UA Shadow DOM 伪元素 (例如 `::-webkit-datetime-edit`)**
    * **`::slotted()` 伪元素**
    * **逻辑伪类 (`:is()`, `:where()`)**

4. **处理 `:visited` 和 `:link` 伪类:**  代码专门处理了 `:visited` 和 `:link` 伪类，因为它们的状态是动态的，需要特殊处理。  规则会被拆分成两个版本，分别对应未访问和已访问的状态。

5. **支持 Shadow DOM:** 代码包含对 Shadow DOM 相关选择器（例如 `::part()`, UA Shadow DOM 伪元素, `::slotted()`, `:host`, `:host-context`) 的处理，表明它能够管理作用于 Shadow DOM 的样式规则。

6. **Bloom Filter 优化:**  `RuleData` 结构体中包含了 `bloom_hash_*` 相关的成员，这暗示着使用了 Bloom Filter 来进一步优化规则匹配过程，通过快速排除不匹配的规则。

7. **管理层叠层 (`CascadeLayer`)、容器查询 (`ContainerQuery`) 和作用域 (`StyleScope`)**: 代码中可以看到对这些概念的支持，将规则与特定的层叠层、容器查询或作用域关联起来。

8. **处理特殊规则类型:**  代码还包含添加和管理特定类型规则的方法，例如 `@page`， `@font-face`， `@keyframes` 等。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **CSS:** `rule_set.cc` 的核心就是处理 CSS 规则。它解析 CSS 样式表（可能由 HTML 中的 `<style>` 标签或外部 CSS 文件提供），并将规则存储在 `RuleSet` 对象中。例如，当解析到以下 CSS 规则时：

   ```css
   .my-class {
       color: blue;
   }
   ```

   `FindBestRuleSetAndAdd` 会提取 `.my-class` 选择器，并将该规则添加到 `RuleSet` 的 `class_rules_` 这个 bucket 中，使用 `my-class` 作为 key。

* **HTML:** 当浏览器渲染 HTML 元素时，需要确定哪些 CSS 规则适用于该元素。`RuleSet` 对象会被用来查找匹配该元素的选择器。例如，当渲染一个具有 `class="my-class"` 的 `<div>` 元素时，渲染引擎会查询 `RuleSet` 的 `class_rules_` bucket 中 key 为 `my-class` 的规则，以找到 `color: blue;` 这个样式。

* **JavaScript:**  虽然 `rule_set.cc` 本身是 C++ 代码，但 JavaScript 可以动态地修改 HTML 结构和元素的类名、属性等。这些修改可能会触发重新评估 CSS 规则的应用。例如，如果 JavaScript 代码使用 `element.classList.add('my-class')` 给一个元素添加了类名 `my-class`，那么渲染引擎就需要重新查找适用于该元素的 CSS 规则，这时就会用到 `RuleSet` 中存储的规则。

**逻辑推理的假设输入与输出示例：**

**假设输入:**  一个包含以下 CSS 规则的样式表被解析：

```css
#unique-id {
  font-weight: bold;
}

.common-class {
  font-size: 16px;
}
```

**逻辑推理:**

1. `FindBestRuleSetAndAdd` 处理 `#unique-id` 选择器时，会提取 "unique-id" 作为 ID，并将对应的 `StyleRule` 添加到 `id_rules_` 这个 `RuleMap` 中，以 "unique-id" 为键。

2. `FindBestRuleSetAndAdd` 处理 `.common-class` 选择器时，会提取 "common-class" 作为类名，并将对应的 `StyleRule` 添加到 `class_rules_` 这个 `RuleMap` 中，以 "common-class" 为键。

**输出:**  `RuleSet` 对象的状态会变成：

* `id_rules_` 包含一个条目，key 为 "unique-id"，value 为指向该规则的 `RuleData`。
* `class_rules_` 包含一个条目，key 为 "common-class"，value 为指向该规则的 `RuleData`。

**用户或编程常见的使用错误举例说明：**

* **CSS 选择器性能问题:**  编写过于复杂的 CSS 选择器可能会导致 `FindBestRuleSetAndAdd` 无法有效地将规则放入特定的 bucket，或者导致匹配过程变慢。 例如，使用通配符和深层嵌套的选择器可能会降低性能。

* **大量唯一的 ID 选择器:** 如果 CSS 中包含大量唯一的 ID 选择器，虽然会被高效地索引，但会增加 `id_rules_` 的内存占用。

* **重复的 CSS 规则:**  虽然 `RuleSet` 主要关注组织，但如果样式表中存在大量重复的规则，可能会浪费内存。虽然这不是 `rule_set.cc` 直接负责处理的，但会影响整个渲染流程的效率。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中打开一个网页:**  这是所有操作的起点。

2. **浏览器加载 HTML 文件:** 浏览器开始解析 HTML 结构。

3. **浏览器遇到 `<style>` 标签或 `<link>` 标签:**  解析器识别出需要加载和解析 CSS 样式表。

4. **CSS 解析器工作:**  Blink 的 CSS 解析器会读取 CSS 文件的内容或 `<style>` 标签内的 CSS 代码。

5. **创建 `StyleRule` 对象:**  对于每个 CSS 规则（例如 `.my-class { ... }`），CSS 解析器会创建一个对应的 `StyleRule` 对象。

6. **调用 `RuleSet::AddRule`:**  对于每个 `StyleRule`，会调用 `RuleSet::AddRule` 方法，将该规则添加到 `RuleSet` 中。

7. **`FindBestRuleSetAndAdd` 执行:** 在 `AddRule` 内部，会调用 `FindBestRuleSetAndAdd` 来分析规则的选择器，并决定将其放入哪个或哪些 bucket 中。

**调试线索:**

* **查看 `RuleSet` 的内容:**  在 Chromium 的调试器中，可以查看特定文档或 shadow root 的 `RuleSet` 对象的内容，检查规则是否被正确地添加到预期的 bucket 中。

* **断点在 `FindBestRuleSetAndAdd` 中:**  可以设置断点在 `FindBestRuleSetAndAdd` 函数的入口处，观察它是如何处理特定的 CSS 选择器的，以及最终选择哪个 bucket。

* **检查选择器的 `is_covered_by_bucketing_` 标志:** 代码中可以看到设置 `is_covered_by_bucketing_` 标志的逻辑。在调试时，可以检查选择器对象的这个标志，以了解是否被认为可以通过 bucketing 进行优化。

* **性能分析工具:**  使用 Chromium 的性能分析工具 (如 DevTools 的 Performance 标签) 可以查看样式计算 (Style Recalculation) 的耗时。如果样式计算耗时过长，可能与 `RuleSet` 的效率有关，需要进一步分析哪些选择器或规则导致了性能瓶颈。

总而言之，`blink/renderer/core/css/rule_set.cc` 文件中的 `RuleSet` 类是 Blink 渲染引擎中管理 CSS 规则的核心组件，它通过高效的组织和索引策略，确保在渲染过程中能够快速找到并应用正确的样式。

### 提示词
```
这是目录为blink/renderer/core/css/rule_set.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 2004-2005 Allan Sandfeld Jensen (kde@carewolf.com)
 * Copyright (C) 2006, 2007 Nicholas Shanks (webkit@nickshanks.com)
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012 Apple Inc. All
 * rights reserved.
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/css/rule_set.h"

#include <memory>
#include <type_traits>
#include <vector>

#include "base/containers/contains.h"
#include "base/substring_set_matcher/substring_set_matcher.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/core/css/css_font_selector.h"
#include "third_party/blink/renderer/core/css/css_selector.h"
#include "third_party/blink/renderer/core/css/css_selector_list.h"
#include "third_party/blink/renderer/core/css/robin_hood_map-inl.h"
#include "third_party/blink/renderer/core/css/seeker.h"
#include "third_party/blink/renderer/core/css/selector_checker-inl.h"
#include "third_party/blink/renderer/core/css/selector_checker.h"
#include "third_party/blink/renderer/core/css/selector_filter.h"
#include "third_party/blink/renderer/core/css/style_rule_import.h"
#include "third_party/blink/renderer/core/css/style_rule_nested_declarations.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_utils.h"
#include "third_party/blink/renderer/core/html/track/text_track_cue.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/invalidation_set_to_selector_map.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"

using base::MatcherStringPattern;
using base::SubstringSetMatcher;

namespace blink {

template <class T>
static void AddRuleToIntervals(const T* value,
                               unsigned position,
                               HeapVector<RuleSet::Interval<T>>& intervals);

static void UnmarkAsCoveredByBucketing(CSSSelector& selector);

static inline ValidPropertyFilter DetermineValidPropertyFilter(
    const AddRuleFlags add_rule_flags,
    const CSSSelector& selector) {
  for (const CSSSelector* component = &selector; component;
       component = component->NextSimpleSelector()) {
    if (component->Match() == CSSSelector::kPseudoElement &&
        component->Value() == TextTrackCue::CueShadowPseudoId()) {
      return ValidPropertyFilter::kCue;
    }
    switch (component->GetPseudoType()) {
      case CSSSelector::kPseudoCue:
        return ValidPropertyFilter::kCue;
      case CSSSelector::kPseudoFirstLetter:
        return ValidPropertyFilter::kFirstLetter;
      case CSSSelector::kPseudoFirstLine:
        return ValidPropertyFilter::kFirstLine;
      case CSSSelector::kPseudoMarker:
        return ValidPropertyFilter::kMarker;
      case CSSSelector::kPseudoSelection:
      case CSSSelector::kPseudoTargetText:
      case CSSSelector::kPseudoGrammarError:
      case CSSSelector::kPseudoSpellingError:
      case CSSSelector::kPseudoHighlight:
        if (UsesHighlightPseudoInheritance(
                component->GetPseudoId(component->GetPseudoType()))) {
          return ValidPropertyFilter::kHighlight;
        } else {
          return ValidPropertyFilter::kHighlightLegacy;
        }
      default:
        break;
    }
  }
  return ValidPropertyFilter::kNoFilter;
}

static bool SelectorListHasLinkOrVisited(const CSSSelector* selector_list) {
  for (const CSSSelector* complex = selector_list; complex;
       complex = CSSSelectorList::Next(*complex)) {
    if (complex->HasLinkOrVisited()) {
      return true;
    }
  }
  return false;
}

static bool StyleScopeHasLinkOrVisited(const StyleScope* style_scope) {
  return style_scope && (SelectorListHasLinkOrVisited(style_scope->From()) ||
                         SelectorListHasLinkOrVisited(style_scope->To()));
}

static unsigned DetermineLinkMatchType(const AddRuleFlags add_rule_flags,
                                       const CSSSelector& selector,
                                       const StyleScope* style_scope) {
  if (selector.HasLinkOrVisited() || StyleScopeHasLinkOrVisited(style_scope)) {
    return (add_rule_flags & kRuleIsVisitedDependent)
               ? CSSSelector::kMatchVisited
               : CSSSelector::kMatchLink;
  }
  return CSSSelector::kMatchAll;
}

RuleData::RuleData(StyleRule* rule,
                   unsigned selector_index,
                   unsigned position,
                   const StyleScope* style_scope,
                   AddRuleFlags add_rule_flags,
                   Vector<unsigned>& bloom_hash_backing)
    : rule_(rule),
      selector_index_(selector_index),
      position_(position),
      specificity_(Selector().Specificity()),
      link_match_type_(
          DetermineLinkMatchType(add_rule_flags, Selector(), style_scope)),
      valid_property_filter_(
          static_cast<std::underlying_type_t<ValidPropertyFilter>>(
              DetermineValidPropertyFilter(add_rule_flags, Selector()))),
      is_entirely_covered_by_bucketing_(
          false),  // Will be computed in ComputeEntirelyCoveredByBucketing().
      is_easy_(false),  // Ditto.
      is_starting_style_((add_rule_flags & kRuleIsStartingStyle) != 0),
      bloom_hash_size_(0),
      bloom_hash_pos_(0) {
  ComputeBloomFilterHashes(style_scope, bloom_hash_backing);
}

void RuleData::ComputeEntirelyCoveredByBucketing() {
  is_easy_ = EasySelectorChecker::IsEasy(&Selector());
  is_entirely_covered_by_bucketing_ = true;
  for (const CSSSelector* selector = &Selector(); selector;
       selector = selector->NextSimpleSelector()) {
    if (!selector->IsCoveredByBucketing()) {
      is_entirely_covered_by_bucketing_ = false;
      break;
    }
  }
}

void RuleData::ResetEntirelyCoveredByBucketing() {
  for (CSSSelector* selector = &MutableSelector(); selector;
       selector = selector->NextSimpleSelector()) {
    selector->SetCoveredByBucketing(false);
    if (selector->Relation() != CSSSelector::kSubSelector) {
      break;
    }
  }
  is_entirely_covered_by_bucketing_ = false;
}

void RuleData::ComputeBloomFilterHashes(const StyleScope* style_scope,
                                        Vector<unsigned>& bloom_hash_backing) {
  if (bloom_hash_backing.size() >= 16777216) {
    // This won't fit into bloom_hash_pos_, so don't collect any hashes.
    return;
  }
  bloom_hash_pos_ = bloom_hash_backing.size();
  SelectorFilter::CollectIdentifierHashes(Selector(), style_scope,
                                          bloom_hash_backing);

  // The clamp here is purely for safety; a real rule would never have
  // as many as 255 descendant selectors.
  bloom_hash_size_ =
      std::min<uint32_t>(bloom_hash_backing.size() - bloom_hash_pos_, 255);

  // If we've already got the exact same set of hashes in the vector,
  // we can simply reuse those, saving a bit of memory and cache space.
  // We only check the trivial case of a tail match; we could go with
  // something like a full suffix tree solution, but this is simple and
  // captures most of the benefits. (It is fairly common, especially with
  // nesting, to have the same sets of parents in consecutive rules.)
  if (bloom_hash_size_ > 0 && bloom_hash_pos_ >= bloom_hash_size_ &&
      std::equal(
          bloom_hash_backing.begin() + bloom_hash_pos_ - bloom_hash_size_,
          bloom_hash_backing.begin() + bloom_hash_pos_,
          bloom_hash_backing.begin() + bloom_hash_pos_)) {
    bloom_hash_backing.resize(bloom_hash_pos_);
    bloom_hash_pos_ -= bloom_hash_size_;
  }
}

void RuleData::MovedToDifferentRuleSet(const Vector<unsigned>& old_backing,
                                       Vector<unsigned>& new_backing,
                                       unsigned new_position) {
  unsigned new_pos = new_backing.size();
  new_backing.insert(new_backing.size(), old_backing.data() + bloom_hash_pos_,
                     bloom_hash_size_);
  bloom_hash_pos_ = new_pos;
  position_ = new_position;
}

void RuleSet::AddToRuleSet(const AtomicString& key,
                           RuleMap& map,
                           const RuleData& rule_data) {
  if (map.IsCompacted()) {
    // This normally should not happen, but may with UA stylesheets;
    // see class comment on RuleMap.
    map.Uncompact();
  }
  if (!map.Add(key, rule_data)) {
    // This should really only happen in case of an attack;
    // we stick it in the universal bucket so that correctness
    // is preserved, even though the performance will be suboptimal.
    RuleData rule_data_copy = rule_data;
    UnmarkAsCoveredByBucketing(rule_data_copy.MutableSelector());
    AddToRuleSet(universal_rules_, rule_data_copy);
    return;
  }
  // Don't call ComputeBloomFilterHashes() here; RuleMap needs that space for
  // group information, and will call ComputeBloomFilterHashes() itself on
  // compaction.
  need_compaction_ = true;
}

void RuleSet::AddToRuleSet(HeapVector<RuleData>& rules,
                           const RuleData& rule_data) {
  rules.push_back(rule_data);
  rules.back().ComputeEntirelyCoveredByBucketing();
  need_compaction_ = true;
}

static void ExtractSelectorValues(const CSSSelector* selector,
                                  const StyleScope* style_scope,
                                  AtomicString& id,
                                  AtomicString& class_name,
                                  AtomicString& attr_name,
                                  AtomicString& attr_value,
                                  bool& is_exact_attr,
                                  AtomicString& custom_pseudo_element_name,
                                  AtomicString& tag_name,
                                  AtomicString& part_name,
                                  AtomicString& picker_name,
                                  CSSSelector::PseudoType& pseudo_type) {
  is_exact_attr = false;
  switch (selector->Match()) {
    case CSSSelector::kId:
      id = selector->Value();
      break;
    case CSSSelector::kClass:
      class_name = selector->Value();
      break;
    case CSSSelector::kTag:
      if (selector->TagQName().LocalName() !=
          CSSSelector::UniversalSelectorAtom()) {
        tag_name = selector->TagQName().LocalName();
      }
      break;
    case CSSSelector::kPseudoClass:
    case CSSSelector::kPseudoElement:
    case CSSSelector::kPagePseudoClass:
      // Must match the cases in RuleSet::FindBestRuleSetAndAdd.
      switch (selector->GetPseudoType()) {
        case CSSSelector::kPseudoFocus:
          if (pseudo_type == CSSSelector::kPseudoScrollMarker ||
              pseudo_type == CSSSelector::kPseudoScrollNextButton ||
              pseudo_type == CSSSelector::kPseudoScrollPrevButton) {
            break;
          }
          [[fallthrough]];
        case CSSSelector::kPseudoCue:
        case CSSSelector::kPseudoLink:
        case CSSSelector::kPseudoVisited:
        case CSSSelector::kPseudoWebkitAnyLink:
        case CSSSelector::kPseudoAnyLink:
        case CSSSelector::kPseudoFocusVisible:
        case CSSSelector::kPseudoPlaceholder:
        case CSSSelector::kPseudoDetailsContent:
        case CSSSelector::kPseudoFileSelectorButton:
        case CSSSelector::kPseudoHost:
        case CSSSelector::kPseudoHostContext:
        case CSSSelector::kPseudoSlotted:
        case CSSSelector::kPseudoSelectorFragmentAnchor:
        case CSSSelector::kPseudoRoot:
        case CSSSelector::kPseudoScrollMarker:
        case CSSSelector::kPseudoScrollNextButton:
        case CSSSelector::kPseudoScrollPrevButton:
          pseudo_type = selector->GetPseudoType();
          break;
        case CSSSelector::kPseudoWebKitCustomElement:
        case CSSSelector::kPseudoBlinkInternalElement:
          custom_pseudo_element_name = selector->Value();
          break;
        case CSSSelector::kPseudoPart:
          part_name = selector->Value();
          break;
        case CSSSelector::kPseudoPicker:
          picker_name = selector->Argument();
          break;
        case CSSSelector::kPseudoIs:
        case CSSSelector::kPseudoWhere:
        case CSSSelector::kPseudoParent: {
          const CSSSelector* selector_list = selector->SelectorListOrParent();
          // If the :is/:where has only a single argument, it effectively acts
          // like a normal selector (save for specificity), and we can put it
          // into a bucket based on that selector.
          //
          // Note that `selector_list` may be nullptr for top-level '&'
          // selectors.
          if (selector_list &&
              CSSSelectorList::IsSingleComplexSelector(*selector_list)) {
            ExtractSelectorValues(selector_list, style_scope, id, class_name,
                                  attr_name, attr_value, is_exact_attr,
                                  custom_pseudo_element_name, tag_name,
                                  part_name, picker_name, pseudo_type);
          }
          break;
        }
        case CSSSelector::kPseudoScope: {
          // Just like :is() and :where(), we can bucket :scope as the
          // <scope-start> it refers to, as long as the <scope-start>
          // contains a single selector.
          //
          // Note that the <scope-start> selector is optional, therefore
          // From() may return nullptr below.
          const CSSSelector* selector_list =
              style_scope ? style_scope->From() : nullptr;
          if (selector_list &&
              CSSSelectorList::IsSingleComplexSelector(*selector_list)) {
            ExtractSelectorValues(selector_list, style_scope, id, class_name,
                                  attr_name, attr_value, is_exact_attr,
                                  custom_pseudo_element_name, tag_name,
                                  part_name, picker_name, pseudo_type);
          }
          break;
        }
        default:
          break;
      }
      break;
    case CSSSelector::kAttributeSet:
      attr_name = selector->Attribute().LocalName();
      attr_value = g_empty_atom;
      break;
    case CSSSelector::kAttributeExact:
      is_exact_attr = true;
      [[fallthrough]];
    case CSSSelector::kAttributeHyphen:
    case CSSSelector::kAttributeList:
    case CSSSelector::kAttributeContain:
    case CSSSelector::kAttributeBegin:
    case CSSSelector::kAttributeEnd:
      attr_name = selector->Attribute().LocalName();
      attr_value = selector->Value();
      break;
    default:
      break;
  }
}

// For a (possibly compound) selector, extract the values used for determining
// its buckets (e.g. for “.foo[baz]”, will return foo for class_name and
// baz for attr_name). Returns the last subselector in the group, which is also
// the one given the highest priority.
static const CSSSelector* ExtractBestSelectorValues(
    const CSSSelector& component,
    const StyleScope* style_scope,
    AtomicString& id,
    AtomicString& class_name,
    AtomicString& attr_name,
    AtomicString& attr_value,
    bool& is_exact_attr,
    AtomicString& custom_pseudo_element_name,
    AtomicString& tag_name,
    AtomicString& part_name,
    AtomicString& picker_name,
    CSSSelector::PseudoType& pseudo_type) {
  const CSSSelector* it = &component;
  for (; it && it->Relation() == CSSSelector::kSubSelector;
       it = it->NextSimpleSelector()) {
    ExtractSelectorValues(it, style_scope, id, class_name, attr_name,
                          attr_value, is_exact_attr, custom_pseudo_element_name,
                          tag_name, part_name, picker_name, pseudo_type);
  }
  if (it) {
    ExtractSelectorValues(it, style_scope, id, class_name, attr_name,
                          attr_value, is_exact_attr, custom_pseudo_element_name,
                          tag_name, part_name, picker_name, pseudo_type);
  }
  return it;
}

template <class Func>
static void MarkAsCoveredByBucketing(CSSSelector& selector,
                                     Func&& should_mark_func) {
  for (CSSSelector* s = &selector;;
       ++s) {  // Termination condition within loop.
    if (should_mark_func(*s)) {
      s->SetCoveredByBucketing(true);
    }

    // NOTE: We could also have tested single-element :is() and :where()
    // if the inside matches, but it's very rare, so we save the runtime
    // here instead. (& in nesting selectors could perhaps be somewhat
    // more common, but we currently don't bucket on & at all.)
    //
    // We could also have taken universal selectors no matter what
    // should_mark_func() says, but again, we consider that not worth it
    // (though if the selector is being put in the universal bucket,
    // there will be an explicit check).

    if (s->IsLastInComplexSelector() ||
        s->Relation() != CSSSelector::kSubSelector) {
      break;
    }
  }
}

static void UnmarkAsCoveredByBucketing(CSSSelector& selector) {
  for (CSSSelector* s = &selector;;
       ++s) {  // Termination condition within loop.
    s->SetCoveredByBucketing(false);
    if (s->IsLastInComplexSelector() ||
        s->Relation() != CSSSelector::kSubSelector) {
      break;
    }
  }
}

template <RuleSet::BucketCoverage bucket_coverage>
void RuleSet::FindBestRuleSetAndAdd(CSSSelector& component,
                                    const RuleData& rule_data,
                                    const StyleScope* style_scope) {
  AtomicString id;
  AtomicString class_name;
  AtomicString attr_name;
  AtomicString attr_value;  // Unused.
  AtomicString custom_pseudo_element_name;
  AtomicString tag_name;
  AtomicString part_name;
  AtomicString picker_name;
  CSSSelector::PseudoType pseudo_type = CSSSelector::kPseudoUnknown;

#if DCHECK_IS_ON()
  all_rules_.push_back(rule_data);
#endif  // DCHECK_IS_ON()

  bool is_exact_attr;
  const CSSSelector* it = ExtractBestSelectorValues(
      component, style_scope, id, class_name, attr_name, attr_value,
      is_exact_attr, custom_pseudo_element_name, tag_name, part_name,
      picker_name, pseudo_type);

  // Prefer rule sets in order of most likely to apply infrequently.
  if (!id.empty()) {
    if (bucket_coverage == BucketCoverage::kCompute) {
      MarkAsCoveredByBucketing(component, [&id](const CSSSelector& selector) {
        return selector.Match() == CSSSelector::kId && selector.Value() == id;
      });
    }
    AddToRuleSet(id, id_rules_, rule_data);
    return;
  }

  if (!class_name.empty()) {
    if (bucket_coverage == BucketCoverage::kCompute) {
      MarkAsCoveredByBucketing(
          component, [&class_name](const CSSSelector& selector) {
            return selector.Match() == CSSSelector::kClass &&
                   selector.Value() == class_name;
          });
    }
    AddToRuleSet(class_name, class_rules_, rule_data);
    return;
  }

  if (!attr_name.empty()) {
    AddToRuleSet(attr_name, attr_rules_, rule_data);
    if (attr_name == html_names::kStyleAttr) {
      has_bucket_for_style_attr_ = true;
    }
    // NOTE: Cannot mark anything as covered by bucketing, since the bucketing
    // does not verify namespaces. (We could consider doing so if the namespace
    // is *, but we'd need to be careful about case sensitivity wrt. legacy
    // attributes.)
    return;
  }

  auto get_ua_shadow_pseudo = [&]() -> const AtomicString& {
    if (picker_name == "select") {
      return shadow_element_names::kPickerSelect;
    } else if (pseudo_type != CSSSelector::kPseudoUnknown) {
      return shadow_element_utils::StringForUAShadowPseudoId(
          CSSSelector::GetPseudoId(pseudo_type));
    }
    return g_null_atom;
  };

  AtomicString ua_shadow_pseudo = get_ua_shadow_pseudo();

  if (RuntimeEnabledFeatures::CSSCascadeCorrectScopeEnabled()) {
    // Any selector with or following ::part() or a UA shadow pseudo-element
    // must go in the bucket for the *innermost* such pseudo-element.

    // TODO(dbaron): Should this eventually check kShadowSlot as well?
    if (part_name.empty() && ua_shadow_pseudo == g_null_atom && it &&
        (it->Relation() == CSSSelector::RelationType::kUAShadow ||
         it->Relation() == CSSSelector::RelationType::kShadowPart)) {
      const CSSSelector* previous = it->NextSimpleSelector();
      if (previous->Match() == CSSSelector::kPseudoElement) {
        ExtractSelectorValues(previous, style_scope, id, class_name, attr_name,
                              attr_value, is_exact_attr,
                              custom_pseudo_element_name, tag_name, part_name,
                              picker_name, pseudo_type);
        ua_shadow_pseudo = get_ua_shadow_pseudo();
      }
    }
  }

  // Any selector with or following ::part() must go in the part bucket,
  // because we look in that bucket in higher scopes to find rules that need
  // to match inside the shadow tree.
  if (!part_name.empty() ||
      (it && it->FollowsPart() &&
       !RuntimeEnabledFeatures::CSSCascadeCorrectScopeEnabled())) {
    // NOTE: Cannot mark as covered by bucketing because the part buckets are
    // shared between the part itself and pseudo-elements inside of them.
    // (Though we do check at least some of the relevant conditions *before*
    // we check whether the selector is covered by bucketing, so it might be
    // doable if we want.)
    // TODO(https://crbug.com/40280846): When the CSSCascadeCorrectScope flag
    // is removed (and enabled), we can revisit this.
    AddToRuleSet(part_pseudo_rules_, rule_data);
    return;
  }

  if (!custom_pseudo_element_name.empty()) {
    // Custom pseudos come before ids and classes in the order of
    // NextSimpleSelector(), and have a relation of ShadowPseudo between them.
    // Therefore we should never be a situation where ExtractSelectorValues
    // finds id and className in addition to custom pseudo.
    DCHECK(id.empty());
    DCHECK(class_name.empty());
    AddToRuleSet(custom_pseudo_element_name, ua_shadow_pseudo_element_rules_,
                 rule_data);
    // TODO: Mark as covered by bucketing?
    return;
  }

  if (ua_shadow_pseudo != g_null_atom) {
    // TODO(dbaron): This needs further work to support multiple
    // pseudo-elements after ::slotted().  This likely requires reorganization
    // of how MatchSlottedRules interacts with MatchOuterScopeRules.
    if (it->FollowsSlotted()) {
      AddToRuleSet(slotted_pseudo_element_rules_, rule_data);
    } else {
      AddToRuleSet(ua_shadow_pseudo, ua_shadow_pseudo_element_rules_,
                   rule_data);
    }
    return;
  }

  switch (pseudo_type) {
    case CSSSelector::kPseudoCue:
      AddToRuleSet(cue_pseudo_rules_, rule_data);
      return;
    case CSSSelector::kPseudoLink:
    case CSSSelector::kPseudoVisited:
    case CSSSelector::kPseudoAnyLink:
    case CSSSelector::kPseudoWebkitAnyLink:
      if (bucket_coverage == BucketCoverage::kCompute) {
        MarkAsCoveredByBucketing(component, [](const CSSSelector& selector) {
          // We can only mark kPseudoAnyLink as checked by bucketing;
          // CollectMatchingRules() does not pre-check e.g. whether
          // the link is visible or not.
          return selector.Match() == CSSSelector::kPseudoClass &&
                 (selector.GetPseudoType() == CSSSelector::kPseudoAnyLink ||
                  selector.GetPseudoType() ==
                      CSSSelector::kPseudoWebkitAnyLink);
        });
      }
      AddToRuleSet(link_pseudo_class_rules_, rule_data);
      return;
    case CSSSelector::kPseudoFocus:
      if (bucket_coverage == BucketCoverage::kCompute) {
        MarkAsCoveredByBucketing(component, [](const CSSSelector& selector) {
          return selector.Match() == CSSSelector::kPseudoClass &&
                 selector.GetPseudoType() == CSSSelector::kPseudoFocus;
        });
      }
      AddToRuleSet(focus_pseudo_class_rules_, rule_data);
      return;
    case CSSSelector::kPseudoSelectorFragmentAnchor:
      AddToRuleSet(selector_fragment_anchor_rules_, rule_data);
      return;
    case CSSSelector::kPseudoFocusVisible:
      if (bucket_coverage == BucketCoverage::kCompute) {
        MarkAsCoveredByBucketing(component, [](const CSSSelector& selector) {
          return selector.Match() == CSSSelector::kPseudoClass &&
                 selector.GetPseudoType() == CSSSelector::kPseudoFocusVisible;
        });
      }
      AddToRuleSet(focus_visible_pseudo_class_rules_, rule_data);
      return;
    case CSSSelector::kPseudoHost:
    case CSSSelector::kPseudoHostContext:
      AddToRuleSet(shadow_host_rules_, rule_data);
      return;
    case CSSSelector::kPseudoSlotted:
      AddToRuleSet(slotted_pseudo_element_rules_, rule_data);
      return;
    case CSSSelector::kPseudoRoot:
      if (bucket_coverage == BucketCoverage::kCompute) {
        MarkAsCoveredByBucketing(component, [](const CSSSelector& selector) {
          return selector.Match() == CSSSelector::kPseudoClass &&
                 selector.GetPseudoType() == CSSSelector::kPseudoRoot;
        });
      }
      AddToRuleSet(root_element_rules_, rule_data);
      return;
    default:
      break;
  }

  if (!tag_name.empty()) {
    // Covered by bucketing only if the selector would match any namespace
    // (since the bucketing does not take the namespace into account).
    if (bucket_coverage == BucketCoverage::kCompute) {
      MarkAsCoveredByBucketing(
          component, [&tag_name](const CSSSelector& selector) {
            return selector.Match() == CSSSelector::kTag &&
                   selector.TagQName().LocalName() == tag_name &&
                   selector.TagQName().NamespaceURI() == g_star_atom;
          });
    }
    AddToRuleSet(tag_name, tag_rules_, rule_data);
    return;
  }

  // The ':scope' pseudo-class (bucketed as universal) may match the host
  // when the selector is scoped (e.g. using '@scope') to that host.
  if (component.IsScopeContaining()) {
    must_check_universal_bucket_for_shadow_host_ = true;
  }

  // Normally, rules involving :host would be stuck in their own bucket
  // above; if we came here, it is because we have something like :is(:host,
  // .foo). Mark that we have this case.
  if (component.IsOrContainsHostPseudoClass()) {
    must_check_universal_bucket_for_shadow_host_ = true;
  }

  // If we didn't find a specialized map to stick it in, file under universal
  // rules.
  MarkAsCoveredByBucketing(component, [](const CSSSelector& selector) {
    return selector.Match() == CSSSelector::kTag &&
           selector.TagQName() == AnyQName();
  });
  AddToRuleSet(universal_rules_, rule_data);
}

void RuleSet::AddRule(StyleRule* rule,
                      unsigned selector_index,
                      AddRuleFlags add_rule_flags,
                      const ContainerQuery* container_query,
                      const CascadeLayer* cascade_layer,
                      const StyleScope* style_scope) {
  // The selector index field in RuleData is only 13 bits so we can't support
  // selectors at index 8192 or beyond.
  // See https://crbug.com/804179
  if (selector_index >= (1 << RuleData::kSelectorIndexBits)) {
    return;
  }
  if (rule_count_ >= (1 << RuleData::kPositionBits)) {
    return;
  }
  RuleData rule_data(rule, selector_index, rule_count_, style_scope,
                     add_rule_flags, bloom_hash_backing_);
  ++rule_count_;
  {
    InvalidationSetToSelectorMap::SelectorScope selector_scope(rule,
                                                               selector_index);
    if (features_.CollectFeaturesFromSelector(rule_data.Selector(),
                                              style_scope) ==
        SelectorPreMatch::kNeverMatches) {
      return;
    }
  }

  FindBestRuleSetAndAdd<BucketCoverage::kCompute>(rule_data.MutableSelector(),
                                                  rule_data, style_scope);

  // If the rule has CSSSelector::kMatchLink, it means that there is a :visited
  // or :link pseudo-class somewhere in the selector. In those cases, we
  // effectively split the rule into two: one which covers the situation
  // where we are in an unvisited link (kMatchLink), and another which covers
  // the visited link case (kMatchVisited).
  if (rule_data.LinkMatchType() == CSSSelector::kMatchLink) {
    // Now the selector will be in two buckets.
    rule_data.ResetEntirelyCoveredByBucketing();

    RuleData visited_dependent(
        rule, rule_data.SelectorIndex(), rule_data.GetPosition(), style_scope,
        add_rule_flags | kRuleIsVisitedDependent, bloom_hash_backing_);
    // Since the selector now is in two buckets, we use BucketCoverage::kIgnore
    // to prevent CSSSelector::is_covered_by_bucketing_ from being set.
    FindBestRuleSetAndAdd<BucketCoverage::kIgnore>(
        visited_dependent.MutableSelector(), visited_dependent, style_scope);
  }

  AddRuleToLayerIntervals(cascade_layer, rule_data.GetPosition());
  AddRuleToIntervals(container_query, rule_data.GetPosition(),
                     container_query_intervals_);
  AddRuleToIntervals(style_scope, rule_data.GetPosition(), scope_intervals_);
}

void RuleSet::AddRuleToLayerIntervals(const CascadeLayer* cascade_layer,
                                      unsigned position) {
  // nullptr in this context means “no layer”, i.e., the implicit outer layer.
  if (!cascade_layer) {
    if (layer_intervals_.empty()) {
      // Don't create the implicit outer layer if we don't need to.
      return;
    } else {
      cascade_layer = EnsureImplicitOuterLayer();
    }
  }

  AddRuleToIntervals(cascade_layer, position, layer_intervals_);
}

// Similar to AddRuleToLayerIntervals, but for container queries and @style
// scopes.
template <class T>
static void AddRuleToIntervals(const T* value,
                               unsigned position,
                               HeapVector<RuleSet::Interval<T>>& intervals) {
  const T* last_value =
      intervals.empty() ? nullptr : intervals.back().value.Get();
  if (value == last_value) {
    return;
  }

  intervals.push_back(RuleSet::Interval<T>(value, position));
}

void RuleSet::AddPageRule(StyleRulePage* rule) {
  need_compaction_ = true;
  page_rules_.push_back(rule);
}

void RuleSet::AddFontFaceRule(StyleRuleFontFace* rule) {
  need_compaction_ = true;
  font_face_rules_.push_back(rule);
}

void RuleSet::AddKeyframesRule(StyleRuleKeyframes* rule) {
  need_compaction_ = true;
  keyframes_rules_.push_back(rule);
}

void RuleSet::AddPropertyRule(StyleRuleProperty* rule) {
  need_compaction_ = true;
  property_rules_.push_back(rule);
}

void RuleSet::AddCounterStyleRule(StyleRuleCounterStyle* rule) {
  need_compaction_ = true;
  counter_style_rules_.push_back(rule);
}

void RuleSet::AddFontPaletteValuesRule(StyleRuleFontPaletteValues* rule) {
  need_compaction_ = true;
  font_palette_values_rules_.push_back(rule);
}

void RuleSet::AddFontFeatureValuesRule(StyleRuleFontFeatureValues* rule) {
  need_compaction_ = true;
  font_feature_values_rules_.push_back(rule);
}

void RuleSet::AddPositionTryRule(StyleRulePositionTry* rule) {
  need_compaction_ = true;
  position_try_rules_.push_back(rule);
}

void RuleSet::AddFunctionRule(StyleRuleFunction* rule) {
  need_compaction_ = true;
  function_rules_.push_back(rule);
}

void RuleSet::AddViewTransitionRule(StyleRuleViewTransition*
```