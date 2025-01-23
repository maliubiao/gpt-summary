Response:
Let's break down the thought process for analyzing the `rule_invalidation_data.cc` file.

1. **Understand the Core Purpose:**  The filename itself, `rule_invalidation_data.cc`, strongly suggests this file is about managing data related to *rule invalidation*. In the context of a rendering engine like Blink, "invalidation" refers to marking parts of the rendered output as needing to be recalculated or redrawn because something has changed. CSS rules are central to styling, so this file likely manages data about *how changes in the DOM or CSS affect which rules need to be re-evaluated*.

2. **Scan for Key Data Structures:** Look for class definitions and member variables. The class `RuleInvalidationData` is the central element. Its member variables are crucial to understanding what kind of data it holds. We see several `HashMap`s:
    * `class_invalidation_sets`: Maps class names to `InvalidationSet`s.
    * `id_invalidation_sets`: Maps IDs to `InvalidationSet`s.
    * `attribute_invalidation_sets`: Maps attribute names to `InvalidationSet`s.
    * `pseudo_invalidation_sets`: Maps pseudo-class types to `InvalidationSet`s.

   These maps strongly indicate that the file deals with invalidation triggered by changes to classes, IDs, attributes, and pseudo-classes. The `InvalidationSet` type itself seems important (though not defined in this file).

3. **Examine Key Methods:** Look at the methods of `RuleInvalidationData`.
    * `operator==`: This suggests the ability to compare two `RuleInvalidationData` objects for equality. This is useful for testing and possibly for caching or optimization.
    * `Clear()`:  Indicates a way to reset the invalidation data.
    * `CollectInvalidationSetsFor...`:  These methods (for class, ID, attribute, pseudo-class) are the core logic. They seem to take an `InvalidationLists` object and an element, and based on the changes, populate the `InvalidationLists`. The `TRACE_SCHEDULE_STYLE_INVALIDATION` calls within these methods are strong hints about how this data is used in the styling pipeline.
    * `CollectSiblingInvalidationSetFor...`:  These seem like specialized versions of the above, specifically for sibling selectors.
    * `CollectUniversalSiblingInvalidationSet`, `CollectNthInvalidationSet`, `CollectPartInvalidationSet`: These handle invalidation for other selector types.
    * `NeedsHasInvalidationFor...`: These methods relate to the `:has()` pseudo-class, indicating logic to determine if a change necessitates invalidation because of `:has()` selectors.
    * `ToString()`:  Useful for debugging and logging, providing a string representation of the invalidation data.
    * `ExtractInvalidationSets`: A helper function to extract specific types of `InvalidationSet`s.

4. **Infer Relationships with Web Technologies:** Based on the data structures and method names, connect the code to web technologies:
    * **CSS:** The file directly deals with CSS selectors (classes, IDs, attributes, pseudo-classes, `:has()`, `::first-line`, `:window-inactive`, `::part`). The concept of invalidation is directly tied to how CSS changes trigger re-rendering.
    * **HTML:** The `Element` parameter in many methods shows the connection to the HTML DOM. Changes to HTML attributes, classes, and IDs are the primary triggers for the invalidation logic.
    * **JavaScript:** While this C++ file doesn't directly execute JavaScript, JavaScript code often manipulates the DOM (adding/removing classes, changing attributes, etc.). These DOM manipulations are the *input* that triggers the invalidation logic managed by this file.

5. **Construct Examples and Scenarios:**  Think about how user actions or JavaScript code could lead to the execution of the methods in this file.
    * **User Actions:** Clicking a button that changes an element's class, hovering over an element (affecting `:hover`), focusing on an input field (`:focus`).
    * **JavaScript:** `element.classList.add('new-class')`, `element.id = 'new-id'`, `element.setAttribute('data-foo', 'bar')`.

6. **Consider Debugging and Error Scenarios:**  How would a developer use this information for debugging? What common mistakes could developers make that would lead to issues involving this code?  Focus on incorrect or unexpected styling behavior due to invalidation issues.

7. **Structure the Explanation:** Organize the findings into logical sections: Functionality, Relationship to Web Tech, Logic (with examples), Usage Errors, and Debugging.

8. **Refine and Elaborate:** Review the initial analysis. Are there any nuances missed? Can the explanations be clearer or more detailed? For instance, explicitly mentioning the performance implications of efficient invalidation.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just about invalidating styles."
* **Correction:** "It's more specifically about *how* CSS rules trigger invalidation based on DOM changes."
* **Initial thought:** "The `InvalidationSet` is just a set of rules."
* **Correction:** "The code distinguishes between `DescendantInvalidationSet` and `SiblingInvalidationSet`, suggesting different scopes of invalidation."
* **Initial thought:**  Focusing too much on the specific implementation details of the `HashMap`.
* **Correction:**  Shifting focus to the *purpose* of the data structures and methods within the context of CSS invalidation.

By following these steps, including the iterative refinement process, we can arrive at a comprehensive and accurate understanding of the `rule_invalidation_data.cc` file and its role in the Blink rendering engine.
好的，我们来详细分析一下 `blink/renderer/core/css/invalidation/rule_invalidation_data.cc` 这个文件的功能。

**功能概述:**

`rule_invalidation_data.cc` 文件定义了 `RuleInvalidationData` 类，这个类是 Blink 渲染引擎中用于存储和管理 **CSS 规则失效信息** 的核心数据结构。 它的主要功能是：

1. **存储触发 CSS 规则失效的条件:**  它记录了哪些 CSS 规则会因为特定的 DOM 变化（例如，类名改变、ID 改变、属性改变等）而需要重新评估和应用。
2. **优化 CSS 样式计算:** 通过精确地记录失效信息，Blink 可以避免不必要的样式重新计算，从而提高渲染性能。只有当 DOM 变化与 `RuleInvalidationData` 中记录的失效条件匹配时，才会触发相应的样式重新计算。
3. **支持各种 CSS 选择器:** 它支持各种类型的 CSS 选择器，包括类选择器、ID 选择器、属性选择器、伪类选择器、以及更复杂的组合选择器（如兄弟选择器、`:has()` 伪类等）。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`RuleInvalidationData` 扮演着连接 HTML (DOM), CSS 和 JavaScript 的关键角色，它确保当 HTML 结构或样式发生变化时，浏览器能够正确地更新渲染结果。

* **HTML (DOM):**  `RuleInvalidationData` 存储的失效信息直接关联到 HTML 元素及其属性。当 JavaScript 修改 DOM 结构或属性时，这些修改可能会触发 CSS 规则的失效。

   **举例:**
   ```html
   <div id="myDiv" class="container active"></div>
   ```
   ```css
   #myDiv { color: red; }
   .container { background-color: blue; }
   .active { font-weight: bold; }
   ```
   如果 JavaScript 代码执行了 `document.getElementById('myDiv').classList.remove('active')`，那么 `RuleInvalidationData` 中与 `.active` 类相关的失效信息会被用来判断哪些规则需要重新计算（例如，移除 `font-weight: bold` 样式）。

* **CSS:** `RuleInvalidationData` 存储的信息来源于 CSS 规则的选择器。 当 CSS 样式表被加载或修改时，Blink 会解析这些规则，并将选择器中指定的条件提取出来，存储到 `RuleInvalidationData` 中。

   **举例:**
   对于 CSS 规则 `.container .item:hover { color: green; }`，`RuleInvalidationData` 会记录：
     - 当一个具有 `item` 类的元素是具有 `container` 类的元素的后代，并且该 `item` 元素处于 `:hover` 状态时，需要触发失效。

* **JavaScript:** JavaScript 通常通过 DOM API 来操作 HTML 结构和样式。 这些操作是触发 CSS 规则失效的源头。 Blink 使用 `RuleInvalidationData` 来确定哪些 CSS 规则受到了 JavaScript DOM 操作的影响。

   **举例:**
   ```javascript
   const element = document.querySelector('#myDiv');
   element.setAttribute('data-state', 'loading');
   ```
   ```css
   #myDiv[data-state="loading"] { opacity: 0.5; }
   ```
   当 JavaScript 设置了 `data-state` 属性时，`RuleInvalidationData` 中与 `[data-state="loading"]` 属性选择器相关的失效信息会被激活，导致 `#myDiv` 的透明度样式被重新计算。

**逻辑推理 (假设输入与输出):**

假设我们有以下 CSS 规则和 HTML 结构：

**输入 CSS:**
```css
.text { color: black; }
#uniqueElement { font-size: 16px; }
.container > .item { margin-bottom: 10px; }
```

**输入 HTML:**
```html
<div class="text">Some text</div>
<p id="uniqueElement">A unique paragraph</p>
<div class="container">
  <span class="item">Item 1</span>
</div>
```

**假设的 `RuleInvalidationData` 内容 (简化表示):**

```
class_invalidation_sets: {
  "text": InvalidationSet(descendants) // 当有元素添加或移除 "text" 类时失效
},
id_invalidation_sets: {
  "uniqueElement": InvalidationSet(descendants) // 当有元素的 ID 变为 "uniqueElement" 时失效
},
attribute_invalidation_sets: {},
pseudo_invalidation_sets: {},
// ... 其他信息
```

**假设的 JavaScript 操作:**
```javascript
document.querySelector('.text').classList.add('highlight');
```

**输出 (触发的失效):**

由于 `.text` 类的变化，Blink 会查找 `RuleInvalidationData` 中与 `.text` 相关的 `InvalidationSet`，并标记拥有 `.text` 类的元素需要重新计算样式。 如果存在与 `.highlight` 类相关的规则，也会进行类似的查找和标记。

**用户或编程常见的使用错误:**

1. **过度使用全局选择器 (`*`) 或复杂选择器:**  虽然 `RuleInvalidationData` 努力优化，但过于宽泛或复杂的选择器会增加需要跟踪的失效条件，可能导致性能下降。
   **举例:**  使用 `* { margin: 0; }` 会导致任何元素的属性变化都可能触发失效。
2. **在 JavaScript 中频繁修改元素的类名或 ID:**  如果 JavaScript 代码在一个动画循环中不断修改元素的类名，会导致大量的样式重新计算，影响性能。
3. **不理解 CSS 继承和层叠:**  有时开发者可能会修改一个父元素的样式，期望影响所有子元素，但由于 CSS 优先级或特异性问题，子元素的样式可能没有按预期更新。 这可能导致误认为失效机制有问题。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中加载网页:**  浏览器开始解析 HTML 和 CSS。
2. **CSS 解析器工作:**  Blink 的 CSS 解析器会解析 CSS 样式表中的规则，并提取选择器信息。
3. **构建 `RuleInvalidationData`:**  根据解析出的选择器信息，Blink 会构建或更新 `RuleInvalidationData` 实例，存储触发失效的条件。
4. **用户与网页互动或 JavaScript 执行:**
   - 用户点击按钮，触发 JavaScript 代码修改 DOM (例如，添加或删除类名)。
   - JavaScript 代码使用 DOM API (如 `setAttribute`, `classList.add`) 修改元素属性。
5. **触发失效检查:**  当 DOM 发生变化时，Blink 会遍历受影响元素的祖先链和兄弟节点，并查找与这些元素相关的 `RuleInvalidationData`。
6. **匹配失效条件:**  Blink 将 DOM 的变化与 `RuleInvalidationData` 中存储的失效条件进行匹配。例如，如果一个元素的类名被添加，Blink 会查找 `class_invalidation_sets` 中是否有与该类名相关的条目。
7. **标记需要重新计算样式的元素:**  如果找到匹配的失效条件，相关的元素会被标记为需要重新计算样式。
8. **样式计算和布局:**  Blink 的样式计算模块会根据标记的信息，重新计算这些元素的最终样式。
9. **渲染:**  最后，渲染模块会根据新的样式信息重新绘制页面。

**作为调试线索:**

当开发者遇到样式没有按预期更新的问题时，`RuleInvalidationData` 的信息可以作为重要的调试线索：

* **检查 `RuleInvalidationData` 的内容:**  开发者可以使用 Blink 开发者工具或其他调试方法，查看特定元素关联的 `RuleInvalidationData`，了解哪些 CSS 规则会因为该元素的变化而失效。
* **分析失效条件:**  检查失效条件是否正确地反映了 CSS 规则的选择器。如果失效条件不正确，可能是 CSS 解析或选择器匹配存在问题。
* **追踪 DOM 操作:**  结合 JavaScript 代码，追踪哪些 DOM 操作触发了失效。 确认这些操作是否是预期的，以及是否触发了正确的失效。

总而言之，`rule_invalidation_data.cc` 中定义的 `RuleInvalidationData` 类是 Blink 渲染引擎中管理 CSS 规则失效信息的关键组件，它连接了 HTML、CSS 和 JavaScript，确保当页面内容或样式发生变化时，浏览器能够高效地更新渲染结果。理解其功能对于理解浏览器渲染过程和进行性能优化至关重要。

### 提示词
```
这是目录为blink/renderer/core/css/invalidation/rule_invalidation_data.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/invalidation/rule_invalidation_data.h"

#include "base/memory/values_equivalent.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/space_split_string.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"

namespace blink {

namespace {

template <typename KeyType,
          typename MapType = HashMap<KeyType, scoped_refptr<InvalidationSet>>>
bool InvalidationSetMapsEqual(const MapType& a, const MapType& b) {
  if (a.size() != b.size()) {
    return false;
  }
  for (const auto& entry : a) {
    auto it = b.find(entry.key);
    if (it == b.end()) {
      return false;
    }
    if (!base::ValuesEquivalent(entry.value, it->value)) {
      return false;
    }
  }
  return true;
}

}  // anonymous namespace

bool RuleInvalidationData::operator==(const RuleInvalidationData& other) const {
  return InvalidationSetMapsEqual<AtomicString>(
             class_invalidation_sets, other.class_invalidation_sets) &&
         base::ValuesEquivalent(names_with_self_invalidation,
                                other.names_with_self_invalidation) &&
         InvalidationSetMapsEqual<AtomicString>(id_invalidation_sets,
                                                other.id_invalidation_sets) &&
         InvalidationSetMapsEqual<AtomicString>(
             attribute_invalidation_sets, other.attribute_invalidation_sets) &&
         InvalidationSetMapsEqual<CSSSelector::PseudoType>(
             pseudo_invalidation_sets, other.pseudo_invalidation_sets) &&
         base::ValuesEquivalent(universal_sibling_invalidation_set,
                                other.universal_sibling_invalidation_set) &&
         base::ValuesEquivalent(nth_invalidation_set,
                                other.nth_invalidation_set) &&
         base::ValuesEquivalent(universal_sibling_invalidation_set,
                                other.universal_sibling_invalidation_set) &&
         classes_in_has_argument == other.classes_in_has_argument &&
         attributes_in_has_argument == other.attributes_in_has_argument &&
         ids_in_has_argument == other.ids_in_has_argument &&
         tag_names_in_has_argument == other.tag_names_in_has_argument &&
         max_direct_adjacent_selectors == other.max_direct_adjacent_selectors &&
         uses_first_line_rules == other.uses_first_line_rules &&
         uses_window_inactive_selector == other.uses_window_inactive_selector &&
         universal_in_has_argument == other.universal_in_has_argument &&
         not_pseudo_in_has_argument == other.not_pseudo_in_has_argument &&
         pseudos_in_has_argument == other.pseudos_in_has_argument &&
         invalidates_parts == other.invalidates_parts &&
         uses_has_inside_nth == other.uses_has_inside_nth;
}

void RuleInvalidationData::Clear() {
  class_invalidation_sets.clear();
  names_with_self_invalidation.reset();
  attribute_invalidation_sets.clear();
  id_invalidation_sets.clear();
  pseudo_invalidation_sets.clear();
  universal_sibling_invalidation_set = nullptr;
  nth_invalidation_set = nullptr;
  classes_in_has_argument.clear();
  attributes_in_has_argument.clear();
  ids_in_has_argument.clear();
  tag_names_in_has_argument.clear();
  pseudos_in_has_argument.clear();
  max_direct_adjacent_selectors = 0;
  uses_first_line_rules = false;
  uses_window_inactive_selector = false;
  universal_in_has_argument = false;
  not_pseudo_in_has_argument = false;
  invalidates_parts = false;
  uses_has_inside_nth = false;
}

void RuleInvalidationData::CollectInvalidationSetsForClass(
    InvalidationLists& invalidation_lists,
    Element& element,
    const AtomicString& class_name) const {
  // Implicit self-invalidation sets for all classes (with Bloom filter
  // rejection); see comment on class_invalidation_sets_.
  if (names_with_self_invalidation && names_with_self_invalidation->MayContain(
                                          class_name.Hash() * kClassSalt)) {
    invalidation_lists.descendants.push_back(
        InvalidationSet::SelfInvalidationSet());
  }

  RuleInvalidationData::InvalidationSetMap::const_iterator it =
      class_invalidation_sets.find(class_name);
  if (it == class_invalidation_sets.end()) {
    return;
  }

  DescendantInvalidationSet* descendants;
  SiblingInvalidationSet* siblings;
  ExtractInvalidationSets(it->value.get(), descendants, siblings);

  if (descendants) {
    TRACE_SCHEDULE_STYLE_INVALIDATION(element, *descendants, ClassChange,
                                      class_name);
    invalidation_lists.descendants.push_back(descendants);
  }

  if (siblings) {
    TRACE_SCHEDULE_STYLE_INVALIDATION(element, *siblings, ClassChange,
                                      class_name);
    invalidation_lists.siblings.push_back(siblings);
  }
}

void RuleInvalidationData::CollectSiblingInvalidationSetForClass(
    InvalidationLists& invalidation_lists,
    Element& element,
    const AtomicString& class_name,
    unsigned min_direct_adjacent) const {
  RuleInvalidationData::InvalidationSetMap::const_iterator it =
      class_invalidation_sets.find(class_name);
  if (it == class_invalidation_sets.end()) {
    return;
  }

  auto* sibling_set = DynamicTo<SiblingInvalidationSet>(it->value.get());
  if (!sibling_set) {
    return;
  }

  if (sibling_set->MaxDirectAdjacentSelectors() < min_direct_adjacent) {
    return;
  }

  TRACE_SCHEDULE_STYLE_INVALIDATION(element, *sibling_set, ClassChange,
                                    class_name);
  invalidation_lists.siblings.push_back(sibling_set);
}

void RuleInvalidationData::CollectInvalidationSetsForId(
    InvalidationLists& invalidation_lists,
    Element& element,
    const AtomicString& id) const {
  if (names_with_self_invalidation &&
      names_with_self_invalidation->MayContain(id.Hash() * kIdSalt)) {
    invalidation_lists.descendants.push_back(
        InvalidationSet::SelfInvalidationSet());
  }

  RuleInvalidationData::InvalidationSetMap::const_iterator it =
      id_invalidation_sets.find(id);
  if (it == id_invalidation_sets.end()) {
    return;
  }

  DescendantInvalidationSet* descendants;
  SiblingInvalidationSet* siblings;
  ExtractInvalidationSets(it->value.get(), descendants, siblings);

  if (descendants) {
    TRACE_SCHEDULE_STYLE_INVALIDATION(element, *descendants, IdChange, id);
    invalidation_lists.descendants.push_back(descendants);
  }

  if (siblings) {
    TRACE_SCHEDULE_STYLE_INVALIDATION(element, *siblings, IdChange, id);
    invalidation_lists.siblings.push_back(siblings);
  }
}

void RuleInvalidationData::CollectSiblingInvalidationSetForId(
    InvalidationLists& invalidation_lists,
    Element& element,
    const AtomicString& id,
    unsigned min_direct_adjacent) const {
  RuleInvalidationData::InvalidationSetMap::const_iterator it =
      id_invalidation_sets.find(id);
  if (it == id_invalidation_sets.end()) {
    return;
  }

  auto* sibling_set = DynamicTo<SiblingInvalidationSet>(it->value.get());
  if (!sibling_set) {
    return;
  }

  if (sibling_set->MaxDirectAdjacentSelectors() < min_direct_adjacent) {
    return;
  }

  TRACE_SCHEDULE_STYLE_INVALIDATION(element, *sibling_set, IdChange, id);
  invalidation_lists.siblings.push_back(sibling_set);
}

void RuleInvalidationData::CollectInvalidationSetsForAttribute(
    InvalidationLists& invalidation_lists,
    Element& element,
    const QualifiedName& attribute_name) const {
  RuleInvalidationData::InvalidationSetMap::const_iterator it =
      attribute_invalidation_sets.find(attribute_name.LocalName());
  if (it == attribute_invalidation_sets.end()) {
    return;
  }

  DescendantInvalidationSet* descendants;
  SiblingInvalidationSet* siblings;
  ExtractInvalidationSets(it->value.get(), descendants, siblings);

  if (descendants) {
    TRACE_SCHEDULE_STYLE_INVALIDATION(element, *descendants, AttributeChange,
                                      attribute_name);
    invalidation_lists.descendants.push_back(descendants);
  }

  if (siblings) {
    TRACE_SCHEDULE_STYLE_INVALIDATION(element, *siblings, AttributeChange,
                                      attribute_name);
    invalidation_lists.siblings.push_back(siblings);
  }
}

void RuleInvalidationData::CollectSiblingInvalidationSetForAttribute(
    InvalidationLists& invalidation_lists,
    Element& element,
    const QualifiedName& attribute_name,
    unsigned min_direct_adjacent) const {
  RuleInvalidationData::InvalidationSetMap::const_iterator it =
      attribute_invalidation_sets.find(attribute_name.LocalName());
  if (it == attribute_invalidation_sets.end()) {
    return;
  }

  auto* sibling_set = DynamicTo<SiblingInvalidationSet>(it->value.get());
  if (!sibling_set) {
    return;
  }

  if (sibling_set->MaxDirectAdjacentSelectors() < min_direct_adjacent) {
    return;
  }

  TRACE_SCHEDULE_STYLE_INVALIDATION(element, *sibling_set, AttributeChange,
                                    attribute_name);
  invalidation_lists.siblings.push_back(sibling_set);
}

void RuleInvalidationData::CollectInvalidationSetsForPseudoClass(
    InvalidationLists& invalidation_lists,
    Element& element,
    CSSSelector::PseudoType pseudo) const {
  RuleInvalidationData::PseudoTypeInvalidationSetMap::const_iterator it =
      pseudo_invalidation_sets.find(pseudo);
  if (it == pseudo_invalidation_sets.end()) {
    return;
  }

  DescendantInvalidationSet* descendants;
  SiblingInvalidationSet* siblings;
  ExtractInvalidationSets(it->value.get(), descendants, siblings);

  if (descendants) {
    TRACE_SCHEDULE_STYLE_INVALIDATION(element, *descendants, PseudoChange,
                                      pseudo);
    invalidation_lists.descendants.push_back(descendants);
  }

  if (siblings) {
    TRACE_SCHEDULE_STYLE_INVALIDATION(element, *siblings, PseudoChange, pseudo);
    invalidation_lists.siblings.push_back(siblings);
  }
}

void RuleInvalidationData::CollectUniversalSiblingInvalidationSet(
    InvalidationLists& invalidation_lists,
    unsigned min_direct_adjacent) const {
  if (universal_sibling_invalidation_set &&
      universal_sibling_invalidation_set->MaxDirectAdjacentSelectors() >=
          min_direct_adjacent) {
    invalidation_lists.siblings.push_back(universal_sibling_invalidation_set);
  }
}

void RuleInvalidationData::CollectNthInvalidationSet(
    InvalidationLists& invalidation_lists) const {
  if (nth_invalidation_set) {
    invalidation_lists.siblings.push_back(nth_invalidation_set);
  }
}

void RuleInvalidationData::CollectPartInvalidationSet(
    InvalidationLists& invalidation_lists) const {
  if (invalidates_parts) {
    invalidation_lists.descendants.push_back(
        InvalidationSet::PartInvalidationSet());
  }
}

bool RuleInvalidationData::NeedsHasInvalidationForClass(
    const AtomicString& class_name) const {
  return classes_in_has_argument.Contains(class_name);
}

bool RuleInvalidationData::NeedsHasInvalidationForAttribute(
    const QualifiedName& attribute_name) const {
  return attributes_in_has_argument.Contains(attribute_name.LocalName());
}

bool RuleInvalidationData::NeedsHasInvalidationForId(
    const AtomicString& id) const {
  return ids_in_has_argument.Contains(id);
}

bool RuleInvalidationData::NeedsHasInvalidationForTagName(
    const AtomicString& tag_name) const {
  return universal_in_has_argument ||
         tag_names_in_has_argument.Contains(tag_name);
}

bool RuleInvalidationData::NeedsHasInvalidationForInsertedOrRemovedElement(
    Element& element) const {
  if (not_pseudo_in_has_argument) {
    return true;
  }

  if (element.HasID()) {
    if (NeedsHasInvalidationForId(element.IdForStyleResolution())) {
      return true;
    }
  }

  if (element.HasClass()) {
    const SpaceSplitString& class_names = element.ClassNames();
    for (const AtomicString& class_name : class_names) {
      if (NeedsHasInvalidationForClass(class_name)) {
        return true;
      }
    }
  }

  return !attributes_in_has_argument.empty() ||
         NeedsHasInvalidationForTagName(element.LocalNameForSelectorMatching());
}

bool RuleInvalidationData::NeedsHasInvalidationForPseudoClass(
    CSSSelector::PseudoType pseudo_type) const {
  return pseudos_in_has_argument.Contains(pseudo_type);
}

String RuleInvalidationData::ToString() const {
  StringBuilder builder;

  enum TypeFlags {
    kId = 1 << 0,
    kClass = 1 << 1,
    kAttribute = 1 << 2,
    kPseudo = 1 << 3,
    kDescendant = 1 << 4,
    kSibling = 1 << 5,
    kUniversal = 1 << 6,
    kNth = 1 << 7,
  };

  struct Entry {
    String name;
    const InvalidationSet* set;
    unsigned flags;
  };

  Vector<Entry> entries;

  auto add_invalidation_sets = [&entries](const String& base,
                                          InvalidationSet* set, unsigned flags,
                                          const char* prefix = "",
                                          const char* suffix = "") {
    if (!set) {
      return;
    }
    DescendantInvalidationSet* descendants;
    SiblingInvalidationSet* siblings;
    RuleInvalidationData::ExtractInvalidationSets(set, descendants, siblings);

    if (descendants) {
      entries.push_back(Entry{base, descendants, flags | kDescendant});
    }
    if (siblings) {
      entries.push_back(Entry{base, siblings, flags | kSibling});
    }
    if (siblings && siblings->SiblingDescendants()) {
      entries.push_back(Entry{base, siblings->SiblingDescendants(),
                              flags | kSibling | kDescendant});
    }
  };

  auto format_name = [](const String& base, unsigned flags) {
    StringBuilder builder;
    // Prefix:

    builder.Append((flags & kId) ? "#" : "");
    builder.Append((flags & kClass) ? "." : "");
    builder.Append((flags & kAttribute) ? "[" : "");

    builder.Append(base);

    // Suffix:
    builder.Append((flags & kAttribute) ? "]" : "");

    builder.Append("[");
    if (flags & kSibling) {
      builder.Append("+");
    }
    if (flags & kDescendant) {
      builder.Append(">");
    }
    builder.Append("]");

    return builder.ReleaseString();
  };

  auto format_max_direct_adjancent = [](unsigned max) -> String {
    if (max == SiblingInvalidationSet::kDirectAdjacentMax) {
      return "~";
    }
    if (max) {
      return String::Number(max);
    }
    return g_empty_atom;
  };

  for (auto& i : id_invalidation_sets) {
    add_invalidation_sets(i.key, i.value.get(), kId, "#");
  }
  for (auto& i : class_invalidation_sets) {
    add_invalidation_sets(i.key, i.value.get(), kClass, ".");
  }
  for (auto& i : attribute_invalidation_sets) {
    add_invalidation_sets(i.key, i.value.get(), kAttribute, "[", "]");
  }
  for (auto& i : pseudo_invalidation_sets) {
    String name = CSSSelector::FormatPseudoTypeForDebugging(
        static_cast<CSSSelector::PseudoType>(i.key));
    add_invalidation_sets(name, i.value.get(), kPseudo, ":", "");
  }

  add_invalidation_sets("*", universal_sibling_invalidation_set.get(),
                        kUniversal);
  add_invalidation_sets("nth", nth_invalidation_set.get(), kNth);

  std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
    if (a.flags != b.flags) {
      return a.flags < b.flags;
    }
    return WTF::CodeUnitCompareLessThan(a.name, b.name);
  });

  for (const Entry& entry : entries) {
    builder.Append(format_name(entry.name, entry.flags));
    builder.Append(entry.set->ToString());
    builder.Append(" ");
  }

  StringBuilder metadata;
  metadata.Append(uses_first_line_rules ? "F" : "");
  metadata.Append(uses_window_inactive_selector ? "W" : "");
  metadata.Append(invalidates_parts ? "P" : "");
  metadata.Append(format_max_direct_adjancent(max_direct_adjacent_selectors));

  if (!metadata.empty()) {
    builder.Append("META:");
    builder.Append(metadata.ReleaseString());
  }

  return builder.ReleaseString();
}

// static
void RuleInvalidationData::ExtractInvalidationSets(
    InvalidationSet* invalidation_set,
    DescendantInvalidationSet*& descendants,
    SiblingInvalidationSet*& siblings) {
  CHECK(invalidation_set->IsAlive());
  if (auto* descendant =
          DynamicTo<DescendantInvalidationSet>(invalidation_set)) {
    descendants = descendant;
    siblings = nullptr;
    return;
  }

  siblings = To<SiblingInvalidationSet>(invalidation_set);
  descendants = siblings->Descendants();
}

}  // namespace blink
```