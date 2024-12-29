Response:
The user wants to understand the functionality of the `check_pseudo_has_argument_context.cc` file in the Chromium Blink engine.

Here's a breakdown of the thought process to answer the request:

1. **Understand the Core Functionality:** The file name suggests it deals with the `:has()` CSS pseudo-class, specifically the context of its arguments. Reading the initial comments and includes confirms this. The code seems to be about analyzing the selector within the `:has()` pseudo-class.

2. **Identify Key Classes:**  The code defines two main classes: `CheckPseudoHasArgumentContext` and `CheckPseudoHasArgumentTraversalIterator`. These are the central components of the functionality.

3. **Analyze `CheckPseudoHasArgumentContext`:**
    * **Purpose:**  The comments and code indicate it analyzes the `:has()` argument selector to determine its characteristics, like depth limitations, adjacent sibling limitations, and whether it matches across shadow boundaries. This information is crucial for optimizing selector matching.
    * **Key Members:**  `has_argument_`, `depth_limit_`, `adjacent_distance_limit_`, `traversal_scope_`, `siblings_affected_by_has_flags_`, `pseudo_has_argument_hashes_`. Understanding what these members represent is key.
    * **The `CheckPseudoHasArgumentCompoundIterator`:** This nested class is for iterating through the compound selectors within the `:has()` argument. It also plays a role in identifying sibling relationships within the argument selector. Focus on the logic within this iterator, especially how it determines if a compound selector is affected by siblings.
    * **Relationships to CSS:**  The core function is directly related to CSS, specifically the `:has()` pseudo-class. It parses CSS selectors.

4. **Analyze `CheckPseudoHasArgumentTraversalIterator`:**
    * **Purpose:**  This class is responsible for iterating through the DOM based on the analysis done by `CheckPseudoHasArgumentContext`. It determines which elements need to be checked to see if the `:has()` condition is met.
    * **Key Members:** `has_anchor_element_`, `match_in_shadow_tree_`, `depth_limit_`, `last_element_`, `current_element_`, `sibling_at_fixed_distance_`, `current_depth_`. Understand how these members control the traversal.
    * **Relationships to DOM:** This iterator directly interacts with the DOM, traversing elements.

5. **Connect to JavaScript and HTML:**
    * **JavaScript:** While this C++ code doesn't directly execute JavaScript, its functionality is triggered by CSS parsing and style calculations, which are often influenced by JavaScript manipulating the DOM or CSSOM.
    * **HTML:** The DOM structure being traversed is created from HTML. The CSS selectors target elements defined in the HTML.

6. **Illustrate with Examples:**  Concrete examples make the explanation clearer.
    * **CSS:** Show examples of `:has()` selectors with different combinators and pseudo-classes to demonstrate how the context analysis works.
    * **HTML:**  Provide simple HTML structures that correspond to the CSS examples.
    * **JavaScript:**  Give examples of JavaScript code that could trigger the evaluation of these `:has()` selectors.

7. **Logical Reasoning and Input/Output:**
    * **Input:** A `:has()` CSS selector string.
    * **Output:** The analyzed properties of the selector (depth limit, adjacency limit, traversal scope, sibling flags). Demonstrate how different input selectors lead to different outputs.

8. **Common Usage Errors:** Think about common mistakes developers might make when using `:has()`, leading to unexpected behavior or performance issues. Focus on complexity and performance implications.

9. **Debugging Clues:**  How would a developer end up looking at this code? What steps might lead them to this file during debugging? This involves understanding the flow of CSS parsing and selector matching in Blink.

10. **Structure and Refine:** Organize the information logically. Start with the high-level purpose, then delve into the details of each class. Use clear language and provide illustrative examples. Review for clarity and accuracy.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:** Focus solely on the iteration.
* **Correction:** Realize the `CheckPseudoHasArgumentContext` is crucial for *setting up* the iteration. The analysis comes before the traversal.
* **Initial thought:**  Oversimplify the sibling flags.
* **Correction:**  Pay closer attention to the different flags (`kSiblingsOfMatchingElement`, `kAncestorSiblingsOfMatchingElement`) and how they are determined by the `CheckPseudoHasArgumentCompoundIterator`.
* **Initial thought:**  Not enough emphasis on the performance implications.
* **Correction:**  Highlight how this analysis is related to optimization and preventing unnecessary DOM traversal.
* **Initial thought:**  Vague explanation of debugging.
* **Correction:** Provide more concrete scenarios where a developer might inspect this code (e.g., performance issues, unexpected matching behavior).
这个文件 `blink/renderer/core/css/check_pseudo_has_argument_context.cc` 的主要功能是**分析 CSS `:has()` 伪类选择器的参数，并确定在进行选择器匹配时需要遍历的 DOM 范围和方式。**  它为高效地实现 `:has()` 伪类提供了上下文信息，用于优化选择器匹配过程。

以下是该文件功能的详细说明，以及它与 JavaScript、HTML 和 CSS 的关系，以及其他方面的说明：

**1. 功能概述:**

* **解析 `:has()` 参数:** 该文件中的代码负责解析 `:has()` 伪类内部的 CSS 选择器（即参数）。
* **确定遍历范围和深度:**  根据 `:has()` 参数选择器的结构，分析出需要遍历的 DOM 树的范围（例如，子树、兄弟节点）和深度限制。
* **识别影响匹配的因素:**  识别出 `:has()` 参数选择器中哪些部分会受到兄弟节点的影响（例如，使用了 `nth-child` 或兄弟选择器）。
* **生成快速拒绝哈希:**  收集 `:has()` 参数中简单选择器的哈希值，用于快速排除不匹配的情况。
* **为选择器检查器提供上下文:**  将分析结果传递给选择器检查器 (SelectorChecker)，以便它能够有效地执行 `:has()` 的匹配。

**2. 与 JavaScript, HTML, CSS 的关系：**

* **CSS:**
    * **核心功能:**  这个文件直接处理 CSS 的 `:has()` 伪类。`:has()` 允许你选择父元素，如果其后代元素匹配了 `:has()` 中指定的选择器。
    * **示例:**
        * `div:has(p)`: 选择包含 `<p>` 元素的 `<div>` 元素。
        * `ul:has(> li.active)`: 选择直接子元素中包含类名为 `active` 的 `<li>` 元素的 `<ul>` 元素。
        * `section:has(h2 + p)`: 选择包含一个 `<h2>` 元素，并且紧随其后有一个 `<p>` 元素的 `<section>` 元素。
        * 该文件会分析 `p`，`> li.active`，`h2 + p` 这些 `:has()` 内部的参数选择器。

* **HTML:**
    * **DOM 结构遍历:** 该文件分析的结果直接影响到在 HTML 文档形成的 DOM 树中进行元素遍历的方式。例如，如果 `:has()` 参数涉及到后代选择器，代码会确定需要遍历的子树深度。
    * **示例:** 对于 CSS `div:has(span.highlight)`, 如果有如下 HTML 结构：
      ```html
      <div>
        <p>一些文本</p>
        <span><strong class="highlight">高亮文本</strong></span>
      </div>
      ```
      `check_pseudo_has_argument_context.cc` 会分析 `span.highlight`，并确定需要遍历 `div` 的子树来查找匹配的 `<span>` 元素。

* **JavaScript:**
    * **CSSOM (CSS Object Model):** JavaScript 可以操作 CSSOM，包括修改样式规则，这可能涉及到包含 `:has()` 的规则。当浏览器需要重新计算样式并应用时，这个文件中的代码会被调用。
    * **DOM 操作:** JavaScript 对 DOM 的操作（例如，添加、删除元素，修改类名）可能会影响 `:has()` 选择器的匹配结果。当 DOM 发生变化时，浏览器需要重新评估这些选择器，这个文件会参与到这个过程中。
    * **示例:**
      ```javascript
      // JavaScript 添加一个类名为 'highlight' 的 span 元素
      const span = document.createElement('span');
      span.classList.add('highlight');
      document.querySelector('div').appendChild(span);
      ```
      如果 CSS 中有 `div:has(span.highlight)`，这个 JavaScript 操作会导致该选择器开始匹配该 `div` 元素。`check_pseudo_has_argument_context.cc` 参与到这个重新评估的过程中。

**3. 逻辑推理和假设输入与输出：**

假设有以下 CSS 选择器和对应的分析结果：

* **输入:** `:has(p)`
    * **输出:**
        * 遍历范围: 子树 (因为 `p` 可以是 `has()` 锚点的后代)
        * 深度限制: 无限 (默认遍历整个子树)
        * 是否受兄弟节点影响: 否 (简单类型选择器 `p` 不涉及兄弟关系)

* **输入:** `:has(> .active)`
    * **输出:**
        * 遍历范围: 直接子元素
        * 深度限制: 1
        * 是否受兄弟节点影响: 否 (类选择器 `.active` 不涉及兄弟关系)

* **输入:** `:has(p ~ span)`
    * **输出:**
        * 遍历范围: 后续兄弟节点
        * 深度限制: 0 (只检查兄弟节点)
        * 是否受兄弟节点影响: 是 (使用了兄弟选择器 `~`)

* **输入:** `:has(.item:nth-child(3))`
    * **输出:**
        * 遍历范围: 子树
        * 深度限制: 无限
        * 是否受兄弟节点影响: 是 (使用了 `:nth-child`)

**4. 用户或编程常见的使用错误：**

* **性能问题：** `:has()` 选择器，特别是当参数选择器很复杂或者需要遍历大量 DOM 元素时，可能会导致性能问题。开发者可能会滥用 `:has()` 而没有意识到其潜在的性能影响。
* **参数选择器错误：**  `:has()` 内部的参数选择器如果写错，会导致样式不生效。例如，拼写错误、使用了不支持的组合器等。
* **理解 `:has()` 的作用域：**  开发者可能不清楚 `:has()` 是在其锚点元素的后代中查找匹配元素。例如，`body:has(header)` 只会检查 `<body>` 元素的后代是否包含 `<header>`，而不会检查 `<body>` 自身是否是 `<header>`。
* **过度使用复杂的 `:has()`：**  嵌套多层 `:has()` 或在 `:has()` 中使用非常复杂的选择器会显著增加浏览器计算样式的负担。

**示例：常见的错误使用导致的性能问题**

```css
/* 假设 HTML 中有很多 div 元素 */
div:has(> div > div > div > p.important) {
  /* 应用样式 */
}
```

如果 HTML 结构中有很多嵌套的 `div` 元素，并且浏览器需要检查每个 `div` 是否符合这个复杂的 `:has()` 条件，那么性能会受到影响。浏览器需要深入遍历 `div` 的子树来查找符合条件的 `<p>` 元素。

**5. 用户操作是如何一步步的到达这里，作为调试线索：**

以下是一些用户操作和调试步骤，可能会导致开发者查看 `check_pseudo_has_argument_context.cc` 这个文件：

1. **用户报告样式问题：** 用户反馈网页样式不正确，某些元素应该应用样式却没有应用。
2. **开发者检查 CSS：** 开发者查看 CSS 代码，发现使用了 `:has()` 伪类。
3. **怀疑 `:has()` 匹配失败：** 开发者怀疑 `:has()` 内部的选择器没有正确匹配到元素。
4. **使用浏览器开发者工具调试：**
    * **Elements 面板：** 开发者可能会查看 DOM 树，检查 `:has()` 锚点元素的后代是否确实存在符合参数选择器的元素。
    * **Styles 面板：** 开发者可以查看元素的计算样式 (Computed) 或规则 (Rules)，看 `:has()` 规则是否被应用，以及是否有任何警告或错误信息。
    * **Performance 面板：** 如果页面加载或渲染缓慢，开发者可能会使用 Performance 面板来分析性能瓶颈。如果发现样式计算 (Recalculate Style) 耗时过长，并且涉及到 `:has()` 选择器，那么可能需要深入了解 `:has()` 的实现。
5. **源码调试 (Source Debugging)：**  为了更深入地理解 `:has()` 的匹配过程，开发者可能会查看 Chromium 浏览器的 Blink 引擎源码。
    * **设置断点：** 开发者可能会在与 `:has()` 相关的代码中设置断点，例如 `check_pseudo_has_argument_context.cc`，以查看代码执行流程和变量值。
    * **搜索相关代码：** 开发者可能会搜索包含 "has" 关键字的文件，或者根据 CSS 选择器匹配的流程找到这个文件。
6. **查看日志或性能追踪：**  Blink 引擎可能会有日志或性能追踪信息，记录了选择器匹配的细节。这些信息可能会指向 `check_pseudo_has_argument_context.cc` 中执行的代码。

**总结:**

`check_pseudo_has_argument_context.cc` 是 Blink 引擎中一个关键的文件，它负责分析 CSS `:has()` 伪类选择器的参数，并为后续的 DOM 遍历和选择器匹配提供必要的上下文信息。理解这个文件的功能有助于开发者理解 `:has()` 的工作原理，并能更好地调试与 `:has()` 相关的样式问题和性能瓶颈。

Prompt: 
```
这是目录为blink/renderer/core/css/check_pseudo_has_argument_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/check_pseudo_has_argument_context.h"

#include "third_party/blink/renderer/core/css/check_pseudo_has_fast_reject_filter.h"
#include "third_party/blink/renderer/core/css/css_selector_list.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"

namespace blink {

namespace {

// Iterator class for the compound selectors in the :has() argument selector.
// During iteration, this class collects :has() pseudo class argument
// hashes for fast rejection and provides current compound information.
class CheckPseudoHasArgumentCompoundIterator {
  STACK_ALLOCATED();

 public:
  CheckPseudoHasArgumentCompoundIterator(
      const CSSSelector* compound,
      Vector<unsigned>& pseudo_has_argument_hashes);

  void operator++();
  bool AtEnd() const { return !next_compound_; }

  inline CSSSelector::RelationType RelationToNextCompound() const {
    return relation_to_next_compound_;
  }

  bool CurrentCompoundAffectedBySiblingsOfMatchingElement() const {
    return current_compound_affected_by_ & kSiblingsOfMatchingElement;
  }

  bool CurrentCompoundAffectedByAncestorSiblingsOfMatchingElement() const {
    return current_compound_affected_by_ & kAncestorSiblingsOfMatchingElement;
  }

 private:
  // Flags for extracting sibling relationship information from a :has()
  // argument selector.
  //
  // CheckPseudoHasArgumentContext extracts the relationship information
  // (sibling_combinator_between_child_or_descendant_combinator_ and
  // sibling_combinator_at_rightmost_) and provides them to the SelectorChecker
  // so that the SelectorChecker marks elements that affect a :has() state when
  // there is an element that matches the :has() argument selector. (Please
  // refer the SetAffectedByHasForAgumentMatchedElement() in
  // selector_checker.cc)
  //
  // To extract the information, CheckPseudoHasArgumentContext need to check
  // sibling relationships in a :has() argument selector.
  //
  // By default, CheckPseudoHasArgumentContext can get the sibling relationship
  // information from the direct and indirect adjacent combinators ('~', '+')
  // between two compound selectors of the :has() argument selector.
  // (e.g. set sibling_combinator_at_rightmost_ flag for ':has(.a .b ~ .c)')
  //
  // In most cases, a compound selector doesn't have any sibling relationships
  // in it. (.e.g. 'div.item:hover')
  // But it can have implicit sibling relationships when it has a child indexed
  // pseudo class or a logical combination pseudo class containing a complex
  // selector.
  // - .a:nth-child(3) : An element that matches this compound selector has
  //                     relationships with its siblings since 'nth-child(3)'
  //                     state can be affected by sibling existence.
  // - .a:is(.b ~ .c) : An element that matches this compound selector has
  //                    relationships with its siblings since ':is(.b ~ .c)'
  //                    state can be affected by siblings' class values.
  //
  // A compound selector matching result on an element can be affected by
  // following sibling relationships:
  // - affected by the siblings of the matching element
  // - affected by the ancestors' siblings of the matching element.
  //
  // To extract the sibling relationships within a compound selector of a :has()
  // argument, CheckPseudoHasArgumentContext collects these flags from the
  // simple selectors in the compound selector:
  // - kAffectedBySiblingsOfMatchingElement:
  //     Indicates that the siblings of the matching element can affect the
  //     selector match result.
  // - kAffectedByAncestorSiblingsOfMatchingElement:
  //     Indicates that the matching element's ancestors' siblings can affect
  //     the selector match result.
  //
  // 'MatchingElement' in the flag name indicates the selector's subject
  // element, i.e. the element on which the ':has()' argument selector is being
  // tested.
  using AffectedByFlags = uint32_t;
  enum AffectedByFlag : uint32_t {
    kMatchingElementOnly = 0,
    kSiblingsOfMatchingElement = 1 << 0,
    kAncestorSiblingsOfMatchingElement = 1 << 1,
  };

  inline static bool NeedToCollectAffectedByFlagsFromSubSelector(
      const CSSSelector* simple_selector) {
    switch (simple_selector->GetPseudoType()) {
      case CSSSelector::kPseudoIs:
      case CSSSelector::kPseudoWhere:
      case CSSSelector::kPseudoNot:
      case CSSSelector::kPseudoParent:
        return true;
      default:
        return false;
    }
  }

  static void CollectAffectedByFlagsFromSimpleSelector(
      const CSSSelector* simple_selector,
      AffectedByFlags&);

  const CSSSelector* next_compound_;
  Vector<unsigned>& pseudo_has_argument_hashes_;
  CSSSelector::RelationType relation_to_next_compound_ =
      CSSSelector::kSubSelector;
  AffectedByFlags current_compound_affected_by_ = kMatchingElementOnly;
};

CheckPseudoHasArgumentCompoundIterator::CheckPseudoHasArgumentCompoundIterator(
    const CSSSelector* compound,
    Vector<unsigned>& pseudo_has_argument_hashes)
    : next_compound_(compound),
      pseudo_has_argument_hashes_(pseudo_has_argument_hashes) {
  ++(*this);
}

// Collect sibling relationship within a simple selector in ':has()' argument.
//
// In most cases, a simple selector doesn't have any sibling relationships
// in it. (.e.g. 'div', '.item', ':hover')
// But it can have implicit sibling relationships if it is a child indexed
// pseudo class or a logical combination pseudo class containing a complex
// selector.
// - :nth-child(3) : An element that matches this selector has relationships
//                   with its siblings since the match result can be affected
//                   by sibling existence.
// - :is(.a ~ .b) : An element that matches this selector has relationships
//                  with its siblings since the match result can be affected
//                  by siblings' class values.
// - :is(.a ~ .b .c) : An element that matches this selector has relationships
//                     with its ancestors' siblings since the match result can
//                     be affected by ancestors' siblings' class values.
//
// static
void CheckPseudoHasArgumentCompoundIterator::
    CollectAffectedByFlagsFromSimpleSelector(const CSSSelector* simple_selector,
                                             AffectedByFlags& affected_by) {
  if (simple_selector->IsChildIndexedSelector()) {
    affected_by |= kSiblingsOfMatchingElement;
    return;
  }

  if (!NeedToCollectAffectedByFlagsFromSubSelector(simple_selector)) {
    return;
  }

  // In case of a logical combination pseudo class (e.g. :is(), :where()), the
  // relationship within the logical combination can be collected by checking
  // the simple selectors or the combinators in its sub selectors.
  //
  // While checking the simple selectors and combinators in selector matching
  // order (from rightmost to left), if the sibling relationship is collected,
  // we need to differentiate the sibling relationship by checking whether the
  // child or descendant combinator has already been found or not since the
  // collected sibling relationship make the logical combination pseudo class
  // containing sibling relationship or ancestor sibling relationship.
  //
  // We can see this with the following nested ':is()' case:
  // - ':is(:is(.ancestor_sibling ~ .ancestor) .target)'
  //
  // The inner ':is()' pseudo class contains the 'sibling relationship'
  // because there is one adjacent combinator in the sub selector of the
  // pseudo class and there is no child or descendant combinator to the
  // right of the adjacent combinator:
  // - ':is(.ancestor_sibling ~ .ancestor)'
  //
  // The 'sibling relationship' within the inner 'is()' pseudo class makes
  // the outer ':is()' pseudo class containing the 'ancestor sibling
  // relationship' because there is a descendant combinator to the right of
  // the inner ':is()' pseudo class:
  // - ':is(:is(...) .target)'
  const CSSSelector* sub_selector = simple_selector->SelectorListOrParent();
  for (; sub_selector; sub_selector = CSSSelectorList::Next(*sub_selector)) {
    bool found_child_or_descendant_combinator_in_sub_selector = false;

    for (const CSSSelector* selector = sub_selector; selector;
         selector = selector->NextSimpleSelector()) {
      AffectedByFlags simple_in_sub_affected_by = kMatchingElementOnly;

      CollectAffectedByFlagsFromSimpleSelector(selector,
                                               simple_in_sub_affected_by);

      if (simple_in_sub_affected_by & kSiblingsOfMatchingElement) {
        found_child_or_descendant_combinator_in_sub_selector
            ? affected_by |= kAncestorSiblingsOfMatchingElement
            : affected_by |= kSiblingsOfMatchingElement;
      }
      if (simple_in_sub_affected_by & kAncestorSiblingsOfMatchingElement) {
        affected_by |= kAncestorSiblingsOfMatchingElement;
      }

      switch (selector->Relation()) {
        case CSSSelector::kDescendant:
        case CSSSelector::kChild:
          found_child_or_descendant_combinator_in_sub_selector = true;
          break;
        case CSSSelector::kDirectAdjacent:
        case CSSSelector::kIndirectAdjacent:
          found_child_or_descendant_combinator_in_sub_selector
              ? affected_by |= kAncestorSiblingsOfMatchingElement
              : affected_by |= kSiblingsOfMatchingElement;
          break;
        default:
          break;
      }
    }
  }
}

void CheckPseudoHasArgumentCompoundIterator::operator++() {
  DCHECK(next_compound_);
  current_compound_affected_by_ = kMatchingElementOnly;
  for (const CSSSelector* simple_selector = next_compound_; simple_selector;
       simple_selector = simple_selector->NextSimpleSelector()) {
    CheckPseudoHasFastRejectFilter::CollectPseudoHasArgumentHashes(
        pseudo_has_argument_hashes_, simple_selector);

    CollectAffectedByFlagsFromSimpleSelector(simple_selector,
                                             current_compound_affected_by_);

    relation_to_next_compound_ = simple_selector->Relation();
    if (relation_to_next_compound_ != CSSSelector::kSubSelector) {
      next_compound_ = simple_selector->NextSimpleSelector();
      return;
    }
  }
  next_compound_ = nullptr;
}

}  // namespace

CheckPseudoHasArgumentContext::CheckPseudoHasArgumentContext(
    const CSSSelector* selector,
    bool match_in_shadow_tree)
    : has_argument_(selector), match_in_shadow_tree_(match_in_shadow_tree) {
  depth_limit_ = 0;
  adjacent_distance_limit_ = 0;
  bool contains_child_or_descendant_combinator = false;
  bool sibling_combinator_at_leftmost = false;
  CheckPseudoHasArgumentCompoundIterator iterator(selector,
                                                  pseudo_has_argument_hashes_);
  for (; !iterator.AtEnd(); ++iterator) {
    // If the compound contains an :nth-child() or another child-indexed
    // selector, or the compound contains a logical combination pseudo class
    // containing a sibling relationship in its sub-selector, we need to do the
    // same invalidation as for an indirect adjacent combinator since inserting
    // or removing a sibling at any place may change matching of a :has()
    // selector on any of its siblings or sibling descendant.
    if (iterator.CurrentCompoundAffectedBySiblingsOfMatchingElement()) {
      if (contains_child_or_descendant_combinator) {
        sibling_combinator_at_leftmost = true;
      } else {
        sibling_combinator_at_rightmost_ = true;
      }
    }
    if (iterator.CurrentCompoundAffectedByAncestorSiblingsOfMatchingElement()) {
      sibling_combinator_between_child_or_descendant_combinator_ = true;
    }

    switch (iterator.RelationToNextCompound()) {
      case CSSSelector::kRelativeDescendant:
        leftmost_relation_ = iterator.RelationToNextCompound();
        [[fallthrough]];
      case CSSSelector::kDescendant:
        if (sibling_combinator_at_leftmost) {
          sibling_combinator_at_leftmost = false;
          sibling_combinator_between_child_or_descendant_combinator_ = true;
        }
        contains_child_or_descendant_combinator = true;
        depth_limit_ = kInfiniteDepth;
        adjacent_distance_limit_ = 0;
        break;

      case CSSSelector::kRelativeChild:
        leftmost_relation_ = iterator.RelationToNextCompound();
        [[fallthrough]];
      case CSSSelector::kChild:
        if (sibling_combinator_at_leftmost) {
          sibling_combinator_at_leftmost = false;
          sibling_combinator_between_child_or_descendant_combinator_ = true;
        }
        contains_child_or_descendant_combinator = true;
        if (DepthFixed()) {
          depth_limit_++;
        }
        adjacent_distance_limit_ = 0;
        break;

      case CSSSelector::kRelativeDirectAdjacent:
        leftmost_relation_ = iterator.RelationToNextCompound();
        [[fallthrough]];
      case CSSSelector::kDirectAdjacent:
        if (contains_child_or_descendant_combinator) {
          sibling_combinator_at_leftmost = true;
        } else {
          sibling_combinator_at_rightmost_ = true;
        }
        if (AdjacentDistanceFixed()) {
          adjacent_distance_limit_++;
        }
        break;

      case CSSSelector::kRelativeIndirectAdjacent:
        leftmost_relation_ = iterator.RelationToNextCompound();
        [[fallthrough]];
      case CSSSelector::kIndirectAdjacent:
        if (contains_child_or_descendant_combinator) {
          sibling_combinator_at_leftmost = true;
        } else {
          sibling_combinator_at_rightmost_ = true;
        }
        adjacent_distance_limit_ = kInfiniteAdjacentDistance;
        break;

      default:
        NOTREACHED();
    }
  }
  DCHECK_NE(leftmost_relation_, CSSSelector::kSubSelector);
  DCHECK_LE(adjacent_distance_limit_, kInfiniteAdjacentDistance);
  DCHECK_LE(depth_limit_, kInfiniteDepth);

  switch (leftmost_relation_) {
    case CSSSelector::kRelativeDescendant:
    case CSSSelector::kRelativeChild:
      if (DepthFixed()) {
        traversal_scope_ = kFixedDepthDescendants;
      } else {
        traversal_scope_ = kSubtree;
      }
      siblings_affected_by_has_flags_ =
          SiblingsAffectedByHasFlags::kNoSiblingsAffectedByHasFlags;
      break;
    case CSSSelector::kRelativeIndirectAdjacent:
    case CSSSelector::kRelativeDirectAdjacent:
      if (DepthLimit() == 0) {
        if (AdjacentDistanceFixed()) {
          traversal_scope_ = kOneNextSibling;
        } else {
          traversal_scope_ = kAllNextSiblings;
        }
        siblings_affected_by_has_flags_ =
            SiblingsAffectedByHasFlags::kFlagForSiblingRelationship;
      } else {
        if (AdjacentDistanceFixed()) {
          if (DepthFixed()) {
            traversal_scope_ = kOneNextSiblingFixedDepthDescendants;
          } else {
            traversal_scope_ = kOneNextSiblingSubtree;
          }
        } else {
          if (DepthFixed()) {
            traversal_scope_ = kAllNextSiblingsFixedDepthDescendants;
          } else {
            traversal_scope_ = kAllNextSiblingSubtrees;
          }
        }
        siblings_affected_by_has_flags_ =
            SiblingsAffectedByHasFlags::kFlagForSiblingDescendantRelationship;
      }
      break;
    default:
      NOTREACHED();
  }

  if (match_in_shadow_tree_) {
    switch (traversal_scope_) {
      case kSubtree:
        traversal_scope_ = kShadowRootSubtree;
        break;
      case kFixedDepthDescendants:
        traversal_scope_ = kShadowRootFixedDepthDescendants;
        break;
      default:
        traversal_scope_ = kInvalidShadowRootTraversalScope;
        break;
    }
  }
}

CheckPseudoHasArgumentTraversalIterator::
    CheckPseudoHasArgumentTraversalIterator(
        Element& has_anchor_element,
        CheckPseudoHasArgumentContext& context)
    : has_anchor_element_(&has_anchor_element),
      match_in_shadow_tree_(context.MatchInShadowTree()),
      depth_limit_(context.DepthLimit()) {
  if (match_in_shadow_tree_) {
    if (!has_anchor_element.GetShadowRoot() ||
        context.TraversalScope() == kInvalidShadowRootTraversalScope) {
      DCHECK_EQ(current_element_, nullptr);
      return;
    }
  }

  if (!context.AdjacentDistanceFixed()) {
    // Set the last_element_ as the next sibling of the :has() anchor element,
    // and move to the last sibling of the :has() anchor element, and move again
    // to the last descendant of the last sibling.
    last_element_ = ElementTraversal::NextSibling(*has_anchor_element_);
    if (!last_element_) {
      DCHECK_EQ(current_element_, nullptr);
      return;
    }
    Element* last_sibling =
        ElementTraversal::LastChild(*has_anchor_element_->parentNode());
    current_element_ = LastWithin(last_sibling);
    if (!current_element_) {
      current_element_ = last_sibling;
    }
  } else if (context.AdjacentDistanceLimit() == 0) {
    DCHECK_GT(context.DepthLimit(), 0);
    // Set the last_element_ as the first child of the :has() anchor element,
    // and move to the last descendant of the :has() anchor element without
    // exceeding the depth limit.
    ContainerNode* has_anchor_node = has_anchor_element_;
    if (match_in_shadow_tree_) {
      has_anchor_node = has_anchor_element_->GetShadowRoot();
    }
    last_element_ = ElementTraversal::FirstChild(*has_anchor_node);
    if (!last_element_) {
      DCHECK_EQ(current_element_, nullptr);
      return;
    }
    current_element_ = LastWithin(has_anchor_node);
    DCHECK(current_element_);
  } else {
    // Set last_element_ as the next sibling of the :has() anchor element, set
    // the sibling_at_fixed_distance_ as the element at the adjacent distance
    // of the :has() anchor element, and move to the last descendant of the
    // sibling at fixed distance without exceeding the depth limit.
    int distance = 1;
    Element* old_sibling = nullptr;
    Element* sibling = ElementTraversal::NextSibling(*has_anchor_element_);
    for (; distance < context.AdjacentDistanceLimit() && sibling;
         distance++, sibling = ElementTraversal::NextSibling(*sibling)) {
      old_sibling = sibling;
    }
    if (sibling) {
      sibling_at_fixed_distance_ = sibling;
      current_element_ = LastWithin(sibling_at_fixed_distance_);
      if (!current_element_) {
        current_element_ = sibling_at_fixed_distance_;
      }
    } else {
      current_element_ = old_sibling;
      if (!current_element_) {
        return;
      }
      // set the depth_limit_ to 0 so that the iterator only traverse to the
      // siblings of the :has() anchor element.
      depth_limit_ = 0;
    }
    last_element_ = ElementTraversal::NextSibling(*has_anchor_element_);
  }
}

Element* CheckPseudoHasArgumentTraversalIterator::LastWithin(
    ContainerNode* container_node) {
  // If the current depth is at the depth limit, return null.
  if (current_depth_ == depth_limit_) {
    return nullptr;
  }

  // Return the last element of the pre-order traversal starting from the passed
  // in container node without exceeding the depth limit.
  Element* last_descendant = nullptr;
  for (Element* descendant = ElementTraversal::LastChild(*container_node);
       descendant; descendant = ElementTraversal::LastChild(*descendant)) {
    last_descendant = descendant;
    if (++current_depth_ == depth_limit_) {
      break;
    }
  }
  return last_descendant;
}

void CheckPseudoHasArgumentTraversalIterator::operator++() {
  DCHECK(current_element_);
  DCHECK_NE(current_element_, has_anchor_element_);
  if (current_element_ == last_element_) {
    current_element_ = nullptr;
    return;
  }

  // If current element is the sibling at fixed distance, set the depth_limit_
  // to 0 so that the iterator only traverse to the siblings of the :has()
  // anchor element.
  if (current_depth_ == 0 && sibling_at_fixed_distance_ == current_element_) {
    sibling_at_fixed_distance_ = nullptr;
    depth_limit_ = 0;
  }

  // Move to the previous element in DOM tree order within the depth limit.
  if (Element* next = ElementTraversal::PreviousSibling(*current_element_)) {
    Element* last_descendant = LastWithin(next);
    current_element_ = last_descendant ? last_descendant : next;
  } else {
    DCHECK_GT(current_depth_, 0);
    current_depth_--;
    current_element_ = current_element_->parentElement();
  }
  DCHECK(current_element_);
}

}  // namespace blink

"""

```