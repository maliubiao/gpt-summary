Response:
Let's break down the thought process to analyze the provided C++ code for `style_invalidator.cc`.

1. **Understand the Goal:** The request is to explain the functionality of this file within the Chromium Blink rendering engine, focusing on its interaction with HTML, CSS, and JavaScript, and identifying potential user/programming errors and debugging approaches.

2. **Initial Code Scan and Keyword Recognition:**  Quickly scan the code for key terms and patterns. Words like `Invalidate`, `StyleRecalc`, `InvalidationSet`, `Element`, `Document`, `CSS`, and concepts like "subtree" and "siblings" immediately stand out as relevant to style recalculation and CSS application. The presence of `TRACE_STYLE_INVALIDATOR_INVALIDATION` suggests debugging or performance monitoring instrumentation.

3. **Identify the Core Class:**  The file name and the prominent presence of `StyleInvalidator` point to this being the central class responsible for triggering style invalidation.

4. **Analyze the `Invalidate` Methods (Entry Points):**  The overloaded `Invalidate` methods (taking `Document` and `Element` as arguments) are likely the entry points for the invalidation process. Focus on what these methods do.

    * **`Invalidate(Document& document, Element* root_element)`:** This seems to be the top-level invalidation trigger. It handles document-level invalidation and then calls the other `Invalidate` for a specific element. The logic around `NeedsStyleInvalidation()` and `ClearNeedsStyleInvalidation()` hints at a state management mechanism. The loop iterating through siblings and ancestors suggests a traversal strategy.

    * **`Invalidate(Element& element, SiblingData& sibling_data)`:** This is the core recursive function. It advances sibling tracking, checks for invalidation matches, and then potentially recurses down to children. The `RecursionCheckpoint` suggests managing state during recursion.

5. **Examine Supporting Classes and Data Structures:**  Look at other classes and data structures used:

    * **`InvalidationSet`:**  This class clearly holds information about *what* needs to be invalidated. Its methods like `InvalidatesElement`, `WholeSubtreeInvalid`, and flags like `CustomPseudoInvalid` are key to understanding the criteria for invalidation.

    * **`SiblingData`:** This manages invalidation related to sibling elements, likely for handling adjacent selectors (`+`, `~`).

    * **`PendingInvalidationMap`:** This maps nodes to collections of `InvalidationSet`s, indicating which invalidations are waiting to be processed.

    * **`NodeInvalidationSets`:**  Likely a container for different types of invalidation sets (sibling, descendant) associated with a node.

6. **Trace the Logic Flow:**  Imagine a scenario where a CSS property changes. How might this code be involved?

    * The change likely triggers setting a "needs style invalidation" flag on some element.
    * The `Invalidate(Document, Element)` method would be called.
    * The code would traverse the DOM, checking elements against the `InvalidationSet`s.
    * If an element matches an `InvalidationSet`, its style needs to be recalculated (`SetNeedsStyleRecalc`).
    * The recursion ensures that the invalidation propagates down the tree.

7. **Connect to HTML, CSS, and JavaScript:**

    * **HTML:** The code operates on `Element`s and the DOM structure, which are fundamental to HTML. Changes in HTML structure (adding/removing elements) or attributes can trigger invalidation.

    * **CSS:** The `InvalidationSet`s are derived from CSS rules. Changes in CSS (e.g., modifying a stylesheet, adding a class) lead to the creation of these sets. Selectors play a crucial role in determining which elements are affected.

    * **JavaScript:** JavaScript can manipulate the DOM and CSS. For instance, `element.style.color = 'red'` or adding/removing classes via JavaScript will trigger the invalidation process.

8. **Identify Potential Errors and Debugging:**

    * **User Errors:** Think about common mistakes web developers make with CSS and JavaScript that might lead to unexpected style recalculations. Overly broad selectors, frequent DOM manipulations, and complex CSS rules are good candidates.

    * **Debugging:** The tracing macros (`TRACE_STYLE_INVALIDATOR_INVALIDATION`) suggest using logging or debugging tools to track invalidation. Understanding the call stack leading to `Invalidate` is important.

9. **Formulate Examples and Explanations:** Based on the understanding gained, construct concrete examples that illustrate the functionality and the connections to HTML, CSS, and JavaScript. Provide hypothetical inputs and outputs to show how the code might behave in specific scenarios.

10. **Structure the Answer:** Organize the information logically, starting with a high-level overview of the file's purpose and then diving into specific functionalities, connections, errors, and debugging. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This just recalculates styles."  **Correction:** It *triggers* the *need* for recalculation based on changes and CSS rules. It's more about the *invalidation* process.
* **Focusing too much on specific lines:**  **Correction:** Step back and understand the overall algorithm and the roles of different classes.
* **Not enough emphasis on the "why":** **Correction:** Explain *why* this invalidation is necessary—to keep the rendered page consistent with the current HTML, CSS, and state.
* **Overlooking the tracing aspects:** **Correction:** Recognize the importance of the `TRACE_*` macros for debugging and performance analysis.

By following this iterative process of examining the code, tracing the logic, connecting it to the web development context, and refining the understanding, a comprehensive and accurate explanation can be constructed.
这个文件 `style_invalidator.cc` 是 Chromium Blink 引擎中负责**标记需要重新计算样式的元素**的关键组件。它管理着样式失效（invalidation）的过程，确保在 HTML、CSS 或 JavaScript 发生影响元素样式变化时，只有必要的元素才会被标记为需要重新计算样式，从而提高渲染性能。

以下是它的主要功能：

**1. 接收样式失效通知并传播:**

*   当文档的 DOM 结构、元素属性、CSS 样式规则发生变化时，其他 Blink 组件会通知 `StyleInvalidator`。
*   `StyleInvalidator` 接收这些通知，并根据失效的类型和范围，决定哪些元素需要重新计算样式。

**2. 管理和应用失效集 (Invalidation Sets):**

*   `InvalidationSet` 对象描述了导致样式失效的具体原因和影响范围。例如，一个 CSS 规则的变化可能会创建一个 `InvalidationSet`。
*   `StyleInvalidator` 维护着待处理的失效集列表 (`invalidation_sets_` 和 `pending_invalidation_map_`)。
*   它会将这些失效集与 DOM 树中的元素进行匹配，判断哪些元素受到影响。

**3. 递归地遍历 DOM 树并标记失效元素:**

*   `Invalidate` 方法是核心，它从指定的根元素开始，递归地遍历其子树。
*   在遍历过程中，它会检查当前元素是否与待处理的失效集匹配 (`MatchesCurrentInvalidationSets` 和 `MatchCurrentInvalidationSets`)。
*   如果元素匹配某个失效集，则会调用 `element.SetNeedsStyleRecalc()` 将其标记为需要重新计算样式。

**4. 处理不同类型的样式失效:**

*   **全局失效 (Document-level Invalidation):** 当文档级别的样式发生变化时（例如，修改了 `<style>` 标签或引入了新的样式表），整个文档可能会被标记为需要失效。
*   **局部失效 (Element-level Invalidation):**  更常见的情况是，只有部分元素受到影响，例如，修改了某个元素的 class 属性或内联样式。
*   **Sibling 相关的失效 (Sibling Invalidation):**  处理像 `:nth-child`, `+`, `~` 这样的 CSS 选择器引起的失效，这些选择器的结果取决于兄弟元素的状态。`SiblingData` 结构用于跟踪兄弟元素的状态。
*   **Shadow DOM 相关的失效:**  正确处理 Shadow DOM 边界的样式失效。
*   **Slot 元素相关的失效:** 处理 `<slot>` 元素中分发的节点引起的样式失效。
*   **Parts 相关的失效:**  处理 CSS Parts 功能引起的样式失效。
*   **Custom Pseudo-classes 相关的失效:** 处理自定义伪类引起的失效。

**5. 优化失效过程:**

*   **避免不必要的遍历:**  通过 `WholeSubtreeInvalid()` 标志，如果整个子树都需要重新计算样式，则可以跳过对子节点的详细检查。
*   **延迟失效 (Pending Invalidation):**  使用 `pending_invalidation_map_` 存储待处理的失效信息，可以在合适的时机批量处理，提高效率。

**它与 JavaScript, HTML, CSS 的关系举例说明:**

*   **JavaScript:**
    *   **假设输入:** JavaScript 代码修改了元素的 `className` 属性，例如 `element.className = 'new-class';`
    *   **逻辑推理:**  Blink 引擎会捕获到这个 DOM 属性的变化，并创建一个与 class 属性相关的 `InvalidationSet`。`StyleInvalidator::Invalidate` 会被调用，遍历 DOM 树，找到 `element`，并发现它与这个 `InvalidationSet` 匹配。
    *   **输出:** `element` 的 `NeedsStyleRecalc` 标志会被设置为 true。
*   **HTML:**
    *   **假设输入:**  HTML 结构发生变化，例如通过 JavaScript `element.appendChild(newNode)` 添加了一个新的子元素。
    *   **逻辑推理:**  Blink 引擎会捕获到 DOM 树的结构变化，可能会创建一个影响父元素和新子元素的 `InvalidationSet`。`StyleInvalidator::Invalidate` 会遍历到父元素和新子元素，并根据失效集标记它们。
    *   **输出:** 父元素和新子元素的 `NeedsStyleRecalc` 标志可能会被设置为 true。
*   **CSS:**
    *   **假设输入:**  CSS 样式规则被修改，例如通过 JavaScript 修改了样式表的 `cssRules`。
    *   **逻辑推理:**  Blink 引擎会解析新的 CSS 规则，并根据规则的变化创建新的 `InvalidationSet`。例如，如果修改了一个影响所有 `div` 元素的规则，则会创建一个匹配 `div` 元素的失效集。`StyleInvalidator::Invalidate` 会遍历 DOM 树，找到 `div` 元素，并使其与新的失效集匹配。
    *   **输出:** 所有 `div` 元素的 `NeedsStyleRecalc` 标志可能会被设置为 true。

**用户或编程常见的使用错误举例说明:**

*   **错误:**  频繁地在 JavaScript 中修改元素的内联样式或 class 属性，导致大量的样式失效。
    *   **场景:**  一个动画效果通过 JavaScript 每帧都修改元素的 `style.left` 属性。
    *   **后果:**  `StyleInvalidator` 会不断地标记该元素及其可能相关的元素需要重新计算样式，导致频繁的样式计算和布局，影响性能，可能导致页面卡顿。
*   **错误:**  编写过于宽泛的 CSS 选择器，导致不必要的样式失效。
    *   **场景:**  一个 CSS 规则 `div * { color: red; }` 会影响所有 `div` 元素的所有后代。
    *   **后果:**  当任何 `div` 元素或其后代的样式发生变化时，`StyleInvalidator` 可能需要检查大量的元素，即使这些元素实际上不受影响。
*   **错误:**  在自定义元素或 Shadow DOM 中不当使用 slotted 内容，导致样式失效逻辑混乱。
    *   **场景:**  自定义元素中使用了 `<slot>`，并且 CSS 规则依赖于 slotted 内容的状态，但 slotted 内容的生命周期管理不当。
    *   **后果:**  `StyleInvalidator` 可能无法正确识别哪些元素需要重新计算样式，导致样式错误或性能问题。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在浏览器中进行以下操作：

1. **用户在输入框中输入文字。**
2. **JavaScript 监听输入事件，并根据输入内容动态地添加或移除某些元素的 CSS 类。** 例如，高亮匹配的搜索结果。
3. **CSS 规则定义了不同类名对应的样式。**

**调试线索:**

当用户输入文字时，JavaScript 代码会执行，修改 DOM 元素的 `className` 属性。这个操作会触发 Blink 引擎的样式失效流程：

1. **DOM 修改通知:**  当 `className` 属性改变时，Blink 的 DOM 组件会发出一个通知，表明元素的属性已更改。
2. **样式失效触发:**  Blink 的样式系统接收到这个通知，并创建一个与 class 属性变化相关的 `InvalidationSet`。
3. **`StyleInvalidator::Invalidate` 调用:**  Blink 会调用 `StyleInvalidator::Invalidate` 方法，通常以修改的元素或其最近的包含块作为根元素。
4. **失效集匹配:**  `StyleInvalidator` 会遍历 DOM 树，并将创建的 `InvalidationSet` 与遍历到的元素进行匹配。它会检查元素的 class 属性是否与失效集描述的变化相关。
5. **标记需要重算样式:**  对于 class 属性被修改的元素，以及可能受到 CSS 选择器影响的其他元素（例如，使用了 `:hover`, `:nth-child` 等选择器），`StyleInvalidator` 会调用 `element.SetNeedsStyleRecalc()` 将它们标记为需要重新计算样式。
6. **后续处理:**  被标记为需要重新计算样式的元素，在布局阶段会进行样式的重新计算，并将结果用于渲染。

**调试时，可以关注以下方面：**

*   **断点设置:**  在 `StyleInvalidator::Invalidate`, `MatchesCurrentInvalidationSets`, `PushInvalidationSetsForContainerNode` 等关键方法中设置断点，观察失效过程的触发和执行。
*   **日志输出:**  查看 Blink 的日志输出，了解哪些失效集被创建，哪些元素被标记为失效。可以使用 `TRACE_STYLE_INVALIDATOR_INVALIDATION` 相关的宏来开启更详细的日志。
*   **Performance 工具:**  使用 Chrome DevTools 的 Performance 面板，查看 "Recalculate Style" 事件的耗时和调用栈，可以帮助定位导致样式失效的原因。
*   **Invalidation Tracking:**  Chrome DevTools 的 "Rendering" 选项卡下有 "Paint flashing" 和 "Layout Shift Regions" 等工具，可以帮助可视化哪些区域发生了重绘和回流，这与样式失效直接相关。

总而言之，`style_invalidator.cc` 是 Blink 引擎中一个至关重要的模块，它负责高效地管理样式失效，确保在各种变化发生时，只有必要的元素才会被标记为需要重新计算样式，从而保证页面的性能和正确渲染。理解其工作原理对于开发高性能的 Web 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/core/css/invalidation/style_invalidator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/invalidation/style_invalidator.h"

#include "third_party/blink/renderer/core/css/invalidation/invalidation_set.h"
#include "third_party/blink/renderer/core/css/invalidation/invalidation_tracing_flag.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"

namespace blink {

#define TRACE_STYLE_INVALIDATOR_INVALIDATION_IF_ENABLED(element, reason) \
  if (InvalidationTracingFlag::IsEnabled()) [[unlikely]]                 \
    TRACE_STYLE_INVALIDATOR_INVALIDATION(element, reason);

void StyleInvalidator::Invalidate(Document& document, Element* root_element) {
  SiblingData sibling_data;

  if (document.NeedsStyleInvalidation()) [[unlikely]] {
    DCHECK(root_element == document.documentElement());
    PushInvalidationSetsForContainerNode(document, sibling_data);
    document.ClearNeedsStyleInvalidation();
    DCHECK(sibling_data.IsEmpty());
  }

  if (root_element) {
    Invalidate(*root_element, sibling_data);
    if (!sibling_data.IsEmpty()) {
      for (Element* child = ElementTraversal::NextSibling(*root_element); child;
           child = ElementTraversal::NextSibling(*child)) {
        Invalidate(*child, sibling_data);
      }
    }
    for (Node* ancestor = root_element; ancestor;
         ancestor = ancestor->ParentOrShadowHostNode()) {
      ancestor->ClearChildNeedsStyleInvalidation();
    }
  }
  document.ClearChildNeedsStyleInvalidation();
  pending_invalidation_map_.clear();
  pending_nth_sets_.clear();
}

StyleInvalidator::StyleInvalidator(
    PendingInvalidationMap& pending_invalidation_map)
    : pending_invalidation_map_(pending_invalidation_map) {}

StyleInvalidator::~StyleInvalidator() = default;

void StyleInvalidator::PushInvalidationSet(
    const InvalidationSet& invalidation_set) {
  DCHECK(!invalidation_flags_.WholeSubtreeInvalid());
  DCHECK(!invalidation_set.WholeSubtreeInvalid());
  DCHECK(!invalidation_set.IsEmpty());
  if (invalidation_set.CustomPseudoInvalid()) {
    invalidation_flags_.SetInvalidateCustomPseudo(true);
  }
  if (invalidation_set.TreeBoundaryCrossing()) {
    invalidation_flags_.SetTreeBoundaryCrossing(true);
  }
  if (invalidation_set.InsertionPointCrossing()) {
    invalidation_flags_.SetInsertionPointCrossing(true);
  }
  if (invalidation_set.InvalidatesSlotted()) {
    invalidation_flags_.SetInvalidatesSlotted(true);
  }
  if (invalidation_set.InvalidatesParts()) {
    invalidation_flags_.SetInvalidatesParts(true);
  }
  invalidation_sets_.push_back(&invalidation_set);
}

ALWAYS_INLINE bool StyleInvalidator::MatchesCurrentInvalidationSets(
    Element& element) const {
  if (invalidation_flags_.InvalidateCustomPseudo() &&
      element.ShadowPseudoId() != g_null_atom) {
    TRACE_STYLE_INVALIDATOR_INVALIDATION_IF_ENABLED(element,
                                                    kInvalidateCustomPseudo);
    return true;
  }

  for (auto* const invalidation_set : invalidation_sets_) {
    if (invalidation_set->InvalidatesElement(element)) {
      return true;
    }
  }

  return false;
}

bool StyleInvalidator::MatchesCurrentInvalidationSetsAsSlotted(
    Element& element) const {
  DCHECK(invalidation_flags_.InvalidatesSlotted());

  for (auto* const invalidation_set : invalidation_sets_) {
    if (!invalidation_set->InvalidatesSlotted()) {
      continue;
    }
    if (invalidation_set->InvalidatesElement(element)) {
      return true;
    }
  }
  return false;
}

bool StyleInvalidator::MatchesCurrentInvalidationSetsAsParts(
    Element& element) const {
  DCHECK(invalidation_flags_.InvalidatesParts());

  for (auto* const invalidation_set : invalidation_sets_) {
    if (!invalidation_set->InvalidatesParts()) {
      continue;
    }
    if (invalidation_set->InvalidatesElement(element)) {
      return true;
    }
  }
  return false;
}

void StyleInvalidator::SiblingData::PushInvalidationSet(
    const SiblingInvalidationSet& invalidation_set) {
  unsigned invalidation_limit;
  if (invalidation_set.MaxDirectAdjacentSelectors() == UINT_MAX) {
    invalidation_limit = UINT_MAX;
  } else {
    invalidation_limit =
        element_index_ + invalidation_set.MaxDirectAdjacentSelectors();
  }
  invalidation_entries_.push_back(Entry(&invalidation_set, invalidation_limit));
}

bool StyleInvalidator::SiblingData::MatchCurrentInvalidationSets(
    Element& element,
    StyleInvalidator& style_invalidator) {
  bool this_element_needs_style_recalc = false;
  DCHECK(!style_invalidator.WholeSubtreeInvalid());

  unsigned index = 0;
  while (index < invalidation_entries_.size()) {
    if (element_index_ > invalidation_entries_[index].invalidation_limit_) {
      // invalidation_entries_[index] only applies to earlier siblings. Remove
      // it.
      invalidation_entries_[index] = invalidation_entries_.back();
      invalidation_entries_.pop_back();
      continue;
    }

    const SiblingInvalidationSet& invalidation_set =
        *invalidation_entries_[index].invalidation_set_;
    ++index;
    if (!invalidation_set.InvalidatesElement(element)) {
      continue;
    }

    if (invalidation_set.InvalidatesSelf()) {
      this_element_needs_style_recalc = true;
    }

    if (const DescendantInvalidationSet* descendants =
            invalidation_set.SiblingDescendants()) {
      if (descendants->WholeSubtreeInvalid()) {
        TRACE_STYLE_INVALIDATOR_INVALIDATION_SET(
            element, kInvalidationSetInvalidatesSubtree, *descendants);
        element.SetNeedsStyleRecalc(
            kSubtreeStyleChange, StyleChangeReasonForTracing::Create(
                                     style_change_reason::kRelatedStyleRule));
        return true;
      }

      if (!descendants->IsEmpty()) {
        style_invalidator.PushInvalidationSet(*descendants);
      }
    }
  }
  return this_element_needs_style_recalc;
}

void StyleInvalidator::PushInvalidationSetsForContainerNode(
    ContainerNode& node,
    SiblingData& sibling_data) {
  auto pending_invalidations_iterator = pending_invalidation_map_.find(&node);
  if (pending_invalidations_iterator == pending_invalidation_map_.end()) {
    DUMP_WILL_BE_NOTREACHED()
        << "We should strictly not have marked an element for "
           "invalidation without any pending invalidations.";
    return;
  }
  NodeInvalidationSets& pending_invalidations =
      pending_invalidations_iterator->value;

  DCHECK(pending_nth_sets_.empty());

  for (const auto& invalidation_set : pending_invalidations.Siblings()) {
    CHECK(invalidation_set->IsAlive());
    if (invalidation_set->IsNthSiblingInvalidationSet()) {
      AddPendingNthSiblingInvalidationSet(
          To<NthSiblingInvalidationSet>(*invalidation_set));
    } else {
      sibling_data.PushInvalidationSet(
          To<SiblingInvalidationSet>(*invalidation_set));
    }
  }

  if (node.GetStyleChangeType() == kSubtreeStyleChange) {
    return;
  }

  if (!pending_invalidations.Descendants().empty()) {
    for (const auto& invalidation_set : pending_invalidations.Descendants()) {
      CHECK(invalidation_set->IsAlive());
      PushInvalidationSet(*invalidation_set);
    }
    if (InvalidationTracingFlag::IsEnabled()) [[unlikely]] {
      DEVTOOLS_TIMELINE_TRACE_EVENT_INSTANT_WITH_CATEGORIES(
          TRACE_DISABLED_BY_DEFAULT("devtools.timeline.invalidationTracking"),
          "StyleInvalidatorInvalidationTracking",
          inspector_style_invalidator_invalidate_event::InvalidationList, node,
          pending_invalidations.Descendants());
    }
  }
}

ALWAYS_INLINE bool StyleInvalidator::CheckInvalidationSetsAgainstElement(
    Element& element,
    SiblingData& sibling_data) {
  // We need to call both because the sibling data may invalidate the whole
  // subtree at which point we can stop recursing.
  bool matches_current = MatchesCurrentInvalidationSets(element);
  bool matches_sibling;
  if (!sibling_data.IsEmpty() &&
      sibling_data.MatchCurrentInvalidationSets(element, *this)) [[unlikely]] {
    matches_sibling = true;
  } else {
    matches_sibling = false;
  }
  return matches_current || matches_sibling;
}

void StyleInvalidator::InvalidateShadowRootChildren(Element& element) {
  if (ShadowRoot* root = element.GetShadowRoot()) {
    if (!TreeBoundaryCrossing() && !root->ChildNeedsStyleInvalidation() &&
        !root->NeedsStyleInvalidation()) {
      return;
    }
    RecursionCheckpoint checkpoint(this);
    SiblingData sibling_data;
    if (!WholeSubtreeInvalid()) {
      if (root->NeedsStyleInvalidation()) [[unlikely]] {
        // The shadow root does not have any siblings. There should never be any
        // other sets than the nth set to schedule.
        DCHECK(sibling_data.IsEmpty());
        PushInvalidationSetsForContainerNode(*root, sibling_data);
      }
    }
    PushNthSiblingInvalidationSets(sibling_data);
    for (Element* child = ElementTraversal::FirstChild(*root); child;
         child = ElementTraversal::NextSibling(*child)) {
      Invalidate(*child, sibling_data);
    }
    root->ClearChildNeedsStyleInvalidation();
    root->ClearNeedsStyleInvalidation();
  }
}

void StyleInvalidator::InvalidateChildren(Element& element) {
  if (!!element.GetShadowRoot()) [[unlikely]] {
    InvalidateShadowRootChildren(element);
  }

  // Initialization of the variable costs up to 15% on blink_perf.css
  // AttributeDescendantSelector.html benchmark.
  SiblingData sibling_data STACK_UNINITIALIZED;
  PushNthSiblingInvalidationSets(sibling_data);

  for (Element* child = ElementTraversal::FirstChild(element); child;
       child = ElementTraversal::NextSibling(*child)) {
    Invalidate(*child, sibling_data);
  }
}

void StyleInvalidator::Invalidate(Element& element, SiblingData& sibling_data) {
  sibling_data.Advance();
  // Preserves the current stack of pending invalidations and other state and
  // restores it when this method returns.
  RecursionCheckpoint checkpoint(this);

  // If we have already entered a subtree that is going to be entirely
  // recalculated then there is no need to test against current invalidation
  // sets or to continue to accumulate new invalidation sets as we descend the
  // tree.
  if (!WholeSubtreeInvalid()) {
    if (element.GetStyleChangeType() == kSubtreeStyleChange) {
      SetWholeSubtreeInvalid();
    } else if (CheckInvalidationSetsAgainstElement(element, sibling_data)) {
      element.SetNeedsStyleRecalc(kLocalStyleChange,
                                  StyleChangeReasonForTracing::Create(
                                      style_change_reason::kRelatedStyleRule));
    }
    if (element.NeedsStyleInvalidation()) [[unlikely]] {
      PushInvalidationSetsForContainerNode(element, sibling_data);
    }

    auto* html_slot_element = DynamicTo<HTMLSlotElement>(element);
    if (html_slot_element && InvalidatesSlotted()) {
      InvalidateSlotDistributedElements(*html_slot_element);
    }
  }

  // We need to recurse into children if:
  // * the whole subtree is not invalid and we have invalidation sets that
  //   could apply to the descendants.
  // * there are invalidation sets attached to descendants then we need to
  //   clear the flags on the nodes, whether we use the sets or not.
  if ((!WholeSubtreeInvalid() && HasInvalidationSets() &&
       element.GetComputedStyle()) ||
      element.ChildNeedsStyleInvalidation()) {
    InvalidateChildren(element);
  } else {
    ClearPendingNthSiblingInvalidationSets();
  }

  element.ClearChildNeedsStyleInvalidation();
  element.ClearNeedsStyleInvalidation();
}

void StyleInvalidator::InvalidateSlotDistributedElements(
    HTMLSlotElement& slot) const {
  for (auto& distributed_node : slot.FlattenedAssignedNodes()) {
    if (distributed_node->NeedsStyleRecalc()) {
      continue;
    }
    auto* element = DynamicTo<Element>(distributed_node.Get());
    if (!element) {
      continue;
    }
    if (MatchesCurrentInvalidationSetsAsSlotted(*element)) {
      distributed_node->SetNeedsStyleRecalc(
          kLocalStyleChange, StyleChangeReasonForTracing::Create(
                                 style_change_reason::kRelatedStyleRule));
    }
  }
}

}  // namespace blink

"""

```