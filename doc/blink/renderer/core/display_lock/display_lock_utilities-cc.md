Response:
Let's break down the thought process for summarizing the provided C++ code.

**1. Initial Understanding of the Goal:**

The core request is to analyze a Chromium Blink engine source file (`display_lock_utilities.cc`) and explain its functionality, its relationship to web technologies (JavaScript, HTML, CSS), provide examples with input/output if logical reasoning is involved, highlight potential user/programming errors, and finally, summarize its overall purpose. The prompt also specifies this is Part 1 of 2.

**2. High-Level Overview of the Code:**

The file name itself, "display_lock_utilities.cc," strongly suggests it contains utility functions related to a "display lock" feature within the Blink rendering engine. The includes confirm this, pointing to classes like `DisplayLockContext`, `DisplayLockDocumentState`, and fundamental DOM elements (`Element`, `Node`).

**3. Identifying Key Functionalities (Iterative Process):**

I started by skimming the code, looking for function definitions and their names. This gives a broad sense of what the utility class offers. I noticed patterns and groupings of related functions.

* **Ancestor Traversal:** Many functions deal with finding the nearest ancestor (inclusive or exclusive) that has a display lock. Names like `NearestLockedExclusiveAncestor`, `NearestLockedInclusiveAncestor`, `HighestLockedInclusiveAncestor`, `HighestLockedExclusiveAncestor` are prominent. This suggests a core function of determining if a node is within a locked region.

* **Activation:** Functions like `ActivateFindInPageMatchRangeIfNeeded` and `NeedsActivationForFindInPage` indicate functionality related to activating display locks based on certain events.

* **Forced Updates:**  The `ScopedForcedUpdate` class stands out. It seems designed to temporarily override display locks to force updates in specific scenarios. This is important for interactions like selection changes or programmatic updates.

* **Preventing Updates (Style, Layout, Paint):** Several functions with names like `LockedInclusiveAncestorPreventingLayout`, `LockedAncestorPreventingPaint`, etc., are designed to check if any ancestor with a display lock is preventing specific rendering phases.

* **Focus and Selection:** Functions like `ElementLostFocus`, `ElementGainedFocus`, and `SelectionChanged` suggest that display locks interact with focus and selection mechanisms.

* **Memoization:**  The `memoizer_` variable and functions like `IsLockedForAccessibility` and `IsDisplayLockedPreventingPaint` point to an optimization technique (memoization) to avoid redundant calculations when checking for lock status.

**4. Mapping to Web Technologies:**

After identifying the core functionalities, I considered how they relate to JavaScript, HTML, and CSS.

* **HTML:** Display locks are conceptually tied to HTML elements. The functions operate on `Node` and `Element` objects, which represent the HTML structure. The `hidden="until-found"` attribute example directly relates to HTML attributes.

* **CSS:** Display locks can influence rendering and thus implicitly interact with CSS. While not directly manipulating CSS properties, they can prevent style application or layout calculations.

* **JavaScript:**  JavaScript can trigger actions that might interact with display locks (e.g., find-in-page, programmatic scrolling, focus changes). The `ActivateDisplayLockIfNeeded` function is a direct link.

**5. Developing Examples (Logical Reasoning and Assumptions):**

For functions involving logical decisions, I tried to create simple "if-then" scenarios.

* **`NearestLockedExclusiveAncestor`:**  The assumption is the input is a node, and the output is the nearest *exclusive* ancestor with a lock. I pictured a simple DOM tree to illustrate.

* **`ActivateFindInPageMatchRangeIfNeeded`:**  The assumption is a range of text is provided (likely from a find-in-page operation). The output is whether a display lock was activated. The internal logic connects to finding an enclosing block element.

* **`IsDisplayLockedPreventingPaint`:**  The example demonstrates how a locked ancestor prevents painting of its descendants.

**6. Identifying Potential Errors:**

I looked for patterns that could lead to common mistakes:

* **Incorrectly assuming an element is unlocked:** If a developer tries to manipulate or measure an element within a locked subtree without considering the lock, they might get unexpected results.

* **Forgetting to activate a lock:** If a feature relies on a display lock being active but the activation logic isn't triggered correctly, the feature might not work as intended.

**7. Structuring the Summary:**

Finally, I organized the information into a clear and concise summary. I grouped related functionalities together and used descriptive language. I explicitly addressed the prompts about web technologies, examples, and errors.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe focus on individual function implementations.
* **Correction:**  Shift focus to the *purpose* of groups of functions and their overall contribution to the display lock mechanism.

* **Initial thought:** Provide very detailed technical explanations of internal mechanics.
* **Correction:**  Keep the explanation at a higher level, focusing on the *what* and *why* rather than the intricate *how*.

* **Initial thought:**  Separate the web technology connections completely.
* **Correction:** Integrate the web technology relevance throughout the explanation to show the practical implications of the C++ code.

By following this iterative process of understanding, identifying key functionalities, relating them to web technologies, generating examples, and considering potential errors, I was able to construct a comprehensive summary of the provided C++ code.
好的，这是对 `blink/renderer/core/display_lock/display_lock_utilities.cc` 文件功能的归纳：

**文件功能归纳：**

`display_lock_utilities.cc` 文件提供了一系列**静态工具函数**，用于管理和查询 Blink 渲染引擎中的 **Display Lock (显示锁定)** 机制。 Display Lock 是一种优化技术，允许在特定 DOM 子树上暂停渲染更新（例如样式计算、布局、绘制），直到满足特定条件（例如用户交互、JavaScript 触发）。

**核心功能可以概括为以下几点：**

1. **判断节点是否被 Display Lock 影响/阻止更新:**
   - 提供多种函数来判断一个节点或其祖先是否被 Display Lock 锁定，并阻止了特定的渲染阶段（样式、布局、绘制、预绘制）。
   - 这些函数考虑了 Display Lock 的“排他性”和“包含性”，即锁定是否影响自身以及后代。
   - 区分了“阻止”和“允许激活”的 Display Lock 状态。

2. **Display Lock 的激活与管理:**
   - 提供函数来判断是否需要激活 Display Lock (例如，由于查找页面功能)。
   - 提供函数来获取可以被激活的祖先 Display Lock。
   - 包含一个 `ScopedForcedUpdate` 类，用于在特定范围内临时解除 Display Lock 的阻止，强制进行更新（例如，为了处理用户选择变化）。

3. **处理与用户交互相关的 Display Lock:**
   - 提供函数来处理元素获得和失去焦点时 Display Lock 的通知。
   - 提供函数来处理用户选择变化时 Display Lock 的通知。

4. **优化和性能:**
   - 使用 memoization (记忆化) 技术 (`memoizer_`) 来缓存 `IsDisplayLockedPreventingPaint` 和 `IsLockedForAccessibility` 的结果，以提高性能，避免重复计算。

5. **与其他 Blink 模块的交互:**
   - 依赖于 `DisplayLockContext` 和 `DisplayLockDocumentState` 来获取和管理 Display Lock 的状态。
   - 使用 DOM 遍历 API (`FlatTreeTraversal`, `NodeTraversal`) 来查找祖先节点。
   - 与布局系统 (`LayoutObject`, `LayoutView`) 交互，判断 Display Lock 对布局的影响。
   - 与编辑 (`editing`) 模块交互，例如在查找页面功能中。

**与 JavaScript, HTML, CSS 的关系举例说明：**

1. **HTML:**  Display Lock 是应用于 HTML 元素的。`NearestLockedInclusiveAncestor` 等函数会接收 `Node` 或 `Element` 对象作为输入，这些对象直接对应于 HTML 结构中的节点和元素。

   * **举例:**  假设一个 HTML 结构如下：
     ```html
     <div id="locked-parent" style="display:none;">
       <p>Content inside locked area.</p>
     </div>
     <script>
       // JavaScript 可能设置 #locked-parent 的 displayLock 状态
     </script>
     ```
     `NearestLockedInclusiveAncestor(document.querySelector('p'))` 可能会返回 `document.getElementById('locked-parent')`，如果该元素上存在有效的 Display Lock。

2. **CSS:** Display Lock 会影响 CSS 样式计算和渲染。如果一个元素被 Display Lock 阻止绘制，即使 CSS 样式已经应用，该元素也不会被渲染到屏幕上。

   * **举例:**  如果 `LockedAncestorPreventingPaint(document.querySelector('p'))` 返回一个元素，则意味着 `p` 元素及其后代由于某个祖先元素的 Display Lock 设置，当前不会被绘制，即使其 CSS 属性（例如 `color`, `background-color`）已经计算出来。

3. **JavaScript:**  JavaScript 可以触发 Display Lock 的激活或解除，也可以查询 Display Lock 的状态。

   * **举例:**  查找页面 (Find-in-Page) 功能通常由 JavaScript 实现。`ActivateFindInPageMatchRangeIfNeeded` 函数会被调用，根据 JavaScript 提供的匹配范围来判断是否需要激活相关的 Display Lock，以确保高亮显示的匹配项可见。
   * **假设输入:** JavaScript 执行 `window.find("example")` 找到了一个匹配项，并创建了一个表示该匹配项的 `EphemeralRangeInFlatTree` 对象。
   * **输出:** `ActivateFindInPageMatchRangeIfNeeded` 函数根据该范围内的元素是否位于具有可激活 Display Lock 的子树中，返回 `true` (如果激活了 Display Lock) 或 `false`。

**逻辑推理的假设输入与输出举例:**

1. **`NearestLockedExclusiveAncestor`:**
   * **假设输入:** 一个 `Text` 节点，它嵌套在一个被 Display Lock 锁定的 `div` 元素和一个未锁定的 `section` 元素中。
   * **输出:** 指向该被锁定的 `div` 元素的指针。

2. **`IsDisplayLockedPreventingPaint`:**
   * **假设输入:** 一个 `span` 元素，它的父 `div` 元素上有一个 Display Lock，并且该 Display Lock 设置为阻止绘制子元素。
   * **输出:** `true`。

**用户或编程常见的使用错误举例:**

1. **错误地假设元素总是立即渲染:**  开发者可能会在 JavaScript 中修改一个被 Display Lock 锁定的元素，并期望更改立即反映在屏幕上。然而，如果 Display Lock 仍然有效，更新将被延迟。
   * **场景:**  一个动画效果，需要在短时间内频繁更新元素的样式。如果父元素意外地被 Display Lock 锁定，动画可能会卡顿或不流畅。
   * **错误:**  开发者没有考虑到 Display Lock 的存在，并假设样式的更改会立即生效。

2. **在 Display Lock 阻止更新时尝试获取布局信息:**  如果尝试访问被 Display Lock 阻止更新的元素的布局信息（例如 `offsetWidth`, `getBoundingClientRect`），可能会得到过时的或不准确的结果。
   * **场景:**  一个 JavaScript 函数需要计算某个元素相对于视口的位置，但该元素位于一个被 Display Lock 阻止布局的区域。
   * **错误:**  开发者没有检查 Display Lock 的状态，直接获取布局信息，导致计算结果错误。

**总结：**

`display_lock_utilities.cc` 是 Blink 渲染引擎中 Display Lock 机制的关键组成部分，提供了一系列工具函数，用于判断 Display Lock 的状态、进行激活管理，并处理与用户交互相关的逻辑。它在优化渲染性能方面发挥着重要作用，但也需要开发者理解其工作原理，以避免在编写 JavaScript、HTML 和 CSS 时出现与渲染更新相关的错误。

Prompt: 
```
这是目录为blink/renderer/core/display_lock/display_lock_utilities.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"

#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_context.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/slot_assignment_engine.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/editing_boundary.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_shift_tracker.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_set.h"
#include "third_party/blink/renderer/platform/heap/member.h"

namespace blink {

DisplayLockUtilities::LockCheckMemoizationScope*
    DisplayLockUtilities::memoizer_ = nullptr;

namespace {

// Returns the nearest non-inclusive ancestor of |node| that is display
// locked.
Element* NearestLockedExclusiveAncestor(const Node& node) {
  if (!node.isConnected() ||
      node.GetDocument()
              .GetDisplayLockDocumentState()
              .LockedDisplayLockCount() == 0 ||
      node.IsShadowRoot()) {
    return nullptr;
  }
  // TODO(crbug.com/924550): Once we figure out a more efficient way to
  // determine whether we're inside a locked subtree or not, change this.
  for (Node& ancestor : FlatTreeTraversal::AncestorsOf(node)) {
    auto* ancestor_element = DynamicTo<Element>(ancestor);
    if (!ancestor_element)
      continue;
    if (auto* context = ancestor_element->GetDisplayLockContext()) {
      if (context->IsLocked())
        return ancestor_element;
    }
  }
  return nullptr;
}

const Element* NearestLockedInclusiveAncestor(const Node& node) {
  auto* element = DynamicTo<Element>(node);
  if (!element)
    return NearestLockedExclusiveAncestor(node);
  if (!node.isConnected() ||
      node.GetDocument()
              .GetDisplayLockDocumentState()
              .LockedDisplayLockCount() == 0 ||
      node.IsShadowRoot()) {
    return nullptr;
  }
  if (auto* context = element->GetDisplayLockContext()) {
    if (context->IsLocked())
      return element;
  }
  return NearestLockedExclusiveAncestor(node);
}

Element* NearestLockedInclusiveAncestor(Node& node) {
  return const_cast<Element*>(
      NearestLockedInclusiveAncestor(static_cast<const Node&>(node)));
}

Element* NearestLockedInclusiveAncestor(const LayoutObject& object) {
  auto* node = object.GetNode();
  auto* ancestor = object.Parent();
  while (ancestor && !node) {
    node = ancestor->GetNode();
    ancestor = ancestor->Parent();
  }
  return node ? NearestLockedInclusiveAncestor(*node) : nullptr;
}

Element* NearestLockedExclusiveAncestor(const LayoutObject& object) {
  if (auto* node = object.GetNode())
    return NearestLockedExclusiveAncestor(*node);
  // Since we now navigate to an ancestor, use the inclusive version.
  if (auto* parent = object.Parent())
    return NearestLockedInclusiveAncestor(*parent);
  return nullptr;
}

// Returns the frame owner node for the frame that contains the given child, if
// one exists. Returns nullptr otherwise.
Node* GetFrameOwnerNode(const Node* child) {
  if (!child || !child->GetDocument().GetFrame() ||
      !child->GetDocument().GetFrame()->OwnerLayoutObject()) {
    return nullptr;
  }
  return child->GetDocument().GetFrame()->OwnerLayoutObject()->GetNode();
}

void PopulateAncestorContexts(
    Node& node,
    HeapHashSet<Member<DisplayLockContext>>& contexts) {
  for (Node& ancestor : FlatTreeTraversal::InclusiveAncestorsOf(node)) {
    auto* ancestor_element = DynamicTo<Element>(ancestor);
    if (!ancestor_element)
      continue;
    if (auto* context = ancestor_element->GetDisplayLockContext())
      contexts.insert(context);
  }
}

template <typename Lambda>
Element* LockedAncestorPreventingUpdate(const Node& node,
                                        Lambda update_is_prevented) {
  for (auto* ancestor = NearestLockedExclusiveAncestor(node); ancestor;
       ancestor = NearestLockedExclusiveAncestor(*ancestor)) {
    DCHECK(ancestor->GetDisplayLockContext());
    if (update_is_prevented(ancestor->GetDisplayLockContext()))
      return ancestor;
  }
  return nullptr;
}

template <typename Lambda>
const Element* LockedInclusiveAncestorPreventingUpdate(
    const Node& node,
    Lambda update_is_prevented) {
  if (auto* element = DynamicTo<Element>(node)) {
    if (auto* context = element->GetDisplayLockContext()) {
      if (update_is_prevented(context))
        return element;
    }
  }
  return LockedAncestorPreventingUpdate(node, std::move(update_is_prevented));
}

template <typename Lambda>
Element* LockedAncestorPreventingUpdate(const LayoutObject& object,
                                        Lambda update_is_prevented) {
  if (auto* ancestor = NearestLockedExclusiveAncestor(object)) {
    if (update_is_prevented(ancestor->GetDisplayLockContext()))
      return ancestor;
    return LockedAncestorPreventingUpdate(*ancestor, update_is_prevented);
  }
  return nullptr;
}

template <typename Lambda>
Element* LockedInclusiveAncestorPreventingUpdate(const LayoutObject& object,
                                                 Lambda update_is_prevented) {
  if (auto* ancestor = NearestLockedInclusiveAncestor(object)) {
    if (update_is_prevented(ancestor->GetDisplayLockContext()))
      return ancestor;
    return LockedAncestorPreventingUpdate(*ancestor, update_is_prevented);
  }
  return nullptr;
}

}  // namespace

bool DisplayLockUtilities::ActivateFindInPageMatchRangeIfNeeded(
    const EphemeralRangeInFlatTree& range) {
  DCHECK(!range.IsNull());
  DCHECK(!range.IsCollapsed());
  if (!range.GetDocument()
           .GetDisplayLockDocumentState()
           .HasActivatableLocks()) {
    return false;
  }
  // Find-in-page matches can't span multiple block-level elements (because the
  // text will be broken by newlines between blocks), so first we find the
  // block-level element which contains the match.
  // This means we only need to traverse up from one node in the range, in this
  // case we are traversing from the start position of the range.
  Element* enclosing_block =
      EnclosingBlock(range.StartPosition(), kCanCrossEditingBoundary);
  // Note that we don't check the `range.EndPosition()` since we just activate
  // the beginning of the range. In find-in-page cases, the end position is the
  // same since the matches cannot cross block boundaries. However, in
  // scroll-to-text, the range might be different, but we still just activate
  // the beginning of the range. See
  // https://github.com/WICG/display-locking/issues/125 for more details.
  DCHECK(enclosing_block);
  return enclosing_block->ActivateDisplayLockIfNeeded(
      DisplayLockActivationReason::kFindInPage);
}

bool DisplayLockUtilities::NeedsActivationForFindInPage(
    const EphemeralRangeInFlatTree& range) {
  DisplayLockDocumentState& state =
      range.GetDocument().GetDisplayLockDocumentState();
  if (!state.HasActivatableLocks()) {
    return false;
  }

  Element* enclosing_block =
      EnclosingBlock(range.StartPosition(), kCanCrossEditingBoundary);

  HeapVector<Member<Element>> activatable_targets;
  for (Node& ancestor :
       FlatTreeTraversal::InclusiveAncestorsOf(*enclosing_block)) {
    auto* ancestor_element = DynamicTo<Element>(ancestor);
    if (!ancestor_element) {
      continue;
    }
    if (auto* context = ancestor_element->GetDisplayLockContext()) {
      if (context->ShouldCommitForActivation(
              DisplayLockActivationReason::kFindInPage)) {
        return true;
      }
    }
  }

  return false;
}

const HeapVector<Member<Element>>
DisplayLockUtilities::ActivatableLockedInclusiveAncestors(
    const Node& node,
    DisplayLockActivationReason reason) {
  HeapVector<Member<Element>> elements_to_activate;
  if (node.GetDocument()
          .GetDisplayLockDocumentState()
          .LockedDisplayLockCount() ==
      node.GetDocument()
          .GetDisplayLockDocumentState()
          .DisplayLockBlockingAllActivationCount())
    return elements_to_activate;

  for (Node& ancestor : FlatTreeTraversal::InclusiveAncestorsOf(node)) {
    auto* ancestor_element = DynamicTo<Element>(ancestor);
    if (!ancestor_element)
      continue;
    if (auto* context = ancestor_element->GetDisplayLockContext()) {
      if (!context->IsLocked())
        continue;
      if (!context->IsActivatable(reason)) {
        // If we find a non-activatable locked ancestor, then we shouldn't
        // activate anything.
        elements_to_activate.clear();
        return elements_to_activate;
      }
      elements_to_activate.push_back(ancestor_element);
    }
  }
  return elements_to_activate;
}

DisplayLockUtilities::ScopedForcedUpdate::Impl::Impl(
    const Range* range,
    DisplayLockContext::ForcedPhase phase,
    bool only_cv_auto,
    bool emit_warnings)
    : node_(range->FirstNode()),
      phase_(phase),
      only_cv_auto_(only_cv_auto),
      emit_warnings_(emit_warnings) {
  if (!node_)
    return;

  // Selection doesn't span frames, so we don't need to worry about including
  // subframes inside the Range or multiple parent frames.
  auto* owner_node = GetFrameOwnerNode(node_);
  if (owner_node)
    parent_frame_impl_ = MakeGarbageCollected<Impl>(owner_node, phase, true);

  range->OwnerDocument().GetDisplayLockDocumentState().BeginRangeForcedScope(
      range, this);

  if (node_->GetDocument()
          .GetDisplayLockDocumentState()
          .LockedDisplayLockCount() == 0)
    return;

  // TODO(crbug.com/1256849): Move this loop to a shared iterator class so we
  //   can combine it with the one in DisplayLockDocumentState.
  // Ranges use NodeTraversal::Next to go in between their start and end nodes,
  // and will access the layout information of each of those nodes. In order to
  // ensure that each of these nodes has unlocked layout information, we have to
  // do a scoped unlock for each of those nodes by unlocking all of their flat
  // tree ancestors.
  for (Node* node = range->FirstNode(); node != range->PastLastNode();
       node = NodeTraversal::Next(*node)) {
    if (node->IsChildOfShadowHost()) {
      // This node may be slotted into another place in the flat tree, so we
      // have to do a flat tree parent traversal for it.
      for (Node* ancestor = node; ancestor;
           ancestor = FlatTreeTraversal::Parent(*ancestor)) {
        if (Element* element = DynamicTo<Element>(ancestor)) {
          if (DisplayLockContext* context = element->GetDisplayLockContext()) {
            forced_context_set_.insert(context);
          }
        }
      }
    } else {
      if (Element* element = DynamicTo<Element>(node)) {
        if (DisplayLockContext* context = element->GetDisplayLockContext()) {
          forced_context_set_.insert(context);
        }
      }
    }
  }
  for (Node* node = range->FirstNode(); node;
       node = FlatTreeTraversal::Parent(*node)) {
    if (Element* element = DynamicTo<Element>(node)) {
      if (DisplayLockContext* context = element->GetDisplayLockContext()) {
        forced_context_set_.insert(context);
      }
    }
  }
  for (DisplayLockContext* context : forced_context_set_) {
    context->NotifyForcedUpdateScopeStarted(phase_, emit_warnings_);
  }
}

DisplayLockUtilities::ScopedForcedUpdate::Impl::Impl(
    const Node* node,
    DisplayLockContext::ForcedPhase phase,
    bool include_self,
    bool only_cv_auto,
    bool emit_warnings)
    : node_(node),
      phase_(phase),
      only_cv_auto_(only_cv_auto),
      emit_warnings_(emit_warnings) {
  if (!node_)
    return;

  auto* owner_node = GetFrameOwnerNode(node);
  if (owner_node)
    parent_frame_impl_ = MakeGarbageCollected<Impl>(owner_node, phase, true);

  node->GetDocument().GetDisplayLockDocumentState().BeginNodeForcedScope(
      node, include_self, this);

  if (node->GetDocument()
          .GetDisplayLockDocumentState()
          .LockedDisplayLockCount() == 0)
    return;

  // We can't do flat tree traversals on shadow roots - they aren't in the flat
  // tree. However, they also can't be DisplayLocked, so just go to their host.
  if (node->IsShadowRoot()) {
    node = node->ParentOrShadowHostNode();
  }

  // Get the right ancestor view. Only use inclusive ancestors if the node
  // itself is locked and it prevents self layout, or if |include_self| is true.
  // If self layout is not prevented, we don't need to force the subtree layout,
  // so use exclusive ancestors in that case.
  auto ancestor_view = [node, include_self] {
    if (auto* element = DynamicTo<Element>(node)) {
      auto* context = element->GetDisplayLockContext();
      if (context && include_self)
        return FlatTreeTraversal::InclusiveAncestorsOf(*node);
    }
    return FlatTreeTraversal::AncestorsOf(*node);
  }();

  // TODO(vmpstr): This is somewhat inefficient, since we would pay the cost
  // of traversing the ancestor chain even for nodes that are not in the
  // locked subtree. We need to figure out if there is a supplementary
  // structure that we can use to quickly identify nodes that are in the
  // locked subtree.
  for (Node& ancestor : ancestor_view) {
    auto* ancestor_node = DynamicTo<Element>(ancestor);
    if (!ancestor_node)
      continue;
    if (auto* context = ancestor_node->GetDisplayLockContext()) {
      ForceDisplayLockIfNeeded(context);
    }
  }
}

void DisplayLockUtilities::ScopedForcedUpdate::Impl::EnsureMinimumForcedPhase(
    DisplayLockContext::ForcedPhase phase) {
  // Our `phase_` is already at least as permissive as `phase`.
  if (static_cast<int>(phase_) >= static_cast<int>(phase))
    return;
  for (auto context : forced_context_set_)
    context->UpgradeForcedScope(phase_, phase, emit_warnings_);
  phase_ = phase;
}

void DisplayLockUtilities::ScopedForcedUpdate::Impl::Destroy() {
  if (!node_)
    return;
  node_->GetDocument().GetDisplayLockDocumentState().EndForcedScope(this);
  if (parent_frame_impl_)
    parent_frame_impl_->Destroy();
  for (auto context : forced_context_set_) {
    context->NotifyForcedUpdateScopeEnded(phase_);
  }
}

void DisplayLockUtilities::ScopedForcedUpdate::Impl::
    AddForcedUpdateScopeForContext(DisplayLockContext* context) {
  if (!forced_context_set_.Contains(context)) {
    ForceDisplayLockIfNeeded(context);
  }
}

void DisplayLockUtilities::ScopedForcedUpdate::Impl::ForceDisplayLockIfNeeded(
    DisplayLockContext* context) {
  if (!only_cv_auto_ ||
      context->IsActivatable(DisplayLockActivationReason::kViewport)) {
    forced_context_set_.insert(context);
    context->NotifyForcedUpdateScopeStarted(phase_, emit_warnings_);
  }
}

Element*
DisplayLockUtilities::LockedInclusiveAncestorPreventingStyleWithinTreeScope(
    const Node& node) {
  if (!node.isConnected() || node.GetDocument()
                                     .GetDisplayLockDocumentState()
                                     .LockedDisplayLockCount() == 0) {
    return nullptr;
  }

  for (Node& ancestor : NodeTraversal::InclusiveAncestorsOf(node)) {
    DCHECK(ancestor.GetTreeScope() == node.GetTreeScope());
    Element* ancestor_element = DynamicTo<Element>(ancestor);
    if (!ancestor_element)
      continue;
    if (DisplayLockContext* context =
            ancestor_element->GetDisplayLockContext()) {
      if (!context->ShouldStyleChildren())
        return ancestor_element;
    }
  }
  return nullptr;
}

const Element* DisplayLockUtilities::LockedInclusiveAncestorPreventingLayout(
    const Node& node) {
  return LockedInclusiveAncestorPreventingUpdate(
      node, [](DisplayLockContext* context) {
        return !context->ShouldLayoutChildren();
      });
}

const Element* DisplayLockUtilities::LockedInclusiveAncestorPreventingPaint(
    const Node& node) {
  return LockedInclusiveAncestorPreventingUpdate(
      node, [](DisplayLockContext* context) {
        return !context->ShouldPaintChildren();
      });
}

const Element* DisplayLockUtilities::LockedInclusiveAncestorPreventingPaint(
    const LayoutObject& object) {
  return LockedInclusiveAncestorPreventingUpdate(
      object, [](DisplayLockContext* context) {
        return !context->ShouldPaintChildren();
      });
}

Element* DisplayLockUtilities::HighestLockedInclusiveAncestor(
    const Node& node) {
  if (node.IsShadowRoot())
    return nullptr;
  auto* node_ptr = const_cast<Node*>(&node);
  // If the exclusive result exists, then that's higher than this node, so
  // return it.
  if (auto* result = HighestLockedExclusiveAncestor(node))
    return result;

  // Otherwise, we know the node is not in a locked subtree, so the only
  // other possibility is that the node itself is locked.
  auto* element = DynamicTo<Element>(node_ptr);
  if (element && element->GetDisplayLockContext() &&
      element->GetDisplayLockContext()->IsLocked()) {
    return element;
  }
  return nullptr;
}

Element* DisplayLockUtilities::HighestLockedExclusiveAncestor(
    const Node& node) {
  if (node.IsShadowRoot())
    return nullptr;

  Node* parent = FlatTreeTraversal::Parent(node);
  Element* locked_ancestor = nullptr;
  while (parent) {
    auto* locked_candidate = NearestLockedInclusiveAncestor(*parent);
    auto* last_node = parent;
    if (locked_candidate) {
      locked_ancestor = locked_candidate;
      parent = FlatTreeTraversal::Parent(*parent);
    } else {
      parent = nullptr;
    }

    if (!parent)
      parent = GetFrameOwnerNode(last_node);
  }
  return locked_ancestor;
}

bool DisplayLockUtilities::IsInUnlockedOrActivatableSubtree(
    const Node& node,
    DisplayLockActivationReason activation_reason) {
  if (node.GetDocument()
              .GetDisplayLockDocumentState()
              .LockedDisplayLockCount() == 0 ||
      node.IsShadowRoot()) {
    return true;
  }

  if (activation_reason == DisplayLockActivationReason::kAccessibility &&
      memoizer_) {
    return !IsLockedForAccessibility(node);
  }

  for (auto* element = NearestLockedExclusiveAncestor(node); element;
       element = NearestLockedExclusiveAncestor(*element)) {
    if (!element->GetDisplayLockContext()->IsActivatable(activation_reason)) {
      return false;
    }
  }
  return true;
}

bool DisplayLockUtilities::IsLockedForAccessibility(const Node& node) {
  // This is a private helper for accessibility, only called if we have a
  // memoizer.
  DCHECK(memoizer_);

  // Consult the memoizer, if we know the result we can return early.
  auto result = memoizer_->IsNodeLockedForAccessibility(&node);
  if (result)
    return *result;

  // Walk up the ancestor chain checking for locked & non-activatable context.
  // See IsDisplayLockedPreventingPaint for an explanation of memoization.
  const Node* previous_ancestor = &node;
  bool ancestor_is_locked = false;
  for (Node& ancestor : FlatTreeTraversal::AncestorsOf(node)) {
    // Reset ancestor is locked, we may set it again just below.
    ancestor_is_locked = false;

    // If we have a context, check if it's locked and if it's also not
    // activatable for accessibility then we found our answer: `node` is locked
    // for accessibility.
    if (auto* ancestor_element = DynamicTo<Element>(ancestor)) {
      if (auto* context = ancestor_element->GetDisplayLockContext()) {
        ancestor_is_locked = context->IsLocked();
        if (ancestor_is_locked &&
            !context->IsActivatable(
                DisplayLockActivationReason::kAccessibility)) {
          // Other than the node, we also know that previous_ancestor must be
          // locked for accessibility. Record that.
          memoizer_->NotifyLockedForAccessibility(previous_ancestor);
          return true;
        }
      }
    }

    // Since we didn't find the answer above, before continuing the walk consult
    // with the memoizer: it might know the answer.
    result = memoizer_->IsNodeLockedForAccessibility(&ancestor);
    if (result) {
      // Note that if we know the result for current ancestor, then that same
      // result applies for previous_ancestor. This is certainly true for
      // positive -- LockedForAccessibility -- results, but it's also true for
      // negative -- Unlocked -- results if the ancestor itself is not locked.
      if (*result)
        memoizer_->NotifyLockedForAccessibility(previous_ancestor);
      else if (!ancestor_is_locked)
        memoizer_->NotifyUnlocked(previous_ancestor);
      return *result;
    }

    // Update the previous ancestor.
    previous_ancestor = &ancestor;
  }

  // If we reached the end of the loop, then the last node we visited
  // (presumably the root of the flat tree) is not locked.
  memoizer_->NotifyUnlocked(previous_ancestor);
  return false;
}

bool DisplayLockUtilities::IsInLockedSubtreeCrossingFrames(
    const Node& source_node,
    IncludeSelfOrNot self) {
  if (LocalFrameView* frame_view = source_node.GetDocument().View()) {
    if (frame_view->IsDisplayLocked())
      return true;
  }
  const Node* node = &source_node;

  // If we don't need to check self, skip to the parent immediately.
  if (self == kExcludeSelf)
    node = FlatTreeTraversal::Parent(*node);

  // If we don't have a flat-tree parent, get the |source_node|'s owner node
  // instead.
  if (!node)
    node = GetFrameOwnerNode(&source_node);

  while (node) {
    if (NearestLockedInclusiveAncestor(*node))
      return true;
    node = GetFrameOwnerNode(node);
  }
  return false;
}

void DisplayLockUtilities::ElementLostFocus(Element* element) {
  if (element &&
      element->GetDocument().GetDisplayLockDocumentState().DisplayLockCount() ==
          0) {
    return;
  }
  for (; element; element = FlatTreeTraversal::ParentElement(*element)) {
    auto* context = element->GetDisplayLockContext();
    if (context)
      context->NotifySubtreeLostFocus();
  }
}
void DisplayLockUtilities::ElementGainedFocus(Element* element) {
  if (element &&
      element->GetDocument().GetDisplayLockDocumentState().DisplayLockCount() ==
          0) {
    return;
  }

  for (; element; element = FlatTreeTraversal::ParentElement(*element)) {
    auto* context = element->GetDisplayLockContext();
    if (context)
      context->NotifySubtreeGainedFocus();
  }
}

// static
bool DisplayLockUtilities::NeedsSelectionChangedUpdate(
    const Document& document) {
  return document.GetDisplayLockDocumentState().DisplayLockCount() > 0;
}

void DisplayLockUtilities::SelectionChanged(
    const EphemeralRangeInFlatTree& old_selection,
    const EphemeralRangeInFlatTree& new_selection) {
  if ((!old_selection.IsNull() && old_selection.GetDocument()
                                          .GetDisplayLockDocumentState()
                                          .DisplayLockCount() == 0) ||
      (!new_selection.IsNull() && new_selection.GetDocument()
                                          .GetDisplayLockDocumentState()
                                          .DisplayLockCount() == 0)) {
    return;
  }

  TRACE_EVENT0("blink", "DisplayLockUtilities::SelectionChanged");

  HeapHashSet<Member<Node>> new_nodes;
  for (Node& node : new_selection.Nodes())
    new_nodes.insert(&node);

  HeapHashSet<Member<DisplayLockContext>> lost_selection_contexts;
  HeapHashSet<Member<DisplayLockContext>> gained_selection_contexts;

  for (Node& node : old_selection.Nodes()) {
    if (auto it = new_nodes.find(&node); it != new_nodes.end()) {
      new_nodes.erase(it);
      continue;
    }
    PopulateAncestorContexts(node, lost_selection_contexts);
  }

  for (Node* node : new_nodes) {
    PopulateAncestorContexts(*node, gained_selection_contexts);
  }

  for (DisplayLockContext* context : lost_selection_contexts) {
    if (auto it = gained_selection_contexts.find(context);
        it != gained_selection_contexts.end()) {
      gained_selection_contexts.erase(it);
      continue;
    }
    context->NotifySubtreeLostSelection();
  }

  for (DisplayLockContext* context : gained_selection_contexts) {
    context->NotifySubtreeGainedSelection();
  }
}

void DisplayLockUtilities::SelectionRemovedFromDocument(Document& document) {
  document.GetDisplayLockDocumentState().NotifySelectionRemoved();
}

Element* DisplayLockUtilities::LockedAncestorPreventingPaint(
    const LayoutObject& object) {
  return LockedAncestorPreventingUpdate(
      object, [](DisplayLockContext* context) {
        return !context->ShouldPaintChildren();
      });
}

Element* DisplayLockUtilities::LockedAncestorPreventingPaint(const Node& node) {
  return LockedAncestorPreventingUpdate(node, [](DisplayLockContext* context) {
    return !context->ShouldPaintChildren();
  });
}

Element* DisplayLockUtilities::LockedAncestorPreventingPrePaint(
    const LayoutObject& object) {
  return LockedAncestorPreventingUpdate(
      object, [](DisplayLockContext* context) {
        return !context->ShouldPrePaintChildren();
      });
}

Element* DisplayLockUtilities::LockedAncestorPreventingLayout(
    const LayoutObject& object) {
  return LockedAncestorPreventingUpdate(
      object, [](DisplayLockContext* context) {
        return !context->ShouldLayoutChildren();
      });
}

Element* DisplayLockUtilities::LockedAncestorPreventingLayout(
    const Node& node) {
  return LockedAncestorPreventingUpdate(node, [](DisplayLockContext* context) {
    return !context->ShouldLayoutChildren();
  });
}

Element* DisplayLockUtilities::LockedAncestorPreventingStyle(const Node& node) {
  return LockedAncestorPreventingUpdate(node, [](DisplayLockContext* context) {
    return !context->ShouldStyleChildren();
  });
}

#if DCHECK_IS_ON()
bool DisplayLockUtilities::AssertStyleAllowed(const Node& node) {
  if (node.GetDocument().IsFlatTreeTraversalForbidden() ||
      node.GetDocument()
          .GetSlotAssignmentEngine()
          .HasPendingSlotAssignmentRecalc()) {
    return true;
  }
  return !LockedAncestorPreventingStyle(node);
}
#endif

bool DisplayLockUtilities::PrePaintBlockedInParentFrame(LayoutView* view) {
  auto* owner = view->GetFrameView()->GetFrame().OwnerLayoutObject();
  if (!owner)
    return false;

  auto* element = NearestLockedInclusiveAncestor(*owner);
  while (element) {
    if (!element->GetDisplayLockContext()->ShouldPrePaintChildren())
      return true;
    element = NearestLockedExclusiveAncestor(*element);
  }
  return false;
}

bool DisplayLockUtilities::IsAutoWithoutLayout(const LayoutObject& object) {
  auto* context = object.GetDisplayLockContext();
  if (!context)
    return false;
  return !context->IsLocked() && context->IsAuto() &&
         !context->HadLifecycleUpdateSinceLastUnlock();
}

bool DisplayLockUtilities::RevealHiddenUntilFoundAncestors(const Node& node) {
  // Since setting the open attribute fires mutation events which could mess
  // with the FlatTreeTraversal iterator, we should first iterate details
  // elements to open and then open them all.
  HeapVector<Member<HTMLElement>> elements_to_reveal;

  for (Node& parent : FlatTreeTraversal::InclusiveAncestorsOf(node)) {
    if (HTMLElement* element = DynamicTo<HTMLElement>(parent)) {
      if (EqualIgnoringASCIICase(
              element->FastGetAttribute(html_names::kHiddenAttr),
              "until-found")) {
        elements_to_reveal.push_back(element);
      }
    }
  }

  for (HTMLElement* element : elements_to_reveal) {
    element->DispatchEvent(
        *Event::CreateBubble(event_type_names::kBeforematch));
  }

  for (HTMLElement* element : elements_to_reveal) {
    element->removeAttribute(html_names::kHiddenAttr);
  }

  return elements_to_reveal.size();
}

static bool CheckSelf(const Node* node) {
  if (auto* element = DynamicTo<Element>(node)) {
    if (auto* context = element->GetDisplayLockContext()) {
      if (!context->ShouldPaintChildren())
        return true;
    }
  }
  return false;
}

bool DisplayLockUtilities::IsDisplayLockedPreventingPaintUnmemoized(
    const Node& node,
    bool inclusive_check) {
  return inclusive_check
             ? DisplayLockUtilities::LockedInclusiveAncestorPreventingPaint(
                   node)
             : DisplayLockUtilities::LockedAncestorPreventingPaint(node);
}

bool DisplayLockUtilities::IsDisplayLockedPreventingPaint(
    const Node* node,
    bool inclusive_check) {
  // If we have a memoizer, consult with it to see if we already know the
  // result. Otherwise, fallback to get-element versions.
  if (memoizer_) {
    // Consult memoizer with it to see if we already know the
    // result. Otherwise, fallback to get-element versions.
    auto memoized_result = memoizer_->IsNodeLocked(node);
    if (memoized_result) {
      bool final_result =
          *memoized_result || (inclusive_check && CheckSelf(node));
#if DCHECK_IS_ON()
      bool nonmemoized_result =
          IsDisplayLockedPreventingPaintUnmemoized(*node, inclusive_check);
      DCHECK_EQ(final_result, nonmemoized_result)
          << "\nMemoized result did not match non-memoized result for "
          << (inclusive_check ? "inclusive" : "non-inclusive") << " check."
          << "\n* node = " << node
          << "\n* Inclusive ancestor preventing paint: "
          << DisplayLockUtilities::LockedInclusiveAncestorPreventingPaint(*node)
          << "\n* Non-inclusive ancestor preventing paint: "
          << DisplayLockUtilities::LockedAncestorPreventingPaint(*node);
#endif

      // The memoizer can only be used for non-inclusive checks.
      return final_result;
    }
  } else {
    return inclusive_check
               ? DisplayLockUtilities::LockedInclusiveAncestorPreventingPaint(
                     *node)
               : DisplayLockUtilities::LockedAncestorPreventingPaint(*node);
  }

  // Do some sanity checks that we can early-out on.
  if (!node->isConnected() ||
      node->GetDocument()
              .GetDisplayLockDocumentState()
              .LockedDisplayLockCount() == 0 ||
      node->IsShadowRoot()) {
    return false;
  }

  // Compute the result by walking the tree and memoize the result.
  // Handle the inclusive check -- that is, check the node itself. Note that
  // it's important not to memoize that since the memoization consists of
  // ancestor checks only.
  if (inclusive_check && CheckSelf(node))
    return true;

  // Walk up the ancestor chain, and consult with both the memoizer and check
  // directly if we're skipping paint. When we find a result (or finish the
  // loop), then save the last visited ancestor (previous_ancestor) into the
  // memoizer. This ensures that any future calls in the similar subtree would
  // have to check one level less. In turn, this means that if we have many
  // calls, it will eventually only check only a few levels. This also keeps the
  // memoizer cache fairly small.
  const Node* previous_ancestor = node;
  for (Node& ancestor : FlatTreeTraversal::AncestorsOf(*node)) {
    if (auto* ancestor_element = DynamicTo<Element>(ancestor)) {
      if (auto* context = ancestor_element->GetDisplayLockContext()) {
        // Note that technically we could do a similar approach to
        // IsLockedForAccessibility by recording whether this context is locked
        // but allow paint. However, that situation is not possible since all
        // locked contexts always prevent paint.
        DCHECK(!context->IsLocked() || !context->ShouldPaintChildren());
        if (!context->ShouldPaintChildren()) {
          memoizer_->NotifyLocked(previous_ancestor);
          return true;
        }
      }
    }

    auto result = memoizer_->IsNodeLocked(&ancestor);
    if (result) {
      // Propagate the result to the previous_ancestor as well. Note that if
      // `ancestor` is in an unlocked subtree then `previous_ancestor` must also
      // be in such a subtree because the only way it isn't is if `ancestor` is
      // itself locked, which is checked above.
      if (*result)
        memoizer_->NotifyLocked(previous_ancestor);
      else
        memoizer_->NotifyUnlocked(previous_ancestor);
      return *result;
    }

    // Update previous ancestor!
    previous_ancestor = &ancestor;
  }

  // If we reached the end o
"""


```