Response:
My thought process to analyze the `flat_tree_traversal.cc` file went something like this:

1. **Understand the Purpose:** The filename itself, `flat_tree_traversal.cc`, strongly suggests this file deals with navigating a "flat tree" structure. Knowing this is in the Blink rendering engine context, I immediately connect it to the concept of the *composed tree* used in Shadow DOM. The "flat tree" is the flattened view of the DOM, including the content distributed into shadow roots.

2. **Examine the Includes:**  The included headers provide further clues:
    * `flat_tree_traversal.h`:  The corresponding header file, likely containing declarations.
    * `element.h`, `flat_tree_node_data.h`, `slot_assignment.h`, `html_slot_element.h`: These point directly to the core concepts of Shadow DOM and how nodes are assigned to slots within shadow trees.

3. **Analyze the Namespace:** The code is within the `blink` namespace, confirming it's part of the Blink rendering engine.

4. **Focus on Key Functions:** I scanned the file for the most prominent functions, paying attention to their names and parameters:
    * Functions starting with `Traverse`: `TraverseChild`, `TraverseSiblings`, `TraverseParent`, etc. These are clearly the core traversal mechanisms. The `TraversalDirection` enum suggests the traversal can go forward or backward.
    * Functions like `ChildAt`, `NextSkippingChildren`, `PreviousPostOrder`: These seem to be variations or more specialized forms of tree traversal.
    * Functions like `ContainsIncludingPseudoElement`, `IsDescendantOf`, `CommonAncestor`: These suggest operations for determining relationships between nodes in the flat tree.
    * Functions related to counting: `Index`, `CountChildren`.
    * Functions relating to the "end" of subtrees: `LastWithin`, `LastWithinOrSelf`.
    * The `AssertFlatTreeNodeDataUpdated` function (under `DCHECK_IS_ON()`): This is for internal debugging and verification, ensuring the flat tree data structures are consistent.

5. **Connect to Shadow DOM:**  The presence of `HTMLSlotElement`, `ShadowRoot`, and the logic within the `Traverse*` functions involving slot assignment strongly indicate the primary function of this file is to provide a way to traverse the DOM *as it appears after Shadow DOM composition*.

6. **Infer Functionality and Relationships:**  Based on the function names and the Shadow DOM context, I started deducing the relationships with JavaScript, HTML, and CSS:
    * **JavaScript:**  JavaScript APIs that operate on the DOM (like `parentNode`, `childNodes`, `nextSibling`, `previousSibling`, `querySelector`, event handling) need to reflect the composed tree when Shadow DOM is involved. This file likely provides the underlying implementation for those APIs in Blink.
    * **HTML:**  The `<slot>` element is central to Shadow DOM composition. This file handles how content is projected into slots during traversal.
    * **CSS:** CSS selectors need to match elements in the composed tree. The rendering engine uses the flat tree structure to determine which styles apply to which elements. The concept of the flat tree is crucial for CSS selectors that cross shadow boundaries (like `:host`, `::slotted`).

7. **Consider Error Scenarios and Debugging:** I thought about common developer errors related to Shadow DOM:
    * Incorrectly assuming the DOM structure is the same as the source HTML when Shadow DOM is used.
    * Not understanding how content is distributed into slots.
    * Issues with event bubbling/capturing across shadow boundaries.
    * Debugging tools often need to show the composed tree, and this file is likely part of the infrastructure that enables that.

8. **Construct Examples and Hypothetical Input/Output:**  To solidify my understanding, I mentally constructed simple HTML snippets with Shadow DOM and thought about how the traversal functions would behave. For example, a host with a shadow root containing a slot, and light DOM children. I envisioned the `TraverseChild`, `TraverseSiblings`, and `TraverseParent` functions navigating this composed tree.

9. **Refine and Organize:**  Finally, I organized my thoughts into the requested categories: functionality, relationships with web technologies, logical reasoning (input/output), user errors, and debugging. I aimed for clear, concise explanations and concrete examples. I paid special attention to explaining *why* this file is important in the context of modern web development with Shadow DOM.

By following this process, I could effectively analyze the provided code snippet and extract its key functionalities and relationships within the Blink rendering engine.
这个文件 `blink/renderer/core/dom/flat_tree_traversal.cc` 的主要功能是**提供一种遍历DOM树的机制，这种遍历方式考虑了Shadow DOM的影响，即所谓的“扁平树”（flat tree）遍历**。

在没有Shadow DOM的情况下，遍历DOM树是很直接的，就是按照父子和兄弟关系进行。但是，当引入Shadow DOM后，一个元素可能拥有一个shadow root，其子节点一部分来自于light DOM（原始HTML），一部分来自于shadow DOM。扁平树的概念就是将这种逻辑上的嵌套关系“扁平化”，形成一个最终渲染时的节点顺序。

以下是该文件功能的详细列举和相关说明：

**主要功能:**

1. **定义了扁平树遍历的各种方法:**  提供了一系列静态方法，用于在DOM树中进行各种方向的遍历，例如：
    * `TraverseChild(const Node& node, TraversalDirection direction)`: 获取指定节点的第一个或最后一个扁平子节点。
    * `TraverseSiblings(const Node& node, TraversalDirection direction)`: 获取指定节点的扁平前一个或后一个兄弟节点。
    * `TraverseParent(const Node& node)`: 获取指定节点的扁平父节点。
    * `TraverseFirstChild(const Node& node)`: 获取指定节点的第一个扁平子节点。
    * `TraverseLastChild(const Node& node)`: 获取指定节点的最后一个扁平子节点。
    * `TraverseNextSibling(const Node& node)`: 获取指定节点的下一个扁平兄弟节点。
    * `TraversePreviousSibling(const Node& node)`: 获取指定节点的上一个扁平兄弟节点。
    * `NextSkippingChildren(const Node& node)`: 获取指定节点的下一个兄弟节点，跳过其子节点。
    * `PreviousAbsoluteSibling(const Node& node)`: 获取指定节点的前一个绝对兄弟节点。
    * `PreviousPostOrder(const Node& current, const Node* stay_within)`:  按照后序遍历的顺序获取前一个节点。
    * `TraverseNextAncestorSibling(const Node& node)`: 获取指定节点的父节点的下一个兄弟节点。
    * `TraversePreviousAncestorSibling(const Node& node)`: 获取指定节点的父节点的上一个兄弟节点。

2. **处理Shadow DOM的边界:**  这些遍历方法的核心在于如何跨越Shadow DOM的边界进行导航。例如，当遍历一个宿主元素（host）的子节点时，如果该宿主元素有shadow root，则会先遍历shadow root的内容。当遍历一个 `<slot>` 元素时，会遍历被分配到该插槽的节点。

3. **维护扁平树节点数据:** 该文件可能依赖于 `FlatTreeNodeData` 结构，用于存储与扁平树相关的附加信息，例如节点被分配到的插槽。

4. **提供辅助方法:**  提供了一些用于判断节点关系或获取节点信息的辅助方法，例如：
    * `ContainsIncludingPseudoElement(const ContainerNode& container, const Node& node)`: 判断一个容器节点是否包含另一个节点（包括伪元素）。
    * `IsDescendantOf(const Node& node, const Node& other)`: 判断一个节点是否是另一个节点的后代。
    * `CommonAncestor(const Node& node_a, const Node& node_b)`: 查找两个节点的最近公共祖先。
    * `Index(const Node& node)`: 获取节点在其扁平父节点中的索引。
    * `CountChildren(const Node& node)`: 获取节点的扁平子节点数量。
    * `LastWithin(const Node& node)`: 获取节点树中最深的最后一个后代节点。
    * `LastWithinOrSelf(const Node& node)`: 获取节点自身或其树中最深的最后一个后代节点。
    * `InclusiveParentElement(const Node& node)`: 获取节点自身（如果是Element）或其扁平父元素。

5. **调试断言 (DCHECK_IS_ON()):**  在调试模式下，包含 `AssertFlatTreeNodeDataUpdated` 函数，用于检查 `FlatTreeNodeData` 的一致性，确保插槽分配等信息是最新的。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:**  JavaScript 代码可以通过 DOM API 与 HTML 文档进行交互。许多 DOM API 的实现需要基于扁平树进行操作，特别是涉及到 Shadow DOM 的场景。
    * **举例:**  当 JavaScript 代码使用 `parentNode` 访问一个被分配到插槽中的节点的父节点时，`FlatTreeTraversal::TraverseParent` 方法会被调用，它会返回包含该插槽的 Shadow Root 的宿主元素，而不是该节点在 light DOM 中的原始父节点。
    * **假设输入:** 一个 `<p>` 元素被分配到一个 `<slot>` 中，而该 `<slot>` 位于一个 Shadow Root 中。JavaScript 调用该 `<p>` 元素的 `parentNode`。
    * **输出:**  `FlatTreeTraversal::TraverseParent` 将返回 Shadow Root 的宿主元素。

* **HTML:** HTML 定义了文档的结构，包括 Shadow DOM 的使用，例如 `<template>` 和 `<slot>` 元素。`FlatTreeTraversal` 的功能是理解和处理这些 HTML 结构带来的影响。
    * **举例:**  当浏览器渲染包含 `<slot>` 元素的 HTML 时，`FlatTreeTraversal` 会被用于确定哪些节点应该被渲染在插槽的位置。
    * **用户操作:** 用户在一个使用了 Shadow DOM 的 Web Component 中插入一些内容到插槽中。
    * **浏览器内部流程:**  浏览器会使用 `FlatTreeTraversal` 来构建最终渲染的节点顺序，确保插入的内容出现在正确的位置。

* **CSS:** CSS 样式规则可以应用于 DOM 树中的元素。当存在 Shadow DOM 时，CSS 的作用域和继承规则会受到影响。扁平树的概念对于 CSS 选择器匹配和样式应用至关重要。
    * **举例:**  CSS 选择器如 `::slotted()` 用于选中被分配到插槽中的元素。Blink 需要使用扁平树遍历来找到这些元素。
    * **假设输入:**  一个 CSS 规则 `::slotted(p) { color: red; }` 应用于一个包含 `<slot>` 的 Shadow Root。Light DOM 中有一个 `<p>` 元素被分配到该 `<slot>` 中。
    * **内部逻辑:** `FlatTreeTraversal` 会在遍历 Shadow Root 的过程中，识别出分配到 `<slot>` 的 `<p>` 元素，从而使 CSS 规则生效。

**逻辑推理的假设输入与输出:**

* **假设输入:**
    ```html
    <my-element>
      #shadow-root
      <slot></slot>
    </my-element>
    <script>
      const myElement = document.querySelector('my-element');
      const shadowRoot = myElement.attachShadow({ mode: 'open' });
      shadowRoot.innerHTML = '<slot></slot>';

      const p = document.createElement('p');
      p.textContent = 'Hello';
      myElement.appendChild(p);

      console.log(p.parentNode); // JavaScript 访问父节点
    </script>
    ```
* **`FlatTreeTraversal::TraverseParent(p)` 的输出:**  `myElement` 节点。这是因为在扁平树中，被分配到插槽的 `<p>` 元素的父节点是包含该插槽的 Shadow Root 的宿主元素。

**用户或编程常见的使用错误:**

* **错误地假设 DOM 结构与 HTML 源代码完全一致:**  开发者可能会忘记 Shadow DOM 的存在，并假设 DOM 树的结构与原始 HTML 一致，这会导致在使用 DOM API 时出现意外的结果。
    * **举例:**  开发者直接访问一个被分配到插槽的元素的 `parentNode`，期望得到其在 light DOM 中的父元素，但实际上会得到 Shadow Host。
    * **调试线索:**  在开发者工具中查看元素的父节点，可能会发现其父节点是一个 Shadow Root 的宿主元素，而不是预期的 light DOM 父元素。

* **在 Shadow DOM 边界处理事件时的误解:**  事件冒泡和捕获在 Shadow DOM 中有特殊的处理规则。开发者可能没有理解事件是如何跨越 Shadow DOM 边界的。
    * **用户操作:** 用户点击了一个位于 Shadow Root 内部的元素。
    * **调试线索:** 开发者可能会在 light DOM 上监听该元素的点击事件，但由于事件冒泡的重定向，事件可能不会直接冒泡到 light DOM 上，或者目标元素会发生变化。

**用户操作如何一步步地到达这里 (作为调试线索):**

1. **用户与网页交互:** 用户在浏览器中访问一个包含使用了 Shadow DOM 的 Web Component 的网页，并与页面元素进行交互，例如点击按钮、输入文本等。

2. **浏览器事件处理:** 用户的操作触发了浏览器事件（如 `click`，`mouseover` 等）。

3. **事件冒泡/捕获和目标确定:** 浏览器需要确定事件的目标元素，这涉及到扁平树的遍历，以确定事件最终发生在哪个逻辑上的元素上。

4. **JavaScript 代码执行:** 如果有 JavaScript 代码监听了相关事件，那么事件处理函数会被执行。这些 JavaScript 代码可能会调用 DOM API 来查询或操作 DOM 结构。

5. **DOM API 调用:**  JavaScript 代码中对 DOM API 的调用（如 `parentNode`, `childNodes`, `querySelector` 等）会触发 Blink 引擎内部相应的 C++ 代码执行。

6. **`FlatTreeTraversal` 的调用:** 当这些 DOM API 的操作涉及到 Shadow DOM 的边界时，Blink 引擎会调用 `flat_tree_traversal.cc` 中定义的遍历方法，以在扁平树上进行正确的导航。

**总结:**

`flat_tree_traversal.cc` 是 Chromium Blink 引擎中负责处理包含 Shadow DOM 的文档结构遍历的关键文件。它提供了一种逻辑上的扁平视图，使得 JavaScript, CSS 和浏览器内部操作能够正确地理解和处理 Shadow DOM 带来的结构变化。理解这个文件的功能对于理解浏览器如何渲染和处理包含 Shadow DOM 的网页至关重要，并且可以帮助开发者调试与 Shadow DOM 相关的各种问题。

### 提示词
```
这是目录为blink/renderer/core/dom/flat_tree_traversal.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"

#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/flat_tree_node_data.h"
#include "third_party/blink/renderer/core/dom/slot_assignment.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"

namespace blink {

#if DCHECK_IS_ON()
void FlatTreeTraversal::AssertFlatTreeNodeDataUpdated(
    const Node& root,
    int& assigned_nodes_in_slot_count,
    int& nodes_which_have_assigned_slot_count) {
  for (Node& node : NodeTraversal::StartsAt(root)) {
    if (auto* element = DynamicTo<Element>(node)) {
      if (ShadowRoot* shadow_root = element->GetShadowRoot()) {
        DCHECK(!shadow_root->NeedsSlotAssignmentRecalc());
        AssertFlatTreeNodeDataUpdated(*shadow_root,
                                      assigned_nodes_in_slot_count,
                                      nodes_which_have_assigned_slot_count);
      }
    }
    if (HTMLSlotElement* slot =
            ToHTMLSlotElementIfSupportsAssignmentOrNull(node)) {
      assigned_nodes_in_slot_count += slot->AssignedNodes().size();
    }
    if (node.IsChildOfShadowHost()) {
      ShadowRoot* parent_shadow_root = node.ParentElementShadowRoot();
      DCHECK(parent_shadow_root);
      if (!parent_shadow_root->HasSlotAssignment()) {
        // |node|'s FlatTreeNodeData can be anything in this case.
        // Nothing can be checked.
        continue;
      }
      if (!node.IsSlotable()) {
        DCHECK(!node.GetFlatTreeNodeData());
        continue;
      }
      if (HTMLSlotElement* assigned_slot =
              parent_shadow_root->AssignedSlotFor(node)) {
        ++nodes_which_have_assigned_slot_count;
        DCHECK(node.GetFlatTreeNodeData());
        DCHECK_EQ(node.GetFlatTreeNodeData()->AssignedSlot(), assigned_slot);
        if (Node* previous =
                node.GetFlatTreeNodeData()->PreviousInAssignedNodes()) {
          DCHECK(previous->GetFlatTreeNodeData());
          DCHECK_EQ(previous->GetFlatTreeNodeData()->NextInAssignedNodes(),
                    node);
          DCHECK_EQ(previous->parentElement(), node.parentElement());
        }
        if (Node* next = node.GetFlatTreeNodeData()->NextInAssignedNodes()) {
          DCHECK(next->GetFlatTreeNodeData());
          DCHECK_EQ(next->GetFlatTreeNodeData()->PreviousInAssignedNodes(),
                    node);
          DCHECK_EQ(next->parentElement(), node.parentElement());
        }
      } else {
        DCHECK(!node.GetFlatTreeNodeData() ||
               node.GetFlatTreeNodeData()->IsCleared());
      }
    }
  }
}
#endif

Node* FlatTreeTraversal::TraverseChild(const Node& node,
                                       TraversalDirection direction) {
  if (auto* slot = ToHTMLSlotElementIfSupportsAssignmentOrNull(node)) {
    if (slot->AssignedNodes().empty()) {
      return direction == kTraversalDirectionForward ? slot->firstChild()
                                                     : slot->lastChild();
    }
    return direction == kTraversalDirectionForward ? slot->FirstAssignedNode()
                                                   : slot->LastAssignedNode();
  }
  Node* child;
  if (ShadowRoot* shadow_root = node.GetShadowRoot()) {
    child = direction == kTraversalDirectionForward ? shadow_root->firstChild()
                                                    : shadow_root->lastChild();
  } else {
    child = direction == kTraversalDirectionForward ? node.firstChild()
                                                    : node.lastChild();
  }
  return child;
}

Node* FlatTreeTraversal::TraverseSiblings(const Node& node,
                                          TraversalDirection direction) {
  if (node.IsChildOfShadowHost())
    return TraverseSiblingsForHostChild(node, direction);

  return direction == kTraversalDirectionForward ? node.nextSibling()
                                                 : node.previousSibling();
}

Node* FlatTreeTraversal::TraverseSiblingsForHostChild(
    const Node& node,
    TraversalDirection direction) {
  ShadowRoot* shadow_root = node.ParentElementShadowRoot();
  DCHECK(shadow_root);
  if (!shadow_root->HasSlotAssignment()) {
    // The shadow root doesn't have any slot.
    return nullptr;
  }
  shadow_root->GetSlotAssignment().RecalcAssignment();

  FlatTreeNodeData* flat_tree_node_data = node.GetFlatTreeNodeData();
  if (!flat_tree_node_data) {
    // This node has never been assigned to any slot.
    return nullptr;
  }
  if (flat_tree_node_data->AssignedSlot()) {
    return direction == kTraversalDirectionForward
               ? flat_tree_node_data->NextInAssignedNodes()
               : flat_tree_node_data->PreviousInAssignedNodes();
  }
  // This node is not assigned to any slot.
  DCHECK(!flat_tree_node_data->NextInAssignedNodes());
  DCHECK(!flat_tree_node_data->PreviousInAssignedNodes());
  return nullptr;
}

ContainerNode* FlatTreeTraversal::TraverseParent(const Node& node) {
  // This code is called extensively, so it minimizes repetitive work (such
  // as avoiding multiple calls to parentElement()).

  // TODO(hayato): Stop this hack for a pseudo element because a pseudo element
  // is not a child of its parentOrShadowHostNode() in a flat tree.
  if (node.IsPseudoElement())
    return node.ParentOrShadowHostNode();

  ContainerNode* parent_node = node.parentNode();
  if (!parent_node)
    return nullptr;

  if (Element* parent_element = DynamicTo<Element>(parent_node)) {
    if (parent_element->GetShadowRoot())
      return node.AssignedSlot();

    if (auto* parent_slot =
            ToHTMLSlotElementIfSupportsAssignmentOrNull(*parent_element)) {
      if (!parent_slot->AssignedNodes().empty())
        return nullptr;
      return parent_slot;
    }
  }

  auto* shadow_root = DynamicTo<ShadowRoot>(parent_node);
  if (!shadow_root)
    return parent_node;

  return &shadow_root->host();
}

Node* FlatTreeTraversal::ChildAt(const Node& node, unsigned index) {
  AssertPrecondition(node);
  Node* child = TraverseFirstChild(node);
  while (child && index--)
    child = NextSibling(*child);
  AssertPostcondition(child);
  return child;
}

Node* FlatTreeTraversal::NextSkippingChildren(const Node& node) {
  if (Node* next_sibling = TraverseNextSibling(node))
    return next_sibling;
  return TraverseNextAncestorSibling(node);
}

bool FlatTreeTraversal::ContainsIncludingPseudoElement(
    const ContainerNode& container,
    const Node& node) {
  AssertPrecondition(container);
  AssertPrecondition(node);
  // This can be slower than FlatTreeTraversal::contains() because we
  // can't early exit even when container doesn't have children.
  for (const Node* current = &node; current;
       current = TraverseParent(*current)) {
    if (current == &container)
      return true;
  }
  return false;
}

Node* FlatTreeTraversal::PreviousAbsoluteSibling(const Node& node) {
  if (Node* previous_sibling = TraversePreviousSibling(node))
    return previous_sibling;
  return TraversePreviousAncestorSibling(node);
}

Node* FlatTreeTraversal::PreviousAncestorSiblingPostOrder(
    const Node& current,
    const Node* stay_within) {
  DCHECK(!FlatTreeTraversal::PreviousSibling(current));
  for (Node* parent = FlatTreeTraversal::Parent(current); parent;
       parent = FlatTreeTraversal::Parent(*parent)) {
    if (parent == stay_within)
      return nullptr;
    if (Node* previous_sibling = FlatTreeTraversal::PreviousSibling(*parent))
      return previous_sibling;
  }
  return nullptr;
}

// TODO(yosin) We should consider introducing template class to share code
// between DOM tree traversal and flat tree tarversal.
Node* FlatTreeTraversal::PreviousPostOrder(const Node& current,
                                           const Node* stay_within) {
  AssertPrecondition(current);
  if (stay_within)
    AssertPrecondition(*stay_within);
  if (Node* last_child = TraverseLastChild(current)) {
    AssertPostcondition(last_child);
    return last_child;
  }
  if (current == stay_within)
    return nullptr;
  if (Node* previous_sibling = TraversePreviousSibling(current)) {
    AssertPostcondition(previous_sibling);
    return previous_sibling;
  }
  return PreviousAncestorSiblingPostOrder(current, stay_within);
}

bool FlatTreeTraversal::IsDescendantOf(const Node& node, const Node& other) {
  AssertPrecondition(node);
  AssertPrecondition(other);
  if (!HasChildren(other) || node.isConnected() != other.isConnected())
    return false;
  for (const ContainerNode* n = TraverseParent(node); n;
       n = TraverseParent(*n)) {
    if (n == other)
      return true;
  }
  return false;
}

Node* FlatTreeTraversal::CommonAncestor(const Node& node_a,
                                        const Node& node_b) {
  AssertPrecondition(node_a);
  AssertPrecondition(node_b);
  Node* result = node_a.CommonAncestor(
      node_b, [](const Node& node) { return FlatTreeTraversal::Parent(node); });
  AssertPostcondition(result);
  return result;
}

Node* FlatTreeTraversal::TraverseNextAncestorSibling(const Node& node) {
  DCHECK(!TraverseNextSibling(node));
  for (Node* parent = TraverseParent(node); parent;
       parent = TraverseParent(*parent)) {
    if (Node* next_sibling = TraverseNextSibling(*parent))
      return next_sibling;
  }
  return nullptr;
}

Node* FlatTreeTraversal::TraversePreviousAncestorSibling(const Node& node) {
  DCHECK(!TraversePreviousSibling(node));
  for (Node* parent = TraverseParent(node); parent;
       parent = TraverseParent(*parent)) {
    if (Node* previous_sibling = TraversePreviousSibling(*parent))
      return previous_sibling;
  }
  return nullptr;
}

unsigned FlatTreeTraversal::Index(const Node& node) {
  AssertPrecondition(node);
  unsigned count = 0;
  for (Node* runner = TraversePreviousSibling(node); runner;
       runner = PreviousSibling(*runner))
    ++count;
  return count;
}

unsigned FlatTreeTraversal::CountChildren(const Node& node) {
  AssertPrecondition(node);
  unsigned count = 0;
  for (Node* runner = TraverseFirstChild(node); runner;
       runner = TraverseNextSibling(*runner))
    ++count;
  return count;
}

Node* FlatTreeTraversal::LastWithin(const Node& node) {
  AssertPrecondition(node);
  Node* descendant = TraverseLastChild(node);
  for (Node* child = descendant; child; child = LastChild(*child))
    descendant = child;
  AssertPostcondition(descendant);
  return descendant;
}

Node& FlatTreeTraversal::LastWithinOrSelf(const Node& node) {
  AssertPrecondition(node);
  Node* last_descendant = LastWithin(node);
  Node& result = last_descendant ? *last_descendant : const_cast<Node&>(node);
  AssertPostcondition(&result);
  return result;
}

const Element* FlatTreeTraversal::InclusiveParentElement(const Node& node) {
  AssertPrecondition(node);
  const Element* inclusive_parent = DynamicTo<Element>(node);
  if (!inclusive_parent) {
    inclusive_parent = ParentElement(node);
  }
  AssertPostcondition(inclusive_parent);
  return inclusive_parent;
}

}  // namespace blink
```