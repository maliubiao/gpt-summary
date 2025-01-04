Response:
The user wants to understand the functionality of the `event_path.cc` file in the Chromium Blink rendering engine. I need to:

1. **Summarize the file's core purpose:**  It's about constructing and manipulating the event path during event dispatch.
2. **Explain its relation to web technologies:**  Connect the concepts in the code (events, nodes, DOM, shadow DOM) to JavaScript, HTML, and CSS.
3. **Illustrate with examples:** Provide concrete scenarios showing how the code interacts with web pages.
4. **Perform logical reasoning:**  Describe how the code processes input and generates output, including hypothetical cases.
5. **Highlight potential user/developer errors:** Identify common mistakes related to event handling that this code addresses.
6. **Explain how users reach this code:** Detail the user interactions that trigger the execution of this file's logic, aiding in debugging.
好的，让我们来分析一下 `blink/renderer/core/dom/events/event_path.cc` 这个文件的功能。

**主要功能:**

`event_path.cc` 文件定义了 `EventPath` 类，这个类的主要功能是**构建和管理事件在 DOM 树中的传播路径**。当一个事件发生时（例如用户的点击），浏览器需要确定哪些元素应该接收到这个事件。`EventPath` 类负责生成一个有序的元素列表，代表事件传播的路径，以便事件可以按照正确的顺序被分发到这些元素。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:** `EventPath` 直接操作 HTML 元素构成的 DOM 树。当用户与 HTML 元素交互时，例如点击一个按钮 (`<button>Click Me</button>`)，`EventPath` 会遍历从触发事件的元素到根元素的路径。

* **JavaScript:** JavaScript 通过事件监听器 (`addEventListener`) 来捕获和处理事件。`EventPath` 构建的路径决定了哪个元素的事件监听器会被触发，以及触发的顺序（捕获阶段和冒泡阶段）。

   ```javascript
   // HTML: <div id="outer"><button id="inner">Click Me</button></div>

   const outerDiv = document.getElementById('outer');
   const innerButton = document.getElementById('inner');

   outerDiv.addEventListener('click', function(event) {
     console.log('Outer div clicked');
   });

   innerButton.addEventListener('click', function(event) {
     console.log('Inner button clicked');
     event.stopPropagation(); // 阻止事件冒泡
   });
   ```

   在这个例子中，当用户点击 "Click Me" 按钮时，`EventPath` 会构建一个包含 `innerButton` 和 `outerDiv` (以及它们的父元素) 的路径。  JavaScript 的事件监听器会按照路径顺序被调用。 `event.stopPropagation()` 会阻止事件继续向上传播。

* **CSS:**  CSS 可以通过伪元素 (pseudo-elements) 来创建额外的元素。 `EventPath` 需要能够正确处理这些伪元素，确定事件是否应该传播到它们。

   ```html
   <style>
     #styled::before {
       content: "Before ";
       display: inline-block;
       background-color: lightblue;
       padding: 5px;
     }
   </style>
   <div id="styled">Text</div>
   ```

   如果用户点击了 `::before` 伪元素，`EventPath` 会将其父元素 (`#styled`) 作为事件的目标。 `EventPath::EventTargetRespectingTargetRules` 函数就处理了这种情况，确保事件的目标是其父节点。

**逻辑推理 (假设输入与输出):**

假设 HTML 结构如下：

```html
<div id="grandparent">
  <div id="parent">
    <button id="child">Click</button>
  </div>
</div>
```

**假设输入:** 用户点击了 ID 为 `child` 的按钮。

**输出 (简化的事件路径):**

1. `child` 元素 (`HTMLButtonElement`)
2. `parent` 元素 (`HTMLDivElement`)
3. `grandparent` 元素 (`HTMLDivElement`)
4. `<body>` 元素 (`HTMLBodyElement`)
5. `<html>` 元素 (`HTMLHtmlElement`)
6. `document` 对象 (`Document`)
7. `window` 对象 (由 `WindowEventContext` 管理，虽然不是 DOM 节点)

**关键的逻辑点:**

* **冒泡 (Bubbling):**  事件通常会从触发事件的最深层元素开始，向上冒泡到文档根节点。 `CalculatePath` 函数负责构建这个向上的路径。
* **捕获 (Capturing):** 在冒泡之前，事件可以先从文档根节点向下传播到目标元素。虽然 `EventPath` 的主要职责是构建冒泡路径，但它提供的上下文信息也为捕获阶段的处理提供了基础。
* **Shadow DOM:**  如果存在 Shadow DOM，`EventPath` 需要根据事件的 `composed` 属性来决定是否穿透 Shadow Boundary。`ShouldStopAtShadowRoot` 函数就处理了这种情况。
* **Slot 元素:** 当使用 `<slot>` 元素进行内容分发时，`EventPath` 需要正确地将事件路由到分发的元素。

**用户或编程常见的使用错误及举例说明:**

* **错误地假设事件目标:**  开发者可能会错误地认为事件的目标始终是用户直接交互的元素。例如，在 Shadow DOM 中，如果事件没有设置 `composed: true`，事件的目标可能停留在 Shadow Host 上，而不是 Shadow DOM 内部的元素。

   ```html
   <!-- Shadow DOM 示例 -->
   <my-component>
     #shadow-root
     <button id="shadowButton">Click Me</button>
   </my-component>

   <script>
     const component = document.querySelector('my-component');
     component.shadowRoot.querySelector('#shadowButton').addEventListener('click', function(event) {
       console.log('Shadow button clicked', event.target); // event.target 是 shadowButton
     });

     component.addEventListener('click', function(event) {
       console.log('Component clicked', event.target); // event.target 是 my-component
     });
   </script>
   ```

   在这个例子中，外部的事件监听器接收到的 `event.target` 是 `<my-component>`，而不是 Shadow DOM 内部的按钮。理解 `EventPath` 如何处理 Shadow DOM 可以帮助开发者避免这种误解。

* **过度依赖事件冒泡而不理解路径:**  开发者可能依赖事件冒泡，但没有充分理解事件传播的路径，导致在复杂的 DOM 结构中出现意外的行为。例如，没有考虑到 Shadow DOM 或 `slot` 元素对事件路径的影响。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户交互:** 用户在浏览器中执行某个操作，例如点击一个链接、输入文本、鼠标悬停等。

2. **浏览器事件生成:**  浏览器的底层系统（例如操作系统或渲染引擎的输入处理部分）检测到用户交互，并生成一个对应的事件对象 (例如 `MouseEvent`, `KeyboardEvent`)。

3. **事件分发开始:**  渲染引擎开始事件分发过程。

4. **确定事件目标:**  根据用户交互的位置，浏览器确定事件的初始目标元素。

5. **`EventPath` 构建:**  `EventPath` 类被实例化，接收事件的初始目标元素和事件对象作为参数。 `CalculatePath` 方法被调用，开始构建事件传播的路径。

6. **遍历 DOM 树:** `CalculatePath` 方法从目标元素开始，向上遍历 DOM 树，直到根节点 (或遇到阻止事件传播的情况)。在这个过程中，它会考虑 Shadow DOM 和 `slot` 元素的影响。

7. **路径存储:** 构建好的事件路径被存储在 `EventPath` 对象的内部数据结构中 (`node_event_contexts_`, `tree_scope_event_contexts_`)。

8. **事件传播:**  事件按照构建好的路径进行传播，依次触发路径上元素的事件监听器 (在捕获和冒泡阶段)。

**调试线索:**

当你在 Chromium 浏览器中调试事件处理问题时，理解 `EventPath` 的工作原理非常有帮助：

* **查看事件目标:** 使用浏览器的开发者工具检查事件对象的 `target` 属性，可以确定事件的初始目标。
* **断点调试:**  在 `event_path.cc` 中的关键函数（如 `CalculatePath`, `ShouldStopAtShadowRoot`）设置断点，可以观察事件路径的构建过程，理解事件是如何穿过 Shadow DOM 或 `slot` 元素的。
* **检查事件监听器:**  使用开发者工具的 "Event Listeners" 面板，可以查看特定元素上注册的事件监听器，以及它们是在捕获阶段还是冒泡阶段触发。
* **分析 `composedPath()`:** 在 JavaScript 中，可以使用 `event.composedPath()` 方法获取事件的完整传播路径，包括穿过 Shadow DOM 的路径，这与 `EventPath` 构建的路径密切相关。

总而言之，`event_path.cc` 中的 `EventPath` 类是 Chromium Blink 引擎中事件处理的核心组件之一，它负责构建事件传播的蓝图，确保事件能够按照预定的规则和顺序到达目标元素，并触发相应的事件监听器。理解它的工作原理对于深入理解浏览器事件机制和进行 Web 开发调试至关重要。

Prompt: 
```
这是目录为blink/renderer/core/dom/events/event_path.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/dom/events/event_path.h"

#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/window_event_context.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/events/touch_event.h"
#include "third_party/blink/renderer/core/events/touch_event_context.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/input/touch.h"
#include "third_party/blink/renderer/core/input/touch_list.h"

namespace blink {

EventTarget& EventPath::EventTargetRespectingTargetRules(Node& reference_node) {
  if (reference_node.IsPseudoElement() &&
      !reference_node.IsScrollControlPseudoElement()) {
    DCHECK(reference_node.parentNode());
    return *reference_node.parentNode();
  }

  return reference_node;
}

static inline bool ShouldStopAtShadowRoot(Event& event,
                                          ShadowRoot& shadow_root,
                                          EventTarget& target) {
  // An event is scoped by default unless event.composed flag is set.
  return !event.composed() && target.ToNode() &&
         target.ToNode()->OwnerShadowHost() == shadow_root.host();
}

EventPath::EventPath(Node& node, Event* event) : node_(node), event_(event) {
  Initialize();
}

void EventPath::InitializeWith(Node& node, Event* event) {
  node_ = &node;
  event_ = event;
  window_event_context_ = nullptr;
  node_event_contexts_.clear();
  tree_scope_event_contexts_.clear();
  Initialize();
}

static inline bool EventPathShouldBeEmptyFor(Node& node) {
  // Event path should be empty for orphaned pseudo elements, and nodes
  // whose document is stopped. In corner cases (crbug.com/1210480), the node
  // document can get detached before we can remove event listeners.
  if (RuntimeEnabledFeatures::PseudoElementsFocusableEnabled() &&
      node.IsScrollControlPseudoElement()) {
    return false;
  }
  return (node.IsPseudoElement() && !node.parentElement()) ||
         node.GetDocument().IsStopped();
}

void EventPath::Initialize() {
  if (EventPathShouldBeEmptyFor(*node_))
    return;

  CalculatePath();
  CalculateAdjustedTargets();
  CalculateTreeOrderAndSetNearestAncestorClosedTree();
}

void EventPath::CalculatePath() {
  DCHECK(node_);
  DCHECK(node_event_contexts_.empty());

  // For performance and memory usage reasons we want to store the
  // path using as few bytes as possible and with as few allocations
  // as possible which is why we gather the data on the stack before
  // storing it in a perfectly sized node_event_contexts_ Vector.
  HeapVector<Member<Node>, 64> nodes_in_path;
  Node* current = node_;

  nodes_in_path.push_back(current);
  while (current) {
    if (event_ && current->KeepEventInNode(*event_))
      break;
    if (current->IsChildOfShadowHost() && !current->IsPseudoElement()) {
      if (HTMLSlotElement* slot = current->AssignedSlot()) {
        current = slot;
        nodes_in_path.push_back(current);
        continue;
      }
    }
    if (auto* shadow_root = DynamicTo<ShadowRoot>(current)) {
      if (event_ && ShouldStopAtShadowRoot(*event_, *shadow_root, *node_))
        break;
      current = current->OwnerShadowHost();
      nodes_in_path.push_back(current);
    } else {
      current = current->parentNode();
      if (current)
        nodes_in_path.push_back(current);
    }
  }
  node_event_contexts_ = HeapVector<NodeEventContext>(
      nodes_in_path, [](Node* node_in_path) -> NodeEventContext {
        DCHECK(node_in_path);
        return NodeEventContext(
            *node_in_path, EventTargetRespectingTargetRules(*node_in_path));
      });
}

void EventPath::CalculateTreeOrderAndSetNearestAncestorClosedTree() {
  // Precondition:
  //   - TreeScopes in tree_scope_event_contexts_ must be *connected* in the
  //     same composed tree.
  //   - The root tree must be included.
  TreeScopeEventContext* root_tree = nullptr;
  for (const auto& tree_scope_event_context : tree_scope_event_contexts_) {
    TreeScope* parent =
        tree_scope_event_context.Get()->GetTreeScope().ParentTreeScope();
    if (!parent) {
      DCHECK(!root_tree);
      root_tree = tree_scope_event_context.Get();
      continue;
    }
    TreeScopeEventContext* parent_tree_scope_event_context =
        GetTreeScopeEventContext(*parent);
    DCHECK(parent_tree_scope_event_context);
    parent_tree_scope_event_context->AddChild(*tree_scope_event_context.Get());
  }
  DCHECK(root_tree);
  root_tree->CalculateTreeOrderAndSetNearestAncestorClosedTree(0, nullptr);
}

TreeScopeEventContext* EventPath::GetTreeScopeEventContext(
    TreeScope& tree_scope) {
  for (TreeScopeEventContext* tree_scope_event_context :
       tree_scope_event_contexts_) {
    if (tree_scope_event_context->GetTreeScope() == tree_scope) {
      return tree_scope_event_context;
    }
  }
  return nullptr;
}

TreeScopeEventContext* EventPath::EnsureTreeScopeEventContext(
    Node* current_target,
    TreeScope* tree_scope) {
  if (!tree_scope)
    return nullptr;
  TreeScopeEventContext* tree_scope_event_context =
      GetTreeScopeEventContext(*tree_scope);
  if (!tree_scope_event_context) {
    tree_scope_event_context =
        MakeGarbageCollected<TreeScopeEventContext>(*tree_scope);
    tree_scope_event_contexts_.push_back(tree_scope_event_context);

    TreeScopeEventContext* parent_tree_scope_event_context =
        EnsureTreeScopeEventContext(nullptr, tree_scope->ParentTreeScope());
    if (parent_tree_scope_event_context &&
        parent_tree_scope_event_context->Target()) {
      tree_scope_event_context->SetTarget(
          *parent_tree_scope_event_context->Target());
    } else if (current_target) {
      tree_scope_event_context->SetTarget(
          EventTargetRespectingTargetRules(*current_target));
    }
  } else if (!tree_scope_event_context->Target() && current_target) {
    tree_scope_event_context->SetTarget(
        EventTargetRespectingTargetRules(*current_target));
  }
  return tree_scope_event_context;
}

void EventPath::CalculateAdjustedTargets() {
  const TreeScope* last_tree_scope = nullptr;
  TreeScopeEventContext* last_tree_scope_event_context = nullptr;

  for (auto& context : node_event_contexts_) {
    Node& current_node = context.GetNode();
    TreeScope& current_tree_scope = current_node.GetTreeScope();
    if (last_tree_scope != &current_tree_scope) {
      last_tree_scope_event_context =
          EnsureTreeScopeEventContext(&current_node, &current_tree_scope);
    }
    DCHECK(last_tree_scope_event_context);
    context.SetTreeScopeEventContext(last_tree_scope_event_context);
    last_tree_scope = &current_tree_scope;
  }
}

void EventPath::BuildRelatedNodeMap(const Node& related_node,
                                    RelatedTargetMap& related_target_map) {
  EventPath* related_target_event_path =
      MakeGarbageCollected<EventPath>(const_cast<Node&>(related_node));
  for (const auto& tree_scope_event_context :
       related_target_event_path->tree_scope_event_contexts_) {
    related_target_map.insert(&tree_scope_event_context->GetTreeScope(),
                              tree_scope_event_context->Target());
  }
  // Oilpan: It is important to explicitly clear the vectors to reuse
  // the memory in subsequent event dispatchings.
  related_target_event_path->Clear();
}

EventTarget* EventPath::FindRelatedNode(TreeScope& scope,
                                        RelatedTargetMap& related_target_map) {
  HeapVector<Member<TreeScope>, 32> parent_tree_scopes;
  EventTarget* related_node = nullptr;
  for (TreeScope* current = &scope; current;
       current = current->ParentTreeScope()) {
    parent_tree_scopes.push_back(current);
    RelatedTargetMap::const_iterator iter = related_target_map.find(current);
    if (iter != related_target_map.end() && iter->value) {
      related_node = iter->value;
      break;
    }
  }
  DCHECK(related_node);
  for (const auto& entry : parent_tree_scopes)
    related_target_map.insert(entry, related_node);

  return related_node;
}

void EventPath::AdjustForRelatedTarget(Node& target,
                                       EventTarget* related_target) {
  if (!related_target)
    return;
  Node* related_target_node = related_target->ToNode();
  if (!related_target_node)
    return;
  if (target.GetDocument() != related_target_node->GetDocument())
    return;
  RetargetRelatedTarget(*related_target_node);
  ShrinkForRelatedTarget(target, *related_target_node);
}

void EventPath::RetargetRelatedTarget(const Node& related_target_node) {
  RelatedTargetMap related_node_map;
  BuildRelatedNodeMap(related_target_node, related_node_map);

  for (const auto& tree_scope_event_context : tree_scope_event_contexts_) {
    EventTarget* adjusted_related_target = FindRelatedNode(
        tree_scope_event_context->GetTreeScope(), related_node_map);
    DCHECK(adjusted_related_target);
    tree_scope_event_context.Get()->SetRelatedTarget(*adjusted_related_target);
  }
  // Explicitly clear the heap container to avoid memory regressions in the hot
  // path.
  // TODO(bikineev): Revisit after young generation is there.
  related_node_map.clear();
}

namespace {

bool ShouldStopEventPath(EventTarget& adjusted_target,
                         EventTarget& adjusted_related_target,
                         const Node& event_target_node,
                         const Node& event_related_target_node) {
  if (&adjusted_target != &adjusted_related_target)
    return false;
  Node* adjusted_target_node = adjusted_target.ToNode();
  if (!adjusted_target_node)
    return false;
  Node* adjusted_related_target_node = adjusted_related_target.ToNode();
  if (!adjusted_related_target_node)
    return false;
  // Events should be dispatched at least until its root even when event's
  // target and related_target are identical.
  if (adjusted_target_node->GetTreeScope() ==
          event_target_node.GetTreeScope() &&
      adjusted_related_target_node->GetTreeScope() ==
          event_related_target_node.GetTreeScope())
    return false;
  return true;
}

}  // anonymous namespace

void EventPath::ShrinkForRelatedTarget(const Node& event_target_node,
                                       const Node& event_related_target_node) {
  for (wtf_size_t i = 0; i < size(); ++i) {
    if (ShouldStopEventPath(*(*this)[i].Target(), *(*this)[i].RelatedTarget(),
                            event_target_node, event_related_target_node)) {
      Shrink(i);
      break;
    }
  }
}

void EventPath::AdjustForTouchEvent(const TouchEvent& touch_event) {
  // Each vector and a TouchEventContext share the same TouchList instance.
  HeapVector<Member<TouchList>> adjusted_touches;
  HeapVector<Member<TouchList>> adjusted_target_touches;
  HeapVector<Member<TouchList>> adjusted_changed_touches;
  HeapVector<Member<TreeScope>> tree_scopes;

  for (const auto& tree_scope_event_context : tree_scope_event_contexts_) {
    TouchEventContext& touch_event_context =
        tree_scope_event_context->EnsureTouchEventContext();
    adjusted_touches.push_back(&touch_event_context.Touches());
    adjusted_target_touches.push_back(&touch_event_context.TargetTouches());
    adjusted_changed_touches.push_back(&touch_event_context.ChangedTouches());
    tree_scopes.push_back(&tree_scope_event_context->GetTreeScope());
  }

  // AdjustTouchList appends adjusted Touch(es) to each member TouchList
  // instance in |adjusted_touch_list| argument, which is reflected on
  // TouchEventContext because they refer to the same TouchList instance.
  AdjustTouchList(touch_event.touches(), adjusted_touches, tree_scopes);
  AdjustTouchList(touch_event.targetTouches(), adjusted_target_touches,
                  tree_scopes);
  AdjustTouchList(touch_event.changedTouches(), adjusted_changed_touches,
                  tree_scopes);

#if DCHECK_IS_ON()
  for (const auto& tree_scope_event_context : tree_scope_event_contexts_) {
    TreeScope& tree_scope = tree_scope_event_context->GetTreeScope();
    TouchEventContext* touch_event_context =
        tree_scope_event_context->GetTouchEventContext();
    CheckReachability(tree_scope, touch_event_context->Touches());
    CheckReachability(tree_scope, touch_event_context->TargetTouches());
    CheckReachability(tree_scope, touch_event_context->ChangedTouches());
  }
#endif
}

void EventPath::AdjustTouchList(
    const TouchList* const touch_list,
    HeapVector<Member<TouchList>> adjusted_touch_list,
    const HeapVector<Member<TreeScope>>& tree_scopes) {
  if (!touch_list)
    return;
  for (wtf_size_t i = 0; i < touch_list->length(); ++i) {
    const Touch& touch = *touch_list->item(i);
    if (!touch.target())
      continue;

    Node* target_node = touch.target()->ToNode();
    if (!target_node)
      continue;

    RelatedTargetMap related_node_map;
    BuildRelatedNodeMap(*target_node, related_node_map);
    for (wtf_size_t j = 0; j < tree_scopes.size(); ++j) {
      adjusted_touch_list[j]->Append(touch.CloneWithNewTarget(
          FindRelatedNode(*tree_scopes[j], related_node_map)));
    }
    // Explicitly clear the heap container to avoid memory regressions in the
    // hot path.
    // TODO(bikineev): Revisit after young generation is there.
    related_node_map.clear();
  }
}

void EventPath::AdjustForDisabledFormControl() {
  for (unsigned i = 0; i < node_event_contexts_.size(); i++) {
    if (IsDisabledFormControl(&node_event_contexts_[i].GetNode())) {
      Shrink(i);
      return;
    }
  }
}

bool EventPath::DisabledFormControlExistsInPath() const {
  for (const auto& context : node_event_contexts_) {
    if (IsDisabledFormControl(&context.GetNode()))
      return true;
  }
  return false;
}

bool EventPath::HasEventListenersInPath(const AtomicString& event_type) const {
  for (const auto& context : node_event_contexts_) {
    if (context.GetNode().HasEventListeners(event_type))
      return true;
  }
  return false;
}

NodeEventContext& EventPath::TopNodeEventContext() {
  DCHECK(!IsEmpty());
  return Last();
}

void EventPath::EnsureWindowEventContext() {
  DCHECK(event_);
  if (!window_event_context_) {
    window_event_context_ = MakeGarbageCollected<WindowEventContext>(
        *event_, TopNodeEventContext());
  }
}

#if DCHECK_IS_ON()
void EventPath::CheckReachability(TreeScope& tree_scope,
                                  TouchList& touch_list) {
  for (wtf_size_t i = 0; i < touch_list.length(); ++i) {
    DCHECK(touch_list.item(i)
               ->target()
               ->ToNode()
               ->GetTreeScope()
               .IsInclusiveAncestorTreeScopeOf(tree_scope));
  }
}
#endif

void EventPath::Trace(Visitor* visitor) const {
  visitor->Trace(node_event_contexts_);
  visitor->Trace(node_);
  visitor->Trace(event_);
  visitor->Trace(tree_scope_event_contexts_);
  visitor->Trace(window_event_context_);
}

}  // namespace blink

"""

```