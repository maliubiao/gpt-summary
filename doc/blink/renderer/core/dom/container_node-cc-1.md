Response:
Let's break down the thought process for analyzing the provided code snippet of `container_node.cc`.

**1. Initial Reading and Skimming for Keywords and Structure:**

First, I would quickly read through the code, looking for familiar terms related to DOM manipulation and browser internals. Keywords like `appendChild`, `removeChild`, `insertBefore`, `parentNode`, `firstChild`, `lastChild`, `layout`, `style`, `event`, `mutation`, `JavaScript`, `HTML`, and `CSS` would immediately catch my attention. The structure of the code, with various methods and conditional logic, suggests this file is responsible for managing the children of a container node in the DOM.

**2. Identifying Core Functionality:**

Based on the keywords and structure, I'd start grouping related methods and inferring their purpose. I would notice patterns like:

* **Adding/Removing Children:**  Methods like `AppendChild`, `RemoveChild`, `RemoveBetween`, `ParserAppendChild`, `RemoveChildren`. These clearly handle the basic DOM manipulation of adding and removing child nodes.
* **Layout and Rendering:** Mentions of `LayoutBox`, `AttachLayoutTree`, `DetachLayoutTree`, `RebuildLayoutTreeForChild`, `RecalcDescendantStyles`. This points to the file's involvement in the layout and rendering process.
* **Events and Mutation Observers:**  `DispatchChildInsertionEvents`, `DispatchChildRemovalEvents`, `NotifyMutationObserversNodeWillDetach`, `ChildListMutationScope`. This signifies the file's role in managing DOM events and notifying mutation observers about changes.
* **Parser Integration:** `ParserAppendChild`, `ParserRemoveChild`, `ParserFinishedBuildingDocumentFragment`. These suggest interaction with the HTML parsing process.
* **Query Selectors:** `querySelector`, `querySelectorAll`. These are direct implementations of JavaScript DOM querying methods.

**3. Focusing on Key Methods and their Interactions:**

Next, I would dive deeper into the more complex or frequently used methods, analyzing their internal logic and how they interact with other parts of the code:

* **`AppendChild` and `RemoveChild`:** I'd examine the pre-insertion validity checks, the handling of document focus, the potential for mutation events to move nodes, and the interaction with the layout tree. I'd pay attention to the `ExceptionState` parameters, indicating potential JavaScript errors.
* **`WillRemoveChild` and `WillRemoveChildren`:**  I'd notice the calls to `ScriptForbiddenScope` and `EventDispatchForbiddenScope`, suggesting constraints during these operations. The handling of `ChildFrameDisconnector` is important for understanding how subframes are managed.
* **The `ChildrenChanged` method:** This looks like a central point for notifying the document and style engine about changes to the children. I'd note the different `ChildrenChangeType` values.

**4. Connecting to JavaScript, HTML, and CSS:**

With a good understanding of the core functionality, I would then explicitly think about how these operations relate to the web development technologies:

* **JavaScript:**  The `AppendChild`, `RemoveChild`, `querySelector`, and `querySelectorAll` methods are directly accessible from JavaScript. The exception handling and event dispatching mechanisms are also crucial for how JavaScript interacts with the DOM.
* **HTML:** The structure of the DOM tree being manipulated directly reflects the HTML structure. The parser integration methods handle the conversion of HTML markup into the DOM.
* **CSS:** The layout and style-related methods are responsible for applying CSS styles and calculating the visual layout of the page. The invalidation mechanisms ensure that style and layout are updated when the DOM changes.

**5. Generating Examples and Scenarios:**

To solidify my understanding and illustrate the relationships, I would create concrete examples:

* **JavaScript Interaction:**  A simple JavaScript code snippet calling `appendChild` or `removeChild` and explaining how it leads to the execution of the corresponding C++ methods.
* **HTML Parsing:** Describing how the browser parser encounters HTML tags and calls the `ParserAppendChild` method to create the corresponding DOM nodes.
* **CSS Styling:**  Explaining how adding or removing nodes can trigger style recalculation and layout updates, involving methods like `RecalcDescendantStyles` and `AttachLayoutTree`.

**6. Considering User/Programming Errors:**

I'd consider common mistakes developers make when working with the DOM:

* Attempting to remove a node that isn't a child.
* Manipulating the DOM in event handlers in a way that causes unexpected side effects (like moving nodes).
* Incorrectly using `querySelector` and `querySelectorAll` with invalid selectors.

**7. Thinking about Debugging and User Actions:**

To understand how a user's actions might lead to this code, I would consider the sequence of events:

* User interacts with the page (e.g., clicks a button).
* JavaScript event handler is triggered.
* JavaScript code manipulates the DOM using methods like `appendChild` or `removeChild`.
* This triggers the execution of the C++ methods in `container_node.cc`.

**8. Structuring the Output:**

Finally, I would organize my findings into a clear and structured format, addressing the specific points requested in the prompt: functionality, relation to JavaScript/HTML/CSS, logical reasoning (assumptions and outputs), common errors, debugging clues, and a concise summary. I'd use headings, bullet points, and code examples to make the information easy to understand.

**Self-Correction/Refinement during the Process:**

* **Initial Overwhelm:**  The initial amount of code might seem daunting. The key is to break it down into smaller, manageable pieces.
* **Focusing on the "Why":**  Instead of just listing methods, focus on *why* those methods exist and what role they play in the overall DOM manipulation process.
* **Connecting the Dots:**  Constantly look for connections between different methods and how they work together. For example, how does `AppendChild` relate to `NotifyNodeInserted` and `ChildrenChanged`?
* **Using Analogies:** Sometimes, thinking of real-world analogies (like building blocks or a family tree) can help understand the relationships between DOM nodes.

By following this iterative and analytical process, I can effectively understand and explain the functionality of the `container_node.cc` file.
好的，让我们继续分析 `blink/renderer/core/dom/container_node.cc` 的第 2 部分代码。

**功能归纳:**

这部分代码主要负责实现 `ContainerNode` 中关于**移除（Removal）和添加（Insertion）子节点**的核心功能。它涵盖了通过 JavaScript API 和 HTML 解析器进行的节点操作，并处理了相关的事件分发、布局更新、样式失效以及对 Mutation Observer 的通知。  此外，还包括对子框架的管理和一些优化措施。

**更详细的功能点:**

* **子节点的移除 (Removal):**
    * **`WillRemoveChild()`:** 在移除子节点前执行，用于禁止脚本执行和事件分发，并通知文档即将移除节点。
    * **`WillRemoveChildren()`:** 在移除所有子节点前执行，用于获取所有子节点，通知 Mutation Observer，并断开子框架的连接（非原子移动情况下）。
    * **`RemoveChild(Node* old_child, ExceptionState& exception_state)`:**  通过 JavaScript API 移除指定的子节点。包含错误检查（例如，子节点是否是该节点的子节点），处理焦点元素的移除，以及可能的 Mutation 事件触发的节点移动。还会检查是否需要合并相邻的 `LayoutTextCombine` 对象。
    * **`RemoveChild(Node* old_child)`:**  `RemoveChild` 的重载版本，不抛出异常。
    * **`RemoveBetween(Node* previous_child, Node* next_child, Node& old_child)`:**  实际执行节点移除操作，更新兄弟节点和父节点的指针，并调用 `GetDocument().AdoptIfNeeded(old_child)`。
    * **`ParserRemoveChild(Node& old_child)`:**  由 HTML 解析器调用以移除子节点，处理子框架的断开连接。
    * **`RemoveChildren(SubtreeModificationAction action)`:**  移除所有子节点，可以控制是否触发 `subtreeModified` 事件。

* **子节点的添加 (Insertion):**
    * **`AppendChildren(const VectorOf<Node>& new_children, ExceptionState& exception_state)`:**  通过 JavaScript API 批量添加多个子节点。
    * **`AppendChild(Node* new_child, ExceptionState& exception_state)`:**  通过 JavaScript API 添加单个子节点。包含预插入有效性检查，处理节点从旧父节点移除的情况。
    * **`AppendChild(Node* new_child)`:**  `AppendChild` 的重载版本，不抛出异常。
    * **`ParserAppendChild(Node* new_child)`:**  由 HTML 解析器调用以添加子节点。
    * **`ParserAppendChildInDocumentFragment(Node* new_child)`:**  在构建 `DocumentFragment` 时由解析器调用以添加子节点。
    * **`ParserFinishedBuildingDocumentFragment()`:**  在解析器完成构建 `DocumentFragment` 后调用，用于触发相关通知。

* **事件分发和通知:**
    * **`DispatchChildRemovalEvents(Node& child)`:**  分发节点移除相关的 DOM 事件（如 `DOMNodeRemoved` 和 `DOMNodeRemovedFromDocument`）。
    * **`DispatchChildInsertionEvents(Node& child)`:**  分发节点插入相关的 DOM 事件（如 `DOMNodeInserted` 和 `DOMNodeInsertedIntoDocument`）。
    * **`NotifyNodeRemoved(Node& root)`:**  通知节点及其后代节点它们已被移除。
    * **`NotifyNodeInserted(Node& root, ChildrenChangeSource source)`:** 通知节点及其后代节点它们已被插入。
    * **`NotifyNodeInsertedInternal(...)`:** 内部辅助函数，用于递归通知节点插入事件。
    * **`NotifyNodeAtEndOfBuildingFragmentTree(...)`:** 在构建 DocumentFragment 树的末尾通知节点。

* **布局和样式更新:**
    * **`AttachLayoutTree(AttachContext& context)`:**  将节点的布局树附加到父节点。
    * **`DetachLayoutTree(bool performing_reattach)`:**  从父节点分离节点的布局树。
    * **`ChildrenChanged(const ChildrenChange& change)`:**  当子节点发生变化时调用，用于更新 DOM 树版本，通知文档，失效节点列表缓存，并触发样式更新。

* **其他功能:**
    * **`ShouldMergeCombinedTextAfterRemoval(...)`:**  判断移除节点后是否需要合并相邻的 `LayoutTextCombine` 对象，以优化渲染。
    * **`GetLayoutBoxForScrolling()`:** 获取用于滚动的布局盒。
    * **`IsReadingFlowContainer()`:** 判断是否是阅读流容器。
    * **`CloneChildNodesFrom(...)`:** 从另一个 `ContainerNode` 克隆子节点。
    * **`BoundingBox()`:** 获取节点的边界框。
    * **`children()`:**  返回子元素的 `HTMLCollection`。
    * **`firstElementChild()`, `lastElementChild()`, `childElementCount()`:**  获取第一个、最后一个子元素以及子元素的数量。
    * **`querySelector()`, `querySelectorAll()`:**  实现 CSS 选择器查询功能。
    * **`CountChildren()`:**  统计子节点的数量。
    * **`HasOnlyText()`:**  判断是否只包含文本子节点。
    * **`SetRestyleFlag()`:**  设置样式重计算的标记。
    * **`RecalcDescendantStyles()`:**  递归地重新计算后代节点的样式。
    * **`RebuildLayoutTreeForChild()`:**  为子节点重建布局树。
    * **`RebuildChildrenLayoutTrees()`:**  重建所有子节点的布局树。
    * **`CheckForSiblingStyleChanges()`:**  检查兄弟节点样式是否需要更新。
    * **`InvalidateNodeListCachesInAncestors()`:**  失效祖先节点的 NodeList 缓存。

**与 JavaScript, HTML, CSS 的关系举例说明:**

1. **JavaScript:**
   ```javascript
   // 假设 container 是一个 DOM 元素
   const newElement = document.createElement('div');
   container.appendChild(newElement); // 这会触发 ContainerNode::AppendChild

   const childToRemove = container.firstChild;
   container.removeChild(childToRemove); // 这会触发 ContainerNode::RemoveChild
   ```
   当 JavaScript 代码调用 `appendChild` 或 `removeChild` 等方法时，Blink 引擎会调用 `ContainerNode` 中相应的 C++ 方法来执行实际的 DOM 操作。

2. **HTML:**
   ```html
   <div>
     <span>这是一个子元素</span>
   </div>
   ```
   当浏览器解析这段 HTML 代码时，解析器会遇到 `<div>` 和 `<span>` 标签。对于 `<div>` 元素，会创建一个 `ContainerNode` 对象（通常是 `HTMLDivElement`）。当解析到 `<span>` 标签时，解析器会调用 `ContainerNode::ParserAppendChild` 方法将 `<span>` 元素作为 `<div>` 元素的子节点添加到 DOM 树中。

3. **CSS:**
   ```css
   .container > span {
     color: blue;
   }
   ```
   当一个元素被添加到或从 DOM 树中移除时，可能会影响 CSS 样式的应用。例如，如果一个 `<span>` 元素被添加到具有 `.container` 类的 `<div>` 元素中，CSS 引擎需要重新计算样式，`ContainerNode::ChildrenChanged` 方法会触发样式失效，最终导致 `RecalcDescendantStyles` 等方法被调用来更新样式。`CheckForSiblingStyleChanges` 方法则会处理像 `:first-child`、`:last-child` 等 CSS 伪类选择器的影响。

**逻辑推理的假设输入与输出:**

**假设输入:**  一个包含若干文本节点和元素节点的 `div` 元素。

**场景 1：移除中间的元素节点**

* **输入:**  调用 `divElement.removeChild(middleElement)`，其中 `middleElement` 是 `divElement` 的一个子元素。
* **输出:**
    * `WillRemoveChild(middleElement)` 被调用。
    * `DispatchChildRemovalEvents(middleElement)` 分发 `DOMNodeRemoved` 事件。
    * `RemoveBetween(previousSiblingOfMiddle, nextSiblingOfMiddle, middleElement)` 更新兄弟节点的链接。
    * `NotifyNodeRemoved(middleElement)` 通知 `middleElement` 及其后代节点已被移除。
    * `ChildrenChanged` 被调用，类型为移除，可能触发样式和布局的更新。

**场景 2：在开头插入一个新元素节点**

* **输入:** 调用 `divElement.insertBefore(newElement, divElement.firstChild)`。
* **输出:**
    * 相关的预插入检查会通过。
    * `NotifyNodeInserted(newElement)` 被调用。
    * `DispatchChildInsertionEvents(newElement)` 分发 `DOMNodeInserted` 事件。
    * `ChildrenChanged` 被调用，类型为插入，可能触发样式和布局的更新。
    * `CheckForSiblingStyleChanges` 可能会被调用，因为插入操作可能影响兄弟节点的样式（例如，`:first-child` 伪类）。

**用户或编程常见的使用错误举例说明:**

1. **尝试移除不存在的子节点:**
   ```javascript
   const container = document.getElementById('myContainer');
   const notAChild = document.createElement('p');
   try {
     container.removeChild(notAChild); // notAChild 不是 container 的子节点
   } catch (error) {
     console.error(error); // 抛出 NotFoundError 异常
   }
   ```
   在这种情况下，`ContainerNode::RemoveChild` 会检查 `old_child->parentNode() != this` 的条件，并抛出 `NotFoundError` 异常。

2. **在事件处理程序中移动节点导致移除失败:**
   ```javascript
   const container1 = document.getElementById('container1');
   const container2 = document.getElementById('container2');
   const childToRemove = container1.firstChild;

   container1.addEventListener('blur', () => {
     container2.appendChild(childToRemove); // 在 blur 事件中将节点移动到另一个容器
   });

   try {
     container1.removeChild(childToRemove); // 当 blur 事件触发后，childToRemove 不再是 container1 的子节点
   } catch (error) {
     console.error(error); // 抛出 NotFoundError 异常，提示节点已移动
   }
   ```
   `ContainerNode::RemoveChild` 会在移除前再次检查 `child->parentNode() != this`，如果节点已被移动，则会抛出异常。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中与网页交互:** 例如，点击按钮、填写表单、滚动页面等。
2. **JavaScript 事件触发:** 用户的交互可能触发 JavaScript 事件监听器（例如 `onclick`, `onchange`）。
3. **JavaScript 代码执行 DOM 操作:** 事件监听器中的 JavaScript 代码可能会调用 DOM API 来修改页面结构，例如 `appendChild`, `removeChild`, `insertBefore`, 设置 `innerHTML` 等。
4. **Blink 引擎调用 C++ 代码:** JavaScript 引擎会将这些 DOM 操作转换为对 Blink 引擎 C++ 代码的调用。对于 `ContainerNode` 相关的操作，会调用 `container_node.cc` 中的相应方法。
5. **代码执行到 `ContainerNode` 中的方法:** 例如，如果 JavaScript 调用 `element.appendChild(newChild)`，执行流会最终到达 `ContainerNode::AppendChild` 方法。

**调试线索:**

* **断点:** 在 `ContainerNode::AppendChild`, `ContainerNode::RemoveChild` 等方法中设置断点，可以观察代码执行流程和参数。
* **DOM 断点:**  在 Chrome 开发者工具中，可以在特定节点的子树修改、节点移除等事件上设置断点，当这些事件发生时，调试器会自动暂停，可以查看调用堆栈，了解是谁触发了这些 DOM 操作。
* **Performance 面板:**  查看 Timeline 或 Performance 面板，可以分析 JavaScript 执行和渲染过程中的性能瓶颈，特别是与 DOM 操作相关的部分。
* **审查 JavaScript 代码:** 仔细检查可能修改 DOM 结构的 JavaScript 代码，特别是事件处理程序和异步操作中的代码。

希望以上分析能够帮助你更好地理解 `blink/renderer/core/dom/container_node.cc` 的功能。

### 提示词
```
这是目录为blink/renderer/core/dom/container_node.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
oved()| must be run after |ChildFrameDisconnector|, because
  // |ChildFrameDisconnector| may remove the node, resulting in an invalid
  // state.
  ScriptForbiddenScope script_forbidden_scope;
  EventDispatchForbiddenScope assert_no_event_dispatch;
  // e.g. mutation event listener can create a new range.
  GetDocument().NodeWillBeRemoved(child);

  if (auto* child_element = DynamicTo<Element>(child)) {
    if (auto* context = child_element->GetDisplayLockContext())
      context->NotifyWillDisconnect();
  }
}

void ContainerNode::WillRemoveChildren() {
  NodeVector children;
  GetChildNodes(*this, children);

  ChildListMutationScope mutation(*this);
  for (const auto& node : children) {
    DCHECK(node);
    Node& child = *node;
    mutation.WillRemoveChild(child);
    child.NotifyMutationObserversNodeWillDetach();
    DispatchChildRemovalEvents(child);
  }

  // Only disconnect subframes in the non-state-preserving-atomic-move case,
  // i.e., the traditional case where we intend to *fully* remove a node from
  // the tree, instead of atomically re-inserting it.
  if (!GetDocument().StatePreservingAtomicMoveInProgress()) {
    ChildFrameDisconnector(
        *this, ChildFrameDisconnector::DisconnectReason::kDisconnectSelf)
        .Disconnect(ChildFrameDisconnector::kDescendantsOnly);
  }
}

LayoutBox* ContainerNode::GetLayoutBoxForScrolling() const {
  return GetLayoutBox();
}

bool ContainerNode::IsReadingFlowContainer() const {
  return GetLayoutBox() ? GetLayoutBox()->IsReadingFlowContainer() : false;
}

void ContainerNode::Trace(Visitor* visitor) const {
  visitor->Trace(first_child_);
  visitor->Trace(last_child_);
  Node::Trace(visitor);
}

static bool ShouldMergeCombinedTextAfterRemoval(const Node& old_child) {
  DCHECK(!old_child.parentNode()->GetForceReattachLayoutTree());

  auto* const layout_object = old_child.GetLayoutObject();
  if (!layout_object)
    return false;

  // Request to merge previous and next |LayoutTextCombine| of |child|.
  // See http:://crbug.com/1227066
  auto* const previous_sibling = layout_object->PreviousSibling();
  if (!previous_sibling)
    return false;
  auto* const next_sibling = layout_object->NextSibling();
  if (!next_sibling)
    return false;
  if (IsA<LayoutTextCombine>(previous_sibling) &&
      IsA<LayoutTextCombine>(next_sibling)) [[unlikely]] {
    return true;
  }

  // Request to merge combined texts in anonymous block.
  // See http://crbug.com/1233432
  if (!previous_sibling->IsAnonymousBlock() ||
      !next_sibling->IsAnonymousBlock())
    return false;

  if (IsA<LayoutTextCombine>(previous_sibling->SlowLastChild()) &&
      IsA<LayoutTextCombine>(next_sibling->SlowFirstChild())) [[unlikely]] {
    return true;
  }
  return false;
}

Node* ContainerNode::RemoveChild(Node* old_child,
                                 ExceptionState& exception_state) {
  // NotFoundError: Raised if oldChild is not a child of this node.
  // FIXME: We should never really get PseudoElements in here, but editing will
  // sometimes attempt to remove them still. We should fix that and enable this
  // DCHECK.  DCHECK(!oldChild->isPseudoElement())
  if (!old_child || old_child->parentNode() != this ||
      old_child->IsPseudoElement()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "The node to be removed is not a child of this node.");
    return nullptr;
  }

  Node* child = old_child;

  if (!GetDocument().StatePreservingAtomicMoveInProgress()) {
    GetDocument().RemoveFocusedElementOfSubtree(*child);
  }

  // Events fired when blurring currently focused node might have moved this
  // child into a different parent.
  if (child->parentNode() != this) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "The node to be removed is no longer a "
        "child of this node. Perhaps it was moved "
        "in a 'blur' event handler?");
    return nullptr;
  }

  WillRemoveChild(*child);

  // TODO(crbug.com/927646): |WillRemoveChild()| may dispatch events that set
  // focus to a node that will be detached, leaving behind a detached focused
  // node. Fix it.

  // Mutation events might have moved this child into a different parent.
  if (child->parentNode() != this) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "The node to be removed is no longer a "
        "child of this node. Perhaps it was moved "
        "in response to a mutation?");
    return nullptr;
  }

  if (!GetForceReattachLayoutTree() &&
      ShouldMergeCombinedTextAfterRemoval(*child)) [[unlikely]] {
    SetForceReattachLayoutTree();
  }

  {
    HTMLFrameOwnerElement::PluginDisposeSuspendScope suspend_plugin_dispose;
    TreeOrderedMap::RemoveScope tree_remove_scope;
    StyleEngine& engine = GetDocument().GetStyleEngine();
    StyleEngine::DetachLayoutTreeScope detach_scope(engine);
    Node* prev = child->previousSibling();
    Node* next = child->nextSibling();
    {
      SlotAssignmentRecalcForbiddenScope forbid_slot_recalc(GetDocument());
      StyleEngine::DOMRemovalScope style_scope(engine);
      RemoveBetween(prev, next, *child);
      NotifyNodeRemoved(*child);
    }
    ChildrenChanged(ChildrenChange::ForRemoval(*child, prev, next,
                                               ChildrenChangeSource::kAPI));
  }
  DispatchSubtreeModifiedEvent();
  return child;
}

Node* ContainerNode::RemoveChild(Node* old_child) {
  return RemoveChild(old_child, ASSERT_NO_EXCEPTION);
}

void ContainerNode::RemoveBetween(Node* previous_child,
                                  Node* next_child,
                                  Node& old_child) {
  EventDispatchForbiddenScope assert_no_event_dispatch;

  DCHECK_EQ(old_child.parentNode(), this);

  if (InActiveDocument() &&
      !GetDocument().StatePreservingAtomicMoveInProgress()) {
    old_child.DetachLayoutTree();
  }

  if (next_child)
    next_child->SetPreviousSibling(previous_child);
  if (previous_child)
    previous_child->SetNextSibling(next_child);
  if (first_child_ == &old_child)
    SetFirstChild(next_child);
  if (last_child_ == &old_child)
    SetLastChild(previous_child);

  old_child.SetPreviousSibling(nullptr);
  old_child.SetNextSibling(nullptr);
  old_child.SetParentOrShadowHostNode(nullptr);

  GetDocument().AdoptIfNeeded(old_child);
}

void ContainerNode::ParserRemoveChild(Node& old_child) {
  DCHECK_EQ(old_child.parentNode(), this);
  DCHECK(!old_child.IsDocumentFragment());

  // This may cause arbitrary Javascript execution via onunload handlers.
  CHECK(!GetDocument().StatePreservingAtomicMoveInProgress());
  if (old_child.ConnectedSubframeCount()) {
    ChildFrameDisconnector(
        old_child, ChildFrameDisconnector::DisconnectReason::kDisconnectSelf)
        .Disconnect();
  }
  if (old_child.parentNode() != this)
    return;

  ChildListMutationScope(*this).WillRemoveChild(old_child);
  old_child.NotifyMutationObserversNodeWillDetach();

  HTMLFrameOwnerElement::PluginDisposeSuspendScope suspend_plugin_dispose;
  TreeOrderedMap::RemoveScope tree_remove_scope;
  StyleEngine& engine = GetDocument().GetStyleEngine();
  StyleEngine::DetachLayoutTreeScope detach_scope(engine);

  Node* prev = old_child.previousSibling();
  Node* next = old_child.nextSibling();
  {
    StyleEngine::DOMRemovalScope style_scope(engine);
    RemoveBetween(prev, next, old_child);
    NotifyNodeRemoved(old_child);
  }
  ChildrenChanged(ChildrenChange::ForRemoval(old_child, prev, next,
                                             ChildrenChangeSource::kParser));
}

// This differs from other remove functions because it forcibly removes all the
// children, regardless of read-only status or event exceptions, e.g.
void ContainerNode::RemoveChildren(SubtreeModificationAction action) {
  if (!first_child_)
    return;

  // Do any prep work needed before actually starting to detach
  // and remove... e.g. stop loading frames, fire unload events.
  WillRemoveChildren();

  {
    // Removing focus can cause frames to load, either via events (focusout,
    // blur) or widget updates (e.g., for <embed>).
    SubframeLoadingDisabler disabler(*this);

    // Exclude this node when looking for removed focusedElement since only
    // children will be removed.
    // This must be later than willRemoveChildren, which might change focus
    // state of a child.
    GetDocument().RemoveFocusedElementOfSubtree(*this, true);

    // Removing a node from a selection can cause widget updates.
    GetDocument().NodeChildrenWillBeRemoved(*this);
  }

  HeapVector<Member<Node>> removed_nodes;
  const bool children_changed = ChildrenChangedAllChildrenRemovedNeedsList();
  {
    HTMLFrameOwnerElement::PluginDisposeSuspendScope suspend_plugin_dispose;
    TreeOrderedMap::RemoveScope tree_remove_scope;
    StyleEngine& engine = GetDocument().GetStyleEngine();
    StyleEngine::DetachLayoutTreeScope detach_scope(engine);
    bool has_element_child = false;
    {
      SlotAssignmentRecalcForbiddenScope forbid_slot_recalc(GetDocument());
      StyleEngine::DOMRemovalScope style_scope(engine);
      EventDispatchForbiddenScope assert_no_event_dispatch;
      ScriptForbiddenScope forbid_script;

      while (Node* child = first_child_) {
        if (child->IsElementNode()) {
          has_element_child = true;
        }
        RemoveBetween(nullptr, child->nextSibling(), *child);
        NotifyNodeRemoved(*child);
        if (children_changed)
          removed_nodes.push_back(child);
      }
    }

    ChildrenChange change = {
        .type = ChildrenChangeType::kAllChildrenRemoved,
        .by_parser = ChildrenChangeSource::kAPI,
        .affects_elements = has_element_child
                                ? ChildrenChangeAffectsElements::kYes
                                : ChildrenChangeAffectsElements::kNo,
        .removed_nodes = std::move(removed_nodes)};
    ChildrenChanged(change);
  }

  if (action == kDispatchSubtreeModifiedEvent)
    DispatchSubtreeModifiedEvent();
}

void ContainerNode::AppendChildren(const VectorOf<Node>& new_children,
                                   ExceptionState& exception_state) {
  if (!EnsurePreInsertionValidity(/*new_child*/ nullptr, &new_children,
                                  /*next*/ nullptr, /*old_child*/ nullptr,
                                  exception_state)) {
    return;
  }

  if (new_children.size() == 1u) {
    // If there's exactly one child then Node::ConvertNodeUnionsIntoNodes
    // didn't remove it from the old parent.
    Node* new_child = new_children[0];
    DOMTreeMutationDetector detector(*new_child, *this);
    new_child->remove(exception_state);
    if (exception_state.HadException()) {
      return;
    }
    if (!detector.NeedsRecheck() &&
        !RecheckNodeInsertionStructuralPrereq(new_children, nullptr,
                                              exception_state)) {
      return;
    }
  }

  NodeVector post_insertion_notification_targets;
  {
    SlotAssignmentRecalcForbiddenScope forbid_slot_recalc(GetDocument());
    ChildListMutationScope mutation(*this);
    InsertNodeVector(new_children, nullptr, AdoptAndAppendChild(),
                     post_insertion_notification_targets);
  }
  DidInsertNodeVector(new_children, nullptr,
                      post_insertion_notification_targets);
}

Node* ContainerNode::AppendChild(Node* new_child,
                                 ExceptionState& exception_state) {
  DCHECK(new_child);
  // Make sure adding the new child is ok
  if (!EnsurePreInsertionValidity(new_child, /*new_children*/ nullptr,
                                  /*next*/ nullptr, /*old_child*/ nullptr,
                                  exception_state)) {
    return new_child;
  }

  NodeVector targets;
  DOMTreeMutationDetector detector(*new_child, *this);
  if (!CollectChildrenAndRemoveFromOldParent(*new_child, targets,
                                             exception_state))
    return new_child;
  if (!detector.NeedsRecheck()) {
    if (!RecheckNodeInsertionStructuralPrereq(targets, nullptr,
                                              exception_state))
      return new_child;
  }

  NodeVector post_insertion_notification_targets;
  {
    SlotAssignmentRecalcForbiddenScope forbid_slot_recalc(GetDocument());
    ChildListMutationScope mutation(*this);
    InsertNodeVector(targets, nullptr, AdoptAndAppendChild(),
                     post_insertion_notification_targets);
  }
  DidInsertNodeVector(targets, nullptr, post_insertion_notification_targets);
  return new_child;
}

Node* ContainerNode::AppendChild(Node* new_child) {
  return AppendChild(new_child, ASSERT_NO_EXCEPTION);
}

void ContainerNode::ParserAppendChild(Node* new_child) {
  DCHECK(new_child);
  DCHECK(!new_child->IsDocumentFragment());
  DCHECK(!IsA<HTMLTemplateElement>(this));

  RUNTIME_CALL_TIMER_SCOPE(GetDocument().GetAgent().isolate(),
                           RuntimeCallStats::CounterId::kParserAppendChild);

  if (!CheckParserAcceptChild(*new_child))
    return;

  // FIXME: parserRemoveChild can run script which could then insert the
  // newChild back into the page. Loop until the child is actually removed.
  // See: fast/parser/execute-script-during-adoption-agency-removal.html
  while (ContainerNode* parent = new_child->parentNode())
    parent->ParserRemoveChild(*new_child);

  if (GetDocument() != new_child->GetDocument())
    GetDocument().adoptNode(new_child, ASSERT_NO_EXCEPTION);

  {
    EventDispatchForbiddenScope assert_no_event_dispatch;
    ScriptForbiddenScope forbid_script;

    AdoptAndAppendChild()(*this, *new_child, nullptr);
    DCHECK_EQ(new_child->ConnectedSubframeCount(), 0u);
    ChildListMutationScope(*this).ChildAdded(*new_child);
  }

  NotifyNodeInserted(*new_child, ChildrenChangeSource::kParser);
}

void ContainerNode::ParserAppendChildInDocumentFragment(Node* new_child) {
  DCHECK(new_child);
  DCHECK(CheckParserAcceptChild(*new_child));
  DCHECK(!new_child->IsDocumentFragment());
  DCHECK(!IsA<HTMLTemplateElement>(this));
  DCHECK_EQ(new_child->GetDocument(), GetDocument());
  DCHECK_EQ(&new_child->GetTreeScope(), &GetTreeScope());
  DCHECK_EQ(new_child->parentNode(), nullptr);
  EventDispatchForbiddenScope assert_no_event_dispatch;
  ScriptForbiddenScope forbid_script;
  AppendChildCommon(*new_child);
  DCHECK_EQ(new_child->ConnectedSubframeCount(), 0u);
  // TODO(sky): This has to happen for every add. It seems like it should be
  // better factored.
  ChildListMutationScope(*this).ChildAdded(*new_child);
  probe::DidInsertDOMNode(this);
}

void ContainerNode::ParserFinishedBuildingDocumentFragment() {
  EventDispatchForbiddenScope assert_no_event_dispatch;
  ScriptForbiddenScope forbid_script;
  const bool may_contain_shadow_roots = GetDocument().MayContainShadowRoots();

  const ChildrenChange change =
      ChildrenChange::ForFinishingBuildingDocumentFragmentTree();
  for (Node& node : NodeTraversal::DescendantsOf(*this)) {
    NotifyNodeAtEndOfBuildingFragmentTree(node, change,
                                          may_contain_shadow_roots);
  }

  if (GetDocument().ShouldInvalidateNodeListCaches(nullptr)) {
    GetDocument().InvalidateNodeListCaches(nullptr);
  }
}

void ContainerNode::NotifyNodeAtEndOfBuildingFragmentTree(
    Node& node,
    const ChildrenChange& change,
    bool may_contain_shadow_roots) {
  // Fast path parser only creates disconnected nodes.
  DCHECK(!node.isConnected());

  if (may_contain_shadow_roots) {
    node.CheckSlotChangeAfterInserted();
  }

  // As an optimization we don't notify leaf nodes when when inserting
  // into detached subtrees that are not in a shadow tree, unless the
  // node has DOM Parts attached.
  if (!node.IsContainerNode() && !IsInShadowTree() && !node.GetDOMParts()) {
    return;
  }

  // NotifyNodeInserted() keeps a list of nodes to call
  // DidNotifySubtreeInsertionsToDocument() on if InsertedInto() returns
  // kInsertionShouldCallDidNotifySubtreeInsertions, but only if the node
  // is connected. None of the nodes are connected at this point, so it's
  // not needed here.
  node.InsertedInto(*this);

  if (ShadowRoot* shadow_root = node.GetShadowRoot()) {
    for (Node& shadow_node :
         NodeTraversal::InclusiveDescendantsOf(*shadow_root)) {
      NotifyNodeAtEndOfBuildingFragmentTree(shadow_node, change,
                                            may_contain_shadow_roots);
    }
  }

  // No node-lists should have been created at this (otherwise
  // InvalidateNodeListCaches() would need to be called).
  DCHECK(!RareData() || !RareData()->NodeLists());

  if (node.IsContainerNode()) {
    DynamicTo<ContainerNode>(node)->ChildrenChanged(change);
  }
}

DISABLE_CFI_PERF
void ContainerNode::NotifyNodeInserted(Node& root,
                                       ChildrenChangeSource source) {
#if DCHECK_IS_ON()
  DCHECK(!EventDispatchForbiddenScope::IsEventDispatchForbidden());
#endif
  DCHECK(!root.IsShadowRoot());

  if (GetDocument().MayContainShadowRoots())
    root.CheckSlotChangeAfterInserted();

  probe::DidInsertDOMNode(&root);

  NodeVector post_insertion_notification_targets;
  NotifyNodeInsertedInternal(root, post_insertion_notification_targets);

  ChildrenChanged(ChildrenChange::ForInsertion(root, root.previousSibling(),
                                               root.nextSibling(), source));

  for (const auto& target_node : post_insertion_notification_targets) {
    if (target_node->isConnected())
      target_node->DidNotifySubtreeInsertionsToDocument();
  }
}

DISABLE_CFI_PERF
void ContainerNode::NotifyNodeInsertedInternal(
    Node& root,
    NodeVector& post_insertion_notification_targets) {
  const bool is_state_preserving_atomic_insert =
      GetDocument().StatePreservingAtomicMoveInProgress();
  EventDispatchForbiddenScope assert_no_event_dispatch;
  ScriptForbiddenScope forbid_script;

  for (Node& node : NodeTraversal::InclusiveDescendantsOf(root)) {
    // As an optimization we don't notify leaf nodes when inserting into
    // detached subtrees that are not in a shadow tree, unless the node has DOM
    // Parts attached.
    if (!isConnected() && !IsInShadowTree() && !node.IsContainerNode() &&
        !node.GetDOMParts()) {
      continue;
    }

    // Only tag the target as one that we need to call post-insertion steps on
    // if it is being *fully* inserted, and not re-inserted as part of a
    // state-preserving atomic move. That's because the post-insertion steps can
    // run script and modify the frame tree, neither of which are allowed in a
    // state-preserving atomic move.
    if (Node::kInsertionShouldCallDidNotifySubtreeInsertions ==
            node.InsertedInto(*this) &&
        !is_state_preserving_atomic_insert) {
      post_insertion_notification_targets.push_back(&node);
    }
    if (ShadowRoot* shadow_root = node.GetShadowRoot()) {
      NotifyNodeInsertedInternal(*shadow_root,
                                 post_insertion_notification_targets);
    }
  }
}

void ContainerNode::NotifyNodeRemoved(Node& root) {
  ScriptForbiddenScope forbid_script;
  EventDispatchForbiddenScope assert_no_event_dispatch;

  for (Node& node : NodeTraversal::InclusiveDescendantsOf(root)) {
    // As an optimization we skip notifying Text nodes and other leaf nodes
    // of removal when they're not in the Document tree, not in a shadow root,
    // and don't have DOM Parts, since the virtual call to removedFrom is not
    // needed.
    if (!node.IsContainerNode() && !node.IsInTreeScope() &&
        !node.GetDOMParts()) {
      continue;
    }
    node.RemovedFrom(*this);
    if (ShadowRoot* shadow_root = node.GetShadowRoot())
      NotifyNodeRemoved(*shadow_root);
  }
}

void ContainerNode::RemovedFrom(ContainerNode& insertion_point) {
  if (isConnected()) {
    if (NeedsStyleInvalidation()) {
      GetDocument()
          .GetStyleEngine()
          .GetPendingNodeInvalidations()
          .ClearInvalidation(*this);
      ClearNeedsStyleInvalidation();
    }
    ClearChildNeedsStyleInvalidation();
  }
  Node::RemovedFrom(insertion_point);
}

DISABLE_CFI_PERF
void ContainerNode::AttachLayoutTree(AttachContext& context) {
  for (Node* child = firstChild(); child; child = child->nextSibling())
    child->AttachLayoutTree(context);
  Node::AttachLayoutTree(context);
  ClearChildNeedsReattachLayoutTree();
}

void ContainerNode::DetachLayoutTree(bool performing_reattach) {
  for (Node* child = firstChild(); child; child = child->nextSibling())
    child->DetachLayoutTree(performing_reattach);
  Node::DetachLayoutTree(performing_reattach);
}

void ContainerNode::ChildrenChanged(const ChildrenChange& change) {
  GetDocument().IncDOMTreeVersion();
  GetDocument().NotifyChangeChildren(*this, change);
  if (change.type ==
      ChildrenChangeType::kFinishedBuildingDocumentFragmentTree) {
    // The rest of this is not necessary when building a DocumentFragment.
    return;
  }

  InvalidateNodeListCachesInAncestors(nullptr, nullptr, &change);
  if (change.IsChildRemoval() ||
      change.type == ChildrenChangeType::kAllChildrenRemoved) {
    GetDocument().GetStyleEngine().ChildrenRemoved(*this);
    return;
  }
  if (!change.IsChildInsertion())
    return;
  Node* inserted_node = change.sibling_changed;
  if (inserted_node->IsContainerNode() || inserted_node->IsTextNode())
    inserted_node->ClearFlatTreeNodeDataIfHostChanged(*this);
  if (!InActiveDocument())
    return;
  if (Element* element = DynamicTo<Element>(this)) {
    if (GetDocument().StatePreservingAtomicMoveInProgress()) {
      inserted_node->FlatTreeParentChanged();
    }
    if (!element->GetComputedStyle()) {
      // There is no need to mark for style recalc if the parent element does
      // not already have a ComputedStyle. For instance if we insert nodes into
      // a display:none subtree. If this ContainerNode gets a ComputedStyle
      // during the next style recalc, we will traverse into the inserted
      // children since the ComputedStyle goes from null to non-null.
      return;
    }
  }
  if (inserted_node->IsContainerNode() || inserted_node->IsTextNode())
    inserted_node->SetStyleChangeOnInsertion();
}

bool ContainerNode::ChildrenChangedAllChildrenRemovedNeedsList() const {
  return false;
}

void ContainerNode::CloneChildNodesFrom(const ContainerNode& node,
                                        NodeCloningData& data) {
  CHECK(data.Has(CloneOption::kIncludeDescendants));
  for (const Node& child : NodeTraversal::ChildrenOf(node)) {
    child.Clone(GetDocument(), data, this);
  }
}

PhysicalRect ContainerNode::BoundingBox() const {
  if (!GetLayoutObject())
    return PhysicalRect();
  return GetLayoutObject()->AbsoluteBoundingBoxRectHandlingEmptyInline();
}

HTMLCollection* ContainerNode::children() {
  return EnsureCachedCollection<HTMLCollection>(kNodeChildren);
}

Element* ContainerNode::firstElementChild() {
  return ElementTraversal::FirstChild(*this);
}

Element* ContainerNode::lastElementChild() {
  return ElementTraversal::LastChild(*this);
}

unsigned ContainerNode::childElementCount() {
  unsigned count = 0;
  for (Element* child = ElementTraversal::FirstChild(*this); child;
       child = ElementTraversal::NextSibling(*child)) {
    ++count;
  }
  return count;
}

Element* ContainerNode::querySelector(const AtomicString& selectors,
                                      ExceptionState& exception_state) {
  return QuerySelector(selectors, exception_state);
}

StaticElementList* ContainerNode::querySelectorAll(
    const AtomicString& selectors,
    ExceptionState& exception_state) {
  return QuerySelectorAll(selectors, exception_state);
}

unsigned ContainerNode::CountChildren() const {
  unsigned count = 0;
  for (Node* node = firstChild(); node; node = node->nextSibling())
    count++;
  return count;
}

bool ContainerNode::HasOnlyText() const {
  bool has_text = false;
  for (Node* child = firstChild(); child; child = child->nextSibling()) {
    switch (child->getNodeType()) {
      case kTextNode:
      case kCdataSectionNode:
        has_text = has_text || !To<Text>(child)->data().empty();
        break;
      case kCommentNode:
        // Ignore comments.
        break;
      default:
        return false;
    }
  }
  return has_text;
}

Element* ContainerNode::QuerySelector(const AtomicString& selectors,
                                      ExceptionState& exception_state) {
  SelectorQuery* selector_query = GetDocument().GetSelectorQueryCache().Add(
      selectors, GetDocument(), exception_state);
  if (!selector_query)
    return nullptr;
  return selector_query->QueryFirst(*this);
}

Element* ContainerNode::QuerySelector(const AtomicString& selectors) {
  return QuerySelector(selectors, ASSERT_NO_EXCEPTION);
}

StaticElementList* ContainerNode::QuerySelectorAll(
    const AtomicString& selectors,
    ExceptionState& exception_state) {
  SelectorQuery* selector_query = GetDocument().GetSelectorQueryCache().Add(
      selectors, GetDocument(), exception_state);
  if (!selector_query)
    return nullptr;
  return selector_query->QueryAll(*this);
}

StaticElementList* ContainerNode::QuerySelectorAll(
    const AtomicString& selectors) {
  return QuerySelectorAll(selectors, ASSERT_NO_EXCEPTION);
}

static void DispatchChildInsertionEvents(Node& child) {
  Document& document = child.GetDocument();
  if (child.IsInShadowTree() || document.ShouldSuppressMutationEvents()) {
    return;
  }

#if DCHECK_IS_ON()
  DCHECK(!EventDispatchForbiddenScope::IsEventDispatchForbidden());
#endif

  Node* c = &child;

  if (c->parentNode() &&
      document.HasListenerType(Document::kDOMNodeInsertedListener)) {
    c->DispatchScopedEvent(
        *MutationEvent::Create(event_type_names::kDOMNodeInserted,
                               Event::Bubbles::kYes, c->parentNode()));
  }

  // dispatch the DOMNodeInsertedIntoDocument event to all descendants
  if (c->isConnected() && document.HasListenerType(
                              Document::kDOMNodeInsertedIntoDocumentListener)) {
    for (; c; c = NodeTraversal::Next(*c, &child)) {
      c->DispatchScopedEvent(*MutationEvent::Create(
          event_type_names::kDOMNodeInsertedIntoDocument, Event::Bubbles::kNo));
    }
  }
}

static void DispatchChildRemovalEvents(Node& child) {
  probe::WillRemoveDOMNode(&child);

  Document& document = child.GetDocument();
  if (child.IsInShadowTree() || document.ShouldSuppressMutationEvents()) {
    return;
  }

#if DCHECK_IS_ON()
  DCHECK(!EventDispatchForbiddenScope::IsEventDispatchForbidden());
#endif

  Node* c = &child;

  // Dispatch pre-removal mutation events.
  if (c->parentNode() &&
      document.HasListenerType(Document::kDOMNodeRemovedListener)) {
    NodeChildRemovalTracker scope(child);
    c->DispatchScopedEvent(
        *MutationEvent::Create(event_type_names::kDOMNodeRemoved,
                               Event::Bubbles::kYes, c->parentNode()));
  }

  // Dispatch the DOMNodeRemovedFromDocument event to all descendants.
  if (c->isConnected() &&
      document.HasListenerType(Document::kDOMNodeRemovedFromDocumentListener)) {
    NodeChildRemovalTracker scope(child);
    for (; c; c = NodeTraversal::Next(*c, &child)) {
      c->DispatchScopedEvent(*MutationEvent::Create(
          event_type_names::kDOMNodeRemovedFromDocument, Event::Bubbles::kNo));
    }
  }
}

void ContainerNode::SetRestyleFlag(DynamicRestyleFlags mask) {
  DCHECK(IsElementNode() || IsShadowRoot());
  EnsureRareData().SetRestyleFlag(mask);
}

void ContainerNode::RecalcDescendantStyles(
    const StyleRecalcChange change,
    const StyleRecalcContext& style_recalc_context) {
  DCHECK(GetDocument().InStyleRecalc());
  DCHECK(!NeedsStyleRecalc());

  for (Node* child = firstChild(); child; child = child->nextSibling()) {
    if (!change.TraverseChild(*child)) {
      continue;
    }
    if (auto* child_text_node = DynamicTo<Text>(child))
      child_text_node->RecalcTextStyle(change);

    if (auto* child_element = DynamicTo<Element>(child)) {
      child_element->RecalcStyle(change, style_recalc_context);
    }
  }
}

void ContainerNode::RebuildLayoutTreeForChild(
    Node* child,
    WhitespaceAttacher& whitespace_attacher) {
  if (auto* child_text_node = DynamicTo<Text>(child)) {
    if (child->NeedsReattachLayoutTree())
      child_text_node->RebuildTextLayoutTree(whitespace_attacher);
    else
      whitespace_attacher.DidVisitText(child_text_node);
    return;
  }

  auto* element = DynamicTo<Element>(child);
  if (!element)
    return;

  if (element->NeedsRebuildLayoutTree(whitespace_attacher))
    element->RebuildLayoutTree(whitespace_attacher);
  else
    whitespace_attacher.DidVisitElement(element);
}

void ContainerNode::RebuildChildrenLayoutTrees(
    WhitespaceAttacher& whitespace_attacher) {
  DCHECK(!NeedsReattachLayoutTree());

  if (IsActiveSlot()) {
    if (auto* slot = DynamicTo<HTMLSlotElement>(this)) {
      slot->RebuildDistributedChildrenLayoutTrees(whitespace_attacher);
    }
    return;
  }

  // This loop is deliberately backwards because we use insertBefore in the
  // layout tree, and want to avoid a potentially n^2 loop to find the insertion
  // point while building the layout tree.  Having us start from the last child
  // and work our way back means in the common case, we'll find the insertion
  // point in O(1) time.  See crbug.com/288225
  for (Node* child = lastChild(); child; child = child->previousSibling())
    RebuildLayoutTreeForChild(child, whitespace_attacher);
}

void ContainerNode::CheckForSiblingStyleChanges(SiblingCheckType change_type,
                                                Element* changed_element,
                                                Node* node_before_change,
                                                Node* node_after_change) {
  if (!InActiveDocument() || GetDocument().HasPendingForcedStyleRecalc() ||
      GetStyleChangeType() == kSubtreeStyleChange)
    return;

  if (!HasRestyleFlag(DynamicRestyleFlags::kChildrenAffectedByStructuralRules))
    return;

  auto* element_after_change = DynamicTo<Element>(node_after_change);
  if (node_after_change && !element_after_change)
    element_after_change = ElementTraversal::NextSibling(*node_after_change);
  auto* element_before_change = DynamicTo<Element>(node_before_change);
  if (node_before_change && !element_before_change) {
    element_before_change =
        ElementTraversal::PreviousSibling(*node_before_change);
  }

  // TODO(futhark@chromium.org): move this code into StyleEngine and collect the
  // various invalidation sets into a single InvalidationLists object and
  // schedule with a single scheduleInvalidationSetsForNode for efficiency.

  // Forward positional selectors include :nth-child, :nth-of-type,
  // :first-of-type, and only-of-type. Backward positional selectors include
  // :nth-last-child, :nth-last-of-type, :last-of-type, and :only-of-type.
  if ((ChildrenAffectedByForwardPositionalRules() && element_after_change) ||
      (ChildrenAffectedByBackwardPositionalRules() && element_before_change)) {
    GetDocument().GetStyleEngine().ScheduleNthPseudoInvalidations(*this);
  }

  if (ChildrenAffectedByFirstChildRules() && !element_before_change &&
      element_after_change &&
      element_after_change->AffectedByFirstChildRules()) {
    DCHECK_NE(change_type, kFinishedParsingChildren);
    element_after_change->PseudoStateChanged(CSSSelector::kPseudoFirstChild);
    element_after_change->PseudoStateChanged(CSSSelector::kPseudoOnlyChild);
  }

  if (ChildrenAffectedByLastChildRules() && !element_after_change &&
      element_before_change &&
      element_before_change->AffectedByLastChildRules()) {
    element_before_change->PseudoStateChanged(CSSSelector::kPseudoLastChild);
    element_before_change->PseudoStateChanged(CSSSelector::kPseudoOnlyChild);
  }

  // For ~ and + combinators, succeeding siblings may need style invalidation
  // after an element is inserted or removed.

  if (!element_after_change)
    return;

  if (!ChildrenAffectedByIndirectAdjacentRules() &&
      !ChildrenAffectedByDirectAdjacentRules())
    return;

  if (change_type == kSiblingElementInserted) {
    GetDocument().GetStyleEngine().ScheduleInvalidationsForInsertedSibling(
        element_before_change, *changed_element);
    return;
  }

  DCHECK(change_type == kSiblingElementRemoved);
  GetDocument().GetStyleEngine().ScheduleInvalidationsForRemovedSibling(
      element_before_change, *changed_element, *element_after_change);
}

void ContainerNode::InvalidateNodeListCachesInAncestors(
    const QualifiedName* attr_name,
    Element* attribute_owner_element,
    const ChildrenChange* change) {
  // This is a performance optimization, NodeList cache invalidation is
  // not necessary for a text c
```