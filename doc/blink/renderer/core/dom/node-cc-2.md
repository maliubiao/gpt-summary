Response:
The user wants a summary of the functionalities present in the provided C++ code snippet from `blink/renderer/core/dom/node.cc`. I need to identify the key operations and concepts illustrated by the code. Specifically, I should look for:

1. **Core DOM Node operations:**  Things like finding common ancestors, attaching/detaching from the layout tree, comparing document positions, handling insertion and removal, and getting/setting text content.
2. **Relationships with web technologies:** How these operations relate to JavaScript, HTML, and CSS. I should provide examples of how these functionalities are exposed or used in the context of these technologies.
3. **Logic and reasoning:** If the code performs comparisons or conditional logic, I should try to infer the purpose and provide example inputs and outputs to illustrate the logic.
4. **Potential errors:**  Identify scenarios where incorrect usage or external factors could lead to unexpected behavior or errors related to this code.
5. **Debugging context:** Explain how a user's action might trigger execution within this code, offering insights for debugging.
6. **Overall functionality:** Condense the identified features into a concise summary as requested in the prompt.

**Plan:**

1. **Read through the code:**  Identify function definitions and their core logic.
2. **Categorize functionalities:** Group the functions based on their purpose (e.g., tree manipulation, layout, comparison).
3. **Relate to web technologies:** For each category, explain how it's connected to JavaScript, HTML, or CSS, providing concrete examples.
4. **Analyze logic:**  For functions with conditional logic, devise simple input scenarios and the expected output.
5. **Identify potential errors:** Think about common mistakes or situations that could interact negatively with these functions.
6. **Trace user interaction:**  Imagine common user actions that could lead to these functions being called.
7. **Synthesize the summary:** Combine the identified functionalities into a concise overview.
这是`blink/renderer/core/dom/node.cc`文件的第三部分，主要包含以下功能：

**1. 布局树的重新连接 (Reattaching Layout Tree):**

* **`ReattachLayoutTree(AttachContext& context)`:**  这是一个核心函数，用于将节点重新连接到布局树。它会先 `DetachLayoutTree`，然后再 `AttachLayoutTree`。
    * **假设输入:** 一个需要重新连接的 `Node` 对象和一个 `AttachContext` 对象。
    * **输出:**  该节点及其子树已连接到布局树。
* **`AttachLayoutTree(AttachContext& context)`:**  将节点连接到布局树。会进行一些断言检查，并通知辅助功能对象缓存 (AXObjectCache)。
    * **与 CSS 关系:**  布局树是根据 HTML 结构和 CSS 样式构建的。此函数确保当节点的 CSS 样式发生变化或节点在 DOM 树中移动后，其对应的布局对象能够正确地连接到布局树，从而影响页面的渲染。
    * **举例说明:**  当通过 JavaScript 修改元素的 `style` 属性，或者添加/移除 CSS 类时，可能会触发布局树的重新连接。
* **`DetachLayoutTree(bool performing_reattach)`:**  将节点从布局树中分离。会通知辅助功能对象缓存并销毁布局对象。
    * **与 CSS 关系:** 当一个节点的 CSS 样式导致其不再需要渲染（例如，`display: none;`）或节点从 DOM 树中移除时，会调用此函数将其从布局树中移除。
    * **举例说明:**  当 JavaScript 设置元素的 `display` 属性为 `none` 或使用 `removeChild` 方法移除元素时，会触发布局树的分离。

**2. 强制重新连接布局树 (Forcing Layout Tree Reattachment):**

* **`SetForceReattachLayoutTree()`:**  标记节点需要强制重新连接到布局树。这通常用于确保在某些情况下（例如，节点内容或属性发生重要变化时）即使没有明显的样式变化也进行布局更新。
    * **与 JavaScript, HTML, CSS 关系:**  JavaScript 可以修改节点的属性或内容，这些修改可能需要强制重新连接布局树以确保渲染的正确性。
    * **假设输入:** 一个需要强制重新连接布局树的 `Node` 对象。
    * **输出:**  该节点被标记为需要强制重新连接布局树。
    * **用户或编程常见的使用错误:**  不必要地频繁调用此函数可能会导致性能问题，因为重新连接布局树是一个相对昂贵的操作。

**3. 检查是否需要更新 (Needs Update Checks):**

* **`NeedsWhitespaceChildrenUpdate() const`:** 检查布局对象是否需要更新其空白子节点。
    * **与 HTML 关系:**  HTML 中的空白符处理规则比较复杂，此函数用于判断布局引擎是否需要重新处理节点的空白子节点，例如，当节点的文本内容发生变化时。
* **`NeedsLayoutSubtreeUpdate() const`:** 检查布局对象是否需要更新其子树布局。
    * **与 HTML, CSS 关系:** 当节点的子节点结构或样式发生变化时，可能会需要更新子树布局。

**4. 判断是否可以开始选择 (Can Start Selection):**

* **`CanStartSelection() const`:**  判断是否可以在该节点上开始文本选择。会考虑节点的 `user-select` CSS 属性和是否可编辑。
    * **与 JavaScript, HTML, CSS 关系:**  用户在浏览器中拖动鼠标进行文本选择时，浏览器需要判断起始位置的节点是否允许开始选择。`user-select` CSS 属性（如 `none`）可以阻止用户在该元素上进行选择。
    * **假设输入:**  一个 `Node` 对象。
    * **输出:** `true` 如果可以开始选择，`false` 否则。
    * **用户操作:** 用户尝试在网页上拖动鼠标选择文本。
    * **调试线索:** 如果用户无法在某个元素上选择文本，可以检查该元素的 `user-select` 属性以及其父元素的 `user-select` 属性。

**5. 判断是否为可富文本编辑 (Is Richly Editable):**

* **`IsRichlyEditableForAccessibility() const`:**  判断节点是否为可富文本编辑，用于辅助功能。
    * **与 HTML 关系:**  与带有 `contenteditable` 属性的 HTML 元素相关。

**6. 通知优先级滚动锚点状态改变 (Notify Priority Scroll Anchor Status Changed):**

* **`NotifyPriorityScrollAnchorStatusChanged()`:**  通知布局对象其作为优先级滚动锚点的状态发生了变化。
    * **与 CSS 关系:**  与 CSS 滚动锚点相关的功能。

**7. 插槽相关 (Slot Related):**

* **`IsActiveSlot() const`:** 判断节点是否是一个激活的 `<slot>` 元素。
    * **与 HTML 关系:**  与 Web Components 中的 `<slot>` 元素相关。
* **`SlotName() const`:** 获取可插槽元素的插槽名称。
    * **与 HTML 关系:**  与 Web Components 中的 `<slot>` 元素和带有 `slot` 属性的元素相关。

**8. Shadow DOM 相关 (Shadow DOM Related):**

* **`ParentElementShadowRoot() const`:** 获取父元素的 Shadow Root。
    * **与 JavaScript, HTML 关系:**  与 Shadow DOM 技术相关。JavaScript 可以创建和操作 Shadow DOM。
* **`IsChildOfShadowHost() const`:** 判断节点是否是 Shadow Host 的子节点。
    * **与 JavaScript, HTML 关系:**  与 Shadow DOM 技术相关。
* **`ShadowRootOfParent() const`:** 获取父元素的 Shadow Root。
    * **与 JavaScript, HTML 关系:**  与 Shadow DOM 技术相关。
* **`OwnerShadowHost() const`:** 获取拥有该节点的 Shadow Host 元素。
    * **与 JavaScript, HTML 关系:**  与 Shadow DOM 技术相关。
* **`ContainingShadowRoot() const`:** 获取包含该节点的 Shadow Root。
    * **与 JavaScript, HTML 关系:**  与 Shadow DOM 技术相关。
* **`NonBoundaryShadowTreeRootNode()`:** 获取非边界的 Shadow Tree 根节点。
    * **与 JavaScript, HTML 关系:**  与 Shadow DOM 技术相关。
* **`NonShadowBoundaryParentNode() const`:** 获取非 Shadow Boundary 的父节点。
    * **与 JavaScript, HTML 关系:**  与 Shadow DOM 技术相关。
* **`ParentOrShadowHostElement() const`:** 获取父元素或 Shadow Host 元素。
    * **与 JavaScript, HTML 关系:**  与 Shadow DOM 技术相关。
* **`ParentOrShadowHostOrTemplateHostNode() const`:** 获取父节点、Shadow Host 节点或模板 Host 节点。
    * **与 HTML 关系:**  与 Shadow DOM 和 `<template>` 元素相关。

**9. Tree Scope 相关 (Tree Scope Related):**

* **`OriginatingTreeScope() const`:** 获取原始的 Tree Scope。
    * **与 HTML, SVG 关系:**  用于处理 HTML 和 SVG 元素在不同 Tree Scope 中的情况。

**10. 所有者文档 (Owner Document):**

* **`ownerDocument() const`:** 获取节点的拥有者文档。
    * **与 JavaScript, HTML 关系:**  JavaScript 中可以通过 `node.ownerDocument` 获取节点的文档对象。

**11. 基础 URI (Base URI):**

* **`baseURI() const`:** 获取节点的基础 URI。
    * **与 HTML 关系:**  与 HTML 文档的 `<base>` 元素相关。

**12. 判断节点是否相等 (Is Equal Node):**

* **`isEqualNode(Node* other) const`:**  判断当前节点是否与另一个节点在结构和属性上相等。
    * **与 JavaScript 关系:**  对应 JavaScript 中的 `node.isEqualNode()` 方法。
    * **假设输入:** 两个 `Node` 对象。
    * **输出:** `true` 如果两个节点相等，`false` 否则。

**13. 命名空间相关 (Namespace Related):**

* **`isDefaultNamespace(const AtomicString& namespace_uri_maybe_empty) const`:**  判断给定的命名空间 URI 是否是节点的默认命名空间。
    * **与 HTML, XML 关系:**  与 HTML 和 XML 的命名空间概念相关。
* **`lookupPrefix(const AtomicString& namespace_uri) const`:**  查找给定命名空间 URI 的前缀。
    * **与 HTML, XML 关系:**  与 HTML 和 XML 的命名空间概念相关。
* **`lookupNamespaceURI(const String& specified_prefix) const`:**  查找给定前缀的命名空间 URI。
    * **与 HTML, XML 关系:**  与 HTML 和 XML 的命名空间概念相关。

**14. 文本内容相关 (Text Content Related):**

* **`textContent(bool convert_brs_to_newlines, TextVisitor* visitor, unsigned int max_length) const`:**  获取节点的文本内容，可以选择是否将 `<br>` 转换为换行符。
    * **与 JavaScript, HTML 关系:**  对应 JavaScript 中的 `node.textContent` 属性。
    * **用户操作:** JavaScript 代码读取元素的 `textContent` 属性。
* **`textContentForBinding() const`:**  为 V8 绑定获取文本内容。
    * **与 JavaScript 关系:**  用于 JavaScript 和 C++ 之间的互操作。
* **`setTextContentForBinding(const V8UnionStringOrTrustedScript* value, ExceptionState& exception_state)`:** 为 V8 绑定设置文本内容。
    * **与 JavaScript 关系:**  用于 JavaScript 和 C++ 之间的互操作。
* **`setTextContent(const String& text)`:**  设置节点的文本内容。
    * **与 JavaScript, HTML 关系:**  对应 JavaScript 中的 `node.textContent = value` 操作。
    * **用户操作:** JavaScript 代码设置元素的 `textContent` 属性。
    * **编程常见的使用错误:**  在非容器节点上设置 `textContent` 可能不会产生预期的效果。

**15. 比较文档位置 (Compare Document Position):**

* **`compareDocumentPosition(const Node* other_node, ShadowTreesTreatment treatment) const`:**  比较当前节点与另一个节点在文档中的位置关系。
    * **与 JavaScript 关系:**  对应 JavaScript 中的 `node.compareDocumentPosition()` 方法。
    * **假设输入:** 两个 `Node` 对象和一个 `ShadowTreesTreatment` 枚举值。
    * **输出:**  一个表示两个节点位置关系的位掩码（例如，是否包含，是否在前面，是否断开连接）。
    * **用户操作:**  JavaScript 代码调用 `compareDocumentPosition` 方法来确定两个节点在 DOM 树中的相对位置。

**16. 使外观失效 (Invalidate If Has Effective Appearance):**

* **`InvalidateIfHasEffectiveAppearance() const`:**  如果节点具有有效的外观，则使其失效，触发重新绘制。
    * **与 CSS 关系:** 当节点的样式发生变化，并且这些样式会影响其外观时，需要调用此函数来标记节点需要重新绘制。

**17. 插入和移除通知 (Insertion and Removal Notifications):**

* **`InsertedInto(ContainerNode& insertion_point)`:**  当节点被插入到文档中时调用。
    * **与 JavaScript 关系:**  当 JavaScript 使用 `appendChild`、`insertBefore` 等方法将节点插入到 DOM 树中时触发。
    * **假设输入:** 被插入的 `Node` 对象和插入点 `ContainerNode` 对象。
    * **输出:**  `InsertionNotificationRequest::kInsertionDone`，表示插入完成。
* **`MovedFrom(ContainerNode& old_parent)`:** 当节点从旧的父节点移动时调用（在 `InsertedInto` 之前）。
* **`RemovedFrom(ContainerNode& insertion_point)`:** 当节点从文档中移除时调用。
    * **与 JavaScript 关系:**  当 JavaScript 使用 `removeChild` 等方法从 DOM 树中移除节点时触发。
    * **假设输入:** 被移除的 `Node` 对象和移除前的父节点 `ContainerNode` 对象。

**18. 调试相关 (Debugging Related):**

* **`DebugName() const`:**  返回节点的调试名称，包含标签名、ID 和类名。
* **`ToString() const`:** 返回节点的字符串表示形式，用于调试输出。
* **`ToTreeStringForThis() const`:** 返回包含当前节点的树形字符串表示。
* **`ToFlatTreeStringForThis() const`:** 返回包含当前节点的扁平树形字符串表示。
* **`PrintNodePathTo(std::ostream& stream) const`:**  打印到节点的路径。

**归纳一下它的功能:**

这部分 `Node.cc` 文件主要负责处理 DOM 节点在布局树中的生命周期管理（连接和分离）、确定节点在文档中的位置关系、处理文本内容、处理与 Shadow DOM 和 Web Components 相关的操作，以及提供一些用于调试和判断节点状态的方法。它在 Blink 渲染引擎中扮演着至关重要的角色，连接了 DOM 树的结构和最终的页面渲染。许多用户在浏览器中的操作，例如点击、拖拽、输入文本，以及 JavaScript 对 DOM 的操作，都会间接地触发这里定义的逻辑。

### 提示词
```
这是目录为blink/renderer/core/dom/node.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
(current);
    if (curr_fragment && curr_fragment->IsTemplateContent())
      current =
          static_cast<const TemplateContentDocumentFragment*>(current)->Host();
    else
      current = current->ParentOrShadowHostNode();
  } while (current);
  return false;
}

Node* Node::CommonAncestor(const Node& other,
                           ContainerNode* (*parent)(const Node&)) const {
  if (this == other)
    return const_cast<Node*>(this);
  if (GetDocument() != other.GetDocument())
    return nullptr;
  int this_depth = 0;
  for (const Node* node = this; node; node = parent(*node)) {
    if (node == &other)
      return const_cast<Node*>(node);
    this_depth++;
  }
  int other_depth = 0;
  for (const Node* node = &other; node; node = parent(*node)) {
    if (node == this)
      return const_cast<Node*>(this);
    other_depth++;
  }
  const Node* this_iterator = this;
  const Node* other_iterator = &other;
  if (this_depth > other_depth) {
    for (int i = this_depth; i > other_depth; --i)
      this_iterator = parent(*this_iterator);
  } else if (other_depth > this_depth) {
    for (int i = other_depth; i > this_depth; --i)
      other_iterator = parent(*other_iterator);
  }
  while (this_iterator) {
    if (this_iterator == other_iterator)
      return const_cast<Node*>(this_iterator);
    this_iterator = parent(*this_iterator);
    other_iterator = parent(*other_iterator);
  }
  DCHECK(!other_iterator);
  return nullptr;
}

void Node::ReattachLayoutTree(AttachContext& context) {
  context.performing_reattach = true;
  ReattachHookScope reattach_scope(*this);

  DetachLayoutTree(context.performing_reattach);
  AttachLayoutTree(context);
  DCHECK(!NeedsReattachLayoutTree());
}

void Node::AttachLayoutTree(AttachContext& context) {
  DCHECK(GetDocument().InStyleRecalc() || IsDocumentNode() ||
         GetDocument().GetStyleEngine().InScrollMarkersAttachment());
  DCHECK(!GetDocument().Lifecycle().InDetach());
  DCHECK(!context.performing_reattach ||
         GetDocument().GetStyleEngine().InRebuildLayoutTree());

  LayoutObject* layout_object = GetLayoutObject();
  DCHECK(!layout_object ||
         (layout_object->Style() &&
          (layout_object->Parent() || IsA<LayoutView>(layout_object))));

  ClearNeedsReattachLayoutTree();

  if (AXObjectCache* cache = GetDocument().ExistingAXObjectCache()) {
    cache->NodeIsAttached(this);
  }

  if (context.performing_reattach)
    ReattachHookScope::NotifyAttach(*this);
}

void Node::DetachLayoutTree(bool performing_reattach) {
  // Re-attachment is not generally allowed from PositionTryStyleRecalc, but
  // computing style for display:none pseudo elements will insert a pseudo
  // element, compute the style, and remove it again, which includes a
  // DetachLayoutTree().
  DCHECK(GetDocument().Lifecycle().StateAllowsDetach() ||
         GetDocument().GetStyleEngine().InContainerQueryStyleRecalc() ||
         GetDocument().GetStyleEngine().InScrollMarkersAttachment() ||
         (GetDocument().GetStyleEngine().InPositionTryStyleRecalc() &&
          IsPseudoElement() && !GetLayoutObject()));
  DCHECK(!performing_reattach ||
         GetDocument().GetStyleEngine().InRebuildLayoutTree() ||
         GetDocument().GetStyleEngine().InScrollMarkersAttachment());
  DocumentLifecycle::DetachScope will_detach(GetDocument().Lifecycle());

  if (auto* cache = GetDocument().ExistingAXObjectCache()) {
    cache->RemoveSubtree(this);
  }

  if (performing_reattach) {
    ReattachHookScope::NotifyDetach(*this);
  }

  if (GetLayoutObject()) {
    GetLayoutObject()->DestroyAndCleanupAnonymousWrappers(performing_reattach);
  }
  SetLayoutObject(nullptr);
  if (!performing_reattach) {
    // We are clearing the ComputedStyle for elements, which means we should not
    // need to recalc style. Also, this way we can detect if we need to remove
    // this Node as a StyleRecalcRoot if this detach is because the node is
    // removed from the flat tree. That is necessary because we are not allowed
    // to have a style recalc root outside the flat tree when traversing the
    // flat tree for style recalc
    // (see StyleRecalcRoot::FlatTreePositionChanged()).
    ClearNeedsStyleRecalc();
    ClearChildNeedsStyleRecalc();
  }
}

void Node::SetForceReattachLayoutTree() {
  DCHECK(!GetDocument().GetStyleEngine().InRebuildLayoutTree());
  DCHECK(IsElementNode() || IsTextNode());
  if (GetForceReattachLayoutTree())
    return;
  if (!InActiveDocument())
    return;
  if (Element* element = DynamicTo<Element>(this)) {
    if (!element->GetComputedStyle()) {
      DCHECK(!GetLayoutObject());
      return;
    }
  } else {
    DCHECK(IsTextNode());
    if (!GetLayoutObject() && ShouldSkipMarkingStyleDirty())
      return;
  }
  SetFlag(kForceReattachLayoutTree);
  if (!NeedsStyleRecalc()) {
    // Make sure we traverse down to this node during style recalc.
    MarkAncestorsWithChildNeedsStyleRecalc();
  }
}

bool Node::NeedsWhitespaceChildrenUpdate() const {
  if (const auto* layout_object = GetLayoutObject())
    return layout_object->WhitespaceChildrenMayChange();
  return false;
}

bool Node::NeedsLayoutSubtreeUpdate() const {
  if (const auto* layout_object = GetLayoutObject()) {
    return layout_object->WhitespaceChildrenMayChange() ||
           layout_object->WasNotifiedOfSubtreeChange();
  }
  return false;
}

// FIXME: Shouldn't these functions be in the editing code?  Code that asks
// questions about HTML in the core DOM class is obviously misplaced.
bool Node::CanStartSelection() const {
  if (DisplayLockUtilities::LockedAncestorPreventingPaint(*this)) {
    if (const Element* element =
            FlatTreeTraversal::InclusiveParentElement(*this)) {
      GetDocument().UpdateStyleAndLayoutTreeForElement(
          element, DocumentUpdateReason::kSelection);
    }
  }
  if (IsEditable(*this)) {
    return true;
  }

  if (GetLayoutObject()) {
    const ComputedStyle& style = GetLayoutObject()->StyleRef();
    EUserSelect user_select = style.UsedUserSelect();
    if (user_select == EUserSelect::kNone)
      return false;
    // We allow selections to begin within |user-select: text/all| sub trees
    // but not if the element is draggable.
    if (style.UserDrag() != EUserDrag::kElement &&
        (user_select == EUserSelect::kText || user_select == EUserSelect::kAll))
      return true;
  }
  ContainerNode* parent = FlatTreeTraversal::Parent(*this);
  return parent ? parent->CanStartSelection() : true;
}

bool Node::IsRichlyEditableForAccessibility() const {
#if DCHECK_IS_ON()  // Required in order to get Lifecycle().ToString()
  DCHECK_GE(GetDocument().Lifecycle().GetState(),
            DocumentLifecycle::kStyleClean)
      << "Unclean document style at lifecycle state "
      << GetDocument().Lifecycle().ToString();
#endif  // DCHECK_IS_ON()

  return IsRichlyEditable(*this);
}

void Node::NotifyPriorityScrollAnchorStatusChanged() {
  auto* node = this;
  while (node && !node->GetLayoutObject())
    node = FlatTreeTraversal::Parent(*node);
  if (node) {
    DCHECK(node->GetLayoutObject());
    node->GetLayoutObject()->NotifyPriorityScrollAnchorStatusChanged();
  }
}

bool Node::IsActiveSlot() const {
  return ToHTMLSlotElementIfSupportsAssignmentOrNull(*this);
}

AtomicString Node::SlotName() const {
  DCHECK(IsSlotable());
  if (IsElementNode()) {
    return HTMLSlotElement::NormalizeSlotName(
        To<Element>(*this).FastGetAttribute(html_names::kSlotAttr));
  }
  DCHECK(IsTextNode());
  return g_empty_atom;
}

ShadowRoot* Node::ParentElementShadowRoot() const {
  Element* parent = parentElement();
  return parent ? parent->GetShadowRoot() : nullptr;
}

bool Node::IsChildOfShadowHost() const {
  return ParentElementShadowRoot();
}

ShadowRoot* Node::ShadowRootOfParent() const {
  if (Element* parent = parentElement())
    return parent->GetShadowRoot();
  return nullptr;
}

Element* Node::OwnerShadowHost() const {
  if (ShadowRoot* root = ContainingShadowRoot())
    return &root->host();
  return nullptr;
}

ShadowRoot* Node::ContainingShadowRoot() const {
  Node& root = GetTreeScope().RootNode();
  return DynamicTo<ShadowRoot>(root);
}

Node* Node::NonBoundaryShadowTreeRootNode() {
  DCHECK(!IsShadowRoot());
  Node* root = this;
  while (root) {
    if (root->IsShadowRoot())
      return root;
    Node* parent = root->ParentOrShadowHostNode();
    if (parent && parent->IsShadowRoot())
      return root;
    root = parent;
  }
  return nullptr;
}

ContainerNode* Node::NonShadowBoundaryParentNode() const {
  ContainerNode* parent = parentNode();
  return parent && !parent->IsShadowRoot() ? parent : nullptr;
}

Element* Node::ParentOrShadowHostElement() const {
  ContainerNode* parent = ParentOrShadowHostNode();
  if (!parent)
    return nullptr;

  if (auto* shadow_root = DynamicTo<ShadowRoot>(parent))
    return &shadow_root->host();

  return DynamicTo<Element>(parent);
}

ContainerNode* Node::ParentOrShadowHostOrTemplateHostNode() const {
  auto* this_fragment = DynamicTo<DocumentFragment>(this);
  if (this_fragment && this_fragment->IsTemplateContent())
    return static_cast<const TemplateContentDocumentFragment*>(this)->Host();
  return ParentOrShadowHostNode();
}

TreeScope& Node::OriginatingTreeScope() const {
  if (const SVGElement* svg_element = DynamicTo<SVGElement>(this)) {
    if (const SVGElement* corr_element = svg_element->CorrespondingElement()) {
      DCHECK(!corr_element->CorrespondingElement());
      return corr_element->GetTreeScope();
    }
  }
  return GetTreeScope();
}

Document* Node::ownerDocument() const {
  Document* doc = &GetDocument();
  return doc == this ? nullptr : doc;
}

const KURL& Node::baseURI() const {
  return GetDocument().BaseURL();
}

bool Node::isEqualNode(Node* other) const {
  if (!other)
    return false;

  NodeType node_type = getNodeType();
  if (node_type != other->getNodeType())
    return false;

  if (nodeValue() != other->nodeValue())
    return false;

  if (auto* this_attr = DynamicTo<Attr>(this)) {
    auto* other_attr = To<Attr>(other);
    if (this_attr->localName() != other_attr->localName())
      return false;

    if (this_attr->namespaceURI() != other_attr->namespaceURI())
      return false;
  } else if (auto* this_element = DynamicTo<Element>(this)) {
    auto* other_element = DynamicTo<Element>(other);
    if (this_element->TagQName() != other_element->TagQName())
      return false;

    if (!this_element->HasEquivalentAttributes(*other_element))
      return false;
  } else if (nodeName() != other->nodeName()) {
    return false;
  }

  Node* child = firstChild();
  Node* other_child = other->firstChild();

  while (child) {
    if (!child->isEqualNode(other_child))
      return false;

    child = child->nextSibling();
    other_child = other_child->nextSibling();
  }

  if (other_child)
    return false;

  if (const auto* document_type_this = DynamicTo<DocumentType>(this)) {
    const auto* document_type_other = To<DocumentType>(other);

    if (document_type_this->publicId() != document_type_other->publicId())
      return false;

    if (document_type_this->systemId() != document_type_other->systemId())
      return false;
  }

  return true;
}

bool Node::isDefaultNamespace(
    const AtomicString& namespace_uri_maybe_empty) const {
  // https://dom.spec.whatwg.org/#dom-node-isdefaultnamespace

  // 1. If namespace is the empty string, then set it to null.
  const AtomicString& namespace_uri = namespace_uri_maybe_empty.empty()
                                          ? g_null_atom
                                          : namespace_uri_maybe_empty;

  // 2. Let defaultNamespace be the result of running locate a namespace for
  // context object using null.
  const AtomicString& default_namespace = lookupNamespaceURI(String());

  // 3. Return true if defaultNamespace is the same as namespace, and false
  // otherwise.
  return namespace_uri == default_namespace;
}

const AtomicString& Node::lookupPrefix(
    const AtomicString& namespace_uri) const {
  // Implemented according to
  // https://dom.spec.whatwg.org/#dom-node-lookupprefix

  if (namespace_uri.empty() || namespace_uri.IsNull())
    return g_null_atom;

  const Element* context;

  switch (getNodeType()) {
    case kElementNode:
      context = To<Element>(this);
      break;
    case kDocumentNode:
      context = To<Document>(this)->documentElement();
      break;
    case kDocumentFragmentNode:
    case kDocumentTypeNode:
      context = nullptr;
      break;
    case kAttributeNode:
      context = To<Attr>(this)->ownerElement();
      break;
    default:
      context = parentElement();
      break;
  }

  if (!context)
    return g_null_atom;

  return context->LocateNamespacePrefix(namespace_uri);
}

const AtomicString& Node::lookupNamespaceURI(
    const String& specified_prefix) const {
  // Implemented according to
  // https://dom.spec.whatwg.org/#dom-node-lookupnamespaceuri

  // 1. If prefix is the empty string, then set it to null.
  String prefix = specified_prefix;
  if (!specified_prefix.IsNull() && specified_prefix.empty())
    prefix = String();

  // 2. Return the result of running locate a namespace for the context object
  // using prefix.

  // https://dom.spec.whatwg.org/#locate-a-namespace
  switch (getNodeType()) {
    case kElementNode: {
      const auto& element = To<Element>(*this);

      // 1. If prefix is "xml", then return the XML namespace.
      if (prefix == g_xml_atom) {
        return xml_names::kNamespaceURI;
      }

      // 2. If prefix is "xmlns", then return the XMLNS namespace.
      if (prefix == g_xmlns_atom) {
        return xmlns_names::kNamespaceURI;
      }

      // 3. If its namespace is not null and its namespace prefix is prefix,
      // then return namespace.
      if (!element.namespaceURI().IsNull() && element.prefix() == prefix)
        return element.namespaceURI();

      // 4. If it has an attribute whose namespace is the XMLNS namespace,
      // namespace prefix is "xmlns", and local name is prefix, or if prefix is
      // null and it has an attribute whose namespace is the XMLNS namespace,
      // namespace prefix is null, and local name is "xmlns", then return its
      // value if it is not the empty string, and null otherwise.
      AttributeCollection attributes = element.Attributes();
      for (const Attribute& attr : attributes) {
        if (attr.Prefix() == g_xmlns_atom && attr.LocalName() == prefix) {
          if (!attr.Value().empty())
            return attr.Value();
          return g_null_atom;
        }
        if (attr.LocalName() == g_xmlns_atom && prefix.IsNull()) {
          if (!attr.Value().empty())
            return attr.Value();
          return g_null_atom;
        }
      }

      // 5. If its parent element is null, then return null.
      // 6. Return the result of running locate a namespace on its parent
      // element using prefix.
      if (Element* parent = parentElement())
        return parent->lookupNamespaceURI(prefix);
      return g_null_atom;
    }
    case kDocumentNode:
      if (Element* de = To<Document>(this)->documentElement())
        return de->lookupNamespaceURI(prefix);
      return g_null_atom;
    case kDocumentTypeNode:
    case kDocumentFragmentNode:
      return g_null_atom;
    case kAttributeNode: {
      const auto* attr = To<Attr>(this);
      if (attr->ownerElement())
        return attr->ownerElement()->lookupNamespaceURI(prefix);
      return g_null_atom;
    }
    default:
      if (Element* parent = parentElement())
        return parent->lookupNamespaceURI(prefix);
      return g_null_atom;
  }
}

String Node::textContent(bool convert_brs_to_newlines,
                         TextVisitor* visitor,
                         unsigned int max_length) const {
  // This covers ProcessingInstruction and Comment that should return their
  // value when .textContent is accessed on them, but should be ignored when
  // iterated over as a descendant of a ContainerNode.
  if (auto* character_data = DynamicTo<CharacterData>(this))
    return character_data->data();

  // Attribute nodes have their attribute values as textContent.
  if (auto* attr = DynamicTo<Attr>(this))
    return attr->value();

  // Documents and non-container nodes (that are not CharacterData)
  // have null textContent.
  if (IsDocumentNode() || !IsContainerNode())
    return String();

  StringBuilder content;
  for (const Node& node : NodeTraversal::InclusiveDescendantsOf(*this)) {
    if (visitor) {
      visitor->WillVisit(node, content.length());
    }
    if (IsA<HTMLBRElement>(node) && convert_brs_to_newlines) {
      content.Append('\n');
    } else if (auto* text_node = DynamicTo<Text>(node)) {
      content.Append(text_node->data());
      // Only abridge text content when max_length is explicitly set.
      if (max_length < UINT_MAX && content.length() > max_length) {
        content.Resize(max_length);
        break;
      }
    }
  }

  return content.ReleaseString();
}

V8UnionStringOrTrustedScript* Node::textContentForBinding() const {
  const String& value = textContent();
  if (value.IsNull())
    return nullptr;
  return MakeGarbageCollected<V8UnionStringOrTrustedScript>(value);
}

void Node::setTextContentForBinding(const V8UnionStringOrTrustedScript* value,
                                    ExceptionState& exception_state) {
  if (!value)
    return setTextContent(g_empty_string);

  switch (value->GetContentType()) {
    case V8UnionStringOrTrustedScript::ContentType::kString:
      return setTextContent(value->GetAsString());
    case V8UnionStringOrTrustedScript::ContentType::kTrustedScript:
      return setTextContent(value->GetAsTrustedScript()->toString());
  }

  NOTREACHED();
}

void Node::setTextContent(const String& text) {
  switch (getNodeType()) {
    case kAttributeNode:
    case kTextNode:
    case kCdataSectionNode:
    case kCommentNode:
    case kProcessingInstructionNode:
      setNodeValue(text);
      return;
    case kElementNode:
    case kDocumentFragmentNode: {
      // FIXME: Merge this logic into replaceChildrenWithText.
      auto* container = To<ContainerNode>(this);

      // Note: This is an intentional optimization.
      // See crbug.com/352836 also.
      // No need to do anything if the text is identical.
      if (container->HasOneTextChild() &&
          To<Text>(container->firstChild())->data() == text && !text.empty())
        return;

      ChildListMutationScope mutation(*this);
      // Note: This API will not insert empty text nodes:
      // https://dom.spec.whatwg.org/#dom-node-textcontent
      if (text.empty()) {
        container->RemoveChildren(kDispatchSubtreeModifiedEvent);
      } else {
        container->RemoveChildren(kOmitSubtreeModifiedEvent);
        container->AppendChild(GetDocument().createTextNode(text),
                               ASSERT_NO_EXCEPTION);
      }
      return;
    }
    case kDocumentNode:
    case kDocumentTypeNode:
      // Do nothing.
      return;
  }
  NOTREACHED();
}

uint16_t Node::compareDocumentPosition(const Node* other_node,
                                       ShadowTreesTreatment treatment) const {
  if (other_node == this)
    return kDocumentPositionEquivalent;

  const auto* attr1 = DynamicTo<Attr>(this);
  const Attr* attr2 = DynamicTo<Attr>(other_node);

  const Node* start1 = attr1 ? attr1->ownerElement() : this;
  const Node* start2 = attr2 ? attr2->ownerElement() : other_node;

  // If either of start1 or start2 is null, then we are disconnected, since one
  // of the nodes is an orphaned attribute node.
  if (!start1 || !start2) {
    uint16_t direction = (this > other_node) ? kDocumentPositionPreceding
                                             : kDocumentPositionFollowing;
    return kDocumentPositionDisconnected |
           kDocumentPositionImplementationSpecific | direction;
  }

  HeapVector<Member<const Node>, 16> chain1;
  HeapVector<Member<const Node>, 16> chain2;
  if (attr1)
    chain1.push_back(attr1);
  if (attr2)
    chain2.push_back(attr2);

  if (attr1 && attr2 && start1 == start2 && start1) {
    // We are comparing two attributes on the same node. Crawl our attribute map
    // and see which one we hit first.
    const Element* owner1 = attr1->ownerElement();
    AttributeCollection attributes = owner1->Attributes();
    for (const Attribute& attr : attributes) {
      // If neither of the two determining nodes is a child node and nodeType is
      // the same for both determining nodes, then an implementation-dependent
      // order between the determining nodes is returned. This order is stable
      // as long as no nodes of the same nodeType are inserted into or removed
      // from the direct container. This would be the case, for example, when
      // comparing two attributes of the same element, and inserting or removing
      // additional attributes might change the order between existing
      // attributes.
      if (attr1->GetQualifiedName() == attr.GetName())
        return kDocumentPositionImplementationSpecific |
               kDocumentPositionFollowing;
      if (attr2->GetQualifiedName() == attr.GetName())
        return kDocumentPositionImplementationSpecific |
               kDocumentPositionPreceding;
    }

    NOTREACHED();
  }

  // If one node is in the document and the other is not, we must be
  // disconnected.  If the nodes have different owning documents, they must be
  // disconnected.  Note that we avoid comparing Attr nodes here, since they
  // return false from isConnected() all the time (which seems like a bug).
  if (start1->isConnected() != start2->isConnected() ||
      (treatment == kTreatShadowTreesAsDisconnected &&
       start1->GetTreeScope() != start2->GetTreeScope())) {
    uint16_t direction = (this > other_node) ? kDocumentPositionPreceding
                                             : kDocumentPositionFollowing;
    return kDocumentPositionDisconnected |
           kDocumentPositionImplementationSpecific | direction;
  }

  // We need to find a common ancestor container, and then compare the indices
  // of the two immediate children.
  const Node* current;
  for (current = start1; current; current = current->ParentOrShadowHostNode())
    chain1.push_back(current);
  for (current = start2; current; current = current->ParentOrShadowHostNode())
    chain2.push_back(current);

  unsigned index1 = chain1.size();
  unsigned index2 = chain2.size();

  // If the two elements don't have a common root, they're not in the same tree.
  if (chain1[index1 - 1] != chain2[index2 - 1]) {
    uint16_t direction = (this > other_node) ? kDocumentPositionPreceding
                                             : kDocumentPositionFollowing;
    return kDocumentPositionDisconnected |
           kDocumentPositionImplementationSpecific | direction;
  }

  unsigned connection = start1->GetTreeScope() != start2->GetTreeScope()
                            ? kDocumentPositionDisconnected |
                                  kDocumentPositionImplementationSpecific
                            : 0;

  // Walk the two chains backwards and look for the first difference.
  for (unsigned i = std::min(index1, index2); i; --i) {
    const Node* child1 = chain1[--index1];
    const Node* child2 = chain2[--index2];
    if (child1 != child2) {
      // If one of the children is an attribute, it wins.
      if (child1->getNodeType() == kAttributeNode)
        return kDocumentPositionFollowing | connection;
      if (child2->getNodeType() == kAttributeNode)
        return kDocumentPositionPreceding | connection;

      // If one of the children is a shadow root,
      if (child1->IsShadowRoot() || child2->IsShadowRoot()) {
        if (!child2->IsShadowRoot())
          return Node::kDocumentPositionFollowing | connection;
        if (!child1->IsShadowRoot())
          return Node::kDocumentPositionPreceding | connection;

        return Node::kDocumentPositionPreceding | connection;
      }

      if (!child2->PseudoAwareNextSibling()) {
        return kDocumentPositionFollowing | connection;
      }
      if (!child1->PseudoAwareNextSibling()) {
        return kDocumentPositionPreceding | connection;
      }

      // Otherwise we need to see which node occurs first.  Crawl backwards from
      // child2 looking for child1.
      for (const Node* child = child2->PseudoAwarePreviousSibling(); child;
           child = child->PseudoAwarePreviousSibling()) {
        if (child == child1)
          return kDocumentPositionFollowing | connection;
      }
      return kDocumentPositionPreceding | connection;
    }
  }

  // There was no difference between the two parent chains, i.e., one was a
  // subset of the other.  The shorter chain is the ancestor.
  return index1 < index2 ? kDocumentPositionFollowing |
                               kDocumentPositionContainedBy | connection
                         : kDocumentPositionPreceding |
                               kDocumentPositionContains | connection;
}

void Node::InvalidateIfHasEffectiveAppearance() const {
  auto* layout_object = GetLayoutObject();
  if (!layout_object)
    return;

  if (!layout_object->StyleRef().HasEffectiveAppearance())
    return;

  layout_object->SetSubtreeShouldDoFullPaintInvalidation();
}

Node::InsertionNotificationRequest Node::InsertedInto(
    ContainerNode& insertion_point) {
  DCHECK(!ChildNeedsStyleInvalidation());
  DCHECK(!NeedsStyleInvalidation());
  DCHECK(insertion_point.isConnected() || insertion_point.IsInShadowTree() ||
         IsContainerNode() || GetDOMParts());
  if (insertion_point.isConnected()) {
    SetFlag(kIsConnectedFlag);
#if DCHECK_IS_ON()
    insertion_point.GetDocument().IncrementNodeCount();
#endif
  }
  if (ParentOrShadowHostNode()->IsInShadowTree())
    SetFlag(kIsInShadowTreeFlag);
  if (auto* cache = GetDocument().ExistingAXObjectCache()) {
    cache->NodeIsConnected(this);
  }

  return kInsertionDone;
}

void Node::MovedFrom(ContainerNode& old_parent) {}

void Node::RemovedFrom(ContainerNode& insertion_point) {
  DCHECK(IsContainerNode() || IsInTreeScope() || GetDOMParts());
  if (insertion_point.isConnected()) {
    ClearNeedsStyleRecalc();
    ClearChildNeedsStyleRecalc();
    ClearNeedsStyleInvalidation();
    ClearChildNeedsStyleInvalidation();
    ClearFlag(kIsConnectedFlag);
#if DCHECK_IS_ON()
    insertion_point.GetDocument().DecrementNodeCount();
#endif
  }
  if (IsInShadowTree() && !GetTreeScope().RootNode().IsShadowRoot()) {
    ClearFlag(kIsInShadowTreeFlag);
  }
  if (auto* cache = GetDocument().ExistingAXObjectCache()) {
    cache->Remove(this);
  }
}

String Node::DebugName() const {
  StringBuilder name;
  name.Append(nodeName());
  if (const auto* vt_pseudo =
          DynamicTo<ViewTransitionPseudoElementBase>(this)) {
    name.Append("(");
    name.Append(vt_pseudo->view_transition_name());
    name.Append(")");
  } else if (const auto* this_element = DynamicTo<Element>(this)) {
    if (this_element->HasID()) {
      name.Append(" id=\'");
      name.Append(this_element->GetIdAttribute());
      name.Append('\'');
    }

    if (this_element->HasClass()) {
      name.Append(" class=\'");
      for (wtf_size_t i = 0; i < this_element->ClassNames().size(); ++i) {
        if (i > 0)
          name.Append(' ');
        name.Append(this_element->ClassNames()[i]);
      }
      name.Append('\'');
    }
  }
  return name.ReleaseString();
}

static void DumpAttributeDesc(const Node& node,
                              const QualifiedName& name,
                              StringBuilder& builder) {
  auto* element = DynamicTo<Element>(node);
  if (!element)
    return;
  const AtomicString& value = element->getAttribute(name);
  if (value.empty())
    return;
  builder.Append(' ');
  builder.Append(name.ToString());
  builder.Append("=");
  builder.Append(String(value).EncodeForDebugging());
}

std::ostream& operator<<(std::ostream& ostream, const Node& node) {
  return ostream << node.ToString().Utf8();
}

std::ostream& operator<<(std::ostream& ostream, const Node* node) {
  if (!node)
    return ostream << "null";
  return ostream << *node;
}

String Node::ToString() const {
  if (getNodeType() == Node::kProcessingInstructionNode)
    return "?" + nodeName();
  if (auto* shadow_root = DynamicTo<ShadowRoot>(this)) {
    // nodeName of ShadowRoot is #document-fragment.  It's confused with
    // DocumentFragment.
    std::stringstream shadow_root_type;
    shadow_root_type << shadow_root->GetMode();
    String shadow_root_type_str(shadow_root_type.str().c_str());
    return "#shadow-root(" + shadow_root_type_str + ")";
  }
  if (IsDocumentTypeNode())
    return "DOCTYPE " + nodeName();

  StringBuilder builder;
  builder.Append(nodeName());
  if (IsTextNode()) {
    builder.Append(" ");
    builder.Append(nodeValue().EncodeForDebugging());
    return builder.ReleaseString();
  } else if (const auto* vt_pseudo =
                 DynamicTo<ViewTransitionPseudoElementBase>(this)) {
    builder.Append("(");
    builder.Append(vt_pseudo->view_transition_name());
    builder.Append(")");
  } else if (const auto* element = DynamicTo<Element>(this)) {
    const AtomicString& pseudo = element->ShadowPseudoId();
    if (!pseudo.empty()) {
      builder.Append(" ::");
      builder.Append(pseudo);
    }
    DumpAttributeDesc(*this, html_names::kIdAttr, builder);
    DumpAttributeDesc(*this, html_names::kClassAttr, builder);
    DumpAttributeDesc(*this, html_names::kStyleAttr, builder);
  }
  if (IsEditable(*this))
    builder.Append(" (editable)");
  if (GetDocument().FocusedElement() == this)
    builder.Append(" (focused)");
  return builder.ReleaseString();
}

#if DCHECK_IS_ON()

String Node::ToTreeStringForThis() const {
  return ToMarkedTreeString(this, "*");
}

String Node::ToFlatTreeStringForThis() const {
  return ToMarkedFlatTreeString(this, "*");
}

void Node::PrintNodePathTo(std::ostream& stream) const {
  HeapVector<Member<const Node>, 16> chain;
  const Node* parent_node = this;
  while (parent_node->ParentOrShadowHostNode()) {
    chain.push_back(parent_node);
    parent_node = parent_node->ParentOrShadowHostNode();
  }
  for (unsigned index = chain.size(); index > 0; --index) {
    const Node* node = chain[index - 1];
    if (node->IsShadowRoot()) {
      stream << "/#shadow-root";
      continue;
    }

    switch (node->getNodeType()) {
      case kElementNode: {
        stream << "/" << node->nodeName().Utf8();

        const auto* element = To<Element>(node);
        const AtomicString& idattr = element->GetIdAttribute();
        bool has_id_attr = !idattr.IsNull() && !idattr.empty();
        if (node->previousSibling() || node->nextSibling()) {
          int count = 0;
          for (const Node* previous = node->previousSibling(); previous;
               previous = previous->previousSibling()) {
            if (previous->nodeName() == node->nodeName()) {
              ++count;
            }
          }
          if (has_id_attr)
            stream << "[@id=\"" << idattr.Utf8()
                   << "\" and position()=" << count << "]";
          else
            stream << "[" << count << "]";
        } else if (has_id_attr) {
          stream << "[@id=\"" << idattr.Utf8() << "\"]";
        }
        break;
      }
      case kTextNode:
        stream << "/text()";
        break;
      case kAttributeNode:
        stream << "/@" << node->nodeName().Utf8();
        break;
      default:
        break;
    }
  }
}

static void AppendMarkedTree(const String& base_indent,
                             const Node* root_node,
                             const Node* marked_node1,
                             const char* marked_label1,
                             const Node* marked_node2,
                             const char* marked_label2,
                             StringBuilder& builder) {
  for (const Node& node : NodeTraversal::InclusiveDescendantsOf(*root_node)) {
    StringBuilder indent;
    if (node == marked_node1)
      indent.Append(marked_label1);
    if (node == marked_node2)
      indent.Append(marked_label2);
    indent.Append(base_indent);
    for (const Node* tmp_node = &node; tmp_node && tmp_node != root_node;
         tmp_node = tmp_node->ParentOrShadowHostNode())
      indent.Append('\t');
    builder.Append(indent);
    builder.Append(node.ToString());
    builder.Append("\n");
    indent.Append('\t');

    String indent_string = indent.ReleaseString();

    if (const auto* element = DynamicTo<Element>(node)) {
      if (Element* pseudo =
              element->GetPseudoElement(kPseudoIdScrollMarkerGroupBefore)) {
        AppendMarkedTree(indent_string, pseudo, marked_node1, marked_label1,
                         marked_node2, marked_label2, builder);
```