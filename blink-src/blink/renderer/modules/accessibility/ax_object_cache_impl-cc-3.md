Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's Blink rendering engine. This is part 4 of 8, so I need to focus on the specific functions within this snippet.

Here's a breakdown of the functions and their likely purposes based on their names and code:

*   **`NodeIsAttached(Node* node)`**: Handles the logic when a node is attached to the DOM tree. It checks for specific node types (Document, HTMLSelectElement, HTMLTableElement, HTMLImageElement) and performs actions like firing children changed events or deferring tree updates.
*   **`NodeIsAttachedWithCleanLayout(Node* node)`**:  Similar to `NodeIsAttached` but assumes the layout is already clean. It handles `aria-activedescendant`, updates relations, and checks for table role changes.
*   **`NotifyParentChildrenChanged(AXObject* parent)`**: Notifies the parent AXObject that its children have changed. It behaves differently depending on the current lifecycle state of the AXObjectCache.
*   **`ChildrenChangedOnAncestorOf(AXObject* obj)`**:  Handles the case where an ancestor of a given AXObject has had its children changed.
*   **`ChildrenChangedWithCleanLayout(AXObject* obj)`**:  Marks an AXObject's children as needing an update when the layout is clean.
*   **`ChildrenChanged(AXObject* obj)`**: Marks an AXObject's children as needing an update, potentially deferring the update if the lifecycle state requires it.
*   **`InvalidateChildren(AXObject* obj)`**:  Marks an AXObject and its ancestors as needing a children update.
*   **`SlotAssignmentWillChange(Node* node)`**:  Indicates that slot assignments in the Shadow DOM will change, triggering a children changed event.
*   **`ChildrenChanged(Node* node)`**: A convenience overload to call `ChildrenChanged` with an AXObject.
*   **`ChildrenChanged(const LayoutObject* layout_object)`**:  A convenience overload to call `ChildrenChanged` based on a LayoutObject.
*   **`ChildrenChangedWithCleanLayout(Node* node)`**: Convenience overloads for `ChildrenChangedWithCleanLayout`.
*   **`FinalizeTree()`**:  Recursively updates the children of the AX tree to ensure all nodes have their children computed.
*   **`CheckStyleIsComplete(Document& document) const`**:  Performs expensive checks in debug builds to ensure that style calculations are up-to-date.
*   **`CheckTreeIsFinalized()`**: Performs extensive checks in debug builds to ensure the accessibility tree structure is consistent and all necessary updates have been applied.
*   **`GetDeferredEventsDelay()`**: Returns the delay before sending non-interactive accessibility events.
*   **`GetLocationSerializationDelay()`**: Returns the delay between sending accessibility location updates.
*   **`CommitAXUpdates(Document& document, bool force)`**: The central function for processing deferred accessibility updates. It manages the lifecycle, processes events, finalizes the tree, and triggers serialization.
*   **`SerializeUpdatesAndEvents()`**:  Gathers accessibility updates and events and sends them to the accessibility client.

Based on this understanding, I can now formulate the summary and address the specific points requested by the user.
这个代码片段主要负责处理DOM树的**节点连接 (Node Attachment)** 和 **子节点变更 (Children Changed)** 事件，并以此来更新和维护**Accessibility (AX) 树**。它确保了当DOM树发生结构性变化时，辅助功能 API 能够获取到最新的、准确的信息。

以下是更详细的功能说明：

**核心功能：**

1. **监听节点连接事件 (`NodeIsAttached`, `NodeIsAttachedWithCleanLayout`)**:
    *   当一个DOM节点被添加到文档树中时，这些函数会被调用。
    *   它们会检查该节点的类型和状态，并采取相应的行动来更新AX树。
    *   例如，对于 `HTMLSelectElement`，会忽略其下拉框的节点；对于 `HTMLTableElement`，会延迟处理直到其子节点完全解析。
    *   `NodeIsAttachedWithCleanLayout` 假定布局已经完成，可以执行更直接的操作，例如处理 `aria-activedescendant` 属性的变化。

2. **处理子节点变更事件 (`ChildrenChanged`, `NotifyParentChildrenChanged`, `ChildrenChangedOnAncestorOf`, `ChildrenChangedWithCleanLayout`, `InvalidateChildren`, `SlotAssignmentWillChange`)**:
    *   当一个DOM节点的子节点发生变化（添加、删除、重新排序等）时，这些函数会被调用。
    *   它们负责标记AX树中相应的节点需要更新其子节点信息。
    *   `InvalidateChildren` 会标记一个节点及其祖先节点需要更新子节点，以确保AX树的正确性。
    *   `ChildrenChangedWithCleanLayout` 假设布局已经完成，可以直接更新AX树。
    *   `NotifyParentChildrenChanged` 通知父 AXObject 其子节点已更改。
    *   `ChildrenChangedOnAncestorOf`  处理当一个已分离的对象的祖先节点的子节点发生变化的情况。
    *   `SlotAssignmentWillChange` 特指 Shadow DOM 中插槽内容变化的情况。

3. **延迟和提交 AX 更新 (`CommitAXUpdates`)**:
    *   `CommitAXUpdates` 是一个核心函数，负责收集并最终提交对 AX 树的更新。
    *   它会检查文档的生命周期状态，确保在合适的时机进行更新。
    *   为了避免频繁更新，它会采用延迟策略，等待一段时间再进行批量更新。
    *   它可以被强制执行 (`force=true`)，用于需要立即同步的场景。
    *   此函数还负责调用各种清理和检查函数，例如 `CheckStyleIsComplete` 和 `FinalizeTree`。

4. **最终化 AX 树 (`FinalizeTree`)**:
    *   在处理完所有变更后，`FinalizeTree` 会遍历 AX 树，确保每个节点都已计算并缓存了其子节点。这确保了 AX 树的完整性和一致性。

5. **检查 AX 树的完整性 (`CheckTreeIsFinalized`, `CheckStyleIsComplete`)**:
    *   这些函数（通常在调试模式下激活）用于验证 AX 树的结构是否正确，是否存在不一致的状态，以及样式计算是否已完成。这有助于发现潜在的错误。

6. **管理序列化延迟 (`GetDeferredEventsDelay`, `GetLocationSerializationDelay`)**:
    *   这些函数定义了发送辅助功能事件的延迟时间。
    *   针对不同的事件类型（例如，非交互事件 vs. 位置更新），以及是否包含焦点元素，会采用不同的延迟策略，以平衡性能和用户体验。

7. **序列化更新和事件 (`SerializeUpdatesAndEvents`)**:
    *   这个函数负责将 AX 树的变更和相关的辅助功能事件转换为特定的数据格式，并将其发送给辅助功能客户端（例如，屏幕阅读器）。

**与 Javascript, HTML, CSS 的关系及举例说明：**

*   **Javascript:**  当 Javascript 代码操作 DOM 结构（例如，使用 `appendChild`, `removeChild`, `insertBefore` 等）时，会触发 `NodeIsAttached` 和子节点变更相关的函数。
    *   **假设输入:** Javascript 代码执行 `document.getElementById('parent').appendChild(newNode);`
    *   **输出:** `NodeIsAttached(newNode)` 将会被调用。

*   **HTML:** HTML 的结构定义了初始的 DOM 树。当浏览器解析 HTML 并构建 DOM 树时，会多次调用 `NodeIsAttached`。
    *   **假设输入:** HTML 代码片段 `<div id="container"><span>Text</span></div>`
    *   **输出:**  在解析过程中，会依次调用 `NodeIsAttached` 来处理 `<div>` 和 `<span>` 元素。

*   **CSS:** CSS 可以通过改变元素的 `display` 属性等来影响元素的渲染和布局。这些变化可能会影响 AX 树的结构。例如，当一个元素的 `display` 从 `none` 变为其他值时，它可能会被添加到 AX 树中。
    *   **假设输入:** CSS 规则 `.hidden { display: none; }` 和 Javascript 代码 `element.classList.remove('hidden');`
    *   **输出:** 当元素的 `display` 不再是 `none` 并开始参与布局时，可能会调用 `NodeIsAttached`，也可能触发其他 AX 树更新相关的函数。代码中也提到了处理 `display:none` 元素重新获得布局的情况。

**逻辑推理的假设输入与输出：**

*   **假设输入:** 一个 `<div>` 元素初始时没有子节点，然后通过 Javascript 动态添加了三个 `<span>` 子节点。
*   **输出:**
    *   首先，`NodeIsAttached` 会被调用三次，分别对应每个 `<span>` 元素的添加。
    *   然后，`ChildrenChanged(parentDiv)` 或类似函数会被调用，标记 `<div>` 元素的子节点发生了变化。
    *   最终，在 `CommitAXUpdates` 中，`<div>` 元素的 AXObject 的子节点信息会被更新，并可能通过 `SerializeUpdatesAndEvents` 发送给辅助功能客户端。

**用户或编程常见的使用错误举例说明：**

*   **错误:**  在 Javascript 中直接修改 DOM 元素的属性，而没有考虑到这些修改可能需要触发辅助功能更新。例如，动态改变一个可访问元素的 `aria-label` 属性后，没有等待足够的时间或者没有触发相关的事件，导致屏幕阅读器读取到旧的标签。
*   **调试线索:**  如果用户报告屏幕阅读器没有及时更新，或者读取了错误的信息，开发者可以检查与该元素相关的 `ChildrenChanged` 等函数是否被正确调用，以及 `CommitAXUpdates` 是否在预期的时间执行。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户加载网页:**  浏览器开始解析 HTML，构建 DOM 树。在这个过程中，会多次调用 `NodeIsAttached`。
2. **用户与网页交互:** 用户点击按钮、填写表单、展开/折叠内容等操作，这些交互通常会触发 Javascript 代码的执行，进而修改 DOM 结构或元素属性。
3. **DOM 发生变化:** Javascript 代码执行 `appendChild`、`removeChild`、修改元素属性等操作，这些操作会触发 `NodeIsAttached` 或子节点变更相关的函数。
4. **AX 树更新请求:** 被触发的函数会将相应的 AXObject 标记为需要更新。
5. **延迟更新:** `CommitAXUpdates` 函数会等待一段时间（由 `GetDeferredEventsDelay` 决定）来批量处理这些更新。
6. **最终化和序列化:** 在合适的时机，`FinalizeTree` 会确保 AX 树的完整性，然后 `SerializeUpdatesAndEvents` 会将更新发送给辅助功能客户端。

作为调试线索，如果辅助功能出现问题，开发者可以：

*   在 `NodeIsAttached` 和子节点变更相关的函数中设置断点，观察 DOM 变化时是否触发了这些函数。
*   检查 `CommitAXUpdates` 的调用时机和频率，看是否符合预期。
*   查看 `SerializeUpdatesAndEvents` 发送的数据，确认是否包含了正确的变更信息。

**归纳一下它的功能 (第 4 部分)：**

在这个代码片段中，**核心功能是监听和响应 DOM 树的结构性变化（节点连接和子节点变更），并以此来维护和更新 Chromium 的辅助功能 (AX) 树。** 它包含处理这些事件的逻辑，以及管理 AX 树更新的延迟和最终提交过程。 这部分代码确保了当网页的 DOM 结构发生变化时，辅助功能 API 能够及时获取到准确的信息，从而为使用辅助技术的用户提供更好的体验。  它也包含了用于调试和验证 AX 树完整性的机制。

Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_object_cache_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共8部分，请归纳一下它的功能

"""
ut_parent->GetNode());
      }
    }
    return;
  }

  Document* document = DynamicTo<Document>(node);
  if (document) {
    Element* focused_element = GetDocument().FocusedElement();
    // A popup is being shown.
    if (IsA<HTMLSelectElement>(focused_element)) {
      // HTML <select> has a popup that duplicates nodes from the main
      // document, and therefore we ignore that popup and any nodes in it.
      return;
    }
    DCHECK(*document != GetDocument());
    DCHECK(!popup_document_) << "Last popup was not cleared.";
    DCHECK(!popup_document_ || popup_document_ == document)
        << "Last popup was not cleared: " << (void*)popup_document_;
    popup_document_ = document;
    DCHECK(IsPopup(*document));
    // Fire children changed on the focused element that owns this popup.
    ChildrenChanged(focused_element);
    return;
  }
  if (node->GetLayoutObject()) {
    // Handle subtree that was previously display:none gaining layout.
    if (AXObject* obj = Get(node); obj && !obj->GetLayoutObject()) {
      // Had a previous AXObject, but wasn't an AXLayoutObject, even though
      // there is a layout object available.
      RemoveSubtree(node);
      return;
    }
    if ((IsA<HTMLTableElement>(node) || IsA<HTMLSelectElement>(node) ||
         node->GetLayoutObject()->IsAtomicInlineLevel()) &&
        !node->IsFinishedParsingChildren() &&
        !node_to_parse_before_more_tree_updates_) {
      // * Tables must be fully parsed before building, because many of the
      //   computed properties require the entire table.
      // * Custom selects must be fully parsed before building because of
      //   flakes where the entire subtree was not populated. The exact reason
      //   is unclear, but it could be related to the unique use of the flat
      //   vs. natural DOM tree.
      // TODO(accessibility) Fix root select issue, while still passing
      // All/YieldingParserDumpAccessibilityTreeTest.AccessibilityCustomSelect/blink.
      // * Inline text boxes must know their children in order to determine
      //   whether they can be ignored;
      node_to_parse_before_more_tree_updates_ = node;
    }

    // Rare edge case: if an image is added, it could have changed the order of
    // images with the same usemap in the document. Only the first image for a
    // given <map> should have the <area> children. Therefore, get the current
    // primary image before it's updated, and ensure its children are
    // recalculated.
    if (IsA<HTMLImageElement>(node)) {
      if (HTMLMapElement* map = AXObject::GetMapForImage(node)) {
        HTMLImageElement* primary_image_element = map->ImageElement();
        if (node != primary_image_element) {
          // This is a secondary image for its map, and therefore the map does
          // not apply to it. Make sure the primary image recomputes its
          // children.
          ChildrenChanged(primary_image_element);
        } else if (AXObject* ax_previous_parent = GetAXImageForMap(*map)) {
          // This is the primary image for its map and the map's children
          // were previously parented by an AXObject for an <img>
          if (ax_previous_parent->GetNode() != node) {
            // The previous AXObject parent for the maps children does not
            // match!
            ChildrenChanged(ax_previous_parent);
            ax_previous_parent->ClearChildren();
          }
        }
      }
    }
  }

  DeferTreeUpdate(TreeUpdateReason::kNodeIsAttached, node);
}

void AXObjectCacheImpl::NodeIsAttachedWithCleanLayout(Node* node) {
  if (!node || !node->isConnected()) {
    return;
  }

  Element* element = DynamicTo<Element>(node);

#if DCHECK_IS_ON()
  DCHECK(node->GetDocument().Lifecycle().GetState() >=
         DocumentLifecycle::kLayoutClean)
      << "Unclean document at lifecycle "
      << node->GetDocument().Lifecycle().ToString();
#endif  // DCHECK_IS_ON()

  if (AXObject::ElementFromAttributeOrInternals(
          element, html_names::kAriaActivedescendantAttr)) {
    HandleActiveDescendantChangedWithCleanLayout(element);
  }

  AXObject* obj = Get(node);
  CHECK(obj);
  CHECK(obj->ParentObject());

  if (element) {
    MaybeNewRelationTarget(*node, obj);
  }

  if (IsA<HTMLAreaElement>(node)) {
    ChildrenChangedWithCleanLayout(obj);
  }

  // Check if a row or cell's table changed to or from a data table.
  if (IsA<HTMLTableRowElement>(node) || IsA<HTMLTableCellElement>(node)) {
    Element* parent = node->parentElement();
    while (parent) {
      if (DynamicTo<HTMLTableElement>(parent)) {
        break;
      }
      parent = parent->parentElement();
    }
    if (parent) {
      UpdateTableRoleWithCleanLayout(parent);
    }
    TableCellRoleMaybeChanged(node);
  }
}

void AXObjectCacheImpl::NotifyParentChildrenChanged(AXObject* parent) {
  if (!parent) {
    return;
  }
  if (lifecycle_.StateAllowsImmediateTreeUpdates()) {
    ChildrenChangedWithCleanLayout(parent);
  } else {
    AXObject* ax_ancestor = ChildrenChanged(parent);
    if (!ax_ancestor) {
      return;
    }

    CHECK(!IsFrozen())
        << "Attempting to change children on an ancestor is dangerous during "
           "serialization, because the ancestor may have already been "
           "visited. Reaching this line indicates that AXObjectCacheImpl did "
           "not handle a signal and call ChildrenChanged() earlier."
        << "\nParent: " << parent << "\nAncestor: " << ax_ancestor;
  }
}

// Note: do not call this when a child is becoming newly included, because
// it will return early if |obj| was last known to be unincluded.
void AXObjectCacheImpl::ChildrenChangedOnAncestorOf(AXObject* obj) {
  DCHECK(obj);
  DCHECK(!obj->IsDetached());

  // Clear children of ancestors in order to ensure this detached object is not
  // cached in an ancestor's list of children:
  // Any ancestor up to the first included ancestor can contain the now-detached
  // child in it's cached children, and therefore must update children.
  NotifyParentChildrenChanged(obj->ParentObjectIfPresent());
}

void AXObjectCacheImpl::ChildrenChangedWithCleanLayout(AXObject* obj) {
  if (AXObject* ax_ancestor_for_notification = InvalidateChildren(obj)) {
    if (ax_ancestor_for_notification->GetNode() &&
        nodes_with_pending_children_changed_.Contains(
            ax_ancestor_for_notification->AXObjectID())) {
      return;
    }
    ChildrenChangedWithCleanLayout(ax_ancestor_for_notification->GetNode(),
                                   ax_ancestor_for_notification);
  }
}

AXObject* AXObjectCacheImpl::ChildrenChanged(AXObject* obj) {
  CHECK(lifecycle_.StateAllowsDeferTreeUpdates())
      << "Call ChildrenChangedWithCleanLayout() directly while processing "
         "deferred events."
      << *this;
  if (AXObject* ax_ancestor_for_notification = InvalidateChildren(obj)) {
    // Don't enqueue a deferred event on the same node more than once.
    CHECK(lifecycle_.StateAllowsDeferTreeUpdates());
    if (ax_ancestor_for_notification->GetNode() &&
        !nodes_with_pending_children_changed_
             .insert(ax_ancestor_for_notification->AXObjectID())
             .is_new_entry) {
      return nullptr;
    }

    DeferTreeUpdate(TreeUpdateReason::kChildrenChanged,
                    ax_ancestor_for_notification);
    return ax_ancestor_for_notification;
  }
  return nullptr;
}

AXObject* AXObjectCacheImpl::InvalidateChildren(AXObject* obj) {
  if (!obj)
    return nullptr;

  // Clear children of ancestors in order to ensure this detached object is not
  // cached an ancestor's list of children:
  AXObject* ancestor = obj;
  while (ancestor) {
    if (ancestor->NeedsToUpdateChildren() || ancestor->IsDetached())
      return nullptr;  // Processing has already occurred for this ancestor.
    ancestor->SetNeedsToUpdateChildren();

    // Any ancestor up to the first included ancestor can contain the
    // now-detached child in it's cached children, and therefore must update
    // children.
    if (ancestor->CachedIsIncludedInTree()) {
      break;
    }

    ancestor = ancestor->ParentObject();
  }

  // Only process ChildrenChanged() events on the included ancestor. This allows
  // deduping of ChildrenChanged() occurrences within the same subtree.
  // For example, if a subtree has unincluded children, but included
  // grandchildren have changed, only the root children changed needs to be
  // processed.
  if (!ancestor)
    return nullptr;

  // Return ancestor to fire children changed notification on.
  DCHECK(ancestor->CachedIsIncludedInTree())
      << "ChildrenChanged() must only be called on included nodes: "
      << ancestor;

  return ancestor;
}

void AXObjectCacheImpl::SlotAssignmentWillChange(Node* node) {
  ChildrenChanged(node);
}

void AXObjectCacheImpl::ChildrenChanged(Node* node) {
  ChildrenChanged(Get(node));
}

void AXObjectCacheImpl::ChildrenChanged(const LayoutObject* layout_object) {
  if (!layout_object)
    return;

  // Ensure that this object is touched, so that Get() can Invalidate() it if
  // necessary, e.g. to change whether it contains a LayoutObject.
  Get(layout_object);

  // Update using nearest node (walking ancestors if necessary).
  Node* node = GetClosestNodeForLayoutObject(layout_object);
  if (!node)
    return;

  ChildrenChanged(node);
}

void AXObjectCacheImpl::ChildrenChangedWithCleanLayout(Node* node) {
  if (AXObject* obj = Get(node)) {
    ChildrenChangedWithCleanLayout(node, obj);
  }
}

// TODO can node be non-optional?
void AXObjectCacheImpl::ChildrenChangedWithCleanLayout(Node* optional_node,
                                                       AXObject* obj) {
  CHECK(obj);
  CHECK(!obj->IsDetached());

#if DCHECK_IS_ON()
  if (optional_node) {
    DCHECK_EQ(obj->GetNode(), optional_node);
    DCHECK_EQ(obj, Get(optional_node));
  }
  Document* document = obj->GetDocument();
  DCHECK(document);
  DCHECK(document->Lifecycle().GetState() >= DocumentLifecycle::kLayoutClean)
      << "Unclean document at lifecycle " << document->Lifecycle().ToString();
#endif  // DCHECK_IS_ON()

  obj->ChildrenChangedWithCleanLayout();
  DUMP_WILL_BE_CHECK(!obj->IsDetached());
  if (optional_node) {
    CHECK(relation_cache_);
    relation_cache_->UpdateRelatedTree(optional_node, obj);
  }

  TableCellRoleMaybeChanged(optional_node);
}

void AXObjectCacheImpl::FinalizeTree() {
  if (Root()->HasDirtyDescendants()) {
    HeapDeque<Member<AXObject>> objects_to_process;
    objects_to_process.push_back(Root());
    while (!objects_to_process.empty()) {
      AXObject* obj = objects_to_process.front();
      objects_to_process.pop_front();
      if (obj->IsDetached()) {
        continue;
      }
      obj->UpdateChildrenIfNecessary();
      if (obj->HasDirtyDescendants()) {
        obj->SetHasDirtyDescendants(false);
        for (auto& child : obj->ChildrenIncludingIgnored()) {
          objects_to_process.push_back(child);
        }
      }
    }
  }

  CheckTreeIsFinalized();
}

void AXObjectCacheImpl::CheckStyleIsComplete(Document& document) const {
#if EXPENSIVE_DCHECKS_ARE_ON()
  Element* root_element = document.documentElement();
  if (!root_element) {
    return;
  }

  {
    // Check that all style is up-to-date when layout is clean, when a11y is on.
    // This allows content-visibility: auto subtrees to have proper a11y
    // semantics, e.g. for the hidden and focusable states.
    Node* node = root_element;
    do {
      CHECK(!node->NeedsStyleRecalc()) << "Need style on: " << node;
      auto* element = DynamicTo<Element>(node);
      const ComputedStyle* style =
          element ? element->GetComputedStyle() : nullptr;
      if (!style || style->ContentVisibility() == EContentVisibility::kHidden ||
          style->IsEnsuredInDisplayNone()) {
        // content-visibility:hidden nodes are an exception and do not
        // compute style.
        node =
            LayoutTreeBuilderTraversal::NextSkippingChildren(*node, &document);
      } else {
        node = LayoutTreeBuilderTraversal::Next(*node, &document);
      }
    } while (node);
  }

  {
    // Check results of ChildNeedsStyleRecalc() as well, just to be sure there
    // isn't a discrepancy there.
    Node* node = root_element;
    do {
      auto* element = DynamicTo<Element>(node);
      const ComputedStyle* style =
          element ? element->GetComputedStyle() : nullptr;
      if (!style || style->ContentVisibility() == EContentVisibility::kHidden ||
          style->IsEnsuredInDisplayNone()) {
        // content-visibility:hidden nodes are an exception and do not
        // compute style.
        node =
            LayoutTreeBuilderTraversal::NextSkippingChildren(*node, &document);
        continue;
      }
      CHECK(!node->ChildNeedsStyleRecalc()) << "Need style on child: " << node;
      node = LayoutTreeBuilderTraversal::Next(*node, &document);
    } while (node);
  }
#endif
}

void AXObjectCacheImpl::CheckTreeIsFinalized() {
  CHECK(!Root()->NeedsToUpdateCachedValues());

#if DCHECK_IS_ON()

  // Skip check if document load is not complete.
  if (!GetDocument().IsLoadCompleted()) {
    return;
  }

  // After the first 5 checks, only check the tree every 5000 ms.
  tree_check_counter_++;
  auto now = base::Time::Now();
  if (tree_check_counter_ > 5 &&
      last_tree_check_time_stamp_ - now < base::Milliseconds(5000)) {
    return;
  }
  last_tree_check_time_stamp_ = now;

  // The following checks can make tests flaky if the tree being checked
  // is quite large. Therefore cap the number of objects we check.
  constexpr int kMaxObjectsToCheckAfterTreeUpdate = 5000;
  if (objects_.size() > kMaxObjectsToCheckAfterTreeUpdate) {
    DLOG(INFO)
        << "AXObjectCacheImpl::CheckTreeIsFinalized: Only checking first "
        << kMaxObjectsToCheckAfterTreeUpdate
        << " items in objects_ (size: " << objects_.size() << ")";
  }

  // First loop checks that tree structure is consistent.
  int count = 0;
  for (const auto& entry : objects_) {
    if (count > kMaxObjectsToCheckAfterTreeUpdate) {
      break;
    }

    const AXObject* object = entry.value;
    DCHECK(!object->IsDetached());
    DCHECK(object->GetDocument());
    DCHECK(object->GetDocument()->GetFrame())
        << "An object in a closed document should have been removed:"
        << "\n* Object: " << object;
    DCHECK(!object->IsMissingParent())
        << "No object should be missing its parent: " << "\n* Object: "
        << object << "\n* Computed parent: " << object->ComputeParent();
    // Check whether cached values need an update before using any getters that
    // will update them.
    DCHECK(!object->NeedsToUpdateCachedValues())
        << "No cached values should require an update: " << "\n* Object: "
        << object;
    DCHECK(!object->ChildrenNeedToUpdateCachedValues())
        << "Cached values for children should not require an update: "
        << "\n* Object: " << object;
    if (object->IsIncludedInTree()) {
      // All cached children must be included.
      for (const auto& child : object->CachedChildrenIncludingIgnored()) {
        CHECK(child->IsIncludedInTree())
            << "Included parent cannot have unincluded child:" << "\n* Parent: "
            << object << "\n* Child: " << child;
      }
      if (!object->IsRoot()) {
        // Parent must have this child in its cached children.
        AXObject* included_parent = object->ParentObjectIncludedInTree();
        CHECK(included_parent);
        const HeapVector<Member<AXObject>>& siblings =
            included_parent->CachedChildrenIncludingIgnored();
        DCHECK(siblings.Contains(object))
            << "Object was not included in its parent: " << "\n* Object: "
            << object
            << "\n* Included parent: " << included_parent;
      }
    }
    count++;
  }

  // Second loop checks that all dirty bits to update properties or children
  // have been cleared.
  count = 0;
  for (const auto& entry : objects_) {
    if (count > kMaxObjectsToCheckAfterTreeUpdate) {
      break;
    }
    const AXObject* object = entry.value;
    if (object->HasDirtyDescendants()) {
      // This an error: log the top ancestor that still has dirty descendants.
      const AXObject* ancestor = object;
      while (ancestor && ancestor->ParentObjectIncludedInTree() &&
             ancestor->ParentObjectIncludedInTree()->HasDirtyDescendants()) {
        ancestor = ancestor->ParentObjectIncludedInTree();
      }
      AXObject* included_parent = ancestor->ParentObjectIncludedInTree();
      if (!included_parent) {
        included_parent = Root();
      }
      DCHECK(!ancestor->HasDirtyDescendants())
          << "No subtrees should be flagged as needing updates at this point:"
          << "\n* Object: " << ancestor
          << "\n* Included parent: " << included_parent->GetAXTreeForThis();
    }
    AXObject* included_parent = object->ParentObjectIncludedInTree();
    if (!included_parent) {
      included_parent = Root();
    }
    DCHECK(!object->NeedsToUpdateChildren())
        << "No children in the tree should require an update at this point: "
        << "\n* Object: " << object
        << "\n* Included parent: " << included_parent;

    count++;
  }
#endif
}

int AXObjectCacheImpl::GetDeferredEventsDelay() const {
  // The amount of time, in milliseconds, to wait before sending non-interactive
  // events that are deferred before the initial page load.
  constexpr int kDelayForDeferredUpdatesBeforePageLoad = 350;

  // The amount of time, in milliseconds, to wait before sending non-interactive
  // events that are deferred after the initial page load.
  // Shync with same constant in CrossPlatformAccessibilityBrowserTest.
  constexpr int kDelayForDeferredUpdatesAfterPageLoad = 150;

  return GetDocument().IsLoadCompleted()
             ? kDelayForDeferredUpdatesAfterPageLoad
             : kDelayForDeferredUpdatesBeforePageLoad;
}

int AXObjectCacheImpl::GetLocationSerializationDelay() {
  // The amount of time, in milliseconds, to wait in between location updates
  // when the changed nodes don't include the focused node.
  constexpr int kDelayForLocationUpdatesNonFocused = 500;

  // The amount of time, in milliseconds, to wait in between location updates
  // when the changed nodes includes the focused node.
  constexpr int kDelayForLocationUpdatesFocused = 75;

  // It's important for the user to have access to any changes to the
  // currently focused object, so schedule serializations (almost )immediately
  // if that object changes. The root is an exception because it often has focus
  // while the page is loading.
  DOMNodeId focused_node_id = FocusedNode()->GetDomNodeId();
  if (focused_node_id != document_->GetDomNodeId() &&
      changed_bounds_ids_.Contains(focused_node_id)) {
    return kDelayForLocationUpdatesFocused;
  }

  return kDelayForLocationUpdatesNonFocused;
}

void AXObjectCacheImpl::CommitAXUpdates(Document& document, bool force) {
  if (IsPopup(document)) {
    // Only process popup document together with main document.
    DCHECK_EQ(&document, GetPopupDocumentIfShowing());
    // Since a change occurred in the popup, processing of both documents will
    // be needed. A visual update on the main document will force this.
    ScheduleAXUpdate();
    return;
  }

  DCHECK_EQ(document, GetDocument());
  if (!GetDocument().IsActive()) {
    return;
  }

  CheckStyleIsComplete(document);

  // Don't update the tree at an awkward time during page load.
  // Example: when the last node is whitespace, there is not yet enough context
  // to determine the relevance of the whitespace.
  if ((allowed_tree_update_pauses_remaining_ ||
       node_to_parse_before_more_tree_updates_) &&
      !force) {
    if (IsParsingMainDocument()) {
      return;
    }
    allowed_tree_update_pauses_remaining_ = 0;
    node_to_parse_before_more_tree_updates_ = nullptr;
  }

  if (tree_updates_paused_) {
    // Unpause tree updates and rebuild the tree from the root.
    // TODO(accessibility): Add more testing for this feature.
    // TODO(accessibility): Consider waiting until serialization batching timer
    // fires, so that the pause is a bit longer.
    LOG(INFO) << "Accessibility tree updates will be resumed after rebuilding "
                 "the tree from root";
    mark_all_dirty_ = true;
    tree_updates_paused_ = false;
  }

  // Something occurred which requires an immediate serialization.
  if (serialize_immediately_) {
    force = true;
    serialize_immediately_ = false;
  }

  if (!force) {
    // Process the current tree changes unless not enough time has passed, or
    // another serialization is already in flight.
    if (IsSerializationInFlight()) {
      // Another serialization is in flight. When it's finished, this method
      // will be called again.
      return;
    }

    const auto& now = base::Time::Now();
    const auto& delay_between_serializations =
        base::Milliseconds(GetDeferredEventsDelay());
    const auto& elapsed_since_last_serialization =
        now - last_serialization_timestamp_;
    const auto& delay_until_next_serialization =
        delay_between_serializations - elapsed_since_last_serialization;
    if (delay_until_next_serialization.is_positive()) {
      // No serialization needed yet, will serialize after a delay.
      // Set a timer to call this method again, if one isn't already set.
      if (!weak_factory_for_serialization_pipeline_.HasWeakCells()) {
        document.GetTaskRunner(blink::TaskType::kInternalDefault)
            ->PostDelayedTask(
                FROM_HERE,
                WTF::BindOnce(
                    &AXObjectCacheImpl::ScheduleAXUpdate,
                    WrapPersistent(weak_factory_for_serialization_pipeline_
                                       .GetWeakCell())),
                delay_until_next_serialization);
      }
      return;
    }
  }

  weak_factory_for_serialization_pipeline_.Invalidate();

  if (GetPopupDocumentIfShowing()) {
    UpdateLifecycleIfNeeded(*GetPopupDocumentIfShowing());
    CheckStyleIsComplete(*GetPopupDocumentIfShowing());
  }

  lifecycle_.AdvanceTo(AXObjectCacheLifecycle::kProcessDeferredUpdates);

  SCOPED_UMA_HISTOGRAM_TIMER_MICROS(
      "Accessibility.Performance.TotalAccessibilityCleanLayoutLifecycleStages");
  TRACE_EVENT0("accessibility",
               load_sent_
                   ? "TotalAccessibilityCleanLayoutLifecycleStages"
                   : "TotalAccessibilityCleanLayoutLifecycleStagesLoading");

  // Upon exiting this function, listen for tree updates again.
  absl::Cleanup lifecycle_returns_to_queueing_updates = [this] {
    lifecycle_.EnsureStateAtMost(AXObjectCacheLifecycle::kDeferTreeUpdates);
  };

  SCOPED_DISALLOW_LIFECYCLE_TRANSITION();

  // ------------ Process deferred events and update tree  --------------------
  {
    {
      SCOPED_UMA_HISTOGRAM_TIMER_MICROS(
          "Accessibility.Performance.ProcessDeferredUpdatesLifecycleStage");
      TRACE_EVENT0("accessibility",
                   load_sent_ ? "ProcessDeferredUpdatesLifecycleStage"
                              : "ProcessDeferredUpdatesLifecycleStageLoading");

      // If this is the first update, ensure that both an initial tree exists
      // and that the relation cache is initialized. Any existing content with
      // aria-owns relation be added to the relation cache's queue for
      // processing.
      EnsureRelationCacheAndInitialTree();

      // Update (create or remove) validation child of root, if it is needed, so
      // that the tree can be frozen in the correct state.
      ValidationMessageObjectIfInvalid();

      // If MarkDocumentDirty() was called, do it now, so that the entire tree
      // is invalidated before updating it.
      if (mark_all_dirty_) {
        MarkDocumentDirtyWithCleanLayout();
      }

      // Call the queued callback methods that do processing which must occur
      // when layout is clean. These callbacks are stored in
      // |tree_update_callback_queue_|, and have names like
      // FooBarredWithCleanLayout().
      if (IsDirty()) {
        if (GetPopupDocumentIfShowing()) {
          ProcessCleanLayoutCallbacks(*GetPopupDocumentIfShowing());
        }
        ProcessCleanLayoutCallbacks(document);
      }
    }

    // At this point, the popup queue should be clear, and we must ensure this
    // even if nothing is dirty. It seems that there are cases where it
    // IsDirty() returns false where there is no popup document, but there are
    // entries in the popup queue.
    // TODO(https://crbug.com/1507396): It is unclear when this happens, but it
    // explains why we still have a full popup queue in CheckTreeIsFinalized().
    // DCHECKs have been added elsewhere to help discover the underlying cause.
    // For now, keep this line in order to pass CheckTreeIsFinalized().
    tree_update_callback_queue_popup_.clear();

    {
#if defined(REDUCE_AX_INLINE_TEXTBOXES)
      // On Android, the inline textboxes of focused editable subtrees are
      // always loaded, but only if inline text boxes are enabled.
      if (ax_mode_.has_mode(ui::AXMode::kInlineTextBoxes)) {
        AXObject* focus = FocusedObject();
        if (focus && focus->IsEditableRoot()) {
          focus->LoadInlineTextBoxes();
        }
      }
#endif

      mark_all_dirty_ = false;

      // All tree updates have been processed.
      DUMP_WILL_BE_CHECK(!IsMainDocumentDirty());
      DUMP_WILL_BE_CHECK(!IsPopupDocumentDirty());

      // Clean up any remaining unprocessed aria-owns relations, which can
      // result from processing deferred tree updates. For example, if an object
      // is created without a parent, RepairChildrenOfIncludedParent() may be
      // called, which in some cases can queue multiple aria-owns relations that
      // point to the same node to be added to the processing queue.
      relation_cache_->ProcessUpdatesWithCleanLayout();

      EnsureFocusedObject();
      if (mark_all_dirty_) {
        // In some cases, EnsureFocusedObject() causes bad aria-hidden subtrees
        // to be removed, if they contained the focus. This can in turn lead to
        // marking the entire document dirty if a modal dialog or focus within
        // the modal dialog is removed.
        MarkDocumentDirtyWithCleanLayout();
        mark_all_dirty_ = false;
      }

      CHECK(tree_update_callback_queue_main_.empty());
      CHECK(tree_update_callback_queue_popup_.empty());
      CHECK(nodes_with_pending_children_changed_.empty());

      {
        lifecycle_.AdvanceTo(AXObjectCacheLifecycle::kFinalizingTree);
        SCOPED_UMA_HISTOGRAM_TIMER_MICROS(
            "Accessibility.Performance.FinalizingTreeLifecycleStage");
        TRACE_EVENT0("accessibility",
                     load_sent_ ? "FinalizingTreeLifecycleStage"
                                : "FinalizingTreeLifecycleStageLoading");

        // Build out tree, such that each node has computed its children.
        FinalizeTree();

        CHECK(tree_update_callback_queue_main_.empty());
        CHECK(tree_update_callback_queue_popup_.empty());
        CHECK(nodes_with_pending_children_changed_.empty());

        // Updating the tree did not add dirty objects.
        DUMP_WILL_BE_CHECK(!IsDirty())
            << "Cache dirtied at bad time:" << "\nAll: " << mark_all_dirty_
            << "\nRoot children: " << Root()->NeedsToUpdateChildren()
            << "\nRoot descendants: " << Root()->HasDirtyDescendants()
            << "\nRelation cache: " << relation_cache_->IsDirty()
            << "\nUpdates paused: " << tree_updates_paused_;
      }
    }
  }

  lifecycle_.AdvanceTo(AXObjectCacheLifecycle::kSerialize);
  SCOPED_UMA_HISTOGRAM_TIMER_MICROS(
      "Accessibility.Performance.SerializeLifecycleStage");
  TRACE_EVENT0("accessibility", load_sent_ ? "SerializeLifecycleStage"
                                           : "SerializeLifecycleStageLoading");

  // Check whether serializations are needed, or whether we are just here to
  // update as part of a tree snapshot.
  if (!ax_mode_.has_mode(ui::AXMode::kWebContents)) {
    return;
  }

  // Serialize the current tree changes unless not enough time has passed, or
  // another serialization is already in flight.
  if (IsSerializationInFlight()) {
    // Another serialization is in flight. When it's finished, this method
    // will be called again.
    return;
  }

  // ------------------------ Freeze and serialize ---------------------------
  {
    // The frozen state begins immediately after processing deferred events.
    ScopedFreezeAXCache scoped_freeze_cache(*this);

    // ***** Serialize *****
    // Check whether there are dirty objects ready to be serialized.
    // TODO(accessibility) It's a bit confusing that this can be true when the
    // IsDirty() is false, but this is the case for objects marked dirty from
    // RenderAccessibilityImpl, e.g. for the kEndOfTest event.
    bool did_serialize = false;
    if (HasObjectsPendingSerialization()) {
      did_serialize = SerializeUpdatesAndEvents();
    }

    // ***** Serialize Location Changes *****
    // Even if there are no dirty objects, we ensure pending location changes
    // are sent.
    if (reset_token_ && !changed_bounds_ids_.empty()) {
      DCHECK(!did_serialize);  // Location changes should have been sent with
                               // full serialization.
      SerializeLocationChanges();
    }

    // ***** Update Inspector Views *****
    // Accessibility is now clean for both documents: AXObjects can be safely
    // traversed and AXObject's properties can be safely fetched.
    // TODO(accessibility) Now that both documents are always processed at the
    // same time, consider modifying the InspectorAccessibilityAgent so that
    // only the callback for the main document is needed.
    for (auto agent : agents_) {
      agent->AXReadyCallback(document);
      if (GetPopupDocumentIfShowing()) {
        agent->AXReadyCallback(*GetPopupDocumentIfShowing());
      }
    }

    DUMP_WILL_BE_CHECK(!IsDirty());
    // TODO(accessibility): in the future, we may break up serialization into
    // pieces to reduce jank, in which case this assertion will not hold.
    DUMP_WILL_BE_CHECK(!HasObjectsPendingSerialization() || !did_serialize)
        << "A serialization occurred but dirty objects remained.";
  }
}

bool AXObjectCacheImpl::SerializeUpdatesAndEvents() {
  CHECK(HasObjectsPendingSerialization());
  CHECK(!IsSerializationInFlight());
  DCHECK(!ax_mode_.is_mode_off());
  CHECK(ax_mode_.has_mode(ui::AXMode::kWebContents));
  CHECK(lifecycle_.StateAllowsSerialization()) << *this;

  if (!GetDocument().GetFrame()) {
    return false;
  }

  // Dirty objects are present, but we cannot serialize until there is an
  // embedding token, which may not be present when the cache is first
  // initialized.
  const std::optional<base::UnguessableToken>& embedding_token =
      GetDocument().GetFrame()->GetEmbeddingToken();
  if (!embedding_token || embedding_token->is_empty()) {
    return false;
  }

  auto* client = GetWebLocalFrameClient();
  CHECK(client);

  // TODO(accessibility): Review why this value is inconsistent with
  //       ax_mode_.has_mode(ui::AXMode::kWebContents)
  if (!client->IsAccessibilityEnabled()) {
    return false;
  }

  OnSerializationStartSend();

  bool had_end_of_test_event = false;

  // Keep track of load complete messages. When a load completes, it's a good
  // time to inject a stylesheet for image annotation debugging.
  bool had_load_complete_messages = false;

  std::vector<ui::AXTreeUpdate> updates;
  std::vector<ui::AXEvent> events;

  // Serialize all dirty objects in the list at this point in time, stopping
  // either when the queue is empty, or the number of remaining objects to
  // serialize has been reached.
  GetUpdatesAndEventsForSerialization(updates, events, had_end_of_test_event,
                                      had_load_complete_messages);

  /* Clear the pending updates and events as they're about to be serialized */
  pending_objects_to_serialize_.clear();
  pending_events_to_serialize_.clear();

  if (had_end_of_test_event) {
    ui::AXEvent end_of_test(Root()->AXObjectID(),
                            ax::mojom::blink::Event::kEndOfTest);
    if (!IsDirty() && GetDocument().IsLoadCompleted()) {
      // Everything is clean and the document is fully loaded, so kEndOfTest
      // signal can be fired.
      events.emplace_back(end_of_test);
    } else {
      DLOG(ERROR) << "Had end of test event, but document is still dirty.";
      // Document is still dirty, queue up another end of test and process
      // immediately.
      AddEventToSerializationQueue(end_of_test, /*serialize_immediately*/ true);
    }
  }

  // upd
"""


```