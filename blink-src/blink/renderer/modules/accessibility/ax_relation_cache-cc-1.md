Response:
The user wants a summary of the functionalities of the provided C++ code snippet for `AXRelationCache`. I need to go through the code, identify its main purposes and how it interacts with other parts of the Blink rendering engine, specifically focusing on accessibility, JavaScript, HTML, and CSS. I should also pay attention to potential user/programming errors and how to debug issues related to this code.

Here's a breakdown of the functionalities I can identify:

1. **Managing ARIA `owns` relationships:** The code handles the `aria-owns` attribute, tracking which elements own other elements for accessibility purposes. This involves mapping owners to owned children and vice versa. It ensures that only valid `owns` relationships are established and manages updates to these relationships.

2. **Managing ARIA label and description relationships:** The code manages relationships established by `aria-labelledby` and `aria-describedby` attributes, and the `<label for="...">` element. It tracks which elements provide labels or descriptions for other elements.

3. **Managing other ARIA relationships:** The code handles other ARIA attributes like `aria-controls`, `aria-details`, `aria-errormessage`, `aria-flowto`, and `aria-activedescendant`.

4. **Updating the accessibility tree:**  The code ensures that changes in these relationships are reflected in the accessibility tree, triggering updates when necessary.

5. **Handling dynamically added/removed elements:** The code handles cases where elements are added or removed from the DOM, updating the relationship mappings accordingly.

6. **CSS `anchor()` functionality:** The code manages the relationship between positioned elements and their CSS anchors, used for scroll anchoring.

7. **Error prevention and consistency:** The code includes checks and logic to prevent invalid relationships and ensure consistency in the accessibility tree.

Based on these functionalities, I can now formulate the summary.
```
功能归纳：

AXRelationCache 的主要功能是管理和维护 Blink 渲染引擎中用于辅助功能 (Accessibility) 的各种对象关系。它负责跟踪和更新由 HTML 属性 (如 `aria-owns`, `aria-labelledby`, `aria-describedby`, `<label for="...">` 等) 和 CSS 功能 (`anchor()`) 定义的 DOM 元素之间的关系。  其核心目标是确保辅助技术 (如屏幕阅读器) 能够正确理解网页的结构和语义。

**具体功能点:**

1. **管理 `aria-owns` 关系:**
    *   **功能:** 跟踪哪个元素通过 `aria-owns` 属性拥有 (parent) 哪些其他元素 (children)。这允许开发者在 DOM 树结构之外指定逻辑上的父子关系，特别是在动态内容或复杂组件中。
    *   **机制:** 维护 `aria_owner_to_children_mapping_` (owner AXID 到子 AXID 列表的映射) 和 `aria_owned_child_to_owner_mapping_` (子 AXID 到 owner AXID 的映射)。
    *   **更新:** 当 `aria-owns` 属性发生变化时，更新这些映射，并通知相关的 AXObject 进行更新。

2. **管理 ARIA 文本关联关系 (`aria-labelledby`, `aria-describedby`) 和 `<label for="...">`:**
    *   **功能:**  跟踪哪些元素作为其他元素的标签或描述。
    *   **机制:**  维护 `aria_text_relations_node_map_` (作为标签/描述的元素节点 ID 到被标记/描述的元素节点 ID 列表的映射) 和 `aria_text_relations_id_map_` (作为标签/描述的元素 ID 到被标记/描述的元素节点 ID 列表的映射)。 对于 `<label for="...">`，则使用 `all_previously_seen_label_target_ids_` 来跟踪已知的目标 ID。
    *   **更新:** 当这些属性或 `<label>` 元素发生变化时，更新这些映射，并通知相关的 AXObject 进行更新，以便重新计算其可访问名称或描述。

3. **管理其他 ARIA 关系 (`aria-controls`, `aria-details`, `aria-errormessage`, `aria-flowto`, `aria-activedescendant` 等):**
    *   **功能:**  跟踪这些 ARIA 属性定义的关系，例如哪个元素控制着哪个元素，哪个元素是错误消息等。
    *   **机制:**  维护 `aria_other_relations_id_map_` 和 `aria_other_relations_node_map_` 来存储这些关系。
    *   **更新:** 当这些属性发生变化时，更新映射并通知相关的 AXObject 进行更新，以便触发相应的辅助功能事件或更新属性。

4. **管理 CSS `anchor()` 相关的关系:**
    *   **功能:** 跟踪通过 CSS `anchor()` 功能定义的定位元素和其锚点元素之间的关系。
    *   **机制:** 维护 `positioned_obj_to_anchor_mapping_` (定位元素的 AXID 到锚点元素的 AXID 的映射) 和 `anchor_to_positioned_obj_mapping_` (锚点元素的 AXID 到定位元素的 AXID 的映射)。
    *   **更新:** 当元素的布局对象或其 `accessibility-anchor` 发生变化时，更新这些映射。

5. **延迟更新和优化:**
    *   **功能:**  收集需要更新的 AXObject，并在适当的时机 (通常是在布局完成后) 执行批量更新，以提高性能。
    *   **机制:** 使用 `owner_axids_to_update_` 存储需要更新的 owner AXID。
    *   **方法:** `ProcessUpdatesWithCleanLayout()` 方法用于执行这些延迟更新。

6. **对象缓存交互:**
    *   **功能:**  与 `AXObjectCache` 紧密协作，获取和创建 AXObject，并标记 AXObject 为 dirty，以便在后续更新中重新计算其属性。
    *   **方法:**  使用 `object_cache_->Get()`, `object_cache_->GetOrCreate()`, `object_cache_->MarkAXObjectDirtyWithCleanLayout()` 等方法。

7. **处理元素的添加和删除:**
    *   **功能:**  当 DOM 元素被添加或删除时，更新相应的关系映射，以保持辅助功能信息的准确性。
    *   **方法:** `RemoveAXID()` 和 `RemoveOwnedRelation()` 用于在 AXObject 被移除时清理相关的关系映射。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

*   **HTML:** `AXRelationCache` 直接处理 HTML 属性，例如 `aria-owns`, `aria-labelledby`, `aria-describedby`, 以及 `<label>` 元素。
    *   **举例:** 当 HTML 中某个元素的 `aria-owns` 属性被修改时，例如从 `<div id="owner" aria-owns="owned1"></div>` 变为 `<div id="owner" aria-owns="owned2"></div>`，`AXRelationCache` 会更新 `aria_owner_to_children_mapping_`，将 `owner` 的子元素列表从包含 `owned1` 的 AXObject 改为包含 `owned2` 的 AXObject。

*   **JavaScript:** JavaScript 可以动态地修改这些 HTML 属性，从而触发 `AXRelationCache` 的更新。
    *   **假设输入:** JavaScript 代码执行 `document.getElementById('owner').setAttribute('aria-owns', 'newlyOwned');`
    *   **输出:** `AXRelationCache` 会监听到 `aria-owns` 属性的变化，更新内部映射，并将 `owner` 的 AXObject 标记为 dirty，以便在下次更新时反映新的 `owns` 关系。

*   **CSS:** `AXRelationCache` 涉及到 CSS 的 `anchor()` 功能。
    *   **举例:** 当一个元素的 CSS 中设置了 `position: sticky; anchor-name: --my-anchor;`，并且另一个元素设置了 `scroll-anchoring: anchor(--my-anchor);`，`AXRelationCache` 会将这两个元素关联起来，存储在 `positioned_obj_to_anchor_mapping_` 和 `anchor_to_positioned_obj_mapping_` 中。

**逻辑推理的假设输入与输出：**

*   **假设输入:**  HTML 代码片段如下：
    ```html
    <div id="label">This is a label</div>
    <input type="text" aria-labelledby="label">
    ```
*   **输出:** `aria_text_relations_id_map_` 中会存在一个条目，键为 `"label"`，值为包含 `input` 元素 AXID 的列表。当辅助技术查询 `input` 元素的 accessible name 时，`AXRelationCache` 会提供来自 `label` 元素的内容。

**用户或编程常见的使用错误及举例说明：**

*   **错误使用 `aria-owns`:**  开发者可能会错误地使用 `aria-owns` 来表示视觉上的包含关系，而不是逻辑上的父子关系。
    *   **举例:**  一个模态框可能在 DOM 结构上是 `body` 的子元素，但逻辑上“拥有”触发它的按钮。如果开发者错误地使用 `aria-owns` 将 `body` 作为模态框的 owner，可能会导致辅助技术理解上的偏差。
*   **`aria-labelledby` 或 `aria-describedby` 指向不存在的 ID:** 如果 `aria-labelledby` 或 `aria-describedby` 属性引用的 ID 在页面中不存在，`AXRelationCache` 将无法建立正确的文本关联，导致辅助技术无法获取到相应的标签或描述。
    *   **举例:**  `<input type="text" aria-labelledby="nonexistent-id">`，由于 `"nonexistent-id"` 不存在，该输入框将没有关联的标签。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户交互导致 DOM 变化:** 用户与网页进行交互，例如点击按钮、输入文本、滚动页面等，这些操作可能会导致 DOM 结构或属性发生变化。
2. **Blink 渲染引擎处理 DOM 变化:** Blink 渲染引擎会监听这些 DOM 变化。
3. **触发辅助功能更新:** 当涉及到与辅助功能相关的属性 (如 ARIA 属性) 发生变化时，Blink 会通知 `AXRelationCache`。
4. **`AXRelationCache` 更新内部映射:** `AXRelationCache` 会根据变化的属性值，更新其内部维护的各种关系映射。
5. **标记 AXObject 为 dirty:**  `AXRelationCache` 会将受到影响的 AXObject 标记为 dirty，以便在后续的辅助功能树更新中重新计算其属性。
6. **辅助功能树更新:**  在适当的时机，Blink 会根据标记为 dirty 的 AXObject 重新构建或更新辅助功能树。
7. **辅助技术获取信息:**  辅助技术 (如屏幕阅读器) 会从更新后的辅助功能树中获取信息，并呈现给用户。

**调试线索示例：**

假设用户报告屏幕阅读器无法正确读出某个元素的标签。作为调试人员，你可以：

1. 检查该元素的 HTML 代码，查看是否使用了 `aria-labelledby` 或 `<label for="...">` 属性。
2. 如果使用了 `aria-labelledby`，检查引用的 ID 是否正确，对应的元素是否存在。
3. 如果使用了 `<label for="...">`，检查 `for` 属性的值是否与目标元素的 `id` 属性值匹配。
4. 可以使用浏览器的开发者工具 (例如 Chrome 的 Accessibility 标签) 来查看元素的辅助功能属性，确认是否成功关联了标签。
5. 如果怀疑是动态更新导致的问题，可以在 JavaScript 代码中设置断点，观察在属性修改前后 `AXRelationCache` 的内部状态，例如相关映射是否正确更新。

总而言之，`AXRelationCache` 是 Blink 引擎中一个至关重要的组件，它负责维护网页元素的辅助功能关系，确保辅助技术能够准确理解和呈现网页内容，从而提升残障用户的浏览体验。
```
Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_relation_cache.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
ml_names::kAriaOwnsAttr));
    HeapVector<Member<Element>> valid_owned_child_elements;
    for (AtomicString id_name : owned_id_vector) {
      Element* child_element = scope.getElementById(id_name);
      if (!child_element ||
          !IsValidOwnsRelation(const_cast<AXObject*>(owner), *child_element)) {
        continue;
      }
      AXID future_child_axid = child_element->GetDomNodeId();
      HashMap<AXID, AXID>::const_iterator iter =
          aria_owned_child_to_owner_mapping_.find(future_child_axid);
      bool has_previous_owner =
          iter != aria_owned_child_to_owner_mapping_.end();
      if (has_previous_owner && owner->AXObjectID() != iter->value) {
        // Already has a different aria-owns parent.
        continue;
      }

      // Preemptively add the child to owner mapping to satisfy checks
      // that this child is owned, and therefore does not need to be added by
      // any other node who's subtree is eagerly updated during the
      // GetOrCreate() call, as this call recursively fills out subtrees.
      aria_owned_child_to_owner_mapping_.Set(future_child_axid,
                                             owner->AXObjectID());
      if (!has_previous_owner) {
        // Force UpdateAriaOwnerToChildrenMappingWithCleanLayout() to map
        // the new owner.
        force = true;
      }
      valid_owned_child_elements.emplace_back(child_element);
    }

    for (Element* child_element : valid_owned_child_elements) {
      AXObject* child = GetOrCreate(child_element, owner);
      if (child) {
        owned_children.push_back(child);
      }
    }
  }

  // Update the internal validated mapping of owned children. This will
  // fire an event if the mapping has changed.
  UpdateAriaOwnerToChildrenMappingWithCleanLayout(owner, owned_children, force);
}

void AXRelationCache::UpdateAriaOwnerToChildrenMappingWithCleanLayout(
    AXObject* owner,
    HeapVector<Member<AXObject>>& validated_owned_children_result,
    bool force) {
  DCHECK(owner);
  if (!owner->CanHaveChildren())
    return;

  Vector<AXID> validated_owned_child_axids;
  for (auto& child : validated_owned_children_result) {
    validated_owned_child_axids.push_back(child->AXObjectID());
  }

  // Compare this to the current list of owned children, and exit early if
  // there are no changes.
  Vector<AXID> previously_owned_child_ids;
  auto it = aria_owner_to_children_mapping_.find(owner->AXObjectID());
  if (it != aria_owner_to_children_mapping_.end()) {
    previously_owned_child_ids = it->value;
  }

  // Only force the refresh if there was or will be owned children; otherwise,
  // there is nothing to refresh even for a new AXObject replacing an old owner.
  if (previously_owned_child_ids == validated_owned_child_axids &&
      (!force || previously_owned_child_ids.empty())) {
    return;
  }

  // The list of owned children has changed. Even if they were just reordered,
  // to be safe and handle all cases we remove all of the current owned
  // children and add the new list of owned children.
  Vector<AXID> unparented_child_ids;
  UnmapOwnedChildrenWithCleanLayout(owner, previously_owned_child_ids,
                                    unparented_child_ids);
  MapOwnedChildrenWithCleanLayout(owner, validated_owned_child_axids);

#if DCHECK_IS_ON()
  // Owned children must be in tree to avoid serialization issues.
  for (AXObject* child : validated_owned_children_result) {
    DCHECK(IsAriaOwned(child));
    DCHECK(child->ComputeIsIgnoredButIncludedInTree())
        << "Owned child not in tree: " << child
        << "\nRecompute included in tree: "
        << child->ComputeIsIgnoredButIncludedInTree();
  }
#endif

  // Finally, update the mapping from the owner to the list of child IDs.
  if (validated_owned_child_axids.empty()) {
    aria_owner_to_children_mapping_.erase(owner->AXObjectID());
  } else {
    aria_owner_to_children_mapping_.Set(owner->AXObjectID(),
                                        validated_owned_child_axids);
  }

  // Ensure that objects that have lost their parent have one, or that their
  // subtree is pruned if there is no available parent.
  for (AXID unparented_child_id : unparented_child_ids) {
    if (validated_owned_child_axids.Contains(unparented_child_id)) {
      continue;
    }
    // Recompute the real parent and cache it.
    if (AXObject* ax_unparented = ObjectFromAXID(unparented_child_id)) {
      // Invalidating ensures that cached "included in tree" state is recomputed
      // on objects with changed ownership -- owned children must always be
      // included in the tree.
      ax_unparented->InvalidateCachedValues();

      // Find the unparented child's new parent, and reparent it to that
      // back to its real parent in the tree by finding  its current parent,
      // marking that dirty and detaching from that parent.
      AXObject* original_parent = ax_unparented->ParentObjectIfPresent();

      // Recompute the real parent .
      ax_unparented->DetachFromParent();
      MaybeRestoreParentOfOwnedChild(unparented_child_id);

      // Mark everything dirty so that the serializer sees all changes.
      ChildrenChangedWithCleanLayout(original_parent);
      ChildrenChangedWithCleanLayout(ax_unparented->ParentObjectIfPresent());
      if (!ax_unparented->IsDetached()) {
        object_cache_->MarkAXObjectDirtyWithCleanLayout(ax_unparented);
      }
    }
  }

  ChildrenChangedWithCleanLayout(owner);
}

bool AXRelationCache::MayHaveHTMLLabelViaForAttribute(
    const HTMLElement& labelable) {
  const AtomicString& id = labelable.GetIdAttribute();
  if (id.empty())
    return false;
  return all_previously_seen_label_target_ids_.Contains(id);
}

bool AXRelationCache::IsARIALabelOrDescription(Element& element) {
  // Labels and descriptions set by ariaLabelledByElements,
  // ariaDescribedByElements.
  if (aria_text_relations_node_map_.find(element.GetDomNodeId()) !=
      aria_text_relations_node_map_.end()) {
    return true;
  }

  // Labels and descriptions set by aria-labelledby, aria-describedby.
  const AtomicString& id_value = element.GetIdAttribute();
  if (id_value.IsNull()) {
    return false;
  }

  bool found_in_id_mapping = aria_text_relations_id_map_.find(id_value) !=
                             aria_text_relations_id_map_.end();
  return found_in_id_mapping;
}

// Fill source_objects with AXObjects for relations pointing to target.
void AXRelationCache::GetRelationSourcesById(
    const AtomicString& target_id_attr,
    TargetIdToSourceNodeMap& id_map,
    HeapVector<Member<AXObject>>& source_objects) {
  if (target_id_attr == g_null_atom) {
    return;
  }

  auto it = id_map.find(target_id_attr);
  if (it == id_map.end()) {
    return;
  }

  for (DOMNodeId source_node : it->value) {
    AXObject* source_object = Get(DOMNodeIds::NodeForId(source_node));
    if (source_object)
      source_objects.push_back(source_object);
  }
}

void AXRelationCache::GetRelationSourcesByElementReference(
    const DOMNodeId target_node,
    TargetNodeToSourceNodeMap& node_map,
    HeapVector<Member<AXObject>>& source_objects) {
  auto it = node_map.find(target_node);
  if (it == node_map.end()) {
    return;
  }

  for (const DOMNodeId& source_node : it->value) {
    AXObject* source_object = Get(DOMNodeIds::NodeForId(source_node));
    if (source_object) {
      source_objects.push_back(source_object);
    }
  }
}

AXObject* AXRelationCache::GetOrCreateAriaOwnerFor(Node* node, AXObject* obj) {
  CHECK(object_cache_->lifecycle().StateAllowsImmediateTreeUpdates());

  Element* element = DynamicTo<Element>(node);
  if (!element) {
    return nullptr;
  }

#if DCHECK_IS_ON()
  if (obj)
    DCHECK(!obj->IsDetached());
  AXObject* obj_for_node = object_cache_->Get(node);
  DCHECK(!obj || obj_for_node == obj)
      << "Object and node did not match:" << "\n* node = " << node
      << "\n* obj = " << obj << "\n* obj_for_node = " << obj_for_node;
#endif

  // Look for any new aria-owns relations.
  // Schedule an update on any potential new owner.
  HeapVector<Member<AXObject>> related_sources;
  GetRelationSourcesById(element->GetIdAttribute(), aria_owns_id_map_,
                         related_sources);
  GetRelationSourcesByElementReference(element->GetDomNodeId(),
                                       aria_owns_node_map_, related_sources);

  // First check for an existing aria-owns relation to the related AXObject.
  AXObject* ax_new_owner = nullptr;
  for (AXObject* related : related_sources) {
    if (related) {
      // Ensure that the candidate owner updates its children in its validity
      // as an owner is changing.
      owner_axids_to_update_.insert(related->AXObjectID());
      object_cache_->MarkAXObjectDirtyWithCleanLayout(related);
      related->SetNeedsToUpdateChildren();
      if (IsValidOwnsRelation(related, *node)) {
        if (!ax_new_owner) {
          ax_new_owner = related;
        }
        owner_axids_to_update_.insert(related->AXObjectID());
      }
    }
  }

  // Schedule an update on any previous owner. This owner takes priority over
  // any new owners.
  AXObject* related_target = obj ? obj : Get(node);
  if (related_target && IsAriaOwned(related_target)) {
    AXObject* ax_previous_owner = ValidatedAriaOwner(related_target);
    if (ax_previous_owner) {
      owner_axids_to_update_.insert(ax_previous_owner->AXObjectID());
      return ax_previous_owner;
    }
  }

  // Only the first aria-owns relation can be used.
  return ax_new_owner;
}

void AXRelationCache::UpdateRelatedTree(Node* node, AXObject* obj) {
  // This can happen if MarkAXObjectDirtyWithCleanLayout is
  // called and then UpdateRelatedTree is called on the same object,
  // e.g. in TextChangedWithCleanLayout.
  if (obj && obj->IsDetached()) {
    return;
  }

  if (GetOrCreateAriaOwnerFor(node, obj)) {
    // Ensure the aria-owns relation is processed, which in turn ensures that
    // both the owner and owned child exist, and that the parent-child
    // relations are correctly set on each.
    ProcessUpdatesWithCleanLayout();
  }

  // Update names and descriptions.
  UpdateRelatedText(node);
}

void AXRelationCache::UpdateRelatedTreeAfterChange(Element& element) {
  // aria-activedescendant requires special handling, because additional events
  // may be fired when it changes.
  // Check whether aria-activedescendant on the focused object points to
  // `element`. If so, fire activedescendantchanged event now. This is only for
  // ARIA active descendants, not in a native control like a listbox, which
  // has its own initial active descendant handling.
  MarkOldAndNewRelationSourcesDirty(element, aria_activedescendant_id_map_,
                                    aria_activedescendant_node_map_);
  Element* focused_element = element.GetDocument().FocusedElement();
  if (AXObject* ax_focus = Get(focused_element)) {
    if (AXObject::ElementFromAttributeOrInternals(
            focused_element, html_names::kAriaActivedescendantAttr) ==
        &element) {
      ax_focus->HandleActiveDescendantChanged();
    }
  }

  // aria-labelledby and aria-describedby.
  // Additional processing occurs in UpdateRelatedTree() when any node within
  // the label or description subtree changes.
  MarkOldAndNewRelationSourcesDirty(element, aria_text_relations_id_map_,
                                    aria_text_relations_node_map_);

  // aria-controls, aria-details, aria-errormessage, aria-flowto, and
  // aria-actions.
  MarkOldAndNewRelationSourcesDirty(element, aria_other_relations_id_map_,
                                    aria_other_relations_node_map_);
  UpdateReverseOtherRelations(element);

  // Finally, update the registered id attribute for this element.
  UpdateRegisteredIdAttribute(element, element.GetDomNodeId());
}

void AXRelationCache::UpdateRegisteredIdAttribute(Element& element,
                                                  DOMNodeId node_id) {
  const auto& id_attr = element.GetIdAttribute();
  if (id_attr == g_null_atom) {
    registered_id_attributes_.erase(node_id);
  } else {
    registered_id_attributes_.Set(node_id, id_attr);
  }
}

void AXRelationCache::UpdateRelatedText(Node* node) {
  // Shortcut: used cached value to determine whether this node contributes to
  // a name or description. Return early if not.
  if (AXObject* obj = Get(node)) {
    if (!obj->IsUsedForLabelOrDescription()) {
      // Nothing to do, as this node is not part of a label or description.
      return;
    }
  }

  // Walk up ancestor chain from node and refresh text of any related content.
  // TODO(crbug.com/1109265): It's very likely this loop should only walk the
  // unignored AXObject chain, but doing so breaks a number of tests related to
  // name or description computation / invalidation.
  int count = 0;
  constexpr int kMaxAncestorsForNameChangeCheck = 8;
  for (Node* current_node = node;
       ++count < kMaxAncestorsForNameChangeCheck && current_node &&
       !IsA<HTMLBodyElement>(current_node);
       current_node = current_node->parentNode()) {
    if (Element* element = DynamicTo<Element>(current_node)) {
      // Reverse relations via aria-labelledby, aria-describedby, aria-owns.
      HeapVector<Member<AXObject>> related_sources;
      GetRelationSourcesById(element->GetIdAttribute(),
                             aria_text_relations_id_map_, related_sources);
      GetRelationSourcesByElementReference(element->GetDomNodeId(),
                                           aria_text_relations_node_map_,
                                           related_sources);
      for (AXObject* related : related_sources) {
        if (related && related->IsIncludedInTree() &&
            !related->NeedsToUpdateChildren()) {
          object_cache_->MarkAXObjectDirtyWithCleanLayout(related);
        }
      }
    }

    // Ancestors that may derive their accessible name from descendant content
    // should also handle text changed events when descendant content changes.
    if (current_node != node) {
      AXObject* obj = Get(current_node);
      if (obj &&
          (!obj->IsIgnored() || obj->CanSetFocusAttribute()) &&
          obj->SupportsNameFromContents(/*recursive=*/false) &&
          !obj->NeedsToUpdateChildren()) {
        object_cache_->MarkAXObjectDirtyWithCleanLayout(obj);
        break;  // Unlikely/unusual to need multiple name/description changes.
      }
    }

    // Forward relation via <label for="[id]">.
    if (HTMLLabelElement* label = DynamicTo<HTMLLabelElement>(current_node)) {
      object_cache_->MarkElementDirtyWithCleanLayout(LabelChanged(*label));
      break;  // Unlikely/unusual to need multiple name/description changes.
    }
  }
}

void AXRelationCache::MarkOldAndNewRelationSourcesDirty(
    Element& element,
    TargetIdToSourceNodeMap& id_map,
    TargetNodeToSourceNodeMap& node_map) {
  HeapVector<Member<AXObject>> related_sources;
  const AtomicString& id_attr = element.GetIdAttribute();
  GetRelationSourcesById(id_attr, id_map, related_sources);

  const DOMNodeId dom_node_id = element.GetDomNodeId();
  GetRelationSourcesByElementReference(dom_node_id, node_map, related_sources);

  // If id attribute changed, also mark old relation source dirty, and update
  // the map that points from the id attribute to the node id
  auto iter = registered_id_attributes_.find(element.GetDomNodeId());
  if (iter != registered_id_attributes_.end()) {
    const AtomicString& old_id_attr = iter->value;
    if (old_id_attr != id_attr) {
      GetRelationSourcesById(old_id_attr, id_map, related_sources);
    }
  }
  for (AXObject* related : related_sources) {
    object_cache_->MarkAXObjectDirtyWithCleanLayout(related);
  }
}

void AXRelationCache::UpdateCSSAnchorFor(Node* positioned_node) {
  // Remove existing mapping.
  AXID positioned_id = positioned_node->GetDomNodeId();
  if (positioned_obj_to_anchor_mapping_.Contains(positioned_id)) {
    AXID prev_anchor = positioned_obj_to_anchor_mapping_.at(positioned_id);
    anchor_to_positioned_obj_mapping_.erase(prev_anchor);
    positioned_obj_to_anchor_mapping_.erase(positioned_id);
    object_cache_->MarkAXObjectDirtyWithCleanLayout(
        ObjectFromAXID(prev_anchor));
  }

  LayoutBox* layout_box =
      DynamicTo<LayoutBox>(positioned_node->GetLayoutObject());
  if (!layout_box) {
    return;
  }

  Element* anchor = layout_box->AccessibilityAnchor();
  if (!anchor) {
    return;
  }

  // AccessibilityAnchor() only returns an anchor if there is one anchor, so
  // the map is only updated when there is a 1:1 anchor to positioned element
  // mapping.
  AXID anchor_id = anchor->GetDomNodeId();
  anchor_to_positioned_obj_mapping_.Set(anchor_id, positioned_id);
  positioned_obj_to_anchor_mapping_.Set(positioned_id, anchor_id);
  object_cache_->MarkElementDirtyWithCleanLayout(anchor);
}

AXObject* AXRelationCache::GetPositionedObjectForAnchor(
    const AXObject* anchor) {
  HashMap<AXID, AXID>::const_iterator iter =
      anchor_to_positioned_obj_mapping_.find(anchor->AXObjectID());
  if (iter == anchor_to_positioned_obj_mapping_.end()) {
    return nullptr;
  }
  return ObjectFromAXID(iter->value);
}

AXObject* AXRelationCache::GetAnchorForPositionedObject(
    const AXObject* positioned_obj) {
  HashMap<AXID, AXID>::const_iterator iter =
      positioned_obj_to_anchor_mapping_.find(positioned_obj->AXObjectID());
  if (iter == positioned_obj_to_anchor_mapping_.end()) {
    return nullptr;
  }
  return ObjectFromAXID(iter->value);
}

void AXRelationCache::RemoveAXID(AXID obj_id) {
  // Need to remove from maps.
  // There are maps from children to their owners, and owners to their children.
  // In addition, the removed id may be an owner, or be owned, or both.

  // |obj_id| owned others:
  if (aria_owner_to_children_mapping_.Contains(obj_id)) {
    // |obj_id| no longer owns anything.
    Vector<AXID> child_axids = aria_owner_to_children_mapping_.at(obj_id);
    aria_owned_child_to_owner_mapping_.RemoveAll(child_axids);
    // Owned children are no longer owned by |obj_id|
    aria_owner_to_children_mapping_.erase(obj_id);
    // When removing nodes in AXObjectCacheImpl::Dispose we do not need to
    // reparent (that could anyway fail trying to attach to an already removed
    // node.
    // TODO(jdapena@igalia.com): explore if we can skip all processing of the
    // mappings in AXRelationCache in dispose case.
    if (!object_cache_->IsDisposing()) {
      for (const auto& child_axid : child_axids) {
        if (AXObject* owned_child = ObjectFromAXID(child_axid)) {
          owned_child->DetachFromParent();
          CHECK(object_cache_->lifecycle().StateAllowsReparentingAXObjects())
              << "Removing owned child at a bad time, which leads to "
                 "parentless objects at a bad time: "
              << owned_child;
        }
        MaybeRestoreParentOfOwnedChild(child_axid);
      }
    }
    registered_id_attributes_.erase(obj_id);
  }

  // Another id owned |obj_id|:
  RemoveOwnedRelation(obj_id);
}

void AXRelationCache::RemoveOwnedRelation(AXID obj_id) {
  // Another id owned |obj_id|.
  if (aria_owned_child_to_owner_mapping_.Contains(obj_id)) {
    CHECK(object_cache_->lifecycle().StateAllowsReparentingAXObjects());
    // Previous owner no longer relevant to this child.
    // Also, remove |obj_id| from previous owner's owned child list:
    AXID owner_id = aria_owned_child_to_owner_mapping_.Take(obj_id);
    const Vector<AXID>& owners_owned_children =
        aria_owner_to_children_mapping_.at(owner_id);
    for (wtf_size_t index = 0; index < owners_owned_children.size(); index++) {
      if (owners_owned_children[index] == obj_id) {
        aria_owner_to_children_mapping_.at(owner_id).EraseAt(index);
        break;
      }
    }
    if (AXObject* owner = ObjectFromAXID(owner_id)) {
      // The child is removed, so the owner needs to make sure its maps
      // are updated because it could point to something new or even back to the
      // same child if it's recreated, because it still has aria-owns markup.
      // The next call AXRelationCache::ProcessUpdatesWithCleanLayout()
      // will refresh this owner before the tree is frozen.
      owner_axids_to_update_.insert(owner_id);

      if (object_cache_->lifecycle().StateAllowsImmediateTreeUpdates()) {
        // Currently in CommitAXUpdates(). Changing the children of the owner
        // here could interfere with the execution of RemoveSubtree().
        object_cache_->MarkAXObjectDirtyWithCleanLayout(owner);
      } else {
        object_cache_->ChildrenChanged(owner);
      }
    }
    if (AXObject* owned_child = ObjectFromAXID(obj_id)) {
      owned_child->DetachFromParent();
    }
  }
}

AXObject* AXRelationCache::ObjectFromAXID(AXID axid) const {
  return object_cache_->ObjectFromAXID(axid);
}

AXObject* AXRelationCache::Get(Node* node) {
  return object_cache_->Get(node);
}

AXObject* AXRelationCache::GetOrCreate(Node* node, const AXObject* owner) {
  return object_cache_->GetOrCreate(node, const_cast<AXObject*>(owner));
}

void AXRelationCache::ChildrenChangedWithCleanLayout(AXObject* object) {
  if (!object) {
    return;
  }
  object->ChildrenChangedWithCleanLayout();
  object_cache_->MarkAXObjectDirtyWithCleanLayout(object);
}

Node* AXRelationCache::LabelChanged(HTMLLabelElement& label) {
  const auto& id = label.FastGetAttribute(html_names::kForAttr);
  if (id.empty()) {
    return nullptr;
  }

  all_previously_seen_label_target_ids_.insert(id);
  return label.Control();
}

void AXRelationCache::MaybeRestoreParentOfOwnedChild(AXID removed_child_axid) {
  // This works because AXIDs are equal to the DOMNodeID for their DOM nodes.
  if (Node* child_node = DOMNodeIds::NodeForId(removed_child_axid)) {
    object_cache_->RestoreParentOrPrune(child_node);
    // Handle case where there were multiple elements aria-owns=|child|,
    // by making sure they are updated in the next round, in case one of them
    // can now own it because of the removal the old_parent.
    HeapVector<Member<AXObject>> other_potential_owners;
    if (Element* child_element = DynamicTo<Element>(child_node)) {
      GetRelationSourcesById(child_element->GetIdAttribute(), aria_owns_id_map_,
                             other_potential_owners);
      for (AXObject* other_potential_owner : other_potential_owners) {
        owner_axids_to_update_.insert(other_potential_owner->AXObjectID());
      }
    }
  }
}

}  // namespace blink

"""


```