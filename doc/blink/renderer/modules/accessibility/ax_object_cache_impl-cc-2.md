Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. I need to analyze the code and identify its core purpose and how it interacts with other browser functionalities, specifically JavaScript, HTML, and CSS. I should also consider potential usage errors and how users might reach this code.

**Plan:**

1. Identify the main function of the code: This section primarily focuses on removing accessibility objects from the cache.
2. Analyze each function in the snippet and describe its specific role in removing objects.
3. Determine the relationship with JavaScript, HTML, and CSS by identifying how these technologies trigger the removal of accessibility objects.
4. Consider logical reasoning within the code and create hypothetical input/output scenarios.
5. Identify common user or programming errors that might lead to issues in this part of the code.
6. Describe user actions that could trigger the code execution, acting as debugging clues.
7. Synthesize a concise summary of the code's overall functionality.
这是 `AXObjectCacheImpl.cc` 文件的第 3 部分，主要关注**移除** Accessibility (AX) 对象的逻辑，以及一些与此相关的辅助功能。

**功能归纳：**

这部分代码的核心功能是**从 AXObjectCache 中移除 AX 对象**，这些对象可能对应于 DOM 节点、布局对象或内联文本框。它处理了不同情况下的移除，包括：

*   **DOM 节点被移除：** 包括普通节点和伪元素。
*   **布局对象被移除：** 当关联的 DOM 节点不存在时。
*   **弹出窗口（Popup Document）被关闭：**  清理与弹出窗口相关的 AX 对象。
*   **内联文本框被移除。**
*   **子树被移除：** 递归地移除一个节点及其所有后代对应的 AX 对象。

除了基本的移除操作，这部分代码还包含一些重要的辅助功能：

*   **管理 `aria-modal` 对话框：**  在移除节点时更新当前激活的 `aria-modal` 对话框状态。
*   **处理图像 Map：**  确保在移除带有图像 Map 的图片时，相关的 Map 区域也被正确移除。
*   **管理固定或粘性定位的节点：**  记录并处理这些特殊定位的节点。
*   **管理待处理的树更新：**  维护和控制树更新的队列，并根据需要暂停或恢复更新。
*   **处理 `aria-hidden` 属性：**  检测并报告可能导致整个可访问性树被隐藏的错误用法。
*   **处理节点连接事件：**  在节点连接到 DOM 树时执行相关操作，例如更新关系属性。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

*   **HTML：**
    *   **移除 HTML 元素：** 当 JavaScript 通过 `removeChild` 或类似方法移除 HTML 元素时，Blink 引擎会收到通知，然后调用 `AXObjectCacheImpl::Remove(Node* node)` 来移除该元素对应的 AX 对象。
        *   **假设输入：**  一个包含 `<div id="target">Some Content</div>` 的 HTML 页面，JavaScript 代码执行 `document.getElementById('target').remove()`。
        *   **输出：** `AXObjectCacheImpl::Remove` 函数会被调用，移除与该 `div` 元素关联的 AX 对象。
    *   **移除带有 `aria-modal` 属性的 HTML 元素：**  如果移除的是当前激活的 `aria-modal` 对话框，代码会更新 `active_aria_modal_dialog_` 的状态。
        *   **假设输入：** 一个包含 `<div role="dialog" aria-modal="true" id="modal">Modal Content</div>` 的 HTML 页面，并且该对话框是当前激活的 `aria-modal` 对话框。JavaScript 执行 `document.getElementById('modal').remove()`。
        *   **输出：** `AXObjectCacheImpl::Remove` 会被调用，并且 `active_aria_modal_dialog_` 将会被设置为 `nullptr`。
    *   **移除带有 `<map>` 标签的图片：** 如果移除的是带有 `<map>` 标签的图片，需要确保相关的 Map 区域也被移除。
        *   **假设输入：**  一个包含 `<img src="image.png" usemap="#imagemap"><map name="imagemap"><area shape="rect" coords="0,0,100,100" href="#"></map>` 的 HTML 页面，JavaScript 执行 `document.querySelector('img').remove()`。
        *   **输出：** `AXObjectCacheImpl::Remove` 会先移除 `area` 元素的 AX 对象，然后再移除 `img` 元素的 AX 对象。
*   **CSS：**
    *   **通过 CSS 隐藏元素 (例如 `display: none`)：**  虽然不是直接移除 DOM 节点，但 CSS 样式的改变可能会导致某些 AX 对象从可访问性树中移除或标记为忽略。这通常发生在 `AXObjectCacheImpl::ChildrenChanged` 或 `AXObjectCacheImpl::MarkAXObjectDirty` 等函数中，但 `Remove` 也可能被间接调用。
        *   **假设输入：** 一个可见的 `<div>` 元素，JavaScript 修改其样式为 `div.style.display = 'none'`;
        *   **输出：**  与该 `div` 元素关联的 AX 对象可能会被标记为忽略，或者其父对象的子节点列表会更新，从而在可访问性树中移除该对象。
    *   **伪元素被移除或改变：**  当伪元素的样式发生变化导致其不再显示时，或者当包含伪元素的父元素被移除时，会调用 `MarkSubtreeDirty` 和 `RemoveAXObjectsInLayoutSubtree` 来重新计算可访问性树。
        *   **假设输入：** 一个包含 `div::before { content: "hello"; }` 的 CSS 样式，并且页面中存在一个 `<div>` 元素。JavaScript 修改 `div::before` 的 `content` 属性为空字符串。
        *   **输出：** `AXObjectCacheImpl::Remove` (通过 `RemoveAXObjectsInLayoutSubtree`) 可能会被调用，移除与该伪元素相关的 AX 对象。
*   **JavaScript：**
    *   **JavaScript 操作 DOM 导致节点被移除：** 如上 HTML 例子所示，JavaScript 是触发节点移除的主要方式。
    *   **JavaScript 设置 `aria-hidden` 属性：** 虽然 `Remove` 函数本身不直接处理 `aria-hidden` 的设置，但它会检查和处理由于 `aria-hidden` 属性导致的移除情况，并可能发出警告。
        *   **假设输入：**  一个包含 `<div id="container"><p id="focusable" tabindex="0">Focusable Content</p></div>` 的 HTML 页面。JavaScript 执行 `document.getElementById('container').setAttribute('aria-hidden', 'true')`。
        *   **输出：** 当焦点仍然在 `<p>` 元素上时，`AXObjectCacheImpl::DiscardBadAriaHiddenBecauseOfFocus` 可能会被调用，并输出错误信息，表示 `aria-hidden` 被阻止。

**逻辑推理与假设输入/输出：**

*   **假设输入：** 一个包含嵌套 `div` 元素的 HTML 结构： `<div><div><span>Text</span></div></div>`，并且已经为这些元素创建了对应的 AX 对象。JavaScript 代码执行移除最外层 `div` 的操作。
*   **输出：**
    1. `AXObjectCacheImpl::Remove(LayoutObject* layout_object, bool notify_parent)` 首先会被调用，处理最外层 `div` 对应的布局对象。
    2. 由于存在关联的 DOM 节点，会调用 `AXObjectCacheImpl::Remove(Node* node, bool notify_parent)`。
    3. 接着会调用 `AXObjectCacheImpl::RemoveSubtree(const Node* node, bool remove_root, bool notify_parent)`，递归地移除内层 `div` 和 `span` 对应的 AX 对象。
    4. 在移除每个节点时，`layout_object_mapping_` 和 `objects_` 等数据结构会被更新，移除相应的映射关系。

**用户或编程常见的使用错误：**

*   **手动移除 DOM 节点后未清理 AX 对象缓存：**  虽然 Blink 引擎会自动处理大部分情况，但在某些复杂或自定义的场景下，如果开发者直接操作底层数据结构，可能会导致 AX 对象缓存与 DOM 树状态不一致。
*   **错误地使用 `aria-hidden` 隐藏焦点元素：**  `AXObjectCacheImpl::DiscardBadAriaHiddenBecauseOfFocus` 函数会检测这种情况并发出警告。用户可能会错误地认为设置了 `aria-hidden="true"` 就可以完全隐藏元素，而忽略了焦点管理的重要性。
    *   **用户操作：** 用户使用键盘导航，焦点落在一个被其祖先元素设置了 `aria-hidden="true"` 的元素上。
    *   **调试线索：** 控制台会输出错误信息，提示 `aria-hidden` 被阻止。
*   **在短时间内进行大量的 DOM 节点添加和移除操作：**  可能会导致大量的 AX 对象创建和销毁，影响性能。`AXObjectCacheImpl::PauseTreeUpdatesIfQueueFull` 函数尝试缓解这种情况。
*   **不正确的弹出窗口管理：**  如果开发者没有正确地处理弹出窗口的创建和销毁，可能会导致 `AXObjectCacheImpl::RemovePopup` 函数被错误地调用，或者缓存中残留了与已关闭弹出窗口相关的 AX 对象。

**用户操作如何一步步到达这里 (作为调试线索)：**

1. **用户与网页交互：** 用户可能点击了一个按钮，触发 JavaScript 代码执行 DOM 节点的移除操作。
2. **JavaScript 操作 DOM：**  JavaScript 代码调用 `element.remove()` 或 `parentNode.removeChild(element)` 等方法。
3. **Blink 引擎收到 DOM 变更通知：**  渲染引擎会监听到 DOM 树的变化。
4. **触发 Accessibility 相关的处理：** Blink 引擎会通知 Accessibility 模块，DOM 树发生了变化。
5. **调用 `AXObjectCacheImpl::Remove`：** Accessibility 模块会根据移除的节点类型，调用相应的 `Remove` 函数。
6. **执行移除逻辑：**  `Remove` 函数会更新 AX 对象缓存，移除相关的对象和映射关系。

**总结：**

这部分 `AXObjectCacheImpl.cc` 代码的核心职责是**管理和执行 AX 对象的移除操作**，以保持可访问性树与 DOM 树的同步。它处理了各种移除场景，并具备一些辅助功能来确保可访问性的正确性和性能。与 JavaScript、HTML 和 CSS 的交互主要体现在响应 DOM 结构和样式的变化，并对用户可能造成的错误用法进行检测和提示。

Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_object_cache_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共8部分，请归纳一下它的功能

"""
_aria_modal_dialog_ = nullptr;
  }
}

void AXObjectCacheImpl::Remove(LayoutObject* layout_object,
                               bool notify_parent) {
  CHECK(layout_object);

  if (IsA<LayoutView>(layout_object)) {
    // A document is being destroyed.
    // This code is only reached when it is a popup being destroyed.
    // TODO(accessibility) Can we remove this case since Blink calls
    // RemovePopup(document) for us?
    DCHECK(!popup_document_ ||
           popup_document_ == &layout_object->GetDocument());
    // Popup has been destroyed.
    if (popup_document_) {
      RemovePopup(popup_document_);
    }
  }

  // If a DOM node is present, it will have been used to back the AXObject, in
  // which case we need to call Remove(node) instead.
  if (Node* node = layout_object->GetNode()) {
    // Pseudo elements are a special case. The entire subtree needs to be marked
    // dirty so that it is recomputed (it is disappearing or changing).
    if (node->IsPseudoElement()) {
      MarkSubtreeDirty(node);
    }

    if (IsA<HTMLImageElement>(node)) {
      // If an image is removed, ensure its entire subtree is deleted as there
      // may have been children supplied via a map.
      if (auto* layout_image =
              DynamicTo<LayoutImage>(node->GetLayoutObject())) {
        if (auto* map = layout_image->ImageMap()) {
          if (map->ImageElement() == node) {
            RemoveSubtree(map, /*remove_root*/ false);
          }
        }
      }
    }

    Remove(node, notify_parent);
    return;
  }

  auto iter = layout_object_mapping_.find(layout_object);
  if (iter == layout_object_mapping_.end())
    return;

  AXID ax_id = iter->value;
  DCHECK(ax_id);

  layout_object_mapping_.erase(iter);
  Remove(ax_id, false);
}

// This is safe to call even if there isn't a current mapping.
void AXObjectCacheImpl::Remove(Node* node) {
  // Ensure that our plugin serializer, if it exists, is properly
  // reset. Paired with AXNodeObject::Detach.
  if (IsA<HTMLEmbedElement>(node)) {
    ResetPluginTreeSerializer();
  }

  Remove(node, /* notify_parent */ true);
}

void AXObjectCacheImpl::Remove(Node* node, bool notify_parent) {
  DCHECK(node);
  LayoutObject* layout_object = node->GetLayoutObject();
  DCHECK(!layout_object || layout_object_mapping_.find(layout_object) ==
                               layout_object_mapping_.end())
      << "AXObject cannot be backed by both a layout object and node.";

  AXID axid = node->GetDomNodeId();
  whitespace_ignored_map_.erase(axid);

  if (node == active_aria_modal_dialog_ &&
      lifecycle_.StateAllowsAXObjectsToBeDirtied()) {
    UpdateActiveAriaModalDialog(FocusedNode());
  }

  DCHECK_GE(axid, 1);
  Remove(axid, notify_parent);
}

void AXObjectCacheImpl::RemovePopup(Document* popup_document) {
  // The only 2 documents that partake in the cache are the main document and
  // the popup document. This method is only be called for the popup document,
  // because if the main document is shutting down, the cache is disposed.
  DCHECK(popup_document);

  // This can be called even when GetPopupDocumentIfShowing() when the popup
  // is from a <select size=1>, and in order to avoid duplicate objects, which
  // treat that situations as if there is no popup showing.
  if (!GetPopupDocumentIfShowing()) {
    return;
  }
  DCHECK(IsPopup(*popup_document)) << "Use Dispose() to remove main document.";
  RemoveSubtree(popup_document);

  popup_document_ = nullptr;
  pending_events_to_serialize_.clear();
  tree_update_callback_queue_popup_.clear();
}

// This is safe to call even if there isn't a current mapping.
void AXObjectCacheImpl::Remove(AbstractInlineTextBox* inline_text_box) {
  Remove(inline_text_box, /* notify_parent */ true);
}

void AXObjectCacheImpl::Remove(AbstractInlineTextBox* inline_text_box,
                               bool notify_parent) {
  if (!inline_text_box)
    return;

  auto iter = inline_text_box_object_mapping_.find(inline_text_box);
  if (iter == inline_text_box_object_mapping_.end())
    return;

  AXID ax_id = iter->value;
  inline_text_box_object_mapping_.erase(iter);

  Remove(ax_id, notify_parent);
}

void AXObjectCacheImpl::RemoveIncludedSubtree(AXObject* object,
                                              bool remove_root) {
  DCHECK(object);
  if (object->IsDetached()) {
    return;
  }

  for (const auto& ax_child : object->CachedChildrenIncludingIgnored()) {
    RemoveIncludedSubtree(ax_child, /* remove_root */ true);
  }
  if (remove_root) {
    Remove(object, /* notify_parent */ false);
  }
}

void AXObjectCacheImpl::RemoveAXObjectsInLayoutSubtree(
    LayoutObject* subtree_root) {
  Remove(subtree_root, /*notify_parent*/ true);

  LayoutObject* iter = subtree_root;
  while ((iter = iter->NextInPreOrder(subtree_root)) != nullptr) {
    Remove(iter, /*notify_parent*/ false);
  }
}

void AXObjectCacheImpl::RemoveSubtree(const Node* node, bool remove_root) {
  if (!node || !node->isConnected()) {
    return;
  }
  RemoveSubtree(node, remove_root, /*notify_parent*/ true);
}

void AXObjectCacheImpl::RemoveSubtree(const Node* node) {
  RemoveSubtree(node, /*remove_root*/ true);
}

void AXObjectCacheImpl::RemoveSubtree(const Node* node,
                                      bool remove_root,
                                      bool notify_parent) {
  DCHECK(node);
  AXObject* object = Get(node);
  if (!object && !remove_root) {
    // Nothing remaining to do for this subtree. Already removed.
    return;
  }

  if (const HTMLMapElement* map_element = DynamicTo<HTMLMapElement>(node)) {
    // If this node is an image map, it is necessary to notify the <img> node
    // associated with this map that its children will be deleted. The a11y tree
    // will add the children of the image map as children of the image itself
    // (see AXNodeObject::AddImageMapChildren for more details). However, the
    // dom node traversal below would delete these children without notifying
    // their parent that children will change, so this special check here is a
    // must. For all other cases, this is not necessary because the parent is
    // part of the subtree removal or will be notified via notify_parent defined
    // above.
    if (AXObject* image_ax_object = GetAXImageForMap(*map_element)) {
      // Note here that an image will only be returned if the map has children
      // and at least one of them points to an image, so it is guaranteed that
      // we are not notifying a parent if children are not being removed.
      // **important**: this call must come before the node traversal remove
      // below since that could remove a child which would cause it to not point
      // to its image parent, making it impossible to notify the parent.
      NotifyParentChildrenChanged(image_ax_object);
    }
  }

  // Remove children found through dom traversal.
  for (Node* child_node = NodeTraversal::FirstChild(*node); child_node;
       child_node = NodeTraversal::NextSibling(*child_node)) {
    RemoveSubtree(child_node, /* remove_root */ true,
                  /* notify_parent */ false);
  }

  if (!object) {
    return;
  }

  // When removing children, use the cached children to avoid creating a child
  // just to destroy it.
  for (AXObject* ax_included_child : object->CachedChildrenIncludingIgnored()) {
    if (ax_included_child->ParentObjectIfPresent() != object) {
      continue;
    }
    if (ui::CanHaveInlineTextBoxChildren(object->RoleValue())) {
      // Just remove child inline textboxes, don't use their node which is the
      // same as that static text's parent and would cause an infinite loop.
      Remove(ax_included_child, /* notify_parent */ false);
    } else if (ax_included_child->GetNode()) {
      DCHECK(ax_included_child->GetNode() != node);
      RemoveSubtree(ax_included_child->GetNode(),
                    /* remove_root */ true,
                    /* notify_parent */ false);
    } else {
      RemoveIncludedSubtree(ax_included_child, /* remove_root */ true);
    }
  }

  // The code below uses ChildrenChangedWithCleanLayout() instead of
  // notify_parent param in Remove(), which would be queued, and it needs to
  // happen immediately.
  AXObject* parent_to_notify = nullptr;
  if (notify_parent) {
    // Find the parent to notify:
    // If the root is being removed, then it's the root's parent.
    // If the root isn't being removed, its child subtrees are being removed,
    // and thus the root itself is the parent who's children are changing.
    parent_to_notify = remove_root ? object->ParentObjectIfPresent() : object;
  }
  if (remove_root) {
    Remove(object, /* notify_parent */ false);
  }
  if (parent_to_notify) {
    NotifyParentChildrenChanged(parent_to_notify);
  }
}

// All generated AXIDs are negative, ranging from kFirstGeneratedRendererNodeID
// to kLastGeneratedRendererNodeID, in order to avoid conflict with the ids
// reused from dom_node_ids, which are positive, and generated IDs on the
// browser side, which are negative, starting at -1.
AXID AXObjectCacheImpl::GenerateAXID() const {
  // The first id is close to INT_MIN/2, leaving plenty of room for negative
  // generated IDs both here and on the browser side, but starting at an even
  // number makes it easier to read when debugging.
  static AXID last_used_id = ui::kFirstGeneratedRendererNodeID;

  // Generate a new ID.
  AXID obj_id = last_used_id;
  do {
    if (--obj_id == ui::kLastGeneratedRendererNodeID) {
      // This is very unlikely to happen, but if we find that it happens, we
      // could gracefully turn off a11y instead of crashing the renderer.
      CHECK(!has_axid_generator_looped_)
          << "Not enough room more generated accessibility objects.";
      has_axid_generator_looped_ = true;
      obj_id = ui::kFirstGeneratedRendererNodeID;
    }
  } while (has_axid_generator_looped_ && objects_.Contains(obj_id));

  DCHECK(!WTF::IsHashTraitsEmptyOrDeletedValue<HashTraits<AXID>>(obj_id));

  last_used_id = obj_id;

  return obj_id;
}

void AXObjectCacheImpl::AddToFixedOrStickyNodeList(const AXObject* object) {
  DCHECK(object);
  DCHECK(!object->IsDetached());
  fixed_or_sticky_node_ids_.insert(object->AXObjectID());
}

AXID AXObjectCacheImpl::AssociateAXID(AXObject* obj, AXID use_axid) {
  // Check for already-assigned ID.
  DCHECK(!obj->AXObjectID()) << "Object should not already have an AXID";

  AXID new_axid = use_axid ? use_axid : GenerateAXID();

  bool should_have_node_id = obj->IsAXNodeObject() && obj->GetNode();
  DCHECK_EQ(should_have_node_id, IsDOMNodeID(new_axid))
      << "An AXID is also a DOMNodeID (positive integer) if any only if the "
         "AXObject is an AXNodeObject with a DOM node.";

  obj->SetAXObjectID(new_axid);
  objects_.Set(new_axid, obj);

  return new_axid;
}

void AXObjectCacheImpl::RemoveReferencesToAXID(AXID obj_id) {
  DCHECK(!WTF::IsHashTraitsDeletedValue<HashTraits<AXID>>(obj_id));

  // Clear AXIDs from maps. Note: do not need to erase id from
  // changed_bounds_ids_, a set which is cleared each time
  // SerializeLocationChanges() is finished. Also, do not need to erase id from
  // invalidated_ids_main_ or invalidated_ids_popup_, which are cleared each
  // time ProcessInvalidatedObjects() finishes, and having extra ids in those
  // sets is not harmful.

  cached_bounding_boxes_.erase(obj_id);

  if (IsDOMNodeID(obj_id)) {
    // Optimization: these maps only contain ids for AXObjects with a DOM node.
    fixed_or_sticky_node_ids_.erase(obj_id);
    // Only objects with a DOM node can be in the relation cache.
    if (relation_cache_) {
      relation_cache_->RemoveAXID(obj_id);
    }
    // Allow the new AXObject for the same node to be serialized correctly.
    nodes_with_pending_children_changed_.erase(obj_id);
  } else {
    // Non-DOM ids should never find their way into these maps.
    DCHECK(!fixed_or_sticky_node_ids_.Contains(obj_id));
    DCHECK(!nodes_with_pending_children_changed_.Contains(obj_id));
  }
}

AXObject* AXObjectCacheImpl::NearestExistingAncestor(Node* node) {
  // Find the nearest ancestor that already has an accessibility object, since
  // we might be in the middle of a layout.
  while (node) {
    if (AXObject* obj = Get(node))
      return obj;
    node = node->parentNode();
  }
  return nullptr;
}

void AXObjectCacheImpl::UpdateNumTreeUpdatesQueuedBeforeLayoutHistogram() {
  UMA_HISTOGRAM_COUNTS_100000(
      "Blink.Accessibility.NumTreeUpdatesQueuedBeforeLayout",
      tree_update_callback_queue_main_.size() +
          tree_update_callback_queue_popup_.size());
}

void AXObjectCacheImpl::InvalidateBoundingBoxForFixedOrStickyPosition() {
  for (AXID id : fixed_or_sticky_node_ids_)
    InvalidateBoundingBox(id);
}

bool AXObjectCacheImpl::CanDeferTreeUpdate(Document* tree_update_document) {
  DCHECK(lifecycle_.StateAllowsDeferTreeUpdates()) << *this;
  DCHECK(!IsFrozen());

  if (!IsActive(GetDocument()) || tree_updates_paused_)
    return false;

  // Ensure the tree update document is in a good state.
  if (!tree_update_document || !IsActive(*tree_update_document)) {
    return false;
  }

  if (tree_update_document != document_) {
    // If the popup_document_ is null, throw this tree update away, because:
    // - Updates that occur BEFORE the popup is tracked in a11y don't matter,
    // as we will build the entire popup's AXObject subtree once we are
    // notified about the popup.
    // - Updates that occur AFTER the popup is no longer tracked could occur
    // while the popup is currently closing, in which case the updates are no
    // longer useful.
    if (!popup_document_) {
      return false;
    }
    // If we are queuing an update to a document other than the main document,
    // then it must be in an active popup document. The cache would never
    // receive notifications from other documents.
    DUMP_WILL_BE_CHECK_EQ(tree_update_document, popup_document_)
        << "Update in non-main, non-popup document: "
        << tree_update_document->Url().GetString();
  }

  return true;
}

bool AXObjectCacheImpl::PauseTreeUpdatesIfQueueFull() {
  // Check the main document's queue. If there are too many entries, pause all
  // updates and resume later after rebuilding the tree from scratch.
  // Popup is excluded because it's controlled by us and will not have too many
  // updates. In the case of a web page having too many updates, we need to
  // clear all queues, including the popup's.
  if (tree_update_callback_queue_main_.size() >= max_pending_updates_) {
    UpdateNumTreeUpdatesQueuedBeforeLayoutHistogram();
    tree_updates_paused_ = true;
    LOG(INFO) << "Accessibility tree update queue is too big, updates have "
                 "been paused";
    // Clear updates from both documents.
    tree_update_callback_queue_main_.clear();
    tree_update_callback_queue_popup_.clear();
    pending_events_to_serialize_.clear();
    return true;
  }

  return false;
}

void AXObjectCacheImpl::DeferTreeUpdate(
    AXObjectCacheImpl::TreeUpdateReason update_reason,
    Node* node,
    ax::mojom::blink::Event event) {
  CHECK(node);
  CHECK(lifecycle_.StateAllowsDeferTreeUpdates()) << *this;

  Document& tree_update_document = node->GetDocument();
  if (!CanDeferTreeUpdate(&tree_update_document)) {
    return;
  }

  if (PauseTreeUpdatesIfQueueFull()) {
    return;
  }

  TreeUpdateCallbackQueue& queue =
      GetTreeUpdateCallbackQueue(tree_update_document);

  TreeUpdateParams* tree_update = MakeGarbageCollected<TreeUpdateParams>(
      node, 0u, ComputeEventFrom(), active_event_from_action_,
      ActiveEventIntents(), update_reason, event);

  queue.push_back(tree_update);

  if (AXObject* obj = Get(node)) {
    obj->InvalidateCachedValues();
  }

  // These events are fired during RunPostLifecycleTasks(),
  // ensure there is a document lifecycle update scheduled.
  if (IsImmediateProcessingRequired(tree_update)) {
    // Ensure that processing of tree updates occurs immediately in cases
    // where a user action such as focus or selection occurs, so that the user
    // gets immediate feedback.
    ScheduleImmediateSerialization();
  } else {
    // Otherwise, batch updates to improve performance.
    ScheduleAXUpdate();
  }
}
void AXObjectCacheImpl::DeferTreeUpdate(
    AXObjectCacheImpl::TreeUpdateReason update_reason,
    AXObject* obj,
    ax::mojom::blink::Event event,
    bool invalidate_cached_values) {
  // Called for updates that do not have a DOM node, e.g. a children or text
  // changed event that occurs on an anonymous layout block flow.
  CHECK(obj);
  CHECK(lifecycle_.StateAllowsDeferTreeUpdates()) << *this;

  if (obj->IsDetached()) {
    return;
  }

  CHECK(obj->AXObjectID());

  Document* tree_update_document = obj->GetDocument();

  if (!CanDeferTreeUpdate(tree_update_document)) {
    return;
  }

  if (PauseTreeUpdatesIfQueueFull()) {
    return;
  }

  TreeUpdateCallbackQueue& queue =
      GetTreeUpdateCallbackQueue(*tree_update_document);

  queue.push_back(MakeGarbageCollected<TreeUpdateParams>(
      nullptr, obj->AXObjectID(), ComputeEventFrom(), active_event_from_action_,
      ActiveEventIntents(), update_reason, event));

  if (invalidate_cached_values) {
    obj->InvalidateCachedValues();
  }

  // These events are fired during RunPostLifecycleTasks(),
  // ensure there is a document lifecycle update scheduled.
  ScheduleAXUpdate();
}

void AXObjectCacheImpl::SelectionChanged(Node* node) {
  if (!node)
    return;

  PostNotification(&GetDocument(),
                   ax::mojom::blink::Event::kDocumentSelectionChanged);

  // If there is a text control, mark it dirty to serialize
  // IntAttribute::kTextSelStart/kTextSelEnd changes.
  // TODO(accessibility) Remove once we remove kTextSelStart/kTextSelEnd.
  if (TextControlElement* text_control = EnclosingTextControl(node))
    MarkElementDirty(text_control);
}

void AXObjectCacheImpl::StyleChanged(const LayoutObject* layout_object,
                                     bool visibility_or_inertness_changed) {
  DCHECK(layout_object);
  SCOPED_DISALLOW_LIFECYCLE_TRANSITION();
  AXObject* ax_object = Get(layout_object->GetNode());
  if (!ax_object) {
    // No object exists to mark dirty yet -- there can sometimes be a layout in
    // the initial empty document, or style has changed before the object cache
    // becomes aware that the node exists. It's too early for the style change
    // to be useful.
    return;
  }

  if (visibility_or_inertness_changed) {
    ChildrenChanged(ax_object);
    ChildrenChanged(ax_object->ParentObject());
  }
  MarkAXObjectDirty(ax_object);
}

void AXObjectCacheImpl::CSSAnchorChanged(const LayoutObject* positioned_obj) {
  if (Node* node = positioned_obj->GetNode()) {
    DeferTreeUpdate(TreeUpdateReason::kCSSAnchorChanged, node);
  }
}

void AXObjectCacheImpl::TextChanged(Node* node) {
  if (!node)
    return;

  // A text changed event is redundant with children changed on the same node.
  if (AXID node_id = static_cast<AXID>(node->GetDomNodeId())) {
    if (nodes_with_pending_children_changed_.find(node_id) !=
        nodes_with_pending_children_changed_.end()) {
      return;
    }
  }

  DeferTreeUpdate(TreeUpdateReason::kTextChangedOnNode, node);
}

// Return a node for the current layout object or ancestor layout object.
Node* AXObjectCacheImpl::GetClosestNodeForLayoutObject(
    const LayoutObject* layout_object) {
  if (!layout_object) {
    return nullptr;
  }
  Node* node = layout_object->GetNode();
  return node ? node : GetClosestNodeForLayoutObject(layout_object->Parent());
}

void AXObjectCacheImpl::TextChanged(const LayoutObject* layout_object) {
  if (!layout_object)
    return;

  // The node may be null when the text changes on an anonymous layout object,
  // such as a layout block flow that is inserted to parent an inline object
  // when it has a block sibling.
  Node* node = GetClosestNodeForLayoutObject(layout_object);
  if (node) {
    // If the text changed in a pseudo element, rebuild the entire subtree.
    if (node->IsPseudoElement()) {
      RemoveAXObjectsInLayoutSubtree(node->GetLayoutObject());
    } else if (AXID node_id = static_cast<AXID>(node->GetDomNodeId())) {
      // Text changed is redundant with children changed on the same node.
      if (base::Contains(nodes_with_pending_children_changed_, node_id)) {
        return;
      }
    }

    DeferTreeUpdate(TreeUpdateReason::kTextChangedOnClosestNodeForLayoutObject,
                    node);
    return;
  }

  if (Get(layout_object)) {
    DeferTreeUpdate(TreeUpdateReason::kTextChangedOnLayoutObject,
                    Get(layout_object));
  }
}

void AXObjectCacheImpl::TextChangedWithCleanLayout(
    Node* optional_node_for_relation_update,
    AXObject* obj) {
  if (obj ? obj->IsDetached() : !optional_node_for_relation_update)
    return;

#if DCHECK_IS_ON()
  Document* document = obj ? obj->GetDocument()
                           : &optional_node_for_relation_update->GetDocument();
  DCHECK(document->Lifecycle().GetState() >= DocumentLifecycle::kLayoutClean)
      << "Unclean document at lifecycle " << document->Lifecycle().ToString();
#endif  // DCHECK_IS_ON()

  if (obj) {
    if (obj->RoleValue() == ax::mojom::blink::Role::kStaticText &&
        obj->IsIncludedInTree()) {
      if (obj->ShouldLoadInlineTextBoxes()) {
        // Update inline text box children.
        ChildrenChangedWithCleanLayout(optional_node_for_relation_update, obj);
        return;
      }
    }

    MarkAXObjectDirtyWithCleanLayout(obj);
  }

  if (optional_node_for_relation_update) {
    CHECK(relation_cache_);
    relation_cache_->UpdateRelatedTree(optional_node_for_relation_update, obj);
  }
}

void AXObjectCacheImpl::TextChangedWithCleanLayout(Node* node) {
  if (!node)
    return;

  DCHECK(!node->GetDocument().NeedsLayoutTreeUpdateForNode(*node));
  TextChangedWithCleanLayout(node, Get(node));
}

bool AXObjectCacheImpl::HasBadAriaHidden(const AXObject& obj) const {
  return nodes_with_bad_aria_hidden_.Contains(obj.AXObjectID());
}

void AXObjectCacheImpl::DiscardBadAriaHiddenBecauseOfElement(
    const AXObject& obj) {
  bool is_first_time =
      nodes_with_bad_aria_hidden_.insert(obj.AXObjectID()).is_new_entry;

  if (!is_first_time) {
    return;
  }

  Element& element = *obj.GetElement();
  element.AddConsoleMessage(
      mojom::blink::ConsoleMessageSource::kRendering,
      mojom::blink::ConsoleMessageLevel::kError,
      String::Format(
          "Blocked aria-hidden on a <%s> element because it would hide the "
          "entire accessibility tree from assistive technology users. For more "
          "details, see the aria-hidden section of the WAI-ARIA specification "
          "at https://w3c.github.io/aria/#aria-hidden.",
          element.TagQName().ToString().Ascii().c_str()));
}

void AXObjectCacheImpl::DiscardBadAriaHiddenBecauseOfFocus(AXObject& obj) {
  // aria-hidden markup requires an element.
  Element& focused_element = *obj.GetElement();

  // Traverse all the way to the root in case there are multiple
  // ancestors with aria-hidden. Any aria-hidden="true" on any ancestor will
  // be ignored.
  AXObject* bad_aria_hidden_ancestor = nullptr;
  for (AXObject* ancestor = &obj; ancestor;
       ancestor = ancestor->ParentObject()) {
    if (ancestor->IsAriaAttributeTrue(html_names::kAriaHiddenAttr)) {
      if (nodes_with_bad_aria_hidden_.insert(ancestor->AXObjectID())
              .is_new_entry) {
        bad_aria_hidden_ancestor = ancestor;
      }
    }
  }
  // Invalidate the subtree and rebuild it now that this aria-hidden has
  // been marked as bad and will be ignored.
  CHECK(bad_aria_hidden_ancestor)
      << "An aria-hidden node did not have an aria-hidden ancestor.";

  if (bad_aria_hidden_ancestor->GetElement()) {
    bad_aria_hidden_ancestor->GetElement()->AddConsoleMessage(
        mojom::blink::ConsoleMessageSource::kRendering,
        mojom::blink::ConsoleMessageLevel::kError,
        String::Format(
            "Blocked aria-hidden on an element because its descendant retained "
            "focus. The focus must not be hidden from assistive technology "
            "users. Avoid using aria-hidden on a focused element or its "
            "ancestor. Consider using the inert attribute instead, which will "
            "also prevent focus. For more details, see the aria-hidden section "
            "of the WAI-ARIA specification at "
            "https://w3c.github.io/aria/#aria-hidden.\n"
            "Element with focus: %s\nAncestor with aria-hidden: ",
            focused_element.TagQName().ToString().Ascii().c_str()));
  }

  Node* bad_aria_hidden_ancestor_node = bad_aria_hidden_ancestor->GetNode();
  AXObject* ancestor_to_rebuild = bad_aria_hidden_ancestor->ParentObject();
  while (ancestor_to_rebuild) {
    ancestor_to_rebuild->SetNeedsToUpdateChildren();
    if (ancestor_to_rebuild->IsIncludedInTree()) {
      break;
    }
    ancestor_to_rebuild = ancestor_to_rebuild->ParentObject();
  }
  // The root is always included, so ancestor_to_rebuild is never null.
  DCHECK(ancestor_to_rebuild);
  RemoveSubtree(bad_aria_hidden_ancestor_node);
  relation_cache_->ProcessUpdatesWithCleanLayout();
  CHECK(bad_aria_hidden_ancestor->IsDetached());

  ancestor_to_rebuild->UpdateChildrenIfNecessary();
  bad_aria_hidden_ancestor = Get(bad_aria_hidden_ancestor_node);
  if (bad_aria_hidden_ancestor) {
    CHECK(!bad_aria_hidden_ancestor->IsAriaHiddenRoot());
    CHECK(!bad_aria_hidden_ancestor->IsAriaHidden());
  }
  if (AXObject* new_focused_obj = Get(&focused_element)) {
    CHECK(!new_focused_obj->IsAriaHidden());
  }
}

void AXObjectCacheImpl::DocumentTitleChanged() {
  DocumentLifecycle::DisallowTransitionScope disallow(document_->Lifecycle());

  AXObject* root = Get(document_);
  if (root)
    PostNotification(root, ax::mojom::blink::Event::kDocumentTitleChanged);
}

bool AXObjectCacheImpl::IsReadyToProcessTreeUpdatesForNode(const Node* node) {
  DCHECK(node);

  // The maximum number of nodes after whitespace is parsed before a tree update
  // should occur. The value was chosen based on what was needed to eliminate
  // flakiness in existing tests and may need adjustment. Example: the
  // `AccessibilityCSSPseudoElementsSeparatedByWhitespace` Yielding Parser test
  // regularly fails if this value is set to 2, but passes if set to at least 3.
  constexpr int kMaxAllowedTreeUpdatePauses = 3;

  // If we have a node that must be fully parsed before updates can continue,
  // we're ready to process tree updates only if that node has finished parsing
  // its children. In this scenario, the maximum number of tree update pauses is
  // irrelevant.
  if (node_to_parse_before_more_tree_updates_) {
    return node_to_parse_before_more_tree_updates_->IsFinishedParsingChildren();
  }

  // There should be no reason to pause for a script element. Plus if we pause
  // for the script element, the slow-document-load.html web test fails.
  if (IsA<HTMLScriptElement>(node)) {
    return true;
  }

  if (auto* text = DynamicTo<Text>(node)) {
    if (!text->ContainsOnlyWhitespaceOrEmpty()) {
      return true;
    }

    // Whitespace at the end of parsed content is a problem because we won't
    // know if that whitespace node is relevant until we have some text or a
    // block node. And we won't know the layout of a node at connection time.
    // Therefore, if this is a whitespace node, reset the maximum number of
    // allowed pauses and wait.
    allowed_tree_update_pauses_remaining_ = kMaxAllowedTreeUpdatePauses;
    return false;
  }

  // If the node following a whitespace node is a pseudo element, we won't have
  // its contents at the time the node is connected. Those contents can impact
  // the relevance of the whitespace node. So remain paused if node is a pseudo
  // element, without resetting the maximum number of allowed pauses.
  if (node->IsPseudoElement()) {
    return false;
  }

  // No new reason to pause, and there are no prior requested pauses remaining.
  if (!allowed_tree_update_pauses_remaining_) {
    return true;
  }

  // No new reason to pause, but we're not ready to unpause yet. So decrement
  // the number of pauses requested and wait for the next connected node.
  CHECK_GT(allowed_tree_update_pauses_remaining_, 0u);
  allowed_tree_update_pauses_remaining_--;
  return false;
}

void AXObjectCacheImpl::NodeIsConnected(Node* node) {
  if (IsParsingMainDocument()) {
    if (IsReadyToProcessTreeUpdatesForNode(node)) {
      node_to_parse_before_more_tree_updates_ = nullptr;
      allowed_tree_update_pauses_remaining_ = 0;
    }
  } else {
    // Handle case where neither NodeIsAttached() nor SubtreeIsAttached() will
    // be called for this node. This occurs for nodes that are added to
    // display:none subtrees. Ensure that these nodes partake in the AX tree.
    ChildrenChanged(node->parentNode());
  }

  // Process relations.
  if (Element* element = DynamicTo<Element>(node)) {
    if (relation_cache_) {
      // Register relation ids so that reverse relations can be computed.
      relation_cache_->CacheRelations(*element);
      ScheduleAXUpdate();
    }
    if (AXObject::HasARIAOwns(element)) {
      DeferTreeUpdate(TreeUpdateReason::kUpdateAriaOwns, element);
    }
    if (element->HasID()) {
      DeferTreeUpdate(TreeUpdateReason::kIdChanged, element);
    }
  }
}

void AXObjectCacheImpl::UpdateAriaOwnsWithCleanLayout(Node* node) {
  // Process any relation attributes that can affect ax objects already created.
  // Force computation of aria-owns, so that original parents that already
  // computed their children get the aria-owned children removed.
  if (IsA<Element>(node) && AXObject::HasARIAOwns(To<Element>(node))) {
    if (AXObject* obj = Get(node)) {
      CHECK(relation_cache_);
      relation_cache_->UpdateAriaOwnsWithCleanLayout(obj);
    }
  }
}

void AXObjectCacheImpl::SubtreeIsAttached(Node* node) {
  // If the node is the root of a display locked subtree, or was previously
  // display:none, the entire AXObject subtree needs to be destroyed and rebuilt
  // using AXNodeObjects with LayoutObjects.
  // TODO(accessibility): try to improve performance by keeping the existing
  // subtree but setting the LayoutObject and recomputing relevant values,
  // including the role and the ignored state.
  AXObject* obj = Get(node);
  if (!obj) {
    if (!node->GetLayoutObject() && !node->IsFinishedParsingChildren() &&
        !node_to_parse_before_more_tree_updates_) {
      // Unrendered subtrees that are not fully parsed are unsafe to
      // process until they are complete, because there are no NodeIsAttached()
      // signals for incrementally loaded content.
      node_to_parse_before_more_tree_updates_ = node;
    }

    // No AX subtree to invalidate: just add an AXObject for this node.
    // It will automatically add its subtree.
    ChildrenChanged(LayoutTreeBuilderTraversal::Parent(*node));
    // Ensure that aria-owns is updated on this element once the above
    // children changed causes it to have an AXObject.
    if (AXObject::HasARIAOwns(DynamicTo<Element>(node))) {
      DeferTreeUpdate(TreeUpdateReason::kUpdateAriaOwns, node);
    }
    return;
  }

  // Note that technically we do not need to remove the root node for a
  // display-locking (content-visibility) change, since it is only the
  // descendants that gain or lose their objects, but its easier to be
  // consistent here.
  RemoveSubtree(node);
}

void AXObjectCacheImpl::NodeIsAttached(Node* node) {
  CHECK(node);
  CHECK(node->isConnected());
  SCOPED_DISALLOW_LIFECYCLE_TRANSITION();

  // Ensure that ChildrenChanged() occurs on the correct parent in the case
  // where Blink layout code did not have a corresponding LayoutObject parent
  // to fire ChildrenChanged() on, such as in a display:contents case.
  ChildrenChanged(AXObject::GetParentNodeForComputeParent(*this, node));

  // It normally is not necessary to process text nodes here, because we'll
  // also get a call for the attachment of the parent element. However in the
  // YieldingParser scenario, the `previousOnLineId` can be unexpectedly null
  // for whitespace-only nodes whose inclusion had not yet been determined.
  // Sample flake: AccessibilityContenteditableDocsLi. Therefore, find the
  // highest `LayoutInline` ancestor and mark it dirty.
  if (Text* text = DynamicTo<Text>(node)) {
    if (text->ContainsOnlyWhitespaceOrEmpty()) {
      if (auto* layout_object = node->GetLayoutObject()) {
        auto* layout_parent = layout_object->Parent();
        while (layout_parent && layout_parent->Parent() &&
               layout_parent->Parent()->IsLayoutInline()) {
          layout_parent = layout_parent->Parent();
        }
        MarkSubtreeDirty(layo
"""


```