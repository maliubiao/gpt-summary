Response:
The user wants to understand the functionality of the `ax_object.cc` file in the Chromium Blink engine, specifically focusing on a provided code snippet. I need to:

1. **Analyze the code snippet:** Understand what each function within the snippet does.
2. **Identify core functionalities:** Summarize the main purposes of the code.
3. **Relate to web technologies:** Explain how these functionalities connect to JavaScript, HTML, and CSS.
4. **Provide examples:**  Illustrate the relationships with concrete scenarios.
5. **Address potential errors:**  Point out common mistakes related to these functionalities.
6. **Explain user interaction:** Describe how user actions can lead to this code being executed.
7. **Act as a debugging aid:** Suggest how this information can be used for debugging.
8. **Consider the context:** Remember this is part 8 of 10 and provide a summary of the functionalities in this specific part.

Let's break down the code snippet:

- **`UnignoredPreviousSibling()`:** Finds the previous visible sibling, skipping ignored elements.
- **`UnignoredNextInPreOrder()`:** Finds the next visible node in a pre-order traversal, skipping ignored elements.
- **`UnignoredPreviousInPreOrder()`:** Finds the previous visible node in a pre-order traversal, skipping ignored elements.
- **`ParentObject()` (two versions):** Returns the parent AXObject, with debugging assertions and checks for detached/missing parents.
- **`ParentObjectUnignored()`:** Returns the nearest visible parent, skipping ignored elements.
- **`ParentObjectIncludedInTree()`:** Returns the nearest parent that is included in the accessibility tree.
- **`GetClosestElement()`:** Returns the nearest DOM Element associated with the AXObject or its ancestors.
- **`IsContainerWidget()`:** Checks if the AXObject is a container widget that can be navigated with arrow keys.
- **`ContainerWidget()`:** Returns the nearest ancestor that is a container widget.
- **`ContainerListMarkerIncludingIgnored()`:** Returns the nearest ancestor that is a list marker (including ignored ones).
- **`ShouldUseLayoutObjectTraversalForChildren()`:** Determines if layout object traversal should be used to find children (important for pseudo-elements).
- **`UpdateChildrenIfNecessary()`:** Updates the children of the AXObject if they are marked as dirty.
- **`NeedsToUpdateChildren()`:** Checks if the children need to be updated.
- **`CheckIncludedObjectConnectedToRoot()`:** (Debug function) Verifies that an included object is properly connected to the root of the accessibility tree.
- **`SetNeedsToUpdateChildren()`:** Marks the children as needing an update.
- **`CanSafelyUseFlatTreeTraversalNow()`:**  Checks if flat tree traversal can be used safely.
- **`ShouldDestroyWhenDetachingFromParent()`:** Determines if the AXObject should be destroyed when detached from its parent.
- **`DetachFromParent()`:** Detaches the AXObject from its parent.
- **`SetChildTree()`:** Sets the ID of a child AXTree (for out-of-process iframes).
- **`ClearChildren()`:** Removes all child AXObjects.
- **`ChildrenChangedWithCleanLayout()`:** Notifies the AXObject that its children have changed, when the layout is clean.
- **`GetNode()`:** Returns the associated DOM Node (often nullptr in this part of the file).
- **`GetLayoutObject()`:** Returns the associated LayoutObject (often nullptr in this part of the file).
- **`GetElement()`:** Returns the associated DOM Element.
- **`RootScroller()`:** Returns the root scroller AXObject.
- **`DocumentFrameView()`:** Returns the LocalFrameView of the document.
- **`Language()`:** Determines the language of the AXObject.
- **Scroll-related functions (`IsScrollableContainer()`, `IsUserScrollable()`, `GetScrollOffset()`, `MinimumScrollOffset()`, `MaximumScrollOffset()`, `SetScrollOffset()`, `Scroll()`):** Handle scrolling functionalities.
- **Table-related functions (`IsTableLikeRole()`, `IsTableRowLikeRole()`, `IsTableCellLikeRole()`, `ColumnCount()`, `RowCount()`, `ColumnHeaders()`, `RowHeaders()`, `CellForColumnAndRow()`, `ColumnIndex()`, `RowIndex()`, `ColumnSpan()`, `RowSpan()`, `TableRowChildren()`, `TableCellChildren()`):** Handle accessibility for table-like structures.
- **`GetRelativeBounds()`:** Computes the position and size of the AXObject relative to a container.
- **`LocalBoundingBoxRectForAccessibility()`:** Returns the local bounding box (used for inline text).
- **`GetBoundsInFrameCoordinates()`:** Gets the bounding box in frame coordinates.
- **`UpdateStyleAndLayoutTreeForNode()`:** (Not in the provided snippet, but mentioned in the last line).

**Overall Functionality Summary for this Part:**

This section of `ax_object.cc` focuses heavily on **tree traversal and manipulation within the accessibility tree**. It provides methods for finding siblings, parents, and children while considering whether elements are ignored for accessibility purposes. It also includes functionalities for handling parent-child relationships, updating the accessibility tree when changes occur, and determining the geometry and scrolling behavior of accessible objects. A significant portion is dedicated to making the accessibility tree accurately reflect the underlying DOM structure while accounting for CSS layout and accessibility-specific attributes like `aria-hidden`. Finally, it introduces basic table structure navigation.

这是目录为blink/renderer/modules/accessibility/ax_object.cc的chromium blink引擎源代码文件， 这是第8部分，共10部分，请归纳一下它的功能

这个代码片段主要集中在 `AXObject` 的以下几个核心功能：

**1. 树的遍历和导航 (Tree Traversal and Navigation):**

* **查找兄弟节点 (Sibling Navigation):**
    * `UnignoredPreviousSibling()`:  用于查找在同一个未被忽略的父对象下的前一个未被忽略的兄弟节点。它会跳过被忽略的兄弟节点。
    * **假设输入:** 当前 `AXObject` 对象是某个元素的表示。
    * **输出:**  返回前一个未被忽略的兄弟 `AXObject` 指针，如果不存在则返回 `nullptr`。
* **前序遍历 (Pre-order Traversal):**
    * `UnignoredNextInPreOrder()`: 查找在可访问性树中按照前序遍历的下一个未被忽略的节点。
    * `UnignoredPreviousInPreOrder()`: 查找在可访问性树中按照前序遍历的前一个未被忽略的节点。
    * **假设输入:** 当前 `AXObject` 对象是可访问性树中的一个节点。
    * **输出:** 返回下一个/前一个未被忽略的 `AXObject` 指针，如果不存在则返回 `nullptr`。

**与 JavaScript, HTML, CSS 的关系:**

这些方法允许辅助技术（例如屏幕阅读器）按照文档的逻辑结构（由 HTML 决定）进行导航，同时考虑到 CSS 的 `display: none` 或 `visibility: hidden` 以及 `aria-hidden` 属性导致的元素被忽略的情况。

**举例说明:**

假设有以下 HTML 结构：

```html
<div>
  <span>可见元素1</span>
  <span aria-hidden="true">被忽略的元素</span>
  <span>可见元素2</span>
</div>
```

如果当前 `AXObject` 代表 "可见元素2"，那么 `UnignoredPreviousSibling()` 将返回代表 "可见元素1" 的 `AXObject`，而跳过 "被忽略的元素"。

**2. 父节点访问 (Parent Access):**

* `ParentObject()` (两个版本): 返回当前 `AXObject` 的父 `AXObject`。包含调试断言，用于检查是否已分离或缺少父节点。
* `ParentObjectUnignored()`: 返回当前 `AXObject` 的最近的未被忽略的父 `AXObject`，跳过中间被忽略的父节点。
* `ParentObjectIncludedInTree()`: 返回当前 `AXObject` 的最近的被包含在可访问性树中的父 `AXObject`。

**与 JavaScript, HTML, CSS 的关系:**

这些方法反映了 DOM 树的父子关系，但考虑了可访问性树的结构，其中一些 DOM 元素可能由于 CSS 或 `aria-hidden` 而不被包含。JavaScript 可以通过 Accessibility API 调用这些方法来获取元素的父节点信息。

**举例说明:**

假设一个 `div` 元素内部有一个 `span`，并且该 `div` 设置了 `aria-hidden="true"`，而 `span` 本身没有被隐藏。那么，对于 `span` 的 `AXObject`，`ParentObject()` 将返回代表 `div` 的 `AXObject`，但 `ParentObjectUnignored()` 将会继续向上查找，直到找到一个未被忽略的祖先。

**3. 关联 DOM 元素 (Associating with DOM Elements):**

* `GetClosestElement()`:  返回与当前 `AXObject` 或其祖先 `AXObject` 关联的最近的 DOM `Element`。

**与 JavaScript, HTML, CSS 的关系:**

这个方法将可访问性树中的对象映射回 DOM 树中的元素，这对于辅助技术理解元素的语义和内容至关重要。JavaScript 可以利用这个方法来获取与特定可访问性对象对应的 DOM 元素，并进行进一步的操作。

**4. 容器小部件识别 (Container Widget Identification):**

* `IsContainerWidget()`: 判断当前 `AXObject` 是否是一个容器小部件，用户可以使用方向键在子小部件之间导航。
* `ContainerWidget()`:  返回当前 `AXObject` 最近的未被忽略的容器小部件祖先。
* `ContainerListMarkerIncludingIgnored()`: 返回包含被忽略元素的最近的列表标记容器。

**与 JavaScript, HTML, CSS 的关系:**

这些方法与 HTML 中具有交互性的元素（例如具有 `role="listbox"` 或 `role="radiogroup"` 的元素）相关，它们允许辅助技术知道如何与这些复合控件进行交互。

**5. 子节点更新 (Children Update):**

* `ShouldUseLayoutObjectTraversalForChildren()`:  决定在获取子 `AXObject` 时是否应该使用布局对象遍历。对于伪元素或伪元素的后代，通常使用布局对象遍历。
* `UpdateChildrenIfNecessary()`: 如果需要更新子节点（`children_dirty_` 为 true），则清除旧的子节点并重新添加。
* `NeedsToUpdateChildren()`: 检查是否需要更新子节点。
* `SetNeedsToUpdateChildren()`: 设置是否需要更新子节点的状态。

**与 JavaScript, HTML, CSS 的关系:**

当 HTML 结构发生变化（例如添加或删除子元素），或者 CSS 样式影响到元素的渲染和可访问性时，需要更新可访问性树的结构。这些方法确保可访问性树与 DOM 树和渲染状态保持同步。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **页面加载和渲染:** 当用户导航到一个网页时，Blink 引擎会解析 HTML、应用 CSS 并构建渲染树。
2. **可访问性树构建:**  Blink 引擎会根据渲染树构建可访问性树，`AXObject` 就是可访问性树的节点。
3. **用户交互触发:** 用户与页面进行交互，例如：
    * 使用键盘上的 Tab 键或方向键导航。
    * 使用屏幕阅读器等辅助技术浏览页面。
    * JavaScript 代码修改了 DOM 结构或 CSS 样式。
4. **可访问性事件触发:** 这些用户交互或 DOM/CSS 变化会触发可访问性相关的事件。
5. **`AXObject` 方法调用:**  例如，当屏幕阅读器需要知道当前元素的下一个或上一个可见元素时，就会调用 `UnignoredNextInPreOrder()` 或 `UnignoredPreviousSibling()` 等方法。当 DOM 结构改变时，`UpdateChildrenIfNecessary()` 或 `SetNeedsToUpdateChildren()` 会被调用。
6. **调试线索:** 在调试可访问性问题时，可以设置断点在这些方法中，观察 `AXObject` 的状态和调用的堆栈信息，从而了解可访问性树的构建和更新过程，以及辅助技术是如何与页面进行交互的。例如，如果屏幕阅读器无法正确读取某个元素，可能是因为 `UnignoredPreviousSibling()` 方法返回了错误的节点。

**常见的用户或编程使用错误举例:**

* **HTML 结构错误导致可访问性树不正确:** 例如，缺少必要的语义化标签，或者使用了不正确的 ARIA 属性。这可能导致 `ParentObjectUnignored()` 返回意外的结果。
    * **假设输入:** 一个嵌套的 `div` 结构，其中内部 `div` 错误地使用了 `role="button"`。
    * **输出:**  `ParentObjectUnignored()` 可能会错误地将外部 `div` 识别为按钮的容器，尽管在语义上它们没有这种关系.
* **CSS 隐藏元素但未设置 `aria-hidden="true"`:** 这会导致元素在视觉上隐藏，但在可访问性树中仍然存在，从而干扰辅助技术。`UnignoredPreviousSibling()` 等方法可能返回不应该被用户访问的隐藏元素。
* **JavaScript 操作 DOM 但未及时更新可访问性信息:**  例如，使用 JavaScript 动态添加元素后，没有通知可访问性系统，导致 `UpdateChildrenIfNecessary()` 未被触发，可访问性树仍然是旧的。
* **错误地使用 `aria-owns` 等属性:** 可能导致 `ParentObject()` 返回的父节点与 DOM 树的结构不一致。

**归纳一下它的功能 (针对提供的代码片段):**

这部分 `ax_object.cc` 的功能主要集中在 **维护和导航可访问性树的结构**。它提供了查找父节点、兄弟节点和子节点的方法，并考虑了元素是否被忽略的情况。此外，它还包含了识别特定类型的可访问性对象（如容器小部件）以及管理子节点更新的机制。这些功能是确保辅助技术能够正确理解和操作网页内容的基础。这部分代码是可访问性实现的核心组成部分，连接了底层的 DOM 和渲染结构与上层的辅助技术。

Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共10部分，请归纳一下它的功能

"""
use it is not clear whether to search for the "
                    "sibling in the unignored tree or in the whole tree: "
                 << this;
  }

  // Find the previous sibling for the same unignored parent object,
  // flattening accessibility ignored objects.
  //
  // For example :
  // ++A
  // ++++B
  // ++++C IGNORED
  // ++++++E
  // ++++D
  // Objects [B, E, D] will be siblings since C is ignored.

  const AXObject* current_obj = this;
  while (current_obj) {
    AXObject* sibling = current_obj->PreviousSiblingIncludingIgnored();
    if (sibling) {
      const AXObject* unignored_parent = ParentObjectUnignored();
      // If we found an ignored sibling, walk in previous post-order
      // until an unignored object is found, flattening the ignored object.
      while (sibling && sibling->IsIgnored()) {
        sibling =
            sibling->PreviousInPostOrderIncludingIgnored(unignored_parent);
      }
      return sibling;
    }

    // If a sibling has not been found, try again with the parent object,
    // until the unignored parent is reached.
    current_obj = current_obj->ParentObjectIncludedInTree();
    if (!current_obj || !current_obj->IsIgnored())
      return nullptr;
  }
  return nullptr;
}

AXObject* AXObject::UnignoredNextInPreOrder() const {
  AXObject* next = NextInPreOrderIncludingIgnored();
  while (next && next->IsIgnored()) {
    next = next->NextInPreOrderIncludingIgnored();
  }
  return next;
}

AXObject* AXObject::UnignoredPreviousInPreOrder() const {
  AXObject* previous = PreviousInPreOrderIncludingIgnored();
  while (previous && previous->IsIgnored()) {
    previous = previous->PreviousInPreOrderIncludingIgnored();
  }
  return previous;
}

AXObject* AXObject::ParentObject() const {
  DUMP_WILL_BE_CHECK(!IsDetached());
  DUMP_WILL_BE_CHECK(!IsMissingParent()) << "Missing parent: " << this;

  return parent_;
}

AXObject* AXObject::ParentObject() {
  DUMP_WILL_BE_CHECK(!IsDetached());
  // Calling IsMissingParent can cause us to dereference pointers that
  // are null on detached objects, return early here to avoid crashing.
  // TODO(accessibility) Remove early return and change above assertion
  // to CHECK() once this no longer occurs.
  if (IsDetached()) {
    return nullptr;
  }
  DUMP_WILL_BE_CHECK(!IsMissingParent()) << "Missing parent: " << this;

  // TODO(crbug.com/337178753): this should not be necessary once subtree
  // removals can be immediate, complete and safe.
  if (IsMissingParent()) {
    AXObjectCache().RemoveSubtree(GetNode());
    return nullptr;
  }

  return parent_;
}

AXObject* AXObject::ParentObjectUnignored() const {
  AXObject* parent;
  for (parent = ParentObject(); parent && parent->IsIgnored();
       parent = parent->ParentObject()) {
  }

  return parent;
}

AXObject* AXObject::ParentObjectIncludedInTree() const {
  AXObject* parent;
  for (parent = ParentObject();
       parent && !parent->IsIncludedInTree();
       parent = parent->ParentObject()) {
  }

  return parent;
}

Element* AXObject::GetClosestElement() const {
  Element* element = GetElement();
  // Certain AXObjects, such as those created from layout tree traversal,
  // have null values for `AXObject::GetNode()` and `AXObject::GetElement()`.
  // Just look for the closest parent that can handle this request.
  if (!element) {
    for (AXObject* parent = ParentObject(); parent;
         parent = parent->ParentObject()) {
      // It's possible to have a parent without a node here if the parent is a
      // pseudo element descendant. Since we're looking for the nearest element,
      // keep going up the ancestor chain until we find a parent that has one.
      element = parent->GetElement();
      if (element) {
        return element;
      }
    }
  }

  return element;
}

// Container widgets are those that a user tabs into and arrows around
// sub-widgets
bool AXObject::IsContainerWidget() const {
  return ui::IsContainerWithSelectableChildren(RoleValue());
}

AXObject* AXObject::ContainerWidget() const {
  AXObject* ancestor = ParentObjectUnignored();
  while (ancestor && !ancestor->IsContainerWidget())
    ancestor = ancestor->ParentObjectUnignored();

  return ancestor;
}

AXObject* AXObject::ContainerListMarkerIncludingIgnored() const {
  AXObject* ancestor = ParentObject();
  while (ancestor && (!ancestor->GetLayoutObject() ||
                      !ancestor->GetLayoutObject()->IsListMarker())) {
    ancestor = ancestor->ParentObject();
  }

  return ancestor;
}

// Determine which traversal approach is used to get children of an object.
bool AXObject::ShouldUseLayoutObjectTraversalForChildren() const {
  // There are two types of traversal used to find AXObjects:
  // 1. LayoutTreeBuilderTraversal, which takes FlatTreeTraversal and adds
  // pseudo elements on top of that. This is the usual case. However, while this
  // can add pseudo elements it cannot add important content descendants such as
  // text and images. For this, LayoutObject traversal (#2) is required.
  // 2. LayoutObject traversal, which just uses the children of a LayoutObject.

  // Therefore, if the object is a pseudo element or pseudo element descendant,
  // use LayoutObject traversal (#2) to find the children.
  if (GetNode() && GetNode()->IsPseudoElement())
    return true;

  // If no node, this is an anonymous layout object. The only way this can be
  // reached is inside a pseudo element subtree.
  if (!GetNode() && GetLayoutObject()) {
    DCHECK(GetLayoutObject()->IsAnonymous());
    DCHECK(AXObjectCacheImpl::IsRelevantPseudoElementDescendant(
        *GetLayoutObject()));
    return true;
  }

  return false;
}

void AXObject::UpdateChildrenIfNecessary() {
#if DCHECK_IS_ON()
  DCHECK(GetDocument()) << this;
  DCHECK(GetDocument()->IsActive());
  DCHECK(!GetDocument()->IsDetached());
  DCHECK(GetDocument()->GetPage());
  DCHECK(GetDocument()->View());
  DCHECK(!AXObjectCache().HasBeenDisposed());
#endif

  if (!NeedsToUpdateChildren()) {
    CHECK(!child_cached_values_need_update_)
        << "This should only be set when also setting children_dirty_ to true: "
        << this;
    return;
  }

  if (AXObjectCache().IsFrozen()) {
    DUMP_WILL_BE_CHECK(!AXObjectCache().IsFrozen())
        << "Object should have already had its children updated in "
           "AXObjectCacheImpl::FinalizeTree(): "
        << this;
    return;
  }

  if (!CanHaveChildren()) {
    // Clear any children in case the node previously allowed children.
    ClearChildren();
    SetNeedsToUpdateChildren(false);
    child_cached_values_need_update_ = false;
    return;
  }

  UpdateCachedAttributeValuesIfNeeded();

  ClearChildren();
  AddChildren();
  CHECK(!children_dirty_);
  CHECK(!child_cached_values_need_update_);
}

bool AXObject::NeedsToUpdateChildren() const {
  return children_dirty_;
}

#if DCHECK_IS_ON()
void AXObject::CheckIncludedObjectConnectedToRoot() const {
  if (!IsIncludedInTree() || IsRoot()) {
    return;
  }

  const AXObject* included_child = this;
  const AXObject* ancestor = nullptr;
  const AXObject* included_parent = nullptr;
  for (ancestor = ParentObject(); ancestor;
       ancestor = ancestor->ParentObject()) {
    if (ancestor->IsIncludedInTree()) {
      included_parent = ancestor;
      if (included_parent->CachedChildrenIncludingIgnored().Find(
              included_child) == kNotFound) {
        if (AXObject* parent_for_repair = ComputeParent()) {
          parent_for_repair->CheckIncludedObjectConnectedToRoot();
        }

        NOTREACHED() << "Cannot find included child in parents children:\n"
                     << "\n* Child: " << included_child
                     << "\n* Parent:  " << included_parent
                     << "\n--------------\n"
                     << included_parent->GetAXTreeForThis();
      }
      if (included_parent->IsRoot()) {
        return;
      }
      included_child = included_parent;
    }
  }

  NOTREACHED() << "Did not find included parent path to root:"
               << "\n* Last found included parent: " << included_parent
               << "\n* Current object in tree: " << GetAXTreeForThis();
}
#endif

void AXObject::SetNeedsToUpdateChildren(bool update) {
  CHECK(AXObjectCache().lifecycle().StateAllowsAXObjectsToBeDirtied())
      << AXObjectCache();

  if (!update) {
    children_dirty_ = false;
    child_cached_values_need_update_ = false;
    return;
  }

#if defined(AX_FAIL_FAST_BUILD)
  SANITIZER_CHECK(!is_adding_children_)
      << "Should not invalidate children while adding them: " << this;
#endif

  if (children_dirty_) {
    return;
  }

  children_dirty_ = true;
  SetAncestorsHaveDirtyDescendants();
}

// static
bool AXObject::CanSafelyUseFlatTreeTraversalNow(Document& document) {
  return !document.IsFlatTreeTraversalForbidden() &&
         !document.GetSlotAssignmentEngine().HasPendingSlotAssignmentRecalc();
}

bool AXObject::ShouldDestroyWhenDetachingFromParent() const {
  // Do not interfere with the destruction loop in AXObjectCacheImpl::Dispose().
  if (IsDetached() || AXObjectCache().IsDisposing() ||
      AXObjectCache().IsDisposing()) {
    return false;
  }

  // Destroy all pseudo-elements that can't compute their parents, because we
  // are only able to re-attach them via top-down tree walk and not via
  // RepairMissingParent. See GetParentNodeForComputeParent for more
  // commentary.
  auto* layout_object = GetLayoutObject();
  if (layout_object) {
    Node* closest_node =
        AXObjectCacheImpl::GetClosestNodeForLayoutObject(layout_object);
    if (closest_node && closest_node->IsPseudoElement()) {
      return true;
    }
  }

  // Inline textbox children are dependent on their parent's ignored state.
  if (IsAXInlineTextBox()) {
    return true;
  }

  // Image map children are entirely dependent on the parent image.
  if (ParentObject() && IsA<HTMLImageElement>(ParentObject()->GetNode())) {
    return true;
  }

  return false;
}

void AXObject::DetachFromParent() {
  if (IsDetached()) {
    return;
  }

  CHECK(!AXObjectCache().IsFrozen())
      << "Do not detach parent while tree is frozen: " << this;
  if (ShouldDestroyWhenDetachingFromParent()) {
    if (GetNode()) {
      AXObjectCache().RemoveSubtree(GetNode());
    } else {
      // This is rare, but technically a pseudo element descendant can have a
      // subtree, and they do not have nodes.
      AXObjectCache().RemoveIncludedSubtree(this, /* remove_root */ true);
    }
  }
  parent_ = nullptr;
}

void AXObject::SetChildTree(const ui::AXTreeID& child_tree_id) {
  CHECK(!IsDetached());
  CHECK_GE(GetDocument()->Lifecycle().GetState(),
           DocumentLifecycle::kLayoutClean)
      << "Stitching a child tree is an action, and all actions should be "
         "performed when the layout is clean.";
  if (child_tree_id == ui::AXTreeIDUnknown() ||
      child_tree_id_ == child_tree_id) {
    return;
  }
  child_tree_id_ = child_tree_id;
  // A node with a child tree is automatically considered a leaf, and
  // CanHaveChildren() will return false for it.
  AXObjectCache().MarkAXObjectDirtyWithCleanLayout(this);
  AXObjectCache().RemoveSubtree(GetNode(), /*remove_root*/ false);
  AXObjectCache().UpdateAXForAllDocuments();
}

void AXObject::ClearChildren() {
  CHECK(!IsDetached());
  CHECK(!AXObjectCache().IsFrozen())
      << "Do not clear children while tree is frozen: " << this;

  // Detach all weak pointers from immediate children to their parents.
  // First check to make sure the child's parent wasn't already reassigned.
  // In addition, the immediate children are different from children_, and are
  // the objects where the parent_ points to this. For example:
  // Parent (this)
  //   Child not included in tree  (immediate child)
  //     Child included in tree (an item in |children_|)
  // These situations only occur for children that were backed by a DOM node.
  // Therefore, in addition to looping through |children_|, we must also loop
  // through any unincluded children associated with any DOM children;
  // TODO(accessibility) Try to remove ugly second loop when we transition to
  // AccessibilityExposeIgnoredNodes().

  // Loop through AXObject children.

#if defined(AX_FAIL_FAST_BUILD)
  SANITIZER_CHECK(!is_adding_children_)
      << "Should not attempt to simultaneously add and clear children on: "
      << this;
  SANITIZER_CHECK(!is_computing_text_from_descendants_)
      << "Should not attempt to simultaneously compute text from descendants "
         "and clear children on: "
      << this;
#endif

  // Detach included children from their parent (this).
  for (const auto& child : children_) {
    // Check parent first, as the child might be several levels down if there
    // are unincluded nodes in between, in which case the cached parent will
    // also be a descendant (unlike children_, parent_ does not skip levels).
    // Another case where the parent is not the same is when the child has been
    // reparented using aria-owns.
    if (child->ParentObjectIfPresent() == this) {
      child->DetachFromParent();
    }
  }

  children_.clear();

  Node* node = GetNode();
  if (!node) {
    return;
  }

  // Detach unincluded children from their parent (this).
  // These are children that were not cleared from first loop, as well as
  // children that will be included once the parent next updates its children.
  for (Node* child_node = NodeTraversal::FirstChild(*node); child_node;
       child_node = NodeTraversal::NextSibling(*child_node)) {
    // Get the child object that should be detached from this parent.
    // Do not invalidate from layout, because it may be unsafe to check layout
    // at this time. However, do allow invalidations if an object changes its
    // display locking (content-visibility: auto) status, as this may be the
    // only chance to do that, and it's safe to do now.
    AXObject* ax_child_from_node = AXObjectCache().Get(child_node);
    if (ax_child_from_node &&
        ax_child_from_node->ParentObjectIfPresent() == this) {
      ax_child_from_node->DetachFromParent();
    }
  }

  // On clearing of children, ensure that our plugin serializer, if it exists,
  // is properly reset.
  if (IsA<HTMLEmbedElement>(node)) {
    AXObjectCache().ResetPluginTreeSerializer();
  }
}

void AXObject::ChildrenChangedWithCleanLayout() {
  DCHECK(!IsDetached()) << "Don't call on detached node: " << this;

  // When children changed on a <map> that means we need to forward the
  // children changed to the <img> that parents the <area> elements.
  // TODO(accessibility) Consider treating <img usemap> as aria-owns so that
  // we get implementation "for free" vai relation cache, etc.
  if (HTMLMapElement* map_element = DynamicTo<HTMLMapElement>(GetNode())) {
    HTMLImageElement* image_element = map_element->ImageElement();
    if (image_element) {
      AXObject* ax_image = AXObjectCache().Get(image_element);
      if (ax_image) {
        ax_image->ChildrenChangedWithCleanLayout();
        return;
      }
    }
  }

  // Always invalidate |children_| even if it was invalidated before, because
  // now layout is clean.
  SetNeedsToUpdateChildren();

  // Between the time that AXObjectCacheImpl::ChildrenChanged() determines
  // which included parent to use and now, it's possible that the parent will
  // no longer be ignored. This is rare, but is covered by this test:
  // external/wpt/accessibility/crashtests/delayed-ignored-change.html/
  // In this case, first ancestor that's still included in the tree will used.
  if (!IsIncludedInTree()) {
    if (AXObject* ax_parent = ParentObject()) {
      ax_parent->ChildrenChangedWithCleanLayout();
      return;
    }
  }

  // TODO(accessibility) Move this up.
  if (!CanHaveChildren()) {
    return;
  }

  DCHECK(!IsDetached()) << "None of the above should be able to detach |this|: "
                        << this;

  AXObjectCache().MarkAXObjectDirtyWithCleanLayout(this);
}

Node* AXObject::GetNode() const {
  return nullptr;
}

LayoutObject* AXObject::GetLayoutObject() const {
  return nullptr;
}

Element* AXObject::GetElement() const {
  return DynamicTo<Element>(GetNode());
}

AXObject* AXObject::RootScroller() const {
  Node* global_root_scroller = GetDocument()
                                   ->GetPage()
                                   ->GlobalRootScrollerController()
                                   .GlobalRootScroller();
  if (!global_root_scroller)
    return nullptr;

  // Only return the root scroller if it's part of the same document.
  if (global_root_scroller->GetDocument() != GetDocument())
    return nullptr;

  return AXObjectCache().Get(global_root_scroller);
}

LocalFrameView* AXObject::DocumentFrameView() const {
  if (Document* document = GetDocument())
    return document->View();
  return nullptr;
}

AtomicString AXObject::Language() const {
  if (GetElement()) {
    const AtomicString& lang =
        GetElement()->FastGetAttribute(html_names::kLangAttr);
    if (!lang.empty()) {
      return lang;
    }
  }

  // Return early for non-root nodes. The root node's language can't be set by
  // the author so we need to determine its language below.
  if (!IsWebArea()) {
    return g_null_atom;
  }

  // Return the language of the <html> element if present.
  const Document* document = GetDocument();
  DCHECK(document);
  if (Element* html_element = document->documentElement()) {
    if (const AtomicString& html_lang =
            html_element->getAttribute(html_names::kLangAttr)) {
      return html_lang;
    }
  }

  // Fall back to the content language specified in the meta tag.
  // This is not part of what the HTML5 Standard suggests but it still
  // appears to be necessary.
  if (const String languages = document->ContentLanguage()) {
    String first_language = languages.Substring(0, languages.Find(","));
    if (!first_language.empty()) {
      return AtomicString(first_language.StripWhiteSpace());
    }
  }

  // Use the first accept language preference if present.
  if (Page* page = document->GetPage()) {
    const String languages = page->GetChromeClient().AcceptLanguages();
    String first_language = languages.Substring(0, languages.Find(","));
    if (!first_language.empty()) {
      return AtomicString(first_language.StripWhiteSpace());
    }
  }

  // As a last resort, return the default language of the browser's UI.
  AtomicString default_language = DefaultLanguage();
  return default_language;
}

//
// Scrollable containers.
//

bool AXObject::IsScrollableContainer() const {
  return !!GetScrollableAreaIfScrollable();
}

bool AXObject::IsUserScrollable() const {
  Node* node = GetNode();
  if (!node) {
    return false;
  }

  // The element that scrolls the document is not the document itself.
  if (node->IsDocumentNode()) {
    Document& document = node->GetDocument();
    return document.GetLayoutView()->IsUserScrollable();
  }

  LayoutBox* layout_box = DynamicTo<LayoutBox>(node->GetLayoutObject());
  if (!layout_box) {
    return false;
  }

  return layout_box->IsUserScrollable();
}

gfx::Point AXObject::GetScrollOffset() const {
  ScrollableArea* area = GetScrollableAreaIfScrollable();
  if (!area)
    return gfx::Point();
  // TODO(crbug.com/1274078): Should this be converted to scroll position, or
  // should the result type be gfx::Vector2d?
  return gfx::PointAtOffsetFromOrigin(area->ScrollOffsetInt());
}

gfx::Point AXObject::MinimumScrollOffset() const {
  ScrollableArea* area = GetScrollableAreaIfScrollable();
  if (!area)
    return gfx::Point();
  // TODO(crbug.com/1274078): Should this be converted to scroll position, or
  // should the result type be gfx::Vector2d?
  return gfx::PointAtOffsetFromOrigin(area->MinimumScrollOffsetInt());
}

gfx::Point AXObject::MaximumScrollOffset() const {
  ScrollableArea* area = GetScrollableAreaIfScrollable();
  if (!area)
    return gfx::Point();
  // TODO(crbug.com/1274078): Should this be converted to scroll position, or
  // should the result type be gfx::Vector2d?
  return gfx::PointAtOffsetFromOrigin(area->MaximumScrollOffsetInt());
}

void AXObject::SetScrollOffset(const gfx::Point& offset) const {
  ScrollableArea* area = GetScrollableAreaIfScrollable();
  if (!area)
    return;

  // TODO(bokan): This should potentially be a UserScroll.
  area->SetScrollOffset(ScrollOffset(offset.OffsetFromOrigin()),
                        mojom::blink::ScrollType::kProgrammatic);
}

void AXObject::Scroll(ax::mojom::blink::Action scroll_action) const {
  AXObject* offset_container = nullptr;
  gfx::RectF bounds;
  gfx::Transform container_transform;
  GetRelativeBounds(&offset_container, bounds, container_transform);
  if (bounds.IsEmpty())
    return;

  gfx::Point initial = GetScrollOffset();
  gfx::Point min = MinimumScrollOffset();
  gfx::Point max = MaximumScrollOffset();

  // TODO(anastasi): This 4/5ths came from the Android implementation, revisit
  // to find the appropriate modifier to keep enough context onscreen after
  // scrolling.
  int page_x = std::max(base::ClampRound<int>(bounds.width() * 4 / 5), 1);
  int page_y = std::max(base::ClampRound<int>(bounds.height() * 4 / 5), 1);

  // Forward/backward defaults to down/up unless it can only be scrolled
  // horizontally.
  if (scroll_action == ax::mojom::blink::Action::kScrollForward) {
    scroll_action = max.y() > min.y() ? ax::mojom::blink::Action::kScrollDown
                                      : ax::mojom::blink::Action::kScrollRight;
  } else if (scroll_action == ax::mojom::blink::Action::kScrollBackward) {
    scroll_action = max.y() > min.y() ? ax::mojom::blink::Action::kScrollUp
                                      : ax::mojom::blink::Action::kScrollLeft;
  }

  int x = initial.x();
  int y = initial.y();
  switch (scroll_action) {
    case ax::mojom::blink::Action::kScrollUp:
      if (initial.y() == min.y())
        return;
      y = std::max(initial.y() - page_y, min.y());
      break;
    case ax::mojom::blink::Action::kScrollDown:
      if (initial.y() == max.y())
        return;
      y = std::min(initial.y() + page_y, max.y());
      break;
    case ax::mojom::blink::Action::kScrollLeft:
      if (initial.x() == min.x())
        return;
      x = std::max(initial.x() - page_x, min.x());
      break;
    case ax::mojom::blink::Action::kScrollRight:
      if (initial.x() == max.x())
        return;
      x = std::min(initial.x() + page_x, max.x());
      break;
    default:
      NOTREACHED();
  }

  SetScrollOffset(gfx::Point(x, y));

  if (!RuntimeEnabledFeatures::
          SynthesizedKeyboardEventsForAccessibilityActionsEnabled())
    return;

  // There are no keys that produce scroll left/right, so we shouldn't
  // synthesize any keyboard events for these actions.
  if (scroll_action == ax::mojom::blink::Action::kScrollLeft ||
      scroll_action == ax::mojom::blink::Action::kScrollRight)
    return;

  LocalDOMWindow* local_dom_window = GetDocument()->domWindow();
  DispatchKeyboardEvent(local_dom_window, WebInputEvent::Type::kRawKeyDown,
                        scroll_action);
  DispatchKeyboardEvent(local_dom_window, WebInputEvent::Type::kKeyUp,
                        scroll_action);
}

bool AXObject::IsTableLikeRole() const {
  return ui::IsTableLike(RoleValue()) ||
         RoleValue() == ax::mojom::blink::Role::kLayoutTable;
}

bool AXObject::IsTableRowLikeRole() const {
  return ui::IsTableRow(RoleValue()) ||
         RoleValue() == ax::mojom::blink::Role::kLayoutTableRow;
}

bool AXObject::IsTableCellLikeRole() const {
  return ui::IsCellOrTableHeader(RoleValue()) ||
         RoleValue() == ax::mojom::blink::Role::kLayoutTableCell;
}

unsigned AXObject::ColumnCount() const {
  if (!IsTableLikeRole())
    return 0;

  unsigned max_column_count = 0;
  for (const auto& row : TableRowChildren()) {
    unsigned column_count = row->TableCellChildren().size();
    max_column_count = std::max(column_count, max_column_count);
  }

  return max_column_count;
}

unsigned AXObject::RowCount() const {
  if (!IsTableLikeRole())
    return 0;

  return TableRowChildren().size();
}

void AXObject::ColumnHeaders(AXObjectVector& headers) const {
  if (!IsTableLikeRole())
    return;

  for (const auto& row : TableRowChildren()) {
    for (const auto& cell : row->TableCellChildren()) {
      if (cell->RoleValue() == ax::mojom::blink::Role::kColumnHeader)
        headers.push_back(cell);
    }
  }
}

void AXObject::RowHeaders(AXObjectVector& headers) const {
  if (!IsTableLikeRole())
    return;

  for (const auto& row : TableRowChildren()) {
    for (const auto& cell : row->TableCellChildren()) {
      if (cell->RoleValue() == ax::mojom::blink::Role::kRowHeader)
        headers.push_back(cell);
    }
  }
}

AXObject* AXObject::CellForColumnAndRow(unsigned target_column_index,
                                        unsigned target_row_index) const {
  if (!IsTableLikeRole())
    return nullptr;

  // Note that this code is only triggered if this is not a LayoutTable,
  // i.e. it's an ARIA grid/table.
  //
  // TODO(dmazzoni): delete this code or rename it "for testing only"
  // since it's only needed for Blink web tests and not for production.
  unsigned row_index = 0;
  for (const auto& row : TableRowChildren()) {
    unsigned column_index = 0;
    for (const auto& cell : row->TableCellChildren()) {
      if (target_column_index == column_index && target_row_index == row_index)
        return cell.Get();
      column_index++;
    }
    row_index++;
  }

  return nullptr;
}

unsigned AXObject::ColumnIndex() const {
  return 0;
}

unsigned AXObject::RowIndex() const {
  return 0;
}

unsigned AXObject::ColumnSpan() const {
  return IsTableCellLikeRole() ? 1 : 0;
}

unsigned AXObject::RowSpan() const {
  return IsTableCellLikeRole() ? 1 : 0;
}

AXObject::AXObjectVector AXObject::TableRowChildren() const {
  AXObjectVector result;
  for (const auto& child : ChildrenIncludingIgnored()) {
    if (child->IsTableRowLikeRole())
      result.push_back(child);
    else if (child->RoleValue() == ax::mojom::blink::Role::kRowGroup)
      result.AppendVector(child->TableRowChildren());
  }
  return result;
}

AXObject::AXObjectVector AXObject::TableCellChildren() const {
  AXObjectVector result;
  for (const auto& child : ChildrenIncludingIgnored()) {
    if (child->IsTableCellLikeRole())
      result.push_back(child);
    else if (child->RoleValue() == ax::mojom::blink::Role::kGenericContainer)
      result.AppendVector(child->TableCellChildren());
  }
  return result;
}

void AXObject::GetRelativeBounds(AXObject** out_container,
                                 gfx::RectF& out_bounds_in_container,
                                 gfx::Transform& out_container_transform,
                                 bool* clips_children) const {
  *out_container = nullptr;
  out_bounds_in_container = gfx::RectF();
  out_container_transform.MakeIdentity();

  // First check if it has explicit bounds, for example if this element is tied
  // to a canvas path. When explicit coordinates are provided, the ID of the
  // explicit container element that the coordinates are relative to must be
  // provided too.
  if (!explicit_element_rect_.IsEmpty()) {
    *out_container = AXObjectCache().ObjectFromAXID(explicit_container_id_);
    if (*out_container) {
      out_bounds_in_container = gfx::RectF(explicit_element_rect_);
      return;
    }
  }

  LayoutObject* layout_object = GetLayoutObject();
  if (!layout_object)
    return;

  if (layout_object->IsFixedPositioned() ||
      layout_object->IsStickyPositioned()) {
    AXObjectCache().AddToFixedOrStickyNodeList(this);
  }

  if (clips_children) {
    if (IsA<Document>(GetNode())) {
      *clips_children = true;
    } else {
      *clips_children = layout_object->HasNonVisibleOverflow();
    }
  }

  if (IsA<Document>(GetNode())) {
    if (LocalFrameView* view = layout_object->GetFrame()->View()) {
      out_bounds_in_container.set_size(gfx::SizeF(view->Size()));

      // If it's a popup, account for the popup window's offset.
      if (view->GetPage()->GetChromeClient().IsPopup()) {
        gfx::Rect frame_rect = view->FrameToScreen(view->FrameRect());
        LocalFrameView* root_view =
            AXObjectCache().GetDocument().GetFrame()->View();
        gfx::Rect root_frame_rect =
            root_view->FrameToScreen(root_view->FrameRect());

        // Screen coordinates are in DIP without device scale factor applied.
        // Accessibility expects device scale factor applied here which is
        // unapplied at the destination AXTree.
        float scale_factor =
            view->GetPage()->GetChromeClient().WindowToViewportScalar(
                layout_object->GetFrame(), 1.0f);
        out_bounds_in_container.set_origin(
            gfx::PointF(scale_factor * (frame_rect.x() - root_frame_rect.x()),
                        scale_factor * (frame_rect.y() - root_frame_rect.y())));
      }
    }
    return;
  }

  // First compute the container. The container must be an ancestor in the
  // accessibility tree, and its LayoutObject must be an ancestor in the layout
  // tree. Get the first such ancestor that's either scrollable or has a paint
  // layer.
  AXObject* container = ParentObjectUnignored();
  LayoutObject* container_layout_object = nullptr;
  if (layout_object->IsFixedPositioned()) {
    // If it's a fixed position element, the container should simply be the
    // root web area.
    container = AXObjectCache().Get(GetDocument());
  } else {
    while (container) {
      container_layout_object = container->GetLayoutObject();
      if (container_layout_object && container_layout_object->IsBox() &&
          layout_object->IsDescendantOf(container_layout_object)) {
        if (container->IsScrollableContainer() ||
            container_layout_object->HasLayer()) {
          if (layout_object->IsAbsolutePositioned()) {
            // If it's absolutely positioned, the container must be the
            // nearest positioned container, or the root.
            if (IsA<LayoutView>(layout_object)) {
              break;
            }
            if (container_layout_object->IsPositioned())
              break;
          } else {
            break;
          }
        }
      }

      container = container->ParentObjectUnignored();
    }
  }

  if (!container)
    return;
  *out_container = container;
  out_bounds_in_container =
      layout_object->LocalBoundingBoxRectForAccessibility();

  // Frames need to take their border and padding into account so the
  // child element's computed position will be correct.
  if (layout_object->IsBox() && layout_object->GetNode() &&
      layout_object->GetNode()->IsFrameOwnerElement()) {
    out_bounds_in_container =
        gfx::RectF(To<LayoutBox>(layout_object)->PhysicalContentBoxRect());
  }

  // If the container has a scroll offset, subtract that out because we want our
  // bounds to be relative to the *unscrolled* position of the container object.
  if (auto* scrollable_area = container->GetScrollableAreaIfScrollable())
    out_bounds_in_container.Offset(scrollable_area->GetScrollOffset());

  // Compute the transform between the container's coordinate space and this
  // object.
  gfx::Transform transform = layout_object->LocalToAncestorTransform(
      To<LayoutBoxModelObject>(container_layout_object));

  // If the transform is just a simple translation, apply that to the
  // bounding box, but if it's a non-trivial transformation like a rotation,
  // scaling, etc. then return the full matrix instead.
  if (transform.IsIdentityOr2dTranslation()) {
    out_bounds_in_container.Offset(transform.To2dTranslation());
  } else {
    out_container_transform = transform;
  }
}

gfx::RectF AXObject::LocalBoundingBoxRectForAccessibility() {
  if (!GetLayoutObject())
    return gfx::RectF();
  DCHECK(GetLayoutObject()->IsText());
  CHECK(!cached_values_need_update_ || !AXObjectCache().IsFrozen());
  UpdateCachedAttributeValuesIfNeeded();
  return cached_local_bounding_box_;
}

PhysicalRect AXObject::GetBoundsInFrameCoordinates() const {
  AXObject* container = nullptr;
  gfx::RectF bounds;
  gfx::Transform transform;
  GetRelativeBounds(&container, bounds, transform);
  gfx::RectF computed_bounds(0, 0, bounds.width(), bounds.height());
  while (container && container != this) {
    computed_bounds.Offset(bounds.x(), bounds.y());
    if (!container->IsWebArea()) {
      computed_bounds.Offset(-container->GetScrollOffset().x(),
                             -container->GetScrollOffset().y());
    }
    computed_bounds = transform.MapRect(computed_bounds);
    container->GetRelativeBounds(&container, bounds, transform);
  }
  return PhysicalRect::FastAndLossyFromRectF(computed_bounds);
}

void AXObject::UpdateStyleAndLayoutTreeForNode(Node& nod
"""


```