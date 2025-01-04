Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's Blink rendering engine. The code is part of `ax_object_cache_impl.cc`, focusing on managing accessibility objects.

Here's a breakdown of the thought process to answer the user's request:

1. **Identify the Core Function:** The code primarily deals with removing accessibility objects (`AXObject`) from the cache. This includes different scenarios like removing based on AX ID, node, layout object, or inline text box.

2. **Analyze Key Functions:**  Focus on the `Remove` methods. Notice the different overloads handling various ways an object might be identified. Pay attention to the steps involved in removal:
    * Finding the object in the cache.
    * Checking if the object exists.
    * Decrementing the `included_node_count_` (likely for tracking tree size).
    * Notifying the parent about the children change (if `notify_parent` is true).
    * Calling a test-only function (`HandleAXObjectDetachedForTest`).
    * Removing references to the object's ID (`RemoveReferencesToAXID`).
    * Detaching the object itself (`obj->Detach()`).
    * Finally, removing the object from the `objects_` map.

3. **Look for Side Effects and Dependencies:**  Observe what happens *around* the core removal logic:
    * **`ChildrenChangedOnAncestorOf(obj)`:**  This signifies that removing an object can trigger updates up the accessibility tree.
    * **`RemoveReferencesToAXID(ax_id)`:**  This function is crucial for ensuring no lingering references to the removed object exist, preventing dangling pointers.
    * **`obj->Detach()`:** This suggests a cleanup process within the `AXObject` itself.
    * **Impact on Aria-Modal Dialogs:** The code checks if the removed object is the active modal dialog and potentially marks the document as dirty if it is.

4. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **HTML:**  The code interacts with DOM nodes (`Node`, `Element`, specific HTML element types). Removing a DOM element will lead to the removal of its corresponding `AXObject`.
    * **CSS:**  Layout objects (`LayoutObject`, `LayoutText`, `AbstractInlineTextBox`) are linked to CSS styling. Changes in CSS that affect the layout and visibility of elements can trigger the creation or removal of `AXObject`s.
    * **JavaScript:**  JavaScript manipulations of the DOM (adding/removing elements, changing attributes) can indirectly lead to the execution of this removal code.

5. **Formulate Examples:** Create simple scenarios to illustrate the connection between web technologies and the code's function:
    * **HTML Removal:**  Demonstrate how removing an HTML element tag removes its `AXObject`.
    * **CSS `display: none`:** Show how hiding an element with CSS can cause its `AXObject` to be removed.
    * **JavaScript `removeChild`:**  Illustrate how a JavaScript call can trigger the removal process.

6. **Consider Logical Reasoning (Hypothetical Input/Output):**
    * **Input:**  The AX ID of an existing `AXObject`.
    * **Output:** The `AXObject` is no longer present in the cache, and its parent (if any) is notified.

7. **Identify Potential User/Programming Errors:** Think about situations where incorrect usage could lead to issues:
    * **Removing the same object twice:** This could lead to errors if not handled properly (though the code seems to have checks).
    * **Removing an object without updating references:**  This is explicitly handled by `RemoveReferencesToAXID`, but forgetting to do this elsewhere could cause problems.
    * **Removing an object that is still being referenced:** This could lead to dangling pointers.

8. **Trace User Operations:** Think about how a user action could eventually trigger this code:
    * **Basic Content Rendering:** When the browser renders a page, elements might be removed during the initial layout process if deemed unnecessary for accessibility.
    * **DOM Updates:** User interactions or JavaScript can modify the DOM, leading to element removals.
    * **Dynamic Content Loading:**  Content that is dynamically loaded and then removed can trigger this.
    * **Navigation:** As the user navigates between pages, the old page's accessibility tree needs to be cleaned up.

9. **Summarize the Functionality (for Part 2):** Condense the key responsibilities of the code snippet into a concise summary, emphasizing its role in maintaining the integrity of the accessibility tree by removing objects when their corresponding DOM or layout elements are removed.

10. **Review and Refine:** Ensure the explanation is clear, accurate, and addresses all aspects of the user's request. Double-check examples and assumptions.
```cpp
void AXObjectCacheImpl::Remove(AXID ax_id, bool notify_parent) {
  CHECK(lifecycle_.StateAllowsRemovingAXObjects()) << *this;

  if (!ax_id)
    return;

  // First, fetch object to operate some cleanup functions on it.
  auto it = objects_.find(ax_id);
  AXObject* obj = it != objects_.end() ? it->value : nullptr;
  if (!obj)
    return;

#if DCHECK_IS_ON()
  if (obj->CachedIsIncludedInTree()) {
    --included_node_count_;
  }
#endif

  if (!IsDisposing() && !HasBeenDisposed()) {
    if (notify_parent && !obj->IsMissingParent()) {
      ChildrenChangedOnAncestorOf(obj);
    }
    // TODO(aleventhal) This is for web tests only, in order to record MarkDirty
    // events. Is there a way to avoid these calls for normal browsing?
    // Maybe we should use dependency injection from AccessibilityController.
    if (auto* client = GetWebLocalFrameClient()) {
      client->HandleAXObjectDetachedForTest(ax_id);
    }
  }

  // Remove references to AXID before detaching, so that nothing will retrieve a
  // detached object, which is illegal.
  RemoveReferencesToAXID(ax_id);

  // RemoveReferencesToAXID can cause the object to detach, in this case,
  // fail gracefully rather than attempting to double detach.
  DUMP_WILL_BE_CHECK(!obj->IsDetached()) << obj;
  if (obj->IsDetached()) {
    // TODO(accessibility): Remove early return and change above assertion
    // to CHECK() once this no longer occurs.
    return;
  }

  obj->Detach();

  // Remove the object.
  // TODO(accessibility) We don't use the return value, can we use .erase()
  // and it will still make sure that the object is cleaned up?
  objects_.Take(ax_id);

  // Removing an aria-modal dialog can affect the entire tree.
  if (active_aria_modal_dialog_ &&
      active_aria_modal_dialog_ == obj->GetElement()) {
    Settings* settings = GetSettings();
    if (settings && settings->GetAriaModalPrunesAXTree()) {
      MarkDocumentDirty();
    }
    active
```

**功能归纳 (Part 2):**

这段代码片段主要负责 **从 `AXObjectCacheImpl` 中移除 `AXObject` 实例**。它提供了一个基于 `AXID` (Accessibility ID) 的移除方法，并包含了一些清理和通知机制。

**更详细的功能点:**

1. **基于 AXID 移除:**  接收一个 `AXID` 作为参数，用于定位并移除对应的 `AXObject`。
2. **生命周期检查:** `CHECK(lifecycle_.StateAllowsRemovingAXObjects())` 确保在允许移除 `AXObject` 的生命周期阶段执行操作，保证数据一致性。
3. **对象查找:**  通过 `objects_.find(ax_id)` 在内部的 `objects_` 映射表中查找要移除的 `AXObject`。
4. **包含状态更新 (DCHECK):**  如果定义了 `DCHECK_IS_ON()` 并且被移除的对象之前被认为是包含在可访问性树中的，则会递减 `included_node_count_`。这可能用于内部统计和调试。
5. **父节点通知:** 如果 `notify_parent` 为 `true` 且被移除的对象有父节点（`!obj->IsMissingParent()`），则会调用 `ChildrenChangedOnAncestorOf(obj)` 通知父节点其子节点发生了变化。这对于维护可访问性树的结构至关重要。
6. **测试钩子:** 如果存在 `WebLocalFrameClient`，则会调用 `client->HandleAXObjectDetachedForTest(ax_id)`。这通常用于 Web 平台的测试框架，用于记录和验证 `AXObject` 的移除事件。
7. **移除引用:**  在实际移除对象之前，调用 `RemoveReferencesToAXID(ax_id)` 清除其他地方对该 `AXObject` 的引用，防止悬挂指针和非法访问。
8. **对象分离:** 调用 `obj->Detach()` 执行 `AXObject` 自身的清理和分离逻辑，例如解除与其他对象或数据的关联。
9. **从缓存移除:**  最后，使用 `objects_.Take(ax_id)` 从 `objects_` 映射表中真正移除该 `AXObject`。
10. **Aria-Modal 对话框处理:**  如果被移除的对象是当前激活的 aria-modal 对话框，并且启用了 `AriaModalPrunesAXTree` 设置，则会调用 `MarkDocumentDirty()` 将整个文档标记为脏，以便重新构建可访问性树。这是因为 modal 对话框的出现和消失会显著影响页面的可访问性结构。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:** 当一个 HTML 元素被从 DOM 树中移除时（例如通过 JavaScript 的 `removeChild` 方法），与其对应的 `AXObject` 最终会被此代码移除。
    * **假设输入:**  一个包含 HTML 元素 `<div id="target"></div>` 的页面。JavaScript 代码执行 `document.getElementById('target').remove();`。
    * **输出:**  与该 `<div>` 元素关联的 `AXObject` 将会通过此 `Remove` 方法从 `AXObjectCacheImpl` 中移除。

* **CSS:** 当 CSS 样式导致元素不再渲染或对辅助技术不可见时，其对应的 `AXObject` 可能会被移除。例如，设置 `display: none;` 或 `visibility: hidden;`。
    * **假设输入:** 一个包含 HTML 元素 `<p style="display: block;">Visible Text</p>` 的页面。CSS 规则被修改为 `#target { display: none; }`。
    * **输出:** 如果该 `<p>` 元素的 `AXObject` 因为 `display: none;` 而不再需要存在于可访问性树中，它将被此 `Remove` 方法移除。

* **JavaScript:**  JavaScript 代码可以动态地创建和移除 DOM 元素，这些操作会间接地触发此代码来维护可访问性树的同步。
    * **假设输入:**  JavaScript 代码动态创建了一个按钮元素并添加到 DOM 中，稍后又将其移除。
    * **输出:** 当按钮元素被移除时，与其关联的 `AXObject` 将通过此 `Remove` 方法从缓存中移除。

**用户或编程常见的使用错误:**

* **尝试移除不存在的 AXObject:** 如果传入的 `ax_id` 对应的 `AXObject` 不存在于缓存中，此方法会直接返回，不会产生错误。然而，如果调用者错误地认为某个 `AXObject` 存在并尝试移除，可能会导致逻辑上的错误。
* **在错误的生命周期阶段调用移除:** `CHECK(lifecycle_.StateAllowsRemovingAXObjects())` 会在开发阶段捕获这种错误。如果在不允许移除 `AXObject` 的阶段调用此方法，程序会崩溃。
* **忘记更新外部引用:** 虽然 `RemoveReferencesToAXID` 会清除内部引用，但如果开发者在其他地方持有对该 `AXObject` 的引用，并且忘记手动清除，可能会导致悬挂指针。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户执行导致 DOM 结构变化的交互:**  例如，点击一个按钮，该按钮的事件监听器会执行 JavaScript 代码来移除页面上的某个元素。
2. **浏览器接收到 DOM 变化的通知:**  渲染引擎会接收到 DOM 树发生变化的通知。
3. **Blink 的可访问性模块收到通知:**  可访问性模块（包括 `AXObjectCacheImpl`）会监听到 DOM 的变化。
4. **确定需要移除对应的 AXObject:** 可访问性模块会分析 DOM 的变化，识别出哪些 DOM 元素被移除，并确定需要移除与之关联的 `AXObject`。
5. **调用 `AXObjectCacheImpl::Remove`:**  根据被移除 DOM 元素的 `AXID`，调用此 `Remove` 方法来清理 `AXObjectCacheImpl` 中的相应条目。

**假设输入与输出 (逻辑推理):**

* **假设输入:** `ax_id` 为 `123`，且 `objects_` 中存在 `AXID` 为 `123` 的 `AXObject`，其父节点存在。 `notify_parent` 为 `true`。
* **输出:**
    * `AXID` 为 `123` 的 `AXObject` 将从 `objects_` 中移除。
    * 该 `AXObject` 的 `Detach()` 方法会被调用。
    * 其父节点的 `ChildrenChangedOnAncestorOf` 方法会被调用。
    * 如果定义了 `DCHECK_IS_ON()` 且该对象之前被包含在树中，`included_node_count_` 会减 1。
    * 测试钩子 `HandleAXObjectDetachedForTest` 可能会被调用。
    * `RemoveReferencesToAXID(123)` 会被调用。

* **假设输入:** `ax_id` 为 `456`，且 `objects_` 中不存在 `AXID` 为 `456` 的 `AXObject`。
* **输出:**  该方法会直接返回，不会执行任何移除操作。

这段代码是 Chromium 浏览器可访问性实现的关键部分，它负责维护可访问性树与 DOM 树之间的一致性，确保辅助技术能够准确地理解和呈现网页内容。

Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_object_cache_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共8部分，请归纳一下它的功能

"""
);
}

// Rreturns true if `layout_object`represent a text that is all white spaces and
// is all collapsed. This means that this object will not be accessed by an
// InlineCursor.
static bool IsAllCollapsedWhiteSpace(const LayoutObject& layout_object) {
  if (const auto* layout_text = DynamicTo<LayoutText>(&layout_object)) {
    if (layout_text->StyleRef().ShouldCollapseWhiteSpaces() &&
        layout_text->TransformedText()
            .IsAllSpecialCharacters<Character::IsCollapsibleSpace>()) {
      return true;
    }
  }
  return false;
}

// Returns the previous LayoutObject representing text that is in the same line
// as `layout_object`, nullptr if there are none. `layout_object`must be a child
// of `block_flow`.
LayoutObject* PreviousLayoutObjectTextOnLine(
    const LayoutObject& layout_object,
    const LayoutBlockFlow& block_flow) {
  LayoutObject* previous = layout_object.PreviousInPreOrder(&block_flow);
  while (previous) {
    if (IsA<LayoutText>(previous)) {
      InlineCursor cursor;
      cursor.MoveToIncludingCulledInline(*previous);
      while (cursor) {
        if (cursor.Current()->IsInlineBox() ||
            cursor.Current()->IsLineBreak()) {
          return nullptr;
        }
        cursor.MoveToNextForSameLayoutObject();
      }

      return previous;
    }

    previous = previous->PreviousInPreOrder(&block_flow);
  }

  return nullptr;
}

}  // namespace

#define DEBUG_STRING_CASE(ReasonName)                   \
  case AXObjectCacheImpl::TreeUpdateReason::ReasonName: \
    return #ReasonName

static std::string TreeUpdateReasonAsDebugString(
    const AXObjectCacheImpl::TreeUpdateReason& reason) {
  switch (reason) {
    DEBUG_STRING_CASE(kActiveDescendantChanged);
    DEBUG_STRING_CASE(kAriaExpandedChanged);
    DEBUG_STRING_CASE(kAriaOwnsChanged);
    DEBUG_STRING_CASE(kAriaPressedChanged);
    DEBUG_STRING_CASE(kAriaSelectedChanged);
    DEBUG_STRING_CASE(kCSSAnchorChanged);
    DEBUG_STRING_CASE(kDelayEventFromPostNotification);
    DEBUG_STRING_CASE(kDidShowMenuListPopup);
    DEBUG_STRING_CASE(kEditableTextContentChanged);
    DEBUG_STRING_CASE(kFocusableChanged);
    DEBUG_STRING_CASE(kIdChanged);
    DEBUG_STRING_CASE(kMaybeDisallowImplicitSelection);
    DEBUG_STRING_CASE(kNodeIsAttached);
    DEBUG_STRING_CASE(kNodeGainedFocus);
    DEBUG_STRING_CASE(kNodeLostFocus);
    DEBUG_STRING_CASE(kPostNotificationFromHandleLoadComplete);
    DEBUG_STRING_CASE(kPostNotificationFromHandleLoadStart);
    DEBUG_STRING_CASE(kPostNotificationFromHandleScrolledToAnchor);
    DEBUG_STRING_CASE(kReferenceTargetChanged);
    DEBUG_STRING_CASE(kRemoveValidationMessageObjectFromFocusedUIElement);
    DEBUG_STRING_CASE(kRestoreParentOrPrune);
    DEBUG_STRING_CASE(
        kRemoveValidationMessageObjectFromValidationMessageObject);
    DEBUG_STRING_CASE(kRoleChangeFromAriaHasPopup);
    DEBUG_STRING_CASE(kRoleChangeFromImageMapName);
    DEBUG_STRING_CASE(kRoleChangeFromRoleOrType);
    DEBUG_STRING_CASE(kRoleMaybeChangedFromEventListener);
    DEBUG_STRING_CASE(kRoleMaybeChangedFromHref);
    DEBUG_STRING_CASE(kRoleMaybeChangedOnSelect);
    DEBUG_STRING_CASE(kSectionOrRegionRoleMaybeChangedFromLabel);
    DEBUG_STRING_CASE(kSectionOrRegionRoleMaybeChangedFromLabelledBy);
    DEBUG_STRING_CASE(kSectionOrRegionRoleMaybeChangedFromTitle);
    DEBUG_STRING_CASE(kTextChangedOnNode);
    DEBUG_STRING_CASE(kTextChangedOnClosestNodeForLayoutObject);
    DEBUG_STRING_CASE(kTextMarkerDataAdded);
    DEBUG_STRING_CASE(kUpdateActiveMenuOption);
    DEBUG_STRING_CASE(kUpdateAriaOwns);
    DEBUG_STRING_CASE(kUpdateTableRole);
    DEBUG_STRING_CASE(kUseMapAttributeChanged);
    DEBUG_STRING_CASE(kValidationMessageVisibilityChanged);
    DEBUG_STRING_CASE(kChildrenChanged);
    DEBUG_STRING_CASE(kMarkAXObjectDirty);
    DEBUG_STRING_CASE(kMarkAXSubtreeDirty);
    DEBUG_STRING_CASE(kTextChangedOnLayoutObject);
  }

  NOTREACHED();
}

std::string AXObjectCacheImpl::TreeUpdateParams::ToString() {
  std::ostringstream str;
  str << "Tree update: " << TreeUpdateReasonAsDebugString(update_reason);
  if (event != ax::mojom::blink::Event::kNone) {
    str << " with event " << event;
  }

  return str.str();
}

// static
AXObjectCache* AXObjectCacheImpl::Create(Document& document,
                                         const ui::AXMode& ax_mode) {
  return MakeGarbageCollected<AXObjectCacheImpl>(document, ax_mode);
}

AXObjectCacheImpl::AXObjectCacheImpl(Document& document,
                                     const ui::AXMode& ax_mode)
    : document_(document),
#if DCHECK_IS_ON()
      // TODO(accessibility): turn on the UI checker for devtools.
      internal_ui_checker_on_(GetDocument().Url().Protocol() == "chrome"),
#else
      internal_ui_checker_on_(false),
#endif
      ax_mode_(ax_mode),
      validation_message_axid_(0),
      active_aria_modal_dialog_(nullptr),
      render_accessibility_host_(document.GetExecutionContext()),
      ax_tree_source_(BlinkAXTreeSource::Create(*this)) {
  lifecycle_.AdvanceTo(AXObjectCacheLifecycle::kDeferTreeUpdates);
}

AXObjectCacheImpl::~AXObjectCacheImpl() {
  CHECK(HasBeenDisposed());
}

// This is called shortly before the AXObjectCache is deleted.
// The destruction of the AXObjectCache will do most of the cleanup.
void AXObjectCacheImpl::Dispose() {
  lifecycle_.AdvanceTo(AXObjectCacheLifecycle::kDisposing);

  // Detach all objects now. This prevents more work from occurring if we wait
  // for the rendering engine to detach each node individually, because that
  // will cause the renderer to attempt to potentially repair parents, and
  // detach each child individually as Detach() calls ClearChildren().
  for (auto& entry : objects_) {
    AXObject* obj = entry.value;
    obj->Detach();
  }

  // Destroy any pending task to serialize the tree.
  weak_factory_for_serialization_pipeline_.Invalidate();
  weak_factory_for_loc_updates_pipeline_.Invalidate();

  lifecycle_.AdvanceTo(AXObjectCacheLifecycle::kDisposed);
}

void AXObjectCacheImpl::AddInspectorAgent(InspectorAccessibilityAgent* agent) {
  agents_.insert(agent);
}

void AXObjectCacheImpl::RemoveInspectorAgent(
    InspectorAccessibilityAgent* agent) {
  agents_.erase(agent);
}

void AXObjectCacheImpl::EnsureRelationCacheAndInitialTree() {
  if (!relation_cache_) {
    relation_cache_ = std::make_unique<AXRelationCache>(this);
    relation_cache_->Init();

    // Build out initial tree so that AXObjects exist for
    // AXRelationCache::ProcessUpdatesWithCleanLayout();
    // Creating the root will cause its descendants to be created as well.
    if (!Get(document_)) {
      CreateAndInit(document_, document_->GetLayoutView(), nullptr);
    }
  }
}

void AXObjectCacheImpl::EnsureSerializer() {
  if (!ax_tree_serializer_) {
    ax_tree_serializer_ = std::make_unique<ui::AXTreeSerializer<
        const AXObject*, HeapVector<Member<const AXObject>>, ui::AXTreeUpdate*,
        ui::AXTreeData*, ui::AXNodeData>>(ax_tree_source_,
                                          /*crash_on_error*/ true);
  }
}

AXObject* AXObjectCacheImpl::Root() {
  if (AXObject* root = Get(document_)) {
    return root;
  }

  CommitAXUpdates(GetDocument(), /*force*/ true);
  return Get(document_);
}

AXObject* AXObjectCacheImpl::ObjectFromAXID(AXID id) const {
  auto it = objects_.find(id);
  return it != objects_.end() ? it->value : nullptr;
}

AXObject* AXObjectCacheImpl::FirstObjectWithRole(ax::mojom::blink::Role role) {
  const AXObject* root = Root();
  if (!root || root->IsDetached()) {
    return nullptr;
  }
  return root->FirstObjectWithRole(role);
}

Node* AXObjectCacheImpl::FocusedNode() const {
  Node* focused_node = document_->FocusedElement();
  if (!focused_node)
    focused_node = document_;

  // The custom select's button is not included in the a11y hierarchy. Treat
  // focus on the button as if it's on the <select>.
  focused_node = RetargetInput(focused_node);

  // A popup is showing: return the focus within instead of the focus in the
  // main document. Do not do this for HTML <select>, which has special
  // focus manager using the kActiveDescendantId.
  if (GetPopupDocumentIfShowing() && !IsA<HTMLSelectElement>(focused_node)) {
    if (Node* focus_in_popup = GetPopupDocumentIfShowing()->FocusedElement())
      return focus_in_popup;
  }

  return focused_node;
}

void AXObjectCacheImpl::UpdateLifecycleIfNeeded(Document& document) {
  DCHECK(document.defaultView());
  DCHECK(document.GetFrame());
  DCHECK(document.View());

  document.View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kAccessibility);
}

void AXObjectCacheImpl::UpdateAXForAllDocuments() {
#if DCHECK_IS_ON()
  DCHECK(!IsFrozen())
      << "Don't call UpdateAXForAllDocuments() here; layout and a11y are "
         "already clean at the start of serialization.";
  DCHECK(!updating_layout_and_ax_) << "Undesirable recursion.";
  base::AutoReset<bool> updating(&updating_layout_and_ax_, true);
#endif

  // First update the layout for the main and popup document.
  UpdateLifecycleIfNeeded(GetDocument());
  if (Document* popup_document = GetPopupDocumentIfShowing())
    UpdateLifecycleIfNeeded(*popup_document);

  // Next flush all accessibility events and dirty objects, for both the main
  // and popup document, and update tree if needed.
  if (IsDirty() || HasObjectsPendingSerialization()) {
    CommitAXUpdates(GetDocument(), /*force*/ true);
  }
}

AXObject* AXObjectCacheImpl::FocusedObject() const {
#if DCHECK_IS_ON()
  DCHECK(GetDocument().Lifecycle().GetState() >=
         DocumentLifecycle::kAfterPerformLayout);
  if (GetPopupDocumentIfShowing()) {
    DCHECK(GetPopupDocumentIfShowing()->Lifecycle().GetState() >=
           DocumentLifecycle::kAfterPerformLayout);
  }
#endif

  AXObject* obj = Get(FocusedNode());
  if (!obj) {
    // In rare cases it's possible for the focus to not exist in the tree.
    // An example would be a focused element inside of an image map that
    // gets trimmed.
    // In these cases, treat the focus as on the root object itself, so that
    // AT users have some starting point.
    DLOG(ERROR) << "The focus was not part of the a11y tree: " << FocusedNode();
    return Get(document_);
  }

  // The HTML element, for example, is focusable but has an AX object that is
  // not included in the tree.
  if (!obj->IsIncludedInTree()) {
    obj = obj->ParentObjectIncludedInTree();
  }

  return obj;
}

AXObject* AXObjectCacheImpl::EnsureFocusedObject() {
  DCHECK(lifecycle_.StateAllowsImmediateTreeUpdates());
  AXObject* obj = Get(FocusedNode());

  if (obj) {
    if (!obj->IsAriaHidden()) {
      return obj;
    }
    // Repair illegal usage of aria-hidden: it should never contain the focus.
    // The aria-hidden will be ignored when this occurs.
    DiscardBadAriaHiddenBecauseOfFocus(*obj);
  }

  // Now return the focused object of its included in the tree, otherwise
  // return an included ancestor of the focus.
  obj = FocusedObject();
  CHECK(obj) << "Object could not be recreated with aria-hidden off.";
  CHECK(!obj->IsAriaHidden())
      << obj << "\nGet(FocusedNode()): " << Get(FocusedNode());

  return obj;
}

const ui::AXMode& AXObjectCacheImpl::GetAXMode() {
  return ax_mode_;
}

void AXObjectCacheImpl::SetAXMode(const ui::AXMode& ax_mode) {
  ax_mode_ = ax_mode;
}

AXObject* AXObjectCacheImpl::Get(const LayoutObject* layout_object,
                                 AXObject* parent_for_repair) const {
  if (!layout_object)
    return nullptr;

  if (Node* node = layout_object->GetNode()) {
    // If there is a node, it is preferred for backing the AXObject.
    DCHECK(!layout_object_mapping_.Contains(layout_object));
    return Get(node);
  }

  auto it_id = layout_object_mapping_.find(layout_object);
  if (it_id == layout_object_mapping_.end()) {
    return nullptr;
  }
  AXID ax_id = it_id->value;
  DCHECK(!WTF::IsHashTraitsDeletedValue<HashTraits<AXID>>(ax_id));

  auto it_result = objects_.find(ax_id);
  AXObject* result = it_result != objects_.end() ? it_result->value : nullptr;
  DCHECK(result) << "Had AXID for Node but no entry in objects_";
  DCHECK(result->IsAXNodeObject());
  // Do not allow detached objects except when disposing entire tree.
  DCHECK(!result->IsDetached() || IsDisposing())
      << "Detached AXNodeObject in map: " << "AXID#" << ax_id
      << " LayoutObject=" << layout_object;

  if (result->ParentObject()) {
    DCHECK(!parent_for_repair || parent_for_repair == result->ParentObject())
        << "If there is both a previous parent, and a parent supplied for "
           "repair, they must match.";
  } else if (parent_for_repair) {
    result->SetParent(parent_for_repair);
  }

  // If there is no node for the AXObject, then it is an anonymous layout
  // object (e.g. a pseudo-element or object introduced to match the structure
  // of content). Such objects can only be created or destroyed via creation of
  // their parents and recursion via AddPseudoElementChildrenFromLayoutTree.
  DCHECK(!result->IsMissingParent() || !result->GetNode())
      << "Had AXObject but is missing parent: " << layout_object << " "
      << result;

  return result;
}

AXObject* AXObjectCacheImpl::Get(const Node* node) const {
  if (!node)
    return nullptr;

  AXID node_id = static_cast<AXID>(DOMNodeIds::ExistingIdForNode(node));
  if (!node_id) {
    // An ID hasn't yet been generated for this DOM node, but ::CreateAndInit()
    // will ensure a DOMNodeID is generated by using node->GetDomNodeId().
    // Therefore if an id doesn't exist for a DOM node, it means that it can't
    // have an associated AXObject.
    return nullptr;
  }

  auto it_result = objects_.find(node_id);
  if (it_result == objects_.end()) {
    return nullptr;
  }

  AXObject* result = it_result->value;
  DCHECK(result) << "AXID#" << node_id
                 << " in map, but matches an AXObject of null, for " << node;

  // When shutting down, allow detached nodes to be in the map, and do not
  // attempt invalidations.
  if (IsDisposing()) {
    return result->IsDetached() ? nullptr : result;
  }

  DCHECK(!result->IsDetached()) << "Detached object was in map.";

  return result;
}

AXObject* AXObjectCacheImpl::Get(AbstractInlineTextBox* inline_text_box) const {
  if (!inline_text_box)
    return nullptr;

  auto it_ax = inline_text_box_object_mapping_.find(inline_text_box);
  AXID ax_id =
      it_ax != inline_text_box_object_mapping_.end() ? it_ax->value : 0;
  if (!ax_id)
    return nullptr;
  DCHECK(!WTF::IsHashTraitsEmptyOrDeletedValue<HashTraits<AXID>>(ax_id));

  auto it_result = objects_.find(ax_id);
  AXObject* result = it_result != objects_.end() ? it_result->value : nullptr;
#if DCHECK_IS_ON()
  DCHECK(result) << "Had AXID for inline text box but no entry in objects_";
  DCHECK(result->IsAXInlineTextBox());
  // Do not allow detached objects except when disposing entire tree.
  DCHECK(!result->IsDetached() || IsDisposing())
      << "Detached AXInlineTextBox in map: " << "AXID#" << ax_id
      << " Node=" << inline_text_box->GetText();
#endif
  return result;
}

AXObject* AXObjectCacheImpl::GetPositionedObjectForAnchor(const AXObject* obj) {
  return relation_cache_->GetPositionedObjectForAnchor(obj);
}

AXObject* AXObjectCacheImpl::GetAnchorForPositionedObject(const AXObject* obj) {
  return relation_cache_->GetAnchorForPositionedObject(obj);
}

AXObject* AXObjectCacheImpl::GetAXImageForMap(const HTMLMapElement& map) {
  // Find first child node of <map> that has an AXObject and return it's
  // parent, which should be a native image.
  Node* child = NodeTraversal::FirstChild(map);
  while (child) {
    if (AXObject* ax_child = Get(child)) {
      if (AXObject* ax_image = ax_child->ParentObject()) {
        if (ax_image->IsDetached()) {
          return nullptr;
        }
        DCHECK(IsA<HTMLImageElement>(ax_image->GetNode()))
            << "Expected image AX parent of <map>'s DOM child, got: "
            << ax_image->GetNode() << "\n* Map's DOM child was: " << child
            << "\n* ax_image: " << ax_image;
        return ax_image;
      }
    }
    child = NodeTraversal::NextSibling(*child);
  }
  return nullptr;
}

AXObject* AXObjectCacheImpl::CreateFromRenderer(LayoutObject* layout_object) {
  Node* node = layout_object->GetNode();

  // media element
  if (node && node->IsMediaElement())
    return AccessibilityMediaElement::Create(layout_object, *this);

  if (node && node->IsMediaControlElement())
    return AccessibilityMediaControl::Create(layout_object, *this);

  if (auto* html_input_element = DynamicTo<HTMLInputElement>(node)) {
    FormControlType type = html_input_element->FormControlType();
    if (type == FormControlType::kInputRange) {
      return MakeGarbageCollected<AXSlider>(layout_object, *this);
    }
  }

  if (IsA<HTMLProgressElement>(node)) {
    return MakeGarbageCollected<AXProgressIndicator>(layout_object, *this);
  }

  return MakeGarbageCollected<AXNodeObject>(layout_object, *this);
}

// static
bool AXObjectCacheImpl::IsRelevantSlotElement(const HTMLSlotElement& slot) {
  DCHECK(AXObject::CanSafelyUseFlatTreeTraversalNow(slot.GetDocument()));
  DCHECK(slot.SupportsAssignment());

  if (slot.IsInUserAgentShadowRoot() &&
      IsA<HTMLSelectElement>(slot.OwnerShadowHost())) {
    return slot.GetIdAttribute() == shadow_element_names::kSelectOptions;
  }

  // HasAssignedNodesNoRecalc() will return false when  the slot is not in the
  // flat tree. We must also return true when the slot has ordinary children
  // (fallback content).
  return slot.HasAssignedNodesNoRecalc() || slot.hasChildren();
}

// static
bool AXObjectCacheImpl::IsRelevantPseudoElement(const Node& node) {
  DCHECK(node.IsPseudoElement());

  std::optional<String> alt_text =
      AXNodeObject::GetCSSAltText(To<Element>(&node));
  if (alt_text && alt_text->empty()) {
    return false;
  }

  if (!node.GetLayoutObject())
    return false;

  // ::before, ::after, ::marker, ::scroll-marker, ::scroll-*-buttons and
  // ::scroll-marker-group are relevant. Allowing these pseudo elements ensures
  // that all visible descendant pseudo content will be reached, despite only
  // being able to walk layout inside of pseudo content. However, AXObjects
  // aren't created for
  // ::first-letter subtrees. The text of ::first-letter is already available in
  // the child text node of the element that the CSS ::first letter applied to.
  if (To<PseudoElement>(node).CanGenerateContent()) {
    // Ignore non-inline whitespace content, which is used by many pages as
    // a "Micro Clearfix Hack" to clear floats without extra HTML tags. See
    // http://nicolasgallagher.com/micro-clearfix-hack/
    if (node.GetLayoutObject()->IsInline())
      return true;  // Inline: not a clearfix hack.
    if (!node.parentNode()->GetLayoutObject() ||
        node.parentNode()->GetLayoutObject()->IsInline()) {
      return true;  // Parent inline: not a clearfix hack.
    }
    const ComputedStyle* style = node.GetLayoutObject()->Style();
    DCHECK(style);
    ContentData* content_data = style->GetContentData();
    if (!content_data)
      return true;
    if (!content_data->IsText())
      return true;  // Not text: not a clearfix hack.
    if (!To<TextContentData>(content_data)
             ->GetText()
             .ContainsOnlyWhitespaceOrEmpty()) {
      return true;  // Not whitespace: not a clearfix hack.
    }
    return false;  // Is the clearfix hack: ignore pseudo element.
  }

  // ::first-letter is relevant if and only if its parent layout object is a
  // relevant pseudo element. If it's not a pseudo element, then this the
  // ::first-letter text would end up being repeated in the AX Tree.
  if (node.IsFirstLetterPseudoElement()) {
    LayoutObject* layout_parent = node.GetLayoutObject()->Parent();
    DCHECK(layout_parent);
    Node* layout_parent_node = layout_parent->GetNode();
    return layout_parent_node && layout_parent_node->IsPseudoElement() &&
           IsRelevantPseudoElement(*layout_parent_node);
  }

  // The remaining possible pseudo element types are not relevant.
  if (node.IsBackdropPseudoElement() || node.IsViewTransitionPseudoElement()) {
    return false;
  }

  // If this is reached, then a new pseudo element type was added and is not
  // yet handled by accessibility. See  PseudoElementTagName() in
  // pseudo_element.cc for all possible types.
  SANITIZER_NOTREACHED() << "Unhandled type of pseudo element on: " << node;
  return false;
}

// static
bool AXObjectCacheImpl::IsRelevantPseudoElementDescendant(
    const LayoutObject& layout_object) {
  if (layout_object.IsText() && To<LayoutText>(layout_object).HasEmptyText())
    return false;
  const LayoutObject* ancestor = &layout_object;
  while (true) {
    ancestor = ancestor->Parent();
    if (!ancestor)
      return false;
    if (ancestor->IsPseudoElement()) {
      // When an ancestor is exposed using CSS alt text, descendants are pruned.
      if (AXNodeObject::GetCSSAltText(To<Element>(ancestor->GetNode()))) {
        return false;
      }
      return IsRelevantPseudoElement(*ancestor->GetNode());
    }
    if (!ancestor->IsAnonymous())
      return false;
  }
}

AXObject* AXObjectCacheImpl::CreateFromNode(Node* node) {
  if (auto* area = DynamicTo<HTMLAreaElement>(node))
    return MakeGarbageCollected<AXImageMapLink>(area, *this);

  return MakeGarbageCollected<AXNodeObject>(node, *this);
}

AXObject* AXObjectCacheImpl::CreateFromInlineTextBox(
    AbstractInlineTextBox* inline_text_box) {
  return MakeGarbageCollected<AXInlineTextBox>(inline_text_box, *this);
}

AXObject* AXObjectCacheImpl::GetOrCreate(const Node* node, AXObject* parent) {
  return GetOrCreate(const_cast<Node*>(node), parent);
}

AXObject* AXObjectCacheImpl::GetOrCreate(Node* node, AXObject* parent) {
  CHECK(lifecycle_.StateAllowsImmediateTreeUpdates())
      << "Only create AXObjects while processing AX events and tree: " << node
      << " " << *this;

  if (!node)
    return nullptr;

  CHECK(parent);

  if (AXObject* obj = Get(node)) {
    // The object already exists.
    CHECK(!obj->IsDetached());
    if (!obj->IsMissingParent()) {
      return obj;
    }

    // The parent is provided when the object is being added to the parent.
    // This is expected when re-adding a child to a parent via
    // AXNodeObject::AddChildren(), as the parent on previous children
    // will have been cleared immediately before re-adding any of them.
    obj->SetParent(parent);
    CHECK(!obj->IsMissingParent());
    return obj;
  }

  return CreateAndInit(node, node->GetLayoutObject(), parent);
}

// Caller must provide a node, a layout object, or both (where they match).
AXObject* AXObjectCacheImpl::CreateAndInit(Node* node,
                                           LayoutObject* layout_object,
                                           AXObject* parent) {
  // New AXObjects cannot be created when the tree is frozen.
  // In this state, the tree should already be complete because
  // of FinalizeTree().
  CHECK(lifecycle_.StateAllowsImmediateTreeUpdates())
      << "Only create AXObjects while processing AX events and tree: " << node
      << " " << layout_object << " " << *this;

#if DCHECK_IS_ON()
  DCHECK(node || layout_object);
  DCHECK(!node || !layout_object || layout_object->GetNode() == node);
  DCHECK(parent || node == document_);
  DCHECK(!parent || parent->CanHaveChildren());
  DCHECK(GetDocument().Lifecycle().GetState() >=
         DocumentLifecycle::kAfterPerformLayout)
      << "Unclean document at lifecycle "
      << GetDocument().Lifecycle().ToString();
#endif  // DCHECK_IS_ON()

  if (IsA<Document>(node) && parent) {
    // Root of a popup document:
    if (IsA<HTMLSelectElement>(parent->GetNode())) {
      // HTML <select> has a popup that duplicates nodes from the main
      // document, and therefore we ignore that popup and any nodes in it.
      return nullptr;
    }
    if (!GetPopupDocumentIfShowing()) {
      // The popup document is either not showing yet, or is no longer showing.
      return nullptr;
    }
    // All other document nodes with a parent must match the current popup.
    CHECK_EQ(node, GetPopupDocumentIfShowing());
  }

  // Determine the type of accessibility object to be created.
  AXObjectType ax_type = DetermineAXObjectType(node, layout_object, parent);
  if (ax_type == kPruneSubtree) {
    return nullptr;
  }

#if DCHECK_IS_ON()
  if (node) {
    DCHECK(layout_object || ax_type != kCreateFromLayout);
    DCHECK(node->isConnected());
    DCHECK(node->GetDocument().GetFrame())
        << "Creating AXObject in a dead document: " << node;
    DCHECK(node->IsElementNode() || node->IsTextNode() ||
           node->IsDocumentNode())
        << "Should only attempt to create AXObjects for the following types of "
           "node types: document, element and text."
        << "\n* Node is: " << node;
  } else {
    // No node: will create an AXNodeObject using the LayoutObject.
    DCHECK(layout_object->GetDocument().GetFrame())
        << "Creating AXObject in a dead document: " << layout_object;
    DCHECK_EQ(ax_type, kCreateFromLayout);
    DCHECK(!IsA<LayoutView>(layout_object))
        << "AXObject for document is always created with a node.";
  }
#endif

  // If there is a DOM node, use its dom_node_id, otherwise, generate an AXID.
  // The dom_node_id can be used even if there is also a layout object.
  AXID axid;
  if (node) {
    axid = static_cast<AXID>(node->GetDomNodeId());
    if (ax_tree_serializer_) {
      // In the case where axid is being reused, because a previous AXObject
      // existed for the same node, ensure that the serializer sees it as new.
      ax_tree_serializer_->MarkNodeDirty(axid);
    }
  } else {
    axid = GenerateAXID();
  }
  DCHECK(!base::Contains(objects_, axid));

  // Create the new AXObject.
  AXObject* new_obj = nullptr;
  if (ax_type == kCreateFromLayout) {
    // Prefer to create from renderer if there is a layout object because
    // AXLayoutObjects can provide information about bounding boxes.
    if (!node) {
      DCHECK(!layout_object_mapping_.Contains(layout_object))
          << "Already have an AXObject for " << layout_object;
      layout_object_mapping_.Set(layout_object, axid);
    }
    new_obj = CreateFromRenderer(layout_object);
  } else {
    new_obj = CreateFromNode(node);
  }
  DCHECK(new_obj) << "Could not create AXObject.";

  // Give the AXObject its ID and initialize.
  AssociateAXID(new_obj, axid);
  new_obj->Init(parent);
  MaybeDisallowImplicitSelectionWithCleanLayout(new_obj);

#if DCHECK_IS_ON()
  Element* element = DynamicTo<Element>(node);
  if (element && !element->IsPseudoElement()) {
    // Ensure that the relation cache is properly initialized with information
    // from this element.
    relation_cache_->CheckRelationsCached(*element);
  }
#endif

  // Eagerly fill out new subtrees.
  new_obj->UpdateChildrenIfNecessary();

  return new_obj;
}

AXObject* AXObjectCacheImpl::GetOrCreate(LayoutObject* layout_object,
                                         AXObject* parent) {
  CHECK(lifecycle_.StateAllowsImmediateTreeUpdates())
      << layout_object << " " << *this;

  CHECK(parent);

  if (!layout_object)
    return nullptr;

  if (AXObject* obj = Get(layout_object, parent)) {
    return obj;
  }

  return CreateAndInit(layout_object->GetNode(), layout_object, parent);
}

AXObject* AXObjectCacheImpl::GetOrCreate(AbstractInlineTextBox* inline_text_box,
                                         AXObject* parent) {
  CHECK(lifecycle_.StateAllowsImmediateTreeUpdates())
      << "Only create AXObjects while processing AX events and tree." << *this;

  if (!inline_text_box)
    return nullptr;

  if (!parent) {
    LayoutText* layout_text_parent = inline_text_box->GetLayoutText();
    DCHECK(layout_text_parent);
    parent = Get(layout_text_parent);
    if (!parent) {
      DCHECK(inline_text_box->GetText().ContainsOnlyWhitespaceOrEmpty() ||
             IsFrozen() ||
             !IsRelevantPseudoElementDescendant(*layout_text_parent))
          << "No parent for non-whitespace inline textbox: "
          << layout_text_parent
          << "\nParent of parent: " << layout_text_parent->Parent();
      return nullptr;
    }
  }

  // Inline textboxes are included if and only if the parent is unignored.
  // If the parent is ignored but included in tree, the inline textbox is
  // still withheld.
  if (parent->IsIgnored()) {
    return nullptr;
  }

  if (AXObject* obj = Get(inline_text_box)) {
#if DCHECK_IS_ON()
    DCHECK(!obj->IsDetached())
        << "AXObject for inline text box should not be detached: " << obj;
    // AXInlineTextbox objects can't get a new parent, unlike other types of
    // accessible objects that can get a new parent because they moved or
    // because of aria-owns.
    // AXInlineTextbox objects are only added via AddChildren() on static text
    // or line break parents. The children are cleared, and detached from their
    // parent before AddChildren() executes. There should be no previous parent.
    DCHECK(parent->RoleValue() == ax::mojom::blink::Role::kStaticText ||
           parent->RoleValue() == ax::mojom::blink::Role::kLineBreak);
    DCHECK(!obj->ParentObject() || obj->ParentObject() == parent)
        << "Mismatched old and new parent:" << "\n* Old parent: "
        << obj->ParentObject() << "\n* New parent: " << parent;
    DCHECK(ui::CanHaveInlineTextBoxChildren(parent->RoleValue()))
        << "Unexpected parent of inline text box: " << parent->RoleValue();
#endif
    DCHECK(obj->ParentObject() == parent);
    return obj;
  }

  // New AXObjects cannot be created when the tree is frozen.
  if (IsFrozen()) {
    return nullptr;
  }

  AXObject* new_obj = CreateFromInlineTextBox(inline_text_box);

  AXID axid = AssociateAXID(new_obj);

  inline_text_box_object_mapping_.Set(inline_text_box, axid);
  new_obj->Init(parent);
  return new_obj;
}

void AXObjectCacheImpl::Remove(AXObject* object, bool notify_parent) {
  DCHECK(object);
  if (object->IsAXInlineTextBox()) {
    Remove(object->GetInlineTextBox(), notify_parent);
  } else if (object->GetNode()) {
    Remove(object->GetNode(), notify_parent);
  } else if (object->GetLayoutObject()) {
    Remove(object->GetLayoutObject(), notify_parent);
  } else {
    Remove(object->AXObjectID(), notify_parent);
  }
}

// This is safe to call even if there isn't a current mapping.
// This is called by other Remove() methods, called by Blink for DOM and layout
// changes, iterating over all removed content in the subtree:
// - When a DOM subtree is removed, it is called with the root node first, and
//   then descending down into the subtree.
// - When layout for a subtree is detached, it is called on layout objects,
//   starting with leaves and moving upward, ending with the subtree root.
void AXObjectCacheImpl::Remove(AXID ax_id, bool notify_parent) {
  CHECK(lifecycle_.StateAllowsRemovingAXObjects()) << *this;

  if (!ax_id)
    return;

  // First, fetch object to operate some cleanup functions on it.
  auto it = objects_.find(ax_id);
  AXObject* obj = it != objects_.end() ? it->value : nullptr;
  if (!obj)
    return;

#if DCHECK_IS_ON()
  if (obj->CachedIsIncludedInTree()) {
    --included_node_count_;
  }
#endif

  if (!IsDisposing() && !HasBeenDisposed()) {
    if (notify_parent && !obj->IsMissingParent()) {
      ChildrenChangedOnAncestorOf(obj);
    }
    // TODO(aleventhal) This is for web tests only, in order to record MarkDirty
    // events. Is there a way to avoid these calls for normal browsing?
    // Maybe we should use dependency injection from AccessibilityController.
    if (auto* client = GetWebLocalFrameClient()) {
      client->HandleAXObjectDetachedForTest(ax_id);
    }
  }

  // Remove references to AXID before detaching, so that nothing will retrieve a
  // detached object, which is illegal.
  RemoveReferencesToAXID(ax_id);

  // RemoveReferencesToAXID can cause the object to detach, in this case,
  // fail gracefully rather than attempting to double detach.
  DUMP_WILL_BE_CHECK(!obj->IsDetached()) << obj;
  if (obj->IsDetached()) {
    // TODO(accessibility): Remove early return and change above assertion
    // to CHECK() once this no longer occurs.
    return;
  }

  obj->Detach();

  // Remove the object.
  // TODO(accessibility) We don't use the return value, can we use .erase()
  // and it will still make sure that the object is cleaned up?
  objects_.Take(ax_id);

  // Removing an aria-modal dialog can affect the entire tree.
  if (active_aria_modal_dialog_ &&
      active_aria_modal_dialog_ == obj->GetElement()) {
    Settings* settings = GetSettings();
    if (settings && settings->GetAriaModalPrunesAXTree()) {
      MarkDocumentDirty();
    }
    active
"""


```