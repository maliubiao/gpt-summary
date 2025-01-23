Response:
Let's break down the thought process for analyzing this code snippet and generating the response.

**1. Understanding the Request:**

The core request is to analyze the provided C++ code snippet from `ax_object_cache_impl.cc`, focusing on its functionality, relationships with web technologies (JavaScript, HTML, CSS), logical reasoning, potential user/programming errors, debugging clues, and a concise summary. It's also the fifth part of an eight-part analysis, so context from previous parts might be relevant (though not provided here).

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly scan the code, looking for familiar keywords and patterns. This immediately brings up:

* **`AXObjectCacheImpl`:**  The central class. The `Impl` suffix suggests this is an implementation detail. "Cache" hints at storing and managing accessibility information.
* **`updates` and `events`:** These are clearly related to sending accessibility information (updates and events) to an external client.
* **`dirty`:**  This term appears frequently, indicating a mechanism for tracking changes.
* **`serialization`:**  The code explicitly talks about sending updates/events via serialization.
* **`PostNotification`:**  A key function for triggering accessibility events.
* **`TreeUpdateReason`:** An enum indicating different reasons for accessibility tree updates.
* **HTML attributes (e.g., `aria-expanded`, `aria-selected`, `id`, `usemap`):**  These signal interaction with HTML structure and ARIA attributes.
* **DOM elements (e.g., `Node`, `Element`, `HTMLFrameOwnerElement`, `HTMLSelectElement`):**  Direct interaction with the DOM.
* **Layout objects (`LayoutObject`, `LayoutBlockFlow`):**  Integration with the layout engine.
* **Focus (`HandleNodeGainedFocus`, `HandleNodeLostFocus`):**  Handling focus events.
* **Roles (`HandleRoleChange`, `HandleRoleMaybeChanged`):**  Managing accessibility roles.
* **`relation_cache_`:**  A component for managing relationships between accessible objects.
* **`IsParsingMainDocument`, `IsMainDocumentDirty`, `IsPopupDocumentDirty`:**  Handling different document states.
* **`lifecycle_`:**  Managing the document lifecycle.

**3. Grouping Functionality:**

Based on the initial scan, I start grouping related functions and code blocks:

* **Serialization:** `SendAccessibilitySerialization`, `OnSerializationCancelled`, `IsDirty`, `IsMainDocumentDirty`, `IsPopupDocumentDirty`,  `ScheduleAXUpdate`. These are all about preparing and sending accessibility information.
* **Tree Updates:**  `ProcessCleanLayoutCallbacks`, `FireTreeUpdatedEventForAXID`, `FireTreeUpdatedEventForNode`, `DeferTreeUpdate`, `MarkElementDirty`, `MarkAXObjectDirty`, `MarkAXSubtreeDirty`,  various `...WithCleanLayout` functions. These handle updates to the internal accessibility tree.
* **Event Handling:** `PostNotification`, various `Handle...` functions (focus, ARIA changes, clicks, etc.). These react to events and trigger accessibility updates.
* **ARIA Attribute Handling:** Functions specifically dealing with ARIA attributes like `HandleAriaExpandedChange`, `HandleAriaSelectedChanged`, `AriaOwnsChanged`.
* **Relationships:** `relation_cache_`, `IsAriaOwned`, `ValidatedAriaOwner`, `MayHaveHTMLLabel`, `MaybeNewRelationTarget`. This deals with how accessible objects are related to each other.
* **Focus Management:** `HandleNodeGainedFocus`, `HandleNodeLostFocus`.
* **Menu Lists:** `SetMenuListOptionsBounds`, `GetOptionsBounds`.
* **Dirty Checking:** Functions that check if the accessibility tree needs updates.

**4. Identifying Relationships with Web Technologies:**

Now, connect the grouped functionalities to HTML, CSS, and JavaScript:

* **HTML:**  The code directly interacts with HTML elements and their attributes (especially ARIA attributes). The `TreeUpdateReason` enum often corresponds to changes in HTML structure or attributes.
* **CSS:**  While not explicitly manipulating CSS, the code responds to layout changes (`LayoutObject`, `LayoutBlockFlow`). CSS changes that affect layout will indirectly trigger accessibility updates.
* **JavaScript:**  JavaScript interactions can trigger DOM changes, attribute modifications, and focus changes, all of which are handled by this code. For example, a JavaScript click handler might lead to a `HandleClicked` call. ARIA attributes are often dynamically modified via JavaScript.

**5. Logical Reasoning and Examples:**

For each functional area, think about the inputs and outputs and how the logic flows. Create simple scenarios:

* **Serialization:** If the DOM changes (input), the cache becomes dirty and serialization sends updates (output).
* **Event Handling:** If a button is clicked (input), a `kClicked` event is posted (output).
* **ARIA:** If `aria-expanded` changes (input), the `HandleAriaExpandedChangeWithCleanLayout` function is called, updating the accessible state (output).

**6. Identifying User/Programming Errors:**

Think about common mistakes developers make related to accessibility:

* **Incorrect ARIA usage:**  Setting conflicting ARIA attributes could lead to unexpected behavior.
* **Dynamically changing roles:** The code warns against this, indicating potential issues.
* **Not updating ARIA attributes when state changes:** This would lead to inaccurate information being presented to assistive technologies.

**7. Tracing User Actions (Debugging Clues):**

Consider how user actions flow through the system to reach this code:

* **Page Load:** Initial parsing and rendering trigger accessibility object creation.
* **User Interaction:** Clicks, keyboard navigation, form submissions, etc., can all lead to accessibility events.
* **JavaScript Actions:**  Dynamic modifications via JavaScript.

**8. Summarization:**

Finally, synthesize the findings into a concise summary that captures the essence of the code's functionality. Focus on the core responsibilities: managing the accessibility tree, handling updates, and sending information to assistive technologies.

**Self-Correction/Refinement:**

Throughout the process, I might revisit earlier steps. For example, while initially focusing on individual functions, I might realize the importance of the `relation_cache_` and dedicate a separate section to it. Or, when thinking about user errors, I might recall common ARIA pitfalls. The process isn't strictly linear.

By following these steps, I can systematically analyze the code snippet and generate a comprehensive and informative response that addresses all aspects of the request.
这是 `blink/renderer/modules/accessibility/ax_object_cache_impl.cc` 文件的第五部分，该文件是 Chromium Blink 引擎中负责管理可访问性信息的核心组件。根据提供的代码片段，我们可以归纳出以下功能：

**核心功能：维护和同步可访问性树，并将其变化通知给辅助技术 (AT)。**

这部分代码主要关注以下几个方面：

1. **可访问性信息序列化和发送:**
   - `SendAccessibilitySerialization()` 函数负责将收集到的可访问性更新（`updates`）和事件（`events`）序列化并通过 `client` 发送出去。
   - **功能归纳:**  将内部可访问性树的变化转化为外部系统可以理解的消息格式，并发送给辅助技术。
   - **与 JavaScript, HTML, CSS 的关系:**
     - **HTML:** HTML 结构和语义是可访问性树的基础。例如，HTML 元素的标签、属性（尤其是 ARIA 属性）直接影响 `updates` 中的节点信息。
     - **CSS:** CSS 影响元素的渲染和布局，而布局信息（如元素的位置和大小）会包含在 `location_and_scroll_changes` 中。例如，一个元素因为 CSS 的 `position: absolute` 而移动，会导致其边界信息更新。
     - **JavaScript:** JavaScript 可以动态修改 DOM 结构、属性和样式，这些变化会触发可访问性树的更新。例如，JavaScript 通过 `setAttribute('aria-expanded', 'true')` 修改元素的 ARIA 属性，会触发一个事件并导致相关节点的更新。
   - **假设输入与输出:**
     - **假设输入:** `updates` 包含一个 `AXNodeData` 对象，描述了一个按钮元素的 `aria-pressed` 属性从 `false` 变为 `true` 的变化。`events` 包含一个 `kCheckedStateChanged` 事件，关联到该按钮元素。
     - **输出:** `SendAccessibilitySerialization()` 函数将这些信息打包成消息，发送给辅助技术。辅助技术可能会因此更新按钮的状态显示，例如高亮显示或发出“已按下”的提示音。
   - **用户/编程常见的使用错误:**
     - **错误地操作 `updates` 或 `events`:**  开发者不应直接操作这些数据结构，而是通过 `AXObjectCacheImpl` 提供的方法来触发更新。
     - **忘记标记节点为 dirty:** 如果 DOM 发生变化，但相应的可访问性节点没有被标记为 dirty，`SendAccessibilitySerialization()` 就不会发送相应的更新，导致辅助技术信息不准确。
   - **用户操作如何到达这里 (调试线索):**
     1. 用户点击网页上的一个按钮。
     2. 浏览器的事件处理机制捕获到点击事件。
     3. JavaScript 代码（如果有）可能会响应点击事件，并修改按钮的某个属性，例如 `aria-pressed`。
     4. Blink 引擎的渲染流程检测到 DOM 变化。
     5. `AXObjectCacheImpl` 监测到相关节点的属性变化，并将其标记为 dirty。
     6. 在适当的时机（例如，layout 完成后），`CommitAXUpdates()` 会被调用。
     7. `CommitAXUpdates()` 调用 `SendAccessibilitySerialization()`，将 dirty 节点的更新和相关事件发送出去。

2. **管理 Block Flow 数据:**
   - `ResetActiveBlockFlowContainer()` 清空当前活动的 block flow 容器。
   - `GetBlockFlowData()` 返回给定 `AXObject` 关联的 `AXBlockFlowData`。这似乎与文本布局和段落处理有关。
   - **功能归纳:**  管理文本内容的布局信息，可能用于辅助技术理解文本的结构。
   - **与 JavaScript, HTML, CSS 的关系:**
     - **HTML:** HTML 的段落标签 `<p>` 或其他块级元素会创建 block flow。
     - **CSS:** CSS 的布局属性（如 `display: block`, `float`, `clear`）影响 block flow 的形成和结构。
   - **假设输入与输出:**
     - **假设输入:**  一个 `AXObject` 代表一个 HTML 段落元素 `<p>This is a paragraph.</p>`。
     - **输出:** `GetBlockFlowData()` 返回一个 `AXBlockFlowData` 对象，其中可能包含该段落的行数、每行的起始和结束位置等信息。

3. **判断文档状态 (Dirty 状态):**
   - `IsParsingMainDocument()`, `IsMainDocumentDirty()`, `IsPopupDocumentDirty()`, `IsDirty()` 等函数用于判断可访问性树是否需要更新。
   - **功能归纳:**  高效地判断可访问性树的状态，避免不必要的更新和序列化操作。
   - **与 JavaScript, HTML, CSS 的关系:**  任何导致 DOM 结构、属性或布局发生变化的操作都可能导致文档变为 dirty 状态。

4. **处理 Embedding Token 变化:**
   - `EmbeddingTokenChanged()` 标记包含 embedding token 的元素为 dirty。这可能与 Shadow DOM 或 iframe 等嵌入内容有关。

5. **判断文档类型 (Popup):**
   - `IsPopup()` 判断给定的 `Document` 是否是弹出窗口的文档。

6. **获取 Tree Update Callback 队列:**
   - `GetTreeUpdateCallbackQueue()` 返回与给定文档关联的 tree update callback 队列。

7. **处理 Clean Layout 回调:**
   - `ProcessCleanLayoutCallbacks()` 处理在 layout 完成后需要执行的可访问性更新回调。
   - **功能归纳:**  确保在布局稳定后进行可访问性更新，避免因布局不稳定导致的错误信息。

8. **发送通知 (PostNotification):**
   - `PostNotification()` 函数用于向辅助技术发送可访问性事件通知。
   - **功能归纳:**  主动告知辅助技术页面上发生的特定事件，例如焦点变化、状态改变等。
   - **与 JavaScript, HTML, CSS 的关系:**
     - **HTML:**  某些 HTML 元素的交互（例如，按钮点击，复选框状态改变）会触发特定的可访问性事件。
     - **JavaScript:** JavaScript 可以显式地调用 `PostNotification()` 或触发导致 `PostNotification()` 调用的 DOM 事件。

9. **调度可访问性更新 (ScheduleAXUpdate):**
   - `ScheduleAXUpdate()` 负责在合适的时机调度可访问性树的更新。这通常与浏览器的渲染流程同步。

10. **触发 Tree Updated 事件:**
    - `FireTreeUpdatedEventForAXID()` 和 `FireTreeUpdatedEventForNode()` 根据 `TreeUpdateParams` 中的信息，触发针对特定 AXID 或 Node 的更新处理逻辑。
    - **功能归纳:**  执行具体的更新操作，例如更新节点的属性、子节点关系等。

11. **处理特定 ARIA 属性和事件:**
    - 提供了多个 `Handle...WithCleanLayout()` 函数，用于处理特定的 ARIA 属性变化或 DOM 事件，例如 `aria-expanded` 改变、焦点改变、角色改变等。
    - **功能归纳:**  针对特定的可访问性语义进行精细化的处理，确保辅助技术能够准确理解页面的状态和交互。

12. **管理 ARIA Owned 关系:**
    - `IsAriaOwned()`, `ValidatedAriaOwner()`, `ValidatedAriaOwnedChildren()` 等函数用于管理通过 `aria-owns` 属性建立的元素之间的关系。

13. **处理 Label 和 Description 关系:**
    - `MayHaveHTMLLabel()`, `IsLabelOrDescription()` 用于判断元素是否有关联的 label 或 description。

14. **处理表单元素状态变化:**
    - `CheckedStateChanged()`, `ListboxOptionStateChanged()`, `ListboxSelectedChildrenChanged()`, `ListboxActiveIndexChanged()` 等函数处理表单元素的状态变化，并发送相应的可访问性事件。

15. **管理 Menu List 的选项边界:**
    - `SetMenuListOptionsBounds()`, `GetOptionsBounds()` 用于存储和获取下拉菜单选项的屏幕坐标，以便辅助技术可以准确定位和操作菜单项。

16. **处理图片加载完成事件:**
    - `ImageLoaded()` 标记加载完成的图片元素为 dirty，以便更新其可访问性信息。

17. **处理点击事件:**
    - `HandleClicked()` 处理元素的点击事件，并发送相应的可访问性通知。

18. **处理 ARIA Notification:**
    - `HandleAriaNotification()` 和 `RetrieveAriaNotifications()` 用于处理通过 ARIA Live Regions 发出的通知。

19. **处理 Table Role 变化:**
    - `UpdateTableRoleWithCleanLayout()` 用于更新表格的角色信息。

**用户操作是如何一步步的到达这里 (调试线索):**

以 `HandleAriaExpandedChangeWithCleanLayout()` 为例：

1. **用户操作:** 用户点击一个带有 `aria-expanded` 属性的元素（例如，一个可展开/折叠的 section）。
2. **事件触发:** 浏览器捕获到用户的点击事件。
3. **JavaScript 处理 (可能):**  可能存在 JavaScript 代码监听点击事件，并修改该元素的 `aria-expanded` 属性值。
4. **属性变更观察:**  Blink 引擎的属性变更观察机制检测到 `aria-expanded` 属性的变化。
5. **触发可访问性更新:**  `AXObjectCacheImpl` 接收到属性变更通知，并调用 `DeferTreeUpdate(TreeUpdateReason::kAriaExpandedChanged, element)` 将更新请求加入队列。
6. **Clean Layout 完成:**  在布局完成后，`ProcessCleanLayoutCallbacks()` 会被调用。
7. **执行更新回调:**  在 `ProcessCleanLayoutCallbacks()` 中，与 `kAriaExpandedChanged` 相关的回调（即 `FireTreeUpdatedEventForNode()`）会被执行，最终调用 `HandleAriaExpandedChangeWithCleanLayout()`。

**总结这部分的功能:**

这部分代码主要负责可访问性信息的序列化和发送，管理 block flow 数据，判断可访问性树的 dirty 状态，处理各种 DOM 事件和 ARIA 属性变化，以及调度和执行可访问性树的更新操作。它的核心目标是维护一个与 DOM 结构和状态同步的可访问性树，并将这些信息准确地传递给辅助技术，以提升网页的可访问性。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_object_cache_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
ates.empty() -implies-> events.empty()
  DCHECK(!updates.empty() || events.empty())
      << "Every event must have at least one corresponding update because "
         "events cause their related nodes to be marked dirty.";
  DCHECK(!updates.empty());

  // There should be no more dirty objects.
  CHECK(!HasObjectsPendingSerialization());

  /* If there's location updates pending, send them on the way. */
  ui::AXLocationAndScrollUpdates location_and_scroll_changes;
  if (!changed_bounds_ids_.empty()) {
    location_and_scroll_changes = TakeLocationChangsForSerialization();
  }

  /* Send the actual serialization message.*/
  bool success = client->SendAccessibilitySerialization(
      std::move(updates), std::move(events),
      std::move(location_and_scroll_changes), had_load_complete_messages);

  if (!success) {
    // In some cases, like in web tests or if a11y is off, serialization doesn't
    // really occur and thus the function will return false.
    // Cancel serialization to avoid stalling pipeline.
    OnSerializationCancelled();
  }

  if (had_load_complete_messages) {
    load_sent_ = true;
  }

  CHECK(serialization_in_flight_ == success);
  return success;
}

void AXObjectCacheImpl::ResetActiveBlockFlowContainer() {
  active_block_flow_container_ = nullptr;
  active_block_flow_data_ = nullptr;
}

const AXBlockFlowData* AXObjectCacheImpl::GetBlockFlowData(
    const AXObject* object) {
  // TODO: Assumption that we are only really working on one paragraph at a
  // time turned out to be incorrect. Ideally, we can come up with a strategy
  // to make this work in order to avoid memory bloat.
  LayoutBlockFlow* block_flow =
      object->GetLayoutObject()->FragmentItemsContainer();

  if (block_flow != active_block_flow_container_) {
    active_block_flow_container_ = block_flow;
    active_block_flow_data_ = MakeGarbageCollected<AXBlockFlowData>(block_flow);
  }

  return active_block_flow_data_;
}

bool AXObjectCacheImpl::IsParsingMainDocument() const {
  return GetDocument().Parser() &&
         !GetDocument().GetAgent().isolate()->InContext();
}

bool AXObjectCacheImpl::IsMainDocumentDirty() const {
  return !tree_update_callback_queue_main_.empty();
}

bool AXObjectCacheImpl::IsPopupDocumentDirty() const {
  if (!popup_document_) {
    // This should have been cleared in RemovePopup(), but technically the
    // popup could be null without calling that, since it's a weak pointer.
    DCHECK(tree_update_callback_queue_popup_.empty());
    return false;
  }
  return !tree_update_callback_queue_popup_.empty();
}

bool AXObjectCacheImpl::IsDirty() {
  if (!GetDocument().IsActive()) {
    return false;
  }

  if (mark_all_dirty_) {
    return true;
  }
  if (IsMainDocumentDirty() || IsPopupDocumentDirty() || !relation_cache_ ||
      relation_cache_->IsDirty()) {
    return true;
  }
  if (Root()->NeedsToUpdateChildren() || Root()->HasDirtyDescendants()) {
    return true;
  }
  // If tree updates are paused, consider the cache dirty. The next time
  // CommitAXUpdates() is called, the entire tree will be
  // rebuilt from the root.
  if (tree_updates_paused_) {
    return true;
  }
  return false;
}

void AXObjectCacheImpl::EmbeddingTokenChanged(HTMLFrameOwnerElement* element) {
  if (!element)
    return;

  MarkElementDirty(element);
}

bool AXObjectCacheImpl::IsPopup(Document& document) const {
  // There are 1-2 documents per AXObjectCache: the main document and
  // sometimes a popup document.
  int is_popup = document != GetDocument();
  if (is_popup) {
#if DCHECK_IS_ON()
    // Verify that the popup document's owner is the main document.
    LocalFrame* frame = document.GetFrame();
    DCHECK(frame);
    Element* popup_owner = frame->PagePopupOwner();
    DCHECK(popup_owner);
    DCHECK_EQ(popup_owner->GetDocument(), GetDocument())
        << "The popup document's owner should be in the main document.";
    Page* main_page = GetDocument().GetPage();
    DCHECK(main_page);
#endif
    return &document == GetPopupDocumentIfShowing();
  }
  return is_popup;
}

AXObjectCacheImpl::TreeUpdateCallbackQueue&
AXObjectCacheImpl::GetTreeUpdateCallbackQueue(Document& document) {
  return IsPopup(document) ? tree_update_callback_queue_popup_
                           : tree_update_callback_queue_main_;
}

void AXObjectCacheImpl::ProcessCleanLayoutCallbacks(Document& document) {
  SCOPED_DISALLOW_LIFECYCLE_TRANSITION();

  UpdateNumTreeUpdatesQueuedBeforeLayoutHistogram();

  CHECK(!IsFrozen());

  TreeUpdateCallbackQueue old_tree_update_callback_queue;
  GetTreeUpdateCallbackQueue(document).swap(old_tree_update_callback_queue);
  nodes_with_pending_children_changed_.clear();
  last_value_change_node_ = ui::AXNodeData::kInvalidAXID;

  for (TreeUpdateParams* tree_update : old_tree_update_callback_queue) {
    if (tree_update->node) {
      if (tree_update->node->GetDocument() == document) {
        FireTreeUpdatedEventForNode(tree_update);
      }
    } else {
      FireTreeUpdatedEventForAXID(tree_update, document);
    }
  }
}

void AXObjectCacheImpl::PostNotification(const LayoutObject* layout_object,
                                         ax::mojom::blink::Event notification) {
  if (!layout_object)
    return;
  PostNotification(Get(layout_object), notification);
}

void AXObjectCacheImpl::PostNotification(Node* node,
                                         ax::mojom::blink::Event notification) {
  if (!node)
    return;
  PostNotification(Get(node), notification);
}

void AXObjectCacheImpl::PostNotification(AXObject* object,
                                         ax::mojom::blink::Event event_type) {
  if (!object || !object->AXObjectID() || object->IsDetached())
    return;

  ax::mojom::blink::EventFrom event_from = ComputeEventFrom();

  // If PostNotification is called while outside of processing deferred events,
  // defer it to to happen later while processing deferred_events.
  // TODO(accessibility): Replace calls of PostNotification with direct cleaner
  // calls to DeferTreeUpdate.
  if (lifecycle_.StateAllowsDeferTreeUpdates()) {
    // TODO(accessibility): Investigate why invalidate_cached_values needs to be
    // false here and maybe remove it from signature once it's not needed
    // anymore.
    DeferTreeUpdate(TreeUpdateReason::kDelayEventFromPostNotification, object,
                    event_type, /*invalidate_cached_values=*/false);

    if (IsImmediateProcessingRequiredForEvent(event_from, object, event_type)) {
      ScheduleImmediateSerialization();
    }
    return;
  }

  ax::mojom::blink::Action event_from_action = active_event_from_action_;
  const BlinkAXEventIntentsSet& event_intents = ActiveEventIntents();

#if DCHECK_IS_ON()
  // Make sure that we're not in the process of being laid out. Notifications
  // should only be sent after the LayoutObject has finished
  DCHECK(GetDocument().Lifecycle().GetState() !=
         DocumentLifecycle::kInPerformLayout);

  SCOPED_DISALLOW_LIFECYCLE_TRANSITION();
#endif  // DCHECK_IS_ON()

  PostPlatformNotification(object, event_type, event_from, event_from_action,
                           event_intents);
}

void AXObjectCacheImpl::ScheduleAXUpdate() const {
  // A visual update will force accessibility to be updated as well.
  // Scheduling visual updates before the document is finished loading can
  // interfere with event ordering. In any case, at least one visual update will
  // occur between now and when the document load is complete.
  if (!GetDocument().IsLoadCompleted())
    return;

  // If there was a document change that doesn't trigger a lifecycle update on
  // its own, (e.g. because it doesn't make layout dirty), make sure we run
  // lifecycle phases to update the computed accessibility tree.
  LocalFrameView* frame_view = GetDocument().View();
  Page* page = GetDocument().GetPage();
  if (!frame_view || !page)
    return;

  if (!frame_view->CanThrottleRendering() &&
      !GetDocument().GetPage()->Animator().IsServicingAnimations()) {
    page->Animator().ScheduleVisualUpdate(GetDocument().GetFrame());
  }
}

void AXObjectCacheImpl::FireTreeUpdatedEventForAXID(
    TreeUpdateParams* tree_update,
    Document& document) {
  if (!tree_update->axid) {
    // No node and no AXID means that it was a node update, but the
    // WeakMember<Node> is no longer available.
    return;
  }

  AXObject* ax_object = ObjectFromAXID(tree_update->axid);
  if (!ax_object || ax_object->IsDetached()) {
    return;
  }

  if (ax_object->GetNode() && !ax_object->GetNode()->isConnected()) {
    return;
  }

  if (document != *ax_object->GetDocument()) {
    return;
  }

  DUMP_WILL_BE_CHECK(!ax_object->IsMissingParent())
      << tree_update->ToString() << " on " << ax_object;

  // Update cached attributes for all changed nodes before serialization,
  // because updating ignored/included can cause tree structure changes, and
  // the tree structure needs to be stable before serialization begins.
  ax_object->UpdateCachedAttributeValuesIfNeeded(/* notify_parent */ true);
  if (ax_object->IsDetached()) {
    return;
  }

  base::AutoReset<ax::mojom::blink::EventFrom> event_from_resetter(
      &active_event_from_, tree_update->event_from);
  base::AutoReset<ax::mojom::blink::Action> event_from_action_resetter(
      &active_event_from_action_, tree_update->event_from_action);
  ScopedBlinkAXEventIntent defered_event_intents(
      tree_update->event_intents.AsVector(), ax_object->GetDocument());

  // Kept here for convenient debugging:
  // LOG(ERROR) << tree_update->ToString() << " on " << ax_object;

  switch (tree_update->update_reason) {
    case TreeUpdateReason::kChildrenChanged:
      ChildrenChangedWithCleanLayout(ax_object->GetNode(), ax_object);
      break;
    case TreeUpdateReason::kDelayEventFromPostNotification:
      PostNotification(ax_object, tree_update->event);
      break;
    case TreeUpdateReason::kMarkAXObjectDirty:
      MarkAXObjectDirtyWithCleanLayout(ax_object);
      break;
    case TreeUpdateReason::kMarkAXSubtreeDirty:
      MarkAXSubtreeDirtyWithCleanLayout(ax_object);
      break;
    case TreeUpdateReason::kTextChangedOnLayoutObject:
      TextChangedWithCleanLayout(ax_object->GetNode(), ax_object);
      break;
    default:
      NOTREACHED() << "Update reason not handled: "
                   << static_cast<int>(tree_update->update_reason);
  }

  // Ensure that new subtrees are filled out. Any new AXObjects added will
  // also add their children.
  if (!ax_object->IsDetached()) {
    ax_object->UpdateChildrenIfNecessary();
  }
}

void AXObjectCacheImpl::FireTreeUpdatedEventForNode(
    TreeUpdateParams* tree_update) {
  Node* node = tree_update->node;
  CHECK(node);
  if (!node->isConnected()) {
    return;
  }

  // kRestoreParentOrPrune does not require an up-to-date AXObject.
  if (tree_update->update_reason == TreeUpdateReason::kRestoreParentOrPrune) {
    RestoreParentOrPruneWithCleanLayout(node);
    return;
  }

  AXObject* ax_object = Get(node);
  if (!ax_object) {
    return;
  }

  ax_object->UpdateCachedAttributeValuesIfNeeded(/* notify_parent */ true);
  if (ax_object->IsDetached()) {
    return;
  }

  DUMP_WILL_BE_CHECK(!ax_object->IsMissingParent())
      << tree_update->ToString() << " on " << ax_object;

  base::AutoReset<ax::mojom::blink::EventFrom> event_from_resetter(
      &active_event_from_, tree_update->event_from);
  base::AutoReset<ax::mojom::blink::Action> event_from_action_resetter(
      &active_event_from_action_, tree_update->event_from_action);
  ScopedBlinkAXEventIntent defered_event_intents(
      tree_update->event_intents.AsVector(), &node->GetDocument());

  // Kept here for convenient debugging:
  // LOG(ERROR) << tree_update->ToString() << " on " << ax_object;

  switch (tree_update->update_reason) {
    case TreeUpdateReason::kActiveDescendantChanged:
      HandleActiveDescendantChangedWithCleanLayout(node);
      break;
    case TreeUpdateReason::kAriaExpandedChanged:
      HandleAriaExpandedChangeWithCleanLayout(node);
      break;
    case TreeUpdateReason::kAriaOwnsChanged:
      AriaOwnsChangedWithCleanLayout(node);
      break;
    case TreeUpdateReason::kAriaPressedChanged:
      HandleAriaPressedChangedWithCleanLayout(node);
      break;
    case TreeUpdateReason::kAriaSelectedChanged:
      HandleAriaSelectedChangedWithCleanLayout(node);
      break;
    case TreeUpdateReason::kCSSAnchorChanged:
      CSSAnchorChangedWithCleanLayout(node);
      break;
    case TreeUpdateReason::kDidShowMenuListPopup:
      HandleUpdateMenuListPopupWithCleanLayout(node, /*did_show*/ true);
      break;
    case TreeUpdateReason::kMaybeDisallowImplicitSelection:
      MaybeDisallowImplicitSelectionWithCleanLayout(ax_object);
      break;
    case TreeUpdateReason::kEditableTextContentChanged:
      HandleEditableTextContentChangedWithCleanLayout(node);
      break;
    case TreeUpdateReason::kIdChanged:
      // When the id attribute changes, the relations its in may also change.
      MaybeNewRelationTarget(*node, ax_object);
      break;
    case TreeUpdateReason::kNodeGainedFocus:
      HandleNodeGainedFocusWithCleanLayout(node);
      break;
    case TreeUpdateReason::kNodeLostFocus:
      HandleNodeLostFocusWithCleanLayout(node);
      break;
    case TreeUpdateReason::kPostNotificationFromHandleLoadComplete:
    case TreeUpdateReason::kPostNotificationFromHandleLoadStart:
    case TreeUpdateReason::kPostNotificationFromHandleScrolledToAnchor:
      PostNotification(node, tree_update->event);
      break;
    case TreeUpdateReason::kReferenceTargetChanged:
      // When a shadow root's reference target changes, relations referring
      // to the shadow host may change since they will be forwarded to
      // the new reference target.
      MaybeNewRelationTarget(*node, ax_object);
      break;
    case TreeUpdateReason::kRemoveValidationMessageObjectFromFocusedUIElement:
      RemoveValidationMessageObjectWithCleanLayout(node);
      break;
    case TreeUpdateReason::kRoleChangeFromAriaHasPopup:
    case TreeUpdateReason::kRoleChangeFromImageMapName:
    case TreeUpdateReason::kRoleChangeFromRoleOrType:
      HandleRoleChangeWithCleanLayout(node);
      break;
    case TreeUpdateReason::kRoleMaybeChangedFromEventListener:
    case TreeUpdateReason::kRoleMaybeChangedFromHref:
    case TreeUpdateReason::kRoleMaybeChangedOnSelect:
      HandleRoleMaybeChangedWithCleanLayout(node);
      break;
    case TreeUpdateReason::kSectionOrRegionRoleMaybeChangedFromLabel:
    case TreeUpdateReason::kSectionOrRegionRoleMaybeChangedFromLabelledBy:
    case TreeUpdateReason::kSectionOrRegionRoleMaybeChangedFromTitle:
      SectionOrRegionRoleMaybeChangedWithCleanLayout(node);
      break;
    case TreeUpdateReason::kTextChangedOnNode:
    case TreeUpdateReason::kTextChangedOnClosestNodeForLayoutObject:
      TextChangedWithCleanLayout(node);
      break;
    case TreeUpdateReason::kTextMarkerDataAdded:
      HandleTextMarkerDataAddedWithCleanLayout(node);
      break;
    case TreeUpdateReason::kUpdateActiveMenuOption:
      HandleUpdateMenuListPopupWithCleanLayout(node);
      break;
    case TreeUpdateReason::kNodeIsAttached:
      NodeIsAttachedWithCleanLayout(node);
      break;
    case TreeUpdateReason::kUpdateAriaOwns:
      UpdateAriaOwnsWithCleanLayout(node);
      break;
    case TreeUpdateReason::kUpdateTableRole:
      UpdateTableRoleWithCleanLayout(node);
      break;
    case TreeUpdateReason::kUseMapAttributeChanged:
      HandleUseMapAttributeChangedWithCleanLayout(node);
      break;
    case TreeUpdateReason::kValidationMessageVisibilityChanged:
      HandleValidationMessageVisibilityChangedWithCleanLayout(node);
      break;
    default:
      NOTREACHED() << "Update reason not handled: "
                   << static_cast<int>(tree_update->update_reason);
  }
  // Ensure that new subtrees are filled out. Any new AXObjects added will
  // also add their children.
  if (!ax_object->IsDetached()) {
    ax_object->UpdateChildrenIfNecessary();
  }
}

bool AXObjectCacheImpl::IsAriaOwned(const AXObject* object, bool checks) const {
  return relation_cache_ ? relation_cache_->IsAriaOwned(object, checks) : false;
}

AXObject* AXObjectCacheImpl::ValidatedAriaOwner(const AXObject* object) const {
  DCHECK(GetDocument().Lifecycle().GetState() >=
         DocumentLifecycle::kLayoutClean);
  CHECK(relation_cache_);
  return relation_cache_->ValidatedAriaOwner(object);
}

void AXObjectCacheImpl::ValidatedAriaOwnedChildren(
    const AXObject* owner,
    HeapVector<Member<AXObject>>& owned_children) {
  DCHECK(GetDocument().Lifecycle().GetState() >=
         DocumentLifecycle::kLayoutClean);
  CHECK(relation_cache_);
  relation_cache_->ValidatedAriaOwnedChildren(owner, owned_children);
}

bool AXObjectCacheImpl::MayHaveHTMLLabel(const HTMLElement& elem) {
  CHECK(elem.GetDocument().Lifecycle().GetState() >=
        DocumentLifecycle::kLayoutClean)
      << "Unclean document at lifecycle " << elem.GetDocument().ToString();
  CHECK(relation_cache_);

  // Return false if this type of element will not accept a <label for> label.
  if (!elem.IsLabelable())
    return false;

  // Return true if a <label for> pointed to this element at some point.
  if (relation_cache_->MayHaveHTMLLabelViaForAttribute(elem)) {
    return true;
  }

  // Return true if any ancestor is a label, as in <label><input></label>.
  if (Traversal<HTMLLabelElement>::FirstAncestor(elem)) {
    return true;
  }

  // If the element is the reference target of its shadow host, also check if
  // the host may have a label.
  if (ShadowRoot* shadow_root = elem.ContainingShadowRoot()) {
    if (shadow_root->referenceTargetElement() == &elem) {
      if (HTMLElement* host = DynamicTo<HTMLElement>(shadow_root->host())) {
        return MayHaveHTMLLabel(*host);
      }
    }
  }

  return false;
}

bool AXObjectCacheImpl::IsLabelOrDescription(Element& element) {
  if (IsA<HTMLLabelElement>(element)) {
    return true;
  }
  CHECK(relation_cache_);
  return relation_cache_ && relation_cache_->IsARIALabelOrDescription(element);
}

void AXObjectCacheImpl::CheckedStateChanged(Node* node) {
  PostNotification(node, ax::mojom::blink::Event::kCheckedStateChanged);
}

void AXObjectCacheImpl::ListboxOptionStateChanged(HTMLOptionElement* option) {
  PostNotification(option, ax::mojom::Event::kCheckedStateChanged);
}

void AXObjectCacheImpl::ListboxSelectedChildrenChanged(
    HTMLSelectElement* select) {
  PostNotification(select, ax::mojom::Event::kSelectedChildrenChanged);
}

void AXObjectCacheImpl::ListboxActiveIndexChanged(HTMLSelectElement* select) {
  SCOPED_DISALLOW_LIFECYCLE_TRANSITION();

  if (select->IsFocused()) {
    if (HTMLOptionElement* option = select->ActiveSelectionEnd()) {
      DOMNodeId option_id = option->GetDomNodeId();
      if (option_id != last_selected_list_option_) {
        PostNotification(select,
                         ax::mojom::blink::Event::kActiveDescendantChanged);
        last_selected_list_option_ = option_id;
      }
    }
  }
}

void AXObjectCacheImpl::SetMenuListOptionsBounds(
    HTMLSelectElement* select,
    const WTF::Vector<gfx::Rect>& options_bounds) {
  CHECK(select->PopupIsVisible());
  CHECK_EQ(select->GetDocument(), GetDocument());
  options_bounds_ = options_bounds;
  current_menu_list_axid_ = select->GetDomNodeId();
}

const WTF::Vector<gfx::Rect>* AXObjectCacheImpl::GetOptionsBounds(
    const AXObject& ax_menu_list) const {
  if (RuntimeEnabledFeatures::CustomizableSelectEnabled()) {
    // Customizable select does not render in a special popup document and does
    // not need to supply bounding boxes via options_bounds_.
    HTMLSelectElement* select = To<HTMLSelectElement>(ax_menu_list.GetNode());
    if (select->IsAppearanceBasePicker()) {
      CHECK(!current_menu_list_axid_);
      CHECK(options_bounds_.empty());
      return nullptr;
    }
  }

  if (!current_menu_list_axid_ ||
      current_menu_list_axid_ != ax_menu_list.AXObjectID()) {
    return nullptr;
  }

  CHECK_EQ(ax_menu_list.IsExpanded(), kExpandedExpanded);
  CHECK(options_bounds_.size());

  return &options_bounds_;
}

void AXObjectCacheImpl::ImageLoaded(const LayoutObject* layout_object) {
  MarkElementDirty(layout_object->GetNode());
}

void AXObjectCacheImpl::HandleClicked(Node* node) {
  if (AXObject* obj = Get(RetargetInput(node))) {
    PostNotification(obj, ax::mojom::Event::kClicked);
  }
}

void AXObjectCacheImpl::HandleAriaNotification(
    const Node* node,
    const String& announcement,
    const AriaNotificationOptions* options) {
  auto* obj = Get(node);

  if (!obj) {
    return;
  }

  // We use `insert` regardless of whether there is an entry for this node in
  // `aria_notifications_` since, if there is one, it won't be replaced.
  // The return value of `insert` is a pair of an iterator to the entry, called
  // `stored_value`, and a boolean; `stored_value` contains a pair with the key
  // of the entry and a `value` reference to its mapped `AriaNotifications`.
  auto& node_notifications =
      aria_notifications_.insert(obj->AXObjectID(), AriaNotifications())
          .stored_value->value;

  node_notifications.Add(announcement, options);
  DeferTreeUpdate(TreeUpdateReason::kMarkAXObjectDirty, obj);
}

AriaNotifications AXObjectCacheImpl::RetrieveAriaNotifications(
    const AXObject* obj) {
  DCHECK(obj);

  // Conveniently, `Take` returns an empty `AriaNotifications` if there's no
  // entry in `aria_notifications_` associated to the given object.
  return aria_notifications_.Take(obj->AXObjectID());
}

void AXObjectCacheImpl::UpdateTableRoleWithCleanLayout(Node* table) {
  if (AXObject* ax_table = Get(table)) {
    if (ax_table->RoleValue() == ax::mojom::blink::Role::kLayoutTable &&
        ax_table->IsDataTable()) {
      HandleRoleChangeWithCleanLayout(table);
    }
  }
}

void AXObjectCacheImpl::HandleAriaExpandedChangeWithCleanLayout(Node* node) {
  if (!node)
    return;

  SCOPED_DISALLOW_LIFECYCLE_TRANSITION();

  DCHECK(!node->GetDocument().NeedsLayoutTreeUpdateForNode(*node));
  if (AXObject* obj = Get(node)) {
    obj->HandleAriaExpandedChanged();
  }
}

void AXObjectCacheImpl::HandleAriaPressedChangedWithCleanLayout(Node* node) {
  AXObject* ax_object = Get(node);
  if (!ax_object)
    return;

  ax::mojom::blink::Role previous_role = ax_object->RoleValue();
  bool was_toggle_button =
      previous_role == ax::mojom::blink::Role::kToggleButton;
  bool is_toggle_button =
      ax_object->HasAriaAttribute(html_names::kAriaPressedAttr);

  if (was_toggle_button != is_toggle_button)
    HandleRoleChangeWithCleanLayout(node);
  else
    PostNotification(node, ax::mojom::blink::Event::kCheckedStateChanged);
}

void AXObjectCacheImpl::MaybeDisallowImplicitSelectionWithCleanLayout(
    AXObject* subwidget) {
  bool do_notify = false;
  switch (subwidget->RoleValue()) {
    case ax::mojom::blink::Role::kTab:
      if (subwidget->HasAriaAttribute(html_names::kAriaExpandedAttr) ||
          subwidget->HasAriaAttribute(html_names::kAriaSelectedAttr)) {
        do_notify = true;
      }
      break;
    case ax::mojom::blink::Role::kListBoxOption:
    case ax::mojom::blink::Role::kMenuListOption:
    case ax::mojom::blink::Role::kTreeItem:
      if (subwidget->HasAriaAttribute(html_names::kAriaSelectedAttr) ||
          subwidget->HasAriaAttribute(html_names::kAriaCheckedAttr)) {
        do_notify = true;
      }
      break;
    default:
      return;
  }
  if (!do_notify) {
    return;
  }

  if (AXObject* container = subwidget->ContainerWidget()) {
    if (containers_disallowing_implicit_selection_
            .insert(container->AXObjectID())
            .is_new_entry) {
      if (subwidget->RoleValue() == ax::mojom::blink::Role::kTab) {
        // Tabs are a special case, because tab selection can be implicit via
        // focus of an element inside the tab panel it controls. For these, mark
        // all of the child tabs within the containing tablist dirty.
        for (const auto& child : container->CachedChildrenIncludingIgnored()) {
          AddDirtyObjectToSerializationQueue(child);
        }
        return;
      }
      // The active descendant or focus may lose its implicit selected state.
      AXObject* ax_focus = FocusedObject();
      if (ax_focus == container) {
        if (AXObject* activedescendant = container->ActiveDescendant()) {
          AddDirtyObjectToSerializationQueue(activedescendant);
        }
      }
      AddDirtyObjectToSerializationQueue(ax_focus);
    }
  }
}

bool AXObjectCacheImpl::IsImplicitSelectionAllowed(const AXObject* container) {
  DCHECK(container);
  return !containers_disallowing_implicit_selection_.Contains(
      container->AXObjectID());
}

// In single selection containers, selection follows focus, so a selection
// changed event must be fired. This ensures the AT is notified that the
// selected state has changed, so that it does not read "unselected" as
// the user navigates through the items. The event generator will handle
// the correct events as long as the old and newly selected objects are marked
// dirty.
void AXObjectCacheImpl::HandleAriaSelectedChangedWithCleanLayout(Node* node) {
  DCHECK(node);
  SCOPED_DISALLOW_LIFECYCLE_TRANSITION();

  DCHECK(!node->GetDocument().NeedsLayoutTreeUpdateForNode(*node));
  AXObject* obj = Get(node);
  if (!obj)
    return;

  // Mark the previous selected item dirty if it was selected via "selection
  // follows focus".
  if (last_selected_from_active_descendant_)
    MarkElementDirtyWithCleanLayout(last_selected_from_active_descendant_);

  // Mark the newly selected item dirty, and track it for use in the future.
  MarkAXObjectDirtyWithCleanLayout(obj);
  if (obj->IsSelectedFromFocus())
    last_selected_from_active_descendant_ = node;

  PostNotification(obj, ax::mojom::Event::kCheckedStateChanged);

  // TODO(accessibility): this may no longer be needed as it can be generated
  // from the browser side, and could be expensive for many items.
  AXObject* listbox = obj->ParentObjectUnignored();
  if (listbox && listbox->RoleValue() == ax::mojom::Role::kListBox) {
    // Ensure listbox options are in sync as selection status may have changed
    MarkAXSubtreeDirtyWithCleanLayout(listbox);
    PostNotification(listbox, ax::mojom::Event::kSelectedChildrenChanged);
  }
}

void AXObjectCacheImpl::HandleNodeLostFocusWithCleanLayout(Node* node) {
  DCHECK(node);
  DCHECK(!node->GetDocument().NeedsLayoutTreeUpdateForNode(*node));
  AXObject* obj = Get(node);
  if (!obj)
    return;

  PostNotification(obj, ax::mojom::Event::kBlur);

  if (AXObject* active_descendant = obj->ActiveDescendant()) {
    if (active_descendant->IsSelectedFromFocusSupported())
      HandleAriaSelectedChangedWithCleanLayout(active_descendant->GetNode());
  }
}

void AXObjectCacheImpl::HandleNodeGainedFocusWithCleanLayout(Node* node) {
  AXObject* obj = EnsureFocusedObject();

  PostNotification(obj, ax::mojom::Event::kFocus);

  if (AXObject* active_descendant = obj->ActiveDescendant()) {
    if (active_descendant->IsSelectedFromFocusSupported())
      HandleAriaSelectedChangedWithCleanLayout(active_descendant->GetNode());
  }
}

// This might be the new target of a relation. Handle all possible cases.
void AXObjectCacheImpl::MaybeNewRelationTarget(Node& node, AXObject* obj) {
  // Track reverse relations
  CHECK(relation_cache_);
  relation_cache_->UpdateRelatedTree(&node, obj);
  if (Element* element = DynamicTo<Element>(node)) {
    relation_cache_->UpdateRelatedTreeAfterChange(*element);
  }
}

void AXObjectCacheImpl::HandleActiveDescendantChangedWithCleanLayout(
    Node* node) {
  DCHECK(node);
  DCHECK(!node->GetDocument().NeedsLayoutTreeUpdateForNode(*node));

  if (AXObject* obj = Get(node)) {
    obj->HandleActiveDescendantChanged();
  }
}

// A <section> or role=region uses the region role if and only if it has a name.
void AXObjectCacheImpl::SectionOrRegionRoleMaybeChangedWithCleanLayout(
    Node* node) {
  TextChangedWithCleanLayout(node);
  Element* element = To<Element>(node);
  AXObject* ax_object = Get(element);
  if (!ax_object)
    return;

  // Require <section> or role="region" markup.
  if (!element->HasTagName(html_names::kSectionTag) &&
      ax_object->DetermineRawAriaRole() != ax::mojom::blink::Role::kRegion) {
    return;
  }

  HandleRoleMaybeChangedWithCleanLayout(element);
}

void AXObjectCacheImpl::TableCellRoleMaybeChanged(Node* node) {
  if (!node) {
    return;
  }
  // The role for a table cell depends in complex ways on multiple of its
  // siblings (see DecideRoleFromSiblings). Rather than attempt to reproduce
  // that logic here for invalidation, just recompute the role of all siblings
  // when new table cells are added.
  if (auto* cell = DynamicTo<HTMLTableCellElement>(node)) {
    for (auto* prev = LayoutTreeBuilderTraversal::PreviousSibling(*cell); prev;
         prev = LayoutTreeBuilderTraversal::PreviousSibling(*prev)) {
      HandleRoleMaybeChangedWithCleanLayout(prev);
    }
    HandleRoleMaybeChangedWithCleanLayout(cell);
    for (auto* next = LayoutTreeBuilderTraversal::NextSibling(*cell); next;
         next = LayoutTreeBuilderTraversal::PreviousSibling(*next)) {
      HandleRoleMaybeChangedWithCleanLayout(next);
    }
  }
}

void AXObjectCacheImpl::HandleRoleMaybeChangedWithCleanLayout(Node* node) {
  if (AXObject* obj = Get(node)) {
    // If role would stay the same, do nothing.
    if (obj->RoleValue() == obj->DetermineRoleValue()) {
      return;
    }

    HandleRoleChangeWithCleanLayout(node);
  }
}

// Be as safe as possible about changes that could alter the accessibility role,
// as this may require a different subclass of AXObject.
// Role changes are disallowed by the spec but we must handle it gracefully, see
// https://www.w3.org/TR/wai-aria-1.1/#h-roles for more information.
void AXObjectCacheImpl::HandleRoleChangeWithCleanLayout(Node* node) {
  DCHECK(node);
  DCHECK(!node->GetDocument().NeedsLayoutTreeUpdateForNode(*node));

  // Remove the current object and make the parent reconsider its children.
  if (AXObject* obj = Get(node)) {
    bool was_owned = IsAriaOwned(obj);
    AXObject* parent = obj->ParentObjectIncludedInTree();
    ChildrenChangedOnAncestorOf(obj);

    // The positioned object may have changed to/from a tooltip so a details
    // relationship may need to be added/removed from the anchor.
    if (AXObject* anchor = relation_cache_->GetAnchorForPositionedObject(obj)) {
      MarkElementDirtyWithCleanLayout(anchor->GetElement());
    }

    if (!obj->IsDetached()) {
      // Remove and rebuild the subtree, because some descendant computations
      // rely on the role of ancestors.
      // Examples, whether rows return true from SupportsNameFromContents(),
      // propagation of role="none", some table descendant roles.
      RemoveSubtree(node, /* remove_root */ true, /* notify_parent */ false);
    }

    if (was_owned) {
      relation_cache_->UpdateAriaOwnsWithCleanLayout(parent, /*force*/ true);
    }

    // A previous call could have detached the parent.
    if (parent->IsDetached()) {
      return;
    }

    // Calling GetOrCreate(node) will not only create a new object with the
    // correct role, it will also repair all parent-child relationships from the
    // included ancestor done. If a new AXObject is not possible it will remove
    // the subtree.
    parent->UpdateChildrenIfNecessary();
    if (AXObject* new_object = Get(node)) {
      relation_cache_->UpdateAriaOwnsWithCleanLayout(new_object,
                                                     /*force*/ true);
      new_object->UpdateChildrenIfNecessary();
      // Need to mark dirty because the dom_node_id-based ID remains the same,
      // and therefore the serializer may not automatically serialize this node
      // from the children changed on the parent.
      MarkAXSubtreeDirtyWithCleanLayout(new_object);
    }
  }
}

void AXObjectCacheImpl::HandleAttributeChanged(const QualifiedName& attr_name,
                                               Element* element) {
  DCHECK(element);
  if (attr_name.LocalName().StartsWith("aria-")) {
    // Perform updates specific to each attribute.
    if (attr_name == html_names::kAriaActivedescendantAttr) {
      if (relation_cache_) {
        relation_cache_->UpdateReverseActiveDescendantRelations(*element);
      }
      DeferTreeUpdate(TreeUpdateReason::kActiveDescendantChanged, element);
    } else if (attr_name == html_names::kAriaValuenowAttr ||
               attr_name == html_names::kAriaValuetextAttr) {
      HandleValueChanged(element);
    } else if (attr_name == html_names::kAriaLabelAttr) {
      TextChanged(element);
      DeferTreeUpdate(
          TreeUpdateReason::kSectionOrRegionRoleMaybeChangedFromLab
```