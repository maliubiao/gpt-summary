Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is part of the `AXObjectCacheImpl` class in Chromium's Blink rendering engine. This class is responsible for managing the accessibility tree.

Here's a breakdown of how to analyze the code and address each of the user's requests:

1. **Identify the core purpose:** The code snippet focuses on managing the serialization and updates of the accessibility tree. This involves marking objects as dirty, scheduling updates, and packaging changes for the browser process.

2. **Analyze individual functions:**  Go through each function in the snippet and understand its role:
    * `Reset()`: Resets the cache and marks everything as dirty for a full reserialization.
    * `ResetSerializer()`: Resets the serializer and schedules a full update.
    * `MarkElementDirty()`/`MarkElementDirtyWithCleanLayout()`: Marks an AX object associated with a DOM element as needing an update. The "WithCleanLayout" version assumes layout is up-to-date.
    * `GetFromTextOperationInNodeIdMap()`/`ClearTextOperationInNodeIdMap()`:  Manages a map to track text editing operations within nodes.
    * `GetSerializationTarget()`: Finds the appropriate AX object to serialize from a given object.
    * `RestoreParentOrPrune()`/`RestoreParentOrPruneWithCleanLayout()`:  Handles reconnecting a child node to the accessibility tree or removing it if no parent is found.
    * `HandleFocusedUIElementChanged()`:  Manages accessibility updates when the focused element changes.
    * `UpdateActiveAriaModalDialog()`/`AncestorAriaModalDialog()`/`GetActiveAriaModalDialog()`: Handles logic related to ARIA modal dialogs and their impact on the accessibility tree.
    * `TakeLocationChangsForSerialization()`: Collects location and scroll changes for serialization.
    * `SerializeLocationChanges()`:  Schedules and sends location and scroll changes to the browser process.
    * `SerializeEntireTree()`: Serializes the entire accessibility tree.
    * `AddDirtyObjectToSerializationQueue()`: Adds an AX object to a queue for serialization.
    * `MaybeSendCanvasHasNonTrivialFallbackUKM()`:  Logs a UKM event if a canvas element has a non-trivial fallback.
    * `GetUpdatesAndEventsForSerialization()`:  Collects dirty objects and accessibility events to create an update for the browser process.
    * `UpdateIncludedNodeCount()`/`UpdatePluginIncludedNodeCount()`: (DCHECK only) Tracks the number of included nodes in the main and plugin accessibility trees.
    * `IsInternalUICheckerOn()`: (DCHECK only) Determines if internal UI checks are enabled.
    * `GetImagesToAnnotate()`:  Identifies images within an update that might need further annotation.
    * `GetOrCreateRemoteRenderAccessibilityHost()`: Gets or creates the interface to communicate with the browser's accessibility service.
    * `HandleInitialFocus()`: Posts a focus notification for the document.
    * `HandleEditableTextContentChanged()`/`HandleDeletionOrInsertionInTextField()`/`HandleEditableTextContentChangedWithCleanLayout()`/`HandleTextFormControlChanged()`: Handles changes to editable text content.
    * `HandleTextMarkerDataAdded()`/`HandleTextMarkerDataAddedWithCleanLayout()`: Handles the addition of text markers (like spellcheck errors).
    * `HandleValueChanged()`: Handles value changes for form controls.
    * `HandleUpdateActiveMenuOption()`/`HandleUpdateMenuListPopupWithCleanLayout()`/`DidShowMenuListPopup()`/`DidHideMenuListPopup()`: Manages updates related to menu lists.
    * `HandleLoadStart()`/`HandleLoadComplete()`: Handles document load events.
    * `HandleScrolledToAnchor()`: Handles scrolling to an anchor.
    * `InvalidateBoundingBox()`: Marks the bounding box of an object as needing an update.
    * `SetCachedBoundingBox()`: Caches the bounding box information.

3. **Identify relationships with web technologies (JavaScript, HTML, CSS):**
    * **HTML:** The code interacts with the DOM (Document Object Model) through `Node` and `Element` objects. Changes in the HTML structure (adding/removing elements, changing attributes) trigger updates in the accessibility tree managed by this code. For example, adding an ARIA attribute like `aria-modal="true"` would be handled by the `UpdateActiveAriaModalDialog` logic.
    * **JavaScript:** JavaScript can manipulate the DOM, triggering accessibility updates. For instance, dynamically changing the text content of an element or focusing a new element would lead to calls to functions like `HandleEditableTextContentChanged` or `HandleFocusedUIElementChanged`.
    * **CSS:** CSS affects the layout and rendering of elements. Changes in CSS that impact the position or visibility of elements trigger bounding box updates (`InvalidateBoundingBox`, `SerializeLocationChanges`). The `MarkElementDirtyWithCleanLayout` functions suggest an awareness of layout status.

4. **Logical Reasoning (Hypothetical Inputs/Outputs):** For functions like `RestoreParentOrPrune`:
    * **Input:** A `Node* child_node` that has been detached from the main DOM.
    * **Scenario 1 (Parent Found):** If the parent of `child_node` is still in the accessibility tree, the function will re-attach the corresponding AX object as a child of the parent's AX object.
    * **Scenario 2 (Parent Not Found):** If the parent is no longer in the accessibility tree, the function will remove the AX object corresponding to `child_node` and its subtree.

5. **Common User/Programming Errors:**
    * **Forgetting to mark elements dirty:** If a developer modifies the DOM in a way that affects accessibility but doesn't trigger the appropriate "dirty" flags, assistive technologies might not receive the updates.
    * **Incorrect ARIA usage:**  Using ARIA attributes incorrectly (e.g., invalid values or applying them to inappropriate elements) can lead to an inaccurate accessibility tree. The code handles some ARIA-specific logic, like for modal dialogs.
    * **Modifying the DOM without considering accessibility:**  Developers might make changes that break the semantic structure of the document, making it harder for assistive technologies to interpret the content.

6. **User Actions as Debugging Clues:** How a user's action leads to this code:
    1. **User interacts with a web page:** For example, the user clicks on a button, focuses on a text field, or the page content dynamically changes due to JavaScript.
    2. **Browser events are triggered:** These user actions or script executions trigger events within the rendering engine (Blink).
    3. **Accessibility notifications:**  Certain events, especially those related to DOM changes, focus, or input, trigger accessibility-related logic.
    4. **Marking objects dirty:** Functions like `MarkElementDirty` are called to indicate that parts of the accessibility tree need to be updated.
    5. **Scheduling updates:**  The `ScheduleAXUpdate` function is called to queue an update process.
    6. **Serialization:**  Functions like `GetUpdatesAndEventsForSerialization` and `SerializeLocationChanges` are involved in packaging the changes.
    7. **Communication with the browser process:** The `GetOrCreateRemoteRenderAccessibilityHost` interface sends the accessibility updates to the browser process, which then communicates with the operating system's accessibility APIs.
    8. **Assistive technologies receive updates:** Finally, assistive technologies like screen readers receive the updated accessibility information.

7. **Synthesize the functionality:** Combine the understanding of individual functions and their interactions to form a concise summary.

8. **Address the "Part 7 of 8" request:** Since this is part of a larger file, the functionality described in this snippet likely focuses on a specific aspect of the overall accessibility management process. Based on the function names, this part appears to be heavily involved in the *serialization and updating* of the accessibility tree, packaging changes to be sent to the browser process.
这是 `AXObjectCacheImpl.cc` 文件的第七部分，主要关注于 **将 Accessibility 树的更改序列化并发送到浏览器进程** 的功能。

以下是该部分功能的详细列举和说明：

**核心功能：序列化和发送 Accessibility 更新**

* **`Reset()` 和 `ResetSerializer()`:**  这两个函数用于重置 Accessibility 缓存和序列化器。`Reset()` 会清除缓存并标记整个树为脏，强制进行完全重新序列化。`ResetSerializer()` 则只重置序列化器相关的状态，并安排一次更新。
    * **与 Javascript/HTML/CSS 的关系:**  当页面的结构、内容或样式发生重大变化，导致需要重建整个 Accessibility 树时，可能会调用这些函数。例如，通过 JavaScript 动态替换了大量的 DOM 节点。
    * **假设输入与输出:**  `Reset()` 没有直接的输入，调用后内部状态被清除，输出是下次序列化时会发送整个树。 `ResetSerializer()` 也没有直接的输入，输出是安排一次全量更新。

* **标记元素为脏 (`MarkElementDirty`, `MarkElementDirtyWithCleanLayout`):** 这些函数用于标记与特定 DOM 元素关联的 AXObject 需要更新。`WithCleanLayout` 版本表示在调用时布局是干净的，可以进行更精细的更新。
    * **与 Javascript/HTML/CSS 的关系:**  当 JavaScript 修改了 DOM 元素的属性、文本内容，或者 CSS 样式导致元素的 Accessibility 属性发生变化时，会调用这些函数。
    * **举例说明:**
        * **HTML:**  用户通过 JavaScript 修改了 `<div>` 元素的 `aria-label` 属性。
        * **JavaScript:**  一个 JavaScript 框架更新了列表项的文本内容。
        * **CSS:**  CSS 伪类改变了元素的可访问性状态（虽然这种情况比较少见，但某些 CSS 属性会影响 Accessibility 树）。
    * **假设输入与输出:** 输入是一个指向 `Node` 的指针。输出是与该 `Node` 关联的 AXObject 被标记为脏，等待下次序列化。

* **文本操作映射 (`GetFromTextOperationInNodeIdMap`, `ClearTextOperationInNodeIdMap`):**  维护一个映射表，用于跟踪文本输入框等元素内的文本操作（插入、删除）。
    * **与 Javascript/HTML/CSS 的关系:**  当用户在 `<textarea>` 或设置了 `contenteditable` 的元素中输入或删除文本时，会记录这些操作。
    * **假设输入与输出:** `GetFromTextOperationInNodeIdMap` 输入一个 AXID，输出是一个指向 `TextChangedOperation` 向量的指针（如果存在）。`ClearTextOperationInNodeIdMap` 没有输入或输出，只是清空内部映射。

* **获取序列化目标 (`GetSerializationTarget`):**  确定给定 AXObject 是否应该被序列化，或者应该序列化它的父对象。主要考虑对象是否在 Accessibility 树中。

* **恢复父对象或剪枝 (`RestoreParentOrPrune`, `RestoreParentOrPruneWithCleanLayout`):**  处理子节点重新连接到 Accessibility 树或被移除的情况。
    * **与 Javascript/HTML/CSS 的关系:**  当 DOM 结构发生变化，导致节点被移动或移除时，会调用这些函数来更新 Accessibility 树的结构。
    * **假设输入与输出:** 输入是一个指向 `Node` 的指针（子节点）。如果能找到合适的父节点，该子节点的 AXObject 会被重新连接，否则会被移除。

* **处理焦点变化 (`HandleFocusedUIElementChanged`):**  当用户界面焦点发生变化时，更新 Accessibility 树并发送相应的事件。
    * **与 Javascript/HTML/CSS 的关系:** 用户通过键盘 Tab 键切换焦点，或者 JavaScript 调用 `focus()` 方法时，会触发此函数。
    * **举例说明:** 用户点击了一个按钮，焦点从之前的元素转移到了该按钮上。
    * **假设输入与输出:** 输入是旧的焦点元素和新的焦点元素。输出是触发 `kNodeLostFocus` 和 `kNodeGainedFocus` 事件。

* **更新 ARIA 模态对话框状态 (`UpdateActiveAriaModalDialog`, `AncestorAriaModalDialog`, `GetActiveAriaModalDialog`):**  处理 ARIA `aria-modal` 属性对 Accessibility 树的影响，例如在模态对话框激活时，屏蔽对话框外的元素。
    * **与 Javascript/HTML/CSS 的关系:**  当页面上使用了 `aria-modal="true"` 的对话框时，这些函数负责更新 Accessibility 树的忽略状态。
    * **假设输入与输出:** `UpdateActiveAriaModalDialog` 输入当前焦点元素，输出是更新 `active_aria_modal_dialog_` 成员变量并可能标记文档为脏。`AncestorAriaModalDialog` 输入一个 `Node`，输出是最近的祖先模态对话框元素（如果有）。`GetActiveAriaModalDialog` 没有输入，输出是当前激活的模态对话框元素。

* **获取用于序列化的位置更改 (`TakeLocationChangsForSerialization`):**  收集自上次序列化以来，元素的位置和滚动偏移的变化。
    * **与 Javascript/HTML/CSS 的关系:** 当页面的布局发生变化，例如元素移动、大小改变或滚动时，会记录这些变化。
    * **假设输入与输出:**  该函数没有直接的输入。输出是一个 `ui::AXLocationAndScrollUpdates` 对象，包含位置和滚动偏移的更改信息。

* **序列化位置更改 (`SerializeLocationChanges`):**  将收集到的位置和滚动偏移变化发送到浏览器进程。为了避免过于频繁的发送，会设置一个延迟。
    * **与 Javascript/HTML/CSS 的关系:**  当用户滚动页面、动画导致元素移动，或者 JavaScript 修改了元素的布局属性时，可能会触发位置更改的序列化。

* **序列化整个树 (`SerializeEntireTree`):**  将整个 Accessibility 树序列化并发送到浏览器进程。这通常在页面加载完成或需要快照时进行。

* **添加脏对象到序列化队列 (`AddDirtyObjectToSerializationQueue`):**  将需要更新的 AXObject 添加到一个队列中，等待批量序列化。
    * **与 Javascript/HTML/CSS 的关系:**  当 DOM 元素或其 Accessibility 属性发生变化时，会调用此函数。

* **可能发送 Canvas 非平凡回退的 UKM 指标 (`MaybeSendCanvasHasNonTrivialFallbackUKM`):**  用于记录 Canvas 元素是否使用了非简单的回退内容，用于性能和使用情况分析。

* **获取用于序列化的更新和事件 (`GetUpdatesAndEventsForSerialization`):**  这是核心函数，负责将所有标记为脏的 AXObject 和待发送的 Accessibility 事件打包成 `ui::AXTreeUpdate` 和 `ui::AXEvent` 向量，准备发送到浏览器进程。
    * **与 Javascript/HTML/CSS 的关系:**  几乎所有与页面可访问性相关的 DOM 操作最终都会通过这个函数进行序列化。
    * **逻辑推理:**
        * **假设输入:** 一系列被标记为脏的 AXObject 和待发送的 Accessibility 事件。
        * **输出:**  `updates` 向量包含 `ui::AXTreeUpdate` 对象，描述了 Accessibility 树的结构和属性变化。`events` 向量包含 `ui::AXEvent` 对象，表示发生的 Accessibility 事件，例如焦点变化、值变化等。

* **更新包含的节点计数 (`UpdateIncludedNodeCount`, `UpdatePluginIncludedNodeCount`):**  （仅在 DCHECK 构建中）跟踪主 Accessibility 树和插件 Accessibility 树中包含的节点数量，用于调试和一致性检查。

* **内部 UI 检查开关 (`IsInternalUICheckerOn`):** （仅在 DCHECK 构建中）判断是否开启了内部 UI 检查器。

* **获取要注释的图像 (`GetImagesToAnnotate`):**  识别 Accessibility 更新中可能需要进一步注释的图像节点，例如用于 AI 辅助的图像描述。

* **获取或创建远程 RenderAccessibilityHost (`GetOrCreateRemoteRenderAccessibilityHost`):**  获取与浏览器进程通信的接口，用于发送 Accessibility 更新。

* **处理初始焦点 (`HandleInitialFocus`):**  在文档加载完成后发送初始的焦点事件。

* **处理可编辑文本内容变化 (`HandleEditableTextContentChanged`, `HandleDeletionOrInsertionInTextField`, `HandleEditableTextContentChangedWithCleanLayout`, `HandleTextFormControlChanged`):**  处理可编辑文本区域的内容变化，例如用户输入或删除文本。
    * **与 Javascript/HTML/CSS 的关系:**  用户在 `<input type="text">`、`<textarea>` 或设置了 `contenteditable` 的元素中进行编辑时会触发这些函数。
    * **假设输入与输出 (`HandleDeletionOrInsertionInTextField`):** 输入是 `SelectionInDOMTree` 对象，描述了文本选择的变化和是否是删除操作。输出是将文本操作信息添加到 `text_operation_in_node_ids_` 映射表中。

* **处理文本标记数据添加 (`HandleTextMarkerDataAdded`, `HandleTextMarkerDataAddedWithCleanLayout`):**  处理拼写检查、语法错误等文本标记的添加。
    * **与 Javascript/HTML/CSS 的关系:**  当浏览器检测到拼写或语法错误时，会添加相应的标记。

* **处理值变化 (`HandleValueChanged`):**  处理表单控件的值发生变化的情况。
    * **与 Javascript/HTML/CSS 的关系:**  用户拖动滑块、选择下拉框选项、或者通过 JavaScript 修改表单控件的值时会触发此函数。

* **处理更新活动菜单选项 (`HandleUpdateActiveMenuOption`):**  处理菜单列表中当前活动选项的更新。

* **处理更新菜单列表弹出框 (`HandleUpdateMenuListPopupWithCleanLayout`, `DidShowMenuListPopup`, `DidHideMenuListPopup`):**  处理菜单列表弹出框的显示和隐藏，以及活动选项的变化。

* **处理加载开始和完成 (`HandleLoadStart`, `HandleLoadComplete`):**  在文档加载开始和完成时发送相应的 Accessibility 事件。

* **处理滚动到锚点 (`HandleScrolledToAnchor`):**  当页面滚动到特定锚点时发送相应的 Accessibility 事件。

* **使边界框失效 (`InvalidateBoundingBox`):**  标记特定布局对象或 AXID 的边界框需要重新计算和序列化。
    * **与 Javascript/HTML/CSS 的关系:**  当元素的位置或大小发生变化时，会调用此函数。

* **设置缓存的边界框 (`SetCachedBoundingBox`):**  缓存 AXID 对应的边界框信息。

**用户或编程常见的使用错误：**

* **忘记标记元素为脏：**  开发者修改了 DOM 结构或属性，但没有调用 `MarkElementDirty` 或相关的函数，导致 Accessibility 树没有及时更新。这会导致辅助技术无法获取最新的信息。
* **不必要的重复标记：**  过度地标记元素为脏，会导致不必要的序列化和性能损耗。
* **在布局未完成时进行操作：**  在布局未完成时调用 `MarkElementDirtyWithCleanLayout` 可能会导致不一致的状态。
* **错误地使用 ARIA 属性：**  不正确地使用 ARIA 属性可能会导致 Accessibility 树的结构和语义错误，误导辅助技术。

**用户操作如何一步步的到达这里（作为调试线索）：**

1. **用户在网页上进行交互：** 例如，点击按钮、输入文本、滚动页面、切换焦点等。
2. **浏览器事件触发：**  用户的交互会触发相应的浏览器事件，例如 `click`、`input`、`scroll`、`focus` 等。
3. **DOM 发生变化：**  事件处理程序可能会修改 DOM 结构、属性或样式。
4. **Accessibility 相关的回调函数被调用：**  Blink 引擎会监听 DOM 的变化，并调用 `AXObjectCacheImpl` 中相应的回调函数，例如 `HandleAttributeChanged`、`DidAdd子树` 等（虽然这些函数不在此代码片段中，但它们是触发后续操作的入口）。
5. **标记元素为脏：**  在回调函数中，会根据 DOM 的变化情况调用 `MarkElementDirty` 或类似的函数。
6. **调度 Accessibility 更新：**  可能会调用 `ScheduleAXUpdate` 来安排一次 Accessibility 树的更新。
7. **序列化更新和事件：**  在适当的时机，`GetUpdatesAndEventsForSerialization` 和 `SerializeLocationChanges` 等函数会被调用，将脏对象和事件序列化为消息。
8. **发送到浏览器进程：**  通过 `GetOrCreateRemoteRenderAccessibilityHost` 获取的接口，将序列化后的消息发送到浏览器进程。

**归纳一下它的功能 (作为第 7 部分)：**

这部分 `AXObjectCacheImpl.cc` 的代码主要负责 **Accessibility 树的增量更新和序列化**。它的核心任务是监听 Blink 渲染引擎中发生的 DOM 变化和其他相关事件，并高效地将这些变化转化为 Accessibility 树的更新信息，最终通过序列化机制发送到浏览器进程，以便浏览器能够将最新的 Accessibility 信息传递给辅助技术。它涉及到标记需要更新的对象、收集位置变化、处理用户交互引起的焦点和内容变化，以及管理序列化过程。 这部分是 Accessibility 功能的核心组成部分，确保了辅助技术能够及时准确地获取网页的最新状态。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_object_cache_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
anged_bounds_ids_.clear();
  cached_bounding_boxes_.clear();

  // Tell the serializer that everything will need to be serialized.
  DCHECK(Root());
  Root()->SetHasDirtyDescendants(true);
  MarkAXSubtreeDirtyWithCleanLayout(Root());
  ChildrenChangedWithCleanLayout(Root());
  // Do not trim out load complete messages, they must be fired.
  if (!load_sent_ && GetDocument().IsLoadCompleted()) {
    PostNotification(&GetDocument(), ax::mojom::blink::Event::kLoadComplete);
  }
}

void AXObjectCacheImpl::ResetSerializer() {
  if (ax_tree_serializer_) {
    ax_tree_serializer_->Reset();
  }
  if (plugin_serializer_.get()) {
    plugin_serializer_->Reset();
  }

  // Clear anything about to be serialized, because everything will be
  // reserialized anyway.
  pending_objects_to_serialize_.clear();
  pending_events_to_serialize_.clear();
  changed_bounds_ids_.clear();
  cached_bounding_boxes_.clear();

  // Send the serialization at the next available opportunity.
  ScheduleAXUpdate();
}

void AXObjectCacheImpl::MarkElementDirty(const Node* element) {
  // Warning, if no AXObject exists for element, nothing is marked dirty.
  MarkAXObjectDirty(Get(element));
}

WTF::Vector<TextChangedOperation>*
AXObjectCacheImpl::GetFromTextOperationInNodeIdMap(AXID id) {
  auto it = text_operation_in_node_ids_.find(id);
  if (it != text_operation_in_node_ids_.end()) {
    return &it.Get()->value;
  }
  return nullptr;
}

void AXObjectCacheImpl::ClearTextOperationInNodeIdMap() {
  text_operation_in_node_ids_.clear();
}

void AXObjectCacheImpl::MarkElementDirtyWithCleanLayout(const Node* element) {
  // Warning, if no AXObject exists for element, nothing is marked dirty.
  MarkAXObjectDirtyWithCleanLayout(Get(element));
}

AXObject* AXObjectCacheImpl::GetSerializationTarget(AXObject* obj) {
  if (!obj || obj->IsDetached() || !obj->GetDocument() ||
      !obj->GetDocument()->View() ||
      !obj->GetDocument()->View()->GetFrame().GetPage()) {
    return nullptr;
  }

  // Return included in tree object.
  if (obj->IsIncludedInTree())
    return obj;

  return obj->ParentObjectIncludedInTree();
}

void AXObjectCacheImpl::RestoreParentOrPrune(Node* child_node) {
  if (lifecycle_.StateAllowsImmediateTreeUpdates()) {
    RestoreParentOrPruneWithCleanLayout(child_node);
  } else {
    DeferTreeUpdate(TreeUpdateReason::kRestoreParentOrPrune, child_node);
  }
}

void AXObjectCacheImpl::RestoreParentOrPruneWithCleanLayout(Node* child_node) {
  AXObject* child = Get(child_node);
  if (child) {
    ChildrenChangedOnAncestorOf(child);
    // The previous call can cause child to become detached.
    if (child->IsDetached()) {
      child = nullptr;
    }
  }

  AXObject* parent = child ? child->ComputeParentOrNull()
                           : AXObject::ComputeNonARIAParent(*this, child_node);
  if (parent && child) {
    child->SetParent(parent);
    ChildrenChangedOnAncestorOf(child);
  } else {
    // If no parent is currently available, the child may no longer be part of
    // the tree. Remove the child's subtree and ask the parent (if any) to
    // rebuild its subtree.
    RemoveSubtree(child_node);
    ChildrenChangedWithCleanLayout(parent);
  }
}

void AXObjectCacheImpl::HandleFocusedUIElementChanged(
    Element* old_focused_element,
    Element* new_focused_element) {
#if DCHECK_IS_ON()
  // The focus can be in a different document when a popup is open.
  SCOPED_DISALLOW_LIFECYCLE_TRANSITION();
#endif  // DCHECK_IS_ON()

  if (validation_message_axid_) {
    DeferTreeUpdate(
        TreeUpdateReason::kRemoveValidationMessageObjectFromFocusedUIElement,
        document_);
  }

  if (!new_focused_element) {
    // When focus is cleared, implicitly focus the document by sending a blur.
    if (GetDocument().documentElement()) {
      DeferTreeUpdate(TreeUpdateReason::kNodeLostFocus,
                      GetDocument().documentElement());
    }
    return;
  }

  Page* page = new_focused_element->GetDocument().GetPage();
  if (!page)
    return;

  new_focused_element = RetargetInput(new_focused_element);
  old_focused_element = RetargetInput(old_focused_element);

  if (old_focused_element) {
    DeferTreeUpdate(TreeUpdateReason::kNodeLostFocus, old_focused_element);
  }

  UpdateActiveAriaModalDialog(new_focused_element);

  DeferTreeUpdate(TreeUpdateReason::kNodeGainedFocus, FocusedNode());
}

// Check if the focused node is inside an active aria-modal dialog. If so, we
// should mark the cache as dirty to recompute the ignored status of each node.
void AXObjectCacheImpl::UpdateActiveAriaModalDialog(Node* focused_node) {
  Settings* settings = GetSettings();
  if (!settings || !settings->GetAriaModalPrunesAXTree()) {
    return;
  }

  Element* new_active_aria_modal = AncestorAriaModalDialog(focused_node);
  if (active_aria_modal_dialog_ == new_active_aria_modal)
    return;

  active_aria_modal_dialog_ = new_active_aria_modal;
  MarkDocumentDirty();
}

Element* AXObjectCacheImpl::AncestorAriaModalDialog(Node* node) {
  // Find an element with role=dialog|alertdialog and aria-modal="true" that
  // either contains the focus, or is focused.
  do {
    Element* element = DynamicTo<Element>(node);
    if (element) {
      const AtomicString& role_str =
          AXObject::AriaAttribute(*element, html_names::kRoleAttr);
      if (!role_str.empty() &&
          ui::IsDialog(AXObject::FirstValidRoleInRoleString(role_str))) {
        if (AXObject::IsAriaAttributeTrue(*element,
                                          html_names::kAriaModalAttr)) {
          return element;
        }
      }
    }
    node = FlatTreeTraversal::Parent(*node);
  } while (node);

  return nullptr;
}

Element* AXObjectCacheImpl::GetActiveAriaModalDialog() const {
  return active_aria_modal_dialog_;
}

ui::AXLocationAndScrollUpdates
AXObjectCacheImpl::TakeLocationChangsForSerialization() {
  CHECK(!changed_bounds_ids_.empty());

  TRACE_EVENT0("accessibility",
               load_sent_ ? "TakeLocationChangsForSerialization"
                          : "TakeLocationChangsForSerializationLoading");
  SCOPED_UMA_HISTOGRAM_TIMER_MICROS(
      "Accessibility.Performance.TakeLocationChangsForSerialization");

  ui::AXLocationAndScrollUpdates changes;

  // Reserve is just an optimization. The actual value doesn't have to be
  // accurate but just an estimate. Assume the changes will always be half and
  // half.
  changes.location_changes.reserve(changed_bounds_ids_.size());
  changes.scroll_changes.reserve(changed_bounds_ids_.size());

  for (AXID changed_bounds_id : changed_bounds_ids_) {
    if (AXObject* obj = ObjectFromAXID(changed_bounds_id)) {
      DCHECK(!obj->IsDetached());
      // Only update locations that are already known.
      auto bounds = cached_bounding_boxes_.find(changed_bounds_id);
      if (bounds == cached_bounding_boxes_.end()) {
        continue;
      }

      ui::AXRelativeBounds new_location;
      bool clips_children;
      obj->PopulateAXRelativeBounds(new_location, &clips_children);
      gfx::Point scroll_offset = obj->GetScrollOffset();

      if (bounds->value.bounds != new_location) {
        changes.location_changes.emplace_back(changed_bounds_id, new_location);
      }

      if (bounds->value.scroll_x != scroll_offset.x() ||
          bounds->value.scroll_y != scroll_offset.y()) {
        changes.scroll_changes.emplace_back(
            changed_bounds_id, scroll_offset.x(), scroll_offset.y());
      }

      cached_bounding_boxes_.Set(
          changed_bounds_id,
          CachedLocationChange(new_location, scroll_offset.x(),
                               scroll_offset.y()));
    }
  }

  changed_bounds_ids_.clear();
  last_location_serialization_time_ =
      base::Time::Now();  // Since this method is non-recoverable, update the
                          // time here and assume this serializtion will arrive.
  return changes;
}

void AXObjectCacheImpl::SerializeLocationChanges() {
  // We wait until the document load is complete because layout often shifts
  // during the load process.
  if (!GetDocument().IsLoadCompleted()) {
    return;
  }

  CHECK(GetDocument().IsActive());
  TRACE_EVENT0("accessibility", load_sent_ ? "SerializeLocationChanges"
                                           : "SerializeLocationChangesLoading");
  SCOPED_UMA_HISTOGRAM_TIMER_MICROS(
      "Accessibility.Performance.SerializeLocationChanges");

  // Ensure enough time has passed since last locations serialization.
  Document& document = GetDocument();
  const auto& now = base::Time::Now();
  const auto& delay_between_serializations =
      base::Milliseconds(GetLocationSerializationDelay());
  const auto& elapsed_since_last_serialization =
      now - last_location_serialization_time_;
  const auto& delay_until_next_serialization =
      delay_between_serializations - elapsed_since_last_serialization;
  if (delay_until_next_serialization.is_positive()) {
    // No serialization needed yet, will serialize after a delay.
    // Set a timer to call this method again, if one isn't already set.
    if (!weak_factory_for_loc_updates_pipeline_.HasWeakCells()) {
      document.GetTaskRunner(blink::TaskType::kInternalDefault)
          ->PostDelayedTask(
              FROM_HERE,
              WTF::BindOnce(
                  &AXObjectCacheImpl::ScheduleAXUpdate,
                  WrapPersistent(
                      weak_factory_for_loc_updates_pipeline_.GetWeakCell())),
              delay_until_next_serialization);
    }
    return;
  }

  weak_factory_for_loc_updates_pipeline_.Invalidate();

  ui::AXLocationAndScrollUpdates changes = TakeLocationChangsForSerialization();

  // Convert to blink mojom type
  ax::mojom::blink::AXLocationAndScrollUpdatesPtr location_and_scroll_changes =
      ax::mojom::blink::AXLocationAndScrollUpdates::New();
  for (auto& item : changes.location_changes) {
    location_and_scroll_changes->location_changes.push_back(
        ax::mojom::blink::AXLocationChange::New(item.id, item.new_location));
  }
  for (auto& item : changes.scroll_changes) {
    location_and_scroll_changes->scroll_changes.push_back(
        ax::mojom::blink::AXScrollChange::New(item.id, item.scroll_x,
                                              item.scroll_y));
  }

  if (!location_and_scroll_changes->location_changes.empty() ||
      !location_and_scroll_changes->scroll_changes.empty()) {
    CHECK(reset_token_);
    GetOrCreateRemoteRenderAccessibilityHost()->HandleAXLocationChanges(
        std::move(location_and_scroll_changes), *reset_token_);
  }
}

bool AXObjectCacheImpl::SerializeEntireTree(
    size_t max_node_count,
    base::TimeDelta timeout,
    ui::AXTreeUpdate* response,
    std::set<ui::AXSerializationErrorFlag>* out_error) {
  // Ensure that an initial tree exists.
  CHECK(IsFrozen());
  CHECK(!IsDirty());
  CHECK(Root());
  CHECK(!Root()->IsDetached());
  CHECK(GetDocument().IsActive());

  BlinkAXTreeSource* tree_source =
      BlinkAXTreeSource::Create(*this, /* is_snapshot */ true);
  // The new tree source is frozen for its entire lifetime.
  tree_source->Freeze();

  // The serializer returns an ui::AXTreeUpdate, which can store a complete
  // or a partial accessibility tree. AXTreeSerializer is stateful, but the
  // first time you serialize from a brand-new tree you're guaranteed to get a
  // complete tree.
  ui::AXTreeSerializer<const AXObject*, HeapVector<Member<const AXObject>>,
                       ui::AXTreeUpdate*, ui::AXTreeData*, ui::AXNodeData>
      serializer(tree_source);

  if (max_node_count)
    serializer.set_max_node_count(max_node_count);
  if (!timeout.is_zero())
    serializer.set_timeout(timeout);

  bool success = serializer.SerializeChanges(Root(), response, out_error);
  CHECK(success)
      << "Serializer failed. Should have hit DCHECK inside of serializer.";

  if (RuntimeEnabledFeatures::AccessibilitySerializationSizeMetricsEnabled()) {
    // For a tree snapshot, we don't break down by type.
    UMA_HISTOGRAM_CUSTOM_COUNTS(
        "Accessibility.Performance.AXObjectCacheImpl.Snapshot",
        base::saturated_cast<int>(response->ByteSize()), 1, kSizeGb,
        kBucketCount);
  }

  return true;
}

void AXObjectCacheImpl::AddDirtyObjectToSerializationQueue(
    const AXObject* obj,
    ax::mojom::blink::EventFrom event_from,
    ax::mojom::blink::Action event_from_action,
    const std::vector<ui::AXEventIntent>& event_intents) {
  CHECK(!IsFrozen());
  CHECK(lifecycle_.StateAllowsQueueingAXObjectsForSerialization()) << *this;

  // If not included, cannot be serialized, so there is no need to queue.
  if (!obj->IsIncludedInTree()) {
    return;
  }

  // Add to object to a queue that will be sent to the serializer in
  // SerializeDirtyObjectsAndEvents().
  pending_objects_to_serialize_.push_back(
      AXDirtyObject::Create(obj, event_from, event_from_action, event_intents));

  // ensure there is a document lifecycle update scheduled for plugin
  // containers.
  if (obj->GetElement() && DynamicTo<HTMLPlugInElement>(obj->GetElement())) {
    ScheduleImmediateSerialization();
  }
}

void AXObjectCacheImpl::MaybeSendCanvasHasNonTrivialFallbackUKM(
    const AXObject* ax_canvas) {
  if (!ax_canvas->ChildCountIncludingIgnored()) {
    // Canvas does not have fallback.
    return;
  }

  if (ax_canvas->ChildCountIncludingIgnored() == 1 &&
      ui::IsText(ax_canvas->FirstChildIncludingIgnored()->RoleValue())) {
    // Ignore a fallback if it's just a single piece of text, as we are
    // looking for advanced uses of canvas fallbacks.
    return;
  }

  HTMLCanvasElement* canvas = To<HTMLCanvasElement>(ax_canvas->GetNode());
  if (!canvas->HasPlacedElements()) {
    // If it has placed elements, then the descendents are not a fallback.
    return;
  }

  has_emitted_canvas_fallback_ukm_ = true;  // Stop checking.

  ukm::UkmRecorder* ukm_recorder = GetDocument().UkmRecorder();
  DCHECK(ukm_recorder);
  ukm::builders::Accessibility_CanvasHasNonTrivialFallback(
      GetDocument().UkmSourceID())
      .SetSeen(true)
      .Record(ukm_recorder);
}

void AXObjectCacheImpl::GetUpdatesAndEventsForSerialization(
    std::vector<ui::AXTreeUpdate>& updates,
    std::vector<ui::AXEvent>& events,
    bool& had_end_of_test_event,
    bool& had_load_complete_messages) {
  HashSet<int32_t> already_serialized_ids;

  DCHECK_GE(GetDocument().Lifecycle().GetState(),
            DocumentLifecycle::kLayoutClean);
  DCHECK(!popup_document_ || popup_document_->Lifecycle().GetState() >=
                                 DocumentLifecycle::kLayoutClean);
  DUMP_WILL_BE_CHECK(HasObjectsPendingSerialization());

  DCHECK_GE(pending_objects_to_serialize_.size(),
            pending_events_to_serialize_.size())
      << "There should be at least as many updates as events, because events "
         "always mark a node dirty.";

  EnsureSerializer();

  if (plugin_tree_source_ && IsDirty()) {
    // If the document is dirty, ensure the plugin serializer is reset.
    CHECK(plugin_serializer_.get());
    plugin_serializer_->Reset();
  }
  ui::AXNodeData::AXNodeDataSize node_data_size;
  for (auto& current_dirty_object : pending_objects_to_serialize_) {
    const AXObject* obj = current_dirty_object->obj;

    // Dirty objects can be added using MarkWebAXObjectDirty(obj) from other
    // parts of the code as well, so we need to ensure the object still
    // exists.
    if (!obj || obj->IsDetached()) {
      continue;
    }

    DCHECK(obj->GetDocument()->GetFrame())
        << "An object in a closed document should have been detached via "
           "Remove(): "
        << obj;

    // Cannot serialize unincluded object.
    // Only included objects are marked dirty, but this can happen if the
    // object becomes unincluded after it was originally marked dirty, in which
    // cas a children changed will also be fired on the included ancestor. The
    // children changed event on the ancestor means that attempting to
    // serialize this unincluded object is not necessary.
    if (!obj->IsIncludedInTree())
      continue;

    DCHECK(obj->AXObjectID());

    if (already_serialized_ids.Contains(obj->AXObjectID()))
      continue;  // No need to serialize, was already present.

    updates.emplace_back();
    ui::AXTreeUpdate& update = updates.back();
    update.event_from = current_dirty_object->event_from;
    update.event_from_action = current_dirty_object->event_from_action;
    update.event_intents = std::move(current_dirty_object->event_intents);

    bool success = ax_tree_serializer_->SerializeChanges(obj, &update);

    DCHECK(success);
    DCHECK_GT(update.nodes.size(), 0U);

    for (auto& node_data : update.nodes) {
      AXID id = node_data.id;
      DCHECK(id);
      // Kept here for convenient debugging:
      // DVLOG(1) << "*** AX Serialize: " << ObjectFromAXID(id)->ToString();
      already_serialized_ids.insert(node_data.id);

      // Now that the bounding box for this node is serialized, we can clear the
      // node from changed_bounds_ids_ to avoid sending it in
      // SerializeLocationChanges() later.
      changed_bounds_ids_.erase(id);

      // Record advanced uses of canvas fallbacks.
      if (!has_emitted_canvas_fallback_ukm_ &&
          node_data.role == ax::mojom::blink::Role::kCanvas) {
        MaybeSendCanvasHasNonTrivialFallbackUKM(ObjectFromAXID(node_data.id));
      }
    }

    DCHECK(already_serialized_ids.Contains(obj->AXObjectID()))
        << "Did not serialize original node, so it was probably not included "
           "in its parent's children, and should never have been marked dirty "
           "in the first place: "
        << obj->ToString()
        << "\nParent: " << obj->ParentObjectIncludedInTree()
        << "\nIndex in parent: "
        << obj->ParentObjectIncludedInTree()
               ->CachedChildrenIncludingIgnored()
               .Find(obj);

    // If there's a plugin, force the tree data to be generated in every
    // message so the plugin can merge its own tree data changes.
    AddPluginTreeToUpdate(&update);

    if (RuntimeEnabledFeatures::
            AccessibilitySerializationSizeMetricsEnabled()) {
      update.AccumulateSize(node_data_size);
    }
  }

  if (RuntimeEnabledFeatures::AccessibilitySerializationSizeMetricsEnabled()) {
    LogNodeDataSizeDistribution(node_data_size);
    UMA_HISTOGRAM_CUSTOM_COUNTS(
        "Accessibility.Performance.AXObjectCacheImpl.Incremental",
        base::saturated_cast<int>(node_data_size.ByteSize()), 1, kSizeGb,
        kBucketCount);
  }

  // Loop over each event and generate an updated event message.
  for (ui::AXEvent& event : pending_events_to_serialize_) {
    if (event.event_type == ax::mojom::blink::Event::kEndOfTest) {
      had_end_of_test_event = true;
      continue;
    }

    if (!base::Contains(already_serialized_ids, event.id)) {
      // Node no longer exists or could not be serialized.
      // Kept here for convenient debugging:
      // DVLOG(1) << "Dropped AXEvent: " << event.event_type << " on "
      //          << ObjectFromAXID(event.id);
      continue;
    }

#if DCHECK_IS_ON()
    AXObject* obj = ObjectFromAXID(event.id);
    DCHECK(obj && !obj->IsDetached())
        << "Detached object for AXEvent: " << event.event_type << " on #"
        << event.id;
#endif

    if (event.event_type == ax::mojom::blink::Event::kLoadComplete) {
      if (had_load_complete_messages)
        continue;  // De-dupe.
      had_load_complete_messages = true;
    }

    events.push_back(event);

    // Kept here for convenient debugging:
    // DVLOG(1) << "AXEvent: " << event.event_type << " on "
    //          << ObjectFromAXID(event.id);
  }

#if DCHECK_IS_ON()
  // Always compute this state.
  UpdatePluginIncludedNodeCount();

  CheckTreeConsistency(*this, *ax_tree_serializer_, plugin_serializer_.get());

  // Provide the expected node count in the last update, so that
  // AXTree::Unserialize() can check for tree consistency on the browser side.
  if (!updates.back().tree_checks) {
    updates.back().tree_checks.emplace();
  }
  updates.back().tree_checks->node_count =
      GetIncludedNodeCount() + GetPluginIncludedNodeCount();
#endif  // DCHECK_IS_ON()
}

#if DCHECK_IS_ON()
void AXObjectCacheImpl::UpdateIncludedNodeCount(const AXObject* obj) {
  if (obj->IsIncludedInTree()) {
    ++included_node_count_;
  } else {
    --included_node_count_;
  }
}

void AXObjectCacheImpl::UpdatePluginIncludedNodeCount() {
  plugin_included_node_count_ = 0;

  // If the serializer is empty, it means we cleared it at some point e.g. when
  // detaching the embed. In those cases, it's correct to skip computing the
  // count from the plugin tree source which has no idea it was detached.
  if (!plugin_serializer_.get() ||
      plugin_serializer_->ClientTreeNodeCount() == 0) {
    return;
  }

  if (plugin_tree_source_ && plugin_tree_source_->GetRoot()) {
    std::stack<const ui::AXNode*> nodes;
    nodes.push(plugin_tree_source_->GetRoot());
    while (!nodes.empty()) {
      const ui::AXNode* child = nodes.top();
      nodes.pop();
      plugin_included_node_count_++;
      for (size_t i = 0; i < plugin_tree_source_->GetChildCount(child); i++) {
        nodes.push(plugin_tree_source_->ChildAt(child, i));
      }
    }
  }
}

bool AXObjectCacheImpl::IsInternalUICheckerOn(const AXObject& obj) const {
  if (internal_ui_checker_on_) {
    return true;
  }
  // Also turn on for nodes that are inside of a UA shadow root, which is
  // used for complex form controls built into the browser.
  return obj.GetNode() && obj.GetNode()->IsInUserAgentShadowRoot();
}
#endif  // DCHECK_IS_ON()

void AXObjectCacheImpl::GetImagesToAnnotate(
    ui::AXTreeUpdate& update,
    std::vector<ui::AXNodeData*>& nodes) {
  for (auto& node : update.nodes) {
    AXObject* src = ObjectFromAXID(node.id);
    if (!src || src->IsDetached() || !src->IsIncludedInTree() ||
        (src->IsIgnored() &&
         !node.HasState(ax::mojom::blink::State::kFocusable))) {
      continue;
    }

    if (src->IsImage()) {
      nodes.push_back(&node);
      // This else clause matches links/documents because we would like to find
      // an image that is in the near-descendant subtree of the link/document,
      // since that image may be semantically representative of that
      // link/document. See FindExactlyOneInnerImageInMaxDepthThree (not in
      // this file), which is used by the caller of this method to find such
      // an image.
    } else if ((src->IsLink() || ui::IsPlatformDocument(node.role)) &&
               node.GetNameFrom() != ax::mojom::blink::NameFrom::kAttribute) {
      nodes.push_back(&node);
    }
  }
}

HeapMojoRemote<blink::mojom::blink::RenderAccessibilityHost>&
AXObjectCacheImpl::GetOrCreateRemoteRenderAccessibilityHost() {
  if (!render_accessibility_host_) {
    GetDocument().GetFrame()->GetBrowserInterfaceBroker().GetInterface(
        render_accessibility_host_.BindNewPipeAndPassReceiver(
            document_->GetTaskRunner(TaskType::kUserInteraction)));
  }
  return render_accessibility_host_;
}

void AXObjectCacheImpl::HandleInitialFocus() {
  PostNotification(document_, ax::mojom::Event::kFocus);
}

void AXObjectCacheImpl::HandleEditableTextContentChanged(Node* node) {
  if (!node)
    return;

  SCOPED_DISALLOW_LIFECYCLE_TRANSITION();

  DeferTreeUpdate(TreeUpdateReason::kEditableTextContentChanged, node);
}

void AXObjectCacheImpl::HandleDeletionOrInsertionInTextField(
    const SelectionInDOMTree& changed_selection,
    bool is_deletion) {
  Position start_pos = changed_selection.ComputeStartPosition();
  Position end_pos = changed_selection.ComputeEndPosition();

#if DCHECK_IS_ON()
  Document& selection_document =
      start_pos.ComputeContainerNode()->GetDocument();
  DCHECK(selection_document.Lifecycle().GetState() >=
         DocumentLifecycle::kAfterPerformLayout)
      << "Unclean document at lifecycle "
      << selection_document.Lifecycle().ToString();
#endif

  // Currently there are scenarios where the start/end are not offset in
  // anchor, if this is the case, we need to compute their offset in the
  // container node since we need this information on the browser side.
  int start_offset = start_pos.ComputeOffsetInContainerNode();
  int end_offset = end_pos.ComputeOffsetInContainerNode();

  AXObject* start_obj = Get(start_pos.ComputeContainerNode());
  AXObject* end_obj = Get(end_pos.ComputeContainerNode());
  if (!start_obj || !end_obj) {
    return;
  }

  AXObject* text_field_obj = start_obj->GetTextFieldAncestor();
  if (!text_field_obj) {
    return;
  }

  auto it = text_operation_in_node_ids_.find(text_field_obj->AXObjectID());
  ax::mojom::blink::Command op = is_deletion
                                     ? ax::mojom::blink::Command::kDelete
                                     : ax::mojom::blink::Command::kInsert;
  if (it != text_operation_in_node_ids_.end()) {
    it->value.push_back(TextChangedOperation(start_offset, end_offset,
                                             start_obj->AXObjectID(),
                                             end_obj->AXObjectID(), op));
  } else {
    WTF::Vector<TextChangedOperation> info{
        TextChangedOperation(start_offset, end_offset, start_obj->AXObjectID(),
                             end_obj->AXObjectID(), op)};
    text_operation_in_node_ids_.Set(text_field_obj->AXObjectID(), info);
  }
}

void AXObjectCacheImpl::HandleEditableTextContentChangedWithCleanLayout(
    Node* node) {
  AXObject* obj = Get(node);
  if (obj) {
    obj = obj->GetTextFieldAncestor();
  }

  PostNotification(obj, ax::mojom::Event::kValueChanged);
}

void AXObjectCacheImpl::HandleTextFormControlChanged(Node* node) {
  HandleEditableTextContentChanged(node);
}

void AXObjectCacheImpl::HandleTextMarkerDataAdded(Node* start, Node* end) {
  DCHECK(start);
  DCHECK(end);
  DCHECK(IsA<Text>(start));
  DCHECK(IsA<Text>(end));

  // Notify the client of new text marker data.
  // Ensure there is a delay so that the final marker state can be evaluated.
  DeferTreeUpdate(TreeUpdateReason::kTextMarkerDataAdded, start);
  if (start != end) {
    DeferTreeUpdate(TreeUpdateReason::kTextMarkerDataAdded, end);
  }
}

void AXObjectCacheImpl::HandleTextMarkerDataAddedWithCleanLayout(Node* node) {
  Text* text_node = To<Text>(node);
  // If non-spelling/grammar markers are present, assume that children changed
  // should be called.
  DocumentMarkerController& marker_controller = GetDocument().Markers();
  const DocumentMarker::MarkerTypes non_spelling_or_grammar_markers(
      DocumentMarker::kTextMatch | DocumentMarker::kActiveSuggestion |
      DocumentMarker::kSuggestion | DocumentMarker::kTextFragment |
      DocumentMarker::kCustomHighlight);
  if (!marker_controller.MarkersFor(*text_node, non_spelling_or_grammar_markers)
           .empty()) {
    ChildrenChangedWithCleanLayout(node);
    return;
  }

  // Spelling and grammar markers are removed and then readded in quick
  // succession. By checking these here (on a slight delay), we can determine
  // whether the presence of one of these markers actually changed, and only
  // fire ChildrenChangedWithCleanLayout() if they did.
  const DocumentMarker::MarkerTypes spelling_and_grammar_markers(
      DocumentMarker::DocumentMarker::kSpelling |
      DocumentMarker::DocumentMarker::kGrammar);
  bool has_spelling_or_grammar_markers =
      !marker_controller.MarkersFor(*text_node, spelling_and_grammar_markers)
           .empty();
  if (has_spelling_or_grammar_markers) {
    if (nodes_with_spelling_or_grammar_markers_.insert(node->GetDomNodeId())
            .is_new_entry) {
      ChildrenChangedWithCleanLayout(node);
    }
  } else {
    const auto& iter =
        nodes_with_spelling_or_grammar_markers_.find(node->GetDomNodeId());
    if (iter != nodes_with_spelling_or_grammar_markers_.end()) {
      nodes_with_spelling_or_grammar_markers_.erase(iter);
      ChildrenChangedWithCleanLayout(node);
    }
  }
}

void AXObjectCacheImpl::HandleValueChanged(Node* node) {
  // Avoid duplicate processing of rapid value changes, e.g. on a slider being
  // dragged, or a progress meter.
  AXObject* ax_object = Get(node);
  if (ax_object) {
    if (last_value_change_node_ == ax_object->AXObjectID())
      return;
    last_value_change_node_ = ax_object->AXObjectID();
  }

  PostNotification(node, ax::mojom::Event::kValueChanged);

  // If it's a slider, invalidate the thumb's bounding box.
  if (ax_object && ax_object->RoleValue() == ax::mojom::blink::Role::kSlider &&
      !ax_object->NeedsToUpdateChildren() &&
      ax_object->ChildCountIncludingIgnored() == 1) {
    InvalidateBoundingBox(ax_object->ChildAtIncludingIgnored(0)->AXObjectID());
  }
}

void AXObjectCacheImpl::HandleUpdateActiveMenuOption(Node* menu_list) {
  DeferTreeUpdate(TreeUpdateReason::kUpdateActiveMenuOption, menu_list);
}

void AXObjectCacheImpl::HandleUpdateMenuListPopupWithCleanLayout(
    Node* menu_list,
    bool did_show) {
  AXObject* ax_menu_list = Get(menu_list);
  if (!ax_menu_list) {
    return;
  }
  AXObject* ax_popup = ax_menu_list->FirstChildIncludingIgnored();
  if (!ax_popup ||
      ax_popup->RoleValue() != ax::mojom::blink::Role::kMenuListPopup) {
    last_selected_from_active_descendant_ = nullptr;
    return;
  }
  AXObject* active_descendant = ax_popup->ActiveDescendant();
  if (did_show) {
    // On first appearance, mark everything dirty, because the hidden state
    // will change on most descendants.
    MarkAXSubtreeDirtyWithCleanLayout(ax_menu_list);
  } else {
    // Mark the previously selected item dirty so that its updated selection
    // state is reserialized.
    if (last_selected_from_active_descendant_) {
      MarkElementDirtyWithCleanLayout(last_selected_from_active_descendant_);
    }
  }
  if (active_descendant) {
    MarkAXObjectDirtyWithCleanLayout(active_descendant);
    PostNotification(ax_popup,
                     ax::mojom::blink::Event::kActiveDescendantChanged);
    last_selected_from_active_descendant_ = active_descendant->GetNode();
  }
}

void AXObjectCacheImpl::DidShowMenuListPopup(Node* menu_list) {
  SCOPED_DISALLOW_LIFECYCLE_TRANSITION();
  CHECK(menu_list);
  DeferTreeUpdate(TreeUpdateReason::kDidShowMenuListPopup, menu_list);
}

void AXObjectCacheImpl::DidHideMenuListPopup(Node* menu_list) {
  SCOPED_DISALLOW_LIFECYCLE_TRANSITION();
  CHECK(menu_list);
  current_menu_list_axid_ = 0;
  options_bounds_ = {};
  MarkAXSubtreeDirty(Get(menu_list));
}

void AXObjectCacheImpl::HandleLoadStart(Document* document) {
  SCOPED_DISALLOW_LIFECYCLE_TRANSITION();
  // Popups do not need to fire load start or load complete , because ATs do not
  // regard popups as documents -- that is an implementation detail of the
  // browser. The AT regards popups as part of a widget, and a load start or
  // load complete event would only potentially confuse the AT.
  if (!IsPopup(*document) && !IsInitialEmptyDocument(*document)) {
    DeferTreeUpdate(TreeUpdateReason::kPostNotificationFromHandleLoadStart,
                    document, ax::mojom::blink::Event::kLoadStart);
  }
}

void AXObjectCacheImpl::HandleLoadComplete(Document* document) {
  SCOPED_DISALLOW_LIFECYCLE_TRANSITION();

  // TODO(accessibility) Change this to a DCHECK, but that would fail right now
  // in navigation API tests.
  if (!document->IsLoadCompleted())
    return;

  // Popups do not need to fire load start or load complete , because ATs do not
  // regard popups as documents -- that is an implementation detail of the
  // browser. The AT regards popups as part of a widget, and a load start or
  // load complete event would only potentially confuse the AT.
  if (!IsPopup(*document) && !IsInitialEmptyDocument(*document)) {
    DeferTreeUpdate(TreeUpdateReason::kPostNotificationFromHandleLoadComplete,
                    document, ax::mojom::blink::Event::kLoadComplete);
  }
}

void AXObjectCacheImpl::HandleScrolledToAnchor(const Node* anchor_node) {
  if (!anchor_node)
    return;

  DeferTreeUpdate(TreeUpdateReason::kPostNotificationFromHandleScrolledToAnchor,
                  const_cast<Node*>(anchor_node),
                  ax::mojom::blink::Event::kScrolledToAnchor);
}

void AXObjectCacheImpl::InvalidateBoundingBox(
    const LayoutObject* layout_object) {
  if (AXObject* obj = Get(const_cast<LayoutObject*>(layout_object))) {
    InvalidateBoundingBox(obj->AXObjectID());
  }
}

void AXObjectCacheImpl::InvalidateBoundingBox(const AXID& id) {
  changed_bounds_ids_.insert(id);
}

void AXObjectCacheImpl::SetCachedBoundingBox(AXID id,
                                             const ui::AXRelativeBounds& bounds,
                                             const int scroll_x,
                                             const int scroll_y) {
  // When a bounding box of a node is serial
```