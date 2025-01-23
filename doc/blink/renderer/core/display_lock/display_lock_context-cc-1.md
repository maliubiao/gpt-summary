Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. They also want to know about relationships to web technologies (JavaScript, HTML, CSS), examples of logic, and potential user/programming errors.

Here's a breakdown of how to address each part:

1. **Overall Functionality:** Analyze the code, focusing on the methods and their interactions. Identify the main purpose and key actions performed by the `DisplayLockContext` class.

2. **Relationship to Web Technologies:** Consider how the actions in the C++ code relate to concepts in JavaScript, HTML, and CSS. Think about how changes in the C++ code might manifest in the behavior of a web page.

3. **Logic Examples:**  Look for conditional statements and state changes within the code. Formulate hypothetical scenarios with inputs and expected outputs based on the logic.

4. **Common Errors:** Identify situations where incorrect usage or assumptions could lead to problems. Consider the responsibilities of developers interacting with this kind of system.

5. **Summary:**  Synthesize the findings from the previous steps into a concise description of the `DisplayLockContext`'s role.

**Mental Walkthrough of the Code:**

* **`RequiresContext()`:**  This seems to check conditions that necessitate a `TreeBuilderContext`. It's related to the rendering pipeline and likely optimization.
* **`DidMoveToNewDocument()`:** Handles the transfer of a `DisplayLockContext` when an element moves between documents. This involves updating document state and lifecycle listeners.
* **`WillStartLifecycleUpdate()`:** This is a core method triggered at the start of a rendering lifecycle. It handles deferred actions, updates states based on various conditions (like being nested or unlocked temporarily), and potentially updates lifecycle notification registrations.
* **`DidFinishLayout()` and `SetAnchorPositioningRenderStateMayHaveChanged()`:** These deal with anchor positioning and updating lifecycle notifications related to it.
* **`NotifyWillDisconnect()` and `ElementDisconnected()`/`ElementConnected()`:**  These methods handle the lifecycle of the element the `DisplayLockContext` is associated with, including unlocking and managing related state.
* **`DetachLayoutTree()`:** Handles the scenario when the element's layout tree is removed.
* **`ScheduleTopLayerCheck()` and `ScheduleAnimation()`:**  These methods trigger updates and animations, likely related to the visibility and rendering of the locked content.
* **`ShouldForceUnlock()`:**  A crucial method that determines if a lock should be forcibly removed based on CSS properties like `contain` and `display`.
* **`ForceUnlockIfNeeded()`:**  Calls `ShouldForceUnlock()` and performs the unlock if necessary.
* **`ConnectedToView()`:** A simple check for whether the associated element is connected to the rendering view.
* **Focus/Selection related methods (`NotifySubtreeLostFocus()`, `NotifySubtreeGainedFocus()`, `DetermineIfSubtreeHasFocus()`, `NotifySubtreeGainedSelection()`, `NotifySubtreeLostSelection()`, `DetermineIfSubtreeHasSelection()`):** These manage the state of focus and selection within the subtree of the locked element.
* **Top Layer related methods (`DetermineIfSubtreeHasTopLayerElement()`, `ClearHasTopLayerElement()`, `NotifyHasTopLayerElement()`, `SubtreeHasTopLayerElement()`, `DetachDescendantTopLayerElements()`):**  These deal with elements in the top layer (like dialogs or fullscreen elements) and how they interact with display locking.
* **View Transition related methods (`DetermineIfDescendantIsViewTransitionElement()`, `ResetDescendantIsViewTransitionElement()`, `SetDescendantIsViewTransitionElement()`):** These handle the interaction of display locks with view transitions.
* **`SetRenderAffectingState()` and `NotifyRenderAffectingStateChanged()`:** These are the core mechanisms for managing the internal state of the display lock and triggering lock/unlock actions based on various factors.
* **Anchor Positioning related methods (`DescendantIsAnchorTargetFromOutsideDisplayLock()`, `SetAffectedByAnchorPositioning()`):** Handle the impact of anchor positioning on display locks.
* **Scroll Offset methods (`StashScrollOffsetIfAvailable()`, `RestoreScrollOffsetIfStashed()`, `HasStashedScrollOffset()`):** Manage saving and restoring scroll positions for locked elements.
* **`ActivatableDisplayLocksForced()`:**  Checks if activatable locks are forced (likely for testing or specific scenarios).
* **Tracing (`Trace()`):**  Used for debugging and memory management.
* **Debug information (`RenderAffectingStateName()`, `RenderAffectingStateToString()`):** Provides human-readable information about the internal state.

By going through each method and considering its purpose and interaction with other methods, the overall functionality becomes clearer. The relationship to web technologies emerges from understanding how these C++ concepts control the rendering and behavior of elements defined by HTML, styled by CSS, and potentially interacted with by JavaScript.
这个部分的代码主要集中在 `DisplayLockContext` 实例生命周期内的状态管理和与渲染流程的交互。以下是功能的归纳：

**核心功能：维护和更新 `DisplayLockContext` 的内部状态，以决定是否应该锁定与该上下文关联的元素。**

具体来说，这个部分的代码负责：

1. **响应文档变化：**
   - **`DidMoveToNewDocument(Document& old_document)`:**  当元素被移动到新的文档时，更新 `DisplayLockContext` 的文档引用，并将其从旧文档的 `DisplayLockDocumentState` 中移除，添加到新文档的 `DisplayLockDocumentState` 中。这包括更新观察者注册和锁定状态。

   **与 JavaScript/HTML 关系：** 当 JavaScript 操作 DOM 将一个带有 `content-visibility: auto` 并且可能被 `display: none until-found` 或通过 `requestAnimationFrame` 等方式管理的元素从一个文档移动到另一个文档时，此函数会被调用。

2. **处理渲染生命周期事件：**
   - **`WillStartLifecycleUpdate(const LocalFrameView& view)`:** 在渲染生命周期开始时执行一些延迟的操作，例如处理 Intersection Observer 的通知，并根据 `keep_unlocked_count_` 决定是否解锁。同时也会检查是否有待处理的子树状态检查（焦点、选择、顶层元素）。
   - **`DidFinishLayout()`:** 在布局完成后，检查是否与锚点定位相关的渲染状态可能发生了变化，并更新生命周期通知的注册。
   - **`SetAnchorPositioningRenderStateMayHaveChanged()`:**  标记锚点定位相关的渲染状态可能发生了变化，并触发生命周期通知更新。

   **与 CSS 关系：**  CSS 的渲染属性（如 `content-visibility` 和锚点定位相关的属性）的变化会触发布局和渲染生命周期事件，从而影响此函数的执行。

3. **处理元素的连接和断开：**
   - **`NotifyWillDisconnect()`:** 在元素即将断开连接时，如果元素处于锁定状态，则请求父元素进行布局，以确保父元素的 `IsSelfCollapsingBlock` 属性是最新的。
   - **`ElementDisconnected()`:** 当元素断开连接时，将其请求状态设置为可见（解锁），并清除与子元素重算相关的状态。
   - **`ElementConnected()`:** 当元素连接到 DOM 时，标记需要进行子树状态检查（焦点、选择），并安排动画以触发生命周期更新。
   - **`DetachLayoutTree()`:** 当元素的布局树被移除时，将其请求状态设置为可见（解锁）。

   **与 JavaScript/HTML 关系：**  通过 JavaScript 的 DOM 操作（如 `appendChild`, `removeChild`）连接和断开元素会触发这些函数。

4. **触发更新和动画：**
   - **`ScheduleTopLayerCheck()`:**  标记需要检查子树中是否有顶层元素，并安排动画。
   - **`ScheduleAnimation()`:**  安排一个视觉更新，以执行渲染生命周期的各个阶段。

   **与 JavaScript 关系：** JavaScript 可以通过修改 DOM 或触发动画来间接地影响这些函数的调用。

5. **强制解锁机制：**
   - **`ShouldForceUnlock() const`:**  检查元素是否满足锁定所需的条件（例如，是否设置了 `contain: style layout`，并且不是 `display: contents`）。如果不满足，则返回一个原因字符串。
   - **`ForceUnlockIfNeeded()`:** 调用 `ShouldForceUnlock()`，如果需要强制解锁，则执行解锁操作，并设置请求状态为可见，防止在下一帧之前再次锁定。

   **与 CSS 关系：**  CSS 的 `contain` 属性和 `display` 属性直接影响此函数的判断。

   **假设输入与输出：**
   - **假设输入：** 一个元素的 CSS 属性为 `content-visibility: auto; contain: none;` 并且尝试锁定它。
   - **输出：** `ShouldForceUnlock()` 将返回 `"ContainmentNotSatisfied"`，`ForceUnlockIfNeeded()` 将返回 `true` 并执行解锁操作。

6. **管理子树状态：**
   - **焦点状态：** `NotifySubtreeLostFocus()`, `NotifySubtreeGainedFocus()`, `DetermineIfSubtreeHasFocus()` 用于跟踪子树是否获得焦点。
   - **顶层元素状态：** `DetermineIfSubtreeHasTopLayerElement()`, `ClearHasTopLayerElement()`, `NotifyHasTopLayerElement()`, `SubtreeHasTopLayerElement()`, `DetachDescendantTopLayerElements()` 用于管理子树中是否存在顶层元素（例如，对话框、全屏元素）。
   - **选择状态：** `NotifySubtreeGainedSelection()`, `NotifySubtreeLostSelection()`, `DetermineIfSubtreeHasSelection()` 用于跟踪子树中是否有文本被选中。
   - **视图过渡元素状态：** `DetermineIfDescendantIsViewTransitionElement()`, `ResetDescendantIsViewTransitionElement()`, `SetDescendantIsViewTransitionElement()` 用于跟踪子树中是否存在视图过渡元素。

   **与 JavaScript/HTML 关系：**  用户的交互（例如，点击输入框获得焦点，选择文本）或者 JavaScript 操作（例如，展示一个对话框）会影响这些状态。

7. **管理渲染影响状态：**
   - **`SetRenderAffectingState(RenderAffectingState state, bool new_flag)`:**  设置影响渲染的状态标志，并根据状态变化调用 `NotifyRenderAffectingStateChanged()`。
   - **`NotifyRenderAffectingStateChanged()`:**  根据当前的影响渲染的状态，决定是否应该锁定或解锁元素。

   **逻辑推理与假设输入输出：**
   - **假设输入：** `render_affecting_state_[RenderAffectingState::kLockRequested]` 为 `true`，且 `state_` 为 `EContentVisibility::kAuto`，并且以下所有状态都为 `false`: `kIntersectsViewport`, `kSubtreeHasFocus`, `kSubtreeHasSelection`, `kAutoStateUnlockedUntilLifecycle`, `kAutoUnlockedForPrint`, `kSubtreeHasTopLayerElement`, `kDescendantIsViewTransitionElement`, `kDescendantIsAnchorTarget`。
   - **输出：** `NotifyRenderAffectingStateChanged()` 将调用 `Lock()` 方法。

8. **处理锚点定位：**
   - **`DescendantIsAnchorTargetFromOutsideDisplayLock()`:**  检查是否存在布局在当前 `DisplayLockContext` 元素之外的、定位方式为 `out-of-flow` 的后代元素，其锚点目标位于此 `DisplayLockContext` 元素之内。
   - **`SetAffectedByAnchorPositioning(bool val)`:** 设置是否受到锚点定位的影响。

   **与 CSS 关系：**  CSS 的锚点定位属性会影响此函数的判断。

9. **存储和恢复滚动偏移：**
   - **`StashScrollOffsetIfAvailable()`:**  如果元素是可滚动的，则存储当前的滚动偏移。
   - **`RestoreScrollOffsetIfStashed()`:** 如果存储了滚动偏移，则恢复它。
   - **`HasStashedScrollOffset() const`:**  检查是否存储了滚动偏移。

   **与 JavaScript 关系：**  JavaScript 可以通过滚动操作影响滚动偏移，此功能用于在锁定和解锁时保持滚动位置。

10. **调试和追踪：**
    - **`Trace(Visitor* visitor) const`:**  用于内存管理和调试，允许追踪 `DisplayLockContext` 的引用。
    - **`RenderAffectingStateName(int state) const` 和 `RenderAffectingStateToString() const`:**  提供人类可读的渲染影响状态信息，用于调试。

**用户或编程常见的使用错误示例：**

- **错误地假设锁定的元素始终会阻止布局和渲染：**  如果锁定的元素内部有顶层元素（如 `<dialog>`），或者受到外部锚点定位的影响，锁定行为可能会有所不同。
- **在元素不满足锁定条件时尝试锁定：** 例如，尝试锁定一个 `contain` 属性没有设置为 `style layout` 的元素，或者 `display` 属性为 `contents` 的元素。`ShouldForceUnlock()` 方法会检测到这些情况，并强制解锁。
- **在元素连接或断开连接时假设某些状态是稳定的：** 例如，在 `ElementDisconnected()` 中假设可以安全地访问子元素的布局对象，这可能导致崩溃或未定义的行为。
- **在嵌套锁定的场景中对状态更新的顺序或影响理解不正确：** 嵌套的 display locks 可能会导致状态更新的延迟或相互影响。

**总结：**

`DisplayLockContext` 的这部分代码负责管理与 `content-visibility: auto` 元素相关的锁定和解锁行为。它监听文档和元素的生命周期事件，检查影响渲染的各种状态（如焦点、选择、顶层元素、锚点定位），并根据这些状态决定是否应该锁定元素以优化渲染性能。如果元素不满足锁定的前提条件，它还会提供强制解锁的机制。这部分代码是 Blink 渲染引擎中实现 `content-visibility` 功能的关键组成部分。

### 提示词
```
这是目录为blink/renderer/core/display_lock/display_lock_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
PrePaintTreeWalk::ObjectRequiresTreeBuilderContext(*layout_object) ||
           needs_prepaint_subtree_walk_ ||
           needs_effective_allowed_touch_action_update_ ||
           needs_blocking_wheel_event_handler_update_;
  }
  return false;
}

void DisplayLockContext::DidMoveToNewDocument(Document& old_document) {
  DCHECK(element_);
  document_ = &element_->GetDocument();

  old_document.GetDisplayLockDocumentState().RemoveDisplayLockContext(this);
  document_->GetDisplayLockDocumentState().AddDisplayLockContext(this);

  if (is_observed_) {
    old_document.GetDisplayLockDocumentState()
        .UnregisterDisplayLockActivationObservation(element_);
    document_->GetDisplayLockDocumentState()
        .RegisterDisplayLockActivationObservation(element_);
  }

  // Since we're observing the lifecycle updates, ensure that we listen to the
  // right document's view.
  if (is_registered_for_lifecycle_notifications_) {
    if (old_document.View())
      old_document.View()->UnregisterFromLifecycleNotifications(this);

    if (document_->View())
      document_->View()->RegisterForLifecycleNotifications(this);
    else
      is_registered_for_lifecycle_notifications_ = false;
  }

  if (IsLocked()) {
    old_document.GetDisplayLockDocumentState().RemoveLockedDisplayLock();
    document_->GetDisplayLockDocumentState().AddLockedDisplayLock();
    if (!IsActivatable(DisplayLockActivationReason::kAny)) {
      old_document.GetDisplayLockDocumentState()
          .DecrementDisplayLockBlockingAllActivation();
      document_->GetDisplayLockDocumentState()
          .IncrementDisplayLockBlockingAllActivation();
    }
  }

  DetermineIfSubtreeHasFocus();
  DetermineIfSubtreeHasSelection();
  DetermineIfSubtreeHasTopLayerElement();
  DetermineIfDescendantIsViewTransitionElement();
}

void DisplayLockContext::WillStartLifecycleUpdate(const LocalFrameView& view) {
  DCHECK(NeedsLifecycleNotifications());
  // We might have delayed processing intersection observation update (signal
  // that we were not intersecting) because this context was nested in another
  // locked context. At the start of the lifecycle, we should check whether
  // that is still true. In other words, this call will check if we're still
  // nested. If we are, we won't do anything. If we're not, then we will lock
  // this context.
  //
  // Note that when we are no longer nested and and we have not received any
  // notifications from the intersection observer, it means that we are not
  // visible.
  if (needs_deferred_not_intersecting_signal_)
    NotifyIsNotIntersectingViewport();

  bool update_registration = false;

  // If we're keeping this context unlocked, update the values.
  if (keep_unlocked_count_) {
    if (--keep_unlocked_count_) {
      ScheduleAnimation();
    } else {
      SetRenderAffectingState(
          RenderAffectingState::kAutoStateUnlockedUntilLifecycle, false);
      update_registration = true;
    }
  } else {
    DCHECK(!render_affecting_state_[static_cast<int>(
        RenderAffectingState::kAutoStateUnlockedUntilLifecycle)]);
  }

  if (has_pending_subtree_checks_ || has_pending_top_layer_check_) {
    DetermineIfSubtreeHasTopLayerElement();
    has_pending_top_layer_check_ = false;
    update_registration = true;
  }

  if (has_pending_subtree_checks_) {
    DetermineIfSubtreeHasFocus();
    DetermineIfSubtreeHasSelection();

    has_pending_subtree_checks_ = false;
    update_registration = true;
  }

  if (has_pending_clear_has_top_layer_) {
    SetRenderAffectingState(RenderAffectingState::kSubtreeHasTopLayerElement,
                            false);
    has_pending_clear_has_top_layer_ = false;
    update_registration = true;
  }

  if (update_registration)
    UpdateLifecycleNotificationRegistration();
}

void DisplayLockContext::DidFinishLayout() {
  if (!anchor_positioning_render_state_may_have_changed_) {
    return;
  }
  anchor_positioning_render_state_may_have_changed_ = false;
  UpdateLifecycleNotificationRegistration();
  if (DescendantIsAnchorTargetFromOutsideDisplayLock()) {
    SetAffectedByAnchorPositioning(true);
  } else {
    SetAffectedByAnchorPositioning(false);
  }
}

void DisplayLockContext::SetAnchorPositioningRenderStateMayHaveChanged() {
  if (anchor_positioning_render_state_may_have_changed_) {
    return;
  }
  anchor_positioning_render_state_may_have_changed_ = true;
  UpdateLifecycleNotificationRegistration();
}

void DisplayLockContext::NotifyWillDisconnect() {
  if (!IsLocked() || !element_ || !element_->GetLayoutObject())
    return;
  // If we're locked while being disconnected, we need to layout the parent.
  // The reason for this is that we might skip the layout if we're empty while
  // locked, but it's important to update IsSelfCollapsingBlock property on
  // the parent so that it's up to date. This property is updated during
  // layout.
  if (auto* parent = element_->GetLayoutObject()->Parent())
    parent->SetNeedsLayout(layout_invalidation_reason::kDisplayLock);
}

void DisplayLockContext::ElementDisconnected() {
  // We remove the style when disconnecting an element, so we should also unlock
  // the context.
  DCHECK(!element_->GetComputedStyle());
  SetRequestedState(EContentVisibility::kVisible);

  if (auto* document_rules =
          DocumentSpeculationRules::FromIfExists(*document_)) {
    document_rules->DisplayLockedElementDisconnected(element_);
  }

  // blocked_child_recalc_change_ must be cleared because things can be in an
  // inconsistent state when we add the element back (e.g. crbug.com/1262742).
  blocked_child_recalc_change_ = StyleRecalcChange();
}

void DisplayLockContext::ElementConnected() {
  // When connecting the element, we should not have a style.
  DCHECK(!element_->GetComputedStyle());

  // We can't check for subtree selection / focus here, since we are likely in
  // slot reassignment forbidden scope. However, walking the subtree may need
  // this reassignment. This is fine, since the state check can be deferred
  // until the beginning of the next frame.
  has_pending_subtree_checks_ = true;
  UpdateLifecycleNotificationRegistration();
  ScheduleAnimation();
}

void DisplayLockContext::DetachLayoutTree() {
  // When |element_| is removed from the flat tree, we need to set this context
  // to visible.
  if (!element_->GetComputedStyle()) {
    SetRequestedState(EContentVisibility::kVisible);
    blocked_child_recalc_change_ = StyleRecalcChange();
  }
}

void DisplayLockContext::ScheduleTopLayerCheck() {
  has_pending_top_layer_check_ = true;
  UpdateLifecycleNotificationRegistration();
  ScheduleAnimation();
}

void DisplayLockContext::ScheduleAnimation() {
  DCHECK(element_);
  if (!ConnectedToView() || !document_ || !document_->GetPage())
    return;

  // Schedule an animation to perform the lifecycle phases.
  document_->GetPage()->Animator().ScheduleVisualUpdate(document_->GetFrame());
}

const char* DisplayLockContext::ShouldForceUnlock() const {
  DCHECK(element_);
  // This function is only called after style, layout tree, or lifecycle
  // updates, so the style should be up-to-date, except in the case of nested
  // locks, where the style recalc will never actually get to |element_|.
  // TODO(vmpstr): We need to figure out what to do here, since we don't know
  // what the style is and whether this element has proper containment. However,
  // forcing an update from the ancestor locks seems inefficient. For now, we
  // just optimistically assume that we have all of the right containment in
  // place. See crbug.com/926276 for more information.
  if (element_->NeedsStyleRecalc()) {
    DCHECK(DisplayLockUtilities::LockedAncestorPreventingStyle(*element_));
    return nullptr;
  }

  if (element_->HasDisplayContentsStyle())
    return rejection_names::kUnsupportedDisplay;

  auto* style = element_->GetComputedStyle();
  DCHECK(style);

  // We need style and layout containment in order to properly lock the subtree.
  if (!style->ContainsStyle() || !style->ContainsLayout())
    return rejection_names::kContainmentNotSatisfied;

  // We allow replaced elements without fallback content to be locked. This
  // check is similar to the check in DefinitelyNewFormattingContext() in
  // element.cc, but in this case we allow object element to get locked.
  if (const auto* object_element = DynamicTo<HTMLObjectElement>(*element_)) {
    if (!object_element->UseFallbackContent())
      return nullptr;
  } else if (IsA<HTMLImageElement>(*element_) ||
             IsA<HTMLCanvasElement>(*element_) ||
             (element_->IsFormControlElement() &&
              !element_->IsOutputElement()) ||
             element_->IsMediaElement() || element_->IsFrameOwnerElement() ||
             element_->IsSVGElement()) {
    return nullptr;
  }

  // From https://www.w3.org/TR/css-contain-1/#containment-layout
  // If the element does not generate a principal box (as is the case with
  // display: contents or display: none), or if the element is an internal
  // table element other than display: table-cell, if the element is an
  // internal ruby element, or if the element’s principal box is a
  // non-atomic inline-level box, layout containment has no effect.
  // (Note we're allowing display:none for display locked elements).
  if ((style->IsDisplayTableType() &&
       style->Display() != EDisplay::kTableCell) ||
      style->Display() == EDisplay::kRubyText ||
      (style->IsDisplayInlineType() && !style->IsDisplayReplacedType())) {
    return rejection_names::kContainmentNotSatisfied;
  }
  return nullptr;
}

bool DisplayLockContext::ForceUnlockIfNeeded() {
  // We must have "contain: style layout", and disallow display:contents
  // for display locking. Note that we should always guarantee this after
  // every style or layout tree update. Otherwise, proceeding with layout may
  // cause unexpected behavior. By rejecting the promise, the behavior can be
  // detected by script.
  // TODO(rakina): If this is after acquire's promise is resolved and update()
  // commit() isn't in progress, the web author won't know that the element
  // got unlocked. Figure out how to notify the author.
  if (ShouldForceUnlock()) {
    if (IsLocked()) {
      Unlock();
      // If we forced unlock, then we need to prevent subsequent calls to
      // Lock() until the next frame.
      SetRequestedState(EContentVisibility::kVisible);
    }
    return true;
  }
  return false;
}

bool DisplayLockContext::ConnectedToView() const {
  return element_ && document_ && element_->isConnected() && document_->View();
}

void DisplayLockContext::NotifySubtreeLostFocus() {
  SetRenderAffectingState(RenderAffectingState::kSubtreeHasFocus, false);
}

void DisplayLockContext::NotifySubtreeGainedFocus() {
  SetRenderAffectingState(RenderAffectingState::kSubtreeHasFocus, true);
}

void DisplayLockContext::DetermineIfSubtreeHasFocus() {
  if (!ConnectedToView()) {
    SetRenderAffectingState(RenderAffectingState::kSubtreeHasFocus, false);
    return;
  }

  bool subtree_has_focus = false;
  // Iterate up the ancestor chain from the currently focused element. If at any
  // time we find our element, then our subtree is focused.
  for (auto* focused = document_->FocusedElement(); focused;
       focused = FlatTreeTraversal::ParentElement(*focused)) {
    if (focused == element_.Get()) {
      subtree_has_focus = true;
      break;
    }
  }
  SetRenderAffectingState(RenderAffectingState::kSubtreeHasFocus,
                          subtree_has_focus);
}

void DisplayLockContext::DetermineIfSubtreeHasTopLayerElement() {
  if (!ConnectedToView())
    return;

  ClearHasTopLayerElement();

  // Iterate up the ancestor chain from each top layer element.
  // Note that this walk is searching for just the |element_| associated with
  // this lock. The walk in DisplayLockDocumentState walks from top layer
  // elements all the way to the ancestors searching for display locks, so if we
  // have nested display locks that walk is more optimal.
  for (auto top_layer_element : document_->TopLayerElements()) {
    auto* ancestor = top_layer_element.Get();
    while ((ancestor = FlatTreeTraversal::ParentElement(*ancestor))) {
      if (ancestor == element_) {
        NotifyHasTopLayerElement();
        return;
      }
    }
  }
}

void DisplayLockContext::DetermineIfDescendantIsViewTransitionElement() {
  ResetDescendantIsViewTransitionElement();
  if (ConnectedToView()) {
    document_->GetDisplayLockDocumentState()
        .UpdateViewTransitionElementAncestorLocks();
  }
}

void DisplayLockContext::ResetDescendantIsViewTransitionElement() {
  SetRenderAffectingState(
      RenderAffectingState::kDescendantIsViewTransitionElement, false);
}

void DisplayLockContext::SetDescendantIsViewTransitionElement() {
  SetRenderAffectingState(
      RenderAffectingState::kDescendantIsViewTransitionElement, true);
}

void DisplayLockContext::ClearHasTopLayerElement() {
  // Note that this is asynchronous because it can happen during a layout detach
  // which is a bad time to relock a content-visibility auto element (since it
  // causes us to potentially access layout objects which are in a state of
  // being destroyed).
  has_pending_clear_has_top_layer_ = true;
  UpdateLifecycleNotificationRegistration();
  ScheduleAnimation();
}

void DisplayLockContext::NotifyHasTopLayerElement() {
  has_pending_clear_has_top_layer_ = false;
  SetRenderAffectingState(RenderAffectingState::kSubtreeHasTopLayerElement,
                          true);
  UpdateLifecycleNotificationRegistration();
}

bool DisplayLockContext::SubtreeHasTopLayerElement() const {
  return render_affecting_state_[static_cast<int>(
      RenderAffectingState::kSubtreeHasTopLayerElement)];
}

void DisplayLockContext::DetachDescendantTopLayerElements() {
  if (!ConnectedToView() || !SubtreeHasTopLayerElement())
    return;

  std::optional<StyleEngine::DetachLayoutTreeScope> detach_scope;
  if (!document_->InStyleRecalc()) {
    detach_scope.emplace(document_->GetStyleEngine());
  }

  // Detach all top layer elements contained by the element inducing this
  // display lock.
  // Detaching a layout tree can cause further top layer elements to be removed
  // from the top layer element's list (in a nested top layer element case --
  // since we would remove the ::backdrop pseudo when the layout object
  // disappears). This means that we're potentially modifying the list as we're
  // traversing it. Instead of doing that, make a copy.
  auto top_layer_elements = document_->TopLayerElements();
  for (auto top_layer_element : top_layer_elements) {
    auto* ancestor = top_layer_element.Get();
    while ((ancestor = FlatTreeTraversal::ParentElement(*ancestor))) {
      if (ancestor == element_) {
        top_layer_element->DetachLayoutTree();
        break;
      }
    }
  }
}

void DisplayLockContext::NotifySubtreeGainedSelection() {
  SetRenderAffectingState(RenderAffectingState::kSubtreeHasSelection, true);
}

void DisplayLockContext::NotifySubtreeLostSelection() {
  SetRenderAffectingState(RenderAffectingState::kSubtreeHasSelection, false);
}

void DisplayLockContext::DetermineIfSubtreeHasSelection() {
  if (!ConnectedToView() || !document_->GetFrame()) {
    SetRenderAffectingState(RenderAffectingState::kSubtreeHasSelection, false);
    return;
  }

  auto range = ToEphemeralRangeInFlatTree(document_->GetFrame()
                                              ->Selection()
                                              .GetSelectionInDOMTree()
                                              .ComputeRange());
  bool subtree_has_selection = false;
  for (auto& node : range.Nodes()) {
    for (auto& ancestor : FlatTreeTraversal::InclusiveAncestorsOf(node)) {
      if (&ancestor == element_.Get()) {
        subtree_has_selection = true;
        break;
      }
    }
    if (subtree_has_selection)
      break;
  }
  SetRenderAffectingState(RenderAffectingState::kSubtreeHasSelection,
                          subtree_has_selection);
}

void DisplayLockContext::SetRenderAffectingState(RenderAffectingState state,
                                                 bool new_flag) {
  // If we have forced activatable locks, it is possible that we're within
  // find-in-page. We cannot lock an object while doing this, since it may
  // invalidate layout and in turn prevent find-in-page from properly finding
  // text (and DCHECK). Since layout is clean for this lock (we're unlocked),
  // keep the context unlocked until the next lifecycle starts.
  if (state == RenderAffectingState::kSubtreeHasSelection && !new_flag &&
      document_->GetDisplayLockDocumentState()
          .ActivatableDisplayLocksForced()) {
    SetKeepUnlockedUntilLifecycleCount(1);
  }
  // If we are changing state due to disappeared anchors, we're in a post-layout
  // state and therefore can't dirty style. Wait until the next lifecycle
  // starts.
  if (state == RenderAffectingState::kDescendantIsAnchorTarget && !new_flag) {
    SetKeepUnlockedUntilLifecycleCount(1);
  }

  render_affecting_state_[static_cast<int>(state)] = new_flag;
  NotifyRenderAffectingStateChanged();
}

void DisplayLockContext::NotifyRenderAffectingStateChanged() {
  auto state = [this](RenderAffectingState state) {
    return render_affecting_state_[static_cast<int>(state)];
  };

  // Check that we're visible if and only if lock has not been requested.
  DCHECK_EQ(state_ == EContentVisibility::kVisible,
            !state(RenderAffectingState::kLockRequested));

  // We should be locked if the lock has been requested (the above DCHECKs
  // verify that this means that we are not 'visible'), and any of the
  // following is true:
  // - We are not in 'auto' mode (meaning 'hidden') or
  // - We are in 'auto' mode and nothing blocks locking: viewport is
  //   not intersecting, subtree doesn't have focus, and subtree doesn't have
  //   selection, etc. See the condition for the full list.
  bool should_be_locked =
      state(RenderAffectingState::kLockRequested) &&
      (state_ != EContentVisibility::kAuto ||
       (!state(RenderAffectingState::kIntersectsViewport) &&
        !state(RenderAffectingState::kSubtreeHasFocus) &&
        !state(RenderAffectingState::kSubtreeHasSelection) &&
        !state(RenderAffectingState::kAutoStateUnlockedUntilLifecycle) &&
        !state(RenderAffectingState::kAutoUnlockedForPrint) &&
        !state(RenderAffectingState::kSubtreeHasTopLayerElement) &&
        !state(RenderAffectingState::kDescendantIsViewTransitionElement) &&
        !state(RenderAffectingState::kDescendantIsAnchorTarget)));

  if (should_be_locked && !IsLocked())
    Lock();
  else if (!should_be_locked && IsLocked())
    Unlock();
}

bool DisplayLockContext::DescendantIsAnchorTargetFromOutsideDisplayLock() {
  for (auto* obj = element_->GetLayoutObject(); obj; obj = obj->Container()) {
    if (const auto* ancestor_box = DynamicTo<LayoutBox>(obj)) {
      // Return true if any out-of-flow positioned elements below this
      // ancestor are anchored to elements below the display lock.
      for (const PhysicalBoxFragment& fragment :
           ancestor_box->PhysicalFragments()) {
        // Early out if there are no anchor targets in the subtree.
        if (!fragment.HasAnchorQuery()) {
          return false;
        }
        // Early out if there are not OOF children.
        if (!fragment.HasOutOfFlowFragmentChild()) {
          continue;
        }
        for (const PhysicalFragmentLink& fragment_child : fragment.Children()) {
          // Skip non-OOF children.
          if (!fragment_child->IsOutOfFlowPositioned()) {
            continue;
          }
          if (auto* box = DynamicTo<LayoutBox>(
                  fragment_child->GetMutableLayoutObject())) {
            if (auto* display_locks = box->DisplayLocksAffectedByAnchors()) {
              if (display_locks->find(element_) != display_locks->end()) {
                return true;
              }
            }
          }
        }
      }
    }
  }
  return false;
}

void DisplayLockContext::Trace(Visitor* visitor) const {
  visitor->Trace(element_);
  visitor->Trace(document_);
  ElementRareDataField::Trace(visitor);
}

void DisplayLockContext::SetShouldUnlockAutoForPrint(bool flag) {
  SetRenderAffectingState(RenderAffectingState::kAutoUnlockedForPrint, flag);
}

const char* DisplayLockContext::RenderAffectingStateName(int state) const {
  switch (static_cast<RenderAffectingState>(state)) {
    case RenderAffectingState::kLockRequested:
      return "LockRequested";
    case RenderAffectingState::kIntersectsViewport:
      return "IntersectsViewport";
    case RenderAffectingState::kSubtreeHasFocus:
      return "SubtreeHasFocus";
    case RenderAffectingState::kSubtreeHasSelection:
      return "SubtreeHasSelection";
    case RenderAffectingState::kAutoStateUnlockedUntilLifecycle:
      return "AutoStateUnlockedUntilLifecycle";
    case RenderAffectingState::kAutoUnlockedForPrint:
      return "AutoUnlockedForPrint";
    case RenderAffectingState::kSubtreeHasTopLayerElement:
      return "SubtreeHasTopLayerElement";
    case RenderAffectingState::kDescendantIsViewTransitionElement:
      return "DescendantIsViewTransitionElement";
    case RenderAffectingState::kDescendantIsAnchorTarget:
      return "kDescendantIsAnchorTarget";
    case RenderAffectingState::kNumRenderAffectingStates:
      break;
  }
  return "<Invalid State>";
}

String DisplayLockContext::RenderAffectingStateToString() const {
  StringBuilder builder;
  for (int i = 0;
       i < static_cast<int>(RenderAffectingState::kNumRenderAffectingStates);
       ++i) {
    builder.Append(RenderAffectingStateName(i));
    builder.Append(": ");
    builder.Append(render_affecting_state_[i] ? "true" : "false");
    builder.Append("\n");
  }
  return builder.ToString();
}

void DisplayLockContext::StashScrollOffsetIfAvailable() {
  if (auto* area = GetScrollableArea(element_)) {
    const ScrollOffset& offset = area->GetScrollOffset();
    // Only store the offset if it's non-zero. This is because scroll
    // restoration has a small performance implication and restoring to a zero
    // offset is the same as not restoring it.
    if (!offset.IsZero()) {
      stashed_scroll_offset_.emplace(offset);
    }
  }
}

void DisplayLockContext::RestoreScrollOffsetIfStashed() {
  if (!stashed_scroll_offset_.has_value()) {
    return;
  }

  // Restore the offset and reset the value.
  if (auto* area = GetScrollableArea(element_)) {
    area->SetScrollOffset(*stashed_scroll_offset_,
                          mojom::blink::ScrollType::kAnchoring);
    stashed_scroll_offset_.reset();
  }
}

bool DisplayLockContext::HasStashedScrollOffset() const {
  return stashed_scroll_offset_.has_value();
}

bool DisplayLockContext::ActivatableDisplayLocksForced() const {
  return document_->GetDisplayLockDocumentState()
      .ActivatableDisplayLocksForced();
}

void DisplayLockContext::SetAffectedByAnchorPositioning(bool val) {
  SetRenderAffectingState(RenderAffectingState::kDescendantIsAnchorTarget, val);
}

}  // namespace blink
```