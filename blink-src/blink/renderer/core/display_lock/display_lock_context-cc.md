Response:
My thinking process to analyze the provided C++ code snippet and generate the summary involves these steps:

1. **Identify the Core Purpose:** I first look for the main class being defined and the overall goal hinted at by its name and included files. "DisplayLockContext" and the included headers like `display_lock_document_state.h`, `content_visibility_auto_state_change_event.h` strongly suggest a mechanism for controlling the visibility and rendering of elements. The "lock" terminology reinforces this idea of pausing or preventing rendering updates.

2. **Deconstruct Functionality by Examining Methods:** I then go through the public and significant private methods, grouping them by their apparent function. I look for keywords and patterns:
    * **State Management:** `SetRequestedState`, `IsLocked`, `RequestLock`, `RequestUnlock` clearly manage the locked/unlocked state.
    * **Style Adjustment:** `AdjustElementStyle` suggests modifying how the element is styled based on its lock state. The mention of `skipsContents` is a key detail.
    * **Activation/Deactivation:** `CommitForActivation`, `ShouldCommitForActivation`, `UpdateActivationMask`, `UpdateActivationObservationIfNeeded` relate to triggering the display of locked content based on certain conditions.
    * **Lifecycle Management:** The `DidStyleSelf`, `DidStyleChildren`, `DidLayoutChildren`, and related `Should*` methods point to integration with Blink's rendering lifecycle. This is where I start connecting the C++ to the browser's rendering process.
    * **Viewport Intersection:** `NotifyIsIntersectingViewport`, `NotifyIsNotIntersectingViewport` indicate interaction with the browser's visibility detection. This is crucial for understanding the "auto" state.
    * **Forced Updates:** `UpgradeForcedScope`, `NotifyForcedUpdateScopeEnded` suggest a way to temporarily bypass the locking mechanism for debugging or specific scenarios.
    * **Event Dispatching:** `ScheduleStateChangeEventIfNeeded`, `DispatchStateChangeEventIfNeeded` link the internal state to observable events.
    * **Dirty Flag Management:** The `MarkFor*IfNeeded` methods are crucial for understanding how changes in the lock state trigger re-rendering (style, layout, paint).
    * **Top Layer Handling:** `DetermineIfSubtreeHasTopLayerElement`, `DetachDescendantTopLayerElements` points to specific logic for elements in the top layer (like dialogs).

3. **Relate to Web Technologies (JavaScript, HTML, CSS):**  With an understanding of the core functions, I start connecting them to web technologies:
    * **CSS:** The `content-visibility` CSS property is explicitly mentioned and linked to the different states (`auto`, `hidden`, `visible`). The `AdjustElementStyle` method directly manipulates how CSS is applied.
    * **JavaScript:**  The `contentvisibilityautostatechange` event is a clear JavaScript API. The ability to "force" updates might be related to developer tools or internal APIs accessible via JavaScript.
    * **HTML:** The examples of `<img>`, `<canvas>`, `<object>` elements and the interaction with scrolling, focus, and selection tie the functionality to specific HTML elements and user interactions.

4. **Identify Logic and Assumptions (Input/Output):** For specific methods or logical blocks, I try to infer the input and output. For example:
    * `SetRequestedState(kHidden)` ->  Likely sets internal flags to prevent rendering and might trigger a `contentvisibilityautostatechange` event.
    * `NotifyIsIntersectingViewport()` when `state_ == kAuto` -> Could lead to unlocking the element.

5. **Consider Potential User/Programming Errors:**  I think about how developers might misuse the `content-visibility` property or related APIs:
    * Incorrectly assuming immediate visual updates after changing the property.
    * Over-reliance on `content-visibility: auto` without understanding its implications for initial rendering.
    * Potential performance issues if used excessively or on large parts of the page.
    * The warning about forced rendering hints at a potential misuse scenario.

6. **Structure the Summary:** Finally, I organize my findings into logical sections:
    * **Core Function:**  A concise statement of the main purpose.
    * **Key Features:**  A bulleted list of the main capabilities.
    * **Relationship to Web Technologies:** Specific examples of how it interacts with JavaScript, HTML, and CSS.
    * **Logical Inference (Input/Output):** Concrete examples of how different inputs affect the behavior.
    * **Potential Usage Errors:** Common mistakes developers might make.

7. **Refine and Iterate:** I review my summary, ensuring it's accurate, comprehensive, and easy to understand. I might re-read parts of the code or the generated summary to ensure consistency and clarity. For instance, I might initially just say "handles rendering" but then refine it to "controls whether an element's content is rendered and painted."

This iterative process of code examination, functional decomposition, connection to web technologies, and consideration of usage scenarios allows me to generate a detailed and insightful summary of the given C++ source code.
这是提供的 Chromium Blink 引擎源代码文件 `blink/renderer/core/display_lock/display_lock_context.cc` 的第一部分，共两部分。 根据你提供的代码，我可以归纳出以下功能：

**核心功能：控制元素的渲染和绘制行为，特别是与 CSS 属性 `content-visibility` 相关的功能。**

更详细的功能分解如下：

* **管理 `content-visibility` 属性的状态:**
    * 可以设置元素的期望 `content-visibility` 状态 (`kVisible`, `kAuto`, `kHidden`)。
    * 跟踪元素的当前锁定状态 (`is_locked_`)。
    * 根据状态变化请求锁定或解锁元素的渲染。
* **影响元素的样式计算:**
    * `AdjustElementStyle` 方法根据元素的锁定状态调整其计算样式。当元素被锁定时，可以设置 `skipsContents` 为 true，跳过子元素的渲染。
* **控制渲染更新的激活:**
    * 使用激活掩码 (`activatable_mask_`) 来决定元素在哪些条件下可以被激活（解锁并渲染）。
    * 提供 `RequestLock` 和 `RequestUnlock` 方法来显式地请求锁定或解锁。
    * `CommitForActivation` 方法在特定情况下（如无障碍功能、页面内查找、片段导航等）提交激活，可能会临时解锁元素。
* **监听视口交叉状态 (对于 `content-visibility: auto`):**
    * 当 `content-visibility` 为 `auto` 时，会监听元素是否与视口交叉。
    * `NotifyIsIntersectingViewport` 和 `NotifyIsNotIntersectingViewport` 方法处理视口交叉状态的变化，并可能触发元素的解锁或重新锁定。
    * 可以延迟处理未交叉视口的通知，例如当元素嵌套在另一个锁定的元素内时。
* **处理渲染生命周期事件:**
    * 通过 `DidStyleSelf`, `DidStyleChildren`, `DidLayoutChildren` 等方法介入 Blink 的渲染生命周期。
    * 在样式计算后检查是否需要强制解锁。
    * 在布局子元素后，可以恢复之前存储的滚动偏移。
* **处理强制更新 (Forced Updates):**
    * 提供了 `UpgradeForcedScope` 和 `NotifyForcedUpdateScopeEnded` 方法来管理强制渲染更新的范围，允许在锁定的元素内部进行渲染更新。
* **触发 `contentvisibilityautostatechange` 事件:**
    * 当 `content-visibility` 为 `auto` 且元素的锁定状态发生变化时，会调度并触发 `contentvisibilityautostatechange` DOM 事件。
* **处理顶级图层元素:**
    * 可以检测子树中是否存在顶级图层元素（例如，使用 `<dialog>` 标签创建的元素）。
    * 当元素被锁定时，会分离子树中的顶级图层元素的布局对象。
    * 解锁时，可能需要更精细地标记样式重算的脏位以处理顶级图层元素。
* **处理滚动偏移:**
    * 如果元素是滚动容器，可以在锁定时存储其滚动偏移，并在解锁且子元素布局完成后恢复。
* **标记需要更新的渲染阶段:**
    * 提供了 `MarkForStyleRecalcIfNeeded`, `MarkForLayoutIfNeeded`, `MarkAncestorsForPrePaintIfNeeded`, `MarkNeedsRepaintAndPaintArtifactCompositorUpdate`, `MarkNeedsCullRectUpdate` 等方法来标记元素及其祖先需要进行样式重算、布局、预绘制和重绘等操作。
* **管理文档级别的 DisplayLock 状态:**
    * 与 `DisplayLockDocumentState` 类交互，跟踪文档中锁定的 DisplayLockContext 数量。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS `content-visibility` 属性:** `DisplayLockContext` 的核心功能是实现 `content-visibility` 属性的行为。
    * **HTML:** `<div style="content-visibility: auto;">...</div>`  这个 HTML 元素会创建一个 `DisplayLockContext` 对象。
    * **CSS:** `content-visibility: hidden;` 会导致调用 `SetRequestedState(EContentVisibility::kHidden)`。
    * **JavaScript:**  当 `content-visibility: auto` 的元素的锁定状态改变时，会触发 `contentvisibilityautostatechange` 事件，JavaScript 可以监听这个事件来执行相应的操作。
        ```javascript
        const element = document.querySelector('div');
        element.addEventListener('contentvisibilityautostatechange', (event) => {
          console.log('Content visibility state changed:', event.detail.skipped);
        });
        ```

* **样式调整 (`AdjustElementStyle`):** 当元素被锁定（例如，`content-visibility: hidden` 或 `content-visibility: auto` 且不在视口内），`AdjustElementStyle` 可以修改元素的样式，例如设置 `skipsContents: true`，这会影响 CSS 渲染流程，跳过子元素的样式计算和渲染。

* **强制更新:**  虽然代码中没有直接的 JavaScript API 暴露强制更新，但在 Chromium 的开发者工具或其他内部机制中，可能会使用到强制更新来调试或检查锁定的元素。

**逻辑推理 (假设输入与输出):**

假设有一个 `<div>` 元素，其 CSS 属性为 `content-visibility: auto;`:

* **假设输入:** 元素最初不在视口内。
* **输出:**  `DisplayLockContext` 会调用 `RequestLock(DisplayLockActivationReason::kAny)`，并且在 `AdjustElementStyle` 中可能会设置 `skipsContents: true`，导致子元素不被渲染。

* **假设输入:** 用户滚动页面，使该元素进入视口。
* **输出:** `NotifyIsIntersectingViewport` 被调用，`DisplayLockContext` 会调用 `RequestUnlock()`，并且在后续的渲染更新中，`AdjustElementStyle` 不再设置 `skipsContents: true`，子元素开始被渲染。

* **假设输入:** 用户继续滚动，使元素离开视口。
* **输出:** `NotifyIsNotIntersectingViewport` 被调用，`DisplayLockContext` 可能会再次调用 `RequestLock()`。

**用户或编程常见的使用错误举例:**

* **错误地假设 `content-visibility: auto` 会立即隐藏内容:** 开发者可能认为设置 `content-visibility: auto` 会立即隐藏元素，但实际上，只有当元素不在视口内时才会触发锁定并跳过渲染。如果在初始渲染时元素就在视口内，它将立即被渲染。
* **过度使用 `content-visibility: hidden` 而不考虑性能影响:**  虽然 `content-visibility: hidden` 可以提高初始加载性能，但如果大量元素同时被设置为 `hidden`，并且之后又同时解除隐藏，可能会导致明显的性能抖动。
* **不理解 `contentvisibilityautostatechange` 事件的触发时机:** 开发者可能错误地认为该事件会在 `content-visibility` 属性值改变时触发，但实际上它只在 `content-visibility: auto` 状态下，元素的锁定状态发生变化时触发。

**总结：**

`blink/renderer/core/display_lock/display_lock_context.cc` 文件（第一部分）的核心功能是实现 Chromium Blink 引擎中与 CSS `content-visibility` 属性相关的机制。它负责管理元素的渲染锁定状态，根据视口交叉状态和用户交互来决定是否渲染元素的内容，并提供与 Blink 渲染生命周期集成的接口。这部分代码是实现高性能内容可见性控制的关键组件。

Prompt: 
```
这是目录为blink/renderer/core/display_lock/display_lock_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/display_lock/display_lock_context.h"

#include <string>

#include "base/auto_reset.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_macros.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/display_lock/content_visibility_auto_state_change_event.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/html_element_type_helpers.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/oof_positioned_node.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/pre_paint_tree_walk.h"
#include "third_party/blink/renderer/core/speculation_rules/document_speculation_rules.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {
namespace rejection_names {
const char* kContainmentNotSatisfied =
    "Containment requirement is not satisfied.";
const char* kUnsupportedDisplay =
    "Element has unsupported display type (display: contents).";
}  // namespace rejection_names

ScrollableArea* GetScrollableArea(Node* node) {
  if (!node)
    return nullptr;

  LayoutBoxModelObject* object =
      DynamicTo<LayoutBoxModelObject>(node->GetLayoutObject());
  if (!object)
    return nullptr;

  return object->GetScrollableArea();
}

}  // namespace

DisplayLockContext::DisplayLockContext(Element* element)
    : element_(element), document_(&element_->GetDocument()) {
  document_->GetDisplayLockDocumentState().AddDisplayLockContext(this);
  DetermineIfSubtreeHasFocus();
  DetermineIfSubtreeHasSelection();
  DetermineIfSubtreeHasTopLayerElement();
  DetermineIfDescendantIsViewTransitionElement();
}

void DisplayLockContext::SetRequestedState(EContentVisibility state) {
  if (state_ == state) {
    return;
  }
  state_ = state;
  base::AutoReset<bool> scope(&set_requested_state_scope_, true);
  switch (state_) {
    case EContentVisibility::kVisible:
      RequestUnlock();
      break;
    case EContentVisibility::kAuto:
      UseCounter::Count(document_, WebFeature::kContentVisibilityAuto);
      had_any_viewport_intersection_notifications_ = false;
      RequestLock(static_cast<uint16_t>(DisplayLockActivationReason::kAny));
      break;
    case EContentVisibility::kHidden:
      UseCounter::Count(document_, WebFeature::kContentVisibilityHidden);
      RequestLock(
          is_hidden_until_found_ || is_details_slot_
              ? static_cast<uint16_t>(DisplayLockActivationReason::kFindInPage)
              : 0u);
      break;
  }
  // In a new state, we might need to either start or stop observing viewport
  // intersections.
  UpdateActivationObservationIfNeeded();

  // If we needed a deferred not intersecting signal from 'auto' mode, we can
  // set that to false, since the mode has switched to something else. If we're
  // switching _to_ 'auto' mode, this should already be false and will be a
  // no-op.
  DCHECK(state_ != EContentVisibility::kAuto ||
         !needs_deferred_not_intersecting_signal_);
  needs_deferred_not_intersecting_signal_ = false;
  UpdateLifecycleNotificationRegistration();

  // Note that we call this here since the |state_| change is a render affecting
  // state, but is tracked independently.
  NotifyRenderAffectingStateChanged();

  // Since our state changed, check if we need to create a scoped force update
  // object.
  element_->GetDocument().GetDisplayLockDocumentState().ForceLockIfNeeded(
      element_.Get());
}

const ComputedStyle* DisplayLockContext::AdjustElementStyle(
    const ComputedStyle* style) const {
  if (state_ == EContentVisibility::kVisible) {
    return style;
  }
  if (IsLocked()) {
    ComputedStyleBuilder builder(*style);
    builder.SetSkipsContents(true);
    return builder.TakeStyle();
  }
  return style;
}

void DisplayLockContext::RequestLock(uint16_t activation_mask) {
  UpdateActivationMask(activation_mask);
  SetRenderAffectingState(RenderAffectingState::kLockRequested, true);
}

void DisplayLockContext::RequestUnlock() {
  SetRenderAffectingState(RenderAffectingState::kLockRequested, false);
}

void DisplayLockContext::UpdateActivationMask(uint16_t activatable_mask) {
  if (activatable_mask == activatable_mask_)
    return;

  bool all_activation_was_blocked = !activatable_mask_;
  bool all_activation_is_blocked = !activatable_mask;
  UpdateDocumentBookkeeping(IsLocked(), all_activation_was_blocked, IsLocked(),
                            all_activation_is_blocked);

  activatable_mask_ = activatable_mask;
}

void DisplayLockContext::UpdateDocumentBookkeeping(
    bool was_locked,
    bool all_activation_was_blocked,
    bool is_locked,
    bool all_activation_is_blocked) {
  if (!document_)
    return;

  if (was_locked != is_locked) {
    if (is_locked)
      document_->GetDisplayLockDocumentState().AddLockedDisplayLock();
    else
      document_->GetDisplayLockDocumentState().RemoveLockedDisplayLock();
  }

  bool was_locked_and_blocking = was_locked && all_activation_was_blocked;
  bool is_locked_and_blocking = is_locked && all_activation_is_blocked;
  if (was_locked_and_blocking != is_locked_and_blocking) {
    if (is_locked_and_blocking) {
      document_->GetDisplayLockDocumentState()
          .IncrementDisplayLockBlockingAllActivation();
    } else {
      document_->GetDisplayLockDocumentState()
          .DecrementDisplayLockBlockingAllActivation();
    }
  }
}

void DisplayLockContext::UpdateActivationObservationIfNeeded() {
  // If we don't have a document, then we don't have an observer so just make
  // sure we're marked as not observing anything and early out.
  if (!document_) {
    is_observed_ = false;
    return;
  }

  // We require observation if we are in 'auto' mode and we're connected to a
  // view.
  bool should_observe =
      state_ == EContentVisibility::kAuto && ConnectedToView();
  if (is_observed_ == should_observe)
    return;
  is_observed_ = should_observe;

  // Reset viewport intersection notification state, so that if we're observing
  // again, the next observation will be synchronous.
  had_any_viewport_intersection_notifications_ = false;

  if (should_observe) {
    document_->GetDisplayLockDocumentState()
        .RegisterDisplayLockActivationObservation(element_);
  } else {
    document_->GetDisplayLockDocumentState()
        .UnregisterDisplayLockActivationObservation(element_);
    // If we're not listening to viewport intersections, then we can assume
    // we're not intersecting:
    // 1. We might not be connected, in which case we're not intersecting.
    // 2. We might not be in 'auto' mode. which means that this doesn't affect
    //    anything consequential but acts as a reset should we switch back to
    //    the 'auto' mode.
    SetRenderAffectingState(RenderAffectingState::kIntersectsViewport, false);
  }
}

bool DisplayLockContext::NeedsLifecycleNotifications() const {
  return needs_deferred_not_intersecting_signal_ ||
         render_affecting_state_[static_cast<int>(
             RenderAffectingState::kAutoStateUnlockedUntilLifecycle)] ||
         has_pending_subtree_checks_ || has_pending_clear_has_top_layer_ ||
         has_pending_top_layer_check_ ||
         anchor_positioning_render_state_may_have_changed_;
}

void DisplayLockContext::UpdateLifecycleNotificationRegistration() {
  if (!document_ || !document_->View()) {
    is_registered_for_lifecycle_notifications_ = false;
    return;
  }

  bool needs_notifications = NeedsLifecycleNotifications();
  if (needs_notifications == is_registered_for_lifecycle_notifications_)
    return;

  is_registered_for_lifecycle_notifications_ = needs_notifications;
  if (needs_notifications) {
    document_->View()->RegisterForLifecycleNotifications(this);
  } else {
    document_->View()->UnregisterFromLifecycleNotifications(this);
  }
}

void DisplayLockContext::Lock() {
  DCHECK(!IsLocked());
  is_locked_ = true;
  UpdateDocumentBookkeeping(false, !activatable_mask_, true,
                            !activatable_mask_);

  // If we're not connected, then we don't have to do anything else. Otherwise,
  // we need to ensure that we update our style to check for containment later,
  // layout size based on the options, and also clear the painted output.
  if (!ConnectedToView()) {
    return;
  }

  // If there are any pending updates, we cancel them, as the fast updates
  // can't detect a locked display.
  // See: ../paint/README.md#Transform-update-optimization for more information
  document_->View()->RemoveAllPendingUpdates();

  // There are two ways we can get locked:
  // 1. A new content-visibility property needs us to be locked.
  // 2. We're in 'auto' mode and we are not intersecting the viewport.
  // In the first case, we are already in style processing, so we don't need to
  // invalidate style. However, in the second case we invalidate style so that
  // `AdjustElementStyle()` can be called.
  if (CanDirtyStyle()) {
    element_->SetNeedsStyleRecalc(
        kLocalStyleChange,
        StyleChangeReasonForTracing::Create(style_change_reason::kDisplayLock));

    MarkForStyleRecalcIfNeeded();
  }

  // TODO(vmpstr): Note when an 'auto' context gets locked, we should clear
  // the ancestor scroll anchors. This is a workaround for a behavior that
  // happens when the user quickly scrolls (e.g. scrollbar scrolls) into an
  // area that only has locked content. We can get into a loop that will
  // keep unlocking an element, which may shrink it to be out of the viewport,
  // and thus relocking it again. It is is also possible that we selected the
  // scroller itself or one of the locked elements as the anchor, so we don't
  // actually shift the scroll and the loop continues indefinitely. The user
  // can easily get out of the loop by scrolling since that triggers a new
  // scroll anchor selection. The work-around for us is also to pick a new
  // scroll anchor for the scroller that has a newly-locked context. The
  // reason it works is that it causes us to pick an anchor while the element
  // is still unlocked, so when it gets relocked we shift the scroll to
  // whatever visible content we had. The TODO here is to figure out if there
  // is a better way to solve this. In either case, we have to select a new
  // scroll anchor to get out of this behavior.
  element_->NotifyPriorityScrollAnchorStatusChanged();

  // We need to notify the AX cache (if it exists) to update |element_|'s
  // children in the AX cache.
  if (AXObjectCache* cache = element_->GetDocument().ExistingAXObjectCache())
    cache->ChildrenChanged(element_);

  // If we have top layer elements in our subtree, we have to detach their
  // layout objects, since otherwise they would be hoisted out of our subtree.
  DetachDescendantTopLayerElements();

  // Schedule ContentVisibilityAutoStateChange event if needed.
  ScheduleStateChangeEventIfNeeded();

  if (!element_->GetLayoutObject())
    return;

  // If this element is a scroller, then stash its current scroll offset, so
  // that we can restore it when needed.
  // Note that this only applies if the element itself is a scroller. Any
  // subtree scrollers' scroll offsets are not affected.
  StashScrollOffsetIfAvailable();

  MarkNeedsRepaintAndPaintArtifactCompositorUpdate();
}

// Did* function for the lifecycle phases. These functions, along with
// Should* functions in the header, control whether or not to process the
// lifecycle for self or for children.
// =============================================================================
void DisplayLockContext::DidStyleSelf() {
  // If we don't have a style after styling self, it means that we should revert
  // to the default state of being visible. This will get updated when we gain
  // new style.
  if (!element_->GetComputedStyle()) {
    SetRequestedState(EContentVisibility::kVisible);
    return;
  }

  // TODO(vmpstr): This needs to be in the spec.
  if (ForceUnlockIfNeeded())
    return;

  if (!IsLocked() && state_ != EContentVisibility::kVisible) {
    UpdateActivationObservationIfNeeded();
    NotifyRenderAffectingStateChanged();
  }
}

void DisplayLockContext::DidStyleChildren() {
  if (!element_->ChildNeedsReattachLayoutTree())
    return;
  auto* parent = element_->GetReattachParent();
  if (!parent || parent->ChildNeedsReattachLayoutTree())
    return;
  element_->MarkAncestorsWithChildNeedsReattachLayoutTree();
}

void DisplayLockContext::DidLayoutChildren() {
  // Since we did layout on children already, we'll clear this.
  child_layout_was_blocked_ = false;
  had_lifecycle_update_since_last_unlock_ = true;

  // If we're not locked and we laid out the children, then now is a good time
  // to restore the scroll offset.
  if (!is_locked_)
    RestoreScrollOffsetIfStashed();
}
// End Did* functions ==============================================

void DisplayLockContext::CommitForActivation(
    DisplayLockActivationReason reason) {
  DCHECK(element_);
  DCHECK(ConnectedToView());
  DCHECK(IsLocked());
  DCHECK(ShouldCommitForActivation(DisplayLockActivationReason::kAny));

  // The following actions (can) scroll content into view. However, if the
  // position of the target is outside of the bounds that would cause the
  // auto-context to unlock, then we can scroll into wrong content while the
  // context remains lock. To avoid this, unlock it until the next lifecycle.
  // If the scroll is successful, then we will gain visibility anyway so the
  // context will be unlocked for other reasons.
  if (reason == DisplayLockActivationReason::kAccessibility ||
      reason == DisplayLockActivationReason::kFindInPage ||
      reason == DisplayLockActivationReason::kFragmentNavigation ||
      reason == DisplayLockActivationReason::kScrollIntoView ||
      reason == DisplayLockActivationReason::kSimulatedClick) {
    // Note that because the visibility is only determined at the _end_ of the
    // next frame, we need to ensure that we stay unlocked for two frames.
    SetKeepUnlockedUntilLifecycleCount(2);
  }

  if (reason == DisplayLockActivationReason::kFindInPage)
    document_->MarkHasFindInPageContentVisibilityActiveMatch();
}

void DisplayLockContext::SetKeepUnlockedUntilLifecycleCount(int count) {
  DCHECK_GT(count, 0);
  keep_unlocked_count_ = std::max(keep_unlocked_count_, count);
  SetRenderAffectingState(
      RenderAffectingState::kAutoStateUnlockedUntilLifecycle, true);
  UpdateLifecycleNotificationRegistration();
  ScheduleAnimation();
}

void DisplayLockContext::NotifyIsIntersectingViewport() {
  had_any_viewport_intersection_notifications_ = true;
  // If we are now intersecting, then we are definitely not nested in a locked
  // subtree and we don't need to lock as a result.
  needs_deferred_not_intersecting_signal_ = false;
  UpdateLifecycleNotificationRegistration();
  // If we're not connected, then there is no need to change any state.
  // This could be the case if we were disconnected while a viewport
  // intersection notification was pending.
  if (ConnectedToView())
    SetRenderAffectingState(RenderAffectingState::kIntersectsViewport, true);
}

void DisplayLockContext::NotifyIsNotIntersectingViewport() {
  had_any_viewport_intersection_notifications_ = true;

  if (IsLocked()) {
    DCHECK(!needs_deferred_not_intersecting_signal_);
    return;
  }

  // We might have been disconnected while the intersection observation
  // notification was pending. Ensure to unregister from lifecycle
  // notifications if we're doing that, and early out.
  if (!ConnectedToView()) {
    needs_deferred_not_intersecting_signal_ = false;
    UpdateLifecycleNotificationRegistration();
    return;
  }

  // There are two situations we need to consider here:
  // 1. We are off-screen but not nested in any other lock. This means we should
  //    re-lock (also verify that the reason we're in this state is that we're
  //    activated).
  // 2. We are in a nested locked context. This means we don't actually know
  //    whether we should lock or not. In order to avoid needless dirty of the
  //    layout and style trees up to the nested context, we remain unlocked.
  //    However, we also need to ensure that we relock if we become unnested.
  //    So, we simply delay this check to the next frame (via LocalFrameView),
  //    which will call this function again and so we can perform the check
  //    again.
  // Note that we use a signal that we're not painting to defer intersection,
  // since even if we're updating the locked ancestor for style or layout, we
  // should defer intersection notifications.
  auto* locked_ancestor =
      DisplayLockUtilities::LockedAncestorPreventingPaint(*element_);
  if (locked_ancestor) {
    needs_deferred_not_intersecting_signal_ = true;
  } else {
    needs_deferred_not_intersecting_signal_ = false;
    SetRenderAffectingState(RenderAffectingState::kIntersectsViewport, false);
  }
  UpdateLifecycleNotificationRegistration();
}

bool DisplayLockContext::ShouldCommitForActivation(
    DisplayLockActivationReason reason) const {
  return IsActivatable(reason) && IsLocked();
}

void DisplayLockContext::UpgradeForcedScope(ForcedPhase old_phase,
                                            ForcedPhase new_phase,
                                            bool emit_warnings) {
  // Since we're upgrading, it means we have a bigger phase.
  DCHECK_LT(static_cast<int>(old_phase), static_cast<int>(new_phase));

  auto old_forced_info = forced_info_;
  forced_info_.end(old_phase);
  forced_info_.start(new_phase);
  if (IsLocked()) {
    // Now that the update is forced, we should ensure that style layout, and
    // prepaint code can reach it via dirty bits. Note that paint isn't a part
    // of this, since |forced_info_| doesn't force paint to happen. See
    // ShouldPaint(). Also, we could have forced a lock from SetRequestedState
    // during a style update. If that's the case, don't mark style as dirty
    // from within style recalc. We rely on `TakeBlockedStyleRecalcChange`
    // to be called from self style recalc.
    if (CanDirtyStyle() &&
        !old_forced_info.is_forced(ForcedPhase::kStyleAndLayoutTree) &&
        forced_info_.is_forced(ForcedPhase::kStyleAndLayoutTree)) {
      MarkForStyleRecalcIfNeeded();
    }
    if (!old_forced_info.is_forced(ForcedPhase::kLayout) &&
        forced_info_.is_forced(ForcedPhase::kLayout)) {
      MarkForLayoutIfNeeded();
    }
    if (!old_forced_info.is_forced(ForcedPhase::kPrePaint) &&
        forced_info_.is_forced(ForcedPhase::kPrePaint)) {
      MarkAncestorsForPrePaintIfNeeded();
    }

    if (emit_warnings && document_ &&
        document_->GetAgent().isolate()->InContext() && element_ &&
        (!IsActivatable(DisplayLockActivationReason::kAny) ||
         RuntimeEnabledFeatures::
             WarnOnContentVisibilityRenderAccessEnabled())) {
      document_->GetDisplayLockDocumentState().IssueForcedRenderWarning(
          element_);
    }
  }
}

void DisplayLockContext::ScheduleStateChangeEventIfNeeded() {
  if (state_ == EContentVisibility::kAuto &&
      !state_change_task_pending_) {
    document_->GetExecutionContext()
        ->GetTaskRunner(TaskType::kMiscPlatformAPI)
        ->PostTask(
            FROM_HERE,
            WTF::BindOnce(&DisplayLockContext::DispatchStateChangeEventIfNeeded,
                          WrapPersistent(this)));
    state_change_task_pending_ = true;
  }
}

void DisplayLockContext::DispatchStateChangeEventIfNeeded() {
  DCHECK(state_change_task_pending_);
  state_change_task_pending_ = false;
  // If we're not connected to view, reset the state that we reported so that we
  // can report it again on insertion.
  if (!ConnectedToView()) {
    last_notified_skipped_state_.reset();
    return;
  }

  if (!last_notified_skipped_state_ ||
      *last_notified_skipped_state_ != is_locked_) {
    last_notified_skipped_state_ = is_locked_;
    element_->DispatchEvent(*ContentVisibilityAutoStateChangeEvent::Create(
        event_type_names::kContentvisibilityautostatechange, is_locked_));
  }
}

void DisplayLockContext::NotifyForcedUpdateScopeEnded(ForcedPhase phase) {
  // Since we do perform updates in a locked display if we're in a forced
  // update scope, when ending a forced update scope in a locked display, we
  // remove all pending updates, to prevent them from being executed in a
  // locked display.
  // See: ../paint/README.md#Transform-update-optimization for more information
  if (is_locked_) {
    document_->View()->RemoveAllPendingUpdates();
  }
  forced_info_.end(phase);
}

void DisplayLockContext::Unlock() {
  DCHECK(IsLocked());
  is_locked_ = false;
  had_lifecycle_update_since_last_unlock_ = false;
  UpdateDocumentBookkeeping(true, !activatable_mask_, false,
                            !activatable_mask_);

  if (!ConnectedToView())
    return;

  // There are a few ways we can get unlocked:
  // 1. A new content-visibility property needs us to be ulocked.
  // 2. We're in 'auto' mode and we are intersecting the viewport.
  // In the first case, we are already in style processing, so we don't need to
  // invalidate style. However, in the second case we invalidate style so that
  // `AdjustElementStyle()` can be called.
  if (CanDirtyStyle()) {
    // Since size containment depends on the activatability state, we should
    // invalidate the style for this element, so that the style adjuster can
    // properly remove the containment.
    element_->SetNeedsStyleRecalc(
        kLocalStyleChange,
        StyleChangeReasonForTracing::Create(style_change_reason::kDisplayLock));

    // Also propagate any dirty bits that we have previously blocked.
    // If we're in style recalc, this will be handled by
    // `TakeBlockedStyleRecalcChange()` call from self style recalc.
    MarkForStyleRecalcIfNeeded();
  } else if (SubtreeHasTopLayerElement()) {
    // TODO(vmpstr): This seems like a big hammer, but it's unclear to me how we
    // can mark the dirty bits from the descendant top layer node up to this
    // display lock on the ancestor chain while we're in the middle of style
    // recalc. It seems plausible, but we have to be careful.
    blocked_child_recalc_change_ =
        blocked_child_recalc_change_.ForceRecalcDescendants();
  }

  // We also need to notify the AX cache (if it exists) to update the children
  // of |element_| in the AX cache.
  if (auto* ax_cache = element_->GetDocument().ExistingAXObjectCache()) {
    ax_cache->RemoveSubtree(element_);
  }

  // Schedule ContentVisibilityAutoStateChange event if needed.
  ScheduleStateChangeEventIfNeeded();

  auto* layout_object = element_->GetLayoutObject();
  // We might commit without connecting, so there is no layout object yet.
  if (!layout_object)
    return;

  // Now that we know we have a layout object, we should ensure that we can
  // reach the rest of the phases as well.
  MarkForLayoutIfNeeded();
  MarkAncestorsForPrePaintIfNeeded();
  MarkNeedsRepaintAndPaintArtifactCompositorUpdate();
  MarkNeedsCullRectUpdate();
}

bool DisplayLockContext::CanDirtyStyle() const {
  return !set_requested_state_scope_ && !document_->InStyleRecalc();
}

bool DisplayLockContext::MarkForStyleRecalcIfNeeded() {
  DCHECK(CanDirtyStyle());

  if (IsElementDirtyForStyleRecalc()) {
    // Propagate to the ancestors, since the dirty bit in a locked subtree is
    // stopped at the locked ancestor.
    // See comment in IsElementDirtyForStyleRecalc.
    element_->SetNeedsStyleRecalc(
        kLocalStyleChange,
        StyleChangeReasonForTracing::Create(style_change_reason::kDisplayLock));
    element_->MarkAncestorsWithChildNeedsStyleRecalc();

    // When we're forcing a lock, which is done in a CanDirtyStyle context, we
    // mark the top layers that don't have a computed style as needing a style
    // recalc. This is a heuristic since if a top layer doesn't have a computed
    // style then it is possibly under a content-visibility skipped subtree. The
    // alternative is to figure out exactly which top layer element is under
    // this lock and only dirty those, but that seems unnecessary. If the top
    // layer element is locked under a different lock, then the dirty bit
    // wouldn't propagate anyway.
    for (auto top_layer_element : document_->TopLayerElements()) {
      if (!top_layer_element->GetComputedStyle()) {
        top_layer_element->SetNeedsStyleRecalc(
            kLocalStyleChange, StyleChangeReasonForTracing::Create(
                                   style_change_reason::kDisplayLock));
      }
    }
    return true;
  }
  return false;
}

bool DisplayLockContext::MarkForLayoutIfNeeded() {
  if (IsElementDirtyForLayout()) {
    // Forces the marking of ancestors to happen, even if
    // |DisplayLockContext::ShouldLayout()| returns false.
    class ScopedForceLayout {
      STACK_ALLOCATED();

     public:
      explicit ScopedForceLayout(DisplayLockContext* context)
          : context_(context) {
        context_->forced_info_.start(ForcedPhase::kLayout);
      }
      ~ScopedForceLayout() { context_->forced_info_.end(ForcedPhase::kLayout); }

     private:
      DisplayLockContext* context_;
    } scoped_force(this);

    auto* layout_object = element_->GetLayoutObject();

    // Ensure any layout-type specific caches are dirty.
    layout_object->SetGridPlacementDirty(true);

    if (child_layout_was_blocked_ || HasStashedScrollOffset()) {
      // We've previously blocked a child traversal when doing self-layout for
      // the locked element, so we're marking it with child-needs-layout so that
      // it will traverse to the locked element and do the child traversal
      // again. We don't need to mark it for self-layout (by calling
      // |LayoutObject::SetNeedsLayout()|) because the locked element itself
      // doesn't need to relayout.
      //
      // Note that we also make sure to visit the children when we have a
      // stashed scroll offset. This is so that we can restore the offset after
      // laying out the children. If we try to restore it before the layout, it
      // will be ignored since the scroll area may think that it doesn't have
      // enough contents.
      // TODO(vmpstr): In the scroll offset case, we're doing this just so we
      // can reach DisplayLockContext::DidLayoutChildren where we restore the
      // offset. If performance becomes an issue, then we should think of a
      // different time / opportunity to restore the offset.
      layout_object->SetChildNeedsLayout();
      child_layout_was_blocked_ = false;
    } else {
      // Since the dirty layout propagation stops at the locked element, we need
      // to mark its ancestors as dirty here so that it will be traversed to on
      // the next layout.
      layout_object->MarkContainerChainForLayout();
    }
    return true;
  }
  return false;
}

bool DisplayLockContext::MarkAncestorsForPrePaintIfNeeded() {
  // TODO(vmpstr): We should add a compositing phase for proper bookkeeping.
  bool compositing_dirtied = MarkForCompositingUpdatesIfNeeded();

  if (IsElementDirtyForPrePaint()) {
    auto* layout_object = element_->GetLayoutObject();
    if (auto* parent = layout_object->Parent())
      parent->SetSubtreeShouldCheckForPaintInvalidation();

    // Note that if either we or our descendants are marked as needing this
    // update, then ensure to mark self as needing the update. This sets up the
    // correct flags for PrePaint to recompute the necessary values and
    // propagate the information into the subtree.
    if (needs_effective_allowed_touch_action_update_ ||
        layout_object->EffectiveAllowedTouchActionChanged() ||
        layout_object->DescendantEffectiveAllowedTouchActionChanged()) {
      // Note that although the object itself should have up to date value, in
      // order to force recalc of the whole subtree, we mark it as needing an
      // update.
      layout_object->MarkEffectiveAllowedTouchActionChanged();
    }
    if (needs_blocking_wheel_event_handler_update_ ||
        layout_object->BlockingWheelEventHandlerChanged() ||
        layout_object->DescendantBlockingWheelEventHandlerChanged()) {
      // Note that although the object itself should have up to date value, in
      // order to force recalc of the whole subtree, we mark it as needing an
      // update.
      layout_object->MarkBlockingWheelEventHandlerChanged();
    }
    return true;
  }
  return compositing_dirtied;
}

bool DisplayLockContext::MarkNeedsRepaintAndPaintArtifactCompositorUpdate() {
  DCHECK(ConnectedToView());
  if (auto* layout_object = element_->GetLayoutObject()) {
    layout_object->PaintingLayer()->SetNeedsRepaint();
    document_->View()->SetPaintArtifactCompositorNeedsUpdate();
    return true;
  }
  return false;
}

bool DisplayLockContext::MarkNeedsCullRectUpdate() {
  DCHECK(ConnectedToView());
  if (auto* layout_object = element_->GetLayoutObject()) {
    layout_object->PaintingLayer()->SetForcesChildrenCullRectUpdate();
    return true;
  }
  return false;
}

bool DisplayLockContext::MarkForCompositingUpdatesIfNeeded() {
  if (!ConnectedToView())
    return false;

  auto* layout_object = element_->GetLayoutObject();
  if (!layout_object)
    return false;

  auto* layout_box = DynamicTo<LayoutBoxModelObject>(layout_object);
  if (layout_box && layout_box->HasSelfPaintingLayer()) {
    if (needs_compositing_dependent_flag_update_)
      layout_box->Layer()->SetNeedsCompositingInputsUpdate();
    needs_compositing_dependent_flag_update_ = false;

    return true;
  }
  return false;
}

bool DisplayLockContext::IsElementDirtyForStyleRecalc() const {
  // The |element_| checks could be true even if |blocked_child_recalc_change_|
  // is empty. The reason for this is that the |blocked_child_recalc_change_| is
  // set during the style walk that this display lock blocks. However, we could
  // dirty element style and unlock this context (e.g. by c-v auto visibility
  // change) before ever having gone through the style calc that would have been
  // blocked Also these dirty bits were not propagated to the ancestors, so we
  // do need to update the dirty bit state for ancestors.
  return element_->IsDirtyForStyleRecalc() ||
         element_->ChildNeedsStyleRecalc() ||
         element_->ChildNeedsReattachLayoutTree() ||
         !blocked_child_recalc_change_.IsEmpty() || SubtreeHasTopLayerElement();
}

bool DisplayLockContext::IsElementDirtyForLayout() const {
  if (auto* layout_object = element_->GetLayoutObject()) {
    return layout_object->NeedsLayout() || child_layout_was_blocked_ ||
           HasStashedScrollOffset();
  }
  return false;
}

bool DisplayLockContext::IsElementDirtyForPrePaint() const {
  if (auto* layout_object = element_->GetLayoutObject()) {
    return PrePaintTreeWalk::ObjectRequiresPrePaint(*layout_object) ||
   
"""


```