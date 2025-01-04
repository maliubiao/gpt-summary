Response:
Let's break down the thought process for analyzing the given C++ code and extracting its functionality.

1. **Understand the Goal:** The primary goal is to understand the purpose of the `DisplayLockDocumentState` class in the Chromium Blink rendering engine, particularly its interactions with JavaScript, HTML, and CSS. We also need to consider potential usage errors and how the class might reason logically.

2. **Identify Key Data Members:**  Start by looking at the class's member variables. These often provide clues about its state and responsibilities:
    * `document_`:  A pointer to a `Document`. This immediately tells us the class is associated with a specific HTML document.
    * `intersection_observer_`: An `IntersectionObserver`. This suggests the class is involved in monitoring the visibility of elements.
    * `display_lock_contexts_`: A collection of `DisplayLockContext` objects. This is a strong indicator that this class manages multiple display locks within the document.
    * `forced_node_infos_`, `forced_range_infos_`: These collections likely track information about forced rendering, potentially related to JavaScript interactions.
    * `locked_display_lock_count_`: Tracks the number of active display locks.
    * `display_lock_blocking_all_activation_count_`:  Suggests a mechanism to block activation.
    * `last_lock_update_timestamp_`: For tracking lock updates.
    * `activatable_display_locks_forced_`: A flag related to forcing display locks.
    * `printing_`:  Indicates the printing state.
    * `forced_render_warnings_`:  Tracks warnings about forced rendering.

3. **Analyze Member Functions:**  Go through each member function and understand its purpose. Group related functions together:
    * **Construction/Destruction/Tracing:**  `DisplayLockDocumentState()`, `Trace()`. These are standard lifecycle management and debugging tools.
    * **Managing `DisplayLockContext`s:** `AddDisplayLockContext()`, `RemoveDisplayLockContext()`, `DisplayLockCount()`. This confirms the central role of managing `DisplayLockContext` objects.
    * **Locking/Unlocking:** `AddLockedDisplayLock()`, `RemoveLockedDisplayLock()`, `LockedDisplayLockCount()`, `IncrementDisplayLockBlockingAllActivation()`, `DecrementDisplayLockBlockingAllActivation()`, `DisplayLockBlockingAllActivationCount()`, `GetLockUpdateTimestamp()`. These functions clearly manage the state of display locks.
    * **Intersection Observation:** `RegisterDisplayLockActivationObservation()`, `UnregisterDisplayLockActivationObservation()`, `EnsureIntersectionObserver()`, `ProcessDisplayLockActivationObservation()`. These are related to observing when elements become visible.
    * **Top Layer Management:** `ElementAddedToTopLayer()`, `ElementRemovedFromTopLayer()`, `MarkAncestorContextsHaveTopLayerElement()`. These functions deal with elements entering and leaving the top layer (e.g., due to `z-index`).
    * **View Transitions:** `NotifyViewTransitionPseudoTreeChanged()`, `UpdateViewTransitionElementAncestorLocks()`. These are specifically for handling visual transitions between states.
    * **Selection:** `NotifySelectionRemoved()`. Handles the removal of text selections.
    * **Forced Rendering:** `BeginNodeForcedScope()`, `BeginRangeForcedScope()`, `EndForcedScope()`, `EnsureMinimumForcedPhase()`, `ForceLockIfNeeded()`, `ForcedNodeInfo`, `ForcedRangeInfo`. These are concerned with situations where rendering might be forced despite optimizations.
    * **Forcing Activation:** `GetScopedForceActivatableLocks()`, `HasActivatableLocks()`, `ActivatableDisplayLocksForced()`. These allow temporary forcing of display lock activation.
    * **Printing:** `NotifyPrintingOrPreviewChanged()`. Handles changes in the document's printing status.
    * **Warnings:** `IssueForcedRenderWarning()`. Reports warnings related to forced rendering.
    * **Scheduling:** `ScheduleAnimation()`.

4. **Identify Relationships with Web Technologies (JavaScript, HTML, CSS):**
    * **HTML:** The class is fundamentally tied to the `Document` object, which represents the HTML structure. Functions like `ElementAddedToTopLayer` and the intersection observer directly interact with HTML elements.
    * **CSS:**  The concept of "top layer" is a CSS concept related to stacking contexts and `z-index`. `content-visibility` (mentioned in the warnings) is a CSS property. The intersection observer's margin and clipping settings also relate to CSS layout. View transitions are a newer CSS-related feature.
    * **JavaScript:** The intersection observer is exposed to JavaScript. Forced rendering often occurs as a result of JavaScript manipulating the DOM or accessing layout properties. Display locks themselves can be controlled via a JavaScript API (though this code doesn't directly implement that API). The console warnings are for developers, often triggered by JavaScript actions.

5. **Infer Logical Reasoning:** Look for conditional logic and state changes within the functions:
    * The `ProcessDisplayLockActivationObservation` function decides whether to notify synchronously or asynchronously based on whether there were previous notifications. This shows a strategy for optimization.
    * The `MarkAncestorContextsHaveTopLayerElement` function iterates through the element's ancestors, checking for display lock contexts. This demonstrates a hierarchical relationship and dependency.
    * The forced rendering logic ensures that if a node or range is being accessed, the relevant display locks are activated.

6. **Consider User/Programming Errors:** Think about scenarios where developers might misuse the features related to display locks or `content-visibility`:
    * Accessing properties of elements hidden by `content-visibility: auto` might trigger forced rendering warnings.
    * Not understanding how display locks interact with the top layer or view transitions could lead to unexpected behavior.
    * Incorrectly managing the lifecycle of display lock contexts could lead to errors (as hinted at in the comment about garbage collection).

7. **Construct Examples (Hypothetical Inputs & Outputs):** Create simple scenarios to illustrate the functionality. This helps solidify understanding:
    * **Intersection Observer:**  Show how an element entering the viewport might trigger a notification to the `DisplayLockContext`.
    * **Top Layer:** Illustrate how adding an element with a high `z-index` can affect display locks on its ancestors.
    * **Forced Rendering:**  Demonstrate how accessing `offsetHeight` on an element with `content-visibility: auto` might lead to a warning.

8. **Refine and Organize:** Structure the findings logically, starting with a high-level overview and then drilling down into specific functionalities, relationships, and potential issues. Use clear and concise language.

By following this systematic approach, we can effectively analyze the C++ code and extract the requested information, even without being a C++ expert. The key is to focus on the class's purpose, its interactions with other components, and the overall concepts it represents within the web rendering process.
This C++ source code file, `display_lock_document_state.cc`, is part of the Blink rendering engine in Chromium and is responsible for managing the state of **display locks** within a specific HTML document. Display locks are a mechanism to optimize rendering performance by preventing unnecessary rendering of parts of the page that are not currently visible or relevant.

Here's a breakdown of its functionalities:

**Core Functionality: Managing Display Locks within a Document**

* **Tracking Display Lock Contexts:** It maintains a collection (`display_lock_contexts_`) of `DisplayLockContext` objects associated with elements within the document. Each `DisplayLockContext` likely represents a specific region or element that has a display lock applied.
* **Counting Locked Display Locks:** It keeps track of the number of currently active display locks (`locked_display_lock_count_`).
* **Tracking Blocking Display Locks:** It tracks display locks that are actively preventing certain operations, such as activation (`display_lock_blocking_all_activation_count_`). This likely relates to features like user interactions or focus.
* **Observing Display Lock Activation:** It uses an `IntersectionObserver` to monitor when elements with display locks become visible in the viewport. This allows the engine to activate the display lock when the element is about to be displayed.
* **Handling Top Layer Changes:** It responds to elements being added to or removed from the "top layer" (e.g., due to modal dialogs or fullscreen elements). This is important because elements in the top layer might need to bypass display locks on their ancestors.
* **Managing Forced Rendering:** It tracks scenarios where rendering is intentionally forced for elements that might otherwise be skipped due to `content-visibility`. This is often necessary when JavaScript interacts with these elements.
* **Supporting View Transitions:** It integrates with the View Transitions API to ensure display locks are properly handled during transitions between different states of the page.
* **Handling Printing:** It adjusts display lock behavior during printing or print preview.
* **Providing Scoped Force Activation:** It offers a mechanism to temporarily force display locks to be considered "activatable," overriding their normal state.

**Relationship with JavaScript, HTML, and CSS:**

This code interacts heavily with all three web technologies:

* **HTML:**
    * **Element Association:** The `DisplayLockContext` objects are associated with specific HTML elements. The `IntersectionObserver` observes HTML elements. The top layer logic directly deals with `Element` objects.
    * **Example:** When a `<dialog>` element is shown (added to the top layer), `ElementAddedToTopLayer` is called. This function then iterates through the document's display lock contexts and potentially adjusts their state to ensure the dialog's content is rendered.

* **CSS:**
    * **`content-visibility`:** The code explicitly mentions and handles scenarios related to the `content-visibility` CSS property. This property allows developers to hint to the browser that certain parts of the content are not initially visible, allowing the browser to skip their rendering. Display locks work in conjunction with `content-visibility`.
    * **Top Layer (z-index):** The concept of the "top layer" is a CSS concept related to stacking contexts and the `z-index` property.
    * **View Transitions:**  The code interacts with the View Transitions API, which is exposed through CSS and JavaScript.
    * **Intersection Observer Margins:** The `IntersectionObserver` is configured with a margin (150% of the viewport), indicating an awareness of the element's position relative to the visible area, a concept directly tied to CSS layout.
    * **Example:** An element with `content-visibility: auto` might have a display lock associated with it. The browser might initially skip rendering its content. However, when the element becomes visible (as determined by the `IntersectionObserver`), the display lock is activated, and the content is rendered.

* **JavaScript:**
    * **Intersection Observer API:**  While the code implements the internal logic, the `IntersectionObserver` is a JavaScript API that web developers can use.
    * **Forced Rendering (JavaScript Interaction):** When JavaScript accesses properties of an element hidden by `content-visibility: auto` (e.g., `offsetHeight`), the browser might need to "force" the rendering of that subtree. This code tracks these forced rendering scenarios and can issue warnings.
    * **View Transitions API:** JavaScript is used to trigger and control view transitions, and this code ensures display locks are handled correctly during those transitions.
    * **Example:** A JavaScript function might manipulate the DOM within an element that has a display lock. If this manipulation requires the browser to calculate the layout of that element (even if it's not yet visible), the forced rendering logic in this code would be involved.

**Logical Reasoning (Hypothetical Input and Output):**

Let's consider a scenario with `content-visibility: auto`:

**Hypothetical Input:**

1. **HTML:** A `<div>` element with `style="content-visibility: auto;"` is present in the document.
2. **Initial State:** The `<div>` is initially outside the viewport. A `DisplayLockContext` is associated with this `<div>`.
3. **User Action:** The user scrolls the page so that the `<div>` enters the viewport.

**Logical Reasoning within `display_lock_document_state.cc`:**

1. The `IntersectionObserver` (managed by this class) detects that the `<div>` is intersecting the viewport.
2. The `ProcessDisplayLockActivationObservation` function is called.
3. Since the element is now intersecting, `context->NotifyIsIntersectingViewport()` is called on the `DisplayLockContext` associated with the `<div>`.
4. The `DisplayLockContext` then triggers the necessary rendering updates for the content within the `<div>` to become visible.

**Hypothetical Output:**

The content inside the `<div>` element becomes visible on the screen.

**User or Programming Common Usage Errors:**

* **Accessing Layout Information of `content-visibility: auto` Elements Too Early:**
    * **Scenario:** A developer uses JavaScript to access properties like `offsetWidth` or `offsetHeight` of an element that has `content-visibility: auto` but is currently hidden.
    * **Consequence:** This forces the browser to render the element prematurely, negating the performance benefits of `content-visibility`. The `IssueForcedRenderWarning` function in this code is designed to detect and warn about such situations.
    * **Example:**
        ```javascript
        const hiddenDiv = document.getElementById('myHiddenDiv');
        // myHiddenDiv has content-visibility: auto and is initially off-screen.
        console.log(hiddenDiv.offsetHeight); // This might trigger a forced render warning.
        ```

* **Incorrectly Managing Display Lock Lifecycles:** Although not directly controlled by web developers, if the internal logic for creating and destroying `DisplayLockContext` objects is flawed, it could lead to performance issues or incorrect rendering. The comment `DCHECK(false) << ...` in `ScopedForceActivatableDisplayLocks` hints at potential issues if a `DisplayLockContext`'s element is garbage collected prematurely.

* **Over-reliance on Forcing Activation:**  While `ScopedForceActivatableDisplayLocks` provides a way to override display locks, using it excessively can defeat the purpose of having display locks for optimization. Developers should understand when and why forcing activation is truly necessary.

In summary, `display_lock_document_state.cc` is a crucial component for managing the lifecycle and activation of display locks within a web page, working closely with HTML structure, CSS styling hints like `content-visibility`, and JavaScript interactions to optimize rendering performance. It also helps developers identify potential performance pitfalls through warnings related to forced rendering.

Prompt: 
```
这是目录为blink/renderer/core/display_lock/display_lock_document_state.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"

#include "base/trace_event/trace_event.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_context.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/slot_assignment_engine.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer_entry.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/view_transition/view_transition.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"

namespace {

const char kForcedRendering[] =
    "Rendering was performed in a subtree hidden by content-visibility.";
const char kForcedRenderingMax[] =
    "Rendering was performed in a subtree hidden by content-visibility. "
    "Further messages will be suppressed.";
constexpr unsigned kMaxConsoleMessages = 500;

}  // namespace

namespace blink {

DisplayLockDocumentState::DisplayLockDocumentState(Document* document)
    : document_(document) {}

void DisplayLockDocumentState::Trace(Visitor* visitor) const {
  visitor->Trace(document_);
  visitor->Trace(intersection_observer_);
  visitor->Trace(display_lock_contexts_);
  visitor->Trace(forced_node_infos_);
  visitor->Trace(forced_range_infos_);
}

void DisplayLockDocumentState::AddDisplayLockContext(
    DisplayLockContext* context) {
  display_lock_contexts_.insert(context);
  context->SetShouldUnlockAutoForPrint(printing_);
}

void DisplayLockDocumentState::RemoveDisplayLockContext(
    DisplayLockContext* context) {
  display_lock_contexts_.erase(context);
}

int DisplayLockDocumentState::DisplayLockCount() const {
  return display_lock_contexts_.size();
}

void DisplayLockDocumentState::AddLockedDisplayLock() {
  TRACE_COUNTER_ID1(TRACE_DISABLED_BY_DEFAULT("blink.debug.display_lock"),
                    "LockedDisplayLockCount", TRACE_ID_LOCAL(this),
                    locked_display_lock_count_);
  ++locked_display_lock_count_;
  last_lock_update_timestamp_ = base::TimeTicks::Now();
}

void DisplayLockDocumentState::RemoveLockedDisplayLock() {
  DCHECK(locked_display_lock_count_);
  --locked_display_lock_count_;
  last_lock_update_timestamp_ = base::TimeTicks::Now();
  TRACE_COUNTER_ID1(TRACE_DISABLED_BY_DEFAULT("blink.debug.display_lock"),
                    "LockedDisplayLockCount", TRACE_ID_LOCAL(this),
                    locked_display_lock_count_);
}

int DisplayLockDocumentState::LockedDisplayLockCount() const {
  return locked_display_lock_count_;
}

void DisplayLockDocumentState::IncrementDisplayLockBlockingAllActivation() {
  ++display_lock_blocking_all_activation_count_;
}

void DisplayLockDocumentState::DecrementDisplayLockBlockingAllActivation() {
  DCHECK(display_lock_blocking_all_activation_count_);
  --display_lock_blocking_all_activation_count_;
}

int DisplayLockDocumentState::DisplayLockBlockingAllActivationCount() const {
  return display_lock_blocking_all_activation_count_;
}

base::TimeTicks DisplayLockDocumentState::GetLockUpdateTimestamp() {
  return last_lock_update_timestamp_;
}

void DisplayLockDocumentState::RegisterDisplayLockActivationObservation(
    Element* element) {
  EnsureIntersectionObserver().observe(element);
}

void DisplayLockDocumentState::UnregisterDisplayLockActivationObservation(
    Element* element) {
  EnsureIntersectionObserver().unobserve(element);
}

IntersectionObserver& DisplayLockDocumentState::EnsureIntersectionObserver() {
  if (!intersection_observer_) {
    // Use kDeliverDuringPostLayoutSteps method, since we will either notify the
    // display lock synchronously and re-run layout, or delay delivering the
    // signal to the display lock context until the next frame's rAF callbacks
    // have run. This means for the duration of the idle time that follows, we
    // should always have clean layout.
    //
    // Note that we use 150% margin (on the viewport) so that we get the
    // observation before the element enters the viewport.
    //
    // Paint containment requires using the overflow clip edge. To do otherwise
    // results in overflow-clip-margin not being painted in certain scenarios.
    intersection_observer_ = IntersectionObserver::Create(
        *document_,
        WTF::BindRepeating(
            &DisplayLockDocumentState::ProcessDisplayLockActivationObservation,
            WrapWeakPersistent(this)),
        LocalFrameUkmAggregator::kDisplayLockIntersectionObserver,
        IntersectionObserver::Params{
            .margin = {Length::Percent(kViewportMarginPercentage)},
            .margin_target = IntersectionObserver::kApplyMarginToTarget,
            .thresholds = {std::numeric_limits<float>::min()},
            .behavior = IntersectionObserver::kDeliverDuringPostLayoutSteps,
            .use_overflow_clip_edge = true,
        });
  }
  return *intersection_observer_;
}

void DisplayLockDocumentState::ProcessDisplayLockActivationObservation(
    const HeapVector<Member<IntersectionObserverEntry>>& entries) {
  DCHECK(document_);
  DCHECK(document_->View());
  bool had_asynchronous_notifications = false;
  for (auto& entry : entries) {
    auto* context = entry->target()->GetDisplayLockContext();
    DCHECK(context);
    if (context->HadAnyViewportIntersectionNotifications()) {
      if (entry->isIntersecting()) {
        document_->View()->EnqueueStartOfLifecycleTask(
            WTF::BindOnce(&DisplayLockContext::NotifyIsIntersectingViewport,
                          WrapWeakPersistent(context)));
      } else {
        document_->View()->EnqueueStartOfLifecycleTask(
            WTF::BindOnce(&DisplayLockContext::NotifyIsNotIntersectingViewport,
                          WrapWeakPersistent(context)));
      }
      had_asynchronous_notifications = true;
    } else {
      if (entry->isIntersecting())
        context->NotifyIsIntersectingViewport();
      else
        context->NotifyIsNotIntersectingViewport();
    }
  }

  // If we had any asynchronous notifications, they would be delivered before
  // the next lifecycle. Ensure to schedule a frame so that this process
  // happens.
  if (had_asynchronous_notifications) {
    // Note that since we're processing this from within the lifecycle, post a
    // task to schedule a new frame (direct call would be ignored inside a
    // lifecycle).
    document_->GetTaskRunner(TaskType::kInternalFrameLifecycleControl)
        ->PostTask(FROM_HERE,
                   WTF::BindOnce(&DisplayLockDocumentState::ScheduleAnimation,
                                 WrapWeakPersistent(this)));
  }
}

void DisplayLockDocumentState::ScheduleAnimation() {
  if (document_ && document_->View())
    document_->View()->ScheduleAnimation();
}

DisplayLockDocumentState::ScopedForceActivatableDisplayLocks
DisplayLockDocumentState::GetScopedForceActivatableLocks() {
  return ScopedForceActivatableDisplayLocks(this);
}

bool DisplayLockDocumentState::HasActivatableLocks() const {
  return LockedDisplayLockCount() != DisplayLockBlockingAllActivationCount();
}

bool DisplayLockDocumentState::ActivatableDisplayLocksForced() const {
  return activatable_display_locks_forced_;
}

void DisplayLockDocumentState::ElementAddedToTopLayer(Element* element) {
  // If flat tree traversal is forbidden, then we need to schedule an event to
  // do this work later.
  if (document_->IsFlatTreeTraversalForbidden() ||
      document_->GetSlotAssignmentEngine().HasPendingSlotAssignmentRecalc()) {
    for (auto context : display_lock_contexts_) {
      // If making every DisplayLockContext check whether its in the top layer
      // is too slow, then we could actually repeat
      // MarkAncestorContextsHaveTopLayerElement in the next frame instead.
      context->ScheduleTopLayerCheck();
    }
    return;
  }

  if (MarkAncestorContextsHaveTopLayerElement(element)) {
    StyleEngine& style_engine = document_->GetStyleEngine();
    StyleEngine::DetachLayoutTreeScope detach_scope(style_engine);
    element->DetachLayoutTree();
  }
}

void DisplayLockDocumentState::ElementRemovedFromTopLayer(Element*) {
  // If flat tree traversal is forbidden, then we need to schedule an event to
  // do this work later.
  if (document_->IsFlatTreeTraversalForbidden() ||
      document_->GetSlotAssignmentEngine().HasPendingSlotAssignmentRecalc()) {
    for (auto context : display_lock_contexts_) {
      // If making every DisplayLockContext check whether its in the top layer
      // is too slow, then we could actually repeat
      // MarkAncestorContextsHaveTopLayerElement in the next frame instead.
      context->ScheduleTopLayerCheck();
    }
    return;
  }

  for (auto context : display_lock_contexts_)
    context->ClearHasTopLayerElement();
  // We don't use the given element here, but rather all elements that are still
  // in the top layer.
  for (auto element : document_->TopLayerElements())
    MarkAncestorContextsHaveTopLayerElement(element.Get());
}

bool DisplayLockDocumentState::MarkAncestorContextsHaveTopLayerElement(
    Element* element) {
  if (display_lock_contexts_.empty())
    return false;

  bool had_locked_ancestor = false;
  auto* ancestor = element;
  while ((ancestor = FlatTreeTraversal::ParentElement(*ancestor))) {
    if (auto* context = ancestor->GetDisplayLockContext()) {
      context->NotifyHasTopLayerElement();
      had_locked_ancestor |= context->IsLocked();
    }
  }
  return had_locked_ancestor;
}

void DisplayLockDocumentState::NotifyViewTransitionPseudoTreeChanged() {
  // Reset the view transition element flag.
  // TODO(vmpstr): This should be optimized to keep track of elements that
  // actually have this flag set.
  for (auto context : display_lock_contexts_)
    context->ResetDescendantIsViewTransitionElement();

  // Process the view transition elements to check if their ancestors are
  // locks that need to be made relevant.
  UpdateViewTransitionElementAncestorLocks();
}

void DisplayLockDocumentState::UpdateViewTransitionElementAncestorLocks() {
  auto* transition = ViewTransitionUtils::GetTransition(*document_);
  if (!transition)
    return;

  const auto& transitioning_elements = transition->GetTransitioningElements();
  for (auto element : transitioning_elements) {
    auto* ancestor = element.Get();
    // When the element which has c-v:auto is itself a view transition element,
    // we keep it locked. So start with the parent.
    while ((ancestor = FlatTreeTraversal::ParentElement(*ancestor))) {
      if (auto* context = ancestor->GetDisplayLockContext())
        context->SetDescendantIsViewTransitionElement();
    }
  }
}

void DisplayLockDocumentState::NotifySelectionRemoved() {
  for (auto context : display_lock_contexts_)
    context->NotifySubtreeLostSelection();
}

void DisplayLockDocumentState::BeginNodeForcedScope(
    const Node* node,
    bool self_was_forced,
    DisplayLockUtilities::ScopedForcedUpdate::Impl* impl) {
  forced_node_infos_.push_back(ForcedNodeInfo(node, self_was_forced, impl));
}

void DisplayLockDocumentState::BeginRangeForcedScope(
    const Range* range,
    DisplayLockUtilities::ScopedForcedUpdate::Impl* impl) {
  forced_range_infos_.push_back(ForcedRangeInfo(range, impl));
}

void DisplayLockDocumentState::EndForcedScope(
    DisplayLockUtilities::ScopedForcedUpdate::Impl* impl) {
  for (wtf_size_t i = 0; i < forced_node_infos_.size(); ++i) {
    if (forced_node_infos_[i].Chain() == impl) {
      forced_node_infos_.EraseAt(i);
      return;
    }
  }
  for (wtf_size_t i = 0; i < forced_range_infos_.size(); ++i) {
    if (forced_range_infos_[i].Chain() == impl) {
      forced_range_infos_.EraseAt(i);
      return;
    }
  }
  // We should always find a scope to erase.
  NOTREACHED();
}

void DisplayLockDocumentState::EnsureMinimumForcedPhase(
    DisplayLockContext::ForcedPhase phase) {
  for (auto& info : forced_node_infos_)
    info.Chain()->EnsureMinimumForcedPhase(phase);
  for (auto& info : forced_range_infos_)
    info.Chain()->EnsureMinimumForcedPhase(phase);
}

void DisplayLockDocumentState::ForceLockIfNeeded(Element* element) {
  DCHECK(element->GetDisplayLockContext());
  for (ForcedNodeInfo& info : forced_node_infos_)
    info.ForceLockIfNeeded(element);
  for (ForcedRangeInfo& info : forced_range_infos_)
    info.ForceLockIfNeeded(element);
}

void DisplayLockDocumentState::ForcedNodeInfo::ForceLockIfNeeded(
    Element* new_locked_element) {
  auto ancestor_view = self_forced_
                           ? FlatTreeTraversal::InclusiveAncestorsOf(*node_)
                           : FlatTreeTraversal::AncestorsOf(*node_);
  for (Node& ancestor : ancestor_view) {
    if (new_locked_element == &ancestor) {
      chain_->AddForcedUpdateScopeForContext(
          new_locked_element->GetDisplayLockContext());
      break;
    }
  }
}

void DisplayLockDocumentState::ForcedRangeInfo::ForceLockIfNeeded(
    Element* new_locked_element) {
  // TODO(crbug.com/1256849): Combine this with the range loop in
  //   DisplayLockUtilities::ScopedForcedUpdate::Impl::Impl.
  // Ranges use NodeTraversal::Next to go in between their start and end nodes,
  // and will access the layout information of each of those nodes. In order to
  // ensure that each of these nodes has unlocked layout information, we have to
  // do a scoped unlock for each of those nodes by unlocking all of their flat
  // tree ancestors.
  for (Node* node = range_->FirstNode(); node != range_->PastLastNode();
       node = NodeTraversal::Next(*node)) {
    if (node->IsChildOfShadowHost()) {
      // This node may be slotted into another place in the flat tree, so we
      // have to do a flat tree parent traversal for it.
      for (Node* ancestor = node; ancestor;
           ancestor = FlatTreeTraversal::Parent(*ancestor)) {
        if (ancestor == new_locked_element) {
          chain_->AddForcedUpdateScopeForContext(
              new_locked_element->GetDisplayLockContext());
          return;
        }
      }
    } else if (node == new_locked_element) {
      chain_->AddForcedUpdateScopeForContext(
          new_locked_element->GetDisplayLockContext());
      return;
    }
  }
  for (Node* node = range_->FirstNode(); node;
       node = FlatTreeTraversal::Parent(*node)) {
    if (node == new_locked_element) {
      chain_->AddForcedUpdateScopeForContext(
          new_locked_element->GetDisplayLockContext());
      return;
    }
  }
}

// ScopedForcedActivatableDisplayLocks implementation -----------
DisplayLockDocumentState::ScopedForceActivatableDisplayLocks::
    ScopedForceActivatableDisplayLocks(DisplayLockDocumentState* state)
    : state_(state) {
  if (++state_->activatable_display_locks_forced_ == 1) {
    for (auto context : state_->display_lock_contexts_) {
      if (context->HasElement()) {
        context->DidForceActivatableDisplayLocks();
      } else {
        // This used to be a DUMP_WILL_BE_NOTREACHED(), but the crash volume was
        // too high. See crbug.com/41494130
        DCHECK(false)
            << "The DisplayLockContext's element has been garbage collected or"
            << " otherwise deleted, but the DisplayLockContext is still alive!"
            << " This shouldn't happen and could cause a crash. See"
            << " crbug.com/1230206";
      }
    }
  }
}

DisplayLockDocumentState::ScopedForceActivatableDisplayLocks::
    ScopedForceActivatableDisplayLocks(
        ScopedForceActivatableDisplayLocks&& other)
    : state_(other.state_) {
  other.state_ = nullptr;
}

DisplayLockDocumentState::ScopedForceActivatableDisplayLocks&
DisplayLockDocumentState::ScopedForceActivatableDisplayLocks::operator=(
    ScopedForceActivatableDisplayLocks&& other) {
  state_ = other.state_;
  other.state_ = nullptr;
  return *this;
}

DisplayLockDocumentState::ScopedForceActivatableDisplayLocks::
    ~ScopedForceActivatableDisplayLocks() {
  if (!state_)
    return;
  DCHECK(state_->activatable_display_locks_forced_);
  --state_->activatable_display_locks_forced_;
}

void DisplayLockDocumentState::NotifyPrintingOrPreviewChanged() {
  bool was_printing = printing_;
  printing_ = document_->IsPrintingOrPaintingPreview();
  if (printing_ == was_printing)
    return;

  for (auto& context : display_lock_contexts_)
    context->SetShouldUnlockAutoForPrint(printing_);
}

void DisplayLockDocumentState::IssueForcedRenderWarning(Element* element) {
  // Note that this is a verbose level message, since it can happen
  // frequently and is not necessarily a problem if the developer is
  // accessing content-visibility: hidden subtrees intentionally.
  if (forced_render_warnings_ < kMaxConsoleMessages) {
    forced_render_warnings_++;
    auto level =
        RuntimeEnabledFeatures::WarnOnContentVisibilityRenderAccessEnabled()
            ? mojom::blink::ConsoleMessageLevel::kWarning
            : mojom::blink::ConsoleMessageLevel::kVerbose;
    element->AddConsoleMessage(
        mojom::blink::ConsoleMessageSource::kJavaScript, level,
        forced_render_warnings_ == kMaxConsoleMessages ? kForcedRenderingMax
                                                       : kForcedRendering);
  }
}

}  // namespace blink

"""

```