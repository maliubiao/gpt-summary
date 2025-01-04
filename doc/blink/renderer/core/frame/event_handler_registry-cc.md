Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Initial Understanding of the Request:**

The request asks for the functionalities of the `EventHandlerRegistry` class, its relation to web technologies (JavaScript, HTML, CSS), examples, logical inferences, and common usage errors. The core task is to understand what this class *does* within the Blink rendering engine.

**2. Decomposition of the Code - Identifying Key Components:**

I started by scanning the code for key elements and patterns:

* **Includes:**  These provide hints about the class's dependencies and purpose. Seeing includes like `v8_event_listener_options.h`, `event_util.h`, `local_dom_window.h`, `local_frame.h`, `html_frame_owner_element.h`, and `page/chrome_client.h` strongly suggests involvement with event handling, the DOM, frames, and communication with the browser's UI process.

* **Namespace:** `blink` confirms this is part of the Blink rendering engine.

* **Class Declaration:** `class EventHandlerRegistry` is the central focus.

* **Constructor/Destructor:** These are basic lifecycle management but don't reveal core functionality immediately. The destructor's loop with `CheckConsistency` hints at internal integrity checks.

* **Key Methods:**  This is where the core functionality resides. I looked for verbs indicating actions:
    * `EventTypeToClass`:  Mapping event types to internal categories.
    * `EventHandlerTargets`: Accessing registered targets.
    * `HasEventHandlers`: Checking for handlers.
    * `UpdateEventHandlerTargets`, `UpdateEventHandlerInternal`, `UpdateEventHandlerOfType`: Managing the storage of event handlers.
    * `DidAddEventHandler`, `DidRemoveEventHandler`, `DidMoveIntoPage`, `DidMoveOutOfPage`, `DidRemoveAllEventHandlers`: Public methods for registering and unregistering handlers in various scenarios.
    * `NotifyHandlersChanged`: A crucial method for informing other parts of the engine about changes in event handlers.
    * `Trace`, `ProcessCustomWeakness`: Related to memory management and garbage collection.
    * `DocumentDetached`: Handling the removal of event handlers when a document is detached.
    * `CheckConsistency`: Internal debugging/assertion logic.
    * `GetPage`: Accessing the associated page.

* **Data Members:** `frame_` (the associated frame) and `targets_` (the core storage for event handlers, a map-like structure).

* **Enums/Constants:** `EventHandlerClass` defines internal categories of event handlers, crucial for understanding the class's logic.

* **Helper Functions:** `GetEventListenerProperties` and `GetLocalFrameForTarget` provide supporting logic.

**3. Inferring Functionality - Connecting the Dots:**

Based on the identified components, I started inferring the class's role:

* **Centralized Event Handler Management:** The name `EventHandlerRegistry` and the methods for adding/removing handlers strongly suggest it's a central place to track event listeners within a frame.

* **Categorization of Event Listeners:** `EventTypeToClass` and `EventHandlerClass` indicate different types of event listeners are handled differently. The distinction between passive and blocking listeners (especially for scroll, wheel, and touch events) is a key observation, linked to performance optimization.

* **Communication with Compositor:**  The calls to `GetPage()->GetChromeClient().SetEventListenerProperties(...)` directly link this class to informing the compositor thread (responsible for smooth scrolling and rendering) about the presence and properties of event listeners. This explains the passive/blocking distinction's importance.

* **Lifecycle Management:** Methods like `DidMoveIntoPage`, `DidMoveOutOfPage`, and `DocumentDetached` show that the registry manages event listeners when DOM elements or entire documents are added or removed from the page.

* **Memory Management:** `Trace` and `ProcessCustomWeakness` are standard Blink patterns for handling object lifecycle and preventing dangling pointers in a garbage-collected environment.

**4. Relating to Web Technologies:**

Once the internal functionality was clearer, I could connect it to JavaScript, HTML, and CSS:

* **JavaScript:** The core connection is with JavaScript's `addEventListener` and `removeEventListener`. This class is the underlying mechanism that Blink uses to track these listeners. The passive/blocking distinction directly relates to options passed to `addEventListener`.

* **HTML:** The targets of event listeners are HTML elements (or the `window` or `document`). The `EventHandlerRegistry` stores these relationships.

* **CSS:** While less direct, CSS properties like `touch-action` can influence the behavior of touch event listeners. The `MarkEffectiveAllowedTouchActionChanged` calls suggest an interaction where changes in event listeners might require recalculating layout and style information.

**5. Constructing Examples and Logical Inferences:**

With a good understanding of the code, I could create concrete examples:

* **Passive vs. Blocking:**  Demonstrating the impact of the `passive` option on scroll and touch events.
* **Event Delegation:** How event listeners on parent elements can be tracked.
* **Dynamic Addition/Removal:**  Showing how adding/removing listeners updates the registry.

For logical inferences, I focused on the input and output of key methods, especially `EventTypeToClass` and `NotifyHandlersChanged`.

**6. Identifying Common Usage Errors:**

This involved thinking about how developers might misuse event listeners and how this class might be affected:

* **Memory Leaks (Indirectly):**  While the registry itself manages memory, failing to remove event listeners in JavaScript can lead to memory leaks, and this class would be tracking those orphaned listeners.
* **Performance Issues:** Overuse of blocking listeners, especially on scroll/touch, is a common performance problem, and the registry plays a role in informing the browser about these potential bottlenecks.
* **Incorrect Passive/Blocking Usage:** Misunderstanding the implications of passive listeners.

**7. Structuring the Answer:**

Finally, I organized the information into clear categories (Functionality, Relationship to Web Technologies, Logical Inferences, Common Errors) with bullet points and examples to make it easy to understand. I aimed for a balance between technical detail and clear explanations.

**Self-Correction/Refinement:**

During the process, I might have initially missed some connections. For instance, the significance of `MarkEffectiveAllowedTouchActionChanged` might not be immediately obvious. By carefully examining the context (within the `NotifyHandlersChanged` method for touch events), I could infer its relationship to layout and the `touch-action` CSS property. Similarly, understanding the interaction with the `ChromeClient` required recognizing that it's a bridge to the browser's UI process and compositor.
This C++ source code file, `event_handler_registry.cc`, within the Chromium Blink rendering engine, is responsible for **managing and tracking event listeners** within a specific `LocalFrame`. It acts as a central registry to keep track of which event targets (like DOM nodes or the window) have which types of event listeners attached.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Registration and Tracking of Event Listeners:**
   - It maintains a collection (`targets_`) that maps different categories of event listeners (`EventHandlerClass`) to sets of `EventTarget` objects that have listeners of that category.
   - It uses methods like `DidAddEventHandler` and `DidRemoveEventHandler` to update this registry when JavaScript code adds or removes event listeners using `addEventListener` or `removeEventListener`.

2. **Categorization of Event Listeners:**
   - It categorizes event listeners into different `EventHandlerClass` based on the event type and listener options (e.g., passive or blocking). This is done in the `EventTypeToClass` method.
   - Key distinctions are made for:
     - **Scroll Events:**  Separate tracking for scroll event listeners.
     - **Wheel Events:**  Distinguishes between passive and blocking wheel event listeners. Passive listeners indicate they won't prevent scrolling, allowing for smoother performance.
     - **Touch Events:**  Similar to wheel events, it separates passive and blocking touch start/move and end/cancel listeners. It also tracks `touch-action` CSS property implications.
     - **Pointer Events:** Handles generic pointer events.
     - **Pointer Raw Update Events:** A specific type of pointer event handled differently for optimization.

3. **Communication with the Compositor Thread:**
   - A crucial role is to inform the compositor thread (which handles rendering and scrolling) about the presence and properties (passive/blocking) of certain event listeners.
   - The `NotifyHandlersChanged` method is responsible for this, using the `ChromeClient` interface to call methods like `SetHasScrollEventHandlers` and `SetEventListenerProperties`. This is vital for performance optimization, especially for touch and scroll interactions. The compositor can make decisions about how to handle input events based on whether there are blocking listeners.

4. **Handling Document Detachment:**
   - The `DocumentDetached` method ensures that event listeners attached to nodes within a detached document are properly removed from the registry. This prevents leaks and ensures consistency.

5. **Handling Events When Elements Move In/Out of the Page:**
   - `DidMoveIntoPage` and `DidMoveOutOfPage` ensure that the registry is updated when elements are added to or removed from the live DOM tree.

6. **Memory Management:**
   - The `Trace` and `ProcessCustomWeakness` methods are part of Blink's garbage collection mechanism. They help to ensure that the `EventHandlerRegistry` doesn't hold onto dead `EventTarget` objects, preventing memory leaks.

**Relationship with JavaScript, HTML, and CSS:**

This file is a core part of how Blink implements the event handling mechanisms exposed to JavaScript, and it interacts with the underlying HTML structure and, to a lesser extent, CSS.

**Examples:**

* **JavaScript `addEventListener` with passive option:**
   ```javascript
   document.getElementById('myDiv').addEventListener('wheel', function(event) {
       // Handle wheel event
   }, { passive: true });
   ```
   - **Functionality:** When this JavaScript code is executed, the `EventHandlerRegistry::DidAddEventHandler` method will be called. The `EventTypeToClass` method will categorize this as `kWheelEventPassive` because the `passive` option is set to `true`. The `EventHandlerRegistry` will then inform the compositor that there's a passive wheel event listener on this element.

* **JavaScript `addEventListener` without passive option (blocking):**
   ```javascript
   document.getElementById('myDiv').addEventListener('touchstart', function(event) {
       event.preventDefault(); // Prevents default scrolling
   });
   ```
   - **Functionality:**  In this case, `EventTypeToClass` will likely categorize this as `kTouchStartOrMoveEventBlocking` (or potentially `kTouchStartOrMoveEventBlockingLowLatency` depending on other factors). The `EventHandlerRegistry` will notify the compositor that there's a blocking touchstart listener, which might impact scrolling performance.

* **HTML Structure and Event Delegation:**
   ```html
   <div id="parent">
       <button id="child1">Button 1</button>
       <button id="child2">Button 2</button>
   </div>
   <script>
       document.getElementById('parent').addEventListener('click', function(event) {
           console.log('Parent clicked, target:', event.target.id);
       });
   </script>
   ```
   - **Functionality:** The `EventHandlerRegistry` will track the 'click' listener on the `parent` div. When a click occurs on either `child1` or `child2`, the event will bubble up to the `parent`, and the registered listener will be triggered. The `EventHandlerRegistry` ensures this listener is active and ready to handle the event.

* **CSS `touch-action` Property:**
   ```css
   #scrollable {
       touch-action: pan-y;
   }
   ```
   - **Functionality:** While this file doesn't directly parse CSS, the presence of `touch-action` can influence how touch events are handled. The `NotifyHandlersChanged` method considers the `HasEventHandlers(kTouchAction)` check, suggesting that the registry is aware of whether the `touch-action` CSS property is affecting any elements within the frame.

**Logical Inferences (Hypothetical):**

Let's consider a scenario where we add and remove a passive scroll listener:

* **Assumption:** We have an HTML element with ID `scrollableDiv`.
* **Input (JavaScript):**
   ```javascript
   const div = document.getElementById('scrollableDiv');
   const scrollHandler = function() { console.log('Scrolled!'); };
   div.addEventListener('scroll', scrollHandler, { passive: true });
   ```
* **Output (Internal State of `EventHandlerRegistry`):**
   - The `targets_[kScrollEvent]` set will now contain the `EventTarget` corresponding to the `scrollableDiv`.
   - `GetPage()->GetChromeClient().SetHasScrollEventHandlers(frame, true)` will likely be called, informing the compositor about the presence of a scroll listener.

* **Input (JavaScript):**
   ```javascript
   div.removeEventListener('scroll', scrollHandler, { passive: true });
   ```
* **Output (Internal State of `EventHandlerRegistry`):**
   - The `scrollableDiv`'s `EventTarget` will be removed from `targets_[kScrollEvent]`.
   - If this was the last scroll listener in the frame, `GetPage()->GetChromeClient().SetHasScrollEventHandlers(frame, false)` will be called.

**Common Usage Errors (from a developer perspective, impacting this code):**

1. **Forgetting to remove event listeners:** If JavaScript code adds event listeners but doesn't remove them when they are no longer needed, the `EventHandlerRegistry` will continue to track them. This can lead to memory leaks (as the associated JavaScript functions might be kept alive) and potentially unexpected behavior. The `ProcessCustomWeakness` mechanism helps mitigate this within Blink's internal memory management.

2. **Overuse of blocking event listeners (especially for touch and wheel):** Developers might not realize the performance implications of not using the `passive` option for scroll, wheel, and touch events. This can lead to janky scrolling and a poor user experience. The `EventHandlerRegistry` plays a role in informing the browser about these potentially performance- Bottlenecking listeners.

3. **Incorrectly assuming event listener behavior without understanding passive/blocking:** Developers might expect `preventDefault()` to always work in event listeners, but if a passive listener is registered, `preventDefault()` will have no effect. The categorization in `EventHandlerRegistry` is crucial for enforcing this behavior.

4. **Attaching the same listener multiple times:** While the browser usually prevents adding the exact same listener multiple times to the same target, developers might unintentionally add conceptually similar listeners, leading to duplicate event handling. The `EventHandlerRegistry` would track each unique listener.

In summary, `event_handler_registry.cc` is a foundational component in Blink's event handling system. It acts as a meticulous record-keeper of event listeners, enabling efficient event dispatch and crucial communication with the compositor thread for optimized rendering and user interaction. It bridges the gap between JavaScript's event handling API and the underlying C++ rendering engine.

Prompt: 
```
这是目录为blink/renderer/core/frame/event_handler_registry.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/event_handler_registry.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_event_listener_options.h"
#include "third_party/blink/renderer/core/dom/events/add_event_listener_options_resolved.h"
#include "third_party/blink/renderer/core/events/event_util.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scrolling/scrolling_coordinator.h"
#include "third_party/blink/renderer/platform/heap/thread_state_scopes.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"

namespace blink {

namespace {

cc::EventListenerProperties GetEventListenerProperties(bool has_blocking,
                                                       bool has_passive) {
  if (has_blocking && has_passive)
    return cc::EventListenerProperties::kBlockingAndPassive;
  if (has_blocking)
    return cc::EventListenerProperties::kBlocking;
  if (has_passive)
    return cc::EventListenerProperties::kPassive;
  return cc::EventListenerProperties::kNone;
}

LocalFrame* GetLocalFrameForTarget(EventTarget* target) {
  LocalFrame* frame = nullptr;
  if (Node* node = target->ToNode()) {
    frame = node->GetDocument().GetFrame();
  } else if (LocalDOMWindow* dom_window = target->ToLocalDOMWindow()) {
    frame = dom_window->GetFrame();
  } else {
    NOTREACHED() << "Unexpected target type for event handler.";
  }
  return frame;
}

}  // namespace

EventHandlerRegistry::EventHandlerRegistry(LocalFrame& frame) : frame_(frame) {}

EventHandlerRegistry::~EventHandlerRegistry() {
  for (int i = 0; i < kEventHandlerClassCount; ++i) {
    EventHandlerClass handler_class = static_cast<EventHandlerClass>(i);
    CheckConsistency(handler_class);
  }
}

bool EventHandlerRegistry::EventTypeToClass(
    const AtomicString& event_type,
    const AddEventListenerOptions* options,
    EventHandlerClass* result) {
  if (event_type == event_type_names::kScroll) {
    *result = kScrollEvent;
  } else if (event_type == event_type_names::kWheel ||
             event_type == event_type_names::kMousewheel) {
    *result = options->passive() ? kWheelEventPassive : kWheelEventBlocking;
  } else if (event_type == event_type_names::kTouchend ||
             event_type == event_type_names::kTouchcancel) {
    *result = options->passive() ? kTouchEndOrCancelEventPassive
                                 : kTouchEndOrCancelEventBlocking;
  } else if (event_type == event_type_names::kTouchstart ||
             event_type == event_type_names::kTouchmove) {
    *result = options->passive() ? kTouchStartOrMoveEventPassive
                                 : kTouchStartOrMoveEventBlocking;
  } else if (event_type == event_type_names::kPointerrawupdate) {
    // This will be used to avoid waking up the main thread to
    // process pointerrawupdate events and hit-test them when
    // there is no listener on the page.
    *result = kPointerRawUpdateEvent;
  } else if (event_util::IsPointerEventType(event_type)) {
    // The pointer events never block scrolling and the compositor
    // only needs to know about the touch listeners.
    *result = kPointerEvent;
#if DCHECK_IS_ON()
  } else if (event_type == event_type_names::kLoad ||
             event_type == event_type_names::kMousemove ||
             event_type == event_type_names::kTouchstart) {
    *result = kEventsForTesting;
#endif
  } else {
    return false;
  }
  return true;
}

const EventTargetSet* EventHandlerRegistry::EventHandlerTargets(
    EventHandlerClass handler_class) const {
  CheckConsistency(handler_class);
  return &targets_[handler_class];
}

bool EventHandlerRegistry::HasEventHandlers(
    EventHandlerClass handler_class) const {
  CheckConsistency(handler_class);
  return targets_[handler_class].size();
}

void EventHandlerRegistry::UpdateEventHandlerTargets(
    ChangeOperation op,
    EventHandlerClass handler_class,
    EventTarget* target) {
  EventTargetSet* targets = &targets_[handler_class];
  switch (op) {
    case kAdd:
      targets->insert(target);
      return;
    case kRemove:
      DCHECK(targets->Contains(target));
      targets->erase(target);
      return;
    case kRemoveAll:
      targets->RemoveAll(target);
      return;
  }
  NOTREACHED();
}

bool EventHandlerRegistry::UpdateEventHandlerInternal(
    ChangeOperation op,
    EventHandlerClass handler_class,
    EventTarget* target) {
  unsigned old_num_handlers = targets_[handler_class].size();
  UpdateEventHandlerTargets(op, handler_class, target);
  unsigned new_num_handlers = targets_[handler_class].size();

  bool handlers_changed = old_num_handlers != new_num_handlers;
  if (op != kRemoveAll && handlers_changed)
    NotifyHandlersChanged(target, handler_class, new_num_handlers > 0);

  return handlers_changed;
}

void EventHandlerRegistry::UpdateEventHandlerOfType(
    ChangeOperation op,
    const AtomicString& event_type,
    const AddEventListenerOptions* options,
    EventTarget* target) {
  EventHandlerClass handler_class;
  if (!EventTypeToClass(event_type, options, &handler_class))
    return;
  UpdateEventHandlerInternal(op, handler_class, target);
}

void EventHandlerRegistry::DidAddEventHandler(
    EventTarget& target,
    const AtomicString& event_type,
    const AddEventListenerOptions* options) {
  UpdateEventHandlerOfType(kAdd, event_type, options, &target);
}

void EventHandlerRegistry::DidRemoveEventHandler(
    EventTarget& target,
    const AtomicString& event_type,
    const AddEventListenerOptions* options) {
  UpdateEventHandlerOfType(kRemove, event_type, options, &target);
}

void EventHandlerRegistry::DidAddEventHandler(EventTarget& target,
                                              EventHandlerClass handler_class) {
  UpdateEventHandlerInternal(kAdd, handler_class, &target);
}

void EventHandlerRegistry::DidRemoveEventHandler(
    EventTarget& target,
    EventHandlerClass handler_class) {
  UpdateEventHandlerInternal(kRemove, handler_class, &target);
}

void EventHandlerRegistry::DidMoveIntoPage(EventTarget& target) {
  if (!target.HasEventListeners())
    return;

  // This code is not efficient at all.
  Vector<AtomicString> event_types = target.EventTypes();
  for (wtf_size_t i = 0; i < event_types.size(); ++i) {
    EventListenerVector* listeners = target.GetEventListeners(event_types[i]);
    if (!listeners)
      continue;
    for (wtf_size_t count = listeners->size(); count > 0; --count) {
      EventHandlerClass handler_class;
      if (!EventTypeToClass(event_types[i], (*listeners)[count - 1]->Options(),
                            &handler_class)) {
        continue;
      }

      DidAddEventHandler(target, handler_class);
    }
  }
}

void EventHandlerRegistry::DidMoveOutOfPage(EventTarget& target) {
  DidRemoveAllEventHandlers(target);
}

void EventHandlerRegistry::DidRemoveAllEventHandlers(EventTarget& target) {
  std::array<bool, kEventHandlerClassCount> handlers_changed;

  for (int i = 0; i < kEventHandlerClassCount; ++i) {
    EventHandlerClass handler_class = static_cast<EventHandlerClass>(i);
    handlers_changed[i] =
        UpdateEventHandlerInternal(kRemoveAll, handler_class, &target);
  }

  for (int i = 0; i < kEventHandlerClassCount; ++i) {
    EventHandlerClass handler_class = static_cast<EventHandlerClass>(i);
    if (handlers_changed[i]) {
      bool has_handlers = targets_[handler_class].Contains(&target);
      NotifyHandlersChanged(&target, handler_class, has_handlers);
    }
  }
}

void EventHandlerRegistry::NotifyHandlersChanged(
    EventTarget* target,
    EventHandlerClass handler_class,
    bool has_active_handlers) {
  LocalFrame* frame = GetLocalFrameForTarget(target);

  // TODO(keishi): Added for crbug.com/1090687. Change to CHECK once bug is
  // fixed.
  if (!GetPage())
    return;

  switch (handler_class) {
    case kScrollEvent:
      GetPage()->GetChromeClient().SetHasScrollEventHandlers(
          frame, has_active_handlers);
      break;
    case kWheelEventBlocking:
    case kWheelEventPassive:
      GetPage()->GetChromeClient().SetEventListenerProperties(
          frame, cc::EventListenerClass::kMouseWheel,
          GetEventListenerProperties(HasEventHandlers(kWheelEventBlocking),
                                     HasEventHandlers(kWheelEventPassive)));
      break;
    case kTouchStartOrMoveEventBlockingLowLatency:
      GetPage()->GetChromeClient().SetNeedsLowLatencyInput(frame,
                                                           has_active_handlers);
      [[fallthrough]];
    case kTouchAction:
    case kTouchStartOrMoveEventBlocking:
    case kTouchStartOrMoveEventPassive:
    case kPointerEvent:
      GetPage()->GetChromeClient().SetEventListenerProperties(
          frame, cc::EventListenerClass::kTouchStartOrMove,
          GetEventListenerProperties(
              HasEventHandlers(kTouchAction) ||
                  HasEventHandlers(kTouchStartOrMoveEventBlocking) ||
                  HasEventHandlers(kTouchStartOrMoveEventBlockingLowLatency),
              HasEventHandlers(kTouchStartOrMoveEventPassive) ||
                  HasEventHandlers(kPointerEvent)));
      break;
    case kPointerRawUpdateEvent:
      GetPage()->GetChromeClient().SetEventListenerProperties(
          frame, cc::EventListenerClass::kPointerRawUpdate,
          GetEventListenerProperties(false,
                                     HasEventHandlers(kPointerRawUpdateEvent)));
      break;
    case kTouchEndOrCancelEventBlocking:
    case kTouchEndOrCancelEventPassive:
      GetPage()->GetChromeClient().SetEventListenerProperties(
          frame, cc::EventListenerClass::kTouchEndOrCancel,
          GetEventListenerProperties(
              HasEventHandlers(kTouchEndOrCancelEventBlocking),
              HasEventHandlers(kTouchEndOrCancelEventPassive)));
      break;
#if DCHECK_IS_ON()
    case kEventsForTesting:
      break;
#endif
    default:
      NOTREACHED();
  }

  if (handler_class == kTouchStartOrMoveEventBlocking ||
      handler_class == kTouchStartOrMoveEventBlockingLowLatency) {
    if (auto* node = target->ToNode()) {
      if (auto* layout_object = node->GetLayoutObject()) {
        layout_object->MarkEffectiveAllowedTouchActionChanged();
      }
    } else if (auto* dom_window = target->ToLocalDOMWindow()) {
      // This event handler is on a window. Ensure the layout view is
      // invalidated because the layout view tracks the window's blocking
      // touch event rects.
      if (auto* layout_view = dom_window->GetFrame()->ContentLayoutObject())
        layout_view->MarkEffectiveAllowedTouchActionChanged();
    }
  } else if (handler_class == kWheelEventBlocking) {
    if (auto* node = target->ToNode()) {
      if (auto* layout_object = node->GetLayoutObject()) {
        layout_object->MarkBlockingWheelEventHandlerChanged();
      }
    } else if (auto* dom_window = target->ToLocalDOMWindow()) {
      // This event handler is on a window. Ensure the layout view is
      // invalidated because the layout view tracks the window's blocking
      // wheel event handler rects.
      if (auto* layout_view = dom_window->GetFrame()->ContentLayoutObject())
        layout_view->MarkBlockingWheelEventHandlerChanged();
    }
  }
}

void EventHandlerRegistry::Trace(Visitor* visitor) const {
  visitor->Trace(frame_);
  visitor->template RegisterWeakCallbackMethod<
      EventHandlerRegistry, &EventHandlerRegistry::ProcessCustomWeakness>(this);
}

void EventHandlerRegistry::ProcessCustomWeakness(const LivenessBroker& info) {
  // We use Vector<UntracedMember<>> here to avoid BlinkGC allocation in a
  // custom weak callback.
  Vector<UntracedMember<EventTarget>> dead_targets;
  for (int i = 0; i < kEventHandlerClassCount; ++i) {
    EventHandlerClass handler_class = static_cast<EventHandlerClass>(i);
    const EventTargetSet* targets = &targets_[handler_class];
    for (const auto& event_target : *targets) {
      Node* node = event_target.key->ToNode();
      LocalDOMWindow* window = event_target.key->ToLocalDOMWindow();
      if (node && !info.IsHeapObjectAlive(node)) {
        dead_targets.push_back(node);
      } else if (window && !info.IsHeapObjectAlive(window)) {
        dead_targets.push_back(window);
      }
    }
  }
  for (wtf_size_t i = 0; i < dead_targets.size(); ++i)
    DidRemoveAllEventHandlers(*dead_targets[i]);
}

void EventHandlerRegistry::DocumentDetached(Document& document) {
  // Remove all event targets under the detached document.
  for (int handler_class_index = 0;
       handler_class_index < kEventHandlerClassCount; ++handler_class_index) {
    EventHandlerClass handler_class =
        static_cast<EventHandlerClass>(handler_class_index);
    HeapVector<Member<EventTarget>> targets_to_remove;
    {
      // TODO(keishi): If a GC happens while iterating a EventTargetSet, the
      // custom weak processing may remove elements from it. Remove this scope
      // when we get rid of the custom weak processing. crbug.com/1235316
      ThreadState::GCForbiddenScope gc_forbidden(ThreadState::Current());
      const EventTargetSet* targets = &targets_[handler_class];
      for (const auto& event_target : *targets) {
        if (Node* node = event_target.key->ToNode()) {
          for (Document* doc = &node->GetDocument(); doc;
               doc = doc->LocalOwner() ? &doc->LocalOwner()->GetDocument()
                                       : nullptr) {
            if (doc == &document) {
              targets_to_remove.push_back(event_target.key);
              break;
            }
          }
        } else if (event_target.key->ToLocalDOMWindow()) {
          // DOMWindows may outlive their documents, so we shouldn't remove
          // their handlers here.
        } else {
          NOTREACHED();
        }
      }
    }
    for (wtf_size_t i = 0; i < targets_to_remove.size(); ++i)
      UpdateEventHandlerInternal(kRemoveAll, handler_class,
                                 targets_to_remove[i]);
  }
}

void EventHandlerRegistry::CheckConsistency(
    EventHandlerClass handler_class) const {
#if DCHECK_IS_ON()
  // TODO(keishi): If a GC happens while iterating a EventTargetSet, the
  // custom weak processing may remove elements from it. Remove this scope
  // when we get rid of the custom weak processing. crbug.com/1235316
  ThreadState::GCForbiddenScope gc_forbidden(ThreadState::Current());
  const EventTargetSet* targets = &targets_[handler_class];
  for (const auto& event_target : *targets) {
    if (Node* node = event_target.key->ToNode()) {
      // See the header file comment for |documentDetached| if either of these
      // assertions fails.
      DCHECK(node->GetDocument().GetPage());
      DCHECK_EQ(frame_, &node->GetDocument().GetFrame()->LocalFrameRoot());
    } else if (LocalDOMWindow* window = event_target.key->ToLocalDOMWindow()) {
      // If any of these assertions fail, LocalDOMWindow failed to unregister
      // its handlers properly.
      DCHECK(window->GetFrame());
      DCHECK(window->GetFrame()->GetPage());
      DCHECK_EQ(frame_, &window->GetFrame()->LocalFrameRoot());
    }
  }
#endif  // DCHECK_IS_ON()
}

Page* EventHandlerRegistry::GetPage() const {
  DCHECK(frame_->GetPage());
  return frame_->GetPage();
}

}  // namespace blink

"""

```