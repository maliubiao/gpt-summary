Response:
Let's break down the thought process for analyzing the `DOMViewTransition.cc` file.

**1. Understanding the Core Purpose:**

The filename `dom_view_transition.cc` immediately suggests it's related to view transitions within the DOM. The inclusion of `ViewTransition` in the includes and class name reinforces this. The copyright notice confirms it's part of Chromium's Blink rendering engine. The fundamental goal is to manage the lifecycle and state of a view transition.

**2. Identifying Key Components and Relationships:**

* **`DOMViewTransition` Class:** This is the central class. It likely acts as an interface between the core view transition mechanism and the JavaScript/DOM world.
* **`ViewTransition` Class:** The inclusion of its header implies `DOMViewTransition` interacts with a lower-level `ViewTransition` class that handles the actual visual transition logic.
* **Promises:** The use of `ScriptPromise`, `PromiseProperty` is prominent. This indicates asynchronous operations and the need to signal completion/failure to JavaScript. The promises `finished`, `ready`, and `updateCallbackDone` are the main communication channels.
* **Callbacks:** The `update_dom_callback_` suggests a JavaScript function is involved in updating the DOM during the transition.
* **Execution Context:**  The class inherits from `ExecutionContextLifecycleObserver`, showing it's tied to the lifecycle of a JavaScript execution context.

**3. Analyzing the Constructor(s):**

The constructors reveal how `DOMViewTransition` is instantiated. The first constructor handles cross-document navigations where the DOM update is implicitly handled by the navigation itself. The second constructor is the general case, taking an `update_dom_callback`.

**4. Examining Key Methods and Their Interactions:**

* **`skipTransition()`:**  A straightforward method to immediately stop the transition.
* **`finished()`, `ready()`, `updateCallbackDone()`:** These methods return promises, providing access to the different stages of the transition lifecycle. Thinking about when each promise resolves/rejects is crucial.
* **`DidSkipTransition()`:** This is called when the underlying `ViewTransition` is skipped. It handles rejecting the `ready` promise and resolving/rejecting the `finished` promise based on whether the DOM update callback has run.
* **`NotifyDOMCallbackFinished()`, `NotifyDOMCallbackRejected()`:** These are called after the JavaScript `update_dom_callback` completes successfully or fails, respectively. They update the state of the promises.
* **`DidStartAnimating()`, `DidFinishAnimating()`:** These methods resolve the `ready` and `finished` promises, signaling the start and end of the visual animation.
* **`InvokeDOMChangeCallback()`:** This is the core logic for executing the JavaScript callback. It handles potential errors during invocation and manages the promises associated with the callback.
* **`AtMicrotask()`, `HandlePromise()`:** These methods manage the asynchronous resolution/rejection of promises, ensuring they happen in the correct order.

**5. Inferring Functionality and Relationships to Web Technologies:**

Based on the method names and promise interactions, we can infer the following:

* **JavaScript Interaction:** The `update_dom_callback` is a direct link to JavaScript. The promises returned by the `finished`, `ready`, and `updateCallbackDone` methods are also JavaScript-accessible.
* **HTML Interaction:** The `update_dom_callback` is meant to modify the HTML structure or attributes. The entire purpose of view transitions is to provide a smooth visual change between different states of the HTML.
* **CSS Interaction:** While not directly evident in this file, view transitions rely heavily on CSS animations and transitions to create the visual effects. The `ViewTransition` class (not shown here) likely interacts with CSS properties. The tags applied via JavaScript in the callback (e.g., `::view-transition-group()`) are CSS selectors.

**6. Developing Examples and Use Cases:**

With an understanding of the core functionality, it's possible to create illustrative examples.

* **Basic Success Case:** A simple transition where the callback updates the DOM, and the transition animates smoothly.
* **Skipped Transition:**  Demonstrating how `skipTransition()` works.
* **Callback Error:** Showing how an error in the JavaScript callback affects the promises.
* **Timeout:**  Thinking about scenarios where the DOM update might take too long.
* **Invalid State:** Considering situations where the transition might be aborted due to internal inconsistencies.

**7. Identifying Potential User/Programming Errors:**

By considering how developers might interact with this API, common mistakes become apparent.

* **Forgetting `await`:**  A classic JavaScript asynchronous programming mistake.
* **Modifying the DOM outside the callback:**  Understanding the timing of the callback is crucial.
* **Throwing errors in the callback:**  Knowing how errors are propagated is important.
* **Confusing promise resolution order:** The order of `ready` and `finished` promise resolution needs to be understood.

**8. Structuring the Answer:**

Finally, the information needs to be organized logically. Starting with a general overview of the file's purpose, then detailing specific functionalities, and finally addressing the connections to web technologies, examples, and potential errors makes for a comprehensive and easy-to-understand explanation. Using headings and bullet points improves readability.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the low-level details of promise management. Stepping back to consider the overall user experience and how this code enables view transitions in the browser is important.
*  Realizing that the `ViewTransition` class handles the actual animation logic helps clarify the division of responsibilities.
* Emphasizing the *asynchronous* nature of the operations and the role of promises in managing this is key.

By following these steps, we can effectively analyze and explain the functionality of a complex source code file like `DOMViewTransition.cc`.
This C++ source code file, `dom_view_transition.cc`, within the Chromium Blink rendering engine, implements the `DOMViewTransition` class. This class is a crucial part of the **View Transitions API**, a web platform feature that enables smooth visual transitions between different DOM states.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Manages the lifecycle of a view transition:**  The `DOMViewTransition` object represents a single view transition initiated by JavaScript. It tracks the different stages of the transition, from its initiation to its completion or abortion.

2. **Acts as an intermediary between JavaScript and the core view transition mechanism:** It provides a JavaScript-accessible interface (`DOMViewTransition` object) to control and observe the progress of the transition managed by the internal `ViewTransition` object.

3. **Handles the DOM update callback:**  When a view transition starts, an optional JavaScript callback function is executed. `DOMViewTransition` is responsible for invoking this callback and handling its outcome (success or failure).

4. **Manages Promises related to the transition:** It exposes three key promises to JavaScript:
    * **`ready` promise:** Resolves when the browser has captured the "before" state of the transition and is ready to apply the DOM updates.
    * **`updateCallbackDone` promise:** Resolves when the JavaScript DOM update callback has finished executing successfully. Rejects if the callback throws an error.
    * **`finished` promise:** Resolves when the visual transition animation is complete. Rejects if the transition is skipped or aborted.

5. **Handles transition skipping/abortion:** It provides a `skipTransition()` method that allows JavaScript to immediately stop the ongoing transition. It also handles cases where the transition is aborted due to errors or timeouts.

6. **Notifies the core `ViewTransition` about DOM callback completion:**  It informs the underlying `ViewTransition` object whether the DOM update callback succeeded or failed.

**Relationship with JavaScript, HTML, and CSS:**

`DOMViewTransition` is tightly coupled with JavaScript, HTML, and CSS in the context of the View Transitions API:

* **JavaScript:**
    * **Initiation:** The view transition is initiated from JavaScript using `document.startViewTransition()`, which creates a `DOMViewTransition` object internally.
    * **DOM Update Callback:**  JavaScript provides a callback function to `document.startViewTransition()`. This callback is invoked by `DOMViewTransition` to modify the DOM to the new state.
    * **Promise Consumption:** JavaScript code uses the `finished`, `ready`, and `updateCallbackDone` promises to synchronize with the transition lifecycle and perform actions after specific stages.
    * **Skipping:** JavaScript can call the `skipTransition()` method.

    **Example:**

    ```javascript
    const vt = document.startViewTransition(async () => {
      // This is the update DOM callback.
      document.querySelector('#content').textContent = 'New Content!';
      await new Promise(resolve => setTimeout(resolve, 100)); // Simulate some async work
    });

    vt.ready.then(() => {
      console.log('View transition is ready.');
    });

    vt.finished.then(() => {
      console.log('View transition finished.');
    });

    vt.updateCallbackDone.then(() => {
      console.log('DOM update callback completed.');
    });
    ```

* **HTML:**
    * **DOM Manipulation:** The core purpose of the DOM update callback is to modify the HTML structure or attributes. The `DOMViewTransition` ensures this callback is executed at the appropriate time during the transition.
    * **View Transition Names:**  While not directly managed by this file, HTML elements can be given `view-transition-name` CSS property values. This helps the browser identify corresponding elements between the old and new states for creating smooth animations.

* **CSS:**
    * **Animation/Transition Styles:** The visual transition effects (fades, slides, etc.) are primarily driven by CSS animations and transitions. The browser automatically generates these based on the differences between the old and new DOM states and the presence of `view-transition-name` properties.
    * **Pseudo-elements:** The View Transitions API creates pseudo-elements like `::view-transition-group()` to facilitate the animation process.

**Logical Reasoning (Hypothetical Input & Output):**

Let's imagine a scenario where a JavaScript call initiates a view transition with a provided callback:

**Hypothetical Input:**

* **JavaScript Call:**
  ```javascript
  const vt = document.startViewTransition(() => {
    document.getElementById('myElement').classList.add('new-state');
  });
  ```
* **`DOMViewTransition` Object Creation:** A `DOMViewTransition` object is created internally, associated with this transition.
* **Initial State:** The `ready_promise_property_`, `dom_updated_promise_property_`, and `finished_promise_property_` are in a pending state.

**Logical Flow & Potential Outputs:**

1. **`ready` Promise Resolution:**  Once the browser has captured the initial state, `DidStartAnimating()` is called, and the `ready_promise_property_` resolves. **Output (to JavaScript):** The `vt.ready` promise resolves.

2. **DOM Update Callback Invocation:** `InvokeDOMChangeCallback()` is called. It executes the provided JavaScript callback.

3. **Callback Success:** If the callback executes without throwing errors, `DOMChangeFinishedCallback::React()` is invoked, leading to `NotifyDOMCallbackFinished()`. This resolves `dom_updated_promise_property_`. **Output (to JavaScript):** The `vt.updateCallbackDone` promise resolves.

4. **Visual Animation:** The browser performs the visual animation based on the DOM changes and CSS.

5. **`finished` Promise Resolution:** Once the animation is complete, `DidFinishAnimating()` is called, and `finished_promise_property_` resolves. **Output (to JavaScript):** The `vt.finished` promise resolves.

6. **Callback Failure:** If the JavaScript callback throws an error, `DOMChangeRejectedCallback::React()` is invoked, leading to `NotifyDOMCallbackRejected()`. This rejects both `dom_updated_promise_property_` and `ready_promise_property_` (if not already resolved), and also rejects `finished_promise_property_`. **Output (to JavaScript):** The `vt.updateCallbackDone`, `vt.ready` (if pending), and `vt.finished` promises are rejected with the error.

7. **Transition Skipped:** If `skipTransition()` is called, `DidSkipTransition()` is invoked. This will reject `ready_promise_property_` (if pending) and resolve `finished_promise_property_` if the DOM callback was successful, or propagate the rejection from `dom_updated_promise_property_` if the callback failed or hadn't run yet.

**User and Programming Common Usage Errors:**

1. **Forgetting to `await` promises:** Developers might forget to use `await` or `.then()` on the promises returned by `document.startViewTransition()`, leading to code executing before the transition is ready or finished.

   **Example:**

   ```javascript
   document.startViewTransition(() => {
     document.getElementById('element').style.opacity = 0;
   });
   console.log('Opacity might not be 0 yet!'); // This might execute before the DOM update
   ```

2. **Modifying the DOM outside the update callback:** Changes made to the DOM outside the callback function might not be part of the view transition, leading to unexpected visual glitches.

   **Example:**

   ```javascript
   document.getElementById('title').textContent = 'Loading...'; // Change outside the callback
   document.startViewTransition(() => {
     document.getElementById('content').textContent = 'Loaded!';
   });
   ```

3. **Throwing errors in the update callback without proper handling:** If the callback throws an error, the transition will be aborted, and the promises will be rejected. Developers need to handle potential errors gracefully.

   **Example:**

   ```javascript
   document.startViewTransition(() => {
     if (!dataLoaded) {
       throw new Error('Data not loaded yet!');
     }
     document.getElementById('data').textContent = data;
   }).catch(error => {
     console.error('View transition failed:', error);
     // Handle the error, perhaps revert the UI
   });
   ```

4. **Confusing the order of promise resolution:** Developers might misunderstand when the `ready`, `updateCallbackDone`, and `finished` promises resolve and try to perform actions at incorrect times. For instance, trying to access the final DOM state before the `finished` promise resolves might lead to issues if animations are still in progress.

5. **Not understanding the implications of `view-transition-name`:** Incorrect or missing `view-transition-name` properties can result in less effective or broken transitions.

In summary, `dom_view_transition.cc` plays a vital role in orchestrating the View Transitions API within the Chromium rendering engine, acting as the bridge between JavaScript and the underlying transition mechanisms and managing the various stages and promises involved in creating smooth visual transitions on the web.

### 提示词
```
这是目录为blink/renderer/core/view_transition/dom_view_transition.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/view_transition/dom_view_transition.h"

#include "third_party/blink/renderer/bindings/core/v8/capture_source_location.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_property.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/events/error_event.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"

namespace blink {

namespace {

const char kAbortedMessage[] = "Transition was skipped";
const char kInvalidStateMessage[] =
    "Transition was aborted because of invalid state";
const char kTimeoutMessage[] =
    "Transition was aborted because of timeout in DOM update";

}  // namespace

DOMViewTransition::DOMViewTransition(ExecutionContext& execution_context,
                                     ViewTransition& view_transition)
    : DOMViewTransition(execution_context,
                        view_transition,
                        /*update_dom_callback=*/nullptr) {
  if (view_transition.IsForNavigationOnNewDocument()) {
    // In a cross-document view transition, the DOM is "updated" by the
    // navigation so by the time we create this object (in the pagereveal
    // event), the update is complete.
    dom_updated_promise_property_->ResolveWithUndefined();
    dom_callback_result_ = DOMCallbackResult::kSucceeded;
  }
}

DOMViewTransition::DOMViewTransition(
    ExecutionContext& execution_context,
    ViewTransition& view_transition,
    V8ViewTransitionCallback* update_dom_callback)
    : ExecutionContextLifecycleObserver(&execution_context),
      execution_context_(&execution_context),
      view_transition_{&view_transition},
      update_dom_callback_(update_dom_callback),
      finished_promise_property_(
          MakeGarbageCollected<PromiseProperty>(execution_context_)),
      ready_promise_property_(
          MakeGarbageCollected<PromiseProperty>(execution_context_)),
      dom_updated_promise_property_(
          MakeGarbageCollected<PromiseProperty>(execution_context_)) {
  CHECK(execution_context_->GetAgent());
}

DOMViewTransition::~DOMViewTransition() = default;

void DOMViewTransition::ContextDestroyed() {
  execution_context_.Clear();
}

void DOMViewTransition::skipTransition() {
  view_transition_->SkipTransition();
}

ScriptPromise<IDLUndefined> DOMViewTransition::finished(
    ScriptState* script_state) const {
  return finished_promise_property_->Promise(script_state->World());
}

ScriptPromise<IDLUndefined> DOMViewTransition::ready(
    ScriptState* script_state) const {
  return ready_promise_property_->Promise(script_state->World());
}

ScriptPromise<IDLUndefined> DOMViewTransition::updateCallbackDone(
    ScriptState* script_state) const {
  return dom_updated_promise_property_->Promise(script_state->World());
}

void DOMViewTransition::DidSkipTransition(
    ViewTransition::PromiseResponse response) {
  CHECK_NE(response, ViewTransition::PromiseResponse::kResolve);

  if (!execution_context_) {
    return;
  }

  // If the ready promise has not yet been resolved, reject it.
  if (ready_promise_property_->GetState() == PromiseProperty::State::kPending) {
    AtMicrotask(response, ready_promise_property_);
  }

  // If we haven't run the dom change callback yet, schedule a task to do so.
  // The finished promise will propagate the result of the updateCallbackDone
  // promise when this callback runs.
  if (dom_callback_result_ == DOMCallbackResult::kNotInvoked) {
    execution_context_->GetTaskRunner(TaskType::kMiscPlatformAPI)
        ->PostTask(FROM_HERE,
                   WTF::BindOnce(&DOMViewTransition::InvokeDOMChangeCallback,
                                 WrapPersistent(this)));
  } else if (dom_callback_result_ == DOMCallbackResult::kFailed) {
    // If the DOM callback finished and there was a failure then the finished
    // promise should have been rejected with updateCallbackDone.
    CHECK_EQ(finished_promise_property_->GetState(),
             PromiseProperty::State::kRejected);
  } else if (dom_callback_result_ == DOMCallbackResult::kSucceeded) {
    // But if the callback was successful, we need to resolve the finished
    // promise while skipping the transition.
    AtMicrotask(ViewTransition::PromiseResponse::kResolve,
                finished_promise_property_);
  }
}

void DOMViewTransition::NotifyDOMCallbackFinished() {
  CHECK_EQ(dom_callback_result_, DOMCallbackResult::kRunning);
  // Handle all promises which depend on this callback.
  dom_updated_promise_property_->ResolveWithUndefined();

  // If we're already at the terminal state, the transition was skipped before
  // the callback finished. Also handle the finish promise.
  if (view_transition_->IsDone()) {
    finished_promise_property_->ResolveWithUndefined();
  }

  dom_callback_result_ = DOMCallbackResult::kSucceeded;
  view_transition_->NotifyDOMCallbackFinished(true);
}

void DOMViewTransition::NotifyDOMCallbackRejected(ScriptValue value) {
  CHECK_EQ(dom_callback_result_, DOMCallbackResult::kRunning);
  // Handle all promises which depend on this callback.
  dom_updated_promise_property_->Reject(value);

  // The ready promise rejects with the value of updateCallbackDone callback
  // if it's skipped because of an error in the callback.
  if (!view_transition_->IsDone()) {
    ready_promise_property_->Reject(value);
  }

  // If the domUpdate callback fails the transition is skipped. The finish
  // promise should mirror the result of updateCallbackDone.
  finished_promise_property_->Reject(value);

  dom_callback_result_ = DOMCallbackResult::kFailed;
  view_transition_->NotifyDOMCallbackFinished(false);
}

void DOMViewTransition::DidStartAnimating() {
  AtMicrotask(ViewTransition::PromiseResponse::kResolve,
              ready_promise_property_);
}

void DOMViewTransition::DidFinishAnimating() {
  AtMicrotask(ViewTransition::PromiseResponse::kResolve,
              finished_promise_property_);
}

// Invoked when ViewTransitionCallback finishes running.
class DOMChangeFinishedCallback
    : public ThenCallable<IDLUndefined, DOMChangeFinishedCallback> {
 public:
  explicit DOMChangeFinishedCallback(DOMViewTransition& dom_view_transition)
      : dom_view_transition_(&dom_view_transition) {}
  ~DOMChangeFinishedCallback() override = default;

  void React(ScriptState*) {
    dom_view_transition_->NotifyDOMCallbackFinished();
  }
  void Trace(Visitor* visitor) const override {
    ThenCallable<IDLUndefined, DOMChangeFinishedCallback>::Trace(visitor);
    visitor->Trace(dom_view_transition_);
  }

 private:
  Member<DOMViewTransition> dom_view_transition_;
};

class DOMChangeRejectedCallback
    : public ThenCallable<IDLAny, DOMChangeRejectedCallback> {
 public:
  explicit DOMChangeRejectedCallback(DOMViewTransition& dom_view_transition)
      : dom_view_transition_(&dom_view_transition) {}
  ~DOMChangeRejectedCallback() override = default;

  void React(ScriptState*, ScriptValue value) {
    dom_view_transition_->NotifyDOMCallbackRejected(std::move(value));
  }
  void Trace(Visitor* visitor) const override {
    ThenCallable<IDLAny, DOMChangeRejectedCallback>::Trace(visitor);
    visitor->Trace(dom_view_transition_);
  }

 private:
  Member<DOMViewTransition> dom_view_transition_;
};

void DOMViewTransition::InvokeDOMChangeCallback() {
  CHECK_EQ(dom_callback_result_, DOMCallbackResult::kNotInvoked)
      << "UpdateDOM callback invoked multiple times.";

  if (!execution_context_) {
    return;
  }

  dom_callback_result_ = DOMCallbackResult::kRunning;

  ScriptPromise<IDLUndefined> result;

  // It's ok to use the main world when there is no callback, since we're only
  // using it to call DOMChangeFinishedCallback which doesn't use the script
  // state or execute any script.
  ScriptState* script_state =
      update_dom_callback_ ? update_dom_callback_->CallbackRelevantScriptState()
                           : ToScriptStateForMainWorld(execution_context_);
  ScriptState::Scope scope(script_state);

  if (update_dom_callback_) {
    v8::Maybe<ScriptPromise<IDLUndefined>> maybe_result =
        update_dom_callback_->Invoke(nullptr);

    // If the callback couldn't be run for some reason, treat it as an empty
    // promise rejected with an abort exception.
    if (maybe_result.IsNothing()) {
      result = ScriptPromise<IDLUndefined>::RejectWithDOMException(
          script_state, MakeGarbageCollected<DOMException>(
                            DOMExceptionCode::kAbortError, kAbortedMessage));
    } else {
      result = maybe_result.FromJust();
    }
  } else {
    // If there's no callback provided, treat the same as an empty promise
    // resolved without a value.
    result = ToResolvedUndefinedPromise(script_state);
  }

  // Note, the DOMChangeFinishedCallback will be invoked asynchronously.
  result.Then(script_state,
              MakeGarbageCollected<DOMChangeFinishedCallback>(*this),
              MakeGarbageCollected<DOMChangeRejectedCallback>(*this));
}

void DOMViewTransition::Trace(Visitor* visitor) const {
  visitor->Trace(execution_context_);
  visitor->Trace(view_transition_);
  visitor->Trace(update_dom_callback_);
  visitor->Trace(finished_promise_property_);
  visitor->Trace(ready_promise_property_);
  visitor->Trace(dom_updated_promise_property_);

  ExecutionContextLifecycleObserver::Trace(visitor);
  ScriptWrappable::Trace(visitor);
}

void DOMViewTransition::AtMicrotask(ViewTransition::PromiseResponse response,
                                    PromiseProperty* property) {
  if (!execution_context_) {
    return;
  }
  execution_context_->GetAgent()->event_loop()->EnqueueMicrotask(
      WTF::BindOnce(&DOMViewTransition::HandlePromise, WrapPersistent(this),
                    response, WrapPersistent(property)));
}

void DOMViewTransition::HandlePromise(ViewTransition::PromiseResponse response,
                                      PromiseProperty* property) {
  if (!execution_context_) {
    return;
  }

  // It's possible for multiple fulfillment microtasks to be queued so
  // early-out if that's happened.
  if (property->GetState() != PromiseProperty::State::kPending) {
    return;
  }

  // The main world is used here only to create a ScriptValue. While the
  // promises may be accessed from other worlds (in the cross-document case, an
  // extension can add a `pagereveal` event listener) the promises are
  // fulfilled using ScriptPromiseProperty which tracks requests from each
  // world and clones the passed value if needed.
  ScriptState* main_world_script_state =
      ToScriptStateForMainWorld(execution_context_);

  if (!main_world_script_state) {
    return;
  }

  switch (response) {
    case ViewTransition::PromiseResponse::kResolve:
      property->ResolveWithUndefined();
      break;
    case ViewTransition::PromiseResponse::kRejectAbort: {
      ScriptState::Scope scope(main_world_script_state);
      auto value = ScriptValue::From(
          main_world_script_state,
          MakeGarbageCollected<DOMException>(DOMExceptionCode::kAbortError,
                                             kAbortedMessage));
      property->Reject(value);
      break;
    }
    case ViewTransition::PromiseResponse::kRejectInvalidState: {
      ScriptState::Scope scope(main_world_script_state);
      auto value = ScriptValue::From(
          main_world_script_state,
          MakeGarbageCollected<DOMException>(
              DOMExceptionCode::kInvalidStateError, kInvalidStateMessage));
      property->Reject(value);
      break;
    }
    case ViewTransition::PromiseResponse::kRejectTimeout: {
      ScriptState::Scope scope(main_world_script_state);
      auto value = ScriptValue::From(
          main_world_script_state,
          MakeGarbageCollected<DOMException>(DOMExceptionCode::kTimeoutError,
                                             kTimeoutMessage));
      property->Reject(value);
      break;
    }
  }
}

ViewTransitionTypeSet* DOMViewTransition::types() const {
  return view_transition_->Types();
}

}  // namespace blink
```