Response:
Let's break down the thought process for analyzing this code. The goal is to understand the functionality of `navigator_gamepad.cc` and its interactions with other web technologies.

**1. Initial Scan and High-Level Understanding:**

* **Filename and Directory:** `blink/renderer/modules/gamepad/navigator_gamepad.cc` immediately tells us this file is part of the Blink rendering engine, specifically within the "gamepad" module, and likely relates to the `navigator.gamepad` API in JavaScript.
* **Copyright Notice:** Standard boilerplate, but confirms it's related to Google and potentially Apple's prior work.
* **Includes:**  The included headers are key to understanding dependencies and functionality. Look for terms like `gamepad`, `navigator`, `event`, `javascript`, `html`, `css` (though CSS interaction might be indirect), `permissions`, `privacy`, and `v8`.
    * `device/gamepad/public/cpp/gamepads.h`: Low-level gamepad data structures.
    * `third_party/blink/public/common/privacy_budget/...`:  Privacy implications are likely.
    * `third_party/blink/public/mojom/frame/...`: Inter-process communication (IPC) likely involved for user activation.
    * `third_party/blink/renderer/bindings/modules/v8/...`:  Bridge between C++ and JavaScript (V8 engine).
    * `third_party/blink/renderer/core/dom/events/...`: Handling gamepad events.
    * `third_party/blink/renderer/core/frame/...`: Integration with the browser frame and navigator object.
    * `third_party/blink/renderer/modules/gamepad/...`: Other gamepad-related modules within Blink.
* **Namespace:** `blink` namespace confirms it's core Blink code.
* **Static Members:** `kSupplementName` strongly suggests this class is a "supplement" to the `Navigator` object, extending its functionality.

**2. Deeper Dive into Key Sections:**

* **`NavigatorGamepad::From(Navigator& navigator)`:**  This is a common pattern for Blink supplements. It ensures there's only one `NavigatorGamepad` instance per `Navigator`.
* **`getGamepads(Navigator& navigator, ExceptionState& exception_state)`:**  This function directly implements the `navigator.getGamepads()` JavaScript API. Note the permission check (`IsFeatureEnabled`) and security error throwing. This immediately establishes a connection to JavaScript.
* **`NavigatorGamepad::Gamepads()`:** This is where the actual gamepad data is fetched and processed. Look for:
    * `SampleAndCompareGamepadState()`:  Indicates polling and diffing of gamepad data.
    * User activation logic:  Relates gamepad input to user interaction.
    * `UseCounter`:  Metrics and usage tracking.
    * Cross-origin and secure context checks:  Security considerations.
* **`SampleGamepads()`:**  Fetches raw gamepad data from the underlying device. The logic for handling WebXR gamepads is interesting.
* **`GetVibrationActuatorForGamepad()`:**  Handles the gamepad vibration API.
* **`SetTouchEvents()`:**  Manages touch events on gamepads, which are less common but supported.
* **Event Listeners (`DidAddEventListener`, `DidRemoveEventListener`, etc.):**  Crucial for understanding how the C++ code interacts with JavaScript event handlers. Pay attention to the `gamepadconnected` and `gamepaddisconnected` events.
* **`SampleAndCompareGamepadState()` (The Core Logic):**  This function is the heart of the gamepad handling. Carefully trace the steps:
    1. Prevent re-entry.
    2. Start updating if attached.
    3. Sample gamepad data.
    4. Compare with the previous state.
    5. Swap buffers if there's a change.
    6. Dispatch `gamepadconnected` and `gamepaddisconnected` events.
* **`DispatchGamepadEvent()`:**  Creates and dispatches the JavaScript `GamepadEvent`.
* **`PageVisibilityChanged()`:**  Optimizes gamepad polling based on page visibility.

**3. Identifying Connections to Web Technologies:**

* **JavaScript:** `navigator.getGamepads()`, `gamepadconnected` and `gamepaddisconnected` events, `Gamepad` object (though not directly in this file, its usage is clear).
* **HTML:** While not directly manipulating HTML, the gamepad API enables interaction *with* HTML elements through JavaScript (e.g., controlling a game character rendered in a `<canvas>` element).
* **CSS:**  Indirectly related. Gamepad input can trigger JavaScript that modifies CSS styles (e.g., highlighting a button).

**4. Logical Reasoning and Assumptions:**

* **Assumption:** The code relies on an underlying system for getting raw gamepad data (likely through the operating system). This is evidenced by the `device::Gamepads` structure.
* **Input:** User interacts with a gamepad (presses buttons, moves axes). The browser polls for these changes.
* **Output:**  `Gamepad` objects in JavaScript are updated, and `gamepadconnected`/`gamepaddisconnected` events are fired, triggering JavaScript callbacks.

**5. Common User/Programming Errors:**

* Not checking gamepad availability:  `navigator.getGamepads()` might return an empty array.
* Incorrect event listener setup: Forgetting to add listeners for `gamepadconnected` or `gamepaddisconnected`.
* Assuming gamepad indices are constant.
* Not handling different gamepad mappings.

**6. Debugging Walkthrough:**

Imagine a user plugging in a gamepad. How does the code get involved?

1. **User Action:** Plug in the gamepad.
2. **OS Event:** The operating system detects the gamepad.
3. **Browser Hook:** Chromium has a mechanism to listen for these OS-level gamepad events.
4. **`GamepadDispatcher::SampleGamepads()`:** This (inferred) function gets the raw data.
5. **`NavigatorGamepad::SampleGamepads()`:** This function updates the internal `gamepads_back_` with the new data.
6. **`NavigatorGamepad::SampleAndCompareGamepadState()`:** Compares the new state with the old.
7. **Event Dispatch:** If it's a new connection, a `gamepadconnected` event is dispatched.
8. **JavaScript Callback:**  JavaScript code listening for `gamepadconnected` is executed.

**Self-Correction/Refinement during Analysis:**

* **Initial thought:**  Maybe CSS is directly affected by this code.
* **Correction:**  Realized the interaction with CSS is through JavaScript. The C++ code provides the data and events; JavaScript bridges the gap to visual changes.
* **Initial thought:** Focus heavily on individual functions in isolation.
* **Refinement:** Emphasized the *flow* of data and events, especially in `SampleAndCompareGamepadState()`, to understand the overall process.

By following these steps, systematically analyzing the code, and making connections to web technologies, a comprehensive understanding of the file's functionality can be achieved.
This C++ source file, `navigator_gamepad.cc`, within the Chromium Blink engine's gamepad module, is responsible for implementing the `Navigator.gamepad` JavaScript API. It acts as a bridge between the browser's internal gamepad handling and the web page's JavaScript code.

Here's a breakdown of its functionalities:

**1. Exposing Gamepad Information to JavaScript:**

* **`NavigatorGamepad::getGamepads(Navigator& navigator, ExceptionState& exception_state)`:** This is the core function that directly corresponds to the `navigator.getGamepads()` JavaScript call. When a webpage calls `navigator.getGamepads()`, this C++ function is invoked.
* It retrieves the current state of connected gamepads.
* It handles permissions: It checks if the "gamepad" feature is allowed by the Permissions Policy. If not, it throws a `SecurityError`.
* It returns an array of `Gamepad` objects, which are then exposed to JavaScript.

**2. Managing Gamepad State and Events:**

* **Polling for Gamepad Updates:** The code periodically polls the underlying system for gamepad state changes (button presses, axis movements, connections, disconnections). This polling is likely handled by the `GamepadDispatcher`.
* **`SampleGamepads()`:** This function retrieves the current state of connected gamepads from the underlying device layer.
* **`SampleAndCompareGamepadState()`:** This is a crucial function that compares the current gamepad state with the previous state.
* **Dispatching Events:** When gamepad connection or disconnection events occur, or when button/axis states change, this code is responsible for creating and dispatching corresponding JavaScript events (`gamepadconnected` and `gamepaddisconnected`).
* **`DispatchGamepadEvent(const AtomicString& event_name, Gamepad* gamepad)`:**  This function creates and dispatches a `GamepadEvent` to the JavaScript environment.

**3. Handling Gamepad Vibration:**

* **`GetVibrationActuatorForGamepad(const Gamepad& gamepad)`:** This function retrieves or creates a `GamepadHapticActuator` object for a given gamepad, which is used to control gamepad vibration.

**4. Managing Gamepad Touch Events (Less Common):**

* **`SetTouchEvents(const Gamepad& gamepad, GamepadTouchVector& touch_events, base::span<const device::GamepadTouch> data)`:** This function handles touch events on gamepads that support touch surfaces.

**5. Privacy Considerations:**

* The code includes logic for recording gamepad information for identifiability studies (`RecordGamepadsForIdentifiabilityStudy`). This is likely used to understand how gamepad data might be used for fingerprinting and to develop privacy mitigations.

**6. Integration with the Browser Lifecycle:**

* **`DidAddEventListener()`, `DidRemoveEventListener()`, `DidRemoveAllEventListeners()`:** These functions track the addition and removal of `gamepadconnected` and `gamepaddisconnected` event listeners in JavaScript. This helps optimize gamepad polling; if no listeners are present, polling might be reduced.
* **`PageVisibilityChanged()`:** This function adjusts gamepad polling based on the page's visibility. If the page is not visible, polling might be paused to save resources.
* **`StartUpdatingIfAttached()` and `StopUpdating()`:** These functions control the start and stop of gamepad state updates, ensuring updates only occur when the associated frame is attached to a window.

**Relationship with JavaScript, HTML, and CSS:**

* **JavaScript:** This file is the backend implementation of the `navigator.gamepad` JavaScript API. JavaScript code running on a webpage directly interacts with the functionality provided by this C++ code.
    * **Example:**
      ```javascript
      navigator.getGamepads(); // Calls the C++ NavigatorGamepad::getGamepads function.

      window.addEventListener('gamepadconnected', (event) => {
        console.log('Gamepad connected:', event.gamepad);
      }); // The C++ code dispatches this event.
      ```
* **HTML:** HTML elements don't directly interact with this code. However, the gamepad API (implemented here) enables JavaScript to control elements based on gamepad input.
    * **Example:** An HTML `<canvas>` element could render a game character, and JavaScript using the gamepad API could move the character based on joystick input.
* **CSS:**  Similar to HTML, CSS doesn't directly interact with this C++ code. However, JavaScript, driven by gamepad input, can manipulate CSS styles to create interactive effects.
    * **Example:** Pressing a button on a gamepad could trigger JavaScript that adds a class to an HTML button, changing its appearance based on CSS rules.

**Logical Reasoning (Hypothetical Input and Output):**

* **Assumption:** A gamepad with two axes and four buttons is connected to the user's computer.
* **Input (User Action):** The user opens a webpage that calls `navigator.getGamepads()`.
* **Processing (C++ Code):**
    1. `NavigatorGamepad::getGamepads()` is called.
    2. It checks permissions (assuming they are granted).
    3. `SampleGamepads()` retrieves the state of the connected gamepad.
    4. A `Gamepad` object is created (or an existing one is updated).
    5. The `Gamepad` object's properties (axes: `[0, 0]`, `[0, 0]`, buttons: `[false, false, false, false]`, connected: `true`, id: "...") are populated.
* **Output (JavaScript):** The `navigator.getGamepads()` call returns an array containing one `Gamepad` object with the properties reflecting the connected gamepad's state.

* **Input (User Action):** The user presses the first button on the gamepad.
* **Processing (C++ Code):**
    1. The polling mechanism detects the button press.
    2. `SampleGamepads()` updates the gamepad state.
    3. `SampleAndCompareGamepadState()` detects a change in the button state.
    4. `DispatchGamepadEvent()` creates and dispatches a `GamepadEvent` with the `type` of a button press (though button press events themselves are not directly dispatched by this class, rather the overall state change triggers updates that can be observed via polling).
* **Output (JavaScript):**  If the webpage is actively polling or listening for state changes, the `buttons` property of the `Gamepad` object obtained via `navigator.getGamepads()` will now reflect the button press (e.g., `buttons: [true, false, false, false]`).

* **Input (User Action):** The user disconnects the gamepad.
* **Processing (C++ Code):**
    1. The polling mechanism detects the disconnection.
    2. `SampleGamepads()` updates the gamepad state.
    3. `SampleAndCompareGamepadState()` detects the disconnection.
    4. `DispatchGamepadEvent("gamepaddisconnected", ...)` is called.
* **Output (JavaScript):**  A `gamepaddisconnected` event is fired on the `window` object, and any registered event listeners will be executed. Subsequent calls to `navigator.getGamepads()` will likely return an empty array or an array with fewer connected gamepads.

**Common User or Programming Mistakes and Examples:**

* **Not checking for gamepad support:** Users might try to use gamepad features in browsers that don't support the Gamepad API.
    * **Example:**  A website uses `navigator.getGamepads()` without first checking if `navigator.getGamepads` is defined.
* **Assuming gamepad indices are constant:** Gamepad indices can change when gamepads are connected or disconnected.
    * **Example:** A game stores gamepad data based on a fixed index (e.g., gamepad 0) and doesn't handle the case where the user disconnects and reconnects gamepads in a different order.
* **Not handling the `gamepadconnected` and `gamepaddisconnected` events:** Webpages need to listen for these events to properly initialize and de-initialize gamepad interactions.
    * **Example:** A game only calls `navigator.getGamepads()` once on page load and doesn't update its list of active gamepads when a new gamepad is plugged in.
* **Incorrectly interpreting gamepad button and axis values:** Different gamepads might have different mappings for buttons and axes.
    * **Example:** A game assumes the "A" button is always the first button (index 0), which might not be true for all controllers.
* **Security errors due to Permissions Policy:**  If the website is embedded in a context where gamepad access is disallowed by the Permissions Policy, `navigator.getGamepads()` will throw an error.
    * **Example:** An `<iframe>` with a restrictive `allow` attribute might block gamepad access.

**User Operation and Debugging Clues:**

Let's trace a user action leading to this code:

1. **User Action:** The user plugs in a USB gamepad into their computer.
2. **Operating System Event:** The OS detects the new gamepad and makes it available to applications.
3. **Browser Detection:** The Chromium browser (or the underlying operating system integration) detects the newly connected gamepad.
4. **Blink Gamepad Dispatcher:** The `GamepadDispatcher` (likely running in a separate process or thread) is notified about the gamepad connection.
5. **Webpage Interaction:** The user navigates to a webpage that uses the Gamepad API.
6. **JavaScript Call:** The webpage's JavaScript code calls `navigator.getGamepads()` or adds an event listener for `gamepadconnected`.
7. **`NavigatorGamepad::getGamepads()` or `NavigatorGamepad::DidAddEventListener()`:** Depending on the JavaScript action, either `NavigatorGamepad::getGamepads()` will be called to retrieve the current gamepad state (including the newly connected one), or `NavigatorGamepad::DidAddEventListener()` will be called to register the interest in connection events.
8. **Event Dispatch (if listening):** If an event listener was added, `SampleAndCompareGamepadState()` will detect the new connection and `DispatchGamepadEvent("gamepadconnected", ...)` will be called, triggering the JavaScript event handler.

**Debugging Clues:**

* **Breakpoints:** Set breakpoints in `NavigatorGamepad::getGamepads()`, `SampleGamepads()`, `SampleAndCompareGamepadState()`, and `DispatchGamepadEvent()` to observe the flow of execution when a gamepad is connected or interacted with.
* **Logging:** Add `DLOG` or `DVLOG` statements to log the state of gamepads, the events being dispatched, and the values of relevant variables.
* **Chrome DevTools:** Use the "Event Listeners" tab in Chrome DevTools to see if the `gamepadconnected` and `gamepaddisconnected` events are being fired.
* **`chrome://device-log`:** This internal Chrome page might provide lower-level information about device detection, including gamepad connections.
* **Permissions Policy:** Check the "Permissions Policy" section in the "Application" tab of Chrome DevTools to ensure gamepad access is allowed for the current context.
* **Inspect `Gamepad` objects in JavaScript:** Use the browser's developer console to inspect the properties of the `Gamepad` objects returned by `navigator.getGamepads()` to see their current state.

This detailed explanation should provide a comprehensive understanding of the `navigator_gamepad.cc` file and its role in the Chromium browser's gamepad functionality.

Prompt: 
```
这是目录为blink/renderer/modules/gamepad/navigator_gamepad.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2011, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "third_party/blink/renderer/modules/gamepad/navigator_gamepad.h"

#include "base/auto_reset.h"
#include "device/gamepad/public/cpp/gamepads.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_metric_builder.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_study_settings.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gamepad_mapping_type.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/modules/gamepad/gamepad.h"
#include "third_party/blink/renderer/modules/gamepad/gamepad_comparisons.h"
#include "third_party/blink/renderer/modules/gamepad/gamepad_dispatcher.h"
#include "third_party/blink/renderer/modules/gamepad/gamepad_event.h"
#include "third_party/blink/renderer/platform/privacy_budget/identifiability_digest_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"

namespace blink {

namespace {

bool IsGamepadConnectionEvent(const AtomicString& event_type) {
  return event_type == event_type_names::kGamepadconnected ||
         event_type == event_type_names::kGamepaddisconnected;
}

bool HasConnectionEventListeners(LocalDOMWindow* window) {
  return window->HasEventListeners(event_type_names::kGamepadconnected) ||
         window->HasEventListeners(event_type_names::kGamepaddisconnected);
}

}  // namespace

// static
const char NavigatorGamepad::kSupplementName[] = "NavigatorGamepad";
const char kFeaturePolicyBlocked[] =
    "Access to the feature \"gamepad\" is disallowed by permissions policy.";

NavigatorGamepad& NavigatorGamepad::From(Navigator& navigator) {
  NavigatorGamepad* supplement =
      Supplement<Navigator>::From<NavigatorGamepad>(navigator);
  if (!supplement) {
    supplement = MakeGarbageCollected<NavigatorGamepad>(navigator);
    ProvideTo(navigator, supplement);
  }
  return *supplement;
}

namespace {

void RecordGamepadsForIdentifiabilityStudy(
    ExecutionContext* context,
    HeapVector<Member<Gamepad>> gamepads) {
  if (!context || !IdentifiabilityStudySettings::Get()->ShouldSampleSurface(
                      IdentifiableSurface::FromTypeAndToken(
                          IdentifiableSurface::Type::kWebFeature,
                          WebFeature::kGetGamepads)))
    return;
  IdentifiableTokenBuilder builder;
  for (Gamepad* gp : gamepads) {
    if (gp) {
      builder.AddValue(gp->axes().size())
          .AddValue(gp->buttons().size())
          .AddValue(gp->connected())
          .AddToken(IdentifiabilityBenignStringToken(gp->id()))
          .AddToken(IdentifiabilityBenignStringToken(gp->mapping().AsString()))
          .AddValue(gp->timestamp());
      if (auto* vb = gp->vibrationActuator()) {
        builder.AddToken(
            IdentifiabilityBenignStringToken(vb->type().AsString()));
      }
    }
  }
  IdentifiabilityMetricBuilder(context->UkmSourceID())
      .AddWebFeature(WebFeature::kGetGamepads, builder.GetToken())
      .Record(context->UkmRecorder());
}

}  // namespace

// static
HeapVector<Member<Gamepad>> NavigatorGamepad::getGamepads(
    Navigator& navigator,
    ExceptionState& exception_state) {
  if (!navigator.DomWindow()) {
    // Using an existing NavigatorGamepad if one exists, but don't create one
    // for a detached window, as its subclasses depend on a non-null window.
    auto* gamepad = Supplement<Navigator>::From<NavigatorGamepad>(navigator);
    if (gamepad) {
      HeapVector<Member<Gamepad>> result = gamepad->Gamepads();
      RecordGamepadsForIdentifiabilityStudy(gamepad->GetExecutionContext(),
                                            result);
      return result;
    }
    return HeapVector<Member<Gamepad>>();
  }

  auto* navigator_gamepad = &NavigatorGamepad::From(navigator);

  ExecutionContext* context = navigator_gamepad->GetExecutionContext();

  if (!context || !context->IsFeatureEnabled(
                      mojom::blink::PermissionsPolicyFeature::kGamepad)) {
    exception_state.ThrowSecurityError(kFeaturePolicyBlocked);
    return HeapVector<Member<Gamepad>>();
  }

  HeapVector<Member<Gamepad>> result =
      NavigatorGamepad::From(navigator).Gamepads();
  RecordGamepadsForIdentifiabilityStudy(context, result);
  return result;
}

HeapVector<Member<Gamepad>> NavigatorGamepad::Gamepads() {
  SampleAndCompareGamepadState();

  // Ensure |gamepads_| is not null.
  if (gamepads_.size() == 0)
    gamepads_.resize(device::Gamepads::kItemsLengthCap);

  // Allow gamepad button presses to qualify as user activations if the page is
  // visible.
  if (DomWindow() && DomWindow()->GetFrame()->GetPage()->IsPageVisible() &&
      GamepadComparisons::HasUserActivation(gamepads_)) {
    LocalFrame::NotifyUserActivation(
        DomWindow()->GetFrame(),
        mojom::blink::UserActivationNotificationType::kInteraction);
  }
  is_gamepads_exposed_ = true;

  ExecutionContext* context = DomWindow();

  if (DomWindow() &&
      DomWindow()->GetFrame()->IsCrossOriginToOutermostMainFrame()) {
    UseCounter::Count(context, WebFeature::kGetGamepadsFromCrossOriginSubframe);
  }

  if (context && !context->IsSecureContext()) {
    UseCounter::Count(context, WebFeature::kGetGamepadsFromInsecureContext);
  }

  return gamepads_;
}

void NavigatorGamepad::SampleGamepads() {
  device::Gamepads gamepads;
  gamepad_dispatcher_->SampleGamepads(gamepads);

  for (uint32_t i = 0; i < device::Gamepads::kItemsLengthCap; ++i) {
    device::Gamepad& device_gamepad = gamepads.items[i];

    // All WebXR gamepads should be hidden
    if (device_gamepad.is_xr) {
      gamepads_back_[i] = nullptr;
    } else if (device_gamepad.connected) {
      Gamepad* gamepad = gamepads_back_[i];
      if (!gamepad) {
        gamepad = MakeGarbageCollected<Gamepad>(this, i, navigation_start_,
                                                gamepads_start_);
      }
      bool cross_origin_isolated_capability =
          DomWindow() ? DomWindow()->CrossOriginIsolatedCapability() : false;
      gamepad->UpdateFromDeviceState(device_gamepad,
                                     cross_origin_isolated_capability);
      gamepads_back_[i] = gamepad;
    } else {
      gamepads_back_[i] = nullptr;
    }
  }
}

GamepadHapticActuator* NavigatorGamepad::GetVibrationActuatorForGamepad(
    const Gamepad& gamepad) {
  if (!gamepad.connected()) {
    return nullptr;
  }

  if (!gamepad.HasVibrationActuator()) {
    return nullptr;
  }

  int pad_index = gamepad.index();
  DCHECK_GE(pad_index, 0);
  if (!vibration_actuators_[pad_index]) {
    auto* actuator = MakeGarbageCollected<GamepadHapticActuator>(
        *DomWindow(), pad_index, gamepad.GetVibrationActuatorType());
    vibration_actuators_[pad_index] = actuator;
  }
  return vibration_actuators_[pad_index].Get();
}

void NavigatorGamepad::SetTouchEvents(
    const Gamepad& gamepad,
    GamepadTouchVector& touch_events,
    base::span<const device::GamepadTouch> data) {
  int pad_index = gamepad.index();
  DCHECK_GE(pad_index, 0);

  auto& id = next_touch_id_[pad_index];
  auto& id_map = touch_id_map_[pad_index];

  uint32_t the_id = 0u;
  TouchIdMap the_id_map{};
  for (size_t i = 0u; i < data.size(); ++i) {
    if (auto search = id_map.find(data[i].touch_id); search != id_map.end()) {
      the_id = search->value;
    } else {
      the_id = id++;
    }
    the_id_map.Set(data[i].touch_id, the_id);
    touch_events[i]->UpdateValuesFrom(data[i], the_id);
  }

  id_map = std::move(the_id_map);
}

void NavigatorGamepad::Trace(Visitor* visitor) const {
  visitor->Trace(gamepads_);
  visitor->Trace(gamepads_back_);
  visitor->Trace(vibration_actuators_);
  visitor->Trace(gamepad_dispatcher_);
  Supplement<Navigator>::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
  PlatformEventController::Trace(visitor);
  Gamepad::Client::Trace(visitor);
}

bool NavigatorGamepad::StartUpdatingIfAttached() {
  // The frame must be attached to start updating.
  if (DomWindow()) {
    StartUpdating();
    return true;
  }
  return false;
}

void NavigatorGamepad::DidUpdateData() {
  // We should stop listening once we detached.
  DCHECK(DomWindow());

  // Record when gamepad data was first made available to the page.
  if (gamepads_start_.is_null())
    gamepads_start_ = base::TimeTicks::Now();

  // Fetch the new gamepad state and dispatch gamepad events.
  if (has_event_listener_)
    SampleAndCompareGamepadState();
}

NavigatorGamepad::NavigatorGamepad(Navigator& navigator)
    : Supplement<Navigator>(navigator),
      ExecutionContextClient(navigator.DomWindow()),
      PlatformEventController(*navigator.DomWindow()),
      gamepad_dispatcher_(
          MakeGarbageCollected<GamepadDispatcher>(*navigator.DomWindow())) {
  LocalDOMWindow* window = navigator.DomWindow();
  window->RegisterEventListenerObserver(this);

  // Fetch |window.performance.timing.navigationStart|. Gamepad timestamps are
  // reported relative to this value.
  DocumentLoader* loader = window->document()->Loader();
  if (loader) {
    navigation_start_ = loader->GetTiming().NavigationStart();
  } else {
    navigation_start_ = base::TimeTicks::Now();
  }

  vibration_actuators_.resize(device::Gamepads::kItemsLengthCap);
}

NavigatorGamepad::~NavigatorGamepad() = default;

void NavigatorGamepad::RegisterWithDispatcher() {
  gamepad_dispatcher_->AddController(this, DomWindow());
}

void NavigatorGamepad::UnregisterWithDispatcher() {
  gamepad_dispatcher_->RemoveController(this);
}

bool NavigatorGamepad::HasLastData() {
  // Gamepad data is polled instead of pushed.
  return false;
}

void NavigatorGamepad::DidAddEventListener(LocalDOMWindow*,
                                           const AtomicString& event_type) {
  if (IsGamepadConnectionEvent(event_type)) {
    has_connection_event_listener_ = true;
    bool first_event_listener = !has_event_listener_;
    has_event_listener_ = true;

    if (GetPage() && GetPage()->IsPageVisible()) {
      StartUpdatingIfAttached();
      if (first_event_listener)
        SampleAndCompareGamepadState();
    }
  }
}

void NavigatorGamepad::DidRemoveEventListener(LocalDOMWindow* window,
                                              const AtomicString& event_type) {
  if (IsGamepadConnectionEvent(event_type)) {
    has_connection_event_listener_ = HasConnectionEventListeners(window);
    if (!has_connection_event_listener_)
      DidRemoveGamepadEventListeners();
  }
}

void NavigatorGamepad::DidRemoveAllEventListeners(LocalDOMWindow*) {
  DidRemoveGamepadEventListeners();
}

void NavigatorGamepad::DidRemoveGamepadEventListeners() {
  has_event_listener_ = false;
  StopUpdating();
}

void NavigatorGamepad::SampleAndCompareGamepadState() {
  // Avoid re-entry. Do not fetch a new sample until we are finished dispatching
  // events from the previous sample.
  if (processing_events_)
    return;

  base::AutoReset<bool> processing_events_reset(&processing_events_, true);
  if (StartUpdatingIfAttached()) {
    if (GetPage()->IsPageVisible()) {
      // Allocate a buffer to hold the new gamepad state, if needed.
      if (gamepads_back_.size() == 0)
        gamepads_back_.resize(device::Gamepads::kItemsLengthCap);
      SampleGamepads();

      // Compare the new sample with the previous sample and record which
      // gamepad events should be dispatched. Swap buffers if the gamepad
      // state changed. We must swap buffers before dispatching events to
      // ensure |gamepads_| holds the correct data when getGamepads is called
      // from inside a gamepad event listener.
      auto compare_result =
          GamepadComparisons::Compare(gamepads_, gamepads_back_, false, false);
      if (compare_result.IsDifferent()) {
        std::swap(gamepads_, gamepads_back_);
        bool is_gamepads_back_exposed = is_gamepads_exposed_;
        is_gamepads_exposed_ = false;

        // Dispatch gamepad events. Dispatching an event calls the event
        // listeners synchronously.
        //
        // Note: In some instances the gamepad connection state may change while
        // inside an event listener. This is most common when using test APIs
        // that allow the gamepad state to be changed from javascript. The set
        // of event listeners may also change if listeners are added or removed
        // by another listener.
        for (uint32_t i = 0; i < device::Gamepads::kItemsLengthCap; ++i) {
          bool is_connected = compare_result.IsGamepadConnected(i);
          bool is_disconnected = compare_result.IsGamepadDisconnected(i);

          // When a gamepad is disconnected and connected in the same update,
          // dispatch the gamepaddisconnected event first.
          if (has_connection_event_listener_ && is_disconnected) {
            // Reset the vibration state associated with the disconnected
            // gamepad to prevent it from being associated with a
            // newly-connected gamepad at the same index.
            vibration_actuators_[i] = nullptr;

            Gamepad* pad = gamepads_back_[i];
            DCHECK(pad);
            pad->SetConnected(false);
            is_gamepads_back_exposed = true;
            DispatchGamepadEvent(event_type_names::kGamepaddisconnected, pad);
          }
          if (has_connection_event_listener_ && is_connected) {
            Gamepad* pad = gamepads_[i];
            DCHECK(pad);
            is_gamepads_exposed_ = true;
            DispatchGamepadEvent(event_type_names::kGamepadconnected, pad);
          }
        }

        // Clear |gamepads_back_| if it was ever exposed to the page so it can
        // be garbage collected when no active references remain. If it was
        // never exposed, retain the buffer so it can be reused.
        if (is_gamepads_back_exposed)
          gamepads_back_.clear();
      }
    }
  }
}

void NavigatorGamepad::DispatchGamepadEvent(const AtomicString& event_name,
                                            Gamepad* gamepad) {
  // Ensure that we're blocking re-entrancy.
  DCHECK(processing_events_);
  DCHECK(has_connection_event_listener_);
  DCHECK(gamepad);
  DomWindow()->DispatchEvent(*GamepadEvent::Create(
      event_name, Event::Bubbles::kNo, Event::Cancelable::kYes, gamepad));
}

void NavigatorGamepad::PageVisibilityChanged() {
  // Inform the embedder whether it needs to provide gamepad data for us.
  bool visible = GetPage()->IsPageVisible();
  if (visible && (has_event_listener_ || gamepads_.size())) {
    StartUpdatingIfAttached();
  } else {
    StopUpdating();
  }

  if (visible && has_event_listener_)
    SampleAndCompareGamepadState();
}

}  // namespace blink

"""

```