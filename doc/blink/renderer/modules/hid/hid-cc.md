Response:
Let's break down the thought process for analyzing the provided `hid.cc` file.

**1. Understanding the Goal:**

The core request is to understand the functionality of this C++ file within the Chromium Blink engine, specifically focusing on its relationship with web technologies (JavaScript, HTML, CSS), its internal logic, potential user errors, and how user actions might lead to this code being executed.

**2. Initial Code Scan and Keyword Recognition:**

The first step is a quick skim of the code, looking for recognizable keywords and patterns. Keywords like `HID`, `Device`, `Connect`, `Disconnect`, `Request`, `Promise`, `Filter`, `Event`, `Navigator`, `ScriptState`, `ExceptionState`, `SecurityError`, `TypeError`, and includes like `v8_hid_device_filter.h` and `v8_hid_device_request_options.h` immediately jump out. These suggest that the file is involved in the WebHID API.

**3. Identifying Core Functionality Areas:**

Based on the keywords and structure, we can start to categorize the file's responsibilities:

* **API Entry Point:** The `HID` class itself, associated with `NavigatorBase`, suggests this is the main entry point for accessing HID functionality from web content.
* **Device Discovery/Listing:**  Methods like `getDevices` and the associated `FinishGetDevices` clearly relate to retrieving a list of connected HID devices.
* **Device Request/Selection:** `requestDevice` and `FinishRequestDevice` point to a mechanism for the user to select specific HID devices based on filters.
* **Device Connection Management:** `Connect`, `DeviceAdded`, `DeviceRemoved`, and `DeviceChanged` handle the lifecycle of HID device connections.
* **Event Handling:**  The presence of `AddedEventListener`, `DispatchEvent`, and `HIDConnectionEvent` indicates support for `connect` and `disconnect` events.
* **Data Structures:** `device_cache_`, `get_devices_promises_`, `request_device_promises_` are important for managing state.
* **Error Handling:** The use of `ExceptionState`, `ThrowSecurityError`, and `ThrowTypeError` suggests error handling related to permissions and invalid input.
* **Permissions and Security:**  Checks involving `PermissionsPolicyFeature::kHid` and opaque origins highlight the security aspects.
* **Service Interaction:** The `service_` member and calls to `EnsureServiceConnection` and `CloseServiceConnection` indicate communication with a lower-level HID service.
* **Filtering:** The `HIDDeviceFilter` and related conversion functions (`ConvertDeviceFilter`, `CheckDeviceFilterValidity`) are crucial for device selection.

**4. Tracing the JavaScript Interaction:**

Now, the focus shifts to how JavaScript interacts with this C++ code. The `HID` class being a supplement to `NavigatorBase` implies that it's accessed via `navigator.hid`. The method names (`getDevices`, `requestDevice`) directly map to the JavaScript API. The use of `ScriptPromise` confirms asynchronous operations. The `HIDDeviceRequestOptions` and `HIDDeviceFilter` are clearly mirroring JavaScript objects. The `HIDConnectionEvent` being dispatched corresponds to the `connect` and `disconnect` events observable in JavaScript.

**5. Inferring HTML/CSS Relationship (Indirect):**

While this specific file doesn't directly manipulate HTML or CSS, its *purpose* is to enable web pages to interact with HID devices. This interaction is initiated by JavaScript within the context of an HTML document being rendered by the browser. CSS isn't directly involved, but the overall user experience of a webpage utilizing WebHID will be shaped by the HTML structure and CSS styling.

**6. Logical Reasoning and Example Scenarios:**

Here, we start thinking about specific input and output scenarios:

* **`getDevices()`:** Input: User calls `navigator.hid.getDevices()`. Output: A promise that resolves with an array of `HIDDevice` objects (or an empty array).
* **`requestDevice()`:** Input: User calls `navigator.hid.requestDevice({ filters: [...] })`. Output:  A permission prompt. If granted, a promise resolving with an array of selected `HIDDevice` objects. If denied, the promise might reject.
* **Event Handling:** Input: A HID device is plugged in or unplugged. Output: A `connect` or `disconnect` event is dispatched to any registered listeners.

**7. Identifying Potential User Errors:**

This involves thinking about common mistakes developers might make:

* **Calling `requestDevice` without user activation:**  The code explicitly checks for this.
* **Incorrect filter specification:** The `CheckDeviceFilterValidity` function helps identify these errors.
* **Adding event listeners too late in Service Workers:** The code has a specific warning for this.

**8. Tracing User Operations to Code Execution:**

This requires understanding the browser's architecture at a high level:

1. **User Action:** The user interacts with a webpage (e.g., clicks a button).
2. **JavaScript Execution:** This triggers JavaScript code that calls `navigator.hid.requestDevice()` or `navigator.hid.getDevices()`.
3. **Blink Binding Layer:** The JavaScript call is intercepted by the Blink engine's bindings (likely V8 bindings).
4. **C++ Method Invocation:**  The corresponding C++ methods in `hid.cc` are invoked.
5. **Service Communication:** `hid.cc` interacts with the browser's HID service (via Mojo IPC) to get device information or initiate device requests.
6. **Operating System Interaction:** The browser's HID service interacts with the operating system's HID subsystem.
7. **Device Interaction:** The OS interacts with the physical HID devices.
8. **Callbacks and Promises:** Results are passed back through the layers using callbacks and promises, eventually resolving the JavaScript promises.

**9. Review and Refine:**

Finally, review the generated explanation for clarity, accuracy, and completeness. Ensure that all parts of the prompt are addressed. For instance, check if examples are concrete and easy to understand.

This iterative process of scanning, identifying, tracing, reasoning, and refining allows for a comprehensive understanding of the C++ code and its role within the broader web platform.
This C++ file, `hid.cc`, located within the `blink/renderer/modules/hid` directory of the Chromium Blink engine, implements the **WebHID API**. This API allows web pages running in the browser to interact with Human Interface Devices (HID) like keyboards, mice, gamepads, and other specialized input devices.

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Provides the `navigator.hid` interface:** This file defines the `HID` class, which is exposed as a property on the `Navigator` object in JavaScript (`navigator.hid`). This is the primary entry point for web developers to access HID functionality.

2. **Device Discovery (`getDevices()`):**
   - Allows web pages to retrieve a list of already paired and authorized HID devices.
   - This function returns a `Promise` that resolves with an array of `HIDDevice` objects.

3. **Device Request (`requestDevice()`):**
   - Enables web pages to prompt the user to select HID devices to connect to.
   - Takes an optional `HIDDeviceRequestOptions` object as an argument, allowing filtering of devices based on vendor ID, product ID, usage page, and usage.
   - Requires a user gesture (like a button click) for security reasons.
   - Returns a `Promise` that resolves with an array of `HIDDevice` objects that the user selected.

4. **Device Connection Management:**
   - Tracks connected and available HID devices.
   - Uses a `device_cache_` to store `HIDDevice` objects, which represent individual HID devices.
   - Handles events for device connection (`connect`) and disconnection (`disconnect`).
   - Dispatches `HIDConnectionEvent` objects to registered event listeners when devices are connected or disconnected.

5. **Communication with the Browser Process:**
   - Uses Mojo IPC (Inter-Process Communication) to communicate with the browser process, which has direct access to the operating system's HID subsystem.
   - The `service_` member is a `mojo::Remote` to the `HidService` interface in the browser process.
   - The `receiver_` member is a `mojo::Receiver` for the `HidManagerClient` interface, allowing the browser process to send notifications about device changes.

6. **Permissions and Security:**
   - Enforces permissions policies related to the WebHID API.
   - Checks if the "hid" feature is allowed by the Permissions Policy.
   - Restricts access from contexts with opaque origins (e.g., cross-origin iframes without proper setup).
   - Requires user activation for `requestDevice()` to prevent malicious websites from silently requesting device access.

7. **Filtering Devices:**
   - Implements logic to filter HID devices based on the criteria provided in the `HIDDeviceRequestOptions`.
   - The `ConvertDeviceFilter` function translates the JavaScript `HIDDeviceFilter` object into a Mojo representation for communication with the browser process.
   - The `CheckDeviceFilterValidity` function validates the structure of the filter objects.

8. **Error Handling:**
   - Throws `DOMException` (e.g., `NotSupportedError`, `SecurityError`, `TypeError`) to JavaScript when errors occur, such as:
     - Accessing the API from an unsupported context (e.g., detached frame).
     - Feature policy blocking access.
     - Missing user activation for `requestDevice()`.
     - Invalid filter specifications.

**Relationship with JavaScript, HTML, and CSS:**

This `hid.cc` file is the **implementation behind the JavaScript WebHID API**. Here's how they relate:

* **JavaScript:** Web developers use the `navigator.hid` object and its methods (`getDevices()`, `requestDevice()`, and the `connect` and `disconnect` events) in their JavaScript code to interact with HID devices. This C++ code is what makes those JavaScript calls function.

   **Example:**
   ```javascript
   navigator.hid.requestDevice({ filters: [{ vendorId: 0x1234 }] })
     .then(devices => {
       if (devices.length > 0) {
         console.log("HID device selected:", devices[0]);
         devices[0].open(); // Further interaction with the device
       }
     })
     .catch(error => {
       console.error("Error requesting HID device:", error);
     });

   navigator.hid.addEventListener('connect', event => {
     console.log("HID device connected:", event.device);
   });
   ```

* **HTML:** HTML provides the structure for the web page where the JavaScript code using the WebHID API is executed. For instance, a button click in an HTML form might trigger the JavaScript code that calls `navigator.hid.requestDevice()`.

   **Example:**
   ```html
   <button id="connectButton">Connect HID Device</button>
   <script>
     document.getElementById('connectButton').addEventListener('click', () => {
       navigator.hid.requestDevice({ filters: [] });
     });
   </script>
   ```

* **CSS:** CSS is not directly involved in the functionality of this `hid.cc` file. However, CSS can style the user interface elements (like buttons or informational messages) that are part of the user interaction flow for requesting and connecting to HID devices.

**Logical Reasoning (Hypothetical Input and Output):**

**Scenario 1: `getDevices()`**

* **Hypothetical Input:** The JavaScript code `navigator.hid.getDevices()` is executed on a page.
* **Internal Processing:** The `HID::getDevices()` method is called. It communicates with the browser process to retrieve a list of authorized HID devices.
* **Hypothetical Output:** The `Promise` returned by `getDevices()` resolves with an array of `HIDDevice` objects. Each `HIDDevice` object would contain information like `vendorId`, `productId`, `productName`, etc. If no authorized devices are found, the promise resolves with an empty array.

**Scenario 2: `requestDevice()`**

* **Hypothetical Input:** The JavaScript code `navigator.hid.requestDevice({ filters: [{ usagePage: 0x01, usage: 0x02 }] })` is executed after a button click.
* **Internal Processing:**
    1. The `HID::requestDevice()` method is called.
    2. It checks for user activation.
    3. It converts the provided filter into a Mojo structure.
    4. It sends a request to the browser process to show the device picker, filtering devices based on the provided usage page and usage.
    5. The browser displays a system dialog allowing the user to select a matching HID device.
* **Hypothetical Output:**
    * **User selects a device:** The `Promise` resolves with an array containing the selected `HIDDevice` object.
    * **User cancels the dialog:** The `Promise` might reject with an error, or resolve with an empty array (implementation-dependent).
    * **No matching devices found:** The behavior might vary; the promise could reject or resolve with an empty array.

**User or Programming Common Usage Errors:**

1. **Calling `requestDevice()` without user activation:**
   - **Example:**  Calling `navigator.hid.requestDevice()` in the global scope or within a `setTimeout` callback without a preceding user interaction.
   - **Error:** A `SecurityError` will be thrown with the message "Must be handling a user gesture to show a permission request."

2. **Providing invalid filter parameters:**
   - **Example:**  Using `productId` without also specifying `vendorId` in the `filters`.
   - **Error:** A `TypeError` will be thrown with a message like "A filter containing a productId must also contain a vendorId."

3. **Accessing `navigator.hid` in an unsupported context:**
   - **Example:** Trying to use WebHID in a detached iframe or a context where the feature is disabled by Permissions Policy.
   - **Error:** A `NotSupportedError` or `SecurityError` will be thrown.

4. **Adding event listeners for `connect` or `disconnect` too late in a Service Worker:**
   - **Example:** Adding the event listener after the initial evaluation of the Service Worker script.
   - **Warning:** A console warning will be logged indicating that the event handler should be added during the initial evaluation.

**User Operation Steps to Reach This Code (Debugging Clues):**

Let's consider the scenario where a user interacts with a webpage that uses `navigator.hid.requestDevice()`:

1. **User navigates to a webpage:** The user types a URL or clicks a link, loading an HTML page.
2. **Page loads and JavaScript executes:** The browser parses the HTML and executes the embedded JavaScript code.
3. **User interaction triggers a call to `requestDevice()`:** The user might click a button that has an event listener attached to it. This listener executes JavaScript code containing `navigator.hid.requestDevice()`.
4. **Blink's JavaScript engine (V8) intercepts the call:** V8 recognizes the `navigator.hid` object and the `requestDevice` method.
5. **V8 calls the corresponding C++ method in `hid.cc`:**  The `HID::requestDevice()` method in this file is invoked.
6. **`HID::requestDevice()` performs checks:** It verifies user activation and parses the provided filters.
7. **Mojo communication with the browser process:** `HID::requestDevice()` uses the `service_` remote to send a request to the browser process's `HidService`.
8. **Browser process handles the request:** The browser process interacts with the operating system to display the HID device picker dialog.
9. **User selects a device or cancels:** The user interacts with the dialog.
10. **Browser process sends a response back to Blink:** The `HidService` in the browser process sends a response back to the renderer process via the Mojo connection.
11. **`HID::FinishRequestDevice()` is called:** This method in `hid.cc` receives the results from the browser process.
12. **The `Promise` in JavaScript resolves or rejects:**  `HID::FinishRequestDevice()` resolves or rejects the JavaScript `Promise` based on the browser's response (selected devices or an error).

**Debugging Tips:**

* **Breakpoints in `hid.cc`:** Set breakpoints in methods like `HID::requestDevice()`, `HID::getDevices()`, `HID::DeviceAdded()`, etc., to trace the execution flow.
* **Console logging in JavaScript:** Add `console.log` statements before and after calls to `navigator.hid` methods to see when they are called and what data is being passed.
* **Inspect Mojo messages:** Use Chromium's internal tools (like `chrome://tracing`) to inspect the Mojo messages being exchanged between the renderer and browser processes. This can help identify issues in the communication layer.
* **Check Permissions Policy:** Verify that the "hid" feature is not blocked by the Permissions Policy using developer tools.
* **Examine user activation state:**  Ensure that calls to `requestDevice()` are indeed happening within a user gesture handler.

In summary, `hid.cc` is a crucial component of the Blink rendering engine that implements the core logic for the WebHID API, enabling web pages to interact with a wide range of human interface devices. It handles device discovery, connection requests, event management, security, and communication with the browser process.

### 提示词
```
这是目录为blink/renderer/modules/hid/hid.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/hid/hid.h"

#include <utility>

#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/mojom/service_worker/service_worker.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_hid_device_filter.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_hid_device_request_options.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/navigator_base.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/modules/event_target_modules.h"
#include "third_party/blink/renderer/modules/hid/hid_connection_event.h"
#include "third_party/blink/renderer/modules/hid/hid_device.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_global_scope.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

namespace {

const char kContextGone[] = "Script context has shut down.";
const char kFeaturePolicyBlocked[] =
    "Access to the feature \"hid\" is disallowed by permissions policy.";

bool IsContextSupported(ExecutionContext* context) {
  // Since WebHID on Web Workers is in the process of being implemented, we
  // check here if the runtime flag for the appropriate worker is enabled.
  // TODO(https://crbug.com/365932453): Remove this check once the feature has
  // shipped.
  if (!context) {
    return false;
  }

  DCHECK(context->IsWindow() || context->IsDedicatedWorkerGlobalScope() ||
         context->IsServiceWorkerGlobalScope());
  DCHECK(!context->IsDedicatedWorkerGlobalScope() ||
         RuntimeEnabledFeatures::WebHIDOnDedicatedWorkersEnabled());
  DCHECK(!context->IsServiceWorkerGlobalScope() ||
         RuntimeEnabledFeatures::WebHIDOnServiceWorkersEnabled());

  return true;
}

// Carries out basic checks for the web-exposed APIs, to make sure the minimum
// requirements for them to be served are met. Returns true if any conditions
// fail to be met, generating an appropriate exception as well. Otherwise,
// returns false to indicate the call should be allowed.
bool ShouldBlockHidServiceCall(LocalDOMWindow* window,
                               ExecutionContext* context,
                               ExceptionState* exception_state) {
  if (!IsContextSupported(context)) {
    if (exception_state) {
      exception_state->ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                         kContextGone);
    }
    return true;
  }

  // For window and dedicated workers, reject the request if the top-level frame
  // has an opaque origin. For Service Workers, we use their security origin
  // directly as they do not use delegated permissions.
  const SecurityOrigin* security_origin = nullptr;
  if (context->IsWindow()) {
    security_origin =
        window->GetFrame()->Top()->GetSecurityContext()->GetSecurityOrigin();
  } else if (context->IsDedicatedWorkerGlobalScope()) {
    security_origin = static_cast<WorkerGlobalScope*>(context)
                          ->top_level_frame_security_origin();
  } else if (context->IsServiceWorkerGlobalScope()) {
    security_origin = context->GetSecurityOrigin();
  } else {
    NOTREACHED();
  }
  if (security_origin->IsOpaque()) {
    if (exception_state) {
      exception_state->ThrowSecurityError(
          "Access to the WebHID API is denied from contexts where the "
          "top-level "
          "document has an opaque origin.");
    }
    return true;
  }

  if (!context->IsFeatureEnabled(mojom::blink::PermissionsPolicyFeature::kHid,
                                 ReportOptions::kReportOnFailure)) {
    if (exception_state) {
      exception_state->ThrowSecurityError(kFeaturePolicyBlocked);
    }
    return true;
  }

  return false;
}

void RejectWithTypeError(const String& message,
                         ScriptPromiseResolverBase* resolver) {
  ScriptState::Scope scope(resolver->GetScriptState());
  v8::Isolate* isolate = resolver->GetScriptState()->GetIsolate();
  resolver->Reject(V8ThrowException::CreateTypeError(isolate, message));
}

}  // namespace

const char HID::kSupplementName[] = "HID";

HID* HID::hid(NavigatorBase& navigator) {
  HID* hid = Supplement<NavigatorBase>::From<HID>(navigator);
  if (!hid) {
    hid = MakeGarbageCollected<HID>(navigator);
    ProvideTo(navigator, hid);
  }
  return hid;
}

HID::HID(NavigatorBase& navigator)
    : Supplement<NavigatorBase>(navigator),
      service_(navigator.GetExecutionContext()),
      receiver_(this, navigator.GetExecutionContext()) {
  auto* context = GetExecutionContext();
  if (context) {
    feature_handle_for_scheduler_ = context->GetScheduler()->RegisterFeature(
        SchedulingPolicy::Feature::kWebHID,
        {SchedulingPolicy::DisableBackForwardCache()});
  }
}

HID::~HID() {
  DCHECK(get_devices_promises_.empty());
  DCHECK(request_device_promises_.empty());
}

ExecutionContext* HID::GetExecutionContext() const {
  return GetSupplementable()->GetExecutionContext();
}

const AtomicString& HID::InterfaceName() const {
  return event_target_names::kHID;
}

void HID::AddedEventListener(const AtomicString& event_type,
                             RegisteredEventListener& listener) {
  EventTarget::AddedEventListener(event_type, listener);

  if (event_type != event_type_names::kConnect &&
      event_type != event_type_names::kDisconnect) {
    return;
  }

  auto* context = GetExecutionContext();
  if (ShouldBlockHidServiceCall(GetSupplementable()->DomWindow(), context,
                                nullptr)) {
    return;
  }

  if (context->IsServiceWorkerGlobalScope()) {
    auto* service_worker_global_scope =
        static_cast<ServiceWorkerGlobalScope*>(context);
    if (service_worker_global_scope->did_evaluate_script()) {
      String message = String::Format(
          "Event handler of '%s' event must be added on the initial evaluation "
          "of worker script. More info: "
          "https://developer.chrome.com/docs/extensions/mv3/service_workers/"
          "events/",
          event_type.Utf8().c_str());
      GetExecutionContext()->AddConsoleMessage(
          mojom::blink::ConsoleMessageSource::kJavaScript,
          mojom::blink::ConsoleMessageLevel::kWarning, message);
    }
  }

  EnsureServiceConnection();
}

void HID::DeviceAdded(device::mojom::blink::HidDeviceInfoPtr device_info) {
  auto* device = GetOrCreateDevice(std::move(device_info));

  DispatchEvent(*MakeGarbageCollected<HIDConnectionEvent>(
      event_type_names::kConnect, device));
}

void HID::DeviceRemoved(device::mojom::blink::HidDeviceInfoPtr device_info) {
  auto* device = GetOrCreateDevice(std::move(device_info));

  DispatchEvent(*MakeGarbageCollected<HIDConnectionEvent>(
      event_type_names::kDisconnect, device));
}

void HID::DeviceChanged(device::mojom::blink::HidDeviceInfoPtr device_info) {
  auto it = device_cache_.find(device_info->guid);
  if (it != device_cache_.end()) {
    it->value->UpdateDeviceInfo(std::move(device_info));
    return;
  }

  // If the GUID is not in the |device_cache_| then this is the first time we
  // have been notified for this device.
  DeviceAdded(std::move(device_info));
}

ScriptPromise<IDLSequence<HIDDevice>> HID::getDevices(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (ShouldBlockHidServiceCall(GetSupplementable()->DomWindow(),
                                GetExecutionContext(), &exception_state)) {
    return ScriptPromise<IDLSequence<HIDDevice>>();
  }

  auto* resolver = MakeGarbageCollected<HIDDeviceResolver>(
      script_state, exception_state.GetContext());
  get_devices_promises_.insert(resolver);

  EnsureServiceConnection();
  service_->GetDevices(WTF::BindOnce(
      &HID::FinishGetDevices, WrapPersistent(this), WrapPersistent(resolver)));
  return resolver->Promise();
}

ScriptPromise<IDLSequence<HIDDevice>> HID::requestDevice(
    ScriptState* script_state,
    const HIDDeviceRequestOptions* options,
    ExceptionState& exception_state) {
  // requestDevice requires a window to satisfy the user activation requirement
  // and to show a chooser dialog.
  auto* window = GetSupplementable()->DomWindow();
  if (!window) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      kContextGone);
    return ScriptPromise<IDLSequence<HIDDevice>>();
  }

  if (ShouldBlockHidServiceCall(window, GetExecutionContext(),
                                &exception_state)) {
    return ScriptPromise<IDLSequence<HIDDevice>>();
  }

  if (!LocalFrame::HasTransientUserActivation(window->GetFrame())) {
    exception_state.ThrowSecurityError(
        "Must be handling a user gesture to show a permission request.");
    return ScriptPromise<IDLSequence<HIDDevice>>();
  }

  auto* resolver = MakeGarbageCollected<HIDDeviceResolver>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  request_device_promises_.insert(resolver);

  Vector<mojom::blink::HidDeviceFilterPtr> mojo_filters;
  if (options->hasFilters()) {
    mojo_filters.reserve(options->filters().size());
    for (const auto& filter : options->filters()) {
      String error_message = CheckDeviceFilterValidity(*filter);
      if (error_message) {
        RejectWithTypeError(error_message, resolver);
        return promise;
      }
      mojo_filters.push_back(ConvertDeviceFilter(*filter));
    }
  }
  DCHECK_EQ(options->filters().size(), mojo_filters.size());

  Vector<mojom::blink::HidDeviceFilterPtr> mojo_exclusion_filters;
  if (options->hasExclusionFilters()) {
    if (options->exclusionFilters().size() == 0) {
      exception_state.ThrowTypeError(
          "'exclusionFilters', if present, must contain at least one filter.");
      return ScriptPromise<IDLSequence<HIDDevice>>();
    }
    mojo_exclusion_filters.reserve(options->exclusionFilters().size());
    for (const auto& exclusion_filter : options->exclusionFilters()) {
      String error_message = CheckDeviceFilterValidity(*exclusion_filter);
      if (error_message) {
        RejectWithTypeError(error_message, resolver);
        return promise;
      }
      mojo_exclusion_filters.push_back(ConvertDeviceFilter(*exclusion_filter));
    }
    DCHECK_EQ(options->exclusionFilters().size(),
              mojo_exclusion_filters.size());
  }

  EnsureServiceConnection();
  service_->RequestDevice(
      std::move(mojo_filters), std::move(mojo_exclusion_filters),
      WTF::BindOnce(&HID::FinishRequestDevice, WrapPersistent(this),
                    WrapPersistent(resolver)));
  return promise;
}

void HID::Connect(
    const String& device_guid,
    mojo::PendingRemote<device::mojom::blink::HidConnectionClient> client,
    device::mojom::blink::HidManager::ConnectCallback callback) {
  EnsureServiceConnection();
  service_->Connect(device_guid, std::move(client), std::move(callback));
}

void HID::Forget(device::mojom::blink::HidDeviceInfoPtr device_info,
                 mojom::blink::HidService::ForgetCallback callback) {
  EnsureServiceConnection();
  service_->Forget(std::move(device_info), std::move(callback));
}

HIDDevice* HID::GetOrCreateDevice(device::mojom::blink::HidDeviceInfoPtr info) {
  auto it = device_cache_.find(info->guid);
  if (it != device_cache_.end()) {
    return it->value.Get();
  }

  const String guid = info->guid;
  HIDDevice* device = MakeGarbageCollected<HIDDevice>(this, std::move(info),
                                                      GetExecutionContext());
  device_cache_.insert(guid, device);
  return device;
}

void HID::FinishGetDevices(
    HIDDeviceResolver* resolver,
    Vector<device::mojom::blink::HidDeviceInfoPtr> device_infos) {
  DCHECK(get_devices_promises_.Contains(resolver));
  get_devices_promises_.erase(resolver);

  HeapVector<Member<HIDDevice>> devices;
  for (auto& device_info : device_infos)
    devices.push_back(GetOrCreateDevice(std::move(device_info)));

  resolver->Resolve(devices);
}

void HID::FinishRequestDevice(
    HIDDeviceResolver* resolver,
    Vector<device::mojom::blink::HidDeviceInfoPtr> device_infos) {
  DCHECK(request_device_promises_.Contains(resolver));
  request_device_promises_.erase(resolver);

  HeapVector<Member<HIDDevice>> devices;
  for (auto& device_info : device_infos) {
    auto* device = GetOrCreateDevice(std::move(device_info));
    device->ResetIsForgotten();
    devices.push_back(device);
  }

  resolver->Resolve(devices);
}

void HID::EnsureServiceConnection() {
  DCHECK(GetExecutionContext());

  if (service_.is_bound())
    return;

  DCHECK(IsContextSupported(GetExecutionContext()));

  auto task_runner =
      GetExecutionContext()->GetTaskRunner(TaskType::kMiscPlatformAPI);
  GetExecutionContext()->GetBrowserInterfaceBroker().GetInterface(
      service_.BindNewPipeAndPassReceiver(task_runner));
  service_.set_disconnect_handler(
      WTF::BindOnce(&HID::CloseServiceConnection, WrapWeakPersistent(this)));
  DCHECK(!receiver_.is_bound());
  service_->RegisterClient(receiver_.BindNewEndpointAndPassRemote(task_runner));
}

void HID::CloseServiceConnection() {
  service_.reset();
  receiver_.reset();

  // Script may execute during a call to Resolve(). Swap these sets to prevent
  // concurrent modification.
  HeapHashSet<Member<HIDDeviceResolver>> get_devices_promises;
  get_devices_promises_.swap(get_devices_promises);
  for (HIDDeviceResolver* resolver : get_devices_promises) {
    resolver->Resolve(HeapVector<Member<HIDDevice>>());
  }

  HeapHashSet<Member<HIDDeviceResolver>> request_device_promises;
  request_device_promises_.swap(request_device_promises);
  for (HIDDeviceResolver* resolver : request_device_promises) {
    resolver->Resolve(HeapVector<Member<HIDDevice>>());
  }
}

mojom::blink::HidDeviceFilterPtr HID::ConvertDeviceFilter(
    const HIDDeviceFilter& filter) {
  DCHECK(!CheckDeviceFilterValidity(filter));

  auto mojo_filter = mojom::blink::HidDeviceFilter::New();
  if (filter.hasVendorId()) {
    if (filter.hasProductId()) {
      mojo_filter->device_ids =
          mojom::blink::DeviceIdFilter::NewVendorAndProduct(
              mojom::blink::VendorAndProduct::New(filter.vendorId(),
                                                  filter.productId()));
    } else {
      mojo_filter->device_ids =
          mojom::blink::DeviceIdFilter::NewVendor(filter.vendorId());
    }
  }
  if (filter.hasUsagePage()) {
    if (filter.hasUsage()) {
      mojo_filter->usage = mojom::blink::UsageFilter::NewUsageAndPage(
          device::mojom::blink::HidUsageAndPage::New(filter.usage(),
                                                     filter.usagePage()));
    } else {
      mojo_filter->usage =
          mojom::blink::UsageFilter::NewPage(filter.usagePage());
    }
  }
  return mojo_filter;
}

String HID::CheckDeviceFilterValidity(const HIDDeviceFilter& filter) {
  if (!filter.hasVendorId() && !filter.hasProductId() &&
      !filter.hasUsagePage() && !filter.hasUsage()) {
    return "A filter must provide a property to filter by.";
  }

  if (filter.hasProductId() && !filter.hasVendorId()) {
    return "A filter containing a productId must also contain a vendorId.";
  }

  if (filter.hasUsage() && !filter.hasUsagePage()) {
    return "A filter containing a usage must also contain a usagePage.";
  }

  return String();
}

void HID::Trace(Visitor* visitor) const {
  visitor->Trace(service_);
  visitor->Trace(get_devices_promises_);
  visitor->Trace(request_device_promises_);
  visitor->Trace(device_cache_);
  visitor->Trace(receiver_);
  EventTarget::Trace(visitor);
  Supplement<NavigatorBase>::Trace(visitor);
}

}  // namespace blink
```