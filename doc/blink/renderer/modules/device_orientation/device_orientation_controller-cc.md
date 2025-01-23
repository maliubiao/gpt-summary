Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request asks for the functionality of the `DeviceOrientationController.cc` file, its relationship to web technologies (JavaScript, HTML, CSS), logic reasoning examples, common usage errors, and debugging information.

2. **Initial Code Scan - Identify Key Components:**
   - Look for class names: `DeviceOrientationController`. This is the central focus.
   - Look for included headers: These hint at dependencies and functionality. `DeviceOrientationData`, `DeviceOrientationEvent`, `DeviceOrientationEventPump`, `PermissionService`, etc., are strong indicators.
   - Look for important methods: Constructor, destructor, `DidUpdateData`, `DidAddEventListener`, `LastData`, `RequestPermission`, `SetOverride`, etc. These are the actions the class performs.
   - Look for member variables: `orientation_event_pump_`, `override_orientation_data_`, `permission_service_`, `has_event_listener_`, `has_requested_permission_`. These represent the state of the object.
   - Look for namespaces: `blink`. This confirms it's part of the Blink rendering engine.

3. **Core Functionality - Deduction from Names and Methods:**
   - **Device Orientation:** The name itself and classes like `DeviceOrientationData` and `DeviceOrientationEvent` strongly suggest handling device orientation data (alpha, beta, gamma, acceleration, etc.).
   - **Event Handling:**  `DidAddEventListener`, `DispatchDeviceEvent`, `EventTypeName` point to managing event listeners for device orientation changes.
   - **Permissions:** `RequestPermission`, `permission_service_`, and mentions of `PermissionsPolicy` indicate involvement in requesting and checking permissions for accessing device sensors.
   - **Data Management:** `LastData`, `SetOverride`, `ClearOverride` suggest managing and potentially overriding the actual sensor data.
   - **Event Pump:** `DeviceOrientationEventPump` likely handles the underlying mechanism of receiving sensor data from the platform.

4. **Relating to Web Technologies:**
   - **JavaScript:** The `RequestPermission` method returns a `ScriptPromise`, a JavaScript construct. The `DeviceOrientationEvent` will be dispatched to JavaScript event listeners. The use of `LocalDOMWindow` directly connects this to the browser's window object, which is a key JavaScript interface.
   - **HTML:**  The events are dispatched to the `window` object, which is part of the HTML DOM. The permissions might be indirectly related to iframe contexts or the overall security context of the HTML document.
   - **CSS:**  While this code doesn't directly manipulate CSS, CSS *can* be affected by JavaScript code that uses device orientation information. For example, a website might use JavaScript to rotate elements based on device orientation.

5. **Logic Reasoning (Hypothetical Input/Output):**
   - **Permission Flow:** Imagine a user visiting a website. The JavaScript calls `window.DeviceOrientationEvent.requestPermission()`. The `RequestPermission` method in this C++ class is triggered. It interacts with the permission service. The output would be the resolution of the JavaScript promise (granted or denied).
   - **Event Flow:** The device orientation changes. The operating system provides this data. The `DeviceOrientationEventPump` receives it, creates a `DeviceOrientationData` object. `DidUpdateData` is called, which creates a `DeviceOrientationEvent` and dispatches it. The output is the JavaScript `deviceorientation` event firing with the new data.

6. **Common Usage Errors:**
   - **Not Requesting Permission:**  Accessing device orientation without explicitly requesting permission will often be blocked in modern browsers. The code itself checks for this and logs a warning.
   - **Ignoring Permission Denials:**  The JavaScript code needs to handle the case where the permission is denied.
   - **Incorrect Event Listener:**  Listening for the wrong event type or on the wrong object.
   - **Security Context:** Trying to use the API in a non-secure context (HTTP).

7. **Debugging Clues (User Actions Leading to the Code):**
   - The user opens a web page.
   - The web page's JavaScript code attempts to access device orientation information (e.g., by adding an event listener or calling `requestPermission`).
   - The browser, upon encountering this JavaScript, will execute the corresponding Blink C++ code, including the `DeviceOrientationController`. The `DidAddEventListener` or `RequestPermission` methods would be entry points. Device motion could trigger `DidUpdateData`.

8. **Refine and Organize:** After the initial analysis, structure the information clearly with headings like "Functionality," "Relationship to Web Technologies," etc. Use bullet points and examples for better readability. Ensure the language is accurate and avoids overly technical jargon where possible while still being precise. Double-check for consistency and accuracy. For example, ensure that the JavaScript examples correctly reflect how the API would be used.

9. **Self-Critique:** Review the answer. Are the examples clear?  Is the explanation of the code's role accurate?  Have I addressed all parts of the prompt?  Could anything be explained more simply?  (For instance, initially, I might have just listed the included headers without explaining *why* they are important, so I'd refine that to explain what functionality those headers relate to).

By following these steps, you can systematically analyze C++ code within a browser engine context and effectively explain its role and interactions with web technologies.
好的，我们来详细分析一下 `blink/renderer/modules/device_orientation/device_orientation_controller.cc` 这个文件。

**功能列举：**

`DeviceOrientationController` 类的主要功能是管理设备方向（Device Orientation）事件在浏览器渲染引擎 Blink 中的处理。具体来说，它负责：

1. **监听和管理设备方向数据的更新：**  它从底层平台（操作系统或硬件）接收设备方向数据（例如，设备的旋转角度）。
2. **创建和分发 `DeviceOrientationEvent`：** 当设备方向数据更新时，它会创建一个 `DeviceOrientationEvent` 对象，并将该事件分发给注册了监听器的 JavaScript 代码。
3. **处理权限请求：** 它处理 JavaScript 代码发起的获取设备方向权限的请求，并与权限服务（`permission_service_`）交互。
4. **管理事件监听器：**  跟踪 `deviceorientation` 事件的监听器，并在添加或移除监听器时采取相应的操作（例如，开始或停止监听底层设备方向数据）。
5. **遵守 Permissions Policy：** 检查 Permissions Policy，确保当前上下文有权限访问设备方向传感器。
6. **提供数据覆盖机制：** 允许开发者或测试代码通过 `SetOverride` 方法设置一个固定的设备方向数据，用于测试或模拟场景。
7. **记录使用情况：** 使用 `UseCounter` 记录设备方向 API 的使用情况，例如是否在安全上下文中使用，是否在没有请求权限的情况下使用等。
8. **处理安全上下文：** 限制 `deviceorientation` API 只能在安全上下文（HTTPS）中使用。
9. **优化资源使用：**  只在有监听器注册时才开始监听设备方向数据，并在没有监听器时停止监听，以节省资源。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`DeviceOrientationController` 是 Blink 引擎中连接底层设备传感器和上层 Web API 的桥梁。它与 JavaScript、HTML 的交互最为直接。

1. **JavaScript:**
   - **事件监听：** JavaScript 代码可以使用 `window.addEventListener('deviceorientation', function(event) { ... })` 来监听设备方向事件。当 `DeviceOrientationController` 接收到新的设备方向数据并创建 `DeviceOrientationEvent` 时，这个事件会被分发到 JavaScript 中注册的回调函数。
     ```javascript
     window.addEventListener('deviceorientation', function(event) {
       console.log('Alpha:', event.alpha); // 设备绕 Z 轴旋转的角度
       console.log('Beta:', event.beta);   // 设备绕 X 轴旋转的角度
       console.log('Gamma:', event.gamma);  // 设备绕 Y 轴旋转的角度
     });
     ```
   - **权限请求：** JavaScript 代码可以使用新的 Permissions API 请求设备方向权限：
     ```javascript
     navigator.permissions.query({ name: 'device-orientation' })
       .then(function(result) {
         if (result.state === 'granted') {
           // 权限已授予，可以监听事件
         } else if (result.state === 'prompt') {
           // 用户需要授权
         } else if (result.state === 'denied') {
           // 权限被拒绝
         }
       });
     ```
     或者使用 `DeviceOrientationController` 提供的 `requestPermission` 方法（虽然注释中提到目前 Chromium 的传感器权限 UI 没有 "ask" 状态，但这仍然是代码中存在的方法）：
     ```javascript
     window.DeviceOrientationEvent.requestPermission()
       .then(permissionState => {
         if (permissionState === 'granted') {
           // 权限已授予
         } else if (permissionState === 'denied') {
           // 权限被拒绝
         }
       });
     ```

2. **HTML:**
   - `DeviceOrientationController` 与 HTML 元素本身没有直接的交互。但是，HTML 结构中创建的 `<iframe>` 可能会影响权限策略，因为 Permissions Policy 可以应用于不同的浏览上下文。

3. **CSS:**
   - `DeviceOrientationController` 本身不直接操作 CSS。然而，通过 JavaScript 接收到的设备方向数据，开发者可以使用 JavaScript 来动态修改 CSS 属性，从而实现基于设备方向的视觉效果。
     ```javascript
     window.addEventListener('deviceorientation', function(event) {
       const rotateY = event.gamma + 'deg';
       document.getElementById('myElement').style.transform = `rotateY(${rotateY})`;
     });
     ```

**逻辑推理 (假设输入与输出)：**

**场景 1：用户首次访问请求设备方向权限的网站（在安全上下文中）**

* **假设输入：**
    1. 用户访问了一个 HTTPS 网站，该网站的 JavaScript 代码调用了 `window.DeviceOrientationEvent.requestPermission()`。
    2. 用户之前没有对该网站的设备方向权限做出过决定。
* **处理过程：**
    1. JavaScript 调用触发 `DeviceOrientationController::RequestPermission` 方法。
    2. `RequestPermission` 方法与权限服务 (`permission_service_`) 交互，显示权限请求弹窗给用户。
    3. 用户在弹窗中选择 "允许" 或 "阻止"。
* **假设输出：**
    1. 如果用户选择 "允许"，权限服务返回 `mojom::blink::PermissionStatus::GRANTED`。`RequestPermission` 的 Promise 将 resolve 为 `'granted'`。
    2. 如果用户选择 "阻止"，权限服务返回 `mojom::blink::PermissionStatus::DENIED`。`RequestPermission` 的 Promise 将 resolve 为 `'denied'`。

**场景 2：设备方向发生变化，且页面有监听器**

* **假设输入：**
    1. 用户在一个已经授予设备方向权限的 HTTPS 网站上。
    2. 网站的 JavaScript 代码已经通过 `window.addEventListener('deviceorientation', ...)` 注册了监听器。
    3. 底层操作系统/硬件报告了新的设备方向数据 (例如，`alpha: 90, beta: 45, gamma: -30`)。
* **处理过程：**
    1. 底层平台将新的数据传递给 Blink 引擎。
    2. `DeviceOrientationController::DidUpdateData` 方法被调用。
    3. `DidUpdateData` 创建一个新的 `DeviceOrientationEvent` 对象，并将最新的设备方向数据填充到事件中。
    4. 该事件被分发到之前注册的 JavaScript 监听器。
* **假设输出：**
    1. JavaScript 监听器的回调函数被执行，`event.alpha` 的值为 `90`，`event.beta` 的值为 `45`，`event.gamma` 的值为 `-30`。

**用户或编程常见的使用错误及举例说明：**

1. **未在安全上下文中使用：**  在非 HTTPS 页面上使用设备方向 API 会失败。浏览器通常会阻止该功能，并在控制台中显示警告。
   ```javascript
   // 在 HTTP 页面上尝试监听 deviceorientation 事件
   window.addEventListener('deviceorientation', function(event) {
       console.log("设备方向数据", event); // 这可能不会执行
   });
   ```
   **错误信息示例：**  浏览器的开发者工具控制台中可能会显示类似 "deviceorientation events are deprecated on insecure origins. Consider upgrading your site to HTTPS." 的警告。

2. **忘记请求权限：**  在用户明确授予权限之前，尝试监听设备方向事件可能不会收到任何数据，或者浏览器会阻止该功能。
   ```javascript
   // 直接监听事件，但没有请求权限
   window.addEventListener('deviceorientation', function(event) {
       console.log("设备方向数据", event); // 可能不会执行，或者初始数据为 null
   });
   ```
   **改进方法：** 先检查权限状态，如果需要则请求权限。

3. **错误地处理权限被拒绝的情况：**  如果用户拒绝了权限请求，应用程序需要妥善处理这种情况，例如提供降级方案或告知用户为什么需要该权限。
   ```javascript
   window.DeviceOrientationEvent.requestPermission()
     .then(permissionState => {
       if (permissionState === 'granted') {
         window.addEventListener('deviceorientation', function(event) {
           console.log("设备方向数据", event);
         });
       } else if (permissionState === 'denied') {
         console.log("用户拒绝了设备方向权限。");
         // 提供替代功能或解释
       }
     });
   ```

4. **在不需要时保持监听器活动：**  持续监听设备方向事件可能会消耗设备资源（例如电池）。应该在不需要时移除监听器。
   ```javascript
   const handleOrientation = function(event) {
     console.log("设备方向数据", event);
   };

   window.addEventListener('deviceorientation', handleOrientation);

   // ... 在不再需要时移除监听器
   window.removeEventListener('deviceorientation', handleOrientation);
   ```

**用户操作是如何一步步的到达这里，作为调试线索：**

假设开发者需要调试 `DeviceOrientationController` 的行为，以下是用户操作可能触发相关代码的步骤：

1. **用户打开一个网页：**  用户在浏览器中输入网址或点击链接，加载一个包含设备方向相关功能的网页。
2. **网页的 JavaScript 代码尝试访问设备方向 API：**
   - **添加事件监听器：** 网页的 JavaScript 代码执行 `window.addEventListener('deviceorientation', ...)`。这会触发 `DeviceOrientationController::DidAddEventListener` 方法。在该方法中，会进行安全上下文检查、Permissions Policy 检查，并可能开始监听底层设备方向数据。
   - **请求权限：** 网页的 JavaScript 代码执行 `window.DeviceOrientationEvent.requestPermission()`。这会触发 `DeviceOrientationController::RequestPermission` 方法，进而与权限服务交互。
3. **设备方向发生变化：**
   - 用户移动或旋转他们的设备（手机、平板电脑等）。
   - 操作系统或硬件传感器检测到设备方向的变化。
   - 操作系统将新的设备方向数据传递给浏览器。
   - Blink 引擎接收到数据，并通知 `DeviceOrientationController`。
   - `DeviceOrientationController::DidUpdateData` 方法被调用，创建并分发 `DeviceOrientationEvent`。
4. **开发者可能设置了覆盖数据：**
   - 在测试或调试环境中，开发者可能会使用 Blink 提供的 DevTools 功能或者内部 API 来调用 `DeviceOrientationController::SetOverride` 方法，手动设置设备方向数据，模拟特定的设备状态。

**调试线索：**

当调试设备方向相关问题时，可以关注以下几点：

* **权限状态：** 检查网站是否拥有设备方向权限。可以在浏览器的网站设置中查看。
* **安全上下文：** 确保网页运行在 HTTPS 上。
* **Permissions Policy：** 检查页面的 Permissions Policy 是否阻止了设备方向功能。
* **事件监听器：** 确认 JavaScript 代码是否正确地添加了 `deviceorientation` 事件监听器。
* **控制台输出：** 查看浏览器的开发者工具控制台，是否有与设备方向相关的警告或错误信息。
* **断点调试：** 在 `DeviceOrientationController` 的关键方法（例如 `DidAddEventListener`, `DidUpdateData`, `RequestPermission`）设置断点，跟踪代码执行流程，查看数据传递过程。
* **覆盖数据的影响：** 如果怀疑是覆盖数据导致的问题，可以检查是否设置了覆盖，并通过 `ClearOverride` 清除。

希望以上分析能够帮助你理解 `blink/renderer/modules/device_orientation/device_orientation_controller.cc` 文件的功能和它在 Web 技术栈中的作用。

### 提示词
```
这是目录为blink/renderer/modules/device_orientation/device_orientation_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/device_orientation/device_orientation_controller.h"

#include "base/notreached.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_metric_builder.h"
#include "third_party/blink/public/mojom/permissions/permission_status.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_device_orientation_permission_state.h"
#include "third_party/blink/renderer/core/frame/dactyloscoper.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/modules/device_orientation/device_orientation_data.h"
#include "third_party/blink/renderer/modules/device_orientation/device_orientation_event.h"
#include "third_party/blink/renderer/modules/device_orientation/device_orientation_event_pump.h"
#include "third_party/blink/renderer/modules/event_modules.h"
#include "third_party/blink/renderer/modules/permissions/permission_utils.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/assertions.h"

namespace blink {

DeviceOrientationController::DeviceOrientationController(LocalDOMWindow& window)
    : DeviceSingleWindowEventController(window),
      Supplement<LocalDOMWindow>(window),
      permission_service_(&window) {}

DeviceOrientationController::~DeviceOrientationController() = default;

void DeviceOrientationController::DidUpdateData() {
  if (override_orientation_data_)
    return;
  DispatchDeviceEvent(LastEvent());
}

const char DeviceOrientationController::kSupplementName[] =
    "DeviceOrientationController";

DeviceOrientationController& DeviceOrientationController::From(
    LocalDOMWindow& window) {
  DeviceOrientationController* controller =
      Supplement<LocalDOMWindow>::From<DeviceOrientationController>(window);
  if (!controller) {
    controller = MakeGarbageCollected<DeviceOrientationController>(window);
    ProvideTo(window, controller);
  }
  return *controller;
}

void DeviceOrientationController::DidAddEventListener(
    LocalDOMWindow* window,
    const AtomicString& event_type) {
  if (event_type != EventTypeName())
    return;

  // The window could be detached, e.g. if it is the `contentWindow` of an
  // <iframe> that has been removed from the DOM of its parent frame.
  if (GetWindow().IsContextDestroyed())
    return;

  // The API is not exposed to Workers or Worklets, so if the current realm
  // execution context is valid, it must have a responsible browsing context.
  SECURITY_CHECK(GetWindow().GetFrame());

  // The event handler property on `window` is restricted to [SecureContext],
  // but nothing prevents a site from calling `window.addEventListener(...)`
  // from a non-secure browsing context.
  if (!GetWindow().IsSecureContext())
    return;

  UseCounter::Count(GetWindow(), WebFeature::kDeviceOrientationSecureOrigin);
  Dactyloscoper::RecordDirectSurface(
      &GetWindow(), WebFeature::kDeviceOrientationSecureOrigin, String());

  if (!has_requested_permission_) {
    UseCounter::Count(
        GetWindow(),
        WebFeature::kDeviceOrientationUsedWithoutPermissionRequest);
  }

  if (!has_event_listener_) {
    if (!CheckPolicyFeatures(
            {mojom::blink::PermissionsPolicyFeature::kAccelerometer,
             mojom::blink::PermissionsPolicyFeature::kGyroscope})) {
      LogToConsolePolicyFeaturesDisabled(*GetWindow().GetFrame(),
                                         EventTypeName());
      return;
    }
  }

  DeviceSingleWindowEventController::DidAddEventListener(window, event_type);
}

DeviceOrientationData* DeviceOrientationController::LastData() const {
  return override_orientation_data_
             ? override_orientation_data_.Get()
             : orientation_event_pump_
                   ? orientation_event_pump_->LatestDeviceOrientationData()
                   : nullptr;
}

bool DeviceOrientationController::HasLastData() {
  return LastData();
}

void DeviceOrientationController::RegisterWithDispatcher() {
  RegisterWithOrientationEventPump(false /* absolute */);
}

void DeviceOrientationController::UnregisterWithDispatcher() {
  if (orientation_event_pump_)
    orientation_event_pump_->RemoveController();
}

Event* DeviceOrientationController::LastEvent() const {
  return DeviceOrientationEvent::Create(EventTypeName(), LastData());
}

bool DeviceOrientationController::IsNullEvent(Event* event) const {
  auto* orientation_event = To<DeviceOrientationEvent>(event);
  return !orientation_event->Orientation()->CanProvideEventData();
}

const AtomicString& DeviceOrientationController::EventTypeName() const {
  return event_type_names::kDeviceorientation;
}

void DeviceOrientationController::SetOverride(
    DeviceOrientationData* device_orientation_data) {
  DCHECK(device_orientation_data);
  override_orientation_data_ = device_orientation_data;
  DispatchDeviceEvent(LastEvent());
}

void DeviceOrientationController::ClearOverride() {
  if (!override_orientation_data_)
    return;
  override_orientation_data_.Clear();
  if (LastData())
    DidUpdateData();
}

void DeviceOrientationController::RestartPumpIfNeeded() {
  if (!orientation_event_pump_ || !has_event_listener_) {
    return;
  }
  // We do this to make sure that existing connections to
  // device::mojom::blink::Sensor instances are dropped and GetSensor() is
  // called again, so that e.g. the virtual sensors are used when added, or the
  // real ones are used again when the virtual sensors are removed.
  StopUpdating();
  set_needs_checking_null_events(/*enabled=*/true);
  orientation_event_pump_.Clear();
  StartUpdating();
}

void DeviceOrientationController::Trace(Visitor* visitor) const {
  visitor->Trace(override_orientation_data_);
  visitor->Trace(orientation_event_pump_);
  visitor->Trace(permission_service_);
  DeviceSingleWindowEventController::Trace(visitor);
  Supplement<LocalDOMWindow>::Trace(visitor);
}

void DeviceOrientationController::RegisterWithOrientationEventPump(
    bool absolute) {
  if (!orientation_event_pump_) {
    orientation_event_pump_ = MakeGarbageCollected<DeviceOrientationEventPump>(
        *GetWindow().GetFrame(), absolute);
  }
  orientation_event_pump_->SetController(this);
}

ScriptPromise<V8DeviceOrientationPermissionState>
DeviceOrientationController::RequestPermission(ScriptState* script_state) {
  ExecutionContext* context = GetSupplementable();
  DCHECK_EQ(context, ExecutionContext::From(script_state));

  has_requested_permission_ = true;

  if (!permission_service_.is_bound()) {
    ConnectToPermissionService(context,
                               permission_service_.BindNewPipeAndPassReceiver(
                                   context->GetTaskRunner(TaskType::kSensor)));
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<V8DeviceOrientationPermissionState>>(script_state);
  auto promise = resolver->Promise();

  permission_service_->HasPermission(
      CreatePermissionDescriptor(mojom::blink::PermissionName::SENSORS),
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          [](ScriptPromiseResolver<V8DeviceOrientationPermissionState>*
                 resolver,
             mojom::blink::PermissionStatus status) {
            switch (status) {
              case mojom::blink::PermissionStatus::GRANTED:
              case mojom::blink::PermissionStatus::DENIED:
                resolver->Resolve(*V8DeviceOrientationPermissionState::Create(
                    PermissionStatusToString(status)));
                break;
              case mojom::blink::PermissionStatus::ASK:
                // At the moment, this state is not reachable because there
                // is no "ask" or "prompt" state in the Chromium
                // permissions UI for sensors, so HasPermissionStatus() will
                // always return GRANTED or DENIED.
                NOTREACHED();
            }
          })));

  return promise;
}

// static
void DeviceOrientationController::LogToConsolePolicyFeaturesDisabled(
    LocalFrame& frame,
    const AtomicString& event_name) {
  const String& message = String::Format(
      "The %s events are blocked by permissions policy. "
      "See "
      "https://github.com/w3c/webappsec-permissions-policy/blob/master/"
      "features.md#sensor-features",
      event_name.Ascii().c_str());
  auto* console_message = MakeGarbageCollected<ConsoleMessage>(
      mojom::ConsoleMessageSource::kJavaScript,
      mojom::ConsoleMessageLevel::kWarning, std::move(message));
  frame.Console().AddMessage(console_message);
}

}  // namespace blink
```