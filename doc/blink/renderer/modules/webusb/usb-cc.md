Response:
Let's break down the thought process to analyze the `usb.cc` file and generate the detailed explanation.

**1. Understanding the Request:**

The request asks for a functional breakdown of `usb.cc`, its relationship with web technologies (JavaScript, HTML, CSS), examples of logical reasoning, common user/programming errors, and debugging information (how a user reaches this code).

**2. Initial Code Scan and Keyword Identification:**

I started by quickly scanning the code for prominent keywords and include directives. This gives a high-level overview of the file's purpose:

* `#include`:  Points to dependencies, revealing related areas like Mojo, permissions, service workers, V8 bindings, DOM, events, etc.
* `namespace blink`: Indicates this is part of the Blink rendering engine.
* `class USB`:  The central class, suggesting this file implements the WebUSB API.
* `getDevices`, `requestDevice`: These are likely the core functions exposed to JavaScript.
* `USBDeviceFilter`, `USBDeviceRequestOptions`:  Data structures used for filtering and requesting USB devices.
* `ScriptPromise`:  Indicates asynchronous operations returning promises to JavaScript.
* `ExecutionContext`, `LocalDOMWindow`, `WorkerGlobalScope`, `ServiceWorkerGlobalScope`: Shows the API is available in different JavaScript contexts.
* `USBConnectionEvent`:  Indicates events related to device connection/disconnection.
* `device::mojom::blink::UsbDevice`:  Mojo interface for interacting with the device service.
* `FeaturePolicy`: Suggests handling of permissions policies.

**3. Deconstructing Functionality (Core Logic):**

I then examined the key methods of the `USB` class to understand their roles:

* **`USB::usb(NavigatorBase& navigator)`:**  This looks like a static factory method to get the `USB` object associated with the browser's `Navigator` object. This is how JavaScript accesses the WebUSB API.
* **`USB::getDevices(...)`:**  This function likely handles the `navigator.usb.getDevices()` JavaScript call. It interacts with the device service via Mojo to retrieve a list of already permitted USB devices.
* **`USB::requestDevice(...)`:** This is the core of the permission flow. It corresponds to `navigator.usb.requestDevice()` in JavaScript. It handles user gestures, filters, and interacts with the device service to request permission for a specific device.
* **`ConvertDeviceFilter(...)`:** A helper function to translate JavaScript `USBDeviceFilter` objects into the Mojo representation.
* **`OnGetDevices(...)`, `OnGetPermission(...)`:** Callbacks invoked when the Mojo service responds to the `GetDevices` and `GetPermission` requests. They resolve the JavaScript promises with the results.
* **`OnDeviceAdded(...)`, `OnDeviceRemoved(...)`:** Handlers for device connection/disconnection events received from the Mojo service. They dispatch `connect` and `disconnect` events to JavaScript.
* **`EnsureServiceConnection()`:**  Manages the connection to the browser's device service using Mojo.
* **`ShouldBlockUsbServiceCall(...)`:**  Implements checks for feature policy, opaque origins, and supported contexts.

**4. Relating to Web Technologies (JavaScript, HTML, CSS):**

* **JavaScript:** The primary interface. Functions like `getDevices` and `requestDevice` are directly callable from JavaScript. The code uses `ScriptPromise` to handle asynchronous results, which map directly to JavaScript Promises. The filter objects also originate from JavaScript.
* **HTML:**  While not directly interacting with the C++ code, the WebUSB API is triggered by JavaScript within an HTML page. User gestures (like button clicks) in HTML are often necessary to invoke `requestDevice`.
* **CSS:**  CSS has no direct functional relationship with the core WebUSB logic.

**5. Logical Reasoning (Input/Output):**

For `requestDevice`, the input is a JavaScript object (`USBDeviceRequestOptions`) containing filters. The output is a JavaScript Promise that resolves with a `USBDevice` object (if permission is granted) or rejects with an error. The `ConvertDeviceFilter` function demonstrates the internal logic of translating these filters.

**6. User and Programming Errors:**

I considered common mistakes developers might make:

* **No User Gesture:** `requestDevice` requires a user gesture for security reasons.
* **Incorrect Filters:** Providing an incomplete filter (e.g., `productId` without `vendorId`).
* **Feature Policy Blocking:** If the website's permissions policy disallows USB, the API will fail.
* **Service Worker Limitations:**  Specific constraints on event listener registration in service workers.

**7. Debugging Clues (User Operations):**

I traced how a user action could lead to this code:

1. A user interacts with a webpage (e.g., clicks a button).
2. JavaScript code in the webpage calls `navigator.usb.requestDevice()` or `navigator.usb.getDevices()`.
3. The Blink rendering engine translates this JavaScript call to the corresponding C++ methods in `usb.cc`.

**8. Structuring the Explanation:**

Finally, I organized the information logically, using headings and bullet points to make it easy to read and understand. I started with a high-level overview and then delved into more specific details. I made sure to provide concrete examples where possible.

**Self-Correction/Refinement During the Process:**

* Initially, I might have just listed the include files without explaining their significance. I refined this to explain *why* those headers are relevant.
* I initially focused heavily on the `requestDevice` function. I made sure to give sufficient attention to `getDevices` and the event handling as well.
* I double-checked the constraints for service workers regarding event listeners, as this is a common point of confusion.
* I ensured that the examples of user/programming errors were practical and directly related to the code's functionality.

By following this structured approach, combining code analysis with an understanding of web technologies and common development practices, I was able to generate a comprehensive and accurate explanation of the `usb.cc` file.
这个文件 `blink/renderer/modules/webusb/usb.cc` 是 Chromium Blink 引擎中实现 **WebUSB API** 的核心部分。它的主要功能是：

**1. 提供 JavaScript 访问 USB 设备的接口:**

   - 它暴露了全局对象 `navigator.usb`，使得网页 JavaScript 代码能够与连接到用户的计算机上的 USB 设备进行交互。
   - 它实现了 `USB` 接口，该接口包含 `getDevices()` 和 `requestDevice()` 方法，这是 WebUSB API 的主要入口点。

**2. 管理 USB 设备的枚举和权限请求:**

   - **`getDevices()`:**  允许 JavaScript 获取用户已授权访问的 USB 设备列表。
   - **`requestDevice()`:** 启动一个用户代理控制的流程，请求用户授权访问一个或多个特定的 USB 设备。这个方法通常会弹出一个浏览器 UI，让用户选择要授权的设备。

**3. 与浏览器进程中的 USB 服务通信:**

   - 该文件使用 **Mojo** 接口与浏览器进程中的 USB 服务进行通信。浏览器进程拥有访问系统级 USB 设备的权限。
   - 它通过 `device::mojom::blink::UsbDevice`  Mojo 接口与单个 USB 设备进行交互。
   - 它通过 `device::mojom::blink::WebUsbService` Mojo 接口处理设备枚举和权限请求。

**4. 处理 USB 设备的连接和断开事件:**

   - 它监听来自浏览器进程的 USB 设备连接和断开事件。
   - 当设备连接或断开时，它会触发 `connect` 和 `disconnect` 事件，可以通过 JavaScript 的事件监听器捕获这些事件。

**5. 实施安全和权限策略:**

   - 它检查是否满足访问 WebUSB API 的条件，例如：
     - 必须在安全上下文 (HTTPS) 中运行。
     - 受到 Permissions Policy 的限制。
     - 对于 `requestDevice()`，需要用户手势（例如点击按钮）。
   - 它确保只有用户明确授权的设备才能被 JavaScript 代码访问。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**  `usb.cc` 提供的功能主要通过 JavaScript 的 `navigator.usb` 对象暴露给开发者。
    * **`navigator.usb.getDevices()`:**  JavaScript 调用此方法，`usb.cc` 中的 `GetDevices()` 会被执行，它会向浏览器进程请求已授权的设备信息，并将结果通过 Promise 返回给 JavaScript。
       ```javascript
       navigator.usb.getDevices()
         .then(devices => {
           console.log("已授权的 USB 设备:", devices);
         })
         .catch(error => {
           console.error("获取设备失败:", error);
         });
       ```
    * **`navigator.usb.requestDevice(options)`:** JavaScript 调用此方法请求新的 USB 设备访问权限。`usb.cc` 中的 `RequestDevice()` 会启动权限请求流程。
       ```javascript
       document.getElementById('connectButton').addEventListener('click', () => {
         navigator.usb.requestDevice({ filters: [{ vendorId: 0xabcd }] })
           .then(device => {
             console.log("已选择的 USB 设备:", device);
           })
           .catch(error => {
             console.error("选择设备失败:", error);
           });
       });
       ```
       这里的 `options` 参数对应 `USBDeviceRequestOptions`，`filters` 对应 `USBDeviceFilter`，它们在 `usb.cc` 中会被转换成 Mojo 消息。
    * **`connect` 和 `disconnect` 事件:** JavaScript 可以监听 `navigator.usb` 对象的 `connect` 和 `disconnect` 事件。
       ```javascript
       navigator.usb.addEventListener('connect', event => {
         console.log("USB 设备已连接:", event.device);
       });

       navigator.usb.addEventListener('disconnect', event => {
         console.log("USB 设备已断开:", event.device);
       });
       ```
       当 `usb.cc` 中的 `OnDeviceAdded()` 或 `OnDeviceRemoved()` 被调用时，会触发这些事件。

* **HTML:** HTML 提供了用户触发 JavaScript 代码的界面元素，例如按钮。上面 `requestDevice()` 的例子中，点击按钮会触发权限请求。

* **CSS:** CSS 主要负责页面的样式，与 `usb.cc` 的核心功能没有直接关系。

**逻辑推理 (假设输入与输出):**

**假设输入 (JavaScript 调用 `requestDevice`)：**

```javascript
navigator.usb.requestDevice({ filters: [{ vendorId: 0x1234, productId: 0x5678 }] })
```

**`usb.cc` 的内部处理：**

1. **权限检查:** `ShouldBlockUsbServiceCall()` 会检查当前上下文是否允许访问 WebUSB (例如，是否在 HTTPS 下，是否被 Permissions Policy 阻止)。
2. **用户手势检查:** 检查是否存在有效的用户激活 (例如，用户点击了按钮)。
3. **Mojo 消息构建:** `ConvertDeviceFilter()` 将 JavaScript 的 `filters` 转换为 `device::mojom::blink::UsbDeviceFilterPtr`。
4. **发送权限请求:** 通过 Mojo 接口 (`service_->GetPermission()`) 将包含过滤器的权限请求发送到浏览器进程的 USB 服务。
5. **浏览器进程处理:** 浏览器进程会显示一个设备选择器 UI。
6. **用户选择:** 用户在 UI 中选择一个符合过滤条件的 USB 设备并授权。
7. **Mojo 响应:** 浏览器进程通过 Mojo 将被授权的设备信息 (`UsbDeviceInfoPtr`) 发回给 `usb.cc`。
8. **Promise 解析:** `OnGetPermission()` 被调用，它会将 `UsbDeviceInfoPtr` 包装成 `USBDevice` 对象，并通过 Promise 返回给 JavaScript。

**假设输出 (Promise 成功解析)：**

```javascript
// Promise 的 then 回调被调用
then(device => {
  // device 是一个 USBDevice 实例，代表用户授权的设备
  console.log("已选择的 USB 设备:", device);
})
```

**假设输出 (Promise 失败解析)：**

如果用户取消了设备选择，或者没有找到匹配的设备，`OnGetPermission()` 会收到一个空的 `device_info`，然后 Promise 会被拒绝，JavaScript 的 `catch` 回调会被调用。

```javascript
// Promise 的 catch 回调被调用
catch(error => {
  console.error("选择设备失败:", error); // error 通常是一个 DOMException
});
```

**用户或编程常见的使用错误及举例说明:**

1. **未在用户手势下调用 `requestDevice()`:**
   ```javascript
   // 错误示例：在页面加载时立即调用
   navigator.usb.requestDevice({ filters: [] })
     .then(/* ... */)
     .catch(/* ... */);
   ```
   **错误现象:** 浏览器会阻止权限请求，并抛出一个安全错误，因为 `requestDevice()` 需要用户主动触发。

2. **过滤器设置不正确导致无法找到设备:**
   ```javascript
   // 错误示例：vendorId 和 productId 不匹配实际设备
   navigator.usb.requestDevice({ filters: [{ vendorId: 0x0001, productId: 0x0001 }] })
     .then(/* ... */)
     .catch(error => {
       // 可能会收到 "No device selected." 的错误，因为没有匹配的设备
       console.error(error);
     });
   ```
   **解决方法:** 仔细检查设备的 vendorId 和 productId。

3. **在不支持 WebUSB 的上下文中调用:**
   ```javascript
   // 错误示例：在不安全的 HTTP 页面上调用
   navigator.usb.requestDevice({ filters: [] })
     .then(/* ... */)
     .catch(error => {
       // 可能会收到类似 "SecurityError" 的错误
       console.error(error);
     });
   ```
   **解决方法:** 确保页面通过 HTTPS 加载。

4. **Service Worker 中添加事件监听器的时机错误:**
   ```javascript
   // Service Worker 错误示例：在 initial evaluation 之后添加 listener
   self.addEventListener('activate', event => {
     navigator.usb.addEventListener('connect', event => {
       console.log("Service Worker: USB 设备已连接");
     });
   });
   ```
   **错误现象:**  Service Worker 中的 `connect` 和 `disconnect` 事件监听器必须在 Service Worker 脚本的初始评估阶段添加，否则可能无法正常工作。`usb.cc` 中的 `AddedEventListener()` 方法会检查这种情况并发出警告。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户访问包含 WebUSB 代码的网页:** 用户在浏览器中打开一个包含使用 WebUSB API 的 JavaScript 代码的 HTML 页面。
2. **JavaScript 代码执行:** 当页面加载或用户与页面交互时（例如点击按钮），JavaScript 代码会被执行。
3. **调用 `navigator.usb.getDevices()` 或 `navigator.usb.requestDevice()`:**  JavaScript 代码调用这些 WebUSB API 方法。
4. **Blink 引擎处理 JavaScript 调用:**  Blink 引擎接收到 JavaScript 的调用，并将其路由到 `blink/renderer/modules/webusb/usb.cc` 文件中的相应方法 (`GetDevices()` 或 `RequestDevice()`)。
5. **`usb.cc` 与浏览器进程通信:** `usb.cc` 通过 Mojo 接口与浏览器进程中的 USB 服务进行通信。
6. **浏览器进程与操作系统交互:** 浏览器进程中的 USB 服务与操作系统交互，枚举 USB 设备或显示权限请求对话框。
7. **用户操作 (权限请求场景):** 如果调用的是 `requestDevice()`，浏览器会弹出设备选择器，用户可以选择一个设备或取消。
8. **结果返回:** 浏览器进程将结果通过 Mojo 返回给 `usb.cc`。
9. **Promise 状态更新:** `usb.cc` 更新 JavaScript Promise 的状态 (resolve 或 reject)。
10. **JavaScript 回调执行:** JavaScript 中与 Promise 关联的 `then` 或 `catch` 回调函数被执行，处理 USB 设备信息或错误。

**作为调试线索：**

* **断点:** 可以在 `usb.cc` 中的关键方法 (`GetDevices()`, `RequestDevice()`, `OnGetPermission()`, `OnDeviceAdded()`, `OnDeviceRemoved()`) 设置断点，跟踪代码执行流程。
* **Mojo 接口监控:** 可以监控 Mojo 消息的发送和接收，查看 `usb.cc` 与浏览器进程之间传递的数据。
* **控制台日志:**  在 JavaScript 代码中添加 `console.log` 语句，查看 API 调用时的参数和返回结果。
* **浏览器开发者工具:** 使用浏览器的开发者工具，特别是 "设备" 或 "USB" 相关的部分（如果存在），可以查看已连接的 USB 设备和相关的状态信息。
* **Permissions Policy 检查:**  检查页面的 Permissions Policy 头信息，确认 WebUSB 功能是否被允许。
* **安全上下文检查:** 确保页面是通过 HTTPS 加载的。
* **用户手势验证:** 确认 `requestDevice()` 是在用户手势的上下文中调用的。

通过以上分析，可以更好地理解 `blink/renderer/modules/webusb/usb.cc` 文件的功能以及它在 WebUSB API 实现中的作用，并能针对常见问题进行调试和排查。

Prompt: 
```
这是目录为blink/renderer/modules/webusb/usb.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webusb/usb.h"

#include <utility>

#include "base/notreached.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "services/device/public/mojom/usb_device.mojom-blink.h"
#include "services/device/public/mojom/usb_enumeration_options.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/mojom/service_worker/service_worker.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_usb_device_filter.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_usb_device_request_options.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/navigator_base.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/modules/event_target_modules.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_global_scope.h"
#include "third_party/blink/renderer/modules/webusb/usb_connection_event.h"
#include "third_party/blink/renderer/modules/webusb/usb_device.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

using device::mojom::blink::UsbDevice;
using device::mojom::blink::UsbDeviceFilterPtr;
using device::mojom::blink::UsbDeviceInfoPtr;

namespace blink {
namespace {

const char kFeaturePolicyBlocked[] =
    "Access to the feature \"usb\" is disallowed by permissions policy.";
const char kNoDeviceSelected[] = "No device selected.";

void RejectWithTypeError(const String& error_details,
                         ScriptPromiseResolverBase* resolver) {
  ScriptState::Scope scope(resolver->GetScriptState());
  v8::Isolate* isolate = resolver->GetScriptState()->GetIsolate();
  resolver->Reject(V8ThrowException::CreateTypeError(isolate, error_details));
}

UsbDeviceFilterPtr ConvertDeviceFilter(const USBDeviceFilter* filter,
                                       ScriptPromiseResolverBase* resolver) {
  auto mojo_filter = device::mojom::blink::UsbDeviceFilter::New();
  mojo_filter->has_vendor_id = filter->hasVendorId();
  if (mojo_filter->has_vendor_id)
    mojo_filter->vendor_id = filter->vendorId();
  mojo_filter->has_product_id = filter->hasProductId();
  if (mojo_filter->has_product_id) {
    if (!mojo_filter->has_vendor_id) {
      RejectWithTypeError(
          "A filter containing a productId must also contain a vendorId.",
          resolver);
      return nullptr;
    }
    mojo_filter->product_id = filter->productId();
  }
  mojo_filter->has_class_code = filter->hasClassCode();
  if (mojo_filter->has_class_code)
    mojo_filter->class_code = filter->classCode();
  mojo_filter->has_subclass_code = filter->hasSubclassCode();
  if (mojo_filter->has_subclass_code) {
    if (!mojo_filter->has_class_code) {
      RejectWithTypeError(
          "A filter containing a subclassCode must also contain a classCode.",
          resolver);
      return nullptr;
    }
    mojo_filter->subclass_code = filter->subclassCode();
  }
  mojo_filter->has_protocol_code = filter->hasProtocolCode();
  if (mojo_filter->has_protocol_code) {
    if (!mojo_filter->has_subclass_code) {
      RejectWithTypeError(
          "A filter containing a protocolCode must also contain a "
          "subclassCode.",
          resolver);
      return nullptr;
    }
    mojo_filter->protocol_code = filter->protocolCode();
  }
  if (filter->hasSerialNumber())
    mojo_filter->serial_number = filter->serialNumber();
  return mojo_filter;
}

bool IsContextSupported(ExecutionContext* context) {
  // Since WebUSB on Web Workers is in the process of being implemented, we
  // check here if the runtime flag for the appropriate worker is enabled.
  // TODO(https://crbug.com/837406): Remove this check once the feature has
  // shipped.
  if (!context) {
    return false;
  }

  DCHECK(context->IsWindow() || context->IsDedicatedWorkerGlobalScope() ||
         context->IsServiceWorkerGlobalScope());
  DCHECK(!context->IsDedicatedWorkerGlobalScope() ||
         RuntimeEnabledFeatures::WebUSBOnDedicatedWorkersEnabled());
  DCHECK(!context->IsServiceWorkerGlobalScope() ||
         RuntimeEnabledFeatures::WebUSBOnServiceWorkersEnabled());

  return true;
}

// Carries out basic checks for the web-exposed APIs, to make sure the minimum
// requirements for them to be served are met. Returns true if any conditions
// fail to be met, generating an appropriate exception as well. Otherwise,
// returns false to indicate the call should be allowed.
bool ShouldBlockUsbServiceCall(LocalDOMWindow* window,
                               ExecutionContext* context,
                               ExceptionState* exception_state) {
  if (!IsContextSupported(context)) {
    if (exception_state) {
      exception_state->ThrowDOMException(
          DOMExceptionCode::kNotSupportedError,
          "The implementation did not support the requested type of object or "
          "operation.");
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
          "Access to the WebUSB API is denied from contexts where the "
          "top-level document has an opaque origin.");
    }
    return true;
  }

  if (!context->IsFeatureEnabled(mojom::blink::PermissionsPolicyFeature::kUsb,
                                 ReportOptions::kReportOnFailure)) {
    if (exception_state) {
      exception_state->ThrowSecurityError(kFeaturePolicyBlocked);
    }
    return true;
  }

  return false;
}

}  // namespace

const char USB::kSupplementName[] = "USB";

USB* USB::usb(NavigatorBase& navigator) {
  USB* usb = Supplement<NavigatorBase>::From<USB>(navigator);
  if (!usb) {
    usb = MakeGarbageCollected<USB>(navigator);
    ProvideTo(navigator, usb);
  }
  return usb;
}

USB::USB(NavigatorBase& navigator)
    : Supplement<NavigatorBase>(navigator),
      ExecutionContextLifecycleObserver(navigator.GetExecutionContext()),
      service_(navigator.GetExecutionContext()),
      client_receiver_(this, navigator.GetExecutionContext()) {}

USB::~USB() {
  // |service_| may still be valid but there should be no more outstanding
  // requests to them because each holds a persistent handle to this object.
  DCHECK(get_devices_requests_.empty());
  DCHECK(get_permission_requests_.empty());
}

ScriptPromise<IDLSequence<USBDevice>> USB::getDevices(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (ShouldBlockUsbServiceCall(GetSupplementable()->DomWindow(),
                                GetExecutionContext(), &exception_state)) {
    return ScriptPromise<IDLSequence<USBDevice>>();
  }

  EnsureServiceConnection();
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<USBDevice>>>(
          script_state, exception_state.GetContext());
  get_devices_requests_.insert(resolver);
  service_->GetDevices(WTF::BindOnce(&USB::OnGetDevices, WrapPersistent(this),
                                     WrapPersistent(resolver)));
  return resolver->Promise();
}

ScriptPromise<USBDevice> USB::requestDevice(
    ScriptState* script_state,
    const USBDeviceRequestOptions* options,
    ExceptionState& exception_state) {
  if (!DomWindow()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The implementation did not support the requested type of object or "
        "operation.");
    return EmptyPromise();
  }

  if (ShouldBlockUsbServiceCall(GetSupplementable()->DomWindow(),
                                GetExecutionContext(), &exception_state)) {
    return EmptyPromise();
  }

  EnsureServiceConnection();

  if (!LocalFrame::HasTransientUserActivation(DomWindow()->GetFrame())) {
    exception_state.ThrowSecurityError(
        "Must be handling a user gesture to show a permission request.");
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<USBDevice>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  auto mojo_options = mojom::blink::WebUsbRequestDeviceOptions::New();
  if (options->hasFilters()) {
    mojo_options->filters.reserve(options->filters().size());
    for (const auto& filter : options->filters()) {
      UsbDeviceFilterPtr converted_filter =
          ConvertDeviceFilter(filter, resolver);
      if (!converted_filter)
        return promise;
      mojo_options->filters.push_back(std::move(converted_filter));
    }
  }
  mojo_options->exclusion_filters.reserve(options->exclusionFilters().size());
  for (const auto& filter : options->exclusionFilters()) {
    UsbDeviceFilterPtr converted_filter = ConvertDeviceFilter(filter, resolver);
    if (!converted_filter) {
      return promise;
    }
    mojo_options->exclusion_filters.push_back(std::move(converted_filter));
  }

  DCHECK(options->filters().size() == mojo_options->filters.size());
  DCHECK(options->exclusionFilters().size() ==
         mojo_options->exclusion_filters.size());
  get_permission_requests_.insert(resolver);
  service_->GetPermission(std::move(mojo_options),
                          resolver->WrapCallbackInScriptScope(WTF::BindOnce(
                              &USB::OnGetPermission, WrapPersistent(this))));
  return promise;
}

ExecutionContext* USB::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

const AtomicString& USB::InterfaceName() const {
  return event_target_names::kUSB;
}

void USB::ContextDestroyed() {
  get_devices_requests_.clear();
  get_permission_requests_.clear();
}

USBDevice* USB::GetOrCreateDevice(UsbDeviceInfoPtr device_info) {
  auto it = device_cache_.find(device_info->guid);
  if (it != device_cache_.end()) {
    return it->value.Get();
  }

  String guid = device_info->guid;
  mojo::PendingRemote<UsbDevice> pipe;
  service_->GetDevice(guid, pipe.InitWithNewPipeAndPassReceiver());
  USBDevice* device = MakeGarbageCollected<USBDevice>(
      this, std::move(device_info), std::move(pipe), GetExecutionContext());
  device_cache_.insert(guid, device);
  return device;
}

void USB::ForgetDevice(
    const String& device_guid,
    mojom::blink::WebUsbService::ForgetDeviceCallback callback) {
  EnsureServiceConnection();
  service_->ForgetDevice(device_guid, std::move(callback));
}

void USB::OnGetDevices(ScriptPromiseResolver<IDLSequence<USBDevice>>* resolver,
                       Vector<UsbDeviceInfoPtr> device_infos) {
  DCHECK(get_devices_requests_.Contains(resolver));

  HeapVector<Member<USBDevice>> devices;
  for (auto& device_info : device_infos)
    devices.push_back(GetOrCreateDevice(std::move(device_info)));
  resolver->Resolve(devices);
  get_devices_requests_.erase(resolver);
}

void USB::OnGetPermission(ScriptPromiseResolver<USBDevice>* resolver,
                          UsbDeviceInfoPtr device_info) {
  DCHECK(get_permission_requests_.Contains(resolver));

  EnsureServiceConnection();

  if (service_.is_bound() && device_info) {
    resolver->Resolve(GetOrCreateDevice(std::move(device_info)));
  } else {
    resolver->RejectWithDOMException(DOMExceptionCode::kNotFoundError,
                                     kNoDeviceSelected);
  }
  get_permission_requests_.erase(resolver);
}

void USB::OnDeviceAdded(UsbDeviceInfoPtr device_info) {
  if (!service_.is_bound())
    return;

  DispatchEvent(*USBConnectionEvent::Create(
      event_type_names::kConnect, GetOrCreateDevice(std::move(device_info))));
}

void USB::OnDeviceRemoved(UsbDeviceInfoPtr device_info) {
  String guid = device_info->guid;
  USBDevice* device = nullptr;
  const auto it = device_cache_.find(guid);
  if (it != device_cache_.end()) {
    device = it->value;
  } else {
    device = MakeGarbageCollected<USBDevice>(this, std::move(device_info),
                                             mojo::NullRemote(),
                                             GetExecutionContext());
  }
  DispatchEvent(
      *USBConnectionEvent::Create(event_type_names::kDisconnect, device));
  device_cache_.erase(guid);
}

void USB::OnServiceConnectionError() {
  service_.reset();
  client_receiver_.reset();

  // This loop is resolving promises with a value and so it is possible for
  // script to be executed in the process of determining if the value is a
  // thenable. Move the set to a local variable to prevent such execution from
  // invalidating the iterator used by the loop.
  HeapHashSet<Member<ScriptPromiseResolver<IDLSequence<USBDevice>>>>
      get_devices_requests;
  get_devices_requests.swap(get_devices_requests_);
  for (auto& resolver : get_devices_requests)
    resolver->Resolve(HeapVector<Member<USBDevice>>(0));

  // Similar protection is unnecessary when rejecting a promise.
  for (auto& resolver : get_permission_requests_) {
    ScriptState* resolver_script_state = resolver->GetScriptState();
    if (!IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                       resolver_script_state)) {
      continue;
    }
    ScriptState::Scope script_state_scope(resolver_script_state);
    resolver->RejectWithDOMException(DOMExceptionCode::kNotFoundError,
                                     kNoDeviceSelected);
  }
}

void USB::AddedEventListener(const AtomicString& event_type,
                             RegisteredEventListener& listener) {
  EventTarget::AddedEventListener(event_type, listener);
  if (event_type != event_type_names::kConnect &&
      event_type != event_type_names::kDisconnect) {
    return;
  }

  auto* context = GetExecutionContext();
  if (ShouldBlockUsbServiceCall(GetSupplementable()->DomWindow(), context,
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

void USB::EnsureServiceConnection() {
  if (service_.is_bound())
    return;

  DCHECK(IsContextSupported(GetExecutionContext()));
  DCHECK(IsFeatureEnabled(ReportOptions::kDoNotReport));
  // See https://bit.ly/2S0zRAS for task types.
  auto task_runner =
      GetExecutionContext()->GetTaskRunner(TaskType::kMiscPlatformAPI);
  GetExecutionContext()->GetBrowserInterfaceBroker().GetInterface(
      service_.BindNewPipeAndPassReceiver(task_runner));
  service_.set_disconnect_handler(
      WTF::BindOnce(&USB::OnServiceConnectionError, WrapWeakPersistent(this)));

  DCHECK(!client_receiver_.is_bound());

  service_->SetClient(
      client_receiver_.BindNewEndpointAndPassRemote(task_runner));
}

bool USB::IsFeatureEnabled(ReportOptions report_options) const {
  return GetExecutionContext()->IsFeatureEnabled(
      mojom::blink::PermissionsPolicyFeature::kUsb, report_options);
}

void USB::Trace(Visitor* visitor) const {
  visitor->Trace(service_);
  visitor->Trace(get_devices_requests_);
  visitor->Trace(get_permission_requests_);
  visitor->Trace(client_receiver_);
  visitor->Trace(device_cache_);
  EventTarget::Trace(visitor);
  Supplement<NavigatorBase>::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

}  // namespace blink

"""

```