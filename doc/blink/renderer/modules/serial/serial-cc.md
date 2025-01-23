Response:
Let's break down the thought process for analyzing the `serial.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of this specific Chromium Blink file (`serial.cc`) and its relationship to web technologies like JavaScript, HTML, and CSS. We also need to consider error handling, user interaction, and debugging aspects.

2. **Initial Code Scan (Keywords and Structure):**  First, I'll scan the code for keywords that give immediate clues about its purpose. I see:
    * `#include`: Indicates dependencies on other modules (e.g., `mojom/serial`, `bindings/core/v8`, `core/dom`, `modules/serial`).
    * `namespace blink`:  Confirms this is part of the Blink rendering engine.
    * `class Serial`:  The main class, likely responsible for exposing the Serial API to JavaScript.
    * `getPorts`, `requestPort`:  These function names strongly suggest API methods for enumerating and requesting serial ports.
    * `ScriptPromise`:  Indicates asynchronous operations and integration with JavaScript Promises.
    * `EventTarget`:  Signals that `Serial` objects can emit events.
    * `mojom::blink::SerialService`:  Points to an interface for communicating with a lower-level service (likely in the browser process).
    * Error messages (e.g., `kContextGone`, `kFeaturePolicyBlocked`, `kNoPortSelected`):  These highlight potential issues.

3. **Identify Core Functionality:** Based on the keywords and the overall structure, the core functionality seems to be:
    * **Exposing the Web Serial API:**  This file implements the JavaScript `Serial` interface, allowing web pages to interact with serial ports.
    * **Port Discovery (`getPorts`):**  Provides a way to list available serial ports.
    * **Port Request (`requestPort`):**  Allows web pages to request access to a specific serial port, often involving user permission.
    * **Connection Management:** Handles connection state changes (connect/disconnect).
    * **Permissions and Security:** Enforces permissions policies and security checks.
    * **Communication with Browser Process:** Interacts with a browser-level service to perform the actual serial port operations.

4. **Map to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The primary interaction point. The methods like `getPorts()` and `requestPort()` are directly callable from JavaScript. The use of `ScriptPromise` is a clear indicator of asynchronous JavaScript interaction.
    * **HTML:**  While not directly involved in the *implementation*, the Serial API is *used* by JavaScript within an HTML page. The user interaction that triggers the `requestPort()` flow usually originates from an HTML element (e.g., a button click).
    * **CSS:**  CSS has no direct relationship to the *functionality* of the Web Serial API. CSS can style the UI elements that trigger the API calls, but it doesn't influence the underlying serial communication.

5. **Logical Reasoning and Examples:**
    * **`getPorts()`:**
        * **Input (Implicit):** User navigates to a page with JavaScript that calls `navigator.serial.getPorts()`.
        * **Output:** A JavaScript Promise that resolves with an array of `SerialPort` objects representing the available ports.
    * **`requestPort()`:**
        * **Input:** User clicks a button, triggering JavaScript that calls `navigator.serial.requestPort()`.
        * **Output (Success):** A JavaScript Promise resolving with a `SerialPort` object representing the granted port. The browser likely shows a permission prompt.
        * **Output (Failure):** A JavaScript Promise rejecting with an error (e.g., `NotFoundError` if the user cancels).

6. **User and Programming Errors:** Focus on common mistakes when using the API:
    * **Missing User Gesture:**  `requestPort()` requires a user gesture for security reasons.
    * **Incorrect Filters:**  Providing invalid filter criteria can prevent finding the desired port.
    * **Permissions Policy:** The API might be disabled by the website's permissions policy.
    * **Context Issues:**  Trying to use the API in an insecure context (e.g., an HTTP page) will fail.

7. **Debugging and User Steps:** Think about how a developer might end up looking at this code:
    * **User Action:** User interacts with a web page that uses the Serial API (e.g., clicks a "Connect" button).
    * **JavaScript Execution:** The JavaScript calls `navigator.serial.requestPort()`.
    * **Blink Engine Involvement:** The browser calls into the Blink rendering engine (`serial.cc`).
    * **Permission Check:**  Blink checks permissions and potentially shows a prompt.
    * **Service Call:** Blink communicates with the browser process to find and connect to the port.
    * **Error or Success:**  The process succeeds or fails, potentially leading the developer to inspect the Blink code to understand why.

8. **Refinement and Structure:** Organize the information logically, using headings and bullet points for clarity. Ensure that the explanations are concise and easy to understand for someone familiar with web development concepts. Specifically, be careful to distinguish between what the C++ code *does* and how JavaScript interacts with it.

9. **Review and Accuracy:** Double-check the information for technical accuracy and completeness. Make sure the examples are clear and the error scenarios are plausible.

Self-Correction/Refinement during the process:

* **Initial Thought:**  Might focus too much on the low-level details of serial communication. **Correction:** Shift focus to the API exposed to JavaScript and the flow of user interaction.
* **Confusion:**  Might initially blur the lines between the Blink code and the browser process code. **Correction:** Clearly delineate the responsibilities of `serial.cc` within the Blink engine.
* **Omission:**  Might forget to explicitly mention the role of permissions. **Correction:**  Add a section on security and permissions policy.
* **Clarity:**  Examples might be too technical. **Correction:** Simplify the examples to focus on the JavaScript API calls and expected outcomes.

By following this structured approach, incorporating relevant details from the code, and thinking about the developer's perspective, I can produce a comprehensive and accurate explanation of the `serial.cc` file's functionality.
这个文件 `blink/renderer/modules/serial/serial.cc` 是 Chromium Blink 引擎中实现 **Web Serial API** 的核心代码。它的主要功能是：

**1. 提供 JavaScript 访问串行端口的能力:**

   - 它实现了 `Navigator.serial` 接口，允许网页中的 JavaScript 代码与用户的计算机上的串行端口进行通信。
   - 这使得网页能够与各种硬件设备（例如，微控制器、3D 打印机、工业设备等）进行交互。

**2. 管理串行端口的发现和连接:**

   - **`getPorts()` 方法:** 允许 JavaScript 查询当前已授权访问的串行端口列表。
   - **`requestPort()` 方法:** 允许 JavaScript 请求用户选择一个串行端口进行连接。这个过程通常会弹出一个浏览器原生对话框，让用户选择并授权访问。

**3. 处理权限和安全问题:**

   - **权限策略检查:** 检查当前的文档和上下文是否允许使用 Web Serial API。例如，通过检查 Permissions Policy 是否允许 "serial" 功能。
   - **安全上下文限制:** 限制在不安全的上下文（例如，HTTP 页面）中使用该 API。
   - **用户激活要求:**  `requestPort()` 通常需要用户激活（例如，在按钮点击事件处理程序中调用），以防止恶意网站未经用户同意访问串行端口。

**4. 与浏览器进程进行通信:**

   - 使用 Mojo IPC (Inter-Process Communication) 与浏览器进程中的串行服务进行通信。
   - 这包括发送请求以获取端口列表、请求连接端口、打开/关闭端口等操作。

**5. 管理 `SerialPort` 对象:**

   - 创建和管理代表已连接串行端口的 `SerialPort` 对象。
   - 当串行端口的状态发生变化（例如，连接或断开连接）时，通知相关的 `SerialPort` 对象。

**6. 触发事件:**

   - 当串行端口连接状态改变时，会触发 `connect` 和 `disconnect` 事件。这些事件可以在 JavaScript 中监听。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:**
    ```javascript
    // 获取已授权的端口列表
    navigator.serial.getPorts().then(ports => {
      if (ports.length === 0) {
        console.log("No serial ports found.");
      } else {
        console.log("Available serial ports:", ports);
      }
    });

    // 请求用户选择一个端口
    document.getElementById('connectButton').addEventListener('click', async () => {
      try {
        const port = await navigator.serial.requestPort();
        console.log("Port selected:", port);
        // 连接端口并开始通信
        await port.open({ baudRate: 9600 });
        console.log("Port opened.");
      } catch (error) {
        console.error("Error opening serial port:", error);
      }
    });

    // 监听连接和断开事件
    navigator.serial.addEventListener('connect', event => {
      console.log("Serial port connected.");
    });

    navigator.serial.addEventListener('disconnect', event => {
      console.log("Serial port disconnected.");
    });
    ```
    这段 JavaScript 代码直接使用了 `navigator.serial` 提供的 API，这些 API 的底层实现就位于 `serial.cc` 中。

* **HTML:**
    ```html
    <button id="connectButton">Connect Serial Port</button>
    ```
    HTML 定义了用户交互的元素，例如这里的按钮。用户点击按钮会触发 JavaScript 代码，进而调用 `navigator.serial.requestPort()`，最终会执行 `serial.cc` 中的相应逻辑。

* **CSS:**
    CSS **没有直接的功能关系**。CSS 用于控制网页的样式和布局，而 Web Serial API 专注于提供硬件通信能力。尽管 CSS 可以美化触发串行端口操作的按钮，但它不参与 API 的核心逻辑。

**逻辑推理的假设输入与输出:**

**假设输入:**

1. **用户在支持 Web Serial API 的浏览器中访问了一个网页。**
2. **网页的 JavaScript 代码调用了 `navigator.serial.getPorts()`。**

**逻辑推理过程 (在 `serial.cc` 中):**

1. `Serial::getPorts()` 方法被调用。
2. `ShouldBlockSerialServiceCall()` 函数会检查权限策略和安全上下文。
3. 如果检查通过，则会创建一个 `ScriptPromiseResolver` 用于异步返回结果。
4. `EnsureServiceConnection()` 确保与浏览器进程的串行服务已连接。
5. 通过 Mojo IPC 调用浏览器进程的 `SerialService::GetPorts()` 方法。
6. 浏览器进程获取已授权的串行端口信息。
7. 浏览器进程将端口信息通过 Mojo IPC 返回给 Blink 进程。
8. `Serial::OnGetPorts()` 方法接收到端口信息。
9. `Serial::OnGetPorts()` 创建 `SerialPort` 对象并将它们存储起来。
10. `ScriptPromiseResolver` 的 Promise 被解析为包含 `SerialPort` 对象数组的结果。

**假设输出:**

如果用户已经授权过访问某些串行端口，则 `getPorts()` 返回的 Promise 将解析为一个包含这些 `SerialPort` 对象的数组。如果用户没有授权任何端口，则返回的数组将为空。

**用户或编程常见的使用错误举例说明:**

1. **在不安全上下文中使用 `navigator.serial`:**
   - **错误:** 在 HTTP 页面中调用 `navigator.serial.requestPort()`。
   - **结果:** 浏览器会抛出一个安全错误，因为 Web Serial API 只能在安全上下文（HTTPS）中使用。
   - **错误信息 (类似):**  "SecurityError: The Serial API is restricted to secure contexts."

2. **在没有用户激活的情况下调用 `navigator.serial.requestPort()`:**
   - **错误:** 在页面加载时立即调用 `navigator.serial.requestPort()`。
   - **结果:** 浏览器会阻止请求，因为它需要用户的明确操作来触发权限请求。
   - **错误信息 (类似):** "SecurityError: Must be handling a user gesture to show a permission request."

3. **提供的过滤器不正确导致无法找到想要的端口:**
   - **错误:** 在 `requestPort()` 中使用了错误的 `filters` 参数，例如 `usbVendorId` 或 `usbProductId` 不匹配实际设备的 ID。
   - **结果:** 用户可能会看到端口选择对话框，但找不到他们想要连接的设备，或者即使找到了，连接也可能失败。
   - **调试提示:** 开发者需要仔细检查设备的 USB VID 和 PID，并在过滤器中正确配置。

4. **未处理 Promise 的 rejection:**
   - **错误:** 调用 `navigator.serial.requestPort()` 后，没有正确处理 Promise 的 `catch` 块。
   - **结果:** 如果用户取消了端口选择对话框，或者发生了其他错误，Promise 会被 reject，如果没有 `catch` 处理，可能会导致 unhandled promise rejection 错误。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设用户想要连接一个 USB 串口设备：

1. **用户打开一个网页:** 该网页包含使用 Web Serial API 的 JavaScript 代码。
2. **用户点击页面上的一个 "连接设备" 按钮:** 这个按钮的 `onclick` 事件处理程序会调用 `navigator.serial.requestPort()`。
3. **浏览器接收到 `requestPort()` 的调用:** 这会触发 Blink 引擎中 `serial.cc` 的 `Serial::requestPort()` 方法。
4. **权限检查:** `ShouldBlockSerialServiceCall()` 会检查当前上下文是否允许使用该 API。
5. **用户手势验证:** Blink 引擎会检查 `requestPort()` 是否在用户手势（例如，按钮点击）的处理过程中调用。
6. **显示端口选择对话框:** 如果权限检查和用户手势验证都通过，浏览器会显示一个原生的对话框，列出可用的串行端口。
7. **用户选择一个端口并点击 "连接":** 用户在对话框中选择他们想要连接的 USB 串口设备。
8. **浏览器将选择的端口信息传递给 Blink 进程:** 这通过 Mojo IPC 进行通信。
9. **`Serial::OnRequestPort()` 被调用:** `serial.cc` 中的 `Serial::OnRequestPort()` 方法接收到浏览器进程返回的端口信息。
10. **创建 `SerialPort` 对象并 resolve Promise:**  `Serial::OnRequestPort()` 创建一个 `SerialPort` 对象来代表已连接的端口，并将该对象作为 Promise 的结果返回给 JavaScript。

**作为调试线索:**

当开发者在调试 Web Serial API 相关问题时，理解这个流程非常重要。

* **如果 `requestPort()` 没有弹出对话框:** 可能是权限策略阻止了 API 的使用，或者 `requestPort()` 没有在用户手势处理程序中调用。
* **如果端口选择对话框没有显示预期的设备:** 可能是设备的驱动问题，或者提供的 `filters` 参数不正确。
* **如果在连接或数据传输过程中出现问题:**  开发者需要查看 `SerialPort` 对象的方法（如 `open()`, `writable`, `readable`）以及相关的错误信息。

`serial.cc` 中的代码是理解 Web Serial API 工作原理的关键入口点，可以帮助开发者理解权限管理、与浏览器进程的通信以及 `SerialPort` 对象的生命周期。通过查看这里的代码，结合浏览器提供的开发者工具，可以更深入地排查 Web Serial API 的问题。

### 提示词
```
这是目录为blink/renderer/modules/serial/serial.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/serial/serial.h"

#include <inttypes.h>

#include <utility>

#include "base/unguessable_token.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy_feature.mojom-blink.h"
#include "third_party/blink/public/mojom/serial/serial.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_serial_port_filter.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_serial_port_request_options.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/navigator_base.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth_uuid.h"
#include "third_party/blink/renderer/modules/event_target_modules_names.h"
#include "third_party/blink/renderer/modules/serial/serial_port.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

namespace {

const char kContextGone[] = "Script context has shut down.";
const char kFeaturePolicyBlocked[] =
    "Access to the feature \"serial\" is disallowed by permissions policy.";
const char kNoPortSelected[] = "No port selected by the user.";

String TokenToString(const base::UnguessableToken& token) {
  // TODO(crbug.com/918702): Implement HashTraits for UnguessableToken.
  return String::Format("%016" PRIX64 "%016" PRIX64,
                        token.GetHighForSerialization(),
                        token.GetLowForSerialization());
}

// Carries out basic checks for the web-exposed APIs, to make sure the minimum
// requirements for them to be served are met. Returns true if any conditions
// fail to be met, generating an appropriate exception as well. Otherwise,
// returns false to indicate the call should be allowed.
bool ShouldBlockSerialServiceCall(LocalDOMWindow* window,
                                  ExecutionContext* context,
                                  ExceptionState* exception_state) {
  if (!context) {
    if (exception_state) {
      exception_state->ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                         kContextGone);
    }

    return true;
  }

  // Rejects if the top-level frame has an opaque origin.
  const SecurityOrigin* security_origin = nullptr;
  if (context->IsWindow()) {
    security_origin =
        window->GetFrame()->Top()->GetSecurityContext()->GetSecurityOrigin();
  } else if (context->IsDedicatedWorkerGlobalScope()) {
    security_origin = static_cast<WorkerGlobalScope*>(context)
                          ->top_level_frame_security_origin();
  } else {
    NOTREACHED();
  }

  if (security_origin->IsOpaque()) {
    if (exception_state) {
      exception_state->ThrowSecurityError(
          "Access to the Web Serial API is denied from contexts where the "
          "top-level document has an opaque origin.");
    }
    return true;
  }

  if (!context->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kSerial,
          ReportOptions::kReportOnFailure)) {
    if (exception_state) {
      exception_state->ThrowSecurityError(kFeaturePolicyBlocked);
    }
    return true;
  }

  return false;
}

}  // namespace

const char Serial::kSupplementName[] = "Serial";

Serial* Serial::serial(NavigatorBase& navigator) {
  Serial* serial = Supplement<NavigatorBase>::From<Serial>(navigator);
  if (!serial) {
    serial = MakeGarbageCollected<Serial>(navigator);
    ProvideTo(navigator, serial);
  }
  return serial;
}

Serial::Serial(NavigatorBase& navigator)
    : Supplement<NavigatorBase>(navigator),
      ExecutionContextLifecycleObserver(navigator.GetExecutionContext()),
      service_(navigator.GetExecutionContext()),
      receiver_(this, navigator.GetExecutionContext()) {}

ExecutionContext* Serial::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

const AtomicString& Serial::InterfaceName() const {
  return event_target_names::kSerial;
}

void Serial::ContextDestroyed() {
  for (auto& entry : port_cache_)
    entry.value->ContextDestroyed();
}

void Serial::OnPortConnectedStateChanged(
    mojom::blink::SerialPortInfoPtr port_info) {
  bool connected = port_info->connected;
  SerialPort* port = GetOrCreatePort(std::move(port_info));
  port->set_connected(connected);
  if (connected) {
    port->DispatchEvent(*Event::CreateBubble(event_type_names::kConnect));
  } else {
    port->DispatchEvent(*Event::CreateBubble(event_type_names::kDisconnect));
  }
}

ScriptPromise<IDLSequence<SerialPort>> Serial::getPorts(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (ShouldBlockSerialServiceCall(GetSupplementable()->DomWindow(),
                                   GetExecutionContext(), &exception_state)) {
    return ScriptPromise<IDLSequence<SerialPort>>();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<SerialPort>>>(
          script_state, exception_state.GetContext());
  get_ports_promises_.insert(resolver);

  EnsureServiceConnection();
  service_->GetPorts(WTF::BindOnce(&Serial::OnGetPorts, WrapPersistent(this),
                                   WrapPersistent(resolver)));

  return resolver->Promise();
}

// static
mojom::blink::SerialPortFilterPtr Serial::CreateMojoFilter(
    const SerialPortFilter* filter,
    ExceptionState& exception_state) {
  auto mojo_filter = mojom::blink::SerialPortFilter::New();

  if (filter->hasBluetoothServiceClassId()) {
    if (filter->hasUsbVendorId() || filter->hasUsbProductId()) {
      exception_state.ThrowTypeError(
          "A filter cannot specify both bluetoothServiceClassId and "
          "usbVendorId or usbProductId.");
      return nullptr;
    }
    mojo_filter->bluetooth_service_class_id =
        ::bluetooth::mojom::blink::UUID::New(
            GetBluetoothUUIDFromV8Value(filter->bluetoothServiceClassId()));
    if (mojo_filter->bluetooth_service_class_id->uuid.empty()) {
      exception_state.ThrowTypeError(
          "Invalid Bluetooth service class ID filter value.");
      return nullptr;
    }
    return mojo_filter;
  }

  mojo_filter->has_product_id = filter->hasUsbProductId();
  mojo_filter->has_vendor_id = filter->hasUsbVendorId();
  if (mojo_filter->has_product_id) {
    if (!mojo_filter->has_vendor_id) {
      exception_state.ThrowTypeError(
          "A filter containing a usbProductId must also specify a "
          "usbVendorId.");
      return nullptr;
    }
    mojo_filter->product_id = filter->usbProductId();
  }

  if (mojo_filter->has_vendor_id) {
    mojo_filter->vendor_id = filter->usbVendorId();
  } else {
    exception_state.ThrowTypeError(
        "A filter must provide a property to filter by.");
    return nullptr;
  }

  return mojo_filter;
}

ScriptPromise<SerialPort> Serial::requestPort(
    ScriptState* script_state,
    const SerialPortRequestOptions* options,
    ExceptionState& exception_state) {
  if (ShouldBlockSerialServiceCall(GetSupplementable()->DomWindow(),
                                   GetExecutionContext(), &exception_state)) {
    return EmptyPromise();
  }

  if (!LocalFrame::HasTransientUserActivation(DomWindow()->GetFrame())) {
    exception_state.ThrowSecurityError(
        "Must be handling a user gesture to show a permission request.");
    return EmptyPromise();
  }

  Vector<mojom::blink::SerialPortFilterPtr> filters;
  if (options && options->hasFilters()) {
    for (const auto& filter : options->filters()) {
      auto mojo_filter = CreateMojoFilter(filter, exception_state);
      if (!mojo_filter) {
        CHECK(exception_state.HadException());
        return EmptyPromise();
      }

      CHECK(!exception_state.HadException());
      filters.push_back(std::move(mojo_filter));
    }
  }

  Vector<::bluetooth::mojom::blink::UUIDPtr>
      allowed_bluetooth_service_class_ids;
  if (options && options->hasAllowedBluetoothServiceClassIds()) {
    for (const auto& id : options->allowedBluetoothServiceClassIds()) {
      allowed_bluetooth_service_class_ids.push_back(
          ::bluetooth::mojom::blink::UUID::New(
              GetBluetoothUUIDFromV8Value(id)));
    }
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<SerialPort>>(
      script_state, exception_state.GetContext());
  request_port_promises_.insert(resolver);

  EnsureServiceConnection();
  service_->RequestPort(std::move(filters),
                        std::move(allowed_bluetooth_service_class_ids),
                        resolver->WrapCallbackInScriptScope(WTF::BindOnce(
                            &Serial::OnRequestPort, WrapPersistent(this))));

  return resolver->Promise();
}

void Serial::OpenPort(
    const base::UnguessableToken& token,
    device::mojom::blink::SerialConnectionOptionsPtr options,
    mojo::PendingRemote<device::mojom::blink::SerialPortClient> client,
    mojom::blink::SerialService::OpenPortCallback callback) {
  EnsureServiceConnection();
  service_->OpenPort(token, std::move(options), std::move(client),
                     std::move(callback));
}

void Serial::ForgetPort(
    const base::UnguessableToken& token,
    mojom::blink::SerialService::ForgetPortCallback callback) {
  EnsureServiceConnection();
  service_->ForgetPort(token, std::move(callback));
}

void Serial::Trace(Visitor* visitor) const {
  visitor->Trace(service_);
  visitor->Trace(receiver_);
  visitor->Trace(get_ports_promises_);
  visitor->Trace(request_port_promises_);
  visitor->Trace(port_cache_);
  EventTarget::Trace(visitor);
  Supplement<NavigatorBase>::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

void Serial::AddedEventListener(const AtomicString& event_type,
                                RegisteredEventListener& listener) {
  EventTarget::AddedEventListener(event_type, listener);

  if (event_type != event_type_names::kConnect &&
      event_type != event_type_names::kDisconnect) {
    return;
  }

  if (ShouldBlockSerialServiceCall(GetSupplementable()->DomWindow(),
                                   GetExecutionContext(), nullptr)) {
    return;
  }

  EnsureServiceConnection();
}

void Serial::EnsureServiceConnection() {
  DCHECK(GetExecutionContext());

  if (service_.is_bound())
    return;

  auto task_runner =
      GetExecutionContext()->GetTaskRunner(TaskType::kMiscPlatformAPI);
  GetExecutionContext()->GetBrowserInterfaceBroker().GetInterface(
      service_.BindNewPipeAndPassReceiver(task_runner));
  service_.set_disconnect_handler(WTF::BindOnce(
      &Serial::OnServiceConnectionError, WrapWeakPersistent(this)));

  service_->SetClient(receiver_.BindNewPipeAndPassRemote(task_runner));
}

void Serial::OnServiceConnectionError() {
  service_.reset();
  receiver_.reset();

  // Script may execute during a call to Resolve(). Swap these sets to prevent
  // concurrent modification.
  HeapHashSet<Member<ScriptPromiseResolver<IDLSequence<SerialPort>>>>
      get_ports_promises;
  get_ports_promises_.swap(get_ports_promises);
  for (auto& resolver : get_ports_promises) {
    resolver->Resolve(HeapVector<Member<SerialPort>>());
  }

  HeapHashSet<Member<ScriptPromiseResolverBase>> request_port_promises;
  request_port_promises_.swap(request_port_promises);
  for (ScriptPromiseResolverBase* resolver : request_port_promises) {
    ScriptState* resolver_script_state = resolver->GetScriptState();
    if (!IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                       resolver_script_state)) {
      continue;
    }
    ScriptState::Scope script_state_scope(resolver_script_state);
    resolver->RejectWithDOMException(DOMExceptionCode::kNotFoundError,
                                     kNoPortSelected);
  }
}

SerialPort* Serial::GetOrCreatePort(mojom::blink::SerialPortInfoPtr info) {
  auto it = port_cache_.find(TokenToString(info->token));
  if (it != port_cache_.end()) {
    return it->value.Get();
  }

  SerialPort* port = MakeGarbageCollected<SerialPort>(this, std::move(info));
  port_cache_.insert(TokenToString(port->token()), port);
  return port;
}

void Serial::OnGetPorts(
    ScriptPromiseResolver<IDLSequence<SerialPort>>* resolver,
    Vector<mojom::blink::SerialPortInfoPtr> port_infos) {
  DCHECK(get_ports_promises_.Contains(resolver));
  get_ports_promises_.erase(resolver);

  HeapVector<Member<SerialPort>> ports;
  for (auto& port_info : port_infos)
    ports.push_back(GetOrCreatePort(std::move(port_info)));

  resolver->Resolve(ports);
}

void Serial::OnRequestPort(ScriptPromiseResolver<SerialPort>* resolver,
                           mojom::blink::SerialPortInfoPtr port_info) {
  DCHECK(request_port_promises_.Contains(resolver));
  request_port_promises_.erase(resolver);

  if (!port_info) {
    resolver->RejectWithDOMException(DOMExceptionCode::kNotFoundError,
                                     kNoPortSelected);
    return;
  }

  resolver->Resolve(GetOrCreatePort(std::move(port_info)));
}

}  // namespace blink
```