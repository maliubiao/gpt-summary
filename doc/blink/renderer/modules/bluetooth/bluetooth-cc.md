Response:
Let's break down the thought process for analyzing the `bluetooth.cc` file.

**1. Initial Understanding & Purpose:**

* **Identify the Core Subject:** The file name `bluetooth.cc` and the `#include` directives clearly indicate this file is about implementing the Web Bluetooth API within the Blink rendering engine of Chromium.
* **High-Level Functionality:**  The code aims to enable web pages to interact with Bluetooth devices. This involves discovering devices, connecting to them, and exchanging data.

**2. Deconstructing the Code (Top-Down and Keyword-Driven):**

* **Headers:**  Examine the included headers. They provide crucial hints about dependencies and functionality. Notice includes like:
    * `third_party/blink/renderer/modules/bluetooth/...`:  Indicates this is part of the `modules/bluetooth` component, suggesting a modular design for Blink's features.
    * `mojo/public/cpp/bindings/...`: Points to the use of Mojo for inter-process communication, likely between the renderer and the browser process.
    * `third_party/blink/public/mojom/bluetooth/...`:  Confirms the use of Mojo interfaces (`.mojom`) specifically for Bluetooth.
    * `third_party/blink/renderer/bindings/core/v8/...` and `third_party/blink/renderer/bindings/modules/v8/...`:  Shows the bridge between C++ and JavaScript/V8. Keywords like `ScriptPromise`, `ScriptPromiseResolver`, and various V8 types are key here.
    * `third_party/blink/renderer/core/dom/...` and `third_party/blink/renderer/core/frame/...`:  Connect the Bluetooth functionality to the DOM, frames, and the overall web page structure.
    * `third_party/blink/renderer/platform/...`:  Deals with platform-specific concerns and utilities.

* **Namespaces:**  The `namespace blink {` clearly defines the scope.

* **Static Constants:** The constants (e.g., `kMaxDeviceNameLength`, `kInactiveDocumentError`) often define limits, error messages, or key strings, giving insights into potential constraints and error handling.

* **Static Helper Functions:**  These functions usually encapsulate common logic or transformations:
    * `IsRequestDenied`:  Handles basic checks like document activity and fenced frames – crucial for security and API access control.
    * `IsFeatureEnabled`: Checks Permissions Policy – essential for browser-level feature gating.
    * `AddUnsupportedPlatformConsoleMessage`:  A developer reminder – useful for understanding the current state of the API.
    * `CanonicalizeFilter`:  Important for understanding how filtering of Bluetooth devices works based on the provided criteria.
    * `ConvertRequestDeviceOptions` and `ConvertRequestLEScanOptions`:  Focus on transforming JavaScript options into Mojo structures for communication with the browser process.

* **Class `Bluetooth`:**  This is the core class. Analyze its methods:
    * `getAvailability`:  Checks if Bluetooth is available.
    * `getDevices`:  Retrieves already paired/known Bluetooth devices.
    * `requestDevice`:  Initiates the device request flow, prompting the user to select a device.
    * `requestLEScan`:  Starts Bluetooth Low Energy scanning.
    * `AdvertisingEvent`:  Handles incoming advertising events from Bluetooth devices.
    * `PageVisibilityChanged`, `CancelScan`, `IsScanActive`:  Manage the lifecycle of Bluetooth operations and connections.

* **Callbacks:**  Methods like `GetDevicesCallback`, `RequestDeviceCallback`, and `RequestScanningCallback` handle asynchronous responses from the browser process, resolving or rejecting promises based on the outcome.

* **Mojo Usage:** Pay close attention to how Mojo interfaces (`mojom::blink::WebBluetooth...`) are used for communication. The `service_` member and methods that interact with it are key.

* **Error Handling:** Look for `ExceptionState` and how errors are thrown (e.g., `exception_state.ThrowTypeError`). This reveals common usage errors.

* **JavaScript/HTML/CSS Interaction:** The file doesn't directly manipulate HTML or CSS. However, its methods are exposed to JavaScript, which *can* then manipulate the DOM and styles based on the Bluetooth data received.

**3. Connecting to the Request:**

* **Functionality Listing:** Based on the deconstruction, list the main capabilities of the file.
* **JavaScript/HTML/CSS Relationship:** Explain how the JavaScript API exposed by this C++ code interacts with the front-end.
* **Logical Reasoning (Assumptions & Outputs):** For complex functions like filtering, think about example inputs to the JavaScript API and the corresponding outputs or behavior.
* **Common Usage Errors:**  Identify the error messages and the conditions under which they are triggered. This leads to examples of incorrect JavaScript usage.
* **User Operation Debugging:** Think about the user's journey that would lead to this code being executed. This starts with user interaction in the browser.

**4. Refining and Structuring the Answer:**

* **Organize by Request Points:** Structure the answer according to the questions asked in the prompt.
* **Provide Concrete Examples:**  Illustrate the concepts with specific JavaScript code snippets.
* **Maintain Clarity and Conciseness:**  Use clear language and avoid jargon where possible.
* **Review and Iterate:**  Read through the answer to ensure accuracy and completeness.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file just handles device connection."  **Correction:**  Realized it also manages scanning, availability checks, and error handling.
* **Initial thought:** "The JavaScript interaction is obvious." **Correction:**  Needed to provide specific examples of how the JavaScript API is used and what results to expect.
* **Stuck on a detail:**  If unsure about a specific function, refer back to the code comments or the Web Bluetooth specification.

By following this structured approach, combining top-down analysis with keyword recognition, and iteratively refining the understanding, one can effectively analyze complex source code like the `bluetooth.cc` file and answer detailed questions about its functionality and interactions.
好的，我们来详细分析一下 `blink/renderer/modules/bluetooth/bluetooth.cc` 这个 Chromium Blink 引擎的源代码文件。

**文件功能概要：**

`bluetooth.cc` 文件是 Chromium Blink 引擎中实现 Web Bluetooth API 的核心部分。它主要负责以下功能：

1. **暴露 JavaScript API：**  它定义了 `Bluetooth` 类，这个类在 JavaScript 中作为 `navigator.bluetooth` 对象暴露出来，允许网页开发者使用 Web Bluetooth 功能。
2. **管理蓝牙设备发现和连接：**  它处理设备扫描、过滤、请求用户授权连接特定蓝牙设备等操作。
3. **与浏览器进程通信：**  它使用 Mojo IPC (Inter-Process Communication) 机制与浏览器进程中的蓝牙服务进行通信，实际的蓝牙操作是由浏览器进程完成的。
4. **处理权限请求：** 它负责处理与 Web Bluetooth API 相关的权限请求，例如在用户尝试连接蓝牙设备时请求用户授权。
5. **管理蓝牙扫描：** 它支持蓝牙低功耗 (LE) 设备的扫描，允许网页监听广播的蓝牙设备。
6. **处理蓝牙事件：**  它接收来自浏览器进程的蓝牙事件，例如设备广播事件，并通过事件分发机制传递给 JavaScript。
7. **提供设备对象：** 它创建和管理 `BluetoothDevice` 对象，这些对象代表已连接或发现的蓝牙设备，并提供与设备交互的方法。
8. **实现 Web Bluetooth 规范：** 它遵循 Web Bluetooth Community Group 制定的规范，确保 API 的行为符合标准。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`bluetooth.cc` 文件本身是用 C++ 编写的，但它直接与 JavaScript 交互，使得 Web Bluetooth 功能可以在网页中使用。它不直接涉及 HTML 或 CSS。

* **JavaScript：**
    * **功能暴露：** `Bluetooth` 类被绑定到 JavaScript 的 `navigator.bluetooth` 对象。开发者可以通过这个对象调用 `requestDevice()` (请求连接设备), `getAvailability()` (检查蓝牙可用性), `getDevices()` (获取已配对设备), `requestLEScan()` (启动蓝牙 LE 扫描) 等方法。
    * **事件处理：**  `Bluetooth` 类作为事件目标 (EventTarget)，可以监听 `advertisementreceived` 事件，当收到蓝牙广播时，会触发这个事件，并将 `BluetoothAdvertisingEvent` 对象传递给 JavaScript 事件处理函数。
    * **数据传递：**  JavaScript 调用 `requestDevice()` 等方法时，会传递参数（例如过滤器），这些参数会被转换成 C++ 中相应的数据结构，并通过 Mojo 传递给浏览器进程。反之，浏览器进程返回的蓝牙设备信息也会被转换成 JavaScript 可用的对象。

    **JavaScript 示例：**

    ```javascript
    navigator.bluetooth.requestDevice({
      filters: [{ services: ['battery_service'] }]
    })
    .then(device => {
      console.log('已选择设备:', device.name);
      // 连接 GATT 服务器...
      return device.gatt.connect();
    })
    .then(server => {
      console.log('已连接 GATT 服务器');
      // 获取服务...
      return server.getPrimaryService('battery_service');
    })
    .then(service => {
      console.log('已获取 Battery Service');
      // 获取特征值...
      return service.getCharacteristic('battery_level');
    })
    .then(characteristic => {
      console.log('已获取 Battery Level 特征值');
      // 读取特征值...
      return characteristic.readValue();
    })
    .then(value => {
      const batteryLevel = value.getUint8(0);
      console.log(`电量: ${batteryLevel}%`);
    })
    .catch(error => {
      console.error('发生错误:', error);
    });

    navigator.bluetooth.addEventListener('advertisementreceived', event => {
      console.log('收到广播:', event.device.name);
      console.log('UUIDs:', event.uuids);
      console.log('Manufacturer Data:', event.manufacturerData);
    });

    navigator.bluetooth.requestLEScan({
      filters: [{ services: ['heart_rate'] }]
    })
    .then(scan => {
      console.log('开始扫描...');
      // 停止扫描
      // scan.stop();
    })
    .catch(error => {
      console.error('扫描失败:', error);
    });
    ```

* **HTML/CSS：**
    * `bluetooth.cc` 本身不直接操作 HTML 或 CSS。然而，JavaScript 通过 Web Bluetooth API 获取到蓝牙设备信息后，可以动态地修改 HTML 结构或 CSS 样式来呈现这些信息。例如，可以在网页上显示已连接的蓝牙设备名称或电池电量。

    **HTML 示例 (JavaScript 可能操作的部分)：**

    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>Web Bluetooth Demo</title>
    </head>
    <body>
      <h1>蓝牙设备信息</h1>
      <ul id="devices"></ul>
      <script>
        // ... 上面的 JavaScript 代码 ...
        function displayDevice(device) {
          const li = document.createElement('li');
          li.textContent = device.name;
          document.getElementById('devices').appendChild(li);
        }
      </script>
    </body>
    </html>
    ```

**逻辑推理 (假设输入与输出)：**

让我们以 `requestDevice()` 方法为例进行逻辑推理：

* **假设输入 (JavaScript 调用 `requestDevice()`):**
    ```javascript
    navigator.bluetooth.requestDevice({
      filters: [{ namePrefix: 'MyDevice' }]
    });
    ```
* **`bluetooth.cc` 的处理过程：**
    1. JavaScript 调用 `requestDevice()`，并将包含过滤器选项的对象传递给 Blink。
    2. `Bluetooth::requestDevice()` 方法被调用。
    3. 进行一系列检查，例如文档是否激活，是否在 fenced frame 中，是否违反 Permissions Policy 等。
    4. 调用 `ConvertRequestDeviceOptions()` 将 JavaScript 的 `RequestDeviceOptions` 转换为 Mojo 消息 `WebBluetoothRequestDeviceOptionsPtr`。
    5. 通过 Mojo 将 `WebBluetoothRequestDeviceOptionsPtr` 发送到浏览器进程的蓝牙服务。
    6. 浏览器进程的蓝牙服务会弹出设备选择器，供用户选择名称以 "MyDevice" 开头的蓝牙设备。
    7. 用户选择设备或取消操作。
* **可能的输出 (回调到 JavaScript):**
    * **用户选择设备：**  `RequestDeviceCallback` 被调用，将 `mojom::blink::WebBluetoothResult::SUCCESS` 和代表所选设备的 `mojom::blink::WebBluetoothDevicePtr` 传递给它。`GetBluetoothDeviceRepresentingDevice()` 创建 `BluetoothDevice` 对象，并通过 Promise 的 resolve 回调将 `BluetoothDevice` 对象返回给 JavaScript。
    * **用户取消：** `RequestDeviceCallback` 被调用，将 `mojom::blink::WebBluetoothResult::USER_CANCELLED_DIALOG` 传递给它。Promise 的 reject 回调被调用，并抛出一个 `DOMException`。
    * **发生错误 (例如蓝牙不可用)：**  `RequestDeviceCallback` 被调用，将相应的 `mojom::blink::WebBluetoothResult` 传递给它，Promise 的 reject 回调被调用，并抛出一个 `DOMException`。

**用户或编程常见的使用错误及举例说明：**

1. **未在安全上下文中使用 (HTTPS)：** Web Bluetooth API 只能在安全上下文（HTTPS）中使用。
   ```javascript
   // 在 HTTP 页面上调用会报错
   navigator.bluetooth.requestDevice({ /* ... */ });
   ```
   **错误信息 (可能在控制台看到)：** "SecurityError: Web Bluetooth API is available only in secure contexts."

2. **在没有用户手势的情况下调用 `requestDevice()` 或 `requestLEScan()`：**  这些方法需要用户手势（例如点击按钮）来触发，以防止恶意网站随意弹出蓝牙请求。
   ```javascript
   // 页面加载时立即调用，没有用户点击
   window.onload = function() {
     navigator.bluetooth.requestDevice({ /* ... */ }); // 可能会被浏览器阻止
   };
   ```
   **错误信息 (可能在控制台看到)：** "SecurityError: Must be handling a user gesture to show a permission request." (对应代码中的 `kHandleGestureForPermissionRequest`)

3. **提供的过滤器不合法或过于宽泛：**
   ```javascript
   // 过滤器中既没有 services 也没有 name 等限制
   navigator.bluetooth.requestDevice({ filters: [{}] });
   ```
   **错误信息 (可能抛出 TypeError)：** "'filters' member must be non-empty to find any devices." (在 `ConvertRequestDeviceOptions` 中检查) 或 "'services', if present, must contain at least one service." (在 `CanonicalizeFilter` 中检查)

4. **尝试在 fenced frame 中使用 Web Bluetooth：** Fenced frames 有更严格的权限限制。
   ```html
   <!-- 假设在一个 fenced frame 中执行 JavaScript -->
   <script>
     navigator.bluetooth.requestDevice({ /* ... */ });
   </script>
   ```
   **错误信息 (可能抛出 NotAllowedError)：** "NotAllowedError: Web Bluetooth is not allowed in a fenced frame tree." (对应代码中的 `kFencedFrameError`)

5. **Permissions Policy 阻止访问蓝牙功能：**  页面的 Permissions Policy 可能禁用了蓝牙功能。
   ```
   // 假设服务器发送了禁止蓝牙的 Permissions Policy 头
   // Feature-Policy: bluetooth 'none';
   navigator.bluetooth.requestDevice({ /* ... */ });
   ```
   **错误信息 (可能抛出 SecurityError)：** "SecurityError: Access to the feature \"bluetooth\" is disallowed by permissions policy." (对应代码中的 `kPermissionsPolicyBlocked`)

**说明用户操作是如何一步步的到达这里，作为调试线索：**

假设用户想要连接一个蓝牙心率带到网页上：

1. **用户打开网页：** 用户在浏览器中访问一个使用了 Web Bluetooth API 的网页（例如通过 HTTPS 访问）。
2. **网页加载 JavaScript：** 浏览器加载网页的 HTML、CSS 和 JavaScript 代码。
3. **用户交互触发蓝牙请求：** 用户点击了网页上的一个 "连接心率带" 的按钮。这个按钮的 `onclick` 事件处理函数中调用了 `navigator.bluetooth.requestDevice()`。
   ```javascript
   document.getElementById('connectButton').onclick = function() {
     navigator.bluetooth.requestDevice({
       filters: [{ services: ['heart_rate'] }]
     })
     .then(device => {
       console.log('已选择心率带:', device.name);
       // 后续连接和数据读取操作...
     })
     .catch(error => {
       console.error('连接失败:', error);
     });
   };
   ```
4. **Blink 处理 `requestDevice()` 调用：**
   * JavaScript 的调用会触发 Blink 引擎中对应的 C++ 代码，即 `Bluetooth::requestDevice()` 方法。
   * Blink 会检查安全上下文、用户手势、Permissions Policy 等。
   * `ConvertRequestDeviceOptions()` 将 JavaScript 的过滤器选项转换成 Mojo 消息。
5. **Mojo IPC 通信：**  Blink 通过 Mojo IPC 将请求发送到浏览器进程的蓝牙服务。
6. **浏览器进程处理蓝牙请求：** 浏览器进程的蓝牙服务会弹出设备选择器，显示可用的蓝牙设备，并允许用户选择。
7. **用户选择或取消：**
   * **用户选择：** 浏览器进程接收到用户选择的设备信息，并通过 Mojo IPC 发送回 Blink 进程。`Bluetooth::RequestDeviceCallback()` 被调用，创建 `BluetoothDevice` 对象，并通过 Promise resolve 回调将设备对象传递给 JavaScript。
   * **用户取消：** 浏览器进程通知 Blink 进程用户取消了操作。`Bluetooth::RequestDeviceCallback()` 被调用，并通过 Promise reject 回调将错误信息传递给 JavaScript。
8. **JavaScript 处理结果：**  JavaScript 的 Promise 的 `then` 或 `catch` 回调函数被执行，处理连接成功或失败的情况。

**调试线索：**

* **控制台日志：**  在 Chrome 的开发者工具的控制台中查看是否有错误信息或日志输出。`console.log()` 和 `console.error()` 是常用的调试手段。
* **网络面板 (Mojo)：**  在 Chrome 的 `chrome://inspect/#mojo` 页面可以查看 Mojo 消息的传递情况，有助于理解 Blink 和浏览器进程之间的通信。
* **断点调试：**  可以在 `bluetooth.cc` 文件中设置断点，结合 Chrome 的开发者工具，逐步执行 C++ 代码，查看变量的值和执行流程。这需要编译 Chromium 代码。
* **`chrome://bluetooth-internals/`：**  这个 Chrome 内部页面提供了更详细的蓝牙状态信息，可以帮助诊断蓝牙适配器和设备的问题。
* **Permissions Policy 检查：**  检查网页的 HTTP 响应头或 meta 标签，确认是否设置了限制蓝牙访问的 Permissions Policy。

希望以上详细的分析能够帮助你理解 `blink/renderer/modules/bluetooth/bluetooth.cc` 文件的功能和作用。

### 提示词
```
这是目录为blink/renderer/modules/bluetooth/bluetooth.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/bluetooth/bluetooth.h"

#include <utility>

#include "build/build_config.h"
#include "build/chromeos_buildflags.h"
#include "mojo/public/cpp/bindings/associated_receiver_set.h"
#include "mojo/public/cpp/bindings/pending_associated_remote.h"
#include "mojo/public/cpp/bindings/receiver_set.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "third_party/blink/public/mojom/bluetooth/web_bluetooth.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_string_unsignedlong.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_bluetooth_advertising_event_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_bluetooth_data_filter_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_bluetooth_le_scan_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_bluetooth_manufacturer_data_filter_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_request_device_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_typedefs.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth_device.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth_error.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth_le_scan.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth_manufacturer_data_map.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth_remote_gatt_characteristic.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth_service_data_map.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth_uuid.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"

namespace blink {

namespace {

// Per the Bluetooth Spec: The name is a user-friendly name associated with the
// device and consists of a maximum of 248 bytes coded according to the UTF-8
// standard.
const size_t kMaxDeviceNameLength = 248;
const char kDeviceNameTooLong[] =
    "A device name can't be longer than 248 bytes.";
const char kInactiveDocumentError[] = "Document not active";
const char kHandleGestureForPermissionRequest[] =
    "Must be handling a user gesture to show a permission request.";
const char kFencedFrameError[] =
    "Web Bluetooth is not allowed in a fenced frame tree.";
const char kPermissionsPolicyBlocked[] =
    "Access to the feature \"bluetooth\" is disallowed by permissions policy.";

// Does basic checks that are common to all IDL calls, mainly that the window is
// valid, and the request is not being done from a fenced frame tree. Returns
// true if exceptions have been flagged, and false otherwise.
bool IsRequestDenied(LocalDOMWindow* window, ExceptionState& exception_state) {
  if (!window) {
    exception_state.ThrowTypeError(kInactiveDocumentError);
  } else if (window->GetFrame()->IsInFencedFrameTree()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotAllowedError,
                                      kFencedFrameError);
  } else if (window->GetFrame()
                 ->Top()
                 ->GetSecurityContext()
                 ->GetSecurityOrigin()
                 ->IsOpaque()) {
    exception_state.ThrowSecurityError(
        "Access to the Web Bluetooth API is denied from contexts where the "
        "top-level document has an opaque origin.");
  }

  return exception_state.HadException();
}

// Checks whether the document is allowed by Permissions Policy to call Web
// Bluetooth API methods.
bool IsFeatureEnabled(LocalDOMWindow* window) {
  return window->IsFeatureEnabled(
      mojom::blink::PermissionsPolicyFeature::kBluetooth,
      ReportOptions::kReportOnFailure);
}

// Remind developers when they are using Web Bluetooth on unsupported platforms.
// TODO(https://crbug.com/570344): Remove this method when all platforms are
// supported.
void AddUnsupportedPlatformConsoleMessage(ExecutionContext* context) {
#if !BUILDFLAG(IS_CHROMEOS_ASH) && !BUILDFLAG(IS_ANDROID) && \
    !BUILDFLAG(IS_MAC) && !BUILDFLAG(IS_WIN)
  context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::blink::ConsoleMessageSource::kJavaScript,
      mojom::blink::ConsoleMessageLevel::kInfo,
      "Web Bluetooth is experimental on this platform. See "
      "https://github.com/WebBluetoothCG/web-bluetooth/blob/main/"
      "implementation-status.md"));
#endif
}

void CanonicalizeFilter(
    const BluetoothLEScanFilterInit* filter,
    mojom::blink::WebBluetoothLeScanFilterPtr& canonicalized_filter,
    ExceptionState& exception_state) {
  if (!(filter->hasServices() || filter->hasName() || filter->hasNamePrefix() ||
        filter->hasManufacturerData())) {
    exception_state.ThrowTypeError(
        "A filter must restrict the devices in some way.");
    return;
  }

  if (filter->hasServices()) {
    if (filter->services().size() == 0) {
      exception_state.ThrowTypeError(
          "'services', if present, must contain at least one service.");
      return;
    }
    canonicalized_filter->services.emplace();
    for (const V8UnionStringOrUnsignedLong* service : filter->services()) {
      const String& validated_service =
          BluetoothUUID::getService(service, exception_state);
      if (exception_state.HadException())
        return;
      canonicalized_filter->services->push_back(validated_service);
    }
  }

  if (filter->hasName()) {
    size_t name_length = filter->name().Utf8().length();
    if (name_length > kMaxDeviceNameLength) {
      exception_state.ThrowTypeError(kDeviceNameTooLong);
      return;
    }
    canonicalized_filter->name = filter->name();
  }

  if (filter->hasNamePrefix()) {
    size_t name_prefix_length = filter->namePrefix().Utf8().length();
    if (name_prefix_length > kMaxDeviceNameLength) {
      exception_state.ThrowTypeError(kDeviceNameTooLong);
      return;
    }
    if (filter->namePrefix().length() == 0) {
      exception_state.ThrowTypeError(
          "'namePrefix', if present, must be non-empty.");
      return;
    }
    canonicalized_filter->name_prefix = filter->namePrefix();
  }

  if (filter->hasManufacturerData()) {
    if (filter->manufacturerData().size() == 0) {
      exception_state.ThrowTypeError(
          "'manufacturerData', if present, must be non-empty.");
      return;
    }
    canonicalized_filter->manufacturer_data.emplace();
    for (const auto& manufacturer_data : filter->manufacturerData()) {
      std::optional<base::span<const uint8_t>> data_prefix_buffer;
      if (manufacturer_data->hasDataPrefix()) {
        data_prefix_buffer =
            DOMArrayPiece(manufacturer_data->dataPrefix()).ByteSpan();
      }

      std::optional<base::span<const uint8_t>> mask_buffer;
      if (manufacturer_data->hasMask()) {
        mask_buffer = DOMArrayPiece(manufacturer_data->mask()).ByteSpan();
      }

      if (mask_buffer.has_value()) {
        if (!data_prefix_buffer.has_value()) {
          exception_state.ThrowTypeError(
              "'dataPrefix' must be non-empty when 'mask' is present.");
          return;
        }

        if (data_prefix_buffer->size() != mask_buffer->size()) {
          exception_state.ThrowTypeError(
              "'mask' size must be equal to 'dataPrefix' size.");
          return;
        }
      }

      Vector<mojom::blink::WebBluetoothDataFilterPtr> data_filters_vector;
      if (data_prefix_buffer.has_value()) {
        if (data_prefix_buffer->size() == 0) {
          exception_state.ThrowTypeError(
              "'dataPrefix', if present, must be non-empty.");
          return;
        }

        // Iterate by index here since we're iterating through two arrays.
        for (size_t i = 0; i < data_prefix_buffer->size(); ++i) {
          const uint8_t data = (*data_prefix_buffer)[i];
          const uint8_t mask =
              mask_buffer.has_value() ? (*mask_buffer)[i] : 0xff;
          data_filters_vector.push_back(
              mojom::blink::WebBluetoothDataFilter::New(data, mask));
        }
      }

      auto company = mojom::blink::WebBluetoothCompany::New();
      company->id = manufacturer_data->companyIdentifier();
      auto result = canonicalized_filter->manufacturer_data->insert(
          std::move(company), std::move(data_filters_vector));
      if (!result.is_new_entry) {
        exception_state.ThrowTypeError("'companyIdentifier' must be unique.");
        return;
      }
    }
  }
}

void ConvertRequestDeviceOptions(
    const RequestDeviceOptions* options,
    mojom::blink::WebBluetoothRequestDeviceOptionsPtr& result,
    ExecutionContext* execution_context,
    ExceptionState& exception_state) {
  if (options->hasExclusionFilters() && !options->hasFilters()) {
    exception_state.ThrowTypeError(
        "'filters' member must be present if 'exclusionFilters' is present.");
    return;
  }

  if (!(options->hasFilters() ^ options->acceptAllDevices())) {
    exception_state.ThrowTypeError(
        "Either 'filters' should be present or 'acceptAllDevices' should be "
        "true, but not both.");
    return;
  }

  result->accept_all_devices = options->acceptAllDevices();

  if (options->hasFilters()) {
    if (options->filters().empty()) {
      exception_state.ThrowTypeError(
          "'filters' member must be non-empty to find any devices.");
      return;
    }

    result->filters.emplace();

    for (const BluetoothLEScanFilterInit* filter : options->filters()) {
      auto canonicalized_filter = mojom::blink::WebBluetoothLeScanFilter::New();

      CanonicalizeFilter(filter, canonicalized_filter, exception_state);
      if (exception_state.HadException())
        return;

      if (canonicalized_filter->manufacturer_data) {
        UseCounter::Count(execution_context,
                          WebFeature::kWebBluetoothManufacturerDataFilter);
      }

      result->filters->push_back(std::move(canonicalized_filter));
    }
  }

  if (options->hasExclusionFilters()) {
    if (options->exclusionFilters().empty()) {
      exception_state.ThrowTypeError(
          "'exclusionFilters' member must be non-empty to exclude any device.");
      return;
    }

    result->exclusion_filters.emplace();

    for (const BluetoothLEScanFilterInit* filter :
         options->exclusionFilters()) {
      auto canonicalized_filter = mojom::blink::WebBluetoothLeScanFilter::New();

      CanonicalizeFilter(filter, canonicalized_filter, exception_state);
      if (exception_state.HadException()) {
        return;
      }

      result->exclusion_filters->push_back(std::move(canonicalized_filter));
    }
  }

  if (options->hasOptionalServices()) {
    for (const V8UnionStringOrUnsignedLong* optional_service :
         options->optionalServices()) {
      const String& validated_optional_service =
          BluetoothUUID::getService(optional_service, exception_state);
      if (exception_state.HadException())
        return;
      result->optional_services.push_back(validated_optional_service);
    }
  }

  if (options->hasOptionalManufacturerData()) {
    for (const uint16_t manufacturer_code :
         options->optionalManufacturerData()) {
      result->optional_manufacturer_data.push_back(manufacturer_code);
    }
  }
}

}  // namespace

ScriptPromise<IDLBoolean> Bluetooth::getAvailability(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  LocalDOMWindow* window = GetSupplementable()->DomWindow();

  if (IsRequestDenied(window, exception_state)) {
    return EmptyPromise();
  }

  // If Bluetooth is disallowed by Permissions Policy, getAvailability should
  // return false.
  if (!IsFeatureEnabled(window)) {
    return ToResolvedPromise<IDLBoolean>(script_state, false);
  }

  CHECK(window->IsSecureContext());
  EnsureServiceConnection(window);

  // Subsequent steps are handled in the browser process.
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  service_->GetAvailability(
      WTF::BindOnce([](ScriptPromiseResolver<IDLBoolean>* resolver,
                       bool result) { resolver->Resolve(result); },
                    WrapPersistent(resolver)));
  return promise;
}

void Bluetooth::GetDevicesCallback(
    ScriptPromiseResolver<IDLSequence<BluetoothDevice>>* resolver,
    Vector<mojom::blink::WebBluetoothDevicePtr> devices) {
  if (!resolver->GetExecutionContext() ||
      resolver->GetExecutionContext()->IsContextDestroyed()) {
    return;
  }

  HeapVector<Member<BluetoothDevice>> bluetooth_devices;
  for (auto& device : devices) {
    BluetoothDevice* bluetooth_device = GetBluetoothDeviceRepresentingDevice(
        std::move(device), resolver->GetExecutionContext());
    bluetooth_devices.push_back(*bluetooth_device);
  }
  resolver->Resolve(bluetooth_devices);
}

void Bluetooth::RequestDeviceCallback(
    ScriptPromiseResolver<BluetoothDevice>* resolver,
    mojom::blink::WebBluetoothResult result,
    mojom::blink::WebBluetoothDevicePtr device) {
  if (!resolver->GetExecutionContext() ||
      resolver->GetExecutionContext()->IsContextDestroyed()) {
    return;
  }

  if (result == mojom::blink::WebBluetoothResult::SUCCESS) {
    BluetoothDevice* bluetooth_device = GetBluetoothDeviceRepresentingDevice(
        std::move(device), resolver->GetExecutionContext());
    resolver->Resolve(bluetooth_device);
  } else {
    resolver->Reject(BluetoothError::CreateDOMException(result));
  }
}

ScriptPromise<IDLSequence<BluetoothDevice>> Bluetooth::getDevices(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  LocalDOMWindow* window = GetSupplementable()->DomWindow();

  if (IsRequestDenied(window, exception_state)) {
    return ScriptPromise<IDLSequence<BluetoothDevice>>();
  }

  if (!IsFeatureEnabled(window)) {
    exception_state.ThrowSecurityError(kPermissionsPolicyBlocked);
    return ScriptPromise<IDLSequence<BluetoothDevice>>();
  }

  AddUnsupportedPlatformConsoleMessage(window);
  CHECK(window->IsSecureContext());

  EnsureServiceConnection(window);
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<BluetoothDevice>>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  service_->GetDevices(WTF::BindOnce(&Bluetooth::GetDevicesCallback,
                                     WrapPersistent(this),
                                     WrapPersistent(resolver)));
  return promise;
}

// https://webbluetoothcg.github.io/web-bluetooth/#dom-bluetooth-requestdevice
ScriptPromise<BluetoothDevice> Bluetooth::requestDevice(
    ScriptState* script_state,
    const RequestDeviceOptions* options,
    ExceptionState& exception_state) {
  LocalDOMWindow* window = GetSupplementable()->DomWindow();

  if (IsRequestDenied(window, exception_state)) {
    return EmptyPromise();
  }

  if (!IsFeatureEnabled(window)) {
    exception_state.ThrowSecurityError(kPermissionsPolicyBlocked);
    return EmptyPromise();
  }

  AddUnsupportedPlatformConsoleMessage(window);
  CHECK(window->IsSecureContext());

  // If the algorithm is not allowed to show a popup, reject promise with a
  // SecurityError and abort these steps.
  auto* frame = window->GetFrame();
  DCHECK(frame);
  if (!LocalFrame::HasTransientUserActivation(frame)) {
    exception_state.ThrowSecurityError(kHandleGestureForPermissionRequest);
    return EmptyPromise();
  }

  EnsureServiceConnection(window);

  // In order to convert the arguments from service names and aliases to just
  // UUIDs, do the following substeps:
  auto device_options = mojom::blink::WebBluetoothRequestDeviceOptions::New();
  ConvertRequestDeviceOptions(options, device_options, GetExecutionContext(),
                              exception_state);

  if (exception_state.HadException())
    return EmptyPromise();

  // Subsequent steps are handled in the browser process.
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<BluetoothDevice>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  service_->RequestDevice(
      std::move(device_options),
      WTF::BindOnce(&Bluetooth::RequestDeviceCallback, WrapPersistent(this),
                    WrapPersistent(resolver)));
  return promise;
}

static void ConvertRequestLEScanOptions(
    const BluetoothLEScanOptions* options,
    mojom::blink::WebBluetoothRequestLEScanOptionsPtr& result,
    ExceptionState& exception_state) {
  if (!(options->hasFilters() ^ options->acceptAllAdvertisements())) {
    exception_state.ThrowTypeError(
        "Either 'filters' should be present or 'acceptAllAdvertisements' "
        "should be true, but not both.");
    return;
  }

  result->accept_all_advertisements = options->acceptAllAdvertisements();
  result->keep_repeated_devices = options->keepRepeatedDevices();

  if (options->hasFilters()) {
    if (options->filters().empty()) {
      exception_state.ThrowTypeError(
          "'filters' member must be non-empty to find any devices.");
      return;
    }

    result->filters.emplace();

    for (const BluetoothLEScanFilterInit* filter : options->filters()) {
      auto canonicalized_filter = mojom::blink::WebBluetoothLeScanFilter::New();

      CanonicalizeFilter(filter, canonicalized_filter, exception_state);
      if (exception_state.HadException())
        return;

      result->filters->push_back(std::move(canonicalized_filter));
    }
  }
}

void Bluetooth::RequestScanningCallback(
    ScriptPromiseResolver<BluetoothLEScan>* resolver,
    mojo::ReceiverId id,
    mojom::blink::WebBluetoothRequestLEScanOptionsPtr options,
    mojom::blink::WebBluetoothResult result) {
  if (!resolver->GetExecutionContext() ||
      resolver->GetExecutionContext()->IsContextDestroyed()) {
    return;
  }

  if (result != mojom::blink::WebBluetoothResult::SUCCESS) {
    resolver->Reject(BluetoothError::CreateDOMException(result));
    return;
  }

  auto* scan =
      MakeGarbageCollected<BluetoothLEScan>(id, this, std::move(options));
  resolver->Resolve(scan);
}

// https://webbluetoothcg.github.io/web-bluetooth/scanning.html#dom-bluetooth-requestlescan
ScriptPromise<BluetoothLEScan> Bluetooth::requestLEScan(
    ScriptState* script_state,
    const BluetoothLEScanOptions* options,
    ExceptionState& exception_state) {
  LocalDOMWindow* window = GetSupplementable()->DomWindow();

  if (IsRequestDenied(window, exception_state)) {
    return EmptyPromise();
  }

  if (!IsFeatureEnabled(window)) {
    exception_state.ThrowSecurityError(kPermissionsPolicyBlocked);
    return EmptyPromise();
  }

  // Remind developers when they are using Web Bluetooth on unsupported
  // platforms.
  window->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::ConsoleMessageSource::kJavaScript,
      mojom::ConsoleMessageLevel::kInfo,
      "Web Bluetooth Scanning is experimental on this platform. See "
      "https://github.com/WebBluetoothCG/web-bluetooth/blob/main/"
      "implementation-status.md"));

  CHECK(window->IsSecureContext());

  // If the algorithm is not allowed to show a popup, reject promise with a
  // SecurityError and abort these steps.
  auto* frame = window->GetFrame();
  // If Navigator::DomWindow() returned a non-null |window|, GetFrame() should
  // be valid.
  DCHECK(frame);
  if (!LocalFrame::HasTransientUserActivation(frame)) {
    exception_state.ThrowSecurityError(kHandleGestureForPermissionRequest);
    return EmptyPromise();
  }

  EnsureServiceConnection(window);

  auto scan_options = mojom::blink::WebBluetoothRequestLEScanOptions::New();
  ConvertRequestLEScanOptions(options, scan_options, exception_state);

  if (exception_state.HadException())
    return EmptyPromise();

  // Subsequent steps are handled in the browser process.
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<BluetoothLEScan>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  mojo::PendingAssociatedRemote<mojom::blink::WebBluetoothAdvertisementClient>
      client;
  // See https://bit.ly/2S0zRAS for task types.
  mojo::ReceiverId id =
      client_receivers_.Add(client.InitWithNewEndpointAndPassReceiver(),
                            window->GetTaskRunner(TaskType::kMiscPlatformAPI));

  auto scan_options_copy = scan_options->Clone();
  service_->RequestScanningStart(
      std::move(client), std::move(scan_options),
      WTF::BindOnce(&Bluetooth::RequestScanningCallback, WrapPersistent(this),
                    WrapPersistent(resolver), id,
                    std::move(scan_options_copy)));

  return promise;
}

void Bluetooth::AdvertisingEvent(
    mojom::blink::WebBluetoothAdvertisingEventPtr advertising_event) {
  auto* event = MakeGarbageCollected<BluetoothAdvertisingEvent>(
      event_type_names::kAdvertisementreceived,
      GetBluetoothDeviceRepresentingDevice(std::move(advertising_event->device),
                                           GetExecutionContext()),
      std::move(advertising_event));
  DispatchEvent(*event);
}

void Bluetooth::PageVisibilityChanged() {
  client_receivers_.Clear();
}

void Bluetooth::CancelScan(mojo::ReceiverId id) {
  client_receivers_.Remove(id);
}

bool Bluetooth::IsScanActive(mojo::ReceiverId id) const {
  return client_receivers_.HasReceiver(id);
}

const WTF::AtomicString& Bluetooth::InterfaceName() const {
  return event_type_names::kAdvertisementreceived;
}

ExecutionContext* Bluetooth::GetExecutionContext() const {
  return GetSupplementable()->DomWindow();
}

void Bluetooth::Trace(Visitor* visitor) const {
  visitor->Trace(device_instance_map_);
  visitor->Trace(client_receivers_);
  visitor->Trace(service_);
  EventTarget::Trace(visitor);
  Supplement<Navigator>::Trace(visitor);
  PageVisibilityObserver::Trace(visitor);
}

// static
const char Bluetooth::kSupplementName[] = "Bluetooth";

Bluetooth* Bluetooth::bluetooth(Navigator& navigator) {
  if (!navigator.DomWindow())
    return nullptr;

  Bluetooth* supplement = Supplement<Navigator>::From<Bluetooth>(navigator);
  if (!supplement) {
    supplement = MakeGarbageCollected<Bluetooth>(navigator);
    ProvideTo(navigator, supplement);
  }
  return supplement;
}

Bluetooth::Bluetooth(Navigator& navigator)
    : Supplement<Navigator>(navigator),
      PageVisibilityObserver(navigator.DomWindow()->GetFrame()->GetPage()),
      client_receivers_(this, navigator.DomWindow()),
      service_(navigator.DomWindow()) {}

Bluetooth::~Bluetooth() = default;

BluetoothDevice* Bluetooth::GetBluetoothDeviceRepresentingDevice(
    mojom::blink::WebBluetoothDevicePtr device_ptr,
    ExecutionContext* context) {
  // TODO(crbug.com/1275634): convert device_instance_map_ to use
  // WebBluetoothDeviceId as key
  auto it =
      device_instance_map_.find(device_ptr->id.DeviceIdInBase64().c_str());
  if (it != device_instance_map_.end()) {
    return it->value.Get();
  }

  BluetoothDevice* device = MakeGarbageCollected<BluetoothDevice>(
      context, std::move(device_ptr), this);
  auto result = device_instance_map_.insert(
      device->GetDevice()->id.DeviceIdInBase64().c_str(), device);
  DCHECK(result.is_new_entry);
  return device;
}

void Bluetooth::EnsureServiceConnection(ExecutionContext* context) {
  if (!service_.is_bound()) {
    // See https://bit.ly/2S0zRAS for task types.
    auto task_runner = context->GetTaskRunner(TaskType::kMiscPlatformAPI);
    context->GetBrowserInterfaceBroker().GetInterface(
        service_.BindNewPipeAndPassReceiver(task_runner));
  }
}

}  // namespace blink
```