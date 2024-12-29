Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Goal:** The core request is to analyze the provided C++ code, specifically the `blink/renderer/modules/bluetooth/bluetooth_error.cc` file. The analysis should cover its functionality, relationship to web technologies (JS, HTML, CSS), provide examples, and explain how a user might trigger this code.

2. **Initial Code Scan (High-Level):**
   - I see `#include` directives, suggesting dependencies on other Blink components and standard C++.
   - The namespace `blink` and `namespace { ... }` indicate code organization and encapsulation.
   - There are static methods within the `BluetoothError` class. This suggests utility functions related to Bluetooth errors.
   - The presence of `DOMException` hints at how these errors are exposed to the JavaScript side.
   - Constants like `kGATTServerNotConnectedBase` suggest specific error message patterns.
   - A `switch` statement based on `BluetoothOperation` and `BluetoothErrorCode` implies handling different types of Bluetooth errors.
   - Another `switch` statement based on `mojom::blink::WebBluetoothResult` further reinforces error handling logic. The `#define MAP_ERROR` macro looks interesting.

3. **Deconstruct Functionality (Method by Method):**

   - **`CreateNotConnectedExceptionMessage(BluetoothOperation)`:**
     - Purpose:  Generates a user-friendly error message when a GATT server operation is attempted without a connection.
     - Input: `BluetoothOperation` enum (e.g., retrieving services, characteristics).
     - Output: A `String` containing the error message.
     - Logic: A `switch` statement maps the `BluetoothOperation` to a descriptive verb. The output string uses `String::Format` to insert this verb into a base message.

   - **`CreateNotConnectedException(BluetoothOperation)`:**
     - Purpose: Creates a `DOMException` object representing a network error due to a disconnected GATT server.
     - Input: `BluetoothOperation` enum.
     - Output: A `DOMException*`.
     - Logic: Calls `CreateNotConnectedExceptionMessage` to get the message, then uses `MakeGarbageCollected<DOMException>` to create the exception with the `NETWORK_ERROR` code.

   - **`CreateDOMException(BluetoothErrorCode, const String&)`:**
     - Purpose: Creates a `DOMException` based on a `BluetoothErrorCode` and a detailed message.
     - Input: `BluetoothErrorCode` enum, a `String` for the detailed message.
     - Output: A `DOMException*`.
     - Logic: A `switch` statement maps specific `BluetoothErrorCode` values (like invalid service, not found) to corresponding `DOMExceptionCode` values (like `INVALID_STATE_ERROR`, `NOT_FOUND_ERROR`).

   - **`CreateDOMException(mojom::blink::WebBluetoothResult)`:**
     - Purpose: This is the most complex part. It creates `DOMException` objects based on the `WebBluetoothResult` enum, which likely comes from the underlying Bluetooth system.
     - Input: `mojom::blink::WebBluetoothResult` enum.
     - Output: A `DOMException*`.
     - Logic:
       - Initial check for `SUCCESS` and "not found" codes, which shouldn't be handled here (or have a more specific handling elsewhere). This raises a `NOTREACHED()`.
       - The `#define MAP_ERROR` macro is used extensively. This is a common C++ technique to reduce boilerplate code. It defines a macro that takes an enum value, a DOMException code, and an error message, and generates a `case` within the `switch` statement.
       - The macro then maps various `WebBluetoothResult` values to specific `DOMException` types (AbortError, InvalidModificationError, InvalidStateError, NetworkError, NotFoundError, NotSupportedError, SecurityError, NotAllowedError, UnknownError) with corresponding messages.

4. **Relating to Web Technologies (JS, HTML, CSS):**

   - The key connection is through the `DOMException`. JavaScript code interacting with the Web Bluetooth API will receive these `DOMException` objects when errors occur.
   - **JavaScript:** The primary interface. JS code uses functions like `navigator.bluetooth.requestDevice()`, `device.gatt.connect()`, `server.getPrimaryService()`, etc. Errors in these operations will often manifest as `DOMException` objects created by this C++ code.
   - **HTML:** Indirectly related. HTML provides the structure for web pages. User interactions (like clicking a button to connect to a Bluetooth device) in the HTML trigger the JavaScript that then uses the Web Bluetooth API, potentially leading to these errors.
   - **CSS:**  No direct relationship. CSS handles styling and presentation, not the underlying logic of the Web Bluetooth API.

5. **Examples and Scenarios:**

   - **Not Connected:** Try to read a characteristic value without calling `device.gatt.connect()`.
   - **Service/Characteristic/Descriptor Not Found:** Request a service, characteristic, or descriptor with an incorrect UUID.
   - **Permission Denied:** The user cancels the device selection prompt.
   - **Device Out of Range:** Attempt to interact with a device that has moved out of Bluetooth range.

6. **User Actions and Debugging:**

   - Trace the user's steps in the web application. What buttons did they click? What actions did they take that led to the error?
   - Examine the JavaScript console for the `DOMException` object. The `name` and `message` properties will often correspond to the error messages defined in the C++ code.
   - Use browser developer tools to inspect the state of Bluetooth objects (devices, services, characteristics).
   - Check for browser permissions related to Bluetooth.
   - Verify that the Bluetooth device is powered on and discoverable.

7. **Refine and Organize:** Structure the analysis with clear headings and bullet points. Provide concrete examples for each point. Ensure the explanation is easy to understand, even for someone not deeply familiar with Blink internals.

8. **Self-Correction/Review:** Did I address all parts of the prompt? Are the examples clear and accurate? Is the explanation of the code's functionality correct?  Is the connection to web technologies well-explained?  Have I considered common user errors?  Does the debugging advice make sense? For instance, initially I might have just listed the functions without explaining *why* they are important or how they connect to the web. I need to make that explicit. Also, double-checking the mapping of `BluetoothErrorCode` and `WebBluetoothResult` to `DOMExceptionCode` ensures accuracy. The macro usage needs explanation for clarity.
这个 C++ 代码文件 `bluetooth_error.cc` 的主要功能是 **为 Chromium Blink 引擎中的 Web Bluetooth API 生成和管理错误信息，并将其转化为 JavaScript 可以理解的 `DOMException` 对象**。

更具体地说，它做了以下几件事情：

1. **定义了用于创建特定错误信息的静态方法:**  例如 `CreateNotConnectedExceptionMessage` 用于生成“GATT Server is disconnected”类型的错误消息。

2. **根据不同的错误场景创建 `DOMException` 对象:**  这些 `DOMException` 对象会被传递给 JavaScript 代码，让开发者可以捕获并处理这些错误。

3. **将底层的 Bluetooth 错误码 (`BluetoothErrorCode` 和 `mojom::blink::WebBluetoothResult`) 映射到对应的 `DOMException` 类型和消息。** 这意味着来自蓝牙硬件或系统层面的错误会被转化为 Web API 规范中定义的 `DOMException`，例如 `NetworkError`，`NotFoundError`，`SecurityError` 等。

**它与 JavaScript, HTML, CSS 的功能的关系：**

这个 C++ 文件直接参与了 **Web Bluetooth API** 的实现，而 Web Bluetooth API 是一个允许 JavaScript 代码与用户的蓝牙设备进行通信的 Web 标准。

* **与 JavaScript 的关系最为密切:**  当 JavaScript 代码尝试进行蓝牙操作（例如连接设备、读取特征值等）时，如果出现错误，这个 C++ 文件中的代码会被调用来创建相应的 `DOMException` 对象。JavaScript 代码可以使用 `try...catch` 语句来捕获这些异常并进行处理。

   **举例说明:**

   ```javascript
   // JavaScript 代码尝试连接到蓝牙设备
   navigator.bluetooth.requestDevice({
       // ...
   })
   .then(device => {
       return device.gatt.connect();
   })
   .then(server => {
       // ...
   })
   .catch(error => {
       // error 就是一个 DOMException 对象，它的 name 和 message 属性是由 bluetooth_error.cc 中的代码生成的
       console.error('连接错误:', error.name, error.message);
   });
   ```

   在这个例子中，如果 `device.gatt.connect()` 失败（例如设备不在范围内），`bluetooth_error.cc` 中的 `CreateDOMException` 方法会根据具体的错误原因创建一个 `DOMException` 对象，例如 `NetworkError`，并且附带相应的消息，例如 "Bluetooth Device is no longer in range."。这个 `error` 对象会被 `catch` 语句捕获。

* **与 HTML 的关系是间接的:**  HTML 提供了网页的结构，其中可以包含触发蓝牙操作的 JavaScript 代码。例如，用户点击一个按钮可能会调用 JavaScript 函数来连接蓝牙设备。

   **举例说明:**

   ```html
   <!DOCTYPE html>
   <html>
   <head>
       <title>蓝牙示例</title>
   </head>
   <body>
       <button id="connectButton">连接蓝牙设备</button>
       <script>
           document.getElementById('connectButton').addEventListener('click', function() {
               navigator.bluetooth.requestDevice({
                   // ...
               })
               .catch(error => {
                   console.error('连接错误:', error.name, error.message);
               });
           });
       </script>
   </body>
   </html>
   ```

   在这个 HTML 代码中，用户点击 "连接蓝牙设备" 按钮会触发 JavaScript 代码，如果连接失败，`bluetooth_error.cc` 负责生成错误信息并传递给 JavaScript 的 `catch` 块。

* **与 CSS 没有直接的功能关系:** CSS 负责网页的样式，不参与 Web Bluetooth API 的错误处理逻辑。

**逻辑推理的假设输入与输出:**

假设 JavaScript 代码尝试连接到一个已经断开连接的 GATT 服务器，并尝试读取一个特征值：

**假设输入 (在 C++ 代码层面):**

* `BluetoothOperation` 枚举值为 `BluetoothOperation::kCharacteristicsRetrieval` (因为尝试读取特征值)。
* 底层蓝牙系统报告 GATT 服务器未连接。

**逻辑推理 (在 `bluetooth_error.cc` 中):**

1. `CreateNotConnectedExceptionMessage(BluetoothOperation::kCharacteristicsRetrieval)` 被调用。
2. `switch` 语句匹配到 `BluetoothOperation::kCharacteristicsRetrieval`。
3. `operation_string` 被设置为 `"retrieve characteristics"`。
4. 返回的字符串是 `"GATT Server is disconnected. Cannot retrieve characteristics. (Re)connect first with \`device.gatt.connect\`."`。

**假设输出 (返回给 JavaScript):**

* 一个 `DOMException` 对象。
* `DOMException` 的 `name` 属性为 `"NetworkError"` (由 `CreateNotConnectedException` 函数设置)。
* `DOMException` 的 `message` 属性为 `"GATT Server is disconnected. Cannot retrieve characteristics. (Re)connect first with \`device.gatt.connect\`."`。

**用户或编程常见的使用错误举例说明:**

1. **尝试在未连接 GATT 服务器的情况下执行 GATT 操作:**
   ```javascript
   navigator.bluetooth.requestDevice({ /* ... */ })
       .then(device => {
           // 注意这里没有调用 device.gatt.connect()
           return device.gatt.getPrimaryService('...')
               .then(service => service.getCharacteristic('...'))
               .then(characteristic => characteristic.readValue());
       })
       .catch(error => {
           console.error(error.name, error.message); // 输出 NetworkError, "GATT Server is disconnected..."
       });
   ```
   **错误原因:** 用户忘记在执行 GATT 操作之前调用 `device.gatt.connect()` 来建立连接。`bluetooth_error.cc` 会生成一个 `NetworkError` 类型的 `DOMException`，提示用户先连接。

2. **请求不存在的服务、特征值或描述符:**
   ```javascript
   navigator.bluetooth.requestDevice({ /* ... */ })
       .then(device => device.gatt.connect())
       .then(server => server.getPrimaryService('invalid-service-uuid')) // 假设该 UUID 不存在
       .catch(error => {
           console.error(error.name, error.message); // 输出 NotFoundError, "Service with UUID invalid-service-uuid not found."
       });
   ```
   **错误原因:**  开发者使用了错误的 UUID 来请求服务。`bluetooth_error.cc` 会根据 `BluetoothErrorCode::kServiceNotFound` 生成一个 `NotFoundError` 类型的 `DOMException`。

3. **在用户取消设备选择器时未处理错误:**
   ```javascript
   navigator.bluetooth.requestDevice({ /* ... */ })
       .then(device => {
           // ...
       });
   ```
   **错误原因:** 如果用户在 `navigator.bluetooth.requestDevice()` 弹出的设备选择器中点击 "取消"，Promise 会被 reject，但如果开发者没有提供 `catch` 语句，错误将不会被处理。 `bluetooth_error.cc` 会生成一个 `NotFoundError` 类型的 `DOMException`，消息为 "User cancelled the requestDevice() chooser."

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在网页上点击了一个 "读取设备信息" 的按钮，并且代码尝试读取一个蓝牙设备的特征值，但设备已经断开连接。

1. **用户操作:** 用户点击了网页上的 "读取设备信息" 按钮。
2. **JavaScript 触发:** 该按钮的点击事件监听器中的 JavaScript 代码开始执行。
3. **尝试执行蓝牙操作:** JavaScript 代码调用了 Web Bluetooth API 的方法，例如 `characteristic.readValue()`。
4. **底层蓝牙系统反馈错误:** 由于设备已断开连接，底层的蓝牙系统或蓝牙适配器会返回一个错误信息，表明 GATT 服务器未连接。
5. **Blink 引擎捕获错误:** Blink 引擎中的 Web Bluetooth API 实现（在 `blink/renderer/modules/bluetooth` 目录下）会捕获到这个底层错误。
6. **调用 `bluetooth_error.cc` 中的方法:**  根据错误类型，相应的静态方法（例如 `CreateNotConnectedException` 或 `CreateDOMException`）会被调用。
7. **创建 `DOMException` 对象:**  `bluetooth_error.cc` 中的代码会根据错误信息创建一个 `DOMException` 对象，设置 `name` 和 `message` 属性。
8. **`DOMException` 传递给 JavaScript:**  创建的 `DOMException` 对象会被传递回 JavaScript 代码中 Promise 的 `reject` 回调或者 `catch` 语句中。
9. **JavaScript 处理错误 (或未处理):**  JavaScript 代码可以捕获这个 `DOMException` 并进行处理，例如显示错误消息给用户。如果代码没有 `catch` 语句，浏览器控制台会显示未处理的错误。

**调试线索:**

* **查看浏览器控制台:** 当出现蓝牙相关的错误时，浏览器控制台通常会显示 `DOMException` 的 `name` 和 `message` 属性，这些信息是由 `bluetooth_error.cc` 生成的。
* **使用开发者工具断点调试 JavaScript 代码:**  在可能发生错误的 Web Bluetooth API 调用处设置断点，查看 `catch` 语句中捕获的 `error` 对象。
* **检查蓝牙设备状态:** 确认蓝牙设备是否已连接，是否在范围内，电量是否充足。
* **查看 Blink 引擎的日志:** 如果需要更深入的调试，可以查看 Chromium 的内部日志，这可能包含更详细的蓝牙错误信息。
* **理解 Web Bluetooth API 规范:** 了解不同蓝牙操作可能产生的错误类型以及对应的 `DOMException`，可以帮助你更好地理解错误信息。

总而言之，`bluetooth_error.cc` 是 Web Bluetooth API 实现中至关重要的一部分，它负责将底层的蓝牙错误转化为开发者友好的 `DOMException` 对象，使得 JavaScript 代码能够可靠地处理蓝牙操作中可能出现的各种问题。

Prompt: 
```
这是目录为blink/renderer/modules/bluetooth/bluetooth_error.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/bluetooth/bluetooth_error.h"

#include "third_party/blink/public/mojom/bluetooth/web_bluetooth.mojom-blink.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

namespace {

const char kGATTServerNotConnectedBase[] =
    "GATT Server is disconnected. "
    "Cannot %s. (Re)connect first with `device.gatt.connect`.";

}  // namespace

// static
String BluetoothError::CreateNotConnectedExceptionMessage(
    BluetoothOperation operation) {
  const char* operation_string = nullptr;
  switch (operation) {
    case BluetoothOperation::kServicesRetrieval:
      operation_string = "retrieve services";
      break;
    case BluetoothOperation::kCharacteristicsRetrieval:
      operation_string = "retrieve characteristics";
      break;
    case BluetoothOperation::kDescriptorsRetrieval:
      operation_string = "retrieve descriptors";
      break;
    case BluetoothOperation::kGATT:
      operation_string = "perform GATT operations";
      break;
  }
  return String::Format(kGATTServerNotConnectedBase, operation_string);
}

// static
DOMException* BluetoothError::CreateNotConnectedException(
    BluetoothOperation operation) {
  return MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNetworkError,
      CreateNotConnectedExceptionMessage(operation));
}

// static
DOMException* BluetoothError::CreateDOMException(
    BluetoothErrorCode error,
    const String& detailed_message) {
  switch (error) {
    case BluetoothErrorCode::kInvalidService:
    case BluetoothErrorCode::kInvalidCharacteristic:
    case BluetoothErrorCode::kInvalidDescriptor:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kInvalidStateError, detailed_message);
    case BluetoothErrorCode::kServiceNotFound:
    case BluetoothErrorCode::kCharacteristicNotFound:
    case BluetoothErrorCode::kDescriptorNotFound:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotFoundError, detailed_message);
  }
  NOTREACHED();
}

// static
DOMException* BluetoothError::CreateDOMException(
    mojom::blink::WebBluetoothResult error) {
  switch (error) {
    case mojom::blink::WebBluetoothResult::SUCCESS:
    case mojom::blink::WebBluetoothResult::SERVICE_NOT_FOUND:
    case mojom::blink::WebBluetoothResult::CHARACTERISTIC_NOT_FOUND:
    case mojom::blink::WebBluetoothResult::DESCRIPTOR_NOT_FOUND:
      // The above result codes are not expected here. SUCCESS is not
      // an error and the others have a detailed message and are
      // expected to be redirected to the switch above that handles
      // BluetoothErrorCode.
      NOTREACHED();
#define MAP_ERROR(enumeration, name, message)         \
  case mojom::blink::WebBluetoothResult::enumeration: \
    return MakeGarbageCollected<DOMException>(name, message);

      // AbortErrors:
      MAP_ERROR(WATCH_ADVERTISEMENTS_ABORTED, DOMExceptionCode::kAbortError,
                "The Bluetooth operation was cancelled.");

      // InvalidModificationErrors:
      MAP_ERROR(GATT_INVALID_ATTRIBUTE_LENGTH,
                DOMExceptionCode::kInvalidModificationError,
                "GATT Error: invalid attribute length.");
      MAP_ERROR(CONNECT_INVALID_ARGS,
                DOMExceptionCode::kInvalidModificationError,
                "Connection Error: invalid arguments.");

      // InvalidStateErrors:
      MAP_ERROR(SERVICE_NO_LONGER_EXISTS, DOMExceptionCode::kInvalidStateError,
                "GATT Service no longer exists.");
      MAP_ERROR(CHARACTERISTIC_NO_LONGER_EXISTS,
                DOMExceptionCode::kInvalidStateError,
                "GATT Characteristic no longer exists.");
      MAP_ERROR(DESCRIPTOR_NO_LONGER_EXISTS,
                DOMExceptionCode::kInvalidStateError,
                "GATT Descriptor no longer exists.");
      MAP_ERROR(PROMPT_CANCELED, DOMExceptionCode::kInvalidStateError,
                "User canceled the permission prompt.");
      MAP_ERROR(CONNECT_NOT_READY, DOMExceptionCode::kInvalidStateError,
                "Connection Error: Not ready.");
      MAP_ERROR(CONNECT_ALREADY_CONNECTED, DOMExceptionCode::kInvalidStateError,
                "Connection Error: Already connected.");
      MAP_ERROR(CONNECT_ALREADY_EXISTS, DOMExceptionCode::kInvalidStateError,
                "Connection Error: Already exists.");
      MAP_ERROR(CONNECT_NOT_CONNECTED, DOMExceptionCode::kInvalidStateError,
                "Connection Error: Not connected.");
      MAP_ERROR(CONNECT_NON_AUTH_TIMEOUT, DOMExceptionCode::kInvalidStateError,
                "Connection Error: Non-authentication timeout.");

      // NetworkErrors:
      MAP_ERROR(CONNECT_ALREADY_IN_PROGRESS, DOMExceptionCode::kNetworkError,
                "Connection already in progress.");
      MAP_ERROR(CONNECT_AUTH_CANCELED, DOMExceptionCode::kNetworkError,
                "Authentication canceled.");
      MAP_ERROR(CONNECT_AUTH_FAILED, DOMExceptionCode::kNetworkError,
                "Authentication failed.");
      MAP_ERROR(CONNECT_AUTH_REJECTED, DOMExceptionCode::kNetworkError,
                "Authentication rejected.");
      MAP_ERROR(CONNECT_AUTH_TIMEOUT, DOMExceptionCode::kNetworkError,
                "Authentication timeout.");
      MAP_ERROR(CONNECT_UNKNOWN_ERROR, DOMExceptionCode::kNetworkError,
                "Unknown error when connecting to the device.");
      MAP_ERROR(CONNECT_UNKNOWN_FAILURE, DOMExceptionCode::kNetworkError,
                "Connection failed for unknown reason.");
      MAP_ERROR(CONNECT_UNSUPPORTED_DEVICE, DOMExceptionCode::kNetworkError,
                "Unsupported device.");
      MAP_ERROR(DEVICE_NO_LONGER_IN_RANGE, DOMExceptionCode::kNetworkError,
                "Bluetooth Device is no longer in range.");
      MAP_ERROR(GATT_NOT_PAIRED, DOMExceptionCode::kNetworkError,
                "GATT Error: Not paired.");
      MAP_ERROR(GATT_OPERATION_IN_PROGRESS, DOMExceptionCode::kNetworkError,
                "GATT operation already in progress.");
      MAP_ERROR(CONNECT_CONN_FAILED, DOMExceptionCode::kNetworkError,
                "Connection Error: Connection attempt failed.");

      // NotFoundErrors:
      MAP_ERROR(WEB_BLUETOOTH_NOT_SUPPORTED, DOMExceptionCode::kNotFoundError,
                "Web Bluetooth is not supported on this platform. For a list "
                "of supported platforms see: https://goo.gl/J6ASzs");
      MAP_ERROR(NO_BLUETOOTH_ADAPTER, DOMExceptionCode::kNotFoundError,
                "Bluetooth adapter not available.");
      MAP_ERROR(CHOSEN_DEVICE_VANISHED, DOMExceptionCode::kNotFoundError,
                "User selected a device that doesn't exist anymore.");
      MAP_ERROR(CHOOSER_CANCELLED, DOMExceptionCode::kNotFoundError,
                "User cancelled the requestDevice() chooser.");
      MAP_ERROR(CHOOSER_NOT_SHOWN_API_GLOBALLY_DISABLED,
                DOMExceptionCode::kNotFoundError,
                "Web Bluetooth API globally disabled.");
      MAP_ERROR(CHOOSER_NOT_SHOWN_API_LOCALLY_DISABLED,
                DOMExceptionCode::kNotFoundError,
                "User or their enterprise policy has disabled Web Bluetooth.");
      MAP_ERROR(
          CHOOSER_NOT_SHOWN_USER_DENIED_PERMISSION_TO_SCAN,
          DOMExceptionCode::kNotFoundError,
          "User denied the browser permission to scan for Bluetooth devices.");
      MAP_ERROR(NO_SERVICES_FOUND, DOMExceptionCode::kNotFoundError,
                "No Services found in device.");
      MAP_ERROR(NO_CHARACTERISTICS_FOUND, DOMExceptionCode::kNotFoundError,
                "No Characteristics found in service.");
      MAP_ERROR(NO_DESCRIPTORS_FOUND, DOMExceptionCode::kNotFoundError,
                "No Descriptors found in Characteristic.");
      MAP_ERROR(BLUETOOTH_LOW_ENERGY_NOT_AVAILABLE,
                DOMExceptionCode::kNotFoundError,
                "Bluetooth Low Energy not available.");
      MAP_ERROR(CONNECT_DOES_NOT_EXIST, DOMExceptionCode::kNotFoundError,
                "Does not exist.");

      // NotSupportedErrors:
      MAP_ERROR(GATT_UNKNOWN_ERROR, DOMExceptionCode::kNotSupportedError,
                "GATT Error Unknown.");
      MAP_ERROR(GATT_UNKNOWN_FAILURE, DOMExceptionCode::kNotSupportedError,
                "GATT operation failed for unknown reason.");
      MAP_ERROR(GATT_NOT_PERMITTED, DOMExceptionCode::kNotSupportedError,
                "GATT operation not permitted.");
      MAP_ERROR(GATT_NOT_SUPPORTED, DOMExceptionCode::kNotSupportedError,
                "GATT Error: Not supported.");
      MAP_ERROR(GATT_UNTRANSLATED_ERROR_CODE,
                DOMExceptionCode::kNotSupportedError,
                "GATT Error: Unknown GattErrorCode.");

      // SecurityErrors:
      MAP_ERROR(GATT_NOT_AUTHORIZED, DOMExceptionCode::kSecurityError,
                "GATT operation not authorized.");
      MAP_ERROR(BLOCKLISTED_CHARACTERISTIC_UUID,
                DOMExceptionCode::kSecurityError,
                "getCharacteristic(s) called with blocklisted UUID. "
                "https://goo.gl/4NeimX");
      MAP_ERROR(BLOCKLISTED_DESCRIPTOR_UUID, DOMExceptionCode::kSecurityError,
                "getDescriptor(s) called with blocklisted UUID. "
                "https://goo.gl/4NeimX");
      MAP_ERROR(BLOCKLISTED_READ, DOMExceptionCode::kSecurityError,
                "readValue() called on blocklisted object marked "
                "exclude-reads. https://goo.gl/4NeimX");
      MAP_ERROR(BLOCKLISTED_WRITE, DOMExceptionCode::kSecurityError,
                "writeValue() called on blocklisted object marked "
                "exclude-writes. https://goo.gl/4NeimX");
      MAP_ERROR(NOT_ALLOWED_TO_ACCESS_ANY_SERVICE,
                DOMExceptionCode::kSecurityError,
                "Origin is not allowed to access any service. Tip: Add the "
                "service UUID to 'optionalServices' in requestDevice() "
                "options. https://goo.gl/HxfxSQ");
      MAP_ERROR(NOT_ALLOWED_TO_ACCESS_SERVICE, DOMExceptionCode::kSecurityError,
                "Origin is not allowed to access the service. Tip: Add the "
                "service UUID to 'optionalServices' in requestDevice() "
                "options. https://goo.gl/HxfxSQ");
      MAP_ERROR(REQUEST_DEVICE_WITH_BLOCKLISTED_UUID_OR_MANUFACTURER_DATA,
                DOMExceptionCode::kSecurityError,
                "requestDevice() called with a filter containing a blocklisted "
                "UUID or manufacturer data. https://goo.gl/4NeimX");
      MAP_ERROR(PERMISSIONS_POLICY_VIOLATION, DOMExceptionCode::kSecurityError,
                "Access to the feature \"bluetooth\" is disallowed by "
                "permissions policy.");

      // NotAllowedErrors:
      MAP_ERROR(SCANNING_BLOCKED, DOMExceptionCode::kNotAllowedError,
                "requestLEScan() call is blocked by user.");

      // UnknownErrors:
      MAP_ERROR(CONNECT_NO_MEMORY, DOMExceptionCode::kUnknownError,
                "Connection Error: An internal error has occurred.");
      MAP_ERROR(CONNECT_JNI_ENVIRONMENT, DOMExceptionCode::kUnknownError,
                "Connection Error: An internal error has occurred.");
      MAP_ERROR(CONNECT_JNI_THREAD_ATTACH, DOMExceptionCode::kUnknownError,
                "Connection Error: An internal error has occurred.");
      MAP_ERROR(CONNECT_WAKELOCK, DOMExceptionCode::kUnknownError,
                "Connection Error: An internal error has occurred.");
      MAP_ERROR(CONNECT_UNEXPECTED_STATE, DOMExceptionCode::kUnknownError,
                "Connection Error: An internal error has occurred.");
      MAP_ERROR(CONNECT_SOCKET_ERROR, DOMExceptionCode::kUnknownError,
                "Connection Error: An internal error has occurred.");

#undef MAP_ERROR
  }

  NOTREACHED();
}

}  // namespace blink

"""

```