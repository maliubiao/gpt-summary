Response:
Let's break down the thought process for analyzing the `BluetoothRemoteGATTCharacteristic.cc` file.

1. **Understanding the Core Purpose:** The filename itself, `bluetooth_remote_gatt_characteristic.cc`, strongly suggests this file is responsible for handling interactions with a remote GATT (Generic Attribute Profile) characteristic within the Bluetooth framework in the Chromium Blink engine. The `Remote` part indicates it deals with characteristics on a *connected* Bluetooth device, not local ones. `GATT` ties it specifically to the data exchange protocol. `Characteristic` pinpoints the level of Bluetooth abstraction it manages.

2. **Initial Code Scan - Identifying Key Elements:**  A quick skim of the code reveals several important aspects:
    * **Includes:**  The included headers give hints about dependencies and functionalities:
        * `mojom/bluetooth/web_bluetooth.mojom-blink.h`:  Interaction with the lower-level Bluetooth service (likely via Mojo IPC).
        * `bindings/core/v8/...`: Integration with JavaScript via V8. This confirms the JavaScript connection.
        * `core/dom/...`: DOM manipulation, specifically events. This hints at how changes are reported to the web page.
        * `modules/bluetooth/...`: Other related Bluetooth classes within Blink, showing the broader context.
        * `platform/...`: Platform-level abstractions.
    * **Class Definition:** The central class is `BluetoothRemoteGATTCharacteristic`.
    * **Methods:**  Methods like `readValue`, `writeValue`, `startNotifications`, `stopNotifications`, and `getDescriptor` strongly suggest the primary actions that can be performed on a Bluetooth characteristic.
    * **Callbacks:** Methods with `Callback` in their name (e.g., `ReadValueCallback`, `WriteValueCallback`, `NotificationsCallback`, `GetDescriptorsCallback`) point to asynchronous operations and how results are handled.
    * **Promises:** The use of `ScriptPromise` throughout the public methods clearly links these operations to JavaScript Promises, crucial for asynchronous JavaScript interaction.
    * **Events:** The dispatching of `characteristicvaluechanged` events indicates how the browser informs the web page about changes in the characteristic's value.
    * **Error Handling:**  Checks for connection status, invalid states, and the use of `DOMException` demonstrate error handling.

3. **Mapping to Web Bluetooth API:** Based on the method names and the overall context, the connection to the Web Bluetooth API becomes evident. The methods directly correspond to JavaScript methods available on a `BluetoothRemoteGATTCharacteristic` object in the browser. For example:
    * `readValue` <-> `characteristic.readValue()`
    * `writeValue` <-> `characteristic.writeValue()`
    * `startNotifications` <-> `characteristic.startNotifications()`
    * `getDescriptor` <-> `characteristic.getDescriptor()`

4. **Analyzing Functionality - Method by Method:** Now, delve into the specific functions, focusing on what they do, their inputs, and their outputs:
    * **Constructor:** Initializes the object with data received from the lower-level Bluetooth service.
    * **`SetValue`:**  Internally updates the cached value of the characteristic.
    * **`RemoteCharacteristicValueChanged`:**  Handles value change notifications from the Bluetooth device. It's important to note the handling of deferred events during notification registration.
    * **`readValue`:** Initiates a read operation and returns a Promise that resolves with the characteristic's value.
    * **`writeValue` family:** Initiates write operations (with and without response) and returns a Promise. Pay attention to the size limit check (512 bytes).
    * **`startNotifications` and `stopNotifications`:**  Manage the subscription to characteristic value change notifications. The use of Mojo associated receivers is a detail to note.
    * **`getDescriptor` and `getDescriptors`:** Retrieve descriptors associated with the characteristic.

5. **Identifying Relationships with JavaScript, HTML, CSS:**
    * **JavaScript:** The core interaction. The C++ code implements the backend logic for the JavaScript Web Bluetooth API. JavaScript calls the methods, and the C++ code executes the Bluetooth operations. Promises bridge the asynchronous gap.
    * **HTML:** HTML provides the structure where the JavaScript code runs. Buttons or other UI elements can trigger JavaScript code that interacts with the Bluetooth API.
    * **CSS:** CSS styles the HTML elements. While not directly involved in the Bluetooth logic, it affects how the user interface appears.

6. **Logical Inference (Hypothetical Input/Output):** Consider specific scenarios:
    * **`readValue`:**  Input: JavaScript calls `characteristic.readValue()`. Output: A Promise that resolves with a `DataView` containing the characteristic's value (as a byte array). Error cases lead to Promise rejection.
    * **`writeValue`:** Input: JavaScript calls `characteristic.writeValue(new Uint8Array([1, 2, 3]))`. Output: A Promise that resolves when the write is successful, or rejects if it fails.
    * **`startNotifications`:** Input: JavaScript calls `characteristic.startNotifications()`. Output: A Promise that resolves when notifications are successfully started. Subsequent value changes trigger `characteristicvaluechanged` events.

7. **Common User/Programming Errors:** Think about what developers might do wrong:
    * **Forgetting to connect:** Trying to access characteristics before connecting to the GATT server.
    * **Incorrect UUIDs:** Using the wrong UUID for a characteristic.
    * **Writing too much data:** Exceeding the 512-byte limit for writes.
    * **Not handling disconnections:**  The Bluetooth connection can drop, and code needs to handle this.
    * **Incorrect permissions:** The Bluetooth device might not allow certain operations.

8. **Debugging Workflow (User Steps):**  Imagine a user interacting with a webpage that uses Bluetooth:
    1. User clicks a button on the webpage.
    2. JavaScript code is executed.
    3. This JavaScript code uses the Web Bluetooth API (e.g., `navigator.bluetooth.requestDevice()`, `device.gatt.connect()`, `service.getCharacteristic()`).
    4. The JavaScript code calls a method on a `BluetoothRemoteGATTCharacteristic` object (e.g., `characteristic.readValue()`).
    5. This JavaScript call triggers the corresponding C++ method in this file (`BluetoothRemoteGATTCharacteristic::readValue`).
    6. The C++ code interacts with the lower-level Bluetooth service via Mojo.
    7. The Bluetooth service on the operating system communicates with the Bluetooth device.
    8. The response from the Bluetooth device is passed back through the layers to the C++ code.
    9. The C++ code resolves the JavaScript Promise with the data.
    10. The JavaScript code handles the resolved Promise and updates the webpage.

9. **Refining and Structuring the Explanation:** Organize the gathered information into logical sections (Functionality, JavaScript/HTML/CSS Relation, Logic Inference, Common Errors, Debugging). Use clear and concise language. Provide concrete examples.

This methodical approach, starting with the big picture and progressively drilling down into the details, while constantly relating the code back to its purpose and how it's used, allows for a comprehensive understanding of the `BluetoothRemoteGATTCharacteristic.cc` file.
这个文件 `blink/renderer/modules/bluetooth/bluetooth_remote_gatt_characteristic.cc` 是 Chromium Blink 渲染引擎中，用于处理远程 GATT (Generic Attribute Profile) 特征（Characteristic）的核心逻辑。它实现了 Web Bluetooth API 中 `BluetoothRemoteGATTCharacteristic` 接口的功能。

以下是它的主要功能：

**1. 表示和管理远程 GATT 特征:**

*   **封装底层 Mojo 对象:** 它持有一个 `mojom::blink::WebBluetoothRemoteGATTCharacteristicPtr` 对象，该对象是通过 Mojo 与浏览器进程中的 Bluetooth 服务进行通信的桥梁。
*   **存储特征信息:** 它存储了从蓝牙设备获取的特征的 UUID、属性（properties）等信息。
*   **关联服务和设备:** 它知道这个特征属于哪个 `BluetoothRemoteGATTService` 和 `BluetoothDevice`。

**2. 实现读取特征值的功能 (readValue):**

*   **JavaScript 调用:** 当 JavaScript 代码调用 `characteristic.readValue()` 时，会触发这个 C++ 方法。
*   **向蓝牙服务发送请求:** 它通过 Mojo 向浏览器进程的蓝牙服务发送读取特征值的请求。
*   **处理读取结果:**  当蓝牙服务返回读取结果后，会调用 `ReadValueCallback`。
*   **解析和存储值:** `ReadValueCallback` 将收到的字节数组转换为 `DOMDataView` 对象并存储起来。
*   **触发事件:**  如果成功读取，会触发 `characteristicvaluechanged` 事件，通知监听器特征值已更改。
*   **返回 Promise:** `readValue` 方法返回一个 JavaScript Promise，该 Promise 会在读取成功时解析为 `DataView` 对象，失败时拒绝。

**3. 实现写入特征值的功能 (writeValue, writeValueWithResponse, writeValueWithoutResponse):**

*   **JavaScript 调用:** 当 JavaScript 代码调用 `characteristic.writeValue(...)` 等方法时，会触发这些 C++ 方法。
*   **数据校验:**  会检查写入的数据大小是否超过限制 (512 字节)。
*   **向蓝牙服务发送请求:** 通过 Mojo 向蓝牙服务发送写入请求，并指定写入类型（带响应或不带响应）。
*   **处理写入结果:**  当蓝牙服务返回写入结果后，会调用 `WriteValueCallback`。
*   **更新本地值:** 如果写入成功，会更新本地存储的特征值。
*   **返回 Promise:** 这些方法返回 JavaScript Promise，成功时解析，失败时拒绝。

**4. 实现订阅特征值变化通知的功能 (startNotifications, stopNotifications):**

*   **JavaScript 调用:** 当 JavaScript 代码调用 `characteristic.startNotifications()` 或 `characteristic.stopNotifications()` 时，会触发这些方法。
*   **建立或断开通知通道:** 通过 Mojo 向蓝牙服务发送开始或停止通知的请求。
*   **注册客户端:** `startNotifications` 会注册一个 Mojo 客户端接口，用于接收蓝牙设备发送的通知。
*   **接收通知:** 当蓝牙设备发送特征值变化的通知时，会调用 `RemoteCharacteristicValueChanged` 方法。
*   **触发事件:** `RemoteCharacteristicValueChanged` 方法会将收到的值更新，并触发 `characteristicvaluechanged` 事件。
*   **返回 Promise:** 这些方法返回 JavaScript Promise，指示订阅或取消订阅是否成功。

**5. 获取特征的描述符 (getDescriptor, getDescriptors):**

*   **JavaScript 调用:** 当 JavaScript 代码调用 `characteristic.getDescriptor(...)` 或 `characteristic.getDescriptors(...)` 时触发。
*   **向蓝牙服务发送请求:** 通过 Mojo 向蓝牙服务发送获取描述符的请求，可以指定特定的 UUID 或获取所有描述符。
*   **处理获取结果:**  当蓝牙服务返回描述符信息后，会调用 `GetDescriptorsCallback`。
*   **创建描述符对象:** `GetDescriptorsCallback` 会根据收到的 Mojo 对象创建 `BluetoothRemoteGATTDescriptor` 对象。
*   **返回 Promise:** 这些方法返回 JavaScript Promise，解析为单个或多个 `BluetoothRemoteGATTDescriptor` 对象。

**与 Javascript, HTML, CSS 的关系:**

这个文件是 Web Bluetooth API 的一部分，它直接与 JavaScript 功能相关，而 JavaScript 可以操作 HTML 结构和 CSS 样式。

*   **JavaScript:**  `BluetoothRemoteGATTCharacteristic.cc` 实现了 `BluetoothRemoteGATTCharacteristic` JavaScript 接口背后的核心逻辑。JavaScript 代码通过调用 `characteristic.readValue()`, `characteristic.writeValue(...)`, `characteristic.startNotifications()` 等方法来使用这里实现的功能。

    ```javascript
    // JavaScript 示例
    navigator.bluetooth.requestDevice({
      filters: [{ services: ['heart_rate'] }]
    })
    .then(device => device.gatt.connect())
    .then(server => server.getPrimaryService('heart_rate'))
    .then(service => service.getCharacteristic('heart_rate_measurement'))
    .then(characteristic => {
      // 读取特征值
      characteristic.readValue()
        .then(value => {
          console.log('Heart Rate:', value.getUint8(0));
        });

      // 监听特征值变化
      characteristic.startNotifications()
        .then(() => {
          characteristic.addEventListener('characteristicvaluechanged',
                                            handleHeartRateChange);
        });
    })
    .catch(error => { console.error('Error:', error); });

    function handleHeartRateChange(event) {
      const value = event.target.value;
      console.log('Heart Rate changed to:', value.getUint8(0));
      // 可以更新 HTML 元素显示心率
      document.getElementById('heart-rate').textContent = value.getUint8(0);
    }
    ```

*   **HTML:** HTML 提供了用户界面，用户可以通过交互（例如点击按钮）触发 JavaScript 代码，进而调用 Web Bluetooth API。在上面的 JavaScript 例子中，我们假设 HTML 中有一个 id 为 `heart-rate` 的元素用于显示心率。

    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>Web Bluetooth Heart Rate Monitor</title>
    </head>
    <body>
      <h1>Heart Rate: <span id="heart-rate">--</span> bpm</h1>
      <button id="connectButton">Connect to Heart Rate Monitor</button>
      <script src="script.js"></script>
    </body>
    </html>
    ```

*   **CSS:** CSS 用于控制 HTML 元素的样式和布局，虽然不直接参与蓝牙逻辑，但它影响用户如何看到和与使用了 Web Bluetooth 的网页进行交互。

**逻辑推理 (假设输入与输出):**

假设一个蓝牙心率监测设备广播了心率服务 (UUID: `0x180D`)，并且心率测量特征 (UUID: `0x2A37`) 的值是单字节无符号整数。

**假设输入:**

1. **用户操作:** 用户点击了网页上的 "Connect to Heart Rate Monitor" 按钮。
2. **JavaScript 调用:**  JavaScript 代码执行 `characteristic.readValue()`。

**逻辑推理过程 (在 `BluetoothRemoteGATTCharacteristic.cc` 中):**

1. `readValue` 方法被调用。
2. 它通过 Mojo 向蓝牙服务发送读取特征值 (UUID: `0x2A37`) 的请求。
3. 蓝牙服务与心率监测设备通信。
4. 心率监测设备返回一个字节的数据，例如 `0x64` (十进制 100)。
5. 蓝牙服务将数据通过 Mojo 返回给渲染进程。
6. `ReadValueCallback` 被调用，接收到包含 `0x64` 的字节数组。
7. `ReadValueCallback` 将字节数组转换为 `DOMDataView`。
8. `readValue` 返回的 Promise 被解析，其值为包含 `0x64` 的 `DataView` 对象。

**输出:**

*   **JavaScript 接收到的 `DataView`:**  `value.getUint8(0)` 将返回 `100`。
*   **网页更新:** JavaScript 代码可能会将心率值更新到 HTML 元素上，例如 `document.getElementById('heart-rate').textContent = '100';`。

**涉及用户或者编程常见的使用错误:**

1. **未连接到 GATT 服务器:** 在调用 `readValue` 或 `writeValue` 等方法之前，必须先成功连接到设备的 GATT 服务器。如果未连接，这些方法会抛出 `NetworkError` 异常。

    ```javascript
    // 错误示例：在连接之前尝试读取
    navigator.bluetooth.requestDevice(...)
      .then(device => {
        // 注意：这里没有调用 device.gatt.connect()
        return device.gatt.getPrimaryService('heart_rate')
          .then(service => service.getCharacteristic('heart_rate_measurement'))
          .then(characteristic => characteristic.readValue()); // 可能抛出 NetworkError
      });
    ```

2. **尝试在未支持的操作上调用方法:** 如果尝试在不支持 `read` 属性的特征上调用 `readValue`，或者在不支持 `write` 属性的特征上调用 `writeValue`，这些操作会失败并抛出异常。

    ```javascript
    // 假设 characteristic 不支持写入
    characteristic.writeValue(new Uint8Array([0x01])) // 可能抛出 InvalidStateError
      .catch(error => console.error("Write failed:", error));
    ```

3. **写入的数据超过最大长度:**  GATT 特征的值有最大长度限制（通常是 512 字节）。尝试写入超过此限制的数据会导致 `InvalidModificationError` 异常。

    ```javascript
    const largeData = new Uint8Array(1024); // 超过 512 字节
    characteristic.writeValue(largeData) // 会抛出 InvalidModificationError
      .catch(error => console.error("Write failed:", error));
    ```

4. **在断开连接后尝试操作:**  如果蓝牙连接中断，尝试对特征进行操作会导致 `NetworkError` 异常。开发者需要监听设备的 `gattserverdisconnected` 事件并妥善处理断线情况。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户操作:** 用户在网页上与某个按钮或元素进行交互，例如点击了一个 "读取心率" 的按钮。
2. **JavaScript 事件处理:** 网页的 JavaScript 代码监听了这个按钮的点击事件。
3. **调用 Web Bluetooth API:** 在事件处理函数中，JavaScript 代码调用了 `characteristic.readValue()` 方法。这里的 `characteristic` 对象是通过之前的 `navigator.bluetooth.requestDevice()`, `device.gatt.connect()`, `service.getCharacteristic()` 等步骤获取的。
4. **Blink 绑定层:**  JavaScript 引擎 (V8) 将 `characteristic.readValue()` 的调用传递给 Blink 的绑定层。
5. **`BluetoothRemoteGATTCharacteristic::readValue`:**  Blink 的绑定层会将这个 JavaScript 调用映射到 `blink/renderer/modules/bluetooth/bluetooth_remote_gatt_characteristic.cc` 文件中的 `BluetoothRemoteGATTCharacteristic::readValue` 方法。
6. **Mojo 调用:** `readValue` 方法内部会创建并发送一个 Mojo 消息，请求浏览器进程的蓝牙服务读取特征值。
7. **浏览器进程处理:** 浏览器进程的蓝牙服务接收到 Mojo 消息，并与操作系统底层的蓝牙 API 进行交互，最终与蓝牙设备通信。
8. **数据返回:** 蓝牙设备返回特征值，数据通过操作系统和浏览器进程的蓝牙服务，再次通过 Mojo 返回到渲染进程。
9. **`BluetoothRemoteGATTCharacteristic::ReadValueCallback`:**  渲染进程接收到 Mojo 消息后，会调用 `BluetoothRemoteGATTCharacteristic::ReadValueCallback` 方法处理返回的数据。
10. **Promise 解析:** `ReadValueCallback` 方法会将数据转换为 `DataView` 对象，并解析之前 `readValue` 方法返回的 JavaScript Promise。
11. **JavaScript 回调:**  JavaScript 中 `readValue().then(...)` 的回调函数会被调用，接收到包含特征值的 `DataView` 对象，并可以更新网页内容。

**调试线索:**

在调试 Web Bluetooth 相关问题时，可以关注以下线索：

*   **JavaScript 控制台错误:**  查看浏览器控制台是否有与 Web Bluetooth 相关的错误消息，例如 `NetworkError`, `InvalidStateError`, `SecurityError` 等。
*   **`chrome://bluetooth-internals`:**  Chrome 浏览器提供了 `chrome://bluetooth-internals` 页面，可以查看蓝牙设备的连接状态、GATT 服务和特征的信息，以及蓝牙事件的日志，这对于诊断连接问题或特征发现问题很有帮助。
*   **断点调试:** 在 Chrome 开发者工具中，可以在 JavaScript 代码中设置断点，查看变量的值，追踪代码执行流程。也可以在 C++ 代码中设置断点（如果可以构建 Chromium），深入了解 Blink 引擎的执行过程。
*   **Mojo 日志:**  如果涉及到 Mojo 通信问题，可以尝试启用 Mojo 日志来查看消息的发送和接收情况。
*   **蓝牙抓包:**  使用蓝牙抓包工具（例如 Wireshark）可以捕获蓝牙设备之间的通信数据，用于分析底层的蓝牙协议交互。

总而言之，`bluetooth_remote_gatt_characteristic.cc` 文件是 Web Bluetooth API 中操作远程 GATT 特征的关键组成部分，它连接了 JavaScript 代码和底层的蓝牙服务，负责实现读取、写入、订阅通知等核心功能。 理解它的功能和工作流程对于开发和调试 Web Bluetooth 应用至关重要。

### 提示词
```
这是目录为blink/renderer/modules/bluetooth/bluetooth_remote_gatt_characteristic.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/bluetooth/bluetooth_remote_gatt_characteristic.h"

#include <utility>

#include "mojo/public/cpp/bindings/associated_receiver_set.h"
#include "mojo/public/cpp/bindings/pending_associated_remote.h"
#include "third_party/blink/public/mojom/bluetooth/web_bluetooth.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth_characteristic_properties.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth_device.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth_error.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth_remote_gatt_descriptor.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth_remote_gatt_service.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth_remote_gatt_utils.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth_uuid.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

BluetoothRemoteGATTCharacteristic::BluetoothRemoteGATTCharacteristic(
    ExecutionContext* context,
    mojom::blink::WebBluetoothRemoteGATTCharacteristicPtr characteristic,
    BluetoothRemoteGATTService* service,
    BluetoothDevice* device)
    : ActiveScriptWrappable<BluetoothRemoteGATTCharacteristic>({}),
      ExecutionContextLifecycleObserver(context),
      characteristic_(std::move(characteristic)),
      service_(service),
      device_(device),
      receivers_(this, context) {
  properties_ = MakeGarbageCollected<BluetoothCharacteristicProperties>(
      characteristic_->properties);
}

void BluetoothRemoteGATTCharacteristic::SetValue(DOMDataView* dom_data_view) {
  value_ = dom_data_view;
}

void BluetoothRemoteGATTCharacteristic::RemoteCharacteristicValueChanged(
    base::span<const uint8_t> value) {
  if (!GetGatt()->connected())
    return;
  SetValue(BluetoothRemoteGATTUtils::ConvertSpanToDataView(value));
  if (notification_registration_in_progress()) {
    // Save event and value to be dispatched after notification is registered.
    deferred_value_change_data_.push_back(
        MakeGarbageCollected<DeferredValueChange>(
            Event::Create(event_type_names::kCharacteristicvaluechanged),
            value_, /*promise=*/nullptr));
  } else {
    DispatchEvent(
        *Event::Create(event_type_names::kCharacteristicvaluechanged));
  }
}

const WTF::AtomicString& BluetoothRemoteGATTCharacteristic::InterfaceName()
    const {
  return event_target_names::kBluetoothRemoteGATTCharacteristic;
}

ExecutionContext* BluetoothRemoteGATTCharacteristic::GetExecutionContext()
    const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

bool BluetoothRemoteGATTCharacteristic::HasPendingActivity() const {
  // This object should be considered active as long as there are registered
  // event listeners. Even if script drops all references this can still be
  // found again through the BluetoothRemoteGATTServer object.
  return GetExecutionContext() && HasEventListeners();
}

void BluetoothRemoteGATTCharacteristic::AddedEventListener(
    const AtomicString& event_type,
    RegisteredEventListener& registered_listener) {
  EventTarget::AddedEventListener(event_type, registered_listener);
}

void BluetoothRemoteGATTCharacteristic::ReadValueCallback(
    ScriptPromiseResolver<NotShared<DOMDataView>>* resolver,
    mojom::blink::WebBluetoothResult result,
    base::span<const uint8_t> value) {
  if (!resolver->GetExecutionContext() ||
      resolver->GetExecutionContext()->IsContextDestroyed())
    return;

  // If the device is disconnected, reject.
  if (!GetGatt()->RemoveFromActiveAlgorithms(resolver)) {
    resolver->Reject(
        BluetoothError::CreateNotConnectedException(BluetoothOperation::kGATT));
    return;
  }

  if (result == mojom::blink::WebBluetoothResult::SUCCESS) {
    DOMDataView* dom_data_view =
        BluetoothRemoteGATTUtils::ConvertSpanToDataView(value);
    SetValue(dom_data_view);
    if (notification_registration_in_progress()) {
      // Save event to be dispatched after notification is registered.
      deferred_value_change_data_.push_back(
          MakeGarbageCollected<DeferredValueChange>(
              Event::Create(event_type_names::kCharacteristicvaluechanged),
              dom_data_view, resolver));
    } else {
      DispatchEvent(
          *Event::Create(event_type_names::kCharacteristicvaluechanged));
      resolver->Resolve(NotShared(dom_data_view));
    }
  } else {
    resolver->Reject(BluetoothError::CreateDOMException(result));
  }
}

ScriptPromise<NotShared<DOMDataView>>
BluetoothRemoteGATTCharacteristic::readValue(ScriptState* script_state,
                                             ExceptionState& exception_state) {
  if (!GetGatt()->connected() || !GetBluetooth()->IsServiceBound()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNetworkError,
        BluetoothError::CreateNotConnectedExceptionMessage(
            BluetoothOperation::kGATT));
    return ScriptPromise<NotShared<DOMDataView>>();
  }

  if (!GetGatt()->device()->IsValidCharacteristic(
          characteristic_->instance_id)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        CreateInvalidCharacteristicErrorMessage());
    return ScriptPromise<NotShared<DOMDataView>>();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<NotShared<DOMDataView>>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  GetGatt()->AddToActiveAlgorithms(resolver);

  mojom::blink::WebBluetoothService* service = GetBluetooth()->Service();
  service->RemoteCharacteristicReadValue(
      characteristic_->instance_id,
      WTF::BindOnce(&BluetoothRemoteGATTCharacteristic::ReadValueCallback,
                    WrapPersistent(this), WrapPersistent(resolver)));

  return promise;
}

void BluetoothRemoteGATTCharacteristic::WriteValueCallback(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    DOMDataView* new_value,
    mojom::blink::WebBluetoothResult result) {
  if (!resolver->GetExecutionContext() ||
      resolver->GetExecutionContext()->IsContextDestroyed())
    return;

  // If the device is disconnected, reject.
  if (!GetGatt()->RemoveFromActiveAlgorithms(resolver)) {
    resolver->Reject(
        BluetoothError::CreateNotConnectedException(BluetoothOperation::kGATT));
    return;
  }

  if (result == mojom::blink::WebBluetoothResult::SUCCESS) {
    SetValue(new_value);
    resolver->Resolve();
  } else {
    resolver->Reject(BluetoothError::CreateDOMException(result));
  }
}

ScriptPromise<IDLUndefined>
BluetoothRemoteGATTCharacteristic::WriteCharacteristicValue(
    ScriptState* script_state,
    base::span<const uint8_t> value,
    mojom::blink::WebBluetoothWriteType write_type,
    ExceptionState& exception_state) {
  if (!GetGatt()->connected() || !GetBluetooth()->IsServiceBound()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNetworkError,
        BluetoothError::CreateNotConnectedExceptionMessage(
            BluetoothOperation::kGATT));
    return EmptyPromise();
  }

  if (!GetGatt()->device()->IsValidCharacteristic(
          characteristic_->instance_id)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        CreateInvalidCharacteristicErrorMessage());
    return EmptyPromise();
  }

  // Partial implementation of writeValue algorithm:
  // https://webbluetoothcg.github.io/web-bluetooth/#dom-bluetoothremotegattcharacteristic-writevalue

  // If bytes is more than 512 bytes long (the maximum length of an attribute
  // value, per Long Attribute Values) return a promise rejected with an
  // InvalidModificationError and abort.
  if (value.size() > 512) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidModificationError,
        "Value can't exceed 512 bytes.");
    return EmptyPromise();
  }

  // Let newValue be a copy of the bytes held by value.
  DOMDataView* new_value =
      BluetoothRemoteGATTUtils::ConvertSpanToDataView(value);

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  GetGatt()->AddToActiveAlgorithms(resolver);

  mojom::blink::WebBluetoothService* service = GetBluetooth()->Service();
  service->RemoteCharacteristicWriteValue(
      characteristic_->instance_id, value, write_type,
      WTF::BindOnce(&BluetoothRemoteGATTCharacteristic::WriteValueCallback,
                    WrapPersistent(this), WrapPersistent(resolver),
                    WrapPersistent(new_value)));

  return promise;
}

ScriptPromise<IDLUndefined> BluetoothRemoteGATTCharacteristic::writeValue(
    ScriptState* script_state,
    base::span<const uint8_t> value,
    ExceptionState& exception_state) {
  return WriteCharacteristicValue(
      script_state, value,
      mojom::blink::WebBluetoothWriteType::kWriteDefaultDeprecated,
      exception_state);
}

ScriptPromise<IDLUndefined>
BluetoothRemoteGATTCharacteristic::writeValueWithResponse(
    ScriptState* script_state,
    base::span<const uint8_t> value,
    ExceptionState& exception_state) {
  return WriteCharacteristicValue(
      script_state, value,
      mojom::blink::WebBluetoothWriteType::kWriteWithResponse, exception_state);
}

ScriptPromise<IDLUndefined>
BluetoothRemoteGATTCharacteristic::writeValueWithoutResponse(
    ScriptState* script_state,
    base::span<const uint8_t> value,
    ExceptionState& exception_state) {
  return WriteCharacteristicValue(
      script_state, value,
      mojom::blink::WebBluetoothWriteType::kWriteWithoutResponse,
      exception_state);
}

void BluetoothRemoteGATTCharacteristic::NotificationsCallback(
    ScriptPromiseResolver<BluetoothRemoteGATTCharacteristic>* resolver,
    bool started,
    mojom::blink::WebBluetoothResult result) {
  if (started) {
    DCHECK_NE(num_in_flight_notification_registrations_, 0U);
    num_in_flight_notification_registrations_--;
  }
  if (!resolver->GetExecutionContext() ||
      resolver->GetExecutionContext()->IsContextDestroyed()) {
    return;
  }

  // If the device is disconnected, reject.
  if (!GetGatt()->RemoveFromActiveAlgorithms(resolver)) {
    resolver->Reject(
        BluetoothError::CreateNotConnectedException(BluetoothOperation::kGATT));
    return;
  }

  // Store the agent as the `resolver`'s execution context may
  // start destruction with promise resolution.
  Agent* agent = resolver->GetExecutionContext()->GetAgent();
  if (result == mojom::blink::WebBluetoothResult::SUCCESS) {
    resolver->Resolve(this);
  } else {
    resolver->Reject(BluetoothError::CreateDOMException(result));
  }

  if (started && !notification_registration_in_progress() &&
      !deferred_value_change_data_.empty()) {
    // Ensure promises are resolved before dispatching events allows them
    // to add listeners.
    agent->event_loop()->PerformMicrotaskCheckpoint();
    // Dispatch deferred characteristicvaluechanged events created during the
    // registration of notifications.
    auto deferred_value_change_data = std::move(deferred_value_change_data_);
    deferred_value_change_data_.clear();
    for (const auto& value_changed_data : deferred_value_change_data) {
      auto prior_value = value_;
      value_ = value_changed_data->dom_data_view;
      DispatchEvent(*value_changed_data->event);
      if (value_changed_data->resolver)
        value_changed_data->resolver->Resolve(value_);
      value_ = prior_value;
    }
  }
}

ScriptPromise<BluetoothRemoteGATTCharacteristic>
BluetoothRemoteGATTCharacteristic::startNotifications(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!GetGatt()->connected() || !GetBluetooth()->IsServiceBound()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNetworkError,
        BluetoothError::CreateNotConnectedExceptionMessage(
            BluetoothOperation::kGATT));
    return EmptyPromise();
  }

  if (!GetGatt()->device()->IsValidCharacteristic(
          characteristic_->instance_id)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        CreateInvalidCharacteristicErrorMessage());
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<BluetoothRemoteGATTCharacteristic>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  GetGatt()->AddToActiveAlgorithms(resolver);

  mojom::blink::WebBluetoothService* service = GetBluetooth()->Service();
  mojo::PendingAssociatedRemote<mojom::blink::WebBluetoothCharacteristicClient>
      client;
  // See https://bit.ly/2S0zRAS for task types.
  receivers_.Add(
      client.InitWithNewEndpointAndPassReceiver(),
      GetExecutionContext()->GetTaskRunner(TaskType::kMiscPlatformAPI));

  num_in_flight_notification_registrations_++;
  service->RemoteCharacteristicStartNotifications(
      characteristic_->instance_id, std::move(client),
      WTF::BindOnce(&BluetoothRemoteGATTCharacteristic::NotificationsCallback,
                    WrapPersistent(this), WrapPersistent(resolver),
                    /*starting=*/true));

  return promise;
}

ScriptPromise<BluetoothRemoteGATTCharacteristic>
BluetoothRemoteGATTCharacteristic::stopNotifications(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!GetGatt()->connected() || !GetBluetooth()->IsServiceBound()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNetworkError,
        BluetoothError::CreateNotConnectedExceptionMessage(
            BluetoothOperation::kGATT));
    return EmptyPromise();
  }

  if (!GetGatt()->device()->IsValidCharacteristic(
          characteristic_->instance_id)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        CreateInvalidCharacteristicErrorMessage());
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<BluetoothRemoteGATTCharacteristic>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  GetGatt()->AddToActiveAlgorithms(resolver);

  mojom::blink::WebBluetoothService* service = GetBluetooth()->Service();
  service->RemoteCharacteristicStopNotifications(
      characteristic_->instance_id,
      WTF::BindOnce(&BluetoothRemoteGATTCharacteristic::NotificationsCallback,
                    WrapPersistent(this), WrapPersistent(resolver),
                    /*starting=*/false,
                    mojom::blink::WebBluetoothResult::SUCCESS));
  return promise;
}

ScriptPromise<BluetoothRemoteGATTDescriptor>
BluetoothRemoteGATTCharacteristic::getDescriptor(
    ScriptState* script_state,
    const V8BluetoothDescriptorUUID* descriptor_uuid,
    ExceptionState& exception_state) {
  String descriptor =
      BluetoothUUID::getDescriptor(descriptor_uuid, exception_state);
  if (exception_state.HadException()) {
    return EmptyPromise();
  }

  if (!GetGatt()->connected() || !GetBluetooth()->IsServiceBound()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNetworkError,
        BluetoothError::CreateNotConnectedExceptionMessage(
            BluetoothOperation::kDescriptorsRetrieval));
    return EmptyPromise();
  }

  if (!GetGatt()->device()->IsValidCharacteristic(
          characteristic_->instance_id)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        CreateInvalidCharacteristicErrorMessage());
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<BluetoothRemoteGATTDescriptor>>(
      script_state, exception_state.GetContext());
  GetGatt()->AddToActiveAlgorithms(resolver);

  mojom::blink::WebBluetoothService* service = GetBluetooth()->Service();
  auto quantity = mojom::blink::WebBluetoothGATTQueryQuantity::SINGLE;
  service->RemoteCharacteristicGetDescriptors(
      characteristic_->instance_id, quantity, descriptor,
      WTF::BindOnce(&BluetoothRemoteGATTCharacteristic::GetDescriptorsCallback,
                    WrapPersistent(this), descriptor,
                    characteristic_->instance_id, quantity,
                    WrapPersistent(resolver)));
  return resolver->Promise();
}

ScriptPromise<IDLSequence<BluetoothRemoteGATTDescriptor>>
BluetoothRemoteGATTCharacteristic::getDescriptors(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  return GetDescriptorsImpl(script_state, exception_state);
}

ScriptPromise<IDLSequence<BluetoothRemoteGATTDescriptor>>
BluetoothRemoteGATTCharacteristic::getDescriptors(
    ScriptState* script_state,
    const V8BluetoothDescriptorUUID* descriptor_uuid,
    ExceptionState& exception_state) {
  String descriptor =
      BluetoothUUID::getDescriptor(descriptor_uuid, exception_state);
  if (exception_state.HadException()) {
    return EmptyPromise();
  }

  return GetDescriptorsImpl(script_state, exception_state, descriptor);
}

ScriptPromise<IDLSequence<BluetoothRemoteGATTDescriptor>>
BluetoothRemoteGATTCharacteristic::GetDescriptorsImpl(
    ScriptState* script_state,
    ExceptionState& exception_state,
    const String& descriptors_uuid) {
  if (!GetGatt()->connected() || !GetBluetooth()->IsServiceBound()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNetworkError,
        BluetoothError::CreateNotConnectedExceptionMessage(
            BluetoothOperation::kDescriptorsRetrieval));
    return EmptyPromise();
  }

  if (!GetGatt()->device()->IsValidCharacteristic(
          characteristic_->instance_id)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        CreateInvalidCharacteristicErrorMessage());
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLSequence<BluetoothRemoteGATTDescriptor>>>(
      script_state, exception_state.GetContext());
  GetGatt()->AddToActiveAlgorithms(resolver);

  mojom::blink::WebBluetoothService* service = GetBluetooth()->Service();
  auto quantity = mojom::blink::WebBluetoothGATTQueryQuantity::MULTIPLE;
  service->RemoteCharacteristicGetDescriptors(
      characteristic_->instance_id, quantity, descriptors_uuid,
      WTF::BindOnce(&BluetoothRemoteGATTCharacteristic::GetDescriptorsCallback,
                    WrapPersistent(this), descriptors_uuid,
                    characteristic_->instance_id, quantity,
                    WrapPersistent(resolver)));
  return resolver->Promise();
}

// Callback that allows us to resolve the promise with a single descriptor
// or with a vector owning the descriptors.
void BluetoothRemoteGATTCharacteristic::GetDescriptorsCallback(
    const String& requested_descriptor_uuid,
    const String& characteristic_instance_id,
    mojom::blink::WebBluetoothGATTQueryQuantity quantity,
    ScriptPromiseResolverBase* resolver,
    mojom::blink::WebBluetoothResult result,
    std::optional<Vector<mojom::blink::WebBluetoothRemoteGATTDescriptorPtr>>
        descriptors) {
  if (!resolver->GetExecutionContext() ||
      resolver->GetExecutionContext()->IsContextDestroyed())
    return;

  // If the device is disconnected, reject.
  if (!service_->device()->gatt()->RemoveFromActiveAlgorithms(resolver)) {
    resolver->Reject(BluetoothError::CreateNotConnectedException(
        BluetoothOperation::kDescriptorsRetrieval));
    return;
  }

  if (result == mojom::blink::WebBluetoothResult::SUCCESS) {
    DCHECK(descriptors);

    if (quantity == mojom::blink::WebBluetoothGATTQueryQuantity::SINGLE) {
      DCHECK_EQ(1u, descriptors->size());
      resolver->DowncastTo<BluetoothRemoteGATTDescriptor>()->Resolve(
          service_->device()->GetOrCreateBluetoothRemoteGATTDescriptor(
              std::move(descriptors.value()[0]), this));
      return;
    }

    HeapVector<Member<BluetoothRemoteGATTDescriptor>> gatt_descriptors;
    gatt_descriptors.ReserveInitialCapacity(descriptors->size());
    for (auto& descriptor : descriptors.value()) {
      gatt_descriptors.push_back(
          service_->device()->GetOrCreateBluetoothRemoteGATTDescriptor(
              std::move(descriptor), this));
    }
    resolver->DowncastTo<IDLSequence<BluetoothRemoteGATTDescriptor>>()->Resolve(
        gatt_descriptors);
  } else {
    if (result == mojom::blink::WebBluetoothResult::DESCRIPTOR_NOT_FOUND) {
      resolver->Reject(BluetoothError::CreateDOMException(
          BluetoothErrorCode::kDescriptorNotFound,
          "No Descriptors matching UUID " + requested_descriptor_uuid +
              " found in Characteristic with UUID " + uuid() + "."));
    } else {
      resolver->Reject(BluetoothError::CreateDOMException(result));
    }
  }
}

String
BluetoothRemoteGATTCharacteristic::CreateInvalidCharacteristicErrorMessage() {
  return "Characteristic with UUID " + uuid() +
         " is no longer valid. Remember to retrieve the characteristic again "
         "after reconnecting.";
}

void BluetoothRemoteGATTCharacteristic::Trace(Visitor* visitor) const {
  visitor->Trace(service_);
  visitor->Trace(properties_);
  visitor->Trace(value_);
  visitor->Trace(device_);
  visitor->Trace(receivers_);
  visitor->Trace(deferred_value_change_data_);

  EventTarget::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

void BluetoothRemoteGATTCharacteristic::DeferredValueChange::Trace(
    Visitor* visitor) const {
  visitor->Trace(event);
  visitor->Trace(dom_data_view);
  if (resolver)
    visitor->Trace(resolver);
}

}  // namespace blink
```