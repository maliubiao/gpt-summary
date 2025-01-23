Response:
Let's break down the thought process for analyzing the provided C++ code for `BluetoothRemoteGATTServer`.

**1. Understanding the Goal:**

The request asks for a breakdown of the `BluetoothRemoteGATTServer.cc` file, focusing on its functionality, relationships with web technologies (JavaScript, HTML, CSS), logical inferences, potential user/programming errors, and debugging insights.

**2. Initial Code Scan and Keyword Recognition:**

My first step is to quickly scan the code for important keywords and structures:

*   `BluetoothRemoteGATTServer`: The core class being analyzed.
*   `connect`, `disconnect`, `getPrimaryService`, `getPrimaryServices`: Public methods, indicating primary functionalities.
*   `mojom::blink::WebBluetooth...`:  Indicates interaction with the Chromium's Mojo interface for inter-process communication (IPC), specifically related to Bluetooth.
*   `ScriptPromise`, `ScriptPromiseResolver`:  Signals asynchronous operations and callbacks, linking to JavaScript Promises.
*   `BluetoothDevice`, `BluetoothRemoteGATTService`:  Related classes, hinting at the object model and relationships.
*   `ExecutionContext`, `TaskRunner`:  Concepts related to Blink's threading model.
*   `DOMException`: Indicates error handling that will be exposed to JavaScript.
*   `Event`:  Suggests event dispatching, likely the `disconnected` event.
*   `active_algorithms_`: A data structure that manages ongoing asynchronous operations.

**3. Deconstructing Functionality - Method by Method:**

Next, I go through each public method and key internal functions, trying to understand their purpose:

*   **Constructor (`BluetoothRemoteGATTServer`)**: Initializes the object, notably setting up the Mojo receiver (`client_receivers_`) and storing a pointer to the `BluetoothDevice`.
*   **`GATTServerDisconnected()`**:  Handles the disconnection event from the underlying Bluetooth stack.
*   **`AddToActiveAlgorithms`, `RemoveFromActiveAlgorithms`**:  Manage a set of active promises, important for handling disconnections gracefully.
*   **`CleanupDisconnectedDeviceAndFireEvent()`**:  Resets the object's state and fires the `disconnected` event.
*   **`DispatchDisconnected()`**:  Triggers the cleanup and event firing if not already disconnected.
*   **`connect()`**: Initiates a connection to the remote GATT server. This involves using the Mojo interface to send a `RemoteServerConnect` request. It returns a JavaScript Promise.
*   **`ConnectCallback()`**:  The callback function executed after the `RemoteServerConnect` request completes. It resolves or rejects the Promise based on the result.
*   **`disconnect()`**:  Initiates disconnection. It clears active promises and uses the Mojo interface to send a `RemoteServerDisconnect` request.
*   **`getPrimaryService()` (single UUID)**: Retrieves a specific primary service. It uses the Mojo interface with `RemoteServerGetPrimaryServices` and a quantity of `SINGLE`.
*   **`getPrimaryServices()` (single UUID)**: Retrieves all primary services matching a specific UUID. It uses the Mojo interface with `RemoteServerGetPrimaryServices` and a quantity of `MULTIPLE`.
*   **`getPrimaryServices()` (no UUID)**: Retrieves all primary services. It uses the Mojo interface with `RemoteServerGetPrimaryServices` and a quantity of `MULTIPLE`.
*   **`GetPrimaryServicesCallback()`**: The callback for the `getPrimaryServices` methods. It receives the results from the Mojo call and resolves or rejects the Promise, potentially creating `BluetoothRemoteGATTService` objects.
*   **`GetPrimaryServicesImpl()`**: A helper function to avoid code duplication in the `getPrimaryServices` methods. It sets up the Mojo call.

**4. Identifying Relationships with Web Technologies:**

As I analyze the methods, I look for connections to web technologies:

*   **JavaScript:**  The use of `ScriptPromise` directly links to JavaScript Promises. The methods are clearly intended to be called from JavaScript. The callback functions are the bridge between the C++ implementation and the JavaScript world.
*   **HTML:**  While the code itself doesn't directly interact with HTML, the Bluetooth functionality it provides is exposed to web pages, allowing JavaScript to interact with Bluetooth devices initiated from HTML elements or scripts.
*   **CSS:** No direct relationship with CSS.

**5. Inferring Logic and Examples:**

Based on the method names and their actions, I can infer the logical flow:

*   **Connect:** The user initiates a connection, leading to a Promise that resolves when the connection is established or rejects if it fails.
*   **Disconnect:** The user disconnects, potentially triggering events and cleanup.
*   **Get Services:** The user requests GATT services, resulting in a Promise that resolves with the requested services or rejects if not found or disconnected.

I then create concrete examples of how these actions would be used in JavaScript, including the expected input and output.

**6. Spotting Potential Errors:**

Thinking about how users or programmers might interact with this API helps identify potential error scenarios:

*   **Calling methods before connecting:**  The code explicitly checks for `connected_` and throws `NetworkError`.
*   **Trying to get non-existent services:** The `SERVICE_NOT_FOUND` result from Mojo is translated into a specific DOMException.
*   **Forgetting to handle Promise rejections:**  A common JavaScript error.
*   **Device disconnecting unexpectedly:**  The `GATTServerDisconnected` method handles this.

**7. Tracing User Actions and Debugging:**

To understand how a user reaches this code, I consider the typical flow of using Web Bluetooth:

1. A website uses the Web Bluetooth API (`navigator.bluetooth.requestDevice`).
2. The user selects a device.
3. The website calls `device.gatt.connect()`, which leads to this C++ code.
4. The website then might call `server.getPrimaryService()` or `server.getPrimaryServices()`.

For debugging, I would look at:

*   JavaScript console logs and errors.
*   Blink's logging infrastructure (potentially searching for "Bluetooth").
*   Network inspection tools to see the underlying Bluetooth communication (if available).
*   Breakpoints in the C++ code itself.

**8. Structuring the Answer:**

Finally, I organize the information into the categories requested by the prompt: functionality, relationship with web technologies, logical inferences, common errors, and debugging. I use clear headings and examples to make the explanation easy to understand.

**Self-Correction/Refinement during the process:**

*   Initially, I might have focused too much on the Mojo details. I needed to shift the focus to how these details translate to the user-facing API and potential issues.
*   I made sure to connect the C++ code back to the corresponding JavaScript API elements.
*   I reviewed the code again to ensure I hadn't missed any key aspects or error conditions.
这是 `blink/renderer/modules/bluetooth/bluetooth_remote_gatt_server.cc` 文件的功能分析。这个文件是 Chromium Blink 引擎中实现 Web Bluetooth API 的一部分，专门负责处理与远程 GATT (Generic Attribute Profile) 服务器的连接和交互。

**主要功能:**

1. **管理与远程 GATT 服务器的连接状态:**
    *   维护与远程蓝牙设备的 GATT 服务器的连接状态 (`connected_` 成员变量)。
    *   提供 `connect()` 方法用于建立与远程 GATT 服务器的连接。
    *   提供 `disconnect()` 方法用于断开与远程 GATT 服务器的连接。
    *   处理来自底层蓝牙系统的断开连接事件 (`GATTServerDisconnected()`)。
    *   在连接断开时清理资源并触发 `disconnected` 事件。

2. **获取远程 GATT 服务:**
    *   提供 `getPrimaryService()` 方法用于获取指定 UUID 的首要（primary）服务。
    *   提供 `getPrimaryServices()` 方法用于获取所有或指定 UUID 的首要服务列表。
    *   内部使用 Mojo (Chromium 的进程间通信机制) 与浏览器进程中的蓝牙服务进行通信，以获取远程服务信息。
    *   使用回调函数 (`GetPrimaryServicesCallback()`) 处理来自 Mojo 服务的响应，并将结果转换为 JavaScript Promise。

3. **异步操作管理:**
    *   使用 `active_algorithms_` 存储当前正在进行的异步操作（主要是 Promise），以便在连接断开时可以正确地拒绝这些 Promise，避免未完成的回调。

4. **与 `BluetoothDevice` 关联:**
    *   `BluetoothRemoteGATTServer` 对象与一个 `BluetoothDevice` 对象关联，代表与之通信的远程蓝牙设备。
    *   通过 `device_` 成员变量访问关联的 `BluetoothDevice` 对象。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个 C++ 文件是 Web Bluetooth API 的底层实现，它直接暴露给 JavaScript 使用。

*   **JavaScript:**
    *   `connect()` 方法对应 JavaScript 中 `BluetoothRemoteGATTServer` 对象的 `connect()` 方法。当 JavaScript 调用 `server.connect()` 时，最终会调用到这里的 C++ 代码。
        ```javascript
        navigator.bluetooth.requestDevice({
          filters: [{ services: ['battery_service'] }]
        })
        .then(device => {
          console.log('连接到设备:', device.name);
          return device.gatt.connect(); // 调用 C++ 的 connect()
        })
        .then(server => {
          console.log('连接到 GATT 服务器:', server);
          // ...
        })
        .catch(error => {
          console.error('连接错误:', error);
        });
        ```
    *   `disconnect()` 方法对应 JavaScript 中 `BluetoothRemoteGATTServer` 对象的 `disconnect()` 方法。
        ```javascript
        if (server && server.connected) {
          server.disconnect(); // 调用 C++ 的 disconnect()
          console.log('已断开连接');
        }
        ```
    *   `getPrimaryService()` 和 `getPrimaryServices()` 方法对应 JavaScript 中 `BluetoothRemoteGATTServer` 对象的同名方法。这些方法返回 JavaScript Promise，最终会通过 C++ 代码调用底层的蓝牙操作，并将结果返回给 JavaScript。
        ```javascript
        server.getPrimaryService('battery_service') // 调用 C++ 的 getPrimaryService()
          .then(service => {
            console.log('找到服务:', service);
          })
          .catch(error => {
            console.error('获取服务失败:', error);
          });

        server.getPrimaryServices() // 调用 C++ 的 getPrimaryServices()
          .then(services => {
            console.log('找到所有首要服务:', services);
          });
        ```
    *   `disconnected` 事件：当 C++ 代码检测到连接断开时，会触发一个事件，这个事件可以在 JavaScript 中监听。
        ```javascript
        navigator.bluetooth.requestDevice({
          filters: [{ services: ['battery_service'] }]
        })
        .then(device => {
          device.addEventListener('gattserverdisconnected', () => {
            console.log('GATT 服务器断开连接');
          });
          return device.gatt.connect();
        });
        ```

*   **HTML:**  HTML 本身不直接与这个 C++ 文件交互。HTML 提供了用户交互的界面，例如按钮，用户点击按钮后，JavaScript 代码可能会调用 Web Bluetooth API 中的方法，从而间接地触发这里的 C++ 代码执行。

*   **CSS:** CSS 负责页面的样式，与这个 C++ 文件没有直接关系。

**逻辑推理及假设输入与输出:**

**假设输入 (connect()):**

1. JavaScript 代码调用 `device.gatt.connect()`。
2. 相关的 `BluetoothDevice` 对象已经通过 `navigator.bluetooth.requestDevice()` 获取。
3. 设备支持 GATT 服务。

**输出 (connect()):**

*   **成功:** 如果连接成功，`connect()` 方法返回的 JavaScript Promise 将会 resolve，并带有一个 `BluetoothRemoteGATTServer` 对象。`connected_` 成员变量会被设置为 `true`。
*   **失败:** 如果连接失败（例如，设备不可达，连接被拒绝），Promise 将会 reject，并带有一个 `DOMException` 对象，包含错误信息。

**假设输入 (getPrimaryService('some-uuid')):**

1. JavaScript 代码调用 `server.getPrimaryService('some-uuid')`，其中 `'some-uuid'` 是一个 GATT 服务 UUID。
2. `BluetoothRemoteGATTServer` 对象处于已连接状态 (`connected_` 为 `true`)。

**输出 (getPrimaryService('some-uuid')):**

*   **成功:** 如果找到匹配 UUID 的服务，Promise 将会 resolve，并带有一个 `BluetoothRemoteGATTService` 对象。
*   **失败 (服务未找到):** 如果没有找到匹配 UUID 的服务，Promise 将会 reject，并带有一个 `DOMException` 对象，错误码为 `NotFoundError` (或类似表示服务未找到的错误)。
*   **失败 (连接断开):** 如果在请求过程中连接断开，Promise 将会 reject，并带有一个表示网络错误的 `DOMException`。

**用户或编程常见的使用错误举例说明:**

1. **在未连接的情况下调用 `getPrimaryService` 或 `getPrimaryServices`:**
    *   **错误:** 用户 JavaScript 代码在调用 `server.connect()` 的 Promise resolve 之前，就尝试调用 `server.getPrimaryService()`。
    *   **后果:** C++ 代码会检查 `connected_` 状态，如果未连接，会抛出一个 `NetworkError` 类型的 `DOMException`，导致 JavaScript Promise reject。
    *   **JavaScript 示例:**
        ```javascript
        navigator.bluetooth.requestDevice({
          filters: [{ services: ['battery_service'] }]
        })
        .then(device => {
          const serverPromise = device.gatt.connect();
          serverPromise.then(server => {
            // 正确的做法是在连接成功后获取服务
            server.getPrimaryService('battery_service').then(/* ... */);
          });
          // 错误的做法：在连接完成前就尝试获取服务
          device.gatt.getPrimaryService('battery_service')
            .catch(error => console.error("错误：未连接时尝试获取服务", error));
        });
        ```

2. **忘记处理 Promise 的 rejection:**
    *   **错误:** 用户 JavaScript 代码调用了返回 Promise 的方法（如 `connect`, `getPrimaryService`），但没有提供 `.catch()` 来处理 Promise 被拒绝的情况。
    *   **后果:** 如果操作失败，未处理的 Promise rejection 可能会导致 JavaScript 运行时错误或未知的行为。
    *   **JavaScript 示例:**
        ```javascript
        navigator.bluetooth.requestDevice({
          filters: [{ services: ['unknown_service'] }] // 故意使用不存在的服务
        })
        .then(device => device.gatt.connect())
        .then(server => server.getPrimaryService('unknown_service'))
        // 缺少 .catch() 来处理服务未找到的情况
        .then(service => console.log("找到服务", service));
        ```

3. **假设设备总是连接的:**
    *   **错误:** 用户 JavaScript 代码没有考虑到蓝牙连接可能会意外断开的情况。
    *   **后果:** 如果在操作过程中设备断开连接，相关的 Promise 会被拒绝，如果用户没有监听 `gattserverdisconnected` 事件或妥善处理 Promise rejection，可能会导致程序出错。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在网页上触发了与蓝牙相关的操作:**  例如，点击一个 "连接蓝牙设备" 的按钮。
2. **JavaScript 代码调用 `navigator.bluetooth.requestDevice()`:**  这会触发浏览器显示蓝牙设备选择器。
3. **用户在选择器中选择了一个蓝牙设备。**
4. **JavaScript 代码获取到 `BluetoothDevice` 对象。**
5. **JavaScript 代码调用 `device.gatt.connect()`:**  这会触发 `bluetooth_remote_gatt_server.cc` 中的 `BluetoothRemoteGATTServer::connect()` 方法。
    *   **调试线索:** 可以在 JavaScript 代码中设置断点，查看 `device` 对象是否存在，以及 `device.gatt` 是否为 `BluetoothRemoteGATTServer` 的实例。
6. **如果 `connect()` 成功，JavaScript 代码会获得 `BluetoothRemoteGATTServer` 对象。**
7. **JavaScript 代码调用 `server.getPrimaryService()` 或 `server.getPrimaryServices()`:** 这会触发 `bluetooth_remote_gatt_server.cc` 中对应的 `getPrimaryService()` 或 `getPrimaryServices()` 方法。
    *   **调试线索:** 可以在 JavaScript 代码中设置断点，查看传递给 `getPrimaryService()` 的 UUID 是否正确。
8. **C++ 代码通过 Mojo 与浏览器进程中的蓝牙服务通信，请求获取远程 GATT 服务信息。**
    *   **调试线索:** 可以使用 Chromium 的内部日志工具（例如 `chrome://webrtc-internals` 或命令行标志）来查看 Mojo 消息的传递情况。也可以在 C++ 代码中添加日志输出。
9. **浏览器进程中的蓝牙服务与操作系统或蓝牙硬件进行交互，获取服务信息。**
10. **服务信息通过 Mojo 返回到渲染进程的 `BluetoothRemoteGATTServer` 对象。**
11. **`GetPrimaryServicesCallback()` 方法被调用，将服务信息转换为 `BluetoothRemoteGATTService` 对象，并通过 Promise resolve 返回给 JavaScript。**

作为调试线索，以下是一些可以关注的点：

*   **JavaScript 错误信息:** 查看浏览器控制台是否有任何 JavaScript 错误或 Promise rejection 的信息。
*   **Web Bluetooth API 的使用是否正确:**  检查 JavaScript 代码中调用 Web Bluetooth API 的顺序和参数是否正确。
*   **蓝牙设备状态:** 确认蓝牙设备是否已开启，并且在范围内。
*   **Mojo 通信:** 使用 Chromium 的内部工具查看 Mojo 消息是否正常发送和接收。
*   **C++ 代码断点和日志:** 在 `bluetooth_remote_gatt_server.cc` 中设置断点或添加日志输出，可以跟踪代码的执行流程和变量的值。例如，可以在 `ConnectCallback` 和 `GetPrimaryServicesCallback` 中添加日志，查看连接和获取服务的结果。
*   **设备端蓝牙日志:** 如果可以访问蓝牙设备的日志，可以查看设备端的蓝牙通信情况，以判断问题是否出在设备端。

总而言之，`bluetooth_remote_gatt_server.cc` 是 Web Bluetooth API 中至关重要的一个环节，它负责管理与远程蓝牙 GATT 服务器的连接和数据交互，并将底层的蓝牙操作抽象成 JavaScript 可以使用的 API。理解其功能和与 JavaScript 的关系，对于调试 Web Bluetooth 应用至关重要。

### 提示词
```
这是目录为blink/renderer/modules/bluetooth/bluetooth_remote_gatt_server.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/bluetooth/bluetooth_remote_gatt_server.h"

#include <utility>

#include "mojo/public/cpp/bindings/associated_receiver_set.h"
#include "mojo/public/cpp/bindings/pending_associated_remote.h"
#include "third_party/blink/public/mojom/bluetooth/web_bluetooth.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/callback_promise_adapter.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth_device.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth_error.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth_remote_gatt_service.h"
#include "third_party/blink/renderer/modules/bluetooth/bluetooth_uuid.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

BluetoothRemoteGATTServer::BluetoothRemoteGATTServer(ExecutionContext* context,
                                                     BluetoothDevice* device)
    :  // See https://bit.ly/2S0zRAS for task types.
      task_runner_(context->GetTaskRunner(TaskType::kMiscPlatformAPI)),
      client_receivers_(this, context),
      device_(device),
      connected_(false) {}

void BluetoothRemoteGATTServer::GATTServerDisconnected() {
  DispatchDisconnected();
}

void BluetoothRemoteGATTServer::AddToActiveAlgorithms(
    ScriptPromiseResolverBase* resolver) {
  auto result = active_algorithms_.insert(resolver);
  CHECK(result.is_new_entry);
}

bool BluetoothRemoteGATTServer::RemoveFromActiveAlgorithms(
    ScriptPromiseResolverBase* resolver) {
  if (!active_algorithms_.Contains(resolver)) {
    return false;
  }
  active_algorithms_.erase(resolver);
  return true;
}

void BluetoothRemoteGATTServer::CleanupDisconnectedDeviceAndFireEvent() {
  DCHECK(connected_);
  connected_ = false;
  active_algorithms_.clear();
  device_->ClearAttributeInstanceMapAndFireEvent();
}

void BluetoothRemoteGATTServer::DispatchDisconnected() {
  if (!connected_) {
    return;
  }
  CleanupDisconnectedDeviceAndFireEvent();
}

void BluetoothRemoteGATTServer::Trace(Visitor* visitor) const {
  visitor->Trace(client_receivers_);
  visitor->Trace(active_algorithms_);
  visitor->Trace(device_);
  ScriptWrappable::Trace(visitor);
}

void BluetoothRemoteGATTServer::ConnectCallback(
    ScriptPromiseResolver<BluetoothRemoteGATTServer>* resolver,
    mojom::blink::WebBluetoothResult result) {
  if (!resolver->GetExecutionContext() ||
      resolver->GetExecutionContext()->IsContextDestroyed())
    return;

  if (result == mojom::blink::WebBluetoothResult::SUCCESS) {
    connected_ = true;
    resolver->Resolve(this);
  } else {
    resolver->Reject(BluetoothError::CreateDOMException(result));
  }
}

ScriptPromise<BluetoothRemoteGATTServer> BluetoothRemoteGATTServer::connect(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<BluetoothRemoteGATTServer>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  if (!device_->GetBluetooth()->IsServiceBound()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNetworkError,
        BluetoothError::CreateNotConnectedExceptionMessage(
            BluetoothOperation::kServicesRetrieval));
    return EmptyPromise();
  }

  mojom::blink::WebBluetoothService* service =
      device_->GetBluetooth()->Service();
  mojo::PendingAssociatedRemote<mojom::blink::WebBluetoothServerClient> client;
  client_receivers_.Add(client.InitWithNewEndpointAndPassReceiver(),
                        task_runner_);

  service->RemoteServerConnect(
      device_->GetDevice()->id, std::move(client),
      WTF::BindOnce(&BluetoothRemoteGATTServer::ConnectCallback,
                    WrapPersistent(this), WrapPersistent(resolver)));

  return promise;
}

void BluetoothRemoteGATTServer::disconnect(ScriptState* script_state,
                                           ExceptionState& exception_state) {
  if (!connected_)
    return;

  if (!device_->GetBluetooth()->IsServiceBound()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNetworkError,
        BluetoothError::CreateNotConnectedExceptionMessage(
            BluetoothOperation::kServicesRetrieval));
    return;
  }

  CleanupDisconnectedDeviceAndFireEvent();
  client_receivers_.Clear();
  mojom::blink::WebBluetoothService* service =
      device_->GetBluetooth()->Service();
  service->RemoteServerDisconnect(device_->GetDevice()->id);
}

// Callback that allows us to resolve the promise with a single service or
// with a vector owning the services.
void BluetoothRemoteGATTServer::GetPrimaryServicesCallback(
    const String& requested_service_uuid,
    mojom::blink::WebBluetoothGATTQueryQuantity quantity,
    ScriptPromiseResolverBase* resolver,
    mojom::blink::WebBluetoothResult result,
    std::optional<Vector<mojom::blink::WebBluetoothRemoteGATTServicePtr>>
        services) {
  if (!resolver->GetExecutionContext() ||
      resolver->GetExecutionContext()->IsContextDestroyed())
    return;

  // If the device is disconnected, reject.
  if (!RemoveFromActiveAlgorithms(resolver)) {
    resolver->Reject(BluetoothError::CreateNotConnectedException(
        BluetoothOperation::kServicesRetrieval));
    return;
  }

  if (result == mojom::blink::WebBluetoothResult::SUCCESS) {
    DCHECK(services);

    if (quantity == mojom::blink::WebBluetoothGATTQueryQuantity::SINGLE) {
      DCHECK_EQ(1u, services->size());
      resolver->DowncastTo<BluetoothRemoteGATTService>()->Resolve(
          device_->GetOrCreateRemoteGATTService(std::move(services.value()[0]),
                                                true /* isPrimary */,
                                                device_->id()));
      return;
    }

    HeapVector<Member<BluetoothRemoteGATTService>> gatt_services;
    gatt_services.ReserveInitialCapacity(services->size());

    for (auto& service : services.value()) {
      gatt_services.push_back(device_->GetOrCreateRemoteGATTService(
          std::move(service), true /* isPrimary */, device_->id()));
    }
    resolver->DowncastTo<IDLSequence<BluetoothRemoteGATTService>>()->Resolve(
        gatt_services);
  } else {
    if (result == mojom::blink::WebBluetoothResult::SERVICE_NOT_FOUND) {
      resolver->Reject(BluetoothError::CreateDOMException(
          BluetoothErrorCode::kServiceNotFound, "No Services matching UUID " +
                                                    requested_service_uuid +
                                                    " found in Device."));
    } else {
      resolver->Reject(BluetoothError::CreateDOMException(result));
    }
  }
}

ScriptPromise<BluetoothRemoteGATTService>
BluetoothRemoteGATTServer::getPrimaryService(
    ScriptState* script_state,
    const V8BluetoothServiceUUID* service,
    ExceptionState& exception_state) {
  String service_uuid = BluetoothUUID::getService(service, exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  if (!connected_ || !device_->GetBluetooth()->IsServiceBound()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNetworkError,
        BluetoothError::CreateNotConnectedExceptionMessage(
            BluetoothOperation::kServicesRetrieval));
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<BluetoothRemoteGATTService>>(
          script_state, exception_state.GetContext());
  GetPrimaryServicesImpl(resolver,
                         mojom::blink::WebBluetoothGATTQueryQuantity::SINGLE,
                         service_uuid);
  return resolver->Promise();
}

ScriptPromise<IDLSequence<BluetoothRemoteGATTService>>
BluetoothRemoteGATTServer::getPrimaryServices(
    ScriptState* script_state,
    const V8BluetoothServiceUUID* service,
    ExceptionState& exception_state) {
  String service_uuid = BluetoothUUID::getService(service, exception_state);
  if (exception_state.HadException())
    return ScriptPromise<IDLSequence<BluetoothRemoteGATTService>>();

  if (!connected_ || !device_->GetBluetooth()->IsServiceBound()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNetworkError,
        BluetoothError::CreateNotConnectedExceptionMessage(
            BluetoothOperation::kServicesRetrieval));
    return ScriptPromise<IDLSequence<BluetoothRemoteGATTService>>();
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLSequence<BluetoothRemoteGATTService>>>(
      script_state, exception_state.GetContext());
  GetPrimaryServicesImpl(resolver,
                         mojom::blink::WebBluetoothGATTQueryQuantity::MULTIPLE,
                         service_uuid);
  return resolver->Promise();
}

ScriptPromise<IDLSequence<BluetoothRemoteGATTService>>
BluetoothRemoteGATTServer::getPrimaryServices(ScriptState* script_state,
                                              ExceptionState& exception_state) {
  if (!connected_ || !device_->GetBluetooth()->IsServiceBound()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNetworkError,
        BluetoothError::CreateNotConnectedExceptionMessage(
            BluetoothOperation::kServicesRetrieval));
    return ScriptPromise<IDLSequence<BluetoothRemoteGATTService>>();
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLSequence<BluetoothRemoteGATTService>>>(
      script_state, exception_state.GetContext());
  GetPrimaryServicesImpl(resolver,
                         mojom::blink::WebBluetoothGATTQueryQuantity::MULTIPLE);
  return resolver->Promise();
}

void BluetoothRemoteGATTServer::GetPrimaryServicesImpl(
    ScriptPromiseResolverBase* resolver,
    mojom::blink::WebBluetoothGATTQueryQuantity quantity,
    String services_uuid) {

  AddToActiveAlgorithms(resolver);

  mojom::blink::WebBluetoothService* service =
      device_->GetBluetooth()->Service();
  service->RemoteServerGetPrimaryServices(
      device_->GetDevice()->id, quantity, services_uuid,
      WTF::BindOnce(&BluetoothRemoteGATTServer::GetPrimaryServicesCallback,
                    WrapPersistent(this), services_uuid, quantity,
                    WrapPersistent(resolver)));
}

}  // namespace blink
```