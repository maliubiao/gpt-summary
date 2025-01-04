Response:
The user wants a summary of the functionality of the provided C++ code snippet from `usb_device.cc`. This is part 2 of 2, so I need to synthesize the information from the previous part (which I don't have access to). However, I can deduce the overall purpose by looking at the function names and the context.

Here's a breakdown of the thought process to analyze this code snippet:

1. **Identify the Core Class:** The code is within the `USBDevice` class in the `blink` namespace. This immediately suggests it's responsible for representing and managing a USB device within the Chromium rendering engine.

2. **Analyze Individual Methods:** Go through each method and understand its purpose based on its name and parameters.

    * **`SetEndpointsForInterface`:** This method manages which endpoints (communication channels) are active for a given interface. It updates internal bit vectors (`in_endpoints_`, `out_endpoints_`). It takes a `set` boolean to indicate whether to enable or disable the endpoints.

    * **`AsyncOpen`:** Handles the asynchronous process of opening a USB device. It receives a `result` indicating success or failure. It manages the open state and uses `ScriptPromiseResolver` for asynchronous JavaScript interaction. It handles specific error cases like `ACCESS_DENIED`.

    * **`AsyncClose`:** Handles asynchronously closing the device. It updates the open state.

    * **`AsyncForget`:**  Presumably handles forgetting a device, though the current implementation simply resolves the promise.

    * **`OnDeviceOpenedOrClosed`:** Updates the internal `opened_` flag and resets interface-related state when a device is closed.

    * **`AsyncSelectConfiguration`:**  Handles the asynchronous selection of a USB configuration. It receives a success flag and updates the internal configuration index.

    * **`OnConfigurationSelected`:**  Updates the internal state after a configuration is selected, including resizing and resetting interface-related data structures.

    * **`AsyncClaimInterface`:** Handles claiming exclusive access to a specific interface. It handles success, protected class errors, and general failures.

    * **`AsyncReleaseInterface`:** Handles releasing a previously claimed interface.

    * **`OnInterfaceClaimedOrUnclaimed`:** Updates the `claimed_interfaces_` status and calls `SetEndpointsForInterface`.

    * **`AsyncSelectAlternateInterface`:** Handles selecting an alternate setting for an interface.

    * **`AsyncControlTransferIn` and `AsyncControlTransferOut`:** Handle control transfers, which are used for device configuration and control. They deal with data transfer and status reporting.

    * **`AsyncClearHalt`:**  Handles clearing a stall condition on an endpoint.

    * **`AsyncTransferIn` and `AsyncTransferOut`:** Handle bulk transfers, typically used for data.

    * **`AsyncIsochronousTransferIn` and `AsyncIsochronousTransferOut`:** Handle isochronous transfers, used for time-sensitive data like audio or video. These methods involve processing packet-level status.

    * **`AsyncReset`:** Handles resetting the USB device.

    * **`OnConnectionError`:**  Handles the event of the USB device being disconnected. It updates the state and rejects pending promises with a "NotFoundError".

    * **`MarkRequestComplete`:** Removes a completed request from the `device_requests_` map.

3. **Identify Relationships with Web Technologies:** Look for interactions with JavaScript, HTML, and CSS concepts.

    * **JavaScript:**  The use of `ScriptPromiseResolver` indicates this code directly interacts with JavaScript Promises, a fundamental asynchronous programming construct in JavaScript. The methods like `Resolve()` and `RejectWith...()` are key to this interaction. The data structures being passed around (like `USBInTransferResult`, `USBOutTransferResult`) are likely represented as JavaScript objects.

    * **HTML:**  While not directly evident in this snippet, the WebUSB API allows JavaScript in a web page (HTML) to interact with USB devices. This C++ code is the backend implementation that makes that possible. User interaction within the HTML page (like clicking a "connect" button) would trigger JavaScript calls that eventually reach this C++ code.

    * **CSS:**  No direct relationship with CSS is apparent in this code. CSS is for styling, and this code deals with device communication logic.

4. **Infer Logic and Data Flow:**  Understand how the methods interact and manage the state of the USB device. The `opened_`, `claimed_interfaces_`, `selected_alternate_indices_`, `in_endpoints_`, and `out_endpoints_` members are crucial for tracking the device's current status. The asynchronous nature of many operations is managed using Promises.

5. **Identify Potential Errors:**  Look for error handling and potential issues users or developers might encounter. Access denied, protected interface classes, and network errors are explicitly handled. Incorrect usage of the WebUSB API in JavaScript could lead to these errors.

6. **Trace User Actions:** Imagine the steps a user would take to trigger this code. Granting USB permissions, selecting a device, opening it, claiming interfaces, performing transfers, and finally closing or forgetting the device are all potential user actions.

7. **Synthesize the Summary:** Combine the observations into a concise description of the file's purpose. Emphasize its role in implementing the WebUSB API within the Chromium browser.
好的，这是对 `blink/renderer/modules/webusb/usb_device.cc` 文件代码片段功能的归纳：

**功能归纳：**

这段代码片段主要负责处理 `USBDevice` 对象在不同生命周期阶段和操作请求完成时的异步回调和状态更新。它维护了 USB 设备的连接状态、接口声明状态、配置选择状态、以及端点信息，并在操作成功或失败时更新这些状态并通知 JavaScript 层。

**具体功能点：**

* **管理端点启用状态：** `SetEndpointsForInterface` 方法根据接口的端点信息，更新内部的 `in_endpoints_` 和 `out_endpoints_` 位向量，用于记录当前接口启用的输入和输出端点。
* **处理设备打开操作：** `AsyncOpen` 方法处理异步打开设备的结果。成功则更新设备为打开状态，失败则根据错误类型（如权限拒绝）通知 JavaScript 层。
* **处理设备关闭操作：** `AsyncClose` 方法处理异步关闭设备的操作，更新设备为关闭状态。
* **处理设备遗忘操作：** `AsyncForget` 方法目前简单地 resolve promise，表示异步遗忘操作完成。
* **管理设备打开/关闭状态：** `OnDeviceOpenedOrClosed` 方法更新设备的 `opened_` 状态，并在设备关闭时重置接口和端点相关的内部状态。
* **处理配置选择操作：** `AsyncSelectConfiguration` 和 `OnConfigurationSelected` 方法处理异步选择设备配置的操作，更新内部的配置索引和接口信息。
* **处理接口声明操作：** `AsyncClaimInterface` 方法处理异步声明接口的操作，根据结果更新接口声明状态，并处理诸如受保护接口类的错误。
* **处理接口释放操作：** `AsyncReleaseInterface` 方法处理异步释放接口的操作，更新接口声明状态。
* **管理接口声明/释放状态：** `OnInterfaceClaimedOrUnclaimed` 方法更新接口的声明状态，并调用 `SetEndpointsForInterface` 更新端点信息。
* **处理选择备用接口操作：** `AsyncSelectAlternateInterface` 方法处理异步选择备用接口的操作，更新相应的状态。
* **处理控制传输：** `AsyncControlTransferIn` 和 `AsyncControlTransferOut` 方法处理控制传输的结果，将状态和数据传递给 JavaScript 层。
* **处理清除端点 Halt 状态：** `AsyncClearHalt` 方法处理清除端点 Halt 状态的结果。
* **处理批量传输：** `AsyncTransferIn` 和 `AsyncTransferOut` 方法处理批量传输的结果，将状态和数据传递给 JavaScript 层。
* **处理同步传输：** `AsyncIsochronousTransferIn` 和 `AsyncIsochronousTransferOut` 方法处理同步传输的结果，包括处理每个数据包的状态。
* **处理设备重置操作：** `AsyncReset` 方法处理异步重置设备的操作。
* **处理连接错误：** `OnConnectionError` 方法在设备连接断开时被调用，重置设备状态并拒绝所有待处理的 Promise。
* **标记请求完成：** `MarkRequestComplete` 方法从待处理的请求列表中移除已完成的请求。

**与 JavaScript, HTML, CSS 的关系：**

这段 C++ 代码是 WebUSB API 在 Chromium Blink 渲染引擎中的一部分实现。它负责处理底层 USB 设备操作，并通过回调和 Promise 与上层的 JavaScript 代码进行通信。

* **JavaScript:**
    * JavaScript 代码会调用 WebUSB API 的方法（例如 `usbDevice.open()`, `usbDevice.claimInterface()`, `usbDevice.controlTransferIn()` 等）。
    * 这些 JavaScript 方法的调用会触发 Blink 渲染引擎中相应的 C++ 代码的执行。
    * 这段代码中的 `ScriptPromiseResolver` 用于将 C++ 中的异步操作结果传递回 JavaScript 的 Promise 对象。例如，`AsyncOpen` 方法在设备打开成功后调用 `resolver->Resolve()`，或者在失败后调用 `resolver->RejectWithSecurityError()`，这些都会影响 JavaScript Promise 的状态和结果。
    * `USBInTransferResult` 和 `USBOutTransferResult` 等数据结构会被转换为 JavaScript 可以理解的对象，以便在 JavaScript 中访问 USB 设备传输的数据和状态。
* **HTML:**
    * HTML 页面通过 `<script>` 标签引入 JavaScript 代码。
    * 用户在 HTML 页面上的交互（例如点击按钮触发连接 USB 设备的事件）会调用相应的 JavaScript 函数，最终触发此处 C++ 代码的执行。
* **CSS:**
    * CSS 主要负责网页的样式，与这段处理 USB 设备逻辑的 C++ 代码没有直接关系。

**逻辑推理、假设输入与输出：**

**假设输入：** 用户在 JavaScript 中调用 `usbDevice.open()` 尝试打开一个 USB 设备。

**C++ 代码执行流程 (部分):**

1. JavaScript 调用会触发 `USBDevice::Open()` (在 Part 1 中)。
2. `USBDevice::Open()` 会向底层发送打开设备的请求。
3. 底层操作完成后，会将结果通过 `device::mojom::blink::UsbOpenDeviceResultPtr` 传递给 `USBDevice::AsyncOpen`。

**`AsyncOpen` 方法的逻辑推理：**

* **输入：** `ScriptPromiseResolver<IDLUndefined>* resolver` (与 JavaScript Promise 关联)，`device::mojom::blink::UsbOpenDeviceResultPtr result` (包含打开操作的结果)。
* **条件判断：** `result->is_success()` 检查打开操作是否成功。
    * **如果成功：**
        * 调用 `OnDeviceOpenedOrClosed(true)` 更新设备状态。
        * 调用 `resolver->Resolve()`，将 JavaScript Promise 置为 resolved 状态。
    * **如果失败：**
        * `result->get_error()` 获取错误类型。
        * **如果错误是 `UsbOpenDeviceError::ACCESS_DENIED`：**
            * 调用 `OnDeviceOpenedOrClosed(false)` 更新设备状态。
            * 调用 `resolver->RejectWithSecurityError()`，将 JavaScript Promise 置为 rejected 状态，并附带相应的错误信息。
        * **如果错误是 `UsbOpenDeviceError::ALREADY_OPEN`：**
            * 代码执行到 `NOTREACHED()`，因为 `USBDevice` 应该在内部防止重复打开。
* **输出：** 无直接的函数返回值，但通过 `resolver` 对象改变了 JavaScript Promise 的状态。

**用户或编程常见的使用错误：**

* **未获得用户授权就尝试打开设备：** 用户在浏览器中需要明确授权网站访问 USB 设备。如果 JavaScript 代码直接尝试打开设备而没有进行授权请求，`AsyncOpen` 方法可能会收到 `UsbOpenDeviceError::ACCESS_DENIED` 错误，导致 Promise 被 reject。
* **尝试声明受保护的接口类：** 某些 USB 接口类被操作系统或浏览器保护，不允许网页直接访问。如果 JavaScript 尝试声明这类接口，`AsyncClaimInterface` 方法会收到 `UsbClaimInterfaceResult::kProtectedClass`，并在控制台输出警告信息，同时 reject Promise。
* **在设备未打开的情况下进行操作：**  例如，在调用 `usbDevice.open()` 成功之前，就尝试进行数据传输或声明接口，会导致操作失败。
* **在接口未声明的情况下尝试进行接口相关的传输：** 必须先成功调用 `claimInterface()` 才能进行该接口上的数据传输。
* **在设备断开连接后，JavaScript 代码仍然尝试操作该设备：** `OnConnectionError` 会被调用，并拒绝所有待处理的 Promise，JavaScript 代码需要捕获这些错误并进行相应的处理。

**用户操作到达这里的步骤 (作为调试线索)：**

1. **用户访问包含 WebUSB 功能的网页：** 用户在浏览器中打开一个使用了 WebUSB API 的网页。
2. **网页 JavaScript 代码请求访问 USB 设备：** 网页上的 JavaScript 代码可能调用 `navigator.usb.requestDevice()` 来请求用户选择 USB 设备。
3. **用户选择 USB 设备并授权：** 用户在浏览器弹出的设备选择器中选择一个 USB 设备并授予网站访问权限。
4. **JavaScript 代码获取 `USBDevice` 对象：**  `navigator.usb.requestDevice()` 成功后，会返回一个 `USBDevice` 对象给 JavaScript 代码。
5. **JavaScript 代码调用 `usbDevice.open()`：** 网页 JavaScript 代码调用 `usbDevice.open()` 方法尝试打开选定的 USB 设备。
6. **浏览器进程处理 `open()` 请求：** 浏览器进程接收到 JavaScript 的请求，并与操作系统进行交互，尝试打开 USB 设备。
7. **Blink 渲染引擎中的 C++ 代码被调用：** 浏览器进程将打开设备的结果传递给 Blink 渲染引擎中的 `USBDevice::AsyncOpen` 方法。
8. **`AsyncOpen` 方法处理结果并更新状态：** `AsyncOpen` 方法根据设备打开的结果（成功或失败），更新 `USBDevice` 对象的内部状态，并通过 Promise 将结果传递回 JavaScript 代码。

通过查看相关日志、断点调试 C++ 代码以及 JavaScript 代码的 Promise 状态，可以追踪用户操作是如何一步步到达 `usb_device.cc` 文件的。特别关注网络面板中 WebUSB 相关的请求和响应，以及控制台输出的错误信息。

Prompt: 
```
这是目录为blink/renderer/modules/webusb/usb_device.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
 endpoint->endpoint_number;
    if (endpoint_number == 0 || endpoint_number >= kEndpointsBitsNumber)
      continue;  // Ignore endpoints with invalid indices.
    auto& bit_vector = endpoint->direction == UsbTransferDirection::INBOUND
                           ? in_endpoints_
                           : out_endpoints_;
    if (set)
      bit_vector.set(endpoint_number - 1);
    else
      bit_vector.reset(endpoint_number - 1);
  }
}

void USBDevice::AsyncOpen(ScriptPromiseResolver<IDLUndefined>* resolver,
                          device::mojom::blink::UsbOpenDeviceResultPtr result) {
  MarkRequestComplete(resolver);

  if (result->is_success()) {
    OnDeviceOpenedOrClosed(/*opened=*/true);
    resolver->Resolve();
    return;
  }

  DCHECK(result->is_error());
  switch (result->get_error()) {
    case UsbOpenDeviceError::ACCESS_DENIED:
      OnDeviceOpenedOrClosed(false /* not opened */);
      resolver->RejectWithSecurityError(kAccessDeniedError, kAccessDeniedError);
      break;
    case UsbOpenDeviceError::ALREADY_OPEN:
      // This class keeps track of open state and won't try to open a device
      // that is already open.
      NOTREACHED();
  }
}

void USBDevice::AsyncClose(ScriptPromiseResolver<IDLUndefined>* resolver) {
  MarkRequestComplete(resolver);

  OnDeviceOpenedOrClosed(false /* closed */);
  resolver->Resolve();
}

void USBDevice::AsyncForget(ScriptPromiseResolver<IDLUndefined>* resolver) {
  resolver->Resolve();
}

void USBDevice::OnDeviceOpenedOrClosed(bool opened) {
  opened_ = opened;
  if (!opened_) {
    claimed_interfaces_.Fill(false);
    selected_alternate_indices_.Fill(0);
    in_endpoints_.reset();
    out_endpoints_.reset();
  }
  device_state_change_in_progress_ = false;
}

void USBDevice::AsyncSelectConfiguration(
    wtf_size_t configuration_index,
    ScriptPromiseResolver<IDLUndefined>* resolver,
    bool success) {
  MarkRequestComplete(resolver);

  OnConfigurationSelected(success, configuration_index);
  if (success) {
    resolver->Resolve();
  } else {
    resolver->RejectWithDOMException(DOMExceptionCode::kNetworkError,
                                     "Unable to set device configuration.");
  }
}

void USBDevice::OnConfigurationSelected(bool success,
                                        wtf_size_t configuration_index) {
  if (success) {
    configuration_index_ = configuration_index;
    wtf_size_t num_interfaces =
        Info().configurations[configuration_index_]->interfaces.size();
    claimed_interfaces_.resize(num_interfaces);
    claimed_interfaces_.Fill(false);
    interface_state_change_in_progress_.resize(num_interfaces);
    interface_state_change_in_progress_.Fill(false);
    selected_alternate_indices_.resize(num_interfaces);
    selected_alternate_indices_.Fill(0);
    in_endpoints_.reset();
    out_endpoints_.reset();
  }
  device_state_change_in_progress_ = false;
}

void USBDevice::AsyncClaimInterface(
    wtf_size_t interface_index,
    ScriptPromiseResolver<IDLUndefined>* resolver,
    device::mojom::blink::UsbClaimInterfaceResult result) {
  MarkRequestComplete(resolver);

  OnInterfaceClaimedOrUnclaimed(result == UsbClaimInterfaceResult::kSuccess,
                                interface_index);

  switch (result) {
    case UsbClaimInterfaceResult::kSuccess:
      resolver->Resolve();
      break;
    case UsbClaimInterfaceResult::kProtectedClass:
      GetExecutionContext()->AddConsoleMessage(
          MakeGarbageCollected<ConsoleMessage>(
              mojom::blink::ConsoleMessageSource::kJavaScript,
              mojom::blink::ConsoleMessageLevel::kWarning,
              "An attempt to claim a USB device interface "
              "has been blocked because it "
              "implements a protected interface class."));
      resolver->RejectWithSecurityError(kProtectedInterfaceClassError,
                                        kProtectedInterfaceClassError);
      break;
    case UsbClaimInterfaceResult::kFailure:
      resolver->RejectWithDOMException(DOMExceptionCode::kNetworkError,
                                       "Unable to claim interface.");
      break;
  }
}

void USBDevice::AsyncReleaseInterface(
    wtf_size_t interface_index,
    ScriptPromiseResolver<IDLUndefined>* resolver,
    bool success) {
  MarkRequestComplete(resolver);

  OnInterfaceClaimedOrUnclaimed(!success, interface_index);
  if (success) {
    resolver->Resolve();
  } else {
    resolver->RejectWithDOMException(DOMExceptionCode::kNetworkError,
                                     "Unable to release interface.");
  }
}

void USBDevice::OnInterfaceClaimedOrUnclaimed(bool claimed,
                                              wtf_size_t interface_index) {
  if (claimed) {
    claimed_interfaces_[interface_index] = true;
  } else {
    claimed_interfaces_[interface_index] = false;
    selected_alternate_indices_[interface_index] = 0;
  }
  SetEndpointsForInterface(interface_index, claimed);
  interface_state_change_in_progress_[interface_index] = false;
}

void USBDevice::AsyncSelectAlternateInterface(
    wtf_size_t interface_index,
    wtf_size_t alternate_index,
    ScriptPromiseResolver<IDLUndefined>* resolver,
    bool success) {
  MarkRequestComplete(resolver);

  if (success)
    selected_alternate_indices_[interface_index] = alternate_index;
  SetEndpointsForInterface(interface_index, success);
  interface_state_change_in_progress_[interface_index] = false;

  if (success) {
    resolver->Resolve();
  } else {
    resolver->RejectWithDOMException(DOMExceptionCode::kNetworkError,
                                     "Unable to set device interface.");
  }
}

void USBDevice::AsyncControlTransferIn(
    ScriptPromiseResolver<USBInTransferResult>* resolver,
    UsbTransferStatus status,
    base::span<const uint8_t> data) {
  MarkRequestComplete(resolver);

  if (CheckFatalTransferStatus(resolver, status))
    return;

  resolver->Resolve(
      USBInTransferResult::Create(ConvertTransferStatus(status), data));
}

void USBDevice::AsyncControlTransferOut(
    uint32_t transfer_length,
    ScriptPromiseResolver<USBOutTransferResult>* resolver,
    UsbTransferStatus status) {
  MarkRequestComplete(resolver);

  if (CheckFatalTransferStatus(resolver, status))
    return;

  resolver->Resolve(USBOutTransferResult::Create(ConvertTransferStatus(status),
                                                 transfer_length));
}

void USBDevice::AsyncClearHalt(ScriptPromiseResolver<IDLUndefined>* resolver,
                               bool success) {
  MarkRequestComplete(resolver);

  if (success) {
    resolver->Resolve();
  } else {
    resolver->RejectWithDOMException(DOMExceptionCode::kNetworkError,
                                     "Unable to clear endpoint.");
  }
}

void USBDevice::AsyncTransferIn(
    ScriptPromiseResolver<USBInTransferResult>* resolver,
    UsbTransferStatus status,
    base::span<const uint8_t> data) {
  MarkRequestComplete(resolver);

  if (CheckFatalTransferStatus(resolver, status))
    return;

  resolver->Resolve(
      USBInTransferResult::Create(ConvertTransferStatus(status), data));
}

void USBDevice::AsyncTransferOut(
    uint32_t transfer_length,
    ScriptPromiseResolver<USBOutTransferResult>* resolver,
    UsbTransferStatus status) {
  MarkRequestComplete(resolver);

  if (CheckFatalTransferStatus(resolver, status))
    return;

  resolver->Resolve(USBOutTransferResult::Create(ConvertTransferStatus(status),
                                                 transfer_length));
}

void USBDevice::AsyncIsochronousTransferIn(
    ScriptPromiseResolver<USBIsochronousInTransferResult>* resolver,
    base::span<const uint8_t> data,
    Vector<UsbIsochronousPacketPtr> mojo_packets) {
  MarkRequestComplete(resolver);

  DOMArrayBuffer* buffer = DOMArrayBuffer::Create(data);
  HeapVector<Member<USBIsochronousInTransferPacket>> packets;
  packets.reserve(mojo_packets.size());
  uint32_t byte_offset = 0;
  for (const auto& packet : mojo_packets) {
    if (CheckFatalTransferStatus(resolver, packet->status))
      return;

    DOMDataView* data_view = nullptr;
    if (buffer) {
      data_view =
          DOMDataView::Create(buffer, byte_offset, packet->transferred_length);
    }
    packets.push_back(USBIsochronousInTransferPacket::Create(
        ConvertTransferStatus(packet->status),
        NotShared<DOMDataView>(data_view)));
    byte_offset += packet->length;
  }
  resolver->Resolve(USBIsochronousInTransferResult::Create(buffer, packets));
}

void USBDevice::AsyncIsochronousTransferOut(
    ScriptPromiseResolver<USBIsochronousOutTransferResult>* resolver,
    Vector<UsbIsochronousPacketPtr> mojo_packets) {
  MarkRequestComplete(resolver);

  HeapVector<Member<USBIsochronousOutTransferPacket>> packets;
  packets.reserve(mojo_packets.size());
  for (const auto& packet : mojo_packets) {
    if (CheckFatalTransferStatus(resolver, packet->status))
      return;

    packets.push_back(USBIsochronousOutTransferPacket::Create(
        ConvertTransferStatus(packet->status), packet->transferred_length));
  }
  resolver->Resolve(USBIsochronousOutTransferResult::Create(packets));
}

void USBDevice::AsyncReset(ScriptPromiseResolver<IDLUndefined>* resolver,
                           bool success) {
  MarkRequestComplete(resolver);

  if (success) {
    resolver->Resolve();
  } else {
    resolver->RejectWithDOMException(DOMExceptionCode::kNetworkError,
                                     "Unable to reset the device.");
  }
}

void USBDevice::OnConnectionError() {
  device_.reset();
  opened_ = false;

  for (auto& resolver : device_requests_) {
    ScriptState* script_state = resolver->GetScriptState();
    if (IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                      script_state)) {
      ScriptState::Scope script_state_scope(script_state);
      resolver->RejectWithDOMException(DOMExceptionCode::kNotFoundError,
                                       kDeviceDisconnected);
    }
  }
  device_requests_.clear();
}

void USBDevice::MarkRequestComplete(ScriptPromiseResolverBase* resolver) {
  auto request_entry = device_requests_.find(resolver);
  // Since all callbacks are wrapped with a check that the execution context is
  // still valid we can guarantee that `device_requests_` hasn't been cleared
  // yet if we are in this function.
  CHECK(request_entry != device_requests_.end(), base::NotFatalUntil::M130);
  device_requests_.erase(request_entry);
}

}  // namespace blink

"""


```