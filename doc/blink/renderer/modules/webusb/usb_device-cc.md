Response:
The user wants a summary of the `blink/renderer/modules/webusb/usb_device.cc` file's functionality. I need to identify the main responsibilities of this class based on the provided code.

Looking at the includes and the methods, I can deduce the following functionalities:

1. **Device Management:**  Opening, closing, and forgetting USB devices.
2. **Configuration Management:** Selecting a specific configuration for the device.
3. **Interface Management:** Claiming and releasing interfaces of a USB device. Selecting alternate settings for an interface.
4. **Data Transfer:** Performing control, bulk (generic), and isochronous transfers (both IN and OUT). Clearing halt conditions on endpoints.
5. **Error Handling:**  Managing errors and exceptions related to USB operations.
6. **State Management:** Tracking the current state of the USB device (open, closed, configuration selected, interfaces claimed, etc.).

The file interacts with JavaScript via the WebUSB API, handling promises and converting between JavaScript objects and internal representations. It doesn't directly deal with HTML or CSS.
这是一个实现了 Chromium Blink 引擎中 `USBDevice` 类的源代码文件。`USBDevice` 类是 WebUSB API 的核心部分，它代表了一个连接到系统的 USB 设备，并提供了与该设备进行通信的方法。

**主要功能归纳：**

1. **设备生命周期管理:**
    *   `open()`:  打开 USB 设备，建立与底层 USB 服务的连接。
    *   `close()`: 关闭 USB 设备，断开与底层 USB 服务的连接。
    *   `forget()`:  通知浏览器忘记该 USB 设备，用于持久化权限的管理。

2. **设备配置管理:**
    *   `selectConfiguration()`: 选择 USB 设备的特定配置（Configuration）。一个设备可以有多个配置，每个配置定义了设备的不同功能。

3. **接口声明和释放:**
    *   `claimInterface()`: 声明对 USB 设备特定接口（Interface）的所有权。在进行数据传输之前，必须先声明接口。
    *   `releaseInterface()`: 释放对已声明的 USB 设备接口的所有权。

4. **备用接口选择:**
    *   `selectAlternateInterface()`:  选择接口的备用设置（Alternate Setting）。一个接口可以有多个备用设置，每个设置定义了不同的端点（Endpoint）配置。

5. **控制传输:**
    *   `controlTransferIn()`: 向 USB 设备的控制端点发送控制请求并接收数据。
    *   `controlTransferOut()`: 向 USB 设备的控制端点发送控制请求并发送数据。

6. **批量传输 (Generic Transfer):**
    *   `transferIn()`: 从 USB 设备的指定端点接收批量数据。
    *   `transferOut()`: 向 USB 设备的指定端点发送批量数据。

7. **同步传输 (Isochronous Transfer):**
    *   `isochronousTransferIn()`: 从 USB 设备的指定端点接收同步数据。同步传输适用于时间敏感的数据，例如音频和视频。
    *   `isochronousTransferOut()`: 向 USB 设备的指定端点发送同步数据。

8. **端点控制:**
    *   `clearHalt()`: 清除指定端点的暂停（Halt）状态。当端点出现错误时可能会进入暂停状态。

9. **设备重置:**
    *   `reset()`: 重置 USB 设备，使其恢复到初始状态。

10. **内部状态管理:**
    *   维护设备连接状态 (`opened_`)。
    *   跟踪当前选定的配置 (`configuration_index_`)。
    *   记录已声明的接口 (`claimed_interfaces_`) 和选定的备用接口设置 (`selected_alternate_indices_`).
    *   管理设备和接口状态变更的进行状态 (`device_state_change_in_progress_`, `interface_state_change_in_progress_`).
    *   存储设备的端点信息 (`in_endpoints_`, `out_endpoints_`).

11. **错误处理:**
    *   检查设备是否已打开，配置是否已选择，接口是否已声明等状态，并在不满足条件时抛出异常。
    *   处理底层 USB 操作返回的错误状态，并将其转换为 JavaScript 的 `DOMException`。

**与 JavaScript, HTML, CSS 的关系举例说明：**

*   **JavaScript:**  这个 C++ 文件实现了 WebUSB API 的底层逻辑，JavaScript 代码通过调用 WebUSB API 的方法（如 `navigator.usb.requestDevice()`, `device.open()`, `device.transferOut()`, 等）来间接地使用这个文件中的功能。例如：

    ```javascript
    navigator.usb.requestDevice({ filters: [] })
      .then(device => {
        console.log("设备已连接:", device.productName);
        return device.open(); // 这里会调用 usb_device.cc 中的 USBDevice::open
      })
      .then(() => device.selectConfiguration(1)) // 调用 USBDevice::selectConfiguration
      .then(() => device.claimInterface(0))     // 调用 USBDevice::claimInterface
      .then(() => device.transferOut(3, new Uint8Array([0x01, 0x02]))) // 调用 USBDevice::transferOut
      .catch(error => { console.error("发生错误:", error); });
    ```

*   **HTML:** HTML 元素（例如按钮）可以通过事件监听器触发 JavaScript 代码，从而间接地调用 `usb_device.cc` 中的功能。例如，用户点击一个 "发送数据" 按钮，按钮的 `onclick` 事件处理函数可能会调用 `device.transferOut()`。

    ```html
    <button id="sendButton">发送数据</button>
    <script>
      const sendButton = document.getElementById('sendButton');
      let usbDevice; // 在其他地方获取已连接的 USBDevice 对象

      sendButton.onclick = function() {
        if (usbDevice) {
          usbDevice.transferOut(3, new Uint8Array([0x03, 0x04]))
            .catch(error => console.error("发送数据失败:", error));
        }
      };
    </script>
    ```

*   **CSS:** CSS 主要负责页面的样式和布局，与 `usb_device.cc` 中的功能没有直接关系。

**逻辑推理的假设输入与输出 (示例):**

假设 JavaScript 代码调用 `device.transferOut(3, new Uint8Array([0x0A, 0x0B]))`:

*   **假设输入:**
    *   `endpoint_number`: 3
    *   `data`:  `[0x0A, 0x0B]` (表示为 `base::span<const uint8_t>`)
    *   设备已打开 (`opened_` 为 true)。
    *   配置已选择 (`configuration_index_` 不为 `kNotFound`)。
    *   包含端点 3 的接口已被声明，并且其备用设置已选择。
    *   不存在正在进行的设备或接口状态变更。

*   **逻辑处理:**
    1. `EnsureEndpointAvailable()` 检查端点 3 是否可用。
    2. `ShouldRejectUsbTransferLength()` 检查数据长度是否超过限制。
    3. 创建一个 `ScriptPromiseResolver<USBOutTransferResult>`。
    4. 调用底层 Mojo 接口 `device_->GenericTransferOut()`，传递端点号、数据等参数。
    5. 底层 USB 操作完成后，通过回调函数 `AsyncTransferOut` 将结果返回给 Promise。

*   **可能的输出:**
    *   如果传输成功，Promise 会 resolve 一个 `USBOutTransferResult` 对象，其中 `status` 为 `ok`，`bytesWritten` 为 2。
    *   如果传输失败（例如，设备断开连接），Promise 会 reject 一个 `DOMException`。

**用户或编程常见的使用错误举例说明：**

1. **未打开设备就进行操作:**  用户在 JavaScript 中调用 `device.transferOut()` 之前没有先调用 `device.open()`。`usb_device.cc` 中的相应方法会检查 `opened_` 标志，并抛出 `InvalidStateError` 异常，提示 "The device must be opened first."。

2. **未声明接口就进行端点操作:** 用户在调用 `device.transferOut()` 操作某个接口的端点之前，没有先调用 `device.claimInterface()` 声明该接口。`EnsureEndpointAvailable()` 会检查接口是否已声明，如果未声明则抛出 `NotFoundError` 异常，提示 "The specified endpoint is not part of a claimed and selected alternate interface."。

3. **传输数据大小超过限制:**  用户尝试通过 `transferOut()` 发送大量数据，超过了 `kUsbTransferLengthLimit` 定义的上限。`ShouldRejectUsbTransferLength()` 会检查数据大小，并抛出 `DataError` 异常，提示数据缓冲区超过了支持的最大大小。

4. **尝试在设备或接口状态变更时进行操作:**  例如，在调用 `device.selectConfiguration()` 之后，但在 Promise resolve 之前，用户尝试调用 `device.transferOut()`。`EnsureNoDeviceOrInterfaceChangeInProgress()` 会检查 `device_state_change_in_progress_` 或 `AnyInterfaceChangeInProgress()`，如果为 true，则抛出 `InvalidStateError` 异常，提示 "An operation that changes the device state is in progress." 或 "An operation that changes interface state is in progress."。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户连接 USB 设备:** 操作系统检测到新的 USB 设备连接。
2. **网页请求访问 USB 设备:** 网页通过 JavaScript 调用 `navigator.usb.requestDevice()` 方法，可能会显示一个设备选择器供用户选择。
3. **用户允许访问:** 用户在设备选择器中选择一个设备并允许网页访问。
4. **JavaScript 获取 `USBDevice` 对象:** 浏览器的 WebUSB 实现创建一个 `USBDevice` 对象，并在 JavaScript 中返回。这个对象对应着 `usb_device.cc` 中的一个实例。
5. **JavaScript 调用 `USBDevice` 的方法:**  例如，用户点击网页上的按钮，触发 JavaScript 代码调用 `device.open()`。
6. **浏览器调用 C++ 代码:** JavaScript 的调用会跨越 JavaScript 和 C++ 的边界，最终调用到 `blink/renderer/modules/webusb/usb_device.cc` 文件中 `USBDevice::open()` 方法。
7. **C++ 代码与底层 USB 服务交互:** `USBDevice::open()` 方法会调用 Mojo 接口与浏览器进程中的 USB 服务进行通信，从而打开设备。

在调试 WebUSB 相关问题时，可以按照这个步骤反向追踪：

*   检查 JavaScript 代码中调用的 WebUSB API 方法和参数。
*   查看浏览器控制台的错误信息，了解是否有 JavaScript 异常抛出。
*   在 `usb_device.cc` 中设置断点，例如在 `USBDevice::open()`、`USBDevice::transferOut()` 等方法入口处，来观察 C++ 代码的执行流程和状态。
*   检查浏览器底层的 USB 日志，了解与操作系统 USB 驱动的交互情况。

总而言之，`blink/renderer/modules/webusb/usb_device.cc` 是 WebUSB API 在 Chromium Blink 引擎中的核心实现，负责处理与 USB 设备的各种操作，并将底层的 USB 通信能力暴露给 JavaScript。它需要处理各种状态管理、错误检查，并与浏览器的其他组件协同工作。

Prompt: 
```
这是目录为blink/renderer/modules/webusb/usb_device.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webusb/usb_device.h"

#include <limits>
#include <optional>
#include <utility>

#include "base/containers/span.h"
#include "base/not_fatal_until.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_usb_control_transfer_parameters.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_usb_direction.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_view.h"
#include "third_party/blink/renderer/modules/webusb/usb.h"
#include "third_party/blink/renderer/modules/webusb/usb_configuration.h"
#include "third_party/blink/renderer/modules/webusb/usb_in_transfer_result.h"
#include "third_party/blink/renderer/modules/webusb/usb_isochronous_in_transfer_result.h"
#include "third_party/blink/renderer/modules/webusb/usb_isochronous_out_transfer_result.h"
#include "third_party/blink/renderer/modules/webusb/usb_out_transfer_result.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

using device::mojom::blink::UsbClaimInterfaceResult;
using device::mojom::blink::UsbControlTransferParamsPtr;
using device::mojom::blink::UsbControlTransferRecipient;
using device::mojom::blink::UsbControlTransferType;
using device::mojom::blink::UsbDevice;
using device::mojom::blink::UsbDeviceInfoPtr;
using device::mojom::blink::UsbIsochronousPacketPtr;
using device::mojom::blink::UsbOpenDeviceError;
using device::mojom::blink::UsbTransferDirection;
using device::mojom::blink::UsbTransferStatus;

namespace blink {

namespace {

const char kAccessDeniedError[] = "Access denied.";
const char kPacketLengthsTooBig[] =
    "The total packet length exceeded the maximum size.";
const char kBufferSizeMismatch[] =
    "The data buffer size must match the total packet length.";
const char kDeviceStateChangeInProgress[] =
    "An operation that changes the device state is in progress.";
const char kDeviceDisconnected[] = "The device was disconnected.";
const char kInterfaceNotFound[] =
    "The interface number provided is not supported by the device in its "
    "current configuration.";
const char kInterfaceStateChangeInProgress[] =
    "An operation that changes interface state is in progress.";
const char kOpenRequired[] = "The device must be opened first.";
const char kProtectedInterfaceClassError[] =
    "The requested interface implements a protected class.";
const char kTransferPermissionDeniedError[] = "The transfer was not allowed.";

const int kUsbTransferLengthLimit = 32 * 1024 * 1024;

bool CheckFatalTransferStatus(ScriptPromiseResolverBase* resolver,
                              const UsbTransferStatus& status) {
  switch (status) {
    case UsbTransferStatus::TRANSFER_ERROR:
      resolver->RejectWithDOMException(DOMExceptionCode::kNetworkError,
                                       "A transfer error has occurred.");
      return true;
    case UsbTransferStatus::PERMISSION_DENIED:
      resolver->RejectWithSecurityError(kTransferPermissionDeniedError,
                                        kTransferPermissionDeniedError);
      return true;
    case UsbTransferStatus::TIMEOUT:
      resolver->RejectWithDOMException(DOMExceptionCode::kTimeoutError,
                                       "The transfer timed out.");
      return true;
    case UsbTransferStatus::CANCELLED:
      resolver->RejectWithDOMException(DOMExceptionCode::kAbortError,
                                       "The transfer was cancelled.");
      return true;
    case UsbTransferStatus::DISCONNECT:
      resolver->RejectWithDOMException(DOMExceptionCode::kNotFoundError,
                                       kDeviceDisconnected);
      return true;
    case UsbTransferStatus::COMPLETED:
    case UsbTransferStatus::STALLED:
    case UsbTransferStatus::BABBLE:
    case UsbTransferStatus::SHORT_PACKET:
      return false;
    default:
      NOTREACHED();
  }
}

V8USBTransferStatus ConvertTransferStatus(const UsbTransferStatus& status) {
  switch (status) {
    case UsbTransferStatus::COMPLETED:
    case UsbTransferStatus::SHORT_PACKET:
      return V8USBTransferStatus(V8USBTransferStatus::Enum::kOk);
    case UsbTransferStatus::STALLED:
      return V8USBTransferStatus(V8USBTransferStatus::Enum::kStall);
    case UsbTransferStatus::BABBLE:
      return V8USBTransferStatus(V8USBTransferStatus::Enum::kBabble);
    case UsbTransferStatus::TRANSFER_ERROR:
    case UsbTransferStatus::PERMISSION_DENIED:
    case UsbTransferStatus::TIMEOUT:
    case UsbTransferStatus::CANCELLED:
    case UsbTransferStatus::DISCONNECT:
      NOTREACHED();
  }
}

// Returns the sum of `packet_lengths`, or nullopt if the sum would overflow.
std::optional<uint32_t> TotalPacketLength(
    const Vector<unsigned>& packet_lengths) {
  uint32_t total_bytes = 0;
  for (const auto packet_length : packet_lengths) {
    // Check for overflow.
    if (std::numeric_limits<uint32_t>::max() - total_bytes < packet_length) {
      return std::nullopt;
    }
    total_bytes += packet_length;
  }
  return total_bytes;
}

bool ShouldRejectUsbTransferLength(size_t length,
                                   ExceptionState& exception_state) {
  if (!base::FeatureList::IsEnabled(
          blink::features::kWebUSBTransferSizeLimit)) {
    return false;
  }

  if (length <= kUsbTransferLengthLimit) {
    return false;
  }
  exception_state.ThrowDOMException(
      DOMExceptionCode::kDataError,
      String::Format(
          "The data buffer exceeded supported maximum size of %d bytes",
          kUsbTransferLengthLimit));
  return true;
}

}  // namespace

USBDevice::USBDevice(USB* parent,
                     UsbDeviceInfoPtr device_info,
                     mojo::PendingRemote<UsbDevice> device,
                     ExecutionContext* context)
    : ExecutionContextLifecycleObserver(context),
      parent_(parent),
      device_info_(std::move(device_info)),
      device_(context),
      opened_(false),
      device_state_change_in_progress_(false),
      configuration_index_(kNotFound) {
  device_.Bind(std::move(device),
               context->GetTaskRunner(TaskType::kMiscPlatformAPI));
  if (device_.is_bound()) {
    device_.set_disconnect_handler(
        WTF::BindOnce(&USBDevice::OnConnectionError, WrapWeakPersistent(this)));
  }

  for (wtf_size_t i = 0; i < Info().configurations.size(); ++i)
    configurations_.push_back(USBConfiguration::Create(this, i));

  wtf_size_t configuration_index =
      FindConfigurationIndex(Info().active_configuration);
  if (configuration_index != kNotFound)
    OnConfigurationSelected(true /* success */, configuration_index);
}

USBDevice::~USBDevice() {
  // |m_device| may still be valid but there should be no more outstanding
  // requests because each holds a persistent handle to this object.
  DCHECK(device_requests_.empty());
}

bool USBDevice::IsInterfaceClaimed(wtf_size_t configuration_index,
                                   wtf_size_t interface_index) const {
  return configuration_index_ != kNotFound &&
         configuration_index_ == configuration_index &&
         claimed_interfaces_[interface_index];
}

wtf_size_t USBDevice::SelectedAlternateInterfaceIndex(
    wtf_size_t interface_index) const {
  return selected_alternate_indices_[interface_index];
}

USBConfiguration* USBDevice::configuration() const {
  if (configuration_index_ == kNotFound)
    return nullptr;
  DCHECK_LT(configuration_index_, configurations_.size());
  return configurations_[configuration_index_].Get();
}

HeapVector<Member<USBConfiguration>> USBDevice::configurations() const {
  return configurations_;
}

ScriptPromise<IDLUndefined> USBDevice::open(ScriptState* script_state,
                                            ExceptionState& exception_state) {
  EnsureNoDeviceOrInterfaceChangeInProgress(exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  if (opened_)
    return ToResolvedUndefinedPromise(script_state);

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  device_state_change_in_progress_ = true;
  device_requests_.insert(resolver);
  device_->Open(WTF::BindOnce(&USBDevice::AsyncOpen, WrapPersistent(this),
                              WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLUndefined> USBDevice::close(ScriptState* script_state,
                                             ExceptionState& exception_state) {
  EnsureNoDeviceOrInterfaceChangeInProgress(exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  if (!opened_)
    return ToResolvedUndefinedPromise(script_state);

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  device_state_change_in_progress_ = true;
  device_requests_.insert(resolver);
  device_->Close(WTF::BindOnce(&USBDevice::AsyncClose, WrapPersistent(this),
                               WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLUndefined> USBDevice::forget(ScriptState* script_state,
                                              ExceptionState& exception_state) {
  if (!GetExecutionContext()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Script context has shut down.");
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  parent_->ForgetDevice(
      device_info_->guid,
      WTF::BindOnce(&USBDevice::AsyncForget, WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> USBDevice::selectConfiguration(
    ScriptState* script_state,
    uint8_t configuration_value,
    ExceptionState& exception_state) {
  EnsureNoDeviceOrInterfaceChangeInProgress(exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  if (!opened_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kOpenRequired);
    return EmptyPromise();
  }

  wtf_size_t configuration_index = FindConfigurationIndex(configuration_value);
  if (configuration_index == kNotFound) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "The configuration value provided is not supported by the device.");
    return EmptyPromise();
  }

  if (configuration_index_ == configuration_index)
    return ToResolvedUndefinedPromise(script_state);

  device_state_change_in_progress_ = true;

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  device_requests_.insert(resolver);
  device_->SetConfiguration(
      configuration_value,
      WTF::BindOnce(&USBDevice::AsyncSelectConfiguration, WrapPersistent(this),
                    configuration_index, WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLUndefined> USBDevice::claimInterface(
    ScriptState* script_state,
    uint8_t interface_number,
    ExceptionState& exception_state) {
  EnsureDeviceConfigured(exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  wtf_size_t interface_index = FindInterfaceIndex(interface_number);
  if (interface_index == kNotFound) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotFoundError,
                                      kInterfaceNotFound);
    return EmptyPromise();
  }

  if (interface_state_change_in_progress_[interface_index]) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kInterfaceStateChangeInProgress);
    return EmptyPromise();
  }

  if (claimed_interfaces_[interface_index])
    return ToResolvedUndefinedPromise(script_state);

  interface_state_change_in_progress_[interface_index] = true;

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  device_requests_.insert(resolver);
  device_->ClaimInterface(
      interface_number,
      WTF::BindOnce(&USBDevice::AsyncClaimInterface, WrapPersistent(this),
                    interface_index, WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLUndefined> USBDevice::releaseInterface(
    ScriptState* script_state,
    uint8_t interface_number,
    ExceptionState& exception_state) {
  EnsureDeviceConfigured(exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  wtf_size_t interface_index = FindInterfaceIndex(interface_number);
  if (interface_index == kNotFound) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "The interface number provided is not supported by the device in its "
        "current configuration.");
    return EmptyPromise();
  }

  if (interface_state_change_in_progress_[interface_index]) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kInterfaceStateChangeInProgress);
    return EmptyPromise();
  }

  if (!claimed_interfaces_[interface_index])
    return ToResolvedUndefinedPromise(script_state);

  // Mark this interface's endpoints unavailable while its state is
  // changing.
  SetEndpointsForInterface(interface_index, false);
  interface_state_change_in_progress_[interface_index] = true;

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  device_requests_.insert(resolver);
  device_->ReleaseInterface(
      interface_number,
      WTF::BindOnce(&USBDevice::AsyncReleaseInterface, WrapPersistent(this),
                    interface_index, WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLUndefined> USBDevice::selectAlternateInterface(
    ScriptState* script_state,
    uint8_t interface_number,
    uint8_t alternate_setting,
    ExceptionState& exception_state) {
  EnsureInterfaceClaimed(interface_number, exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  // TODO(reillyg): This is duplicated work.
  wtf_size_t interface_index = FindInterfaceIndex(interface_number);
  DCHECK_NE(interface_index, kNotFound);
  wtf_size_t alternate_index =
      FindAlternateIndex(interface_index, alternate_setting);
  if (alternate_index == kNotFound) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "The alternate setting provided is not supported by the device in its "
        "current configuration.");
    return EmptyPromise();
  }

  // Mark this old alternate interface's endpoints unavailable while
  // the change is in progress.
  SetEndpointsForInterface(interface_index, false);
  interface_state_change_in_progress_[interface_index] = true;

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  device_requests_.insert(resolver);
  device_->SetInterfaceAlternateSetting(
      interface_number, alternate_setting,
      WTF::BindOnce(&USBDevice::AsyncSelectAlternateInterface,
                    WrapPersistent(this), interface_index, alternate_index,
                    WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<USBInTransferResult> USBDevice::controlTransferIn(
    ScriptState* script_state,
    const USBControlTransferParameters* setup,
    uint16_t length,
    ExceptionState& exception_state) {
  EnsureNoDeviceOrInterfaceChangeInProgress(exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  if (!opened_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kOpenRequired);
    return EmptyPromise();
  }

  auto parameters = ConvertControlTransferParameters(setup, exception_state);
  if (!parameters)
    return EmptyPromise();

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<USBInTransferResult>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  device_requests_.insert(resolver);
  device_->ControlTransferIn(
      std::move(parameters), length, 0,
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          &USBDevice::AsyncControlTransferIn, WrapPersistent(this))));
  return promise;
}

ScriptPromise<USBOutTransferResult> USBDevice::controlTransferOut(
    ScriptState* script_state,
    const USBControlTransferParameters* setup,
    ExceptionState& exception_state) {
  return controlTransferOut(script_state, setup, {}, exception_state);
}

ScriptPromise<USBOutTransferResult> USBDevice::controlTransferOut(
    ScriptState* script_state,
    const USBControlTransferParameters* setup,
    base::span<const uint8_t> data,
    ExceptionState& exception_state) {
  EnsureNoDeviceOrInterfaceChangeInProgress(exception_state);
  if (exception_state.HadException()) {
    return EmptyPromise();
  }

  if (!opened_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kOpenRequired);
    return EmptyPromise();
  }

  auto parameters = ConvertControlTransferParameters(setup, exception_state);
  if (!parameters) {
    return EmptyPromise();
  }

  if (ShouldRejectUsbTransferLength(data.size(), exception_state)) {
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<USBOutTransferResult>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  device_requests_.insert(resolver);
  device_->ControlTransferOut(
      std::move(parameters), data, 0,
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          &USBDevice::AsyncControlTransferOut, WrapPersistent(this),
          static_cast<uint32_t>(data.size()))));
  return promise;
}

ScriptPromise<IDLUndefined> USBDevice::clearHalt(
    ScriptState* script_state,
    const V8USBDirection& direction,
    uint8_t endpoint_number,
    ExceptionState& exception_state) {
  UsbTransferDirection mojo_direction =
      direction.AsEnum() == V8USBDirection::Enum::kIn
          ? UsbTransferDirection::INBOUND
          : UsbTransferDirection::OUTBOUND;
  EnsureEndpointAvailable(mojo_direction == UsbTransferDirection::INBOUND,
                          endpoint_number, exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  device_requests_.insert(resolver);
  device_->ClearHalt(
      mojo_direction, endpoint_number,
      WTF::BindOnce(&USBDevice::AsyncClearHalt, WrapPersistent(this),
                    WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<USBInTransferResult> USBDevice::transferIn(
    ScriptState* script_state,
    uint8_t endpoint_number,
    unsigned length,
    ExceptionState& exception_state) {
  if (ShouldRejectUsbTransferLength(length, exception_state)) {
    return EmptyPromise();
  }
  EnsureEndpointAvailable(/*in_transfer=*/true, endpoint_number,
                          exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<USBInTransferResult>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  device_requests_.insert(resolver);
  device_->GenericTransferIn(
      endpoint_number, length, 0,
      resolver->WrapCallbackInScriptScope(
          WTF::BindOnce(&USBDevice::AsyncTransferIn, WrapPersistent(this))));
  return promise;
}

ScriptPromise<USBOutTransferResult> USBDevice::transferOut(
    ScriptState* script_state,
    uint8_t endpoint_number,
    base::span<const uint8_t> data,
    ExceptionState& exception_state) {
  EnsureEndpointAvailable(/*in_transfer=*/false, endpoint_number,
                          exception_state);
  if (exception_state.HadException()) {
    return EmptyPromise();
  }

  if (ShouldRejectUsbTransferLength(data.size(), exception_state)) {
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<USBOutTransferResult>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  device_requests_.insert(resolver);
  device_->GenericTransferOut(
      endpoint_number, data, 0,
      resolver->WrapCallbackInScriptScope(
          WTF::BindOnce(&USBDevice::AsyncTransferOut, WrapPersistent(this),
                        static_cast<uint32_t>(data.size()))));
  return promise;
}

ScriptPromise<USBIsochronousInTransferResult> USBDevice::isochronousTransferIn(
    ScriptState* script_state,
    uint8_t endpoint_number,
    Vector<unsigned> packet_lengths,
    ExceptionState& exception_state) {
  EnsureEndpointAvailable(/*in_transfer=*/true, endpoint_number,
                          exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  std::optional<uint32_t> total_bytes = TotalPacketLength(packet_lengths);
  if (!total_bytes.has_value()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                      kPacketLengthsTooBig);
    return EmptyPromise();
  }
  if (ShouldRejectUsbTransferLength(total_bytes.value(), exception_state)) {
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<USBIsochronousInTransferResult>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  device_requests_.insert(resolver);
  device_->IsochronousTransferIn(
      endpoint_number, packet_lengths, 0,
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          &USBDevice::AsyncIsochronousTransferIn, WrapPersistent(this))));
  return promise;
}

ScriptPromise<USBIsochronousOutTransferResult>
USBDevice::isochronousTransferOut(ScriptState* script_state,
                                  uint8_t endpoint_number,
                                  base::span<const uint8_t> data,
                                  Vector<unsigned> packet_lengths,
                                  ExceptionState& exception_state) {
  EnsureEndpointAvailable(/*in_transfer=*/false, endpoint_number,
                          exception_state);
  if (exception_state.HadException()) {
    return EmptyPromise();
  }

  std::optional<uint32_t> total_bytes = TotalPacketLength(packet_lengths);
  if (!total_bytes.has_value()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                      kPacketLengthsTooBig);
    return EmptyPromise();
  }
  if (ShouldRejectUsbTransferLength(total_bytes.value(), exception_state)) {
    return EmptyPromise();
  }
  if (total_bytes.value() != data.size()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                      kBufferSizeMismatch);
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<USBIsochronousOutTransferResult>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  device_requests_.insert(resolver);
  device_->IsochronousTransferOut(
      endpoint_number, data, packet_lengths, 0,
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          &USBDevice::AsyncIsochronousTransferOut, WrapPersistent(this))));
  return promise;
}

ScriptPromise<IDLUndefined> USBDevice::reset(ScriptState* script_state,
                                             ExceptionState& exception_state) {
  EnsureNoDeviceOrInterfaceChangeInProgress(exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  if (!opened_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kOpenRequired);
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  device_requests_.insert(resolver);
  device_->Reset(WTF::BindOnce(&USBDevice::AsyncReset, WrapPersistent(this),
                               WrapPersistent(resolver)));
  return promise;
}

void USBDevice::ContextDestroyed() {
  device_requests_.clear();
}

void USBDevice::Trace(Visitor* visitor) const {
  visitor->Trace(parent_);
  visitor->Trace(device_);
  visitor->Trace(device_requests_);
  visitor->Trace(configurations_);
  ScriptWrappable::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

wtf_size_t USBDevice::FindConfigurationIndex(
    uint8_t configuration_value) const {
  const auto& configurations = Info().configurations;
  for (wtf_size_t i = 0; i < configurations.size(); ++i) {
    if (configurations[i]->configuration_value == configuration_value)
      return i;
  }
  return kNotFound;
}

wtf_size_t USBDevice::FindInterfaceIndex(uint8_t interface_number) const {
  DCHECK_NE(configuration_index_, kNotFound);
  const auto& interfaces =
      Info().configurations[configuration_index_]->interfaces;
  for (wtf_size_t i = 0; i < interfaces.size(); ++i) {
    if (interfaces[i]->interface_number == interface_number)
      return i;
  }
  return kNotFound;
}

wtf_size_t USBDevice::FindAlternateIndex(uint32_t interface_index,
                                         uint8_t alternate_setting) const {
  DCHECK_NE(configuration_index_, kNotFound);
  const auto& alternates = Info()
                               .configurations[configuration_index_]
                               ->interfaces[interface_index]
                               ->alternates;
  for (wtf_size_t i = 0; i < alternates.size(); ++i) {
    if (alternates[i]->alternate_setting == alternate_setting)
      return i;
  }
  return kNotFound;
}

void USBDevice::EnsureNoDeviceChangeInProgress(
    ExceptionState& exception_state) const {
  if (!device_.is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotFoundError,
                                      kDeviceDisconnected);
    return;
  }

  if (device_state_change_in_progress_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kDeviceStateChangeInProgress);
    return;
  }
}

void USBDevice::EnsureNoDeviceOrInterfaceChangeInProgress(
    ExceptionState& exception_state) const {
  EnsureNoDeviceChangeInProgress(exception_state);
  if (exception_state.HadException())
    return;

  if (AnyInterfaceChangeInProgress()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kInterfaceStateChangeInProgress);
    return;
  }
}

void USBDevice::EnsureDeviceConfigured(ExceptionState& exception_state) const {
  EnsureNoDeviceChangeInProgress(exception_state);
  if (exception_state.HadException())
    return;

  if (!opened_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kOpenRequired);
    return;
  }

  if (configuration_index_ == kNotFound) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The device must have a configuration selected.");
    return;
  }
}

void USBDevice::EnsureInterfaceClaimed(uint8_t interface_number,
                                       ExceptionState& exception_state) const {
  EnsureDeviceConfigured(exception_state);
  if (exception_state.HadException())
    return;

  wtf_size_t interface_index = FindInterfaceIndex(interface_number);
  if (interface_index == kNotFound) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotFoundError,
                                      kInterfaceNotFound);
    return;
  }

  if (interface_state_change_in_progress_[interface_index]) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kInterfaceStateChangeInProgress);
    return;
  }

  if (!claimed_interfaces_[interface_index]) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The specified interface has not been claimed.");
    return;
  }
}

void USBDevice::EnsureEndpointAvailable(bool in_transfer,
                                        uint8_t endpoint_number,
                                        ExceptionState& exception_state) const {
  EnsureDeviceConfigured(exception_state);
  if (exception_state.HadException())
    return;

  if (endpoint_number == 0 || endpoint_number >= kEndpointsBitsNumber) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        "The specified endpoint number is out of range.");
    return;
  }

  auto& bit_vector = in_transfer ? in_endpoints_ : out_endpoints_;
  if (!bit_vector[endpoint_number - 1]) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "The specified endpoint is not part of a claimed and selected "
        "alternate interface.");
    return;
  }
}

bool USBDevice::AnyInterfaceChangeInProgress() const {
  for (wtf_size_t i = 0; i < interface_state_change_in_progress_.size(); ++i) {
    if (interface_state_change_in_progress_[i])
      return true;
  }
  return false;
}

UsbControlTransferParamsPtr USBDevice::ConvertControlTransferParameters(
    const USBControlTransferParameters* parameters,
    ExceptionState& exception_state) const {
  auto mojo_parameters = device::mojom::blink::UsbControlTransferParams::New();

  switch (parameters->requestType().AsEnum()) {
    case V8USBRequestType::Enum::kStandard:
      mojo_parameters->type = UsbControlTransferType::STANDARD;
      break;
    case V8USBRequestType::Enum::kClass:
      mojo_parameters->type = UsbControlTransferType::CLASS;
      break;
    case V8USBRequestType::Enum::kVendor:
      mojo_parameters->type = UsbControlTransferType::VENDOR;
      break;
  }

  switch (parameters->recipient().AsEnum()) {
    case V8USBRecipient::Enum::kDevice:
      mojo_parameters->recipient = UsbControlTransferRecipient::DEVICE;
      break;
    case V8USBRecipient::Enum::kInterface: {
      uint8_t interface_number = parameters->index() & 0xff;
      EnsureInterfaceClaimed(interface_number, exception_state);
      if (exception_state.HadException())
        return nullptr;

      mojo_parameters->recipient = UsbControlTransferRecipient::INTERFACE;
      break;
    }
    case V8USBRecipient::Enum::kEndpoint: {
      bool in_transfer = parameters->index() & 0x80;
      uint8_t endpoint_number = parameters->index() & 0x0f;
      EnsureEndpointAvailable(in_transfer, endpoint_number, exception_state);
      if (exception_state.HadException())
        return nullptr;

      mojo_parameters->recipient = UsbControlTransferRecipient::ENDPOINT;
      break;
    }
    case V8USBRecipient::Enum::kOther:
      mojo_parameters->recipient = UsbControlTransferRecipient::OTHER;
      break;
  }

  mojo_parameters->request = parameters->request();
  mojo_parameters->value = parameters->value();
  mojo_parameters->index = parameters->index();
  return mojo_parameters;
}

void USBDevice::SetEndpointsForInterface(wtf_size_t interface_index, bool set) {
  const auto& configuration = *Info().configurations[configuration_index_];
  const auto& interface = *configuration.interfaces[interface_index];
  const auto& alternate =
      *interface.alternates[selected_alternate_indices_[interface_index]];
  for (const auto& endpoint : alternate.endpoints) {
    uint8_t endpoint_number =
"""


```