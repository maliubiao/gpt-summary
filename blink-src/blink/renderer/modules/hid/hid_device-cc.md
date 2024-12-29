Response:
Let's break down the thought process for analyzing the `hid_device.cc` file.

1. **Understand the Goal:** The core request is to understand the *functionality* of this specific Chromium Blink file (`hid_device.cc`). This involves more than just listing code; it means explaining *what it does* in the context of the browser and web development. The request also explicitly asks about relationships with JavaScript, HTML, CSS, logical reasoning, common errors, and debugging.

2. **Initial Scan and Keywords:**  The first step is to quickly scan the file for important keywords and concepts. Looking at the includes, namespace, and member variables immediately gives clues:
    * `#include "third_party/blink/renderer/modules/hid/hid_device.h"` - Confirms this is the implementation for the `HIDDevice` class.
    * `namespace blink` - It's part of the Blink rendering engine.
    * `device::mojom::blink::HidDeviceInfoPtr` -  Deals with HID device information. "mojom" suggests inter-process communication (IPC).
    * `ScriptPromise`, `ScriptPromiseResolver` -  Indicates asynchronous operations, which are common in web APIs.
    * `HIDInputReportEvent` - This class handles events related to receiving data from the HID device.
    * `open()`, `close()`, `sendReport()`, `receiveFeatureReport()`, `forget()` - These are clearly methods for interacting with a HID device.

3. **High-Level Functionality:** Based on the keywords, the primary function of `hid_device.cc` is to provide the underlying implementation for the JavaScript `HIDDevice` interface. This interface allows web pages to interact with Human Interface Devices (like keyboards, mice, gamepads, etc.).

4. **Connecting to JavaScript, HTML, and CSS:**  The connection to JavaScript is direct. This C++ code implements the functionality exposed to JavaScript via the `HIDDevice` API.

    * **JavaScript Example:**  The examples provided in the initial analysis (requesting devices, opening, sending, receiving data, handling events) are crucial for illustrating this connection. These show how the C++ code is invoked from JavaScript.
    * **HTML:**  While not directly interacting with HTML elements in this specific file, the `HIDDevice` API is accessed *from* JavaScript that is embedded in HTML or in separate JavaScript files loaded by HTML. The permission flow mentioned (user granting access) is initiated because of JavaScript running within a web page loaded by HTML.
    * **CSS:**  There's no direct interaction with CSS at this level. CSS styles the *presentation* of web pages, but HID device interaction is about *functionality*.

5. **Logical Reasoning (Assumptions and Outputs):**  The code contains several conditional checks and logical flows. Thinking about what happens in different scenarios is key:

    * **`open()`:**
        * **Input:** JavaScript calls `device.open()`.
        * **Assumption:** The device is not already open, the context is valid, and the device is not forgotten.
        * **Output:**  A promise that resolves if the connection is successful, or rejects if it fails (already open, context gone, open failed).
    * **`sendReport()`:**
        * **Input:** JavaScript calls `device.sendReport(reportId, data)`.
        * **Assumption:** The device is open, not forgotten, and the data is within limits.
        * **Output:** A promise that resolves if the send is successful, or rejects if it fails (not open, forgotten, data too big, send failed).
    * **Protected Report Types:** The logic in `IsProtectedReportType` is a clear example of conditional logic. Input is the `HidUsageAndPage` and `ReportType`. Output is a boolean indicating protection.

6. **Common Usage Errors:**  Thinking from a developer's perspective is important here:

    * **Not calling `open()`:**  This is a very common mistake when working with device APIs.
    * **Trying to open an already open device:** The error message "The device is already open." is a direct result of this.
    * **Incorrect data format:** While not explicitly checked in *this* file, developers might send incorrectly formatted data, leading to device issues. This file *does* check the `ArrayBuffer` size.
    * **Permissions:** Forgetting to request or handle permission denials is a crucial point.

7. **Debugging Clues (User Actions and Code Path):** This requires tracing the user's actions that lead to the execution of code within `hid_device.cc`.

    * **Requesting Devices:** The `navigator.hid.requestDevice()` call in JavaScript initiates the process.
    * **User Selection:** The user selecting a device triggers the browser's permission flow and ultimately leads to the creation of the `HIDDevice` object in C++.
    * **JavaScript API Calls:**  Every JavaScript call to methods like `open()`, `sendReport()`, etc., directly calls the corresponding C++ methods in this file.
    * **Events:**  When the HID device sends data, the browser's HID subsystem receives it and routes it to the `HIDDevice` object, which then dispatches the `inputreport` event to JavaScript.

8. **Structure and Refinement:** Once the core ideas are down, it's important to organize them logically and provide clear explanations and examples. Using headings and bullet points helps with readability.

9. **Review and Iterate:** After the initial draft, reviewing and refining the explanation is necessary. Are the explanations clear? Are the examples relevant? Have all aspects of the request been addressed?  For example, ensuring the explanation of "protected reports" is clear and links back to security considerations.

This systematic approach, starting from a high-level understanding and drilling down into specifics, using code inspection and logical reasoning, allows for a comprehensive analysis of the functionality of `hid_device.cc`.
好的，让我们来详细分析一下 `blink/renderer/modules/hid/hid_device.cc` 这个文件。

**文件功能概述**

`hid_device.cc` 文件是 Chromium Blink 渲染引擎中实现 `HIDDevice` 接口的核心代码。`HIDDevice` 接口允许 Web 页面上的 JavaScript 代码与连接到计算机的人机接口设备 (Human Interface Devices, HID) 进行通信，例如键盘、鼠标、游戏手柄等。

**主要功能点:**

1. **设备表示:**  `HIDDevice` 类代表一个已连接的 HID 设备。它存储了设备的各种信息，例如 vendorId, productId, productName 以及设备报告的结构信息（collections）。

2. **打开和关闭设备:**
   - `open()` 方法：允许 JavaScript 代码请求打开与 HID 设备的连接。这会触发底层的操作系统 API 来建立连接。成功连接后，设备可以进行数据传输。
   - `close()` 方法：允许 JavaScript 代码关闭与 HID 设备的连接。

3. **数据传输:**
   - `sendReport()` 方法：允许 JavaScript 代码向 HID 设备发送输出报告。输出报告通常用于控制设备的行为，例如设置 LED 灯的状态。
   - `sendFeatureReport()` 方法：允许 JavaScript 代码向 HID 设备发送或接收特征报告。特征报告用于获取或设置设备的特定配置信息。
   - `receiveFeatureReport()` 方法：允许 JavaScript 代码从 HID 设备接收特征报告。
   - `OnInputReport()` 方法：当 HID 设备发送输入报告时被调用。输入报告通常包含设备的状态信息，例如按键是否被按下，鼠标的移动等。这个方法会将接收到的数据封装成 `HIDInputReportEvent` 并分发给 JavaScript。

4. **设备遗忘:**
   - `forget()` 方法：允许 Web 应用程序“遗忘”一个用户明确授予访问权限的 HID 设备。这会撤销应用程序对该设备的持久化访问权限。

5. **设备信息管理:**
   - `UpdateDeviceInfo()` 方法：用于更新 `HIDDevice` 对象中存储的设备信息，例如当设备连接状态发生变化时。

6. **错误处理:** 文件中定义了许多常量字符串，用于表示各种错误情况，例如设备未打开、操作正在进行中、设备已被遗忘等。当操作失败时，会通过 `ScriptPromise` 的 reject 方法将包含错误信息的 `DOMException` 传递给 JavaScript。

7. **生命周期管理:**  `HIDDevice` 继承自 `ExecutionContextLifecycleObserver`，这意味着它会跟踪关联的 JavaScript 执行上下文的生命周期，并在上下文销毁时清理资源。

**与 JavaScript, HTML, CSS 的关系**

`hid_device.cc` 文件本身是用 C++ 编写的，属于 Blink 渲染引擎的底层实现。它不直接处理 HTML 或 CSS。但是，它与 JavaScript 的交互非常密切，因为它是 WebHID API 在 Blink 引擎中的具体实现。

**举例说明:**

* **JavaScript 请求设备:**  当 JavaScript 代码调用 `navigator.hid.requestDevice()` 时，会触发浏览器底层的 HID 设备枚举流程。一旦用户选择了设备并授予了权限，Blink 引擎会创建对应的 `HIDDevice` C++ 对象，并将其包装成 JavaScript 的 `HIDDevice` 对象返回给 JavaScript 代码。

* **JavaScript 打开设备:**
   ```javascript
   navigator.hid.requestDevice({ filters: [] })
     .then(devices => {
       if (devices.length > 0) {
         const device = devices[0];
         device.open()
           .then(() => {
             console.log("HID Device opened");
           })
           .catch(error => {
             console.error("Error opening HID device:", error);
           });
       }
     });
   ```
   在这个例子中，`device.open()` 方法实际上会调用 `hid_device.cc` 中的 `HIDDevice::open()` 方法。

* **JavaScript 发送报告:**
   ```javascript
   // 假设 device 是一个已打开的 HIDDevice 对象
   const outputReportId = 0x01;
   const data = new Uint8Array([0x01, 0x00, 0xFF]); // 示例数据
   device.sendReport(outputReportId, data)
     .then(() => {
       console.log("Output report sent");
     })
     .catch(error => {
       console.error("Error sending output report:", error);
     });
   ```
   这里的 `device.sendReport()` 方法会调用 `hid_device.cc` 中的 `HIDDevice::sendReport()` 方法。

* **JavaScript 接收输入报告:**
   ```javascript
   // 假设 device 是一个已打开的 HIDDevice 对象
   device.addEventListener('inputreport', event => {
     const { reportId, data } = event;
     console.log(`Received input report with ID ${reportId}:`, data);
     // 处理接收到的数据
   });
   ```
   当 HID 设备发送数据时，`hid_device.cc` 中的 `HIDDevice::OnInputReport()` 方法会被调用，它会创建一个 `HIDInputReportEvent` 对象，并将其分发给 JavaScript 的事件监听器。

**逻辑推理 (假设输入与输出)**

假设 JavaScript 代码调用了 `device.open()` 方法：

* **假设输入:**  `HIDDevice` 对象当前未打开 (`opened()` 返回 false)，且没有设备状态更改正在进行中 (`device_state_change_in_progress_` 为 false)，设备未被遗忘 (`device_is_forgotten_` 为 false)。
* **逻辑推理:**
    1. 创建一个 `ScriptPromiseResolver` 来管理异步操作的结果。
    2. 创建一个 `device::mojom::blink::HidConnectionClient` 的管道，用于与浏览器进程中的 HID 服务通信。
    3. 设置 `device_state_change_in_progress_` 为 true，表示正在进行设备状态更改。
    4. 调用 `parent_->Connect()` 方法，向浏览器进程请求打开设备连接。
    5. `parent_->Connect()` 的回调函数 `FinishOpen()` 会在连接尝试完成后被调用。
* **预期输出 (成功情况):**
    1. `FinishOpen()` 方法接收到一个 `device::mojom::blink::HidConnection` 的 `PendingRemote` 对象。
    2. `connection_` 被绑定到这个 `PendingRemote`。
    3. 连接的断开处理程序被设置。
    4. Promise 被 resolve。
* **预期输出 (失败情况):**
    1. `FinishOpen()` 方法接收到一个空的 `PendingRemote` 或者执行上下文已销毁。
    2. `receiver_` 被重置。
    3. Promise 被 reject，并带有相应的 `DOMException` (例如 "Failed to open the device.")。

**用户或编程常见的使用错误 (举例说明)**

1. **未先调用 `open()` 就尝试发送报告:**
   ```javascript
   navigator.hid.requestDevice({ filters: [] })
     .then(devices => {
       if (devices.length > 0) {
         const device = devices[0];
         const data = new Uint8Array([0x01]);
         device.sendReport(0x00, data) // 错误：未调用 open()
           .catch(error => {
             console.error(error.message); // 输出: "The device must be opened first."
           });
       }
     });
   ```
   在这种情况下，`HIDDevice::sendReport()` 方法会检查 `opened()` 的状态，如果设备未打开，则会 reject Promise 并抛出 "The device must be opened first." 的错误。

2. **多次调用 `open()`:**
   ```javascript
   navigator.hid.requestDevice({ filters: [] })
     .then(devices => {
       if (devices.length > 0) {
         const device = devices[0];
         device.open()
           .then(() => {
             console.log("Device opened successfully");
             return device.open(); // 错误：尝试再次打开
           })
           .catch(error => {
             console.error(error.message); // 输出: "The device is already open."
           });
       }
     });
   ```
   `HIDDevice::open()` 方法会检查设备是否已经打开，如果是，则会 reject Promise 并抛出 "The device is already open." 的错误。

3. **发送过大的 ArrayBuffer:**
   ```javascript
   navigator.hid.requestDevice({ filters: [] })
     .then(devices => {
       if (devices.length > 0) {
         const device = devices[0];
         device.open().then(() => {
           const largeData = new Uint8Array(1024 * 1024); // 假设最大允许大小小于这个值
           device.sendReport(0x00, largeData)
             .catch(error => {
               console.error(error.message); // 输出: "The provided ArrayBuffer exceeds the maximum allowed size."
             });
         });
       }
     });
   ```
   `HIDDevice::sendReport()` 方法会检查 `ArrayBuffer` 的大小，如果超出限制，则会 reject Promise 并抛出 "The provided ArrayBuffer exceeds the maximum allowed size." 的错误。

**用户操作是如何一步步的到达这里，作为调试线索**

1. **用户访问包含 WebHID 代码的网页:** 用户在浏览器中打开一个包含使用 WebHID API 的 JavaScript 代码的 HTML 页面。

2. **JavaScript 调用 `navigator.hid.requestDevice()`:** 网页上的 JavaScript 代码调用 `navigator.hid.requestDevice()` 方法，请求访问 HID 设备。

3. **浏览器显示设备选择器:** 浏览器会弹出一个设备选择器，列出用户计算机上可用的 HID 设备。

4. **用户选择设备并授予权限:** 用户在设备选择器中选择一个设备，并明确授予该网页访问该设备的权限。

5. **Blink 创建 `HIDDevice` 对象:**  一旦用户授予权限，浏览器进程会将此信息传递给渲染器进程。Blink 引擎会创建一个对应的 `HIDDevice` C++ 对象，并将其关联到 JavaScript 的 `HIDDevice` 对象。

6. **JavaScript 调用 `device.open()`:**  JavaScript 代码可能会接着调用 `device.open()` 方法，尝试建立与设备的连接。这会调用 `hid_device.cc` 中的 `HIDDevice::open()` 方法。

7. **Blink 与操作系统 HID 服务通信:** `HIDDevice::open()` 方法会通过 Mojo 接口与浏览器进程中的 HID 服务进行通信，最终调用操作系统的 HID API 来打开设备。

8. **JavaScript 发送/接收数据:** 如果设备成功打开，JavaScript 代码可以调用 `device.sendReport()`、`device.sendFeatureReport()` 或监听 `inputreport` 事件来与设备交换数据。这些操作会分别调用 `hid_device.cc` 中相应的方法。

9. **设备发送输入报告:** 当连接的 HID 设备发送数据时，操作系统会将数据传递给浏览器进程，然后通过 Mojo 接口传递到渲染器进程的 `HIDDevice` 对象，最终触发 `HIDDevice::OnInputReport()` 方法，并将事件分发给 JavaScript。

**调试线索:**

* **断点:** 在 `hid_device.cc` 中的关键方法 (例如 `open`, `sendReport`, `OnInputReport`) 设置断点，可以跟踪代码的执行流程，查看变量的值，并了解操作是否成功以及原因。
* **日志:**  可以使用 `DLOG` 或 `DVLOG` 在 `hid_device.cc` 中添加日志输出，记录关键步骤和变量状态。这些日志可以在 Chrome 的内部日志中查看。
* **Mojo 接口监控:** 可以监控 Blink 引擎与浏览器进程之间 HID 相关的 Mojo 消息传递，了解请求的发送和响应。
* **浏览器开发者工具:**  虽然不能直接调试 C++ 代码，但浏览器开发者工具的 "Sources" 面板可以调试 JavaScript 代码，查看 JavaScript 如何调用 WebHID API，以及如何处理返回的 Promise 和事件。
* **`chrome://device-log/`:**  这个 Chrome 内部页面可以显示一些设备相关的日志信息，可能包含 HID 设备连接和通信的线索。

总而言之，`hid_device.cc` 是 WebHID API 的核心实现，负责在 Blink 渲染引擎中管理 HID 设备的连接、数据传输和生命周期，并与 JavaScript 代码进行交互。理解这个文件的功能对于深入了解 WebHID API 的工作原理至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/hid/hid_device.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/hid/hid_device.h"

#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_hid_collection_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_hid_report_info.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_piece.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_data_view.h"
#include "third_party/blink/renderer/modules/event_target_modules.h"
#include "third_party/blink/renderer/modules/hid/hid_input_report_event.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

const char kDeviceStateChangeInProgress[] =
    "An operation that changes the device state is in progress.";
const char kDeviceIsForgotten[] = "The device is forgotten.";
const char kOpenRequired[] = "The device must be opened first.";
const char kOpenFailed[] = "Failed to open the device.";
const char kSendReportFailed[] = "Failed to write the report.";
const char kSendFeatureReportFailed[] = "Failed to write the feature report.";
const char kReceiveFeatureReportFailed[] =
    "Failed to receive the feature report.";
const char kUnexpectedClose[] = "The device was closed unexpectedly.";
const char kArrayBufferTooBig[] =
    "The provided ArrayBuffer exceeds the maximum allowed size.";
const char kContextGone[] = "Script context has shut down.";

enum ReportType {
  kInput,
  kOutput,
  kFeature,
};

bool IsProtectedReportType(
    const device::mojom::blink::HidUsageAndPage& hid_usage_and_page,
    ReportType report_type) {
  const uint16_t usage = hid_usage_and_page.usage;
  const uint16_t usage_page = hid_usage_and_page.usage_page;

  if (usage_page == device::mojom::blink::kPageFido)
    return true;

  if (usage_page == device::mojom::blink::kPageKeyboard)
    return true;

  if (usage_page != device::mojom::blink::kPageGenericDesktop)
    return false;

  if (usage == device::mojom::blink::kGenericDesktopPointer ||
      usage == device::mojom::blink::kGenericDesktopMouse ||
      usage == device::mojom::blink::kGenericDesktopKeyboard ||
      usage == device::mojom::blink::kGenericDesktopKeypad) {
    return report_type != ReportType::kFeature;
  }

  if (usage >= device::mojom::blink::kGenericDesktopSystemControl &&
      usage <= device::mojom::blink::kGenericDesktopSystemWarmRestart) {
    return true;
  }

  if (usage >= device::mojom::blink::kGenericDesktopSystemDock &&
      usage <= device::mojom::blink::kGenericDesktopSystemDisplaySwap) {
    return true;
  }

  return false;
}

// The HID specification defines four canonical unit systems. Each unit system
// corresponds to a set of units for length, mass, time, temperature, current,
// and luminous intensity. The vendor-defined unit system can be used for
// devices which produce measurements that cannot be adequately described by
// these unit systems.
//
// See the Units table in section 6.2.2.7 of the Device Class Definition for
// HID v1.11.
// https://www.usb.org/document-library/device-class-definition-hid-111
enum HidUnitSystem {
  // none: No unit system
  kUnitSystemNone = 0x00,
  // si-linear: Centimeter, Gram, Seconds, Kelvin, Ampere, Candela
  kUnitSystemSILinear = 0x01,
  // si-rotation: Radians, Gram, Seconds, Kelvin, Ampere, Candela
  kUnitSystemSIRotation = 0x02,
  // english-linear: Inch, Slug, Seconds, Fahrenheit, Ampere, Candela
  kUnitSystemEnglishLinear = 0x03,
  // english-linear: Degrees, Slug, Seconds, Fahrenheit, Ampere, Candela
  kUnitSystemEnglishRotation = 0x04,
  // vendor-defined unit system
  kUnitSystemVendorDefined = 0x0f,
};

uint32_t ConvertHidUsageAndPageToUint32(
    const device::mojom::blink::HidUsageAndPage& usage) {
  return (usage.usage_page) << 16 | usage.usage;
}

String UnitSystemToString(uint8_t unit) {
  DCHECK_LE(unit, 0x0f);
  switch (unit) {
    case kUnitSystemNone:
      return "none";
    case kUnitSystemSILinear:
      return "si-linear";
    case kUnitSystemSIRotation:
      return "si-rotation";
    case kUnitSystemEnglishLinear:
      return "english-linear";
    case kUnitSystemEnglishRotation:
      return "english-rotation";
    case kUnitSystemVendorDefined:
      return "vendor-defined";
    default:
      break;
  }
  // Values other than those defined in HidUnitSystem are reserved by the spec.
  return "reserved";
}

// Convert |unit_factor_exponent| from its coded representation to a signed
// integer type.
int8_t UnitFactorExponentToInt(uint8_t unit_factor_exponent) {
  DCHECK_LE(unit_factor_exponent, 0x0f);
  // Values from 0x08 to 0x0f encode negative exponents.
  if (unit_factor_exponent > 0x08)
    return static_cast<int8_t>(unit_factor_exponent) - 16;
  return unit_factor_exponent;
}

// Unpack the 32-bit unit definition value |unit| into each of its components.
// The unit definition value includes the unit system as well as unit factor
// exponents for each of the 6 units defined by the unit system.
void UnpackUnitValues(uint32_t unit,
                      String& unit_system,
                      int8_t& length_exponent,
                      int8_t& mass_exponent,
                      int8_t& time_exponent,
                      int8_t& temperature_exponent,
                      int8_t& current_exponent,
                      int8_t& luminous_intensity_exponent) {
  unit_system = UnitSystemToString(unit & 0x0f);
  length_exponent = UnitFactorExponentToInt((unit >> 4) & 0x0f);
  mass_exponent = UnitFactorExponentToInt((unit >> 8) & 0x0f);
  time_exponent = UnitFactorExponentToInt((unit >> 12) & 0x0f);
  temperature_exponent = UnitFactorExponentToInt((unit >> 16) & 0x0f);
  current_exponent = UnitFactorExponentToInt((unit >> 20) & 0x0f);
  luminous_intensity_exponent = UnitFactorExponentToInt((unit >> 24) & 0x0f);
}

HIDReportInfo* ToHIDReportInfo(
    const device::mojom::blink::HidReportDescription& report_info) {
  HIDReportInfo* result = HIDReportInfo::Create();
  result->setReportId(report_info.report_id);

  HeapVector<Member<HIDReportItem>> items;
  for (const auto& item : report_info.items)
    items.push_back(HIDDevice::ToHIDReportItem(*item));
  result->setItems(items);

  return result;
}

HIDCollectionInfo* ToHIDCollectionInfo(
    const device::mojom::blink::HidCollectionInfo& collection) {
  HIDCollectionInfo* result = HIDCollectionInfo::Create();
  result->setUsage(collection.usage->usage);
  result->setUsagePage(collection.usage->usage_page);
  result->setType(collection.collection_type);

  HeapVector<Member<HIDReportInfo>> input_reports;
  for (const auto& report : collection.input_reports)
    input_reports.push_back(ToHIDReportInfo(*report));
  result->setInputReports(input_reports);

  HeapVector<Member<HIDReportInfo>> output_reports;
  for (const auto& report : collection.output_reports)
    output_reports.push_back(ToHIDReportInfo(*report));
  result->setOutputReports(output_reports);

  HeapVector<Member<HIDReportInfo>> feature_reports;
  for (const auto& report : collection.feature_reports)
    feature_reports.push_back(ToHIDReportInfo(*report));
  result->setFeatureReports(feature_reports);

  HeapVector<Member<HIDCollectionInfo>> children;
  for (const auto& child : collection.children)
    children.push_back(ToHIDCollectionInfo(*child));
  result->setChildren(children);

  return result;
}

}  // namespace

HIDDevice::HIDDevice(ServiceInterface* parent,
                     device::mojom::blink::HidDeviceInfoPtr info,
                     ExecutionContext* context)
    : ExecutionContextLifecycleObserver(context),
      ActiveScriptWrappable<HIDDevice>({}),
      parent_(parent),
      connection_(context),
      receiver_(this, context) {
  UpdateDeviceInfo(std::move(info));
}

HIDDevice::~HIDDevice() {
  DCHECK(device_requests_.empty());
}

ExecutionContext* HIDDevice::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

const AtomicString& HIDDevice::InterfaceName() const {
  return event_target_names::kHIDDevice;
}

void HIDDevice::OnInputReport(uint8_t report_id,
                              const Vector<uint8_t>& buffer) {
  DispatchEvent(*MakeGarbageCollected<HIDInputReportEvent>(
      event_type_names::kInputreport, this, report_id, buffer));
}

bool HIDDevice::opened() const {
  return connection_.is_bound();
}

uint16_t HIDDevice::vendorId() const {
  return device_info_->vendor_id;
}

uint16_t HIDDevice::productId() const {
  return device_info_->product_id;
}

String HIDDevice::productName() const {
  return device_info_->product_name;
}

const HeapVector<Member<HIDCollectionInfo>>& HIDDevice::collections() const {
  return collections_;
}

ScriptPromise<IDLUndefined> HIDDevice::open(ScriptState* script_state,
                                            ExceptionState& exception_state) {
  if (!GetExecutionContext()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      kContextGone);
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();
  if (!EnsureNoDeviceChangeInProgress(resolver) ||
      !EnsureDeviceIsNotForgotten(resolver)) {
    return promise;
  }

  if (opened()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The device is already open.");
    return promise;
  }

  mojo::PendingRemote<device::mojom::blink::HidConnectionClient> client;
  receiver_.Bind(client.InitWithNewPipeAndPassReceiver(),
                 ExecutionContext::From(script_state)
                     ->GetTaskRunner(TaskType::kMiscPlatformAPI));

  device_state_change_in_progress_ = true;
  device_requests_.insert(resolver);
  parent_->Connect(device_info_->guid, std::move(client),
                   WTF::BindOnce(&HIDDevice::FinishOpen, WrapPersistent(this),
                                 WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLUndefined> HIDDevice::close(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();
  if (!EnsureNoDeviceChangeInProgress(resolver) ||
      !EnsureDeviceIsNotForgotten(resolver)) {
    return promise;
  }

  connection_.reset();
  receiver_.reset();
  resolver->Resolve();
  return promise;
}

ScriptPromise<IDLUndefined> HIDDevice::forget(ScriptState* script_state,
                                              ExceptionState& exception_state) {
  if (!GetExecutionContext()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      kContextGone);
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();
  if (!EnsureNoDeviceChangeInProgress(resolver))
    return promise;

  device_state_change_in_progress_ = true;
  parent_->Forget(device_info_.Clone(),
                  WTF::BindOnce(&HIDDevice::FinishForget, WrapPersistent(this),
                                WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLUndefined> HIDDevice::sendReport(ScriptState* script_state,
                                                  uint8_t report_id,
                                                  const DOMArrayPiece& data) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();
  if (!EnsureNoDeviceChangeInProgress(resolver) ||
      !EnsureDeviceIsNotForgotten(resolver)) {
    return promise;
  }

  if (!opened()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     kOpenRequired);
    return promise;
  }

  if (!base::CheckedNumeric<wtf_size_t>(data.ByteLength()).IsValid()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kNotSupportedError,
                                     kArrayBufferTooBig);
    return promise;
  }

  Vector<uint8_t> vector;
  vector.AppendSpan(data.ByteSpan());

  device_requests_.insert(resolver);
  connection_->Write(
      report_id, vector,
      WTF::BindOnce(&HIDDevice::FinishSendReport, WrapPersistent(this),
                    WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLUndefined> HIDDevice::sendFeatureReport(
    ScriptState* script_state,
    uint8_t report_id,
    const DOMArrayPiece& data) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();
  if (!EnsureNoDeviceChangeInProgress(resolver) ||
      !EnsureDeviceIsNotForgotten(resolver)) {
    return promise;
  }

  if (!opened()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     kOpenRequired);
    return promise;
  }

  if (!base::CheckedNumeric<wtf_size_t>(data.ByteLength()).IsValid()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kNotSupportedError,
                                     kArrayBufferTooBig);
    return promise;
  }

  Vector<uint8_t> vector;
  vector.AppendSpan(data.ByteSpan());

  device_requests_.insert(resolver);
  connection_->SendFeatureReport(
      report_id, vector,
      WTF::BindOnce(&HIDDevice::FinishSendFeatureReport, WrapPersistent(this),
                    WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<NotShared<DOMDataView>> HIDDevice::receiveFeatureReport(
    ScriptState* script_state,
    uint8_t report_id) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<NotShared<DOMDataView>>>(
          script_state);
  auto promise = resolver->Promise();
  if (!EnsureNoDeviceChangeInProgress(resolver) ||
      !EnsureDeviceIsNotForgotten(resolver)) {
    return promise;
  }

  if (!opened()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, kOpenRequired));
    return promise;
  }

  device_requests_.insert(resolver);
  connection_->GetFeatureReport(
      report_id, WTF::BindOnce(&HIDDevice::FinishReceiveFeatureReport,
                               WrapPersistent(this), WrapPersistent(resolver)));
  return promise;
}

void HIDDevice::ContextDestroyed() {
  device_requests_.clear();
}

bool HIDDevice::HasPendingActivity() const {
  // The object should be considered active if it is connected and has at least
  // one event listener.
  return connection_.is_bound() && HasEventListeners();
}

void HIDDevice::UpdateDeviceInfo(device::mojom::blink::HidDeviceInfoPtr info) {
  device_info_ = std::move(info);
  collections_.clear();
  for (const auto& collection : device_info_->collections) {
    auto* collection_info = ToHIDCollectionInfo(*collection);
    // Omit information about protected reports.
    if (IsProtectedReportType(*collection->usage, ReportType::kInput)) {
      collection_info->setInputReports(HeapVector<Member<HIDReportInfo>>{});
    }
    if (IsProtectedReportType(*collection->usage, ReportType::kOutput)) {
      collection_info->setOutputReports(HeapVector<Member<HIDReportInfo>>{});
    }
    if (IsProtectedReportType(*collection->usage, ReportType::kFeature)) {
      collection_info->setFeatureReports(HeapVector<Member<HIDReportInfo>>{});
    }
    collections_.push_back(collection_info);
  }
}

void HIDDevice::ResetIsForgotten() {
  device_is_forgotten_ = false;
}

void HIDDevice::Trace(Visitor* visitor) const {
  visitor->Trace(parent_);
  visitor->Trace(connection_);
  visitor->Trace(receiver_);
  visitor->Trace(device_requests_);
  visitor->Trace(collections_);
  EventTarget::Trace(visitor);
  ScriptWrappable::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

bool HIDDevice::EnsureNoDeviceChangeInProgress(
    ScriptPromiseResolverBase* resolver) const {
  if (device_state_change_in_progress_) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     kDeviceStateChangeInProgress);
    return false;
  }
  return true;
}

bool HIDDevice::EnsureDeviceIsNotForgotten(
    ScriptPromiseResolverBase* resolver) const {
  if (device_is_forgotten_) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     kDeviceIsForgotten);
    return false;
  }
  return true;
}

void HIDDevice::FinishOpen(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    mojo::PendingRemote<device::mojom::blink::HidConnection> connection) {
  MarkRequestComplete(resolver);
  device_state_change_in_progress_ = false;

  if (connection && GetExecutionContext()) {
    connection_.Bind(
        std::move(connection),
        GetExecutionContext()->GetTaskRunner(TaskType::kMiscPlatformAPI));
    connection_.set_disconnect_handler(WTF::BindOnce(
        &HIDDevice::OnServiceConnectionError, WrapWeakPersistent(this)));
    resolver->Resolve();
  } else {
    // If the connection or the context is null, the open failed.
    receiver_.reset();
    resolver->RejectWithDOMException(DOMExceptionCode::kNotAllowedError,
                                     kOpenFailed);
  }
}

void HIDDevice::FinishForget(ScriptPromiseResolver<IDLUndefined>* resolver) {
  device_state_change_in_progress_ = false;
  device_is_forgotten_ = true;
  connection_.reset();
  receiver_.reset();
  resolver->Resolve();
}

void HIDDevice::OnServiceConnectionError() {
  for (auto& resolver : device_requests_) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, kUnexpectedClose));
  }
  device_requests_.clear();
}

void HIDDevice::FinishSendReport(ScriptPromiseResolver<IDLUndefined>* resolver,
                                 bool success) {
  MarkRequestComplete(resolver);
  if (success) {
    resolver->Resolve();
  } else {
    resolver->RejectWithDOMException(DOMExceptionCode::kNotAllowedError,
                                     kSendReportFailed);
  }
}

void HIDDevice::FinishSendFeatureReport(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    bool success) {
  MarkRequestComplete(resolver);
  if (success) {
    resolver->Resolve();
  } else {
    resolver->RejectWithDOMException(DOMExceptionCode::kNotAllowedError,
                                     kSendFeatureReportFailed);
  }
}

void HIDDevice::FinishReceiveFeatureReport(
    ScriptPromiseResolver<NotShared<DOMDataView>>* resolver,
    bool success,
    const std::optional<Vector<uint8_t>>& data) {
  MarkRequestComplete(resolver);
  if (success && data) {
    DOMArrayBuffer* dom_buffer = DOMArrayBuffer::Create(data.value());
    DOMDataView* data_view = DOMDataView::Create(dom_buffer, 0, data->size());
    resolver->Resolve(NotShared(data_view));
  } else {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotAllowedError, kReceiveFeatureReportFailed));
  }
}

void HIDDevice::MarkRequestComplete(ScriptPromiseResolverBase* resolver) {
  auto find_result = device_requests_.find(resolver);
  CHECK_NE(device_requests_.end(), find_result);
  device_requests_.erase(find_result);
}

// static
HIDReportItem* HIDDevice::ToHIDReportItem(
    const device::mojom::blink::HidReportItem& report_item) {
  HIDReportItem* result = HIDReportItem::Create();
  result->setIsAbsolute(!report_item.is_relative);
  result->setIsArray(!report_item.is_variable);
  result->setIsBufferedBytes(report_item.is_buffered_bytes);
  result->setIsConstant(report_item.is_constant);
  result->setIsLinear(!report_item.is_non_linear);
  result->setIsRange(report_item.is_range);
  result->setIsVolatile(report_item.is_volatile);
  result->setHasNull(report_item.has_null_position);
  result->setHasPreferredState(!report_item.no_preferred_state);
  result->setWrap(report_item.wrap);
  result->setReportSize(report_item.report_size);
  result->setReportCount(report_item.report_count);
  result->setUnitExponent(
      UnitFactorExponentToInt(report_item.unit_exponent & 0x0f));
  result->setLogicalMinimum(report_item.logical_minimum);
  result->setLogicalMaximum(report_item.logical_maximum);
  result->setPhysicalMinimum(report_item.physical_minimum);
  result->setPhysicalMaximum(report_item.physical_maximum);

  if (report_item.is_range) {
    result->setUsageMinimum(
        ConvertHidUsageAndPageToUint32(*report_item.usage_minimum));
    result->setUsageMaximum(
        ConvertHidUsageAndPageToUint32(*report_item.usage_maximum));
  } else {
    Vector<uint32_t> usages;
    for (const auto& usage : report_item.usages)
      usages.push_back(ConvertHidUsageAndPageToUint32(*usage));
    result->setUsages(usages);
  }

  String unit_system;
  int8_t unit_factor_length_exponent;
  int8_t unit_factor_mass_exponent;
  int8_t unit_factor_time_exponent;
  int8_t unit_factor_temperature_exponent;
  int8_t unit_factor_current_exponent;
  int8_t unit_factor_luminous_intensity_exponent;
  UnpackUnitValues(report_item.unit, unit_system, unit_factor_length_exponent,
                   unit_factor_mass_exponent, unit_factor_time_exponent,
                   unit_factor_temperature_exponent,
                   unit_factor_current_exponent,
                   unit_factor_luminous_intensity_exponent);
  result->setUnitSystem(unit_system);
  result->setUnitFactorLengthExponent(unit_factor_length_exponent);
  result->setUnitFactorMassExponent(unit_factor_mass_exponent);
  result->setUnitFactorTimeExponent(unit_factor_time_exponent);
  result->setUnitFactorTemperatureExponent(unit_factor_temperature_exponent);
  result->setUnitFactorCurrentExponent(unit_factor_current_exponent);
  result->setUnitFactorLuminousIntensityExponent(
      unit_factor_luminous_intensity_exponent);

  // TODO(mattreynolds): Set |strings_|.

  return result;
}

}  // namespace blink

"""

```