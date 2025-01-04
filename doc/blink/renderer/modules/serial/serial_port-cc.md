Response:
Let's break down the thought process for analyzing the provided `serial_port.cc` file.

**1. Understanding the Goal:**

The primary goal is to analyze the functionality of the `SerialPort` class within the Chromium Blink engine, specifically focusing on its interactions with JavaScript, HTML, CSS, potential errors, debugging, and the underlying logic.

**2. Initial Scan and Keyword Identification:**

The first step is to quickly scan the code, looking for key terms and patterns that reveal the class's purpose. Some immediately stand out:

* **`SerialPort`:** This is the central entity.
* **`open()`, `close()`, `getSignals()`, `setSignals()`:** These look like methods for controlling a serial port.
* **`ReadableStream`, `WritableStream`:**  Indicates interaction with the Streams API, suggesting data transfer.
* **`mojo`:**  Implies inter-process communication and interaction with lower-level system components.
* **`ScriptPromise`:**  Shows asynchronous operations exposed to JavaScript.
* **`ExceptionState`:**  Points to error handling.
* **`SerialOptions`, `SerialInputSignals`, `SerialOutputSignals`:**  Suggest data structures for configuring and interacting with the port.
* **`parent_` (of type `Serial*`):** Indicates a hierarchical relationship, likely part of the Web Serial API.
* **Event handling (`DispatchEventInternal`):** Suggests it's an `EventTarget`.

**3. Deeper Dive into Key Methods:**

Next, we examine the core methods to understand their specific functions:

* **`SerialPort()` (constructor):** Initializes the `SerialPort` object, taking `Serial` (parent) and `SerialPortInfo` as arguments. Note the initialization of `port_` (Mojo interface) and `client_receiver_`.
* **`open()`:** This is crucial. It takes `SerialOptions`, validates them, creates a Mojo connection, and returns a `ScriptPromise`. Pay attention to the validation logic (baud rate, data bits, parity, stop bits, buffer size) and the error handling.
* **`readable()` and `writable()`:** These methods create and return `ReadableStream` and `WritableStream` objects, respectively. They interact with Mojo data pipes for data flow. The error conditions (`!port_.is_bound()`, `open_resolver_`, `IsClosing()`, fatal errors) are important.
* **`getSignals()` and `setSignals()`:** These methods get and set control signals (DTR, RTS, etc.) on the serial port, using Mojo calls and returning `ScriptPromise`s. The warning about RTS with hardware flow control is noteworthy.
* **`close()`:**  Initiates the closing process, handling both readable and writable streams.
* **`forget()`:** Removes the port from the browser's remembered list.

**4. Tracing Data Flow and Interactions:**

Now, consider how data flows through the system:

* **JavaScript `navigator.serial.requestPort()`:** (Though not in the code, it's the entry point). This eventually leads to the creation of a `SerialPort` object.
* **JavaScript `port.open(options)`:** Triggers the `SerialPort::open()` method.
* **Mojo:**  The `port_` member communicates with the browser's serial port implementation (likely in the browser process). Data is exchanged via Mojo data pipes.
* **Streams API:**  The `readable()` and `writable()` methods create JavaScript-accessible streams that are backed by the Mojo data pipes.

**5. Identifying Relationships with Web Technologies:**

* **JavaScript:** The entire class is designed to be accessed and controlled via JavaScript. The `ScriptPromise` return types directly expose asynchronous operations. The input and output signals, and options are all represented by JavaScript objects/dictionaries.
* **HTML:**  HTML doesn't directly interact with this code. However, user interaction within a webpage (e.g., clicking a button to open a serial port) is the trigger for JavaScript code that *uses* this `SerialPort` class.
* **CSS:** CSS has no direct relationship with this low-level functionality.

**6. Inferring Logic and Assumptions:**

* **Asynchronous Operations:** The use of `ScriptPromise` is a clear indicator of asynchronous behavior.
* **Error Handling:**  The code explicitly checks for various error conditions and throws `DOMException`s, which are then caught and handled in JavaScript.
* **Resource Management:**  The handling of Mojo pipes and the `close()` method suggest careful resource management.
* **State Management:**  The `open_resolver_`, `close_resolver_`, and the `port_.is_bound()` checks indicate state management to prevent invalid operations.

**7. Considering User and Programming Errors:**

Think about common mistakes developers might make:

* Providing invalid options to `open()`.
* Trying to open an already open port.
* Trying to read or write to a closed port.
* Not handling the asynchronous nature of the operations correctly (e.g., trying to send data before the port is open).

**8. Debugging Scenarios and User Actions:**

Imagine a user trying to use a serial port:

* **User connects a serial device.**
* **User visits a webpage using the Web Serial API.**
* **JavaScript calls `navigator.serial.requestPort()` and the user selects a port.**
* **JavaScript calls `port.open(options)`:** This is where the `SerialPort::open()` method is invoked. If this fails, look at the error messages in the console.
* **JavaScript gets the readable/writable streams:**  `SerialPort::readable()` and `SerialPort::writable()` are called.
* **Data transfer occurs.**
* **JavaScript calls `port.close()`:** Triggers `SerialPort::close()`.

**9. Structuring the Analysis:**

Finally, organize the findings into clear categories as requested by the prompt:

* **Functionality:**  Summarize what the class does.
* **Relationship to Web Technologies:** Explain the connections to JavaScript, HTML, and CSS.
* **Logic and Assumptions:** Describe the underlying logic and any assumptions made.
* **User/Programming Errors:** Provide concrete examples.
* **Debugging:** Outline user actions and how they lead to this code.

**Self-Correction/Refinement During the Process:**

* Initially, I might focus too much on the Mojo specifics. It's important to remember the *user-facing* functionality and how JavaScript interacts with it.
*  Double-check the error conditions and the corresponding error messages.
*  Ensure the debugging scenario is realistic and step-by-step.
*  Review the prompt to make sure all aspects have been addressed.

By following this systematic approach, we can thoroughly analyze the provided source code and extract the relevant information in a clear and organized manner.
好的，让我们来详细分析一下 `blink/renderer/modules/serial/serial_port.cc` 这个文件。

**文件功能概要：**

`serial_port.cc` 文件定义了 Chromium Blink 引擎中 `SerialPort` 类的实现。`SerialPort` 类是 Web Serial API 的核心组件之一，它代表了一个连接到系统的物理串行端口。  主要功能包括：

1. **打开和关闭串行端口:**  允许 JavaScript 代码请求打开一个串行端口，并配置端口的各种参数（波特率、数据位、校验位、停止位等）。也提供关闭端口的功能。
2. **读写数据流:**  提供 `readable` 和 `writable` 属性，返回 `ReadableStream` 和 `WritableStream` 对象，使得可以通过标准的 JavaScript Streams API 进行串行数据的读取和写入。
3. **控制串行信号:**  允许 JavaScript 代码获取和设置串行端口的控制信号（例如 DTR, RTS）。
4. **管理端口状态:**  维护端口的连接状态，处理连接错误和断开事件。
5. **与底层 Mojo 服务通信:**  通过 Mojo 接口与浏览器进程中负责实际串行端口操作的组件进行通信。
6. **处理异步操作:**  使用 `ScriptPromise` 来处理打开、关闭、获取/设置信号等异步操作。
7. **生命周期管理:**  作为 `EventTarget`，可以监听和分发事件。

**与 JavaScript, HTML, CSS 的关系：**

这个文件是 Web Serial API 在 Blink 渲染引擎中的后端实现，直接与 JavaScript 代码交互，使得网页能够访问和控制用户的串行端口。

* **JavaScript:**
    * **`navigator.serial.requestPort()`:**  虽然这个方法的实现不在这个文件中，但它是用户发起串行端口连接的入口。用户通过 JavaScript 调用此方法，浏览器会弹出一个对话框让用户选择可用的串行端口。
    * **`SerialPort` 对象:**  一旦用户选择了一个端口，JavaScript 会获得一个 `SerialPort` 对象的实例。这个 `SerialPort` 对象的行为就由 `serial_port.cc` 中的代码定义。
    * **`port.open(options)`:**  JavaScript 调用 `SerialPort` 对象的 `open()` 方法来打开端口并配置参数。`serial_port.cc` 中的 `SerialPort::open()` 方法负责处理这些参数，并与底层 Mojo 服务通信。
        * **假设输入:**  JavaScript 代码调用 `port.open({ baudRate: 9600, dataBits: 8, stopBits: 1, parity: 'none' })`。
        * **输出:**  如果一切顺利，`open()` 方法返回一个 resolves 的 Promise，表示端口已成功打开。如果失败，Promise 会 reject，并抛出一个 `DOMException`。
    * **`port.readable` 和 `port.writable`:** JavaScript 可以访问这两个属性来获得 `ReadableStream` 和 `WritableStream` 对象，用于读写数据。这些 Stream 的底层实现由 `SerialPortUnderlyingSource` 和 `SerialPortUnderlyingSink` 类提供，并与 Mojo 数据管道连接。
        * **举例:**  JavaScript 代码可以通过 `port.writable.getWriter().write(new Uint8Array([0x01, 0x02]))` 向串行端口发送数据。
    * **`port.getSignals()` 和 `port.setSignals()`:**  JavaScript 可以调用这些方法来获取和设置串行端口的控制信号。
        * **举例:**  JavaScript 代码可以调用 `port.setSignals({ dataTerminalReady: true })` 来设置 DTR 信号。
    * **`port.close()`:** JavaScript 调用此方法来关闭串行端口。
    * **`port.forget()`:**  JavaScript 调用此方法让浏览器不再记住该端口的授权信息。
    * **事件监听:**  `SerialPort` 继承自 `EventTarget`，JavaScript 可以监听 `connect` 和 `disconnect` 事件，以便在串行端口连接状态发生变化时得到通知。

* **HTML:**  HTML 本身不直接与 `serial_port.cc` 交互。但是，网页中的 HTML 元素（如按钮）可以触发 JavaScript 代码，而这些 JavaScript 代码会使用 Web Serial API 和 `SerialPort` 对象。

* **CSS:** CSS 与 `serial_port.cc` 没有直接关系，它负责网页的样式和布局，不涉及串行端口的底层操作。

**逻辑推理，假设输入与输出：**

* **场景:**  用户尝试打开一个不存在的串行端口或一个已经被其他程序占用的端口。
* **假设输入:** JavaScript 代码调用 `port.open(options)`，但底层 Mojo 服务返回一个表示打开失败的信号。
* **逻辑推理:** `SerialPort::OnOpen()` 方法会接收到空的 `port` 参数。
* **输出:** `open_resolver_` 的 Promise 会被 reject，并抛出一个 `NetworkError` 类型的 `DOMException`，错误信息为 "Failed to open serial port."。JavaScript 代码可以通过 Promise 的 `.catch()` 方法捕获这个错误。

* **场景:**  在硬件流控制启用的情况下，JavaScript 尝试手动设置 RTS 信号。
* **假设输入:**  JavaScript 代码调用 `port.open({ flowControl: 'hardware' })`，然后调用 `port.setSignals({ requestToSend: true })`。
* **逻辑推理:** `SerialPort::setSignals()` 方法会检测到硬件流控制已启用且 RTS 信号被手动设置。
* **输出:**  除了正常设置 RTS 信号外，还会向控制台输出一个信息级别的警告消息，提示开发者不应该在硬件流控制时手动设置 RTS。

**用户或编程常见的使用错误：**

1. **尝试在端口未打开的情况下进行读写或控制信号操作:**
   * **错误代码示例:**
     ```javascript
     let port; // Port 未初始化或未成功打开
     const writer = port.writable.getWriter(); // 报错：Cannot read properties of undefined (reading 'writable')
     ```
   * **说明:**  必须先成功调用 `port.open()` 并等待 Promise resolve 后才能进行后续操作。
   * **`serial_port.cc` 中的处理:** 许多方法（如 `readable`, `writable`, `getSignals`, `setSignals`）都会检查 `port_.is_bound()` 来确保端口已打开，否则会抛出 `InvalidStateError`。

2. **提供了无效的 `SerialOptions` 参数:**
   * **错误代码示例:**
     ```javascript
     port.open({ baudRate: 0 }); // 波特率不能为 0
     ```
   * **说明:**  `SerialOptions` 中的参数必须符合规范（例如，波特率必须大于 0，数据位只能是 7 或 8，停止位只能是 1 或 2）。
   * **`serial_port.cc` 中的处理:** `SerialPort::open()` 方法会对 `SerialOptions` 进行校验，如果参数无效会抛出 `TypeError`。

3. **尝试在 `open()` 操作进行中再次调用 `open()`:**
   * **错误代码示例:**
     ```javascript
     port.open(options1);
     port.open(options2); // 第二次调用会报错
     ```
   * **说明:**  在之前的 `open()` 操作完成之前，不能再次调用 `open()`。
   * **`serial_port.cc` 中的处理:** `SerialPort::open()` 方法会检查 `open_resolver_` 是否存在，如果存在则表示有正在进行的 `open()` 操作，会抛出 `InvalidStateError`。

4. **尝试在 `close()` 操作进行中再次调用 `close()`:**
   * **错误代码示例:**
     ```javascript
     port.close();
     port.close(); // 第二次调用会报错
     ```
   * **说明:**  在之前的 `close()` 操作完成之前，不能再次调用 `close()`。
   * **`serial_port.cc` 中的处理:** `SerialPort::close()` 方法会检查 `IsClosing()` 的返回值，如果为 true 则表示有正在进行的 `close()` 操作，会抛出 `InvalidStateError`。

5. **未正确处理异步操作的结果（Promise 的 rejected 状态）:**
   * **错误代码示例:**
     ```javascript
     port.open(options); // 未添加 .catch() 处理错误
     // ... 假设 open 失败，后续操作可能报错
     ```
   * **说明:**  像 `open`, `close`, `getSignals`, `setSignals` 这样的操作都是异步的，应该使用 `.then()` 和 `.catch()` 来处理 Promise 的 resolve 和 reject 状态。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户打开一个支持 Web Serial API 的网页。**
2. **网页的 JavaScript 代码调用 `navigator.serial.requestPort()`。**
3. **浏览器显示一个对话框，列出可用的串行端口。**
4. **用户选择一个串行端口并授权网页访问。**
5. **JavaScript 代码获得一个 `SerialPort` 对象的实例。**  这个实例的创建可能发生在浏览器进程中，然后通过 IPC 传递给渲染进程。
6. **JavaScript 代码调用 `port.open(options)`。**
   * 这会触发 Blink 渲染引擎中的 `SerialPort::open()` 方法。
   * 在 `SerialPort::open()` 中，会创建与浏览器进程中串行端口服务的 Mojo 连接。
   *  如果打开成功，Mojo 服务会返回一个 `SerialPort` 接口的远程对象 (`mojo::PendingRemote<device::mojom::blink::SerialPort>`)。
   * `SerialPort::OnOpen()` 方法会被调用，完成端口的绑定和 Promise 的 resolve。
7. **JavaScript 代码调用 `port.readable` 或 `port.writable`。**
   * 这会触发 `SerialPort::readable()` 或 `SerialPort::writable()` 方法。
   * 这些方法会创建 Mojo 数据管道，并与底层服务建立数据流连接。
   * 返回对应的 `ReadableStream` 或 `WritableStream` 对象给 JavaScript。
8. **JavaScript 代码使用 `ReadableStream` 和 `WritableStream` 进行数据读写。**
   * 当 JavaScript 从 `readable` 流读取数据时，底层会通过 Mojo 数据管道接收来自串行端口的数据。
   * 当 JavaScript 向 `writable` 流写入数据时，底层会通过 Mojo 数据管道将数据发送到串行端口。
9. **JavaScript 代码调用 `port.getSignals()` 或 `port.setSignals(signals)`。**
   * 这会触发 `SerialPort::getSignals()` 或 `SerialPort::setSignals()` 方法。
   * 这些方法会调用 Mojo 接口来获取或设置串行端口的控制信号。
   * `SerialPort::OnGetSignals()` 或 `SerialPort::OnSetSignals()` 方法会处理 Mojo 调用的结果，并 resolve 或 reject 对应的 Promise。
10. **JavaScript 代码调用 `port.close()`。**
    * 这会触发 `SerialPort::close()` 方法。
    * 该方法会尝试取消正在进行的读写操作，并关闭与底层 Mojo 服务的连接。
    * `SerialPort::OnClose()` 方法会被调用，完成清理工作并 resolve close 的 Promise。

**作为调试线索:**

如果你在调试 Web Serial API 相关的问题，`serial_port.cc` 文件是关键的入口点，可以帮助你理解以下内容：

* **端口打开和关闭的流程:**  追踪 `open()` 和 `close()` 方法的执行，查看 Mojo 调用的参数和返回值，可以了解端口是否成功打开或关闭，以及失败的原因。
* **数据流的建立和传输:**  理解 `readable()` 和 `writable()` 方法如何创建 Streams API 对象，以及它们如何与 Mojo 数据管道交互，可以帮助你排查数据读写的问题。
* **控制信号的处理:**  查看 `getSignals()` 和 `setSignals()` 方法，了解控制信号是如何通过 Mojo 传递到硬件的。
* **错误处理逻辑:**  分析代码中抛出的各种 `DOMException`，可以帮助你理解在哪些情况下会发生错误，以及错误的具体原因。
* **与底层 Mojo 服务的交互:**  通过查看 Mojo 接口的调用，可以了解 Blink 渲染引擎是如何与浏览器进程中的串行端口服务进行通信的。

总而言之，`blink/renderer/modules/serial/serial_port.cc` 是 Web Serial API 在 Blink 渲染引擎中的核心实现，负责将 JavaScript 的请求转换为底层的串行端口操作，并管理端口的状态和数据流。理解这个文件的功能和实现细节，对于开发和调试 Web Serial API 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/serial/serial_port.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/serial/serial_port.h"

#include "mojo/public/cpp/bindings/pending_remote.h"
#include "third_party/blink/public/mojom/devtools/console_message.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_string_unsignedlong.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_serial_input_signals.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_serial_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_serial_output_signals.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_serial_port_info.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/modules/event_target_modules_names.h"
#include "third_party/blink/renderer/modules/serial/serial.h"
#include "third_party/blink/renderer/modules/serial/serial_port_underlying_sink.h"
#include "third_party/blink/renderer/modules/serial/serial_port_underlying_source.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"

namespace blink {

namespace {

using ::device::mojom::blink::SerialReceiveError;
using ::device::mojom::blink::SerialSendError;

const char kResourcesExhaustedReadBuffer[] =
    "Resources exhausted allocating read buffer.";
const char kResourcesExhaustedWriteBuffer[] =
    "Resources exhausted allocation write buffer.";
const char kNoSignals[] =
    "Signals dictionary must contain at least one member.";
const char kPortClosed[] = "The port is closed.";
const char kOpenError[] = "Failed to open serial port.";
const char kDeviceLostError[] = "The device has been lost.";
const int kMaxBufferSize = 16 * 1024 * 1024; /* 16 MiB */

bool SendErrorIsFatal(SerialSendError error) {
  switch (error) {
    case SerialSendError::NONE:
      NOTREACHED();
    case SerialSendError::SYSTEM_ERROR:
      return false;
    case SerialSendError::DISCONNECTED:
      return true;
  }
}

bool ReceiveErrorIsFatal(SerialReceiveError error) {
  switch (error) {
    case SerialReceiveError::NONE:
      NOTREACHED();
    case SerialReceiveError::BREAK:
    case SerialReceiveError::FRAME_ERROR:
    case SerialReceiveError::OVERRUN:
    case SerialReceiveError::BUFFER_OVERFLOW:
    case SerialReceiveError::PARITY_ERROR:
    case SerialReceiveError::SYSTEM_ERROR:
      return false;
    case SerialReceiveError::DISCONNECTED:
    case SerialReceiveError::DEVICE_LOST:
      return true;
  }
}

}  // namespace

SerialPort::SerialPort(Serial* parent, mojom::blink::SerialPortInfoPtr info)
    : ActiveScriptWrappable<SerialPort>({}),
      info_(std::move(info)),
      connected_(info_->connected),
      parent_(parent),
      port_(parent->GetExecutionContext()),
      client_receiver_(this, parent->GetExecutionContext()) {}

SerialPort::~SerialPort() = default;

SerialPortInfo* SerialPort::getInfo() {
  auto* info = MakeGarbageCollected<SerialPortInfo>();
  if (info_->has_usb_vendor_id)
    info->setUsbVendorId(info_->usb_vendor_id);
  if (info_->has_usb_product_id)
    info->setUsbProductId(info_->usb_product_id);
  if (info_->bluetooth_service_class_id) {
    info->setBluetoothServiceClassId(
        MakeGarbageCollected<V8UnionStringOrUnsignedLong>(
            info_->bluetooth_service_class_id->uuid));
  }
  return info;
}

ScriptPromise<IDLUndefined> SerialPort::open(ScriptState* script_state,
                                             const SerialOptions* options,
                                             ExceptionState& exception_state) {
  if (!GetExecutionContext()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Script context has shut down.");
    return EmptyPromise();
  }

  if (open_resolver_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "A call to open() is already in progress.");
    return EmptyPromise();
  }

  if (port_.is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The port is already open.");
    return EmptyPromise();
  }

  auto mojo_options = device::mojom::blink::SerialConnectionOptions::New();

  if (options->baudRate() == 0) {
    exception_state.ThrowTypeError(
        "Requested baud rate must be greater than zero.");
    return EmptyPromise();
  }
  mojo_options->bitrate = options->baudRate();

  switch (options->dataBits()) {
    case 7:
      mojo_options->data_bits = device::mojom::blink::SerialDataBits::SEVEN;
      break;
    case 8:
      mojo_options->data_bits = device::mojom::blink::SerialDataBits::EIGHT;
      break;
    default:
      exception_state.ThrowTypeError(
          "Requested number of data bits must be 7 or 8.");
      return EmptyPromise();
  }

  if (options->parity() == "none") {
    mojo_options->parity_bit = device::mojom::blink::SerialParityBit::NO_PARITY;
  } else if (options->parity() == "even") {
    mojo_options->parity_bit = device::mojom::blink::SerialParityBit::EVEN;
  } else if (options->parity() == "odd") {
    mojo_options->parity_bit = device::mojom::blink::SerialParityBit::ODD;
  } else {
    NOTREACHED();
  }

  switch (options->stopBits()) {
    case 1:
      mojo_options->stop_bits = device::mojom::blink::SerialStopBits::ONE;
      break;
    case 2:
      mojo_options->stop_bits = device::mojom::blink::SerialStopBits::TWO;
      break;
    default:
      exception_state.ThrowTypeError(
          "Requested number of stop bits must be 1 or 2.");
      return EmptyPromise();
  }

  if (options->bufferSize() == 0) {
    exception_state.ThrowTypeError(String::Format(
        "Requested buffer size (%d bytes) must be greater than zero.",
        options->bufferSize()));
    return EmptyPromise();
  }

  if (options->bufferSize() > kMaxBufferSize) {
    exception_state.ThrowTypeError(
        String::Format("Requested buffer size (%d bytes) is greater than "
                       "the maximum allowed (%d bytes).",
                       options->bufferSize(), kMaxBufferSize));
    return EmptyPromise();
  }
  buffer_size_ = options->bufferSize();

  hardware_flow_control_ = options->flowControl() == "hardware";
  mojo_options->has_cts_flow_control = true;
  mojo_options->cts_flow_control = hardware_flow_control_;

  mojo::PendingRemote<device::mojom::blink::SerialPortClient> client;
  open_resolver_ = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto callback = WTF::BindOnce(&SerialPort::OnOpen, WrapPersistent(this),
                                client.InitWithNewPipeAndPassReceiver());

  parent_->OpenPort(info_->token, std::move(mojo_options), std::move(client),
                    std::move(callback));

  return open_resolver_->Promise();
}

ReadableStream* SerialPort::readable(ScriptState* script_state,
                                     ExceptionState& exception_state) {
  if (readable_)
    return readable_.Get();

  if (!port_.is_bound() || open_resolver_ || IsClosing() || read_fatal_)
    return nullptr;

  mojo::ScopedDataPipeProducerHandle producer;
  mojo::ScopedDataPipeConsumerHandle consumer;
  if (!CreateDataPipe(&producer, &consumer)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kQuotaExceededError,
                                      kResourcesExhaustedReadBuffer);
    return nullptr;
  }

  port_->StartReading(std::move(producer));

  DCHECK(!underlying_source_);
  underlying_source_ = MakeGarbageCollected<SerialPortUnderlyingSource>(
      script_state, this, std::move(consumer));
  readable_ =
      ReadableStream::CreateByteStream(script_state, underlying_source_);
  return readable_.Get();
}

WritableStream* SerialPort::writable(ScriptState* script_state,
                                     ExceptionState& exception_state) {
  if (writable_)
    return writable_.Get();

  if (!port_.is_bound() || open_resolver_ || IsClosing() || write_fatal_)
    return nullptr;

  mojo::ScopedDataPipeProducerHandle producer;
  mojo::ScopedDataPipeConsumerHandle consumer;
  if (!CreateDataPipe(&producer, &consumer)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kQuotaExceededError,
                                      kResourcesExhaustedWriteBuffer);
    return nullptr;
  }

  port_->StartWriting(std::move(consumer));

  DCHECK(!underlying_sink_);
  underlying_sink_ =
      MakeGarbageCollected<SerialPortUnderlyingSink>(this, std::move(producer));
  // Ideally the stream would report the number of bytes that could be written
  // to the underlying Mojo data pipe. As an approximation the high water mark
  // is set to 1 so that the stream appears ready but producers observing
  // backpressure won't queue additional chunks in the stream and thus add an
  // extra layer of buffering.
  writable_ = WritableStream::CreateWithCountQueueingStrategy(
      script_state, underlying_sink_, /*high_water_mark=*/1);
  return writable_.Get();
}

ScriptPromise<SerialInputSignals> SerialPort::getSignals(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!port_.is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kPortClosed);
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<SerialInputSignals>>(
          script_state, exception_state.GetContext());
  signal_resolvers_.insert(resolver);
  port_->GetControlSignals(resolver->WrapCallbackInScriptScope(
      WTF::BindOnce(&SerialPort::OnGetSignals, WrapPersistent(this))));
  return resolver->Promise();
}

ScriptPromise<IDLUndefined> SerialPort::setSignals(
    ScriptState* script_state,
    const SerialOutputSignals* signals,
    ExceptionState& exception_state) {
  ExecutionContext* context = GetExecutionContext();
  if (!context) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Script context has shut down.");
    return EmptyPromise();
  }

  if (!port_.is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kPortClosed);
    return EmptyPromise();
  }

  if (!signals->hasDataTerminalReady() && !signals->hasRequestToSend() &&
      !signals->hasBrk()) {
    exception_state.ThrowTypeError(kNoSignals);
    return EmptyPromise();
  }

  auto mojo_signals = device::mojom::blink::SerialHostControlSignals::New();
  if (signals->hasDataTerminalReady()) {
    mojo_signals->has_dtr = true;
    mojo_signals->dtr = signals->dataTerminalReady();
  }
  if (signals->hasRequestToSend()) {
    mojo_signals->has_rts = true;
    mojo_signals->rts = signals->requestToSend();

    if (hardware_flow_control_) {
      // This combination may be deprecated in the future but generate a console
      // warning for now: https://github.com/WICG/serial/issues/158
      context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kRecommendation,
          mojom::blink::ConsoleMessageLevel::kInfo,
          "The RTS (request to send) signal should not be configured manually "
          "when using hardware flow control. This combination may not be "
          "supported on all platforms."));
    }
  }
  if (signals->hasBrk()) {
    mojo_signals->has_brk = true;
    mojo_signals->brk = signals->brk();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  signal_resolvers_.insert(resolver);
  port_->SetControlSignals(
      std::move(mojo_signals),
      resolver->WrapCallbackInScriptScope(
          WTF::BindOnce(&SerialPort::OnSetSignals, WrapPersistent(this))));
  return resolver->Promise();
}

ScriptPromise<IDLUndefined> SerialPort::close(ScriptState* script_state,
                                              ExceptionState& exception_state) {
  if (!port_.is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The port is already closed.");
    return EmptyPromise();
  }

  if (IsClosing()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "A call to close() is already in progress.");
    return EmptyPromise();
  }

  close_resolver_ = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = close_resolver_->Promise();

  if (!readable_ && !writable_) {
    StreamsClosed();
    return promise;
  }

  if (readable_) {
    readable_->cancel(script_state, exception_state);
    if (exception_state.HadException()) {
      AbortClose();
      return EmptyPromise();
    }
  }
  if (writable_) {
    ScriptValue reason(script_state->GetIsolate(),
                       V8ThrowDOMException::CreateOrDie(
                           script_state->GetIsolate(),
                           DOMExceptionCode::kInvalidStateError, kPortClosed));
    writable_->abort(script_state, reason, exception_state);
    if (exception_state.HadException()) {
      AbortClose();
      return EmptyPromise();
    }
  }

  return promise;
}

ScriptPromise<IDLUndefined> SerialPort::forget(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  ExecutionContext* context = GetExecutionContext();
  if (!context) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Script context has shut down.");
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  parent_->ForgetPort(info_->token,
                      WTF::BindOnce(
                          [](ScriptPromiseResolver<IDLUndefined>* resolver) {
                            resolver->Resolve();
                          },
                          WrapPersistent(resolver)));

  return resolver->Promise();
}

void SerialPort::AbortClose() {
  DCHECK(IsClosing());
  // Dropping |close_resolver_| is okay because the Promise it is attached to
  // won't be returned to script in this case.
  close_resolver_ = nullptr;
}

void SerialPort::StreamsClosed() {
  DCHECK(!readable_);
  DCHECK(!writable_);
  DCHECK(IsClosing());

  port_->Close(/*flush=*/true,
               WTF::BindOnce(&SerialPort::OnClose, WrapPersistent(this)));
}

void SerialPort::Flush(
    device::mojom::blink::SerialPortFlushMode mode,
    device::mojom::blink::SerialPort::FlushCallback callback) {
  DCHECK(port_.is_bound());
  port_->Flush(mode, std::move(callback));
}

void SerialPort::Drain(
    device::mojom::blink::SerialPort::DrainCallback callback) {
  DCHECK(port_.is_bound());
  port_->Drain(std::move(callback));
}

void SerialPort::UnderlyingSourceClosed() {
  DCHECK(readable_);
  readable_ = nullptr;
  underlying_source_ = nullptr;

  if (IsClosing() && !writable_) {
    StreamsClosed();
  }
}

void SerialPort::UnderlyingSinkClosed() {
  DCHECK(writable_);
  writable_ = nullptr;
  underlying_sink_ = nullptr;

  if (IsClosing() && !readable_) {
    StreamsClosed();
  }
}

void SerialPort::ContextDestroyed() {
  // Release connection-related resources as quickly as possible.
  port_.reset();
}

void SerialPort::Trace(Visitor* visitor) const {
  visitor->Trace(parent_);
  visitor->Trace(port_);
  visitor->Trace(client_receiver_);
  visitor->Trace(readable_);
  visitor->Trace(underlying_source_);
  visitor->Trace(writable_);
  visitor->Trace(underlying_sink_);
  visitor->Trace(open_resolver_);
  visitor->Trace(signal_resolvers_);
  visitor->Trace(close_resolver_);
  EventTarget::Trace(visitor);
  ActiveScriptWrappable<SerialPort>::Trace(visitor);
}

bool SerialPort::HasPendingActivity() const {
  // There is no need to check if the execution context has been destroyed, this
  // is handled by the common tracing logic.
  //
  // This object should be considered active as long as it is open so that any
  // chain of streams originating from this port are not closed prematurely.
  return port_.is_bound();
}

ExecutionContext* SerialPort::GetExecutionContext() const {
  return parent_->GetExecutionContext();
}

const AtomicString& SerialPort::InterfaceName() const {
  return event_target_names::kSerialPort;
}

DispatchEventResult SerialPort::DispatchEventInternal(Event& event) {
  event.SetTarget(this);

  // Events fired on a SerialPort instance bubble to the parent Serial instance.
  event.SetEventPhase(Event::PhaseType::kCapturingPhase);
  event.SetCurrentTarget(parent_);
  parent_->FireEventListeners(event);
  if (event.PropagationStopped())
    goto doneDispatching;

  event.SetEventPhase(Event::PhaseType::kAtTarget);
  event.SetCurrentTarget(this);
  FireEventListeners(event);
  if (event.PropagationStopped() || !event.bubbles())
    goto doneDispatching;

  event.SetEventPhase(Event::PhaseType::kBubblingPhase);
  event.SetCurrentTarget(parent_);
  parent_->FireEventListeners(event);

doneDispatching:
  event.SetCurrentTarget(nullptr);
  event.SetEventPhase(Event::PhaseType::kNone);
  return EventTarget::GetDispatchEventResult(event);
}

void SerialPort::OnReadError(device::mojom::blink::SerialReceiveError error) {
  if (ReceiveErrorIsFatal(error))
    read_fatal_ = true;
  if (underlying_source_)
    underlying_source_->SignalErrorOnClose(error);
}

void SerialPort::OnSendError(device::mojom::blink::SerialSendError error) {
  if (SendErrorIsFatal(error))
    write_fatal_ = true;
  if (underlying_sink_)
    underlying_sink_->SignalError(error);
}

bool SerialPort::CreateDataPipe(mojo::ScopedDataPipeProducerHandle* producer,
                                mojo::ScopedDataPipeConsumerHandle* consumer) {
  MojoCreateDataPipeOptions options;
  options.struct_size = sizeof(MojoCreateDataPipeOptions);
  options.flags = MOJO_CREATE_DATA_PIPE_FLAG_NONE;
  options.element_num_bytes = 1;
  options.capacity_num_bytes = buffer_size_;

  MojoResult result = mojo::CreateDataPipe(&options, *producer, *consumer);
  if (result == MOJO_RESULT_OK)
    return true;

  DCHECK_EQ(result, MOJO_RESULT_RESOURCE_EXHAUSTED);
  return false;
}

void SerialPort::OnConnectionError() {
  read_fatal_ = false;
  write_fatal_ = false;
  port_.reset();
  client_receiver_.reset();

  if (open_resolver_) {
    ScriptState* script_state = open_resolver_->GetScriptState();
    if (IsInParallelAlgorithmRunnable(open_resolver_->GetExecutionContext(),
                                      script_state)) {
      ScriptState::Scope script_state_scope(script_state);
      open_resolver_->RejectWithDOMException(DOMExceptionCode::kNetworkError,
                                             kOpenError);
      open_resolver_ = nullptr;
    }
  }

  for (auto& resolver : signal_resolvers_) {
    ScriptState* script_state = resolver->GetScriptState();
    if (IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                      script_state)) {
      ScriptState::Scope script_state_scope(script_state);
      resolver->RejectWithDOMException(DOMExceptionCode::kNetworkError,
                                       kDeviceLostError);
    }
  }
  signal_resolvers_.clear();

  if (IsClosing()) {
    close_resolver_->Resolve();
    close_resolver_ = nullptr;
  }

  if (underlying_source_)
    underlying_source_->SignalErrorOnClose(SerialReceiveError::DISCONNECTED);

  if (underlying_sink_)
    underlying_sink_->SignalError(SerialSendError::DISCONNECTED);
}

void SerialPort::OnOpen(
    mojo::PendingReceiver<device::mojom::blink::SerialPortClient>
        client_receiver,
    mojo::PendingRemote<device::mojom::blink::SerialPort> port) {
  if (!port) {
    open_resolver_->RejectWithDOMException(DOMExceptionCode::kNetworkError,
                                           kOpenError);
    open_resolver_ = nullptr;
    return;
  }

  auto* execution_context = GetExecutionContext();
  feature_handle_for_scheduler_ =
      execution_context->GetScheduler()->RegisterFeature(
          SchedulingPolicy::Feature::kWebSerial,
          SchedulingPolicy{SchedulingPolicy::DisableAggressiveThrottling()});

  port_.Bind(std::move(port),
             execution_context->GetTaskRunner(TaskType::kMiscPlatformAPI));
  port_.set_disconnect_handler(
      WTF::BindOnce(&SerialPort::OnConnectionError, WrapWeakPersistent(this)));
  client_receiver_.Bind(
      std::move(client_receiver),
      execution_context->GetTaskRunner(TaskType::kMiscPlatformAPI));

  open_resolver_->Resolve();
  open_resolver_ = nullptr;
}

void SerialPort::OnGetSignals(
    ScriptPromiseResolver<SerialInputSignals>* resolver,
    device::mojom::blink::SerialPortControlSignalsPtr mojo_signals) {
  DCHECK(signal_resolvers_.Contains(resolver));
  signal_resolvers_.erase(resolver);

  if (!mojo_signals) {
    resolver->RejectWithDOMException(DOMExceptionCode::kNetworkError,
                                     "Failed to get control signals.");
    return;
  }

  auto* signals = MakeGarbageCollected<SerialInputSignals>();
  signals->setDataCarrierDetect(mojo_signals->dcd);
  signals->setClearToSend(mojo_signals->cts);
  signals->setRingIndicator(mojo_signals->ri);
  signals->setDataSetReady(mojo_signals->dsr);
  resolver->Resolve(signals);
}

void SerialPort::OnSetSignals(ScriptPromiseResolver<IDLUndefined>* resolver,
                              bool success) {
  DCHECK(signal_resolvers_.Contains(resolver));
  signal_resolvers_.erase(resolver);

  if (!success) {
    resolver->RejectWithDOMException(DOMExceptionCode::kNetworkError,
                                     "Failed to set control signals.");
    return;
  }

  resolver->Resolve();
}

void SerialPort::OnClose() {
  read_fatal_ = false;
  write_fatal_ = false;
  port_.reset();
  client_receiver_.reset();

  DCHECK(IsClosing());
  close_resolver_->Resolve();
  close_resolver_ = nullptr;
  feature_handle_for_scheduler_.reset();
}

}  // namespace blink

"""

```