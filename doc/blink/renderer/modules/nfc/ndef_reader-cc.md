Response:
My thought process to answer the request about `ndef_reader.cc` goes like this:

1. **Understand the Core Functionality:** The filename `ndef_reader.cc` and the import of `ndef.mojom-blink.h` immediately suggest this file deals with NFC (Near-Field Communication) and reading/writing NDEF (NFC Data Exchange Format) messages. The `NDEFReader` class name confirms this.

2. **Identify Key Methods:** I scan the code for public methods of the `NDEFReader` class. The prominent ones are `scan()`, `write()`, and `makeReadOnly()`. These are the primary actions users of this API would initiate.

3. **Analyze Each Key Method:**
    * **`scan()`:** This method is clearly for initiating the reading of NFC tags. I look for how it interacts with the underlying system (via `nfc_proxy_`). I note the permission request (`GetPermissionService()->RequestPermission(...)`), the promise-based structure (`ScriptPromise`), and the handling of `AbortSignal`. The `NDEFReadingEvent` dispatch is also important.
    * **`write()`:** This is for writing NDEF messages to NFC tags. Similar to `scan()`, I see permission requests, promise handling, and `AbortSignal` integration. The creation of the `NDEFMessage` object is a crucial step here.
    * **`makeReadOnly()`:**  This method aims to make an NFC tag read-only. The pattern of permission requests, promise handling, and `AbortSignal` is consistent with the other methods.

4. **Trace the Flow and Interactions:**  I pay attention to how `NDEFReader` interacts with other components:
    * **`NFCProxy`:** This seems to be the interface to the lower-level NFC system. Methods like `StartReading`, `StopReading`, `Push`, `CancelPush`, `MakeReadOnly`, and `CancelMakeReadOnly` point to this interaction.
    * **`PermissionService`:**  Crucial for security, the code explicitly requests NFC permissions before performing operations.
    * **`AbortSignal`:**  The code thoroughly integrates with `AbortSignal`, allowing developers to cancel ongoing NFC operations.
    * **Events (`NDEFReadingEvent`, `readingerror`):** The dispatching of these events is how the API informs the web page about NFC tag interactions.
    * **Promises (`ScriptPromise`):** The asynchronous nature of NFC operations is handled using Promises, making the API easier to use in JavaScript.

5. **Identify Connections to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The methods are directly callable from JavaScript. The `ScriptPromise` return type is a key indicator. The event dispatch mechanism is also a JavaScript concept. The arguments to the methods (like `NDEFScanOptions`, `NDEFWriteOptions`, and the message data) are represented as JavaScript objects.
    * **HTML:**  The API would be invoked from JavaScript within an HTML page. The user interaction that triggers the JavaScript call (e.g., a button click) is part of the HTML structure.
    * **CSS:**  While CSS doesn't directly interact with the NFC API, it could be used to style the UI elements that trigger NFC interactions (e.g., the button to initiate a scan).

6. **Look for Logic and Assumptions:**
    * **Permissions:** The code assumes the user will grant NFC permissions. If not, the promises are rejected.
    * **Top-Level Browsing Context:**  The code enforces the restriction that NFC API can only be used in the main frame for security reasons.
    * **NFC Hardware Support:** The code implicitly assumes the underlying system has NFC capabilities. The `NOT_SUPPORTED` error handling addresses this.
    * **Correct NDEF Message Format:** The `write()` method parses the provided message and assumes it's a valid NDEF message.

7. **Consider Potential User/Programming Errors:**
    * **Permission Denied:** Forgetting to handle promise rejections due to permission denials.
    * **Incorrect API Usage:** Calling `scan()` while another scan is active.
    * **Using the API in an iframe:** Violating the top-level browsing context restriction.
    * **Providing invalid NDEF messages:** Leading to `SyntaxError`.
    * **Not handling `readingerror` events:** Missing information about NFC read errors.
    * **Forgetting to Abort:** Not using `AbortSignal` when necessary, leading to long-running, unnecessary operations.

8. **Simulate User Actions (Debugging Scenario):** I think about how a developer would end up in this code during debugging. The most likely scenario involves:
    * A user interacts with a web page (e.g., clicks a button).
    * This triggers JavaScript code that calls `navigator.nfc.ndef.scan()` or `navigator.nfc.ndef.write()`.
    * The browser then executes the corresponding C++ code in `ndef_reader.cc`.
    * Setting breakpoints in this C++ code allows developers to inspect the state of the NFC operations.

9. **Structure the Answer:** I organize the information into logical sections as requested: functionalities, relationships with web technologies, logical inferences, common errors, and debugging scenarios. I use clear and concise language and provide specific code examples where appropriate.

By following these steps, I can comprehensively analyze the provided C++ code and generate a detailed and informative answer to the user's request.
好的，我们来详细分析一下 `blink/renderer/modules/nfc/ndef_reader.cc` 这个 Chromium Blink 引擎源代码文件的功能。

**文件功能概览**

`ndef_reader.cc` 文件实现了 Web NFC API 中的 `NDEFReader` 接口。这个接口允许网页读取和写入 NFC (Near-Field Communication) 标签，并将其内容解析为 NDEF (NFC Data Exchange Format) 消息。

核心功能包括：

1. **扫描 NFC 标签 (`scan()` 方法):**  允许网页开始扫描附近的 NFC 标签。当检测到标签时，会触发 `reading` 事件，提供标签中的 NDEF 消息。
2. **写入 NFC 标签 (`write()` 方法):** 允许网页将 NDEF 消息写入到 NFC 标签。
3. **将 NFC 标签设为只读 (`makeReadOnly()` 方法):**  允许网页将 NFC 标签设置为只读，防止后续写入。
4. **处理权限请求:**  与用户的设备 NFC 功能交互需要权限，此文件负责处理权限请求。
5. **处理中止信号 (`AbortSignal`):** 允许网页在操作进行中取消扫描、写入或设为只读的操作。
6. **事件派发:**  当扫描到标签或发生错误时，会派发相应的事件（如 `reading` 和 `readingerror`）。
7. **错误处理:**  处理各种 NFC 操作中可能出现的错误，并将错误信息转换为 DOMException 抛给 JavaScript。
8. **与底层 NFC 服务交互:** 通过 `NFCProxy` 与设备底层的 NFC 服务进行通信。

**与 JavaScript, HTML, CSS 的关系及举例**

`NDEFReader` 是一个 JavaScript 可访问的接口，因此它与 JavaScript 有着直接的关系。HTML 用于构建网页结构，JavaScript 代码通常嵌入在 HTML 中来调用 `NDEFReader` 的方法。CSS 用于美化网页，与 NFC 的核心功能没有直接关系，但可以用来样式化触发 NFC 操作的 UI 元素。

**JavaScript 交互示例:**

```javascript
// HTML 中可能有一个按钮触发 NFC 扫描
const scanButton = document.getElementById('scanNFC');

scanButton.addEventListener('click', async () => {
  try {
    const reader = new NDEFReader();
    await reader.scan(); // 调用 scan() 方法

    reader.addEventListener('reading', event => {
      const { message, serialNumber } = event;
      console.log('NFC Tag Serial Number:', serialNumber);
      console.log('NDEF Message:', message);
      // 处理读取到的 NDEF 消息
    });

    reader.addEventListener('readingerror', () => {
      console.log('Error reading NFC tag.');
    });
  } catch (error) {
    console.error('NFC Scan failed:', error);
  }
});

// 写入 NFC 标签
const writeButton = document.getElementById('writeNFC');
writeButton.addEventListener('click', async () => {
  try {
    const writer = new NDEFReader();
    const textRecord = { recordType: "text", data: "Hello NFC!" };
    await writer.write({ records: [textRecord] }); // 调用 write() 方法
    console.log('Message written to NFC tag.');
  } catch (error) {
    console.error('Failed to write to NFC tag:', error);
  }
});
```

在这个例子中：

* JavaScript 代码使用 `new NDEFReader()` 创建 `NDEFReader` 实例。
* `reader.scan()` 调用了 C++ 代码中的 `NDEFReader::scan()` 方法，开始扫描 NFC 标签。
* `reader.addEventListener('reading', ...)` 监听 `reading` 事件，该事件由 C++ 代码在扫描到标签并解析出 NDEF 消息后触发。事件对象包含 `message` (NDEF 消息) 和 `serialNumber` (标签序列号)。
* `writer.write(...)` 调用了 C++ 代码中的 `NDEFReader::write()` 方法，将指定的 NDEF 消息写入标签。

**HTML 结构示例:**

```html
<!DOCTYPE html>
<html>
<head>
  <title>Web NFC Example</title>
</head>
<body>
  <button id="scanNFC">Scan NFC Tag</button>
  <button id="writeNFC">Write to NFC Tag</button>
  <script src="script.js"></script>
</body>
</html>
```

**CSS 示例 (间接关系):**

```css
#scanNFC {
  padding: 10px 20px;
  background-color: #4CAF50;
  color: white;
  border: none;
  cursor: pointer;
}
```

**逻辑推理 (假设输入与输出)**

**假设输入 (针对 `scan()` 方法):**

* **用户操作:** 用户点击了网页上的 "Scan NFC Tag" 按钮。
* **JavaScript 调用:**  JavaScript 代码调用了 `navigator.nfc.ndef.scan()`。
* **权限状态:** 用户已授予或临时授予了 NFC 权限。
* **NFC 设备状态:** 用户的设备上 NFC 功能已启用。
* **附近 NFC 标签:** 附近存在一个包含有效 NDEF 消息的 NFC 标签。

**输出:**

1. **`NDEFReader::scan()` 被调用:** C++ 代码接收到 JavaScript 的调用。
2. **权限检查:**  代码会检查 NFC 权限。
3. **底层 NFC 服务启动:** `NFCProxy` 通知底层服务开始扫描。
4. **检测到标签:** 底层服务检测到 NFC 标签。
5. **读取 NDEF 消息:** 底层服务读取标签中的数据。
6. **解析 NDEF 消息:**  数据被解析成 `device::mojom::blink::NDEFMessage` 对象。
7. **创建 `NDEFReadingEvent`:**  C++ 代码创建一个 `NDEFReadingEvent` 对象，包含解析后的 NDEF 消息。
8. **派发 `reading` 事件:**  该事件被派发到 JavaScript 环境。
9. **JavaScript 处理:**  JavaScript 中 `reading` 事件监听器被触发，可以访问 `event.message` 和 `event.serialNumber`。

**假设输入 (针对 `write()` 方法):**

* **用户操作:** 用户点击了网页上的 "Write to NFC Tag" 按钮。
* **JavaScript 调用:** JavaScript 代码调用了 `navigator.nfc.ndef.write({ records: [...] })`。
* **权限状态:** 用户已授予或临时授予了 NFC 权限。
* **NFC 设备状态:** 用户的设备上 NFC 功能已启用。
* **附近 NFC 标签:** 附近存在一个可以写入的 NFC 标签。
* **有效的 NDEF 消息数据:**  `write()` 方法接收到了格式正确的 NDEF 消息数据。

**输出:**

1. **`NDEFReader::write()` 被调用:** C++ 代码接收到 JavaScript 的调用。
2. **权限检查:** 代码会检查 NFC 权限。
3. **创建 NDEF 消息对象:**  JavaScript 传递的记录被转换为 `device::mojom::blink::NDEFMessage` 对象。
4. **底层 NFC 服务启动写入:** `NFCProxy` 通知底层服务开始写入操作。
5. **写入数据到标签:** 底层服务将 NDEF 消息写入到 NFC 标签。
6. **写入成功或失败:** 底层服务返回写入结果。
7. **Promise 解析或拒绝:**  `write()` 方法返回的 Promise 会根据写入结果被解析 (resolve) 或拒绝 (reject)。

**用户或编程常见的使用错误及举例说明**

1. **权限未授予:**
   * **错误:** 用户忘记在浏览器中授予 NFC 权限，或者在隐身模式下使用 (可能阻止权限请求)。
   * **现象:** 调用 `scan()` 或 `write()` 方法时，Promise 会被拒绝，抛出 `NotAllowedError` 类型的 `DOMException`。
   * **JavaScript 示例:**
     ```javascript
     reader.scan().catch(error => {
       if (error.name === 'NotAllowedError') {
         console.error('NFC permission denied.');
       }
     });
     ```

2. **在非顶级浏览上下文中调用:**
   * **错误:**  在 iframe 或 Web Worker 中尝试使用 Web NFC API。
   * **现象:** 调用 `scan()`, `write()`, 或 `makeReadOnly()` 会立即抛出 `InvalidStateError` 类型的 `DOMException`。
   * **C++ 代码逻辑:**  `NDEFReader::scan()`, `NDEFReader::write()`, 和 `NDEFReader::makeReadOnly()` 方法开头会检查 `DomWindow()->GetFrame()->IsMainFrame()`。

3. **并发调用 `scan()`:**
   * **错误:** 在一个 `scan()` 操作尚未完成时，再次调用 `scan()`。
   * **现象:** 第二次调用 `scan()` 会抛出 `InvalidStateError` 类型的 `DOMException`。
   * **C++ 代码逻辑:** `NDEFReader::scan()` 方法会检查 `scan_resolver_` 和 `nfc_proxy_->IsReading(this)` 来判断是否有正在进行的扫描。

4. **提供无效的 NDEF 消息数据 (`write()`):**
   * **错误:**  传递给 `write()` 方法的 `records` 数组格式不正确或包含无效的数据。
   * **现象:**  `NDEFMessage::Create()` 方法会抛出异常，导致 `write()` 方法返回的 Promise 被拒绝，可能抛出 `SyntaxError`。

5. **忘记处理 `readingerror` 事件:**
   * **错误:**  只监听了 `reading` 事件，但没有监听 `readingerror` 事件。
   * **现象:**  当 NFC 读取过程中发生错误时（例如，标签在读取过程中被移开），开发者无法得知发生了错误。
   * **建议:**  始终同时监听 `reading` 和 `readingerror` 事件。

6. **不使用 `AbortSignal` 来取消操作:**
   * **错误:**  发起了一个 `scan()` 或 `write()` 操作，但在不需要时没有提供 `AbortSignal` 来取消它。
   * **现象:**  操作会一直进行直到完成或遇到错误，浪费资源。
   * **JavaScript 示例:**
     ```javascript
     const controller = new AbortController();
     reader.scan({ signal: controller.signal });
     // ... 稍后取消
     controller.abort();
     ```

**用户操作是如何一步步的到达这里，作为调试线索**

假设用户想要使用网页上的 NFC 功能来读取一个标签：

1. **用户打开网页:** 用户在 Chrome 浏览器中打开一个包含 Web NFC 功能的网页。
2. **网页加载:** 浏览器加载 HTML、CSS 和 JavaScript 代码。
3. **用户交互:** 用户与网页上的某个元素交互，例如点击一个 "扫描 NFC 标签" 的按钮。
4. **JavaScript 执行:**  该按钮的点击事件监听器中的 JavaScript 代码被执行，通常会创建一个 `NDEFReader` 实例并调用其 `scan()` 方法。
5. **`NDEFReader::scan()` 被调用 (C++):**  JavaScript 的调用通过 Blink 的绑定机制传递到 C++ 层的 `blink::NDEFReader::scan()` 方法。
6. **权限请求 (C++):** `scan()` 方法内部会调用 `GetPermissionService()->RequestPermission(...)` 来请求 NFC 权限（如果尚未授权）。这可能会触发浏览器显示权限提示。
7. **底层 NFC 服务交互 (C++):** 如果权限被授予，`scan()` 方法会通过 `nfc_proxy_->StartReading(this, ...)` 与设备底层的 NFC 服务通信，指示其开始扫描 NFC 标签。
8. **检测到 NFC 标签 (底层):**  设备底层的 NFC 硬件检测到附近的 NFC 标签。
9. **数据读取和解析 (底层 -> C++):**  底层服务读取标签中的数据，并将其解析为 NDEF 消息。这个 NDEF 消息数据会被传递回 Blink 的 C++ 代码。
10. **`NDEFReader::OnReading()` 被调用 (C++):**  当成功读取并解析到 NDEF 消息后，`NFCProxy` 会调用 `NDEFReader::OnReading()` 方法，传递标签序列号和 NDEF 消息对象。
11. **创建和派发 `NDEFReadingEvent` (C++):** `OnReading()` 方法创建一个 `NDEFReadingEvent` 对象，并将 NDEF 消息封装在其中。然后，它调用 `DispatchEvent()` 将事件派发到 JavaScript 环境。
12. **JavaScript 事件处理:**  网页中注册的 `reading` 事件监听器被触发，可以访问事件对象中的 NDEF 消息数据。

**调试线索:**

* **断点:**  在 `NDEFReader::scan()`, `NDEFReader::ReadOnRequestPermission()`, `NDEFReader::ReadOnRequestCompleted()`, `NDEFReader::OnReading()` 等关键 C++ 方法中设置断点，可以跟踪代码的执行流程，查看权限状态、NFC 服务交互和 NDEF 消息的解析过程。
* **日志:**  使用 `DLOG` 或 `DVLOG` 在 C++ 代码中添加日志输出，记录关键变量的值和执行状态。
* **Chrome 开发者工具:**
    * **Console:** 查看 JavaScript 的 `console.log` 输出，了解 JavaScript 的执行情况和接收到的事件数据。
    * **Network:** 虽然 Web NFC 不涉及 HTTP 请求，但可以查看是否有其他网络请求导致问题。
    * **Sensors (Experimental):** 在某些版本的 Chrome 中，可能有实验性的传感器工具可以查看 NFC 相关的活动。
* **`chrome://device-log`:**  可以查看设备相关的日志信息，可能包含 NFC 相关的错误或状态。
* **Mojo Inspector (`chrome://mojo-webui/`):**  可以查看 Blink 和底层服务之间的 Mojo 通信，帮助诊断通信问题。

希望以上分析能够帮助你理解 `blink/renderer/modules/nfc/ndef_reader.cc` 的功能以及它在 Web NFC API 中的作用。

Prompt: 
```
这是目录为blink/renderer/modules/nfc/ndef_reader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/nfc/ndef_reader.h"

#include <memory>

#include "services/device/public/mojom/nfc.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ndef_make_read_only_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ndef_scan_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ndef_write_options.h"
#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/scoped_abort_state.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/modules/event_target_modules.h"
#include "third_party/blink/renderer/modules/nfc/ndef_message.h"
#include "third_party/blink/renderer/modules/nfc/ndef_reading_event.h"
#include "third_party/blink/renderer/modules/nfc/nfc_proxy.h"
#include "third_party/blink/renderer/modules/nfc/nfc_type_converters.h"
#include "third_party/blink/renderer/modules/permissions/permission_utils.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/scheduling_policy.h"

namespace blink {

using mojom::blink::PermissionName;
using mojom::blink::PermissionService;

namespace {

v8::Local<v8::Value> NDEFErrorTypeToDOMException(
    v8::Isolate* isolate,
    device::mojom::blink::NDEFErrorType error_type,
    const String& error_message) {
  switch (error_type) {
    case device::mojom::blink::NDEFErrorType::NOT_ALLOWED:
      return V8ThrowDOMException::CreateOrDie(
          isolate, DOMExceptionCode::kNotAllowedError, error_message);
    case device::mojom::blink::NDEFErrorType::NOT_SUPPORTED:
      return V8ThrowDOMException::CreateOrDie(
          isolate, DOMExceptionCode::kNotSupportedError, error_message);
    case device::mojom::blink::NDEFErrorType::NOT_READABLE:
      return V8ThrowDOMException::CreateOrDie(
          isolate, DOMExceptionCode::kNotReadableError, error_message);
    case device::mojom::blink::NDEFErrorType::INVALID_MESSAGE:
      return V8ThrowDOMException::CreateOrDie(
          isolate, DOMExceptionCode::kSyntaxError, error_message);
    case device::mojom::blink::NDEFErrorType::OPERATION_CANCELLED:
      return V8ThrowDOMException::CreateOrDie(
          isolate, DOMExceptionCode::kAbortError, error_message);
    case device::mojom::blink::NDEFErrorType::IO_ERROR:
      return V8ThrowDOMException::CreateOrDie(
          isolate, DOMExceptionCode::kNetworkError, error_message);
  }
  NOTREACHED();
}

v8::Local<v8::Value> NDEFErrorPtrToDOMException(
    v8::Isolate* isolate,
    device::mojom::blink::NDEFErrorPtr error) {
  return NDEFErrorTypeToDOMException(isolate, error->error_type,
                                     error->error_message);
}

constexpr char kNotSupportedOrPermissionDenied[] =
    "Web NFC is unavailable or permission denied.";

constexpr char kChildFrameErrorMessage[] =
    "Web NFC can only be accessed in a top-level browsing context.";

}  // namespace

class NDEFReader::ReadAbortAlgorithm final : public AbortSignal::Algorithm {
 public:
  ReadAbortAlgorithm(NDEFReader* ndef_reader, AbortSignal* signal)
      : ndef_reader_(ndef_reader), abort_signal_(signal) {}
  ~ReadAbortAlgorithm() override = default;

  void Run() override { ndef_reader_->ReadAbort(abort_signal_); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(ndef_reader_);
    visitor->Trace(abort_signal_);
    Algorithm::Trace(visitor);
  }

 private:
  Member<NDEFReader> ndef_reader_;
  Member<AbortSignal> abort_signal_;
};

class NDEFReader::WriteAbortAlgorithm final : public AbortSignal::Algorithm {
 public:
  explicit WriteAbortAlgorithm(NDEFReader* ndef_reader)
      : ndef_reader_(ndef_reader) {}
  ~WriteAbortAlgorithm() override = default;

  void Run() override { ndef_reader_->WriteAbort(); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(ndef_reader_);
    Algorithm::Trace(visitor);
  }

 private:
  Member<NDEFReader> ndef_reader_;
};

class NDEFReader::MakeReadOnlyAbortAlgorithm final
    : public AbortSignal::Algorithm {
 public:
  explicit MakeReadOnlyAbortAlgorithm(NDEFReader* ndef_reader)
      : ndef_reader_(ndef_reader) {}
  ~MakeReadOnlyAbortAlgorithm() override = default;

  void Run() override { ndef_reader_->MakeReadOnlyAbort(); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(ndef_reader_);
    Algorithm::Trace(visitor);
  }

 private:
  Member<NDEFReader> ndef_reader_;
};

// static
NDEFReader* NDEFReader::Create(ExecutionContext* context) {
  context->GetScheduler()->RegisterStickyFeature(
      SchedulingPolicy::Feature::kWebNfc,
      {SchedulingPolicy::DisableBackForwardCache()});
  return MakeGarbageCollected<NDEFReader>(context);
}

NDEFReader::NDEFReader(ExecutionContext* context)
    : ActiveScriptWrappable<NDEFReader>({}),
      ExecutionContextLifecycleObserver(context),
      nfc_proxy_(NFCProxy::From(*DomWindow())),
      permission_service_(context) {}

NDEFReader::~NDEFReader() = default;

const AtomicString& NDEFReader::InterfaceName() const {
  return event_target_names::kNDEFReader;
}

ExecutionContext* NDEFReader::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

bool NDEFReader::HasPendingActivity() const {
  return GetExecutionContext() && nfc_proxy_->IsReading(this) &&
         HasEventListeners();
}

// https://w3c.github.io/web-nfc/#the-scan-method
ScriptPromise<IDLUndefined> NDEFReader::scan(ScriptState* script_state,
                                             const NDEFScanOptions* options,
                                             ExceptionState& exception_state) {
  // https://w3c.github.io/web-nfc/#security-policies
  // WebNFC API must be only accessible from top level browsing context.
  if (!DomWindow() || !DomWindow()->GetFrame()->IsMainFrame()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kChildFrameErrorMessage);
    return EmptyPromise();
  }

  if (scan_signal_ && scan_abort_handle_) {
    scan_signal_->RemoveAlgorithm(scan_abort_handle_);
    scan_abort_handle_.Clear();
  }
  scan_signal_ = options->getSignalOr(nullptr);
  if (scan_signal_) {
    if (scan_signal_->aborted()) {
      return ScriptPromise<IDLUndefined>::Reject(
          script_state, scan_signal_->reason(script_state));
    }
    scan_abort_handle_ = scan_signal_->AddAlgorithm(
        MakeGarbageCollected<ReadAbortAlgorithm>(this, scan_signal_));
  }

  // Reject promise when there's already an ongoing scan.
  if (scan_resolver_ || nfc_proxy_->IsReading(this)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "A scan() operation is ongoing.");
    return EmptyPromise();
  }

  scan_resolver_ = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  GetPermissionService()->RequestPermission(
      CreatePermissionDescriptor(PermissionName::NFC),
      LocalFrame::HasTransientUserActivation(DomWindow()->GetFrame()),
      WTF::BindOnce(&NDEFReader::ReadOnRequestPermission, WrapPersistent(this),
                    WrapPersistent(options)));
  return scan_resolver_->Promise();
}

void NDEFReader::ReadOnRequestPermission(
    const NDEFScanOptions* options,
    mojom::blink::PermissionStatus status) {
  if (!scan_resolver_)
    return;

  ScriptState* script_state = scan_resolver_->GetScriptState();

  if (!IsInParallelAlgorithmRunnable(scan_resolver_->GetExecutionContext(),
                                     script_state)) {
    scan_resolver_.Clear();
    return;
  }

  if (status != mojom::blink::PermissionStatus::GRANTED) {
    scan_resolver_->RejectWithDOMException(DOMExceptionCode::kNotAllowedError,
                                           "NFC permission request denied.");
    scan_resolver_.Clear();
    return;
  }

  DCHECK(!scan_signal_ || !scan_signal_->aborted());

  nfc_proxy_->StartReading(
      this,
      WTF::BindOnce(&NDEFReader::ReadOnRequestCompleted, WrapPersistent(this)));
}

void NDEFReader::ReadOnRequestCompleted(
    device::mojom::blink::NDEFErrorPtr error) {
  if (!scan_resolver_)
    return;

  ScriptState* script_state = scan_resolver_->GetScriptState();

  if (!IsInParallelAlgorithmRunnable(scan_resolver_->GetExecutionContext(),
                                     script_state)) {
    scan_resolver_.Clear();
    return;
  }

  ScriptState::Scope script_state_scope(script_state);

  if (error) {
    scan_resolver_->Reject(NDEFErrorPtrToDOMException(
        script_state->GetIsolate(), std::move(error)));
  } else {
    scan_resolver_->Resolve();
  }

  scan_resolver_.Clear();
}

void NDEFReader::OnReading(const String& serial_number,
                           const device::mojom::blink::NDEFMessage& message) {
  DCHECK(nfc_proxy_->IsReading(this));
  DispatchEvent(*MakeGarbageCollected<NDEFReadingEvent>(
      event_type_names::kReading, serial_number,
      MakeGarbageCollected<NDEFMessage>(message)));
}

void NDEFReader::OnReadingError(const String& message) {
  GetExecutionContext()->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::blink::ConsoleMessageSource::kJavaScript,
      mojom::blink::ConsoleMessageLevel::kInfo, message));

  // Dispatch the event as the final step in this method as it may cause script
  // to run that destroys the execution context.
  DispatchEvent(*Event::Create(event_type_names::kReadingerror));
}

void NDEFReader::ContextDestroyed() {
  nfc_proxy_->StopReading(this);
  scan_abort_handle_.Clear();
}

void NDEFReader::ReadAbort(AbortSignal* signal) {
  nfc_proxy_->StopReading(this);
  scan_abort_handle_.Clear();

  if (!scan_resolver_)
    return;

  ScriptState* script_state = scan_resolver_->GetScriptState();

  if (!IsInParallelAlgorithmRunnable(scan_resolver_->GetExecutionContext(),
                                     script_state)) {
    scan_resolver_.Clear();
    return;
  }

  ScriptState::Scope script_state_scope(script_state);

  scan_resolver_->Reject(scan_signal_->reason(script_state));
  scan_resolver_.Clear();
}

// https://w3c.github.io/web-nfc/#writing-content
// https://w3c.github.io/web-nfc/#the-write-method
ScriptPromise<IDLUndefined> NDEFReader::write(
    ScriptState* script_state,
    const V8NDEFMessageSource* write_message,
    const NDEFWriteOptions* options,
    ExceptionState& exception_state) {
  // https://w3c.github.io/web-nfc/#security-policies
  // WebNFC API must be only accessible from top level browsing context.
  if (!DomWindow() || !DomWindow()->GetFrame()->IsMainFrame()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kChildFrameErrorMessage);
    return EmptyPromise();
  }

  std::unique_ptr<ScopedAbortState> scoped_abort_state = nullptr;
  if (auto* signal = options->getSignalOr(nullptr)) {
    if (signal->aborted()) {
      return ScriptPromise<IDLUndefined>::Reject(script_state,
                                                 signal->reason(script_state));
    }
    auto* handle =
        signal->AddAlgorithm(MakeGarbageCollected<WriteAbortAlgorithm>(this));
    scoped_abort_state = std::make_unique<ScopedAbortState>(signal, handle);
  }

  // Step 11.2: Run "create NDEF message", if this throws an exception,
  // reject p with that exception and abort these steps.
  NDEFMessage* ndef_message =
      NDEFMessage::Create(script_state, write_message, exception_state);
  if (exception_state.HadException()) {
    return EmptyPromise();
  }

  auto message = device::mojom::blink::NDEFMessage::From(ndef_message);
  DCHECK(message);

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  write_requests_.insert(resolver);

  // Add the writer to proxy's writer list for Mojo connection error
  // notification.
  nfc_proxy_->AddWriter(this);

  GetPermissionService()->RequestPermission(
      CreatePermissionDescriptor(PermissionName::NFC),
      LocalFrame::HasTransientUserActivation(DomWindow()->GetFrame()),
      WTF::BindOnce(&NDEFReader::WriteOnRequestPermission, WrapPersistent(this),
                    WrapPersistent(resolver), std::move(scoped_abort_state),
                    WrapPersistent(options), std::move(message)));

  return resolver->Promise();
}

void NDEFReader::WriteOnRequestPermission(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    std::unique_ptr<ScopedAbortState> scoped_abort_state,
    const NDEFWriteOptions* options,
    device::mojom::blink::NDEFMessagePtr message,
    mojom::blink::PermissionStatus status) {
  DCHECK(resolver);

  ScriptState* script_state = resolver->GetScriptState();

  if (!IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                     script_state)) {
    return;
  }

  ScriptState::Scope script_state_scope(script_state);

  if (status != mojom::blink::PermissionStatus::GRANTED) {
    resolver->RejectWithDOMException(DOMExceptionCode::kNotAllowedError,
                                     "NFC permission request denied.");
    return;
  }

  AbortSignal* signal =
      scoped_abort_state ? scoped_abort_state->Signal() : nullptr;
  if (signal && signal->aborted()) {
    resolver->Reject(signal->reason(script_state));
    return;
  }

  auto callback =
      WTF::BindOnce(&NDEFReader::WriteOnRequestCompleted, WrapPersistent(this),
                    WrapPersistent(resolver), std::move(scoped_abort_state));
  nfc_proxy_->Push(std::move(message),
                   device::mojom::blink::NDEFWriteOptions::From(options),
                   std::move(callback));
}

void NDEFReader::WriteOnRequestCompleted(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    std::unique_ptr<ScopedAbortState> scoped_abort_state,
    device::mojom::blink::NDEFErrorPtr error) {
  DCHECK(write_requests_.Contains(resolver));

  write_requests_.erase(resolver);

  ScriptState* script_state = resolver->GetScriptState();

  if (!IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                     script_state)) {
    return;
  }

  AbortSignal* signal =
      scoped_abort_state ? scoped_abort_state->Signal() : nullptr;

  ScriptState::Scope script_state_scope(script_state);

  if (error.is_null()) {
    resolver->Resolve();
  } else if (signal && signal->aborted()) {
    resolver->Reject(signal->reason(script_state));
  } else {
    resolver->Reject(NDEFErrorPtrToDOMException(script_state->GetIsolate(),
                                                std::move(error)));
  }
}

void NDEFReader::WriteAbort() {
  // WriteOnRequestCompleted() should always be called whether the push
  // operation is cancelled successfully or not.
  nfc_proxy_->CancelPush();
}

ScriptPromise<IDLUndefined> NDEFReader::makeReadOnly(
    ScriptState* script_state,
    const NDEFMakeReadOnlyOptions* options,
    ExceptionState& exception_state) {
  // https://w3c.github.io/web-nfc/#security-policies
  // WebNFC API must be only accessible from top level browsing context.
  if (!DomWindow() || !DomWindow()->GetFrame()->IsMainFrame()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kChildFrameErrorMessage);
    return EmptyPromise();
  }

  std::unique_ptr<ScopedAbortState> scoped_abort_state = nullptr;
  if (auto* signal = options->getSignalOr(nullptr)) {
    if (signal->aborted()) {
      return ScriptPromise<IDLUndefined>::Reject(script_state,
                                                 signal->reason(script_state));
    }
    auto* handle = signal->AddAlgorithm(
        MakeGarbageCollected<MakeReadOnlyAbortAlgorithm>(this));
    scoped_abort_state = std::make_unique<ScopedAbortState>(signal, handle);
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  make_read_only_requests_.insert(resolver);

  // Add the writer to proxy's writer list for Mojo connection error
  // notification.
  nfc_proxy_->AddWriter(this);

  GetPermissionService()->RequestPermission(
      CreatePermissionDescriptor(PermissionName::NFC),
      LocalFrame::HasTransientUserActivation(DomWindow()->GetFrame()),
      WTF::BindOnce(&NDEFReader::MakeReadOnlyOnRequestPermission,
                    WrapPersistent(this), WrapPersistent(resolver),
                    std::move(scoped_abort_state), WrapPersistent(options)));

  return resolver->Promise();
}

void NDEFReader::MakeReadOnlyOnRequestPermission(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    std::unique_ptr<ScopedAbortState> scoped_abort_state,
    const NDEFMakeReadOnlyOptions* options,
    mojom::blink::PermissionStatus status) {
  DCHECK(resolver);

  ScriptState* script_state = resolver->GetScriptState();

  if (!IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                     script_state)) {
    return;
  }

  ScriptState::Scope script_state_scope(resolver->GetScriptState());

  if (status != mojom::blink::PermissionStatus::GRANTED) {
    resolver->RejectWithDOMException(DOMExceptionCode::kNotAllowedError,
                                     "NFC permission request denied.");
    return;
  }

  AbortSignal* signal =
      scoped_abort_state ? scoped_abort_state->Signal() : nullptr;
  if (signal && signal->aborted()) {
    resolver->Reject(signal->reason(script_state));
    return;
  }

  auto callback = WTF::BindOnce(&NDEFReader::MakeReadOnlyOnRequestCompleted,
                                WrapPersistent(this), WrapPersistent(resolver),
                                std::move(scoped_abort_state));
  nfc_proxy_->MakeReadOnly(std::move(callback));
}

void NDEFReader::MakeReadOnlyOnRequestCompleted(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    std::unique_ptr<ScopedAbortState> scoped_abort_state,
    device::mojom::blink::NDEFErrorPtr error) {
  DCHECK(make_read_only_requests_.Contains(resolver));

  make_read_only_requests_.erase(resolver);

  ScriptState* script_state = resolver->GetScriptState();

  if (!IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                     script_state)) {
    return;
  }

  AbortSignal* signal =
      scoped_abort_state ? scoped_abort_state->Signal() : nullptr;

  ScriptState::Scope script_state_scope(script_state);

  if (error.is_null()) {
    resolver->Resolve();
  } else if (signal && signal->aborted()) {
    resolver->Reject(signal->reason(script_state));
  } else {
    resolver->Reject(NDEFErrorPtrToDOMException(script_state->GetIsolate(),
                                                std::move(error)));
  }
}

void NDEFReader::MakeReadOnlyAbort() {
  // MakeReadOnlyOnRequestCompleted() should always be called whether the
  // makeReadOnly operation is cancelled successfully or not.
  nfc_proxy_->CancelMakeReadOnly();
}

void NDEFReader::Trace(Visitor* visitor) const {
  visitor->Trace(nfc_proxy_);
  visitor->Trace(permission_service_);
  visitor->Trace(scan_resolver_);
  visitor->Trace(scan_signal_);
  visitor->Trace(scan_abort_handle_);
  visitor->Trace(write_requests_);
  visitor->Trace(make_read_only_requests_);
  EventTarget::Trace(visitor);
  ActiveScriptWrappable::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

PermissionService* NDEFReader::GetPermissionService() {
  if (!permission_service_.is_bound()) {
    ConnectToPermissionService(
        GetExecutionContext(),
        permission_service_.BindNewPipeAndPassReceiver(
            GetExecutionContext()->GetTaskRunner(TaskType::kMiscPlatformAPI)));
  }
  return permission_service_.get();
}

void NDEFReader::ReadOnMojoConnectionError() {
  // If |scan_resolver_| has already settled this rejection is silently ignored.
  if (!scan_resolver_)
    return;

  ScriptState* script_state = scan_resolver_->GetScriptState();

  if (!IsInParallelAlgorithmRunnable(scan_resolver_->GetExecutionContext(),
                                     script_state)) {
    scan_resolver_.Clear();
    return;
  }

  ScriptState::Scope script_state_scope(script_state);

  scan_resolver_->Reject(NDEFErrorTypeToDOMException(
      script_state->GetIsolate(),
      device::mojom::blink::NDEFErrorType::NOT_SUPPORTED,
      kNotSupportedOrPermissionDenied));
  scan_resolver_.Clear();
}

void NDEFReader::WriteOnMojoConnectionError() {
  // If the mojo connection breaks, All push requests will be rejected with a
  // default error.

  // Script may execute during a call to Reject(). Swap these sets to prevent
  // concurrent modification.
  HeapHashSet<Member<ScriptPromiseResolver<IDLUndefined>>> write_requests;
  write_requests_.swap(write_requests);
  for (ScriptPromiseResolverBase* resolver : write_requests) {
    DCHECK(resolver);

    ScriptState* script_state = resolver->GetScriptState();

    if (!IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                       script_state)) {
      continue;
    }

    ScriptState::Scope script_state_scope(script_state);

    resolver->Reject(NDEFErrorTypeToDOMException(
        script_state->GetIsolate(),
        device::mojom::blink::NDEFErrorType::NOT_SUPPORTED,
        kNotSupportedOrPermissionDenied));
  }
}

void NDEFReader::MakeReadOnlyOnMojoConnectionError() {
  // If the mojo connection breaks, All makeReadOnly requests will be rejected
  // with a default error.

  // Script may execute during a call to Reject(). Swap these sets to prevent
  // concurrent modification.
  HeapHashSet<Member<ScriptPromiseResolver<IDLUndefined>>>
      make_read_only_requests;
  make_read_only_requests_.swap(make_read_only_requests);
  for (ScriptPromiseResolverBase* resolver : make_read_only_requests) {
    DCHECK(resolver);

    ScriptState* script_state = resolver->GetScriptState();

    if (!IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                       script_state)) {
      continue;
    }

    ScriptState::Scope script_state_scope(script_state);

    resolver->Reject(NDEFErrorTypeToDOMException(
        script_state->GetIsolate(),
        device::mojom::blink::NDEFErrorType::NOT_SUPPORTED,
        kNotSupportedOrPermissionDenied));
  }
}

}  // namespace blink

"""

```