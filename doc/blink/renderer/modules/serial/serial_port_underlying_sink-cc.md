Response:
Let's break down the thought process for analyzing this C++ code and generating the comprehensive response.

**1. Understanding the Core Functionality:**

* **Identify the Class:** The first step is to recognize the main class, `SerialPortUnderlyingSink`. The name itself suggests its role:  it's the *underlying* implementation for a *sink* associated with a `SerialPort`. A "sink" in the context of streams usually means something that consumes data.
* **Look at the Constructor:**  The constructor takes a `SerialPort*` and a `mojo::ScopedDataPipeProducerHandle`. This immediately hints at a connection to the `SerialPort` and the use of Mojo for inter-process communication (data pipes). The `watcher_` is also initialized here, pointing towards asynchronous handling of data availability.
* **Examine Public Methods:**  The public methods (`start`, `write`, `close`, `abort`) directly correspond to the standard `WritableStreamSink` interface in the Streams API. This confirms the class's role in implementing the writing side of a serial port stream.
* **Analyze Key Data Members:**  `data_pipe_`, `watcher_`, `serial_port_`, `buffer_source_`, `pending_operation_`, `offset_`, `abort_handle_` are crucial. Understanding their purpose (data pipe for sending, watcher for async notifications, serial port object, data to be written, a promise for the current operation, the current position in the data, and a handle for aborting) is key to understanding the code's flow.

**2. Tracing the Data Flow (Conceptual):**

* **`write()`:**  Data comes in as a JavaScript `ArrayBuffer` or `ArrayBufferView`. It's converted to a `V8BufferSource`. The data is then written to the `data_pipe_`. The `watcher_` is used to wait for the pipe to be writable.
* **`OnHandleReady()` and `WriteData()`:** These methods handle the asynchronous writing to the data pipe. `WriteData()` attempts to write data, and if the pipe is full, `watcher_` waits for it to become writable again.
* **`close()`:**  Signals the end of the writing process. It calls `serial_port_->Drain()`, indicating it's waiting for the serial port to finish sending any buffered data.
* **`abort()`:**  Stops the writing process abruptly. It can either flush the remaining data or just close the connection depending on whether the port is already closing.
* **`SignalError()`:** Handles errors that occur during the writing process, propagating them back to JavaScript via a rejected promise or an error on the stream controller.

**3. Connecting to JavaScript, HTML, and CSS:**

* **JavaScript:** The core connection is the Streams API. The `SerialPort` API in JavaScript allows creating writable streams that are backed by this C++ code. Keywords like `WritableStream`, `getWriter()`, `write()`, `close()`, and `abort()` are essential.
* **HTML:**  HTML provides the UI elements that trigger the JavaScript code interacting with the Serial Port API (e.g., buttons to connect, send data).
* **CSS:** CSS is purely for styling and doesn't directly interact with this C++ code.

**4. Logical Reasoning and Examples:**

* **Assumptions:**  The code assumes a functioning Mojo data pipe and a valid `SerialPort` object.
* **Input/Output:** For `write()`, the input is a JavaScript `ArrayBuffer` or `ArrayBufferView`. The output is a promise that resolves when the write is successful or rejects on error.
* **Error Handling:** The `SignalError()` method clearly outlines the types of errors and how they are propagated.

**5. Identifying User/Programming Errors:**

* **Detached Buffers:**  The code explicitly handles detached `ArrayBuffer`s, which is a common JavaScript memory management concern.
* **Incorrect Data Types:** While not explicitly handled *in this specific file*, the JavaScript API would perform type checking before reaching this C++ code.
* **Attempting Writes After Closing:** The checks for `pending_operation_` and the documentation highlight that `close()` is only called after pending writes are complete. Trying to write after closing would likely lead to errors.

**6. Debugging and User Steps:**

* **User Steps:**  Think about the typical user workflow: selecting a serial port, connecting, sending data, and then potentially disconnecting or encountering errors.
* **Debugging:** Focus on the data flow. Set breakpoints in the JavaScript when `write()` is called, then trace into the C++ code. Examine the state of `data_pipe_`, `offset_`, and `pending_operation_`. Look for error conditions that might lead to `SignalError()`.

**7. Structuring the Response:**

* **Start with a high-level summary:** What is the file's purpose?
* **Break down the functionality:**  Go through the key methods and data members.
* **Connect to web technologies:** Explain the relationship to JavaScript, HTML, and CSS.
* **Provide examples:** Illustrate the concepts with code snippets.
* **Discuss error scenarios:**  Highlight potential issues.
* **Explain debugging:** Offer guidance on how to investigate problems.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** "This file just sends data to the serial port."  **Correction:** It's more nuanced than that. It manages the asynchronous writing process, handles errors, and integrates with the Streams API.
* **Focusing too much on low-level details:**  **Correction:**  Need to balance the technical details with the higher-level purpose and its connection to web technologies.
* **Not enough emphasis on the Streams API:** **Correction:** The Streams API is the key interface, and that should be emphasized more strongly.

By following these steps, combining code analysis with knowledge of web technologies and common programming concepts, we can generate a comprehensive and accurate explanation of the given C++ source code file.
这个C++源代码文件 `serial_port_underlying_sink.cc` 实现了 Chromium Blink 引擎中用于向串行端口（Serial Port）写入数据的底层机制。它作为 Web Serial API 中 `WritableStreamSink` 的一个具体实现，负责接收来自 JavaScript 的数据块，并通过 Mojo 管道将其发送到浏览器进程之外的设备服务进行实际的串行通信。

以下是该文件的功能列表，并解释了它与 JavaScript、HTML 和 CSS 的关系，以及可能的使用错误和调试线索：

**功能列表:**

1. **实现 `WritableStreamSink` 接口:**  该类 `SerialPortUnderlyingSink` 实现了 `WritableStreamSink` 接口，这是 Web Streams API 中定义的可写流的底层接口。这意味着它可以接收来自 JavaScript 可写流的数据块。

2. **管理 Mojo 数据管道:**  使用 Mojo `ScopedDataPipeProducerHandle` 创建一个数据管道，用于将要写入串行端口的数据发送到浏览器进程之外的设备服务。

3. **异步写入数据:**  通过 `write()` 方法接收来自 JavaScript 的数据块（`ArrayBuffer` 或 `ArrayBufferView`），并将其写入 Mojo 数据管道。这个过程是异步的，使用了 `mojo::SimpleWatcher` 来监听数据管道是否可写。

4. **处理写入完成、错误和关闭:**
   - `OnHandleReady()`: 当 Mojo 数据管道准备好写入数据时被调用，继续写入操作。
   - `OnFlushOrDrain()`: 在 `close()` 或 `abort()` 操作完成后被调用，表示数据已刷新或排空。
   - `SignalError()`:  当发生串行端口写入错误时被调用，将错误信息传递回 JavaScript。
   - `PipeClosed()`: 当 Mojo 数据管道关闭时被调用，清理资源。

5. **支持流的启动、关闭和中止:**
   - `start()`:  处理可写流的启动逻辑，例如关联中止信号。
   - `close()`:  处理可写流的关闭逻辑，等待所有未完成的写入操作完成，并通知设备服务刷新缓冲区。
   - `abort()`:  处理可写流的中止逻辑，停止当前的写入操作，并可以选择刷新缓冲区。

6. **关联 `SerialPort` 对象:**  持有 `SerialPort` 对象的指针，以便在需要时调用其方法，例如刷新缓冲区 (`Drain` 和 `Flush`) 和通知端口已关闭 (`UnderlyingSinkClosed`).

7. **处理中止信号:**  监听关联的可写流的中止信号，并在流被中止时执行相应的清理操作 (`OnAborted()`).

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**  这个 C++ 文件是 Web Serial API 的底层实现的一部分，直接与 JavaScript 代码交互。当 JavaScript 代码使用 `WritableStream` 的 `getWriter()` 方法获取一个写入器，并调用其 `write()`、`close()` 或 `abort()` 方法时，最终会调用到 `SerialPortUnderlyingSink` 相应的方法。

   **举例说明:**

   ```javascript
   // JavaScript 代码
   navigator.serial.requestPort()
     .then(port => port.open({ baudRate: 9600 }))
     .then(() => port.writable.getWriter())
     .then(writer => {
       const data = new Uint8Array([0x01, 0x02, 0x03]);
       return writer.write(data); // 调用 SerialPortUnderlyingSink::write
     })
     .then(() => writer.close()); // 调用 SerialPortUnderlyingSink::close
   ```

   在这个例子中，`writer.write(data)` 会触发 `SerialPortUnderlyingSink::write` 方法，将 `data` 写入底层的数据管道。`writer.close()` 会触发 `SerialPortUnderlyingSink::close` 方法。

* **HTML:**  HTML 主要负责提供用户界面元素，例如按钮，用于触发与 Web Serial API 相关的 JavaScript 代码。HTML 本身不直接与 `serial_port_underlying_sink.cc` 交互。

   **举例说明:**

   ```html
   <!DOCTYPE html>
   <html>
   <head>
     <title>Serial Port Example</title>
   </head>
   <body>
     <button id="sendButton">Send Data</button>
     <script>
       document.getElementById('sendButton').addEventListener('click', () => {
         navigator.serial.requestPort()
           .then(port => port.open({ baudRate: 9600 }))
           .then(() => port.writable.getWriter())
           .then(writer => {
             const data = new Uint8Array([0x0A]);
             return writer.write(data);
           });
       });
     </script>
   </body>
   </html>
   ```

   在这个例子中，点击 "Send Data" 按钮会执行 JavaScript 代码，最终调用到 `SerialPortUnderlyingSink::write`。

* **CSS:** CSS 负责网页的样式，与 `serial_port_underlying_sink.cc` 没有直接关系。

**逻辑推理与假设输入/输出:**

**假设输入 (SerialPortUnderlyingSink::write):**

* `script_state`:  当前的 JavaScript 执行上下文。
* `chunk`:  一个 `ScriptValue`，通常是一个 `ArrayBuffer` 或 `ArrayBufferView`，包含要发送的字节数据。例如，`Uint8Array([0x41, 0x42, 0x43])` 代表发送 ASCII 字符 "ABC"。
* `controller`:  关联的 `WritableStreamDefaultController` 对象。
* `exception_state`:  用于报告异常状态。

**逻辑推理 (SerialPortUnderlyingSink::write):**

1. 将 `chunk` 转换为可读的字节序列 (`buffer_source_`)。
2. 创建一个 `ScriptPromiseResolver` 来跟踪写入操作的状态。
3. 调用 `WriteData()` 尝试将数据写入 Mojo 数据管道。

**假设输出 (取决于 `WriteData()` 的结果):**

* **成功写入 (Mojo 返回 `MOJO_RESULT_OK`)**:
    - 如果所有数据都已写入，`pending_operation_` 的 Promise 将会被解决 (resolve)。
    - 如果数据管道暂时写满，`watcher_` 将被激活，等待管道再次可写。
* **管道关闭 (Mojo 返回 `MOJO_RESULT_FAILED_PRECONDITION`)**:
    - 调用 `PipeClosed()` 清理资源。
    - `pending_operation_` 的 Promise 不会被解决，后续操作可能会失败。
* **其他错误 (Mojo 返回其他错误码)**:
    - 可能会触发 `NOTREACHED()`，表示预期之外的情况。

**假设输入 (用户操作导致):**

用户在网页上点击一个 "发送" 按钮，该按钮的事件监听器调用了 JavaScript 的 `writer.write(data)` 方法，其中 `data` 是用户想要通过串口发送的数据。

**假设输出 (最终效果):**

如果一切正常，`data` 中的字节数据最终会通过串行端口发送到连接的外部设备。`writer.write(data)` 返回的 Promise 会在数据成功写入底层管道后 resolve。

**用户或编程常见的使用错误:**

1. **尝试在端口未打开或关闭后写入:**  JavaScript 代码应该确保在调用 `writer.write()` 之前端口已经成功打开，并且在端口关闭后不再尝试写入。否则，可能会导致错误或未定义的行为。

   **举例:**

   ```javascript
   let writer;
   navigator.serial.requestPort()
     .then(port => port.open({ baudRate: 9600 }))
     .then(() => port.writable.getWriter())
     .then(w => { writer = w; });

   // 稍后在某个事件中尝试写入，但可能端口已经关闭
   function sendData() {
     if (writer) {
       writer.write(new Uint8Array([0x0F]));
     } else {
       console.error("Writer is not available. Port might be closed.");
     }
   }
   ```

2. **写入的数据格式不正确:**  虽然 `SerialPortUnderlyingSink` 接收的是 `ArrayBuffer` 或 `ArrayBufferView`，但实际的设备可能期望特定格式的数据。确保发送的数据与设备期望的格式匹配。

3. **在 `close()` 操作完成前销毁 `WritableStream` 或 `WritableStreamDefaultWriter`:** 这可能会导致资源泄漏或未完成的操作。应该等待 `writer.close()` 返回的 Promise resolve 后再进行清理操作。

4. **忽略 `write()` 操作返回的 Promise:**  `writer.write()` 返回一个 Promise，它会在数据成功写入底层管道后 resolve，或在发生错误时 reject。忽略这个 Promise 可能导致无法捕获和处理错误。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户与网页交互:** 用户在浏览器中打开一个使用 Web Serial API 的网页。
2. **JavaScript 代码执行:** 网页上的 JavaScript 代码调用 `navigator.serial.requestPort()` 请求访问串行端口。
3. **用户选择串行端口:** 浏览器会提示用户选择一个可用的串行端口。
4. **JavaScript 代码打开端口:** 用户选择端口后，JavaScript 代码调用 `port.open()` 打开选定的串行端口。
5. **获取可写流的写入器:** JavaScript 代码调用 `port.writable.getWriter()` 获取一个 `WritableStreamDefaultWriter` 对象。
6. **调用 `writer.write()`:** JavaScript 代码调用 `writer.write(data)` 尝试向串行端口发送数据。
7. **Blink 引擎处理 `write()` 调用:**  `writer.write()` 的调用会最终传递到 Blink 引擎中 `SerialPort` 相关的 JavaScript 绑定代码。
8. **创建 `SerialPortUnderlyingSink` (如果需要):** 如果这是第一次写入，或者之前的 sink 已经失效，可能会创建一个 `SerialPortUnderlyingSink` 实例。
9. **调用 `SerialPortUnderlyingSink::write()`:**  Blink 引擎会调用 `serial_port_underlying_sink.cc` 中的 `SerialPortUnderlyingSink::write()` 方法，并将要发送的数据传递给它。
10. **数据写入 Mojo 管道:** `SerialPortUnderlyingSink::write()` 将数据写入 Mojo 数据管道。
11. **设备服务处理数据:** 浏览器进程之外的设备服务会监听这个 Mojo 管道，接收数据并将其发送到实际的串行端口。

**调试线索:**

* **在 JavaScript 代码中设置断点:**  在调用 `writer.write()` 的地方设置断点，检查要发送的数据是否正确。
* **在 `SerialPortUnderlyingSink::write()` 中设置断点:**  检查该方法是否被调用，以及接收到的数据是否与 JavaScript 代码中发送的数据一致。
* **检查 Mojo 数据管道的状态:**  可以使用 Chromium 的内部工具或日志来检查 Mojo 数据管道的状态，例如是否正常连接，是否有数据流动。
* **查看 Chromium 的串口日志:** Chromium 通常会有与串口通信相关的日志输出，可以帮助诊断底层通信问题。
* **检查设备驱动和硬件:**  确保串行端口设备驱动已正确安装，并且硬件连接正常。
* **使用串口监视工具:** 使用第三方的串口监视工具来捕获实际通过串口发送和接收的数据，以验证数据是否正确发送。

总而言之，`serial_port_underlying_sink.cc` 是 Web Serial API 中至关重要的底层组件，它桥接了 JavaScript 的数据操作和操作系统底层的串行通信机制，负责高效、可靠地将数据从网页发送到外部设备。 理解它的功能和交互方式对于调试 Web Serial API 相关的问题至关重要。

### 提示词
```
这是目录为blink/renderer/modules/serial/serial_port_underlying_sink.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/serial/serial_port_underlying_sink.h"

#include "base/numerics/safe_conversions.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview.h"
#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_controller.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_piece.h"
#include "third_party/blink/renderer/modules/serial/serial_port.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"

namespace blink {

namespace {
using ::device::mojom::blink::SerialSendError;
}

SerialPortUnderlyingSink::SerialPortUnderlyingSink(
    SerialPort* serial_port,
    mojo::ScopedDataPipeProducerHandle handle)
    : data_pipe_(std::move(handle)),
      watcher_(FROM_HERE, mojo::SimpleWatcher::ArmingPolicy::MANUAL),
      serial_port_(serial_port) {
  watcher_.Watch(data_pipe_.get(), MOJO_HANDLE_SIGNAL_WRITABLE,
                 MOJO_TRIGGER_CONDITION_SIGNALS_SATISFIED,
                 WTF::BindRepeating(&SerialPortUnderlyingSink::OnHandleReady,
                                    WrapWeakPersistent(this)));
}

ScriptPromise<IDLUndefined> SerialPortUnderlyingSink::start(
    ScriptState* script_state,
    WritableStreamDefaultController* controller,
    ExceptionState& exception_state) {
  script_state_ = script_state;
  controller_ = controller;

  class AbortAlgorithm final : public AbortSignal::Algorithm {
   public:
    explicit AbortAlgorithm(SerialPortUnderlyingSink* sink) : sink_(sink) {}

    void Run() override { sink_->OnAborted(); }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(sink_);
      Algorithm::Trace(visitor);
    }

   private:
    Member<SerialPortUnderlyingSink> sink_;
  };

  DCHECK(!abort_handle_);
  abort_handle_ = controller->signal()->AddAlgorithm(
      MakeGarbageCollected<AbortAlgorithm>(this));

  return ToResolvedUndefinedPromise(script_state);
}

ScriptPromise<IDLUndefined> SerialPortUnderlyingSink::write(
    ScriptState* script_state,
    ScriptValue chunk,
    WritableStreamDefaultController* controller,
    ExceptionState& exception_state) {
  // There can only be one call to write() in progress at a time.
  DCHECK(!buffer_source_);
  DCHECK_EQ(0u, offset_);
  DCHECK(!pending_operation_);

  buffer_source_ = V8BufferSource::Create(script_state->GetIsolate(),
                                          chunk.V8Value(), exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  pending_operation_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
          script_state, exception_state.GetContext());
  auto promise = pending_operation_->Promise();

  WriteData();
  return promise;
}

ScriptPromise<IDLUndefined> SerialPortUnderlyingSink::close(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  // The specification guarantees that this will only be called after all
  // pending writes have been completed.
  DCHECK(!pending_operation_);

  watcher_.Cancel();
  data_pipe_.reset();
  abort_handle_.Clear();

  pending_operation_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
          script_state, exception_state.GetContext());
  serial_port_->Drain(WTF::BindOnce(&SerialPortUnderlyingSink::OnFlushOrDrain,
                                    WrapPersistent(this)));
  return pending_operation_->Promise();
}

ScriptPromise<IDLUndefined> SerialPortUnderlyingSink::abort(
    ScriptState* script_state,
    ScriptValue reason,
    ExceptionState& exception_state) {
  // The specification guarantees that this will only be called after all
  // pending writes have been completed.
  DCHECK(!pending_operation_);

  watcher_.Cancel();
  data_pipe_.reset();
  abort_handle_.Clear();

  // If the port is closing the flush will be performed when it closes so we
  // don't need to do it here.
  if (serial_port_->IsClosing()) {
    serial_port_->UnderlyingSinkClosed();
    return ToResolvedUndefinedPromise(script_state);
  }

  pending_operation_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
          script_state, exception_state.GetContext());
  serial_port_->Flush(device::mojom::blink::SerialPortFlushMode::kTransmit,
                      WTF::BindOnce(&SerialPortUnderlyingSink::OnFlushOrDrain,
                                    WrapPersistent(this)));
  return pending_operation_->Promise();
}

void SerialPortUnderlyingSink::SignalError(SerialSendError error) {
  watcher_.Cancel();
  data_pipe_.reset();
  abort_handle_.Clear();

  ScriptState* script_state = pending_operation_
                                  ? pending_operation_->GetScriptState()
                                  : script_state_.Get();
  ScriptState::Scope script_state_scope(script_state_);

  v8::Isolate* isolate = script_state->GetIsolate();
  v8::Local<v8::Value> exception;
  switch (error) {
    case SerialSendError::NONE:
      NOTREACHED();
    case SerialSendError::DISCONNECTED:
      exception = V8ThrowDOMException::CreateOrDie(
          isolate, DOMExceptionCode::kNetworkError,
          "The device has been lost.");
      break;
    case SerialSendError::SYSTEM_ERROR:
      exception = V8ThrowDOMException::CreateOrDie(
          isolate, DOMExceptionCode::kUnknownError,
          "An unknown system error has occurred.");
      break;
  }

  if (pending_operation_) {
    pending_operation_->Reject(exception);
    pending_operation_ = nullptr;
  } else {
    controller_->error(script_state_, ScriptValue(isolate, exception));
  }

  serial_port_->UnderlyingSinkClosed();
}

void SerialPortUnderlyingSink::Trace(Visitor* visitor) const {
  visitor->Trace(serial_port_);
  visitor->Trace(script_state_);
  visitor->Trace(controller_);
  visitor->Trace(abort_handle_);
  visitor->Trace(buffer_source_);
  visitor->Trace(pending_operation_);
  UnderlyingSinkBase::Trace(visitor);
}

void SerialPortUnderlyingSink::OnAborted() {
  watcher_.Cancel();
  abort_handle_.Clear();

  // Rejecting |pending_operation_| allows the rest of the process of aborting
  // the stream to be handled by abort().
  if (pending_operation_) {
    ScriptState* script_state = pending_operation_->GetScriptState();
    pending_operation_->Reject(controller_->signal()->reason(script_state));
    pending_operation_ = nullptr;
  }
}

void SerialPortUnderlyingSink::OnHandleReady(MojoResult result,
                                             const mojo::HandleSignalsState&) {
  switch (result) {
    case MOJO_RESULT_OK:
      WriteData();
      break;
    case MOJO_RESULT_FAILED_PRECONDITION:
      PipeClosed();
      break;
    default:
      NOTREACHED();
  }
}

void SerialPortUnderlyingSink::OnFlushOrDrain() {
  // If pending_operation_ is nullptr, that means SignalError happened before
  // flush finished and SerialPort::UnderlyingSinkClosed has been called.
  if (pending_operation_) {
    pending_operation_->Resolve();
    pending_operation_ = nullptr;
    serial_port_->UnderlyingSinkClosed();
  }
}

void SerialPortUnderlyingSink::WriteData() {
  DCHECK(data_pipe_);
  DCHECK(pending_operation_);
  DCHECK(buffer_source_);

  DOMArrayPiece array_piece(buffer_source_);
  // From https://webidl.spec.whatwg.org/#dfn-get-buffer-source-copy, if the
  // buffer source is detached then an empty byte sequence is returned, which
  // means the write is complete.
  if (array_piece.IsDetached()) {
    buffer_source_ = nullptr;
    offset_ = 0;
    pending_operation_->Resolve();
    pending_operation_ = nullptr;
    return;
  }

  size_t actually_written_bytes = 0;
  MojoResult result =
      data_pipe_->WriteData(array_piece.ByteSpan().subspan(offset_),
                            MOJO_WRITE_DATA_FLAG_NONE, actually_written_bytes);
  switch (result) {
    case MOJO_RESULT_OK:
      offset_ += actually_written_bytes;
      if (offset_ == array_piece.ByteLength()) {
        buffer_source_ = nullptr;
        offset_ = 0;
        pending_operation_->Resolve();
        pending_operation_ = nullptr;
        break;
      }
      [[fallthrough]];
    case MOJO_RESULT_SHOULD_WAIT:
      watcher_.ArmOrNotify();
      break;
    case MOJO_RESULT_FAILED_PRECONDITION:
      PipeClosed();
      break;
    default:
      NOTREACHED();
  }
}

void SerialPortUnderlyingSink::PipeClosed() {
  watcher_.Cancel();
  data_pipe_.reset();
  abort_handle_.Clear();
}

void SerialPortUnderlyingSink::Dispose() {
  // Ensure that `watcher_` is disarmed so that `OnHandleReady()` is not called
  // after this object becomes garbage.
  PipeClosed();
}

}  // namespace blink
```