Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

**1. Initial Reading and Goal Identification:**

The first step is a quick skim of the code to get a general idea of what it does. Keywords like `TCPReadableStreamWrapper`, `ReadableByteStreamWrapper`, `mojo::ScopedDataPipeConsumerHandle`, `Pull`, `CloseStream`, `ErrorStream`, and the presence of callbacks (`on_close_`) immediately suggest this code is about handling incoming data from a TCP socket and presenting it as a JavaScript ReadableStream. The file path (`blink/renderer/modules/direct_sockets`) reinforces this. The goal is to explain the functionality, its relation to web technologies, potential issues, and how a user might trigger this code.

**2. Deconstructing the Class:**

Next, I'd examine the class members and methods systematically.

* **Constructor:**  What are the inputs? `ScriptState`, `CloseOnceCallback`, and `mojo::ScopedDataPipeConsumerHandle`. This tells me it's part of the Blink rendering engine (due to `ScriptState`) and interacts with the Mojo IPC system for receiving data (due to the data pipe). The watchers (`read_watcher_`, `close_watcher_`) signal asynchronous operations. The constructor also initializes the JavaScript ReadableStream and its controller.

* **`OnHandleReady`:** This is clearly a callback for the `read_watcher_`. It's triggered when data is available on the data pipe. The call to `Pull()` is the key action.

* **`Pull`:** This is where the actual reading from the data pipe happens. The logic branches depending on whether it's a BYOB ("bring your own buffer") read or a standard read. This connects to the different `read()` methods available in JavaScript streams. The use of `DOMArrayPiece` and `DOMUint8Array` signifies interaction with JavaScript typed arrays.

* **`CloseStream`:** Handles the explicit closing of the stream, likely initiated from JavaScript. It updates the internal state and invokes the `on_close_` callback.

* **`ErrorStream`:**  Handles errors received from the underlying TCP socket. It differentiates between graceful closure and actual errors. It also involves throwing JavaScript exceptions (`V8ThrowDOMException`). The histogram usage (`DirectSockets.TCPReadableStreamError`) indicates logging for debugging and metrics.

* **`ResetPipe`:**  Cleans up resources by cancelling watchers and resetting the data pipe.

* **`Dispose`:**  Similar to `ResetPipe`, likely for object destruction.

* **`OnHandleReset`:**  This is the callback for `close_watcher_`, triggered when the Mojo pipe is closed by the peer. It handles both normal closure and error scenarios, potentially invoking the error handler if an error was pending.

**3. Identifying Relationships with Web Technologies:**

With a good understanding of the C++ code, the next step is to connect it to JavaScript, HTML, and CSS.

* **JavaScript:** The most direct connection is with the `ReadableStream` API. This class *wraps* the underlying data source (the TCP socket) and exposes it as a JavaScript `ReadableStream`. The `enqueue` and `respond` methods in `Pull` directly correspond to how data is pushed into the JavaScript stream. The `close()` and `error()` methods on the controller are also key JavaScript API elements.

* **HTML:** While this specific C++ code doesn't directly manipulate HTML, the `direct_sockets` feature itself is accessed through JavaScript APIs that are used within web pages loaded in an HTML context.

* **CSS:**  There's generally no direct relationship between this code and CSS. CSS deals with styling, while this deals with data transfer.

**4. Logical Inference and Examples:**

Here, the goal is to illustrate the flow of data and the consequences of different actions.

* **Success Case:**  Simulating a successful data transfer involves assuming data arrives on the Mojo pipe, is read in `Pull`, and enqueued into the JavaScript stream.

* **BYOB Case:** Specifically highlight how the BYOB read path works, where the JavaScript code provides the buffer.

* **Error Case:** Demonstrate what happens when the TCP socket encounters an error, how it translates to a JavaScript error, and how the stream is closed.

**5. Common Usage Errors:**

Consider what mistakes a developer using the `direct_sockets` API (which this code supports) might make. Examples include not handling errors, trying to read after the stream is closed, or misuse of BYOB reads.

**6. Tracing User Operations:**

This is crucial for debugging. Think about the sequence of user actions that would lead to this C++ code being executed. It starts with JavaScript code using the `direct_sockets` API to establish a TCP connection. Data arriving on the socket is then handled by this wrapper. Closing the tab or the server closing the connection are also important scenarios.

**7. Structuring the Explanation:**

Finally, organize the information logically with clear headings and examples. Start with a high-level overview of the file's purpose, then delve into the details of each function, connecting it to the bigger picture. Use formatting (like bullet points and code blocks) to improve readability. The "Debugging Clues" section is essential for understanding how this code fits into the larger system.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe I should focus only on the C++ details.
* **Correction:** Realized the prompt explicitly asks for connections to JavaScript, HTML, and CSS, so the explanation needs to bridge the gap between the C++ implementation and the web API.

* **Initial thought:** I'll just describe what each function does in isolation.
* **Correction:**  Emphasized the flow of data and how the different parts of the class interact with each other and the external Mojo pipe and JavaScript.

* **Initial thought:** Just list potential errors.
* **Correction:** Provided specific, actionable examples of how a developer might misuse the API.

By following this systematic approach of reading, deconstructing, connecting, illustrating, and structuring, it's possible to generate a comprehensive and accurate explanation of the given C++ source code within the context of a web browser engine.
这个C++源代码文件 `tcp_readable_stream_wrapper.cc` 是 Chromium Blink 渲染引擎中 `direct_sockets` 模块的一部分。它的主要功能是 **将底层的 TCP socket 数据流转换为 JavaScript 可读流 (ReadableStream)**。  它充当了 C++ 网络层和 JavaScript 流 API 之间的桥梁。

以下是其功能的详细列举：

**主要功能:**

1. **创建并管理 JavaScript ReadableStream:**
   - 接收一个 Mojo `ScopedDataPipeConsumerHandle`，这个 handle 代表了 TCP 连接的数据接收端。
   - 创建一个 JavaScript 的 `ReadableByteStream` 实例，供 JavaScript 代码使用。
   - 将底层的数据管道 (Mojo data pipe) 连接到这个 JavaScript 流。

2. **从底层的 TCP socket 读取数据:**
   - 使用 Mojo 的 `SimpleWatcher` 监听数据管道上的可读事件 (`MOJO_HANDLE_SIGNAL_READABLE`)。
   - 当数据可用时 (`OnHandleReady` 回调)，调用 `Pull()` 方法。
   - `Pull()` 方法尝试从数据管道中读取数据块。

3. **将读取到的数据传递给 JavaScript:**
   - 如果 JavaScript 端使用默认的读取方式，将读取到的数据封装成 `DOMUint8Array` 并通过 `ReadableByteStreamController::enqueue()` 方法添加到 JavaScript 流中。
   - 如果 JavaScript 端使用 BYOB (Bring Your Own Buffer) 读取方式，则将数据复制到 JavaScript 提供的 `ArrayBuffer` 中，并通过 `ReadableByteStreamController::respond()` 方法通知 JavaScript。

4. **处理 TCP 连接的关闭:**
   - 使用 Mojo 的 `SimpleWatcher` 监听数据管道的关闭事件 (`MOJO_HANDLE_SIGNAL_PEER_CLOSED`)。
   - 当连接关闭时 (`OnHandleReset` 回调)，根据情况执行以下操作：
     - 如果是正常关闭，调用 JavaScript 流控制器的 `close()` 方法，通知 JavaScript 流已结束。
     - 如果在关闭前发生了错误，并且有待处理的异常 (`pending_exception_`)，则将该异常传递给 JavaScript 流控制器的 `error()` 方法。

5. **处理 TCP 连接错误:**
   - `ErrorStream()` 方法用于处理来自底层 TCP 连接的错误。
   - 记录错误码到直方图 (`DirectSockets.TCPReadableStreamError`)。
   - 如果是优雅关闭（`net::OK`），则标记状态为优雅关闭，并在管道关闭时处理。
   - 如果是真正的错误，则创建一个 JavaScript `DOMException` (NetworkError)，并将错误信息传递给 JavaScript 流控制器的 `error()` 方法。

6. **资源管理:**
   - `ResetPipe()` 方法用于清理资源，包括取消监听器和重置数据管道。
   - `Dispose()` 方法在对象不再需要时调用，用于释放资源。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件直接与 JavaScript 功能相关，它是将底层的网络数据暴露给 JavaScript 的桥梁。

**举例说明:**

假设 JavaScript 代码使用 `direct_sockets` API 创建了一个 TCP 连接并获取了可读流：

```javascript
// JavaScript 代码
async function connectAndRead() {
  const socket = await navigator.directSockets.connect('example.com', 80);
  const readableStream = socket.readable;
  const reader = readableStream.getReader();

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        console.log('读取完成');
        break;
      }
      // value 是一个 Uint8Array，包含从 socket 读取的数据
      console.log('接收到数据:', value);
    }
  } catch (error) {
    console.error('读取过程中发生错误:', error);
  } finally {
    reader.releaseLock();
    socket.close();
  }
}

connectAndRead();
```

在这个例子中：

- 当 `navigator.directSockets.connect()` 成功建立连接后，Blink 引擎会在 C++ 层创建一个 `TCPReadableStreamWrapper` 实例，并将底层的 TCP 连接的读取端封装到 Mojo 数据管道中。
- JavaScript 代码通过 `socket.readable` 获得了由 `TCPReadableStreamWrapper` 封装的 `ReadableStream` 对象。
- 当服务器向 `example.com:80` 发送数据时，底层的 TCP 连接接收到数据，Mojo 数据管道变为可读。
- `TCPReadableStreamWrapper` 的 `read_watcher_` 监听到可读事件，触发 `OnHandleReady`，进而调用 `Pull()`。
- `Pull()` 从 Mojo 数据管道读取数据，并将其通过 `Controller()->enqueue()` 方法添加到 JavaScript 的 `readableStream` 中。
- JavaScript 的 `reader.read()` Promise 会 resolve，返回包含数据的 `value` (一个 `Uint8Array`)。

**与 HTML 和 CSS 的关系：**

这个文件本身不直接涉及 HTML 和 CSS 的渲染或解析。然而，`direct_sockets` API 最终是在 HTML 页面中通过 JavaScript 代码调用的。  用户在浏览器中访问包含使用 `direct_sockets` API 的 JavaScript 代码的 HTML 页面时，这个 C++ 代码才会被执行。CSS 则与此文件几乎没有直接关系。

**逻辑推理 (假设输入与输出):**

**假设输入：**

1. Mojo 数据管道接收到来自 TCP 连接的数据：`[0x48, 0x65, 0x6c, 0x6c, 0x6f]` (代表 "Hello" 的 ASCII 码)。
2. JavaScript 端使用默认的读取方式 (非 BYOB)。

**输出：**

1. `TCPReadableStreamWrapper::Pull()` 方法被调用。
2. `Pull()` 方法从 Mojo 数据管道中读取到 `[0x48, 0x65, 0x6c, 0x6c, 0x6f]`。
3. `Pull()` 方法创建一个 `DOMUint8Array`，内容为 `[72, 101, 108, 108, 111]` (十进制表示)。
4. `ReadableByteStreamController::enqueue()` 方法被调用，将这个 `DOMUint8Array` 添加到 JavaScript 的 `ReadableStream` 中。
5. JavaScript 端 `reader.read()` 返回的 Promise 会 resolve，`value` 属性是一个 `Uint8Array`，其内容为 `[72, 101, 108, 108, 111]`。

**假设输入 (BYOB)：**

1. Mojo 数据管道接收到来自 TCP 连接的数据：`[0x57, 0x6f, 0x72, 0x6c, 0x64]` (代表 "World" 的 ASCII 码)。
2. JavaScript 端使用 BYOB 读取方式，并通过 `reader.read(buffer)` 提供了一个 `Uint8Array` 类型的 `buffer`。

**输出：**

1. `TCPReadableStreamWrapper::Pull()` 方法被调用。
2. `Pull()` 方法从 Mojo 数据管道中读取到 `[0x57, 0x6f, 0x72, 0x6c, 0x64]`。
3. `Pull()` 方法将读取到的数据复制到 JavaScript 提供的 `buffer` 中。
4. `ReadableByteStreamController::respond()` 方法被调用，告知 JavaScript 实际读取的字节数 (5)。
5. JavaScript 端 `reader.read(buffer)` 返回的 Promise 会 resolve，`value` 属性是提供的 `buffer`，其内容已被填充为 `[87, 111, 114, 108, 100]`。

**用户或编程常见的使用错误：**

1. **未处理读取错误:** JavaScript 代码没有正确处理 `reader.read()` 返回的 Promise 的 rejection 情况，可能导致程序在网络错误发生时崩溃或行为异常。

   ```javascript
   // 错误示例
   reader.read().then(({ done, value }) => {
       // ... 处理数据
   });

   // 正确示例
   reader.read().then(({ done, value }) => {
       // ... 处理数据
   }).catch(error => {
       console.error("读取错误:", error);
       // ... 进行错误处理，例如关闭 socket
   });
   ```

2. **在流关闭后尝试读取:**  JavaScript 代码在 `readableStream` 已经关闭后仍然尝试调用 `reader.read()`，这会导致 Promise 被 reject。

   ```javascript
   // 错误示例
   socket.close();
   reader.read().then(/* ... */); // 此时流可能已经关闭

   // 正确示例：在关闭流之前完成读取
   reader.read().then(({ done, value }) => {
       if (done) {
           socket.close();
       }
   });
   ```

3. **BYOB 读取缓冲区大小不足:**  在使用 BYOB 读取时，提供的 `ArrayBuffer` 或 `Uint8Array` 的大小小于实际接收到的数据量，会导致数据被截断。

   ```javascript
   // 错误示例 (假设接收到 10 字节数据)
   const buffer = new Uint8Array(5);
   reader.read(buffer).then(/* ... 只能读取前 5 个字节 */);

   // 正确示例：确保缓冲区足够大
   const buffer = new Uint8Array(10);
   reader.read(buffer).then(/* ... */);
   ```

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户访问包含相关 JavaScript 代码的网页:** 用户在浏览器地址栏输入 URL 或点击链接，加载包含使用 `direct_sockets` API 的 JavaScript 代码的 HTML 页面。

2. **JavaScript 代码执行 `navigator.directSockets.connect()`:**  页面加载完成后，JavaScript 代码开始执行，调用 `navigator.directSockets.connect('example.com', 80)` 等方法尝试建立 TCP 连接。

3. **Blink 引擎创建 `TCPReadableStreamWrapper`:**  在 C++ 层，Blink 引擎的 `direct_sockets` 模块处理连接请求，并为成功的连接创建一个 `TCPReadableStreamWrapper` 实例，将底层的 socket 数据流封装起来。

4. **JavaScript 代码获取 `ReadableStream` 并开始读取:**  JavaScript 代码通过 `socket.readable` 获取到由 `TCPReadableStreamWrapper` 提供的 `ReadableStream` 对象，并调用 `getReader()` 获取读取器，然后开始调用 `reader.read()` 方法尝试读取数据。

5. **服务器发送数据:**  远程服务器 (例如 `example.com` 的服务器) 向客户端发送数据。

6. **数据到达客户端，触发 Mojo 数据管道可读事件:**  客户端操作系统接收到来自服务器的数据，并将数据写入到与 `TCPReadableStreamWrapper` 关联的 Mojo 数据管道中，触发管道的可读事件。

7. **`TCPReadableStreamWrapper::OnHandleReady` 被调用:**  Mojo 的 `read_watcher_` 监听到可读事件，调用 `TCPReadableStreamWrapper` 的 `OnHandleReady` 回调函数。

8. **`TCPReadableStreamWrapper::Pull` 被调用:**  `OnHandleReady` 函数调用 `Pull()` 方法，开始从 Mojo 数据管道中读取数据。

9. **数据被读取并传递给 JavaScript:** `Pull()` 方法将读取到的数据封装成 `DOMUint8Array` 或复制到 BYOB 缓冲区，并通过 `enqueue()` 或 `respond()` 方法将其传递给 JavaScript 的 `ReadableStream`。

10. **JavaScript 的 `reader.read()` Promise resolve:**  JavaScript 代码中 `reader.read()` 返回的 Promise 因为有新数据到达而 resolve，并将数据传递给 JavaScript 代码进行处理。

**调试线索:**

- **断点设置:**  在 `TCPReadableStreamWrapper::OnHandleReady` 和 `TCPReadableStreamWrapper::Pull` 方法中设置断点，可以观察数据何时到达 C++ 层，以及如何被处理。
- **Mojo 日志:**  查看 Mojo 相关的日志，可以了解数据管道的状态和事件。
- **网络抓包:**  使用 Wireshark 等工具抓取网络包，可以验证数据是否正确地在客户端和服务器之间传输。
- **Chrome 开发者工具:**  使用 Chrome 开发者工具的 "Network" 标签可以查看网络请求和响应，虽然 `direct_sockets` 不走 HTTP 协议，但可以帮助理解连接的生命周期。在 "Sources" 标签中可以调试 JavaScript 代码，观察 `ReadableStream` 的状态和数据。
- **Blink 渲染引擎调试工具:**  如果需要深入调试 Blink 引擎的内部，可以使用 Blink 提供的调试工具和日志。

总而言之，`tcp_readable_stream_wrapper.cc` 负责将底层的 TCP 数据流适配到 JavaScript 的 `ReadableStream` API，使得 JavaScript 可以方便地以流的方式处理来自 TCP 连接的数据。

Prompt: 
```
这是目录为blink/renderer/modules/direct_sockets/tcp_readable_stream_wrapper.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/direct_sockets/tcp_readable_stream_wrapper.h"

#include "base/check.h"
#include "base/containers/span.h"
#include "base/metrics/histogram_functions.h"
#include "base/notreached.h"
#include "mojo/public/cpp/system/simple_watcher.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_byob_request.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_piece.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/modules/direct_sockets/stream_wrapper.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"

namespace blink {

TCPReadableStreamWrapper::TCPReadableStreamWrapper(
    ScriptState* script_state,
    CloseOnceCallback on_close,
    mojo::ScopedDataPipeConsumerHandle handle)
    : ReadableByteStreamWrapper(script_state),
      on_close_(std::move(on_close)),
      data_pipe_(std::move(handle)),
      read_watcher_(FROM_HERE, mojo::SimpleWatcher::ArmingPolicy::MANUAL),
      close_watcher_(FROM_HERE, mojo::SimpleWatcher::ArmingPolicy::AUTOMATIC) {
  read_watcher_.Watch(
      data_pipe_.get(), MOJO_HANDLE_SIGNAL_READABLE,
      MOJO_TRIGGER_CONDITION_SIGNALS_SATISFIED,
      WTF::BindRepeating(&TCPReadableStreamWrapper::OnHandleReady,
                         WrapWeakPersistent(this)));

  close_watcher_.Watch(
      data_pipe_.get(), MOJO_HANDLE_SIGNAL_PEER_CLOSED,
      MOJO_TRIGGER_CONDITION_SIGNALS_SATISFIED,
      WTF::BindRepeating(&TCPReadableStreamWrapper::OnHandleReset,
                         WrapWeakPersistent(this)));

  ScriptState::Scope scope(script_state);

  auto* source =
      ReadableByteStreamWrapper::MakeForwardingUnderlyingByteSource(this);
  SetSource(source);

  auto* readable = ReadableStream::CreateByteStream(script_state, source);
  SetReadable(readable);

  // UnderlyingByteSourceBase doesn't expose Controller() until the first call
  // to Pull(); this becomes problematic if the socket is errored beforehand -
  // calls to close() / error() will be invoked on a nullptr. Hence we obtain
  // the controller directly.
  auto* controller =
      To<ReadableByteStreamController>(readable->GetController());
  DCHECK(controller);
  SetController(controller);
}

void TCPReadableStreamWrapper::Trace(Visitor* visitor) const {
  visitor->Trace(pending_exception_);
  ReadableByteStreamWrapper::Trace(visitor);
}

void TCPReadableStreamWrapper::OnHandleReady(MojoResult result,
                                             const mojo::HandleSignalsState&) {
  switch (result) {
    case MOJO_RESULT_OK:
      Pull();
      break;

    case MOJO_RESULT_FAILED_PRECONDITION:
      // Will be handled by |close_watcher_|.
      break;

    default:
      NOTREACHED();
  }
}

void TCPReadableStreamWrapper::Pull() {
  if (!GetScriptState()->ContextIsValid())
    return;

  DCHECK(data_pipe_);

  base::span<const uint8_t> data_buffer;
  auto result =
      data_pipe_->BeginReadData(MOJO_BEGIN_READ_DATA_FLAG_NONE, data_buffer);
  switch (result) {
    case MOJO_RESULT_OK: {
      // respond() or enqueue() will only throw if their arguments are invalid
      // or the stream is errored. The code below guarantees that the length is
      // in range and the chunk is a valid view. If the stream becomes errored
      // then this method cannot be called because the watcher is disarmed.
      NonThrowableExceptionState exception_state;

      auto* script_state = GetScriptState();
      ScriptState::Scope scope(script_state);

      if (ReadableStreamBYOBRequest* request = Controller()->byobRequest()) {
        DOMArrayPiece view(request->view().Get());
        data_buffer =
            data_buffer.first(std::min(data_buffer.size(), view.ByteLength()));
        view.ByteSpan().copy_prefix_from(data_buffer);
        request->respond(script_state, data_buffer.size(), exception_state);
      } else {
        auto buffer = NotShared(DOMUint8Array::Create(data_buffer));
        Controller()->enqueue(script_state, buffer, exception_state);
      }

      result = data_pipe_->EndReadData(data_buffer.size());
      DCHECK_EQ(result, MOJO_RESULT_OK);

      break;
    }

    case MOJO_RESULT_SHOULD_WAIT:
      read_watcher_.ArmOrNotify();
      return;

    case MOJO_RESULT_FAILED_PRECONDITION:
      // Will be handled by |close_watcher_|.
      return;

    default:
      NOTREACHED() << "Unexpected result: " << result;
  }
}

void TCPReadableStreamWrapper::CloseStream() {
  // Even if we're in the process of graceful close, readable.cancel() has
  // priority.
  if (GetState() != State::kOpen && GetState() != State::kGracefullyClosing) {
    return;
  }
  SetState(State::kClosed);

  ResetPipe();
  std::move(on_close_).Run(ScriptValue());
  return;
}

void TCPReadableStreamWrapper::ErrorStream(int32_t error_code) {
  if (GetState() != State::kOpen) {
    return;
  }
  graceful_peer_shutdown_ = (error_code == net::OK);

  // Error codes are negative.
  base::UmaHistogramSparse("DirectSockets.TCPReadableStreamError", -error_code);

  auto* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  if (graceful_peer_shutdown_) {
    if (data_pipe_) {
      // This is the case where OnReadError() arrived before pipe break.
      // Set |state| to kGracefullyClosing and handle the rest in
      // OnHandleReset().
      SetState(State::kGracefullyClosing);
    } else {
      // This is the case where OnReadError() arrived after pipe break.
      // Since all data has already been read, we can simply close the
      // controller, set |state| to kClosed and invoke the closing callback.
      SetState(State::kClosed);
      DCHECK(ReadableStream::IsReadable(Readable()));
      NonThrowableExceptionState exception_state;
      Controller()->close(script_state, exception_state);
      std::move(on_close_).Run(ScriptValue());
    }
    return;
  }

  SetState(State::kAborted);

  auto exception = ScriptValue(
      script_state->GetIsolate(),
      V8ThrowDOMException::CreateOrDie(script_state->GetIsolate(),
                                       DOMExceptionCode::kNetworkError,
                                       String{"Stream aborted by the remote: " +
                                              net::ErrorToString(error_code)}));

  if (data_pipe_) {
    pending_exception_ = exception;
    return;
  }

  Controller()->error(script_state, exception);
  std::move(on_close_).Run(exception);
}

void TCPReadableStreamWrapper::ResetPipe() {
  read_watcher_.Cancel();
  close_watcher_.Cancel();
  data_pipe_.reset();
}

void TCPReadableStreamWrapper::Dispose() {
  ResetPipe();
}

void TCPReadableStreamWrapper::OnHandleReset(MojoResult result,
                                             const mojo::HandleSignalsState&) {
#if DCHECK_IS_ON()
  DCHECK_EQ(result, MOJO_RESULT_OK);
  DCHECK(data_pipe_);
  DCHECK(on_close_);
  DCHECK(!(!pending_exception_.IsEmpty() && graceful_peer_shutdown_));
  if (!pending_exception_.IsEmpty() || graceful_peer_shutdown_) {
    DCHECK_NE(GetState(), State::kOpen);
  } else {
    DCHECK_EQ(GetState(), State::kOpen);
  }
#endif

  ResetPipe();

  auto* script_state = GetScriptState();
  // Happens in unit tests if V8TestingScope goes out before OnHandleReset
  // propagates.
  if (!script_state->ContextIsValid()) {
    return;
  }

  ScriptState::Scope scope(script_state);
  if (!pending_exception_.IsEmpty()) {
    Controller()->error(script_state, pending_exception_);

    SetState(State::kAborted);
    std::move(on_close_).Run(pending_exception_);

    pending_exception_.Clear();
  } else if (graceful_peer_shutdown_) {
    DCHECK(ReadableStream::IsReadable(Readable()));
    NonThrowableExceptionState exception_state;
    Controller()->close(script_state, exception_state);

    SetState(State::kClosed);
    std::move(on_close_).Run(ScriptValue());
  }
}

}  // namespace blink

"""

```