Response:
Let's break down the thought process for analyzing the `FileSystemUnderlyingSink.cc` file.

1. **Understand the Core Purpose:** The file name itself, `FileSystemUnderlyingSink.cc`, gives a strong hint. "UnderlyingSink" suggests it's an implementation detail related to writing data to the file system. The `file_system_access` directory confirms it's part of the File System Access API. Therefore, the primary function is likely to handle the low-level writing operations for this API.

2. **Identify Key Components and Interactions:** Look for classes, methods, and data members.

    * **`FileSystemUnderlyingSink` Class:** This is the main class. Its constructor takes a `writer_remote`, suggesting it communicates with another part of the system (likely the browser process).
    * **Mojo:** The presence of `mojo::PendingRemote`, `mojo::Receiver`, `mojo::DataPipeProducer`, and mentions of data pipes indicate that inter-process communication (IPC) using Mojo is a central aspect.
    * **Promises:** The `ScriptPromise` return types and `ScriptPromiseResolver` usage point to asynchronous operations and the JavaScript Promise API.
    * **`WritableStreamDefaultController`:** This suggests integration with the Streams API in JavaScript.
    * **`WriteParams` and Command Types:** These indicate support for different types of write operations beyond simple data writes (e.g., `truncate`, `seek`).
    * **`WriterHelper` Classes (`StreamWriterHelper`, `BlobWriterHelper`):** These helper classes manage the complexities of writing different data types (strings/buffers and Blobs) using data pipes.
    * **Error Handling:** The use of `ExceptionState` and the `ThrowDOMExceptionAndInvalidateSink` and `ThrowTypeErrorAndInvalidateSink` functions highlight the importance of error management.

3. **Analyze Key Methods:**  Go through the public methods of `FileSystemUnderlyingSink` and understand their roles:

    * **`start()`:**  A simple resolved promise, suggesting minimal initialization.
    * **`write()`:** This is a core method. It handles different input types (`WriteParams` or data) and delegates to `HandleParams` or `WriteData`.
    * **`close()`:** Handles closing the file writer.
    * **`abort()`:** Handles aborting the write operation.
    * **`HandleParams()`:** Processes `WriteParams` to perform `truncate`, `seek`, or `write` operations based on the command type.
    * **`WriteData()`:**  The actual implementation of writing data. It sets up data pipes and interacts with Mojo.
    * **`Truncate()`:**  Handles truncating the file.
    * **`Seek()`:** Handles changing the current write position.
    * **`WriteComplete()`, `TruncateComplete()`, `CloseComplete()`:** These are callbacks from the browser process, handling the results of asynchronous operations.

4. **Trace Data Flow (Conceptual):** Imagine a write operation initiated from JavaScript.

    * JavaScript calls a method on a `FileSystemWritableFileStream`.
    * This likely calls the `write()` method of `FileSystemUnderlyingSink`.
    * Data is prepared (converted to ArrayBuffer, Blob, etc.).
    * A Mojo data pipe is created.
    * Data is written to the data pipe.
    * A Mojo message is sent to the browser process with the consumer end of the pipe.
    * The browser process reads from the pipe and writes to the actual file.
    * The browser process sends a completion message back.
    * The `WriteComplete()` callback in `FileSystemUnderlyingSink` is invoked.
    * The JavaScript Promise is resolved or rejected.

5. **Relate to Web Standards:** Connect the code to the File System Access API specifications. Keywords like "WritableStream," "sink," "write," "truncate," and "seek" are direct mappings to the API.

6. **Consider User/Developer Perspective:** Think about how developers use this API and what errors they might encounter. Focus on the error handling logic and the conditions that trigger exceptions.

7. **Debugging Clues:**  Consider how a developer would debug issues related to file writing. The steps mentioned in the "User Operation to Reach Here" section are typical scenarios. Logs and network inspection tools (for Mojo messages, though this is more internal) would be relevant.

8. **Address Specific Prompts:** Go back to the initial request and systematically address each point:

    * **Functionality:** Summarize the core responsibilities.
    * **Relationship to JS/HTML/CSS:** Explain how the code enables file system access from the web. Provide concrete JavaScript examples. CSS relevance is minimal.
    * **Logical Reasoning (Assumptions/Inputs/Outputs):**  Focus on the data transformations and IPC involved in a write operation. Specify example input data and the expected outcome (success or specific error).
    * **Common Errors:**  Think about typical user mistakes when using the API (incorrect parameters, trying to write after closing, etc.).
    * **User Operation/Debugging:**  Outline the steps a user takes to trigger the code and how a developer might investigate issues.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just about writing data."  **Correction:** Realized it handles more than just raw writes (truncate, seek).
* **Initial thought:** "Mojo is just an implementation detail." **Correction:** Recognized that Mojo and data pipes are fundamental to how data is transferred between the renderer and the browser process.
* **Initially missed:** The significance of the `WriterHelper` classes in managing the asynchronous nature of data production and writing. **Correction:**  Analyzed their roles in handling Blobs and other data sources.
* **Didn't initially explicitly connect:** The error handling in the C++ code to the specific exceptions developers see in JavaScript. **Correction:** Made the link clearer.

By following these steps and constantly refining the understanding, a comprehensive analysis like the example answer can be constructed.
根据提供的 Chromium Blink 引擎源代码文件 `blink/renderer/modules/file_system_access/file_system_underlying_sink.cc`，我们可以列举出它的主要功能以及与其他 Web 技术（JavaScript, HTML, CSS）的关系：

**主要功能:**

1. **实现 File System Access API 的底层写入操作:**  `FileSystemUnderlyingSink` 类是 File System Access API 中 `FileSystemWritableFileStream` 接口的底层实现。它负责处理向文件写入数据的实际操作。

2. **管理与浏览器进程中文件写入器的通信:** 它通过 Mojo IPC (Inter-Process Communication) 与浏览器进程中的文件写入器 (`FileSystemAccessFileWriter`) 进行通信。这允许渲染进程（处理网页逻辑）安全地请求浏览器进程执行文件系统操作。

3. **处理不同类型的数据写入:**  它可以接收不同类型的待写入数据，包括：
    * `ArrayBuffer` 和 `ArrayBufferView` (二进制数据)
    * `Blob` (二进制大数据对象)
    * `USVString` (UTF-16 字符串)
    * 包含操作参数的对象 (`WriteParams`)，用于执行诸如 `seek` (移动文件指针) 和 `truncate` (截断文件) 等操作。

4. **支持 `WritableStream` API:**  它作为 `WritableStream` 的底层 sink 实现，这意味着 JavaScript 可以通过标准的 `WritableStream` API 来驱动文件的写入操作。

5. **处理写入过程中的错误:** 它负责捕获和处理写入过程中可能发生的各种错误，并将这些错误信息转换为 JavaScript 可以理解的异常。

6. **实现 `truncate` 和 `seek` 操作:** 除了写入数据，它还支持修改文件的大小 (`truncate`) 和移动文件内部的读写位置 (`seek`)。

7. **管理写入状态和生命周期:**  它跟踪当前的写入状态，例如是否有正在进行的写入操作，并在必要时重置与浏览器进程的连接。

**与 JavaScript, HTML, CSS 的关系:**

这个 C++ 文件本身不直接涉及 HTML 或 CSS 的解析和渲染。它的核心作用在于支持 JavaScript 中 File System Access API 的文件写入功能。

**与 JavaScript 的关系 (重要):**

* **File System Access API 的桥梁:**  `FileSystemUnderlyingSink` 是 JavaScript 中 `FileSystemWritableFileStream` 背后的 C++ 实现。当 JavaScript 代码调用 `FileSystemWritableFileStream` 的 `write()`, `truncate()`, `seek()`, 或 `close()` 方法时，最终会调用到这个 C++ 类的相应方法。

* **`WritableStream` 集成:** JavaScript 可以创建一个 `FileSystemWritableFileStream` 对象，它是一个 `WritableStream` 的实例。`FileSystemUnderlyingSink` 就是这个 `WritableStream` 的 underlying sink。JavaScript 通过 `WritableStreamDefaultWriter` 向 stream 中写入数据，这些数据会被传递给 `FileSystemUnderlyingSink` 进行处理。

* **数据类型转换:** 这个 C++ 文件负责处理 JavaScript 中不同数据类型（如 ArrayBuffer, Blob, String）到 Mojo 数据管道的转换，以便将数据传递给浏览器进程进行写入。

**举例说明 (JavaScript):**

```javascript
async function writeFile(fileHandle, content) {
  const writableStream = await fileHandle.createWritable(); // 创建可写流
  await writableStream.write(content); // 写入数据 (content 可以是字符串, ArrayBuffer, Blob 等)
  await writableStream.close();      // 关闭流
}

async function truncateFile(fileHandle, size) {
  const writableStream = await fileHandle.createWritable();
  await writableStream.truncate(size); // 截断文件
  await writableStream.close();
}

async function seekInFile(fileHandle, position) {
  const writableStream = await fileHandle.createWritable();
  await writableStream.seek(position); // 移动文件指针
  // 可以在 seek 后进行 write 操作
  await writableStream.close();
}

// 用户选择文件后，可以通过 fileHandle 调用上述函数
```

在这个例子中：

* `fileHandle.createWritable()` 在底层会创建一个与 `FileSystemUnderlyingSink` 关联的 `FileSystemWritableFileStream` 对象。
* `writableStream.write(content)`  的调用会最终触发 `FileSystemUnderlyingSink::write()` 方法，并将 `content` 数据传递给它。
* `writableStream.truncate(size)` 的调用会触发 `FileSystemUnderlyingSink::Truncate()` 方法。
* `writableStream.seek(position)` 的调用会触发 `FileSystemUnderlyingSink::Seek()` 方法。

**逻辑推理 (假设输入与输出):**

**假设输入 (JavaScript 调用 `write()`):**

* `script_state`: 当前 JavaScript 的执行状态。
* `chunk`: 一个 JavaScript 值，可能是 `ArrayBuffer`, `Blob`, `USVString`, 或者一个包含 `type: "write", data: ...` 的对象。
* `controller`:  `WritableStreamDefaultController` 对象。
* `exception_state`: 用于处理异常。

**假设 `chunk` 是一个 `USVString` ("Hello"):**

1. `FileSystemUnderlyingSink::write()` 方法会被调用。
2. 通过 `NativeValueTraits` 将 JavaScript 的字符串 "Hello" 转换为 C++ 的字符串类型。
3. 创建一个 Mojo 数据管道。
4. 将字符串 "Hello" 的 UTF-8 编码数据写入数据管道的生产者端。
5. 调用 `writer_remote_->Write()`，将数据管道的消费者端句柄和写入位置信息发送给浏览器进程。
6. 浏览器进程从数据管道读取 "Hello" 并写入到实际的文件中。
7. 浏览器进程通过 Mojo 返回写入结果（成功或失败，以及写入的字节数）。
8. `FileSystemUnderlyingSink::WriteComplete()` 方法被调用，根据结果解析 Promise。

**输出:**

* 如果写入成功，Promise 会 resolve。
* 如果写入失败，Promise 会 reject，并带有相应的 `FileSystemAccessError`。

**假设输入 (JavaScript 调用 `truncate(1024)`):**

1. `FileSystemUnderlyingSink::HandleParams()` 方法会被调用，因为 `chunk` 可能是一个 `{ type: "truncate", size: 1024 }` 的对象。
2. `HandleParams()` 判断 `params.type()` 是 `kTruncate`。
3. 调用 `FileSystemUnderlyingSink::Truncate(script_state, 1024, exception_state)`。
4. 调用 `writer_remote_->Truncate(1024, ...)`，将截断大小发送给浏览器进程。
5. 浏览器进程执行文件截断操作。
6. 浏览器进程通过 Mojo 返回操作结果（成功或失败）。
7. `FileSystemUnderlyingSink::TruncateComplete()` 方法被调用，根据结果解析 Promise。

**输出:**

* 如果截断成功，Promise 会 resolve。
* 如果截断失败，Promise 会 reject，并带有相应的 `FileSystemAccessError`。

**用户或编程常见的使用错误:**

1. **尝试在流关闭后写入:**  JavaScript 代码在调用 `writableStream.close()` 后，如果再次尝试调用 `writableStream.write()`，会导致 `FileSystemUnderlyingSink` 检测到无效状态并抛出 `InvalidStateError`。

   ```javascript
   const writableStream = await fileHandle.createWritable();
   await writableStream.close();
   await writableStream.write("some data"); // 错误：流已关闭
   ```

2. **传递无效的 `WriteParams`:**  如果 `write()` 方法接收到一个 `WriteParams` 对象，但缺少必要的参数（例如 `truncate` 缺少 `size`），`FileSystemUnderlyingSink::HandleParams()` 会抛出 `SyntaxError`。

   ```javascript
   await writableStream.write({ type: "truncate" }); // 错误：缺少 size 参数
   ```

3. **在有未完成操作时尝试关闭:** 如果在有正在进行的 `write` 或 `truncate` 操作时尝试调用 `close()`,  `FileSystemUnderlyingSink::close()` 会抛出 `InvalidStateError`。 虽然规范保证在调用 abort 后才会调用 close，但在某些异常情况下可能会发生。

4. **传递 `null` 数据给 `write` 操作:**  如果 `WriteParams` 中 `type` 为 "write" 但 `data` 为 `null`，会抛出 `TypeError`.

   ```javascript
   await writableStream.write({ type: "write", data: null }); // 错误：data 不能为 null
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在网页上触发了文件写入操作:**  这可能是用户点击了一个 "保存" 按钮，或者网页上的 JavaScript 代码自动触发了文件写入。

2. **JavaScript 代码获取了 `FileSystemFileHandle`:**  通常通过 `window.showSaveFilePicker()` 或 `DataTransferItem.getAsFileSystemHandle()` 等 API 获取。

3. **JavaScript 代码调用 `fileHandle.createWritable()`:**  这会创建一个 `FileSystemWritableFileStream` 对象，并在底层与 `FileSystemUnderlyingSink` 关联。

4. **JavaScript 代码调用 `writableStream.write(data)` 或 `writableStream.truncate(size)` 或 `writableStream.seek(position)`:**  这些调用会触发 `FileSystemUnderlyingSink` 中的相应方法。

5. **浏览器渲染进程通过 Mojo IPC 向浏览器进程发送请求:**  请求浏览器进程执行实际的文件系统操作。

6. **浏览器进程执行文件系统操作:**  例如，打开文件、写入数据、修改文件大小等。

7. **浏览器进程通过 Mojo IPC 将结果返回给渲染进程的 `FileSystemUnderlyingSink`。**

8. **`FileSystemUnderlyingSink` 根据结果解析 Promise，并通知 JavaScript 代码操作是否成功。**

**作为调试线索:**

* **查看 JavaScript 控制台的错误信息:**  如果操作失败，浏览器通常会在控制台显示相应的错误信息，例如 `DOMException: Failed to execute 'write' on 'FileSystemWritableFileStream': The stream is closed.`  这些错误信息可以帮助定位问题。

* **使用 Chrome 的开发者工具进行断点调试:**  可以在 `FileSystemUnderlyingSink.cc` 的关键方法（如 `write`, `HandleParams`, `TruncateComplete` 等）设置断点，以跟踪代码的执行流程，查看传入的参数和返回值，以及在哪个环节出现了问题。

* **检查 Mojo IPC 消息:**  虽然一般开发者不太可能直接查看 Mojo 消息，但 Chrome 内部的调试工具可以记录和分析 Mojo 消息的传递，这对于理解渲染进程和浏览器进程之间的通信非常有帮助。

* **检查浏览器进程的文件系统操作日志:**  在某些情况下，浏览器进程可能会记录文件系统操作的日志，这些日志可以提供更底层的错误信息。

总而言之，`FileSystemUnderlyingSink.cc` 是 File System Access API 实现的关键组成部分，它负责处理 JavaScript 发起的底层文件写入、截断和定位操作，并与浏览器进程安全地通信来完成这些任务。理解它的功能对于调试和理解 File System Access API 的行为至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/file_system_access/file_system_underlying_sink.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/file_system_access/file_system_underlying_sink.h"

#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/system/string_data_source.h"
#include "net/base/net_errors.h"
#include "third_party/blink/public/common/blob/blob_utils.h"
#include "third_party/blink/public/mojom/blob/blob.mojom-blink.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_error.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview_blob_usvstring.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_arraybuffer_arraybufferview_blob_usvstring_writeparams.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_write_command_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_write_params.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_access_error.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"

namespace blink {

FileSystemUnderlyingSink::FileSystemUnderlyingSink(
    ExecutionContext* context,
    mojo::PendingRemote<mojom::blink::FileSystemAccessFileWriter> writer_remote)
    : writer_remote_(context) {
  writer_remote_.Bind(std::move(writer_remote),
                      context->GetTaskRunner(TaskType::kStorage));
  DCHECK(writer_remote_.is_bound());
}

ScriptPromise<IDLUndefined> FileSystemUnderlyingSink::start(
    ScriptState* script_state,
    WritableStreamDefaultController* controller,
    ExceptionState& exception_state) {
  return ToResolvedUndefinedPromise(script_state);
}

ScriptPromise<IDLUndefined> FileSystemUnderlyingSink::write(
    ScriptState* script_state,
    ScriptValue chunk,
    WritableStreamDefaultController* controller,
    ExceptionState& exception_state) {
  auto* input = NativeValueTraits<
      V8UnionArrayBufferOrArrayBufferViewOrBlobOrUSVStringOrWriteParams>::
      NativeValue(script_state->GetIsolate(), chunk.V8Value(), exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  if (input->IsWriteParams()) {
    return HandleParams(script_state, *input->GetAsWriteParams(),
                        exception_state);
  }

  auto* write_data =
      input->GetAsV8UnionArrayBufferOrArrayBufferViewOrBlobOrUSVString();
  return WriteData(script_state, offset_, write_data, exception_state);
}

ScriptPromise<IDLUndefined> FileSystemUnderlyingSink::close(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!writer_remote_.is_bound() || pending_operation_) {
    ThrowDOMExceptionAndInvalidateSink(exception_state,
                                       DOMExceptionCode::kInvalidStateError,
                                       "Object reached an invalid state");
    return EmptyPromise();
  }
  pending_operation_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
          script_state, exception_state.GetContext());
  auto result = pending_operation_->Promise();
  writer_remote_->Close(WTF::BindOnce(&FileSystemUnderlyingSink::CloseComplete,
                                      WrapPersistent(this)));

  return result;
}

ScriptPromise<IDLUndefined> FileSystemUnderlyingSink::abort(
    ScriptState* script_state,
    ScriptValue reason,
    ExceptionState& exception_state) {
  // The specification guarantees that this will only be called after all
  // pending writes have been aborted. Terminating the remote connection
  // will ensure that the writes are not closed successfully.
  if (writer_remote_.is_bound())
    writer_remote_.reset();
  return ToResolvedUndefinedPromise(script_state);
}

ScriptPromise<IDLUndefined> FileSystemUnderlyingSink::HandleParams(
    ScriptState* script_state,
    const WriteParams& params,
    ExceptionState& exception_state) {
  if (params.type() == V8WriteCommandType::Enum::kTruncate) {
    if (!params.hasSizeNonNull()) {
      ThrowDOMExceptionAndInvalidateSink(
          exception_state, DOMExceptionCode::kSyntaxError,
          "Invalid params passed. truncate requires a size argument");
      return EmptyPromise();
    }
    return Truncate(script_state, params.sizeNonNull(), exception_state);
  }

  if (params.type() == V8WriteCommandType::Enum::kSeek) {
    if (!params.hasPositionNonNull()) {
      ThrowDOMExceptionAndInvalidateSink(
          exception_state, DOMExceptionCode::kSyntaxError,
          "Invalid params passed. seek requires a position argument");
      return EmptyPromise();
    }
    return Seek(script_state, params.positionNonNull(), exception_state);
  }

  if (params.type() == V8WriteCommandType::Enum::kWrite) {
    uint64_t position =
        params.hasPositionNonNull() ? params.positionNonNull() : offset_;
    if (!params.hasData()) {
      ThrowDOMExceptionAndInvalidateSink(
          exception_state, DOMExceptionCode::kSyntaxError,
          "Invalid params passed. write requires a data argument");
      return EmptyPromise();
    }
    if (!params.data()) {
      ThrowTypeErrorAndInvalidateSink(
          exception_state,
          "Invalid params passed. write requires a non-null data");
      return EmptyPromise();
    }
    return WriteData(script_state, position, params.data(), exception_state);
  }

  ThrowDOMExceptionAndInvalidateSink(exception_state,
                                     DOMExceptionCode::kInvalidStateError,
                                     "Object reached an invalid state");
  return EmptyPromise();
}

namespace {
// Write operations generally consist of two separate operations, both of which
// can result in an error:
// 1) The data producer (be it a Blob or mojo::DataPipeProducer) writes data to
//    a data pipe.
// 2) The browser side file writer implementation reads data from the data pipe,
//    and writes this to the file.
//
// Both operations can report errors in either order, and we have to wait for
// both to report success before we can consider the combined write call to have
// succeeded. This helper class listens for both complete events and signals
// success when both succeeded, or an error when either operation failed.
//
// This class deletes itself after calling its callback.
class WriterHelper {
 public:
  explicit WriterHelper(
      base::OnceCallback<void(mojom::blink::FileSystemAccessErrorPtr result,
                              uint64_t bytes_written)> callback)
      : callback_(std::move(callback)) {}
  virtual ~WriterHelper() = default;

  // This method is called in response to the mojom Write call. It reports the
  // result of the write operation from the point of view of the file system API
  // implementation.
  void WriteComplete(mojom::blink::FileSystemAccessErrorPtr result,
                     uint64_t bytes_written) {
    DCHECK(!write_result_);
    write_result_ = std::move(result);
    bytes_written_ = bytes_written;
    MaybeCallCallbackAndDeleteThis();
  }

  // This method is called by renderer side code (in subclasses of this class)
  // when we've finished producing data to be written.
  void ProducerComplete(mojom::blink::FileSystemAccessErrorPtr result) {
    DCHECK(!producer_result_);
    producer_result_ = std::move(result);
    MaybeCallCallbackAndDeleteThis();
  }

  virtual base::WeakPtr<WriterHelper> AsWeakPtr() = 0;

 private:
  void MaybeCallCallbackAndDeleteThis() {
    DCHECK(callback_);

    if (!producer_result_.is_null() &&
        producer_result_->status != mojom::blink::FileSystemAccessStatus::kOk) {
      // Producing data failed, report that error.
      std::move(callback_).Run(std::move(producer_result_), bytes_written_);
      delete this;
      return;
    }

    if (!write_result_.is_null() &&
        write_result_->status != mojom::blink::FileSystemAccessStatus::kOk) {
      // Writing failed, report that error.
      std::move(callback_).Run(std::move(write_result_), bytes_written_);
      delete this;
      return;
    }

    if (!producer_result_.is_null() && !write_result_.is_null()) {
      // Both operations succeeded, report success.
      std::move(callback_).Run(std::move(write_result_), bytes_written_);
      delete this;
      return;
    }

    // Still waiting for the other operation to complete, so don't call the
    // callback yet.
  }

  base::OnceCallback<void(mojom::blink::FileSystemAccessErrorPtr result,
                          uint64_t bytes_written)>
      callback_;

  mojom::blink::FileSystemAccessErrorPtr producer_result_;
  mojom::blink::FileSystemAccessErrorPtr write_result_;
  uint64_t bytes_written_ = 0;
};

// WriterHelper implementation that is used when data is being produced by a
// mojo::DataPipeProducer, generally because the data was passed in as an
// ArrayBuffer or String.
class StreamWriterHelper final : public WriterHelper {
 public:
  StreamWriterHelper(
      std::unique_ptr<mojo::DataPipeProducer> producer,
      base::OnceCallback<void(mojom::blink::FileSystemAccessErrorPtr result,
                              uint64_t bytes_written)> callback)
      : WriterHelper(std::move(callback)), producer_(std::move(producer)) {}

  void DataProducerComplete(MojoResult result) {
    // Reset `producer_` to close the DataPipe. Without this the Write operation
    // will never complete as it will keep waiting for more data.
    producer_ = nullptr;

    if (result == MOJO_RESULT_OK) {
      ProducerComplete(mojom::blink::FileSystemAccessError::New(
          mojom::blink::FileSystemAccessStatus::kOk, base::File::FILE_OK, ""));
    } else {
      ProducerComplete(mojom::blink::FileSystemAccessError::New(
          mojom::blink::FileSystemAccessStatus::kOperationAborted,
          base::File::FILE_OK, "Failed to write data to data pipe"));
    }
  }

  base::WeakPtr<WriterHelper> AsWeakPtr() override {
    return weak_ptr_factory_.GetWeakPtr();
  }

 private:
  std::unique_ptr<mojo::DataPipeProducer> producer_;
  base::WeakPtrFactory<WriterHelper> weak_ptr_factory_{this};
};

// WriterHelper implementation that is used when data is being produced by a
// Blob.
class BlobWriterHelper final : public mojom::blink::BlobReaderClient,
                               public WriterHelper {
 public:
  BlobWriterHelper(
      mojo::PendingReceiver<mojom::blink::BlobReaderClient> receiver,
      base::OnceCallback<void(mojom::blink::FileSystemAccessErrorPtr result,
                              uint64_t bytes_written)> callback)
      : WriterHelper(std::move(callback)),
        receiver_(this, std::move(receiver)) {
    receiver_.set_disconnect_handler(
        WTF::BindOnce(&BlobWriterHelper::OnDisconnect, WTF::Unretained(this)));
  }

  // BlobReaderClient:
  void OnCalculatedSize(uint64_t total_size,
                        uint64_t expected_content_size) override {}
  void OnComplete(int32_t status, uint64_t data_length) override {
    complete_called_ = true;
    // This error conversion matches what FileReaderLoader does. Failing to read
    // a blob using FileReader should result in the same exception type as
    // failing to read a blob here.
    if (status == net::OK) {
      ProducerComplete(mojom::blink::FileSystemAccessError::New(
          mojom::blink::FileSystemAccessStatus::kOk, base::File::FILE_OK, ""));
    } else if (status == net::ERR_FILE_NOT_FOUND) {
      ProducerComplete(mojom::blink::FileSystemAccessError::New(
          mojom::blink::FileSystemAccessStatus::kFileError,
          base::File::FILE_ERROR_NOT_FOUND, ""));
    } else {
      ProducerComplete(mojom::blink::FileSystemAccessError::New(
          mojom::blink::FileSystemAccessStatus::kFileError,
          base::File::FILE_ERROR_IO, ""));
    }
  }

  base::WeakPtr<WriterHelper> AsWeakPtr() override {
    return weak_ptr_factory_.GetWeakPtr();
  }

 private:
  void OnDisconnect() {
    if (!complete_called_) {
      // Disconnected without getting a read result, treat this as read failure.
      ProducerComplete(mojom::blink::FileSystemAccessError::New(
          mojom::blink::FileSystemAccessStatus::kOperationAborted,
          base::File::FILE_OK, "Blob disconnected while reading"));
    }
  }

  mojo::Receiver<mojom::blink::BlobReaderClient> receiver_;
  bool complete_called_ = false;
  base::WeakPtrFactory<WriterHelper> weak_ptr_factory_{this};
};

// Creates a mojo data pipe, where the capacity of the data pipe is derived from
// the provided `data_size`. Returns false and throws an exception if creating
// the data pipe failed.
bool CreateDataPipe(uint64_t data_size,
                    ExceptionState& exception_state,
                    mojo::ScopedDataPipeProducerHandle& producer,
                    mojo::ScopedDataPipeConsumerHandle& consumer) {
  MojoCreateDataPipeOptions options;
  options.struct_size = sizeof(MojoCreateDataPipeOptions);
  options.flags = MOJO_CREATE_DATA_PIPE_FLAG_NONE;
  options.element_num_bytes = 1;
  options.capacity_num_bytes = BlobUtils::GetDataPipeCapacity(data_size);

  MojoResult rv = CreateDataPipe(&options, producer, consumer);
  return rv == MOJO_RESULT_OK;
}

}  // namespace

void FileSystemUnderlyingSink::ThrowDOMExceptionAndInvalidateSink(
    ExceptionState& exception_state,
    DOMExceptionCode error,
    const char* message) {
  exception_state.ThrowDOMException(error, message);
  writer_remote_.reset();
}

void FileSystemUnderlyingSink::ThrowTypeErrorAndInvalidateSink(
    ExceptionState& exception_state,
    const char* message) {
  exception_state.ThrowTypeError(message);
  writer_remote_.reset();
}

ScriptPromise<IDLUndefined> FileSystemUnderlyingSink::WriteData(
    ScriptState* script_state,
    uint64_t position,
    const V8UnionArrayBufferOrArrayBufferViewOrBlobOrUSVString* data,
    ExceptionState& exception_state) {
  DCHECK(data);

  if (!writer_remote_.is_bound() || pending_operation_) {
    ThrowDOMExceptionAndInvalidateSink(exception_state,
                                       DOMExceptionCode::kInvalidStateError,
                                       "Object reached an invalid state");
    return EmptyPromise();
  }

  offset_ = position;
  std::unique_ptr<mojo::DataPipeProducer::DataSource> data_source;
  switch (data->GetContentType()) {
    case V8UnionArrayBufferOrArrayBufferViewOrBlobOrUSVString::ContentType::
        kArrayBuffer: {
      DOMArrayBuffer* array_buffer = data->GetAsArrayBuffer();
      data_source = std::make_unique<mojo::StringDataSource>(
          base::as_chars(array_buffer->ByteSpan()),
          mojo::StringDataSource::AsyncWritingMode::
              STRING_MAY_BE_INVALIDATED_BEFORE_COMPLETION);
      break;
    }
    case V8UnionArrayBufferOrArrayBufferViewOrBlobOrUSVString::ContentType::
        kArrayBufferView: {
      DOMArrayBufferView* array_buffer_view =
          data->GetAsArrayBufferView().Get();
      data_source = std::make_unique<mojo::StringDataSource>(
          base::as_chars(array_buffer_view->ByteSpan()),
          mojo::StringDataSource::AsyncWritingMode::
              STRING_MAY_BE_INVALIDATED_BEFORE_COMPLETION);
      break;
    }
    case V8UnionArrayBufferOrArrayBufferViewOrBlobOrUSVString::ContentType::
        kBlob:
      break;
    case V8UnionArrayBufferOrArrayBufferViewOrBlobOrUSVString::ContentType::
        kUSVString:
      data_source = std::make_unique<mojo::StringDataSource>(
          StringUTF8Adaptor(data->GetAsUSVString()).AsStringView(),
          mojo::StringDataSource::AsyncWritingMode::
              STRING_MAY_BE_INVALIDATED_BEFORE_COMPLETION);
      break;
  }

  DCHECK(data_source || data->IsBlob());
  uint64_t data_size =
      data_source ? data_source->GetLength() : data->GetAsBlob()->size();

  mojo::ScopedDataPipeProducerHandle producer_handle;
  mojo::ScopedDataPipeConsumerHandle consumer_handle;
  if (!CreateDataPipe(data_size, exception_state, producer_handle,
                      consumer_handle)) {
    ThrowDOMExceptionAndInvalidateSink(exception_state,
                                       DOMExceptionCode::kInvalidStateError,
                                       "Failed to create datapipe");
    return EmptyPromise();
  }

  WriterHelper* helper;
  if (data->IsBlob()) {
    mojo::PendingRemote<mojom::blink::BlobReaderClient> reader_client;
    helper = new BlobWriterHelper(
        reader_client.InitWithNewPipeAndPassReceiver(),
        WTF::BindOnce(&FileSystemUnderlyingSink::WriteComplete,
                      WrapPersistent(this)));
    data->GetAsBlob()->GetBlobDataHandle()->ReadAll(std::move(producer_handle),
                                                    std::move(reader_client));
  } else {
    auto producer =
        std::make_unique<mojo::DataPipeProducer>(std::move(producer_handle));
    auto* producer_ptr = producer.get();
    helper = new StreamWriterHelper(
        std::move(producer),
        WTF::BindOnce(&FileSystemUnderlyingSink::WriteComplete,
                      WrapPersistent(this)));
    // Unretained is safe because the producer is owned by `helper`.
    producer_ptr->Write(
        std::move(data_source),
        WTF::BindOnce(
            &StreamWriterHelper::DataProducerComplete,
            WTF::Unretained(static_cast<StreamWriterHelper*>(helper))));
  }

  writer_remote_->Write(
      position, std::move(consumer_handle),
      WTF::BindOnce(&WriterHelper::WriteComplete, helper->AsWeakPtr()));

  pending_operation_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
          script_state, exception_state.GetContext());
  return pending_operation_->Promise();
}

ScriptPromise<IDLUndefined> FileSystemUnderlyingSink::Truncate(
    ScriptState* script_state,
    uint64_t size,
    ExceptionState& exception_state) {
  if (!writer_remote_.is_bound() || pending_operation_) {
    ThrowDOMExceptionAndInvalidateSink(exception_state,
                                       DOMExceptionCode::kInvalidStateError,
                                       "Object reached an invalid state");
    return EmptyPromise();
  }
  pending_operation_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
          script_state, exception_state.GetContext());
  auto result = pending_operation_->Promise();
  writer_remote_->Truncate(
      size, WTF::BindOnce(&FileSystemUnderlyingSink::TruncateComplete,
                          WrapPersistent(this), size));
  return result;
}

ScriptPromise<IDLUndefined> FileSystemUnderlyingSink::Seek(
    ScriptState* script_state,
    uint64_t offset,
    ExceptionState& exception_state) {
  if (!writer_remote_.is_bound() || pending_operation_) {
    ThrowDOMExceptionAndInvalidateSink(exception_state,
                                       DOMExceptionCode::kInvalidStateError,
                                       "Object reached an invalid state");
    return EmptyPromise();
  }
  offset_ = offset;
  return ToResolvedUndefinedPromise(script_state);
}

void FileSystemUnderlyingSink::WriteComplete(
    mojom::blink::FileSystemAccessErrorPtr result,
    uint64_t bytes_written) {
  DCHECK(pending_operation_);

  if (result->status == mojom::blink::FileSystemAccessStatus::kOk) {
    // Advance offset.
    offset_ += bytes_written;

    pending_operation_->Resolve();
  } else {
    // An error of any kind puts the underlying stream into an unrecoverable
    // error state. See https://crbug.com/1380650#c5. Close the mojo pipe to
    // clean up resources held by the browser process - including the file lock.
    writer_remote_.reset();
    file_system_access_error::Reject(pending_operation_, *result);
  }
  pending_operation_ = nullptr;
}

void FileSystemUnderlyingSink::TruncateComplete(
    uint64_t to_size,
    mojom::blink::FileSystemAccessErrorPtr result) {
  DCHECK(pending_operation_);

  if (result->status == mojom::blink::FileSystemAccessStatus::kOk) {
    // Set offset to smallest last set size so that a subsequent write is not
    // out of bounds.
    offset_ = to_size < offset_ ? to_size : offset_;

    pending_operation_->Resolve();
  } else {
    // An error of any kind puts the underlying stream into an unrecoverable
    // error state. See https://crbug.com/1380650#c5. Close the mojo pipe to
    // clean up resources held by the browser process - including the file lock.
    writer_remote_.reset();
    file_system_access_error::Reject(pending_operation_, *result);
  }
  pending_operation_ = nullptr;
}

void FileSystemUnderlyingSink::CloseComplete(
    mojom::blink::FileSystemAccessErrorPtr result) {
  DCHECK(pending_operation_);

  // We close the mojo pipe because we intend this writable file stream to be
  // discarded after close. Subsequent operations will fail.
  writer_remote_.reset();

  file_system_access_error::ResolveOrReject(pending_operation_, *result);
  pending_operation_ = nullptr;
}

void FileSystemUnderlyingSink::Trace(Visitor* visitor) const {
  ScriptWrappable::Trace(visitor);
  UnderlyingSinkBase::Trace(visitor);
  visitor->Trace(writer_remote_);
  visitor->Trace(pending_operation_);
}

}  // namespace blink

"""

```