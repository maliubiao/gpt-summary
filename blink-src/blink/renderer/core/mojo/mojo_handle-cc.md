Response:
Let's break down the thought process for analyzing the `mojo_handle.cc` file and generating the detailed response.

**1. Understanding the Core Purpose:**

The first step is to identify the central theme of the file. The filename `mojo_handle.cc` and the included headers like `mojo/public/c/system/message_pipe.h` and `mojo/public/cpp/system/message_pipe.h` strongly suggest that this file is about managing Mojo handles within the Blink rendering engine. Mojo is a system for inter-process communication, and handles are the mechanism for processes to interact.

**2. Identifying Key Functionalities by Examining Public Methods:**

Next, I would scan the public methods of the `MojoHandle` class. This is where the core actions are defined. I'd list them out and try to understand their purpose based on their names and parameters:

* `TakeHandle()`:  Likely used to retrieve the underlying Mojo handle. The `std::move` suggests ownership transfer.
* `close()`:  For releasing the Mojo handle.
* `watch()`:  Seems to be related to observing the state of the handle and triggering a callback. The `MojoHandleSignals` parameter confirms this.
* `writeMessage()`:  Clearly for sending data over a message pipe associated with the handle. The `V8BufferSource` and `MojoHandle` parameters indicate the data and potential attached handles.
* `readMessage()`:  For receiving data from a message pipe. The return type `MojoReadMessageResult` suggests it provides information about the received data.
* `writeData()`, `queryData()`, `discardData()`, `readData()`: These all seem related to reading and writing raw data to a data pipe (as opposed to messages).
* `mapBuffer()`:  The name suggests mapping a shared memory buffer associated with the handle into the process's address space.
* `duplicateBufferHandle()`: For creating a new handle that refers to the same underlying shared memory buffer.

**3. Analyzing Internal Logic and Data Structures:**

After understanding the high-level functions, I'd delve into the implementations of these methods. This involves:

* **Mapping to Mojo C APIs:**  Notice the frequent calls to functions like `MojoWriteMessageNew`, `MojoReadMessageNew`, `MojoWriteData`, `MojoReadData`, `MojoDuplicateBufferHandle`, etc. These are the underlying C APIs of the Mojo system. Understanding that `MojoHandle` acts as a wrapper around these C APIs is crucial.
* **Handling `V8BufferSource`:** The `ByteSpanForBufferSource` function reveals how JavaScript `ArrayBuffer` and `ArrayBufferView` objects are converted into raw byte spans for Mojo operations.
* **Working with Handles:** The code shows how Mojo handles are moved (`std::move`), copied, and managed. The `HeapVector<Member<MojoHandle>>` indicates garbage collection awareness.
* **Result Structures:** The various `Mojo...Result` classes (`MojoReadMessageResult`, `MojoWriteDataResult`, etc.) are used to package the outcomes of Mojo operations, including success/failure codes and associated data (like received buffers or new handles).
* **Error Handling:**  The code checks the return values of Mojo C APIs and sets appropriate error codes in the result structures.
* **Shared Memory Handling:** The `mapBuffer` function demonstrates the process of unwrapping and re-wrapping shared memory regions to interact with them as `DOMArrayBuffer` in Blink.

**4. Connecting to JavaScript, HTML, and CSS:**

This is where I'd connect the low-level Mojo operations to the higher-level web technologies:

* **JavaScript Interaction:** The presence of `ScriptState*` and the use of `V8BufferSource` and result objects directly linked to V8 types (`V8MojoWatchCallback`, `V8MojoReadMessageResult`, etc.) clearly indicate that this code is a bridge between the C++ Mojo implementation and JavaScript.
* **Use Cases:**  I'd brainstorm common scenarios where inter-process communication is needed in a browser:
    * **Service Workers:** Communicating with the main browser process.
    * **Web Workers:**  Interacting with the main thread.
    * **Iframes/Cross-Origin Communication:** Sending messages between different browsing contexts.
    * **File System Access:**  Potentially using Mojo to interact with the file system service.
    * **Device APIs:**  Interacting with hardware through browser services.
* **HTML and CSS Relevance:** While not directly manipulating HTML or CSS, Mojo enables features that *support* these technologies. For example, a service worker fetching resources (related to HTML/CSS) might use Mojo for communication.

**5. Inferring Logical Reasoning and Assumptions:**

Looking at the code, I'd infer:

* **Assumption:**  Mojo handles represent communication channels or shared memory regions.
* **Reasoning:**  `writeMessage` takes data and handles, suggesting the ability to send both data and capabilities. `readMessage` returns both, implying the reception of both. `mapBuffer` directly manipulates shared memory.
* **Input/Output Examples:** I'd create simple scenarios to illustrate how the functions might be used, like sending a string between two endpoints.

**6. Identifying Common Usage Errors:**

Based on my understanding of the API and common programming mistakes, I'd consider:

* **Invalid Handles:**  Trying to use a closed or invalid handle is a classic error. The code explicitly checks for this in `writeMessage`.
* **Mismatched Operations:**  Trying to read from a handle that's meant for writing, or vice-versa.
* **Buffer Management:**  Incorrectly sizing buffers or not handling the `numBytes` return value properly in read/write operations.
* **Ownership Issues:**  Forgetting that `TakeHandle()` transfers ownership and then trying to use the original `MojoHandle`.

**7. Structuring the Response:**

Finally, I'd organize the information into logical sections with clear headings and examples, similar to the provided good answer. This makes the explanation easier to understand and digest. I would start with the core functionality, then connect it to web technologies, provide examples, and finally discuss potential errors.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe `MojoHandle` directly manages the underlying OS resources.
* **Correction:**  Realization that it's a wrapper around the Mojo C API, abstracting the low-level details.
* **Initial thought:** Focus heavily on message pipes.
* **Refinement:** Recognizing the importance of data pipes and shared memory operations as well.
* **Ensuring Clarity:** Using precise terminology and avoiding jargon where possible, or explaining it when necessary.

By following these steps, I can systematically analyze the code and produce a comprehensive explanation of its functionality and relevance.
这个文件 `blink/renderer/core/mojo/mojo_handle.cc` 的核心功能是 **封装和管理 Mojo 系统中的句柄 (handles)**。 它提供了一个 C++ 类 `MojoHandle`，用于在 Blink 渲染引擎中安全和方便地使用 Mojo 句柄。

以下是它的主要功能分解：

**1. 句柄的持有和管理:**

* **`MojoHandle(mojo::ScopedHandle handle)` 构造函数:**  接收一个 Mojo 的 `ScopedHandle`，并存储在 `MojoHandle` 对象中。`ScopedHandle` 是一种 RAII 机制的智能指针，用于自动管理 Mojo 句柄的生命周期。
* **`TakeHandle()`:**  将持有的 `mojo::ScopedHandle` 的所有权移交给调用者。这意味着调用此方法后，`MojoHandle` 对象不再持有该句柄。
* **`close()`:**  显式地关闭持有的 Mojo 句柄。
* **`handle_` 成员变量:**  私有成员，存储实际的 `mojo::ScopedHandle`。

**2. 观察句柄状态:**

* **`watch(ScriptState* script_state, const MojoHandleSignals* signals, V8MojoWatchCallback* callback)`:**  允许 JavaScript 代码监控 Mojo 句柄上的特定信号（例如，可读或可写）。当信号触发时，会执行 JavaScript 回调函数。这通过 `MojoWatcher` 类实现。

**3. 通过消息管道 (Message Pipe) 进行通信:**

* **`writeMessage(const V8BufferSource* buffer, const HeapVector<Member<MojoHandle>>& handles)`:**  通过与该 `MojoHandle` 关联的消息管道发送消息。
    * `buffer`: 包含要发送的数据，可以是 `ArrayBuffer` 或 `ArrayBufferView`。
    * `handles`:  一个可选的 Mojo 句柄向量，可以与消息一起发送，实现能力传递。
    * **与 JavaScript 的关系:**  JavaScript 可以创建 `ArrayBuffer` 或 `ArrayBufferView` 对象作为 `buffer` 传递，并通过 `MojoHandle` 发送给其他进程或组件。
    * **逻辑推理:**
        * **假设输入:**  一个包含字符串 "hello" 的 JavaScript `ArrayBuffer` 和一个空的句柄向量。
        * **输出:**  通过 Mojo 消息管道发送一个包含 "hello" 的消息。
* **`readMessage(const MojoReadMessageFlags* flags_dict)`:**  从与该 `MojoHandle` 关联的消息管道接收消息。
    * **与 JavaScript 的关系:**  接收到的消息数据会转换为 JavaScript 的 `ArrayBuffer`，并且接收到的 Mojo 句柄也会被封装成 `MojoHandle` 对象，可以在 JavaScript 中使用。
    * **逻辑推理:**
        * **假设输入:**  一个包含字符串 "world" 的 Mojo 消息，可能还包含一个共享内存句柄。
        * **输出:**  返回一个 `MojoReadMessageResult` 对象，其中包含一个包含 "world" 的 JavaScript `ArrayBuffer` 和一个表示接收到的共享内存的 `MojoHandle`。

**4. 通过数据管道 (Data Pipe) 进行数据传输:**

* **`writeData(const V8BufferSource* buffer, const MojoWriteDataOptions* options_dict)`:**  通过与该 `MojoHandle` 关联的数据管道写入数据。
    * **与 JavaScript 的关系:**  类似于 `writeMessage`，JavaScript 可以提供 `ArrayBuffer` 或 `ArrayBufferView` 作为数据源。
* **`queryData() const`:**  查询数据管道中可用的数据量。
* **`discardData(unsigned num_bytes, const MojoDiscardDataOptions* options_dict)`:**  从数据管道中丢弃指定数量的数据。
* **`readData(const V8BufferSource* buffer, const MojoReadDataOptions* options_dict) const`:**  从数据管道中读取数据到提供的 `buffer` 中。
    * **与 JavaScript 的关系:**  JavaScript 提供一个 `ArrayBuffer` 或 `ArrayBufferView` 作为接收数据的目标。

**5. 共享内存 (Shared Buffer) 管理:**

* **`mapBuffer(unsigned offset, unsigned num_bytes)`:**  将与该 `MojoHandle` 关联的共享内存区域映射到进程的地址空间，并创建一个 JavaScript 的 `ArrayBuffer` 对象来访问这部分内存。
    * **与 JavaScript 的关系:**  允许 JavaScript 直接访问和操作由 Mojo 管理的共享内存。这对于在不同进程之间高效地共享大量数据非常重要。
    * **逻辑推理:**
        * **假设输入:**  一个指向 1MB 共享内存的 `MojoHandle`，以及 `offset = 1024`, `num_bytes = 4096`。
        * **输出:**  返回一个 `MojoMapBufferResult` 对象，其中包含一个映射了共享内存中从 1024 字节开始的 4096 字节的 JavaScript `ArrayBuffer`。
* **`duplicateBufferHandle(const MojoDuplicateBufferHandleOptions* options_dict)`:**  复制共享内存的句柄。可以创建只读的副本。
    * **与 JavaScript 的关系:**  允许 JavaScript 创建指向同一共享内存的不同句柄，可以用于在不同的上下文或 worker 中共享内存。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **Service Worker 和主线程通信:**  Service Worker 运行在独立的进程中。可以使用 Mojo 消息管道与主线程进行通信。例如，Service Worker 可以使用 `writeMessage` 发送从网络获取的数据（例如 HTML 或 CSS 资源）到主线程。主线程可以使用 `readMessage` 接收数据并更新页面。
* **Web Worker 和主线程共享数据:** Web Worker 也可以运行在独立的线程或进程中。可以使用共享内存来高效地共享大量数据，例如图像数据或大型 JSON 对象。主线程可以使用 `duplicateBufferHandle` 创建一个共享内存句柄，并将其发送给 Worker。Worker 可以使用 `mapBuffer` 将共享内存映射到自己的地址空间进行访问。
* **扩展 API (例如 File System Access API):**  浏览器的一些扩展 API 可能使用 Mojo 与浏览器进程中的服务进行通信。例如，File System Access API 可能使用 Mojo 消息管道来请求读取或写入文件。传递文件数据可能涉及到使用共享内存句柄。

**用户或编程常见的使用错误举例说明:**

1. **尝试在句柄关闭后使用它:**
   ```c++
   MojoHandle my_handle = ...;
   my_handle.close();
   // 错误：尝试在句柄关闭后写入消息
   MojoResult result = my_handle.writeMessage(&buffer, {});
   // 此时 result 很可能是 MOJO_RESULT_FAILED_PRECONDITION 或其他错误。
   ```
   **与 JavaScript 的关系:**  如果 JavaScript 代码持有一个已经关闭的 `MojoHandle` 对象并尝试调用其方法，会导致错误。

2. **忘记管理句柄的所有权:**
   ```c++
   MojoHandle my_handle = ...;
   mojo::ScopedHandle raw_handle = my_handle.TakeHandle();
   // 此时 my_handle 不再拥有句柄
   // 错误：尝试使用已经移交所有权的句柄
   my_handle.close(); // 这里不会有任何效果，因为 handle_ 已经为空
   ```
   **与 JavaScript 的关系:** 如果 JavaScript 调用了一个返回 `MojoHandle` 的方法，并将该对象传递给另一个函数，需要明确哪个部分负责关闭该句柄，否则可能导致资源泄漏。

3. **在 `readData` 或 `writeData` 中使用错误的缓冲区大小:**
   ```c++
   MojoHandle data_pipe = ...;
   char buffer[10];
   V8 фундамент buffer_source(buffer, sizeof(buffer)); // 假设 V8BufferSource 可以从原始指针创建
   // 错误：尝试读取比管道中实际数据更多的数据
   MojoReadDataResult* read_result = data_pipe.readData(&buffer_source, nullptr);
   // 如果管道中只有 5 个字节，则 read_result->numBytes() 将是 5，而不是 10。
   ```
   **与 JavaScript 的关系:**  JavaScript 需要确保提供的 `ArrayBuffer` 或 `ArrayBufferView` 的大小与预期读取或写入的数据量匹配。

4. **在多线程环境下不正确地共享 `MojoHandle`:**  `MojoHandle` 对象本身可能不是线程安全的。如果需要在多线程之间共享 Mojo 通信能力，通常需要复制句柄 (例如通过 `duplicateBufferHandle` 或消息传递)。

**总结:**

`mojo_handle.cc` 文件是 Blink 引擎中处理 Mojo 通信的核心部分。它提供了 C++ 接口来操作 Mojo 句柄，并与 JavaScript 的 `ArrayBuffer` 等类型紧密集成，使得 JavaScript 代码能够利用 Mojo 的跨进程通信和共享内存能力，构建更强大和高效的 Web 应用。 理解 `MojoHandle` 的功能对于理解 Blink 如何与浏览器其他组件以及外部进程进行交互至关重要。

Prompt: 
```
这是目录为blink/renderer/core/mojo/mojo_handle.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/mojo/mojo_handle.h"

#include "base/numerics/safe_math.h"
#include "mojo/public/c/system/message_pipe.h"
#include "mojo/public/cpp/bindings/message.h"
#include "mojo/public/cpp/system/message_pipe.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mojo_create_shared_buffer_result.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mojo_discard_data_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mojo_duplicate_buffer_handle_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mojo_map_buffer_result.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mojo_read_data_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mojo_read_data_result.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mojo_read_message_flags.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mojo_read_message_result.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mojo_write_data_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mojo_write_data_result.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/mojo/mojo_watcher.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_view.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"

// Mojo messages typically do not contain many handles. In fact most
// messages do not contain any handle. An inline capacity of 4 should avoid
// heap allocation in vast majority of cases.
static const size_t kHandleVectorInlineCapacity = 4;

namespace blink {

namespace {

base::span<uint8_t> ByteSpanForBufferSource(const V8BufferSource& buffer) {
  switch (buffer.GetContentType()) {
    case V8BufferSource::ContentType::kArrayBuffer:
      return buffer.GetAsArrayBuffer()->ByteSpan();
    case V8BufferSource::ContentType::kArrayBufferView:
      return buffer.GetAsArrayBufferView()->ByteSpan();
  }
  return {};
}

}  // namespace

mojo::ScopedHandle MojoHandle::TakeHandle() {
  return std::move(handle_);
}

MojoHandle::MojoHandle(mojo::ScopedHandle handle)
    : handle_(std::move(handle)) {}

void MojoHandle::close() {
  handle_.reset();
}

MojoWatcher* MojoHandle::watch(ScriptState* script_state,
                               const MojoHandleSignals* signals,
                               V8MojoWatchCallback* callback) {
  return MojoWatcher::Create(handle_.get(), signals, callback,
                             ExecutionContext::From(script_state));
}

MojoResult MojoHandle::writeMessage(
    const V8BufferSource* buffer,
    const HeapVector<Member<MojoHandle>>& handles) {
  Vector<mojo::ScopedHandle, kHandleVectorInlineCapacity> scoped_handles;
  scoped_handles.reserve(handles.size());
  bool has_invalid_handles = false;
  for (auto& handle : handles) {
    if (!handle->handle_.is_valid())
      has_invalid_handles = true;
    else
      scoped_handles.emplace_back(std::move(handle->handle_));
  }
  if (has_invalid_handles)
    return MOJO_RESULT_INVALID_ARGUMENT;

  base::span<const uint8_t> bytes = ByteSpanForBufferSource(*buffer);

  auto message = mojo::Message(bytes, base::make_span(scoped_handles));
  DCHECK(!message.IsNull());
  return mojo::WriteMessageNew(mojo::MessagePipeHandle(handle_.get().value()),
                               message.TakeMojoMessage(),
                               MOJO_WRITE_MESSAGE_FLAG_NONE);
}

MojoReadMessageResult* MojoHandle::readMessage(
    const MojoReadMessageFlags* flags_dict) {
  MojoReadMessageResult* result_dict = MojoReadMessageResult::Create();

  mojo::ScopedMessageHandle message;
  MojoResult result =
      mojo::ReadMessageNew(mojo::MessagePipeHandle(handle_.get().value()),
                           &message, MOJO_READ_MESSAGE_FLAG_NONE);
  if (result != MOJO_RESULT_OK) {
    result_dict->setResult(result);
    return result_dict;
  }

  result = MojoSerializeMessage(message->value(), nullptr);
  if (result != MOJO_RESULT_OK && result != MOJO_RESULT_FAILED_PRECONDITION) {
    result_dict->setResult(MOJO_RESULT_ABORTED);
    return result_dict;
  }

  uint32_t num_bytes = 0, num_handles = 0;
  void* bytes;
  Vector<::MojoHandle, kHandleVectorInlineCapacity> raw_handles;
  result = MojoGetMessageData(message->value(), nullptr, &bytes, &num_bytes,
                              nullptr, &num_handles);
  if (result == MOJO_RESULT_RESOURCE_EXHAUSTED) {
    raw_handles.resize(num_handles);
    result = MojoGetMessageData(message->value(), nullptr, &bytes, &num_bytes,
                                raw_handles.data(), &num_handles);
  }

  if (result != MOJO_RESULT_OK) {
    result_dict->setResult(MOJO_RESULT_ABORTED);
    return result_dict;
  }

  DOMArrayBuffer* buffer =
      DOMArrayBuffer::CreateUninitializedOrNull(num_bytes, 1);
  if (num_bytes) {
    CHECK(buffer);
    memcpy(buffer->Data(), bytes, num_bytes);
  }
  result_dict->setBuffer(buffer);

  HeapVector<Member<MojoHandle>> handles(num_handles);
  for (uint32_t i = 0; i < num_handles; ++i) {
    handles[i] = MakeGarbageCollected<MojoHandle>(
        mojo::MakeScopedHandle(mojo::Handle(raw_handles[i])));
  }
  result_dict->setHandles(handles);
  result_dict->setResult(result);

  return result_dict;
}

MojoWriteDataResult* MojoHandle::writeData(
    const V8BufferSource* buffer,
    const MojoWriteDataOptions* options_dict) {
  MojoWriteDataFlags flags = MOJO_WRITE_DATA_FLAG_NONE;
  if (options_dict->allOrNone())
    flags |= MOJO_WRITE_DATA_FLAG_ALL_OR_NONE;

  base::span<const uint8_t> bytes = ByteSpanForBufferSource(*buffer);

  ::MojoWriteDataOptions options;
  options.struct_size = sizeof(options);
  options.flags = flags;
  uint32_t num_bytes = 0;
  MojoResult result =
      base::CheckedNumeric<uint32_t>(bytes.size()).AssignIfValid(&num_bytes)
          ? MojoWriteData(handle_.get().value(), bytes.data(), &num_bytes,
                          &options)
          : MOJO_RESULT_INVALID_ARGUMENT;

  MojoWriteDataResult* result_dict = MojoWriteDataResult::Create();
  result_dict->setResult(result);
  result_dict->setNumBytes(result == MOJO_RESULT_OK ? num_bytes : 0);
  return result_dict;
}

MojoReadDataResult* MojoHandle::queryData() const {
  MojoReadDataResult* result_dict = MojoReadDataResult::Create();
  uint32_t num_bytes = 0;
  ::MojoReadDataOptions options;
  options.struct_size = sizeof(options);
  options.flags = MOJO_READ_DATA_FLAG_QUERY;
  MojoResult result =
      MojoReadData(handle_.get().value(), &options, nullptr, &num_bytes);
  result_dict->setResult(result);
  result_dict->setNumBytes(num_bytes);
  return result_dict;
}

MojoReadDataResult* MojoHandle::discardData(
    unsigned num_bytes,
    const MojoDiscardDataOptions* options_dict) {
  MojoReadDataResult* result_dict = MojoReadDataResult::Create();
  MojoReadDataFlags flags = MOJO_READ_DATA_FLAG_DISCARD;
  if (options_dict->allOrNone())
    flags |= MOJO_READ_DATA_FLAG_ALL_OR_NONE;

  ::MojoReadDataOptions options;
  options.struct_size = sizeof(options);
  options.flags = flags;
  MojoResult result =
      MojoReadData(handle_.get().value(), &options, nullptr, &num_bytes);
  result_dict->setResult(result);
  result_dict->setNumBytes(result == MOJO_RESULT_OK ? num_bytes : 0);
  return result_dict;
}

MojoReadDataResult* MojoHandle::readData(
    const V8BufferSource* buffer,
    const MojoReadDataOptions* options_dict) const {
  MojoReadDataFlags flags = MOJO_READ_DATA_FLAG_NONE;
  if (options_dict->allOrNone())
    flags |= MOJO_READ_DATA_FLAG_ALL_OR_NONE;
  if (options_dict->peek())
    flags |= MOJO_READ_DATA_FLAG_PEEK;

  base::span<uint8_t> bytes = ByteSpanForBufferSource(*buffer);

  ::MojoReadDataOptions options;
  options.struct_size = sizeof(options);
  options.flags = flags;

  uint32_t num_bytes;
  MojoResult result =
      base::CheckedNumeric<uint32_t>(bytes.size()).AssignIfValid(&num_bytes)
          ? MojoReadData(handle_.get().value(), &options, bytes.data(),
                         &num_bytes)
          : MOJO_RESULT_INVALID_ARGUMENT;

  MojoReadDataResult* result_dict = MojoReadDataResult::Create();
  result_dict->setResult(result);
  result_dict->setNumBytes(result == MOJO_RESULT_OK ? num_bytes : 0);
  return result_dict;
}

MojoMapBufferResult* MojoHandle::mapBuffer(unsigned offset,
                                           unsigned num_bytes) {
  MojoMapBufferResult* result_dict = MojoMapBufferResult::Create();

  // We need to extract the underlying shared memory region to map it as array
  // buffer contents. However, as we don't know what kind of shared memory
  // region is currently backing the buffer, we unwrap it to the underlying
  // platform shared memory region. We also don't want to duplicate the region,
  // and so need to perform a small dance here to first unwrap, and later
  // re-wrap the MojoSharedBuffer to/from a //base shared memory region.
  mojo::SharedBufferHandle buffer_handle(handle_.release().value());
  auto region = mojo::UnwrapPlatformSharedMemoryRegion(
      mojo::ScopedSharedBufferHandle(buffer_handle));

  if (region.IsValid()) {
    ArrayBufferContents contents(region, offset, num_bytes);
    if (contents.IsValid()) {
      result_dict->setResult(MOJO_RESULT_OK);
      result_dict->setBuffer(DOMArrayBuffer::Create(contents));
    } else {
      // Contents would be invalid if `MapAt()` failed.
      result_dict->setResult(MOJO_RESULT_INVALID_ARGUMENT);
    }
  } else {
    result_dict->setResult(MOJO_RESULT_UNKNOWN);
  }

  // 2nd part of the dance: we now need to wrap the shared memory region into a
  // mojo handle again.
  mojo::ScopedSharedBufferHandle mojo_buffer =
      mojo::WrapPlatformSharedMemoryRegion(std::move(region));
  handle_.reset(mojo::Handle(mojo_buffer.release().value()));

  return result_dict;
}

MojoCreateSharedBufferResult* MojoHandle::duplicateBufferHandle(
    const MojoDuplicateBufferHandleOptions* options_dict) {
  MojoCreateSharedBufferResult* result_dict =
      MojoCreateSharedBufferResult::Create();

  ::MojoDuplicateBufferHandleOptions options = {
      sizeof(options), MOJO_DUPLICATE_BUFFER_HANDLE_FLAG_NONE};
  if (options_dict->readOnly())
    options.flags |= MOJO_DUPLICATE_BUFFER_HANDLE_FLAG_READ_ONLY;

  mojo::Handle handle;
  MojoResult result = MojoDuplicateBufferHandle(handle_.get().value(), &options,
                                                handle.mutable_value());
  result_dict->setResult(result);
  if (result == MOJO_RESULT_OK) {
    result_dict->setHandle(
        MakeGarbageCollected<MojoHandle>(mojo::MakeScopedHandle(handle)));
  }
  return result_dict;
}

}  // namespace blink

"""

```