Response:
Let's break down the thought process for analyzing this `FileWriter.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of this C++ file within the Chromium/Blink context, specifically focusing on its interactions with JavaScript, HTML, and CSS, along with potential user errors and debugging strategies.

2. **Initial Code Scan (Keywords and Structure):** Quickly scan the code for keywords and structural elements that give clues about its purpose. Look for:
    * **Class Name:** `FileWriter` -  This strongly suggests it's about writing data to files.
    * **Includes:**  Headers like `<filesystem/file_writer.h>`, `<fileapi/blob.h>`, `<filesystem/file_system_dispatcher.h>` point to file system interactions and data handling. The presence of `ProgressEvent` and `exception_state` indicates interaction with web APIs and error reporting.
    * **Methods:**  `write`, `seek`, `truncate`, `abort` are strong indicators of file manipulation operations.
    * **States/Enums:** `ready_state_` (kInit, kWriting, kDone), `operation_in_progress_` (kOperationNone, kOperationWrite, kOperationTruncate, kOperationAbort) suggest a state machine managing asynchronous file operations.
    * **Event Firing:**  `FireEvent` is used with event type names like `kWritestart`, `kProgress`, `kWrite`, `kWriteend`, `kAbort`, `kError`, suggesting this class dispatches events to JavaScript.
    * **Asynchronous Operations:** The use of callbacks (`WTF::BindOnce`, `WTF::BindRepeating`) and `FileSystemDispatcher` strongly suggests asynchronous communication with the underlying file system.

3. **Identify Core Functionality:** Based on the initial scan, the core functionality revolves around:
    * **Writing data to a file:**  The `write` method takes a `Blob` (representing file data) and initiates a write operation.
    * **Seeking within a file:** The `seek` method allows changing the current position in the file.
    * **Truncating a file:** The `truncate` method reduces the file size to a specified length.
    * **Aborting an operation:** The `abort` method cancels an ongoing write or truncate operation.
    * **Managing the state of the writing process:** The `ready_state_` and `operation_in_progress_` variables track the current state of the `FileWriter`.

4. **Analyze Interactions with JavaScript/Web APIs:**
    * **`Blob`:** This is a fundamental JavaScript API for representing raw binary data, clearly linking this C++ code to JavaScript.
    * **Events:** The `FireEvent` calls dispatch standard `ProgressEvent` objects. These events are crucial for JavaScript to monitor the progress and completion of file operations initiated via the File API. The specific event types (`writestart`, `progress`, `write`, `writeend`, `abort`, `error`) directly correspond to events defined in the File API specifications.
    * **Error Handling (`ExceptionState`):** The use of `ExceptionState` to report errors back to JavaScript is a standard pattern in Blink.

5. **Illustrate with Examples (JavaScript/HTML/CSS):**  To make the connection to web technologies concrete, construct illustrative JavaScript code snippets that would trigger the functionalities of this C++ file. Focus on the File API elements:
    * `FileWriter` object creation.
    * `write()` with a `Blob`.
    * `seek()` to change the position.
    * `truncate()` to resize.
    * `abort()` to cancel.
    * Event listeners (`onloadstart`, `onprogress`, `onload`, `onloadend`, `onabort`, `onerror`) to observe the process.

6. **Deduce Logic and Reasoning (Hypothetical Input/Output):** Consider the sequence of operations and the internal state management. For example, when `write` is called:
    * **Input:** A `Blob` object.
    * **Internal Logic:** Set `ready_state_` to `kWriting`, store the `Blob`, initiate an asynchronous write operation via `FileSystemDispatcher`.
    * **Output (Indirect):**  Fires `writestart` event. Later, fires `progress` events, and finally `write` or `error` and `writeend` events.

7. **Identify Common User Errors:** Think about how developers might misuse the File API, leading to this C++ code being triggered in unexpected ways or throwing errors. Common errors include:
    * Calling methods in the wrong state (e.g., `write` while already writing).
    * Providing invalid arguments (e.g., negative `truncate` length).
    * Not handling errors properly in JavaScript.
    * Exceeding recursion limits (though less common in typical user code, more relevant for internal implementation details).

8. **Outline Debugging Steps:** Consider how a developer would reach this specific code file during debugging. This usually involves:
    * **Starting with the JavaScript code:**  Identify the File API calls that are causing issues.
    * **Setting breakpoints in JavaScript:**  Trace the execution flow.
    * **Looking at browser developer tools:** Inspect network requests (though less direct here as it's local file system), console errors, and potentially performance profiling.
    * **Moving to C++ debugging (more advanced):** If the issue isn't apparent in JavaScript, developers might need to set breakpoints in the `FileWriter.cc` code to understand the internal state and the flow of execution. This requires a local Chromium build and debugging tools.

9. **Structure the Answer:**  Organize the findings into clear sections:
    * **Functionality:**  A concise summary of what the file does.
    * **Relationship to Web Technologies:**  Explicitly link the C++ code to JavaScript, HTML, and CSS concepts (primarily through the File API and event handling).
    * **Logic and Reasoning:** Illustrate the internal workings with input/output examples.
    * **User Errors:** Provide concrete examples of how developers can misuse the API.
    * **Debugging:** Outline steps to reach this code during debugging.

10. **Refine and Elaborate:** Review the generated answer, adding details and clarifying any ambiguous points. For instance, explicitly mention the asynchronous nature of the operations and the role of `FileSystemDispatcher`. Ensure the examples are clear and easy to understand.

By following these steps, we can systematically analyze the C++ code and provide a comprehensive explanation of its functionality and its relevance within the broader context of web development.
好的，让我们来详细分析一下 `blink/renderer/modules/filesystem/file_writer.cc` 这个 Chromium Blink 引擎的源代码文件。

**功能概述**

`FileWriter.cc` 文件实现了 `FileWriter` 类，这个类是 Web File API 中 `FileWriter` 接口在 Blink 渲染引擎中的具体实现。它的主要功能是允许网页上的 JavaScript 代码异步地向用户文件系统中的文件写入数据、调整文件指针位置以及截断文件。

更具体地说，`FileWriter` 类负责以下操作：

* **写入数据 (write):**  接收一个 `Blob` 对象（代表要写入的数据），将其内容写入到文件中，从当前文件指针位置开始。
* **移动文件指针 (seek):** 允许 JavaScript 代码改变文件内部的操作指针位置，后续的写入操作将从新的位置开始。
* **截断文件 (truncate):**  将文件的大小调整为指定的长度。
* **中止操作 (abort):**  取消当前正在进行的写入或截断操作。
* **管理状态:** 维护写入操作的状态（例如，初始化、写入中、完成）并触发相应的事件。
* **错误处理:**  处理文件操作过程中可能出现的错误，并将错误信息传递给 JavaScript。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`FileWriter` 类直接关联到 JavaScript 的 File API。网页开发者可以通过 JavaScript 代码创建 `FileWriter` 对象，并调用其方法来操作文件。

* **JavaScript 接口:** `FileWriter` 类的方法（如 `write()`, `seek()`, `truncate()`, `abort()`）直接对应 JavaScript 中 `FileWriter` 接口的方法。

* **`Blob` 对象:** `FileWriter` 的 `write()` 方法接收一个 `Blob` 对象作为参数。`Blob` 是 JavaScript 中表示原始二进制数据的对象，通常用于处理文件内容。

* **事件驱动:** `FileWriter` 在操作的不同阶段会触发事件，例如 `writestart` (写入开始), `progress` (写入进度), `write` (写入成功), `writeend` (写入结束), `abort` (写入中止), `error` (写入错误)。JavaScript 可以监听这些事件来获取操作状态和结果。

**举例说明:**

假设以下 JavaScript 代码用于向用户选择的文件写入内容：

```javascript
function writeFile(fileHandle, content) {
  fileHandle.createWriter()
    .then((writer) => {
      writer.onwriteend = function(e) {
        console.log('写入完成');
      };
      writer.onerror = function(e) {
        console.error('写入出错:', e);
      };

      const blob = new Blob([content], { type: 'text/plain' });
      writer.write(blob); // 调用 FileWriter 的 write 方法
    })
    .catch((err) => {
      console.error('创建 FileWriter 失败:', err);
    });
}

// 假设 fileHandle 是通过 File System Access API 获取的文件句柄
// 例如：const fileHandle = await window.showSaveFilePicker();
```

在这个例子中：

1. `fileHandle.createWriter()` 会在 Blink 内部创建一个与该文件关联的 `FileWriter` 对象。
2. `writer.write(blob)` 调用了 `FileWriter.cc` 中实现的 `write()` 方法。
3. `blob` 对象的内容会被传递到 C++ 层进行实际的写入操作。
4. `FileWriter` 对象在写入的不同阶段会触发 `writestart`, `progress`, `writeend` 等事件，这些事件会被 JavaScript 监听并处理。
5. 如果写入过程中发生错误，`FileWriter` 会触发 `error` 事件。

**与 HTML 和 CSS 的关系:**

`FileWriter` 本身不直接与 HTML 或 CSS 交互。然而，它作为 Web File API 的一部分，使得 JavaScript 能够操作用户本地文件，这可以间接地影响 HTML 内容或依赖于本地存储的 Web 应用的行为。例如，一个 Web 应用可以使用 `FileWriter` 将用户编辑的文档保存到本地文件系统，然后用户可以再次加载这个文件到 HTML 页面中进行展示。

**逻辑推理 (假设输入与输出)**

假设我们有以下 JavaScript 代码调用 `FileWriter` 的 `write` 方法：

```javascript
const writer = // ... 获取到的 FileWriter 对象 ...
const blob = new Blob(['Hello, World!'], { type: 'text/plain' });
writer.write(blob);
```

**假设输入:**

* `FileWriter` 对象处于 `kInit` 或 `kDone` 状态。
* `blob` 对象包含字符串 "Hello, World!"。
* 文件指针当前位置为文件的起始位置 (0)。

**逻辑推理过程:**

1. `writer.write(blob)` 被调用，进入 `FileWriter::write` 方法。
2. `FileWriter` 的状态变为 `kWriting`。
3. `bytes_to_write_` 被设置为 `blob` 的大小 (13 字节)。
4. 如果当前没有其他操作正在进行 (`operation_in_progress_ == kOperationNone`)，则调用 `DoOperation(kOperationWrite)`。
5. `DoOperation` 方法会调用底层的 `FileSystemDispatcher` 来执行实际的写入操作。
6. `FileSystemDispatcher` 会与操作系统的文件系统交互，将 "Hello, World!" 写入到文件中。
7. 在写入过程中，可能会多次调用 `DidWriteImpl` 来报告写入的字节数。
8. 当写入完成时，调用 `DidWriteImpl` 并设置 `complete` 为 true。
9. `FileWriter` 触发 `progress` 事件（可能多次），然后触发 `write` 事件，最后触发 `writeend` 事件。
10. `FileWriter` 的状态变为 `kDone`。

**假设输出 (触发的事件和状态变化):**

* 触发 `writestart` 事件。
* 可能会触发多次 `progress` 事件，每次事件的 `loaded` 属性会增加，直到等于 `total` 属性 (13)。
* 触发 `write` 事件。
* 触发 `writeend` 事件。
* `FileWriter` 的 `readyState` 属性会依次变为 `WRITING` 和 `DONE`。

**涉及用户或编程常见的使用错误及举例说明**

1. **在错误的状态下调用方法:**

   ```javascript
   const writer = // ... 获取到的 FileWriter 对象 ...
   const blob1 = new Blob(['Data 1']);
   writer.write(blob1);
   const blob2 = new Blob(['Data 2']);
   writer.write(blob2); // 错误：在写入操作进行中再次调用 write
   ```
   在第一次 `write` 操作尚未完成时再次调用 `write` 会导致错误，因为 `FileWriter` 的 `readyState` 仍然是 `WRITING`。Blink 会抛出一个 `InvalidStateError` 异常。

2. **`truncate` 方法的参数错误:**

   ```javascript
   const writer = // ... 获取到的 FileWriter 对象 ...
   writer.truncate(-10); // 错误：截断长度不能为负数
   ```
   传递给 `truncate` 方法的长度参数不能为负数。Blink 会抛出一个 `InvalidStateError` 异常。

3. **未处理错误事件:**

   ```javascript
   const writer = // ... 获取到的 FileWriter 对象 ...
   writer.write(someInvalidBlob); // 假设这是一个导致写入失败的 Blob

   // JavaScript 代码没有监听 'error' 事件，导致用户可能不知道写入失败
   ```
   开发者应该监听 `error` 事件来处理可能发生的写入错误，例如磁盘空间不足、文件权限问题等。

4. **过度的 `abort` 调用:**

   虽然 `abort` 可以取消操作，但频繁调用可能会导致资源浪费或意外行为。

**说明用户操作是如何一步步的到达这里，作为调试线索**

要到达 `FileWriter.cc` 中的代码，通常涉及以下用户操作和浏览器内部流程：

1. **用户交互或网页加载:** 用户在网页上执行了某些操作（例如，点击“保存”按钮，上传文件），或者网页本身在加载时执行了 JavaScript 代码。

2. **JavaScript 代码调用 File API:** 网页的 JavaScript 代码使用了 File API 的相关接口，例如：
   * 通过 `window.showSaveFilePicker()` 或拖放等方式获取了 `FileSystemFileHandle` 或 `File` 对象。
   * 调用了 `fileHandle.createWriter()` 方法来创建 `FileWriter` 对象。
   * 在 `FileWriter` 对象上调用了 `write()`, `seek()`, `truncate()`, 或 `abort()` 方法。

3. **Blink 接收 JavaScript 调用:**  V8 JavaScript 引擎执行 JavaScript 代码，当遇到 File API 的调用时，会将这些调用转发到 Blink 渲染引擎的相应模块。

4. **创建 `FileWriter` 对象:** 当 `createWriter()` 被调用时，Blink 会创建 `FileWriter` 类的实例。

5. **调用 `FileWriter` 的方法:** 当 JavaScript 调用 `writer.write(blob)` 等方法时，会最终调用到 `FileWriter.cc` 中对应的 C++ 方法，例如 `FileWriter::write()。`

6. **与 `FileSystemDispatcher` 交互:** `FileWriter` 类会将实际的文件操作请求委托给 `FileSystemDispatcher` 类。`FileSystemDispatcher` 负责与操作系统的文件系统进行异步通信。

7. **操作系统文件操作:** `FileSystemDispatcher` 发起系统调用，执行实际的文件写入、移动指针或截断操作。

8. **回调通知:** 当操作系统完成文件操作后，会通知 Blink。

9. **`FileWriter` 处理回调:** `FileWriter` 类会接收到来自 `FileSystemDispatcher` 的回调（例如 `DidWriteImpl`, `DidTruncateImpl`, `DidFailImpl`），并更新自身状态，触发相应的 JavaScript 事件。

**调试线索:**

* **断点调试:** 在 Chrome 的开发者工具中，可以在 JavaScript 代码中设置断点，跟踪 File API 的调用过程。
* **Blink 源码调试:** 如果需要深入了解 Blink 内部的执行流程，可以下载 Chromium 源码，并在 `FileWriter.cc` 中设置断点，查看 C++ 代码的执行过程。这需要编译 Chromium 的调试版本。
* **控制台输出:** 在 JavaScript 代码中添加 `console.log` 语句，输出相关变量的值，帮助理解程序执行状态。
* **网络面板（尽管这里不是网络请求）:**  虽然 `FileWriter` 操作的是本地文件系统，但在某些情况下，与文件操作相关的元数据或配置可能通过网络加载，可以关注网络面板是否有异常。
* **Error 事件监听:**  确保在 JavaScript 中正确监听了 `error` 事件，以便捕获并处理文件操作过程中出现的错误。

总而言之，`FileWriter.cc` 是 Blink 渲染引擎中处理文件写入操作的核心组件，它连接了 JavaScript 的 File API 和底层的操作系统文件系统，负责管理写入过程的状态、处理错误并通知 JavaScript 代码操作结果。理解其功能对于调试与文件操作相关的 Web 应用问题至关重要。

### 提示词
```
这是目录为blink/renderer/modules/filesystem/file_writer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2010 Google Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/filesystem/file_writer.h"

#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/renderer/core/events/progress_event.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/fileapi/file_error.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/modules/filesystem/file_system_dispatcher.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

static const int kMaxRecursionDepth = 3;
static const base::TimeDelta kProgressNotificationInterval =
    base::Milliseconds(50);
static constexpr uint64_t kMaxTruncateLength =
    std::numeric_limits<uint64_t>::max();

FileWriter::FileWriter(ExecutionContext* context)
    : ActiveScriptWrappable<FileWriter>({}),
      ExecutionContextLifecycleObserver(context),
      ready_state_(kInit),
      operation_in_progress_(kOperationNone),
      queued_operation_(kOperationNone),
      bytes_written_(0),
      bytes_to_write_(0),
      truncate_length_(kMaxTruncateLength),
      num_aborts_(0),
      recursion_depth_(0),
      request_id_(0) {}

FileWriter::~FileWriter() {
  DCHECK(!recursion_depth_);
}

const AtomicString& FileWriter::InterfaceName() const {
  return event_target_names::kFileWriter;
}

void FileWriter::ContextDestroyed() {
  Dispose();
}

bool FileWriter::HasPendingActivity() const {
  return operation_in_progress_ != kOperationNone ||
         queued_operation_ != kOperationNone || ready_state_ == kWriting;
}

void FileWriter::write(Blob* data, ExceptionState& exception_state) {
  if (!GetExecutionContext())
    return;
  DCHECK(data);
  DCHECK_EQ(truncate_length_, kMaxTruncateLength);
  if (ready_state_ == kWriting) {
    SetError(FileErrorCode::kInvalidStateErr, exception_state);
    return;
  }
  if (recursion_depth_ > kMaxRecursionDepth) {
    SetError(FileErrorCode::kSecurityErr, exception_state);
    return;
  }

  blob_being_written_ = data;
  ready_state_ = kWriting;
  bytes_written_ = 0;
  bytes_to_write_ = data->size();
  DCHECK_EQ(queued_operation_, kOperationNone);
  if (operation_in_progress_ != kOperationNone) {
    // We must be waiting for an abort to complete, since m_readyState wasn't
    // kWriting.
    DCHECK_EQ(operation_in_progress_, kOperationAbort);
    queued_operation_ = kOperationWrite;
  } else
    DoOperation(kOperationWrite);

  FireEvent(event_type_names::kWritestart);
}

void FileWriter::seek(int64_t position, ExceptionState& exception_state) {
  if (!GetExecutionContext())
    return;
  if (ready_state_ == kWriting) {
    SetError(FileErrorCode::kInvalidStateErr, exception_state);
    return;
  }

  DCHECK_EQ(truncate_length_, kMaxTruncateLength);
  DCHECK_EQ(queued_operation_, kOperationNone);
  SeekInternal(position);
}

void FileWriter::truncate(int64_t position, ExceptionState& exception_state) {
  if (!GetExecutionContext())
    return;
  DCHECK_EQ(truncate_length_, kMaxTruncateLength);
  if (ready_state_ == kWriting || position < 0) {
    SetError(FileErrorCode::kInvalidStateErr, exception_state);
    return;
  }
  if (recursion_depth_ > kMaxRecursionDepth) {
    SetError(FileErrorCode::kSecurityErr, exception_state);
    return;
  }

  ready_state_ = kWriting;
  bytes_written_ = 0;
  bytes_to_write_ = 0;
  truncate_length_ = position;
  DCHECK_EQ(queued_operation_, kOperationNone);
  if (operation_in_progress_ != kOperationNone) {
    // We must be waiting for an abort to complete, since m_readyState wasn't
    // kWriting.
    DCHECK_EQ(operation_in_progress_, kOperationAbort);
    queued_operation_ = kOperationTruncate;
  } else
    DoOperation(kOperationTruncate);
  FireEvent(event_type_names::kWritestart);
}

void FileWriter::abort(ExceptionState& exception_state) {
  if (!GetExecutionContext())
    return;
  if (ready_state_ != kWriting)
    return;
  ++num_aborts_;

  DoOperation(kOperationAbort);
  SignalCompletion(base::File::FILE_ERROR_ABORT);
}

void FileWriter::DidWriteImpl(int64_t bytes, bool complete) {
  if (operation_in_progress_ == kOperationAbort) {
    CompleteAbort();
    return;
  }
  DCHECK_EQ(kWriting, ready_state_);
  DCHECK_EQ(kMaxTruncateLength, truncate_length_);
  DCHECK_EQ(kOperationWrite, operation_in_progress_);
  DCHECK(!bytes_to_write_ || bytes + bytes_written_ > 0);
  DCHECK(bytes + bytes_written_ <= bytes_to_write_);
  bytes_written_ += bytes;
  DCHECK((bytes_written_ == bytes_to_write_) || !complete);
  SetPosition(position() + bytes);
  if (position() > length())
    SetLength(position());
  if (complete) {
    blob_being_written_.Clear();
    operation_in_progress_ = kOperationNone;
  }

  uint64_t num_aborts = num_aborts_;
  // We could get an abort in the handler for this event. If we do, it's
  // already handled the cleanup and signalCompletion call.
  base::TimeTicks now = base::TimeTicks::Now();
  if (complete || !last_progress_notification_time_.is_null() ||
      (now - last_progress_notification_time_ >
       kProgressNotificationInterval)) {
    last_progress_notification_time_ = now;
    FireEvent(event_type_names::kProgress);
  }

  if (complete) {
    if (num_aborts == num_aborts_)
      SignalCompletion(base::File::FILE_OK);
  }
}

void FileWriter::DidTruncateImpl() {
  if (operation_in_progress_ == kOperationAbort) {
    CompleteAbort();
    return;
  }
  DCHECK_EQ(operation_in_progress_, kOperationTruncate);
  DCHECK_NE(truncate_length_, kMaxTruncateLength);
  SetLength(truncate_length_);
  if (position() > length())
    SetPosition(length());
  operation_in_progress_ = kOperationNone;
  SignalCompletion(base::File::FILE_OK);
}

void FileWriter::DidFailImpl(base::File::Error error) {
  DCHECK_NE(kOperationNone, operation_in_progress_);
  DCHECK_NE(base::File::FILE_OK, error);
  if (operation_in_progress_ == kOperationAbort) {
    CompleteAbort();
    return;
  }
  DCHECK_EQ(kOperationNone, queued_operation_);
  DCHECK_EQ(kWriting, ready_state_);
  blob_being_written_.Clear();
  operation_in_progress_ = kOperationNone;
  SignalCompletion(error);
}

void FileWriter::DoTruncate(const KURL& path, int64_t offset) {
  FileSystemDispatcher::From(GetExecutionContext())
      .Truncate(
          path, offset, &request_id_,
          WTF::BindOnce(&FileWriter::DidFinish, WrapWeakPersistent(this)));
}

void FileWriter::DoWrite(const KURL& path, const Blob& blob, int64_t offset) {
  FileSystemDispatcher::From(GetExecutionContext())
      .Write(
          path, blob, offset, &request_id_,
          WTF::BindRepeating(&FileWriter::DidWrite, WrapWeakPersistent(this)),
          WTF::BindOnce(&FileWriter::DidFinish, WrapWeakPersistent(this)));
}

void FileWriter::DoCancel() {
  FileSystemDispatcher::From(GetExecutionContext())
      .Cancel(request_id_,
              WTF::BindOnce(&FileWriter::DidFinish, WrapWeakPersistent(this)));
}

void FileWriter::CompleteAbort() {
  DCHECK_EQ(operation_in_progress_, kOperationAbort);
  operation_in_progress_ = kOperationNone;
  Operation operation = queued_operation_;
  queued_operation_ = kOperationNone;
  DoOperation(operation);
}

void FileWriter::DoOperation(Operation operation) {
  async_task_context_.Schedule(GetExecutionContext(), "FileWriter");
  switch (operation) {
    case kOperationWrite:
      DCHECK_EQ(kOperationNone, operation_in_progress_);
      DCHECK_EQ(kMaxTruncateLength, truncate_length_);
      DCHECK(blob_being_written_.Get());
      DCHECK_EQ(kWriting, ready_state_);
      Write(position(), *blob_being_written_);
      break;
    case kOperationTruncate:
      DCHECK_EQ(kOperationNone, operation_in_progress_);
      DCHECK_NE(truncate_length_, kMaxTruncateLength);
      DCHECK_EQ(kWriting, ready_state_);
      Truncate(truncate_length_);
      break;
    case kOperationNone:
      DCHECK_EQ(kOperationNone, operation_in_progress_);
      DCHECK_EQ(kMaxTruncateLength, truncate_length_);
      DCHECK(!blob_being_written_.Get());
      DCHECK_EQ(kDone, ready_state_);
      break;
    case kOperationAbort:
      if (operation_in_progress_ == kOperationWrite ||
          operation_in_progress_ == kOperationTruncate)
        Cancel();
      else if (operation_in_progress_ != kOperationAbort)
        operation = kOperationNone;
      queued_operation_ = kOperationNone;
      blob_being_written_.Clear();
      truncate_length_ = kMaxTruncateLength;
      break;
  }
  DCHECK_EQ(queued_operation_, kOperationNone);
  operation_in_progress_ = operation;
}

void FileWriter::SignalCompletion(base::File::Error error) {
  ready_state_ = kDone;
  truncate_length_ = kMaxTruncateLength;
  if (error != base::File::FILE_OK) {
    error_ = file_error::CreateDOMException(error);
    if (base::File::FILE_ERROR_ABORT == error)
      FireEvent(event_type_names::kAbort);
    else
      FireEvent(event_type_names::kError);
  } else {
    FireEvent(event_type_names::kWrite);
  }
  FireEvent(event_type_names::kWriteend);

  async_task_context_.Cancel();
}

void FileWriter::FireEvent(const AtomicString& type) {
  probe::AsyncTask async_task(GetExecutionContext(), &async_task_context_);
  ++recursion_depth_;
  DispatchEvent(
      *ProgressEvent::Create(type, true, bytes_written_, bytes_to_write_));
  DCHECK_GT(recursion_depth_, 0);
  --recursion_depth_;
}

void FileWriter::SetError(FileErrorCode error_code,
                          ExceptionState& exception_state) {
  DCHECK_NE(error_code, FileErrorCode::kOK);
  file_error::ThrowDOMException(exception_state, error_code);
  error_ = file_error::CreateDOMException(error_code);
}

void FileWriter::Dispose() {
  // Make sure we've actually got something to stop, and haven't already called
  // abort().
  if (ready_state_ == kWriting) {
    DoOperation(kOperationAbort);
    ready_state_ = kDone;
  }
  // Prevents any queued operations from running after abort completes.
  queued_operation_ = kOperationNone;
}

void FileWriter::Trace(Visitor* visitor) const {
  visitor->Trace(error_);
  visitor->Trace(blob_being_written_);
  EventTarget::Trace(visitor);
  FileWriterBase::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

}  // namespace blink
```