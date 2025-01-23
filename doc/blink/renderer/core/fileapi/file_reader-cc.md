Response:
Let's break down the thought process for analyzing the `FileReader.cc` file.

**1. Initial Skim and Identification of Core Purpose:**

The first step is always a quick read-through to grasp the main functionality. Keywords like "FileReader", "readAsArrayBuffer", "readAsText", "Blob", "ProgressEvent", "abort", and the copyright notice pointing to file handling immediately signal that this code deals with reading file data in a web browser context. The directory name `blink/renderer/core/fileapi/` reinforces this.

**2. Identifying Key Classes and Structures:**

As I read, I pay attention to class definitions. `FileReader` is the main class, but `ThrottlingController` stands out as a crucial supporting class related to managing concurrent requests. Noticing `FileReaderLoader` suggests an internal helper for the actual data loading. The use of `HeapDeque` and `HeapHashSet` within `ThrottlingController` hints at managing a queue and set of `FileReader` objects.

**3. Tracing the Data Flow:**

Next, I try to follow the lifecycle of a file read operation. This involves looking at the various `readAs...` methods:

* **Trigger:** A JavaScript call to `FileReader.readAsArrayBuffer()`, etc., initiates the process.
* **Internal Setup:** The `ReadInternal` method is called, which sets the `state_`, `loading_state_`, and stores the `Blob` information.
* **Request Management:** The `ThrottlingController::PushReader` method adds the `FileReader` to a queue, managing concurrency.
* **Actual Reading:** `ExecutePendingRead` creates and starts a `FileReaderLoader` to handle the I/O.
* **Progress and Completion:**  `DidStartLoading`, `DidReceiveData`, `DidFinishLoading`, and `DidFail` handle the callbacks from the loader, firing events and updating the `FileReader`'s state.
* **Result Delivery:** The `result()` method provides the read data.
* **Cancellation:** The `abort()` method allows stopping the reading process.

**4. Mapping to Web Technologies (JavaScript, HTML, CSS):**

Now I connect the internal workings to the web platform:

* **JavaScript:** The `FileReader` class is directly exposed to JavaScript. Methods like `readAsArrayBuffer`, `readAsText`, `readAsDataURL`, and `abort` are the API surface. Events like `onloadstart`, `onprogress`, `onload`, `onerror`, and `onloadend` are clearly related to JavaScript event handling.
* **HTML:** The primary interaction with `FileReader` in HTML comes through the `<input type="file">` element. When a user selects a file, JavaScript can access the `File` object (which inherits from `Blob`) and pass it to a `FileReader`.
* **CSS:** While less direct, CSS can be indirectly affected. For example, if a user uploads an image, the `FileReader` might be used to read it as a data URL, which could then be used as the `background-image` of an element.

**5. Identifying Assumptions and Logical Inferences:**

* **Concurrency Control:** The `ThrottlingController`'s existence implies a need to manage concurrent file read operations to avoid overwhelming the system or network. The `kMaxOutstandingRequestsPerThread` constant confirms this.
* **Asynchronous Nature:** The events and the use of a loader strongly suggest that file reading is an asynchronous operation. This prevents the browser's UI thread from blocking.
* **Error Handling:** The `error_` member and the `DidFail` method clearly indicate a mechanism for handling errors during the file reading process.

**6. Considering User/Programming Errors:**

Thinking about how developers might misuse `FileReader`:

* **Calling `readAs...` multiple times concurrently:** The code explicitly throws an `InvalidStateError` for this.
* **Accessing `result` before loading is complete:** The `result()` method returns `nullptr` until `DidFinishLoading` is called.
* **Not handling errors:**  Developers need to attach `onerror` event listeners.
* **Detached `FileReader`:** The code checks for detached execution contexts.

**7. Structuring the Output:**

Finally, I organize the information into logical categories (functionality, relationship to web technologies, logical inference, common errors) and provide concrete examples where appropriate. Using bullet points and code snippets makes the explanation clearer and easier to understand. I also explicitly state the assumptions made based on the code.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:** "Is this just about reading local files?"  **Correction:** While local file reading is a primary use case, `FileReader` can also be used with `Blob` objects created in other ways (e.g., from network responses).
* **Initial thought:** "Does CSS directly interact with `FileReader`?" **Correction:** The interaction is indirect, mainly through JavaScript manipulating the DOM based on data read by `FileReader`.
* **Focusing too much on low-level details:** **Correction:**  Shift focus to the higher-level purpose and how it relates to web development concepts.

By following this systematic approach, combining code reading with understanding the broader web platform context, and considering potential use cases and errors, it's possible to generate a comprehensive and informative analysis of the `FileReader.cc` file.
好的，我们来分析一下 `blink/renderer/core/fileapi/file_reader.cc` 这个文件的功能。

**主要功能:**

`FileReader.cc` 文件实现了 Web API 中的 `FileReader` 接口。`FileReader` 接口允许 Web 应用**异步读取存储在用户计算机上的文件（或原始数据缓冲区）的内容**。

具体来说，它的核心功能包括：

1. **启动文件读取操作:**  提供 `readAsArrayBuffer()`, `readAsBinaryString()`, `readAsText()`, `readAsDataURL()` 等方法，用于指定以不同格式读取文件内容。
2. **异步读取文件内容:**  使用内部的 `FileReaderLoader` 类来实际执行文件读取操作，这个操作是在后台异步进行的，不会阻塞主线程。
3. **提供读取进度信息:**  通过 `ProgressEvent` 事件，可以监听文件读取的进度（已加载的字节数和总字节数）。
4. **处理读取结果:**  读取完成后，会将文件内容存储在 `result_` 成员变量中，并触发 `load` 事件。读取失败则会设置 `error_` 成员变量，并触发 `error` 事件。
5. **支持取消读取操作:**  提供 `abort()` 方法来中断正在进行的读取操作。
6. **管理并发读取请求:**  通过 `ThrottlingController` 类来限制同一线程中并发的 `FileReader` 请求数量，避免资源过度消耗。

**与 JavaScript, HTML, CSS 的关系以及举例说明:**

`FileReader` 是一个 JavaScript API，因此它直接与 JavaScript 代码交互。HTML 中的 `<input type="file">` 元素允许用户选择本地文件，JavaScript 可以获取到 `File` 对象（`Blob` 的子类），然后将其传递给 `FileReader` 的读取方法。CSS 本身不直接与 `FileReader` 交互，但 `FileReader` 读取到的数据可能会被 JavaScript 用于动态修改 CSS 样式。

**举例说明:**

**HTML:**

```html
<input type="file" id="fileInput">
<img id="imagePreview" style="display: none;">
```

**JavaScript:**

```javascript
const fileInput = document.getElementById('fileInput');
const imagePreview = document.getElementById('imagePreview');

fileInput.addEventListener('change', function() {
  const file = fileInput.files[0];
  const reader = new FileReader();

  reader.onload = function(e) {
    // 读取完成，将图片数据显示在<img>标签中
    imagePreview.src = e.target.result;
    imagePreview.style.display = 'block';
  };

  reader.onerror = function(e) {
    console.error("文件读取失败:", e);
  };

  reader.onprogress = function(e) {
    if (e.lengthComputable) {
      const percentLoaded = Math.round((e.loaded / e.total) * 100);
      console.log("加载进度: " + percentLoaded + "%");
    }
  };

  reader.readAsDataURL(file); // 以 data URL 格式读取文件内容
});
```

**说明:**

* 当用户在 `<input type="file">` 中选择一个图片文件时，会触发 `change` 事件。
* JavaScript 获取到选择的 `File` 对象。
* 创建一个 `FileReader` 对象。
* 设置 `onload` 事件处理函数，当文件读取成功后，将读取到的 Data URL 设置为 `<img>` 标签的 `src` 属性，从而显示图片。
* 设置 `onerror` 事件处理函数，处理文件读取失败的情况。
* 设置 `onprogress` 事件处理函数，显示文件读取的进度。
* 调用 `reader.readAsDataURL(file)` 开始读取文件。

**逻辑推理与假设输入输出:**

假设用户选择了一个名为 "example.txt" 的文本文件，内容为 "Hello, World!"。

**假设输入:**

* `Blob` 对象，指向 "example.txt" 文件。
* 调用 `fileReader.readAsText(blob)` 方法。

**逻辑推理:**

1. `FileReader` 对象的状态从 `kEmpty` 变为 `kLoading`。
2. `FileReaderLoader` 开始异步读取文件内容。
3. 会触发 `loadstart` 事件。
4. 可能会多次触发 `progress` 事件，报告读取进度。
5. 读取完成后，文件内容 "Hello, World!" 会被存储在 `result_` 成员变量中。
6. 触发 `load` 事件，事件对象的 `target.result` 属性将包含 "Hello, World!" 字符串。
7. `FileReader` 对象的状态变为 `kDone`。
8. 触发 `loadend` 事件。

**假设输入:**

* `Blob` 对象，指向一个 1MB 的图片文件。
* 调用 `fileReader.readAsArrayBuffer(blob)` 方法。

**逻辑推理:**

1. `FileReader` 对象的状态变为 `kLoading`。
2. `FileReaderLoader` 开始异步读取图片文件内容。
3. 触发 `loadstart` 事件。
4. 可能会多次触发 `progress` 事件，报告读取进度 (例如：加载了 10%, 50%, 80% 等)。事件对象的 `loaded` 属性会更新已加载的字节数，`total` 属性会是文件总大小。
5. 读取完成后，图片的二进制数据会以 `ArrayBuffer` 的形式存储在 `result_` 成员变量中。
6. 触发 `load` 事件，事件对象的 `target.result` 属性将是一个包含图片数据的 `ArrayBuffer` 对象。
7. `FileReader` 对象的状态变为 `kDone`。
8. 触发 `loadend` 事件。

**用户或编程常见的使用错误举例说明:**

1. **在读取完成之前访问 `result` 属性:**

   ```javascript
   const reader = new FileReader();
   reader.readAsText(file);
   console.log(reader.result); // 错误：此时 result 可能是 null 或 undefined
   ```

   **正确做法:**  应该在 `onload` 事件处理函数中访问 `result` 属性。

2. **没有处理错误事件:**

   ```javascript
   const reader = new FileReader();
   reader.readAsText(file);
   // 没有设置 onerror 事件处理函数，如果读取失败，用户可能不会得到任何提示。
   ```

   **正确做法:**  应该设置 `onerror` 事件处理函数来处理读取失败的情况。

3. **在同一个 `FileReader` 对象上并发调用多个读取方法:**

   ```javascript
   const reader = new FileReader();
   reader.readAsText(file1);
   reader.readAsArrayBuffer(file2); // 错误：会抛出 InvalidStateError
   ```

   **说明:**  `FileReader` 对象在一次只能进行一个读取操作。如果需要同时读取多个文件，需要创建多个 `FileReader` 对象。源码中的 `state_ == kLoading` 检查会抛出 `DOMExceptionCode::kInvalidStateError`。

4. **尝试读取已经 detached 的 `FileReader` 对象:**

   在某些特殊情况下，例如 `FileReader` 所属的 `Document` 已经从 `Frame` 中分离，尝试读取会导致错误。源码中会检查 `GetExecutionContext()` 是否有效，如果无效则抛出 `DOMExceptionCode::kAbortError`。

5. **忘记处理 `progress` 事件以提供用户反馈:**

   对于大文件的读取，不提供进度反馈可能会让用户觉得程序卡死。

6. **滥用 `FileReader` 读取大量小文件:**

   虽然 `FileReader` 可以读取文件，但对于需要频繁读取大量小文件的情况，可能存在性能瓶颈。

**总结:**

`FileReader.cc` 是 Chromium Blink 引擎中实现文件读取核心功能的代码，它负责将用户选择的文件内容异步加载到 Web 应用中，并提供了丰富的事件机制来跟踪读取状态和处理结果。理解其功能对于开发涉及文件上传、处理等功能的 Web 应用至关重要。它与 JavaScript 通过 API 交互，与 HTML 中的文件选择元素配合使用，而 CSS 则间接地通过 JavaScript 操作由 `FileReader` 读取的数据。开发者需要注意正确使用 `FileReader` 的 API 和处理相关的事件，避免常见的错误。

### 提示词
```
这是目录为blink/renderer/core/fileapi/file_reader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
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

#include "third_party/blink/renderer/core/fileapi/file_reader.h"

#include "base/auto_reset.h"
#include "base/timer/elapsed_timer.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_string.h"
#include "third_party/blink/renderer/core/event_target_names.h"
#include "third_party/blink/renderer/core/events/progress_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fileapi/file.h"
#include "third_party/blink/renderer/core/fileapi/file_error.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/supplementable.h"
#include "third_party/blink/renderer/platform/wtf/deque.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"

namespace blink {

namespace {

const std::string Utf8BlobUUID(Blob* blob) {
  return blob->Uuid().Utf8();
}

const std::string Utf8FilePath(Blob* blob) {
  return blob->HasBackingFile() ? To<File>(blob)->GetPath().Utf8() : "";
}

}  // namespace

// Embedders like chromium limit the number of simultaneous requests to avoid
// excessive IPC congestion. We limit this to 100 per thread to throttle the
// requests (the value is arbitrarily chosen).
static const size_t kMaxOutstandingRequestsPerThread = 100;
static const base::TimeDelta kProgressNotificationInterval =
    base::Milliseconds(50);

class FileReader::ThrottlingController final
    : public GarbageCollected<FileReader::ThrottlingController>,
      public Supplement<ExecutionContext> {
 public:
  static const char kSupplementName[];

  static ThrottlingController* From(ExecutionContext* context) {
    if (!context)
      return nullptr;

    ThrottlingController* controller =
        Supplement<ExecutionContext>::From<ThrottlingController>(*context);
    if (!controller) {
      controller = MakeGarbageCollected<ThrottlingController>(*context);
      ProvideTo(*context, controller);
    }
    return controller;
  }

  enum FinishReaderType { kDoNotRunPendingReaders, kRunPendingReaders };

  static void PushReader(ExecutionContext* context, FileReader* reader) {
    ThrottlingController* controller = From(context);
    if (!controller)
      return;

    reader->async_task_context()->Schedule(context, "FileReader");
    controller->PushReader(reader);
  }

  static FinishReaderType RemoveReader(ExecutionContext* context,
                                       FileReader* reader) {
    ThrottlingController* controller = From(context);
    if (!controller)
      return kDoNotRunPendingReaders;

    return controller->RemoveReader(reader);
  }

  static void FinishReader(ExecutionContext* context,
                           FileReader* reader,
                           FinishReaderType next_step) {
    ThrottlingController* controller = From(context);
    if (!controller)
      return;

    controller->FinishReader(reader, next_step);
    reader->async_task_context()->Cancel();
  }

  explicit ThrottlingController(ExecutionContext& context)
      : Supplement<ExecutionContext>(context),
        max_running_readers_(kMaxOutstandingRequestsPerThread) {}

  void Trace(Visitor* visitor) const override {
    visitor->Trace(pending_readers_);
    visitor->Trace(running_readers_);
    Supplement<ExecutionContext>::Trace(visitor);
  }

 private:
  void PushReader(FileReader* reader) {
    if (pending_readers_.empty() &&
        running_readers_.size() < max_running_readers_) {
      reader->ExecutePendingRead();
      DCHECK(!running_readers_.Contains(reader));
      running_readers_.insert(reader);
      return;
    }
    pending_readers_.push_back(reader);
    ExecuteReaders();
  }

  FinishReaderType RemoveReader(FileReader* reader) {
    FileReaderHashSet::const_iterator hash_iter = running_readers_.find(reader);
    if (hash_iter != running_readers_.end()) {
      running_readers_.erase(hash_iter);
      return kRunPendingReaders;
    }
    FileReaderDeque::const_iterator deque_end = pending_readers_.end();
    for (FileReaderDeque::const_iterator it = pending_readers_.begin();
         it != deque_end; ++it) {
      if (*it == reader) {
        pending_readers_.erase(it);
        break;
      }
    }
    return kDoNotRunPendingReaders;
  }

  void FinishReader(FileReader* reader, FinishReaderType next_step) {
    if (next_step == kRunPendingReaders)
      ExecuteReaders();
  }

  void ExecuteReaders() {
    // Dont execute more readers if the context is already destroyed (or in the
    // process of being destroyed).
    if (GetSupplementable()->IsContextDestroyed())
      return;
    while (running_readers_.size() < max_running_readers_) {
      if (pending_readers_.empty())
        return;
      FileReader* reader = pending_readers_.TakeFirst();
      reader->ExecutePendingRead();
      running_readers_.insert(reader);
    }
  }

  const size_t max_running_readers_;

  using FileReaderDeque = HeapDeque<Member<FileReader>>;
  using FileReaderHashSet = HeapHashSet<Member<FileReader>>;

  FileReaderDeque pending_readers_;
  FileReaderHashSet running_readers_;
};

// static
const char FileReader::ThrottlingController::kSupplementName[] =
    "FileReaderThrottlingController";

FileReader* FileReader::Create(ExecutionContext* context) {
  return MakeGarbageCollected<FileReader>(context);
}

FileReader::FileReader(ExecutionContext* context)
    : ActiveScriptWrappable<FileReader>({}),
      ExecutionContextLifecycleObserver(context),
      state_(kEmpty),
      loading_state_(kLoadingStateNone),
      still_firing_events_(false),
      read_type_(FileReadType::kReadAsBinaryString) {}

FileReader::~FileReader() = default;

const AtomicString& FileReader::InterfaceName() const {
  return event_target_names::kFileReader;
}

void FileReader::ContextDestroyed() {
  // The delayed abort task tidies up and advances to the DONE state.
  if (loading_state_ == kLoadingStateAborted)
    return;

  if (HasPendingActivity()) {
    ExecutionContext* destroyed_context = GetExecutionContext();
    ThrottlingController::FinishReader(
        destroyed_context, this,
        ThrottlingController::RemoveReader(destroyed_context, this));
  }
  Terminate();
}

bool FileReader::HasPendingActivity() const {
  return state_ == kLoading || still_firing_events_;
}

void FileReader::readAsArrayBuffer(Blob* blob,
                                   ExceptionState& exception_state) {
  DCHECK(blob);
  DVLOG(1) << "reading as array buffer: " << Utf8BlobUUID(blob).data() << " "
           << Utf8FilePath(blob).data();

  ReadInternal(blob, FileReadType::kReadAsArrayBuffer, exception_state);
}

void FileReader::readAsBinaryString(Blob* blob,
                                    ExceptionState& exception_state) {
  DCHECK(blob);
  DVLOG(1) << "reading as binary: " << Utf8BlobUUID(blob).data() << " "
           << Utf8FilePath(blob).data();

  ReadInternal(blob, FileReadType::kReadAsBinaryString, exception_state);
}

void FileReader::readAsText(Blob* blob,
                            const String& encoding,
                            ExceptionState& exception_state) {
  DCHECK(blob);
  DVLOG(1) << "reading as text: " << Utf8BlobUUID(blob).data() << " "
           << Utf8FilePath(blob).data();

  encoding_ = encoding;
  ReadInternal(blob, FileReadType::kReadAsText, exception_state);
}

void FileReader::readAsText(Blob* blob, ExceptionState& exception_state) {
  readAsText(blob, String(), exception_state);
}

void FileReader::readAsDataURL(Blob* blob, ExceptionState& exception_state) {
  DCHECK(blob);
  DVLOG(1) << "reading as data URL: " << Utf8BlobUUID(blob).data() << " "
           << Utf8FilePath(blob).data();

  ReadInternal(blob, FileReadType::kReadAsDataURL, exception_state);
}

void FileReader::ReadInternal(Blob* blob,
                              FileReadType type,
                              ExceptionState& exception_state) {
  // If multiple concurrent read methods are called on the same FileReader,
  // InvalidStateError should be thrown when the state is kLoading.
  if (state_ == kLoading) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The object is already busy reading Blobs.");
    return;
  }

  ExecutionContext* context = GetExecutionContext();
  if (!context) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kAbortError,
        "Reading from a detached FileReader is not supported.");
    return;
  }

  // A document loader will not load new resources once the Document has
  // detached from its frame.
  LocalDOMWindow* window = DynamicTo<LocalDOMWindow>(context);
  if (window && !window->GetFrame()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kAbortError,
        "Reading from a Document-detached FileReader is not supported.");
    return;
  }

  // "Snapshot" the Blob data rather than the Blob itself as ongoing
  // read operations should not be affected if close() is called on
  // the Blob being read.
  blob_data_handle_ = blob->GetBlobDataHandle();
  blob_type_ = blob->type();
  read_type_ = type;
  state_ = kLoading;
  loading_state_ = kLoadingStatePending;
  error_ = nullptr;
  result_ = nullptr;
  DCHECK(ThrottlingController::From(context));
  ThrottlingController::PushReader(context, this);
}

void FileReader::ExecutePendingRead() {
  DCHECK_EQ(loading_state_, kLoadingStatePending);
  loading_state_ = kLoadingStateLoading;

  loader_ = MakeGarbageCollected<FileReaderLoader>(
      this, GetExecutionContext()->GetTaskRunner(TaskType::kFileReading));
  loader_->Start(blob_data_handle_);
  blob_data_handle_ = nullptr;
}

void FileReader::abort() {
  DVLOG(1) << "aborting";

  if (loading_state_ != kLoadingStateLoading &&
      loading_state_ != kLoadingStatePending) {
    return;
  }
  loading_state_ = kLoadingStateAborted;

  DCHECK_NE(kDone, state_);
  // Synchronously cancel the loader before dispatching events. This way we make
  // sure the FileReader internal state stays consistent even if another load
  // is started from one of the event handlers, or right after abort returns.
  Terminate();

  base::AutoReset<bool> firing_events(&still_firing_events_, true);

  // Setting error implicitly makes |result| return null.
  error_ = file_error::CreateDOMException(FileErrorCode::kAbortErr);

  // Unregister the reader.
  ThrottlingController::FinishReaderType final_step =
      ThrottlingController::RemoveReader(GetExecutionContext(), this);

  FireEvent(event_type_names::kAbort);
  // TODO(https://crbug.com/1204139): Only fire loadend event if no new load was
  // started from the abort event handler.
  FireEvent(event_type_names::kLoadend);

  // All possible events have fired and we're done, no more pending activity.
  ThrottlingController::FinishReader(GetExecutionContext(), this, final_step);
}

V8UnionArrayBufferOrString* FileReader::result() const {
  if (error_ || !loader_)
    return nullptr;

  // Only set the result after |loader_| has finished loading which means that
  // FileReader::DidFinishLoading() has also been called. This ensures that the
  // result is not available until just before the kLoad event is fired.
  if (!loader_->HasFinishedLoading() || state_ != ReadyState::kDone) {
    return nullptr;
  }

  return result_.Get();
}

void FileReader::Terminate() {
  if (loader_) {
    loader_->Cancel();
    loader_ = nullptr;
  }
  state_ = kDone;
  result_ = nullptr;
  loading_state_ = kLoadingStateNone;
}

FileErrorCode FileReader::DidStartLoading() {
  base::AutoReset<bool> firing_events(&still_firing_events_, true);
  FireEvent(event_type_names::kLoadstart);
  return FileErrorCode::kOK;
}

FileErrorCode FileReader::DidReceiveData() {
  // Fire the progress event at least every 50ms.
  if (!last_progress_notification_time_) {
    last_progress_notification_time_ = base::ElapsedTimer();
  } else if (last_progress_notification_time_->Elapsed() >
             kProgressNotificationInterval) {
    base::AutoReset<bool> firing_events(&still_firing_events_, true);
    FireEvent(event_type_names::kProgress);
    last_progress_notification_time_ = base::ElapsedTimer();
  }
  return FileErrorCode::kOK;
}

void FileReader::DidFinishLoading(FileReaderData contents) {
  if (loading_state_ == kLoadingStateAborted)
    return;
  DCHECK_EQ(loading_state_, kLoadingStateLoading);

  if (read_type_ == FileReadType::kReadAsArrayBuffer) {
    result_ = MakeGarbageCollected<V8UnionArrayBufferOrString>(
        std::move(contents).AsDOMArrayBuffer());
  } else {
    result_ = MakeGarbageCollected<V8UnionArrayBufferOrString>(
        std::move(contents).AsString(read_type_, encoding_, blob_type_));
  }
  // When we set m_state to DONE below, we still need to fire
  // the load and loadend events. To avoid GC to collect this FileReader, we
  // use this separate variable to keep the wrapper of this FileReader alive.
  // An alternative would be to keep any ActiveScriptWrappables alive that is on
  // the stack.
  base::AutoReset<bool> firing_events(&still_firing_events_, true);

  // It's important that we change m_loadingState before firing any events
  // since any of the events could call abort(), which internally checks
  // if we're still loading (therefore we need abort process) or not.
  loading_state_ = kLoadingStateNone;

  FireEvent(event_type_names::kProgress);

  DCHECK_NE(kDone, state_);
  state_ = kDone;

  // Unregister the reader.
  ThrottlingController::FinishReaderType final_step =
      ThrottlingController::RemoveReader(GetExecutionContext(), this);

  FireEvent(event_type_names::kLoad);
  // TODO(https://crbug.com/1204139): Only fire loadend event if no new load was
  // started from the abort event handler.
  FireEvent(event_type_names::kLoadend);

  // All possible events have fired and we're done, no more pending activity.
  ThrottlingController::FinishReader(GetExecutionContext(), this, final_step);
}

void FileReader::DidFail(FileErrorCode error_code) {
  FileReaderAccumulator::DidFail(error_code);
  if (loading_state_ == kLoadingStateAborted)
    return;

  base::AutoReset<bool> firing_events(&still_firing_events_, true);

  DCHECK_EQ(kLoadingStateLoading, loading_state_);
  loading_state_ = kLoadingStateNone;

  DCHECK_NE(kDone, state_);
  state_ = kDone;

  error_ = file_error::CreateDOMException(error_code);

  // Unregister the reader.
  ThrottlingController::FinishReaderType final_step =
      ThrottlingController::RemoveReader(GetExecutionContext(), this);

  FireEvent(event_type_names::kError);
  FireEvent(event_type_names::kLoadend);

  // All possible events have fired and we're done, no more pending activity.
  ThrottlingController::FinishReader(GetExecutionContext(), this, final_step);
}

void FileReader::FireEvent(const AtomicString& type) {
  probe::AsyncTask async_task(GetExecutionContext(), async_task_context(),
                              "event");
  if (!loader_) {
    DispatchEvent(*ProgressEvent::Create(type, false, 0, 0));
    return;
  }

  if (loader_->TotalBytes()) {
    DispatchEvent(*ProgressEvent::Create(type, true, loader_->BytesLoaded(),
                                         *loader_->TotalBytes()));
  } else {
    DispatchEvent(
        *ProgressEvent::Create(type, false, loader_->BytesLoaded(), 0));
  }
}

void FileReader::Trace(Visitor* visitor) const {
  visitor->Trace(error_);
  visitor->Trace(loader_);
  visitor->Trace(result_);
  EventTarget::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
  FileReaderAccumulator::Trace(visitor);
}

}  // namespace blink
```