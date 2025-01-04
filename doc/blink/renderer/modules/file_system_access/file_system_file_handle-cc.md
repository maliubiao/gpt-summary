Response:
Let's break down the thought process for analyzing the `FileSystemFileHandle.cc` file.

**1. Initial Understanding and Core Purpose:**

The first step is to grasp the file's name and location. `blink/renderer/modules/file_system_access/file_system_file_handle.cc` strongly suggests this file implements the functionality of a `FileSystemFileHandle` within the File System Access API in Chromium's Blink rendering engine. The `.cc` extension indicates it's a C++ source file.

**2. Identifying Key Components and Functionality:**

Next, scan the code for keywords, class names, and function names that reveal its responsibilities. Look for:

* **Class Declaration:** `class FileSystemFileHandle` confirms the primary class.
* **Inheritance:** `FileSystemHandle` indicates it inherits from another related class.
* **Includes:** Headers like `mojom/file_system_access/...`, `bindings/core/v8/...`, and `core/fileapi/...` point to interactions with the Mojo IPC system, JavaScript bindings, and the core file API.
* **Methods:** Names like `createWritable`, `getFile`, `createSyncAccessHandle`, `transfer`, `queryPermission`, `requestPermission`, `move`, `remove`, `isSameEntry`, `getUniqueId`, and `getCloudIdentifiers` are the primary actions this class facilitates.
* **Mojo Interaction:**  The presence of `mojo::PendingRemote<mojom::blink::FileSystemAccessFileHandle>` and calls to methods on `mojo_ptr_` signify communication with a browser process component that handles the actual file system operations.
* **Promises:**  The extensive use of `ScriptPromise` indicates that many operations are asynchronous and involve JavaScript promises.
* **Error Handling:** The use of `ExceptionState` and calls to `file_system_access_error::Reject` demonstrate how errors are reported to JavaScript.

**3. Relating to JavaScript, HTML, and CSS:**

Now, consider how these functionalities map to web development concepts:

* **JavaScript:** The methods directly correspond to methods exposed on the `FileSystemFileHandle` JavaScript interface. Examples: `fileHandle.createWritable()`, `fileHandle.getFile()`, `fileHandle.createSyncAccessHandle()`.
* **HTML:** While not directly involved in rendering, the File System Access API is triggered by user interactions like `<input type="file" webkitdirectory>` or through JavaScript APIs like `window.showOpenFilePicker()`. The `FileSystemFileHandle` represents a file selected through these mechanisms.
* **CSS:**  CSS has no direct interaction with the File System Access API.

**4. Logical Reasoning (Hypothetical Inputs and Outputs):**

For each core method, consider what input the JavaScript might provide and what the expected output would be:

* **`createWritable()`:**
    * Input: Optional `FileSystemCreateWritableOptions` (specifying lock mode, keeping existing data).
    * Output: A `Promise` that resolves with a `FileSystemWritableFileStream` object.
* **`getFile()`:**
    * Input: None.
    * Output: A `Promise` that resolves with a `File` object (similar to a `<input type="file">` result).
* **`createSyncAccessHandle()`:**
    * Input: Optional `FileSystemCreateSyncAccessHandleOptions` (specifying lock mode).
    * Output: A `Promise` that resolves with a `FileSystemSyncAccessHandle` object (for synchronous file access).
* **Permission methods:**
    * Input:  Whether the permission is for read or write access.
    * Output: A `Promise` (for `requestPermission`) or a direct callback (for `queryPermission`) indicating the permission status.

**5. Identifying Common User/Programming Errors:**

Think about typical mistakes developers might make when using this API:

* **Calling methods after the handle is invalid:** This leads to `InvalidStateError`.
* **Incorrect permission requests:**  Trying to write to a file without write permission.
* **Using synchronous API (`createSyncAccessHandle`) in the main thread:** This can block the UI.
* **Not handling promise rejections:**  Failing to catch errors during file operations.

**6. Tracing User Operations (Debugging Clues):**

Consider how a user's action might lead to this specific code being executed:

* **`showOpenFilePicker()` or `showSaveFilePicker()`:** The user selects a file. The browser process resolves this to a `FileSystemFileHandle` and passes it to the renderer process.
* **Drag and Drop:**  Dragging a file into the browser window.
* **`<input type="file" webkitdirectory>`:**  Selecting a directory containing files.

The debugging process would involve:

* **Setting breakpoints in this C++ code:** To inspect the state of the `FileSystemFileHandle`.
* **Tracing Mojo messages:** To see the communication between the renderer and browser processes.
* **Examining JavaScript error logs:** To understand how errors are propagated back to the web page.

**7. Iterative Refinement:**

After the initial analysis, revisit the code and documentation (if available) for finer details and nuances. For example, understanding the different lock modes for `createWritable` and `createSyncAccessHandle`, or the purpose of the `Transfer()` method for cross-document file sharing.

This systematic approach allows for a comprehensive understanding of the `FileSystemFileHandle.cc` file, its role in the File System Access API, and its interactions with the web platform.
好的，让我们来详细分析一下 `blink/renderer/modules/file_system_access/file_system_file_handle.cc` 这个 Chromium Blink 引擎的源代码文件。

**文件功能概述**

`FileSystemFileHandle.cc` 文件实现了 `FileSystemFileHandle` 类，这个类是 File System Access API 的核心组成部分。它代表了用户在文件系统中选择的一个**文件**的句柄。通过这个句柄，Web 应用程序可以执行与该文件相关的操作，例如：

* **创建可写的文件流 (`createWritable`)**:  允许应用程序向文件中写入数据。
* **获取文件对象 (`getFile`)**:  获取一个 `File` 对象，该对象包含了文件的元数据（如名称、大小、最后修改时间）和文件内容（作为 Blob）。
* **创建同步访问句柄 (`createSyncAccessHandle`)**: 允许应用程序对文件进行同步的读写操作（需要注意，同步操作可能会阻塞主线程）。
* **传输句柄 (`Transfer`)**:  创建一个可以转移到其他上下文（如 Web Worker 或其他文档）的令牌，用于共享对文件的访问权限。
* **查询和请求权限 (`QueryPermissionImpl`, `RequestPermissionImpl`)**:  检查或请求对文件的读写权限。
* **移动或重命名文件 (`MoveImpl`)**:  将文件移动到新的位置或更改其名称。
* **删除文件 (`RemoveImpl`)**:  删除文件。
* **判断是否是同一个文件 (`IsSameEntryImpl`)**:  比较两个 `FileSystemFileHandle` 是否指向同一个文件。
* **获取唯一标识符 (`GetUniqueIdImpl`)**:  获取文件的唯一标识符。
* **获取云标识符 (`GetCloudIdentifiersImpl`)**:  获取与云存储相关的标识符。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`FileSystemFileHandle` 类是直接暴露给 JavaScript 的 API 的一部分。当用户通过 JavaScript 代码与 File System Access API 交互时，会创建并使用 `FileSystemFileHandle` 的实例。

**JavaScript 示例：**

```javascript
async function openAndWriteFile() {
  try {
    const [fileHandle] = await window.showOpenFilePicker(); // 用户选择文件
    if (fileHandle) {
      const writableStream = await fileHandle.createWritable(); // 创建可写流
      await writableStream.write('Hello, world!');
      await writableStream.close();
      console.log('写入成功！');
    }
  } catch (err) {
    console.error('文件操作失败:', err);
  }
}

async function getFileInfo() {
  try {
    const [fileHandle] = await window.showOpenFilePicker();
    if (fileHandle) {
      const file = await fileHandle.getFile(); // 获取 File 对象
      console.log('文件名:', file.name);
      console.log('文件大小:', file.size);
      console.log('最后修改时间:', file.lastModified);
    }
  } catch (err) {
    console.error('获取文件信息失败:', err);
  }
}
```

**HTML 示例：**

HTML 本身不直接操作 `FileSystemFileHandle`，但用户与 HTML 元素（例如 `<button>` 触发 `showOpenFilePicker`）的交互是创建 `FileSystemFileHandle` 的入口。

```html
<!DOCTYPE html>
<html>
<head>
  <title>File System Access Example</title>
</head>
<body>
  <button onclick="openAndWriteFile()">打开并写入文件</button>
  <button onclick="getFileInfo()">获取文件信息</button>
  <script src="script.js"></script>
</body>
</html>
```

**CSS 示例：**

CSS 与 `FileSystemFileHandle` 没有直接关系，因为它主要负责页面的样式和布局。

**逻辑推理 (假设输入与输出)**

假设我们调用 `fileHandle.getFile()` 方法：

**假设输入：**

* `fileHandle` 是一个有效的 `FileSystemFileHandle` 实例，它关联着文件系统中的一个真实文件。
* 文件名为 "my_document.txt"。
* 文件大小为 1024 字节。
* 文件最后修改时间是 2024 年 1 月 1 日。

**预期输出：**

* `getFile()` 方法返回一个 `Promise`。
* 当 `Promise` resolve 时，会返回一个 `File` 对象。
* 该 `File` 对象的属性如下：
    * `name`: "my_document.txt"
    * `size`: 1024
    * `lastModified`:  表示 2024 年 1 月 1 日的时间戳。
    * `type`:  文件的 MIME 类型（例如 "text/plain"）。
    * 内部包含一个指向文件内容的 Blob 数据。

**用户或编程常见的使用错误及举例说明**

1. **在 `FileSystemFileHandle` 失效后调用方法：**  一旦 `FileSystemFileHandle` 关联的文件被删除或由于某些原因不再可访问，尝试调用其方法会导致错误。

   ```javascript
   async function processFile(fileHandle) {
     const file = await fileHandle.getFile();
     console.log(file.name);
     // ... 可能在其他地方或稍后，文件被用户或程序删除了 ...
     try {
       const writable = await fileHandle.createWritable(); // 错误！文件句柄可能已失效
       // ...
     } catch (error) {
       console.error("操作失败，文件句柄可能已失效:", error); // 可能会抛出 InvalidStateError
     }
   }
   ```

2. **没有处理 Promise 的 rejection：** File System Access API 的许多操作是异步的，并返回 `Promise`。如果没有正确处理 `Promise` 的 `reject` 情况，可能会导致未捕获的错误。

   ```javascript
   async function writeFile(fileHandle) {
     fileHandle.createWritable() // 如果创建可写流失败（例如权限问题）会 reject
       .then(writable => {
         // ... 写入操作
       }); // 缺少 .catch 来处理错误情况
   }
   ```
   **正确的做法是添加 `.catch()`：**
   ```javascript
   async function writeFile(fileHandle) {
     fileHandle.createWritable()
       .then(writable => {
         // ... 写入操作
       })
       .catch(error => {
         console.error("创建可写流失败:", error);
       });
   }
   ```

3. **在不安全的环境中使用同步 API (`createSyncAccessHandle`)：**  `createSyncAccessHandle` 会阻塞主线程，如果在主线程上调用可能会导致页面卡顿。应该仅在 Web Worker 等安全的环境中使用。

   ```javascript
   async function syncReadFile(fileHandle) {
     try {
       const syncHandle = await fileHandle.createSyncAccessHandle(); // 在主线程上使用可能导致卡顿
       const buffer = new ArrayBuffer(1024);
       syncHandle.read(buffer, { at: 0 });
       syncHandle.close();
       // ...
     } catch (error) {
       console.error("同步读取失败:", error);
     }
   }
   ```

**用户操作是如何一步步的到达这里，作为调试线索**

1. **用户触发文件选择或保存操作：**
   * 用户点击带有 `onclick="openAndWriteFile()"` 的按钮。
   * `openAndWriteFile()` 函数调用 `window.showOpenFilePicker()` 或 `window.showSaveFilePicker()`。

2. **浏览器显示文件选择器：**
   * 浏览器弹出操作系统提供的文件选择对话框。

3. **用户选择文件并确认：**
   * 用户在文件选择器中浏览并选中一个文件。
   * 用户点击 "打开" 或 "保存" 按钮。

4. **浏览器进程处理用户选择：**
   * 浏览器进程接收到用户选择的文件信息。
   * 浏览器进程会根据安全策略和权限检查，决定是否允许 Web 应用程序访问该文件。

5. **创建 `FileSystemFileHandle` 的 Mojo 接口：**
   * 如果允许访问，浏览器进程会创建一个用于与渲染进程通信的 Mojo 接口 (`mojom::blink::FileSystemAccessFileHandle`)。

6. **传递 `FileSystemFileHandle` 对象到渲染进程：**
   * 浏览器进程将 `FileSystemFileHandle` 的 Mojo 远程端点（`mojo::PendingRemote<mojom::blink::FileSystemAccessFileHandle>`) 发送给渲染进程。

7. **JavaScript 接收 `FileSystemFileHandle`：**
   * 渲染进程中的 JavaScript 代码会接收到 `showOpenFilePicker()` 或 `showSaveFilePicker()` Promise 的 resolve 值，该值是一个包含 `FileSystemFileHandle` 实例的数组。

8. **JavaScript 调用 `FileSystemFileHandle` 的方法：**
   * 在 JavaScript 中，通过获得的 `fileHandle` 对象调用如 `createWritable()`、`getFile()` 等方法。

9. **Blink 引擎处理 JavaScript 调用：**
   * 当 JavaScript 调用 `fileHandle.createWritable()` 时，Blink 引擎会调用 `FileSystemFileHandle::createWritable` 方法（正是我们分析的这个文件中的代码）。

10. **Mojo 调用发送到浏览器进程：**
    * `FileSystemFileHandle::createWritable` 方法内部会通过 `mojo_ptr_->CreateFileWriter(...)` 将请求发送回浏览器进程，以执行实际的文件系统操作。

**调试线索：**

* **JavaScript 断点：** 在 JavaScript 代码中设置断点，查看 `fileHandle` 对象是否被正确创建，以及调用方法时的参数。
* **Mojo 接口跟踪：** 使用 Chromium 的内部工具（如 `chrome://tracing`）跟踪 Mojo 消息的传递，可以了解渲染进程和浏览器进程之间的通信过程，确认 `FileSystemAccessFileHandle` 接口是否正常工作。
* **Blink 引擎 C++ 断点：** 在 `FileSystemFileHandle.cc` 文件的相关方法中设置断点，例如 `createWritable`、`getFile` 等，可以深入了解 Blink 引擎如何处理这些请求，查看 Mojo 接口的状态和参数。
* **浏览器进程日志：** 浏览器进程通常会有日志输出，可以查看与文件系统访问相关的错误或信息。
* **权限检查：** 确认 Web 应用程序是否拥有访问所选文件的权限。浏览器控制台可能会显示相关的权限错误。

总而言之，`FileSystemFileHandle.cc` 是 File System Access API 在 Blink 渲染引擎中的关键实现，它连接了 JavaScript API 和底层的操作系统文件系统操作，负责处理各种文件相关的操作请求。理解这个文件的功能对于理解 File System Access API 的工作原理至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/file_system_access/file_system_file_handle.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/file_system_access/file_system_file_handle.h"

#include "mojo/public/cpp/bindings/pending_remote.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_cloud_identifier.mojom-blink.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_error.mojom-blink.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_file_writer.mojom-blink.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_transfer_token.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_file_system_create_sync_access_handle_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_file_system_create_writable_options.h"
#include "third_party/blink/renderer/core/fileapi/file.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_access_error.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_access_file_delegate.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_sync_access_handle.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_writable_file_stream.h"
#include "third_party/blink/renderer/modules/file_system_access/storage_manager_file_system_access.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/file_metadata.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

using mojom::blink::FileSystemAccessErrorPtr;

FileSystemFileHandle::FileSystemFileHandle(
    ExecutionContext* context,
    const String& name,
    mojo::PendingRemote<mojom::blink::FileSystemAccessFileHandle> mojo_ptr)
    : FileSystemHandle(context, name), mojo_ptr_(context) {
  mojo_ptr_.Bind(std::move(mojo_ptr),
                 context->GetTaskRunner(TaskType::kStorage));
  DCHECK(mojo_ptr_.is_bound());
}

ScriptPromise<FileSystemWritableFileStream>
FileSystemFileHandle::createWritable(
    ScriptState* script_state,
    const FileSystemCreateWritableOptions* options,
    ExceptionState& exception_state) {
  if (!mojo_ptr_.is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError, "");
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<FileSystemWritableFileStream>>(
          script_state, exception_state.GetContext());
  auto result = resolver->Promise();

  mojom::blink::FileSystemAccessWritableFileStreamLockMode lock_mode;

  switch (options->mode().AsEnum()) {
    case V8FileSystemWritableFileStreamMode::Enum::kExclusive:
      lock_mode =
          mojom::blink::FileSystemAccessWritableFileStreamLockMode::kExclusive;
      break;
    case V8FileSystemWritableFileStreamMode::Enum::kSiloed:
      lock_mode =
          mojom::blink::FileSystemAccessWritableFileStreamLockMode::kSiloed;
      break;
  }

  mojo_ptr_->CreateFileWriter(
      options->keepExistingData(), options->autoClose(), lock_mode,
      WTF::BindOnce(
          [](FileSystemFileHandle*,
             ScriptPromiseResolver<FileSystemWritableFileStream>* resolver,
             V8FileSystemWritableFileStreamMode lock_mode,
             mojom::blink::FileSystemAccessErrorPtr result,
             mojo::PendingRemote<mojom::blink::FileSystemAccessFileWriter>
                 writer) {
            // Keep `this` alive so the handle will not be garbage-collected
            // before the promise is resolved.
            ScriptState* script_state = resolver->GetScriptState();
            if (!script_state) {
              return;
            }
            if (result->status != mojom::blink::FileSystemAccessStatus::kOk) {
              file_system_access_error::Reject(resolver, *result);
              return;
            }

            resolver->Resolve(FileSystemWritableFileStream::Create(
                script_state, std::move(writer), lock_mode));
          },
          WrapPersistent(this), WrapPersistent(resolver), options->mode()));

  return result;
}

ScriptPromise<File> FileSystemFileHandle::getFile(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!mojo_ptr_.is_bound()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError, "");
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<File>>(
      script_state, exception_state.GetContext());
  auto result = resolver->Promise();

  mojo_ptr_->AsBlob(WTF::BindOnce(
      [](FileSystemFileHandle*, ScriptPromiseResolver<File>* resolver,
         const String& name, FileSystemAccessErrorPtr result,
         const base::File::Info& info,
         const scoped_refptr<BlobDataHandle>& blob) {
        // Keep `this` alive so the handle will not be garbage-collected
        // before the promise is resolved.
        if (result->status != mojom::blink::FileSystemAccessStatus::kOk) {
          file_system_access_error::Reject(resolver, *result);
          return;
        }
        resolver->Resolve(MakeGarbageCollected<File>(
            name, NullableTimeToOptionalTime(info.last_modified), blob));
      },
      WrapPersistent(this), WrapPersistent(resolver), name()));

  return result;
}

ScriptPromise<FileSystemSyncAccessHandle>
FileSystemFileHandle::createSyncAccessHandle(ScriptState* script_state,
                                             ExceptionState& exception_state) {
  return createSyncAccessHandle(
      script_state, FileSystemCreateSyncAccessHandleOptions::Create(),
      exception_state);
}

ScriptPromise<FileSystemSyncAccessHandle>
FileSystemFileHandle::createSyncAccessHandle(
    ScriptState* script_state,
    const FileSystemCreateSyncAccessHandleOptions* options,
    ExceptionState& exception_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<FileSystemSyncAccessHandle>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  auto on_allowed_callback =
      WTF::BindOnce(&FileSystemFileHandle::CreateSyncAccessHandleImpl,
                    WrapWeakPersistent(this), WrapPersistent(options),
                    WrapPersistent(resolver));

  auto on_got_storage_access_status_cb =
      WTF::BindOnce(&FileSystemFileHandle::OnGotFileSystemStorageAccessStatus,
                    WrapWeakPersistent(this), WrapPersistent(resolver),
                    std::move(on_allowed_callback));

  if (storage_access_status_.has_value()) {
    std::move(on_got_storage_access_status_cb)
        .Run(mojom::blink::FileSystemAccessError::New(
            /*status=*/get<0>(storage_access_status_.value()),
            /*file_error=*/get<1>(storage_access_status_.value()),
            /*message=*/get<2>(storage_access_status_.value())));
  } else {
    StorageManagerFileSystemAccess::CheckStorageAccessIsAllowed(
        ExecutionContext::From(script_state),
        std::move(on_got_storage_access_status_cb));
  }

  return promise;
}

void FileSystemFileHandle::CreateSyncAccessHandleImpl(
    const FileSystemCreateSyncAccessHandleOptions* options,
    ScriptPromiseResolver<FileSystemSyncAccessHandle>* resolver) {
  if (!mojo_ptr_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError, "");
    return;
  }

  mojom::blink::FileSystemAccessAccessHandleLockMode lock_mode;

  // This assertion protects against the IDL enum changing without updating the
  // corresponding mojom interface, or vice versa.
  //
  static_assert(
      V8FileSystemSyncAccessHandleMode::kEnumSize ==
          static_cast<size_t>(
              mojom::blink::FileSystemAccessAccessHandleLockMode::kMaxValue)
              // This offset of 1 accounts for the zero-indexing of the mojom
              // enum values.
              + 1
              // TODO(crbug/1513463): This offset of 1 accounts for the
              // "in-place" option. This should be removed.
              + 1,
      "the number of values in the FileSystemAccessAccessHandleLockMode mojom "
      "enum must match the number of values in the "
      "FileSystemSyncAccessHandleMode blink enum");

  switch (options->mode().AsEnum()) {
    // TODO(crbug/1513463): "in-place" acts as an alternative to "readwrite".
    // This is for backwards compatibility and should be removed.
    case V8FileSystemSyncAccessHandleMode::Enum::kInPlace:
    case V8FileSystemSyncAccessHandleMode::Enum::kReadwrite:
      lock_mode =
          mojom::blink::FileSystemAccessAccessHandleLockMode::kReadwrite;
      break;
    case V8FileSystemSyncAccessHandleMode::Enum::kReadOnly:
      lock_mode = mojom::blink::FileSystemAccessAccessHandleLockMode::kReadOnly;
      break;
    case V8FileSystemSyncAccessHandleMode::Enum::kReadwriteUnsafe:
      lock_mode =
          mojom::blink::FileSystemAccessAccessHandleLockMode::kReadwriteUnsafe;
      break;
  }

  mojo_ptr_->OpenAccessHandle(
      lock_mode,
      WTF::BindOnce(
          [](FileSystemFileHandle*,
             ScriptPromiseResolver<FileSystemSyncAccessHandle>* resolver,
             V8FileSystemSyncAccessHandleMode lock_mode,
             FileSystemAccessErrorPtr result,
             mojom::blink::FileSystemAccessAccessHandleFilePtr file,
             mojo::PendingRemote<mojom::blink::FileSystemAccessAccessHandleHost>
                 access_handle_remote) {
            // Keep `this` alive so the handle will not be garbage-collected
            // before the promise is resolved.
            if (result->status != mojom::blink::FileSystemAccessStatus::kOk) {
              file_system_access_error::Reject(resolver, *result);
              return;
            }
            DCHECK(!file.is_null());
            DCHECK(access_handle_remote.is_valid());

            ExecutionContext* context = resolver->GetExecutionContext();
            if (!context) {
              return;
            }

            FileSystemAccessFileDelegate* file_delegate = nullptr;
            if (file->is_regular_file()) {
              mojom::blink::FileSystemAccessRegularFilePtr regular_file =
                  std::move(file->get_regular_file());
              file_delegate = FileSystemAccessFileDelegate::Create(
                  context, std::move(regular_file));
            } else if (file->is_incognito_file_delegate()) {
              file_delegate = FileSystemAccessFileDelegate::CreateForIncognito(
                  context, std::move(file->get_incognito_file_delegate()));
            }

            if (!file_delegate || !file_delegate->IsValid()) {
              file_system_access_error::Reject(
                  resolver,
                  *mojom::blink::FileSystemAccessError::New(
                      mojom::blink::FileSystemAccessStatus::kFileError,
                      base::File::Error::FILE_ERROR_FAILED, "File not valid"));
              return;
            }
            resolver->Resolve(MakeGarbageCollected<FileSystemSyncAccessHandle>(
                context, std::move(file_delegate),
                std::move(access_handle_remote), std::move(lock_mode)));
          },
          WrapPersistent(this), WrapPersistent(resolver), options->mode()));
}

mojo::PendingRemote<mojom::blink::FileSystemAccessTransferToken>
FileSystemFileHandle::Transfer() {
  mojo::PendingRemote<mojom::blink::FileSystemAccessTransferToken> result;
  if (mojo_ptr_.is_bound()) {
    mojo_ptr_->Transfer(result.InitWithNewPipeAndPassReceiver());
  }
  return result;
}

void FileSystemFileHandle::Trace(Visitor* visitor) const {
  visitor->Trace(mojo_ptr_);
  FileSystemHandle::Trace(visitor);
}

void FileSystemFileHandle::QueryPermissionImpl(
    bool writable,
    base::OnceCallback<void(mojom::blink::PermissionStatus)> callback) {
  if (!mojo_ptr_.is_bound()) {
    std::move(callback).Run(mojom::blink::PermissionStatus::DENIED);
    return;
  }
  mojo_ptr_->GetPermissionStatus(writable, std::move(callback));
}

void FileSystemFileHandle::RequestPermissionImpl(
    bool writable,
    base::OnceCallback<void(mojom::blink::FileSystemAccessErrorPtr,
                            mojom::blink::PermissionStatus)> callback) {
  if (!mojo_ptr_.is_bound()) {
    std::move(callback).Run(
        mojom::blink::FileSystemAccessError::New(
            mojom::blink::FileSystemAccessStatus::kInvalidState,
            base::File::Error::FILE_ERROR_FAILED, "Context Destroyed"),
        mojom::blink::PermissionStatus::DENIED);
    return;
  }

  mojo_ptr_->RequestPermission(writable, std::move(callback));
}

void FileSystemFileHandle::MoveImpl(
    mojo::PendingRemote<mojom::blink::FileSystemAccessTransferToken> dest,
    const String& new_entry_name,
    base::OnceCallback<void(mojom::blink::FileSystemAccessErrorPtr)> callback) {
  if (!mojo_ptr_.is_bound()) {
    std::move(callback).Run(mojom::blink::FileSystemAccessError::New(
        mojom::blink::FileSystemAccessStatus::kInvalidState,
        base::File::Error::FILE_ERROR_FAILED, "Context Destroyed"));
    return;
  }

  if (dest.is_valid()) {
    mojo_ptr_->Move(std::move(dest), new_entry_name, std::move(callback));
  } else {
    mojo_ptr_->Rename(new_entry_name, std::move(callback));
  }
}

void FileSystemFileHandle::RemoveImpl(
    const FileSystemRemoveOptions* options,
    base::OnceCallback<void(mojom::blink::FileSystemAccessErrorPtr)> callback) {
  if (!mojo_ptr_.is_bound()) {
    std::move(callback).Run(mojom::blink::FileSystemAccessError::New(
        mojom::blink::FileSystemAccessStatus::kInvalidState,
        base::File::Error::FILE_ERROR_FAILED, "Context Destroyed"));
    return;
  }

  mojo_ptr_->Remove(std::move(callback));
}

void FileSystemFileHandle::IsSameEntryImpl(
    mojo::PendingRemote<mojom::blink::FileSystemAccessTransferToken> other,
    base::OnceCallback<void(mojom::blink::FileSystemAccessErrorPtr, bool)>
        callback) {
  if (!mojo_ptr_.is_bound()) {
    std::move(callback).Run(
        mojom::blink::FileSystemAccessError::New(
            mojom::blink::FileSystemAccessStatus::kInvalidState,
            base::File::Error::FILE_ERROR_FAILED, "Context Destroyed"),
        false);
    return;
  }

  mojo_ptr_->IsSameEntry(std::move(other), std::move(callback));
}

void FileSystemFileHandle::GetUniqueIdImpl(
    base::OnceCallback<void(mojom::blink::FileSystemAccessErrorPtr,
                            const WTF::String&)> callback) {
  if (!mojo_ptr_.is_bound()) {
    std::move(callback).Run(
        mojom::blink::FileSystemAccessError::New(
            mojom::blink::FileSystemAccessStatus::kInvalidState,
            base::File::Error::FILE_ERROR_FAILED, "Context Destroyed"),
        "");
    return;
  }
  mojo_ptr_->GetUniqueId(std::move(callback));
}

void FileSystemFileHandle::GetCloudIdentifiersImpl(
    base::OnceCallback<void(
        mojom::blink::FileSystemAccessErrorPtr,
        Vector<mojom::blink::FileSystemAccessCloudIdentifierPtr>)> callback) {
  if (!mojo_ptr_.is_bound()) {
    std::move(callback).Run(
        mojom::blink::FileSystemAccessError::New(
            mojom::blink::FileSystemAccessStatus::kInvalidState,
            base::File::Error::FILE_ERROR_FAILED, "Context Destroyed"),
        {});
    return;
  }
  mojo_ptr_->GetCloudIdentifiers(std::move(callback));
}

void FileSystemFileHandle::OnGotFileSystemStorageAccessStatus(
    ScriptPromiseResolver<FileSystemSyncAccessHandle>* resolver,
    base::OnceClosure on_allowed_callback,
    mojom::blink::FileSystemAccessErrorPtr result) {
  if (!resolver->GetExecutionContext() ||
      !resolver->GetScriptState()->ContextIsValid()) {
    return;
  }

  CHECK(result);
  if (storage_access_status_.has_value()) {
    CHECK_EQ(/*status=*/get<0>(storage_access_status_.value()), result->status);
    CHECK_EQ(/*file_error=*/get<1>(storage_access_status_.value()),
             result->file_error);
    CHECK_EQ(/*message=*/get<2>(storage_access_status_.value()),
             result->message);
  } else {
    storage_access_status_ =
        std::make_tuple(result->status, result->file_error, result->message);
  }

  if (result->status != mojom::blink::FileSystemAccessStatus::kOk) {
    auto* const isolate = resolver->GetScriptState()->GetIsolate();
    ScriptState::Scope scope(resolver->GetScriptState());
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        isolate, DOMExceptionCode::kSecurityError, result->message));
    return;
  }

  std::move(on_allowed_callback).Run();
}

}  // namespace blink

"""

```