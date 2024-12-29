Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Core Goal:** The first step is to recognize what this code is about. The filename `file_system_directory_handle.cc` and the namespace `blink::FileSystemAccess` strongly suggest it deals with handling directories within a file system access API in the Chromium browser (Blink rendering engine).

2. **Identify Key Classes and Structures:**  Scan the code for prominent class names. The main class is `FileSystemDirectoryHandle`. Notice also `IterationSource`, which is an inner class, and various `mojom::blink::FileSystemAccess*` types. These `mojom` types indicate interaction with other parts of the Chromium system, likely through inter-process communication (IPC).

3. **Analyze Class Members:** Look at the member variables of `FileSystemDirectoryHandle`. The presence of `mojo::PendingRemote<mojom::blink::FileSystemAccessDirectoryHandle>` is crucial. This suggests that the `FileSystemDirectoryHandle` in the renderer process is a *proxy* for the actual directory handle, which likely resides in the browser process. The `mojo_ptr_` member is the connection to that remote object.

4. **Examine Public Methods:**  Focus on the public methods of `FileSystemDirectoryHandle`. These methods represent the API surface exposed to JavaScript (though not directly). Methods like `getFileHandle`, `getDirectoryHandle`, `removeEntry`, `resolve`, `Transfer`, `QueryPermissionImpl`, `RequestPermissionImpl`, `MoveImpl`, `RemoveImpl`, `IsSameEntryImpl`, `GetUniqueIdImpl`, `GetCloudIdentifiersImpl`, and `CreateIterationSource` are the core functionalities of this class.

5. **Connect to JavaScript API:** Based on the method names and their parameters, start making connections to the Web File System Access API. For example:
    * `getFileHandle` strongly corresponds to the JavaScript `FileSystemDirectoryHandle.getFileHandle()` method.
    * `getDirectoryHandle` maps to `FileSystemDirectoryHandle.getDirectoryHandle()`.
    * `removeEntry` maps to `FileSystemDirectoryHandle.removeEntry()`.
    * The `IterationSource` class and `CreateIterationSource` suggest implementation of the asynchronous iteration protocol (using `for await...of` in JavaScript).

6. **Analyze Method Logic:**  For each public method, try to understand its purpose by looking at the code:
    * **Mojo Interaction:**  Notice the frequent use of `mojo_ptr_->MethodName(...)`. This signifies calls to the browser process to perform the actual file system operations.
    * **Promise Handling:** The methods return `ScriptPromise` objects. This confirms their asynchronous nature and how they interact with JavaScript's promise mechanism. Look for `ScriptPromiseResolver` usage for resolving or rejecting promises based on the result of the Mojo calls.
    * **Error Handling:**  Observe how `FileSystemAccessErrorPtr` is used to represent errors returned from the browser process and how `file_system_access_error::Reject` is used to propagate these errors to the JavaScript promise.
    * **Options Handling:**  Pay attention to parameters like `FileSystemGetFileOptions`, `FileSystemGetDirectoryOptions`, and `FileSystemRemoveOptions`, and how they're passed to the Mojo calls.
    * **`IterationSource` Logic:** Analyze the `IterationSource` class. It uses a `HeapMojoReceiver` to listen for directory entries from the browser. It queues the results and resolves the JavaScript promise for each entry as it arrives. This explains how the `entries()` method of `FileSystemDirectoryHandle` is implemented.

7. **Consider Edge Cases and Errors:** Think about potential problems or common mistakes:
    * **`mojo_ptr_.is_bound()` Checks:**  These checks are crucial. If the connection to the browser process is lost, many operations will fail. This points to a potential user error or browser-side issue.
    * **Invalid State Error:** The code explicitly throws `InvalidStateError` in several places when `mojo_ptr_` is not bound. This suggests scenarios where the `FileSystemDirectoryHandle` object might be in an unusable state.
    * **Permission Issues:** The `QueryPermissionImpl` and `RequestPermissionImpl` methods directly deal with permissions, a common area for user errors.

8. **Infer User Actions:**  Based on the functionalities, deduce how a user might trigger this code:
    * Using the `<input type="file" webkitdirectory>` element to select a directory.
    * Calling methods like `showDirectoryPicker()` in JavaScript.
    * Using the `FileSystemDirectoryHandle` API (e.g., `getDirectoryHandle`, `getFileHandle`, `removeEntry`, `entries()`).

9. **Construct Examples and Scenarios:** Create concrete examples of how JavaScript code interacts with this C++ code. This helps illustrate the connection between the front-end and back-end.

10. **Structure the Output:**  Organize the analysis into clear sections: Functionality, Relationship to JavaScript/HTML/CSS, Logical Reasoning, User/Programming Errors, and Debugging Clues. Use code snippets where appropriate to illustrate points.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This looks like it just manages file system operations."  **Correction:**  "It *represents* a directory handle in the renderer process, delegating actual operations to the browser process via Mojo."
* **Initial thought:** "The `IterationSource` just gets all the entries at once." **Correction:** "It retrieves entries in chunks, potentially for large directories, as indicated by `has_more_entries`."
* **Missing a key connection:** "How does the JavaScript get the `FileSystemDirectoryHandle` in the first place?"  **Realization:** This code doesn't cover *creation*. It handles operations *on* an existing handle. The creation likely happens in other parts of the File System Access API implementation.

By following these steps, iterating through the code, and making connections between the C++ implementation and the JavaScript API, a comprehensive understanding of the `FileSystemDirectoryHandle.cc` file can be achieved.
这个文件 `blink/renderer/modules/file_system_access/file_system_directory_handle.cc` 是 Chromium Blink 渲染引擎中，用于实现 **Web File System Access API** 中 `FileSystemDirectoryHandle` 接口的关键组件。它负责管理对文件系统目录的操作，并与浏览器进程进行通信以执行这些操作。

以下是它的主要功能和相关说明：

**功能列表:**

1. **表示文件系统目录:** `FileSystemDirectoryHandle` 类在 JavaScript 中代表一个文件系统目录。这个 C++ 文件实现了该类的核心逻辑。

2. **获取文件句柄 (`getFileHandle`)**:
   - 允许 JavaScript 代码获取目录中特定文件的 `FileSystemFileHandle`。
   - 可以选择创建文件 (如果不存在)。
   - 通过 Mojo IPC (Inter-Process Communication) 与浏览器进程通信，请求获取文件句柄。

3. **获取目录句柄 (`getDirectoryHandle`)**:
   - 允许 JavaScript 代码获取目录中子目录的 `FileSystemDirectoryHandle`。
   - 可以选择创建子目录 (如果不存在)。
   - 同样使用 Mojo IPC 与浏览器进程通信。

4. **删除条目 (`removeEntry`)**:
   - 允许 JavaScript 代码删除目录中的文件或子目录。
   - 支持递归删除子目录及其内容。
   - 通过 Mojo IPC 与浏览器进程通信。

5. **解析路径 (`resolve`)**:
   - 允许 JavaScript 代码解析一个 `FileSystemHandle` (文件或目录) 相对于当前目录的路径。
   - 返回一个包含路径段的字符串数组。
   - 通过 Mojo IPC 与浏览器进程通信。

6. **传输句柄 (`Transfer`)**:
   - 允许将目录句柄转移到另一个上下文或进程。
   - 返回一个 `mojom::blink::FileSystemAccessTransferToken`，用于在其他地方重建句柄。

7. **查询权限 (`QueryPermissionImpl`)**:
   - 允许查询当前目录的读写权限状态。
   - 通过 Mojo IPC 与浏览器进程通信。

8. **请求权限 (`RequestPermissionImpl`)**:
   - 允许请求当前目录的读写权限。
   - 通过 Mojo IPC 与浏览器进程通信。

9. **移动/重命名 (`MoveImpl`)**:
   - 允许移动或重命名当前目录。
   - 如果提供了目标目录的传输令牌 (`dest`)，则执行移动操作。
   - 否则，执行重命名操作。
   - 通过 Mojo IPC 与浏览器进程通信。

10. **删除自身 (`RemoveImpl`)**:
    - 允许删除当前目录自身。
    - 支持递归删除。
    - 通过 Mojo IPC 与浏览器进程通信。

11. **判断是否是同一个条目 (`IsSameEntryImpl`)**:
    - 允许判断当前目录是否与另一个 `FileSystemHandle` 指向同一个文件系统条目。
    - 通过 Mojo IPC 与浏览器进程通信。

12. **获取唯一 ID (`GetUniqueIdImpl`)**:
    - 允许获取目录的唯一标识符。
    - 通过 Mojo IPC 与浏览器进程通信。

13. **获取云标识符 (`GetCloudIdentifiersImpl`)**:
    - 允许获取与目录相关的云存储标识符 (如果适用)。
    - 通过 Mojo IPC 与浏览器进程通信。

14. **实现异步迭代 (`CreateIterationSource`, `IterationSource`)**:
    - 支持使用 JavaScript 的 `for await...of` 语法遍历目录中的条目。
    - `IterationSource` 是一个内部类，负责管理异步迭代的状态，并从浏览器进程分批获取目录条目。

**与 JavaScript, HTML, CSS 的关系 (举例说明):**

`FileSystemDirectoryHandle.cc` 的功能直接对应于 JavaScript 中 `FileSystemDirectoryHandle` 接口的方法。以下是一些示例：

* **JavaScript:**
  ```javascript
  const directoryHandle = await window.showDirectoryPicker();
  const fileHandle = await directoryHandle.getFileHandle('my-file.txt', { create: true });
  const subDirectoryHandle = await directoryHandle.getDirectoryHandle('my-folder');
  await directoryHandle.removeEntry('old-file.txt');

  for await (const [name, handle] of directoryHandle.entries()) {
    console.log(name, handle);
  }
  ```

* **HTML:**
  HTML 主要通过触发 JavaScript 代码来间接使用这些功能，例如通过 `<input type="file" webkitdirectory>` 元素让用户选择一个目录，然后 JavaScript 代码可以获取该目录的 `FileSystemDirectoryHandle`。

  ```html
  <input type="file" webkitdirectory id="directoryPicker">
  <script>
    document.getElementById('directoryPicker').addEventListener('change', async (event) => {
      const directoryHandle = await event.target.files[0].handle; // 获取 DirectoryHandle
      // ... 使用 directoryHandle 进行操作
    });
  </script>
  ```

* **CSS:**
  CSS 与此文件直接关联较少。但如果涉及到文件选择器的样式，可能会间接影响用户与文件系统 API 的交互体验。

**逻辑推理 (假设输入与输出):**

假设有以下 JavaScript 代码：

```javascript
const directoryHandle = await window.showDirectoryPicker();
const fileHandle = await directoryHandle.getFileHandle('new_file.txt', { create: true });
```

**假设输入:**

* `directoryHandle`: 一个有效的 `FileSystemDirectoryHandle` 对象，指向用户选择的目录。
* `'new_file.txt'`:  要获取或创建的文件名。
* `{ create: true }`:  选项，指示如果文件不存在则创建。

**逻辑推理过程 (发生在 `FileSystemDirectoryHandle::getFileHandle` 中):**

1. JavaScript 调用 `directoryHandle.getFileHandle('new_file.txt', { create: true })`。
2. Blink 的 JavaScript 绑定层将此调用转发到 C++ 的 `FileSystemDirectoryHandle::getFileHandle` 方法。
3. `FileSystemDirectoryHandle::getFileHandle` 检查 `mojo_ptr_` 是否已绑定 (连接到浏览器进程)。
4. 创建一个 `ScriptPromiseResolver` 来处理异步操作的结果。
5. 通过 `mojo_ptr_->GetFile('new_file.txt', true, ...)` 发送一个 IPC 消息到浏览器进程，请求获取或创建名为 `new_file.txt` 的文件句柄。
6. 浏览器进程执行文件系统操作。
7. 浏览器进程通过 Mojo IPC 将结果 (成功或失败，以及文件句柄的 Mojo 接口) 发送回渲染进程。
8. `FileSystemDirectoryHandle::getFileHandle` 中的回调函数接收到结果。
9. 如果操作成功，则创建一个新的 `FileSystemFileHandle` 对象，并使用 `resolver->Resolve()` 解析 JavaScript Promise。
10. 如果操作失败，则使用 `file_system_access_error::Reject()` 拒绝 JavaScript Promise，并传递错误信息。

**假设输出 (成功):**

* JavaScript Promise 被解析为一个新的 `FileSystemFileHandle` 对象，代表文件 "new_file.txt"。

**假设输出 (失败，例如权限不足):**

* JavaScript Promise 被拒绝，并抛出一个 `DOMException`，其消息描述了错误原因 (例如 "Permission denied")。

**用户或编程常见的使用错误 (举例说明):**

1. **尝试在未绑定的句柄上操作:**
   - **错误示例:**  如果 `FileSystemDirectoryHandle` 对象在某些情况下变得无效 (例如，关联的文件系统条目被删除，或者页面被卸载)，尝试在其上调用方法会导致错误。
   - **C++ 代码中的体现:**  方法开始时会检查 `!mojo_ptr_.is_bound()`，如果未绑定则抛出 `InvalidStateError`。

2. **权限问题:**
   - **错误示例:**  JavaScript 代码尝试访问或修改用户没有权限的目录或文件。
   - **C++ 代码中的体现:**  浏览器进程会检查权限，并通过 Mojo IPC 返回相应的错误状态 (例如 `kPermissionDenied`)，最终导致 JavaScript Promise 被拒绝。

3. **文件或目录不存在:**
   - **错误示例:**  尝试获取一个不存在的文件或目录，且 `create` 选项为 `false`。
   - **C++ 代码中的体现:** 浏览器进程会返回 `kNotFound` 错误状态。

4. **操作冲突:**
   - **错误示例:**  多个 JavaScript 代码尝试同时修改同一个文件或目录，可能导致数据不一致或操作失败。
   - **C++ 代码中的体现:**  Mojo IPC 的调用是异步的，Blink 引擎会尝试协调这些操作，但某些并发场景下可能会失败，并返回相应的错误状态。

5. **递归删除包含内容的目录时未设置 `recursive: true`:**
   - **错误示例:**  调用 `removeEntry` 删除一个非空目录，但未设置 `recursive: true` 选项。
   - **C++ 代码中的体现:** 浏览器进程会返回一个错误，指示目录非空，需要递归删除。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户交互触发:** 用户在网页上执行某些操作，例如：
   - 点击 `<input type="file" webkitdirectory>` 元素并选择一个目录。
   - 调用 `window.showDirectoryPicker()` 或 `window.showOpenFilePicker()` 等 API。
   - 拖放一个文件夹到浏览器窗口。

2. **浏览器进程处理:** 浏览器进程接收到用户的操作请求，并根据用户的选择或 API 调用，获取到文件系统条目的信息。

3. **创建 FileSystemDirectoryHandle (或其他句柄):** 浏览器进程会创建一个代表用户选择的目录的 `FileSystemDirectoryHandle` 的 Mojo 接口实例。

4. **Mojo IPC 传递:**  这个 Mojo 接口实例的 "pending remote" 端被传递到渲染进程 (当前网页的进程)。

5. **Blink 创建 C++ 对象:**  在渲染进程中，`FileSystemDirectoryHandle.cc` 中的代码接收到这个 pending remote，并创建一个 `FileSystemDirectoryHandle` C++ 对象，`mojo_ptr_` 成员会绑定到这个 remote。

6. **JavaScript 调用方法:**  网页的 JavaScript 代码调用 `FileSystemDirectoryHandle` 对象的方法，例如 `getFileHandle`。

7. **C++ 方法执行:**  调用会被传递到 `FileSystemDirectoryHandle.cc` 中相应的方法 (例如 `getFileHandle`)。

8. **Mojo IPC 调用:**  C++ 方法通过 `mojo_ptr_` 发送 IPC 消息到浏览器进程，请求执行文件系统操作。

9. **浏览器进程执行操作:** 浏览器进程接收到请求，并执行实际的文件系统操作。

10. **Mojo IPC 返回结果:** 浏览器进程将操作结果 (成功或失败，以及相关数据) 通过 Mojo IPC 返回给渲染进程。

11. **Promise 解析/拒绝:**  `FileSystemDirectoryHandle.cc` 中的回调函数根据浏览器进程返回的结果，解析或拒绝 JavaScript 的 Promise。

**调试线索:**

* **断点:** 在 `FileSystemDirectoryHandle.cc` 的关键方法 (例如 `getFileHandle`, `getDirectoryHandle`, `removeEntry`) 中设置断点，可以观察参数的值，以及 Mojo IPC 调用的过程和结果。
* **Mojo 日志:**  Chromium 提供了 Mojo 的日志记录功能，可以查看 IPC 消息的发送和接收，帮助理解渲染进程和浏览器进程之间的通信。
* **`chrome://inspect/#devices`:** 可以连接到正在运行的 Chrome 实例，查看渲染进程的控制台输出和性能信息。
* **审查 JavaScript 代码:**  检查 JavaScript 代码中对 `FileSystemDirectoryHandle` 的使用方式，确保参数正确，并正确处理 Promise 的结果。
* **权限检查:**  检查浏览器的权限设置，确保网页有访问用户所选文件系统部分的权限。

总而言之，`FileSystemDirectoryHandle.cc` 是 Web File System Access API 在 Blink 渲染引擎中的核心实现，负责将 JavaScript 的文件系统操作请求转发到浏览器进程，并处理返回的结果，从而让网页能够安全地与用户的文件系统进行交互。

Prompt: 
```
这是目录为blink/renderer/modules/file_system_access/file_system_directory_handle.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/file_system_access/file_system_directory_handle.h"

#include "mojo/public/cpp/bindings/pending_remote.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_cloud_identifier.mojom-blink.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_directory_handle.mojom-blink.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_error.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_file_system_get_directory_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_file_system_get_file_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_file_system_remove_options.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/execution_context_lifecycle_observer.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_access_error.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_file_handle.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_deque.h"
#include "third_party/blink/renderer/platform/heap/self_keep_alive.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_receiver.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class FileSystemDirectoryHandle::IterationSource final
    : public PairAsyncIterable<FileSystemDirectoryHandle>::IterationSource,
      public ExecutionContextClient,
      public mojom::blink::FileSystemAccessDirectoryEntriesListener {
 public:
  IterationSource(ScriptState* script_state,
                  ExecutionContext* execution_context,
                  Kind kind,
                  FileSystemDirectoryHandle* directory)
      : PairAsyncIterable<FileSystemDirectoryHandle>::IterationSource(
            script_state,
            kind),
        ExecutionContextClient(execution_context),
        directory_(directory),
        receiver_(this, execution_context),
        keep_alive_(this) {
    directory_->MojoHandle()->GetEntries(receiver_.BindNewPipeAndPassRemote(
        execution_context->GetTaskRunner(TaskType::kStorage)));
  }

  void DidReadDirectory(mojom::blink::FileSystemAccessErrorPtr result,
                        Vector<mojom::blink::FileSystemAccessEntryPtr> entries,
                        bool has_more_entries) override {
    is_waiting_for_more_entries_ = has_more_entries;
    ExecutionContext* const execution_context = GetExecutionContext();
    if (!has_more_entries || !execution_context) {
      keep_alive_.Clear();
    }
    if (!execution_context) {
      return;
    }
    if (result->status == mojom::blink::FileSystemAccessStatus::kOk) {
      for (auto& entry : entries) {
        file_system_handle_queue_.push_back(
            FileSystemHandle::CreateFromMojoEntry(std::move(entry),
                                                  execution_context));
      }
    } else {
      CHECK(!has_more_entries);
      error_ = std::move(result);
    }
    ScriptState::Scope script_state_scope(GetScriptState());
    TryResolvePromise();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(directory_);
    visitor->Trace(receiver_);
    visitor->Trace(file_system_handle_queue_);
    PairAsyncIterable<FileSystemDirectoryHandle>::IterationSource::Trace(
        visitor);
    ExecutionContextClient::Trace(visitor);
  }

 protected:
  void GetNextIterationResult() override { TryResolvePromise(); }

 private:
  void TryResolvePromise() {
    if (!HasPendingPromise()) {
      return;
    }

    if (!file_system_handle_queue_.empty()) {
      FileSystemHandle* handle = file_system_handle_queue_.TakeFirst();
      TakePendingPromiseResolver()->Resolve(
          MakeIterationResult(handle->name(), handle));
      return;
    }

    if (error_) {
      file_system_access_error::Reject(TakePendingPromiseResolver(), *error_);
      return;
    }

    if (!is_waiting_for_more_entries_) {
      TakePendingPromiseResolver()->Resolve(MakeEndOfIteration());
      return;
    }
  }

  Member<FileSystemDirectoryHandle> directory_;
  HeapMojoReceiver<mojom::blink::FileSystemAccessDirectoryEntriesListener,
                   IterationSource>
      receiver_;
  // Queue of the successful results.
  HeapDeque<Member<FileSystemHandle>> file_system_handle_queue_;
  mojom::blink::FileSystemAccessErrorPtr error_;
  bool is_waiting_for_more_entries_ = true;
  // HeapMojoReceived won't retain us, so maintain a keepalive while
  // waiting for the browser to send all entries.
  SelfKeepAlive<IterationSource> keep_alive_;
};

using mojom::blink::FileSystemAccessErrorPtr;

FileSystemDirectoryHandle::FileSystemDirectoryHandle(
    ExecutionContext* context,
    const String& name,
    mojo::PendingRemote<mojom::blink::FileSystemAccessDirectoryHandle> mojo_ptr)
    : FileSystemHandle(context, name), mojo_ptr_(context) {
  mojo_ptr_.Bind(std::move(mojo_ptr),
                 context->GetTaskRunner(TaskType::kStorage));
  DCHECK(mojo_ptr_.is_bound());
}

ScriptPromise<FileSystemFileHandle> FileSystemDirectoryHandle::getFileHandle(
    ScriptState* script_state,
    const String& name,
    const FileSystemGetFileOptions* options,
    ExceptionState& exception_state) {
  if (!mojo_ptr_.is_bound()) {
    // TODO(crbug.com/1293949): Add an error message.
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError, "");
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<FileSystemFileHandle>>(
          script_state, exception_state.GetContext());
  auto result = resolver->Promise();

  mojo_ptr_->GetFile(
      name, options->create(),
      WTF::BindOnce(
          [](FileSystemDirectoryHandle*,
             ScriptPromiseResolver<FileSystemFileHandle>* resolver,
             const String& name, FileSystemAccessErrorPtr result,
             mojo::PendingRemote<mojom::blink::FileSystemAccessFileHandle>
                 handle) {
            // Keep `this` alive so the handle will not be garbage-collected
            // before the promise is resolved.
            ExecutionContext* context = resolver->GetExecutionContext();
            if (!context) {
              return;
            }
            if (result->status != mojom::blink::FileSystemAccessStatus::kOk) {
              file_system_access_error::Reject(resolver, *result);
              return;
            }
            resolver->Resolve(MakeGarbageCollected<FileSystemFileHandle>(
                context, name, std::move(handle)));
          },
          WrapPersistent(this), WrapPersistent(resolver), name));

  return result;
}

ScriptPromise<FileSystemDirectoryHandle>
FileSystemDirectoryHandle::getDirectoryHandle(
    ScriptState* script_state,
    const String& name,
    const FileSystemGetDirectoryOptions* options,
    ExceptionState& exception_state) {
  if (!mojo_ptr_.is_bound()) {
    // TODO(crbug.com/1293949): Add an error message.
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError, "");
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<FileSystemDirectoryHandle>>(
          script_state, exception_state.GetContext());
  auto result = resolver->Promise();

  mojo_ptr_->GetDirectory(
      name, options->create(),
      WTF::BindOnce(
          [](FileSystemDirectoryHandle*,
             ScriptPromiseResolver<FileSystemDirectoryHandle>* resolver,
             const String& name, FileSystemAccessErrorPtr result,
             mojo::PendingRemote<mojom::blink::FileSystemAccessDirectoryHandle>
                 handle) {
            // Keep `this` alive so the handle will not be garbage-collected
            // before the promise is resolved.
            ExecutionContext* context = resolver->GetExecutionContext();
            if (!context) {
              return;
            }
            if (result->status != mojom::blink::FileSystemAccessStatus::kOk) {
              file_system_access_error::Reject(resolver, *result);
              return;
            }
            resolver->Resolve(MakeGarbageCollected<FileSystemDirectoryHandle>(
                context, name, std::move(handle)));
          },
          WrapPersistent(this), WrapPersistent(resolver), name));

  return result;
}

ScriptPromise<IDLUndefined> FileSystemDirectoryHandle::removeEntry(
    ScriptState* script_state,
    const String& name,
    const FileSystemRemoveOptions* options,
    ExceptionState& exception_state) {
  if (!mojo_ptr_.is_bound()) {
    // TODO(crbug.com/1293949): Add an error message.
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError, "");
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto result = resolver->Promise();

  mojo_ptr_->RemoveEntry(name, options->recursive(),
                         WTF::BindOnce(
                             [](FileSystemDirectoryHandle*,
                                ScriptPromiseResolver<IDLUndefined>* resolver,
                                FileSystemAccessErrorPtr result) {
                               // Keep `this` alive so the handle will not be
                               // garbage-collected before the promise is
                               // resolved.
                               file_system_access_error::ResolveOrReject(
                                   resolver, *result);
                             },
                             WrapPersistent(this), WrapPersistent(resolver)));

  return result;
}

ScriptPromise<IDLNullable<IDLSequence<IDLUSVString>>>
FileSystemDirectoryHandle::resolve(ScriptState* script_state,
                                   FileSystemHandle* possible_child,
                                   ExceptionState& exception_state) {
  if (!mojo_ptr_.is_bound()) {
    // TODO(crbug.com/1293949): Add an error message.
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError, "");
    return ScriptPromise<IDLNullable<IDLSequence<IDLUSVString>>>();
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLNullable<IDLSequence<IDLUSVString>>>>(
      script_state, exception_state.GetContext());
  auto result = resolver->Promise();

  mojo_ptr_->Resolve(
      possible_child->Transfer(),
      WTF::BindOnce(
          [](FileSystemDirectoryHandle*,
             ScriptPromiseResolver<IDLNullable<IDLSequence<IDLUSVString>>>*
                 resolver,
             FileSystemAccessErrorPtr result,
             const std::optional<Vector<String>>& path) {
            // Keep `this` alive so the handle will not be garbage-collected
            // before the promise is resolved.
            if (result->status != mojom::blink::FileSystemAccessStatus::kOk) {
              file_system_access_error::Reject(resolver, *result);
              return;
            }
            if (!path.has_value()) {
              resolver->Resolve(std::nullopt);
              return;
            }
            resolver->Resolve(*path);
          },
          WrapPersistent(this), WrapPersistent(resolver)));

  return result;
}

mojo::PendingRemote<mojom::blink::FileSystemAccessTransferToken>
FileSystemDirectoryHandle::Transfer() {
  mojo::PendingRemote<mojom::blink::FileSystemAccessTransferToken> result;
  if (mojo_ptr_.is_bound()) {
    mojo_ptr_->Transfer(result.InitWithNewPipeAndPassReceiver());
  }
  return result;
}

void FileSystemDirectoryHandle::Trace(Visitor* visitor) const {
  visitor->Trace(mojo_ptr_);
  FileSystemHandle::Trace(visitor);
}

void FileSystemDirectoryHandle::QueryPermissionImpl(
    bool writable,
    base::OnceCallback<void(mojom::blink::PermissionStatus)> callback) {
  if (!mojo_ptr_.is_bound()) {
    std::move(callback).Run(mojom::blink::PermissionStatus::DENIED);
    return;
  }
  mojo_ptr_->GetPermissionStatus(writable, std::move(callback));
}

void FileSystemDirectoryHandle::RequestPermissionImpl(
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

void FileSystemDirectoryHandle::MoveImpl(
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

void FileSystemDirectoryHandle::RemoveImpl(
    const FileSystemRemoveOptions* options,
    base::OnceCallback<void(mojom::blink::FileSystemAccessErrorPtr)> callback) {
  if (!mojo_ptr_.is_bound()) {
    std::move(callback).Run(mojom::blink::FileSystemAccessError::New(
        mojom::blink::FileSystemAccessStatus::kInvalidState,
        base::File::Error::FILE_ERROR_FAILED, "Context Destroyed"));
    return;
  }

  mojo_ptr_->Remove(options->recursive(), std::move(callback));
}

void FileSystemDirectoryHandle::IsSameEntryImpl(
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

  mojo_ptr_->Resolve(
      std::move(other),
      WTF::BindOnce(
          [](base::OnceCallback<void(mojom::blink::FileSystemAccessErrorPtr,
                                     bool)> callback,
             FileSystemAccessErrorPtr result,
             const std::optional<Vector<String>>& path) {
            std::move(callback).Run(std::move(result),
                                    path.has_value() && path->empty());
          },
          std::move(callback)));
}

void FileSystemDirectoryHandle::GetUniqueIdImpl(
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

void FileSystemDirectoryHandle::GetCloudIdentifiersImpl(
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

PairAsyncIterable<FileSystemDirectoryHandle>::IterationSource*
FileSystemDirectoryHandle::CreateIterationSource(
    ScriptState* script_state,
    PairAsyncIterable<FileSystemDirectoryHandle>::IterationSource::Kind kind,
    ExceptionState& exception_state) {
  ExecutionContext* execution_context = GetExecutionContext();
  if (!execution_context) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The window is detached.");
    return nullptr;
  }

  return MakeGarbageCollected<IterationSource>(script_state, execution_context,
                                               kind, this);
}

}  // namespace blink

"""

```