Response:
Let's break down the thought process to analyze the provided C++ code for `FileSystemHandle.cc`.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the C++ file, focusing on its functionalities, relationships with web technologies (JavaScript, HTML, CSS), logical reasoning with examples, potential user errors, and how a user's action might lead to this code being executed.

**2. Initial Code Scan and High-Level Understanding:**

First, I quickly scanned the code to get a general idea of what it does. Keywords like `FileSystemHandle`, `queryPermission`, `requestPermission`, `move`, `remove`, `isSameEntry`, `getUniqueId`, `getCloudIdentifiers`, and the inclusion of `mojom::blink` suggest this file deals with the browser's interaction with the file system, likely exposed through a Web API. The use of `ScriptPromise` indicates asynchronous operations, which is common in web APIs.

**3. Identifying Core Functionalities:**

I then started to identify the key methods within the `FileSystemHandle` class. Each method seems to correspond to a specific action a user or script can take with a file or directory handle:

* **`CreateFromMojoEntry`:**  This looks like a factory method to create either a `FileSystemFileHandle` or `FileSystemDirectoryHandle` based on data received from the browser's process (using Mojo).
* **`queryPermission`:** Checks the current permission status for the handle.
* **`requestPermission`:** Asks the user for permission to access the file system.
* **`move` (multiple overloads):** Renames or moves the file/directory.
* **`remove`:** Deletes the file/directory.
* **`isSameEntry`:** Checks if two handles refer to the same file/directory.
* **`getUniqueId`:** Retrieves a unique identifier for the entry.
* **`getCloudIdentifiers`:** Gets identifiers related to cloud storage.

**4. Connecting to Web Technologies:**

The presence of `ScriptState`, `ScriptPromise`, and the overall structure strongly suggests a connection to JavaScript. I knew that the File System Access API is the relevant web API here. I then started to make direct connections between the C++ methods and their JavaScript counterparts:

* `queryPermission` maps directly to the `FileSystemHandle.queryPermission()` JavaScript method.
* `requestPermission` maps to `FileSystemHandle.requestPermission()`.
* The various `move` overloads map to `FileSystemHandle.move()`.
* `remove` maps to `FileSystemHandle.remove()`.
* `isSameEntry` maps to `FileSystemHandle.isSameEntry()`.
* `getUniqueId` maps to `FileSystemHandle.getUniqueId()`.
* `getCloudIdentifiers` maps to `FileSystemHandle.getCloudIdentifiers()`.

I considered how these JavaScript APIs are used. They are typically triggered by user interactions or script logic, often involving asynchronous operations (hence the promises).

**5. Logical Reasoning and Examples:**

For each identified functionality, I tried to think about how it works and what the inputs and outputs would be. This involved considering:

* **Inputs:**  What data does the C++ method receive? (e.g., permission descriptors, destination directories, new names).
* **Processing:** What is the C++ code actually doing? (e.g., checking permissions, calling Mojo interfaces, updating internal state).
* **Outputs:** What does the method return (usually a `ScriptPromise` resolving with a specific value or rejecting with an error)?

I then created concrete examples to illustrate the flow, including JavaScript snippets showing how a developer would use the corresponding API. For the `move` example, I showed different scenarios: renaming within the same directory and moving to a different directory.

**6. Identifying User and Programming Errors:**

I considered common mistakes developers might make when using the File System Access API:

* **Permissions:** Forgetting to request permissions or handling permission denials.
* **Invalid Paths/Names:** Trying to move or create files with invalid characters or names.
* **Operating on Removed Entries:** Attempting to use a handle after the corresponding file/directory has been deleted.
* **Type Mismatches:**  Trying to move a file to a location expecting a directory.

**7. Tracing User Actions:**

This part required imagining the user's journey that would lead to this code being executed. The key is understanding how the File System Access API is initiated:

* **User Interaction:**  The user needs to initiate a file system operation, like selecting a file or directory using `<input type="file">` with the `webkitdirectory` attribute, or by using the `showOpenFilePicker` or `showSaveFilePicker` methods.
* **JavaScript API Calls:** The JavaScript code uses the File System Access API methods (e.g., `showDirectoryPicker()`, `getFileHandle()`, `getDirectoryHandle()`).
* **Browser Internals:** The browser then translates these JavaScript calls into internal operations, which eventually involve the C++ code in `FileSystemHandle.cc`.

I outlined a step-by-step example of a user selecting a directory, showing how the JavaScript calls would lead to the creation of `FileSystemHandle` objects and potential calls to methods like `queryPermission` or `requestPermission`.

**8. Iterative Refinement:**

Throughout this process, I reread the code snippets, double-checked my understanding of the File System Access API, and refined my explanations to be clear and accurate. I also ensured that the examples were consistent with the code's functionality. For instance, I noticed the use of `WrapPersistent` for the `this` pointer in the promise callbacks, indicating the need to keep the `FileSystemHandle` alive until the promise resolves. This detail reinforces the asynchronous nature of the operations.

**Self-Correction/Refinement Example During the Process:**

Initially, I might have just said "this file handles file system operations." But that's too vague. As I examined the methods, I realized the code isn't *directly* performing the low-level file I/O. Instead, it's orchestrating the *permissions*, *metadata*, and *names* of file system entries. The actual file reading/writing happens in other parts of the Chromium codebase, likely triggered by methods within `FileSystemFileHandle`. This realization led to a more accurate description of the file's role.

By following this systematic approach, breaking down the code into smaller pieces, and focusing on the connections between the C++ implementation and the web APIs, I could build a comprehensive and accurate analysis of `FileSystemHandle.cc`.
好的，这是对`blink/renderer/modules/file_system_access/file_system_handle.cc` 文件功能的详细分析：

**文件功能总览**

`FileSystemHandle.cc` 文件定义了 `FileSystemHandle` 类，它是 Chromium Blink 引擎中 **File System Access API** 的核心抽象基类。  它代表了用户在文件系统中选择的一个文件或目录的句柄。这个基类定义了所有文件系统条目（文件和目录）共享的通用操作和属性。

**核心功能分解**

1. **表示文件系统条目:**
   - `FileSystemHandle` 对象封装了对底层文件系统条目的引用。它不直接拥有文件内容或目录结构，而是持有一个可以与浏览器进程（Browser Process）通信的 Mojo 接口，以执行文件系统操作。
   - 构造函数 `FileSystemHandle(ExecutionContext* execution_context, const String& name)` 用于创建 `FileSystemHandle` 实例，存储条目的名称。
   - 静态方法 `CreateFromMojoEntry` 是一个工厂方法，根据从浏览器进程接收到的 `mojom::blink::FileSystemAccessEntryPtr` 信息，创建具体的 `FileSystemFileHandle` 或 `FileSystemDirectoryHandle` 子类实例。

2. **权限管理:**
   - `queryPermission`:  查询当前对该文件或目录的访问权限状态。它接收一个 `FileSystemHandlePermissionDescriptor` 对象，指定需要查询的权限模式（读或读写），并返回一个 Promise，最终解析为 `PermissionState` 枚举值（granted, denied, prompt）。
   - `requestPermission`:  请求用户授予对该文件或目录的访问权限。它同样接收一个 `FileSystemHandlePermissionDescriptor` 对象，指定请求的权限模式。如果用户授予权限，Promise 将解析为 `PermissionState::granted`；如果用户拒绝，Promise 可能解析为 `PermissionState::denied` 或抛出错误。

3. **文件/目录操作:**
   - `move` (多个重载):  用于移动或重命名文件或目录。
     - 可以将当前句柄移动到新的名称下（在同一目录下）。
     - 可以将当前句柄移动到另一个 `FileSystemDirectoryHandle` 代表的目录下，并可选择指定新的名称。
   - `remove`:  删除当前句柄代表的文件或目录。它可以接收一个 `FileSystemRemoveOptions` 对象，用于指定删除选项（例如，是否递归删除目录）。
   - `isSameEntry`:  判断当前句柄是否与另一个 `FileSystemHandle` 指向同一个文件系统条目。

4. **元数据访问:**
   - `name()`:  返回文件或目录的名称。
   - `getUniqueId`:  获取文件或目录的唯一标识符。这是一个在浏览器生命周期内保持不变的字符串，可以用于跨会话跟踪同一个文件或目录。
   - `getCloudIdentifiers`:  获取与该文件或目录关联的云存储标识符。这允许 Web 应用识别用户在不同云服务（如 Google Drive, Dropbox）中同步的文件。

**与 Javascript, HTML, CSS 的关系及举例**

`FileSystemHandle` 是 JavaScript 中 `FileSystemFileHandle` 和 `FileSystemDirectoryHandle` 对象的底层实现，这些对象通过 File System Access API 暴露给 Web 开发者。

**JavaScript 示例:**

```javascript
// 获取一个文件句柄
async function openFile() {
  const [fileHandle] = await window.showOpenFilePicker();

  // 查询读取权限
  const permissionStatus = await fileHandle.queryPermission({ mode: 'read' });
  console.log("Read permission:", permissionStatus);

  // 请求读写权限
  if (permissionStatus !== 'granted') {
    const requestStatus = await fileHandle.requestPermission({ mode: 'readwrite' });
    console.log("Request readwrite permission:", requestStatus);
  }

  // 移动文件到新名称
  try {
    await fileHandle.move("newFileName.txt");
    console.log("File moved successfully.");
  } catch (error) {
    console.error("Error moving file:", error);
  }

  // 获取唯一 ID
  const uniqueId = await fileHandle.getUniqueId();
  console.log("Unique ID:", uniqueId);
}

// 获取一个目录句柄
async function openDirectory() {
  const directoryHandle = await window.showDirectoryPicker();

  // 获取子文件句柄
  const fileHandle = await directoryHandle.getFileHandle("myFile.txt");

  // 将文件句柄移动到另一个目录句柄下
  const newDirectoryHandle = await window.showDirectoryPicker();
  await fileHandle.move(newDirectoryHandle);
  console.log("File moved to new directory.");
}
```

**HTML:**

HTML 中通常通过用户交互（例如点击按钮触发 `showOpenFilePicker` 或 `showDirectoryPicker`）来启动文件系统访问。

```html
<button onclick="openFile()">打开文件</button>
<button onclick="openDirectory()">打开目录</button>
<script src="script.js"></script>
```

**CSS:**

CSS 与此文件的功能没有直接关系，因为它主要处理文件系统的逻辑和权限。

**逻辑推理、假设输入与输出**

**假设输入:**

* **场景 1 (queryPermission):**
    * `descriptor->mode()` 为 `V8FileSystemPermissionMode::Enum::kRead`
    * 用户之前已经授予了对该文件的读取权限。
* **场景 2 (requestPermission):**
    * `descriptor->mode()` 为 `V8FileSystemPermissionMode::Enum::kReadwrite`
    * 用户之前没有授予对该文件的任何权限。
* **场景 3 (move - 重命名):**
    * `new_entry_name` 为 "renamed_file.txt"
    * 该操作在同一目录下进行，且目标名称不存在。
* **场景 4 (remove):**
    * `options` 为 `nullptr` (使用默认选项，非递归删除)。
    * 当前句柄指向一个空目录。

**预期输出:**

* **场景 1 (queryPermission):** Promise 解析为 `V8PermissionState::kGranted`。
* **场景 2 (requestPermission):** 弹出权限请求对话框，如果用户点击 "允许"，Promise 解析为 `V8PermissionState::kGranted`；如果用户点击 "拒绝"，Promise 解析为 `V8PermissionState::kDenied` 或抛出一个包含 `FileSystemAccessError` 的 rejection。
* **场景 3 (move - 重命名):** Promise 解析为 `IDLUndefined`，并且该 `FileSystemHandle` 对象的 `name_` 成员变量更新为 "renamed_file.txt"。
* **场景 4 (remove):** Promise 解析为 `IDLUndefined`，底层文件系统条目被成功删除。

**用户或编程常见的使用错误**

1. **未请求权限就尝试操作:**  开发者可能会忘记在执行文件读写等操作前调用 `requestPermission` 或 `queryPermission`。这会导致操作失败并抛出错误。
   ```javascript
   // 错误示例：直接尝试读取，未先请求权限
   async function readFileContent(fileHandle) {
     // ... 尝试通过 fileHandle 读取文件内容 ... // 可能会失败
   }
   ```
   **正确做法:**
   ```javascript
   async function readFileContent(fileHandle) {
     const permission = await fileHandle.requestPermission({ mode: 'read' });
     if (permission === 'granted') {
       // ... 读取文件内容 ...
     } else {
       console.error("Permission denied.");
     }
   }
   ```

2. **移动或删除不存在的条目:**  如果尝试移动或删除一个已经被删除或者根本不存在的文件或目录，操作会失败。
   ```javascript
   async function moveFile(fileHandle) {
     try {
       await fileHandle.move("nonExistentDirectory/newFile.txt");
     } catch (error) {
       console.error("Error moving file:", error); // 可能会提示找不到目录
     }
   }
   ```

3. **删除非空目录时未指定递归删除:**  如果尝试删除一个非空目录，并且 `remove` 方法的 `options` 参数未指定 `recursive: true`，则操作会失败。
   ```javascript
   async function removeDirectory(directoryHandle) {
     try {
       await directoryHandle.remove(); // 如果目录非空，会失败
     } catch (error) {
       console.error("Error removing directory:", error);
     }
   }

   async function removeDirectoryRecursively(directoryHandle) {
     try {
       await directoryHandle.remove({ recursive: true });
     } catch (error) {
       console.error("Error removing directory:", error);
     }
   }
   ```

**用户操作如何一步步到达这里 (作为调试线索)**

1. **用户在网页上触发了文件系统访问操作:** 例如，用户点击了一个按钮，该按钮的事件监听器调用了 File System Access API 的方法。
2. **JavaScript 代码调用了 `window.showOpenFilePicker()` 或 `window.showDirectoryPicker()`:** 这些方法会弹出文件选择器或目录选择器，让用户选择文件或目录。
3. **用户在文件选择器/目录选择器中选择了文件或目录，并点击了 "打开" 或 "选择" 按钮。**
4. **浏览器进程 (Browser Process) 处理用户选择:**  浏览器进程与操作系统交互，获取用户选择的文件或目录的信息。
5. **浏览器进程创建 Mojo 接口:**  浏览器进程创建一个用于与渲染进程通信的 Mojo 接口，该接口允许渲染进程对选定的文件或目录执行操作。
6. **浏览器进程将 `FileSystemAccessEntryPtr` 通过 Mojo 发送到渲染进程。**
7. **渲染进程中的 JavaScript 代码接收到 `FileSystemFileHandle` 或 `FileSystemDirectoryHandle` 对象。**
8. **JavaScript 代码调用了 `fileHandle.queryPermission()`，`fileHandle.requestPermission()`，`fileHandle.move()`，`fileHandle.remove()` 等方法。**
9. **这些 JavaScript 方法的调用会触发 Blink 引擎中对应的 C++ 代码执行，最终到达 `FileSystemHandle.cc` 中的相应方法。** 例如，调用 `fileHandle.requestPermission()` 会导致 `FileSystemHandle::requestPermission` 方法被调用。
10. **`FileSystemHandle` 的方法会通过持有的 Mojo 接口与浏览器进程通信，执行实际的文件系统操作。**

**调试线索:**

* **断点:** 在 `FileSystemHandle.cc` 的关键方法（如 `queryPermission`, `requestPermission`, `move`, `remove`）设置断点，可以跟踪代码执行流程，查看参数和返回值。
* **日志输出:** 在 C++ 代码中添加 `DLOG` 或 `DVLOG` 输出，可以记录关键信息，例如权限状态、操作结果、错误信息等。
* **Mojo Inspector:** 使用 Chromium 的 Mojo Inspector 工具可以查看渲染进程和浏览器进程之间的 Mojo 消息传递，帮助理解 API 调用是如何在进程间流转的。
* **Web Inspector (开发者工具):**  在浏览器的开发者工具中，可以查看 JavaScript 代码的执行情况，包括 Promise 的状态和错误信息，从而推断出可能触发 C++ 代码的问题。

总而言之，`FileSystemHandle.cc` 是 File System Access API 在 Blink 渲染引擎中的核心组成部分，负责管理文件和目录句柄的通用操作，并与浏览器进程协作完成实际的文件系统操作和权限管理。 它架起了 JavaScript API 和底层操作系统文件系统之间的桥梁。

Prompt: 
```
这是目录为blink/renderer/modules/file_system_access/file_system_handle.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/file_system_access/file_system_handle.h"

#include "mojo/public/cpp/bindings/pending_remote.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_cloud_identifier.mojom-blink.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_error.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_permission_state.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_file_system_cloud_identifier.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_file_system_handle_permission_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_file_system_permission_mode.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_access_error.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_directory_handle.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_file_handle.h"
#include "third_party/blink/renderer/modules/permissions/permission_utils.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {
using mojom::blink::FileSystemAccessEntryPtr;
using mojom::blink::FileSystemAccessErrorPtr;

FileSystemHandle::FileSystemHandle(ExecutionContext* execution_context,
                                   const String& name)
    : ExecutionContextClient(execution_context), name_(name) {}

// static
FileSystemHandle* FileSystemHandle::CreateFromMojoEntry(
    mojom::blink::FileSystemAccessEntryPtr e,
    ExecutionContext* execution_context) {
  if (e->entry_handle->is_file()) {
    return MakeGarbageCollected<FileSystemFileHandle>(
        execution_context, e->name, std::move(e->entry_handle->get_file()));
  }
  return MakeGarbageCollected<FileSystemDirectoryHandle>(
      execution_context, e->name, std::move(e->entry_handle->get_directory()));
}

ScriptPromise<V8PermissionState> FileSystemHandle::queryPermission(
    ScriptState* script_state,
    const FileSystemHandlePermissionDescriptor* descriptor) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<V8PermissionState>>(
          script_state);
  auto result = resolver->Promise();

  QueryPermissionImpl(
      descriptor->mode() == V8FileSystemPermissionMode::Enum::kReadwrite,
      WTF::BindOnce(
          [](FileSystemHandle* handle,
             ScriptPromiseResolver<V8PermissionState>* resolver,
             mojom::blink::PermissionStatus result) {
            // Keep `this` alive so the handle will not be garbage-collected
            // before the promise is resolved.
            resolver->Resolve(ToV8PermissionState(result));
          },
          WrapPersistent(this), WrapPersistent(resolver)));

  return result;
}

ScriptPromise<V8PermissionState> FileSystemHandle::requestPermission(
    ScriptState* script_state,
    const FileSystemHandlePermissionDescriptor* descriptor,
    ExceptionState& exception_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<V8PermissionState>>(
          script_state, exception_state.GetContext());
  auto result = resolver->Promise();

  RequestPermissionImpl(
      descriptor->mode() == V8FileSystemPermissionMode::Enum::kReadwrite,
      WTF::BindOnce(
          [](FileSystemHandle*,
             ScriptPromiseResolver<V8PermissionState>* resolver,
             FileSystemAccessErrorPtr result,
             mojom::blink::PermissionStatus status) {
            // Keep `this` alive so the handle will not be garbage-collected
            // before the promise is resolved.
            if (result->status != mojom::blink::FileSystemAccessStatus::kOk) {
              file_system_access_error::Reject(resolver, *result);
              return;
            }
            resolver->Resolve(ToV8PermissionState(status));
          },
          WrapPersistent(this), WrapPersistent(resolver)));

  return result;
}

ScriptPromise<IDLUndefined> FileSystemHandle::move(
    ScriptState* script_state,
    const String& new_entry_name,
    ExceptionState& exception_state) {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto result = resolver->Promise();

  MoveImpl(
      mojo::NullRemote(), new_entry_name,
      WTF::BindOnce(
          [](FileSystemHandle* handle, const String& new_name,
             ScriptPromiseResolver<IDLUndefined>* resolver,
             FileSystemAccessErrorPtr result) {
            if (result->status == mojom::blink::FileSystemAccessStatus::kOk) {
              handle->name_ = new_name;
            }
            file_system_access_error::ResolveOrReject(resolver, *result);
          },
          WrapPersistent(this), new_entry_name, WrapPersistent(resolver)));

  return result;
}

ScriptPromise<IDLUndefined> FileSystemHandle::move(
    ScriptState* script_state,
    FileSystemDirectoryHandle* destination_directory,
    ExceptionState& exception_state) {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto result = resolver->Promise();

  MoveImpl(
      destination_directory->Transfer(), name_,
      WTF::BindOnce(
          [](FileSystemHandle*, ScriptPromiseResolver<IDLUndefined>* resolver,
             FileSystemAccessErrorPtr result) {
            // Keep `this` alive so the handle will not be
            // garbage-collected before the promise is resolved.
            file_system_access_error::ResolveOrReject(resolver, *result);
          },
          WrapPersistent(this), WrapPersistent(resolver)));

  return result;
}

ScriptPromise<IDLUndefined> FileSystemHandle::move(
    ScriptState* script_state,
    FileSystemDirectoryHandle* destination_directory,
    const String& new_entry_name,
    ExceptionState& exception_state) {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto result = resolver->Promise();

  MoveImpl(
      destination_directory->Transfer(), new_entry_name,
      WTF::BindOnce(
          [](FileSystemHandle* handle, const String& new_name,
             ScriptPromiseResolver<IDLUndefined>* resolver,
             FileSystemAccessErrorPtr result) {
            if (result->status == mojom::blink::FileSystemAccessStatus::kOk) {
              handle->name_ = new_name;
            }
            file_system_access_error::ResolveOrReject(resolver, *result);
          },
          WrapPersistent(this), new_entry_name, WrapPersistent(resolver)));

  return result;
}

ScriptPromise<IDLUndefined> FileSystemHandle::remove(
    ScriptState* script_state,
    const FileSystemRemoveOptions* options,
    ExceptionState& exception_state) {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto result = resolver->Promise();

  RemoveImpl(options, WTF::BindOnce(
                          [](FileSystemHandle*,
                             ScriptPromiseResolver<IDLUndefined>* resolver,
                             FileSystemAccessErrorPtr result) {
                            // Keep `this` alive so the handle will not be
                            // garbage-collected before the promise is resolved.
                            file_system_access_error::ResolveOrReject(resolver,
                                                                      *result);
                          },
                          WrapPersistent(this), WrapPersistent(resolver)));

  return result;
}

ScriptPromise<IDLBoolean> FileSystemHandle::isSameEntry(
    ScriptState* script_state,
    FileSystemHandle* other,
    ExceptionState& exception_state) {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(
      script_state, exception_state.GetContext());
  auto result = resolver->Promise();

  IsSameEntryImpl(
      other->Transfer(),
      WTF::BindOnce(
          [](FileSystemHandle*, ScriptPromiseResolver<IDLBoolean>* resolver,
             FileSystemAccessErrorPtr result, bool same) {
            // Keep `this` alive so the handle will not be garbage-collected
            // before the promise is resolved.
            if (result->status != mojom::blink::FileSystemAccessStatus::kOk) {
              file_system_access_error::Reject(resolver, *result);
              return;
            }
            resolver->Resolve(same);
          },
          WrapPersistent(this), WrapPersistent(resolver)));
  return result;
}

ScriptPromise<IDLUSVString> FileSystemHandle::getUniqueId(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUSVString>>(
      script_state, exception_state.GetContext());
  auto result = resolver->Promise();

  GetUniqueIdImpl(WTF::BindOnce(
      [](FileSystemHandle*, ScriptPromiseResolver<IDLUSVString>* resolver,
         FileSystemAccessErrorPtr result, const WTF::String& id) {
        // Keep `this` alive so the handle will not be garbage-collected
        // before the promise is resolved.
        if (result->status != mojom::blink::FileSystemAccessStatus::kOk) {
          file_system_access_error::Reject(resolver, *result);
          return;
        }

        resolver->Resolve(std::move(id));
      },
      WrapPersistent(this), WrapPersistent(resolver)));
  return result;
}

ScriptPromise<IDLSequence<FileSystemCloudIdentifier>>
FileSystemHandle::getCloudIdentifiers(ScriptState* script_state,
                                      ExceptionState& exception_state) {
  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLSequence<FileSystemCloudIdentifier>>>(
      script_state, exception_state.GetContext());
  auto result = resolver->Promise();

  GetCloudIdentifiersImpl(WTF::BindOnce(
      [](FileSystemHandle*,
         ScriptPromiseResolver<IDLSequence<FileSystemCloudIdentifier>>*
             resolver,
         FileSystemAccessErrorPtr result,
         Vector<mojom::blink::FileSystemAccessCloudIdentifierPtr>
             cloud_identifiers) {
        // Keep `this` alive so the handle will not be garbage-collected
        // before the promise is resolved.
        if (result->status != mojom::blink::FileSystemAccessStatus::kOk) {
          file_system_access_error::Reject(resolver, *result);
          return;
        }

        HeapVector<Member<FileSystemCloudIdentifier>> return_values;
        return_values.ReserveInitialCapacity(cloud_identifiers.size());
        for (auto& cloud_identifier : cloud_identifiers) {
          FileSystemCloudIdentifier* return_value =
              FileSystemCloudIdentifier::Create();
          return_value->setProviderName(cloud_identifier->provider_name);
          return_value->setId(cloud_identifier->id);
          return_values.push_back(return_value);
        }
        resolver->Resolve(return_values);
      },
      WrapPersistent(this), WrapPersistent(resolver)));
  return result;
}

void FileSystemHandle::Trace(Visitor* visitor) const {
  ScriptWrappable::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
}

}  // namespace blink

"""

```