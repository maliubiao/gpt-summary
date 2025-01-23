Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request asks for the functionality of the `WorkerGlobalScopeFileSystem.cc` file in the Chromium Blink engine, its relation to web technologies (JS, HTML, CSS), examples, debugging hints, and common errors.

2. **Identify the Core Functionality:**  The filename and the `#include` directives immediately suggest this file is related to file system access within a Web Worker context. Specifically, the presence of `webkitRequestFileSystem`, `webkitRequestFileSystemSync`, `webkitResolveLocalFileSystemURL`, and `webkitResolveLocalFileSystemSyncURL` are strong indicators of the core functionalities. These function names clearly map to requesting file systems and resolving URLs within those file systems. The `Sync` suffix indicates synchronous versions of these operations.

3. **Analyze Each Function:**

   * **`webkitRequestFileSystem` (Asynchronous):**
      * **Purpose:**  Asynchronously requests access to a file system.
      * **Parameters:** Takes the `WorkerGlobalScope`, the file system `type` (temporary or persistent), the requested `size`, and success/error callbacks.
      * **Security Checks:**  Verifies if the security origin can access the file system. Local file access is also tracked via `UseCounter`.
      * **Type Validation:** Checks if the provided `type` is valid (temporary or persistent).
      * **Implementation:** Uses `LocalFileSystem::RequestFileSystem` with `kAsynchronous`. It constructs `FileSystemCallbacks` to handle the asynchronous results.
      * **Mapping to Web Technologies:** Directly relates to the JavaScript `webkitRequestFileSystem` API available in Web Workers. This API allows web workers to request storage for files.

   * **`webkitRequestFileSystemSync` (Synchronous):**
      * **Purpose:** Synchronously requests access to a file system.
      * **Parameters:**  Similar to the asynchronous version, but includes an `ExceptionState` for handling synchronous errors.
      * **Security Checks and Type Validation:**  Identical to the asynchronous version.
      * **Implementation:**  Uses `LocalFileSystem::RequestFileSystem` with `kSynchronous`. Employs `FileSystemCallbacksSyncHelper` to wait for the result and throw exceptions if necessary. The result is wrapped in a `DOMFileSystemSync` object.
      * **Mapping to Web Technologies:**  Corresponds to the (now deprecated) synchronous version of `webkitRequestFileSystem` in Web Workers. Its existence highlights the distinction between asynchronous and synchronous file access.

   * **`webkitResolveLocalFileSystemURL` (Asynchronous):**
      * **Purpose:** Asynchronously resolves a URL within the file system to an `Entry` (either a file or a directory).
      * **Parameters:** Takes the `WorkerGlobalScope`, the `url` to resolve, and success/error callbacks.
      * **Security Checks:** Checks if the security origin can access the file system and if it's allowed to request the given `url`.
      * **URL Validation:** Verifies if the provided `url` is valid.
      * **Implementation:** Uses `LocalFileSystem::ResolveURL` with `kAsynchronous` and `ResolveURICallbacks`.
      * **Mapping to Web Technologies:**  Maps to the JavaScript `webkitResolveLocalFileSystemURL` API, allowing resolution of file system entries from URLs within web workers.

   * **`webkitResolveLocalFileSystemSyncURL` (Synchronous):**
      * **Purpose:** Synchronously resolves a file system URL to an `Entry`.
      * **Parameters:** Similar to the asynchronous version, including `ExceptionState`.
      * **Security Checks and URL Validation:** Identical to the asynchronous version.
      * **Implementation:** Uses `LocalFileSystem::ResolveURL` with `kSynchronous` and `EntryCallbacksSyncHelper`. The resolved `Entry` is wrapped in an `EntrySync` object.
      * **Mapping to Web Technologies:**  Corresponds to the (deprecated) synchronous version of `webkitResolveLocalFileSystemURL`.

4. **Identify Relationships with Web Technologies:**  The function names themselves (`webkitRequestFileSystem`, `webkitResolveLocalFileSystemURL`) and the parameter types (callbacks) strongly suggest a direct mapping to JavaScript APIs. The concept of "temporary" and "persistent" storage directly aligns with how web applications request storage. The resolved URLs and entries directly represent file system resources that JavaScript can interact with. While CSS doesn't directly trigger these functions, it's possible a web worker using the file system might generate CSS content dynamically. HTML interacts because the initial JavaScript in an HTML page can spawn web workers that utilize these file system APIs.

5. **Consider Logic and Examples:**

   * **`webkitRequestFileSystem`:** Imagine a web worker processing images. It needs persistent storage to cache processed images. The JavaScript would call `webkitRequestFileSystem(TEMPORARY, 1024 * 1024, successCallback, errorCallback)` to request 1MB of temporary storage.
   * **`webkitResolveLocalFileSystemURL`:** After getting a file entry URL from a previous operation (like `createWriter`), the worker could use `webkitResolveLocalFileSystemURL(fileURL, successCallback, errorCallback)` to get the actual `FileEntry` object again.

6. **Think About User and Programming Errors:**

   * **Security Errors:**  A common user error is trying to access the file system from an insecure context (non-HTTPS). A programming error is forgetting to handle the error callback.
   * **Invalid Type:**  Providing an incorrect type value to `webkitRequestFileSystem` is a programming error.
   * **Invalid URL:** Passing a malformed URL to `webkitResolveLocalFileSystemURL` is a common programming error.
   * **Synchronous Operations in the Main Thread:**  Trying to use the synchronous versions in the main browser thread would block the UI, leading to a bad user experience (though this code is specifically for Web Workers, where synchronous operations are allowed).

7. **Trace User Operations (Debugging Clues):**  Think about the sequence of actions that would lead to this code being executed. A user action (e.g., clicking a button) triggers JavaScript code. This JavaScript spawns a web worker. The web worker then calls `webkitRequestFileSystem` or `webkitResolveLocalFileSystemURL`. Setting breakpoints in the JavaScript and then stepping into the Blink C++ code is the typical debugging approach.

8. **Address Specific Instructions:** Go back to the original request and make sure every point has been addressed (functionality, JS/HTML/CSS relation, examples, assumptions/outputs, user errors, debugging).

9. **Refine and Organize:** Structure the answer clearly with headings and bullet points to make it easy to read and understand. Ensure the language is precise and avoids jargon where possible, or explains it if necessary.

This methodical approach, starting with understanding the purpose and dissecting each function, helps to cover all aspects of the request and provides a comprehensive analysis of the code.
这个C++文件 `worker_global_scope_file_system.cc` 属于 Chromium Blink 引擎，负责实现在 **Web Worker** 环境中对 **File System API** 的支持。 它的主要功能是：

**核心功能：**

1. **`webkitRequestFileSystem` (异步):** 允许 Web Worker 请求访问文件系统。这对应了 JavaScript 中 `webkitRequestFileSystem` 方法。
    * 功能：根据指定的类型（临时或持久）和请求的大小，请求访问文件系统。成功后，会调用成功回调函数，并传递一个 `FileSystem` 对象。失败则调用错误回调函数。
    * 与 JavaScript 的关系： 这是 JavaScript `webkitRequestFileSystem` API 在 Blink 引擎中的具体实现。Web Worker 可以通过这个 API 请求一块隔离的存储空间来存放文件。
    * 假设输入与输出：
        * 假设输入：在 Web Worker 中调用 `webkitRequestFileSystem(TEMPORARY, 1024 * 1024, successCallback, errorCallback)`。
        * 假设输出：
            * 如果成功，`successCallback` 会被调用，并带有一个代表临时文件系统的 `FileSystem` 对象。
            * 如果失败（例如，权限不足、无效的类型），`errorCallback` 会被调用，并带有一个 `FileError` 对象，指示错误原因。

2. **`webkitRequestFileSystemSync` (同步):** 允许 Web Worker **同步** 请求访问文件系统。这对应了 JavaScript 中 **已废弃的** 同步 `webkitRequestFileSystem` 方法。
    * 功能：与异步版本类似，但它是同步的，会阻塞 Web Worker 的执行直到文件系统请求完成。成功后返回一个 `DOMFileSystemSync` 对象，失败则抛出异常。
    * 与 JavaScript 的关系： 这是 **已废弃的** JavaScript 同步 `webkitRequestFileSystem` API 在 Blink 引擎中的实现。 由于同步操作会阻塞线程，在主线程中已被移除，但在 Web Worker 中曾经允许使用。
    * 假设输入与输出：
        * 假设输入：在 Web Worker 中调用 `webkitRequestFileSystemSync(TEMPORARY, 1024 * 1024)`。
        * 假设输出：
            * 如果成功，函数会返回一个 `DOMFileSystemSync` 对象。
            * 如果失败，会抛出一个 JavaScript 异常 (通过 `ExceptionState` 传递)。

3. **`webkitResolveLocalFileSystemURL` (异步):** 允许 Web Worker 异步解析本地文件系统 URL。这对应了 JavaScript 中 `webkitResolveLocalFileSystemURL` 方法。
    * 功能：将一个文件系统内部的 URL 解析为一个 `Entry` 对象，该对象可以是文件 (`FileEntry`) 或目录 (`DirectoryEntry`)。
    * 与 JavaScript 的关系： 这是 JavaScript `webkitResolveLocalFileSystemURL` API 在 Blink 引擎中的具体实现。Web Worker 可以使用这个 API 来获取文件或目录的元数据。
    * 假设输入与输出：
        * 假设输入：在 Web Worker 中，有一个代表文件或目录的 URL，例如 `file:///temporary/myfile.txt`，然后调用 `webkitResolveLocalFileSystemURL('file:///temporary/myfile.txt', successCallback, errorCallback)`.
        * 假设输出：
            * 如果 URL 指向一个存在的文件，`successCallback` 会被调用，并带有一个 `FileEntry` 对象。
            * 如果 URL 指向一个存在的目录，`successCallback` 会被调用，并带有一个 `DirectoryEntry` 对象。
            * 如果 URL 无效或指向不存在的资源，`errorCallback` 会被调用，并带有一个 `FileError` 对象。

4. **`webkitResolveLocalFileSystemSyncURL` (同步):** 允许 Web Worker **同步** 解析本地文件系统 URL。这对应了 JavaScript 中 **已废弃的** 同步 `webkitResolveLocalFileSystemURL` 方法。
    * 功能：与异步版本类似，但它是同步的，会阻塞 Web Worker 的执行。成功后返回一个 `EntrySync` 对象，失败则抛出异常。
    * 与 JavaScript 的关系： 这是 **已废弃的** JavaScript 同步 `webkitResolveLocalFileSystemURL` API 在 Blink 引擎中的实现。
    * 假设输入与输出：
        * 假设输入：在 Web Worker 中，有一个代表文件或目录的 URL，例如 `file:///temporary/mydir`，然后调用 `webkitResolveLocalFileSystemSyncURL('file:///temporary/mydir')`.
        * 假设输出：
            * 如果 URL 指向一个存在的目录，函数会返回一个 `DirectoryEntrySync` 对象。
            * 如果 URL 指向一个存在的文件，函数会返回一个 `FileEntrySync` 对象。
            * 如果 URL 无效或指向不存在的资源，会抛出一个 JavaScript 异常 (通过 `ExceptionState` 传递)。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **JavaScript:**  这个文件直接实现了 JavaScript 的 File System API 在 Web Worker 环境下的功能。Web Worker 中的 JavaScript 代码可以直接调用 `webkitRequestFileSystem` 和 `webkitResolveLocalFileSystemURL` (以及已废弃的同步版本) 来操作文件系统。
    ```javascript
    // 在 Web Worker 中
    webkitRequestFileSystem(TEMPORARY, 1024, function(fs) {
      console.log('文件系统已获取:', fs);
      fs.root.getFile('myFile.txt', {create: true}, function(fileEntry) {
        console.log('文件已创建:', fileEntry.toURL());
        webkitResolveLocalFileSystemURL(fileEntry.toURL(), function(resolvedEntry) {
          console.log('URL 已解析:', resolvedEntry);
        }, function(error) {
          console.error('解析 URL 失败:', error);
        });
      }, function(error) {
        console.error('创建文件失败:', error);
      });
    }, function(error) {
      console.error('请求文件系统失败:', error);
    });
    ```

* **HTML:** HTML 页面可以通过创建和运行 Web Worker 来间接使用这些功能。HTML 中的脚本可以创建 Web Worker，然后在 Web Worker 内部调用文件系统相关的 API。
    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>Web Worker 文件系统示例</title>
    </head>
    <body>
      <script>
        const worker = new Worker('worker.js');
        // ... 与 Web Worker 通信 ...
      </script>
    </body>
    </html>
    ```
    `worker.js` 内容可能包含上面 JavaScript 示例中的文件系统操作代码。

* **CSS:**  CSS 本身不直接与此文件交互。然而，Web Worker 中使用文件系统存储的数据（例如，动态生成的 CSS 文件），可能会被主线程的 CSS 引擎加载和应用。

**逻辑推理的假设输入与输出：**

* **假设输入 (针对 `webkitRequestFileSystem`)：**
    * Web Worker 的安全上下文允许访问文件系统。
    * 请求类型为 `TEMPORARY`。
    * 请求大小为 1MB (1024 * 1024 字节)。
* **假设输出 (针对 `webkitRequestFileSystem`)：**
    * 成功：会创建一个临时的文件系统隔离空间，并通过回调函数将 `FileSystem` 对象传递给 Web Worker。
    * 失败：如果因为配额限制、安全策略或其他原因无法创建，会调用错误回调函数，并传递一个 `FileError` 对象，其 `code` 属性会指示具体的错误类型（例如 `QUOTA_EXCEEDED_ERR`, `SECURITY_ERR`）。

* **假设输入 (针对 `webkitResolveLocalFileSystemURL`)：**
    * Web Worker 的安全上下文允许访问文件系统。
    * 提供的 URL 是一个有效的文件系统内部 URL，指向一个已存在的文件。
* **假设输出 (针对 `webkitResolveLocalFileSystemURL`)：**
    * 成功：会创建一个 `FileEntry` 对象，并通过回调函数传递给 Web Worker，该对象包含了文件的元数据（例如，文件名、文件路径）。
    * 失败：如果 URL 无效或文件不存在，会调用错误回调函数，并传递一个 `FileError` 对象，其 `code` 属性会指示具体的错误类型（例如 `NOT_FOUND_ERR`, `ENCODING_ERR`）。

**涉及用户或编程常见的使用错误举例说明：**

1. **安全错误 (SecurityError):** 用户尝试在不安全的上下文（例如，非 HTTPS 页面）中使用 File System API。浏览器会阻止访问，并抛出安全错误。
    * **用户操作：** 在 HTTP 页面上运行包含文件系统访问的 JavaScript 代码。
    * **调试线索：** 浏览器控制台会显示类似 "SecurityError: The operation is insecure." 的错误信息。 代码会进入 `webkitRequestFileSystem` 或 `webkitResolveLocalFileSystemURL` 函数，并在安全检查时返回错误。

2. **无效的操作类型 (InvalidModificationError):**  在使用同步版本的 API 时，提供了无效的文件系统类型（既不是 `TEMPORARY` 也不是 `PERSISTENT`）。
    * **编程错误：**  调用 `webkitRequestFileSystemSync` 时使用了错误的类型值。
    * **调试线索：** 代码会进入 `webkitRequestFileSystemSync`，并在类型检查时抛出 `DOMExceptionCode::kInvalidModificationError` 异常。

3. **无效的 URL (EncodingError):**  传递给 `webkitResolveLocalFileSystemURL` 或 `webkitResolveLocalFileSystemSyncURL` 的 URL 格式不正确或者无法解析。
    * **编程错误：** 手动构建了错误的本地文件系统 URL 字符串。
    * **调试线索：** 代码会进入 `webkitResolveLocalFileSystemURL` 或 `webkitResolveLocalFileSystemSyncURL`，并在 URL 验证时返回错误或抛出 `DOMExceptionCode::kEncodingError` 异常。

4. **配额超出 (QuotaExceededError):**  请求的文件系统大小超过了浏览器允许的配额限制。
    * **用户操作：**  网站需要存储大量数据，超过了浏览器为该站点分配的存储空间。
    * **调试线索：** `webkitRequestFileSystem` 的错误回调函数会被调用，并且 `FileError` 对象的 `code` 属性值为 `QUOTA_EXCEEDED_ERR`。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在浏览器中访问了一个网页，该网页的功能需要使用 Web Worker 来处理一些文件操作。

1. **用户访问网页:** 用户在浏览器地址栏输入网址，或者点击一个链接打开网页。
2. **网页加载并执行 JavaScript:** 浏览器加载 HTML、CSS 和 JavaScript 代码。
3. **JavaScript 创建 Web Worker:**  网页的 JavaScript 代码创建了一个新的 Web Worker。
   ```javascript
   const myWorker = new Worker('worker.js');
   ```
4. **Web Worker 脚本执行:**  浏览器在一个单独的线程中运行 `worker.js` 文件中的 JavaScript 代码。
5. **Web Worker 调用文件系统 API:**  `worker.js` 中的代码调用了 `webkitRequestFileSystem` 或 `webkitResolveLocalFileSystemURL` 等文件系统相关的 API。
   ```javascript
   // 在 worker.js 中
   webkitRequestFileSystem(TEMPORARY, 1024, successCallback, errorCallback);
   ```
6. **Blink 引擎处理请求:**  V8 引擎执行到文件系统 API 调用时，会调用 Blink 引擎中对应的 C++ 代码，即 `worker_global_scope_file_system.cc` 中的函数。
7. **进入 `worker_global_scope_file_system.cc`:**  根据调用的 API 类型（异步或同步），会进入 `webkitRequestFileSystem`、`webkitRequestFileSystemSync`、`webkitResolveLocalFileSystemURL` 或 `webkitResolveLocalFileSystemSyncURL` 中的相应函数。
8. **执行逻辑和回调:**  这些 C++ 函数会执行安全检查、参数验证，并与底层的文件系统模块交互。最终，它们会调用 JavaScript 中定义的回调函数（`successCallback` 或 `errorCallback`）来返回结果或错误信息给 Web Worker。

**调试线索：**

* **在浏览器开发者工具中查看 Web Worker 的控制台:**  可以查看 Web Worker 中 `console.log` 或 `console.error` 的输出，了解文件系统操作的结果或错误。
* **在浏览器开发者工具中设置断点:** 可以在 Web Worker 的 JavaScript 代码中设置断点，查看调用文件系统 API 时的参数和状态。
* **在 Blink 引擎源代码中设置断点:** 如果需要深入了解 Blink 引擎的执行过程，可以在 `worker_global_scope_file_system.cc` 相关的函数中设置断点，例如在安全检查、参数验证或调用底层文件系统模块的地方。需要编译 Chromium 才能进行此类调试。
* **查看网络请求:**  虽然文件系统 API 不涉及网络请求，但如果 Web Worker 从服务器加载文件并存储到文件系统，可以查看相关的网络请求。
* **检查浏览器安全策略:** 确保当前网页的上下文允许访问文件系统。例如，检查是否使用了 HTTPS。

总而言之，`worker_global_scope_file_system.cc` 是 Chromium Blink 引擎中 Web Worker 使用 File System API 的关键实现，它连接了 JavaScript API 和底层的操作系统文件系统操作。 理解其功能有助于开发者调试 Web Worker 中与文件系统相关的错误。

### 提示词
```
这是目录为blink/renderer/modules/filesystem/worker_global_scope_file_system.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2008 Apple Inc. All Rights Reserved.
 * Copyright (C) 2009, 2011 Google Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "third_party/blink/renderer/modules/filesystem/worker_global_scope_file_system.h"

#include <memory>

#include "third_party/blink/public/mojom/filesystem/file_system.mojom-blink.h"
#include "third_party/blink/renderer/core/fileapi/file_error.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/modules/filesystem/async_callback_helper.h"
#include "third_party/blink/renderer/modules/filesystem/directory_entry_sync.h"
#include "third_party/blink/renderer/modules/filesystem/dom_file_system.h"
#include "third_party/blink/renderer/modules/filesystem/entry.h"
#include "third_party/blink/renderer/modules/filesystem/file_entry_sync.h"
#include "third_party/blink/renderer/modules/filesystem/file_system_callbacks.h"
#include "third_party/blink/renderer/modules/filesystem/local_file_system.h"
#include "third_party/blink/renderer/modules/filesystem/sync_callback_helper.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"

namespace blink {

void WorkerGlobalScopeFileSystem::webkitRequestFileSystem(
    WorkerGlobalScope& worker,
    int type,
    int64_t size,
    V8FileSystemCallback* success_callback,
    V8ErrorCallback* error_callback) {
  ExecutionContext* secure_context = worker.GetExecutionContext();
  auto error_callback_wrapper =
      AsyncCallbackHelper::ErrorCallback(error_callback);

  if (!secure_context->GetSecurityOrigin()->CanAccessFileSystem()) {
    DOMFileSystem::ReportError(&worker, std::move(error_callback_wrapper),
                               base::File::FILE_ERROR_SECURITY);
    return;
  } else if (secure_context->GetSecurityOrigin()->IsLocal()) {
    UseCounter::Count(secure_context, WebFeature::kFileAccessedFileSystem);
  }

  mojom::blink::FileSystemType file_system_type =
      static_cast<mojom::blink::FileSystemType>(type);
  if (!DOMFileSystemBase::IsValidType(file_system_type)) {
    DOMFileSystem::ReportError(&worker, std::move(error_callback_wrapper),
                               base::File::FILE_ERROR_INVALID_OPERATION);
    return;
  }

  auto success_callback_wrapper =
      AsyncCallbackHelper::SuccessCallback<DOMFileSystem>(success_callback);

  LocalFileSystem::From(worker)->RequestFileSystem(
      file_system_type, size,
      std::make_unique<FileSystemCallbacks>(std::move(success_callback_wrapper),
                                            std::move(error_callback_wrapper),
                                            &worker, file_system_type),
      LocalFileSystem::kAsynchronous);
}

DOMFileSystemSync* WorkerGlobalScopeFileSystem::webkitRequestFileSystemSync(
    WorkerGlobalScope& worker,
    int type,
    int64_t size,
    ExceptionState& exception_state) {
  ExecutionContext* secure_context = worker.GetExecutionContext();
  if (!secure_context->GetSecurityOrigin()->CanAccessFileSystem()) {
    exception_state.ThrowSecurityError(file_error::kSecurityErrorMessage);
    return nullptr;
  } else if (secure_context->GetSecurityOrigin()->IsLocal()) {
    UseCounter::Count(secure_context, WebFeature::kFileAccessedFileSystem);
  }

  mojom::blink::FileSystemType file_system_type =
      static_cast<mojom::blink::FileSystemType>(type);
  if (!DOMFileSystemBase::IsValidType(file_system_type)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidModificationError,
        "the type must be kTemporary or kPersistent.");
    return nullptr;
  }

  auto* sync_helper = MakeGarbageCollected<FileSystemCallbacksSyncHelper>();

  auto success_callback_wrapper =
      WTF::BindOnce(&FileSystemCallbacksSyncHelper::OnSuccess,
                    WrapPersistentIfNeeded(sync_helper));
  auto error_callback_wrapper =
      WTF::BindOnce(&FileSystemCallbacksSyncHelper::OnError,
                    WrapPersistentIfNeeded(sync_helper));

  auto callbacks = std::make_unique<FileSystemCallbacks>(
      std::move(success_callback_wrapper), std::move(error_callback_wrapper),
      &worker, file_system_type);

  LocalFileSystem::From(worker)->RequestFileSystem(
      file_system_type, size, std::move(callbacks),
      LocalFileSystem::kSynchronous);
  DOMFileSystem* file_system = sync_helper->GetResultOrThrow(exception_state);
  return file_system ? MakeGarbageCollected<DOMFileSystemSync>(file_system)
                     : nullptr;
}

void WorkerGlobalScopeFileSystem::webkitResolveLocalFileSystemURL(
    WorkerGlobalScope& worker,
    const String& url,
    V8EntryCallback* success_callback,
    V8ErrorCallback* error_callback) {
  KURL completed_url = worker.CompleteURL(url);
  ExecutionContext* secure_context = worker.GetExecutionContext();
  auto error_callback_wrapper =
      AsyncCallbackHelper::ErrorCallback(error_callback);

  if (!secure_context->GetSecurityOrigin()->CanAccessFileSystem() ||
      !secure_context->GetSecurityOrigin()->CanRequest(completed_url)) {
    DOMFileSystem::ReportError(&worker, std::move(error_callback_wrapper),
                               base::File::FILE_ERROR_SECURITY);
    return;
  } else if (secure_context->GetSecurityOrigin()->IsLocal()) {
    UseCounter::Count(secure_context, WebFeature::kFileAccessedFileSystem);
  }

  if (!completed_url.IsValid()) {
    DOMFileSystem::ReportError(&worker, std::move(error_callback_wrapper),
                               base::File::FILE_ERROR_INVALID_URL);
    return;
  }

  auto success_callback_wrapper =
      AsyncCallbackHelper::SuccessCallback<Entry>(success_callback);

  LocalFileSystem::From(worker)->ResolveURL(
      completed_url,
      std::make_unique<ResolveURICallbacks>(std::move(success_callback_wrapper),
                                            std::move(error_callback_wrapper),
                                            &worker),
      LocalFileSystem::kAsynchronous);
}

EntrySync* WorkerGlobalScopeFileSystem::webkitResolveLocalFileSystemSyncURL(
    WorkerGlobalScope& worker,
    const String& url,
    ExceptionState& exception_state) {
  KURL completed_url = worker.CompleteURL(url);
  ExecutionContext* secure_context = worker.GetExecutionContext();
  if (!secure_context->GetSecurityOrigin()->CanAccessFileSystem() ||
      !secure_context->GetSecurityOrigin()->CanRequest(completed_url)) {
    exception_state.ThrowSecurityError(file_error::kSecurityErrorMessage);
    return nullptr;
  } else if (secure_context->GetSecurityOrigin()->IsLocal()) {
    UseCounter::Count(secure_context, WebFeature::kFileAccessedFileSystem);
  }

  if (!completed_url.IsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kEncodingError,
                                      "the URL '" + url + "' is invalid.");
    return nullptr;
  }

  auto* sync_helper = MakeGarbageCollected<EntryCallbacksSyncHelper>();

  auto success_callback_wrapper =
      WTF::BindOnce(&EntryCallbacksSyncHelper::OnSuccess,
                    WrapPersistentIfNeeded(sync_helper));
  auto error_callback_wrapper = WTF::BindOnce(
      &EntryCallbacksSyncHelper::OnError, WrapPersistentIfNeeded(sync_helper));

  std::unique_ptr<ResolveURICallbacks> callbacks =
      std::make_unique<ResolveURICallbacks>(std::move(success_callback_wrapper),
                                            std::move(error_callback_wrapper),
                                            &worker);

  LocalFileSystem::From(worker)->ResolveURL(completed_url, std::move(callbacks),
                                            LocalFileSystem::kSynchronous);

  Entry* entry = sync_helper->GetResultOrThrow(exception_state);
  return entry ? EntrySync::Create(entry) : nullptr;
}

static_assert(static_cast<int>(WorkerGlobalScopeFileSystem::kTemporary) ==
                  static_cast<int>(mojom::blink::FileSystemType::kTemporary),
              "WorkerGlobalScopeFileSystem::kTemporary should match "
              "FileSystemTypeTemporary");
static_assert(static_cast<int>(WorkerGlobalScopeFileSystem::kPersistent) ==
                  static_cast<int>(mojom::blink::FileSystemType::kPersistent),
              "WorkerGlobalScopeFileSystem::kPersistent should match "
              "FileSystemTypePersistent");

}  // namespace blink
```