Response:
Let's break down the thought process to analyze the `StorageManagerFileSystemAccess.cc` file.

1. **Understand the Goal:** The core task is to analyze the functionality of the given C++ file within the Chromium Blink rendering engine, specifically focusing on its role in the File System Access API and its interaction with web technologies.

2. **Initial Reading and Keyword Identification:**  First, read through the code to get a general sense of its purpose. Look for keywords and function names that hint at its functionality. In this case, key terms are:

    * `StorageManagerFileSystemAccess` (the class name - this is likely a central component)
    * `getDirectory`
    * `CheckStorageAccessIsAllowed` (appears multiple times - likely a crucial permission check)
    * `DidGetSandboxedFileSystem`
    * `FileSystemDirectoryHandle`
    * `mojom::blink::FileSystemAccessError` (Mojo interface for error reporting)
    * `ScriptPromise` (indicates asynchronous operations and interaction with JavaScript)
    * `ExecutionContext` (represents the context in which the code is running, like a window or worker)
    * `WebContentSettingsClient` (likely involved in permission decisions)
    * `SecurityOrigin` (related to web security and permissions)
    * `kSandboxRootDirectoryName` (suggests a sandboxed filesystem)

3. **Deconstruct Functionality by Method:** Analyze each function individually:

    * **`getDirectory`:** This is the primary entry point. It's called with a `StorageManager`. It immediately calls `CheckStorageAccessIsAllowed` and, upon success, calls `DidGetSandboxedFileSystem`. This suggests it's the initial request for access to the file system. *Relationship to Web Tech:*  This is the JavaScript API's entry point for getting the root of the sandboxed file system.

    * **`CheckStorageAccessIsAllowed` (overloads):** This function seems responsible for determining if the current context has permission to access the file system. It checks:
        * `GetSecurityOrigin()->CanAccessFileSystem()`: A basic security check.
        * Sandboxing status:  If sandboxed *without* `allow-same-origin`, access is denied.
        * Calls `WebContentSettingsClient` to get permission, handling both `LocalDOMWindow` and `WorkerGlobalScope` contexts. *Relationship to Web Tech:* This directly enforces browser security policies related to the File System Access API.

    * **`OnGotAccessAllowed`:** This is a callback for the permission check. It handles success and failure, rejecting the promise with a `SecurityError` if access is denied. *Relationship to Web Tech:* This directly manipulates the JavaScript `Promise` returned by `getDirectory`.

    * **`DidGetSandboxedFileSystem`:** This is called after successful permission checks. It creates a `FileSystemDirectoryHandle` representing the root of the sandboxed file system and resolves the JavaScript promise. *Relationship to Web Tech:*  This provides the JavaScript with the `FileSystemDirectoryHandle` object, allowing further interaction with the file system.

    * **`DidGetSandboxedFileSystemForDevtools`:** This seems to be a specialized version for DevTools, allowing inspection of the file system. It has a similar structure to the regular `DidGetSandboxedFileSystem`. *Relationship to Web Tech:* This is not directly used by regular web pages but aids developers in debugging.

4. **Identify Relationships with Web Technologies:**  Based on the function analysis, explicitly link the C++ code to JavaScript, HTML, and CSS:

    * **JavaScript:** The most direct interaction is through the `ScriptPromise`. The `getDirectory` function is the likely implementation behind a JavaScript API method (though the exact JS API isn't in this code). The success and failure of the operation are communicated back to JavaScript through promise resolution and rejection.
    * **HTML:**  The File System Access API is often triggered by user interaction with HTML elements (e.g., a button click). The code doesn't directly interact with HTML, but the user action in the HTML is what eventually leads to this C++ code being executed.
    * **CSS:**  CSS has no direct interaction with this specific C++ file.

5. **Develop Scenarios (Hypothetical Input/Output):** Create simple scenarios to illustrate the code's behavior:

    * **Success:** User clicks a button -> JavaScript calls `navigator.storage.getDirectory()` (hypothetical) -> Permission granted -> `FileSystemDirectoryHandle` resolved.
    * **Permission Denied (Sandboxing):**  Page loaded in a sandboxed iframe without `allow-same-origin` -> JavaScript call -> Permission denied -> Promise rejected with `SecurityError`.
    * **Permission Denied (User Setting):** User has globally disabled file system access -> JavaScript call -> Permission denied -> Promise rejected with `SecurityError`.

6. **Identify Potential User Errors:** Think about how a developer might misuse the API or encounter errors due to restrictions:

    * Trying to use the API in an insecure context (HTTP).
    * Not handling promise rejections properly in JavaScript.
    * Confusing the sandboxed file system with the user's actual file system.

7. **Trace User Steps (Debugging):**  Outline the steps a user takes to reach this code, which is valuable for debugging:

    * User interacts with a webpage (click, form submission, etc.).
    * JavaScript code calls a File System Access API method (like the hypothetical `navigator.storage.getDirectory()`).
    * The browser's JavaScript engine calls the corresponding Blink C++ code (like `StorageManagerFileSystemAccess::getDirectory`).
    * The C++ code performs permission checks.
    * Depending on the outcome, the promise is resolved or rejected, and the JavaScript callback is executed.

8. **Structure the Answer:** Organize the findings logically, addressing each part of the prompt: functionality, relationship with web technologies, hypothetical scenarios, user errors, and debugging. Use clear and concise language. Use code snippets where appropriate (even though the prompt provided the entire file, highlighting key parts within the explanation is good).

9. **Review and Refine:** Read through the generated answer to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might forget to explicitly mention the role of Mojo, but rereading the code and seeing `mojom` would remind me to include that.

By following these steps, we can systematically analyze the C++ code and provide a comprehensive explanation of its functionality and its relationship to web technologies.
这个C++源代码文件 `storage_manager_file_system_access.cc` 属于 Chromium Blink 引擎，负责实现 **File System Access API** 中与 **持久化存储（Storage）** 相关的部分功能。更具体地说，它主要处理获取 **沙盒文件系统根目录句柄** 的请求。

以下是该文件的详细功能列表：

**主要功能:**

1. **提供获取沙盒文件系统根目录的功能 (`getDirectory`)**:  这是该文件的核心功能。它允许网页或 Service Worker 获取一个代表其沙盒文件系统根目录的 `FileSystemDirectoryHandle` 对象。这个句柄是访问该源的持久化存储的入口点。

2. **进行存储访问权限检查 (`CheckStorageAccessIsAllowed`)**: 在返回文件系统句柄之前，代码会进行严格的权限检查，确保当前上下文（例如，浏览上下文或 Worker）被允许访问存储。这包括：
    * **基本的安全源检查**: 检查当前 Security Origin 是否被允许访问文件系统。
    * **沙盒环境检查**: 如果当前上下文在一个没有 `allow-same-origin` 标志的沙盒 iframe 中，则会拒绝访问。
    * **内容设置客户端检查**:  调用 `WebContentSettingsClient` 来检查更细粒度的存储访问权限，允许浏览器或扩展程序进行更精细的控制。

3. **处理异步操作**: 使用 `ScriptPromise` 来处理涉及权限检查和获取文件系统句柄的异步操作，确保与 JavaScript 的交互是非阻塞的。

4. **与 Mojo 接口交互**: 使用 Mojo 接口 (`mojom::blink::FileSystemAccessErrorPtr`, `mojo::PendingRemote<mojom::blink::FileSystemAccessDirectoryHandle>`) 与浏览器进程进行通信，以执行实际的文件系统操作和获取句柄。

5. **处理错误情况**:  在权限检查失败或获取文件系统句柄失败时，会创建并抛出相应的 `DOMException`，通知 JavaScript 代码操作失败的原因。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个 C++ 文件是 File System Access API 在 Blink 渲染引擎中的后端实现。JavaScript 代码通过调用浏览器提供的 API 来触发这里的 C++ 代码。

**JavaScript:**

* **`navigator.storage.getDirectory()` (假设的 API，实际可能略有不同):**  当 JavaScript 代码调用类似 `navigator.storage.getDirectory()` 的方法时，浏览器会调用到 `StorageManagerFileSystemAccess::getDirectory` 方法。
    ```javascript
    // JavaScript 代码
    async function getMyFileSystem() {
      try {
        const root = await navigator.storage.getDirectory();
        console.log("获得了文件系统根目录句柄:", root);
        // 可以使用 root 进行文件和目录操作
      } catch (error) {
        console.error("获取文件系统失败:", error);
      }
    }

    getMyFileSystem();
    ```
    在这个例子中，`navigator.storage.getDirectory()` 的执行最终会调用到 `StorageManagerFileSystemAccess::getDirectory`，该 C++ 代码会执行权限检查，并最终返回一个 `FileSystemDirectoryHandle` 对象给 JavaScript。

* **`FileSystemDirectoryHandle` 对象:**  C++ 代码创建的 `FileSystemDirectoryHandle` 对象会被传递回 JavaScript，JavaScript 可以使用这个对象来创建、读取、写入和删除文件和目录。

**HTML:**

* HTML 元素（例如按钮）的事件监听器可能会触发 JavaScript 代码来调用文件系统 API。
    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>文件系统访问示例</title>
    </head>
    <body>
      <button id="getFileSystemButton">获取文件系统</button>
      <script>
        document.getElementById('getFileSystemButton').addEventListener('click', async () => {
          try {
            const root = await navigator.storage.getDirectory();
            console.log("获得了文件系统根目录句柄:", root);
          } catch (error) {
            console.error("获取文件系统失败:", error);
          }
        });
      </script>
    </body>
    </html>
    ```
    在这个例子中，当用户点击 "获取文件系统" 按钮时，JavaScript 代码会尝试获取文件系统，最终会触发 `StorageManagerFileSystemAccess::getDirectory` 的执行。

**CSS:**

* CSS 与此 C++ 文件没有直接的功能关系。CSS 负责页面的样式，而此文件负责文件系统访问的逻辑。

**逻辑推理，假设输入与输出:**

**假设输入：**

* **场景 1 (成功获取):**
    * 用户通过 HTTPS 访问了一个网页。
    * 网页 JavaScript 调用了 `navigator.storage.getDirectory()`。
    * 用户的浏览器设置允许该网站访问文件系统存储。
    * 该网页不在沙盒 iframe 中，或者沙盒 iframe 具有 `allow-same-origin` 标志。
* **场景 2 (权限被拒绝 - 沙盒):**
    * 用户访问了一个位于没有 `allow-same-origin` 标志的沙盒 iframe 中的网页。
    * 网页 JavaScript 调用了 `navigator.storage.getDirectory()`。
* **场景 3 (权限被拒绝 - 用户设置):**
    * 用户通过 HTTPS 访问了一个网页。
    * 网页 JavaScript 调用了 `navigator.storage.getDirectory()`。
    * 用户已在浏览器设置中阻止该网站访问文件系统存储。

**假设输出：**

* **场景 1 (成功获取):**
    * `CheckStorageAccessIsAllowed` 返回成功。
    * `DidGetSandboxedFileSystem` 被调用，创建一个 `FileSystemDirectoryHandle` 对象。
    * JavaScript 的 Promise 被解析（resolved），返回 `FileSystemDirectoryHandle` 对象。
* **场景 2 (权限被拒绝 - 沙盒):**
    * `CheckStorageAccessIsAllowed` 检测到沙盒环境且缺少 `allow-same-origin` 标志。
    * `OnGotAccessAllowed` 被调用，收到一个 `FileSystemAccessError`，状态为 `kSecurityError`，消息指示沙盒限制。
    * JavaScript 的 Promise 被拒绝（rejected），抛出一个 `SecurityError` 类型的 `DOMException`。
* **场景 3 (权限被拒绝 - 用户设置):**
    * `CheckStorageAccessIsAllowed` 调用 `WebContentSettingsClient` 后，收到拒绝访问的响应。
    * `OnGotAccessAllowed` 被调用，收到一个 `FileSystemAccessError`，状态为 `kSecurityError`，消息指示存储访问被拒绝。
    * JavaScript 的 Promise 被拒绝（rejected），抛出一个 `SecurityError` 类型的 `DOMException`。

**用户或编程常见的使用错误:**

1. **在不安全的上下文中使用 API (HTTP):** File System Access API 通常只在安全上下文（HTTPS）中可用。尝试在 HTTP 页面中使用会导致权限错误。
    * **错误示例 (JavaScript):** 在 HTTP 页面中调用 `navigator.storage.getDirectory()` 会导致 Promise 被拒绝。
    * **错误提示:** 浏览器的开发者工具可能会显示与安全上下文相关的错误信息。

2. **未处理 Promise 的 rejection:**  如果 JavaScript 代码没有正确地处理 `navigator.storage.getDirectory()` 返回的 Promise 的 rejection，当权限被拒绝时，可能会导致未捕获的错误。
    * **错误示例 (JavaScript):**
    ```javascript
    navigator.storage.getDirectory(); // 没有 .then() 或 .catch()
    ```
    * **后果:** 当权限被拒绝时，会抛出未捕获的 Promise rejection 错误。

3. **混淆沙盒文件系统与本地文件系统:**  通过 `navigator.storage.getDirectory()` 获取的是一个沙盒化的文件系统，与用户设备的实际文件系统隔离。尝试使用这个句柄访问本地文件系统的路径会失败。
    * **错误示例 (假设的错误用法):**  尝试将沙盒文件系统中的文件路径与本地文件系统的路径混用。
    * **后果:** 文件操作会失败，并可能抛出 `NotFoundError` 或其他相关的 `DOMException`。

4. **在没有用户交互的情况下请求权限 (可能被浏览器阻止):**  某些浏览器可能会限制在没有用户明确交互的情况下请求某些敏感权限，包括文件系统访问。
    * **错误场景:** 页面加载后立即调用 `navigator.storage.getDirectory()`，而没有用户点击按钮或其他交互。
    * **后果:** 可能会导致权限请求被静默拒绝。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中打开一个网页。**
2. **网页加载完成，JavaScript 代码开始执行。**
3. **JavaScript 代码调用了与 File System Access API 相关的函数，例如 `navigator.storage.getDirectory()`。**
4. **浏览器的 JavaScript 引擎识别到这个 API 调用，并将其转发到 Blink 渲染引擎中的相应模块。**
5. **在 Blink 渲染引擎中，`StorageManagerFileSystemAccess::getDirectory` 方法被调用。**
6. **`CheckStorageAccessIsAllowed` 方法被调用，开始进行权限检查：**
    * 检查当前的安全源是否允许文件系统访问。
    * 检查当前上下文是否在沙盒环境中，并检查 `allow-same-origin` 标志。
    * 调用 `WebContentSettingsClient` 获取更细粒度的权限设置。
7. **根据权限检查的结果：**
    * **如果权限允许:** `DidGetSandboxedFileSystem` 方法被调用，它会通过 Mojo 接口与浏览器进程通信，请求获取沙盒文件系统的根目录句柄。浏览器进程返回一个 `mojo::PendingRemote<mojom::blink::FileSystemAccessDirectoryHandle>`。`DidGetSandboxedFileSystem` 创建一个 `FileSystemDirectoryHandle` 对象，并通过 Promise 的 resolve 将其返回给 JavaScript 代码。
    * **如果权限被拒绝:**  `OnGotAccessAllowed` 方法接收到一个表示错误的 `mojom::blink::FileSystemAccessErrorPtr`。该方法会创建一个相应的 `DOMException`，并通过 Promise 的 reject 将错误信息返回给 JavaScript 代码。
8. **JavaScript 代码接收到 Promise 的结果（成功或失败），并执行相应的处理逻辑。**

**调试线索:**

* **浏览器的开发者工具 (Console):** 查看是否有 JavaScript 错误信息，特别是与 Promise rejection 相关的错误。
* **浏览器的开发者工具 (Network):**  虽然这个过程不涉及 HTTP 请求，但如果与某些权限相关的策略是通过网络加载的，可能会有相关信息。
* **浏览器的开发者工具 (Application/Storage):**  查看与存储相关的设置和权限信息。
* **Chromium 的内部调试页面 (chrome://inspect/#pages):** 可以检查页面的状态和是否有相关的错误或警告。
* **Blink 渲染引擎的调试日志:** 如果需要深入了解 C++ 层的执行过程，可以启用 Blink 的调试日志，查看 `StorageManagerFileSystemAccess` 和相关模块的日志输出。

总而言之，`storage_manager_file_system_access.cc` 是 File System Access API 的关键组成部分，负责处理获取沙盒文件系统根目录的请求，并确保在执行操作前进行必要的权限检查，从而保障用户的安全和隐私。它通过异步 Promise 与 JavaScript 进行交互，并将文件系统操作的请求转发到浏览器进程进行处理。

Prompt: 
```
这是目录为blink/renderer/modules/file_system_access/storage_manager_file_system_access.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/file_system_access/storage_manager_file_system_access.h"

#include <utility>

#include "mojo/public/cpp/bindings/pending_remote.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_error.mojom-blink.h"
#include "third_party/blink/public/platform/web_content_settings_client.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_access_error.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_access_manager.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_directory_handle.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {
// The name to use for the root directory of a sandboxed file system.
constexpr const char kSandboxRootDirectoryName[] = "";

// Called with the result of browser-side permissions checks.
void OnGotAccessAllowed(
    ScriptPromiseResolver<FileSystemDirectoryHandle>* resolver,
    base::OnceCallback<void(ScriptPromiseResolver<FileSystemDirectoryHandle>*)>
        on_allowed,
    const mojom::blink::FileSystemAccessErrorPtr result) {
  if (!resolver->GetExecutionContext() ||
      !resolver->GetScriptState()->ContextIsValid()) {
    return;
  }

  if (result->status != mojom::blink::FileSystemAccessStatus::kOk) {
    auto* const isolate = resolver->GetScriptState()->GetIsolate();
    ScriptState::Scope scope(resolver->GetScriptState());
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        isolate, DOMExceptionCode::kSecurityError, result->message));
    return;
  }

  std::move(on_allowed).Run(resolver);
}

}  // namespace

// static
ScriptPromise<FileSystemDirectoryHandle>
StorageManagerFileSystemAccess::getDirectory(ScriptState* script_state,
                                             const StorageManager& storage,
                                             ExceptionState& exception_state) {
  return CheckStorageAccessIsAllowed(
      script_state, exception_state,
      WTF::BindOnce([](ScriptPromiseResolver<FileSystemDirectoryHandle>*
                           resolver) {
        FileSystemAccessManager::From(resolver->GetExecutionContext())
            ->GetSandboxedFileSystem(WTF::BindOnce(
                &StorageManagerFileSystemAccess::DidGetSandboxedFileSystem,
                WrapPersistent(resolver)));
      }));
}

// static
ScriptPromise<FileSystemDirectoryHandle>
StorageManagerFileSystemAccess::CheckStorageAccessIsAllowed(
    ScriptState* script_state,
    ExceptionState& exception_state,
    base::OnceCallback<void(ScriptPromiseResolver<FileSystemDirectoryHandle>*)>
        on_allowed) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<FileSystemDirectoryHandle>>(
          script_state, exception_state.GetContext());
  auto result = resolver->Promise();

  CheckStorageAccessIsAllowed(
      ExecutionContext::From(script_state),
      WTF::BindOnce(&OnGotAccessAllowed, WrapPersistent(resolver),
                    std::move(on_allowed)));

  return result;
}

// static
void StorageManagerFileSystemAccess::CheckStorageAccessIsAllowed(
    ExecutionContext* context,
    base::OnceCallback<void(mojom::blink::FileSystemAccessErrorPtr)> callback) {
  if (!context->GetSecurityOrigin()->CanAccessFileSystem()) {
    if (context->IsSandboxed(network::mojom::blink::WebSandboxFlags::kOrigin)) {
      std::move(callback).Run(mojom::blink::FileSystemAccessError::New(
          mojom::blink::FileSystemAccessStatus::kSecurityError,
          base::File::Error::FILE_ERROR_SECURITY,
          "Storage directory access is denied because the context is "
          "sandboxed and lacks the 'allow-same-origin' flag."));
      return;
    }
    std::move(callback).Run(mojom::blink::FileSystemAccessError::New(
        mojom::blink::FileSystemAccessStatus::kSecurityError,
        base::File::Error::FILE_ERROR_SECURITY,
        "Storage directory access is denied."));
    return;
  }

  SECURITY_DCHECK(context->IsWindow() || context->IsWorkerGlobalScope());

  auto storage_access_callback =
      [](base::OnceCallback<void(mojom::blink::FileSystemAccessErrorPtr)>
             inner_callback,
         bool is_allowed) {
        std::move(inner_callback)
            .Run(is_allowed
                     ? mojom::blink::FileSystemAccessError::New(
                           mojom::blink::FileSystemAccessStatus::kOk,
                           base::File::FILE_OK, "")
                     : mojom::blink::FileSystemAccessError::New(
                           mojom::blink::FileSystemAccessStatus::kSecurityError,
                           base::File::Error::FILE_ERROR_SECURITY,
                           "Storage directory access is denied."));
      };

  if (auto* window = DynamicTo<LocalDOMWindow>(context)) {
    LocalFrame* frame = window->GetFrame();
    if (!frame) {
      std::move(callback).Run(mojom::blink::FileSystemAccessError::New(
          mojom::blink::FileSystemAccessStatus::kSecurityError,
          base::File::Error::FILE_ERROR_SECURITY,
          "Storage directory access is denied."));
      return;
    }
    frame->AllowStorageAccessAndNotify(
        WebContentSettingsClient::StorageType::kFileSystem,
        WTF::BindOnce(std::move(storage_access_callback), std::move(callback)));
    return;
  }

  WebContentSettingsClient* content_settings_client =
      To<WorkerGlobalScope>(context)->ContentSettingsClient();
  if (!content_settings_client) {
    std::move(callback).Run(mojom::blink::FileSystemAccessError::New(
        mojom::blink::FileSystemAccessStatus::kOk, base::File::FILE_OK, ""));
    return;
  }
  content_settings_client->AllowStorageAccess(
      WebContentSettingsClient::StorageType::kFileSystem,
      WTF::BindOnce(std::move(storage_access_callback), std::move(callback)));
}

// static
void StorageManagerFileSystemAccess::DidGetSandboxedFileSystem(
    ScriptPromiseResolver<FileSystemDirectoryHandle>* resolver,
    mojom::blink::FileSystemAccessErrorPtr result,
    mojo::PendingRemote<mojom::blink::FileSystemAccessDirectoryHandle> handle) {
  ExecutionContext* context = resolver->GetExecutionContext();
  if (!context)
    return;
  if (result->status != mojom::blink::FileSystemAccessStatus::kOk) {
    file_system_access_error::Reject(resolver, *result);
    return;
  }
  resolver->Resolve(MakeGarbageCollected<FileSystemDirectoryHandle>(
      context, kSandboxRootDirectoryName, std::move(handle)));
}

void StorageManagerFileSystemAccess::DidGetSandboxedFileSystemForDevtools(
    ExecutionContext* context,
    base::OnceCallback<void(mojom::blink::FileSystemAccessErrorPtr,
                            FileSystemDirectoryHandle*)> callback,
    mojom::blink::FileSystemAccessErrorPtr result,
    mojo::PendingRemote<mojom::blink::FileSystemAccessDirectoryHandle> handle) {
  if (!context) {
    return;
  }

  if (result->status != mojom::blink::FileSystemAccessStatus::kOk) {
    std::move(callback).Run(std::move(result), nullptr);
    return;
  }

  std::move(callback).Run(
      std::move(result),
      MakeGarbageCollected<FileSystemDirectoryHandle>(
          context, kSandboxRootDirectoryName, std::move(handle)));
}

}  // namespace blink

"""

```