Response:
Let's break down the thought process for analyzing the `FileSystemObserver.cc` file.

1. **Understand the Goal:** The primary objective is to analyze the functionality of this specific Chromium Blink engine source file (`file_system_observer.cc`) and explain its role in the context of web development (JavaScript, HTML, CSS) and potential user interactions.

2. **Initial Scan for Key Concepts:**  The first step is to quickly scan the code for recognizable terms and patterns. This helps establish the general purpose of the file. Keywords that stand out include:
    * `FileSystemObserver` (the class name itself is a strong indicator).
    * `observe`, `unobserve`, `disconnect`, `OnFileChanges`. These seem to be the core actions the observer performs.
    * `FileSystemHandle`. This suggests interaction with file system entities.
    * `ScriptPromise`, `callback`. This points to asynchronous operations and interactions with JavaScript.
    * `mojom::blink::FileSystemAccess*`. This indicates communication with other parts of the Chromium system (likely the browser process).
    * `ExecutionContext`. This ties the code to a specific browsing context (window, worker).
    * `SecurityOrigin`, security checks. Permissions and security are clearly important.
    * `ExceptionState`, `ThrowSecurityError`, `Reject`. Error handling is present.

3. **Identify Core Functionality (Based on Method Names):**

    * **`Create()`:** This is a static factory method, responsible for creating `FileSystemObserver` instances. The security checks within `Create()` are a critical part of its functionality. It also establishes the connection (`BindObserverHost`) to the browser process.

    * **`FileSystemObserver()` (constructor):** Initializes the observer with the context, callback, and sets up the Mojo communication channel.

    * **`observe()`:**  This is the key method for starting observation. It takes a `FileSystemHandle` and options, and returns a `ScriptPromise`. The storage access check (`CheckStorageAccessIsAllowed`) is an important preliminary step.

    * **`OnGotStorageAccessStatus()`:**  Handles the result of the storage access check. If access is granted, it calls the browser process to start observation.

    * **`DidObserve()`:**  Handles the response from the browser process after attempting to start observation. It either resolves or rejects the `ScriptPromise` and manages the observation collection.

    * **`unobserve()`:** Stops observing a specific `FileSystemHandle`.

    * **`disconnect()`:**  Completely disconnects the observer.

    * **`OnFileChanges()`:** This is the callback from the browser process, triggered when file system changes are detected. It converts the Mojo data into `FileSystemChangeRecord` objects and invokes the JavaScript callback.

4. **Analyze Relationships with Web Technologies:**

    * **JavaScript:** The presence of `ScriptPromise`, `V8FileSystemObserverCallback`, and the invocation of the callback in `OnFileChanges` clearly shows a strong connection to JavaScript. The `observe` method is called from JavaScript, and the `OnFileChanges` event delivers updates back to JavaScript.

    * **HTML:** While not directly interacting with HTML elements, the File System Access API, which this code is a part of, is initiated through JavaScript in an HTML page. The user interaction that grants permissions is a crucial link.

    * **CSS:**  No direct relationship with CSS is evident in this particular file. File system observation is about data changes, not visual styling.

5. **Consider Logic and Data Flow:**

    * **Observation Initiation:** JavaScript calls `observer.observe(fileHandle, options)`. This leads to permission checks and then a request to the browser process.
    * **Browser Process Interaction:** The browser process handles the actual file system monitoring.
    * **Change Notification:** When changes occur, the browser process sends a notification via Mojo to `OnFileChanges`.
    * **Callback Invocation:** `OnFileChanges` processes the notification and triggers the JavaScript callback function provided during observer creation.

6. **Identify Potential User/Programming Errors:**

    * **Security Errors:**  Failing to request or obtain necessary permissions is a common user error.
    * **Incorrect Handle:** Providing an invalid or inaccessible `FileSystemHandle` will lead to errors.
    * **Forgetting to `unobserve` or `disconnect`:** This could lead to resource leaks in the browser process.
    * **Misunderstanding Callback Data:** Incorrectly interpreting the `FileSystemChangeRecord` data.

7. **Trace User Interaction (Debugging Clues):**

    * Start with the user action that triggers file system access (e.g., selecting a folder using a file picker).
    * Follow the JavaScript code that calls `FileSystemObserver.observe()`.
    * Understand how the browser process gets involved and starts monitoring.
    * Track the flow of change notifications back to the JavaScript callback.

8. **Hypothesize Inputs and Outputs (for logical reasoning):**

    * **Input to `observe()`:** A valid `FileSystemHandle` (e.g., representing a directory), `recursive: true` or `false`.
    * **Output of `observe()`:** A `Promise` that resolves when the observation is successfully set up.
    * **Input to `OnFileChanges()`:** A vector of `mojom::blink::FileSystemAccessChangePtr` objects describing file system events (creation, modification, deletion).
    * **Output of `OnFileChanges()`:** Invocation of the JavaScript callback with an array of `FileSystemChangeRecord` objects.

9. **Refine and Structure the Explanation:** Organize the findings into logical sections (Functionality, Relationship to Web Technologies, Logic, Errors, Debugging, etc.) to create a clear and comprehensive explanation. Use examples to illustrate the concepts.

10. **Review and Iterate:**  Read through the generated explanation to ensure accuracy, clarity, and completeness. Address any ambiguities or missing information. For instance, ensure the explanation of Mojo and the interaction with the browser process is understandable even for someone not deeply familiar with Chromium internals.
好的，让我们来详细分析一下 `blink/renderer/modules/file_system_access/file_system_observer.cc` 这个文件的功能。

**文件功能概览**

`FileSystemObserver.cc` 实现了 File System Access API 中的 `FileSystemObserver` 接口。该接口允许 Web 应用程序监听文件系统中的更改。简而言之，它的主要功能是：

1. **创建文件系统观察者 (`FileSystemObserver::Create`)**:  创建一个可以监听特定文件系统条目（文件或目录）变化的观察者对象。这个创建过程会进行安全检查，确保调用上下文有权限访问文件系统。
2. **开始观察 (`FileSystemObserver::observe`)**: 指示观察者开始监听特定文件系统句柄 (`FileSystemHandle`) 的变化。可以设置 `recursive` 选项来决定是否监听子目录的变化。
3. **停止观察 (`FileSystemObserver::unobserve`)**:  停止观察特定文件系统句柄的变化。
4. **断开连接 (`FileSystemObserver::disconnect`)**:  完全断开观察者与文件系统的连接，停止接收任何通知。
5. **接收文件系统变更通知 (`FileSystemObserver::OnFileChanges`)**:  当被观察的文件系统条目发生变化时（例如，文件被创建、修改、删除），操作系统会通知浏览器进程，然后浏览器进程通过 Mojo 接口将变更信息传递给 `FileSystemObserver` 对象。这个方法负责将 Mojo 传输过来的变更信息转换为 `FileSystemChangeRecord` 对象，并调用 JavaScript 回调函数来通知 Web 应用程序。

**与 JavaScript, HTML, CSS 的关系**

`FileSystemObserver` 是 File System Access API 的一部分，这个 API 是为了让 Web 应用程序能够在用户授权的情况下访问用户本地文件系统。 因此，它与 JavaScript 有着直接且重要的联系。

* **JavaScript**:  Web 开发者使用 JavaScript 代码来创建和操作 `FileSystemObserver` 对象。
    * **创建观察者:**  在 JavaScript 中，你会使用 `FileSystemHandle` 对象调用 `createObserver()` 方法来创建一个 `FileSystemObserver` 实例。例如：
      ```javascript
      const directoryHandle = await window.showDirectoryPicker();
      const observer = directoryHandle.createObserver(changes => {
        console.log("文件系统变化:", changes);
      });
      ```
    * **开始观察:** 使用 `observer.observe(fileSystemHandle, options)` 方法开始监听。
      ```javascript
      await observer.observe(directoryHandle, { recursive: true });
      ```
    * **接收变更:**  当文件系统发生变化时，`FileSystemObserver` 会调用你在 `createObserver()` 中提供的回调函数。回调函数的参数 `changes` 是一个 `FileSystemChangeRecord` 对象的数组，描述了发生的变更。
    * **停止观察:** 使用 `observer.unobserve(fileSystemHandle)` 或 `observer.disconnect()` 来停止监听。

* **HTML**: HTML 本身不直接与 `FileSystemObserver` 交互。然而，用户与 HTML 页面的交互（例如，点击按钮触发 JavaScript 代码）可能会导致 `FileSystemObserver` 的创建和使用。例如，一个文件管理器 Web 应用可能会使用 `FileSystemObserver` 来实时更新目录内容。

* **CSS**: CSS 与 `FileSystemObserver` 没有直接关系。CSS 负责页面的样式和布局，而 `FileSystemObserver` 处理的是文件系统事件。

**逻辑推理：假设输入与输出**

假设我们有以下场景：

**假设输入:**

1. 一个已经通过 `window.showDirectoryPicker()` 获取的 `FileSystemDirectoryHandle` 对象，代表用户选择的一个目录。
2. 在 JavaScript 中创建了一个 `FileSystemObserver` 对象，并绑定了一个回调函数来处理文件系统变化。
3. 调用 `observer.observe(directoryHandle, { recursive: true })` 开始观察该目录及其子目录。
4. 用户通过操作系统文件管理器，在该目录下创建了一个新的文件 "new_file.txt"。

**逻辑推理过程 (在 `FileSystemObserver.cc` 中发生的部分):**

1. 操作系统检测到文件系统变化。
2. 浏览器进程（可能通过一个独立的进程或线程进行文件系统监控）接收到这个变化通知。
3. 浏览器进程识别出这个变化发生在被观察的目录中。
4. 浏览器进程创建一个 `mojom::blink::FileSystemAccessChangePtr` 对象，其中包含了关于这次变化的元数据，例如：
    *   `type`: 表示变化类型，例如 `kCreated`。
    *   `metadata->root`: 指向被观察的根目录的 `mojom::blink::FileSystemEntryPtr`。
    *   `metadata->changed_entry`: 指向新创建的文件 "new_file.txt" 的 `mojom::blink::FileSystemEntryPtr`。
    *   `metadata->relative_path`:  新创建文件相对于根目录的路径，这里可能是 "new_file.txt"。
5. 浏览器进程通过与 `FileSystemObserver` 关联的 Mojo 管道发送这个 `mojom::blink::FileSystemAccessChangePtr` 对象。
6. `FileSystemObserver::OnFileChanges` 方法接收到这个 Mojo 消息。
7. `OnFileChanges` 方法将 `mojom::blink::FileSystemAccessChangePtr` 转换为 `FileSystemChangeRecord` 对象。这包括创建 `FileSystemHandle` 对象来表示根目录和被更改的文件。
8. `OnFileChanges` 调用在 JavaScript 中注册的回调函数，并将包含 `FileSystemChangeRecord` 对象的数组作为参数传递给它。

**预期输出 (在 JavaScript 回调函数中):**

回调函数会接收到一个包含一个 `FileSystemChangeRecord` 对象的数组，该对象会描述新文件的创建。例如，`FileSystemChangeRecord` 的属性可能包含：

*   `type`: "created"
*   `root`: 一个 `FileSystemDirectoryHandle` 对象，代表被观察的目录。
*   `changedEntry`: 一个 `FileSystemFileHandle` 对象，代表新创建的文件 "new_file.txt"。
*   `relativePath`: "new_file.txt"

**用户或编程常见的使用错误**

1. **权限错误**: 用户拒绝授予 Web 应用程序访问文件系统的权限。在这种情况下，调用 `createObserver()` 可能会抛出异常，或者 `observe()` 返回的 Promise 会被拒绝。

    *   **假设输入**: 用户在浏览器提示时点击了 "拒绝" 访问文件系统的请求。
    *   **预期结果**:  `FileSystemObserver::Create` 中的安全检查会失败，`exception_state.ThrowSecurityError()` 会被调用，JavaScript 中创建观察者的操作会抛出 `SecurityError` 类型的异常。

2. **尝试观察未授权的句柄**: 尝试观察一个 Web 应用程序没有访问权限的 `FileSystemHandle`。

    *   **假设输入**:  Web 应用尝试观察一个用户没有通过 `showOpenFilePicker` 或 `showDirectoryPicker` 选择过的文件或目录。
    *   **预期结果**:  `FileSystemObserver::observe` 方法可能会在内部与浏览器进程通信时遇到权限问题，导致 `DidObserve` 中接收到的 `result->status` 不是 `kOk`，从而导致 Promise 被拒绝，并抛出 `SecurityError`。

3. **忘记取消观察**:  如果 Web 应用程序不再需要监听文件系统变化，但忘记调用 `unobserve()` 或 `disconnect()`，可能会导致不必要的资源消耗。 虽然现代浏览器通常会处理这种情况，但在某些边缘情况下，过多的活跃观察者可能会影响性能。

4. **错误地假设回调的触发时机**:  开发者可能会错误地假设文件系统变化会立即同步地反映在回调中。实际上，通知可能存在一定的延迟。

5. **在错误的上下文中创建观察者**:  `FileSystemObserver::Create` 中有安全检查，确保它是在 Window、DedicatedWorkerGlobalScope 或 SharedWorkerGlobalScope 中创建的。如果在其他上下文中尝试创建，会抛出异常。

    *   **假设输入**: 尝试在一个不支持文件系统访问的上下文（例如，一个 Service Worker，除非特别配置）中调用 `createObserver()`。
    *   **预期结果**: `FileSystemObserver::Create` 中的 `SECURITY_CHECK` 会失败，抛出断言错误或者更严重的问题，因为文件系统访问在某些上下文中是被明确禁止的。

**用户操作是如何一步步的到达这里，作为调试线索**

为了调试 `FileSystemObserver.cc` 中的代码，可以追踪以下用户操作和代码执行路径：

1. **用户交互触发文件系统访问**:
    *   用户点击一个按钮或执行某个操作，导致 JavaScript 代码调用 `window.showOpenFilePicker()` 或 `window.showDirectoryPicker()`。
    *   浏览器显示文件选择器对话框。
    *   用户选择一个或多个文件/目录，并授予 Web 应用程序相应的权限。

2. **JavaScript 创建 `FileSystemObserver`**:
    *   在用户选择文件/目录成功后，`showOpenFilePicker()` 或 `showDirectoryPicker()` 返回一个 `FileSystemHandle` 对象（可能是 `FileSystemFileHandle` 或 `FileSystemDirectoryHandle`）。
    *   JavaScript 代码调用 `fileSystemHandle.createObserver(callback)` 来创建 `FileSystemObserver` 实例。这会调用到 `FileSystemObserver::Create`。

3. **开始观察**:
    *   JavaScript 代码调用 `observer.observe(fileSystemHandle, options)` 来开始监听文件系统变化。这会调用到 `FileSystemObserver::observe`。

4. **文件系统发生变化 (用户操作或程序操作)**:
    *   用户通过操作系统文件管理器修改、创建、删除了被观察目录或文件中的内容。
    *   或者，运行在同一台机器上的其他程序修改了这些文件。

5. **浏览器接收并处理变化**:
    *   操作系统的文件系统事件机制通知浏览器进程。
    *   浏览器进程识别出这些变化与正在被观察的 `FileSystemHandle` 相关联。
    *   浏览器进程构造 `mojom::blink::FileSystemAccessChangePtr` 对象。
    *   浏览器进程通过 Mojo 接口将这些变化信息发送到渲染器进程中的 `FileSystemObserver` 对象。

6. **`OnFileChanges` 被调用**:
    *   渲染器进程的 `FileSystemObserver::OnFileChanges` 方法接收到 Mojo 消息。
    *   该方法将 Mojo 数据转换为 `FileSystemChangeRecord` 对象。
    *   该方法调用在 JavaScript 中注册的回调函数。

**调试线索**:

*   **断点**: 在 `FileSystemObserver::Create`, `FileSystemObserver::observe`, `FileSystemObserver::OnFileChanges` 等关键方法设置断点，可以跟踪代码执行流程和变量值。
*   **Mojo 接口**: 使用 Chromium 的内部工具（如 `chrome://tracing` 或 `mojo_shell`）可以检查 Mojo 消息的传递，确认浏览器进程是否正确地发送了文件系统变化通知。
*   **日志输出**: 在关键位置添加 `DLOG` 或 `DVLOG` 输出，可以记录关键事件和数据。
*   **JavaScript 调试**: 使用浏览器的开发者工具，可以在 JavaScript 代码中设置断点，查看 `createObserver` 返回的 `FileSystemObserver` 对象，以及回调函数接收到的 `changes` 参数。
*   **权限检查**: 检查浏览器的权限设置，确认 Web 应用程序是否被授予了文件系统访问权限。
*   **错误处理**: 注意 JavaScript 中可能抛出的异常，以及 `observe()` 返回的 Promise 的 rejected 状态，这些可以提供关于错误的线索。

希望这个详细的解释能够帮助你理解 `FileSystemObserver.cc` 的功能和它在整个 File System Access API 中的作用。

### 提示词
```
这是目录为blink/renderer/modules/file_system_access/file_system_observer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/file_system_access/file_system_observer.h"

#include "third_party/blink/public/mojom/file_system_access/file_system_access_error.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_file_system_observer_callback.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_file_system_observer_observe_options.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_access_error.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_access_manager.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_change_record.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_handle.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_observation_collection.h"
#include "third_party/blink/renderer/modules/file_system_access/storage_manager_file_system_access.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

// static
FileSystemObserver* FileSystemObserver::Create(
    ScriptState* script_state,
    V8FileSystemObserverCallback* callback,
    ExceptionState& exception_state) {
  auto* context = ExecutionContext::From(script_state);

  SECURITY_CHECK(context->IsWindow() ||
                 context->IsDedicatedWorkerGlobalScope() ||
                 context->IsSharedWorkerGlobalScope());

  if (!context->GetSecurityOrigin()->CanAccessFileSystem()) {
    if (context->IsSandboxed(network::mojom::blink::WebSandboxFlags::kOrigin)) {
      exception_state.ThrowSecurityError(
          "File system access is denied because the context is "
          "sandboxed and lacks the 'allow-same-origin' flag.");
      return nullptr;
    } else {
      exception_state.ThrowSecurityError("File system access is denied.");
      return nullptr;
    }
  }

  mojo::PendingRemote<mojom::blink::FileSystemAccessObserverHost> host_remote;
  mojo::PendingReceiver<mojom::blink::FileSystemAccessObserverHost>
      host_receiver = host_remote.InitWithNewPipeAndPassReceiver();

  auto* observer_host = MakeGarbageCollected<FileSystemObserver>(
      context, callback, std::move(host_remote));

  FileSystemAccessManager::From(context)->BindObserverHost(
      std::move(host_receiver));
  return observer_host;
}

FileSystemObserver::FileSystemObserver(
    ExecutionContext* context,
    V8FileSystemObserverCallback* callback,
    mojo::PendingRemote<mojom::blink::FileSystemAccessObserverHost> host_remote)
    : execution_context_(context),
      callback_(callback),
      host_remote_(context) {
  host_remote_.Bind(std::move(host_remote),
                    execution_context_->GetTaskRunner(TaskType::kStorage));
}

ScriptPromise<IDLUndefined> FileSystemObserver::observe(
    ScriptState* script_state,
    FileSystemHandle* handle,
    FileSystemObserverObserveOptions* options,
    ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto result = resolver->Promise();

  auto on_got_storage_access_status_cb =
      WTF::BindOnce(&FileSystemObserver::OnGotStorageAccessStatus,
                    WrapWeakPersistent(this), WrapPersistent(resolver),
                    WrapPersistent(handle), WrapPersistent(options));

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

  return result;
}

void FileSystemObserver::OnGotStorageAccessStatus(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    FileSystemHandle* handle,
    FileSystemObserverObserveOptions* options,
    mojom::blink::FileSystemAccessErrorPtr result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

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

  host_remote_->Observe(
      handle->Transfer(), options->recursive(),
      WTF::BindOnce(&FileSystemObserver::DidObserve, WrapPersistent(this),
                    WrapPersistent(resolver)));
}

void FileSystemObserver::DidObserve(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    mojom::blink::FileSystemAccessErrorPtr result,
    mojo::PendingReceiver<mojom::blink::FileSystemAccessObserver>
        observer_receiver) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (result->status != mojom::blink::FileSystemAccessStatus::kOk) {
    file_system_access_error::Reject(resolver, *result);
    return;
  }

  FileSystemObservationCollection::From(execution_context_)
      ->AddObservation(this, std::move(observer_receiver));

  resolver->Resolve();
}

void FileSystemObserver::unobserve(FileSystemHandle* handle) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!host_remote_.is_bound()) {
    return;
  }

  // TODO(https://crbug.com/321980469): Unqueue and pause records for this
  // observation, or consider making observe() return a token which can be
  // passed to this method.

  // Disconnects the receiver of an observer corresponding to `handle`, if such
  // an observer exists. This will remove it from our `observer_receivers_` set.
  // It would be nice to disconnect the receiver from here, but we don't know
  // which observer (if any) corresponds to `handle` without hopping to the
  // browser to validate `handle`.
  host_remote_->Unobserve(handle->Transfer());
}

void FileSystemObserver::disconnect() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  FileSystemObservationCollection::From(execution_context_)
      ->RemoveObserver(this);
}

void FileSystemObserver::OnFileChanges(
    WTF::Vector<mojom::blink::FileSystemAccessChangePtr> mojo_changes) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  HeapVector<Member<FileSystemChangeRecord>> records;
  for (auto& mojo_change : mojo_changes) {
    FileSystemHandle* root_handle = FileSystemHandle::CreateFromMojoEntry(
        std::move(mojo_change->metadata->root), execution_context_);
    FileSystemHandle* changed_file_handle =
        FileSystemHandle::CreateFromMojoEntry(
            std::move(mojo_change->metadata->changed_entry),
            execution_context_);

    auto* record = MakeGarbageCollected<FileSystemChangeRecord>(
        root_handle, changed_file_handle,
        std::move(mojo_change->metadata->relative_path),
        std::move(mojo_change->type));
    records.push_back(record);
  }

  callback_->InvokeAndReportException(this, std::move(records), this);
}

void FileSystemObserver::Trace(Visitor* visitor) const {
  visitor->Trace(execution_context_);
  visitor->Trace(callback_);
  visitor->Trace(host_remote_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink
```