Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Understanding the Core Purpose:**

The first step is to read the code and comments to grasp the overall goal. The file name `storage_bucket_manager.cc` and the namespace `blink::buckets` immediately suggest this code manages storage buckets. The copyright notice and includes provide context (Chromium, Blink). Reading the initial part of the code reveals key classes like `StorageBucketManager`, `StorageBucket`, and `StorageBucketOptions`. The `open`, `keys`, and `Delete` methods strongly indicate it's an interface for interacting with these buckets.

**2. Identifying Key Functionalities:**

Next, I go through each public method in `StorageBucketManager` and understand its purpose:

* **`StorageBucketManager` (constructor):**  Sets up the manager, linking it to a `NavigatorBase`.
* **`storageBuckets` (static method):** Provides access to the `StorageBucketManager` instance, creating it if it doesn't exist. This is a common pattern for providing a singleton-like behavior within a specific scope.
* **`open`:**  The core function for creating or opening a storage bucket. It takes a name and options as input. The return type `ScriptPromise<StorageBucket>` signals it's asynchronous and interacts with JavaScript.
* **`keys`:** Retrieves a list of existing storage bucket names. Again, the `ScriptPromise` indicates asynchronous JavaScript interaction.
* **`Delete`:**  Deletes a storage bucket by its name. Another asynchronous operation via `ScriptPromise`.
* **`GetBucketForDevtools`:** A special method likely used for developer tools to inspect storage buckets. It returns a `StorageBucket` object directly, suggesting it's not part of the standard JavaScript API.

**3. Analyzing Interactions with JavaScript, HTML, and CSS:**

The `ScriptPromise` return types in `open`, `keys`, and `Delete` are the strongest indicators of JavaScript interaction. I look for patterns like:

* **`ScriptState* script_state`:** This is a key parameter passed from the JavaScript side, representing the V8 execution context.
* **`MakeGarbageCollected<ScriptPromiseResolver...>`:**  This pattern is used to create promises that will be resolved or rejected from the C++ side.
* **`ExceptionState& exception_state`:** This is how C++ code reports errors back to JavaScript, which are then typically surfaced as JavaScript exceptions.
* **`v8_throw_exception.h`:** Inclusion of this header reinforces the connection to V8, the JavaScript engine.
* **`NavigatorBase`:** This class is part of the browser's core navigation and windowing system, making the `StorageBucketManager` accessible from JavaScript through the `navigator` object.

Based on these observations, I can deduce that the `StorageBucketManager` is exposed as a JavaScript API. While it doesn't directly manipulate HTML or CSS, it provides a storage mechanism that JavaScript code can use, which *indirectly* affects how web applications manage data and potentially influence how they render HTML and CSS (e.g., storing user preferences, cached data).

**4. Logical Reasoning and Hypothetical Input/Output:**

For each public method, I consider what inputs it takes and what outputs it produces, especially considering success and error scenarios.

* **`open`:**
    * **Input:** A bucket name (string), optional `StorageBucketOptions` (persisted, quota, durability, expires).
    * **Success Output:** A `StorageBucket` object wrapped in a Promise.
    * **Error Output:** A rejected Promise with a `TypeError` (invalid name, zero quota) or `SecurityError` (access denied) or `DOMException` (unknown error, quota exceeded, invalid expiration).

* **`keys`:**
    * **Input:** None directly, but depends on the existing storage buckets.
    * **Success Output:** A Promise resolving with an array of bucket names (strings).
    * **Error Output:** A rejected Promise with a `DOMException` (unknown error).

* **`Delete`:**
    * **Input:** A bucket name (string).
    * **Success Output:** A Promise resolving with `undefined`.
    * **Error Output:** A rejected Promise with a `TypeError` (invalid name) or `SecurityError` (access denied) or `DOMException` (unknown error).

**5. Identifying User/Programming Errors:**

I look for validation checks and error handling within the code:

* **`IsValidName`:** This function checks for invalid bucket names (e.g., uppercase letters, special characters at the beginning, length restrictions). This directly relates to user input (the bucket name).
* **Quota Check (`options->hasQuota() && options->quota() == 0`):** Prevents creating buckets with a zero quota.
* **Security Checks (`!context->GetSecurityOrigin()->CanAccessStorageBuckets()`):** Ensures the API is used in a permitted context.
* **Error Handling in Callbacks (`DidOpen`, `DidGetKeys`, `DidDelete`):** The `switch` statement in `DidOpen` and the checks for `!success` in other callbacks handle errors received from the underlying storage system.

**6. Tracing User Operations to the Code:**

This requires understanding how the Storage Buckets API is exposed in JavaScript. I would look for API documentation or examples of how developers use it. The method names (`open`, `keys`, `delete`) directly map to the JavaScript API. Therefore, a typical flow would be:

1. **JavaScript Code:**  `navigator.storageBuckets.open('my-bucket', { quota: 1024 });`
2. **Blink Binding Layer:** The JavaScript call is intercepted by Blink's binding layer, which converts JavaScript values to C++ types.
3. **`StorageBucketManager::open`:** This C++ method is invoked with the provided name and options.
4. **Mojo Communication:** The `GetBucketManager` method obtains a `BucketManagerHost` interface (via Mojo IPC) to communicate with the browser process (where the actual storage operations likely happen).
5. **Browser Process:** The browser process handles the storage request.
6. **Callback:** The result is sent back to the renderer process, invoking the `DidOpen` callback in `StorageBucketManager`.
7. **Promise Resolution:** The `DidOpen` method resolves or rejects the JavaScript Promise.

Similar flows apply to the `keys` and `delete` methods.

**7. Using the `#include` Directives:**

The included headers provide further clues about the functionality:

* **`third_party/blink/public/platform/browser_interface_broker_proxy.h`:**  Indicates communication with the browser process.
* **`third_party/blink/public/platform/task_type.h`:** Shows the use of specific task runners.
* **`third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h`:**  Confirms the use of script promises.
* **`third_party/blink/renderer/bindings/modules/v8/v8_storage_bucket_options.h`:** Defines the structure for the `StorageBucketOptions`.
* **`third_party/blink/renderer/core/dom/dom_exception.h`:**  Shows the use of DOM exceptions for error reporting.
* **`third_party/blink/renderer/core/execution_context/navigator_base.h`:**  Indicates the manager is associated with a navigator.
* **`third_party/blink/renderer/modules/buckets/storage_bucket.h`:**  Defines the `StorageBucket` class.
* **`third_party/blink/renderer/platform/bindings/...`:** Various headers related to the V8 binding layer.
* **`third_party/blink/renderer/platform/weborigin/security_origin.h`:**  Highlights the importance of security checks.
* **`third_party/blink/renderer/platform/wtf/...`:**  Use of utility classes from the WTF library.

By systematically analyzing the code in this manner, I can build a comprehensive understanding of its functionality, its interactions with web technologies, potential errors, and how user actions lead to its execution.
好的，让我们详细分析一下 `blink/renderer/modules/buckets/storage_bucket_manager.cc` 这个文件。

**功能概览**

`StorageBucketManager` 的主要功能是作为 Blink 渲染引擎中管理和操作存储桶（Storage Buckets）的中心接口。它负责：

1. **创建和打开存储桶 (`open` 方法):**  允许 JavaScript 代码请求打开或创建具有特定名称和选项的存储桶。
2. **列出所有存储桶名称 (`keys` 方法):** 提供一个方法来获取当前源（origin）下所有已创建的存储桶的名称列表。
3. **删除存储桶 (`Delete` 方法):** 允许删除指定名称的存储桶。
4. **与浏览器进程通信:**  通过 Mojo IPC 与浏览器进程中的 `BucketManagerHost` 通信，实际的存储桶操作由浏览器进程负责。
5. **管理生命周期:**  作为 `NavigatorBase` 的补充（Supplement），它的生命周期与 `NavigatorBase` 相关联。
6. **处理错误:**  处理来自浏览器进程的错误，并将这些错误转化为 JavaScript 的 Promise rejection。
7. **提供给开发者工具使用 (`GetBucketForDevtools`):**  提供一个特殊的方法，允许开发者工具获取存储桶的信息。
8. **参数校验:** 验证存储桶名称的有效性，并对选项参数进行检查。

**与 JavaScript, HTML, CSS 的关系**

`StorageBucketManager` 是通过 JavaScript API 暴露给网页开发者的，它本身不直接操作 HTML 或 CSS。但是，通过提供的 JavaScript API，开发者可以使用存储桶来存储与网页相关的数据，从而间接地影响 HTML 和 CSS 的展示和行为。

**举例说明:**

* **JavaScript:**  开发者可以使用 `navigator.storageBuckets` API 来调用 `StorageBucketManager` 的功能。

   ```javascript
   // 打开或创建名为 'my-images' 的存储桶，并设置最大配额
   navigator.storageBuckets.open('my-images', {
       quota: 1024 * 1024 // 1MB
   }).then(bucket => {
       console.log('存储桶已打开:', bucket.name);
       // 在这里可以使用 bucket 对象进行进一步操作，例如访问 IndexedDB
   }).catch(error => {
       console.error('打开存储桶失败:', error);
   });

   // 获取所有存储桶的名称
   navigator.storageBuckets.keys().then(bucketNames => {
       console.log('所有存储桶名称:', bucketNames);
   });

   // 删除名为 'temp-data' 的存储桶
   navigator.storageBuckets.delete('temp-data').then(() => {
       console.log('存储桶已删除');
   }).catch(error => {
       console.error('删除存储桶失败:', error);
   });
   ```

* **HTML:**  虽然 `StorageBucketManager` 不直接操作 HTML，但 JavaScript 可以使用存储桶存储数据，然后根据这些数据动态生成 HTML 内容或修改现有的 HTML 结构。例如，可以存储用户偏好设置，并在页面加载时根据这些设置渲染不同的 UI 元素。

* **CSS:**  类似地，存储桶中存储的数据可以用来动态修改 CSS 样式。例如，用户选择的网站主题颜色可以存储在存储桶中，然后 JavaScript 代码读取该值并动态更新页面的 CSS 变量或类名。

**逻辑推理（假设输入与输出）**

假设用户在 JavaScript 中调用了 `navigator.storageBuckets.open('user-data', { persisted: true })`:

* **假设输入:**
    * `script_state`: 当前 JavaScript 的执行状态。
    * `name`:  字符串 "user-data"。
    * `options`:  `StorageBucketOptions` 对象，其中 `persisted` 属性为 `true`。
    * `exception_state`:  用于报告异常的对象。

* **逻辑推理过程:**
    1. `StorageBucketManager::open` 方法被调用。
    2. 检查执行上下文是否已销毁，如果已销毁则抛出 `TypeError` 并返回 rejected Promise。
    3. 检查当前安全源是否有访问 Storage Buckets API 的权限，如果没有则抛出 `SecurityError` 并返回 rejected Promise。
    4. 调用 `IsValidName('user-data')` 验证名称是否有效。
    5. 将 `StorageBucketOptions` 转换为 Mojo 消息 `mojom::blink::BucketPoliciesPtr`，其中 `policies->persisted` 为 `true`。
    6. 通过 `GetBucketManager(script_state)` 获取 `BucketManagerHost` 的远程接口。
    7. 调用 `BucketManagerHost` 的 `OpenBucket` 方法，传递存储桶名称、策略和回调函数 `DidOpen`。

* **假设输出（成功情况）:**
    * 浏览器进程成功创建或打开了名为 "user-data" 的存储桶。
    * 浏览器进程通过 Mojo IPC 调用 `StorageBucketManager::DidOpen` 回调函数，并传递一个 `BucketHost` 的远程接口。
    * `DidOpen` 方法创建一个新的 `StorageBucket` 对象，并将 Promise resolve 为该对象。

* **假设输出（失败情况，例如名称无效）:**
    * `IsValidName('User Data!')` 返回 `false`。
    * `open` 方法创建一个 rejected Promise，并带有 `TypeError` 异常，错误消息为 "The bucket name 'User Data!' is not a valid name."。

**用户或编程常见的使用错误**

1. **无效的存储桶名称:**  使用包含大写字母、特殊字符（除了 '-' 和 '_' 在中间）或以特殊字符开头的名称。
   ```javascript
   navigator.storageBuckets.open('MyBucket', {}); // 错误：包含大写字母
   navigator.storageBuckets.open('$invalid', {}); // 错误：以特殊字符开头
   ```
   * **错误信息:** "The bucket name 'MyBucket' is not a valid name." 或 "The bucket name '$invalid' is not a valid name."

2. **设置配额为零:**  尝试创建一个配额为 0 的存储桶。
   ```javascript
   navigator.storageBuckets.open('empty-bucket', { quota: 0 }); // 错误：配额为零
   ```
   * **错误信息:** "The bucket's quota cannot equal zero."

3. **在不允许访问 Storage Buckets API 的上下文中使用:** 例如在嵌入的 iframe 中，并且该 iframe 的安全策略不允许访问。
   ```javascript
   // 在一个没有 Storage Buckets API 权限的上下文中
   navigator.storageBuckets.open('my-bucket', {}); // 错误：没有权限
   ```
   * **错误信息:** "Access to Storage Buckets API is denied in this context."

4. **在 window/worker 被销毁后尝试操作:**  在页面卸载或 worker 终止后，尝试调用 `navigator.storageBuckets` 的方法。
   ```javascript
   // 假设在 window.onbeforeunload 或 worker 的 close 事件中
   navigator.storageBuckets.open('last-attempt', {}); // 错误：上下文已销毁
   ```
   * **错误信息:** "The window/worker has been destroyed."

**用户操作是如何一步步的到达这里，作为调试线索**

假设用户访问一个网页，并且该网页的代码尝试创建一个名为 "user-settings" 的持久化存储桶。

1. **用户在浏览器中输入网址或点击链接访问该网页。**
2. **浏览器加载 HTML、CSS 和 JavaScript 资源。**
3. **JavaScript 代码执行，其中包含了以下代码片段：**
   ```javascript
   navigator.storageBuckets.open('user-settings', { persisted: true })
       .then(bucket => {
           console.log('User settings bucket opened:', bucket);
           // 后续操作，例如存储用户偏好设置
       })
       .catch(error => {
           console.error('Failed to open user settings bucket:', error);
       });
   ```
4. **当 JavaScript 引擎执行到 `navigator.storageBuckets.open` 时，Blink 内部会将这个调用路由到 `StorageBucketManager::open` 方法。**
5. **在 `StorageBucketManager::open` 中，会进行一系列的检查，例如名称有效性、权限等。**
6. **如果所有检查都通过，`StorageBucketManager` 会通过 Mojo IPC 向浏览器进程发送一个 `OpenBucket` 的请求。**
7. **浏览器进程接收到请求后，会执行实际的存储桶创建或打开操作。**
8. **浏览器进程完成操作后，会将结果（成功或失败，以及 `BucketHost` 的接口）通过 Mojo IPC 返回给渲染进程。**
9. **渲染进程的 `StorageBucketManager::DidOpen` 方法会被调用，根据浏览器进程返回的结果来 resolve 或 reject JavaScript 的 Promise。**
10. **如果 Promise 被 resolve，JavaScript 的 `.then()` 回调函数会被执行；如果 Promise 被 reject，JavaScript 的 `.catch()` 回调函数会被执行。**

**调试线索:**

* **在 Chrome 的开发者工具中查看 "Application" -> "Storage Buckets" 面板:**  可以查看当前源下的所有存储桶，以及它们的属性（如名称、配额、持久性等）。如果操作没有如预期创建或修改存储桶，可以检查这里。
* **在开发者工具的 "Console" 面板中查看错误信息:**  `StorageBucketManager` 会将错误信息转换为 JavaScript 的异常抛出，这些错误信息会显示在控制台中。
* **使用开发者工具的 "Sources" 面板进行断点调试:**  在相关的 JavaScript 代码或 `StorageBucketManager::open` 等 C++ 代码中设置断点，可以逐步跟踪代码的执行流程，查看变量的值，了解请求是如何被处理的。
* **查看 `chrome://blob-internals/` 和 `chrome://quota-internals/` 页面:**  这些 Chrome 内部页面提供了关于 Blob 和 Quota 系统的更底层信息，可能有助于诊断与存储桶相关的配额问题。
* **启用 Blink 的日志输出:**  可以通过命令行参数或其他方式启用 Blink 的详细日志输出，查看 `StorageBucketManager` 与浏览器进程之间的 Mojo 通信情况。

希望这个详细的分析对您有所帮助！

### 提示词
```
这是目录为blink/renderer/modules/buckets/storage_bucket_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/buckets/storage_bucket_manager.h"

#include <cstdint>

#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_storage_bucket_options.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/navigator_base.h"
#include "third_party/blink/renderer/modules/buckets/storage_bucket.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/ascii_ctype.h"

namespace blink {

namespace {

bool IsValidName(const String& name) {
  if (!name.IsLowerASCII()) {
    return false;
  }

  if (!name.ContainsOnlyASCIIOrEmpty()) {
    return false;
  }

  if (name.empty() || name.length() >= 64) {
    return false;
  }

  // | name | must only contain lowercase latin letters, digits 0-9, or special
  // characters '-' & '_' in the middle of the name, but not at the beginning.
  for (wtf_size_t i = 0; i < name.length(); i++) {
    if (!IsASCIIAlphanumeric(name[i]) &&
        (i == 0 || (name[i] != '_' && name[i] != '-'))) {
      return false;
    }
  }
  return true;
}

mojom::blink::BucketPoliciesPtr ToMojoBucketPolicies(
    const StorageBucketOptions* options) {
  auto policies = mojom::blink::BucketPolicies::New();
  if (options->hasPersisted()) {
    policies->persisted = options->persisted();
    policies->has_persisted = true;
  }

  if (options->hasQuota()) {
    DCHECK_LE(options->quota(), uint64_t{std::numeric_limits<int64_t>::max()});
    policies->quota = options->quota();
    policies->has_quota = true;
  }

  if (options->hasDurability()) {
    policies->durability = options->durability() == "strict"
                               ? mojom::blink::BucketDurability::kStrict
                               : mojom::blink::BucketDurability::kRelaxed;
    policies->has_durability = true;
  }

  if (options->hasExpires()) {
    policies->expires =
        base::Time::FromMillisecondsSinceUnixEpoch(options->expires());
  }

  return policies;
}

}  // namespace

const char StorageBucketManager::kSupplementName[] = "StorageBucketManager";

StorageBucketManager::StorageBucketManager(NavigatorBase& navigator)
    : Supplement<NavigatorBase>(navigator),
      ExecutionContextClient(navigator.GetExecutionContext()),
      manager_remote_(navigator.GetExecutionContext()),
      navigator_base_(navigator) {}

StorageBucketManager* StorageBucketManager::storageBuckets(
    NavigatorBase& navigator) {
  auto* supplement =
      Supplement<NavigatorBase>::From<StorageBucketManager>(navigator);
  if (!supplement) {
    supplement = MakeGarbageCollected<StorageBucketManager>(navigator);
    Supplement<NavigatorBase>::ProvideTo(navigator, supplement);
  }
  return supplement;
}

ScriptPromise<StorageBucket> StorageBucketManager::open(
    ScriptState* script_state,
    const String& name,
    const StorageBucketOptions* options,
    ExceptionState& exception_state) {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<StorageBucket>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  ExecutionContext* context = ExecutionContext::From(script_state);

  if (context->IsContextDestroyed()) {
    exception_state.ThrowTypeError("The window/worker has been destroyed.");
    return promise;
  }

  if (!context->GetSecurityOrigin()->CanAccessStorageBuckets()) {
    exception_state.ThrowSecurityError(
        "Access to Storage Buckets API is denied in this context.");
    return promise;
  }

  if (!IsValidName(name)) {
    resolver->Reject(V8ThrowException::CreateTypeError(
        script_state->GetIsolate(),
        "The bucket name '" + name + "' is not a valid name."));
    return promise;
  }

  if (options->hasQuota() && options->quota() == 0) {
    resolver->Reject(V8ThrowException::CreateTypeError(
        script_state->GetIsolate(), "The bucket's quota cannot equal zero."));
    return promise;
  }

  mojom::blink::BucketPoliciesPtr bucket_policies =
      ToMojoBucketPolicies(options);
  GetBucketManager(script_state)
      ->OpenBucket(
          name, std::move(bucket_policies),
          WTF::BindOnce(&StorageBucketManager::DidOpen, WrapPersistent(this),
                        WrapPersistent(resolver), name));
  return promise;
}

ScriptPromise<IDLSequence<IDLString>> StorageBucketManager::keys(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<IDLString>>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  ExecutionContext* context = ExecutionContext::From(script_state);
  if (context->IsContextDestroyed()) {
    exception_state.ThrowTypeError("The window/worker has been destroyed.");
    return promise;
  }

  if (!context->GetSecurityOrigin()->CanAccessStorageBuckets()) {
    exception_state.ThrowSecurityError(
        "Access to Storage Buckets API is denied in this context.");
    return promise;
  }

  GetBucketManager(script_state)
      ->Keys(WTF::BindOnce(&StorageBucketManager::DidGetKeys,
                           WrapPersistent(this), WrapPersistent(resolver)));
  return promise;
}

ScriptPromise<IDLUndefined> StorageBucketManager::Delete(
    ScriptState* script_state,
    const String& name,
    ExceptionState& exception_state) {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  ExecutionContext* context = ExecutionContext::From(script_state);
  if (context->IsContextDestroyed()) {
    exception_state.ThrowTypeError("The window/worker has been destroyed.");
    return promise;
  }

  if (!context->GetSecurityOrigin()->CanAccessStorageBuckets()) {
    exception_state.ThrowSecurityError(
        "Access to Storage Buckets API is denied in this context.");
    return promise;
  }

  if (!IsValidName(name)) {
    resolver->Reject(V8ThrowException::CreateTypeError(
        script_state->GetIsolate(),
        "The bucket name " + name + " is not a valid name."));
    return promise;
  }

  GetBucketManager(script_state)
      ->DeleteBucket(
          name, WTF::BindOnce(&StorageBucketManager::DidDelete,
                              WrapPersistent(this), WrapPersistent(resolver)));
  return promise;
}

mojom::blink::BucketManagerHost* StorageBucketManager::GetBucketManager(
    ScriptState* script_state) {
  if (!manager_remote_.is_bound()) {
    ExecutionContext* context = ExecutionContext::From(script_state);
    mojo::PendingReceiver<mojom::blink::BucketManagerHost> receiver =
        manager_remote_.BindNewPipeAndPassReceiver(
            context->GetTaskRunner(blink::TaskType::kMiscPlatformAPI));
    context->GetBrowserInterfaceBroker().GetInterface(std::move(receiver));
  }
  DCHECK(manager_remote_.is_bound());
  return manager_remote_.get();
}

void StorageBucketManager::DidOpen(
    ScriptPromiseResolver<StorageBucket>* resolver,
    const String& name,
    mojo::PendingRemote<mojom::blink::BucketHost> bucket_remote,
    mojom::blink::BucketError error) {
  ScriptState* script_state = resolver->GetScriptState();
  if (!script_state->ContextIsValid()) {
    return;
  }
  ScriptState::Scope scope(script_state);

  if (!bucket_remote) {
    switch (error) {
      case mojom::blink::BucketError::kUnknown:
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kUnknownError,
            "Unknown error occured while creating a bucket."));
        return;
      case mojom::blink::BucketError::kQuotaExceeded:
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kQuotaExceededError,
            "Too many buckets created."));
        return;
      case mojom::blink::BucketError::kInvalidExpiration:
        resolver->Reject(V8ThrowException::CreateTypeError(
            script_state->GetIsolate(), "The bucket expiration is invalid."));
        return;
    }
  }

  resolver->Resolve(MakeGarbageCollected<StorageBucket>(
      navigator_base_, name, std::move(bucket_remote)));
}

void StorageBucketManager::DidGetKeys(
    ScriptPromiseResolver<IDLSequence<IDLString>>* resolver,
    const Vector<String>& keys,
    bool success) {
  ScriptState* script_state = resolver->GetScriptState();
  if (!script_state->ContextIsValid()) {
    return;
  }
  ScriptState::Scope scope(script_state);

  if (!success) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kUnknownError,
        "Unknown error occured while retrieving bucket names."));
    return;
  }
  resolver->Resolve(keys);
}

void StorageBucketManager::DidDelete(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    bool success) {
  if (!success) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kUnknownError,
        "Unknown error occured while deleting a bucket."));
    return;
  }
  resolver->Resolve();
}

StorageBucket* StorageBucketManager::GetBucketForDevtools(
    ScriptState* script_state,
    const String& name) {
  ExecutionContext* context = ExecutionContext::From(script_state);
  if (!context->GetSecurityOrigin()->CanAccessStorageBuckets()) {
    return nullptr;
  }

  mojo::PendingRemote<mojom::blink::BucketHost> bucket_remote;

  GetBucketManager(script_state)
      ->GetBucketForDevtools(name,
                             bucket_remote.InitWithNewPipeAndPassReceiver());

  return MakeGarbageCollected<StorageBucket>(navigator_base_, name,
                                             std::move(bucket_remote));
}

void StorageBucketManager::Trace(Visitor* visitor) const {
  visitor->Trace(manager_remote_);
  visitor->Trace(navigator_base_);
  ScriptWrappable::Trace(visitor);
  Supplement<NavigatorBase>::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
}

}  // namespace blink
```