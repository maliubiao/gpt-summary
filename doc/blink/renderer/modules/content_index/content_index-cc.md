Response:
Let's break down the thought process to analyze the provided C++ code for `content_index.cc`.

1. **Understand the Goal:** The core request is to analyze the functionality of this specific Chromium source file (`content_index.cc`) and its relationship to web technologies (JavaScript, HTML, CSS). We also need to cover error handling, user interactions, and debugging information.

2. **Initial Code Scan (Keywords and Structure):**  A quick scan reveals key terms and structural elements:
    * `#include`:  Indicates dependencies on other Chromium components. Notice includes related to `v8` (JavaScript bindings), `DOMException`, `ServiceWorkerRegistration`, `KURL` (URLs), and `mojom` (Mojo interface definitions). This immediately suggests interaction with JavaScript and backend services.
    * Class `ContentIndex`: This is the central class we need to analyze.
    * Public methods: `add`, `deleteDescription`, `getDescriptions`. These strongly hint at the core functionalities of managing some kind of indexed content.
    * Private methods with `Did...`: These are likely callbacks from asynchronous operations.
    * `ValidateDescription`: A validation function, important for understanding input constraints.
    * `GetService`: A method to obtain a `ContentIndexService`, suggesting communication with another process.
    * Promises (`ScriptPromise`):  Indicates asynchronous operations and integration with JavaScript's Promise API.
    * Exception handling (`ExceptionState`, `ThrowTypeError`, `ThrowDOMException`):  Points to how errors are reported to JavaScript.

3. **Analyze Public Methods (Functionality and JavaScript Relation):**

    * **`add(ScriptState*, const ContentDescription*, ExceptionState&)`:**
        * **Functionality:**  The name suggests adding content to the index. It takes a `ContentDescription`.
        * **JavaScript Relation:** This method is likely exposed to JavaScript as part of the `ServiceWorkerRegistration` API. A JavaScript developer would call a method (probably `registration.contentIndex.add()`) with data corresponding to the `ContentDescription`. The `ScriptState` confirms this interaction. The use of `ScriptPromise` means the JavaScript call will return a Promise.
        * **Error Handling:** Checks for active registration and fenced frames. Uses `ValidateDescription` for input validation.
        * **Example:**  A website wants to make certain content available offline or discoverable. The JavaScript could be:
          ```javascript
          navigator.serviceWorker.ready.then(registration => {
            registration.contentIndex.add({
              id: 'my-article-1',
              title: 'My Awesome Article',
              description: 'A summary of the article.',
              launch_url: '/articles/1',
              icons: [{ src: '/icons/article-1-192.png', sizes: '192x192', type: 'image/png' }]
            }).then(() => console.log('Content added!'));
          });
          ```

    * **`deleteDescription(ScriptState*, const String&, ExceptionState&)`:**
        * **Functionality:** Removes content from the index based on its ID.
        * **JavaScript Relation:** Exposed to JavaScript, likely as `registration.contentIndex.delete('some-id')`. Returns a Promise.
        * **Error Handling:** Checks for active registration and fenced frames.
        * **Example:**
          ```javascript
          navigator.serviceWorker.ready.then(registration => {
            registration.contentIndex.delete('my-article-1').then(() => console.log('Content deleted!'));
          });
          ```

    * **`getDescriptions(ScriptState*, ExceptionState&)`:**
        * **Functionality:** Retrieves all content descriptions from the index.
        * **JavaScript Relation:** Likely `registration.contentIndex.getDescriptions()`. Returns a Promise that resolves with an array of content descriptions.
        * **Error Handling:** Checks for active registration and fenced frames.
        * **Example:**
          ```javascript
          navigator.serviceWorker.ready.then(registration => {
            registration.contentIndex.getDescriptions().then(descriptions => {
              console.log('Available content:', descriptions);
            });
          });
          ```

4. **Analyze Private Methods (Internal Logic):**  These methods handle the asynchronous parts of the public methods. Pay attention to the data flow and error handling within them.

    * **`ValidateDescription`:**  Crucial for understanding input validation rules. It checks for empty fields, valid URLs, and if the launch URL is within the service worker's scope. This directly relates to how developers *must* format their `ContentDescription` objects in JavaScript.

    * **`DidGetIconSizes`, `DidGetIcons`:**  These methods deal with fetching and processing icons. This is where the relationship with image resources (potentially referenced in HTML or CSS, though the code itself doesn't directly *parse* HTML/CSS) becomes apparent. The `ContentDescription`'s `icons` array in JavaScript defines these.

    * **`DidAdd`, `DidDeleteDescription`, `DidGetDescriptions`:** These are callbacks receiving results from the `ContentIndexService` (the backend). They handle success and error scenarios, translating backend errors into DOMExceptions or TypeErrors that JavaScript can catch.

5. **Identify Relationships with HTML and CSS:**

    * **HTML:** The `launch_url` in the `ContentDescription` likely points to an HTML page. The `id`, `title`, and `description` will likely be used to display information about the indexed content, potentially within the HTML of the website itself or in platform-specific UI (like a "Read Later" list).
    * **CSS:** The icons specified in the `ContentDescription` are image resources. CSS might be used to style how these icons are displayed if the website chooses to show the indexed content.

6. **Logical Reasoning and Input/Output Examples:**  For `ValidateDescription`, we can create explicit input/output examples. For the core methods, the JavaScript examples from step 3 serve this purpose.

7. **Common User/Programming Errors:**  Think about the validation rules and asynchronous nature of the API. What mistakes could a developer make?

    * Incorrect data types in the `ContentDescription`.
    * Providing invalid URLs.
    * Forgetting to wait for the service worker to be ready.
    * Not handling the Promises correctly (especially error cases).

8. **Debugging Clues and User Actions:**  Trace the execution flow. How does a user action lead to this code being executed?

    * User installs a website as a PWA. The service worker registers.
    * Website JavaScript calls `registration.contentIndex.add()`.
    * The browser calls the `ContentIndex::add` method in this C++ file.
    * Validation occurs.
    * Communication with the backend service happens.

    For debugging, knowing this flow is essential. If something goes wrong, you might:
    * Set breakpoints in the JavaScript.
    * Set breakpoints in `ContentIndex::add` and `ValidateDescription`.
    * Inspect the `ContentDescription` object in the debugger.
    * Look at the network requests for the icons.
    * Check the service worker's console for errors.

9. **Review and Refine:**  Go through the analysis, ensuring it's clear, accurate, and addresses all aspects of the prompt. Organize the information logically.

This detailed breakdown illustrates how to approach analyzing source code, connecting it to web technologies, and understanding its role in a larger system like a web browser. The key is to follow the flow of execution, identify key components and their interactions, and consider the developer's perspective.
这个文件 `content_index.cc` 是 Chromium Blink 渲染引擎中 `ContentIndex` API 的实现。 `ContentIndex` API 允许 Web 应用通过 Service Worker 注册来管理和展示用户可能感兴趣的离线内容，例如文章、视频或播客。

以下是该文件的主要功能：

**1. 提供 JavaScript API 的底层实现:**

*   该文件实现了在 JavaScript 中通过 `ServiceWorkerRegistration.contentIndex` 访问的 `ContentIndex` 接口。
*   它包含了 `add()`, `deleteDescription()`, 和 `getDescriptions()` 等方法的 C++ 实现，这些方法对应了 JavaScript API 中的同名方法。

**2. 管理待索引的内容描述 (Content Description):**

*   `add()` 方法接收一个 `ContentDescription` 对象，该对象描述了要添加到索引的内容，包括 ID、标题、描述、启动 URL、图标等信息。
*   `deleteDescription()` 方法根据提供的 ID 从索引中移除内容。
*   `getDescriptions()` 方法返回当前索引中的所有内容描述列表。

**3. 与浏览器进程中的 Content Index 服务通信:**

*   该文件使用 Mojo (Chromium 的进程间通信机制) 与浏览器进程中的 `ContentIndexService` 进行通信。
*   `GetService()` 方法用于获取 `ContentIndexService` 的接口，以便向浏览器进程发送添加、删除和获取内容描述的请求。

**4. 处理图标加载:**

*   `add()` 方法在添加内容时会检查 `ContentDescription` 中提供的图标。
*   它使用 `ContentIndexIconLoader` 来异步加载图标，并在加载完成后将图标数据发送到浏览器进程。

**5. 进行参数校验:**

*   `ValidateDescription()` 函数用于验证 `ContentDescription` 对象是否有效，例如检查 ID、标题、描述是否为空，图标和启动 URL 是否有效等。
*   如果校验失败，会抛出相应的 `TypeError` 异常给 JavaScript。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`ContentIndex` API 是一个 JavaScript API，用于增强 Service Worker 的功能。它本身不直接操作 HTML 或 CSS，但它影响用户与 Web 应用的交互和内容展示方式。

*   **JavaScript:**  `content_index.cc` 实现了 JavaScript API 的底层逻辑。Web 开发者使用 JavaScript 调用 `ServiceWorkerRegistration.contentIndex.add()`, `deleteDescription()`, 和 `getDescriptions()` 方法。

    **例子:**

    ```javascript
    navigator.serviceWorker.ready.then(registration => {
      registration.contentIndex.add({
        id: 'my-article-1',
        title: 'My Awesome Article',
        description: 'A summary of the article.',
        launch_url: '/articles/1',
        icons: [{ src: '/icons/article-1-192.png', sizes: '192x192', type: 'image/png' }]
      }).then(() => console.log('Content added to index!'));
    });
    ```

*   **HTML:**  `ContentIndex` 中 `ContentDescription` 的 `launch_url` 字段指向一个 HTML 页面。当用户通过浏览器提供的界面访问索引中的内容时，浏览器会导航到这个 URL。

    **例子:**  `launch_url` 可能指向一个包含完整文章内容的 HTML 文件，例如 `/articles/1.html`。

*   **CSS:**  `ContentIndex` 中的 `icons` 字段指定了用于在浏览器界面中展示内容的图标。这些图标通常是 PNG 或其他图像格式，可以通过 CSS 进行样式化（尽管 `content_index.cc` 本身不涉及 CSS 处理）。

    **例子:**  浏览器可能会在一个 "离线可用" 或 "稍后阅读" 的列表中显示使用这些图标的内容条目。

**逻辑推理与假设输入输出:**

假设 JavaScript 代码调用 `registration.contentIndex.add()` 并传入以下 `ContentDescription`:

**假设输入:**

```javascript
{
  id: 'my-video-1',
  title: 'Funny Cat Video',
  description: 'A hilarious video of a cat playing with a ball of yarn.',
  launch_url: '/videos/cat-video',
  icons: [{ src: '/icons/cat-video-192.png', sizes: '192x192', type: 'image/png' }]
}
```

**`content_index.cc` 中的逻辑推理和输出:**

1. `ContentIndex::add()` 被调用。
2. `ValidateDescription()` 会检查 `id`, `title`, `description` 不为空，`launch_url` 和 `icons[0].src` 是有效的 URL，并且 `launch_url` 在 Service Worker 的 scope 内。
3. 如果校验通过，`ContentIndexIconLoader` 会开始加载 `/icons/cat-video-192.png`。
4. `GetService()->GetIconSizes()` 会被调用，以获取浏览器期望的图标尺寸。
5. 加载成功后，`GetService()->Add()` 会被调用，将包含图标数据和其他元数据的 `ContentDescription` 发送到浏览器进程的 `ContentIndexService`。
6. 如果一切顺利，`DidAdd()` 回调会被触发，并且 JavaScript Promise 会 resolve。

**假设输出 (不包括 Mojo 消息的具体细节):**

*   **JavaScript:**  `then` 回调函数会被执行，控制台输出 "Content added to index!"。
*   **浏览器内部:**  `ContentIndexService` 会将该内容描述存储起来，以便后续在浏览器界面中展示。

**用户或编程常见的使用错误及举例说明:**

1. **`ContentDescription` 中缺少必填字段:**

    **错误代码:**

    ```javascript
    registration.contentIndex.add({
      launch_url: '/some/url'
      // 缺少 id, title, description
    });
    ```

    **结果:** `ValidateDescription()` 会返回相应的错误消息，例如 "ID cannot be empty"，`add()` 方法会抛出一个 `TypeError` 异常。

2. **提供无效的 URL:**

    **错误代码:**

    ```javascript
    registration.contentIndex.add({
      id: 'invalid-url',
      title: 'Invalid URL',
      description: 'Example with invalid URL',
      launch_url: 'not a url', // 无效的 URL
      icons: []
    });
    ```

    **结果:** `ValidateDescription()` 会返回 "Invalid launch URL provided"，`add()` 方法会抛出一个 `TypeError` 异常。

3. **图标 URL 使用了不允许的协议 (例如 `data:`):**

    **错误代码:**

    ```javascript
    registration.contentIndex.add({
      // ...其他字段
      icons: [{ src: 'data:image/png;base64,...', sizes: '192x192', type: 'image/png' }]
    });
    ```

    **结果:** `ValidateDescription()` 会返回 "Invalid icon URL protocol"，因为只允许 HTTP(S) 协议。

4. **启动 URL 不在 Service Worker 的 scope 内:**

    **错误代码 (假设 Service Worker scope 是 `/app/`):**

    ```javascript
    registration.contentIndex.add({
      // ...其他字段
      launch_url: '/outside/scope'
    });
    ```

    **结果:** `ValidateDescription()` 会返回 "Launch URL must belong to the Service Worker's scope"。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户访问了一个安装了 Service Worker 的 Web 应用。**
2. **Web 应用的前端 JavaScript 代码调用了 `navigator.serviceWorker.register()` 来注册 Service Worker。**
3. **Service Worker 成功激活。**
4. **在 Service Worker 的生命周期内 (例如在 `install` 或 `activate` 事件中，或者在页面加载后的某个时刻)，JavaScript 代码调用了 `registration.contentIndex.add()` 来添加内容到索引。**
5. **浏览器接收到 `add()` 的调用，并最终调用 `blink::ContentIndex::add()` 方法。**
6. **在 `add()` 方法中，会进行参数校验，然后与浏览器进程中的 `ContentIndexService` 进行通信。**

**调试线索:**

*   **断点:** 可以在 `blink::ContentIndex::add()`, `ValidateDescription()`, `ContentIndexIconLoader::Start()`, 以及与 `ContentIndexService` 通信的相关代码中设置断点，来观察执行流程和变量值。
*   **日志:** 可以添加日志输出，记录 `ContentDescription` 的内容、校验结果、Mojo 消息的发送和接收等信息。
*   **Service Worker 控制台:** 查看 Service Worker 的控制台输出，可以了解是否有 JavaScript 异常抛出，以及 `add()`, `deleteDescription()`, `getDescriptions()` 方法的 Promise 是否 resolve 或 reject。
*   **浏览器内部页面:** Chromium 提供了 `chrome://serviceworker-internals` 页面，可以查看 Service Worker 的状态和注册信息。 虽然这个页面不直接显示 Content Index 的内容，但可以帮助确认 Service Worker 是否正常运行。
*   **Mojo Inspector:** 如果需要深入了解进程间通信，可以使用 Mojo Inspector 工具来查看 `ContentIndex` 相关的 Mojo 消息。

总而言之，`content_index.cc` 文件是 Chromium 中 `ContentIndex` API 的核心实现，它连接了 JavaScript API 和浏览器底层的 Content Index 服务，负责管理和验证待索引的内容，并处理图标加载等操作。 理解这个文件的功能对于调试和理解 Web 应用如何使用 `ContentIndex` API 至关重要。

### 提示词
```
这是目录为blink/renderer/modules/content_index/content_index.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/content_index/content_index.h"

#include <optional>

#include "base/task/sequenced_task_runner.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_content_icon_definition.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/content_index/content_description_type_converter.h"
#include "third_party/blink/renderer/modules/content_index/content_index_icon_loader.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_registration.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"

namespace blink {

namespace {

// Validates |description|. If there is an error, an error message to be passed
// to a TypeError is passed. Otherwise a null string is returned.
WTF::String ValidateDescription(const ContentDescription& description,
                                ServiceWorkerRegistration* registration) {
  // TODO(crbug.com/973844): Should field sizes be capped?

  if (description.id().empty())
    return "ID cannot be empty";

  if (description.title().empty())
    return "Title cannot be empty";

  if (description.description().empty())
    return "Description cannot be empty";

  if (description.url().empty())
    return "Invalid launch URL provided";

  for (const auto& icon : description.icons()) {
    if (icon->src().empty())
      return "Invalid icon URL provided";
    KURL icon_url =
        registration->GetExecutionContext()->CompleteURL(icon->src());
    if (!icon_url.ProtocolIsInHTTPFamily())
      return "Invalid icon URL protocol";
  }

  KURL launch_url =
      registration->GetExecutionContext()->CompleteURL(description.url());
  auto* security_origin =
      registration->GetExecutionContext()->GetSecurityOrigin();
  if (!security_origin->CanRequest(launch_url))
    return "Service Worker cannot request provided launch URL";

  if (!launch_url.GetString().StartsWith(registration->scope()))
    return "Launch URL must belong to the Service Worker's scope";

  return WTF::String();
}

}  // namespace

ContentIndex::ContentIndex(ServiceWorkerRegistration* registration,
                           scoped_refptr<base::SequencedTaskRunner> task_runner)
    : registration_(registration),
      task_runner_(std::move(task_runner)),
      content_index_service_(registration->GetExecutionContext()) {
  DCHECK(registration_);
}

ContentIndex::~ContentIndex() = default;

ScriptPromise<IDLUndefined> ContentIndex::add(
    ScriptState* script_state,
    const ContentDescription* description,
    ExceptionState& exception_state) {
  if (!registration_->active()) {
    exception_state.ThrowTypeError(
        "No active registration available on the ServiceWorkerRegistration.");
    return EmptyPromise();
  }

  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  if (execution_context->IsInFencedFrame()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "ContentIndex is not allowed in fenced frames.");
    return EmptyPromise();
  }

  WTF::String description_error =
      ValidateDescription(*description, registration_.Get());
  if (!description_error.IsNull()) {
    exception_state.ThrowTypeError(description_error);
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  auto mojo_description = mojom::blink::ContentDescription::From(description);
  auto category = mojo_description->category;
  GetService()->GetIconSizes(
      category,
      WTF::BindOnce(&ContentIndex::DidGetIconSizes, WrapPersistent(this),
                    std::move(mojo_description), WrapPersistent(resolver)));

  return promise;
}

void ContentIndex::DidGetIconSizes(
    mojom::blink::ContentDescriptionPtr description,
    ScriptPromiseResolver<IDLUndefined>* resolver,
    const Vector<gfx::Size>& icon_sizes) {
  if (!icon_sizes.empty() && description->icons.empty()) {
    resolver->RejectWithTypeError("icons must be provided");
    return;
  }

  if (!registration_->GetExecutionContext()) {
    // The SW execution context is not valid for some reason. Bail out.
    resolver->RejectWithTypeError("Service worker is no longer valid.");
    return;
  }

  if (icon_sizes.empty()) {
    DidGetIcons(resolver, std::move(description), /* icons= */ {});
    return;
  }

  auto* icon_loader = MakeGarbageCollected<ContentIndexIconLoader>();
  icon_loader->Start(
      registration_->GetExecutionContext(), std::move(description), icon_sizes,
      WTF::BindOnce(&ContentIndex::DidGetIcons, WrapPersistent(this),
                    WrapPersistent(resolver)));
}

void ContentIndex::DidGetIcons(ScriptPromiseResolver<IDLUndefined>* resolver,
                               mojom::blink::ContentDescriptionPtr description,
                               Vector<SkBitmap> icons) {
  for (const auto& icon : icons) {
    if (icon.isNull()) {
      resolver->RejectWithTypeError("Icon could not be loaded");
      return;
    }
  }

  if (!registration_->GetExecutionContext()) {
    // The SW execution context is not valid for some reason. Bail out.
    resolver->RejectWithTypeError("Service worker is no longer valid.");
    return;
  }

  KURL launch_url = registration_->GetExecutionContext()->CompleteURL(
      description->launch_url);

  GetService()->Add(
      registration_->RegistrationId(), std::move(description), icons,
      launch_url,
      WTF::BindOnce(&ContentIndex::DidAdd, WrapPersistent(resolver)));
}

void ContentIndex::DidAdd(ScriptPromiseResolver<IDLUndefined>* resolver,
                          mojom::blink::ContentIndexError error) {
  switch (error) {
    case mojom::blink::ContentIndexError::NONE:
      resolver->Resolve();
      return;
    case mojom::blink::ContentIndexError::STORAGE_ERROR:
      resolver->RejectWithDOMException(
          DOMExceptionCode::kAbortError,
          "Failed to add description due to I/O error.");
      return;
    case mojom::blink::ContentIndexError::INVALID_PARAMETER:
      // The renderer should have been killed.
      NOTREACHED();
    case mojom::blink::ContentIndexError::NO_SERVICE_WORKER:
      resolver->RejectWithTypeError("Service worker must be active");
      return;
  }
}

ScriptPromise<IDLUndefined> ContentIndex::deleteDescription(
    ScriptState* script_state,
    const String& id,
    ExceptionState& exception_state) {
  if (!registration_->active()) {
    exception_state.ThrowTypeError(
        "No active registration available on the ServiceWorkerRegistration.");
    return EmptyPromise();
  }

  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  if (execution_context->IsInFencedFrame()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "ContentIndex is not allowed in fenced frames.");
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  GetService()->Delete(registration_->RegistrationId(), id,
                       WTF::BindOnce(&ContentIndex::DidDeleteDescription,
                                     WrapPersistent(resolver)));

  return promise;
}

void ContentIndex::DidDeleteDescription(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    mojom::blink::ContentIndexError error) {
  switch (error) {
    case mojom::blink::ContentIndexError::NONE:
      resolver->Resolve();
      return;
    case mojom::blink::ContentIndexError::STORAGE_ERROR:
      resolver->RejectWithDOMException(
          DOMExceptionCode::kAbortError,
          "Failed to delete description due to I/O error.");
      return;
    case mojom::blink::ContentIndexError::INVALID_PARAMETER:
      // The renderer should have been killed.
      NOTREACHED();
    case mojom::blink::ContentIndexError::NO_SERVICE_WORKER:
      // This value shouldn't apply to this callback.
      NOTREACHED();
  }
}

ScriptPromise<IDLSequence<ContentDescription>> ContentIndex::getDescriptions(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!registration_->active()) {
    exception_state.ThrowTypeError(
        "No active registration available on the ServiceWorkerRegistration.");
    return ScriptPromise<IDLSequence<ContentDescription>>();
  }

  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  if (execution_context->IsInFencedFrame()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "ContentIndex is not allowed in fenced frames.");
    return ScriptPromise<IDLSequence<ContentDescription>>();
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLSequence<ContentDescription>>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  GetService()->GetDescriptions(registration_->RegistrationId(),
                                WTF::BindOnce(&ContentIndex::DidGetDescriptions,
                                              WrapPersistent(resolver)));

  return promise;
}

void ContentIndex::DidGetDescriptions(
    ScriptPromiseResolver<IDLSequence<ContentDescription>>* resolver,
    mojom::blink::ContentIndexError error,
    Vector<mojom::blink::ContentDescriptionPtr> descriptions) {
  HeapVector<Member<ContentDescription>> blink_descriptions;
  blink_descriptions.reserve(descriptions.size());
  for (const auto& description : descriptions)
    blink_descriptions.push_back(description.To<blink::ContentDescription*>());

  switch (error) {
    case mojom::blink::ContentIndexError::NONE:
      resolver->Resolve(std::move(blink_descriptions));
      return;
    case mojom::blink::ContentIndexError::STORAGE_ERROR:
      resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
          resolver->GetScriptState()->GetIsolate(),
          DOMExceptionCode::kAbortError,
          "Failed to get descriptions due to I/O error."));
      return;
    case mojom::blink::ContentIndexError::INVALID_PARAMETER:
      // The renderer should have been killed.
      NOTREACHED();
    case mojom::blink::ContentIndexError::NO_SERVICE_WORKER:
      // This value shouldn't apply to this callback.
      NOTREACHED();
  }
}

void ContentIndex::Trace(Visitor* visitor) const {
  visitor->Trace(registration_);
  visitor->Trace(content_index_service_);
  ScriptWrappable::Trace(visitor);
}

mojom::blink::ContentIndexService* ContentIndex::GetService() {
  if (!content_index_service_.is_bound()) {
    registration_->GetExecutionContext()
        ->GetBrowserInterfaceBroker()
        .GetInterface(
            content_index_service_.BindNewPipeAndPassReceiver(task_runner_));
  }
  return content_index_service_.get();
}

}  // namespace blink
```