Response:
Let's break down the thought process for analyzing the `DocumentStorageAccess.cc` file.

**1. Initial Understanding - The "What"**

* **File Location:** The path `blink/renderer/modules/storage_access/document_storage_access.cc` immediately tells us this file is part of the Blink rendering engine, specifically related to "storage access."  The "modules" directory suggests it's an API exposed to web developers.
* **Copyright Header:**  The standard Chromium copyright header confirms it's a Chromium file.
* **Includes:** The `#include` statements are the first clue to the file's dependencies and purpose:
    * `base/metrics/histogram_functions.h`:  Indicates the file records metrics about its usage.
    * `net/storage_access_api/status.h`: Suggests interaction with the network stack and a defined "storage access API."
    * `services/metrics/public/cpp/ukm_builders.h`: Another metrics component, likely for more detailed user behavior tracking.
    * `third_party/blink/public/mojom/permissions/...`:  Strongly implies interaction with the Permissions API. The `.mojom` suffix indicates inter-process communication definitions.
    * `third_party/blink/renderer/bindings/...`: Points to the file's role in exposing functionality to JavaScript. Keywords like "bindings," "v8," "ScriptPromise," and "IDL" are key here.
    * `third_party/blink/renderer/core/inspector/console_message.h`: Shows the file can output messages to the browser's developer console.
    * `third_party/blink/renderer/core/loader/cookie_jar.h`:  Confirms involvement with cookie handling.
    * `third_party/blink/renderer/modules/storage_access/storage_access_handle.h`:  Suggests the file creates or manages `StorageAccessHandle` objects.

**2. Core Functionality - The "Why"**

Based on the includes and the file name, the central purpose is to manage how web pages request and obtain access to storage (specifically cookies and potentially other storage mechanisms) in a cross-site context. The "Document" part of the name implies this functionality is exposed on the `document` object in JavaScript.

**3. Key Methods - The "How"**

Scanning the class definition and its methods reveals the primary functionalities:

* **`hasStorageAccess()`:**  A method to check if the current document already has storage access. This is synchronous in its implementation but returns a `ScriptPromise`, indicating it might involve asynchronous checks in the background.
* **`requestStorageAccess()`:** The core function to request storage access. There are overloaded versions: one without arguments (implicitly requesting unpartitioned cookie access) and one taking a `StorageAccessTypes` object (allowing granular control over requested storage types). This uses the Permissions API.
* **`requestStorageAccessFor()`:**  A method specifically for requesting *top-level* storage access for a given site. This appears to be a more privileged operation, likely used in specific scenarios.
* **Internal Helper Methods:** The `RequestStorageAccessImpl` and `Process...PermissionState` methods are internal logic for handling the asynchronous permission requests and resolving the promises.

**4. Relationship to Web Technologies - The "Connections"**

* **JavaScript:** The methods are clearly exposed to JavaScript. The use of `ScriptPromise` is a direct indicator. The static methods called from JavaScript directly invoke the instance methods.
* **HTML:**  The functionality is triggered by JavaScript code within an HTML document. The state of the document (e.g., active, secure context, embedded in a frame) influences the outcome.
* **CSS:**  Less directly related to CSS, but the presence of fenced frames (mentioned in the code) can influence the behavior, and fenced frames are styled with CSS. However, the core logic isn't directly about CSS.

**5. Logical Reasoning and Examples - The "Scenarios"**

* **`hasStorageAccess()`:**  A simple check. If the document is in a secure context and cookies are enabled, it returns `true`. Otherwise, `false`.
* **`requestStorageAccess()` (basic):** User gesture is crucial. If the user interacts with an iframe and the iframe calls `document.requestStorageAccess()`, the browser will likely prompt the user for permission.
* **`requestStorageAccess()` (with `StorageAccessTypes`):** This allows more specific requests. For instance, an iframe might only need access to `localStorage` and not cookies.
* **`requestStorageAccessFor()`:** This is top-level-initiated. The main frame might call this to request access to the storage of a specific embedded iframe's origin.

**6. Common Errors - The "Gotchas"**

* **No User Gesture:**  Crucial for `requestStorageAccess()`. Without it, the request will fail.
* **Insecure Context:**  Both `hasStorageAccess()` and `requestStorageAccess()` require a secure context (HTTPS).
* **Opaque Origins:** Pages with opaque origins cannot request storage access.
* **Incorrect Frame:** `requestStorageAccessFor()` can only be called from the top-level frame.
* **Invalid Origin:** Providing an invalid or opaque origin to `requestStorageAccessFor()` will lead to errors.
* **Requesting No Access:** The `StorageAccessTypes` version of `requestStorageAccess()` requires specifying at least one type of storage.

**7. Debugging - The "Path"**

The debugging section focuses on how a developer might end up at this specific code:

* **JavaScript Call:**  The most direct way is a JavaScript call to `document.hasStorageAccess()`, `document.requestStorageAccess()`, or `document.requestStorageAccessFor()`.
* **Permissions API Interaction:** The code heavily relies on the Permissions API. If a permission request is being processed, this code might be involved.
* **Cookie Handling:**  Since cookie access is a primary concern, any interaction with cookies in a cross-site context could potentially lead here.
* **Developer Tools:** Using the browser's developer tools to step through JavaScript code, set breakpoints, or inspect network requests related to cookies can lead to this code.

**8. Iteration and Refinement:**

The initial analysis might be somewhat high-level. As you examine the code more closely, you'd refine your understanding:

* **Metrics:** Realize the importance of the UMA and UKM metrics for tracking API usage and potential issues.
* **Error Handling:** Notice the consistent use of `DOMException` for reporting errors to JavaScript.
* **Security Checks:** Appreciate the various security checks in place (secure context, opaque origins, sandboxing, etc.).
* **Fenced Frames:**  Understand the specific handling of storage access requests within fenced frames.

By following this thought process, combining code analysis with knowledge of web technologies and debugging techniques, one can effectively understand the functionality and purpose of a complex source code file like `DocumentStorageAccess.cc`.
好的，让我们详细分析一下 `blink/renderer/modules/storage_access/document_storage_access.cc` 这个文件。

**文件功能总览**

这个文件实现了 Blink 渲染引擎中 `DocumentStorageAccess` 接口的功能。这个接口主要负责处理网页请求跨站点存储访问权限的逻辑。简单来说，它允许在一个网站的上下文中运行的脚本请求访问另一个网站的存储（例如 Cookie、localStorage、IndexedDB 等）。

**核心功能点：**

1. **`hasStorageAccess()`**:
   - **功能:**  检查当前文档是否已经拥有未分区 (unpartitioned) 的存储访问权限。
   - **实现逻辑:**  它会检查文档的激活状态、Origin 是否透明、是否在安全上下文 (HTTPS)、顶层 Origin 是否透明等条件，最终通过检查 `CookiesEnabled()` 来判断是否拥有权限。
   - **与 Web 技术的关系:**
     - **JavaScript:**  此方法直接暴露给 JavaScript，可以通过 `document.hasStorageAccess()` 调用。
     - **HTML:**  此方法在 HTML 文档的上下文中执行，检查的是当前文档的一些属性。
   - **假设输入与输出:**
     - **假设输入:**  一个嵌入在 HTTPS 页面中的 iframe，且该 iframe 的顶层页面也是 HTTPS。
     - **预期输出:**  如果用户之前已经授予了该 iframe 所在的源站存储访问权限，则返回 `true` 的 Promise；否则，返回 `false` 的 Promise。

2. **`requestStorageAccess()` (无参数版本)**:
   - **功能:** 请求未分区的 Cookie 访问权限。
   - **实现逻辑:**  它会进行一系列安全检查（是否激活、是否安全上下文、Origin 是否透明、是否在沙箱中等），然后调用 Permission API 请求 `storage-access` 权限。
   - **与 Web 技术的关系:**
     - **JavaScript:**  通过 `document.requestStorageAccess()` 调用。
     - **HTML:**  在 HTML 文档的上下文中触发权限请求。
   - **假设输入与输出:**
     - **假设输入:**  用户在 HTTPS 页面中点击一个按钮，该按钮触发一个嵌入的 iframe 调用 `document.requestStorageAccess()`。
     - **预期输出:**
       - 如果用户之前没有拒绝过该 iframe 所在源站的存储访问请求，并且浏览器允许，则会弹出一个权限提示框。
       - 如果用户授予权限，Promise 将 resolve。
       - 如果用户拒绝权限或由于其他原因无法授予权限，Promise 将 reject。

3. **`requestStorageAccess()` (带 `StorageAccessTypes` 参数版本)**:
   - **功能:**  请求对指定类型的存储介质的访问权限。
   - **实现逻辑:**  与无参数版本类似，但可以更精细地控制请求的存储类型（例如，只请求 `localStorage`，不请求 Cookie）。它同样会调用 Permission API 请求 `storage-access` 权限。
   - **与 Web 技术的关系:**
     - **JavaScript:**  通过 `document.requestStorageAccess({ cookies: true, localStorage: true })` 这样的方式调用。
     - **HTML:**  在 HTML 文档的上下文中触发权限请求。
   - **假设输入与输出:**
     - **假设输入:**  一个嵌入的 iframe 调用 `document.requestStorageAccess({ localStorage: true })`。
     - **预期输出:**  与无参数版本类似，但权限请求的范围可能更窄，只针对 `localStorage`。

4. **`hasUnpartitionedCookieAccess()`**:
   - **功能:**  这是 `hasStorageAccess()` 的一个别名，专门用于检查未分区的 Cookie 访问权限。
   - **实现逻辑:**  直接调用 `hasStorageAccess()`。

5. **`requestStorageAccessFor()`**:
   - **功能:**  允许顶层文档请求访问特定站点 (site) 的存储权限。这个方法只能在顶层文档中使用。
   - **实现逻辑:**  进行安全检查后，会调用 Permission API 请求 `top-level-storage-access` 权限，并传递目标站点的 Origin。
   - **与 Web 技术的关系:**
     - **JavaScript:**  通过 `document.requestStorageAccessFor('https://example.com')` 调用。
     - **HTML:**  只能在顶层 HTML 文档的上下文中调用。
   - **假设输入与输出:**
     - **假设输入:**  在 `https://main.com` 页面中，JavaScript 代码调用 `document.requestStorageAccessFor('https://iframe.com')`。
     - **预期输出:**
       - 如果 `https://main.com` 和 `https://iframe.com` 不是同源的，且用户之前没有拒绝过该请求，则会弹出一个权限提示框，询问用户是否允许 `https://main.com` 访问 `https://iframe.com` 的存储。
       - 如果用户授权，Promise 将 resolve。
       - 如果用户拒绝或由于其他原因无法授权，Promise 将 reject。

**用户或编程常见的使用错误举例说明:**

1. **在非用户激活的情况下调用 `requestStorageAccess()`:**
   - **错误场景:**  一个 iframe 在 `onload` 事件中立即调用 `document.requestStorageAccess()`。
   - **后果:**  浏览器会阻止该请求，因为缺乏用户的手势来发起权限请求。
   - **JavaScript 代码示例:**
     ```javascript
     // iframe 的代码
     window.onload = function() {
       document.requestStorageAccess(); // 可能会失败
     };
     ```
   - **调试线索:**  浏览器的控制台会输出类似 "requestStorageAccess: Requires user activation." 的错误信息。`FireRequestStorageAccessHistogram` 函数会记录 `REJECTED_NO_USER_GESTURE`。

2. **在不安全的上下文中调用 `requestStorageAccess()`:**
   - **错误场景:**  在一个通过 HTTP 加载的页面中调用 `document.requestStorageAccess()`。
   - **后果:**  浏览器会阻止该请求，因为存储访问权限通常只在安全上下文 (HTTPS) 中授予。
   - **JavaScript 代码示例:**
     ```javascript
     // 在 http://example.com/ 页面中
     document.requestStorageAccess(); // 将会失败
     ```
   - **调试线索:**  浏览器的控制台会输出类似 "requestStorageAccess: May not be used in an insecure context." 的错误信息。`FireRequestStorageAccessHistogram` 函数会记录 `REJECTED_INSECURE_CONTEXT`。

3. **在 iframe 中调用 `requestStorageAccessFor()`:**
   - **错误场景:**  在一个 iframe 中调用 `document.requestStorageAccessFor()`。
   - **后果:**  浏览器会阻止该请求，因为 `requestStorageAccessFor()` 只能在顶层文档中使用。
   - **JavaScript 代码示例:**
     ```javascript
     // 在 iframe 中
     document.requestStorageAccessFor('https://another-site.com'); // 将会失败
     ```
   - **调试线索:**  浏览器的控制台会输出类似 "requestStorageAccessFor: Only supported in primary top-level browsing contexts." 的错误信息。`FireRequestStorageAccessForMetrics` 函数会记录 `REJECTED_INCORRECT_FRAME`。

4. **传递无效的 Origin 给 `requestStorageAccessFor()`:**
   - **错误场景:**  调用 `document.requestStorageAccessFor()` 时，传递一个格式错误的字符串或者一个 opaque 的 Origin。
   - **后果:**  请求会被拒绝。
   - **JavaScript 代码示例:**
     ```javascript
     document.requestStorageAccessFor('invalid-origin'); // 将会失败
     document.requestStorageAccessFor('null'); // 将会失败 (opaque origin)
     ```
   - **调试线索:**  浏览器的控制台会输出类似 "requestStorageAccessFor: Invalid origin." 或 "requestStorageAccessFor: Invalid origin parameter." 的错误信息。`FireRequestStorageAccessForMetrics` 函数会记录 `REJECTED_INVALID_ORIGIN` 或 `REJECTED_OPAQUE_ORIGIN`。

5. **`requestStorageAccess()` 请求了 0 个类型的存储介质:**
    - **错误场景:** 使用 `requestStorageAccess` 的对象参数版本时，没有指定任何需要访问的存储类型。
    - **后果:**  `requestStorageAccess` 会抛出一个 `SecurityError` 异常。
    - **JavaScript 代码示例:**
      ```javascript
      document.requestStorageAccess({}); // 将会抛出异常
      ```
    - **调试线索:** 浏览器的控制台会显示一个 `SecurityError` 异常，消息为 "You must request access for at least one storage/communication medium."

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户正在浏览一个网页 `https://main.com`，该页面嵌入了一个来自 `https://iframe.com` 的 iframe。

1. **用户访问 `https://main.com`。**
2. **`https://main.com` 中的 JavaScript 代码动态创建或加载了来自 `https://iframe.com` 的 iframe。**
3. **在 `https://iframe.com` 的页面加载完成后，其内部的 JavaScript 代码尝试请求存储访问权限：**
   - **场景 1 (调用 `document.requestStorageAccess()`):**
     ```javascript
     // 在 https://iframe.com 的页面中
     document.requestStorageAccess().then(() => {
       console.log('Storage access granted!');
     }).catch(() => {
       console.error('Storage access denied.');
     });
     ```
   - **场景 2 (调用 `document.requestStorageAccessFor()`):**
     ```javascript
     // 这段代码在 iframe 中执行会失败，但如果错误地放置在这里就会触发相关逻辑
     document.requestStorageAccessFor('https://another-site.com').then(() => {
       console.log('Storage access for another site granted!');
     }).catch(() => {
       console.error('Storage access for another site denied.');
     });
     ```
   - **场景 3 (顶层页面调用 `document.requestStorageAccessFor()`):**
     ```javascript
     // 在 https://main.com 的页面中
     iframeElement.contentDocument.requestStorageAccessFor('https://iframe.com').then(() => {
       console.log('Top-level storage access granted!');
     }).catch(() => {
       console.error('Top-level storage access denied.');
     });
     ```
4. **Blink 渲染引擎在执行到 `document.requestStorageAccess()` 或 `document.requestStorageAccessFor()` 时，会调用 `DocumentStorageAccess` 类的相应静态方法 (`requestStorageAccess()` 或 `requestStorageAccessFor()`)。**
5. **这些静态方法会获取 `DocumentStorageAccess` 的实例，并调用实例方法来处理实际的逻辑，包括安全检查、权限请求等。**
6. **如果需要请求权限，Blink 会与浏览器的权限管理系统交互，可能会弹出权限提示框给用户。**
7. **用户在权限提示框中的操作（允许或拒绝）会影响 Promise 的 resolve 或 reject。**
8. **`FireRequestStorageAccessHistogram` 和 `FireRequestStorageAccessForMetrics` 等函数会被调用，记录 API 的使用情况和结果，用于 Telemetry 数据收集。**
9. **如果出现错误，例如不安全上下文或缺乏用户激活，会调用 `AddConsoleMessage` 将错误信息输出到开发者控制台。**

**总结:**

`DocumentStorageAccess.cc` 是 Blink 引擎中负责处理跨站点存储访问请求的核心组件。它通过 JavaScript API 暴露功能，并与浏览器的权限管理系统紧密集成，确保用户对存储访问的控制。理解这个文件的功能对于理解浏览器的隐私和安全机制至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/storage_access/document_storage_access.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/storage_access/document_storage_access.h"

#include "base/metrics/histogram_functions.h"
#include "net/storage_access_api/status.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "third_party/blink/public/mojom/permissions/permission.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions/permission_status.mojom-blink-forward.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_storage_access_types.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/cookie_jar.h"
#include "third_party/blink/renderer/modules/storage_access/storage_access_handle.h"

namespace blink {

namespace {

// This enum must match the numbering for RequestStorageResult in
// histograms/enums.xml. Do not reorder or remove items, only add new items
// at the end.
//
// This enum is used by both requestStorageAccess and requestStorageAccessFor
// for but there is no guarantee that every enum value is used by each method.
enum class RequestStorageResult {
  APPROVED_EXISTING_ACCESS = 0,
  // APPROVED_NEW_GRANT = 1,
  REJECTED_NO_USER_GESTURE = 2,
  REJECTED_NO_ORIGIN = 3,
  REJECTED_OPAQUE_ORIGIN = 4,
  REJECTED_EXISTING_DENIAL = 5,
  REJECTED_SANDBOXED = 6,
  REJECTED_GRANT_DENIED = 7,
  REJECTED_INCORRECT_FRAME = 8,
  REJECTED_INSECURE_CONTEXT = 9,
  APPROVED_PRIMARY_FRAME = 10,
  REJECTED_CREDENTIALLESS_IFRAME = 11,
  APPROVED_NEW_OR_EXISTING_GRANT = 12,
  REJECTED_FENCED_FRAME = 13,
  REJECTED_INVALID_ORIGIN = 14,
  kMaxValue = REJECTED_INVALID_ORIGIN,
};

void FireRequestStorageAccessHistogram(RequestStorageResult result) {
  base::UmaHistogramEnumeration("API.StorageAccess.RequestStorageAccess2",
                                result);
}

void FireRequestStorageAccessForMetrics(RequestStorageResult result,
                                        ExecutionContext* context) {
  base::UmaHistogramEnumeration(
      "API.TopLevelStorageAccess.RequestStorageAccessFor2", result);

  CHECK(context);

  ukm::builders::RequestStorageAccessFor_RequestStorageResult(
      context->UkmSourceID())
      .SetRequestStorageResult(static_cast<int64_t>(result))
      .Record(context->UkmRecorder());
}

}  // namespace

// static
const char DocumentStorageAccess::kNoAccessRequested[] =
    "You must request access for at least one storage/communication medium.";

// static
const char DocumentStorageAccess::kSupplementName[] = "DocumentStorageAccess";

// static
DocumentStorageAccess& DocumentStorageAccess::From(Document& document) {
  DocumentStorageAccess* supplement =
      Supplement<Document>::From<DocumentStorageAccess>(document);
  if (!supplement) {
    supplement = MakeGarbageCollected<DocumentStorageAccess>(document);
    ProvideTo(document, supplement);
  }
  return *supplement;
}

// static
ScriptPromise<IDLBoolean> DocumentStorageAccess::hasStorageAccess(
    ScriptState* script_state,
    Document& document) {
  return From(document).hasStorageAccess(script_state);
}

// static
ScriptPromise<IDLUndefined> DocumentStorageAccess::requestStorageAccess(
    ScriptState* script_state,
    Document& document) {
  return From(document).requestStorageAccess(script_state);
}

// static
ScriptPromise<StorageAccessHandle> DocumentStorageAccess::requestStorageAccess(
    ScriptState* script_state,
    Document& document,
    const StorageAccessTypes* storage_access_types) {
  return From(document).requestStorageAccess(script_state,
                                             storage_access_types);
}

// static
ScriptPromise<IDLBoolean> DocumentStorageAccess::hasUnpartitionedCookieAccess(
    ScriptState* script_state,
    Document& document) {
  return From(document).hasUnpartitionedCookieAccess(script_state);
}

// static
ScriptPromise<IDLUndefined> DocumentStorageAccess::requestStorageAccessFor(
    ScriptState* script_state,
    Document& document,
    const AtomicString& site) {
  return From(document).requestStorageAccessFor(script_state, site);
}

DocumentStorageAccess::DocumentStorageAccess(Document& document)
    : Supplement<Document>(document) {}

void DocumentStorageAccess::Trace(Visitor* visitor) const {
  Supplement<Document>::Trace(visitor);
}

ScriptPromise<IDLBoolean> DocumentStorageAccess::hasStorageAccess(
    ScriptState* script_state) {
  // See
  // https://privacycg.github.io/storage-access/#dom-document-hasstorageaccess
  // for the steps implemented here.

  // Step #2: if doc is not fully active, reject p with an InvalidStateError and
  // return p.
  if (!GetSupplementable()->GetFrame()) {
    // Note that in detached frames, resolvers are not able to return a promise.
    return ScriptPromise<IDLBoolean>::RejectWithDOMException(
        script_state, MakeGarbageCollected<DOMException>(
                          DOMExceptionCode::kInvalidStateError,
                          "hasStorageAccess: Cannot be used unless the "
                          "document is fully active."));
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(script_state);
  auto promise = resolver->Promise();
  resolver->Resolve([&]() -> bool {
    // #3: if doc's origin is opaque, return false.
    if (GetSupplementable()
            ->GetExecutionContext()
            ->GetSecurityOrigin()
            ->IsOpaque()) {
      return false;
    }

    // #?: if window.credentialless is true, return false.
    if (GetSupplementable()->dom_window_->credentialless()) {
      return false;
    }

    // #5: if global is not a secure context, return false.
    if (!GetSupplementable()->dom_window_->isSecureContext()) {
      return false;
    }

    // #6: if the top-level origin of doc's relevant settings object is an
    // opaque origin, return false.
    if (GetSupplementable()->TopFrameOrigin()->IsOpaque()) {
      return false;
    }

    // #7 - #10: checks unpartitioned cookie availability with global's `has
    // storage access`.
    return GetSupplementable()->CookiesEnabled();
  }());
  return promise;
}

ScriptPromise<IDLUndefined> DocumentStorageAccess::requestStorageAccess(
    ScriptState* script_state) {
  // Requesting storage access via `requestStorageAccess()` idl always requests
  // unpartitioned cookie access.
  return RequestStorageAccessImpl(
      script_state,
      /*request_unpartitioned_cookie_access=*/true,
      WTF::BindOnce([](ScriptPromiseResolver<IDLUndefined>* resolver) {
        DCHECK(resolver);
        resolver->Resolve();
      }));
}

ScriptPromise<StorageAccessHandle> DocumentStorageAccess::requestStorageAccess(
    ScriptState* script_state,
    const StorageAccessTypes* storage_access_types) {
  if (!storage_access_types->all() && !storage_access_types->cookies() &&
      !storage_access_types->sessionStorage() &&
      !storage_access_types->localStorage() &&
      !storage_access_types->indexedDB() && !storage_access_types->locks() &&
      !storage_access_types->caches() &&
      !storage_access_types->getDirectory() &&
      !storage_access_types->estimate() &&
      !storage_access_types->createObjectURL() &&
      !storage_access_types->revokeObjectURL() &&
      !storage_access_types->broadcastChannel() &&
      !storage_access_types->sharedWorker()) {
    return ScriptPromise<StorageAccessHandle>::RejectWithDOMException(
        script_state, MakeGarbageCollected<DOMException>(
                          DOMExceptionCode::kSecurityError,
                          DocumentStorageAccess::kNoAccessRequested));
  }
  return RequestStorageAccessImpl(
      script_state,
      /*request_unpartitioned_cookie_access=*/storage_access_types->all() ||
          storage_access_types->cookies(),
      WTF::BindOnce(
          [](LocalDOMWindow* window,
             const StorageAccessTypes* storage_access_types,
             ScriptPromiseResolver<StorageAccessHandle>* resolver) {
            if (!window) {
                return;
            }
            DCHECK(storage_access_types);
            DCHECK(resolver);
            resolver->Resolve(MakeGarbageCollected<StorageAccessHandle>(
                *window, storage_access_types));
          },
          WrapWeakPersistent(GetSupplementable()->domWindow()),
          WrapPersistent(storage_access_types)));
}

ScriptPromise<IDLBoolean> DocumentStorageAccess::hasUnpartitionedCookieAccess(
    ScriptState* script_state) {
  return hasStorageAccess(script_state);
}

template <typename T>
ScriptPromise<T> DocumentStorageAccess::RequestStorageAccessImpl(
    ScriptState* script_state,
    bool request_unpartitioned_cookie_access,
    base::OnceCallback<void(ScriptPromiseResolver<T>*)> on_resolve) {
  if (!GetSupplementable()->GetFrame()) {
    FireRequestStorageAccessHistogram(RequestStorageResult::REJECTED_NO_ORIGIN);

    // Note that in detached frames, resolvers are not able to return a promise.
    return ScriptPromise<T>::RejectWithDOMException(
        script_state, MakeGarbageCollected<DOMException>(
                          DOMExceptionCode::kInvalidStateError,
                          "requestStorageAccess: Cannot be used unless the "
                          "document is fully active."));
  }

  if (GetSupplementable()->cookie_jar_) {
    // Storage access might be about to change in which case the ability for
    // |cookie_jar_| to retrieve values might also. Invalidate its cache in case
    // that happens so it can't return data that shouldn't be accessible.
    GetSupplementable()->cookie_jar_->InvalidateCache();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<T>>(script_state);

  // Access the promise first to ensure it is created so that the proper state
  // can be changed when it is resolved or rejected.
  auto promise = resolver->Promise();

  if (!GetSupplementable()->dom_window_->isSecureContext()) {
    GetSupplementable()->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        ConsoleMessage::Source::kSecurity, ConsoleMessage::Level::kError,
        "requestStorageAccess: May not be used in an insecure context."));
    FireRequestStorageAccessHistogram(
        RequestStorageResult::REJECTED_INSECURE_CONTEXT);

    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kNotAllowedError,
        "requestStorageAccess not allowed"));
    return promise;
  }

  if (GetSupplementable()->IsInOutermostMainFrame()) {
    FireRequestStorageAccessHistogram(
        RequestStorageResult::APPROVED_PRIMARY_FRAME);

    // If this is the outermost frame we no longer need to make a request and
    // can resolve the promise.
    resolver->Resolve();
    return promise;
  }

  if (GetSupplementable()->dom_window_->GetSecurityOrigin()->IsOpaque()) {
    GetSupplementable()->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        ConsoleMessage::Source::kSecurity, ConsoleMessage::Level::kError,
        "requestStorageAccess: Cannot be used by opaque origins."));
    FireRequestStorageAccessHistogram(
        RequestStorageResult::REJECTED_OPAQUE_ORIGIN);

    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kNotAllowedError,
        "requestStorageAccess not allowed"));
    return promise;
  }

  if (GetSupplementable()->dom_window_->credentialless()) {
    GetSupplementable()->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        ConsoleMessage::Source::kSecurity, ConsoleMessage::Level::kError,
        "requestStorageAccess: May not be used in a credentialless iframe"));
    FireRequestStorageAccessHistogram(
        RequestStorageResult::REJECTED_CREDENTIALLESS_IFRAME);

    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kNotAllowedError,
        "requestStorageAccess not allowed"));
    return promise;
  }

  if (GetSupplementable()->dom_window_->IsSandboxed(
          network::mojom::blink::WebSandboxFlags::
              kStorageAccessByUserActivation)) {
    GetSupplementable()->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        ConsoleMessage::Source::kSecurity, ConsoleMessage::Level::kError,
        GetSupplementable()->dom_window_->GetFrame()->IsInFencedFrameTree()
            ? "requestStorageAccess: Refused to execute request. The document "
              "is in a fenced frame tree."
            : "requestStorageAccess: Refused to execute request. The document "
              "is sandboxed, and the 'allow-storage-access-by-user-activation' "
              "keyword is not set."));

    FireRequestStorageAccessHistogram(
        GetSupplementable()->dom_window_->GetFrame()->IsInFencedFrameTree()
            ? RequestStorageResult::REJECTED_FENCED_FRAME
            : RequestStorageResult::REJECTED_SANDBOXED);

    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kNotAllowedError,
        "requestStorageAccess not allowed"));
    return promise;
  }
  if (RuntimeEnabledFeatures::FedCmWithStorageAccessAPIEnabled(
          GetSupplementable()->GetExecutionContext()) &&
      GetSupplementable()->GetExecutionContext()->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kIdentityCredentialsGet)) {
    UseCounter::Count(GetSupplementable()->GetExecutionContext(),
                      WebFeature::kFedCmWithStorageAccessAPI);
  }
  // RequestPermission may return `GRANTED` without actually creating a
  // permission grant if cookies are already accessible.
  auto descriptor = mojom::blink::PermissionDescriptor::New();
  descriptor->name = mojom::blink::PermissionName::STORAGE_ACCESS;
  GetSupplementable()
      ->GetPermissionService(ExecutionContext::From(resolver->GetScriptState()))
      ->RequestPermission(
          std::move(descriptor),
          LocalFrame::HasTransientUserActivation(
              GetSupplementable()->GetFrame()),
          WTF::BindOnce(
              &DocumentStorageAccess::ProcessStorageAccessPermissionState<T>,
              WrapPersistent(this), WrapPersistent(resolver),
              request_unpartitioned_cookie_access, std::move(on_resolve)));

  return promise;
}

template <typename T>
void DocumentStorageAccess::ProcessStorageAccessPermissionState(
    ScriptPromiseResolver<T>* resolver,
    bool request_unpartitioned_cookie_access,
    base::OnceCallback<void(ScriptPromiseResolver<T>*)> on_resolve,
    mojom::blink::PermissionStatus status) {
  DCHECK(resolver);

  ScriptState* script_state = resolver->GetScriptState();
  DCHECK(script_state);
  ScriptState::Scope scope(script_state);

  // document could be no longer alive.
  if (!GetSupplementable()->dom_window_) {
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kNotAllowedError,
        "document shutdown"));
    return;
  }

  if (status == mojom::blink::PermissionStatus::GRANTED) {
    FireRequestStorageAccessHistogram(
        RequestStorageResult::APPROVED_NEW_OR_EXISTING_GRANT);
    if (request_unpartitioned_cookie_access) {
      GetSupplementable()->dom_window_->SetStorageAccessApiStatus(
          net::StorageAccessApiStatus::kAccessViaAPI);
    }
    std::move(on_resolve).Run(resolver);
  } else {
    LocalFrame::ConsumeTransientUserActivation(GetSupplementable()->GetFrame());
    FireRequestStorageAccessHistogram(
        RequestStorageResult::REJECTED_GRANT_DENIED);
    GetSupplementable()->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        ConsoleMessage::Source::kSecurity, ConsoleMessage::Level::kError,
        "requestStorageAccess: Permission denied."));
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kNotAllowedError,
        "requestStorageAccess not allowed"));
  }
}

ScriptPromise<IDLUndefined> DocumentStorageAccess::requestStorageAccessFor(
    ScriptState* script_state,
    const AtomicString& origin) {
  if (!GetSupplementable()->GetFrame()) {
    FireRequestStorageAccessForMetrics(RequestStorageResult::REJECTED_NO_ORIGIN,
                                       ExecutionContext::From(script_state));
    // Note that in detached frames, resolvers are not able to return a promise.
    return ScriptPromise<IDLUndefined>::RejectWithDOMException(
        script_state, MakeGarbageCollected<DOMException>(
                          DOMExceptionCode::kInvalidStateError,
                          "requestStorageAccessFor: Cannot be used unless "
                          "the document is fully active."));
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);

  // Access the promise first to ensure it is created so that the proper state
  // can be changed when it is resolved or rejected.
  auto promise = resolver->Promise();

  if (!GetSupplementable()->IsInOutermostMainFrame()) {
    GetSupplementable()->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        ConsoleMessage::Source::kSecurity, ConsoleMessage::Level::kError,
        "requestStorageAccessFor: Only supported in primary top-level "
        "browsing contexts."));
    // RequestStorageResult values that only make sense from within an iframe
    // are recorded as REJECTED_INCORRECT_FRAME.
    FireRequestStorageAccessForMetrics(
        RequestStorageResult::REJECTED_INCORRECT_FRAME,
        ExecutionContext::From(script_state));
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kNotAllowedError,
        "requestStorageAccessFor not allowed"));
    return promise;
  }

  if (GetSupplementable()->dom_window_->GetSecurityOrigin()->IsOpaque()) {
    GetSupplementable()->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        ConsoleMessage::Source::kSecurity, ConsoleMessage::Level::kError,
        "requestStorageAccessFor: Cannot be used by opaque origins."));

    FireRequestStorageAccessForMetrics(
        RequestStorageResult::REJECTED_OPAQUE_ORIGIN,
        ExecutionContext::From(script_state));
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kNotAllowedError,
        "requestStorageAccessFor not allowed"));
    return promise;
  }

  // `requestStorageAccessFor` must be rejected for any given iframe. In
  // particular, it must have been rejected by credentialless iframes:
  CHECK(!GetSupplementable()->dom_window_->credentialless());

  if (!GetSupplementable()->dom_window_->isSecureContext()) {
    GetSupplementable()->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        ConsoleMessage::Source::kSecurity, ConsoleMessage::Level::kError,
        "requestStorageAccessFor: May not be used in an insecure "
        "context."));
    FireRequestStorageAccessForMetrics(
        RequestStorageResult::REJECTED_INSECURE_CONTEXT,
        ExecutionContext::From(script_state));

    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kNotAllowedError,
        "requestStorageAccessFor not allowed"));
    return promise;
  }

  KURL origin_as_kurl{origin};
  if (!origin_as_kurl.IsValid()) {
    GetSupplementable()->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        ConsoleMessage::Source::kSecurity, ConsoleMessage::Level::kError,
        "requestStorageAccessFor: Invalid origin."));
    FireRequestStorageAccessForMetrics(
        RequestStorageResult::REJECTED_INVALID_ORIGIN,
        ExecutionContext::From(script_state));
    resolver->Reject(V8ThrowException::CreateTypeError(
        script_state->GetIsolate(), "Invalid origin"));
    return promise;
  }

  scoped_refptr<SecurityOrigin> supplied_origin =
      SecurityOrigin::Create(origin_as_kurl);
  if (supplied_origin->IsOpaque()) {
    GetSupplementable()->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        ConsoleMessage::Source::kSecurity, ConsoleMessage::Level::kError,
        "requestStorageAccessFor: Invalid origin parameter."));
    FireRequestStorageAccessForMetrics(
        RequestStorageResult::REJECTED_OPAQUE_ORIGIN,
        ExecutionContext::From(script_state));
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kNotAllowedError,
        "requestStorageAccessFor not allowed"));
    return promise;
  }

  if (GetSupplementable()->dom_window_->GetSecurityOrigin()->IsSameSiteWith(
          supplied_origin.get())) {
    // Access is not actually disabled, so accept the request.
    resolver->Resolve();
    FireRequestStorageAccessForMetrics(
        RequestStorageResult::APPROVED_EXISTING_ACCESS,
        ExecutionContext::From(script_state));
    return promise;
  }

  auto descriptor = mojom::blink::PermissionDescriptor::New();
  descriptor->name = mojom::blink::PermissionName::TOP_LEVEL_STORAGE_ACCESS;
  auto top_level_storage_access_extension =
      mojom::blink::TopLevelStorageAccessPermissionDescriptor::New();
  top_level_storage_access_extension->requestedOrigin = supplied_origin;
  descriptor->extension =
      mojom::blink::PermissionDescriptorExtension::NewTopLevelStorageAccess(
          std::move(top_level_storage_access_extension));

  GetSupplementable()
      ->GetPermissionService(ExecutionContext::From(script_state))
      ->RequestPermission(
          std::move(descriptor),
          LocalFrame::HasTransientUserActivation(
              GetSupplementable()->GetFrame()),
          WTF::BindOnce(&DocumentStorageAccess::
                            ProcessTopLevelStorageAccessPermissionState,
                        WrapPersistent(this), WrapPersistent(resolver)));

  return promise;
}

void DocumentStorageAccess::ProcessTopLevelStorageAccessPermissionState(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    mojom::blink::PermissionStatus status) {
  DCHECK(resolver);
  DCHECK(GetSupplementable()->GetFrame());
  ScriptState* script_state = resolver->GetScriptState();
  DCHECK(script_state);
  ScriptState::Scope scope(script_state);

  if (status == mojom::blink::PermissionStatus::GRANTED) {
    FireRequestStorageAccessForMetrics(
        RequestStorageResult::APPROVED_NEW_OR_EXISTING_GRANT,
        ExecutionContext::From(script_state));
    resolver->Resolve();
  } else {
    LocalFrame::ConsumeTransientUserActivation(GetSupplementable()->GetFrame());
    FireRequestStorageAccessForMetrics(
        RequestStorageResult::REJECTED_GRANT_DENIED,
        ExecutionContext::From(script_state));
    GetSupplementable()->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        ConsoleMessage::Source::kSecurity, ConsoleMessage::Level::kError,
        "requestStorageAccessFor: Permission denied."));
    resolver->Reject(V8ThrowDOMException::CreateOrEmpty(
        script_state->GetIsolate(), DOMExceptionCode::kNotAllowedError,
        "requestStorageAccessFor not allowed"));
  }
}

}  // namespace blink

"""

```