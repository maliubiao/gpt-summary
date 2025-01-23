Response:
Let's break down the thought process for analyzing this Chromium source code.

1. **Understand the Goal:** The request asks for a functional breakdown of the `permissions.cc` file, focusing on its role, interaction with web technologies (JavaScript, HTML, CSS), logical reasoning, potential errors, and debugging context.

2. **Initial Code Scan and Keyword Identification:**  Quickly skim the code, looking for recognizable keywords and structures. This immediately reveals:
    * `#include` statements: Indicate dependencies (other Blink components, standard libraries). Specifically, look for mentions of `javascript`, `html` (via DOM elements like `Document`, `Window`), and anything related to permissions.
    * Class declaration (`class Permissions`):  This is the core of the file.
    * Methods (`query`, `request`, `revoke`, `requestAll`): These are the primary actions the `Permissions` object can perform, and likely correspond to the JavaScript `navigator.permissions` API.
    * `ScriptPromise`:  Signals asynchronous operations and interaction with JavaScript promises.
    * `PermissionStatus`: Represents the state of a permission.
    * `PermissionDescriptor`:  Defines what permission is being requested.
    * `mojom::blink::PermissionService`: Suggests communication with a lower-level service (likely in the browser process) for handling permission logic.
    * `ExecutionContext`:  Indicates the context in which this code runs (e.g., a document, worker).
    * `NavigatorBase`: The object this `Permissions` class supplements, making it accessible via `navigator.permissions`.

3. **Identify Core Functionality (Based on Methods):**  The main methods strongly suggest the primary functions of this file:
    * `query()`:  Check the current status of a permission.
    * `request()`: Ask the user for a permission.
    * `revoke()`: Remove a previously granted permission (less common, but exists).
    * `requestAll()`: Request multiple permissions at once.

4. **Analyze Interactions with Web Technologies:**
    * **JavaScript:** The method signatures (`ScriptState* script_state`, `ScriptValue& raw_permission`, `ScriptPromise`) clearly show this code directly handles calls from JavaScript. The `navigator.permissions` API is the obvious connection. The examples provided in the initial thought process directly link these methods to their JavaScript counterparts.
    * **HTML:** The code checks for `LocalDOMWindow` and `Document` activity. This ties into the execution context within a web page. Permissions are often tied to specific documents or frames. The "active document" check in `query()` is a crucial link.
    * **CSS:**  While not directly manipulating CSS, permission status *can* influence styling. For example, a website might hide certain features if a camera permission is denied. This is an indirect relationship.

5. **Trace the Logical Flow (High-Level):**  When a JavaScript call to `navigator.permissions.query()`, `request()`, etc., occurs:
    1. The JavaScript call is routed to the corresponding `Permissions` class method in Blink.
    2. The input (permission descriptor) is parsed.
    3. The `Permissions` object communicates with the `PermissionService` (via Mojo IPC) to perform the actual permission check/request at the browser level.
    4. The `PermissionService` interacts with the operating system or user settings.
    5. The result is sent back to the `Permissions` object.
    6. The `Permissions` object resolves the JavaScript `Promise` with the `PermissionStatus`.

6. **Consider Logical Reasoning and Edge Cases:**
    * **`query()` and Document Activity:** The check for `document->IsActive()` is a crucial piece of logic. It prevents permission queries in inactive documents (like those in the back/forward cache), which makes sense because those documents aren't actively being displayed or interacted with. This is a good candidate for a "logical reasoning" example.
    * **`requestAll()` Optimization:** The `requestAll()` method's logic to avoid duplicate permission requests is an optimization. This can be described with a hypothetical input and output.
    * **Permission Verification:** The `VerifyPermissionsAndReturnStatus` and `PermissionVerificationComplete` methods handle a more complex scenario where the actual granted permission might be a more general version of the requested permission (e.g., requesting PTZ might result in general camera permission). This is another good example of internal logic.

7. **Think About User Errors and Debugging:**
    * **Incorrect Permission Name:**  A common user error is misspelling or using an invalid permission name. This would likely result in an exception during the parsing of the `PermissionDescriptor`.
    * **Calling `query()` in an inactive document:** This is explicitly handled by throwing an `InvalidStateError`.
    * **Debugging Flow:** Start from the JavaScript call, trace through the Blink code (`permissions.cc`), look for communication with the `PermissionService`, and then (if necessary) dive into the browser process's permission handling logic. Knowing the method names in `permissions.cc` helps set breakpoints effectively.

8. **Structure the Answer:** Organize the findings into logical sections as requested by the prompt:
    * Functionality Overview
    * Relationship to JavaScript, HTML, CSS (with examples)
    * Logical Reasoning (with assumptions and outputs)
    * Common Errors (with examples)
    * User Operation and Debugging

9. **Refine and Elaborate:**  Go back through each section and add details. Explain *why* certain things are happening. For example, don't just say "it calls the PermissionService," explain that it's for delegating the actual permission handling to the browser process. Make sure the examples are clear and illustrate the points.

10. **Review and Correct:** Read through the entire answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas where more detail might be needed. For instance, ensure the JavaScript examples directly correspond to the C++ methods.

This structured approach allows for a comprehensive analysis of the code, addressing all aspects of the original request. The key is to start with the big picture and gradually zoom in on the details, focusing on the interactions and purpose of the code within the larger Chromium ecosystem.
好的，我们来详细分析一下 `blink/renderer/modules/permissions/permissions.cc` 这个文件。

**文件功能概述**

`permissions.cc` 文件是 Chromium Blink 渲染引擎中实现 **Permissions API** 的核心部分。Permissions API 允许网页查询和请求用户授予对特定受保护功能的访问权限（例如，摄像头、麦克风、地理位置等）。

主要功能包括：

1. **实现 `navigator.permissions` 对象:**  该文件创建并管理 `navigator.permissions` 对象，这是 JavaScript 中访问 Permissions API 的入口点。
2. **处理权限查询 (`permissions.query()`):**  接收来自 JavaScript 的权限查询请求，并将请求传递给更底层的权限服务。接收权限服务的响应，并将其封装成 JavaScript Promise 返回。
3. **处理权限请求 (`permissions.request()`):** 接收来自 JavaScript 的权限请求，会触发浏览器向用户显示权限提示框。将请求传递给权限服务，并处理用户的授权/拒绝行为，最终将结果封装成 JavaScript Promise 返回。
4. **处理权限撤销 (`permissions.revoke()`):**  允许网页请求撤销之前授予的权限。同样，该请求会传递给权限服务。
5. **处理批量权限请求 (`permissions.requestAll()`):**  允许网页一次性请求多个权限。该方法会优化请求过程，避免重复请求相同的权限类型。
6. **管理 `PermissionStatus` 对象:**  创建和管理 `PermissionStatus` 对象，该对象表示特定权限的当前状态（`granted`、`denied` 或 `prompt`）。
7. **与底层权限服务通信:**  使用 Mojo IPC 与浏览器进程中的权限服务进行通信，以执行实际的权限检查和请求操作。
8. **处理权限状态变化:**  监听权限状态的变化，并通知相应的 `PermissionStatus` 对象，以便触发 JavaScript 中的 `change` 事件。
9. **生命周期管理:**  作为 `NavigatorBase` 的补充，管理自身的生命周期，并在相关对象销毁时进行清理。

**与 JavaScript, HTML, CSS 的关系**

这个文件是 JavaScript Permissions API 在 Blink 渲染引擎中的具体实现，因此与 JavaScript 的关系最为密切。

* **JavaScript:**
    * **`navigator.permissions.query(descriptor)`:**  在 JavaScript 中调用 `navigator.permissions.query()` 方法时，最终会调用到 `permissions.cc` 中的 `Permissions::query()` 方法。
        * **假设输入：** JavaScript 代码 `navigator.permissions.query({ name: 'camera' })`
        * **逻辑推理：**  `Permissions::query()` 方法会解析传入的 `descriptor` 对象，提取权限名称（'camera'），然后向权限服务发起查询请求。
        * **假设输出：**  `Permissions::query()` 方法会返回一个 JavaScript Promise，该 Promise 最终会 resolve 成一个 `PermissionStatus` 对象，表示摄像头权限的状态（例如，`{ state: 'granted' }`）。
    * **`navigator.permissions.request(descriptor)`:**  JavaScript 调用 `navigator.permissions.request()` 会触发 `Permissions::request()`。
        * **假设输入：** JavaScript 代码 `navigator.permissions.request({ name: 'geolocation' })`
        * **逻辑推理：** `Permissions::request()` 会解析权限描述符，并向权限服务发起请求，这通常会导致浏览器显示地理位置权限请求的提示框。
        * **假设输出：**  Promise 会 resolve 成一个 `PermissionStatus` 对象，其 `state` 属性反映了用户的授权结果（`'granted'` 或 `'denied'`）。
    * **`navigator.permissions.revoke(descriptor)`:** JavaScript 调用 `navigator.permissions.revoke()` 会触发 `Permissions::revoke()`。
        * **假设输入：** JavaScript 代码 `navigator.permissions.revoke({ name: 'notifications' })`
        * **逻辑推理：** `Permissions::revoke()` 会通知权限服务撤销通知权限。
        * **假设输出：** Promise 会 resolve 成一个表示撤销后状态的 `PermissionStatus` 对象。
    * **`navigator.permissions.requestAll(descriptors)`:** JavaScript 调用 `navigator.permissions.requestAll()` 会触发 `Permissions::requestAll()`。
        * **假设输入：** JavaScript 代码 `navigator.permissions.requestAll([{ name: 'camera' }, { name: 'microphone' }])`
        * **逻辑推理：** `Permissions::requestAll()` 会解析多个权限描述符，并尝试一次性请求这些权限。
        * **假设输出：** Promise 会 resolve 成一个包含多个 `PermissionStatus` 对象的数组，每个对象对应一个请求的权限。

* **HTML:**
    * Permissions API 的使用场景通常与用户在 HTML 页面上的交互相关。例如，一个网页上的按钮点击事件可能会触发 JavaScript 代码调用 `navigator.permissions.request()` 来请求摄像头权限，以便进行视频通话。
    * 该文件中的代码会检查当前的执行上下文是否是 `LocalDOMWindow` 对象，以及关联的 `Document` 是否处于活动状态。这是因为某些权限操作只能在活动的文档上下文中进行。
    * **用户操作如何到达这里：** 用户在 HTML 页面上与元素交互（例如点击按钮） -> 触发相应的 JavaScript 事件处理函数 ->  事件处理函数调用 `navigator.permissions.query()` 或 `navigator.permissions.request()`。

* **CSS:**
    * `permissions.cc` 文件本身并不直接操作 CSS。但是，Permissions API 的结果可能会间接地影响 CSS 样式。例如，如果用户拒绝了摄像头权限，网页可能会使用 JavaScript 动态地修改 CSS 类，隐藏或禁用与摄像头相关的功能按钮。

**逻辑推理的举例说明**

* **假设输入：**  用户在一个已经授予了麦克风权限的网页上，再次调用 `navigator.permissions.query({ name: 'microphone' })`。
* **逻辑推理：** `Permissions::query()` 方法会检查当前权限状态。由于麦克风权限已经授予，该方法会直接从本地或缓存中获取状态，而无需再次向用户请求。
* **假设输出：** 返回的 Promise 会立即 resolve 成一个 `PermissionStatus` 对象，其 `state` 属性为 `'granted'`。

* **假设输入：** 用户在一个 `<iframe>` 内的网页上请求地理位置权限，并且该 `<iframe>` 没有设置 `allow="geolocation"` 特性。
* **逻辑推理：**  `Permissions::request()` 方法在将请求传递给底层权限服务之前，可能会进行一些初步的权限策略检查。在这种情况下，由于 iframe 缺少必要的特性，权限请求可能会被立即拒绝。
* **假设输出：** 返回的 Promise 可能会 resolve 成一个 `PermissionStatus` 对象，其 `state` 属性为 `'denied'`，或者抛出一个异常。

**用户或编程常见的使用错误**

1. **在非安全上下文 (non-secure context) 中使用 Permissions API:** 许多强大的权限（如摄像头、麦克风）只能在 HTTPS 或 localhost 等安全上下文中请求。如果在 HTTP 页面上调用这些 API，可能会导致错误或功能失效。
    * **错误示例：** 在一个 `http://example.com` 的页面上调用 `navigator.permissions.request({ name: 'camera' })` 可能会导致 Promise 被 rejected。
2. **在 Document 不活跃时调用 `permissions.query()`:**  如果在一个文档已经处于非活动状态（例如，在浏览器的往返缓存中）时调用 `permissions.query()`，会抛出一个 `InvalidStateError` 异常。
    * **错误示例：** 用户点击浏览器的后退按钮，然后 JavaScript 尝试访问上一个页面的权限状态。
3. **权限名称拼写错误或使用不支持的权限名称:** 如果传入 `query()` 或 `request()` 的权限描述符中的 `name` 属性值不正确，会导致无法识别的权限请求。
    * **错误示例：** `navigator.permissions.request({ name: 'camara' })` (拼写错误)。
4. **忘记处理 Promise 的 rejected 状态:**  权限请求可能会被用户拒绝或因其他原因失败。开发者需要正确地处理 Promise 的 `catch` 分支，以优雅地处理这些情况。
    * **错误示例：** 只写了 `.then()`，没有写 `.catch()`，当权限被拒绝时，可能会导致未处理的 Promise rejection 错误。

**用户操作如何一步步的到达这里 (调试线索)**

假设用户在网页上点击了一个按钮，该按钮的功能是打开摄像头。

1. **用户操作:** 用户在浏览器中打开一个网页，并点击了页面上的一个“打开摄像头”按钮。
2. **JavaScript 事件处理:**  按钮的点击事件触发了预先注册的 JavaScript 事件处理函数。
3. **调用 Permissions API:** 在 JavaScript 事件处理函数中，代码调用了 `navigator.permissions.request({ name: 'camera' })`。
4. **Blink 渲染引擎处理:**  这个 JavaScript 调用被 Blink 渲染引擎接收。
5. **`Permissions::request()` 调用:**  Blink 将该调用路由到 `blink/renderer/modules/permissions/permissions.cc` 文件中的 `Permissions::request()` 方法。
6. **权限服务交互:** `Permissions::request()` 方法会创建一个权限请求消息，并通过 Mojo IPC 将其发送到浏览器进程的权限服务。
7. **浏览器进程处理:** 浏览器进程的权限服务接收到请求，可能会显示权限提示框给用户。
8. **用户授权/拒绝:** 用户在提示框中选择“允许”或“拒绝”。
9. **权限服务响应:** 浏览器进程的权限服务将用户的选择结果发送回 Blink 渲染引擎。
10. **`Permissions` 对象处理响应:** `Permissions::request()` 方法接收到权限服务的响应。
11. **Promise 解析:**  `Permissions::request()` 方法根据响应结果解析最初的 JavaScript Promise，将其 resolve 为 `granted` 或 `denied` 状态的 `PermissionStatus` 对象。
12. **JavaScript 回调:**  JavaScript 中 `navigator.permissions.request()` 返回的 Promise 的 `.then()` 或 `.catch()` 回调函数被执行，从而处理权限请求的结果。

**调试线索:**

* 在 Chrome 开发者工具的 "Sources" 面板中，可以设置断点在 JavaScript 调用 `navigator.permissions.request()` 的地方，查看调用栈。
* 可以在 `permissions.cc` 文件中的 `Permissions::query()`、`Permissions::request()` 等方法入口处设置断点，观察代码的执行流程和变量的值。
* 可以使用 Chrome 提供的内部 URL `chrome://permissions` 来查看当前网站的权限状态。
* 可以检查浏览器的控制台，查看是否有与权限相关的错误或警告信息。
* 可以使用 `// Copyright 2014 The Chromium Authors` 等注释信息，在 Chromium 源代码中搜索相关代码，深入了解其实现细节。

希望以上分析能够帮助你理解 `blink/renderer/modules/permissions/permissions.cc` 文件的功能和作用。

### 提示词
```
这是目录为blink/renderer/modules/permissions/permissions.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/permissions/permissions.h"

#include <memory>
#include <utility>

#include "base/metrics/histogram_functions.h"
#include "base/time/time.h"
#include "third_party/blink/public/common/permissions/permission_utils.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_permission_descriptor.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/navigator_base.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/modules/permissions/permission_status.h"
#include "third_party/blink/renderer/modules/permissions/permission_utils.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

namespace blink {

using mojom::blink::PermissionDescriptorPtr;
using mojom::blink::PermissionName;
using mojom::blink::PermissionService;

// static
const char Permissions::kSupplementName[] = "Permissions";

// static
Permissions* Permissions::permissions(NavigatorBase& navigator) {
  Permissions* supplement =
      Supplement<NavigatorBase>::From<Permissions>(navigator);
  if (!supplement) {
    supplement = MakeGarbageCollected<Permissions>(navigator);
    ProvideTo(navigator, supplement);
  }
  return supplement;
}

Permissions::Permissions(NavigatorBase& navigator)
    : Supplement<NavigatorBase>(navigator),
      ExecutionContextLifecycleObserver(navigator.GetExecutionContext()),
      service_(navigator.GetExecutionContext()) {}

ScriptPromise<PermissionStatus> Permissions::query(
    ScriptState* script_state,
    const ScriptValue& raw_permission,
    ExceptionState& exception_state) {
  // https://www.w3.org/TR/permissions/#query-method
  // If this's relevant global object is a Window object, and if the current
  // settings object's associated Document is not fully active, return a promise
  // rejected with an "InvalidStateError" DOMException.
  auto* context = ExecutionContext::From(script_state);
  if (auto* window = DynamicTo<LocalDOMWindow>(context)) {
    auto* document = window->document();
    if (document && !document->IsActive()) {
      // It's impossible for Permissions.query to occur while in BFCache.
      if (document->GetPage()) {
        DCHECK(!document->GetPage()
                    ->GetPageLifecycleState()
                    ->is_in_back_forward_cache);
      }
      exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                        "The document is not active");
      return EmptyPromise();
    }
  }

  PermissionDescriptorPtr descriptor =
      ParsePermissionDescriptor(script_state, raw_permission, exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<PermissionStatus>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  // If the current origin is a file scheme, it will unlikely return a
  // meaningful value because most APIs are broken on file scheme and no
  // permission prompt will be shown even if the returned permission will most
  // likely be "prompt".
  PermissionDescriptorPtr descriptor_copy = descriptor->Clone();
  base::TimeTicks query_start_time;
  GetService(context)->HasPermission(
      std::move(descriptor),
      WTF::BindOnce(&Permissions::QueryTaskComplete, WrapPersistent(this),
                    WrapPersistent(resolver), std::move(descriptor_copy),
                    query_start_time));
  return promise;
}

ScriptPromise<PermissionStatus> Permissions::request(
    ScriptState* script_state,
    const ScriptValue& raw_permission,
    ExceptionState& exception_state) {
  PermissionDescriptorPtr descriptor =
      ParsePermissionDescriptor(script_state, raw_permission, exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  ExecutionContext* context = ExecutionContext::From(script_state);

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<PermissionStatus>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  PermissionDescriptorPtr descriptor_copy = descriptor->Clone();
  LocalDOMWindow* window = DynamicTo<LocalDOMWindow>(context);
  LocalFrame* frame = window ? window->GetFrame() : nullptr;

  GetService(context)->RequestPermission(
      std::move(descriptor), LocalFrame::HasTransientUserActivation(frame),
      WTF::BindOnce(&Permissions::VerifyPermissionAndReturnStatus,
                    WrapPersistent(this), WrapPersistent(resolver),
                    std::move(descriptor_copy)));
  return promise;
}

ScriptPromise<PermissionStatus> Permissions::revoke(
    ScriptState* script_state,
    const ScriptValue& raw_permission,
    ExceptionState& exception_state) {
  PermissionDescriptorPtr descriptor =
      ParsePermissionDescriptor(script_state, raw_permission, exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<PermissionStatus>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  PermissionDescriptorPtr descriptor_copy = descriptor->Clone();
  GetService(ExecutionContext::From(script_state))
      ->RevokePermission(
          std::move(descriptor),
          WTF::BindOnce(&Permissions::TaskComplete, WrapPersistent(this),
                        WrapPersistent(resolver), std::move(descriptor_copy)));
  return promise;
}

ScriptPromise<IDLSequence<PermissionStatus>> Permissions::requestAll(
    ScriptState* script_state,
    const HeapVector<ScriptValue>& raw_permissions,
    ExceptionState& exception_state) {
  Vector<PermissionDescriptorPtr> internal_permissions;
  Vector<int> caller_index_to_internal_index;
  caller_index_to_internal_index.resize(raw_permissions.size());

  ExecutionContext* context = ExecutionContext::From(script_state);

  for (wtf_size_t i = 0; i < raw_permissions.size(); ++i) {
    const ScriptValue& raw_permission = raw_permissions[i];

    auto descriptor = ParsePermissionDescriptor(script_state, raw_permission,
                                                exception_state);
    if (exception_state.HadException())
      return ScriptPromise<IDLSequence<PermissionStatus>>();

    // Only append permissions types that are not already present in the vector.
    wtf_size_t internal_index = kNotFound;
    for (wtf_size_t j = 0; j < internal_permissions.size(); ++j) {
      if (internal_permissions[j]->name == descriptor->name) {
        internal_index = j;
        break;
      }
    }
    if (internal_index == kNotFound) {
      internal_index = internal_permissions.size();
      internal_permissions.push_back(std::move(descriptor));
    }
    caller_index_to_internal_index[i] = internal_index;
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLSequence<PermissionStatus>>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  Vector<PermissionDescriptorPtr> internal_permissions_copy;
  internal_permissions_copy.reserve(internal_permissions.size());
  for (const auto& descriptor : internal_permissions)
    internal_permissions_copy.push_back(descriptor->Clone());

  LocalDOMWindow* window = DynamicTo<LocalDOMWindow>(context);
  LocalFrame* frame = window ? window->GetFrame() : nullptr;

  GetService(context)->RequestPermissions(
      std::move(internal_permissions),
      LocalFrame::HasTransientUserActivation(frame),
      WTF::BindOnce(
          &Permissions::VerifyPermissionsAndReturnStatus, WrapPersistent(this),
          WrapPersistent(resolver), std::move(internal_permissions_copy),
          std::move(caller_index_to_internal_index),
          -1 /* last_verified_permission_index */, true /* is_bulk_request */));
  return promise;
}

void Permissions::ContextDestroyed() {
  base::UmaHistogramCounts1000("Permissions.API.CreatedPermissionStatusObjects",
                               created_permission_status_objects_);
}

void Permissions::Trace(Visitor* visitor) const {
  visitor->Trace(service_);
  visitor->Trace(listeners_);
  ScriptWrappable::Trace(visitor);
  Supplement<NavigatorBase>::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

PermissionService* Permissions::GetService(
    ExecutionContext* execution_context) {
  if (!service_.is_bound()) {
    ConnectToPermissionService(
        execution_context,
        service_.BindNewPipeAndPassReceiver(
            execution_context->GetTaskRunner(TaskType::kPermission)));
    service_.set_disconnect_handler(WTF::BindOnce(
        &Permissions::ServiceConnectionError, WrapWeakPersistent(this)));
  }
  return service_.get();
}

void Permissions::ServiceConnectionError() {
  service_.reset();
}
void Permissions::QueryTaskComplete(
    ScriptPromiseResolver<PermissionStatus>* resolver,
    mojom::blink::PermissionDescriptorPtr descriptor,
    base::TimeTicks query_start_time,
    mojom::blink::PermissionStatus result) {
  base::UmaHistogramTimes("Permissions.Query.QueryResponseTime",
                          base::TimeTicks::Now() - query_start_time);
  TaskComplete(resolver, std::move(descriptor), result);
}

void Permissions::TaskComplete(
    ScriptPromiseResolver<PermissionStatus>* resolver,
    mojom::blink::PermissionDescriptorPtr descriptor,
    mojom::blink::PermissionStatus result) {
  if (!resolver->GetExecutionContext() ||
      resolver->GetExecutionContext()->IsContextDestroyed())
    return;

  PermissionStatusListener* listener =
      GetOrCreatePermissionStatusListener(result, std::move(descriptor));
  if (listener)
    resolver->Resolve(PermissionStatus::Take(listener, resolver));
}

void Permissions::VerifyPermissionAndReturnStatus(
    ScriptPromiseResolverBase* resolver,
    mojom::blink::PermissionDescriptorPtr descriptor,
    mojom::blink::PermissionStatus result) {
  Vector<int> caller_index_to_internal_index;
  caller_index_to_internal_index.push_back(0);
  Vector<mojom::blink::PermissionStatus> results;
  results.push_back(std::move(result));
  Vector<mojom::blink::PermissionDescriptorPtr> descriptors;
  descriptors.push_back(std::move(descriptor));

  VerifyPermissionsAndReturnStatus(resolver, std::move(descriptors),
                                   std::move(caller_index_to_internal_index),
                                   -1 /* last_verified_permission_index */,
                                   false /* is_bulk_request */,
                                   std::move(results));
}

void Permissions::VerifyPermissionsAndReturnStatus(
    ScriptPromiseResolverBase* resolver,
    Vector<mojom::blink::PermissionDescriptorPtr> descriptors,
    Vector<int> caller_index_to_internal_index,
    int last_verified_permission_index,
    bool is_bulk_request,
    const Vector<mojom::blink::PermissionStatus>& results) {
  DCHECK(caller_index_to_internal_index.size() == 1u || is_bulk_request);
  DCHECK_EQ(descriptors.size(), caller_index_to_internal_index.size());

  if (!resolver->GetExecutionContext() ||
      resolver->GetExecutionContext()->IsContextDestroyed())
    return;

  // Create the response vector by finding the status for each index by
  // using the caller to internal index mapping and looking up the status
  // using the internal index obtained.
  HeapVector<Member<PermissionStatus>> result;
  result.ReserveInitialCapacity(caller_index_to_internal_index.size());
  for (int internal_index : caller_index_to_internal_index) {
    // If there is a chance that this permission result came from a different
    // permission type (e.g. a PTZ request could be replaced with a camera
    // request internally), then re-check the actual permission type to ensure
    // that it it indeed that permission type. If it's not, replace the
    // descriptor with the verification descriptor.
    auto verification_descriptor = CreatePermissionVerificationDescriptor(
        *GetPermissionType(*descriptors[internal_index]));
    if (last_verified_permission_index == -1 && verification_descriptor) {
      auto descriptor_copy = descriptors[internal_index]->Clone();
      service_->HasPermission(
          std::move(descriptor_copy),
          WTF::BindOnce(&Permissions::PermissionVerificationComplete,
                        WrapPersistent(this), WrapPersistent(resolver),
                        std::move(descriptors),
                        std::move(caller_index_to_internal_index),
                        std::move(results), std::move(verification_descriptor),
                        internal_index, is_bulk_request));
      return;
    }

    // This is the last permission that was verified.
    if (internal_index == last_verified_permission_index)
      last_verified_permission_index = -1;

    PermissionStatusListener* listener = GetOrCreatePermissionStatusListener(
        results[internal_index], descriptors[internal_index]->Clone());
    if (listener) {
      // If it's not a bulk request, return the first (and only) result.
      if (!is_bulk_request) {
        resolver->DowncastTo<PermissionStatus>()->Resolve(
            PermissionStatus::Take(listener, resolver));
        return;
      }
      result.push_back(PermissionStatus::Take(listener, resolver));
    }
  }
  resolver->DowncastTo<IDLSequence<PermissionStatus>>()->Resolve(result);
}

void Permissions::PermissionVerificationComplete(
    ScriptPromiseResolverBase* resolver,
    Vector<mojom::blink::PermissionDescriptorPtr> descriptors,
    Vector<int> caller_index_to_internal_index,
    const Vector<mojom::blink::PermissionStatus>& results,
    mojom::blink::PermissionDescriptorPtr verification_descriptor,
    int internal_index_to_verify,
    bool is_bulk_request,
    mojom::blink::PermissionStatus verification_result) {
  if (verification_result != results[internal_index_to_verify]) {
    // The permission actually came from the verification descriptor, so use
    // that descriptor when returning the permission status.
    descriptors[internal_index_to_verify] = std::move(verification_descriptor);
  }

  VerifyPermissionsAndReturnStatus(resolver, std::move(descriptors),
                                   std::move(caller_index_to_internal_index),
                                   internal_index_to_verify, is_bulk_request,
                                   std::move(results));
}

PermissionStatusListener* Permissions::GetOrCreatePermissionStatusListener(
    mojom::blink::PermissionStatus status,
    mojom::blink::PermissionDescriptorPtr descriptor) {
  auto type = GetPermissionType(*descriptor);
  if (!type)
    return nullptr;

  if (!listeners_.Contains(*type)) {
    listeners_.insert(
        *type, PermissionStatusListener::Create(*this, GetExecutionContext(),
                                                status, std::move(descriptor)));
  } else {
    listeners_.at(*type)->SetStatus(status);
  }

  return listeners_.at(*type);
}

std::optional<PermissionType> Permissions::GetPermissionType(
    const mojom::blink::PermissionDescriptor& descriptor) {
  return PermissionDescriptorInfoToPermissionType(
      descriptor.name,
      descriptor.extension && descriptor.extension->is_midi() &&
          descriptor.extension->get_midi()->sysex,
      descriptor.extension && descriptor.extension->is_camera_device() &&
          descriptor.extension->get_camera_device()->panTiltZoom,
      descriptor.extension && descriptor.extension->is_clipboard() &&
          descriptor.extension->get_clipboard()->will_be_sanitized,
      descriptor.extension && descriptor.extension->is_clipboard() &&
          descriptor.extension->get_clipboard()->has_user_gesture,
      descriptor.extension && descriptor.extension->is_fullscreen() &&
          descriptor.extension->get_fullscreen()->allow_without_user_gesture);
}

mojom::blink::PermissionDescriptorPtr
Permissions::CreatePermissionVerificationDescriptor(
    PermissionType descriptor_type) {
  if (descriptor_type == PermissionType::CAMERA_PAN_TILT_ZOOM) {
    return CreateVideoCapturePermissionDescriptor(false /* pan_tilt_zoom */);
  }
  return nullptr;
}

}  // namespace blink
```