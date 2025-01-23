Response:
Let's break down the thought process for analyzing the `global_fetch.cc` file.

1. **Understand the Core Purpose:** The filename `global_fetch.cc` and the presence of the `GlobalFetch` class immediately suggest that this file is responsible for implementing the global `fetch()` and `fetchLater()` JavaScript APIs within the Blink rendering engine. The "global" aspect implies it's accessible from various contexts (windows, workers).

2. **Identify Key Components:**  Scan the `#include` directives and the class definitions. This reveals the main players:
    * `GlobalFetch`: The public interface for accessing `fetch` and `fetchLater`.
    * `GlobalFetchImpl`:  The implementation details, likely templated for different global scopes.
    * `FetchManager`:  Handles the core fetch logic (network requests, caching, etc.).
    * `FetchLaterManager`:  Handles the delayed/background fetch functionality of `fetchLater`.
    * `Request`:  Represents a fetch request with its URL, headers, etc.
    * `Response`: Represents the server's response to a fetch request.
    * `ScriptPromise`:  Blink's representation of JavaScript Promises, crucial for the asynchronous nature of `fetch`.
    * `ExecutionContext`:  Represents the context in which JavaScript code is running (e.g., a window or worker).
    * `ExceptionState`:  For handling JavaScript exceptions.
    * `UseCounter`: For tracking usage of the `fetch` API.

3. **Analyze the `GlobalFetchImpl` Class:** This class seems to be the heart of the implementation. Notice the template parameter `T`, suggesting it can adapt to different global scope types (like `LocalDOMWindow` or `WorkerGlobalScope`).

    * **`From()` method:**  This static method implements the "supplement" pattern in Blink. It ensures that each relevant global scope gets its own instance of `GlobalFetchImpl`.
    * **Constructor:** Initializes the `FetchManager` and potentially the `FetchLaterManager` based on feature flags and the execution context.
    * **`Fetch()` method:**  This is the implementation of the global `fetch()` function. Key steps include:
        * Creating a `Request` object from the input arguments.
        * Calling `probe::WillSendXMLHttpOrFetchNetworkRequest` (indicating a network request is about to happen).
        * Passing the `Request` data to the `FetchManager`.
        * Returning a `ScriptPromise` that will resolve with the `Response`.
    * **`FetchLater()` method:** Implements the `fetchLater()` functionality, similar to `Fetch()` but using the `FetchLaterManager`. It also handles the `activateAfter` option.
    * **`FetchCount()`:**  A simple counter for tracking the number of `fetch()` calls.

4. **Analyze the `GlobalFetch` Static Methods:** These are the entry points called from JavaScript. They:
    * Obtain the appropriate `ScopedFetcher` (which is a `GlobalFetchImpl` instance).
    * Increment usage counters.
    * Call the corresponding methods on the `ScopedFetcher`.

5. **Connect to JavaScript, HTML, and CSS:**

    * **JavaScript:** The entire purpose of this code is to implement JavaScript's `fetch()` and `fetchLater()` APIs. The parameters and return types (`ScriptPromise`, `V8RequestInfo`, `RequestInit`, `Response`) directly correspond to how these APIs are used in JavaScript.
    * **HTML:** When JavaScript code embedded in an HTML document uses `fetch()`, the execution flow eventually leads to this C++ code. The same applies to service workers or web workers launched from HTML.
    * **CSS:**  While `fetch()` itself isn't directly related to CSS *rendering*, it can be used to dynamically load CSS stylesheets. For example, JavaScript might fetch a CSS file and then inject it into the document's `<head>`.

6. **Infer Logical Reasoning and Examples:**

    * **`Fetch()`:**  The code creates a `Request` object and then passes it to `FetchManager`. If the `Request` creation fails (e.g., invalid URL), an exception is thrown. The output is a `ScriptPromise` that represents the eventual `Response`.
    * **`FetchLater()`:** Similar to `Fetch()`, but with the added `activateAfter` parameter. The output is a `FetchLaterResult` object.

7. **Identify User/Programming Errors:**  Look for explicit error handling (throwing `TypeError`) and common issues related to the `fetch` API.

8. **Trace User Actions:** Think about the steps a user would take in a browser that would lead to this code being executed. This involves the user interacting with a webpage that uses `fetch()` or `fetchLater()`.

9. **Review and Refine:**  Go back through the analysis to ensure accuracy and completeness. Check for any missed details or potential misunderstandings. For example, the supplement pattern might require a bit more explanation. Consider the implications of the feature flag for `fetchLater`.

This structured approach helps to systematically dissect the code and understand its role within the larger Chromium/Blink architecture. The focus is on identifying the key components, their interactions, and their connection to the web platform's APIs.
好的，让我们来分析一下 `blink/renderer/core/fetch/global_fetch.cc` 文件的功能。

**核心功能：实现全局的 `fetch` 和 `fetchLater` API**

这个文件的主要职责是实现浏览器中全局可用的 `fetch` 和 `fetchLater` JavaScript API。这些 API 允许 JavaScript 代码发起网络请求。

**功能分解：**

1. **`GlobalFetch` 类和 `ScopedFetcher` 接口:**
   - `GlobalFetch` 提供静态方法 `fetch` 和 `fetchLater`，作为 JavaScript 调用这些 API 的入口。
   - `ScopedFetcher` 是一个抽象接口，定义了 `Fetch` 和 `FetchLater` 的行为。这是为了支持在不同的全局作用域（例如主窗口、Worker）中共享 `fetch` 功能。

2. **`GlobalFetchImpl` 类:**
   - 这是一个模板类，实现了 `ScopedFetcher` 接口。它使用模板参数 `T` 来适应不同的全局作用域类型（例如 `LocalDOMWindow` 或 `WorkerGlobalScope`）。
   - 它包含了 `FetchManager` 和 `FetchLaterManager` 的实例，分别负责处理常规的 `fetch` 请求和延迟的 `fetchLater` 请求。
   - **`Fetch()` 方法:**
     - 接收 JavaScript 传递的请求信息 (`V8RequestInfo`) 和初始化选项 (`RequestInit`)。
     - 创建一个 `Request` 对象来表示这个请求。
     - 调用 `probe::WillSendXMLHttpOrFetchNetworkRequest` 进行性能监控和调试。
     - 从 `Request` 对象中获取 `FetchRequestData`。
     - 调用 `MeasureFetchProperties` 记录一些关于请求属性的指标（例如重定向模式、缓存模式）。
     - 将请求传递给 `FetchManager` 的 `Fetch` 方法，由 `FetchManager` 负责实际的网络请求处理。
     - 返回一个 `ScriptPromise<Response>`，代表异步操作的结果。
   - **`FetchLater()` 方法:**
     - 类似于 `Fetch()` 方法，但用于处理 `fetchLater` API。
     - 它接收 `DeferredRequestInit` 作为初始化选项，允许设置 `activateAfter` 等延迟激活的参数。
     - 将请求传递给 `FetchLaterManager` 的 `FetchLater` 方法。
     - 返回一个 `FetchLaterResult` 对象，用于管理延迟请求。
   - **`FetchCount()` 方法:** 返回 `fetch()` 方法被调用的次数，用于统计。

3. **`MeasureFetchProperties()` 函数:**  记录 `fetch` 请求的一些属性，用于 Chromium 的使用情况统计（UseCounter）。例如，记录是否使用了 `redirect: 'error'` 或 `redirect: 'manual'` 以及缓存模式是否为 `no-cache`。

4. **Supplement 模式:**  `GlobalFetchImpl` 使用了 Blink 的 Supplement 模式，允许将功能添加到已有的对象（如 `LocalDOMWindow` 或 `WorkerGlobalScope`）。`From()` 静态方法负责获取或创建与特定全局对象关联的 `GlobalFetchImpl` 实例。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个文件直接关联到 JavaScript 的 `fetch` 和 `fetchLater` API，这些 API 是 Web 开发中非常核心的部分。

* **JavaScript:**
    ```javascript
    // 使用 fetch 发起一个 GET 请求
    fetch('https://example.com/data.json')
      .then(response => response.json())
      .then(data => console.log(data));

    // 使用 fetch 发起一个 POST 请求
    fetch('https://example.com/submit', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ key: 'value' })
    });

    // 使用 fetchLater 发起一个延迟请求
    fetchLater('https://example.com/background-task', { activateAfter: 5000 }); // 5秒后激活
    ```
    当你在 JavaScript 中调用 `fetch()` 或 `fetchLater()` 时，Blink 引擎内部会调用到这个文件中的 `GlobalFetch::fetch` 或 `GlobalFetch::fetchLater` 静态方法，然后进一步调用到 `GlobalFetchImpl` 对应的方法来处理请求。

* **HTML:**
    HTML 文件中嵌入的 `<script>` 标签中的 JavaScript 代码可以直接使用 `fetch` 和 `fetchLater` API。例如：
    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>Fetch Example</title>
    </head>
    <body>
      <script>
        fetch('/api/items')
          .then(response => response.json())
          .then(items => {
            // 在页面上显示 items
            console.log(items);
          });
      </script>
    </body>
    </html>
    ```

* **CSS:**
    虽然 `fetch` API 本身不直接操作 CSS 样式，但 JavaScript 可以使用 `fetch` 来动态加载 CSS 文件，或者从服务器获取 CSS 变量等。例如：
    ```javascript
    fetch('/styles.css')
      .then(response => response.text())
      .then(css => {
        const style = document.createElement('style');
        style.textContent = css;
        document.head.appendChild(style);
      });
    ```
    在这个例子中，`fetch` 用于获取 CSS 内容，然后将其添加到页面的 `<head>` 中。

**逻辑推理 (假设输入与输出):**

**假设输入 (针对 `Fetch()`):**

* **`script_state`:** 当前 JavaScript 执行上下文的状态。
* **`input`:** 一个字符串 URL 或一个 `Request` 对象，表示要请求的资源。例如: `"https://api.example.com/users"`。
* **`init`:** 一个可选的配置对象，包含请求的方法、头部、模式等。例如: `{ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"name": "John"}' }`。
* **`exception_state`:** 用于报告 JavaScript 异常的对象。

**输出 (针对 `Fetch()`):**

* **成功:** 返回一个 `ScriptPromise<Response>`，该 Promise 将在收到服务器响应后 resolve，并携带一个 `Response` 对象，包含响应的状态码、头部和内容。
* **失败:** 如果请求过程中发生错误（例如网络错误、CORS 问题），Promise 将 reject，`exception_state` 可能会记录异常信息。

**假设输入 (针对 `FetchLater()`):**

* **`script_state`:** 当前 JavaScript 执行上下文的状态。
* **`input`:** 一个字符串 URL 或一个 `Request` 对象。例如: `"/download/report"`。
* **`init`:** 一个可选的配置对象，包含请求的方法、头部，以及 `activateAfter` 属性（以毫秒为单位的延迟时间）。例如: `{ method: 'GET', activateAfter: 10000 }`。
* **`exception_state`:** 用于报告 JavaScript 异常的对象。

**输出 (针对 `FetchLater()`):**

* **成功:** 返回一个 `FetchLaterResult` 对象，该对象允许开发者管理和跟踪延迟的请求。
* **失败:** 如果参数无效或环境不支持 `fetchLater`，`exception_state` 可能会记录异常信息，返回 `nullptr`。

**用户或编程常见的使用错误举例说明：**

1. **CORS 错误:**
   - **场景:** JavaScript 代码尝试使用 `fetch` 请求一个不同源的资源，但服务器没有设置正确的 CORS 头部 (`Access-Control-Allow-Origin`)。
   - **用户操作:** 用户访问包含该 JavaScript 代码的网页。
   - **结果:**  `fetch` 请求失败，浏览器控制台会显示 CORS 相关的错误信息。`GlobalFetch::Fetch` 方法内部会将请求传递给网络层，网络层会根据 CORS 策略判断是否允许请求，如果被阻止，Promise 将会 reject。

2. **网络连接错误:**
   - **场景:** 用户的网络连接中断，或者请求的服务器无法访问。
   - **用户操作:** 用户在网络不稳定的情况下尝试访问网页或执行使用 `fetch` 的操作。
   - **结果:** `fetch` 请求会失败，Promise 会 reject，可能抛出 `TypeError: Failed to fetch` 类型的错误。

3. **无效的 URL:**
   - **场景:**  JavaScript 代码传递给 `fetch` 的 URL 是无效的。
   - **用户操作:** 用户可能点击了一个包含错误链接的按钮，或者应用的逻辑生成了错误的 URL。
   - **结果:** 在 `Request::Create` 阶段会抛出异常，`GlobalFetch::fetch` 方法会捕获这个异常并返回一个 rejected 的 Promise。

4. **在不支持 `fetchLater` 的环境中使用:**
   - **场景:** 在一个不支持 `fetchLater` API 的浏览器版本或 Worker 上尝试调用 `fetchLater`。
   - **编程错误:** 开发者没有进行特性检测就使用了 `fetchLater`。
   - **结果:** `GlobalFetch::fetchLater` 方法会检查 `blink::features::kFetchLaterAPI` 特性是否启用，如果未启用，会抛出一个 `TypeError`。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在浏览器中访问了一个网页，网页上有一个按钮，点击按钮后会使用 `fetch` API 从服务器获取数据并显示在页面上。

1. **用户操作:** 用户在浏览器中打开了包含相关 JavaScript 代码的 HTML 页面。
2. **用户操作:** 用户点击了页面上的按钮。
3. **JavaScript 执行:** 与按钮点击事件关联的 JavaScript 代码开始执行。
4. **`fetch` 调用:** JavaScript 代码中调用了 `fetch('/api/data')`。
5. **Blink 引擎处理:**
   - JavaScript 引擎 (V8) 将 `fetch` 调用传递给 Blink 渲染引擎。
   - Blink 引擎会找到 `globalThis.fetch` 的实现，即 `blink::GlobalFetch::fetch` 静态方法。
   - `blink::GlobalFetch::fetch` 方法会获取与当前全局作用域关联的 `GlobalFetchImpl` 实例。
   - `GlobalFetchImpl::Fetch` 方法会被调用，接收 URL 和可选的配置对象。
   - `GlobalFetchImpl::Fetch` 内部会创建 `Request` 对象，并调用 `FetchManager` 的 `Fetch` 方法来发起网络请求。
6. **网络请求:** `FetchManager` 会创建网络请求，发送到服务器。
7. **服务器响应:** 服务器返回响应数据。
8. **Blink 引擎处理响应:** `FetchManager` 接收到响应，创建一个 `Response` 对象。
9. **Promise resolve:** `GlobalFetchImpl::Fetch` 返回的 Promise 会 resolve，并将 `Response` 对象传递给 JavaScript 的 `then` 回调。
10. **JavaScript 处理响应:** JavaScript 代码的 `then` 回调函数被执行，处理服务器返回的数据并更新页面。

**调试线索:**

如果在调试过程中需要查看 `blink/renderer/core/fetch/global_fetch.cc` 的代码执行情况，可以设置断点在以下位置：

* `GlobalFetch::fetch` 和 `GlobalFetch::fetchLater` 静态方法：查看 JavaScript 调用 `fetch` 或 `fetchLater` 时是否到达这里。
* `GlobalFetchImpl::Fetch` 和 `GlobalFetchImpl::FetchLater` 方法：查看请求是如何被创建和传递的。
* `Request::Create`：查看 `Request` 对象是如何被创建的，是否有无效的参数导致异常。
* `FetchManager::Fetch` 和 `FetchLaterManager::FetchLater`：查看网络请求是如何被实际发起的。
* `MeasureFetchProperties`：查看请求属性的记录情况。

通过这些断点，开发者可以跟踪 `fetch` 或 `fetchLater` 请求的整个生命周期，了解请求参数、执行路径以及可能出现的错误。

总而言之，`blink/renderer/core/fetch/global_fetch.cc` 文件是 Blink 引擎中实现全局 `fetch` 和 `fetchLater` API 的关键组成部分，它负责接收来自 JavaScript 的请求，创建请求对象，并将其传递给底层的网络模块进行处理。理解这个文件的功能对于理解 Chromium 的网络请求机制至关重要。

### 提示词
```
这是目录为blink/renderer/core/fetch/global_fetch.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/fetch/global_fetch.h"

#include "base/feature_list.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_deferred_request_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_request_init.h"
#include "third_party/blink/renderer/core/execution_context/navigator_base.h"
#include "third_party/blink/renderer/core/fetch/fetch_later_result.h"
#include "third_party/blink/renderer/core/fetch/fetch_manager.h"
#include "third_party/blink/renderer/core/fetch/request.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/supplementable.h"

namespace blink {

namespace {

void MeasureFetchProperties(ExecutionContext* execution_context,
                            FetchRequestData* data) {
  // 'redirect' measurement
  if (data->Redirect() == network::mojom::RedirectMode::kError)
    UseCounter::Count(execution_context, WebFeature::kFetchRedirectError);
  else if (data->Redirect() == network::mojom::RedirectMode::kManual)
    UseCounter::Count(execution_context, WebFeature::kFetchRedirectManual);

  // 'cache' measurement: https://crbug.com/959789
  if (data->CacheMode() == mojom::FetchCacheMode::kBypassCache)
    UseCounter::Count(execution_context, WebFeature::kFetchCacheReload);
}

template <typename T>
class GlobalFetchImpl final : public GarbageCollected<GlobalFetchImpl<T>>,
                              public GlobalFetch::ScopedFetcher,
                              public Supplement<T> {
 public:
  static const char kSupplementName[];

  static ScopedFetcher* From(T& supplementable,
                             ExecutionContext* execution_context) {
    GlobalFetchImpl* supplement =
        Supplement<T>::template From<GlobalFetchImpl>(supplementable);
    if (!supplement) {
      supplement = MakeGarbageCollected<GlobalFetchImpl>(supplementable,
                                                         execution_context);
      Supplement<T>::ProvideTo(supplementable, supplement);
    }
    return supplement;
  }

  explicit GlobalFetchImpl(T& supplementable,
                           ExecutionContext* execution_context)
      : Supplement<T>(supplementable),
        fetch_manager_(MakeGarbageCollected<FetchManager>(execution_context)),
        // TODO(crbug.com/1356128): FetchLater is only supported in Document.
        fetch_later_manager_(
            base::FeatureList::IsEnabled(blink::features::kFetchLaterAPI) &&
                    execution_context->IsWindow()
                ? MakeGarbageCollected<FetchLaterManager>(execution_context)
                : nullptr) {}

  ScriptPromise<Response> Fetch(ScriptState* script_state,
                                const V8RequestInfo* input,
                                const RequestInit* init,
                                ExceptionState& exception_state) override {
    fetch_count_ += 1;

    ExecutionContext* execution_context = fetch_manager_->GetExecutionContext();
    if (!script_state->ContextIsValid() || !execution_context) {
      // TODO(yhirano): Should this be moved to bindings?
      exception_state.ThrowTypeError("The global scope is shutting down.");
      return EmptyPromise();
    }

    // "Let |r| be the associated request of the result of invoking the
    // initial value of Request as constructor with |input| and |init| as
    // arguments. If this throws an exception, reject |p| with it."
    Request* r = Request::Create(script_state, input, init, exception_state);
    if (exception_state.HadException())
      return EmptyPromise();

    probe::WillSendXMLHttpOrFetchNetworkRequest(execution_context, r->url());
    FetchRequestData* request_data =
        r->PassRequestData(script_state, exception_state);
    MeasureFetchProperties(execution_context, request_data);

    // Even if this was checked at the beginning of the function, it might
    // have been set to nullptr during Request::Create.
    if (!fetch_manager_->GetExecutionContext()) {
      exception_state.ThrowTypeError("The global scope is shutting down.");
      return EmptyPromise();
    }

    auto promise = fetch_manager_->Fetch(script_state, request_data,
                                         r->signal(), exception_state);
    if (exception_state.HadException())
      return EmptyPromise();

    return promise;
  }

  FetchLaterResult* FetchLater(ScriptState* script_state,
                               const V8RequestInfo* input,
                               const DeferredRequestInit* init,
                               ExceptionState& exception_state) override {
    if (!base::FeatureList::IsEnabled(blink::features::kFetchLaterAPI) ||
        !fetch_later_manager_) {
      exception_state.ThrowTypeError(
          "FetchLater is not supported in this scope.");
      return nullptr;
    }
    ExecutionContext* ec = fetch_later_manager_->GetExecutionContext();
    if (!script_state->ContextIsValid() || !ec) {
      exception_state.ThrowTypeError("The global scope is shutting down.");
      return nullptr;
    }

    // https://whatpr.org/fetch/1647.html#dom-global-fetch-later
    // Run the fetchLater(input, init) method steps:

    // 1. Let `r` be the result of invoking the initial value of Request as
    // constructor with `input` and `init` as arguments. This may throw an
    // exception.
    Request* r =
        Request::Create(script_state, input,
                        static_cast<const RequestInit*>(init), exception_state);
    if (exception_state.HadException()) {
      return nullptr;
    }

    probe::WillSendXMLHttpOrFetchNetworkRequest(ec, r->url());
    FetchRequestData* request_data =
        r->PassRequestData(script_state, exception_state);
    MeasureFetchProperties(ec, request_data);
    // 5. If init is given and init ["activateAfter"] exists, then set
    // `activate_after` to init ["activateAfter"].
    std::optional<DOMHighResTimeStamp> activate_after =
        (init->hasActivateAfter() ? std::make_optional(init->activateAfter())
                                  : std::nullopt);
    auto* result = fetch_later_manager_->FetchLater(script_state, request_data,
                                                    r->signal(), activate_after,
                                                    exception_state);
    if (exception_state.HadException()) {
      return nullptr;
    }

    return result;
  }

  uint32_t FetchCount() const override { return fetch_count_; }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(fetch_manager_);
    visitor->Trace(fetch_later_manager_);
    ScopedFetcher::Trace(visitor);
    Supplement<T>::Trace(visitor);
  }

 private:
  Member<FetchManager> fetch_manager_;
  Member<FetchLaterManager> fetch_later_manager_;
  uint32_t fetch_count_ = 0;
};

// static
template <typename T>
const char GlobalFetchImpl<T>::kSupplementName[] = "GlobalFetchImpl";

}  // namespace

GlobalFetch::ScopedFetcher::~ScopedFetcher() {}

FetchLaterResult* GlobalFetch::ScopedFetcher::FetchLater(
    ScriptState* script_state,
    const V8RequestInfo* input,
    const DeferredRequestInit* init,
    ExceptionState& exception_state) {
  NOTREACHED();
}

GlobalFetch::ScopedFetcher* GlobalFetch::ScopedFetcher::From(
    LocalDOMWindow& window) {
  return GlobalFetchImpl<LocalDOMWindow>::From(window,
                                               window.GetExecutionContext());
}

GlobalFetch::ScopedFetcher* GlobalFetch::ScopedFetcher::From(
    WorkerGlobalScope& worker) {
  return GlobalFetchImpl<WorkerGlobalScope>::From(worker,
                                                  worker.GetExecutionContext());
}

GlobalFetch::ScopedFetcher* GlobalFetch::ScopedFetcher::From(
    NavigatorBase& navigator) {
  return GlobalFetchImpl<NavigatorBase>::From(navigator,
                                              navigator.GetExecutionContext());
}

void GlobalFetch::ScopedFetcher::Trace(Visitor* visitor) const {}

ScriptPromise<Response> GlobalFetch::fetch(ScriptState* script_state,
                                           LocalDOMWindow& window,
                                           const V8RequestInfo* input,
                                           const RequestInit* init,
                                           ExceptionState& exception_state) {
  UseCounter::Count(window.GetExecutionContext(), WebFeature::kFetch);
  if (!window.GetFrame()) {
    exception_state.ThrowTypeError("The global scope is shutting down.");
    return EmptyPromise();
  }
  return ScopedFetcher::From(window)->Fetch(script_state, input, init,
                                            exception_state);
}

ScriptPromise<Response> GlobalFetch::fetch(ScriptState* script_state,
                                           WorkerGlobalScope& worker,
                                           const V8RequestInfo* input,
                                           const RequestInit* init,
                                           ExceptionState& exception_state) {
  UseCounter::Count(worker.GetExecutionContext(), WebFeature::kFetch);
  return ScopedFetcher::From(worker)->Fetch(script_state, input, init,
                                            exception_state);
}

FetchLaterResult* GlobalFetch::fetchLater(ScriptState* script_state,
                                          LocalDOMWindow& window,
                                          const V8RequestInfo* input,
                                          const DeferredRequestInit* init,
                                          ExceptionState& exception_state) {
  UseCounter::Count(window.GetExecutionContext(), WebFeature::kFetchLater);
  if (!window.GetFrame()) {
    exception_state.ThrowTypeError("The global scope is shutting down.");
    return nullptr;
  }
  return ScopedFetcher::From(window)->FetchLater(script_state, input, init,
                                                 exception_state);
}

}  // namespace blink
```