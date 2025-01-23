Response:
Let's break down the thought process to analyze the `BackgroundFetchRegistration.cc` file.

1. **Understand the Goal:** The core request is to understand the functionality of this specific Chromium Blink file. This involves identifying its purpose, how it interacts with other components (especially JavaScript, HTML, CSS), potential errors, and how a user might trigger its execution.

2. **Initial Scan and Keyword Identification:**  Start by quickly reading through the file, looking for keywords and familiar concepts. I see:
    * `BackgroundFetchRegistration` (obviously central)
    * `ServiceWorkerRegistration` (indicates Service Worker involvement)
    * `mojom::blink::BackgroundFetch*` (suggests communication with other processes via Mojo)
    * `ScriptPromise`, `V8*` (clearly interacts with JavaScript)
    * `Event`, `DispatchEvent` (part of the eventing system)
    * `CacheQueryOptions`, `Request`, `Response` (related to fetching and caching)
    * `abort`, `match`, `matchAll` (methods exposed to JavaScript)
    * `OnProgress`, `OnRequestCompleted` (methods likely called from the browser process)

3. **Identify the Core Functionality:** Based on the keywords and structure, it's clear this class represents a single background fetch registration. It manages the state (progress, result, failure reason) and provides methods to interact with the registration (abort, match requests). The interaction with `ServiceWorkerRegistration` suggests the background fetch is initiated and managed within the context of a service worker.

4. **Map to JavaScript API:** The presence of `ScriptPromise` and methods like `abort`, `match`, and `matchAll` strongly indicates these are the methods exposed to JavaScript through the `BackgroundFetchRegistration` interface. The arguments and return types (e.g., `ScriptPromise<IDLBoolean>`, `ScriptPromise<BackgroundFetchRecord>`) further solidify this connection.

5. **Analyze Key Methods:**  Focus on the important methods and understand their purpose:
    * **Constructor:** Initializes the object with data received from the browser process.
    * **`OnProgress`:** Updates the progress state and dispatches a `progress` event, making this information available to the JavaScript.
    * **`OnRequestCompleted`:**  Handles completion of individual requests within the background fetch. It likely updates the state of associated `BackgroundFetchRecord` objects.
    * **`abort`:**  Initiates the abort process. It communicates with the browser process via Mojo.
    * **`match` and `matchAll`:** Allow querying the requests associated with the background fetch, potentially against the cache. The interaction with `CacheQueryOptions` confirms this.
    * **`DidGetMatchingRequests`:**  Handles the response from the browser process for `match` and `matchAll`. It creates `BackgroundFetchRecord` objects representing the matched requests.
    * **`UpdateRecord`:** Updates the state of a `BackgroundFetchRecord` based on the response or abort status.

6. **Establish Relationships with Web Technologies:**
    * **JavaScript:** The primary interface for interacting with `BackgroundFetchRegistration`. The methods like `abort()`, `match()`, and `matchAll()` are direct JavaScript API calls. Events like `progress` are also dispatched and can be listened to in JavaScript.
    * **HTML:**  While not directly interacting with the *code* in this file, the user action that triggers the background fetch (e.g., clicking a link that triggers the service worker to start a background fetch) is rooted in HTML.
    * **CSS:**  Indirectly related. The visual feedback for a background fetch (if implemented by the developer) might use CSS for styling. The icon used in the notification could be referenced in CSS, though this file itself doesn't manipulate CSS.

7. **Infer Logic and Data Flow:**  Trace the flow of data. The browser process provides the initial registration data. JavaScript calls methods on `BackgroundFetchRegistration`. These calls are relayed to the browser process via Mojo. The browser process performs the actual fetching and updates the registration state, which is then communicated back to the renderer process via methods like `OnProgress` and `OnRequestCompleted`.

8. **Identify Potential Errors and Usage Mistakes:** Think about common pitfalls:
    * Trying to use `match` or `matchAll` after the records are no longer available.
    * Not handling the `progress` event to provide user feedback.
    * Incorrectly constructing the request object passed to `match`.
    * Expecting immediate results from `abort`, `match`, or `matchAll` when they return promises.

9. **Consider Debugging Scenarios:** How would a developer end up looking at this file during debugging?
    * Seeing errors related to background fetch in the console.
    * Stepping through the JavaScript code and noticing calls to `BackgroundFetchRegistration` methods.
    * Investigating why a background fetch isn't progressing or completing as expected.
    * Examining the network requests associated with the background fetch.

10. **Structure the Explanation:** Organize the findings logically, covering:
    * Core functionality.
    * Relationships with web technologies (with examples).
    * Logic and data flow (with input/output examples, even if hypothetical).
    * Common errors.
    * Debugging scenarios.

11. **Refine and Elaborate:** Review the generated explanation for clarity and accuracy. Add more details and examples where necessary. For instance, for the user action, be specific about how a user interaction might trigger the service worker to initiate the fetch. For errors, provide concrete examples of JavaScript code snippets that would lead to those errors.

By following this structured approach, combining code analysis with knowledge of web technologies and debugging practices, it's possible to generate a comprehensive and insightful explanation of the `BackgroundFetchRegistration.cc` file.
好的，让我们来分析一下 `blink/renderer/modules/background_fetch/background_fetch_registration.cc` 文件的功能。

**文件功能概述:**

`BackgroundFetchRegistration.cc` 文件定义了 `BackgroundFetchRegistration` 类，该类是 Blink 渲染引擎中用于表示一个活跃的后台获取（Background Fetch）操作的接口。它封装了与特定后台获取操作相关的状态、方法和事件处理逻辑。  你可以把它看作是 JavaScript 中 `BackgroundFetchRegistration` 对象的内部实现。

**主要功能点:**

1. **状态管理:**  `BackgroundFetchRegistration` 对象维护了后台获取操作的各种状态信息，包括：
   - `developer_id_`:  开发者提供的唯一标识符。
   - `upload_total_`, `uploaded_`:  上传的总字节数和已上传的字节数。
   - `download_total_`, `downloaded_`: 下载的总字节数和已下载的字节数。
   - `result_`:  后台获取的结果（成功或失败）。
   - `failure_reason_`: 后台获取失败的原因。
   - `records_available_`: 指示与此后台获取关联的记录是否仍然可用。

2. **与 Service Worker 的关联:**  `BackgroundFetchRegistration` 对象与一个 `ServiceWorkerRegistration` 对象关联，表明后台获取操作是由特定的 Service Worker 发起的。

3. **与浏览器进程的通信:**  通过 `registration_service_` 成员（一个 `mojom::blink::BackgroundFetchRegistration` 接口），该类可以与浏览器进程中的后台获取服务进行通信，例如：
   - `Abort()`:  请求中止后台获取操作。
   - `MatchRequests()`:  根据请求信息匹配已完成或正在进行的后台获取请求。
   - `UpdateUI()`: 更新后台获取的 UI 展示（例如，通知的标题和图标）。

4. **事件分发:**  该类继承自 `EventTarget`，可以分发事件，最主要的事件是 `progress` 事件，用于通知 JavaScript 关于下载或上传进度的更新。

5. **请求匹配 (Matching):** 提供了 `match()` 和 `matchAll()` 方法，允许 JavaScript 代码根据 `Request` 对象或 URL 匹配与该后台获取关联的已完成请求。

6. **中止 (Aborting):** 提供了 `abort()` 方法，允许 JavaScript 代码请求中止后台获取操作。

7. **结果和失败原因查询:**  提供了 `result()` 和 `failureReason()` 方法，允许 JavaScript 代码获取后台获取操作的最终结果和失败原因。

**与 JavaScript, HTML, CSS 的关系 (及举例):**

`BackgroundFetchRegistration` 类是 JavaScript `BackgroundFetchRegistration` 接口在 Blink 引擎中的实现，因此它直接与 JavaScript 代码交互。

**JavaScript 示例:**

```javascript
navigator.serviceWorker.ready.then(registration => {
  registration.backgroundFetch.get('my-fetch-id').then(fetchRegistration => {
    if (fetchRegistration) {
      console.log('后台获取已找到:', fetchRegistration.id);

      // 监听进度事件
      fetchRegistration.addEventListener('progress', event => {
        const downloaded = event.downloaded;
        const downloadTotal = event.downloadTotal;
        console.log(`下载进度: ${downloaded} / ${downloadTotal}`);
      });

      // 获取结果和失败原因
      console.log('结果:', fetchRegistration.result);
      console.log('失败原因:', fetchRegistration.failureReason);

      // 中止后台获取
      // fetchRegistration.abort().then(aborted => {
      //   if (aborted) {
      //     console.log('后台获取已中止');
      //   } else {
      //     console.log('中止后台获取失败');
      //   }
      // });

      // 匹配已完成的请求
      // fetchRegistration.match('/api/data').then(record => {
      //   if (record) {
      //     console.log('匹配到的请求:', record.request.url);
      //     record.response.then(response => {
      //       console.log('匹配到的响应状态:', response.status);
      //     });
      //   } else {
      //     console.log('未找到匹配的请求');
      //   }
      // });
    } else {
      console.log('未找到指定的后台获取');
    }
  });
});
```

**HTML 示例:**

HTML 本身不直接与 `BackgroundFetchRegistration.cc` 交互，但用户在 HTML 页面上的操作（例如点击一个触发 Service Worker 启动后台获取的按钮）是最终触发 `BackgroundFetchRegistration` 对象创建和生命周期的起点。

```html
<!DOCTYPE html>
<html>
<head>
  <title>后台获取示例</title>
</head>
<body>
  <button id="startFetch">开始后台获取</button>
  <script>
    document.getElementById('startFetch').addEventListener('click', () => {
      navigator.serviceWorker.ready.then(registration => {
        registration.backgroundFetch.fetch('my-fetch-id', ['/api/data', '/images/logo.png'], {
          title: '我的后台下载',
          icons: [{ src: '/images/icon.png', sizes: '96x96', type: 'image/png' }]
        }).then(fetchRegistration => {
          console.log('后台获取已启动:', fetchRegistration.id);
        });
      });
    });

    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('/sw.js');
    }
  </script>
</body>
</html>
```

**CSS 示例:**

CSS 也不会直接与 `BackgroundFetchRegistration.cc` 交互。但是，如果开发者在网页上展示后台获取的进度或状态，他们可能会使用 CSS 来样式化这些元素。例如，一个显示下载进度的进度条。

**逻辑推理与假设输入输出:**

**假设输入:**  JavaScript 代码调用 `fetchRegistration.abort()`。

**输出:**
- `BackgroundFetchRegistration` 对象调用其内部的 `registration_service_->Abort()` 方法，向浏览器进程发送中止请求。
- 浏览器进程处理该请求，并可能更新后台获取的状态。
- 浏览器进程最终可能会通过 `BackgroundFetchRegistration::OnProgress()` 回调通知渲染进程状态更新，例如 `failure_reason_` 更新为 `CANCELLED_BY_DEVELOPER`。
- `abort()` 方法返回的 `Promise` 会根据浏览器进程的响应解析为 `true` (中止成功) 或 `false` (中止失败)。

**假设输入:** JavaScript 代码调用 `fetchRegistration.match('/api/data')`。

**输出:**
- `BackgroundFetchRegistration` 对象调用其内部的 `registration_service_->MatchRequests()` 方法，将 URL `/api/data` 发送给浏览器进程。
- 浏览器进程在与此后台获取关联的已完成请求中查找匹配项。
- 浏览器进程通过 `BackgroundFetchRegistration::DidGetMatchingRequests()` 回调，将匹配到的 `mojom::blink::BackgroundFetchSettledFetchPtr` 对象返回给渲染进程。
- `DidGetMatchingRequests()` 方法会创建或更新 `BackgroundFetchRecord` 对象，并将其包装在 `Promise` 中返回给 JavaScript。

**用户或编程常见的使用错误:**

1. **尝试在后台获取完成后或记录不可用时调用 `match()` 或 `matchAll()`:**  如果 `records_available_` 为 `false`，这些方法会抛出 `InvalidStateError` 异常。

   **JavaScript 示例:**

   ```javascript
   navigator.serviceWorker.ready.then(registration => {
     registration.backgroundFetch.get('my-fetch-id').then(fetchRegistration => {
       // ... 等待后台获取完成或被取消 ...
       setTimeout(() => {
         fetchRegistration.match('/some/resource').catch(error => {
           console.error("匹配失败:", error.message); // 可能输出 "匹配失败: The records associated with this background fetch are no longer available."
         });
       }, 60000); // 假设后台获取在 60 秒后完成
     });
   });
   ```

2. **忘记监听 `progress` 事件以提供用户反馈:**  用户可能不知道后台操作正在进行中。

   **错误示例 (缺少 `progress` 监听器):**

   ```javascript
   navigator.serviceWorker.ready.then(registration => {
     registration.backgroundFetch.fetch('my-fetch-id', ['/large/file']).then(fetchRegistration => {
       console.log('后台获取已启动');
       // 没有添加 progress 监听器
     });
   });
   ```

3. **在 `match()` 中传递错误的请求信息:** 传递的 URL 或 `Request` 对象可能与后台获取中实际请求的 URL 不匹配。

   **错误示例:**

   ```javascript
   navigator.serviceWorker.ready.then(registration => {
     registration.backgroundFetch.get('my-fetch-id').then(fetchRegistration => {
       fetchRegistration.match('/wrong/api/endpoint').then(record => {
         if (!record) {
           console.log("未找到匹配项"); // 因为 URL 不匹配
         }
       });
     });
   });
   ```

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在网页上执行某个操作:** 例如，点击一个下载按钮或一个触发数据同步的按钮。
2. **JavaScript 代码在 Service Worker 上调用 `backgroundFetch.fetch()`:**  这会创建一个新的后台获取操作。
3. **浏览器进程接收到后台获取请求:** 浏览器进程会创建一个与此请求关联的 `BackgroundFetchRegistration` 的内部表示。
4. **浏览器进程通过 Mojo 接口将新的 `BackgroundFetchRegistration` 信息传递给渲染进程:** 这会导致在渲染进程中创建 `blink::BackgroundFetchRegistration` 对象。
5. **JavaScript 代码可以通过 `get()` 方法获取到 `BackgroundFetchRegistration` 对象:**  例如，`registration.backgroundFetch.get('my-fetch-id')`。
6. **开发者可能在控制台中查看 `fetchRegistration` 对象:**  或者在调试器中单步执行涉及到 `fetchRegistration` 的代码。
7. **如果需要查看 `BackgroundFetchRegistration.cc` 的具体实现，开发者可能在 Chrome 的源代码中查找该文件:** 这通常发生在需要深入了解 Blink 引擎内部工作原理或调试特定问题时。
8. **在调试器中设置断点:** 开发者可能会在 `BackgroundFetchRegistration.cc` 的特定方法（如 `OnProgress`、`DidAbort`、`MatchImpl`）中设置断点，以观察代码的执行流程和状态变化。

总而言之，`BackgroundFetchRegistration.cc` 是 Blink 引擎中实现后台获取 API 核心功能的关键组件，它负责管理后台获取操作的状态、与浏览器进程通信，并为 JavaScript 提供交互接口。理解这个文件有助于开发者更好地理解和调试后台获取功能。

### 提示词
```
这是目录为blink/renderer/modules/background_fetch/background_fetch_registration.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/background_fetch/background_fetch_registration.h"

#include <optional>
#include <utility>

#include "third_party/blink/public/common/privacy_budget/identifiability_metric_builder.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_surface.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_request_usvstring.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_background_fetch_failure_reason.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_background_fetch_result.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_cache_query_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_image_resource.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/fetch/request.h"
#include "third_party/blink/renderer/core/fetch/response.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/modules/background_fetch/background_fetch_bridge.h"
#include "third_party/blink/renderer/modules/background_fetch/background_fetch_record.h"
#include "third_party/blink/renderer/modules/cache_storage/cache.h"
#include "third_party/blink/renderer/modules/event_target_modules_names.h"
#include "third_party/blink/renderer/modules/service_worker/service_worker_registration.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

BackgroundFetchRegistration::BackgroundFetchRegistration(
    ServiceWorkerRegistration* service_worker_registration,
    mojom::blink::BackgroundFetchRegistrationPtr registration)
    : ActiveScriptWrappable<BackgroundFetchRegistration>({}),
      developer_id_(registration->registration_data->developer_id),
      upload_total_(registration->registration_data->upload_total),
      uploaded_(registration->registration_data->uploaded),
      download_total_(registration->registration_data->download_total),
      downloaded_(registration->registration_data->downloaded),
      result_(registration->registration_data->result),
      failure_reason_(registration->registration_data->failure_reason),
      registration_service_(service_worker_registration->GetExecutionContext()),
      observer_receiver_(this,
                         service_worker_registration->GetExecutionContext()) {
  DCHECK(service_worker_registration);
  registration_ = service_worker_registration;

  ExecutionContext* context = GetExecutionContext();
  if (!context || context->IsContextDestroyed())
    return;

  auto service_task_runner = context->GetTaskRunner(TaskType::kBackgroundFetch);
  registration_service_.Bind(std::move(registration->registration_interface),
                             std::move(service_task_runner));

  auto observer_task_runner =
      context->GetTaskRunner(TaskType::kBackgroundFetch);
  registration_service_->AddRegistrationObserver(
      observer_receiver_.BindNewPipeAndPassRemote(observer_task_runner));
}

BackgroundFetchRegistration::~BackgroundFetchRegistration() = default;

void BackgroundFetchRegistration::OnProgress(
    uint64_t upload_total,
    uint64_t uploaded,
    uint64_t download_total,
    uint64_t downloaded,
    mojom::BackgroundFetchResult result,
    mojom::BackgroundFetchFailureReason failure_reason) {
  upload_total_ = upload_total;
  uploaded_ = uploaded;
  download_total_ = download_total;
  downloaded_ = downloaded;
  result_ = result;
  failure_reason_ = failure_reason;

  DispatchEvent(*Event::Create(event_type_names::kProgress));
}

void BackgroundFetchRegistration::OnRecordsUnavailable() {
  records_available_ = false;
}

void BackgroundFetchRegistration::OnRequestCompleted(
    mojom::blink::FetchAPIRequestPtr request,
    mojom::blink::FetchAPIResponsePtr response) {
  for (auto it = observers_.begin(); it != observers_.end();) {
    BackgroundFetchRecord* observer = it->Get();
    if (observer->ObservedUrl() == request->url) {
      observer->OnRequestCompleted(response->Clone());
      it = observers_.erase(it);
    } else {
      it++;
    }
  }
}

String BackgroundFetchRegistration::id() const {
  return developer_id_;
}

uint64_t BackgroundFetchRegistration::uploadTotal() const {
  return upload_total_;
}

uint64_t BackgroundFetchRegistration::uploaded() const {
  return uploaded_;
}

uint64_t BackgroundFetchRegistration::downloadTotal() const {
  return download_total_;
}

uint64_t BackgroundFetchRegistration::downloaded() const {
  return downloaded_;
}

bool BackgroundFetchRegistration::recordsAvailable() const {
  return records_available_;
}

const AtomicString& BackgroundFetchRegistration::InterfaceName() const {
  return event_target_names::kBackgroundFetchRegistration;
}

ExecutionContext* BackgroundFetchRegistration::GetExecutionContext() const {
  DCHECK(registration_);
  return registration_->GetExecutionContext();
}

ScriptPromise<IDLBoolean> BackgroundFetchRegistration::abort(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  DCHECK(registration_);
  DCHECK(registration_service_);

  registration_service_->Abort(
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          &BackgroundFetchRegistration::DidAbort, WrapPersistent(this))));

  return promise;
}

ScriptPromise<BackgroundFetchRecord> BackgroundFetchRegistration::match(
    ScriptState* script_state,
    const V8RequestInfo* request,
    const CacheQueryOptions* options,
    ExceptionState& exception_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<BackgroundFetchRecord>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  MatchImpl(script_state, resolver, request,
            mojom::blink::CacheQueryOptions::From(options), exception_state,
            /* match_all = */ false);
  return promise;
}

ScriptPromise<IDLSequence<BackgroundFetchRecord>>
BackgroundFetchRegistration::matchAll(ScriptState* script_state,
                                      ExceptionState& exception_state) {
  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLSequence<BackgroundFetchRecord>>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  MatchImpl(script_state, resolver, /* request = */ nullptr,
            /* cache_query_options = */ nullptr, exception_state,
            /* match_all = */ true);
  return promise;
}

ScriptPromise<IDLSequence<BackgroundFetchRecord>>
BackgroundFetchRegistration::matchAll(ScriptState* script_state,
                                      const V8RequestInfo* request,
                                      const CacheQueryOptions* options,
                                      ExceptionState& exception_state) {
  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLSequence<BackgroundFetchRecord>>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  MatchImpl(script_state, resolver, request,
            mojom::blink::CacheQueryOptions::From(options), exception_state,
            /* match_all = */ true);
  return promise;
}

void BackgroundFetchRegistration::MatchImpl(
    ScriptState* script_state,
    ScriptPromiseResolverBase* resolver,
    const V8RequestInfo* request,
    mojom::blink::CacheQueryOptionsPtr cache_query_options,
    ExceptionState& exception_state,
    bool match_all) {
  DCHECK(script_state);

  if (!records_available_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The records associated with this background fetch are no longer "
        "available.");
    return;
  }

  // Convert |request| to mojom::blink::FetchAPIRequestPtr.
  mojom::blink::FetchAPIRequestPtr request_to_match;
  if (request) {
    switch (request->GetContentType()) {
      case V8RequestInfo::ContentType::kRequest:
        request_to_match = request->GetAsRequest()->CreateFetchAPIRequest();
        break;
      case V8RequestInfo::ContentType::kUSVString: {
        Request* new_request = Request::Create(
            script_state, request->GetAsUSVString(), exception_state);
        if (exception_state.HadException())
          return;
        request_to_match = new_request->CreateFetchAPIRequest();
        break;
      }
    }
  }

  DCHECK(registration_);
  DCHECK(registration_service_);
  registration_service_->MatchRequests(
      std::move(request_to_match), std::move(cache_query_options), match_all,
      WTF::BindOnce(&BackgroundFetchRegistration::DidGetMatchingRequests,
                    WrapPersistent(this), WrapPersistent(resolver), match_all));
}

void BackgroundFetchRegistration::DidGetMatchingRequests(
    ScriptPromiseResolverBase* resolver,
    bool return_all,
    Vector<mojom::blink::BackgroundFetchSettledFetchPtr> settled_fetches) {
  DCHECK(resolver);

  ScriptState* script_state = resolver->GetScriptState();
  // Do not remove this, |scope| is needed for calling ToV8()
  ScriptState::Scope scope(script_state);
  HeapVector<Member<BackgroundFetchRecord>> to_return;
  to_return.ReserveInitialCapacity(settled_fetches.size());

  for (auto& fetch : settled_fetches) {
    Request* request =
        Request::Create(script_state, std::move(fetch->request),
                        Request::ForServiceWorkerFetchEvent::kFalse);
    auto* record =
        MakeGarbageCollected<BackgroundFetchRecord>(request, script_state);

    // If this request is incomplete, enlist this record to receive updates on
    // the request.
    if (fetch->response.is_null() && !IsAborted())
      observers_.push_back(*record);

    UpdateRecord(record, fetch->response);
    to_return.push_back(record);
  }

  if (!return_all) {
    if (settled_fetches.empty()) {
      // Nothing was matched. Resolve with `undefined`.
      resolver->DowncastTo<BackgroundFetchRecord>()->Resolve();
      return;
    }

    DCHECK_EQ(settled_fetches.size(), 1u);
    DCHECK_EQ(to_return.size(), 1u);
    resolver->DowncastTo<BackgroundFetchRecord>()->Resolve(to_return[0]);
    return;
  }

  resolver->DowncastTo<IDLSequence<BackgroundFetchRecord>>()->Resolve(
      to_return);
}

void BackgroundFetchRegistration::UpdateRecord(
    BackgroundFetchRecord* record,
    mojom::blink::FetchAPIResponsePtr& response) {
  DCHECK(record);

  if (!record->IsRecordPending())
    return;

  // Per the spec, resolve with a valid response, if there is one available,
  // even if the fetch has been aborted.
  if (!response.is_null()) {
    record->SetResponseAndUpdateState(response);
    return;
  }

  if (IsAborted()) {
    record->UpdateState(BackgroundFetchRecord::State::kAborted);
    return;
  }

  if (result_ != mojom::blink::BackgroundFetchResult::UNSET)
    record->UpdateState(BackgroundFetchRecord::State::kSettled);
}

bool BackgroundFetchRegistration::IsAborted() {
  return failure_reason_ ==
             mojom::BackgroundFetchFailureReason::CANCELLED_FROM_UI ||
         failure_reason_ ==
             mojom::BackgroundFetchFailureReason::CANCELLED_BY_DEVELOPER;
}

void BackgroundFetchRegistration::DidAbort(
    ScriptPromiseResolver<IDLBoolean>* resolver,
    mojom::blink::BackgroundFetchError error) {
  switch (error) {
    case mojom::blink::BackgroundFetchError::NONE:
      resolver->Resolve(/* success = */ true);
      return;
    case mojom::blink::BackgroundFetchError::INVALID_ID:
      resolver->Resolve(/* success = */ false);
      return;
    case mojom::blink::BackgroundFetchError::STORAGE_ERROR:
      resolver->RejectWithDOMException(
          DOMExceptionCode::kAbortError,
          "Failed to abort registration due to I/O error.");
      return;
    case mojom::blink::BackgroundFetchError::SERVICE_WORKER_UNAVAILABLE:
    case mojom::blink::BackgroundFetchError::DUPLICATED_DEVELOPER_ID:
    case mojom::blink::BackgroundFetchError::INVALID_ARGUMENT:
    case mojom::blink::BackgroundFetchError::PERMISSION_DENIED:
    case mojom::blink::BackgroundFetchError::QUOTA_EXCEEDED:
    case mojom::blink::BackgroundFetchError::REGISTRATION_LIMIT_EXCEEDED:
      // Not applicable for this callback.
      break;
  }

  NOTREACHED();
}

V8BackgroundFetchResult BackgroundFetchRegistration::result() const {
  switch (result_) {
    case mojom::BackgroundFetchResult::SUCCESS:
      return V8BackgroundFetchResult(V8BackgroundFetchResult::Enum::kSuccess);
    case mojom::BackgroundFetchResult::FAILURE:
      return V8BackgroundFetchResult(V8BackgroundFetchResult::Enum::kFailure);
    case mojom::BackgroundFetchResult::UNSET:
      return V8BackgroundFetchResult(V8BackgroundFetchResult::Enum::k);
  }
  NOTREACHED();
}

V8BackgroundFetchFailureReason BackgroundFetchRegistration::failureReason()
    const {
  blink::IdentifiabilityMetricBuilder(GetExecutionContext()->UkmSourceID())
      .Add(
          blink::IdentifiableSurface::FromTypeAndToken(
              blink::IdentifiableSurface::Type::kWebFeature,
              WebFeature::
                  kV8BackgroundFetchRegistration_FailureReason_AttributeGetter),
          failure_reason_ ==
              mojom::BackgroundFetchFailureReason::QUOTA_EXCEEDED)
      .Record(GetExecutionContext()->UkmRecorder());
  switch (failure_reason_) {
    case mojom::BackgroundFetchFailureReason::NONE:
      return V8BackgroundFetchFailureReason(
          V8BackgroundFetchFailureReason::Enum::k);
    case mojom::BackgroundFetchFailureReason::CANCELLED_FROM_UI:
    case mojom::BackgroundFetchFailureReason::CANCELLED_BY_DEVELOPER:
      return V8BackgroundFetchFailureReason(
          V8BackgroundFetchFailureReason::Enum::kAborted);
    case mojom::BackgroundFetchFailureReason::BAD_STATUS:
      return V8BackgroundFetchFailureReason(
          V8BackgroundFetchFailureReason::Enum::kBadStatus);
    case mojom::BackgroundFetchFailureReason::SERVICE_WORKER_UNAVAILABLE:
    case mojom::BackgroundFetchFailureReason::FETCH_ERROR:
      return V8BackgroundFetchFailureReason(
          V8BackgroundFetchFailureReason::Enum::kFetchError);
    case mojom::BackgroundFetchFailureReason::QUOTA_EXCEEDED:
      return V8BackgroundFetchFailureReason(
          V8BackgroundFetchFailureReason::Enum::kQuotaExceeded);
    case mojom::BackgroundFetchFailureReason::DOWNLOAD_TOTAL_EXCEEDED:
      return V8BackgroundFetchFailureReason(
          V8BackgroundFetchFailureReason::Enum::kDownloadTotalExceeded);
  }
  NOTREACHED();
}

bool BackgroundFetchRegistration::HasPendingActivity() const {
  if (!GetExecutionContext())
    return false;
  if (GetExecutionContext()->IsContextDestroyed())
    return false;

  return !observers_.empty();
}

void BackgroundFetchRegistration::UpdateUI(
    const String& in_title,
    const SkBitmap& in_icon,
    mojom::blink::BackgroundFetchRegistrationService::UpdateUICallback
        callback) {
  DCHECK(registration_service_);
  registration_service_->UpdateUI(in_title, in_icon, std::move(callback));
}

void BackgroundFetchRegistration::Trace(Visitor* visitor) const {
  visitor->Trace(registration_);
  visitor->Trace(observers_);
  visitor->Trace(registration_service_);
  visitor->Trace(observer_receiver_);
  EventTarget::Trace(visitor);
  ActiveScriptWrappable::Trace(visitor);
}

}  // namespace blink
```