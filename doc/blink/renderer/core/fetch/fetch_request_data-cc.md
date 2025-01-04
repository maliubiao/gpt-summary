Response:
Let's break down the thought process to analyze the `fetch_request_data.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relation to web technologies (JS, HTML, CSS), examples of logical reasoning, common user errors, and debugging clues.

2. **High-Level Overview (Code Scan):**  First, skim the code to identify key components and included headers. Notice imports like `mojom::blink::FetchAPIRequestPtr`, `WebHttpBody`, `WebURLRequest`, `BlobBytesConsumer`, `FormDataBytesConsumer`, and `DataPipeBytesConsumer`. These immediately suggest this file is involved in handling the data associated with fetch requests in the Blink rendering engine. The namespace `blink::fetch` reinforces this.

3. **Identify the Core Class:** The central element is `FetchRequestData`. It's the class being created and manipulated. This is where we'll focus most of our analysis.

4. **Analyze the `Create` Method:** This is likely the entry point for creating `FetchRequestData` objects. Go through the steps within this method:
    * It takes a `mojom::blink::FetchAPIRequestPtr` as input – this is a key data structure coming from the browser process.
    * It copies data from the `fetch_api_request` into the `FetchRequestData` object (URL, method, headers, etc.).
    * **Crucially:** It handles different body types (`blob`, `form data`, `stream`). This is a significant aspect of its functionality. Pay close attention to how each type is handled, especially the creation of `BytesConsumer` objects.
    * It sets various other request properties like destination, referrer, mode, credentials, cache mode, etc. These map directly to fetch API options in JavaScript.

5. **Analyze other Methods:**
    * `CloneExceptBody()`: Creates a copy without the request body. This is important for scenarios where the body might be consumed separately or multiple requests need the same metadata.
    * `Clone()`:  Creates a full copy, handling the potential need to "tee" (split) the request body stream. This is necessary because a stream can only be consumed once.
    * `Pass()`:  Similar to cloning, but it *moves* the body, making the original `FetchRequestData` object unusable for sending the body again. This optimization is likely for internal use.

6. **Relate to Web Technologies (JS, HTML, CSS):** Now, connect the functionality to user-facing web technologies:
    * **JavaScript `fetch()` API:** The `FetchRequestData` class directly corresponds to the request object created by the JavaScript `fetch()` API. The `Create` method handles the options passed to `fetch()`. The different body types (`Blob`, `FormData`, `ReadableStream`) are all supported in `fetch()`.
    * **HTML `<form>`:**  Submitting an HTML form often results in a fetch request (especially with `method="POST"`). `FormDataBytesConsumer` is directly involved in handling form submissions.
    * **CSS (indirectly):** While not directly involved with CSS *syntax*, CSS resources (stylesheets, fonts) are fetched using the same underlying mechanisms. The `FetchRequestData` would be used when the browser fetches these resources. The priority setting could influence the order in which CSS and other resources are loaded.

7. **Logical Reasoning and Examples:**  Think about the decisions made in the code. For instance, why are certain headers excluded for service workers? The comment provides a hint (security).

    * **Hypothetical Input/Output (for `Create` with a Blob):**
        * **Input:** `fetch_api_request` with a URL, method "POST", headers, and a `blob` object.
        * **Output:** A `FetchRequestData` object with the URL, method, headers, and a `BlobBytesConsumer` configured to read the blob's data. The `buffer_byte_length_` would be set to the blob's size.

8. **User and Programming Errors:** Consider how mistakes in the JavaScript `fetch()` API or HTML can lead to this code being executed with specific states:
    * Incorrect header names in `fetch()` might be filtered out.
    * Providing a body for a GET request is generally discouraged and could be handled (or rejected) here.
    * Issues with `ReadableStream` implementations could lead to errors in the data pipe handling.

9. **Debugging Clues and User Actions:** Trace how a user action can lead to this code:
    * Typing a URL and pressing Enter.
    * Clicking a link.
    * Submitting a form.
    * JavaScript code calling `fetch()`.
    * A service worker intercepting a fetch request.

10. **Structure the Answer:** Organize the findings into logical sections: Functionality, relation to web technologies, logical reasoning, common errors, and debugging. Use clear and concise language, and provide specific code examples where possible (even if simplified). Use the provided code snippets to illustrate points.

11. **Refine and Review:** Read through the generated explanation, checking for accuracy, completeness, and clarity. Ensure the examples are relevant and easy to understand. For instance, initially, I might forget to explicitly mention the role of `ExecutionContext`, but reviewing the code reveals its usage for task runners and other context-related operations.

By following this systematic approach, we can effectively analyze the given source code and generate a comprehensive explanation that addresses all aspects of the original request.
好的，我们来分析一下 `blink/renderer/core/fetch/fetch_request_data.cc` 文件的功能和相关信息。

**功能概述:**

`FetchRequestData` 类是 Blink 渲染引擎中用来存储和管理 **fetch 请求** 相关数据的一个核心类。它封装了发起一个网络请求所需的所有信息，这些信息可以来自 JavaScript 的 `fetch()` API 调用，也可以是浏览器内部发起的资源请求。

主要功能包括：

1. **存储请求属性:**  保存了请求的 URL、HTTP 方法 (GET, POST 等)、请求头 (Headers)、请求体 (Body) 以及其他与请求相关的属性，例如：
    * `url_`: 请求的 URL。
    * `method_`: HTTP 方法 (GET, POST, PUT, DELETE 等)。
    * `header_list_`: 请求头列表。
    * `buffer_`: 请求体数据，可以有多种形式 (Blob, FormData, ReadableStream)。
    * `credentials_`:  处理凭据的模式 (omit, same-origin, include)。
    * `mode_`: 请求的模式 (cors, no-cors, same-origin)。
    * `cache_mode_`: 缓存模式 (default, no-store, reload, no-cache, force-cache, only-if-cached)。
    * `redirect_`: 重定向模式 (follow, error, manual)。
    * `referrer_`: 引用 URL 和策略。
    * `priority_`: 请求的优先级。
    * 等等。

2. **创建请求数据:** 提供了 `Create` 静态方法，用于根据 `mojom::blink::FetchAPIRequestPtr` (通过 Mojo 传递的请求信息) 创建 `FetchRequestData` 对象。 这个方法负责将来自 JavaScript 或浏览器内部的请求信息转换为内部表示。

3. **克隆和传递请求数据:**  提供了 `Clone`, `CloneExceptBody`, 和 `Pass` 方法，用于复制或移动 `FetchRequestData` 对象。这在处理 Service Worker 和其他需要共享或传递请求信息的场景中非常重要。

4. **管理请求体:** 能够处理不同类型的请求体数据，包括：
    * **Blob:** 二进制大对象。
    * **FormData:** 用于提交表单数据。
    * **ReadableStream:** 可读数据流。
    * 通过 `BytesConsumer` 接口来抽象不同类型请求体的读取。

5. **与 Mojo 集成:** 使用 Mojo 接口 (`mojom::blink::FetchAPIRequestPtr`) 接收来自浏览器进程的请求信息。

6. **Service Worker 特殊处理:**  在为 Service Worker 的 `fetch` 事件创建请求数据时，会排除某些请求头 (例如 `Sec-Fetch-*`)。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`FetchRequestData` 是浏览器处理网络请求的核心部分，与 JavaScript 的 `fetch()` API 和 HTML 表单提交密切相关。CSS 虽然不直接操作 `FetchRequestData`，但浏览器在加载 CSS 资源时也会使用类似的机制。

**JavaScript `fetch()` API:**

* 当 JavaScript 代码调用 `fetch()` 发起网络请求时，`fetch()` 的参数 (URL, method, headers, body, credentials, mode 等) 会被转换成 `mojom::blink::FetchAPIRequestPtr` 对象，并通过 IPC 传递到渲染进程。
* 渲染进程中的 `FetchRequestData::Create` 方法会接收这个 `mojom::blink::FetchAPIRequestPtr`，并创建一个 `FetchRequestData` 对象来存储这些信息。

```javascript
// JavaScript 示例
fetch('https://example.com/data', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ key: 'value' }),
  credentials: 'include',
  mode: 'cors'
})
.then(response => response.json())
.then(data => console.log(data));
```

在这个例子中，`fetch()` 的参数将会影响 `FetchRequestData` 对象的以下属性：

* `url_` 将会是 `'https://example.com/data'`。
* `method_` 将会是 `'POST'`。
* `header_list_` 将包含 `'Content-Type: application/json'`。
* `buffer_` 将包含 `JSON.stringify({ key: 'value' })` 的数据，并且会使用适当的 `BytesConsumer` (可能涉及 `BlobBytesConsumer` 或 `DataPipeBytesConsumer`，取决于 body 的具体类型)。
* `credentials_` 将会是 `CredentialsMode::kInclude`。
* `mode_` 将会是 `FetchMode::kCORS`。

**HTML 表单提交:**

* 当用户提交一个 HTML 表单时 (特别是使用 `method="POST"` 时)，浏览器会创建一个对应的网络请求。
* 表单的数据会被编码成 `FormData`，并作为请求体。
* `FetchRequestData::Create` 方法在处理来自表单提交的请求时，会识别出 `FormData`，并使用 `FormDataBytesConsumer` 来处理请求体数据。

```html
<!-- HTML 表单示例 -->
<form action="/submit" method="POST" enctype="multipart/form-data">
  <input type="text" name="username" value="test">
  <input type="file" name="avatar">
  <button type="submit">Submit</button>
</form>
```

在这个例子中，当表单提交时，会创建一个 `FetchRequestData` 对象，其 `buffer_` 属性会使用 `FormDataBytesConsumer` 来封装表单数据 (包括 `username` 和 `avatar` 的内容)。

**CSS 资源加载 (间接关系):**

* 当浏览器解析 HTML 并遇到 `<link rel="stylesheet">` 标签时，会发起一个请求来获取 CSS 文件。
* 虽然没有直接的 JavaScript `fetch()` 调用，但浏览器内部会创建一个类似的请求，并使用类似 `FetchRequestData` 的机制来管理请求信息，例如 CSS 文件的 URL、请求头等。

**逻辑推理与假设输入/输出:**

**假设输入:**  一个 `mojom::blink::FetchAPIRequestPtr` 对象，表示一个带有 Blob 类型请求体的 POST 请求。

```c++
// 假设的输入 (简化表示)
mojom::blink::FetchAPIRequestPtr fetch_api_request = mojom::blink::FetchAPIRequest::New();
fetch_api_request->url = GURL("https://example.com/upload");
fetch_api_request->method = "POST";
fetch_api_request->headers.emplace_back("Content-Type", "image/png");
fetch_api_request->blob = MakeGarbageCollected<Blob>(/* 一些 Blob 数据 */);
fetch_api_request->blob->set_size(1024); // 假设 Blob 大小为 1024 字节
```

**输出 (在 `FetchRequestData::Create` 方法中):**

* 创建一个 `FetchRequestData` 对象。
* `request->url_` 将会是 `GURL("https://example.com/upload")`。
* `request->method_` 将会是 `"POST"`。
* `request->header_list_` 将包含一个元素 `{"Content-Type", "image/png"}`。
* `request->buffer_` 将会被设置为一个 `BodyStreamBuffer`，它内部使用 `BlobBytesConsumer` 来读取 Blob 的数据。
* `request->buffer_byte_length_` 将会是 `1024`。

**用户或编程常见的使用错误及举例说明:**

1. **CORS 问题:**  如果 JavaScript 代码尝试使用 `fetch()` 访问跨域资源，但服务器没有设置正确的 CORS 头 (例如 `Access-Control-Allow-Origin`)，浏览器会阻止请求。 虽然 `FetchRequestData` 本身不负责 CORS 策略的检查，但它存储了请求的 `mode_` 属性 (例如 `cors`)，这个属性会影响后续的 CORS 检查逻辑。

   * **用户操作:**  用户访问一个网页，该网页上的 JavaScript 代码尝试 `fetch()` 一个来自不同域名的 API。
   * **错误:** 浏览器控制台会显示 CORS 相关的错误信息，指示请求被阻止。

2. **请求体类型不匹配:**  在发送 POST 请求时，如果请求头中的 `Content-Type` 与请求体的实际类型不匹配，可能会导致服务器无法正确解析请求。

   * **编程错误:**  JavaScript 代码设置了 `Content-Type: application/json`，但 `body` 却是 `FormData` 对象。
   * **结果:**  服务器可能会返回 400 Bad Request 错误。`FetchRequestData` 会按原样存储这些信息，但后续的网络层处理可能会根据这些信息进行操作。

3. **Service Worker 拦截修改请求头导致错误:**  Service Worker 可以拦截 `fetch` 请求并修改请求头。 如果错误地移除了必要的请求头，或者添加了不正确的请求头，可能会导致请求失败。

   * **用户操作:**  用户访问一个由 Service Worker 控制的页面，Service Worker 拦截了发往特定 URL 的请求并修改了请求头。
   * **错误:**  修改后的请求头可能导致服务器拒绝请求或返回意外结果。 `FetchRequestData` 在 Service Worker 中被创建和修改，错误可能在此阶段引入。

**用户操作如何一步步到达这里 (作为调试线索):**

假设我们需要调试一个用户在使用 `fetch()` API 上传文件时遇到的问题。

1. **用户操作:** 用户在一个网页上点击了一个上传按钮，该按钮触发 JavaScript 代码使用 `fetch()` 发送一个包含文件数据的 POST 请求。

2. **JavaScript 代码执行:**  JavaScript 代码获取用户选择的文件 (通常通过 `<input type="file">`)，创建一个 `FormData` 对象，并将文件添加到 `FormData` 中。然后调用 `fetch()` 发起请求。

   ```javascript
   const fileInput = document.getElementById('fileUpload');
   const file = fileInput.files[0];
   const formData = new FormData();
   formData.append('file', file);

   fetch('/upload', {
     method: 'POST',
     body: formData
   })
   .then(/* ... */);
   ```

3. **Blink 渲染引擎处理 `fetch()` 调用:**
   * Blink 的 JavaScript 引擎接收到 `fetch()` 调用。
   * 将 `fetch()` 的参数 (URL, method, headers，以及 `FormData` 类型的 body) 转换为 `mojom::blink::FetchAPIRequestPtr` 对象。
   * 通过 IPC 将 `mojom::blink::FetchAPIRequestPtr` 发送到渲染进程。

4. **`FetchRequestData::Create` 被调用:**
   * 渲染进程接收到 `mojom::blink::FetchAPIRequestPtr`。
   * 调用 `FetchRequestData::Create` 方法，传入该 Mojo 对象。
   * 在 `Create` 方法中，会识别出请求体是 `FormData`，并创建一个 `FormDataBytesConsumer` 来处理请求体数据。
   * 创建一个 `FetchRequestData` 对象，其中包含了上传请求的所有信息。

5. **网络请求发送:**
   * `FetchRequestData` 对象被传递给 Blink 的网络模块。
   * 网络模块根据 `FetchRequestData` 中的信息构建并发送实际的 HTTP 请求。

**调试线索:**

* **断点:** 在 `FetchRequestData::Create` 方法中设置断点，可以查看接收到的 `mojom::blink::FetchAPIRequestPtr` 的内容，确认 JavaScript 传递的参数是否正确。
* **检查请求头:** 查看 `request->header_list_` 的内容，确认 `Content-Type` 是否正确设置，以及是否有其他可能影响上传的请求头。
* **检查请求体:**  虽然不容易直接查看 `FormDataBytesConsumer` 的内容，但可以检查 `request->buffer_` 是否被正确创建，以及相关的元数据 (例如大小)。
* **Service Worker:** 如果页面有 Service Worker，检查 Service Worker 是否拦截了该请求并进行了修改。可以在 Service Worker 的 `fetch` 事件监听器中设置断点。
* **网络面板:**  使用 Chrome DevTools 的 "Network" 面板，可以查看实际发送的 HTTP 请求的详细信息，包括请求头、请求体等，这可以帮助确认 `FetchRequestData` 中的信息是否被正确地传递到网络层。

总而言之，`blink/renderer/core/fetch/fetch_request_data.cc` 文件中的 `FetchRequestData` 类是 Blink 渲染引擎中处理网络请求的核心数据结构，它桥接了 JavaScript 的 `fetch()` API、HTML 表单提交和底层的网络传输机制。理解它的功能对于调试网络请求相关的问题至关重要。

Prompt: 
```
这是目录为blink/renderer/core/fetch/fetch_request_data.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fetch/fetch_request_data.h"

#include "base/unguessable_token.h"
#include "net/base/request_priority.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_http_body.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fetch/blob_bytes_consumer.h"
#include "third_party/blink/renderer/core/fetch/fetch_header_list.h"
#include "third_party/blink/renderer/core/fetch/form_data_bytes_consumer.h"
#include "third_party/blink/renderer/core/loader/threadable_loader.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/bytes_consumer.h"
#include "third_party/blink/renderer/platform/loader/fetch/data_pipe_bytes_consumer.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/network/http_names.h"

namespace {

::blink::ResourceLoadPriority ConvertRequestPriorityToResourceLoadPriority(
    net::RequestPriority priority) {
  switch (priority) {
    case net::RequestPriority::THROTTLED:
      break;
    case net::RequestPriority::IDLE:
      return ::blink::ResourceLoadPriority::kVeryLow;
    case net::RequestPriority::LOWEST:
      return ::blink::ResourceLoadPriority::kLow;
    case net::RequestPriority::LOW:
      return ::blink::ResourceLoadPriority::kMedium;
    case net::RequestPriority::MEDIUM:
      return ::blink::ResourceLoadPriority::kHigh;
    case net::RequestPriority::HIGHEST:
      return ::blink::ResourceLoadPriority::kVeryHigh;
  }

  NOTREACHED() << priority;
}

}  // namespace

namespace blink {

namespace {

bool IsExcludedHeaderForServiceWorkerFetchEvent(const String& header_name) {
  // Excluding Sec-Fetch-... headers as suggested in
  // https://crbug.com/949997#c4.
  if (header_name.StartsWithIgnoringASCIICase("sec-fetch-")) {
    return true;
  }

  return false;
}

void SignalError(Persistent<DataPipeBytesConsumer::CompletionNotifier> notifier,
                 uint32_t reason,
                 const std::string& description) {
  notifier->SignalError(BytesConsumer::Error());
}

void SignalSize(
    std::unique_ptr<mojo::Remote<network::mojom::blink::ChunkedDataPipeGetter>>,
    Persistent<DataPipeBytesConsumer::CompletionNotifier> notifier,
    int32_t status,
    uint64_t size) {
  if (status != 0) {
    // error case
    notifier->SignalError(BytesConsumer::Error());
    return;
  }
  notifier->SignalSize(size);
}

}  // namespace

FetchRequestData* FetchRequestData::Create(
    ScriptState* script_state,
    mojom::blink::FetchAPIRequestPtr fetch_api_request,
    ForServiceWorkerFetchEvent for_service_worker_fetch_event) {
  DCHECK(fetch_api_request);
  FetchRequestData* request = MakeGarbageCollected<FetchRequestData>(
      script_state ? ExecutionContext::From(script_state) : nullptr);
  request->url_ = fetch_api_request->url;
  request->method_ = AtomicString(fetch_api_request->method);
  for (const auto& pair : fetch_api_request->headers) {
    // TODO(leonhsl): Check sources of |fetch_api_request.headers| to make clear
    // whether we really need this filter.
    if (EqualIgnoringASCIICase(pair.key, "referer"))
      continue;
    if (for_service_worker_fetch_event == ForServiceWorkerFetchEvent::kTrue &&
        IsExcludedHeaderForServiceWorkerFetchEvent(pair.key)) {
      continue;
    }
    request->header_list_->Append(pair.key, pair.value);
  }

  if (fetch_api_request->blob) {
    DCHECK(fetch_api_request->body.IsEmpty());
    request->SetBuffer(
        BodyStreamBuffer::Create(
            script_state,
            MakeGarbageCollected<BlobBytesConsumer>(
                ExecutionContext::From(script_state), fetch_api_request->blob),
            nullptr /* AbortSignal */, /*cached_metadata_handler=*/nullptr),
        fetch_api_request->blob->size());
  } else if (fetch_api_request->body.FormBody()) {
    request->SetBuffer(
        BodyStreamBuffer::Create(script_state,
                                 MakeGarbageCollected<FormDataBytesConsumer>(
                                     ExecutionContext::From(script_state),
                                     fetch_api_request->body.FormBody()),
                                 nullptr /* AbortSignal */,
                                 /*cached_metadata_handler=*/nullptr),
        fetch_api_request->body.FormBody()->SizeInBytes());
  } else if (fetch_api_request->body.StreamBody()) {
    mojo::ScopedDataPipeConsumerHandle readable;
    mojo::ScopedDataPipeProducerHandle writable;
    MojoCreateDataPipeOptions options{sizeof(MojoCreateDataPipeOptions),
                                      MOJO_CREATE_DATA_PIPE_FLAG_NONE, 1, 0};
    const MojoResult result =
        mojo::CreateDataPipe(&options, writable, readable);
    if (result == MOJO_RESULT_OK) {
      DataPipeBytesConsumer::CompletionNotifier* completion_notifier = nullptr;
      // Explicitly creating a ReadableStream here in order to remember
      // that the request is created from a ReadableStream.
      auto* stream =
          BodyStreamBuffer::Create(
              script_state,
              MakeGarbageCollected<DataPipeBytesConsumer>(
                  ExecutionContext::From(script_state)
                      ->GetTaskRunner(TaskType::kNetworking),
                  std::move(readable), &completion_notifier),
              /*AbortSignal=*/nullptr, /*cached_metadata_handler=*/nullptr)
              ->Stream();
      request->SetBuffer(
          MakeGarbageCollected<BodyStreamBuffer>(script_state, stream,
                                                 /*AbortSignal=*/nullptr));

      auto body_remote = std::make_unique<
          mojo::Remote<network::mojom::blink::ChunkedDataPipeGetter>>(
          fetch_api_request->body.TakeStreamBody());
      body_remote->set_disconnect_with_reason_handler(
          WTF::BindOnce(SignalError, WrapPersistent(completion_notifier)));
      auto* body_remote_raw = body_remote.get();
      (*body_remote_raw)
          ->GetSize(WTF::BindOnce(SignalSize, std::move(body_remote),
                                  WrapPersistent(completion_notifier)));
      (*body_remote_raw)->StartReading(std::move(writable));
    } else {
      request->SetBuffer(BodyStreamBuffer::Create(
          script_state, BytesConsumer::CreateErrored(BytesConsumer::Error()),
          nullptr /* AbortSignal */, /*cached_metadata_handler=*/nullptr));
    }
  }

  // Context is always set to FETCH later, so we don't copy it
  // from fetch_api_request here.
  // TODO(crbug.com/1045925): Remove this comment too when
  // we deprecate SetContext.

  request->SetDestination(fetch_api_request->destination);
  if (fetch_api_request->request_initiator)
    request->SetOrigin(fetch_api_request->request_initiator);
  request->SetNavigationRedirectChain(
      fetch_api_request->navigation_redirect_chain);
  request->SetReferrerString(AtomicString(Referrer::NoReferrer()));
  if (fetch_api_request->referrer) {
    if (!fetch_api_request->referrer->url.IsEmpty()) {
      request->SetReferrerString(
          AtomicString(fetch_api_request->referrer->url));
    }
    request->SetReferrerPolicy(fetch_api_request->referrer->policy);
  }
  request->SetMode(fetch_api_request->mode);
  request->SetTargetAddressSpace(fetch_api_request->target_address_space);
  request->SetCredentials(fetch_api_request->credentials_mode);
  request->SetCacheMode(fetch_api_request->cache_mode);
  request->SetRedirect(fetch_api_request->redirect_mode);
  request->SetMimeType(request->header_list_->ExtractMIMEType());
  request->SetIntegrity(fetch_api_request->integrity);
  request->SetKeepalive(fetch_api_request->keepalive);
  request->SetIsHistoryNavigation(fetch_api_request->is_history_navigation);
  request->SetPriority(ConvertRequestPriorityToResourceLoadPriority(
      fetch_api_request->priority));
  if (fetch_api_request->fetch_window_id)
    request->SetWindowId(fetch_api_request->fetch_window_id.value());

  if (fetch_api_request->trust_token_params) {
    if (script_state) {
      // script state might be null for some tests
      DCHECK(RuntimeEnabledFeatures::PrivateStateTokensEnabled(
          ExecutionContext::From(script_state)));
    }
    std::optional<network::mojom::blink::TrustTokenParams> trust_token_params =
        std::move(*(fetch_api_request->trust_token_params->Clone().get()));
    request->SetTrustTokenParams(trust_token_params);
  }

  request->SetAttributionReportingEligibility(
      fetch_api_request->attribution_reporting_eligibility);
  request->SetAttributionReportingSupport(
      fetch_api_request->attribution_reporting_support);

  if (fetch_api_request->service_worker_race_network_request_token) {
    request->SetServiceWorkerRaceNetworkRequestToken(
        fetch_api_request->service_worker_race_network_request_token.value());
  }

  return request;
}

FetchRequestData* FetchRequestData::CloneExceptBody() {
  auto* request = MakeGarbageCollected<FetchRequestData>(execution_context_);
  request->url_ = url_;
  request->method_ = method_;
  request->header_list_ = header_list_->Clone();
  request->origin_ = origin_;
  request->navigation_redirect_chain_ = navigation_redirect_chain_;
  request->isolated_world_origin_ = isolated_world_origin_;
  request->destination_ = destination_;
  request->referrer_string_ = referrer_string_;
  request->referrer_policy_ = referrer_policy_;
  request->mode_ = mode_;
  request->target_address_space_ = target_address_space_;
  request->credentials_ = credentials_;
  request->cache_mode_ = cache_mode_;
  request->redirect_ = redirect_;
  request->mime_type_ = mime_type_;
  request->integrity_ = integrity_;
  request->priority_ = priority_;
  request->fetch_priority_hint_ = fetch_priority_hint_;
  request->original_destination_ = original_destination_;
  request->keepalive_ = keepalive_;
  request->browsing_topics_ = browsing_topics_;
  request->ad_auction_headers_ = ad_auction_headers_;
  request->shared_storage_writable_ = shared_storage_writable_;
  request->is_history_navigation_ = is_history_navigation_;
  request->window_id_ = window_id_;
  request->trust_token_params_ = trust_token_params_;
  request->attribution_reporting_eligibility_ =
      attribution_reporting_eligibility_;
  request->attribution_reporting_support_ = attribution_reporting_support_;
  request->service_worker_race_network_request_token_ =
      service_worker_race_network_request_token_;
  return request;
}

FetchRequestData* FetchRequestData::Clone(ScriptState* script_state,
                                          ExceptionState& exception_state) {
  FetchRequestData* request = FetchRequestData::CloneExceptBody();
  if (request->service_worker_race_network_request_token_) {
    request->service_worker_race_network_request_token_ =
        base::UnguessableToken::Null();
  }
  if (buffer_) {
    BodyStreamBuffer* new1 = nullptr;
    BodyStreamBuffer* new2 = nullptr;
    buffer_->Tee(&new1, &new2, exception_state);
    if (exception_state.HadException())
      return nullptr;
    buffer_ = new1;
    request->buffer_ = new2;
    request->buffer_byte_length_ = buffer_byte_length_;
  }
  if (url_loader_factory_.is_bound()) {
    url_loader_factory_->Clone(
        request->url_loader_factory_.BindNewPipeAndPassReceiver(
            ExecutionContext::From(script_state)
                ->GetTaskRunner(TaskType::kNetworking)));
  }
  return request;
}

FetchRequestData* FetchRequestData::Pass(ScriptState* script_state,
                                         ExceptionState& exception_state) {
  FetchRequestData* request = FetchRequestData::CloneExceptBody();
  if (buffer_) {
    request->buffer_ = buffer_;
    request->buffer_byte_length_ = buffer_byte_length_;
    buffer_ = BodyStreamBuffer::Create(
        script_state, BytesConsumer::CreateClosed(), nullptr /* AbortSignal */,
        /*cached_metadata_handler=*/nullptr);
    buffer_->CloseAndLockAndDisturb(exception_state);
    buffer_byte_length_ = 0;
  }
  request->url_loader_factory_ = std::move(url_loader_factory_);
  return request;
}

FetchRequestData::~FetchRequestData() {}

FetchRequestData::FetchRequestData(ExecutionContext* execution_context)
    : referrer_string_(Referrer::ClientReferrerString()),
      url_loader_factory_(execution_context),
      execution_context_(execution_context) {}

void FetchRequestData::Trace(Visitor* visitor) const {
  visitor->Trace(buffer_);
  visitor->Trace(header_list_);
  visitor->Trace(url_loader_factory_);
  visitor->Trace(execution_context_);
}

}  // namespace blink

"""

```