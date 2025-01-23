Response:
The user wants a summary of the functionality of the provided C++ code file `blink/renderer/core/fetch/request.cc`. I need to identify the main responsibilities of this file within the Chromium Blink rendering engine, specifically focusing on how it relates to:

1. **Fetch API Requests:**  The file name and content strongly suggest it's responsible for managing and manipulating `Request` objects used in the Fetch API.
2. **JavaScript Interaction:**  How does this C++ code interact with JavaScript's `Request` object?  Look for conversions between C++ and JavaScript types.
3. **HTML/CSS Relevance:** Are there any connections to how resources are fetched for HTML and CSS (e.g., images, stylesheets, scripts)?
4. **Logic and Data Flow:**  Identify key functions and their roles in processing request data. Hypothesize inputs and outputs for important functions.
5. **Potential Errors:**  What are common mistakes users or developers might make when working with Fetch requests that this code handles?
6. **Debugging:** How might a developer end up examining this file during debugging? What user actions lead to this code being executed?

**Plan:**

1. **Core Functionality:** Determine the primary purpose of `request.cc`. It seems to be about creating, copying, and configuring `Request` objects.
2. **JavaScript Bridge:** Analyze how JavaScript `Request` objects (represented by `RequestInit`) are translated into the internal C++ representation (`FetchRequestData`). Look for V8 bindings.
3. **Resource Loading:**  See if the code interacts with components responsible for actually fetching resources (like `ResourceLoader`).
4. **Function Breakdown:** Examine key functions like `CreateRequestWithRequestOrString` and `ExtractBody`. Infer their purpose and data flow.
5. **Error Scenarios:**  Identify conditions that lead to `TypeError` or other exceptions based on the code's logic (e.g., invalid URLs, restricted methods, forbidden headers).
6. **User Actions and Debugging:**  Think about common web development tasks that involve Fetch API calls and how those actions might lead a debugger to this file.
7. **Concise Summary:**  Provide a high-level overview of the file's purpose as the first part of the two-part response.
```
这是目录为blink/renderer/core/fetch/request.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

**blink/renderer/core/fetch/request.cc 的功能归纳 (第 1 部分)**

这个 C++ 文件 `request.cc` 是 Chromium Blink 渲染引擎中负责处理 **Fetch API 的 `Request` 对象**的核心部分。它的主要功能可以归纳为：

1. **创建和配置 `Request` 对象:**  该文件包含了创建 `Request` 对象的逻辑，这些对象用于发起网络请求。它能够根据不同的输入（例如 URL 字符串、已有的 `Request` 对象、以及 JavaScript 传递的配置信息 `RequestInit`）创建新的 `Request` 对象。

2. **处理 JavaScript `RequestInit` 字典:**  当 JavaScript 代码使用 `fetch()` API 创建请求时，会传递一个 `RequestInit` 字典来配置请求的各种属性。这个文件中的代码负责将这个 JavaScript 字典转换为 Blink 引擎内部的 `FetchRequestData` 结构。

3. **管理请求的各种属性:**  `Request` 对象包含了发起网络请求所需的各种信息，例如请求的 URL、HTTP 方法（GET, POST 等）、请求头、请求体、缓存模式、凭据模式、重定向模式等等。该文件负责管理和设置这些属性。

4. **处理请求体 (Body):**  文件中的代码能够处理不同类型的请求体，包括字符串、`Blob` 对象、`ArrayBuffer`、`FormData` 对象和 `URLSearchParams` 对象，并将它们转换为可以用于网络传输的格式。它还支持 `ReadableStream` 作为请求体，用于实现流式上传。

5. **与 JavaScript 对象的交互:**  该文件使用了 Blink 的 V8 绑定机制，使得 C++ 的 `Request` 对象能够与 JavaScript 中的 `Request` 对象互相转换和交互。例如，`V8Blob::ToWrappable` 用于将 JavaScript 的 `Blob` 对象转换为 C++ 的 `Blob` 对象。

6. **执行各种策略和检查:**  在创建和配置 `Request` 对象时，该文件会执行一些安全策略和有效性检查，例如检查 URL 的有效性、HTTP 方法的合法性、以及某些属性的组合是否符合规范。

**与 JavaScript, HTML, CSS 的功能关系举例说明:**

*   **JavaScript (Fetch API):** 当 JavaScript 代码调用 `fetch('https://example.com', { method: 'POST', body: 'some data' })` 时，Blink 引擎内部会调用这个文件中的代码来创建一个 `Request` 对象。`RequestInit` 字典 `{ method: 'POST', body: 'some data' }` 会被解析并用于配置内部的 `FetchRequestData`。

*   **HTML (`<script>`, `<img>`, `<link>` 等标签):** 当浏览器解析 HTML 时，遇到像 `<script src="...">`、`<img src="...">` 或 `<link rel="stylesheet" href="...">` 这样的标签时，Blink 引擎会创建相应的 `Request` 对象来请求这些资源。虽然这些请求通常不由 JavaScript 直接发起，但底层的 `Request` 对象创建和管理逻辑仍然会用到这个文件中的代码。例如，`<img src="image.png">` 会导致浏览器创建一个 GET 请求，其 `destination` 属性会被设置为 `image`。

*   **CSS (`url()` 函数):**  在 CSS 文件中，`url()` 函数用于引用外部资源，例如背景图片 (`background-image: url('bg.png')`) 或字体文件 (`@font-face { src: url('font.woff2'); }`)。当浏览器解析 CSS 并遇到 `url()` 函数时，也会创建一个 `Request` 对象来加载这些资源。

**逻辑推理举例:**

假设 JavaScript 代码执行以下操作：

```javascript
const headers = new Headers();
headers.append('Content-Type', 'application/json');
const request = new Request('https://api.example.com/data', {
  method: 'POST',
  headers: headers,
  body: JSON.stringify({ key: 'value' }),
  mode: 'cors'
});
```

**假设输入:**

*   `input_string`:  `"https://api.example.com/data"`
*   `init`: 一个包含了 `method: 'POST'`, `headers`: (包含 'Content-Type': 'application/json'), `body`: (表示 `JSON.stringify({ key: 'value' })` 的字符串), `mode: 'cors'` 的 `RequestInit` 对象。

**逻辑推理:**  `Request::CreateRequestWithRequestOrString` 函数会被调用。代码会解析 URL，处理 `RequestInit` 中的各个属性，例如设置 `request->SetMethod("POST")`，将 `headers` 转换为内部表示，并将 `body` 字符串处理为可以发送的数据。

**假设输出:**

*   一个 `Request` 对象，其内部的 `FetchRequestData` 结构包含以下信息：
    *   `url`:  `https://api.example.com/data`
    *   `method`: `"POST"`
    *   `headerList`:  包含 `Content-Type: application/json` 的请求头列表。
    *   `body`:  表示字符串 `{"key":"value"}` 的 `BodyStreamBuffer`。
    *   `mode`: `network::mojom::RequestMode::kCors`

**用户或编程常见的使用错误举例:**

1. **在构造 `Request` 时传入无效的 URL:**  例如 `new Request('invalid-url')` 会导致 `CreateRequestWithRequestOrString` 中 URL 解析失败并抛出 `TypeError`。

2. **尝试在 `RequestInit` 中设置 `mode: 'navigate'`:**  由于导航请求有特殊的处理流程，直接在 `RequestInit` 中设置 `'navigate'` 会导致代码抛出 `TypeError`。

3. **在请求中使用禁用的 HTTP 方法:** 例如尝试创建一个 `TRACE` 请求可能会被阻止并抛出 `TypeError`。

4. **尝试从包含凭据的 URL 创建请求:**  例如 `new Request('https://user:password@example.com')` 会因为 URL 中包含用户名和密码而抛出 `TypeError`。

5. **在 `only-if-cached` 模式下使用非 `same-origin` 的请求:**  如果设置了 `cache: 'only-if-cached'` 但 `mode` 不是 `'same-origin'`，会导致 `TypeError`，因为 `only-if-cached` 模式通常用于 Service Worker 拦截的同源请求。

**用户操作如何一步步到达这里 (调试线索):**

假设开发者在调试一个网页，该网页在用户点击一个按钮后会发起一个 POST 请求提交表单数据。

1. **用户操作:** 用户在网页上填写表单，然后点击提交按钮。
2. **JavaScript 代码执行:**  与按钮点击事件关联的 JavaScript 代码被执行。这段代码可能使用了 `fetch()` API 来发起 POST 请求。
3. **`fetch()` 调用:**  JavaScript 调用 `fetch('/submit-form', { method: 'POST', body: formData })`。
4. **Blink 引擎处理:**  Blink 引擎接收到 `fetch()` 调用，并开始创建 `Request` 对象。
5. **`request.cc` 中的代码执行:**  `blink/renderer/core/fetch/request.cc` 文件中的 `Request::CreateRequestWithRequestOrString` 函数会被调用，负责根据提供的 URL 和 `RequestInit` 配置创建内部的 `FetchRequestData`。
6. **处理请求体:**  如果 `body` 是 `FormData` 对象，`ExtractBody` 函数会被调用，将 `FormData` 转换为可以发送的网络数据。
7. **网络请求:** 创建好的 `Request` 对象会被传递给网络层，最终发起实际的网络请求。

如果在调试过程中，开发者发现请求的某些属性设置不正确，或者请求无法成功发送，他们可能会在浏览器的开发者工具中设置断点，逐步跟踪 `fetch()` 调用的执行流程，最终可能会进入到 `blink/renderer/core/fetch/request.cc` 文件中的相关代码，查看 `Request` 对象的创建和配置过程，以便找出问题所在。例如，开发者可能会检查 `RequestInit` 中的 `headers` 是否正确传递，或者 `body` 是否被正确编码。

### 提示词
```
这是目录为blink/renderer/core/fetch/request.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fetch/request.h"

#include <optional>

#include "mojo/public/cpp/bindings/pending_remote.h"
#include "services/network/public/cpp/request_destination.h"
#include "services/network/public/cpp/request_mode.h"
#include "services/network/public/mojom/attribution.mojom-blink.h"
#include "services/network/public/mojom/ip_address_space.mojom-blink.h"
#include "services/network/public/mojom/trust_tokens.mojom-blink.h"
#include "third_party/blink/public/common/blob/blob_utils.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy_feature.mojom-blink.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/renderer/bindings/core/v8/dictionary.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_abort_signal.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_blob.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_form_data.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_ip_address_space.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_private_token.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_request_cache.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_request_destination.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_request_duplex.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_request_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_request_mode.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_request_redirect.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_request_usvstring.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_url_search_params.h"
#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fetch/attribution_reporting_to_mojom.h"
#include "third_party/blink/renderer/core/fetch/blob_bytes_consumer.h"
#include "third_party/blink/renderer/core/fetch/body_stream_buffer.h"
#include "third_party/blink/renderer/core/fetch/fetch_manager.h"
#include "third_party/blink/renderer/core/fetch/form_data_bytes_consumer.h"
#include "third_party/blink/renderer/core/fetch/request_util.h"
#include "third_party/blink/renderer/core/fetch/trust_token_to_mojom.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/fileapi/public_url_manager.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/forms/form_data.h"
#include "third_party/blink/renderer/core/loader/threadable_loader.h"
#include "third_party/blink/renderer/core/url/url_search_params.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/cors/cors.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_utils.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/network/encoded_form_data.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_or_worker_scheduler.h"
#include "third_party/blink/renderer/platform/weborigin/origin_access_entry.h"
#include "third_party/blink/renderer/platform/weborigin/referrer.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"

namespace blink {

namespace {

using network::mojom::blink::TrustTokenOperationType;

V8RequestDestination::Enum DestinationToV8Enum(
    network::mojom::RequestDestination destination) {
  switch (destination) {
    case network::mojom::RequestDestination::kEmpty:
      return V8RequestDestination::Enum::k;
    case network::mojom::RequestDestination::kAudio:
      return V8RequestDestination::Enum::kAudio;
    case network::mojom::RequestDestination::kAudioWorklet:
      return V8RequestDestination::Enum::kAudioworklet;
    case network::mojom::RequestDestination::kDocument:
      return V8RequestDestination::Enum::kDocument;
    case network::mojom::RequestDestination::kEmbed:
      return V8RequestDestination::Enum::kEmbed;
    case network::mojom::RequestDestination::kFont:
      return V8RequestDestination::Enum::kFont;
    case network::mojom::RequestDestination::kFrame:
      return V8RequestDestination::Enum::kFrame;
    case network::mojom::RequestDestination::kIframe:
      return V8RequestDestination::Enum::kIFrame;
    case network::mojom::RequestDestination::kImage:
      return V8RequestDestination::Enum::kImage;
    case network::mojom::RequestDestination::kManifest:
      return V8RequestDestination::Enum::kManifest;
    case network::mojom::RequestDestination::kObject:
      return V8RequestDestination::Enum::kObject;
    case network::mojom::RequestDestination::kPaintWorklet:
      return V8RequestDestination::Enum::kPaintworklet;
    case network::mojom::RequestDestination::kReport:
      return V8RequestDestination::Enum::kReport;
    case network::mojom::RequestDestination::kScript:
      return V8RequestDestination::Enum::kScript;
    case network::mojom::RequestDestination::kSharedWorker:
      return V8RequestDestination::Enum::kSharedworker;
    case network::mojom::RequestDestination::kStyle:
      return V8RequestDestination::Enum::kStyle;
    case network::mojom::RequestDestination::kTrack:
      return V8RequestDestination::Enum::kTrack;
    case network::mojom::RequestDestination::kVideo:
      return V8RequestDestination::Enum::kVideo;
    case network::mojom::RequestDestination::kWorker:
      return V8RequestDestination::Enum::kWorker;
    case network::mojom::RequestDestination::kXslt:
      return V8RequestDestination::Enum::kXslt;
    case network::mojom::RequestDestination::kFencedframe:
      return V8RequestDestination::Enum::kFencedframe;
    case network::mojom::RequestDestination::kDictionary:
      return V8RequestDestination::Enum::kDictionary;
    case network::mojom::RequestDestination::kSpeculationRules:
      return V8RequestDestination::Enum::kSpeculationrules;
    case network::mojom::RequestDestination::kJson:
      return V8RequestDestination::Enum::kJson;
    case network::mojom::RequestDestination::kServiceWorker:
      return V8RequestDestination::Enum::kServiceworker;
    case network::mojom::RequestDestination::kWebBundle:
      return V8RequestDestination::Enum::kWebbundle;
    case network::mojom::RequestDestination::kWebIdentity:
      return V8RequestDestination::Enum::kWebidentity;
    case network::mojom::RequestDestination::kSharedStorageWorklet:
      return V8RequestDestination::Enum::kSharedstorageworklet;
  }
  NOTREACHED();
}

}  // namespace

FetchRequestData* CreateCopyOfFetchRequestDataForFetch(
    ScriptState* script_state,
    const FetchRequestData* original) {
  ExecutionContext* context = ExecutionContext::From(script_state);
  auto* request = MakeGarbageCollected<FetchRequestData>(context);
  request->SetURL(original->Url());
  request->SetMethod(original->Method());
  request->SetHeaderList(original->HeaderList()->Clone());
  request->SetOrigin(original->Origin() ? original->Origin()
                                        : context->GetSecurityOrigin());
  request->SetNavigationRedirectChain(original->NavigationRedirectChain());
  // FIXME: Set client.
  DOMWrapperWorld& world = script_state->World();
  if (world.IsIsolatedWorld()) {
    request->SetIsolatedWorldOrigin(
        world.IsolatedWorldSecurityOrigin(context->GetAgentClusterID()));
  }
  // FIXME: Set ForceOriginHeaderFlag.
  request->SetReferrerString(original->ReferrerString());
  request->SetReferrerPolicy(original->GetReferrerPolicy());
  request->SetMode(original->Mode());
  request->SetTargetAddressSpace(original->TargetAddressSpace());
  request->SetCredentials(original->Credentials());
  request->SetCacheMode(original->CacheMode());
  request->SetRedirect(original->Redirect());
  request->SetIntegrity(original->Integrity());
  request->SetFetchPriorityHint(original->FetchPriorityHint());
  request->SetPriority(original->Priority());
  request->SetKeepalive(original->Keepalive());
  request->SetBrowsingTopics(original->BrowsingTopics());
  request->SetAdAuctionHeaders(original->AdAuctionHeaders());
  request->SetSharedStorageWritable(original->SharedStorageWritable());
  request->SetIsHistoryNavigation(original->IsHistoryNavigation());
  if (original->URLLoaderFactory()) {
    mojo::PendingRemote<network::mojom::blink::URLLoaderFactory> factory_clone;
    original->URLLoaderFactory()->Clone(
        factory_clone.InitWithNewPipeAndPassReceiver());
    request->SetURLLoaderFactory(std::move(factory_clone));
  }
  request->SetWindowId(original->WindowId());
  request->SetTrustTokenParams(original->TrustTokenParams());
  request->SetAttributionReportingEligibility(
      original->AttributionReportingEligibility());
  request->SetAttributionReportingSupport(original->AttributionSupport());
  request->SetServiceWorkerRaceNetworkRequestToken(
      original->ServiceWorkerRaceNetworkRequestToken());

  // When a new request is created from another the destination is always reset
  // to be `kEmpty`.  In order to facilitate some later checks when a service
  // worker forwards a navigation request we want to keep track of the
  // destination of the original request.  Therefore record the original
  // request's destination if its non-empty, otherwise just carry forward
  // whatever "original destination" value was already set.
  if (original->Destination() != network::mojom::RequestDestination::kEmpty)
    request->SetOriginalDestination(original->Destination());
  else
    request->SetOriginalDestination(original->OriginalDestination());

  return request;
}

static bool AreAnyMembersPresent(const RequestInit* init) {
  return init->hasMethod() || init->hasHeaders() || init->hasBody() ||
         init->hasReferrer() || init->hasReferrerPolicy() || init->hasMode() ||
         init->hasTargetAddressSpace() || init->hasCredentials() ||
         init->hasCache() || init->hasRedirect() || init->hasIntegrity() ||
         init->hasKeepalive() || init->hasBrowsingTopics() ||
         init->hasAdAuctionHeaders() || init->hasSharedStorageWritable() ||
         init->hasPriority() || init->hasSignal() || init->hasDuplex() ||
         init->hasPrivateToken() || init->hasAttributionReporting();
}

static BodyStreamBuffer* ExtractBody(ScriptState* script_state,
                                     ExceptionState& exception_state,
                                     v8::Local<v8::Value> body,
                                     String& content_type,
                                     uint64_t& body_byte_length) {
  DCHECK(!body->IsNull());
  BodyStreamBuffer* return_buffer = nullptr;

  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  v8::Isolate* isolate = script_state->GetIsolate();

  if (Blob* blob = V8Blob::ToWrappable(isolate, body)) {
    body_byte_length = blob->size();
    return_buffer = BodyStreamBuffer::Create(
        script_state,
        MakeGarbageCollected<BlobBytesConsumer>(execution_context,
                                                blob->GetBlobDataHandle()),
        nullptr /* AbortSignal */, /*cached_metadata_handler=*/nullptr);
    content_type = blob->type();
  } else if (body->IsArrayBuffer()) {
    // Avoid calling into V8 from the following constructor parameters, which
    // is potentially unsafe.
    DOMArrayBuffer* array_buffer =
        NativeValueTraits<DOMArrayBuffer>::NativeValue(isolate, body,
                                                       exception_state);
    if (exception_state.HadException())
      return nullptr;
    if (!base::CheckedNumeric<wtf_size_t>(array_buffer->ByteLength())
             .IsValid()) {
      exception_state.ThrowRangeError(
          "The provided ArrayBuffer exceeds the maximum supported size");
      return nullptr;
    }
    body_byte_length = array_buffer->ByteLength();
    return_buffer = BodyStreamBuffer::Create(
        script_state, MakeGarbageCollected<FormDataBytesConsumer>(array_buffer),
        nullptr /* AbortSignal */, /*cached_metadata_handler=*/nullptr);
  } else if (body->IsArrayBufferView()) {
    // Avoid calling into V8 from the following constructor parameters, which
    // is potentially unsafe.
    DOMArrayBufferView* array_buffer_view =
        NativeValueTraits<MaybeShared<DOMArrayBufferView>>::NativeValue(
            isolate, body, exception_state)
            .Get();
    if (exception_state.HadException())
      return nullptr;
    if (!base::CheckedNumeric<wtf_size_t>(array_buffer_view->byteLength())
             .IsValid()) {
      exception_state.ThrowRangeError(
          "The provided ArrayBufferView exceeds the maximum supported size");
      return nullptr;
    }
    body_byte_length = array_buffer_view->byteLength();
    return_buffer = BodyStreamBuffer::Create(
        script_state,
        MakeGarbageCollected<FormDataBytesConsumer>(array_buffer_view),
        nullptr /* AbortSignal */, /*cached_metadata_handler=*/nullptr);
  } else if (FormData* form = V8FormData::ToWrappable(isolate, body)) {
    scoped_refptr<EncodedFormData> form_data = form->EncodeMultiPartFormData();
    // Here we handle formData->boundary() as a C-style string. See
    // FormDataEncoder::generateUniqueBoundaryString.
    content_type = AtomicString("multipart/form-data; boundary=") +
                   form_data->Boundary().data();
    body_byte_length = form_data->SizeInBytes();
    return_buffer = BodyStreamBuffer::Create(
        script_state,
        MakeGarbageCollected<FormDataBytesConsumer>(execution_context,
                                                    std::move(form_data)),
        nullptr /* AbortSignal */, /*cached_metadata_handler=*/nullptr);
  } else if (URLSearchParams* url_search_params =
                 V8URLSearchParams::ToWrappable(isolate, body)) {
    scoped_refptr<EncodedFormData> form_data =
        url_search_params->ToEncodedFormData();
    body_byte_length = form_data->SizeInBytes();
    return_buffer = BodyStreamBuffer::Create(
        script_state,
        MakeGarbageCollected<FormDataBytesConsumer>(execution_context,
                                                    std::move(form_data)),
        nullptr /* AbortSignal */, /*cached_metadata_handler=*/nullptr);
    content_type = "application/x-www-form-urlencoded;charset=UTF-8";
  } else if (ReadableStream* readable_stream =
                 V8ReadableStream::ToWrappable(isolate, body);
             readable_stream &&
             RuntimeEnabledFeatures::FetchUploadStreamingEnabled(
                 execution_context)) {
    // This is implemented in Request::CreateRequestWithRequestOrString():
    //   "If the |keepalive| flag is set, then throw a TypeError."

    //   "If |object| is disturbed or locked, then throw a TypeError."
    if (readable_stream->IsDisturbed()) {
      exception_state.ThrowTypeError(
          "The provided ReadableStream is disturbed");
      return nullptr;
    }
    if (readable_stream->IsLocked()) {
      exception_state.ThrowTypeError("The provided ReadableStream is locked");
      return nullptr;
    }
    //   "Set |stream| to |object|."
    return_buffer = MakeGarbageCollected<BodyStreamBuffer>(
        script_state, readable_stream, /*cached_metadata_handler=*/nullptr);
  } else {
    String string = NativeValueTraits<IDLUSVString>::NativeValue(
        isolate, body, exception_state);
    if (exception_state.HadException())
      return nullptr;

    body_byte_length = string.length();
    return_buffer = BodyStreamBuffer::Create(
        script_state, MakeGarbageCollected<FormDataBytesConsumer>(string),
        nullptr /* AbortSignal */, /*cached_metadata_handler=*/nullptr);
    content_type = "text/plain;charset=UTF-8";
  }

  return return_buffer;
}

Request* Request::CreateRequestWithRequestOrString(
    ScriptState* script_state,
    Request* input_request,
    const String& input_string,
    const RequestInit* init,
    ExceptionState& exception_state) {
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  scoped_refptr<const SecurityOrigin> origin =
      execution_context->GetSecurityOrigin();

  // "Let |signal| be null."
  AbortSignal* signal = nullptr;

  // The spec says:
  // - "Let |window| be client."
  // - "If |request|'s window is an environment settings object and its
  //   origin is same origin with current settings object's origin, set
  //   |window| to |request|'s window."
  // - "If |init|'s window member is present and it is not null, throw a
  //   TypeError."
  // - "If |init|'s window member is present, set |window| to no-window."
  //
  // We partially do this: if |request|'s window is present, it is copied to
  // the new request in the following step. There is no same-origin check
  // because |request|'s window is implemented as |FetchRequestData.window_id_|
  // and is an opaque id that this renderer doesn't understand. It's only set on
  // |input_request| when a service worker intercepted the request from a
  // (same-origin) frame, so it must be same-origin.
  //
  // TODO(yhirano): Add support for |init.window|.

  // "Set |request| to a new request whose url is |request|'s current url,
  // method is |request|'s method, header list is a copy of |request|'s
  // header list, unsafe-request flag is set, client is entry settings object,
  // window is |window|, origin is "client", omit-Origin-header flag is
  // |request|'s omit-Origin-header flag, same-origin data-URL flag is set,
  // referrer is |request|'s referrer, referrer policy is |request|'s
  // referrer policy, destination is the empty string, mode is |request|'s
  // mode, credentials mode is |request|'s credentials mode, cache mode is
  // |request|'s cache mode, redirect mode is |request|'s redirect mode, and
  // integrity metadata is |request|'s integrity metadata."
  FetchRequestData* request = CreateCopyOfFetchRequestDataForFetch(
      script_state, input_request ? input_request->GetRequest()
                                  : MakeGarbageCollected<FetchRequestData>(
                                        execution_context));

  if (input_request) {
    // "Set |signal| to input’s signal."
    signal = input_request->signal_;
  }

  // We don't use fallback values. We set these flags directly in below.
  // - "Let |fallbackMode| be null."
  // - "Let |fallbackCredentials| be null."

  // "Let |baseURL| be entry settings object's API base URL."
  const KURL base_url = execution_context->BaseURL();

  // "If |input| is a string, run these substeps:"
  if (!input_request) {
    // "Let |parsedURL| be the result of parsing |input| with |baseURL|."
    KURL parsed_url = KURL(base_url, input_string);
    // "If |parsedURL| is failure, throw a TypeError."
    if (!parsed_url.IsValid()) {
      exception_state.ThrowTypeError("Failed to parse URL from " +
                                     input_string);
      return nullptr;
    }
    //   "If |parsedURL| includes credentials, throw a TypeError."
    if (!parsed_url.User().empty() || !parsed_url.Pass().empty()) {
      exception_state.ThrowTypeError(
          "Request cannot be constructed from a URL that includes "
          "credentials: " +
          input_string);
      return nullptr;
    }
    // "Set |request|'s url to |parsedURL| and replace |request|'s url list
    // single URL with a copy of |parsedURL|."
    request->SetURL(parsed_url);

    // Parsing URLs should also resolve blob URLs. This is important because
    // fetching of a blob URL should work even after the URL is revoked as long
    // as the request was created while the URL was still valid.
    if (parsed_url.ProtocolIs("blob")) {
      mojo::PendingRemote<network::mojom::blink::URLLoaderFactory>
          url_loader_factory;
      ExecutionContext::From(script_state)
          ->GetPublicURLManager()
          .Resolve(parsed_url,
                   url_loader_factory.InitWithNewPipeAndPassReceiver());
      request->SetURLLoaderFactory(std::move(url_loader_factory));
    }

    // We don't use fallback values. We set these flags directly in below.
    // - "Set |fallbackMode| to "cors"."
    // - "Set |fallbackCredentials| to "omit"."
  }

  // "If any of |init|'s members are present, then:"
  if (AreAnyMembersPresent(init)) {
    request->SetOrigin(execution_context->GetSecurityOrigin());
    request->SetOriginalDestination(network::mojom::RequestDestination::kEmpty);
    request->SetNavigationRedirectChain(Vector<KURL>());

    // "If |request|'s |mode| is "navigate", then set it to "same-origin".
    if (request->Mode() == network::mojom::RequestMode::kNavigate)
      request->SetMode(network::mojom::RequestMode::kSameOrigin);

    // TODO(yhirano): Implement the following substep:
    // "Unset |request|'s reload-navigation flag."

    // "Unset |request|'s history-navigation flag."
    request->SetIsHistoryNavigation(false);

    // "Set |request|’s referrer to "client"."
    request->SetReferrerString(Referrer::ClientReferrerString());

    // "Set |request|’s referrer policy to the empty string."
    request->SetReferrerPolicy(network::mojom::ReferrerPolicy::kDefault);
  }

  // "If init’s referrer member is present, then:"
  if (init->hasReferrer()) {
    // Nothing to do for the step "Let |referrer| be |init|'s referrer
    // member."

    if (init->referrer().empty()) {
      // "If |referrer| is the empty string, set |request|'s referrer to
      // "no-referrer" and terminate these substeps."
      request->SetReferrerString(AtomicString(Referrer::NoReferrer()));
    } else {
      // "Let |parsedReferrer| be the result of parsing |referrer| with
      // |baseURL|."
      KURL parsed_referrer(base_url, init->referrer());
      if (!parsed_referrer.IsValid()) {
        // "If |parsedReferrer| is failure, throw a TypeError."
        exception_state.ThrowTypeError("Referrer '" + init->referrer() +
                                       "' is not a valid URL.");
        return nullptr;
      }
      if ((parsed_referrer.ProtocolIsAbout() &&
           parsed_referrer.Host().empty() &&
           parsed_referrer.GetPath() == "client") ||
          !origin->IsSameOriginWith(
              SecurityOrigin::Create(parsed_referrer).get())) {
        // If |parsedReferrer|'s host is empty
        // it's cannot-be-a-base-URL flag must be set

        // "If one of the following conditions is true, then set
        // request’s referrer to "client":
        //
        //     |parsedReferrer|’s cannot-be-a-base-URL flag is set,
        //     scheme is "about", and path contains a single string "client".
        //
        //     parsedReferrer’s origin is not same origin with origin"
        //
        request->SetReferrerString(Referrer::ClientReferrerString());
      } else {
        // "Set |request|'s referrer to |parsedReferrer|."
        request->SetReferrerString(AtomicString(parsed_referrer.GetString()));
      }
    }
  }

  // "If init's referrerPolicy member is present, set request's referrer
  // policy to it."
  if (init->hasReferrerPolicy()) {
    // In case referrerPolicy = "", the SecurityPolicy method below will not
    // actually set referrer_policy, so we'll default to
    // network::mojom::ReferrerPolicy::kDefault.
    network::mojom::ReferrerPolicy referrer_policy =
        network::mojom::ReferrerPolicy::kDefault;
    switch (init->referrerPolicy().AsEnum()) {
      case V8ReferrerPolicy::Enum::k:
        referrer_policy = network::mojom::ReferrerPolicy::kDefault;
        break;
      case V8ReferrerPolicy::Enum::kNoReferrer:
        referrer_policy = network::mojom::ReferrerPolicy::kNever;
        break;
      case V8ReferrerPolicy::Enum::kNoReferrerWhenDowngrade:
        referrer_policy =
            network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade;
        break;
      case V8ReferrerPolicy::Enum::kSameOrigin:
        referrer_policy = network::mojom::ReferrerPolicy::kSameOrigin;
        break;
      case V8ReferrerPolicy::Enum::kOrigin:
        referrer_policy = network::mojom::ReferrerPolicy::kOrigin;
        break;
      case V8ReferrerPolicy::Enum::kStrictOrigin:
        referrer_policy = network::mojom::ReferrerPolicy::kStrictOrigin;
        break;
      case V8ReferrerPolicy::Enum::kOriginWhenCrossOrigin:
        referrer_policy =
            network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin;
        break;
      case V8ReferrerPolicy::Enum::kStrictOriginWhenCrossOrigin:
        referrer_policy =
            network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin;
        break;
      case V8ReferrerPolicy::Enum::kUnsafeUrl:
        referrer_policy = network::mojom::ReferrerPolicy::kAlways;
        break;
      default:
        NOTREACHED();
    }
    request->SetReferrerPolicy(referrer_policy);
  }

  // The following code performs the following steps:
  // - "Let |mode| be |init|'s mode member if it is present, and
  //   |fallbackMode| otherwise."
  // - "If |mode| is "navigate", throw a TypeError."
  // - "If |mode| is non-null, set |request|'s mode to |mode|."
  if (init->hasMode()) {
    network::mojom::RequestMode mode = V8RequestModeToMojom(init->mode());
    if (mode == network::mojom::RequestMode::kNavigate) {
      exception_state.ThrowTypeError(
          "Cannot construct a Request with a RequestInit whose mode member is "
          "set as 'navigate'.");
      return nullptr;
    }
    request->SetMode(mode);
  } else {
    // |inputRequest| is directly checked here instead of setting and
    // checking |fallbackMode| as specified in the spec.
    if (!input_request)
      request->SetMode(network::mojom::RequestMode::kCors);
  }

  // "If |init|'s priority member is present, set |request|'s priority
  // to it." For more information see Priority Hints at
  // https://wicg.github.io/priority-hints/#fetch-integration
  if (init->hasPriority()) {
    UseCounter::Count(execution_context, WebFeature::kPriorityHints);
    if (init->priority() == "low") {
      request->SetFetchPriorityHint(mojom::blink::FetchPriorityHint::kLow);
    } else if (init->priority() == "high") {
      request->SetFetchPriorityHint(mojom::blink::FetchPriorityHint::kHigh);
    }
  }

  // "Let |credentials| be |init|'s credentials member if it is present, and
  // |fallbackCredentials| otherwise."
  // "If |credentials| is non-null, set |request|'s credentials mode to
  // |credentials|."
  if (init->hasCredentials()) {
    request->SetCredentials(
        V8RequestCredentialsToCredentialsMode(init->credentials().AsEnum()));
  } else if (!input_request) {
    request->SetCredentials(network::mojom::CredentialsMode::kSameOrigin);
  }

  // The following code performs the following steps:
  // - "Let |targetAddressSpace| be |init|'s targetAddressSpace member if it is
  // present, and |unknown| otherwise."
  if (init->hasTargetAddressSpace()) {
    if (init->targetAddressSpace() == "local") {
      request->SetTargetAddressSpace(network::mojom::IPAddressSpace::kLocal);
    } else if (init->targetAddressSpace() == "private") {
      request->SetTargetAddressSpace(network::mojom::IPAddressSpace::kPrivate);
    } else if (init->targetAddressSpace() == "public") {
      request->SetTargetAddressSpace(network::mojom::IPAddressSpace::kPublic);
    } else if (init->targetAddressSpace() == "unknown") {
      request->SetTargetAddressSpace(network::mojom::IPAddressSpace::kUnknown);
    }
  } else {
    request->SetTargetAddressSpace(network::mojom::IPAddressSpace::kUnknown);
  }

  // "If |init|'s cache member is present, set |request|'s cache mode to it."
  if (init->hasCache()) {
    auto&& cache = init->cache();
    if (cache == "default") {
      request->SetCacheMode(mojom::blink::FetchCacheMode::kDefault);
    } else if (cache == "no-store") {
      request->SetCacheMode(mojom::blink::FetchCacheMode::kNoStore);
    } else if (cache == "reload") {
      request->SetCacheMode(mojom::blink::FetchCacheMode::kBypassCache);
    } else if (cache == "no-cache") {
      request->SetCacheMode(mojom::blink::FetchCacheMode::kValidateCache);
    } else if (cache == "force-cache") {
      request->SetCacheMode(mojom::blink::FetchCacheMode::kForceCache);
    } else if (cache == "only-if-cached") {
      request->SetCacheMode(mojom::blink::FetchCacheMode::kOnlyIfCached);
    }
  }

  // If |request|’s cache mode is "only-if-cached" and |request|’s mode is not
  // "same-origin", then throw a TypeError.
  if (request->CacheMode() == mojom::blink::FetchCacheMode::kOnlyIfCached &&
      request->Mode() != network::mojom::RequestMode::kSameOrigin) {
    exception_state.ThrowTypeError(
        "'only-if-cached' can be set only with 'same-origin' mode");
    return nullptr;
  }

  // "If |init|'s redirect member is present, set |request|'s redirect mode
  // to it."
  if (init->hasRedirect()) {
    if (init->redirect() == "follow") {
      request->SetRedirect(network::mojom::RedirectMode::kFollow);
    } else if (init->redirect() == "error") {
      request->SetRedirect(network::mojom::RedirectMode::kError);
    } else if (init->redirect() == "manual") {
      request->SetRedirect(network::mojom::RedirectMode::kManual);
    }
  }

  // "If |init|'s integrity member is present, set |request|'s
  // integrity metadata to it."
  if (init->hasIntegrity())
    request->SetIntegrity(init->integrity());

  if (init->hasKeepalive())
    request->SetKeepalive(init->keepalive());

  if (init->hasBrowsingTopics()) {
    if (!execution_context->IsSecureContext()) {
      exception_state.ThrowTypeError(
          "browsingTopics: Topics operations are only available in secure "
          "contexts.");
      return nullptr;
    }

    request->SetBrowsingTopics(init->browsingTopics());

    if (init->browsingTopics()) {
      UseCounter::Count(execution_context,
                        mojom::blink::WebFeature::kTopicsAPIFetch);
      UseCounter::Count(execution_context,
                        mojom::blink::WebFeature::kTopicsAPIAll);
    }
  }

  if (init->hasAdAuctionHeaders()) {
    if (!execution_context->IsSecureContext()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNotAllowedError,
          "adAuctionHeaders: ad auction operations are only available in "
          "secure contexts.");
      return nullptr;
    }

    request->SetAdAuctionHeaders(init->adAuctionHeaders());
  }

  if (init->hasSharedStorageWritable()) {
    if (!execution_context->IsSecureContext()) {
      exception_state.ThrowTypeError(
          "sharedStorageWritable: sharedStorage operations are only available"
          " in secure contexts.");
      return nullptr;
    }
    if (SecurityOrigin::Create(request->Url())->IsOpaque()) {
      exception_state.ThrowTypeError(
          "sharedStorageWritable: sharedStorage operations are not available"
          " for opaque origins.");
      return nullptr;
    }
    request->SetSharedStorageWritable(init->sharedStorageWritable());
    if (init->sharedStorageWritable()) {
      UseCounter::Count(
          execution_context,
          mojom::blink::WebFeature::kSharedStorageAPI_Fetch_Attribute);
    }
  }

  // "If |init|'s method member is present, let |method| be it and run these
  // substeps:"
  if (init->hasMethod()) {
    // "If |method| is not a method or method is a forbidden method, throw
    // a TypeError."
    if (!IsValidHTTPToken(init->method())) {
      exception_state.ThrowTypeError("'" + init->method() +
                                     "' is not a valid HTTP method.");
      return nullptr;
    }
    if (FetchUtils::IsForbiddenMethod(ini
```