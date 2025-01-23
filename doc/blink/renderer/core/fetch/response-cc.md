Response:
Let's break down the thought process to generate the detailed analysis of `response.cc`.

1. **Understand the Core Request:** The request asks for a functional breakdown of `response.cc`, its relationship to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, common user errors, and how a user operation might lead to this code.

2. **Initial Scan and Keyword Identification:** Quickly read through the code, looking for key terms and patterns. Notice:
    * `#include` statements indicating dependencies (e.g., `mojom/fetch`, `bindings/core/v8`, `core/fetch`). This immediately tells us it's related to network requests and the JavaScript interface.
    * Class and method names like `Response`, `Create`, `error`, `redirect`, `clone`, `status`, `headers`, `blob`, `formData`, `json`. These are strong hints about the functionalities.
    *  Mentions of `Fetch API`, `CORS`, `Headers`, `Body`, `ReadableStream`. These point to the specific web standards being implemented.
    *  Error handling and validation (e.g., `ExceptionState`, `ThrowRangeError`, `ThrowTypeError`).

3. **Categorize Functionality:** Based on the initial scan, group the functionalities into logical categories:
    * **Response Creation:** How `Response` objects are instantiated. Look for `Create` methods.
    * **Response Properties:** Accessors for information like status, URL, headers, etc. Look for `get` methods or simple member accessors.
    * **Response Body Handling:**  How different body types (Blob, FormData, ArrayBuffer, etc.) are processed. Look for code dealing with `BodyStreamBuffer`, `BlobBytesConsumer`, `FormDataBytesConsumer`.
    * **Response Modification/Manipulation:**  Methods like `clone`, `redirect`.
    * **Internal Data Handling:**  Methods for accessing the underlying `FetchResponseData`.
    * **Error Handling:**  Methods like `error()`.
    * **Filtering:**  Mechanisms for applying CORS restrictions (`FilterResponseData`).

4. **Analyze Individual Functions/Code Blocks:** Go through the code more systematically, function by function, or even significant code blocks within functions. For each:
    * **Purpose:** What is this code supposed to do?
    * **Inputs:** What parameters does it take?  What are their types?
    * **Outputs:** What does it return? What side effects does it have (e.g., setting internal state)?
    * **Logic:**  How does it achieve its purpose? Are there conditional branches, loops, specific algorithms?
    * **Connections to Web Standards:**  Does it implement parts of the Fetch API or other relevant specs?  Look for comments referencing the spec.
    * **Potential Errors:** What could go wrong? What validations are in place?

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Think about how the functionalities in `response.cc` manifest in web development:
    * **JavaScript:**  The `Response` object is directly exposed to JavaScript. Methods like `response.json()`, `response.text()`, `response.blob()`, `response.headers.get()` directly interact with the code in this file. The `fetch()` API returns `Response` objects.
    * **HTML:**  While not directly interacting, HTML triggers network requests (e.g., `<img>`, `<script>`, `<a>`, `<form>`), which eventually lead to `Response` objects being created.
    * **CSS:** Similar to HTML, CSS files are fetched, and the browser processes the resulting `Response`.

6. **Develop Examples and Scenarios:** Create concrete examples to illustrate the functionality and connections:
    * **JavaScript Interaction:** Show how to use `fetch()` and access `Response` properties and methods.
    * **HTML/CSS Interaction:**  Explain how loading resources involves fetching and processing responses.
    * **Logical Reasoning:**  Pick a specific function (like `redirect`) and trace its logic with example inputs and outputs.
    * **User Errors:** Think about common mistakes developers make when working with the Fetch API (e.g., trying to read the body twice, providing invalid status codes).

7. **Consider User Actions and Debugging:**  Imagine how a user's action in the browser could lead to this code being executed. Think about the sequence of events: user clicks a link, browser initiates a request, server sends a response, Blink processes the response, and `response.cc` plays a role. For debugging, consider logging or breakpoints within this file to inspect the state of `Response` objects.

8. **Structure and Refine:** Organize the information logically into the requested sections. Use clear and concise language. Provide code snippets where appropriate. Review and refine the explanation for accuracy and completeness. Ensure the examples are illustrative and easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus too much on the C++ details. **Correction:** Shift focus to the *functionality* and how it relates to the user and web development.
* **Overlook connections:** Miss some obvious links between the C++ code and the JavaScript Fetch API. **Correction:**  Explicitly map C++ methods to their JavaScript counterparts.
* **Vague explanations:** Use overly technical terms without sufficient explanation. **Correction:**  Explain concepts in a way that's accessible to a broader audience, including web developers who may not be C++ experts.
* **Lack of concrete examples:** Describe functionality without showing how it's used. **Correction:** Provide code examples to illustrate the concepts.
* **Insufficient debugging information:**  Not enough detail on how a developer would actually encounter this code during debugging. **Correction:**  Add a section on user actions and debugging strategies.

By following this detailed thought process, iteratively building upon initial observations, and refining the explanation, we arrive at the comprehensive analysis of `response.cc`.
好的，让我们来详细分析 `blink/renderer/core/fetch/response.cc` 这个文件。

**文件功能概要:**

`response.cc` 文件是 Chromium Blink 渲染引擎中处理 HTTP 响应的核心组件。它定义了 `Response` 类，该类是对 Fetch API 中 `Response` 接口的 C++ 实现。其主要功能包括：

1. **表示 HTTP 响应:** 存储和管理从网络或缓存中获取的 HTTP 响应的各种属性，例如状态码、状态文本、头部信息、URL 列表以及响应体。
2. **提供 JavaScript 接口:**  通过 Blink 的绑定机制，将 `Response` 类的功能暴露给 JavaScript，使得网页脚本可以使用 Fetch API 来操作和访问响应数据。
3. **处理响应体:**  支持不同类型的响应体，包括文本、JSON、Blob、ArrayBuffer、FormData 和 ReadableStream，并提供相应的处理逻辑。
4. **实现 CORS 过滤:**  根据 CORS (跨域资源共享) 策略过滤响应头部，确保安全性。
5. **支持创建和操作 `Response` 对象:** 提供静态方法用于创建不同类型的 `Response` 对象，例如成功响应、错误响应、重定向响应等。
6. **克隆 `Response` 对象:**  允许创建 `Response` 对象的副本。
7. **与底层网络模块交互:**  接收来自 Chromium 网络栈的响应数据，并将其转换为 `Response` 对象。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`response.cc` 文件是浏览器实现 Web 标准 Fetch API 的关键部分，因此与 JavaScript, HTML, CSS 都有密切关系：

**1. 与 JavaScript 的关系 (最直接):**

* **Fetch API 的核心:** JavaScript 通过 `fetch()` 函数发起网络请求，服务器返回的响应在 Blink 内部会被创建为一个 `Response` 对象（对应 `response.cc` 中实现的 `Response` 类）。
* **访问响应属性和方法:** JavaScript 可以通过 `Response` 对象访问响应的各种属性和方法，这些属性和方法在 `response.cc` 中有相应的实现：
    * `response.status`: 获取 HTTP 状态码 (对应 `Response::status()`).
    * `response.statusText`: 获取 HTTP 状态文本 (对应 `Response::statusText()`).
    * `response.headers`: 获取响应头 (对应 `Response::headers()`).
    * `response.url`: 获取响应的 URL (对应 `Response::url()`).
    * `response.ok`: 判断响应状态是否成功 (200-299) (对应 `Response::ok()`).
    * `response.redirected`: 判断响应是否发生重定向 (对应 `Response::redirected()`).
    * `response.text()`: 将响应体作为文本读取 (对应 `Body::Text()`, 在 `response.cc` 中使用 `Body` 基类).
    * `response.json()`: 将响应体解析为 JSON (对应 `Body::Json()`).
    * `response.blob()`: 将响应体作为 Blob 对象读取 (对应 `Body::Blob()`).
    * `response.arrayBuffer()`: 将响应体作为 ArrayBuffer 读取 (对应 `Body::ArrayBuffer()`).
    * `response.formData()`: 将响应体作为 FormData 对象读取 (对应 `Body::FormData()`).
    * `response.body`: 获取响应体的 ReadableStream (对应 `Response::body()`, 基于 `Body` 基类).
    * `response.clone()`: 克隆一个 `Response` 对象 (对应 `Response::clone()`).
    * `Response.error()`: 创建一个网络错误的 `Response` 对象 (对应 `Response::error()`).
    * `Response.redirect()`: 创建一个重定向的 `Response` 对象 (对应 `Response::redirect()`).
    * `Response.json()`: 创建一个包含 JSON 数据的 `Response` 对象 (对应 `Response::staticJson()`).
    * `response.type`: 获取响应类型 (basic, cors, default, error, opaque, opaqueredirect) (对应 `Response::type()`).

   **举例:**

   ```javascript
   fetch('https://example.com/data.json')
     .then(response => {
       console.log(response.status); // 打印状态码
       console.log(response.headers.get('Content-Type')); // 打印 Content-Type 头
       return response.json(); // 将响应体解析为 JSON
     })
     .then(data => {
       console.log(data); // 处理 JSON 数据
     })
     .catch(error => {
       console.error('Fetch error:', error);
     });
   ```

**2. 与 HTML 的关系:**

* **资源加载:** 当浏览器解析 HTML 文档时，会遇到各种需要加载的资源，如图片 (`<img>`)、脚本 (`<script>`)、样式表 (`<link rel="stylesheet">`) 等。这些资源的加载过程会触发网络请求，并最终生成 `Response` 对象。
* **表单提交:**  HTML 表单 (`<form>`) 提交时，浏览器会发起 POST 或 GET 请求，服务器的响应也会被封装成 `Response` 对象。

   **举例:**

   ```html
   <!DOCTYPE html>
   <html>
   <head>
     <title>Example</title>
     <link rel="stylesheet" href="style.css">
   </head>
   <body>
     <img src="image.png" alt="An image">
     <script src="script.js"></script>
   </body>
   </html>
   ```

   当浏览器加载这个 HTML 页面时，会分别对 `style.css` 和 `image.png` 以及 `script.js` 发起请求，每个请求的响应都会在 Blink 内部被创建为 `Response` 对象。

**3. 与 CSS 的关系:**

* **CSS 文件加载:** 浏览器加载 CSS 文件时，会发起 HTTP 请求，服务器返回的 CSS 文件内容会被封装到 `Response` 对象中。浏览器解析 CSSOM (CSS Object Model) 的过程会读取这个 `Response` 对象的响应体。

   **举例:**

   在上面的 HTML 例子中， `<link rel="stylesheet" href="style.css">` 标签会导致浏览器请求 `style.css` 文件。 `response.cc` 会参与处理这个请求的响应。

**逻辑推理举例 (假设输入与输出):**

**场景:** JavaScript 代码使用 `fetch()` 请求一个 JSON 文件。

**假设输入:**

* **网络请求:**  一个 GET 请求发送到 `https://api.example.com/users`.
* **服务器响应:**
    * **状态码:** 200 OK
    * **状态文本:** OK
    * **Headers:**
        * `Content-Type: application/json; charset=utf-8`
        * `Date: Tue, 23 May 2023 10:00:00 GMT`
    * **Body:** `[{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]`

**`response.cc` 中的逻辑推理和处理 (简化描述):**

1. **接收网络数据:** Blink 的网络模块接收到来自服务器的响应数据。
2. **创建 `FetchResponseData`:**  在 `Response::CreateUnfilteredFetchResponseDataWithoutBody` 中，根据接收到的数据创建一个 `FetchResponseData` 对象，包含状态码、状态文本、头部信息等。
3. **设置响应体:**  根据 `Content-Type` 头部判断响应体类型，并将响应体数据存储在 `BodyStreamBuffer` 中。
4. **创建 `Response` 对象:** 在 `Response::Create` 中，使用 `FetchResponseData` 创建一个 `Response` 对象。
5. **MIME 类型提取:** 在 `Response::CreateUnfilteredFetchResponseDataWithoutBody` 中，从 `Content-Type` 头部提取 MIME 类型 `application/json`。
6. **JavaScript 访问:** 当 JavaScript 调用 `response.json()` 时，会调用 `Body::Json()`，该方法会解析 `BodyStreamBuffer` 中的 JSON 数据并返回 JavaScript 对象。

**假设输出 (JavaScript 中):**

```javascript
fetch('https://api.example.com/users')
  .then(response => {
    console.log(response.status); // 输出: 200
    console.log(response.statusText); // 输出: OK
    console.log(response.headers.get('content-type')); // 输出: application/json; charset=utf-8
    return response.json();
  })
  .then(users => {
    console.log(users); // 输出: [{id: 1, name: "Alice"}, {id: 2, name: "Bob"}]
  });
```

**用户或编程常见的使用错误及举例说明:**

1. **尝试多次读取响应体:**  `Response` 的 body 只能读取一次。如果尝试多次调用 `response.json()` 或 `response.text()` 等方法，会抛出错误。

   **错误示例:**

   ```javascript
   fetch('https://example.com/data.json')
     .then(response => {
       response.json().then(data1 => console.log(data1));
       response.json().then(data2 => console.log(data2)); // 错误：body 已被使用
     });
   ```
   **`response.cc` 的相关处理:** `IsBodyUsed()` 方法会检查 body 是否已被读取，如果已被读取则在 `Body::Json()`, `Body::Text()` 等方法中抛出 `TypeError`。

2. **在状态码为 204 或 205 的响应中尝试读取 body:**  这些状态码表示没有响应体。尝试读取会返回 rejected 的 Promise。

   **错误示例:**

   ```javascript
   fetch('https://example.com/no-content') // 假设返回 204 No Content
     .then(response => {
       console.log(response.status); // 输出: 204
       return response.json(); // 会被 reject
     })
     .catch(error => console.error(error)); // 捕获错误
   ```
   **`response.cc` 的相关处理:**  `IsNullBodyStatus()` 函数用于判断状态码是否为 null body status。在 `Response::Create` 中，如果尝试创建一个具有 null body status 且有 body 的 Response 对象，会抛出 `TypeError`。

3. **提供无效的状态码或状态文本创建 `Response` 对象:** 使用 `Response()` 构造函数时，提供的状态码必须在 200-599 之间，状态文本必须符合规范。

   **错误示例:**

   ```javascript
   const response = new Response('body', { status: 100, statusText: 'Invalid Status' }); // 抛出 RangeError 和 TypeError
   ```
   **`response.cc` 的相关处理:** `Response::Create` 中会检查状态码的范围 (`status < 200 || 599 < status`)，如果超出范围则抛出 `RangeError`。同时会使用 `IsValidReasonPhrase()` 检查状态文本的有效性，无效则抛出 `TypeError`。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户操作 (例如):** 用户在浏览器地址栏输入 URL 并按下回车，或者点击了页面上的一个链接，或者页面上的 JavaScript 代码执行了 `fetch()` 函数。

2. **浏览器发起网络请求:** 浏览器内核根据用户操作或 JavaScript 代码的指示，构建并发送 HTTP 请求到服务器。

3. **Chromium 网络栈处理请求:** Chromium 的网络栈 (位于 `//net` 目录) 负责处理网络请求的发送和接收。

4. **接收服务器响应:** 服务器返回 HTTP 响应数据。

5. **网络栈传递响应数据给 Blink:**  网络栈接收到响应后，会将响应头、状态码、以及响应体数据传递给 Blink 渲染引擎。

6. **Blink 创建 `FetchResponseData`:** 在 `blink/renderer/core/loader/` 或 `blink/renderer/modules/` 目录下与网络请求相关的代码中，会调用 `response.cc` 中的 `Response::CreateUnfilteredFetchResponseDataWithoutBody` 或类似的函数，根据接收到的网络数据创建一个 `FetchResponseData` 对象。

7. **创建 `Response` 对象:** 接着会调用 `Response::Create` 方法，基于 `FetchResponseData` 创建一个 JavaScript 可访问的 `Response` 对象。

8. **JavaScript 代码访问 `Response` 对象:** 如果是 JavaScript 发起的 `fetch()` 请求，Promise 会 resolve 并返回创建的 `Response` 对象，JavaScript 代码可以进一步操作这个对象。

**调试线索:**

* **在 `fetch()` 调用处设置断点:** 如果问题与特定的网络请求有关，可以在 JavaScript 代码中发起 `fetch()` 请求的地方设置断点，查看 `response` 对象的内容。
* **在 `response.cc` 中设置断点:**  如果怀疑问题出在 `Response` 对象的创建或属性处理上，可以在 `response.cc` 中相关的 `Create` 方法、属性 getter 方法 (如 `status()`, `headers()`) 或 body 处理方法 (如 `Body::Json()`, `Body::Text()`) 设置断点。
* **查看网络面板:**  浏览器的开发者工具的网络面板可以查看详细的请求和响应信息，包括请求头、响应头、状态码、响应体等，这有助于判断服务器返回的数据是否符合预期。
* **使用 `console.log()` 输出 `Response` 对象:** 在 JavaScript 代码中，可以将 `response` 对象打印到控制台，查看其属性值。

总而言之，`blink/renderer/core/fetch/response.cc` 是 Blink 引擎中实现 Fetch API `Response` 接口的关键 C++ 文件，它连接了底层的网络数据和上层的 JavaScript 代码，负责表示、处理和提供 HTTP 响应信息。理解其功能对于理解浏览器如何处理网络请求以及如何调试与 Fetch API 相关的问题至关重要。

### 提示词
```
这是目录为blink/renderer/core/fetch/response.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/fetch/response.h"

#include <memory>
#include <optional>

#include "base/memory/scoped_refptr.h"
#include "services/network/public/cpp/header_util.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_response.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/dictionary.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_blob.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_form_data.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_response_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_response_type.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_url_search_params.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fetch/blob_bytes_consumer.h"
#include "third_party/blink/renderer/core/fetch/body_stream_buffer.h"
#include "third_party/blink/renderer/core/fetch/form_data_bytes_consumer.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/forms/form_data.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_view.h"
#include "third_party/blink/renderer/core/url/url_search_params.h"
#include "third_party/blink/renderer/platform/bindings/exception_messages.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/cors/cors.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_utils.h"
#include "third_party/blink/renderer/platform/network/encoded_form_data.h"
#include "third_party/blink/renderer/platform/network/http_header_map.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/network/network_utils.h"

namespace blink {

namespace {

template <typename CorsHeadersContainer>
FetchResponseData* FilterResponseDataInternal(
    network::mojom::FetchResponseType response_type,
    FetchResponseData* response,
    CorsHeadersContainer& headers) {
  switch (response_type) {
    case network::mojom::FetchResponseType::kBasic:
      return response->CreateBasicFilteredResponse();
      break;
    case network::mojom::FetchResponseType::kCors: {
      HTTPHeaderSet header_names;
      for (const auto& header : headers)
        header_names.insert(header.Ascii());
      return response->CreateCorsFilteredResponse(header_names);
      break;
    }
    case network::mojom::FetchResponseType::kOpaque:
      return response->CreateOpaqueFilteredResponse();
      break;
    case network::mojom::FetchResponseType::kOpaqueRedirect:
      return response->CreateOpaqueRedirectFilteredResponse();
      break;
    case network::mojom::FetchResponseType::kDefault:
      return response;
      break;
    case network::mojom::FetchResponseType::kError:
      DCHECK_EQ(response->GetType(), network::mojom::FetchResponseType::kError);
      return response;
      break;
  }
  return response;
}

FetchResponseData* CreateFetchResponseDataFromFetchAPIResponse(
    ScriptState* script_state,
    mojom::blink::FetchAPIResponse& fetch_api_response) {
  FetchResponseData* response =
      Response::CreateUnfilteredFetchResponseDataWithoutBody(
          script_state, fetch_api_response);

  if (fetch_api_response.blob) {
    response->ReplaceBodyStreamBuffer(BodyStreamBuffer::Create(
        script_state,
        MakeGarbageCollected<BlobBytesConsumer>(
            ExecutionContext::From(script_state), fetch_api_response.blob),
        nullptr /* AbortSignal */, /*cached_metadata_handler=*/nullptr,
        fetch_api_response.side_data_blob));
  }

  // Filter the response according to |fetch_api_response|'s ResponseType.
  response =
      FilterResponseDataInternal(fetch_api_response.response_type, response,
                                 fetch_api_response.cors_exposed_header_names);

  return response;
}

// Checks whether |status| is a null body status.
// Spec: https://fetch.spec.whatwg.org/#null-body-status
bool IsNullBodyStatus(uint16_t status) {
  if (status == 101 || status == 204 || status == 205 || status == 304)
    return true;

  return false;
}

// Check whether |statusText| is a ByteString and
// matches the Reason-Phrase token production.
// RFC 2616: https://tools.ietf.org/html/rfc2616
// RFC 7230: https://tools.ietf.org/html/rfc7230
// "reason-phrase = *( HTAB / SP / VCHAR / obs-text )"
bool IsValidReasonPhrase(const String& status_text) {
  for (unsigned i = 0; i < status_text.length(); ++i) {
    UChar c = status_text[i];
    if (!(c == 0x09                      // HTAB
          || (0x20 <= c && c <= 0x7E)    // SP / VCHAR
          || (0x80 <= c && c <= 0xFF)))  // obs-text
      return false;
  }
  return true;
}

}  // namespace

Response* Response::Create(ScriptState* script_state,
                           ExceptionState& exception_state) {
  return Create(script_state, nullptr, String(), ResponseInit::Create(),
                exception_state);
}

Response* Response::Create(ScriptState* script_state,
                           ScriptValue body_value,
                           const ResponseInit* init,
                           ExceptionState& exception_state) {
  v8::Local<v8::Value> body = body_value.V8Value();
  v8::Isolate* isolate = script_state->GetIsolate();
  ExecutionContext* execution_context = ExecutionContext::From(script_state);

  BodyStreamBuffer* body_buffer = nullptr;
  String content_type;
  if (body_value.IsUndefined() || body_value.IsNull()) {
    // Note: The IDL processor cannot handle this situation. See
    // https://crbug.com/335871.
  } else if (Blob* blob = V8Blob::ToWrappable(isolate, body)) {
    body_buffer = BodyStreamBuffer::Create(
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
    } else {
      body_buffer = BodyStreamBuffer::Create(
          script_state,
          MakeGarbageCollected<FormDataBytesConsumer>(array_buffer),
          nullptr /* AbortSignal */, /*cached_metadata_handler=*/nullptr);
    }
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
    } else {
      body_buffer = BodyStreamBuffer::Create(
          script_state,
          MakeGarbageCollected<FormDataBytesConsumer>(array_buffer_view),
          nullptr /* AbortSignal */, /*cached_metadata_handler=*/nullptr);
    }
  } else if (FormData* form = V8FormData::ToWrappable(isolate, body)) {
    scoped_refptr<EncodedFormData> form_data = form->EncodeMultiPartFormData();
    // Here we handle formData->boundary() as a C-style string. See
    // FormDataEncoder::generateUniqueBoundaryString.
    content_type = AtomicString("multipart/form-data; boundary=") +
                   form_data->Boundary().data();
    body_buffer = BodyStreamBuffer::Create(
        script_state,
        MakeGarbageCollected<FormDataBytesConsumer>(execution_context,
                                                    std::move(form_data)),
        nullptr /* AbortSignal */, /*cached_metadata_handler=*/nullptr);
  } else if (URLSearchParams* url_search_params =
                 V8URLSearchParams::ToWrappable(isolate, body)) {
    scoped_refptr<EncodedFormData> form_data =
        url_search_params->ToEncodedFormData();
    body_buffer = BodyStreamBuffer::Create(
        script_state,
        MakeGarbageCollected<FormDataBytesConsumer>(execution_context,
                                                    std::move(form_data)),
        nullptr /* AbortSignal */, /*cached_metadata_handler=*/nullptr);
    content_type = "application/x-www-form-urlencoded;charset=UTF-8";
  } else if (ReadableStream* stream =
                 V8ReadableStream::ToWrappable(isolate, body)) {
    UseCounter::Count(execution_context,
                      WebFeature::kFetchResponseConstructionWithStream);
    body_buffer = MakeGarbageCollected<BodyStreamBuffer>(
        script_state, stream, /*cached_metadata_handler=*/nullptr);
  } else {
    String string = NativeValueTraits<IDLUSVString>::NativeValue(
        isolate, body, exception_state);
    if (exception_state.HadException())
      return nullptr;
    body_buffer = BodyStreamBuffer::Create(
        script_state, MakeGarbageCollected<FormDataBytesConsumer>(string),
        nullptr /* AbortSignal */, /*cached_metadata_handler=*/nullptr);
    content_type = "text/plain;charset=UTF-8";
  }
  return Create(script_state, body_buffer, content_type, init, exception_state);
}

Response* Response::Create(ScriptState* script_state,
                           BodyStreamBuffer* body,
                           const String& content_type,
                           const ResponseInit* init,
                           ExceptionState& exception_state) {
  uint16_t status = init->status();

  // "1. If |init|'s status member is not in the range 200 to 599, inclusive,
  // throw a RangeError."
  if (status < 200 || 599 < status) {
    exception_state.ThrowRangeError(
        ExceptionMessages::IndexOutsideRange<unsigned>(
            "status", status, 200, ExceptionMessages::kInclusiveBound, 599,
            ExceptionMessages::kInclusiveBound));
    return nullptr;
  }

  // "2. If |init|'s statusText member does not match the Reason-Phrase
  // token production, throw a TypeError."
  if (!IsValidReasonPhrase(init->statusText())) {
    exception_state.ThrowTypeError("Invalid statusText");
    return nullptr;
  }

  // "3. Let |r| be a new Response object, associated with a new response.
  // "4. Set |r|'s headers to a new Headers object whose list is
  // |r|'s response's header list, and guard is "response" "
  Response* r =
      MakeGarbageCollected<Response>(ExecutionContext::From(script_state));
  // "5. Set |r|'s response's status to |init|'s status member."
  r->response_->SetStatus(init->status());

  // "6. Set |r|'s response's status message to |init|'s statusText member."
  r->response_->SetStatusMessage(AtomicString(init->statusText()));

  // "7. If |init|'s headers exists, then fill |r|’s headers with
  // |init|'s headers"
  if (init->hasHeaders()) {
    // "1. Empty |r|'s response's header list."
    r->response_->HeaderList()->ClearList();
    // "2. Fill |r|'s Headers object with |init|'s headers member. Rethrow
    // any exceptions."
    r->headers_->FillWith(script_state, init->headers(), exception_state);
    if (exception_state.HadException())
      return nullptr;
  }
  // "8. If body is non-null, then:"
  if (body) {
    // "1. If |init|'s status is a null body status, then throw a TypeError."
    if (IsNullBodyStatus(status)) {
      exception_state.ThrowTypeError(
          "Response with null body status cannot have body");
      return nullptr;
    }
    // "2. Let |Content-Type| be null."
    // "3. Set |r|'s response's body and |Content-Type|
    // to the result of extracting body."
    // https://fetch.spec.whatwg.org/#concept-bodyinit-extract
    // Step 5, Blob:
    // "If object's type attribute is not the empty byte sequence, set
    // Content-Type to its value."
    r->response_->ReplaceBodyStreamBuffer(body);

    // https://fetch.spec.whatwg.org/#concept-bodyinit-extract
    // Step 5, ReadableStream:
    // "If object is disturbed or locked, then throw a TypeError."
    // If the BodyStreamBuffer was not constructed from a ReadableStream
    // then IsStreamLocked and IsStreamDisturbed will always be false.
    // So we don't have to check BodyStreamBuffer is a ReadableStream
    // or not.
    if (body->IsStreamLocked() || body->IsStreamDisturbed()) {
      exception_state.ThrowTypeError(
          "Response body object should not be disturbed or locked");
      return nullptr;
    }

    // "4. If |Content-Type| is non-null and |r|'s response's header list
    // contains no header named `Content-Type`, append `Content-Type`/
    // |Content-Type| to |r|'s response's header list."
    if (!content_type.empty() &&
        !r->response_->HeaderList()->Has("Content-Type"))
      r->response_->HeaderList()->Append("Content-Type", content_type);
  }

  // "9. Set |r|'s MIME type to the result of extracting a MIME type
  // from |r|'s response's header list."
  r->response_->SetMimeType(r->response_->HeaderList()->ExtractMIMEType());

  // "10. Set |r|'s response’s HTTPS state to current settings object's"
  // HTTPS state."
  // "11. Resolve |r|'s trailer promise with a new Headers object whose
  // guard is "immutable"."
  // "12. Return |r|."
  return r;
}

Response* Response::Create(ExecutionContext* context,
                           FetchResponseData* response) {
  return MakeGarbageCollected<Response>(context, response);
}

Response* Response::Create(ScriptState* script_state,
                           mojom::blink::FetchAPIResponse& response) {
  auto* fetch_response_data =
      CreateFetchResponseDataFromFetchAPIResponse(script_state, response);
  return MakeGarbageCollected<Response>(ExecutionContext::From(script_state),
                                        fetch_response_data);
}

Response* Response::error(ScriptState* script_state) {
  FetchResponseData* response_data =
      FetchResponseData::CreateNetworkErrorResponse();
  Response* r = MakeGarbageCollected<Response>(
      ExecutionContext::From(script_state), response_data);
  r->headers_->SetGuard(Headers::kImmutableGuard);
  return r;
}

Response* Response::redirect(ScriptState* script_state,
                             const String& url,
                             uint16_t status,
                             ExceptionState& exception_state) {
  KURL parsed_url = ExecutionContext::From(script_state)->CompleteURL(url);
  if (!parsed_url.IsValid()) {
    exception_state.ThrowTypeError("Failed to parse URL from " + url);
    return nullptr;
  }

  if (!network_utils::IsRedirectResponseCode(status)) {
    exception_state.ThrowRangeError("Invalid status code");
    return nullptr;
  }

  Response* r =
      MakeGarbageCollected<Response>(ExecutionContext::From(script_state));
  r->headers_->SetGuard(Headers::kImmutableGuard);
  r->response_->SetStatus(status);
  r->response_->HeaderList()->Set("Location", parsed_url);

  return r;
}

Response* Response::staticJson(ScriptState* script_state,
                               ScriptValue data,
                               const ResponseInit* init,
                               ExceptionState& exception_state) {
  // "1. Let bytes the result of running serialize a JavaScript value to JSON
  // bytes on data."
  v8::Local<v8::String> v8_string;
  TryRethrowScope rethrow_scope(script_state->GetIsolate(), exception_state);
  if (!v8::JSON::Stringify(script_state->GetContext(), data.V8Value())
           .ToLocal(&v8_string)) {
    return nullptr;
  }

  String string = ToBlinkString<String>(script_state->GetIsolate(), v8_string,
                                        kDoNotExternalize);

  // JSON.stringify can fail to produce a string value in one of two ways: it
  // can throw an exception (as with unserializable objects), or it can return
  // `undefined` (as with e.g. passing a function). If JSON.stringify returns
  // `undefined`, the v8 API then coerces it to the string value "undefined".
  // Check for this, and consider it a failure.
  if (string == "undefined") {
    exception_state.ThrowTypeError("The data is not JSON serializable");
    return nullptr;
  }

  BodyStreamBuffer* body_buffer = BodyStreamBuffer::Create(
      script_state, MakeGarbageCollected<FormDataBytesConsumer>(string),
      /*abort_signal=*/nullptr, /*cached_metadata_handler=*/nullptr);
  String content_type = "application/json";

  return Create(script_state, body_buffer, content_type, init, exception_state);
}

FetchResponseData* Response::CreateUnfilteredFetchResponseDataWithoutBody(
    ScriptState* script_state,
    mojom::blink::FetchAPIResponse& fetch_api_response) {
  FetchResponseData* response = nullptr;
  if (fetch_api_response.status_code > 0)
    response = FetchResponseData::Create();
  else
    response = FetchResponseData::CreateNetworkErrorResponse();

  response->SetPadding(fetch_api_response.padding);
  response->SetResponseSource(fetch_api_response.response_source);
  response->SetURLList(fetch_api_response.url_list);
  response->SetStatus(fetch_api_response.status_code);
  response->SetStatusMessage(WTF::AtomicString(fetch_api_response.status_text));
  response->SetRequestMethod(
      WTF::AtomicString(fetch_api_response.request_method));
  response->SetResponseTime(fetch_api_response.response_time);
  response->SetCacheStorageCacheName(
      fetch_api_response.cache_storage_cache_name);
  response->SetConnectionInfo(fetch_api_response.connection_info);
  response->SetAlpnNegotiatedProtocol(
      WTF::AtomicString(fetch_api_response.alpn_negotiated_protocol));
  response->SetWasFetchedViaSpdy(fetch_api_response.was_fetched_via_spdy);
  response->SetHasRangeRequested(fetch_api_response.has_range_requested);
  response->SetRequestIncludeCredentials(
      fetch_api_response.request_include_credentials);

  for (const auto& header : fetch_api_response.headers)
    response->HeaderList()->Append(header.key, header.value);

  // Use the |mime_type| provided by the FetchAPIResponse if its set.
  // Otherwise fall back to extracting the mime type from the headers.  This
  // can happen when the response is loaded from an older cache_storage
  // instance that did not yet store the mime_type value.
  if (!fetch_api_response.mime_type.IsNull())
    response->SetMimeType(fetch_api_response.mime_type);
  else
    response->SetMimeType(response->HeaderList()->ExtractMIMEType());

  return response;
}

FetchResponseData* Response::FilterResponseData(
    network::mojom::FetchResponseType response_type,
    FetchResponseData* response,
    WTF::Vector<WTF::String>& headers) {
  return FilterResponseDataInternal(response_type, response, headers);
}

V8ResponseType Response::type() const {
  // "The type attribute's getter must return response's type."
  switch (response_->GetType()) {
    case network::mojom::FetchResponseType::kBasic:
      return V8ResponseType(V8ResponseType::Enum::kBasic);
    case network::mojom::FetchResponseType::kCors:
      return V8ResponseType(V8ResponseType::Enum::kCors);
    case network::mojom::FetchResponseType::kDefault:
      return V8ResponseType(V8ResponseType::Enum::kDefault);
    case network::mojom::FetchResponseType::kError:
      return V8ResponseType(V8ResponseType::Enum::kError);
    case network::mojom::FetchResponseType::kOpaque:
      return V8ResponseType(V8ResponseType::Enum::kOpaque);
    case network::mojom::FetchResponseType::kOpaqueRedirect:
      return V8ResponseType(V8ResponseType::Enum::kOpaqueredirect);
  }
  NOTREACHED();
}

String Response::url() const {
  // "The url attribute's getter must return the empty string if response's
  // url is null and response's url, serialized with the exclude fragment
  // flag set, otherwise."
  const KURL* response_url = response_->Url();
  if (!response_url)
    return g_empty_string;
  if (!response_url->HasFragmentIdentifier())
    return *response_url;
  KURL url(*response_url);
  url.RemoveFragmentIdentifier();
  return url;
}

bool Response::redirected() const {
  return response_->UrlList().size() > 1;
}

uint16_t Response::status() const {
  // "The status attribute's getter must return response's status."
  return response_->Status();
}

bool Response::ok() const {
  // "The ok attribute's getter must return true
  // if response's status is in the range 200 to 299, and false otherwise."
  return network::IsSuccessfulStatus(status());
}

String Response::statusText() const {
  // "The statusText attribute's getter must return response's status message."
  return response_->StatusMessage();
}

Headers* Response::headers() const {
  // "The headers attribute's getter must return the associated Headers object."
  return headers_.Get();
}

Response* Response::clone(ScriptState* script_state,
                          ExceptionState& exception_state) {
  if (IsBodyLocked() || IsBodyUsed()) {
    exception_state.ThrowTypeError("Response body is already used");
    return nullptr;
  }

  FetchResponseData* response = response_->Clone(script_state, exception_state);
  if (exception_state.HadException())
    return nullptr;
  Headers* headers = Headers::Create(response->HeaderList());
  headers->SetGuard(headers_->GetGuard());
  return MakeGarbageCollected<Response>(GetExecutionContext(), response,
                                        headers);
}

mojom::blink::FetchAPIResponsePtr Response::PopulateFetchAPIResponse(
    const KURL& request_url) {
  return response_->PopulateFetchAPIResponse(request_url);
}

Response::Response(ExecutionContext* context)
    : Response(context, FetchResponseData::Create()) {}

Response::Response(ExecutionContext* context, FetchResponseData* response)
    : Response(context, response, Headers::Create(response->HeaderList())) {
  headers_->SetGuard(Headers::kResponseGuard);
}

Response::Response(ExecutionContext* context,
                   FetchResponseData* response,
                   Headers* headers)
    : Body(context), response_(response), headers_(headers) {}

bool Response::HasBody() const {
  return response_->InternalBuffer();
}

bool Response::IsBodyUsed() const {
  auto* body_buffer = InternalBodyBuffer();
  return body_buffer && body_buffer->IsStreamDisturbed();
}

String Response::MimeType() const {
  return response_->MimeType();
}

String Response::ContentType() const {
  String result;
  response_->HeaderList()->Get(http_names::kContentType, result);
  return result;
}

String Response::InternalMIMEType() const {
  return response_->InternalMIMEType();
}

const Vector<KURL>& Response::InternalURLList() const {
  return response_->InternalURLList();
}

FetchHeaderList* Response::InternalHeaderList() const {
  return response_->InternalHeaderList();
}

void Response::Trace(Visitor* visitor) const {
  ScriptWrappable::Trace(visitor);
  Body::Trace(visitor);
  visitor->Trace(response_);
  visitor->Trace(headers_);
}

}  // namespace blink
```