Response:
The user wants a summary of the functionality of the provided C++ code snippet from `blink/renderer/core/fetch/request.cc`. This is the second part of the file, so I need to consider the context from the previous part. The request also asks for connections to JavaScript, HTML, and CSS, examples of logical reasoning (input/output), common user errors, and debugging clues.

Here's a breakdown of how to approach this:

1. **Overall Function:**  Identify the primary purpose of this code. It's clearly about creating and managing `Request` objects in the Blink rendering engine, which are representations of HTTP requests in the Fetch API.

2. **Key Functions/Methods:** List the most important functions and what they do. Focus on the `Create` methods and the getter methods for `Request` properties.

3. **Relationship to Web Technologies:** Explain how the `Request` object relates to JavaScript's `fetch()` API, HTML's elements that initiate requests (like `<form>` or `<a>`), and how it *indirectly* relates to CSS (through fetching resources).

4. **Logical Reasoning (Input/Output):** For key functions like the `Create` methods, describe what input they take (URL, `RequestInit` object) and what output they produce (a `Request` object or `nullptr` in case of errors).

5. **User/Programming Errors:** Think about common mistakes when using the Fetch API in JavaScript that would lead to errors handled in this C++ code. Examples: invalid HTTP methods, trying to send a body with a GET request, reusing a request body.

6. **User Operation and Debugging:** Explain how a user action in the browser (e.g., clicking a link, submitting a form) triggers the creation of a `Request` object in Blink. This serves as a debugging clue – if something is wrong with a request, tracing back to the user's action is important.

7. **Part 2 Summary:**  Focus on what this *specific* part of the code does. It primarily contains the implementations of various `Create` methods and the getter methods for the `Request` object's properties.

**Pre-computation/Analysis of the Code Snippet:**

* **`Create` Methods:**  There are multiple `Create` methods, indicating different ways to construct a `Request` (from a URL string, another `Request` object, with or without an `init` object). Pay attention to how they handle `RequestInit` options.
* **Getter Methods:**  The code defines getters for properties like `method`, `url`, `mode`, `credentials`, `headers`, `body`, etc. These map directly to the properties of the JavaScript `Request` object.
* **Error Handling:** The code uses `ExceptionState` to report errors, often throwing `TypeError` exceptions for invalid input or state.
* **`RequestInit` Processing:** The code parses and validates options from the `RequestInit` dictionary passed from JavaScript.
* **Body Handling:** There's logic for handling request bodies, including extracting bodies from various sources and checking for valid body usage.
* **CORS and Security:** The code includes checks related to CORS (Cross-Origin Resource Sharing), secure contexts, and Trust Tokens, indicating security considerations.
* **Cloning:** The `clone()` method allows creating copies of `Request` objects.

By systematically analyzing these aspects, I can construct a comprehensive answer that addresses all the user's requirements.
这是 blink 渲染引擎中 `blink/renderer/core/fetch/request.cc` 文件的第二部分，它主要负责 **创建和管理 HTTP 请求 (Request) 对象**。 延续第一部分，这部分代码继续实现了 `Request` 类的各种创建方法和属性访问器。

以下是其功能的详细列举：

**主要功能：**

1. **多种方式创建 `Request` 对象:**
    *   **从 `V8RequestInfo` (可以是一个已有的 `Request` 对象或 URL 字符串) 和 `RequestInit` 对象创建:** `Request::Create(ScriptState* script_state, const V8RequestInfo* input, const RequestInit* init, ExceptionState& exception_state)`。 这是创建 `Request` 对象的核心方法，它根据传入的 `input` 类型（现有的 `Request` 或 URL 字符串）以及 `init` 对象（包含请求的各种配置信息）来创建新的 `Request` 对象。
    *   **从 URL 字符串和可选的 `RequestInit` 对象创建:** `Request::Create(ScriptState* script_state, const String& input, const RequestInit* init, ExceptionState& exception_state)`。 允许直接使用 URL 字符串创建 `Request` 对象。
    *   **从已有的 `Request` 对象和可选的 `RequestInit` 对象创建:** `Request::Create(ScriptState* script_state, Request* input, const RequestInit* init, ExceptionState& exception_state)`。  允许基于现有的 `Request` 对象创建新的 `Request`，并可以覆盖一些配置项。
    *   **从 `FetchRequestData` 和 `AbortSignal` 创建:** `Request::Create(ScriptState* script_state, FetchRequestData* request, AbortSignal* signal)`。  这种方式更底层，直接使用请求数据和中止信号创建 `Request` 对象。
    *   **从 `mojom::blink::FetchAPIRequestPtr` 创建 (用于 Service Worker):** `Request::Create(ScriptState* script_state, mojom::blink::FetchAPIRequestPtr fetch_api_request, ForServiceWorkerFetchEvent for_service_worker_fetch_event)`。  专门用于 Service Worker 环境创建 `Request` 对象。

2. **提供 `Request` 对象的属性访问器 (getters):**  实现了 `Request` 类中各种属性的 getter 方法，这些属性对应了 JavaScript 中 `Request` 对象的属性。 例如：
    *   `method()`:  获取请求方法 (GET, POST, 等)。
    *   `url()`: 获取请求的 URL。
    *   `destination()`: 获取请求的目标资源类型 (document, script, image, 等)。
    *   `referrer()`: 获取请求的引用 URL。
    *   `getReferrerPolicy()`: 获取引用策略。
    *   `mode()`: 获取请求的模式 (cors, no-cors, same-origin, 等)。
    *   `credentials()`: 获取凭据模式 (omit, same-origin, include)。
    *   `cache()`: 获取缓存模式。
    *   `redirect()`: 获取重定向模式 (follow, error, manual)。
    *   `integrity()`: 获取子资源完整性校验值。
    *   `duplex()`: 获取请求的双工模式。
    *   `keepalive()`: 获取是否保持连接。
    *   `targetAddressSpace()`: 获取目标地址空间。
    *   `isHistoryNavigation()`: 获取是否是历史导航。
    *   `headers()`:  （在第一部分）获取请求头。

3. **实现 `clone()` 方法:**  `Request::clone(ScriptState* script_state, ExceptionState& exception_state)` 允许克隆一个 `Request` 对象。如果请求体已被使用或锁定，则会抛出异常。

4. **实现 `PassRequestData()` 方法:**  `Request::PassRequestData(ScriptState* script_state, ExceptionState& exception_state)` 用于将请求数据传递出去，通常用于发起实际的网络请求。

5. **实现 `HasBody()` 方法:**  `Request::HasBody()` 检查请求是否有请求体。

6. **实现 `CreateFetchAPIRequest()` 方法:**  `Request::CreateFetchAPIRequest()` 将 `Request` 对象的信息转换为 `mojom::blink::FetchAPIRequestPtr` 对象，这通常用于进程间通信，将请求信息传递给网络进程。

7. **提供 `V8RequestCredentialsToCredentialsMode()` 静态方法:**  用于将 JavaScript 的 `RequestCredentials` 枚举值转换为 Blink 内部使用的凭据模式枚举值。

**与 JavaScript, HTML, CSS 的功能关系：**

*   **JavaScript:** 这个文件直接实现了 JavaScript `fetch()` API 中 `Request` 接口的底层逻辑。JavaScript 代码通过 `new Request()` 构造函数或者在 `fetch()` 函数中传入 URL 或已有的 `Request` 对象来创建请求。这个 C++ 代码负责接收这些调用，解析参数，并创建内部的 `Request` 对象。例如：
    ```javascript
    // JavaScript 代码
    const request = new Request('https://example.com/data.json', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ key: 'value' }),
      mode: 'cors'
    });

    fetch(request)
      .then(response => response.json())
      .then(data => console.log(data));
    ```
    当执行 `new Request()` 时，Blink 内部会调用 `Request::Create` 系列方法，并将 JavaScript 传递的参数（URL, `method`, `headers`, `body`, `mode` 等）转换为 C++ 的数据结构。

*   **HTML:** HTML 元素，如 `<form>` 标签提交或者 `<a>` 标签的点击，也会导致网络请求的产生。 虽然这个文件本身不直接处理 HTML，但当浏览器处理这些 HTML 元素时，会创建相应的 `Request` 对象。 例如，当用户点击一个带有 `href` 属性的 `<a>` 标签时，浏览器会创建一个 `Request` 对象，其 URL 就是 `href` 的值，方法是 `GET`。

*   **CSS:**  CSS 文件中引用外部资源 (例如图片、字体) 时，浏览器也会发起网络请求。 同样，Blink 会创建 `Request` 对象来获取这些资源。  例如：
    ```css
    /* CSS 代码 */
    .my-image {
      background-image: url('image.png');
    }
    ```
    当浏览器解析到这条 CSS 规则时，会创建一个 `Request` 对象来请求 `image.png`。

**逻辑推理的假设输入与输出：**

**假设输入 (JavaScript 代码):**

```javascript
const requestInit = {
  method: 'PUT',
  headers: { 'X-Custom-Header': 'value' },
  body: 'Request Body',
  mode: 'cors',
  credentials: 'include'
};
const request = new Request('https://api.example.com/resource', requestInit);
```

**逻辑推理 (C++ 代码执行过程):**

1. `new Request('https://api.example.com/resource', requestInit)` 在 JavaScript 中被调用。
2. Blink 将 JavaScript 的参数传递给 C++ 的 `Request::Create` 方法（可能是 `Create(ScriptState*, const String&, const RequestInit*, ExceptionState&)`）。
3. `Create` 方法会：
    *   解析 URL 字符串 `'https://api.example.com/resource'`。
    *   从 `requestInit` 中提取 `method` 为 `'PUT'`。
    *   规范化 `method` 为大写 `'PUT'`。
    *   从 `requestInit` 中提取 `mode` 为 `'cors'`，并转换为 Blink 内部的 `network::mojom::RequestMode::kCors`。
    *   从 `requestInit` 中提取 `credentials` 为 `'include'`，并转换为 `network::mojom::CredentialsMode::kInclude`。
    *   创建一个 `Headers` 对象，并将 `{'X-Custom-Header': 'value'}` 添加到请求头中。
    *   处理 `body`，将其设置为请求体。
    *   创建一个新的 `Request` 对象，并将上述信息存储在其中。

**假设输出 (C++ `Request` 对象的状态):**

*   `request_->Method()`:  `"PUT"`
*   `request_->Url()`:  `KURL("https://api.example.com/resource")`
*   `request_->Mode()`: `network::mojom::RequestMode::kCors`
*   `request_->Credentials()`: `network::mojom::CredentialsMode::kInclude`
*   `headers_->List()`:  包含 `{"X-Custom-Header", "value"}`
*   `BodyBuffer()`:  包含 `"Request Body"` 的 `BodyStreamBuffer`

**用户或编程常见的使用错误：**

1. **在 GET 或 HEAD 请求中设置 body:**
    *   **错误代码 (JavaScript):**
        ```javascript
        const request = new Request('/data', { method: 'GET', body: 'some data' });
        ```
    *   **C++ 代码中的处理:**  在 `CreateRequestWithRequestOrString` 方法中，会检查 `request->Method()` 是否为 `http_names::kGET` 或 `http_names::kHEAD`，如果是且 `init->hasBody()` 或 `input_body` 不为空，则会抛出一个 `TypeError` 异常，提示 "Request with GET/HEAD method cannot have body."

2. **在 `no-cors` 模式下使用非 CORS 安全的 HTTP 方法:**
    *   **错误代码 (JavaScript):**
        ```javascript
        const request = new Request('/data', { method: 'PUT', mode: 'no-cors' });
        ```
    *   **C++ 代码中的处理:** 在 `CreateRequestWithRequestOrString` 方法中，如果 `r->GetRequest()->Mode()` 是 `network::mojom::RequestMode::kNoCors`，并且 `r->GetRequest()->Method()` 不是 CORS 安全的方法（例如 PUT, DELETE），则会抛出一个 `TypeError` 异常，提示 "'PUT' is unsupported in no-cors mode."

3. **在不安全的上下文中使用 `trustToken` 或 `attributionReporting`:**
    *   **错误代码 (JavaScript，在非 HTTPS 页面上):**
        ```javascript
        const request = new Request('/data', { privateToken: '...' });
        ```
    *   **C++ 代码中的处理:**  在处理 `init->hasPrivateToken()` 和 `init->hasAttributionReporting()` 的代码块中，会检查 `execution_context->IsSecureContext()`，如果不是安全上下文（例如 HTTP 页面），则会抛出一个 `TypeError` 异常，提示 "trustToken: TrustTokens operations are only available in secure contexts." 或 "attributionReporting: Attribution Reporting operations are only available in secure contexts."

4. **尝试重用已使用的 Request 对象的 body:**
    *   **错误代码 (JavaScript):**
        ```javascript
        const request = new Request('/data', { body: '...' });
        request.text().then(() => {
          const request2 = new Request(request); // 尝试从已使用的 request 创建新的 request
        });
        ```
    *   **C++ 代码中的处理:** 在 `CreateRequestWithRequestOrString` 方法中，如果 `input_body == body` 并且 `input_request` 存在且其 body 已经被使用 (`input_request->IsBodyUsed()`) 或锁定 (`input_request->IsBodyLocked()`)，则会抛出一个 `TypeError` 异常，提示 "Cannot construct a Request with a Request object that has already been used."

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入 URL 并回车，或者点击一个 `<a>` 链接。** 浏览器需要创建一个初始的导航请求。
2. **网页上的 JavaScript 代码执行了 `fetch()` 函数或创建了 `new Request()` 对象。** 这是最常见的触发 `Request` 对象创建的方式。
3. **用户提交了一个 HTML `<form>` 表单。** 浏览器会根据表单的属性创建一个 `Request` 对象。
4. **网页上的 CSS 引用了外部资源 (例如 `background-image: url(...)`)。**  Blink 需要创建 `Request` 对象来获取这些资源。
5. **Service Worker 拦截了 fetch 事件。** Service Worker 可以构造新的 `Request` 对象来发起请求。

**调试线索:**

当开发者在调试网络请求相关问题时，理解 `Request` 对象的创建过程至关重要。如果在网络面板中看到一个意外的请求，或者在 JavaScript 中捕获到与 `Request` 对象相关的错误，可以按照以下步骤进行调试：

1. **确定请求是如何发起的:**  是 JavaScript 的 `fetch()` 调用，HTML 元素触发，还是 CSS 资源加载？
2. **检查 JavaScript 代码中 `fetch()` 或 `new Request()` 的参数:**  确认 URL、方法、请求头、请求体、模式等是否正确。
3. **如果请求是由 HTML 元素触发，检查 HTML 元素的属性:** 例如 `<form>` 的 `action` 和 `method`，`<a>` 的 `href`。
4. **如果是 CSS 资源加载，检查 CSS 文件中的 URL 是否正确。**
5. **如果涉及到 Service Worker，检查 Service Worker 的代码逻辑。**

通过以上步骤，开发者可以逐步追踪到 `Request` 对象的创建过程，并找到问题的根源。例如，如果发现一个 GET 请求意外地携带了请求体，就可以回到 JavaScript 代码中检查是否错误地给 GET 请求设置了 `body` 属性。

**总结其功能 (第二部分):**

总而言之，`blink/renderer/core/fetch/request.cc` 文件的第二部分主要负责 **具体实现 `Request` 对象的创建过程和提供访问其属性的方法**。 它接收来自 JavaScript 和 Blink 内部其他模块的请求，根据提供的参数创建和配置 `Request` 对象，并处理一些常见的用户错误。 这部分代码是 Blink 中 Fetch API 实现的核心组成部分，它连接了 JavaScript 的 `Request` 对象和底层网络请求的实现。

### 提示词
```
这是目录为blink/renderer/core/fetch/request.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
t->method())) {
      exception_state.ThrowTypeError("'" + init->method() +
                                     "' HTTP method is unsupported.");
      return nullptr;
    }
    // "Normalize |method|."
    // "Set |request|'s method to |method|."
    request->SetMethod(
        FetchUtils::NormalizeMethod(AtomicString(init->method())));
  }

  // "If |init|'s signal member is present, then set |signal| to it."
  if (init->hasSignal()) {
    signal = init->signal();
  }

  if (init->hasPrivateToken()) {
    UseCounter::Count(ExecutionContext::From(script_state),
                      mojom::blink::WebFeature::kTrustTokenFetch);

    network::mojom::blink::TrustTokenParams params;
    if (!ConvertTrustTokenToMojomAndCheckPermissions(
            *init->privateToken(), GetPSTFeatures(*execution_context),
            &exception_state, &params)) {
      // Whenever parsing the trustToken argument fails, we expect a suitable
      // exception to be thrown.
      DCHECK(exception_state.HadException());
      return nullptr;
    }

    if (!execution_context->IsSecureContext()) {
      exception_state.ThrowTypeError(
          "trustToken: TrustTokens operations are only available in secure "
          "contexts.");
      return nullptr;
    }

    request->SetTrustTokenParams(std::move(params));
  }

  if (init->hasAttributionReporting()) {
    if (!execution_context->IsSecureContext()) {
      exception_state.ThrowTypeError(
          "attributionReporting: Attribution Reporting operations are only "
          "available in secure contexts.");
      return nullptr;
    }

    request->SetAttributionReportingEligibility(
        ConvertAttributionReportingRequestOptionsToMojom(
            *init->attributionReporting(), *execution_context,
            exception_state));
  }

  // "Let  signals  be [|signal|] if  signal  is non-null; otherwise []."
  HeapVector<Member<AbortSignal>> signals;
  if (signal) {
    signals.push_back(signal);
  }
  // "Set |r|'s signal to the result of creating a new dependent abort signal
  // from |signals|".
  auto* request_signal =
      MakeGarbageCollected<AbortSignal>(script_state, signals);

  // "Let |r| be a new Request object associated with |request| and a new
  // Headers object whose guard is "request"."
  Request* r = Request::Create(script_state, request, request_signal);

  // "If |r|'s request's mode is "no-cors", run these substeps:
  if (r->GetRequest()->Mode() == network::mojom::RequestMode::kNoCors) {
    // "If |r|'s request's method is not a CORS-safelisted method, throw a
    // TypeError."
    if (!cors::IsCorsSafelistedMethod(r->GetRequest()->Method())) {
      exception_state.ThrowTypeError("'" + r->GetRequest()->Method() +
                                     "' is unsupported in no-cors mode.");
      return nullptr;
    }
    // "Set |r|'s Headers object's guard to "request-no-cors"."
    r->getHeaders()->SetGuard(Headers::kRequestNoCorsGuard);
  }

  if (AreAnyMembersPresent(init)) {
    // Perform the following steps:
    // - "Let |headers| be a copy of |r|'s Headers object."
    // - "If |init|'s headers member is present, set |headers| to |init|'s
    //   headers member."
    //
    // We don't create a copy of r's Headers object when init's headers member
    // is present.
    Headers* headers = nullptr;
    if (!init->hasHeaders()) {
      headers = r->getHeaders()->Clone();
    }
    // "Empty |r|'s request's header list."
    r->request_->HeaderList()->ClearList();

    // "Fill |r|'s Headers object with |headers|. Rethrow any exceptions."
    if (init->hasHeaders()) {
      r->getHeaders()->FillWith(script_state, init->headers(), exception_state);
    } else {
      DCHECK(headers);
      r->getHeaders()->FillWith(script_state, headers, exception_state);
    }
    if (exception_state.HadException())
      return nullptr;
  }

  // "Let |inputBody| be |input|'s request's body if |input| is a
  //   Request object, and null otherwise."
  BodyStreamBuffer* input_body =
      input_request ? input_request->BodyBuffer() : nullptr;
  uint64_t input_body_byte_length =
      input_request ? input_request->BodyBufferByteLength() : 0;

  // "If either |init|["body"] exists and is non-null or |inputBody| is
  // non-null, and |request|'s method is `GET` or `HEAD`, throw a TypeError.
  v8::Local<v8::Value> init_body =
      init->hasBody() ? init->body().V8Value() : v8::Local<v8::Value>();
  if ((!init_body.IsEmpty() && !init_body->IsNull()) || input_body) {
    if (request->Method() == http_names::kGET ||
        request->Method() == http_names::kHEAD) {
      exception_state.ThrowTypeError(
          "Request with GET/HEAD method cannot have body.");
      return nullptr;
    }
  }

  // "Let |body| be |inputBody|."
  BodyStreamBuffer* body = input_body;
  uint64_t body_byte_length = input_body_byte_length;

  // "If |init|["body"] exists and is non-null, then:"
  if (!init_body.IsEmpty() && !init_body->IsNull()) {
    // - If |init|["keepalive"] exists and is true, then set |body| and
    //   |Content-Type| to the result of extracting |init|["body"], with the
    //   |keepalive| flag set.
    // From "extract a body":
    // - If the keepalive flag is set, then throw a TypeError.
    if (init->hasKeepalive() && init->keepalive() &&
        V8ReadableStream::HasInstance(script_state->GetIsolate(), init_body)) {
      exception_state.ThrowTypeError(
          "Keepalive request cannot have a ReadableStream body.");
      return nullptr;
    }

    // "Otherwise, set |body| and |Content-Type| to the result of extracting
    //  init["body"]."
    String content_type;
    body = ExtractBody(script_state, exception_state, init_body, content_type,
                       body_byte_length);
    // "If |Content-Type| is non-null and |this|'s header's header list
    //  does not contain `Content-Type`, then append
    //   `Content-Type`/|Content-Type| to |this|'s headers object.
    if (!content_type.empty() &&
        !r->getHeaders()->has(http_names::kContentType, exception_state)) {
      r->getHeaders()->append(script_state, http_names::kContentType,
                              content_type, exception_state);
    }
    if (exception_state.HadException())
      return nullptr;
  }

  // "If `inputOrInitBody` is non-null and `inputOrInitBody`’s source is null,
  // then:"
  if (body && body->IsMadeFromReadableStream()) {
    // "If `initBody` is non-null and `init["duplex"]` does not exist, then
    // throw a TypeError."
    if (!init_body.IsEmpty() && !init_body->IsNull() && !init->hasDuplex()) {
      exception_state.ThrowTypeError(
          "The `duplex` member must be specified for a request with a "
          "streaming body");
      return nullptr;
    }

    // "If |this|’s request’s mode is neither "same-origin" nor "cors", then
    // throw a TypeError."
    if (request->Mode() != network::mojom::RequestMode::kSameOrigin &&
        request->Mode() != network::mojom::RequestMode::kCors &&
        request->Mode() !=
            network::mojom::RequestMode::kCorsWithForcedPreflight) {
      exception_state.ThrowTypeError(
          "If request is made from ReadableStream, mode should be"
          "\"same-origin\" or \"cors\"");
      return nullptr;
    }
    // "Set this’s request’s use-CORS-preflight flag."
    request->SetMode(network::mojom::RequestMode::kCorsWithForcedPreflight);
  }

  // "If |inputBody| is |body| and |input| is disturbed or locked, then throw a
  // TypeError."
  if (input_body == body && input_request &&
      (input_request->IsBodyUsed() || input_request->IsBodyLocked())) {
    exception_state.ThrowTypeError(
        "Cannot construct a Request with a Request object that has already "
        "been used.");
    return nullptr;
  }

  // "Set |this|'s request's body to |body|.
  if (body)
    r->request_->SetBuffer(body, body_byte_length);

  // "Set |r|'s MIME type to the result of extracting a MIME type from |r|'s
  // request's header list."
  r->request_->SetMimeType(r->request_->HeaderList()->ExtractMIMEType());

  // "If |input| is a Request object and |input|'s request's body is
  // non-null, run these substeps:"
  if (input_request && input_request->BodyBuffer()) {
    // "Let |dummyStream| be an empty ReadableStream object."
    auto* dummy_stream =
        BodyStreamBuffer::Create(script_state, BytesConsumer::CreateClosed(),
                                 nullptr, /*cached_metadata_handler=*/nullptr);
    // "Set |input|'s request's body to a new body whose stream is
    // |dummyStream|."
    input_request->request_->SetBuffer(dummy_stream);
    // "Let |reader| be the result of getting reader from |dummyStream|."
    // "Read all bytes from |dummyStream| with |reader|."
    input_request->BodyBuffer()->CloseAndLockAndDisturb(exception_state);
  }

  // "Return |r|."
  return r;
}

Request* Request::Create(ScriptState* script_state,
                         const V8RequestInfo* input,
                         const RequestInit* init,
                         ExceptionState& exception_state) {
  DCHECK(input);

  switch (input->GetContentType()) {
    case V8RequestInfo::ContentType::kRequest:
      return Create(script_state, input->GetAsRequest(), init, exception_state);
    case V8RequestInfo::ContentType::kUSVString:
      return Create(script_state, input->GetAsUSVString(), init,
                    exception_state);
  }

  NOTREACHED();
}

Request* Request::Create(ScriptState* script_state,
                         const String& input,
                         ExceptionState& exception_state) {
  return Create(script_state, input, RequestInit::Create(), exception_state);
}

Request* Request::Create(ScriptState* script_state,
                         const String& input,
                         const RequestInit* init,
                         ExceptionState& exception_state) {
  return CreateRequestWithRequestOrString(script_state, nullptr, input, init,
                                          exception_state);
}

Request* Request::Create(ScriptState* script_state,
                         Request* input,
                         ExceptionState& exception_state) {
  return Create(script_state, input, RequestInit::Create(), exception_state);
}

Request* Request::Create(ScriptState* script_state,
                         Request* input,
                         const RequestInit* init,
                         ExceptionState& exception_state) {
  return CreateRequestWithRequestOrString(script_state, input, String(), init,
                                          exception_state);
}

Request* Request::Create(ScriptState* script_state,
                         FetchRequestData* request,
                         AbortSignal* signal) {
  return MakeGarbageCollected<Request>(script_state, request, signal);
}

Request* Request::Create(
    ScriptState* script_state,
    mojom::blink::FetchAPIRequestPtr fetch_api_request,
    ForServiceWorkerFetchEvent for_service_worker_fetch_event) {
  FetchRequestData* data =
      FetchRequestData::Create(script_state, std::move(fetch_api_request),
                               for_service_worker_fetch_event);
  auto* signal =
      MakeGarbageCollected<AbortSignal>(ExecutionContext::From(script_state));
  return MakeGarbageCollected<Request>(script_state, data, signal);
}

network::mojom::CredentialsMode Request::V8RequestCredentialsToCredentialsMode(
    V8RequestCredentials::Enum credentials_mode) {
  switch (credentials_mode) {
    case V8RequestCredentials::Enum::kOmit:
      return network::mojom::CredentialsMode::kOmit;
    case V8RequestCredentials::Enum::kSameOrigin:
      return network::mojom::CredentialsMode::kSameOrigin;
    case V8RequestCredentials::Enum::kInclude:
      return network::mojom::CredentialsMode::kInclude;
  }
  NOTREACHED();
}

Request::Request(ScriptState* script_state,
                 FetchRequestData* request,
                 Headers* headers,
                 AbortSignal* signal)
    : Body(ExecutionContext::From(script_state)),
      request_(request),
      headers_(headers),
      signal_(signal) {}

Request::Request(ScriptState* script_state,
                 FetchRequestData* request,
                 AbortSignal* signal)
    : Request(script_state,
              request,
              Headers::Create(request->HeaderList()),
              signal) {
  headers_->SetGuard(Headers::kRequestGuard);
}

String Request::method() const {
  // "The method attribute's getter must return request's method."
  return request_->Method();
}

const KURL& Request::url() const {
  return request_->Url();
}

V8RequestDestination Request::destination() const {
  // "The destination attribute’s getter must return request’s destination."
  return V8RequestDestination(DestinationToV8Enum(request_->Destination()));
}

String Request::referrer() const {
  // "The referrer attribute's getter must return the empty string if
  // request's referrer is no referrer, "about:client" if request's referrer
  // is client and request's referrer, serialized, otherwise."
  DCHECK_EQ(Referrer::NoReferrer(), String());
  DCHECK_EQ(Referrer::ClientReferrerString(), "about:client");
  return request_->ReferrerString();
}

V8ReferrerPolicy Request::getReferrerPolicy() const {
  switch (request_->GetReferrerPolicy()) {
    case network::mojom::ReferrerPolicy::kAlways:
      return V8ReferrerPolicy(V8ReferrerPolicy::Enum::kUnsafeUrl);
    case network::mojom::ReferrerPolicy::kDefault:
      return V8ReferrerPolicy(V8ReferrerPolicy::Enum::k);
    case network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade:
      return V8ReferrerPolicy(V8ReferrerPolicy::Enum::kNoReferrerWhenDowngrade);
    case network::mojom::ReferrerPolicy::kNever:
      return V8ReferrerPolicy(V8ReferrerPolicy::Enum::kNoReferrer);
    case network::mojom::ReferrerPolicy::kOrigin:
      return V8ReferrerPolicy(V8ReferrerPolicy::Enum::kOrigin);
    case network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin:
      return V8ReferrerPolicy(V8ReferrerPolicy::Enum::kOriginWhenCrossOrigin);
    case network::mojom::ReferrerPolicy::kSameOrigin:
      return V8ReferrerPolicy(V8ReferrerPolicy::Enum::kSameOrigin);
    case network::mojom::ReferrerPolicy::kStrictOrigin:
      return V8ReferrerPolicy(V8ReferrerPolicy::Enum::kStrictOrigin);
    case network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin:
      return V8ReferrerPolicy(
          V8ReferrerPolicy::Enum::kStrictOriginWhenCrossOrigin);
  }
  NOTREACHED();
}

V8RequestMode Request::mode() const {
  // "The mode attribute's getter must return the value corresponding to the
  // first matching statement, switching on request's mode:"
  switch (request_->Mode()) {
    case network::mojom::RequestMode::kSameOrigin:
      return V8RequestMode(V8RequestMode::Enum::kSameOrigin);
    case network::mojom::RequestMode::kNoCors:
      return V8RequestMode(V8RequestMode::Enum::kNoCors);
    case network::mojom::RequestMode::kCors:
    case network::mojom::RequestMode::kCorsWithForcedPreflight:
      return V8RequestMode(V8RequestMode::Enum::kCors);
    case network::mojom::RequestMode::kNavigate:
      return V8RequestMode(V8RequestMode::Enum::kNavigate);
  }
  NOTREACHED();
}

V8RequestCredentials Request::credentials() const {
  // "The credentials attribute's getter must return the value corresponding
  // to the first matching statement, switching on request's credentials
  // mode:"
  switch (request_->Credentials()) {
    case network::mojom::CredentialsMode::kOmit:
    case network::mojom::CredentialsMode::kOmitBug_775438_Workaround:
      return V8RequestCredentials(V8RequestCredentials::Enum::kOmit);
    case network::mojom::CredentialsMode::kSameOrigin:
      return V8RequestCredentials(V8RequestCredentials::Enum::kSameOrigin);
    case network::mojom::CredentialsMode::kInclude:
      return V8RequestCredentials(V8RequestCredentials::Enum::kInclude);
  }
  NOTREACHED();
}

V8RequestCache Request::cache() const {
  // "The cache attribute's getter must return request's cache mode."
  switch (request_->CacheMode()) {
    case mojom::blink::FetchCacheMode::kDefault:
      return V8RequestCache(V8RequestCache::Enum::kDefault);
    case mojom::blink::FetchCacheMode::kNoStore:
      return V8RequestCache(V8RequestCache::Enum::kNoStore);
    case mojom::blink::FetchCacheMode::kBypassCache:
      return V8RequestCache(V8RequestCache::Enum::kReload);
    case mojom::blink::FetchCacheMode::kValidateCache:
      return V8RequestCache(V8RequestCache::Enum::kNoCache);
    case mojom::blink::FetchCacheMode::kForceCache:
      return V8RequestCache(V8RequestCache::Enum::kForceCache);
    case mojom::blink::FetchCacheMode::kOnlyIfCached:
      return V8RequestCache(V8RequestCache::Enum::kOnlyIfCached);
    case mojom::blink::FetchCacheMode::kUnspecifiedOnlyIfCachedStrict:
    case mojom::blink::FetchCacheMode::kUnspecifiedForceCacheMiss:
      // Should not happen.
      break;
  }
  NOTREACHED();
}

V8RequestRedirect Request::redirect() const {
  // "The redirect attribute's getter must return request's redirect mode."
  switch (request_->Redirect()) {
    case network::mojom::RedirectMode::kFollow:
      return V8RequestRedirect(V8RequestRedirect::Enum::kFollow);
    case network::mojom::RedirectMode::kError:
      return V8RequestRedirect(V8RequestRedirect::Enum::kError);
    case network::mojom::RedirectMode::kManual:
      return V8RequestRedirect(V8RequestRedirect::Enum::kManual);
  }
  NOTREACHED();
}

String Request::integrity() const {
  return request_->Integrity();
}

V8RequestDuplex Request::duplex() const {
  return V8RequestDuplex(V8RequestDuplex::Enum::kHalf);
}

bool Request::keepalive() const {
  return request_->Keepalive();
}

V8IPAddressSpace Request::targetAddressSpace() const {
  switch (request_->TargetAddressSpace()) {
    case network::mojom::IPAddressSpace::kLocal:
      return V8IPAddressSpace(V8IPAddressSpace::Enum::kLocal);
    case network::mojom::IPAddressSpace::kPrivate:
      return V8IPAddressSpace(V8IPAddressSpace::Enum::kPrivate);
    case network::mojom::IPAddressSpace::kPublic:
      return V8IPAddressSpace(V8IPAddressSpace::Enum::kPublic);
    case network::mojom::IPAddressSpace::kUnknown:
      return V8IPAddressSpace(V8IPAddressSpace::Enum::kUnknown);
  }
  NOTREACHED();
}

bool Request::isHistoryNavigation() const {
  return request_->IsHistoryNavigation();
}

Request* Request::clone(ScriptState* script_state,
                        ExceptionState& exception_state) {
  if (IsBodyLocked() || IsBodyUsed()) {
    exception_state.ThrowTypeError("Request body is already used");
    return nullptr;
  }

  FetchRequestData* request = request_->Clone(script_state, exception_state);
  if (exception_state.HadException())
    return nullptr;
  Headers* headers = Headers::Create(request->HeaderList());
  headers->SetGuard(headers_->GetGuard());

  HeapVector<Member<AbortSignal>> signals;
  CHECK(signal_);
  signals.push_back(signal_);
  auto* signal = MakeGarbageCollected<AbortSignal>(script_state, signals);

  return MakeGarbageCollected<Request>(script_state, request, headers, signal);
}

FetchRequestData* Request::PassRequestData(ScriptState* script_state,
                                           ExceptionState& exception_state) {
  DCHECK(!IsBodyUsed());
  FetchRequestData* data = request_->Pass(script_state, exception_state);
  // |data|'s buffer('s js wrapper) has no retainer, but it's OK because
  // the only caller is the fetch function and it uses the body buffer
  // immediately.
  return data;
}

bool Request::HasBody() const {
  return BodyBuffer();
}

mojom::blink::FetchAPIRequestPtr Request::CreateFetchAPIRequest() const {
  auto fetch_api_request = mojom::blink::FetchAPIRequest::New();
  fetch_api_request->method = method();
  fetch_api_request->mode = request_->Mode();
  fetch_api_request->credentials_mode = request_->Credentials();
  fetch_api_request->cache_mode = request_->CacheMode();
  fetch_api_request->redirect_mode = request_->Redirect();
  fetch_api_request->integrity = request_->Integrity();
  fetch_api_request->is_history_navigation = request_->IsHistoryNavigation();
  fetch_api_request->destination = request_->Destination();
  fetch_api_request->request_initiator = request_->Origin();
  fetch_api_request->url = KURL(request_->Url());

  HTTPHeaderMap headers;
  for (const auto& header : headers_->HeaderList()->List()) {
    if (EqualIgnoringASCIICase(header.first, "referer"))
      continue;
    AtomicString key(header.first);
    AtomicString value(header.second);
    HTTPHeaderMap::AddResult result = headers.Add(key, value);
    if (!result.is_new_entry) {
      result.stored_value->value =
          result.stored_value->value + ", " + String(value);
    }
  }
  for (const auto& pair : headers)
    fetch_api_request->headers.insert(pair.key, pair.value);

  if (!request_->ReferrerString().empty()) {
    fetch_api_request->referrer =
        mojom::blink::Referrer::New(KURL(NullURL(), request_->ReferrerString()),
                                    request_->GetReferrerPolicy());
    DCHECK(fetch_api_request->referrer->url.IsValid());
  }
  // FIXME: How can we set isReload properly? What is the correct place to load
  // it in to the Request object? We should investigate the right way to plumb
  // this information in to here.
  return fetch_api_request;
}

String Request::MimeType() const {
  return request_->MimeType();
}

String Request::ContentType() const {
  String result;
  request_->HeaderList()->Get(http_names::kContentType, result);
  return result;
}

mojom::blink::RequestContextType Request::GetRequestContextType() const {
  if (!request_) {
    return mojom::blink::RequestContextType::UNSPECIFIED;
  }
  return mojom::blink::RequestContextType::FETCH;
}

network::mojom::RequestDestination Request::GetRequestDestination() const {
  if (!request_) {
    return network::mojom::RequestDestination::kEmpty;
  }
  return request_->Destination();
}

network::mojom::RequestMode Request::GetRequestMode() const {
  return request_->Mode();
}

void Request::Trace(Visitor* visitor) const {
  ScriptWrappable::Trace(visitor);
  Body::Trace(visitor);
  visitor->Trace(request_);
  visitor->Trace(headers_);
  visitor->Trace(signal_);
}

}  // namespace blink
```