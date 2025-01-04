Response:
The user wants to understand the functionality of the provided C++ code snippet from `xml_http_request.cc`. This is the second part of a three-part code snippet. I need to summarize the main functionalities within this specific part and relate them to web technologies like JavaScript, HTML, and CSS if applicable. I also need to consider common user errors, debugging, and any logical deductions made within the code.

Here's a breakdown of the functionalities within this part:

1. **Sending Data:**  The code defines multiple `send` methods to handle different types of data being sent via XMLHttpRequest (strings, Blobs, FormData, URLSearchParams, ArrayBuffers, ArrayBufferViews).
2. **Request Creation:** The `CreateRequest` method is responsible for constructing and initiating the actual network request. It handles different scenarios like blob URLs, FTP, CORS, and setting up request headers and body.
3. **Error Handling:**  Methods like `ThrowForLoadFailureIfNeeded`, `HandleNetworkError`, `HandleDidCancel`, and `HandleRequestError` manage various error conditions during the request lifecycle.
4. **Aborting Requests:** The `abort` and `InternalAbort` methods allow for cancelling ongoing requests.
5. **Response Handling:**  Methods like `overrideMimeType`, `setRequestHeader`, `getAllResponseHeaders`, and `getResponseHeader` deal with setting request headers and retrieving response headers.
6. **MIME Type and Charset Handling:** Functions like `FinalResponseMIMETypeInternal`, `GetResponseMIMEType`, `FinalResponseCharset`, and `UpdateContentTypeAndCharset` are involved in managing the MIME type and character encoding of the request and response.
7. **Status and Status Text:** The `status` and `statusText` methods provide access to the HTTP status code and message.
8. **Callbacks from Network Layer:** Methods like `DidFail`, `DidFailRedirectCheck`, `DidFinishLoading`, `DidSendData`, and `DidReceiveResponse` are callbacks invoked by the network layer during the request process.
9. **Blob Handling:** The code includes logic for downloading responses as blobs.

**Connections to Web Technologies:**

*   **JavaScript:** The `send` methods directly correspond to the `XMLHttpRequest.send()` method in JavaScript. The setting and getting of headers (`setRequestHeader`, `getAllResponseHeaders`, `getResponseHeader`) are also JavaScript APIs.
*   **HTML:** The `FormData` object used in one of the `send` methods is often constructed from HTML forms. The response can be an HTML document, which is handled by the parsing logic.
*   **CSS:**  While not directly involved in sending the request, CSS can trigger XHR requests through mechanisms like `url()` in `background-image`. The response to an XHR might be CSS.

**Common User Errors:**

*   Setting headers after calling `send()`.
*   Trying to send data with invalid HTTP methods for blob URLs.
*   Incorrectly setting or overriding MIME types.
*   Making synchronous XHR calls in the main thread, potentially freezing the UI.
这是`blink/renderer/core/xmlhttprequest/xml_http_request.cc`文件的第二部分，主要负责处理XMLHttpRequest的**发送请求**和**处理网络响应**的逻辑。

以下是这个部分的主要功能归纳：

**1. 发送请求 (send 方法的各种重载):**

*   **功能:**  实现了 `XMLHttpRequest` 接口的 `send()` 方法，允许发送不同类型的数据作为请求体。
*   **支持的数据类型:**
    *   `nullptr` (不发送请求体)
    *   `const String& body` (文本数据，默认 Content-Type 为 `text/plain;charset=UTF-8`)
    *   `Blob* body` (二进制大数据)
    *   `FormData* body` (表单数据，Content-Type 为 `multipart/form-data`)
    *   `URLSearchParams* body` (URL编码的表单数据，Content-Type 为 `application/x-www-form-urlencoded;charset=UTF-8`)
    *   `DOMArrayBuffer* body`, `DOMArrayBufferView* body` (二进制数据)
*   **与 JavaScript 的关系:**  这些 `send()` 方法直接对应于 JavaScript 中 `XMLHttpRequest.send()` 方法的不同用法。
    *   **举例:**
        *   `xhr.send("Hello, world!");`  对应 `send(const String& body, ...)`
        *   `xhr.send(new Blob(["data"], { type: 'text/plain' }));` 对应 `send(Blob* body, ...)`
        *   `xhr.send(new FormData(document.getElementById('myForm')));` 对应 `send(FormData* body, ...)`
        *   `xhr.send(new URLSearchParams("param1=value1&param2=value2"));` 对应 `send(URLSearchParams* body, ...)`
        *   `xhr.send(new Uint8Array([1, 2, 3]).buffer);` 对应 `send(DOMArrayBuffer* body, ...)`

**2. 创建和配置请求 (CreateRequest 方法):**

*   **功能:**  接收处理后的请求体数据，创建 `ResourceRequest` 对象，并配置请求的各种属性，例如 URL、HTTP 方法、请求头、CORS 设置、凭据模式等。最终通过 `ThreadableLoader` 发起网络请求。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**  `method_ = "POST"`, `url_ = "https://example.com/api"`, `http_body` 是包含表单数据的 `EncodedFormData` 对象。
    *   **输出:**  创建一个 `ResourceRequest` 对象，其 `httpMethod()` 为 "POST"， `url()` 为 "https://example.com/api"， `httpBody()` 为传入的 `EncodedFormData` 对象。
*   **与 HTML 的关系:**  当发送 `FormData` 时，数据通常来源于 HTML 表单元素。
*   **与 JavaScript 的关系:**  `CreateRequest` 的参数来源于 JavaScript 中对 `XMLHttpRequest` 对象的设置，例如 `open()` 方法设置的 URL 和 HTTP 方法。
*   **处理特定协议限制:**  例如，只允许 GET 请求 `blob:` URL，以及不支持 `ftp:` 协议。

**3. 处理加载失败 (ThrowForLoadFailureIfNeeded 方法):**

*   **功能:**  根据 `exception_code_` 的值决定是否抛出异常，并在必要时构造包含错误信息的异常消息。
*   **假设输入:**  `exception_code_` 为 `DOMExceptionCode::kNetworkError`， `url_` 为 "https://example.com"。
*   **输出:**  抛出一个类型为 `NetworkError` 的 DOMException，消息可能包含 "Failed to load 'https://example.com/'."。
*   **与 JavaScript 的关系:**  JavaScript 代码可以通过 `try...catch` 语句捕获这些异常。

**4. 异常处理和状态管理 (各种 Handle... 方法):**

*   **功能:**  处理网络请求过程中发生的各种错误情况，例如网络错误、请求取消、超时等。更新 `XMLHttpRequest` 的内部状态，并触发相应的事件。
*   **与 JavaScript 的关系:**  这些方法最终会触发 `XMLHttpRequest` 对象的事件处理函数 (例如 `onerror`, `onabort`)。

**5. 设置请求头 (setRequestHeader 方法和 SetRequestHeaderInternal 方法):**

*   **功能:**  允许用户通过 JavaScript 设置自定义的 HTTP 请求头。
*   **安全限制:**  会检查请求头名称和值的有效性，并阻止设置被禁止的请求头。
*   **与 JavaScript 的关系:**  对应 JavaScript 的 `XMLHttpRequest.setRequestHeader()` 方法。
    *   **用户或编程常见的使用错误:**
        *   在调用 `send()` 后调用 `setRequestHeader()` 会抛出 `InvalidStateError` 异常。
        *   尝试设置被禁止的请求头（例如 `User-Agent`）会被忽略并在控制台输出错误信息。
        *   设置无效的请求头名称或值会抛出 `SyntaxError` 异常。
*   **举例:**
    *   **假设输入:**  在 `state_` 为 `kOpened` 且 `send_flag_` 为 false 的情况下，调用 `setRequestHeader("X-Custom-Header", "custom-value")`。
    *   **输出:**  `request_headers_` 内部的 HTTPHeaderMap 会添加或更新 "X-Custom-Header: custom-value"。

**6. 设置私有Token和归因报告 (setPrivateToken 和 setAttributionReporting 方法):**

*   **功能:**  允许为请求设置私有Token（Trust Token）和归因报告相关的选项。
*   **与 JavaScript 的关系:**  对应 JavaScript 中实验性的 `XMLHttpRequest.setPrivateToken()` 和 `XMLHttpRequest.setAttributionReporting()` 方法。

**7. 获取响应头 (getAllResponseHeaders 和 getResponseHeader 方法):**

*   **功能:**  允许获取完整的响应头字符串或根据名称获取特定的响应头。
*   **安全限制:**  会过滤掉被禁止的响应头，并根据 CORS 设置决定是否暴露某些响应头。
*   **与 JavaScript 的关系:**  对应 JavaScript 的 `XMLHttpRequest.getAllResponseHeaders()` 和 `XMLHttpRequest.getResponseHeader()` 方法。

**8. 处理 MIME 类型和字符编码 (overrideMimeType, FinalResponseMIMETypeInternal, GetResponseMIMEType, FinalResponseCharset, UpdateContentTypeAndCharset 方法):**

*   **功能:**  负责管理请求和响应的 MIME 类型和字符编码。允许用户覆盖响应的 MIME 类型。
*   **与 JavaScript 的关系:**  对应 JavaScript 的 `XMLHttpRequest.overrideMimeType()` 方法。
    *   **用户或编程常见的使用错误:**  在 `state_` 为 `kLoading` 或 `kDone` 时调用 `overrideMimeType()` 会抛出 `InvalidStateError` 异常。

**9. 获取状态码和状态文本 (status 和 statusText 方法):**

*   **功能:**  返回 HTTP 响应的状态码和状态文本。
*   **与 JavaScript 的关系:**  对应 JavaScript 的 `XMLHttpRequest.status` 和 `XMLHttpRequest.statusText` 属性。

**10. 处理网络层回调 (DidFail, DidFailRedirectCheck, DidFinishLoading, DidSendData, DidReceiveResponse 方法):**

*   **功能:**  这些方法是 Chromium 网络层在请求生命周期中不同阶段调用的回调函数。它们负责更新 `XMLHttpRequest` 的内部状态，处理接收到的数据，以及触发相应的事件。
*   **用户操作如何一步步到达这里 (作为调试线索):**
    1. 用户在浏览器中访问一个网页。
    2. 网页的 JavaScript 代码创建了一个 `XMLHttpRequest` 对象。
    3. JavaScript 调用 `xhr.open(method, url)` 设置请求方法和 URL。
    4. JavaScript 可能调用 `xhr.setRequestHeader()` 设置请求头。
    5. JavaScript 调用 `xhr.send(data)` 发送请求。
    6. 浏览器内核（Blink 引擎）的网络层开始处理请求。
    7. 如果请求成功发送，网络层可能会调用 `DidSendData` 报告发送进度。
    8. 服务器响应后，网络层会调用 `DidReceiveResponse` 传递响应头信息。
    9. 网络层逐步接收响应体数据，并可能多次调用 `DidReceiveData` (在后续部分)。
    10. 如果请求过程中发生错误（例如网络中断、服务器错误），网络层会调用 `DidFail` 或 `DidFailRedirectCheck`。
    11. 如果请求成功完成，网络层会调用 `DidFinishLoading`。

**总结 (第2部分功能):**

这部分 `XMLHttpRequest.cc` 源代码的核心功能是**处理发送 XMLHttpRequest 请求的各个阶段**，包括准备请求数据、配置请求参数、实际发起网络请求，以及接收和初步处理网络响应（主要是响应头）。它定义了如何将 JavaScript 中对 `XMLHttpRequest` 对象的调用转化为底层的网络操作，并处理了请求过程中的各种错误情况。 这部分代码是 JavaScript `XMLHttpRequest` API 在 Chromium Blink 引擎中的具体实现。

Prompt: 
```
这是目录为blink/renderer/core/xmlhttprequest/xml_http_request.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
y;

  if (!body.IsNull() && AreMethodAndURLValidForSend()) {
    http_body = EncodedFormData::Create(
        UTF8Encoding().Encode(body, WTF::kNoUnencodables));
    UpdateContentTypeAndCharset(AtomicString("text/plain;charset=UTF-8"),
                                "UTF-8");
  }

  CreateRequest(std::move(http_body), exception_state);
}

void XMLHttpRequest::send(Blob* body, ExceptionState& exception_state) {
  if (!InitSend(exception_state))
    return;

  scoped_refptr<EncodedFormData> http_body;

  if (AreMethodAndURLValidForSend()) {
    if (!HasContentTypeRequestHeader()) {
      const String& blob_type = FetchUtils::NormalizeHeaderValue(body->type());
      if (!blob_type.empty() && ParsedContentType(blob_type).IsValid()) {
        SetRequestHeaderInternal(http_names::kContentType,
                                 AtomicString(blob_type));
      }
    }

    // FIXME: add support for uploading bundles.
    http_body = EncodedFormData::Create();
    if (body->HasBackingFile()) {
      auto* file = To<File>(body);
      if (!file->GetPath().empty())
        http_body->AppendFile(file->GetPath(), file->LastModifiedTime());
      else
        DUMP_WILL_BE_NOTREACHED();
    } else {
      http_body->AppendBlob(body->GetBlobDataHandle());
    }
  }

  CreateRequest(std::move(http_body), exception_state);
}

void XMLHttpRequest::send(FormData* body, ExceptionState& exception_state) {
  if (!InitSend(exception_state))
    return;

  scoped_refptr<EncodedFormData> http_body;

  if (AreMethodAndURLValidForSend()) {
    http_body = body->EncodeMultiPartFormData();

    // TODO (sof): override any author-provided charset= in the
    // content type value to UTF-8 ?
    if (!HasContentTypeRequestHeader()) {
      AtomicString content_type =
          AtomicString("multipart/form-data; boundary=") +
          FetchUtils::NormalizeHeaderValue(http_body->Boundary().data());
      SetRequestHeaderInternal(http_names::kContentType, content_type);
    }
  }

  CreateRequest(std::move(http_body), exception_state);
}

void XMLHttpRequest::send(URLSearchParams* body,
                          ExceptionState& exception_state) {
  if (!InitSend(exception_state))
    return;

  scoped_refptr<EncodedFormData> http_body;

  if (AreMethodAndURLValidForSend()) {
    http_body = body->ToEncodedFormData();
    UpdateContentTypeAndCharset(
        AtomicString("application/x-www-form-urlencoded;charset=UTF-8"),
        "UTF-8");
  }

  CreateRequest(std::move(http_body), exception_state);
}

void XMLHttpRequest::send(DOMArrayBuffer* body,
                          ExceptionState& exception_state) {
  SendBytesData(body->ByteSpan(), exception_state);
}

void XMLHttpRequest::send(DOMArrayBufferView* body,
                          ExceptionState& exception_state) {
  SendBytesData(body->ByteSpan(), exception_state);
}

void XMLHttpRequest::SendBytesData(base::span<const uint8_t> bytes,
                                   ExceptionState& exception_state) {
  if (!InitSend(exception_state))
    return;

  scoped_refptr<EncodedFormData> http_body;

  if (AreMethodAndURLValidForSend()) {
    http_body = EncodedFormData::Create(bytes);
  }

  CreateRequest(std::move(http_body), exception_state);
}

void XMLHttpRequest::SendForInspectorXHRReplay(
    scoped_refptr<EncodedFormData> form_data,
    ExceptionState& exception_state) {
  CreateRequest(form_data ? form_data->DeepCopy() : nullptr, exception_state);
}

void XMLHttpRequest::ThrowForLoadFailureIfNeeded(
    ExceptionState& exception_state,
    const String& reason) {
  if (error_ && exception_code_ == DOMExceptionCode::kNoError)
    exception_code_ = DOMExceptionCode::kNetworkError;

  if (exception_code_ == DOMExceptionCode::kNoError)
    return;

  StringBuilder message;
  message.Append("Failed to load '");
  message.Append(url_.ElidedString());
  message.Append('\'');
  if (reason.IsNull()) {
    message.Append('.');
  } else {
    message.Append(": ");
    message.Append(reason);
  }

  exception_state.ThrowDOMException(exception_code_, message.ToString());
}

void XMLHttpRequest::CreateRequest(scoped_refptr<EncodedFormData> http_body,
                                   ExceptionState& exception_state) {
  // Only GET request is supported for blob URL.
  if (url_.ProtocolIs("blob") && method_ != http_names::kGET) {
    HandleNetworkError();

    if (!async_) {
      ThrowForLoadFailureIfNeeded(
          exception_state,
          "'GET' is the only method allowed for 'blob:' URLs.");
    }
    return;
  }

  if (url_.ProtocolIs("ftp")) {
    LogConsoleError(GetExecutionContext(), "FTP is not supported.");
    HandleNetworkError();
    if (!async_) {
      ThrowForLoadFailureIfNeeded(
          exception_state, "Making a request to a FTP URL is not supported.");
    }
    return;
  }

  DCHECK(GetExecutionContext());
  ExecutionContext& execution_context = *GetExecutionContext();

  send_flag_ = true;
  // The presence of upload event listeners forces us to use preflighting
  // because POSTing to an URL that does not permit cross origin requests should
  // look exactly like POSTing to an URL that does not respond at all.
  // Also, only async requests support upload progress events.
  bool upload_events = false;
  if (async_) {
    CHECK(!execution_context.IsContextDestroyed());
    if (world_ && world_->IsMainWorld()) {
      if (auto* tracker = scheduler::TaskAttributionTracker::From(
              execution_context.GetIsolate())) {
        parent_task_ = tracker->RunningTask();
      }
    }
    async_task_context_.Schedule(&execution_context, "XMLHttpRequest.send");
    DispatchProgressEvent(event_type_names::kLoadstart, 0, 0);
    // Event handler could have invalidated this send operation,
    // (re)setting the send flag and/or initiating another send
    // operation; leave quietly if so.
    if (!send_flag_ || loader_)
      return;
    if (http_body && upload_) {
      upload_events = upload_->HasEventListeners();
      upload_->DispatchEvent(*ProgressEvent::Create(
          event_type_names::kLoadstart, true, 0, http_body->SizeInBytes()));
      // See above.
      if (!send_flag_ || loader_)
        return;
    }
  }

  // We also remember whether upload events should be allowed for this request
  // in case the upload listeners are added after the request is started.
  upload_events_allowed_ =
      GetExecutionContext()->GetSecurityOrigin()->CanRequest(url_) ||
      (isolated_world_security_origin_ &&
       isolated_world_security_origin_->CanRequest(url_)) ||
      upload_events || !cors::IsCorsSafelistedMethod(method_) ||
      !cors::ContainsOnlyCorsSafelistedHeaders(request_headers_);

  ResourceRequest request(url_);
  request.SetRequestorOrigin(GetExecutionContext()->GetSecurityOrigin());
  request.SetIsolatedWorldOrigin(isolated_world_security_origin_);
  request.SetHttpMethod(method_);
  request.SetRequestContext(mojom::blink::RequestContextType::XML_HTTP_REQUEST);
  request.SetFetchLikeAPI(true);
  request.SetMode(upload_events
                      ? network::mojom::RequestMode::kCorsWithForcedPreflight
                      : network::mojom::RequestMode::kCors);
  request.SetTargetAddressSpace(network::mojom::IPAddressSpace::kUnknown);
  request.SetCredentialsMode(
      with_credentials_ ? network::mojom::CredentialsMode::kInclude
                        : network::mojom::CredentialsMode::kSameOrigin);
  request.SetSkipServiceWorker(world_ && world_->IsIsolatedWorld());
  if (trust_token_params_)
    request.SetTrustTokenParams(*trust_token_params_);

  request.SetAttributionReportingEligibility(
      attribution_reporting_eligibility_);

  probe::WillLoadXHR(&execution_context, method_, url_, async_,
                     request_headers_, with_credentials_);

  if (http_body) {
    DCHECK_NE(method_, http_names::kGET);
    DCHECK_NE(method_, http_names::kHEAD);
    request.SetHttpBody(std::move(http_body));
  }

  if (request_headers_.size() > 0)
    request.AddHTTPHeaderFields(request_headers_);

  ResourceLoaderOptions resource_loader_options(world_);
  resource_loader_options.initiator_info.name =
      fetch_initiator_type_names::kXmlhttprequest;
  if (blob_url_loader_factory_) {
    resource_loader_options.url_loader_factory =
        base::MakeRefCounted<base::RefCountedData<
            mojo::PendingRemote<network::mojom::blink::URLLoaderFactory>>>(
            std::move(blob_url_loader_factory_));
  }

  // When responseType is set to "blob", we redirect the downloaded data to a
  // blob directly, except for data: URLs, since those are loaded by
  // renderer side code, and don't support being downloaded to a blob.
  downloading_to_blob_ =
      GetResponseTypeCode() == V8XMLHttpRequestResponseType::Enum::kBlob &&
      !url_.ProtocolIsData();
  if (downloading_to_blob_) {
    request.SetDownloadToBlob(true);
    resource_loader_options.data_buffering_policy = kDoNotBufferData;
  }

  if (async_) {
    resource_loader_options.data_buffering_policy = kDoNotBufferData;
  }

  if (async_) {
    UseCounter::Count(&execution_context,
                      WebFeature::kXMLHttpRequestAsynchronous);
    if (upload_)
      request.SetReportUploadProgress(true);

    // TODO(yhirano): Turn this CHECK into DCHECK: see https://crbug.com/570946.
    CHECK(!loader_);
    DCHECK(send_flag_);
  } else {
    // Use count for XHR synchronous requests.
    UseCounter::Count(&execution_context, WebFeature::kXMLHttpRequestSynchronous);
    if (auto* window = DynamicTo<LocalDOMWindow>(GetExecutionContext())) {
      if (Frame* frame = window->GetFrame()) {
        if (frame->IsCrossOriginToOutermostMainFrame()) {
          UseCounter::Count(
              &execution_context,
              WebFeature::kXMLHttpRequestSynchronousInCrossOriginSubframe);
        } else if (frame->IsMainFrame()) {
          UseCounter::Count(&execution_context,
                            WebFeature::kXMLHttpRequestSynchronousInMainFrame);
        } else {
          UseCounter::Count(
              &execution_context,
              WebFeature::kXMLHttpRequestSynchronousInSameOriginSubframe);
        }
      }
      if (PageDismissalScope::IsActive()) {
        HandleNetworkError();
        ThrowForLoadFailureIfNeeded(exception_state,
                                    "Synchronous XHR in page dismissal. See "
                                    "https://www.chromestatus.com/feature/"
                                    "4664843055398912 for more details.");
        return;
      }
    } else {
      DCHECK(execution_context.IsWorkerGlobalScope());
      UseCounter::Count(&execution_context,
                        WebFeature::kXMLHttpRequestSynchronousInWorker);
    }
    resource_loader_options.synchronous_policy = kRequestSynchronously;
  }

  exception_code_ = DOMExceptionCode::kNoError;
  error_ = false;

  loader_ = MakeGarbageCollected<ThreadableLoader>(execution_context, this,
                                                   resource_loader_options);
  loader_->SetTimeout(timeout_);
  base::TimeTicks start_time = base::TimeTicks::Now();
  loader_->Start(std::move(request));

  if (!async_) {
    base::TimeDelta blocking_time = base::TimeTicks::Now() - start_time;

    probe::DidFinishSyncXHR(&execution_context, blocking_time);

    ThrowForLoadFailureIfNeeded(exception_state, String());
  }
}

void XMLHttpRequest::abort() {
  DVLOG(1) << this << " abort()";

  InternalAbort();

  // The script never gets any chance to call abort() on a sync XHR between
  // send() call and transition to the DONE state. It's because a sync XHR
  // doesn't dispatch any event between them. So, if |m_async| is false, we
  // can skip the "request error steps" (defined in the XHR spec) without any
  // state check.
  //
  // FIXME: It's possible open() is invoked in internalAbort() and |m_async|
  // becomes true by that. We should implement more reliable treatment for
  // nested method invocations at some point.
  if (async_) {
    if ((state_ == kOpened && send_flag_) || state_ == kHeadersReceived ||
        state_ == kLoading) {
      DCHECK(!loader_);
      HandleRequestError(DOMExceptionCode::kNoError, event_type_names::kAbort);
    }
  }
  if (state_ == kDone)
    state_ = kUnsent;
}

void XMLHttpRequest::Dispose() {
  progress_event_throttle_->Stop();
  InternalAbort();
  // TODO(yhirano): Remove this CHECK: see https://crbug.com/570946.
  CHECK(!loader_);
}

void XMLHttpRequest::ClearVariablesForLoading() {
  if (blob_loader_) {
    blob_loader_->Cancel();
    blob_loader_ = nullptr;
  }

  decoder_.reset();

  if (response_document_parser_) {
    response_document_parser_->RemoveClient(this);
    response_document_parser_->Detach();
    response_document_parser_ = nullptr;
  }
}

void XMLHttpRequest::InternalAbort() {
  // If there is an existing pending abort event, cancel it. The caller of this
  // function is responsible for firing any events on XMLHttpRequest, if
  // needed.
  pending_abort_event_.Cancel();

  // Fast path for repeated internalAbort()s; this
  // will happen if an XHR object is notified of context
  // destruction followed by finalization.
  if (error_ && !loader_)
    return;

  error_ = true;

  if (response_document_parser_ && !response_document_parser_->IsStopped())
    response_document_parser_->StopParsing();

  ClearVariablesForLoading();

  ClearResponse();
  ClearRequest();

  if (!loader_)
    return;

  ThreadableLoader* loader = loader_.Release();
  loader->Cancel();

  DCHECK(!loader_);
}

void XMLHttpRequest::ClearResponse() {
  // FIXME: when we add the support for multi-part XHR, we will have to
  // be careful with this initialization.
  received_length_ = 0;

  response_ = ResourceResponse();

  response_text_.Clear();

  parsed_response_ = false;
  response_document_ = nullptr;

  response_blob_ = nullptr;

  length_downloaded_to_blob_ = 0;
  downloading_to_blob_ = false;

  // These variables may referred by the response accessors. So, we can clear
  // this only when we clear the response holder variables above.
  binary_response_builder_ = nullptr;
  response_array_buffer_.Clear();
  response_array_buffer_failure_ = false;

  ReportMemoryUsageToV8();
}

void XMLHttpRequest::ClearRequest() {
  request_headers_.Clear();
}

void XMLHttpRequest::DispatchProgressEvent(const AtomicString& type,
                                           int64_t received_length,
                                           int64_t expected_length) {
  bool length_computable =
      expected_length > 0 && received_length <= expected_length;
  uint64_t loaded =
      received_length >= 0 ? static_cast<uint64_t>(received_length) : 0;
  uint64_t total =
      length_computable ? static_cast<uint64_t>(expected_length) : 0;

  std::optional<scheduler::TaskAttributionTracker::TaskScope>
      task_attribution_scope = MaybeCreateTaskAttributionScope();
  ExecutionContext* context = GetExecutionContext();
  probe::AsyncTask async_task(
      context, &async_task_context_,
      type == event_type_names::kLoadend ? nullptr : "progress", async_);
  progress_event_throttle_->DispatchProgressEvent(type, length_computable,
                                                  loaded, total);
}

void XMLHttpRequest::DispatchProgressEventFromSnapshot(
    const AtomicString& type) {
  DispatchProgressEvent(type, received_length_,
                        response_.ExpectedContentLength());
}

void XMLHttpRequest::HandleNetworkError() {
  DVLOG(1) << this << " handleNetworkError()";

  InternalAbort();

  HandleRequestError(DOMExceptionCode::kNetworkError, event_type_names::kError);
}

void XMLHttpRequest::HandleDidCancel() {
  DVLOG(1) << this << " handleDidCancel()";

  InternalAbort();

  pending_abort_event_ = PostCancellableTask(
      *GetExecutionContext()->GetTaskRunner(TaskType::kNetworking), FROM_HERE,
      WTF::BindOnce(&XMLHttpRequest::HandleRequestError, WrapPersistent(this),
                    DOMExceptionCode::kAbortError, event_type_names::kAbort));
}

void XMLHttpRequest::HandleRequestError(DOMExceptionCode exception_code,
                                        const AtomicString& type) {
  DVLOG(1) << this << " handleRequestError()";

  probe::DidFinishXHR(GetExecutionContext(), this);

  send_flag_ = false;
  if (!async_) {
    DCHECK_NE(exception_code, DOMExceptionCode::kNoError);
    state_ = kDone;
    exception_code_ = exception_code;
    return;
  }

  // With m_error set, the state change steps are minimal: any pending
  // progress event is flushed + a readystatechange is dispatched.
  // No new progress events dispatched; as required, that happens at
  // the end here.
  DCHECK(error_);
  ChangeState(kDone);

  if (!upload_complete_) {
    upload_complete_ = true;
    if (upload_ && upload_events_allowed_)
      upload_->HandleRequestError(type);
  }

  DispatchProgressEvent(type, /*received_length=*/0, /*expected_length=*/0);
  DispatchProgressEvent(event_type_names::kLoadend, /*received_length=*/0,
                        /*expected_length=*/0);

  parent_task_ = nullptr;
}

// https://xhr.spec.whatwg.org/#the-overridemimetype()-method
void XMLHttpRequest::overrideMimeType(const AtomicString& mime_type,
                                      ExceptionState& exception_state) {
  if (state_ == kLoading || state_ == kDone) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "MimeType cannot be overridden when the state is LOADING or DONE.");
    return;
  }

  mime_type_override_ = AtomicString("application/octet-stream");
  if (!ParsedContentType(mime_type).IsValid()) {
    return;
  }

  if (!net::ExtractMimeTypeFromMediaType(mime_type.Utf8(),
                                         /*accept_comma_separated=*/false)
           .has_value()) {
    return;
  }

  mime_type_override_ = mime_type;
}

// https://xhr.spec.whatwg.org/#the-setrequestheader()-method
void XMLHttpRequest::setRequestHeader(const AtomicString& name,
                                      const AtomicString& value,
                                      ExceptionState& exception_state) {
  // "1. If |state| is not "opened", throw an InvalidStateError exception.
  //  2. If the send() flag is set, throw an InvalidStateError exception."
  if (state_ != kOpened || send_flag_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The object's state must be OPENED.");
    return;
  }

  // "3. Normalize |value|."
  const String normalized_value = FetchUtils::NormalizeHeaderValue(value);

  // "4. If |name| is not a name or |value| is not a value, throw a SyntaxError
  //     exception."
  if (!IsValidHTTPToken(name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "'" + name + "' is not a valid HTTP header field name.");
    return;
  }
  if (!IsValidHTTPHeaderValue(normalized_value)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "'" + normalized_value + "' is not a valid HTTP header field value.");
    return;
  }

  // "5. Terminate these steps if (|name|, |value|) is a forbidden request
  //      header."
  // No script (privileged or not) can set unsafe headers.
  if (cors::IsForbiddenRequestHeader(name, value)) {
    LogConsoleError(GetExecutionContext(),
                    "Refused to set unsafe header \"" + name + "\"");
    return;
  }

  // "6. Combine |name|/|value| in author request headers."
  SetRequestHeaderInternal(name, AtomicString(normalized_value));
}

void XMLHttpRequest::SetRequestHeaderInternal(const AtomicString& name,
                                              const AtomicString& value) {
  DCHECK_EQ(value, FetchUtils::NormalizeHeaderValue(value))
      << "Header values must be normalized";
  HTTPHeaderMap::AddResult result = request_headers_.Add(name, value);
  if (!result.is_new_entry) {
    AtomicString new_value = result.stored_value->value + ", " + value;
    result.stored_value->value = new_value;
  }
}

void XMLHttpRequest::setPrivateToken(const PrivateToken* trust_token,
                                     ExceptionState& exception_state) {
  // These precondition checks are copied from |setRequestHeader|.
  if (state_ != kOpened || send_flag_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The object's state must be OPENED.");
    return;
  }

  auto params = network::mojom::blink::TrustTokenParams::New();
  if (!ConvertTrustTokenToMojomAndCheckPermissions(
          *trust_token, GetPSTFeatures(*GetExecutionContext()),
          &exception_state, params.get())) {
    DCHECK(exception_state.HadException());
    return;
  }

  trust_token_params_ = std::move(params);
}

void XMLHttpRequest::setAttributionReporting(
    const AttributionReportingRequestOptions* options,
    ExceptionState& exception_state) {
  // These precondition checks are copied from |setRequestHeader|.
  if (state_ != kOpened || send_flag_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The object's state must be OPENED.");
    return;
  }

  attribution_reporting_eligibility_ =
      ConvertAttributionReportingRequestOptionsToMojom(
          *options, *GetExecutionContext(), exception_state);
}

bool XMLHttpRequest::HasContentTypeRequestHeader() const {
  return request_headers_.Find(http_names::kContentType) !=
         request_headers_.end();
}

String XMLHttpRequest::getAllResponseHeaders() const {
  if (state_ < kHeadersReceived || error_)
    return "";

  StringBuilder string_builder;

  HTTPHeaderSet access_control_expose_header_set =
      cors::ExtractCorsExposedHeaderNamesList(
          with_credentials_ ? network::mojom::CredentialsMode::kInclude
                            : network::mojom::CredentialsMode::kSameOrigin,
          response_);

  // "Let |headers| be the result of sorting |initialHeaders| in ascending
  // order, with |a| being less than |b| if |a|’s name is legacy-uppercased-byte
  // less than |b|’s name."
  Vector<std::pair<String, String>> headers;
  // Although we omit some headers in |response_.HttpHeaderFields()| below,
  // we pre-allocate the buffer for performance.
  headers.ReserveInitialCapacity(response_.HttpHeaderFields().size());
  for (auto it = response_.HttpHeaderFields().begin();
       it != response_.HttpHeaderFields().end(); ++it) {
    // Hide any headers whose name is a forbidden response-header name.
    // This is required for all kinds of filtered responses.
    if (FetchUtils::IsForbiddenResponseHeaderName(it->key)) {
      continue;
    }

    if (response_.GetType() == network::mojom::FetchResponseType::kCors &&
        !cors::IsCorsSafelistedResponseHeader(it->key) &&
        access_control_expose_header_set.find(it->key.Ascii()) ==
            access_control_expose_header_set.end()) {
      continue;
    }

    headers.push_back(std::make_pair(it->key.UpperASCII(), it->value));
  }
  std::sort(headers.begin(), headers.end(),
            [](const std::pair<String, String>& x,
               const std::pair<String, String>& y) {
              return CodeUnitCompareLessThan(x.first, y.first);
            });
  for (const auto& header : headers) {
    string_builder.Append(header.first.LowerASCII());
    string_builder.Append(':');
    string_builder.Append(' ');
    string_builder.Append(header.second);
    string_builder.Append('\r');
    string_builder.Append('\n');
  }

  return string_builder.ToString();
}

const AtomicString& XMLHttpRequest::getResponseHeader(
    const AtomicString& name) const {
  if (state_ < kHeadersReceived || error_)
    return g_null_atom;

  if (FetchUtils::IsForbiddenResponseHeaderName(name)) {
    LogConsoleError(GetExecutionContext(),
                    "Refused to get unsafe header \"" + name + "\"");
    return g_null_atom;
  }

  HTTPHeaderSet access_control_expose_header_set =
      cors::ExtractCorsExposedHeaderNamesList(
          with_credentials_ ? network::mojom::CredentialsMode::kInclude
                            : network::mojom::CredentialsMode::kSameOrigin,
          response_);

  if (response_.GetType() == network::mojom::FetchResponseType::kCors &&
      !cors::IsCorsSafelistedResponseHeader(name) &&
      !base::Contains(access_control_expose_header_set, name.Ascii())) {
    LogConsoleError(GetExecutionContext(),
                    "Refused to get unsafe header \"" + name + "\"");
    return g_null_atom;
  }
  return response_.HttpHeaderField(name);
}

AtomicString XMLHttpRequest::FinalResponseMIMETypeInternal() const {
  std::optional<std::string> overridden_type =
      net::ExtractMimeTypeFromMediaType(mime_type_override_.Utf8(),
                                        /*accept_comma_separated=*/false);
  if (overridden_type.has_value()) {
    return AtomicString::FromUTF8(overridden_type->c_str());
  }

  if (response_.IsHTTP()) {
    AtomicString header = response_.HttpHeaderField(http_names::kContentType);
    std::optional<std::string> extracted_type =
        net::ExtractMimeTypeFromMediaType(header.Utf8(),
                                          /*accept_comma_separated=*/true);
    if (extracted_type.has_value()) {
      return AtomicString::FromUTF8(extracted_type->c_str());
    }

    return g_empty_atom;
  }

  return response_.MimeType();
}

// https://xhr.spec.whatwg.org/#response-body
AtomicString XMLHttpRequest::GetResponseMIMEType() const {
  AtomicString final_type = FinalResponseMIMETypeInternal();
  if (!final_type.empty())
    return final_type;

  return AtomicString("text/xml");
}

// https://xhr.spec.whatwg.org/#final-charset
WTF::TextEncoding XMLHttpRequest::FinalResponseCharset() const {
  // 1. Let label be null. [spec text]
  //
  // 2. If response MIME type's parameters["charset"] exists, then set label to
  // it. [spec text]
  String label = response_.TextEncodingName();

  // 3. If override MIME type's parameters["charset"] exists, then set label to
  // it. [spec text]
  String override_response_charset =
      ExtractCharsetFromMediaType(mime_type_override_);
  if (!override_response_charset.empty())
    label = override_response_charset;

  // 4. If label is null, then return null. [spec text]
  //
  // 5. Let encoding be the result of getting an encoding from label. [spec
  // text]
  //
  // 6. If encoding is failure, then return null. [spec text]
  //
  // 7. Return encoding. [spec text]
  //
  // We rely on WTF::TextEncoding() to return invalid TextEncoding for
  // null, empty, or invalid/unsupported |label|.
  return WTF::TextEncoding(label);
}

void XMLHttpRequest::UpdateContentTypeAndCharset(
    const AtomicString& default_content_type,
    const String& charset) {
  // http://xhr.spec.whatwg.org/#the-send()-method step 4's concilliation of
  // "charset=" in any author-provided Content-Type: request header.
  String content_type = request_headers_.Get(http_names::kContentType);
  if (content_type.IsNull()) {
    SetRequestHeaderInternal(http_names::kContentType, default_content_type);
    return;
  }
  String original_content_type = content_type;
  ReplaceCharsetInMediaType(content_type, charset);
  request_headers_.Set(http_names::kContentType, AtomicString(content_type));

  if (original_content_type != content_type) {
    UseCounter::Count(GetExecutionContext(), WebFeature::kReplaceCharsetInXHR);
    if (!EqualIgnoringASCIICase(original_content_type, content_type)) {
      UseCounter::Count(GetExecutionContext(),
                        WebFeature::kReplaceCharsetInXHRIgnoringCase);
    }
  }
}

bool XMLHttpRequest::ResponseIsXML() const {
  return MIMETypeRegistry::IsXMLMIMEType(GetResponseMIMEType());
}

bool XMLHttpRequest::ResponseIsHTML() const {
  return EqualIgnoringASCIICase(FinalResponseMIMETypeInternal(), "text/html");
}

int XMLHttpRequest::status() const {
  if (state_ == kUnsent || state_ == kOpened || error_)
    return 0;

  if (response_.HttpStatusCode())
    return response_.HttpStatusCode();

  return 0;
}

String XMLHttpRequest::statusText() const {
  if (state_ == kUnsent || state_ == kOpened || error_)
    return String();

  if (!response_.HttpStatusText().IsNull())
    return response_.HttpStatusText();

  return String();
}

void XMLHttpRequest::DidFail(uint64_t, const ResourceError& error) {
  DVLOG(1) << this << " didFail()";

  // If we are already in an error state, for instance we called abort(), bail
  // out early.
  if (error_)
    return;

  // Internally, access check violations are considered `cancellations`, but
  // at least the mixed-content and CSP specs require them to be surfaced as
  // network errors to the page. See:
  //   [1] https://www.w3.org/TR/mixed-content/#algorithms,
  //   [2] https://www.w3.org/TR/CSP3/#fetch-integration.
  if (error.IsCancellation() && !error.IsAccessCheck()) {
    HandleDidCancel();
    return;
  }

  if (error.IsTimeout()) {
    HandleDidTimeout();
    return;
  }

  HandleNetworkError();
}

void XMLHttpRequest::DidFailRedirectCheck(uint64_t) {
  DVLOG(1) << this << " didFailRedirectCheck()";

  HandleNetworkError();
}

void XMLHttpRequest::DidFinishLoading(uint64_t identifier) {
  DVLOG(1) << this << " didFinishLoading(" << identifier << ")";

  if (error_)
    return;

  if (state_ < kHeadersReceived)
    ChangeState(kHeadersReceived);

  if (downloading_to_blob_ &&
      response_type_code_ != V8XMLHttpRequestResponseType::Enum::kBlob &&
      response_blob_) {
    // In this case, we have sent the request with DownloadToBlob true,
    // but the user changed the response type after that. Hence we need to
    // read the response data and provide it to this object.
    blob_loader_ = MakeGarbageCollected<BlobLoader>(
        this, response_blob_->GetBlobDataHandle());
  } else {
    DidFinishLoadingInternal();
  }
}

void XMLHttpRequest::DidFinishLoadingInternal() {
  if (response_document_parser_) {
    response_document_parser_->Finish();
    // The remaining logic lives in `XMLHttpRequest::NotifyParserStopped()`
    // which is called by `DocumentParser::Finish()` synchronously or
    // asynchronously.
    return;
  }

  if (decoder_) {
    if (!response_text_overflow_) {
      auto text = decoder_->Flush();
      if (response_text_.DoesAppendCauseOverflow(text.length())) {
        response_text_overflow_ = true;
        response_text_.Clear();
      } else {
        response_text_.Append(text);
      }
    }
    ReportMemoryUsageToV8();
  }

  ClearVariablesForLoading();
  EndLoading();
}

void XMLHttpRequest::DidFinishLoadingFromBlob() {
  DVLOG(1) << this << " didFinishLoadingFromBlob";

  DidFinishLoadingInternal();
}

void XMLHttpRequest::DidFailLoadingFromBlob() {
  DVLOG(1) << this << " didFailLoadingFromBlob()";

  if (error_)
    return;
  HandleNetworkError();
}

void XMLHttpRequest::NotifyParserStopped() {
  // This should only be called when response document is parsed asynchronously.
  DCHECK(response_document_parser_);
  DCHECK(!response_document_parser_->IsParsing());

  // Do nothing if we are called from |internalAbort()|.
  if (error_)
    return;

  ClearVariablesForLoading();

  if (!response_document_->WellFormed())
    response_document_ = nullptr;

  parsed_response_ = true;

  EndLoading();
}

void XMLHttpRequest::EndLoading() {
  probe::DidFinishXHR(GetExecutionContext(), this);

  if (loader_) {
    // Set |m_error| in order to suppress the cancel notification (see
    // XMLHttpRequest::didFail).
    base::AutoReset<bool> scope(&error_, true);
    loader_.Release()->Cancel();
  }

  send_flag_ = false;
  ChangeState(kDone);

  if (auto* window = DynamicTo<LocalDOMWindow>(GetExecutionContext())) {
    LocalFrame* frame = window->GetFrame();
    if (frame && network::IsSuccessfulStatus(status()))
      frame->GetPage()->GetChromeClient().AjaxSucceeded(frame);
  }

  parent_task_ = nullptr;
}

void XMLHttpRequest::DidSendData(uint64_t bytes_sent,
                                 uint64_t total_bytes_to_be_sent) {
  DVLOG(1) << this << " didSendData(" << bytes_sent << ", "
           << total_bytes_to_be_sent << ")";
  if (!upload_)
    return;

  if (upload_events_allowed_)
    upload_->DispatchProgressEvent(bytes_sent, total_bytes_to_be_sent);

  if (bytes_sent == total_bytes_to_be_sent && !upload_complete_) {
    upload_complete_ = true;
    if (upload_events_allowed_) {
      upload_->DispatchEventAndLoadEnd(event_type_names::kLoad, true,
                                       bytes_sent, total_bytes_to_be_sent);
    }
  }
}

void XMLHttpRequest::DidReceiveResponse(uint64_t identifier,
                                        const ResourceResponse& response) {
  // TODO(yhirano): Remove this CHECK: see https://crbug.
"""


```