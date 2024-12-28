Response:
The user wants to understand the functionality of the `xml_http_request.cc` file in the Chromium Blink rendering engine. They've provided the first part of the source code and need a summary of its purpose. I should focus on identifying the core responsibilities and relate them to web technologies like JavaScript, HTML, and CSS where applicable. I also need to consider common usage errors and how they might lead to this code being executed.

Here's a breakdown of how to approach this:

1. **Identify Core Class:** The filename and the initial lines clearly indicate this file defines the `XMLHttpRequest` class.

2. **Core Functionality:**  `XMLHttpRequest` is the foundation for asynchronous HTTP requests in web browsers. The code snippet confirms this by including methods like `open`, `send`, and handling response data.

3. **Relationship to Web Technologies:**
    * **JavaScript:** `XMLHttpRequest` is directly used in JavaScript to make web requests.
    * **HTML:**  The requests are often triggered by user interactions or scripts within an HTML document. The response might update parts of the HTML.
    * **CSS:** While not directly involved in *making* the requests, the *results* of the requests (e.g., updated HTML) can influence the rendered CSS.

4. **Logical Inference (Based on Code Snippet):**
    * **Input:**  JavaScript code calls `xhr.open()` with a method (e.g., "GET", "POST") and a URL. Then `xhr.send()` is called.
    * **Output:** The `XMLHttpRequest` object internally sets up and executes a network request. The code manages state changes (`readyState`), handles different response types (text, XML, JSON, Blob, ArrayBuffer), and dispatches events (`readystatechange`, `progress`, `load`, `loadend`).

5. **Common User Errors:**
    * Incorrect usage of `open` (e.g., invalid method or URL).
    * Calling `send` before `open`.
    * Setting `responseType` after the request has started.
    * Making synchronous requests on the main thread (which is discouraged).

6. **Debugging Scenario:**  A developer might be stepping through the JavaScript code in their browser's developer tools, and the execution flow enters the `XMLHttpRequest::send` method within this C++ file.

7. **Summarization (for Part 1):** Focus on the initial setup and the `open` method, along with the basic state management.
这是 `blink/renderer/core/xmlhttprequest/xml_http_request.cc` 文件的第一部分，主要负责实现 Chromium Blink 引擎中 `XMLHttpRequest` 接口的核心功能。 `XMLHttpRequest` 是一个 Web API，允许 JavaScript 代码向服务器发起 HTTP 请求，并处理服务器的响应，而无需重新加载整个页面。

以下是根据提供的代码片段归纳出的主要功能点：

**核心功能：**

* **XMLHttpRequest 对象的创建和初始化:**  提供了创建 `XMLHttpRequest` 对象的方法 (`Create`) 和构造函数，用于初始化对象的状态和相关成员变量。
* **状态管理:**  维护 `XMLHttpRequest` 对象的状态 (`readyState`)，包括 `UNSENT`, `OPENED` 等状态，并通过 `ChangeState` 方法进行状态更新。
* **`open()` 方法的实现:**  实现了 `open()` 方法的各种重载形式，用于初始化请求方法 (GET, POST 等)、URL、是否异步、用户名和密码等信息。  此方法会进行 URL 格式和 HTTP 方法的校验。
* **异步和同步请求处理:**  区分并处理异步 (`async = true`) 和同步 (`async = false`) 的 HTTP 请求。  特别地，对于在文档上下文中发起的同步请求，会进行额外的限制和警告。
* **请求头设置:**  虽然这部分代码没有直接展示设置请求头的代码，但可以推断出该文件会管理请求头信息，因为 `XMLHttpRequest` 允许通过 `setRequestHeader` 方法设置请求头。
* **请求体的处理:**  实现了 `send()` 方法的各种重载形式，用于处理不同类型的请求体数据，包括字符串、`Document`、`Blob`、`ArrayBuffer`、`FormData` 和 `URLSearchParams` 等。
* **错误处理:**  包含一些基本的错误检查和处理机制，例如对无效的 HTTP 方法和 URL 的校验，以及在特定状态下调用方法时抛出异常。
* **事件分发:**  负责分发 `readystatechange` 事件，用于通知 JavaScript 代码 `XMLHttpRequest` 对象的状态变化。  也提到了 `progress`, `load`, `loadend` 等事件的触发。
* **`responseType` 的设置和获取:**  允许设置和获取响应类型 (`responseType`)，例如 "text", "document", "json", "blob", "arraybuffer"。  并对在特定状态下设置 `responseType` 进行了限制。
* **超时设置:**  允许设置请求的超时时间 (`timeout`)。
* **`withCredentials` 属性:**  实现了 `withCredentials` 属性的设置，用于控制跨域请求是否携带凭据（例如 Cookie）。
* **内部清理:**  提供了 `InternalAbort()` 方法用于中断当前的请求，并重置 `XMLHttpRequest` 对象的状态。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  `XMLHttpRequest` 是由 JavaScript 代码调用的核心 API，用于实现 Ajax (Asynchronous JavaScript and XML) 技术。JavaScript 通过 `new XMLHttpRequest()` 创建对象，然后调用其 `open()` 和 `send()` 方法发起请求，并通过事件监听器处理服务器响应。
    * **例子:**
        ```javascript
        let xhr = new XMLHttpRequest();
        xhr.open('GET', 'https://example.com/data.json');
        xhr.onload = function() {
            console.log(xhr.responseText);
        };
        xhr.send();
        ```
* **HTML:**  HTML 页面中的 JavaScript 代码可以使用 `XMLHttpRequest` 来动态获取或提交数据，从而更新页面内容，实现更丰富的用户交互。  例如，点击按钮后，JavaScript 使用 `XMLHttpRequest` 从服务器获取数据并更新页面上的某个 `<div>` 元素。
    * **例子:** HTML 中一个按钮，点击后触发 JavaScript 代码，该代码使用 `XMLHttpRequest` 获取服务器数据并更新按钮下方的段落：
        ```html
        <button onclick="loadData()">加载数据</button>
        <p id="data"></p>
        <script>
          function loadData() {
            let xhr = new XMLHttpRequest();
            xhr.open('GET', '/api/data');
            xhr.onload = function() {
              document.getElementById('data').textContent = xhr.responseText;
            };
            xhr.send();
          }
        </script>
        ```
* **CSS:**  `XMLHttpRequest` 本身不直接操作 CSS。但是，通过 `XMLHttpRequest` 获取的数据可以用来动态修改 HTML 结构或内容，从而间接地影响页面的 CSS 样式。 例如，根据服务器返回的数据，JavaScript 可以添加或移除 HTML 元素的类名，从而应用不同的 CSS 样式。
    * **例子:**  服务器返回用户主题偏好，JavaScript 使用 `XMLHttpRequest` 获取后，根据主题偏好给 `<body>` 标签添加不同的类名，应用不同的 CSS 主题：
        ```javascript
        let xhr = new XMLHttpRequest();
        xhr.open('GET', '/api/user_theme');
        xhr.onload = function() {
            document.body.classList.add(xhr.responseText); // 例如返回 "dark-theme"
        };
        xhr.send();
        ```

**逻辑推理 (假设输入与输出):**

* **假设输入:** JavaScript 代码调用 `xhr.open('POST', '/submit', false);` （同步请求）。
* **输出:** `XMLHttpRequest::open` 方法会被调用，`method_` 将被设置为 "POST"，`url_` 将被设置为 `/submit` 的完整 URL，`async_` 将被设置为 `false`。由于是同步请求，并且是在文档上下文中，会检查 `GetSettings()->GetSyncXHRInDocumentsEnabled()` 的值，如果禁用，会抛出 `InvalidAccessError` 异常。同时，会记录同步 XHR 的使用情况。

**用户或编程常见的使用错误:**

* **在 `open()` 之前调用 `send()`:**  会导致 `InvalidStateError` 异常。
    * **例子:**
        ```javascript
        let xhr = new XMLHttpRequest();
        xhr.send(); // 错误：应该先调用 open()
        xhr.open('GET', '/data');
        ```
* **在 `LOADING` 或 `DONE` 状态下设置 `responseType`:** 也会导致 `InvalidStateError` 异常。
    * **例子:**
        ```javascript
        let xhr = new XMLHttpRequest();
        xhr.open('GET', '/data');
        xhr.send();
        xhr.responseType = 'json'; // 错误：在请求发送后设置
        ```
* **在文档上下文中发起同步请求:**  可能会导致浏览器冻结，影响用户体验。浏览器通常会发出警告，甚至禁止这种行为。
    * **例子:**
        ```javascript
        let xhr = new XMLHttpRequest();
        xhr.open('GET', '/data', false); // 应该尽量避免在主线程使用同步请求
        xhr.send();
        ```
* **使用无效的 HTTP 方法名:**  会导致 `SyntaxError` 异常。
    * **例子:**
        ```javascript
        let xhr = new XMLHttpRequest();
        xhr.open('GET-DATA', '/data'); // 错误的方法名
        ```

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中打开一个网页。**
2. **网页的 JavaScript 代码被执行。**
3. **JavaScript 代码创建了一个 `XMLHttpRequest` 对象。**
4. **JavaScript 代码调用了 `xhr.open()` 方法，传入了请求方法和 URL。**  此时，Blink 引擎会执行 `blink/renderer/core/xmlhttprequest/xml_http_request.cc` 文件中的 `XMLHttpRequest::open()` 方法。
5. **如果 `open()` 方法调用成功，JavaScript 代码会继续调用 `xhr.send()` 方法来发送请求。** 这将触发该文件中的 `XMLHttpRequest::send()` 方法。
6. **在请求过程中，服务器的响应数据到达浏览器。** 这会触发与接收数据相关的代码，可能会调用 `DidReceiveData` 等方法。
7. **请求完成（成功或失败），会触发相应的事件，例如 `onload` 或 `onerror`。**  Blink 引擎会更新 `XMLHttpRequest` 对象的状态，并分发 `readystatechange` 等事件。

在调试过程中，开发者可以使用浏览器的开发者工具设置断点在 `XMLHttpRequest::open()` 或 `XMLHttpRequest::send()` 等方法中，以便观察代码的执行流程和变量的值，从而追踪问题。

**总结 (针对第一部分):**

这部分代码主要负责 `XMLHttpRequest` 对象的初始化、状态管理和 `open()` 方法的实现，是发起 HTTP 请求的起始阶段。它处理了请求方法、URL、同步/异步模式的设置，并对一些不合法的操作进行了校验和限制，为后续的请求发送和响应处理奠定了基础。

Prompt: 
```
这是目录为blink/renderer/core/xmlhttprequest/xml_http_request.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 *  Copyright (C) 2004, 2006, 2008 Apple Inc. All rights reserved.
 *  Copyright (C) 2005-2007 Alexey Proskuryakov <ap@webkit.org>
 *  Copyright (C) 2007, 2008 Julien Chaffraix <jchaffraix@webkit.org>
 *  Copyright (C) 2008, 2011 Google Inc. All rights reserved.
 *  Copyright (C) 2012 Intel Corporation
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *  Boston, MA 02110-1301 USA
 */

#include "third_party/blink/renderer/core/xmlhttprequest/xml_http_request.h"

#include <memory>
#include <optional>
#include <utility>

#include "base/auto_reset.h"
#include "base/containers/contains.h"
#include "base/containers/span.h"
#include "base/feature_list.h"
#include "base/numerics/safe_conversions.h"
#include "base/time/time.h"
#include "net/base/mime_util.h"
#include "services/network/public/cpp/header_util.h"
#include "services/network/public/mojom/trust_tokens.mojom-shared.h"
#include "third_party/blink/public/common/blob/blob_utils.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink-forward.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_private_token.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview_blob_document_formdata_urlsearchparams_usvstring.h"
#include "third_party/blink/renderer/core/dom/document_init.h"
#include "third_party/blink/renderer/core/dom/document_parser.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/xml_document.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/event_target_names.h"
#include "third_party/blink/renderer/core/events/progress_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fetch/attribution_reporting_to_mojom.h"
#include "third_party/blink/renderer/core/fetch/trust_token_to_mojom.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/fileapi/file.h"
#include "third_party/blink/renderer/core/fileapi/file_reader_client.h"
#include "third_party/blink/renderer/core/fileapi/file_reader_loader.h"
#include "third_party/blink/renderer/core/fileapi/public_url_manager.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/page_dismissal_scope.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/forms/form_data.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/parser/text_resource_decoder.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/loader/threadable_loader.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_view.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/core/url/url_search_params.h"
#include "third_party/blink/renderer/core/xmlhttprequest/xml_http_request_upload.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/file_metadata.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/cors/cors.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_utils.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_error.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/text_resource_decoder_options.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/network/mime/mime_type_registry.h"
#include "third_party/blink/renderer/platform/network/parsed_content_type.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_tracker.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

// These methods were placed in HTTPParsers.h. Since these methods don't
// perform ABNF validation but loosely look for the part that is likely to be
// indicating the charset parameter, new code should use
// HttpUtil::ParseContentType() than these. To discourage use of these methods,
// moved from HTTPParser.h to the only user XMLHttpRequest.cpp.
//
// TODO(tyoshino): Switch XHR to use HttpUtil. See crbug.com/743311.
void FindCharsetInMediaType(const String& media_type,
                            unsigned& charset_pos,
                            unsigned& charset_len) {
  charset_len = 0;

  unsigned pos = charset_pos;
  unsigned length = media_type.length();

  while (pos < length) {
    pos = media_type.FindIgnoringASCIICase("charset", pos);

    if (pos == kNotFound)
      return;

    // Give up if we find "charset" at the head.
    if (!pos)
      return;

    // Now check that "charset" is not a substring of some longer word.
    if (media_type[pos - 1] > ' ' && media_type[pos - 1] != ';') {
      pos += 7;
      continue;
    }

    pos += 7;

    while (pos < length && media_type[pos] <= ' ')
      ++pos;

    // Treat this as a charset parameter.
    if (media_type[pos++] == '=')
      break;
  }

  while (pos < length && (media_type[pos] <= ' ' || media_type[pos] == '"' ||
                          media_type[pos] == '\''))
    ++pos;

  charset_pos = pos;

  // we don't handle spaces within quoted parameter values, because charset
  // names cannot have any
  while (pos < length && media_type[pos] > ' ' && media_type[pos] != '"' &&
         media_type[pos] != '\'' && media_type[pos] != ';')
    ++pos;

  charset_len = pos - charset_pos;
}
String ExtractCharsetFromMediaType(const String& media_type) {
  unsigned pos = 0;
  unsigned len = 0;
  FindCharsetInMediaType(media_type, pos, len);
  return media_type.Substring(pos, len);
}

void ReplaceCharsetInMediaType(String& media_type,
                               const String& charset_value) {
  unsigned pos = 0;

  while (true) {
    unsigned len = 0;
    FindCharsetInMediaType(media_type, pos, len);
    if (!len)
      return;
    media_type.replace(pos, len, charset_value);
    pos += charset_value.length();
  }
}

void LogConsoleError(ExecutionContext* context, const String& message) {
  if (!context)
    return;
  // FIXME: It's not good to report the bad usage without indicating what source
  // line it came from.  We should pass additional parameters so we can tell the
  // console where the mistake occurred.
  auto* console_message = MakeGarbageCollected<ConsoleMessage>(
      mojom::ConsoleMessageSource::kJavaScript,
      mojom::ConsoleMessageLevel::kError, message);
  context->AddConsoleMessage(console_message);
}

bool ValidateOpenArguments(const AtomicString& method,
                           const KURL& url,
                           ExceptionState& exception_state) {
  if (!IsValidHTTPToken(method)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "'" + method + "' is not a valid HTTP method.");
    return false;
  }

  if (FetchUtils::IsForbiddenMethod(method)) {
    exception_state.ThrowSecurityError("'" + method +
                                       "' HTTP method is unsupported.");
    return false;
  }

  if (!url.IsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "Invalid URL");
    return false;
  }

  return true;
}

}  // namespace

class XMLHttpRequest::BlobLoader final
    : public GarbageCollected<XMLHttpRequest::BlobLoader>,
      public FileReaderClient {
 public:
  BlobLoader(XMLHttpRequest* xhr, scoped_refptr<BlobDataHandle> handle)
      : xhr_(xhr),
        loader_(MakeGarbageCollected<FileReaderLoader>(
            this,
            xhr->GetExecutionContext()->GetTaskRunner(
                TaskType::kFileReading))) {
    loader_->Start(std::move(handle));
  }

  // FileReaderClient functions.
  FileErrorCode DidStartLoading(uint64_t) override {
    return FileErrorCode::kOK;
  }
  FileErrorCode DidReceiveData(base::span<const uint8_t> data) override {
    DCHECK_LE(data.size(), static_cast<size_t>(INT_MAX));
    xhr_->DidReceiveData(base::as_chars(data));
    return FileErrorCode::kOK;
  }
  void DidFinishLoading() override { xhr_->DidFinishLoadingFromBlob(); }
  void DidFail(FileErrorCode error) override { xhr_->DidFailLoadingFromBlob(); }

  void Cancel() { loader_->Cancel(); }

  void Trace(Visitor* visitor) const override {
    FileReaderClient::Trace(visitor);
    visitor->Trace(xhr_);
    visitor->Trace(loader_);
  }

 private:
  Member<XMLHttpRequest> xhr_;
  Member<FileReaderLoader> loader_;
};

XMLHttpRequest* XMLHttpRequest::Create(ScriptState* script_state) {
  return MakeGarbageCollected<XMLHttpRequest>(
      ExecutionContext::From(script_state), &script_state->World());
}

XMLHttpRequest* XMLHttpRequest::Create(ExecutionContext* context) {
  return MakeGarbageCollected<XMLHttpRequest>(context, nullptr);
}

XMLHttpRequest::XMLHttpRequest(ExecutionContext* context,
                               const DOMWrapperWorld* world)
    : ActiveScriptWrappable<XMLHttpRequest>({}),
      ExecutionContextLifecycleObserver(context),
      progress_event_throttle_(
          MakeGarbageCollected<XMLHttpRequestProgressEventThrottle>(this)),
      world_(world),
      isolated_world_security_origin_(world_ && world_->IsIsolatedWorld()
                                          ? world_->IsolatedWorldSecurityOrigin(
                                                context->GetAgentClusterID())
                                          : nullptr) {}

XMLHttpRequest::~XMLHttpRequest() {
  binary_response_builder_ = nullptr;
  length_downloaded_to_blob_ = 0;
  response_text_.Clear();
  ReportMemoryUsageToV8();
}

XMLHttpRequest::State XMLHttpRequest::readyState() const {
  return state_;
}

String XMLHttpRequest::responseText(ExceptionState& exception_state) {
  if (response_type_code_ != kResponseTypeDefault &&
      response_type_code_ != V8XMLHttpRequestResponseType::Enum::kText) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The value is only accessible if the "
                                      "object's 'responseType' is '' or 'text' "
                                      "(was '" +
                                          responseType().AsString() + "').");
    return String();
  }
  if (error_ || (state_ != kLoading && state_ != kDone))
    return String();
  return response_text_.ToString();
}

void XMLHttpRequest::InitResponseDocument() {
  // The W3C spec requires the final MIME type to be some valid XML type, or
  // text/html.  If it is text/html, then the responseType of "document" must
  // have been supplied explicitly.
  bool is_html = ResponseIsHTML();
  if ((response_.IsHTTP() && !ResponseIsXML() && !is_html) ||
      (is_html && response_type_code_ == kResponseTypeDefault) ||
      !GetExecutionContext() || GetExecutionContext()->IsWorkerGlobalScope()) {
    response_document_ = nullptr;
    return;
  }

  DocumentInit init = DocumentInit::Create()
                          .WithExecutionContext(GetExecutionContext())
                          .WithAgent(*GetExecutionContext()->GetAgent())
                          .WithURL(response_.ResponseUrl());
  if (is_html) {
    response_document_ = MakeGarbageCollected<HTMLDocument>(init);
    response_document_->setAllowDeclarativeShadowRoots(false);
  } else
    response_document_ = MakeGarbageCollected<XMLDocument>(init);

  // FIXME: Set Last-Modified.
  response_document_->SetMimeType(GetResponseMIMEType());
}

Document* XMLHttpRequest::responseXML(ExceptionState& exception_state) {
  if (response_type_code_ != kResponseTypeDefault &&
      response_type_code_ != V8XMLHttpRequestResponseType::Enum::kDocument) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The value is only accessible if the "
                                      "object's 'responseType' is '' or "
                                      "'document' (was '" +
                                          responseType().AsString() + "').");
    return nullptr;
  }

  if (error_ || state_ != kDone)
    return nullptr;

  if (!parsed_response_) {
    InitResponseDocument();
    if (!response_document_)
      return nullptr;

    response_document_->SetContent(response_text_.ToString());
    if (!response_document_->WellFormed()) {
      response_document_ = nullptr;
    } else {
      response_document_->OverrideLastModified(
          response_.HttpHeaderField(http_names::kLastModified));
    }

    parsed_response_ = true;
  }

  return response_document_.Get();
}

v8::Local<v8::Value> XMLHttpRequest::ResponseJSON(ScriptState* script_state) {
  DCHECK_EQ(response_type_code_, V8XMLHttpRequestResponseType::Enum::kJson);
  DCHECK(!error_);
  DCHECK_EQ(state_, kDone);
  // Catch syntax error. Swallows an exception (when thrown) as the
  // spec says. https://xhr.spec.whatwg.org/#response-body
  v8::TryCatch try_catch(script_state->GetIsolate());
  v8::Local<v8::Value> json =
      FromJSONString(script_state, response_text_.ToString());
  if (try_catch.HasCaught()) {
    return v8::Null(script_state->GetIsolate());
  }
  return json;
}

Blob* XMLHttpRequest::ResponseBlob() {
  DCHECK_EQ(response_type_code_, V8XMLHttpRequestResponseType::Enum::kBlob);
  DCHECK(!error_);
  DCHECK_EQ(state_, kDone);

  if (!response_blob_) {
    auto blob_data = std::make_unique<BlobData>();
    blob_data->SetContentType(GetResponseMIMEType().LowerASCII());
    size_t size = 0;
    if (binary_response_builder_ && binary_response_builder_->size()) {
      for (const auto& span : *binary_response_builder_)
        blob_data->AppendBytes(base::as_bytes(span));
      size = binary_response_builder_->size();
      binary_response_builder_ = nullptr;
      ReportMemoryUsageToV8();
    }
    response_blob_ = MakeGarbageCollected<Blob>(
        BlobDataHandle::Create(std::move(blob_data), size));
  }

  return response_blob_.Get();
}

DOMArrayBuffer* XMLHttpRequest::ResponseArrayBuffer() {
  DCHECK_EQ(response_type_code_,
            V8XMLHttpRequestResponseType::Enum::kArraybuffer);
  DCHECK(!error_);
  DCHECK_EQ(state_, kDone);

  if (!response_array_buffer_ && !response_array_buffer_failure_) {
    if (binary_response_builder_ && binary_response_builder_->size()) {
      DOMArrayBuffer* buffer = DOMArrayBuffer::CreateUninitializedOrNull(
          binary_response_builder_->size(), 1);
      if (buffer) {
        bool result = binary_response_builder_->GetBytes(buffer->ByteSpan());
        DCHECK(result);
        response_array_buffer_ = buffer;
      }
      // https://xhr.spec.whatwg.org/#arraybuffer-response allows clearing
      // of the 'received bytes' payload when the response buffer allocation
      // fails.
      binary_response_builder_ = nullptr;
      ReportMemoryUsageToV8();
      // Mark allocation as failed; subsequent calls to the accessor must
      // continue to report |null|.
      //
      response_array_buffer_failure_ = !buffer;
    } else {
      response_array_buffer_ = DOMArrayBuffer::Create(base::span<uint8_t>());
    }
  }

  return response_array_buffer_.Get();
}

// https://xhr.spec.whatwg.org/#dom-xmlhttprequest-response
v8::Local<v8::Value> XMLHttpRequest::response(ScriptState* script_state) {
  // The spec handles default or `text` responses as a special case, because
  // these cases are allowed to access the response while still loading.
  if (response_type_code_ == kResponseTypeDefault ||
      response_type_code_ == V8XMLHttpRequestResponseType::Enum::kText) {
    return ToV8Traits<IDLString>::ToV8(script_state,
                                       responseText(ASSERT_NO_EXCEPTION));
  }

  if (error_ || state_ != kDone) {
    return v8::Null(script_state->GetIsolate());
  }

  switch (response_type_code_) {
    case V8XMLHttpRequestResponseType::Enum::kJson:
      return ResponseJSON(script_state);
    case V8XMLHttpRequestResponseType::Enum::kDocument: {
      return ToV8Traits<IDLNullable<Document>>::ToV8(
          script_state, responseXML(ASSERT_NO_EXCEPTION));
    }
    case V8XMLHttpRequestResponseType::Enum::kBlob:
      return ToV8Traits<Blob>::ToV8(script_state, ResponseBlob());
    case V8XMLHttpRequestResponseType::Enum::kArraybuffer:
      return ToV8Traits<IDLNullable<DOMArrayBuffer>>::ToV8(
          script_state, ResponseArrayBuffer());
    default:
      NOTREACHED();
  }
}

void XMLHttpRequest::setTimeout(unsigned timeout,
                                ExceptionState& exception_state) {
  // FIXME: Need to trigger or update the timeout Timer here, if needed.
  // http://webkit.org/b/98156
  // XHR2 spec, 4.7.3. "This implies that the timeout attribute can be set while
  // fetching is in progress. If that occurs it will still be measured relative
  // to the start of fetching."
  if (GetExecutionContext() && GetExecutionContext()->IsWindow() && !async_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "Timeouts cannot be set for synchronous "
                                      "requests made from a document.");
    return;
  }

  timeout_ = base::Milliseconds(timeout);

  // From http://www.w3.org/TR/XMLHttpRequest/#the-timeout-attribute:
  // Note: This implies that the timeout attribute can be set while fetching is
  // in progress. If that occurs it will still be measured relative to the start
  // of fetching.
  //
  // The timeout may be overridden after send.
  if (loader_)
    loader_->SetTimeout(timeout_);
}

void XMLHttpRequest::setResponseType(
    const V8XMLHttpRequestResponseType& response_type,
    ExceptionState& exception_state) {
  const bool is_window =
      GetExecutionContext() && GetExecutionContext()->IsWindow();
  // 1. If the current global object is not a Window object and the given value
  // is "document", then return.
  if (!is_window && response_type == "document") {
    return;
  }

  // 2. If this’s state is loading or done, then throw an "InvalidStateError"
  // DOMException.
  if (state_ >= kLoading) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The response type cannot be set if the "
                                      "object's state is LOADING or DONE.");
    return;
  }

  // Newer functionality is not available to synchronous requests in window
  // contexts, as a spec-mandated attempt to discourage synchronous XHR use.
  // responseType is one such piece of functionality.
  if (is_window && !async_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The response type cannot be changed for "
                                      "synchronous requests made from a "
                                      "document.");
    return;
  }

  response_type_code_ = response_type.AsEnum();
}

V8XMLHttpRequestResponseType XMLHttpRequest::responseType() {
  return V8XMLHttpRequestResponseType(response_type_code_);
}

String XMLHttpRequest::responseURL() {
  KURL response_url(response_.ResponseUrl());
  if (!response_url.IsNull())
    response_url.RemoveFragmentIdentifier();
  return response_url.GetString();
}

XMLHttpRequestUpload* XMLHttpRequest::upload() {
  if (!upload_)
    upload_ = MakeGarbageCollected<XMLHttpRequestUpload>(this);
  return upload_.Get();
}

void XMLHttpRequest::TrackProgress(uint64_t length) {
  received_length_ += length;

  ChangeState(kLoading);
  if (async_) {
    // readyStateChange event is fired as well.
    DispatchProgressEventFromSnapshot(event_type_names::kProgress);
  }
}

void XMLHttpRequest::ChangeState(State new_state) {
  if (state_ != new_state) {
    state_ = new_state;
    DispatchReadyStateChangeEvent();
  }
}

void XMLHttpRequest::DispatchReadyStateChangeEvent() {
  if (!GetExecutionContext())
    return;

  if (async_ || (state_ <= kOpened || state_ == kDone)) {
    DEVTOOLS_TIMELINE_TRACE_EVENT("XHRReadyStateChange",
                                  inspector_xhr_ready_state_change_event::Data,
                                  GetExecutionContext(), this);
    XMLHttpRequestProgressEventThrottle::DeferredEventAction action =
        XMLHttpRequestProgressEventThrottle::kIgnore;
    if (state_ == kDone) {
      if (error_)
        action = XMLHttpRequestProgressEventThrottle::kClear;
      else
        action = XMLHttpRequestProgressEventThrottle::kFlush;
    }
    std::optional<scheduler::TaskAttributionTracker::TaskScope>
        task_attribution_scope = MaybeCreateTaskAttributionScope();
    progress_event_throttle_->DispatchReadyStateChangeEvent(
        Event::Create(event_type_names::kReadystatechange), action);
  }

  if (state_ == kDone && !error_) {
    DEVTOOLS_TIMELINE_TRACE_EVENT("XHRLoad", inspector_xhr_load_event::Data,
                                  GetExecutionContext(), this);
    DispatchProgressEventFromSnapshot(event_type_names::kLoad);
    DispatchProgressEventFromSnapshot(event_type_names::kLoadend);
  }
}

void XMLHttpRequest::setWithCredentials(bool value,
                                        ExceptionState& exception_state) {
  if (state_ > kOpened || send_flag_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The value may only be set if the object's state is UNSENT or OPENED.");
    return;
  }

  with_credentials_ = value;
}

void XMLHttpRequest::open(const AtomicString& method,
                          const String& url_string,
                          ExceptionState& exception_state) {
  if (!GetExecutionContext())
    return;

  KURL url(GetExecutionContext()->CompleteURL(url_string));
  if (!ValidateOpenArguments(method, url, exception_state))
    return;

  open(method, url, true, exception_state);
}

void XMLHttpRequest::open(const AtomicString& method,
                          const String& url_string,
                          bool async,
                          const String& username,
                          const String& password,
                          ExceptionState& exception_state) {
  if (!GetExecutionContext())
    return;

  KURL url(GetExecutionContext()->CompleteURL(url_string));
  if (!ValidateOpenArguments(method, url, exception_state))
    return;

  if (!username.IsNull())
    url.SetUser(username);
  if (!password.IsNull())
    url.SetPass(password);

  open(method, url, async, exception_state);
}

void XMLHttpRequest::open(const AtomicString& method,
                          const KURL& url,
                          bool async,
                          ExceptionState& exception_state) {
  DVLOG(1) << this << " open(" << method << ", " << url.ElidedString() << ", "
           << async << ")";

  DCHECK(ValidateOpenArguments(method, url, exception_state));

  InternalAbort();

  State previous_state = state_;
  state_ = kUnsent;
  error_ = false;
  upload_complete_ = false;
  parent_task_ = nullptr;

  auto* window = DynamicTo<LocalDOMWindow>(GetExecutionContext());
  if (!async && window) {
    if (window->GetFrame() &&
        !window->GetFrame()->GetSettings()->GetSyncXHRInDocumentsEnabled()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidAccessError,
          "Synchronous requests are disabled for this page.");
      return;
    }

    // Newer functionality is not available to synchronous requests in window
    // contexts, as a spec-mandated attempt to discourage synchronous XHR use.
    // responseType is one such piece of functionality.
    if (response_type_code_ != V8XMLHttpRequestResponseType::Enum::k) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidAccessError,
          "Synchronous requests from a document must not set a response type.");
      return;
    }

    // Similarly, timeouts are disabled for synchronous requests as well.
    if (!timeout_.is_zero()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidAccessError,
          "Synchronous requests must not set a timeout.");
      return;
    }

    // Here we just warn that firing sync XHR's may affect responsiveness.
    // Eventually sync xhr will be deprecated and an "InvalidAccessError"
    // exception thrown.
    // Refer : https://xhr.spec.whatwg.org/#sync-warning
    // Use count for XHR synchronous requests on main thread only.
    if (!window->document()->ProcessingBeforeUnload()) {
      Deprecation::CountDeprecation(
          GetExecutionContext(),
          WebFeature::kXMLHttpRequestSynchronousInNonWorkerOutsideBeforeUnload);
    }
  }

  method_ = FetchUtils::NormalizeMethod(method);

  url_ = url;

  if (url_.ProtocolIs("blob")) {
    GetExecutionContext()->GetPublicURLManager().Resolve(
        url_, blob_url_loader_factory_.InitWithNewPipeAndPassReceiver());
  }

  async_ = async;

  DCHECK(!loader_);
  send_flag_ = false;

  // Check previous state to avoid dispatching readyState event
  // when calling open several times in a row.
  if (previous_state != kOpened)
    ChangeState(kOpened);
  else
    state_ = kOpened;
}

bool XMLHttpRequest::InitSend(ExceptionState& exception_state) {
  // We need to check ContextDestroyed because it is possible to create a
  // XMLHttpRequest with already detached document.
  // TODO(yhirano): Fix this.
  if (!GetExecutionContext() || GetExecutionContext()->IsContextDestroyed()) {
    HandleNetworkError();
    ThrowForLoadFailureIfNeeded(exception_state,
                                "Document is already detached.");
    return false;
  }

  if (state_ != kOpened || send_flag_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The object's state must be OPENED.");
    return false;
  }

  if (!async_) {
    if (GetExecutionContext()->IsWindow()) {
      bool sync_xhr_disabled_by_permissions_policy =
          !GetExecutionContext()->IsFeatureEnabled(
              mojom::blink::PermissionsPolicyFeature::kSyncXHR,
              ReportOptions::kReportOnFailure,
              "Synchronous requests are disabled by permissions policy.");

      bool sync_xhr_disabled_by_document_policy =
          !GetExecutionContext()->IsFeatureEnabled(
              mojom::blink::DocumentPolicyFeature::kSyncXHR,
              ReportOptions::kReportOnFailure,
              "Synchronous requests are disabled by document policy.");

      // SyncXHR can be controlled by either permissions policy or document
      // policy during the migration period. See crbug.com/1146505.
      if (sync_xhr_disabled_by_permissions_policy ||
          sync_xhr_disabled_by_document_policy) {
        HandleNetworkError();
        ThrowForLoadFailureIfNeeded(exception_state, String());
        return false;
      }
    }
    v8::Isolate* isolate = GetExecutionContext()->GetIsolate();
    v8::MicrotaskQueue* microtask_queue =
        ToMicrotaskQueue(GetExecutionContext());
    if (isolate &&
        ((microtask_queue && microtask_queue->IsRunningMicrotasks()) ||
         (!microtask_queue &&
          v8::MicrotasksScope::IsRunningMicrotasks(isolate)))) {
      UseCounter::Count(GetExecutionContext(),
                        WebFeature::kDuring_Microtask_SyncXHR);
    }
  }

  error_ = false;
  return true;
}

void XMLHttpRequest::send(const V8UnionDocumentOrXMLHttpRequestBodyInit* body,
                          ExceptionState& exception_state) {
  probe::WillSendXMLHttpOrFetchNetworkRequest(GetExecutionContext(), Url());

  if (!body)
    return send(String(), exception_state);

  switch (body->GetContentType()) {
    case V8UnionDocumentOrXMLHttpRequestBodyInit::ContentType::kArrayBuffer:
      return send(body->GetAsArrayBuffer(), exception_state);
    case V8UnionDocumentOrXMLHttpRequestBodyInit::ContentType::kArrayBufferView:
      return send(body->GetAsArrayBufferView().Get(), exception_state);
    case V8UnionDocumentOrXMLHttpRequestBodyInit::ContentType::kBlob:
      return send(body->GetAsBlob(), exception_state);
    case V8UnionDocumentOrXMLHttpRequestBodyInit::ContentType::kDocument:
      return send(body->GetAsDocument(), exception_state);
    case V8UnionDocumentOrXMLHttpRequestBodyInit::ContentType::kFormData:
      return send(body->GetAsFormData(), exception_state);
    case V8UnionDocumentOrXMLHttpRequestBodyInit::ContentType::kURLSearchParams:
      return send(body->GetAsURLSearchParams(), exception_state);
    case V8UnionDocumentOrXMLHttpRequestBodyInit::ContentType::kUSVString:
      return send(body->GetAsUSVString(), exception_state);
  }

  NOTREACHED();
}

bool XMLHttpRequest::AreMethodAndURLValidForSend() {
  return method_ != http_names::kGET && method_ != http_names::kHEAD &&
         SchemeRegistry::ShouldTreatURLSchemeAsSupportingFetchAPI(
             url_.Protocol());
}

void XMLHttpRequest::send(Document* document, ExceptionState& exception_state) {
  DCHECK(document);

  if (!InitSend(exception_state))
    return;

  scoped_refptr<EncodedFormData> http_body;

  if (AreMethodAndURLValidForSend()) {
    if (IsA<HTMLDocument>(document)) {
      UpdateContentTypeAndCharset(AtomicString("text/html;charset=UTF-8"),
                                  "UTF-8");
    } else if (IsA<XMLDocument>(document)) {
      UpdateContentTypeAndCharset(AtomicString("application/xml;charset=UTF-8"),
                                  "UTF-8");
    }

    String body = CreateMarkup(document);

    http_body = EncodedFormData::Create(
        UTF8Encoding().Encode(body, WTF::kNoUnencodables));
  }

  CreateRequest(std::move(http_body), exception_state);
}

void XMLHttpRequest::send(const String& body, ExceptionState& exception_state) {
  if (!InitSend(exception_state))
    return;

  scoped_refptr<EncodedFormData> http_bod
"""


```