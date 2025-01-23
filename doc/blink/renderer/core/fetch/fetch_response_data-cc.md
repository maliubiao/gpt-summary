Response:
Let's break down the thought process for analyzing the `FetchResponseData.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship to web technologies, examples, logic, potential errors, and debugging context.

2. **High-Level Overview (Scan the Imports and Class Name):** The filename `fetch_response_data.cc` and the imports like `mojom/fetch/fetch_api_response.mojom-blink.h`, `fetch_header_list.h`, `platform/loader/cors/cors.h`, `platform/loader/fetch/fetch_utils.h` immediately suggest this file deals with representing and manipulating HTTP responses within the Blink rendering engine (used by Chromium). The class name `FetchResponseData` confirms this.

3. **Core Functionality (Analyze Key Methods):**  Look for methods that create, modify, or provide information about response data. Key methods that stand out are:
    * `Create()`:  Creates a default response.
    * `CreateNetworkErrorResponse()`: Creates a network error response.
    * `CreateWithBuffer()`: Creates a response with body data.
    * `CreateBasicFilteredResponse()`, `CreateCorsFilteredResponse()`, `CreateOpaqueFilteredResponse()`, `CreateOpaqueRedirectFilteredResponse()`: These are clearly about applying filtering based on CORS and other security considerations.
    * `Clone()`: Creates a copy of the response.
    * `PopulateFetchAPIResponse()`: Converts the internal representation to a more standardized format.
    * `InitFromResourceResponse()`: Populates the `FetchResponseData` from a lower-level `ResourceResponse`.
    * Getters like `Url()`, `InternalStatus()`, `InternalHeaderList()`, `MimeType()`, `InternalBuffer()`, etc.

4. **Connecting to Web Technologies (JavaScript, HTML, CSS):**  Think about how HTTP responses are used in the browser.
    * **JavaScript:** The Fetch API in JavaScript directly interacts with `Response` objects, which are backed by data structures like `FetchResponseData`. Consider scenarios like `fetch()`, `then(response => ...)`, and how response properties (status, headers, body) are accessed.
    * **HTML:**  Fetching resources is fundamental to HTML (images, scripts, stylesheets). When the browser loads an HTML page and encounters `<script src="...">`, `<img src="...">`, etc., it initiates fetches that involve `FetchResponseData`.
    * **CSS:** Similarly, CSS files are fetched. `@import` rules or links to external stylesheets trigger fetches processed by this code. The CORS filtering is crucial for cross-origin CSS.

5. **Logical Reasoning and Examples:** For methods like the filtering ones, try to trace the logic.
    * **Input:**  A "default" response with certain headers.
    * **Process:**  The filtering method removes or keeps specific headers based on rules.
    * **Output:** A filtered response with a modified header list. Specifically consider the CORS headers (`Access-Control-Allow-*`, `Access-Control-Expose-Headers`) and how they influence the filtering.

6. **Common Errors:**  Consider how developers might misuse the Fetch API and how the underlying implementation could lead to errors.
    * **CORS Issues:**  A very common source of errors. Trying to access cross-origin resources without proper CORS headers will lead to filtered responses, potentially blocking JavaScript access.
    * **Incorrect Header Handling:**  Attempting to manually set or modify certain restricted headers in JavaScript won't work because the browser enforces security policies.

7. **Debugging Context:** Think about how a developer would end up needing to understand this code.
    * **Network Tab:**  Seeing failed or unexpected network requests in the browser's developer tools is a starting point.
    * **Error Messages:**  CORS errors in the console are strong indicators.
    * **Debugging Tools:**  Stepping through the Chromium source code would eventually lead to `FetchResponseData` when inspecting how responses are processed.

8. **Structure and Refine:**  Organize the findings into logical sections (Functionality, Relation to Web Tech, Logic Examples, Errors, Debugging). Use clear language and examples. Double-check for accuracy. For example, make sure the header filtering rules are correctly stated according to the code.

9. **Self-Correction/Refinement During Analysis:**
    * **Initial thought:**  Maybe this file *only* deals with the internal representation.
    * **Correction:**  The `PopulateFetchAPIResponse` method shows a clear connection to the JavaScript `Response` object.
    * **Initial thought:** Focus only on the successful cases.
    * **Correction:** The `CreateNetworkErrorResponse` and the discussion of filtering and CORS highlight error scenarios.

By following these steps, iteratively analyzing the code, and connecting it to broader web concepts, a comprehensive understanding of `FetchResponseData.cc` can be achieved.
This C++ source file, `fetch_response_data.cc`, within the Chromium Blink engine, is responsible for **representing and managing the data associated with an HTTP response** in the context of the Fetch API. It's a core component in how Blink handles network requests and responses initiated by web pages.

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Data Storage:** It acts as a container for various pieces of information about an HTTP response, including:
   - **Response Type:** (e.g., `basic`, `cors`, `opaque`, `error`) indicating how the response was obtained and what restrictions apply.
   - **Response Source:** (e.g., `network`, `http-cache`) indicating where the response came from.
   - **HTTP Status Code:** (e.g., 200, 404, 500).
   - **HTTP Status Message:** (e.g., "OK", "Not Found").
   - **Headers:** A list of HTTP headers and their values.
   - **URL List:**  A history of URLs involved in redirects.
   - **Body Stream Buffer:**  A buffer to hold the response body data.
   - **MIME Type:** The declared content type of the response.
   - **Timing Information:**  Response time.
   - **Cache-related information:** Cache storage name.
   - **CORS-related information:** Exposed headers.
   - **Connection information:**  Details about the network connection.
   - **ALPN Negotiated Protocol:** The application-layer protocol negotiated.
   - **SPDY/HTTP2 indication:** Whether the response was fetched via SPDY/HTTP2.
   - **Range Request indication:** Whether a range request was made.
   - **Credentials Mode:** Whether credentials were included in the request.
   - **Authentication Challenge Information:** Information about authentication challenges.
   - **Padding:** For security purposes, to obscure the actual size of the response.
   - **Internal Response:**  A pointer to the "original" response when a filtered response is created.

2. **Response Creation:** It provides methods for creating different types of `FetchResponseData` objects:
   - `Create()`: Creates a default successful response.
   - `CreateNetworkErrorResponse()`: Creates a response representing a network error.
   - `CreateWithBuffer()`: Creates a response with an associated body buffer.
   - `CreateBasicFilteredResponse()`: Creates a "basic" filtered response (used for same-origin requests).
   - `CreateCorsFilteredResponse()`: Creates a CORS filtered response (for cross-origin requests with proper CORS headers).
   - `CreateOpaqueFilteredResponse()`: Creates an opaque filtered response (for cross-origin requests without CORS).
   - `CreateOpaqueRedirectFilteredResponse()`: Creates an opaque filtered response for redirects.

3. **Response Filtering:** It implements the logic for filtering response headers based on CORS policies. This is crucial for web security, preventing malicious scripts from accessing sensitive data from other origins.

4. **Cloning:** The `Clone()` method creates a deep copy of the `FetchResponseData` object, which is necessary in various scenarios, such as when the response is being processed by different parts of the rendering engine.

5. **Conversion to Mojo Structure:** The `PopulateFetchAPIResponse()` method converts the internal `FetchResponseData` into a `mojom::blink::FetchAPIResponsePtr`, which is a platform-independent representation used for communication across different processes in Chromium.

6. **Initialization from `ResourceResponse`:** The `InitFromResourceResponse()` method takes a lower-level `ResourceResponse` (from the network stack) and populates the `FetchResponseData` with its information.

**Relationship with JavaScript, HTML, and CSS:**

This file is **deeply intertwined** with the functionality of JavaScript's Fetch API and how browsers load HTML and CSS resources.

* **JavaScript Fetch API:** When a JavaScript code uses the `fetch()` API, the browser's network stack fetches the resource. Upon receiving the response, a `FetchResponseData` object is created to hold the response information. This object is then used to construct the `Response` object that is returned to the JavaScript code.

   **Example:**
   ```javascript
   fetch('https://example.com/data.json')
     .then(response => {
       console.log(response.status); // Accessing the status code from FetchResponseData
       console.log(response.headers.get('Content-Type')); // Accessing headers
       return response.json(); // Accessing the body (which uses the buffer)
     })
     .then(data => console.log(data));
   ```
   In this example, the `response` object in the `.then()` block has its underlying data represented by a `FetchResponseData` instance.

* **HTML Resource Loading:** When the browser parses an HTML document and encounters elements like `<img src="...">`, `<script src="...">`, `<link rel="stylesheet" href="...">`, it initiates network requests. The responses to these requests are represented by `FetchResponseData`.

   **Example:**
   ```html
   <img src="image.png">
   <link rel="stylesheet" href="style.css">
   <script src="script.js"></script>
   ```
   For each of these resources, a `FetchResponseData` object will be created upon receiving the HTTP response.

* **CSS Resource Loading:** Similar to HTML, when the browser loads CSS files, the response is handled by `FetchResponseData`. This is particularly relevant for CORS, as CSS loaded from cross-origin domains is subject to CORS checks managed within this file.

**Logic and Examples (Assumptions and Outputs):**

Let's consider the `CreateCorsFilteredResponse()` method:

**Assumption (Input):**

- A `FetchResponseData` object (`this`) representing a default network response from `https://api.example.com/data` requested from `https://my-website.com`.
- The response headers include:
  - `Content-Type: application/json`
  - `X-Custom-Header: some-value`
  - `Access-Control-Expose-Headers: X-Custom-Header`

**Logic:**

The `CreateCorsFilteredResponse()` method will create a new `FetchResponseData` object with `type_` set to `kCors`. It will then iterate through the headers of the original response and only include headers that are either CORS-safelisted (`Cache-Control`, `Content-Language`, etc.) or explicitly exposed via the `Access-Control-Expose-Headers` header.

**Output:**

A new `FetchResponseData` object with:

- `type_`: `kCors`
- `status_`: Same as the original response.
- `status_message_`: Same as the original response.
- `header_list_`: Containing:
  - `Content-Type: application/json` (CORS-safelisted)
  - `X-Custom-Header: some-value` (explicitly exposed)
  - Potentially other CORS-safelisted headers from the original response.
- The `internal_response_` will point to the original `FetchResponseData` object.

**Common User or Programming Errors and Examples:**

1. **CORS Misconfiguration:** A very common error. If a web developer tries to fetch data from a different origin using JavaScript's `fetch()` without the server providing the correct CORS headers, the `CreateCorsFilteredResponse()` method will create an opaque or CORS-filtered response. This will prevent the JavaScript code from accessing the response body or most headers.

   **Example:**
   - **User Action:** JavaScript on `https://my-website.com` makes a `fetch()` request to `https://api.different-domain.com/data`.
   - **Server Error:** `https://api.different-domain.com/data` does not include the `Access-Control-Allow-Origin` header with a value of `https://my-website.com` or `*`.
   - **Outcome:** `CreateCorsFilteredResponse()` will likely create an opaque response (if no CORS headers are present at all). The JavaScript `response` object will have limited access, and `response.json()` or `response.text()` will likely throw an error.

2. **Incorrectly Assuming Access to Headers:** Developers might assume they can access any header in a response, but CORS filtering restricts this for cross-origin requests.

   **Example:**
   - **User Action:** JavaScript fetches a cross-origin resource.
   - **Server Response:** The server sends a header `X-Tracking-ID: 12345`.
   - **Developer Error:** The JavaScript code tries to access `response.headers.get('X-Tracking-ID')` without `X-Tracking-ID` being in the `Access-Control-Expose-Headers` list.
   - **Outcome:** The `FetchResponseData` (if CORS filtered) will not include `X-Tracking-ID` in its header list, and `response.headers.get('X-Tracking-ID')` will return `null`.

**User Operation and Debugging Clues:**

Let's illustrate how a user operation might lead to this file and provide debugging clues:

**Scenario:** A user visits `https://my-website.com`, which has JavaScript code fetching data from `https://api.example.com/data`. The user encounters an error where the data is not being displayed correctly.

**Step-by-Step User Operation:**

1. **User types `https://my-website.com` in the browser's address bar and presses Enter.**
2. **The browser fetches the HTML of `https://my-website.com`.**
3. **The browser parses the HTML and encounters JavaScript code that calls `fetch('https://api.example.com/data')`.**
4. **Blink initiates a network request to `https://api.example.com/data`.**
5. **The network stack receives the HTTP response from `https://api.example.com/data`.**
6. **The response data is used to create a `ResourceResponse` object.**
7. **`FetchResponseData::InitFromResourceResponse()` is called to populate a `FetchResponseData` object from the `ResourceResponse`.**
8. **Depending on the response headers (specifically CORS headers), `CreateBasicFilteredResponse()`, `CreateCorsFilteredResponse()`, or `CreateOpaqueFilteredResponse()` might be called to create a filtered response.**
9. **The `FetchResponseData` object is used to construct the `Response` object accessible in the JavaScript code.**
10. **The JavaScript code attempts to process the response, but encounters issues due to missing data or restricted access (e.g., CORS error).**

**Debugging Clues:**

- **Browser Developer Tools (Network Tab):** Inspecting the network request to `https://api.example.com/data` will show the HTTP status code, headers, and response body.
    - **CORS Error Indication:** Look for the `Access-Control-Allow-Origin` header in the server's response. If it's missing or doesn't match the origin of `my-website.com`, it's a strong indication of a CORS issue.
    - **Response Type:** The "Type" column in the Network tab might show "cors" or "basic", giving a hint about the filtering applied.
- **Browser Developer Tools (Console Tab):**  CORS errors are often reported in the console, indicating that the browser has blocked access to the response due to security policies. The error message will often mention the missing or incorrect CORS headers.
- **Debugging the JavaScript Code:**  Setting breakpoints in the JavaScript code that handles the `fetch()` response can help identify if the `response` object has the expected data and headers.
- **Stepping through Chromium Source Code (Advanced):**  If you have the Chromium source code, you can set breakpoints within `fetch_response_data.cc`, particularly in the filtering methods, to see exactly how the response is being processed and what headers are being included or excluded. This would require understanding the Chromium build process and debugging tools.

In summary, `fetch_response_data.cc` is a fundamental file in Blink responsible for managing HTTP response information and enforcing web security policies like CORS. It plays a crucial role in how web pages interact with network resources.

### 提示词
```
这是目录为blink/renderer/core/fetch/fetch_response_data.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/fetch/fetch_response_data.h"

#include "base/numerics/safe_conversions.h"
#include "storage/common/quota/padding_key.h"
#include "third_party/blink/public/common/storage_key/storage_key.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_response.mojom-blink.h"
#include "third_party/blink/renderer/core/fetch/fetch_header_list.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/loader/cors/cors.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_utils.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"

using Type = network::mojom::FetchResponseType;
using ResponseSource = network::mojom::FetchResponseSource;

namespace blink {

namespace {

Vector<String> HeaderSetToVector(const HTTPHeaderSet& headers) {
  Vector<String> result;
  result.ReserveInitialCapacity(base::checked_cast<wtf_size_t>(headers.size()));
  // HTTPHeaderSet stores headers using Latin1 encoding.
  for (const auto& header : headers)
    result.push_back(String(header));
  return result;
}

}  // namespace

FetchResponseData* FetchResponseData::Create() {
  // "Unless stated otherwise, a response's url is null, status is 200, status
  // message is the empty byte sequence, header list is an empty header list,
  // and body is null."
  return MakeGarbageCollected<FetchResponseData>(
      Type::kDefault, ResponseSource::kUnspecified, 200, g_empty_atom);
}

FetchResponseData* FetchResponseData::CreateNetworkErrorResponse() {
  // "A network error is a response whose status is always 0, status message
  // is always the empty byte sequence, header list is aways an empty list,
  // and body is always null."
  return MakeGarbageCollected<FetchResponseData>(
      Type::kError, ResponseSource::kUnspecified, 0, g_empty_atom);
}

FetchResponseData* FetchResponseData::CreateWithBuffer(
    BodyStreamBuffer* buffer) {
  FetchResponseData* response = FetchResponseData::Create();
  response->buffer_ = buffer;
  return response;
}

FetchResponseData* FetchResponseData::CreateBasicFilteredResponse() const {
  DCHECK_EQ(type_, Type::kDefault);
  // "A basic filtered response is a filtered response whose type is |basic|,
  // header list excludes any headers in internal response's header list whose
  // name is `Set-Cookie` or `Set-Cookie2`."
  FetchResponseData* response = MakeGarbageCollected<FetchResponseData>(
      Type::kBasic, response_source_, status_, status_message_);
  response->SetURLList(url_list_);
  for (const auto& header : header_list_->List()) {
    if (FetchUtils::IsForbiddenResponseHeaderName(header.first))
      continue;
    response->header_list_->Append(header.first, header.second);
  }
  response->buffer_ = buffer_;
  response->mime_type_ = mime_type_;
  response->internal_response_ = const_cast<FetchResponseData*>(this);
  return response;
}

FetchResponseData* FetchResponseData::CreateCorsFilteredResponse(
    const HTTPHeaderSet& exposed_headers) const {
  DCHECK_EQ(type_, Type::kDefault);
  // "A CORS filtered response is a filtered response whose type is |CORS|,
  // header list excludes all headers in internal response's header list,
  // except those whose name is either one of `Cache-Control`,
  // `Content-Language`, `Content-Type`, `Expires`, `Last-Modified`, and
  // `Pragma`, and except those whose name is one of the values resulting from
  // parsing `Access-Control-Expose-Headers` in internal response's header
  // list."
  FetchResponseData* response = MakeGarbageCollected<FetchResponseData>(
      Type::kCors, response_source_, status_, status_message_);
  response->SetURLList(url_list_);
  for (const auto& header : header_list_->List()) {
    const String& name = header.first;
    if (cors::IsCorsSafelistedResponseHeader(name) ||
        (exposed_headers.find(name.Ascii()) != exposed_headers.end() &&
         !FetchUtils::IsForbiddenResponseHeaderName(name))) {
      response->header_list_->Append(name, header.second);
    }
  }
  response->cors_exposed_header_names_ = exposed_headers;
  response->buffer_ = buffer_;
  response->mime_type_ = mime_type_;
  response->internal_response_ = const_cast<FetchResponseData*>(this);
  return response;
}

FetchResponseData* FetchResponseData::CreateOpaqueFilteredResponse() const {
  DCHECK_EQ(type_, Type::kDefault);
  // "An opaque filtered response is a filtered response whose type is
  // 'opaque', url list is the empty list, status is 0, status message is the
  // empty byte sequence, header list is the empty list, body is null, and
  // cache state is 'none'."
  //
  // https://fetch.spec.whatwg.org/#concept-filtered-response-opaque
  FetchResponseData* response = MakeGarbageCollected<FetchResponseData>(
      Type::kOpaque, response_source_, 0, g_empty_atom);
  response->internal_response_ = const_cast<FetchResponseData*>(this);
  return response;
}

FetchResponseData* FetchResponseData::CreateOpaqueRedirectFilteredResponse()
    const {
  DCHECK_EQ(type_, Type::kDefault);
  // "An opaque filtered response is a filtered response whose type is
  // 'opaqueredirect', status is 0, status message is the empty byte sequence,
  // header list is the empty list, body is null, and cache state is 'none'."
  //
  // https://fetch.spec.whatwg.org/#concept-filtered-response-opaque-redirect
  FetchResponseData* response = MakeGarbageCollected<FetchResponseData>(
      Type::kOpaqueRedirect, response_source_, 0, g_empty_atom);
  response->SetURLList(url_list_);
  response->internal_response_ = const_cast<FetchResponseData*>(this);
  return response;
}

const KURL* FetchResponseData::Url() const {
  // "A response has an associated url. It is a pointer to the last response URL
  // in response’s url list and null if response’s url list is the empty list."
  if (url_list_.empty())
    return nullptr;
  return &url_list_.back();
}

uint16_t FetchResponseData::InternalStatus() const {
  if (internal_response_) {
    return internal_response_->Status();
  }
  return Status();
}

FetchHeaderList* FetchResponseData::InternalHeaderList() const {
  if (internal_response_) {
    return internal_response_->HeaderList();
  }
  return HeaderList();
}

String FetchResponseData::MimeType() const {
  return mime_type_;
}

BodyStreamBuffer* FetchResponseData::InternalBuffer() const {
  if (internal_response_) {
    return internal_response_->buffer_.Get();
  }
  return buffer_.Get();
}

String FetchResponseData::InternalMIMEType() const {
  if (internal_response_) {
    return internal_response_->MimeType();
  }
  return mime_type_;
}

bool FetchResponseData::RequestIncludeCredentials() const {
  return internal_response_ ? internal_response_->RequestIncludeCredentials()
                            : request_include_credentials_;
}

void FetchResponseData::SetURLList(const Vector<KURL>& url_list) {
  url_list_ = url_list;
}

const Vector<KURL>& FetchResponseData::InternalURLList() const {
  if (internal_response_) {
    return internal_response_->url_list_;
  }
  return url_list_;
}

FetchResponseData* FetchResponseData::Clone(ScriptState* script_state,
                                            ExceptionState& exception_state) {
  FetchResponseData* new_response = Create();
  new_response->type_ = type_;
  new_response->padding_ = padding_;
  new_response->response_source_ = response_source_;
  if (termination_reason_) {
    new_response->termination_reason_ = std::make_unique<TerminationReason>();
    *new_response->termination_reason_ = *termination_reason_;
  }
  new_response->SetURLList(url_list_);
  new_response->status_ = status_;
  new_response->status_message_ = status_message_;
  new_response->header_list_ = header_list_->Clone();
  new_response->mime_type_ = mime_type_;
  new_response->request_method_ = request_method_;
  new_response->response_time_ = response_time_;
  new_response->cache_storage_cache_name_ = cache_storage_cache_name_;
  new_response->cors_exposed_header_names_ = cors_exposed_header_names_;
  new_response->connection_info_ = connection_info_;
  new_response->alpn_negotiated_protocol_ = alpn_negotiated_protocol_;
  new_response->was_fetched_via_spdy_ = was_fetched_via_spdy_;
  new_response->has_range_requested_ = has_range_requested_;
  new_response->request_include_credentials_ = request_include_credentials_;
  if (auth_challenge_info_) {
    new_response->auth_challenge_info_ =
        std::make_unique<net::AuthChallengeInfo>(*auth_challenge_info_);
  }

  switch (type_) {
    case Type::kBasic:
    case Type::kCors:
      DCHECK(internal_response_);
      DCHECK_EQ(buffer_, internal_response_->buffer_);
      DCHECK_EQ(internal_response_->type_, Type::kDefault);
      new_response->internal_response_ =
          internal_response_->Clone(script_state, exception_state);
      if (exception_state.HadException())
        return nullptr;
      buffer_ = internal_response_->buffer_;
      new_response->buffer_ = new_response->internal_response_->buffer_;
      break;
    case Type::kDefault: {
      DCHECK(!internal_response_);
      if (buffer_) {
        BodyStreamBuffer* new1 = nullptr;
        BodyStreamBuffer* new2 = nullptr;
        buffer_->Tee(&new1, &new2, exception_state);
        if (exception_state.HadException())
          return nullptr;
        buffer_ = new1;
        new_response->buffer_ = new2;
      }
      break;
    }
    case Type::kError:
      DCHECK(!internal_response_);
      DCHECK(!buffer_);
      break;
    case Type::kOpaque:
    case Type::kOpaqueRedirect:
      DCHECK(internal_response_);
      DCHECK(!buffer_);
      DCHECK_EQ(internal_response_->type_, Type::kDefault);
      new_response->internal_response_ =
          internal_response_->Clone(script_state, exception_state);
      if (exception_state.HadException())
        return nullptr;
      break;
  }
  return new_response;
}

mojom::blink::FetchAPIResponsePtr FetchResponseData::PopulateFetchAPIResponse(
    const KURL& request_url) {
  if (internal_response_) {
    mojom::blink::FetchAPIResponsePtr response =
        internal_response_->PopulateFetchAPIResponse(request_url);
    response->response_type = type_;
    response->response_source = response_source_;
    response->cors_exposed_header_names =
        HeaderSetToVector(cors_exposed_header_names_);
    return response;
  }
  mojom::blink::FetchAPIResponsePtr response =
      mojom::blink::FetchAPIResponse::New();
  response->url_list = url_list_;
  response->status_code = status_;
  response->status_text = status_message_;
  response->response_type = type_;
  response->padding = padding_;
  response->response_source = response_source_;
  response->mime_type = mime_type_;
  response->request_method = request_method_;
  response->response_time = response_time_;
  response->cache_storage_cache_name = cache_storage_cache_name_;
  response->cors_exposed_header_names =
      HeaderSetToVector(cors_exposed_header_names_);
  response->connection_info = connection_info_;
  response->alpn_negotiated_protocol = alpn_negotiated_protocol_;
  response->was_fetched_via_spdy = was_fetched_via_spdy_;
  response->has_range_requested = has_range_requested_;
  response->request_include_credentials = request_include_credentials_;
  for (const auto& header : HeaderList()->List())
    response->headers.insert(header.first, header.second);
  response->parsed_headers = ParseHeaders(
      HeaderList()->GetAsRawString(status_, status_message_), request_url);
  if (auth_challenge_info_) {
    response->auth_challenge_info = *auth_challenge_info_;
  }
  return response;
}

void FetchResponseData::InitFromResourceResponse(
    ExecutionContext* context,
    network::mojom::FetchResponseType response_type,
    const Vector<KURL>& request_url_list,
    const AtomicString& request_method,
    network::mojom::CredentialsMode request_credentials,
    const ResourceResponse& response) {
  SetStatus(response.HttpStatusCode());
  if (response.CurrentRequestUrl().ProtocolIsAbout() ||
      response.CurrentRequestUrl().ProtocolIsData() ||
      response.CurrentRequestUrl().ProtocolIs("blob")) {
    SetStatusMessage(AtomicString("OK"));
  } else {
    SetStatusMessage(response.HttpStatusText());
  }

  for (auto& it : response.HttpHeaderFields())
    HeaderList()->Append(it.key, it.value);

  // Corresponds to https://fetch.spec.whatwg.org/#main-fetch step:
  // "If |internalResponse|’s URL list is empty, then set it to a clone of
  // |request|’s URL list."
  if (response.UrlListViaServiceWorker().empty()) {
    // Note: |UrlListViaServiceWorker()| is empty, unless the response came from
    // a service worker, in which case it will only be empty if it was created
    // through new Response().
    SetURLList(request_url_list);
  } else {
    DCHECK(response.WasFetchedViaServiceWorker());
    SetURLList(response.UrlListViaServiceWorker());
  }

  SetMimeType(response.MimeType());
  SetRequestMethod(request_method);
  SetResponseTime(response.ResponseTime());
  SetCacheStorageCacheName(response.CacheStorageCacheName());

  if (response.WasCached()) {
    SetResponseSource(network::mojom::FetchResponseSource::kHttpCache);
  } else if (!response.WasFetchedViaServiceWorker()) {
    SetResponseSource(network::mojom::FetchResponseSource::kNetwork);
  }

  SetConnectionInfo(response.ConnectionInfo());

  // Some non-http responses, like data: url responses, will have a null
  // |alpn_negotiated_protocol|.  In these cases we leave the default
  // value of "unknown".
  if (!response.AlpnNegotiatedProtocol().IsNull())
    SetAlpnNegotiatedProtocol(response.AlpnNegotiatedProtocol());

  SetWasFetchedViaSpdy(response.WasFetchedViaSPDY());

  SetHasRangeRequested(response.HasRangeRequested());

  // Use the explicit padding in the response provided by a service worker
  // or compute a new padding if necessary.
  if (response.GetPadding()) {
    SetPadding(response.GetPadding());
  } else {
    if (storage::ShouldPadResponseType(response_type)) {
      int64_t padding =
          response.WasCached()
              ? storage::ComputeStableResponsePadding(
                    // TODO(https://crbug.com/1199077): Investigate the need to
                    // have a specified storage key within the ExecutionContext
                    // and if warranted change this to use the actual storage
                    // key instead.
                    blink::StorageKey::CreateFirstParty(
                        context->GetSecurityOrigin()->ToUrlOrigin()),
                    Url()->GetString().Utf8(), ResponseTime(),
                    request_method.Utf8())
              : storage::ComputeRandomResponsePadding();
      SetPadding(padding);
    }
  }

  SetAuthChallengeInfo(response.AuthChallengeInfo());
  SetRequestIncludeCredentials(response.RequestIncludeCredentials());
}

FetchResponseData::FetchResponseData(Type type,
                                     network::mojom::FetchResponseSource source,
                                     uint16_t status,
                                     AtomicString status_message)
    : type_(type),
      padding_(0),
      response_source_(source),
      status_(status),
      status_message_(status_message),
      header_list_(MakeGarbageCollected<FetchHeaderList>()),
      response_time_(base::Time::Now()),
      alpn_negotiated_protocol_("unknown"),
      was_fetched_via_spdy_(false),
      has_range_requested_(false),
      request_include_credentials_(true) {}

void FetchResponseData::SetAuthChallengeInfo(
    const std::optional<net::AuthChallengeInfo>& auth_challenge_info) {
  if (auth_challenge_info) {
    auth_challenge_info_ =
        std::make_unique<net::AuthChallengeInfo>(*auth_challenge_info);
  }
}

void FetchResponseData::SetRequestIncludeCredentials(
    bool request_include_credentials) {
  DCHECK(!internal_response_);
  request_include_credentials_ = request_include_credentials;
}

void FetchResponseData::ReplaceBodyStreamBuffer(BodyStreamBuffer* buffer) {
  if (type_ == Type::kBasic || type_ == Type::kCors) {
    DCHECK(internal_response_);
    internal_response_->buffer_ = buffer;
    buffer_ = buffer;
  } else if (type_ == Type::kDefault) {
    DCHECK(!internal_response_);
    buffer_ = buffer;
  }
}

void FetchResponseData::Trace(Visitor* visitor) const {
  visitor->Trace(header_list_);
  visitor->Trace(internal_response_);
  visitor->Trace(buffer_);
}

}  // namespace blink
```