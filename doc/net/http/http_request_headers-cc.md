Response:
Let's break down the thought process for analyzing this C++ header file (`http_request_headers.cc`).

**1. Initial Understanding - What is this?**

The first clue is the file path: `net/http/http_request_headers.cc`. This immediately suggests:

* **Network Stack:** It's part of Chromium's network component.
* **HTTP:**  Deals with the Hypertext Transfer Protocol.
* **Request Headers:** Specifically focused on the headers of an HTTP request.
* **Implementation (``.cc``):** This file contains the actual code implementation, not just declarations (which would be in a `.h` or `.hpp` file).

**2. Core Functionality - What does it *do*?**

Skimming the code, I see the `HttpRequestHeaders` class. This is the central element. I look for its methods:

* **Constructors/Destructor:** Basic object lifecycle management.
* **`GetHeader`:** Retrieves the value of a header.
* **`SetHeader`:** Sets or replaces a header. There are variations like `SetHeaderIfMissing` and `SetHeaderWithoutCheckForTesting`. The "without check" one is a red flag for potential internal use or testing scenarios.
* **`RemoveHeader`:** Deletes a header.
* **`Clear`:** Removes all headers.
* **`AddHeaderFromString` / `AddHeadersFromString`:**  Parses header lines from strings. This is crucial for constructing headers from raw data.
* **`MergeFrom`:** Combines headers from another `HttpRequestHeaders` object.
* **`ToString`:** Serializes the headers into a string representation (likely for sending over the network or logging).
* **`NetLogParams`:**  Prepares data for Chromium's network logging system. This is important for debugging.
* **`SetAcceptEncodingIfMissing`:**  A specific function to manage the `Accept-Encoding` header, taking into account various factors like URL security and supported compression methods.
* **`FindHeader`:**  Internal helper to locate a header.

**Key Insight:** The class acts as a container and manager for HTTP request headers. It provides methods for manipulation, serialization, and logging.

**3. Relationship to JavaScript:**

Now, the crucial question: how does this C++ code interact with JavaScript in a web browser?

* **Browser as a Platform:**  Chromium (and thus Chrome) is built using C++. The browser's core networking logic is implemented in C++.
* **JavaScript's Role:** JavaScript (running in the browser's rendering engine, Blink) initiates network requests (e.g., using `fetch` or `XMLHttpRequest`).
* **The Bridge:** There's a boundary between the JavaScript environment and the underlying C++ network stack. When JavaScript makes a request, it provides information like the URL, HTTP method, and *headers*.
* **Connecting the Dots:** The JavaScript headers provided are eventually translated and used to populate an instance of `HttpRequestHeaders` in the C++ backend. This object then guides how the network request is actually formed and sent.

**Example:** A `fetch` call in JavaScript setting a custom header directly translates to a call to a `SetHeader` method in the C++ code.

**4. Logical Inference and Assumptions:**

To illustrate the functionality, I need to create hypothetical inputs and outputs.

* **Assumption:**  The `HttpRequestHeaders` object is being used to build a request.
* **Input:** Setting various headers.
* **Output:** The `ToString()` method demonstrating the resulting formatted header string.

This allows showcasing the order and format of the headers.

**5. User and Programming Errors:**

Thinking about common mistakes requires understanding how developers use HTTP headers.

* **Incorrect Header Names/Values:** The code has `CHECK` statements that validate header names and values. This suggests that providing invalid input is a potential error.
* **Case Sensitivity:**  While internally, the code uses case-insensitive comparisons for header names, developers might incorrectly assume strict case sensitivity.
* **Missing Essential Headers:**  For certain requests, like `POST`, `Content-Type` is crucial. Forgetting it can lead to server-side issues.
* **Security Headers:** Misconfiguring security-related headers (like `Origin`, `Authorization`) can create vulnerabilities.

**6. Tracing User Actions:**

To demonstrate how a user action reaches this code, I need to trace a common web browsing scenario.

* **User Action:**  Typing a URL and pressing Enter, or clicking a link.
* **JavaScript Involvement:** The browser's rendering engine interprets the user action. If it's a simple navigation, it might initiate a request directly. If it's a more complex interaction, JavaScript might be involved via `fetch` or `XMLHttpRequest`.
* **The Hand-off:**  JavaScript (or the browser core) packages the request information, including headers, and passes it down to the C++ networking layer.
* **`HttpRequestHeaders` Creation:** Somewhere within the C++ network stack, an instance of `HttpRequestHeaders` is created and populated with the provided header information.

**7. Refinement and Clarity:**

Finally, I review the explanation to ensure it's clear, concise, and addresses all parts of the prompt. I organize the information logically and provide concrete examples. I also make sure to highlight key concepts and the flow of data between JavaScript and C++. The "debugging clue" aspect is addressed by showing how the `NetLogParams` function helps in tracking the headers.

This systematic approach, from understanding the basics to tracing user actions and considering potential errors, allows for a comprehensive analysis of the given C++ code.
这个文件 `net/http/http_request_headers.cc` 定义了 Chromium 网络栈中用于表示和操作 HTTP 请求头的 `HttpRequestHeaders` 类。它的主要功能是：

**1. 存储和管理 HTTP 请求头：**

*   `HttpRequestHeaders` 类内部使用一个 `std::vector` 来存储键值对形式的 HTTP 请求头。每个键值对由 `HeaderKeyValuePair` 结构体表示。
*   提供了添加、删除、修改和获取请求头的方法，例如 `SetHeader`, `GetHeader`, `RemoveHeader`, `AddHeaderFromString`, `AddHeadersFromString`, `MergeFrom`, `Clear`。

**2. 提供对常见 HTTP 请求头的常量定义：**

*   定义了大量常用的 HTTP 请求头名称常量，例如 `kAccept`, `kContentType`, `kUserAgent` 等，方便代码中使用，避免硬编码字符串，提高代码可读性和维护性。
*   定义了常见的 HTTP 方法常量，例如 `kGetMethod`, `kPostMethod` 等。

**3. 辅助处理特定的请求头：**

*   **`SetAcceptEncodingIfMissing`:**  这是一个重要的函数，用于在请求头中设置 `Accept-Encoding` 头，指示客户端支持的压缩编码方式（如 gzip, deflate, br, zstd）。它会考虑以下因素：
    *   是否已经存在 `Accept-Encoding` 头。
    *   是否存在 `Range` 头，如果存在，通常设置为 `identity` 表示不接受内容编码。
    *   URL 的 scheme 是否是加密的 (HTTPS) 或本地地址 (localhost)，这会影响是否支持更高级的压缩算法 (br, zstd)。
    *   是否启用了 Brotli 和 Zstandard 支持。
    *   是否接受特定类型的流 (`accepted_stream_types`)。

**4. 提供迭代器接口：**

*   提供了 `Iterator` 类，用于遍历存储的请求头。

**5. 提供网络日志记录功能：**

*   `NetLogParams` 函数用于生成包含请求行和请求头的网络日志信息，方便调试网络请求过程。

**它与 JavaScript 的功能关系：**

`HttpRequestHeaders` 类本身是 C++ 代码，JavaScript 无法直接访问或操作它。但是，它在浏览器中扮演着至关重要的角色，与 JavaScript 发起的网络请求紧密相关。

当 JavaScript 代码通过 `fetch API` 或 `XMLHttpRequest` 发起一个 HTTP 请求时，JavaScript 可以设置请求头。浏览器底层会将这些 JavaScript 设置的请求头信息传递给 C++ 网络栈。在 C++ 网络栈中，这些信息会被用来填充一个 `HttpRequestHeaders` 对象的实例。

**举例说明：**

假设 JavaScript 代码执行了以下操作：

```javascript
fetch('https://example.com/data', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-Custom-Header': 'some-value'
  },
  body: JSON.stringify({ key: 'value' })
});
```

当这个 `fetch` 请求被发送时，浏览器底层的 C++ 网络栈会创建一个 `HttpRequestHeaders` 对象，并使用 JavaScript 提供的 header 信息填充它。`HttpRequestHeaders` 对象最终会包含以下信息（简化表示）：

```
Content-Type: application/json
X-Custom-Header: some-value
```

`SetAcceptEncodingIfMissing` 函数也会在这个过程中被调用，根据当前环境和请求属性，可能会添加 `Accept-Encoding` 头。

**逻辑推理与假设输入输出：**

**假设输入：**

1. 一个空的 `HttpRequestHeaders` 对象。
2. 调用 `SetHeader("Content-Type", "application/xml")`
3. 调用 `SetHeader("User-Agent", "MyBrowser/1.0")`
4. 调用 `SetHeaderIfMissing("Content-Type", "text/plain")`
5. 调用 `ToString()`

**逻辑推理：**

*   步骤 2 会设置 "Content-Type" 头为 "application/xml"。
*   步骤 3 会设置 "User-Agent" 头为 "MyBrowser/1.0"。
*   步骤 4 尝试设置 "Content-Type" 头，但由于已经存在，所以不会生效。
*   步骤 5 将所有头转换为字符串。

**输出：**

```
Content-Type: application/xml
User-Agent: MyBrowser/1.0

```

**假设输入（关于 `SetAcceptEncodingIfMissing`）：**

1. 一个 `HttpRequestHeaders` 对象，不包含 `Accept-Encoding` 头。
2. URL 为 `https://example.com/image.png` (HTTPS)。
3. 启用了 Brotli 和 Zstandard 支持。
4. `accepted_stream_types` 为空 (表示接受所有流类型)。

**逻辑推理：**

*   由于 URL 是 HTTPS，并且启用了 Brotli 和 Zstandard，`SetAcceptEncodingIfMissing` 会将 `Accept-Encoding` 头设置为包含 gzip, deflate, br, zstd。

**输出 (调用 `ToString()` 后的部分内容)：**

```
Accept-Encoding: gzip, deflate, br, zstd
...其他header...
```

**用户或编程常见的使用错误：**

1. **设置无效的 Header 名称或值：**  `SetHeader` 函数内部会调用 `HttpUtil::IsValidHeaderName` 和 `HttpUtil::IsValidHeaderValue` 进行校验。如果用户尝试设置包含非法字符的 header 名称或值，会导致 `CHECK` 失败，程序崩溃 (Debug 版本)。在 Release 版本中，行为可能未定义，但很可能 header 不会被正确设置。

    **例子：**
    ```c++
    HttpRequestHeaders headers;
    headers.SetHeader("Invalid Header\nName", "value"); // 错误：Header 名称包含换行符
    ```

2. **大小写错误：**  HTTP Header 名称是大小写不敏感的，但在编程时可能会错误地假设它是大小写敏感的。虽然 `HttpRequestHeaders` 内部查找头使用大小写不敏感的比较，但在手动构造字符串时需要注意。

    **例子：**
    ```c++
    HttpRequestHeaders headers;
    headers.SetHeader("content-type", "application/json");
    std::optional<std::string> contentType = headers.GetHeader("Content-Type"); // 可以获取到
    ```

3. **忘记设置必要的 Header：**  对于某些请求，例如 `POST` 请求，可能需要设置 `Content-Type` 头。如果忘记设置，服务器可能无法正确解析请求体。

    **例子：**
    ```c++
    // 发送 POST 请求，但忘记设置 Content-Type
    HttpRequestHeaders headers;
    headers.SetHeader(HttpRequestHeaders::kHost, "example.com");
    std::string request = base::StringPrintf("POST /data HTTP/1.1\r\n%s\r\n", headers.ToString().c_str());
    // 服务器可能无法知道请求体是什么格式
    ```

4. **错误地使用 `SetHeaderIfMissing`：**  如果用户误以为 `SetHeaderIfMissing` 会合并相同名称的 Header，可能会导致预期之外的结果。它只会在 Header 不存在时才设置。

    **例子：**
    ```c++
    HttpRequestHeaders headers;
    headers.SetHeader("Accept-Language", "en-US");
    headers.SetHeaderIfMissing("Accept-Language", "zh-CN"); // 不会生效，因为 Accept-Language 已经存在
    ```

**用户操作是如何一步步到达这里，作为调试线索：**

假设用户在 Chrome 浏览器中访问 `https://example.com/data` 并触发了一个使用 `fetch` API 的 JavaScript 请求。以下是操作步骤如何到达 `HttpRequestHeaders` 的：

1. **用户在地址栏输入 URL 或点击链接。**
2. **浏览器解析 URL，确定需要发起一个 HTTP 请求。**
3. **如果页面包含 JavaScript 代码，并且该代码使用了 `fetch` API 或 `XMLHttpRequest` 发起网络请求，JavaScript 会构建请求的相关信息，包括 URL、方法、请求头等。**
4. **`fetch` 或 `XMLHttpRequest` 的调用会触发浏览器底层的网络请求流程。**
5. **浏览器内核 (例如 Blink) 会将 JavaScript 提供的请求头信息传递给 Chromium 的网络栈 (Net)。**
6. **在 Net 栈中，会创建一个 `HttpRequestHeaders` 对象。**
7. **JavaScript 提供的请求头信息（例如 `Content-Type`, 自定义 header）会被复制到这个 `HttpRequestHeaders` 对象中，通过调用 `SetHeader` 或类似的方法。**
8. **`SetAcceptEncodingIfMissing` 函数可能会被调用，根据当前的网络环境和请求属性，设置或不设置 `Accept-Encoding` 头。**
9. **最终，`HttpRequestHeaders` 对象包含了完整的请求头信息，用于构造实际的 HTTP 请求报文，并发送到服务器。**

**作为调试线索：**

*   **网络面板：** Chrome 的开发者工具 (DevTools) 的 "Network" 面板会显示浏览器发送的实际请求头。通过对比 Network 面板中看到的请求头和 JavaScript 代码中设置的请求头，可以帮助开发者判断是否在 JavaScript 层面设置了正确的 header。
*   **NetLog：** Chromium 的 NetLog 功能可以记录详细的网络事件，包括请求头的创建和修改过程。开发者可以通过抓取 NetLog 并分析，来追踪请求头是如何一步步被构建和修改的，从而定位问题。`HttpRequestHeaders::NetLogParams` 函数就用于生成 NetLog 信息。
*   **断点调试：** 如果开发者有 Chromium 的源码，可以在 `HttpRequestHeaders` 的相关方法（例如 `SetHeader`, `SetAcceptEncodingIfMissing`) 设置断点，来观察请求头的变化过程，查看是否有预期的 header 被设置，以及设置的值是否正确。

总而言之，`net/http/http_request_headers.cc` 定义的 `HttpRequestHeaders` 类是 Chromium 网络栈中管理 HTTP 请求头的核心组件，它连接了 JavaScript 发起的网络请求和底层的网络传输实现。理解其功能和使用方式对于调试网络问题至关重要。

### 提示词
```
这是目录为net/http/http_request_headers.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_request_headers.h"

#include <string_view>
#include <utility>

#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/strings/escape.h"
#include "base/strings/strcat.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/values.h"
#include "net/base/url_util.h"
#include "net/http/http_log_util.h"
#include "net/http/http_util.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_values.h"

namespace net {

namespace {

bool SupportsStreamType(
    const std::optional<base::flat_set<SourceStream::SourceType>>&
        accepted_stream_types,
    SourceStream::SourceType type) {
  if (!accepted_stream_types)
    return true;
  return accepted_stream_types->contains(type);
}

}  // namespace

const char HttpRequestHeaders::kConnectMethod[] = "CONNECT";
const char HttpRequestHeaders::kDeleteMethod[] = "DELETE";
const char HttpRequestHeaders::kGetMethod[] = "GET";
const char HttpRequestHeaders::kHeadMethod[] = "HEAD";
const char HttpRequestHeaders::kOptionsMethod[] = "OPTIONS";
const char HttpRequestHeaders::kPatchMethod[] = "PATCH";
const char HttpRequestHeaders::kPostMethod[] = "POST";
const char HttpRequestHeaders::kPutMethod[] = "PUT";
const char HttpRequestHeaders::kTraceMethod[] = "TRACE";
const char HttpRequestHeaders::kTrackMethod[] = "TRACK";
const char HttpRequestHeaders::kAccept[] = "Accept";
const char HttpRequestHeaders::kAcceptCharset[] = "Accept-Charset";
const char HttpRequestHeaders::kAcceptEncoding[] = "Accept-Encoding";
const char HttpRequestHeaders::kAcceptLanguage[] = "Accept-Language";
const char HttpRequestHeaders::kAuthorization[] = "Authorization";
const char HttpRequestHeaders::kCacheControl[] = "Cache-Control";
const char HttpRequestHeaders::kConnection[] = "Connection";
const char HttpRequestHeaders::kContentLength[] = "Content-Length";
const char HttpRequestHeaders::kContentType[] = "Content-Type";
const char HttpRequestHeaders::kCookie[] = "Cookie";
const char HttpRequestHeaders::kHost[] = "Host";
const char HttpRequestHeaders::kIfMatch[] = "If-Match";
const char HttpRequestHeaders::kIfModifiedSince[] = "If-Modified-Since";
const char HttpRequestHeaders::kIfNoneMatch[] = "If-None-Match";
const char HttpRequestHeaders::kIfRange[] = "If-Range";
const char HttpRequestHeaders::kIfUnmodifiedSince[] = "If-Unmodified-Since";
const char HttpRequestHeaders::kOrigin[] = "Origin";
const char HttpRequestHeaders::kPragma[] = "Pragma";
const char HttpRequestHeaders::kPriority[] = "Priority";
const char HttpRequestHeaders::kProxyAuthorization[] = "Proxy-Authorization";
const char HttpRequestHeaders::kProxyConnection[] = "Proxy-Connection";
const char HttpRequestHeaders::kRange[] = "Range";
const char HttpRequestHeaders::kReferer[] = "Referer";
const char HttpRequestHeaders::kTransferEncoding[] = "Transfer-Encoding";
const char HttpRequestHeaders::kUserAgent[] = "User-Agent";

HttpRequestHeaders::HeaderKeyValuePair::HeaderKeyValuePair() = default;

HttpRequestHeaders::HeaderKeyValuePair::HeaderKeyValuePair(
    std::string_view key,
    std::string_view value)
    : HeaderKeyValuePair(key, std::string(value)) {}

HttpRequestHeaders::HeaderKeyValuePair::HeaderKeyValuePair(std::string_view key,
                                                           std::string&& value)
    : key(key), value(std::move(value)) {}

HttpRequestHeaders::Iterator::Iterator(const HttpRequestHeaders& headers)
    : curr_(headers.headers_.begin()), end_(headers.headers_.end()) {}

HttpRequestHeaders::Iterator::~Iterator() = default;

bool HttpRequestHeaders::Iterator::GetNext() {
  if (!started_) {
    started_ = true;
    return curr_ != end_;
  }

  if (curr_ == end_)
    return false;

  ++curr_;
  return curr_ != end_;
}

HttpRequestHeaders::HttpRequestHeaders() = default;
HttpRequestHeaders::HttpRequestHeaders(const HttpRequestHeaders& other) =
    default;
HttpRequestHeaders::HttpRequestHeaders(HttpRequestHeaders&& other) = default;
HttpRequestHeaders::~HttpRequestHeaders() = default;

HttpRequestHeaders& HttpRequestHeaders::operator=(
    const HttpRequestHeaders& other) = default;
HttpRequestHeaders& HttpRequestHeaders::operator=(HttpRequestHeaders&& other) =
    default;

std::optional<std::string> HttpRequestHeaders::GetHeader(
    std::string_view key) const {
  auto it = FindHeader(key);
  if (it == headers_.end())
    return std::nullopt;
  return it->value;
}

void HttpRequestHeaders::Clear() {
  headers_.clear();
}

void HttpRequestHeaders::SetHeader(std::string_view key,
                                   std::string_view value) {
  SetHeader(key, std::string(value));
}

void HttpRequestHeaders::SetHeader(std::string_view key, std::string&& value) {
  // Invalid header names or values could mean clients can attach
  // browser-internal headers.
  CHECK(HttpUtil::IsValidHeaderName(key)) << key;
  CHECK(HttpUtil::IsValidHeaderValue(value)) << key << " has invalid value.";

  SetHeaderInternal(key, std::move(value));
}

void HttpRequestHeaders::SetHeaderWithoutCheckForTesting(
    std::string_view key,
    std::string_view value) {
  SetHeaderInternal(key, std::string(value));
}

void HttpRequestHeaders::SetHeaderIfMissing(std::string_view key,
                                            std::string_view value) {
  // Invalid header names or values could mean clients can attach
  // browser-internal headers.
  CHECK(HttpUtil::IsValidHeaderName(key));
  CHECK(HttpUtil::IsValidHeaderValue(value));
  auto it = FindHeader(key);
  if (it == headers_.end())
    headers_.push_back(HeaderKeyValuePair(key, value));
}

void HttpRequestHeaders::RemoveHeader(std::string_view key) {
  auto it = FindHeader(key);
  if (it != headers_.end())
    headers_.erase(it);
}

void HttpRequestHeaders::AddHeaderFromString(std::string_view header_line) {
  DCHECK_EQ(std::string::npos, header_line.find("\r\n"))
      << "\"" << header_line << "\" contains CRLF.";

  const std::string::size_type key_end_index = header_line.find(":");
  if (key_end_index == std::string::npos) {
    LOG(DFATAL) << "\"" << header_line << "\" is missing colon delimiter.";
    return;
  }

  if (key_end_index == 0) {
    LOG(DFATAL) << "\"" << header_line << "\" is missing header key.";
    return;
  }

  const std::string_view header_key = header_line.substr(0, key_end_index);
  if (!HttpUtil::IsValidHeaderName(header_key)) {
    LOG(DFATAL) << "\"" << header_line << "\" has invalid header key.";
    return;
  }

  const std::string::size_type value_index = key_end_index + 1;

  if (value_index < header_line.size()) {
    std::string_view header_value = header_line.substr(value_index);
    header_value = HttpUtil::TrimLWS(header_value);
    if (!HttpUtil::IsValidHeaderValue(header_value)) {
      LOG(DFATAL) << "\"" << header_line << "\" has invalid header value.";
      return;
    }
    SetHeader(header_key, header_value);
  } else if (value_index == header_line.size()) {
    SetHeader(header_key, "");
  } else {
    NOTREACHED();
  }
}

void HttpRequestHeaders::AddHeadersFromString(std::string_view headers) {
  for (std::string_view header : base::SplitStringPieceUsingSubstr(
           headers, "\r\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY)) {
    AddHeaderFromString(header);
  }
}

void HttpRequestHeaders::MergeFrom(const HttpRequestHeaders& other) {
  for (const auto& header : other.headers_) {
    SetHeader(header.key, header.value);
  }
}

std::string HttpRequestHeaders::ToString() const {
  std::string output;
  for (const auto& header : headers_) {
    base::StringAppendF(&output, "%s: %s\r\n", header.key.c_str(),
                        header.value.c_str());
  }
  output.append("\r\n");
  return output;
}

base::Value::Dict HttpRequestHeaders::NetLogParams(
    const std::string& request_line,
    NetLogCaptureMode capture_mode) const {
  base::Value::Dict dict;
  dict.Set("line", NetLogStringValue(request_line));
  base::Value::List headers;
  for (const auto& header : headers_) {
    std::string log_value =
        ElideHeaderValueForNetLog(capture_mode, header.key, header.value);
    headers.Append(
        NetLogStringValue(base::StrCat({header.key, ": ", log_value})));
  }
  dict.Set("headers", std::move(headers));
  return dict;
}

void HttpRequestHeaders::SetAcceptEncodingIfMissing(
    const GURL& url,
    const std::optional<base::flat_set<SourceStream::SourceType>>&
        accepted_stream_types,
    bool enable_brotli,
    bool enable_zstd) {
  if (HasHeader(kAcceptEncoding))
    return;

  // If a range is specifically requested, set the "Accepted Encoding" header to
  // "identity".
  if (HasHeader(kRange)) {
    SetHeader(kAcceptEncoding, "identity");
    return;
  }

  // Supply Accept-Encoding headers first so that it is more likely that they
  // will be in the first transmitted packet. This can sometimes make it easier
  // to filter and analyze the streams to assure that a proxy has not damaged
  // these headers. Some proxies deliberately corrupt Accept-Encoding headers.
  std::vector<std::string> advertised_encoding_names;
  if (SupportsStreamType(accepted_stream_types,
                         SourceStream::SourceType::TYPE_GZIP)) {
    advertised_encoding_names.push_back("gzip");
  }
  if (SupportsStreamType(accepted_stream_types,
                         SourceStream::SourceType::TYPE_DEFLATE)) {
    advertised_encoding_names.push_back("deflate");
  }

  const bool can_use_advanced_encodings =
      (url.SchemeIsCryptographic() || IsLocalhost(url));

  // Advertise "br" encoding only if transferred data is opaque to proxy.
  if (enable_brotli &&
      SupportsStreamType(accepted_stream_types,
                         SourceStream::SourceType::TYPE_BROTLI) &&
      can_use_advanced_encodings) {
    advertised_encoding_names.push_back("br");
  }
  // Advertise "zstd" encoding only if transferred data is opaque to proxy.
  if (enable_zstd &&
      SupportsStreamType(accepted_stream_types,
                         SourceStream::SourceType::TYPE_ZSTD) &&
      can_use_advanced_encodings) {
    advertised_encoding_names.push_back("zstd");
  }
  if (!advertised_encoding_names.empty()) {
    // Tell the server what compression formats are supported.
    SetHeader(
        kAcceptEncoding,
        base::JoinString(base::make_span(advertised_encoding_names), ", "));
  }
}

HttpRequestHeaders::HeaderVector::iterator HttpRequestHeaders::FindHeader(
    std::string_view key) {
  for (auto it = headers_.begin(); it != headers_.end(); ++it) {
    if (base::EqualsCaseInsensitiveASCII(key, it->key))
      return it;
  }

  return headers_.end();
}

HttpRequestHeaders::HeaderVector::const_iterator HttpRequestHeaders::FindHeader(
    std::string_view key) const {
  for (auto it = headers_.begin(); it != headers_.end(); ++it) {
    if (base::EqualsCaseInsensitiveASCII(key, it->key))
      return it;
  }

  return headers_.end();
}

void HttpRequestHeaders::SetHeaderInternal(std::string_view key,
                                           std::string&& value) {
  auto it = FindHeader(key);
  if (it != headers_.end())
    it->value = std::move(value);
  else
    headers_.emplace_back(key, std::move(value));
}

}  // namespace net
```