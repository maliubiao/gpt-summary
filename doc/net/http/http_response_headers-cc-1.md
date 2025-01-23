Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of Chromium's network stack and specifically deals with HTTP response headers. I need to analyze the code and describe its main purposes, including:

1. **Core Functionality:** What are the primary tasks this code performs related to HTTP response headers?
2. **Relation to JavaScript:** Does this code directly interact with or influence JavaScript functionality in a web browser? If so, how?
3. **Logic and Assumptions:**  Are there logical steps or reasoning involved? Can I provide example inputs and expected outputs based on these?
4. **Common User/Programming Errors:**  What mistakes could developers or users make that might lead to this code being executed or reveal issues here?
5. **User Interaction and Debugging:** How does a user's action eventually lead to this code being involved, and how can this be used for debugging?
6. **Summary:** Condense the overall purpose of the code.

**Analysis of the Code:**

The code defines the `HttpResponseHeaders` class, which is responsible for parsing, storing, and providing access to HTTP response headers. Key functionalities include:

- **Parsing headers:**  `AddHeader`, `AddToParsed` handle the process of breaking down the raw header string into individual name-value pairs. It also handles cases where header values are comma-separated and need to be split.
- **Accessing header values:**  Methods like `EnumerateHeader`, `GetNormalizedHeader`, `HasHeaderValue`, `GetTimeValuedHeader`, `GetInt64HeaderValue` provide ways to retrieve header information.
- **Cache control logic:** Functions like `RequiresValidation`, `GetFreshnessLifetimes`, `GetCurrentAge`, `GetMaxAgeValue`, `GetExpiresValue`, `GetStaleWhileRevalidateValue` implement the logic for determining if a cached response is fresh or stale based on cache-related headers.
- **Redirect handling:** `IsRedirect` checks if the response is a redirect and extracts the target URL from the `Location` header.
- **Security-related headers:**  Functions like `AddNonCacheableHeaders`, `AddHopByHopHeaders`, `AddCookieHeaders`, `AddChallengeHeaders`, `AddSecurityStateHeaders` identify and categorize specific headers. `HasStorageAccessRetryHeader` deals with a particular security header.
- **Content type processing:** `GetMimeTypeAndCharset`, `GetMimeType`, `GetCharset` are used to extract the MIME type and charset from the `Content-Type` header.
- **Connection management:** `IsKeepAlive` determines if the connection should be kept alive based on `Connection` or `Proxy-Connection` headers.
- **Content encoding:** `IsChunkEncoded` checks for chunked transfer encoding.
- **Content range handling:** `GetContentRangeFor206` parses the `Content-Range` header for partial content responses.
- **Net logging:** `NetLogParams` prepares header information for network logging.
- **Strict equality check:** `StrictlyEquals` compares two `HttpResponseHeaders` objects for complete equality.

**Relationship with JavaScript:**

HTTP response headers directly affect how web browsers interpret and process web content, which in turn impacts JavaScript execution. For example:

- **Cache control headers (e.g., `Cache-Control`, `Expires`):** Determine whether a resource is fetched from the cache or the network, influencing page load speed and JavaScript execution timing.
- **`Content-Type` header:**  Informs the browser how to interpret the response body. If a JavaScript file is served with the wrong `Content-Type`, the browser might not execute it.
- **`Location` header (for redirects):**  Causes the browser to navigate to a new URL, potentially loading and executing different JavaScript.
- **`Set-Cookie` header:**  Instructs the browser to store cookies, which JavaScript can then access and use.
- **Security headers (e.g., `Strict-Transport-Security`, `Content-Security-Policy`):**  Control security policies that directly impact what JavaScript code is allowed to do.

**Logic and Assumptions:**

The code makes assumptions based on HTTP specifications (RFCs). For example, the cache control logic follows rules defined in RFC 2616 and related documents. The parsing of dates and times also follows HTTP date format conventions.

**Common Errors:**

- **Incorrectly configured server:** A server might send incorrect cache control headers, leading to unexpected caching behavior. For example, setting `Cache-Control: no-cache` when the intent was to allow caching with validation.
- **Mismatched `Content-Type`:** Serving a JavaScript file with `text/plain` instead of `application/javascript` will prevent the browser from executing it.
- **Incorrect date formats:**  Invalid date formats in headers like `Expires` can lead to parsing errors and unexpected caching behavior.

**User Interaction and Debugging:**

A user's action, like clicking a link or typing a URL in the browser, triggers network requests. When a server responds, the raw HTTP headers are received by the browser's network stack. This `HttpResponseHeaders` class is involved in parsing and processing these headers.

**Debugging:** Developers can use browser developer tools (Network tab) to inspect the raw headers of a response. This allows them to see the values that this code is processing and identify any discrepancies or errors.

Now, I can formulate the detailed answer.
这是对 Chromium 网络栈中 `net/http/http_response_headers.cc` 文件功能的归纳总结，基于提供的代码片段。

**功能归纳:**

`HttpResponseHeaders` 类的主要功能是 **解析、存储和提供对 HTTP 响应头的访问和操作**。它实现了与 HTTP 缓存、重定向、内容类型处理、连接管理以及安全相关的多种逻辑。

具体来说，该类的功能可以归纳为以下几点：

1. **头部解析和存储:**
   - 接收原始的 HTTP 响应头字符串 (`raw_headers_`)。
   - 将响应头解析成键值对，并存储在 `parsed_` 成员变量中，这是一个 `ParsedHeader` 结构体的向量，每个结构体记录了头部名称和值的起始和结束迭代器。
   - `AddHeader` 方法负责添加头部，并处理逗号分隔的头部值，将其拆分成多个独立的头部。

2. **头部访问:**
   - 提供多种方法来访问存储的头部信息，例如：
     - `EnumerateHeader`: 遍历指定名称的所有头部值。
     - `GetNormalizedHeader`: 获取指定名称的第一个头部值（标准化后）。
     - `HasHeaderValue`: 检查是否存在具有特定值的头部。
     - `GetTimeValuedHeader`: 解析日期时间类型的头部值（如 `Date`, `Expires`, `Last-Modified`）。
     - `GetInt64HeaderValue`: 解析整数类型的头部值（如 `Content-Length`）。

3. **缓存控制:**
   - 实现了 HTTP 缓存相关的逻辑，根据响应头（如 `Cache-Control`, `Expires`, `Pragma`, `Age` 等）判断响应是否新鲜，是否需要重新验证。
   - `RequiresValidation`: 判断是否需要验证缓存。
   - `GetFreshnessLifetimes`: 计算响应的新鲜度生命周期和允许的陈旧时间。
   - `GetCurrentAge`: 计算响应的当前年龄。
   - `GetMaxAgeValue`, `GetExpiresValue`, `GetStaleWhileRevalidateValue`: 获取特定的缓存控制指令值。

4. **重定向处理:**
   - `IsRedirect`: 判断响应状态码是否为重定向，并尝试获取 `Location` 头部的值作为重定向目标 URL。

5. **内容类型处理:**
   - `GetMimeTypeAndCharset`: 解析 `Content-Type` 头部，提取 MIME 类型和字符集。

6. **连接管理:**
   - `IsKeepAlive`: 根据 `Connection` 或 `Proxy-Connection` 头部判断连接是否保持活跃。

7. **安全相关头部处理:**
   - 提供了方法来识别和处理特定的安全相关头部，例如：
     - `AddNonCacheableHeaders`:  处理 `cache-control: no-cache="..."` 指令，找出不应缓存的头部。
     - `AddHopByHopHeaders`, `AddCookieHeaders`, `AddChallengeHeaders`, `AddSecurityStateHeaders`: 将特定类型的头部添加到集合中。
     - `HasStorageAccessRetryHeader`:  检查 `Activate-Storage-Access` 头部。

8. **内容编码处理:**
   - `IsChunkEncoded`: 判断响应是否使用了分块传输编码。

9. **内容范围处理:**
   - `GetContentRangeFor206`: 解析状态码为 206 (Partial Content) 的响应中的 `Content-Range` 头部。

10. **网络日志记录:**
    - `NetLogParams`:  生成包含响应头信息的 `base::Value::Dict`，用于网络日志记录。

11. **严格相等性比较:**
    - `StrictlyEquals`:  用于比较两个 `HttpResponseHeaders` 对象是否完全相等，包括 HTTP 版本、状态码、原始头部字符串和解析后的头部信息。

**与 JavaScript 的关系举例:**

`HttpResponseHeaders` 处理的 HTTP 响应头信息直接影响着 JavaScript 在浏览器中的行为：

- **缓存控制:** 当 JavaScript 发起网络请求时，浏览器会检查 `HttpResponseHeaders` 中缓存相关的头部。如果资源可以从缓存中获取，则不会发起新的网络请求，JavaScript 可以更快地执行。例如，如果响应头包含 `Cache-Control: max-age=3600`，则在 3600 秒内，浏览器可能会直接从缓存加载资源，而不会重新请求，这会影响依赖于该资源的 JavaScript 代码的执行时机。
- **`Content-Type`:**  如果服务器返回的 JavaScript 文件的 `Content-Type` 头部不是 `application/javascript` (或类似的 MIME 类型)，浏览器可能不会将其识别为可执行的 JavaScript 代码，从而导致脚本无法执行。
- **重定向:** 如果服务器返回一个重定向响应（状态码为 3xx，并带有 `Location` 头部），浏览器会根据 `HttpResponseHeaders` 中的信息跳转到新的 URL。这可能会导致加载不同的 HTML 页面和 JavaScript 代码。
- **Cookie:** `Set-Cookie` 头部由 `HttpResponseHeaders` 处理，它指示浏览器存储 Cookie。JavaScript 可以通过 `document.cookie` API 访问这些 Cookie，从而实现状态管理和用户跟踪等功能。
- **安全头部:**  例如，`Content-Security-Policy` (CSP) 头部在 `HttpResponseHeaders` 中被解析，它定义了浏览器允许加载的资源来源。这会直接限制页面中 JavaScript 代码可以执行的操作，例如禁止加载来自特定域名的脚本。

**逻辑推理的假设输入与输出:**

假设输入一个包含以下头的 HTTP 响应：

```
HTTP/1.1 200 OK
Date: Tue, 07 Nov 2023 10:00:00 GMT
Cache-Control: max-age=3600
Content-Type: text/html; charset=utf-8
```

**假设输入:**
- `raw_headers_`:  包含上述头部信息的字符串。
- `response_time`:  解析到响应的时间，例如 `Time::Now()`.

**逻辑推理和输出示例:**

- 调用 `GetMaxAgeValue()`:  会解析 `Cache-Control` 头部，输出 `base::Seconds(3600)`.
- 调用 `GetMimeTypeAndCharset(&mime_type, &charset)`: 会解析 `Content-Type` 头部，输出 `mime_type = "text/html"`, `charset = "utf-8"`.
- 调用 `GetDateValue()`: 会解析 `Date` 头部，输出一个 `Time` 对象，对应 `Tue, 07 Nov 2023 10:00:00 GMT`。
- 调用 `RequiresValidation(request_time, response_time, current_time)`: 会根据 `max-age` 计算新鲜度，如果 `current_time` 在 `response_time` 之后的 3600 秒内，则可能返回 `VALIDATION_NONE`，否则可能返回 `VALIDATION_SYNCHRONOUS` 或 `VALIDATION_ASYNCHRONOUS`。

**用户或编程常见的使用错误举例:**

1. **服务器配置错误：** 服务器错误地配置了缓存头部，例如设置了过短的 `max-age` 或错误地使用了 `no-cache`，导致浏览器频繁地重新请求资源，即使资源没有更新。这会导致不必要的网络流量和降低页面加载速度，用户可能会抱怨页面加载慢。
2. **`Content-Type` 错误：**  服务器返回 JavaScript 文件时，`Content-Type` 设置为 `text/plain`。浏览器收到响应后，由于 `Content-Type` 不正确，不会将该文件识别为 JavaScript，导致脚本无法执行，页面功能异常。开发者在调试时可能会在控制台看到关于 MIME 类型不匹配的错误。
3. **日期格式错误：** 服务器返回的日期格式不符合 HTTP 标准，例如 `Expires: 0` (在某些情况下应被视为已过期，但取决于特性开关)，或者使用了非法的日期格式。这可能导致 `GetTimeValuedHeader` 解析失败，缓存逻辑出现错误。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户在浏览器地址栏输入 URL 或点击链接:** 这会触发浏览器发起一个 HTTP 请求。
2. **浏览器建立网络连接并发送请求到服务器。**
3. **服务器处理请求并生成 HTTP 响应，包含响应头和响应体。**
4. **浏览器接收到服务器的响应。**
5. **网络栈开始解析接收到的原始响应头字符串。**  `HttpResponseHeaders` 对象被创建，并将原始头部信息传递给它。
6. **`HttpResponseHeaders::AddHeader` 等方法被调用，逐行解析头部信息，并存储到 `parsed_` 成员中。**
7. **后续浏览器处理响应的逻辑会调用 `HttpResponseHeaders` 的各种方法来获取头部信息。** 例如，缓存模块会调用 `RequiresValidation` 来判断是否需要缓存，渲染引擎会调用 `GetMimeTypeAndCharset` 来确定如何处理响应体。
8. **如果出现问题，例如资源未按预期缓存，或者 JavaScript 代码无法执行，开发者可以使用浏览器开发者工具的 "Network" 标签来查看请求和响应的详细信息，包括原始的响应头。** 通过检查响应头，开发者可以判断服务器返回的头部是否正确，以及 `HttpResponseHeaders` 的解析和处理逻辑是否按预期工作。例如，如果缓存行为异常，可以检查 `Cache-Control` 和 `Expires` 头部的值。如果 JavaScript 执行失败，可以检查 `Content-Type` 头部。

总而言之，`HttpResponseHeaders` 是 Chromium 网络栈中处理 HTTP 响应头的核心组件，它负责将原始的头部信息解析成结构化的数据，并提供各种方法来访问和操作这些数据，从而支持浏览器的缓存、重定向、内容处理和安全策略等关键功能。

### 提示词
```
这是目录为net/http/http_response_headers.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
.InSeconds());
    return base::Seconds(seconds);
  }

  return std::nullopt;
}

void HttpResponseHeaders::AddHeader(std::string::const_iterator name_begin,
                                    std::string::const_iterator name_end,
                                    std::string::const_iterator values_begin,
                                    std::string::const_iterator values_end,
                                    ContainsCommas contains_commas) {
  // If the header can be coalesced, then we should split it up.
  if (values_begin == values_end ||
      HttpUtil::IsNonCoalescingHeader(
          base::MakeStringPiece(name_begin, name_end)) ||
      contains_commas == ContainsCommas::kNo) {
    AddToParsed(name_begin, name_end, values_begin, values_end);
  } else {
    std::string_view values = base::MakeStringPiece(values_begin, values_end);
    HttpUtil::ValuesIterator it(values, ',', /*ignore_empty_values=*/false);
    while (it.GetNext()) {
      // Convert from a string_view back to a string iterator. To do this,
      // find the offset of the start of `it.value()` relative to to the start
      // of `values`, and add it to to the start of values.
      //
      // TODO(crbug.com/369533090): Converting from a string_view back to a
      // string iterator is awkward. Switch this class to using string_views.
      std::string::const_iterator sub_value_begin =
          values_begin + (it.value().data() - values.data());
      std::string::const_iterator sub_value_end =
          sub_value_begin + it.value().length();

      AddToParsed(name_begin, name_end, sub_value_begin, sub_value_end);
      // clobber these so that subsequent values are treated as continuations
      name_begin = name_end = values_end;
    }
  }
}

void HttpResponseHeaders::AddToParsed(std::string::const_iterator name_begin,
                                      std::string::const_iterator name_end,
                                      std::string::const_iterator value_begin,
                                      std::string::const_iterator value_end) {
  ParsedHeader header;
  header.name_begin = name_begin;
  header.name_end = name_end;
  header.value_begin = value_begin;
  header.value_end = value_end;
  parsed_.push_back(header);
}

void HttpResponseHeaders::AddNonCacheableHeaders(HeaderSet* result) const {
  // Add server specified transients.  Any 'cache-control: no-cache="foo,bar"'
  // headers present in the response specify additional headers that we should
  // not store in the cache.
  const char kCacheControl[] = "cache-control";
  const char kPrefix[] = "no-cache=\"";
  const size_t kPrefixLen = sizeof(kPrefix) - 1;

  std::optional<std::string_view> value;
  size_t iter = 0;
  while ((value = EnumerateHeader(&iter, kCacheControl))) {
    // If the value is smaller than the prefix and a terminal quote, skip
    // it.
    if (value->size() <= kPrefixLen ||
        value->compare(0, kPrefixLen, kPrefix) != 0) {
      continue;
    }
    // if it doesn't end with a quote, then treat as malformed
    if (value->back() != '\"') {
      continue;
    }

    // process the value as a comma-separated list of items. Each
    // item can be wrapped by linear white space.

    // Remove the prefix and close quote.
    std::string_view remaining =
        value->substr(kPrefixLen, value->size() - kPrefixLen - 1);
    // Use base::KEEP_WHITESPACE despite trimming each item so can use the HTTP
    // definition of whitespace.
    std::vector<std::string_view> items = base::SplitStringPiece(
        remaining, /*separators=*/",", base::KEEP_WHITESPACE,
        base::SPLIT_WANT_NONEMPTY);
    for (std::string_view item : items) {
      // Trim off leading and trailing whitespace in this item.
      item = HttpUtil::TrimLWS(item);

      // If the header is not empty, lowercase and insert into set.
      if (!item.empty()) {
        result->insert(base::ToLowerASCII(item));
      }
    }
  }
}

void HttpResponseHeaders::AddHopByHopHeaders(HeaderSet* result) {
  for (const auto* header : kHopByHopResponseHeaders)
    result->insert(std::string(header));
}

void HttpResponseHeaders::AddCookieHeaders(HeaderSet* result) {
  for (const auto* header : kCookieResponseHeaders)
    result->insert(std::string(header));
}

void HttpResponseHeaders::AddChallengeHeaders(HeaderSet* result) {
  for (const auto* header : kChallengeResponseHeaders)
    result->insert(std::string(header));
}

void HttpResponseHeaders::AddHopContentRangeHeaders(HeaderSet* result) {
  result->insert(kContentRange);
}

void HttpResponseHeaders::AddSecurityStateHeaders(HeaderSet* result) {
  for (const auto* header : kSecurityStateHeaders)
    result->insert(std::string(header));
}

void HttpResponseHeaders::GetMimeTypeAndCharset(std::string* mime_type,
                                                std::string* charset) const {
  mime_type->clear();
  charset->clear();

  std::optional<std::string_view> value;
  bool had_charset = false;
  size_t iter = 0;
  while ((value = EnumerateHeader(&iter, "content-type"))) {
    HttpUtil::ParseContentType(*value, mime_type, charset, &had_charset,
                               /*boundary=*/nullptr);
  }
}

bool HttpResponseHeaders::GetMimeType(std::string* mime_type) const {
  std::string unused;
  GetMimeTypeAndCharset(mime_type, &unused);
  return !mime_type->empty();
}

bool HttpResponseHeaders::GetCharset(std::string* charset) const {
  std::string unused;
  GetMimeTypeAndCharset(&unused, charset);
  return !charset->empty();
}

bool HttpResponseHeaders::IsRedirect(std::string* location) const {
  if (!IsRedirectResponseCode(response_code_))
    return false;

  // If we lack a Location header, then we can't treat this as a redirect.
  // We assume that the first non-empty location value is the target URL that
  // we want to follow.  TODO(darin): Is this consistent with other browsers?
  size_t i = std::string::npos;
  do {
    i = FindHeader(++i, "location");
    if (i == std::string::npos)
      return false;
    // If the location value is empty, then it doesn't count.
  } while (parsed_[i].value_begin == parsed_[i].value_end);

  if (location) {
    auto location_strpiece =
        base::MakeStringPiece(parsed_[i].value_begin, parsed_[i].value_end);
    // Escape any non-ASCII characters to preserve them.  The server should
    // only be returning ASCII here, but for compat we need to do this.
    //
    // The URL parser escapes things internally, but it expect the bytes to be
    // valid UTF-8, so encoding errors turn into replacement characters before
    // escaping. Escaping here preserves the bytes as-is. See
    // https://crbug.com/942073#c14.
    *location = base::EscapeNonASCII(location_strpiece);
  }

  return true;
}

bool HttpResponseHeaders::HasStorageAccessRetryHeader(
    const std::string* expected_origin) const {
  std::optional<std::string> header_value =
      GetNormalizedHeader(kActivateStorageAccessHeader);
  if (!header_value) {
    return false;
  }
  const std::optional<structured_headers::ParameterizedItem> item =
      structured_headers::ParseItem(*header_value);
  if (!item || !item->item.is_token() || item->item.GetString() != "retry") {
    return false;
  }
  return base::ranges::any_of(
      item->params, [&](const auto& key_and_value) -> bool {
        const auto [key, value] = key_and_value;
        if (key != "allowed-origin") {
          return false;
        }
        if (value.is_token() && value.GetString() == "*") {
          return true;
        }
        return expected_origin && value.is_string() &&
               value.GetString() == *expected_origin;
      });
}

// static
bool HttpResponseHeaders::IsRedirectResponseCode(int response_code) {
  // Users probably want to see 300 (multiple choice) pages, so we don't count
  // them as redirects that need to be followed.
  return (response_code == HTTP_MOVED_PERMANENTLY ||
          response_code == HTTP_FOUND || response_code == HTTP_SEE_OTHER ||
          response_code == HTTP_TEMPORARY_REDIRECT ||
          response_code == HTTP_PERMANENT_REDIRECT);
}

// From RFC 2616 section 13.2.4:
//
// The calculation to determine if a response has expired is quite simple:
//
//   response_is_fresh = (freshness_lifetime > current_age)
//
// Of course, there are other factors that can force a response to always be
// validated or re-fetched.
//
// From RFC 5861 section 3, a stale response may be used while revalidation is
// performed in the background if
//
//   freshness_lifetime + stale_while_revalidate > current_age
//
ValidationType HttpResponseHeaders::RequiresValidation(
    const Time& request_time,
    const Time& response_time,
    const Time& current_time) const {
  FreshnessLifetimes lifetimes = GetFreshnessLifetimes(response_time);
  if (lifetimes.freshness.is_zero() && lifetimes.staleness.is_zero())
    return VALIDATION_SYNCHRONOUS;

  base::TimeDelta age =
      GetCurrentAge(request_time, response_time, current_time);

  if (lifetimes.freshness > age)
    return VALIDATION_NONE;

  if (lifetimes.freshness + lifetimes.staleness > age)
    return VALIDATION_ASYNCHRONOUS;

  return VALIDATION_SYNCHRONOUS;
}

// From RFC 2616 section 13.2.4:
//
// The max-age directive takes priority over Expires, so if max-age is present
// in a response, the calculation is simply:
//
//   freshness_lifetime = max_age_value
//
// Otherwise, if Expires is present in the response, the calculation is:
//
//   freshness_lifetime = expires_value - date_value
//
// Note that neither of these calculations is vulnerable to clock skew, since
// all of the information comes from the origin server.
//
// Also, if the response does have a Last-Modified time, the heuristic
// expiration value SHOULD be no more than some fraction of the interval since
// that time. A typical setting of this fraction might be 10%:
//
//   freshness_lifetime = (date_value - last_modified_value) * 0.10
//
// If the stale-while-revalidate directive is present, then it is used to set
// the |staleness| time, unless it overridden by another directive.
//
HttpResponseHeaders::FreshnessLifetimes
HttpResponseHeaders::GetFreshnessLifetimes(const Time& response_time) const {
  FreshnessLifetimes lifetimes;
  // Check for headers that force a response to never be fresh.  For backwards
  // compat, we treat "Pragma: no-cache" as a synonym for "Cache-Control:
  // no-cache" even though RFC 2616 does not specify it.
  if (HasHeaderValue("cache-control", "no-cache") ||
      HasHeaderValue("cache-control", "no-store") ||
      HasHeaderValue("pragma", "no-cache")) {
    return lifetimes;
  }

  // Cache-Control directive must_revalidate overrides stale-while-revalidate.
  bool must_revalidate = HasHeaderValue("cache-control", "must-revalidate");

  lifetimes.staleness =
      must_revalidate
          ? base::TimeDelta()
          : GetStaleWhileRevalidateValue().value_or(base::TimeDelta());

  // NOTE: "Cache-Control: max-age" overrides Expires, so we only check the
  // Expires header after checking for max-age in GetFreshnessLifetimes.  This
  // is important since "Expires: <date in the past>" means not fresh, but
  // it should not trump a max-age value.
  std::optional<base::TimeDelta> max_age_value = GetMaxAgeValue();
  if (max_age_value) {
    lifetimes.freshness = max_age_value.value();
    return lifetimes;
  }

  // If there is no Date header, then assume that the server response was
  // generated at the time when we received the response.
  Time date_value = GetDateValue().value_or(response_time);

  std::optional<Time> expires_value = GetExpiresValue();
  if (expires_value) {
    // The expires value can be a date in the past!
    if (expires_value > date_value) {
      lifetimes.freshness = expires_value.value() - date_value;
      return lifetimes;
    }

    DCHECK_EQ(base::TimeDelta(), lifetimes.freshness);
    return lifetimes;
  }

  // From RFC 2616 section 13.4:
  //
  //   A response received with a status code of 200, 203, 206, 300, 301 or 410
  //   MAY be stored by a cache and used in reply to a subsequent request,
  //   subject to the expiration mechanism, unless a cache-control directive
  //   prohibits caching.
  //   ...
  //   A response received with any other status code (e.g. status codes 302
  //   and 307) MUST NOT be returned in a reply to a subsequent request unless
  //   there are cache-control directives or another header(s) that explicitly
  //   allow it.
  //
  // From RFC 2616 section 14.9.4:
  //
  //   When the must-revalidate directive is present in a response received by
  //   a cache, that cache MUST NOT use the entry after it becomes stale to
  //   respond to a subsequent request without first revalidating it with the
  //   origin server. (I.e., the cache MUST do an end-to-end revalidation every
  //   time, if, based solely on the origin server's Expires or max-age value,
  //   the cached response is stale.)
  //
  // https://datatracker.ietf.org/doc/draft-reschke-http-status-308/ is an
  // experimental RFC that adds 308 permanent redirect as well, for which "any
  // future references ... SHOULD use one of the returned URIs."
  if ((response_code_ == HTTP_OK ||
       response_code_ == HTTP_NON_AUTHORITATIVE_INFORMATION ||
       response_code_ == HTTP_PARTIAL_CONTENT) &&
      !must_revalidate) {
    // TODO(darin): Implement a smarter heuristic.
    std::optional<Time> last_modified_value = GetLastModifiedValue();
    if (last_modified_value) {
      // The last-modified value can be a date in the future!
      if (last_modified_value.value() <= date_value) {
        lifetimes.freshness = (date_value - last_modified_value.value()) / 10;
        return lifetimes;
      }
    }
  }

  // These responses are implicitly fresh (unless otherwise overruled):
  if (response_code_ == HTTP_MULTIPLE_CHOICES ||
      response_code_ == HTTP_MOVED_PERMANENTLY ||
      response_code_ == HTTP_PERMANENT_REDIRECT ||
      response_code_ == HTTP_GONE) {
    lifetimes.freshness = base::TimeDelta::Max();
    lifetimes.staleness = base::TimeDelta();  // It should never be stale.
    return lifetimes;
  }

  // Our heuristic freshness estimate for this resource is 0 seconds, in
  // accordance with common browser behaviour. However, stale-while-revalidate
  // may still apply.
  DCHECK_EQ(base::TimeDelta(), lifetimes.freshness);
  return lifetimes;
}

// From RFC 7234 section 4.2.3:
//
// The following data is used for the age calculation:
//
//    age_value
//
//       The term "age_value" denotes the value of the Age header field
//       (Section 5.1), in a form appropriate for arithmetic operation; or
//       0, if not available.
//
//    date_value
//
//       The term "date_value" denotes the value of the Date header field,
//       in a form appropriate for arithmetic operations.  See Section
//       7.1.1.2 of [RFC7231] for the definition of the Date header field,
//       and for requirements regarding responses without it.
//
//    now
//
//       The term "now" means "the current value of the clock at the host
//       performing the calculation".  A host ought to use NTP ([RFC5905])
//       or some similar protocol to synchronize its clocks to Coordinated
//       Universal Time.
//
//    request_time
//
//       The current value of the clock at the host at the time the request
//       resulting in the stored response was made.
//
//    response_time
//
//       The current value of the clock at the host at the time the
//       response was received.
//
//    The age is then calculated as
//
//     apparent_age = max(0, response_time - date_value);
//     response_delay = response_time - request_time;
//     corrected_age_value = age_value + response_delay;
//     corrected_initial_age = max(apparent_age, corrected_age_value);
//     resident_time = now - response_time;
//     current_age = corrected_initial_age + resident_time;
//
base::TimeDelta HttpResponseHeaders::GetCurrentAge(
    const Time& request_time,
    const Time& response_time,
    const Time& current_time) const {
  // If there is no Date header, then assume that the server response was
  // generated at the time when we received the response.
  Time date_value = GetDateValue().value_or(response_time);

  // If there is no Age header, then assume age is zero.
  base::TimeDelta age_value = GetAgeValue().value_or(base::TimeDelta());

  base::TimeDelta apparent_age =
      std::max(base::TimeDelta(), response_time - date_value);
  base::TimeDelta response_delay = response_time - request_time;
  base::TimeDelta corrected_age_value = age_value + response_delay;
  base::TimeDelta corrected_initial_age =
      std::max(apparent_age, corrected_age_value);
  base::TimeDelta resident_time = current_time - response_time;
  base::TimeDelta current_age = corrected_initial_age + resident_time;

  return current_age;
}

std::optional<base::TimeDelta> HttpResponseHeaders::GetMaxAgeValue() const {
  return GetCacheControlDirective("max-age");
}

std::optional<base::TimeDelta> HttpResponseHeaders::GetAgeValue() const {
  std::optional<std::string> value;
  if (!(value = EnumerateHeader(nullptr, "Age"))) {
    return std::nullopt;
  }

  // Parse the delta-seconds as 1*DIGIT.
  uint32_t seconds;
  ParseIntError error;
  if (!ParseUint32(*value, ParseIntFormat::NON_NEGATIVE, &seconds, &error)) {
    if (error == ParseIntError::FAILED_OVERFLOW) {
      // If the Age value cannot fit in a uint32_t, saturate it to a maximum
      // value. This is similar to what RFC 2616 says in section 14.6 for how
      // caches should transmit values that overflow.
      seconds = std::numeric_limits<decltype(seconds)>::max();
    } else {
      return std::nullopt;
    }
  }

  return base::Seconds(seconds);
}

std::optional<Time> HttpResponseHeaders::GetDateValue() const {
  return GetTimeValuedHeader("Date");
}

std::optional<Time> HttpResponseHeaders::GetLastModifiedValue() const {
  return GetTimeValuedHeader("Last-Modified");
}

std::optional<Time> HttpResponseHeaders::GetExpiresValue() const {
  return GetTimeValuedHeader("Expires");
}

std::optional<base::TimeDelta>
HttpResponseHeaders::GetStaleWhileRevalidateValue() const {
  return GetCacheControlDirective("stale-while-revalidate");
}

std::optional<Time> HttpResponseHeaders::GetTimeValuedHeader(
    const std::string& name) const {
  std::optional<std::string_view> value;
  if (!(value = EnumerateHeader(nullptr, name))) {
    return std::nullopt;
  }

  // In case of parsing the Expires header value, an invalid string 0 should be
  // treated as expired according to the RFC 9111 section 5.3 as below:
  //
  // > A cache recipient MUST interpret invalid date formats, especially the
  // > value "0", as representing a time in the past (i.e., "already expired").
  if (base::FeatureList::IsEnabled(
          features::kTreatHTTPExpiresHeaderValueZeroAsExpired) &&
      name == "Expires" && *value == "0") {
    return Time::Min();
  }

  // When parsing HTTP dates it's beneficial to default to GMT because:
  // 1. RFC2616 3.3.1 says times should always be specified in GMT
  // 2. Only counter-example incorrectly appended "UTC" (crbug.com/153759)
  // 3. When adjusting cookie expiration times for clock skew
  //    (crbug.com/135131) this better matches our cookie expiration
  //    time parser which ignores timezone specifiers and assumes GMT.
  // 4. This is exactly what Firefox does.
  // TODO(pauljensen): The ideal solution would be to return std::nullopt if the
  // timezone could not be understood so as to avoid making other calculations
  // based on an incorrect time.  This would require modifying the time
  // library or duplicating the code. (http://crbug.com/158327)
  Time result;
  return Time::FromUTCString(std::string(*value).c_str(), &result)
             ? std::make_optional(result)
             : std::nullopt;
}

// We accept the first value of "close" or "keep-alive" in a Connection or
// Proxy-Connection header, in that order. Obeying "keep-alive" in HTTP/1.1 or
// "close" in 1.0 is not strictly standards-compliant, but we'd like to
// avoid looking at the Proxy-Connection header whenever it is reasonable to do
// so.
// TODO(ricea): Measure real-world usage of the "Proxy-Connection" header,
// with a view to reducing support for it in order to make our Connection header
// handling more RFC 7230 compliant.
bool HttpResponseHeaders::IsKeepAlive() const {
  // NOTE: It is perhaps risky to assume that a Proxy-Connection header is
  // meaningful when we don't know that this response was from a proxy, but
  // Mozilla also does this, so we'll do the same.
  static const char* const kConnectionHeaders[] = {"connection",
                                                   "proxy-connection"};
  struct KeepAliveToken {
    const char* const token;
    bool keep_alive;
  };
  static const KeepAliveToken kKeepAliveTokens[] = {{"keep-alive", true},
                                                    {"close", false}};

  if (http_version_ < HttpVersion(1, 0))
    return false;

  for (const char* header : kConnectionHeaders) {
    size_t iterator = 0;
    std::optional<std::string_view> token;
    while ((token = EnumerateHeader(&iterator, header))) {
      for (const KeepAliveToken& keep_alive_token : kKeepAliveTokens) {
        if (base::EqualsCaseInsensitiveASCII(*token, keep_alive_token.token)) {
          return keep_alive_token.keep_alive;
        }
      }
    }
  }
  return http_version_ != HttpVersion(1, 0);
}

bool HttpResponseHeaders::HasStrongValidators() const {
  return HttpUtil::HasStrongValidators(
      GetHttpVersion(), EnumerateHeader(nullptr, "etag"),
      EnumerateHeader(nullptr, "Last-Modified"),
      EnumerateHeader(nullptr, "Date"));
}

bool HttpResponseHeaders::HasValidators() const {
  return HttpUtil::HasValidators(GetHttpVersion(),
                                 EnumerateHeader(nullptr, "etag"),
                                 EnumerateHeader(nullptr, "Last-Modified"));
}

// From RFC 2616:
// Content-Length = "Content-Length" ":" 1*DIGIT
int64_t HttpResponseHeaders::GetContentLength() const {
  return GetInt64HeaderValue("content-length");
}

int64_t HttpResponseHeaders::GetInt64HeaderValue(
    const std::string& header) const {
  size_t iter = 0;
  std::optional<std::string_view> content_length =
      EnumerateHeader(&iter, header);
  if (!content_length || content_length->empty()) {
    return -1;
  }

  if ((*content_length)[0] == '+') {
    return -1;
  }

  int64_t result;
  bool ok = base::StringToInt64(*content_length, &result);
  if (!ok || result < 0) {
    return -1;
  }

  return result;
}

bool HttpResponseHeaders::GetContentRangeFor206(
    int64_t* first_byte_position,
    int64_t* last_byte_position,
    int64_t* instance_length) const {
  size_t iter = 0;
  std::optional<std::string_view> content_range =
      EnumerateHeader(&iter, kContentRange);
  if (!content_range) {
    *first_byte_position = *last_byte_position = *instance_length = -1;
    return false;
  }

  return HttpUtil::ParseContentRangeHeaderFor206(
      *content_range, first_byte_position, last_byte_position, instance_length);
}

base::Value::Dict HttpResponseHeaders::NetLogParams(
    NetLogCaptureMode capture_mode) const {
  base::Value::Dict dict;
  base::Value::List headers;
  headers.Append(NetLogStringValue(GetStatusLine()));
  size_t iterator = 0;
  std::string name;
  std::string value;
  while (EnumerateHeaderLines(&iterator, &name, &value)) {
    std::string log_value =
        ElideHeaderValueForNetLog(capture_mode, name, value);
    headers.Append(NetLogStringValue(base::StrCat({name, ": ", log_value})));
  }
  dict.Set("headers", std::move(headers));
  return dict;
}

bool HttpResponseHeaders::IsChunkEncoded() const {
  // Ignore spurious chunked responses from HTTP/1.0 servers and proxies.
  return GetHttpVersion() >= HttpVersion(1, 1) &&
         HasHeaderValue("Transfer-Encoding", "chunked");
}

bool HttpResponseHeaders::IsCookieResponseHeader(std::string_view name) {
  for (const char* cookie_header : kCookieResponseHeaders) {
    if (base::EqualsCaseInsensitiveASCII(cookie_header, name))
      return true;
  }
  return false;
}

void HttpResponseHeaders::WriteIntoTrace(perfetto::TracedValue context) const {
  perfetto::TracedDictionary dict = std::move(context).WriteDictionary();
  dict.Add("response_code", response_code_);
  dict.Add("headers", parsed_);
}

bool HttpResponseHeaders::StrictlyEquals(
    const HttpResponseHeaders& other) const {
  if (http_version_ != other.http_version_ ||
      response_code_ != other.response_code_ ||
      raw_headers_ != other.raw_headers_ ||
      parsed_.size() != other.parsed_.size()) {
    return false;
  }

  auto offsets_match = [&](std::string::const_iterator this_offset,
                           std::string::const_iterator other_offset) {
    return this_offset - raw_headers_.begin() ==
           other_offset - other.raw_headers_.begin();
  };
  return std::mismatch(parsed_.begin(), parsed_.end(), other.parsed_.begin(),
                       [&](const ParsedHeader& lhs, const ParsedHeader& rhs) {
                         return offsets_match(lhs.name_begin, rhs.name_begin) &&
                                offsets_match(lhs.name_end, rhs.name_end) &&
                                offsets_match(lhs.value_begin,
                                              rhs.value_begin) &&
                                offsets_match(lhs.value_end, rhs.value_end);
                       }) == std::pair(parsed_.end(), other.parsed_.end());
}

}  // namespace net
```