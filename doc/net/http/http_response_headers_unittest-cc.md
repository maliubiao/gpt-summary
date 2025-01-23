Response:
My thought process for analyzing the provided C++ code and generating the summary involved the following steps:

1. **Identify the Core Functionality:** I first looked at the file name (`http_response_headers_unittest.cc`) and the included header (`net/http/http_response_headers.h`). This immediately told me the file was a unit test for the `HttpResponseHeaders` class in Chromium's network stack. The purpose is to test the various functionalities of this class.

2. **Scan for Key Classes and Methods under Test:** I then scanned the code for test fixtures (like `HttpResponseHeadersTest`, `HttpResponseHeadersCacheControlTest`, etc.) and individual test cases (using `TEST_P` and `TEST`). This gave me a high-level overview of what aspects of `HttpResponseHeaders` were being tested.

3. **Analyze Individual Test Groups:** I examined each test fixture and its associated test cases. For instance:
    * `CommonHttpResponseHeadersTest`:  This test group uses parameterization (`INSTANTIATE_TEST_SUITE_P`) with the `response_headers_tests` array. This indicates it's testing the basic parsing and normalization of various HTTP header combinations. I noted the `HeadersToRaw` function converts human-readable headers to the internal representation.
    * `HttpResponseHeadersCacheControlTest`: This clearly focuses on testing the parsing and handling of `Cache-Control` headers, particularly `max-age` and `stale-while-revalidate`.
    * `PersistenceTest`:  This group tests the ability to serialize and deserialize `HttpResponseHeaders` using `base::Pickle`, covering different persistence options (e.g., excluding hop-by-hop headers, cookies).
    * Other `TEST` functions like `EnumerateHeader_Coalesced`, `EnumerateHeader_Challenge`, `GetAgeValue`, `GetMimeType`, and `RequiresValidationTest` each target specific methods and functionalities of the `HttpResponseHeaders` class.

4. **Infer Functionality from Test Cases:** By looking at the inputs and expected outputs of the tests (even though the full output isn't provided in the snippet), I could deduce what each test was verifying. For example:
    * Tests in `CommonHttpResponseHeadersTest` show how the class handles whitespace, different HTTP versions, missing status text, invalid status lines, etc.
    * `PersistenceTest` checks if header information is correctly preserved or filtered based on the `PersistOptions`.
    * `GetAgeValue` tests parsing of the `Age` header, including handling of invalid or out-of-range values.
    * `GetMimeType` tests extracting the MIME type and charset from the `Content-Type` header, dealing with various formats and edge cases.
    * `RequiresValidationTest` examines how the class determines if a cached response needs revalidation based on headers like `Cache-Control`, `Expires`, `Date`, and `Last-Modified`.

5. **Identify Potential Links to JavaScript:** I considered how HTTP headers interact with JavaScript in a browser environment. Key areas include:
    * **Caching:** JavaScript code (through `fetch` or `XMLHttpRequest`) is affected by caching directives in HTTP headers. The tests related to `Cache-Control`, `Expires`, `Age`, and `RequiresValidation` directly relate to this.
    * **Cookies:**  The `Set-Cookie` header, tested in `PersistenceTest`, is crucial for managing user sessions and state, and JavaScript can access and manipulate cookies.
    * **Content Type:** The `Content-Type` header influences how the browser interprets the response data, which is relevant when JavaScript processes the response.
    * **Security Headers:** While not explicitly prominent in *this snippet*, headers like `Strict-Transport-Security` (mentioned in a test) have security implications that affect JavaScript's ability to interact with the server.

6. **Consider User/Programming Errors:** I thought about common mistakes developers might make when dealing with HTTP headers, and how the `HttpResponseHeaders` class might handle them:
    * Incorrect header formatting (tested in `CommonHttpResponseHeadersTest`).
    * Misunderstanding caching directives.
    * Issues with date formats in headers.
    * Incorrectly setting or interpreting `Content-Type`.

7. **Think about Debugging Scenarios:** I imagined a scenario where a web developer is debugging an issue related to caching or incorrect response interpretation. Understanding how the `HttpResponseHeaders` class parses and interprets headers is essential for diagnosing such problems. The unit tests themselves serve as examples of how to verify header parsing.

8. **Structure the Summary:** Finally, I organized my findings into a coherent summary, covering the core functionality, JavaScript relevance, logical inferences, common errors, and debugging context. I aimed for clarity and conciseness, highlighting the key takeaways from the code snippet.

By following these steps, I could systematically analyze the code and generate a comprehensive and informative summary, even without executing the code or having the complete context of the `HttpResponseHeaders` class implementation.
这是文件 `net/http/http_response_headers_unittest.cc` 的 Chromium 网络栈源代码，它主要的功能是**测试 `net::HttpResponseHeaders` 类的各种功能**。`HttpResponseHeaders` 类负责解析和存储 HTTP 响应头。

**具体功能归纳如下：**

1. **HTTP 响应头解析和规范化:**
   - 测试 `HttpResponseHeaders` 类如何解析原始的 HTTP 响应头字符串。
   - 验证解析后的头信息是否被正确规范化，例如：去除多余空格、处理大小写不敏感的头名称、处理空值头等。
   - **假设输入:** 一个包含各种格式 HTTP 响应头的字符串，例如 `"HTTP/1.1  200  OK\nContent-Type: text/html\n"`。
   - **预期输出:** `HttpResponseHeaders` 对象，其内部存储的头信息已规范化，例如 `{"Content-Type": "text/html"}`。

2. **HTTP 版本、状态码和状态文本的提取:**
   - 测试 `HttpResponseHeaders` 类能否正确提取 HTTP 版本 (例如 HTTP/1.1, HTTP/1.0, HTTP/0.9)。
   - 验证能否正确提取 HTTP 状态码 (例如 200, 404, 500)。
   - 验证能否正确提取状态文本 (例如 OK, Not Found)。

3. **`Cache-Control` 头部的解析:**
   - 测试 `HttpResponseHeaders` 类如何解析 `Cache-Control` 头部，包括 `max-age`, `stale-while-revalidate` 等指令。
   - 验证能否正确提取这些指令的值并将其转换为 `base::TimeDelta` 对象。

4. **HTTP 头部持久化 (序列化和反序列化):**
   - 测试 `HttpResponseHeaders` 类是否能够将自身序列化到 `base::Pickle` 对象中，以便存储或传输。
   - 验证从 `base::Pickle` 对象反序列化后， `HttpResponseHeaders` 对象是否能恢复其原始状态。
   - 测试不同的持久化选项 (`PersistOptions`)，例如：保留所有头部、去除 hop-by-hop 头部、去除不可缓存的头部、去除 cookie 头部和去除安全状态相关的头部。

5. **枚举 HTTP 头部:**
   - 测试 `EnumerateHeader` 方法，验证其能够正确地枚举具有相同名称的多个头部，例如 `Set-Cookie` 或 `Cache-Control`。
   - 验证对于具有逗号分隔值的头部（例如 `Cache-Control`），能否正确地枚举出每个独立的值。
   - 验证对于某些特殊头部（例如 `WWW-Authenticate`），逗号不应该被视为分隔符。

6. **日期相关头部的解析:**
   - 测试 `HttpResponseHeaders` 类解析日期头部（例如 `Date`, `Last-Modified`, `Expires`）的功能。
   - 验证对于格式不完全符合 RFC 规范的日期字符串，是否能进行合理的解释，例如，当缺少时区信息时，默认解释为 GMT。

7. **`Age` 头部的解析:**
   - 测试 `HttpResponseHeaders` 类解析 `Age` 头部，并将其值转换为 `base::TimeDelta` 对象。
   - 验证对于无效的 `Age` 值（例如非数字、负数、带有前导加号），是否能正确处理。
   - 验证对于溢出的 `Age` 值，是否会饱和到一个最大值。

8. **`Content-Type` 头部的解析:**
   - 测试 `HttpResponseHeaders` 类解析 `Content-Type` 头部，并提取 MIME 类型和字符集信息。
   - 验证在存在多个 `Content-Type` 头部时，如何选择正确的 MIME 类型和字符集。
   - 验证如何处理 `Content-Type` 头部中包含的参数和注释。

9. **判断是否需要重新验证缓存:**
   - 测试 `RequiresValidation` 方法，验证其根据各种缓存相关的头部（例如 `Cache-Control`, `Expires`, `Date`, `Last-Modified`）以及请求和响应时间，判断缓存是否过期，并返回相应的 `ValidationType`。
   - **假设输入:** 包含缓存控制头的 HTTP 响应头，以及请求时间、响应时间和当前时间。
   - **预期输出:** `ValidationType` 枚举值，例如 `VALIDATION_NONE` (不需要重新验证), `VALIDATION_SYNCHRONOUS` (需要同步重新验证)。

**与 JavaScript 的关系：**

`HttpResponseHeaders` 类处理的 HTTP 响应头信息直接影响着 Web 浏览器（包括 JavaScript 运行环境）的行为。以下是一些关系示例：

- **缓存控制:**  `Cache-Control`, `Expires`, `Pragma` 等头部决定了浏览器是否可以缓存资源，以及缓存多久。JavaScript 发起的网络请求（通过 `fetch` API 或 `XMLHttpRequest`）会受到这些头部的约束。例如，如果响应头包含 `Cache-Control: max-age=3600`，浏览器可能会缓存该资源 1 小时，后续 JavaScript 发起的相同请求可能会直接从缓存中获取，而无需再次请求服务器。
- **Cookie:** `Set-Cookie` 头部由服务器发送，指示浏览器存储 cookie。JavaScript 可以通过 `document.cookie` 属性读取和设置 cookie。`HttpResponseHeaders` 负责解析 `Set-Cookie` 头部，浏览器会根据解析结果存储 cookie。
- **Content-Type:** `Content-Type` 头部告诉浏览器响应体的 MIME 类型，这会影响浏览器如何处理响应数据。例如，如果 `Content-Type` 是 `application/json`，浏览器会将其作为 JSON 数据处理，JavaScript 可以方便地使用 `JSON.parse()` 解析它。
- **安全策略:** 诸如 `Strict-Transport-Security` (HSTS) 等安全头部会影响浏览器对后续请求的处理，即使是通过 JavaScript 发起的请求。

**用户或编程常见的使用错误举例：**

- **日期格式错误:** 服务器可能发送格式不符合 RFC 规范的日期头部，导致浏览器解析错误，影响缓存策略。例如，缺少时区信息或使用了非标准的日期格式。
- **`Cache-Control` 指令冲突:** 服务器可能设置了相互冲突的 `Cache-Control` 指令，例如同时设置 `no-cache` 和一个较长的 `max-age`，导致开发者困惑浏览器的缓存行为。
- **`Content-Type` 设置不正确:** 服务器可能返回了错误的 `Content-Type`，例如返回 JSON 数据但 `Content-Type` 却是 `text/html`，这会导致浏览器无法正确解析数据，JavaScript 代码也会出错。
- **误解缓存行为:** 开发者可能没有充分理解 HTTP 缓存的工作原理，错误地设置缓存头部，导致用户总是获取到旧版本资源或缓存了不应该缓存的敏感数据。

**用户操作如何一步步到达这里，作为调试线索：**

假设用户在使用 Chrome 浏览器访问一个网页时遇到了与 HTTP 响应头相关的问题，例如：

1. **用户访问网页:** 用户在地址栏输入 URL 并按下回车，或者点击了一个链接。
2. **浏览器发起 HTTP 请求:** Chrome 浏览器会向服务器发送 HTTP 请求。
3. **服务器返回 HTTP 响应:** 服务器处理请求后，会返回包含 HTTP 响应头的响应。
4. **Chrome 网络栈处理响应头:** Chrome 的网络栈（包括 `net::HttpResponseHeaders` 类）会接收并解析这些响应头。
5. **问题出现:**  在这个阶段，如果响应头存在问题（例如格式错误、缓存指令冲突等），可能会导致以下情况：
   - **缓存问题:** 页面没有被正确缓存，导致重复请求；或者页面被错误地缓存，导致用户看到旧版本内容。
   - **Cookie 问题:** Cookie 没有被正确设置或读取。
   - **内容解析错误:**  浏览器无法正确解析响应体，例如 JSON 数据显示为纯文本。
   - **安全问题:** HSTS 等安全策略没有生效。

作为调试线索，开发者可以：

- **使用开发者工具 (F12):** 在 Chrome 的开发者工具的 "Network" 标签页中查看请求和响应的详细信息，包括原始的响应头。
- **查看 `net-internals` (chrome://net-internals/#http):** 这个工具提供了更底层的网络请求信息，可以帮助诊断更复杂的问题。
- **检查服务器配置:**  确认服务器返回的 HTTP 响应头是否符合预期。
- **查看 Chrome 源代码 (如果需要深入了解):**  `net/http/http_response_headers_unittest.cc` 文件本身就是调试和理解 `HttpResponseHeaders` 类行为的良好资源。通过阅读测试用例，可以了解该类如何处理各种不同的头部格式和场景。

**总结一下 `net/http/http_response_headers_unittest.cc` 的功能：**

这个单元测试文件全面地测试了 `net::HttpResponseHeaders` 类的各项功能，包括 HTTP 响应头的解析、规范化、特定头部信息的提取（如缓存控制、日期、内容类型等）以及持久化能力。这些测试确保了 Chromium 浏览器能够正确地理解和处理服务器返回的 HTTP 响应头，从而保证了网络功能的正常运行，并对 JavaScript 在浏览器环境中的行为产生直接影响。

### 提示词
```
这是目录为net/http/http_response_headers_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_response_headers.h"

#include <stdint.h>

#include <iostream>
#include <memory>
#include <optional>
#include <string_view>
#include <unordered_set>

#include "base/pickle.h"
#include "base/strings/stringprintf.h"
#include "base/time/time.h"
#include "base/types/optional_util.h"
#include "base/values.h"
#include "net/base/cronet_buildflags.h"
#include "net/base/tracing.h"
#include "net/http/http_byte_range.h"
#include "net/http/http_response_headers_test_util.h"
#include "net/http/http_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

#if !BUILDFLAG(CRONET_BUILD)
#include "third_party/perfetto/include/perfetto/test/traced_value_test_support.h"
#endif

namespace net {

namespace {

struct TestData {
  const char* raw_headers;
  const char* expected_headers;
  HttpVersion expected_version;
  int expected_response_code;
  const char* expected_status_text;
};

class HttpResponseHeadersTest : public testing::Test {
};

// Transform "normal"-looking headers (\n-separated) to the appropriate
// input format for ParseRawHeaders (\0-separated).
void HeadersToRaw(std::string* headers) {
  std::replace(headers->begin(), headers->end(), '\n', '\0');
  if (!headers->empty())
    *headers += '\0';
}

class HttpResponseHeadersCacheControlTest : public HttpResponseHeadersTest {
 protected:
  // Make tests less verbose.
  typedef base::TimeDelta TimeDelta;

  // Initilise the headers() value with a Cache-Control header set to
  // |cache_control|. |cache_control| is copied and so can safely be a
  // temporary.
  void InitializeHeadersWithCacheControl(const char* cache_control) {
    std::string raw_headers("HTTP/1.1 200 OK\n");
    raw_headers += "Cache-Control: ";
    raw_headers += cache_control;
    raw_headers += "\n";
    HeadersToRaw(&raw_headers);
    headers_ = base::MakeRefCounted<HttpResponseHeaders>(raw_headers);
  }

  const scoped_refptr<HttpResponseHeaders>& headers() { return headers_; }

  // Get the max-age value. This should only be used in tests where a valid
  // max-age parameter is expected to be present.
  TimeDelta GetMaxAgeValue() {
    DCHECK(headers_.get()) << "Call InitializeHeadersWithCacheControl() first";
    std::optional<TimeDelta> max_age_value = headers()->GetMaxAgeValue();
    EXPECT_TRUE(max_age_value);
    return max_age_value.value();
  }

  // Get the stale-while-revalidate value. This should only be used in tests
  // where a valid max-age parameter is expected to be present.
  TimeDelta GetStaleWhileRevalidateValue() {
    DCHECK(headers_.get()) << "Call InitializeHeadersWithCacheControl() first";
    std::optional<TimeDelta> stale_while_revalidate_value =
        headers()->GetStaleWhileRevalidateValue();
    EXPECT_TRUE(stale_while_revalidate_value);
    return stale_while_revalidate_value.value();
  }

 private:
  scoped_refptr<HttpResponseHeaders> headers_;
};

class CommonHttpResponseHeadersTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<TestData> {
};

constexpr auto ToSimpleString = test::HttpResponseHeadersToSimpleString;

// Transform to readable output format (so it's easier to see diffs).
void EscapeForPrinting(std::string* s) {
  std::replace(s->begin(), s->end(), ' ', '_');
  std::replace(s->begin(), s->end(), '\n', '\\');
}

TEST_P(CommonHttpResponseHeadersTest, TestCommon) {
  const TestData test = GetParam();

  std::string raw_headers(test.raw_headers);
  HeadersToRaw(&raw_headers);
  std::string expected_headers(test.expected_headers);

  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(raw_headers);
  std::string headers = ToSimpleString(parsed);

  EscapeForPrinting(&headers);
  EscapeForPrinting(&expected_headers);

  EXPECT_EQ(expected_headers, headers);

  SCOPED_TRACE(test.raw_headers);

  EXPECT_TRUE(test.expected_version == parsed->GetHttpVersion());
  EXPECT_EQ(test.expected_response_code, parsed->response_code());
  EXPECT_EQ(test.expected_status_text, parsed->GetStatusText());
}

TestData response_headers_tests[] = {
    {// Normalize whitespace.
     "HTTP/1.1    202   Accepted  \n"
     "Content-TYPE  : text/html; charset=utf-8  \n"
     "Set-Cookie: a \n"
     "Set-Cookie:   b \n",

     "HTTP/1.1 202 Accepted\n"
     "Content-TYPE: text/html; charset=utf-8\n"
     "Set-Cookie: a\n"
     "Set-Cookie: b\n",

     HttpVersion(1, 1), 202, "Accepted"},
    {// Normalize leading whitespace.
     "HTTP/1.1    202   Accepted  \n"
     // Starts with space -- will be skipped as invalid.
     "  Content-TYPE  : text/html; charset=utf-8  \n"
     "Set-Cookie: a \n"
     "Set-Cookie:   b \n",

     "HTTP/1.1 202 Accepted\n"
     "Set-Cookie: a\n"
     "Set-Cookie: b\n",

     HttpVersion(1, 1), 202, "Accepted"},
    {// Keep whitespace within status text.
     "HTTP/1.0 404 Not   found  \n",

     "HTTP/1.0 404 Not   found\n",

     HttpVersion(1, 0), 404, "Not   found"},
    {// Normalize blank headers.
     "HTTP/1.1 200 OK\n"
     "Header1 :          \n"
     "Header2: \n"
     "Header3:\n"
     "Header4\n"
     "Header5    :\n",

     "HTTP/1.1 200 OK\n"
     "Header1: \n"
     "Header2: \n"
     "Header3: \n"
     "Header5: \n",

     HttpVersion(1, 1), 200, "OK"},
    {// Don't believe the http/0.9 version if there are headers!
     "hTtP/0.9 201\n"
     "Content-TYPE: text/html; charset=utf-8\n",

     "HTTP/1.0 201\n"
     "Content-TYPE: text/html; charset=utf-8\n",

     HttpVersion(1, 0), 201, ""},
    {// Accept the HTTP/0.9 version number if there are no headers.
     // This is how HTTP/0.9 responses get constructed from
     // HttpNetworkTransaction.
     "hTtP/0.9 200 OK\n",

     "HTTP/0.9 200 OK\n",

     HttpVersion(0, 9), 200, "OK"},
    {// Do not add missing status text.
     "HTTP/1.1 201\n"
     "Content-TYPE: text/html; charset=utf-8\n",

     "HTTP/1.1 201\n"
     "Content-TYPE: text/html; charset=utf-8\n",

     HttpVersion(1, 1), 201, ""},
    {// Normalize bad status line.
     "SCREWED_UP_STATUS_LINE\n"
     "Content-TYPE: text/html; charset=utf-8\n",

     "HTTP/1.0 200 OK\n"
     "Content-TYPE: text/html; charset=utf-8\n",

     HttpVersion(1, 0), 200, "OK"},
    {// Normalize bad status line.
     "Foo bar.",

     "HTTP/1.0 200\n",

     HttpVersion(1, 0), 200, ""},
    {// Normalize invalid status code.
     "HTTP/1.1 -1  Unknown\n",

     "HTTP/1.1 200\n",

     HttpVersion(1, 1), 200, ""},
    {// Normalize empty header.
     "",

     "HTTP/1.0 200 OK\n",

     HttpVersion(1, 0), 200, "OK"},
    {// Normalize headers that start with a colon.
     "HTTP/1.1    202   Accepted  \n"
     "foo: bar\n"
     ": a \n"
     " : b\n"
     "baz: blat \n",

     "HTTP/1.1 202 Accepted\n"
     "foo: bar\n"
     "baz: blat\n",

     HttpVersion(1, 1), 202, "Accepted"},
    {// Normalize headers that end with a colon.
     "HTTP/1.1    202   Accepted  \n"
     "foo:   \n"
     "bar:\n"
     "baz: blat \n"
     "zip:\n",

     "HTTP/1.1 202 Accepted\n"
     "foo: \n"
     "bar: \n"
     "baz: blat\n"
     "zip: \n",

     HttpVersion(1, 1), 202, "Accepted"},
    {// Normalize whitespace headers.
     "\n   \n",

     "HTTP/1.0 200 OK\n",

     HttpVersion(1, 0), 200, "OK"},
    {// Has multiple Set-Cookie headers.
     "HTTP/1.1 200 OK\n"
     "Set-Cookie: x=1\n"
     "Set-Cookie: y=2\n",

     "HTTP/1.1 200 OK\n"
     "Set-Cookie: x=1\n"
     "Set-Cookie: y=2\n",

     HttpVersion(1, 1), 200, "OK"},
    {// Has multiple cache-control headers.
     "HTTP/1.1 200 OK\n"
     "Cache-control: private\n"
     "cache-Control: no-store\n",

     "HTTP/1.1 200 OK\n"
     "Cache-control: private\n"
     "cache-Control: no-store\n",

     HttpVersion(1, 1), 200, "OK"},
    {// Has multiple-value cache-control header.
     "HTTP/1.1 200 OK\n"
     "Cache-Control: private, no-store\n",

     "HTTP/1.1 200 OK\n"
     "Cache-Control: private, no-store\n",

     HttpVersion(1, 1), 200, "OK"},
    {// Missing HTTP.
     " 200 Yes\n",

     "HTTP/1.0 200 Yes\n",

     HttpVersion(1, 0), 200, "Yes"},
    {// Only HTTP.
     "HTTP\n",

     "HTTP/1.0 200 OK\n",

     HttpVersion(1, 0), 200, "OK"},
    {// Missing HTTP version.
     "HTTP 404 No\n",

     "HTTP/1.0 404 No\n",

     HttpVersion(1, 0), 404, "No"},
    {// Missing dot in HTTP version.
     "HTTP/1 304 Not Friday\n",

     "HTTP/1.0 304 Not Friday\n",

     HttpVersion(1, 0), 304, "Not Friday"},
    {// Multi-digit HTTP version (our error detection is bad).
     "HTTP/234.01 204 Nothing here\n",

     "HTTP/2.0 204 Nothing here\n",

     HttpVersion(2, 0), 204, "Nothing here"},
    {// HTTP minor version attached to response code (pretty bad parsing).
     "HTTP/1 302.1 Bad parse\n",

     "HTTP/1.1 302 .1 Bad parse\n",

     HttpVersion(1, 1), 302, ".1 Bad parse"},
    {// HTTP minor version inside the status text (bad parsing).
     "HTTP/1 410 Gone in 0.1 seconds\n",

     "HTTP/1.1 410 Gone in 0.1 seconds\n",

     HttpVersion(1, 1), 410, "Gone in 0.1 seconds"},
    {// Status text smushed into response code.
     "HTTP/1.1 426Smush\n",

     "HTTP/1.1 426 Smush\n",

     HttpVersion(1, 1), 426, "Smush"},
    {// Tab not recognised as separator (this is standard compliant).
     "HTTP/1.1\t500 204 Bad\n",

     "HTTP/1.1 204 Bad\n",

     HttpVersion(1, 1), 204, "Bad"},
    {// Junk after HTTP version is ignored.
     "HTTP/1.1ignored 201 Not ignored\n",

     "HTTP/1.1 201 Not ignored\n",

     HttpVersion(1, 1), 201, "Not ignored"},
    {// Tab gets included in status text.
     "HTTP/1.1 501\tStatus\t\n",

     "HTTP/1.1 501 \tStatus\t\n",

     HttpVersion(1, 1), 501, "\tStatus\t"},
    {// Zero response code.
     "HTTP/1.1 0 Zero\n",

     "HTTP/1.1 0 Zero\n",

     HttpVersion(1, 1), 0, "Zero"},
    {// Oversize response code.
     "HTTP/1.1 20230904 Monday\n",

     "HTTP/1.1 20230904 Monday\n",

     HttpVersion(1, 1), 20230904, "Monday"},
    {// Overflowing response code.
     "HTTP/1.1 9123456789 Overflow\n",

     "HTTP/1.1 9123456789 Overflow\n",

     HttpVersion(1, 1), 2147483647, "Overflow"},
};

INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         CommonHttpResponseHeadersTest,
                         testing::ValuesIn(response_headers_tests));

struct PersistData {
  HttpResponseHeaders::PersistOptions options;
  const char* raw_headers;
  const char* expected_headers;
};

class PersistenceTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<PersistData> {
};

TEST_P(PersistenceTest, Persist) {
  const PersistData test = GetParam();

  std::string headers = test.raw_headers;
  HeadersToRaw(&headers);
  auto parsed1 = base::MakeRefCounted<HttpResponseHeaders>(headers);

  base::Pickle pickle;
  parsed1->Persist(&pickle, test.options);

  base::PickleIterator iter(pickle);
  auto parsed2 = base::MakeRefCounted<HttpResponseHeaders>(&iter);

  EXPECT_EQ(std::string(test.expected_headers), ToSimpleString(parsed2));
}

const struct PersistData persistence_tests[] = {
    {HttpResponseHeaders::PERSIST_ALL,
     "HTTP/1.1 200 OK\n"
     "Cache-control:private\n"
     "cache-Control:no-store\n",

     "HTTP/1.1 200 OK\n"
     "Cache-control: private\n"
     "cache-Control: no-store\n"},
    {HttpResponseHeaders::PERSIST_SANS_HOP_BY_HOP,
     "HTTP/1.1 200 OK\n"
     "connection: keep-alive\n"
     "server: blah\n",

     "HTTP/1.1 200 OK\n"
     "server: blah\n"},
    {HttpResponseHeaders::PERSIST_SANS_NON_CACHEABLE |
         HttpResponseHeaders::PERSIST_SANS_HOP_BY_HOP,
     "HTTP/1.1 200 OK\n"
     "fOo: 1\n"
     "Foo: 2\n"
     "Transfer-Encoding: chunked\n"
     "CoNnection: keep-alive\n"
     "cache-control: private, no-cache=\"foo\"\n",

     "HTTP/1.1 200 OK\n"
     "cache-control: private, no-cache=\"foo\"\n"},
    {HttpResponseHeaders::PERSIST_SANS_NON_CACHEABLE,
     "HTTP/1.1 200 OK\n"
     "Foo: 2\n"
     "Cache-Control: private,no-cache=\"foo, bar\"\n"
     "bar",

     "HTTP/1.1 200 OK\n"
     "Cache-Control: private,no-cache=\"foo, bar\"\n"},
    // Ignore bogus no-cache value.
    {HttpResponseHeaders::PERSIST_SANS_NON_CACHEABLE,
     "HTTP/1.1 200 OK\n"
     "Foo: 2\n"
     "Cache-Control: private,no-cache=foo\n",

     "HTTP/1.1 200 OK\n"
     "Foo: 2\n"
     "Cache-Control: private,no-cache=foo\n"},
    // Ignore bogus no-cache value.
    {HttpResponseHeaders::PERSIST_SANS_NON_CACHEABLE,
     "HTTP/1.1 200 OK\n"
     "Foo: 2\n"
     "Cache-Control: private, no-cache=\n",

     "HTTP/1.1 200 OK\n"
     "Foo: 2\n"
     "Cache-Control: private, no-cache=\n"},
    // Ignore empty no-cache value.
    {HttpResponseHeaders::PERSIST_SANS_NON_CACHEABLE,
     "HTTP/1.1 200 OK\n"
     "Foo: 2\n"
     "Cache-Control: private, no-cache=\"\"\n",

     "HTTP/1.1 200 OK\n"
     "Foo: 2\n"
     "Cache-Control: private, no-cache=\"\"\n"},
    // Ignore wrong quotes no-cache value.
    {HttpResponseHeaders::PERSIST_SANS_NON_CACHEABLE,
     "HTTP/1.1 200 OK\n"
     "Foo: 2\n"
     "Cache-Control: private, no-cache=\'foo\'\n",

     "HTTP/1.1 200 OK\n"
     "Foo: 2\n"
     "Cache-Control: private, no-cache=\'foo\'\n"},
    // Ignore unterminated quotes no-cache value.
    {HttpResponseHeaders::PERSIST_SANS_NON_CACHEABLE,
     "HTTP/1.1 200 OK\n"
     "Foo: 2\n"
     "Cache-Control: private, no-cache=\"foo\n",

     "HTTP/1.1 200 OK\n"
     "Foo: 2\n"
     "Cache-Control: private, no-cache=\"foo\n"},
    // Accept sloppy LWS.
    {HttpResponseHeaders::PERSIST_SANS_NON_CACHEABLE,
     "HTTP/1.1 200 OK\n"
     "Foo: 2\n"
     "Cache-Control: private, no-cache=\" foo\t, bar\"\n",

     "HTTP/1.1 200 OK\n"
     "Cache-Control: private, no-cache=\" foo\t, bar\"\n"},
    // Header name appears twice, separated by another header.
    {HttpResponseHeaders::PERSIST_ALL,
     "HTTP/1.1 200 OK\n"
     "Foo: 1\n"
     "Bar: 2\n"
     "Foo: 3\n",

     "HTTP/1.1 200 OK\n"
     "Foo: 1\n"
     "Bar: 2\n"
     "Foo: 3\n"},
    // Header name appears twice, separated by another header (type 2).
    {HttpResponseHeaders::PERSIST_ALL,
     "HTTP/1.1 200 OK\n"
     "Foo: 1, 3\n"
     "Bar: 2\n"
     "Foo: 4\n",

     "HTTP/1.1 200 OK\n"
     "Foo: 1, 3\n"
     "Bar: 2\n"
     "Foo: 4\n"},
    // Test filtering of cookie headers.
    {HttpResponseHeaders::PERSIST_SANS_COOKIES,
     "HTTP/1.1 200 OK\n"
     "Set-Cookie: foo=bar; httponly\n"
     "Set-Cookie: bar=foo\n"
     "Bar: 1\n"
     "Set-Cookie2: bar2=foo2\n",

     "HTTP/1.1 200 OK\n"
     "Bar: 1\n"},
    {HttpResponseHeaders::PERSIST_SANS_COOKIES,
     "HTTP/1.1 200 OK\n"
     "Set-Cookie: foo=bar\n"
     "Foo: 2\n"
     "Clear-Site-Data: \"cookies\"\n"
     "Bar: 3\n",

     "HTTP/1.1 200 OK\n"
     "Foo: 2\n"
     "Bar: 3\n"},
    // Test LWS at the end of a header.
    {HttpResponseHeaders::PERSIST_ALL,
     "HTTP/1.1 200 OK\n"
     "Content-Length: 450   \n"
     "Content-Encoding: gzip\n",

     "HTTP/1.1 200 OK\n"
     "Content-Length: 450\n"
     "Content-Encoding: gzip\n"},
    // Test LWS at the end of a header.
    {HttpResponseHeaders::PERSIST_RAW,
     "HTTP/1.1 200 OK\n"
     "Content-Length: 450   \n"
     "Content-Encoding: gzip\n",

     "HTTP/1.1 200 OK\n"
     "Content-Length: 450\n"
     "Content-Encoding: gzip\n"},
    // Test filtering of transport security state headers.
    {HttpResponseHeaders::PERSIST_SANS_SECURITY_STATE,
     "HTTP/1.1 200 OK\n"
     "Strict-Transport-Security: max-age=1576800\n"
     "Bar: 1\n",

     "HTTP/1.1 200 OK\n"
     "Bar: 1\n"},
};

INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         PersistenceTest,
                         testing::ValuesIn(persistence_tests));

TEST(HttpResponseHeadersTest, EnumerateHeader_Coalesced) {
  // Ensure that commas in quoted strings are not regarded as value separators.
  // Ensure that whitespace following a value is trimmed properly.
  std::string headers =
      "HTTP/1.1 200 OK\n"
      "Cache-control:,,private , no-cache=\"set-cookie,server\",\n"
      "cache-Control: no-store\n"
      "cache-Control:\n";
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);

  size_t iter = 0;
  EXPECT_EQ("", parsed->EnumerateHeader(&iter, "cache-control"));
  EXPECT_EQ("", parsed->EnumerateHeader(&iter, "cache-control"));
  EXPECT_EQ("private", parsed->EnumerateHeader(&iter, "cache-control"));
  EXPECT_EQ("no-cache=\"set-cookie,server\"",
            parsed->EnumerateHeader(&iter, "cache-control"));
  EXPECT_EQ("", parsed->EnumerateHeader(&iter, "cache-control"));
  EXPECT_EQ("no-store", parsed->EnumerateHeader(&iter, "cache-control"));
  EXPECT_EQ("", parsed->EnumerateHeader(&iter, "cache-control"));
  EXPECT_FALSE(parsed->EnumerateHeader(&iter, "cache-control"));

  // Test the deprecated overload that returns values as std::strings.
  iter = 0;
  std::string value;
  ASSERT_TRUE(parsed->EnumerateHeader(&iter, "cache-control", &value));
  EXPECT_EQ("", value);
  ASSERT_TRUE(parsed->EnumerateHeader(&iter, "cache-control", &value));
  EXPECT_EQ("", value);
  ASSERT_TRUE(parsed->EnumerateHeader(&iter, "cache-control", &value));
  EXPECT_EQ("private", value);
  ASSERT_TRUE(parsed->EnumerateHeader(&iter, "cache-control", &value));
  EXPECT_EQ("no-cache=\"set-cookie,server\"", value);
  ASSERT_TRUE(parsed->EnumerateHeader(&iter, "cache-control", &value));
  EXPECT_EQ("", value);
  ASSERT_TRUE(parsed->EnumerateHeader(&iter, "cache-control", &value));
  EXPECT_EQ("no-store", value);
  ASSERT_TRUE(parsed->EnumerateHeader(&iter, "cache-control", &value));
  EXPECT_EQ("", value);
  EXPECT_FALSE(parsed->EnumerateHeader(&iter, "cache-control", &value));
}

TEST(HttpResponseHeadersTest, EnumerateHeader_Challenge) {
  // Even though WWW-Authenticate has commas, it should not be treated as
  // coalesced values.
  std::string headers =
      "HTTP/1.1 401 OK\n"
      "WWW-Authenticate:Digest realm=foobar, nonce=x, domain=y\n"
      "WWW-Authenticate:Basic realm=quatar\n";
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);

  size_t iter = 0;
  EXPECT_EQ("Digest realm=foobar, nonce=x, domain=y",
            parsed->EnumerateHeader(&iter, "WWW-Authenticate"));
  EXPECT_EQ("Basic realm=quatar",
            parsed->EnumerateHeader(&iter, "WWW-Authenticate"));
  EXPECT_FALSE(parsed->EnumerateHeader(&iter, "WWW-Authenticate"));

  // Test the deprecated overload that returns values as std::strings.
  iter = 0;
  std::string value;
  EXPECT_TRUE(parsed->EnumerateHeader(&iter, "WWW-Authenticate", &value));
  EXPECT_EQ("Digest realm=foobar, nonce=x, domain=y", value);
  EXPECT_TRUE(parsed->EnumerateHeader(&iter, "WWW-Authenticate", &value));
  EXPECT_EQ("Basic realm=quatar", value);
  EXPECT_FALSE(parsed->EnumerateHeader(&iter, "WWW-Authenticate", &value));
}

TEST(HttpResponseHeadersTest, EnumerateHeader_DateValued) {
  // The comma in a date valued header should not be treated as a
  // field-value separator.
  std::string headers =
      "HTTP/1.1 200 OK\n"
      "Date: Tue, 07 Aug 2007 23:10:55 GMT\n"
      "Last-Modified: Wed, 01 Aug 2007 23:23:45 GMT\n";
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);

  EXPECT_EQ("Tue, 07 Aug 2007 23:10:55 GMT",
            parsed->EnumerateHeader(nullptr, "date"));
  EXPECT_EQ("Wed, 01 Aug 2007 23:23:45 GMT",
            parsed->EnumerateHeader(nullptr, "last-modified"));

  // Test the deprecated overload that returns values as std::strings.
  std::string value;
  EXPECT_TRUE(parsed->EnumerateHeader(nullptr, "date", &value));
  EXPECT_EQ("Tue, 07 Aug 2007 23:10:55 GMT", value);
  EXPECT_TRUE(parsed->EnumerateHeader(nullptr, "last-modified", &value));
  EXPECT_EQ("Wed, 01 Aug 2007 23:23:45 GMT", value);
}

TEST(HttpResponseHeadersTest, DefaultDateToGMT) {
  // Verify we make the best interpretation when parsing dates that incorrectly
  // do not end in "GMT" as RFC2616 requires.
  std::string headers =
      "HTTP/1.1 200 OK\n"
      "Date: Tue, 07 Aug 2007 23:10:55\n"
      "Last-Modified: Tue, 07 Aug 2007 19:10:55 EDT\n"
      "Expires: Tue, 07 Aug 2007 23:10:55 UTC\n";
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);
  base::Time expected_value;
  ASSERT_TRUE(base::Time::FromString("Tue, 07 Aug 2007 23:10:55 GMT",
                                     &expected_value));

  // When the timezone is missing, GMT is a good guess as its what RFC2616
  // requires.
  EXPECT_EQ(expected_value, parsed->GetDateValue());
  // If GMT is missing but an RFC822-conforming one is present, use that.
  EXPECT_EQ(expected_value, parsed->GetLastModifiedValue());
  // If an unknown timezone is present, treat like a missing timezone and
  // default to GMT.  The only example of a web server not specifying "GMT"
  // used "UTC" which is equivalent to GMT.
  EXPECT_THAT(parsed->GetExpiresValue(),
              testing::AnyOf(std::nullopt, expected_value));
}

TEST(HttpResponseHeadersTest, GetAgeValue10) {
  std::string headers =
      "HTTP/1.1 200 OK\n"
      "Age: 10\n";
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);
  EXPECT_EQ(base::Seconds(10), parsed->GetAgeValue());
}

TEST(HttpResponseHeadersTest, GetAgeValue0) {
  std::string headers =
      "HTTP/1.1 200 OK\n"
      "Age: 0\n";
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);
  EXPECT_EQ(base::TimeDelta(), parsed->GetAgeValue());
}

TEST(HttpResponseHeadersTest, GetAgeValueBogus) {
  std::string headers =
      "HTTP/1.1 200 OK\n"
      "Age: donkey\n";
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);
  EXPECT_FALSE(parsed->GetAgeValue());
}

TEST(HttpResponseHeadersTest, GetAgeValueNegative) {
  std::string headers =
      "HTTP/1.1 200 OK\n"
      "Age: -10\n";
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);
  EXPECT_FALSE(parsed->GetAgeValue());
}

TEST(HttpResponseHeadersTest, GetAgeValueLeadingPlus) {
  std::string headers =
      "HTTP/1.1 200 OK\n"
      "Age: +10\n";
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);
  EXPECT_FALSE(parsed->GetAgeValue());
}

TEST(HttpResponseHeadersTest, GetAgeValueOverflow) {
  std::string headers =
      "HTTP/1.1 200 OK\n"
      "Age: 999999999999999999999999999999999999999999\n";
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);

  // Should have saturated to 2^32 - 1.
  EXPECT_EQ(base::Seconds(static_cast<int64_t>(0xFFFFFFFFL)),
            parsed->GetAgeValue());
}

struct ContentTypeTestData {
  const std::string raw_headers;
  const std::string mime_type;
  const bool has_mimetype;
  const std::string charset;
  const bool has_charset;
  const std::string all_content_type;
};

class ContentTypeTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<ContentTypeTestData> {
};

TEST_P(ContentTypeTest, GetMimeType) {
  const ContentTypeTestData test = GetParam();

  std::string headers(test.raw_headers);
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);

  std::string value;
  EXPECT_EQ(test.has_mimetype, parsed->GetMimeType(&value));
  EXPECT_EQ(test.mime_type, value);
  value.clear();
  EXPECT_EQ(test.has_charset, parsed->GetCharset(&value));
  EXPECT_EQ(test.charset, value);
  EXPECT_EQ(parsed->GetNormalizedHeader("content-type"), test.all_content_type);
}

// clang-format off
const ContentTypeTestData mimetype_tests[] = {
  { "HTTP/1.1 200 OK\n"
    "Content-type: text/html\n",
    "text/html", true,
    "", false,
    "text/html" },
  // Multiple content-type headers should give us the last one.
  { "HTTP/1.1 200 OK\n"
    "Content-type: text/html\n"
    "Content-type: text/html\n",
    "text/html", true,
    "", false,
    "text/html, text/html" },
  { "HTTP/1.1 200 OK\n"
    "Content-type: text/plain\n"
    "Content-type: text/html\n"
    "Content-type: text/plain\n"
    "Content-type: text/html\n",
    "text/html", true,
    "", false,
    "text/plain, text/html, text/plain, text/html" },
  // Test charset parsing.
  { "HTTP/1.1 200 OK\n"
    "Content-type: text/html\n"
    "Content-type: text/html; charset=ISO-8859-1\n",
    "text/html", true,
    "iso-8859-1", true,
    "text/html, text/html; charset=ISO-8859-1" },
  // Test charset in double quotes.
  { "HTTP/1.1 200 OK\n"
    "Content-type: text/html\n"
    "Content-type: text/html; charset=\"ISO-8859-1\"\n",
    "text/html", true,
    "iso-8859-1", true,
    "text/html, text/html; charset=\"ISO-8859-1\"" },
  // If there are multiple matching content-type headers, we carry
  // over the charset value.
  { "HTTP/1.1 200 OK\n"
    "Content-type: text/html;charset=utf-8\n"
    "Content-type: text/html\n",
    "text/html", true,
    "utf-8", true,
    "text/html;charset=utf-8, text/html" },
  // Regression test for https://crbug.com/772350:
  // Single quotes are not delimiters but must be treated as part of charset.
  { "HTTP/1.1 200 OK\n"
    "Content-type: text/html;charset='utf-8'\n"
    "Content-type: text/html\n",
    "text/html", true,
    "'utf-8'", true,
    "text/html;charset='utf-8', text/html" },
  // First charset wins if matching content-type.
  { "HTTP/1.1 200 OK\n"
    "Content-type: text/html;charset=utf-8\n"
    "Content-type: text/html;charset=iso-8859-1\n",
    "text/html", true,
    "iso-8859-1", true,
    "text/html;charset=utf-8, text/html;charset=iso-8859-1" },
  // Charset is ignored if the content types change.
  { "HTTP/1.1 200 OK\n"
    "Content-type: text/plain;charset=utf-8\n"
    "Content-type: text/html\n",
    "text/html", true,
    "", false,
    "text/plain;charset=utf-8, text/html" },
  // Empty content-type.
  { "HTTP/1.1 200 OK\n"
    "Content-type: \n",
    "", false,
    "", false,
    "" },
  // Emtpy charset.
  { "HTTP/1.1 200 OK\n"
    "Content-type: text/html;charset=\n",
    "text/html", true,
    "", false,
    "text/html;charset=" },
  // Multiple charsets, first one wins.
  { "HTTP/1.1 200 OK\n"
    "Content-type: text/html;charset=utf-8; charset=iso-8859-1\n",
    "text/html", true,
    "utf-8", true,
    "text/html;charset=utf-8; charset=iso-8859-1" },
  // Multiple params.
  { "HTTP/1.1 200 OK\n"
    "Content-type: text/html; foo=utf-8; charset=iso-8859-1\n",
    "text/html", true,
    "iso-8859-1", true,
    "text/html; foo=utf-8; charset=iso-8859-1" },
  { "HTTP/1.1 200 OK\n"
    "Content-type: text/html ; charset=utf-8 ; bar=iso-8859-1\n",
    "text/html", true,
    "utf-8", true,
    "text/html ; charset=utf-8 ; bar=iso-8859-1" },
  // Comma embeded in quotes.
  { "HTTP/1.1 200 OK\n"
    "Content-type: text/html ; charset=\"utf-8,text/plain\" ;\n",
    "text/html", true,
    "utf-8,text/plain", true,
    "text/html ; charset=\"utf-8,text/plain\" ;" },
  // Charset with leading spaces.
  { "HTTP/1.1 200 OK\n"
    "Content-type: text/html ; charset= \"utf-8\" ;\n",
    "text/html", true,
    "utf-8", true,
    "text/html ; charset= \"utf-8\" ;" },
  // Media type comments in mime-type.
  { "HTTP/1.1 200 OK\n"
    "Content-type: text/html (html)\n",
    "text/html", true,
    "", false,
   "text/html (html)" },
  // Incomplete charset= param.
  { "HTTP/1.1 200 OK\n"
    "Content-type: text/html; char=\n",
    "text/html", true,
    "", false,
    "text/html; char=" },
  // Invalid media type: no slash.
  { "HTTP/1.1 200 OK\n"
    "Content-type: texthtml\n",
    "", false,
    "", false,
    "texthtml" },
  // Invalid media type: "*/*".
  { "HTTP/1.1 200 OK\n"
    "Content-type: */*\n",
    "", false,
    "", false,
    "*/*" },
};
// clang-format on

INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         ContentTypeTest,
                         testing::ValuesIn(mimetype_tests));

struct RequiresValidationTestData {
  const char* headers;
  ValidationType validation_type;
};

class RequiresValidationTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<RequiresValidationTestData> {
};

TEST_P(RequiresValidationTest, RequiresValidation) {
  const RequiresValidationTestData test = GetParam();

  base::Time request_time, response_time, current_time;
  ASSERT_TRUE(
      base::Time::FromString("Wed, 28 Nov 2007 00:40:09 GMT", &request_time));
  ASSERT_TRUE(
      base::Time::FromString("Wed, 28 Nov 2007 00:40:12 GMT", &response_time));
  ASSERT_TRUE(
      base::Time::FromString("Wed, 28 Nov 2007 00:45:20 GMT", &current_time));

  std::string headers(test.headers);
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);

  ValidationType validation_type =
      parsed->RequiresValidation(request_time, response_time, current_time);
  EXPECT_EQ(test.validation_type, validation_type);
}

const struct RequiresValidationTestData requires_validation_tests[] = {
    // No expiry info: expires immediately.
    {"HTTP/1.1 200 OK\n"
     "\n",
     VALIDATION_SYNCHRONOUS},
    // No expiry info: expires immediately.
    {"HTTP/1.1 200 OK\n"
     "\n",
     VALIDATION_SYNCHRONOUS},
    // Valid for a little while.
    {"HTTP/1.1 200 OK\n"
     "cache-control: max-age=10000\n"
     "\n",
     VALIDATION_NONE},
    // Expires in the future.
    {"HTTP/1.1 200 OK\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "expires: Wed, 28 Nov 2007 01:00:00 GMT\n"
     "\n",
     VALIDATION_NONE},
    // Already expired.
    {"HTTP/1.1 200 OK\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "expires: Wed, 28 Nov 2007 00:00:00 GMT\n"
     "\n",
     VALIDATION_SYNCHRONOUS},
    // Max-age trumps expires.
    {"HTTP/1.1 200 OK\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "expires: Wed, 28 Nov 2007 00:00:00 GMT\n"
     "cache-control: max-age=10000\n"
     "\n",
     VALIDATION_NONE},
    // Last-modified heuristic: modified a while ago.
    {"HTTP/1.1 200 OK\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "last-modified: Wed, 27 Nov 2007 08:00:00 GMT\n"
     "\n",
     VALIDATION_NONE},
    {"HTTP/1.1 203 Non-Authoritative Information\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "last-modified: Wed, 27 Nov 2007 08:00:00 GMT\n"
     "\n",
     VALIDATION_NONE},
    {"HTTP/1.1 206 Partial Content\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "last-modified: Wed, 27 Nov 2007 08:00:00 GMT\n"
     "\n",
     VALIDATION_NONE},
    // Last-modified heuristic: modified a while ago and it's VALIDATION_NONE
    // (fresh) like above but VALIDATION_SYNCHRONOUS if expires header value is
    // "0".
    {"HTTP/1.1 200 OK\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "last-modified: Tue, 27 Nov 2007 08:00:00 GMT\n"
     "expires: 0\n"
     "\n",
     VALIDATION_SYNCHRONOUS},
    {"HTTP/1.1 200 OK\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "last-modified: Tue, 27 Nov 2007 08:00:00 GMT\n"
     "expires:  0 \n"
     "\n",
     VALIDATION_SYNCHRONOUS},
    // The cache is fresh if the expires header value is an invalid date string
    // except for "0"
    {"HTTP/1.1 200 OK\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "last-modified: Tue, 27 Nov 2007 08:00:00 GMT\n"
     "expires: banana \n"
     "\n",
     VALIDATION_NONE},
    // Last-modified heuristic: modified recently.
    {"HTTP/1.1 200 OK\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "last-modified: Wed, 28 Nov 2007 00:40:10 GMT\n"
     "\n",
     VALIDATION_SYNCHRONOUS},
    {"HTTP/1.1 203 Non-Authoritative Information\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "last-modified: Wed, 28 Nov 2007 00:40:10 GMT\n"
     "\n",
     VALIDATION_SYNCHRONOUS},
    {"HTTP/1.1 206 Partial Content\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "last-modified: Wed, 28 Nov 2007 00:40:10 GMT\n"
     "\n",
     VALIDATION_SYNCHRONOUS},
    // Cached permanent redirect.
    {"HTTP/1.1 301 Moved Permanently\n"
     "\n",
     VALIDATION_NONE},
    // Another cached permanent redirect.
    {"HTTP/1.1 308 Permanent Redirect\n"
     "\n",
     VALIDATION_NONE},
    // Cached redirect: not reusable even though by default it would be.
    {"HTTP/1.1 300 Multiple Choices\n"
     "Cache-Control: no-cache\n"
     "\n",
     VALIDATION_SYNCHRONOUS},
    // Cached forever by default.
    {"HTTP/1.1 410 Gone\n"
     "\n",
     VALIDATION_NONE},
    // Cached temporary redirect: not reusable.
    {"HTTP/1.1 302 Found\n"
     "\n",
     VALIDATION_SYNCHRONOUS},
    // Cached temporary redirect: reusable.
    {"HTTP/1.1 302 Found\n"
     "cache-control: max-age=10000\n"
     "\n",
     VALIDATION_NONE},
    // Cache-control: max-age=N overrides expires: date in the past.
    {"HTTP/1.1 200 OK\n"
```