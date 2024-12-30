Response:
Let's break down the thought process for analyzing this C++ code snippet and generating the response.

**1. Understanding the Goal:**

The primary goal is to analyze the provided C++ code (`http_util_unittest.cc`) and explain its functionality. Specifically, the prompt asks for:

* **Functionality:** What does this code *do*?
* **JavaScript Relevance:**  Is there any connection to JavaScript?
* **Logic Reasoning:**  Can we infer input/output based on the tests?
* **Common Errors:** What mistakes might users or programmers make?
* **User Journey:** How does a user's action lead to this code being involved?
* **Debugging Clues:** How does this help with debugging?
* **Overall Summary:** A concise summary of the file's purpose.

**2. Initial Code Scan and Identification of Key Elements:**

The first step is to quickly scan the code and identify the most prominent features:

* **`#include` directives:** These tell us about the dependencies. `net/http/http_util.h` is the most important, suggesting this file tests the functionality defined in `http_util.h`. Other includes (`algorithm`, `limits`, `string_view`, `base/strings/string_util.h`, `base/time/time.h`, `testing/gtest/include/gtest/gtest.h`) point to standard library components, base utilities, and the Google Test framework. The `#ifdef UNSAFE_BUFFERS_BUILD` block is a conditional compilation directive and can be noted but isn't core to the functionality being tested.
* **`namespace net {`:** This indicates that the code belongs to the `net` namespace, which is a strong signal that it's part of the networking stack.
* **`TEST(HttpUtilTest, ...)`:**  This is the hallmark of Google Test. Each `TEST` macro defines an independent test case. The first argument (`HttpUtilTest`) groups these tests, and the second argument is the specific test name.
* **Test Names (e.g., `IsSafeHeader`, `HeadersIterator`, `ValuesIterator`, `Unquote`, `StrictUnquote`, etc.):**  These names provide direct clues about the functions being tested within `http_util.h`.
* **Assertions (e.g., `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `ASSERT_TRUE`):** These are the mechanisms used by Google Test to verify the correctness of the code being tested.

**3. Analyzing Individual Test Cases:**

Now, we examine each test case in more detail:

* **`IsSafeHeader`:** This test checks the `IsSafeHeader` function. It has two arrays: `unsafe_headers` and `safe_headers`. The test iterates through these arrays and asserts the expected boolean return value of `IsSafeHeader`. It also tests cases with forbidden methods for specific headers.
* **`HeadersIterator`:** This test focuses on the `HeadersIterator` class. It creates a string of headers, initializes the iterator, and then uses `GetNext()` to iterate through the headers, verifying the `name()` and `values()` of each. It also tests malformed header lines and the `AdvanceTo` and `Reset` methods.
* **`ValuesIterator`:** Similar to `HeadersIterator`, this test focuses on the `ValuesIterator` class, which is used to iterate through comma-separated values within a header. It tests both ignoring and including empty values.
* **`Unquote` and `StrictUnquote`:** These tests examine functions for removing quotes from strings, with `StrictUnquote` adding stricter validation.
* **`Quote`:**  This test checks the function for adding quotes to a string.
* **`LocateEndOfHeaders` and `LocateEndOfAdditionalHeaders`:** These tests focus on functions that find the end of the header section in an HTTP message.
* **`AssembleRawHeaders`:** This test examines a function that reconstructs raw HTTP headers, including handling line continuations.
* **`RequestUrlSanitize`:** This test checks a function that sanitizes URLs for requests, removing things like hashes and authentication information.
* **`GenerateAcceptLanguageHeader`:** This test verifies the generation of the `Accept-Language` header based on a language list.
* **`ParseContentType` and `ParseContentResetCharset`:** These tests check the functionality of parsing the `Content-Type` header to extract the MIME type, charset, and boundary.
* **`ParseContentRangeHeader`:** This test examines the parsing of the `Content-Range` header.
* **`ParseRetryAfterHeader`:** This test checks the parsing of the `Retry-After` header, handling both numeric delays and date values.

**4. Identifying Functionality and Relationships:**

Based on the test names and the logic within each test, we can deduce the following about the file's functionality:

* **Testing `net::HttpUtil`:** The primary purpose is to test the utility functions within the `net::HttpUtil` class.
* **Header Manipulation:**  A significant portion of the tests deals with HTTP headers: identifying safe headers, iterating through headers and values, quoting and unquoting, locating the end of headers, and assembling raw headers.
* **URL Handling:**  The `RequestUrlSanitize` test indicates functionality for cleaning up URLs.
* **Content Type Parsing:** The tests for `ParseContentType` show functionality for extracting information from the `Content-Type` header.
* **Range and Retry-After Parsing:** The tests for `ParseContentRangeHeader` and `ParseRetryAfterHeader` indicate functionality for parsing these specific headers.

**5. Addressing JavaScript Relevance:**

We need to consider if any of these functionalities directly relate to JavaScript. While the C++ code itself doesn't execute JavaScript, its functions are used within the browser's networking stack, which *does* interact with JavaScript. Key connections are:

* **Fetching Resources:** JavaScript's `fetch` API or `XMLHttpRequest` ultimately rely on the browser's networking stack to send HTTP requests and receive responses. The header parsing and manipulation functions tested here are crucial for processing those responses.
* **Security:** The `IsSafeHeader` function is directly related to browser security, preventing JavaScript from setting or reading potentially sensitive headers.

**6. Inferring Input/Output and Common Errors:**

For each test, the input is usually a string (header, values, URL, etc.), and the output is a boolean (for assertions like `EXPECT_TRUE`/`EXPECT_FALSE`) or a specific value (string, integer, etc.) being compared with `EXPECT_EQ`. We can construct hypothetical examples based on the test cases.

Common errors often arise from:

* **Incorrect header formatting:** Misplaced colons, incorrect line endings, etc. (tested by `HeadersIterator_MalformedLine`).
* **Incorrect quoting:**  Mismatched quotes, missing escape characters (tested by `StrictUnquote`).
* **Invalid header names:**  Attempting to set restricted headers (related to `IsSafeHeader`).
* **Incorrect date/time formats:** Errors in `Retry-After` headers.
* **Range errors:**  Invalid ranges in `Content-Range` headers.

**7. Tracing the User Journey and Debugging:**

To understand how a user's action reaches this code, we consider scenarios like:

* **Webpage Loading:** When a user navigates to a website, the browser sends HTTP requests. The parsing and validation of the server's responses involve the functions tested here.
* **JavaScript `fetch()` calls:**  JavaScript making a network request will trigger the underlying networking stack, including header processing.
* **File Downloads:**  Handling `Content-Range` headers is crucial for resuming interrupted downloads or downloading parts of a file.

Debugging would involve looking at the raw HTTP headers being sent and received and using tools to step through the C++ networking code. The tests themselves provide valuable debugging information by illustrating expected behavior.

**8. Summarizing Functionality:**

Finally, we synthesize the information gathered into a concise summary of the file's purpose.

By following this structured approach, we can thoroughly analyze the C++ code and generate a comprehensive explanation that addresses all the points raised in the prompt. The key is to break down the code into its individual components (test cases), understand what each component is testing, and then connect those individual pieces to the broader functionality of the networking stack and its interaction with JavaScript.
好的，这是对`net/http/http_util_unittest.cc`文件第一部分的分析和总结：

**功能归纳:**

这个C++源代码文件 `http_util_unittest.cc` 是 Chromium 网络栈的一部分，专门用于对 `net/http/http_util.h` 中定义的 HTTP 实用工具函数进行单元测试。  从目前提供的代码片段来看，它主要测试了以下几方面功能：

1. **HTTP 头部安全校验 (`IsSafeHeader` 测试):**
   -  验证 `HttpUtil::IsSafeHeader` 函数，该函数用于判断给定的 HTTP 头部是否是安全的，可以被客户端随意设置。
   -  测试了各种不安全（例如以 "sec-" 或 "proxy-" 开头的头部，以及 `connection`, `content-length`, `cookie` 等关键头部）和安全头部的情况。
   -  还测试了对于一些特殊的头部（例如 `x-http-method`），当其值包含被禁止的 HTTP 方法（如 `CONNECT`, `TRACE`, `TRACK`）时，也会被认为是不安全的。

2. **HTTP 头部迭代器 (`HeadersIterator` 测试):**
   -  验证 `HttpUtil::HeadersIterator` 类，该类用于方便地遍历和解析 HTTP 头部字符串。
   -  测试了从格式良好的头部字符串中提取头部名称和值。
   -  测试了处理格式错误的头部行的情况（例如缺少冒号，或者头部名称无效）。
   -  测试了 `AdvanceTo` 方法，用于直接定位到指定名称的头部。
   -  测试了 `Reset` 方法，用于将迭代器重置到头部字符串的开始。

3. **HTTP 头部值迭代器 (`ValuesIterator` 测试):**
   -  验证 `HttpUtil::ValuesIterator` 类，该类用于迭代逗号分隔的头部值。
   -  测试了忽略和不忽略空值的情况。
   -  测试了头部值中包含空格和制表符的情况。

4. **字符串引号处理 (`Unquote` 和 `StrictUnquote` 测试):**
   -  验证 `HttpUtil::Unquote` 函数，该函数用于移除字符串两端的引号，并处理转义字符。
   -  验证 `HttpUtil::StrictUnquote` 函数，与 `Unquote` 类似，但要求字符串必须以引号开头和结尾，提供更严格的校验。

5. **字符串引号添加 (`Quote` 测试):**
   -  验证 `HttpUtil::Quote` 函数，该函数用于给字符串添加引号，并转义内部的引号。

6. **查找头部结束位置 (`LocateEndOfHeaders` 和 `LocateEndOfAdditionalHeaders` 测试):**
   -  验证 `HttpUtil::LocateEndOfHeaders` 函数，用于在 HTTP 消息中查找头部结束的标志 (`\r\n\r\n` 或 `\n\n`)。
   -  验证 `HttpUtil::LocateEndOfAdditionalHeaders` 函数，用于查找额外的头部结束标志（通常用于分块编码）。

7. **组装原始头部 (`AssembleRawHeaders` 测试):**
   -  验证 `HttpUtil::AssembleRawHeaders` 函数，该函数将 HTTP 状态行和头部行组合成一个原始的头部字符串，并处理头部行的续行。

8. **请求 URL 清理 (`RequestUrlSanitize` 测试):**
   -  验证 `HttpUtil::SpecForRequest` 函数，该函数用于清理请求的 URL，例如移除 URL 中的哈希值 (#hash) 和身份验证信息 (user:pass@)。

9. **生成 `Accept-Language` 头部 (`GenerateAcceptLanguageHeader` 测试):**
   -  验证 `HttpUtil::GenerateAcceptLanguageHeader` 函数，根据给定的语言代码列表生成 `Accept-Language` 头部字符串。

10. **解析 `Content-Type` 头部 (`ParseContentType` 和 `ParseContentResetCharset` 测试):**
    - 验证 `HttpUtil::ParseContentType` 函数，用于解析 `Content-Type` 头部，提取 MIME 类型、字符集和边界信息。
    - 验证 `ParseContentResetCharset` 的行为，确保在 MIME 类型变化时字符集会被正确重置。

11. **解析 `Content-Range` 头部 (`ParseContentRangeHeader` 测试):**
    - 验证 `HttpUtil::ParseContentRangeHeaderFor206` 函数，用于解析 `Content-Range` 头部，提取起始字节位置、结束字节位置和实例总长度。

12. **解析 `Retry-After` 头部 (`ParseRetryAfterHeader` 测试):**
    - 验证 `HttpUtil::ParseRetryAfterHeader` 函数，用于解析 `Retry-After` 头部，提取重试的时间间隔（秒数或具体时间）。

**与 JavaScript 的关系:**

虽然这段 C++ 代码本身不包含 JavaScript，但它所测试的 HTTP 实用工具函数在 Chromium 浏览器中被广泛使用，直接影响着 JavaScript 的网络请求功能：

* **`IsSafeHeader`:** 当 JavaScript 使用 `fetch` API 或 `XMLHttpRequest` 设置请求头时，浏览器会使用类似的机制来检查这些头部是否安全。这是出于安全考虑，防止恶意 JavaScript 代码设置影响浏览器行为的关键头部。
* **头部迭代器和解析函数:**  当浏览器接收到 HTTP 响应时，JavaScript 可以通过 API (例如 `response.headers`) 获取响应头。浏览器内部会使用类似 `HeadersIterator` 和 `ParseContentType` 等工具来解析这些头部，并将结构化的数据提供给 JavaScript。
* **URL 清理:**  在 JavaScript 发起网络请求时，浏览器可能会对 URL 进行清理，例如移除敏感信息，以符合安全策略。
* **`Accept-Language` 头部:**  浏览器会根据用户的语言设置自动生成 `Accept-Language` 头部，并通过 `HttpUtil::GenerateAcceptLanguageHeader` 这样的函数实现，以便告知服务器用户偏好的语言。

**逻辑推理、假设输入与输出 (部分举例):**

**假设输入 `IsSafeHeader`:**

* **输入:** `unsafe_header = "cookie"`, `value = ""`
* **输出:** `EXPECT_FALSE` (因为 "cookie" 是不安全的头部)

* **输入:** `safe_header = "x-custom-header"`, `value = ""`
* **输出:** `EXPECT_TRUE` (因为 "x-custom-header" 是自定义的，被认为是安全的)

* **输入:** `header = "x-http-method"`, `value = "GET"`
* **输出:** `EXPECT_TRUE`

* **输入:** `header = "x-http-method"`, `value = "CONNECT"`
* **输出:** `EXPECT_FALSE` (因为 "CONNECT" 是被禁止的方法)

**假设输入 `HeadersIterator`:**

* **输入 headers:** `"Content-Type: text/html\r\nCache-Control: max-age=3600\r\n"`
* **第一次 `it.GetNext()` 输出:** `name() = "Content-Type"`, `values() = "text/html"`
* **第二次 `it.GetNext()` 输出:** `name() = "Cache-Control"`, `values() = "max-age=3600"`

**假设输入 `ParseContentType`:**

* **输入 content_type:** `"application/json; charset=utf-8"`
* **输出:** `mime_type = "application/json"`, `charset = "utf-8"`, `had_charset = true`

**用户或编程常见的使用错误 (举例):**

1. **错误地认为不安全的头部可以随意设置:**  开发者可能尝试使用 JavaScript 设置 `Cookie` 或 `Origin` 等头部，但浏览器会阻止这种行为，这与 `IsSafeHeader` 的逻辑相关。
   ```javascript
   // 尝试设置不安全的头部 (会被浏览器阻止或修改)
   fetch('/api', {
       headers: {
           'Cookie': 'mycookie=value' // 浏览器通常会忽略或覆盖这个设置
       }
   });
   ```

2. **错误地解析多行头部值:**  开发者可能没有正确处理头部值的续行，导致解析错误。`AssembleRawHeaders` 的测试用例就覆盖了这种情况。

3. **URL 清理导致的意外行为:** 开发者可能依赖于 URL 中包含哈希值或认证信息，但浏览器的 URL 清理机制会移除这些信息，导致请求失败或行为不符合预期。

4. **`Content-Type` 解析不完整:**  开发者可能只关注 MIME 类型，而忽略了字符集或其他参数，导致文本显示乱码等问题。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入网址或点击链接。**
2. **浏览器解析 URL，并决定发起 HTTP 请求。**
3. **如果涉及到自定义请求头 (通过 JavaScript 的 `fetch` 或 `XMLHttpRequest`)，浏览器会调用类似 `HttpUtil::IsSafeHeader` 的函数来检查这些头部是否安全。**
4. **网络栈开始构建 HTTP 请求报文。`HttpUtil::GenerateAcceptLanguageHeader` 可能会被调用来添加 `Accept-Language` 头部。**
5. **请求发送到服务器，服务器返回 HTTP 响应。**
6. **浏览器接收到响应，开始解析响应头。`HttpUtil::LocateEndOfHeaders` 用于定位头部结束位置。**
7. **`HttpUtil::HeadersIterator` 被用来遍历响应头。**
8. **对于特定的头部，例如 `Content-Type`，会调用 `HttpUtil::ParseContentType` 来提取相关信息，以便浏览器知道如何处理响应体（例如，如果它是 HTML，则交给渲染引擎；如果是 JSON，则交给 JavaScript 解析）。**
9. **如果响应状态码是 206 (Partial Content)，则会调用 `HttpUtil::ParseContentRangeHeaderFor206` 来解析 `Content-Range` 头部，以便处理分块下载。**
10. **如果响应状态码是 429 或 503，可能会调用 `HttpUtil::ParseRetryAfterHeader` 来获取服务器建议的重试时间。**

在调试网络相关问题时，如果发现请求头没有按预期发送，或者响应头解析出现问题，就可以查看 `net/http/http_util.cc` 中的相关测试用例，了解这些工具函数的预期行为，并结合抓包工具分析实际的网络数据，定位问题所在。例如，如果发现 JavaScript 设置的某个头部没有生效，可以检查 `IsSafeHeader` 的逻辑，看该头部是否被认为是安全的。

**总结:**

`net/http/http_util_unittest.cc` 的第一部分主要集中在测试 `net::HttpUtil` 中用于处理和解析 HTTP 头部、URL 以及一些特定 HTTP 头部（如 `Content-Type`, `Content-Range`, `Retry-After`）的实用工具函数。这些函数在 Chromium 浏览器的网络请求和响应处理流程中扮演着基础且关键的角色，直接影响着 JavaScript 网络 API 的行为和浏览器的功能。 通过这些单元测试，可以确保这些核心工具函数的正确性和可靠性。

Prompt: 
```
这是目录为net/http/http_util_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/http/http_util.h"

#include <algorithm>
#include <limits>
#include <string_view>

#include "base/strings/string_util.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

TEST(HttpUtilTest, IsSafeHeader) {
  static const char* const unsafe_headers[] = {
      "sec-",
      "sEc-",
      "sec-foo",
      "sEc-FoO",
      "proxy-",
      "pRoXy-",
      "proxy-foo",
      "pRoXy-FoO",
      "accept-charset",
      "accept-encoding",
      "access-control-request-headers",
      "access-control-request-method",
      "access-control-request-private-network",
      "connection",
      "content-length",
      "cookie",
      "cookie2",
      "date",
      "dnt",
      "expect",
      "host",
      "keep-alive",
      "origin",
      "referer",
      "set-cookie",
      "te",
      "trailer",
      "transfer-encoding",
      "upgrade",
      "user-agent",
      "via",
  };
  for (const auto* unsafe_header : unsafe_headers) {
    EXPECT_FALSE(HttpUtil::IsSafeHeader(unsafe_header, "")) << unsafe_header;
    EXPECT_FALSE(HttpUtil::IsSafeHeader(base::ToUpperASCII(unsafe_header), ""))
        << unsafe_header;
  }
  static const char* const safe_headers[] = {
      "foo",
      "x-",
      "x-foo",
      "content-disposition",
      "update",
      "accept-charseta",
      "accept_charset",
      "accept-encodinga",
      "accept_encoding",
      "access-control-request-headersa",
      "access-control-request-header",
      "access_control_request_header",
      "access-control-request-methoda",
      "access_control_request_method",
      "connectiona",
      "content-lengtha",
      "content_length",
      "content-transfer-encoding",
      "cookiea",
      "cookie2a",
      "cookie3",
      "content-transfer-encodinga",
      "content_transfer_encoding",
      "datea",
      "expecta",
      "hosta",
      "keep-alivea",
      "keep_alive",
      "origina",
      "referera",
      "referrer",
      "tea",
      "trailera",
      "transfer-encodinga",
      "transfer_encoding",
      "upgradea",
      "user-agenta",
      "user_agent",
      "viaa",
      // Following 3 headers are safe if there is no forbidden method in values.
      "x-http-method",
      "x-http-method-override",
      "x-method-override",
  };
  for (const auto* safe_header : safe_headers) {
    EXPECT_TRUE(HttpUtil::IsSafeHeader(safe_header, "")) << safe_header;
    EXPECT_TRUE(HttpUtil::IsSafeHeader(base::ToUpperASCII(safe_header), ""))
        << safe_header;
  }

  static const char* const disallowed_with_forbidden_methods_headers[] = {
      "x-http-method",
      "x-http-method-override",
      "x-method-override",
  };
  static const struct {
    const char* value;
    bool is_safe;
  } disallowed_values[] = {{"connect", false},
                           {"trace", false},
                           {"track", false},
                           {"CONNECT", false},
                           {"cOnnEcT", false},
                           {"get", true},
                           {"get,post", true},
                           {"get,connect", false},
                           {"get, connect", false},
                           {"get,connect ", false},
                           {"get,connect ,post", false},
                           {"get,,,,connect", false},
                           {"trace,get,PUT", false}};
  for (const auto* header : disallowed_with_forbidden_methods_headers) {
    for (const auto& test_case : disallowed_values) {
      EXPECT_EQ(test_case.is_safe,
                HttpUtil::IsSafeHeader(header, test_case.value))
          << header << ": " << test_case.value;
    }
  }
}

TEST(HttpUtilTest, HeadersIterator) {
  std::string headers = "foo: 1\t\r\nbar: hello world\r\nbaz: 3 \r\n";

  HttpUtil::HeadersIterator it(headers.begin(), headers.end(), "\r\n");

  ASSERT_TRUE(it.GetNext());
  EXPECT_EQ(std::string("foo"), it.name());
  EXPECT_EQ(std::string("1"), it.values());

  ASSERT_TRUE(it.GetNext());
  EXPECT_EQ(std::string("bar"), it.name());
  EXPECT_EQ(std::string("hello world"), it.values());

  ASSERT_TRUE(it.GetNext());
  EXPECT_EQ(std::string("baz"), it.name());
  EXPECT_EQ(std::string("3"), it.values());

  EXPECT_FALSE(it.GetNext());
}

TEST(HttpUtilTest, HeadersIterator_MalformedLine) {
  std::string headers = "foo: 1\n: 2\n3\nbar: 4";

  HttpUtil::HeadersIterator it(headers.begin(), headers.end(), "\n");

  ASSERT_TRUE(it.GetNext());
  EXPECT_EQ(std::string("foo"), it.name());
  EXPECT_EQ(std::string("1"), it.values());

  ASSERT_TRUE(it.GetNext());
  EXPECT_EQ(std::string("bar"), it.name());
  EXPECT_EQ(std::string("4"), it.values());

  EXPECT_FALSE(it.GetNext());
}

TEST(HttpUtilTest, HeadersIterator_MalformedName) {
  std::string headers = "[ignore me] /: 3\r\n";

  HttpUtil::HeadersIterator it(headers.begin(), headers.end(), "\r\n");

  EXPECT_FALSE(it.GetNext());
}

TEST(HttpUtilTest, HeadersIterator_MalformedNameFollowedByValidLine) {
  std::string headers = "[ignore me] /: 3\r\nbar: 4\n";

  HttpUtil::HeadersIterator it(headers.begin(), headers.end(), "\r\n");

  ASSERT_TRUE(it.GetNext());
  EXPECT_EQ(std::string("bar"), it.name());
  EXPECT_EQ(std::string("4"), it.values());

  EXPECT_FALSE(it.GetNext());
}

TEST(HttpUtilTest, HeadersIterator_AdvanceTo) {
  std::string headers = "foo: 1\r\n: 2\r\n3\r\nbar: 4";

  HttpUtil::HeadersIterator it(headers.begin(), headers.end(), "\r\n");
  EXPECT_TRUE(it.AdvanceTo("foo"));
  EXPECT_EQ("foo", it.name());
  EXPECT_TRUE(it.AdvanceTo("bar"));
  EXPECT_EQ("bar", it.name());
  EXPECT_FALSE(it.AdvanceTo("blat"));
  EXPECT_FALSE(it.GetNext());  // should be at end of headers
}

TEST(HttpUtilTest, HeadersIterator_Reset) {
  std::string headers = "foo: 1\r\n: 2\r\n3\r\nbar: 4";
  HttpUtil::HeadersIterator it(headers.begin(), headers.end(), "\r\n");
  // Search past "foo".
  EXPECT_TRUE(it.AdvanceTo("bar"));
  // Now try advancing to "foo".  This time it should fail since the iterator
  // position is past it.
  EXPECT_FALSE(it.AdvanceTo("foo"));
  it.Reset();
  // Now that we reset the iterator position, we should find 'foo'
  EXPECT_TRUE(it.AdvanceTo("foo"));
}

TEST(HttpUtilTest, ValuesIterator) {
  std::string values = " must-revalidate,   no-cache=\"foo, bar\"\t, private ";

  HttpUtil::ValuesIterator it(values, ',',
                              /*ignore_empty_values=*/true);

  ASSERT_TRUE(it.GetNext());
  EXPECT_EQ("must-revalidate", it.value());

  ASSERT_TRUE(it.GetNext());
  EXPECT_EQ("no-cache=\"foo, bar\"", it.value());

  ASSERT_TRUE(it.GetNext());
  EXPECT_EQ("private", it.value());

  EXPECT_FALSE(it.GetNext());
}

TEST(HttpUtilTest, ValuesIterator_EmptyValues) {
  std::string values = ", foopy , \t ,,,";

  HttpUtil::ValuesIterator it(values, ',', /*ignore_empty_values=*/true);
  ASSERT_TRUE(it.GetNext());
  EXPECT_EQ("foopy", it.value());
  EXPECT_FALSE(it.GetNext());

  HttpUtil::ValuesIterator it_with_empty_values(values, ',',
                                                /*ignore_empty_values=*/false);
  ASSERT_TRUE(it_with_empty_values.GetNext());
  EXPECT_EQ("", it_with_empty_values.value());

  ASSERT_TRUE(it_with_empty_values.GetNext());
  EXPECT_EQ("foopy", it_with_empty_values.value());

  ASSERT_TRUE(it_with_empty_values.GetNext());
  EXPECT_EQ("", it_with_empty_values.value());

  ASSERT_TRUE(it_with_empty_values.GetNext());
  EXPECT_EQ("", it_with_empty_values.value());

  ASSERT_TRUE(it_with_empty_values.GetNext());
  EXPECT_EQ("", it_with_empty_values.value());

  ASSERT_TRUE(it_with_empty_values.GetNext());
  EXPECT_EQ("", it_with_empty_values.value());

  EXPECT_FALSE(it_with_empty_values.GetNext());
}

TEST(HttpUtilTest, ValuesIterator_Blanks) {
  std::string values = " \t ";

  HttpUtil::ValuesIterator it(values, ',', /*ignore_empty_values=*/true);
  EXPECT_FALSE(it.GetNext());

  HttpUtil::ValuesIterator it_with_empty_values(values, ',',
                                                /*ignore_empty_values=*/false);
  ASSERT_TRUE(it_with_empty_values.GetNext());
  EXPECT_EQ("", it_with_empty_values.value());
  EXPECT_FALSE(it_with_empty_values.GetNext());
}

TEST(HttpUtilTest, Unquote) {
  // Replace <backslash> " with ".
  EXPECT_STREQ("xyz\"abc", HttpUtil::Unquote("\"xyz\\\"abc\"").c_str());

  // Replace <backslash> <backslash> with <backslash>
  EXPECT_STREQ("xyz\\abc", HttpUtil::Unquote("\"xyz\\\\abc\"").c_str());
  EXPECT_STREQ("xyz\\\\\\abc",
               HttpUtil::Unquote("\"xyz\\\\\\\\\\\\abc\"").c_str());

  // Replace <backslash> X with X
  EXPECT_STREQ("xyzXabc", HttpUtil::Unquote("\"xyz\\Xabc\"").c_str());

  // Act as identity function on unquoted inputs.
  EXPECT_STREQ("X", HttpUtil::Unquote("X").c_str());
  EXPECT_STREQ("\"", HttpUtil::Unquote("\"").c_str());

  // Allow quotes in the middle of the input.
  EXPECT_STREQ("foo\"bar", HttpUtil::Unquote("\"foo\"bar\"").c_str());

  // Allow the final quote to be escaped.
  EXPECT_STREQ("foo", HttpUtil::Unquote("\"foo\\\"").c_str());
}

TEST(HttpUtilTest, StrictUnquote) {
  std::string out;

  // Replace <backslash> " with ".
  EXPECT_TRUE(HttpUtil::StrictUnquote("\"xyz\\\"abc\"", &out));
  EXPECT_STREQ("xyz\"abc", out.c_str());

  // Replace <backslash> <backslash> with <backslash>.
  EXPECT_TRUE(HttpUtil::StrictUnquote("\"xyz\\\\abc\"", &out));
  EXPECT_STREQ("xyz\\abc", out.c_str());
  EXPECT_TRUE(HttpUtil::StrictUnquote("\"xyz\\\\\\\\\\\\abc\"", &out));
  EXPECT_STREQ("xyz\\\\\\abc", out.c_str());

  // Replace <backslash> X with X.
  EXPECT_TRUE(HttpUtil::StrictUnquote("\"xyz\\Xabc\"", &out));
  EXPECT_STREQ("xyzXabc", out.c_str());

  // Empty quoted string.
  EXPECT_TRUE(HttpUtil::StrictUnquote("\"\"", &out));
  EXPECT_STREQ("", out.c_str());

  // Return false on unquoted inputs.
  EXPECT_FALSE(HttpUtil::StrictUnquote("X", &out));
  EXPECT_FALSE(HttpUtil::StrictUnquote("", &out));

  // Return false on mismatched quotes.
  EXPECT_FALSE(HttpUtil::StrictUnquote("\"", &out));
  EXPECT_FALSE(HttpUtil::StrictUnquote("\"xyz", &out));
  EXPECT_FALSE(HttpUtil::StrictUnquote("\"abc'", &out));

  // Return false on escaped terminal quote.
  EXPECT_FALSE(HttpUtil::StrictUnquote("\"abc\\\"", &out));
  EXPECT_FALSE(HttpUtil::StrictUnquote("\"\\\"", &out));

  // Allow escaped backslash before terminal quote.
  EXPECT_TRUE(HttpUtil::StrictUnquote("\"\\\\\"", &out));
  EXPECT_STREQ("\\", out.c_str());

  // Don't allow single quotes to act as quote marks.
  EXPECT_FALSE(HttpUtil::StrictUnquote("'x\"'", &out));
  EXPECT_TRUE(HttpUtil::StrictUnquote("\"x'\"", &out));
  EXPECT_STREQ("x'", out.c_str());
  EXPECT_FALSE(HttpUtil::StrictUnquote("''", &out));
}

TEST(HttpUtilTest, Quote) {
  EXPECT_STREQ("\"xyz\\\"abc\"", HttpUtil::Quote("xyz\"abc").c_str());

  // Replace <backslash> <backslash> with <backslash>
  EXPECT_STREQ("\"xyz\\\\abc\"", HttpUtil::Quote("xyz\\abc").c_str());

  // Replace <backslash> X with X
  EXPECT_STREQ("\"xyzXabc\"", HttpUtil::Quote("xyzXabc").c_str());
}

TEST(HttpUtilTest, LocateEndOfHeaders) {
  struct {
    const std::string_view input;
    size_t expected_result;
  } tests[] = {
      {"\r\n", std::string::npos},
      {"\n", std::string::npos},
      {"\r", std::string::npos},
      {"foo", std::string::npos},
      {"\r\n\r\n", 4},
      {"foo\r\nbar\r\n\r\n", 12},
      {"foo\nbar\n\n", 9},
      {"foo\r\nbar\r\n\r\njunk", 12},
      {"foo\nbar\n\njunk", 9},
      {"foo\nbar\n\r\njunk", 10},
      {"foo\nbar\r\n\njunk", 10},
  };
  for (const auto& test : tests) {
    size_t eoh = HttpUtil::LocateEndOfHeaders(base::as_byte_span(test.input));
    EXPECT_EQ(test.expected_result, eoh);
  }
}

TEST(HttpUtilTest, LocateEndOfAdditionalHeaders) {
  struct {
    const std::string_view input;
    size_t expected_result;
  } tests[] = {
      {"\r\n", 2},
      {"\n", 1},
      {"\r", std::string::npos},
      {"foo", std::string::npos},
      {"\r\n\r\n", 2},
      {"foo\r\nbar\r\n\r\n", 12},
      {"foo\nbar\n\n", 9},
      {"foo\r\nbar\r\n\r\njunk", 12},
      {"foo\nbar\n\njunk", 9},
      {"foo\nbar\n\r\njunk", 10},
      {"foo\nbar\r\n\njunk", 10},
  };
  for (const auto& test : tests) {
    size_t eoh =
        HttpUtil::LocateEndOfAdditionalHeaders(base::as_byte_span(test.input));
    EXPECT_EQ(test.expected_result, eoh);
  }
}
TEST(HttpUtilTest, AssembleRawHeaders) {
  // clang-format off
  struct {
    const char* const input;  // with '|' representing '\0'
    const char* const expected_result;  // with '\0' changed to '|'
  } tests[] = {
    { "HTTP/1.0 200 OK\r\nFoo: 1\r\nBar: 2\r\n\r\n",
      "HTTP/1.0 200 OK|Foo: 1|Bar: 2||" },

    { "HTTP/1.0 200 OK\nFoo: 1\nBar: 2\n\n",
      "HTTP/1.0 200 OK|Foo: 1|Bar: 2||" },

    // Valid line continuation (single SP).
    {
      "HTTP/1.0 200 OK\n"
      "Foo: 1\n"
      " continuation\n"
      "Bar: 2\n\n",

      "HTTP/1.0 200 OK|"
      "Foo: 1 continuation|"
      "Bar: 2||"
    },

    // Valid line continuation (single HT).
    {
      "HTTP/1.0 200 OK\n"
      "Foo: 1\n"
      "\tcontinuation\n"
      "Bar: 2\n\n",

      "HTTP/1.0 200 OK|"
      "Foo: 1 continuation|"
      "Bar: 2||"
    },

    // Valid line continuation (multiple SP).
    {
      "HTTP/1.0 200 OK\n"
      "Foo: 1\n"
      "   continuation\n"
      "Bar: 2\n\n",

      "HTTP/1.0 200 OK|"
      "Foo: 1 continuation|"
      "Bar: 2||"
    },

    // Valid line continuation (multiple HT).
    {
      "HTTP/1.0 200 OK\n"
      "Foo: 1\n"
      "\t\t\tcontinuation\n"
      "Bar: 2\n\n",

      "HTTP/1.0 200 OK|"
      "Foo: 1 continuation|"
      "Bar: 2||"
    },

    // Valid line continuation (mixed HT, SP).
    {
      "HTTP/1.0 200 OK\n"
      "Foo: 1\n"
      " \t \t continuation\n"
      "Bar: 2\n\n",

      "HTTP/1.0 200 OK|"
      "Foo: 1 continuation|"
      "Bar: 2||"
    },

    // Valid multi-line continuation
    {
      "HTTP/1.0 200 OK\n"
      "Foo: 1\n"
      " continuation1\n"
      "\tcontinuation2\n"
      "  continuation3\n"
      "Bar: 2\n\n",

      "HTTP/1.0 200 OK|"
      "Foo: 1 continuation1 continuation2 continuation3|"
      "Bar: 2||"
    },

    // Continuation of quoted value.
    // This is different from what Firefox does, since it
    // will preserve the LWS.
    {
      "HTTP/1.0 200 OK\n"
      "Etag: \"34534-d3\n"
      "    134q\"\n"
      "Bar: 2\n\n",

      "HTTP/1.0 200 OK|"
      "Etag: \"34534-d3 134q\"|"
      "Bar: 2||"
    },

    // Valid multi-line continuation, full LWS lines
    {
      "HTTP/1.0 200 OK\n"
      "Foo: 1\n"
      "         \n"
      "\t\t\t\t\n"
      "\t  continuation\n"
      "Bar: 2\n\n",

      // One SP per continued line = 3.
      "HTTP/1.0 200 OK|"
      "Foo: 1   continuation|"
      "Bar: 2||"
    },

    // Valid multi-line continuation, all LWS
    {
      "HTTP/1.0 200 OK\n"
      "Foo: 1\n"
      "         \n"
      "\t\t\t\t\n"
      "\t  \n"
      "Bar: 2\n\n",

      // One SP per continued line = 3.
      "HTTP/1.0 200 OK|"
      "Foo: 1   |"
      "Bar: 2||"
    },

    // Valid line continuation (No value bytes in first line).
    {
      "HTTP/1.0 200 OK\n"
      "Foo:\n"
      " value\n"
      "Bar: 2\n\n",

      "HTTP/1.0 200 OK|"
      "Foo: value|"
      "Bar: 2||"
    },

    // Not a line continuation (can't continue status line).
    {
      "HTTP/1.0 200 OK\n"
      " Foo: 1\n"
      "Bar: 2\n\n",

      "HTTP/1.0 200 OK|"
      " Foo: 1|"
      "Bar: 2||"
    },

    // Not a line continuation (can't continue status line).
    {
      "HTTP/1.0\n"
      " 200 OK\n"
      "Foo: 1\n"
      "Bar: 2\n\n",

      "HTTP/1.0|"
      " 200 OK|"
      "Foo: 1|"
      "Bar: 2||"
    },

    // Not a line continuation (can't continue status line).
    {
      "HTTP/1.0 404\n"
      " Not Found\n"
      "Foo: 1\n"
      "Bar: 2\n\n",

      "HTTP/1.0 404|"
      " Not Found|"
      "Foo: 1|"
      "Bar: 2||"
    },

    // Unterminated status line.
    {
      "HTTP/1.0 200 OK",

      "HTTP/1.0 200 OK||"
    },

    // Single terminated, with headers
    {
      "HTTP/1.0 200 OK\n"
      "Foo: 1\n"
      "Bar: 2\n",

      "HTTP/1.0 200 OK|"
      "Foo: 1|"
      "Bar: 2||"
    },

    // Not terminated, with headers
    {
      "HTTP/1.0 200 OK\n"
      "Foo: 1\n"
      "Bar: 2",

      "HTTP/1.0 200 OK|"
      "Foo: 1|"
      "Bar: 2||"
    },

    // Not a line continuation (VT)
    {
      "HTTP/1.0 200 OK\n"
      "Foo: 1\n"
      "\vInvalidContinuation\n"
      "Bar: 2\n\n",

      "HTTP/1.0 200 OK|"
      "Foo: 1|"
      "\vInvalidContinuation|"
      "Bar: 2||"
    },

    // Not a line continuation (formfeed)
    {
      "HTTP/1.0 200 OK\n"
      "Foo: 1\n"
      "\fInvalidContinuation\n"
      "Bar: 2\n\n",

      "HTTP/1.0 200 OK|"
      "Foo: 1|"
      "\fInvalidContinuation|"
      "Bar: 2||"
    },

    // Not a line continuation -- can't continue header names.
    {
      "HTTP/1.0 200 OK\n"
      "Serv\n"
      " er: Apache\n"
      "\tInvalidContinuation\n"
      "Bar: 2\n\n",

      "HTTP/1.0 200 OK|"
      "Serv|"
      " er: Apache|"
      "\tInvalidContinuation|"
      "Bar: 2||"
    },

    // Not a line continuation -- no value to continue.
    {
      "HTTP/1.0 200 OK\n"
      "Foo: 1\n"
      "garbage\n"
      "  not-a-continuation\n"
      "Bar: 2\n\n",

      "HTTP/1.0 200 OK|"
      "Foo: 1|"
      "garbage|"
      "  not-a-continuation|"
      "Bar: 2||",
    },

    // Not a line continuation -- no valid name.
    {
      "HTTP/1.0 200 OK\n"
      ": 1\n"
      "  garbage\n"
      "Bar: 2\n\n",

      "HTTP/1.0 200 OK|"
      ": 1|"
      "  garbage|"
      "Bar: 2||",
    },

    // Not a line continuation -- no valid name (whitespace)
    {
      "HTTP/1.0 200 OK\n"
      "   : 1\n"
      "  garbage\n"
      "Bar: 2\n\n",

      "HTTP/1.0 200 OK|"
      "   : 1|"
      "  garbage|"
      "Bar: 2||",
    },

    // Embed NULLs in the status line. They should not be understood
    // as line separators.
    {
      "HTTP/1.0 200 OK|Bar2:0|Baz2:1\r\nFoo: 1\r\nBar: 2\r\n\r\n",
      "HTTP/1.0 200 OKBar2:0Baz2:1|Foo: 1|Bar: 2||"
    },

    // Embed NULLs in a header line. They should not be understood as
    // line separators.
    {
      "HTTP/1.0 200 OK\nFoo: 1|Foo2: 3\nBar: 2\n\n",
      "HTTP/1.0 200 OK|Foo: 1Foo2: 3|Bar: 2||"
    },

    // The embedded NUL at the start of the line (before "Blah:") should not be
    // interpreted as LWS (as that would mistake it for a header line
    // continuation).
    {
      "HTTP/1.0 200 OK\n"
      "Foo: 1\n"
      "|Blah: 3\n"
      "Bar: 2\n\n",
      "HTTP/1.0 200 OK|Foo: 1|Blah: 3|Bar: 2||"
    },
  };
  // clang-format on
  for (const auto& test : tests) {
    std::string input = test.input;
    std::replace(input.begin(), input.end(), '|', '\0');
    std::string raw = HttpUtil::AssembleRawHeaders(input);
    std::replace(raw.begin(), raw.end(), '\0', '|');
    EXPECT_EQ(test.expected_result, raw);
  }
}

// Test SpecForRequest().
TEST(HttpUtilTest, RequestUrlSanitize) {
  struct {
    const char* const url;
    const char* const expected_spec;
  } tests[] = {
    { // Check that #hash is removed.
      "http://www.google.com:78/foobar?query=1#hash",
      "http://www.google.com:78/foobar?query=1",
    },
    { // The reference may itself contain # -- strip all of it.
      "http://192.168.0.1?query=1#hash#10#11#13#14",
      "http://192.168.0.1/?query=1",
    },
    { // Strip username/password.
      "http://user:pass@google.com",
      "http://google.com/",
    },
    { // https scheme
      "https://www.google.com:78/foobar?query=1#hash",
      "https://www.google.com:78/foobar?query=1",
    },
    { // WebSocket's ws scheme
      "ws://www.google.com:78/foobar?query=1#hash",
      "ws://www.google.com:78/foobar?query=1",
    },
    { // WebSocket's wss scheme
      "wss://www.google.com:78/foobar?query=1#hash",
      "wss://www.google.com:78/foobar?query=1",
    }
  };
  for (size_t i = 0; i < std::size(tests); ++i) {
    SCOPED_TRACE(i);

    GURL url(GURL(tests[i].url));
    std::string expected_spec(tests[i].expected_spec);

    EXPECT_EQ(expected_spec, HttpUtil::SpecForRequest(url));
  }
}

TEST(HttpUtilTest, GenerateAcceptLanguageHeader) {
  std::string header = HttpUtil::GenerateAcceptLanguageHeader("");
  EXPECT_TRUE(header.empty());

  header = HttpUtil::GenerateAcceptLanguageHeader("es");
  EXPECT_EQ(std::string("es"), header);

  header = HttpUtil::GenerateAcceptLanguageHeader("en-US,fr,de");
  EXPECT_EQ(std::string("en-US,fr;q=0.9,de;q=0.8"), header);

  header = HttpUtil::GenerateAcceptLanguageHeader("en-US,fr,de,ko,zh-CN,ja");
  EXPECT_EQ(
      std::string("en-US,fr;q=0.9,de;q=0.8,ko;q=0.7,zh-CN;q=0.6,ja;q=0.5"),
      header);
}

// HttpResponseHeadersTest.GetMimeType also tests ParseContentType.
TEST(HttpUtilTest, ParseContentType) {
  // clang-format off
  const struct {
    const char* const content_type;
    const char* const expected_mime_type;
    const char* const expected_charset;
    const bool expected_had_charset;
    const char* const expected_boundary;
  } tests[] = {
    { "text/html",
      "text/html",
      "",
      false,
      ""
    },
    { "text/html;",
      "text/html",
      "",
      false,
      ""
    },
    { "text/html; charset=utf-8",
      "text/html",
      "utf-8",
      true,
      ""
    },
    // Parameter name is "charset ", not "charset".  See https://crbug.com/772834.
    { "text/html; charset =utf-8",
      "text/html",
      "",
      false,
      ""
    },
    { "text/html; charset= utf-8",
      "text/html",
      "utf-8",
      true,
      ""
    },
    { "text/html; charset=utf-8 ",
      "text/html",
      "utf-8",
      true,
      ""
    },

    { "text/html; boundary=\"WebKit-ada-df-dsf-adsfadsfs\"",
      "text/html",
      "",
      false,
      "WebKit-ada-df-dsf-adsfadsfs"
    },
    // Parameter name is "boundary ", not "boundary".
    // See https://crbug.com/772834.
    { "text/html; boundary =\"WebKit-ada-df-dsf-adsfadsfs\"",
      "text/html",
      "",
      false,
      ""
    },
    // Parameter value includes leading space.  See https://crbug.com/772834.
    { "text/html; boundary= \"WebKit-ada-df-dsf-adsfadsfs\"",
      "text/html",
      "",
      false,
      "WebKit-ada-df-dsf-adsfadsfs"
    },
    // Parameter value includes leading space.  See https://crbug.com/772834.
    { "text/html; boundary= \"WebKit-ada-df-dsf-adsfadsfs\"   ",
      "text/html",
      "",
      false,
      "WebKit-ada-df-dsf-adsfadsfs"
    },
    { "text/html; boundary=\"WebKit-ada-df-dsf-adsfadsfs  \"",
      "text/html",
      "",
      false,
      "WebKit-ada-df-dsf-adsfadsfs"
    },
    { "text/html; boundary=WebKit-ada-df-dsf-adsfadsfs",
      "text/html",
      "",
      false,
      "WebKit-ada-df-dsf-adsfadsfs"
    },
    { "text/html; charset",
      "text/html",
      "",
      false,
      ""
    },
    { "text/html; charset=",
      "text/html",
      "",
      false,
      ""
    },
    { "text/html; charset= ",
      "text/html",
      "",
      false,
      ""
    },
    { "text/html; charset= ;",
      "text/html",
      "",
      false,
      ""
    },
    // Empty quoted strings are allowed.
    { "text/html; charset=\"\"",
      "text/html",
      "",
      true,
      ""
    },

    // Leading and trailing whitespace in quotes is trimmed.
    { "text/html; charset=\" \"",
      "text/html",
      "",
      true,
      ""
    },
    { "text/html; charset=\" foo \"",
      "text/html",
      "foo",
      true,
      ""
    },

    // With multiple values, should use the first one.
    { "text/html; charset=foo; charset=utf-8",
      "text/html",
      "foo",
      true,
      ""
    },
    { "text/html; charset; charset=; charset=utf-8",
      "text/html",
      "utf-8",
      true,
      ""
    },
    { "text/html; charset=utf-8; charset=; charset",
      "text/html",
      "utf-8",
      true,
      ""
    },
    { "text/html; boundary=foo; boundary=bar",
      "text/html",
      "",
      false,
      "foo"
    },

    // Stray quotes ignored.
    { "text/html; \"; \"\"; charset=utf-8",
      "text/html",
      "utf-8",
      true,
      ""
    },
    // Non-leading quotes kept as-is.
    { "text/html; charset=u\"tf-8\"",
      "text/html",
      "u\"tf-8\"",
      true,
      ""
    },
    { "text/html; charset=\"utf-8\"",
      "text/html",
      "utf-8",
      true,
      ""
    },
    // No closing quote.
    { "text/html; charset=\"utf-8",
      "text/html",
      "utf-8",
      true,
      ""
    },
    // Check that \ is treated as an escape character.
    { "text/html; charset=\"\\utf\\-\\8\"",
      "text/html",
      "utf-8",
      true,
      ""
    },
    // More interseting escape character test - test escaped backslash, escaped
    // quote, and backslash at end of input in unterminated quoted string.
    { "text/html; charset=\"\\\\\\\"\\",
      "text/html",
      "\\\"\\",
      true,
      ""
    },
    // Check quoted semicolon.
    { "text/html; charset=\";charset=utf-8;\"",
      "text/html",
      ";charset=utf-8;",
      true,
      ""
    },
    // Unclear if this one should just return utf-8 or not.
    { "text/html; charset= \"utf-8\"",
      "text/html",
      "utf-8",
      true,
      ""
    },
    // Regression test for https://crbug.com/772350:
    // Single quotes are not delimiters but must be treated as part of charset.
    { "text/html; charset='utf-8'",
      "text/html",
      "'utf-8'",
      true,
      ""
    },
    // Empty subtype should be accepted.
    { "text/",
      "text/",
      "",
      false,
      ""
    },
    // "*/*" is ignored unless it has params, or is not an exact match.
    { "*/*", "", "", false, "" },
    { "*/*; charset=utf-8", "*/*", "utf-8", true, "" },
    { "*/* ", "*/*", "", false, "" },
    // Regression test for https://crbug.com/1326529
    { "teXT/html", "text/html", "", false, ""},
    // TODO(abarth): Add more interesting test cases.
  };
  // clang-format on
  for (const auto& test : tests) {
    std::string mime_type;
    std::string charset;
    bool had_charset = false;
    std::string boundary;
    HttpUtil::ParseContentType(test.content_type, &mime_type, &charset,
                               &had_charset, &boundary);
    EXPECT_EQ(test.expected_mime_type, mime_type)
        << "content_type=" << test.content_type;
    EXPECT_EQ(test.expected_charset, charset)
        << "content_type=" << test.content_type;
    EXPECT_EQ(test.expected_had_charset, had_charset)
        << "content_type=" << test.content_type;
    EXPECT_EQ(test.expected_boundary, boundary)
        << "content_type=" << test.content_type;
  }
}

TEST(HttpUtilTest, ParseContentResetCharset) {
  std::string mime_type;
  std::string charset;
  bool had_charset = false;
  std::string boundary;

  // Set mime (capitalization should be ignored), but not charset.
  HttpUtil::ParseContentType("Text/Html", &mime_type, &charset, &had_charset,
                             &boundary);
  EXPECT_EQ("text/html", mime_type);
  EXPECT_EQ("", charset);
  EXPECT_FALSE(had_charset);

  // The same mime, add charset.
  HttpUtil::ParseContentType("tExt/hTml;charset=utf-8", &mime_type, &charset,
                             &had_charset, &boundary);
  EXPECT_EQ("text/html", mime_type);
  EXPECT_EQ("utf-8", charset);
  EXPECT_TRUE(had_charset);

  // The same mime (different capitalization), but no charset - should not clear
  // charset.
  HttpUtil::ParseContentType("teXt/htMl", &mime_type, &charset, &had_charset,
                             &boundary);
  EXPECT_EQ("text/html", mime_type);
  EXPECT_EQ("utf-8", charset);
  EXPECT_TRUE(had_charset);

  // A different mime will clear charset.
  HttpUtil::ParseContentType("texT/plaiN", &mime_type, &charset, &had_charset,
                             &boundary);
  EXPECT_EQ("text/plain", mime_type);
  EXPECT_EQ("", charset);
  EXPECT_TRUE(had_charset);
}

TEST(HttpUtilTest, ParseContentRangeHeader) {
  const struct {
    const char* const content_range_header_spec;
    bool expected_return_value;
    int64_t expected_first_byte_position;
    int64_t expected_last_byte_position;
    int64_t expected_instance_length;
  } tests[] = {
      {"", false, -1, -1, -1},
      {"megabytes 0-10/50", false, -1, -1, -1},
      {"0-10/50", false, -1, -1, -1},
      {"Bytes 0-50/51", true, 0, 50, 51},
      {"bytes 0-50/51", true, 0, 50, 51},
      {"bytes\t0-50/51", false, -1, -1, -1},
      {"    bytes 0-50/51", true, 0, 50, 51},
      {"    bytes    0    -   50  \t / \t51", true, 0, 50, 51},
      {"bytes 0\t-\t50\t/\t51\t", true, 0, 50, 51},
      {"  \tbytes\t\t\t 0\t-\t50\t/\t51\t", true, 0, 50, 51},
      {"\t   bytes \t  0    -   50   /   5   1", false, -1, -1, -1},
      {"\t   bytes \t  0    -   5 0   /   51", false, -1, -1, -1},
      {"bytes 50-0/51", false, -1, -1, -1},
      {"bytes * /*", false, -1, -1, -1},
      {"bytes *   /    *   ", false, -1, -1, -1},
      {"bytes 0-50/*", false, -1, -1, -1},
      {"bytes 0-50  /    * ", false, -1, -1, -1},
      {"bytes 0-10000000000/10000000001", true, 0, 10000000000ll,
       10000000001ll},
      {"bytes 0-10000000000/10000000000", false, -1, -1, -1},
      // 64 bit wraparound.
      {"bytes 0 - 9223372036854775807 / 100", false, -1, -1, -1},
      // 64 bit wraparound.
      {"bytes 0 - 100 / -9223372036854775808", false, -1, -1, -1},
      {"bytes */50", false, -1, -1, -1},
      {"bytes 0-50/10", false, -1, -1, -1},
      {"bytes 40-50/45", false, -1, -1, -1},
      {"bytes 0-50/-10", false, -1, -1, -1},
      {"bytes 0-0/1", true, 0, 0, 1},
      {"bytes 0-40000000000000000000/40000000000000000001", false, -1, -1, -1},
      {"bytes 1-/100", false, -1, -1, -1},
      {"bytes -/100", false, -1, -1, -1},
      {"bytes -1/100", false, -1, -1, -1},
      {"bytes 0-1233/*", false, -1, -1, -1},
      {"bytes -123 - -1/100", false, -1, -1, -1},
  };

  for (const auto& test : tests) {
    int64_t first_byte_position, last_byte_position, instance_length;
    EXPECT_EQ(test.expected_return_value,
              HttpUtil::ParseContentRangeHeaderFor206(
                  test.content_range_header_spec, &first_byte_position,
                  &last_byte_position, &instance_length))
        << test.content_range_header_spec;
    EXPECT_EQ(test.expected_first_byte_position, first_byte_position)
        << test.content_range_header_spec;
    EXPECT_EQ(test.expected_last_byte_position, last_byte_position)
        << test.content_range_header_spec;
    EXPECT_EQ(test.expected_instance_length, instance_length)
        << test.content_range_header_spec;
  }
}

TEST(HttpUtilTest, ParseRetryAfterHeader) {
  base::Time::Exploded now_exploded = {2014, 11, 4, 5, 22, 39, 30, 0};
  base::Time now;
  EXPECT_TRUE(base::Time::FromUTCExploded(now_exploded, &now));

  base::Time::Exploded later_exploded = {2015, 1, 5, 1, 12, 34, 56, 0};
  base::Time later;
  EXPECT_TRUE(base::Time::FromUTCExploded(later_exploded, &later));

  const struct {
    const char* retry_after_string;
    bool expected_return_value;
    base::TimeDelta expected_retry_after;
  } tests[] = {{"", false, base::TimeDelta()},
               {"-3", false, base::TimeDelta()},
               {"-2", false, base::TimeDelta()},
               {"-1", false, base::TimeDelta()},
               {"+0", false, base::TimeDelta()},
               {"+1", false, base::TimeDelta()},
               {"0", true, base::Seconds(0)},
               {"1", true, base::Seconds(1)},
               {"2", true, base::Seconds(2)},
               {"3", true, base::Seconds(3)},
               {"60", true, base::Seconds(60)},
               {"3600", true, base::Seconds(3600)},
               {"86400", true, base::Seconds(86400)},
               {"Thu, 1 Jan 2015 12:34:56 GMT", true, later - now},
               {"Mon, 1 Jan 1900 12:34:56 GMT", false, base::TimeDelta()}};

  for (size_t i = 0; i < std::size(tests); ++i) {
    base::TimeDelta retry_after;
    bool return_value = HttpUtil::ParseRetryAfterHeader(
        tests[i].retry_after_string, now, &retry_after);
    EXPECT_EQ(tests[i].expected_return_value, return_value)
        << "Test case " << i << ": expected " << tests[i].expected_return_value
        << " but got " << return_value << ".";
    if (tests[i].expected_return_value && return_value) {
      EXPECT_EQ(tests[i].expected_retry_after, retry_after)
          << "Test case " << i << ": expected "
          << tests[i].expected_retry_after.InSeconds() << "s but got "
          << retry_after.InSeconds() << "s.";
    }
  }
}

TES
"""


```