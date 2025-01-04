Response:
Let's break down the thought process for analyzing this code snippet and answering the prompt.

1. **Understand the Goal:** The request asks for a functional summary of a C++ unit test file (`http_response_headers_unittest.cc`) within the Chromium networking stack. It also asks for connections to JavaScript, examples with inputs/outputs, common user/programming errors, debugging hints, and a final summarization. The "Part 2 of 3" indicates this is part of a larger context, but we should treat this snippet as a self-contained unit for now.

2. **Identify the Core Subject:** The filename `http_response_headers_unittest.cc` immediately tells us the tests are focused on the `HttpResponseHeaders` class. This class likely deals with parsing, manipulating, and interpreting HTTP response headers.

3. **Scan for Key Test Structures:**  Look for common C++ testing patterns. The code uses Google Test (`TEST_`, `TEST_P`, `INSTANTIATE_TEST_SUITE_P`, `EXPECT_EQ`). The `INSTANTIATE_TEST_SUITE_P` lines are particularly important because they link test case names (like `RequiresValidationTest`, `UpdateTest`) to data structures holding test inputs and expected outputs.

4. **Analyze Each Test Suite:**  Go through each test suite and its associated data structures:

    * **`RequiresValidationTest`:**  The `requires_validation_tests` array holds pairs of HTTP header strings and an enum `VALIDATION_NONE`, `VALIDATION_SYNCHRONOUS`, or `VALIDATION_ASYNCHRONOUS`. The test itself checks if `RequiresValidation()` returns the expected validation type. This suggests the `HttpResponseHeaders` class has logic to determine if a cached response needs revalidation based on its headers (like `Cache-Control`, `Expires`, `Pragma`).

    * **`UpdateTest`:** The `update_tests` array contains `orig_headers`, `new_headers`, and `expected_headers`. The `Update()` test method takes an initial `HttpResponseHeaders` object and updates it with another. The test verifies that the resulting headers match the `expected_headers`. This tells us the `HttpResponseHeaders` class has an `Update()` method, likely used for handling 304 Not Modified responses.

    * **`EnumerateHeaderLinesTest`:** The `enumerate_header_tests` array holds HTTP header strings and `expected_lines`. The `EnumerateHeaderLines()` test iterates through the headers, extracting name-value pairs, and compares the concatenated result to `expected_lines`. This confirms a mechanism to access individual header lines.

    * **`IsRedirectTest`:**  The `is_redirect_tests` array contains headers, an expected `location`, and a boolean `is_redirect`. The `IsRedirect()` test checks if the `HttpResponseHeaders` correctly identifies redirects and extracts the `Location` header.

    * **`HasStorageAccessRetryTest`:** This suite deals with the `Activate-Storage-Access` header. The tests check if `HasStorageAccessRetryHeader()` returns the correct boolean based on the header's presence and potentially an expected origin.

    * **`GetContentLengthTest`:**  The `content_length_tests` array provides headers and expected content lengths. The `GetContentLength()` test verifies the parsing of the `Content-Length` header.

    * **`ContentRangeTest`:** This suite tests the parsing of the `Content-Range` header for 206 Partial Content responses. It checks the extraction of first byte, last byte, and instance size.

    * **`IsKeepAliveTest`:** The `keepalive_tests` array tests the logic for determining if a connection should be kept alive based on the `Connection` and `Proxy-Connection` headers and the HTTP version.

    * **`HasStrongValidatorsTest`:**  This checks if the response has "strong" cache validators (like `ETag` in HTTP/1.1 or `Last-Modified` with a recent `Date`).

    * **Individual `HttpResponseHeadersTest` tests:** These test specific scenarios like the absence/presence of validators and handling of empty or comma-separated header values using `GetNormalizedHeader`. The `AddHeader` and `SetHeader` tests demonstrate header manipulation methods. `TryToCreateWithNul` tests for handling invalid input.

    * **`RemoveHeaderTest`, `RemoveHeadersTest`, `RemoveIndividualHeaderTest`:** These test the functionality of removing headers by name or name-value pair.

5. **Connect to JavaScript (if applicable):**  Consider how the tested functionality relates to web browsers and JavaScript. Caching, redirects, and content length are all concepts that directly affect how web pages load and how JavaScript interacts with network resources. Examples can be crafted around `fetch()` API or browser caching behavior.

6. **Construct Input/Output Examples:** For each test suite (or a representative subset), devise simple input header strings and the expected output or behavior of the `HttpResponseHeaders` methods being tested.

7. **Identify Common Errors:** Think about common mistakes developers make when dealing with HTTP headers. Misinterpreting cache directives, incorrect handling of redirects, and forgetting about content length are good candidates.

8. **Provide Debugging Hints:**  Relate user actions (like clicking a link or refreshing a page) to the point where this code might be involved. Explain how these tests serve as debugging aids.

9. **Synthesize the Summary:** Combine the analysis of each test suite into a concise overview of the file's purpose. Focus on the core functionalities being tested.

10. **Address Part 2:**  Specifically address the "Part 2" instruction and reiterate the main functionalities covered in this code snippet.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this file only tests parsing.
* **Correction:**  The `UpdateTest`, `AddHeader`, `SetHeader`, and removal tests show that the file also covers *manipulation* of headers.
* **Initial thought:**  The JavaScript connection might be weak.
* **Refinement:** Focus on core web concepts that both C++ networking code and JavaScript (through browser APIs) interact with directly, like caching and redirects. Be specific with API examples.
* **Initial thought:**  Just list the tests.
* **Refinement:** Group the tests by functionality and explain *why* these functionalities are important in the context of HTTP processing. The request asks for the *function* of the file.
这是目录为`net/http/http_response_headers_unittest.cc`的 Chromium 网络栈源代码文件的第二部分，它延续了第一部分的功能，主要集中在对 `HttpResponseHeaders` 类的各种方法的单元测试。该类的作用是封装 HTTP 响应头，并提供解析、访问和操作这些头信息的功能。

**本部分 (第 2 部分) 的主要功能归纳：**

* **缓存验证需求测试 (`RequiresValidationTest`):**
    * 测试 `RequiresValidation()` 方法，该方法根据响应头（例如 `Cache-Control`, `Expires`, `Pragma`）判断是否需要对缓存的响应进行重新验证。
    * 测试了各种缓存指令的组合，以及它们如何影响同步或异步重新验证的需求。

* **更新测试 (`UpdateTest`):**
    * 测试 `Update()` 方法，该方法用于处理接收到 304 Not Modified 响应时，用新响应头更新现有响应头。
    * 验证了在更新过程中，哪些头部会被替换，哪些会被保留，以及特定头部（如安全相关的头部）的处理方式。

* **枚举头部行测试 (`EnumerateHeaderLinesTest`):**
    * 测试 `EnumerateHeaderLines()` 方法，该方法用于迭代访问所有头部行的名称和值。
    * 验证了可以正确地遍历包含重复名称的头部。

* **重定向测试 (`IsRedirectTest`):**
    * 测试 `IsRedirect()` 方法，该方法判断响应是否为重定向，并提取重定向的 `Location` URL。
    * 涵盖了各种有效的和无效的 `Location` 头部，包括包含特殊字符的情况。

* **存储访问重试头部测试 (`HasStorageAccessRetryTest`):**
    * 测试 `HasStorageAccessRetryHeader()` 方法，该方法检查是否存在 `Activate-Storage-Access: retry` 头部，并验证可选的 `allowed-origin` 参数是否匹配。

* **获取内容长度测试 (`GetContentLengthTest`):**
    * 测试 `GetContentLength()` 方法，该方法解析并返回 `Content-Length` 头部的值。
    * 涵盖了各种有效和无效的 `Content-Length` 头部格式，包括空格、非法字符、以及溢出的情况。

* **获取内容范围测试 (`ContentRangeTest`):**
    * 测试 `GetContentRangeFor206()` 方法，该方法解析 206 Partial Content 响应中的 `Content-Range` 头部，提取起始字节位置、结束字节位置和实例总大小。

* **Keep-Alive 连接测试 (`IsKeepAliveTest`):**
    * 测试 `IsKeepAlive()` 方法，该方法根据 `Connection` 和 `Proxy-Connection` 头部以及 HTTP 版本判断是否应该保持连接活跃。
    * 涵盖了 HTTP/1.0 和 HTTP/1.1 的各种情况，包括 `close` 和 `keep-alive` 指令的组合和优先级。

* **强校验器测试 (`HasStrongValidatorsTest`):**
    * 测试 `HasStrongValidators()` 方法，该方法判断响应是否包含“强”缓存校验器（例如，HTTP/1.1 的 `ETag` 或包含有效 `Date` 的 `Last-Modified`）。
    * 同时隐式测试了 `HasValidators()` 方法。

* **通用的校验器测试 (`HttpResponseHeadersTest` 中的独立测试):**
    * 针对 `HasValidators()` 方法的更具体的测试用例，涵盖了存在 `ETag`、`Last-Modified` 和弱 `ETag` 的情况。

* **获取规范化头部测试 (`GetNormalizedHeaderWithEmptyValues`, `GetNormalizedHeaderWithCommas`):**
    * 测试 `GetNormalizedHeader()` 方法，该方法返回指定头部的值，并将多个同名头部的值连接成一个逗号分隔的字符串。
    * 特别关注了处理空值和逗号的情况。

* **添加头部测试 (`AddHeader`):**
    * 测试 `AddHeader()` 方法，该方法向响应头添加一个新的头部行。
    * 验证了可以添加具有相同名称的多个头部。

* **设置头部测试 (`SetHeader`):**
    * 测试 `SetHeader()` 方法，该方法设置指定名称的头部，如果存在则替换其值。

* **尝试创建包含 NULL 字符的头部测试 (`TryToCreateWithNul`):**
    * 测试 `TryToCreate()` 方法在处理包含 NULL 字符的头部字符串时的行为，预期会创建失败。

* **删除头部测试 (`RemoveHeaderTest`, `RemoveHeadersTest`, `RemoveIndividualHeaderTest`):**
    * 测试了多种删除头部的方法：
        * `RemoveHeader()`: 删除所有具有指定名称的头部。
        * `RemoveHeaders()`: 删除一组指定名称的头部。
        * `RemoveHeaderLine()`: 删除具有指定名称和值的特定头部行。

**与 JavaScript 的关系举例说明：**

本部分测试的功能与 JavaScript 在浏览器中的缓存、网络请求和资源加载密切相关。

* **缓存验证：** 当 JavaScript 使用 `fetch` API 或浏览器加载资源时，`HttpResponseHeaders` 中的缓存指令（例如 `Cache-Control`, `Expires`）会影响浏览器如何缓存这些资源。如果 `RequiresValidation()` 返回需要验证，浏览器可能会发送条件请求（带有 `If-None-Match` 或 `If-Modified-Since` 头部）。

    ```javascript
    // JavaScript 发起一个 fetch 请求
    fetch('https://example.com/data.json')
      .then(response => {
        if (response.ok) {
          return response.json();
        } else if (response.status === 304) {
          // 使用缓存的数据，因为服务器返回 304 Not Modified
          console.log('使用缓存数据');
        }
      });
    ```

* **重定向：** 当服务器返回 301、302、307 或 308 状态码时，`IsRedirect()` 方法用于解析 `Location` 头部，指示浏览器或 `fetch` API 应该重定向到哪个 URL。JavaScript 可以通过 `response.redirected` 属性来判断请求是否发生了重定向。

    ```javascript
    fetch('https://example.com/old-url')
      .then(response => {
        console.log('是否重定向:', response.redirected);
        console.log('最终 URL:', response.url);
      });
    ```

* **内容长度：** `GetContentLength()` 返回的内容长度可以帮助 JavaScript 预估下载进度，尤其是在处理大文件下载时。

    ```javascript
    fetch('https://example.com/large-file.zip')
      .then(response => {
        const contentLength = response.headers.get('Content-Length');
        console.log('文件大小:', contentLength);
        // ... 可以使用 ReadableStream 来处理下载进度
      });
    ```

* **Keep-Alive：**  `IsKeepAlive()` 的结果影响浏览器是否会为后续请求重用相同的 TCP 连接，这直接影响 JavaScript 发起多个请求时的性能。

**逻辑推理的假设输入与输出举例：**

**假设输入 (用于 `RequiresValidationTest`):**

```
HTTP/1.1 200 OK
Date: Wed, 28 Nov 2007 00:40:11 GMT
Cache-Control: max-age=60
```

**假设当前时间:** `Wed, 28 Nov 2007 00:41:00 GMT` (晚于 Date 头部 59 秒)

**输出:** `RequiresValidation()` 方法应该返回 `VALIDATION_NONE`，因为 `max-age` 尚未过期。

**假设输入 (用于 `IsRedirectTest`):**

```
HTTP/1.1 302 Found
Location: https://new.example.com/
```

**输出:** `IsRedirect()` 方法应该返回 `true`，并且 `location` 参数会被设置为 `"https://new.example.com/"`。

**用户或编程常见的使用错误举例说明：**

* **错误地假设缓存策略:** 开发者可能会错误地认为设置了 `Expires` 头部就能保证资源被缓存，而忽略了 `Cache-Control` 可能会覆盖 `Expires`。例如，如果同时设置了 `Expires` 和 `Cache-Control: no-cache`，则资源仍然需要重新验证。

* **重定向循环:**  服务器配置错误可能导致重定向循环。例如，URL A 重定向到 URL B，URL B 又重定向回 URL A。浏览器或网络库需要检测并阻止这种无限循环。

* **内容长度不匹配:** 服务器发送的 `Content-Length` 头部与实际响应体的大小不一致。这会导致数据截断或客户端解析错误。

* **Keep-Alive 连接管理不当:**  在某些情况下，服务器可能会过早关闭 Keep-Alive 连接，导致客户端请求失败。反之，客户端也需要合理地管理连接，避免资源浪费。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户在浏览器地址栏输入 URL 并访问一个网页。**
2. **浏览器向服务器发送 HTTP 请求。**
3. **服务器返回 HTTP 响应，其中包括响应头。**
4. **Chromium 网络栈接收到响应头，并创建 `HttpResponseHeaders` 对象来存储这些信息。**
5. **如果响应需要进行缓存决策，`RequiresValidation()` 方法会被调用，根据响应头中的缓存指令判断是否需要重新验证。**
6. **如果响应是 304 Not Modified，`Update()` 方法会被调用，用新的头部信息更新缓存的响应头。**
7. **如果响应是重定向，`IsRedirect()` 方法会被调用，提取 `Location` 头部，浏览器会发起新的请求。**
8. **如果 JavaScript 代码使用 `fetch` API 获取资源，`HttpResponseHeaders` 中的信息会被用来处理响应，例如获取内容长度，或者检查是否有特定的安全头部。**

当开发者在 Chromium 网络层进行调试时，如果怀疑是 HTTP 响应头处理的问题，他们可能会在这个 `http_response_headers_unittest.cc` 文件中寻找相关的测试用例，或者编写新的测试用例来复现和验证 bug。通过查看测试用例的输入（模拟的响应头）和预期输出，可以更好地理解 `HttpResponseHeaders` 类的行为，并定位问题所在。

Prompt: 
```
这是目录为net/http/http_response_headers_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
   "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "expires: Wed, 28 Nov 2007 00:20:11 GMT\n"
     "cache-control: max-age=10000\n"
     "\n",
     VALIDATION_NONE},
    // Cache-control: no-store overrides expires: in the future.
    {"HTTP/1.1 200 OK\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "expires: Wed, 29 Nov 2007 00:40:11 GMT\n"
     "cache-control: no-store,private,no-cache=\"foo\"\n"
     "\n",
     VALIDATION_SYNCHRONOUS},
    // Pragma: no-cache overrides last-modified heuristic.
    {"HTTP/1.1 200 OK\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "last-modified: Wed, 27 Nov 2007 08:00:00 GMT\n"
     "pragma: no-cache\n"
     "\n",
     VALIDATION_SYNCHRONOUS},
    // max-age has expired, needs synchronous revalidation
    {"HTTP/1.1 200 OK\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "cache-control: max-age=300\n"
     "\n",
     VALIDATION_SYNCHRONOUS},
    // max-age has expired, stale-while-revalidate has not, eligible for
    // asynchronous revalidation
    {"HTTP/1.1 200 OK\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "cache-control: max-age=300, stale-while-revalidate=3600\n"
     "\n",
     VALIDATION_ASYNCHRONOUS},
    // max-age and stale-while-revalidate have expired, needs synchronous
    // revalidation
    {"HTTP/1.1 200 OK\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "cache-control: max-age=300, stale-while-revalidate=5\n"
     "\n",
     VALIDATION_SYNCHRONOUS},
    // max-age is 0, stale-while-revalidate is large enough to permit
    // asynchronous revalidation
    {"HTTP/1.1 200 OK\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "cache-control: max-age=0, stale-while-revalidate=360\n"
     "\n",
     VALIDATION_ASYNCHRONOUS},
    // stale-while-revalidate must not override no-cache or similar directives.
    {"HTTP/1.1 200 OK\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "cache-control: no-cache, stale-while-revalidate=360\n"
     "\n",
     VALIDATION_SYNCHRONOUS},
    // max-age has not expired, so no revalidation is needed.
    {"HTTP/1.1 200 OK\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "cache-control: max-age=3600, stale-while-revalidate=3600\n"
     "\n",
     VALIDATION_NONE},
    // must-revalidate overrides stale-while-revalidate, so synchronous
    // validation
    // is needed.
    {"HTTP/1.1 200 OK\n"
     "date: Wed, 28 Nov 2007 00:40:11 GMT\n"
     "cache-control: must-revalidate, max-age=300, "
     "stale-while-revalidate=3600\n"
     "\n",
     VALIDATION_SYNCHRONOUS},

    // TODO(darin): Add many many more tests here.
};

INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         RequiresValidationTest,
                         testing::ValuesIn(requires_validation_tests));

struct UpdateTestData {
  const char* orig_headers;
  const char* new_headers;
  const char* expected_headers;
};

class UpdateTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<UpdateTestData> {
};

TEST_P(UpdateTest, Update) {
  const UpdateTestData test = GetParam();

  std::string orig_headers(test.orig_headers);
  HeadersToRaw(&orig_headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(orig_headers);

  std::string new_headers(test.new_headers);
  HeadersToRaw(&new_headers);
  auto new_parsed = base::MakeRefCounted<HttpResponseHeaders>(new_headers);

  parsed->Update(*new_parsed.get());

  EXPECT_EQ(std::string(test.expected_headers), ToSimpleString(parsed));
}

const UpdateTestData update_tests[] = {
    {"HTTP/1.1 200 OK\n",

     "HTTP/1/1 304 Not Modified\n"
     "connection: keep-alive\n"
     "Cache-control: max-age=10000\n",

     "HTTP/1.1 200 OK\n"
     "Cache-control: max-age=10000\n"},
    {"HTTP/1.1 200 OK\n"
     "Foo: 1\n"
     "Cache-control: private\n",

     "HTTP/1/1 304 Not Modified\n"
     "connection: keep-alive\n"
     "Cache-control: max-age=10000\n",

     "HTTP/1.1 200 OK\n"
     "Cache-control: max-age=10000\n"
     "Foo: 1\n"},
    {"HTTP/1.1 200 OK\n"
     "Foo: 1\n"
     "Cache-control: private\n",

     "HTTP/1/1 304 Not Modified\n"
     "connection: keep-alive\n"
     "Cache-CONTROL: max-age=10000\n",

     "HTTP/1.1 200 OK\n"
     "Cache-CONTROL: max-age=10000\n"
     "Foo: 1\n"},
    {"HTTP/1.1 200 OK\n"
     "Content-Length: 450\n",

     "HTTP/1/1 304 Not Modified\n"
     "connection: keep-alive\n"
     "Cache-control:      max-age=10001   \n",

     "HTTP/1.1 200 OK\n"
     "Cache-control: max-age=10001\n"
     "Content-Length: 450\n"},
    {
        "HTTP/1.1 200 OK\n"
        "X-Frame-Options: DENY\n",

        "HTTP/1/1 304 Not Modified\n"
        "X-Frame-Options: ALLOW\n",

        "HTTP/1.1 200 OK\n"
        "X-Frame-Options: DENY\n",
    },
    {
        "HTTP/1.1 200 OK\n"
        "X-WebKit-CSP: default-src 'none'\n",

        "HTTP/1/1 304 Not Modified\n"
        "X-WebKit-CSP: default-src *\n",

        "HTTP/1.1 200 OK\n"
        "X-WebKit-CSP: default-src 'none'\n",
    },
    {
        "HTTP/1.1 200 OK\n"
        "X-XSS-Protection: 1\n",

        "HTTP/1/1 304 Not Modified\n"
        "X-XSS-Protection: 0\n",

        "HTTP/1.1 200 OK\n"
        "X-XSS-Protection: 1\n",
    },
    {"HTTP/1.1 200 OK\n",

     "HTTP/1/1 304 Not Modified\n"
     "X-Content-Type-Options: nosniff\n",

     "HTTP/1.1 200 OK\n"},
    {"HTTP/1.1 200 OK\n"
     "Content-Encoding: identity\n"
     "Content-Length: 100\n"
     "Content-Type: text/html\n"
     "Content-Security-Policy: default-src 'none'\n",

     "HTTP/1/1 304 Not Modified\n"
     "Content-Encoding: gzip\n"
     "Content-Length: 200\n"
     "Content-Type: text/xml\n"
     "Content-Security-Policy: default-src 'self'\n",

     "HTTP/1.1 200 OK\n"
     "Content-Security-Policy: default-src 'self'\n"
     "Content-Encoding: identity\n"
     "Content-Length: 100\n"
     "Content-Type: text/html\n"},
    {"HTTP/1.1 200 OK\n"
     "Content-Location: /example_page.html\n",

     "HTTP/1/1 304 Not Modified\n"
     "Content-Location: /not_example_page.html\n",

     "HTTP/1.1 200 OK\n"
     "Content-Location: /example_page.html\n"},
};

INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         UpdateTest,
                         testing::ValuesIn(update_tests));

struct EnumerateHeaderTestData {
  const char* headers;
  const char* expected_lines;
};

class EnumerateHeaderLinesTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<EnumerateHeaderTestData> {
};

TEST_P(EnumerateHeaderLinesTest, EnumerateHeaderLines) {
  const EnumerateHeaderTestData test = GetParam();

  std::string headers(test.headers);
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);

  std::string name, value, lines;

  size_t iter = 0;
  while (parsed->EnumerateHeaderLines(&iter, &name, &value)) {
    lines.append(name);
    lines.append(": ");
    lines.append(value);
    lines.append("\n");
  }

  EXPECT_EQ(std::string(test.expected_lines), lines);
}

const EnumerateHeaderTestData enumerate_header_tests[] = {
    {"HTTP/1.1 200 OK\n",

     ""},
    {"HTTP/1.1 200 OK\n"
     "Foo: 1\n",

     "Foo: 1\n"},
    {"HTTP/1.1 200 OK\n"
     "Foo: 1\n"
     "Bar: 2\n"
     "Foo: 3\n",

     "Foo: 1\nBar: 2\nFoo: 3\n"},
    {"HTTP/1.1 200 OK\n"
     "Foo: 1, 2, 3\n",

     "Foo: 1, 2, 3\n"},
    {"HTTP/1.1 200 OK\n"
     "Foo: ,, 1,, 2, 3,, \n",

     "Foo: ,, 1,, 2, 3,,\n"},
};

INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         EnumerateHeaderLinesTest,
                         testing::ValuesIn(enumerate_header_tests));

struct IsRedirectTestData {
  const char* headers;
  const char* location;
  bool is_redirect;
};

class IsRedirectTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<IsRedirectTestData> {
};

TEST_P(IsRedirectTest, IsRedirect) {
  const IsRedirectTestData test = GetParam();

  std::string headers(test.headers);
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);

  std::string location;
  EXPECT_EQ(parsed->IsRedirect(&location), test.is_redirect);
  EXPECT_EQ(location, test.location);
}

const IsRedirectTestData is_redirect_tests[] = {
  { "HTTP/1.1 200 OK\n",
    "",
    false
  },
  { "HTTP/1.1 301 Moved\n"
    "Location: http://foopy/\n",
    "http://foopy/",
    true
  },
  { "HTTP/1.1 301 Moved\n"
    "Location: \t \n",
    "",
    false
  },
  // We use the first location header as the target of the redirect.
  { "HTTP/1.1 301 Moved\n"
    "Location: http://foo/\n"
    "Location: http://bar/\n",
    "http://foo/",
    true
  },
  // We use the first _valid_ location header as the target of the redirect.
  { "HTTP/1.1 301 Moved\n"
    "Location: \n"
    "Location: http://bar/\n",
    "http://bar/",
    true
  },
  // Bug 1050541 (location header with an unescaped comma).
  { "HTTP/1.1 301 Moved\n"
    "Location: http://foo/bar,baz.html\n",
    "http://foo/bar,baz.html",
    true
  },
  // Bug 1224617 (location header with non-ASCII bytes).
  { "HTTP/1.1 301 Moved\n"
    "Location: http://foo/bar?key=\xE4\xF6\xFC\n",
    "http://foo/bar?key=%E4%F6%FC",
    true
  },
  // Shift_JIS, Big5, and GBK contain multibyte characters with the trailing
  // byte falling in the ASCII range.
  { "HTTP/1.1 301 Moved\n"
    "Location: http://foo/bar?key=\x81\x5E\xD8\xBF\n",
    "http://foo/bar?key=%81^%D8%BF",
    true
  },
  { "HTTP/1.1 301 Moved\n"
    "Location: http://foo/bar?key=\x82\x40\xBD\xC4\n",
    "http://foo/bar?key=%82@%BD%C4",
    true
  },
  { "HTTP/1.1 301 Moved\n"
    "Location: http://foo/bar?key=\x83\x5C\x82\x5D\xCB\xD7\n",
    "http://foo/bar?key=%83\\%82]%CB%D7",
    true
  },
};

INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         IsRedirectTest,
                         testing::ValuesIn(is_redirect_tests));

struct HasStorageAccessRetryTestData {
  const char* headers;
  std::optional<std::string> expected_origin;

  bool want_result;
};

class HasStorageAccessRetryTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<HasStorageAccessRetryTestData> {};

TEST_P(HasStorageAccessRetryTest, HasStorageAccessRetry) {
  const HasStorageAccessRetryTestData test = GetParam();

  std::string headers(test.headers);
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);

  EXPECT_EQ(parsed->HasStorageAccessRetryHeader(
                base::OptionalToPtr(test.expected_origin)),
            test.want_result);
}

const HasStorageAccessRetryTestData has_storage_access_retry_tests[] = {
    // No expected initiator; explicit allowlist.
    {"HTTP/1.1 200 OK\n"
     R"(Activate-Storage-Access: retry; allowed-origin="https://example.com:123")"
     "\n",
     std::nullopt, false},
    // No expected initiator; wildcard allowlist matches anyway, since the
    // server says anything goes.
    {"HTTP/1.1 200 OK\n"
     R"(Activate-Storage-Access: retry; allowed-origin=*)"
     "\n",
     std::nullopt, true},
    // No allowlist, no expected initiator.
    {"HTTP/1.1 200 OK\n"
     "Activate-Storage-Access: retry\n",
     std::nullopt, false},
    // No allowlist.
    {"HTTP/1.1 200 OK\n"
     "Activate-Storage-Access: retry\n",
     "https://example.com", false},
    // Invalid structured header.
    {"HTTP/1.1 200 OK\n"
     R"(Activate-Storage-Access: retry, allowed-origin:"https://example.com:123")"
     "\n",
     "https://example.com:123", false},
    // Unknown parameter.
    {"HTTP/1.1 200 OK\n"
     R"(Activate-Storage-Access: retry; frobnify="https://example.com:123")"
     "\n",
     "https://example.com:123", false},
    // allowed-origin parameter present along with unrecognized parameter.
    {"HTTP/1.1 200 OK\n"
     R"(Activate-Storage-Access: retry; frobnify=*;)"
     R"( allowed-origin="https://example.com:123")"
     "\n",
     "https://example.com:123", true},
    // Allowlist and expected initiator match.
    {"HTTP/1.1 200 OK\n"
     R"(Activate-Storage-Access: retry; allowed-origin="https://example.com:123")"
     "\n",
     "https://example.com:123", true},
    // Allowlist and expected initiator mismatch.
    {"HTTP/1.1 200 OK\n"
     R"(Activate-Storage-Access: retry; allowed-origin="https://example.com")"
     "\n",
     "https://example.com:123", false},
    // This is a list, not an item, so it is ignored.
    {"HTTP/1.1 200 OK\n"
     R"(Activate-Storage-Access: foo, retry; allowed-origin=*, bar)"
     "\n",
     "https://example.com", false},
    // This is a list (supplied in multiple field lines), not an item, so it is
    // ignored.
    {"HTTP/1.1 200 OK\n"
     "Activate-Storage-Access: foo\n"
     "Activate-Storage-Access: retry; allowed-origin=*, bar\n",
     "https://example.com", false},
};

INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         HasStorageAccessRetryTest,
                         testing::ValuesIn(has_storage_access_retry_tests));

struct ContentLengthTestData {
  const char* headers;
  int64_t expected_len;
};

class GetContentLengthTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<ContentLengthTestData> {
};

TEST_P(GetContentLengthTest, GetContentLength) {
  const ContentLengthTestData test = GetParam();

  std::string headers(test.headers);
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);

  EXPECT_EQ(test.expected_len, parsed->GetContentLength());
}

const ContentLengthTestData content_length_tests[] = {
    {"HTTP/1.1 200 OK\n", -1},
    {"HTTP/1.1 200 OK\n"
     "Content-Length: 10\n",
     10},
    {"HTTP/1.1 200 OK\n"
     "Content-Length: \n",
     -1},
    {"HTTP/1.1 200 OK\n"
     "Content-Length: abc\n",
     -1},
    {"HTTP/1.1 200 OK\n"
     "Content-Length: -10\n",
     -1},
    {"HTTP/1.1 200 OK\n"
     "Content-Length:  +10\n",
     -1},
    {"HTTP/1.1 200 OK\n"
     "Content-Length: 23xb5\n",
     -1},
    {"HTTP/1.1 200 OK\n"
     "Content-Length: 0xA\n",
     -1},
    {"HTTP/1.1 200 OK\n"
     "Content-Length: 010\n",
     10},
    // Content-Length too big, will overflow an int64_t.
    {"HTTP/1.1 200 OK\n"
     "Content-Length: 40000000000000000000\n",
     -1},
    {"HTTP/1.1 200 OK\n"
     "Content-Length:       10\n",
     10},
    {"HTTP/1.1 200 OK\n"
     "Content-Length: 10  \n",
     10},
    {"HTTP/1.1 200 OK\n"
     "Content-Length: \t10\n",
     10},
    {"HTTP/1.1 200 OK\n"
     "Content-Length: \v10\n",
     -1},
    {"HTTP/1.1 200 OK\n"
     "Content-Length: \f10\n",
     -1},
    {"HTTP/1.1 200 OK\n"
     "cOnTeNt-LENgth: 33\n",
     33},
    {"HTTP/1.1 200 OK\n"
     "Content-Length: 34\r\n",
     -1},
};

INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         GetContentLengthTest,
                         testing::ValuesIn(content_length_tests));

struct ContentRangeTestData {
  const char* headers;
  bool expected_return_value;
  int64_t expected_first_byte_position;
  int64_t expected_last_byte_position;
  int64_t expected_instance_size;
};

class ContentRangeTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<ContentRangeTestData> {
};

TEST_P(ContentRangeTest, GetContentRangeFor206) {
  const ContentRangeTestData test = GetParam();

  std::string headers(test.headers);
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);

  int64_t first_byte_position;
  int64_t last_byte_position;
  int64_t instance_size;
  bool return_value = parsed->GetContentRangeFor206(
      &first_byte_position, &last_byte_position, &instance_size);
  EXPECT_EQ(test.expected_return_value, return_value);
  EXPECT_EQ(test.expected_first_byte_position, first_byte_position);
  EXPECT_EQ(test.expected_last_byte_position, last_byte_position);
  EXPECT_EQ(test.expected_instance_size, instance_size);
}

const ContentRangeTestData content_range_tests[] = {
    {"HTTP/1.1 206 Partial Content", false, -1, -1, -1},
    {"HTTP/1.1 206 Partial Content\n"
     "Content-Range:",
     false, -1, -1, -1},
    {"HTTP/1.1 206 Partial Content\n"
     "Content-Range: bytes 0-50/51",
     true, 0, 50, 51},
    {"HTTP/1.1 206 Partial Content\n"
     "Content-Range: bytes 50-0/51",
     false, -1, -1, -1},
    {"HTTP/1.1 416 Requested range not satisfiable\n"
     "Content-Range: bytes */*",
     false, -1, -1, -1},
    {"HTTP/1.1 206 Partial Content\n"
     "Content-Range: bytes 0-50/*",
     false, -1, -1, -1},
};

INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         ContentRangeTest,
                         testing::ValuesIn(content_range_tests));

struct KeepAliveTestData {
  const char* headers;
  bool expected_keep_alive;
};

// Enable GTest to print KeepAliveTestData in an intelligible way if the test
// fails.
void PrintTo(const KeepAliveTestData& keep_alive_test_data,
             std::ostream* os) {
  *os << "{\"" << keep_alive_test_data.headers << "\", " << std::boolalpha
      << keep_alive_test_data.expected_keep_alive << "}";
}

class IsKeepAliveTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<KeepAliveTestData> {
};

TEST_P(IsKeepAliveTest, IsKeepAlive) {
  const KeepAliveTestData test = GetParam();

  std::string headers(test.headers);
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);

  EXPECT_EQ(test.expected_keep_alive, parsed->IsKeepAlive());
}

const KeepAliveTestData keepalive_tests[] = {
  // The status line fabricated by HttpNetworkTransaction for a 0.9 response.
  // Treated as 0.9.
  { "HTTP/0.9 200 OK",
    false
  },
  // This could come from a broken server.  Treated as 1.0 because it has a
  // header.
  { "HTTP/0.9 200 OK\n"
    "connection: keep-alive\n",
    true
  },
  { "HTTP/1.1 200 OK\n",
    true
  },
  { "HTTP/1.0 200 OK\n",
    false
  },
  { "HTTP/1.0 200 OK\n"
    "connection: close\n",
    false
  },
  { "HTTP/1.0 200 OK\n"
    "connection: keep-alive\n",
    true
  },
  { "HTTP/1.0 200 OK\n"
    "connection: kEeP-AliVe\n",
    true
  },
  { "HTTP/1.0 200 OK\n"
    "connection: keep-aliveX\n",
    false
  },
  { "HTTP/1.1 200 OK\n"
    "connection: close\n",
    false
  },
  { "HTTP/1.1 200 OK\n"
    "connection: keep-alive\n",
    true
  },
  { "HTTP/1.0 200 OK\n"
    "proxy-connection: close\n",
    false
  },
  { "HTTP/1.0 200 OK\n"
    "proxy-connection: keep-alive\n",
    true
  },
  { "HTTP/1.1 200 OK\n"
    "proxy-connection: close\n",
    false
  },
  { "HTTP/1.1 200 OK\n"
    "proxy-connection: keep-alive\n",
    true
  },
  { "HTTP/1.1 200 OK\n"
    "Connection: Upgrade, close\n",
    false
  },
  { "HTTP/1.1 200 OK\n"
    "Connection: Upgrade, keep-alive\n",
    true
  },
  { "HTTP/1.1 200 OK\n"
    "Connection: Upgrade\n"
    "Connection: close\n",
    false
  },
  { "HTTP/1.1 200 OK\n"
    "Connection: Upgrade\n"
    "Connection: keep-alive\n",
    true
  },
  { "HTTP/1.1 200 OK\n"
    "Connection: close, Upgrade\n",
    false
  },
  { "HTTP/1.1 200 OK\n"
    "Connection: keep-alive, Upgrade\n",
    true
  },
  { "HTTP/1.1 200 OK\n"
    "Connection: Upgrade\n"
    "Proxy-Connection: close\n",
    false
  },
  { "HTTP/1.1 200 OK\n"
    "Connection: Upgrade\n"
    "Proxy-Connection: keep-alive\n",
    true
  },
  // In situations where the response headers conflict with themselves, use the
  // first one for backwards-compatibility.
  { "HTTP/1.1 200 OK\n"
    "Connection: close\n"
    "Connection: keep-alive\n",
    false
  },
  { "HTTP/1.1 200 OK\n"
    "Connection: keep-alive\n"
    "Connection: close\n",
    true
  },
  { "HTTP/1.0 200 OK\n"
    "Connection: close\n"
    "Connection: keep-alive\n",
    false
  },
  { "HTTP/1.0 200 OK\n"
    "Connection: keep-alive\n"
    "Connection: close\n",
    true
  },
  // Ignore the Proxy-Connection header if at all possible.
  { "HTTP/1.0 200 OK\n"
    "Proxy-Connection: keep-alive\n"
    "Connection: close\n",
    false
  },
  { "HTTP/1.1 200 OK\n"
    "Proxy-Connection: close\n"
    "Connection: keep-alive\n",
    true
  },
  // Older versions of Chrome would have ignored Proxy-Connection in this case,
  // but it doesn't seem safe.
  { "HTTP/1.1 200 OK\n"
    "Proxy-Connection: close\n"
    "Connection: Transfer-Encoding\n",
    false
  },
};

INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         IsKeepAliveTest,
                         testing::ValuesIn(keepalive_tests));

struct HasStrongValidatorsTestData {
  const char* headers;
  bool expected_result;
};

class HasStrongValidatorsTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<HasStrongValidatorsTestData> {
};

TEST_P(HasStrongValidatorsTest, HasStrongValidators) {
  const HasStrongValidatorsTestData test = GetParam();

  std::string headers(test.headers);
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);

  EXPECT_EQ(test.expected_result, parsed->HasStrongValidators());
  // Having string validators implies having validators.
  if (parsed->HasStrongValidators()) {
    EXPECT_TRUE(parsed->HasValidators());
  }
}

const HasStrongValidatorsTestData strong_validators_tests[] = {
  { "HTTP/0.9 200 OK",
    false
  },
  { "HTTP/1.0 200 OK\n"
    "Date: Wed, 28 Nov 2007 01:40:10 GMT\n"
    "Last-Modified: Wed, 28 Nov 2007 00:40:10 GMT\n"
    "ETag: \"foo\"\n",
    false
  },
  { "HTTP/1.1 200 OK\n"
    "Date: Wed, 28 Nov 2007 01:40:10 GMT\n"
    "Last-Modified: Wed, 28 Nov 2007 00:40:10 GMT\n"
    "ETag: \"foo\"\n",
    true
  },
  { "HTTP/1.1 200 OK\n"
    "Date: Wed, 28 Nov 2007 00:41:10 GMT\n"
    "Last-Modified: Wed, 28 Nov 2007 00:40:10 GMT\n",
    true
  },
  { "HTTP/1.1 200 OK\n"
    "Date: Wed, 28 Nov 2007 00:41:09 GMT\n"
    "Last-Modified: Wed, 28 Nov 2007 00:40:10 GMT\n",
    false
  },
  { "HTTP/1.1 200 OK\n"
    "ETag: \"foo\"\n",
    true
  },
  // This is not really a weak etag:
  { "HTTP/1.1 200 OK\n"
    "etag: \"w/foo\"\n",
    true
  },
  // This is a weak etag:
  { "HTTP/1.1 200 OK\n"
    "etag: w/\"foo\"\n",
    false
  },
  { "HTTP/1.1 200 OK\n"
    "etag:    W  /   \"foo\"\n",
    false
  }
};

INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         HasStrongValidatorsTest,
                         testing::ValuesIn(strong_validators_tests));

TEST(HttpResponseHeadersTest, HasValidatorsNone) {
  std::string headers("HTTP/1.1 200 OK");
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);
  EXPECT_FALSE(parsed->HasValidators());
}

TEST(HttpResponseHeadersTest, HasValidatorsEtag) {
  std::string headers(
      "HTTP/1.1 200 OK\n"
      "etag: \"anything\"");
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);
  EXPECT_TRUE(parsed->HasValidators());
}

TEST(HttpResponseHeadersTest, HasValidatorsLastModified) {
  std::string headers(
      "HTTP/1.1 200 OK\n"
      "Last-Modified: Wed, 28 Nov 2007 00:40:10 GMT");
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);
  EXPECT_TRUE(parsed->HasValidators());
}

TEST(HttpResponseHeadersTest, HasValidatorsWeakEtag) {
  std::string headers(
      "HTTP/1.1 200 OK\n"
      "etag: W/\"anything\"");
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);
  EXPECT_TRUE(parsed->HasValidators());
}

TEST(HttpResponseHeadersTest, GetNormalizedHeaderWithEmptyValues) {
  std::string headers(
      "HTTP/1.1 200 OK\n"
      "a:\n"
      "b: \n"
      "c:*\n"
      "d: *\n"
      "e:    \n"
      "a: \n"
      "b:*\n"
      "c:\n"
      "d:*\n"
      "a:\n");
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);

  EXPECT_EQ(parsed->GetNormalizedHeader("a"), ", , ");
  EXPECT_EQ(parsed->GetNormalizedHeader("b"), ", *");
  EXPECT_EQ(parsed->GetNormalizedHeader("c"), "*, ");
  EXPECT_EQ(parsed->GetNormalizedHeader("d"), "*, *");
  EXPECT_EQ(parsed->GetNormalizedHeader("e"), "");
  EXPECT_EQ(parsed->GetNormalizedHeader("f"), std::nullopt);
}

TEST(HttpResponseHeadersTest, GetNormalizedHeaderWithCommas) {
  std::string headers(
      "HTTP/1.1 200 OK\n"
      "a: foo, bar\n"
      "b: , foo, bar,\n"
      "c: ,,,\n"
      "d:  ,  ,  ,  \n"
      "e:\t,\t,\t,\t\n"
      "a: ,");
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);

  // TODO(mmenke): "Normalized" headers probably should preserve the
  // leading/trailing whitespace from the original headers.
  EXPECT_EQ(parsed->GetNormalizedHeader("a"), "foo, bar, ,");
  EXPECT_EQ(parsed->GetNormalizedHeader("b"), ", foo, bar,");
  EXPECT_EQ(parsed->GetNormalizedHeader("c"), ",,,");
  EXPECT_EQ(parsed->GetNormalizedHeader("d"), ",  ,  ,");
  EXPECT_EQ(parsed->GetNormalizedHeader("e"), ",\t,\t,");
  EXPECT_EQ(parsed->GetNormalizedHeader("f"), std::nullopt);
}

TEST(HttpResponseHeadersTest, AddHeader) {
  scoped_refptr<HttpResponseHeaders> headers = HttpResponseHeaders::TryToCreate(
      "HTTP/1.1 200 OK\n"
      "connection: keep-alive\n"
      "Cache-control: max-age=10000\n");
  ASSERT_TRUE(headers);

  headers->AddHeader("Content-Length", "450");
  EXPECT_EQ(
      "HTTP/1.1 200 OK\n"
      "connection: keep-alive\n"
      "Cache-control: max-age=10000\n"
      "Content-Length: 450\n",
      ToSimpleString(headers));

  // Add a second Content-Length header with extra spaces in the value. It
  // should be added to the end, and the extra spaces removed.
  headers->AddHeader("Content-Length", "   42    ");
  EXPECT_EQ(
      "HTTP/1.1 200 OK\n"
      "connection: keep-alive\n"
      "Cache-control: max-age=10000\n"
      "Content-Length: 450\n"
      "Content-Length: 42\n",
      ToSimpleString(headers));
}

TEST(HttpResponseHeadersTest, SetHeader) {
  scoped_refptr<HttpResponseHeaders> headers = HttpResponseHeaders::TryToCreate(
      "HTTP/1.1 200 OK\n"
      "connection: keep-alive\n"
      "Cache-control: max-age=10000\n");
  ASSERT_TRUE(headers);

  headers->SetHeader("Content-Length", "450");
  EXPECT_EQ(
      "HTTP/1.1 200 OK\n"
      "connection: keep-alive\n"
      "Cache-control: max-age=10000\n"
      "Content-Length: 450\n",
      ToSimpleString(headers));

  headers->SetHeader("Content-Length", "   42    ");
  EXPECT_EQ(
      "HTTP/1.1 200 OK\n"
      "connection: keep-alive\n"
      "Cache-control: max-age=10000\n"
      "Content-Length: 42\n",
      ToSimpleString(headers));

  headers->SetHeader("connection", "close");
  EXPECT_EQ(
      "HTTP/1.1 200 OK\n"
      "Cache-control: max-age=10000\n"
      "Content-Length: 42\n"
      "connection: close\n",
      ToSimpleString(headers));
}

TEST(HttpResponseHeadersTest, TryToCreateWithNul) {
  static constexpr char kHeadersWithNuls[] = {
      "HTTP/1.1 200 OK\0"
      "Content-Type: application/octet-stream\0"};
  // The size must be specified explicitly to include the nul characters.
  static constexpr std::string_view kHeadersWithNulsAsStringPiece(
      kHeadersWithNuls, sizeof(kHeadersWithNuls));
  scoped_refptr<HttpResponseHeaders> headers =
      HttpResponseHeaders::TryToCreate(kHeadersWithNulsAsStringPiece);
  EXPECT_EQ(headers, nullptr);
}

#if !BUILDFLAG(CRONET_BUILD)
// Cronet disables tracing so this test would fail.
TEST(HttpResponseHeadersTest, TracingSupport) {
  scoped_refptr<HttpResponseHeaders> headers = HttpResponseHeaders::TryToCreate(
      "HTTP/1.1 200 OK\n"
      "connection: keep-alive\n");
  ASSERT_TRUE(headers);

  EXPECT_EQ(perfetto::TracedValueToString(headers),
            "{response_code:200,headers:[{name:connection,value:keep-alive}]}");
}
#endif

struct RemoveHeaderTestData {
  const char* orig_headers;
  const char* to_remove;
  const char* expected_headers;
};

class RemoveHeaderTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<RemoveHeaderTestData> {
};

TEST_P(RemoveHeaderTest, RemoveHeader) {
  const RemoveHeaderTestData test = GetParam();

  std::string orig_headers(test.orig_headers);
  HeadersToRaw(&orig_headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(orig_headers);

  std::string name(test.to_remove);
  parsed->RemoveHeader(name);

  EXPECT_EQ(std::string(test.expected_headers), ToSimpleString(parsed));
}

const RemoveHeaderTestData remove_header_tests[] = {
  { "HTTP/1.1 200 OK\n"
    "connection: keep-alive\n"
    "Cache-control: max-age=10000\n"
    "Content-Length: 450\n",

    "Content-Length",

    "HTTP/1.1 200 OK\n"
    "connection: keep-alive\n"
    "Cache-control: max-age=10000\n"
  },
  { "HTTP/1.1 200 OK\n"
    "connection: keep-alive  \n"
    "Content-Length  : 450  \n"
    "Cache-control: max-age=10000\n",

    "Content-Length",

    "HTTP/1.1 200 OK\n"
    "connection: keep-alive\n"
    "Cache-control: max-age=10000\n"
  },
};

INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         RemoveHeaderTest,
                         testing::ValuesIn(remove_header_tests));

struct RemoveHeadersTestData {
  const char* orig_headers;
  const char* to_remove[2];
  const char* expected_headers;
};

class RemoveHeadersTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<RemoveHeadersTestData> {};

TEST_P(RemoveHeadersTest, RemoveHeaders) {
  const RemoveHeadersTestData test = GetParam();

  std::string orig_headers(test.orig_headers);
  HeadersToRaw(&orig_headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(orig_headers);

  std::unordered_set<std::string> to_remove;
  for (auto* header : test.to_remove) {
    if (header)
      to_remove.insert(header);
  }
  parsed->RemoveHeaders(to_remove);

  EXPECT_EQ(std::string(test.expected_headers), ToSimpleString(parsed));
}

const RemoveHeadersTestData remove_headers_tests[] = {
    {"HTTP/1.1 200 OK\n"
     "connection: keep-alive\n"
     "Cache-control: max-age=10000\n"
     "Content-Length: 450\n",

     {"Content-Length", "CACHE-control"},

     "HTTP/1.1 200 OK\n"
     "connection: keep-alive\n"},

    {"HTTP/1.1 200 OK\n"
     "connection: keep-alive\n"
     "Content-Length: 450\n",

     {"foo", "bar"},

     "HTTP/1.1 200 OK\n"
     "connection: keep-alive\n"
     "Content-Length: 450\n"},

    {"HTTP/1.1 404 Kinda not OK\n"
     "connection: keep-alive  \n",

     {},

     "HTTP/1.1 404 Kinda not OK\n"
     "connection: keep-alive\n"},
};

INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         RemoveHeadersTest,
                         testing::ValuesIn(remove_headers_tests));

struct RemoveIndividualHeaderTestData {
  const char* orig_headers;
  const char* to_remove_name;
  const char* to_remove_value;
  const char* expected_headers;
};

class RemoveIndividualHeaderTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<RemoveIndividualHeaderTestData> {
};

TEST_P(RemoveIndividualHeaderTest, RemoveIndividualHeader) {
  const RemoveIndividualHeaderTestData test = GetParam();

  std::string orig_headers(test.orig_headers);
  HeadersToRaw(&orig_headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(orig_headers);

  std::string name(test.to_remove_name);
  std::string value(test.to_remove_value);
  parsed->RemoveHeaderLine(name, value);

  EXPECT_EQ(std::string(test.expected_headers), ToSimpleString(parsed));
}

const RemoveIndividualHeaderTestData remove_individual_header_tests[] = {
  { "HTTP/1.1 200 OK\n"
    "connection: keep-alive\n"
    "Cache-control: max-age=10000\n"
    "Content-Length: 450\n",

    "Content-Length",

    "450",

    "HTTP/1.1 200 OK\n"
    "connection: keep-alive\n"
    "Cache-control: max-age=10000\n"
  },
  { "HTTP/1.1 200 OK\n"
    "connection: keep-alive  \n"
    "Content-Length  : 450  \n"
    "Cache-control: max-age=10000\n",

    "Content-Length",

    "450",

    "HTTP/1.1 200 OK\n"
    "connection: keep-alive\n"
    "Cache-control: max-age=10000\n"
  },
  { "HTTP/1.1 200 OK\n"
    "connection: keep-alive  \n"
    "Content-Length: 450\n"
    "Cache-control: max-age=10000\n",

    "Content-Length",  // Matching name.

    "999",  // Mismatching value.

    "HTTP/1.1 200 OK\n"
    "connection: keep-alive\n"
    "Content-Length: 450\n"
    "Cache-control: max-age=10000\n"
  },
  { "HTTP/1.1 200 OK\n"
    "connection: keep-alive  \n"
    "Foo: bar, baz\n"
    "Foo: bar\n"
    "Cache-control: max-age=10000\n",

    "Foo",

    "bar, baz",  // Space in value.

    "HTTP/1.1 200 OK\n"
    "connection: keep-alive\n"
    "Foo: bar\n"
    "Cache-control: max-age=10000\n"
  },
  { "HTTP/1.1 200 OK\n"
    "connection: keep-alive  \n"
    "Foo: bar, baz\n"
    "Cache-control: max-age=10000\n",

    "Foo",

    "baz",  // Only partial match -> ignored.

    "HTTP/1.1 200 OK\n"
    "connection: keep-alive\n"
    "Foo: bar, baz\n"
    "Cache-control: max-age=10000\n"
  },
};

I
"""


```