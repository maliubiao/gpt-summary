Response:
The user wants to understand the functionality of the provided C++ code, which is part of Chromium's networking stack and deals with testing the `HttpResponseHeaders` class.

Here's a breakdown of the thought process to answer the user's request:

1. **Identify the Core Functionality:** The filename `http_response_headers_unittest.cc` and the presence of `TEST_F` and `TEST_P` macros immediately indicate this is a unit test file. The focus is on testing the `HttpResponseHeaders` class.

2. **Analyze Test Structure:** The code is structured using Google Test (gtest) framework. Key elements are:
    * `TEST_F`:  Tests that operate within a fixture class (like `HttpResponseHeadersTest` or its derived classes).
    * `TEST_P`: Parameterized tests that run the same test logic with different input data.
    * `INSTANTIATE_TEST_SUITE_P`:  Defines the parameter sets for parameterized tests.
    * `struct ...TestData`:  Structures used to hold input and expected output data for parameterized tests.

3. **Categorize Test Groups:** The test names and the `TestData` structures suggest different areas of functionality being tested within `HttpResponseHeaders`:
    * `RemoveIndividualHeaderTest`: Testing the removal of specific headers.
    * `ReplaceStatusTest`: Testing the replacement of the HTTP status line.
    * `UpdateWithNewRangeTest`: Testing updating headers when a new content range is requested (likely for partial content downloads).
    * `HttpResponseHeadersCacheControlTest`: A fixture specifically for testing cache control related header parsing.
    * `MaxAgeEdgeCasesTest`: Testing various edge cases for parsing the `max-age` directive in `Cache-Control`.
    * `GetCurrentAgeTest`: Testing the calculation of the current age of a cached response.
    * `HttpResponseHeadersBuilderTest`: Testing the `HttpResponseHeaders::Builder` class for constructing headers programmatically.
    * `BuilderStatusLineTest`: Testing the builder's ability to handle different status line formats.
    * `BuilderHeadersTest`: Testing the builder's ability to add and format headers.
    * `StrictlyEqualsSuccess`, `StrictlyEqualsVersionMismatch`, etc.: Testing the `StrictlyEquals` method for comparing `HttpResponseHeaders` objects.

4. **Detail Functionality within Each Category:** For each category, analyze the test logic and the data provided in the `TestData` structures. This involves:
    * Understanding the method being tested (e.g., `RemoveHeader`, `ReplaceStatusLine`, `UpdateWithNewRange`, `GetMaxAgeValue`, `GetCurrentAge`, `Build`, `StrictlyEquals`).
    * Identifying the different scenarios being tested (e.g., removing existing vs. non-existent headers, replacing with valid/invalid status lines, updating range with/without status replacement, various `max-age` formats, calculating age with/without `Age` header, building headers with single/multiple values, comparing headers with different versions/status codes/header content).

5. **Look for JavaScript Connections:**  Consider how HTTP headers are relevant to JavaScript. Key areas include:
    * **Caching:** JavaScript running in a browser is heavily influenced by HTTP caching headers like `Cache-Control`, `Expires`, `Pragma`, `Age`, `Last-Modified`, `ETag`.
    * **Content Handling:** Headers like `Content-Type` tell the browser how to interpret the response data, which affects how JavaScript can process it.
    * **Cookies:** `Set-Cookie` headers are crucial for managing session state and user tracking, accessible to JavaScript.
    * **Range Requests:** While not directly manipulated by typical JavaScript, understanding range requests is important when dealing with media or large file downloads.
    * **Security:** Headers like `Content-Security-Policy` (though not explicitly tested here) are very relevant to JavaScript security.

6. **Construct Examples and Scenarios:** For areas with JavaScript relevance, create concrete examples to illustrate the connection. For instance, how a `Cache-Control: max-age=...` header affects `fetch()` requests in JavaScript.

7. **Identify Potential User Errors:** Think about common mistakes developers might make when dealing with HTTP headers, both on the server-side (generating incorrect headers) and the client-side (misinterpreting headers). Examples: incorrect `Cache-Control` directives, missing or wrong `Content-Type`, setting conflicting caching headers.

8. **Trace User Operations (Debugging):** Explain how a user's interaction with a web browser might lead to this code being executed. This involves the flow of a network request: user action -> browser initiates request -> server responds with headers -> browser parses headers (using code like this) -> browser takes action based on headers (caching, rendering, etc.).

9. **Summarize Functionality:**  Provide a concise overview of the file's purpose, reiterating that it's testing the parsing and manipulation of HTTP response headers.

10. **Review and Refine:** Ensure the answer is clear, well-organized, and addresses all aspects of the user's request. Check for accuracy and completeness. For instance, initially, I might have focused too much on the C++ implementation details. I need to remember to bridge the gap to JavaScript where applicable. Also, ensure the examples are easy to understand.
这是Chromium网络栈中 `net/http/http_response_headers_unittest.cc` 文件的第三部分，主要包含以下功能：

**总体功能归纳：**

这个文件的主要功能是**测试 `net::HttpResponseHeaders` 类及其相关的功能**。`HttpResponseHeaders` 类负责解析、存储和操作 HTTP 响应头。  这些测试覆盖了各种场景，包括：

* **移除单个头部:** 测试从响应头中移除特定头部字段的功能。
* **替换状态行:** 测试替换响应头的状态行（例如 "HTTP/1.1 200 OK"）的功能。
* **根据新的范围更新头部:** 测试在处理部分内容请求时更新响应头（例如添加 `Content-Range` 头部）的功能。
* **Cache-Control 头部解析:**  详细测试了 `Cache-Control` 头部中 `max-age` 和 `stale-while-revalidate` 指令的解析，包括各种有效和无效的格式，以及边界情况。
* **计算当前 Age:** 测试根据 `Date` 和 `Age` 头部计算响应的当前年龄的功能。
* **构建 HttpResponseHeaders 对象:** 测试使用 `HttpResponseHeaders::Builder` 类来创建 `HttpResponseHeaders` 对象的功能，并验证构建出的头部内容。
* **严格相等性比较:** 测试 `HttpResponseHeaders` 对象的严格相等性比较方法，包括版本、状态码、状态文本和原始头部内容的比对。

**具体功能分解：**

1. **移除单个头部 (续前一部分):**
   - `INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders, RemoveIndividualHeaderTest, ...)`:  继续实例化之前定义的 `RemoveIndividualHeaderTest` 参数化测试套件，使用 `remove_individual_header_tests` 中的测试用例。

2. **替换状态行 (Replace Status Line):**
   - `struct ReplaceStatusTestData`: 定义了用于测试替换状态行的数据结构，包含原始头部、新的状态行和期望的头部。
   - `class ReplaceStatusTest`:  定义了测试替换状态行的测试类，使用参数化测试。
   - `TEST_P(ReplaceStatusTest, ReplaceStatus)`:  测试用例，读取参数化数据，解析原始头部，调用 `ReplaceStatusLine` 方法替换状态行，并断言结果与期望一致。
   - `replace_status_tests`: 提供了多个测试用例，涵盖了替换状态码和 HTTP 版本的情况。
   - **假设输入与输出：**
     - **假设输入:**
       ```
       orig_headers = "HTTP/1.1 206 Partial Content\nconnection: keep-alive\nContent-Length: 450\n"
       new_status = "HTTP/1.1 200 OK"
       ```
     - **预期输出:**
       ```
       expected_headers = "HTTP/1.1 200 OK\nconnection: keep-alive\nContent-Length: 450\n"
       ```

3. **根据新的范围更新头部 (Update With New Range):**
   - `struct UpdateWithNewRangeTestData`: 定义了用于测试根据新的范围更新头部的数据结构，包含原始头部、期望的头部（不替换状态行）和期望的头部（替换状态行）。
   - `class UpdateWithNewRangeTest`: 定义了测试根据新的范围更新头部的测试类，使用参数化测试。
   - `TEST_P(UpdateWithNewRangeTest, UpdateWithNewRange)`: 测试用例，读取参数化数据，创建 `HttpByteRange` 对象，解析原始头部，调用 `UpdateWithNewRange` 方法更新头部，并断言结果与期望一致。测试了是否替换状态行的两种情况。
   - `update_range_tests`: 提供了多个测试用例，模拟了部分内容请求的场景。
   - **假设输入与输出：**
     - **假设输入:**
       ```
       orig_headers = "HTTP/1.1 200 OK\nContent-Length: 450\n"
       range = HttpByteRange::Bounded(3, 5)
       content_size = 450
       replace_status = false
       ```
     - **预期输出:**
       ```
       expected_headers = "HTTP/1.1 200 OK\nContent-Range: bytes 3-5/450\nContent-Length: 3\n"
       ```
     - **假设输入:**
       ```
       orig_headers = "HTTP/1.1 200 OK\nContent-Length: 450\n"
       range = HttpByteRange::Bounded(3, 5)
       content_size = 450
       replace_status = true
       ```
     - **预期输出:**
       ```
       expected_headers_with_replaced_status = "HTTP/1.1 206 Partial Content\nContent-Range: bytes 3-5/450\nContent-Length: 3\n"
       ```

4. **Cache-Control 头部解析 (Max-Age 和 Stale-While-Revalidate):**
   - `TEST_F(HttpResponseHeadersCacheControlTest, AbsentMaxAgeReturnsFalse)`: 测试当 `Cache-Control` 头部不存在 `max-age` 指令时，`GetMaxAgeValue()` 返回 `false`。
   - 后续多个 `TEST_F` 测试了 `max-age` 指令各种格式的解析，包括无效格式（缺少参数、带空格、负数等）和有效格式。
   - `struct MaxAgeTestData`: 定义了用于测试 `max-age` 指令边缘情况的数据结构，包含 `max-age` 字符串和期望的秒数。
   - `class MaxAgeEdgeCasesTest`: 定义了测试 `max-age` 指令边缘情况的测试类，使用参数化测试。
   - `TEST_P(MaxAgeEdgeCasesTest, MaxAgeEdgeCases)`: 测试用例，读取参数化数据，设置 `Cache-Control` 头部，并断言 `GetMaxAgeValue()` 的结果与期望一致。
   - 类似的测试用例也用于测试 `stale-while-revalidate` 指令的解析。
   - **用户或编程常见的使用错误：**
     - **错误的 `max-age` 格式:**  例如 `"max-age= 10"` (等号后有空格), `"max-age=abc"` (非数字), `"max-age=-1"` (负数)。 这些测试确保了 `HttpResponseHeaders` 能够正确处理这些错误情况并返回合理的默认值或错误指示。
     - **忘记设置 `max-age`:**  当希望浏览器缓存内容时，开发者可能会忘记设置 `max-age`，导致浏览器使用默认的缓存策略，这可能不是期望的行为。
     - **设置过小的 `max-age`:**  如果 `max-age` 设置得太小，会导致浏览器频繁地重新请求资源，影响性能。
     - **混淆 `max-age` 和其他缓存指令:**  开发者可能不清楚各种缓存指令的作用和优先级，导致缓存行为不符合预期。

5. **计算当前 Age (Get Current Age):**
   - `struct GetCurrentAgeTestData`: 定义了用于测试计算当前 Age 的数据结构，包含头部、请求时间、响应时间、当前时间和期望的 Age 值。
   - `class GetCurrentAgeTest`: 定义了测试计算当前 Age 的测试类，使用参数化测试。
   - `TEST_P(GetCurrentAgeTest, GetCurrentAge)`: 测试用例，读取参数化数据，解析时间字符串，解析头部，调用 `GetCurrentAge` 方法计算 Age，并断言结果与期望一致。
   - `get_current_age_tests`: 提供了多个测试用例，涵盖了有无 `Date` 和 `Age` 头部的情况。
   - **用户操作到达这里作为调试线索：**
     1. 用户在浏览器中访问一个网页或资源。
     2. 浏览器发送 HTTP 请求到服务器。
     3. 服务器返回 HTTP 响应，其中包含头部信息，可能包括 `Date` 和 `Age` 头部。
     4. Chromium 的网络栈接收到响应头。
     5. 如果需要确定缓存策略或诊断缓存问题，可能会调用 `HttpResponseHeaders::GetCurrentAge` 方法来计算响应的当前年龄。 这个测试就是为了确保这个计算逻辑的正确性。

6. **构建 HttpResponseHeaders 对象 (HttpResponseHeadersBuilderTest):**
   - `TEST(HttpResponseHeadersBuilderTest, Version)`: 测试使用 `HttpResponseHeaders::Builder` 设置 HTTP 版本的功能。
   - `struct BuilderStatusLineTestData`: 定义了用于测试构建器处理不同状态行的数据结构。
   - `class BuilderStatusLineTest`: 定义了测试构建器处理状态行的测试类，使用参数化测试。
   - `TEST_P(BuilderStatusLineTest, Common)`: 测试用例，使用构建器创建 `HttpResponseHeaders` 对象，并断言状态行、响应码和状态文本与期望一致。
   - `kBuilderStatusLineTests`: 提供了各种状态行的测试用例，包括带有状态文本、没有状态文本、空状态等情况。
   - `struct BuilderHeadersTestData`: 定义了用于测试构建器添加头部的数据结构。
   - `class BuilderHeadersTest`: 定义了测试构建器添加头部的测试类，使用参数化测试。
   - `TEST_P(BuilderHeadersTest, Common)`: 测试用例，使用构建器添加头部，并断言最终生成的头部字符串与期望一致。
   - `builder_headers_tests`: 提供了各种添加头部的测试用例，包括单个头部、多个头部、空值头部、多值头部等情况。

7. **严格相等性比较 (StrictlyEquals):**
   - `TEST(HttpResponseHeadersTest, StrictlyEqualsSuccess)`: 测试两个内容完全相同的 `HttpResponseHeaders` 对象使用 `StrictlyEquals` 方法比较返回 `true`。
   - 后续多个 `TEST` 测试了各种不相等的情况，例如 HTTP 版本不一致、响应码不一致、状态文本不一致、原始头部内容不一致。

**与 JavaScript 功能的关系及举例：**

HTTP 响应头对于 JavaScript 在浏览器中的行为至关重要。以下是一些与本文件中测试的功能相关的例子：

* **缓存控制 (`max-age`, `stale-while-revalidate`):**
   - 当 JavaScript 代码使用 `fetch()` API 或 `XMLHttpRequest` 发起网络请求时，浏览器会检查响应头的缓存指令。
   - 如果响应头中包含 `Cache-Control: max-age=3600`，浏览器会将该资源缓存 3600 秒。在缓存过期前，如果 JavaScript 再次请求相同的资源，浏览器可以直接从缓存中返回，而无需再次向服务器发送请求。
   - `stale-while-revalidate` 允许浏览器在缓存过期后仍然使用旧的缓存响应，同时在后台重新请求资源。如果 JavaScript 发起请求时缓存已过期，浏览器会立即返回旧数据，并开始向服务器请求新数据。下次请求时，将会使用新的数据。
   - **JavaScript 示例：**
     ```javascript
     fetch('https://example.com/data.json')
       .then(response => response.json())
       .then(data => console.log(data));
     ```
     如果服务器返回的响应头包含 `Cache-Control: max-age=60`,  那么在 60 秒内再次执行这段代码，浏览器很可能直接从缓存中获取 `data.json`，而不会发送新的网络请求。

* **部分内容请求 (`Content-Range`, 状态码 206):**
   - 当 JavaScript 需要下载大文件的一部分时，可以使用 `Range` 请求头向服务器请求指定范围的内容。
   - 服务器会返回状态码 `206 Partial Content`，并在响应头中包含 `Content-Range` 头部，指示返回的是哪一部分内容。
   - JavaScript 可以根据 `Content-Range` 头部来处理接收到的数据片段。例如，用于实现视频或音频的流式播放。
   - **JavaScript 示例 (假设服务器支持 Range 请求):**
     ```javascript
     fetch('https://example.com/large-file.zip', {
       headers: {
         'Range': 'bytes=100-200'
       }
     })
     .then(response => {
       if (response.status === 206) {
         console.log('Partial content received');
         console.log(response.headers.get('Content-Range'));
         return response.blob();
       } else {
         console.log('Full content received');
         return response.blob();
       }
     })
     .then(blob => {
       // 处理接收到的部分或完整文件数据
     });
     ```

**用户操作是如何一步步的到达这里，作为调试线索：**

当开发者在 Chromium 浏览器中遇到与网络请求和响应头相关的 bug 时，可能会查看这个单元测试文件作为调试线索：

1. **用户报告问题：** 用户可能会报告浏览器缓存行为异常，例如页面内容没有及时更新，或者即使离线也能访问某些资源。
2. **开发者怀疑是 HTTP 头部解析问题：**  开发者可能会怀疑是 `HttpResponseHeaders` 类在解析缓存相关的头部（如 `Cache-Control`）时出现了错误。
3. **查看单元测试：** 开发者会查看 `net/http/http_response_headers_unittest.cc` 文件，特别是与 `Cache-Control` 相关的测试用例（例如 `HttpResponseHeadersCacheControlTest` 和 `MaxAgeEdgeCasesTest`），来了解代码的预期行为和已知的边界情况。
4. **分析测试用例：** 开发者会分析这些测试用例的输入（各种 `Cache-Control` 头部字符串）和期望的输出（`GetMaxAgeValue()` 的返回值），来确认代码在不同场景下的处理逻辑。
5. **重现问题并调试代码：** 开发者可能会尝试重现用户报告的问题，并设置断点在 `HttpResponseHeaders` 类的相关代码中，例如 `ParseCacheControlDirectives` 或 `GetMaxAgeValue` 方法，来观察实际的头部解析过程和变量的值。
6. **编写新的测试用例：** 如果发现现有的测试用例没有覆盖到导致 bug 的特定场景，开发者会编写新的测试用例来复现该 bug，并确保修复后的代码能够通过新的测试。

总而言之，`net/http/http_response_headers_unittest.cc` 文件通过大量的单元测试，确保了 `HttpResponseHeaders` 类能够正确地解析和操作 HTTP 响应头，这对于 Chromium 浏览器的网络功能（包括缓存、内容协商、部分内容请求等）的正确运行至关重要。这些测试也为开发者提供了理解和调试相关问题的参考。

Prompt: 
```
这是目录为net/http/http_response_headers_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
NSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         RemoveIndividualHeaderTest,
                         testing::ValuesIn(remove_individual_header_tests));

struct ReplaceStatusTestData {
  const char* orig_headers;
  const char* new_status;
  const char* expected_headers;
};

class ReplaceStatusTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<ReplaceStatusTestData> {
};

TEST_P(ReplaceStatusTest, ReplaceStatus) {
  const ReplaceStatusTestData test = GetParam();

  std::string orig_headers(test.orig_headers);
  HeadersToRaw(&orig_headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(orig_headers);

  std::string name(test.new_status);
  parsed->ReplaceStatusLine(name);

  EXPECT_EQ(std::string(test.expected_headers), ToSimpleString(parsed));
}

const ReplaceStatusTestData replace_status_tests[] = {
  { "HTTP/1.1 206 Partial Content\n"
    "connection: keep-alive\n"
    "Cache-control: max-age=10000\n"
    "Content-Length: 450\n",

    "HTTP/1.1 200 OK",

    "HTTP/1.1 200 OK\n"
    "connection: keep-alive\n"
    "Cache-control: max-age=10000\n"
    "Content-Length: 450\n"
  },
  { "HTTP/1.1 200 OK\n"
    "connection: keep-alive\n",

    "HTTP/1.1 304 Not Modified",

    "HTTP/1.1 304 Not Modified\n"
    "connection: keep-alive\n"
  },
  { "HTTP/1.1 200 OK\n"
    "connection: keep-alive  \n"
    "Content-Length  : 450   \n"
    "Cache-control: max-age=10000\n",

    "HTTP/1//1 304 Not Modified",

    "HTTP/1.0 304 Not Modified\n"
    "connection: keep-alive\n"
    "Content-Length: 450\n"
    "Cache-control: max-age=10000\n"
  },
};

INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         ReplaceStatusTest,
                         testing::ValuesIn(replace_status_tests));

struct UpdateWithNewRangeTestData {
  const char* orig_headers;
  const char* expected_headers;
  const char* expected_headers_with_replaced_status;
};

class UpdateWithNewRangeTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<UpdateWithNewRangeTestData> {
};

TEST_P(UpdateWithNewRangeTest, UpdateWithNewRange) {
  const UpdateWithNewRangeTestData test = GetParam();

  const HttpByteRange range = HttpByteRange::Bounded(3, 5);

  std::string orig_headers(test.orig_headers);
  std::replace(orig_headers.begin(), orig_headers.end(), '\n', '\0');
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(orig_headers + '\0');
  int64_t content_size = parsed->GetContentLength();

  // Update headers without replacing status line.
  parsed->UpdateWithNewRange(range, content_size, false);
  EXPECT_EQ(std::string(test.expected_headers), ToSimpleString(parsed));

  // Replace status line too.
  parsed->UpdateWithNewRange(range, content_size, true);
  EXPECT_EQ(std::string(test.expected_headers_with_replaced_status),
            ToSimpleString(parsed));
}

const UpdateWithNewRangeTestData update_range_tests[] = {
  { "HTTP/1.1 200 OK\n"
    "Content-Length: 450\n",

    "HTTP/1.1 200 OK\n"
    "Content-Range: bytes 3-5/450\n"
    "Content-Length: 3\n",

    "HTTP/1.1 206 Partial Content\n"
    "Content-Range: bytes 3-5/450\n"
    "Content-Length: 3\n",
  },
  { "HTTP/1.1 200 OK\n"
    "Content-Length: 5\n",

    "HTTP/1.1 200 OK\n"
    "Content-Range: bytes 3-5/5\n"
    "Content-Length: 3\n",

    "HTTP/1.1 206 Partial Content\n"
    "Content-Range: bytes 3-5/5\n"
    "Content-Length: 3\n",
  },
};

INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         UpdateWithNewRangeTest,
                         testing::ValuesIn(update_range_tests));

TEST_F(HttpResponseHeadersCacheControlTest, AbsentMaxAgeReturnsFalse) {
  InitializeHeadersWithCacheControl("nocache");
  EXPECT_FALSE(headers()->GetMaxAgeValue());
}

TEST_F(HttpResponseHeadersCacheControlTest, MaxAgeWithNoParameterRejected) {
  InitializeHeadersWithCacheControl("max-age=,private");
  EXPECT_FALSE(headers()->GetMaxAgeValue());
}

TEST_F(HttpResponseHeadersCacheControlTest, MaxAgeWithSpaceParameterRejected) {
  InitializeHeadersWithCacheControl("max-age= ,private");
  EXPECT_FALSE(headers()->GetMaxAgeValue());
}

TEST_F(HttpResponseHeadersCacheControlTest, MaxAgeWithInterimSpaceIsRejected) {
  InitializeHeadersWithCacheControl("max-age=1 2");
  EXPECT_FALSE(headers()->GetMaxAgeValue());
}

TEST_F(HttpResponseHeadersCacheControlTest, MaxAgeWithMinusSignIsRejected) {
  InitializeHeadersWithCacheControl("max-age=-7");
  EXPECT_FALSE(headers()->GetMaxAgeValue());
}

TEST_F(HttpResponseHeadersCacheControlTest,
       MaxAgeWithSpaceBeforeEqualsIsRejected) {
  InitializeHeadersWithCacheControl("max-age = 7");
  EXPECT_FALSE(headers()->GetMaxAgeValue());
}

TEST_F(HttpResponseHeadersCacheControlTest,
       MaxAgeWithLeadingandTrailingSpaces) {
  InitializeHeadersWithCacheControl("max-age= 7  ");
  EXPECT_EQ(base::Seconds(7), GetMaxAgeValue());
}

TEST_F(HttpResponseHeadersCacheControlTest, MaxAgeFirstMatchUsed) {
  InitializeHeadersWithCacheControl("max-age=10, max-age=20");
  EXPECT_EQ(base::Seconds(10), GetMaxAgeValue());
}

TEST_F(HttpResponseHeadersCacheControlTest, MaxAgeBogusFirstMatchUsed) {
  // "max-age10" isn't parsed as "max-age"; "max-age=now" is bogus and
  // ignored and so "max-age=20" is used.
  InitializeHeadersWithCacheControl(
      "max-age10, max-age=now, max-age=20, max-age=30");
  EXPECT_EQ(base::Seconds(20), GetMaxAgeValue());
}

TEST_F(HttpResponseHeadersCacheControlTest, MaxAgeCaseInsensitive) {
  InitializeHeadersWithCacheControl("Max-aGe=15");
  EXPECT_EQ(base::Seconds(15), GetMaxAgeValue());
}

TEST_F(HttpResponseHeadersCacheControlTest, MaxAgeOverflow) {
  InitializeHeadersWithCacheControl("max-age=99999999999999999999");
  EXPECT_EQ(base::TimeDelta::FiniteMax().InSeconds(),
            GetMaxAgeValue().InSeconds());
}

struct MaxAgeTestData {
  const char* max_age_string;
  const std::optional<int64_t> expected_seconds;
};

class MaxAgeEdgeCasesTest
    : public HttpResponseHeadersCacheControlTest,
      public ::testing::WithParamInterface<MaxAgeTestData> {
};

TEST_P(MaxAgeEdgeCasesTest, MaxAgeEdgeCases) {
  const MaxAgeTestData test = GetParam();

  std::string max_age = "max-age=";
  InitializeHeadersWithCacheControl(
      (max_age + test.max_age_string).c_str());
  if (test.expected_seconds.has_value()) {
    EXPECT_EQ(test.expected_seconds.value(), GetMaxAgeValue().InSeconds())
        << " for max-age=" << test.max_age_string;
  } else {
    EXPECT_FALSE(headers()->GetMaxAgeValue());
  }
}

const MaxAgeTestData max_age_tests[] = {
    {" 1 ", 1},  // Spaces are ignored.
    {"-1", std::nullopt},
    {"--1", std::nullopt},
    {"2s", std::nullopt},
    {"3 days", std::nullopt},
    {"'4'", std::nullopt},
    {"\"5\"", std::nullopt},
    {"0x6", std::nullopt},  // Hex not parsed as hex.
    {"7F", std::nullopt},   // Hex without 0x still not parsed as hex.
    {"010", 10},            // Octal not parsed as octal.
    {"9223372036853", 9223372036853},
    {"9223372036854", 9223372036854},
    {"9223372036855", 9223372036854},
    {"9223372036854775806", 9223372036854},
    {"9223372036854775807", 9223372036854},
    {"20000000000000000000", 9223372036854},  // Overflow int64_t.
};

INSTANTIATE_TEST_SUITE_P(HttpResponseHeadersCacheControl,
                         MaxAgeEdgeCasesTest,
                         testing::ValuesIn(max_age_tests));

TEST_F(HttpResponseHeadersCacheControlTest,
       AbsentStaleWhileRevalidateReturnsFalse) {
  InitializeHeadersWithCacheControl("max-age=3600");
  EXPECT_FALSE(headers()->GetStaleWhileRevalidateValue());
}

TEST_F(HttpResponseHeadersCacheControlTest,
       StaleWhileRevalidateWithoutValueRejected) {
  InitializeHeadersWithCacheControl("max-age=3600,stale-while-revalidate=");
  EXPECT_FALSE(headers()->GetStaleWhileRevalidateValue());
}

TEST_F(HttpResponseHeadersCacheControlTest,
       StaleWhileRevalidateWithInvalidValueIgnored) {
  InitializeHeadersWithCacheControl("max-age=3600,stale-while-revalidate=true");
  EXPECT_FALSE(headers()->GetStaleWhileRevalidateValue());
}

TEST_F(HttpResponseHeadersCacheControlTest, StaleWhileRevalidateValueReturned) {
  InitializeHeadersWithCacheControl("max-age=3600,stale-while-revalidate=7200");
  EXPECT_EQ(base::Seconds(7200), GetStaleWhileRevalidateValue());
}

TEST_F(HttpResponseHeadersCacheControlTest,
       FirstStaleWhileRevalidateValueUsed) {
  InitializeHeadersWithCacheControl(
      "stale-while-revalidate=1,stale-while-revalidate=7200");
  EXPECT_EQ(base::Seconds(1), GetStaleWhileRevalidateValue());
}

struct GetCurrentAgeTestData {
  const char* headers;
  const char* request_time;
  const char* response_time;
  const char* current_time;
  const int expected_age;
};

class GetCurrentAgeTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<GetCurrentAgeTestData> {
};

TEST_P(GetCurrentAgeTest, GetCurrentAge) {
  const GetCurrentAgeTestData test = GetParam();

  base::Time request_time, response_time, current_time;
  ASSERT_TRUE(base::Time::FromString(test.request_time, &request_time));
  ASSERT_TRUE(base::Time::FromString(test.response_time, &response_time));
  ASSERT_TRUE(base::Time::FromString(test.current_time, &current_time));

  std::string headers(test.headers);
  HeadersToRaw(&headers);
  auto parsed = base::MakeRefCounted<HttpResponseHeaders>(headers);

  base::TimeDelta age =
      parsed->GetCurrentAge(request_time, response_time, current_time);
  EXPECT_EQ(test.expected_age, age.InSeconds());
}

const struct GetCurrentAgeTestData get_current_age_tests[] = {
    // Without Date header.
    {"HTTP/1.1 200 OK\n"
     "Age: 2",
     "Fri, 20 Jan 2011 10:40:08 GMT", "Fri, 20 Jan 2011 10:40:12 GMT",
     "Fri, 20 Jan 2011 10:40:14 GMT", 8},
    // Without Age header.
    {"HTTP/1.1 200 OK\n"
     "Date: Fri, 20 Jan 2011 10:40:10 GMT\n",
     "Fri, 20 Jan 2011 10:40:08 GMT", "Fri, 20 Jan 2011 10:40:12 GMT",
     "Fri, 20 Jan 2011 10:40:14 GMT", 6},
    // date_value > response_time with Age header.
    {"HTTP/1.1 200 OK\n"
     "Date: Fri, 20 Jan 2011 10:40:14 GMT\n"
     "Age: 2\n",
     "Fri, 20 Jan 2011 10:40:08 GMT", "Fri, 20 Jan 2011 10:40:12 GMT",
     "Fri, 20 Jan 2011 10:40:14 GMT", 8},
     // date_value > response_time without Age header.
     {"HTTP/1.1 200 OK\n"
     "Date: Fri, 20 Jan 2011 10:40:14 GMT\n",
     "Fri, 20 Jan 2011 10:40:08 GMT", "Fri, 20 Jan 2011 10:40:12 GMT",
     "Fri, 20 Jan 2011 10:40:14 GMT", 6},
    // apparent_age > corrected_age_value
    {"HTTP/1.1 200 OK\n"
     "Date: Fri, 20 Jan 2011 10:40:07 GMT\n"
     "Age: 0\n",
     "Fri, 20 Jan 2011 10:40:08 GMT", "Fri, 20 Jan 2011 10:40:12 GMT",
     "Fri, 20 Jan 2011 10:40:14 GMT", 7}};

INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         GetCurrentAgeTest,
                         testing::ValuesIn(get_current_age_tests));

TEST(HttpResponseHeadersBuilderTest, Version) {
  for (HttpVersion version :
       {HttpVersion(1, 0), HttpVersion(1, 1), HttpVersion(2, 0)}) {
    auto headers = HttpResponseHeaders::Builder(version, "200").Build();
    EXPECT_EQ(base::StringPrintf("HTTP/%d.%d 200", version.major_value(),
                                 version.minor_value()),
              headers->GetStatusLine());
    EXPECT_EQ(version, headers->GetHttpVersion());
  }
}

struct BuilderStatusLineTestData {
  const std::string_view status;
  const std::string_view expected_status_line;
  const int expected_response_code;
  const std::string_view expected_status_text;
};

// Provide GTest with a method to print the BuilderStatusLineTestData, for ease
// of debugging.
void PrintTo(const BuilderStatusLineTestData& data, std::ostream* os) {
  *os << "\"" << data.status << "\", \"" << data.expected_status_line << "\", "
      << data.expected_response_code << ", \"" << data.expected_status_text
      << "\"}";
}

class BuilderStatusLineTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<BuilderStatusLineTestData> {};

TEST_P(BuilderStatusLineTest, Common) {
  const auto& [status, expected_status_line, expected_response_code,
               expected_status_text] = GetParam();

  auto http_response_headers =
      HttpResponseHeaders::Builder({1, 1}, status).Build();

  EXPECT_EQ(expected_status_line, http_response_headers->GetStatusLine());
  EXPECT_EQ(expected_response_code, http_response_headers->response_code());
  EXPECT_EQ(expected_status_text, http_response_headers->GetStatusText());
}

constexpr BuilderStatusLineTestData kBuilderStatusLineTests[] = {
    {// Simple case.
     "200 OK",

     "HTTP/1.1 200 OK", 200, "OK"},
    {// No status text.
     "200",

     "HTTP/1.1 200", 200, ""},
    {// Empty status.
     "",

     "HTTP/1.1 200", 200, ""},
    {// Space status.
     " ",

     "HTTP/1.1 200", 200, ""},
    {// Spaces removed from status.
     "    204       No content   ",

     "HTTP/1.1 204 No content", 204, "No content"},
    {// Tabs treated as terminating whitespace.
     "204   \t  No  content \t ",

     "HTTP/1.1 204 \t  No  content \t", 204, "\t  No  content \t"},
    {// Status text smushed into response code.
     "426Smush",

     "HTTP/1.1 426 Smush", 426, "Smush"},
    {// Tab gets included in status text.
     "501\tStatus\t",

     "HTTP/1.1 501 \tStatus\t", 501, "\tStatus\t"},
    {// Zero response code.
     "0 Zero",

     "HTTP/1.1 0 Zero", 0, "Zero"},
    {// Oversize response code.
     "20230904 Monday",

     "HTTP/1.1 20230904 Monday", 20230904, "Monday"},
    {// Overflowing response code.
     "9123456789 Overflow",

     "HTTP/1.1 9123456789 Overflow", 2147483647, "Overflow"},
};

INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         BuilderStatusLineTest,
                         testing::ValuesIn(kBuilderStatusLineTests));

struct BuilderHeadersTestData {
  const std::vector<std::pair<std::string_view, std::string_view>> headers;
  const std::string_view expected_headers;
};

// Provide GTest with a method to print the BuilderHeadersTestData, for ease of
// debugging.
void PrintTo(const BuilderHeadersTestData& data, std::ostream* os) {
  *os << "{";
  for (const auto& header : data.headers) {
    *os << "{\"" << header.first << "\", \"" << header.second << "\"},";
  }
  std::string expected_headers(data.expected_headers);
  EscapeForPrinting(&expected_headers);
  *os << "}, \"" << expected_headers << "\"}";
}

class BuilderHeadersTest
    : public HttpResponseHeadersTest,
      public ::testing::WithParamInterface<BuilderHeadersTestData> {};

TEST_P(BuilderHeadersTest, Common) {
  const auto& [headers, expected_headers_const] = GetParam();
  HttpResponseHeaders::Builder builder({1, 1}, "200");
  for (const auto& [key, value] : headers) {
    builder.AddHeader(key, value);
  }
  auto http_response_headers = builder.Build();

  std::string output_headers = ToSimpleString(http_response_headers);
  std::string expected_headers(expected_headers_const);

  EscapeForPrinting(&output_headers);
  EscapeForPrinting(&expected_headers);

  EXPECT_EQ(expected_headers, output_headers);
}

const BuilderHeadersTestData builder_headers_tests[] = {
    {// Single header.
     {{"Content-Type", "text/html"}},

     "HTTP/1.1 200\n"
     "Content-Type: text/html\n"},
    {// Multiple headers.
     {
         {"Content-Type", "text/html"},
         {"Content-Length", "6"},
         {"Set-Cookie", "a=1"},
     },

     "HTTP/1.1 200\n"
     "Content-Type: text/html\n"
     "Content-Length: 6\n"
     "Set-Cookie: a=1\n"},
    {// Empty header value.
     {{"Pragma", ""}},

     "HTTP/1.1 200\n"
     "Pragma: \n"},
    {// Multiple header value.
     {{"Cache-Control", "no-cache, no-store"}},

     "HTTP/1.1 200\n"
     "Cache-Control: no-cache, no-store\n"},
    {// Spaces are removed around values, but when EnumerateHeaderLines()
     // rejoins continuations, it keeps interior spaces. .
     {{"X-Commas", "   ,  ,    "}},

     "HTTP/1.1 200\n"
     "X-Commas: ,  ,\n"},
    {// Single value is trimmed.
     {{"Pragma", "     no-cache   "}},

     "HTTP/1.1 200\n"
     "Pragma: no-cache\n"},
    {// Location header is trimmed.
     {{"Location", "   http://example.com/   "}},

     "HTTP/1.1 200\n"
     "Location: http://example.com/\n"},
};

INSTANTIATE_TEST_SUITE_P(HttpResponseHeaders,
                         BuilderHeadersTest,
                         testing::ValuesIn(builder_headers_tests));

TEST(HttpResponseHeadersTest, StrictlyEqualsSuccess) {
  constexpr char kRawHeaders[] =
      "HTTP/1.1 200\n"
      "Content-Type:application/octet-stream\n"
      "Cache-Control:no-cache, no-store\n";
  std::string raw_headers = kRawHeaders;
  HeadersToRaw(&raw_headers);
  const auto parsed = base::MakeRefCounted<HttpResponseHeaders>(raw_headers);
  const auto built = HttpResponseHeaders::Builder({1, 1}, "200")
                         .AddHeader("Content-Type", "application/octet-stream")
                         .AddHeader("Cache-Control", "no-cache, no-store")
                         .Build();
  EXPECT_TRUE(parsed->StrictlyEquals(*built));
  EXPECT_TRUE(built->StrictlyEquals(*parsed));
}

TEST(HttpResponseHeadersTest, StrictlyEqualsVersionMismatch) {
  const auto http10 = HttpResponseHeaders::Builder({1, 0}, "200").Build();
  const auto http11 = HttpResponseHeaders::Builder({1, 1}, "200").Build();
  EXPECT_FALSE(http10->StrictlyEquals(*http11));
  EXPECT_FALSE(http11->StrictlyEquals(*http10));
}

TEST(HttpResponseHeadersTest, StrictlyEqualsResponseCodeMismatch) {
  const auto response200 = HttpResponseHeaders::Builder({1, 1}, "200").Build();
  const auto response404 = HttpResponseHeaders::Builder({1, 1}, "404").Build();
  EXPECT_FALSE(response200->StrictlyEquals(*response404));
  EXPECT_FALSE(response404->StrictlyEquals(*response200));
}

TEST(HttpResponseHeadersTest, StrictlyEqualsStatusTextMismatch) {
  const auto ok = HttpResponseHeaders::Builder({1, 1}, "200 OK").Build();
  const auto ng = HttpResponseHeaders::Builder({1, 1}, "200 NG").Build();
  EXPECT_FALSE(ok->StrictlyEquals(*ng));
  EXPECT_FALSE(ng->StrictlyEquals(*ok));
}

TEST(HttpResponseHeadersTest, StrictlyEqualsRawMismatch) {
  // These are designed so that the offsets of names and values will be the
  // same.
  std::string raw1 =
      "HTTP/1.1 200\n"
      "Pragma :None\n";
  std::string raw2 =
      "HTTP/1.1 200\n"
      "Pragma: None\n";
  HeadersToRaw(&raw1);
  HeadersToRaw(&raw2);
  const auto parsed1 = base::MakeRefCounted<HttpResponseHeaders>(raw1);
  const auto parsed2 = base::MakeRefCounted<HttpResponseHeaders>(raw2);
  EXPECT_FALSE(parsed1->StrictlyEquals(*parsed2));
  EXPECT_FALSE(parsed2->StrictlyEquals(*parsed1));
}

// There's no known way to produce an HttpResponseHeaders object with the same
// `raw_headers_` but different `parsed_` structures, so there's no test for
// that.

}  // namespace

}  // namespace net

"""


```