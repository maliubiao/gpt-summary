Response:
The user wants a summary of the functionality of the C++ code in `net/third_party/quiche/src/quiche/balsa/balsa_headers_test.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose of the file:** The filename `balsa_headers_test.cc` strongly suggests this file contains unit tests for the `BalsaHeaders` class.

2. **Scan the test cases:** Quickly read through the names of the `TEST` macros. This provides a high-level overview of what aspects of `BalsaHeaders` are being tested. Keywords like "SetResponseReasonPhrase", "SetResponseVersion", "AppendToHeader", "SetContentLength", "ToggleChunkedEncoding", "ForEachHeader", and "WriteToBuffer" stand out.

3. **Group related tests:**  Notice that several tests are related to setting response attributes (reason phrase, version, code), header manipulation (appending, removing), and content encoding. This helps in organizing the functional summary.

4. **Analyze the test logic (using the provided snippet):** The code snippet demonstrates testing the retrieval of response attributes (`response_code`, `response_reason_phrase`, `response_version`, `first_line`) after setting them. It also tests iterating through the header lines. This confirms the initial assessment and provides concrete examples.

5. **Look for Javascript relevance:** Consider if any of the tested functionalities have direct parallels in Javascript's handling of HTTP headers. The concepts of setting and getting headers, and the structure of HTTP requests and responses, are definitely shared.

6. **Identify potential user errors:** Think about common mistakes developers make when working with HTTP headers. Incorrectly setting content length when using chunked encoding, or manipulating headers in a way that violates HTTP specifications are possibilities. The tests for `SetContentLength` and `ToggleChunkedEncoding` hint at these concerns.

7. **Infer user journey for debugging:** Imagine a scenario where a developer encounters a bug related to HTTP headers. How might they end up looking at this specific test file? They might be investigating how headers are parsed, serialized, or manipulated within the Chromium network stack, specifically within the context of the QUIC protocol (given the file path).

8. **Synthesize the summary:** Combine the observations from the previous steps into a concise summary. Emphasize the testing aspect and the areas of `BalsaHeaders` functionality being validated.

9. **Address specific instructions:**
    * **Functionality Listing:** Create a bulleted list based on the test case analysis.
    * **Javascript Relation:** Provide examples of how Javascript interacts with HTTP headers (e.g., `fetch` API, `XMLHttpRequest`).
    * **Logical Reasoning (Hypothetical Input/Output):**  Use the provided code snippet as an example. Focus on the header manipulation and the expected outcomes.
    * **User/Programming Errors:**  Give concrete examples related to content length and chunked encoding.
    * **User Operation for Debugging:** Describe a plausible debugging scenario.
    * **Overall Function Summary:**  Reiterate the core purpose of the file as a test suite for `BalsaHeaders`.
    * **Part of Series:** Acknowledge that this is part 4 of 5 and tailor the summary accordingly.

10. **Review and Refine:** Read through the generated response to ensure accuracy, clarity, and completeness. Ensure all parts of the prompt are addressed. For example, explicitly state that the file tests the *correctness* of the `BalsaHeaders` class.
这是对 Chromium 网络栈中 `net/third_party/quiche/src/quiche/balsa/balsa_headers_test.cc` 文件功能的总结，基于提供的代码片段和上下文，它是一个 **单元测试文件**，专门用于测试 `BalsaHeaders` 类的各种功能。

**功能归纳:**

这个测试文件主要用于验证 `BalsaHeaders` 类的以下功能：

* **HTTP 响应头部的设置和获取:**
    * 设置和获取响应状态码 (response code)。
    * 设置和获取响应原因短语 (response reason phrase)。
    * 设置和获取 HTTP 版本 (response version)。
    * 设置和获取完整的首行 (first line) 字符串。
    * 测试在没有初始首行的情况下设置这些属性的行为。
* **HTTP 请求头部的设置和获取 (虽然代码片段侧重于响应，但测试文件通常也会覆盖请求):**
    * 设置请求首行，包括方法、URL 和 HTTP 版本。
* **HTTP 头部字段的添加、获取、修改和删除:**
    * 添加单个头部字段。
    * 添加具有相同键的多个头部字段。
    * 获取指定键的单个头部值。
    * 获取指定键的所有头部值。
    * 追加头部值到已存在的头部字段 (带和不带逗号分隔)。
    * 删除所有指定键的头部字段。
    * 删除指定前缀的头部字段。
* **迭代器功能测试:**
    * 测试遍历头部字段的迭代器是否正常工作。
    * 测试迭代器与 `std::ostream` 的配合使用。
* **Content-Length 头部处理:**
    * 设置 `Content-Length` 头部。
    * 清除 `Content-Length` 头部。
    * 检查 `Content-Length` 状态 (有效或无效)。
* **Transfer-Encoding 头部处理:**
    * 设置 `Transfer-Encoding: chunked`。
    * 清除 `Transfer-Encoding` 头部。
    * 检查 `transfer_encoding_is_chunked_` 标志。
* **判断是否需要关闭连接 (framed by connection close):**
    * 根据响应状态码判断是否需要关闭连接。
* **处理头部字段中的非法字符:**
* **处理头部行首的 `\r` 字符:**
* **判断 `BalsaHeaders` 对象是否为空。**
* **使用 `ForEachHeader` 遍历头部字段。**
* **写入头部信息到缓冲区:**
    * 支持将头部键转换为小写、保持原样或进行特定格式化 (Propercase)。
    * 支持不合并相同键的头部字段。

**与 Javascript 的关系及举例说明:**

虽然这段 C++ 代码本身不是 Javascript，但它测试的网络协议 (HTTP) 是 Javascript 在 Web 开发中进行网络请求的基础。以下是一些关联的例子：

* **HTTP 头部操作:** Javascript 中的 `fetch` API 或 `XMLHttpRequest` 对象允许开发者在发送请求和接收响应时访问和操作 HTTP 头部。`BalsaHeaders` 类的功能在服务端或底层网络库中实现，确保了这些头部信息的正确解析和构建，从而使得 Javascript 代码能够可靠地发送和接收数据。

    ```javascript
    // 使用 fetch API 设置和获取请求头
    fetch('/data', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Custom-Header': 'some value'
      }
    })
    .then(response => {
      console.log(response.headers.get('Content-Type')); // 获取响应头
    });

    // 使用 XMLHttpRequest 设置和获取请求头
    const xhr = new XMLHttpRequest();
    xhr.open('GET', '/data');
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.onreadystatechange = function() {
      if (xhr.readyState === 4 && xhr.status === 200) {
        console.log(xhr.getResponseHeader('Content-Type')); // 获取响应头
      }
    };
    xhr.send();
    ```

* **Content-Length 和 Transfer-Encoding:**  Javascript 不会直接操作这两个头部，但浏览器会根据这些头部来处理响应体。例如，如果 `Transfer-Encoding` 是 `chunked`，浏览器会按块接收数据。`BalsaHeaders` 的测试确保了服务端正确设置这些头部，浏览器才能正确解析。

* **HTTP 状态码和原因短语:** Javascript 可以通过 `response.status` 和 `response.statusText` 获取 HTTP 状态码和原因短语。`BalsaHeaders` 的测试保证了这些信息在服务器端的正确设置。

**逻辑推理 (假设输入与输出):**

提供的代码片段展示了一个测试用例 `TEST(BalsaHeaders, MergeAndGetFirstLine)`， 我们可以进行如下推理:

**假设输入:**

一个 `BalsaHeaders` 对象 `headers4` 被创建，并依次设置了多个头部信息，以及一个包含请求行和一些头部信息的字符串被合并到该对象中。

```
// 初始状态，headers4 可能已经添加了一些头部
headers4.AddHeader("key4", "value4");

// 合并的字符串
std::string first;
first.append("GET /foo HTTP/1.0\r\n");
first.append("key 2: value\n 2\r\n");
first.append("key\n 3: value3\r\n");
```

**预期输出:**

在合并操作后，`headers4` 的首行会被更新为响应行，并且之前的头部信息会被保留。`first_line()` 方法应该返回合并后的首行字符串，并且可以通过迭代器访问所有的头部字段。

```
EXPECT_EQ("HTTP/1.1 200 reason phrase asdf", headers4.first_line());
// ... 并且可以通过迭代器访问 "key 2", "key\n 3", "key4" 等头部
```

**用户或编程常见的使用错误及举例说明:**

* **错误地同时设置 `Content-Length` 和 `Transfer-Encoding: chunked`:**  HTTP 规范中明确指出，当使用分块传输编码时，不应该设置 `Content-Length`。`BalsaHeaders` 的测试应该会覆盖这种情况，确保能够正确处理或抛出错误。

    ```c++
    // 错误示例
    BalsaHeaders headers;
    headers.SetContentLength(1024);
    headers.SetTransferEncodingToChunkedAndClearContentLength(); // 这应该清除 Content-Length
    ```

* **设置了不合法的 HTTP 响应状态码或版本:**  `BalsaHeaders` 的测试会验证设置这些属性时是否进行了基本的格式检查。

    ```c++
    // 错误示例
    BalsaHeaders headers;
    headers.SetResponseFirstline("HTTP/3.0", 99, "Invalid Code"); // HTTP/3.0 可能还未被广泛支持，99 不是合法的状态码
    ```

* **在应该使用 `AppendToHeader` 时错误地覆盖了头部字段:**  如果需要添加具有相同键的多个头部，应该使用 `AppendHeader` 或 `AppendToHeader`，而不是多次使用 `SetHeader`，后者会覆盖之前的设置。

    ```c++
    // 错误示例
    BalsaHeaders headers;
    headers.SetHeader("Cache-Control", "max-age=3600");
    headers.SetHeader("Cache-Control", "must-revalidate"); // 错误，会覆盖之前的设置
    // 正确做法
    headers.AppendHeader("Cache-Control", "max-age=3600");
    headers.AppendHeader("Cache-Control", "must-revalidate");
    ```

**用户操作是如何一步步的到达这里，作为调试线索。**

作为一个调试线索，用户操作到这里可能经历以下步骤：

1. **用户在浏览器中发起了一个网络请求。**
2. **Chromium 网络栈处理该请求。**
3. **服务器返回一个 HTTP 响应。**
4. **Chromium 网络栈接收到响应数据。**
5. **在网络栈的某个环节，`BalsaHeaders` 类被用来解析或构建 HTTP 头部信息。**
6. **如果响应头部解析或处理出现问题，开发者可能会需要调试 `BalsaHeaders` 类的行为。**
7. **开发者可能会查看 `balsa_headers_test.cc` 文件，了解 `BalsaHeaders` 类的预期行为，并编写或运行相关的测试用例来复现和定位问题。**
8. **例如，如果开发者怀疑响应头部的合并逻辑有问题，他们可能会关注 `MergeAndGetFirstLine` 这样的测试用例。**
9. **或者，如果 `Content-Length` 或 `Transfer-Encoding` 的处理出现异常，他们可能会查看 `SetContentLength` 或 `ToggleChunkedEncoding` 相关的测试。**

**这是第4部分，共5部分，请归纳一下它的功能**

作为第 4 部分，这个测试文件深入测试了 `BalsaHeaders` 类中关于 **HTTP 头部字段的各种操作**，包括设置、获取、添加、删除和修改，以及对 `Content-Length` 和 `Transfer-Encoding` 等重要头部字段的特殊处理。它验证了 `BalsaHeaders` 类在处理 HTTP 头部信息时的正确性和鲁棒性，确保了网络栈能够正确地解析和构建 HTTP 消息。 这部分测试用例覆盖了更细致的头部操作逻辑，为 `BalsaHeaders` 类的可靠性提供了保证。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/balsa/balsa_headers_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// "GET /foo HTTP/1.0"     // 17
  // "XXXXXXXXXXXXXX"        // 14
  // "key 2: value\n 2\r\n"  // 17
  // "key\n 3: value3\r\n"   // 16
  // "key4: value4\r\n"      // 14
  //
  //       ->
  //
  // "HTTP/1.1 200 reason phrase asdf"  // 31 = (17 + 14)
  // "key 2: value\n 2\r\n"             // 17
  // "key\n 3: value3\r\n"              // 16
  // "key4: value4\r\n"                 // 14

  EXPECT_EQ("200", headers4.response_code());
  EXPECT_EQ("reason phrase asdf", headers4.response_reason_phrase());
  EXPECT_EQ("HTTP/1.1", headers4.response_version());

  EXPECT_EQ("HTTP/1.1 200 reason phrase asdf", headers4.first_line());
  chli = headers4.lines().begin();
  EXPECT_EQ("key 2", chli->first);
  EXPECT_EQ("value\n 2", chli->second);
  ++chli;
  EXPECT_EQ("key\n 3", chli->first);
  EXPECT_EQ("value3", chli->second);
  ++chli;
  EXPECT_EQ("key4", chli->first);
  EXPECT_EQ("value4", chli->second);
  ++chli;
  EXPECT_EQ(headers4.lines().end(), chli);
}

TEST(BalsaHeaders, IteratorWorksWithOStreamAsExpected) {
  {
    std::stringstream actual;
    BalsaHeaders::const_header_lines_iterator chli;
    actual << chli;
    // Note that the output depends on the flavor of standard library in use.
    EXPECT_THAT(actual.str(), AnyOf(StrEq("[0, 0]"),      // libstdc++
                                    StrEq("[(nil), 0]"),  // libc++
                                    StrEq("[0x0, 0]")));  // libc++ on Mac
  }
  {
    BalsaHeaders headers;
    std::stringstream actual;
    BalsaHeaders::const_header_lines_iterator chli = headers.lines().begin();
    actual << chli;
    std::stringstream expected;
    expected << "[" << &headers << ", 0]";
    EXPECT_THAT(expected.str(), StrEq(actual.str()));
  }
}

TEST(BalsaHeaders, TestSetResponseReasonPhraseWithNoInitialFirstline) {
  BalsaHeaders balsa_headers;
  balsa_headers.SetResponseReasonPhrase("don't need a reason");
  EXPECT_THAT(balsa_headers.first_line(), StrEq("  don't need a reason"));
  EXPECT_TRUE(balsa_headers.response_version().empty());
  EXPECT_TRUE(balsa_headers.response_code().empty());
  EXPECT_THAT(balsa_headers.response_reason_phrase(),
              StrEq("don't need a reason"));
}

// Testing each of 9 combinations separately was taking up way too much of this
// file (not to mention the inordinate amount of stupid code duplication), thus
// this test tests all 9 combinations of smaller, equal, and larger in one
// place.
TEST(BalsaHeaders, TestSetResponseReasonPhrase) {
  const char* response_reason_phrases[] = {
      "qwerty asdfgh",
      "qwerty",
      "qwerty asdfghjkl",
  };
  size_t arraysize_squared = (ABSL_ARRAYSIZE(response_reason_phrases) *
                              ABSL_ARRAYSIZE(response_reason_phrases));
  // We go through the 9 different permutations of (response_reason_phrases
  // choose 2) in the loop below. For each permutation, we mutate the firstline
  // twice-- once from the original, and once from the previous.
  for (size_t iteration = 0; iteration < arraysize_squared; ++iteration) {
    SCOPED_TRACE("Original firstline: \"HTTP/1.0 200 reason phrase\"");
    BalsaHeaders headers = CreateHTTPHeaders(true,
                                             "HTTP/1.0 200 reason phrase\r\n"
                                             "content-length: 0\r\n"
                                             "\r\n");
    ASSERT_THAT(headers.first_line(), StrEq("HTTP/1.0 200 reason phrase"));

    {
      int first = iteration / ABSL_ARRAYSIZE(response_reason_phrases);
      const char* response_reason_phrase_first = response_reason_phrases[first];
      std::string expected_new_firstline =
          absl::StrFormat("HTTP/1.0 200 %s", response_reason_phrase_first);
      SCOPED_TRACE(absl::StrFormat("Then set response_reason_phrase(\"%s\")",
                                   response_reason_phrase_first));

      headers.SetResponseReasonPhrase(response_reason_phrase_first);
      EXPECT_THAT(headers.first_line(),
                  StrEq(absl::StrFormat("HTTP/1.0 200 %s",
                                        response_reason_phrase_first)));
      EXPECT_THAT(headers.response_version(), StrEq("HTTP/1.0"));
      EXPECT_THAT(headers.response_code(), StrEq("200"));
      EXPECT_THAT(headers.response_reason_phrase(),
                  StrEq(response_reason_phrase_first));
    }

    // Note that each iteration of the outer loop causes the headers to be left
    // in a different state. Nothing wrong with that, but we should use each of
    // these states, and try each of our scenarios again. This inner loop does
    // that.
    {
      int second = iteration % ABSL_ARRAYSIZE(response_reason_phrases);
      const char* response_reason_phrase_second =
          response_reason_phrases[second];
      std::string expected_new_firstline =
          absl::StrFormat("HTTP/1.0 200 %s", response_reason_phrase_second);
      SCOPED_TRACE(absl::StrFormat("Then set response_reason_phrase(\"%s\")",
                                   response_reason_phrase_second));

      headers.SetResponseReasonPhrase(response_reason_phrase_second);
      EXPECT_THAT(headers.first_line(),
                  StrEq(absl::StrFormat("HTTP/1.0 200 %s",
                                        response_reason_phrase_second)));
      EXPECT_THAT(headers.response_version(), StrEq("HTTP/1.0"));
      EXPECT_THAT(headers.response_code(), StrEq("200"));
      EXPECT_THAT(headers.response_reason_phrase(),
                  StrEq(response_reason_phrase_second));
    }
  }
}

TEST(BalsaHeaders, TestSetResponseVersionWithNoInitialFirstline) {
  BalsaHeaders balsa_headers;
  balsa_headers.SetResponseVersion("HTTP/1.1");
  EXPECT_THAT(balsa_headers.first_line(), StrEq("HTTP/1.1  "));
  EXPECT_THAT(balsa_headers.response_version(), StrEq("HTTP/1.1"));
  EXPECT_TRUE(balsa_headers.response_code().empty());
  EXPECT_TRUE(balsa_headers.response_reason_phrase().empty());
}

// Testing each of 9 combinations separately was taking up way too much of this
// file (not to mention the inordinate amount of stupid code duplication), thus
// this test tests all 9 combinations of smaller, equal, and larger in one
// place.
TEST(BalsaHeaders, TestSetResponseVersion) {
  const char* response_versions[] = {
      "ABCD/123",
      "ABCD",
      "ABCD/123456",
  };
  size_t arraysize_squared =
      (ABSL_ARRAYSIZE(response_versions) * ABSL_ARRAYSIZE(response_versions));
  // We go through the 9 different permutations of (response_versions choose 2)
  // in the loop below. For each permutation, we mutate the firstline twice--
  // once from the original, and once from the previous.
  for (size_t iteration = 0; iteration < arraysize_squared; ++iteration) {
    SCOPED_TRACE("Original firstline: \"HTTP/1.0 200 reason phrase\"");
    BalsaHeaders headers = CreateHTTPHeaders(false,
                                             "HTTP/1.0 200 reason phrase\r\n"
                                             "content-length: 0\r\n"
                                             "\r\n");
    ASSERT_THAT(headers.first_line(), StrEq("HTTP/1.0 200 reason phrase"));

    // This structure guarantees that we'll visit all of the possible
    // variations of setting.

    {
      int first = iteration / ABSL_ARRAYSIZE(response_versions);
      const char* response_version_first = response_versions[first];
      std::string expected_new_firstline =
          absl::StrFormat("%s 200 reason phrase", response_version_first);
      SCOPED_TRACE(absl::StrFormat("Then set response_version(\"%s\")",
                                   response_version_first));

      headers.SetResponseVersion(response_version_first);
      EXPECT_THAT(headers.first_line(), StrEq(expected_new_firstline));
      EXPECT_THAT(headers.response_version(), StrEq(response_version_first));
      EXPECT_THAT(headers.response_code(), StrEq("200"));
      EXPECT_THAT(headers.response_reason_phrase(), StrEq("reason phrase"));
    }
    {
      int second = iteration % ABSL_ARRAYSIZE(response_versions);
      const char* response_version_second = response_versions[second];
      std::string expected_new_firstline =
          absl::StrFormat("%s 200 reason phrase", response_version_second);
      SCOPED_TRACE(absl::StrFormat("Then set response_version(\"%s\")",
                                   response_version_second));

      headers.SetResponseVersion(response_version_second);
      EXPECT_THAT(headers.first_line(), StrEq(expected_new_firstline));
      EXPECT_THAT(headers.response_version(), StrEq(response_version_second));
      EXPECT_THAT(headers.response_code(), StrEq("200"));
      EXPECT_THAT(headers.response_reason_phrase(), StrEq("reason phrase"));
    }
  }
}

TEST(BalsaHeaders, TestSetResponseReasonAndVersionWithNoInitialFirstline) {
  BalsaHeaders headers;
  headers.SetResponseVersion("HTTP/1.1");
  headers.SetResponseReasonPhrase("don't need a reason");
  EXPECT_THAT(headers.first_line(), StrEq("HTTP/1.1  don't need a reason"));
  EXPECT_THAT(headers.response_version(), StrEq("HTTP/1.1"));
  EXPECT_TRUE(headers.response_code().empty());
  EXPECT_THAT(headers.response_reason_phrase(), StrEq("don't need a reason"));
}

TEST(BalsaHeaders, TestSetResponseCodeWithNoInitialFirstline) {
  BalsaHeaders balsa_headers;
  balsa_headers.SetParsedResponseCodeAndUpdateFirstline(2002);
  EXPECT_THAT(balsa_headers.first_line(), StrEq(" 2002 "));
  EXPECT_TRUE(balsa_headers.response_version().empty());
  EXPECT_THAT(balsa_headers.response_code(), StrEq("2002"));
  EXPECT_TRUE(balsa_headers.response_reason_phrase().empty());
  EXPECT_THAT(balsa_headers.parsed_response_code(), Eq(2002));
}

TEST(BalsaHeaders, TestSetParsedResponseCode) {
  BalsaHeaders balsa_headers;
  balsa_headers.set_parsed_response_code(std::numeric_limits<int>::max());
  EXPECT_THAT(balsa_headers.parsed_response_code(),
              Eq(std::numeric_limits<int>::max()));
}

TEST(BalsaHeaders, TestSetResponseCode) {
  const char* response_codes[] = {
      "200"
      "23",
      "200200",
  };
  size_t arraysize_squared =
      (ABSL_ARRAYSIZE(response_codes) * ABSL_ARRAYSIZE(response_codes));
  // We go through the 9 different permutations of (response_codes choose 2)
  // in the loop below. For each permutation, we mutate the firstline twice--
  // once from the original, and once from the previous.
  for (size_t iteration = 0; iteration < arraysize_squared; ++iteration) {
    SCOPED_TRACE("Original firstline: \"HTTP/1.0 200 reason phrase\"");
    BalsaHeaders headers = CreateHTTPHeaders(false,
                                             "HTTP/1.0 200 reason phrase\r\n"
                                             "content-length: 0\r\n"
                                             "\r\n");
    ASSERT_THAT(headers.first_line(), StrEq("HTTP/1.0 200 reason phrase"));

    // This structure guarantees that we'll visit all of the possible
    // variations of setting.

    {
      int first = iteration / ABSL_ARRAYSIZE(response_codes);
      const char* response_code_first = response_codes[first];
      std::string expected_new_firstline =
          absl::StrFormat("HTTP/1.0 %s reason phrase", response_code_first);
      SCOPED_TRACE(absl::StrFormat("Then set response_code(\"%s\")",
                                   response_code_first));

      headers.SetResponseCode(response_code_first);

      EXPECT_THAT(headers.first_line(), StrEq(expected_new_firstline));
      EXPECT_THAT(headers.response_version(), StrEq("HTTP/1.0"));
      EXPECT_THAT(headers.response_code(), StrEq(response_code_first));
      EXPECT_THAT(headers.response_reason_phrase(), StrEq("reason phrase"));
    }
    {
      int second = iteration % ABSL_ARRAYSIZE(response_codes);
      const char* response_code_second = response_codes[second];
      std::string expected_new_secondline =
          absl::StrFormat("HTTP/1.0 %s reason phrase", response_code_second);
      SCOPED_TRACE(absl::StrFormat("Then set response_code(\"%s\")",
                                   response_code_second));

      headers.SetResponseCode(response_code_second);

      EXPECT_THAT(headers.first_line(), StrEq(expected_new_secondline));
      EXPECT_THAT(headers.response_version(), StrEq("HTTP/1.0"));
      EXPECT_THAT(headers.response_code(), StrEq(response_code_second));
      EXPECT_THAT(headers.response_reason_phrase(), StrEq("reason phrase"));
    }
  }
}

TEST(BalsaHeaders, TestAppendToHeader) {
  // Test the basic case of appending to a header.
  BalsaHeaders headers;
  headers.AppendHeader("foo", "foo_value");
  headers.AppendHeader("bar", "bar_value");
  headers.AppendToHeader("foo", "foo_value2");

  EXPECT_THAT(headers.GetHeader("foo"), StrEq("foo_value,foo_value2"));
  EXPECT_THAT(headers.GetHeader("bar"), StrEq("bar_value"));
}

TEST(BalsaHeaders, TestInitialAppend) {
  // Test that AppendToHeader works properly when the header did not already
  // exist.
  BalsaHeaders headers;
  headers.AppendToHeader("foo", "foo_value");
  EXPECT_THAT(headers.GetHeader("foo"), StrEq("foo_value"));
  headers.AppendToHeader("foo", "foo_value2");
  EXPECT_THAT(headers.GetHeader("foo"), StrEq("foo_value,foo_value2"));
}

TEST(BalsaHeaders, TestAppendAndRemove) {
  // Test that AppendToHeader works properly with removing.
  BalsaHeaders headers;
  headers.AppendToHeader("foo", "foo_value");
  EXPECT_THAT(headers.GetHeader("foo"), StrEq("foo_value"));
  headers.AppendToHeader("foo", "foo_value2");
  EXPECT_THAT(headers.GetHeader("foo"), StrEq("foo_value,foo_value2"));
  headers.RemoveAllOfHeader("foo");
  headers.AppendToHeader("foo", "foo_value3");
  EXPECT_THAT(headers.GetHeader("foo"), StrEq("foo_value3"));
  headers.AppendToHeader("foo", "foo_value4");
  EXPECT_THAT(headers.GetHeader("foo"), StrEq("foo_value3,foo_value4"));
}

TEST(BalsaHeaders, TestAppendToHeaderWithCommaAndSpace) {
  // Test the basic case of appending to a header with comma and space.
  BalsaHeaders headers;
  headers.AppendHeader("foo", "foo_value");
  headers.AppendHeader("bar", "bar_value");
  headers.AppendToHeaderWithCommaAndSpace("foo", "foo_value2");

  EXPECT_THAT(headers.GetHeader("foo"), StrEq("foo_value, foo_value2"));
  EXPECT_THAT(headers.GetHeader("bar"), StrEq("bar_value"));
}

TEST(BalsaHeaders, TestInitialAppendWithCommaAndSpace) {
  // Test that AppendToHeadeWithCommaAndSpace works properly when the
  // header did not already exist.
  BalsaHeaders headers;
  headers.AppendToHeaderWithCommaAndSpace("foo", "foo_value");
  EXPECT_THAT(headers.GetHeader("foo"), StrEq("foo_value"));
  headers.AppendToHeaderWithCommaAndSpace("foo", "foo_value2");
  EXPECT_THAT(headers.GetHeader("foo"), StrEq("foo_value, foo_value2"));
}

TEST(BalsaHeaders, TestAppendWithCommaAndSpaceAndRemove) {
  // Test that AppendToHeadeWithCommaAndSpace works properly with removing.
  BalsaHeaders headers;
  headers.AppendToHeaderWithCommaAndSpace("foo", "foo_value");
  EXPECT_THAT(headers.GetHeader("foo"), StrEq("foo_value"));
  headers.AppendToHeaderWithCommaAndSpace("foo", "foo_value2");
  EXPECT_THAT(headers.GetHeader("foo"), StrEq("foo_value, foo_value2"));
  headers.RemoveAllOfHeader("foo");
  headers.AppendToHeaderWithCommaAndSpace("foo", "foo_value3");
  EXPECT_THAT(headers.GetHeader("foo"), StrEq("foo_value3"));
  headers.AppendToHeaderWithCommaAndSpace("foo", "foo_value4");
  EXPECT_THAT(headers.GetHeader("foo"), StrEq("foo_value3, foo_value4"));
}

TEST(BalsaHeaders, SetContentLength) {
  // Test that SetContentLength correctly sets the content-length header and
  // sets the content length status.
  BalsaHeaders headers;
  headers.SetContentLength(10);
  EXPECT_THAT(headers.GetHeader("Content-length"), StrEq("10"));
  EXPECT_EQ(BalsaHeadersEnums::VALID_CONTENT_LENGTH,
            headers.content_length_status());
  EXPECT_TRUE(headers.content_length_valid());

  // Test overwriting the content-length.
  headers.SetContentLength(0);
  EXPECT_THAT(headers.GetHeader("Content-length"), StrEq("0"));
  EXPECT_EQ(BalsaHeadersEnums::VALID_CONTENT_LENGTH,
            headers.content_length_status());
  EXPECT_TRUE(headers.content_length_valid());

  // Make sure there is only one header line after the overwrite.
  BalsaHeaders::const_header_lines_iterator iter =
      headers.GetHeaderPosition("Content-length");
  EXPECT_EQ(headers.lines().begin(), iter);
  EXPECT_EQ(headers.lines().end(), ++iter);

  // Test setting the same content-length again, this should be no-op.
  headers.SetContentLength(0);
  EXPECT_THAT(headers.GetHeader("Content-length"), StrEq("0"));
  EXPECT_EQ(BalsaHeadersEnums::VALID_CONTENT_LENGTH,
            headers.content_length_status());
  EXPECT_TRUE(headers.content_length_valid());

  // Make sure the number of header lines didn't change.
  iter = headers.GetHeaderPosition("Content-length");
  EXPECT_EQ(headers.lines().begin(), iter);
  EXPECT_EQ(headers.lines().end(), ++iter);
}

TEST(BalsaHeaders, ToggleChunkedEncoding) {
  // Test that SetTransferEncodingToChunkedAndClearContentLength correctly adds
  // chunk-encoding header and sets the transfer_encoding_is_chunked_
  // flag.
  BalsaHeaders headers;
  headers.SetTransferEncodingToChunkedAndClearContentLength();
  EXPECT_EQ("chunked", headers.GetAllOfHeaderAsString("Transfer-Encoding"));
  EXPECT_TRUE(headers.HasHeadersWithPrefix("Transfer-Encoding"));
  EXPECT_TRUE(headers.HasHeadersWithPrefix("transfer-encoding"));
  EXPECT_TRUE(headers.HasHeadersWithPrefix("transfer"));
  EXPECT_TRUE(headers.transfer_encoding_is_chunked());

  // Set it to the same value, nothing should change.
  headers.SetTransferEncodingToChunkedAndClearContentLength();
  EXPECT_EQ("chunked", headers.GetAllOfHeaderAsString("Transfer-Encoding"));
  EXPECT_TRUE(headers.HasHeadersWithPrefix("Transfer-Encoding"));
  EXPECT_TRUE(headers.HasHeadersWithPrefix("transfer-encoding"));
  EXPECT_TRUE(headers.HasHeadersWithPrefix("transfer"));
  EXPECT_TRUE(headers.transfer_encoding_is_chunked());
  BalsaHeaders::const_header_lines_iterator iter =
      headers.GetHeaderPosition("Transfer-Encoding");
  EXPECT_EQ(headers.lines().begin(), iter);
  EXPECT_EQ(headers.lines().end(), ++iter);

  // Removes the chunked encoding, and there should be no transfer-encoding
  // headers left.
  headers.SetNoTransferEncoding();
  EXPECT_FALSE(headers.HasHeader("Transfer-Encoding"));
  EXPECT_FALSE(headers.HasHeadersWithPrefix("Transfer-Encoding"));
  EXPECT_FALSE(headers.HasHeadersWithPrefix("transfer-encoding"));
  EXPECT_FALSE(headers.HasHeadersWithPrefix("transfer"));
  EXPECT_FALSE(headers.transfer_encoding_is_chunked());
  EXPECT_EQ(headers.lines().end(), headers.lines().begin());

  // Clear chunked again, this should be a no-op and the header should not
  // change.
  headers.SetNoTransferEncoding();
  EXPECT_FALSE(headers.HasHeader("Transfer-Encoding"));
  EXPECT_FALSE(headers.HasHeadersWithPrefix("Transfer-Encoding"));
  EXPECT_FALSE(headers.HasHeadersWithPrefix("transfer-encoding"));
  EXPECT_FALSE(headers.HasHeadersWithPrefix("transfer"));
  EXPECT_FALSE(headers.transfer_encoding_is_chunked());
  EXPECT_EQ(headers.lines().end(), headers.lines().begin());
}

TEST(BalsaHeaders, SetNoTransferEncodingByRemoveHeader) {
  // Tests that calling Remove() methods to clear the Transfer-Encoding
  // header correctly resets transfer_encoding_is_chunked_ internal state.
  BalsaHeaders headers;
  headers.SetTransferEncodingToChunkedAndClearContentLength();
  headers.RemoveAllOfHeader("Transfer-Encoding");
  EXPECT_FALSE(headers.transfer_encoding_is_chunked());

  headers.SetTransferEncodingToChunkedAndClearContentLength();
  std::vector<absl::string_view> headers_to_remove;
  headers_to_remove.emplace_back("Transfer-Encoding");
  headers.RemoveAllOfHeaderInList(headers_to_remove);
  EXPECT_FALSE(headers.transfer_encoding_is_chunked());

  headers.SetTransferEncodingToChunkedAndClearContentLength();
  headers.RemoveAllHeadersWithPrefix("Transfer");
  EXPECT_FALSE(headers.transfer_encoding_is_chunked());
}

TEST(BalsaHeaders, ClearContentLength) {
  // Test that ClearContentLength() removes the content-length header and
  // resets content_length_status().
  BalsaHeaders headers;
  headers.SetContentLength(10);
  headers.ClearContentLength();
  EXPECT_FALSE(headers.HasHeader("Content-length"));
  EXPECT_EQ(BalsaHeadersEnums::NO_CONTENT_LENGTH,
            headers.content_length_status());
  EXPECT_FALSE(headers.content_length_valid());

  // Clear it again; nothing should change.
  headers.ClearContentLength();
  EXPECT_FALSE(headers.HasHeader("Content-length"));
  EXPECT_EQ(BalsaHeadersEnums::NO_CONTENT_LENGTH,
            headers.content_length_status());
  EXPECT_FALSE(headers.content_length_valid());

  // Set chunked encoding and test that ClearContentLength() has no effect.
  headers.SetTransferEncodingToChunkedAndClearContentLength();
  headers.ClearContentLength();
  EXPECT_EQ("chunked", headers.GetAllOfHeaderAsString("Transfer-Encoding"));
  EXPECT_TRUE(headers.transfer_encoding_is_chunked());
  BalsaHeaders::const_header_lines_iterator iter =
      headers.GetHeaderPosition("Transfer-Encoding");
  EXPECT_EQ(headers.lines().begin(), iter);
  EXPECT_EQ(headers.lines().end(), ++iter);

  // Remove chunked encoding, and verify that the state is the same as after
  // ClearContentLength().
  headers.SetNoTransferEncoding();
  EXPECT_EQ(BalsaHeadersEnums::NO_CONTENT_LENGTH,
            headers.content_length_status());
  EXPECT_FALSE(headers.content_length_valid());
}

TEST(BalsaHeaders, ClearContentLengthByRemoveHeader) {
  // Test that calling Remove() methods to clear the content-length header
  // correctly resets internal content length fields.
  BalsaHeaders headers;
  headers.SetContentLength(10);
  headers.RemoveAllOfHeader("Content-Length");
  EXPECT_EQ(BalsaHeadersEnums::NO_CONTENT_LENGTH,
            headers.content_length_status());
  EXPECT_EQ(0u, headers.content_length());
  EXPECT_FALSE(headers.content_length_valid());

  headers.SetContentLength(11);
  std::vector<absl::string_view> headers_to_remove;
  headers_to_remove.emplace_back("Content-Length");
  headers.RemoveAllOfHeaderInList(headers_to_remove);
  EXPECT_EQ(BalsaHeadersEnums::NO_CONTENT_LENGTH,
            headers.content_length_status());
  EXPECT_EQ(0u, headers.content_length());
  EXPECT_FALSE(headers.content_length_valid());

  headers.SetContentLength(12);
  headers.RemoveAllHeadersWithPrefix("Content");
  EXPECT_EQ(BalsaHeadersEnums::NO_CONTENT_LENGTH,
            headers.content_length_status());
  EXPECT_EQ(0u, headers.content_length());
  EXPECT_FALSE(headers.content_length_valid());
}

// Chunk-encoding an identity-coded BalsaHeaders removes the identity-coding.
TEST(BalsaHeaders, IdentityCodingToChunked) {
  std::string message =
      "HTTP/1.1 200 OK\r\n"
      "Transfer-Encoding: identity\r\n\r\n";
  BalsaHeaders headers;
  BalsaFrame balsa_frame;
  balsa_frame.set_is_request(false);
  balsa_frame.set_balsa_headers(&headers);
  EXPECT_EQ(message.size(),
            balsa_frame.ProcessInput(message.data(), message.size()));

  EXPECT_TRUE(headers.is_framed_by_connection_close());
  EXPECT_FALSE(headers.transfer_encoding_is_chunked());
  EXPECT_THAT(headers.GetAllOfHeader("Transfer-Encoding"),
              ElementsAre("identity"));

  headers.SetTransferEncodingToChunkedAndClearContentLength();

  EXPECT_FALSE(headers.is_framed_by_connection_close());
  EXPECT_TRUE(headers.transfer_encoding_is_chunked());
  EXPECT_THAT(headers.GetAllOfHeader("Transfer-Encoding"),
              ElementsAre("chunked"));
}

TEST(BalsaHeaders, SwitchContentLengthToChunk) {
  // Test that a header originally with content length header is correctly
  // switched to using chunk encoding.
  BalsaHeaders headers;
  headers.SetContentLength(10);
  EXPECT_THAT(headers.GetHeader("Content-length"), StrEq("10"));
  EXPECT_EQ(BalsaHeadersEnums::VALID_CONTENT_LENGTH,
            headers.content_length_status());
  EXPECT_TRUE(headers.content_length_valid());

  headers.SetTransferEncodingToChunkedAndClearContentLength();
  EXPECT_EQ("chunked", headers.GetAllOfHeaderAsString("Transfer-Encoding"));
  EXPECT_TRUE(headers.transfer_encoding_is_chunked());
  EXPECT_FALSE(headers.HasHeader("Content-length"));
  EXPECT_EQ(BalsaHeadersEnums::NO_CONTENT_LENGTH,
            headers.content_length_status());
  EXPECT_FALSE(headers.content_length_valid());
}

TEST(BalsaHeaders, SwitchChunkedToContentLength) {
  // Test that a header originally with chunk encoding is correctly
  // switched to using content length.
  BalsaHeaders headers;
  headers.SetTransferEncodingToChunkedAndClearContentLength();
  EXPECT_EQ("chunked", headers.GetAllOfHeaderAsString("Transfer-Encoding"));
  EXPECT_TRUE(headers.transfer_encoding_is_chunked());
  EXPECT_FALSE(headers.HasHeader("Content-length"));
  EXPECT_EQ(BalsaHeadersEnums::NO_CONTENT_LENGTH,
            headers.content_length_status());
  EXPECT_FALSE(headers.content_length_valid());

  headers.SetContentLength(10);
  EXPECT_THAT(headers.GetHeader("Content-length"), StrEq("10"));
  EXPECT_EQ(BalsaHeadersEnums::VALID_CONTENT_LENGTH,
            headers.content_length_status());
  EXPECT_TRUE(headers.content_length_valid());
  EXPECT_FALSE(headers.HasHeader("Transfer-Encoding"));
  EXPECT_FALSE(headers.transfer_encoding_is_chunked());
}

TEST(BalsaHeaders, OneHundredResponseMessagesNoFramedByClose) {
  BalsaHeaders headers;
  headers.SetResponseFirstline("HTTP/1.1", 100, "Continue");
  EXPECT_FALSE(headers.is_framed_by_connection_close());
}

TEST(BalsaHeaders, TwoOhFourResponseMessagesNoFramedByClose) {
  BalsaHeaders headers;
  headers.SetResponseFirstline("HTTP/1.1", 204, "Continue");
  EXPECT_FALSE(headers.is_framed_by_connection_close());
}

TEST(BalsaHeaders, ThreeOhFourResponseMessagesNoFramedByClose) {
  BalsaHeaders headers;
  headers.SetResponseFirstline("HTTP/1.1", 304, "Continue");
  EXPECT_FALSE(headers.is_framed_by_connection_close());
}

TEST(BalsaHeaders, InvalidCharInHeaderValue) {
  std::string message =
      "GET http://www.256.com/foo HTTP/1.1\r\n"
      "Host: \x01\x01www.265.com\r\n"
      "\r\n";
  BalsaHeaders headers = CreateHTTPHeaders(true, message);
  EXPECT_EQ("www.265.com", headers.GetHeader("Host"));
  SimpleBuffer buffer;
  headers.WriteHeaderAndEndingToBuffer(&buffer);
  message.replace(message.find_first_of(0x1), 2, "");
  EXPECT_EQ(message, buffer.GetReadableRegion());
}

TEST(BalsaHeaders, CarriageReturnAtStartOfLine) {
  std::string message =
      "GET /foo HTTP/1.1\r\n"
      "Host: www.265.com\r\n"
      "Foo: bar\r\n"
      "\rX-User-Ip: 1.2.3.4\r\n"
      "\r\n";
  BalsaHeaders headers;
  BalsaFrame balsa_frame;
  balsa_frame.set_is_request(true);
  balsa_frame.set_balsa_headers(&headers);
  EXPECT_EQ(message.size(),
            balsa_frame.ProcessInput(message.data(), message.size()));
  EXPECT_EQ(BalsaFrameEnums::INVALID_HEADER_FORMAT, balsa_frame.ErrorCode());
  EXPECT_TRUE(balsa_frame.Error());
}

TEST(BalsaHeaders, CheckEmpty) {
  BalsaHeaders headers;
  EXPECT_TRUE(headers.IsEmpty());
}

TEST(BalsaHeaders, CheckNonEmpty) {
  BalsaHeaders headers;
  BalsaHeadersTestPeer::WriteFromFramer(&headers, "a b c", 5);
  EXPECT_FALSE(headers.IsEmpty());
}

TEST(BalsaHeaders, ForEachHeader) {
  BalsaHeaders headers;
  headers.AppendHeader(":host", "SomeHost");
  headers.AppendHeader("key", "val1,val2val2,val2,val3");
  headers.AppendHeader("key", "val4val5val6");
  headers.AppendHeader("key", "val11 val12");
  headers.AppendHeader("key", "v val13");
  headers.AppendHeader("key", "val7");
  headers.AppendHeader("key", "");
  headers.AppendHeader("key", "val8 , val9 ,, val10");
  headers.AppendHeader("key", " val14 ");
  headers.AppendHeader("key2", "val15");
  headers.AppendHeader("key", "Val16");
  headers.AppendHeader("key", "foo, Val17, bar");
  headers.AppendHeader("date", "2 Jan 1970");
  headers.AppendHeader("AcceptEncoding", "MyFavoriteEncoding");

  {
    std::string result;
    EXPECT_TRUE(headers.ForEachHeader(
        [&result](const absl::string_view key, absl::string_view value) {
          result.append("<")
              .append(key.data(), key.size())
              .append("> = <")
              .append(value.data(), value.size())
              .append(">\n");
          return true;
        }));

    EXPECT_EQ(result,
              "<:host> = <SomeHost>\n"
              "<key> = <val1,val2val2,val2,val3>\n"
              "<key> = <val4val5val6>\n"
              "<key> = <val11 val12>\n"
              "<key> = <v val13>\n"
              "<key> = <val7>\n"
              "<key> = <>\n"
              "<key> = <val8 , val9 ,, val10>\n"
              "<key> = < val14 >\n"
              "<key2> = <val15>\n"
              "<key> = <Val16>\n"
              "<key> = <foo, Val17, bar>\n"
              "<date> = <2 Jan 1970>\n"
              "<AcceptEncoding> = <MyFavoriteEncoding>\n");
  }

  {
    std::string result;
    EXPECT_FALSE(headers.ForEachHeader(
        [&result](const absl::string_view key, absl::string_view value) {
          result.append("<")
              .append(key.data(), key.size())
              .append("> = <")
              .append(value.data(), value.size())
              .append(">\n");
          return !value.empty();
        }));

    EXPECT_EQ(result,
              "<:host> = <SomeHost>\n"
              "<key> = <val1,val2val2,val2,val3>\n"
              "<key> = <val4val5val6>\n"
              "<key> = <val11 val12>\n"
              "<key> = <v val13>\n"
              "<key> = <val7>\n"
              "<key> = <>\n");
  }
}

TEST(BalsaHeaders, WriteToBufferWithLowerCasedHeaderKey) {
  BalsaHeaders headers;
  headers.SetRequestFirstlineFromStringPieces("GET", "/", "HTTP/1.0");
  headers.AppendHeader("Key1", "value1");
  headers.AppendHeader("Key2", "value2");
  std::string expected_lower_case =
      "GET / HTTP/1.0\r\n"
      "key1: value1\r\n"
      "key2: value2\r\n";
  std::string expected_lower_case_with_end =
      "GET / HTTP/1.0\r\n"
      "key1: value1\r\n"
      "key2: value2\r\n\r\n";
  std::string expected_upper_case =
      "GET / HTTP/1.0\r\n"
      "Key1: value1\r\n"
      "Key2: value2\r\n";
  std::string expected_upper_case_with_end =
      "GET / HTTP/1.0\r\n"
      "Key1: value1\r\n"
      "Key2: value2\r\n\r\n";

  SimpleBuffer simple_buffer;
  headers.WriteToBuffer(&simple_buffer, BalsaHeaders::CaseOption::kLowercase,
                        BalsaHeaders::CoalesceOption::kNoCoalesce);
  EXPECT_THAT(simple_buffer.GetReadableRegion(), StrEq(expected_lower_case));

  simple_buffer.Clear();
  headers.WriteToBuffer(&simple_buffer);
  EXPECT_THAT(simple_buffer.GetReadableRegion(), StrEq(expected_upper_case));

  simple_buffer.Clear();
  headers.WriteHeaderAndEndingToBuffer(&simple_buffer);
  EXPECT_THAT(simple_buffer.GetReadableRegion(),
              StrEq(expected_upper_case_with_end));

  simple_buffer.Clear();
  headers.WriteHeaderAndEndingToBuffer(
      &simple_buffer, BalsaHeaders::CaseOption::kLowercase,
      BalsaHeaders::CoalesceOption::kNoCoalesce);
  EXPECT_THAT(simple_buffer.GetReadableRegion(),
              StrEq(expected_lower_case_with_end));
}

TEST(BalsaHeaders, WriteToBufferWithProperCasedHeaderKey) {
  BalsaHeaders headers;
  headers.SetRequestFirstlineFromStringPieces("GET", "/", "HTTP/1.0");
  headers.AppendHeader("Te", "value1");
  headers.AppendHeader("my-Test-header", "value2");
  std::string expected_proper_case =
      "GET / HTTP/1.0\r\n"
      "TE: value1\r\n"
      "My-Test-Header: value2\r\n";
  std::string expected_proper_case_with_end =
      "GET / HTTP/1.0\r\n"
      "TE: value1\r\n"
      "My-Test-Header: value2\r\n\r\n";
  std::string expected_unmodified =
      "GET / HTTP/1.0\r\n"
      "Te: value1\r\n"
      "my-Test-header: value2\r\n";
  std::string expected_unmodified_with_end =
      "GET / HTTP/1.0\r\n"
      "Te: value1\r\n"
      "my-Test-header: value2\r\n\r\n";

  SimpleBuffer simple_buffer;
  headers.WriteToBuffer(&simple_buffer, BalsaHeaders::CaseOption::kPropercase,
                        BalsaHeaders::CoalesceOption::kNoCoalesce);
  EXPECT_EQ(simple_buffer.GetReadableRegion(), expected_proper_case);

  simple_buffer.Clear();
  headers.WriteToBuffer(&simple_buffer,
                        BalsaHeaders::CaseOption::kNoModification,
                        BalsaHeaders::CoalesceOption::kNoCoalesce);
  EXPECT_EQ(simple_buffer.GetReadableRegion(), expected_unmodified);

  simple_buffer.Clear();
  headers.WriteHeaderAndEndingToBuffer(
      &simple_buffer, BalsaHeaders::CaseOption::kNoModification,
      BalsaHeaders::CoalesceOption::kNoCoalesce);
  EXPECT_EQ(simple_buffer.GetReadableRegion(), expected_unmodified_with_end);

  simple_buffer.Clear();
  headers.WriteHeaderAndEndingToBuffer(
      &simple_buffer, BalsaHeaders::CaseOption::kPropercase,
      BalsaHeaders::CoalesceOp
```