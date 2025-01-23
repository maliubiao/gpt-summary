Response:
The user wants a summary of the functionalities present in the provided C++ code snippet. The code is a part of the Chromium network stack, specifically dealing with HTTP frame parsing.

Here's a breakdown of the code's features and how to approach the summarization:

1. **Core Functionality:** The code primarily tests the `BalsaFrame` class, which is responsible for parsing HTTP frames (requests and responses). This involves verifying the parsing of the first line (request line or status line), headers, and potentially chunked bodies and trailers.

2. **Testing Scenarios:** The tests cover various scenarios, including:
    * Valid and invalid first lines (HTTP version, status codes, request methods, URLs).
    * Handling different whitespace in the first line and headers.
    * Parsing headers with different delimiters and line endings.
    * Handling header continuations.
    * Testing the visitor pattern for notifying about parsed parts of the message.
    * Handling messages with zero content length and missing content length.
    * Parsing chunked transfer encoding, including chunk extensions and trailers.
    * Testing error conditions (invalid characters, chunk length overflows, etc.).
    * Testing behavior when no visitor is set or the visitor is changed during parsing.

3. **Key Classes and Concepts:**
    * `HTTPBalsaFrameTest`: A test fixture providing setup and helper functions for testing `BalsaFrame`.
    * `BalsaFrame`: The class under test, responsible for parsing HTTP frames.
    * `BalsaHeaders`:  A class to store parsed HTTP headers.
    * `BalsaVisitor`: An interface used to notify the client about parsed parts of the HTTP message.
    * `HttpValidationPolicy`: A class to configure how strictly the parser validates the HTTP message.
    * `BalsaFrameEnums::ErrorCode`: Enumeration of possible error codes during parsing.

4. **JavaScript Relevance:**  While the code is in C++, its functionality is directly related to how web browsers (like Chrome) process HTTP messages. JavaScript running in a browser interacts with the results of this parsing.

5. **Logical Inference and Error Handling:** The tests demonstrate logical inference by verifying that given specific input, the `BalsaFrame` parser produces the expected output or error. The error handling tests cover common mistakes in HTTP message formatting.

6. **User Interaction and Debugging:** Understanding how the parser works is crucial for debugging network issues. The tests indirectly show the path a user action takes by triggering specific HTTP requests or responses that are then processed by this code.

**Plan for Summarization:**

* Start with the main purpose: testing the HTTP frame parsing functionality.
* Highlight the different aspects of parsing that are tested (first line, headers, chunking, trailers).
* Mention the role of the visitor pattern and error handling.
* Briefly touch on the JavaScript connection as this code underpins browser networking.
这是对 Chromium 网络栈中 `net/third_party/quiche/src/quiche/balsa/balsa_frame_test.cc` 文件部分源代码的分析，主要关注 HTTP 响应首行的解析和 HTTP 头的解析功能测试。

**功能归纳 (第2部分):**

这部分代码主要集中在测试 `BalsaFrame` 类在处理 **HTTP 响应** 消息时的首行（状态行）和后续的 HTTP 头的解析功能，并验证了以下几个方面：

1. **响应状态码的解析:**
   - 测试了正确解析合法的数字响应状态码。
   - 测试了解析非数字、负数的响应状态码时应该产生的错误。
   - 测试了响应状态码后缺少空格的情况。
   - 测试了响应状态码后存在尾部空格的情况。

2. **响应状态行的正确解析:**
   - 使用 `FirstLineParsedCorrectlyHelper` 函数，通过不同的分隔符（空格和制表符）组合，验证了状态行各个部分的正确解析，包括 HTTP 版本、状态码和原因短语。

3. **状态行的清理 (Sanitization):**
   - 测试了在不同的 `HttpValidationPolicy` 设置下，如何处理状态行中的非法空格字符（如 `\r` 和 `\t`）。
   - 验证了 `NONE` (不处理), `SANITIZE` (清理替换), `REJECT` (拒绝并报错) 三种策略下的行为和预期的错误码。

4. **HTTP 头的解析:**
   - 通过 `HeaderLineTestHelper` 函数，针对请求和响应消息，测试了 HTTP 头的正确解析，包括：
     - 不同的键值对分隔符 (`:`, `: `, `:\t` 等)。
     - 不同的行尾符 (`\n`, `\r\n`)。
     - 包含特殊字符（如冒号、回车）的头值。
     - 头部的延续行（以空格或制表符开头的行）。
     - 空的键或值。
     - 键值都为空的情况。

5. **非法字符的检测:**
   - 测试了当 `HttpValidationPolicy` 设置为禁止请求头中出现单独的 `\r` 时，`BalsaFrame` 能否正确检测并报错。
   - 特别测试了 `\r` 出现在输入边界的情况。
   - 测试了 HTTP 头键中包含非法字符 (`\r`) 的情况。

6. **处理头部的空白行:**
   - 通过 `WhitespaceHeaderTestHelper` 函数，测试了在请求和响应消息中，单独包含空格或制表符的行是否会产生错误。
   - 测试了正确的头部延续行的处理。
   - 测试了头部中可能被误认为是延续行的特殊情况。

7. **Visitor 模式的应用:**
   - 测试了在解析简单的 HTTP 请求时，`BalsaVisitor` 的各个回调函数 (`OnRequestFirstLineInput`, `ProcessHeaders`, `HeaderDone`, `MessageDone`) 是否被正确调用，并传递了预期的参数。
   - 测试了在请求头之前存在空白行的情况下，`BalsaVisitor` 的调用情况。
   - 测试了 content-length 为 0 的请求的处理。
   - 测试了缺少 content-length 但需要 body 的请求的处理，以及通过设置 `HttpValidationPolicy` 可以允许缺少 content-length 的情况。
   - 测试了 `Connection` 头中只有逗号分隔符的情况。
   - 测试了在解析过程中将 `BalsaVisitor` 设置为 `nullptr` 的情况。

8. **Chunked 传输编码的处理:**
   - 测试了带有 trailers 的 chunked 请求的处理，并验证了 `OnTrailers` 回调函数的调用。
   - 测试了在响应消息中使用 chunked 传输编码的情况。
   - 测试了 `transfer-encoding: identity` 被忽略的情况。
   - 测试了在 chunked 数据解析过程中将 `BalsaVisitor` 设置为 `nullptr` 的情况。
   - 测试了 chunked 长度溢出的错误处理。
   - 测试了 chunked 长度可以使用分号分隔的扩展字段的情况。
   - 测试了 chunked 长度包含非 ASCII 字符导致错误的情况。

**与 JavaScript 的关系举例说明:**

虽然这是 C++ 代码，但它直接影响着浏览器（例如 Chrome）如何解析从服务器接收到的 HTTP 响应。当 JavaScript 通过 `fetch` API 或 `XMLHttpRequest` 发起网络请求后，浏览器接收到的 HTTP 响应会经过类似 `BalsaFrame` 这样的解析器。

**举例:**

假设一个 JavaScript 代码发起了一个 `fetch` 请求，服务器返回的响应头中包含一个非法的状态行，例如：

```
HTTP/1.1 0x3 Not Valid
Content-Type: text/plain
Content-Length: 10

Hello World!
```

`BalsaFrame` 在解析到 `"HTTP/1.1 0x3 Not Valid"` 时，会因为 `"0x3"` 不是一个合法的数字状态码而产生错误 (对应 `TEST_F(HTTPBalsaFrameTest, NonnumericResponseCode)` 测试用例)。这个错误最终可能会被浏览器内部的网络层捕获，并影响到 `fetch` API 返回的 `Response` 对象的状态。例如，`response.ok` 可能会返回 `false`，并且 `response.status` 可能无法正确表示。JavaScript 开发者可以通过检查 `Response` 对象的状态来了解请求是否成功，但这背后的实现就依赖于像 `BalsaFrame` 这样的底层解析器。

**逻辑推理的假设输入与输出:**

**假设输入:**

```
std::string input = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n";
```

**假设输出 (基于 `VisitorInvokedProperlyForTrivialRequest` 的逻辑):**

如果 `balsa_frame_` 被配置为处理响应，并且设置了一个 `visitor_mock_`，那么预期会调用 `visitor_mock_` 的以下方法：

- `OnResponseFirstLineInput("HTTP/1.1 404 Not Found", "HTTP/1.1", "404", "Not Found")`
- `ProcessHeaders` (传入包含 `Content-Type: application/json` 的 `BalsaHeaders` 对象)
- `HeaderDone()`
- `MessageDone()`
- `OnHeaderInput("HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n")`

**用户或编程常见的使用错误举例说明:**

一个常见的用户或编程错误是在手动构建 HTTP 响应时，错误地添加了不符合 HTTP 规范的字符或格式。

**举例:**

一个后端开发者可能错误地生成了如下的响应头：

```
HTTP/1.1 200 OK\n
Content-Type: text/html\r
Content-Length: 13\n
\n
Hello, World!
```

在这个例子中：

- 首行使用了 `\n` 而不是 `\r\n`。
- `Content-Type` 头部使用了 `\r` 而不是 `\r\n`。
- `Content-Length` 头部使用了 `\n` 而不是 `\r\n`。

当浏览器接收到这样的响应时，`BalsaFrame` 在解析这些头部时会检测到这些不符合规范的换行符，并可能产生错误（例如，`INVALID_HEADER_LINE_ENDING`，虽然在这个代码片段中没有直接测试这种错误，但相关的机制是存在的）。这可能导致浏览器无法正确解析响应头，从而影响页面的加载或 JavaScript 代码的执行。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入 URL 或点击链接:** 这会触发浏览器发起 HTTP 请求。
2. **服务器处理请求并生成 HTTP 响应:**  服务器按照 HTTP 协议构建响应消息。
3. **网络传输:**  响应消息通过网络传输到用户的浏览器。
4. **浏览器接收到响应数据:**  浏览器接收到的是字节流形式的 HTTP 响应。
5. **`BalsaFrame` 进行 HTTP 响应解析:**  `BalsaFrame` (或类似的 HTTP 解析器) 负责将接收到的字节流解析成有意义的 HTTP 结构，包括状态行和头部。
6. **测试覆盖了各种解析场景:**  `balsa_frame_test.cc` 中的测试用例模拟了各种可能的响应格式，包括错误的情况，以确保 `BalsaFrame` 能够正确处理并报告错误。

如果用户遇到网页加载错误、资源加载失败等问题，网络工程师或前端开发者在调试时，可以使用浏览器的开发者工具查看网络请求的详细信息，包括响应头。如果响应头格式不正确，很可能就是 `BalsaFrame` 这样的解析器在底层发现了问题。通过分析 `BalsaFrame` 的源代码和测试用例，可以更好地理解浏览器是如何处理这些错误，并帮助定位问题根源是出在服务器端还是网络传输过程中。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/balsa/balsa_frame_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
parsed);
    EXPECT_EQ(framer.ErrorCode(), expected_error);
  }
}

TEST_F(HTTPBalsaFrameTest, NonnumericResponseCode) {
  balsa_frame_.set_is_request(false);

  VerifyFirstLineParsing("HTTP/1.1 0x3 Digits only\r\n\r\n",
                         BalsaFrameEnums::FAILED_CONVERTING_STATUS_CODE_TO_INT);

  EXPECT_EQ("HTTP/1.1 0x3 Digits only", headers_.first_line());
}

TEST_F(HTTPBalsaFrameTest, NegativeResponseCode) {
  balsa_frame_.set_is_request(false);

  VerifyFirstLineParsing("HTTP/1.1 -11 No sign allowed\r\n\r\n",
                         BalsaFrameEnums::FAILED_CONVERTING_STATUS_CODE_TO_INT);

  EXPECT_EQ("HTTP/1.1 -11 No sign allowed", headers_.first_line());
}

TEST_F(HTTPBalsaFrameTest, WithoutTrailingWhitespace) {
  balsa_frame_.set_is_request(false);

  VerifyFirstLineParsing(
      "HTTP/1.1 101\r\n\r\n",
      BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_RESPONSE_STATUSCODE);

  EXPECT_EQ("HTTP/1.1 101", headers_.first_line());
}

TEST_F(HTTPBalsaFrameTest, TrailingWhitespace) {
  balsa_frame_.set_is_request(false);

  // b/69446061
  std::string firstline = "HTTP/1.1 101 \r\n\r\n";
  balsa_frame_.ProcessInput(firstline.data(), firstline.size());

  EXPECT_EQ("HTTP/1.1 101 ", headers_.first_line());
}

TEST(HTTPBalsaFrame, ResponseFirstLineParsedCorrectly) {
  const char* response_tokens[3] = {"HTTP/1.1", "200", "A reason\tphrase"};
  FirstLineParsedCorrectlyHelper(response_tokens, 200, false, " ");
  FirstLineParsedCorrectlyHelper(response_tokens, 200, false, "\t");
  FirstLineParsedCorrectlyHelper(response_tokens, 200, false, "\t    ");
  FirstLineParsedCorrectlyHelper(response_tokens, 200, false, "   \t");
  FirstLineParsedCorrectlyHelper(response_tokens, 200, false, "   \t \t  ");

  response_tokens[1] = "312";
  FirstLineParsedCorrectlyHelper(response_tokens, 312, false, " ");
  FirstLineParsedCorrectlyHelper(response_tokens, 312, false, "\t");
  FirstLineParsedCorrectlyHelper(response_tokens, 312, false, "\t    ");
  FirstLineParsedCorrectlyHelper(response_tokens, 312, false, "   \t");
  FirstLineParsedCorrectlyHelper(response_tokens, 312, false, "   \t \t  ");

  // Who knows what the future may hold w.r.t. response codes?!
  response_tokens[1] = "4242";
  FirstLineParsedCorrectlyHelper(response_tokens, 4242, false, " ");
  FirstLineParsedCorrectlyHelper(response_tokens, 4242, false, "\t");
  FirstLineParsedCorrectlyHelper(response_tokens, 4242, false, "\t    ");
  FirstLineParsedCorrectlyHelper(response_tokens, 4242, false, "   \t");
  FirstLineParsedCorrectlyHelper(response_tokens, 4242, false, "   \t \t  ");
}

TEST(HTTPBalsaFrame, StatusLineSanitizedProperly) {
  SCOPED_TRACE("Testing that the status line is properly sanitized.");
  using enum HttpValidationPolicy::FirstLineValidationOption;
  using FirstLineValidationOption =
      HttpValidationPolicy::FirstLineValidationOption;

  struct TestCase {
    const absl::string_view input;     // Input to the parser.
    const absl::string_view parsed;    // Expected output.
    FirstLineValidationOption option;  // Whether to sanitize/reject.
    BalsaFrameEnums::ErrorCode expected_error;
  };
  const std::vector<TestCase> cases = {
      // No invalid whitespace.
      {"HTTP/1.1 200 OK\r\n", "HTTP/1.1 200 OK", NONE,
       BalsaFrameEnums::BALSA_NO_ERROR},
      {"HTTP/1.1 200 OK\r\n", "HTTP/1.1 200 OK", SANITIZE,
       BalsaFrameEnums::BALSA_NO_ERROR},
      {"HTTP/1.1 200 OK\r\n", "HTTP/1.1 200 OK", REJECT,
       BalsaFrameEnums::BALSA_NO_ERROR},

      // Illegal CR in the status-line.
      {"HTTP/1.1 200\rOK\r\n", "HTTP/1.1 200\rOK", NONE,
       BalsaFrameEnums::BALSA_NO_ERROR},
      {"HTTP/1.1 200\rOK\r\n", "HTTP/1.1 200 OK", SANITIZE,
       BalsaFrameEnums::BALSA_NO_ERROR},
      {"HTTP/1.1 200\rOK\r\n", "", REJECT,
       BalsaFrameEnums::INVALID_WS_IN_STATUS_LINE},

      // Invalid tab in the status-line.
      {"HTTP/1.1 \t200 OK\r\n", "HTTP/1.1 \t200 OK", NONE,
       BalsaFrameEnums::BALSA_NO_ERROR},
      {"HTTP/1.1 \t200 OK\r\n", "HTTP/1.1  200 OK", SANITIZE,
       BalsaFrameEnums::BALSA_NO_ERROR},
      {"HTTP/1.1 \t200 OK\r\n", "", REJECT,
       BalsaFrameEnums::INVALID_WS_IN_STATUS_LINE},

      // Both CR and tab in the request-line.
      {"HTTP/1.1 \t200\rOK \r\n", "HTTP/1.1 \t200\rOK", NONE,
       BalsaFrameEnums::BALSA_NO_ERROR},
      {"HTTP/1.1 \t200\rOK \r\n", "HTTP/1.1  200 OK", SANITIZE,
       BalsaFrameEnums::BALSA_NO_ERROR},
      {"HTTP/1.1 \t200\rOK \r\n", "", REJECT,
       BalsaFrameEnums::INVALID_WS_IN_STATUS_LINE},
  };
  const absl::string_view kHeaderLineAndEnding =
      "Foo: bar\r\nContent-Length: 0\r\n\r\n";
  for (auto& [firstline, parsed, ws_option, expected_error] : cases) {
    SCOPED_TRACE(
        absl::StrCat("Input: ", absl::CEscape(firstline),
                     " Expected output: ", absl::CEscape(parsed),
                     " whitespace option: ", static_cast<int>(ws_option)));
    const std::string input = absl::StrCat(firstline, kHeaderLineAndEnding);

    BalsaHeaders headers;
    BalsaFrame framer;
    HttpValidationPolicy policy;
    policy.sanitize_cr_tab_in_first_line = ws_option;
    framer.set_http_validation_policy(policy);
    framer.set_is_request(false);
    framer.set_balsa_headers(&headers);
    framer.ProcessInput(input.data(), input.size());
    EXPECT_EQ(headers.first_line(), parsed);
    EXPECT_EQ(framer.ErrorCode(), expected_error);
  }
}

void HeaderLineTestHelper(const char* firstline, bool is_request,
                          const std::pair<std::string, std::string>* headers,
                          size_t headers_len, const char* colon,
                          const char* line_ending) {
  BalsaHeaders balsa_headers;
  BalsaFrame framer;
  framer.set_is_request(is_request);
  framer.set_balsa_headers(&balsa_headers);
  std::string message =
      CreateMessage(firstline, headers, headers_len, colon, line_ending, "");
  SCOPED_TRACE(EscapeString(message));
  size_t bytes_consumed = framer.ProcessInput(message.data(), message.size());
  EXPECT_EQ(message.size(), bytes_consumed);
  VerifyHeaderLines(headers, headers_len, *framer.headers());
}

TEST(HTTPBalsaFrame, RequestLinesParsedProperly) {
  SCOPED_TRACE("Testing that lines are properly parsed.");
  const char firstline[] = "GET / HTTP/1.1\r\n";
  const std::pair<std::string, std::string> headers[] = {
      std::pair<std::string, std::string>("foo", "bar"),
      std::pair<std::string, std::string>("duck", "water"),
      std::pair<std::string, std::string>("goose", "neck"),
      std::pair<std::string, std::string>("key_is_fine",
                                          "value:includes:colons"),
      std::pair<std::string, std::string>("trucks",
                                          "along\rvalue\rincluding\rslash\rrs"),
      std::pair<std::string, std::string>("monster", "truck"),
      std::pair<std::string, std::string>("another_key", ":colons in value"),
      std::pair<std::string, std::string>("another_key", "colons in value:"),
      std::pair<std::string, std::string>("another_key",
                                          "value includes\r\n continuation"),
      std::pair<std::string, std::string>("key_without_continuations",
                                          "multiple\n in\r\n the\n value"),
      std::pair<std::string, std::string>("key_without_value",
                                          ""),  // empty value
      std::pair<std::string, std::string>("",
                                          "value without key"),  // empty key
      std::pair<std::string, std::string>("", ""),  // both key and value empty
      std::pair<std::string, std::string>("normal_key", "normal_value"),
  };
  const size_t headers_len = ABSL_ARRAYSIZE(headers);
  HeaderLineTestHelper(firstline, true, headers, headers_len, ":", "\n");
  HeaderLineTestHelper(firstline, true, headers, headers_len, ": ", "\n");
  HeaderLineTestHelper(firstline, true, headers, headers_len, ": ", "\r\n");
  HeaderLineTestHelper(firstline, true, headers, headers_len, ":\t", "\n");
  HeaderLineTestHelper(firstline, true, headers, headers_len, ":\t", "\r\n");
  HeaderLineTestHelper(firstline, true, headers, headers_len, ":\t ", "\n");
  HeaderLineTestHelper(firstline, true, headers, headers_len, ":\t ", "\r\n");
  HeaderLineTestHelper(firstline, true, headers, headers_len, ":\t\t", "\n");
  HeaderLineTestHelper(firstline, true, headers, headers_len, ":\t\t", "\r\n");
  HeaderLineTestHelper(firstline, true, headers, headers_len, ":\t \t", "\n");
  HeaderLineTestHelper(firstline, true, headers, headers_len, ":\t \t", "\r\n");
}

TEST(HTTPBalsaFrame, CarriageReturnIllegalInHeaders) {
  HttpValidationPolicy policy{.disallow_lone_cr_in_request_headers = true};
  BalsaHeaders balsa_headers;
  BalsaFrame framer;
  framer.set_is_request(true);
  framer.set_balsa_headers(&balsa_headers);
  framer.set_http_validation_policy(policy);
  framer.set_invalid_chars_level(BalsaFrame::InvalidCharsLevel::kError);
  const std::pair<std::string, std::string> headers[] = {
      std::pair<std::string, std::string>("foo", "bar"),
      std::pair<std::string, std::string>("trucks", "value-has-solo-\r-in it"),
  };
  std::string message =
      CreateMessage("GET / \rHTTP/1.1\r\n", headers, 2, ":", "\r\n", "");
  framer.ProcessInput(message.data(), message.size());
  EXPECT_EQ(framer.ErrorCode(), BalsaFrameEnums::INVALID_HEADER_CHARACTER);
}

// Test that lone '\r' detection works correctly in the firstline
// even if it is the last character of fractional input.
TEST(HTTPBalsaFrame, CarriageReturnIllegalInFirstLineOnInputBoundary) {
  HttpValidationPolicy policy{.disallow_lone_cr_in_request_headers = true};
  BalsaHeaders balsa_headers;
  BalsaFrame framer;
  framer.set_is_request(true);
  framer.set_balsa_headers(&balsa_headers);
  framer.set_http_validation_policy(policy);
  framer.set_invalid_chars_level(BalsaFrame::InvalidCharsLevel::kError);
  constexpr absl::string_view message1("GET / \r");
  constexpr absl::string_view message2("HTTP/1.1\r\n\r\n");
  EXPECT_EQ(message1.size(),
            framer.ProcessInput(message1.data(), message1.size()));
  EXPECT_EQ(message2.size(),
            framer.ProcessInput(message2.data(), message2.size()));
  EXPECT_EQ(framer.ErrorCode(), BalsaFrameEnums::INVALID_HEADER_CHARACTER);
}

// Test that lone '\r' detection works correctly in header values
// even if it is the last character of fractional input.
TEST(HTTPBalsaFrame, CarriageReturnIllegalInHeaderValueOnInputBoundary) {
  HttpValidationPolicy policy{.disallow_lone_cr_in_request_headers = true};
  BalsaHeaders balsa_headers;
  BalsaFrame framer;
  framer.set_is_request(true);
  framer.set_balsa_headers(&balsa_headers);
  framer.set_http_validation_policy(policy);
  framer.set_invalid_chars_level(BalsaFrame::InvalidCharsLevel::kError);
  constexpr absl::string_view message1("GET / HTTP/1.1\r\nfoo: b\r");
  constexpr absl::string_view message2("ar\r\n\r\n");
  EXPECT_EQ(message1.size(),
            framer.ProcessInput(message1.data(), message1.size()));
  EXPECT_EQ(message2.size(),
            framer.ProcessInput(message2.data(), message2.size()));
  EXPECT_EQ(framer.ErrorCode(), BalsaFrameEnums::INVALID_HEADER_CHARACTER);
}

TEST(HTTPBalsaFrame, CarriageReturnIllegalInHeaderKey) {
  BalsaHeaders balsa_headers;
  BalsaFrame framer;
  framer.set_is_request(true);
  framer.set_balsa_headers(&balsa_headers);
  framer.set_invalid_chars_level(BalsaFrame::InvalidCharsLevel::kError);
  const std::pair<std::string, std::string> headers[] = {
      std::pair<std::string, std::string>("tru\rcks", "along"),
  };
  std::string message =
      CreateMessage("GET / HTTP/1.1\r\n", headers, 1, ":", "\r\n", "");
  framer.ProcessInput(message.data(), message.size());
  EXPECT_EQ(framer.ErrorCode(), BalsaFrameEnums::INVALID_HEADER_NAME_CHARACTER);
}

TEST(HTTPBalsaFrame, ResponseLinesParsedProperly) {
  SCOPED_TRACE("ResponseLineParsedProperly");
  const char firstline[] = "HTTP/1.0 200 A reason\tphrase\r\n";
  const std::pair<std::string, std::string> headers[] = {
      std::pair<std::string, std::string>("foo", "bar"),
      std::pair<std::string, std::string>("duck", "water"),
      std::pair<std::string, std::string>("goose", "neck"),
      std::pair<std::string, std::string>("key_is_fine",
                                          "value:includes:colons"),
      std::pair<std::string, std::string>("trucks",
                                          "along\rvalue\rincluding\rslash\rrs"),
      std::pair<std::string, std::string>("monster", "truck"),
      std::pair<std::string, std::string>("another_key", ":colons in value"),
      std::pair<std::string, std::string>("another_key", "colons in value:"),
      std::pair<std::string, std::string>("another_key",
                                          "value includes\r\n continuation"),
      std::pair<std::string, std::string>("key_includes_no_continuations",
                                          "multiple\n in\r\n the\n value"),
      std::pair<std::string, std::string>("key_without_value",
                                          ""),  // empty value
      std::pair<std::string, std::string>("",
                                          "value without key"),  // empty key
      std::pair<std::string, std::string>("", ""),  // both key and value empty
      std::pair<std::string, std::string>("normal_key", "normal_value"),
  };
  const size_t headers_len = ABSL_ARRAYSIZE(headers);
  HeaderLineTestHelper(firstline, false, headers, headers_len, ":", "\n");
  HeaderLineTestHelper(firstline, false, headers, headers_len, ": ", "\n");
  HeaderLineTestHelper(firstline, false, headers, headers_len, ": ", "\r\n");
  HeaderLineTestHelper(firstline, false, headers, headers_len, ":\t", "\n");
  HeaderLineTestHelper(firstline, false, headers, headers_len, ":\t", "\r\n");
  HeaderLineTestHelper(firstline, false, headers, headers_len, ":\t ", "\n");
  HeaderLineTestHelper(firstline, false, headers, headers_len, ":\t ", "\r\n");
  HeaderLineTestHelper(firstline, false, headers, headers_len, ":\t\t", "\n");
  HeaderLineTestHelper(firstline, false, headers, headers_len, ":\t\t", "\r\n");
  HeaderLineTestHelper(firstline, false, headers, headers_len, ":\t \t", "\n");
  HeaderLineTestHelper(firstline, false, headers, headers_len, ":\t \t",
                       "\r\n");
}

void WhitespaceHeaderTestHelper(
    const std::string& message, bool is_request,
    BalsaFrameEnums::ErrorCode expected_error_code) {
  BalsaHeaders balsa_headers;
  BalsaFrame framer;
  framer.set_is_request(is_request);
  framer.set_balsa_headers(&balsa_headers);
  SCOPED_TRACE(EscapeString(message));
  size_t bytes_consumed = framer.ProcessInput(message.data(), message.size());
  EXPECT_EQ(message.size(), bytes_consumed);
  if (expected_error_code == BalsaFrameEnums::BALSA_NO_ERROR) {
    EXPECT_EQ(false, framer.Error());
  } else {
    EXPECT_EQ(true, framer.Error());
  }
  EXPECT_EQ(expected_error_code, framer.ErrorCode());
}

TEST(HTTPBalsaFrame, WhitespaceInRequestsProcessedProperly) {
  SCOPED_TRACE(
      "Test that a request header with a line with spaces and no "
      "data generates an error.");
  WhitespaceHeaderTestHelper(
      "GET / HTTP/1.1\r\n"
      " \r\n"
      "\r\n",
      true, BalsaFrameEnums::INVALID_HEADER_NAME_CHARACTER);
  WhitespaceHeaderTestHelper(
      "GET / HTTP/1.1\r\n"
      "   \r\n"
      "test: test\r\n"
      "\r\n",
      true, BalsaFrameEnums::INVALID_HEADER_NAME_CHARACTER);

  SCOPED_TRACE("Test proper handling for line continuation in requests.");
  WhitespaceHeaderTestHelper(
      "GET / HTTP/1.1\r\n"
      "test: test\r\n"
      " continued\r\n"
      "\r\n",
      true, BalsaFrameEnums::BALSA_NO_ERROR);
  WhitespaceHeaderTestHelper(
      "GET / HTTP/1.1\r\n"
      "test: test\r\n"
      " \r\n"
      "\r\n",
      true, BalsaFrameEnums::BALSA_NO_ERROR);
  SCOPED_TRACE(
      "Test a confusing and ambiguous case: is it a line continuation or a new "
      "header field?");
  WhitespaceHeaderTestHelper(
      "GET / HTTP/1.1\r\n"
      "test: test\r\n"
      "  confusing:continued\r\n"
      "\r\n",
      true, BalsaFrameEnums::BALSA_NO_ERROR);
}

TEST(HTTPBalsaFrame, WhitespaceInResponsesProcessedProperly) {
  SCOPED_TRACE(
      "Test that a response header with a line with spaces and no "
      "data generates an error.");
  WhitespaceHeaderTestHelper(
      "HTTP/1.0 200 Reason\r\n"
      "  \r\nContent-Length: 0\r\n"
      "\r\n",
      false, BalsaFrameEnums::INVALID_HEADER_NAME_CHARACTER);

  SCOPED_TRACE("Test proper handling for line continuation in responses.");
  WhitespaceHeaderTestHelper(
      "HTTP/1.0 200 Reason\r\n"
      "test: test\r\n"
      " continued\r\n"
      "Content-Length: 0\r\n"
      "\r\n",
      false, BalsaFrameEnums::BALSA_NO_ERROR);
  WhitespaceHeaderTestHelper(
      "HTTP/1.0 200 Reason\r\n"
      "test: test\r\n"
      " \r\n"
      "Content-Length: 0\r\n"
      "\r\n",
      false, BalsaFrameEnums::BALSA_NO_ERROR);
  SCOPED_TRACE(
      "Test a confusing and ambiguous case: is it a line continuation or a new "
      "header field?");
  WhitespaceHeaderTestHelper(
      "HTTP/1.0 200 Reason\r\n"
      "test: test\r\n"
      "   confusing:continued\r\n"
      "Content-Length: 0\r\n"
      "\r\n",
      false, BalsaFrameEnums::BALSA_NO_ERROR);
}

TEST_F(HTTPBalsaFrameTest, VisitorInvokedProperlyForTrivialRequest) {
  std::string message = "GET /foobar HTTP/1.0\r\n\n";

  FakeHeaders fake_headers;

  {
    InSequence s;

    EXPECT_CALL(visitor_mock_,
                OnRequestFirstLineInput("GET /foobar HTTP/1.0", "GET",
                                        "/foobar", "HTTP/1.0"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(message));

  ASSERT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
}

TEST_F(HTTPBalsaFrameTest, VisitorInvokedProperlyForRequestWithBlankLines) {
  std::string message = "\n\n\r\n\nGET /foobar HTTP/1.0\r\n\n";

  FakeHeaders fake_headers;

  {
    InSequence s1;
    // Yes, that is correct-- the framer 'eats' the blank-lines at the beginning
    // and never notifies the visitor.

    EXPECT_CALL(visitor_mock_,
                OnRequestFirstLineInput("GET /foobar HTTP/1.0", "GET",
                                        "/foobar", "HTTP/1.0"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput("GET /foobar HTTP/1.0\r\n\n"));

  ASSERT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
}

TEST_F(HTTPBalsaFrameTest,
       VisitorInvokedProperlyForRequestWithSplitBlankLines) {
  std::string blanks =
      "\n"
      "\n"
      "\r\n"
      "\n";
  std::string header_input = "GET /foobar HTTP/1.0\r\n\n";

  FakeHeaders fake_headers;

  {
    InSequence s1;
    // Yes, that is correct-- the framer 'eats' the blank-lines at the beginning
    // and never notifies the visitor.

    EXPECT_CALL(visitor_mock_,
                OnRequestFirstLineInput("GET /foobar HTTP/1.0", "GET",
                                        "/foobar", "HTTP/1.0"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput("GET /foobar HTTP/1.0\r\n\n"));

  ASSERT_EQ(blanks.size(),
            balsa_frame_.ProcessInput(blanks.data(), blanks.size()));
  ASSERT_EQ(header_input.size(), balsa_frame_.ProcessInput(
                                     header_input.data(), header_input.size()));
}

TEST_F(HTTPBalsaFrameTest,
       VisitorInvokedProperlyForRequestWithZeroContentLength) {
  std::string message =
      "PUT /search?q=fo HTTP/1.1\n"
      "content-length:      0  \n"
      "\n";

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("content-length", "0");

  {
    InSequence s1;

    EXPECT_CALL(visitor_mock_,
                OnRequestFirstLineInput("PUT /search?q=fo HTTP/1.1", "PUT",
                                        "/search?q=fo", "HTTP/1.1"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(message));

  ASSERT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
}

TEST_F(HTTPBalsaFrameTest,
       VisitorInvokedProperlyForRequestWithMissingContentLength) {
  std::string message =
      "PUT /search?q=fo HTTP/1.1\n"
      "\n";

  auto error_code =
      BalsaFrameEnums::BalsaFrameEnums::REQUIRED_BODY_BUT_NO_CONTENT_LENGTH;
  EXPECT_CALL(visitor_mock_, HandleError(error_code));

  balsa_frame_.ProcessInput(message.data(), message.size());
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(error_code, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, ContentLengthNotRequired) {
  HttpValidationPolicy http_validation_policy;
  http_validation_policy.require_content_length_if_body_required = false;
  balsa_frame_.set_http_validation_policy(http_validation_policy);

  std::string message =
      "PUT /search?q=fo HTTP/1.1\n"
      "\n";

  balsa_frame_.ProcessInput(message.data(), message.size());
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
}

TEST_F(HTTPBalsaFrameTest,
       VisitorInvokedProperlyForPermittedMissingContentLength) {
  std::string message =
      "PUT /search?q=fo HTTP/1.1\n"
      "\n";

  FakeHeaders fake_headers;

  {
    InSequence s1;

    EXPECT_CALL(visitor_mock_,
                OnRequestFirstLineInput("PUT /search?q=fo HTTP/1.1", "PUT",
                                        "/search?q=fo", "HTTP/1.1"));
  }
  ASSERT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
}

TEST_F(HTTPBalsaFrameTest, NothingBadHappensWhenNothingInConnectionLine) {
  // This is similar to the test above, but we use different whitespace
  // throughout.
  std::string message =
      "PUT \t /search?q=fo \t HTTP/1.1 \t \r\n"
      "Connection:\r\n"
      "content-length: 0\r\n"
      "\r\n";

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("Connection", "");
  fake_headers.AddKeyValue("content-length", "0");

  {
    InSequence s1;

    EXPECT_CALL(visitor_mock_,
                OnRequestFirstLineInput("PUT \t /search?q=fo \t HTTP/1.1",
                                        "PUT", "/search?q=fo", "HTTP/1.1"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(message));

  ASSERT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
}

TEST_F(HTTPBalsaFrameTest, NothingBadHappensWhenOnlyCommentsInConnectionLine) {
  // This is similar to the test above, but we use different whitespace
  // throughout.
  std::string message =
      "PUT \t /search?q=fo \t HTTP/1.1 \t \r\n"
      "Connection: ,,,,,,,,\r\n"
      "content-length: 0\r\n"
      "\r\n";

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("Connection", ",,,,,,,,");
  fake_headers.AddKeyValue("content-length", "0");

  {
    InSequence s1;

    EXPECT_CALL(visitor_mock_,
                OnRequestFirstLineInput("PUT \t /search?q=fo \t HTTP/1.1",
                                        "PUT", "/search?q=fo", "HTTP/1.1"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(message));

  ASSERT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
}

TEST_F(HTTPBalsaFrameTest,
       VisitorInvokedProperlyForRequestWithZeroContentLengthMk2) {
  // This is similar to the test above, but we use different whitespace
  // throughout.
  std::string message =
      "PUT \t /search?q=fo \t HTTP/1.1 \t \r\n"
      "Connection:      \t close      \t\r\n"
      "content-length:  \t\t   0 \t\t  \r\n"
      "\r\n";

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("Connection", "close");
  fake_headers.AddKeyValue("content-length", "0");

  {
    InSequence s1;

    EXPECT_CALL(visitor_mock_,
                OnRequestFirstLineInput("PUT \t /search?q=fo \t HTTP/1.1",
                                        "PUT", "/search?q=fo", "HTTP/1.1"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(message));

  ASSERT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
}

TEST_F(HTTPBalsaFrameTest, NothingBadHappensWhenNoVisitorIsAssigned) {
  std::string headers =
      "GET / HTTP/1.1\r\n"
      "Connection: close\r\n"
      "transfer-encoding: chunked\r\n"
      "\r\n";

  std::string chunks =
      "3\r\n"
      "123\r\n"
      "0\r\n";
  std::string trailer =
      "crass: monkeys\r\n"
      "funky: monkeys\r\n"
      "\r\n";

  balsa_frame_.set_balsa_visitor(nullptr);
  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));
  ASSERT_EQ(chunks.size(),
            balsa_frame_.ProcessInput(chunks.data(), chunks.size()));
  EXPECT_EQ(trailer.size(),
            balsa_frame_.ProcessInput(trailer.data(), trailer.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, RequestWithTrailers) {
  std::string headers =
      "GET / HTTP/1.1\r\n"
      "Connection: close\r\n"
      "transfer-encoding: chunked\r\n"
      "\r\n";

  std::string chunks =
      "3\r\n"
      "123\r\n"
      "0\r\n";
  std::string trailer =
      "crass: monkeys\r\n"
      "funky: monkeys\r\n"
      "\r\n";

  InSequence s;

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("Connection", "close");
  fake_headers.AddKeyValue("transfer-encoding", "chunked");
  EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));
  testing::Mock::VerifyAndClearExpectations(&visitor_mock_);

  ASSERT_EQ(chunks.size(),
            balsa_frame_.ProcessInput(chunks.data(), chunks.size()));

  FakeHeaders fake_trailers;
  fake_trailers.AddKeyValue("crass", "monkeys");
  fake_trailers.AddKeyValue("funky", "monkeys");
  EXPECT_CALL(visitor_mock_, OnTrailers(fake_trailers));

  EXPECT_CALL(visitor_mock_, OnTrailerInput(_)).Times(AtLeast(1));

  EXPECT_EQ(trailer.size(),
            balsa_frame_.ProcessInput(trailer.data(), trailer.size()));

  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, NothingBadHappensWhenNoVisitorIsAssignedInResponse) {
  std::string headers =
      "HTTP/1.1 502 Bad Gateway\r\n"
      "Connection: close\r\n"
      "transfer-encoding: chunked\r\n"
      "\r\n";

  std::string chunks =
      "3\r\n"
      "123\r\n"
      "0\r\n";
  std::string trailer =
      "crass: monkeys\r\n"
      "funky: monkeys\r\n"
      "\r\n";
  balsa_frame_.set_is_request(false);
  balsa_frame_.set_balsa_visitor(nullptr);

  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));
  ASSERT_EQ(chunks.size(),
            balsa_frame_.ProcessInput(chunks.data(), chunks.size()));
  EXPECT_EQ(trailer.size(),
            balsa_frame_.ProcessInput(trailer.data(), trailer.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, TransferEncodingIdentityIsIgnored) {
  std::string headers =
      "GET / HTTP/1.1\r\n"
      "Connection: close\r\n"
      "transfer-encoding: identity\r\n"
      "content-length: 10\r\n"
      "\r\n";

  std::string body = "1234567890";
  std::string message = (headers + body);

  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  ASSERT_EQ(body.size(), balsa_frame_.ProcessInput(body.data(), body.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest,
       NothingBadHappensWhenAVisitorIsChangedToNULLInMidParsing) {
  std::string headers =
      "GET / HTTP/1.1\r\n"
      "Connection: close\r\n"
      "transfer-encoding: chunked\r\n"
      "\r\n";

  std::string chunks =
      "3\r\n"
      "123\r\n"
      "0\r\n";
  std::string trailer =
      "crass: monkeys\r\n"
      "funky: monkeys\r\n"
      "\n";

  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));
  balsa_frame_.set_balsa_visitor(nullptr);
  ASSERT_EQ(chunks.size(),
            balsa_frame_.ProcessInput(chunks.data(), chunks.size()));
  ASSERT_EQ(trailer.size(),
            balsa_frame_.ProcessInput(trailer.data(), trailer.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest,
       NothingBadHappensWhenAVisitorIsChangedToNULLInMidParsingInTrailer) {
  std::string headers =
      "HTTP/1.1 503 Server Not Available\r\n"
      "Connection: close\r\n"
      "transfer-encoding: chunked\r\n"
      "\r\n";

  std::string chunks =
      "3\r\n"
      "123\r\n"
      "0\r\n";
  std::string trailer =
      "crass: monkeys\r\n"
      "funky: monkeys\r\n"
      "\n";

  balsa_frame_.set_is_request(false);

  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));
  balsa_frame_.set_balsa_visitor(nullptr);
  ASSERT_EQ(chunks.size(),
            balsa_frame_.ProcessInput(chunks.data(), chunks.size()));
  ASSERT_EQ(trailer.size(),
            balsa_frame_.ProcessInput(trailer.data(), trailer.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest,
       NothingBadHappensWhenNoVisitorAssignedAndChunkingErrorOccurs) {
  std::string headers =
      "GET / HTTP/1.1\r\n"
      "Connection: close\r\n"
      "transfer-encoding: chunked\r\n"
      "\r\n";

  std::string chunks =
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\r\n"  // should overflow
      "0\r\n";
  std::string trailer =
      "crass: monkeys\r\n"
      "funky: monkeys\r\n"
      "\n";

  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));
  balsa_frame_.set_balsa_visitor(nullptr);
  EXPECT_GE(chunks.size(),
            balsa_frame_.ProcessInput(chunks.data(), chunks.size()));
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::CHUNK_LENGTH_OVERFLOW, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, FramerRecognizesSemicolonAsChunkSizeDelimiter) {
  std::string headers =
      "GET / HTTP/1.1\r\n"
      "Connection: close\r\n"
      "transfer-encoding: chunked\r\n"
      "\r\n";

  std::string chunks =
      "8; foo=bar\r\n"
      "deadbeef\r\n"
      "0\r\n"
      "\r\n";

  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));

  balsa_frame_.set_balsa_visitor(&visitor_mock_);
  EXPECT_CALL(visitor_mock_, OnChunkLength(8));
  EXPECT_CALL(visitor_mock_, OnChunkLength(0));
  EXPECT_CALL(visitor_mock_, OnChunkExtensionInput("; foo=bar"));
  EXPECT_CALL(visitor_mock_, OnChunkExtensionInput(""));

  EXPECT_EQ(chunks.size(),
            balsa_frame_.ProcessInput(chunks.data(), chunks.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
}

TEST_F(HTTPBalsaFrameTest, NonAsciiCharacterInChunkLength) {
  std::string headers =
      "GET / HTTP/1.1\r\n"
      "Connection: close\r\n"
      "transfer-encoding: chunked\r\n"
      "\r\n";

  std::string chunks =
      "555\xAB\r\n"  // Character overflowing 7 bits, see b/20238315
      "0\r\n";
  std::string trailer =
      "crass: monkeys\r\n"
      "funky: monkeys\r\n"
      "\n";

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("Connection", "close");
  fake_headers.AddKeyValue("transfer-encoding", "chunked"
```