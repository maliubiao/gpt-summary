Response:
The user wants a summary of the functionality of the provided C++ code, which is a test file for `BalsaFrame`, a class likely responsible for parsing HTTP frames in Chromium's network stack. I need to go through the test cases and identify what aspects of `BalsaFrame` they are testing. I also need to address specific points in the prompt regarding JavaScript, logical reasoning, common errors, debugging, and finally, provide a concise summary.

Here's a breakdown of the test cases and their implied functionalities:

- **`TransferEncodingNotChunked`**: Tests handling of non-chunked transfer encoding when `content-length` is present.
- **`TransferEncodingChunkedNoContentLength`**: Tests handling of chunked transfer encoding without `content-length`.
- **`TransferEncodingChunkedIdentityContentLength`**: Tests error handling when both chunked and identity encoding are present with `content-length`.
- **`MissingContentLength`**: Tests behavior when `content-length` is missing for a non-chunked response.
- **`MultipleTransferEncodingsWithMissingContentLength`**: Tests handling of multiple transfer encodings without `content-length`.
- **`TestDetachOnDone`**:  Tests the ability to detach header handling once a message is complete.
- **`ChangeMaxHeadersLengthOnFirstLine`**: Tests modifying the maximum header length during the processing of the first line.
- **`ChangeMaxHeadersLengthOnHeaderDone`**: Tests modifying the maximum header length after headers have been processed.
- **`HeadersSizeSameAsMaxLengthIsAccepted`**: Tests that the parser correctly handles headers of the maximum allowed length.
- Tests for invalid characters in header names (`KeyHasSpaces`, `SpaceBeforeColon`, `SpaceBeforeColonNotAfter`, `KeyHasTabs`, `TabBeforeColon`, `KeyHasContinuation`, `KeyHasMultipleContinuations`, `KeyHasDoubleQuote`, `KeyHasDisallowedDoubleQuote`).
- **`TrailerMissingColon`**: Tests the handling of trailers with missing colons (as a warning).
- **`MultipleHeadersInTrailer`**: Tests parsing of multiple headers in the trailer.
- **`NothingBadHappensWithNULLTrailer`**: Tests behavior when trailer processing is not explicitly enabled.
- **`FrameAndResetAndFrameAgain`**: Tests that the `Reset()` function correctly resets the state for processing new frames.
- Tests for invalid characters in header values (`InvalidCharsInHeaderValueError`, `InvalidCharsInHeaderNameError`, `InvalidCharsInRequestHeaderError`, `InvalidCharsInResponseHeaderAllowed`, `InvalidCharsInResponseHeaderError`, `InvalidCharsErrorSet`, `InvalidCharEndOfLine`, `InvalidCharInFirstLine`).
- **`GibberishInHeadersAndTrailer`**: Tests the parser's robustness against non-standard header and trailer content.
- **`TrailerTooLong`**: Tests handling of trailers exceeding the maximum allowed length.
- Tests for handling of "100 Continue" responses (`Parse100ContinueNoContinueHeadersNoCallback`, `Parse100Continue`, `Support100ContinueNoCallback`, `Support100Continue`, `InterimHeadersCallbackTakesPrecedence`, `Support100Continue401UnauthorizedNoCallback`, `Support100Continue401Unauthorized`).

Based on this analysis, I can now formulate the summary.
这个文件 `net/third_party/quiche/src/quiche/balsa/balsa_frame_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，它专门用于测试 `BalsaFrame` 类的功能。 `BalsaFrame` 类是用于解析 HTTP 消息（请求或响应）的帧结构的。

**主要功能归纳:**

这个测试文件的主要功能是全面测试 `BalsaFrame` 类的各种场景和边界情况，以确保其能够正确解析和处理 HTTP 消息的各个部分，包括：

1. **请求行和状态行解析:** 测试能否正确解析 HTTP 请求的请求方法、URI 和版本，以及 HTTP 响应的状态码和状态消息。
2. **头部解析:**  测试能否正确解析 HTTP 头部，包括头部字段名和字段值的解析，以及处理重复头部、Transfer-Encoding 和 Content-Length 等特殊头部的情况。
3. **消息体处理:** 测试能否正确处理不同类型的消息体，包括带有 Content-Length 的消息体和 chunked 编码的消息体。
4. **Trailer 处理:** 测试能否正确解析和处理 chunked 编码消息后的 Trailer 部分。
5. **错误处理:** 测试在遇到格式错误、无效字符、头部过长等错误情况时的处理机制，以及错误代码的设置。
6. **100 Continue 处理:** 测试对于 HTTP/1.1 中 100 Continue 响应的处理流程。
7. **最大头部长度限制:** 测试 `BalsaFrame` 是否能正确应用和处理最大头部长度的限制。
8. **Invalid Character 处理:** 测试对于 HTTP 头部中无效字符的处理策略，可以设置为忽略、警告或错误。
9. **状态重置:** 测试 `Reset()` 方法能否正确重置 `BalsaFrame` 的内部状态，以便处理新的 HTTP 消息。

**与 Javascript 的关系:**

虽然这个 C++ 代码本身不直接涉及 Javascript，但它所处理的 HTTP 协议是 Web 开发的基础。当 Javascript 代码（例如在浏览器中运行的脚本）发起 HTTP 请求或接收 HTTP 响应时，底层的网络栈（包括 Chromium 使用的这个部分）会负责解析和处理 HTTP 消息。

**举例说明:**

假设一个 Javascript 使用 `fetch` API 发起一个简单的 GET 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当服务器返回响应时，服务器发送的 HTTP 响应报文会经过 `BalsaFrame` 进行解析。例如，服务器可能返回这样的响应：

```
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 25

{"message": "Hello, world!"}
```

`BalsaFrame` 的功能就是解析以上响应报文的各个部分：

* **状态行:** `HTTP/1.1 200 OK`
* **头部:** `Content-Type: application/json` 和 `Content-Length: 25`
* **消息体:** `{"message": "Hello, world!"}`

解析完成后，这些信息会被传递给更上层的网络模块，最终 Javascript 代码可以通过 `response.json()` 方法访问到 JSON 格式的响应体。

**逻辑推理、假设输入与输出:**

以下是一个测试用例 `MissingContentLength` 的逻辑推理：

* **假设输入:** 一个 HTTP 响应头，没有 `Content-Length` 头部，并且没有使用 chunked 编码。
  ```
  HTTP/1.1 200 OK\r\n\r\n
  ```
* **`BalsaFrame` 的处理:** `BalsaFrame` 在解析头部后，发现既没有 `Content-Length` 也没有 `transfer-encoding: chunked`，因此无法确定消息体是否存在以及长度。
* **预期输出:** `balsa_frame_.ErrorCode()` 应该返回 `BalsaFrameEnums::MAYBE_BODY_BUT_NO_CONTENT_LENGTH`，表示可能存在消息体，但缺少指示其长度的信息。 `balsa_frame_.Error()` 应该为 `false`，因为这通常被视为一个警告或需要上层处理的情况，而不是一个致命错误。

**用户或编程常见的使用错误:**

一个常见的编程错误是服务器在响应中没有正确设置 `Content-Length` 头部，也没有使用 `transfer-encoding: chunked`。

**举例说明:**

如果一个开发者编写了一个简单的 HTTP 服务器，并且忘记了在非 chunked 的响应中设置 `Content-Length` 头部，那么当客户端接收到响应时，底层的 `BalsaFrame` 会报告 `MAYBE_BODY_BUT_NO_CONTENT_LENGTH` 错误码。虽然这可能不会导致连接断开，但客户端可能无法正确读取完整的响应体，导致数据丢失或解析错误。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中输入 URL 或点击链接:**  这会触发浏览器发起一个 HTTP 请求。
2. **浏览器构建 HTTP 请求报文:**  浏览器根据用户操作构建符合 HTTP 协议的请求报文。
3. **请求报文通过网络发送到服务器:** 请求报文经过操作系统的网络协议栈发送到目标服务器。
4. **服务器处理请求并生成 HTTP 响应报文:** 服务器接收到请求后，进行处理并生成相应的 HTTP 响应报文。
5. **响应报文通过网络发送回客户端:** 响应报文经过网络发送回用户的浏览器。
6. **浏览器接收到响应报文:** 浏览器的网络模块接收到服务器发送的响应报文。
7. **`BalsaFrame` 解析响应报文:**  接收到的响应报文会被传递给 `BalsaFrame` 类进行解析，提取状态行、头部和消息体等信息.
8. **测试文件模拟各种异常情况:**  `balsa_frame_test.cc` 中的测试用例会模拟各种格式错误或不符合 HTTP 规范的响应报文，例如缺少 `Content-Length`、头部包含无效字符等等，来测试 `BalsaFrame` 在这些情况下的处理是否正确。

**第 5 部分功能归纳:**

这个代码片段（第 5 部分）主要关注以下 `BalsaFrame` 的功能测试：

* **处理缺少 `Content-Length` 但没有使用 chunked 编码的响应。**
* **处理同时存在多个 `transfer-encoding` 头部，并且缺少 `Content-Length` 的情况。**
* **测试在消息处理完成时解绑 header 对象的机制。**
* **测试在请求行和头部解析完成时修改最大头部长度限制的行为及其影响。**
* **测试当头部大小正好等于最大头部长度限制时的情况。**
* **深入测试 HTTP 头部字段名称中包含空格、Tab 字符、换行符等无效字符时的错误处理。**
* **测试头部字段名称中包含双引号的正常和禁用情况。**
* **测试 HTTP Trailer 部分缺少冒号时的处理（作为警告）。**
* **测试解析包含多个头部的 Trailer 部分。**
* **测试在没有设置 Trailer 时的正常处理流程。**
* **测试 `Reset()` 方法是否能正确重置与 Trailer 相关的状态。**
* **测试在头部值中包含无效字符时的错误处理，并区分不同的错误级别。**
* **测试在头部名称中包含无效字符时的错误处理（即使错误级别设置为忽略）。**
* **测试请求头部中包含无效字符时的错误处理。**
* **测试响应头部中包含无效字符时，在不同错误级别下的处理差异。**
* **通过参数化测试，测试在头部值中包含各种 ASCII 控制字符时的错误处理。**
* **测试在头部行的末尾或首行包含无效字符时的错误处理。**
* **测试解析头部和 Trailer 中包含乱码数据的场景。**
* **测试 Trailer 部分过长时的错误处理。**
* **测试处理 "100 Continue" 响应，包括不使用回调和使用回调的情况。**

总而言之，这部分代码着重于测试 `BalsaFrame` 对各种 HTTP 头部格式、Trailer 以及错误情况的鲁棒性和正确性。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/balsa/balsa_frame_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能

"""
lidation_policy);

  std::string header =
      "HTTP/1.1 200 OK\r\n"
      "transfer-encoding: chunked-identity\r\n"
      "content-length: 3\r\n"
      "\r\n";
  balsa_frame_.set_is_request(false);
  balsa_frame_.ProcessInput(header.data(), header.size());

  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, MissingContentLength) {
  std::string header = "HTTP/1.1 200 OK\r\n\r\n";
  balsa_frame_.set_is_request(false);
  balsa_frame_.ProcessInput(header.data(), header.size());

  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::MAYBE_BODY_BUT_NO_CONTENT_LENGTH,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, MultipleTransferEncodingsWithMissingContentLength) {
  HttpValidationPolicy http_validation_policy;
  http_validation_policy.validate_transfer_encoding = false;
  balsa_frame_.set_http_validation_policy(http_validation_policy);

  std::string header =
      "HTTP/1.1 200 OK\r\n"
      "transfer-encoding: chunked\r\n"
      "transfer-encoding: identity\r\n"
      "\r\n";
  balsa_frame_.set_is_request(false);
  balsa_frame_.ProcessInput(header.data(), header.size());

  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::MAYBE_BODY_BUT_NO_CONTENT_LENGTH,
            balsa_frame_.ErrorCode());
}

class DetachOnDoneFramer : public NoOpBalsaVisitor {
 public:
  DetachOnDoneFramer() {
    framer_.set_balsa_headers(&headers_);
    framer_.set_balsa_visitor(this);
  }

  void MessageDone() override { framer_.set_balsa_headers(nullptr); }

  BalsaFrame* framer() { return &framer_; }

 protected:
  BalsaFrame framer_;
  BalsaHeaders headers_;
};

TEST(HTTPBalsaFrame, TestDetachOnDone) {
  DetachOnDoneFramer framer;
  const char* message = "GET HTTP/1.1\r\n\r\n";
  // Frame the whole message.  The framer will call MessageDone which will set
  // the headers to nullptr.
  framer.framer()->ProcessInput(message, strlen(message));
  EXPECT_TRUE(framer.framer()->MessageFullyRead());
  EXPECT_FALSE(framer.framer()->Error());
}

// We simply extend DetachOnDoneFramer so that we do not have
// to provide trivial implementation for various functions.
class ModifyMaxHeaderLengthFramerInFirstLine : public DetachOnDoneFramer {
 public:
  void MessageDone() override {}
  // This sets to max_header_length to a low number and
  // this would cause us to reject the query. Even though
  // our original headers length was acceptable.
  void OnRequestFirstLineInput(absl::string_view /*line_input*/,
                               absl::string_view /*method_input*/,
                               absl::string_view /*request_uri*/,
                               absl::string_view /*version_input*/
                               ) override {
    framer_.set_max_header_length(1);
  }
};

// In this case we have already processed the headers and called on
// the visitor HeadersDone and hence its too late to reduce the
// max_header_length here.
class ModifyMaxHeaderLengthFramerInHeaderDone : public DetachOnDoneFramer {
 public:
  void MessageDone() override {}
  void HeaderDone() override { framer_.set_max_header_length(1); }
};

TEST(HTTPBalsaFrame, ChangeMaxHeadersLengthOnFirstLine) {
  std::string message =
      "PUT /foo HTTP/1.1\r\n"
      "Content-Length: 2\r\n"
      "header: xxxxxxxxx\r\n\r\n"
      "B";  // body begin

  ModifyMaxHeaderLengthFramerInFirstLine balsa_frame;
  balsa_frame.framer()->set_is_request(true);
  balsa_frame.framer()->set_max_header_length(message.size() - 1);

  balsa_frame.framer()->ProcessInput(message.data(), message.size());
  EXPECT_EQ(BalsaFrameEnums::HEADERS_TOO_LONG,
            balsa_frame.framer()->ErrorCode());
}

TEST(HTTPBalsaFrame, ChangeMaxHeadersLengthOnHeaderDone) {
  std::string message =
      "PUT /foo HTTP/1.1\r\n"
      "Content-Length: 2\r\n"
      "header: xxxxxxxxx\r\n\r\n"
      "B";  // body begin

  ModifyMaxHeaderLengthFramerInHeaderDone balsa_frame;
  balsa_frame.framer()->set_is_request(true);
  balsa_frame.framer()->set_max_header_length(message.size() - 1);

  balsa_frame.framer()->ProcessInput(message.data(), message.size());
  EXPECT_EQ(0, balsa_frame.framer()->ErrorCode());
}

// This is a simple test to ensure the simple case that we accept
// a query which has headers size same as the max_header_length.
// (i.e., there is no off by one error).
TEST(HTTPBalsaFrame, HeadersSizeSameAsMaxLengthIsAccepted) {
  std::string message =
      "GET /foo HTTP/1.1\r\n"
      "header: xxxxxxxxx\r\n\r\n";

  ModifyMaxHeaderLengthFramerInHeaderDone balsa_frame;
  balsa_frame.framer()->set_is_request(true);
  balsa_frame.framer()->set_max_header_length(message.size());
  balsa_frame.framer()->ProcessInput(message.data(), message.size());
  EXPECT_EQ(0, balsa_frame.framer()->ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, KeyHasSpaces) {
  const std::string message =
      "GET / HTTP/1.1\r\n"
      "key has spaces: lock\r\n"
      "\r\n";
  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_HEADER_NAME_CHARACTER,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, SpaceBeforeColon) {
  const std::string message =
      "GET / HTTP/1.1\r\n"
      "key : lock\r\n"
      "\r\n";
  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_HEADER_NAME_CHARACTER,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, SpaceBeforeColonNotAfter) {
  const std::string message =
      "GET / HTTP/1.1\r\n"
      "key :lock\r\n"
      "\r\n";
  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_HEADER_NAME_CHARACTER,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, KeyHasTabs) {
  const std::string message =
      "GET / HTTP/1.1\r\n"
      "key\thas\ttabs: lock\r\n"
      "\r\n";
  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_HEADER_NAME_CHARACTER,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, TabBeforeColon) {
  const std::string message =
      "GET / HTTP/1.1\r\n"
      "key\t: lock\r\n"
      "\r\n";
  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_HEADER_NAME_CHARACTER,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, KeyHasContinuation) {
  const std::string message =
      "GET / HTTP/1.1\r\n"
      "key\n includes continuation: but not value\r\n"
      "\r\n";
  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_HEADER_NAME_CHARACTER,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, KeyHasMultipleContinuations) {
  const std::string message =
      "GET / HTTP/1.1\r\n"
      "key\n includes\r\n multiple\n continuations: but not value\r\n"
      "\r\n";
  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_HEADER_NAME_CHARACTER,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, KeyHasDoubleQuote) {
  const std::string message =
      "GET / HTTP/1.1\r\n"
      "key\"hasquote: lock\r\n"
      "\r\n";
  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
  EXPECT_TRUE(headers_.HasHeader("key\"hasquote"));
}

TEST_F(HTTPBalsaFrameTest, KeyHasDisallowedDoubleQuote) {
  HttpValidationPolicy http_validation_policy;
  http_validation_policy.disallow_double_quote_in_header_name = true;
  balsa_frame_.set_http_validation_policy(http_validation_policy);

  const std::string message =
      "GET / HTTP/1.1\r\n"
      "key\"hasquote: lock\r\n"
      "\r\n";
  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_HEADER_NAME_CHARACTER,
            balsa_frame_.ErrorCode());
}

// Missing colon is a warning, not an error.
TEST_F(HTTPBalsaFrameTest, TrailerMissingColon) {
  std::string headers =
      "HTTP/1.0 302 Redirect\r\n"
      "transfer-encoding: chunked\r\n"
      "\r\n";

  std::string chunks =
      "3\r\n"
      "123\r\n"
      "0\r\n";
  std::string trailer =
      "crass_monkeys\n"
      "\r\n";

  balsa_frame_.set_is_request(false);
  EXPECT_CALL(visitor_mock_,
              HandleWarning(BalsaFrameEnums::TRAILER_MISSING_COLON));
  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));
  ASSERT_EQ(chunks.size(),
            balsa_frame_.ProcessInput(chunks.data(), chunks.size()));

  FakeHeaders fake_trailers;
  fake_trailers.AddKeyValue("crass_monkeys", "");
  EXPECT_CALL(visitor_mock_, OnTrailers(fake_trailers));
  EXPECT_EQ(trailer.size(),
            balsa_frame_.ProcessInput(trailer.data(), trailer.size()));

  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::TRAILER_MISSING_COLON, balsa_frame_.ErrorCode());
}

// This tests multiple headers in trailer. We currently do not and have no plan
// to support Trailer field in headers to limit valid field-name in trailer.
// Test that we aren't confused by the non-alphanumeric characters in the
// trailer, especially ':'.
TEST_F(HTTPBalsaFrameTest, MultipleHeadersInTrailer) {
  std::string headers =
      "HTTP/1.1 200 OK\r\n"
      "transfer-encoding: chunked\r\n"
      "\r\n";

  std::string chunks =
      "3\r\n"
      "123\n"
      "0\n";
  std::map<std::string, std::string> trailer;
  trailer["X-Trace"] =
      "http://trace.example.com/trace?host="
      "foobar.example.com&start=2012-06-03_15:59:06&rpc_duration=0.243349";
  trailer["Date"] = "Sun, 03 Jun 2012 22:59:06 GMT";
  trailer["Content-Type"] = "text/html";
  trailer["X-Backends"] = "127.0.0.1_0,foo.example.com:39359";
  trailer["X-Request-Trace"] =
      "foo.example.com:39359,127.0.0.1_1,"
      "foo.example.com:39359,127.0.0.1_0,"
      "foo.example.com:39359";
  trailer["X-Service-Trace"] = "default";
  trailer["X-Service"] = "default";

  std::map<std::string, std::string>::const_iterator iter;
  std::string trailer_data;
  TestSeed seed;
  seed.Initialize(GetQuicheCommandLineFlag(FLAGS_randseed));
  RandomEngine rng;
  rng.seed(seed.GetSeed());
  FakeHeaders fake_headers_in_trailer;
  for (iter = trailer.begin(); iter != trailer.end(); ++iter) {
    trailer_data += iter->first;
    trailer_data += ":";
    std::stringstream leading_whitespace_for_value;
    AppendRandomWhitespace(rng, &leading_whitespace_for_value);
    trailer_data += leading_whitespace_for_value.str();
    trailer_data += iter->second;
    std::stringstream trailing_whitespace_for_value;
    AppendRandomWhitespace(rng, &trailing_whitespace_for_value);
    trailer_data += trailing_whitespace_for_value.str();
    trailer_data += random_line_term(rng);
    fake_headers_in_trailer.AddKeyValue(iter->first, iter->second);
  }
  trailer_data += random_line_term(rng);

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("transfer-encoding", "chunked");

  {
    InSequence s1;
    EXPECT_CALL(visitor_mock_, OnResponseFirstLineInput(
                                   "HTTP/1.1 200 OK", "HTTP/1.1", "200", "OK"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, OnChunkLength(3));
    EXPECT_CALL(visitor_mock_, OnChunkLength(0));
    EXPECT_CALL(visitor_mock_, OnTrailers(fake_headers_in_trailer));
    EXPECT_CALL(visitor_mock_, OnTrailerInput(trailer_data));
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(headers));
  std::string body_input;
  EXPECT_CALL(visitor_mock_, OnRawBodyInput(_))
      .WillRepeatedly([&body_input](absl::string_view input) {
        absl::StrAppend(&body_input, input);
      });
  EXPECT_CALL(visitor_mock_, OnBodyChunkInput("123"));

  balsa_frame_.set_is_request(false);

  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));
  ASSERT_EQ(chunks.size(),
            balsa_frame_.ProcessInput(chunks.data(), chunks.size()));
  EXPECT_EQ(trailer_data.size(), balsa_frame_.ProcessInput(
                                     trailer_data.data(), trailer_data.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());

  EXPECT_EQ(chunks, body_input);
}

// Test if trailer is not set (the common case), everything will be fine.
TEST_F(HTTPBalsaFrameTest, NothingBadHappensWithNULLTrailer) {
  std::string headers =
      "HTTP/1.1 200 OK\r\n"
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

  // Use another BalsaFrame, which does not have the trailers option set.
  BalsaFrame balsa_frame;
  balsa_frame.set_balsa_headers(&headers_);
  balsa_frame.set_is_request(false);
  balsa_frame.set_balsa_visitor(nullptr);

  ASSERT_EQ(headers.size(),
            balsa_frame.ProcessInput(headers.data(), headers.size()));
  ASSERT_EQ(chunks.size(),
            balsa_frame.ProcessInput(chunks.data(), chunks.size()));
  ASSERT_EQ(trailer.size(),
            balsa_frame.ProcessInput(trailer.data(), trailer.size()));
  EXPECT_TRUE(balsa_frame.MessageFullyRead());
  EXPECT_FALSE(balsa_frame.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame.ErrorCode());
}

// Test Reset() correctly resets trailer related states.
TEST_F(HTTPBalsaFrameTest, FrameAndResetAndFrameAgain) {
  std::string headers =
      "HTTP/1.1 200 OK\r\n"
      "transfer-encoding: chunked\r\n"
      "\r\n";

  std::string chunks =
      "3\r\n"
      "123\r\n"
      "0\r\n";
  std::string trailer =
      "k: v\n"
      "\n";

  balsa_frame_.set_is_request(false);

  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));
  ASSERT_EQ(chunks.size(),
            balsa_frame_.ProcessInput(chunks.data(), chunks.size()));
  {
    FakeHeaders fake_trailers;
    fake_trailers.AddKeyValue("k", "v");
    EXPECT_CALL(visitor_mock_, OnTrailers(fake_trailers));
  }
  ASSERT_EQ(trailer.size(),
            balsa_frame_.ProcessInput(trailer.data(), trailer.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());

  balsa_frame_.Reset();

  headers =
      "HTTP/1.1 404 Error\r\n"
      "transfer-encoding: chunked\r\n"
      "\r\n";

  chunks =
      "4\r\n"
      "1234\r\n"
      "0\r\n";
  trailer =
      "nk: nv\n"
      "\n";

  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));
  ASSERT_EQ(chunks.size(),
            balsa_frame_.ProcessInput(chunks.data(), chunks.size()));
  {
    FakeHeaders fake_trailers;
    fake_trailers.AddKeyValue("nk", "nv");
    EXPECT_CALL(visitor_mock_, OnTrailers(fake_trailers));
  }
  ASSERT_EQ(trailer.size(),
            balsa_frame_.ProcessInput(trailer.data(), trailer.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

// valid chars are 9 (tab), 10 (LF), 13(CR), and 32-255
TEST_F(HTTPBalsaFrameTest, InvalidCharsInHeaderValueError) {
  balsa_frame_.set_invalid_chars_level(BalsaFrame::InvalidCharsLevel::kError);
  // nulls are double escaped since otherwise this initialized wrong
  const std::string kEscapedInvalid1 =
      "GET /foo HTTP/1.1\r\n"
      "Bogus-Head: val\\x00\r\n"
      "More-Invalid: \\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0B\x0C\x0E\x0F\r\n"
      "And-More: \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D"
      "\x1E\x1F\r\n\r\n";
  std::string message;
  // now we convert to real embedded nulls
  absl::CUnescape(kEscapedInvalid1, &message);

  EXPECT_CALL(visitor_mock_,
              HandleError(BalsaFrameEnums::INVALID_HEADER_CHARACTER));

  balsa_frame_.ProcessInput(message.data(), message.size());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
}

// Header names reject invalid chars even when the InvalidCharsLevel is kOff.
TEST_F(HTTPBalsaFrameTest, InvalidCharsInHeaderNameError) {
  balsa_frame_.set_invalid_chars_level(BalsaFrame::InvalidCharsLevel::kOff);
  // nulls are double escaped since otherwise this initialized wrong
  const std::string kEscapedInvalid1 =
      "GET /foo HTTP/1.1\r\n"
      "Bogus\\x00-Head: val\r\n\r\n";
  std::string message;
  // now we convert to real embedded nulls
  absl::CUnescape(kEscapedInvalid1, &message);

  EXPECT_CALL(visitor_mock_,
              HandleError(BalsaFrameEnums::INVALID_HEADER_NAME_CHARACTER));

  balsa_frame_.ProcessInput(message.data(), message.size());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
}

TEST_F(HTTPBalsaFrameTest, InvalidCharsInRequestHeaderError) {
  balsa_frame_.set_invalid_chars_level(BalsaFrame::InvalidCharsLevel::kError);
  const std::string kEscapedInvalid =
      "GET /foo HTTP/1.1\r\n"
      "Smuggle-Me: \\x00GET /bar HTTP/1.1\r\n"
      "Another-Header: value\r\n\r\n";
  std::string message;
  absl::CUnescape(kEscapedInvalid, &message);

  EXPECT_CALL(visitor_mock_,
              HandleError(BalsaFrameEnums::INVALID_HEADER_CHARACTER));

  balsa_frame_.ProcessInput(message.data(), message.size());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
}

TEST_F(HTTPBalsaFrameTest, InvalidCharsInResponseHeaderAllowed) {
  balsa_frame_.set_is_request(false);
  balsa_frame_.set_invalid_chars_level(BalsaFrame::InvalidCharsLevel::kOff);

  const absl::string_view headers =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 5\r\n"
      "foo: a\022b\r\n"
      "\r\n";
  EXPECT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));

  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, InvalidCharsInResponseHeaderError) {
  balsa_frame_.set_is_request(false);
  balsa_frame_.set_invalid_chars_level(BalsaFrame::InvalidCharsLevel::kError);

  const absl::string_view headers =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 5\r\n"
      "foo: a\022b\r\n"
      "\r\n";
  EXPECT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));

  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_HEADER_CHARACTER,
            balsa_frame_.ErrorCode());
}

class HTTPBalsaFrameTestOneChar : public HTTPBalsaFrameTest,
                                  public testing::WithParamInterface<char> {
 public:
  char GetCharUnderTest() { return GetParam(); }
};

TEST_P(HTTPBalsaFrameTestOneChar, InvalidCharsErrorSet) {
  balsa_frame_.set_invalid_chars_level(BalsaFrame::InvalidCharsLevel::kError);
  const std::string kRequest =
      "GET /foo HTTP/1.1\r\n"
      "Bogus-Char-Goes-Here: ";
  const std::string kEnding = "\r\n\r\n";
  std::string message = kRequest;
  const char c = GetCharUnderTest();
  message.append(1, c);
  message.append(kEnding);
  if (c == 9 || c == 10 || c == 13) {
    // valid char
    EXPECT_CALL(visitor_mock_,
                HandleError(BalsaFrameEnums::INVALID_HEADER_CHARACTER))
        .Times(0);
    balsa_frame_.ProcessInput(message.data(), message.size());
    EXPECT_FALSE(balsa_frame_.Error());
    EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  } else {
    // invalid char
    EXPECT_CALL(visitor_mock_,
                HandleError(BalsaFrameEnums::INVALID_HEADER_CHARACTER));
    balsa_frame_.ProcessInput(message.data(), message.size());
    EXPECT_TRUE(balsa_frame_.Error());
    EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  }
}

INSTANTIATE_TEST_SUITE_P(TestInvalidCharSet, HTTPBalsaFrameTestOneChar,
                         Range<char>(0, 32));

TEST_F(HTTPBalsaFrameTest, InvalidCharEndOfLine) {
  balsa_frame_.set_invalid_chars_level(BalsaFrame::InvalidCharsLevel::kError);
  const std::string kInvalid1 =
      "GET /foo HTTP/1.1\r\n"
      "Header-Key: headervalue\\x00\r\n"
      "Legit-Header: legitvalue\r\n\r\n";
  std::string message;
  absl::CUnescape(kInvalid1, &message);

  EXPECT_CALL(visitor_mock_,
              HandleError(BalsaFrameEnums::INVALID_HEADER_CHARACTER));
  balsa_frame_.ProcessInput(message.data(), message.size());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
}

TEST_F(HTTPBalsaFrameTest, InvalidCharInFirstLine) {
  balsa_frame_.set_invalid_chars_level(BalsaFrame::InvalidCharsLevel::kError);
  const std::string kInvalid1 =
      "GET /foo \\x00HTTP/1.1\r\n"
      "Legit-Header: legitvalue\r\n\r\n";
  std::string message;
  absl::CUnescape(kInvalid1, &message);

  EXPECT_CALL(visitor_mock_,
              HandleError(BalsaFrameEnums::INVALID_HEADER_CHARACTER));
  balsa_frame_.ProcessInput(message.data(), message.size());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
}

// Test gibberish in headers and trailer. GFE does not crash but garbage in
// garbage out.
TEST_F(HTTPBalsaFrameTest, GibberishInHeadersAndTrailer) {
  // Use static_cast<char> for values exceeding SCHAR_MAX to make sure this
  // compiles on platforms where char is signed.
  const char kGibberish1[] = {static_cast<char>(138), static_cast<char>(175),
                              static_cast<char>(233), 0};
  const char kGibberish2[] = {'?',
                              '?',
                              static_cast<char>(128),
                              static_cast<char>(255),
                              static_cast<char>(129),
                              static_cast<char>(254),
                              0};
  const char kGibberish3[] = "foo: bar : eeep : baz";

  std::string gibberish_headers =
      absl::StrCat(kGibberish1, ":", kGibberish2, "\r\n", kGibberish3, "\r\n");

  std::string headers = absl::StrCat(
      "HTTP/1.1 200 OK\r\n"
      "transfer-encoding: chunked\r\n",
      gibberish_headers, "\r\n");

  std::string chunks =
      "3\r\n"
      "123\r\n"
      "0\r\n";

  std::string trailer = absl::StrCat("k: v\n", gibberish_headers, "\n");

  balsa_frame_.set_is_request(false);

  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));
  ASSERT_EQ(chunks.size(),
            balsa_frame_.ProcessInput(chunks.data(), chunks.size()));

  FakeHeaders fake_trailers;
  fake_trailers.AddKeyValue("k", "v");
  fake_trailers.AddKeyValue(kGibberish1, kGibberish2);
  fake_trailers.AddKeyValue("foo", "bar : eeep : baz");
  EXPECT_CALL(visitor_mock_, OnTrailers(fake_trailers));
  ASSERT_EQ(trailer.size(),
            balsa_frame_.ProcessInput(trailer.data(), trailer.size()));

  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());

  // Transfer-encoding can be multi-valued, so GetHeader does not work.
  EXPECT_TRUE(headers_.transfer_encoding_is_chunked());
  absl::string_view field_value = headers_.GetHeader(kGibberish1);
  EXPECT_EQ(kGibberish2, field_value);
  field_value = headers_.GetHeader("foo");
  EXPECT_EQ("bar : eeep : baz", field_value);
}

// Note we reuse the header length limit because trailer is just multiple
// headers.
TEST_F(HTTPBalsaFrameTest, TrailerTooLong) {
  std::string headers =
      "HTTP/1.0 200 ok\r\n"
      "transfer-encoding: chunked\r\n"
      "\r\n";

  std::string chunks =
      "3\r\n"
      "123\r\n"
      "0\r\n";
  std::string trailer =
      "very : long trailer\n"
      "should:cause\r\n"
      "trailer :too long error\n"
      "\r\n";

  balsa_frame_.set_is_request(false);
  ASSERT_LT(headers.size(), trailer.size());
  balsa_frame_.set_max_header_length(headers.size());

  EXPECT_CALL(visitor_mock_, HandleError(BalsaFrameEnums::TRAILER_TOO_LONG));
  EXPECT_CALL(visitor_mock_, OnTrailers(_)).Times(0);
  EXPECT_CALL(visitor_mock_, MessageDone()).Times(0);
  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));
  ASSERT_EQ(chunks.size(),
            balsa_frame_.ProcessInput(chunks.data(), chunks.size()));
  EXPECT_EQ(balsa_frame_.max_header_length(),
            balsa_frame_.ProcessInput(trailer.data(), trailer.size()));
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::TRAILER_TOO_LONG, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, Parse100ContinueNoContinueHeadersNoCallback) {
  std::string continue_headers =
      "HTTP/1.1 100 Continue\r\n"
      "\r\n";

  // Do not set continue headers (or use interim callbacks). Then the parsed
  // continue headers are treated as final headers.
  balsa_frame_.set_is_request(false);
  balsa_frame_.set_use_interim_headers_callback(false);

  InSequence s;
  EXPECT_CALL(visitor_mock_, HeaderDone());
  EXPECT_CALL(visitor_mock_, MessageDone());

  ASSERT_EQ(balsa_frame_.ProcessInput(continue_headers.data(),
                                      continue_headers.size()),
            continue_headers.size())
      << balsa_frame_.ErrorCode();
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(headers_.parsed_response_code(), 100);
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
}

TEST_F(HTTPBalsaFrameTest, Parse100Continue) {
  std::string continue_headers =
      "HTTP/1.1 100 Continue\r\n"
      "\r\n";

  // The parsed continue headers are delivered as interim headers.
  balsa_frame_.set_is_request(false);
  balsa_frame_.set_use_interim_headers_callback(true);

  InSequence s;
  EXPECT_CALL(visitor_mock_, OnInterimHeaders(Pointee(Property(
                                 &BalsaHeaders::parsed_response_code, 100))));
  EXPECT_CALL(visitor_mock_, HeaderDone()).Times(0);
  EXPECT_CALL(visitor_mock_, MessageDone()).Times(0);

  ASSERT_EQ(balsa_frame_.ProcessInput(continue_headers.data(),
                                      continue_headers.size()),
            continue_headers.size())
      << balsa_frame_.ErrorCode();
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(headers_.parsed_response_code(), 0u);
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
}

// Handle two sets of headers when set up properly and the first is 100
// Continue.
TEST_F(HTTPBalsaFrameTest, Support100ContinueNoCallback) {
  std::string initial_headers =
      "HTTP/1.1 100 Continue\r\n"
      "\r\n";
  std::string real_headers =
      "HTTP/1.1 200 OK\r\n"
      "content-length: 3\r\n"
      "\r\n";
  std::string body = "foo";

  balsa_frame_.set_is_request(false);
  BalsaHeaders continue_headers;
  balsa_frame_.set_continue_headers(&continue_headers);
  balsa_frame_.set_use_interim_headers_callback(false);

  ASSERT_EQ(initial_headers.size(),
            balsa_frame_.ProcessInput(initial_headers.data(),
                                      initial_headers.size()));
  ASSERT_EQ(real_headers.size(),
            balsa_frame_.ProcessInput(real_headers.data(), real_headers.size()))
      << balsa_frame_.ErrorCode();
  ASSERT_EQ(body.size(), balsa_frame_.ProcessInput(body.data(), body.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

// Handle two sets of headers when set up properly and the first is 100
// Continue.
TEST_F(HTTPBalsaFrameTest, Support100Continue) {
  std::string initial_headers =
      "HTTP/1.1 100 Continue\r\n"
      "\r\n";
  std::string real_headers =
      "HTTP/1.1 200 OK\r\n"
      "content-length: 3\r\n"
      "\r\n";
  std::string body = "foo";

  balsa_frame_.set_is_request(false);
  balsa_frame_.set_use_interim_headers_callback(true);

  InSequence s;
  EXPECT_CALL(visitor_mock_, OnInterimHeaders(Pointee(Property(
                                 &BalsaHeaders::parsed_response_code, 100))));
  ASSERT_EQ(
      balsa_frame_.ProcessInput(initial_headers.data(), initial_headers.size()),
      initial_headers.size());
  ASSERT_FALSE(balsa_frame_.Error());

  EXPECT_CALL(visitor_mock_, HeaderDone());
  ASSERT_EQ(balsa_frame_.ProcessInput(real_headers.data(), real_headers.size()),
            real_headers.size())
      << balsa_frame_.ErrorCode();
  EXPECT_EQ(headers_.parsed_response_code(), 200);

  EXPECT_CALL(visitor_mock_, MessageDone());
  ASSERT_EQ(balsa_frame_.ProcessInput(body.data(), body.size()), body.size());

  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(balsa_frame_.ErrorCode(), BalsaFrameEnums::BALSA_NO_ERROR);
}

// If both the interim headers callback and continue headers are set, only the
// former should be used.
TEST_F(HTTPBalsaFrameTest, InterimHeadersCallbackTakesPrecedence) {
  std::string initial_headers =
      "HTTP/1.1 100 Continue\r\n"
      "\r\n";
  std::string real_headers =
      "HTTP/1.1 200 OK\r\n"
      "content-length: 3\r\n"
      "\r\n";
  std::string body = "foo";

  balsa_frame_.set_is_request(false);
  BalsaHeaders continue_headers;
  balsa_frame_.set_continue_headers(&continue_headers);
  balsa_frame_.set_use_interim_headers_callback(true);

  InSequence s;
  EXPECT_CALL(visitor_mock_, OnInterimHeaders(Pointee(Property(
                                 &BalsaHeaders::parsed_response_code, 100))));
  EXPECT_CALL(visitor_mock_, ContinueHeaderDone).Times(0);
  ASSERT_EQ(
      balsa_frame_.ProcessInput(initial_headers.data(), initial_headers.size()),
      initial_headers.size());
  EXPECT_EQ(continue_headers.parsed_response_code(), 0u);
  ASSERT_FALSE(balsa_frame_.Error());

  EXPECT_CALL(visitor_mock_, HeaderDone());
  ASSERT_EQ(balsa_frame_.ProcessInput(real_headers.data(), real_headers.size()),
            real_headers.size())
      << balsa_frame_.ErrorCode();
  EXPECT_EQ(headers_.parsed_response_code(), 200);

  EXPECT_CALL(visitor_mock_, MessageDone());
  ASSERT_EQ(balsa_frame_.ProcessInput(body.data(), body.size()), body.size());

  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(balsa_frame_.ErrorCode(), BalsaFrameEnums::BALSA_NO_ERROR);
}

// Handle two sets of headers when set up properly and the first is 100
// Continue and it meets the conditions for b/62408297.
TEST_F(HTTPBalsaFrameTest, Support100Continue401UnauthorizedNoCallback) {
  std::string initial_headers =
      "HTTP/1.1 100 Continue\r\n"
      "\r\n";
  std::string real_headers =
      "HTTP/1.1 401 Unauthorized\r\n"
      "content-length: 3\r\n"
      "\r\n";
  std::string body = "foo";

  balsa_frame_.set_is_request(false);
  BalsaHeaders continue_headers;
  balsa_frame_.set_continue_headers(&continue_headers);
  balsa_frame_.set_use_interim_headers_callback(false);

  ASSERT_EQ(initial_headers.size(),
            balsa_frame_.ProcessInput(initial_headers.data(),
                                      initial_headers.size()));
  ASSERT_EQ(real_headers.size(),
            balsa_frame_.ProcessInput(real_headers.data(), real_headers.size()))
      << balsa_frame_.ErrorCode();
  ASSERT_EQ(body.size(), balsa_frame_.ProcessInput(body.data(), body.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

// Handle two sets of headers when set up properly and the first is 100
// Continue and it meets the conditions for b/62408297.
TEST_F(HTTPBalsaFrameTest, Support100Continue401Unauthorized) {
  std::string initial_headers =
      "HTTP/1.1 100 Continue\r\n"
      "\r\n";
  std::string real_headers =
      "HTTP/1.1 401 Unauthorized\r\n"
      "content-length: 3\r\n"
      "\r\n";
  std::string body = "foo";

  balsa_frame_.set_is_request(false);
  balsa_frame_.set_use_interim_headers_callback(true);

  InSequence s;
  EXPECT_CALL(visitor_mock_, OnInterimHeaders(Pointee(Property(
           
"""


```