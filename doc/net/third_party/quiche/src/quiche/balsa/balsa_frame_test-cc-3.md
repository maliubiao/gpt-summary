Response:
The user wants a summary of the functionality of the C++ source code file `net/third_party/quiche/src/quiche/balsa/balsa_frame_test.cc`. The request also asks to identify any relationships to JavaScript, provide examples of logical reasoning with inputs and outputs, highlight common user or programming errors, explain how a user might reach this code for debugging, and finally, summarize the file's purpose as part 4 of a 6-part series.

Here's a breakdown of how to address each point:

1. **Functionality:**  The file name and the content (lots of `TEST_F` calls using `EXPECT_CALL`) clearly indicate this is a unit test file. It's testing the `BalsaFrame` class, likely responsible for parsing HTTP frames. The tests cover various scenarios like handling different HTTP methods, headers, body types (chunked, content-length), trailers, error conditions, and edge cases.

2. **Relationship to JavaScript:** HTTP is a fundamental protocol for web communication, and JavaScript often interacts with HTTP through `XMLHttpRequest` or `fetch` API calls. While this C++ code doesn't directly execute JavaScript, it's crucial for the underlying network stack that handles HTTP requests and responses initiated by JavaScript code in a browser.

3. **Logical Reasoning (Input/Output):**  Many tests follow a pattern: setting up an HTTP message (input), processing it with `balsa_frame_.ProcessInput()`, and then asserting the expected behavior through mock visitor calls (`EXPECT_CALL`). I can pick a simple test to illustrate this.

4. **User/Programming Errors:** The tests themselves often simulate error scenarios, like malformed headers, incorrect chunk encoding, or exceeding header limits. These represent common mistakes in HTTP message construction.

5. **Debugging Scenario:**  A developer working on Chromium's network stack, specifically the HTTP parsing logic, might encounter this test file. If they're fixing a bug related to how HTTP frames are processed, they might add or modify tests here to verify their fix. Breakpoints in the `BalsaFrame` code during network activity could lead them here.

6. **Overall Functionality (Part 4 of 6):**  Given that this is a test file, its purpose within a larger context is to ensure the robustness and correctness of the `BalsaFrame` class. Being part 4 of 6 suggests there might be other related test files or different categories of tests.

**Mental Sandbox Simulation:**

I'll imagine looking through the test cases:

*   `VisitorInvokedProperlyForSimpleGet`:  Input: "GET / HTTP/1.1\r\n\r\n". Output: Mock visitor calls for request line, header done, message done.
*   `VisitorInvokedProperlyForResponseWithTransferEncoding`: Input: An HTTP response with chunked encoding. Output: Mock visitor calls for response line, headers, chunk lengths, body chunks, message done.
*   `AppropriateActionTakenWhenHeadersTooLongWithTooMuchInput`: Input: A long header. Output: Mock visitor call for error handling.

I see tests for various scenarios, including error handling (e.g., `ErrorWhenHeaderKeyIsEmpty`), different header line endings, and handling of `BytesSafeToSplice` for flow control.

**Constraint Checklist & Confidence Score:**

1. List functionalities? Yes.
2. Relation to JavaScript? Yes.
3. JavaScript examples? Yes.
4. Logical reasoning? Yes.
5. Input/Output examples? Yes.
6. User/programming errors? Yes.
7. Examples of errors? Yes.
8. User operation to reach code? Yes.
9. Debugging线索? Yes.
10. Summarize functionality? Yes.
11. Part 4 of 6? Yes.

Confidence Score: 5/5. I'm confident I can address all the requirements.

Strategizing complete. I will now generate the response.

这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/balsa/balsa_frame_test.cc` 文件的功能列表：

1. **单元测试 `BalsaFrame` 类:** 该文件包含了针对 `BalsaFrame` 类的各种单元测试。`BalsaFrame` 类很可能负责 HTTP 消息的帧解析和处理。

2. **测试 HTTP 请求解析:**  测试用例模拟并验证了 `BalsaFrame` 类正确解析各种类型的 HTTP 请求，包括：
    *   简单的 GET 请求
    *   带有不同头部信息的请求
    *   带有请求体的请求 (通过 `Content-Length`)

3. **测试 HTTP 响应解析:**  测试用例模拟并验证了 `BalsaFrame` 类正确解析各种类型的 HTTP 响应，包括：
    *   带有不同状态码和状态信息的响应
    *   带有 `Content-Length` 头部的响应
    *   带有 `Transfer-Encoding: chunked` 头部的响应
    *   带有 `Transfer-Encoding: chunked` 头部和 trailers 的响应

4. **测试访问者模式的正确调用:**  该文件使用 mock 对象 (`BalsaVisitorMock`) 来验证 `BalsaFrame` 在解析过程中是否正确地调用了访问者对象的方法，例如：
    *   `OnRequestFirstLineInput` 和 `OnResponseFirstLineInput` (解析起始行)
    *   `ProcessHeaders` 和 `HeaderDone` (解析头部)
    *   `OnBodyChunkInput` 和 `OnRawBodyInput` (处理消息体)
    *   `OnChunkLength` 和 `OnChunkExtensionInput` (处理分块编码)
    *   `OnTrailers` 和 `OnTrailerInput` (处理 trailers)
    *   `MessageDone` (消息解析完成)

5. **测试错误处理:**  测试用例验证了 `BalsaFrame` 类在遇到错误情况时是否采取了适当的措施，例如：
    *   `HEADERS_TOO_LONG`: 头部过长
    *   `INVALID_HEADER_FORMAT`: 无效的头部格式
    *   `HEADER_MISSING_COLON`: 头部缺少冒号
    *   `INVALID_TRAILER_FORMAT`: 无效的 trailer 格式
    *   `INVALID_TRAILER_NAME_CHARACTER`:  Trailer 名称包含非法字符
    *   `MULTIPLE_CONTENT_LENGTH_KEYS`: 存在多个 `Content-Length` 头部
    *   `MULTIPLE_TRANSFER_ENCODING_KEYS`: 存在多个 `Transfer-Encoding` 头部
    *   `UNKNOWN_TRANSFER_ENCODING`: 未知的传输编码
    *   `CALLED_BYTES_SPLICED_WHEN_UNSAFE_TO_DO_SO`: 在不安全的时候调用了 `BytesSpliced`
    *   `CALLED_BYTES_SPLICED_AND_EXCEEDED_SAFE_SPLICE_AMOUNT`: 调用 `BytesSpliced` 超过了安全拼接量

6. **测试不同的头部行尾格式:** 验证了 `BalsaFrame` 可以处理 `\r\n`, `\n`, 以及混合的行尾格式。

7. **测试 `BytesSafeToSplice` 和 `BytesSpliced`:**  验证了用于流控制的 `BytesSafeToSplice` 和 `BytesSpliced` 方法在处理 `Content-Length` 和 chunked 编码时的正确行为。

8. **随机测试:** 包含使用随机输入块大小进行测试的用例，以提高测试覆盖率和发现潜在的边界情况。

### 与 JavaScript 的关系

虽然此 C++ 代码不直接执行 JavaScript，但它与 JavaScript 的功能有密切关系。

*   **HTTP 协议基础:** JavaScript 在浏览器环境中通过 `XMLHttpRequest` 或 `fetch` API 发起网络请求，这些请求和响应都遵循 HTTP 协议。 `BalsaFrame` 负责在 Chromium 的网络层解析这些 HTTP 消息。
*   **网络通信桥梁:**  当 JavaScript 代码发起一个 HTTP 请求时，Chromium 的网络栈会处理这个请求，包括将请求信息格式化成 HTTP 消息。当接收到服务器的响应时，`BalsaFrame` 负责解析 HTTP 响应，并将解析后的信息传递给上层 JavaScript 代码。

**举例说明:**

假设 JavaScript 代码发起一个带有 chunked 编码响应的请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.text())
  .then(data => console.log(data));
```

在这个过程中，服务器返回的 HTTP 响应可能包含如下头部：

```
HTTP/1.1 200 OK
Transfer-Encoding: chunked
...其他头部...

4\r\n
Wiki\r\n
6\r\n
pedia\r\n
E\r\n
 in\r\n\
chunks.\r\n
0\r\n
\r\n
```

`BalsaFrame` 的功能就是解析这个响应。它会：

1. 识别响应起始行 `HTTP/1.1 200 OK`。
2. 解析头部 `Transfer-Encoding: chunked`，从而知道响应体是分块编码的。
3. 读取每个 chunk 的长度 (例如 "4")。
4. 读取相应长度的数据 ("Wiki")。
5. 重复步骤 3 和 4 直到遇到长度为 0 的 chunk。
6. 将解析后的数据 ("Wikipedia in chunks.") 传递给上层。

虽然 JavaScript 代码不直接调用 `BalsaFrame`，但 `BalsaFrame` 的正确工作是 JavaScript 代码能够成功获取和处理网络数据的关键。

### 逻辑推理的假设输入与输出

**示例 1: 测试简单的 GET 请求解析**

**假设输入:**

```
GET /index.html HTTP/1.1\r\n
Host: example.com\r\n
\r\n
```

**预期输出:**

*   `visitor_mock_->OnRequestFirstLineInput` 被调用，参数为 `"GET /index.html HTTP/1.1"`, `"GET"`, `"/index.html"`, `"HTTP/1.1"`。
*   `visitor_mock_->ProcessHeaders` 被调用，参数包含键值对 `{"Host": "example.com"}`。
*   `visitor_mock_->HeaderDone` 被调用。
*   `visitor_mock_->MessageDone` 被调用。

**示例 2: 测试带有 chunked 编码的响应解析**

**假设输入:**

```
HTTP/1.1 200 OK\r\n
Transfer-Encoding: chunked\r\n
\r\n
4\r\n
Data\r\n
0\r\n
\r\n
```

**预期输出:**

*   `visitor_mock_->OnResponseFirstLineInput` 被调用，参数为 `"HTTP/1.1 200 OK"`, `"HTTP/1.1"`, `"200"`, `"OK"`。
*   `visitor_mock_->ProcessHeaders` 被调用，参数包含键值对 `{"Transfer-Encoding": "chunked"}`。
*   `visitor_mock_->HeaderDone` 被调用。
*   `visitor_mock_->OnChunkLength` 被调用，参数为 `4`。
*   `visitor_mock_->OnBodyChunkInput` 被调用，参数为 `"Data"`。
*   `visitor_mock_->OnChunkLength` 被调用，参数为 `0`。
*   `visitor_mock_->MessageDone` 被调用。

### 涉及用户或编程常见的使用错误

1. **发送过长的头部:**  用户或程序可能会生成包含非常长的头部行的 HTTP 请求或响应，超过了服务器或客户端的限制。`BalsaFrame` 的测试用例 `AppropriateActionTakenWhenHeadersTooLongWithTooMuchInput`  模拟了这种情况，并验证了 `BalsaFrame` 会触发 `HEADERS_TOO_LONG` 错误。

    **用户操作:**  一个恶意用户可能会尝试发送包含大量 cookie 或自定义头的请求，以试图利用服务器的资源。

2. **生成格式错误的头部:**  头部行的格式必须是 `name: value\r\n`。如果缺少冒号，或者头部名称包含非法字符，就会导致解析错误。测试用例 `AppropriateActionTakenWhenHeaderColonsAreFunny` 和 `ErrorWhenHeaderKeyIsEmpty` 验证了 `BalsaFrame` 对这些错误的检测。

    **编程错误:**  在手动构建 HTTP 消息时，程序员可能会不小心遗漏冒号或使用错误的字符。

3. **chunked 编码错误:**  在使用 chunked 编码时，每个 chunk 的大小和结尾格式必须正确。如果 chunk 大小不是有效的十六进制数，或者缺少结尾的 `\r\n`，就会导致解析失败。虽然在这个文件中没有直接模拟 chunk 编码错误的测试，但在 `BalsaFrame` 的实现中应该有相应的处理。

    **编程错误:**  在实现支持 chunked 编码的 HTTP 服务器时，可能会错误地计算 chunk 的大小或忘记添加结尾。

4. **Trailer 格式错误:**  如果启用了 trailers，其格式也必须遵循 HTTP 规范。测试用例 `InvalidTrailerFormat` 验证了 `BalsaFrame` 对无效 trailer 格式的检测。

    **编程错误:**  在生成带有 trailers 的 HTTP 响应时，可能会出现格式错误。

5. **多次指定 `Content-Length` 或 `Transfer-Encoding`:**  HTTP 规范通常不允许在同一个消息中多次指定 `Content-Length` 或 `Transfer-Encoding` 头部。测试用例 `TwoDifferentContentLengthHeadersIsAnError` 和 `TwoTransferEncodingHeadersIsAnError` 验证了 `BalsaFrame` 对这些冲突的检测。

    **编程错误:**  在代码中处理 HTTP 头部时，可能会错误地多次设置这些头部。

### 用户操作如何一步步地到达这里，作为调试线索

假设一个 Chromium 开发者正在调试一个与 HTTP 响应解析相关的问题，例如，一个网站的 chunked 编码的响应没有被正确地处理。以下是可能的步骤：

1. **用户报告或开发者发现 Bug:** 用户可能会报告某个网站加载不完整，或者开发者在测试中发现 chunked 编码的响应处理有问题。

2. **确定问题可能出在网络层:**  通过检查网络面板或者日志，开发者可能会怀疑问题出在 Chromium 的网络栈，特别是 HTTP 消息的解析部分。

3. **定位到 `BalsaFrame`:**  HTTP 消息的帧解析是网络栈的关键环节，开发者可能会查找负责 HTTP 消息解析的组件。 `BalsaFrame` 的名字暗示了它与 HTTP 帧处理有关。

4. **查看 `BalsaFrame` 的单元测试:** 为了理解 `BalsaFrame` 的工作原理和预期行为，开发者会查看其相关的单元测试文件，也就是 `balsa_frame_test.cc`。

5. **查找相关的测试用例:** 开发者可能会在 `balsa_frame_test.cc` 中查找与 chunked 编码相关的测试用例，例如 `VisitorInvokedProperlyForResponseWithTransferEncoding`。

6. **运行或调试测试用例:** 开发者可以运行这个特定的测试用例，看它是否通过。如果测试失败，就可以直接在这个测试用例中设置断点，查看 `BalsaFrame` 在处理 chunked 编码响应时的内部状态和逻辑。

7. **在实际网络请求中设置断点:**  开发者可能会在 `BalsaFrame::ProcessInput` 等关键方法中设置断点，然后使用 Chromium 浏览器访问出现问题的网站，以便在实际的网络请求中观察 `BalsaFrame` 的行为。

8. **分析调用栈和变量:** 当断点命中时，开发者可以查看调用栈，了解 `BalsaFrame` 是如何被调用的，以及相关的 HTTP 消息数据。他们还可以检查 `BalsaFrame` 内部的状态变量，例如当前的解析状态，已读取的字节数等。

9. **修改代码并重新测试:**  根据调试结果，开发者可能会修改 `BalsaFrame` 的代码以修复 bug。修改后，他们会重新运行相关的单元测试，确保修复有效，并且没有引入新的问题。

因此，`balsa_frame_test.cc` 文件是开发者理解和调试 `BalsaFrame` 行为的重要资源。

### 功能归纳 (第 4 部分，共 6 部分)

作为系列测试文件的第 4 部分，`balsa_frame_test.cc` 的主要功能是**详细地测试 `BalsaFrame` 类在处理各种正常和异常的 HTTP 消息帧时的行为**。它通过模拟不同的 HTTP 请求和响应场景，并使用 mock 对象验证 `BalsaFrame` 是否按照预期解析消息，调用访问者方法，以及处理错误。这部分测试可能专注于以下几个方面：

*   **更复杂的 HTTP 消息结构:** 例如，包含多种头部，带有扩展的 chunked 编码，或者包含 trailers 的消息。
*   **边界情况和错误处理:**  深入测试各种可能的错误情况，例如无效的头部格式，不符合规范的 chunked 编码，以及资源限制等。
*   **流处理和状态管理:**  验证 `BalsaFrame` 在分段接收数据时的状态管理和流控制机制。
*   **性能相关的测试 (可能在其他部分):**  虽然这个文件主要关注功能正确性，但其他部分的测试可能还会关注性能。

总而言之，`balsa_frame_test.cc` 是确保 `BalsaFrame` 类作为 HTTP 消息解析器的核心组件能够可靠、正确地工作的重要保障。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/balsa/balsa_frame_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
));
  EXPECT_EQ(message_body.size(),
            balsa_frame_.ProcessInput(message.data() + message_headers.size(),
                                      message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest,
       VisitorInvokedProperlyForResponseWithTransferEncoding) {
  std::string message_headers =
      "HTTP/1.1  \t 200 Ok all is well\r\n"
      "trAnsfer-eNcoding:  chunked\r\n"
      "\r\n";
  std::string message_body =
      "A            chunkjed extension  \r\n"
      "01234567890            more crud including numbers 123123\r\n"
      "3f\n"
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
      "0 last one\r\n"
      "\r\n";
  std::string message_body_data =
      "0123456789"
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

  std::string message =
      std::string(message_headers) + std::string(message_body);

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("trAnsfer-eNcoding", "chunked");

  balsa_frame_.set_is_request(false);
  {
    InSequence s1;
    EXPECT_CALL(visitor_mock_,
                OnResponseFirstLineInput("HTTP/1.1  \t 200 Ok all is well",
                                         "HTTP/1.1", "200", "Ok all is well"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, OnChunkLength(10));
    EXPECT_CALL(visitor_mock_, OnChunkLength(63));
    EXPECT_CALL(visitor_mock_, OnChunkLength(0));
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(message_headers));
  std::string body_input;
  EXPECT_CALL(visitor_mock_, OnRawBodyInput(_))
      .WillRepeatedly([&body_input](absl::string_view input) {
        absl::StrAppend(&body_input, input);
      });
  std::string body_data;
  EXPECT_CALL(visitor_mock_, OnBodyChunkInput(_))
      .WillRepeatedly([&body_data](absl::string_view input) {
        absl::StrAppend(&body_data, input);
      });
  EXPECT_CALL(visitor_mock_, OnTrailerInput(_)).Times(0);

  ASSERT_EQ(message_headers.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_EQ(message_body.size(),
            balsa_frame_.ProcessInput(message.data() + message_headers.size(),
                                      message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());

  EXPECT_EQ(message_body, body_input);
  EXPECT_EQ(message_body_data, body_data);
}

TEST_F(HTTPBalsaFrameTest,
       VisitorInvokedProperlyForResponseWithTransferEncodingAndTrailers) {
  std::string message_headers =
      "HTTP/1.1  \t 200 Ok all is well\r\n"
      "trAnsfer-eNcoding:  chunked\r\n"
      "\r\n";
  std::string message_body =
      "A            chunkjed extension  \r\n"
      "01234567890            more crud including numbers 123123\r\n"
      "3f\n"
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
      "0 last one\r\n";
  std::string trailer_data =
      "a_trailer_key: and a trailer value\r\n"
      "\r\n";
  std::string message_body_data =
      "0123456789"
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

  std::string message = (std::string(message_headers) +
                         std::string(message_body) + std::string(trailer_data));

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("trAnsfer-eNcoding", "chunked");

  FakeHeaders fake_headers_in_trailer;
  fake_headers_in_trailer.AddKeyValue("a_trailer_key", "and a trailer value");

  balsa_frame_.set_is_request(false);

  {
    InSequence s1;
    EXPECT_CALL(visitor_mock_,
                OnResponseFirstLineInput("HTTP/1.1  \t 200 Ok all is well",
                                         "HTTP/1.1", "200", "Ok all is well"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, OnChunkLength(10));
    EXPECT_CALL(visitor_mock_, OnChunkLength(63));
    EXPECT_CALL(visitor_mock_, OnChunkLength(0));
    EXPECT_CALL(visitor_mock_, OnTrailers(fake_headers_in_trailer));
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(message_headers));
  std::string body_input;
  EXPECT_CALL(visitor_mock_, OnRawBodyInput(_))
      .WillRepeatedly([&body_input](absl::string_view input) {
        absl::StrAppend(&body_input, input);
      });
  std::string body_data;
  EXPECT_CALL(visitor_mock_, OnBodyChunkInput(_))
      .WillRepeatedly([&body_data](absl::string_view input) {
        absl::StrAppend(&body_data, input);
      });
  EXPECT_CALL(visitor_mock_, OnTrailerInput(trailer_data));

  ASSERT_EQ(message_headers.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_EQ(message_body.size() + trailer_data.size(),
            balsa_frame_.ProcessInput(message.data() + message_headers.size(),
                                      message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());

  EXPECT_EQ(message_body, body_input);
  EXPECT_EQ(message_body_data, body_data);
}

TEST_F(
    HTTPBalsaFrameTest,
    VisitorInvokedProperlyForResponseWithTransferEncodingAndTrailersBytePer) {
  std::string message_headers =
      "HTTP/1.1  \t 200 Ok all is well\r\n"
      "trAnsfer-eNcoding:  chunked\r\n"
      "\r\n";
  std::string message_body =
      "A            chunkjed extension  \r\n"
      "01234567890            more crud including numbers 123123\r\n"
      "3f\n"
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
      "0 last one\r\n";
  std::string trailer_data =
      "a_trailer_key: and a trailer value\r\n"
      "\r\n";
  std::string message_body_data =
      "0123456789"
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

  std::string message = (std::string(message_headers) +
                         std::string(message_body) + std::string(trailer_data));

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("trAnsfer-eNcoding", "chunked");
  FakeHeaders fake_headers_in_trailer;
  fake_headers_in_trailer.AddKeyValue("a_trailer_key", "and a trailer value");

  balsa_frame_.set_is_request(false);

  {
    InSequence s1;
    EXPECT_CALL(visitor_mock_,
                OnResponseFirstLineInput("HTTP/1.1  \t 200 Ok all is well",
                                         "HTTP/1.1", "200", "Ok all is well"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, OnChunkLength(10));
    EXPECT_CALL(visitor_mock_, OnChunkLength(63));
    EXPECT_CALL(visitor_mock_, OnChunkLength(0));
    EXPECT_CALL(visitor_mock_, OnTrailers(fake_headers_in_trailer));
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(message_headers));
  std::string body_input;
  EXPECT_CALL(visitor_mock_, OnRawBodyInput(_))
      .WillRepeatedly([&body_input](absl::string_view input) {
        absl::StrAppend(&body_input, input);
      });
  std::string body_data;
  EXPECT_CALL(visitor_mock_, OnBodyChunkInput(_))
      .WillRepeatedly([&body_data](absl::string_view input) {
        absl::StrAppend(&body_data, input);
      });
  std::string trailer_input;
  EXPECT_CALL(visitor_mock_, OnTrailerInput(_))
      .WillRepeatedly([&trailer_input](absl::string_view input) {
        absl::StrAppend(&trailer_input, input);
      });

  for (size_t i = 0; i < message.size(); ++i) {
    ASSERT_EQ(1u, balsa_frame_.ProcessInput(message.data() + i, 1));
  }
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());

  EXPECT_EQ(message_body, body_input);
  EXPECT_EQ(message_body_data, body_data);
  EXPECT_EQ(trailer_data, trailer_input);
}

TEST(HTTPBalsaFrame,
     VisitorInvokedProperlyForResponseWithTransferEncodingAndTrailersRandom) {
  TestSeed seed;
  seed.Initialize(GetQuicheCommandLineFlag(FLAGS_randseed));
  RandomEngine rng;
  rng.seed(seed.GetSeed());
  for (int i = 0; i < 1000; ++i) {
    std::string message_headers =
        "HTTP/1.1  \t 200 Ok all is well\r\n"
        "trAnsfer-eNcoding:  chunked\r\n"
        "\r\n";
    std::string message_body =
        "A            chunkjed extension  \r\n"
        "01234567890            more crud including numbers 123123\r\n"
        "3f\n"
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
        "0 last one\r\n";
    std::string trailer_data =
        "a_trailer_key: and a trailer value\r\n"
        "\r\n";
    std::string message_body_data =
        "0123456789"
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

    std::string message =
        (std::string(message_headers) + std::string(message_body) +
         std::string(trailer_data));

    FakeHeaders fake_headers;
    fake_headers.AddKeyValue("trAnsfer-eNcoding", "chunked");
    FakeHeaders fake_headers_in_trailer;
    fake_headers_in_trailer.AddKeyValue("a_trailer_key", "and a trailer value");

    StrictMock<BalsaVisitorMock> visitor_mock;

    BalsaHeaders headers;
    BalsaFrame balsa_frame;
    balsa_frame.set_is_request(false);
    balsa_frame.set_balsa_headers(&headers);
    balsa_frame.EnableTrailers();
    balsa_frame.set_balsa_visitor(&visitor_mock);

    {
      InSequence s1;
      EXPECT_CALL(visitor_mock, OnResponseFirstLineInput(
                                    "HTTP/1.1  \t 200 Ok all is well",
                                    "HTTP/1.1", "200", "Ok all is well"));
      EXPECT_CALL(visitor_mock, ProcessHeaders(fake_headers));
      EXPECT_CALL(visitor_mock, HeaderDone());
      EXPECT_CALL(visitor_mock, OnTrailers(fake_headers_in_trailer));
      EXPECT_CALL(visitor_mock, MessageDone());
    }
    EXPECT_CALL(visitor_mock, OnHeaderInput(message_headers));
    std::string body_input;
    EXPECT_CALL(visitor_mock, OnRawBodyInput(_))
        .WillRepeatedly([&body_input](absl::string_view input) {
          absl::StrAppend(&body_input, input);
        });
    std::string body_data;
    EXPECT_CALL(visitor_mock, OnBodyChunkInput(_))
        .WillRepeatedly([&body_data](absl::string_view input) {
          absl::StrAppend(&body_data, input);
        });
    std::string trailer_input;
    EXPECT_CALL(visitor_mock, OnTrailerInput(_))
        .WillRepeatedly([&trailer_input](absl::string_view input) {
          absl::StrAppend(&trailer_input, input);
        });
    EXPECT_CALL(visitor_mock, OnChunkLength(_)).Times(AtLeast(1));
    EXPECT_CALL(visitor_mock, OnChunkExtensionInput(_)).Times(AtLeast(1));

    size_t count = 0;
    size_t total_processed = 0;
    for (size_t j = 0; j < message.size();) {
      auto dist = std::uniform_int_distribution<>(0, message.size() - j + 1);
      count = dist(rng);
      size_t processed = balsa_frame.ProcessInput(message.data() + j, count);
      ASSERT_GE(count, processed);
      total_processed += processed;
      j += processed;
    }
    EXPECT_EQ(message.size(), total_processed);
    EXPECT_TRUE(balsa_frame.MessageFullyRead());
    EXPECT_FALSE(balsa_frame.Error());
    EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame.ErrorCode());

    EXPECT_EQ(message_body, body_input);
    EXPECT_EQ(message_body_data, body_data);
    EXPECT_EQ(trailer_data, trailer_input);
  }
}

TEST_F(HTTPBalsaFrameTest,
       AppropriateActionTakenWhenHeadersTooLongWithTooMuchInput) {
  const absl::string_view message =
      "GET /asflkasfdhjsafdkljhasfdlkjhasdflkjhsafdlkjhh HTTP/1.1";
  const size_t kAmountLessThanHeaderLen = 10;
  ASSERT_LE(kAmountLessThanHeaderLen, message.size());

  auto error_code = BalsaFrameEnums::HEADERS_TOO_LONG;
  EXPECT_CALL(visitor_mock_, HandleError(error_code));

  balsa_frame_.set_max_header_length(message.size() - kAmountLessThanHeaderLen);

  ASSERT_EQ(balsa_frame_.max_header_length(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::HEADERS_TOO_LONG, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, AppropriateActionTakenWhenHeadersTooLongWithBody) {
  std::string message =
      "PUT /foo HTTP/1.1\r\n"
      "Content-Length: 4\r\n"
      "header: xxxxxxxxx\r\n\r\n"
      "B";  // body begin

  auto error_code = BalsaFrameEnums::HEADERS_TOO_LONG;
  EXPECT_CALL(visitor_mock_, HandleError(error_code));

  // -2 because we have 1 byte of body, and we want to refuse
  // this.
  balsa_frame_.set_max_header_length(message.size() - 2);

  ASSERT_EQ(balsa_frame_.max_header_length(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::HEADERS_TOO_LONG, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, AppropriateActionTakenWhenHeadersTooLongWhenReset) {
  std::string message =
      "GET /asflkasfdhjsafdkljhasfdlkjhasdflkjhsafdlkjhh HTTP/1.1\r\n"
      "\r\n";
  const size_t kAmountLessThanHeaderLen = 10;
  ASSERT_LE(kAmountLessThanHeaderLen, message.size());

  auto error_code = BalsaFrameEnums::HEADERS_TOO_LONG;

  ASSERT_EQ(message.size() - 2,
            balsa_frame_.ProcessInput(message.data(), message.size() - 2));

  // Now set max header length to something smaller.
  balsa_frame_.set_max_header_length(message.size() - kAmountLessThanHeaderLen);
  EXPECT_CALL(visitor_mock_, HandleError(error_code));

  ASSERT_EQ(0u,
            balsa_frame_.ProcessInput(message.data() + message.size() - 2, 2));
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::HEADERS_TOO_LONG, balsa_frame_.ErrorCode());
}

class BalsaFrameParsingTest : public QuicheTest {
 protected:
  void SetUp() override {
    balsa_frame_.set_is_request(true);
    balsa_frame_.set_balsa_headers(&headers_);
    balsa_frame_.set_balsa_visitor(&visitor_mock_);
  }

  void TestEmptyHeaderKeyHelper(const std::string& message) {
    InSequence s;
    EXPECT_CALL(visitor_mock_, OnRequestFirstLineInput("GET / HTTP/1.1", "GET",
                                                       "/", "HTTP/1.1"));
    EXPECT_CALL(visitor_mock_, OnHeaderInput(_));
    EXPECT_CALL(visitor_mock_,
                HandleError(BalsaFrameEnums::INVALID_HEADER_FORMAT));

    ASSERT_EQ(message.size(),
              balsa_frame_.ProcessInput(message.data(), message.size()));
    EXPECT_TRUE(balsa_frame_.Error());
    Mock::VerifyAndClearExpectations(&visitor_mock_);
  }

  void TestInvalidTrailerFormat(const std::string& trailer,
                                bool invalid_name_char) {
    balsa_frame_.set_is_request(false);
    balsa_frame_.EnableTrailers();

    std::string headers =
        "HTTP/1.0 200 ok\r\n"
        "transfer-encoding: chunked\r\n"
        "\r\n";

    std::string chunks =
        "3\r\n"
        "123\r\n"
        "0\r\n";

    InSequence s;

    EXPECT_CALL(visitor_mock_, OnResponseFirstLineInput);
    EXPECT_CALL(visitor_mock_, OnHeaderInput);
    EXPECT_CALL(visitor_mock_, ProcessHeaders);
    EXPECT_CALL(visitor_mock_, HeaderDone);
    EXPECT_CALL(visitor_mock_, OnChunkLength(3));
    EXPECT_CALL(visitor_mock_, OnChunkExtensionInput);
    EXPECT_CALL(visitor_mock_, OnRawBodyInput);
    EXPECT_CALL(visitor_mock_, OnBodyChunkInput);
    EXPECT_CALL(visitor_mock_, OnChunkLength(0));
    EXPECT_CALL(visitor_mock_, OnChunkExtensionInput);
    EXPECT_CALL(visitor_mock_, OnRawBodyInput);
    EXPECT_CALL(visitor_mock_, OnRawBodyInput);
    const auto expected_error =
        invalid_name_char ? BalsaFrameEnums::INVALID_TRAILER_NAME_CHARACTER
                          : BalsaFrameEnums::INVALID_TRAILER_FORMAT;
    EXPECT_CALL(visitor_mock_, HandleError(expected_error)).Times(1);

    EXPECT_CALL(visitor_mock_, OnTrailers(_)).Times(0);
    EXPECT_CALL(visitor_mock_, MessageDone()).Times(0);

    ASSERT_EQ(headers.size(),
              balsa_frame_.ProcessInput(headers.data(), headers.size()));
    ASSERT_EQ(chunks.size(),
              balsa_frame_.ProcessInput(chunks.data(), chunks.size()));
    EXPECT_EQ(trailer.size(),
              balsa_frame_.ProcessInput(trailer.data(), trailer.size()));
    EXPECT_FALSE(balsa_frame_.MessageFullyRead());
    EXPECT_TRUE(balsa_frame_.Error());
    EXPECT_EQ(expected_error, balsa_frame_.ErrorCode());

    Mock::VerifyAndClearExpectations(&visitor_mock_);
  }

  BalsaHeaders headers_;
  BalsaFrame balsa_frame_;
  StrictMock<BalsaVisitorMock> visitor_mock_;
};

TEST_F(BalsaFrameParsingTest, AppropriateActionTakenWhenHeaderColonsAreFunny) {
  std::string message =
      "GET / HTTP/1.1\r\n"
      "a\r\n"
      "b\r\n"
      "c\r\n"
      "d\r\n"
      "e\r\n"
      "f\r\n"
      "g\r\n"
      "h\r\n"
      "i:\r\n"
      "j\r\n"
      "k\r\n"
      "l\r\n"
      "m\r\n"
      "n\r\n"
      "o\r\n"
      "p\r\n"
      "q\r\n"
      "r\r\n"
      "s\r\n"
      "t\r\n"
      "u\r\n"
      "v\r\n"
      "w\r\n"
      "x\r\n"
      "y\r\n"
      "z\r\n"
      "A\r\n"
      "B\r\n"
      ": val\r\n"
      "\r\n";

  EXPECT_CALL(visitor_mock_, OnRequestFirstLineInput("GET / HTTP/1.1", "GET",
                                                     "/", "HTTP/1.1"));
  EXPECT_CALL(visitor_mock_, OnHeaderInput(_));
  EXPECT_CALL(visitor_mock_,
              HandleWarning(BalsaFrameEnums::HEADER_MISSING_COLON))
      .Times(27);
  EXPECT_CALL(visitor_mock_,
              HandleError(BalsaFrameEnums::INVALID_HEADER_FORMAT));

  ASSERT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));

  EXPECT_TRUE(balsa_frame_.Error());
}

TEST_F(BalsaFrameParsingTest, ErrorWhenHeaderKeyIsEmpty) {
  std::string firstKeyIsEmpty =
      "GET / HTTP/1.1\r\n"
      ": \r\n"
      "a:b\r\n"
      "c:d\r\n"
      "\r\n";
  TestEmptyHeaderKeyHelper(firstKeyIsEmpty);

  balsa_frame_.Reset();

  std::string laterKeyIsEmpty =
      "GET / HTTP/1.1\r\n"
      "a:b\r\n"
      ": \r\n"
      "c:d\r\n"
      "\r\n";
  TestEmptyHeaderKeyHelper(laterKeyIsEmpty);
}

TEST_F(BalsaFrameParsingTest, InvalidTrailerFormat) {
  std::string trailer =
      ":monkeys\n"
      "\r\n";
  TestInvalidTrailerFormat(trailer, /*invalid_name_char=*/false);

  balsa_frame_.Reset();

  std::string trailer2 =
      "   \r\n"
      "test: test\r\n"
      "\r\n";
  TestInvalidTrailerFormat(trailer2, /*invalid_name_char=*/true);

  balsa_frame_.Reset();

  std::string trailer3 =
      "a: b\r\n"
      ": test\r\n"
      "\r\n";
  TestInvalidTrailerFormat(trailer3, /*invalid_name_char=*/false);
}

TEST_F(HTTPBalsaFrameTest,
       EnsureHeaderFramingFoundWithVariousCombinationsOfRN_RN) {
  const std::string message =
      "GET / HTTP/1.1\r\n"
      "content-length: 0\r\n"
      "a\r\n"
      "b\r\n"
      "c\r\n"
      "d\r\n"
      "e\r\n"
      "f\r\n"
      "g\r\n"
      "h\r\n"
      "i\r\n"
      "\r\n";
  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_FALSE(balsa_frame_.Error())
      << BalsaFrameEnums::ErrorCodeToString(balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest,
       EnsureHeaderFramingFoundWithVariousCombinationsOfRN_N) {
  const std::string message =
      "GET / HTTP/1.1\n"
      "content-length: 0\n"
      "a\n"
      "b\n"
      "c\n"
      "d\n"
      "e\n"
      "f\n"
      "g\n"
      "h\n"
      "i\n"
      "\n";
  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_FALSE(balsa_frame_.Error())
      << BalsaFrameEnums::ErrorCodeToString(balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest,
       EnsureHeaderFramingFoundWithVariousCombinationsOfRN_RN_N) {
  const std::string message =
      "GET / HTTP/1.1\n"
      "content-length: 0\r\n"
      "a\r\n"
      "b\n"
      "c\r\n"
      "d\n"
      "e\r\n"
      "f\n"
      "g\r\n"
      "h\n"
      "i\r\n"
      "\n";
  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_FALSE(balsa_frame_.Error())
      << BalsaFrameEnums::ErrorCodeToString(balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest,
       EnsureHeaderFramingFoundWithVariousCombinationsOfRN_N_RN) {
  const std::string message =
      "GET / HTTP/1.1\n"
      "content-length: 0\r\n"
      "a\n"
      "b\r\n"
      "c\n"
      "d\r\n"
      "e\n"
      "f\r\n"
      "g\n"
      "h\r\n"
      "i\n"
      "\r\n";
  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_FALSE(balsa_frame_.Error())
      << BalsaFrameEnums::ErrorCodeToString(balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, ReadUntilCloseStateEnteredAsExpectedAndNotExited) {
  std::string message =
      "HTTP/1.1 200 OK\r\n"
      "\r\n";
  balsa_frame_.set_is_request(false);
  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_FALSE(balsa_frame_.Error())
      << BalsaFrameEnums::ErrorCodeToString(balsa_frame_.ErrorCode());
  EXPECT_EQ(BalsaFrameEnums::READING_UNTIL_CLOSE, balsa_frame_.ParseState());

  std::string gobldygook = "-198324-9182-43981-23498-98342-jasldfn-1294hj";
  for (int i = 0; i < 1000; ++i) {
    EXPECT_EQ(gobldygook.size(),
              balsa_frame_.ProcessInput(gobldygook.data(), gobldygook.size()));
    EXPECT_FALSE(balsa_frame_.Error())
        << BalsaFrameEnums::ErrorCodeToString(balsa_frame_.ErrorCode());
    EXPECT_EQ(BalsaFrameEnums::READING_UNTIL_CLOSE, balsa_frame_.ParseState());
  }
}

TEST_F(HTTPBalsaFrameTest,
       BytesSafeToSpliceAndBytesSplicedWorksWithContentLength) {
  std::string header =
      "HTTP/1.1 200 OK\r\n"
      "content-length: 1000\r\n"
      "\r\n";
  balsa_frame_.set_is_request(false);
  size_t bytes_safe_to_splice = 1000;
  EXPECT_EQ(0u, balsa_frame_.BytesSafeToSplice());
  EXPECT_EQ(header.size(),
            balsa_frame_.ProcessInput(header.data(), header.size()));
  EXPECT_EQ(bytes_safe_to_splice, balsa_frame_.BytesSafeToSplice());
  while (bytes_safe_to_splice > 0) {
    balsa_frame_.BytesSpliced(1);
    bytes_safe_to_splice -= 1;
    ASSERT_FALSE(balsa_frame_.Error())
        << BalsaFrameEnums::ParseStateToString(balsa_frame_.ParseState()) << " "
        << BalsaFrameEnums::ErrorCodeToString(balsa_frame_.ErrorCode())
        << " with bytes_safe_to_splice: " << bytes_safe_to_splice
        << " and BytesSafeToSplice(): " << balsa_frame_.BytesSafeToSplice();
  }
  EXPECT_EQ(0u, balsa_frame_.BytesSafeToSplice());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
}

TEST_F(HTTPBalsaFrameTest, BytesSplicedFlagsErrorsWhenNotInProperState) {
  balsa_frame_.set_is_request(false);
  balsa_frame_.BytesSpliced(1);
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::CALLED_BYTES_SPLICED_WHEN_UNSAFE_TO_DO_SO,
            balsa_frame_.ErrorCode());
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
}

TEST_F(HTTPBalsaFrameTest,
       BytesSplicedFlagsErrorsWhenTooMuchSplicedForContentLen) {
  std::string header =
      "HTTP/1.1 200 OK\r\n"
      "content-length: 1000\r\n"
      "\r\n";
  balsa_frame_.set_is_request(false);
  EXPECT_EQ(0u, balsa_frame_.BytesSafeToSplice());
  EXPECT_EQ(header.size(),
            balsa_frame_.ProcessInput(header.data(), header.size()));
  EXPECT_EQ(1000u, balsa_frame_.BytesSafeToSplice());
  balsa_frame_.BytesSpliced(1001);
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(
      BalsaFrameEnums::CALLED_BYTES_SPLICED_AND_EXCEEDED_SAFE_SPLICE_AMOUNT,
      balsa_frame_.ErrorCode());
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
}

TEST_F(HTTPBalsaFrameTest, BytesSplicedWorksAsExpectedForReadUntilClose) {
  std::string header =
      "HTTP/1.1 200 OK\r\n"
      "\r\n";
  balsa_frame_.set_is_request(false);
  EXPECT_EQ(0u, balsa_frame_.BytesSafeToSplice());
  EXPECT_EQ(header.size(),
            balsa_frame_.ProcessInput(header.data(), header.size()));
  EXPECT_EQ(BalsaFrameEnums::READING_UNTIL_CLOSE, balsa_frame_.ParseState());
  EXPECT_EQ(std::numeric_limits<size_t>::max(),
            balsa_frame_.BytesSafeToSplice());
  for (int i = 0; i < 1000; ++i) {
    EXPECT_EQ(std::numeric_limits<size_t>::max(),
              balsa_frame_.BytesSafeToSplice());
    balsa_frame_.BytesSpliced(12312312);
    EXPECT_FALSE(balsa_frame_.Error());
    EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  }
  EXPECT_EQ(std::numeric_limits<size_t>::max(),
            balsa_frame_.BytesSafeToSplice());
}

TEST_F(HTTPBalsaFrameTest,
       BytesSplicedFlagsErrorsWhenTooMuchSplicedForChunked) {
  std::string header =
      "HTTP/1.1 200 OK\r\n"
      "transfer-encoding: chunked\r\n"
      "\r\n";
  std::string body_fragment = "a\r\n";
  balsa_frame_.set_is_request(false);
  EXPECT_EQ(0u, balsa_frame_.BytesSafeToSplice());
  EXPECT_EQ(header.size(),
            balsa_frame_.ProcessInput(header.data(), header.size()));
  EXPECT_EQ(0u, balsa_frame_.BytesSafeToSplice());
  EXPECT_EQ(
      body_fragment.size(),
      balsa_frame_.ProcessInput(body_fragment.data(), body_fragment.size()));
  EXPECT_EQ(10u, balsa_frame_.BytesSafeToSplice());
  balsa_frame_.BytesSpliced(11);
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(
      BalsaFrameEnums::CALLED_BYTES_SPLICED_AND_EXCEEDED_SAFE_SPLICE_AMOUNT,
      balsa_frame_.ErrorCode());
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
}

TEST_F(HTTPBalsaFrameTest, BytesSafeToSpliceAndBytesSplicedWorksWithChunks) {
  std::string header =
      "HTTP/1.1 200 OK\r\n"
      "transfer-encoding: chunked\r\n"
      "\r\n";
  balsa_frame_.set_is_request(false);
  EXPECT_EQ(0u, balsa_frame_.BytesSafeToSplice());
  EXPECT_EQ(header.size(),
            balsa_frame_.ProcessInput(header.data(), header.size()));

  {
    std::string body_fragment = "3e8\r\n";
    EXPECT_FALSE(balsa_frame_.MessageFullyRead());
    size_t bytes_safe_to_splice = 1000;
    EXPECT_EQ(0u, balsa_frame_.BytesSafeToSplice());
    EXPECT_EQ(
        body_fragment.size(),
        balsa_frame_.ProcessInput(body_fragment.data(), body_fragment.size()));
    EXPECT_EQ(bytes_safe_to_splice, balsa_frame_.BytesSafeToSplice());
    while (bytes_safe_to_splice > 0) {
      balsa_frame_.BytesSpliced(1);
      bytes_safe_to_splice -= 1;
      ASSERT_FALSE(balsa_frame_.Error());
    }
    EXPECT_EQ(0u, balsa_frame_.BytesSafeToSplice());
    EXPECT_FALSE(balsa_frame_.Error());
  }
  {
    std::string body_fragment = "\r\n7d0\r\n";
    EXPECT_FALSE(balsa_frame_.MessageFullyRead());
    size_t bytes_safe_to_splice = 2000;
    EXPECT_EQ(0u, balsa_frame_.BytesSafeToSplice());
    EXPECT_EQ(
        body_fragment.size(),
        balsa_frame_.ProcessInput(body_fragment.data(), body_fragment.size()));
    EXPECT_EQ(bytes_safe_to_splice, balsa_frame_.BytesSafeToSplice());
    while (bytes_safe_to_splice > 0) {
      balsa_frame_.BytesSpliced(1);
      bytes_safe_to_splice -= 1;
      ASSERT_FALSE(balsa_frame_.Error());
    }
    EXPECT_EQ(0u, balsa_frame_.BytesSafeToSplice());
    EXPECT_FALSE(balsa_frame_.Error());
  }
  {
    std::string body_fragment = "\r\n1\r\n";
    EXPECT_FALSE(balsa_frame_.MessageFullyRead());
    size_t bytes_safe_to_splice = 1;
    EXPECT_EQ(0u, balsa_frame_.BytesSafeToSplice());
    EXPECT_EQ(
        body_fragment.size(),
        balsa_frame_.ProcessInput(body_fragment.data(), body_fragment.size()));
    EXPECT_EQ(bytes_safe_to_splice, balsa_frame_.BytesSafeToSplice());
    while (bytes_safe_to_splice > 0) {
      balsa_frame_.BytesSpliced(1);
      bytes_safe_to_splice -= 1;
      ASSERT_FALSE(balsa_frame_.Error());
    }
    EXPECT_EQ(0u, balsa_frame_.BytesSafeToSplice());
    EXPECT_FALSE(balsa_frame_.Error());
  }
  {
    std::string body_fragment = "\r\n0\r\n\r\n";
    EXPECT_FALSE(balsa_frame_.MessageFullyRead());
    EXPECT_EQ(0u, balsa_frame_.BytesSafeToSplice());
    EXPECT_EQ(
        body_fragment.size(),
        balsa_frame_.ProcessInput(body_fragment.data(), body_fragment.size()));
    EXPECT_EQ(0u, balsa_frame_.BytesSafeToSplice());
    EXPECT_FALSE(balsa_frame_.Error());
  }
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
}

TEST_F(HTTPBalsaFrameTest, TwoDifferentContentLengthHeadersIsAnError) {
  std::string header =
      "HTTP/1.1 200 OK\r\n"
      "content-length: 12\r\n"
      "content-length: 14\r\n"
      "\r\n";
  balsa_frame_.set_is_request(false);
  balsa_frame_.ProcessInput(header.data(), header.size());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::MULTIPLE_CONTENT_LENGTH_KEYS,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, TwoSameContentLengthHeadersIsNotAnError) {
  std::string header =
      "POST / HTTP/1.1\r\n"
      "content-length: 1\r\n"
      "content-length: 1\r\n"
      "\r\n"
      "1";
  balsa_frame_.ProcessInput(header.data(), header.size());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
  EXPECT_FALSE(balsa_frame_.Error());
  balsa_frame_.ProcessInput(header.data(), header.size());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
}

TEST_F(HTTPBalsaFrameTest, TwoSameContentLengthHeadersIsAnError) {
  HttpValidationPolicy http_validation_policy;
  http_validation_policy.disallow_multiple_content_length = true;
  balsa_frame_.set_http_validation_policy(http_validation_policy);

  std::string header =
      "POST / HTTP/1.1\r\n"
      "content-length: 1\r\n"
      "content-length: 1\r\n"
      "\r\n"
      "1";
  balsa_frame_.ProcessInput(header.data(), header.size());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::MULTIPLE_CONTENT_LENGTH_KEYS,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, TwoTransferEncodingHeadersIsAnError) {
  std::string header =
      "HTTP/1.1 200 OK\r\n"
      "transfer-encoding: chunked\r\n"
      "transfer-encoding: identity\r\n"
      "content-length: 3\r\n"
      "\r\n";
  balsa_frame_.set_is_request(false);
  balsa_frame_.ProcessInput(header.data(), header.size());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::MULTIPLE_TRANSFER_ENCODING_KEYS,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, AcceptTwoTransferEncodingHeaders) {
  HttpValidationPolicy http_validation_policy;
  http_validation_policy.validate_transfer_encoding = false;
  balsa_frame_.set_http_validation_policy(http_validation_policy);

  std::string header =
      "HTTP/1.1 200 OK\r\n"
      "transfer-encoding: chunked\r\n"
      "transfer-encoding: identity\r\n"
      "content-length: 3\r\n"
      "\r\n";
  balsa_frame_.set_is_request(false);
  balsa_frame_.ProcessInput(header.data(), header.size());

  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, TwoTransferEncodingTokensIsAnError) {
  std::string header =
      "HTTP/1.1 200 OK\r\n"
      "transfer-encoding: chunked, identity\r\n"
      "content-length: 3\r\n"
      "\r\n";
  balsa_frame_.set_is_request(false);
  balsa_frame_.ProcessInput(header.data(), header.size());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::UNKNOWN_TRANSFER_ENCODING,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, AcceptTwoTransferEncodingTokens) {
  HttpValidationPolicy http_validation_policy;
  http_validation_policy.validate_transfer_encoding = false;
  balsa_frame_.set_http_validation_policy(http_validation_policy);

  std::string header =
      "HTTP/1.1 200 OK\r\n"
      "transfer-encoding: chunked, identity\r\n"
      "content-length: 3\r\n"
      "\r\n";
  balsa_frame_.set_is_request(false);
  balsa_frame_.ProcessInput(header.data(), header.size());

  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, UnknownTransferEncodingTokenIsAnError) {
  std::string header =
      "HTTP/1.1 200 OK\r\n"
      "transfer-encoding: chunked-identity\r\n"
      "content-length: 3\r\n"
      "\r\n";
  balsa_frame_.set_is_request(false);
  balsa_frame_.ProcessInput(header.data(), header.size());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::UNKNOWN_TRANSFER_ENCODING,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, AcceptUnknownTransferEncodingToken) {
  HttpValidationPolicy http_validation_policy;
  http_validation_policy.validate_transfer_encoding = false;
  balsa_frame_.set_http_validation_policy(http_va
```