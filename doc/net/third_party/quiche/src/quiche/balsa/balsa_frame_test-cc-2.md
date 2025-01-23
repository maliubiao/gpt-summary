Response:
The user wants to understand the functionality of the C++ source code file `net/third_party/quiche/src/quiche/balsa/balsa_frame_test.cc`. They are particularly interested in its relation to JavaScript, logical reasoning with input and output examples, common usage errors, and debugging tips.

Based on the file name and the code content, it appears to be a unit test file for a component named `BalsaFrame`, which is likely involved in parsing and processing HTTP frames.

Here's a breakdown of the thought process:

1. **Identify the core function:** The file name `balsa_frame_test.cc` strongly suggests that it's a test file. The presence of `TEST_F` macros confirms this. The tests are for a class called `HTTPBalsaFrameTest`, which likely tests the functionality of a class named `BalsaFrame`.

2. **Analyze the test structure:** Each `TEST_F` function represents a specific test case. These test cases typically set up input data (HTTP headers and body), configure expectations on a mock object (`visitor_mock_`), call the `ProcessInput` method of the `balsa_frame_`, and then assert the outcomes (e.g., whether the message is fully read, if an error occurred, and the error code).

3. **Determine the purpose of the tested component:** The tests cover various scenarios related to HTTP frame processing, including:
    * Parsing request and response first lines.
    * Handling different header formats and values.
    * Processing chunked transfer encoding, including error cases like invalid chunk lengths and overflows.
    * Handling content length.
    * Validating target URIs.
    * Handling warnings and errors during parsing.

4. **Assess the relevance to JavaScript:**  HTTP is a fundamental protocol for web communication, which includes interactions between JavaScript in web browsers and backend servers. While the C++ code itself isn't directly executed by JavaScript, its purpose is to process HTTP messages that are frequently generated and consumed by JavaScript applications.

5. **Generate examples for logical reasoning:** For each test case, identify the input (HTTP message) and the expected behavior (mock object calls, return values, error status). This demonstrates the logical flow and the component's responses to different inputs.

6. **Identify potential user/programming errors:** Analyze the test cases that simulate error conditions (e.g., invalid chunk length, content length overflow, invalid target URI). These scenarios represent common mistakes developers might make when constructing HTTP messages or when servers send malformed responses.

7. **Trace user operations for debugging:** Think about how a user action in a browser (like clicking a link, submitting a form, or loading a page) would lead to HTTP requests and responses. The `BalsaFrame` component is involved in parsing these messages, so its tests provide insights into how it handles different aspects of the HTTP protocol.

8. **Summarize the functionality:** Based on the analysis, provide a concise overview of the file's purpose and the functionality of the `BalsaFrame` component it tests. Emphasize its role in HTTP parsing and validation.

9. **Address the "Part 3 of 6" instruction:**  Acknowledge that this is a part of a larger set and reiterate the core function based on the observed test cases. Since it's a test file, its main function is to verify the correctness of the `BalsaFrame` component.

**Self-Correction/Refinement:** Initially, I might focus too much on the individual test names. However, it's more important to categorize the *types* of scenarios being tested (e.g., chunked encoding, content length, first-line parsing, error handling). This provides a more holistic understanding. Also, initially, I might not explicitly connect the C++ code to JavaScript. It's important to highlight that HTTP is the common ground and how this C++ component supports the communication that JavaScript relies on.
```cpp
"""
);

  auto error_code = BalsaFrameEnums::INVALID_CHUNK_LENGTH;
  {
    InSequence s1;
    EXPECT_CALL(visitor_mock_, OnRequestFirstLineInput("GET / HTTP/1.1", "GET",
                                                       "/", "HTTP/1.1"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, OnRawBodyInput("555\xAB"));
    EXPECT_CALL(visitor_mock_, HandleError(error_code));
  }

  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));
  EXPECT_EQ(strlen("555\xAB"),
            balsa_frame_.ProcessInput(chunks.data(), chunks.size()));
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_CHUNK_LENGTH, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, VisitorCalledAsExpectedWhenChunkingOverflowOccurs) {
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

  const char* chunk_read_before_overflow = "FFFFFFFFFFFFFFFFF";

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("Connection", "close");
  fake_headers.AddKeyValue("transfer-encoding", "chunked");

  auto error_code = BalsaFrameEnums::CHUNK_LENGTH_OVERFLOW;
  {
    InSequence s1;
    EXPECT_CALL(visitor_mock_, OnRequestFirstLineInput("GET / HTTP/1.1", "GET",
                                                       "/", "HTTP/1.1"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, OnRawBodyInput(chunk_read_before_overflow));
    EXPECT_CALL(visitor_mock_, HandleError(error_code));
  }

  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));
  EXPECT_EQ(strlen(chunk_read_before_overflow),
            balsa_frame_.ProcessInput(chunks.data(), chunks.size()));
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::CHUNK_LENGTH_OVERFLOW, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest,
       VisitorCalledAsExpectedWhenInvalidChunkLengthOccurs) {
  std::string headers =
      "GET / HTTP/1.1\r\n"
      "Connection: close\r\n"
      "transfer-encoding: chunked\r\n"
      "\r\n";

  std::string chunks =
      "12z123 \r\n"  // invalid chunk length
      "0\r\n";
  std::string trailer =
      "crass: monkeys\r\n"
      "funky: monkeys\r\n"
      "\n";

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("Connection", "close");
  fake_headers.AddKeyValue("transfer-encoding", "chunked");

  auto error_code = BalsaFrameEnums::INVALID_CHUNK_LENGTH;
  {
    InSequence s1;
    EXPECT_CALL(visitor_mock_, OnRequestFirstLineInput("GET / HTTP/1.1", "GET",
                                                       "/", "HTTP/1.1"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, OnRawBodyInput("12z"));
    EXPECT_CALL(visitor_mock_, HandleError(error_code));
  }

  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));
  EXPECT_EQ(3u, balsa_frame_.ProcessInput(chunks.data(), chunks.size()));
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_CHUNK_LENGTH, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, VisitorInvokedProperlyForRequestWithContentLength) {
  std::string message_headers =
      "PUT \t /search?q=fo \t HTTP/1.1 \t \r\n"
      "content-length:  \t\t   20 \t\t  \r\n"
      "\r\n";
  std::string message_body = "12345678901234567890";
  std::string message =
      std::string(message_headers) + std::string(message_body);

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("content-length", "20");

  {
    InSequence s1;
    EXPECT_CALL(visitor_mock_,
                OnRequestFirstLineInput("PUT \t /search?q=fo \t HTTP/1.1",
                                        "PUT", "/search?q=fo", "HTTP/1.1"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, OnRawBodyInput(message_body));
    EXPECT_CALL(visitor_mock_, OnBodyChunkInput(message_body));
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(message_headers));

  ASSERT_EQ(message_headers.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  ASSERT_EQ(message_body.size(),
            balsa_frame_.ProcessInput(message.data() + message_headers.size(),
                                      message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest,
       VisitorInvokedProperlyForRequestWithOneCharContentLength) {
  std::string message_headers =
      "PUT \t /search?q=fo \t HTTP/1.1 \t \r\n"
      "content-length:  \t\t   2 \t\t  \r\n"
      "\r\n";
  std::string message_body = "12";
  std::string message =
      std::string(message_headers) + std::string(message_body);

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("content-length", "2");

  {
    InSequence s1;
    EXPECT_CALL(visitor_mock_,
                OnRequestFirstLineInput("PUT \t /search?q=fo \t HTTP/1.1",
                                        "PUT", "/search?q=fo", "HTTP/1.1"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, OnRawBodyInput(message_body));
    EXPECT_CALL(visitor_mock_, OnBodyChunkInput(message_body));
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(message_headers));

  ASSERT_EQ(message_headers.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  ASSERT_EQ(message_body.size(),
            balsa_frame_.ProcessInput(message.data() + message_headers.size(),
                                      message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, InvalidChunkExtensionWithCarriageReturn) {
  balsa_frame_.set_http_validation_policy(
      HttpValidationPolicy{.disallow_lone_cr_in_chunk_extension = true});
  std::string message_headers =
      "POST /potato?salad=withmayo HTTP/1.1\r\n"
      "transfer-encoding: chunked\r\n"
      "\r\n";
  std::string message_body =
      "9; bad\rextension\r\n"
      "012345678\r\n"
      "0\r\n"
      "\r\n";
  std::string message =
      std::string(message_headers) + std::string(message_body);

  EXPECT_CALL(visitor_mock_,
              HandleError(BalsaFrameEnums::INVALID_CHUNK_EXTENSION));
  ASSERT_EQ(message_headers.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  balsa_frame_.ProcessInput(message.data() + message_headers.size(),
                            message.size());
}

// Regression test for b/347710034: `disallow_lone_cr_in_chunk_extension` should
// not trigger false positive when "\r\n" terminating chunk length is separated
// into multiple calls to ProcessInput().
TEST_F(HTTPBalsaFrameTest, ChunkExtensionCarriageReturnLineFeedAtBoundary) {
  balsa_frame_.set_http_validation_policy(
      HttpValidationPolicy{.disallow_lone_cr_in_chunk_extension = true});
  EXPECT_CALL(visitor_mock_, ProcessHeaders(_));
  EXPECT_CALL(visitor_mock_, HeaderDone());
  constexpr absl::string_view headers(
      "POST / HTTP/1.1\r\n"
      "transfer-encoding: chunked\r\n\r\n");
  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));

  constexpr absl::string_view body1("3\r");
  ASSERT_EQ(body1.size(),
            balsa_frame_.ProcessInput(body1.data(), body1.size()));
  ASSERT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());

  constexpr absl::string_view body2(
      "\nfoo\r\n"
      "0\r\n\r\n");

  EXPECT_CALL(visitor_mock_, OnBodyChunkInput("foo"));
  EXPECT_CALL(visitor_mock_, MessageDone());
  ASSERT_EQ(body2.size(),
            balsa_frame_.ProcessInput(body2.data(), body2.size()));

  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
}

// A CR character followed by a non-LF character is detected even if separated
// into multiple calls to ProcessInput().
TEST_F(HTTPBalsaFrameTest, ChunkExtensionLoneCarriageReturnAtBoundary) {
  balsa_frame_.set_http_validation_policy(
      HttpValidationPolicy{.disallow_lone_cr_in_chunk_extension = true});
  EXPECT_CALL(visitor_mock_, ProcessHeaders(_));
  EXPECT_CALL(visitor_mock_, HeaderDone());
  constexpr absl::string_view headers(
      "POST / HTTP/1.1\r\n"
      "transfer-encoding: chunked\r\n\r\n");
  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));

  constexpr absl::string_view body1("3\r");
  ASSERT_EQ(body1.size(),
            balsa_frame_.ProcessInput(body1.data(), body1.size()));
  ASSERT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());

  constexpr absl::string_view body2("a");
  EXPECT_EQ(0, balsa_frame_.ProcessInput(body2.data(), body2.size()));
  EXPECT_EQ(BalsaFrameEnums::INVALID_CHUNK_EXTENSION, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest,
       VisitorInvokedProperlyForRequestWithTransferEncoding) {
  std::string message_headers =
      "DELETE /search?q=fo \t HTTP/1.1 \t \r\n"
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

  {
    InSequence s1;
    EXPECT_CALL(visitor_mock_,
                OnRequestFirstLineInput("DELETE /search?q=fo \t HTTP/1.1",
                                        "DELETE", "/search?q=fo", "HTTP/1.1"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, OnChunkLength(10));
    EXPECT_CALL(visitor_mock_,
                OnChunkExtensionInput("            chunkjed extension  "));
    EXPECT_CALL(visitor_mock_, OnChunkLength(63));
    EXPECT_CALL(visitor_mock_, OnChunkExtensionInput(""));
    EXPECT_CALL(visitor_mock_, OnChunkLength(0));
    EXPECT_CALL(visitor_mock_, OnChunkExtensionInput(" last one"));
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
       VisitorInvokedProperlyForRequestWithTransferEncodingAndTrailers) {
  std::string message_headers =
      "DELETE /search?q=fo \t HTTP/1.1 \t \r\n"
      "trAnsfer-eNcoding:  chunked\r\n"
      "another_random_header:  \r\n"
      "  \t \n"
      "  \t includes a continuation\n"
      "\r\n";
  std::string message_body =
      "A            chunkjed extension  \r\n"
      "01234567890            more crud including numbers 123123\r\n"
      "3f\n"
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
      "1  \r\n"
      "x   \r\n"
      "0 last one\r\n";
  std::string trailer_data =
      "a_trailer_key: and a trailer value\r\n"
      "\r\n";
  std::string message_body_data =
      "0123456789"
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

  std::string message = (std::string(message_headers) +
                         std::string(message_body) + std::string(trailer_data));

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("trAnsfer-eNcoding", "chunked");
  fake_headers.AddKeyValue("another_random_header", "includes a continuation");

  FakeHeaders fake_trailers;
  fake_trailers.AddKeyValue("a_trailer_key", "and a trailer value");

  {
    InSequence s1;

    EXPECT_CALL(visitor_mock_,
                OnRequestFirstLineInput("DELETE /search?q=fo \t HTTP/1.1",
                                        "DELETE", "/search?q=fo", "HTTP/1.1"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, OnChunkLength(10));
    EXPECT_CALL(visitor_mock_, OnChunkLength(63));
    EXPECT_CALL(visitor_mock_, OnChunkLength(1));
    EXPECT_CALL(visitor_mock_, OnChunkLength(0));
    EXPECT_CALL(visitor_mock_, OnTrailers(fake_trailers));
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
  EXPECT_CALL(visitor_mock_, OnChunkExtensionInput(_)).Times(AnyNumber());

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

TEST_F(HTTPBalsaFrameTest,
       VisitorInvokedProperlyWithRequestFirstLineWarningWithOnlyMethod) {
  std::string message = "GET\n";

  FakeHeaders fake_headers;

  auto error_code = BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_REQUEST_METHOD;
  {
    InSequence s;
    EXPECT_CALL(visitor_mock_, HandleWarning(error_code));
    EXPECT_CALL(visitor_mock_, OnRequestFirstLineInput("GET", "GET", "", ""));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(message));

  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_REQUEST_METHOD,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest,
       VisitorInvokedProperlyWithRequestFirstLineWarningWithOnlyMethodAndWS) {
  std::string message = "GET  \n";

  FakeHeaders fake_headers;

  auto error_code = BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_REQUEST_METHOD;
  {
    InSequence s;
    EXPECT_CALL(visitor_mock_, HandleWarning(error_code));
    // The flag setting here intentionally alters the framer's behavior with
    // trailing whitespace.
    EXPECT_CALL(visitor_mock_, OnRequestFirstLineInput("GET  ", "GET", "", ""));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(message));

  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_REQUEST_METHOD,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, AbsoluteFormTargetUri) {
  std::string message =
      "GET http://www.google.com/index.html HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "\r\n";
  balsa_frame_.set_is_request(true);

  EXPECT_CALL(visitor_mock_, OnHeaderInput(message));

  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
  EXPECT_EQ("http://www.google.com/index.html",
            balsa_frame_.headers()->request_uri());
  EXPECT_EQ("example.com", balsa_frame_.headers()->GetHeader("host"));
}

TEST_F(HTTPBalsaFrameTest, InvalidAbsoluteFormTargetUri) {
  std::string message =
      "GET -pwn/index.html HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "\r\n";
  balsa_frame_.set_is_request(true);

  EXPECT_CALL(visitor_mock_, OnHeaderInput(message));

  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.is_valid_target_uri());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
  EXPECT_EQ("-pwn/index.html", balsa_frame_.headers()->request_uri());
  EXPECT_EQ("example.com", balsa_frame_.headers()->GetHeader("host"));
}

TEST_F(HTTPBalsaFrameTest, RejectInvalidAbsoluteFormTargetUri) {
  HttpValidationPolicy http_validation_policy{.disallow_invalid_target_uris =
                                                  true};
  balsa_frame_.set_http_validation_policy(http_validation_policy);
  std::string message =
      "GET -pwn/index.html HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "\r\n";
  balsa_frame_.set_is_request(true);

  const size_t end_of_first_line = message.find_first_of("\r\n") + 1;
  EXPECT_EQ(end_of_first_line,
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_TARGET_URI, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, RejectStarForNonOptions) {
  HttpValidationPolicy http_validation_policy{.disallow_invalid_target_uris =
                                                  true};
  balsa_frame_.set_http_validation_policy(http_validation_policy);
  std::string message =
      "GET * HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "\r\n";
  balsa_frame_.set_is_request(true);

  const size_t end_of_first_line = message.find_first_of("\r\n") + 1;
  EXPECT_EQ(end_of_first_line,
            balsa_frame_.ProcessInput(message.data(), message.size()));

  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_TARGET_URI, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, AllowStarForOptions) {
  HttpValidationPolicy http_validation_policy{.disallow_invalid_target_uris =
                                                  true};
  balsa_frame_.set_http_validation_policy(http_validation_policy);
  std::string message =
      "OPTIONS * HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "\r\n";
  balsa_frame_.set_is_request(true);

  EXPECT_CALL(visitor_mock_, OnHeaderInput(message));

  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
}

TEST_F(HTTPBalsaFrameTest, RejectConnectWithNoPort) {
  HttpValidationPolicy http_validation_policy{.disallow_invalid_target_uris =
                                                  true};
  balsa_frame_.set_http_validation_policy(http_validation_policy);
  std::string message =
      "CONNECT example.com HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "\r\n";
  balsa_frame_.set_is_request(true);

  const size_t end_of_first_line = message.find_first_of("\r\n") + 1;
  EXPECT_EQ(end_of_first_line,
            balsa_frame_.ProcessInput(message.data(), message.size()));

  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_TARGET_URI, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, RejectConnectWithInvalidPort) {
  HttpValidationPolicy http_validation_policy{.disallow_invalid_target_uris =
                                                  true};
  balsa_frame_.set_http_validation_policy(http_validation_policy);
  std::string message =
      "CONNECT example.com:443z HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "\r\n";
  balsa_frame_.set_is_request(true);

  const size_t end_of_first_line = message.find_first_of("\r\n") + 1;
  EXPECT_EQ(end_of_first_line,
            balsa_frame_.ProcessInput(message.data(), message.size()));

  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_TARGET_URI, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, AllowConnectWithValidPort) {
  HttpValidationPolicy http_validation_policy{.disallow_invalid_target_uris =
                                                  true};
  balsa_frame_.set_http_validation_policy(http_validation_policy);
  std::string message =
      "CONNECT example.com:443 HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "\r\n";
  balsa_frame_.set_is_request(true);

  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
}

TEST_F(HTTPBalsaFrameTest,
       VisitorInvokedProperlyWithRequestFirstLineWarningWithMethodAndURI) {
  std::string message = "GET /uri\n";

  FakeHeaders fake_headers;

  auto error
### 提示词
```
这是目录为net/third_party/quiche/src/quiche/balsa/balsa_frame_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
);

  auto error_code = BalsaFrameEnums::INVALID_CHUNK_LENGTH;
  {
    InSequence s1;
    EXPECT_CALL(visitor_mock_, OnRequestFirstLineInput("GET / HTTP/1.1", "GET",
                                                       "/", "HTTP/1.1"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, OnRawBodyInput("555\xAB"));
    EXPECT_CALL(visitor_mock_, HandleError(error_code));
  }

  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));
  EXPECT_EQ(strlen("555\xAB"),
            balsa_frame_.ProcessInput(chunks.data(), chunks.size()));
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_CHUNK_LENGTH, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, VisitorCalledAsExpectedWhenChunkingOverflowOccurs) {
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

  const char* chunk_read_before_overflow = "FFFFFFFFFFFFFFFFF";

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("Connection", "close");
  fake_headers.AddKeyValue("transfer-encoding", "chunked");

  auto error_code = BalsaFrameEnums::CHUNK_LENGTH_OVERFLOW;
  {
    InSequence s1;
    EXPECT_CALL(visitor_mock_, OnRequestFirstLineInput("GET / HTTP/1.1", "GET",
                                                       "/", "HTTP/1.1"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, OnRawBodyInput(chunk_read_before_overflow));
    EXPECT_CALL(visitor_mock_, HandleError(error_code));
  }

  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));
  EXPECT_EQ(strlen(chunk_read_before_overflow),
            balsa_frame_.ProcessInput(chunks.data(), chunks.size()));
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::CHUNK_LENGTH_OVERFLOW, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest,
       VisitorCalledAsExpectedWhenInvalidChunkLengthOccurs) {
  std::string headers =
      "GET / HTTP/1.1\r\n"
      "Connection: close\r\n"
      "transfer-encoding: chunked\r\n"
      "\r\n";

  std::string chunks =
      "12z123 \r\n"  // invalid chunk length
      "0\r\n";
  std::string trailer =
      "crass: monkeys\r\n"
      "funky: monkeys\r\n"
      "\n";

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("Connection", "close");
  fake_headers.AddKeyValue("transfer-encoding", "chunked");

  auto error_code = BalsaFrameEnums::INVALID_CHUNK_LENGTH;
  {
    InSequence s1;
    EXPECT_CALL(visitor_mock_, OnRequestFirstLineInput("GET / HTTP/1.1", "GET",
                                                       "/", "HTTP/1.1"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, OnRawBodyInput("12z"));
    EXPECT_CALL(visitor_mock_, HandleError(error_code));
  }

  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));
  EXPECT_EQ(3u, balsa_frame_.ProcessInput(chunks.data(), chunks.size()));
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_CHUNK_LENGTH, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, VisitorInvokedProperlyForRequestWithContentLength) {
  std::string message_headers =
      "PUT \t /search?q=fo \t HTTP/1.1 \t \r\n"
      "content-length:  \t\t   20 \t\t  \r\n"
      "\r\n";
  std::string message_body = "12345678901234567890";
  std::string message =
      std::string(message_headers) + std::string(message_body);

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("content-length", "20");

  {
    InSequence s1;
    EXPECT_CALL(visitor_mock_,
                OnRequestFirstLineInput("PUT \t /search?q=fo \t HTTP/1.1",
                                        "PUT", "/search?q=fo", "HTTP/1.1"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, OnRawBodyInput(message_body));
    EXPECT_CALL(visitor_mock_, OnBodyChunkInput(message_body));
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(message_headers));

  ASSERT_EQ(message_headers.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  ASSERT_EQ(message_body.size(),
            balsa_frame_.ProcessInput(message.data() + message_headers.size(),
                                      message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest,
       VisitorInvokedProperlyForRequestWithOneCharContentLength) {
  std::string message_headers =
      "PUT \t /search?q=fo \t HTTP/1.1 \t \r\n"
      "content-length:  \t\t   2 \t\t  \r\n"
      "\r\n";
  std::string message_body = "12";
  std::string message =
      std::string(message_headers) + std::string(message_body);

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("content-length", "2");

  {
    InSequence s1;
    EXPECT_CALL(visitor_mock_,
                OnRequestFirstLineInput("PUT \t /search?q=fo \t HTTP/1.1",
                                        "PUT", "/search?q=fo", "HTTP/1.1"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, OnRawBodyInput(message_body));
    EXPECT_CALL(visitor_mock_, OnBodyChunkInput(message_body));
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(message_headers));

  ASSERT_EQ(message_headers.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  ASSERT_EQ(message_body.size(),
            balsa_frame_.ProcessInput(message.data() + message_headers.size(),
                                      message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, InvalidChunkExtensionWithCarriageReturn) {
  balsa_frame_.set_http_validation_policy(
      HttpValidationPolicy{.disallow_lone_cr_in_chunk_extension = true});
  std::string message_headers =
      "POST /potato?salad=withmayo HTTP/1.1\r\n"
      "transfer-encoding: chunked\r\n"
      "\r\n";
  std::string message_body =
      "9; bad\rextension\r\n"
      "012345678\r\n"
      "0\r\n"
      "\r\n";
  std::string message =
      std::string(message_headers) + std::string(message_body);

  EXPECT_CALL(visitor_mock_,
              HandleError(BalsaFrameEnums::INVALID_CHUNK_EXTENSION));
  ASSERT_EQ(message_headers.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  balsa_frame_.ProcessInput(message.data() + message_headers.size(),
                            message.size());
}

// Regression test for b/347710034: `disallow_lone_cr_in_chunk_extension` should
// not trigger false positive when "\r\n" terminating chunk length is separated
// into multiple calls to ProcessInput().
TEST_F(HTTPBalsaFrameTest, ChunkExtensionCarriageReturnLineFeedAtBoundary) {
  balsa_frame_.set_http_validation_policy(
      HttpValidationPolicy{.disallow_lone_cr_in_chunk_extension = true});
  EXPECT_CALL(visitor_mock_, ProcessHeaders(_));
  EXPECT_CALL(visitor_mock_, HeaderDone());
  constexpr absl::string_view headers(
      "POST / HTTP/1.1\r\n"
      "transfer-encoding: chunked\r\n\r\n");
  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));

  constexpr absl::string_view body1("3\r");
  ASSERT_EQ(body1.size(),
            balsa_frame_.ProcessInput(body1.data(), body1.size()));
  ASSERT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());

  constexpr absl::string_view body2(
      "\nfoo\r\n"
      "0\r\n\r\n");

  EXPECT_CALL(visitor_mock_, OnBodyChunkInput("foo"));
  EXPECT_CALL(visitor_mock_, MessageDone());
  ASSERT_EQ(body2.size(),
            balsa_frame_.ProcessInput(body2.data(), body2.size()));

  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
}

// A CR character followed by a non-LF character is detected even if separated
// into multiple calls to ProcessInput().
TEST_F(HTTPBalsaFrameTest, ChunkExtensionLoneCarriageReturnAtBoundary) {
  balsa_frame_.set_http_validation_policy(
      HttpValidationPolicy{.disallow_lone_cr_in_chunk_extension = true});
  EXPECT_CALL(visitor_mock_, ProcessHeaders(_));
  EXPECT_CALL(visitor_mock_, HeaderDone());
  constexpr absl::string_view headers(
      "POST / HTTP/1.1\r\n"
      "transfer-encoding: chunked\r\n\r\n");
  ASSERT_EQ(headers.size(),
            balsa_frame_.ProcessInput(headers.data(), headers.size()));

  constexpr absl::string_view body1("3\r");
  ASSERT_EQ(body1.size(),
            balsa_frame_.ProcessInput(body1.data(), body1.size()));
  ASSERT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());

  constexpr absl::string_view body2("a");
  EXPECT_EQ(0, balsa_frame_.ProcessInput(body2.data(), body2.size()));
  EXPECT_EQ(BalsaFrameEnums::INVALID_CHUNK_EXTENSION, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest,
       VisitorInvokedProperlyForRequestWithTransferEncoding) {
  std::string message_headers =
      "DELETE /search?q=fo \t HTTP/1.1 \t \r\n"
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

  {
    InSequence s1;
    EXPECT_CALL(visitor_mock_,
                OnRequestFirstLineInput("DELETE /search?q=fo \t HTTP/1.1",
                                        "DELETE", "/search?q=fo", "HTTP/1.1"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, OnChunkLength(10));
    EXPECT_CALL(visitor_mock_,
                OnChunkExtensionInput("            chunkjed extension  "));
    EXPECT_CALL(visitor_mock_, OnChunkLength(63));
    EXPECT_CALL(visitor_mock_, OnChunkExtensionInput(""));
    EXPECT_CALL(visitor_mock_, OnChunkLength(0));
    EXPECT_CALL(visitor_mock_, OnChunkExtensionInput(" last one"));
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
       VisitorInvokedProperlyForRequestWithTransferEncodingAndTrailers) {
  std::string message_headers =
      "DELETE /search?q=fo \t HTTP/1.1 \t \r\n"
      "trAnsfer-eNcoding:  chunked\r\n"
      "another_random_header:  \r\n"
      "  \t \n"
      "  \t includes a continuation\n"
      "\r\n";
  std::string message_body =
      "A            chunkjed extension  \r\n"
      "01234567890            more crud including numbers 123123\r\n"
      "3f\n"
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
      "1  \r\n"
      "x   \r\n"
      "0 last one\r\n";
  std::string trailer_data =
      "a_trailer_key: and a trailer value\r\n"
      "\r\n";
  std::string message_body_data =
      "0123456789"
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

  std::string message = (std::string(message_headers) +
                         std::string(message_body) + std::string(trailer_data));

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("trAnsfer-eNcoding", "chunked");
  fake_headers.AddKeyValue("another_random_header", "includes a continuation");

  FakeHeaders fake_trailers;
  fake_trailers.AddKeyValue("a_trailer_key", "and a trailer value");

  {
    InSequence s1;

    EXPECT_CALL(visitor_mock_,
                OnRequestFirstLineInput("DELETE /search?q=fo \t HTTP/1.1",
                                        "DELETE", "/search?q=fo", "HTTP/1.1"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, OnChunkLength(10));
    EXPECT_CALL(visitor_mock_, OnChunkLength(63));
    EXPECT_CALL(visitor_mock_, OnChunkLength(1));
    EXPECT_CALL(visitor_mock_, OnChunkLength(0));
    EXPECT_CALL(visitor_mock_, OnTrailers(fake_trailers));
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
  EXPECT_CALL(visitor_mock_, OnChunkExtensionInput(_)).Times(AnyNumber());

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

TEST_F(HTTPBalsaFrameTest,
       VisitorInvokedProperlyWithRequestFirstLineWarningWithOnlyMethod) {
  std::string message = "GET\n";

  FakeHeaders fake_headers;

  auto error_code = BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_REQUEST_METHOD;
  {
    InSequence s;
    EXPECT_CALL(visitor_mock_, HandleWarning(error_code));
    EXPECT_CALL(visitor_mock_, OnRequestFirstLineInput("GET", "GET", "", ""));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(message));

  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_REQUEST_METHOD,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest,
       VisitorInvokedProperlyWithRequestFirstLineWarningWithOnlyMethodAndWS) {
  std::string message = "GET  \n";

  FakeHeaders fake_headers;

  auto error_code = BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_REQUEST_METHOD;
  {
    InSequence s;
    EXPECT_CALL(visitor_mock_, HandleWarning(error_code));
    // The flag setting here intentionally alters the framer's behavior with
    // trailing whitespace.
    EXPECT_CALL(visitor_mock_, OnRequestFirstLineInput("GET  ", "GET", "", ""));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(message));

  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_REQUEST_METHOD,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, AbsoluteFormTargetUri) {
  std::string message =
      "GET http://www.google.com/index.html HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "\r\n";
  balsa_frame_.set_is_request(true);

  EXPECT_CALL(visitor_mock_, OnHeaderInput(message));

  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
  EXPECT_EQ("http://www.google.com/index.html",
            balsa_frame_.headers()->request_uri());
  EXPECT_EQ("example.com", balsa_frame_.headers()->GetHeader("host"));
}

TEST_F(HTTPBalsaFrameTest, InvalidAbsoluteFormTargetUri) {
  std::string message =
      "GET -pwn/index.html HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "\r\n";
  balsa_frame_.set_is_request(true);

  EXPECT_CALL(visitor_mock_, OnHeaderInput(message));

  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.is_valid_target_uri());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
  EXPECT_EQ("-pwn/index.html", balsa_frame_.headers()->request_uri());
  EXPECT_EQ("example.com", balsa_frame_.headers()->GetHeader("host"));
}

TEST_F(HTTPBalsaFrameTest, RejectInvalidAbsoluteFormTargetUri) {
  HttpValidationPolicy http_validation_policy{.disallow_invalid_target_uris =
                                                  true};
  balsa_frame_.set_http_validation_policy(http_validation_policy);
  std::string message =
      "GET -pwn/index.html HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "\r\n";
  balsa_frame_.set_is_request(true);

  const size_t end_of_first_line = message.find_first_of("\r\n") + 1;
  EXPECT_EQ(end_of_first_line,
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_TARGET_URI, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, RejectStarForNonOptions) {
  HttpValidationPolicy http_validation_policy{.disallow_invalid_target_uris =
                                                  true};
  balsa_frame_.set_http_validation_policy(http_validation_policy);
  std::string message =
      "GET * HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "\r\n";
  balsa_frame_.set_is_request(true);

  const size_t end_of_first_line = message.find_first_of("\r\n") + 1;
  EXPECT_EQ(end_of_first_line,
            balsa_frame_.ProcessInput(message.data(), message.size()));

  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_TARGET_URI, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, AllowStarForOptions) {
  HttpValidationPolicy http_validation_policy{.disallow_invalid_target_uris =
                                                  true};
  balsa_frame_.set_http_validation_policy(http_validation_policy);
  std::string message =
      "OPTIONS * HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "\r\n";
  balsa_frame_.set_is_request(true);

  EXPECT_CALL(visitor_mock_, OnHeaderInput(message));

  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
}

TEST_F(HTTPBalsaFrameTest, RejectConnectWithNoPort) {
  HttpValidationPolicy http_validation_policy{.disallow_invalid_target_uris =
                                                  true};
  balsa_frame_.set_http_validation_policy(http_validation_policy);
  std::string message =
      "CONNECT example.com HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "\r\n";
  balsa_frame_.set_is_request(true);

  const size_t end_of_first_line = message.find_first_of("\r\n") + 1;
  EXPECT_EQ(end_of_first_line,
            balsa_frame_.ProcessInput(message.data(), message.size()));

  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_TARGET_URI, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, RejectConnectWithInvalidPort) {
  HttpValidationPolicy http_validation_policy{.disallow_invalid_target_uris =
                                                  true};
  balsa_frame_.set_http_validation_policy(http_validation_policy);
  std::string message =
      "CONNECT example.com:443z HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "\r\n";
  balsa_frame_.set_is_request(true);

  const size_t end_of_first_line = message.find_first_of("\r\n") + 1;
  EXPECT_EQ(end_of_first_line,
            balsa_frame_.ProcessInput(message.data(), message.size()));

  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::INVALID_TARGET_URI, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, AllowConnectWithValidPort) {
  HttpValidationPolicy http_validation_policy{.disallow_invalid_target_uris =
                                                  true};
  balsa_frame_.set_http_validation_policy(http_validation_policy);
  std::string message =
      "CONNECT example.com:443 HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "\r\n";
  balsa_frame_.set_is_request(true);

  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
}

TEST_F(HTTPBalsaFrameTest,
       VisitorInvokedProperlyWithRequestFirstLineWarningWithMethodAndURI) {
  std::string message = "GET /uri\n";

  FakeHeaders fake_headers;

  auto error_code =
      BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_REQUEST_REQUEST_URI;
  {
    InSequence s;
    EXPECT_CALL(visitor_mock_, HandleWarning(error_code));
    EXPECT_CALL(visitor_mock_,
                OnRequestFirstLineInput("GET /uri", "GET", "/uri", ""));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(message));

  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_REQUEST_REQUEST_URI,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, VisitorInvokedProperlyWithResponseFirstLineError) {
  std::string message = "HTTP/1.1\n\n";

  FakeHeaders fake_headers;

  balsa_frame_.set_is_request(false);
  auto error_code = BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_RESPONSE_VERSION;
  {
    InSequence s;
    EXPECT_CALL(visitor_mock_, HandleError(error_code));
    // The function returns before any of the following is called.
    EXPECT_CALL(visitor_mock_, OnRequestFirstLineInput).Times(0);
    EXPECT_CALL(visitor_mock_, ProcessHeaders(_)).Times(0);
    EXPECT_CALL(visitor_mock_, HeaderDone()).Times(0);
    EXPECT_CALL(visitor_mock_, MessageDone()).Times(0);
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(_)).Times(0);

  EXPECT_GE(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::FAILED_TO_FIND_WS_AFTER_RESPONSE_VERSION,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, FlagsErrorWithContentLengthOverflow) {
  std::string message =
      "HTTP/1.0 200 OK\r\n"
      "content-length: 9999999999999999999999999999999999999999\n"
      "\n";

  balsa_frame_.set_is_request(false);
  auto error_code = BalsaFrameEnums::UNPARSABLE_CONTENT_LENGTH;
  EXPECT_CALL(visitor_mock_, HandleError(error_code));

  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::UNPARSABLE_CONTENT_LENGTH,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, FlagsErrorWithInvalidResponseCode) {
  std::string message =
      "HTTP/1.0 x OK\r\n"
      "\n";

  balsa_frame_.set_is_request(false);
  auto error_code = BalsaFrameEnums::FAILED_CONVERTING_STATUS_CODE_TO_INT;
  EXPECT_CALL(visitor_mock_, HandleError(error_code));

  EXPECT_GE(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::FAILED_CONVERTING_STATUS_CODE_TO_INT,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, FlagsErrorWithOverflowingResponseCode) {
  std::string message =
      "HTTP/1.0 999999999999999999999999999999999999999 OK\r\n"
      "\n";

  balsa_frame_.set_is_request(false);
  auto error_code = BalsaFrameEnums::FAILED_CONVERTING_STATUS_CODE_TO_INT;
  EXPECT_CALL(visitor_mock_, HandleError(error_code));

  EXPECT_GE(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::FAILED_CONVERTING_STATUS_CODE_TO_INT,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, FlagsErrorWithInvalidContentLength) {
  std::string message =
      "HTTP/1.0 200 OK\r\n"
      "content-length: xxx\n"
      "\n";

  balsa_frame_.set_is_request(false);
  auto error_code = BalsaFrameEnums::UNPARSABLE_CONTENT_LENGTH;
  EXPECT_CALL(visitor_mock_, HandleError(error_code));

  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::UNPARSABLE_CONTENT_LENGTH,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, FlagsErrorWithNegativeContentLengthValue) {
  std::string message =
      "HTTP/1.0 200 OK\r\n"
      "content-length: -20\n"
      "\n";

  balsa_frame_.set_is_request(false);
  auto error_code = BalsaFrameEnums::UNPARSABLE_CONTENT_LENGTH;
  EXPECT_CALL(visitor_mock_, HandleError(error_code));

  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::UNPARSABLE_CONTENT_LENGTH,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, FlagsErrorWithEmptyContentLengthValue) {
  std::string message =
      "HTTP/1.0 200 OK\r\n"
      "content-length: \n"
      "\n";

  balsa_frame_.set_is_request(false);
  auto error_code = BalsaFrameEnums::UNPARSABLE_CONTENT_LENGTH;
  EXPECT_CALL(visitor_mock_, HandleError(error_code));

  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_FALSE(balsa_frame_.MessageFullyRead());
  EXPECT_TRUE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::UNPARSABLE_CONTENT_LENGTH,
            balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, VisitorInvokedProperlyForTrivialResponse) {
  std::string message =
      "HTTP/1.0 200 OK\r\n"
      "content-length: 0\n"
      "\n";

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("content-length", "0");

  balsa_frame_.set_is_request(false);
  {
    InSequence s;
    EXPECT_CALL(visitor_mock_, OnResponseFirstLineInput(
                                   "HTTP/1.0 200 OK", "HTTP/1.0", "200", "OK"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(message));

  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest,
       VisitorInvokedProperlyForResponseWithSplitBlankLines) {
  std::string blanks =
      "\n"
      "\r\n"
      "\r\n";
  std::string header_input =
      "HTTP/1.0 200 OK\r\n"
      "content-length: 0\n"
      "\n";
  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("content-length", "0");

  balsa_frame_.set_is_request(false);
  {
    InSequence s;
    EXPECT_CALL(visitor_mock_, OnResponseFirstLineInput(
                                   "HTTP/1.0 200 OK", "HTTP/1.0", "200", "OK"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(header_input));

  EXPECT_EQ(blanks.size(),
            balsa_frame_.ProcessInput(blanks.data(), blanks.size()));
  EXPECT_EQ(header_input.size(), balsa_frame_.ProcessInput(
                                     header_input.data(), header_input.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, VisitorInvokedProperlyForResponseWithBlankLines) {
  std::string blanks =
      "\n"
      "\r\n"
      "\n"
      "\n"
      "\r\n"
      "\r\n";
  std::string header_input =
      "HTTP/1.0 200 OK\r\n"
      "content-length: 0\n"
      "\n";
  std::string message = blanks + header_input;

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("content-length", "0");

  balsa_frame_.set_is_request(false);
  {
    InSequence s;
    EXPECT_CALL(visitor_mock_, OnResponseFirstLineInput(
                                   "HTTP/1.0 200 OK", "HTTP/1.0", "200", "OK"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(header_input));

  EXPECT_EQ(message.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()));
  EXPECT_TRUE(balsa_frame_.MessageFullyRead());
  EXPECT_FALSE(balsa_frame_.Error());
  EXPECT_EQ(BalsaFrameEnums::BALSA_NO_ERROR, balsa_frame_.ErrorCode());
}

TEST_F(HTTPBalsaFrameTest, VisitorInvokedProperlyForResponseWithContentLength) {
  std::string message_headers =
      "HTTP/1.1  \t 200 Ok all is well\r\n"
      "content-length:  \t\t   20 \t\t  \r\n"
      "\r\n";
  std::string message_body = "12345678901234567890";
  std::string message =
      std::string(message_headers) + std::string(message_body);

  FakeHeaders fake_headers;
  fake_headers.AddKeyValue("content-length", "20");

  balsa_frame_.set_is_request(false);
  {
    InSequence s1;
    EXPECT_CALL(visitor_mock_,
                OnResponseFirstLineInput("HTTP/1.1  \t 200 Ok all is well",
                                         "HTTP/1.1", "200", "Ok all is well"));
    EXPECT_CALL(visitor_mock_, ProcessHeaders(fake_headers));
    EXPECT_CALL(visitor_mock_, HeaderDone());
    EXPECT_CALL(visitor_mock_, OnRawBodyInput(message_body));
    EXPECT_CALL(visitor_mock_, OnBodyChunkInput(message_body));
    EXPECT_CALL(visitor_mock_, MessageDone());
  }
  EXPECT_CALL(visitor_mock_, OnHeaderInput(message_headers));

  ASSERT_EQ(message_headers.size(),
            balsa_frame_.ProcessInput(message.data(), message.size()
```