Response:
Let's break down the thought process for analyzing this C++ unittest file for an HTTP server.

**1. Understanding the Goal:**

The core request is to understand the functionality of `net/server/http_server_unittest.cc`, especially in relation to JavaScript, user errors, debugging, and to summarize its functions.

**2. Initial Scan and High-Level Understanding:**

* **Filename:** `http_server_unittest.cc` strongly suggests this file contains unit tests for an HTTP server implementation.
* **Includes:**  A quick scan of the `#include` directives confirms this. We see headers related to networking (`net/base/*.h`, `net/socket/*.h`), HTTP (`net/http/*.h`), and testing (`testing/gtest/*.h`, `net/test/*.h`). The presence of `#include "net/server/http_server.h"` is crucial – it means this file tests the `HttpServer` class itself.
* **Namespaces:** The code uses the `net` namespace, which is common in Chromium for networking-related code.
* **Test Fixture:** The `HttpServerTest` class inheriting from `TestWithTaskEnvironment` and `HttpServer::Delegate` indicates the setup for testing asynchronous operations and the server's delegate interface.

**3. Deeper Dive into Key Components:**

* **`TestHttpClient`:** This class is clearly a helper for simulating HTTP client behavior. It handles connecting, sending requests, and reading responses. This is the primary way the tests interact with the `HttpServer`.
* **`ReceivedRequest` struct:**  This structure holds information about a received HTTP request, making it easy to assert the correctness of the server's parsing.
* **`HttpServerTest` Fixture Methods:**
    * `SetUp()`: Initializes the `HttpServer` instance.
    * `TearDown()`: Cleans up after each test.
    * `OnConnect()`, `OnHttpRequest()`, `OnWebSocketRequest()`, `OnWebSocketMessage()`, `OnClose()`: These are implementations of the `HttpServer::Delegate` interface. They're the hooks the test uses to observe the server's behavior.
    * `WaitForRequest()`, `HasRequest()`:  Methods for waiting for and checking if a request has been received.
    * `CreateConnection()`: Establishes a client connection to the server, ensuring both sides are connected.
    * `RunUntilConnectionIdClosed()`:  Waits until a specific connection is closed.
    * `HandleAcceptResult()`:  Used in specific scenarios where a pre-existing socket is passed to the server.
* **Test Cases (`TEST_F` macros):**  These are the individual test scenarios. Reading through the names gives a good idea of the tested functionalities: `Request`, `RequestWithHeaders`, `RequestWithBody`, `UpgradeIgnored`, WebSocket tests, `Send200`, `SendRaw`, etc.

**4. Analyzing Functionality and Relationships:**

* **Core Functionality:** The primary function is to test the `HttpServer` class. It verifies that the server correctly handles HTTP requests, including different methods, headers, bodies, and connection management. It also tests WebSocket functionality.
* **JavaScript Relationship:**  Directly, this C++ code has no direct JavaScript functionality within *this file*. However, the *purpose* of this HTTP server is to potentially serve web content to a browser, which would then execute JavaScript. So, the indirect relationship is that a working, well-tested HTTP server is essential for JavaScript-heavy web applications.
* **Logic and Assumptions:**
    * **Assumption:** The server is listening on `127.0.0.1` on an ephemeral port.
    * **Input/Output (Example):**
        * **Input:**  `client.Send("GET /data HTTP/1.1\r\nHeader: Value\r\n\r\n")`
        * **Output (in `OnHttpRequest`):** `request.info.method == "GET"`, `request.info.path == "/data"`, `request.info.headers["header"] == "Value"`.
* **User/Programming Errors:**
    * **Example:** Sending an incomplete HTTP request (`"GET /test HTTP/1.1\r\n\r)"`) leads to the server closing the connection. This tests the server's robustness in handling malformed input. A common programming error might be a client incorrectly formatting the HTTP request.
* **Debugging Clues:** The tests themselves act as debugging clues. If a test fails, it points to a specific area of the `HttpServer` that isn't working as expected. The `CreateConnection` and `RunUntilConnectionIdClosed` methods help set up and observe specific connection states, useful for debugging connection-related issues.

**5. Summarizing Functionality (for Part 1):**

Based on the analysis so far, the core functionalities of this first part of the file can be summarized as:

* **Setting up a testing environment** for the `HttpServer` class using Google Test.
* **Providing a `TestHttpClient` helper class** to simulate client interactions with the server.
* **Defining a test fixture `HttpServerTest`** that implements the `HttpServer::Delegate` interface to observe server events.
* **Testing basic HTTP request handling:** Verifying that the server correctly parses HTTP requests (method, path, headers, body).
* **Testing the server's handling of malformed requests** (e.g., broken termination).
* **Testing HTTP requests with various headers**, including duplicates and different whitespace variations.
* **Testing HTTP requests with a body**.
* **Initial testing of WebSocket upgrade requests.**

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus heavily on direct JavaScript interaction.
* **Correction:** Realized that this is a C++ unit test. The JavaScript connection is *indirect*. Focus shifted to how the HTTP server enables JavaScript functionality in a browser context.
* **Initial thought:**  Treat all `TEST_F` as equal in importance for the summary.
* **Correction:**  Recognized that the early tests (basic HTTP) lay the foundation, and the WebSocket tests are a significant feature being tested. Prioritized mentioning both.

This iterative process of scanning, deep-diving, analyzing relationships, and refining understanding allows for a comprehensive breakdown of the code's purpose and functionality.
This is the first part of a unit test file (`http_server_unittest.cc`) for the `HttpServer` class in Chromium's networking stack. Here's a breakdown of its functionality:

**Core Functionality:**

This file primarily focuses on testing the core functionality of the `HttpServer` class. It sets up various scenarios to ensure the server behaves as expected when receiving different types of HTTP requests and WebSocket connection attempts. The tests cover:

1. **Basic HTTP Request Handling:**
   - Receiving and parsing basic HTTP GET requests.
   - Handling requests with different headers, including variations in whitespace and duplicate headers.
   - Parsing requests with a body (Content-Length).
   - Handling incomplete or malformed HTTP requests (broken termination).

2. **WebSocket Handling (Initial Stages):**
   - Detecting and processing HTTP upgrade requests specifically for WebSockets.
   - Testing scenarios where trailing junk data is sent after a WebSocket upgrade request.

3. **Simulating Client Behavior:**
   - It introduces a `TestHttpClient` class to act as a client, simplifying the process of sending requests and receiving responses. This client handles TCP connection, sending data, and reading data.

4. **Utilizing a Test Framework:**
   - It uses the Google Test framework (`testing/gtest/include/gtest/gtest.h`) to define and run individual test cases.

5. **Asynchronous Testing:**
   - It uses `base::RunLoop` and `base::test::TestFuture` to handle asynchronous operations inherent in network communication. This allows the tests to wait for events like connection establishment and request reception.

6. **Delegate Pattern:**
   - It implements the `HttpServer::Delegate` interface (`HttpServerTest` class) to receive notifications from the `HttpServer` about incoming connections, HTTP requests, and WebSocket events. This allows the tests to observe and verify the server's internal state and actions.

**Relationship to JavaScript:**

While this C++ code doesn't directly execute JavaScript, it's crucial for the functionality of web pages that run JavaScript in browsers. Here's the connection:

* **Serving Web Content:**  An `HttpServer` is responsible for serving web content (HTML, CSS, JavaScript files) to a browser. The tests here ensure that the server correctly receives requests from the browser (which might be triggered by JavaScript code) and would eventually be responsible for sending back the requested resources.
* **WebSocket Communication:**  JavaScript in a web browser can establish WebSocket connections with a server. The tests in this file verify that the `HttpServer` correctly recognizes and handles the initial HTTP upgrade request that initiates a WebSocket connection. Although this part doesn't test the full WebSocket communication, it sets the stage for that.

**Examples of Logical Reasoning (Hypothetical Inputs and Outputs):**

* **Scenario:** Testing a basic GET request.
    * **Hypothetical Input (from `TestHttpClient`):** `"GET /index.html HTTP/1.1\r\n\r\n"`
    * **Expected Output (in `HttpServerTest::OnHttpRequest`):**
        - `info.method` would be `"GET"`.
        - `info.path` would be `"/index.html"`.
        - `info.headers` would be an empty map (no headers in this simple case).
        - `info.data` would be an empty string (no request body).
* **Scenario:** Testing a GET request with a custom header.
    * **Hypothetical Input (from `TestHttpClient`):** `"GET /data HTTP/1.1\r\nX-Custom-Header: MyValue\r\n\r\n"`
    * **Expected Output (in `HttpServerTest::OnHttpRequest`):**
        - `info.method` would be `"GET"`.
        - `info.path` would be `"/data"`.
        - `info.headers` would contain an entry: `{"x-custom-header": "MyValue"}`.
        - `info.data` would be an empty string.

**User or Programming Common Usage Errors (and how tests catch them):**

* **Incorrect HTTP Request Formatting:** A common error is sending a request that doesn't adhere to the HTTP specification (e.g., missing the final `\r\n`). The `RequestBrokenTermination` test specifically checks how the server handles such malformed requests (it should likely close the connection gracefully).
* **Incorrect Content-Length:** If a client specifies a `Content-Length` header that doesn't match the actual body size, the server's behavior needs to be predictable. While not explicitly shown in this *part* of the file, subsequent tests or server logic would likely handle this.
* **WebSocket Upgrade Issues:** If a client attempts a WebSocket upgrade with incorrect headers (e.g., missing `Sec-WebSocket-Key`), the server should reject the upgrade. The `RequestWebSocket` tests ensure the server correctly identifies valid WebSocket upgrade attempts.

**User Operations Leading Here (Debugging Perspective):**

Let's imagine a user is experiencing an issue with a web application where a specific HTTP request isn't being processed correctly by the server. Here's how a developer might end up looking at this unit test file:

1. **Bug Report:** A user reports that a certain action in the web application (e.g., clicking a button) doesn't work as expected.
2. **Network Inspection:** The developer uses browser developer tools (Network tab) to inspect the HTTP request being sent. They notice the request might have specific headers or a body.
3. **Server-Side Debugging:** The developer starts debugging the server-side code that handles these requests. They might set breakpoints in the `HttpServer::OnHttpRequest` method or related parts of the code.
4. **Identifying the `HttpServer` Class:**  The developer realizes the issue lies within the `HttpServer` class responsible for receiving and parsing the request.
5. **Looking at Unit Tests:** To understand how the `HttpServer` is *supposed* to work and to find examples of handling similar requests, the developer might look at the unit tests for the `HttpServer`, specifically `net/server/http_server_unittest.cc`.
6. **Finding Relevant Tests:** They would look for tests with names that suggest they cover scenarios similar to the problematic request (e.g., tests involving specific headers, request bodies, or WebSocket upgrades if that's relevant).
7. **Analyzing the Test:**  By examining the test code, they can understand:
    - How a well-formed request of that type should look.
    - What the expected behavior of the `HttpServer` is when receiving such a request.
    - Potential edge cases or error conditions that are being tested.
8. **Using Tests as a Basis for New Tests:** If there isn't an existing test covering the exact scenario of the bug, the developer might write a new unit test based on the existing ones to reproduce the bug and then fix the underlying code.

**Summary of Functionality (Part 1):**

This first part of `net/server/http_server_unittest.cc` focuses on **establishing the basic testing infrastructure and verifying the fundamental capabilities of the `HttpServer` in handling standard HTTP requests and the initial stages of WebSocket connection upgrades.** It uses a mock client to send requests and a delegate to observe the server's actions, ensuring the server correctly parses request methods, paths, headers, and bodies, and reacts appropriately to malformed requests and WebSocket upgrade attempts.

Prompt: 
```
这是目录为net/server/http_server_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/server/http_server.h"

#include <stdint.h>

#include <algorithm>
#include <memory>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "base/auto_reset.h"
#include "base/check_op.h"
#include "base/compiler_specific.h"
#include "base/containers/span.h"
#include "base/format_macros.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/notreached.h"
#include "base/numerics/safe_conversions.h"
#include "base/run_loop.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/test_future.h"
#include "base/time/time.h"
#include "net/base/address_list.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_util.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_with_source.h"
#include "net/server/http_server_request_info.h"
#include "net/socket/tcp_client_socket.h"
#include "net/socket/tcp_server_socket.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/websockets/websocket_frame.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsOk;

namespace net {

namespace {

const int kMaxExpectedResponseLength = 2048;

class TestHttpClient {
 public:
  TestHttpClient() = default;

  int ConnectAndWait(const IPEndPoint& address) {
    AddressList addresses(address);
    NetLogSource source;
    socket_ = std::make_unique<TCPClientSocket>(addresses, nullptr, nullptr,
                                                nullptr, source);

    TestCompletionCallback callback;
    int rv = socket_->Connect(callback.callback());
    return callback.GetResult(rv);
  }

  void Send(const std::string& data) {
    write_buffer_ = base::MakeRefCounted<DrainableIOBuffer>(
        base::MakeRefCounted<StringIOBuffer>(data), data.length());
    Write();
  }

  bool Read(std::string* message, int expected_bytes) {
    int total_bytes_received = 0;
    message->clear();
    while (total_bytes_received < expected_bytes) {
      TestCompletionCallback callback;
      ReadInternal(&callback);
      int bytes_received = callback.WaitForResult();
      if (bytes_received <= 0) {
        return false;
      }

      total_bytes_received += bytes_received;
      message->append(read_buffer_->data(), bytes_received);
    }
    return true;
  }

  bool ReadResponse(std::string* message) {
    if (!Read(message, 1)) {
      return false;
    }
    while (!IsCompleteResponse(*message)) {
      std::string chunk;
      if (!Read(&chunk, 1)) {
        return false;
      }
      message->append(chunk);
    }
    return true;
  }

  void ExpectUsedThenDisconnectedWithNoData() {
    // Check that the socket was opened...
    ASSERT_TRUE(socket_->WasEverUsed());

    // ...then closed when the server disconnected. Verify that the socket was
    // closed by checking that a Read() fails.
    std::string response;
    ASSERT_FALSE(Read(&response, 1u));
    ASSERT_TRUE(response.empty());
  }

  TCPClientSocket& socket() { return *socket_; }

 private:
  void Write() {
    int result = socket_->Write(
        write_buffer_.get(), write_buffer_->BytesRemaining(),
        base::BindOnce(&TestHttpClient::OnWrite, base::Unretained(this)),
        TRAFFIC_ANNOTATION_FOR_TESTS);
    if (result != ERR_IO_PENDING) {
      OnWrite(result);
    }
  }

  void OnWrite(int result) {
    ASSERT_GT(result, 0);
    write_buffer_->DidConsume(result);
    if (write_buffer_->BytesRemaining()) {
      Write();
    }
  }

  void ReadInternal(TestCompletionCallback* callback) {
    read_buffer_ =
        base::MakeRefCounted<IOBufferWithSize>(kMaxExpectedResponseLength);
    int result = socket_->Read(read_buffer_.get(), kMaxExpectedResponseLength,
                               callback->callback());
    if (result != ERR_IO_PENDING) {
      callback->callback().Run(result);
    }
  }

  bool IsCompleteResponse(const std::string& response) {
    // Check end of headers first.
    size_t end_of_headers =
        HttpUtil::LocateEndOfHeaders(base::as_byte_span(response));
    if (end_of_headers == std::string::npos) {
      return false;
    }

    // Return true if response has data equal to or more than content length.
    int64_t body_size = static_cast<int64_t>(response.size()) - end_of_headers;
    DCHECK_LE(0, body_size);
    auto headers =
        base::MakeRefCounted<HttpResponseHeaders>(HttpUtil::AssembleRawHeaders(
            std::string_view(response.data(), end_of_headers)));
    return body_size >= headers->GetContentLength();
  }

  scoped_refptr<IOBufferWithSize> read_buffer_;
  scoped_refptr<DrainableIOBuffer> write_buffer_;
  std::unique_ptr<TCPClientSocket> socket_;
};

struct ReceivedRequest {
  HttpServerRequestInfo info;
  int connection_id;
};

}  // namespace

class HttpServerTest : public TestWithTaskEnvironment,
                       public HttpServer::Delegate {
 public:
  HttpServerTest() = default;

  void SetUp() override {
    auto server_socket =
        std::make_unique<TCPServerSocket>(nullptr, NetLogSource());
    server_socket->ListenWithAddressAndPort("127.0.0.1", 0, 1);
    server_ = std::make_unique<HttpServer>(std::move(server_socket), this);
    ASSERT_THAT(server_->GetLocalAddress(&server_address_), IsOk());
  }

  void TearDown() override {
    // Run the event loop some to make sure that the memory handed over to
    // DeleteSoon gets fully freed.
    base::RunLoop().RunUntilIdle();
  }

  void OnConnect(int connection_id) override {
    DCHECK(connection_map_.find(connection_id) == connection_map_.end());
    connection_map_[connection_id] = true;
    // This is set in CreateConnection(), which must be invoked once for every
    // expected connection.
    quit_on_create_loop_->Quit();
  }

  void OnHttpRequest(int connection_id,
                     const HttpServerRequestInfo& info) override {
    received_request_.SetValue({.info = info, .connection_id = connection_id});
  }

  void OnWebSocketRequest(int connection_id,
                          const HttpServerRequestInfo& info) override {
    NOTREACHED();
  }

  void OnWebSocketMessage(int connection_id, std::string data) override {
    NOTREACHED();
  }

  void OnClose(int connection_id) override {
    DCHECK(connection_map_.find(connection_id) != connection_map_.end());
    connection_map_[connection_id] = false;
    if (connection_id == quit_on_close_connection_) {
      std::move(run_loop_quit_func_).Run();
    }
  }

  ReceivedRequest WaitForRequest() { return received_request_.Take(); }

  bool HasRequest() const { return received_request_.IsReady(); }

  // Connections should only be created using this method, which waits until
  // both the server and the client have received the connected socket.
  void CreateConnection(TestHttpClient* client) {
    ASSERT_FALSE(quit_on_create_loop_);
    quit_on_create_loop_ = std::make_unique<base::RunLoop>();
    EXPECT_THAT(client->ConnectAndWait(server_address_), IsOk());
    quit_on_create_loop_->Run();
    quit_on_create_loop_.reset();
  }

  void RunUntilConnectionIdClosed(int connection_id) {
    quit_on_close_connection_ = connection_id;
    auto iter = connection_map_.find(connection_id);
    if (iter != connection_map_.end() && !iter->second) {
      // Already disconnected.
      return;
    }

    base::RunLoop run_loop;
    base::AutoReset<base::OnceClosure> run_loop_quit_func(
        &run_loop_quit_func_, run_loop.QuitClosure());
    run_loop.Run();

    iter = connection_map_.find(connection_id);
    ASSERT_TRUE(iter != connection_map_.end());
    ASSERT_FALSE(iter->second);
  }

  void HandleAcceptResult(std::unique_ptr<StreamSocket> socket) {
    ASSERT_FALSE(quit_on_create_loop_);
    quit_on_create_loop_ = std::make_unique<base::RunLoop>();
    server_->accepted_socket_ = std::move(socket);
    server_->HandleAcceptResult(OK);
    quit_on_create_loop_->Run();
    quit_on_create_loop_.reset();
  }

  std::unordered_map<int, bool>& connection_map() { return connection_map_; }

 protected:
  std::unique_ptr<HttpServer> server_;
  IPEndPoint server_address_;
  base::OnceClosure run_loop_quit_func_;
  std::unordered_map<int /* connection_id */, bool /* connected */>
      connection_map_;

 private:
  base::test::TestFuture<ReceivedRequest> received_request_;
  std::unique_ptr<base::RunLoop> quit_on_create_loop_;
  int quit_on_close_connection_ = -1;
};

namespace {

class WebSocketTest : public HttpServerTest {
  void OnHttpRequest(int connection_id,
                     const HttpServerRequestInfo& info) override {
    NOTREACHED();
  }

  void OnWebSocketRequest(int connection_id,
                          const HttpServerRequestInfo& info) override {
    HttpServerTest::OnHttpRequest(connection_id, info);
  }

  void OnWebSocketMessage(int connection_id, std::string data) override {}
};

class WebSocketAcceptingTest : public WebSocketTest {
 public:
  void OnWebSocketRequest(int connection_id,
                          const HttpServerRequestInfo& info) override {
    HttpServerTest::OnHttpRequest(connection_id, info);
    server_->AcceptWebSocket(connection_id, info, TRAFFIC_ANNOTATION_FOR_TESTS);
  }

  void OnWebSocketMessage(int connection_id, std::string data) override {
    last_message_.SetValue(data);
  }

  std::string GetMessage() { return last_message_.Take(); }

 private:
  base::test::TestFuture<std::string> last_message_;
};

std::string EncodeFrame(std::string message,
                        WebSocketFrameHeader::OpCodeEnum op_code,
                        bool mask,
                        bool finish) {
  WebSocketFrameHeader header(op_code);
  header.final = finish;
  header.masked = mask;
  header.payload_length = message.size();
  const size_t header_size = GetWebSocketFrameHeaderSize(header);
  std::string frame_header;
  frame_header.resize(header_size);
  if (mask) {
    WebSocketMaskingKey masking_key = GenerateWebSocketMaskingKey();
    WriteWebSocketFrameHeader(header, &masking_key,
                              base::as_writable_byte_span(frame_header));
    MaskWebSocketFramePayload(masking_key, 0,
                              base::as_writable_byte_span(message));
  } else {
    WriteWebSocketFrameHeader(header, nullptr,
                              base::as_writable_byte_span(frame_header));
  }
  return frame_header + message;
}

TEST_F(HttpServerTest, Request) {
  TestHttpClient client;
  CreateConnection(&client);
  client.Send("GET /test HTTP/1.1\r\n\r\n");
  ReceivedRequest request = WaitForRequest();
  ASSERT_EQ("GET", request.info.method);
  ASSERT_EQ("/test", request.info.path);
  ASSERT_EQ("", request.info.data);
  ASSERT_EQ(0u, request.info.headers.size());
  ASSERT_TRUE(request.info.peer.ToString().starts_with("127.0.0.1"));
}

TEST_F(HttpServerTest, RequestBrokenTermination) {
  TestHttpClient client;
  CreateConnection(&client);
  client.Send("GET /test HTTP/1.1\r\n\r)");
  RunUntilConnectionIdClosed(1);
  EXPECT_FALSE(HasRequest());
  client.ExpectUsedThenDisconnectedWithNoData();
}

TEST_F(HttpServerTest, RequestWithHeaders) {
  TestHttpClient client;
  CreateConnection(&client);
  const char* const kHeaders[][3] = {
      {"Header", ": ", "1"},
      {"HeaderWithNoWhitespace", ":", "1"},
      {"HeaderWithWhitespace", "   :  \t   ", "1 1 1 \t  "},
      {"HeaderWithColon", ": ", "1:1"},
      {"EmptyHeader", ":", ""},
      {"EmptyHeaderWithWhitespace", ":  \t  ", ""},
      {"HeaderWithNonASCII", ":  ", "\xf7"},
  };
  std::string headers;
  for (const auto& header : kHeaders) {
    headers += std::string(header[0]) + header[1] + header[2] + "\r\n";
  }

  client.Send("GET /test HTTP/1.1\r\n" + headers + "\r\n");
  auto request = WaitForRequest();
  ASSERT_EQ("", request.info.data);

  for (const auto& header : kHeaders) {
    std::string field = base::ToLowerASCII(std::string(header[0]));
    std::string value = header[2];
    ASSERT_EQ(1u, request.info.headers.count(field)) << field;
    ASSERT_EQ(value, request.info.headers[field]) << header[0];
  }
}

TEST_F(HttpServerTest, RequestWithDuplicateHeaders) {
  TestHttpClient client;
  CreateConnection(&client);
  const char* const kHeaders[][3] = {
      // clang-format off
      {"FirstHeader", ": ", "1"},
      {"DuplicateHeader", ": ", "2"},
      {"MiddleHeader", ": ", "3"},
      {"DuplicateHeader", ": ", "4"},
      {"LastHeader", ": ", "5"},
      // clang-format on
  };
  std::string headers;
  for (const auto& header : kHeaders) {
    headers += std::string(header[0]) + header[1] + header[2] + "\r\n";
  }

  client.Send("GET /test HTTP/1.1\r\n" + headers + "\r\n");
  auto request = WaitForRequest();
  ASSERT_EQ("", request.info.data);

  for (const auto& header : kHeaders) {
    std::string field = base::ToLowerASCII(std::string(header[0]));
    std::string value = (field == "duplicateheader") ? "2,4" : header[2];
    ASSERT_EQ(1u, request.info.headers.count(field)) << field;
    ASSERT_EQ(value, request.info.headers[field]) << header[0];
  }
}

TEST_F(HttpServerTest, HasHeaderValueTest) {
  TestHttpClient client;
  CreateConnection(&client);
  const char* const kHeaders[] = {
      "Header: Abcd",
      "HeaderWithNoWhitespace:E",
      "HeaderWithWhitespace   :  \t   f \t  ",
      "DuplicateHeader: g",
      "HeaderWithComma: h, i ,j",
      "DuplicateHeader: k",
      "EmptyHeader:",
      "EmptyHeaderWithWhitespace:  \t  ",
      "HeaderWithNonASCII:  \xf7",
  };
  std::string headers;
  for (const char* header : kHeaders) {
    headers += std::string(header) + "\r\n";
  }

  client.Send("GET /test HTTP/1.1\r\n" + headers + "\r\n");
  auto request = WaitForRequest();
  ASSERT_EQ("", request.info.data);

  ASSERT_TRUE(request.info.HasHeaderValue("header", "abcd"));
  ASSERT_FALSE(request.info.HasHeaderValue("header", "bc"));
  ASSERT_TRUE(request.info.HasHeaderValue("headerwithnowhitespace", "e"));
  ASSERT_TRUE(request.info.HasHeaderValue("headerwithwhitespace", "f"));
  ASSERT_TRUE(request.info.HasHeaderValue("duplicateheader", "g"));
  ASSERT_TRUE(request.info.HasHeaderValue("headerwithcomma", "h"));
  ASSERT_TRUE(request.info.HasHeaderValue("headerwithcomma", "i"));
  ASSERT_TRUE(request.info.HasHeaderValue("headerwithcomma", "j"));
  ASSERT_TRUE(request.info.HasHeaderValue("duplicateheader", "k"));
  ASSERT_FALSE(request.info.HasHeaderValue("emptyheader", "x"));
  ASSERT_FALSE(request.info.HasHeaderValue("emptyheaderwithwhitespace", "x"));
  ASSERT_TRUE(request.info.HasHeaderValue("headerwithnonascii", "\xf7"));
}

TEST_F(HttpServerTest, RequestWithBody) {
  TestHttpClient client;
  CreateConnection(&client);
  std::string body = "a" + std::string(1 << 10, 'b') + "c";
  client.Send(
      base::StringPrintf("GET /test HTTP/1.1\r\n"
                         "SomeHeader: 1\r\n"
                         "Content-Length: %" PRIuS "\r\n\r\n%s",
                         body.length(), body.c_str()));
  auto request = WaitForRequest();
  ASSERT_EQ(2u, request.info.headers.size());
  ASSERT_EQ(body.length(), request.info.data.length());
  ASSERT_EQ('a', body[0]);
  ASSERT_EQ('c', *body.rbegin());
}

// Tests that |HttpServer::HandleReadResult| will ignore Upgrade header if value
// is not WebSocket.
TEST_F(HttpServerTest, UpgradeIgnored) {
  TestHttpClient client;
  CreateConnection(&client);
  client.Send(
      "GET /test HTTP/1.1\r\n"
      "Upgrade: h2c\r\n"
      "Connection: SomethingElse, Upgrade\r\n"
      "\r\n");
  WaitForRequest();
}

TEST_F(WebSocketTest, RequestWebSocket) {
  TestHttpClient client;
  CreateConnection(&client);
  client.Send(
      "GET /test HTTP/1.1\r\n"
      "Upgrade: WebSocket\r\n"
      "Connection: SomethingElse, Upgrade\r\n"
      "Sec-WebSocket-Version: 8\r\n"
      "Sec-WebSocket-Key: key\r\n"
      "\r\n");
  WaitForRequest();
}

TEST_F(WebSocketTest, RequestWebSocketTrailingJunk) {
  TestHttpClient client;
  CreateConnection(&client);
  client.Send(
      "GET /test HTTP/1.1\r\n"
      "Upgrade: WebSocket\r\n"
      "Connection: SomethingElse, Upgrade\r\n"
      "Sec-WebSocket-Version: 8\r\n"
      "Sec-WebSocket-Key: key\r\n"
      "\r\nHello? Anyone");
  RunUntilConnectionIdClosed(1);
  client.ExpectUsedThenDisconnectedWithNoData();
}

TEST_F(WebSocketAcceptingTest, SendPingFrameWithNoMessage) {
  TestHttpClient client;
  CreateConnection(&client);
  std::string response;
  client.Send(
      "GET /test HTTP/1.1\r\n"
      "Upgrade: WebSocket\r\n"
      "Connection: SomethingElse, Upgrade\r\n"
      "Sec-WebSocket-Version: 8\r\n"
      "Sec-WebSocket-Key: key\r\n\r\n");
  WaitForRequest();
  ASSERT_TRUE(client.ReadResponse(&response));
  const std::string message = "";
  const std::string ping_frame =
      EncodeFrame(message, WebSocketFrameHeader::OpCodeEnum::kOpCodePing,
                  /* mask= */ true, /* finish= */ true);
  const std::string pong_frame =
      EncodeFrame(message, WebSocketFrameHeader::OpCodeEnum::kOpCodePong,
                  /* mask= */ false, /* finish= */ true);
  client.Send(ping_frame);
  ASSERT_TRUE(client.Read(&response, pong_frame.length()));
  EXPECT_EQ(response, pong_frame);
}

TEST_F(WebSocketAcceptingTest, SendPingFrameWithMessage) {
  TestHttpClient client;
  CreateConnection(&client);
  std::string response;
  client.Send(
      "GET /test HTTP/1.1\r\n"
      "Upgrade: WebSocket\r\n"
      "Connection: SomethingElse, Upgrade\r\n"
      "Sec-WebSocket-Version: 8\r\n"
      "Sec-WebSocket-Key: key\r\n\r\n");
  WaitForRequest();
  ASSERT_TRUE(client.ReadResponse(&response));
  const std::string message = "hello";
  const std::string ping_frame =
      EncodeFrame(message, WebSocketFrameHeader::OpCodeEnum::kOpCodePing,
                  /* mask= */ true, /* finish= */ true);
  const std::string pong_frame =
      EncodeFrame(message, WebSocketFrameHeader::OpCodeEnum::kOpCodePong,
                  /* mask= */ false, /* finish= */ true);
  client.Send(ping_frame);
  ASSERT_TRUE(client.Read(&response, pong_frame.length()));
  EXPECT_EQ(response, pong_frame);
}

TEST_F(WebSocketAcceptingTest, SendPongFrame) {
  TestHttpClient client;
  CreateConnection(&client);
  std::string response;
  client.Send(
      "GET /test HTTP/1.1\r\n"
      "Upgrade: WebSocket\r\n"
      "Connection: SomethingElse, Upgrade\r\n"
      "Sec-WebSocket-Version: 8\r\n"
      "Sec-WebSocket-Key: key\r\n\r\n");
  WaitForRequest();
  ASSERT_TRUE(client.ReadResponse(&response));
  const std::string ping_frame = EncodeFrame(
      /* message= */ "", WebSocketFrameHeader::OpCodeEnum::kOpCodePing,
      /* mask= */ true, /* finish= */ true);
  const std::string pong_frame_send = EncodeFrame(
      /* message= */ "", WebSocketFrameHeader::OpCodeEnum::kOpCodePong,
      /* mask= */ true, /* finish= */ true);
  const std::string pong_frame_receive = EncodeFrame(
      /* message= */ "", WebSocketFrameHeader::OpCodeEnum::kOpCodePong,
      /* mask= */ false, /* finish= */ true);
  client.Send(pong_frame_send);
  client.Send(ping_frame);
  ASSERT_TRUE(client.Read(&response, pong_frame_receive.length()));
  EXPECT_EQ(response, pong_frame_receive);
}

TEST_F(WebSocketAcceptingTest, SendLongTextFrame) {
  TestHttpClient client;
  CreateConnection(&client);
  std::string response;
  client.Send(
      "GET /test HTTP/1.1\r\n"
      "Upgrade: WebSocket\r\n"
      "Connection: SomethingElse, Upgrade\r\n"
      "Sec-WebSocket-Version: 8\r\n"
      "Sec-WebSocket-Key: key\r\n\r\n");
  WaitForRequest();
  ASSERT_TRUE(client.ReadResponse(&response));
  constexpr int kFrameSize = 100000;
  const std::string text_frame(kFrameSize, 'a');
  const std::string continuation_frame(kFrameSize, 'b');
  const std::string text_encoded_frame =
      EncodeFrame(text_frame, WebSocketFrameHeader::OpCodeEnum::kOpCodeText,
                  /* mask= */ true,
                  /* finish= */ false);
  const std::string continuation_encoded_frame = EncodeFrame(
      continuation_frame, WebSocketFrameHeader::OpCodeEnum::kOpCodeContinuation,
      /* mask= */ true, /* finish= */ true);
  client.Send(text_encoded_frame);
  client.Send(continuation_encoded_frame);
  std::string received_message = GetMessage();
  EXPECT_EQ(received_message.size(),
            text_frame.size() + continuation_frame.size());
  EXPECT_EQ(received_message, text_frame + continuation_frame);
}

TEST_F(WebSocketAcceptingTest, SendTwoTextFrame) {
  TestHttpClient client;
  CreateConnection(&client);
  std::string response;
  client.Send(
      "GET /test HTTP/1.1\r\n"
      "Upgrade: WebSocket\r\n"
      "Connection: SomethingElse, Upgrade\r\n"
      "Sec-WebSocket-Version: 8\r\n"
      "Sec-WebSocket-Key: key\r\n\r\n");
  WaitForRequest();
  ASSERT_TRUE(client.ReadResponse(&response));
  const std::string text_frame_first = "foo";
  const std::string continuation_frame_first = "bar";
  const std::string text_encoded_frame_first = EncodeFrame(
      text_frame_first, WebSocketFrameHeader::OpCodeEnum::kOpCodeText,
      /* mask= */ true,
      /* finish= */ false);
  const std::string continuation_encoded_frame_first =
      EncodeFrame(continuation_frame_first,
                  WebSocketFrameHeader::OpCodeEnum::kOpCodeContinuation,
                  /* mask= */ true, /* finish= */ true);

  const std::string text_frame_second = "FOO";
  const std::string continuation_frame_second = "BAR";
  const std::string text_encoded_frame_second = EncodeFrame(
      text_frame_second, WebSocketFrameHeader::OpCodeEnum::kOpCodeText,
      /* mask= */ true,
      /* finish= */ false);
  const std::string continuation_encoded_frame_second =
      EncodeFrame(continuation_frame_second,
                  WebSocketFrameHeader::OpCodeEnum::kOpCodeContinuation,
                  /* mask= */ true, /* finish= */ true);

  // text_encoded_frame_first -> text_encoded_frame_second
  client.Send(text_encoded_frame_first);
  client.Send(continuation_encoded_frame_first);
  std::string received_message = GetMessage();
  EXPECT_EQ(received_message, "foobar");
  client.Send(text_encoded_frame_second);
  client.Send(continuation_encoded_frame_second);
  received_message = GetMessage();
  EXPECT_EQ(received_message, "FOOBAR");
}

TEST_F(WebSocketAcceptingTest, SendPingPongFrame) {
  TestHttpClient client;
  CreateConnection(&client);
  std::string response;
  client.Send(
      "GET /test HTTP/1.1\r\n"
      "Upgrade: WebSocket\r\n"
      "Connection: SomethingElse, Upgrade\r\n"
      "Sec-WebSocket-Version: 8\r\n"
      "Sec-WebSocket-Key: key\r\n\r\n");
  WaitForRequest();
  ASSERT_TRUE(client.ReadResponse(&response));

  const std::string ping_message_first = "";
  const std::string ping_frame_first = EncodeFrame(
      ping_message_first, WebSocketFrameHeader::OpCodeEnum::kOpCodePing,
      /* mask= */ true, /* finish= */ true);
  const std::string pong_frame_receive_first = EncodeFrame(
      ping_message_first, WebSocketFrameHeader::OpCodeEnum::kOpCodePong,
      /* mask= */ false, /* finish= */ true);
  const std::string pong_frame_send = EncodeFrame(
      /* message= */ "", WebSocketFrameHeader::OpCodeEnum::kOpCodePong,
      /* mask= */ true, /* finish= */ true);
  const std::string ping_message_second = "hello";
  const std::string ping_frame_second = EncodeFrame(
      ping_message_second, WebSocketFrameHeader::OpCodeEnum::kOpCodePing,
      /* mask= */ true, /* finish= */ true);
  const std::string pong_frame_receive_second = EncodeFrame(
      ping_message_second, WebSocketFrameHeader::OpCodeEnum::kOpCodePong,
      /* mask= */ false, /* finish= */ true);

  // ping_frame_first -> pong_frame_send -> ping_frame_second
  client.Send(ping_frame_first);
  ASSERT_TRUE(client.Read(&response, pong_frame_receive_first.length()));
  EXPECT_EQ(response, pong_frame_receive_first);
  client.Send(pong_frame_send);
  client.Send(ping_frame_second);
  ASSERT_TRUE(client.Read(&response, pong_frame_receive_second.length()));
  EXPECT_EQ(response, pong_frame_receive_second);
}

TEST_F(WebSocketAcceptingTest, SendTextAndPingFrame) {
  TestHttpClient client;
  CreateConnection(&client);
  std::string response;
  client.Send(
      "GET /test HTTP/1.1\r\n"
      "Upgrade: WebSocket\r\n"
      "Connection: SomethingElse, Upgrade\r\n"
      "Sec-WebSocket-Version: 8\r\n"
      "Sec-WebSocket-Key: key\r\n\r\n");
  WaitForRequest();
  ASSERT_TRUE(client.ReadResponse(&response));

  const std::string text_frame = "foo";
  const std::string continuation_frame = "bar";
  const std::string text_encoded_frame =
      EncodeFrame(text_frame, WebSocketFrameHeader::OpCodeEnum::kOpCodeText,
                  /* mask= */ true,
                  /* finish= */ false);
  const std::string continuation_encoded_frame = EncodeFrame(
      continuation_frame, WebSocketFrameHeader::OpCodeEnum::kOpCodeContinuation,
      /* mask= */ true, /* finish= */ true);
  const std::string ping_message = "ping";
  const std::string ping_frame =
      EncodeFrame(ping_message, WebSocketFrameHeader::OpCodeEnum::kOpCodePing,
                  /* mask= */ true, /* finish= */ true);
  const std::string pong_frame =
      EncodeFrame(ping_message, WebSocketFrameHeader::OpCodeEnum::kOpCodePong,
                  /* mask= */ false, /* finish= */ true);

  // text_encoded_frame -> ping_frame -> continuation_encoded_frame
  client.Send(text_encoded_frame);
  client.Send(ping_frame);
  client.Send(continuation_encoded_frame);
  ASSERT_TRUE(client.Read(&response, pong_frame.length()));
  EXPECT_EQ(response, pong_frame);
  std::string received_message = GetMessage();
  EXPECT_EQ(received_message, "foobar");
}

TEST_F(WebSocketAcceptingTest, SendTextAndPingFrameWithMessage) {
  TestHttpClient client;
  CreateConnection(&client);
  std::string response;
  client.Send(
      "GET /test HTTP/1.1\r\n"
      "Upgrade: WebSocket\r\n"
      "Connection: SomethingElse, Upgrade\r\n"
      "Sec-WebSocket-Version: 8\r\n"
      "Sec-WebSocket-Key: key\r\n\r\n");
  WaitForRequest();
  ASSERT_TRUE(client.ReadResponse(&response));

  const std::string text_frame = "foo";
  const std::string continuation_frame = "bar";
  const std::string text_encoded_frame =
      EncodeFrame(text_frame, WebSocketFrameHeader::OpCodeEnum::kOpCodeText,
                  /* mask= */ true,
                  /* finish= */ false);
  const std::string continuation_encoded_frame = EncodeFrame(
      continuation_frame, WebSocketFrameHeader::OpCodeEnum::kOpCodeContinuation,
      /* mask= */ true, /* finish= */ true);
  const std::string ping_message = "hello";
  const std::string ping_frame =
      EncodeFrame(ping_message, WebSocketFrameHeader::OpCodeEnum::kOpCodePing,
                  /* mask= */ true, /* finish= */ true);
  const std::string pong_frame =
      EncodeFrame(ping_message, WebSocketFrameHeader::OpCodeEnum::kOpCodePong,
                  /* mask= */ false, /* finish= */ true);

  // text_encoded_frame -> ping_frame -> continuation_frame
  client.Send(text_encoded_frame);
  client.Send(ping_frame);
  client.Send(continuation_encoded_frame);
  ASSERT_TRUE(client.Read(&response, pong_frame.length()));
  EXPECT_EQ(response, pong_frame);
  std::string received_message = GetMessage();
  EXPECT_EQ(received_message, "foobar");
}

TEST_F(WebSocketAcceptingTest, SendTextAndPongFrame) {
  TestHttpClient client;
  CreateConnection(&client);
  std::string response;
  client.Send(
      "GET /test HTTP/1.1\r\n"
      "Upgrade: WebSocket\r\n"
      "Connection: SomethingElse, Upgrade\r\n"
      "Sec-WebSocket-Version: 8\r\n"
      "Sec-WebSocket-Key: key\r\n\r\n");
  WaitForRequest();
  ASSERT_TRUE(client.ReadResponse(&response));

  const std::string text_frame = "foo";
  const std::string continuation_frame = "bar";
  const std::string text_encoded_frame =
      EncodeFrame(text_frame, WebSocketFrameHeader::OpCodeEnum::kOpCodeText,
                  /* mask= */ true,
                  /* finish= */ false);
  const std::string continuation_encoded_frame = EncodeFrame(
      continuation_frame, WebSocketFrameHeader::OpCodeEnum::kOpCodeContinuation,
      /* mask= */ true, /* finish= */ true);
  const std::string pong_message = "pong";
  const std::string pong_frame =
      EncodeFrame(pong_message, WebSocketFrameHeader::OpCodeEnum::kOpCodePong,
                  /* mask= */ true, /* finish= */ true);

  // text_encoded_frame -> pong_frame -> continuation_encoded_frame
  client.Send(text_encoded_frame);
  client.Send(pong_frame);
  client.Send(continuation_encoded_frame);
  std::string received_message = GetMessage();
  EXPECT_EQ(received_message, "foobar");
}

TEST_F(WebSocketAcceptingTest, SendTextPingPongFrame) {
  TestHttpClient client;
  CreateConnection(&client);
  std::string response;
  client.Send(
      "GET /test HTTP/1.1\r\n"
      "Upgrade: WebSocket\r\n"
      "Connection: SomethingElse, Upgrade\r\n"
      "Sec-WebSocket-Version: 8\r\n"
      "Sec-WebSocket-Key: key\r\n\r\n");
  WaitForRequest();
  ASSERT_TRUE(client.ReadResponse(&response));

  const std::string text_frame = "foo";
  const std::string continuation_frame = "bar";
  const std::string text_encoded_frame =
      EncodeFrame(text_frame, WebSocketFrameHeader::OpCodeEnum::kOpCodeText,
                  /* mask= */ true,
                  /* finish= */ false);
  const std::string continuation_encoded_frame = EncodeFrame(
      continuation_frame, WebSocketFrameHeader::OpCodeEnum::kOpCodeContinuation,
      /* mask= */ true, /* finish= */ true);

  const std::string ping_message_first = "hello";
  const std::string ping_frame_first = EncodeFrame(
      ping_message_first, WebSocketFrameHeader::OpCodeEnum::kOpCodePing,
      /* mask= */ true, /* finish= */ true);
  const std::string pong_frame_first = EncodeFrame(
      ping_message_first, WebSocketFrameHeader::OpCodeEnum::kOpCodePong,
      /* mask= */ false, /* finish= */ true);

  const std::string ping_message_second = "HELLO";
  const std::string ping_frame_second = EncodeFrame(
      ping_message_second, WebSocketFrameHeader::OpCodeEnum::kOpCodePing,
      /* mask= */ true, /* finish= */ true);
  const std::string pong_frame_second = EncodeFrame(
      ping_message_second, WebSocketFrameHeader::OpCodeEnum::kOpCodePong,
      /* mask= */ false, /* finish= */ true);

  // text_encoded_frame -> ping_frame_first -> ping_frame_second ->
  // continuation_encoded_frame
  client.Send(text_encoded_frame);
  client.Send(ping_frame_first);
  ASSERT_TRUE(client.Read(&response, pong_frame_first.length()));
  EXPECT_EQ(response, pong_frame_first);
  client.Send(ping_frame_second);
  ASSERT_TRUE(client.Read(&response, pong_frame_second.length()));
  EXPECT_EQ(response, pong_frame_second);
  client.Send(continuation_encoded_frame);
  std::string received_message = GetMessage();
  EXPECT_EQ(received_message, "foobar");
}

TEST_F(HttpServerTest, RequestWithTooLargeBody) {
  TestHttpClient client;
  CreateConnection(&client);
  client.Send(
      "GET /test HTTP/1.1\r\n"
      "Content-Length: 1073741824\r\n\r\n");
  std::string response;
  ASSERT_TRUE(client.ReadResponse(&response));
  EXPECT_EQ(
      "HTTP/1.1 500 Internal Server Error\r\n"
      "Content-Length:42\r\n"
      "Content-Type:text/html\r\n\r\n"
      "request content-length too big or unknown.",
      response);
}

TEST_F(HttpServerTest, Send200) {
  TestHttpClient client;
  CreateConnection(&client);
  client.Send("GET /test HTTP/1.1\r\n\r\n");
  auto request = WaitForRequest();
  server_->Send200(request.connection_id, "Response!", "text/plain",
                   TRAFFIC_ANNOTATION_FOR_TESTS);

  std::string response;
  ASSERT_TRUE(client.ReadResponse(&response));
  ASSERT_TRUE(response.starts_with("HTTP/1.1 200 OK"));
  ASSERT_TRUE(response.ends_with("Response!"));
}

TEST_F(HttpServerTest, SendRaw) {
  TestHttpClient client;
  CreateConnection(&client);
  client.Send("GET /test HTTP/1.1\r\n\r\n");
  auto request = WaitForRequest();
  server_->SendRaw(request.connection_id, "Raw Data ",
                   TRAFFIC_ANNOTATION_FOR_TESTS);
  server_->SendRaw(request.connection_id, "More Data",
                   TRAF
"""


```