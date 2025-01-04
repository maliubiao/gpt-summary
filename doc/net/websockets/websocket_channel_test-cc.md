Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a test file for `WebSocketChannel` in Chromium's network stack.

Here's a breakdown of the thinking process to generate the summary:

1. **Identify the core purpose:** The file is named `websocket_channel_test.cc`. The `_test` suffix immediately indicates that this is a test file. It tests the functionality of `WebSocketChannel`.

2. **Scan for key classes and components:**  Look for the main class being tested (`WebSocketChannel`) and any related classes or mocks used within the tests. The code includes:
    * `WebSocketChannel` (the class under test)
    * `WebSocketEventInterface` (used for communication and events)
    * `WebSocketStream` (represents the underlying WebSocket connection)
    * Mock classes for the above (e.g., `MockWebSocketEventInterface`, `MockWebSocketStream`)
    * Fake implementations (e.g., `FakeWebSocketEventInterface`, `FakeWebSocketStream`, `ReadableFakeWebSocketStream`, etc.) for controlled testing.
    * Structures and helper functions for creating and comparing WebSocket frames (`InitFrame`, `CreateFrameVector`, `EqualsFrames`).

3. **Understand the testing approach:** The presence of mocks and fakes reveals that the tests aim to isolate `WebSocketChannel` and verify its behavior in different scenarios by controlling the interactions with its dependencies.

4. **Identify the types of tests:**  Look for patterns in the setup and assertions. The code shows:
    * **Basic connectivity tests:**  Simulating successful and failed connections.
    * **Data transfer tests:** Sending and receiving data frames.
    * **Closing handshake tests:**  Testing the initiation and handling of connection closure.
    * **Error handling tests:**  Simulating network errors and protocol violations.
    * **Event handling tests:** Verifying that `WebSocketChannel` calls the correct methods on the `WebSocketEventInterface` in response to different events.
    * **Frame manipulation tests:**  Creating, sending, and receiving WebSocket frames.

5. **Look for JavaScript relevance:**  Consider how WebSockets are used in a browser context. JavaScript code interacts with the WebSocket API to establish and use WebSocket connections. This C++ code, being part of the browser's network stack, *implements* the underlying mechanics. The tests ensure that this implementation correctly handles the protocols and semantics that JavaScript developers rely on. Examples include:
    * JavaScript sending and receiving text and binary data (mirrored by the frame creation and testing).
    * JavaScript initiating and handling connection closures (tested through close frame scenarios).
    * JavaScript handling errors (tested with various error conditions).

6. **Analyze the provided code snippets and macros:**
    * The `#include` directives show the dependencies of the test file.
    * The `CLOSE_DATA` macro suggests tests related to sending close messages with different status codes.
    * The stream insertion operators for `WebSocketFrameHeader` and `WebSocketFrame` indicate utilities for debugging and logging frame content, likely used in assertions or test output.

7. **Infer assumptions and inputs/outputs:** Since this is a *test* file, the primary "input" is the setup of the `WebSocketChannel` and its dependencies (using mocks or fakes). The "output" is the observed behavior of the `WebSocketChannel` and the calls made to the mock event interface. For example:
    * **Assumption:**  A WebSocket server is expected to respond to the handshake.
    * **Input:**  A URL for the WebSocket connection.
    * **Expected Output:**  Successful connection establishment and `OnAddChannelResponse` being called on the event interface.

8. **Consider common user/programming errors:** Think about mistakes developers might make when using the WebSocket API in JavaScript that the underlying C++ code needs to handle robustly. Examples:
    * Sending invalid data frames (tested with different frame structures).
    * Attempting to send data after the connection is closed (implicitly tested by closure scenarios).
    * Incorrectly handling close codes (tested by the `CLOSE_DATA` macro and close frame tests).

9. **Trace user interaction (debugging perspective):** Imagine a user navigating to a web page that uses WebSockets. The steps would be:
    1. User navigates to a webpage.
    2. JavaScript code on the page creates a `WebSocket` object.
    3. The browser initiates a WebSocket handshake (this is where the C++ code comes into play).
    4. The `WebSocketChannel` handles the connection establishment and data transfer.
    5. If issues occur, developers might inspect network logs or use debugging tools to understand the communication flow, potentially leading them to examine code like `websocket_channel_test.cc` to understand how the underlying implementation is tested.

10. **Synthesize the summary:** Combine the observations into a concise description of the file's purpose and functionality. Emphasize the testing aspect and its role in ensuring the correctness of the `WebSocketChannel` implementation.

By following these steps, we can arrive at a comprehensive summary that addresses the user's request.
这是Chromium网络栈中 `net/websockets/websocket_channel_test.cc` 文件的第一部分，主要功能是为 `WebSocketChannel` 类编写单元测试。`WebSocketChannel` 是 Chromium 中处理 WebSocket 连接的核心类之一。

**主要功能归纳:**

* **测试 `WebSocketChannel` 的核心功能:** 这个文件通过各种测试用例来验证 `WebSocketChannel` 类的正确性。这包括连接建立、数据发送和接收、连接关闭、错误处理等各个方面。
* **使用 Mock 和 Fake 对象进行隔离测试:**  为了更方便地测试 `WebSocketChannel` 的逻辑，并隔离外部依赖，该文件使用了 Google Mock 框架创建了 `MockWebSocketEventInterface` 和 `MockWebSocketStream`，以及一些 `FakeWebSocketEventInterface` 和 `FakeWebSocketStream` 的实现。这些 Mock 和 Fake 对象允许测试用例精确地控制依赖项的行为，并验证 `WebSocketChannel` 与它们的交互。
* **定义了用于测试的辅助结构和宏:**  文件中定义了 `InitFrame` 结构用于方便地初始化 `WebSocketFrame` 对象，以及 `CLOSE_DATA` 宏用于构造关闭消息的 body。这些工具简化了测试用例的编写。
* **覆盖了多种 WebSocket 操作场景:**  从已经定义的内容来看，测试涵盖了帧的发送和接收（包括最终帧和非最终帧，不同操作码），连接的建立和关闭，以及模拟各种网络状态（例如，可读、可写、连接重置等）。
* **验证了 `WebSocketChannel` 与 `WebSocketEventInterface` 的交互:**  通过 `MockWebSocketEventInterface`，测试用例可以验证 `WebSocketChannel` 在不同阶段是否正确地调用了事件接口的相应方法，例如 `OnCreateURLRequest`、`OnURLRequestConnected`、`OnDataFrame`、`OnClosingHandshake`、`OnFailChannel`、`OnDropChannel` 等。

**与 JavaScript 功能的关系以及举例说明:**

`WebSocketChannel` 是浏览器网络栈的底层实现，直接服务于 JavaScript 中的 `WebSocket` API。JavaScript 代码通过 `WebSocket` 对象发起连接、发送和接收数据。`websocket_channel_test.cc` 中的测试确保了 `WebSocketChannel` 的行为符合 WebSocket 协议规范，从而保证了 JavaScript `WebSocket` API 的正确性。

**举例说明:**

* **JavaScript 发送文本消息:**  当 JavaScript 代码使用 `websocket.send("Hello")` 发送文本消息时，浏览器底层会创建相应的 WebSocket 数据帧，并通过 `WebSocketChannel` 发送出去。此测试文件中可能包含验证 `WebSocketChannel` 能否正确地将 JavaScript 发送的字符串封装成 `TEXT_FRAME` 并发送的测试用例。
* **JavaScript 接收二进制消息:** 当服务器向客户端发送二进制数据时，`WebSocketChannel` 负责接收这些数据，并将其通过 `WebSocketEventInterface::OnDataFrame` 方法传递给上层。测试用例会模拟服务器发送二进制帧，并验证 `OnDataFrame` 是否被正确调用，并且传递的数据是正确的。
* **JavaScript 关闭连接:** 当 JavaScript 代码调用 `websocket.close()` 时，浏览器会发起 WebSocket 关闭握手。`WebSocketChannel` 负责发送关闭帧并处理接收到的关闭帧。测试用例会验证 `WebSocketChannel` 能否正确地发起和处理关闭握手，并调用 `WebSocketEventInterface::OnClosingHandshake` 和 `OnDropChannel` 等方法。

**逻辑推理，假设输入与输出:**

由于这是测试代码，其主要目的是验证逻辑。以下是一个简单的假设输入和输出示例：

**假设输入:**

1. 创建一个 `WebSocketChannel` 实例，并使用一个返回成功握手响应的 `FakeWebSocketStream` 进行连接。
2. 模拟接收到一个包含文本数据 "Test Message" 的 WebSocket 帧。

**预期输出:**

1. `WebSocketEventInterface::OnAddChannelResponse` 方法被调用，表示握手成功。
2. `WebSocketEventInterface::OnDataFrameVector` 方法被调用，参数 `fin` 为 true，`type` 为 `TEXT_FRAME`，`payload` 为 "Test Message"。

**涉及用户或者编程常见的使用错误，并举例说明:**

虽然这个文件是测试底层实现，但它间接反映了用户或开发者可能犯的错误，以及 `WebSocketChannel` 如何处理这些错误。

* **发送过大的消息:** 用户可能尝试发送超出 WebSocket 协议限制的消息。测试用例可能会验证 `WebSocketChannel` 是否能够正确处理或拒绝发送过大的帧。
* **服务器不遵循协议:** 测试用例可能会模拟服务器发送不符合 WebSocket 协议的帧（例如，错误的掩码位），并验证 `WebSocketChannel` 是否能够检测到这些错误并断开连接。
* **在连接关闭后尝试发送数据:**  开发者可能会在 JavaScript 中在连接关闭后仍然尝试发送消息。虽然这个测试文件主要关注底层，但相关的错误处理逻辑最终会在 `WebSocketChannel` 中实现，并可能通过测试用例进行验证。例如，测试用例可能会在模拟连接已关闭的情况下尝试调用 `SendFrame`，并验证是否会返回错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

当开发者在使用 JavaScript `WebSocket` API 时遇到问题，例如连接失败、数据传输异常、连接意外断开等，他们可能会：

1. **检查浏览器控制台的网络请求:** 查看 WebSocket 连接的状态和返回的错误信息。
2. **使用浏览器的开发者工具查看 WebSocket 帧:**  分析发送和接收的 WebSocket 帧内容，判断是否有协议错误或数据问题。
3. **搜索 Chromium 的网络代码:** 如果怀疑是浏览器底层的实现问题，开发者可能会搜索相关的源代码，例如 `net/websockets` 目录下的文件。
4. **查看 `websocket_channel_test.cc`:**  阅读测试用例可以帮助理解 `WebSocketChannel` 的预期行为，以及它如何处理各种情况。测试用例往往包含了各种边界情况和错误场景，可以帮助开发者理解问题的根源。
5. **设置断点进行调试:** 如果需要深入了解代码的执行过程，开发者可能会在 `WebSocketChannel` 的相关代码中设置断点，并重现问题，观察代码的执行流程和变量的值。`websocket_channel_test.cc` 中的测试用例可以作为调试的参考和起点。

**本部分功能归纳:**

总而言之，`net/websockets/websocket_channel_test.cc` 的第一部分主要定义了用于测试 `WebSocketChannel` 类的基础框架和工具，包括 Mock 和 Fake 对象、辅助结构和宏。它为后续的测试用例的编写奠定了基础，旨在全面验证 `WebSocketChannel` 在各种 WebSocket 操作场景下的正确性和健壮性。它与 JavaScript `WebSocket` API 的功能紧密相关，因为它测试了 JavaScript API 底层的实现。

Prompt: 
```
这是目录为net/websockets/websocket_channel_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/websockets/websocket_channel.h"

#include <stddef.h>
#include <string.h>

#include <algorithm>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/containers/span.h"
#include "base/dcheck_is_on.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/ranges/algorithm.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "net/base/auth.h"
#include "net/base/completion_once_callback.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/isolation_info.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/cookies/site_for_cookies.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/log/net_log_with_source.h"
#include "net/ssl/ssl_info.h"
#include "net/storage_access_api/status.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"
#include "net/websockets/websocket_errors.h"
#include "net/websockets/websocket_event_interface.h"
#include "net/websockets/websocket_handshake_request_info.h"
#include "net/websockets/websocket_handshake_response_info.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

// Hacky macros to construct the body of a Close message from a code and a
// string, while ensuring the result is a compile-time constant string.
// Use like CLOSE_DATA(NORMAL_CLOSURE, "Explanation String")
#define CLOSE_DATA(code, string) WEBSOCKET_CLOSE_CODE_AS_STRING_##code string
#define WEBSOCKET_CLOSE_CODE_AS_STRING_NORMAL_CLOSURE "\x03\xe8"
#define WEBSOCKET_CLOSE_CODE_AS_STRING_GOING_AWAY "\x03\xe9"
#define WEBSOCKET_CLOSE_CODE_AS_STRING_PROTOCOL_ERROR "\x03\xea"
#define WEBSOCKET_CLOSE_CODE_AS_STRING_ABNORMAL_CLOSURE "\x03\xee"
#define WEBSOCKET_CLOSE_CODE_AS_STRING_SERVER_ERROR "\x03\xf3"

namespace net {

class WebSocketBasicHandshakeStream;
class WebSocketHttp2HandshakeStream;

// Printing helpers to allow GoogleMock to print frames. These are explicitly
// designed to look like the static initialisation format we use in these
// tests. They have to live in the net namespace in order to be found by
// GoogleMock; a nested anonymous namespace will not work.

std::ostream& operator<<(std::ostream& os, const WebSocketFrameHeader& header) {
  return os << (header.final ? "FINAL_FRAME" : "NOT_FINAL_FRAME") << ", "
            << header.opcode << ", "
            << (header.masked ? "MASKED" : "NOT_MASKED");
}

std::ostream& operator<<(std::ostream& os, const WebSocketFrame& frame) {
  os << "{" << frame.header << ", ";
  if (!frame.payload.empty()) {
    return os << "\"" << base::as_string_view(frame.payload) << "\"}";
  }
  return os << "NULL}";
}

std::ostream& operator<<(
    std::ostream& os,
    const std::vector<std::unique_ptr<WebSocketFrame>>& frames) {
  os << "{";
  bool first = true;
  for (const auto& frame : frames) {
    if (!first) {
      os << ",\n";
    } else {
      first = false;
    }
    os << *frame;
  }
  return os << "}";
}

std::ostream& operator<<(
    std::ostream& os,
    const std::vector<std::unique_ptr<WebSocketFrame>>* vector) {
  return os << '&' << *vector;
}

namespace {

using ::base::TimeDelta;

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::DefaultValue;
using ::testing::DoAll;
using ::testing::InSequence;
using ::testing::MockFunction;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::SaveArg;
using ::testing::StrictMock;

// A selection of characters that have traditionally been mangled in some
// environment or other, for testing 8-bit cleanliness.
constexpr char kBinaryBlob[] = {
    '\n',   '\r',    // BACKWARDS CRNL
    '\0',            // nul
    '\x7F',          // DEL
    '\x80', '\xFF',  // NOT VALID UTF-8
    '\x1A',          // Control-Z, EOF on DOS
    '\x03',          // Control-C
    '\x04',          // EOT, special for Unix terms
    '\x1B',          // ESC, often special
    '\b',            // backspace
    '\'',            // single-quote, special in PHP
};
constexpr size_t kBinaryBlobSize = std::size(kBinaryBlob);

constexpr int kVeryBigTimeoutMillis = 60 * 60 * 24 * 1000;

// TestTimeouts::tiny_timeout() is 100ms! I could run halfway around the world
// in that time! I would like my tests to run a bit quicker.
constexpr int kVeryTinyTimeoutMillis = 1;

using ChannelState = WebSocketChannel::ChannelState;
constexpr ChannelState CHANNEL_ALIVE = WebSocketChannel::CHANNEL_ALIVE;
constexpr ChannelState CHANNEL_DELETED = WebSocketChannel::CHANNEL_DELETED;

// This typedef mainly exists to avoid having to repeat the "NOLINT" incantation
// all over the place.
typedef StrictMock< MockFunction<void(int)> > Checkpoint;  // NOLINT

// This mock is for testing expectations about how the EventInterface is used.
class MockWebSocketEventInterface : public WebSocketEventInterface {
 public:
  MockWebSocketEventInterface() = default;

  void OnDataFrame(bool fin,
                   WebSocketMessageType type,
                   base::span<const char> payload) override {
    return OnDataFrameVector(fin, type,
                             std::vector<char>(payload.begin(), payload.end()));
  }

  MOCK_METHOD1(OnCreateURLRequest, void(URLRequest*));
  MOCK_METHOD2(OnURLRequestConnected, void(URLRequest*, const TransportInfo&));
  MOCK_METHOD3(OnAddChannelResponse,
               void(std::unique_ptr<WebSocketHandshakeResponseInfo> response,
                    const std::string&,
                    const std::string&));  // NOLINT
  MOCK_METHOD3(OnDataFrameVector,
               void(bool,
                    WebSocketMessageType,
                    const std::vector<char>&));           // NOLINT
  MOCK_METHOD0(HasPendingDataFrames, bool(void));         // NOLINT
  MOCK_METHOD0(OnSendDataFrameDone, void(void));          // NOLINT
  MOCK_METHOD0(OnClosingHandshake, void(void));           // NOLINT
  MOCK_METHOD3(OnFailChannel,
               void(const std::string&, int, std::optional<int>));  // NOLINT
  MOCK_METHOD3(OnDropChannel,
               void(bool, uint16_t, const std::string&));  // NOLINT

  // We can't use GMock with std::unique_ptr.
  void OnStartOpeningHandshake(
      std::unique_ptr<WebSocketHandshakeRequestInfo>) override {
    OnStartOpeningHandshakeCalled();
  }
  void OnSSLCertificateError(
      std::unique_ptr<SSLErrorCallbacks> ssl_error_callbacks,
      const GURL& url,
      int net_error,
      const SSLInfo& ssl_info,
      bool fatal) override {
    OnSSLCertificateErrorCalled(
        ssl_error_callbacks.get(), url, ssl_info, fatal);
  }
  int OnAuthRequired(const AuthChallengeInfo& auth_info,
                     scoped_refptr<HttpResponseHeaders> response_headers,
                     const IPEndPoint& remote_endpoint,
                     base::OnceCallback<void(const AuthCredentials*)> callback,
                     std::optional<AuthCredentials>* credentials) override {
    return OnAuthRequiredCalled(std::move(auth_info),
                                std::move(response_headers), remote_endpoint,
                                credentials);
  }

  MOCK_METHOD0(OnStartOpeningHandshakeCalled, void());  // NOLINT
  MOCK_METHOD4(
      OnSSLCertificateErrorCalled,
      void(SSLErrorCallbacks*, const GURL&, const SSLInfo&, bool));  // NOLINT
  MOCK_METHOD4(OnAuthRequiredCalled,
               int(const AuthChallengeInfo&,
                   scoped_refptr<HttpResponseHeaders>,
                   const IPEndPoint&,
                   std::optional<AuthCredentials>*));
};

// This fake EventInterface is for tests which need a WebSocketEventInterface
// implementation but are not verifying how it is used.
class FakeWebSocketEventInterface : public WebSocketEventInterface {
  void OnCreateURLRequest(URLRequest* request) override {}
  void OnURLRequestConnected(URLRequest* request,
                             const TransportInfo& info) override {}
  void OnAddChannelResponse(
      std::unique_ptr<WebSocketHandshakeResponseInfo> response,
      const std::string& selected_protocol,
      const std::string& extensions) override {}
  void OnDataFrame(bool fin,
                   WebSocketMessageType type,
                   base::span<const char> data_span) override {}
  void OnSendDataFrameDone() override {}
  bool HasPendingDataFrames() override { return false; }
  void OnClosingHandshake() override {}
  void OnFailChannel(const std::string& message,
                     int net_error,
                     std::optional<int> response_code) override {}
  void OnDropChannel(bool was_clean,
                     uint16_t code,
                     const std::string& reason) override {}
  void OnStartOpeningHandshake(
      std::unique_ptr<WebSocketHandshakeRequestInfo> request) override {}
  void OnSSLCertificateError(
      std::unique_ptr<SSLErrorCallbacks> ssl_error_callbacks,
      const GURL& url,
      int net_error,
      const SSLInfo& ssl_info,
      bool fatal) override {}
  int OnAuthRequired(const AuthChallengeInfo& auth_info,
                     scoped_refptr<HttpResponseHeaders> response_headers,
                     const IPEndPoint& remote_endpoint,
                     base::OnceCallback<void(const AuthCredentials*)> callback,
                     std::optional<AuthCredentials>* credentials) override {
    *credentials = std::nullopt;
    return OK;
  }
};

// This fake WebSocketStream is for tests that require a WebSocketStream but are
// not testing the way it is used. It has minimal functionality to return
// the |protocol| and |extensions| that it was constructed with.
class FakeWebSocketStream : public WebSocketStream {
 public:
  // Constructs with empty protocol and extensions.
  FakeWebSocketStream() = default;

  // Constructs with specified protocol and extensions.
  FakeWebSocketStream(const std::string& protocol,
                      const std::string& extensions)
      : protocol_(protocol), extensions_(extensions) {}

  int ReadFrames(std::vector<std::unique_ptr<WebSocketFrame>>* frames,
                 CompletionOnceCallback callback) override {
    return ERR_IO_PENDING;
  }

  int WriteFrames(std::vector<std::unique_ptr<WebSocketFrame>>* frames,
                  CompletionOnceCallback callback) override {
    return ERR_IO_PENDING;
  }

  void Close() override {}

  // Returns the string passed to the constructor.
  std::string GetSubProtocol() const override { return protocol_; }

  // Returns the string passed to the constructor.
  std::string GetExtensions() const override { return extensions_; }

  const NetLogWithSource& GetNetLogWithSource() const override {
    return net_log_;
  }

 private:
  // The string to return from GetSubProtocol().
  std::string protocol_;

  // The string to return from GetExtensions().
  std::string extensions_;

  NetLogWithSource net_log_;
};

// To make the static initialisers easier to read, we use enums rather than
// bools.
enum IsFinal { NOT_FINAL_FRAME, FINAL_FRAME };

enum IsMasked { NOT_MASKED, MASKED };

// This is used to initialise a WebSocketFrame but is statically initialisable.
struct InitFrame {
  IsFinal final;
  // Reserved fields omitted for now. Add them if you need them.
  WebSocketFrameHeader::OpCode opcode;
  IsMasked masked;

  // Will be used to create the IOBuffer member. Can be null for null data. Is a
  // nul-terminated string for ease-of-use. |header.payload_length| is
  // initialised from |strlen(data)|. This means it is not 8-bit clean, but this
  // is not an issue for test data.
  const char* const data;
};

// For GoogleMock
std::ostream& operator<<(std::ostream& os, const InitFrame& frame) {
  os << "{" << (frame.final == FINAL_FRAME ? "FINAL_FRAME" : "NOT_FINAL_FRAME")
     << ", " << frame.opcode << ", "
     << (frame.masked == MASKED ? "MASKED" : "NOT_MASKED") << ", ";
  if (frame.data) {
    return os << "\"" << frame.data << "\"}";
  }
  return os << "NULL}";
}

template <size_t N>
std::ostream& operator<<(std::ostream& os, const InitFrame (&frames)[N]) {
  os << "{";
  bool first = true;
  for (size_t i = 0; i < N; ++i) {
    if (!first) {
      os << ",\n";
    } else {
      first = false;
    }
    os << frames[i];
  }
  return os << "}";
}

// Convert a const array of InitFrame structs to the format used at
// runtime. Templated on the size of the array to save typing.
template <size_t N>
std::vector<std::unique_ptr<WebSocketFrame>> CreateFrameVector(
    const InitFrame (&source_frames)[N],
    std::vector<scoped_refptr<IOBuffer>>* result_frame_data) {
  std::vector<std::unique_ptr<WebSocketFrame>> result_frames;
  result_frames.reserve(N);
  for (size_t i = 0; i < N; ++i) {
    const InitFrame& source_frame = source_frames[i];
    auto result_frame = std::make_unique<WebSocketFrame>(source_frame.opcode);
    size_t frame_length = source_frame.data ? strlen(source_frame.data) : 0;
    WebSocketFrameHeader& result_header = result_frame->header;
    result_header.final = (source_frame.final == FINAL_FRAME);
    result_header.masked = (source_frame.masked == MASKED);
    result_header.payload_length = frame_length;
    if (source_frame.data) {
      auto buffer = base::MakeRefCounted<IOBufferWithSize>(frame_length);
      result_frame_data->push_back(buffer);
      std::copy(source_frame.data, source_frame.data + frame_length,
                buffer->data());
      result_frame->payload = buffer->span();
    }
    result_frames.push_back(std::move(result_frame));
  }
  return result_frames;
}

// A GoogleMock action which can be used to respond to call to ReadFrames with
// some frames. Use like ReadFrames(_, _).WillOnce(ReturnFrames(&frames,
// &result_frame_data_)); |frames| is an array of InitFrame. |frames| needs to
// be passed by pointer because otherwise it will be treated as a pointer and
// the array size information will be lost.
ACTION_P2(ReturnFrames, source_frames, result_frame_data) {
  *arg0 = CreateFrameVector(*source_frames, result_frame_data);
  return OK;
}

// The implementation of a GoogleMock matcher which can be used to compare a
// std::vector<std::unique_ptr<WebSocketFrame>>* against an expectation defined
// as an
// array of InitFrame objects. Although it is possible to compose built-in
// GoogleMock matchers to check the contents of a WebSocketFrame, the results
// are so unreadable that it is better to use this matcher.
template <size_t N>
class EqualsFramesMatcher : public ::testing::MatcherInterface<
                                std::vector<std::unique_ptr<WebSocketFrame>>*> {
 public:
  explicit EqualsFramesMatcher(const InitFrame (*expect_frames)[N])
      : expect_frames_(expect_frames) {}

  bool MatchAndExplain(
      std::vector<std::unique_ptr<WebSocketFrame>>* actual_frames,
      ::testing::MatchResultListener* listener) const override {
    if (actual_frames->size() != N) {
      *listener << "the vector size is " << actual_frames->size();
      return false;
    }
    for (size_t i = 0; i < N; ++i) {
      const WebSocketFrame& actual_frame = *(*actual_frames)[i];
      const InitFrame& expected_frame = (*expect_frames_)[i];
      if (actual_frame.header.final != (expected_frame.final == FINAL_FRAME)) {
        *listener << "the frame is marked as "
                  << (actual_frame.header.final ? "" : "not ") << "final";
        return false;
      }
      if (actual_frame.header.opcode != expected_frame.opcode) {
        *listener << "the opcode is " << actual_frame.header.opcode;
        return false;
      }
      if (actual_frame.header.masked != (expected_frame.masked == MASKED)) {
        *listener << "the frame is "
                  << (actual_frame.header.masked ? "masked" : "not masked");
        return false;
      }
      const size_t expected_length =
          expected_frame.data ? strlen(expected_frame.data) : 0;
      if (actual_frame.header.payload_length != expected_length) {
        *listener << "the payload length is "
                  << actual_frame.header.payload_length;
        return false;
      }
      if (expected_length != 0 &&
          memcmp(actual_frame.payload.data(), expected_frame.data,
                 actual_frame.header.payload_length) != 0) {
        *listener << "the data content differs";
        return false;
      }
    }
    return true;
  }

  void DescribeTo(std::ostream* os) const override {
    *os << "matches " << *expect_frames_;
  }

  void DescribeNegationTo(std::ostream* os) const override {
    *os << "does not match " << *expect_frames_;
  }

 private:
  const InitFrame (*expect_frames_)[N];
};

// The definition of EqualsFrames GoogleMock matcher. Unlike the ReturnFrames
// action, this can take the array by reference.
template <size_t N>
::testing::Matcher<std::vector<std::unique_ptr<WebSocketFrame>>*> EqualsFrames(
    const InitFrame (&frames)[N]) {
  return ::testing::MakeMatcher(new EqualsFramesMatcher<N>(&frames));
}

// A GoogleMock action to run a Closure.
ACTION_P(InvokeClosure, test_closure) {
  test_closure->closure().Run();
}

// A FakeWebSocketStream whose ReadFrames() function returns data.
class ReadableFakeWebSocketStream : public FakeWebSocketStream {
 public:
  enum IsSync { SYNC, ASYNC };

  // After constructing the object, call PrepareReadFrames() once for each
  // time you wish it to return from the test.
  ReadableFakeWebSocketStream() = default;

  // Check that all the prepared responses have been consumed.
  ~ReadableFakeWebSocketStream() override {
    CHECK(index_ >= responses_.size());
    CHECK(!read_frames_pending_);
  }

  // Prepares a fake response. Fake responses will be returned from ReadFrames()
  // in the same order they were prepared with PrepareReadFrames() and
  // PrepareReadFramesError(). If |async| is ASYNC, then ReadFrames() will
  // return ERR_IO_PENDING and the callback will be scheduled to run on the
  // message loop. This requires the test case to run the message loop. If
  // |async| is SYNC, the response will be returned synchronously. |error| is
  // returned directly from ReadFrames() in the synchronous case, or passed to
  // the callback in the asynchronous case. |frames| will be converted to a
  // std::vector<std::unique_ptr<WebSocketFrame>> and copied to the pointer that
  // was
  // passed to ReadFrames().
  template <size_t N>
  void PrepareReadFrames(IsSync async,
                         int error,
                         const InitFrame (&frames)[N]) {
    responses_.push_back(std::make_unique<Response>(
        async, error, CreateFrameVector(frames, &result_frame_data_)));
  }

  // An alternate version of PrepareReadFrames for when we need to construct
  // the frames manually.
  void PrepareRawReadFrames(
      IsSync async,
      int error,
      std::vector<std::unique_ptr<WebSocketFrame>> frames) {
    responses_.push_back(
        std::make_unique<Response>(async, error, std::move(frames)));
  }

  // Prepares a fake error response (ie. there is no data).
  void PrepareReadFramesError(IsSync async, int error) {
    responses_.push_back(std::make_unique<Response>(
        async, error, std::vector<std::unique_ptr<WebSocketFrame>>()));
  }

  int ReadFrames(std::vector<std::unique_ptr<WebSocketFrame>>* frames,
                 CompletionOnceCallback callback) override {
    CHECK(!read_frames_pending_);
    if (index_ >= responses_.size())
      return ERR_IO_PENDING;
    if (responses_[index_]->async == ASYNC) {
      read_frames_pending_ = true;
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE,
          base::BindOnce(&ReadableFakeWebSocketStream::DoCallback,
                         base::Unretained(this), frames, std::move(callback)));
      return ERR_IO_PENDING;
    } else {
      frames->swap(responses_[index_]->frames);
      return responses_[index_++]->error;
    }
  }

 private:
  void DoCallback(std::vector<std::unique_ptr<WebSocketFrame>>* frames,
                  CompletionOnceCallback callback) {
    read_frames_pending_ = false;
    frames->swap(responses_[index_]->frames);
    std::move(callback).Run(responses_[index_++]->error);
    return;
  }

  struct Response {
    Response(IsSync async,
             int error,
             std::vector<std::unique_ptr<WebSocketFrame>> frames)
        : async(async), error(error), frames(std::move(frames)) {}

    // Bad things will happen if we attempt to copy or assign |frames|.
    Response(const Response&) = delete;
    Response& operator=(const Response&) = delete;

    IsSync async;
    int error;
    std::vector<std::unique_ptr<WebSocketFrame>> frames;
  };
  std::vector<std::unique_ptr<Response>> responses_;

  // The index into the responses_ array of the next response to be returned.
  size_t index_ = 0;

  // True when an async response from ReadFrames() is pending. This only applies
  // to "real" async responses. Once all the prepared responses have been
  // returned, ReadFrames() returns ERR_IO_PENDING but read_frames_pending_ is
  // not set to true.
  bool read_frames_pending_ = false;

  std::vector<scoped_refptr<IOBuffer>> result_frame_data_;
};

// A FakeWebSocketStream where writes always complete successfully and
// synchronously.
class WriteableFakeWebSocketStream : public FakeWebSocketStream {
 public:
  int WriteFrames(std::vector<std::unique_ptr<WebSocketFrame>>* frames,
                  CompletionOnceCallback callback) override {
    return OK;
  }
};

// A FakeWebSocketStream where writes always fail.
class UnWriteableFakeWebSocketStream : public FakeWebSocketStream {
 public:
  int WriteFrames(std::vector<std::unique_ptr<WebSocketFrame>>* frames,
                  CompletionOnceCallback callback) override {
    return ERR_CONNECTION_RESET;
  }
};

// A FakeWebSocketStream which echoes any frames written back. Clears the
// "masked" header bit, but makes no other checks for validity. Tests using this
// must run the MessageLoop to receive the callback(s). If a message with opcode
// Close is echoed, then an ERR_CONNECTION_CLOSED is returned in the next
// callback. The test must do something to cause WriteFrames() to be called,
// otherwise the ReadFrames() callback will never be called.
class EchoeyFakeWebSocketStream : public FakeWebSocketStream {
 public:
  EchoeyFakeWebSocketStream() = default;

  int WriteFrames(std::vector<std::unique_ptr<WebSocketFrame>>* frames,
                  CompletionOnceCallback callback) override {
    for (const auto& frame : *frames) {
      auto buffer = base::MakeRefCounted<IOBufferWithSize>(
          static_cast<size_t>(frame->header.payload_length));
      buffer->span().copy_from(frame->payload);
      frame->payload = buffer->span();
      buffers_.push_back(buffer);
    }
    stored_frames_.insert(stored_frames_.end(),
                          std::make_move_iterator(frames->begin()),
                          std::make_move_iterator(frames->end()));
    frames->clear();
    // Users of WebSocketStream will not expect the ReadFrames() callback to be
    // called from within WriteFrames(), so post it to the message loop instead.
    PostCallback();
    return OK;
  }

  int ReadFrames(std::vector<std::unique_ptr<WebSocketFrame>>* frames,
                 CompletionOnceCallback callback) override {
    read_callback_ = std::move(callback);
    read_frames_ = frames;
    if (done_)
      PostCallback();
    return ERR_IO_PENDING;
  }

 private:
  void PostCallback() {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&EchoeyFakeWebSocketStream::DoCallback,
                                  base::Unretained(this)));
  }

  void DoCallback() {
    if (done_) {
      std::move(read_callback_).Run(ERR_CONNECTION_CLOSED);
    } else if (!stored_frames_.empty()) {
      done_ = MoveFrames(read_frames_);
      read_frames_ = nullptr;
      std::move(read_callback_).Run(OK);
    }
  }

  // Copy the frames stored in stored_frames_ to |out|, while clearing the
  // "masked" header bit. Returns true if a Close Frame was seen, false
  // otherwise.
  bool MoveFrames(std::vector<std::unique_ptr<WebSocketFrame>>* out) {
    bool seen_close = false;
    *out = std::move(stored_frames_);
    for (const auto& frame : *out) {
      WebSocketFrameHeader& header = frame->header;
      header.masked = false;
      if (header.opcode == WebSocketFrameHeader::kOpCodeClose)
        seen_close = true;
    }
    return seen_close;
  }

  std::vector<std::unique_ptr<WebSocketFrame>> stored_frames_;
  CompletionOnceCallback read_callback_;
  // Owned by the caller of ReadFrames().
  raw_ptr<std::vector<std::unique_ptr<WebSocketFrame>>> read_frames_ = nullptr;
  std::vector<scoped_refptr<IOBuffer>> buffers_;
  // True if we should close the connection.
  bool done_ = false;
};

// A FakeWebSocketStream where writes trigger a connection reset.
// This differs from UnWriteableFakeWebSocketStream in that it is asynchronous
// and triggers ReadFrames to return a reset as well. Tests using this need to
// run the message loop. There are two tricky parts here:
// 1. Calling the write callback may call Close(), after which the read callback
//    should not be called.
// 2. Calling either callback may delete the stream altogether.
class ResetOnWriteFakeWebSocketStream : public FakeWebSocketStream {
 public:
  ResetOnWriteFakeWebSocketStream() = default;

  int WriteFrames(std::vector<std::unique_ptr<WebSocketFrame>>* frames,
                  CompletionOnceCallback callback) override {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(
            &ResetOnWriteFakeWebSocketStream::CallCallbackUnlessClosed,
            weak_ptr_factory_.GetWeakPtr(), std::move(callback),
            ERR_CONNECTION_RESET));
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(
            &ResetOnWriteFakeWebSocketStream::CallCallbackUnlessClosed,
            weak_ptr_factory_.GetWeakPtr(), std::move(read_callback_),
            ERR_CONNECTION_RESET));
    return ERR_IO_PENDING;
  }

  int ReadFrames(std::vector<std::unique_ptr<WebSocketFrame>>* frames,
                 CompletionOnceCallback callback) override {
    read_callback_ = std::move(callback);
    return ERR_IO_PENDING;
  }

  void Close() override { closed_ = true; }

 private:
  void CallCallbackUnlessClosed(CompletionOnceCallback callback, int value) {
    if (!closed_)
      std::move(callback).Run(value);
  }

  CompletionOnceCallback read_callback_;
  bool closed_ = false;
  // An IO error can result in the socket being deleted, so we use weak pointers
  // to ensure correct behaviour in that case.
  base::WeakPtrFactory<ResetOnWriteFakeWebSocketStream> weak_ptr_factory_{this};
};

// This mock is for verifying that WebSocket protocol semantics are obeyed (to
// the extent that they are implemented in WebSocketCommon).
class MockWebSocketStream : public WebSocketStream {
 public:
  MOCK_METHOD2(ReadFrames,
               int(std::vector<std::unique_ptr<WebSocketFrame>>*,
                   CompletionOnceCallback));
  MOCK_METHOD2(WriteFrames,
               int(std::vector<std::unique_ptr<WebSocketFrame>>*,
                   CompletionOnceCallback));

  MOCK_METHOD0(Close, void());
  MOCK_CONST_METHOD0(GetSubProtocol, std::string());
  MOCK_CONST_METHOD0(GetExtensions, std::string());
  MOCK_CONST_METHOD0(GetNetLogWithSource, NetLogWithSource&());
  MOCK_METHOD0(AsWebSocketStream, WebSocketStream*());
};

class MockWebSocketStreamRequest : public WebSocketStreamRequest {
 public:
  MOCK_METHOD1(OnBasicHandshakeStreamCreated,
               void(WebSocketBasicHandshakeStream* handshake_stream));
  MOCK_METHOD1(OnHttp2HandshakeStreamCreated,
               void(WebSocketHttp2HandshakeStream* handshake_stream));
  MOCK_METHOD1(OnFailure, void(const std::string& message));
};

struct WebSocketStreamCreationCallbackArgumentSaver {
  std::unique_ptr<WebSocketStreamRequest> Create(
      const GURL& new_socket_url,
      const std::vector<std::string>& requested_subprotocols,
      const url::Origin& new_origin,
      const SiteForCookies& new_site_for_cookies,
      StorageAccessApiStatus new_storage_access_api_status,
      const IsolationInfo& new_isolation_info,
      const HttpRequestHeaders& additional_headers,
      URLRequestContext* new_url_request_context,
      const NetLogWithSource& net_log,
      NetworkTrafficAnnotationTag traffic_annotation,
      std::unique_ptr<WebSocketStream::ConnectDelegate> new_connect_delegate) {
    socket_url = new_socket_url;
    origin = new_origin;
    site_for_cookies = new_site_for_cookies;
    storage_access_api_status = new_storage_access_api_status;
    isolation_info = new_isolation_info;
    url_request_context = new_url_request_context;
    connect_delegate = std::move(new_connect_delegate);
    return std::make_unique<MockWebSocketStreamRequest>();
  }

  GURL socket_url;
  url::Origin origin;
  SiteForCookies site_for_cookies;
  StorageAccessApiStatus storage_access_api_status;
  IsolationInfo isolation_info;
  raw_ptr<URLRequestContext> url_request_context;
  std::unique_ptr<WebSocketStream::ConnectDelegate> connect_delegate;
};

std::vector<char> AsVector(std::string_view s) {
  return std::vector<char>(s.begin(), s.end());
}

// Converts a std::string_view to a IOBuffer. For test purposes, it is
// convenient to be able to specify data as a string, but the
// WebSocketEventInterface requires the IOBuffer type.
scoped_refptr<IOBuffer> AsIOBuffer(std::string_view s) {
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(s.size());
  base::ranges::copy(s, buffer->data());
  return buffer;
}

class FakeSSLErrorCallbacks
    : public WebSocketEventInterface::SSLErrorCallbacks {
 public:
  void CancelSSLRequest(int error, const SSLInfo* ssl_info) override {}
  void ContinueSSLRequest() override {}
};

// Base class for all test fixtures.
class WebSocketChannelTest : public TestWithTaskEnvironment {
 protected:
  WebSocketChannelTest() : stream_(std::make_unique<FakeWebSocketStream>()) {}

  ~WebSocketChannelTest() override {
    // This has to be destroyed before `channel_`, which has to be destroyed
    // before the URLRequestContext (which is also owned by `argument_saver`).
    connect_data_.argument_saver.connect_delegate.reset();
  }

  // Creates a new WebSocketChannel and connects it, using the settings stored
  // in |connect_data_|.
  void CreateChannelAndConnect() {
    channel_ = std::make_unique<WebSocketChannel>(
        CreateEventInterface(), connect_data_.url_request_context.get());
    channel_->SendAddChannelRequestForTesting(
        connect_data_.socket_url, connect_data_.requested_subprotocols,
        connect_data_.origin, connect_data_.site_for_cookies,
        net::StorageAccessApiStatus::kNone, connect_data_.isolation_info,
        HttpRequestHeaders(), TRAFFIC_ANNOTATION_FOR_TESTS,
        base::BindOnce(&WebSocketStreamCreationCallbackArgumentSaver::Create,
                       base::Unretained(&connect_data_.argument_saver)));
  }

  // Same as CreateChannelAndConnect(), but calls the on_success callback as
  // well. This method is virtual so that subclasses can also set the stream.
  virtual void CreateChannelAndConnectSuccessfully() {
    CreateChannelAndConnect();
    connect_data_.argument_saver.connect_delegate->OnSuccess(
        std::move(stream_), std::make_unique<WebSocketHandshakeResponseInfo>(
                                GURL(), nullptr, IPEndPoint(), base::Time()));
    std::ignore = channel_->ReadFrames();
  }

  // Returns a WebSocketEventInterface to be passed to the WebSocketChannel.
  // This implementation returns a newly-created fake. Subclasses may return a
  // mock instead.
  virtual std::unique_ptr<WebSocketEventInterface> CreateEventInterface
"""


```