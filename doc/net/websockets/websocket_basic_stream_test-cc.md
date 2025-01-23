Response:
The user wants me to analyze the provided C++ source code file `websocket_basic_stream_test.cc`. I need to identify its functionalities, its relation to JavaScript (if any), provide examples with hypothetical inputs and outputs for logical deductions, highlight common usage errors, describe user actions leading to this code, and finally, summarize the file's purpose.

Here's a breakdown of the steps:

1. **Functionality Analysis**: Read through the code, focusing on the test cases defined using `TEST_F`. Each `TEST_F` likely represents a specific functionality of the `WebSocketBasicStream` class being tested. Look for patterns in setup, actions (calling methods on `stream_`), and assertions (`EXPECT_THAT`, `ASSERT_EQ`).

2. **JavaScript Relation**:  Consider how WebSockets are used in web browsers. JavaScript's `WebSocket` API is the primary interface. Look for tests that simulate scenarios originating from JavaScript WebSocket interactions, such as sending and receiving data frames, handling different frame types (text, binary, control frames like ping/pong/close), and error conditions.

3. **Logical Deduction (Input/Output)**: For specific test cases that demonstrate logical behavior (e.g., handling fragmented frames, combining headers and bodies), imagine the input data stream to the underlying socket and the expected output in terms of `WebSocketFrame` objects.

4. **Common Usage Errors**: Think from a developer's perspective using the `WebSocketBasicStream` class. What could go wrong during integration? This might involve incorrect setup, improper handling of asynchronous operations, or misunderstanding the expected input data format.

5. **User Actions & Debugging**:  Imagine a user interacting with a web page that uses WebSockets. Trace the path from user action (e.g., sending a message) to where this low-level networking code might be involved. This helps in understanding how a developer might end up debugging issues in this area.

6. **Summary**:  Condense the findings into a concise overview of the file's role. It's primarily a unit test suite for `WebSocketBasicStream`.

**Pre-computation/Pre-analysis:**

* **File Name**: `websocket_basic_stream_test.cc` strongly suggests this is a test file.
* **Includes**: The included headers provide clues about the class under test (`websocket_basic_stream.h`) and its dependencies (networking primitives like sockets, buffers, error codes, time). The presence of testing frameworks like `gtest` confirms it's a unit test.
* **Test Fixtures**: Classes like `WebSocketBasicStreamSocketTest`, `WebSocketBasicStreamSocketSingleReadTest`, etc., are set up to provide common testing environments and data.
* **Constant Definitions**:  Macros like `WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT` and the numerous `k...` constants define sample WebSocket frame data, which will be used in the test cases.

By systematically analyzing these elements, I can address each part of the user's request.
这是对 Chromium 网络栈中 `net/websockets/websocket_basic_stream_test.cc` 文件的功能进行分析。该文件是用于测试 `WebSocketBasicStream` 类的单元测试文件。

**功能列举:**

该文件的主要功能是测试 `net::WebSocketBasicStream` 类的各种方法和功能，以确保其在处理 WebSocket 通信时的正确性。具体来说，它测试了以下方面：

1. **基本构造和初始化**: 测试 `WebSocketBasicStream` 对象的创建。
2. **同步和异步读取帧**: 测试 `ReadFrames` 方法在同步和异步模式下正确读取完整的 WebSocket 数据帧。
3. **分片帧的处理**: 测试如何处理接收到的分片帧，包括头部和负载分片到达的情况，以及如何将它们组合成完整的 `WebSocketFrame` 对象。
4. **消息的组装**: 测试如何将多个连续的帧组合成一个完整的 WebSocket 消息，并正确设置帧的 `final` 标志和操作码。
5. **空帧的处理**: 测试如何处理空的 WebSocket 数据帧，包括作为消息的第一个、中间和最后一个帧的情况。
6. **连接关闭的处理**: 测试在连接关闭时 `ReadFrames` 方法的返回值（`ERR_CONNECTION_CLOSED`）。
7. **错误处理**: 测试 `ReadFrames` 方法如何传递底层 socket 返回的错误。
8. **HTTP 读取缓冲区的使用**: 测试当 WebSocket 连接升级成功后，如何利用 HTTP 响应中剩余的数据（如果包含完整的或部分 WebSocket 帧头）进行读取。
9. **控制帧的处理**: 测试如何读取和解析控制帧 (例如 Ping, Pong, Close)。
10. **掩码处理 (虽然代码中包含掩码相关的常量，但这段代码片段中没有直接测试掩码的功能)**。
11. **缓冲区大小管理 (从 `WebSocketBasicStreamSwitchTest` 类名推测，虽然这段代码片段中没有直接的测试)**。

**与 JavaScript 功能的关系以及举例说明:**

`WebSocketBasicStream` 类是 Chromium 中处理底层 WebSocket 连接的核心组件之一。它负责从 socket 读取数据，解析 WebSocket 帧，并将它们传递给上层。在浏览器中，JavaScript 的 `WebSocket` API 是开发者与 WebSocket 服务器交互的接口。

当 JavaScript 代码创建一个 `WebSocket` 对象并连接到服务器后，底层就会建立一个 TCP 连接，然后进行 WebSocket 握手。一旦握手成功，浏览器（Chromium）会使用 `WebSocketBasicStream` 类来处理后续的 WebSocket 数据传输。

**举例说明:**

* **JavaScript 发送消息:** 当 JavaScript 代码调用 `websocket.send("Hello")` 时，浏览器会将 "Hello" 封装成一个或多个 WebSocket 数据帧，并通过底层的 socket 发送出去。`WebSocketBasicStream` 负责接收服务器发送的响应帧。
* **JavaScript 接收消息:** 当服务器向浏览器发送 WebSocket 消息时，底层 socket 接收到数据。`WebSocketBasicStream` 的 `ReadFrames` 方法会被调用来解析这些数据，将它们组装成 `WebSocketFrame` 对象，然后传递给上层的 WebSocket 接口，最终触发 JavaScript `websocket.onmessage` 事件。
* **JavaScript 关闭连接:** 当 JavaScript 代码调用 `websocket.close()` 时，浏览器会发送一个 WebSocket 关闭帧。`WebSocketBasicStream` 可以接收到服务器发送的关闭帧，并通知上层连接已关闭。

**逻辑推理 (假设输入与输出):**

假设输入的是一个包含两个完整 WebSocket 文本帧的数据流：`\x81\x05Hello\x81\x04Test`

* **假设输入:**  底层 socket 接收到字节流 `\x81\x05Hello\x81\x04Test`。
* **`ReadFrames` 方法调用:** 调用 `stream_->ReadFrames(&frames, cb_.callback())`。
* **逻辑推理:** `WebSocketBasicStream` 会解析这个字节流，识别出两个独立的 WebSocket 帧。第一个帧的操作码是文本 (`0x1`)，payload 长度是 5，内容是 "Hello"。第二个帧的操作码也是文本，payload 长度是 4，内容是 "Test"。
* **预期输出:** `frames` 向量将包含两个 `std::unique_ptr<WebSocketFrame>` 对象。
    * 第一个 `WebSocketFrame`: `header.final = true`, `header.opcode = 0x1`, `header.payload_length = 5`, `payload = "Hello"`.
    * 第二个 `WebSocketFrame`: `header.final = true`, `header.opcode = 0x1`, `header.payload_length = 4`, `payload = "Test"`.

**用户或编程常见的使用错误以及举例说明:**

虽然这个测试文件本身不涉及用户直接操作，但它测试的代码是底层网络栈的一部分。编程中与 `WebSocketBasicStream` 相关的常见错误可能发生在集成和使用这个类的上层代码中，例如：

1. **没有正确处理异步操作:** `ReadFrames` 方法可能是异步的，返回 `ERR_IO_PENDING`。如果上层代码没有正确使用回调函数或等待机制，可能会导致数据丢失或程序逻辑错误。
2. **假设一次读取就能获得完整帧:** WebSocket 帧可能会分片到达。上层代码需要能够处理接收到的多个分片，直到获得完整的消息。
3. **错误地假设帧的类型或内容:**  需要根据帧头中的操作码来判断帧的类型（文本、二进制、控制帧）并进行相应的处理。
4. **没有正确处理连接关闭:** 当 `ReadFrames` 返回 `ERR_CONNECTION_CLOSED` 时，上层代码需要清理资源并停止进一步的读写操作。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中打开一个网页，该网页使用 JavaScript `WebSocket` API 连接到一个 WebSocket 服务器。**
2. **JavaScript 代码调用 `websocket.send(data)` 发送消息，或者服务器向浏览器推送消息。**
3. **Chromium 浏览器底层的网络栈接收到 WebSocket 数据。**
4. **接收到的数据会被传递到 `net::WebSocketChannel` 或类似的更高层级的 WebSocket 处理类。**
5. **`net::WebSocketChannel` 会调用 `net::WebSocketBasicStream::ReadFrames` 方法来读取和解析底层的 WebSocket 帧数据。**
6. **如果在这个过程中出现问题，例如接收到的数据格式不正确，或者连接意外关闭，开发人员可能会需要调试 `WebSocketBasicStream` 类的行为。**
7. **调试时，可以使用网络抓包工具查看底层的 TCP 数据包，确认发送和接收的数据是否符合 WebSocket 协议。**
8. **开发者可能会运行 `websocket_basic_stream_test.cc` 中的单元测试来验证 `WebSocketBasicStream` 类的特定功能是否正常工作，或者编写新的测试来复现和修复 bug。**
9. **通过分析测试用例的输入（模拟的 socket 数据）和预期输出，可以帮助理解 `WebSocketBasicStream` 的工作原理，并定位问题所在。**

**归纳一下它的功能 (第1部分):**

这个代码文件的主要功能是为 `net::WebSocketBasicStream` 类提供全面的单元测试。它通过模拟不同的 socket 数据输入（包括完整的、分片的、错误的帧数据），来验证 `WebSocketBasicStream` 类在读取和解析 WebSocket 帧时的正确性。这些测试覆盖了同步和异步读取模式，以及各种帧类型和边界情况，确保该类在各种场景下都能可靠地工作。这对于保证 Chromium 浏览器中 WebSocket 功能的稳定性和正确性至关重要。

### 提示词
```
这是目录为net/websockets/websocket_basic_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

// Tests for WebSocketBasicStream. Note that we do not attempt to verify that
// frame parsing itself functions correctly, as that is covered by the
// WebSocketFrameParser tests.

#include "net/websockets/websocket_basic_stream.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>  // for memcpy() and memset().

#include <iterator>
#include <optional>
#include <utility>

#include "base/containers/heap_array.h"
#include "base/containers/span.h"
#include "base/numerics/byte_conversions.h"
#include "base/time/time.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/privacy_mode.h"
#include "net/base/request_priority.h"
#include "net/base/test_completion_callback.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/client_socket_pool.h"
#include "net/socket/connect_job.h"
#include "net/socket/socket_tag.h"
#include "net/socket/socket_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {
namespace {

#define WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(name, value) \
  const char k##name[] = value;                                  \
  const size_t k##name##Size = std::size(k##name) - 1

WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(SampleFrame, "\x81\x06Sample");
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(
    PartialLargeFrame,
    "\x81\x7F\x00\x00\x00\x00\x7F\xFF\xFF\xFF"
    "chromiunum ad pasco per loca insanis pullum manducat frumenti");
constexpr size_t kLargeFrameHeaderSize = 10;
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(MultipleFrames,
                                            "\x81\x01X\x81\x01Y\x81\x01Z");
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(EmptyFirstFrame, "\x01\x00");
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(EmptyMiddleFrame, "\x00\x00");
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(EmptyFinalTextFrame, "\x81\x00");
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(EmptyFinalContinuationFrame,
                                            "\x80\x00");
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(ValidPong, "\x8A\x00");
// This frame encodes a payload length of 7 in two bytes, which is always
// invalid.
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(InvalidFrame,
                                            "\x81\x7E\x00\x07Invalid");
// Control frames must have the FIN bit set. This one does not.
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(PingFrameWithoutFin, "\x09\x00");
// Control frames must have a payload of 125 bytes or less. This one has
// a payload of 126 bytes.
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(
    126BytePong,
    "\x8a\x7e\x00\x7eZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
    "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ");
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(CloseFrame,
                                            "\x88\x09\x03\xe8occludo");
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(WriteFrame,
                                            "\x81\x85\x00\x00\x00\x00Write");
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(MaskedEmptyPong,
                                            "\x8A\x80\x00\x00\x00\x00");
constexpr WebSocketMaskingKey kNulMaskingKey = {{'\0', '\0', '\0', '\0'}};
constexpr WebSocketMaskingKey kNonNulMaskingKey = {
    {'\x0d', '\x1b', '\x06', '\x17'}};

// A masking key generator function which generates the identity mask,
// ie. "\0\0\0\0".
WebSocketMaskingKey GenerateNulMaskingKey() {
  return kNulMaskingKey;
}

// A masking key generation function which generates a fixed masking key with no
// nul characters.
WebSocketMaskingKey GenerateNonNulMaskingKey() {
  return kNonNulMaskingKey;
}

// A subclass of StaticSocketDataProvider modified to require that all data
// expected to be read or written actually is.
class StrictStaticSocketDataProvider : public StaticSocketDataProvider {
 public:
  StrictStaticSocketDataProvider(base::span<const MockRead> reads,
                                 base::span<const MockWrite> writes,
                                 bool strict_mode)
      : StaticSocketDataProvider(reads, writes), strict_mode_(strict_mode) {}

  ~StrictStaticSocketDataProvider() override {
    if (strict_mode_) {
      EXPECT_EQ(read_count(), read_index());
      EXPECT_EQ(write_count(), write_index());
    }
  }

 private:
  const bool strict_mode_;
};

// A fixture for tests which only perform normal socket operations.
class WebSocketBasicStreamSocketTest : public TestWithTaskEnvironment {
 protected:
  WebSocketBasicStreamSocketTest()
      : common_connect_job_params_(
            &factory_,
            /*host_resolver=*/nullptr,
            /*http_auth_cache=*/nullptr,
            /*http_auth_handler_factory=*/nullptr,
            /*spdy_session_pool=*/nullptr,
            /*quic_supported_versions=*/nullptr,
            /*quic_session_pool=*/nullptr,
            /*proxy_delegate=*/nullptr,
            /*http_user_agent_settings=*/nullptr,
            /*ssl_client_context=*/nullptr,
            /*socket_performance_watcher_factory=*/nullptr,
            /*network_quality_estimator=*/nullptr,
            /*net_log=*/nullptr,
            /*websocket_endpoint_lock_manager=*/nullptr,
            /*http_server_properties*/ nullptr,
            /*alpn_protos=*/nullptr,
            /*application_settings=*/nullptr,
            /*ignore_certificate_errors=*/nullptr,
            /*early_data_enabled=*/nullptr),
        pool_(1, 1, &common_connect_job_params_),
        generator_(&GenerateNulMaskingKey) {}

  ~WebSocketBasicStreamSocketTest() override {
    // stream_ has a reference to socket_data_ (via MockTCPClientSocket) and so
    // should be destroyed first.
    stream_.reset();
  }

  std::unique_ptr<ClientSocketHandle> MakeTransportSocket(
      base::span<const MockRead> reads,
      base::span<const MockWrite> writes) {
    socket_data_ = std::make_unique<StrictStaticSocketDataProvider>(
        reads, writes, expect_all_io_to_complete_);
    socket_data_->set_connect_data(MockConnect(SYNCHRONOUS, OK));
    factory_.AddSocketDataProvider(socket_data_.get());

    auto transport_socket = std::make_unique<ClientSocketHandle>();
    scoped_refptr<ClientSocketPool::SocketParams> null_params;
    ClientSocketPool::GroupId group_id(
        url::SchemeHostPort(url::kHttpScheme, "a", 80),
        PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
        SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
    transport_socket->Init(
        group_id, null_params, std::nullopt /* proxy_annotation_tag */, MEDIUM,
        SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
        CompletionOnceCallback(), ClientSocketPool::ProxyAuthCallback(), &pool_,
        NetLogWithSource());
    return transport_socket;
  }

  void SetHttpReadBuffer(const char* data, size_t size) {
    http_read_buffer_ = base::MakeRefCounted<GrowableIOBuffer>();
    http_read_buffer_->SetCapacity(size);
    memcpy(http_read_buffer_->data(), data, size);
    http_read_buffer_->set_offset(size);
  }

  void CreateStream(base::span<const MockRead> reads,
                    base::span<const MockWrite> writes) {
    stream_ = WebSocketBasicStream::CreateWebSocketBasicStreamForTesting(
        MakeTransportSocket(reads, writes), http_read_buffer_, sub_protocol_,
        extensions_, net_log_, generator_);
  }

  std::unique_ptr<SocketDataProvider> socket_data_;
  MockClientSocketFactory factory_;
  const CommonConnectJobParams common_connect_job_params_;
  MockTransportClientSocketPool pool_;
  TestCompletionCallback cb_;
  scoped_refptr<GrowableIOBuffer> http_read_buffer_;
  std::string sub_protocol_;
  std::string extensions_;
  NetLogWithSource net_log_;
  WebSocketBasicStream::WebSocketMaskingKeyGeneratorFunction generator_;
  bool expect_all_io_to_complete_ = true;
  std::unique_ptr<WebSocketBasicStream> stream_;
};

// A test fixture for the common case of tests that only perform a single read.
class WebSocketBasicStreamSocketSingleReadTest
    : public WebSocketBasicStreamSocketTest {
 protected:
  void CreateRead(const MockRead& read) {
    reads_[0] = read;
    CreateStream(reads_, base::span<MockWrite>());
  }

  MockRead reads_[1];
};

// A test fixture for tests that perform chunked reads.
class WebSocketBasicStreamSocketChunkedReadTest
    : public WebSocketBasicStreamSocketTest {
 protected:
  // Specify the behaviour if there aren't enough chunks to use all the data. If
  // LAST_FRAME_BIG is specified, then the rest of the data will be
  // put in the last chunk. If LAST_FRAME_NOT_BIG is specified, then the last
  // frame will be no bigger than the rest of the frames (but it can be smaller,
  // if not enough data remains).
  enum LastFrameBehaviour { LAST_FRAME_BIG, LAST_FRAME_NOT_BIG };

  // Prepares a read from |data| of |data_size|, split into |number_of_chunks|,
  // each of |chunk_size| (except that the last chunk may be larger or
  // smaller). All reads must be either SYNCHRONOUS or ASYNC (not a mixture),
  // and errors cannot be simulated. Once data is exhausted, further reads will
  // return 0 (ie. connection closed).
  void CreateChunkedRead(IoMode mode,
                         const char data[],
                         size_t data_size,
                         int chunk_size,
                         size_t number_of_chunks,
                         LastFrameBehaviour last_frame_behaviour) {
    reads_.clear();
    const char* start = data;
    for (size_t i = 0; i < number_of_chunks; ++i) {
      int len = chunk_size;
      const bool is_last_chunk = (i == number_of_chunks - 1);
      if ((last_frame_behaviour == LAST_FRAME_BIG && is_last_chunk) ||
          static_cast<int>(data + data_size - start) < len) {
        len = static_cast<int>(data + data_size - start);
      }
      reads_.emplace_back(mode, start, len);
      start += len;
    }
    CreateStream(reads_, base::span<MockWrite>());
  }

  std::vector<MockRead> reads_;
};

// Test fixture for write tests.
class WebSocketBasicStreamSocketWriteTest
    : public WebSocketBasicStreamSocketTest {
 protected:
  // All write tests use the same frame, so it is easiest to create it during
  // test creation.
  void SetUp() override { PrepareWriteFrame(); }

  // Creates a WebSocketFrame with a wire format matching kWriteFrame and adds
  // it to |frames_|.
  void PrepareWriteFrame() {
    auto frame =
        std::make_unique<WebSocketFrame>(WebSocketFrameHeader::kOpCodeText);
    const size_t payload_size =
        kWriteFrameSize - (WebSocketFrameHeader::kBaseHeaderSize +
                           WebSocketFrameHeader::kMaskingKeyLength);
    auto buffer = base::MakeRefCounted<IOBufferWithSize>(payload_size);
    frame_buffers_.push_back(buffer);
    buffer->span().copy_from(
        base::byte_span_from_cstring(kWriteFrame).last(payload_size));
    frame->payload = buffer->span();
    WebSocketFrameHeader& header = frame->header;
    header.final = true;
    header.masked = true;
    header.payload_length = payload_size;
    frames_.push_back(std::move(frame));
  }

  // TODO(yoichio): Make this type std::vector<std::string>.
  std::vector<scoped_refptr<IOBuffer>> frame_buffers_;
  std::vector<std::unique_ptr<WebSocketFrame>> frames_;
};

// A test fixture for tests that perform read buffer size switching.
class WebSocketBasicStreamSwitchTest : public WebSocketBasicStreamSocketTest {
 protected:
  // This is used to specify the read start/end time.
  base::TimeTicks MicrosecondsFromStart(int microseconds) {
    static const base::TimeTicks kStartPoint =
        base::TimeTicks::UnixEpoch() + base::Seconds(60);
    return kStartPoint + base::Microseconds(microseconds);
  }

  WebSocketBasicStream::BufferSizeManager buffer_size_manager_;
};

TEST_F(WebSocketBasicStreamSocketTest, ConstructionWorks) {
  CreateStream(base::span<MockRead>(), base::span<MockWrite>());
}

TEST_F(WebSocketBasicStreamSocketSingleReadTest, SyncReadWorks) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  CreateRead(MockRead(SYNCHRONOUS, kSampleFrame, kSampleFrameSize));
  int result = stream_->ReadFrames(&frames, cb_.callback());
  EXPECT_THAT(result, IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_EQ(UINT64_C(6), frames[0]->header.payload_length);
  EXPECT_TRUE(frames[0]->header.final);
}

TEST_F(WebSocketBasicStreamSocketSingleReadTest, AsyncReadWorks) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  CreateRead(MockRead(ASYNC, kSampleFrame, kSampleFrameSize));
  int result = stream_->ReadFrames(&frames, cb_.callback());
  ASSERT_THAT(result, IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_EQ(UINT64_C(6), frames[0]->header.payload_length);
  // Don't repeat all the tests from SyncReadWorks; just enough to be sure the
  // frame was really read.
}

// ReadFrames will not return a frame whose header has not been wholly received.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, HeaderFragmentedSync) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  CreateChunkedRead(SYNCHRONOUS, kSampleFrame, kSampleFrameSize, 1, 2,
                    LAST_FRAME_BIG);
  int result = stream_->ReadFrames(&frames, cb_.callback());
  EXPECT_THAT(result, IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_EQ(UINT64_C(6), frames[0]->header.payload_length);
}

// The same behaviour applies to asynchronous reads.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, HeaderFragmentedAsync) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  CreateChunkedRead(ASYNC, kSampleFrame, kSampleFrameSize, 1, 2,
                    LAST_FRAME_BIG);
  int result = stream_->ReadFrames(&frames, cb_.callback());
  ASSERT_THAT(result, IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_EQ(UINT64_C(6), frames[0]->header.payload_length);
}

// If it receives an incomplete header in a synchronous call, then has to wait
// for the rest of the frame, ReadFrames will return ERR_IO_PENDING.
TEST_F(WebSocketBasicStreamSocketTest, HeaderFragmentedSyncAsync) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  MockRead reads[] = {MockRead(SYNCHRONOUS, kSampleFrame, 1),
                      MockRead(ASYNC, kSampleFrame + 1, kSampleFrameSize - 1)};
  CreateStream(reads, base::span<MockWrite>());
  int result = stream_->ReadFrames(&frames, cb_.callback());
  ASSERT_THAT(result, IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_EQ(UINT64_C(6), frames[0]->header.payload_length);
}

// An extended header should also return ERR_IO_PENDING if it is not completely
// received.
TEST_F(WebSocketBasicStreamSocketTest, FragmentedLargeHeader) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kPartialLargeFrame, kLargeFrameHeaderSize - 1),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  CreateStream(reads, base::span<MockWrite>());
  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()),
              IsError(ERR_IO_PENDING));
}

// A frame that does not arrive in a single read should be broken into separate
// frames.
TEST_F(WebSocketBasicStreamSocketSingleReadTest, LargeFrameFirstChunk) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  CreateRead(MockRead(SYNCHRONOUS, kPartialLargeFrame, kPartialLargeFrameSize));
  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_FALSE(frames[0]->header.final);
  EXPECT_EQ(kPartialLargeFrameSize - kLargeFrameHeaderSize,
            static_cast<size_t>(frames[0]->header.payload_length));
}

// If only the header of a data frame arrives, we should receive a frame with a
// zero-size payload.
TEST_F(WebSocketBasicStreamSocketSingleReadTest, HeaderOnlyChunk) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  CreateRead(MockRead(SYNCHRONOUS, kPartialLargeFrame, kLargeFrameHeaderSize));

  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames.size());
  ASSERT_TRUE(frames[0]->payload.empty());
  EXPECT_EQ(0U, frames[0]->header.payload_length);
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[0]->header.opcode);
}

// If the header and the body of a data frame arrive seperately, we should see
// them as separate frames.
TEST_F(WebSocketBasicStreamSocketTest, HeaderBodySeparated) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kPartialLargeFrame, kLargeFrameHeaderSize),
      MockRead(ASYNC, kPartialLargeFrame + kLargeFrameHeaderSize,
               kPartialLargeFrameSize - kLargeFrameHeaderSize)};
  CreateStream(reads, base::span<MockWrite>());
  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames.size());
  ASSERT_TRUE(frames[0]->payload.empty());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[0]->header.opcode);
  frames.clear();
  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_EQ(kPartialLargeFrameSize - kLargeFrameHeaderSize,
            frames[0]->header.payload_length);
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeContinuation,
            frames[0]->header.opcode);
}

// Every frame has a header with a correct payload_length field.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, LargeFrameTwoChunks) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  constexpr size_t kChunkSize = 16;
  CreateChunkedRead(ASYNC, kPartialLargeFrame, kPartialLargeFrameSize,
                    kChunkSize, 2, LAST_FRAME_NOT_BIG);
  TestCompletionCallback cb[2];

  ASSERT_THAT(stream_->ReadFrames(&frames, cb[0].callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb[0].WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_EQ(kChunkSize - kLargeFrameHeaderSize,
            frames[0]->header.payload_length);

  frames.clear();
  ASSERT_THAT(stream_->ReadFrames(&frames, cb[1].callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb[1].WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_EQ(kChunkSize, frames[0]->header.payload_length);
}

// Only the final frame of a fragmented message has |final| bit set.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, OnlyFinalChunkIsFinal) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  static constexpr size_t kFirstChunkSize = 4;
  CreateChunkedRead(ASYNC, kSampleFrame, kSampleFrameSize, kFirstChunkSize, 2,
                    LAST_FRAME_BIG);
  TestCompletionCallback cb[2];

  ASSERT_THAT(stream_->ReadFrames(&frames, cb[0].callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb[0].WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames.size());
  ASSERT_FALSE(frames[0]->header.final);

  frames.clear();
  ASSERT_THAT(stream_->ReadFrames(&frames, cb[1].callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb[1].WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames.size());
  ASSERT_TRUE(frames[0]->header.final);
}

// All frames after the first have their opcode changed to Continuation.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, ContinuationOpCodeUsed) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  constexpr size_t kFirstChunkSize = 3;
  constexpr int kChunkCount = 3;
  // The input data is one frame with opcode Text, which arrives in three
  // separate chunks.
  CreateChunkedRead(ASYNC, kSampleFrame, kSampleFrameSize, kFirstChunkSize,
                    kChunkCount, LAST_FRAME_BIG);
  TestCompletionCallback cb[kChunkCount];

  ASSERT_THAT(stream_->ReadFrames(&frames, cb[0].callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb[0].WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[0]->header.opcode);

  // This test uses a loop to verify that the opcode for every frames generated
  // after the first is converted to Continuation.
  for (int i = 1; i < kChunkCount; ++i) {
    frames.clear();
    ASSERT_THAT(stream_->ReadFrames(&frames, cb[i].callback()),
                IsError(ERR_IO_PENDING));
    EXPECT_THAT(cb[i].WaitForResult(), IsOk());
    ASSERT_EQ(1U, frames.size());
    EXPECT_EQ(WebSocketFrameHeader::kOpCodeContinuation,
              frames[0]->header.opcode);
  }
}

// Multiple frames that arrive together should be parsed correctly.
TEST_F(WebSocketBasicStreamSocketSingleReadTest, ThreeFramesTogether) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  CreateRead(MockRead(SYNCHRONOUS, kMultipleFrames, kMultipleFramesSize));

  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()), IsOk());
  ASSERT_EQ(3U, frames.size());
  EXPECT_TRUE(frames[0]->header.final);
  EXPECT_TRUE(frames[1]->header.final);
  EXPECT_TRUE(frames[2]->header.final);
}

// ERR_CONNECTION_CLOSED must be returned on close.
TEST_F(WebSocketBasicStreamSocketSingleReadTest, SyncClose) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  CreateRead(MockRead(SYNCHRONOUS, "", 0));

  EXPECT_EQ(ERR_CONNECTION_CLOSED,
            stream_->ReadFrames(&frames, cb_.callback()));
}

TEST_F(WebSocketBasicStreamSocketSingleReadTest, AsyncClose) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  CreateRead(MockRead(ASYNC, "", 0));

  ASSERT_THAT(stream_->ReadFrames(&frames, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsError(ERR_CONNECTION_CLOSED));
}

// The result should be the same if the socket returns
// ERR_CONNECTION_CLOSED. This is not expected to happen on an established
// connection; a Read of size 0 is the expected behaviour. The key point of this
// test is to confirm that ReadFrames() behaviour is identical in both cases.
TEST_F(WebSocketBasicStreamSocketSingleReadTest, SyncCloseWithErr) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  CreateRead(MockRead(SYNCHRONOUS, ERR_CONNECTION_CLOSED));

  EXPECT_EQ(ERR_CONNECTION_CLOSED,
            stream_->ReadFrames(&frames, cb_.callback()));
}

TEST_F(WebSocketBasicStreamSocketSingleReadTest, AsyncCloseWithErr) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  CreateRead(MockRead(ASYNC, ERR_CONNECTION_CLOSED));

  ASSERT_THAT(stream_->ReadFrames(&frames, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsError(ERR_CONNECTION_CLOSED));
}

TEST_F(WebSocketBasicStreamSocketSingleReadTest, SyncErrorsPassedThrough) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  // ERR_INSUFFICIENT_RESOURCES here represents an arbitrary error that
  // WebSocketBasicStream gives no special handling to.
  CreateRead(MockRead(SYNCHRONOUS, ERR_INSUFFICIENT_RESOURCES));

  EXPECT_EQ(ERR_INSUFFICIENT_RESOURCES,
            stream_->ReadFrames(&frames, cb_.callback()));
}

TEST_F(WebSocketBasicStreamSocketSingleReadTest, AsyncErrorsPassedThrough) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  CreateRead(MockRead(ASYNC, ERR_INSUFFICIENT_RESOURCES));

  ASSERT_THAT(stream_->ReadFrames(&frames, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsError(ERR_INSUFFICIENT_RESOURCES));
}

// If we get a frame followed by a close, we should receive them separately.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, CloseAfterFrame) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  // The chunk size equals the data size, so the second chunk is 0 size, closing
  // the connection.
  CreateChunkedRead(SYNCHRONOUS, kSampleFrame, kSampleFrameSize,
                    kSampleFrameSize, 2, LAST_FRAME_NOT_BIG);

  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()), IsOk());
  EXPECT_EQ(1U, frames.size());
  frames.clear();
  EXPECT_EQ(ERR_CONNECTION_CLOSED,
            stream_->ReadFrames(&frames, cb_.callback()));
}

// Synchronous close after an async frame header is handled by a different code
// path.
TEST_F(WebSocketBasicStreamSocketTest, AsyncCloseAfterIncompleteHeader) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  MockRead reads[] = {MockRead(ASYNC, kSampleFrame, 1U),
                      MockRead(SYNCHRONOUS, "", 0)};
  CreateStream(reads, base::span<MockWrite>());

  ASSERT_THAT(stream_->ReadFrames(&frames, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsError(ERR_CONNECTION_CLOSED));
}

// When Stream::Read returns ERR_CONNECTION_CLOSED we get the same result via a
// slightly different code path.
TEST_F(WebSocketBasicStreamSocketTest, AsyncErrCloseAfterIncompleteHeader) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  MockRead reads[] = {MockRead(ASYNC, kSampleFrame, 1U),
                      MockRead(SYNCHRONOUS, ERR_CONNECTION_CLOSED)};
  CreateStream(reads, base::span<MockWrite>());

  ASSERT_THAT(stream_->ReadFrames(&frames, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsError(ERR_CONNECTION_CLOSED));
}

// An empty first frame is not ignored.
TEST_F(WebSocketBasicStreamSocketSingleReadTest, EmptyFirstFrame) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  CreateRead(MockRead(SYNCHRONOUS, kEmptyFirstFrame, kEmptyFirstFrameSize));

  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames.size());
  ASSERT_TRUE(frames[0]->payload.empty());
  EXPECT_EQ(0U, frames[0]->header.payload_length);
}

// An empty frame in the middle of a message is processed as part of the
// message.
TEST_F(WebSocketBasicStreamSocketTest, EmptyMiddleFrame) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kEmptyFirstFrame, kEmptyFirstFrameSize),
      MockRead(SYNCHRONOUS, kEmptyMiddleFrame, kEmptyMiddleFrameSize),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  CreateStream(reads, base::span<MockWrite>());

  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()), IsOk());
  EXPECT_EQ(1U, frames.size());
  frames.clear();
  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()), IsOk());
  EXPECT_EQ(1U, frames.size());
  frames.clear();
  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()),
              IsError(ERR_IO_PENDING));
}

// An empty frame in the middle of a message that arrives separately is
// processed.
TEST_F(WebSocketBasicStreamSocketTest, EmptyMiddleFrameAsync) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kEmptyFirstFrame, kEmptyFirstFrameSize),
      MockRead(ASYNC, kEmptyMiddleFrame, kEmptyMiddleFrameSize),
      // We include a pong message to verify the middle frame was actually
      // processed.
      MockRead(ASYNC, kValidPong, kValidPongSize)};
  CreateStream(reads, base::span<MockWrite>());

  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()), IsOk());
  EXPECT_EQ(1U, frames.size());
  frames.clear();
  ASSERT_THAT(stream_->ReadFrames(&frames, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeContinuation,
            frames[0]->header.opcode);
  frames.clear();
  ASSERT_THAT(stream_->ReadFrames(&frames, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodePong, frames[0]->header.opcode);
}

// An empty final frame is not ignored.
TEST_F(WebSocketBasicStreamSocketSingleReadTest, EmptyFinalFrame) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  CreateRead(
      MockRead(SYNCHRONOUS, kEmptyFinalTextFrame, kEmptyFinalTextFrameSize));

  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames.size());
  ASSERT_TRUE(frames[0]->payload.empty());
  EXPECT_EQ(0U, frames[0]->header.payload_length);
}

// An empty middle frame is processed with a final frame present.
TEST_F(WebSocketBasicStreamSocketTest, ThreeFrameEmptyMessage) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kEmptyFirstFrame, kEmptyFirstFrameSize),
      MockRead(SYNCHRONOUS, kEmptyMiddleFrame, kEmptyMiddleFrameSize),
      MockRead(SYNCHRONOUS, kEmptyFinalContinuationFrame,
               kEmptyFinalContinuationFrameSize)};
  CreateStream(reads, base::span<MockWrite>());

  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[0]->header.opcode);
  frames.clear();
  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeContinuation,
            frames[0]->header.opcode);
  frames.clear();
  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeContinuation,
            frames[0]->header.opcode);
  EXPECT_TRUE(frames[0]->header.final);
}

// If there was a frame read at the same time as the response headers (and the
// handshake succeeded), then we should parse it.
TEST_F(WebSocketBasicStreamSocketTest, HttpReadBufferIsUsed) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  SetHttpReadBuffer(kSampleFrame, kSampleFrameSize);
  CreateStream(base::span<MockRead>(), base::span<MockWrite>());

  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames.size());
  ASSERT_FALSE(frames[0]->payload.empty());
  EXPECT_EQ(UINT64_C(6), frames[0]->header.payload_length);
}

// Check that a frame whose header partially arrived at the end of the response
// headers works correctly.
TEST_F(WebSocketBasicStreamSocketSingleReadTest,
       PartialFrameHeaderInHttpResponse) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  SetHttpReadBuffer(kSampleFrame, 1);
  CreateRead(MockRead(ASYNC, kSampleFrame + 1, kSampleFrameSize - 1));

  ASSERT_THAT(stream_->ReadFrames(&frames, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames.size());
  ASSERT_FALSE(frames[0]->payload.empty());
  EXPECT_EQ(UINT64_C(6), frames[0]->header.payload_length);
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames[0]->header.opcode);
}

// Check that a control frame which partially arrives at the end of the response
// headers works correctly.
TEST_F(WebSocketBasicStreamSocketSingleReadTest,
       PartialControlFrameInHttpResponse) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  constexpr size_t kPartialFrameBytes = 3;
  SetHttpReadBuffer(kCloseFrame, kPartialFrameBytes);
  CreateRead(MockRead(ASYNC, kCloseFrame + kPartialFrameBytes,
                      kCloseFrameSize - kPartialFrameBytes));

  ASSERT_THAT(stream_->ReadFrames(&frames, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeClose, frames[0]->header.opcode);
  EXPECT_EQ(kCloseFrameSize - 2, frames[0]->header.payload_length);
  EXPECT_EQ(base::as_string_view(frames[0]->payload),
            std::string_view(kCloseFrame + 2, kCloseFrameSize - 2));
}

// Check that a control frame which partially arrives at the end of the response
// headers works correctly. Synchronous version (unlikely in practice).
TEST_F(WebSocketBasicStreamSocketSingleReadTest,
       PartialControlFrameInHttpResponseSync) {
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  constexpr size_t kPartialFrameBytes = 3;
  SetHttpReadBuffer(kCloseFrame, kPartialFrameBytes);
  CreateRead(MockRead(SYNCHRONOUS, kCloseFrame + kPartialFrameBytes,
                      kCloseFrameSize - kPartialFrameBytes));

  EXPECT_THAT(stream_->ReadFrames(&frames, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeClose, frames[0]->header.opcode);
}

// Check that an invalid frame results in an err
```