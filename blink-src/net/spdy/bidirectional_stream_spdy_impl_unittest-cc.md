Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Understand the Goal:** The primary goal is to understand what this specific file, `bidirectional_stream_spdy_impl_unittest.cc`, *does*. It's a unittest, so its purpose is to test the functionality of another component. The filename suggests it's testing something related to bidirectional streams over SPDY.

2. **Identify the Tested Class:** The `#include` directives are crucial. The first non-comment `#include` is `"net/spdy/bidirectional_stream_spdy_impl.h"`. This immediately tells us the core class being tested is `BidirectionalStreamSpdyImpl`.

3. **Unittest Structure:**  Recognize the typical structure of a C++ unittest using Google Test (`TEST_F`, `EXPECT_...`, `ASSERT_...`). This signals that the file contains individual test cases for different scenarios.

4. **Scan for Test Case Names:** Quickly scan through the file for lines starting with `TEST_F`. This provides a high-level overview of the different functionalities being tested:
    * `SimplePostRequest`
    * `LoadTimingTwoRequests`
    * `SendDataAfterStreamFailed`
    * `RstWithNoErrorBeforeSendIsComplete`
    * `RequestDetectBrokenConnection`

5. **Analyze Individual Test Cases (Deep Dive):**  Pick a few key test cases and analyze them in detail. Let's take `SimplePostRequest` as an example:
    * **Mock Data:** Observe the `MockWrite` and `MockRead` arrays. These simulate network interactions. Analyze what data is being sent (a POST request with body) and what is being received (a response). The `ERR_IO_PENDING` indicates asynchronous behavior and the need for pausing/resuming.
    * **Request Setup:**  Look at the `BidirectionalStreamRequestInfo` object. This configures the request (method, URL, headers).
    * **Delegate Class:**  Notice the use of a custom `TestDelegateBase`. This delegate receives callbacks from the `BidirectionalStreamSpdyImpl` and allows the test to verify the behavior. Pay attention to what the delegate does in each callback (e.g., `OnDataRead`, `OnDataSent`).
    * **Action and Verification:**  See how the test interacts with the `BidirectionalStreamSpdyImpl` (e.g., `Start`, `SendData`). Then, examine the `EXPECT_...` statements to see what properties are being checked (e.g., `on_data_read_count`, `GetProtocol`, `GetTotalSentBytes`).
    * **Load Timing:** Notice the `LoadTimingInfo` checks. This suggests a focus on performance and connection reuse.

6. **Look for Common Patterns:** As you analyze more test cases, look for recurring patterns:
    * The use of `SequencedSocketData` for controlled network simulation.
    * The `TestDelegateBase` pattern for intercepting and verifying stream events.
    * Different error scenarios being tested (e.g., `SendDataAfterStreamFailed`).
    * Tests related to connection management (e.g., `LoadTimingTwoRequests`, `RequestDetectBrokenConnection`).

7. **Consider JavaScript Relevance:**  Think about how the tested component might relate to JavaScript in a browser environment. Bidirectional streams are often used for WebSocket-like communication. The HTTP/2 protocol, which SPDY is based on, is the foundation for many modern web interactions. JavaScript's `fetch` API or WebSockets can potentially utilize these underlying network mechanisms.

8. **Identify Potential User/Programming Errors:**  Based on the test cases, consider what mistakes a developer using the `BidirectionalStreamSpdyImpl` might make. Sending data after the stream has failed is an obvious one tested here.

9. **Debugging Perspective:** How could a developer end up looking at this unittest file during debugging?  If they're investigating issues with network requests, particularly those involving HTTP/2 or SPDY, and they see unexpected behavior, they might look at these tests to understand how the system *should* be working and to potentially reproduce their issue in a controlled environment.

10. **Logical Inferences and Assumptions:** When a test case involves specific sequences of reads and writes, try to infer the logical flow and the assumptions behind the test. For example, the `LoadTimingTwoRequests` test assumes that the second request will reuse the existing connection.

11. **Structure the Explanation:** Organize the findings logically:
    * **Purpose:** Start with the overall goal of the file.
    * **Core Functionality:** Explain the main class being tested.
    * **Key Features Tested:** Summarize the different aspects covered by the test cases.
    * **JavaScript Relevance:**  Connect the functionality to web development concepts.
    * **Logical Reasoning:** Provide examples with input/output assumptions.
    * **User/Programming Errors:** Illustrate common mistakes.
    * **Debugging Context:** Explain how this file fits into a debugging workflow.

By following these steps, we can systematically analyze the C++ unittest file and extract the necessary information to answer the prompt's questions comprehensively. The iterative process of examining test cases, identifying patterns, and relating them to broader concepts is key to understanding the file's functionality.
这个文件 `net/spdy/bidirectional_stream_spdy_impl_unittest.cc` 是 Chromium 网络栈中用于测试 `BidirectionalStreamSpdyImpl` 类的单元测试文件。 `BidirectionalStreamSpdyImpl` 是一个用于实现基于 SPDY 协议的双向流的类。

**功能列举:**

该文件的主要功能是验证 `BidirectionalStreamSpdyImpl` 类的各种功能和行为，包括但不限于：

1. **基本的请求和响应:** 测试发送 HTTP 请求并接收响应的基本流程，包括请求头、请求体、响应头和响应体。
2. **POST 请求处理:** 特别测试了带有请求体的 POST 请求的发送和处理。
3. **负载时序 (Load Timing):** 验证请求的负载时序信息是否正确记录，包括连接重用和新建连接的情况。
4. **错误处理:** 测试在流过程中发生错误时的处理逻辑，例如接收到 `RST_STREAM` 帧。
5. **在流失败后发送数据:** 测试在流已经失败后尝试发送数据的行为，预期会失败。
6. **`RST_STREAM` 帧处理:** 测试接收到带有 `NO_ERROR` 的 `RST_STREAM` 帧时，对未完成的发送操作的处理，避免崩溃。
7. **断开连接检测:** 测试 `detect_broken_connection` 功能，即检测连接是否断开，并涉及到心跳机制。
8. **发送数据 (`SendData` 和 `SendvData`):**  测试使用不同的方法发送数据的行为。
9. **协议协商:** 验证连接使用的协议是否是预期的 (SPDY，在这里测试用例中通常指 HTTP/2)。
10. **数据发送和接收统计:** 验证发送和接收的总字节数是否正确。
11. **回调触发:** 验证各种事件的回调函数是否被正确调用，例如 `OnStreamReady`, `OnHeadersReceived`, `OnDataRead`, `OnDataSent`, `OnTrailersReceived`, `OnFailed`。

**与 JavaScript 的关系及举例说明:**

`BidirectionalStreamSpdyImpl` 虽然是用 C++ 实现的，但它所处理的 SPDY 协议是 HTTP/2 的基础，而 HTTP/2 是现代 Web 浏览器与服务器通信的核心协议之一。  因此，它与 JavaScript 在以下方面存在间接但重要的关系：

* **`fetch` API 和 WebSocket API:**  当 JavaScript 代码使用 `fetch` API 发起网络请求，或者使用 WebSocket API 建立双向通信时，如果浏览器和服务器协商使用了 HTTP/2 协议，那么底层就可能使用到 `BidirectionalStreamSpdyImpl` 这样的 C++ 代码来处理网络数据传输。

**举例说明:**

假设一个 JavaScript 应用使用 `fetch` API 发送一个 POST 请求：

```javascript
fetch('https://example.com/api', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ key: 'value' })
})
.then(response => response.json())
.then(data => console.log(data));
```

在这个过程中，如果与 `example.com` 的连接是通过 HTTP/2 建立的，那么 Chromium 的网络栈会使用 `BidirectionalStreamSpdyImpl` 来处理以下任务：

1. **将 JavaScript 的请求转换为 SPDY 帧:**  `BidirectionalStreamSpdyImpl` 负责将 `fetch` API 提供的请求方法、URL、头部和请求体数据封装成 SPDY 的 HEADERS 帧和 DATA 帧。
2. **通过 socket 发送 SPDY 帧:**  将封装好的 SPDY 帧通过底层的 socket 连接发送到服务器。
3. **接收和解析 SPDY 帧:**  从服务器接收到的 SPDY 的 HEADERS 帧和 DATA 帧会被 `BidirectionalStreamSpdyImpl` 解析，提取出响应头和响应体数据。
4. **将 SPDY 响应转换回 HTTP 响应:**  将解析出的响应头和响应体数据传递给上层，最终呈现为 `fetch` API 返回的 `Response` 对象。

**逻辑推理、假设输入与输出:**

**测试用例:** `SimplePostRequest`

**假设输入:**

* **模拟的网络交互 (通过 `MockWrite` 和 `MockRead` 定义):**
    * **发送:**
        * 一个包含 POST 请求头部的 SPDY HEADERS 帧。
        * 一个包含请求体的 SPDY DATA 帧，并设置 FIN 标志表示数据发送完成。
    * **接收:**
        * 一个包含成功响应头部的 SPDY HEADERS 帧。
        * 一个空的 SPDY DATA 帧，并设置 FIN 标志表示响应结束。
* **`BidirectionalStreamRequestInfo` 对象:**  包含请求方法 "POST"，目标 URL，以及 `Content-Length` 头部。
* **要发送的数据:** 字符串 "Body data"。

**逻辑推理:**

1. `BidirectionalStreamSpdyImpl` 收到 `Start` 调用，根据 `BidirectionalStreamRequestInfo` 构建 SPDY 请求头部帧。
2. 调用 `SendData` 发送请求体数据，这将被封装成 SPDY DATA 帧。
3. `BidirectionalStreamSpdyImpl` 将发送 SPDY HEADERS 帧和 DATA 帧到模拟的 socket。
4. `BidirectionalStreamSpdyImpl` 从模拟的 socket 接收 SPDY HEADERS 帧和 DATA 帧。
5. 解析接收到的 SPDY 帧，提取响应头部和响应体 (为空)。
6. 通知 Delegate ( `TestDelegateBase` ) 接收到头部和数据。
7. 由于响应 DATA 帧带有 FIN 标志，流被认为是完成的。
8. 负载时序信息会被记录。

**预期输出 (通过 `EXPECT_...` 断言验证):**

* `delegate->on_data_read_count()` 等于 1 (接收到一个空的 data 帧)。
* `delegate->on_data_sent_count()` 等于 1 (发送了一个 data 帧)。
* `delegate->GetProtocol()` 返回 HTTP/2 (或 SPDY 的对应枚举值)。
* `delegate->GetTotalSentBytes()` 等于发送的 HEADERS 帧和 DATA 帧的总大小。
* `delegate->GetTotalReceivedBytes()` 等于接收的 HEADERS 帧和 DATA 帧的总大小。
* `delegate->GetLoadTimingInfo()` 返回的负载时序信息符合新建连接的特征 (`TestLoadTimingNotReused`)。

**用户或编程常见的使用错误及举例说明:**

1. **在流已经关闭后尝试发送数据:**  这是 `SendDataAfterStreamFailed` 测试用例所验证的。如果开发者在 `OnFailed` 回调被调用后仍然尝试调用 `SendData`，这将会导致错误，因为流已经不再接受新的数据。

   ```c++
   // 假设 stream_delegate 是 TestDelegateBase 的实例，且流已经失败
   scoped_refptr<StringIOBuffer> buf = base::MakeRefCounted<StringIOBuffer>("more data");
   stream_delegate->SendData(buf.get(), buf->size(), false); // 错误的使用方式
   ```

2. **没有设置正确的 `Content-Length` 头部:**  虽然 HTTP/2 可以通过流控制来处理数据，但在一些情况下，显式设置 `Content-Length` 仍然很重要。如果开发者发送 POST 请求时没有正确设置 `Content-Length`，可能会导致服务器无法正确解析请求体。

   ```c++
   BidirectionalStreamRequestInfo request_info;
   request_info.method = "POST";
   request_info.url = default_url_;
   // 忘记设置 Content-Length
   // request_info.extra_headers.SetHeader(net::HttpRequestHeaders::kContentLength, ...);

   auto delegate = std::make_unique<TestDelegateBase>(...);
   delegate->Start(&request_info, ...);
   scoped_refptr<StringIOBuffer> write_buffer = ...;
   delegate->SendData(write_buffer.get(), write_buffer->size(), true);
   ```

3. **过早地结束流:**  如果开发者在没有发送完所有数据的情况下设置了流的结束标志 (例如，在发送部分请求体后就设置了 `end_of_stream=true`)，服务器可能会收到不完整的请求。

   ```c++
   auto delegate = std::make_unique<TestDelegateBase>(...);
   delegate->Start(&request_info, ...);
   scoped_refptr<StringIOBuffer> part1 = ...;
   delegate->SendData(part1.get(), part1->size(), false);
   scoped_refptr<StringIOBuffer> part2 = ...;
   delegate->SendData(part2.get(), part2->size(), true); // 假设这里本应该发送更多数据
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用 Chrome 浏览器浏览网页时遇到网络问题，例如页面加载缓慢或请求失败，并且开发者怀疑问题可能与 HTTP/2 的双向流实现有关。以下是可能到达 `bidirectional_stream_spdy_impl_unittest.cc` 的步骤：

1. **开发者工具检查:** 开发者打开 Chrome 的开发者工具 (通常按 F12)。
2. **Network 面板:**  切换到 Network 面板，查看网络请求的详细信息。
3. **协议分析:**  检查请求的 "Protocol" 列，确认连接是否使用了 "h2" (HTTP/2)。
4. **问题复现:** 尝试复现导致问题的用户操作，并观察 Network 面板中的请求行为。
5. **怀疑 SPDY 实现:** 如果怀疑问题与 HTTP/2 的特定行为有关，例如流的建立、数据传输或错误处理，开发者可能会开始查看 Chromium 的网络栈源代码。
6. **源码定位:**  开发者可能会根据关键词搜索，例如 "BidirectionalStream", "SPDY", "HTTP2 Stream"。
7. **查找测试用例:** 开发者可能会先找到 `bidirectional_stream_spdy_impl_unittest.cc` 文件，因为单元测试通常提供了对特定功能最直接的验证方式。
8. **分析测试用例:**  开发者会阅读测试用例，了解 `BidirectionalStreamSpdyImpl` 的预期行为以及如何使用它。例如，如果开发者遇到了在流失败后发送数据的问题，他们可能会找到 `SendDataAfterStreamFailed` 这个测试用例，从而理解 Chromium 的实现方式。
9. **设置断点和调试:**  如果需要更深入的了解，开发者可能会在 `BidirectionalStreamSpdyImpl` 的源代码中设置断点，并尝试复现问题，以便跟踪代码的执行流程。他们也可能修改单元测试，添加新的测试用例来验证他们假设的场景。

总而言之，`bidirectional_stream_spdy_impl_unittest.cc` 是理解和调试 Chromium 网络栈中 SPDY 双向流实现的关键入口点之一。它通过一系列精心设计的测试用例，展示了该类的功能、边界情况和错误处理逻辑，为开发者提供了宝贵的参考。

Prompt: 
```
这是目录为net/spdy/bidirectional_stream_spdy_impl_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/spdy/bidirectional_stream_spdy_impl.h"

#include <string>
#include <string_view>

#include "base/containers/span.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/time/time.h"
#include "base/timer/mock_timer.h"
#include "base/timer/timer.h"
#include "net/base/load_timing_info.h"
#include "net/base/load_timing_info_test_util.h"
#include "net/base/net_errors.h"
#include "net/base/session_usage.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/log/net_log.h"
#include "net/socket/socket_tag.h"
#include "net/socket/socket_test_util.h"
#include "net/spdy/spdy_session.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

const char kBodyData[] = "Body data";
const size_t kBodyDataSize = std::size(kBodyData);
// Size of the buffer to be allocated for each read.
const size_t kReadBufferSize = 4096;

// Tests the load timing of a stream that's connected and is not the first
// request sent on a connection.
void TestLoadTimingReused(const LoadTimingInfo& load_timing_info) {
  EXPECT_TRUE(load_timing_info.socket_reused);
  EXPECT_NE(NetLogSource::kInvalidId, load_timing_info.socket_log_id);

  ExpectConnectTimingHasNoTimes(load_timing_info.connect_timing);
  ExpectLoadTimingHasOnlyConnectionTimes(load_timing_info);
}

// Tests the load timing of a stream that's connected and using a fresh
// connection.
void TestLoadTimingNotReused(const LoadTimingInfo& load_timing_info) {
  EXPECT_FALSE(load_timing_info.socket_reused);
  EXPECT_NE(NetLogSource::kInvalidId, load_timing_info.socket_log_id);

  ExpectConnectTimingHasTimes(
      load_timing_info.connect_timing,
      CONNECT_TIMING_HAS_SSL_TIMES | CONNECT_TIMING_HAS_DNS_TIMES);
  ExpectLoadTimingHasOnlyConnectionTimes(load_timing_info);
}

class TestDelegateBase : public BidirectionalStreamImpl::Delegate {
 public:
  TestDelegateBase(base::WeakPtr<SpdySession> session,
                   IOBuffer* read_buf,
                   int read_buf_len)
      : stream_(std::make_unique<BidirectionalStreamSpdyImpl>(session,
                                                              NetLogSource())),
        read_buf_(read_buf),
        read_buf_len_(read_buf_len) {}

  TestDelegateBase(const TestDelegateBase&) = delete;
  TestDelegateBase& operator=(const TestDelegateBase&) = delete;

  ~TestDelegateBase() override = default;

  void OnStreamReady(bool request_headers_sent) override {
    CHECK(!on_failed_called_);
  }

  void OnHeadersReceived(
      const quiche::HttpHeaderBlock& response_headers) override {
    CHECK(!on_failed_called_);
    CHECK(!not_expect_callback_);
    response_headers_ = response_headers.Clone();
    if (!do_not_start_read_)
      StartOrContinueReading();
  }

  void OnDataRead(int bytes_read) override {
    CHECK(!on_failed_called_);
    CHECK(!not_expect_callback_);
    on_data_read_count_++;
    CHECK_GE(bytes_read, OK);
    bytes_read_ += bytes_read;
    data_received_.append(read_buf_->data(), bytes_read);
    if (!do_not_start_read_)
      StartOrContinueReading();
  }

  void OnDataSent() override {
    CHECK(!on_failed_called_);
    CHECK(!not_expect_callback_);
    on_data_sent_count_++;
  }

  void OnTrailersReceived(const quiche::HttpHeaderBlock& trailers) override {
    CHECK(!on_failed_called_);
    trailers_ = trailers.Clone();
    if (run_until_completion_)
      loop_->Quit();
  }

  void OnFailed(int error) override {
    CHECK(!on_failed_called_);
    CHECK(!not_expect_callback_);
    CHECK_NE(OK, error);
    error_ = error;
    on_failed_called_ = true;
    if (run_until_completion_)
      loop_->Quit();
  }

  void Start(const BidirectionalStreamRequestInfo* request,
             const NetLogWithSource& net_log) {
    stream_->Start(request, net_log,
                   /*send_request_headers_automatically=*/false, this,
                   std::make_unique<base::OneShotTimer>(),
                   TRAFFIC_ANNOTATION_FOR_TESTS);
    not_expect_callback_ = false;
  }

  void SendData(IOBuffer* data, int length, bool end_of_stream) {
    SendvData({data}, {length}, end_of_stream);
  }

  void SendvData(const std::vector<scoped_refptr<IOBuffer>>& data,
                 const std::vector<int>& length,
                 bool end_of_stream) {
    not_expect_callback_ = true;
    stream_->SendvData(data, length, end_of_stream);
    not_expect_callback_ = false;
  }

  // Sets whether the delegate should wait until the completion of the stream.
  void SetRunUntilCompletion(bool run_until_completion) {
    run_until_completion_ = run_until_completion;
    loop_ = std::make_unique<base::RunLoop>();
  }

  // Wait until the stream reaches completion.
  void WaitUntilCompletion() { loop_->Run(); }

  // Starts or continues read data from |stream_| until there is no more
  // byte can be read synchronously.
  void StartOrContinueReading() {
    int rv = ReadData();
    while (rv > 0) {
      rv = ReadData();
    }
    if (run_until_completion_ && rv == 0)
      loop_->Quit();
  }

  // Calls ReadData on the |stream_| and updates internal states.
  int ReadData() {
    int rv = stream_->ReadData(read_buf_.get(), read_buf_len_);
    if (rv > 0) {
      data_received_.append(read_buf_->data(), rv);
      bytes_read_ += rv;
    }
    return rv;
  }

  NextProto GetProtocol() const { return stream_->GetProtocol(); }

  int64_t GetTotalReceivedBytes() const {
      return stream_->GetTotalReceivedBytes();
  }

  int64_t GetTotalSentBytes() const {
      return stream_->GetTotalSentBytes();
  }

  bool GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const {
    return stream_->GetLoadTimingInfo(load_timing_info);
  }

  // Const getters for internal states.
  const std::string& data_received() const { return data_received_; }
  int bytes_read() const { return bytes_read_; }
  int error() const { return error_; }
  const quiche::HttpHeaderBlock& response_headers() const {
    return response_headers_;
  }
  const quiche::HttpHeaderBlock& trailers() const { return trailers_; }
  int on_data_read_count() const { return on_data_read_count_; }
  int on_data_sent_count() const { return on_data_sent_count_; }
  bool on_failed_called() const { return on_failed_called_; }

  // Sets whether the delegate should automatically start reading.
  void set_do_not_start_read(bool do_not_start_read) {
    do_not_start_read_ = do_not_start_read;
  }

 private:
  std::unique_ptr<BidirectionalStreamSpdyImpl> stream_;
  scoped_refptr<IOBuffer> read_buf_;
  int read_buf_len_;
  std::string data_received_;
  std::unique_ptr<base::RunLoop> loop_;
  quiche::HttpHeaderBlock response_headers_;
  quiche::HttpHeaderBlock trailers_;
  int error_ = OK;
  int bytes_read_ = 0;
  int on_data_read_count_ = 0;
  int on_data_sent_count_ = 0;
  bool do_not_start_read_ = false;
  bool run_until_completion_ = false;
  bool not_expect_callback_ = false;
  bool on_failed_called_ = false;
};

}  // namespace

class BidirectionalStreamSpdyImplTest : public testing::TestWithParam<bool>,
                                        public WithTaskEnvironment {
 public:
  BidirectionalStreamSpdyImplTest()
      : default_url_(kDefaultUrl),
        host_port_pair_(HostPortPair::FromURL(default_url_)),
        key_(host_port_pair_,
             PRIVACY_MODE_DISABLED,
             ProxyChain::Direct(),
             SessionUsage::kDestination,
             SocketTag(),
             NetworkAnonymizationKey(),
             SecureDnsPolicy::kAllow,
             /*disable_cert_verification_network_fetches=*/false),
        ssl_data_(SSLSocketDataProvider(ASYNC, OK)) {
    ssl_data_.next_proto = kProtoHTTP2;
    ssl_data_.ssl_info.cert =
        ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");
  }

  bool IsBrokenConnectionDetectionEnabled() const {
    if (!session_)
      return false;

    return session_->IsBrokenConnectionDetectionEnabled();
  }

 protected:
  void TearDown() override {
    if (sequenced_data_) {
      EXPECT_TRUE(sequenced_data_->AllReadDataConsumed());
      EXPECT_TRUE(sequenced_data_->AllWriteDataConsumed());
    }
  }

  // Initializes the session using SequencedSocketData.
  void InitSession(base::span<const MockRead> reads,
                   base::span<const MockWrite> writes) {
    ASSERT_TRUE(ssl_data_.ssl_info.cert.get());
    session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data_);
    sequenced_data_ = std::make_unique<SequencedSocketData>(reads, writes);
    session_deps_.socket_factory->AddSocketDataProvider(sequenced_data_.get());
    session_deps_.net_log = NetLog::Get();
    http_session_ = SpdySessionDependencies::SpdyCreateSession(&session_deps_);
    session_ =
        CreateSpdySession(http_session_.get(), key_, net_log_with_source_);
  }

  NetLogWithSource net_log_with_source_{
      NetLogWithSource::Make(NetLogSourceType::NONE)};
  SpdyTestUtil spdy_util_;
  SpdySessionDependencies session_deps_;
  const GURL default_url_;
  const HostPortPair host_port_pair_;
  const SpdySessionKey key_;
  std::unique_ptr<SequencedSocketData> sequenced_data_;
  std::unique_ptr<HttpNetworkSession> http_session_;
  base::WeakPtr<SpdySession> session_;

 private:
  SSLSocketDataProvider ssl_data_;
};

TEST_F(BidirectionalStreamSpdyImplTest, SimplePostRequest) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize, LOW, nullptr, 0));
  spdy::SpdySerializedFrame data_frame(spdy_util_.ConstructSpdyDataFrame(
      1, std::string_view(kBodyData, kBodyDataSize), /*fin=*/true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(data_frame, 3),
  };
  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  spdy::SpdySerializedFrame response_body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, /*fin=*/true));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause.
      CreateMockRead(response_body_frame, 4), MockRead(ASYNC, 0, 5),
  };
  InitSession(reads, writes);

  BidirectionalStreamRequestInfo request_info;
  request_info.method = "POST";
  request_info.url = default_url_;
  request_info.extra_headers.SetHeader(net::HttpRequestHeaders::kContentLength,
                                       base::NumberToString(kBodyDataSize));

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate = std::make_unique<TestDelegateBase>(
      session_, read_buffer.get(), kReadBufferSize);
  delegate->SetRunUntilCompletion(true);
  delegate->Start(&request_info, net_log_with_source_);
  sequenced_data_->RunUntilPaused();

  scoped_refptr<StringIOBuffer> write_buffer =
      base::MakeRefCounted<StringIOBuffer>(
          std::string(kBodyData, kBodyDataSize));
  delegate->SendData(write_buffer.get(), write_buffer->size(), true);
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();
  delegate->WaitUntilCompletion();
  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(delegate->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info);

  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(1, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ(CountWriteBytes(writes), delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamSpdyImplTest, LoadTimingTwoRequests) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, /*stream_id=*/1, LOW));
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, /*stream_id=*/3, LOW));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(req2, 2),
  };
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, /*stream_id=*/1));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, /*stream_id=*/3));
  spdy::SpdySerializedFrame resp_body(
      spdy_util_.ConstructSpdyDataFrame(/*stream_id=*/1, /*fin=*/true));
  spdy::SpdySerializedFrame resp_body2(
      spdy_util_.ConstructSpdyDataFrame(/*stream_id=*/3, /*fin=*/true));
  MockRead reads[] = {CreateMockRead(resp, 1), CreateMockRead(resp_body, 3),
                      CreateMockRead(resp2, 4), CreateMockRead(resp_body2, 5),
                      MockRead(ASYNC, 0, 6)};
  InitSession(reads, writes);

  BidirectionalStreamRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = default_url_;
  request_info.end_stream_on_headers = true;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto read_buffer2 = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate = std::make_unique<TestDelegateBase>(
      session_, read_buffer.get(), kReadBufferSize);
  auto delegate2 = std::make_unique<TestDelegateBase>(
      session_, read_buffer2.get(), kReadBufferSize);
  delegate->SetRunUntilCompletion(true);
  delegate2->SetRunUntilCompletion(true);
  delegate->Start(&request_info, net_log_with_source_);
  delegate2->Start(&request_info, net_log_with_source_);

  base::RunLoop().RunUntilIdle();
  delegate->WaitUntilCompletion();
  delegate2->WaitUntilCompletion();
  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(delegate->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info);
  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(delegate2->GetLoadTimingInfo(&load_timing_info2));
  TestLoadTimingReused(load_timing_info2);
}

TEST_F(BidirectionalStreamSpdyImplTest, SendDataAfterStreamFailed) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize * 3, LOW, nullptr, 0));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_PROTOCOL_ERROR));

  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 2),
  };

  const char* const kExtraHeaders[] = {"X-UpperCase", "yes"};
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(kExtraHeaders, 1, 1));

  MockRead reads[] = {
      CreateMockRead(resp, 1), MockRead(ASYNC, 0, 3),
  };

  InitSession(reads, writes);

  BidirectionalStreamRequestInfo request_info;
  request_info.method = "POST";
  request_info.url = default_url_;
  request_info.extra_headers.SetHeader(net::HttpRequestHeaders::kContentLength,
                                       base::NumberToString(kBodyDataSize * 3));

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate = std::make_unique<TestDelegateBase>(
      session_, read_buffer.get(), kReadBufferSize);
  delegate->SetRunUntilCompletion(true);
  delegate->Start(&request_info, net_log_with_source_);
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(delegate->on_failed_called());

  // Try to send data after OnFailed(), should not get called back.
  scoped_refptr<StringIOBuffer> buf =
      base::MakeRefCounted<StringIOBuffer>("dummy");
  delegate->SendData(buf.get(), buf->size(), false);
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(delegate->error(), IsError(ERR_HTTP2_PROTOCOL_ERROR));
  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  // BidirectionalStreamSpdyStreamJob does not count the bytes sent for |rst|
  // because it is sent after SpdyStream::Delegate::OnClose is called.
  EXPECT_EQ(CountWriteBytes(base::make_span(writes, 1u)),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(0, delegate->GetTotalReceivedBytes());
}

INSTANTIATE_TEST_SUITE_P(BidirectionalStreamSpdyImplTests,
                         BidirectionalStreamSpdyImplTest,
                         ::testing::Bool());

// Tests that when received RST_STREAM with NO_ERROR, BidirectionalStream does
// not crash when processing pending writes. See crbug.com/650438.
TEST_P(BidirectionalStreamSpdyImplTest, RstWithNoErrorBeforeSendIsComplete) {
  bool is_test_sendv = GetParam();
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize * 3, LOW, nullptr, 0));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_NO_ERROR));
  MockRead reads[] = {CreateMockRead(resp, 1),
                      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause.
                      CreateMockRead(rst, 3), MockRead(ASYNC, 0, 4)};

  InitSession(reads, writes);

  BidirectionalStreamRequestInfo request_info;
  request_info.method = "POST";
  request_info.url = default_url_;
  request_info.extra_headers.SetHeader(net::HttpRequestHeaders::kContentLength,
                                       base::NumberToString(kBodyDataSize * 3));

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate = std::make_unique<TestDelegateBase>(
      session_, read_buffer.get(), kReadBufferSize);
  delegate->SetRunUntilCompletion(true);
  delegate->Start(&request_info, net_log_with_source_);
  sequenced_data_->RunUntilPaused();
  // Make a write pending before receiving RST_STREAM.
  scoped_refptr<StringIOBuffer> write_buffer =
      base::MakeRefCounted<StringIOBuffer>(
          std::string(kBodyData, kBodyDataSize));
  delegate->SendData(write_buffer.get(), write_buffer->size(), false);
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();

  // Make sure OnClose() without an error completes any pending write().
  EXPECT_EQ(1, delegate->on_data_sent_count());
  EXPECT_FALSE(delegate->on_failed_called());

  if (is_test_sendv) {
    std::vector<scoped_refptr<IOBuffer>> three_buffers = {
        write_buffer.get(), write_buffer.get(), write_buffer.get()};
    std::vector<int> three_lengths = {
        write_buffer->size(), write_buffer->size(), write_buffer->size()};
    delegate->SendvData(three_buffers, three_lengths, /*end_of_stream=*/true);
    base::RunLoop().RunUntilIdle();
  } else {
    for (size_t j = 0; j < 3; j++) {
      delegate->SendData(write_buffer.get(), write_buffer->size(),
                         /*end_of_stream=*/j == 2);
      base::RunLoop().RunUntilIdle();
    }
  }
  delegate->WaitUntilCompletion();
  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(delegate->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info);

  EXPECT_THAT(delegate->error(), IsError(OK));
  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(is_test_sendv ? 2 : 4, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ(CountWriteBytes(base::make_span(writes, 1u)),
            delegate->GetTotalSentBytes());
  // Should not count RST stream.
  EXPECT_EQ(CountReadBytes(base::make_span(reads).first(std::size(reads) - 2)),
            delegate->GetTotalReceivedBytes());

  // Now call SendData again should produce an error because end of stream
  // flag has been written.
  if (is_test_sendv) {
    std::vector<scoped_refptr<IOBuffer>> buffer = {write_buffer.get()};
    std::vector<int> buffer_size = {write_buffer->size()};
    delegate->SendvData(buffer, buffer_size, true);
  } else {
    delegate->SendData(write_buffer.get(), write_buffer->size(), true);
  }
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(delegate->error(), IsError(ERR_UNEXPECTED));
  EXPECT_TRUE(delegate->on_failed_called());
  EXPECT_EQ(is_test_sendv ? 2 : 4, delegate->on_data_sent_count());
}

TEST_F(BidirectionalStreamSpdyImplTest, RequestDetectBrokenConnection) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize, LOW, nullptr, 0));
  spdy::SpdySerializedFrame data_frame(spdy_util_.ConstructSpdyDataFrame(
      1, std::string_view(kBodyData, kBodyDataSize), /*fin=*/true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
      CreateMockWrite(data_frame, 3),
  };
  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  spdy::SpdySerializedFrame response_body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, /*fin=*/true));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause.
      CreateMockRead(response_body_frame, 4),
      MockRead(ASYNC, 0, 5),
  };
  InitSession(reads, writes);
  EXPECT_FALSE(IsBrokenConnectionDetectionEnabled());

  BidirectionalStreamRequestInfo request_info;
  request_info.method = "POST";
  request_info.url = default_url_;
  request_info.extra_headers.SetHeader(net::HttpRequestHeaders::kContentLength,
                                       base::NumberToString(kBodyDataSize));
  request_info.detect_broken_connection = true;
  request_info.heartbeat_interval = base::Seconds(1);

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate = std::make_unique<TestDelegateBase>(
      session_, read_buffer.get(), kReadBufferSize);
  delegate->SetRunUntilCompletion(true);
  delegate->Start(&request_info, net_log_with_source_);
  sequenced_data_->RunUntilPaused();

  // Since we set request_info.detect_broken_connection to true, this should be
  // enabled for the bidi stream lifetime.
  EXPECT_TRUE(IsBrokenConnectionDetectionEnabled());

  scoped_refptr<StringIOBuffer> write_buffer =
      base::MakeRefCounted<StringIOBuffer>(
          std::string(kBodyData, kBodyDataSize));
  delegate->SendData(write_buffer.get(), write_buffer->size(), true);
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();
  delegate->WaitUntilCompletion();
  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(delegate->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info);

  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(1, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ(CountWriteBytes(writes), delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), delegate->GetTotalReceivedBytes());

  delegate.reset();
  // Once the bidi stream has been destroyed this should go back to being
  // disabled.
  EXPECT_FALSE(IsBrokenConnectionDetectionEnabled());
}

}  // namespace net

"""

```