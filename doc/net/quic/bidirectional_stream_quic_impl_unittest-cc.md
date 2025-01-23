Response:
The user wants a summary of the provided C++ unit test file for Chromium's network stack. The file is named `bidirectional_stream_quic_impl_unittest.cc` and is located in the `net/quic` directory.

Here's a breakdown of the request and how to address each point:

1. **List its functions:**  This requires analyzing the code for the main purpose of the file. Unit tests are designed to verify the functionality of a specific class or component. The file name suggests it's testing `BidirectionalStreamQuicImpl`.

2. **Relationship to JavaScript:**  Consider how bidirectional streams and QUIC are used in web browsers, which often involves JavaScript. Think about APIs like `fetch()` or WebSockets over HTTP/3.

3. **Logical reasoning (input/output):** Since it's a *unit test*, the "logic" being tested is within `BidirectionalStreamQuicImpl`. The tests will simulate various inputs (requests, data, errors) and verify the outputs (callbacks, internal state changes). Examples need to be related to the class being tested.

4. **Common user/programming errors:** Identify potential mistakes developers might make when using or implementing bidirectional streams with QUIC.

5. **User operation to reach this code (debugging):** Think about the steps a user might take in a browser that would lead to the execution of this QUIC stream code.

6. **Summarize its function (for part 1):** This is the main goal for this part of the request.

**Mental Sandbox Simulation:**

* **Scanning the code:** The `#include` directives reveal the dependencies and hint at the functionality being tested. We see includes related to QUIC, bidirectional streams, HTTP, and testing frameworks. The presence of `Mock` classes is a strong indicator of unit testing.
* **Identifying the target class:** The file name and the inclusion of `"net/quic/bidirectional_stream_quic_impl.h"` clearly indicate that `BidirectionalStreamQuicImpl` is the class under test.
* **Test structure:** The code defines test fixture `BidirectionalStreamQuicImplTest` which inherits from `::testing::TestWithParam`. This suggests parameterization to test different QUIC versions. Helper classes like `TestDelegateBase` and `DeleteStreamDelegate` are used to observe the behavior of `BidirectionalStreamQuicImpl`.
* **Core testing scenarios:** The test case `GetRequest` simulates a basic GET request. The code sets up mock network interactions (using `MockWrite`) and then creates and interacts with a `BidirectionalStreamQuicImpl` instance.

**High-Level Plan:**

1. State that the file contains unit tests for `BidirectionalStreamQuicImpl`.
2. Explain the general purpose of these tests.
3. Briefly touch upon the role of mock objects in the tests.
4. Mention the parameterized testing for different QUIC versions.
这是一个名为 `bidirectional_stream_quic_impl_unittest.cc` 的 C++ 源代码文件，属于 Chromium 网络栈的 `net/quic` 目录。 从文件名来看，它的主要功能是 **测试 `BidirectionalStreamQuicImpl` 类的实现**。

更具体地说，这个文件包含了一系列单元测试，用于验证 `BidirectionalStreamQuicImpl` 类的各种行为和功能，例如：

* **启动和管理 QUIC 双向流:**  测试如何创建、启动和关闭双向流。
* **发送和接收数据:**  验证数据在流上的正确发送和接收，包括不同大小的数据块和流的结束标记（FIN）。
* **处理请求头和响应头:**  测试请求头和响应头的发送和接收，以及与 HTTP 语义的交互。
* **处理 trailers (尾部):** 验证 HTTP trailers 的发送和接收。
* **处理错误情况:**  测试各种错误场景，例如连接断开、流被重置等。
* **与 QUIC 会话的交互:**  验证 `BidirectionalStreamQuicImpl` 如何与底层的 `QuicChromiumClientSession` 进行交互。
* **异步操作:**  测试涉及异步操作（例如读取和写入）的回调机制。
* **NetLog 集成:**  验证是否正确记录了网络事件。
* **LoadTimingInfo 的获取:**  测试是否能够正确获取加载时间信息。
* **在不同的生命周期阶段删除流:** 测试在不同的回调阶段删除流是否会导致问题。

**与 JavaScript 的关系：**

`BidirectionalStreamQuicImpl` 本身是 C++ 代码，直接与 JavaScript 没有直接的语法关系。然而，它在 Chromium 中扮演着关键的角色，支持浏览器中通过 QUIC 协议建立的双向通信，而这种通信通常是 JavaScript 发起的。

**举例说明:**

1. **`fetch()` API:** 当 JavaScript 代码使用 `fetch()` API 发起一个使用了 HTTP/3 (QUIC) 的请求时，Chromium 的网络栈会使用 `BidirectionalStreamQuicImpl` 来管理这个底层的 QUIC 流。测试用例会模拟 JavaScript 发起请求，然后验证 `BidirectionalStreamQuicImpl` 是否正确发送请求头、处理响应数据等。

2. **WebSockets over HTTP/3:**  如果 WebSocket 连接建立在 HTTP/3 之上，`BidirectionalStreamQuicImpl` 也会被用于管理这个双向的 WebSocket 连接。测试会模拟 WebSocket 的数据传输，验证数据的可靠性和顺序性。

**逻辑推理、假设输入与输出：**

由于这是单元测试，每个测试用例都针对特定的逻辑单元。以下是一个简化的例子：

**假设输入:**

* **模拟网络层发送一个包含 HTTP 响应头的数据包到 `BidirectionalStreamQuicImpl`。**
* **响应头包含状态码 "200 OK" 和一些自定义的 Header。**

**测试的 `BidirectionalStreamQuicImpl` 组件的逻辑:**

* **解析收到的 QUIC 数据包。**
* **提取 HTTP 响应头信息。**
* **调用其 `Delegate` 的 `OnHeadersReceived` 方法，将解析后的响应头传递给 Delegate。**

**预期输出:**

* **在测试代码中设置的 `TestDelegateBase` 实例的 `OnHeadersReceived` 方法会被调用。**
* **`TestDelegateBase` 内部存储的 `response_headers_` 成员变量会包含收到的状态码 "200 OK" 和自定义的 Header。**

**用户或编程常见的使用错误：**

1. **在未调用 `Start()` 之前尝试发送数据:**  如果用户（这里的“用户”指的是使用 `BidirectionalStreamQuicImpl` 的代码）在 `BidirectionalStreamQuicImpl` 对象初始化后，但在调用 `Start()` 方法之前就尝试使用 `SendData()` 或 `SendvData()` 发送数据，会导致错误。测试用例可能会验证这种情况是否会导致断言失败或特定的错误回调。

2. **错误地处理异步回调:**  QUIC 操作通常是异步的。开发者可能会错误地阻塞主线程等待回调，或者在回调未完成时就访问流的状态。测试用例会通过模拟异步操作和检查回调的顺序和参数来发现这类错误。

3. **在流的生命周期结束后尝试操作:**  一旦流结束（例如，接收到 FIN 或 RST_STREAM），继续尝试发送或接收数据是不允许的。测试用例会模拟流的结束并验证后续的操作是否被正确拒绝。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入一个 HTTPS 网址并回车。**
2. **浏览器开始解析 URL 并查找对应的 IP 地址。**
3. **如果服务器支持 HTTP/3，并且客户端也启用了 HTTP/3，浏览器会尝试与服务器建立 QUIC 连接。**
4. **QUIC 连接建立成功后，浏览器会创建一个 `BidirectionalStreamQuicImpl` 实例来发起 HTTP 请求。**
5. **`BidirectionalStreamQuicImpl` 会将 HTTP 请求头转换为 QUIC 数据帧并通过底层的 QUIC 会话发送出去。**
6. **服务器响应后，`BidirectionalStreamQuicImpl` 会接收并解析响应头和数据。**
7. **如果出现网络问题、服务器错误或协议错误，可能会触发 `BidirectionalStreamQuicImpl` 中的错误处理逻辑，这正是单元测试要覆盖的场景。**

在调试过程中，如果怀疑与 QUIC 流相关的行为有误，开发者可能会：

* **查看 NetLog:** Chromium 的 NetLog 会记录详细的网络事件，包括 QUIC 连接和流的创建、数据传输、错误信息等。
* **使用 Wireshark 或其他网络抓包工具:**  分析实际的网络数据包，检查 QUIC 协议的细节。
* **运行单元测试:** 针对 `BidirectionalStreamQuicImpl` 的单元测试可以帮助隔离问题，验证特定功能的正确性。开发者可以运行这些测试，观察是否与预期行为一致。
* **设置断点:** 在 `BidirectionalStreamQuicImpl` 的代码中设置断点，逐步跟踪代码执行，查看变量的值和调用堆栈。

**归纳一下它的功能 (第 1 部分):**

作为第 1 部分，目前的代码主要定义了 **基础的测试框架和辅助类**，用于测试 `BidirectionalStreamQuicImpl`。  这包括：

* **引入必要的头文件:**  包含了 `BidirectionalStreamQuicImpl.h` 以及各种 QUIC 相关的类和测试工具。
* **定义枚举 `DelegateMethod`:**  用于标识 `BidirectionalStreamImpl::Delegate` 中的不同回调方法，方便测试用例的编写和断言。
* **定义基类 `TestDelegateBase`:**  实现了一个 `BidirectionalStreamImpl::Delegate` 的基础版本，用于捕获和验证回调，并提供了一些辅助方法来控制测试流程，例如启动流、发送数据、等待回调等。这个基类极大地简化了编写测试用例的过程。
* **定义派生类 `DeleteStreamDelegate`:**  继承自 `TestDelegateBase`，用于测试在 `Delegate` 的不同回调阶段删除 `BidirectionalStreamQuicImpl` 对象的情况，以验证资源管理的正确性。
* **定义测试固件 `BidirectionalStreamQuicImplTest`:**  这是一个使用 gtest 框架定义的测试类，用于组织和执行针对 `BidirectionalStreamQuicImpl` 的测试用例。它包含了初始化 QUIC 会话、创建数据包、模拟网络行为等辅助方法，为编写具体的测试用例提供了基础环境。
* **实例化测试套件:** 使用 `INSTANTIATE_TEST_SUITE_P` 宏来针对所有支持的 QUIC 版本运行测试。
* **第一个测试用例 `GetRequest` 的开始:**  展示了一个基本的 GET 请求的测试用例框架，但代码尚未完成。

总而言之，第 1 部分的核心是搭建测试环境和提供通用的测试工具，为后续编写更具体的 `BidirectionalStreamQuicImpl` 功能测试用例做准备。

### 提示词
```
这是目录为net/quic/bidirectional_stream_quic_impl_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/quic/bidirectional_stream_quic_impl.h"

#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/default_tick_clock.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "net/base/completion_once_callback.h"
#include "net/base/connection_endpoint_metadata.h"
#include "net/base/ip_address.h"
#include "net/base/load_timing_info.h"
#include "net/base/load_timing_info_test_util.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/privacy_mode.h"
#include "net/base/proxy_chain.h"
#include "net/base/session_usage.h"
#include "net/dns/public/host_resolver_results.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/bidirectional_stream_request_info.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/quic/address_utils.h"
#include "net/quic/mock_crypto_client_stream_factory.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/quic/quic_chromium_packet_reader.h"
#include "net/quic/quic_chromium_packet_writer.h"
#include "net/quic/quic_context.h"
#include "net/quic/quic_crypto_client_config_handle.h"
#include "net/quic/quic_http_utils.h"
#include "net/quic/quic_server_info.h"
#include "net/quic/quic_session_alias_key.h"
#include "net/quic/quic_session_key.h"
#include "net/quic/quic_session_pool.h"
#include "net/quic/quic_test_packet_maker.h"
#include "net/quic/quic_test_packet_printer.h"
#include "net/quic/test_quic_crypto_client_config_handle.h"
#include "net/quic/test_task_runner.h"
#include "net/socket/socket_test_util.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/third_party/quiche/src/quiche/common/quiche_text_utils.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/crypto_protocol.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/quic_decrypter.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/quic_encrypter.h"
#include "net/third_party/quiche/src/quiche/quic/core/http/spdy_utils.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_connection.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/crypto_test_utils.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/mock_clock.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/mock_connection_id_generator.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/mock_random.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/qpack/qpack_test_utils.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_connection_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_session_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_spdy_session_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_test_utils.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

namespace net::test {

namespace {

const char kUploadData[] = "Really nifty data!";
const char kDefaultServerHostName[] = "www.google.com";
const uint16_t kDefaultServerPort = 80;
// Size of the buffer to be allocated for each read.
const size_t kReadBufferSize = 4096;

enum DelegateMethod {
  kOnStreamReady,
  kOnHeadersReceived,
  kOnTrailersReceived,
  kOnDataRead,
  kOnDataSent,
  kOnFailed
};

class TestDelegateBase : public BidirectionalStreamImpl::Delegate {
 public:
  TestDelegateBase(IOBuffer* read_buf, int read_buf_len)
      : TestDelegateBase(read_buf,
                         read_buf_len,
                         std::make_unique<base::OneShotTimer>()) {}

  TestDelegateBase(IOBuffer* read_buf,
                   int read_buf_len,
                   std::unique_ptr<base::OneShotTimer> timer)
      : read_buf_(read_buf),
        read_buf_len_(read_buf_len),
        timer_(std::move(timer)) {
    loop_ = std::make_unique<base::RunLoop>();
  }

  TestDelegateBase(const TestDelegateBase&) = delete;
  TestDelegateBase& operator=(const TestDelegateBase&) = delete;

  ~TestDelegateBase() override = default;

  void OnStreamReady(bool request_headers_sent) override {
    CHECK(!is_ready_);
    CHECK(!on_failed_called_);
    EXPECT_EQ(send_request_headers_automatically_, request_headers_sent);
    CHECK(!not_expect_callback_);
    is_ready_ = true;
    loop_->Quit();
  }

  void OnHeadersReceived(
      const quiche::HttpHeaderBlock& response_headers) override {
    CHECK(!on_failed_called_);
    CHECK(!not_expect_callback_);

    response_headers_ = response_headers.Clone();
    loop_->Quit();
  }

  void OnDataRead(int bytes_read) override {
    CHECK(!on_failed_called_);
    CHECK(!not_expect_callback_);
    CHECK(!callback_.is_null());

    // If read EOF, make sure this callback is after trailers callback.
    if (bytes_read == 0) {
      EXPECT_TRUE(!trailers_expected_ || trailers_received_);
    }
    ++on_data_read_count_;
    CHECK_GE(bytes_read, OK);
    data_received_.append(read_buf_->data(), bytes_read);
    std::move(callback_).Run(bytes_read);
  }

  void OnDataSent() override {
    CHECK(!on_failed_called_);
    CHECK(!not_expect_callback_);

    ++on_data_sent_count_;
    loop_->Quit();
  }

  void OnTrailersReceived(const quiche::HttpHeaderBlock& trailers) override {
    CHECK(!on_failed_called_);
    CHECK(!not_expect_callback_);

    trailers_received_ = true;
    trailers_ = trailers.Clone();
    loop_->Quit();
  }

  void OnFailed(int error) override {
    CHECK(!on_failed_called_);
    CHECK(!not_expect_callback_);
    CHECK_EQ(OK, error_);
    CHECK_NE(OK, error);

    on_failed_called_ = true;
    error_ = error;
    loop_->Quit();
  }

  void Start(const BidirectionalStreamRequestInfo* request_info,
             const NetLogWithSource& net_log,
             std::unique_ptr<QuicChromiumClientSession::Handle> session) {
    not_expect_callback_ = true;
    stream_ = std::make_unique<BidirectionalStreamQuicImpl>(std::move(session));
    stream_->Start(request_info, net_log, send_request_headers_automatically_,
                   this, nullptr, TRAFFIC_ANNOTATION_FOR_TESTS);
    not_expect_callback_ = false;
  }

  void SendRequestHeaders() {
    not_expect_callback_ = true;
    stream_->SendRequestHeaders();
    not_expect_callback_ = false;
  }

  void SendData(const scoped_refptr<IOBuffer>& data,
                int length,
                bool end_of_stream) {
    SendvData({data}, {length}, end_of_stream);
  }

  void SendvData(const std::vector<scoped_refptr<IOBuffer>>& data,
                 const std::vector<int>& lengths,
                 bool end_of_stream) {
    not_expect_callback_ = true;
    stream_->SendvData(data, lengths, end_of_stream);
    not_expect_callback_ = false;
  }

  // Waits until next Delegate callback.
  void WaitUntilNextCallback(DelegateMethod method) {
    ASSERT_FALSE(on_failed_called_);
    bool is_ready = is_ready_;
    bool headers_received = !response_headers_.empty();
    bool trailers_received = trailers_received_;
    int on_data_read_count = on_data_read_count_;
    int on_data_sent_count = on_data_sent_count_;

    loop_->Run();
    loop_ = std::make_unique<base::RunLoop>();

    EXPECT_EQ(method == kOnFailed, on_failed_called_);
    EXPECT_EQ(is_ready || (method == kOnStreamReady), is_ready_);
    EXPECT_EQ(headers_received || (method == kOnHeadersReceived),
              !response_headers_.empty());
    EXPECT_EQ(trailers_received || (method == kOnTrailersReceived),
              trailers_received_);
    EXPECT_EQ(on_data_read_count + (method == kOnDataRead ? 1 : 0),
              on_data_read_count_);
    EXPECT_EQ(on_data_sent_count + (method == kOnDataSent ? 1 : 0),
              on_data_sent_count_);
  }

  // Calls ReadData on the |stream_| and updates |data_received_|.
  int ReadData(CompletionOnceCallback callback) {
    not_expect_callback_ = true;
    int rv = stream_->ReadData(read_buf_.get(), read_buf_len_);
    not_expect_callback_ = false;
    if (rv > 0) {
      data_received_.append(read_buf_->data(), rv);
    }
    if (rv == ERR_IO_PENDING) {
      callback_ = std::move(callback);
    }
    return rv;
  }

  NextProto GetProtocol() const {
    if (stream_) {
      return stream_->GetProtocol();
    }
    return next_proto_;
  }

  int64_t GetTotalReceivedBytes() const {
    if (stream_) {
      return stream_->GetTotalReceivedBytes();
    }
    return received_bytes_;
  }

  int64_t GetTotalSentBytes() const {
    if (stream_) {
      return stream_->GetTotalSentBytes();
    }
    return sent_bytes_;
  }

  bool GetLoadTimingInfo(LoadTimingInfo* load_timing_info) {
    if (stream_) {
      return stream_->GetLoadTimingInfo(load_timing_info);
    }
    *load_timing_info = load_timing_info_;
    return has_load_timing_info_;
  }

  void DoNotSendRequestHeadersAutomatically() {
    send_request_headers_automatically_ = false;
  }

  // Deletes |stream_|.
  void DeleteStream() {
    next_proto_ = stream_->GetProtocol();
    received_bytes_ = stream_->GetTotalReceivedBytes();
    sent_bytes_ = stream_->GetTotalSentBytes();
    has_load_timing_info_ = stream_->GetLoadTimingInfo(&load_timing_info_);
    stream_.reset();
  }

  void set_trailers_expected(bool trailers_expected) {
    trailers_expected_ = trailers_expected;
  }
  // Const getters for internal states.
  const std::string& data_received() const { return data_received_; }
  int error() const { return error_; }
  const quiche::HttpHeaderBlock& response_headers() const {
    return response_headers_;
  }
  const quiche::HttpHeaderBlock& trailers() const { return trailers_; }
  int on_data_read_count() const { return on_data_read_count_; }
  int on_data_sent_count() const { return on_data_sent_count_; }
  bool on_failed_called() const { return on_failed_called_; }
  bool is_ready() const { return is_ready_; }

 protected:
  // Quits |loop_|.
  void QuitLoop() { loop_->Quit(); }

 private:
  std::unique_ptr<BidirectionalStreamQuicImpl> stream_;
  scoped_refptr<IOBuffer> read_buf_;
  int read_buf_len_;
  std::unique_ptr<base::OneShotTimer> timer_;
  std::string data_received_;
  std::unique_ptr<base::RunLoop> loop_;
  quiche::HttpHeaderBlock response_headers_;
  quiche::HttpHeaderBlock trailers_;
  NextProto next_proto_ = kProtoUnknown;
  int64_t received_bytes_ = 0;
  int64_t sent_bytes_ = 0;
  bool has_load_timing_info_ = false;
  LoadTimingInfo load_timing_info_;
  int error_ = OK;
  int on_data_read_count_ = 0;
  int on_data_sent_count_ = 0;
  // This is to ensure that delegate callback is not invoked synchronously when
  // calling into |stream_|.
  bool not_expect_callback_ = false;
  bool on_failed_called_ = false;
  CompletionOnceCallback callback_;
  bool send_request_headers_automatically_ = true;
  bool is_ready_ = false;
  bool trailers_expected_ = false;
  bool trailers_received_ = false;
};

// A delegate that deletes the stream in a particular callback.
class DeleteStreamDelegate : public TestDelegateBase {
 public:
  // Specifies in which callback the stream can be deleted.
  enum Phase {
    ON_STREAM_READY,
    ON_HEADERS_RECEIVED,
    ON_DATA_READ,
    ON_TRAILERS_RECEIVED,
    ON_FAILED,
  };

  DeleteStreamDelegate(IOBuffer* buf, int buf_len, Phase phase)
      : TestDelegateBase(buf, buf_len), phase_(phase) {}

  DeleteStreamDelegate(const DeleteStreamDelegate&) = delete;
  DeleteStreamDelegate& operator=(const DeleteStreamDelegate&) = delete;

  ~DeleteStreamDelegate() override = default;

  void OnStreamReady(bool request_headers_sent) override {
    TestDelegateBase::OnStreamReady(request_headers_sent);
    if (phase_ == ON_STREAM_READY) {
      DeleteStream();
    }
  }

  void OnHeadersReceived(
      const quiche::HttpHeaderBlock& response_headers) override {
    // Make a copy of |response_headers| before the stream is deleted, since
    // the headers are owned by the stream.
    quiche::HttpHeaderBlock headers_copy = response_headers.Clone();
    if (phase_ == ON_HEADERS_RECEIVED) {
      DeleteStream();
    }
    TestDelegateBase::OnHeadersReceived(headers_copy);
  }

  void OnDataSent() override { NOTREACHED(); }

  void OnDataRead(int bytes_read) override {
    DCHECK_NE(ON_HEADERS_RECEIVED, phase_);
    if (phase_ == ON_DATA_READ) {
      DeleteStream();
    }
    TestDelegateBase::OnDataRead(bytes_read);
  }

  void OnTrailersReceived(const quiche::HttpHeaderBlock& trailers) override {
    DCHECK_NE(ON_HEADERS_RECEIVED, phase_);
    DCHECK_NE(ON_DATA_READ, phase_);
    // Make a copy of |response_headers| before the stream is deleted, since
    // the headers are owned by the stream.
    quiche::HttpHeaderBlock trailers_copy = trailers.Clone();
    if (phase_ == ON_TRAILERS_RECEIVED) {
      DeleteStream();
    }
    TestDelegateBase::OnTrailersReceived(trailers_copy);
  }

  void OnFailed(int error) override {
    DCHECK_EQ(ON_FAILED, phase_);
    DeleteStream();
    TestDelegateBase::OnFailed(error);
  }

 private:
  // Indicates in which callback the delegate should cancel or delete the
  // stream.
  Phase phase_;
};

}  // namespace

class BidirectionalStreamQuicImplTest
    : public ::testing::TestWithParam<quic::ParsedQuicVersion>,
      public WithTaskEnvironment {
 protected:
  static const bool kFin = true;

  // Holds a packet to be written to the wire, and the IO mode that should
  // be used by the mock socket when performing the write.
  struct PacketToWrite {
    PacketToWrite(IoMode mode, quic::QuicReceivedPacket* packet)
        : mode(mode), packet(packet) {}
    PacketToWrite(IoMode mode, int rv) : mode(mode), packet(nullptr), rv(rv) {}
    IoMode mode;
    raw_ptr<quic::QuicReceivedPacket, DanglingUntriaged> packet;
    int rv;
  };

  BidirectionalStreamQuicImplTest()
      : version_(GetParam()),
        crypto_config_(
            quic::test::crypto_test_utils::ProofVerifierForTesting()),
        read_buffer_(base::MakeRefCounted<IOBufferWithSize>(4096)),
        connection_id_(quic::test::TestConnectionId(2)),
        stream_id_(GetNthClientInitiatedBidirectionalStreamId(0)),
        client_maker_(version_,
                      connection_id_,
                      &clock_,
                      kDefaultServerHostName,
                      quic::Perspective::IS_CLIENT),
        server_maker_(version_,
                      connection_id_,
                      &clock_,
                      kDefaultServerHostName,
                      quic::Perspective::IS_SERVER,
                      false),
        printer_(version_),
        destination_(url::kHttpsScheme,
                     kDefaultServerHostName,
                     kDefaultServerPort) {
    quic::QuicEnableVersion(version_);
    FLAGS_quic_enable_http3_grease_randomness = false;
    IPAddress ip(192, 0, 2, 33);
    peer_addr_ = IPEndPoint(ip, 443);
    self_addr_ = IPEndPoint(ip, 8435);
    clock_.AdvanceTime(quic::QuicTime::Delta::FromMilliseconds(20));
  }

  ~BidirectionalStreamQuicImplTest() override {
    if (session_) {
      session_->CloseSessionOnError(
          ERR_ABORTED, quic::QUIC_INTERNAL_ERROR,
          quic::ConnectionCloseBehavior::SILENT_CLOSE);
    }
    for (auto& write : writes_) {
      delete write.packet;
    }
  }

  void TearDown() override {
    if (socket_data_) {
      EXPECT_TRUE(socket_data_->AllReadDataConsumed());
      EXPECT_TRUE(socket_data_->AllWriteDataConsumed());
    }
  }

  // Adds a packet to the list of expected writes.
  void AddWrite(std::unique_ptr<quic::QuicReceivedPacket> packet) {
    writes_.emplace_back(SYNCHRONOUS, packet.release());
  }

  // Adds a write error to the list of expected writes.
  void AddWriteError(IoMode mode, int rv) { writes_.emplace_back(mode, rv); }

  void ProcessPacket(std::unique_ptr<quic::QuicReceivedPacket> packet) {
    connection_->ProcessUdpPacket(ToQuicSocketAddress(self_addr_),
                                  ToQuicSocketAddress(peer_addr_), *packet);
  }

  // Configures the test fixture to use the list of expected writes.
  void Initialize() {
    crypto_client_stream_factory_.set_handshake_mode(
        MockCryptoClientStream::ZERO_RTT);
    mock_writes_ = std::make_unique<MockWrite[]>(writes_.size());
    for (size_t i = 0; i < writes_.size(); i++) {
      if (writes_[i].packet == nullptr) {
        mock_writes_[i] = MockWrite(writes_[i].mode, writes_[i].rv, i);
      } else {
        mock_writes_[i] = MockWrite(writes_[i].mode, writes_[i].packet->data(),
                                    writes_[i].packet->length());
      }
    }

    socket_data_ = std::make_unique<StaticSocketDataProvider>(
        base::span<MockRead>(),
        base::make_span(mock_writes_.get(), writes_.size()));
    socket_data_->set_printer(&printer_);

    auto socket = std::make_unique<MockUDPClientSocket>(socket_data_.get(),
                                                        NetLog::Get());
    socket->Connect(peer_addr_);
    runner_ = base::MakeRefCounted<TestTaskRunner>(&clock_);
    helper_ = std::make_unique<QuicChromiumConnectionHelper>(
        &clock_, &random_generator_);
    alarm_factory_ =
        std::make_unique<QuicChromiumAlarmFactory>(runner_.get(), &clock_);
    connection_ = new quic::QuicConnection(
        connection_id_, quic::QuicSocketAddress(),
        ToQuicSocketAddress(peer_addr_), helper_.get(), alarm_factory_.get(),
        new QuicChromiumPacketWriter(socket.get(), runner_.get()),
        true /* owns_writer */, quic::Perspective::IS_CLIENT,
        quic::test::SupportedVersions(version_), connection_id_generator_);
    if (connection_->version().KnowsWhichDecrypterToUse()) {
      connection_->InstallDecrypter(
          quic::ENCRYPTION_FORWARD_SECURE,
          std::make_unique<quic::test::StrictTaggingDecrypter>(
              quic::ENCRYPTION_FORWARD_SECURE));
    }
    base::TimeTicks dns_end = base::TimeTicks::Now();
    base::TimeTicks dns_start = dns_end - base::Milliseconds(1);

    session_ = std::make_unique<QuicChromiumClientSession>(
        connection_, std::move(socket),
        /*stream_factory=*/nullptr, &crypto_client_stream_factory_, &clock_,
        &transport_security_state_, &ssl_config_service_,
        base::WrapUnique(static_cast<QuicServerInfo*>(nullptr)),
        QuicSessionAliasKey(
            url::SchemeHostPort(),
            QuicSessionKey(kDefaultServerHostName, kDefaultServerPort,
                           PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                           SessionUsage::kDestination, SocketTag(),
                           NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                           /*require_dns_https_alpn=*/false)),
        /*require_confirmation=*/false,
        /*migrate_session_early_v2=*/false,
        /*migrate_session_on_network_change_v2=*/false,
        /*default_network=*/handles::kInvalidNetworkHandle,
        quic::QuicTime::Delta::FromMilliseconds(
            kDefaultRetransmittableOnWireTimeout.InMilliseconds()),
        /*migrate_idle_session=*/false, /*allow_port_migration=*/false,
        kDefaultIdleSessionMigrationPeriod, /*multi_port_probing_interval=*/0,
        kMaxTimeOnNonDefaultNetwork,
        kMaxMigrationsToNonDefaultNetworkOnWriteError,
        kMaxMigrationsToNonDefaultNetworkOnPathDegrading,
        kQuicYieldAfterPacketsRead,
        quic::QuicTime::Delta::FromMilliseconds(
            kQuicYieldAfterDurationMilliseconds),
        /*cert_verify_flags=*/0, quic::test::DefaultQuicConfig(),
        std::make_unique<TestQuicCryptoClientConfigHandle>(&crypto_config_),
        "CONNECTION_UNKNOWN", dns_start, dns_end,
        base::DefaultTickClock::GetInstance(),
        base::SingleThreadTaskRunner::GetCurrentDefault().get(),
        /*socket_performance_watcher=*/nullptr, ConnectionEndpointMetadata(),
        /*report_ecn=*/true, /*enable_origin_frame=*/true,
        /*server_preferred_address=*/true,
        MultiplexedSessionCreationInitiator::kUnknown,
        NetLogWithSource::Make(NetLogSourceType::NONE));
    session_->Initialize();

    // Blackhole QPACK decoder stream instead of constructing mock writes.
    session_->qpack_decoder()->set_qpack_stream_sender_delegate(
        &noop_qpack_stream_sender_delegate_);

    TestCompletionCallback callback;
    session_->CryptoConnect(callback.callback());
    EXPECT_TRUE(session_->IsEncryptionEstablished());
  }

  void ConfirmHandshake() {
    crypto_client_stream_factory_.last_stream()
        ->NotifySessionOneRttKeyAvailable();
  }

  void SetRequest(const std::string& method,
                  const std::string& path,
                  RequestPriority priority) {
    request_headers_ = client_maker_.GetRequestHeaders(method, "http", path);
  }

  quiche::HttpHeaderBlock ConstructResponseHeaders(
      const std::string& response_code) {
    return server_maker_.GetResponseHeaders(response_code);
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructServerDataPacket(
      uint64_t packet_number,
      bool fin,
      std::string_view data) {
    std::unique_ptr<quic::QuicReceivedPacket> packet(
        server_maker_.Packet(packet_number)
            .AddStreamFrame(stream_id_, fin, data)
            .Build());
    DVLOG(2) << "packet(" << packet_number << "): " << std::endl
             << quiche::QuicheTextUtils::HexDump(packet->AsStringPiece());
    return packet;
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructClientDataPacket(
      bool fin,
      std::string_view data) {
    return client_maker_.Packet(++packet_number_)
        .AddStreamFrame(stream_id_, fin, data)
        .Build();
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructRequestHeadersPacket(
      bool fin,
      RequestPriority request_priority,
      size_t* spdy_headers_frame_length) {
    return ConstructRequestHeadersPacketInner(stream_id_, fin, request_priority,
                                              spdy_headers_frame_length);
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructRequestHeadersPacketInner(
      quic::QuicStreamId stream_id,
      bool fin,
      RequestPriority request_priority,
      size_t* spdy_headers_frame_length) {
    spdy::SpdyPriority priority =
        ConvertRequestPriorityToQuicPriority(request_priority);
    std::unique_ptr<quic::QuicReceivedPacket> packet(
        client_maker_.MakeRequestHeadersPacket(
            ++packet_number_, stream_id, fin, priority,
            std::move(request_headers_), spdy_headers_frame_length));
    DVLOG(2) << "packet(" << packet_number_ << "): " << std::endl
             << quiche::QuicheTextUtils::HexDump(packet->AsStringPiece());
    return packet;
  }

  std::unique_ptr<quic::QuicReceivedPacket>
  ConstructRequestHeadersAndMultipleDataFramesPacket(
      bool fin,
      RequestPriority request_priority,
      size_t* spdy_headers_frame_length,
      const std::vector<std::string>& data) {
    spdy::SpdyPriority priority =
        ConvertRequestPriorityToQuicPriority(request_priority);
    std::unique_ptr<quic::QuicReceivedPacket> packet(
        client_maker_.MakeRequestHeadersAndMultipleDataFramesPacket(
            ++packet_number_, stream_id_, fin, priority,
            std::move(request_headers_), spdy_headers_frame_length, data));
    DVLOG(2) << "packet(" << packet_number_ << "): " << std::endl
             << quiche::QuicheTextUtils::HexDump(packet->AsStringPiece());
    return packet;
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructResponseHeadersPacket(
      uint64_t packet_number,
      bool fin,
      quiche::HttpHeaderBlock response_headers,
      size_t* spdy_headers_frame_length) {
    return ConstructResponseHeadersPacketInner(packet_number, stream_id_, fin,
                                               std::move(response_headers),
                                               spdy_headers_frame_length);
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructResponseHeadersPacketInner(
      uint64_t packet_number,
      quic::QuicStreamId stream_id,
      bool fin,
      quiche::HttpHeaderBlock response_headers,
      size_t* spdy_headers_frame_length) {
    return server_maker_.MakeResponseHeadersPacket(
        packet_number, stream_id, fin, std::move(response_headers),
        spdy_headers_frame_length);
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructResponseTrailersPacket(
      uint64_t packet_number,
      bool fin,
      quiche::HttpHeaderBlock trailers,
      size_t* spdy_headers_frame_length) {
    return server_maker_.MakeResponseHeadersPacket(packet_number, stream_id_,
                                                   fin, std::move(trailers),
                                                   spdy_headers_frame_length);
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructClientRstStreamPacket() {
    return ConstructRstStreamCancelledPacket(++packet_number_, &client_maker_);
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructServerRstStreamPacket(
      uint64_t packet_number) {
    return ConstructRstStreamCancelledPacket(packet_number, &server_maker_);
  }

  std::unique_ptr<quic::QuicReceivedPacket>
  ConstructClientEarlyRstStreamPacket() {
    return ConstructRstStreamCancelledPacket(++packet_number_, &client_maker_);
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructRstStreamCancelledPacket(
      uint64_t packet_number,
      QuicTestPacketMaker* maker) {
    std::unique_ptr<quic::QuicReceivedPacket> packet(
        client_maker_.Packet(packet_number)
            .AddStopSendingFrame(stream_id_, quic::QUIC_STREAM_CANCELLED)
            .AddRstStreamFrame(stream_id_, quic::QUIC_STREAM_CANCELLED)
            .Build());
    DVLOG(2) << "packet(" << packet_number << "): " << std::endl
             << quiche::QuicheTextUtils::HexDump(packet->AsStringPiece());
    return packet;
  }

  std::unique_ptr<quic::QuicReceivedPacket>
  ConstructClientAckAndRstStreamPacket(uint64_t largest_received,
                                       uint64_t smallest_received) {
    return client_maker_.Packet(++packet_number_)
        .AddAckFrame(/*first_received=*/1, largest_received, smallest_received)
        .AddStopSendingFrame(stream_id_, quic::QUIC_STREAM_CANCELLED)
        .AddRstStreamFrame(stream_id_, quic::QUIC_STREAM_CANCELLED)
        .Build();
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructAckAndDataPacket(
      uint64_t packet_number,
      uint64_t largest_received,
      uint64_t smallest_received,
      bool fin,
      std::string_view data,
      QuicTestPacketMaker* maker) {
    std::unique_ptr<quic::QuicReceivedPacket> packet(
        maker->Packet(packet_number)
            .AddAckFrame(/*first_received=*/1, largest_received,
                         smallest_received)
            .AddStreamFrame(stream_id_, fin, data)
            .Build());
    DVLOG(2) << "packet(" << packet_number << "): " << std::endl
             << quiche::QuicheTextUtils::HexDump(packet->AsStringPiece());
    return packet;
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructClientAckPacket(
      uint64_t largest_received,
      uint64_t smallest_received) {
    return client_maker_.Packet(++packet_number_)
        .AddAckFrame(1, largest_received, smallest_received)
        .Build();
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructServerAckPacket(
      uint64_t packet_number,
      uint64_t largest_received,
      uint64_t smallest_received,
      uint64_t least_unacked) {
    return server_maker_.Packet(packet_number)
        .AddAckFrame(largest_received, smallest_received, least_unacked)
        .Build();
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructInitialSettingsPacket() {
    return client_maker_.MakeInitialSettingsPacket(++packet_number_);
  }

  void ExpectLoadTimingValid(const LoadTimingInfo& load_timing_info,
                             bool session_reused) {
    EXPECT_EQ(session_reused, load_timing_info.socket_reused);

    if (session_reused) {
      ExpectConnectTimingHasNoTimes(load_timing_info.connect_timing);
    } else {
      ExpectConnectTimingHasTimes(
          load_timing_info.connect_timing,
          CONNECT_TIMING_HAS_SSL_TIMES | CONNECT_TIMING_HAS_DNS_TIMES);
    }
    ExpectLoadTimingHasOnlyConnectionTimes(load_timing_info);
  }

  const RecordingNetLogObserver& net_log_observer() const {
    return net_log_observer_;
  }

  const NetLogWithSource& net_log_with_source() const {
    return net_log_with_source_;
  }

  QuicChromiumClientSession* session() const { return session_.get(); }

  quic::QuicStreamId GetNthClientInitiatedBidirectionalStreamId(int n) {
    return quic::test::GetNthClientInitiatedBidirectionalStreamId(
        version_.transport_version, n);
  }

  std::string ConstructDataHeader(size_t body_len) {
    quiche::QuicheBuffer buffer = quic::HttpEncoder::SerializeDataFrameHeader(
        body_len, quiche::SimpleBufferAllocator::Get());
    return std::string(buffer.data(), buffer.size());
  }

 protected:
  quic::test::QuicFlagSaver saver_;
  const quic::ParsedQuicVersion version_;
  RecordingNetLogObserver net_log_observer_;
  NetLogWithSource net_log_with_source_{
      NetLogWithSource::Make(NetLogSourceType::NONE)};
  scoped_refptr<TestTaskRunner> runner_;
  std::unique_ptr<MockWrite[]> mock_writes_;
  quic::MockClock clock_;
  raw_ptr<quic::QuicConnection, DanglingUntriaged> connection_;
  std::unique_ptr<QuicChromiumConnectionHelper> helper_;
  std::unique_ptr<QuicChromiumAlarmFactory> alarm_factory_;
  TransportSecurityState transport_security_state_;
  SSLConfigServiceDefaults ssl_config_service_;
  std::unique_ptr<QuicChromiumClientSession> session_;
  quic::QuicCryptoClientConfig crypto_config_;
  HttpRequestHeaders headers_;
  HttpResponseInfo response_;
  scoped_refptr<IOBufferWithSize> read_buffer_;
  quiche::HttpHeaderBlock request_headers_;
  const quic::QuicConnectionId connection_id_;
  const quic::QuicStreamId stream_id_;
  QuicTestPacketMaker client_maker_;
  uint64_t packet_number_ = 0;
  QuicTestPacketMaker server_maker_;
  IPEndPoint self_addr_;
  IPEndPoint peer_addr_;
  quic::test::MockRandom random_generator_{0};
  QuicPacketPrinter printer_;
  MockCryptoClientStreamFactory crypto_client_stream_factory_;
  std::unique_ptr<StaticSocketDataProvider> socket_data_;
  std::vector<PacketToWrite> writes_;
  url::SchemeHostPort destination_;
  quic::test::MockConnectionIdGenerator connection_id_generator_;
  quic::test::NoopQpackStreamSenderDelegate noop_qpack_stream_sender_delegate_;
};

INSTANTIATE_TEST_SUITE_P(Version,
                         BidirectionalStreamQuicImplTest,
                         ::testing::ValuesIn(AllSupportedQuicVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(BidirectionalStreamQuicImplTest, GetRequest) {
  SetRequest("GET", "/", DEFAULT_PRIORITY);
  size_t spdy_request_headers_frame_length;
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  AddWrite(ConstructInitialSettingsPacket());
  AddWrite(ConstructRequestHeadersPacketInner(
      GetNthClientInitiatedBidirectionalStreamId(0), kFin, DEFAULT_PRIORITY,
      &spdy_request_headers_frame_length));
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  AddWrite(ConstructClientAckPacket(3, 1));

  Initialize();

  BidirectionalStreamRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.google.com/");
  request.end_stream_on_headers = true;
  request.priority = DEFAULT_PRIORITY;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate =
      std::make_unique<TestDelegateBase>(read_buffer.get(), kReadBufferSize);
  delegate->set_trailers_expected(true);
  delegate->Start(&request, net_log_with_source(),
                  session()->CreateHandle(destination_));
  delegate->WaitUntilNextCallback(kOnStreamReady);
  ConfirmHandshake();

  //
```