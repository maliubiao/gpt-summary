Response:
My thinking process to arrive at the summary of the provided C++ code snippet goes like this:

1. **Identify the Core File:** The initial prompt clearly states the file is `net/http/bidirectional_stream_unittest.cc`. The `_unittest` suffix immediately signals that this file contains *tests* for the `BidirectionalStream` class.

2. **Scan for Key Class Names:**  I quickly scanned the `#include` directives and the code itself for prominent class names. `BidirectionalStream`, `BidirectionalStreamRequestInfo`, `HttpNetworkSession`, and delegates like `TestDelegateBase` and `DeleteStreamDelegate` stand out. These are the central actors in the tests.

3. **Recognize Test Structure:**  The presence of `TEST_F` macros from the Google Test framework confirms this is a unit test file. Each `TEST_F` function represents an individual test case.

4. **Analyze Individual Test Cases (High Level):** I read through the names of the `TEST_F` functions to get a sense of what aspects of `BidirectionalStream` are being tested:
    * `CreateInsecureStream`:  Likely tests handling of HTTP vs. HTTPS.
    * `SimplePostRequest`: Tests a basic POST request.
    * `LoadTimingTwoRequests`: Focuses on performance metrics for multiple requests.
    * `CreateInsecureStreamAndDestroyStreamRightAfter`: Tests resource management, specifically destruction.
    * `ClientAuthRequestIgnored`:  Tests interaction with client certificate authentication.
    * `TestReadDataAfterClose`:  Tests behavior after the stream is closed.
    * `TestNetLogContainEntries`: Tests the logging functionality.
    * `DeleteStreamInVariousCallbacks`: Tests object lifetime management in different scenarios.
    * `SendvData`: Tests sending data using a vector of buffers.
    * `TimeoutNotSetByDefault`: Tests default timeout behavior.
    * `SetTimeout`: Tests setting a custom timeout.
    * `CancelWithError`: Tests canceling the stream with an error.
    * `CancelMidRead`: Tests canceling during a read operation.
    * `CancelMidWrite`: Tests canceling during a write operation.
    * `ResetMidRead`: Tests resetting the stream during a read.
    * `ResetMidWrite`: Tests resetting the stream during a write.
    * `ReceivesGoAway`: Tests how the stream reacts to a `GOAWAY` frame.
    * `SendDataBeforeHeadersComplete`: Tests sending data before headers are fully received.
    * `DelayedByTimer`: Tests the use of timers for delays.
    * `OnStreamReadyNotCalledForZeroRtt`: Tests a specific optimization.
    * `OnStreamReadyCalledForNonZeroRtt`: Tests the expected behavior for non-zero RTT connections.
    * `SocketTagPassed`: Tests if socket tagging is correctly propagated.

5. **Identify Common Patterns:**  Several tests use `MockWrite` and `MockRead` to simulate network interactions. The `TestDelegateBase` class and its variations are used to observe and control the behavior of the `BidirectionalStream`. Load timing information is frequently checked.

6. **Infer Overall Function:** Based on the individual tests and common patterns, the primary function of this file is clearly to **thoroughly test the `BidirectionalStream` class**. This includes testing its core functionality (sending/receiving data, handling headers and trailers), error handling, resource management, and integration with other network components (like logging and socket handling).

7. **Consider Javascript Relevance (As requested):**  Although this is C++ code, `BidirectionalStream` in Chromium's network stack is a fundamental building block for web communication. JavaScript APIs like `fetch()` (especially with the `duplex` option) or the older `XMLHttpRequest` can potentially use `BidirectionalStream` under the hood for certain types of communication, particularly when HTTP/2 or later protocols are involved. The tests themselves don't directly interact with JavaScript, but they ensure the underlying C++ implementation behaves correctly, which is crucial for the reliability of web applications.

8. **Address Logical Reasoning, User Errors, and Debugging:**  While the tests themselves involve specific inputs and expected outputs, the broader implication is to prevent common user or programming errors. For example, testing insecure schemes prevents developers from accidentally using `BidirectionalStream` with HTTP when HTTPS is required. Testing cancellation scenarios helps ensure that resource cleanup happens correctly if a request is aborted. The debugging aspect is inherent in unit testing – these tests act as early detectors of bugs in the `BidirectionalStream` implementation.

9. **Structure the Summary:** I organized the findings into logical categories: core functionality, testing methodology, relevance to JavaScript, implications for users/developers, debugging role, and the overall purpose. This provides a comprehensive overview.

10. **Refine and Elaborate:** I added details like the specific delegate classes and the use of mock objects to make the summary more informative. I also explicitly mentioned the HTTP/2 focus evident in the code.
```
首先，让我们对提供的代码片段进行分析，并归纳其功能。

**代码片段分析:**

这段代码是 Chromium 网络栈中 `net/http/bidirectional_stream_unittest.cc` 文件的开头部分，它包含了以下关键元素：

* **头文件包含:** 引入了大量的 C++ 标准库头文件（如 `<memory>`, `<string>`, `<vector>`）以及 Chromium 网络栈相关的头文件（如 `bidirectional_stream.h`, `http_network_session.h`, `net_errors.h` 等）。这些头文件提供了编写测试用例所需的类、函数和常量定义。
* **条件编译:** `#ifdef UNSAFE_BUFFERS_BUILD` 和 `#pragma allow_unsafe_buffers` 块表明，这段代码可能在特定的构建配置下需要处理不安全的缓冲区。这通常与性能优化或底层内存操作有关。
* **命名空间:** 代码位于 `net` 命名空间下，进一步限定了其所属的 Chromium 网络模块。内部还有一个匿名命名空间 `namespace {` 用于定义只在本文件中可见的辅助常量和函数。
* **常量定义:** 定义了一些测试中使用的常量，例如 `kBodyData`, `kBodyDataSize`, `kBodyDataString`, `kReadBufferSize`。
* **辅助函数:** 定义了一些辅助函数，例如 `ExpectLoadTimingValid`, `TestLoadTimingReused`, `TestLoadTimingNotReused`。这些函数用于断言和验证 `LoadTimingInfo` 结构体中的时间戳信息，这对于测试网络请求的性能指标非常重要。
* **`TestDelegateBase` 类:** 定义了一个名为 `TestDelegateBase` 的基类，它继承自 `BidirectionalStream::Delegate`。这个类充当双向流的委托，用于模拟网络请求的生命周期，接收和处理事件，例如流就绪、接收到头、读取到数据、发送数据、接收到尾部、请求失败等。这个基类提供了方便的方法来启动和控制双向流，并收集测试结果。
* **`DeleteStreamDelegate` 类:** 定义了一个继承自 `TestDelegateBase` 的派生类 `DeleteStreamDelegate`。这个类的主要目的是在特定的回调函数中删除（销毁）双向流对象，用于测试对象生命周期管理和异常情况处理。
* **`MockTimer` 类:**  定义了一个继承自 `base::MockOneShotTimer` 的模拟定时器类。这个定时器被设计成除非显式触发，否则不会启动延迟任务，这对于精确控制异步操作的时序非常有用。
* **`BidirectionalStreamTest` 类:**  定义了一个名为 `BidirectionalStreamTest` 的测试类，它继承自 `net::TestWithTaskEnvironment`。这个类使用了 Google Test 框架（gtest）来组织和运行测试用例。它包含了测试所需的成员变量，例如 `default_url_`, `host_port_pair_`, `ssl_data_`, `sequenced_data_`, `http_session_` 等。`InitSession` 方法用于初始化测试所需的 HTTP 会话。

**功能归纳 (第 1 部分):**

这段代码是 Chromium 网络栈中 **`BidirectionalStream` 类的单元测试文件的起始部分**。其主要功能包括：

1. **提供测试基础设施:**  定义了用于测试 `BidirectionalStream` 类的各种辅助类、函数和常量。
2. **模拟双向流的行为:**  通过 `TestDelegateBase` 和 `DeleteStreamDelegate` 类，模拟了双向流在不同场景下的行为，例如数据接收、发送、错误处理以及生命周期管理。
3. **提供时间控制机制:** 使用 `MockTimer` 类来精确控制异步操作的时序，以便进行更精细的测试。
4. **初始化测试环境:** `BidirectionalStreamTest` 类负责初始化测试所需的网络会话和其他依赖项。
5. **定义通用的负载时序测试方法:**  `ExpectLoadTimingValid`, `TestLoadTimingReused`, `TestLoadTimingNotReused` 等函数用于验证网络请求的性能指标。

**与 JavaScript 功能的关系:**

`BidirectionalStream` 是 Chromium 网络栈的底层实现，它直接处理 HTTP/2 和 HTTP/3 等协议的双向通信。在 JavaScript 中，开发者通常不会直接操作 `BidirectionalStream` 类。然而，JavaScript 的 `fetch` API 和 `XMLHttpRequest` API 在底层可能会使用 `BidirectionalStream` 来实现某些类型的网络请求，尤其是在需要双向数据传输或服务端推送的场景下。

**举例说明:**

假设一个 JavaScript 应用使用 `fetch` API 发起一个使用了 HTTP/2 的请求，并且服务端支持推送功能。在这种情况下，Chromium 浏览器底层的 `BidirectionalStream` 可能会被用来处理这个请求，以及接收服务端主动推送的数据。

虽然 JavaScript 代码本身不会直接调用 `BidirectionalStream` 的方法，但这段 C++ 测试代码的目的是确保 `BidirectionalStream` 类的行为符合预期，这直接影响了基于 JavaScript 的 Web 应用的网络功能是否正常工作。如果 `BidirectionalStream` 有 bug，可能会导致 JavaScript 的 `fetch` 请求失败、数据接收不完整或者性能下降。

**逻辑推理、假设输入与输出 (在后续部分可能体现更多):**

由于这是代码的开头部分，具体的逻辑推理和假设输入输出将在后续的测试用例中体现。例如，在测试发送数据时，可能会假设输入特定的请求头和请求体，然后验证发送的数据是否符合预期。在测试接收数据时，可能会模拟服务端返回特定的响应头和响应体，然后验证 `TestDelegateBase` 接收到的数据是否正确。

**用户或编程常见的使用错误 (可能在后续部分测试):**

这段代码本身是测试代码，它的目的是发现 `BidirectionalStream` 实现中的错误。但是，通过测试用例，我们可以推断出一些用户或编程中可能犯的错误，例如：

* **尝试在不允许的 URL  Scheme 下创建 `BidirectionalStream`:** 例如，尝试使用 `http://` 而不是 `https://` 来建立双向流连接，如果协议要求安全连接。
* **在不恰当的时机调用 `ReadData` 或 `SendData`:** 例如，在流还未建立或者已经关闭后尝试读写数据。
* **不正确处理流的生命周期:** 例如，在流的回调函数中错误地删除流对象，可能导致崩溃或未定义的行为。

**用户操作如何一步步的到达这里 (调试线索):**

作为调试线索，用户操作到达这里的路径可能如下：

1. **用户在浏览器中访问一个使用了 HTTP/2 或 HTTP/3 的网站。**
2. **网页上的 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起一个需要双向通信的请求，或者服务端主动推送数据。**
3. **Chromium 浏览器网络栈的底层代码（包括 `BidirectionalStream` 的实现）会处理这个请求。**
4. **如果在这个过程中出现问题，例如连接失败、数据传输错误等，开发者可能会需要查看网络日志或者进行更底层的调试。**
5. **开发者可能会运行 `net/http/bidirectional_stream_unittest.cc` 中的测试用例来验证 `BidirectionalStream` 类的行为，以排查问题是否出在这个底层组件上。**
6. **开发者可能会修改测试用例，添加断点，或者使用其他调试工具来分析 `BidirectionalStream` 在特定场景下的行为。**

总而言之，这段代码是 `BidirectionalStream` 类的测试代码的开始，它为后续的测试用例提供了基础的框架和工具。这些测试用例旨在验证 `BidirectionalStream` 类的功能正确性、健壮性和性能。
```
Prompt: 
```
这是目录为net/http/bidirectional_stream_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/http/bidirectional_stream.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/containers/span.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/scoped_feature_list.h"
#include "base/time/time.h"
#include "base/timer/mock_timer.h"
#include "base/timer/timer.h"
#include "build/build_config.h"
#include "net/base/completion_once_callback.h"
#include "net/base/features.h"
#include "net/base/load_timing_info.h"
#include "net/base/load_timing_info_test_util.h"
#include "net/base/net_errors.h"
#include "net/base/session_usage.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/bidirectional_stream_request_info.h"
#include "net/http/http_network_session.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_server_properties.h"
#include "net/log/net_log.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source_type.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/socket/socket_tag.h"
#include "net/socket/socket_test_util.h"
#include "net/spdy/spdy_session.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

const char kBodyData[] = "Body data";
const size_t kBodyDataSize = std::size(kBodyData);
const std::string kBodyDataString(kBodyData, kBodyDataSize);
// Size of the buffer to be allocated for each read.
const size_t kReadBufferSize = 4096;

// Expects that fields of |load_timing_info| are valid time stamps.
void ExpectLoadTimingValid(const LoadTimingInfo& load_timing_info) {
  EXPECT_FALSE(load_timing_info.request_start.is_null());
  EXPECT_FALSE(load_timing_info.request_start_time.is_null());
  EXPECT_FALSE(load_timing_info.receive_headers_end.is_null());
  EXPECT_FALSE(load_timing_info.send_start.is_null());
  EXPECT_FALSE(load_timing_info.send_end.is_null());
  EXPECT_TRUE(load_timing_info.request_start <=
              load_timing_info.receive_headers_end);
  EXPECT_TRUE(load_timing_info.send_start <= load_timing_info.send_end);
}

// Tests the load timing of a stream that's connected and is not the first
// request sent on a connection.
void TestLoadTimingReused(const LoadTimingInfo& load_timing_info) {
  EXPECT_TRUE(load_timing_info.socket_reused);

  ExpectConnectTimingHasNoTimes(load_timing_info.connect_timing);
  ExpectLoadTimingValid(load_timing_info);
}

// Tests the load timing of a stream that's connected and using a fresh
// connection.
void TestLoadTimingNotReused(const LoadTimingInfo& load_timing_info) {
  EXPECT_FALSE(load_timing_info.socket_reused);

  ExpectConnectTimingHasTimes(
      load_timing_info.connect_timing,
      CONNECT_TIMING_HAS_SSL_TIMES | CONNECT_TIMING_HAS_DNS_TIMES);
  ExpectLoadTimingValid(load_timing_info);
}

// Delegate that reads data but does not send any data.
class TestDelegateBase : public BidirectionalStream::Delegate {
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
        timer_(std::move(timer)) {}

  TestDelegateBase(const TestDelegateBase&) = delete;
  TestDelegateBase& operator=(const TestDelegateBase&) = delete;

  ~TestDelegateBase() override = default;

  void OnStreamReady(bool request_headers_sent) override {
    // Request headers should always be sent in H2's case, because the
    // functionality to combine header frame with data frames is not
    // implemented.
    EXPECT_TRUE(request_headers_sent);
    if (callback_.is_null())
      return;
    std::move(callback_).Run(OK);
  }

  void OnHeadersReceived(
      const quiche::HttpHeaderBlock& response_headers) override {
    CHECK(!not_expect_callback_);

    response_headers_ = response_headers.Clone();

    if (!do_not_start_read_)
      StartOrContinueReading();
  }

  void OnDataRead(int bytes_read) override {
    CHECK(!not_expect_callback_);

    ++on_data_read_count_;
    CHECK_GE(bytes_read, OK);
    data_received_.append(read_buf_->data(), bytes_read);
    if (!do_not_start_read_)
      StartOrContinueReading();
  }

  void OnDataSent() override {
    CHECK(!not_expect_callback_);

    ++on_data_sent_count_;
  }

  void OnTrailersReceived(const quiche::HttpHeaderBlock& trailers) override {
    CHECK(!not_expect_callback_);

    trailers_ = trailers.Clone();
    if (run_until_completion_)
      loop_->Quit();
  }

  void OnFailed(int error) override {
    CHECK(!not_expect_callback_);
    CHECK_EQ(OK, error_);
    CHECK_NE(OK, error);

    error_ = error;
    if (run_until_completion_)
      loop_->Quit();
  }

  void Start(std::unique_ptr<BidirectionalStreamRequestInfo> request_info,
             HttpNetworkSession* session) {
    stream_ = std::make_unique<BidirectionalStream>(
        std::move(request_info), session, true, this, std::move(timer_));
    if (run_until_completion_)
      loop_->Run();
  }

  void Start(std::unique_ptr<BidirectionalStreamRequestInfo> request_info,
             HttpNetworkSession* session,
             CompletionOnceCallback cb) {
    callback_ = std::move(cb);
    stream_ = std::make_unique<BidirectionalStream>(
        std::move(request_info), session, true, this, std::move(timer_));
    if (run_until_completion_)
      WaitUntilCompletion();
  }

  void WaitUntilCompletion() { loop_->Run(); }

  void SendData(const scoped_refptr<IOBuffer>& data,
                int length,
                bool end_of_stream) {
    SendvData({data}, {length}, end_of_stream);
  }

  void SendvData(const std::vector<scoped_refptr<IOBuffer>>& data,
                 const std::vector<int>& length,
                 bool end_of_stream) {
    not_expect_callback_ = true;
    stream_->SendvData(data, length, end_of_stream);
    not_expect_callback_ = false;
  }

  // Starts or continues reading data from |stream_| until no more bytes
  // can be read synchronously.
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
    not_expect_callback_ = true;
    int rv = stream_->ReadData(read_buf_.get(), read_buf_len_);
    not_expect_callback_ = false;
    if (rv > 0)
      data_received_.append(read_buf_->data(), rv);
    return rv;
  }

  // Deletes |stream_|.
  void DeleteStream() {
    next_proto_ = stream_->GetProtocol();
    received_bytes_ = stream_->GetTotalReceivedBytes();
    sent_bytes_ = stream_->GetTotalSentBytes();
    stream_->GetLoadTimingInfo(&load_timing_info_);
    stream_.reset();
  }

  NextProto GetProtocol() const {
    if (stream_)
      return stream_->GetProtocol();
    return next_proto_;
  }

  int64_t GetTotalReceivedBytes() const {
    if (stream_)
      return stream_->GetTotalReceivedBytes();
    return received_bytes_;
  }

  int64_t GetTotalSentBytes() const {
    if (stream_)
      return stream_->GetTotalSentBytes();
    return sent_bytes_;
  }

  void GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const {
    if (stream_) {
      stream_->GetLoadTimingInfo(load_timing_info);
      return;
    }
    *load_timing_info = load_timing_info_;
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

  // Sets whether the delegate should automatically start reading.
  void set_do_not_start_read(bool do_not_start_read) {
    do_not_start_read_ = do_not_start_read;
  }
  // Sets whether the delegate should wait until the completion of the stream.
  void SetRunUntilCompletion(bool run_until_completion) {
    run_until_completion_ = run_until_completion;
    loop_ = std::make_unique<base::RunLoop>();
  }

 protected:
  // Quits |loop_|.
  void QuitLoop() { loop_->Quit(); }

 private:
  std::unique_ptr<BidirectionalStream> stream_;
  scoped_refptr<IOBuffer> read_buf_;
  int read_buf_len_;
  std::unique_ptr<base::OneShotTimer> timer_;
  std::string data_received_;
  std::unique_ptr<base::RunLoop> loop_;
  quiche::HttpHeaderBlock response_headers_;
  quiche::HttpHeaderBlock trailers_;
  NextProto next_proto_;
  int64_t received_bytes_ = 0;
  int64_t sent_bytes_ = 0;
  LoadTimingInfo load_timing_info_;
  int error_ = OK;
  int on_data_read_count_ = 0;
  int on_data_sent_count_ = 0;
  bool do_not_start_read_ = false;
  bool run_until_completion_ = false;
  // This is to ensure that delegate callback is not invoked synchronously when
  // calling into |stream_|.
  bool not_expect_callback_ = false;

  CompletionOnceCallback callback_;
};

// A delegate that deletes the stream in a particular callback.
class DeleteStreamDelegate : public TestDelegateBase {
 public:
  // Specifies in which callback the stream can be deleted.
  enum Phase {
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

  void OnHeadersReceived(
      const quiche::HttpHeaderBlock& response_headers) override {
    TestDelegateBase::OnHeadersReceived(response_headers);
    if (phase_ == ON_HEADERS_RECEIVED) {
      DeleteStream();
      QuitLoop();
    }
  }

  void OnDataSent() override { NOTREACHED(); }

  void OnDataRead(int bytes_read) override {
    if (phase_ == ON_HEADERS_RECEIVED) {
      NOTREACHED();
    }
    TestDelegateBase::OnDataRead(bytes_read);
    if (phase_ == ON_DATA_READ) {
      DeleteStream();
      QuitLoop();
    }
  }

  void OnTrailersReceived(const quiche::HttpHeaderBlock& trailers) override {
    if (phase_ == ON_HEADERS_RECEIVED || phase_ == ON_DATA_READ) {
      NOTREACHED();
    }
    TestDelegateBase::OnTrailersReceived(trailers);
    if (phase_ == ON_TRAILERS_RECEIVED) {
      DeleteStream();
      QuitLoop();
    }
  }

  void OnFailed(int error) override {
    if (phase_ != ON_FAILED) {
      NOTREACHED();
    }
    TestDelegateBase::OnFailed(error);
    DeleteStream();
    QuitLoop();
  }

 private:
  // Indicates in which callback the delegate should cancel or delete the
  // stream.
  Phase phase_;
};

// A Timer that does not start a delayed task unless the timer is fired.
class MockTimer : public base::MockOneShotTimer {
 public:
  MockTimer() = default;

  MockTimer(const MockTimer&) = delete;
  MockTimer& operator=(const MockTimer&) = delete;

  ~MockTimer() override = default;

  void Start(const base::Location& posted_from,
             base::TimeDelta delay,
             base::OnceClosure user_task) override {
    // Sets a maximum delay, so the timer does not fire unless it is told to.
    base::TimeDelta infinite_delay = base::TimeDelta::Max();
    base::MockOneShotTimer::Start(posted_from, infinite_delay,
                                  std::move(user_task));
  }
};

}  // namespace

class BidirectionalStreamTest : public TestWithTaskEnvironment {
 public:
  BidirectionalStreamTest()
      : default_url_(kDefaultUrl),
        host_port_pair_(HostPortPair::FromURL(default_url_)),
        ssl_data_(SSLSocketDataProvider(ASYNC, OK)) {
    // Explicitly disable HappyEyeballsV3 because it doesn't support
    // bidirectional streams.
    // TODO(crbug.com/346835898): Support bidirectional streams in
    // HappyEyeballsV3.
    feature_list_.InitAndDisableFeature(features::kHappyEyeballsV3);
    ssl_data_.next_proto = kProtoHTTP2;
    ssl_data_.ssl_info.cert =
        ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");
    net_log_observer_.SetObserverCaptureMode(NetLogCaptureMode::kEverything);
    auto socket_factory = std::make_unique<MockTaggingClientSocketFactory>();
    socket_factory_ = socket_factory.get();
    session_deps_.socket_factory = std::move(socket_factory);
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
                   base::span<const MockWrite> writes,
                   const SocketTag& socket_tag) {
    ASSERT_TRUE(ssl_data_.ssl_info.cert.get());
    session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data_);
    sequenced_data_ = std::make_unique<SequencedSocketData>(reads, writes);
    session_deps_.socket_factory->AddSocketDataProvider(sequenced_data_.get());
    session_deps_.net_log = NetLog::Get();
    http_session_ = SpdySessionDependencies::SpdyCreateSession(&session_deps_);
    SpdySessionKey key(host_port_pair_, PRIVACY_MODE_DISABLED,
                       ProxyChain::Direct(), SessionUsage::kDestination,
                       socket_tag, NetworkAnonymizationKey(),
                       SecureDnsPolicy::kAllow,
                       /*disable_cert_verification_network_fetches=*/false);
    session_ =
        CreateSpdySession(http_session_.get(), key,
                          NetLogWithSource::Make(NetLogSourceType::NONE));
  }

  RecordingNetLogObserver net_log_observer_;
  SpdyTestUtil spdy_util_;
  SpdySessionDependencies session_deps_;
  const GURL default_url_;
  const HostPortPair host_port_pair_;
  std::unique_ptr<SequencedSocketData> sequenced_data_;
  std::unique_ptr<HttpNetworkSession> http_session_;
  raw_ptr<MockTaggingClientSocketFactory> socket_factory_;

 private:
  SSLSocketDataProvider ssl_data_;
  base::WeakPtr<SpdySession> session_;
  base::test::ScopedFeatureList feature_list_;
};

TEST_F(BidirectionalStreamTest, CreateInsecureStream) {
  auto request_info = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info->method = "GET";
  request_info->url = GURL("http://www.example.org/");

  auto session = std::make_unique<HttpNetworkSession>(
      SpdySessionDependencies::CreateSessionParams(&session_deps_),
      SpdySessionDependencies::CreateSessionContext(&session_deps_));
  TestDelegateBase delegate(nullptr, 0);
  delegate.SetRunUntilCompletion(true);
  delegate.Start(std::move(request_info), session.get());

  EXPECT_THAT(delegate.error(), IsError(ERR_DISALLOWED_URL_SCHEME));
}

TEST_F(BidirectionalStreamTest, SimplePostRequest) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize, LOW, nullptr, 0));
  spdy::SpdySerializedFrame data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, kBodyDataString, /*fin=*/true));
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
  InitSession(reads, writes, SocketTag());

  auto request_info = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info->method = "POST";
  request_info->url = default_url_;
  request_info->extra_headers.SetHeader(HttpRequestHeaders::kContentLength,
                                        base::NumberToString(kBodyDataSize));
  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate =
      std::make_unique<TestDelegateBase>(read_buffer.get(), kReadBufferSize);
  delegate->Start(std::move(request_info), http_session_.get());
  sequenced_data_->RunUntilPaused();

  scoped_refptr<StringIOBuffer> buf =
      base::MakeRefCounted<StringIOBuffer>(kBodyDataString);
  delegate->SendData(buf.get(), buf->size(), true);
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();
  LoadTimingInfo load_timing_info;
  delegate->GetLoadTimingInfo(&load_timing_info);
  TestLoadTimingNotReused(load_timing_info);

  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(1, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ(CountWriteBytes(writes), delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, LoadTimingTwoRequests) {
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
  InitSession(reads, writes, SocketTag());

  auto request_info = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->end_stream_on_headers = true;
  auto request_info2 = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info2->method = "GET";
  request_info2->url = default_url_;
  request_info2->end_stream_on_headers = true;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto read_buffer2 = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate =
      std::make_unique<TestDelegateBase>(read_buffer.get(), kReadBufferSize);
  auto delegate2 =
      std::make_unique<TestDelegateBase>(read_buffer2.get(), kReadBufferSize);
  delegate->Start(std::move(request_info), http_session_.get());
  delegate2->Start(std::move(request_info2), http_session_.get());
  delegate->SetRunUntilCompletion(true);
  delegate2->SetRunUntilCompletion(true);
  base::RunLoop().RunUntilIdle();

  delegate->WaitUntilCompletion();
  delegate2->WaitUntilCompletion();
  LoadTimingInfo load_timing_info;
  delegate->GetLoadTimingInfo(&load_timing_info);
  TestLoadTimingNotReused(load_timing_info);
  LoadTimingInfo load_timing_info2;
  delegate2->GetLoadTimingInfo(&load_timing_info2);
  TestLoadTimingReused(load_timing_info2);
}

// Creates a BidirectionalStream with an insecure scheme. Destroy the stream
// without waiting for the OnFailed task to be executed.
TEST_F(BidirectionalStreamTest,
       CreateInsecureStreamAndDestroyStreamRightAfter) {
  auto request_info = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info->method = "GET";
  request_info->url = GURL("http://www.example.org/");

  auto delegate = std::make_unique<TestDelegateBase>(nullptr, 0);
  auto session = std::make_unique<HttpNetworkSession>(
      SpdySessionDependencies::CreateSessionParams(&session_deps_),
      SpdySessionDependencies::CreateSessionContext(&session_deps_));
  delegate->Start(std::move(request_info), session.get());
  // Reset stream right before the OnFailed task is executed.
  delegate.reset();

  base::RunLoop().RunUntilIdle();
}

TEST_F(BidirectionalStreamTest, ClientAuthRequestIgnored) {
  auto cert_request = base::MakeRefCounted<SSLCertRequestInfo>();
  cert_request->host_and_port = host_port_pair_;

  // First attempt receives client auth request.
  SSLSocketDataProvider ssl_data1(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl_data1.next_proto = kProtoHTTP2;
  ssl_data1.cert_request_info = cert_request;

  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data1);
  StaticSocketDataProvider socket_data1;
  session_deps_.socket_factory->AddSocketDataProvider(&socket_data1);

  // Second attempt succeeds.
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(kDefaultUrl, 1, LOWEST));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      CreateMockRead(body_frame, 2),
      MockRead(SYNCHRONOUS, OK, 3),
  };

  SSLSocketDataProvider ssl_data2(ASYNC, OK);
  ssl_data2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data2);
  SequencedSocketData socket_data2(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&socket_data2);

  http_session_ = SpdySessionDependencies::SpdyCreateSession(&session_deps_);
  SpdySessionKey key(host_port_pair_, PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
                     SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/false);
  auto request_info = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->end_stream_on_headers = true;
  request_info->priority = LOWEST;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto delegate =
      std::make_unique<TestDelegateBase>(read_buffer.get(), kReadBufferSize);

  delegate->SetRunUntilCompletion(true);
  delegate->Start(std::move(request_info), http_session_.get());

  // Ensure the certificate was added to the client auth cache.
  scoped_refptr<X509Certificate> client_cert;
  scoped_refptr<SSLPrivateKey> client_private_key;
  ASSERT_TRUE(http_session_->ssl_client_context()->GetClientCertificate(
      host_port_pair_, &client_cert, &client_private_key));
  ASSERT_FALSE(client_cert);
  ASSERT_FALSE(client_private_key);

  const quiche::HttpHeaderBlock& response_headers =
      delegate->response_headers();
  EXPECT_EQ("200", response_headers.find(":status")->second);
  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
}

// Simulates user calling ReadData after END_STREAM has been received in
// BidirectionalStreamSpdyImpl.
TEST_F(BidirectionalStreamTest, TestReadDataAfterClose) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(kDefaultUrl, 1, LOWEST));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  const char* const kExtraResponseHeaders[] = {"header-name", "header-value"};
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(kExtraResponseHeaders, 1, 1));

  spdy::SpdySerializedFrame body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, false));
  // Last body frame has END_STREAM flag set.
  spdy::SpdySerializedFrame last_body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, true));

  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause.
      CreateMockRead(body_frame, 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4),  // Force a pause.
      CreateMockRead(body_frame, 5),
      CreateMockRead(last_body_frame, 6),
      MockRead(SYNCHRONOUS, 0, 7),
  };

  InitSession(reads, writes, SocketTag());

  auto request_info = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->end_stream_on_headers = true;
  request_info->priority = LOWEST;

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  // Create a MockTimer. Retain a raw pointer since the underlying
  // BidirectionalStreamImpl owns it.
  auto timer = std::make_unique<MockTimer>();
  MockTimer* timer_ptr = timer.get();
  auto delegate = std::make_unique<TestDelegateBase>(
      read_buffer.get(), kReadBufferSize, std::move(timer));
  delegate->set_do_not_start_read(true);

  delegate->Start(std::move(request_info), http_session_.get());

  // Write request, and deliver response headers.
  sequenced_data_->RunUntilPaused();
  EXPECT_FALSE(timer_ptr->IsRunning());
  // ReadData returns asynchronously because no data is buffered.
  int rv = delegate->ReadData();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Deliver a DATA frame.
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();
  timer_ptr->Fire();
  // Asynchronous completion callback is invoke.
  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(kUploadDataSize * 1,
            static_cast<int>(delegate->data_received().size()));

  // Deliver the rest. Note that user has not called a second ReadData.
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();
  // ReadData now. Read should complete synchronously.
  rv = delegate->ReadData();
  EXPECT_EQ(kUploadDataSize * 2, rv);
  rv = delegate->ReadData();
  EXPECT_THAT(rv, IsOk());  // EOF.

  const quiche::HttpHeaderBlock& response_headers =
      delegate->response_headers();
  EXPECT_EQ("200", response_headers.find(":status")->second);
  EXPECT_EQ("header-value", response_headers.find("header-name")->second);
  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ(CountWriteBytes(writes), delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), delegate->GetTotalReceivedBytes());
}

// Tests that the NetLog contains correct entries.
TEST_F(BidirectionalStreamTest, TestNetLogContainEntries) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize * 3, LOWEST, nullptr, 0));
  spdy::SpdySerializedFrame data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, kBodyDataString, /*fin=*/true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(data_frame, 3),
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame response_body_frame1(
      spdy_util_.ConstructSpdyDataFrame(1, false));
  spdy::SpdySerializedFrame response_body_frame2(
      spdy_util_.ConstructSpdyDataFrame(1, false));

  quiche::HttpHeaderBlock trailers;
  trailers["foo"] = "bar";
  spdy::SpdySerializedFrame response_trailers(
      spdy_util_.ConstructSpdyResponseHeaders(1, std::move(trailers), true));

  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause.
      CreateMockRead(response_body_frame1, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 5),  // Force a pause.
      CreateMockRead(response_body_frame2, 6),
      CreateMockRead(response_trailers, 7),
      MockRead(ASYNC, 0, 8),
  };

  InitSession(reads, writes, SocketTag());

  auto request_info = std::make_unique<BidirectionalStreamRequestInfo>();
  request_info->method = "POST";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->extra_headers.SetHeader(
      HttpRequestHeaders::kContentLength,
      base::NumberToString(kBodyDataSize * 3));

  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  auto timer = std::make_unique<MockTimer>();
  MockTimer* timer_ptr = timer.get();
  auto delegate = std::make_unique<TestDelegateBase>(
      read_buffer.get(), kReadBufferSize, std::move(timer));
  delegate->set_do_not_start_read(true);
  delegate->Start(std::move(request_info), http_session_.get());
  // Send the request and receive response headers.
  sequenced_data_->RunUntilPaused();
  EXPECT_FALSE(timer_ptr->IsRunning());

  scoped_refptr<StringIOBuffer> buf =
      base::MakeRefCounted<StringIOBuffer>(kBodyDataString);
  // Send a DATA frame.
  delegate->SendData(buf, buf->size(), true);
  // ReadData returns asynchronously because no data is buffered.
  int rv = delegate->ReadData();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Deliver the first DATA frame.
  sequenced_data_->Resume();
  sequenced_data_->RunUntilPaused();
  // |sequenced_data_| is now stopped after delivering first DATA frame but
  // before the second DATA frame.
  // Fire the timer to allow the first ReadData to complete asynchronously.
  timer_ptr->Fire();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, delegate->on_data_read_count());

  // Now let |sequenced_data_| run until completion.
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();
  // All data has been delivered, and OnClosed() has been invoked.
  // Read now, and it should complete synchronously.
  rv = delegate->ReadData();
  EXPECT_EQ(kUploadDataSize, rv);
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(1, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ("bar", delegate->trailers().find("foo")->second);
  EXPECT_EQ(CountWriteBytes(writes), delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), delegate->GetTotalReceivedBytes());

  // Destroy the delegate will destroy the stream, so we can get an end event
  // for BIDIRECTIONAL_STREAM_ALIVE.
  delegate.reset();
  auto entries = net_log_observer_.GetEntries();

  size_t index = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::BIDIRECTIONAL_STREAM_ALIVE,
      NetLogEventPhase::BEGIN);
  // HTTP_STREAM_REQUEST is nested inside in BIDIRECTIONAL_STREAM_ALIVE.
  index = ExpectLogContainsSomewhere(entries, index,
                                     NetLogEventType::HTTP_STREAM_REQUEST,
                                     NetLogEventPhase::BEGIN);
  index = ExpectLogContainsSomewhere(entries, index,
                                     NetLogEventType::HTTP_STREAM_REQUEST,
                                     NetLogEventPhase::END);
  // Headers received should happen after HTTP_STREAM_REQUEST.
  index = ExpectLogContainsSomewhere(
      entries, index, NetLogEventType::BIDIRECTIONAL_STREAM_RECV_HEADERS,
      NetLogEventPhase::NONE);
  // Trailers received should happen after headers received. It might happen
  // before the reads complete.
  ExpectLogContainsSomewhere(
      entries, index, NetLogEventType::BIDIRECTIONAL_STREAM_RECV_TRAILERS,
      NetLogEventPhase::NONE);
  index = ExpectLogContainsSomewhere(
      entries, index, NetLogEventType::BIDIRECTIONAL_STREAM_SENDV_DATA,
      NetLogEventPhase::NONE);
  index = ExpectLogContainsSomewhere(
      entries, index, NetLogEventType::BIDIRECTIONAL_STREAM_READ_DATA,
      NetLogEventPhase::NONE);
  EXPECT_EQ(ERR_IO_PENDING, GetIntegerValueFromParams(entries[index], "rv"));

  // Sent bytes. Sending data is always asynchronous.
  index = ExpectLogContainsSomewhere(
      entries, index, NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_SENT,
      NetLogEventPhase::NONE);
  EXPECT_EQ(NetLogSourceType::BIDIRECTIONAL_STREAM, entries[index].source.type);
  // Received bytes for asynchronous read.
  index = ExpectLogContainsSomewhere(
      entries, index, NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_RECEIVED,
      NetL
"""


```