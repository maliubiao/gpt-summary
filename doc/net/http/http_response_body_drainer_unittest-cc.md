Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Understand the Goal:** The core request is to understand the functionality of the `http_response_body_drainer_unittest.cc` file within the Chromium network stack. This immediately signals that the file's purpose is *testing* a component called `HttpResponseBodyDrainer`.

2. **Identify the Tested Class:** The `#include "net/http/http_response_body_drainer.h"` line is the most crucial piece of information for determining the target of the tests. This tells us we're dealing with the `HttpResponseBodyDrainer` class.

3. **Infer the Tested Class's Purpose:**  The name "HttpResponseBodyDrainer" strongly suggests its function: to consume and discard the body of an HTTP response. The "drainer" analogy is quite apt. Why would we want to do this?  Likely scenarios include:
    * Closing a connection gracefully when we don't need the body.
    * Ensuring the TCP connection can be reused.
    * Handling error scenarios where the response body might still be arriving.

4. **Examine the Test Structure (GTest):**  The presence of `#include "testing/gtest/include/gtest/gtest.h"` indicates the use of Google Test framework. This means we should look for `TEST_F` macros, which define individual test cases. The `HttpResponseBodyDrainerTest` class acts as the test fixture, setting up the necessary environment for each test.

5. **Analyze Individual Test Cases:**  Go through each `TEST_F` and try to understand what aspect of `HttpResponseBodyDrainer` is being tested:
    * `DrainBodySyncSingleOK`, `DrainBodySyncOK`, `DrainBodyAsyncOK`:  These test successful draining under synchronous and asynchronous read scenarios, with different numbers of data chunks. "OK" likely means the drainer completes without error and allows connection reuse.
    * `DrainBodyAsyncEmptyChunk`, `DrainBodySyncEmptyChunk`:  These focus on handling the end-of-body marker (a zero-sized chunk in chunked encoding).
    * `DrainBodySizeEqualsDrainBuffer`: Checks if draining works correctly when the body size is exactly the buffer size used by the drainer.
    * `DrainBodyTimeOut`:  Tests the drainer's behavior when reading from the stream stalls indefinitely. This likely simulates a network issue. The expectation is likely that the connection is *not* reusable.
    * `CancelledBySession`:  Examines the scenario where the `HttpNetworkSession` itself cancels the draining process. This implies the drainer needs to handle being destroyed mid-operation.
    * `DrainBodyTooLarge`: Tests what happens if the response body is larger than the drainer's buffer. This likely results in the connection not being reusable.
    * `DrainBodyCantReuse`:  Explicitly tests the case where the underlying `HttpStream` indicates that the connection cannot be reused.

6. **Identify Dependencies and Mocking:**  The code uses a `MockHttpStream`. This is a common practice in unit testing to isolate the `HttpResponseBodyDrainer` from the complexities of a real HTTP stream. Pay attention to how the mock stream is configured in each test (e.g., `set_num_chunks`, `set_sync`, `set_stall_reads_forever`). This reveals the specific conditions being tested.

7. **Look for Interaction with `HttpNetworkSession`:** The tests use `session_->StartResponseDrainer(std::move(drainer_))`. This is the primary way the drainer is initiated within the context of an `HttpNetworkSession`.

8. **Analyze the Mock Stream's Logic:**  Understand how `MockHttpStream::ReadResponseBody` and `MockHttpStream::Close` are implemented. The `CloseResultWaiter` is used to synchronize the test with the asynchronous `Close` call. The mock stream controls the flow of data and simulates different scenarios (e.g., synchronous vs. asynchronous reads, number of chunks, stalling).

9. **Consider Javascript Relevance (and the Lack Thereof in This Case):**  The prompt asks about connections to JavaScript. While the *purpose* of draining HTTP bodies is relevant to web browsers (which involve JavaScript), the *implementation* in this specific C++ file is at a lower level. There's no direct JavaScript interaction in the *code itself*. However, the *reason* for this code's existence is to support higher-level browser functionalities, including those driven by JavaScript making HTTP requests.

10. **Infer User/Programming Errors:** Think about how a developer might misuse or encounter issues related to body draining. Not draining the body when required can lead to connection leaks or prevent reuse. Incorrectly assuming the body is always available can also cause problems.

11. **Trace User Actions (Conceptual):**  Consider how a user's actions in a browser might lead to this code being executed. Any time a browser receives an HTTP response and doesn't need to process the full body (e.g., a HEAD request, a connection being closed prematurely), the body drainer might be used.

12. **Formulate Assumptions and Outputs:**  For each test case, consider the *setup* of the mock stream as the "input" and the result of `result_waiter_.WaitForResult()` as the "output."  This helps formalize the logic being tested.

13. **Structure the Answer:** Organize the findings into logical sections, covering functionality, JavaScript relevance, logic inference, common errors, and debugging. Use clear and concise language. Provide specific examples from the code to support the explanations.

By following this structured approach, one can effectively analyze and understand the functionality of even relatively complex C++ unit test files like this one.
这个文件 `net/http/http_response_body_drainer_unittest.cc` 是 Chromium 网络栈中的一个单元测试文件，它的主要功能是测试 `HttpResponseBodyDrainer` 类的行为。 `HttpResponseBodyDrainer` 的作用是在 HTTP 响应体不需要被完全读取时，负责高效地读取并丢弃剩余的响应体数据，以便可以复用底层的 TCP 连接。

以下是这个文件的功能点的详细解释：

**1. 测试 `HttpResponseBodyDrainer` 的基本功能:**

*   **成功 Drain (同步和异步):** 测试在正常情况下，`HttpResponseBodyDrainer` 能够成功读取并丢弃响应体数据，并且允许连接被复用。测试了同步和异步两种读取模式。
*   **处理空 Chunk:** 测试当响应体使用 chunked 编码，并且最后一个 chunk 是 0 字节时，`HttpResponseBodyDrainer` 能否正确处理。
*   **Drain 大小等于缓冲区大小:** 测试当响应体大小恰好等于 `HttpResponseBodyDrainer` 的内部缓冲区大小时，能否正常工作。

**2. 测试 `HttpResponseBodyDrainer` 的错误处理和边缘情况:**

*   **超时 (Timeout):** 测试当底层 `HttpStream` 的读取操作一直阻塞时，`HttpResponseBodyDrainer` 是否会按照预期，阻止连接被复用。
*   **被 Session 取消 (CancelledBySession):** 测试当 `HttpNetworkSession` 决定取消 drain 操作时，`HttpResponseBodyDrainer` 的行为。这通常发生在会话被提前关闭的情况下。
*   **响应体过大 (DrainBodyTooLarge):** 测试当响应体的大小超过 `HttpResponseBodyDrainer` 的设计处理能力时，是否会阻止连接被复用。
*   **连接不可复用 (DrainBodyCantReuse):** 测试当底层的 `HttpStream` 指示连接不可复用时，`HttpResponseBodyDrainer` 的行为。

**3. 使用 Mock 对象进行隔离测试:**

*   为了独立地测试 `HttpResponseBodyDrainer`，该文件使用了 `MockHttpStream` 模拟了真实的 `HttpStream` 的行为。这样可以精确控制数据读取的节奏、返回的数据量以及模拟各种错误情况。

**与 JavaScript 的关系 (间接):**

`HttpResponseBodyDrainer` 本身是 C++ 代码，并不直接与 JavaScript 交互。然而，它的功能对于浏览器执行 JavaScript 发起的网络请求至关重要。

当 JavaScript 通过 `fetch` API 或 `XMLHttpRequest` 发起一个 HTTP 请求，并且浏览器决定不需要完全读取响应体时 (例如，因为请求方法是 HEAD，或者用户关闭了页面)，`HttpResponseBodyDrainer` 就会被调用。它的作用是确保底层的连接可以被安全地复用，以提高后续请求的效率。

**举例说明:**

假设一个 JavaScript 应用程序发起了一个 HEAD 请求来检查某个 URL 是否存在。HEAD 请求的响应体通常为空或者很小，应用程序并不需要读取响应体的内容。在这种情况下，浏览器网络栈会使用 `HttpResponseBodyDrainer` 来快速丢弃响应体（即使服务器可能发送了一些数据），并释放连接以便后续请求可以重用。

**假设输入与输出 (逻辑推理):**

以下基于某些测试用例进行假设输入和输出的推理：

*   **测试用例:** `DrainBodySyncOK`
    *   **假设输入:** `MockHttpStream` 配置为同步读取 3 个 chunk 的数据。
    *   **预期输出:** `result_waiter_.WaitForResult()` 返回 `false`，表示 drain 操作成功，并且连接可以被复用。因为 `MockHttpStream::Close` 方法中 `set_result(not_reusable)`，而这里期望可复用，所以 `not_reusable` 是 `false`。
*   **测试用例:** `DrainBodyTimeOut`
    *   **假设输入:** `MockHttpStream` 配置为读取 2 个 chunk，但设置了 `stall_reads_forever()`，导致读取操作永远不会完成。
    *   **预期输出:** `result_waiter_.WaitForResult()` 返回 `true`，表示 drain 操作因为超时而失败，并且连接不能被复用。
*   **测试用例:** `DrainBodyTooLarge`
    *   **假设输入:** `MockHttpStream` 配置为读取比 `HttpResponseBodyDrainer` 缓冲区能容纳的更多 chunk 的数据。
    *   **预期输出:** `result_waiter_.WaitForResult()` 返回 `true`，表示 drain 操作因为响应体过大而导致连接不能被复用。

**用户或编程常见的使用错误:**

尽管用户不会直接与 `HttpResponseBodyDrainer` 交互，但编程错误可能导致它被不正确地使用或依赖：

*   **在需要读取响应体的情况下错误地使用了 Drainer:** 如果应用程序预期接收响应体的数据，但网络栈错误地认为不需要读取并使用了 `HttpResponseBodyDrainer`，则会导致数据丢失。这通常是网络栈内部逻辑错误，而不是用户直接操作错误。
*   **过早关闭连接:** 如果上层代码在 `HttpResponseBodyDrainer` 完成 draining 之前就强制关闭了连接，可能会导致资源泄漏或者连接状态不一致。

**用户操作如何一步步到达这里 (调试线索):**

当需要调试与 `HttpResponseBodyDrainer` 相关的问题时，可以考虑以下用户操作路径：

1. **用户发起一个 HTTP 请求:** 例如，在浏览器地址栏输入 URL，点击链接，或者 JavaScript 代码执行 `fetch` 或 `XMLHttpRequest`。
2. **网络栈接收到响应头:** 浏览器接收到服务器返回的 HTTP 响应头。
3. **决定是否需要读取响应体:**  网络栈根据请求方法（如 HEAD）、响应状态码、连接状态等因素判断是否需要读取响应体。如果不需要，或者由于某些原因需要中断响应体的接收。
4. **创建 `HttpResponseBodyDrainer`:** 如果决定不完全读取响应体，`HttpNetworkSession` 会创建一个 `HttpResponseBodyDrainer` 对象，并将其与当前的 `HttpStream` 关联。
5. **启动 Drain 操作:** `HttpNetworkSession::StartResponseDrainer` 被调用，开始 drain 操作。`HttpResponseBodyDrainer` 会异步地从 `HttpStream` 读取数据并丢弃。
6. **等待 Drain 完成或发生错误:** `HttpResponseBodyDrainer` 会持续读取直到所有数据被读取完毕，或者发生错误（例如超时）。
7. **连接标记为可复用或不可复用:** 根据 drain 操作的结果，底层的 TCP 连接会被标记为可以复用或者需要关闭。

**调试线索:**

*   如果在网络请求过程中发现连接没有被复用，可以检查是否是因为响应体没有被正确 drain 导致的。
*   可以通过网络抓包工具（如 Wireshark）观察连接的关闭和复用情况。
*   在 Chromium 源码中设置断点，例如在 `HttpNetworkSession::StartResponseDrainer` 和 `HttpResponseBodyDrainer` 的 `ReadMore` 方法中，可以观察 drain 操作的执行流程。
*   查看 NetLog 可以提供关于网络事件的详细信息，包括 drain 操作的开始和结束。

总而言之，`net/http/http_response_body_drainer_unittest.cc` 通过各种测试用例，确保 `HttpResponseBodyDrainer` 能够可靠地执行其职责，即在不需要响应体内容时，高效地清理连接，为后续的网络请求提供更好的性能。

Prompt: 
```
这是目录为net/http/http_response_body_drainer_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_response_body_drainer.h"

#include <stdint.h>

#include <cstring>
#include <set>
#include <string_view>
#include <utility>

#include "base/compiler_specific.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/no_destructor.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "net/base/completion_once_callback.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/http/http_network_session.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_stream.h"
#include "net/http/transport_security_state.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/quic/quic_context.h"
#include "net/socket/socket_test_util.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/test/test_with_task_environment.h"
#include "net/url_request/static_http_user_agent_settings.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

const int kMagicChunkSize = 1024;
static_assert((HttpResponseBodyDrainer::kDrainBodyBufferSize %
               kMagicChunkSize) == 0,
              "chunk size needs to divide evenly into buffer size");

class CloseResultWaiter {
 public:
  CloseResultWaiter() = default;

  CloseResultWaiter(const CloseResultWaiter&) = delete;
  CloseResultWaiter& operator=(const CloseResultWaiter&) = delete;

  int WaitForResult() {
    CHECK(!waiting_for_result_);
    while (!have_result_) {
      waiting_for_result_ = true;
      loop_.Run();
      waiting_for_result_ = false;
    }
    return result_;
  }

  void set_result(bool result) {
    result_ = result;
    have_result_ = true;
    if (waiting_for_result_) {
      loop_.Quit();
    }
  }

 private:
  int result_ = false;
  bool have_result_ = false;
  bool waiting_for_result_ = false;
  base::RunLoop loop_;
};

class MockHttpStream : public HttpStream {
 public:
  explicit MockHttpStream(CloseResultWaiter* result_waiter)
      : result_waiter_(result_waiter) {}

  MockHttpStream(const MockHttpStream&) = delete;
  MockHttpStream& operator=(const MockHttpStream&) = delete;

  ~MockHttpStream() override = default;

  // HttpStream implementation.
  void RegisterRequest(const HttpRequestInfo* request_info) override {}
  int InitializeStream(bool can_send_early,
                       RequestPriority priority,
                       const NetLogWithSource& net_log,
                       CompletionOnceCallback callback) override {
    return ERR_UNEXPECTED;
  }
  int SendRequest(const HttpRequestHeaders& request_headers,
                  HttpResponseInfo* response,
                  CompletionOnceCallback callback) override {
    return ERR_UNEXPECTED;
  }
  int ReadResponseHeaders(CompletionOnceCallback callback) override {
    return ERR_UNEXPECTED;
  }

  bool IsConnectionReused() const override { return false; }
  void SetConnectionReused() override {}
  bool CanReuseConnection() const override { return can_reuse_connection_; }
  int64_t GetTotalReceivedBytes() const override { return 0; }
  int64_t GetTotalSentBytes() const override { return 0; }
  bool GetAlternativeService(
      AlternativeService* alternative_service) const override {
    return false;
  }
  void GetSSLInfo(SSLInfo* ssl_info) override {}
  int GetRemoteEndpoint(IPEndPoint* endpoint) override {
    return ERR_UNEXPECTED;
  }

  // Mocked API
  int ReadResponseBody(IOBuffer* buf,
                       int buf_len,
                       CompletionOnceCallback callback) override;
  void Close(bool not_reusable) override {
    CHECK(!closed_);
    closed_ = true;
    result_waiter_->set_result(not_reusable);
  }

  std::unique_ptr<HttpStream> RenewStreamForAuth() override { return nullptr; }

  bool IsResponseBodyComplete() const override { return is_complete_; }

  bool GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const override {
    return false;
  }

  void Drain(HttpNetworkSession*) override {}

  void PopulateNetErrorDetails(NetErrorDetails* details) override { return; }

  void SetPriority(RequestPriority priority) override {}

  const std::set<std::string>& GetDnsAliases() const override {
    static const base::NoDestructor<std::set<std::string>> nullset_result;
    return *nullset_result;
  }

  std::string_view GetAcceptChViaAlps() const override { return {}; }

  // Methods to tweak/observer mock behavior:
  void set_stall_reads_forever() { stall_reads_forever_ = true; }

  void set_num_chunks(int num_chunks) { num_chunks_ = num_chunks; }

  void set_sync() { is_sync_ = true; }

  void set_is_last_chunk_zero_size() { is_last_chunk_zero_size_ = true; }

  // Sets result value of CanReuseConnection. Defaults to true.
  void set_can_reuse_connection(bool can_reuse_connection) {
    can_reuse_connection_ = can_reuse_connection;
  }

  void SetRequestHeadersCallback(RequestHeadersCallback callback) override {}

 private:
  int ReadResponseBodyImpl(IOBuffer* buf, int buf_len);
  void CompleteRead();

  bool closed() const { return closed_; }

  const raw_ptr<CloseResultWaiter> result_waiter_;
  scoped_refptr<IOBuffer> user_buf_;
  CompletionOnceCallback callback_;
  int buf_len_ = 0;
  bool closed_ = false;
  bool stall_reads_forever_ = false;
  int num_chunks_ = 0;
  bool is_sync_ = false;
  bool is_last_chunk_zero_size_ = false;
  bool is_complete_ = false;
  bool can_reuse_connection_ = true;

  base::WeakPtrFactory<MockHttpStream> weak_factory_{this};
};

int MockHttpStream::ReadResponseBody(IOBuffer* buf,
                                     int buf_len,
                                     CompletionOnceCallback callback) {
  CHECK(!callback.is_null());
  CHECK(callback_.is_null());
  CHECK(buf);

  if (stall_reads_forever_)
    return ERR_IO_PENDING;

  if (is_complete_)
    return ERR_UNEXPECTED;

  if (!is_sync_) {
    user_buf_ = buf;
    buf_len_ = buf_len;
    callback_ = std::move(callback);
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&MockHttpStream::CompleteRead,
                                  weak_factory_.GetWeakPtr()));
    return ERR_IO_PENDING;
  } else {
    return ReadResponseBodyImpl(buf, buf_len);
  }
}

int MockHttpStream::ReadResponseBodyImpl(IOBuffer* buf, int buf_len) {
  if (is_last_chunk_zero_size_ && num_chunks_ == 1) {
    buf_len = 0;
  } else {
    if (buf_len > kMagicChunkSize)
      buf_len = kMagicChunkSize;
    std::memset(buf->data(), 1, buf_len);
  }
  num_chunks_--;
  if (!num_chunks_)
    is_complete_ = true;

  return buf_len;
}

void MockHttpStream::CompleteRead() {
  int result = ReadResponseBodyImpl(user_buf_.get(), buf_len_);
  user_buf_ = nullptr;
  std::move(callback_).Run(result);
}

class HttpResponseBodyDrainerTest : public TestWithTaskEnvironment {
 protected:
  HttpResponseBodyDrainerTest()
      : proxy_resolution_service_(
            ConfiguredProxyResolutionService::CreateDirect()),
        ssl_config_service_(std::make_unique<SSLConfigServiceDefaults>()),
        http_server_properties_(std::make_unique<HttpServerProperties>()),
        session_(CreateNetworkSession()),
        mock_stream_(new MockHttpStream(&result_waiter_)) {
    drainer_ = std::make_unique<HttpResponseBodyDrainer>(mock_stream_);
  }

  ~HttpResponseBodyDrainerTest() override = default;

  std::unique_ptr<HttpNetworkSession> CreateNetworkSession() {
    HttpNetworkSessionContext context;
    context.client_socket_factory = &socket_factory_;
    context.proxy_resolution_service = proxy_resolution_service_.get();
    context.ssl_config_service = ssl_config_service_.get();
    context.http_user_agent_settings = &http_user_agent_settings_;
    context.http_server_properties = http_server_properties_.get();
    context.cert_verifier = &cert_verifier_;
    context.transport_security_state = &transport_security_state_;
    context.quic_context = &quic_context_;
    return std::make_unique<HttpNetworkSession>(HttpNetworkSessionParams(),
                                                context);
  }

  std::unique_ptr<ProxyResolutionService> proxy_resolution_service_;
  std::unique_ptr<SSLConfigService> ssl_config_service_;
  StaticHttpUserAgentSettings http_user_agent_settings_ = {"*", "test-ua"};
  std::unique_ptr<HttpServerProperties> http_server_properties_;
  MockCertVerifier cert_verifier_;
  TransportSecurityState transport_security_state_;
  QuicContext quic_context_;
  MockClientSocketFactory socket_factory_;
  const std::unique_ptr<HttpNetworkSession> session_;
  CloseResultWaiter result_waiter_;
  const raw_ptr<MockHttpStream, AcrossTasksDanglingUntriaged>
      mock_stream_;  // Owned by |drainer_|.
  std::unique_ptr<HttpResponseBodyDrainer> drainer_;
};

TEST_F(HttpResponseBodyDrainerTest, DrainBodySyncSingleOK) {
  mock_stream_->set_num_chunks(1);
  mock_stream_->set_sync();
  session_->StartResponseDrainer(std::move(drainer_));
  EXPECT_FALSE(result_waiter_.WaitForResult());
}

TEST_F(HttpResponseBodyDrainerTest, DrainBodySyncOK) {
  mock_stream_->set_num_chunks(3);
  mock_stream_->set_sync();
  session_->StartResponseDrainer(std::move(drainer_));
  EXPECT_FALSE(result_waiter_.WaitForResult());
}

TEST_F(HttpResponseBodyDrainerTest, DrainBodyAsyncOK) {
  mock_stream_->set_num_chunks(3);
  session_->StartResponseDrainer(std::move(drainer_));
  EXPECT_FALSE(result_waiter_.WaitForResult());
}

// Test the case when the final chunk is 0 bytes. This can happen when
// the final 0-byte chunk of a chunk-encoded http response is read in a last
// call to ReadResponseBody, after all data were returned from HttpStream.
TEST_F(HttpResponseBodyDrainerTest, DrainBodyAsyncEmptyChunk) {
  mock_stream_->set_num_chunks(4);
  mock_stream_->set_is_last_chunk_zero_size();
  session_->StartResponseDrainer(std::move(drainer_));
  EXPECT_FALSE(result_waiter_.WaitForResult());
}

TEST_F(HttpResponseBodyDrainerTest, DrainBodySyncEmptyChunk) {
  mock_stream_->set_num_chunks(4);
  mock_stream_->set_sync();
  mock_stream_->set_is_last_chunk_zero_size();
  session_->StartResponseDrainer(std::move(drainer_));
  EXPECT_FALSE(result_waiter_.WaitForResult());
}

TEST_F(HttpResponseBodyDrainerTest, DrainBodySizeEqualsDrainBuffer) {
  mock_stream_->set_num_chunks(
      HttpResponseBodyDrainer::kDrainBodyBufferSize / kMagicChunkSize);
  session_->StartResponseDrainer(std::move(drainer_));
  EXPECT_FALSE(result_waiter_.WaitForResult());
}

TEST_F(HttpResponseBodyDrainerTest, DrainBodyTimeOut) {
  mock_stream_->set_num_chunks(2);
  mock_stream_->set_stall_reads_forever();
  session_->StartResponseDrainer(std::move(drainer_));
  EXPECT_TRUE(result_waiter_.WaitForResult());
}

TEST_F(HttpResponseBodyDrainerTest, CancelledBySession) {
  mock_stream_->set_num_chunks(2);
  mock_stream_->set_stall_reads_forever();
  session_->StartResponseDrainer(std::move(drainer_));
  // HttpNetworkSession should delete |drainer_|.
}

TEST_F(HttpResponseBodyDrainerTest, DrainBodyTooLarge) {
  int too_many_chunks =
      HttpResponseBodyDrainer::kDrainBodyBufferSize / kMagicChunkSize;
  too_many_chunks += 1;  // Now it's too large.

  mock_stream_->set_num_chunks(too_many_chunks);
  session_->StartResponseDrainer(std::move(drainer_));
  EXPECT_TRUE(result_waiter_.WaitForResult());
}

TEST_F(HttpResponseBodyDrainerTest, DrainBodyCantReuse) {
  mock_stream_->set_num_chunks(1);
  mock_stream_->set_can_reuse_connection(false);
  session_->StartResponseDrainer(std::move(drainer_));
  EXPECT_TRUE(result_waiter_.WaitForResult());
}

}  // namespace

}  // namespace net

"""

```