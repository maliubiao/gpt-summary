Response:
The user wants a summary of the functionality of the `net/spdy/spdy_network_transaction_unittest.cc` file.
I need to analyze the included headers and the structure of the test file to understand what it tests.

Based on the headers, this file is part of the Chromium network stack and specifically focuses on testing the `SpdyNetworkTransaction`. SPDY is the predecessor to HTTP/2.

Key aspects to cover:

1. **Primary Function:** Testing the behavior of `SpdyNetworkTransaction`.
2. **Relationship to Javascript:** Likely minimal, but needs to be explored. Network stack interactions are usually handled by the browser, which has Javascript components.
3. **Logical Reasoning:**  Test cases often involve setting up specific scenarios and asserting expected outcomes. I need to identify patterns in the test setup and assertions.
4. **User/Programming Errors:** Common misuses of the `SpdyNetworkTransaction` or related APIs are likely tested.
5. **User Journey to this Code:**  How does a user action trigger this code path? This involves understanding the overall network request lifecycle.
6. **Functionality of the First Part:** Based on the provided snippet, it seems to be setting up the test environment and defining basic test cases.

**Plan:**

1. **Analyze Imports:** List the key headers and what functionality they represent.
2. **Identify Test Fixture:** Describe the purpose of `SpdyNetworkTransactionTest`.
3. **Summarize Test Cases (so far):**  Focus on what the initial test cases are verifying (e.g., basic GET request).
4. **Consider Javascript Interaction:**  Think about how network requests initiated from Javascript would eventually reach this part of the code.
5. **Infer Logical Reasoning:**  Look for examples of setting up inputs (requests, mock data) and asserting outputs (response status, data).
6. **Speculate on User Errors:** Based on the tested functionality, what could a developer or user do wrong?
7. **Trace User Actions:** Outline a simplified path of a user action leading to network code execution.
这是 Chromium 网络栈中 `net/spdy/spdy_network_transaction_unittest.cc` 文件的第一部分，它的主要功能是 **测试 `SpdyNetworkTransaction` 类的各种行为和功能**。

以下是根据提供的代码片段进行的更详细的功能归纳：

**主要功能:**

* **单元测试 `SpdyNetworkTransaction`:**  这个文件包含了针对 `SpdyNetworkTransaction` 类的各种单元测试用例。`SpdyNetworkTransaction` 是 Chromium 网络栈中处理 SPDY (HTTP/2 的前身) 协议网络事务的核心类。
* **测试 SPDY 协议相关的网络交互:**  测试用例模拟了使用 SPDY 协议进行网络请求和响应的场景，包括发送请求头、接收响应头、传输数据等。
* **验证 `SpdyNetworkTransaction` 的正确性:**  测试用例验证了 `SpdyNetworkTransaction` 在各种情况下的行为是否符合预期，例如成功请求、错误处理、优先级设置、上传数据等。
* **模拟网络环境:**  使用了 `MockRead` 和 `MockWrite` 来模拟底层的网络 socket 的读取和写入操作，允许在不实际进行网络通信的情况下测试网络事务的逻辑。
* **测试不同的请求类型:**  测试了 GET 和 POST 请求，以及不同类型的 POST 请求，例如带有普通数据、文件数据和分块数据的请求。
* **测试连接管理:**  涉及到了 `SpdySession` 和 `SpdySessionPool` 的使用，间接测试了连接的建立、复用和关闭等行为。
* **测试优先级:**  包含了对请求优先级的设置和处理的测试，验证了高优先级的请求是否能够优先发送和处理。
* **测试推送 (Push) 功能 (虽然这段代码中没有直接体现，但作为 `spdy_network_transaction_unittest.cc` 的一部分，它很可能在其他部分涉及):**  SPDY 协议支持服务器向客户端推送资源，这个文件很可能包含对推送功能的测试。

**与 Javascript 的关系：**

`SpdyNetworkTransaction` 本身是用 C++ 实现的，直接与 Javascript 没有交互。但是，当 Javascript 代码发起一个网络请求 (例如使用 `fetch` API 或 `XMLHttpRequest`) 时，如果浏览器和服务器之间协商使用了 SPDY 或 HTTP/2 协议，那么底层的网络通信就会使用到 `SpdyNetworkTransaction`。

**举例说明:**

1. **Javascript 发起请求:**  用户在浏览器中执行 Javascript 代码，例如 `fetch('https://www.example.org/data')`。
2. **浏览器网络栈处理:** 浏览器网络栈接收到这个请求，并根据当前的网络状态和协议协商结果，决定使用 SPDY (或 HTTP/2) 进行通信。
3. **创建 `SpdyNetworkTransaction`:** 网络栈会创建 `SpdyNetworkTransaction` 的实例来处理这个 SPDY 请求。
4. **测试用例模拟:**  `spdy_network_transaction_unittest.cc` 中的测试用例，例如 `TEST_P(SpdyNetworkTransactionTest, Get)`，模拟了上述步骤中 `SpdyNetworkTransaction` 处理 GET 请求的过程，验证了请求头是否正确发送，响应头和数据是否正确接收。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* **测试用例:** `TEST_P(SpdyNetworkTransactionTest, Get)`
* **模拟请求:**  一个指向 `kDefaultUrl` 的 GET 请求。
* **模拟网络数据:**  `MockWrite` 定义了要发送的 SPDY HEADERS 帧，`MockRead` 定义了要接收的 SPDY HEADERS 帧和 DATA 帧。

**预期输出:**

* `helper.output().rv` (事务结果):  `OK` (表示请求成功)。
* `helper.output().status_line`: `"HTTP/1.1 200"` (表示 HTTP 状态码为 200 OK)。
* `helper.output().response_data`: `"hello!"` (表示接收到的响应体数据)。

**用户或编程常见的使用错误 (举例说明):**

* **未正确设置请求头:**  如果程序员在 Javascript 中使用 `fetch` 或 `XMLHttpRequest` 时，没有正确设置请求头，可能会导致服务器拒绝请求。`SpdyNetworkTransaction` 的测试会验证在各种头信息存在或缺失的情况下，请求是否能正确处理。例如，测试会检查必要的 Host 头是否被正确设置。
* **上传数据格式错误:**  在使用 POST 请求上传数据时，如果数据格式不正确 (例如 Content-Type 头与实际数据不符)，服务器可能会解析失败。`SpdyNetworkTransaction` 的测试会模拟各种上传场景，包括不同类型的上传数据流，来确保上传功能的正确性。
* **处理连接错误不当:**  在实际应用中，网络连接可能会中断或遇到错误。`SpdyNetworkTransaction` 的测试会模拟这些错误场景，验证上层代码是否能正确处理这些错误，例如通过 Javascript 的 `fetch` API 的 `catch` 块捕获错误。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中输入网址或点击链接:**  这会触发浏览器发起一个网络请求。
2. **浏览器解析 URL 并确定协议:** 浏览器会解析用户输入的 URL，并根据 URL 的协议 (HTTPS) 和与服务器的协商结果，决定使用 SPDY (或 HTTP/2)。
3. **创建 `URLRequest`:** 浏览器会创建一个 `URLRequest` 对象来表示这个网络请求。
4. **创建 `HttpTransaction`:**  `URLRequest` 会创建一个 `HttpTransaction` 的子类来处理具体的网络事务。如果使用了 SPDY，则会创建 `SpdyNetworkTransaction`。
5. **`SpdyNetworkTransaction` 处理请求:**  `SpdyNetworkTransaction` 负责与服务器建立连接 (如果需要)、发送请求头、接收响应头和数据。
6. **单元测试模拟上述过程:**  `spdy_network_transaction_unittest.cc` 中的测试用例通过模拟网络数据和调用 `SpdyNetworkTransaction` 的方法，来验证其在各个阶段的正确行为。在调试网络问题时，开发者可能会查看这些单元测试，以了解 `SpdyNetworkTransaction` 在特定情况下的预期行为。

**第一部分功能归纳:**

总而言之，这份代码的第一部分主要负责搭建 `SpdyNetworkTransaction` 的单元测试环境，并提供了一些基础的测试用例，例如测试基本的 GET 请求，以及设置请求优先级的功能。它为后续更复杂的 SPDY 网络事务行为的测试奠定了基础。

Prompt: 
```
这是目录为net/spdy/spdy_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共12部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include <cmath>
#include <string_view>
#include <utility>
#include <vector>

#include "base/containers/span.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/raw_ptr.h"
#include "base/numerics/safe_conversions.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/test_file_util.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/base/auth.h"
#include "net/base/chunked_upload_data_stream.h"
#include "net/base/completion_once_callback.h"
#include "net/base/elements_upload_data_stream.h"
#include "net/base/features.h"
#include "net/base/hex_utils.h"
#include "net/base/ip_endpoint.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/proxy_delegate.h"
#include "net/base/proxy_server.h"
#include "net/base/proxy_string_util.h"
#include "net/base/request_priority.h"
#include "net/base/schemeful_site.h"
#include "net/base/session_usage.h"
#include "net/base/test_proxy_delegate.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/base/upload_file_element_reader.h"
#include "net/dns/mock_host_resolver.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_auth_scheme.h"
#include "net/http/http_connection_info.h"
#include "net/http/http_network_session.h"
#include "net/http/http_network_session_peer.h"
#include "net/http/http_network_transaction.h"
#include "net/http/http_proxy_connect_job.h"
#include "net/http/http_response_info.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_transaction_test_util.h"
#include "net/http/test_upload_data_stream_not_allow_http1.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_tag.h"
#include "net/spdy/alps_decoder.h"
#include "net/spdy/buffered_spdy_framer.h"
#include "net/spdy/spdy_http_stream.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/spdy/spdy_session.h"
#include "net/spdy/spdy_session_pool.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_protocol.h"
#include "net/third_party/quiche/src/quiche/http2/test_tools/spdy_test_utils.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"
#include "net/websockets/websocket_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/platform_test.h"
#include "url/gurl.h"
#include "url/url_constants.h"

using net::test::IsError;
using net::test::IsOk;

//-----------------------------------------------------------------------------

namespace net {

namespace {

using testing::Each;
using testing::Eq;

const int32_t kBufferSize = SpdyHttpStream::kRequestBodyBufferSize;

struct TestParams {
  explicit TestParams(bool happy_eyeballs_v3_enabled)
      : happy_eyeballs_v3_enabled(happy_eyeballs_v3_enabled) {}

  bool happy_eyeballs_v3_enabled;
};

std::vector<TestParams> GetTestParams() {
  return {TestParams(/*happy_eyeballs_v3_enabled=*/false),
          TestParams(/*happy_eyeballs_v3_enabled=*/true)};
}

}  // namespace

const char kPushedUrl[] = "https://www.example.org/foo.dat";

class SpdyNetworkTransactionTest
    : public TestWithTaskEnvironment,
      public ::testing::WithParamInterface<TestParams> {
 protected:
  SpdyNetworkTransactionTest()
      : TestWithTaskEnvironment(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME),
        default_url_(kDefaultUrl),
        host_port_pair_(HostPortPair::FromURL(default_url_)),
        spdy_util_(/*use_priority_header=*/true) {
    std::vector<base::test::FeatureRef> enabled_features;
    std::vector<base::test::FeatureRef> disabled_features;

    if (HappyEyeballsV3Enabled()) {
      enabled_features.emplace_back(features::kHappyEyeballsV3);
    } else {
      disabled_features.emplace_back(features::kHappyEyeballsV3);
    }

    feature_list_.InitWithFeatures(enabled_features, disabled_features);
  }

  ~SpdyNetworkTransactionTest() override {
    // Clear raw_ptr to upload pointer prior to deleting it, to avoid triggering
    // danling raw_ptr warning.
    request_.upload_data_stream = nullptr;

    // UploadDataStream may post a deletion task back to the message loop on
    // destruction.
    upload_data_stream_.reset();
    base::RunLoop().RunUntilIdle();
  }

  void SetUp() override {
    request_.method = "GET";
    request_.url = GURL(kDefaultUrl);
    request_.traffic_annotation =
        net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  }

  struct TransactionHelperResult {
    int rv;
    std::string status_line;
    std::string response_data;
    HttpResponseInfo response_info;
  };

  // A helper class that handles all the initial npn/ssl setup.
  class NormalSpdyTransactionHelper {
   public:
    NormalSpdyTransactionHelper(
        const HttpRequestInfo& request,
        RequestPriority priority,
        const NetLogWithSource& log,
        std::unique_ptr<SpdySessionDependencies> session_deps)
        : request_(request),
          priority_(priority),
          session_deps_(session_deps.get() == nullptr
                            ? std::make_unique<SpdySessionDependencies>()
                            : std::move(session_deps)),
          log_(log) {
      session_deps_->net_log = log.net_log();
      session_ =
          SpdySessionDependencies::SpdyCreateSession(session_deps_.get());
    }

    ~NormalSpdyTransactionHelper() {
      // Any test which doesn't close the socket by sending it an EOF will
      // have a valid session left open, which leaks the entire session pool.
      // This is just fine - in fact, some of our tests intentionally do this
      // so that we can check consistency of the SpdySessionPool as the test
      // finishes.  If we had put an EOF on the socket, the SpdySession would
      // have closed and we wouldn't be able to check the consistency.

      // Forcefully close existing sessions here.
      session()->spdy_session_pool()->CloseAllSessions();
    }

    void RunPreTestSetup() {
      // We're now ready to use SSL-npn SPDY.
      trans_ =
          std::make_unique<HttpNetworkTransaction>(priority_, session_.get());
    }

    // Start the transaction, read some data, finish.
    void RunDefaultTest() {
      if (!StartDefaultTest()) {
        return;
      }
      FinishDefaultTest();
    }

    bool StartDefaultTest() {
      output_.rv = trans_->Start(&request_, callback_.callback(), log_);

      // We expect an IO Pending or some sort of error.
      EXPECT_LT(output_.rv, 0);
      return output_.rv == ERR_IO_PENDING;
    }

    void FinishDefaultTest() {
      output_.rv = callback_.WaitForResult();
      // Finish async network reads/writes.
      base::RunLoop().RunUntilIdle();
      if (output_.rv != OK) {
        session_->spdy_session_pool()->CloseCurrentSessions(ERR_ABORTED);
        return;
      }

      // Verify responses.
      const HttpResponseInfo* response = trans_->GetResponseInfo();
      ASSERT_TRUE(response);
      ASSERT_TRUE(response->headers);
      EXPECT_EQ(HttpConnectionInfo::kHTTP2, response->connection_info);
      EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
      EXPECT_TRUE(response->was_fetched_via_spdy);
      EXPECT_TRUE(response->was_alpn_negotiated);
      EXPECT_EQ("127.0.0.1", response->remote_endpoint.ToStringWithoutPort());
      EXPECT_EQ(443, response->remote_endpoint.port());
      output_.status_line = response->headers->GetStatusLine();
      output_.response_info = *response;  // Make a copy so we can verify.
      output_.rv = ReadTransaction(trans_.get(), &output_.response_data);
    }

    void FinishDefaultTestWithoutVerification() {
      output_.rv = callback_.WaitForResult();
      // Finish async network reads/writes.
      base::RunLoop().RunUntilIdle();
      if (output_.rv != OK) {
        session_->spdy_session_pool()->CloseCurrentSessions(ERR_ABORTED);
      }
    }

    void WaitForCallbackToComplete() { output_.rv = callback_.WaitForResult(); }

    // Most tests will want to call this function. In particular, the MockReads
    // should end with an empty read, and that read needs to be processed to
    // ensure proper deletion of the spdy_session_pool.
    void VerifyDataConsumed() {
      for (const SocketDataProvider* provider : data_vector_) {
        EXPECT_TRUE(provider->AllReadDataConsumed());
        EXPECT_TRUE(provider->AllWriteDataConsumed());
      }
    }

    // Occasionally a test will expect to error out before certain reads are
    // processed. In that case we want to explicitly ensure that the reads were
    // not processed.
    void VerifyDataNotConsumed() {
      for (const SocketDataProvider* provider : data_vector_) {
        EXPECT_FALSE(provider->AllReadDataConsumed());
        EXPECT_FALSE(provider->AllWriteDataConsumed());
      }
    }

    void RunToCompletion(SocketDataProvider* data) {
      RunPreTestSetup();
      AddData(data);
      RunDefaultTest();
      VerifyDataConsumed();
    }

    void RunToCompletionWithSSLData(
        SocketDataProvider* data,
        std::unique_ptr<SSLSocketDataProvider> ssl_provider) {
      RunPreTestSetup();
      AddDataWithSSLSocketDataProvider(data, std::move(ssl_provider));
      RunDefaultTest();
      VerifyDataConsumed();
    }

    void AddData(SocketDataProvider* data) {
      auto ssl_provider = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
      ssl_provider->ssl_info.cert =
          ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
      AddDataWithSSLSocketDataProvider(data, std::move(ssl_provider));
    }

    void AddDataWithSSLSocketDataProvider(
        SocketDataProvider* data,
        std::unique_ptr<SSLSocketDataProvider> ssl_provider) {
      data_vector_.push_back(data);
      if (ssl_provider->next_proto == kProtoUnknown) {
        ssl_provider->next_proto = kProtoHTTP2;
      }
      // Even when next_protos only includes HTTP1, `application_settions`
      // always includes the full list from the HttpNetworkSession. The
      // SSLClientSocket layer, which is mocked out in these tests, is the layer
      // responsible for only sending the relevant settings.
      ssl_provider->expected_application_settings = {{{kProtoHTTP2, {}}}};

      session_deps_->socket_factory->AddSSLSocketDataProvider(
          ssl_provider.get());
      ssl_vector_.push_back(std::move(ssl_provider));

      session_deps_->socket_factory->AddSocketDataProvider(data);
    }

    size_t GetSpdySessionCount() {
      std::unique_ptr<base::Value> value(
          session_->spdy_session_pool()->SpdySessionPoolInfoToValue());
      CHECK(value && value->is_list());
      return value->GetList().size();
    }

    HttpNetworkTransaction* trans() { return trans_.get(); }
    void ResetTrans() { trans_.reset(); }
    const TransactionHelperResult& output() { return output_; }
    HttpNetworkSession* session() const { return session_.get(); }
    SpdySessionDependencies* session_deps() { return session_deps_.get(); }

   private:
    typedef std::vector<raw_ptr<SocketDataProvider>> DataVector;
    typedef std::vector<std::unique_ptr<SSLSocketDataProvider>> SSLVector;
    typedef std::vector<std::unique_ptr<SocketDataProvider>> AlternateVector;
    const HttpRequestInfo request_;
    const RequestPriority priority_;
    std::unique_ptr<SpdySessionDependencies> session_deps_;
    std::unique_ptr<HttpNetworkSession> session_;
    TransactionHelperResult output_;
    SSLVector ssl_vector_;
    TestCompletionCallback callback_;
    std::unique_ptr<HttpNetworkTransaction> trans_;
    DataVector data_vector_;
    const NetLogWithSource log_;
  };

  void ConnectStatusHelperWithExpectedStatus(const MockRead& status,
                                             int expected_status);

  void ConnectStatusHelper(const MockRead& status);

  [[nodiscard]] HttpRequestInfo CreateGetPushRequest() const {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL(kPushedUrl);
    request.traffic_annotation =
        net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
    return request;
  }

  void UsePostRequest() {
    ASSERT_FALSE(upload_data_stream_);
    std::vector<std::unique_ptr<UploadElementReader>> element_readers;
    element_readers.push_back(std::make_unique<UploadBytesElementReader>(
        base::byte_span_from_cstring(kUploadData)));
    upload_data_stream_ = std::make_unique<ElementsUploadDataStream>(
        std::move(element_readers), 0);

    request_.method = "POST";
    request_.upload_data_stream = upload_data_stream_.get();
  }

  void UseFilePostRequest() {
    ASSERT_FALSE(upload_data_stream_);
    base::FilePath file_path;
    CHECK(base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &file_path));
    CHECK(base::WriteFile(file_path, kUploadData));

    std::vector<std::unique_ptr<UploadElementReader>> element_readers;
    element_readers.push_back(std::make_unique<UploadFileElementReader>(
        base::SingleThreadTaskRunner::GetCurrentDefault().get(), file_path, 0,
        kUploadDataSize, base::Time()));
    upload_data_stream_ = std::make_unique<ElementsUploadDataStream>(
        std::move(element_readers), 0);

    request_.method = "POST";
    request_.upload_data_stream = upload_data_stream_.get();
    request_.traffic_annotation =
        net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  }

  void UseUnreadableFilePostRequest() {
    ASSERT_FALSE(upload_data_stream_);
    base::FilePath file_path;
    CHECK(base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &file_path));
    CHECK(base::WriteFile(file_path, kUploadData));
    CHECK(base::MakeFileUnreadable(file_path));

    std::vector<std::unique_ptr<UploadElementReader>> element_readers;
    element_readers.push_back(std::make_unique<UploadFileElementReader>(
        base::SingleThreadTaskRunner::GetCurrentDefault().get(), file_path, 0,
        kUploadDataSize, base::Time()));
    upload_data_stream_ = std::make_unique<ElementsUploadDataStream>(
        std::move(element_readers), 0);

    request_.method = "POST";
    request_.upload_data_stream = upload_data_stream_.get();
  }

  void UseComplexPostRequest() {
    ASSERT_FALSE(upload_data_stream_);
    static constexpr size_t kFileRangeOffset = 1;
    static constexpr size_t kFileRangeLength = 3;
    CHECK_LT(static_cast<int>(kFileRangeOffset + kFileRangeLength),
             kUploadDataSize);

    base::FilePath file_path;
    CHECK(base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &file_path));
    CHECK(base::WriteFile(file_path, kUploadData));

    std::vector<std::unique_ptr<UploadElementReader>> element_readers;
    element_readers.push_back(std::make_unique<UploadBytesElementReader>(
        base::byte_span_from_cstring(kUploadData).first<kFileRangeOffset>()));
    element_readers.push_back(std::make_unique<UploadFileElementReader>(
        base::SingleThreadTaskRunner::GetCurrentDefault().get(), file_path,
        kFileRangeOffset, kFileRangeLength, base::Time()));
    element_readers.push_back(std::make_unique<UploadBytesElementReader>(
        base::byte_span_from_cstring(kUploadData)
            .subspan<kFileRangeOffset + kFileRangeLength>()));
    upload_data_stream_ = std::make_unique<ElementsUploadDataStream>(
        std::move(element_readers), 0);

    request_.method = "POST";
    request_.upload_data_stream = upload_data_stream_.get();
  }

  void UseChunkedPostRequest() {
    ASSERT_FALSE(upload_chunked_data_stream_);
    upload_chunked_data_stream_ = std::make_unique<ChunkedUploadDataStream>(0);
    request_.method = "POST";
    request_.upload_data_stream = upload_chunked_data_stream_.get();
  }

  // Read the result of a particular transaction, knowing that we've got
  // multiple transactions in the read pipeline; so as we read, we may have
  // to skip over data destined for other transactions while we consume
  // the data for |trans|.
  int ReadResult(HttpNetworkTransaction* trans, std::string* result) {
    const int kSize = 3000;

    int bytes_read = 0;
    scoped_refptr<IOBufferWithSize> buf =
        base::MakeRefCounted<IOBufferWithSize>(kSize);
    TestCompletionCallback callback;
    while (true) {
      int rv = trans->Read(buf.get(), kSize, callback.callback());
      if (rv == ERR_IO_PENDING) {
        rv = callback.WaitForResult();
      } else if (rv <= 0) {
        break;
      }
      result->append(buf->data(), rv);
      bytes_read += rv;
    }
    return bytes_read;
  }

  void VerifyStreamsClosed(const NormalSpdyTransactionHelper& helper) {
    // This lengthy block is reaching into the pool to dig out the active
    // session.  Once we have the session, we verify that the streams are
    // all closed and not leaked at this point.
    SpdySessionKey key(
        HostPortPair::FromURL(request_.url), PRIVACY_MODE_DISABLED,
        ProxyChain::Direct(), SessionUsage::kDestination, SocketTag(),
        request_.network_anonymization_key, SecureDnsPolicy::kAllow,
        /*disable_cert_verification_network_fetches=*/false);
    HttpNetworkSession* session = helper.session();
    base::WeakPtr<SpdySession> spdy_session =
        session->spdy_session_pool()->FindAvailableSession(
            key, /* enable_ip_based_pooling = */ true,
            /* is_websocket = */ false, log_);
    ASSERT_TRUE(spdy_session);
    EXPECT_EQ(0u, num_active_streams(spdy_session));
  }

  static void DeleteSessionCallback(NormalSpdyTransactionHelper* helper,
                                    int result) {
    helper->ResetTrans();
  }

  static void StartTransactionCallback(HttpNetworkSession* session,
                                       GURL url,
                                       NetLogWithSource log,
                                       int result) {
    HttpRequestInfo request;
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session);
    TestCompletionCallback callback;
    request.method = "GET";
    request.url = url;
    request.traffic_annotation =
        net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
    int rv = trans.Start(&request, callback.callback(), log);
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    callback.WaitForResult();
  }

  ChunkedUploadDataStream* upload_chunked_data_stream() {
    return upload_chunked_data_stream_.get();
  }

  size_t num_active_streams(base::WeakPtr<SpdySession> session) {
    return session->active_streams_.size();
  }

  static spdy::SpdyStreamId spdy_stream_hi_water_mark(
      base::WeakPtr<SpdySession> session) {
    return session->stream_hi_water_mark_;
  }

  base::RepeatingClosure FastForwardByCallback(base::TimeDelta delta) {
    return base::BindRepeating(&SpdyNetworkTransactionTest::FastForwardBy,
                               base::Unretained(this), delta);
  }

  bool HappyEyeballsV3Enabled() const {
    return GetParam().happy_eyeballs_v3_enabled;
  }

  const GURL default_url_;
  const HostPortPair host_port_pair_;

  const NetLogWithSource log_;
  std::unique_ptr<ChunkedUploadDataStream> upload_chunked_data_stream_;
  std::unique_ptr<UploadDataStream> upload_data_stream_;
  HttpRequestInfo request_;
  SpdyTestUtil spdy_util_;

  base::ScopedTempDir temp_dir_;
  base::test::ScopedFeatureList feature_list_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         SpdyNetworkTransactionTest,
                         testing::ValuesIn(GetTestParams()));

// Verify HttpNetworkTransaction constructor.
TEST_P(SpdyNetworkTransactionTest, Constructor) {
  auto session_deps = std::make_unique<SpdySessionDependencies>();
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(session_deps.get()));
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
}

TEST_P(SpdyNetworkTransactionTest, Get) {
  // Construct the request.
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

TEST_P(SpdyNetworkTransactionTest, SetPriority) {
  for (bool set_priority_before_starting_transaction : {true, false}) {
    SpdyTestUtil spdy_test_util(/*use_priority_header=*/true);
    spdy::SpdySerializedFrame req(
        spdy_test_util.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
    MockWrite writes[] = {CreateMockWrite(req, 0)};

    spdy::SpdySerializedFrame resp(
        spdy_test_util.ConstructSpdyGetReply(nullptr, 0, 1));
    spdy::SpdySerializedFrame body(
        spdy_test_util.ConstructSpdyDataFrame(1, true));
    MockRead reads[] = {CreateMockRead(resp, 1), CreateMockRead(body, 2),
                        MockRead(ASYNC, 0, 3)};

    SequencedSocketData data(reads, writes);
    NormalSpdyTransactionHelper helper(request_, HIGHEST, log_, nullptr);
    helper.RunPreTestSetup();
    helper.AddData(&data);

    if (set_priority_before_starting_transaction) {
      helper.trans()->SetPriority(LOWEST);
      EXPECT_TRUE(helper.StartDefaultTest());
    } else {
      EXPECT_TRUE(helper.StartDefaultTest());
      helper.trans()->SetPriority(LOWEST);
    }

    helper.FinishDefaultTest();
    helper.VerifyDataConsumed();

    TransactionHelperResult out = helper.output();
    EXPECT_THAT(out.rv, IsOk());
    EXPECT_EQ("HTTP/1.1 200", out.status_line);
    EXPECT_EQ("hello!", out.response_data);
  }
}

// Test that changing the request priority of an existing stream triggers
// sending PRIORITY frames in case there are multiple open streams and their
// relative priorities change.
TEST_P(SpdyNetworkTransactionTest, SetPriorityOnExistingStream) {
  const char* kUrl2 = "https://www.example.org/bar";

  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, HIGHEST));
  spdy::SpdySerializedFrame req2(spdy_util_.ConstructSpdyGet(kUrl2, 3, MEDIUM));
  spdy::SpdySerializedFrame priority1(
      spdy_util_.ConstructSpdyPriority(3, 0, MEDIUM, true));
  spdy::SpdySerializedFrame priority2(
      spdy_util_.ConstructSpdyPriority(1, 3, LOWEST, true));
  MockWrite writes[] = {CreateMockWrite(req1, 0), CreateMockWrite(req2, 2),
                        CreateMockWrite(priority1, 4),
                        CreateMockWrite(priority2, 5)};

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead reads[] = {CreateMockRead(resp1, 1), CreateMockRead(resp2, 3),
                      CreateMockRead(body1, 6), CreateMockRead(body2, 7),
                      MockRead(ASYNC, 0, 8)};

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, HIGHEST, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  EXPECT_TRUE(helper.StartDefaultTest());

  // Open HTTP/2 connection and create first stream.
  base::RunLoop().RunUntilIdle();

  HttpNetworkTransaction trans2(MEDIUM, helper.session());
  HttpRequestInfo request2;
  request2.url = GURL(kUrl2);
  request2.method = "GET";
  request2.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  TestCompletionCallback callback2;
  int rv = trans2.Start(&request2, callback2.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Create second stream.
  base::RunLoop().RunUntilIdle();

  // First request has HIGHEST priority, second request has MEDIUM priority.
  // Changing the priority of the first request to LOWEST changes their order,
  // and therefore triggers sending PRIORITY frames.
  helper.trans()->SetPriority(LOWEST);

  helper.FinishDefaultTest();
  helper.VerifyDataConsumed();

  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);

  rv = callback2.WaitForResult();
  ASSERT_THAT(rv, IsOk());
  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ(HttpConnectionInfo::kHTTP2, response2->connection_info);
  EXPECT_EQ("HTTP/1.1 200", response2->headers->GetStatusLine());
}

// Create two requests: a lower priority one first, then a higher priority one.
// Test that the second request gets sent out first.
TEST_P(SpdyNetworkTransactionTest, RequestsOrderedByPriority) {
  const char* kUrl2 = "https://www.example.org/foo";

  // First send second request on stream 1, then first request on stream 3.
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(kUrl2, 1, HIGHEST));
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOW));
  MockWrite writes[] = {CreateMockWrite(req2, 0), CreateMockWrite(req1, 1)};

  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body2(
      spdy_util_.ConstructSpdyDataFrame(1, "stream 1", true));
  spdy::SpdySerializedFrame body1(
      spdy_util_.ConstructSpdyDataFrame(3, "stream 3", true));
  MockRead reads[] = {CreateMockRead(resp2, 2), CreateMockRead(body2, 3),
                      CreateMockRead(resp1, 4), CreateMockRead(body1, 5),
                      MockRead(ASYNC, 0, 6)};

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, LOW, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);

  // Create HTTP/2 connection.  This is necessary because starting the first
  // transaction does not create the connection yet, so the second request
  // could not use the same connection, whereas running the message loop after
  // starting the first transaction would call Socket::Write() with the first
  // HEADERS frame, so the second transaction could not get ahead of it.
  SpdySessionKey key(HostPortPair("www.example.org", 443),
                     PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/false);
  auto spdy_session = CreateSpdySession(helper.session(), key, log_);
  EXPECT_TRUE(spdy_session);

  // Start first transaction.
  EXPECT_TRUE(helper.StartDefaultTest());

  // Start second transaction.
  HttpNetworkTransaction trans2(HIGHEST, helper.session());
  HttpRequestInfo request2;
  request2.url = GURL(kUrl2);
  request2.method = "GET";
  request2.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  TestCompletionCallback callback2;
  int rv = trans2.Start(&request2, callback2.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Complete first transaction and verify results.
  helper.FinishDefaultTest();
  helper.VerifyDataConsumed();

  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("stream 3", out.response_data);

  // Complete second transaction and verify results.
  rv = callback2.WaitForResult();
  ASSERT_THAT(rv, IsOk());
  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ(HttpConnectionInfo::kHTTP2, response2->connection_info);
  EXPECT_EQ("HTTP/1.1 200", response2->headers->GetStatusLine());
  std::string response_data;
  ReadTransaction(&trans2, &response_data);
  EXPECT_EQ("stream 1", response_data);
}

// Test that already enqueued HEADERS frames are reordered if their relative
// priority changes.
TEST_P(SpdyNetworkTransactionTest, QueuedFramesReorderedOnPriorityChange) {
  const char* kUrl2 = "https://www.example.org/foo";
  const char* kUrl3 = "https://www.example.org/bar";

  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, DEFAULT_PRIORITY));
  spdy::SpdySerializedFrame req3(spdy_util_.ConstructSpdyGet(kUrl3, 3, MEDIUM));
  // The headers for request 2 are set before the request is sent to SPDY and
  // are populated with the initial value (HIGHEST). The priority when it is
  // actually sent (later) is "LOWEST" which is sent on the actual priority
  // frame.
  spdy::SpdySerializedFrame req2(spdy_util_.ConstructSpdyGet(
      kUrl2, 5, LOWEST, kDefaultPriorityIncremental, HIGHEST));
  MockWrite writes[] = {MockWrite(ASYNC, ERR_IO_PENDING, 0),
                        CreateMockWrite(req1, 1), CreateMockWrite(req3, 2),
                        CreateMockWrite(req2, 3)};

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame resp3(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 5));
  spdy::SpdySerializedFrame body1(
      spdy_util_.ConstructSpdyDataFrame(1, "stream 1", true));
  spdy::SpdySerializedFrame body3(
      spdy_util_.ConstructSpdyDataFrame(3, "stream 3", true));
  spdy::SpdySerializedFrame body2(
      spdy_util_.ConstructSpdyDataFrame(5, "stream 5", true));
  MockRead reads[] = {CreateMockRead(resp1, 4), CreateMockRead(body1, 5),
                      CreateMockRead(resp3, 6), CreateMockRead(body3, 7),
                      CreateMockRead(resp2, 8), CreateMockRead(body2, 9),
                      MockRead(ASYNC, 0, 10)};

  SequencedSocketData data(reads, writes);
  // Priority of first request does not matter, because Socket::Write() will be
  // called with its HEADERS frame before the other requests start.
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  EXPECT_TRUE(helper.StartDefaultTest());

  // Open HTTP/2 connection, create HEADERS frame for first request, and call
  // Socket::Write() with that frame.  After this, no other request can get
  // ahead of the first one.
  base::RunLoop().RunUntilIdle();

  HttpNetworkTransaction trans2(HIGHEST, helper.session());
  HttpRequestInfo request2;
  request2.url = GURL(kUrl2);
  request2.method = "GET";
  request2.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  TestCompletionCallback callback2;
  int rv = trans2.Start(&request2, callback2.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  HttpNetworkTransaction trans3(MEDIUM, helper.session());
  HttpRequestInfo request3;
  request3.url = GURL(kUrl3);
  request3.method = "GET";
  request3.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  TestCompletionCallback callback3;
  rv = trans3.Sta
"""


```