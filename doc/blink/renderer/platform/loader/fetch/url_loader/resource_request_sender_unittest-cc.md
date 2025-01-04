Response:
The user wants to understand the functionality of the `resource_request_sender_unittest.cc` file in the Chromium Blink engine. I need to analyze the provided code snippet and:

1. **Identify the main purpose of the file.**  This file seems to be a unit test for the `ResourceRequestSender` class.
2. **Explain the functionality of the tested class (`ResourceRequestSender`).**  Based on the includes and the test setup, it likely deals with sending resource requests using the network service.
3. **Check for connections to Javascript, HTML, and CSS.**  Since this is about resource loading, it's highly likely there are connections. I'll need to infer these connections from the tested scenarios.
4. **Provide examples of how the functionality relates to web technologies.**
5. **If there's logic involved in the tests, provide example inputs and outputs.** The tests are simulating different scenarios (redirects, cancellations, etc.).
6. **Identify potential user or programming errors the tests might be uncovering.**
7. **Summarize the functionality of the file.**

**Breakdown of the Code Snippet:**

* **Includes:** The includes point to functionalities related to networking (URLLoader, URLResponseHead), concurrency (base::RunLoop), testing (gtest), and Blink-specific components (ResourceRequestSender, ResourceRequestClient, CodeCacheHost).
* **Helper Functions:**  `ReadOneChunk`, `CreateResourceRequest`, `CreateSyncResourceRequest`, `CreateDataPipeConsumerHandleFilledWithString` suggest utilities for setting up test requests and responses.
* **Mock Objects:** `MockRequestClient` and `MockLoader` are used to simulate the behavior of the client receiving responses and the loader handling requests, respectively.
* **DummyCodeCacheHost:** This mock is used for testing interactions with the code cache.
* **ResourceRequestSenderTest Class:** This is the main test fixture, setting up the environment and providing helper methods for sending requests.
* **Individual Tests:** The `TEST_F` macros define individual test cases focusing on specific scenarios like redirects (synchronous and asynchronous, with modifications and cancellations) and basic request/response handling.

**Connections to Web Technologies:**

* **Javascript:** When a Javascript fetches a resource (e.g., using `fetch()` or `XMLHttpRequest`), the browser will internally create and send a `ResourceRequest`. This code is testing how those requests are handled at a lower level in Blink.
* **HTML:** When the HTML parser encounters tags like `<script src="...">`, `<link rel="stylesheet" href="...">`, or `<img>`,  these initiate resource requests. This unit test is relevant to how Blink manages those requests.
* **CSS:** Similar to HTML, when the CSS parser encounters `@import` rules or when linked stylesheets are processed, resource requests are made.

**Hypotheses for Inputs and Outputs:**

For the redirect tests, the input would be an initial request and a simulated server response indicating a redirect. The expected output would be either a successful redirection and the subsequent resource loading or a cancellation of the request.

**Common User/Programming Errors:**

The tests implicitly cover errors like:

* **Incorrect handling of redirects:**  Not following redirects properly or mishandling redirect headers.
* **Race conditions:**  Asynchronous operations might lead to unexpected order of events.
* **Memory management issues:**  Incorrect handling of Mojo interfaces.
* **Incorrect state management:** The `ResourceRequestSender` needs to maintain the state of ongoing requests.

**Summary of Functionality (Part 1):**

The `resource_request_sender_unittest.cc` file primarily tests the `ResourceRequestSender` class in the Chromium Blink engine. This class is responsible for sending resource requests to the network service and handling the responses. The tests cover scenarios like successful requests, different types of redirects (synchronous and asynchronous), and request cancellations. The tests use mock objects to simulate network interactions and client behavior, allowing for focused testing of the `ResourceRequestSender`'s logic.

```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/url_loader/resource_request_sender.h"

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "base/containers/span.h"
#include "base/feature_list.h"
#include "base/run_loop.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/thread_pool.h"
#include "base/test/bind.h"
#include "base/test/task_environment.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/receiver_set.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "mojo/public/cpp/system/data_pipe_utils.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/request_priority.h"
#include "net/http/http_response_headers.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/url_loader_completion_status.h"
#include "services/network/public/cpp/weak_wrapper_shared_url_loader_factory.h"
#include "services/network/public/mojom/url_loader.mojom.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/loader/referrer_utils.h"
#include "third_party/blink/public/mojom/loader/code_cache.mojom-blink.h"
#include "third_party/blink/public/platform/resource_load_info_notifier_wrapper.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_url_request_extra_data.h"
#include "third_party/blink/public/platform/web_url_request_util.h"
#include "third_party/blink/renderer/platform/loader/fetch/code_cache_host.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/resource_request_client.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/sync_load_response.h"
#include "third_party/blink/renderer/platform/loader/testing/fake_url_loader_factory_for_background_thread.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/threading.h"
#include "url/gurl.h"

namespace blink {

namespace {

using RefCountedURLLoaderClientRemote =
    base::RefCountedData<mojo::Remote<network::mojom::URLLoaderClient>>;

static constexpr char kTestPageUrl[] = "http://www.google.com/";
static constexpr char kDifferentUrl[] = "http://www.google.com/different";
static constexpr char kRedirectedUrl[] = "http://redirected.example.com/";
static constexpr char kTestUrlForCodeCacheWithHashing[] =
    "codecachewithhashing://www.example.com/";
static constexpr char kTestData[] = "Hello world";

constexpr size_t kDataPipeCapacity = 4096;

std::string ReadOneChunk(mojo::ScopedDataPipeConsumerHandle* handle) {
  std::string buffer(kDataPipeCapacity, '\0');
  size_t actually_read_bytes = 0;
  MojoResult result = (*handle)->ReadData(MOJO_READ_DATA_FLAG_NONE,
                                          base::as_writable_byte_span(buffer),
                                          actually_read_bytes);
  if (result != MOJO_RESULT_OK) {
    return "";
  }
  return buffer.substr(0, actually_read_bytes);
}

// Returns a fake TimeTicks based on the given microsecond offset.
base::TimeTicks TicksFromMicroseconds(int64_t micros) {
  return base::TimeTicks() + base::Microseconds(micros);
}

std::unique_ptr<network::ResourceRequest> CreateResourceRequest() {
  std::unique_ptr<network::ResourceRequest> request(
      new network::ResourceRequest());

  request->method = "GET";
  request->url = GURL(kTestPageUrl);
  request->site_for_cookies = net::SiteForCookies::FromUrl(GURL(kTestPageUrl));
  request->referrer_policy = ReferrerUtils::GetDefaultNetReferrerPolicy();
  request->resource_type = static_cast<int>(mojom::ResourceType::kSubResource);
  request->priority = net::LOW;
  request->mode = network::mojom::RequestMode::kNoCors;

  auto url_request_extra_data = base::MakeRefCounted<WebURLRequestExtraData>();
  url_request_extra_data->CopyToResourceRequest(request.get());

  return request;
}

std::unique_ptr<network::ResourceRequest> CreateSyncResourceRequest() {
  auto request = CreateResourceRequest();
  request->load_flags = net::LOAD_IGNORE_LIMITS;
  return request;
}

mojo::ScopedDataPipeConsumerHandle CreateDataPipeConsumerHandleFilledWithString(
    const std::string& string) {
  mojo::ScopedDataPipeProducerHandle producer_handle;
  mojo::ScopedDataPipeConsumerHandle consumer_handle;
  CHECK_EQ(mojo::CreateDataPipe(nullptr, producer_handle, consumer_handle),
           MOJO_RESULT_OK);
  CHECK(mojo::BlockingCopyFromString(string, producer_handle));
  return consumer_handle;
}

class TestPlatformForRedirects final : public TestingPlatformSupport {
 public:
  bool IsRedirectSafe(const GURL& from_url, const GURL& to_url) override {
    return true;
  }
};

void RegisterURLSchemeAsCodeCacheWithHashing() {
#if DCHECK_IS_ON()
  WTF::SetIsBeforeThreadCreatedForTest();  // Required for next operation:
#endif
  SchemeRegistry::RegisterURLSchemeAsCodeCacheWithHashing(
      "codecachewithhashing");
}

// A mock ResourceRequestClient to receive messages from the
// ResourceRequestSender.
class MockRequestClient : public ResourceRequestClient {
 public:
  MockRequestClient() = default;

  // ResourceRequestClient overrides:
  void OnUploadProgress(uint64_t position, uint64_t size) override {
    upload_progress_called_ = true;
  }
  void OnReceivedRedirect(
      const net::RedirectInfo& redirect_info,
      network::mojom::URLResponseHeadPtr head,
      FollowRedirectCallback follow_redirect_callback) override {
    redirected_ = true;
    last_load_timing_ = head->load_timing;
    CHECK(on_received_redirect_callback_);
    std::move(on_received_redirect_callback_)
        .Run(redirect_info, std::move(head),
             std::move(follow_redirect_callback));
  }
  void OnReceivedResponse(
      network::mojom::URLResponseHeadPtr head,
      mojo::ScopedDataPipeConsumerHandle body,
      std::optional<mojo_base::BigBuffer> cached_metadata) override {
    last_load_timing_ = head->load_timing;
    cached_metadata_ = std::move(cached_metadata);
    received_response_ = true;
    if (body) {
      data_ += ReadOneChunk(&body);
    }
  }
  void OnTransferSizeUpdated(int transfer_size_diff) override {
    transfer_size_updated_called_ = true;
  }
  void OnCompletedRequest(
      const network::URLLoaderCompletionStatus& status) override {
    completion_status_ = status;
    complete_ = true;
  }

  std::string data() { return data_; }
  bool upload_progress_called() const { return upload_progress_called_; }
  bool redirected() const { return redirected_; }
  bool received_response() { return received_response_; }
  const std::optional<mojo_base::BigBuffer>& cached_metadata() const {
    return cached_metadata_;
  }
  bool transfer_size_updated_called() const {
    return transfer_size_updated_called_;
  }
  bool complete() const { return complete_; }
  const net::LoadTimingInfo& last_load_timing() const {
    return last_load_timing_;
  }
  network::URLLoaderCompletionStatus completion_status() {
    return completion_status_;
  }

  void SetOnReceivedRedirectCallback(
      base::OnceCallback<void(const net::RedirectInfo&,
                              network::mojom::URLResponseHeadPtr,
                              FollowRedirectCallback)> callback) {
    on_received_redirect_callback_ = std::move(callback);
  }

 private:
  // Data received. If downloading to file, remains empty.
  std::string data_;

  bool upload_progress_called_ = false;
  bool redirected_ = false;
  bool transfer_size_updated_called_ = false;
  bool received_response_ = false;
  std::optional<mojo_base::BigBuffer> cached_metadata_;
  bool complete_ = false;
  net::LoadTimingInfo last_load_timing_;
  network::URLLoaderCompletionStatus completion_status_;
  base::OnceCallback<void(const net::RedirectInfo&,
                          network::mojom::URLResponseHeadPtr,
                          FollowRedirectCallback)>
      on_received_redirect_callback_;
};

class MockLoader : public network::mojom::URLLoader {
 public:
  using RepeatingFollowRedirectCallback = base::RepeatingCallback<void(
      const std::vector<std::string>& removed_headers,
      const net::HttpRequestHeaders& modified_headers)>;
  MockLoader() = default;
  MockLoader(const MockLoader&) = delete;
  MockLoader& operator=(const MockLoader&) = delete;
  ~MockLoader() override = default;

  // network::mojom::URLLoader implementation:
  void FollowRedirect(
      const std::vector<std::string>& removed_headers,
      const net::HttpRequestHeaders& modified_headers,
      const net::HttpRequestHeaders& modified_cors_exempt_headers,
      const std::optional<GURL>& new_url) override {
    if (follow_redirect_callback_) {
      follow_redirect_callback_.Run(removed_headers, modified_headers);
    }
  }
  void SetPriority(net::RequestPriority priority,
                   int32_t intra_priority_value) override {}
  void PauseReadingBodyFromNet() override {}
  void ResumeReadingBodyFromNet() override {}

  void SetFollowRedirectCallback(RepeatingFollowRedirectCallback callback) {
    follow_redirect_callback_ = std::move(callback);
  }

 private:
  RepeatingFollowRedirectCallback follow_redirect_callback_;
};

using FetchCachedCodeCallback =
    mojom::blink::CodeCacheHost::FetchCachedCodeCallback;
using ProcessCodeCacheRequestCallback = base::RepeatingCallback<
    void(mojom::blink::CodeCacheType, const KURL&, FetchCachedCodeCallback)>;

class DummyCodeCacheHost final : public mojom::blink::CodeCacheHost {
 public:
  explicit DummyCodeCacheHost(
      ProcessCodeCacheRequestCallback process_code_cache_request_callback)
      : process_code_cache_request_callback_(
            std::move(process_code_cache_request_callback)) {
    mojo::PendingRemote<mojom::blink::CodeCacheHost> pending_remote;
    receiver_ = std::make_unique<mojo::Receiver<mojom::blink::CodeCacheHost>>(
        this, pending_remote.InitWithNewPipeAndPassReceiver());
    host_ = std::make_unique<blink::CodeCacheHost>(
        mojo::Remote<mojom::blink::CodeCacheHost>(std::move(pending_remote)));
  }

  // mojom::blink::CodeCacheHost implementations
  void DidGenerateCacheableMetadata(mojom::blink::CodeCacheType cache_type,
                                    const KURL& url,
                                    base::Time expected_response_time,
                                    mojo_base::BigBuffer data) override {}
  void FetchCachedCode(mojom::blink::CodeCacheType cache_type,
                       const KURL& url,
                       FetchCachedCodeCallback callback) override {
    process_code_cache_request_callback_.Run(cache_type, url,
                                             std::move(callback));
  }
  void ClearCodeCacheEntry(mojom::blink::CodeCacheType cache_type,
                           const KURL& url) override {
    did_clear_code_cache_entry_ = true;
  }
  void DidGenerateCacheableMetadataInCacheStorage(
      const KURL& url,
      base::Time expected_response_time,
      mojo_base::BigBuffer data,
      const WTF::String& cache_storage_cache_name) override {}

  blink::CodeCacheHost* GetCodeCacheHost() { return host_.get(); }
  bool did_clear_code_cache_entry() const {
    return did_clear_code_cache_entry_;
  }

 private:
  ProcessCodeCacheRequestCallback process_code_cache_request_callback_;
  std::unique_ptr<mojo::Receiver<mojom::blink::CodeCacheHost>> receiver_;
  std::unique_ptr<blink::CodeCacheHost> host_;
  bool did_clear_code_cache_entry_ = false;
};

// Sets up the message sender override for the unit test.
class ResourceRequestSenderTest : public testing::Test,
                                  public network::mojom::URLLoaderFactory {
 public:
  explicit ResourceRequestSenderTest()
      : resource_request_sender_(new ResourceRequestSender()) {}

  ~ResourceRequestSenderTest() override {
    resource_request_sender_.reset();
    base::RunLoop().RunUntilIdle();
  }

  void CreateLoaderAndStart(
      mojo::PendingReceiver<network::mojom::URLLoader> receiver,
      int32_t request_id,
      uint32_t options,
      const network::ResourceRequest& url_request,
      mojo::PendingRemote<network::mojom::URLLoaderClient> client,
      const net::MutableNetworkTrafficAnnotationTag& annotation) override {
    loader_and_clients_.emplace_back(std::move(receiver), std::move(client));
  }

  void Clone(mojo::PendingReceiver<network::mojom::URLLoaderFactory> receiver)
      override {
    NOTREACHED();
  }

 protected:
  ResourceRequestSender* sender() { return resource_request_sender_.get(); }

  void StartAsync(std::unique_ptr<network::ResourceRequest> request,
                  scoped_refptr<ResourceRequestClient> client,
                  CodeCacheHost* code_cache_host = nullptr) {
    sender()->SendAsync(
        std::move(request), scheduler::GetSingleThreadTaskRunnerForTesting(),
        TRAFFIC_ANNOTATION_FOR_TESTS, false,
        /*cors_exempt_header_list=*/Vector<String>(), std::move(client),
        base::MakeRefCounted<network::WeakWrapperSharedURLLoaderFactory>(this),
        std::vector<std::unique_ptr<URLLoaderThrottle>>(),
        std::make_unique<ResourceLoadInfoNotifierWrapper>(
            /*resource_load_info_notifier=*/nullptr),
        code_cache_host,
        /*evict_from_bfcache_callback=*/
        base::OnceCallback<void(mojom::blink::RendererEvictionReason)>(),
        /*did_buffer_load_while_in_bfcache_callback=*/
        base::RepeatingCallback<void(size_t)>());
  }

  network::mojom::URLResponseHeadPtr CreateResponse() {
    auto response = network::mojom::URLResponseHead::New();
    response->response_time = base::Time::Now();
    return response;
  }

  std::vector<std::pair<mojo::PendingReceiver<network::mojom::URLLoader>,
                        mojo::PendingRemote<network::mojom::URLLoaderClient>>>
      loader_and_clients_;
  base::test::SingleThreadTaskEnvironment task_environment_;
  std::unique_ptr<ResourceRequestSender> resource_request_sender_;

  scoped_refptr<MockRequestClient> mock_client_;

 private:
  ScopedTestingPlatformSupport<TestPlatformForRedirects> platform_;
};

// Tests the generation of unique request ids.
TEST_F(ResourceRequestSenderTest, MakeRequestID) {
  int first_id = GenerateRequestId();
  int second_id = GenerateRequestId();

  // Child process ids are unique (per process) and counting from 0 upwards:
  EXPECT_GT(second_id, first_id);
  EXPECT_GE(first_id, 0);
}

TEST_F(ResourceRequestSenderTest, RedirectSyncFollow) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();
  StartAsync(CreateResourceRequest(), mock_client_);
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));
  std::unique_ptr<MockLoader> mock_loader = std::make_unique<MockLoader>();
  MockLoader* mock_loader_prt = mock_loader.get();
  mojo::MakeSelfOwnedReceiver(std::move(mock_loader),
                              std::move(loader_and_clients_[0].first));

  base::RunLoop run_loop_for_redirect;
  mock_loader_prt->SetFollowRedirectCallback(base::BindLambdaForTesting(
      [&](const std::vector<std::string>& removed_headers,
          const net::HttpRequestHeaders& modified_headers) {
        // network::mojom::URLLoader::FollowRedirect() must be called with an
        // empty `removed_headers` and empty `modified_headers`.
        EXPECT_TRUE(removed_headers.empty());
        EXPECT_TRUE(modified_headers.IsEmpty());
        run_loop_for_redirect.Quit();
      }));

  mock_client_->SetOnReceivedRedirectCallback(base::BindLambdaForTesting(
      [&](const net::RedirectInfo& redirect_info,
          network::mojom::URLResponseHeadPtr head,
          ResourceRequestClient::FollowRedirectCallback callback) {
        EXPECT_EQ(GURL(kRedirectedUrl), redirect_info.new_url);
        // Synchronously call `callback` with an empty `removed_headers` and
        // empty `modified_headers`.
        std::move(callback).Run({}, {});
      }));

  net::RedirectInfo redirect_info;
  redirect_info.new_url = GURL(kRedirectedUrl);
  client->OnReceiveRedirect(redirect_info,
                            network::mojom::URLResponseHead::New());
  run_loop_for_redirect.Run();
  client->OnReceiveResponse(network::mojom::URLResponseHead::New(),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
}

TEST_F(ResourceRequestSenderTest, RedirectSyncFollowWithRemovedHeaders) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();
  StartAsync(CreateResourceRequest(), mock_client_);
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  std::unique_ptr<MockLoader> mock_loader = std::make_unique<MockLoader>();
  MockLoader* mock_loader_prt = mock_loader.get();
  mojo::MakeSelfOwnedReceiver(std::move(mock_loader),
                              std::move(loader_and_clients_[0].first));

  base::RunLoop run_loop_for_redirect;
  mock_loader_prt->SetFollowRedirectCallback(base::BindLambdaForTesting(
      [&](const std::vector<std::string>& removed_headers,
          const net::HttpRequestHeaders& modified_headers) {
        // network::mojom::URLLoader::FollowRedirect() must be called with a
        // non-empty `removed_headers` and empty `modified_headers.
        EXPECT_THAT(removed_headers,
                    ::testing::ElementsAreArray({"Foo-Bar", "Hoge-Piyo"}));
        EXPECT_TRUE(modified_headers.IsEmpty());
        run_loop_for_redirect.Quit();
      }));

  mock_client_->SetOnReceivedRedirectCallback(base::BindLambdaForTesting(
      [&](const net::RedirectInfo& redirect_info,
          network::mojom::URLResponseHeadPtr head,
          ResourceRequestClient::FollowRedirectCallback callback) {
        EXPECT_EQ(GURL(kRedirectedUrl), redirect_info.new_url);
        // Synchronously call `callback` with a non-empty `removed_headers` and
        // empty `modified_headers`.
        std::move(callback).Run({"Foo-Bar", "Hoge-Piyo"}, {});
      }));

  net::RedirectInfo redirect_info;
  redirect_info.new_url = GURL(kRedirectedUrl);
  client->OnReceiveRedirect(redirect_info,
                            network::mojom::URLResponseHead::New());
  run_loop_for_redirect.Run();
  client->OnReceiveResponse(network::mojom::URLResponseHead::New(),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
}

TEST_F(ResourceRequestSenderTest, RedirectSyncFollowWithModifiedHeaders) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();
  StartAsync(CreateResourceRequest(), mock_client_);
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  std::unique_ptr<MockLoader> mock_loader = std::make_unique<MockLoader>();
  MockLoader* mock_loader_prt = mock_loader.get();
  mojo::MakeSelfOwnedReceiver(std::move(mock_loader),
                              std::move(loader_and_clients_[0].first));

  base::RunLoop run_loop_for_redirect;
  mock_loader_prt->SetFollowRedirectCallback(base::BindLambdaForTesting(
      [&](const std::vector<std::string>& removed_headers,
          const net::HttpRequestHeaders& modified_headers) {
        // network::mojom::URLLoader::FollowRedirect() must be called with an
        // empty `removed_headers` and non-empty `modified_headers.
        EXPECT_TRUE(removed_headers.empty());
        EXPECT_EQ(
            "Cookie-Monster: Nom nom nom\r\nDomo-Kun: Loves Chrome\r\n\r\n",
            modified_headers.ToString());
        run_loop_for_redirect.Quit();
      }));

  mock_client_->SetOnReceivedRedirectCallback(base::BindLambdaForTesting(
      [&](const net::RedirectInfo& redirect_info,
          network::mojom::URLResponseHeadPtr head,
          ResourceRequestClient::FollowRedirectCallback callback) {
        EXPECT_EQ(GURL(kRedirectedUrl), redirect_info.new_url);
        // Synchronously call `callback` with an empty `removed_headers` and
        // non-empty `modified_headers`.
        net::HttpRequestHeaders modified_headers;
        modified_headers.SetHeader("Cookie-Monster", "Nom nom nom");
        modified_headers.SetHeader("Domo-Kun", "Loves Chrome");
        std::move(callback).Run({}, std::move(modified_headers));
      }));

  net::RedirectInfo redirect_info;
  redirect_info.new_url = GURL(kRedirectedUrl);
  client->OnReceiveRedirect(redirect_info,
                            network::mojom::URLResponseHead::New());
  run_loop_for_redirect.Run();
  client->OnReceiveResponse(network::mojom::URLResponseHead::New(),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
}

TEST_F(ResourceRequestSenderTest, RedirectSyncCancel) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();
  StartAsync(CreateResourceRequest(), mock_client_);
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));
  std::unique_ptr<MockLoader> mock_loader = std::make_unique<MockLoader>();
  MockLoader* mock_loader_prt = mock_loader.get();
  mojo::MakeSelfOwnedReceiver(std::move(mock_loader),
                              std::move(loader_and_clients_[0].first));

  mock_loader_prt->SetFollowRedirectCallback(
      base::BindRepeating([](const std::vector<std::string>& removed_headers,
                             const net::HttpRequestHeaders& modified_headers) {
        // FollowRedirect() must not be called.
        CHECK(false);
      }));

  mock_client_->SetOnReceivedRedirectCallback(base::BindLambdaForTesting(
      [&](const net::RedirectInfo& redirect_info,
          network::mojom::URLResponseHeadPtr head,
          ResourceRequestClient::FollowRedirectCallback callback) {
        EXPECT_EQ(GURL(kRedirectedUrl), redirect_info.new_url);
        // Synchronously cancels the request in the `OnReceivedRedirect()`.
        sender()->Cancel(scheduler::GetSingleThreadTaskRunnerForTesting());
      }));

  net::RedirectInfo redirect_info;
  redirect_info.new_url = GURL(kRedirectedUrl);
  client->OnReceiveRedirect(redirect_info,
                            network::mojom::URLResponseHead::New());
  base::RunLoop().RunUntilIdle();
}

TEST_F(ResourceRequestSenderTest, RedirectAsyncFollow) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();
  StartAsync(CreateResourceRequest(), mock_client_);
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));
  std::unique_ptr<MockLoader> mock_loader = std::make_unique<MockLoader>();
  MockLoader* mock_loader_prt = mock_loader.get();
  mojo::MakeSelfOwnedReceiver(std::move(mock_loader),
                              std::move(loader_and_clients_[0].first));

  base::RunLoop run_loop_for_redirect;
  mock_loader_prt->SetFollowRedirectCallback(base::BindLambdaForTesting(
      [&](const std::vector<std::string>& removed_headers,
          const net::HttpRequestHeaders& modified_headers) {
        // network::mojom::URLLoader::FollowRedirect() must be called with an
        // empty `removed_headers` and empty `modified_headers.
        EXPECT_TRUE(removed_headers.empty());
        EXPECT_TRUE(modified_headers.IsEmpty());
        run_loop_for_redirect.Quit();
      }));

  std::optional<net::RedirectInfo> received_redirect_info;
  ResourceRequestClient::FollowRedirectCallback follow_redirect_callback;
  mock_client_->SetOnReceivedRedirectCallback(base::BindLambdaForTesting(
      [&](const net::RedirectInfo& redirect_info,
          network::mojom::URLResponseHeadPtr head,
          ResourceRequestClient::FollowRedirectCallback callback) {
        received_redirect_info = redirect_info;
        follow_redirect_callback = std::move(callback);
      }));

  net::RedirectInfo redirect_info;
  redirect_info.new_url = GURL(kRedirectedUrl);
  client->OnReceiveRedirect(redirect_info,
                            network::mojom::URLResponseHead::New());
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(received_redirect_info);
  EXPECT_EQ(GURL(kRedirectedUrl), received_redirect_info->new_url);
  // Asynchronously call `callback` with an empty `removed_headers` and empty
  // `modified_headers`.
  std::move(follow_redirect_callback).Run({}, {});
  run_loop_for_redirect.Run();
  client->OnReceiveResponse(network::mojom::URLResponseHead::New(),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
}

TEST_F(ResourceRequestSenderTest, RedirectAsyncFollowWithRemovedHeaders) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();
  StartAsync(CreateResourceRequest(), mock_client_);
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));
  std::unique_ptr<MockLoader> mock_loader = std::make_unique<MockLoader>();
  MockLoader* mock_loader_prt = mock_loader.get();
  mojo::MakeSelfOwnedReceiver(std::move(mock_loader),
                              std::move(loader_
Prompt: 
```
这是目录为blink/renderer/platform/loader/fetch/url_loader/resource_request_sender_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/url_loader/resource_request_sender.h"

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "base/containers/span.h"
#include "base/feature_list.h"
#include "base/run_loop.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/thread_pool.h"
#include "base/test/bind.h"
#include "base/test/task_environment.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/receiver_set.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "mojo/public/cpp/system/data_pipe_utils.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/request_priority.h"
#include "net/http/http_response_headers.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/url_loader_completion_status.h"
#include "services/network/public/cpp/weak_wrapper_shared_url_loader_factory.h"
#include "services/network/public/mojom/url_loader.mojom.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/loader/referrer_utils.h"
#include "third_party/blink/public/mojom/loader/code_cache.mojom-blink.h"
#include "third_party/blink/public/platform/resource_load_info_notifier_wrapper.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_url_request_extra_data.h"
#include "third_party/blink/public/platform/web_url_request_util.h"
#include "third_party/blink/renderer/platform/loader/fetch/code_cache_host.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/resource_request_client.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/sync_load_response.h"
#include "third_party/blink/renderer/platform/loader/testing/fake_url_loader_factory_for_background_thread.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/threading.h"
#include "url/gurl.h"

namespace blink {

namespace {

using RefCountedURLLoaderClientRemote =
    base::RefCountedData<mojo::Remote<network::mojom::URLLoaderClient>>;

static constexpr char kTestPageUrl[] = "http://www.google.com/";
static constexpr char kDifferentUrl[] = "http://www.google.com/different";
static constexpr char kRedirectedUrl[] = "http://redirected.example.com/";
static constexpr char kTestUrlForCodeCacheWithHashing[] =
    "codecachewithhashing://www.example.com/";
static constexpr char kTestData[] = "Hello world";

constexpr size_t kDataPipeCapacity = 4096;

std::string ReadOneChunk(mojo::ScopedDataPipeConsumerHandle* handle) {
  std::string buffer(kDataPipeCapacity, '\0');
  size_t actually_read_bytes = 0;
  MojoResult result = (*handle)->ReadData(MOJO_READ_DATA_FLAG_NONE,
                                          base::as_writable_byte_span(buffer),
                                          actually_read_bytes);
  if (result != MOJO_RESULT_OK) {
    return "";
  }
  return buffer.substr(0, actually_read_bytes);
}

// Returns a fake TimeTicks based on the given microsecond offset.
base::TimeTicks TicksFromMicroseconds(int64_t micros) {
  return base::TimeTicks() + base::Microseconds(micros);
}

std::unique_ptr<network::ResourceRequest> CreateResourceRequest() {
  std::unique_ptr<network::ResourceRequest> request(
      new network::ResourceRequest());

  request->method = "GET";
  request->url = GURL(kTestPageUrl);
  request->site_for_cookies = net::SiteForCookies::FromUrl(GURL(kTestPageUrl));
  request->referrer_policy = ReferrerUtils::GetDefaultNetReferrerPolicy();
  request->resource_type = static_cast<int>(mojom::ResourceType::kSubResource);
  request->priority = net::LOW;
  request->mode = network::mojom::RequestMode::kNoCors;

  auto url_request_extra_data = base::MakeRefCounted<WebURLRequestExtraData>();
  url_request_extra_data->CopyToResourceRequest(request.get());

  return request;
}

std::unique_ptr<network::ResourceRequest> CreateSyncResourceRequest() {
  auto request = CreateResourceRequest();
  request->load_flags = net::LOAD_IGNORE_LIMITS;
  return request;
}

mojo::ScopedDataPipeConsumerHandle CreateDataPipeConsumerHandleFilledWithString(
    const std::string& string) {
  mojo::ScopedDataPipeProducerHandle producer_handle;
  mojo::ScopedDataPipeConsumerHandle consumer_handle;
  CHECK_EQ(mojo::CreateDataPipe(nullptr, producer_handle, consumer_handle),
           MOJO_RESULT_OK);
  CHECK(mojo::BlockingCopyFromString(string, producer_handle));
  return consumer_handle;
}

class TestPlatformForRedirects final : public TestingPlatformSupport {
 public:
  bool IsRedirectSafe(const GURL& from_url, const GURL& to_url) override {
    return true;
  }
};

void RegisterURLSchemeAsCodeCacheWithHashing() {
#if DCHECK_IS_ON()
  WTF::SetIsBeforeThreadCreatedForTest();  // Required for next operation:
#endif
  SchemeRegistry::RegisterURLSchemeAsCodeCacheWithHashing(
      "codecachewithhashing");
}

// A mock ResourceRequestClient to receive messages from the
// ResourceRequestSender.
class MockRequestClient : public ResourceRequestClient {
 public:
  MockRequestClient() = default;

  // ResourceRequestClient overrides:
  void OnUploadProgress(uint64_t position, uint64_t size) override {
    upload_progress_called_ = true;
  }
  void OnReceivedRedirect(
      const net::RedirectInfo& redirect_info,
      network::mojom::URLResponseHeadPtr head,
      FollowRedirectCallback follow_redirect_callback) override {
    redirected_ = true;
    last_load_timing_ = head->load_timing;
    CHECK(on_received_redirect_callback_);
    std::move(on_received_redirect_callback_)
        .Run(redirect_info, std::move(head),
             std::move(follow_redirect_callback));
  }
  void OnReceivedResponse(
      network::mojom::URLResponseHeadPtr head,
      mojo::ScopedDataPipeConsumerHandle body,
      std::optional<mojo_base::BigBuffer> cached_metadata) override {
    last_load_timing_ = head->load_timing;
    cached_metadata_ = std::move(cached_metadata);
    received_response_ = true;
    if (body) {
      data_ += ReadOneChunk(&body);
    }
  }
  void OnTransferSizeUpdated(int transfer_size_diff) override {
    transfer_size_updated_called_ = true;
  }
  void OnCompletedRequest(
      const network::URLLoaderCompletionStatus& status) override {
    completion_status_ = status;
    complete_ = true;
  }

  std::string data() { return data_; }
  bool upload_progress_called() const { return upload_progress_called_; }
  bool redirected() const { return redirected_; }
  bool received_response() { return received_response_; }
  const std::optional<mojo_base::BigBuffer>& cached_metadata() const {
    return cached_metadata_;
  }
  bool transfer_size_updated_called() const {
    return transfer_size_updated_called_;
  }
  bool complete() const { return complete_; }
  const net::LoadTimingInfo& last_load_timing() const {
    return last_load_timing_;
  }
  network::URLLoaderCompletionStatus completion_status() {
    return completion_status_;
  }

  void SetOnReceivedRedirectCallback(
      base::OnceCallback<void(const net::RedirectInfo&,
                              network::mojom::URLResponseHeadPtr,
                              FollowRedirectCallback)> callback) {
    on_received_redirect_callback_ = std::move(callback);
  }

 private:
  // Data received. If downloading to file, remains empty.
  std::string data_;

  bool upload_progress_called_ = false;
  bool redirected_ = false;
  bool transfer_size_updated_called_ = false;
  bool received_response_ = false;
  std::optional<mojo_base::BigBuffer> cached_metadata_;
  bool complete_ = false;
  net::LoadTimingInfo last_load_timing_;
  network::URLLoaderCompletionStatus completion_status_;
  base::OnceCallback<void(const net::RedirectInfo&,
                          network::mojom::URLResponseHeadPtr,
                          FollowRedirectCallback)>
      on_received_redirect_callback_;
};

class MockLoader : public network::mojom::URLLoader {
 public:
  using RepeatingFollowRedirectCallback = base::RepeatingCallback<void(
      const std::vector<std::string>& removed_headers,
      const net::HttpRequestHeaders& modified_headers)>;
  MockLoader() = default;
  MockLoader(const MockLoader&) = delete;
  MockLoader& operator=(const MockLoader&) = delete;
  ~MockLoader() override = default;

  // network::mojom::URLLoader implementation:
  void FollowRedirect(
      const std::vector<std::string>& removed_headers,
      const net::HttpRequestHeaders& modified_headers,
      const net::HttpRequestHeaders& modified_cors_exempt_headers,
      const std::optional<GURL>& new_url) override {
    if (follow_redirect_callback_) {
      follow_redirect_callback_.Run(removed_headers, modified_headers);
    }
  }
  void SetPriority(net::RequestPriority priority,
                   int32_t intra_priority_value) override {}
  void PauseReadingBodyFromNet() override {}
  void ResumeReadingBodyFromNet() override {}

  void SetFollowRedirectCallback(RepeatingFollowRedirectCallback callback) {
    follow_redirect_callback_ = std::move(callback);
  }

 private:
  RepeatingFollowRedirectCallback follow_redirect_callback_;
};

using FetchCachedCodeCallback =
    mojom::blink::CodeCacheHost::FetchCachedCodeCallback;
using ProcessCodeCacheRequestCallback = base::RepeatingCallback<
    void(mojom::blink::CodeCacheType, const KURL&, FetchCachedCodeCallback)>;

class DummyCodeCacheHost final : public mojom::blink::CodeCacheHost {
 public:
  explicit DummyCodeCacheHost(
      ProcessCodeCacheRequestCallback process_code_cache_request_callback)
      : process_code_cache_request_callback_(
            std::move(process_code_cache_request_callback)) {
    mojo::PendingRemote<mojom::blink::CodeCacheHost> pending_remote;
    receiver_ = std::make_unique<mojo::Receiver<mojom::blink::CodeCacheHost>>(
        this, pending_remote.InitWithNewPipeAndPassReceiver());
    host_ = std::make_unique<blink::CodeCacheHost>(
        mojo::Remote<mojom::blink::CodeCacheHost>(std::move(pending_remote)));
  }

  // mojom::blink::CodeCacheHost implementations
  void DidGenerateCacheableMetadata(mojom::blink::CodeCacheType cache_type,
                                    const KURL& url,
                                    base::Time expected_response_time,
                                    mojo_base::BigBuffer data) override {}
  void FetchCachedCode(mojom::blink::CodeCacheType cache_type,
                       const KURL& url,
                       FetchCachedCodeCallback callback) override {
    process_code_cache_request_callback_.Run(cache_type, url,
                                             std::move(callback));
  }
  void ClearCodeCacheEntry(mojom::blink::CodeCacheType cache_type,
                           const KURL& url) override {
    did_clear_code_cache_entry_ = true;
  }
  void DidGenerateCacheableMetadataInCacheStorage(
      const KURL& url,
      base::Time expected_response_time,
      mojo_base::BigBuffer data,
      const WTF::String& cache_storage_cache_name) override {}

  blink::CodeCacheHost* GetCodeCacheHost() { return host_.get(); }
  bool did_clear_code_cache_entry() const {
    return did_clear_code_cache_entry_;
  }

 private:
  ProcessCodeCacheRequestCallback process_code_cache_request_callback_;
  std::unique_ptr<mojo::Receiver<mojom::blink::CodeCacheHost>> receiver_;
  std::unique_ptr<blink::CodeCacheHost> host_;
  bool did_clear_code_cache_entry_ = false;
};

// Sets up the message sender override for the unit test.
class ResourceRequestSenderTest : public testing::Test,
                                  public network::mojom::URLLoaderFactory {
 public:
  explicit ResourceRequestSenderTest()
      : resource_request_sender_(new ResourceRequestSender()) {}

  ~ResourceRequestSenderTest() override {
    resource_request_sender_.reset();
    base::RunLoop().RunUntilIdle();
  }

  void CreateLoaderAndStart(
      mojo::PendingReceiver<network::mojom::URLLoader> receiver,
      int32_t request_id,
      uint32_t options,
      const network::ResourceRequest& url_request,
      mojo::PendingRemote<network::mojom::URLLoaderClient> client,
      const net::MutableNetworkTrafficAnnotationTag& annotation) override {
    loader_and_clients_.emplace_back(std::move(receiver), std::move(client));
  }

  void Clone(mojo::PendingReceiver<network::mojom::URLLoaderFactory> receiver)
      override {
    NOTREACHED();
  }

 protected:
  ResourceRequestSender* sender() { return resource_request_sender_.get(); }

  void StartAsync(std::unique_ptr<network::ResourceRequest> request,
                  scoped_refptr<ResourceRequestClient> client,
                  CodeCacheHost* code_cache_host = nullptr) {
    sender()->SendAsync(
        std::move(request), scheduler::GetSingleThreadTaskRunnerForTesting(),
        TRAFFIC_ANNOTATION_FOR_TESTS, false,
        /*cors_exempt_header_list=*/Vector<String>(), std::move(client),
        base::MakeRefCounted<network::WeakWrapperSharedURLLoaderFactory>(this),
        std::vector<std::unique_ptr<URLLoaderThrottle>>(),
        std::make_unique<ResourceLoadInfoNotifierWrapper>(
            /*resource_load_info_notifier=*/nullptr),
        code_cache_host,
        /*evict_from_bfcache_callback=*/
        base::OnceCallback<void(mojom::blink::RendererEvictionReason)>(),
        /*did_buffer_load_while_in_bfcache_callback=*/
        base::RepeatingCallback<void(size_t)>());
  }

  network::mojom::URLResponseHeadPtr CreateResponse() {
    auto response = network::mojom::URLResponseHead::New();
    response->response_time = base::Time::Now();
    return response;
  }

  std::vector<std::pair<mojo::PendingReceiver<network::mojom::URLLoader>,
                        mojo::PendingRemote<network::mojom::URLLoaderClient>>>
      loader_and_clients_;
  base::test::SingleThreadTaskEnvironment task_environment_;
  std::unique_ptr<ResourceRequestSender> resource_request_sender_;

  scoped_refptr<MockRequestClient> mock_client_;

 private:
  ScopedTestingPlatformSupport<TestPlatformForRedirects> platform_;
};

// Tests the generation of unique request ids.
TEST_F(ResourceRequestSenderTest, MakeRequestID) {
  int first_id = GenerateRequestId();
  int second_id = GenerateRequestId();

  // Child process ids are unique (per process) and counting from 0 upwards:
  EXPECT_GT(second_id, first_id);
  EXPECT_GE(first_id, 0);
}

TEST_F(ResourceRequestSenderTest, RedirectSyncFollow) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();
  StartAsync(CreateResourceRequest(), mock_client_);
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));
  std::unique_ptr<MockLoader> mock_loader = std::make_unique<MockLoader>();
  MockLoader* mock_loader_prt = mock_loader.get();
  mojo::MakeSelfOwnedReceiver(std::move(mock_loader),
                              std::move(loader_and_clients_[0].first));

  base::RunLoop run_loop_for_redirect;
  mock_loader_prt->SetFollowRedirectCallback(base::BindLambdaForTesting(
      [&](const std::vector<std::string>& removed_headers,
          const net::HttpRequestHeaders& modified_headers) {
        // network::mojom::URLLoader::FollowRedirect() must be called with an
        // empty `removed_headers` and empty `modified_headers`.
        EXPECT_TRUE(removed_headers.empty());
        EXPECT_TRUE(modified_headers.IsEmpty());
        run_loop_for_redirect.Quit();
      }));

  mock_client_->SetOnReceivedRedirectCallback(base::BindLambdaForTesting(
      [&](const net::RedirectInfo& redirect_info,
          network::mojom::URLResponseHeadPtr head,
          ResourceRequestClient::FollowRedirectCallback callback) {
        EXPECT_EQ(GURL(kRedirectedUrl), redirect_info.new_url);
        // Synchronously call `callback` with an empty `removed_headers` and
        // empty `modified_headers`.
        std::move(callback).Run({}, {});
      }));

  net::RedirectInfo redirect_info;
  redirect_info.new_url = GURL(kRedirectedUrl);
  client->OnReceiveRedirect(redirect_info,
                            network::mojom::URLResponseHead::New());
  run_loop_for_redirect.Run();
  client->OnReceiveResponse(network::mojom::URLResponseHead::New(),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
}

TEST_F(ResourceRequestSenderTest, RedirectSyncFollowWithRemovedHeaders) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();
  StartAsync(CreateResourceRequest(), mock_client_);
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  std::unique_ptr<MockLoader> mock_loader = std::make_unique<MockLoader>();
  MockLoader* mock_loader_prt = mock_loader.get();
  mojo::MakeSelfOwnedReceiver(std::move(mock_loader),
                              std::move(loader_and_clients_[0].first));

  base::RunLoop run_loop_for_redirect;
  mock_loader_prt->SetFollowRedirectCallback(base::BindLambdaForTesting(
      [&](const std::vector<std::string>& removed_headers,
          const net::HttpRequestHeaders& modified_headers) {
        // network::mojom::URLLoader::FollowRedirect() must be called with a
        // non-empty `removed_headers` and empty `modified_headers.
        EXPECT_THAT(removed_headers,
                    ::testing::ElementsAreArray({"Foo-Bar", "Hoge-Piyo"}));
        EXPECT_TRUE(modified_headers.IsEmpty());
        run_loop_for_redirect.Quit();
      }));

  mock_client_->SetOnReceivedRedirectCallback(base::BindLambdaForTesting(
      [&](const net::RedirectInfo& redirect_info,
          network::mojom::URLResponseHeadPtr head,
          ResourceRequestClient::FollowRedirectCallback callback) {
        EXPECT_EQ(GURL(kRedirectedUrl), redirect_info.new_url);
        // Synchronously call `callback` with a non-empty `removed_headers` and
        // empty `modified_headers`.
        std::move(callback).Run({"Foo-Bar", "Hoge-Piyo"}, {});
      }));

  net::RedirectInfo redirect_info;
  redirect_info.new_url = GURL(kRedirectedUrl);
  client->OnReceiveRedirect(redirect_info,
                            network::mojom::URLResponseHead::New());
  run_loop_for_redirect.Run();
  client->OnReceiveResponse(network::mojom::URLResponseHead::New(),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
}

TEST_F(ResourceRequestSenderTest, RedirectSyncFollowWithModifiedHeaders) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();
  StartAsync(CreateResourceRequest(), mock_client_);
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  std::unique_ptr<MockLoader> mock_loader = std::make_unique<MockLoader>();
  MockLoader* mock_loader_prt = mock_loader.get();
  mojo::MakeSelfOwnedReceiver(std::move(mock_loader),
                              std::move(loader_and_clients_[0].first));

  base::RunLoop run_loop_for_redirect;
  mock_loader_prt->SetFollowRedirectCallback(base::BindLambdaForTesting(
      [&](const std::vector<std::string>& removed_headers,
          const net::HttpRequestHeaders& modified_headers) {
        // network::mojom::URLLoader::FollowRedirect() must be called with an
        // empty `removed_headers` and non-empty `modified_headers.
        EXPECT_TRUE(removed_headers.empty());
        EXPECT_EQ(
            "Cookie-Monster: Nom nom nom\r\nDomo-Kun: Loves Chrome\r\n\r\n",
            modified_headers.ToString());
        run_loop_for_redirect.Quit();
      }));

  mock_client_->SetOnReceivedRedirectCallback(base::BindLambdaForTesting(
      [&](const net::RedirectInfo& redirect_info,
          network::mojom::URLResponseHeadPtr head,
          ResourceRequestClient::FollowRedirectCallback callback) {
        EXPECT_EQ(GURL(kRedirectedUrl), redirect_info.new_url);
        // Synchronously call `callback` with an empty `removed_headers` and
        // non-empty `modified_headers`.
        net::HttpRequestHeaders modified_headers;
        modified_headers.SetHeader("Cookie-Monster", "Nom nom nom");
        modified_headers.SetHeader("Domo-Kun", "Loves Chrome");
        std::move(callback).Run({}, std::move(modified_headers));
      }));

  net::RedirectInfo redirect_info;
  redirect_info.new_url = GURL(kRedirectedUrl);
  client->OnReceiveRedirect(redirect_info,
                            network::mojom::URLResponseHead::New());
  run_loop_for_redirect.Run();
  client->OnReceiveResponse(network::mojom::URLResponseHead::New(),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
}

TEST_F(ResourceRequestSenderTest, RedirectSyncCancel) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();
  StartAsync(CreateResourceRequest(), mock_client_);
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));
  std::unique_ptr<MockLoader> mock_loader = std::make_unique<MockLoader>();
  MockLoader* mock_loader_prt = mock_loader.get();
  mojo::MakeSelfOwnedReceiver(std::move(mock_loader),
                              std::move(loader_and_clients_[0].first));

  mock_loader_prt->SetFollowRedirectCallback(
      base::BindRepeating([](const std::vector<std::string>& removed_headers,
                             const net::HttpRequestHeaders& modified_headers) {
        // FollowRedirect() must not be called.
        CHECK(false);
      }));

  mock_client_->SetOnReceivedRedirectCallback(base::BindLambdaForTesting(
      [&](const net::RedirectInfo& redirect_info,
          network::mojom::URLResponseHeadPtr head,
          ResourceRequestClient::FollowRedirectCallback callback) {
        EXPECT_EQ(GURL(kRedirectedUrl), redirect_info.new_url);
        // Synchronously cancels the request in the `OnReceivedRedirect()`.
        sender()->Cancel(scheduler::GetSingleThreadTaskRunnerForTesting());
      }));

  net::RedirectInfo redirect_info;
  redirect_info.new_url = GURL(kRedirectedUrl);
  client->OnReceiveRedirect(redirect_info,
                            network::mojom::URLResponseHead::New());
  base::RunLoop().RunUntilIdle();
}

TEST_F(ResourceRequestSenderTest, RedirectAsyncFollow) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();
  StartAsync(CreateResourceRequest(), mock_client_);
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));
  std::unique_ptr<MockLoader> mock_loader = std::make_unique<MockLoader>();
  MockLoader* mock_loader_prt = mock_loader.get();
  mojo::MakeSelfOwnedReceiver(std::move(mock_loader),
                              std::move(loader_and_clients_[0].first));

  base::RunLoop run_loop_for_redirect;
  mock_loader_prt->SetFollowRedirectCallback(base::BindLambdaForTesting(
      [&](const std::vector<std::string>& removed_headers,
          const net::HttpRequestHeaders& modified_headers) {
        // network::mojom::URLLoader::FollowRedirect() must be called with an
        // empty `removed_headers` and empty `modified_headers.
        EXPECT_TRUE(removed_headers.empty());
        EXPECT_TRUE(modified_headers.IsEmpty());
        run_loop_for_redirect.Quit();
      }));

  std::optional<net::RedirectInfo> received_redirect_info;
  ResourceRequestClient::FollowRedirectCallback follow_redirect_callback;
  mock_client_->SetOnReceivedRedirectCallback(base::BindLambdaForTesting(
      [&](const net::RedirectInfo& redirect_info,
          network::mojom::URLResponseHeadPtr head,
          ResourceRequestClient::FollowRedirectCallback callback) {
        received_redirect_info = redirect_info;
        follow_redirect_callback = std::move(callback);
      }));

  net::RedirectInfo redirect_info;
  redirect_info.new_url = GURL(kRedirectedUrl);
  client->OnReceiveRedirect(redirect_info,
                            network::mojom::URLResponseHead::New());
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(received_redirect_info);
  EXPECT_EQ(GURL(kRedirectedUrl), received_redirect_info->new_url);
  // Asynchronously call `callback` with an empty `removed_headers` and empty
  // `modified_headers`.
  std::move(follow_redirect_callback).Run({}, {});
  run_loop_for_redirect.Run();
  client->OnReceiveResponse(network::mojom::URLResponseHead::New(),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
}

TEST_F(ResourceRequestSenderTest, RedirectAsyncFollowWithRemovedHeaders) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();
  StartAsync(CreateResourceRequest(), mock_client_);
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));
  std::unique_ptr<MockLoader> mock_loader = std::make_unique<MockLoader>();
  MockLoader* mock_loader_prt = mock_loader.get();
  mojo::MakeSelfOwnedReceiver(std::move(mock_loader),
                              std::move(loader_and_clients_[0].first));

  base::RunLoop run_loop_for_redirect;
  mock_loader_prt->SetFollowRedirectCallback(base::BindLambdaForTesting(
      [&](const std::vector<std::string>& removed_headers,
          const net::HttpRequestHeaders& modified_headers) {
        // network::mojom::URLLoader::FollowRedirect() must be called with a
        // non-empty `removed_headers` and empty `modified_headers.
        EXPECT_THAT(removed_headers,
                    ::testing::ElementsAreArray({"Foo-Bar", "Hoge-Piyo"}));
        EXPECT_TRUE(modified_headers.IsEmpty());
        run_loop_for_redirect.Quit();
      }));

  std::optional<net::RedirectInfo> received_redirect_info;
  ResourceRequestClient::FollowRedirectCallback follow_redirect_callback;
  mock_client_->SetOnReceivedRedirectCallback(base::BindLambdaForTesting(
      [&](const net::RedirectInfo& redirect_info,
          network::mojom::URLResponseHeadPtr head,
          ResourceRequestClient::FollowRedirectCallback callback) {
        received_redirect_info = redirect_info;
        follow_redirect_callback = std::move(callback);
      }));

  net::RedirectInfo redirect_info;
  redirect_info.new_url = GURL(kRedirectedUrl);
  client->OnReceiveRedirect(redirect_info,
                            network::mojom::URLResponseHead::New());
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(received_redirect_info);
  EXPECT_EQ(GURL(kRedirectedUrl), received_redirect_info->new_url);

  // Asynchronously call `callback` with a non-empty `removed_headers` and an
  // empty `modified_headers`.
  std::move(follow_redirect_callback).Run({"Foo-Bar", "Hoge-Piyo"}, {});
  run_loop_for_redirect.Run();
  client->OnReceiveResponse(network::mojom::URLResponseHead::New(),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
}

TEST_F(ResourceRequestSenderTest, RedirectAsyncFollowWithModifiedHeaders) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();
  StartAsync(CreateResourceRequest(), mock_client_);
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));
  std::unique_ptr<MockLoader> mock_loader = std::make_unique<MockLoader>();
  MockLoader* mock_loader_prt = mock_loader.get();
  mojo::MakeSelfOwnedReceiver(std::move(mock_loader),
                              std::move(loader_and_clients_[0].first));

  base::RunLoop run_loop_for_redirect;
  mock_loader_prt->SetFollowRedirectCallback(base::BindLambdaForTesting(
      [&](const std::vector<std::string>& removed_headers,
          const net::HttpRequestHeaders& modified_headers) {
        // network::mojom::URLLoader::FollowRedirect() must be called with an
        // empty `removed_headers` and non-empty `modified_headers.
        EXPECT_TRUE(removed_headers.empty());
        EXPECT_EQ(
            "Cookie-Monster: Nom nom nom\r\nDomo-Kun: Loves Chrome\r\n\r\n",
            modified_headers.ToString());
        run_loop_for_redirect.Quit();
      }));

  std::optional<net::RedirectInfo> received_redirect_info;
  ResourceRequestClient::FollowRedirectCallback follow_redirect_callback;
  mock_client_->SetOnReceivedRedirectCallback(base::BindLambdaForTesting(
      [&](const net::RedirectInfo& redirect_info,
          network::mojom::URLResponseHeadPtr head,
          ResourceRequestClient::FollowRedirectCallback callback) {
        received_redirect_info = redirect_info;
        follow_redirect_callback = std::move(callback);
      }));

  net::RedirectInfo redirect_info;
  redirect_info.new_url = GURL(kRedirectedUrl);
  client->OnReceiveRedirect(redirect_info,
                            network::mojom::URLResponseHead::New());
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(received_redirect_info);
  EXPECT_EQ(GURL(kRedirectedUrl), received_redirect_info->new_url);

  // Asynchronously call `callback` with an empty `removed_headers` and
  // non-empty `modified_headers`.
  net::HttpRequestHeaders modified_headers;
  modified_headers.SetHeader("Cookie-Monster", "Nom nom nom");
  modified_headers.SetHeader("Domo-Kun", "Loves Chrome");
  std::move(follow_redirect_callback).Run({}, std::move(modified_headers));
  run_loop_for_redirect.Run();
  client->OnReceiveResponse(network::mojom::URLResponseHead::New(),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
}

TEST_F(ResourceRequestSenderTest, RedirectAsyncFollowAfterCancel) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();
  StartAsync(CreateResourceRequest(), mock_client_);
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));
  std::unique_ptr<MockLoader> mock_loader = std::make_unique<MockLoader>();
  MockLoader* mock_loader_prt = mock_loader.get();
  mojo::MakeSelfOwnedReceiver(std::move(mock_loader),
                              std::move(loader_and_clients_[0].first));

  mock_loader_prt->SetFollowRedirectCallback(
      base::BindRepeating([](const std::vector<std::string>& removed_headers,
                             const net::HttpRequestHeaders& modified_headers) {
        // FollowRedirect() must not be called.
        CHECK(false);
      }));

  net::RedirectInfo redirect_info;
  redirect_info.new_url = GURL(kRedirectedUrl);

  std::optional<net::RedirectInfo> received_redirect_info;
  ResourceRequestClient::FollowRedirectCallback follow_redirect_callback;
  mock_client_->SetOnReceivedRedirectCallback(base::BindLambdaForTesting(
      [&](const net::RedirectInfo& redirect_info,
          network::mojom::URLResponseHeadPtr head,
          ResourceRequestClient::FollowRedirectCallback callback) {
        received_redirect_info = redirect_info;
        follow_redirect_callback = std::move(callback);
      }));
  client->OnReceiveRedirect(redirect_info,
                            network::mojom::URLResponseHead::New());
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(received_redirect_info);
  EXPECT_EQ(redirect_info.new_url, received_redirect_info->new_url);

  // Aynchronously cancels the request.
  sender()->Cancel(scheduler::GetSingleThreadTaskRunnerForTesting());
  std::move(follow_redirect_callback).Run({}, {});
  base::RunLoop().RunUntilIdle();
}

TEST_F(ResourceRequestSenderTest, ReceiveResponseWithoutMetadata) {
  mock_client_ = base::MakeRefCounted<MockRequestCl
"""


```