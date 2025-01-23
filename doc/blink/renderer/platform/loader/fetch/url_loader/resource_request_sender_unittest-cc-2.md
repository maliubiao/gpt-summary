Response:
The user wants a summary of the functionality of the provided C++ code, which is a unit test file for `ResourceRequestSender` in the Chromium Blink engine. I need to identify the main purpose of this class and how the tests verify its behavior. I also need to look for connections to JavaScript, HTML, and CSS, provide examples if found, and identify potential user/programming errors.

Here's a breakdown of the code's functionality and how it relates to the user's requests:

1. **Core Functionality:** The tests focus on verifying the `ResourceRequestSender` class's ability to initiate and manage resource requests. This includes handling redirects, interacting with the code cache, and processing responses.

2. **JavaScript/HTML/CSS Relation:** Resource requests are fundamental to loading web resources, including JavaScript, HTML, and CSS files. The tests simulate scenarios like fetching these resources and handling redirects, which are common in web development.

3. **Logical Reasoning and Examples:** The tests use mock objects and specific input conditions to verify expected output. I can extract these scenarios and present them as "if input X, then output Y" examples.

4. **User/Programming Errors:** The tests implicitly cover potential errors by verifying correct behavior under various conditions. I can identify common mistakes related to resource loading and how the `ResourceRequestSender` handles them.

5. **Overall Summary:** I need to synthesize the individual test cases into a concise summary of the `ResourceRequestSender`'s role and the aspects being tested.

**Mental Sandbox Simulation:**

* **Scenario 1: Basic Request:** A test sends a simple resource request and verifies that the response is received correctly. This directly relates to fetching any web resource.
* **Scenario 2: Redirect Handling:** Tests simulate server redirects and check if `ResourceRequestSender` correctly follows them, potentially modifying headers. This is crucial for navigating web pages.
* **Scenario 3: Code Cache Interaction:** Tests involving the `DummyCodeCacheHost` demonstrate how `ResourceRequestSender` interacts with the code cache for resources like WebAssembly modules. This is relevant to JavaScript performance.
* **Scenario 4: Synchronous Requests:** Tests in the `ResourceRequestSenderSyncTest` suite verify the behavior of synchronous resource loading, which can be used in specific scenarios within web pages.
* **Scenario 5: Time Conversion:** The `TimeConversionTest` and `CompletionTimeConversionTest` suites ensure that timing information related to resource loading is correctly handled and converted, which is important for performance monitoring and analysis.

**Key Takeaways for the Summary:**

* `ResourceRequestSender` is responsible for sending network requests for web resources.
* It handles asynchronous and synchronous requests.
* It correctly follows redirects, allowing modification of headers during redirects.
* It interacts with the code cache for optimizing resource loading, particularly for WebAssembly.
* It provides mechanisms for tracking and converting timing information related to network requests.

Confidence Score: 5/5 - I'm confident I can provide a comprehensive summary and address all aspects of the user's request.
这是对 `blink/renderer/platform/loader/fetch/url_loader/resource_request_sender_unittest.cc` 文件的功能归纳总结，延续之前两个部分的内容。该文件主要包含对 `ResourceRequestSender` 类的单元测试。这个类在 Chromium Blink 引擎中负责**发起和管理资源请求**，是网络请求流程中的核心组件。

综合来看，这个单元测试文件通过各种测试用例，验证了 `ResourceRequestSender` 在不同场景下的行为是否符合预期。 这些场景包括：

**核心功能:**

* **发起异步和同步请求:** 测试了 `StartAsync` 和 `SendSync` 方法，验证了发起网络请求的基本功能。
* **处理重定向:**  测试了在异步和同步请求中，`ResourceRequestSender` 如何处理 HTTP 重定向，包括：
    * 接收到重定向通知 (`OnReceiveRedirect`)。
    * 决定是否跟随重定向。
    * 在跟随重定向时，是否能添加或移除请求头。
    * 取消重定向请求。
* **与代码缓存交互:** 测试了 `ResourceRequestSender` 如何与代码缓存交互，特别是在请求 WebAssembly 资源时。
    * 验证了在请求 WebAssembly 时会查询代码缓存。
    * 验证了在特定情况下（如跨域重定向），会清除代码缓存。
* **处理 Keepalive 请求:** 测试了对于标记为 keepalive 的请求的处理方式。
* **处理响应:** 测试了接收到服务器响应 (`OnReceiveResponse`) 的处理，包括：
    * 接收响应头和响应体。
    * 处理没有元数据的响应。
* **处理请求完成:** 测试了请求完成 (`OnComplete`) 的处理。
* **处理各种网络错误:** 虽然代码中没有明确展示，但作为单元测试，它可能涵盖了各种网络错误场景（如连接失败、超时等），尽管这些可能在其他相关的测试文件中。

**与 JavaScript, HTML, CSS 的关系举例:**

`ResourceRequestSender` 负责加载所有类型的 Web 资源，因此与 JavaScript, HTML, CSS 的功能息息相关。

* **JavaScript:**
    * **例子：WebAssembly 代码缓存请求测试 (`WebAssemblyCodeCacheRequest`)**  直接关联到 JavaScript 中的 WebAssembly 功能。当浏览器请求 `.wasm` 文件时，`ResourceRequestSender` 会参与发起请求，并与代码缓存进行交互，以优化加载速度。
    * **假设输入：**  JavaScript 代码尝试加载一个 WebAssembly 模块： `await fetch('my-module.wasm');`
    * **输出：** `ResourceRequestSender` 发起一个类型为 `RequestDestination::kEmpty` 的请求，并调用代码缓存服务检查是否存在缓存。
* **HTML:**
    * **例子：基本的异步请求测试 (`BasicAsyncRequest`)** 可以模拟加载 HTML 文件。
    * **假设输入：**  浏览器导航到一个新的 URL，例如 `https://example.com/index.html`。
    * **输出：** `ResourceRequestSender` 发起一个针对 `https://example.com/index.html` 的请求，以获取 HTML 内容。
* **CSS:**
    * **例子：没有直接的 CSS 特定测试，但逻辑类似。** 加载 CSS 文件的方式与 HTML 类似。
    * **假设输入：**  HTML 文件中包含一个 `<link>` 标签引用 CSS 文件： `<link rel="stylesheet" href="style.css">`。
    * **输出：**  当浏览器解析到这个标签时，`ResourceRequestSender` 会发起一个针对 `style.css` 的请求。
* **重定向:**  无论是请求 HTML, JavaScript 还是 CSS 文件，都可能发生重定向。测试中对重定向的处理，确保了这些资源能够正确加载。

**逻辑推理 (假设输入与输出):**

* **假设输入 (异步重定向):**  请求 `kTestPageUrl`，服务器返回一个 302 重定向到相同的 `kTestPageUrl` (不同的 scheme)。
* **输出:** `loader_and_clients_.size()` 为 2，表示创建了两个 URLLoader，并且第二次请求的 URL 与重定向后的 URL 一致。代码缓存会被清除。
* **假设输入 (同步重定向，Client决定不跟随):** 请求某个 URL，服务器返回重定向，`MockRequestClient` 的 `OnReceivedRedirectCallback` 中不调用 `callback`。
* **输出:** 同步请求最终返回 `net::ERR_ABORTED` 错误码，表示请求被取消。

**涉及用户或者编程常见的使用错误 (举例说明):**

* **未正确处理重定向:** 开发者可能错误地假设请求不会被重定向，或者没有正确处理重定向后的 URL 或请求头。`ResourceRequestSender` 的测试确保了 Blink 引擎能正确处理这些情况，但开发者仍然需要在他们的代码中注意这些潜在的问题。
* **缓存策略理解不足:** 开发者可能不了解浏览器缓存的工作方式，导致不必要的网络请求。 `ResourceRequestSender` 与代码缓存的交互测试，体现了浏览器在优化资源加载方面的努力。开发者应该合理设置缓存头，以提高性能。
* **同步请求的滥用:**  虽然 `ResourceRequestSender` 提供了同步请求的功能，但在主线程上进行同步网络请求会导致页面卡顿，是应该避免的常见错误。测试中也验证了同步请求的行为，但这并不意味着应该随意使用。

**功能归纳 (第三部分):**

这部分测试主要集中在以下方面：

* **同步请求的详细测试:**  深入测试了 `ResourceRequestSender` 的同步请求功能 (`SendSync`)，包括处理重定向时添加或移除请求头的情况，以及取消同步请求的情况。
* **时间转换测试:**  测试了在网络请求过程中，各种时间戳 (`request_start`, `response_start`, `completion_time` 等) 的正确记录和转换。这对于性能分析和调试非常重要。测试用例覆盖了部分初始化、未初始化以及完整初始化的情况，确保时间信息的准确性。
* **完成时间转换的特定测试:** 针对请求完成时间 (`completion_time`) 进行了更细致的测试，包括空时间戳和远程请求开始时间不可用的情况，验证了时间转换逻辑的健壮性。

总而言之，`resource_request_sender_unittest.cc` 通过大量的单元测试，细致地验证了 `ResourceRequestSender` 在各种场景下的正确性和健壮性，确保了 Blink 引擎能够可靠高效地发起和管理网络资源请求，这是构建现代 Web 应用的基础。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/url_loader/resource_request_sender_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
GURL(kTestPageUrl), redirect_info.new_url);
        // Synchronously call `callback` with an empty `removed_headers`.
        std::move(callback).Run({}, {});
      }));
  net::RedirectInfo redirect_info;
  redirect_info.new_url = GURL(kTestPageUrl);
  client->OnReceiveRedirect(redirect_info,
                            network::mojom::URLResponseHead::New());
  base::RunLoop().RunUntilIdle();

  // Different scheme redirect triggers another CreateLoaderAndStart() call.
  ASSERT_EQ(2u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> second_client(
      std::move(loader_and_clients_[1].second));

  // Send a response without metadata.
  second_client->OnReceiveResponse(
      CreateResponse(), mojo::ScopedDataPipeConsumerHandle(), std::nullopt);

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
  EXPECT_FALSE(mock_client_->cached_metadata());
  // Code cache must be cleared.
  EXPECT_TRUE(code_cache_host->did_clear_code_cache_entry());
}

TEST_F(ResourceRequestSenderTest, WebAssemblyCodeCacheRequest) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->destination = network::mojom::RequestDestination::kEmpty;

  base::RunLoop run_loop;
  FetchCachedCodeCallback fetch_cached_code_callback;
  auto code_cache_host =
      std::make_unique<DummyCodeCacheHost>(base::BindLambdaForTesting(
          [&](mojom::blink::CodeCacheType cache_type, const KURL& url,
              FetchCachedCodeCallback callback) {
            fetch_cached_code_callback = std::move(callback);
            // When `destination` is RequestDestination::kEmpty, `cache_type`
            // must be `CodeCacheType::kWebAssembly`.
            EXPECT_EQ(mojom::blink::CodeCacheType::kWebAssembly, cache_type);
            EXPECT_EQ(kTestPageUrl, url);
            run_loop.Quit();
          }));

  StartAsync(std::move(request), mock_client_,
             code_cache_host->GetCodeCacheHost());
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  run_loop.Run();
  std::move(fetch_cached_code_callback)
      .Run(base::Time(), mojo_base::BigBuffer());
  base::RunLoop().RunUntilIdle();

  client->OnReceiveResponse(CreateResponse(),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
  EXPECT_FALSE(mock_client_->cached_metadata());
  EXPECT_FALSE(code_cache_host->did_clear_code_cache_entry());
}

TEST_F(ResourceRequestSenderTest, KeepaliveRequest) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->keepalive = true;

  auto code_cache_host =
      std::make_unique<DummyCodeCacheHost>(base::BindLambdaForTesting(
          [&](mojom::blink::CodeCacheType cache_type, const KURL& url,
              FetchCachedCodeCallback callback) {
            CHECK(false) << "FetchCachedCode shouold not be called";
          }));

  StartAsync(std::move(request), mock_client_,
             code_cache_host->GetCodeCacheHost());
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  client->OnReceiveResponse(CreateResponse(),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
}

class ResourceRequestSenderSyncTest : public testing::Test {
 public:
  explicit ResourceRequestSenderSyncTest() = default;
  ResourceRequestSenderSyncTest(const ResourceRequestSenderSyncTest&) = delete;
  ResourceRequestSenderSyncTest& operator=(
      const ResourceRequestSenderSyncTest&) = delete;
  ~ResourceRequestSenderSyncTest() override = default;

 protected:
  SyncLoadResponse SendSync(
      scoped_refptr<ResourceRequestClient> client,
      scoped_refptr<network::SharedURLLoaderFactory> loader_factory) {
    base::WaitableEvent terminate_sync_load_event(
        base::WaitableEvent::ResetPolicy::MANUAL,
        base::WaitableEvent::InitialState::NOT_SIGNALED);
    SyncLoadResponse response;
    auto sender = std::make_unique<ResourceRequestSender>();
    sender->SendSync(CreateSyncResourceRequest(), TRAFFIC_ANNOTATION_FOR_TESTS,
                     network::mojom::kURLLoadOptionSynchronous, &response,
                     std::move(loader_factory),
                     /*throttles=*/{},
                     /*timeout=*/base::Seconds(100),
                     /*cors_exempt_header_list*/ {}, &terminate_sync_load_event,
                     /*download_to_blob_registry=*/
                     mojo::PendingRemote<mojom::blink::BlobRegistry>(), client,
                     std::make_unique<ResourceLoadInfoNotifierWrapper>(
                         /*resource_load_info_notifier=*/nullptr));
    return response;
  }
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

 private:
  ScopedTestingPlatformSupport<TestPlatformForRedirects> platform_;
};

TEST_F(ResourceRequestSenderSyncTest, SendSyncRequest) {
  scoped_refptr<MockRequestClient> mock_client =
      base::MakeRefCounted<MockRequestClient>();
  auto loader_factory =
      base::MakeRefCounted<
          FakeURLLoaderFactoryForBackgroundThread>(base::BindOnce(
          [](mojo::PendingReceiver<network::mojom::URLLoader> loader,
             mojo::PendingRemote<network::mojom::URLLoaderClient> client) {
            mojo::MakeSelfOwnedReceiver(std::make_unique<MockLoader>(),
                                        std::move(loader));
            mojo::Remote<network::mojom::URLLoaderClient> loader_client(
                std::move(client));
            loader_client->OnReceiveResponse(
                network::mojom::URLResponseHead::New(),
                CreateDataPipeConsumerHandleFilledWithString(kTestData),
                std::nullopt);
            loader_client->OnComplete(
                network::URLLoaderCompletionStatus(net::Error::OK));
          }));
  SyncLoadResponse response = SendSync(mock_client, std::move(loader_factory));
  EXPECT_EQ(net::OK, response.error_code);
  ASSERT_TRUE(response.data);
  EXPECT_EQ(kTestData,
            std::string(response.data->begin()->data(), response.data->size()));
}

TEST_F(ResourceRequestSenderSyncTest, SendSyncRedirect) {
  scoped_refptr<MockRequestClient> mock_client =
      base::MakeRefCounted<MockRequestClient>();
  mock_client->SetOnReceivedRedirectCallback(base::BindLambdaForTesting(
      [&](const net::RedirectInfo& redirect_info,
          network::mojom::URLResponseHeadPtr head,
          ResourceRequestClient::FollowRedirectCallback callback) {
        EXPECT_EQ(GURL(kRedirectedUrl), redirect_info.new_url);
        // Synchronously call `callback` with an empty `removed_headers` and
        // empty `modified_headers`.
        std::move(callback).Run({}, {});
      }));

  auto loader_factory = base::MakeRefCounted<
      FakeURLLoaderFactoryForBackgroundThread>(base::BindOnce(
      [](mojo::PendingReceiver<network::mojom::URLLoader> loader,
         mojo::PendingRemote<network::mojom::URLLoaderClient> client) {
        std::unique_ptr<MockLoader> mock_loader =
            std::make_unique<MockLoader>();
        MockLoader* mock_loader_prt = mock_loader.get();
        mojo::MakeSelfOwnedReceiver(std::move(mock_loader), std::move(loader));

        mojo::Remote<network::mojom::URLLoaderClient> loader_client(
            std::move(client));

        net::RedirectInfo redirect_info;
        redirect_info.new_url = GURL(kRedirectedUrl);
        loader_client->OnReceiveRedirect(
            redirect_info, network::mojom::URLResponseHead::New());

        scoped_refptr<RefCountedURLLoaderClientRemote> refcounted_client =
            base::MakeRefCounted<RefCountedURLLoaderClientRemote>(
                std::move(loader_client));

        mock_loader_prt->SetFollowRedirectCallback(base::BindRepeating(
            [](scoped_refptr<RefCountedURLLoaderClientRemote> refcounted_client,
               const std::vector<std::string>& removed_headers,
               const net::HttpRequestHeaders& modified_headers) {
              // network::mojom::URLLoader::FollowRedirect() must be called with
              // an empty `removed_headers` and empty `modified_headers.
              EXPECT_TRUE(removed_headers.empty());
              EXPECT_TRUE(modified_headers.IsEmpty());

              // After FollowRedirect() is called, calls
              // URLLoaderClient::OnReceiveResponse() and
              // URLLoaderClient::OnComplete()
              refcounted_client->data->OnReceiveResponse(
                  network::mojom::URLResponseHead::New(),
                  CreateDataPipeConsumerHandleFilledWithString(kTestData),
                  std::nullopt);

              refcounted_client->data->OnComplete(
                  network::URLLoaderCompletionStatus(net::Error::OK));
            },
            std::move(refcounted_client)));
      }));

  SyncLoadResponse response = SendSync(mock_client, std::move(loader_factory));
  EXPECT_EQ(net::OK, response.error_code);
  ASSERT_TRUE(response.data);
  EXPECT_EQ(kTestData,
            std::string(response.data->begin()->data(), response.data->size()));
}

TEST_F(ResourceRequestSenderSyncTest, SendSyncRedirectWithRemovedHeaders) {
  scoped_refptr<MockRequestClient> mock_client =
      base::MakeRefCounted<MockRequestClient>();
  mock_client->SetOnReceivedRedirectCallback(base::BindLambdaForTesting(
      [&](const net::RedirectInfo& redirect_info,
          network::mojom::URLResponseHeadPtr head,
          ResourceRequestClient::FollowRedirectCallback callback) {
        EXPECT_EQ(GURL(kRedirectedUrl), redirect_info.new_url);
        // network::mojom::URLLoader::FollowRedirect() must be called with a
        // non-empty `removed_headers` and empty `modified_headers.
        std::move(callback).Run({"Foo-Bar", "Hoge-Piyo"}, {});
      }));

  auto loader_factory = base::MakeRefCounted<
      FakeURLLoaderFactoryForBackgroundThread>(base::BindOnce(
      [](mojo::PendingReceiver<network::mojom::URLLoader> loader,
         mojo::PendingRemote<network::mojom::URLLoaderClient> client) {
        std::unique_ptr<MockLoader> mock_loader =
            std::make_unique<MockLoader>();
        MockLoader* mock_loader_prt = mock_loader.get();
        mojo::MakeSelfOwnedReceiver(std::move(mock_loader), std::move(loader));

        mojo::Remote<network::mojom::URLLoaderClient> loader_client(
            std::move(client));

        net::RedirectInfo redirect_info;
        redirect_info.new_url = GURL(kRedirectedUrl);
        loader_client->OnReceiveRedirect(
            redirect_info, network::mojom::URLResponseHead::New());

        scoped_refptr<RefCountedURLLoaderClientRemote> refcounted_client =
            base::MakeRefCounted<RefCountedURLLoaderClientRemote>(
                std::move(loader_client));

        mock_loader_prt->SetFollowRedirectCallback(base::BindRepeating(
            [](scoped_refptr<RefCountedURLLoaderClientRemote> refcounted_client,
               const std::vector<std::string>& removed_headers,
               const net::HttpRequestHeaders& modified_headers) {
              // Synchronously call `callback` with a non-empty
              // `removed_headers` and empty `modified_headers.
              EXPECT_THAT(removed_headers, ::testing::ElementsAreArray(
                                               {"Foo-Bar", "Hoge-Piyo"}));
              EXPECT_TRUE(modified_headers.IsEmpty());

              // After FollowRedirect() is called, calls
              // URLLoaderClient::OnReceiveResponse() and
              // URLLoaderClient::OnComplete()
              refcounted_client->data->OnReceiveResponse(
                  network::mojom::URLResponseHead::New(),
                  CreateDataPipeConsumerHandleFilledWithString(kTestData),
                  std::nullopt);
              refcounted_client->data->OnComplete(
                  network::URLLoaderCompletionStatus(net::Error::OK));
            },
            std::move(refcounted_client)));
      }));

  SyncLoadResponse response = SendSync(mock_client, std::move(loader_factory));
  EXPECT_EQ(net::OK, response.error_code);
  ASSERT_TRUE(response.data);
  EXPECT_EQ(kTestData,
            std::string(response.data->begin()->data(), response.data->size()));
}

TEST_F(ResourceRequestSenderSyncTest, SendSyncRedirectWithModifiedHeaders) {
  scoped_refptr<MockRequestClient> mock_client =
      base::MakeRefCounted<MockRequestClient>();
  mock_client->SetOnReceivedRedirectCallback(base::BindLambdaForTesting(
      [&](const net::RedirectInfo& redirect_info,
          network::mojom::URLResponseHeadPtr head,
          ResourceRequestClient::FollowRedirectCallback callback) {
        EXPECT_EQ(GURL(kRedirectedUrl), redirect_info.new_url);
        // network::mojom::URLLoader::FollowRedirect() must be called with an
        // empty `removed_headers` and non-empty `modified_headers.
        net::HttpRequestHeaders modified_headers;
        modified_headers.SetHeader("Cookie-Monster", "Nom nom nom");
        modified_headers.SetHeader("Domo-Kun", "Loves Chrome");
        std::move(callback).Run({}, std::move(modified_headers));
      }));

  auto loader_factory = base::MakeRefCounted<
      FakeURLLoaderFactoryForBackgroundThread>(base::BindOnce(
      [](mojo::PendingReceiver<network::mojom::URLLoader> loader,
         mojo::PendingRemote<network::mojom::URLLoaderClient> client) {
        std::unique_ptr<MockLoader> mock_loader =
            std::make_unique<MockLoader>();
        MockLoader* mock_loader_prt = mock_loader.get();
        mojo::MakeSelfOwnedReceiver(std::move(mock_loader), std::move(loader));

        mojo::Remote<network::mojom::URLLoaderClient> loader_client(
            std::move(client));

        net::RedirectInfo redirect_info;
        redirect_info.new_url = GURL(kRedirectedUrl);
        loader_client->OnReceiveRedirect(
            redirect_info, network::mojom::URLResponseHead::New());

        scoped_refptr<RefCountedURLLoaderClientRemote> refcounted_client =
            base::MakeRefCounted<RefCountedURLLoaderClientRemote>(
                std::move(loader_client));

        mock_loader_prt->SetFollowRedirectCallback(base::BindRepeating(
            [](scoped_refptr<RefCountedURLLoaderClientRemote> refcounted_client,
               const std::vector<std::string>& removed_headers,
               const net::HttpRequestHeaders& modified_headers) {
              // Synchronously call `callback` with an empty
              // `removed_headers` and non-empty `modified_headers.
              EXPECT_TRUE(removed_headers.empty());
              EXPECT_EQ(
                  "Cookie-Monster: Nom nom nom\r\nDomo-Kun: Loves "
                  "Chrome\r\n\r\n",
                  modified_headers.ToString());

              // After FollowRedirect() is called, calls
              // URLLoaderClient::OnReceiveResponse() and
              // URLLoaderClient::OnComplete()
              refcounted_client->data->OnReceiveResponse(
                  network::mojom::URLResponseHead::New(),
                  CreateDataPipeConsumerHandleFilledWithString(kTestData),
                  std::nullopt);
              refcounted_client->data->OnComplete(
                  network::URLLoaderCompletionStatus(net::Error::OK));
            },
            std::move(refcounted_client)));
      }));

  SyncLoadResponse response = SendSync(mock_client, std::move(loader_factory));
  EXPECT_EQ(net::OK, response.error_code);
  ASSERT_TRUE(response.data);
  EXPECT_EQ(kTestData,
            std::string(response.data->begin()->data(), response.data->size()));
}

TEST_F(ResourceRequestSenderSyncTest, SendSyncRedirectCancel) {
  scoped_refptr<MockRequestClient> mock_client =
      base::MakeRefCounted<MockRequestClient>();
  mock_client->SetOnReceivedRedirectCallback(base::BindLambdaForTesting(
      [&](const net::RedirectInfo& redirect_info,
          network::mojom::URLResponseHeadPtr head,
          ResourceRequestClient::FollowRedirectCallback callback) {
        EXPECT_EQ(GURL(kRedirectedUrl), redirect_info.new_url);
        // Don't call callback to cancel the request.
      }));

  auto loader_factory =
      base::MakeRefCounted<
          FakeURLLoaderFactoryForBackgroundThread>(base::BindOnce(
          [](mojo::PendingReceiver<network::mojom::URLLoader> loader,
             mojo::PendingRemote<network::mojom::URLLoaderClient> client) {
            std::unique_ptr<MockLoader> mock_loader =
                std::make_unique<MockLoader>();
            MockLoader* mock_loader_prt = mock_loader.get();
            mojo::MakeSelfOwnedReceiver(std::move(mock_loader),
                                        std::move(loader));

            mojo::Remote<network::mojom::URLLoaderClient> loader_client(
                std::move(client));

            net::RedirectInfo redirect_info;
            redirect_info.new_url = GURL(kRedirectedUrl);
            loader_client->OnReceiveRedirect(
                redirect_info, network::mojom::URLResponseHead::New());

            scoped_refptr<RefCountedURLLoaderClientRemote> refcounted_client =
                base::MakeRefCounted<RefCountedURLLoaderClientRemote>(
                    std::move(loader_client));

            mock_loader_prt->SetFollowRedirectCallback(base::BindRepeating(
                [](scoped_refptr<base::RefCountedData<mojo::Remote<
                       network::mojom::URLLoaderClient>>> refcounted_client,
                   const std::vector<std::string>& removed_headers,
                   const net::HttpRequestHeaders& modified_headers) {
                  // FollowRedirect() must not be called.
                  CHECK(false);
                },
                std::move(refcounted_client)));
          }));

  SyncLoadResponse response = SendSync(mock_client, std::move(loader_factory));
  EXPECT_EQ(net::ERR_ABORTED, response.error_code);
  EXPECT_FALSE(response.data);
}

class TimeConversionTest : public ResourceRequestSenderTest {
 public:
  void PerformTest(network::mojom::URLResponseHeadPtr response_head) {
    std::unique_ptr<network::ResourceRequest> request(CreateResourceRequest());
    mock_client_ = base::MakeRefCounted<MockRequestClient>();
    StartAsync(std::move(request), mock_client_);

    ASSERT_EQ(1u, loader_and_clients_.size());
    mojo::Remote<network::mojom::URLLoaderClient> client(
        std::move(loader_and_clients_[0].second));
    loader_and_clients_.clear();
    client->OnReceiveResponse(std::move(response_head),
                              mojo::ScopedDataPipeConsumerHandle(),
                              std::nullopt);
    base::RunLoop().RunUntilIdle();
  }
  const net::LoadTimingInfo& received_load_timing() const {
    CHECK(mock_client_);
    return mock_client_->last_load_timing();
  }
};

TEST_F(TimeConversionTest, ProperlyInitialized) {
  auto response_head = network::mojom::URLResponseHead::New();
  response_head->request_start = TicksFromMicroseconds(5);
  response_head->response_start = TicksFromMicroseconds(15);
  response_head->load_timing.request_start_time = base::Time::Now();
  response_head->load_timing.request_start = TicksFromMicroseconds(10);
  response_head->load_timing.connect_timing.connect_start =
      TicksFromMicroseconds(13);

  auto request_start = response_head->load_timing.request_start;
  PerformTest(std::move(response_head));

  EXPECT_LT(base::TimeTicks(), received_load_timing().request_start);
  EXPECT_EQ(base::TimeTicks(),
            received_load_timing().connect_timing.domain_lookup_start);
  EXPECT_LE(request_start, received_load_timing().connect_timing.connect_start);
}

TEST_F(TimeConversionTest, PartiallyInitialized) {
  auto response_head = network::mojom::URLResponseHead::New();
  response_head->request_start = TicksFromMicroseconds(5);
  response_head->response_start = TicksFromMicroseconds(15);

  PerformTest(std::move(response_head));

  EXPECT_EQ(base::TimeTicks(), received_load_timing().request_start);
  EXPECT_EQ(base::TimeTicks(),
            received_load_timing().connect_timing.domain_lookup_start);
}

TEST_F(TimeConversionTest, NotInitialized) {
  auto response_head = network::mojom::URLResponseHead::New();

  PerformTest(std::move(response_head));

  EXPECT_EQ(base::TimeTicks(), received_load_timing().request_start);
  EXPECT_EQ(base::TimeTicks(),
            received_load_timing().connect_timing.domain_lookup_start);
}

class CompletionTimeConversionTest : public ResourceRequestSenderTest {
 public:
  void PerformTest(base::TimeTicks remote_request_start,
                   base::TimeTicks completion_time,
                   base::TimeDelta delay) {
    std::unique_ptr<network::ResourceRequest> request(CreateResourceRequest());
    mock_client_ = base::MakeRefCounted<MockRequestClient>();
    StartAsync(std::move(request), mock_client_);

    ASSERT_EQ(1u, loader_and_clients_.size());
    mojo::Remote<network::mojom::URLLoaderClient> client(
        std::move(loader_and_clients_[0].second));
    auto response_head = network::mojom::URLResponseHead::New();
    response_head->request_start = remote_request_start;
    response_head->load_timing.request_start = remote_request_start;
    response_head->load_timing.receive_headers_end = remote_request_start;
    // We need to put something non-null time, otherwise no values will be
    // copied.
    response_head->load_timing.request_start_time =
        base::Time() + base::Seconds(99);

    mojo::ScopedDataPipeProducerHandle producer_handle;
    mojo::ScopedDataPipeConsumerHandle consumer_handle;
    ASSERT_EQ(mojo::CreateDataPipe(nullptr, producer_handle, consumer_handle),
              MOJO_RESULT_OK);

    client->OnReceiveResponse(std::move(response_head),
                              std::move(consumer_handle), std::nullopt);
    producer_handle.reset();  // The response is empty.

    network::URLLoaderCompletionStatus status;
    status.completion_time = completion_time;

    client->OnComplete(status);

    const base::TimeTicks until = base::TimeTicks::Now() + delay;
    while (base::TimeTicks::Now() < until) {
      base::PlatformThread::Sleep(base::Milliseconds(1));
    }
    base::RunLoop().RunUntilIdle();
    loader_and_clients_.clear();
  }

  base::TimeTicks request_start() const {
    EXPECT_TRUE(mock_client_->received_response());
    return mock_client_->last_load_timing().request_start;
  }
  base::TimeTicks completion_time() const {
    EXPECT_TRUE(mock_client_->complete());
    return mock_client_->completion_status().completion_time;
  }
};

TEST_F(CompletionTimeConversionTest, NullCompletionTimestamp) {
  const auto remote_request_start = base::TimeTicks() + base::Milliseconds(4);

  PerformTest(remote_request_start, base::TimeTicks(), base::TimeDelta());

  EXPECT_EQ(base::TimeTicks(), completion_time());
}

TEST_F(CompletionTimeConversionTest, RemoteRequestStartIsUnavailable) {
  base::TimeTicks begin = base::TimeTicks::Now();

  const auto remote_completion_time = base::TimeTicks() + base::Milliseconds(8);

  PerformTest(base::TimeTicks(), remote_completion_time, base::TimeDelta());

  base::TimeTicks end = base::TimeTicks::Now();
  EXPECT_LE(begin, completion_time());
  EXPECT_LE(completion_time(), end);
}

TEST_F(CompletionTimeConversionTest, Convert) {
  const auto remote_request_start = base::TimeTicks() + base::Milliseconds(4);

  const auto remote_completion_time =
      remote_request_start + base::Milliseconds(3);

  PerformTest(remote_request_start, remote_completion_time,
              base::Milliseconds(15));

  EXPECT_EQ(completion_time(), request_start() + base::Milliseconds(3));
}

}  // namespace
}  // namespace blink
```