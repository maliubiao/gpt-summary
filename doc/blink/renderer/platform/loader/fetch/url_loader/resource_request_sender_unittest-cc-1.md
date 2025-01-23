Response:
The user has provided a C++ unit test file for `ResourceRequestSender` in Chromium's Blink engine and is asking for a summary of its functionalities. Specifically, the user wants to know:
1. What are the functionalities of the code?
2. How does it relate to JavaScript, HTML, and CSS?
3. Are there any logical inferences that can be made with example inputs and outputs?
4. Are there any common user or programming errors demonstrated?
5. This is part 2 of 3, so summarize the functionalities of this specific part.

Looking at the code, it primarily focuses on testing how `ResourceRequestSender` interacts with the code cache. The tests cover scenarios such as:

- Receiving responses with and without metadata.
- Receiving cached code data before receiving a network response.
- Handling mismatches between cached code timestamps and network response timestamps.
- Interactions with service workers and the cache storage API.
- Specific handling for code cache with hashing.
- Handling the case where the `ResourceRequestSender` is "frozen".

**Overall Strategy:**  I will go through each test case, understand what it's testing, and then synthesize that information into a functional summary, relating it to web technologies where applicable.

**Detailed Plan:**

1. **Identify the core component being tested:**  `ResourceRequestSender` and its interaction with the code cache.
2. **Analyze each `TEST_F` function:**
    - Determine the scenario being tested.
    - Identify the key actions and assertions.
    - Note any interactions with `MockRequestClient` and `DummyCodeCacheHost`.
3. **Relate to web technologies:** Connect the tested scenarios to how browsers load and execute web resources (JavaScript, specifically for code caching).
4. **Logical Inferences:** Based on the test names and assertions, infer the expected behavior of `ResourceRequestSender` under different conditions. Provide hypothetical inputs (request types, cache state) and outputs (client notifications, cache updates).
5. **Common Errors:**  Think about common mistakes developers might make regarding caching, request handling, and service worker interactions, and see if any of the tests highlight these.
6. **Synthesize the Part 2 summary:** Focus on the code presented in this specific excerpt and summarize its core functionalities related to code caching.

**Mental Walkthrough of the Code:**

- The tests heavily use `MockRequestClient` to verify the notifications received by the client of `ResourceRequestSender`.
- `DummyCodeCacheHost` simulates the behavior of the code cache.
- Several tests focus on the order of events: receiving code cache data before or after the network response.
- Some tests explicitly check if the code cache is cleared under certain conditions (e.g., timestamp mismatch, service worker intervention).
- The tests involving service workers differentiate between synthetic responses, pass-through responses, and responses with different URLs.
- The "frozen" state test is interesting and likely related to performance optimization or resource management.

**Key Observations for Synthesis:**

- Code caching is a primary concern.
- The tests verify the correctness of cache updates and invalidations.
- Service worker interactions impact code cache behavior.
- The `ResourceRequestSender` needs to handle asynchronous operations and various interleavings of network responses and cached data.

**(Self-Correction):** Initially, I might have focused too broadly on all aspects of `ResourceRequestSender`. However, the provided code snippet is clearly centered around code caching, so I need to tailor the summary accordingly. The "part 2 of 3" instruction reinforces this focus.
这个C++代码文件 `resource_request_sender_unittest.cc` 的第 2 部分主要专注于测试 `ResourceRequestSender` 类在处理 **代码缓存 (Code Cache)** 相关的逻辑。  它模拟了各种场景，验证 `ResourceRequestSender` 在与代码缓存交互时的行为是否符合预期。

以下是这个代码部分的功能归纳：

**核心功能：测试 `ResourceRequestSender` 与代码缓存的交互**

这部分测试主要围绕以下几个方面展开：

1. **接收和处理代码缓存数据：**
   - 测试当代码缓存中存在数据时，`ResourceRequestSender` 是否能够正确地接收并传递给客户端 (通过 `MockRequestClient` 模拟)。
   - 测试当代码缓存中没有数据时，`ResourceRequestSender` 的处理方式。
   - 测试接收到代码缓存数据后，是否还能正常接收并处理来自网络的响应。

2. **代码缓存的有效性验证：**
   - 测试当代码缓存的时间戳与网络响应的时间戳不一致时，`ResourceRequestSender` 是否会清理代码缓存。这确保了代码缓存不会使用过时的版本。

3. **与网络响应的交互：**
   - 测试在接收到代码缓存数据之后，接收到网络响应时，元数据 (metadata) 的处理情况。
   - 测试接收网络响应的元数据后，再接收到代码缓存的情况，以及是否会清理代码缓存。

4. **在特定状态下的行为：**
   - 测试当 `ResourceRequestSender` 处于 "冻结 (frozen)" 状态时，接收到代码缓存数据的处理方式，以及解冻后的行为。这可能涉及到资源加载的优先级或暂停机制。

5. **与 Service Worker 的交互：**
   - 测试当请求通过 Service Worker 处理时，代码缓存的行为。
   - 区分了 Service Worker 返回合成响应 (synthetic response)、直通响应 (pass-through response) 以及不同 URL 的响应，验证代码缓存是否会正确地被清理或保留。
   - 测试当响应来自 Service Worker 的缓存存储 (Cache Storage) 时，代码缓存的行为。

6. **针对特定 URL Scheme 的代码缓存行为：**
   - 测试针对注册为需要哈希的代码缓存的 URL Scheme，在有或没有代码缓存数据时的处理情况。

**与 JavaScript, HTML, CSS 的关系：**

这部分代码主要与 **JavaScript** 的性能优化密切相关。代码缓存用于存储编译后的 JavaScript 代码，以便在后续加载相同的脚本时可以更快地执行，而无需重新解析和编译。

* **JavaScript:** 代码缓存直接影响 JavaScript 的加载和执行速度。这些测试验证了在各种情况下，例如首次加载、重复加载、Service Worker 干预等，代码缓存的正确使用和更新机制。例如，测试 `ReceiveCodeCacheThenReceiveResponse` 模拟了从缓存加载 JavaScript 代码，然后接收到网络响应的情况。

* **HTML:**  HTML 中通过 `<script>` 标签引入 JavaScript 文件。代码缓存的有效性直接影响到浏览器加载包含这些脚本的 HTML 页面的速度。

* **CSS:** 虽然这段代码主要关注 JavaScript 的代码缓存，但类似的缓存机制也可能用于 CSS 资源。然而，这段特定的测试代码并没有直接涉及到 CSS。

**逻辑推理（假设输入与输出）：**

**假设输入 1:**

* **请求目标:**  一个 JavaScript 文件 (`request->destination = network::mojom::RequestDestination::kScript;`)
* **代码缓存状态:** 代码缓存中存在与请求 URL 匹配的有效数据，且时间戳与预期一致。
* **网络响应:** 网络响应正常返回。

**预期输出 1:**

* `mock_client_->received_response()` 为 true (客户端接收到响应)。
* `mock_client_->cached_metadata()` 存在且包含代码缓存的数据 (客户端接收到缓存的元数据)。
* `code_cache_host->did_clear_code_cache_entry()` 为 false (代码缓存未被清理)。

**假设输入 2:**

* **请求目标:** 一个 JavaScript 文件。
* **代码缓存状态:** 代码缓存中存在与请求 URL 匹配的数据，但时间戳与网络响应的时间戳不一致。
* **网络响应:** 网络响应正常返回。

**预期输出 2:**

* `mock_client_->received_response()` 为 true。
* `mock_client_->cached_metadata()` 为空或不包含代码缓存的数据。
* `code_cache_host->did_clear_code_cache_entry()` 为 true (代码缓存被清理)。

**用户或编程常见的使用错误：**

这些单元测试主要关注引擎内部的逻辑，不太直接暴露用户或编程的常见使用错误。然而，可以推断出一些潜在的错误：

* **缓存策略配置错误:** 如果浏览器的缓存策略配置不当，可能导致代码缓存无法正常工作，例如缓存过期时间设置过短或根本不缓存。虽然不是直接在这些测试中体现，但这些测试保证了引擎在正确配置下行为的正确性。
* **Service Worker 行为不当:**  开发者编写的 Service Worker 如果错误地处理了缓存逻辑，可能会导致代码缓存失效或不被使用。例如，Service Worker 可能总是返回新的网络响应，而忽略了代码缓存。测试中针对 Service Worker 的场景就模拟了这种情况。
* **对缓存时间戳的误解:** 开发者可能没有意识到缓存的时间戳对于缓存的有效性至关重要，导致在某些情况下错误地认为缓存应该有效。

**总结 - 第 2 部分的功能：**

这部分代码主要功能是 **验证 `ResourceRequestSender` 在处理 JavaScript 代码缓存时的各种场景和逻辑**。它覆盖了代码缓存的加载、有效性检查、与网络响应的交互、在特定状态下的行为以及与 Service Worker 的协同工作，确保 Blink 引擎能够正确且高效地利用代码缓存来提升 JavaScript 的加载性能。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/url_loader/resource_request_sender_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->destination = network::mojom::RequestDestination::kScript;

  StartAsync(std::move(request), mock_client_);
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  // Send a response without metadata.
  client->OnReceiveResponse(network::mojom::URLResponseHead::New(),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
  EXPECT_FALSE(mock_client_->cached_metadata());
}

TEST_F(ResourceRequestSenderTest, ReceiveResponseWithMetadata) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->destination = network::mojom::RequestDestination::kScript;

  StartAsync(std::move(request), mock_client_);
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  // Send a response with metadata.
  std::vector<uint8_t> metadata{1, 2, 3, 4, 5};
  client->OnReceiveResponse(network::mojom::URLResponseHead::New(),
                            mojo::ScopedDataPipeConsumerHandle(),
                            mojo_base::BigBuffer(metadata));

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
  ASSERT_TRUE(mock_client_->cached_metadata());
  EXPECT_EQ(metadata.size(), mock_client_->cached_metadata()->size());
}

TEST_F(ResourceRequestSenderTest, EmptyCodeCacheThenReceiveResponse) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->destination = network::mojom::RequestDestination::kScript;

  base::RunLoop run_loop;
  FetchCachedCodeCallback fetch_cached_code_callback;
  auto code_cache_host =
      std::make_unique<DummyCodeCacheHost>(base::BindLambdaForTesting(
          [&](mojom::blink::CodeCacheType cache_type, const KURL& url,
              FetchCachedCodeCallback callback) {
            fetch_cached_code_callback = std::move(callback);
            EXPECT_EQ(mojom::blink::CodeCacheType::kJavascript, cache_type);
            EXPECT_EQ(kTestPageUrl, url);
            run_loop.Quit();
          }));

  StartAsync(std::move(request), mock_client_,
             code_cache_host->GetCodeCacheHost());
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  run_loop.Run();
  // Send an empty cached data from CodeCacheHost.
  std::move(fetch_cached_code_callback)
      .Run(base::Time(), mojo_base::BigBuffer());
  base::RunLoop().RunUntilIdle();

  // Send a response without metadata.
  client->OnReceiveResponse(network::mojom::URLResponseHead::New(),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
  EXPECT_FALSE(mock_client_->cached_metadata());
  EXPECT_FALSE(code_cache_host->did_clear_code_cache_entry());
}

TEST_F(ResourceRequestSenderTest, ReceiveCodeCacheThenReceiveResponse) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->destination = network::mojom::RequestDestination::kScript;

  base::RunLoop run_loop;
  FetchCachedCodeCallback fetch_cached_code_callback;
  auto code_cache_host =
      std::make_unique<DummyCodeCacheHost>(base::BindLambdaForTesting(
          [&](mojom::blink::CodeCacheType cache_type, const KURL& url,
              FetchCachedCodeCallback callback) {
            fetch_cached_code_callback = std::move(callback);
            run_loop.Quit();
          }));

  StartAsync(std::move(request), mock_client_,
             code_cache_host->GetCodeCacheHost());
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  run_loop.Run();

  auto response = CreateResponse();

  // Send a cached data from CodeCacheHost.
  std::vector<uint8_t> cache_data{1, 2, 3, 4, 5, 6};
  std::move(fetch_cached_code_callback)
      .Run(response->response_time, mojo_base::BigBuffer(cache_data));
  base::RunLoop().RunUntilIdle();

  // Send a response without metadata.
  client->OnReceiveResponse(std::move(response),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
  ASSERT_TRUE(mock_client_->cached_metadata());
  EXPECT_EQ(cache_data.size(), mock_client_->cached_metadata()->size());
  EXPECT_FALSE(code_cache_host->did_clear_code_cache_entry());
}

TEST_F(ResourceRequestSenderTest,
       ReceiveTimeMismatchCodeCacheThenReceiveResponse) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->destination = network::mojom::RequestDestination::kScript;

  base::RunLoop run_loop;
  FetchCachedCodeCallback fetch_cached_code_callback;
  auto code_cache_host =
      std::make_unique<DummyCodeCacheHost>(base::BindLambdaForTesting(
          [&](mojom::blink::CodeCacheType cache_type, const KURL& url,
              FetchCachedCodeCallback callback) {
            fetch_cached_code_callback = std::move(callback);
            run_loop.Quit();
          }));

  StartAsync(std::move(request), mock_client_,
             code_cache_host->GetCodeCacheHost());
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  run_loop.Run();

  auto response = CreateResponse();

  // Send a cached data from CodeCacheHost.
  std::vector<uint8_t> cache_data{1, 2, 3, 4, 5, 6};
  std::move(fetch_cached_code_callback)
      .Run(response->response_time - base::Seconds(1),
           mojo_base::BigBuffer(cache_data));
  base::RunLoop().RunUntilIdle();

  // Send a response without metadata.
  client->OnReceiveResponse(std::move(response),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(mock_client_->received_response());
  EXPECT_FALSE(mock_client_->cached_metadata());
  // Code cache must be cleared.
  EXPECT_TRUE(code_cache_host->did_clear_code_cache_entry());
}

TEST_F(ResourceRequestSenderTest,
       ReceiveEmptyCodeCacheThenReceiveResponseWithMetadata) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->destination = network::mojom::RequestDestination::kScript;

  base::RunLoop run_loop;
  FetchCachedCodeCallback fetch_cached_code_callback;
  auto code_cache_host =
      std::make_unique<DummyCodeCacheHost>(base::BindLambdaForTesting(
          [&](mojom::blink::CodeCacheType cache_type, const KURL& url,
              FetchCachedCodeCallback callback) {
            fetch_cached_code_callback = std::move(callback);
            run_loop.Quit();
          }));

  StartAsync(std::move(request), mock_client_,
             code_cache_host->GetCodeCacheHost());
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  // Send an empty cached data from CodeCacheHost.
  run_loop.Run();
  std::move(fetch_cached_code_callback)
      .Run(base::Time(), mojo_base::BigBuffer());
  base::RunLoop().RunUntilIdle();

  // Send a response with metadata.
  std::vector<uint8_t> metadata{1, 2, 3, 4, 5};
  client->OnReceiveResponse(CreateResponse(),
                            mojo::ScopedDataPipeConsumerHandle(),
                            mojo_base::BigBuffer(metadata));

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
  ASSERT_TRUE(mock_client_->cached_metadata());
  EXPECT_EQ(metadata.size(), mock_client_->cached_metadata()->size());
  EXPECT_FALSE(code_cache_host->did_clear_code_cache_entry());
}

TEST_F(ResourceRequestSenderTest,
       ReceiveCodeCacheThenReceiveResponseWithMetadata) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->destination = network::mojom::RequestDestination::kScript;

  base::RunLoop run_loop;
  FetchCachedCodeCallback fetch_cached_code_callback;
  auto code_cache_host =
      std::make_unique<DummyCodeCacheHost>(base::BindLambdaForTesting(
          [&](mojom::blink::CodeCacheType cache_type, const KURL& url,
              FetchCachedCodeCallback callback) {
            fetch_cached_code_callback = std::move(callback);
            run_loop.Quit();
          }));

  StartAsync(std::move(request), mock_client_,
             code_cache_host->GetCodeCacheHost());
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  run_loop.Run();

  auto response = CreateResponse();

  // Send a cached data from CodeCacheHost.
  std::vector<uint8_t> cache_data{1, 2, 3, 4, 5, 6};
  std::move(fetch_cached_code_callback)
      .Run(response->response_time, mojo_base::BigBuffer(cache_data));
  base::RunLoop().RunUntilIdle();

  // Send a response with metadata.
  std::vector<uint8_t> metadata{1, 2, 3, 4, 5};
  client->OnReceiveResponse(std::move(response),
                            mojo::ScopedDataPipeConsumerHandle(),
                            mojo_base::BigBuffer(metadata));

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
  ASSERT_TRUE(mock_client_->cached_metadata());
  EXPECT_EQ(metadata.size(), mock_client_->cached_metadata()->size());
  // Code cache must be cleared.
  EXPECT_TRUE(code_cache_host->did_clear_code_cache_entry());
}

TEST_F(ResourceRequestSenderTest,
       ReceiveResponseWithMetadataThenReceiveCodeCache) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->destination = network::mojom::RequestDestination::kScript;

  base::RunLoop run_loop;
  FetchCachedCodeCallback fetch_cached_code_callback;
  auto code_cache_host =
      std::make_unique<DummyCodeCacheHost>(base::BindLambdaForTesting(
          [&](mojom::blink::CodeCacheType cache_type, const KURL& url,
              FetchCachedCodeCallback callback) {
            fetch_cached_code_callback = std::move(callback);
            run_loop.Quit();
          }));

  StartAsync(std::move(request), mock_client_,
             code_cache_host->GetCodeCacheHost());
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  run_loop.Run();

  auto response = CreateResponse();
  auto response_time = response->response_time;

  // Send a response with metadata.
  std::vector<uint8_t> metadata{1, 2, 3, 4, 5};
  client->OnReceiveResponse(std::move(response),
                            mojo::ScopedDataPipeConsumerHandle(),
                            mojo_base::BigBuffer(metadata));
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
  ASSERT_TRUE(mock_client_->cached_metadata());
  EXPECT_EQ(metadata.size(), mock_client_->cached_metadata()->size());

  // Send a cached data from CodeCacheHost.
  std::vector<uint8_t> cache_data{1, 2, 3, 4, 5, 6};
  std::move(fetch_cached_code_callback)
      .Run(response_time, mojo_base::BigBuffer(cache_data));

  base::RunLoop().RunUntilIdle();
  // Code cache must be cleared.
  EXPECT_TRUE(code_cache_host->did_clear_code_cache_entry());
}

TEST_F(ResourceRequestSenderTest,
       ReceiveResponseWithMetadataThenReceiveEmptyCodeCache) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->destination = network::mojom::RequestDestination::kScript;

  base::RunLoop run_loop;
  FetchCachedCodeCallback fetch_cached_code_callback;
  auto code_cache_host =
      std::make_unique<DummyCodeCacheHost>(base::BindLambdaForTesting(
          [&](mojom::blink::CodeCacheType cache_type, const KURL& url,
              FetchCachedCodeCallback callback) {
            fetch_cached_code_callback = std::move(callback);
            run_loop.Quit();
          }));

  StartAsync(std::move(request), mock_client_,
             code_cache_host->GetCodeCacheHost());
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  run_loop.Run();

  auto response = CreateResponse();

  // Send a response with metadata.
  std::vector<uint8_t> metadata{1, 2, 3, 4, 5};
  client->OnReceiveResponse(std::move(response),
                            mojo::ScopedDataPipeConsumerHandle(),
                            mojo_base::BigBuffer(metadata));
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
  ASSERT_TRUE(mock_client_->cached_metadata());
  EXPECT_EQ(metadata.size(), mock_client_->cached_metadata()->size());

  // Send an empty cached data from CodeCacheHost.
  std::move(fetch_cached_code_callback)
      .Run(base::Time(), mojo_base::BigBuffer());

  base::RunLoop().RunUntilIdle();
  // Code cache must be cleared.
  EXPECT_FALSE(code_cache_host->did_clear_code_cache_entry());
}

TEST_F(ResourceRequestSenderTest, SlowCodeCache) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->destination = network::mojom::RequestDestination::kScript;

  base::RunLoop run_loop;
  FetchCachedCodeCallback fetch_cached_code_callback;
  auto code_cache_host =
      std::make_unique<DummyCodeCacheHost>(base::BindLambdaForTesting(
          [&](mojom::blink::CodeCacheType cache_type, const KURL& url,
              FetchCachedCodeCallback callback) {
            fetch_cached_code_callback = std::move(callback);
            run_loop.Quit();
          }));

  StartAsync(std::move(request), mock_client_,
             code_cache_host->GetCodeCacheHost());
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));
  std::unique_ptr<MockLoader> mock_loader = std::make_unique<MockLoader>();
  MockLoader* mock_loader_prt = mock_loader.get();
  mojo::MakeSelfOwnedReceiver(std::move(mock_loader),
                              std::move(loader_and_clients_[0].first));

  run_loop.Run();

  bool follow_redirect_callback_called = false;
  mock_loader_prt->SetFollowRedirectCallback(base::BindLambdaForTesting(
      [&](const std::vector<std::string>& removed_headers,
          const net::HttpRequestHeaders& modified_headers) {
        follow_redirect_callback_called = true;
      }));

  mock_client_->SetOnReceivedRedirectCallback(base::BindLambdaForTesting(
      [&](const net::RedirectInfo& redirect_info,
          network::mojom::URLResponseHeadPtr head,
          ResourceRequestClient::FollowRedirectCallback callback) {
        std::move(callback).Run({}, {});
      }));

  auto response = CreateResponse();
  auto response_time = response->response_time;

  // Call URLLoaderClient IPCs.
  net::RedirectInfo redirect_info;
  redirect_info.new_url = GURL(kRedirectedUrl);
  client->OnReceiveRedirect(redirect_info,
                            network::mojom::URLResponseHead::New());
  client->OnUploadProgress(/*current_position=*/10, /*total_size=*/10,
                           base::BindLambdaForTesting([]() {}));
  client->OnReceiveResponse(
      std::move(response),
      CreateDataPipeConsumerHandleFilledWithString(kTestData), std::nullopt);
  client->OnTransferSizeUpdated(100);
  client->OnComplete(network::URLLoaderCompletionStatus(net::Error::OK));
  base::RunLoop().RunUntilIdle();

  // MockRequestClient should not have received any response.
  EXPECT_FALSE(mock_client_->redirected());
  EXPECT_FALSE(follow_redirect_callback_called);
  EXPECT_FALSE(mock_client_->upload_progress_called());
  EXPECT_FALSE(mock_client_->received_response());
  EXPECT_TRUE(mock_client_->data().empty());
  EXPECT_FALSE(mock_client_->transfer_size_updated_called());
  EXPECT_FALSE(mock_client_->complete());

  // Send a cached data from CodeCacheHost.
  std::vector<uint8_t> cache_data{1, 2, 3, 4, 5, 6};
  std::move(fetch_cached_code_callback)
      .Run(response_time, mojo_base::BigBuffer(cache_data));

  base::RunLoop().RunUntilIdle();

  // MockRequestClient must have received the response.
  EXPECT_TRUE(mock_client_->redirected());
  EXPECT_TRUE(follow_redirect_callback_called);
  EXPECT_TRUE(mock_client_->upload_progress_called());
  EXPECT_TRUE(mock_client_->received_response());
  EXPECT_EQ(kTestData, mock_client_->data());
  EXPECT_TRUE(mock_client_->transfer_size_updated_called());
  EXPECT_TRUE(mock_client_->complete());

  ASSERT_TRUE(mock_client_->cached_metadata());
  EXPECT_EQ(cache_data.size(), mock_client_->cached_metadata()->size());
  EXPECT_FALSE(code_cache_host->did_clear_code_cache_entry());
}

TEST_F(ResourceRequestSenderTest, ReceiveCodeCacheWhileFrozen) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->destination = network::mojom::RequestDestination::kScript;

  base::RunLoop run_loop;
  FetchCachedCodeCallback fetch_cached_code_callback;
  auto code_cache_host =
      std::make_unique<DummyCodeCacheHost>(base::BindLambdaForTesting(
          [&](mojom::blink::CodeCacheType cache_type, const KURL& url,
              FetchCachedCodeCallback callback) {
            fetch_cached_code_callback = std::move(callback);
            run_loop.Quit();
          }));

  StartAsync(std::move(request), mock_client_,
             code_cache_host->GetCodeCacheHost());
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  run_loop.Run();

  auto response = CreateResponse();
  auto response_time = response->response_time;

  // Call URLLoaderClient IPCs.
  client->OnUploadProgress(/*current_position=*/10, /*total_size=*/10,
                           base::BindLambdaForTesting([]() {}));
  client->OnReceiveResponse(
      std::move(response),
      CreateDataPipeConsumerHandleFilledWithString(kTestData), std::nullopt);
  client->OnTransferSizeUpdated(100);
  client->OnComplete(network::URLLoaderCompletionStatus(net::Error::OK));
  base::RunLoop().RunUntilIdle();

  // MockRequestClient should not have received any response.
  EXPECT_FALSE(mock_client_->upload_progress_called());
  EXPECT_FALSE(mock_client_->received_response());
  EXPECT_TRUE(mock_client_->data().empty());
  EXPECT_FALSE(mock_client_->transfer_size_updated_called());
  EXPECT_FALSE(mock_client_->complete());

  // Freeze the sender.
  sender()->Freeze(LoaderFreezeMode::kStrict);

  // Send a cached data from CodeCacheHost.
  std::vector<uint8_t> cache_data{1, 2, 3, 4, 5, 6};
  std::move(fetch_cached_code_callback)
      .Run(response_time, mojo_base::BigBuffer(cache_data));

  base::RunLoop().RunUntilIdle();

  // MockRequestClient should not have received any response.
  EXPECT_FALSE(mock_client_->upload_progress_called());
  EXPECT_FALSE(mock_client_->received_response());
  EXPECT_TRUE(mock_client_->data().empty());
  EXPECT_FALSE(mock_client_->transfer_size_updated_called());
  EXPECT_FALSE(mock_client_->complete());

  // Unfreeze the sender.
  sender()->Freeze(LoaderFreezeMode::kNone);

  base::RunLoop().RunUntilIdle();

  // MockRequestClient must have received the response.
  EXPECT_TRUE(mock_client_->upload_progress_called());
  EXPECT_TRUE(mock_client_->received_response());
  EXPECT_EQ(kTestData, mock_client_->data());
  EXPECT_TRUE(mock_client_->transfer_size_updated_called());
  EXPECT_TRUE(mock_client_->complete());

  ASSERT_TRUE(mock_client_->cached_metadata());
  EXPECT_EQ(cache_data.size(), mock_client_->cached_metadata()->size());
  EXPECT_FALSE(code_cache_host->did_clear_code_cache_entry());
}

TEST_F(ResourceRequestSenderTest,
       ReceiveCodeCacheThenReceiveSyntheticResponseFromServiceWorker) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->destination = network::mojom::RequestDestination::kScript;

  base::RunLoop run_loop;
  FetchCachedCodeCallback fetch_cached_code_callback;
  auto code_cache_host =
      std::make_unique<DummyCodeCacheHost>(base::BindLambdaForTesting(
          [&](mojom::blink::CodeCacheType cache_type, const KURL& url,
              FetchCachedCodeCallback callback) {
            fetch_cached_code_callback = std::move(callback);
            run_loop.Quit();
          }));

  StartAsync(std::move(request), mock_client_,
             code_cache_host->GetCodeCacheHost());
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  run_loop.Run();

  auto response = CreateResponse();
  response->was_fetched_via_service_worker = true;

  // Send a cached data from CodeCacheHost.
  std::vector<uint8_t> cache_data{1, 2, 3, 4, 5, 6};
  std::move(fetch_cached_code_callback)
      .Run(response->response_time, mojo_base::BigBuffer(cache_data));
  base::RunLoop().RunUntilIdle();

  // Send a response without metadata.
  client->OnReceiveResponse(std::move(response),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
  EXPECT_FALSE(mock_client_->cached_metadata());
  // Code cache must be cleared.
  EXPECT_TRUE(code_cache_host->did_clear_code_cache_entry());
}

TEST_F(ResourceRequestSenderTest,
       ReceiveCodeCacheThenReceivePassThroughResponseFromServiceWorker) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->destination = network::mojom::RequestDestination::kScript;

  base::RunLoop run_loop;
  FetchCachedCodeCallback fetch_cached_code_callback;
  auto code_cache_host =
      std::make_unique<DummyCodeCacheHost>(base::BindLambdaForTesting(
          [&](mojom::blink::CodeCacheType cache_type, const KURL& url,
              FetchCachedCodeCallback callback) {
            fetch_cached_code_callback = std::move(callback);
            run_loop.Quit();
          }));

  StartAsync(std::move(request), mock_client_,
             code_cache_host->GetCodeCacheHost());
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  run_loop.Run();

  auto response = CreateResponse();
  response->was_fetched_via_service_worker = true;
  response->url_list_via_service_worker.emplace_back(kTestPageUrl);

  // Send a cached data from CodeCacheHost.
  std::vector<uint8_t> cache_data{1, 2, 3, 4, 5, 6};
  std::move(fetch_cached_code_callback)
      .Run(response->response_time, mojo_base::BigBuffer(cache_data));
  base::RunLoop().RunUntilIdle();

  // Send a response without metadata.
  client->OnReceiveResponse(std::move(response),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
  ASSERT_TRUE(mock_client_->cached_metadata());
  EXPECT_EQ(cache_data.size(), mock_client_->cached_metadata()->size());
  // Code cache must not be cleared.
  EXPECT_FALSE(code_cache_host->did_clear_code_cache_entry());
}

TEST_F(ResourceRequestSenderTest,
       ReceiveCodeCacheThenReceiveDifferentUrlResponseFromServiceWorker) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->destination = network::mojom::RequestDestination::kScript;

  base::RunLoop run_loop;
  FetchCachedCodeCallback fetch_cached_code_callback;
  auto code_cache_host =
      std::make_unique<DummyCodeCacheHost>(base::BindLambdaForTesting(
          [&](mojom::blink::CodeCacheType cache_type, const KURL& url,
              FetchCachedCodeCallback callback) {
            fetch_cached_code_callback = std::move(callback);
            run_loop.Quit();
          }));

  StartAsync(std::move(request), mock_client_,
             code_cache_host->GetCodeCacheHost());
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  run_loop.Run();

  auto response = CreateResponse();
  response->was_fetched_via_service_worker = true;
  response->url_list_via_service_worker.emplace_back(kDifferentUrl);

  // Send a cached data from CodeCacheHost.
  std::vector<uint8_t> cache_data{1, 2, 3, 4, 5, 6};
  std::move(fetch_cached_code_callback)
      .Run(response->response_time, mojo_base::BigBuffer(cache_data));
  base::RunLoop().RunUntilIdle();

  // Send a response without metadata.
  client->OnReceiveResponse(std::move(response),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
  EXPECT_FALSE(mock_client_->cached_metadata());
  // Code cache must be cleared.
  EXPECT_TRUE(code_cache_host->did_clear_code_cache_entry());
}

TEST_F(ResourceRequestSenderTest,
       ReceiveCodeCacheThenReceiveResponseFromCacheStorageViaServiceWorker) {
  mock_client_ = base::MakeRefCounted<MockRequestClient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->destination = network::mojom::RequestDestination::kScript;

  base::RunLoop run_loop;
  FetchCachedCodeCallback fetch_cached_code_callback;
  auto code_cache_host =
      std::make_unique<DummyCodeCacheHost>(base::BindLambdaForTesting(
          [&](mojom::blink::CodeCacheType cache_type, const KURL& url,
              FetchCachedCodeCallback callback) {
            fetch_cached_code_callback = std::move(callback);
            run_loop.Quit();
          }));

  StartAsync(std::move(request), mock_client_,
             code_cache_host->GetCodeCacheHost());
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  run_loop.Run();

  auto response = CreateResponse();
  response->was_fetched_via_service_worker = true;
  response->cache_storage_cache_name = "dummy";

  // Send a cached data from CodeCacheHost.
  std::vector<uint8_t> cache_data{1, 2, 3, 4, 5, 6};
  std::move(fetch_cached_code_callback)
      .Run(response->response_time, mojo_base::BigBuffer(cache_data));
  base::RunLoop().RunUntilIdle();

  // Send a response without metadata.
  client->OnReceiveResponse(std::move(response),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
  EXPECT_FALSE(mock_client_->cached_metadata());
  // Code cache must be cleared.
  EXPECT_TRUE(code_cache_host->did_clear_code_cache_entry());
}

TEST_F(ResourceRequestSenderTest, CodeCacheWithHashingEmptyCodeCache) {
  RegisterURLSchemeAsCodeCacheWithHashing();
  mock_client_ = base::MakeRefCounted<MockRequestClient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->url = GURL(kTestUrlForCodeCacheWithHashing);
  request->destination = network::mojom::RequestDestination::kScript;

  base::RunLoop run_loop;
  FetchCachedCodeCallback fetch_cached_code_callback;
  auto code_cache_host =
      std::make_unique<DummyCodeCacheHost>(base::BindLambdaForTesting(
          [&](mojom::blink::CodeCacheType cache_type, const KURL& url,
              FetchCachedCodeCallback callback) {
            fetch_cached_code_callback = std::move(callback);
            run_loop.Quit();
          }));

  StartAsync(std::move(request), mock_client_,
             code_cache_host->GetCodeCacheHost());
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  run_loop.Run();

  // Send an empty cached data from CodeCacheHost.
  std::move(fetch_cached_code_callback)
      .Run(base::Time(), mojo_base::BigBuffer());
  base::RunLoop().RunUntilIdle();

  // Send a response without metadata.
  client->OnReceiveResponse(CreateResponse(),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
  ASSERT_TRUE(mock_client_->cached_metadata());
  EXPECT_EQ(0u, mock_client_->cached_metadata()->size());
  // Code cache must not be cleared.
  EXPECT_FALSE(code_cache_host->did_clear_code_cache_entry());
}

TEST_F(ResourceRequestSenderTest, CodeCacheWithHashingWithCodeCache) {
  RegisterURLSchemeAsCodeCacheWithHashing();
  mock_client_ = base::MakeRefCounted<MockRequestClient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->url = GURL(kTestUrlForCodeCacheWithHashing);
  request->destination = network::mojom::RequestDestination::kScript;

  base::RunLoop run_loop;
  FetchCachedCodeCallback fetch_cached_code_callback;
  auto code_cache_host =
      std::make_unique<DummyCodeCacheHost>(base::BindLambdaForTesting(
          [&](mojom::blink::CodeCacheType cache_type, const KURL& url,
              FetchCachedCodeCallback callback) {
            fetch_cached_code_callback = std::move(callback);
            run_loop.Quit();
          }));

  StartAsync(std::move(request), mock_client_,
             code_cache_host->GetCodeCacheHost());
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  run_loop.Run();

  // Send a cached data from CodeCacheHost.
  std::vector<uint8_t> cache_data{1, 2, 3, 4, 5, 6};
  std::move(fetch_cached_code_callback)
      .Run(base::Time(), mojo_base::BigBuffer(cache_data));
  base::RunLoop().RunUntilIdle();

  // Send a response without metadata.
  client->OnReceiveResponse(CreateResponse(),
                            mojo::ScopedDataPipeConsumerHandle(), std::nullopt);

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_client_->received_response());
  ASSERT_TRUE(mock_client_->cached_metadata());
  EXPECT_EQ(cache_data.size(), mock_client_->cached_metadata()->size());
  // Code cache must not be cleared.
  EXPECT_FALSE(code_cache_host->did_clear_code_cache_entry());
}

TEST_F(ResourceRequestSenderTest,
       CodeCacheWithHashingWithCodeCacheAfterRedirectedToDifferentScheme) {
  RegisterURLSchemeAsCodeCacheWithHashing();
  mock_client_ = base::MakeRefCounted<MockRequestClient>();

  std::unique_ptr<network::ResourceRequest> request = CreateResourceRequest();
  request->url = GURL(kTestUrlForCodeCacheWithHashing);
  request->destination = network::mojom::RequestDestination::kScript;

  base::RunLoop run_loop;
  FetchCachedCodeCallback fetch_cached_code_callback;
  auto code_cache_host =
      std::make_unique<DummyCodeCacheHost>(base::BindLambdaForTesting(
          [&](mojom::blink::CodeCacheType cache_type, const KURL& url,
              FetchCachedCodeCallback callback) {
            fetch_cached_code_callback = std::move(callback);
            run_loop.Quit();
          }));

  StartAsync(std::move(request), mock_client_,
             code_cache_host->GetCodeCacheHost());
  ASSERT_EQ(1u, loader_and_clients_.size());
  mojo::Remote<network::mojom::URLLoaderClient> client(
      std::move(loader_and_clients_[0].second));

  run_loop.Run();

  // Send a cached data from CodeCacheHost.
  std::vector<uint8_t> cache_data{1, 2, 3, 4, 5, 6};
  std::move(fetch_cached_code_callback)
      .Run(base::Time(), mojo_base::BigBuffer(cache_data));
  base::RunLoop().RunUntilIdle();

  // Redirect to different scheme URL.
  mock_client_->SetOnReceivedRedirectCallback(base::BindLambdaForTesting(
      [&](const net::RedirectInfo& redirect_info,
          network::mojom::URLResponseHeadPtr head,
          ResourceRequestClient::FollowRedirectCallback callback) {
        EXPECT_EQ(
```