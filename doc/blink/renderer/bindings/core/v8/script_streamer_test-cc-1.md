Response:
The user wants a summary of the functionality of the provided C++ code snippet. This snippet is part of a test file (`script_streamer_test.cc`) for the Chromium Blink engine, specifically focusing on the `BackgroundResourceScriptStreamer`.

To summarize, I need to:

1. **Identify the core purpose of the code:** It seems to be testing the background processing of script resources, particularly how `BackgroundResponseProcessor` interacts with script streaming.
2. **List the key components and their roles:**  Classes like `DummyURLLoader`, `DummyLoaderFactory`, `DummyBackgroundResponseProcessorClient`, and `BackgroundResourceScriptStreamerTest` are present.
3. **Explain the test scenarios:** The code sets up various scenarios using `TEST_F` macros, such as handling different MIME types, code cache presence, script sizes, and encodings.
4. **Connect to web technologies (JavaScript, HTML, CSS):**  The tests relate to how the browser handles JavaScript files, particularly for performance optimization through background processing and caching.
5. **Look for examples of assumptions and outputs:**  The tests make assertions about the state of the system after certain actions.
6. **Identify potential user errors:** These would likely be related to how developers might incorrectly configure script loading or caching.
7. **Describe the user journey to this code:** This involves how the browser fetches and processes scripts.

Based on this, I can construct a summary of the functionality.
这个代码片段是 `blink/renderer/bindings/core/v8/script_streamer_test.cc` 文件的第二部分，主要定义了用于测试 `BackgroundResourceScriptStreamer` 类的辅助类和测试用例。`BackgroundResourceScriptStreamer` 的主要功能是在后台线程处理脚本资源加载，以优化页面加载性能。

**功能归纳：**

这段代码主要定义了一系列用于模拟网络请求和响应、以及模拟缓存行为的辅助类，用于测试 `BackgroundResourceScriptStreamer` 在不同场景下的行为。 这些场景包括：

* **模拟 URL 加载:** 使用 `DummyURLLoader` 和 `DummyLoaderFactory` 来模拟资源加载过程，可以控制加载是否开始，并设置后台响应处理器工厂。
* **模拟后台响应处理:** 使用 `DummyBackgroundResponseProcessorClient` 来接收和验证后台响应处理器的结果，例如收到的响应头、响应体和缓存元数据。
* **模拟缓存元数据发送:** 使用 `DummyCachedMetadataSender` 来模拟发送缓存元数据的过程。
* **创建虚拟的缓存数据:**  `CreateDummyCodeCacheData` 和 `CreateDummyTimeStampData` 函数用于创建用于测试的虚拟代码缓存和时间戳数据。
* **创建虚拟的 URL 响应头:** `CreateURLResponseHead` 函数用于创建带有指定 Content-Type 的虚拟 HTTP 响应头。
* **测试基类:** `BackgroundResourceScriptStreamerTest` 是所有测试用例的基类，它负责初始化测试环境，包括创建 V8 隔离区、模拟资源请求和加载、以及创建 `BackgroundResponseProcessor`。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接关系到 **JavaScript** 的加载和执行优化。 `BackgroundResourceScriptStreamer` 的目标是提高 JavaScript 脚本的加载速度，从而改善用户体验。

* **JavaScript:**  测试用例模拟了各种 JavaScript 文件的加载场景，例如模块脚本 (`is_module_script=true`) 和传统脚本。测试了在存在代码缓存、脚本过小、编码不支持等情况下，后台处理器的行为。
    * **举例：**  `TEST_F(BackgroundResourceScriptStreamerTest, EnoughDataModuleScript)` 测试了对于足够大的模块脚本，后台处理器是否能正常工作并创建 `ScriptStreamer`。

* **HTML:** 虽然代码本身不直接操作 HTML，但它测试的功能是浏览器加载和解析 HTML 文件时遇到的 JavaScript 脚本的处理过程。当 HTML 解析器遇到 `<script>` 标签时，会触发脚本资源的加载，这个测试就是针对这个加载过程的优化。
    * **举例：** 当 HTML 中包含一个外部 JavaScript 文件时，浏览器会发起网络请求加载该文件。 `DummyURLLoader` 模拟了这个请求过程。

* **CSS:**  这段代码与 CSS 的关系较弱。`BackgroundResourceScriptStreamer` 主要关注 JavaScript 脚本的优化。

**逻辑推理及假设输入与输出:**

* **假设输入:**  一个网络请求，请求加载一个 JavaScript 脚本资源，并且该请求的响应头指示 `Content-Type: text/javascript`。
* **输出:**  `BackgroundResponseProcessor` 可能会被创建并开始处理响应。`DummyBackgroundResponseProcessorClient` 会接收到响应头、响应体和可能的缓存元数据。
    * **具体例子：** 在 `TEST_F(BackgroundResourceScriptStreamerTest, EnoughData)` 中，假设输入的脚本内容足够大 (`kLargeEnoughScript`)，那么 `MaybeStartProcessingResponse` 应该返回 `true`，并且后台处理器会处理这个响应。最终，`CheckScriptStreamer()` 会验证 `ScriptStreamer` 是否被成功创建。

**用户或编程常见的使用错误及举例说明:**

* **MIME 类型配置错误:** 服务器可能错误地将 JavaScript 文件配置为其他 MIME 类型（例如 `text/plain`）。
    * **举例：** `TEST_F(BackgroundResourceScriptStreamerTest, UnsupportedModuleMimeType)` 测试了当模块脚本的 MIME 类型不正确时，后台处理器应该如何处理。
* **缓存配置错误:**  开发者可能错误地配置了缓存策略，导致浏览器无法正确利用缓存。虽然测试代码没有直接模拟缓存配置错误，但它测试了有无代码缓存的情况，以及缓存数据是否有效。
* **编码设置错误:**  服务器可能使用了浏览器不支持的编码，或者没有正确声明编码。
    * **举例：** `TEST_F(BackgroundResourceScriptStreamerTest, EncodingNotSupported)` 测试了当脚本使用不支持的编码时，后台处理器应该如何处理。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在浏览器中访问一个网页。**
2. **浏览器解析 HTML 页面。**
3. **浏览器遇到 `<script>` 标签，需要加载外部 JavaScript 文件。**
4. **浏览器发起网络请求，请求该 JavaScript 文件。**  `DummyURLLoader` 模拟了这个过程。
5. **如果启用了后台资源获取 (Background Resource Fetch)，并且满足特定条件（例如脚本大小足够），浏览器可能会尝试在后台线程处理这个脚本。**  `BackgroundResourceScriptStreamer` 的功能就在这里被触发。
6. **`BackgroundResponseProcessor` 尝试处理响应，可能会读取缓存数据。** `DummyBackgroundResponseProcessorClient` 模拟了接收处理结果的客户端。
7. **测试代码模拟了各种可能的响应情况（例如有无缓存、脚本大小、MIME 类型等），以验证 `BackgroundResourceScriptStreamer` 的正确性。**

总而言之，这段代码是 Chromium Blink 引擎中用于测试 JavaScript 脚本后台处理优化功能的重要组成部分，通过模拟各种场景来确保该功能的稳定性和正确性。

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/script_streamer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
 return load_started_; }
  std::unique_ptr<BackgroundResponseProcessorFactory>
  TakeBackgroundResponseProcessorFactory() {
    return std::move(background_response_processor_factory_);
  }

 private:
  class DummyURLLoader final : public URLLoader {
   public:
    explicit DummyURLLoader(
        DummyLoaderFactory* factory,
        scoped_refptr<base::SingleThreadTaskRunner> task_runner)
        : factory_(factory), task_runner_(std::move(task_runner)) {}
    ~DummyURLLoader() override = default;

    // URLLoader implementation:
    void LoadSynchronously(
        std::unique_ptr<network::ResourceRequest> request,
        scoped_refptr<const SecurityOrigin> top_frame_origin,
        bool download_to_blob,
        bool no_mime_sniffing,
        base::TimeDelta timeout_interval,
        URLLoaderClient*,
        WebURLResponse&,
        std::optional<WebURLError>&,
        scoped_refptr<SharedBuffer>&,
        int64_t& encoded_data_length,
        uint64_t& encoded_body_length,
        scoped_refptr<BlobDataHandle>& downloaded_blob,
        std::unique_ptr<blink::ResourceLoadInfoNotifierWrapper>
            resource_load_info_notifier_wrapper) override {
      NOTREACHED();
    }
    void LoadAsynchronously(
        std::unique_ptr<network::ResourceRequest> request,
        scoped_refptr<const SecurityOrigin> top_frame_origin,
        bool no_mime_sniffing,
        std::unique_ptr<blink::ResourceLoadInfoNotifierWrapper>
            resource_load_info_notifier_wrapper,
        CodeCacheHost* code_cache_host,
        URLLoaderClient* client) override {
      factory_->load_started_ = true;
    }
    void Freeze(LoaderFreezeMode) override {}
    void DidChangePriority(WebURLRequest::Priority, int) override {
      NOTREACHED();
    }
    bool CanHandleResponseOnBackground() override { return true; }
    void SetBackgroundResponseProcessorFactory(
        std::unique_ptr<BackgroundResponseProcessorFactory>
            background_response_processor_factory) override {
      factory_->background_response_processor_factory_ =
          std::move(background_response_processor_factory);
    }
    scoped_refptr<base::SingleThreadTaskRunner> GetTaskRunnerForBodyLoader()
        override {
      return task_runner_;
    }
    Persistent<DummyLoaderFactory> factory_;
    scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  };

  bool load_started_ = false;
  std::unique_ptr<BackgroundResponseProcessorFactory>
      background_response_processor_factory_;
};

class DummyBackgroundResponseProcessorClient
    : public BackgroundResponseProcessor::Client {
 public:
  DummyBackgroundResponseProcessorClient()
      : main_thread_task_runner_(
            scheduler::GetSingleThreadTaskRunnerForTesting()) {}

  ~DummyBackgroundResponseProcessorClient() override = default;

  void DidFinishBackgroundResponseProcessor(
      network::mojom::URLResponseHeadPtr head,
      BackgroundResponseProcessor::BodyVariant body,
      std::optional<mojo_base::BigBuffer> cached_metadata) override {
    head_ = std::move(head);
    body_ = std::move(body);
    cached_metadata_ = std::move(cached_metadata);
    run_loop_.Quit();
  }
  void PostTaskToMainThread(CrossThreadOnceClosure task) override {
    PostCrossThreadTask(*main_thread_task_runner_, FROM_HERE, std::move(task));
  }

  void WaitUntilFinished() { run_loop_.Run(); }

  void CheckResultOfFinishCallback(
      base::span<const char> expected_body,
      std::optional<base::span<const uint8_t>> expected_cached_metadata) {
    EXPECT_TRUE(head_);
    if (absl::holds_alternative<SegmentedBuffer>(body_)) {
      const SegmentedBuffer& raw_body = absl::get<SegmentedBuffer>(body_);
      const Vector<char> concatenated_body = raw_body.CopyAs<Vector<char>>();
      EXPECT_THAT(concatenated_body, testing::ElementsAreArray(expected_body));
    } else {
      CHECK(absl::holds_alternative<mojo::ScopedDataPipeConsumerHandle>(body_));
      mojo::ScopedDataPipeConsumerHandle& handle =
          absl::get<mojo::ScopedDataPipeConsumerHandle>(body_);
      std::string text;
      EXPECT_TRUE(mojo::BlockingCopyToString(std::move(handle), &text));
      EXPECT_THAT(text, testing::ElementsAreArray(expected_body));
    }
    ASSERT_EQ(expected_cached_metadata, cached_metadata_);
    if (expected_cached_metadata) {
      EXPECT_THAT(*cached_metadata_,
                  testing::ElementsAreArray(*expected_cached_metadata));
    }
  }

 private:
  scoped_refptr<base::SingleThreadTaskRunner> main_thread_task_runner_;
  base::RunLoop run_loop_;
  network::mojom::URLResponseHeadPtr head_;
  BackgroundResponseProcessor::BodyVariant body_;
  std::optional<mojo_base::BigBuffer> cached_metadata_;
};

class DummyCachedMetadataSender : public CachedMetadataSender {
 public:
  DummyCachedMetadataSender() = default;
  void Send(CodeCacheHost*, base::span<const uint8_t>) override {}
  bool IsServedFromCacheStorage() override { return false; }
};

mojo_base::BigBuffer CreateDummyCodeCacheData() {
  ScriptCachedMetadataHandler* cache_handler =
      MakeGarbageCollected<ScriptCachedMetadataHandler>(
          UTF8Encoding(), std::make_unique<DummyCachedMetadataSender>());
  uint32_t data_type_id = V8CodeCache::TagForCodeCache(cache_handler);
  cache_handler->SetCachedMetadata(
      /*code_cache_host=*/nullptr, data_type_id,
      reinterpret_cast<const uint8_t*>("X"), 1);
  scoped_refptr<CachedMetadata> cached_metadata =
      cache_handler->GetCachedMetadata(data_type_id);
  mojo_base::BigBuffer cached_metadata_buffer =
      mojo_base::BigBuffer(cached_metadata->SerializedData());
  return cached_metadata_buffer;
}

mojo_base::BigBuffer CreateDummyTimeStampData() {
  ScriptCachedMetadataHandler* cache_handler =
      MakeGarbageCollected<ScriptCachedMetadataHandler>(
          UTF8Encoding(), std::make_unique<DummyCachedMetadataSender>());
  uint32_t data_type_id = V8CodeCache::TagForTimeStamp(cache_handler);
  uint64_t now_ms = 11111;
  cache_handler->SetCachedMetadata(
      /*code_cache_host=*/nullptr, data_type_id,
      reinterpret_cast<uint8_t*>(&now_ms), sizeof(now_ms));
  scoped_refptr<CachedMetadata> cached_metadata =
      cache_handler->GetCachedMetadata(data_type_id);
  mojo_base::BigBuffer cached_metadata_buffer =
      mojo_base::BigBuffer(cached_metadata->SerializedData());
  return cached_metadata_buffer;
}

network::mojom::URLResponseHeadPtr CreateURLResponseHead(
    const std::string& content_type = "text/javascript") {
  auto head = network::mojom::URLResponseHead::New();
  head->headers = base::MakeRefCounted<net::HttpResponseHeaders>(
      net::HttpUtil::AssembleRawHeaders(base::StrCat(
          {"HTTP/1.1 200 OK\n", "Content-Type: ", content_type, "\n\n"})));
  return head;
}

}  // namespace

class BackgroundResourceScriptStreamerTest : public testing::Test {
 public:
  explicit BackgroundResourceScriptStreamerTest(
      bool enable_background_code_cache_decode_start = false)
      : url_(String("http://streaming-test.example.com/foo" +
                    base::NumberToString(url_counter_++))) {
    feature_list_.InitWithFeaturesAndParameters(
        {{features::kBackgroundResourceFetch,
          {{"background-script-response-processor", "true"},
           {"background-code-cache-decoder-start",
            enable_background_code_cache_decode_start ? "true" : "false"}}}},
        {});
  }
  ~BackgroundResourceScriptStreamerTest() override = default;

  void TearDown() override {
    RunInBackgroundThred(base::BindLambdaForTesting(
        [&]() { background_response_processor_.reset(); }));
  }

 protected:
  void Init(v8::Isolate* isolate,
            bool is_module_script = false,
            std::optional<WTF::TextEncoding> charset = std::nullopt,
            v8_compile_hints::V8CrowdsourcedCompileHintsConsumer*
                v8_compile_hints_consumer = nullptr) {
    auto* properties = MakeGarbageCollected<TestResourceFetcherProperties>();
    FetchContext* context = MakeGarbageCollected<MockFetchContext>();
    scoped_refptr<base::SingleThreadTaskRunner> main_thread_task_runner =
        scheduler::GetSingleThreadTaskRunnerForTesting();
    DummyLoaderFactory* dummy_loader_factory =
        MakeGarbageCollected<DummyLoaderFactory>();
    auto* fetcher = MakeGarbageCollected<ResourceFetcher>(ResourceFetcherInit(
        properties->MakeDetachable(), context, main_thread_task_runner,
        main_thread_task_runner, dummy_loader_factory,
        MakeGarbageCollected<MockContextLifecycleNotifier>(),
        nullptr /* back_forward_cache_loader_helper */));

    EXPECT_EQ(
        mojo::CreateDataPipe(kDataPipeSize, producer_handle_, consumer_handle_),
        MOJO_RESULT_OK);

    ResourceRequest request(url_);
    request.SetRequestContext(mojom::blink::RequestContextType::SCRIPT);

    resource_client_ =
        MakeGarbageCollected<TestResourceClient>(run_loop_.QuitClosure());
    FetchParameters params = FetchParameters::CreateForTest(std::move(request));
    if (is_module_script) {
      params.SetModuleScript();
    }
    if (charset) {
      params.SetCharset(*charset);
    }
    constexpr v8_compile_hints::V8CrowdsourcedCompileHintsProducer*
        kNoCompileHintsProducer = nullptr;
    resource_ = ScriptResource::Fetch(
        params, fetcher, resource_client_, isolate,
        ScriptResource::kAllowStreaming, kNoCompileHintsProducer,
        v8_compile_hints_consumer, v8_compile_hints::MagicCommentMode::kNever);
    resource_->AddClient(resource_client_, main_thread_task_runner.get());

    CHECK(dummy_loader_factory->load_started());
    background_resource_fetch_task_runner_ =
        base::ThreadPool::CreateSequencedTaskRunner(
            {base::TaskPriority::USER_BLOCKING});

    RunInBackgroundThred(base::BindLambdaForTesting([&]() {
      std::unique_ptr<BackgroundResponseProcessorFactory> factory =
          dummy_loader_factory->TakeBackgroundResponseProcessorFactory();
      background_response_processor_ = std::move(*factory).Create();
    }));
  }

  ClassicScript* CreateClassicScript() const {
    return ClassicScript::CreateFromResource(resource_, ScriptFetchOptions());
  }

 protected:
  void AppendData(std::string_view data) {
    AppendDataToDataPipe(data, producer_handle_);
  }

  void Finish() {
    ResourceResponse response(url_);
    response.SetHttpStatusCode(200);
    resource_->Loader()->DidReceiveResponse(WrappedResourceResponse(response),
                                            std::move(consumer_handle_),
                                            /*cached_metadata=*/std::nullopt);
    producer_handle_.reset();
    resource_->Loader()->DidFinishLoading(base::TimeTicks(), 0, 0, 0);
  }

  void Cancel() { resource_->Loader()->Cancel(); }

  void RunUntilResourceLoaded() { run_loop_.Run(); }

  void RunInBackgroundThred(base::OnceClosure closuer) {
    base::RunLoop loop;
    background_resource_fetch_task_runner_->PostTask(
        FROM_HERE, base::BindLambdaForTesting([&]() {
          std::move(closuer).Run();
          loop.Quit();
        }));
    loop.Run();
  }

  void CheckNotStreamingReason(
      ScriptStreamer::NotStreamingReason expected_not_streamed_reason,
      mojom::blink::ScriptType script_type =
          mojom::blink::ScriptType::kClassic) {
    ScriptStreamer* streamer;
    ScriptStreamer::NotStreamingReason not_streamed_reason;
    std::tie(streamer, not_streamed_reason) =
        ScriptStreamer::TakeFrom(resource_, script_type);
    EXPECT_EQ(expected_not_streamed_reason, not_streamed_reason);
    EXPECT_EQ(nullptr, streamer);
  }

  void CheckScriptStreamer(mojom::blink::ScriptType script_type =
                               mojom::blink::ScriptType::kClassic) {
    ScriptStreamer* streamer;
    ScriptStreamer::NotStreamingReason not_streamed_reason;
    std::tie(streamer, not_streamed_reason) =
        ScriptStreamer::TakeFrom(resource_, script_type);
    EXPECT_EQ(ScriptStreamer::NotStreamingReason::kInvalid,
              not_streamed_reason);
    EXPECT_NE(nullptr, streamer);
  }

  static int url_counter_;

  test::TaskEnvironment task_environment_;
  KURL url_;

  base::RunLoop run_loop_;
  Persistent<TestResourceClient> resource_client_;
  Persistent<ScriptResource> resource_;
  mojo::ScopedDataPipeProducerHandle producer_handle_;
  mojo::ScopedDataPipeConsumerHandle consumer_handle_;
  std::unique_ptr<BackgroundResponseProcessor> background_response_processor_;
  DummyBackgroundResponseProcessorClient background_response_processor_client_;

  scoped_refptr<base::SequencedTaskRunner>
      background_resource_fetch_task_runner_;
  base::test::ScopedFeatureList feature_list_;
};
int BackgroundResourceScriptStreamerTest::url_counter_ = 0;

TEST_F(BackgroundResourceScriptStreamerTest, UnsupportedModuleMimeType) {
  V8TestingScope scope;
  Init(scope.GetIsolate(), /*is_module_script=*/true);
  RunInBackgroundThred(base::BindLambdaForTesting([&]() {
    // "text/plain" is not a valid mime type for module scripts.
    network::mojom::URLResponseHeadPtr head =
        CreateURLResponseHead("text/plain");
    std::optional<mojo_base::BigBuffer> cached_metadata;
    EXPECT_FALSE(background_response_processor_->MaybeStartProcessingResponse(
        head, consumer_handle_, cached_metadata,
        background_resource_fetch_task_runner_,
        &background_response_processor_client_));
    EXPECT_TRUE(head);
    EXPECT_TRUE(consumer_handle_);
    EXPECT_FALSE(cached_metadata);
  }));
  Finish();
  RunUntilResourceLoaded();
  CheckNotStreamingReason(
      ScriptStreamer::NotStreamingReason::kNonJavascriptModuleBackground,
      mojom::blink::ScriptType::kModule);
}

TEST_F(BackgroundResourceScriptStreamerTest, HasCodeCache) {
  V8TestingScope scope;
  Init(scope.GetIsolate());
  mojo_base::BigBuffer code_cache_data = CreateDummyCodeCacheData();
  const std::vector<uint8_t> code_cache_data_copy(
      code_cache_data.data(), code_cache_data.data() + code_cache_data.size());
  RunInBackgroundThred(base::BindLambdaForTesting([&]() {
    network::mojom::URLResponseHeadPtr head = CreateURLResponseHead();
    // Set charset to make the code cache valid.
    head->charset = "utf-8";
    // Set a dummy code cache data.
    std::optional<mojo_base::BigBuffer> cached_metadata =
        std::move(code_cache_data);
    EXPECT_FALSE(background_response_processor_->MaybeStartProcessingResponse(
        head, consumer_handle_, cached_metadata,
        background_resource_fetch_task_runner_,
        &background_response_processor_client_));
    EXPECT_TRUE(head);
    EXPECT_TRUE(consumer_handle_);
    ASSERT_TRUE(cached_metadata);
    EXPECT_THAT(*cached_metadata,
                testing::ElementsAreArray(code_cache_data_copy));
  }));
  Finish();
  RunUntilResourceLoaded();
  // When there is a code cache, we should not stream the script.
  CheckNotStreamingReason(
      ScriptStreamer::NotStreamingReason::kHasCodeCacheBackground);
}

class BackgroundResourceScriptStreamerCodeCacheDecodeStartTest
    : public BackgroundResourceScriptStreamerTest {
 public:
  BackgroundResourceScriptStreamerCodeCacheDecodeStartTest()
      : BackgroundResourceScriptStreamerTest(
            /*enable_background_code_cache_decode_start=*/true) {}
  ~BackgroundResourceScriptStreamerCodeCacheDecodeStartTest() override =
      default;
};

TEST_F(BackgroundResourceScriptStreamerCodeCacheDecodeStartTest, HasCodeCache) {
  V8TestingScope scope;
  Init(scope.GetIsolate());
  mojo_base::BigBuffer code_cache_data = CreateDummyCodeCacheData();
  const std::vector<uint8_t> code_cache_data_copy(
      code_cache_data.data(), code_cache_data.data() + code_cache_data.size());
  RunInBackgroundThred(base::BindLambdaForTesting([&]() {
    network::mojom::URLResponseHeadPtr head = CreateURLResponseHead();
    // Set charset to make the code cache valid.
    head->charset = "utf-8";
    // Set a dummy code cache data.
    std::optional<mojo_base::BigBuffer> cached_metadata =
        std::move(code_cache_data);
    EXPECT_TRUE(background_response_processor_->MaybeStartProcessingResponse(
        head, consumer_handle_, cached_metadata,
        background_resource_fetch_task_runner_,
        &background_response_processor_client_));
    EXPECT_FALSE(head);
    EXPECT_FALSE(consumer_handle_);
    ASSERT_TRUE(cached_metadata);
    EXPECT_EQ(cached_metadata->size(), 0u);
  }));
  AppendData(kLargeEnoughScript);
  producer_handle_.reset();
  background_response_processor_client_.WaitUntilFinished();
  // Checking that the code cache data is passed to the finish callback.
  background_response_processor_client_.CheckResultOfFinishCallback(
      /*expected_body=*/base::make_span(kLargeEnoughScript,
                                        sizeof(kLargeEnoughScript) - 1),
      /*expected_cached_metadata=*/code_cache_data_copy);
  Finish();
  RunUntilResourceLoaded();
  // When there is a code cache, we should not stream the script.
  CheckNotStreamingReason(
      ScriptStreamer::NotStreamingReason::kHasCodeCacheBackground);
}

TEST_F(BackgroundResourceScriptStreamerTest, HasTimeStampData) {
  V8TestingScope scope;
  Init(scope.GetIsolate());
  mojo_base::BigBuffer time_stamp_data = CreateDummyTimeStampData();
  const std::vector<uint8_t> time_stamp_data_copy(
      time_stamp_data.data(), time_stamp_data.data() + time_stamp_data.size());
  RunInBackgroundThred(base::BindLambdaForTesting([&]() {
    network::mojom::URLResponseHeadPtr head = CreateURLResponseHead();
    // Set a dummy time stamp data.
    std::optional<mojo_base::BigBuffer> cached_metadata =
        std::move(time_stamp_data);
    EXPECT_TRUE(background_response_processor_->MaybeStartProcessingResponse(
        head, consumer_handle_, cached_metadata,
        background_resource_fetch_task_runner_,
        &background_response_processor_client_));
    EXPECT_FALSE(head);
    EXPECT_FALSE(consumer_handle_);
    ASSERT_TRUE(cached_metadata);
    EXPECT_EQ(cached_metadata->storage_type(),
              mojo_base::BigBuffer::StorageType::kInvalidBuffer);
  }));
  AppendData(kLargeEnoughScript);
  producer_handle_.reset();
  background_response_processor_client_.WaitUntilFinished();
  // Checking that the dummy time stamp data is passed to the finish callback.
  background_response_processor_client_.CheckResultOfFinishCallback(
      /*expected_body=*/base::make_span(kLargeEnoughScript,
                                        sizeof(kLargeEnoughScript) - 1),
      /*expected_cached_metadata=*/time_stamp_data_copy);
  Finish();
  RunUntilResourceLoaded();
  // ScriptStreamer must have been created.
  CheckScriptStreamer();
}

TEST_F(BackgroundResourceScriptStreamerTest, InvalidCachedMetadata) {
  uint8_t kInvalidCachedMetadata[] = {0x00, 0x00};
  V8TestingScope scope;
  Init(scope.GetIsolate());
  RunInBackgroundThred(base::BindLambdaForTesting([&]() {
    network::mojom::URLResponseHeadPtr head = CreateURLResponseHead();
    // Set an invalid cached metadata.
    std::optional<mojo_base::BigBuffer> cached_metadata =
        mojo_base::BigBuffer(base::make_span(kInvalidCachedMetadata));
    EXPECT_TRUE(background_response_processor_->MaybeStartProcessingResponse(
        head, consumer_handle_, cached_metadata,
        background_resource_fetch_task_runner_,
        &background_response_processor_client_));
    EXPECT_FALSE(head);
    EXPECT_FALSE(consumer_handle_);
    ASSERT_TRUE(cached_metadata);
    EXPECT_EQ(cached_metadata->storage_type(),
              mojo_base::BigBuffer::StorageType::kInvalidBuffer);
  }));
  AppendData(kLargeEnoughScript);
  producer_handle_.reset();
  background_response_processor_client_.WaitUntilFinished();
  // Checking that the dummy metadata is passed to the finish callback.
  background_response_processor_client_.CheckResultOfFinishCallback(
      /*expected_body=*/base::make_span(kLargeEnoughScript,
                                        sizeof(kLargeEnoughScript) - 1),
      /*expected_cached_metadata=*/kInvalidCachedMetadata);
  Finish();
  RunUntilResourceLoaded();
  // ScriptStreamer must have been created.
  CheckScriptStreamer();
}

TEST_F(BackgroundResourceScriptStreamerTest, SmallScript) {
  V8TestingScope scope;
  Init(scope.GetIsolate());
  RunInBackgroundThred(base::BindLambdaForTesting([&]() {
    network::mojom::URLResponseHeadPtr head = CreateURLResponseHead();
    std::optional<mojo_base::BigBuffer> cached_metadata;
    EXPECT_TRUE(background_response_processor_->MaybeStartProcessingResponse(
        head, consumer_handle_, cached_metadata,
        background_resource_fetch_task_runner_,
        &background_response_processor_client_));
    EXPECT_FALSE(head);
    EXPECT_FALSE(consumer_handle_);
    EXPECT_FALSE(cached_metadata);
  }));
  // Append small data and close the data pipe not to trigger streaming.
  AppendData(kTooSmallScript);
  producer_handle_.reset();
  background_response_processor_client_.WaitUntilFinished();
  background_response_processor_client_.CheckResultOfFinishCallback(
      /*expected_body=*/base::make_span(kTooSmallScript,
                                        sizeof(kTooSmallScript) - 1),
      /*expected_cached_metadata=*/std::nullopt);
  Finish();
  RunUntilResourceLoaded();
  // When the script is too small, we should not stream the script.
  CheckNotStreamingReason(
      ScriptStreamer::NotStreamingReason::kScriptTooSmallBackground);
}

TEST_F(BackgroundResourceScriptStreamerTest, SmallScriptInFirstChunk) {
  V8TestingScope scope;
  Init(scope.GetIsolate());
  // Append the data chunk to the producer handle here, so the
  // MaybeStartProcessingResponse() can synchronously read the data chunk in the
  // data pipe.
  AppendData(kTooSmallScript);
  RunInBackgroundThred(base::BindLambdaForTesting([&]() {
    network::mojom::URLResponseHeadPtr head = CreateURLResponseHead();
    std::optional<mojo_base::BigBuffer> cached_metadata;
    EXPECT_TRUE(background_response_processor_->MaybeStartProcessingResponse(
        head, consumer_handle_, cached_metadata,
        background_resource_fetch_task_runner_,
        &background_response_processor_client_));
    EXPECT_FALSE(head);
    EXPECT_FALSE(consumer_handle_);
    EXPECT_FALSE(cached_metadata);
  }));
  producer_handle_.reset();
  background_response_processor_client_.WaitUntilFinished();
  background_response_processor_client_.CheckResultOfFinishCallback(
      /*expected_body=*/base::make_span(kTooSmallScript,
                                        sizeof(kTooSmallScript) - 1),
      /*expected_cached_metadata=*/std::nullopt);
  Finish();
  RunUntilResourceLoaded();
  // When the script is too small, we should not stream the script.
  CheckNotStreamingReason(
      ScriptStreamer::NotStreamingReason::kScriptTooSmallBackground);
}

TEST_F(BackgroundResourceScriptStreamerTest, EmptyScript) {
  V8TestingScope scope;
  Init(scope.GetIsolate());
  RunInBackgroundThred(base::BindLambdaForTesting([&]() {
    network::mojom::URLResponseHeadPtr head = CreateURLResponseHead();
    std::optional<mojo_base::BigBuffer> cached_metadata;
    EXPECT_TRUE(background_response_processor_->MaybeStartProcessingResponse(
        head, consumer_handle_, cached_metadata,
        background_resource_fetch_task_runner_,
        &background_response_processor_client_));
    EXPECT_FALSE(head);
    EXPECT_FALSE(consumer_handle_);
    EXPECT_FALSE(cached_metadata);
  }));
  // Close the data pipe without any data.
  producer_handle_.reset();
  background_response_processor_client_.WaitUntilFinished();
  background_response_processor_client_.CheckResultOfFinishCallback(
      /*expected_body=*/{},
      /*expected_cached_metadata=*/std::nullopt);
  Finish();
  RunUntilResourceLoaded();
  // When the script is too small (empty), we should not stream the script.
  CheckNotStreamingReason(
      ScriptStreamer::NotStreamingReason::kScriptTooSmallBackground);
}

TEST_F(BackgroundResourceScriptStreamerTest, EmptyScriptSyncCheckable) {
  V8TestingScope scope;
  Init(scope.GetIsolate());
  // Close the data pipe here, so the MaybeStartProcessingResponse() can
  // synchronously know that the script is empty.
  producer_handle_.reset();
  RunInBackgroundThred(base::BindLambdaForTesting([&]() {
    network::mojom::URLResponseHeadPtr head = CreateURLResponseHead();
    std::optional<mojo_base::BigBuffer> cached_metadata;
    // MaybeStartProcessingResponse() can synchronously know that the script is
    // empty. So it returns false.
    EXPECT_FALSE(background_response_processor_->MaybeStartProcessingResponse(
        head, consumer_handle_, cached_metadata,
        background_resource_fetch_task_runner_,
        &background_response_processor_client_));
    EXPECT_TRUE(head);
    EXPECT_TRUE(consumer_handle_);
    EXPECT_FALSE(cached_metadata);
  }));
  Finish();
  RunUntilResourceLoaded();
  // When the script is too small, we should not stream the script.
  CheckNotStreamingReason(
      ScriptStreamer::NotStreamingReason::kScriptTooSmallBackground);
}

TEST_F(BackgroundResourceScriptStreamerTest, EnoughData) {
  V8TestingScope scope;
  Init(scope.GetIsolate());
  RunInBackgroundThred(base::BindLambdaForTesting([&]() {
    network::mojom::URLResponseHeadPtr head = CreateURLResponseHead();
    std::optional<mojo_base::BigBuffer> cached_metadata;
    EXPECT_TRUE(background_response_processor_->MaybeStartProcessingResponse(
        head, consumer_handle_, cached_metadata,
        background_resource_fetch_task_runner_,
        &background_response_processor_client_));
    EXPECT_FALSE(head);
    EXPECT_FALSE(consumer_handle_);
    EXPECT_FALSE(cached_metadata);
  }));
  // Append enough data to start streaming.
  AppendData(kLargeEnoughScript);
  producer_handle_.reset();
  background_response_processor_client_.WaitUntilFinished();
  background_response_processor_client_.CheckResultOfFinishCallback(
      /*expected_body=*/base::make_span(kLargeEnoughScript,
                                        sizeof(kLargeEnoughScript) - 1),
      /*expected_cached_metadata=*/std::nullopt);
  Finish();
  RunUntilResourceLoaded();
  // ScriptStreamer must have been created.
  CheckScriptStreamer();
}

TEST_F(BackgroundResourceScriptStreamerTest, EnoughDataInFirstChunk) {
  V8TestingScope scope;
  Init(scope.GetIsolate());
  // Append the data chunk to the producer handle before
  // MaybeStartProcessingResponse(), so that MaybeStartProcessingResponse() can
  // synchronously read the data chunk in the data pipe.
  AppendData(kLargeEnoughScript);
  RunInBackgroundThred(base::BindLambdaForTesting([&]() {
    network::mojom::URLResponseHeadPtr head = CreateURLResponseHead();
    std::optional<mojo_base::BigBuffer> cached_metadata;
    EXPECT_TRUE(background_response_processor_->MaybeStartProcessingResponse(
        head, consumer_handle_, cached_metadata,
        background_resource_fetch_task_runner_,
        &background_response_processor_client_));
    EXPECT_FALSE(head);
    EXPECT_FALSE(consumer_handle_);
    EXPECT_FALSE(cached_metadata);
  }));
  producer_handle_.reset();
  background_response_processor_client_.WaitUntilFinished();
  background_response_processor_client_.CheckResultOfFinishCallback(
      /*expected_body=*/base::make_span(kLargeEnoughScript,
                                        sizeof(kLargeEnoughScript) - 1),
      /*expected_cached_metadata=*/std::nullopt);
  Finish();
  RunUntilResourceLoaded();
  // ScriptStreamer must have been created.
  CheckScriptStreamer();
}

TEST_F(BackgroundResourceScriptStreamerTest, EnoughDataModuleScript) {
  V8TestingScope scope;
  Init(scope.GetIsolate(), /*is_module_script=*/true);
  RunInBackgroundThred(base::BindLambdaForTesting([&]() {
    network::mojom::URLResponseHeadPtr head = CreateURLResponseHead();
    std::optional<mojo_base::BigBuffer> cached_metadata;
    EXPECT_TRUE(background_response_processor_->MaybeStartProcessingResponse(
        head, consumer_handle_, cached_metadata,
        background_resource_fetch_task_runner_,
        &background_response_processor_client_));
    EXPECT_FALSE(head);
    EXPECT_FALSE(consumer_handle_);
    EXPECT_FALSE(cached_metadata);
  }));
  // Append enough data to start streaming.
  AppendData(kLargeEnoughScript);
  producer_handle_.reset();
  background_response_processor_client_.WaitUntilFinished();
  background_response_processor_client_.CheckResultOfFinishCallback(
      /*expected_body=*/base::make_span(kLargeEnoughScript,
                                        sizeof(kLargeEnoughScript) - 1),
      /*expected_cached_metadata=*/std::nullopt);
  Finish();
  RunUntilResourceLoaded();
  // ScriptStreamer must have been created.
  CheckScriptStreamer(mojom::blink::ScriptType::kModule);
}

TEST_F(BackgroundResourceScriptStreamerTest, EncodingNotSupported) {
  V8TestingScope scope;
  // Intentionally using unsupported encoding "EUC-JP".
  Init(scope.GetIsolate(), /*is_module_script=*/false,
       WTF::TextEncoding("EUC-JP"));
  RunInBackgroundThred(base::BindLambdaForTesting([&]() {
    network::mojom::URLResponseHeadPtr head = CreateURLResponseHead();
    std::optional<mojo_base::BigBuffer> cached_metadata;
    EXPECT_TRUE(background_response_processor_->MaybeStartProcessingResponse(
        head, consumer_handle_, cached_metadata,
        background_resource_fetch_task_runner_,
        &background_response_processor_client_));
    EXPECT_FALSE(head);
    EXPECT_FALSE(consumer_handle_);
    EXPECT_FALSE(cached_metadata);
  }));
  // Append enough data to start streaming.
  AppendData(kLargeEnoughScript);
  producer_handle_.reset();
  background_response_processor_client_.WaitUntilFinished();
  background_response_processor_client_.CheckResultOfFinishCallback(
      /*expected_body=*/base::make_span(kLargeEnoughScript,
                                        sizeof(kLargeEnoughScript) - 1),
      /*expected_cached_metadata=*/std::nullopt);
  Finish();
  RunUntilResourceLoaded();
  // The encoding of the script is not supported.
  CheckNotStreamingReason(
      ScriptStreamer::NotStreamingReason::kEncodingNotSupportedBackground);
}

TEST_F(BackgroundResourceScriptStreamerTest, EncodingFromBOM) {
  V8TestingScope scope;
  // Intentionally using unsupported encoding "EUC-JP".
  Init(scope.GetIsolate(), /*is_module_script=*/false,
       WTF::TextEncoding("EUC-JP"));
  RunInBackgroundThred(base::BindLambdaForTesting([&]() {
    network::mojom::URLResponseHeadPtr head = CreateURLResponseHead();
    std::optional<mojo_base::BigBuffer> cached_metadata;
    EXPECT_TRUE(background_response_processor_->MaybeStartProcessingResponse(
        head, consumer_handle_, cached_metadata,
        background_resource_fetch_task_runner_,
        &background_response_processor_client_));
    EXPECT_FALSE(head);
    EXPECT_FALSE(consumer_handle_);
    EXPECT_FALSE(cached_metadata);
  }));
  // Append script with BOM
  AppendData(kScriptWithBOM);
  producer_handle_.reset();
  background_response_processor_client_.WaitUntilFinished();
  background_response_processor_client_.CheckResultOfFinishCallback(
      /*expected_body=*/base::make_span(kScriptWithBOM,
                                        sizeof(kScriptWithBOM) - 1),
      /*expected_cached_metadata=*/std::nullopt);
  Finish();
  RunUntilResourceLoaded();
  // ScriptStreamer must have been created.
  CheckScriptStreamer();
}

TEST_F(BackgroundResourceScriptStreamerTest, ScriptTypeMismatch) {
  V8TestingScope scope;
  Init(scope.GetIsolate(), /*is_module_script=*/true);
  RunInBackgroundThred(base::BindLambdaForTesting([&]() {
    network::mojom::URLResponseHeadPtr head = CreateURLResponseHead();
    std::optional<mojo_base::BigBuffer> cached_metadata;
    EXPECT_TRUE(background_response_processor_->MaybeStartProcessingResponse(
        head, consumer_handle_, cached_metadata,
        background_resource_fetch_task_runner_,
        &background_response_processor_client_));
    EXPECT_FALSE(head);
    EXPECT_FALSE(consumer_handle_);
    EXPECT_FALSE(cached_metadata);
  }));
  // Append enough data to start streaming.
  AppendData(kLargeEnoughScript);
  producer_handle_.reset();
  background_response_processor_client_.WaitUntilFinished();
  background_response_processor_client_.CheckResultOfFinishCallback(
      /*expected_body=*/base::make_span(kLargeEnoughScript,
                                        sizeof(kLargeEnoughScript) - 1),
      /*expected_cached_metadata=*/std::nullopt);
  Finish();
  RunUntilResourceLoaded();
  // Taking ScriptStreamer as a classic script shouold fail with
  // kErrorScriptTypeMismatch, because the script is a module script.
  CheckNotStreamingReason(
      ScriptStreamer::NotStreamingReason::kErrorScriptTypeMismatch,
      mojom::blink::ScriptType::kClassic);
}

TEST_F(BackgroundResourceScriptStreamerTest, CancelWhileWaitingForDataPipe) {
  V8TestingScope scope;
  Init(scope.GetIs
"""


```