Response:
The user wants to understand the functionality of the `resource_loader_test.cc` file in the Chromium Blink engine.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The filename suggests this is a test file for `ResourceLoader`. Its primary function is to verify the correct behavior of the `ResourceLoader` class.

2. **Analyze the included headers:** These provide clues about the functionalities being tested:
    - `resource_loader.h`: The class under test.
    - `fetch_api.mojom-blink.h`, `url_response_head.mojom.h`, `fetch/fetch_api_request.mojom-blink.h`: Indicate testing of features related to fetching resources, including request and response handling.
    - `gtest/gtest.h`, `gmock/gmock.h`:  Clearly a test file using Google Test and Mocking frameworks.
    - `features.h`: Tests might involve feature flags.
    - `platform/resource_load_info_notifier_wrapper.h`:  Likely tests related to resource loading notifications.
    - `platform/web_url.h`, `platform/web_url_request_extra_data.h`: Testing URL handling and request metadata.
    - `platform/exported/wrapped_resource_response.h`, `platform/loader/fetch/resource_response.h`: Testing response handling.
    - `platform/loader/fetch/detachable_use_counter.h`, `platform/instrumentation/use_counter.h`:  Testing usage counting.
    - `platform/loader/fetch/raw_resource.h`, `platform/loader/fetch/resource_fetcher.h`, `platform/loader/fetch/resource_load_scheduler.h`: Testing the interaction of `ResourceLoader` with related fetching components.
    - `platform/loader/fetch/url_loader/url_loader.h`, `platform/loader/fetch/url_loader/url_loader_factory.h`: Testing the underlying URL loading mechanism.
    - `platform/loader/testing/*`:  Utilizing test utilities for loaders.
    - `platform/network/http_names.h`: Testing handling of HTTP headers.
    - `platform/testing/*`: Using general platform testing utilities.

3. **Examine the test structure:**  The file defines a `ResourceLoaderTest` fixture, which sets up common resources for testing. Individual tests then exercise specific aspects of `ResourceLoader`.

4. **Focus on individual test cases:** Each `TEST_F` block usually tests a specific scenario. Analyze the actions performed within each test:
    - Loading resources with different methods (e.g., `RawResource::Fetch`, `RawResource::FetchSynchronously`).
    - Handling different types of URLs (e.g., data URLs).
    - Simulating responses and data transfer.
    - Testing redirects and header handling.
    - Checking interaction with `UseCounter`.
    - Testing deferred loading.
    - Testing subresource filtering.

5. **Relate to web technologies:** Consider how the tested scenarios map to JavaScript, HTML, and CSS features. For example, fetching resources is fundamental to loading any web page asset. Redirects are common in web navigation. Data URLs can be used in HTML and CSS.

6. **Identify logical assumptions and I/O:** For each test, determine the setup (input) and the expected outcome (output).

7. **Spot potential user/programming errors:** Think about common mistakes developers might make when dealing with resource loading, which these tests might be designed to catch.

8. **Synthesize the information:**  Combine the analysis of headers, test structure, and individual test cases to create a summary of the file's functionality.

**Self-Correction/Refinement during the thought process:**

- Initial thought:  This file *only* tests `ResourceLoader` directly. Correction: It tests `ResourceLoader` in the context of how it's used by `RawResource` and interacts with other fetching components.
- Initial thought:  Focus heavily on the technical implementation details. Correction: Balance technical details with the higher-level functional purpose and its relation to web technologies.
- Initial thought: List every single detail of every test case. Correction: Group similar tests and focus on the overarching functionality being demonstrated.
这是 `blink/renderer/platform/loader/fetch/resource_loader_test.cc` 文件的第一部分，主要功能是**测试 Blink 引擎中 `ResourceLoader` 类的各种功能和行为**。`ResourceLoader` 负责实际的网络资源加载过程，是 Blink 渲染引擎中一个核心的组件。

**以下是根据提供的代码片段归纳出的主要功能点，并结合与 JavaScript, HTML, CSS 的关系进行举例说明，同时包含逻辑推理的假设输入输出和常见错误示例：**

**1. 基础资源加载测试:**

*   **功能:** 测试 `ResourceLoader` 是否能正确加载资源并接收响应体数据。
*   **与 Web 技术的关系:**
    *   **JavaScript:** 当 JavaScript 代码使用 `fetch()` API 或 `XMLHttpRequest` 发起网络请求时，最终会由 Blink 的资源加载机制（包括 `ResourceLoader`）来处理。
    *   **HTML:**  浏览器加载 HTML 文档时，会解析其中的 `<img>`, `<script>`, `<link>` 等标签，这些标签指向的资源（图片、脚本、样式表）都需要通过 `ResourceLoader` 进行加载。
    *   **CSS:**  CSS 文件本身需要加载，同时 CSS 中可能包含 `@import` 规则或 `url()` 函数引用的其他资源（例如图片），这些资源的加载也依赖于 `ResourceLoader`。
*   **假设输入与输出:**
    *   **假设输入:**
        *   一个有效的 URL (`https://www.example.com/`)。
        *   一个包含 "hello" 内容的 HTTP 响应。
    *   **预期输出:**
        *   `ResourceLoader` 成功接收到响应头和响应体。
        *   加载的资源状态变为 `ResourceStatus::kCached`。
        *   可以通过 `resource->ResourceBuffer()` 获取到包含 "hello" 内容的 `SharedBuffer`。
*   **常见错误:**
    *   服务器返回非 200 状态码。
    *   网络连接中断或超时。
    *   CORS 策略阻止跨域请求。

**2. Data URL 加载测试:**

*   **功能:** 测试 `ResourceLoader` 对 Data URL 的加载能力，包括异步和同步两种方式，以及是否能处理流式读取。
*   **与 Web 技术的关系:**
    *   **JavaScript:** JavaScript 可以创建和使用 Data URL，例如用于嵌入小型图片或动态生成内容。
    *   **HTML:** `<img>` 标签的 `src` 属性可以直接使用 Data URL。
    *   **CSS:** CSS 的 `background-image` 属性可以使用 Data URL。
*   **假设输入与输出:**
    *   **异步非流式:**
        *   **假设输入:**  Data URL `data:text/plain,Hello%20World!`
        *   **预期输出:**  资源状态变为 `ResourceStatus::kCached`，`resource->ResourceBuffer()` 返回包含 "Hello World!" 的 `SharedBuffer`。
    *   **异步流式:**
        *   **假设输入:**  Data URL `data:text/plain,Hello%20World!`，并设置 `request.SetUseStreamOnResponse(true)`。
        *   **预期输出:**  可以通过 `RawResourceClient::ResponseBodyReceived` 获取到 `BytesConsumer`，读取后得到 "Hello World!"，但 `resource->ResourceBuffer()` 为空。
    *   **同步:**
        *   **假设输入:**  Data URL `data:text/plain,Hello%20World!`
        *   **预期输出:**  资源状态直接变为 `ResourceStatus::kCached`，`resource->ResourceBuffer()` 返回包含 "Hello World!" 的 `SharedBuffer`。
*   **常见错误:**
    *   Data URL 格式错误。
    *   尝试同步加载过大的 Data URL 导致性能问题。

**3. 延迟加载测试 (Defers Loading):**

*   **功能:** 测试 `ResourceLoader` 的延迟加载机制，即在需要时才开始实际加载资源。
*   **与 Web 技术的关系:**
    *   **JavaScript:** 可以通过一些技术（例如 Intersection Observer API）来延迟加载图片或其他资源，以提高页面初始加载速度。
    *   **HTML:**  `<img>` 标签的 `loading="lazy"` 属性可以指示浏览器延迟加载图片。
*   **假设输入与输出:**
    *   **假设输入:**  Data URL 和 `fetcher->SetDefersLoading(LoaderFreezeMode::kStrict)`。
    *   **预期输出:**  在设置延迟加载后，资源状态保持 `ResourceStatus::kPending`，直到取消延迟加载。
*   **常见错误:**
    *   错误地配置延迟加载策略导致资源无法加载。

**4. 重定向处理测试:**

*   **功能:** 测试 `ResourceLoader` 在处理 HTTP 重定向时的行为，特别是跨域重定向和 `Authorization` 头部的处理。
*   **与 Web 技术的关系:**
    *   **JavaScript:**  `fetch()` API 可以配置是否跟随重定向。
    *   **HTML:**  浏览器在加载 HTML 文档中的资源时会自动处理 HTTP 重定向。
*   **假设输入与输出:**
    *   **跨域重定向且存在 `Authorization` 头部:**
        *   **假设输入:**  初始请求包含 `Authorization` 头部，并且重定向到不同的域名。
        *   **预期输出:**  `UseCounter` 记录 `mojom::WebFeature::kAuthorizationCrossOrigin` 的使用。
    *   **跨域重定向但不存在 `Authorization` 头部:**
        *   **假设输入:**  初始请求不包含 `Authorization` 头部，并且重定向到不同的域名。
        *   **预期输出:**  `UseCounter` 不记录相关信息。
*   **常见错误:**
    *   重定向循环。
    *   HTTPS 站点重定向到 HTTP 站点可能导致安全问题。

**5. Subresource Filter 和 CNAME Alias 测试 (ResourceLoaderSubresourceFilterCnameAliasTest):**

*   **功能:** 测试 `ResourceLoader` 如何与子资源过滤器交互，特别是当涉及到 CNAME 别名时，判断资源是否被阻止或标记为广告。
*   **与 Web 技术的关系:**
    *   这部分功能涉及到浏览器内置的广告拦截或内容过滤机制。
*   **假设输入与输出:**
    *   **假设输入:**
        *   一个 URL (`https://www.example.com/some_path.html`).
        *   一个包含 CNAME 别名的 HTTP 响应头，例如 `{"ad.com", "bad-ad.com"}`。
        *   子资源过滤器的阻止列表包含 `https://bad-ad.com/some_path.html`，标记列表包含 `https://ad.com/some_path.html`。
    *   **预期输出:**
        *   `loader->cname_alias_info_for_testing_` 会记录检测到的 CNAME 别名信息。
        *   根据阻止列表和标记列表，资源可能被标记为广告 (`was_ad_tagged_based_on_alias = true`) 或被阻止 (`was_blocked_based_on_alias = true`)。
*   **常见错误:**
    *   CNAME 配置错误导致子资源过滤器误判。

**总结 (根据第一部分代码):**

`resource_loader_test.cc` 的第一部分主要集中在测试 `ResourceLoader` 的**基本资源加载、Data URL 加载、延迟加载以及重定向处理**等核心功能。它通过模拟各种场景，例如不同的 URL 类型、请求方式、响应状态等，来验证 `ResourceLoader` 的行为是否符合预期。此外，还初步涉及了 `ResourceLoader` 与子资源过滤器在 CNAME 别名处理上的交互。 这些测试对于确保 Blink 引擎能够正确、高效、安全地加载各种 Web 资源至关重要。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/resource_loader_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/resource_loader.h"

#include <string>
#include <utility>

#include "base/containers/span.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/scoped_feature_list.h"
#include "mojo/public/c/system/data_pipe.h"
#include "net/http/http_response_headers.h"
#include "services/network/public/mojom/fetch_api.mojom-blink.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/platform/resource_load_info_notifier_wrapper.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_url_request_extra_data.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_response.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/detachable_use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/raw_resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_scheduler.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader_factory.h"
#include "third_party/blink/renderer/platform/loader/testing/bytes_consumer_test_reader.h"
#include "third_party/blink/renderer/platform/loader/testing/mock_fetch_context.h"
#include "third_party/blink/renderer/platform/loader/testing/test_resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/testing/mock_context_lifecycle_notifier.h"
#include "third_party/blink/renderer/platform/testing/noop_url_loader.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support_with_mock_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

using ::testing::_;

class MockUseCounter : public GarbageCollected<MockUseCounter>,
                       public UseCounter {
 public:
  MOCK_METHOD1(CountUse, void(mojom::WebFeature));
  MOCK_METHOD1(CountWebDXFeature, void(mojom::blink::WebDXFeature));
  MOCK_METHOD1(CountDeprecation, void(mojom::WebFeature));
};

}  // namespace

class ResourceLoaderTest : public testing::Test {
 public:
  enum class From {
    kServiceWorker,
    kNetwork,
  };

  ResourceLoaderTest()
      : foo_url_("https://foo.test"), bar_url_("https://bar.test") {}
  ResourceLoaderTest(const ResourceLoaderTest&) = delete;
  ResourceLoaderTest& operator=(const ResourceLoaderTest&) = delete;

 protected:
  using RequestMode = network::mojom::RequestMode;
  using FetchResponseType = network::mojom::FetchResponseType;

  struct TestCase {
    const KURL url;
    const RequestMode request_mode;
    const From from;
    const scoped_refptr<const SecurityOrigin> allowed_origin;
    const FetchResponseType original_response_type;
    const FetchResponseType expectation;
  };

  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform_;
  const KURL foo_url_;
  const KURL bar_url_;

  class NoopLoaderFactory final : public ResourceFetcher::LoaderFactory {
    std::unique_ptr<URLLoader> CreateURLLoader(
        const network::ResourceRequest& request,
        const ResourceLoaderOptions& options,
        scoped_refptr<base::SingleThreadTaskRunner> freezable_task_runner,
        scoped_refptr<base::SingleThreadTaskRunner> unfreezable_task_runner,
        BackForwardCacheLoaderHelper* back_forward_cache_loader_helper,
        const std::optional<base::UnguessableToken>&
            service_worker_race_network_request_token,
        bool is_from_origin_dirty_style_sheet) override {
      return std::make_unique<NoopURLLoader>(std::move(freezable_task_runner));
    }
    CodeCacheHost* GetCodeCacheHost() override { return nullptr; }
  };

  static scoped_refptr<base::SingleThreadTaskRunner> CreateTaskRunner() {
    return base::MakeRefCounted<scheduler::FakeTaskRunner>();
  }

  ResourceFetcher* MakeResourceFetcher(
      TestResourceFetcherProperties* properties,
      FetchContext* context) {
    ResourceFetcherInit init(
        properties->MakeDetachable(), context, CreateTaskRunner(),
        CreateTaskRunner(), MakeGarbageCollected<NoopLoaderFactory>(),
        MakeGarbageCollected<MockContextLifecycleNotifier>(),
        /*back_forward_cache_loader_helper=*/nullptr);
    use_counter_ = MakeGarbageCollected<testing::StrictMock<MockUseCounter>>();
    init.use_counter = MakeGarbageCollected<DetachableUseCounter>(use_counter_);
    return MakeGarbageCollected<ResourceFetcher>(std::move(init));
  }

  MockUseCounter* UseCounter() const { return use_counter_; }

 private:
  base::test::SingleThreadTaskEnvironment task_environment_;
  Persistent<MockUseCounter> use_counter_;
};

std::ostream& operator<<(std::ostream& o, const ResourceLoaderTest::From& f) {
  switch (f) {
    case ResourceLoaderTest::From::kServiceWorker:
      o << "service worker";
      break;
    case ResourceLoaderTest::From::kNetwork:
      o << "network";
      break;
  }
  return o;
}

TEST_F(ResourceLoaderTest, LoadResponseBody) {
  auto* properties = MakeGarbageCollected<TestResourceFetcherProperties>();
  FetchContext* context = MakeGarbageCollected<MockFetchContext>();
  auto* fetcher = MakeResourceFetcher(properties, context);

  KURL url("https://www.example.com/");
  ResourceRequest request(url);
  request.SetRequestContext(mojom::blink::RequestContextType::FETCH);

  FetchParameters params = FetchParameters::CreateForTest(std::move(request));
  Resource* resource = RawResource::Fetch(params, fetcher, nullptr);
  ResourceLoader* loader = resource->Loader();

  ResourceResponse response(url);
  response.SetHttpStatusCode(200);

  mojo::ScopedDataPipeProducerHandle producer;
  mojo::ScopedDataPipeConsumerHandle consumer;
  MojoCreateDataPipeOptions options;
  options.struct_size = sizeof(MojoCreateDataPipeOptions);
  options.flags = MOJO_CREATE_DATA_PIPE_FLAG_NONE;
  options.element_num_bytes = 1;
  options.capacity_num_bytes = 3;

  MojoResult result = CreateDataPipe(&options, producer, consumer);
  ASSERT_EQ(result, MOJO_RESULT_OK);

  loader->DidReceiveResponse(WrappedResourceResponse(response),
                             std::move(consumer),
                             /*cached_metadata=*/std::nullopt);
  loader->DidFinishLoading(base::TimeTicks(), 0, 0, 0);

  size_t actually_written_bytes = 0;
  result =
      producer->WriteData(base::byte_span_from_cstring("he"),
                          MOJO_WRITE_DATA_FLAG_NONE, actually_written_bytes);
  ASSERT_EQ(result, MOJO_RESULT_OK);
  ASSERT_EQ(actually_written_bytes, 2u);

  static_cast<scheduler::FakeTaskRunner*>(fetcher->GetTaskRunner().get())
      ->RunUntilIdle();

  result =
      producer->WriteData(base::byte_span_from_cstring("llo"),
                          MOJO_WRITE_DATA_FLAG_NONE, actually_written_bytes);
  ASSERT_EQ(result, MOJO_RESULT_OK);
  ASSERT_EQ(actually_written_bytes, 3u);

  static_cast<scheduler::FakeTaskRunner*>(fetcher->GetTaskRunner().get())
      ->RunUntilIdle();

  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kPending);

  producer.reset();
  static_cast<scheduler::FakeTaskRunner*>(fetcher->GetTaskRunner().get())
      ->RunUntilIdle();

  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kCached);
  scoped_refptr<const SharedBuffer> buffer = resource->ResourceBuffer();
  StringBuilder data;
  for (const auto& span : *buffer) {
    data.Append(base::as_bytes(span));
  }
  EXPECT_EQ(data.ToString(), "hello");
}

TEST_F(ResourceLoaderTest, LoadDataURL_AsyncAndNonStream) {
  auto* properties = MakeGarbageCollected<TestResourceFetcherProperties>();
  FetchContext* context = MakeGarbageCollected<MockFetchContext>();
  auto* fetcher = MakeResourceFetcher(properties, context);

  // Fetch a data url.
  KURL url("data:text/plain,Hello%20World!");
  ResourceRequest request(url);
  request.SetRequestContext(mojom::blink::RequestContextType::FETCH);
  FetchParameters params = FetchParameters::CreateForTest(std::move(request));
  Resource* resource = RawResource::Fetch(params, fetcher, nullptr);
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kPending);
  static_cast<scheduler::FakeTaskRunner*>(fetcher->GetTaskRunner().get())
      ->RunUntilIdle();

  // The resource has a parsed body.
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kCached);
  scoped_refptr<const SharedBuffer> buffer = resource->ResourceBuffer();
  StringBuilder data;
  for (const auto& span : *buffer) {
    data.Append(base::as_bytes(span));
  }
  EXPECT_EQ(data.ToString(), "Hello World!");
}

// Helper class which stores a BytesConsumer passed by RawResource and reads the
// bytes when ReadThroughBytesConsumer is called.
class TestRawResourceClient final
    : public GarbageCollected<TestRawResourceClient>,
      public RawResourceClient {
 public:
  TestRawResourceClient() = default;

  // Implements RawResourceClient.
  void ResponseBodyReceived(Resource* resource,
                            BytesConsumer& bytes_consumer) override {
    body_ = &bytes_consumer;
  }
  String DebugName() const override { return "TestRawResourceClient"; }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(body_);
    RawResourceClient::Trace(visitor);
  }

  BytesConsumer* body() { return body_.Get(); }

 private:
  Member<BytesConsumer> body_;
};

TEST_F(ResourceLoaderTest, LoadDataURL_AsyncAndStream) {
  auto* properties = MakeGarbageCollected<TestResourceFetcherProperties>();
  FetchContext* context = MakeGarbageCollected<MockFetchContext>();
  auto* fetcher = MakeResourceFetcher(properties, context);
  scheduler::FakeTaskRunner* task_runner =
      static_cast<scheduler::FakeTaskRunner*>(fetcher->GetTaskRunner().get());

  // Fetch a data url as a stream on response.
  KURL url("data:text/plain,Hello%20World!");
  ResourceRequest request(url);
  request.SetRequestContext(mojom::blink::RequestContextType::FETCH);
  request.SetUseStreamOnResponse(true);
  FetchParameters params = FetchParameters::CreateForTest(std::move(request));
  auto* raw_resource_client = MakeGarbageCollected<TestRawResourceClient>();
  Resource* resource = RawResource::Fetch(params, fetcher, raw_resource_client);
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kPending);
  task_runner->RunUntilIdle();

  // It's still pending because we don't read the body yet.
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kPending);

  // Read through the bytes consumer passed back from the ResourceLoader.
  auto* test_reader = MakeGarbageCollected<BytesConsumerTestReader>(
      raw_resource_client->body());
  auto [result, body] = test_reader->Run(task_runner);
  EXPECT_EQ(result, BytesConsumer::Result::kDone);
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kCached);
  EXPECT_EQ(std::string(body.data(), body.size()), "Hello World!");

  // The body is not set to ResourceBuffer since the response body is requested
  // as a stream.
  scoped_refptr<const SharedBuffer> buffer = resource->ResourceBuffer();
  EXPECT_FALSE(buffer);
}

TEST_F(ResourceLoaderTest, LoadDataURL_AsyncEmptyData) {
  auto* properties = MakeGarbageCollected<TestResourceFetcherProperties>();
  FetchContext* context = MakeGarbageCollected<MockFetchContext>();
  auto* fetcher = MakeResourceFetcher(properties, context);

  // Fetch an empty data url.
  KURL url("data:text/html,");
  ResourceRequest request(url);
  request.SetRequestContext(mojom::blink::RequestContextType::FETCH);
  FetchParameters params = FetchParameters::CreateForTest(std::move(request));
  Resource* resource = RawResource::Fetch(params, fetcher, nullptr);
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kPending);
  static_cast<scheduler::FakeTaskRunner*>(fetcher->GetTaskRunner().get())
      ->RunUntilIdle();

  // It successfully finishes, and no buffer is propagated.
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kCached);
  scoped_refptr<const SharedBuffer> buffer = resource->ResourceBuffer();
  EXPECT_FALSE(buffer);
}

TEST_F(ResourceLoaderTest, LoadDataURL_Sync) {
  auto* properties = MakeGarbageCollected<TestResourceFetcherProperties>();
  FetchContext* context = MakeGarbageCollected<MockFetchContext>();
  auto* fetcher = MakeResourceFetcher(properties, context);

  // Fetch a data url synchronously.
  KURL url("data:text/plain,Hello%20World!");
  ResourceRequest request(url);
  request.SetRequestContext(mojom::blink::RequestContextType::FETCH);
  FetchParameters params = FetchParameters::CreateForTest(std::move(request));
  Resource* resource =
      RawResource::FetchSynchronously(params, fetcher, nullptr);

  // The resource has a parsed body.
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kCached);
  scoped_refptr<const SharedBuffer> buffer = resource->ResourceBuffer();
  StringBuilder data;
  for (const auto& span : *buffer) {
    data.Append(base::as_bytes(span));
  }
  EXPECT_EQ(data.ToString(), "Hello World!");
}

TEST_F(ResourceLoaderTest, LoadDataURL_SyncEmptyData) {
  auto* properties = MakeGarbageCollected<TestResourceFetcherProperties>();
  FetchContext* context = MakeGarbageCollected<MockFetchContext>();
  auto* fetcher = MakeResourceFetcher(properties, context);

  // Fetch an empty data url synchronously.
  KURL url("data:text/html,");
  ResourceRequest request(url);
  request.SetRequestContext(mojom::blink::RequestContextType::FETCH);
  FetchParameters params = FetchParameters::CreateForTest(std::move(request));
  Resource* resource =
      RawResource::FetchSynchronously(params, fetcher, nullptr);

  // It successfully finishes, and no buffer is propagated.
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kCached);
  scoped_refptr<const SharedBuffer> buffer = resource->ResourceBuffer();
  EXPECT_FALSE(buffer);
}

TEST_F(ResourceLoaderTest, LoadDataURL_DefersAsyncAndNonStream) {
  auto* properties = MakeGarbageCollected<TestResourceFetcherProperties>();
  FetchContext* context = MakeGarbageCollected<MockFetchContext>();
  auto* fetcher = MakeResourceFetcher(properties, context);
  scheduler::FakeTaskRunner* task_runner =
      static_cast<scheduler::FakeTaskRunner*>(fetcher->GetTaskRunner().get());

  // Fetch a data url.
  KURL url("data:text/plain,Hello%20World!");
  ResourceRequest request(url);
  request.SetRequestContext(mojom::blink::RequestContextType::FETCH);
  FetchParameters params = FetchParameters::CreateForTest(std::move(request));
  Resource* resource = RawResource::Fetch(params, fetcher, nullptr);
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kPending);

  // The resource should still be pending since it's deferred.
  fetcher->SetDefersLoading(LoaderFreezeMode::kStrict);
  task_runner->RunUntilIdle();
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kPending);

  // The resource should still be pending since it's deferred again.
  fetcher->SetDefersLoading(LoaderFreezeMode::kStrict);
  task_runner->RunUntilIdle();
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kPending);

  // The resource should still be pending if it's unset and set in a single
  // task.
  fetcher->SetDefersLoading(LoaderFreezeMode::kNone);
  fetcher->SetDefersLoading(LoaderFreezeMode::kStrict);
  task_runner->RunUntilIdle();
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kPending);

  // The resource has a parsed body.
  fetcher->SetDefersLoading(LoaderFreezeMode::kNone);
  task_runner->RunUntilIdle();
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kCached);
  scoped_refptr<const SharedBuffer> buffer = resource->ResourceBuffer();
  StringBuilder data;
  for (const auto& span : *buffer) {
    data.Append(base::as_bytes(span));
  }
  EXPECT_EQ(data.ToString(), "Hello World!");
}

TEST_F(ResourceLoaderTest, LoadDataURL_DefersAsyncAndStream) {
  auto* properties = MakeGarbageCollected<TestResourceFetcherProperties>();
  FetchContext* context = MakeGarbageCollected<MockFetchContext>();
  auto* fetcher = MakeResourceFetcher(properties, context);
  scheduler::FakeTaskRunner* task_runner =
      static_cast<scheduler::FakeTaskRunner*>(fetcher->GetTaskRunner().get());

  // Fetch a data url as a stream on response.
  KURL url("data:text/plain,Hello%20World!");
  ResourceRequest request(url);
  request.SetRequestContext(mojom::blink::RequestContextType::FETCH);
  request.SetUseStreamOnResponse(true);
  FetchParameters params = FetchParameters::CreateForTest(std::move(request));
  auto* raw_resource_client = MakeGarbageCollected<TestRawResourceClient>();
  Resource* resource = RawResource::Fetch(params, fetcher, raw_resource_client);
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kPending);
  fetcher->SetDefersLoading(LoaderFreezeMode::kStrict);
  task_runner->RunUntilIdle();

  // It's still pending because the body should not provided yet.
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kPending);
  EXPECT_FALSE(raw_resource_client->body());

  // The body should be provided since not deferring now, but it's still pending
  // since we haven't read the body yet.
  fetcher->SetDefersLoading(LoaderFreezeMode::kNone);
  task_runner->RunUntilIdle();
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kPending);
  EXPECT_TRUE(raw_resource_client->body());

  // The resource should still be pending when it's set to deferred again. No
  // body is provided when deferred.
  fetcher->SetDefersLoading(LoaderFreezeMode::kStrict);
  task_runner->RunUntilIdle();
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kPending);
  base::span<const char> buffer;
  BytesConsumer::Result result = raw_resource_client->body()->BeginRead(buffer);
  EXPECT_EQ(BytesConsumer::Result::kShouldWait, result);

  // The resource should still be pending if it's unset and set in a single
  // task. No body is provided when deferred.
  fetcher->SetDefersLoading(LoaderFreezeMode::kNone);
  fetcher->SetDefersLoading(LoaderFreezeMode::kStrict);
  task_runner->RunUntilIdle();
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kPending);
  result = raw_resource_client->body()->BeginRead(buffer);
  EXPECT_EQ(BytesConsumer::Result::kShouldWait, result);

  // Read through the bytes consumer passed back from the ResourceLoader.
  fetcher->SetDefersLoading(LoaderFreezeMode::kNone);
  task_runner->RunUntilIdle();
  auto* test_reader = MakeGarbageCollected<BytesConsumerTestReader>(
      raw_resource_client->body());
  Vector<char> body;
  std::tie(result, body) = test_reader->Run(task_runner);
  EXPECT_EQ(resource->GetStatus(), ResourceStatus::kCached);
  EXPECT_EQ(std::string(body.data(), body.size()), "Hello World!");

  // The body is not set to ResourceBuffer since the response body is requested
  // as a stream.
  EXPECT_FALSE(resource->ResourceBuffer());
}

namespace {

bool WillFollowRedirect(ResourceLoader* loader, KURL new_url) {
  auto response_head = network::mojom::URLResponseHead::New();
  auto response =
      WebURLResponse::Create(new_url, *response_head,
                             /*report_security_info=*/true, /*request_id=*/1);
  bool has_devtools_request_id = false;
  std::vector<std::string> removed_headers;
  net::HttpRequestHeaders modified_headers;
  return loader->WillFollowRedirect(
      new_url, net::SiteForCookies(), /*new_referrer=*/String(),
      network::mojom::ReferrerPolicy::kAlways, "GET", response,
      has_devtools_request_id, &removed_headers, modified_headers,
      /*insecure_scheme_was_upgraded=*/false);
}

}  // namespace

TEST_F(ResourceLoaderTest, AuthorizationCrossOriginRedirect) {
  auto* properties = MakeGarbageCollected<TestResourceFetcherProperties>();
  FetchContext* context = MakeGarbageCollected<MockFetchContext>();
  auto* fetcher = MakeResourceFetcher(properties, context);

  KURL url("https://a.test/");
  ResourceRequest request(url);
  request.SetRequestContext(mojom::blink::RequestContextType::FETCH);
  request.SetHttpHeaderField(http_names::kAuthorization,
                             AtomicString("Basic foo"));

  FetchParameters params = FetchParameters::CreateForTest(std::move(request));
  Resource* resource = RawResource::Fetch(params, fetcher, nullptr);
  ResourceLoader* loader = resource->Loader();

  // Redirect to the same origin. Expect no UseCounter call.
  {
    KURL new_url("https://a.test/foo");
    ASSERT_TRUE(WillFollowRedirect(loader, new_url));
    ::testing::Mock::VerifyAndClear(UseCounter());
  }

  // Redirect to a cross origin. Expect a single UseCounter call.
  {
    EXPECT_CALL(*UseCounter(),
                CountUse(mojom::WebFeature::kAuthorizationCrossOrigin))
        .Times(1);
    KURL new_url("https://b.test");
    ASSERT_TRUE(WillFollowRedirect(loader, new_url));
    ::testing::Mock::VerifyAndClear(UseCounter());
  }
}

TEST_F(ResourceLoaderTest, CrossOriginRedirect_NoAuthorization) {
  auto* properties = MakeGarbageCollected<TestResourceFetcherProperties>();
  FetchContext* context = MakeGarbageCollected<MockFetchContext>();
  auto* fetcher = MakeResourceFetcher(properties, context);

  KURL url("https://a.test/");
  ResourceRequest request(url);
  request.SetRequestContext(mojom::blink::RequestContextType::FETCH);

  FetchParameters params = FetchParameters::CreateForTest(std::move(request));
  Resource* resource = RawResource::Fetch(params, fetcher, nullptr);
  ResourceLoader* loader = resource->Loader();

  // Redirect to a cross origin without Authorization header. Expect no
  // UseCounter call.
  KURL new_url("https://b.test");
  ASSERT_TRUE(WillFollowRedirect(loader, new_url));
  ::testing::Mock::VerifyAndClear(UseCounter());
}

class ResourceLoaderSubresourceFilterCnameAliasTest
    : public ResourceLoaderTest {
 public:
  ResourceLoaderSubresourceFilterCnameAliasTest() = default;
  ~ResourceLoaderSubresourceFilterCnameAliasTest() override = default;

  void SetUp() override {
    feature_list_.InitAndEnableFeature(
        features::kSendCnameAliasesToSubresourceFilterFromRenderer);
    ResourceLoaderTest::SetUp();
  }

  void SetMockSubresourceFilterBlockLists(Vector<String> blocked_urls,
                                          Vector<String> tagged_urls) {
    blocked_urls_ = blocked_urls;
    tagged_urls_ = tagged_urls;
  }

  Resource* CreateResource(ResourceRequest request) {
    FetchParameters params = FetchParameters::CreateForTest(std::move(request));
    auto* fetcher = MakeResourceFetcherWithMockSubresourceFilter();
    return RawResource::Fetch(params, fetcher, nullptr);
  }

  void GiveResponseToLoader(ResourceResponse response, ResourceLoader* loader) {
    CreateMojoDataPipe();
    loader->DidReceiveResponse(WrappedResourceResponse(response),
                               /*body=*/mojo::ScopedDataPipeConsumerHandle(),
                               /*cached_metadata=*/std::nullopt);
  }

 protected:
  FetchContext* MakeFetchContextWithMockSubresourceFilter(
      Vector<String> blocked_urls,
      Vector<String> tagged_urls) {
    auto* context = MakeGarbageCollected<MockFetchContext>();
    context->set_blocked_urls(blocked_urls);
    context->set_tagged_urls(tagged_urls);
    return context;
  }

  ResourceFetcher* MakeResourceFetcherWithMockSubresourceFilter() {
    auto* properties = MakeGarbageCollected<TestResourceFetcherProperties>();
    FetchContext* context =
        MakeFetchContextWithMockSubresourceFilter(blocked_urls_, tagged_urls_);
    return MakeResourceFetcher(properties, context);
  }

  void CreateMojoDataPipe() {
    mojo::ScopedDataPipeProducerHandle producer;
    mojo::ScopedDataPipeConsumerHandle consumer;
    MojoCreateDataPipeOptions options;
    options.struct_size = sizeof(MojoCreateDataPipeOptions);
    options.flags = MOJO_CREATE_DATA_PIPE_FLAG_NONE;
    options.element_num_bytes = 1;
    options.capacity_num_bytes = 3;

    MojoResult result = CreateDataPipe(&options, producer, consumer);
    ASSERT_EQ(result, MOJO_RESULT_OK);
  }

  void ExpectCnameAliasInfoMatching(CnameAliasInfoForTesting info,
                                    ResourceLoader* loader) {
    EXPECT_EQ(loader->cname_alias_info_for_testing_.has_aliases,
              info.has_aliases);

    if (info.has_aliases) {
      EXPECT_EQ(
          loader->cname_alias_info_for_testing_.was_ad_tagged_based_on_alias,
          info.was_ad_tagged_based_on_alias);
      EXPECT_EQ(
          loader->cname_alias_info_for_testing_.was_blocked_based_on_alias,
          info.was_blocked_based_on_alias);
      EXPECT_EQ(loader->cname_alias_info_for_testing_.list_length,
                info.list_length);
      EXPECT_EQ(loader->cname_alias_info_for_testing_.invalid_count,
                info.invalid_count);
      EXPECT_EQ(loader->cname_alias_info_for_testing_.redundant_count,
                info.redundant_count);
    }
  }

 private:
  base::test::ScopedFeatureList feature_list_;
  Vector<String> blocked_urls_;
  Vector<String> tagged_urls_;
};

TEST_F(ResourceLoaderSubresourceFilterCnameAliasTest,
       DnsAliasesCheckedBySubresourceFilterDisallowed_TaggedAndBlocked) {
  // Set the blocklists: the first for blocking, the second for ad-tagging.
  Vector<String> blocked_urls = {"https://bad-ad.com/some_path.html"};
  Vector<String> tagged_urls = {"https://ad.com/some_path.html"};
  SetMockSubresourceFilterBlockLists(blocked_urls, tagged_urls);

  // Create the request.
  KURL url("https://www.example.com/some_path.html");
  ResourceRequest request(url);
  request.SetRequestContext(mojom::blink::RequestContextType::FETCH);

  // Create the resource and loader.
  Resource* resource = CreateResource(std::move(request));
  ResourceLoader* loader = resource->Loader();

  // Create the response.
  ResourceResponse response(url);
  response.SetHttpStatusCode(200);

  // Set the CNAME aliases.
  Vector<String> aliases({"ad.com", "bad-ad.com", "alias3.com"});
  response.SetDnsAliases(aliases);

  // Give the response to the loader.
  GiveResponseToLoader(response, loader);

  // Test the histograms to verify that the CNAME aliases were detected.
  // Expect that the resource was tagged as a ad, due to first alias.
  // Expect that the resource was blocked, due to second alias.
  CnameAliasInfoForTesting info = {.has_aliases = true,
                                   .was_ad_tagged_based_on_alias = true,
                                   .was_blocked_based_on_alias = true,
                                   .list_length = 3,
                                   .invalid_count = 0,
                                   .redundant_count = 0};

  ExpectCnameAliasInfoMatching(info, loader);
}

TEST_F(ResourceLoaderSubresourceFilterCnameAliasTest,
       DnsAliasesCheckedBySubresourceFilterDisallowed_BlockedOnly) {
  // Set the blocklists: the first for blocking, the second for ad-tagging.
  Vector<String> blocked_urls = {"https://bad-ad.com/some_path.html"};
  Vector<String> tagged_urls = {};
  SetMockSubresourceFilterBlockLists(blocked_urls, tagged_urls);

  // Create the request.
  KURL url("https://www.example.com/some_path.html");
  ResourceRequest request(url);
  request.SetRequestContext(mojom::blink::RequestContextType::FETCH);

  // Create the resource and loader.
  Resource* resource = CreateResource(std::move(request));
  ResourceLoader* loader = resource->Loader();

  // Create the response.
  ResourceResponse response(url);
  response.SetHttpStatusCode(200);

  // Set the CNAME aliases.
  Vector<String> aliases({"ad.com", "bad-ad.com", "alias3.com"});
  response.SetDnsAliases(aliases);

  // Give the response to the loader.
  GiveResponseToLoader(response, loader);

  // Test the histograms to verify that the CNAME aliases were detected.
  // Expect that the resource was blocked, due to second alias.
  CnameAliasInfoForTesting info = {.has_aliases = true,
                                   .was_ad_tagged_based_on_alias = false,
                                   .was_blocked_based_on_alias = true,
                                   .list_length = 3,
                                   .invalid_count = 0,
                                   .redundant_count = 0};

  ExpectCnameAliasInfoMatching(info, loader);
}

TEST_F(ResourceLoaderSubresourceFilterCnameAliasTest,
       DnsAliasesCheckedBySubresourceFilterDisallowed_TaggedOnly) {
  // Set the blocklists: the first for blocking, the second for ad-tagging.
  Vector<String> blocked_urls = {};
  Vector<String> tagged_urls = {"https://bad-ad.com/some_path.html"};
  SetMockSubresourceFilterBlockLists(blocked_urls, tagged_urls);

  // Create the request.
  KURL url("https://www.example.com/some_path.html");
  ResourceRequest request(url);
  request.SetRequestContext(mojom::blink::RequestContextType::FETCH);

  // Create the resource and loader.
  Resource* resource = CreateResource(std::move(request));
  ResourceLoader* loader = resource->Loader();

  // Create the response.
  ResourceResponse response(url);
  response.SetHttpStatusCode(200);

  // Set the CNAME aliases.
  Vector<String> aliases({"ad.com", "", "alias3.com", "bad-ad.com"});
  response.SetDnsAliases(aliases);

  // Give the response to the loader.
  GiveResponseToLoader(response, loader);

  // Test the histograms to verify that the CNAME aliases were detected.
  // Expect that the resource was tagged, due to fourth alias.
  // Expect that the invalid empty alias is counted as such.
  CnameAliasInfoForTesting info = {.has_aliases = true,
                                   .was_ad_tagged_based_on_alias = true,
                                   .was_blocked_based_on_alias = false,
                                   .list_length = 4,
                                   .invalid_count = 1,
                                   .redundant_count = 0};

  ExpectCnameAliasInfoMatching(info, loader);
}

TEST_F(ResourceLoaderSubresourceFilterCnameAliasTest,
       DnsAliasesCheckedBySubresourceFilterAllowed_NotBlockedOrTagged) {
  // Set the blocklists: the first for blocking, the second for ad-tagging.
  Vector<String> blocked_urls = {};
  Vector<String> tagged_urls = {};
  SetMockSubresourceFilterBlockLists(blocked_urls, tagged_urls);

  // Create the request.
  KURL url("https://www.example.com/some_path.html");
  ResourceRequest request(url);
  request.SetRequestContext(mojom::blink::RequestContextType::FETCH);

  // Create the resource and loader.
  Resource* resource = CreateResource(std::move(request));
  ResourceLoader* loader = resource->Loader();

  // Create the response.
  ResourceResponse response(url);
  response.SetHttpStatusCode(200);

  // Set the CNAME aliases.
  Vector<String> aliases(
      {"non-ad.com", "?", "alias3.com", "not-an-ad.com", "www.example.com"});
  response.SetDnsAliases(aliases);

  // Give the response to the loader.
  GiveResponseToLoader(response, loader);

  // Test the histograms to verify that the CNAME aliases were detected.
  // Expect that the resource was neither tagged nor blocked.
  // Expect that the invalid alias is counted as such.
  // Expect that the redundant (i.e. matching the request URL) fifth alias to be
  // counted as such.
  CnameAliasInfoForTesting info = {.has_aliases = true,
                                   .was_ad_tagged_based_on_alias = false,
                                   .was_blocked_based_on_alias = false,
                                   .list_length = 5,
                                   .invalid_count = 1,
                                   .redundant_count = 1};

  ExpectCnameAliasInfoMatching(info, loader);
}

TEST_F(ResourceLoaderSubresourceFilterCnameAliasTest,
       DnsAliasesCheckedBySubresourceFilterNoAliases_NoneDetected) {
  // Set the blocklists: the first for blocking, the second for ad-tagging.
  Vector<String> blocked_urls = {};
  Vector<String> tagged_urls = {};
  SetMockSubresourceFilterBlockLists(blocked_urls, tagged_urls);

  // Create the request.
  KURL url("https://www.example.com/some_path.html");
  ResourceRequest request(url);
  request.SetRequestContext(mojom::blink::RequestContextType::FETCH);

  // Create the resource and loader.
  Resource* resource = CreateResource(std::move(request));
  ResourceLoader*
```