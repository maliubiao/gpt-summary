Response:
My thought process to analyze the provided C++ test file goes like this:

1. **Understand the Goal:** The request asks for the functionalities of the test file `resource_loader_code_cache_test.cc`. Specifically, it wants to know how it relates to JavaScript, HTML, and CSS, any logical inferences made, common user errors, and debugging clues.

2. **Identify the Core Subject:** The file name itself strongly suggests the focus is on testing the "code cache" functionality within the resource loading process. "resource_loader" and "code_cache" are key terms.

3. **Examine Includes:** The `#include` directives provide valuable clues about the components being tested:
    * `testing/gtest/include/gtest/gtest.h`: This confirms it's a unit test file using the Google Test framework.
    * `third_party/blink/public/mojom/loader/code_cache.mojom-blink.h`: This indicates interaction with a code cache interface defined using Mojo (Chromium's IPC system).
    * `third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h`:  This signifies interaction with the V8 JavaScript engine (Blink's JavaScript engine) specifically for testing purposes.
    *  Various `third_party/blink/renderer/core/loader/...` and `third_party/blink/renderer/platform/loader/fetch/...` headers point to the core loading and fetching mechanisms, including scripts and cached metadata.

4. **Analyze Test Fixture and Helper Classes:**
    * `CodeCacheTestLoaderFactory`: This custom factory likely overrides the default resource loader creation to provide a simplified or mock loader (`NoopURLLoader`). This suggests the tests focus on the caching logic, not the full network loading process.
    * `ResourceLoaderCodeCacheTest`: This is the main test fixture. The `CommonSetup` method initializes the necessary components for testing, including a `ScriptResource`, `ResourceLoader`, and a mock fetch context.

5. **Deconstruct Individual Tests:** Go through each `TEST_F` function and understand its purpose:
    * `WebUICodeCacheEmptyCachedMetadataInfo`: Tests the case where no code cache data is present in the response.
    * `WebUICodeCacheFullResponse`: Tests successful handling of code cache data in the response.
    * `CodeCacheFullHttpsScheme`: Checks if code caching works for HTTPS resources.
    * `CodeCacheFullHttpsSchemeWithResponseFlag`: Verifies that a flag in the response can trigger code cache usage (specifically with source hashing).
    * `WebUICodeCacheInvalidOuterType`: Tests the scenario where the code cache metadata has an invalid format.
    * `WebUICodeCacheHashCheckSuccess`: Tests successful verification of code cache data using a source code hash.
    * `WebUICodeCacheHashCheckFailure`: Tests the failure case when the source code hash doesn't match the cached data.
    * `WebUICodeCachePlatformOverride`:  Examines how a platform-level setting can enable or disable code caching with hashing.
    * `MockTestingPlatformForCodeCache`: This custom class demonstrates how platform-specific behavior can be mocked for testing.

6. **Identify Relationships to Web Technologies:**
    * **JavaScript:** The presence of `ScriptResource`, interaction with V8, and tests involving source code hashing directly link this to JavaScript code caching. The tests verify that pre-compiled or cached versions of JavaScript code can be stored and retrieved.
    * **HTML:**  While not directly mentioned in the test file's *code*, the process of loading scripts is integral to rendering HTML pages. The cached scripts are fetched and executed when a browser parses an HTML document containing `<script>` tags.
    * **CSS:** Although this specific test file doesn't explicitly handle CSS, the underlying resource loading mechanisms are shared. Similar caching techniques might be applied to CSS resources as well, but this file is focused on *script* code caching.

7. **Logical Inferences and Assumptions:**
    * **Assumption:** The tests assume a simplified network environment thanks to `NoopURLLoader`. The focus is on the code cache logic within Blink, not the complexities of actual network requests.
    * **Inference:** The presence of hash checking suggests a mechanism to ensure the cached code is still valid and corresponds to the current version of the script. This prevents using outdated or corrupted cached data.

8. **Common User/Programming Errors:**  Think about what could go wrong in a real-world scenario based on the tested functionalities:
    * **Mismatched Source Code:**  If a website updates its JavaScript code but the browser uses an old, cached version, this can lead to errors. The hash checking mechanism is designed to mitigate this.
    * **Corrupted Cache Data:** If the cached data on disk is corrupted, the browser might fail to load or execute the script.
    * **Incorrect Cache Configuration:**  If caching headers or settings are misconfigured on the server or in the browser, it can lead to unexpected caching behavior.

9. **Debugging Clues:**  How would a developer use this test file for debugging?
    * **Verifying Caching Logic:**  If there are issues with script loading performance, developers could examine the code cache behavior. Breakpoints in this test file could help understand if the cache is being populated and retrieved correctly.
    * **Understanding Hash Mismatches:** If the browser reports errors related to cached scripts, this test file demonstrates how hash checking works, providing a starting point for investigating why a mismatch might occur.

10. **Structure the Response:** Organize the findings into logical categories as requested by the prompt (functionality, relation to web technologies, logical inferences, user errors, debugging clues). Provide concrete examples where possible.

By following these steps, I can thoroughly analyze the provided code and generate a comprehensive answer that addresses all aspects of the request.
这个文件 `blink/renderer/core/loader/resource/resource_loader_code_cache_test.cc` 是 Chromium Blink 引擎中的一个**单元测试文件**，专门用于测试 `ResourceLoader` 组件中关于**代码缓存 (Code Cache)** 功能的实现。

以下是它的功能和相关说明：

**功能概述:**

该测试文件的主要目的是验证 `ResourceLoader` 在处理资源加载时，如何与代码缓存进行交互，包括：

* **接收并存储代码缓存数据:** 测试当从网络接收到包含代码缓存的响应时，`ResourceLoader` 是否能够正确解析和存储这些数据。
* **校验代码缓存数据的完整性:** 测试是否能够通过哈希等方式验证代码缓存的有效性，防止使用错误的缓存数据。
* **在不同场景下启用/禁用代码缓存:** 测试在不同的网络协议（如 HTTPS）或配置下，代码缓存是否按预期工作。
* **平台级别的代码缓存控制:** 测试平台层面对代码缓存行为的干预（例如，强制启用或禁用）。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件主要与 **JavaScript** 的功能关系最为密切。代码缓存的主要目标是加速 JavaScript 代码的加载和执行。

* **JavaScript:**
    * 当浏览器加载一个 JavaScript 文件时，V8 引擎（Blink 的 JavaScript 引擎）会对代码进行解析和编译。这个编译后的代码可以被缓存起来，下次加载相同的脚本时可以直接使用，从而节省解析和编译的时间。这就是代码缓存的核心功能。
    * 该测试文件模拟了 `ResourceLoader` 接收到带有 JavaScript 代码缓存的响应，并验证是否正确存储和校验这些缓存数据。
    * 例如，测试用例 `WebUICodeCacheHashCheckSuccess` 和 `WebUICodeCacheHashCheckFailure` 就模拟了使用源代码哈希来验证缓存的 JavaScript 代码是否与当前代码一致。

* **HTML:**
    * HTML 文件中通过 `<script>` 标签引用 JavaScript 文件。当浏览器解析 HTML 时，会触发对 JavaScript 文件的加载。`ResourceLoader` 负责执行这个加载过程，包括处理代码缓存。
    * 虽然测试文件本身不直接操作 HTML，但它测试的是 HTML 加载 JavaScript 资源时的关键环节：代码缓存。

* **CSS:**
    * 虽然代码缓存的主要目标是 JavaScript，但类似的缓存机制也可能应用于 CSS 资源（例如，样式表的解析结果）。然而，从这个测试文件的内容来看，它的重点是 **JavaScript 代码缓存**。测试中使用的 `ScriptResource` 类也明确指向 JavaScript 资源。

**逻辑推理 (假设输入与输出):**

以下是一些测试用例的逻辑推理示例：

* **假设输入 (WebUICodeCacheFullResponse):**
    * `ResourceLoader` 接收到一个 HTTP 响应，其中包含一个带有代码缓存数据的 `mojo_base::BigBuffer`。
    * 代码缓存数据的格式是预定义的，包含一个头部 (`CachedMetadataHeader`) 和实际的缓存数据。
* **预期输出:**
    * `resource_->CodeCacheSize()` 应该返回缓存数据的大小，包括头部。这表明代码缓存数据被成功接收和记录。

* **假设输入 (WebUICodeCacheHashCheckSuccess):**
    * `ResourceLoader` 接收到一个 HTTP 响应，其中包含带有哈希值的代码缓存数据。
    * 提供了原始的 JavaScript 源代码 `source_text`。
* **预期输出:**
    * `resource_->CodeCacheSize()` 应该大于 0，表示接收到了缓存数据。
    * `resource_->CacheHandler()->Check(loader_factory_->GetCodeCacheHost(), ParkableString(source_text.Impl()))` 应该成功执行，因为提供的源代码与缓存中的哈希匹配。
    * `resource_->CacheHandler()->GetCachedMetadata(0)` 应该返回一个非空的 `CachedMetadata` 对象，表明缓存数据可以被访问。

* **假设输入 (WebUICodeCacheHashCheckFailure):**
    * `ResourceLoader` 接收到一个 HTTP 响应，其中包含带有哈希值的代码缓存数据。
    * 提供了一个与缓存数据不匹配的 JavaScript 源代码 `source_text_2`。
* **预期输出:**
    * `resource_->CodeCacheSize()` 应该大于 0，表示接收到了缓存数据。
    * `resource_->CacheHandler()->Check(loader_factory_->GetCodeCacheHost(), ParkableString(source_text_2.Impl()))` 执行后，缓存数据应该被清除或标记为无效。
    * `resource_->CodeCacheSize()` 应该变为 0。
    * `resource_->CacheHandler()->GetCachedMetadata(0)` 应该返回空，表明缓存数据不可用。

**用户或编程常见的使用错误:**

虽然这个测试文件是针对 Blink 引擎内部的，但它可以帮助开发者理解与代码缓存相关的潜在问题：

* **服务器配置错误:**  如果服务器没有正确配置缓存相关的 HTTP 头信息（例如 `Cache-Control`），可能会导致浏览器无法正确缓存或验证代码。
* **代码更新后缓存未失效:** 当网站更新了 JavaScript 代码，但浏览器仍然使用了旧的缓存，可能导致功能异常。哈希校验机制就是为了解决这个问题，但如果服务器没有正确设置缓存策略，可能会导致哈希校验失败。
* **本地缓存损坏:**  用户的浏览器本地缓存可能损坏，导致代码缓存数据不可用或错误。
* **浏览器或扩展的缓存策略干扰:** 一些浏览器设置或扩展程序可能会干扰正常的缓存行为。
* **编程错误导致缓存数据不一致:**  在 Blink 引擎的开发过程中，如果代码缓存的生成或校验逻辑有错误，会导致缓存数据不一致的问题。这个测试文件就是用来预防和检测这类错误的。

**用户操作如何一步步到达这里，作为调试线索:**

假设用户遇到了一个与 JavaScript 执行相关的问题，例如页面功能异常或加载缓慢，并且怀疑与代码缓存有关。以下是一些可能的调试步骤，最终可能引导开发者查看这个测试文件：

1. **用户报告问题:** 用户反馈网站功能不正常或加载很慢。
2. **开发者初步排查:** 开发者检查网络请求，发现 JavaScript 资源的加载可能存在问题。他们可能会查看浏览器的开发者工具中的 "Network" 面板。
3. **怀疑缓存问题:**  如果开发者看到 JavaScript 资源使用了缓存 (from cache 或 304 Not Modified)，但页面行为不正常，他们可能会怀疑是缓存导致了问题。
4. **清除缓存尝试:** 开发者可能会建议用户清除浏览器缓存，看是否能解决问题。如果清除缓存后问题消失，则更可能与缓存有关。
5. **深入 Blink 引擎代码:**  如果问题仍然存在，或者开发者需要理解 Blink 引擎内部的缓存机制，他们可能会查看 Blink 引擎的源代码，特别是与资源加载和缓存相关的部分。
6. **定位到代码缓存相关代码:** 开发者可能会搜索 "code cache" 或相关的类名（如 `ResourceLoader`, `ScriptResource`, `CachedMetadataHandler`）来找到相关的源代码文件。
7. **查看测试文件:** 开发者可能会查看 `resource_loader_code_cache_test.cc` 这样的测试文件，以了解代码缓存功能的设计和预期行为。测试用例可以提供关于代码如何工作的具体示例。
8. **分析测试用例:** 开发者可以通过阅读测试用例，了解 Blink 引擎是如何处理各种代码缓存场景的，例如：
    * 如何接收和存储缓存数据。
    * 如何进行哈希校验。
    * 在哪些情况下会使用缓存。
    * 平台层面如何控制缓存行为。
9. **使用测试文件进行本地调试:**  开发者甚至可以修改或运行这些测试用例，来模拟用户遇到的问题场景，并观察 Blink 引擎的内部行为。这可以帮助他们定位问题是出在缓存的读取、写入还是校验环节。

总之，`resource_loader_code_cache_test.cc` 是一个关键的测试文件，用于确保 Blink 引擎的代码缓存功能按预期工作，从而提高 JavaScript 代码的加载性能和用户体验。它可以作为开发者理解代码缓存机制和排查相关问题的宝贵资源。

Prompt: 
```
这是目录为blink/renderer/core/loader/resource/resource_loader_code_cache_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "base/task/single_thread_task_runner.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/loader/code_cache.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/loader/resource/script_resource.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_response.h"
#include "third_party/blink/renderer/platform/loader/fetch/cached_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/code_cache_host.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader.h"
#include "third_party/blink/renderer/platform/loader/fetch/script_cached_metadata_handler.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/cached_metadata_handler.h"
#include "third_party/blink/renderer/platform/loader/testing/mock_fetch_context.h"
#include "third_party/blink/renderer/platform/loader/testing/test_resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_task_runner.h"
#include "third_party/blink/renderer/platform/testing/mock_context_lifecycle_notifier.h"
#include "third_party/blink/renderer/platform/testing/noop_url_loader.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support_with_mock_scheduler.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"

namespace blink {
namespace {

class CodeCacheTestLoaderFactory : public ResourceFetcher::LoaderFactory {
 public:
  CodeCacheTestLoaderFactory() = default;
  ~CodeCacheTestLoaderFactory() override = default;

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

class ResourceLoaderCodeCacheTest : public testing::Test {
 protected:
  static scoped_refptr<base::SingleThreadTaskRunner> CreateTaskRunner() {
    return base::MakeRefCounted<scheduler::FakeTaskRunner>();
  }

  ResourceFetcher* MakeResourceFetcher(
      TestResourceFetcherProperties* properties,
      FetchContext* context,
      ResourceFetcher::LoaderFactory* loader_factory) {
    return MakeGarbageCollected<ResourceFetcher>(ResourceFetcherInit(
        properties->MakeDetachable(), context, CreateTaskRunner(),
        CreateTaskRunner(), loader_factory,
        MakeGarbageCollected<MockContextLifecycleNotifier>(),
        /*back_forward_cache_loader_helper=*/nullptr));
  }

  void CommonSetup(v8::Isolate* isolate, const char* url_string = nullptr) {
#if DCHECK_IS_ON()
    WTF::SetIsBeforeThreadCreatedForTest();  // Required for next operation:
#endif
    SchemeRegistry::RegisterURLSchemeAsCodeCacheWithHashing(
        "codecachewithhashing");

    auto* properties = MakeGarbageCollected<TestResourceFetcherProperties>();
    FetchContext* context = MakeGarbageCollected<MockFetchContext>();
    loader_factory_ = MakeGarbageCollected<CodeCacheTestLoaderFactory>();
    auto* fetcher = MakeResourceFetcher(properties, context, loader_factory_);

    KURL url(url_string ? url_string
                        : "codecachewithhashing://www.example.com/");
    ResourceRequest request(url);
    request.SetRequestContext(mojom::blink::RequestContextType::SCRIPT);

    FetchParameters params = FetchParameters::CreateForTest(std::move(request));
    constexpr v8_compile_hints::V8CrowdsourcedCompileHintsProducer*
        kNoCompileHintsProducer = nullptr;
    constexpr v8_compile_hints::V8CrowdsourcedCompileHintsConsumer*
        kNoCompileHintsConsumer = nullptr;
    resource_ = ScriptResource::Fetch(
        params, fetcher, nullptr, isolate, ScriptResource::kNoStreaming,
        kNoCompileHintsProducer, kNoCompileHintsConsumer,
        v8_compile_hints::MagicCommentMode::kNever);
    loader_ = resource_->Loader();

    response_ = ResourceResponse(url);
    response_.SetHttpStatusCode(200);
    response_.SetResponseTime(base::Time::Now());
  }

  static const size_t kSha256Bytes = 256 / 8;

  std::vector<uint8_t> MakeSerializedCodeCacheData(base::span<uint8_t> data) {
    const size_t kSerializedDataSize =
        sizeof(CachedMetadataHeader) + data.size();
    std::vector<uint8_t> serialized_data(kSerializedDataSize);
    CachedMetadataHeader* header =
        reinterpret_cast<CachedMetadataHeader*>(&serialized_data[0]);
    header->marker = CachedMetadataHandler::kSingleEntryWithTag;
    header->type = 0;
    memcpy(&serialized_data[sizeof(CachedMetadataHeader)], data.data(),
           data.size());
    return serialized_data;
  }

  std::vector<uint8_t> MakeSerializedCodeCacheDataWithHash(
      base::span<uint8_t> data,
      std::optional<String> source_text = {}) {
    const size_t kSerializedDataSize = sizeof(CachedMetadataHeaderWithHash) +
                                       sizeof(CachedMetadataHeader) +
                                       data.size();
    std::vector<uint8_t> serialized_data(kSerializedDataSize);
    CachedMetadataHeaderWithHash* outer_header =
        reinterpret_cast<CachedMetadataHeaderWithHash*>(&serialized_data[0]);
    outer_header->marker =
        CachedMetadataHandler::kSingleEntryWithHashAndPadding;
    if (source_text.has_value()) {
      std::unique_ptr<ParkableStringImpl::SecureDigest> hash =
          ParkableStringImpl::HashString(source_text->Impl());
      CHECK_EQ(hash->size(), kSha256Bytes);
      memcpy(outer_header->hash, hash->data(), kSha256Bytes);
    }
    CachedMetadataHeader* inner_header =
        reinterpret_cast<CachedMetadataHeader*>(
            &serialized_data[sizeof(CachedMetadataHeaderWithHash)]);
    inner_header->marker = CachedMetadataHandler::kSingleEntryWithTag;
    inner_header->type = 0;
    memcpy(&serialized_data[sizeof(CachedMetadataHeaderWithHash) +
                            sizeof(CachedMetadataHeader)],
           data.data(), data.size());
    return serialized_data;
  }

  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform_;

  // State initialized by CommonSetup().
  Persistent<ScriptResource> resource_;
  Persistent<ResourceLoader> loader_;
  Persistent<CodeCacheTestLoaderFactory> loader_factory_;
  ResourceResponse response_;
};

TEST_F(ResourceLoaderCodeCacheTest, WebUICodeCacheEmptyCachedMetadataInfo) {
  V8TestingScope scope;
  CommonSetup(scope.GetIsolate());

  loader_->DidReceiveResponse(WrappedResourceResponse(response_),
                              /*body=*/mojo::ScopedDataPipeConsumerHandle(),
                              /*cached_metadata=*/std::nullopt);

  // No code cache data was present.
  EXPECT_FALSE(resource_->CodeCacheSize());
}

TEST_F(ResourceLoaderCodeCacheTest, WebUICodeCacheFullResponse) {
  V8TestingScope scope;
  CommonSetup(scope.GetIsolate());

  std::vector<uint8_t> cache_data{2, 3, 4, 5, 6};
  loader_->DidReceiveResponse(
      WrappedResourceResponse(response_),
      /*body=*/mojo::ScopedDataPipeConsumerHandle(),
      mojo_base::BigBuffer(MakeSerializedCodeCacheDataWithHash(cache_data)));

  // Code cache data was present.
  EXPECT_EQ(cache_data.size() + sizeof(CachedMetadataHeader),
            resource_->CodeCacheSize());
}

TEST_F(ResourceLoaderCodeCacheTest, CodeCacheFullHttpsScheme) {
  V8TestingScope scope;
  CommonSetup(scope.GetIsolate(), "https://www.example.com/");

  std::vector<uint8_t> cache_data{2, 3, 4, 5, 6};
  loader_->DidReceiveResponse(
      WrappedResourceResponse(response_),
      /*body=*/mojo::ScopedDataPipeConsumerHandle(),
      mojo_base::BigBuffer(MakeSerializedCodeCacheData(cache_data)));

  // Code cache data was present.
  EXPECT_EQ(cache_data.size() + sizeof(CachedMetadataHeader),
            resource_->CodeCacheSize());
}

TEST_F(ResourceLoaderCodeCacheTest, CodeCacheFullHttpsSchemeWithResponseFlag) {
  V8TestingScope scope;
  CommonSetup(scope.GetIsolate(), "https://www.example.com/");

  std::vector<uint8_t> cache_data{2, 3, 4, 5, 6};

  // Nothing has changed yet because the content response hasn't arrived yet.
  EXPECT_FALSE(resource_->CodeCacheSize());

  response_.SetShouldUseSourceHashForJSCodeCache(true);
  loader_->DidReceiveResponse(
      WrappedResourceResponse(response_),
      /*body=*/mojo::ScopedDataPipeConsumerHandle(),
      mojo_base::BigBuffer(MakeSerializedCodeCacheDataWithHash(cache_data)));

  // Code cache data was present.
  EXPECT_EQ(resource_->CodeCacheSize(),
            cache_data.size() + sizeof(CachedMetadataHeader));
}

TEST_F(ResourceLoaderCodeCacheTest, WebUICodeCacheInvalidOuterType) {
  V8TestingScope scope;
  CommonSetup(scope.GetIsolate());

  std::vector<uint8_t> cache_data{2, 3, 4, 5, 6};
  loader_->DidReceiveResponse(
      WrappedResourceResponse(response_),
      /*body=*/mojo::ScopedDataPipeConsumerHandle(),
      mojo_base::BigBuffer(MakeSerializedCodeCacheData(cache_data)));

  // The serialized metadata was rejected due to an invalid outer type.
  EXPECT_FALSE(resource_->CodeCacheSize());
}

TEST_F(ResourceLoaderCodeCacheTest, WebUICodeCacheHashCheckSuccess) {
  V8TestingScope scope;
  CommonSetup(scope.GetIsolate());

  std::vector<uint8_t> cache_data{2, 3, 4, 5, 6};
  String source_text("alert('hello world');");

  loader_->DidReceiveResponse(
      WrappedResourceResponse(response_),
      /*body=*/mojo::ScopedDataPipeConsumerHandle(),
      mojo_base::BigBuffer(
          MakeSerializedCodeCacheDataWithHash(cache_data, source_text)));

  // Code cache data was present.
  EXPECT_EQ(cache_data.size() + sizeof(CachedMetadataHeader),
            resource_->CodeCacheSize());

  // Successful check.
  resource_->CacheHandler()->Check(loader_factory_->GetCodeCacheHost(),
                                   ParkableString(source_text.Impl()));

  // Now the metadata can be accessed.
  scoped_refptr<CachedMetadata> cached_metadata =
      resource_->CacheHandler()->GetCachedMetadata(0);
  EXPECT_TRUE(cached_metadata.get());
  base::span<const uint8_t> metadata = cached_metadata->Data();
  EXPECT_EQ(metadata.size(), cache_data.size());
  EXPECT_EQ(metadata[2], cache_data[2]);

  // But trying to load the metadata with the wrong data_type_id fails.
  EXPECT_FALSE(resource_->CacheHandler()->GetCachedMetadata(4));
}

TEST_F(ResourceLoaderCodeCacheTest, WebUICodeCacheHashCheckFailure) {
  V8TestingScope scope;
  CommonSetup(scope.GetIsolate());

  std::vector<uint8_t> cache_data{2, 3, 4, 5, 6};
  String source_text("alert('hello world');");
  loader_->DidReceiveResponse(
      WrappedResourceResponse(response_),
      /*body=*/mojo::ScopedDataPipeConsumerHandle(),
      mojo_base::BigBuffer(
          MakeSerializedCodeCacheDataWithHash(cache_data, source_text)));

  // Code cache data was present.
  EXPECT_EQ(cache_data.size() + sizeof(CachedMetadataHeader),
            resource_->CodeCacheSize());

  // Failed check: source text is different.
  String source_text_2("alert('improved program');");
  resource_->CacheHandler()->Check(loader_factory_->GetCodeCacheHost(),
                                   ParkableString(source_text_2.Impl()));

  // The metadata has been cleared.
  EXPECT_FALSE(resource_->CodeCacheSize());
  EXPECT_FALSE(resource_->CacheHandler()->GetCachedMetadata(0));
}

class MockTestingPlatformForCodeCache : public TestingPlatformSupport {
 public:
  MockTestingPlatformForCodeCache() = default;
  ~MockTestingPlatformForCodeCache() override = default;

  // TestingPlatformSupport:
  bool ShouldUseCodeCacheWithHashing(const WebURL& request_url) const override {
    return should_use_code_cache_with_hashing_;
  }

  void set_should_use_code_cache_with_hashing(
      bool should_use_code_cache_with_hashing) {
    should_use_code_cache_with_hashing_ = should_use_code_cache_with_hashing;
  }

 private:
  bool should_use_code_cache_with_hashing_ = true;
};

TEST_F(ResourceLoaderCodeCacheTest, WebUICodeCachePlatformOverride) {
  ScopedTestingPlatformSupport<MockTestingPlatformForCodeCache> platform;
  std::vector<uint8_t> cache_data{2, 3, 4, 5, 6};

  {
    platform->set_should_use_code_cache_with_hashing(true);
    V8TestingScope scope;
    CommonSetup(scope.GetIsolate());
    loader_->DidReceiveResponse(
        WrappedResourceResponse(response_),
        /*body=*/mojo::ScopedDataPipeConsumerHandle(),
        mojo_base::BigBuffer(MakeSerializedCodeCacheDataWithHash(cache_data)));

    // Code cache data was present.
    EXPECT_EQ(resource_->CodeCacheSize(),
              cache_data.size() + sizeof(CachedMetadataHeader));
  }

  {
    platform->set_should_use_code_cache_with_hashing(false);
    V8TestingScope scope;
    CommonSetup(scope.GetIsolate());
    loader_->DidReceiveResponse(
        WrappedResourceResponse(response_),
        /*body=*/mojo::ScopedDataPipeConsumerHandle(),
        mojo_base::BigBuffer(MakeSerializedCodeCacheDataWithHash(cache_data)));

    // Code cache data was absent.
    EXPECT_FALSE(resource_->CodeCacheSize());
    EXPECT_FALSE(resource_->CacheHandler());
  }
}

}  // namespace
}  // namespace blink

"""

```