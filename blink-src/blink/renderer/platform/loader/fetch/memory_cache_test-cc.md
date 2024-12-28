Response:
Let's break down the thought process for analyzing this C++ test file for the Blink rendering engine.

**1. Understanding the Goal:**

The core request is to understand what `memory_cache_test.cc` does. Specifically, the prompt asks about its functionality, its relationship to web technologies (JavaScript, HTML, CSS), logical reasoning (input/output examples), and potential user/programming errors.

**2. Initial File Scan (Keywords and Structure):**

My first step is a quick scan of the file for important keywords and structural elements. I look for:

* **Includes:**  What other files are being used? This gives clues about dependencies and the modules being tested. I see includes like `memory_cache.h`, `gtest/gtest.h`, `resource.h`, `resource_fetcher.h`, etc. These immediately suggest the file is testing the `MemoryCache` class and related resource loading mechanisms.
* **Namespaces:**  The code is within the `blink` namespace, which confirms it's part of the Blink rendering engine.
* **Classes:**  The presence of `MemoryCacheTest` inheriting from `testing::Test` indicates this is a unit test file using the Google Test framework. The other custom classes (`FakeDecodedResource`, `FakeResource`) are likely mock or stub implementations used for testing.
* **`TEST_F` Macros:** These are the core test cases in Google Test. I'd quickly scan the names of these tests (e.g., `VeryLargeResourceAccounting`, `ClientRemoval_Basic`, `ResourceMapIsolation`, etc.) to get a high-level understanding of what's being tested.
* **Assertions (e.g., `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`):** These are the verification points within the tests. They show what conditions are being checked.
* **Comments:**  While this file has fewer explanatory comments within the tests, I'd still look for any comments that provide context or explain specific test logic.

**3. Focusing on the `MemoryCache` Class:**

The filename and the `#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"` are strong indicators that the primary focus is testing the `MemoryCache` class.

**4. Analyzing Individual Test Cases:**

Now, I'd go through the `TEST_F` functions one by one, trying to understand the purpose of each:

* **`VeryLargeResourceAccounting`:** This test name suggests it's about handling very large resources in the cache. The code manipulates `kSizeMax` and checks the `MemoryCache::Get()->size()`. This hints at testing memory accounting for large resources.
* **`ClientRemoval_*`:** These tests clearly focus on what happens when resource clients are removed. The use of `MockResourceClient` and assertions about the cache size and contents confirm this. The variations (`_Basic`, `_MultipleResourceMaps`) indicate testing different scenarios of client removal.
* **`RemoveDuringRevalidation`:** This test name points to testing the cache behavior during revalidation of cached resources. The sequence of adding and removing resources suggests this.
* **`ResourceMapIsolation`:** This test uses `SetCacheIdentifier` and checks if resources with different identifiers are treated separately. This verifies the isolation of resources within the cache based on identifiers.
* **`FragmentIdentifier`:** The test manipulates URLs with fragment identifiers (#) and checks if the cache can retrieve resources correctly even with fragments. This relates to how URLs with fragments are treated for caching.
* **`RemoveURLFromCache`:** This is straightforward – testing the ability to explicitly remove a resource from the cache by its URL.
* **`MemoryCacheStrongReferenceTest` (with `kMemoryCacheStrongReference` feature):** The setup enables a specific feature, and the tests (`ResourceTimeout`, `LRU`, `ClearStrongReferences`) focus on a "strong reference" mechanism within the cache, likely related to preventing premature eviction of important resources. The LRU test specifically points to a Least Recently Used eviction strategy.

**5. Connecting to Web Technologies (JavaScript, HTML, CSS):**

This requires thinking about how the memory cache fits into the web browser's functionality.

* **HTML:**  When an HTML parser encounters `<img src="...">`, `<link rel="stylesheet" href="...">`, or `<script src="...">`, these initiate resource fetches. The `MemoryCache` is a key component in storing these fetched resources (images, CSS files, JavaScript files) to avoid redundant downloads. The tests involving URL manipulation and resource types are directly relevant to caching these HTML-referenced resources.
* **CSS:**  CSS files fetched via `<link>` tags are prime candidates for caching. The tests don't explicitly mention CSS, but the underlying caching mechanisms are the same as for other resources.
* **JavaScript:**  JavaScript files loaded via `<script>` tags are also cached. The tests with different URLs and identifiers would apply to JavaScript files as well.

**6. Logical Reasoning (Input/Output Examples):**

For tests like `ClientRemoval`, I can create a mental model:

* **Input:** Add two resources to the cache with clients. Remove one client. Trigger garbage collection.
* **Output:** The resource with the remaining client should still be in the cache. The other should be gone.

For `ResourceMapIsolation`:

* **Input:** Add two resources with the same URL but different cache identifiers.
* **Output:** The cache should treat them as distinct entries. Retrieving by URL and identifier should yield the correct resource.

**7. Identifying User/Programming Errors:**

This requires thinking about common mistakes developers might make related to caching:

* **Incorrect Cache Headers:**  While not directly tested here, the memory cache respects HTTP cache headers. A common error is setting incorrect headers on the server, leading to either excessive caching or no caching at all. I can relate this to the *purpose* of the `MemoryCache` – to optimize resource loading based on these headers.
* **Unexpected Cache Behavior:** Developers might assume resources are cached in a certain way and be surprised when they aren't (e.g., expecting something to be cached when it's not due to a `Cache-Control: no-cache` header). The tests verifying the basic functionality of adding, removing, and retrieving resources help ensure the cache behaves predictably.
* **Memory Leaks (indirectly):** Although not a direct *user* error, the tests that ensure resources are removed from the cache upon client removal or garbage collection are essential for preventing memory leaks within the browser.

**8. Structuring the Answer:**

Finally, I'd organize the information into the requested categories: functionality, relation to web technologies, logical reasoning, and user errors, providing concrete examples from the code where possible. I would also emphasize that this is a *test* file and not the actual implementation of the memory cache. Its purpose is to verify the correctness of the `MemoryCache` class.
这个文件 `memory_cache_test.cc` 是 Chromium Blink 引擎中 `MemoryCache` 类的单元测试文件。它的主要功能是 **验证 `MemoryCache` 类的各项功能是否正常工作**。

以下是它具体的功能及其与 JavaScript, HTML, CSS 的关系，逻辑推理的例子，以及涉及的常见错误：

**1. 功能列举:**

* **测试资源添加和移除:**  验证向 `MemoryCache` 添加和移除资源的功能是否正常，包括不同类型的资源。
* **测试资源大小计算:**  测试 `MemoryCache` 能否正确追踪和计算缓存中资源的大小，即使是很大的资源。
* **测试客户端移除对缓存的影响:**  验证当资源不再被任何客户端引用时，缓存是否能够正确地将其移除，并更新缓存大小。
* **测试在资源重新验证期间的移除:**  验证在资源重新验证的过程中，移除资源是否能正确执行。
* **测试资源映射隔离:**  验证具有相同 URL 但不同缓存标识符的资源是否被独立存储和检索。
* **测试带片段标识符的 URL 处理:**  验证对于带有片段标识符 (#) 的 URL，缓存是否能正确处理和查找资源。
* **测试通过 URL 移除资源:**  验证能否通过 URL 从缓存中移除资源。
* **测试强引用机制 (如果启用):**  测试 `MemoryCache` 中用于防止某些资源过早被回收的强引用机制，包括超时机制和 LRU (Least Recently Used) 策略。

**2. 与 JavaScript, HTML, CSS 的关系 (举例说明):**

`MemoryCache` 在浏览器中扮演着至关重要的角色，它存储着从网络加载的各种资源，包括 JavaScript 文件、HTML 文件、CSS 文件、图片等。这直接影响到网页的加载速度和用户体验。

* **HTML:** 当浏览器解析 HTML 页面时，如果遇到 `<img>`, `<link>`, `<script>` 等标签，它会尝试从 `MemoryCache` 中查找对应的资源。
    * **假设输入:** HTML 文件包含 `<img src="image.png">`， 且 `image.png` 已经加载并存储在 `MemoryCache` 中。
    * **输出:** 浏览器会直接从 `MemoryCache` 中加载 `image.png`，而不需要再次发起网络请求，从而加快页面渲染速度。
* **CSS:**  CSS 文件通过 `<link>` 标签引入，浏览器会将其缓存以便后续页面重复使用。
    * **假设输入:**  页面 A 和页面 B 都引用了相同的 CSS 文件 `style.css`，且 `style.css` 已被页面 A 加载并缓存。
    * **输出:** 当加载页面 B 时，浏览器会直接从 `MemoryCache` 中获取 `style.css`，避免重复下载。
* **JavaScript:** JavaScript 文件通过 `<script>` 标签引入，同样会被缓存。
    * **假设输入:**  JavaScript 文件 `script.js` 被多个页面引用并已缓存。
    * **输出:**  后续访问这些页面时，`script.js` 将从 `MemoryCache` 中加载，提升脚本执行效率。

**3. 逻辑推理 (假设输入与输出):**

* **测试客户端移除:**
    * **假设输入:**  一个图像资源 "image.jpg" 被添加到 `MemoryCache`，并且有两个 `MockResourceClient` 对象（模拟 HTML 页面或 JavaScript 代码）正在使用这个资源。
    * **操作:**  移除其中一个 `MockResourceClient` 对该资源的引用。
    * **输出:**  `MemoryCache` 仍然持有 "image.jpg"，因为还有另一个客户端正在使用它。缓存的大小保持不变（假设资源数据仍在）。只有当所有客户端的引用都被移除，并且发生垃圾回收时，资源才会被真正从 `MemoryCache` 中移除。

* **测试资源映射隔离:**
    * **假设输入:**  两个 `FakeResource` 对象，它们的 URL 都是 "http://test/resource"，但其中一个设置了缓存标识符 "foo"。
    * **操作:**  将这两个资源添加到 `MemoryCache`。
    * **输出:**  `MemoryCache` 会将这两个资源视为不同的条目。通过 `ResourceForURLForTesting` 获取时，不带标识符的调用会返回没有标识符的资源，而带标识符 "foo" 的调用会返回对应的资源。

**4. 涉及用户或编程常见的使用错误 (举例说明):**

虽然这个测试文件是针对 `MemoryCache` 内部逻辑的，但它所测试的功能与开发者在使用 Web 技术时可能遇到的问题息息相关。

* **浏览器缓存行为不符合预期:** 开发者可能会错误地认为某个资源会被缓存，或者缓存的时间会更长，导致用户每次访问页面都需要重新下载资源。这通常与 HTTP 响应头中的缓存控制策略 (如 `Cache-Control`, `Expires`) 设置不当有关。 `MemoryCache` 的正确性保证了在遵循这些缓存策略的前提下，资源能被有效存储和检索。

* **资源重复加载导致性能问题:**  如果 `MemoryCache` 工作不正常，即使资源没有过期，浏览器也可能无法从缓存中加载，而是发起新的网络请求，导致页面加载速度变慢，浪费带宽。 这个测试文件确保了 `MemoryCache` 能够正确地识别和提供已缓存的资源，避免不必要的重复加载。

* **内存泄漏 (间接相关):**  虽然 `MemoryCache` 有自己的内存管理机制，但如果客户端对象没有正确释放对缓存资源的引用，可能会导致资源一直占用内存，无法被垃圾回收。 `MemoryCacheTest` 中测试客户端移除的功能，有助于确保在这种情况下，缓存能够最终释放不再使用的资源。

总而言之，`memory_cache_test.cc` 是一个基础但关键的测试文件，它确保了 Chromium Blink 引擎的资源缓存机制能够正确有效地工作，这对于提供快速、流畅的网页浏览体验至关重要。它验证了 `MemoryCache` 的核心功能，这些功能直接支撑着浏览器对 JavaScript, HTML, CSS 等资源的加载和管理。

Prompt: 
```
这是目录为blink/renderer/platform/loader/fetch/memory_cache_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (c) 2013, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"

#include <string_view>

#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/loader/fetch/raw_resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/testing/mock_fetch_context.h"
#include "third_party/blink/renderer/platform/loader/testing/mock_resource_client.h"
#include "third_party/blink/renderer/platform/loader/testing/test_loader_factory.h"
#include "third_party/blink/renderer/platform/loader/testing/test_resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/testing/mock_context_lifecycle_notifier.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support_with_mock_scheduler.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"

namespace blink {

class FakeDecodedResource final : public Resource {
 public:
  static FakeDecodedResource* Fetch(FetchParameters& params,
                                    ResourceFetcher* fetcher,
                                    ResourceClient* client) {
    return static_cast<FakeDecodedResource*>(
        fetcher->RequestResource(params, Factory(), client));
  }

  FakeDecodedResource(const ResourceRequest& request,
                      const ResourceLoaderOptions& options)
      : Resource(request, ResourceType::kMock, options) {}

  void AppendData(
      absl::variant<SegmentedBuffer, base::span<const char>> data) override {
    Resource::AppendData(std::move(data));
    SetDecodedSize(this->size());
  }

  void FakeEncodedSize(size_t size) { SetEncodedSize(size); }

 private:
  class Factory final : public NonTextResourceFactory {
   public:
    Factory() : NonTextResourceFactory(ResourceType::kMock) {}

    Resource* Create(const ResourceRequest& request,
                     const ResourceLoaderOptions& options) const override {
      return MakeGarbageCollected<FakeDecodedResource>(request, options);
    }
  };

  void DestroyDecodedDataIfPossible() override { SetDecodedSize(0); }
};

class MemoryCacheTest : public testing::Test {
 public:
  class FakeResource final : public Resource {
   public:
    static constexpr size_t kInitialDecodedSize = 42;

    FakeResource(const char* url, ResourceType type)
        : FakeResource(KURL(url), type) {}
    FakeResource(const KURL& url, ResourceType type)
        : FakeResource(ResourceRequest(url),
                       type,
                       ResourceLoaderOptions(nullptr /* world */)) {}
    FakeResource(const ResourceRequest& request,
                 ResourceType type,
                 const ResourceLoaderOptions& options)
        : Resource(request, type, options) {
      SetDecodedSize(kInitialDecodedSize);
    }

    void DestroyDecodedDataIfPossible() override { SetDecodedSize(0u); }
  };

 protected:
  void SetUp() override {
    // Save the global memory cache to restore it upon teardown.
    global_memory_cache_ = ReplaceMemoryCacheForTesting(
        MakeGarbageCollected<MemoryCache>(platform_->test_task_runner()));
    auto* properties = MakeGarbageCollected<TestResourceFetcherProperties>();
    lifecycle_notifier_ = MakeGarbageCollected<MockContextLifecycleNotifier>();
    fetcher_ = MakeGarbageCollected<ResourceFetcher>(ResourceFetcherInit(
        properties->MakeDetachable(), MakeGarbageCollected<MockFetchContext>(),
        base::MakeRefCounted<scheduler::FakeTaskRunner>(),
        base::MakeRefCounted<scheduler::FakeTaskRunner>(),
        MakeGarbageCollected<TestLoaderFactory>(), lifecycle_notifier_,
        nullptr /* back_forward_cache_loader_helper */));
  }

  void TearDown() override {
    ReplaceMemoryCacheForTesting(global_memory_cache_.Release());
  }

  Persistent<MemoryCache> global_memory_cache_;
  Persistent<ResourceFetcher> fetcher_;
  Persistent<MockContextLifecycleNotifier> lifecycle_notifier_;
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform_;

 private:
  base::test::TaskEnvironment task_environment_;
};


TEST_F(MemoryCacheTest, VeryLargeResourceAccounting) {
  const size_t kSizeMax = ~static_cast<size_t>(0);
  const size_t kResourceSize1 = kSizeMax / 16;
  const size_t kResourceSize2 = kSizeMax / 20;
  Persistent<MockResourceClient> client =
      MakeGarbageCollected<MockResourceClient>();
  // Here and below, use an image MIME type. This is because on Android
  // non-image MIME types trigger a query to Java to check which video codecs
  // are supported. This fails in tests. The solution is either to use an image
  // type, or disable the tests on Android.
  // crbug.com/850788.
  FetchParameters params =
      FetchParameters::CreateForTest(ResourceRequest("data:image/jpeg,"));
  FakeDecodedResource* cached_resource =
      FakeDecodedResource::Fetch(params, fetcher_, client);
  cached_resource->FakeEncodedSize(kResourceSize1);

  EXPECT_TRUE(MemoryCache::Get()->Contains(cached_resource));
  EXPECT_EQ(cached_resource->size(), MemoryCache::Get()->size());

  client->RemoveAsClient();
  EXPECT_EQ(cached_resource->size(), MemoryCache::Get()->size());

  cached_resource->FakeEncodedSize(kResourceSize2);
  EXPECT_EQ(cached_resource->size(), MemoryCache::Get()->size());
}

// Verifies that
// - size() is updated appropriately when Resources are added to MemoryCache
//   and garbage collected.
// -
static void TestClientRemoval(ResourceFetcher* fetcher,
                              const String& identifier1,
                              const String& identifier2) {
  const std::string_view kData = "abcde";
  Persistent<MockResourceClient> client1 =
      MakeGarbageCollected<MockResourceClient>();
  Persistent<MockResourceClient> client2 =
      MakeGarbageCollected<MockResourceClient>();
  FetchParameters params1 =
      FetchParameters::CreateForTest(ResourceRequest("data:image/jpeg,foo"));
  Resource* resource1 = FakeDecodedResource::Fetch(params1, fetcher, client1);
  FetchParameters params2 =
      FetchParameters::CreateForTest(ResourceRequest("data:image/jpeg,bar"));
  Resource* resource2 = FakeDecodedResource::Fetch(params2, fetcher, client2);
  resource1->AppendData(kData.substr(0u, 4u));
  resource2->AppendData(kData.substr(0u, 4u));

  // Remove and re-Add the resources, with proper cache identifiers.
  MemoryCache::Get()->Remove(resource1);
  MemoryCache::Get()->Remove(resource2);
  if (!identifier1.empty())
    resource1->SetCacheIdentifier(identifier1);
  if (!identifier2.empty())
    resource2->SetCacheIdentifier(identifier2);
  MemoryCache::Get()->Add(resource1);
  MemoryCache::Get()->Add(resource2);

  size_t original_total_size = resource1->size() + resource2->size();

  // Removing the client from resource1 should not affect the size.
  client1->RemoveAsClient();
  EXPECT_GT(resource1->DecodedSize(), 0u);
  EXPECT_GT(resource2->DecodedSize(), 0u);
  EXPECT_EQ(original_total_size, MemoryCache::Get()->size());
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource1));
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource2));

  // Removing the client from resource2 should not affect the size.
  client2->RemoveAsClient();
  EXPECT_GT(resource1->DecodedSize(), 0u);
  EXPECT_GT(resource2->DecodedSize(), 0u);
  EXPECT_EQ(original_total_size, MemoryCache::Get()->size());
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource1));
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource2));

  WeakPersistent<Resource> resource1_weak = resource1;
  WeakPersistent<Resource> resource2_weak = resource2;

  // Garabage collection should cause resources without clients to be collected
  // and removed from the cache. The size should be updated accordingly.
  ThreadState::Current()->CollectAllGarbageForTesting(
      ThreadState::StackState::kNoHeapPointers);
  EXPECT_FALSE(resource1_weak);
  EXPECT_FALSE(resource2_weak);
  EXPECT_EQ(0u, MemoryCache::Get()->size());
}

TEST_F(MemoryCacheTest, ClientRemoval_Basic) {
  TestClientRemoval(fetcher_, "", "");
}

TEST_F(MemoryCacheTest, ClientRemoval_MultipleResourceMaps) {
  {
    TestClientRemoval(fetcher_, "foo", "");
    MemoryCache::Get()->EvictResources();
  }
  {
    TestClientRemoval(fetcher_, "", "foo");
    MemoryCache::Get()->EvictResources();
  }
  {
    TestClientRemoval(fetcher_, "foo", "bar");
    MemoryCache::Get()->EvictResources();
  }
}

TEST_F(MemoryCacheTest, RemoveDuringRevalidation) {
  auto* resource1 = MakeGarbageCollected<FakeResource>("http://test/resource",
                                                       ResourceType::kRaw);
  MemoryCache::Get()->Add(resource1);

  auto* resource2 = MakeGarbageCollected<FakeResource>("http://test/resource",
                                                       ResourceType::kRaw);
  MemoryCache::Get()->Remove(resource1);
  MemoryCache::Get()->Add(resource2);
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource2));
  EXPECT_FALSE(MemoryCache::Get()->Contains(resource1));

  auto* resource3 = MakeGarbageCollected<FakeResource>("http://test/resource",
                                                       ResourceType::kRaw);
  MemoryCache::Get()->Remove(resource2);
  MemoryCache::Get()->Add(resource3);
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource3));
  EXPECT_FALSE(MemoryCache::Get()->Contains(resource2));
}

TEST_F(MemoryCacheTest, ResourceMapIsolation) {
  auto* resource1 = MakeGarbageCollected<FakeResource>("http://test/resource",
                                                       ResourceType::kRaw);
  MemoryCache::Get()->Add(resource1);

  auto* resource2 = MakeGarbageCollected<FakeResource>("http://test/resource",
                                                       ResourceType::kRaw);
  resource2->SetCacheIdentifier("foo");
  MemoryCache::Get()->Add(resource2);
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource1));
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource2));

  const KURL url = KURL("http://test/resource");
  EXPECT_EQ(resource1, MemoryCache::Get()->ResourceForURLForTesting(url));
  EXPECT_EQ(resource1, MemoryCache::Get()->ResourceForURL(
                           url, MemoryCache::Get()->DefaultCacheIdentifier()));
  EXPECT_EQ(resource2, MemoryCache::Get()->ResourceForURL(url, "foo"));
  EXPECT_EQ(nullptr, MemoryCache::Get()->ResourceForURLForTesting(NullURL()));

  auto* resource3 = MakeGarbageCollected<FakeResource>("http://test/resource",
                                                       ResourceType::kRaw);
  resource3->SetCacheIdentifier("foo");
  MemoryCache::Get()->Remove(resource2);
  MemoryCache::Get()->Add(resource3);
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource1));
  EXPECT_FALSE(MemoryCache::Get()->Contains(resource2));
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource3));

  HeapVector<Member<Resource>> resources =
      MemoryCache::Get()->ResourcesForURL(url);
  EXPECT_EQ(2u, resources.size());

  MemoryCache::Get()->EvictResources();
  EXPECT_FALSE(MemoryCache::Get()->Contains(resource1));
  EXPECT_FALSE(MemoryCache::Get()->Contains(resource3));
}

TEST_F(MemoryCacheTest, FragmentIdentifier) {
  const KURL url1 = KURL("http://test/resource#foo");
  auto* resource = MakeGarbageCollected<FakeResource>(url1, ResourceType::kRaw);
  MemoryCache::Get()->Add(resource);
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource));

  EXPECT_EQ(resource, MemoryCache::Get()->ResourceForURLForTesting(url1));

  const KURL url2 = MemoryCache::RemoveFragmentIdentifierIfNeeded(url1);
  EXPECT_EQ(resource, MemoryCache::Get()->ResourceForURLForTesting(url2));
}

TEST_F(MemoryCacheTest, RemoveURLFromCache) {
  const KURL url1 = KURL("http://test/resource1");
  Persistent<FakeResource> resource1 =
      MakeGarbageCollected<FakeResource>(url1, ResourceType::kRaw);
  MemoryCache::Get()->Add(resource1);
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource1));

  MemoryCache::Get()->RemoveURLFromCache(url1);
  EXPECT_FALSE(MemoryCache::Get()->Contains(resource1));

  const KURL url2 = KURL("http://test/resource2#foo");
  auto* resource2 =
      MakeGarbageCollected<FakeResource>(url2, ResourceType::kRaw);
  MemoryCache::Get()->Add(resource2);
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource2));

  MemoryCache::Get()->RemoveURLFromCache(url2);
  EXPECT_FALSE(MemoryCache::Get()->Contains(resource2));
}

class MemoryCacheStrongReferenceTest : public MemoryCacheTest {
 public:
  void SetUp() override {
    std::vector<base::test::FeatureRef> enable_features = {
      features::kMemoryCacheStrongReference
    };
    scoped_feature_list_.InitWithFeatures(enable_features, {});
    MemoryCacheTest::SetUp();
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

TEST_F(MemoryCacheStrongReferenceTest, ResourceTimeout) {
  const KURL url = KURL("http://test/resource1");
  Member<FakeResource> resource =
      MakeGarbageCollected<FakeResource>(url, ResourceType::kRaw);

  ASSERT_EQ(MemoryCache::Get()->strong_references_.size(), 0u);
  MemoryCache::Get()->strong_references_prune_duration_ = base::Milliseconds(1);
  MemoryCache::Get()->SavePageResourceStrongReferences(
      HeapVector<Member<Resource>>{resource});
  ASSERT_EQ(MemoryCache::Get()->strong_references_.size(), 1u);

  (*MemoryCache::Get()->strong_references_.begin())
      ->memory_cache_last_accessed_ = base::TimeTicks();
  platform_->test_task_runner()->FastForwardBy(base::Minutes(5) +
                                               base::Seconds(1));
  ASSERT_EQ(MemoryCache::Get()->strong_references_.size(), 0u);
}

TEST_F(MemoryCacheStrongReferenceTest, LRU) {
  const KURL url1 = KURL("http://test/resource1");
  const KURL url2 = KURL("http://test/resource1");
  Member<FakeResource> resource1 =
      MakeGarbageCollected<FakeResource>(url1, ResourceType::kRaw);
  Member<FakeResource> resource2 =
      MakeGarbageCollected<FakeResource>(url2, ResourceType::kRaw);
  MemoryCache::Get()->SaveStrongReference(resource1);
  MemoryCache::Get()->SaveStrongReference(resource2);
  MemoryCache::Get()->SaveStrongReference(resource1);
  ASSERT_EQ(MemoryCache::Get()->strong_references_.size(), 2u);
  ASSERT_EQ(*MemoryCache::Get()->strong_references_.begin(), resource2.Get());
}

TEST_F(MemoryCacheStrongReferenceTest, ClearStrongReferences) {
  const KURL kURL("http://test/resource1");
  Member<FakeResource> resource =
      MakeGarbageCollected<FakeResource>(kURL, ResourceType::kRaw);
  MemoryCache::Get()->SaveStrongReference(resource);
  EXPECT_EQ(MemoryCache::Get()->strong_references_.size(), 1u);
  MemoryCache::Get()->ClearStrongReferences();
  EXPECT_EQ(MemoryCache::Get()->strong_references_.size(), 0u);
}

}  // namespace blink

"""

```