Response:
The user wants a summary of the functionality of the provided C++ code file `cache_test.cc`. I need to identify the purpose of the code, its relation to web technologies (JavaScript, HTML, CSS), analyze any logical reasoning within the tests, point out potential user/programming errors it helps prevent, and describe how a user action might lead to this code being executed.

Here's a breakdown of my thought process:

1. **Identify the core purpose:** The file name `cache_test.cc` and the inclusion of `<gtest/gtest.h>` strongly suggest this file contains unit tests. The presence of `blink::renderer::modules::cache_storage` in the path further confirms that these tests are for the cache storage functionality in the Chromium Blink rendering engine.

2. **Analyze the includes:** The included headers reveal the components being tested and the testing framework used:
    * `cache.h`: The class being tested.
    * `gtest/gtest.h`: The Google Test framework.
    * Various `mojom-blink.h` files:  These define the interfaces used for communication between different parts of the Chromium browser (likely between the renderer and the browser process). Specifically, they relate to CacheStorage and Fetch API.
    * Binding-related headers (`idl_types.h`, `script_promise.h`, `v8_request.h`, etc.):  Indicate interactions with JavaScript and the V8 engine.
    * Core DOM and Fetch API headers (`document.h`, `request.h`, `response.h`, etc.):  Show the code interacts with fundamental web concepts.

3. **Examine the code structure:**  The file defines several test classes:
    * `ScopedFetcherForTests`:  A mock implementation of a fetcher, used to control the behavior of network requests during testing.
    * `ErrorCacheForTests`: A mock implementation of the `CacheStorageCache` interface that returns a specified error for all operations. This is useful for testing error handling.
    * `NotImplementedErrorCache`: A specialized `ErrorCacheForTests` that always returns a "not implemented" error.
    * `TestCache`: A subclass of `Cache` that allows checking if it has been aborted.
    * `CacheStorageTest`: The main test fixture that sets up the testing environment and contains the individual test cases.

4. **Infer functionality from test names and code:** The test names (`Basics`, `BasicArguments`, `BatchOperationArguments`, `MatchResponseTest`, `KeysResponseTest`, etc.) clearly indicate the specific aspects of the `Cache` class being tested. The code within each test sets up expectations, performs actions on the `Cache` object, and then uses `EXPECT_*` macros from Google Test to verify the results.

5. **Relate to web technologies:** The code directly interacts with concepts from JavaScript, HTML, and CSS, although indirectly through the Blink rendering engine's internal APIs.
    * **JavaScript:** The tests manipulate `ScriptState`, `ScriptPromise`, `Request`, and `Response` objects, which are the JavaScript representations of web requests and responses in the Cache API. The tests simulate how JavaScript code might interact with the Cache API.
    * **HTML:** The caching mechanism is fundamental to how browsers load and store web resources referenced in HTML (images, scripts, stylesheets). While not directly manipulating HTML elements, these tests ensure the caching of these resources functions correctly.
    * **CSS:** Similar to HTML, CSS files are also web resources that can be cached. The tests don't specifically test CSS but the underlying caching mechanism is the same for all fetchable resources.

6. **Identify logical reasoning:**  The tests follow a typical "arrange, act, assert" pattern. They set up specific conditions (e.g., a mock cache returning a particular error), perform an action (e.g., calling `cache->match`), and then assert that the result matches the expected outcome. The tests involving `ScopedFetcherForTests` demonstrate logical reasoning by verifying that the correct URLs are being fetched.

7. **Recognize potential user/programming errors:** The tests implicitly help prevent common errors:
    * Incorrect handling of errors from cache operations (e.g., `kErrorNotFound`, `kErrorExists`).
    * Passing incorrect arguments to cache methods.
    * Incorrectly interpreting the results of cache operations (e.g., expecting a response when the cache returns `undefined`).

8. **Trace user actions to code execution:** A user action triggering these tests would be a developer running the Chromium unit tests. However, thinking about how a user action *could* involve the cache and lead to *this code being relevant*:
    * A user browsing a website might cause JavaScript code to interact with the Cache API.
    * This JavaScript code might call methods like `caches.open()`, `cache.put()`, `cache.match()`, etc.
    * The Blink rendering engine would then execute the C++ code responsible for handling these Cache API calls, which is what `cache_test.cc` is testing. While the user action doesn't directly trigger the *test*, it triggers the *code being tested*.

9. **Synthesize the summary:** Combine the above observations into a concise description of the file's functionality.

By following these steps, I was able to arrive at the summary provided in the initial prompt.
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/cache_storage/cache.h"

// ... other includes ...

namespace blink {

namespace {

// ... (Helper class and constants like kNotImplementedString) ...

// A test implementation of the CacheStorageCache interface which returns a
// (provided) error for every operation, and optionally checks arguments to
// methods against provided arguments. Also used as a base class for test
// specific caches.
class ErrorCacheForTests : public mojom::blink::CacheStorageCache {
 public:
  // ... methods for simulating error responses ...
};

class NotImplementedErrorCache : public ErrorCacheForTests {
 public:
  NotImplementedErrorCache()
      : ErrorCacheForTests(
            mojom::blink::CacheStorageError::kErrorNotImplemented) {}
};

class TestCache : public Cache {
 public:
  // ... methods for testing abort signals ...
};

class CacheStorageTest : public PageTestBase {
 public:
  // ... setup and utility methods for testing ...
};

// ... (Helper function RequestToRequestInfo) ...

TEST_F(CacheStorageTest, Basics) {
  // ... Basic tests for cache operations ...
}

// Tests that arguments are faithfully passed on calls to Cache methods, except
// for methods which use batch operations, which are tested later.
TEST_F(CacheStorageTest, BasicArguments) {
  // ... Tests for argument passing in cache methods ...
}

// Tests that arguments are faithfully passed to API calls that degrade to batch
// operations.
TEST_F(CacheStorageTest, BatchOperationArguments) {
  // ... Tests for argument passing in batch operations ...
}

class MatchTestCache : public NotImplementedErrorCache {
 public:
  // ... A mock cache for testing match operation ...
};

TEST_F(CacheStorageTest, MatchResponseTest) {
  // ... Tests the response from the match operation ...
}

class KeysTestCache : public NotImplementedErrorCache {
 public:
  // ... A mock cache for testing keys operation ...
};

TEST_F(CacheStorageTest, KeysResponseTest) {
  // ... Tests the response from the keys operation ...
}

class MatchAllAndBatchTestCache : public NotImplementedErrorCache {
 public:
  // ... A mock cache for testing matchAll and batch operations ...
};

TEST_F(CacheStorageTest, MatchAllAndBatchResponseTest) {
  // ... Tests the responses from matchAll and batch operations ...
}

TEST_F(CacheStorageTest, Add) {
  // ... Tests the add operation ...
}

// Verify we don't create and trigger the AbortController when a single request
// to add() addAll() fails.
TEST_F(CacheStorageTest, AddAllAbortOne) {
  // ... Tests abort signal handling for addAll with one failing request ...
}
```

这个文件的功能是为 Blink 渲染引擎的 **Cache API** 提供 **单元测试**。 具体来说，它测试了 `blink::Cache` 类的各种方法和行为。

以下是其主要功能的归纳：

1. **测试 Cache 对象的创建和基本操作:**  例如 `match` 方法在没有实现或遇到特定错误时的行为 (`TEST_F(CacheStorageTest, Basics)`).

2. **测试 Cache 方法的参数传递:** 验证传递给 `Cache` 对象方法的参数是否正确地传递到了底层的实现 (`TEST_F(CacheStorageTest, BasicArguments)` 和 `TEST_F(CacheStorageTest, BatchOperationArguments)`).

3. **模拟 Cache 方法的成功返回:**  创建 mock 对象 (`MatchTestCache`, `KeysTestCache`, `MatchAllAndBatchTestCache`) 来模拟 `match`, `keys`, `matchAll` 等方法的成功返回，并验证返回的结果是否符合预期 (`TEST_F(CacheStorageTest, MatchResponseTest)`, `TEST_F(CacheStorageTest, KeysResponseTest)`, `TEST_F(CacheStorageTest, MatchAllAndBatchResponseTest)`).

4. **测试涉及 "批量操作" 的方法:**  例如 `add`, `addAll`, `delete`, `put` 等方法如何分解为底层的批量操作，并验证参数的正确传递 (`TEST_F(CacheStorageTest, BatchOperationArguments)`, `TEST_F(CacheStorageTest, Add)`).

5. **测试 AbortController 的行为:** 验证在 `add` 或 `addAll` 操作失败时，`AbortController` 是否不会被意外触发 (`TEST_F(CacheStorageTest, AddAllAbortOne)`).

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件主要测试的是浏览器提供的 **Cache API** 的 C++ 实现，该 API 是供 JavaScript 使用的。 虽然测试代码本身是 C++，但它模拟了 JavaScript 代码与 Cache API 的交互。

* **JavaScript:**
    * **举例说明:**  JavaScript 代码可以使用 `caches.open('my-cache').then(function(cache) { return cache.match('/my-resource'); });` 来匹配缓存中的资源。  `cache_test.cc` 中的 `TEST_F(CacheStorageTest, Basics)` 和 `TEST_F(CacheStorageTest, MatchResponseTest)` 等测试就模拟了这种 JavaScript 调用，并验证了 C++ 层的 `Cache::match` 方法的行为和返回值。
    * **假设输入与输出 (逻辑推理):**  假设 JavaScript 调用 `cache.match('https://example.com/image.png')`，并且 `CacheStorageTest` 中有一个 `MatchTestCache` 被配置为返回一个包含该 URL 的 Response 对象。 那么，测试的期望输出是 `cache->match` 方法返回的 Promise 会 resolve 成一个 Response 对象，并且该 Response 对象的 URL 是 `https://example.com/image.png`。

* **HTML:**
    * **举例说明:**  HTML 中的 `<img src="/my-image.png">` 标签可能会导致浏览器请求 `/my-image.png`。  如果 Service Worker 使用 Cache API 缓存了这个图片，后续的请求可能会直接从缓存中读取。 `cache_test.cc` 通过测试 `Cache::match` 等方法来确保这种缓存机制的正确性。

* **CSS:**
    * **举例说明:**  类似于 HTML 中的图片，`<link rel="stylesheet" href="/style.css">` 也会触发对 CSS 文件的请求，该文件也可能被 Cache API 缓存。  `cache_test.cc` 中对 `Cache::put` 和 `Cache::match` 的测试覆盖了 CSS 文件缓存的场景。

**用户或编程常见的使用错误及举例说明:**

* **错误地假设缓存始终存在:** 用户或开发者可能会假设某个资源一定存在于缓存中，而没有处理 `cache.match()` 返回 `undefined` 的情况。 `TEST_F(CacheStorageTest, Basics)` 测试了 `match` 在缓存未命中时的行为，提醒开发者需要处理这种情况。

* **错误地配置 CacheQueryOptions:** 用户可能不理解 `ignoreSearch`, `ignoreMethod`, `ignoreVary` 等选项的作用，导致缓存匹配失败或返回不期望的结果。 `TEST_F(CacheStorageTest, BasicArguments)` 验证了这些选项在 C++ 层的正确传递和处理。

* **在批量操作中传递错误的 Request 或 Response 对象:** 例如，`cache.put()` 需要一个 Request 和一个 Response 对象。 传递错误的类型或状态的对象会导致错误。 `TEST_F(CacheStorageTest, BatchOperationArguments)` 验证了这些参数的正确性。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户访问一个启用了 Service Worker 的网页:**  Service Worker 是使用 Cache API 的主要方式。
2. **Service Worker 脚本被加载和执行:**  Service Worker 的 `install` 或 `activate` 事件中可能会使用 `caches.open()` 打开一个缓存。
3. **Service Worker 的 `fetch` 事件监听器拦截网络请求:** 当用户浏览网页或页面发起资源请求时，Service Worker 的 `fetch` 事件监听器会被触发。
4. **在 `fetch` 事件监听器中，JavaScript 代码使用 Cache API:**
   * 例如，`event.respondWith(caches.match(event.request))` 尝试从缓存中匹配请求。
   * 或者，`caches.open('my-cache').then(cache => cache.put(event.request, response))` 将响应添加到缓存。
5. **Blink 渲染引擎接收到 JavaScript 的 Cache API 调用:**  JavaScript 引擎会将这些调用转换为对 Blink 渲染引擎中 C++ Cache API 实现的调用。
6. **`blink/renderer/modules/cache_storage/cache.cc` 中的代码被执行:**  这个 C++ 文件包含了 `blink::Cache` 类的实现。
7. **如果出现问题或需要调试，开发者可能会查看 `blink/renderer/modules/cache_storage/cache_test.cc`:**  这个测试文件提供了针对 `blink::Cache` 各种功能的单元测试，可以帮助理解和验证 `Cache` 类的行为。通过阅读测试用例，开发者可以了解特定方法在不同场景下的预期输入和输出，从而定位问题。

**总结 (针对第1部分):**

`blink/renderer/modules/cache_storage/cache_test.cc` 的主要功能是为 Blink 渲染引擎的 `blink::Cache` 类提供全面的单元测试。 它通过模拟各种场景，包括成功情况和错误情况，验证了 `Cache` 类的各种方法（如 `match`, `matchAll`, `keys`, `add`, `put`, `delete` 等）的参数传递、返回值以及与底层存储交互的正确性。 这些测试对于确保 Cache API 的稳定性和可靠性至关重要，直接影响了基于 Service Worker 的 Web 应用的缓存机制的正常运行。

Prompt: 
```
这是目录为blink/renderer/modules/cache_storage/cache_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/cache_storage/cache.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/task/single_thread_task_runner.h"
#include "mojo/public/cpp/bindings/associated_receiver.h"
#include "mojo/public/cpp/bindings/associated_remote.h"
#include "services/network/public/mojom/fetch_api.mojom-blink.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/cache_storage/cache_storage.mojom-blink.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_request.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_request_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_response.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_response_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_request_usvstring.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_response_undefined.h"
#include "third_party/blink/renderer/core/dom/abort_controller.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fetch/body_stream_buffer.h"
#include "third_party/blink/renderer/core/fetch/form_data_bytes_consumer.h"
#include "third_party/blink/renderer/core/fetch/global_fetch.h"
#include "third_party/blink/renderer/core/fetch/request.h"
#include "third_party/blink/renderer/core/fetch/response.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/modules/cache_storage/cache_storage_blob_client_list.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

using blink::mojom::CacheStorageError;
using blink::mojom::blink::CacheStorageVerboseError;

namespace blink {

namespace {

const char kNotImplementedString[] =
    "NotSupportedError: Method is not implemented.";

class ScopedFetcherForTests final
    : public GarbageCollected<ScopedFetcherForTests>,
      public GlobalFetch::ScopedFetcher {
 public:
  ScopedFetcherForTests() = default;

  ScriptPromise<Response> Fetch(ScriptState* script_state,
                                const V8RequestInfo* request_info,
                                const RequestInit*,
                                ExceptionState& exception_state) override {
    ++fetch_count_;
    if (expected_url_) {
      switch (request_info->GetContentType()) {
        case V8RequestInfo::ContentType::kRequest:
          EXPECT_EQ(*expected_url_, request_info->GetAsRequest()->url());
          break;
        case V8RequestInfo::ContentType::kUSVString:
          EXPECT_EQ(*expected_url_, request_info->GetAsUSVString());
          break;
      }
    }

    if (response_) {
      return ToResolvedPromise<Response>(script_state, response_);
    }
    exception_state.ThrowTypeError(
        "Unexpected call to fetch, no response available.");
    return EmptyPromise();
  }

  // This does not take ownership of its parameter. The provided sample object
  // is used to check the parameter when called.
  void SetExpectedFetchUrl(const String* expected_url) {
    expected_url_ = expected_url;
  }
  void SetResponse(Response* response) { response_ = response; }

  uint32_t FetchCount() const override { return fetch_count_; }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(response_);
    GlobalFetch::ScopedFetcher::Trace(visitor);
  }

 private:
  uint32_t fetch_count_ = 0;
  raw_ptr<const String> expected_url_ = nullptr;
  Member<Response> response_;
};

// A test implementation of the CacheStorageCache interface which returns a
// (provided) error for every operation, and optionally checks arguments to
// methods against provided arguments. Also used as a base class for test
// specific caches.
class ErrorCacheForTests : public mojom::blink::CacheStorageCache {
 public:
  ErrorCacheForTests(const mojom::blink::CacheStorageError error)
      : error_(error),
        expected_url_(nullptr),
        expected_query_options_(nullptr),
        expected_batch_operations_(nullptr) {}

  std::string GetAndClearLastErrorWebCacheMethodCalled() {
    test::RunPendingTasks();
    std::string old = last_error_web_cache_method_called_;
    last_error_web_cache_method_called_.clear();
    return old;
  }

  // These methods do not take ownership of their parameter. They provide an
  // optional sample object to check parameters against.
  void SetExpectedUrl(const String* expected_url) {
    expected_url_ = expected_url;
  }
  void SetExpectedCacheQueryOptions(
      const mojom::blink::CacheQueryOptionsPtr* expected_query_options) {
    expected_query_options_ = expected_query_options;
  }
  void SetExpectedBatchOperations(const Vector<mojom::blink::BatchOperationPtr>*
                                      expected_batch_operations) {
    expected_batch_operations_ = expected_batch_operations;
  }

  void Match(mojom::blink::FetchAPIRequestPtr fetch_api_request,
             mojom::blink::CacheQueryOptionsPtr query_options,
             bool in_related_fetch_event,
             bool in_range_fetch_event,
             int64_t trace_id,
             MatchCallback callback) override {
    last_error_web_cache_method_called_ = "dispatchMatch";
    CheckUrlIfProvided(fetch_api_request->url);
    CheckCacheQueryOptionsIfProvided(query_options);
    std::move(callback).Run(mojom::blink::MatchResult::NewStatus(error_));
  }
  void MatchAll(mojom::blink::FetchAPIRequestPtr fetch_api_request,
                mojom::blink::CacheQueryOptionsPtr query_options,
                int64_t trace_id,
                MatchAllCallback callback) override {
    last_error_web_cache_method_called_ = "dispatchMatchAll";
    if (fetch_api_request)
      CheckUrlIfProvided(fetch_api_request->url);
    CheckCacheQueryOptionsIfProvided(query_options);
    std::move(callback).Run(mojom::blink::MatchAllResult::NewStatus(error_));
  }
  void GetAllMatchedEntries(mojom::blink::FetchAPIRequestPtr request,
                            mojom::blink::CacheQueryOptionsPtr query_options,
                            int64_t trace_id,
                            GetAllMatchedEntriesCallback callback) override {
    NOTREACHED();
  }
  void Keys(mojom::blink::FetchAPIRequestPtr fetch_api_request,
            mojom::blink::CacheQueryOptionsPtr query_options,
            int64_t trace_id,
            KeysCallback callback) override {
    last_error_web_cache_method_called_ = "dispatchKeys";
    if (fetch_api_request && !fetch_api_request->url.IsEmpty()) {
      CheckUrlIfProvided(fetch_api_request->url);
      CheckCacheQueryOptionsIfProvided(query_options);
    }
    mojom::blink::CacheKeysResultPtr result =
        mojom::blink::CacheKeysResult::NewStatus(error_);
    std::move(callback).Run(std::move(result));
  }
  void Batch(Vector<mojom::blink::BatchOperationPtr> batch_operations,
             int64_t trace_id,
             BatchCallback callback) override {
    last_error_web_cache_method_called_ = "dispatchBatch";
    CheckBatchOperationsIfProvided(batch_operations);
    std::move(callback).Run(CacheStorageVerboseError::New(error_, String()));
  }
  void WriteSideData(const blink::KURL& url,
                     base::Time expected_response_time,
                     mojo_base::BigBuffer data,
                     int64_t trace_id,
                     WriteSideDataCallback callback) override {
    NOTREACHED();
  }

 protected:
  void CheckUrlIfProvided(const KURL& url) {
    if (!expected_url_)
      return;
    EXPECT_EQ(*expected_url_, url);
  }

  void CheckCacheQueryOptionsIfProvided(
      const mojom::blink::CacheQueryOptionsPtr& query_options) {
    if (!expected_query_options_)
      return;
    CompareCacheQueryOptionsForTest(*expected_query_options_, query_options);
  }

  void CheckBatchOperationsIfProvided(
      const Vector<mojom::blink::BatchOperationPtr>& batch_operations) {
    if (!expected_batch_operations_)
      return;
    const Vector<mojom::blink::BatchOperationPtr>& expected_batch_operations =
        *expected_batch_operations_;
    EXPECT_EQ(expected_batch_operations.size(), batch_operations.size());
    for (int i = 0, minsize = std::min(expected_batch_operations.size(),
                                       batch_operations.size());
         i < minsize; ++i) {
      EXPECT_EQ(expected_batch_operations[i]->operation_type,
                batch_operations[i]->operation_type);
      const String expected_request_url =
          expected_batch_operations[i]->request->url;
      EXPECT_EQ(expected_request_url, batch_operations[i]->request->url);
      if (expected_batch_operations[i]->response) {
        ASSERT_EQ(expected_batch_operations[i]->response->url_list.size(),
                  batch_operations[i]->response->url_list.size());
        for (wtf_size_t j = 0;
             j < expected_batch_operations[i]->response->url_list.size(); ++j) {
          EXPECT_EQ(expected_batch_operations[i]->response->url_list[j],
                    batch_operations[i]->response->url_list[j]);
        }
      }
      if (expected_batch_operations[i]->match_options ||
          batch_operations[i]->match_options) {
        CompareCacheQueryOptionsForTest(
            expected_batch_operations[i]->match_options,
            batch_operations[i]->match_options);
      }
    }
  }

 private:
  static void CompareCacheQueryOptionsForTest(
      const mojom::blink::CacheQueryOptionsPtr& expected_query_options,
      const mojom::blink::CacheQueryOptionsPtr& query_options) {
    EXPECT_EQ(expected_query_options->ignore_search,
              query_options->ignore_search);
    EXPECT_EQ(expected_query_options->ignore_method,
              query_options->ignore_method);
    EXPECT_EQ(expected_query_options->ignore_vary, query_options->ignore_vary);
  }

  const mojom::blink::CacheStorageError error_;

  raw_ptr<const String> expected_url_;
  raw_ptr<const mojom::blink::CacheQueryOptionsPtr> expected_query_options_;
  raw_ptr<const Vector<mojom::blink::BatchOperationPtr>>
      expected_batch_operations_;

  std::string last_error_web_cache_method_called_;
};

class NotImplementedErrorCache : public ErrorCacheForTests {
 public:
  NotImplementedErrorCache()
      : ErrorCacheForTests(
            mojom::blink::CacheStorageError::kErrorNotImplemented) {}
};

class TestCache : public Cache {
 public:
  TestCache(
      GlobalFetch::ScopedFetcher* fetcher,
      mojo::PendingAssociatedRemote<mojom::blink::CacheStorageCache> remote,
      ExecutionContext* execution_context)
      : Cache(fetcher,
              MakeGarbageCollected<CacheStorageBlobClientList>(),
              std::move(remote),
              execution_context,
              TaskType::kInternalTest) {}

  bool IsAborted() const {
    return abort_controller_ && abort_controller_->signal()->aborted();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(abort_controller_);
    Cache::Trace(visitor);
  }

 protected:
  AbortController* CreateAbortController(ScriptState* script_state) override {
    if (!abort_controller_)
      abort_controller_ = AbortController::Create(script_state);
    return abort_controller_.Get();
  }

 private:
  Member<blink::AbortController> abort_controller_;
};

class CacheStorageTest : public PageTestBase {
 public:
  void SetUp() override { PageTestBase::SetUp(gfx::Size(1, 1)); }

  TestCache* CreateCache(ScopedFetcherForTests* fetcher,
                         std::unique_ptr<ErrorCacheForTests> cache) {
    mojo::AssociatedRemote<mojom::blink::CacheStorageCache> cache_remote;
    cache_ = std::move(cache);
    receiver_ = std::make_unique<
        mojo::AssociatedReceiver<mojom::blink::CacheStorageCache>>(
        cache_.get(), cache_remote.BindNewEndpointAndPassDedicatedReceiver());
    return MakeGarbageCollected<TestCache>(fetcher, cache_remote.Unbind(),
                                           GetExecutionContext());
  }

  ErrorCacheForTests* test_cache() { return cache_.get(); }

  ScriptState* GetScriptState() {
    return ToScriptStateForMainWorld(GetDocument().GetFrame());
  }
  ExecutionContext* GetExecutionContext() {
    return ExecutionContext::From(GetScriptState());
  }
  v8::Isolate* GetIsolate() { return GetScriptState()->GetIsolate(); }
  v8::Local<v8::Context> GetContext() { return GetScriptState()->GetContext(); }

  Request* NewRequestFromUrl(const String& url) {
    DummyExceptionStateForTesting exception_state;
    Request* request = Request::Create(GetScriptState(), url, exception_state);
    EXPECT_FALSE(exception_state.HadException());
    return exception_state.HadException() ? nullptr : request;
  }

  // Convenience methods for testing the returned promises.
  template <typename IDLType>
  ScriptValue GetRejectValue(ScriptPromise<IDLType>& promise) {
    ScriptPromiseTester tester(GetScriptState(), promise);
    tester.WaitUntilSettled();
    EXPECT_TRUE(tester.IsRejected());
    return tester.Value();
  }

  template <typename IDLType>
  std::string GetRejectString(ScriptPromise<IDLType>& promise) {
    ScriptValue on_reject = GetRejectValue(promise);
    return ToCoreString(
               GetIsolate(),
               on_reject.V8Value()->ToString(GetContext()).ToLocalChecked())
        .Ascii()
        .data();
  }

  template <typename IDLType>
  ScriptValue GetResolveValue(ScriptPromise<IDLType>& promise) {
    ScriptPromiseTester tester(GetScriptState(), promise);
    tester.WaitUntilSettled();
    EXPECT_TRUE(tester.IsFulfilled());
    return tester.Value();
  }

  template <typename IDLType>
  std::string GetResolveString(ScriptPromise<IDLType>& promise) {
    ScriptValue on_resolve = GetResolveValue(promise);
    return ToCoreString(
               GetIsolate(),
               on_resolve.V8Value()->ToString(GetContext()).ToLocalChecked())
        .Ascii()
        .data();
  }

 private:
  std::unique_ptr<ErrorCacheForTests> cache_;
  std::unique_ptr<mojo::AssociatedReceiver<mojom::blink::CacheStorageCache>>
      receiver_;
};

V8RequestInfo* RequestToRequestInfo(Request* value) {
  return MakeGarbageCollected<V8RequestInfo>(value);
}

V8RequestInfo* StringToRequestInfo(const String& value) {
  return MakeGarbageCollected<V8RequestInfo>(value);
}

TEST_F(CacheStorageTest, Basics) {
  ScriptState::Scope scope(GetScriptState());
  NonThrowableExceptionState exception_state;
  auto* fetcher = MakeGarbageCollected<ScopedFetcherForTests>();
  Cache* cache =
      CreateCache(fetcher, std::make_unique<NotImplementedErrorCache>());
  DCHECK(cache);

  const String url = "http://www.cachetest.org/";

  CacheQueryOptions* options = CacheQueryOptions::Create();
  auto match_promise = cache->match(GetScriptState(), StringToRequestInfo(url),
                                    options, exception_state);
  EXPECT_EQ(kNotImplementedString, GetRejectString(match_promise));

  cache = CreateCache(fetcher, std::make_unique<ErrorCacheForTests>(
                                   CacheStorageError::kErrorNotFound));
  match_promise = cache->match(GetScriptState(), StringToRequestInfo(url),
                               options, exception_state);
  ScriptValue script_value = GetResolveValue(match_promise);
  EXPECT_TRUE(script_value.IsUndefined());

  cache = CreateCache(fetcher, std::make_unique<ErrorCacheForTests>(
                                   CacheStorageError::kErrorExists));
  match_promise = cache->match(GetScriptState(), StringToRequestInfo(url),
                               options, exception_state);
  EXPECT_EQ("InvalidAccessError: Entry already exists.",
            GetRejectString(match_promise));
}

// Tests that arguments are faithfully passed on calls to Cache methods, except
// for methods which use batch operations, which are tested later.
TEST_F(CacheStorageTest, BasicArguments) {
  ScriptState::Scope scope(GetScriptState());
  NonThrowableExceptionState exception_state;
  auto* fetcher = MakeGarbageCollected<ScopedFetcherForTests>();
  Cache* cache =
      CreateCache(fetcher, std::make_unique<NotImplementedErrorCache>());
  DCHECK(cache);

  auto match_all_result_no_arguments =
      cache->matchAll(GetScriptState(), exception_state);
  EXPECT_EQ("dispatchMatchAll",
            test_cache()->GetAndClearLastErrorWebCacheMethodCalled());
  EXPECT_EQ(kNotImplementedString,
            GetRejectString(match_all_result_no_arguments));

  const String url = "http://www.cache.arguments.test/";
  test_cache()->SetExpectedUrl(&url);

  mojom::blink::CacheQueryOptionsPtr expected_query_options =
      mojom::blink::CacheQueryOptions::New();
  expected_query_options->ignore_vary = true;
  test_cache()->SetExpectedCacheQueryOptions(&expected_query_options);

  CacheQueryOptions* options = CacheQueryOptions::Create();
  options->setIgnoreVary(true);

  Request* request = NewRequestFromUrl(url);
  DCHECK(request);
  auto match_result =
      cache->match(GetScriptState(), RequestToRequestInfo(request), options,
                   exception_state);
  EXPECT_EQ("dispatchMatch",
            test_cache()->GetAndClearLastErrorWebCacheMethodCalled());
  EXPECT_EQ(kNotImplementedString, GetRejectString(match_result));

  auto string_match_result = cache->match(
      GetScriptState(), StringToRequestInfo(url), options, exception_state);
  EXPECT_EQ("dispatchMatch",
            test_cache()->GetAndClearLastErrorWebCacheMethodCalled());
  EXPECT_EQ(kNotImplementedString, GetRejectString(string_match_result));

  request = NewRequestFromUrl(url);
  DCHECK(request);
  auto match_all_result =
      cache->matchAll(GetScriptState(), RequestToRequestInfo(request), options,
                      exception_state);
  EXPECT_EQ("dispatchMatchAll",
            test_cache()->GetAndClearLastErrorWebCacheMethodCalled());
  EXPECT_EQ(kNotImplementedString, GetRejectString(match_all_result));

  auto string_match_all_result = cache->matchAll(
      GetScriptState(), StringToRequestInfo(url), options, exception_state);
  EXPECT_EQ("dispatchMatchAll",
            test_cache()->GetAndClearLastErrorWebCacheMethodCalled());
  EXPECT_EQ(kNotImplementedString, GetRejectString(string_match_all_result));

  auto keys_result1 = cache->keys(GetScriptState(), exception_state);
  EXPECT_EQ("dispatchKeys",
            test_cache()->GetAndClearLastErrorWebCacheMethodCalled());
  EXPECT_EQ(kNotImplementedString, GetRejectString(keys_result1));

  request = NewRequestFromUrl(url);
  DCHECK(request);
  auto keys_result2 =
      cache->keys(GetScriptState(), RequestToRequestInfo(request), options,
                  exception_state);
  EXPECT_EQ("dispatchKeys",
            test_cache()->GetAndClearLastErrorWebCacheMethodCalled());
  EXPECT_EQ(kNotImplementedString, GetRejectString(keys_result2));

  auto string_keys_result2 = cache->keys(
      GetScriptState(), StringToRequestInfo(url), options, exception_state);
  EXPECT_EQ("dispatchKeys",
            test_cache()->GetAndClearLastErrorWebCacheMethodCalled());
  EXPECT_EQ(kNotImplementedString, GetRejectString(string_keys_result2));
}

// Tests that arguments are faithfully passed to API calls that degrade to batch
// operations.
TEST_F(CacheStorageTest, BatchOperationArguments) {
  ScriptState::Scope scope(GetScriptState());
  NonThrowableExceptionState exception_state;
  auto* fetcher = MakeGarbageCollected<ScopedFetcherForTests>();
  Cache* cache =
      CreateCache(fetcher, std::make_unique<NotImplementedErrorCache>());
  DCHECK(cache);

  mojom::blink::CacheQueryOptionsPtr expected_query_options =
      mojom::blink::CacheQueryOptions::New();
  test_cache()->SetExpectedCacheQueryOptions(&expected_query_options);

  CacheQueryOptions* options = CacheQueryOptions::Create();

  const String url = "http://batch.operations.test/";
  Request* request = NewRequestFromUrl(url);
  DCHECK(request);

  auto fetch_response = mojom::blink::FetchAPIResponse::New();
  fetch_response->url_list.push_back(KURL(url));
  fetch_response->response_type = network::mojom::FetchResponseType::kDefault;
  fetch_response->status_text = String("OK");
  Response* response = Response::Create(GetScriptState(), *fetch_response);

  Vector<mojom::blink::BatchOperationPtr> expected_delete_operations;
  {
    expected_delete_operations.push_back(mojom::blink::BatchOperation::New());
    auto& delete_operation = expected_delete_operations.back();
    delete_operation->operation_type = mojom::blink::OperationType::kDelete;
    delete_operation->request = request->CreateFetchAPIRequest();
    delete_operation->match_options = expected_query_options->Clone();
  }
  test_cache()->SetExpectedBatchOperations(&expected_delete_operations);

  auto delete_result =
      cache->Delete(GetScriptState(), RequestToRequestInfo(request), options,
                    exception_state);
  EXPECT_EQ("dispatchBatch",
            test_cache()->GetAndClearLastErrorWebCacheMethodCalled());
  EXPECT_EQ(kNotImplementedString, GetRejectString(delete_result));

  auto string_delete_result = cache->Delete(
      GetScriptState(), StringToRequestInfo(url), options, exception_state);
  EXPECT_EQ("dispatchBatch",
            test_cache()->GetAndClearLastErrorWebCacheMethodCalled());
  EXPECT_EQ(kNotImplementedString, GetRejectString(string_delete_result));

  Vector<mojom::blink::BatchOperationPtr> expected_put_operations;
  {
    expected_put_operations.push_back(mojom::blink::BatchOperation::New());
    auto& put_operation = expected_put_operations.back();
    put_operation->operation_type = mojom::blink::OperationType::kPut;
    put_operation->request = request->CreateFetchAPIRequest();
    put_operation->response =
        response->PopulateFetchAPIResponse(request->url());
  }
  test_cache()->SetExpectedBatchOperations(&expected_put_operations);

  request = NewRequestFromUrl(url);
  DCHECK(request);
  auto put_result = cache->put(
      GetScriptState(), RequestToRequestInfo(request),
      response->clone(GetScriptState(), exception_state), exception_state);
  EXPECT_EQ("dispatchBatch",
            test_cache()->GetAndClearLastErrorWebCacheMethodCalled());
  EXPECT_EQ(kNotImplementedString, GetRejectString(put_result));

  auto string_put_result = cache->put(
      GetScriptState(), StringToRequestInfo(url), response, exception_state);
  EXPECT_EQ("dispatchBatch",
            test_cache()->GetAndClearLastErrorWebCacheMethodCalled());
  EXPECT_EQ(kNotImplementedString, GetRejectString(string_put_result));

  // FIXME: test add & addAll.
}

class MatchTestCache : public NotImplementedErrorCache {
 public:
  MatchTestCache(mojom::blink::FetchAPIResponsePtr response)
      : response_(std::move(response)) {}

  // From WebServiceWorkerCache:
  void Match(mojom::blink::FetchAPIRequestPtr fetch_api_request,
             mojom::blink::CacheQueryOptionsPtr query_options,
             bool in_related_fetch_event,
             bool in_range_fetch_event,
             int64_t trace_id,
             MatchCallback callback) override {
    mojom::blink::MatchResultPtr result =
        mojom::blink::MatchResult::NewResponse(std::move(response_));
    std::move(callback).Run(std::move(result));
  }

 private:
  mojom::blink::FetchAPIResponsePtr response_;
};

TEST_F(CacheStorageTest, MatchResponseTest) {
  ScriptState::Scope scope(GetScriptState());
  NonThrowableExceptionState exception_state;
  auto* fetcher = MakeGarbageCollected<ScopedFetcherForTests>();
  const String request_url = "http://request.url/";
  const String response_url = "http://match.response.test/";

  mojom::blink::FetchAPIResponsePtr fetch_api_response =
      mojom::blink::FetchAPIResponse::New();
  fetch_api_response->url_list.push_back(KURL(response_url));
  fetch_api_response->response_type =
      network::mojom::FetchResponseType::kDefault;
  fetch_api_response->status_text = String("OK");

  Cache* cache = CreateCache(
      fetcher, std::make_unique<MatchTestCache>(std::move(fetch_api_response)));
  CacheQueryOptions* options = CacheQueryOptions::Create();

  auto result = cache->match(GetScriptState(), StringToRequestInfo(request_url),
                             options, exception_state);
  ScriptValue script_value = GetResolveValue(result);
  Response* response =
      V8Response::ToWrappable(GetIsolate(), script_value.V8Value());
  ASSERT_TRUE(response);
  EXPECT_EQ(response_url, response->url());
}

class KeysTestCache : public NotImplementedErrorCache {
 public:
  KeysTestCache(Vector<mojom::blink::FetchAPIRequestPtr> requests)
      : requests_(std::move(requests)) {}

  void Keys(mojom::blink::FetchAPIRequestPtr fetch_api_request,
            mojom::blink::CacheQueryOptionsPtr query_options,
            int64_t trace_id,
            KeysCallback callback) override {
    mojom::blink::CacheKeysResultPtr result =
        mojom::blink::CacheKeysResult::NewKeys(std::move(requests_));
    std::move(callback).Run(std::move(result));
  }

 private:
  Vector<mojom::blink::FetchAPIRequestPtr> requests_;
};

TEST_F(CacheStorageTest, KeysResponseTest) {
  ScriptState::Scope scope(GetScriptState());
  NonThrowableExceptionState exception_state;
  auto* fetcher = MakeGarbageCollected<ScopedFetcherForTests>();
  const String url1 = "http://first.request/";
  const String url2 = "http://second.request/";

  Vector<String> expected_urls(size_t(2));
  expected_urls[0] = url1;
  expected_urls[1] = url2;

  Vector<mojom::blink::FetchAPIRequestPtr> fetch_api_requests(size_t(2));
  fetch_api_requests[0] = mojom::blink::FetchAPIRequest::New();
  fetch_api_requests[0]->url = KURL(url1);
  fetch_api_requests[0]->method = String("GET");
  fetch_api_requests[1] = mojom::blink::FetchAPIRequest::New();
  fetch_api_requests[1]->url = KURL(url2);
  fetch_api_requests[1]->method = String("GET");

  Cache* cache = CreateCache(
      fetcher, std::make_unique<KeysTestCache>(std::move(fetch_api_requests)));

  auto result = cache->keys(GetScriptState(), exception_state);
  ScriptValue script_value = GetResolveValue(result);

  HeapVector<Member<Request>> requests =
      NativeValueTraits<IDLSequence<Request>>::NativeValue(
          GetIsolate(), script_value.V8Value(), exception_state);
  EXPECT_EQ(expected_urls.size(), requests.size());
  for (int i = 0, minsize = std::min(expected_urls.size(), requests.size());
       i < minsize; ++i) {
    Request* request = requests[i];
    EXPECT_TRUE(request);
    if (request)
      EXPECT_EQ(expected_urls[i], request->url());
  }
}

class MatchAllAndBatchTestCache : public NotImplementedErrorCache {
 public:
  MatchAllAndBatchTestCache(Vector<mojom::blink::FetchAPIResponsePtr> responses)
      : responses_(std::move(responses)) {}

  void MatchAll(mojom::blink::FetchAPIRequestPtr fetch_api_request,
                mojom::blink::CacheQueryOptionsPtr query_options,
                int64_t trace_id,
                MatchAllCallback callback) override {
    mojom::blink::MatchAllResultPtr result =
        mojom::blink::MatchAllResult::NewResponses(std::move(responses_));
    std::move(callback).Run(std::move(result));
  }
  void Batch(Vector<mojom::blink::BatchOperationPtr> batch_operations,
             int64_t trace_id,
             BatchCallback callback) override {
    std::move(callback).Run(CacheStorageVerboseError::New(
        mojom::blink::CacheStorageError::kSuccess, String()));
  }

 private:
  Vector<mojom::blink::FetchAPIResponsePtr> responses_;
};

TEST_F(CacheStorageTest, MatchAllAndBatchResponseTest) {
  ScriptState::Scope scope(GetScriptState());
  NonThrowableExceptionState exception_state;
  auto* fetcher = MakeGarbageCollected<ScopedFetcherForTests>();
  const String url1 = "http://first.response/";
  const String url2 = "http://second.response/";

  Vector<String> expected_urls(size_t(2));
  expected_urls[0] = url1;
  expected_urls[1] = url2;

  Vector<mojom::blink::FetchAPIResponsePtr> fetch_api_responses;
  fetch_api_responses.push_back(mojom::blink::FetchAPIResponse::New());
  fetch_api_responses[0]->url_list = Vector<KURL>({KURL(url1)});
  fetch_api_responses[0]->response_type =
      network::mojom::FetchResponseType::kDefault;
  fetch_api_responses[0]->status_text = String("OK");
  fetch_api_responses.push_back(mojom::blink::FetchAPIResponse::New());
  fetch_api_responses[1]->url_list = Vector<KURL>({KURL(url2)});
  fetch_api_responses[1]->response_type =
      network::mojom::FetchResponseType::kDefault;
  fetch_api_responses[1]->status_text = String("OK");

  Cache* cache =
      CreateCache(fetcher, std::make_unique<MatchAllAndBatchTestCache>(
                               std::move(fetch_api_responses)));

  CacheQueryOptions* options = CacheQueryOptions::Create();
  auto match_all_result =
      cache->matchAll(GetScriptState(), StringToRequestInfo("http://some.url/"),
                      options, exception_state);
  ScriptValue script_value = GetResolveValue(match_all_result);

  HeapVector<Member<Response>> responses =
      NativeValueTraits<IDLSequence<Response>>::NativeValue(
          GetIsolate(), script_value.V8Value(), exception_state);
  EXPECT_EQ(expected_urls.size(), responses.size());
  for (int i = 0, minsize = std::min(expected_urls.size(), responses.size());
       i < minsize; ++i) {
    Response* response = responses[i];
    EXPECT_TRUE(response);
    if (response)
      EXPECT_EQ(expected_urls[i], response->url());
  }

  auto delete_result =
      cache->Delete(GetScriptState(), StringToRequestInfo("http://some.url/"),
                    options, exception_state);
  script_value = GetResolveValue(delete_result);
  EXPECT_TRUE(script_value.V8Value()->IsBoolean());
  EXPECT_EQ(true, script_value.V8Value().As<v8::Boolean>()->Value());
}

TEST_F(CacheStorageTest, Add) {
  ScriptState::Scope scope(GetScriptState());
  NonThrowableExceptionState exception_state;
  auto* fetcher = MakeGarbageCollected<ScopedFetcherForTests>();
  const String url = "http://www.cacheadd.test/";
  const String content_type = "text/plain";
  const String content = "hello cache";

  Cache* cache =
      CreateCache(fetcher, std::make_unique<NotImplementedErrorCache>());

  fetcher->SetExpectedFetchUrl(&url);

  Request* request = NewRequestFromUrl(url);
  Response* response =
      Response::Create(GetScriptState(),
                       BodyStreamBuffer::Create(
                           GetScriptState(),
                           MakeGarbageCollected<FormDataBytesConsumer>(content),
                           nullptr, /*cached_metadata_handler=*/nullptr),
                       content_type, ResponseInit::Create(), exception_state);
  fetcher->SetResponse(response);

  Vector<mojom::blink::BatchOperationPtr> expected_put_operations(size_t(1));
  {
    mojom::blink::BatchOperationPtr put_operation =
        mojom::blink::BatchOperation::New();

    put_operation->operation_type = mojom::blink::OperationType::kPut;
    put_operation->request = request->CreateFetchAPIRequest();
    put_operation->response =
        response->PopulateFetchAPIResponse(request->url());
    expected_put_operations[0] = std::move(put_operation);
  }
  test_cache()->SetExpectedBatchOperations(&expected_put_operations);

  auto add_result = cache->add(GetScriptState(), RequestToRequestInfo(request),
                               exception_state);

  EXPECT_EQ(kNotImplementedString, GetRejectString(add_result));
  EXPECT_EQ(1u, fetcher->FetchCount());
  EXPECT_EQ("dispatchBatch",
            test_cache()->GetAndClearLastErrorWebCacheMethodCalled());
}

// Verify we don't create and trigger the AbortController when a single request
// to add() addAll() fails.
TEST_F(CacheStorageTest, AddAllAbortOne) {
  ScriptState::Scope scope(GetScriptSta
"""


```