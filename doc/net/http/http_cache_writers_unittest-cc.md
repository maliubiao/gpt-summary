Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Identify the Core Purpose:** The file name `http_cache_writers_unittest.cc` immediately tells us this is a test file for something related to "http_cache_writers". The `.cc` extension confirms it's C++ code. The `#include "net/http/http_cache_writers.h"` at the beginning reinforces this. Therefore, the primary function is to test the `HttpCache::Writers` class.

2. **Understand the Test Structure:**  Unit tests in Chromium (and many other C++ projects) often use the Google Test framework (gtest). Look for patterns like `TEST_F(ClassName, TestName)`. This indicates individual test cases within the `WritersTest` fixture class.

3. **Analyze the Fixture Class (`WritersTest`):**
    * **Purpose:** The fixture sets up the environment and provides helper functions for the tests. Think of it as a common ground for all tests in the file.
    * **Key Members:**
        * `scoped_transaction_`:  Likely a helper to define basic HTTP transaction properties (method, URL, data).
        * `cache_`: A mock implementation of `HttpCache`. Mocking allows controlled behavior for testing.
        * `writers_`:  The core object being tested.
        * `disk_entry_`, `entry_`:  Represent the on-disk cache entry and its in-memory representation.
        * `test_cache_`: Another `HttpCache` instance, specifically a `TestHttpCache` subclass to observe internal behavior (like counting `WritersDoneWritingToEntry`).
        * `request_`: A mock HTTP request object.
        * `response_info_`: Holds response header information.
        * `transactions_`: A vector of `TestHttpCacheTransaction` objects. This suggests the `Writers` class manages multiple transactions.
    * **Key Methods:**
        * `CreateWriters()`: Sets up the `Writers` object.
        * `CreateNetworkTransaction()`: Creates a mock network transaction.
        * `CreateWritersAddTransaction()`: A common setup for tests involving adding transactions to the writers.
        * `AddTransactionToExistingWriters()`: Adds a subsequent transaction.
        * `Read()`, `ReadFewBytes()`:  Simulate reading data through the `Writers` object.
        * `ReadAllDeleteTransaction()`: Tests reading while removing transactions.
        * `StopMidRead()`:  Simulates stopping a read operation midway.
        * `ReadAll()`:  Reads all data.
        * `ReadCacheWriteFailure()`, `ReadNetworkFailure()`:  Test error scenarios.
        * `StopCaching()`:  Tests the `StopCaching` functionality.
        * `RemoveFirstTransaction()`: Removes a transaction.
        * `UpdateAndVerifyPriority()`: Checks priority updates.
        * `ShouldKeepEntry()`, `Truncated()`, `ShouldTruncate()`, `CanAddWriters()`: Accessors to check internal state.

4. **Examine Individual Test Cases:**  Go through each `TEST_F` function and understand what it's testing:
    * **Focus on the Arrange-Act-Assert pattern:**  Most tests follow this:
        * **Arrange:** Set up the necessary objects and state (e.g., create writers, add transactions).
        * **Act:** Perform the action being tested (e.g., call `Read`, `StopCaching`, `RemoveTransaction`).
        * **Assert:** Verify the expected outcome using `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `EXPECT_THAT`, etc. (gtest assertions).

5. **Identify Key Functionality of `HttpCache::Writers` (based on the tests):**
    * Adding and managing multiple HTTP cache transactions.
    * Reading data from the underlying cache entry, serving multiple readers concurrently.
    * Handling different buffer sizes for concurrent reads.
    * Managing transaction priorities.
    * Stopping the caching process (`StopCaching`).
    * Handling cache write failures and network errors.
    * Determining whether to keep or truncate a cache entry.
    * Managing parallel writing patterns.

6. **Relate to JavaScript (if applicable):**  In this specific case, the connection to JavaScript is indirect. Think about *how* this caching mechanism is used in a browser:
    * **Fetching Resources:** When JavaScript code in a web page makes requests (e.g., using `fetch` or `XMLHttpRequest`), the browser's network stack (including this HTTP cache) is involved.
    * **Caching Behavior:**  The caching behavior controlled by `HttpCache::Writers` determines whether a resource is loaded from the cache or needs to be re-fetched from the network. This directly impacts JavaScript's performance and the perceived speed of web applications.
    * **Examples:**
        * If a JavaScript makes a `fetch` request for an image, and the `HttpCache::Writers` logic decides to cache it, subsequent requests for the same image will likely be served from the cache, making the page load faster.
        * If `StopCaching` is triggered (perhaps due to user settings or specific response headers), JavaScript's `fetch` requests might always go to the network.
        * The "truncated" state relates to partial content caching, which could affect how JavaScript handles streaming or large resource downloads.

7. **Look for Logic and Assumptions:** The tests reveal assumptions about how the `Writers` class works. For example, the tests involving `ReadMultipleDifferentBufferSizes` assume that concurrent reads with different buffer sizes are handled correctly. The tests with `DeleteTransactionType` show assumptions about how removing transactions impacts ongoing reads.

8. **Consider User/Programming Errors:**
    * **Incorrect Cache Headers:**  While not directly tested here, the effectiveness of the cache relies on correct HTTP caching headers (e.g., `Cache-Control`, `Expires`). Incorrect headers can lead to unexpected caching behavior.
    * **Forcing Cache Bypass:**  Users can force a cache bypass (e.g., with Ctrl+Shift+R in a browser). This would prevent the `HttpCache::Writers` logic from being used for that request.
    * **Programmatic Errors:**  If a programmer incorrectly configures caching policies (though that would likely be at a higher level than this class), it could lead to issues.

9. **Debugging Clues:** The test setup itself provides debugging clues:
    * **Mocking:** The use of mocks allows isolation and controlled testing of specific scenarios. If a test fails, it often points to an issue within the `HttpCache::Writers` logic itself, rather than external factors.
    * **Specific Test Cases:**  The individual test names and the actions they perform help pinpoint the area of the code where a bug might exist. For example, if `StopCachingMidReadKeepEntry` fails, the issue is likely in how `StopCaching` interacts with ongoing read operations.

By following these steps, you can systematically analyze a C++ unittest file and understand its purpose, functionality, and relationship to the larger system.
这个文件 `net/http/http_cache_writers_unittest.cc` 是 Chromium 网络栈中用于测试 `net::HttpCache::Writers` 类的单元测试文件。`HttpCache::Writers` 类负责管理向 HTTP 缓存写入数据的操作，特别是处理多个并发的写操作。

**主要功能:**

1. **测试 `HttpCache::Writers` 类的核心功能:**  验证 `Writers` 类是否能正确地添加、管理和移除多个并发的 HTTP 缓存写操作（transactions）。
2. **测试并发写入的正确性:**  确保在多个 transactions 同时写入缓存时，数据不会损坏，并且所有 transactions 都能正确完成或被取消。
3. **测试读取操作与写入操作的交互:**  验证当有正在进行的写入操作时，读取操作的行为是否符合预期，例如能否读取到部分写入的数据，或者是否需要等待写入完成。
4. **测试缓存策略的执行:**  验证 `Writers` 类在各种情况下的缓存策略执行，例如是否应该保留缓存条目 (`should_keep_entry_`)，是否应该截断缓存条目 (`ShouldTruncate()`).
5. **测试错误处理:**  验证在写入过程中发生错误（例如缓存写入失败、网络错误）时，`Writers` 类能否正确处理并通知相关的 transactions。
6. **测试优先级管理:**  验证 `Writers` 类是否能根据 transactions 的优先级进行管理。

**与 JavaScript 功能的关系 (间接关系):**

这个 C++ 文件本身不包含任何 JavaScript 代码，但它测试的 HTTP 缓存功能直接影响到 web 浏览器中 JavaScript 的行为和性能。

* **资源缓存:** 当 JavaScript 代码通过 `fetch` API 或 `XMLHttpRequest` 发起网络请求时，浏览器会尝试从缓存中加载资源。`HttpCache::Writers` 确保了这些资源被正确地写入缓存。
* **性能优化:** 正确的缓存机制可以显著提高网页加载速度，减少网络请求，从而提升 JavaScript 应用的性能和用户体验。例如，如果一个 JavaScript 文件或图片被缓存了，后续的访问可以直接从缓存加载，而不需要再次从服务器下载。
* **离线访问:** 缓存是实现 PWA (Progressive Web Apps) 离线访问能力的关键组成部分。`HttpCache::Writers` 的正确性直接影响到离线应用能否正常工作。

**举例说明:**

假设一个网页包含一个 JavaScript 文件 `script.js`。

1. **首次加载:** 当浏览器首次访问该网页时，JavaScript 代码会请求 `script.js`。`HttpCache::Writers` 会负责将从服务器下载的 `script.js` 的内容写入到 HTTP 缓存中。
2. **后续加载:** 当用户刷新页面或再次访问该网页时，如果缓存策略允许，浏览器会尝试从缓存中加载 `script.js`。这个过程中并没有 `HttpCache::Writers` 的直接参与（除非缓存条目需要更新或重新验证），但 `Writers` 之前的正确写入是缓存能够命中的前提。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* 多个 `HttpCache::Transaction` 对象同时尝试向同一个缓存条目写入数据。
* 其中一个 transaction 的优先级高于其他 transaction。
* 网络连接速度较慢，导致写入过程需要一定时间。

**预期输出:**

* 优先级较高的 transaction 可能会更快地完成写入，或者在资源竞争时获得优先权。
* 所有成功的 transactions 都应该能将各自的数据正确写入缓存，且不会发生数据覆盖或损坏。
* 读取操作在写入完成前可能会读取到部分数据，具体取决于缓存策略和读取操作的时间点。
* 如果其中一个 transaction 发生错误（例如网络中断），`Writers` 类应该能够正确处理，并可能取消或回滚相关的写入操作。

**用户或编程常见的使用错误:**

* **不正确的缓存配置:**  开发者可能会错误地配置 HTTP 响应头，导致资源无法被缓存或缓存策略不符合预期。例如，设置了 `Cache-Control: no-cache` 或 `Cache-Control: max-age=0` 可能会阻止资源被有效缓存。
* **强制刷新:** 用户可以通过浏览器操作（例如 Ctrl+F5 或 Shift+刷新）强制浏览器跳过缓存，直接从服务器加载资源。这会绕过 `HttpCache::Writers` 管理的缓存机制。
* **缓存失效策略不当:**  如果缓存失效策略设置得过于激进，可能会导致频繁地重新下载资源，降低性能。反之，如果失效策略过于宽松，可能会导致用户看到过期的内容。
* **程序逻辑错误导致重复写入:**  编程错误可能导致 JavaScript 代码发起重复的网络请求，从而触发 `HttpCache::Writers` 进行不必要的缓存写入操作。

**用户操作如何一步步地到达这里 (作为调试线索):**

假设用户在使用 Chrome 浏览器访问一个网页时遇到了缓存相关的问题，例如资源未被正确缓存或使用了过期的缓存。作为开发人员，可以使用以下步骤来逐步接近 `net/http/http_cache_writers_unittest.cc` 这个测试文件，以帮助理解和调试问题：

1. **用户报告问题:** 用户反馈网页加载缓慢，或者某些资源没有更新。
2. **开发者初步排查:**  开发者会先检查浏览器的开发者工具（Network 面板），查看资源的加载情况，包括是否使用了缓存 (from cache / from disk cache)。
3. **怀疑缓存问题:** 如果开发者怀疑是缓存导致的问题，可能会尝试清除浏览器缓存，并重新加载页面。如果问题解决，则进一步确认问题与缓存有关。
4. **深入了解缓存机制:** 开发者可能会查阅 Chromium 的网络栈文档，了解 HTTP 缓存的工作原理，以及 `HttpCache` 相关的组件。
5. **定位到 `HttpCache::Writers`:**  如果问题涉及到缓存的写入过程，例如新的资源无法被正确缓存，或者并发请求导致缓存数据损坏，开发者可能会关注负责缓存写入的 `HttpCache::Writers` 类。
6. **查找相关测试用例:**  为了验证 `HttpCache::Writers` 的行为是否符合预期，开发者可能会查找相关的单元测试文件，例如 `net/http/http_cache_writers_unittest.cc`。
7. **分析测试用例:**  通过分析测试用例，开发者可以了解 `Writers` 类在各种场景下的行为，例如并发写入、错误处理、优先级管理等。这有助于理解问题的根本原因，例如是否是并发写入的 bug 导致了缓存数据损坏。
8. **本地调试和测试:** 开发者可能会尝试在本地运行相关的单元测试，或者修改测试用例来模拟用户遇到的具体场景，以便更好地调试问题。
9. **代码审查:**  如果测试用例揭示了潜在的问题，开发者可能会进一步审查 `HttpCache::Writers` 的源代码，查找可能的 bug。

总而言之，`net/http/http_cache_writers_unittest.cc` 是一个用于验证 HTTP 缓存写入逻辑的关键测试文件，它虽然不直接包含 JavaScript 代码，但其测试的缓存功能对 web 浏览器的性能和 JavaScript 应用的行为至关重要。通过分析这个文件，开发者可以深入了解 Chromium 的缓存机制，并帮助诊断和解决与缓存相关的 bug。

### 提示词
```
这是目录为net/http/http_cache_writers_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_cache_writers.h"

#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/functional/bind.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "crypto/secure_hash.h"
#include "net/http/http_cache.h"
#include "net/http/http_cache_transaction.h"
#include "net/http/http_response_info.h"
#include "net/http/http_transaction.h"
#include "net/http/http_transaction_test_util.h"
#include "net/http/mock_http_cache.h"
#include "net/http/partial_data.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {
// Helper function, generating valid HTTP cache key from `url`.
// See also: HttpCache::GenerateCacheKey(..)
std::string GenerateCacheKey(const std::string& url) {
  return "1/0/" + url;
}
}  // namespace

class WritersTest;

class TestHttpCacheTransaction : public HttpCache::Transaction {
  typedef WebSocketHandshakeStreamBase::CreateHelper CreateHelper;

 public:
  TestHttpCacheTransaction(RequestPriority priority, HttpCache* cache)
      : HttpCache::Transaction(priority, cache) {}
  ~TestHttpCacheTransaction() override = default;

  Transaction::Mode mode() const override { return Transaction::READ_WRITE; }
};

class TestHttpCache : public HttpCache {
 public:
  TestHttpCache(std::unique_ptr<HttpTransactionFactory> network_layer,
                std::unique_ptr<BackendFactory> backend_factory)
      : HttpCache(std::move(network_layer), std::move(backend_factory)) {}

  void WritersDoneWritingToEntry(scoped_refptr<ActiveEntry> entry,
                                 bool success,
                                 bool should_keep_entry,
                                 TransactionSet make_readers) override {
    done_writing_to_entry_count_ += 1;
    make_readers_size_ = make_readers.size();
  }

  void WritersDoomEntryRestartTransactions(ActiveEntry* entry) override {}

  int WritersDoneWritingToEntryCount() const {
    return done_writing_to_entry_count_;
  }

  size_t MakeReadersSize() const { return make_readers_size_; }

 private:
  int done_writing_to_entry_count_ = 0;
  size_t make_readers_size_ = 0u;
};

class WritersTest : public TestWithTaskEnvironment {
 public:
  enum class DeleteTransactionType { NONE, ACTIVE, WAITING, IDLE };
  WritersTest()
      : scoped_transaction_(kSimpleGET_Transaction),
        test_cache_(std::make_unique<MockNetworkLayer>(),
                    std::make_unique<MockBackendFactory>()),
        request_(kSimpleGET_Transaction) {
    scoped_transaction_.response_headers =
        "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n"
        "Content-Length: 22\n"
        "Etag: \"foopy\"\n";
    request_ = MockHttpRequest(scoped_transaction_);
  }

  ~WritersTest() override {
    if (disk_entry_) {
      disk_entry_->Close();
    }
  }

  void CreateWriters() {
    cache_.CreateBackendEntry(GenerateCacheKey(kSimpleGET_Transaction.url),
                              &disk_entry_.AsEphemeralRawAddr(), nullptr);
    entry_ =
        new HttpCache::ActiveEntry(cache_.GetWeakPtr(), disk_entry_, false);
    (static_cast<MockDiskEntry*>(disk_entry_))->AddRef();
    writers_ = std::make_unique<HttpCache::Writers>(
        &test_cache_, base::WrapRefCounted(entry_.get()));
  }

  std::unique_ptr<HttpTransaction> CreateNetworkTransaction() {
    std::unique_ptr<HttpTransaction> transaction;
    MockNetworkLayer* network_layer = cache_.network_layer();
    network_layer->CreateTransaction(DEFAULT_PRIORITY, &transaction);
    return transaction;
  }

  void CreateWritersAddTransaction(
      HttpCache::ParallelWritingPattern parallel_writing_pattern_ =
          HttpCache::PARALLEL_WRITING_JOIN,
      bool content_encoding_present = false) {
    TestCompletionCallback callback;

    // Create and Start a mock network transaction.
    std::unique_ptr<HttpTransaction> network_transaction;
    network_transaction = CreateNetworkTransaction();
    network_transaction->Start(&request_, callback.callback(),
                               NetLogWithSource());
    base::RunLoop().RunUntilIdle();
    response_info_ = *(network_transaction->GetResponseInfo());
    if (content_encoding_present) {
      response_info_.headers->AddHeader("Content-Encoding", "gzip");
    }

    // Create a mock cache transaction.
    std::unique_ptr<TestHttpCacheTransaction> transaction =
        std::make_unique<TestHttpCacheTransaction>(DEFAULT_PRIORITY,
                                                   cache_.http_cache());

    CreateWriters();
    EXPECT_TRUE(writers_->IsEmpty());
    HttpCache::Writers::TransactionInfo info(
        transaction->partial(), transaction->is_truncated(), response_info_);

    writers_->AddTransaction(transaction.get(), parallel_writing_pattern_,
                             transaction->priority(), info);
    writers_->SetNetworkTransaction(transaction.get(),
                                    std::move(network_transaction));
    EXPECT_TRUE(writers_->HasTransaction(transaction.get()));
    transactions_.push_back(std::move(transaction));
  }

  void CreateWritersAddTransactionPriority(
      RequestPriority priority,
      HttpCache::ParallelWritingPattern parallel_writing_pattern_ =
          HttpCache::PARALLEL_WRITING_JOIN) {
    CreateWritersAddTransaction(parallel_writing_pattern_);
    TestHttpCacheTransaction* transaction = transactions_.begin()->get();
    transaction->SetPriority(priority);
  }

  void AddTransactionToExistingWriters() {
    EXPECT_TRUE(writers_);

    // Create a mock cache transaction.
    std::unique_ptr<TestHttpCacheTransaction> transaction =
        std::make_unique<TestHttpCacheTransaction>(DEFAULT_PRIORITY,
                                                   cache_.http_cache());

    HttpCache::Writers::TransactionInfo info(transaction->partial(),
                                             transaction->is_truncated(),
                                             *(transaction->GetResponseInfo()));
    info.response_info = response_info_;
    writers_->AddTransaction(transaction.get(),
                             HttpCache::PARALLEL_WRITING_JOIN,
                             transaction->priority(), info);
    transactions_.push_back(std::move(transaction));
  }

  int Read(std::string* result) {
    EXPECT_TRUE(transactions_.size() >= (size_t)1);
    TestHttpCacheTransaction* transaction = transactions_.begin()->get();
    TestCompletionCallback callback;

    std::string content;
    int rv = 0;
    do {
      auto buf = base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);
      rv = writers_->Read(buf.get(), kDefaultBufferSize, callback.callback(),
                          transaction);
      if (rv == ERR_IO_PENDING) {
        rv = callback.WaitForResult();
        base::RunLoop().RunUntilIdle();
      }

      if (rv > 0) {
        content.append(buf->data(), rv);
      } else if (rv < 0) {
        return rv;
      }
    } while (rv > 0);

    result->swap(content);
    return OK;
  }

  int ReadFewBytes(std::string* result) {
    EXPECT_TRUE(transactions_.size() >= (size_t)1);
    TestHttpCacheTransaction* transaction = transactions_.begin()->get();
    TestCompletionCallback callback;

    std::string content;
    int rv = 0;
    auto buf = base::MakeRefCounted<IOBufferWithSize>(5);
    rv = writers_->Read(buf.get(), 5, callback.callback(), transaction);
    if (rv == ERR_IO_PENDING) {
      rv = callback.WaitForResult();
      base::RunLoop().RunUntilIdle();
    }

    if (rv > 0) {
      result->append(buf->data(), rv);
    } else if (rv < 0) {
      return rv;
    }

    return OK;
  }

  void ReadVerifyTwoDifferentBufferLengths(
      const std::vector<int>& buffer_lengths) {
    EXPECT_EQ(2u, buffer_lengths.size());
    EXPECT_EQ(2u, transactions_.size());

    std::vector<std::string> results(buffer_lengths.size());

    // Check only the 1st Read and not the complete response because the smaller
    // buffer transaction will need to read the remaining response from the
    // cache which will be tested when integrated with TestHttpCacheTransaction
    // layer.

    int rv = 0;

    std::vector<scoped_refptr<IOBuffer>> bufs;
    for (auto buffer_length : buffer_lengths) {
      bufs.push_back(base::MakeRefCounted<IOBufferWithSize>(buffer_length));
    }

    std::vector<TestCompletionCallback> callbacks(buffer_lengths.size());

    // Multiple transactions should be able to read with different sized
    // buffers.
    for (size_t i = 0; i < transactions_.size(); i++) {
      rv = writers_->Read(bufs[i].get(), buffer_lengths[i],
                          callbacks[i].callback(), transactions_[i].get());
      EXPECT_EQ(ERR_IO_PENDING, rv);  // Since the default is asynchronous.
    }

    // If first buffer is smaller, then the second one will only read the
    // smaller length as well.
    std::vector<int> expected_lengths = {buffer_lengths[0],
                                         buffer_lengths[0] < buffer_lengths[1]
                                             ? buffer_lengths[0]
                                             : buffer_lengths[1]};

    for (size_t i = 0; i < callbacks.size(); i++) {
      rv = callbacks[i].WaitForResult();
      EXPECT_EQ(expected_lengths[i], rv);
      results[i].append(bufs[i]->data(), expected_lengths[i]);
    }

    EXPECT_EQ(results[0].substr(0, expected_lengths[1]), results[1]);

    std::string expected(kSimpleGET_Transaction.data);
    EXPECT_EQ(expected.substr(0, expected_lengths[1]), results[1]);
  }

  // Each transaction invokes Read simultaneously. If |deleteType| is not NONE,
  // then it deletes the transaction of given type during the read process.
  void ReadAllDeleteTransaction(DeleteTransactionType deleteType) {
    EXPECT_LE(3u, transactions_.size());

    unsigned int delete_index = std::numeric_limits<unsigned int>::max();
    switch (deleteType) {
      case DeleteTransactionType::NONE:
        break;
      case DeleteTransactionType::ACTIVE:
        delete_index = 0;
        break;
      case DeleteTransactionType::WAITING:
        delete_index = 1;
        break;
      case DeleteTransactionType::IDLE:
        delete_index = 2;
        break;
    }

    std::vector<std::string> results(transactions_.size());
    int rv = 0;
    bool first_iter = true;
    do {
      std::vector<scoped_refptr<IOBuffer>> bufs;
      std::vector<TestCompletionCallback> callbacks(transactions_.size());

      for (size_t i = 0; i < transactions_.size(); i++) {
        bufs.push_back(
            base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize));

        // If we have deleted a transaction in the first iteration, then do not
        // invoke Read on it, in subsequent iterations.
        if (!first_iter && deleteType != DeleteTransactionType::NONE &&
            i == delete_index) {
          continue;
        }

        // For it to be an idle transaction, do not invoke Read.
        if (deleteType == DeleteTransactionType::IDLE && i == delete_index) {
          continue;
        }

        rv = writers_->Read(bufs[i].get(), kDefaultBufferSize,
                            callbacks[i].callback(), transactions_[i].get());
        EXPECT_EQ(ERR_IO_PENDING, rv);  // Since the default is asynchronous.
      }

      if (first_iter && deleteType != DeleteTransactionType::NONE) {
        writers_->RemoveTransaction(transactions_.at(delete_index).get(),
                                    false /* success */);
      }

      // Verify Add Transaction should succeed mid-read.
      AddTransactionToExistingWriters();

      std::vector<int> rvs;
      for (size_t i = 0; i < callbacks.size(); i++) {
        if (i == delete_index && deleteType != DeleteTransactionType::NONE) {
          continue;
        }
        rv = callbacks[i].WaitForResult();
        rvs.push_back(rv);
      }

      // Verify all transactions should read the same length buffer.
      for (size_t i = 1; i < rvs.size(); i++) {
        ASSERT_EQ(rvs[i - 1], rvs[i]);
      }

      if (rv > 0) {
        for (size_t i = 0; i < results.size(); i++) {
          if (i == delete_index && deleteType != DeleteTransactionType::NONE &&
              deleteType != DeleteTransactionType::ACTIVE) {
            continue;
          }
          results.at(i).append(bufs[i]->data(), rv);
        }
      }
      first_iter = false;
    } while (rv > 0);

    for (size_t i = 0; i < results.size(); i++) {
      if (i == delete_index && deleteType != DeleteTransactionType::NONE &&
          deleteType != DeleteTransactionType::ACTIVE) {
        continue;
      }
      EXPECT_EQ(kSimpleGET_Transaction.data, results[i]);
    }

    EXPECT_EQ(OK, rv);
  }

  // Creates a transaction and performs two reads. Returns after the second read
  // has begun but before its callback has run.
  void StopMidRead() {
    CreateWritersAddTransaction();
    EXPECT_FALSE(writers_->IsEmpty());
    EXPECT_EQ(1u, transactions_.size());
    TestHttpCacheTransaction* transaction = transactions_[0].get();

    // Read a few bytes so that truncation is possible.
    TestCompletionCallback callback;
    auto buf = base::MakeRefCounted<IOBufferWithSize>(5);
    int rv = writers_->Read(buf.get(), 5, callback.callback(), transaction);
    EXPECT_EQ(ERR_IO_PENDING, rv);  // Since the default is asynchronous.
    EXPECT_EQ(5, callback.GetResult(rv));

    // Start reading a few more bytes and return.
    buf = base::MakeRefCounted<IOBufferWithSize>(5);
    rv = writers_->Read(buf.get(), 5, base::BindOnce([](int rv) {}),
                        transaction);
    EXPECT_EQ(ERR_IO_PENDING, rv);
  }

  void ReadAll() { ReadAllDeleteTransaction(DeleteTransactionType::NONE); }

  int ReadCacheWriteFailure(std::vector<std::string>* results) {
    int rv = 0;
    int active_transaction_rv = 0;
    bool first_iter = true;
    do {
      std::vector<scoped_refptr<IOBuffer>> bufs;
      std::vector<TestCompletionCallback> callbacks(results->size());

      // Fail the request.
      cache_.disk_cache()->set_soft_failures_mask(MockDiskEntry::FAIL_ALL);

      // We have to open the entry again to propagate the failure flag.
      disk_cache::Entry* en;
      cache_.OpenBackendEntry(GenerateCacheKey(kSimpleGET_Transaction.url),
                              &en);
      en->Close();

      for (size_t i = 0; i < transactions_.size(); i++) {
        bufs.push_back(base::MakeRefCounted<IOBufferWithSize>(30));

        if (!first_iter && i > 0) {
          break;
        }
        rv = writers_->Read(bufs[i].get(), 30, callbacks[i].callback(),
                            transactions_[i].get());
        EXPECT_EQ(ERR_IO_PENDING, rv);  // Since the default is asynchronous.
      }

      for (size_t i = 0; i < callbacks.size(); i++) {
        // Only active transaction should succeed.
        if (i == 0) {
          active_transaction_rv = callbacks[i].WaitForResult();
          EXPECT_LE(0, active_transaction_rv);
          results->at(0).append(bufs[i]->data(), active_transaction_rv);
        } else if (first_iter) {
          rv = callbacks[i].WaitForResult();
          EXPECT_EQ(ERR_CACHE_WRITE_FAILURE, rv);
        }
      }

      first_iter = false;
    } while (active_transaction_rv > 0);

    return active_transaction_rv;
  }

  int ReadNetworkFailure(std::vector<std::string>* results, Error error) {
    int rv = 0;
    std::vector<scoped_refptr<IOBuffer>> bufs;
    std::vector<TestCompletionCallback> callbacks(results->size());

    for (size_t i = 0; i < transactions_.size(); i++) {
      bufs.push_back(base::MakeRefCounted<IOBufferWithSize>(30));

      rv = writers_->Read(bufs[i].get(), 30, callbacks[i].callback(),
                          transactions_[i].get());
      EXPECT_EQ(ERR_IO_PENDING, rv);  // Since the default is asynchronous.
    }

    for (auto& callback : callbacks) {
      rv = callback.WaitForResult();
      EXPECT_EQ(error, rv);
    }

    return error;
  }

  bool StopCaching() {
    TestHttpCacheTransaction* transaction = transactions_.begin()->get();
    EXPECT_TRUE(transaction);
    return writers_->StopCaching(transaction);
  }

  void RemoveFirstTransaction() {
    TestHttpCacheTransaction* transaction = transactions_.begin()->get();
    EXPECT_TRUE(transaction);
    writers_->RemoveTransaction(transaction, false /* success */);
  }

  void UpdateAndVerifyPriority(RequestPriority priority) {
    writers_->UpdatePriority();
    EXPECT_EQ(priority, writers_->priority_);
  }

  bool ShouldKeepEntry() const { return writers_->should_keep_entry_; }

  bool Truncated() const {
    const int kResponseInfoIndex = 0;  // Keep updated with HttpCache.
    TestCompletionCallback callback;
    int io_buf_len = entry_->GetEntry()->GetDataSize(kResponseInfoIndex);
    if (io_buf_len == 0) {
      return false;
    }

    auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(io_buf_len);
    int rv = disk_entry_->ReadData(kResponseInfoIndex, 0, read_buffer.get(),
                                   read_buffer->size(), callback.callback());
    rv = callback.GetResult(rv);
    HttpResponseInfo response_info;
    bool truncated;
    HttpCache::ParseResponseInfo(read_buffer->span(), &response_info,
                                 &truncated);
    return truncated;
  }

  bool ShouldTruncate() { return writers_->ShouldTruncate(); }

  bool CanAddWriters() {
    HttpCache::ParallelWritingPattern parallel_writing_pattern_;
    return writers_->CanAddWriters(&parallel_writing_pattern_);
  }

  ScopedMockTransaction scoped_transaction_;
  MockHttpCache cache_;
  std::unique_ptr<HttpCache::Writers> writers_;
  raw_ptr<disk_cache::Entry> disk_entry_ = nullptr;
  raw_ptr<HttpCache::ActiveEntry> entry_ = nullptr;
  TestHttpCache test_cache_;

  // Should be before transactions_ since it is accessed in the network
  // transaction's destructor.
  MockHttpRequest request_;

  HttpResponseInfo response_info_;
  static const int kDefaultBufferSize = 256;

  std::vector<std::unique_ptr<TestHttpCacheTransaction>> transactions_;
};

const int WritersTest::kDefaultBufferSize;

// Tests successful addition of a transaction.
TEST_F(WritersTest, AddTransaction) {
  CreateWritersAddTransaction();
  EXPECT_FALSE(writers_->IsEmpty());

  // Verify keep_entry_ is true by default.
  EXPECT_TRUE(ShouldKeepEntry());
}

// Tests successful addition of multiple transactions.
TEST_F(WritersTest, AddManyTransactions) {
  CreateWritersAddTransaction();
  EXPECT_FALSE(writers_->IsEmpty());

  for (int i = 0; i < 5; i++) {
    AddTransactionToExistingWriters();
  }

  EXPECT_EQ(6, writers_->GetTransactionsCount());
}

// Tests that CanAddWriters should return false if it is writing exclusively.
TEST_F(WritersTest, AddTransactionsExclusive) {
  CreateWritersAddTransaction(HttpCache::PARALLEL_WRITING_NOT_JOIN_RANGE);
  EXPECT_FALSE(writers_->IsEmpty());

  EXPECT_FALSE(CanAddWriters());
}

// Tests StopCaching should not stop caching if there are multiple writers.
TEST_F(WritersTest, StopCachingMultipleWriters) {
  CreateWritersAddTransaction();
  EXPECT_FALSE(writers_->IsEmpty());

  EXPECT_TRUE(CanAddWriters());
  AddTransactionToExistingWriters();

  EXPECT_FALSE(StopCaching());
  EXPECT_TRUE(CanAddWriters());
}

// Tests StopCaching should stop caching if there is a single writer.
TEST_F(WritersTest, StopCaching) {
  CreateWritersAddTransaction();
  EXPECT_FALSE(writers_->IsEmpty());

  EXPECT_TRUE(StopCaching());
  EXPECT_FALSE(CanAddWriters());
}

// Tests that when the writers object completes, it passes any non-pending
// transactions to WritersDoneWritingToEntry.
TEST_F(WritersTest, MakeReaders) {
  CreateWritersAddTransaction();
  AddTransactionToExistingWriters();
  AddTransactionToExistingWriters();

  std::string remaining_content;
  Read(&remaining_content);

  EXPECT_EQ(1, test_cache_.WritersDoneWritingToEntryCount());
  EXPECT_FALSE(Truncated());
  EXPECT_EQ(2u, test_cache_.MakeReadersSize());
}

// Tests StopCaching should be successful when invoked mid-read.
TEST_F(WritersTest, StopCachingMidReadKeepEntry) {
  StopMidRead();

  // Stop caching and keep the entry after the transaction finishes.
  writers_->StopCaching(true /* keep_entry */);

  // Cannot add more writers while we are in network read-only state.
  EXPECT_FALSE(CanAddWriters());

  // Complete the pending read;
  base::RunLoop().RunUntilIdle();

  // Read the rest of the content and the cache entry should have truncated.
  std::string remaining_content;
  Read(&remaining_content);
  EXPECT_EQ(1, test_cache_.WritersDoneWritingToEntryCount());
  EXPECT_TRUE(Truncated());
}

// Tests StopCaching should be successful when invoked mid-read.
TEST_F(WritersTest, StopCachingMidReadDropEntry) {
  StopMidRead();

  writers_->StopCaching(false /* keep_entry */);

  // Cannot add more writers while we are in network read only state.
  EXPECT_FALSE(CanAddWriters());

  // Complete the pending read.
  base::RunLoop().RunUntilIdle();

  // Read the rest of the content and the cache entry shouldn't have truncated.
  std::string remaining_content;
  Read(&remaining_content);
  EXPECT_EQ(1, test_cache_.WritersDoneWritingToEntryCount());
  EXPECT_FALSE(Truncated());
}

// Tests removing of an idle transaction and change in priority.
TEST_F(WritersTest, RemoveIdleTransaction) {
  CreateWritersAddTransactionPriority(HIGHEST);
  UpdateAndVerifyPriority(HIGHEST);

  AddTransactionToExistingWriters();
  UpdateAndVerifyPriority(HIGHEST);

  EXPECT_FALSE(writers_->IsEmpty());
  EXPECT_EQ(2, writers_->GetTransactionsCount());

  RemoveFirstTransaction();
  EXPECT_EQ(1, writers_->GetTransactionsCount());

  UpdateAndVerifyPriority(DEFAULT_PRIORITY);
}

// Tests that Read is successful.
TEST_F(WritersTest, Read) {
  CreateWritersAddTransaction();
  EXPECT_FALSE(writers_->IsEmpty());

  std::string content;
  int rv = Read(&content);

  EXPECT_THAT(rv, IsOk());
  std::string expected(kSimpleGET_Transaction.data);
  EXPECT_EQ(expected, content);
}

// Tests that multiple transactions can read the same data simultaneously.
TEST_F(WritersTest, ReadMultiple) {
  CreateWritersAddTransaction();
  EXPECT_FALSE(writers_->IsEmpty());

  EXPECT_TRUE(CanAddWriters());
  AddTransactionToExistingWriters();
  AddTransactionToExistingWriters();

  ReadAll();

  EXPECT_EQ(1, test_cache_.WritersDoneWritingToEntryCount());
}

// Tests that multiple transactions can read the same data simultaneously.
TEST_F(WritersTest, ReadMultipleDifferentBufferSizes) {
  CreateWritersAddTransaction();
  EXPECT_FALSE(writers_->IsEmpty());

  EXPECT_TRUE(CanAddWriters());
  AddTransactionToExistingWriters();

  std::vector<int> buffer_lengths{20, 10};
  ReadVerifyTwoDifferentBufferLengths(buffer_lengths);
}

// Same as above but tests the first transaction having smaller buffer size
// than the next.
TEST_F(WritersTest, ReadMultipleDifferentBufferSizes1) {
  CreateWritersAddTransaction();
  EXPECT_FALSE(writers_->IsEmpty());

  EXPECT_TRUE(CanAddWriters());
  AddTransactionToExistingWriters();

  std::vector<int> buffer_lengths{10, 20};
  ReadVerifyTwoDifferentBufferLengths(buffer_lengths);
}

// Tests that ongoing Read completes even when active transaction is deleted
// mid-read. Any transactions waiting should be able to get the read buffer.
TEST_F(WritersTest, ReadMultipleDeleteActiveTransaction) {
  CreateWritersAddTransaction();
  EXPECT_FALSE(writers_->IsEmpty());

  EXPECT_TRUE(CanAddWriters());
  AddTransactionToExistingWriters();
  AddTransactionToExistingWriters();

  ReadAllDeleteTransaction(DeleteTransactionType::ACTIVE);
  EXPECT_EQ(1, test_cache_.WritersDoneWritingToEntryCount());
}

// Tests that ongoing Read is ignored when an active transaction is deleted
// mid-read and there are no more transactions. It should also successfully
// initiate truncation of the entry.
TEST_F(WritersTest, MidReadDeleteActiveTransaction) {
  StopMidRead();

  // Removed the transaction while the read is pending.
  RemoveFirstTransaction();

  EXPECT_EQ(1, test_cache_.WritersDoneWritingToEntryCount());
  EXPECT_TRUE(Truncated());
  EXPECT_TRUE(writers_->IsEmpty());
}

// Tests that removing a waiting for read transaction does not impact other
// transactions.
TEST_F(WritersTest, ReadMultipleDeleteWaitingTransaction) {
  CreateWritersAddTransaction();
  EXPECT_FALSE(writers_->IsEmpty());

  EXPECT_TRUE(CanAddWriters());
  AddTransactionToExistingWriters();
  AddTransactionToExistingWriters();
  AddTransactionToExistingWriters();

  std::vector<std::string> contents(4);
  ReadAllDeleteTransaction(DeleteTransactionType::WAITING);
}

// Tests that removing an idle transaction does not impact other transactions.
TEST_F(WritersTest, ReadMultipleDeleteIdleTransaction) {
  CreateWritersAddTransaction();
  EXPECT_FALSE(writers_->IsEmpty());

  EXPECT_TRUE(CanAddWriters());
  AddTransactionToExistingWriters();
  AddTransactionToExistingWriters();

  std::vector<std::string> contents(3);
  ReadAllDeleteTransaction(DeleteTransactionType::IDLE);
}

// Tests cache write failure.
TEST_F(WritersTest, ReadMultipleCacheWriteFailed) {
  CreateWritersAddTransaction();
  EXPECT_FALSE(writers_->IsEmpty());

  EXPECT_TRUE(CanAddWriters());
  AddTransactionToExistingWriters();
  AddTransactionToExistingWriters();

  std::vector<std::string> contents(3);
  int rv = ReadCacheWriteFailure(&contents);

  EXPECT_THAT(rv, IsOk());
  std::string expected(kSimpleGET_Transaction.data);

  // Only active_transaction_ should succeed.
  EXPECT_EQ(expected, contents.at(0));
}

// Tests that network read failure fails all transactions: active, waiting and
// idle.
TEST_F(WritersTest, ReadMultipleNetworkReadFailed) {
  ScopedMockTransaction transaction(kSimpleGET_Transaction,
                                    "http://failure.example/");
  transaction.read_return_code = ERR_INTERNET_DISCONNECTED;
  MockHttpRequest request(transaction);
  request_ = request;

  CreateWritersAddTransaction();
  EXPECT_FALSE(writers_->IsEmpty());

  EXPECT_TRUE(CanAddWriters());
  AddTransactionToExistingWriters();
  AddTransactionToExistingWriters();

  std::vector<std::string> contents(3);
  int rv = ReadNetworkFailure(&contents, ERR_INTERNET_DISCONNECTED);

  EXPECT_EQ(ERR_INTERNET_DISCONNECTED, rv);
}

// Tests GetLoadState.
TEST_F(WritersTest, GetLoadState) {
  CreateWritersAddTransaction();
  EXPECT_FALSE(writers_->IsEmpty());

  EXPECT_EQ(LOAD_STATE_IDLE, writers_->GetLoadState());
}

// Tests truncating logic.
TEST_F(WritersTest, TruncateEntryFail) {
  CreateWritersAddTransaction();

  EXPECT_FALSE(writers_->IsEmpty());

  RemoveFirstTransaction();

  // Should return false since no content was written to the entry.
  EXPECT_FALSE(ShouldTruncate());
  EXPECT_FALSE(ShouldKeepEntry());
}

// Set network read only.
TEST_F(WritersTest, StopCachingWithKeepEntry) {
  CreateWritersAddTransaction(HttpCache::PARALLEL_WRITING_NOT_JOIN_RANGE);
  EXPECT_FALSE(writers_->network_read_only());

  writers_->StopCaching(true /* keep_entry */);
  EXPECT_TRUE(writers_->network_read_only());
  EXPECT_TRUE(ShouldKeepEntry());
}

TEST_F(WritersTest, StopCachingWithNotKeepEntry) {
  CreateWritersAddTransaction(HttpCache::PARALLEL_WRITING_NOT_JOIN_RANGE);
  EXPECT_FALSE(writers_->network_read_only());

  writers_->StopCaching(false /* keep_entry */);
  EXPECT_TRUE(writers_->network_read_only());
  EXPECT_FALSE(ShouldKeepEntry());
}

// Tests that if content-encoding is set, the entry should not be marked as
// truncated, since we should not be creating range requests for compressed
// entries.
TEST_F(WritersTest, ContentEncodingShouldNotTruncate) {
  CreateWritersAddTransaction(HttpCache::PARALLEL_WRITING_JOIN,
                              true /* content_encoding_present */);
  std::string result;
  ReadFewBytes(&result);

  EXPECT_FALSE(ShouldTruncate());
  EXPECT_FALSE(ShouldKeepEntry());
}

}  // namespace net
```