Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Initial Scan and Purpose Identification:**  The file name `idb_cursor_unittest.cc` immediately suggests this is a unit test file specifically for the `IDBCursor` class. The `#include` directives confirm this, as `third_party/blink/renderer/modules/indexeddb/idb_cursor.h` is included. The presence of `testing/gtest/include/gtest/gtest.h` further reinforces that it's a Google Test-based unit test.

2. **High-Level Functionality Understanding:**  Reading the code, I see a `MockCursorImpl` class. This strongly indicates that the tests are not directly interacting with a real IndexedDB cursor implementation but using a mock object to control and verify interactions. The `IDBCursorTest` class then uses this mock to test different aspects of the `IDBCursor` class's behavior.

3. **Identifying Key Interactions (Mojo):**  The presence of `mojo/public/cpp/bindings/...` headers and the use of `mojo::AssociatedReceiver` and `mojo::AssociatedRemote` are crucial. This tells me that the `IDBCursor` class likely communicates with other components (potentially the browser process or a different thread) using Mojo inter-process communication. The tests will need to simulate these Mojo interactions using the mock.

4. **Identifying Key Concepts (IndexedDB):**  The file includes headers related to IndexedDB concepts: `IDBDatabase`, `IDBKey`, `IDBKeyRange`, `IDBObjectStore`, `IDBTransaction`, `IDBValue`. This confirms that the tests are focusing on the behavior of the cursor in the context of IndexedDB operations.

5. **Analyzing Individual Test Cases:** I go through each `TEST_F` function:
    * **`PrefetchTest`:**  The name suggests it's testing the prefetching mechanism of the cursor. I look for assertions (`EXPECT_EQ`, `EXPECT_GT`) related to the number of prefetch calls and the amount of data prefetched. The loop iterating up to `IDBCursor::kPrefetchContinueThreshold` and then the subsequent prefetch calls are the core of this test. The use of `SetPrefetchData` and simulating the consumption of cached data (`CursorContinue` calls after setting prefetch data) are important aspects.
    * **`AdvancePrefetchTest`:** This test seems to explore how `advance()` interacts with prefetching. I pay attention to the sequence of `CursorContinue` and `AdvanceImpl` calls and how they affect the prefetch cache and the underlying Mojo calls.
    * **`PrefetchReset`:**  This test focuses on when and how the prefetch cache is reset. The `ResetPrefetchCache()` call and the conditions under which `PrefetchReset` is called on the mock are the key elements.

6. **Connecting to Web Technologies (JavaScript, HTML, CSS):**  This requires understanding how IndexedDB is exposed to web developers.
    * **JavaScript:**  IndexedDB is a JavaScript API. The test file, although C++, is testing the *implementation* of that API. I think about how a developer would use `IDBCursor` in JavaScript (e.g., `openCursor()`, `continue()`, `advance()`). The C++ tests are simulating the underlying behavior that would be triggered by these JavaScript calls.
    * **HTML:** IndexedDB data is persisted by the browser and accessed through JavaScript in the context of a web page. The operations tested here are initiated from JavaScript running in an HTML page.
    * **CSS:** CSS is not directly related to IndexedDB's core functionality, which is data storage. However, CSS could *indirectly* be involved if changes to the UI are triggered based on data retrieved from IndexedDB. This connection is less direct.

7. **Inferring Logic and Input/Output:** For each test, I consider:
    * **Hypothetical Input:**  What actions by the JavaScript code would lead to the C++ `IDBCursor` methods being called (e.g., calling `cursor.continue()` repeatedly, calling `cursor.advance()`).
    * **Expected Output:** What the test asserts about the state of the mock object (e.g., the number of calls to `Prefetch`, `Advance`, `Continue`). This helps infer the intended behavior of the `IDBCursor` class.

8. **Identifying Common Usage Errors:**  I think about common mistakes developers might make when working with IndexedDB cursors:
    * Not handling asynchronous operations correctly.
    * Incorrectly using `continue()` and `advance()`.
    * Potential issues with transaction lifecycles. The tests implicitly cover some of these by verifying the core logic.

9. **Tracing User Operations:** This involves outlining the steps a user might take in a web browser that would eventually lead to the execution of the code being tested. This starts from user interaction in a webpage and goes down to the IndexedDB API calls and the underlying C++ implementation.

10. **Review and Refinement:**  I review my analysis to ensure it's accurate, comprehensive, and addresses all aspects of the prompt. I check for any logical inconsistencies or missing details. For example, ensuring I clearly explained the role of the mock object and how it facilitates testing.

This iterative process of reading the code, understanding the surrounding technologies (IndexedDB, Mojo), analyzing individual tests, and connecting it back to the user-facing aspects helps in generating a comprehensive explanation of the test file's functionality.
这个文件 `blink/renderer/modules/indexeddb/idb_cursor_unittest.cc` 是 Chromium Blink 引擎中用于测试 `IDBCursor` 类的单元测试文件。 它的主要功能是 **验证 `IDBCursor` 类的各种方法和行为是否符合预期**。

以下是更详细的功能分解以及与 JavaScript, HTML, CSS 的关系、逻辑推理、常见错误和调试线索：

**文件功能:**

1. **测试 `IDBCursor` 的基本操作:**
   - 测试 `continue()` 方法的行为，包括在达到预取阈值时的预取机制。
   - 测试 `advance()` 方法的行为，包括与预取的交互。
   - 测试游标的生命周期和销毁。

2. **验证预取机制:**
   - 测试当连续调用 `continue()` 时，`IDBCursor` 如何触发预取操作，以提高性能。
   - 验证预取请求的数量和大小是否符合预期。
   - 测试预取数据的使用和缓存机制。

3. **测试预取缓存的重置:**
   - 验证何时以及如何重置预取缓存，以保持数据一致性。

4. **使用 Mock 对象进行隔离测试:**
   - 使用 `MockCursorImpl` 模拟底层的 Mojo 接口 `mojom::blink::IDBCursor` 的行为，允许独立测试 `IDBCursor` 类的逻辑，而无需依赖真实的 IndexedDB 实现。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**  `IDBCursor` 是 IndexedDB API 的核心接口之一，开发者在 JavaScript 中使用它来遍历数据库中的记录。这个测试文件直接测试了 Blink 引擎中 `IDBCursor` 的 C++ 实现，这是 JavaScript IndexedDB API 的底层支撑。
    * **举例:**  当 JavaScript 代码调用 `IDBObjectStore.openCursor()` 或 `IDBIndex.openCursor()` 时，会创建一个 `IDBCursor` 对象。然后开发者可以调用 `cursor.continue()`、`cursor.advance(count)` 等方法来移动游标和获取数据。 这个测试文件就是模拟和验证这些操作在 C++ 层的实现逻辑。

* **HTML:**  HTML 页面通过嵌入的 JavaScript 代码来使用 IndexedDB。 用户在 HTML 页面上的交互（例如点击按钮触发数据加载或修改）可能会导致 JavaScript 代码操作 IndexedDB，进而涉及到 `IDBCursor` 的使用。
    * **举例:** 一个在线待办事项应用，用户点击 "显示已完成事项" 按钮，JavaScript 代码可能会打开一个游标来遍历标记为 "已完成" 的任务，并在页面上显示它们。

* **CSS:** CSS 主要负责页面的样式和布局，与 IndexedDB 的核心功能没有直接关系。 但是，从 IndexedDB 获取的数据最终会在 HTML 中呈现，CSS 可以用来设置这些数据的显示样式。

**逻辑推理 (假设输入与输出):**

假设 JavaScript 代码执行以下操作：

```javascript
const transaction = db.transaction(['myStore'], 'readonly');
const store = transaction.objectStore('myStore');
const request = store.openCursor();

request.onsuccess = function(event) {
  const cursor = event.target.result;
  if (cursor) {
    // 假设连续调用 continue()
    cursor.continue();
    cursor.continue();
    cursor.continue();
    // ... (重复多次直到超过预取阈值)
  }
};
```

**假设输入:**  JavaScript 代码连续调用 `cursor.continue()` 方法，并且次数超过了 `IDBCursor::kPrefetchContinueThreshold` (在代码中可以找到这个常量)。

**假设输出 (对应 `PrefetchTest`):**

* `mock_cursor_->continue_calls()` 的值会随着 JavaScript 的 `continue()` 调用而递增。
* 当连续调用次数达到阈值时，`IDBCursor` 会向底层的 `MockCursorImpl` 发起 `Prefetch` 调用。
* `mock_cursor_->prefetch_calls()` 的值会增加。
* `mock_cursor_->last_prefetch_count()` 的值会反映 `IDBCursor` 请求预取的记录数量。
* 后续的 `cursor.continue()` 调用，如果预取缓存中有数据，则不会立即触发底层的 Mojo 调用，而是先使用缓存中的数据。

**常见的使用错误:**

1. **未处理游标的完成状态:** 开发者可能忘记检查 `cursor` 是否为 null，导致在游标遍历结束后尝试操作它。
   ```javascript
   request.onsuccess = function(event) {
     const cursor = event.target.result;
     if (cursor) {
       // ... 操作 cursor
       cursor.continue();
     } else {
       // 游标遍历完成，需要进行相应的处理
       console.log("游标遍历完成");
     }
   };
   ```

2. **在错误的事务中操作游标:**  游标只能在其创建的事务中有效。如果在事务完成或中止后尝试使用游标，会导致错误。

3. **过度依赖预取假设:** 开发者不应假定预取总是会发生或总是会预取特定数量的数据。预取是优化手段，其行为可能受到多种因素影响。

4. **对游标进行同步操作:** IndexedDB 的操作是异步的。尝试同步地操作游标（例如在一个循环中立即调用多次 `continue()` 并期望立即得到所有结果）是不正确的。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在网页上进行操作:** 例如，用户点击了一个按钮，触发了一个 JavaScript 函数。

2. **JavaScript 代码执行:**
   - 该 JavaScript 函数包含了操作 IndexedDB 的代码。
   - 代码可能首先打开一个数据库连接 (`indexedDB.open()`).
   - 然后创建一个事务 (`db.transaction(...)`).
   - 接着打开一个对象仓库或索引的游标 (`store.openCursor()` 或 `index.openCursor()`).

3. **`openCursor()` 调用触发 Blink 引擎:**  JavaScript 的 `openCursor()` 调用会传递到 Blink 引擎的 C++ 层。

4. **创建 `IDBCursor` 对象:** Blink 引擎会创建 `IDBCursor` 的 C++ 对象，并关联相应的 Mojo 接口。

5. **JavaScript 调用 `cursor.continue()` 或 `cursor.advance()`:**
   - 这些 JavaScript 方法的调用会最终调用到 `IDBCursor` C++ 对象的对应方法 (`CursorContinue()`, `AdvanceImpl()`).

6. **`IDBCursor` 的逻辑执行:**
   - `IDBCursor` 会根据当前状态和预取机制，决定是直接返回缓存中的数据，还是通过 Mojo 接口向底层的 IndexedDB 实现发起请求 (`mock_cursor_->Prefetch()`, `mock_cursor_->Continue()`, `mock_cursor_->Advance()`).

7. **单元测试验证行为:**  `idb_cursor_unittest.cc` 中的测试代码就是模拟了 JavaScript 调用 `continue()` 和 `advance()` 等方法，并断言 `IDBCursor` 对象的行为是否符合预期，例如是否正确地发起了预取请求，预取的数量是否正确，以及在预取数据可用时是否使用了缓存。

**总结:**

`idb_cursor_unittest.cc` 是一个至关重要的测试文件，用于确保 Chromium Blink 引擎中 `IDBCursor` 类的正确性和性能。它通过模拟各种使用场景，验证了游标的基本操作和预取机制，有助于防止错误并提高 IndexedDB 的效率。理解这个文件有助于深入了解 IndexedDB 在浏览器中的实现细节以及如何与 JavaScript API 交互。

### 提示词
```
这是目录为blink/renderer/modules/indexeddb/idb_cursor_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/indexeddb/idb_cursor.h"

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <optional>
#include <utility>

#include "mojo/public/cpp/bindings/associated_receiver.h"
#include "mojo/public/cpp/bindings/associated_remote.h"
#include "mojo/public/cpp/bindings/pending_associated_receiver.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_blob_info.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_idbcursor_idbindex_idbobjectstore.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_idbindex_idbobjectstore.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_database.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_key_range.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_metadata.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_request.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_test_helper.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_transaction.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_value.h"
#include "third_party/blink/renderer/modules/indexeddb/mock_idb_database.h"
#include "third_party/blink/renderer/modules/indexeddb/mock_idb_transaction.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

static constexpr int64_t kStoreId = 5678;
static constexpr int64_t kTransactionId = 1234;

namespace {

class MockCursorImpl : public mojom::blink::IDBCursor {
 public:
  explicit MockCursorImpl(
      mojo::PendingAssociatedReceiver<mojom::blink::IDBCursor> receiver)
      : receiver_(this, std::move(receiver)) {
    receiver_.set_disconnect_handler(WTF::BindOnce(
        &MockCursorImpl::CursorDestroyed, WTF::Unretained(this)));
  }

  void Prefetch(int32_t count,
                mojom::blink::IDBCursor::PrefetchCallback callback) override {
    ++prefetch_calls_;
    last_prefetch_count_ = count;
    std::move(callback).Run(mojom::blink::IDBCursorResult::NewEmpty(true));
  }

  void PrefetchReset(int32_t used_prefetches) override {
    ++reset_calls_;
    last_used_count_ = used_prefetches;
  }

  void Advance(uint32_t count,
               mojom::blink::IDBCursor::AdvanceCallback callback) override {
    ++advance_calls_;
    std::move(callback).Run(mojom::blink::IDBCursorResult::NewEmpty(true));
  }

  void Continue(std::unique_ptr<IDBKey> key,
                std::unique_ptr<IDBKey> primary_key,
                mojom::blink::IDBCursor::ContinueCallback callback) override {
    ++continue_calls_;
    std::move(callback).Run(mojom::blink::IDBCursorResult::NewEmpty(true));
  }

  void CursorDestroyed() { destroyed_ = true; }

  int prefetch_calls() { return prefetch_calls_; }
  int last_prefetch_count() { return last_prefetch_count_; }
  int reset_calls() { return reset_calls_; }
  int last_used_count() { return last_used_count_; }
  int advance_calls() { return advance_calls_; }
  int continue_calls() { return continue_calls_; }
  bool destroyed() { return destroyed_; }

 private:
  int prefetch_calls_ = 0;
  int last_prefetch_count_ = 0;
  int reset_calls_ = 0;
  int last_used_count_ = 0;
  int advance_calls_ = 0;
  int continue_calls_ = 0;
  bool destroyed_ = false;

  mojo::AssociatedReceiver<mojom::blink::IDBCursor> receiver_;
};

}  // namespace

class IDBCursorTest : public testing::Test {
 public:
  IDBCursorTest() : null_key_(IDBKey::CreateNone()) {}

  void SetUpCursor(V8TestingScope& scope) {
    auto* execution_context = scope.GetExecutionContext();
    MockIDBDatabase mock_database;
    // Set up `transaction`.
    IDBDatabase* db = MakeGarbageCollected<IDBDatabase>(
        execution_context, mojo::NullAssociatedReceiver(), mojo::NullRemote(),
        mock_database.BindNewEndpointAndPassDedicatedRemote(), /*priority=*/0);

    MockIDBTransaction mock_transaction_remote;
    IDBTransaction::TransactionMojoRemote transaction_remote(execution_context);
    mojo::PendingAssociatedReceiver<mojom::blink::IDBTransaction> receiver =
        transaction_remote.BindNewEndpointAndPassReceiver(
            blink::scheduler::GetSingleThreadTaskRunnerForTesting());
    receiver.EnableUnassociatedUsage();
    mock_transaction_remote.Bind(std::move(receiver));

    HashSet<String> transaction_scope = {"store"};
    IDBTransaction* transaction = IDBTransaction::CreateNonVersionChange(
        scope.GetScriptState(), std::move(transaction_remote), kTransactionId,
        transaction_scope, mojom::IDBTransactionMode::ReadOnly,
        mojom::IDBTransactionDurability::Relaxed, db);

    // Set up `store`.
    IDBKeyPath store_key_path("primaryKey");
    scoped_refptr<IDBObjectStoreMetadata> store_metadata = base::AdoptRef(
        new IDBObjectStoreMetadata("store", kStoreId, store_key_path, true, 1));
    IDBObjectStore* store =
        MakeGarbageCollected<IDBObjectStore>(store_metadata, transaction);

    // Create a `request` and a `source`.
    IDBRequest* request =
        IDBRequest::Create(scope.GetScriptState(), store, transaction,
                           IDBRequest::AsyncTraceState());
    IDBCursor::Source* source =
        MakeGarbageCollected<IDBCursor::Source>(
          request->source(scope.GetScriptState())->GetAsIDBObjectStore());

    // Set up mojo endpoints.
    mojo::AssociatedRemote<mojom::blink::IDBCursor> remote;
    mock_cursor_ = std::make_unique<MockCursorImpl>(
        remote.BindNewEndpointAndPassDedicatedReceiver());
    cursor_ = MakeGarbageCollected<IDBCursor>(
        remote.Unbind(), mojom::blink::IDBCursorDirection::NextNoDuplicate,
        request,
        source,
        transaction);
  }

  // Disallow copy and assign.
  IDBCursorTest(const IDBCursorTest&) = delete;
  IDBCursorTest& operator=(const IDBCursorTest&) = delete;

 protected:
  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<TestingPlatformSupport> platform_;
  std::unique_ptr<IDBKey> null_key_;
  Persistent<IDBCursor> cursor_;
  std::unique_ptr<MockCursorImpl> mock_cursor_;
};

TEST_F(IDBCursorTest, PrefetchTest) {
  V8TestingScope scope;
  SetUpCursor(scope);
  // Call continue() until prefetching should kick in.
  int continue_calls = 0;
  EXPECT_EQ(mock_cursor_->continue_calls(), 0);
  for (int i = 0; i < IDBCursor::kPrefetchContinueThreshold; ++i) {
    cursor_->CursorContinue(null_key_.get(), null_key_.get(), nullptr);
    platform_->RunUntilIdle();
    EXPECT_EQ(++continue_calls, mock_cursor_->continue_calls());
    EXPECT_EQ(0, mock_cursor_->prefetch_calls());
  }

  // Do enough repetitions to verify that the count grows each time,
  // but not so many that the maximum limit is hit.
  const int kPrefetchRepetitions = 5;

  int expected_key = 0;
  int last_prefetch_count = 0;
  for (int repetitions = 0; repetitions < kPrefetchRepetitions; ++repetitions) {
    // Initiate the prefetch
    cursor_->CursorContinue(null_key_.get(), null_key_.get(), nullptr);
    platform_->RunUntilIdle();
    EXPECT_EQ(continue_calls, mock_cursor_->continue_calls());
    EXPECT_EQ(repetitions + 1, mock_cursor_->prefetch_calls());

    // Verify that the requested count has increased since last time.
    int prefetch_count = mock_cursor_->last_prefetch_count();
    EXPECT_GT(prefetch_count, last_prefetch_count);
    last_prefetch_count = prefetch_count;

    // Fill the prefetch cache as requested.
    Vector<std::unique_ptr<IDBKey>> keys;
    Vector<std::unique_ptr<IDBKey>> primary_keys;
    Vector<std::unique_ptr<IDBValue>> values;
    size_t expected_size = 0;
    for (int i = 0; i < prefetch_count; ++i) {
      std::unique_ptr<IDBKey> key = IDBKey::CreateNumber(expected_key + i);
      keys.emplace_back(std::move(key));
      primary_keys.emplace_back();
      expected_size++;
      EXPECT_EQ(expected_size, keys.size());
      EXPECT_EQ(expected_size, primary_keys.size());
      Vector<WebBlobInfo> blob_info;
      blob_info.ReserveInitialCapacity(expected_key + i);
      for (int j = 0; j < expected_key + i; ++j) {
        blob_info.emplace_back(WebBlobInfo::BlobForTesting(
            WebString("blobuuid"), "text/plain", 123));
      }
      values.emplace_back(
          std::make_unique<IDBValue>(Vector<char>(), std::move(blob_info)));
    }
    cursor_->SetPrefetchData(std::move(keys), std::move(primary_keys),
                             std::move(values));

    // Note that the real dispatcher would call cursor->CachedContinue()
    // immediately after cursor->SetPrefetchData() to service the request
    // that initiated the prefetch.

    // Verify that the cache is used for subsequent continue() calls.
    for (int i = 0; i < prefetch_count; ++i) {
      std::unique_ptr<IDBKey> key;
      Vector<WebBlobInfo> blobs;
      cursor_->CursorContinue(null_key_.get(), null_key_.get(), nullptr);
      platform_->RunUntilIdle();
      EXPECT_EQ(continue_calls, mock_cursor_->continue_calls());
      EXPECT_EQ(mock_cursor_->prefetch_calls(), repetitions + 1);
      EXPECT_EQ(cursor_->used_prefetches_, i + 1);
      EXPECT_EQ(static_cast<int>(cursor_->prefetch_keys_.size()),
                prefetch_count - cursor_->used_prefetches_);
    }
  }

  scope.GetExecutionContext()->NotifyContextDestroyed();
  platform_->RunUntilIdle();
  EXPECT_TRUE(mock_cursor_->destroyed());
}

TEST_F(IDBCursorTest, AdvancePrefetchTest) {
  V8TestingScope scope;
  SetUpCursor(scope);
  // Call continue() until prefetching should kick in.
  EXPECT_EQ(0, mock_cursor_->continue_calls());
  for (int i = 0; i < IDBCursor::kPrefetchContinueThreshold; ++i) {
    cursor_->CursorContinue(null_key_.get(), null_key_.get(), nullptr);
  }
  platform_->RunUntilIdle();
  EXPECT_EQ(0, mock_cursor_->prefetch_calls());

  // Initiate the prefetch
  cursor_->CursorContinue(null_key_.get(), null_key_.get(), nullptr);

  platform_->RunUntilIdle();
  EXPECT_EQ(1, mock_cursor_->prefetch_calls());
  EXPECT_EQ(static_cast<int>(IDBCursor::kPrefetchContinueThreshold),
            mock_cursor_->continue_calls());
  EXPECT_EQ(0, mock_cursor_->advance_calls());

  const int prefetch_count = mock_cursor_->last_prefetch_count();

  // Fill the prefetch cache as requested.
  int expected_key = 0;
  Vector<std::unique_ptr<IDBKey>> keys;
  Vector<std::unique_ptr<IDBKey>> primary_keys;
  Vector<std::unique_ptr<IDBValue>> values;
  size_t expected_size = 0;
  for (int i = 0; i < prefetch_count; ++i) {
    std::unique_ptr<IDBKey> key = IDBKey::CreateNumber(expected_key + i);
    keys.emplace_back(std::move(key));
    primary_keys.emplace_back();
    expected_size++;
    EXPECT_EQ(expected_size, keys.size());
    EXPECT_EQ(expected_size, primary_keys.size());
    Vector<WebBlobInfo> blob_info;
    blob_info.ReserveInitialCapacity(expected_key + i);
    for (int j = 0; j < expected_key + i; ++j) {
      blob_info.emplace_back(WebBlobInfo::BlobForTesting(WebString("blobuuid"),
                                                         "text/plain", 123));
    }
    values.emplace_back(
        std::make_unique<IDBValue>(Vector<char>(), std::move(blob_info)));
  }
  cursor_->SetPrefetchData(std::move(keys), std::move(primary_keys),
                           std::move(values));

  // Note that the real dispatcher would call cursor->CachedContinue()
  // immediately after cursor->SetPrefetchData() to service the request
  // that initiated the prefetch.

  // Need at least this many in the cache for the test steps.
  ASSERT_GE(prefetch_count, 5);

  // IDBCursor.continue()
  std::unique_ptr<IDBKey> key;
  EXPECT_EQ(0, cursor_->prefetch_keys_.back()->Number());
  cursor_->CursorContinue(null_key_.get(), null_key_.get(), nullptr);
  platform_->RunUntilIdle();
  EXPECT_EQ(1, cursor_->prefetch_keys_.back()->Number());

  // IDBCursor.advance(1)
  cursor_->AdvanceImpl(1, nullptr);
  platform_->RunUntilIdle();
  EXPECT_EQ(2, cursor_->prefetch_keys_.back()->Number());

  // IDBCursor.continue()
  EXPECT_EQ(2, cursor_->prefetch_keys_.back()->Number());
  cursor_->CursorContinue(null_key_.get(), null_key_.get(), nullptr);
  platform_->RunUntilIdle();
  EXPECT_EQ(3, cursor_->prefetch_keys_.back()->Number());

  // IDBCursor.advance(2)
  cursor_->AdvanceImpl(2, nullptr);
  platform_->RunUntilIdle();
  EXPECT_EQ(0u, cursor_->prefetch_keys_.size());

  EXPECT_EQ(0, mock_cursor_->advance_calls());

  // IDBCursor.advance(lots) - beyond the fetched amount
  cursor_->AdvanceImpl(IDBCursor::kMaxPrefetchAmount, nullptr);
  platform_->RunUntilIdle();
  EXPECT_EQ(1, mock_cursor_->advance_calls());
  EXPECT_EQ(1, mock_cursor_->prefetch_calls());
  EXPECT_EQ(static_cast<int>(IDBCursor::kPrefetchContinueThreshold),
            mock_cursor_->continue_calls());

  scope.GetExecutionContext()->NotifyContextDestroyed();
  platform_->RunUntilIdle();
  EXPECT_TRUE(mock_cursor_->destroyed());
}

TEST_F(IDBCursorTest, PrefetchReset) {
  V8TestingScope scope;
  SetUpCursor(scope);
  // Call continue() until prefetching should kick in.
  int continue_calls = 0;
  EXPECT_EQ(mock_cursor_->continue_calls(), 0);
  for (int i = 0; i < IDBCursor::kPrefetchContinueThreshold; ++i) {
    cursor_->CursorContinue(null_key_.get(), null_key_.get(), nullptr);
    platform_->RunUntilIdle();
    EXPECT_EQ(++continue_calls, mock_cursor_->continue_calls());
    EXPECT_EQ(0, mock_cursor_->prefetch_calls());
  }

  // Initiate the prefetch
  cursor_->CursorContinue(null_key_.get(), null_key_.get(), nullptr);
  platform_->RunUntilIdle();
  EXPECT_EQ(continue_calls, mock_cursor_->continue_calls());
  EXPECT_EQ(1, mock_cursor_->prefetch_calls());
  EXPECT_EQ(0, mock_cursor_->reset_calls());

  // Now invalidate it
  cursor_->ResetPrefetchCache();

  // No reset should have been sent since nothing has been received yet.
  platform_->RunUntilIdle();
  EXPECT_EQ(0, mock_cursor_->reset_calls());

  // Fill the prefetch cache as requested.
  int prefetch_count = mock_cursor_->last_prefetch_count();
  Vector<std::unique_ptr<IDBKey>> keys(prefetch_count);
  Vector<std::unique_ptr<IDBKey>> primary_keys(prefetch_count);
  Vector<std::unique_ptr<IDBValue>> values;
  for (int i = 0; i < prefetch_count; ++i) {
    values.emplace_back(
        std::make_unique<IDBValue>(Vector<char>(), Vector<WebBlobInfo>()));
  }
  cursor_->SetPrefetchData(std::move(keys), std::move(primary_keys),
                           std::move(values));

  // No reset should have been sent since prefetch data hasn't been used.
  platform_->RunUntilIdle();
  EXPECT_EQ(0, mock_cursor_->reset_calls());

  // The real dispatcher would call cursor->CachedContinue(), so do that:
  cursor_->CachedContinue(nullptr);

  // Now the cursor should have reset the rest of the cache.
  platform_->RunUntilIdle();
  EXPECT_EQ(1, mock_cursor_->reset_calls());
  EXPECT_EQ(1, mock_cursor_->last_used_count());

  scope.GetExecutionContext()->NotifyContextDestroyed();
  platform_->RunUntilIdle();
  EXPECT_TRUE(mock_cursor_->destroyed());
}

}  // namespace blink
```