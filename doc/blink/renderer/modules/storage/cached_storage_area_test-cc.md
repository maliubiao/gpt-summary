Response:
The user wants to understand the functionality of the `cached_storage_area_test.cc` file in the Chromium Blink engine. I need to analyze the code provided and identify its purpose, especially in relation to JavaScript, HTML, and CSS. I should also consider common user or programming errors, provide debugging hints, and summarize the file's function.

**Plan:**

1. **Identify the main class being tested:** `CachedStorageArea`.
2. **Determine the purpose of the tests:** Verify the functionality of `CachedStorageArea`, which seems to be a local cache for storage data (likely localStorage and sessionStorage).
3. **Analyze the test cases:** Look for patterns in the tests that reveal the features being tested, such as:
    - Getting, setting, and removing items.
    - Clearing the storage area.
    - Handling browser disconnections and reconnections.
    - Managing remote updates and conflicts.
    - Dispatching storage events.
    - Handling failures during storage operations.
4. **Relate to web technologies:** Explain how these storage operations connect to JavaScript's `localStorage` and `sessionStorage` APIs.
5. **Provide examples:**  Illustrate the connection with code snippets and user actions.
6. **Consider errors:**  Think about scenarios where things might go wrong for developers or users interacting with storage.
7. **Outline debugging steps:**  Suggest how a developer might use this file to understand storage issues.
8. **Summarize the functionality.**
这是 `blink/renderer/modules/storage/cached_storage_area_test.cc` 文件的第 1 部分，该文件是 Chromium Blink 引擎的源代码，专门用于测试 `CachedStorageArea` 类的功能。`CachedStorageArea` 似乎是 Blink 中用于缓存本地存储 (localStorage) 和会话存储 (sessionStorage) 数据的组件。

**功能归纳（第 1 部分）：**

这个文件的主要功能是为 `CachedStorageArea` 类编写单元测试，以验证其各种操作的正确性。这些测试覆盖了以下核心功能：

1. **基本操作：**
   - 获取、设置和删除存储项 (`SetItem`, `GetItem`, `RemoveItem`)。
   - 获取存储项的数量 (`GetLength`)。
   - 获取指定索引的键 (`GetKey`)。
   - 清空存储区域 (`Clear`)。

2. **缓存管理：**
   - 验证缓存是否按需加载。
   - 模拟浏览器断开连接和重新连接，测试缓存的恢复和同步机制 (`BrowserDisconnect`, `ResetConnection`).

3. **数据同步和冲突解决 (部分涉及)：**
   - 测试在连接重置时，本地缓存如何与后端存储同步，并处理数据差异 (`ResetConnectionWithNoDelta`, `ResetConnectionWithKeyDiff`, `ResetConnectionWithMissingBackendKey`, `ResetConnectionWithMissingLocalKey`, `ResetConnectionWithComplexDiff`)。  这部分的代码暗示了 `CachedStorageArea` 在本地存储和会话存储的处理方式上可能存在差异。

4. **事件处理：**
   - 测试在存储数据发生变化时，如何生成和分发存储事件 (`SetItem`, `Clear_WithData`, `RemoveItem`)。 这涉及到模拟不同的 `AreaSource` (表示不同的浏览上下文) 以验证事件的正确广播。

5. **事务和原子性 (通过 `SetItemCheckpoints` 测试推断)：**
   - 测试在同一任务中多次修改存储项时，是否会生成预期的检查点，这可能与事务的实现有关。

6. **错误处理 (通过 `KeyMutationsAreIgnoredUntilCompletion` 和 `RevertOnChangeFailed` 等测试推断)：**
   - 测试在存储操作进行中接收到远程修改时，本地缓存的处理方式。
   - 测试当本地存储操作失败时，缓存的回滚机制。

**与 JavaScript, HTML, CSS 的关系：**

`CachedStorageArea` 直接关联到 JavaScript 中用于访问本地存储和会话存储的 API：`window.localStorage` 和 `window.sessionStorage`。

* **JavaScript:** 当 JavaScript 代码调用 `localStorage.setItem('key', 'value')` 或 `sessionStorage.getItem('key')` 等方法时，Blink 引擎内部最终会与 `CachedStorageArea` 交互。`CachedStorageArea` 负责管理这些数据的本地缓存，并与底层的存储机制进行同步。

   **举例说明：**
   ```javascript
   // JavaScript 代码
   localStorage.setItem('myKey', 'myValue');
   let value = localStorage.getItem('myKey');
   console.log(value); // 输出 "myValue"
   ```
   在这个例子中，`CachedStorageArea` 的 `SetItem` 方法会被调用来缓存 'myKey' 和 'myValue'。后续的 `getItem` 调用会先尝试从 `CachedStorageArea` 的缓存中获取，如果缓存中没有，则会触发缓存加载或从底层存储读取。

* **HTML:** HTML 本身不直接与 `CachedStorageArea` 交互，但 HTML 中嵌入的 JavaScript 代码可以使用 `localStorage` 和 `sessionStorage` API。

* **CSS:** CSS 与 `CachedStorageArea` 没有直接关系。

**逻辑推理的假设输入与输出：**

以下是一些基于代码和测试用例名称的逻辑推理示例：

* **假设输入:** 调用 `cached_area_->SetItem("testKey", "testValue", source_area_)`。
* **预期输出:**
    - `cached_area_->GetLength()` 返回的值增加 1。
    - `cached_area_->GetItem("testKey")` 返回 "testValue"。
    - 如果是本地存储，`mock_storage_area_.observed_puts()` 应该包含一个表示插入操作的记录。
    - 其他浏览上下文 (由 `source_area2_` 代表) 应该接收到一个存储事件。

* **假设输入:** 在缓存中已存在键 "existingKey" 和值 "oldValue" 的情况下，调用 `cached_area_->RemoveItem("existingKey", source_area_)`。
* **预期输出:**
    - `cached_area_->GetLength()` 返回的值减少 1。
    - `cached_area_->GetItem("existingKey")` 返回 `IsNull()` 或空值。
    - `mock_storage_area_.observed_deletes()` 应该包含一个表示删除操作的记录。
    - 其他浏览上下文应该接收到一个存储事件，指示键 "existingKey" 被删除，旧值为 "oldValue"。

**涉及用户或编程常见的使用错误：**

* **并发修改问题：** 如果多个页面或标签页同时修改同一存储区域的数据，可能会导致数据不一致。`CachedStorageArea` 似乎有机制来处理这些情况，例如通过忽略在本地修改完成前的远程修改 (`KeyMutationsAreIgnoredUntilCompletion` 测试)。

* **数据类型错误：** 虽然 `localStorage` 和 `sessionStorage` 存储的是字符串，但开发者可能会尝试存储其他类型的数据。这通常会被转换为字符串，可能会导致意外的结果。`CachedStorageArea` 的测试中使用了 `StringToUint8Vector` 和 `Uint8VectorToString`，暗示了数据在存储时的编码处理。

* **超出存储容量限制：** 浏览器对 `localStorage` 和 `sessionStorage` 的存储容量有限制。当超出限制时，`setItem` 操作可能会失败。`RevertOnChangeFailed` 相关的测试可能与处理这类失败情况有关。

**用户操作如何一步步到达这里，作为调试线索：**

假设用户在浏览器中遇到了 `localStorage` 或 `sessionStorage` 相关的问题，例如数据丢失、数据不一致或存储操作失败。以下是一些可能导致开发人员查看 `cached_storage_area_test.cc` 的步骤：

1. **用户报告问题：** 用户反馈网站的某些功能（依赖本地存储或会话存储）无法正常工作，例如用户设置丢失、购物车信息不正确等。
2. **开发者检查前端代码：** 开发者首先会检查 JavaScript 代码中对 `localStorage` 或 `sessionStorage` 的使用，查看是否有明显的逻辑错误。
3. **网络面板检查：** 开发者可能会使用浏览器的开发者工具的网络面板，查看是否有与存储相关的网络请求失败或异常。
4. **控制台输出检查：** 开发者会检查控制台是否有与存储相关的错误或警告信息。
5. **Blink 引擎调试：** 如果前端代码没有明显错误，并且怀疑是浏览器底层的存储实现出现了问题，开发者可能需要深入 Blink 引擎进行调试。
6. **定位 `CachedStorageArea`：** 开发者可能会根据函数调用栈或代码搜索，定位到 `CachedStorageArea` 类，因为它负责缓存和管理存储数据。
7. **查看 `cached_storage_area_test.cc`：**  为了理解 `CachedStorageArea` 的工作原理和预期行为，开发者会查看其单元测试文件 `cached_storage_area_test.cc`。通过阅读测试用例，开发者可以了解 `CachedStorageArea` 的各种功能、边界条件以及错误处理机制。例如，如果怀疑是并发修改导致的问题，开发者可能会重点关注与事件处理和数据同步相关的测试用例。
8. **添加断点和日志：** 开发者可以在 `CachedStorageArea` 的相关代码中添加断点和日志，以便在浏览器运行时跟踪存储操作的执行过程，查看数据是如何被缓存、同步和更新的。

总而言之，`cached_storage_area_test.cc` 是理解 Blink 引擎中本地存储和会话存储实现细节的重要入口，它可以帮助开发者验证自己的假设，定位问题根源。

### 提示词
```
这是目录为blink/renderer/modules/storage/cached_storage_area_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/storage/cached_storage_area.h"

#include <tuple>

#include "base/memory/scoped_refptr.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/modules/storage/storage_controller.h"
#include "third_party/blink/renderer/modules/storage/storage_namespace.h"
#include "third_party/blink/renderer/modules/storage/testing/fake_area_source.h"
#include "third_party/blink/renderer/modules/storage/testing/mock_storage_area.h"
#include "third_party/blink/renderer/platform/testing/scoped_mocked_url.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

using FormatOption = CachedStorageArea::FormatOption;
using ::testing::ElementsAre;
using ::testing::UnorderedElementsAre;

class CachedStorageAreaTest : public testing::Test {
 public:
  const String kKey = "key";
  const String kValue = "value";
  const String kValue2 = "another value";
  const std::string kRootString = "http://dom_storage/";
  const KURL kRootUrl = KURL(kRootString.c_str());
  const BlinkStorageKey kRootStorageKey =
      BlinkStorageKey::CreateFromStringForTesting(kRootString.c_str());
  const std::string kPageString = "http://dom_storage/page";
  const KURL kPageUrl = KURL(kPageString.c_str());
  const std::string kPageString2 = "http://dom_storage/other_page";
  const KURL kPageUrl2 = KURL(kPageString2.c_str());
  const String kRemoteSourceId = "1234";
  const String kRemoteSource = kPageUrl2.GetString() + "\n" + kRemoteSourceId;

  void SetUp() override {
    const CachedStorageArea::AreaType area_type =
        IsSessionStorage() ? CachedStorageArea::AreaType::kSessionStorage
                           : CachedStorageArea::AreaType::kLocalStorage;
    test::ScopedMockedURLLoad scoped_mocked_url_load_root(
        kRootUrl, test::CoreTestDataPath("foo.html"));
    LocalDOMWindow* local_dom_window_root =
        To<LocalDOMWindow>(web_view_helper_root_.InitializeAndLoad(kRootString)
                               ->GetPage()
                               ->MainFrame()
                               ->DomWindow());
    cached_area_ = base::MakeRefCounted<CachedStorageArea>(
        area_type, kRootStorageKey, local_dom_window_root, nullptr,
        /*is_session_storage_for_prerendering=*/false);
    cached_area_->SetRemoteAreaForTesting(
        mock_storage_area_.GetInterfaceRemote());
    test::ScopedMockedURLLoad scoped_mocked_url_load(
        kPageUrl, test::CoreTestDataPath("foo.html"));
    LocalDOMWindow* local_dom_window =
        To<LocalDOMWindow>(web_view_helper_.InitializeAndLoad(kPageString)
                               ->GetPage()
                               ->MainFrame()
                               ->DomWindow());
    source_area_ =
        MakeGarbageCollected<FakeAreaSource>(kPageUrl, local_dom_window);
    source_area_id_ = cached_area_->RegisterSource(source_area_);
    source_ = kPageUrl.GetString() + "\n" + source_area_id_;
    test::ScopedMockedURLLoad scoped_mocked_url_load2(
        kPageUrl2, test::CoreTestDataPath("foo.html"));
    LocalDOMWindow* local_dom_window2 =
        To<LocalDOMWindow>(web_view_helper2_.InitializeAndLoad(kPageString2)
                               ->GetPage()
                               ->MainFrame()
                               ->DomWindow());
    source_area2_ =
        MakeGarbageCollected<FakeAreaSource>(kPageUrl2, local_dom_window2);
    cached_area_->RegisterSource(source_area2_);
  }

  virtual bool IsSessionStorage() { return false; }

  bool IsCacheLoaded() { return cached_area_->map_.get(); }

  bool IsIgnoringKeyMutations(const String& key) {
    return cached_area_->pending_mutations_by_key_.Contains(key);
  }

  static Vector<uint8_t> StringToUint8Vector(const String& input,
                                             FormatOption format) {
    return CachedStorageArea::StringToUint8Vector(input, format);
  }

  static String Uint8VectorToString(const Vector<uint8_t>& input,
                                    FormatOption format) {
    return CachedStorageArea::Uint8VectorToString(input, format);
  }

  Vector<uint8_t> KeyToUint8Vector(const String& key) {
    return StringToUint8Vector(
        key, IsSessionStorage() ? FormatOption::kSessionStorageForceUTF8
                                : FormatOption::kLocalStorageDetectFormat);
  }

  Vector<uint8_t> ValueToUint8Vector(const String& value) {
    return StringToUint8Vector(
        value, IsSessionStorage() ? FormatOption::kSessionStorageForceUTF16
                                  : FormatOption::kLocalStorageDetectFormat);
  }

  String KeyFromUint8Vector(const Vector<uint8_t>& key) {
    return Uint8VectorToString(
        key, IsSessionStorage() ? FormatOption::kSessionStorageForceUTF8
                                : FormatOption::kLocalStorageDetectFormat);
  }

  String ValueFromUint8Vector(const Vector<uint8_t>& value) {
    return Uint8VectorToString(
        value, IsSessionStorage() ? FormatOption::kSessionStorageForceUTF16
                                  : FormatOption::kLocalStorageDetectFormat);
  }

  MockStorageArea::ObservedPut ObservedPut(const String& key,
                                           const String& value,
                                           const String& source) {
    return MockStorageArea::ObservedPut{KeyToUint8Vector(key),
                                        ValueToUint8Vector(value), source};
  }

  MockStorageArea::ObservedDelete ObservedDelete(const String& key,
                                                 const String& source) {
    return MockStorageArea::ObservedDelete{KeyToUint8Vector(key), source};
  }

  FakeAreaSource::Event Event(const String& key,
                              const String& old_value,
                              const String& new_value) {
    return FakeAreaSource::Event{key, old_value, new_value, ""};
  }

  void InjectKeyValue(const String& key, const String& value) {
    mock_storage_area_.InjectKeyValue(KeyToUint8Vector(key),
                                      ValueToUint8Vector(value));
  }

 protected:
  test::TaskEnvironment task_environment_;
  MockStorageArea mock_storage_area_;
  Persistent<FakeAreaSource> source_area_;
  Persistent<FakeAreaSource> source_area2_;
  scoped_refptr<CachedStorageArea> cached_area_;
  String source_area_id_;
  String source_;
  frame_test_helpers::WebViewHelper web_view_helper_root_;
  frame_test_helpers::WebViewHelper web_view_helper_;
  frame_test_helpers::WebViewHelper web_view_helper2_;
};

class CachedStorageAreaTestWithParam
    : public CachedStorageAreaTest,
      public testing::WithParamInterface<bool> {
 public:
  bool IsSessionStorage() override { return GetParam(); }
};

INSTANTIATE_TEST_SUITE_P(CachedStorageAreaTest,
                         CachedStorageAreaTestWithParam,
                         ::testing::Bool());

TEST_P(CachedStorageAreaTestWithParam, Basics) {
  EXPECT_FALSE(IsCacheLoaded());

  EXPECT_EQ(0u, cached_area_->GetLength());
  EXPECT_TRUE(cached_area_->SetItem(kKey, kValue, source_area_));
  EXPECT_EQ(1u, cached_area_->GetLength());
  EXPECT_EQ(kKey, cached_area_->GetKey(0));
  EXPECT_EQ(kValue, cached_area_->GetItem(kKey));
  cached_area_->RemoveItem(kKey, source_area_);
  EXPECT_EQ(0u, cached_area_->GetLength());

  mock_storage_area_.Flush();
  EXPECT_EQ(1u, mock_storage_area_.observer_count());
}

TEST_P(CachedStorageAreaTestWithParam, GetLength) {
  // Expect GetLength to load the cache.
  EXPECT_FALSE(IsCacheLoaded());
  EXPECT_EQ(0u, cached_area_->GetLength());
  EXPECT_TRUE(IsCacheLoaded());
  EXPECT_EQ(1, mock_storage_area_.observed_get_alls());
}

TEST_P(CachedStorageAreaTestWithParam, GetKey) {
  // Expect GetKey to load the cache.
  EXPECT_FALSE(IsCacheLoaded());
  EXPECT_TRUE(cached_area_->GetKey(2).IsNull());
  EXPECT_TRUE(IsCacheLoaded());
  EXPECT_EQ(1, mock_storage_area_.observed_get_alls());
}

TEST_P(CachedStorageAreaTestWithParam, GetItem) {
  // Expect GetItem to load the cache.
  EXPECT_FALSE(IsCacheLoaded());
  EXPECT_TRUE(cached_area_->GetItem(kKey).IsNull());
  EXPECT_TRUE(IsCacheLoaded());
  EXPECT_EQ(1, mock_storage_area_.observed_get_alls());
}

TEST_P(CachedStorageAreaTestWithParam, SetItem) {
  // Expect SetItem to load the cache and then generate a change event.
  EXPECT_FALSE(IsCacheLoaded());
  EXPECT_TRUE(cached_area_->SetItem(kKey, kValue, source_area_));
  EXPECT_TRUE(IsCacheLoaded());
  EXPECT_EQ(1, mock_storage_area_.observed_get_alls());

  mock_storage_area_.Flush();
  EXPECT_THAT(mock_storage_area_.observed_puts(),
              ElementsAre(ObservedPut(kKey, kValue, source_)));

  EXPECT_TRUE(source_area_->events.empty());
  if (IsSessionStorage()) {
    ASSERT_EQ(1u, source_area2_->events.size());
    EXPECT_EQ(kKey, source_area2_->events[0].key);
    EXPECT_TRUE(source_area2_->events[0].old_value.IsNull());
    EXPECT_EQ(kValue, source_area2_->events[0].new_value);
    EXPECT_EQ(kPageUrl, source_area2_->events[0].url);
  } else {
    EXPECT_TRUE(source_area2_->events.empty());
  }
}

// Verify that regardless of how many times `SetItem` is called in one task,
// only one checkpoint is generated.
TEST_P(CachedStorageAreaTestWithParam, SetItemCheckpoints) {
  EXPECT_TRUE(cached_area_->SetItem(kKey, kValue, source_area_));
  EXPECT_EQ(mock_storage_area_.observed_checkpoints(), 0U);
  task_environment_.RunUntilIdle();
  EXPECT_EQ(mock_storage_area_.observed_checkpoints(), 1U);

  EXPECT_TRUE(cached_area_->SetItem(kKey, kValue2, source_area_));
  EXPECT_TRUE(cached_area_->SetItem(kKey, kValue, source_area_));
  EXPECT_TRUE(cached_area_->SetItem("key2", kValue, source_area_));
  EXPECT_EQ(mock_storage_area_.observed_checkpoints(), 1U);
  task_environment_.RunUntilIdle();
  EXPECT_EQ(mock_storage_area_.observed_checkpoints(), 2U);
}

TEST_P(CachedStorageAreaTestWithParam, Clear_AlreadyEmpty) {
  // Clear, we expect just the one call to clear in the db since
  // there's no need to load the data prior to deleting it.
  // Except if we're testing session storage, in which case we also expect a
  // load call first, since it needs that for event dispatching.
  EXPECT_FALSE(IsCacheLoaded());
  cached_area_->Clear(source_area_);
  mock_storage_area_.Flush();
  EXPECT_TRUE(IsCacheLoaded());
  EXPECT_THAT(mock_storage_area_.observed_delete_alls(), ElementsAre(source_));
  if (IsSessionStorage()) {
    EXPECT_EQ(1, mock_storage_area_.observed_get_alls());
  } else {
    EXPECT_EQ(0, mock_storage_area_.observed_get_alls());
  }

  // Neither should have events since area was already empty.
  EXPECT_TRUE(source_area_->events.empty());
  EXPECT_TRUE(source_area2_->events.empty());
}

TEST_P(CachedStorageAreaTestWithParam, Clear_WithData) {
  InjectKeyValue(kKey, kValue);

  EXPECT_FALSE(IsCacheLoaded());
  cached_area_->Clear(source_area_);
  mock_storage_area_.Flush();
  EXPECT_TRUE(IsCacheLoaded());
  EXPECT_THAT(mock_storage_area_.observed_delete_alls(), ElementsAre(source_));
  if (IsSessionStorage()) {
    EXPECT_EQ(1, mock_storage_area_.observed_get_alls());
  } else {
    EXPECT_EQ(0, mock_storage_area_.observed_get_alls());
  }

  EXPECT_TRUE(source_area_->events.empty());
  if (IsSessionStorage()) {
    ASSERT_EQ(1u, source_area2_->events.size());
    EXPECT_TRUE(source_area2_->events[0].key.IsNull());
    EXPECT_TRUE(source_area2_->events[0].old_value.IsNull());
    EXPECT_TRUE(source_area2_->events[0].new_value.IsNull());
    EXPECT_EQ(kPageUrl, source_area2_->events[0].url);
  } else {
    EXPECT_TRUE(source_area2_->events.empty());
  }
}

TEST_P(CachedStorageAreaTestWithParam, RemoveItem_NothingToRemove) {
  // RemoveItem with nothing to remove, expect just one call to load.
  EXPECT_FALSE(IsCacheLoaded());
  cached_area_->RemoveItem(kKey, source_area_);
  mock_storage_area_.Flush();
  EXPECT_TRUE(IsCacheLoaded());
  EXPECT_EQ(1, mock_storage_area_.observed_get_alls());
  EXPECT_TRUE(mock_storage_area_.observed_deletes().empty());

  // Neither should have events since area was already empty.
  EXPECT_TRUE(source_area_->events.empty());
  EXPECT_TRUE(source_area2_->events.empty());
}

TEST_P(CachedStorageAreaTestWithParam, RemoveItem) {
  // RemoveItem with something to remove, expect a call to load followed
  // by a call to remove.
  InjectKeyValue(kKey, kValue);

  EXPECT_FALSE(IsCacheLoaded());
  cached_area_->RemoveItem(kKey, source_area_);
  mock_storage_area_.Flush();
  EXPECT_TRUE(IsCacheLoaded());
  EXPECT_EQ(1, mock_storage_area_.observed_get_alls());
  EXPECT_THAT(mock_storage_area_.observed_deletes(),
              ElementsAre(ObservedDelete(kKey, source_)));

  EXPECT_TRUE(source_area_->events.empty());
  if (IsSessionStorage()) {
    ASSERT_EQ(1u, source_area2_->events.size());
    EXPECT_EQ(kKey, source_area2_->events[0].key);
    EXPECT_EQ(kValue, source_area2_->events[0].old_value);
    EXPECT_TRUE(source_area2_->events[0].new_value.IsNull());
    EXPECT_EQ(kPageUrl, source_area2_->events[0].url);
  } else {
    EXPECT_TRUE(source_area2_->events.empty());
  }
}

TEST_P(CachedStorageAreaTestWithParam, BrowserDisconnect) {
  InjectKeyValue(kKey, kValue);

  // GetLength to prime the cache.
  EXPECT_EQ(1u, cached_area_->GetLength());
  EXPECT_TRUE(IsCacheLoaded());
  mock_storage_area_.ResetObservations();

  // Now disconnect the pipe from the browser, simulating situations where the
  // browser might be forced to destroy the LevelDBWrapperImpl.
  mock_storage_area_.CloseAllBindings();

  // Getters should still function.
  EXPECT_EQ(1u, cached_area_->GetLength());
  EXPECT_EQ(kValue, cached_area_->GetItem(kKey));

  // And setters should also still function.
  cached_area_->RemoveItem(kKey, source_area_);
  EXPECT_EQ(0u, cached_area_->GetLength());
  EXPECT_TRUE(cached_area_->GetItem(kKey).IsNull());
}

TEST_P(CachedStorageAreaTestWithParam, ResetConnectionWithNoDelta) {
  const String kKey1 = "key1";
  const String kValue1 = "value1";
  const String kKey2 = "key2";
  const String kValue2 = "value2";
  InjectKeyValue(kKey1, kValue1);
  InjectKeyValue(kKey2, kValue2);

  // Prime the cache.
  EXPECT_EQ(2u, cached_area_->GetLength());
  EXPECT_TRUE(IsCacheLoaded());
  EXPECT_EQ(1, mock_storage_area_.observed_get_alls());

  // Simulate a connection reset, which should always re-initialize the local
  // cache.
  cached_area_->ResetConnection(mock_storage_area_.GetInterfaceRemote());
  EXPECT_TRUE(IsCacheLoaded());
  EXPECT_EQ(2, mock_storage_area_.observed_get_alls());
  EXPECT_EQ(2u, cached_area_->GetLength());

  // Cached values should be unchanged for both Session and Local Storage.
  EXPECT_EQ(kValue1, cached_area_->GetItem(kKey1));
  EXPECT_EQ(kValue2, cached_area_->GetItem(kKey2));

  // There should be no observed operations on the backend.
  mock_storage_area_.Flush();
  EXPECT_TRUE(mock_storage_area_.observed_puts().empty());
  EXPECT_TRUE(mock_storage_area_.observed_deletes().empty());

  // There should also be no generated storage events.
  EXPECT_TRUE(source_area_->events.empty());
}

TEST_P(CachedStorageAreaTestWithParam, ResetConnectionWithKeyDiff) {
  const String kKey1 = "key1";
  const String kValue1 = "value1";
  const String kKey2 = "key2";
  const String kCachedValue2 = "cached_value2";
  const String kPersistedValue2 = "persisted_value2";
  InjectKeyValue(kKey1, kValue1);
  InjectKeyValue(kKey2, kCachedValue2);

  // Prime the cache.
  EXPECT_EQ(2u, cached_area_->GetLength());
  EXPECT_TRUE(IsCacheLoaded());
  EXPECT_EQ(1, mock_storage_area_.observed_get_alls());

  // Now modify the backend so it's out of sync with the cache. Namely, the
  // value of |kKey2| is no different.
  mock_storage_area_.Clear();
  InjectKeyValue(kKey1, kValue1);
  InjectKeyValue(kKey2, kPersistedValue2);

  // Resetting the connection should re-initialize the local cache, with
  // different outcomes for Local and Session Storage.
  cached_area_->ResetConnection(mock_storage_area_.GetInterfaceRemote());
  EXPECT_TRUE(IsCacheLoaded());
  EXPECT_EQ(2, mock_storage_area_.observed_get_alls());
  EXPECT_EQ(2u, cached_area_->GetLength());
  EXPECT_EQ(kValue1, cached_area_->GetItem(kKey1));
  mock_storage_area_.Flush();

  if (IsSessionStorage()) {
    // For Session Storage, we expect the local cache to push changes to the
    // backend, as the local cache is the source of truth.
    EXPECT_EQ(kCachedValue2, cached_area_->GetItem(kKey2));
    EXPECT_THAT(mock_storage_area_.observed_puts(),
                ElementsAre(ObservedPut(kKey2, kCachedValue2, "\n")));
    EXPECT_TRUE(mock_storage_area_.observed_deletes().empty());
    EXPECT_TRUE(source_area_->events.empty());
  } else {
    // For Local Storage, we expect no mutations to the backend but instead a
    // storage event to be broadcast for the diff.
    EXPECT_EQ(kPersistedValue2, cached_area_->GetItem(kKey2));
    EXPECT_TRUE(mock_storage_area_.observed_puts().empty());
    EXPECT_TRUE(mock_storage_area_.observed_deletes().empty());
    EXPECT_THAT(source_area_->events,
                ElementsAre(Event(kKey2, kCachedValue2, kPersistedValue2)));
  }
}

TEST_P(CachedStorageAreaTestWithParam, ResetConnectionWithMissingBackendKey) {
  const String kKey1 = "key1";
  const String kValue1 = "value1";
  const String kKey2 = "key2";
  const String kValue2 = "value2";
  InjectKeyValue(kKey1, kValue1);
  InjectKeyValue(kKey2, kValue2);

  // Prime the cache.
  EXPECT_EQ(2u, cached_area_->GetLength());
  EXPECT_TRUE(IsCacheLoaded());
  EXPECT_EQ(1, mock_storage_area_.observed_get_alls());

  // Now modify the backend so it's out of sync with the cache. Namely, |kKey2|
  // is no longer present in the backend.
  mock_storage_area_.Clear();
  InjectKeyValue(kKey1, kValue1);

  // Resetting the connection should re-initialize the local cache, with
  // different outcomes for Local and Session Storage.
  cached_area_->ResetConnection(mock_storage_area_.GetInterfaceRemote());
  EXPECT_TRUE(IsCacheLoaded());
  EXPECT_EQ(2, mock_storage_area_.observed_get_alls());
  EXPECT_EQ(kValue1, cached_area_->GetItem(kKey1));
  mock_storage_area_.Flush();

  if (IsSessionStorage()) {
    // For Session Storage, we expect the local cache to push changes to the
    // backend, as the local cache is the source of truth.
    EXPECT_EQ(2u, cached_area_->GetLength());
    EXPECT_EQ(kValue2, cached_area_->GetItem(kKey2));
    EXPECT_THAT(mock_storage_area_.observed_puts(),
                ElementsAre(ObservedPut(kKey2, kValue2, "\n")));
    EXPECT_TRUE(mock_storage_area_.observed_deletes().empty());
    EXPECT_TRUE(source_area_->events.empty());
  } else {
    // For Local Storage, we expect no mutations to the backend but instead a
    // storage event to be broadcast for the diff.
    EXPECT_EQ(1u, cached_area_->GetLength());
    EXPECT_TRUE(cached_area_->GetItem(kKey2).IsNull());
    EXPECT_TRUE(mock_storage_area_.observed_puts().empty());
    EXPECT_TRUE(mock_storage_area_.observed_deletes().empty());
    EXPECT_THAT(source_area_->events,
                ElementsAre(Event(kKey2, kValue2, String())));
  }
}

TEST_P(CachedStorageAreaTestWithParam, ResetConnectionWithMissingLocalKey) {
  const String kKey1 = "key1";
  const String kValue1 = "value1";
  const String kKey2 = "key2";
  const String kValue2 = "value2";
  InjectKeyValue(kKey1, kValue1);

  // Prime the cache.
  EXPECT_EQ(1u, cached_area_->GetLength());
  EXPECT_TRUE(IsCacheLoaded());
  EXPECT_EQ(1, mock_storage_area_.observed_get_alls());

  // Now modify the backend so it's out of sync with the cache. Namely, |kKey2|
  // is present in the backend despite never being cached locally.
  InjectKeyValue(kKey2, kValue2);

  // Resetting the connection should re-initialize the local cache, with
  // different outcomes for Local and Session Storage.
  cached_area_->ResetConnection(mock_storage_area_.GetInterfaceRemote());
  EXPECT_TRUE(IsCacheLoaded());
  EXPECT_EQ(2, mock_storage_area_.observed_get_alls());
  EXPECT_EQ(kValue1, cached_area_->GetItem(kKey1));
  mock_storage_area_.Flush();

  if (IsSessionStorage()) {
    // For Session Storage, we expect the local cache to push changes to the
    // backend, as the local cache is the source of truth.
    EXPECT_EQ(1u, cached_area_->GetLength());
    EXPECT_TRUE(cached_area_->GetItem(kKey2).IsNull());
    EXPECT_THAT(mock_storage_area_.observed_deletes(),
                ElementsAre(ObservedDelete(kKey2, "\n")));
    EXPECT_TRUE(mock_storage_area_.observed_puts().empty());
    EXPECT_TRUE(source_area_->events.empty());
  } else {
    // For Local Storage, we expect no mutations to the backend but instead a
    // storage event to be broadcast for the diff.
    EXPECT_EQ(2u, cached_area_->GetLength());
    EXPECT_EQ(kValue2, cached_area_->GetItem(kKey2));
    EXPECT_TRUE(mock_storage_area_.observed_puts().empty());
    EXPECT_TRUE(mock_storage_area_.observed_deletes().empty());
    EXPECT_THAT(source_area_->events,
                ElementsAre(Event(kKey2, String(), kValue2)));
  }
}

TEST_P(CachedStorageAreaTestWithParam, ResetConnectionWithComplexDiff) {
  const String kKey1 = "key1";
  const String kValue1 = "value1";
  const String kKey2 = "key2";
  const String kValue2 = "value2";
  const String kAltValue2 = "alt_value2";
  const String kKey3 = "key3";
  const String kValue3 = "value3";
  const String kKey4 = "key4";
  const String kValue4 = "value4";
  InjectKeyValue(kKey1, kValue1);
  InjectKeyValue(kKey2, kValue2);
  InjectKeyValue(kKey3, kValue3);

  // Prime the cache.
  EXPECT_EQ(3u, cached_area_->GetLength());
  EXPECT_TRUE(IsCacheLoaded());
  EXPECT_EQ(1, mock_storage_area_.observed_get_alls());

  // Now modify the backend so it's out of sync with the cache. Namely, the
  // value of |kKey2| differs, |kKey3| is no longer present in the backend, and
  // |kKey4| is now present where it wasn't before.
  mock_storage_area_.Clear();
  InjectKeyValue(kKey1, kValue1);
  InjectKeyValue(kKey2, kAltValue2);
  InjectKeyValue(kKey4, kValue4);

  // Resetting the connection should re-initialize the local cache, with
  // different outcomes for Local and Session Storage.
  cached_area_->ResetConnection(mock_storage_area_.GetInterfaceRemote());
  EXPECT_TRUE(IsCacheLoaded());
  EXPECT_EQ(2, mock_storage_area_.observed_get_alls());
  EXPECT_EQ(3u, cached_area_->GetLength());
  EXPECT_EQ(kValue1, cached_area_->GetItem(kKey1));
  mock_storage_area_.Flush();

  if (IsSessionStorage()) {
    // For Session Storage, we expect the local cache to push changes to the
    // backend, as the local cache is the source of truth.
    EXPECT_EQ(kValue2, cached_area_->GetItem(kKey2));
    EXPECT_EQ(kValue3, cached_area_->GetItem(kKey3));
    EXPECT_TRUE(cached_area_->GetItem(kKey4).IsNull());
    EXPECT_THAT(mock_storage_area_.observed_puts(),
                UnorderedElementsAre(ObservedPut(kKey2, kValue2, "\n"),
                                     ObservedPut(kKey3, kValue3, "\n")));
    EXPECT_THAT(mock_storage_area_.observed_deletes(),
                ElementsAre(ObservedDelete(kKey4, "\n")));
    EXPECT_TRUE(source_area_->events.empty());
  } else {
    // For Local Storage, we expect no mutations to the backend but instead a
    // storage event to be broadcast for the diff.
    EXPECT_EQ(kAltValue2, cached_area_->GetItem(kKey2));
    EXPECT_TRUE(cached_area_->GetItem(kKey3).IsNull());
    EXPECT_EQ(kValue4, cached_area_->GetItem(kKey4));
    EXPECT_TRUE(mock_storage_area_.observed_puts().empty());
    EXPECT_TRUE(mock_storage_area_.observed_deletes().empty());
    EXPECT_THAT(source_area_->events,
                UnorderedElementsAre(Event(kKey2, kValue2, kAltValue2),
                                     Event(kKey3, kValue3, String()),
                                     Event(kKey4, String(), kValue4)));
  }
}

TEST_F(CachedStorageAreaTest, KeyMutationsAreIgnoredUntilCompletion) {
  mojom::blink::StorageAreaObserver* observer = cached_area_.get();

  // SetItem
  EXPECT_TRUE(cached_area_->SetItem(kKey, kValue, source_area_));
  mock_storage_area_.Flush();
  EXPECT_TRUE(IsIgnoringKeyMutations(kKey));
  observer->KeyDeleted(KeyToUint8Vector(kKey), std::nullopt, kRemoteSource);
  EXPECT_TRUE(IsIgnoringKeyMutations(kKey));
  EXPECT_EQ(kValue, cached_area_->GetItem(kKey));
  observer->KeyChanged(KeyToUint8Vector(kKey), ValueToUint8Vector(kValue),
                       std::nullopt, source_);
  EXPECT_FALSE(IsIgnoringKeyMutations(kKey));

  // RemoveItem
  cached_area_->RemoveItem(kKey, source_area_);
  mock_storage_area_.Flush();
  EXPECT_TRUE(IsIgnoringKeyMutations(kKey));
  observer->KeyDeleted(KeyToUint8Vector(kKey), ValueToUint8Vector(kValue),
                       source_);
  EXPECT_FALSE(IsIgnoringKeyMutations(kKey));

  // Multiple mutations to the same key.
  EXPECT_TRUE(cached_area_->SetItem(kKey, kValue, source_area_));
  cached_area_->RemoveItem(kKey, source_area_);
  EXPECT_TRUE(IsIgnoringKeyMutations(kKey));
  mock_storage_area_.Flush();
  observer->KeyChanged(KeyToUint8Vector(kKey), ValueToUint8Vector(kValue),
                       std::nullopt, source_);
  observer->KeyDeleted(KeyToUint8Vector(kKey), ValueToUint8Vector(kValue),
                       source_);
  EXPECT_FALSE(IsIgnoringKeyMutations(kKey));

  // A failed set item operation should reset the key's cached value.
  EXPECT_TRUE(cached_area_->SetItem(kKey, kValue, source_area_));
  mock_storage_area_.Flush();
  EXPECT_TRUE(IsIgnoringKeyMutations(kKey));
  observer->KeyChangeFailed(KeyToUint8Vector(kKey), source_);
  EXPECT_TRUE(cached_area_->GetItem(kKey).IsNull());
}

TEST_F(CachedStorageAreaTest, ChangeEvents) {
  mojom::blink::StorageAreaObserver* observer = cached_area_.get();

  cached_area_->SetItem(kKey, kValue, source_area_);
  cached_area_->SetItem(kKey, kValue2, source_area_);
  cached_area_->RemoveItem(kKey, source_area_);
  observer->KeyChanged(KeyToUint8Vector(kKey), ValueToUint8Vector(kValue),
                       std::nullopt, source_);
  observer->KeyChanged(KeyToUint8Vector(kKey), ValueToUint8Vector(kValue2),
                       ValueToUint8Vector(kValue), source_);
  observer->KeyDeleted(KeyToUint8Vector(kKey), ValueToUint8Vector(kValue2),
                       source_);

  observer->KeyChanged(KeyToUint8Vector(kKey), ValueToUint8Vector(kValue),
                       std::nullopt, kRemoteSource);
  observer->AllDeleted(/*was_nonempty=*/true, kRemoteSource);

  // Source area should have ignored all but the last two events.
  ASSERT_EQ(2u, source_area_->events.size());

  EXPECT_EQ(kKey, source_area_->events[0].key);
  EXPECT_TRUE(source_area_->events[0].old_value.IsNull());
  EXPECT_EQ(kValue, source_area_->events[0].new_value);
  EXPECT_EQ(kPageUrl2, source_area_->events[0].url);

  EXPECT_TRUE(source_area_->events[1].key.IsNull());
  EXPECT_TRUE(source_area_->events[1].old_value.IsNull());
  EXPECT_TRUE(source_area_->events[1].new_value.IsNull());
  EXPECT_EQ(kPageUrl2, source_area_->events[1].url);

  // Second area should not have ignored any of the events.
  ASSERT_EQ(5u, source_area2_->events.size());

  EXPECT_EQ(kKey, source_area2_->events[0].key);
  EXPECT_TRUE(source_area2_->events[0].old_value.IsNull());
  EXPECT_EQ(kValue, source_area2_->events[0].new_value);
  EXPECT_EQ(kPageUrl, source_area2_->events[0].url);

  EXPECT_EQ(kKey, source_area2_->events[1].key);
  EXPECT_EQ(kValue, source_area2_->events[1].old_value);
  EXPECT_EQ(kValue2, source_area2_->events[1].new_value);
  EXPECT_EQ(kPageUrl, source_area2_->events[1].url);

  EXPECT_EQ(kKey, source_area2_->events[2].key);
  EXPECT_EQ(kValue2, source_area2_->events[2].old_value);
  EXPECT_TRUE(source_area2_->events[2].new_value.IsNull());
  EXPECT_EQ(kPageUrl, source_area2_->events[2].url);

  EXPECT_EQ(kKey, source_area2_->events[3].key);
  EXPECT_TRUE(source_area2_->events[3].old_value.IsNull());
  EXPECT_EQ(kValue, source_area2_->events[3].new_value);
  EXPECT_EQ(kPageUrl2, source_area2_->events[3].url);

  EXPECT_TRUE(source_area2_->events[4].key.IsNull());
  EXPECT_TRUE(source_area2_->events[4].old_value.IsNull());
  EXPECT_TRUE(source_area2_->events[4].new_value.IsNull());
  EXPECT_EQ(kPageUrl2, source_area2_->events[4].url);
}

TEST_F(CachedStorageAreaTest, RevertOnChangeFailed) {
  // Verifies that when local key changes fail, the cache is restored to an
  // appropriate state.
  mojom::blink::StorageAreaObserver* observer = cached_area_.get();
  cached_area_->SetItem(kKey, kValue, source_area_);
  EXPECT_EQ(kValue, cached_area_->GetItem(kKey));
  observer->KeyChangeFailed(KeyToUint8Vector(kKey), source_);
  EXPECT_TRUE(cached_area_->GetItem(kKey).IsNull());
}

TEST_F(CachedStorageAreaTest, RevertOnChangeFailedWithSubsequentChanges) {
  // Failure of an operation observed while another subsequent operation is
  // still queued. In this case, no revert should happen because the change that
  // would be reverted has already been overwritten.
  mojom::blink::StorageAreaObserver* observer = cached_area_.get();
  cached_area_->SetItem(kKey, kValue, source_area_);
  EXPECT_EQ(kValue, cached_area_->GetItem(kKey));
  cached_area_->SetItem(kKey, kValue2, source_area_);
  EXPECT_EQ(kValue2, cached_area_->GetItem(kKey));
  observer->KeyChangeFailed(KeyToUint8Vector(kKey), source_);
  EXPECT_EQ(kValue2, cached_area_->GetItem(kKey));
  observer->KeyChanged(KeyToUint8Vector(kKey), ValueToUint8Vector(kValue2),
                       std::nullopt, source_);
  EXPECT_EQ(kValue2, cached_area_->GetItem(kKey));
}

TEST_F(CachedStorageAreaTest, RevertOnConsecutiveChangeFailures) {
  mojom::blink::StorageAreaObserver* observer = cached_area_.get();
  // If two operations fail in a row, the cache should revert to the original
  // state before either |SetItem()|.
  cached_area_->SetItem(kKey, kValue, source_area_);
  cached_area_->SetItem(kKey, kValue2, source_area_);
  EXPECT_EQ(kValue2, cached_area_->GetItem(kKey));
  observer->KeyChangeFailed(KeyToUint8Vector(kKey), source_);
  // Still caching |kValue2| because that operation is still pending.
  EXPECT_EQ(kValue2, cached_area_->GetItem(kKey));
  observer->KeyChangeFailed(KeyToUint8Vector(kKey), source_);
  // Now that the second operation also failed, the cache should revert to the
  // value from before the first |SetItem()|, i.e. no value.
  EXPECT_TRUE(cached_area_->GetItem(kKey).IsNull());
}

TEST_F(CachedStorageAreaTest, RevertOnChangeFailedWithNonLocalChanges) {
  // If a non-local mutation is observed while a local mutation is pending
  // acknowledgement, and that local mutation ends up getting rejected, the
  // cache should revert to a state reflecting the non-local change that was
  // temporarily ignored.
  mojom::blink::StorageAreaObserver* observer = cached_area_.get();
  cached_area_->SetItem(kKey, kValue, source_area_);
  EXPECT_EQ(kValue, cached_area_->GetItem(kKey));
  // Should be ignored.
  observer->KeyChanged(KeyToUint8Vector(kKey), ValueToUint8Vector(kValue2),
                       std::nullopt, kRemoteSource);
  EXPECT_EQ(kValue, cached_area_->GetItem(kKey));
  // Now that we fail the pending |SetItem()|, the above remote change should be
  // reflected.
  observer->KeyChangeFailed(KeyToUint8Vector(kKey), source_);
  EXPECT_EQ(kValue2, cached_area_->GetItem(kKey));
}

TEST_F(CachedStorageAreaTest, RevertOnChangeFailedAfterNonLocalClear) {
  // If a non-local clear is observed while a local mutation is pending
  // acknowledgement and that local mutation ends up getting rejected, the cache
  // should revert the key to have no value, even if it had a value during the
  // corresponding |SetItem()| call.
  mojom::blink::StorageAreaObserver* observer = cached_area_.get();
  cached_area_->SetItem(kKey, kValue, source_area_);
  EXPECT_EQ(kValue, cached_area_->GetItem(kKey));
  cached_area_->SetItem(kKey, kValue2, source_area_);
  EXPECT_EQ(kValue2, cached_area_->GetItem(kKey));
  observer->KeyChanged(KeyToUint8Vector(kKey), ValueToUint8Vector(kValue),
                       std::nullopt, source_);
  // We still have |kValue2| cached since its mutation is still pending.
  EXPECT_EQ(kValue2, cached_area_->GetItem(kKey));

  // Even after a non-local clear is observed, |kValue2| remains cached because
  // pending local mutations are replayed over a non-local cl
```