Response:
The user wants a summary of the functionality of the C++ source code file `net/extras/sqlite/sqlite_persistent_shared_dictionary_store_unittest.cc`. This file appears to be a unit test suite for a component that manages shared dictionaries in a persistent store using SQLite.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core component:** The file name strongly suggests it's testing `SQLitePersistentSharedDictionaryStore`. This is the central object being tested.

2. **Recognize the testing nature:** The `_unittest.cc` suffix indicates this file contains unit tests. Unit tests verify the behavior of individual components or functions.

3. **Infer the purpose of the store:** The name "shared dictionary store" implies this component manages a collection of "shared dictionaries."  The "persistent" part and the use of "SQLite" suggest these dictionaries are stored on disk and survive application restarts.

4. **Analyze the test names:**  The test names provide direct clues about the functionalities being tested. Keywords like "RegisterDictionary," "GetDictionaries," "ClearDictionaries," "DeleteExpiredDictionaries," "ProcessEviction," "UpdateDictionaryLastUsedTime," etc., directly map to the functions of the `SQLitePersistentSharedDictionaryStore`.

5. **Group related tests:**  Notice that several tests focus on similar functionalities, like different ways to clear dictionaries (by time, by isolation key, by disk cache key). Grouping these helps in summarizing.

6. **Look for interactions with other concepts:** The tests mention "isolation keys" and "disk cache key tokens." This indicates the dictionary store is aware of these related concepts and uses them for organization or identification.

7. **Identify potential JavaScript connections:**  The term "shared dictionary" is related to web technologies. Consider where shared dictionaries are used in the web context – specifically for compression and performance optimization. This leads to the connection with the Compression Dictionary Transport feature and its potential benefits for JavaScript.

8. **Analyze test logic for assumptions and examples:** The tests often set up specific scenarios with pre-defined dictionary data and then assert the outcome of an operation. These setups provide examples of how the functions are expected to behave with different inputs. Look for patterns in how test data is created (e.g., `CreateIsolationKey`, `SharedDictionaryInfo` constructor).

9. **Consider error conditions and usage mistakes:** While not explicitly tested for failures in this snippet, the operations themselves (like registering or deleting) could have error conditions. Think about common mistakes a programmer might make, such as trying to register duplicate dictionaries or deleting non-existent ones.

10. **Trace user interaction (debugging perspective):**  Imagine how a user's action in a browser could lead to these functions being called. Consider the lifecycle of a shared dictionary: fetching, storing, using, potentially being evicted.

11. **Address the "part 4 of 5" instruction:**  Acknowledge that this is a partial view and the summary is based on the provided code snippet.

12. **Structure the summary:** Organize the findings into logical sections: Core Functionality, JavaScript Relationship, Logical Inference (Input/Output), Common Errors, Debugging Clues, and Overall Summary (for this part).

13. **Refine and elaborate:**  Fill in the details, providing concrete examples where possible. For instance, when discussing clearing dictionaries, mention the different criteria used in the tests.

By following these steps, we can generate a comprehensive summary of the provided code, addressing all aspects of the user's request.
这是对 Chromium 网络栈中 `net/extras/sqlite/sqlite_persistent_shared_dictionary_store_unittest.cc` 文件功能的总结，基于提供的代码片段。

**文件功能归纳 (第 4 部分):**

这部分测试用例主要集中在 `SQLitePersistentSharedDictionaryStore` 的以下功能：

* **按时间范围清理字典 (`ClearDictionaries`):**  测试了根据字典的 `last_used_time`，在指定的时间范围内清理字典的功能。它验证了匹配器 (matcher) 函数的调用，以及实际被删除的字典。
* **按隔离键清理字典 (`ClearDictionariesForIsolationKey`):**  测试了针对特定的 `IsolationKey` 清理所有关联字典的功能。包括空存储的情况以及包含多个字典的场景。
* **删除过期字典 (`DeleteExpiredDictionaries`):**  测试了根据字典的 `expiration` 字段，删除已过期字典的功能。
* **处理字典驱逐 (`ProcessEviction`):** 这是本部分的核心功能，测试了在超出存储大小或数量限制时，根据最近最少使用 (LRU) 原则驱逐字典的功能。测试用例覆盖了以下场景：
    * 未超出限制的情况。
    * 超出大小限制的情况。
    * 超出大小限制并驱逐到数量低水位线的情况。
    * 超出数量限制的情况。
    * 超出数量限制并驱逐到大小低水位线的情况。
    * `max_size` 为 0 的情况。
    * 删除所有字典的情况。
* **获取所有磁盘缓存键令牌 (`GetAllDiskCacheKeyTokens`):** 测试了获取所有已存储字典的磁盘缓存键令牌的功能。
* **根据磁盘缓存键令牌删除字典 (`DeleteDictionariesByDiskCacheKeyTokens`):** 测试了根据提供的磁盘缓存键令牌列表删除对应字典的功能。
* **更新字典的最后获取时间 (`UpdateDictionaryLastFetchTime`):** 测试了更新特定字典的最后成功获取时间的功能。
* **更新字典的最后使用时间 (`UpdateDictionaryLastUsedTime`):** 测试了更新特定字典的最后使用时间的功能。

**与 JavaScript 的关系:**

Shared Dictionary API 允许网页加载和使用由服务器提供的共享压缩字典，以减小资源大小并提高加载速度。 `SQLitePersistentSharedDictionaryStore` 负责在本地持久化存储这些字典。

* **示例:** 当一个 JavaScript 脚本尝试使用一个共享字典时，浏览器会首先检查本地存储 (由 `SQLitePersistentSharedDictionaryStore` 管理) 是否存在该字典。如果存在，可以直接使用，而无需重新下载。

**逻辑推理 (假设输入与输出):**

**示例 1: `ClearDictionaries`**

* **假设输入:**
    * 存储中存在多个字典，它们的 `last_used_time` 各不相同。
    * `begin_time`:  `base::Time::Now() - base::Seconds(3)`
    * `end_time`: `base::Time::Now() - base::Seconds(1)`
    * `url_matcher`: 一个 lambda 函数，对于 `https://c3.example/` 返回 `true`，其他 URL 返回 `false`。
* **预期输出:**
    * 返回一个包含 `token3` 的 `std::set<base::UnguessableToken>`，因为只有 `dict3` 的 `last_used_time` 在指定范围内，并且匹配器对它的 URL 返回 `true`。

**示例 2: `ProcessEviction`**

* **假设输入:**
    * 存储中存在四个字典 (`dict1` 到 `dict4`)，大小分别为 1000, 3000, 5000, 7000，`last_used_time` 依次递增。
    * `max_size`: 15000
    * `low_watermark_size`: 10000
    * `max_count`: 10
    * `low_watermark_count`: 9
* **预期输出:**
    * 返回一个包含 `dict1` 和 `dict3` 的 `disk_cache_key_token` 的 `std::set<base::UnguessableToken>`，因为按照 LRU 原则，先删除 `dict1`，然后删除 `dict3`，剩余的 `dict2` 和 `dict4` 的总大小 (10000) 不超过 `low_watermark_size`。

**用户或编程常见的使用错误:**

* **在 `ClearDictionaries` 中提供的匹配器函数逻辑错误:**  如果匹配器函数总是返回 `false`，则不会删除任何字典，即使它们的 `last_used_time` 在指定范围内。
* **在 `ProcessEviction` 中设置不合理的 `max_size` 和 `low_watermark_size`:** 例如，如果 `low_watermark_size` 大于 `max_size`，可能会导致不必要的字典删除。
* **尝试删除不存在的磁盘缓存键令牌:** `DeleteDictionariesByDiskCacheKeyTokens` 会正常执行，但不会有任何字典被删除。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户浏览网页并触发了共享字典的使用:**  当浏览器遇到一个使用了共享字典的资源请求时，它会尝试加载并使用该字典。
2. **浏览器检查本地存储:**  网络栈会调用 `SQLitePersistentSharedDictionaryStore` 的方法来检查本地是否已存在该字典。
3. **如果字典不存在，则下载并存储:** 如果本地没有找到，浏览器会下载字典，并调用 `RegisterDictionary` 将其存储到 SQLite 数据库中。
4. **字典被使用:**  当浏览器需要解压缩资源时，会从本地存储中读取字典。这可能会更新字典的 `last_used_time`。
5. **本地存储空间不足或达到字典数量限制:**  当存储空间不足或字典数量过多时，会触发驱逐策略，调用 `ProcessEviction` 来删除一些旧的或不常用的字典。
6. **用户清理浏览器数据:**  用户在浏览器设置中清除缓存或 Cookie 等数据时，可能会触发 `ClearDictionaries` 或 `ClearDictionariesForIsolationKey` 来删除相关的共享字典。
7. **字典过期:**  即使没有用户操作，过期的字典也会被定期清理，调用 `DeleteExpiredDictionaries`。

**总结 (基于第 4 部分):**

这个代码片段主要测试了 `SQLitePersistentSharedDictionaryStore` 组件中关于 **清理、删除和驱逐** 共享字典的功能。它涵盖了基于时间范围、隔离键、过期时间和存储限制等多种清理策略，并验证了这些策略的正确性。此外，还测试了获取和根据磁盘缓存键令牌删除特定字典的功能，以及更新字典元数据（如最后获取和使用时间）的功能。 这些测试确保了共享字典的本地持久化存储能够有效地管理字典的生命周期，并在必要时进行清理和驱逐，以保持存储空间的有效利用。

### 提示词
```
这是目录为net/extras/sqlite/sqlite_persistent_shared_dictionary_store_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
tion*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/5000, SHA256HashValue({{0x00, 0x03}}),
      /*disk_cache_key_token=*/token3,
      /*primary_key_in_database=*/std::nullopt);
  auto result3 = RegisterDictionary(isolation_key3, dict3);
  dict3.set_primary_key_in_database(result3.primary_key_in_database());

  auto isolation_key4 =
      CreateIsolationKey("https://d1.example/", "https://d2.example/");
  auto token4 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict4 = SharedDictionaryInfo(
      GURL("https://d3.example/dict"),
      /*last_fetch_time=*/base::Time::Now() - base::Seconds(1),
      /*response_time=*/base::Time::Now() - base::Seconds(1),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/7000, SHA256HashValue({{0x00, 0x04}}),
      /*disk_cache_key_token=*/token4,
      /*primary_key_in_database=*/std::nullopt);
  auto result4 = RegisterDictionary(isolation_key4, dict4);
  dict4.set_primary_key_in_database(result4.primary_key_in_database());

  // No matching dictionaries to be deleted.
  EXPECT_TRUE(ClearDictionaries(base::Time::Now() - base::Seconds(200),
                                base::Time::Now() - base::Seconds(4),
                                base::BindRepeating([](const GURL&) {
                                  EXPECT_TRUE(false)
                                      << "Should not be reached.";
                                  return true;
                                }))
                  .empty());
  std::set<GURL> checked_urls;
  EXPECT_TRUE(
      ClearDictionaries(base::Time::Now() - base::Seconds(3),
                        base::Time::Now() - base::Seconds(1),
                        base::BindLambdaForTesting([&](const GURL& url) {
                          checked_urls.insert(url);
                          return false;
                        }))
          .empty());
  // The dict2 which last_used_time is "now - 3 sec" and the dict3
  // which last_used_time is "now - 2 sec" must be selected and the macher is
  // called with those dictionaries frame_origin, top_frame_site and host.
  EXPECT_THAT(checked_urls,
              UnorderedElementsAreArray(
                  {GURL("https://b1.example/"), GURL("https://b2.example/"),
                   GURL("https://b3.example/"), GURL("https://c1.example/"),
                   GURL("https://c2.example/"), GURL("https://c3.example/")}));

  // Deletes dict3.
  std::set<base::UnguessableToken> tokens =
      ClearDictionaries(base::Time::Now() - base::Seconds(3),
                        base::Time::Now() - base::Seconds(1),
                        base::BindRepeating([](const GURL& url) {
                          return url == GURL("https://c3.example/");
                        }));
  EXPECT_THAT(tokens, ElementsAreArray({token3}));

  // Check the remaining dictionaries.
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key1, ElementsAreArray({dict1})),
                          Pair(isolation_key2, ElementsAreArray({dict2})),
                          Pair(isolation_key4, ElementsAreArray({dict4}))));
  // Check the total size of remaining dictionaries.
  EXPECT_EQ(dict1.size() + dict2.size() + dict4.size(),
            GetTotalDictionarySize());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ClearDictionariesForIsolationKeyEmptyStore) {
  CreateStore();
  EXPECT_TRUE(ClearDictionariesForIsolationKey(isolation_key_).empty());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ClearDictionariesForIsolation) {
  CreateStore();

  auto isolation_key1 =
      CreateIsolationKey("https://a1.example/", "https://a2.example/");
  auto token1 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict1 =
      SharedDictionaryInfo(GURL("https://a1.example/dict"),
                           /*last_fetch_time=*/base::Time::Now(),
                           /*response_time=*/base::Time::Now(),
                           /*expiration*/ base::Seconds(100), "/pattern*",
                           /*match_dest_string=*/"", /*id=*/"",
                           /*last_used_time*/ base::Time::Now(),
                           /*size=*/1000, SHA256HashValue({{0x00, 0x01}}),
                           /*disk_cache_key_token=*/token1,
                           /*primary_key_in_database=*/std::nullopt);
  auto result1 = RegisterDictionary(isolation_key1, dict1);
  dict1.set_primary_key_in_database(result1.primary_key_in_database());

  // Same frame origin, different top frame site.
  auto isolation_key2 =
      CreateIsolationKey("https://a1.example/", "https://a3.example/");
  auto token2 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict2 =
      SharedDictionaryInfo(GURL("https://a2.example/dict"),
                           /*last_fetch_time=*/base::Time::Now(),
                           /*response_time=*/base::Time::Now(),
                           /*expiration*/ base::Seconds(100), "/pattern*",
                           /*match_dest_string=*/"", /*id=*/"",
                           /*last_used_time*/ base::Time::Now(),
                           /*size=*/2000, SHA256HashValue({{0x00, 0x02}}),
                           /*disk_cache_key_token=*/token2,
                           /*primary_key_in_database=*/std::nullopt);
  auto result2 = RegisterDictionary(isolation_key2, dict2);
  dict2.set_primary_key_in_database(result2.primary_key_in_database());

  // Different frame origin, same top frame site.
  auto isolation_key3 =
      CreateIsolationKey("https://a4.example/", "https://a2.example/");
  auto token3 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict3 =
      SharedDictionaryInfo(GURL("https://a3.example/dict"),
                           /*last_fetch_time=*/base::Time::Now(),
                           /*response_time=*/base::Time::Now(),
                           /*expiration*/ base::Seconds(100), "/pattern*",
                           /*match_dest_string=*/"", /*id=*/"",
                           /*last_used_time*/ base::Time::Now(),
                           /*size=*/4000, SHA256HashValue({{0x00, 0x03}}),
                           /*disk_cache_key_token=*/token3,
                           /*primary_key_in_database=*/std::nullopt);
  auto result3 = RegisterDictionary(isolation_key3, dict3);
  dict3.set_primary_key_in_database(result3.primary_key_in_database());

  // Different frame origin, different top frame site.
  auto isolation_key4 =
      CreateIsolationKey("https://a4.example/", "https://a5.example/");
  auto token4 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict4 =
      SharedDictionaryInfo(GURL("https://a4.example/dict"),
                           /*last_fetch_time=*/base::Time::Now(),
                           /*response_time=*/base::Time::Now(),
                           /*expiration*/ base::Seconds(100), "/pattern*",
                           /*match_dest_string=*/"", /*id=*/"",
                           /*last_used_time*/ base::Time::Now(),
                           /*size=*/8000, SHA256HashValue({{0x00, 0x04}}),
                           /*disk_cache_key_token=*/token4,
                           /*primary_key_in_database=*/std::nullopt);
  auto result4 = RegisterDictionary(isolation_key4, dict4);
  dict4.set_primary_key_in_database(result4.primary_key_in_database());

  // Deletes dictionaries for `isolation_key_`. The result should be empty.
  EXPECT_TRUE(ClearDictionariesForIsolationKey(isolation_key_).empty());

  // Deletes dictionaries for `isolation_key1`.
  EXPECT_THAT(ClearDictionariesForIsolationKey(isolation_key1),
              ElementsAreArray({token1}));

  // Check the remaining dictionaries.
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key2, ElementsAreArray({dict2})),
                          Pair(isolation_key3, ElementsAreArray({dict3})),
                          Pair(isolation_key4, ElementsAreArray({dict4}))));
  // Check the total size of remaining dictionaries.
  EXPECT_EQ(dict2.size() + dict3.size() + dict4.size(),
            GetTotalDictionarySize());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ClearDictionariesForIsolationMultipleDictionaries) {
  CreateStore();

  auto isolation_key1 = CreateIsolationKey("https://a1.example/");
  auto token1_1 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict1_1 =
      SharedDictionaryInfo(GURL("https://a1.example/dict1"),
                           /*last_fetch_time=*/base::Time::Now(),
                           /*response_time=*/base::Time::Now(),
                           /*expiration*/ base::Seconds(100), "/pattern1*",
                           /*match_dest_string=*/"", /*id=*/"",
                           /*last_used_time*/ base::Time::Now(),
                           /*size=*/1000, SHA256HashValue({{0x00, 0x01}}),
                           /*disk_cache_key_token=*/token1_1,
                           /*primary_key_in_database=*/std::nullopt);
  auto result1_1 = RegisterDictionary(isolation_key1, dict1_1);
  dict1_1.set_primary_key_in_database(result1_1.primary_key_in_database());

  auto token1_2 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict1_2 =
      SharedDictionaryInfo(GURL("https://a1.example/dict1"),
                           /*last_fetch_time=*/base::Time::Now(),
                           /*response_time=*/base::Time::Now(),
                           /*expiration*/ base::Seconds(100), "/pattern2*",
                           /*match_dest_string=*/"", /*id=*/"",
                           /*last_used_time*/ base::Time::Now(),
                           /*size=*/2000, SHA256HashValue({{0x00, 0x02}}),
                           /*disk_cache_key_token=*/token1_2,
                           /*primary_key_in_database=*/std::nullopt);
  auto result1_2 = RegisterDictionary(isolation_key1, dict1_2);
  dict1_2.set_primary_key_in_database(result1_2.primary_key_in_database());

  auto isolation_key2 = CreateIsolationKey("https://a2.example/");
  auto token2 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict2 =
      SharedDictionaryInfo(GURL("https://a2.example/dict"),
                           /*last_fetch_time=*/base::Time::Now(),
                           /*response_time=*/base::Time::Now(),
                           /*expiration*/ base::Seconds(100), "/pattern*",
                           /*match_dest_string=*/"", /*id=*/"",
                           /*last_used_time*/ base::Time::Now(),
                           /*size=*/4000, SHA256HashValue({{0x00, 0x03}}),
                           /*disk_cache_key_token=*/token2,
                           /*primary_key_in_database=*/std::nullopt);
  auto result2 = RegisterDictionary(isolation_key2, dict2);
  dict2.set_primary_key_in_database(result2.primary_key_in_database());

  // Deletes dictionaries for `isolation_key1`.
  EXPECT_THAT(ClearDictionariesForIsolationKey(isolation_key1),
              UnorderedElementsAreArray({token1_1, token1_2}));

  // Check the remaining dictionaries.
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key2, ElementsAreArray({dict2}))));
  // Check the total size of remaining dictionaries.
  EXPECT_EQ(dict2.size(), GetTotalDictionarySize());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest, DeleteExpiredDictionaries) {
  CreateStore();

  const base::Time now = base::Time::Now();
  auto token1 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict1 =
      SharedDictionaryInfo(GURL("https://a.example/dict"),
                           /*last_fetch_time=*/now, /*response_time=*/now,
                           /*expiration*/ base::Seconds(100), "/pattern*",
                           /*match_dest_string=*/"", /*id=*/"",
                           /*last_used_time*/ now,
                           /*size=*/1000, SHA256HashValue({{0x00, 0x01}}),
                           /*disk_cache_key_token=*/token1,
                           /*primary_key_in_database=*/std::nullopt);
  auto result1 = RegisterDictionary(isolation_key_, dict1);
  dict1.set_primary_key_in_database(result1.primary_key_in_database());

  auto token2 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict2 =
      SharedDictionaryInfo(GURL("https://b.example/dict"),
                           /*last_fetch_time=*/now + base::Seconds(1),
                           /*response_time=*/now + base::Seconds(1),
                           /*expiration*/ base::Seconds(99), "/pattern*",
                           /*match_dest_string=*/"", /*id=*/"",
                           /*last_used_time*/ now,
                           /*size=*/3000, SHA256HashValue({{0x00, 0x02}}),
                           /*disk_cache_key_token=*/token2,
                           /*primary_key_in_database=*/std::nullopt);
  auto result2 = RegisterDictionary(isolation_key_, dict2);
  dict2.set_primary_key_in_database(result2.primary_key_in_database());

  auto token3 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict3 =
      SharedDictionaryInfo(GURL("https://c.example/dict"),
                           /*last_fetch_time=*/now + base::Seconds(1),
                           /*response_time=*/now + base::Seconds(1),
                           /*expiration*/ base::Seconds(100), "/pattern*",
                           /*match_dest_string=*/"", /*id=*/"",
                           /*last_used_time*/ now,
                           /*size=*/5000, SHA256HashValue({{0x00, 0x03}}),
                           /*disk_cache_key_token=*/token3,
                           /*primary_key_in_database=*/std::nullopt);
  auto result3 = RegisterDictionary(isolation_key_, dict3);
  dict3.set_primary_key_in_database(result3.primary_key_in_database());

  auto token4 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict4 =
      SharedDictionaryInfo(GURL("https://d.example/dict"),
                           /*last_fetch_time=*/now + base::Seconds(2),
                           /*response_time=*/now + base::Seconds(2),
                           /*expiration*/ base::Seconds(99), "/pattern*",
                           /*match_dest_string=*/"", /*id=*/"",
                           /*last_used_time*/ now,
                           /*size=*/7000, SHA256HashValue({{0x00, 0x04}}),
                           /*disk_cache_key_token=*/token4,
                           /*primary_key_in_database=*/std::nullopt);
  auto result4 = RegisterDictionary(isolation_key_, dict4);
  dict4.set_primary_key_in_database(result4.primary_key_in_database());

  // No matching dictionaries to be deleted.
  EXPECT_TRUE(DeleteExpiredDictionaries(now + base::Seconds(99)).empty());

  std::set<base::UnguessableToken> tokens =
      DeleteExpiredDictionaries(now + base::Seconds(100));
  // The dict1 and dict2 must be deleted.
  EXPECT_THAT(tokens, UnorderedElementsAreArray({token1, token2}));

  // Check the remaining dictionaries.
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key_,
                               UnorderedElementsAreArray({dict3, dict4}))));
  // Check the total size of remaining dictionaries.
  EXPECT_EQ(dict3.size() + dict4.size(), GetTotalDictionarySize());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest, ProcessEvictionNotExceeded) {
  CreateStore();
  auto [dict1, dict2, dict3, dict4] =
      RegisterSharedDictionariesForProcessEvictionTest(store_.get(),
                                                       isolation_key_);
  // The current status:
  //   dict1: size=1000 last_used_time=now
  //   dict3: size=5000 last_used_time=now+2
  //   dict4: size=7000 last_used_time=now+3
  //   dict2: size=3000 last_used_time=now+4

  // No matching dictionaries to be deleted.
  EXPECT_TRUE(ProcessEviction(16000, 15000, 10, 9).empty());
  // Check the remaining dictionaries.
  EXPECT_THAT(
      GetAllDictionaries(),
      ElementsAre(Pair(isolation_key_, UnorderedElementsAreArray(
                                           {dict1, dict2, dict3, dict4}))));
  // Check the total size of remaining dictionaries.
  EXPECT_EQ(dict1.size() + dict2.size() + dict3.size() + dict4.size(),
            GetTotalDictionarySize());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest, ProcessEvictionSizeExceeded) {
  CreateStore();
  auto [dict1, dict2, dict3, dict4] =
      RegisterSharedDictionariesForProcessEvictionTest(store_.get(),
                                                       isolation_key_);
  // The current status:
  //   dict1: size=1000 last_used_time=now
  //   dict3: size=5000 last_used_time=now+2
  //   dict4: size=7000 last_used_time=now+3
  //   dict2: size=3000 last_used_time=now+4

  std::set<base::UnguessableToken> tokens =
      ProcessEviction(15000, 10000, 10, 9);
  // The dict1 and dict3 must be deleted.
  EXPECT_THAT(tokens,
              UnorderedElementsAreArray({dict1.disk_cache_key_token(),
                                         dict3.disk_cache_key_token()}));
  // Check the remaining dictionaries.
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key_,
                               UnorderedElementsAreArray({dict4, dict2}))));
  // Check the total size of remaining dictionaries.
  EXPECT_EQ(dict4.size() + dict2.size(), GetTotalDictionarySize());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ProcessEvictionSizeExceededEvictiedUntilCountLowWatermark) {
  CreateStore();
  auto [dict1, dict2, dict3, dict4] =
      RegisterSharedDictionariesForProcessEvictionTest(store_.get(),
                                                       isolation_key_);
  // The current status:
  //   dict1: size=1000 last_used_time=now
  //   dict3: size=5000 last_used_time=now+2
  //   dict4: size=7000 last_used_time=now+3
  //   dict2: size=3000 last_used_time=now+4

  std::set<base::UnguessableToken> tokens =
      ProcessEviction(15000, 10000, 10, 1);
  // The dict1 and dict3 and dict4 must be deleted.
  EXPECT_THAT(tokens,
              UnorderedElementsAreArray({dict1.disk_cache_key_token(),
                                         dict3.disk_cache_key_token(),
                                         dict4.disk_cache_key_token()}));
  // Check the remaining dictionaries.
  EXPECT_THAT(
      GetAllDictionaries(),
      ElementsAre(Pair(isolation_key_, UnorderedElementsAreArray({dict2}))));
  // Check the total size of remaining dictionaries.
  EXPECT_EQ(dict2.size(), GetTotalDictionarySize());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ProcessEvictionCountExceeded) {
  CreateStore();

  auto [dict1, dict2, dict3, dict4] =
      RegisterSharedDictionariesForProcessEvictionTest(store_.get(),
                                                       isolation_key_);
  // The current status:
  //   dict1: size=1000 last_used_time=now
  //   dict3: size=5000 last_used_time=now+2
  //   dict4: size=7000 last_used_time=now+3
  //   dict2: size=3000 last_used_time=now+4

  std::set<base::UnguessableToken> tokens = ProcessEviction(20000, 20000, 3, 2);
  // The dict1 and dict3 must be deleted.
  EXPECT_THAT(tokens,
              UnorderedElementsAreArray({dict1.disk_cache_key_token(),
                                         dict3.disk_cache_key_token()}));
  // Check the remaining dictionaries.
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key_,
                               UnorderedElementsAreArray({dict4, dict2}))));
  // Check the total size of remaining dictionaries.
  EXPECT_EQ(dict4.size() + dict2.size(), GetTotalDictionarySize());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ProcessEvictionCountExceededEvictedUntilSizeLowWaterMark) {
  CreateStore();

  auto [dict1, dict2, dict3, dict4] =
      RegisterSharedDictionariesForProcessEvictionTest(store_.get(),
                                                       isolation_key_);
  // The current status:
  //   dict1: size=1000 last_used_time=now
  //   dict3: size=5000 last_used_time=now+2
  //   dict4: size=7000 last_used_time=now+3
  //   dict2: size=3000 last_used_time=now+4

  std::set<base::UnguessableToken> tokens = ProcessEviction(20000, 3000, 3, 2);
  // The dict1 and dict3 and dict4 must be deleted.
  EXPECT_THAT(tokens,
              UnorderedElementsAreArray({dict1.disk_cache_key_token(),
                                         dict3.disk_cache_key_token(),
                                         dict4.disk_cache_key_token()}));
  // Check the remaining dictionaries.
  EXPECT_THAT(
      GetAllDictionaries(),
      ElementsAre(Pair(isolation_key_, UnorderedElementsAreArray({dict2}))));
  // Check the total size of remaining dictionaries.
  EXPECT_EQ(dict2.size(), GetTotalDictionarySize());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest, ProcessEvictionZeroMaxSize) {
  CreateStore();

  auto [dict1, dict2, dict3, dict4] =
      RegisterSharedDictionariesForProcessEvictionTest(store_.get(),
                                                       isolation_key_);
  // The current status:
  //   dict1: size=1000 last_used_time=now
  //   dict3: size=5000 last_used_time=now+2
  //   dict4: size=7000 last_used_time=now+3
  //   dict2: size=3000 last_used_time=now+4

  EXPECT_TRUE(ProcessEviction(0, 0, 4, 2).empty());

  std::set<base::UnguessableToken> tokens = ProcessEviction(0, 0, 3, 2);
  // The dict1 and dict3 and dict4 must be deleted.
  EXPECT_THAT(tokens,
              UnorderedElementsAreArray({dict1.disk_cache_key_token(),
                                         dict3.disk_cache_key_token()}));
  // Check the remaining dictionaries.
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key_,
                               UnorderedElementsAreArray({dict2, dict4}))));
  // Check the total size of remaining dictionaries.
  EXPECT_EQ(dict2.size() + dict4.size(), GetTotalDictionarySize());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest, ProcessEvictionDeletesAll) {
  CreateStore();

  const base::Time now = base::Time::Now();
  auto token1 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict1 =
      SharedDictionaryInfo(GURL("https://a.example/dict"),
                           /*last_fetch_time=*/now, /*response_time=*/now,
                           /*expiration*/ base::Seconds(100), "/pattern*",
                           /*match_dest_string=*/"", /*id=*/"",
                           /*last_used_time*/ now,
                           /*size=*/1000, SHA256HashValue({{0x00, 0x01}}),
                           /*disk_cache_key_token=*/token1,
                           /*primary_key_in_database=*/std::nullopt);
  auto result1 = RegisterDictionary(isolation_key_, dict1);
  dict1.set_primary_key_in_database(result1.primary_key_in_database());

  auto token2 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict2 =
      SharedDictionaryInfo(GURL("https://b.example/dict"),
                           /*last_fetch_time=*/now, /*response_time=*/now,
                           /*expiration*/ base::Seconds(100), "/pattern*",
                           /*match_dest_string=*/"", /*id=*/"",
                           /*last_used_time*/ now + base::Seconds(1),
                           /*size=*/3000, SHA256HashValue({{0x00, 0x02}}),
                           /*disk_cache_key_token=*/token2,
                           /*primary_key_in_database=*/std::nullopt);
  auto result2 = RegisterDictionary(isolation_key_, dict2);
  dict2.set_primary_key_in_database(result2.primary_key_in_database());

  // The current status:
  //   dict1: size=1000 last_used_time=now
  //   dict2: size=3000 last_used_time=now+1

  std::set<base::UnguessableToken> tokens = ProcessEviction(1000, 900, 10, 9);
  // The dict1 and dict2 must be deleted.
  EXPECT_THAT(tokens, UnorderedElementsAreArray({token1, token2}));

  EXPECT_TRUE(GetAllDictionaries().empty());

  // Check the total size of remaining dictionaries.
  EXPECT_EQ(0u, GetTotalDictionarySize());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest, GetAllDiskCacheKeyTokens) {
  CreateStore();
  EXPECT_TRUE(GetAllDiskCacheKeyTokens().empty());

  auto token1 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict1 = SharedDictionaryInfo(
      GURL("https://a.example/dict"),
      /*last_fetch_time=*/base::Time::Now() - base::Seconds(4),
      /*response_time=*/base::Time::Now() - base::Seconds(4),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/1000, SHA256HashValue({{0x00, 0x01}}),
      /*disk_cache_key_token=*/token1,
      /*primary_key_in_database=*/std::nullopt);
  RegisterDictionary(isolation_key_, dict1);

  EXPECT_THAT(GetAllDiskCacheKeyTokens(), ElementsAreArray({token1}));

  auto token2 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict2 = SharedDictionaryInfo(
      GURL("https://b.example/dict"),
      /*last_fetch_time=*/base::Time::Now() - base::Seconds(3),
      /*response_time=*/base::Time::Now() - base::Seconds(3),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/3000, SHA256HashValue({{0x00, 0x02}}),
      /*disk_cache_key_token=*/token2,
      /*primary_key_in_database=*/std::nullopt);
  RegisterDictionary(isolation_key_, dict2);

  EXPECT_THAT(GetAllDiskCacheKeyTokens(),
              UnorderedElementsAreArray({token1, token2}));
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       DeleteDictionariesByDiskCacheKeyTokens) {
  CreateStore();
  EXPECT_TRUE(GetAllDiskCacheKeyTokens().empty());

  auto token1 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict1 = SharedDictionaryInfo(
      GURL("https://a.example/dict"),
      /*last_fetch_time=*/base::Time::Now() - base::Seconds(4),
      /*response_time=*/base::Time::Now() - base::Seconds(4),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/1000, SHA256HashValue({{0x00, 0x01}}),
      /*disk_cache_key_token=*/token1,
      /*primary_key_in_database=*/std::nullopt);
  auto result1 = RegisterDictionary(isolation_key_, dict1);
  dict1.set_primary_key_in_database(result1.primary_key_in_database());

  EXPECT_THAT(GetAllDiskCacheKeyTokens(), ElementsAreArray({token1}));

  auto token2 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict2 = SharedDictionaryInfo(
      GURL("https://b.example/dict"),
      /*last_fetch_time=*/base::Time::Now() - base::Seconds(3),
      /*response_time=*/base::Time::Now() - base::Seconds(3),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/3000, SHA256HashValue({{0x00, 0x02}}),
      /*disk_cache_key_token=*/token2,
      /*primary_key_in_database=*/std::nullopt);
  RegisterDictionary(isolation_key_, dict2);
  auto result2 = RegisterDictionary(isolation_key_, dict2);
  dict2.set_primary_key_in_database(result2.primary_key_in_database());

  auto token3 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict3 = SharedDictionaryInfo(
      GURL("https://c.example/dict"),
      /*last_fetch_time=*/base::Time::Now() - base::Seconds(2),
      /*response_time=*/base::Time::Now() - base::Seconds(2),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/5000, SHA256HashValue({{0x00, 0x03}}),
      /*disk_cache_key_token=*/token3,
      /*primary_key_in_database=*/std::nullopt);
  auto result3 = RegisterDictionary(isolation_key_, dict3);
  dict3.set_primary_key_in_database(result3.primary_key_in_database());

  auto token4 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict4 = SharedDictionaryInfo(
      GURL("https://d.example/dict"),
      /*last_fetch_time=*/base::Time::Now() - base::Seconds(1),
      /*response_time=*/base::Time::Now() - base::Seconds(1),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/7000, SHA256HashValue({{0x00, 0x04}}),
      /*disk_cache_key_token=*/token4,
      /*primary_key_in_database=*/std::nullopt);
  auto result4 = RegisterDictionary(isolation_key_, dict4);
  dict4.set_primary_key_in_database(result4.primary_key_in_database());

  EXPECT_EQ(SQLitePersistentSharedDictionaryStore::Error::kOk,
            DeleteDictionariesByDiskCacheKeyTokens({}));

  EXPECT_THAT(
      GetAllDictionaries(),
      ElementsAre(Pair(isolation_key_, UnorderedElementsAreArray(
                                           {dict1, dict2, dict3, dict4}))));
  EXPECT_EQ(16000u, GetTotalDictionarySize());

  EXPECT_EQ(SQLitePersistentSharedDictionaryStore::Error::kOk,
            DeleteDictionariesByDiskCacheKeyTokens({token1}));

  // dict1 must have been deleted.
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key_, UnorderedElementsAreArray(
                                                   {dict2, dict3, dict4}))));
  EXPECT_EQ(15000u, GetTotalDictionarySize());

  EXPECT_EQ(SQLitePersistentSharedDictionaryStore::Error::kOk,
            DeleteDictionariesByDiskCacheKeyTokens({token2, token3}));

  // dict2 and dict3 must have been deleted.
  EXPECT_THAT(
      GetAllDictionaries(),
      ElementsAre(Pair(isolation_key_, UnorderedElementsAreArray({dict4}))));
  EXPECT_EQ(7000u, GetTotalDictionarySize());

  // Call DeleteDictionariesByDiskCacheKeyTokens() with no-maching token.
  EXPECT_EQ(SQLitePersistentSharedDictionaryStore::Error::kOk,
            DeleteDictionariesByDiskCacheKeyTokens(
                {base::UnguessableToken::Create()}));
  EXPECT_THAT(
      GetAllDictionaries(),
      ElementsAre(Pair(isolation_key_, UnorderedElementsAreArray({dict4}))));
  EXPECT_EQ(7000u, GetTotalDictionarySize());

  EXPECT_EQ(SQLitePersistentSharedDictionaryStore::Error::kOk,
            DeleteDictionariesByDiskCacheKeyTokens({token4}));
  // dict4 must have been deleted.
  EXPECT_TRUE(GetAllDictionaries().empty());
  EXPECT_EQ(0u, GetTotalDictionarySize());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       UpdateDictionaryLastFetchTime) {
  CreateStore();
  auto register_dictionary_result =
      RegisterDictionary(isolation_key_, dictionary_info_);

  std::vector<SharedDictionaryInfo> dicts1 = GetDictionaries(isolation_key_);
  ASSERT_EQ(1u, dicts1.size());

  // Move the clock forward by 1 second.
  FastForwardBy(base::Seconds(1));

  const base::Time updated_last_fetch_time = base::Time::Now();
  // Update the last fetch time.
  EXPECT_EQ(SQLitePersistentSharedDictionaryStore::Error::kOk,
            UpdateDictionaryLastFetchTime(
                register_dictionary_result.primary_key_in_database(),
                /*last_fetch_time=*/updated_last_fetch_time));

  std::vector<SharedDictionaryInfo> dicts2 = GetDictionaries(isolation_key_);
  ASSERT_EQ(1u, dicts2.size());

  EXPECT_EQ(dicts1[0].last_fetch_time(), dictionary_info_.last_fetch_time());
  EXPECT_EQ(dicts2[0].last_fetch_time(), updated_last_fetch_time);
  EXPECT_NE(dicts1[0].last_fetch_time(), dicts2[0].last_fetch_time());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       UpdateDictionaryLastUsedTime) {
  CreateStore();
  auto register_dictionary_result =
      RegisterDictionary(isolation_key_, dictionary_info_);

  std::vector<SharedDictionaryInfo> dicts1 = GetDictionaries(isolation_key_);
  ASSERT_EQ(1u, dicts1.size());

  // Move the clock forward by 1 second.
  FastForwardBy(base::Seconds(1));

  std::vector<SharedDictionaryInfo> dicts2 = GetDictionaries(isolation_key_);
  ASSERT_EQ(1u, dicts2.size());

  EXPECT_EQ(dicts1[0].last_used_time(), dicts2[0].last_used_time());

  // Move the clock forward by 1 second.
  FastForwardBy(base::Seconds(1));
  base::Time updated_last_used_time = base::Time::Now();
  store_->UpdateDictionaryLastUsedTime(
      register_dictionary_result.primary_key_in_database(),
      updated_last_used_time);

  std::vector<SharedDictionaryInfo> dicts3 = GetDictionaries(isolation_key_);
  ASSERT_EQ(1u, dicts3.size());
  EXPECT_EQ(updated_last_used_time, dicts3[0].last_used_time());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       MassiveUpdateDictionaryLastUsedTime) {
  CreateStore();
  auto register_dictionary_result =
      RegisterDictionary(isolation_key_, dictionary_info_);
  base::Time up
```