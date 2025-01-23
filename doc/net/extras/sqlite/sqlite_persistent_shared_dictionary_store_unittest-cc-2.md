Response:
The user wants me to summarize the functionality of the provided C++ code snippet. This is the third part of a five-part series, so I should focus on the functions and tests within this specific section.

The code defines tests for the `SQLitePersistentSharedDictionaryStore` class in Chromium's network stack. These tests primarily focus on error handling and specific scenarios related to managing shared dictionaries in the persistent store.

Here's a breakdown of the functionalities covered in this part:

1. **Registering Dictionaries and Eviction:** Tests how registering new dictionaries interacts with size and count limits, potentially evicting older dictionaries.
2. **Error Handling for `GetDictionaries` and `GetAllDictionaries`:** Tests various error conditions during retrieval of dictionaries, like database initialization failure and invalid SQL.
3. **Error Handling for `GetUsageInfo`:** Tests error scenarios for fetching usage information.
4. **Error Handling for `GetOriginsBetween`:**  Tests error scenarios for fetching origins within a time range.
5. **Error Handling for `ClearAllDictionaries`:** Tests error conditions during clearing all dictionaries, including database failures and file access issues.
6. **Error Handling for `ClearDictionaries`:** Tests error conditions for clearing dictionaries based on time range and URL matching, including database failures, invalid SQL, and file access issues. It also covers scenarios where getting the total dictionary size fails.
7. **Error Handling for `ClearDictionariesForIsolationKey`:** Tests error conditions for clearing dictionaries for a specific isolation key.
8. **Error Handling for `DeleteExpiredDictionaries`:** Tests error conditions during the deletion of expired dictionaries.
9. **Error Handling for `ProcessEviction`:** Tests error conditions during the eviction process.
10. **Error Handling for `GetAllDiskCacheKeyTokens`:** Tests error conditions when retrieving all disk cache key tokens.
11. **Error Handling for `DeleteDictionariesByDiskCacheKeyTokens`:** Tests error conditions when deleting dictionaries based on disk cache key tokens.
12. **Error Handling for `UpdateDictionaryLastFetchTime`:** Tests error conditions when updating the last fetch time of a dictionary.
13. **Handling Invalid Data:** Tests how the store handles invalid hash values and tokens in the database.
14. **Callback Behavior After Deletion:** Tests that callbacks are not invoked if the store object is deleted before the operation completes.
15. **Successful Clearing of Dictionaries:** Tests the successful clearing of dictionaries based on time range and URL matching.

Now, let's address the specific requirements:

*   **Functionality Listing:**  I will list the main functionalities tested in this section.
*   **Relationship with JavaScript:** I'll consider if any of these functionalities have a direct impact on JavaScript. Dictionary management affects how the browser handles shared code, which indirectly influences JavaScript performance.
*   **Logical Reasoning (Hypothetical Input/Output):** For the eviction test, I can provide an example of input dictionaries and the expected evicted dictionaries.
*   **User/Programming Errors:**  I'll identify common mistakes that could lead to these error scenarios.
*   **User Operations as Debugging Clues:** I'll outline how user actions might trigger these database operations.
这是`net/extras/sqlite/sqlite_persistent_shared_dictionary_store_unittest.cc`文件的第三部分，主要功能是**测试 `SQLitePersistentSharedDictionaryStore` 类中各种操作失败时的错误处理机制以及一些特定的成功场景**。

**归纳一下它的功能：**

这部分代码着重于测试以下方面的错误处理和特定场景：

*   **注册字典时的容量限制和驱逐行为：** 测试当注册新字典会导致超出单个站点的最大容量或数量限制时，旧字典的驱逐机制。
*   **获取字典信息失败的情况：** 测试 `GetDictionaries` 和 `GetAllDictionaries` 方法在数据库初始化失败或执行无效 SQL 时如何返回错误。
*   **获取使用信息失败的情况：** 测试 `GetUsageInfo` 方法在数据库初始化失败或执行无效 SQL 时如何返回错误。
*   **获取指定时间范围内 Origin 信息失败的情况：** 测试 `GetOriginsBetween` 方法在数据库初始化失败或执行无效 SQL 时如何返回错误。
*   **清除所有字典信息失败的情况：** 测试 `ClearAllDictionaries` 方法在数据库初始化失败或执行 SQL 失败（例如文件不可写）时如何返回错误。
*   **根据条件清除字典信息失败的情况：** 测试 `ClearDictionaries` 方法（包括带 URL 匹配器的版本）在数据库初始化失败、执行无效 SQL 或执行 SQL 失败时如何返回错误。也测试了获取总字典大小失败时的错误处理。
*   **清除特定 Isolation Key 的字典信息失败的情况：** 测试 `ClearDictionariesForIsolationKey` 方法在数据库初始化失败、执行无效 SQL 或获取总字典大小失败时如何返回错误。
*   **删除过期字典信息失败的情况：** 测试 `DeleteExpiredDictionaries` 方法在数据库初始化失败、执行无效 SQL 或获取总字典大小失败时如何返回错误。
*   **处理驱逐操作失败的情况：** 测试 `ProcessEviction` 方法在数据库初始化失败、执行无效 SQL 或执行 SQL 失败时如何返回错误。也测试了获取总字典大小失败时的错误处理。
*   **获取所有 Disk Cache Key Token 失败的情况：** 测试 `GetAllDiskCacheKeyTokens` 方法在数据库初始化失败或执行无效 SQL 时如何返回错误。
*   **通过 Disk Cache Key Token 删除字典信息失败的情况：** 测试 `DeleteDictionariesByDiskCacheKeyTokens` 方法在数据库初始化失败、执行无效 SQL 或获取总字典大小失败时如何返回错误。
*   **更新字典最后获取时间失败的情况：** 测试 `UpdateDictionaryLastFetchTime` 方法在数据库初始化失败或执行无效 SQL 或执行 SQL 失败时如何返回错误。
*   **处理数据库中无效数据的情况：** 测试当数据库中的 SHA256 哈希值或 Disk Cache Key Token 无效时，如何处理并避免崩溃。
*   **测试在 Store 对象被删除后回调不被执行：**  验证在异步操作的回调执行之前，如果 `SQLitePersistentSharedDictionaryStore` 对象被销毁，回调不会被调用，避免了潜在的 use-after-free 问题。
*   **测试成功清除字典的场景：**  测试 `ClearDictionaries` 方法在指定时间范围内成功清除字典，并验证剩余字典和总大小。
*   **测试带 URL 匹配器的成功清除字典的场景：** 测试 `ClearDictionaries` 方法使用 URL 匹配器成功清除特定 Origin 的字典。

**它与 JavaScript 的功能有关系，举例说明：**

Shared Dictionary API 允许网页存储和重用字典资源，从而提高加载速度和效率。`SQLitePersistentSharedDictionaryStore` 负责在浏览器本地持久化存储这些字典信息。

**举例说明：**

1. **注册字典和容量限制:** 当 JavaScript 通过 Shared Dictionary API 请求注册一个新的共享字典时，`SQLitePersistentSharedDictionaryStore` 会尝试将其存储到数据库中。如果当前站点的字典数量或总大小超过限制，存储层会根据一定的策略（例如 LRU）驱逐旧的字典。这直接影响了 JavaScript 能否成功注册字典，以及哪些字典会被保留供后续使用。

    **假设输入：**
    *   JavaScript 代码尝试注册一个新的共享字典，该字典所属的站点已经注册了多个字典，且总大小接近或超过限制。
    *   `max_size_per_site` 和 `max_count_per_site` 被设置为较低的值。

    **输出：**
    *   `RegisterDictionaryImpl` 方法会返回一个 `RegisterDictionaryResult` 对象，其中包含被驱逐的字典的 Disk Cache Key Token 列表。这些被驱逐的字典将无法被该站点后续的请求使用。

2. **清除字典:**  JavaScript 可以通过 API 清除特定或所有共享字典。`SQLitePersistentSharedDictionaryStore` 负责执行这些清除操作。如果数据库操作失败，JavaScript 可能会收到错误通知，表明字典清除失败。

**用户或编程常见的使用错误，请举例说明：**

1. **数据库文件损坏:**  用户本地的浏览器配置文件损坏，导致 SQLite 数据库文件无法正常读取或写入。这会触发诸如 `kFailedToInitializeDatabase` 的错误，导致 JavaScript 的 Shared Dictionary API 操作失败。

2. **存储空间不足:**  用户的磁盘空间不足，导致 SQLite 无法写入新的字典数据。这可能导致注册字典失败，并可能抛出与 SQL 执行相关的错误。

3. **不正确的 API 调用:** 虽然单元测试主要关注存储层，但错误的 JavaScript API 调用，例如尝试注册过大的字典或频繁注册大量字典，可能会间接导致存储层达到容量限制，触发驱逐行为。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户访问网站:** 用户在浏览器中打开一个使用了 Shared Dictionary API 的网站。
2. **网站请求注册共享字典:** 网站的 JavaScript 代码通过 `Document.registerSharedDictionary()` 或相关 API 请求注册一个新的共享字典。
3. **浏览器接收请求:** 浏览器接收到注册共享字典的请求，并将其传递给网络栈中的相应组件。
4. **尝试持久化存储:** `SQLitePersistentSharedDictionaryStore::RegisterDictionaryImpl` 方法被调用，尝试将字典信息写入 SQLite 数据库。
5. **可能触发错误:** 在这个过程中，可能由于以下原因触发测试中模拟的错误情况：
    *   **数据库初始化失败:** 如果是首次使用或数据库文件损坏，初始化可能失败。
    *   **SQL 执行失败:**  如果数据库文件权限不足或磁盘空间不足，SQL 写入操作可能失败。
    *   **超出容量限制:** 如果要注册的字典导致超出当前站点的容量限制，则会触发驱逐逻辑。
6. **错误处理:** 如果发生错误，`SQLitePersistentSharedDictionaryStore` 会返回相应的错误码，并且可能触发回调函数通知上层模块（包括 JavaScript）。

**调试线索:** 如果在实际应用中遇到与共享字典相关的问题，例如注册失败或字典丢失，可以考虑以下调试步骤：

1. **检查浏览器控制台:** 查看是否有与 Shared Dictionary API 相关的错误信息。
2. **检查浏览器内部日志:** Chromium 提供了内部日志记录机制，可以查看更详细的网络和存储操作日志，定位 `SQLitePersistentSharedDictionaryStore` 中发生的错误。
3. **模拟错误场景:** 可以尝试模拟磁盘空间不足或文件权限问题，观察是否会触发类似的错误。
4. **查看数据库文件:** 在开发环境中，可以找到浏览器存储共享字典的 SQLite 数据库文件，查看其状态和内容，验证数据是否正确写入。

总而言之，这部分单元测试主要关注 `SQLitePersistentSharedDictionaryStore` 在各种错误和边界条件下的健壮性，确保即使在异常情况下也能正确处理，并向上层模块返回合适的错误信息。这对于保证 Shared Dictionary API 的可靠性和稳定性至关重要。

### 提示词
```
这是目录为net/extras/sqlite/sqlite_persistent_shared_dictionary_store_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
));

  // The top frame site of `isolation_key3` is same as the top frame site of
  // `isolation_key2`.
  auto isolation_key3 = CreateIsolationKey("https://origin2.test",
                                           "https://top-frame-site2.test");
  auto dict4 = SharedDictionaryInfo(
      GURL("https://d.example/dict"), /*last_fetch_time*/ base::Time::Now(),
      /*response_time=*/base::Time::Now(),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/800, SHA256HashValue({{0x00, 0x04}}),
      /*disk_cache_key_token=*/base::UnguessableToken::Create(),
      /*primary_key_in_database=*/std::nullopt);
  auto result4 = RegisterDictionaryImpl(store_.get(), isolation_key3, dict4,
                                        max_size_per_site, max_count_per_site);
  dict4.set_primary_key_in_database(result4.primary_key_in_database());
  // The dictionary count on "https://top-frame-site2.test" exceeds
  // `max_count_per_site`. Also dictionary size on
  // "https://top-frame-site2.test" exceeds `max_size_per_site`.
  // So both `dict2` and `dict3` must be evicted.
  EXPECT_THAT(result4.evicted_disk_cache_key_tokens(),
              UnorderedElementsAreArray({dict2.disk_cache_key_token(),
                                         dict3.disk_cache_key_token()}));
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key1, ElementsAreArray({dict1})),
                          Pair(isolation_key3, ElementsAreArray({dict4}))));
  EXPECT_EQ(dict1.size() + dict4.size(), GetTotalDictionarySize());
}

void SQLitePersistentSharedDictionaryStoreTest::RunGetDictionariesFailureTest(
    SQLitePersistentSharedDictionaryStore::Error expected_error) {
  CreateStore();
  base::RunLoop run_loop;
  store_->GetDictionaries(
      isolation_key_,
      base::BindLambdaForTesting(
          [&](SQLitePersistentSharedDictionaryStore::DictionaryListOrError
                  result) {
            ASSERT_FALSE(result.has_value());
            EXPECT_EQ(expected_error, result.error());
            run_loop.Quit();
          }));
  run_loop.Run();
  DestroyStore();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       GetDictionariesErrorDatabaseInitializationFailure) {
  CorruptDatabaseFile();
  RunGetDictionariesFailureTest(SQLitePersistentSharedDictionaryStore::Error::
                                    kFailedToInitializeDatabase);
  CheckStoreRecovered();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       GetDictionariesErrorInvalidSql) {
  ManipulateDatabase({"CREATE TABLE dictionaries (dummy TEST NOT NULL)"});
  RunGetDictionariesFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::kInvalidSql);
}

void SQLitePersistentSharedDictionaryStoreTest::
    RunGetAllDictionariesFailureTest(
        SQLitePersistentSharedDictionaryStore::Error expected_error) {
  CreateStore();
  base::RunLoop run_loop;
  store_->GetAllDictionaries(base::BindLambdaForTesting(
      [&](SQLitePersistentSharedDictionaryStore::DictionaryMapOrError result) {
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(expected_error, result.error());
        run_loop.Quit();
      }));
  run_loop.Run();
  DestroyStore();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       GetAllDictionariesErrorDatabaseInitializationFailure) {
  CorruptDatabaseFile();
  RunGetAllDictionariesFailureTest(SQLitePersistentSharedDictionaryStore::
                                       Error::kFailedToInitializeDatabase);
  CheckStoreRecovered();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       GetAllDictionariesErrorInvalidSql) {
  ManipulateDatabase({"CREATE TABLE dictionaries (dummy TEST NOT NULL)"});
  RunGetAllDictionariesFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::kInvalidSql);
}

void SQLitePersistentSharedDictionaryStoreTest::RunGetUsageInfoFailureTest(
    SQLitePersistentSharedDictionaryStore::Error expected_error) {
  CreateStore();
  base::RunLoop run_loop;
  store_->GetUsageInfo(base::BindLambdaForTesting(
      [&](SQLitePersistentSharedDictionaryStore::UsageInfoOrError result) {
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(expected_error, result.error());
        run_loop.Quit();
      }));
  run_loop.Run();
  DestroyStore();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       RunGetUsageInfoErrorDatabaseInitializationFailure) {
  CorruptDatabaseFile();
  RunGetUsageInfoFailureTest(SQLitePersistentSharedDictionaryStore::Error::
                                 kFailedToInitializeDatabase);
  CheckStoreRecovered();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       RunGetUsageInfoErrorInvalidSql) {
  ManipulateDatabase({"CREATE TABLE dictionaries (dummy TEST NOT NULL)"});
  RunGetUsageInfoFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::kInvalidSql);
}

void SQLitePersistentSharedDictionaryStoreTest::RunGetOriginsBetweenFailureTest(
    SQLitePersistentSharedDictionaryStore::Error expected_error) {
  CreateStore();
  base::RunLoop run_loop;
  store_->GetOriginsBetween(
      base::Time::Now(), base::Time::Now() + base::Seconds(1),
      base::BindLambdaForTesting(
          [&](SQLitePersistentSharedDictionaryStore::OriginListOrError result) {
            ASSERT_FALSE(result.has_value());
            EXPECT_EQ(expected_error, result.error());
            run_loop.Quit();
          }));
  run_loop.Run();
  DestroyStore();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       RunGetOriginsBetweenErrorDatabaseInitializationFailure) {
  CorruptDatabaseFile();
  RunGetOriginsBetweenFailureTest(SQLitePersistentSharedDictionaryStore::Error::
                                      kFailedToInitializeDatabase);
  CheckStoreRecovered();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       RunGetOriginsBetweenErrorInvalidSql) {
  ManipulateDatabase({"CREATE TABLE dictionaries (dummy TEST NOT NULL)"});
  RunGetOriginsBetweenFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::kInvalidSql);
}

void SQLitePersistentSharedDictionaryStoreTest::
    RunClearAllDictionariesFailureTest(
        SQLitePersistentSharedDictionaryStore::Error expected_error) {
  CreateStore();
  base::RunLoop run_loop;
  store_->ClearAllDictionaries(base::BindLambdaForTesting(
      [&](SQLitePersistentSharedDictionaryStore::UnguessableTokenSetOrError
              result) {
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(expected_error, result.error());
        run_loop.Quit();
      }));
  run_loop.Run();
  DestroyStore();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ClearAllDictionariesErrorDatabaseInitializationFailure) {
  CorruptDatabaseFile();
  RunClearAllDictionariesFailureTest(SQLitePersistentSharedDictionaryStore::
                                         Error::kFailedToInitializeDatabase);
  CheckStoreRecovered();
}

#if !BUILDFLAG(IS_FUCHSIA) && !BUILDFLAG(IS_WIN)
// MakeFileUnwritable() doesn't cause the failure on Fuchsia and Windows. So
// disabling the test on Fuchsia and Windows.
TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ClearAllDictionariesErrorSqlExecutionFailure) {
  CreateStore();
  ClearAllDictionaries();
  DestroyStore();
  MakeFileUnwritable();
  RunClearAllDictionariesFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::kFailedToSetTotalDictSize);
}
#endif  // !BUILDFLAG(IS_FUCHSIA)

void SQLitePersistentSharedDictionaryStoreTest::RunClearDictionariesFailureTest(
    base::RepeatingCallback<bool(const GURL&)> url_matcher,
    SQLitePersistentSharedDictionaryStore::Error expected_error) {
  CreateStore();
  base::RunLoop run_loop;
  store_->ClearDictionaries(
      base::Time::Now() - base::Seconds(10), base::Time::Now(),
      std::move(url_matcher),
      base::BindLambdaForTesting(
          [&](SQLitePersistentSharedDictionaryStore::UnguessableTokenSetOrError
                  result) {
            ASSERT_FALSE(result.has_value());
            EXPECT_EQ(expected_error, result.error());
            run_loop.Quit();
          }));
  run_loop.Run();
  DestroyStore();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ClearDictionariesErrorDatabaseInitializationFailure) {
  CorruptDatabaseFile();
  RunClearDictionariesFailureTest(base::RepeatingCallback<bool(const GURL&)>(),
                                  SQLitePersistentSharedDictionaryStore::Error::
                                      kFailedToInitializeDatabase);
  CheckStoreRecovered();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ClearDictionariesErrorInvalidSql) {
  ManipulateDatabase({"CREATE TABLE dictionaries (dummy TEST NOT NULL)"});
  RunClearDictionariesFailureTest(
      base::RepeatingCallback<bool(const GURL&)>(),
      SQLitePersistentSharedDictionaryStore::Error::kInvalidSql);
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ClearDictionariesWithUrlMatcherErrorInvalidSql) {
  ManipulateDatabase({"CREATE TABLE dictionaries (dummy TEST NOT NULL)"});
  RunClearDictionariesFailureTest(
      base::BindRepeating([](const GURL&) { return true; }),
      SQLitePersistentSharedDictionaryStore::Error::kInvalidSql);
}

#if !BUILDFLAG(IS_FUCHSIA) && !BUILDFLAG(IS_WIN)
// MakeFileUnwritable() doesn't cause the failure on Fuchsia and Windows. So
// disabling the test on Fuchsia and Windows.
TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ClearDictionariesErrorSqlExecutionFailure) {
  CreateStore();
  RegisterDictionary(isolation_key_, dictionary_info_);
  DestroyStore();
  MakeFileUnwritable();
  RunClearDictionariesFailureTest(
      base::RepeatingCallback<bool(const GURL&)>(),
      SQLitePersistentSharedDictionaryStore::Error::kFailedToExecuteSql);
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ClearDictionariesWithUrlMatcherErrorSqlExecutionFailure) {
  CreateStore();
  RegisterDictionary(isolation_key_, dictionary_info_);
  DestroyStore();
  MakeFileUnwritable();
  RunClearDictionariesFailureTest(
      base::BindRepeating([](const GURL&) { return true; }),
      SQLitePersistentSharedDictionaryStore::Error::kFailedToExecuteSql);
}
#endif  // !BUILDFLAG(IS_FUCHSIA)

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ClearDictionariesErrorFailedToGetTotalDictSize) {
  CreateStore();
  RegisterDictionary(isolation_key_, dictionary_info_);
  DestroyStore();
  ManipulateDatabase({"DELETE FROM meta WHERE key='total_dict_size'"});

  RunClearDictionariesFailureTest(
      base::RepeatingCallback<bool(const GURL&)>(),
      SQLitePersistentSharedDictionaryStore::Error::kFailedToGetTotalDictSize);

  CreateStore();
  // ClearAllDictionaries() resets total_dict_size in metadata.
  EXPECT_THAT(
      ClearAllDictionaries(),
      UnorderedElementsAreArray({dictionary_info_.disk_cache_key_token()}));
  // So ClearDictionaries() should succeed.
  EXPECT_TRUE(ClearDictionaries(base::Time::Now() - base::Seconds(10),
                                base::Time::Now(),
                                base::RepeatingCallback<bool(const GURL&)>())
                  .empty());
}

void SQLitePersistentSharedDictionaryStoreTest::
    RunClearDictionariesForIsolationKeyFailureTest(
        SQLitePersistentSharedDictionaryStore::Error expected_error) {
  CreateStore();
  base::RunLoop run_loop;
  store_->ClearDictionariesForIsolationKey(
      isolation_key_,
      base::BindLambdaForTesting(
          [&](SQLitePersistentSharedDictionaryStore::UnguessableTokenSetOrError
                  result) {
            ASSERT_FALSE(result.has_value());
            EXPECT_EQ(expected_error, result.error());
            run_loop.Quit();
          }));
  run_loop.Run();
  DestroyStore();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ClearDictionariesForIsolationKeyErrorDatabaseInitializationFailure) {
  CorruptDatabaseFile();
  RunClearDictionariesForIsolationKeyFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::
          kFailedToInitializeDatabase);
  CheckStoreRecovered();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ClearDictionariesForIsolationKeyErrorInvalidSql) {
  ManipulateDatabase({"CREATE TABLE dictionaries (dummy TEST NOT NULL)"});
  RunClearDictionariesForIsolationKeyFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::kInvalidSql);
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ClearDictionariesForIsolationKeyErrorFailedToGetTotalDictSize) {
  CreateStore();
  RegisterDictionary(isolation_key_, dictionary_info_);
  DestroyStore();
  ManipulateDatabase({"DELETE FROM meta WHERE key='total_dict_size'"});

  RunClearDictionariesForIsolationKeyFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::kFailedToGetTotalDictSize);

  CreateStore();
  // ClearAllDictionaries() resets total_dict_size in metadata.
  EXPECT_THAT(
      ClearAllDictionaries(),
      UnorderedElementsAreArray({dictionary_info_.disk_cache_key_token()}));
  // So ClearDictionariesForIsolationKey() should succeed.
  EXPECT_TRUE(ClearDictionariesForIsolationKey(isolation_key_).empty());
}

void SQLitePersistentSharedDictionaryStoreTest::
    RunDeleteExpiredDictionariesFailureTest(
        SQLitePersistentSharedDictionaryStore::Error expected_error) {
  CreateStore();
  base::RunLoop run_loop;
  store_->DeleteExpiredDictionaries(
      base::Time::Now(),
      base::BindLambdaForTesting(
          [&](SQLitePersistentSharedDictionaryStore::UnguessableTokenSetOrError
                  result) {
            ASSERT_FALSE(result.has_value());
            EXPECT_EQ(expected_error, result.error());
            run_loop.Quit();
          }));
  run_loop.Run();
  DestroyStore();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       DeleteExpiredDictionariesErrorDatabaseInitializationFailure) {
  CorruptDatabaseFile();
  RunDeleteExpiredDictionariesFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::
          kFailedToInitializeDatabase);
  CheckStoreRecovered();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       DeleteExpiredDictionariesErrorInvalidSql) {
  ManipulateDatabase({"CREATE TABLE dictionaries (dummy TEST NOT NULL)"});
  RunDeleteExpiredDictionariesFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::kInvalidSql);
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       DeleteExpiredDictionariesErrorFailedToGetTotalDictSize) {
  CreateStore();
  RegisterDictionary(isolation_key_, dictionary_info_);
  DestroyStore();
  ManipulateDatabase({"DELETE FROM meta WHERE key='total_dict_size'"});

  // Move the clock forward by 90 seconds to make `dictionary_info_` expired.
  FastForwardBy(base::Seconds(90));

  RunDeleteExpiredDictionariesFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::kFailedToGetTotalDictSize);

  CreateStore();
  // ClearAllDictionaries() resets total_dict_size in metadata.
  EXPECT_THAT(
      ClearAllDictionaries(),
      UnorderedElementsAreArray({dictionary_info_.disk_cache_key_token()}));
  // So DeleteExpiredDictionaries() should succeed.
  EXPECT_TRUE(DeleteExpiredDictionaries(base::Time::Now()).empty());
}

void SQLitePersistentSharedDictionaryStoreTest::RunProcessEvictionFailureTest(
    SQLitePersistentSharedDictionaryStore::Error expected_error) {
  CreateStore();
  base::RunLoop run_loop;
  store_->ProcessEviction(
      /*cache_max_size=*/1, /*size_low_watermark=*/1,
      /*cache_max_count=*/1, /*count_low_watermark=*/1,
      base::BindLambdaForTesting(
          [&](SQLitePersistentSharedDictionaryStore::UnguessableTokenSetOrError
                  result) {
            ASSERT_FALSE(result.has_value());
            EXPECT_EQ(expected_error, result.error());
            run_loop.Quit();
          }));
  run_loop.Run();
  DestroyStore();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ProcessEvictionErrorDatabaseInitializationFailure) {
  CorruptDatabaseFile();
  RunProcessEvictionFailureTest(SQLitePersistentSharedDictionaryStore::Error::
                                    kFailedToInitializeDatabase);
  CheckStoreRecovered();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ProcessEvictionErrorInvalidSql) {
  CreateStore();
  RegisterDictionary(isolation_key_, dictionary_info_);
  DestroyStore();
  // Delete the existing `dictionaries` table, and create a broken
  // `dictionaries` table.
  ManipulateDatabase({"DROP TABLE dictionaries",
                      "CREATE TABLE dictionaries (dummy TEST NOT NULL)"});
  RunProcessEvictionFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::kInvalidSql);
}

#if !BUILDFLAG(IS_FUCHSIA) && !BUILDFLAG(IS_WIN)
// MakeFileUnwritable() doesn't cause the failure on Fuchsia and Windows. So
// disabling the test on Fuchsia and Windows.
TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ProcessEvictionErrorSqlExecutionFailure) {
  CreateStore();
  RegisterDictionary(isolation_key_, dictionary_info_);
  DestroyStore();
  MakeFileUnwritable();

  RunProcessEvictionFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::kFailedToExecuteSql);
}
#endif  // !BUILDFLAG(IS_FUCHSIA)

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ProcessEvictionErrorFailedToGetTotalDictSize) {
  CreateStore();
  RegisterDictionary(isolation_key_, dictionary_info_);
  DestroyStore();
  ManipulateDatabase({"DELETE FROM meta WHERE key='total_dict_size'"});

  RunProcessEvictionFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::kFailedToGetTotalDictSize);

  CreateStore();
  // ClearAllDictionaries() resets total_dict_size in metadata.
  EXPECT_THAT(
      ClearAllDictionaries(),
      UnorderedElementsAreArray({dictionary_info_.disk_cache_key_token()}));
  // So ProcessEviction() should succeed.
  EXPECT_TRUE(ProcessEviction(
                  /*cache_max_size=*/1, /*size_low_watermark=*/1,
                  /*cache_max_count=*/1, /*count_low_watermark=*/1)
                  .empty());
}

void SQLitePersistentSharedDictionaryStoreTest::
    RunGetAllDiskCacheKeyTokensFailureTest(
        SQLitePersistentSharedDictionaryStore::Error expected_error) {
  CreateStore();
  base::RunLoop run_loop;
  store_->GetAllDiskCacheKeyTokens(base::BindLambdaForTesting(
      [&](SQLitePersistentSharedDictionaryStore::UnguessableTokenSetOrError
              result) {
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(expected_error, result.error());
        run_loop.Quit();
      }));
  run_loop.Run();
  DestroyStore();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       GetAllDiskCacheKeyTokensErrorDatabaseInitializationFailure) {
  CorruptDatabaseFile();
  RunGetAllDiskCacheKeyTokensFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::
          kFailedToInitializeDatabase);
  CheckStoreRecovered();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       GetAllDiskCacheKeyTokensErrorInvalidSql) {
  ManipulateDatabase({"CREATE TABLE dictionaries (dummy TEST NOT NULL)"});
  RunGetAllDiskCacheKeyTokensFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::kInvalidSql);
}

TEST_F(
    SQLitePersistentSharedDictionaryStoreTest,
    DeleteDictionariesByDiskCacheKeyTokensErrorDatabaseInitializationFailure) {
  CorruptDatabaseFile();
  CreateStore();
  EXPECT_EQ(
      SQLitePersistentSharedDictionaryStore::Error::kFailedToInitializeDatabase,
      DeleteDictionariesByDiskCacheKeyTokens(
          {dictionary_info_.disk_cache_key_token()}));
  DestroyStore();
  CheckStoreRecovered();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       DeleteDictionariesByDiskCacheKeyTokensErrorInvalidSql) {
  ManipulateDatabase({"CREATE TABLE dictionaries (dummy TEST NOT NULL)"});
  CreateStore();
  EXPECT_EQ(SQLitePersistentSharedDictionaryStore::Error::kInvalidSql,
            DeleteDictionariesByDiskCacheKeyTokens(
                {dictionary_info_.disk_cache_key_token()}));
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       DeleteDictionariesByDiskCacheKeyTokensErrorFailedToGetTotalDictSize) {
  CreateStore();
  RegisterDictionary(isolation_key_, dictionary_info_);
  DestroyStore();
  ManipulateDatabase({"DELETE FROM meta WHERE key='total_dict_size'"});
  CreateStore();
  EXPECT_EQ(
      SQLitePersistentSharedDictionaryStore::Error::kFailedToGetTotalDictSize,
      DeleteDictionariesByDiskCacheKeyTokens(
          {dictionary_info_.disk_cache_key_token()}));

  // ClearAllDictionaries() resets total_dict_size in metadata.
  EXPECT_THAT(
      ClearAllDictionaries(),
      UnorderedElementsAreArray({dictionary_info_.disk_cache_key_token()}));
  // So DeleteDictionariesByDiskCacheKeyTokens() should succeed.
  EXPECT_EQ(SQLitePersistentSharedDictionaryStore::Error::kOk,
            DeleteDictionariesByDiskCacheKeyTokens(
                {base::UnguessableToken::Create()}));
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       UpdateDictionaryLastFetchTimeErrorDatabaseInitializationFailure) {
  CorruptDatabaseFile();
  CreateStore();
  EXPECT_EQ(
      SQLitePersistentSharedDictionaryStore::Error::kFailedToInitializeDatabase,
      UpdateDictionaryLastFetchTime(/*primary_key_in_database=*/0,
                                    /*last_fetch_time=*/base::Time::Now()));
  DestroyStore();
  CheckStoreRecovered();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       UpdateDictionaryLastFetchTimeErrorInvalidSql) {
  ManipulateDatabase({"CREATE TABLE dictionaries (dummy TEST NOT NULL)"});
  CreateStore();
  EXPECT_EQ(
      SQLitePersistentSharedDictionaryStore::Error::kInvalidSql,
      UpdateDictionaryLastFetchTime(/*primary_key_in_database=*/0,
                                    /*last_fetch_time=*/base::Time::Now()));
}

#if !BUILDFLAG(IS_FUCHSIA) && !BUILDFLAG(IS_WIN)
// MakeFileUnwritable() doesn't cause the failure on Fuchsia and Windows. So
// disabling the test on Fuchsia and Windows.
TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       UpdateDictionaryLastFetchTimeErrorSqlExecutionFailure) {
  CreateStore();
  auto register_dictionary_result =
      RegisterDictionary(isolation_key_, dictionary_info_);
  DestroyStore();
  MakeFileUnwritable();
  CreateStore();
  EXPECT_EQ(SQLitePersistentSharedDictionaryStore::Error::kFailedToExecuteSql,
            UpdateDictionaryLastFetchTime(
                register_dictionary_result.primary_key_in_database(),
                /*last_fetch_time=*/base::Time::Now()));
}
#endif  // !BUILDFLAG(IS_FUCHSIA)

TEST_F(SQLitePersistentSharedDictionaryStoreTest, InvalidHash) {
  CreateStore();
  auto register_dictionary_result =
      RegisterDictionary(isolation_key_, dictionary_info_);
  SharedDictionaryInfo expected_info = dictionary_info_;
  expected_info.set_primary_key_in_database(
      register_dictionary_result.primary_key_in_database());
  EXPECT_THAT(GetDictionaries(isolation_key_),
              ElementsAreArray({expected_info}));
  DestroyStore();

  ManipulateDatabase({"UPDATE dictionaries set sha256='DUMMY'"});

  CreateStore();
  EXPECT_TRUE(GetDictionaries(isolation_key_).empty());
  EXPECT_TRUE(GetAllDictionaries().empty());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest, InvalidToken) {
  CreateStore();
  auto register_dictionary_result =
      RegisterDictionary(isolation_key_, dictionary_info_);
  SharedDictionaryInfo expected_info = dictionary_info_;
  expected_info.set_primary_key_in_database(
      register_dictionary_result.primary_key_in_database());
  EXPECT_THAT(GetDictionaries(isolation_key_),
              ElementsAreArray({expected_info}));
  DestroyStore();

  // {token_low=0, token_high=0} token is treated as invalid.
  ManipulateDatabase({"UPDATE dictionaries set token_low=0, token_high=0"});

  CreateStore();
  EXPECT_TRUE(GetDictionaries(isolation_key_).empty());
  EXPECT_TRUE(GetAllDictionaries().empty());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       GetTotalDictionarySizeCallbackNotCalledAfterStoreDeleted) {
  CreateStore();
  store_->GetTotalDictionarySize(base::BindLambdaForTesting(
      [](base::expected<uint64_t,
                        SQLitePersistentSharedDictionaryStore::Error>) {
        EXPECT_TRUE(false) << "Should not be reached.";
      }));
  store_.reset();
  RunUntilIdle();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       RegisterDictionaryCallbackNotCalledAfterStoreDeleted) {
  CreateStore();
  store_->RegisterDictionary(
      isolation_key_, dictionary_info_,
      /*max_size_per_site=*/1000000,
      /*max_count_per_site=*/1000,
      base::BindLambdaForTesting(
          [](SQLitePersistentSharedDictionaryStore::
                 RegisterDictionaryResultOrError result) {
            EXPECT_TRUE(false) << "Should not be reached.";
          }));
  store_.reset();
  RunUntilIdle();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       GetDictionariesCallbackNotCalledAfterStoreDeleted) {
  CreateStore();
  store_->GetDictionaries(
      isolation_key_,
      base::BindLambdaForTesting(
          [](SQLitePersistentSharedDictionaryStore::DictionaryListOrError) {
            EXPECT_TRUE(false) << "Should not be reached.";
          }));
  store_.reset();
  RunUntilIdle();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       GetAllDictionariesCallbackNotCalledAfterStoreDeleted) {
  CreateStore();
  store_->GetAllDictionaries(base::BindLambdaForTesting(
      [](SQLitePersistentSharedDictionaryStore::DictionaryMapOrError result) {
        EXPECT_TRUE(false) << "Should not be reached.";
      }));
  store_.reset();
  RunUntilIdle();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ClearAllDictionariesCallbackNotCalledAfterStoreDeleted) {
  CreateStore();
  store_->ClearAllDictionaries(base::BindLambdaForTesting(
      [](SQLitePersistentSharedDictionaryStore::UnguessableTokenSetOrError
             result) { EXPECT_TRUE(false) << "Should not be reached."; }));
  store_.reset();
  RunUntilIdle();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ClearDictionariesCallbackNotCalledAfterStoreDeleted) {
  CreateStore();
  store_->ClearDictionaries(
      base::Time::Now() - base::Seconds(1), base::Time::Now(),
      base::RepeatingCallback<bool(const GURL&)>(),
      base::BindLambdaForTesting(
          [&](SQLitePersistentSharedDictionaryStore::UnguessableTokenSetOrError
                  result) { EXPECT_TRUE(false) << "Should not be reached."; }));
  store_.reset();
  RunUntilIdle();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       DeleteExpiredDictionariesCallbackNotCalledAfterStoreDeleted) {
  CreateStore();
  store_->DeleteExpiredDictionaries(
      base::Time::Now(),
      base::BindLambdaForTesting(
          [&](SQLitePersistentSharedDictionaryStore::UnguessableTokenSetOrError
                  result) { EXPECT_TRUE(false) << "Should not be reached."; }));
  store_.reset();
  RunUntilIdle();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest, ClearDictionaries) {
  CreateStore();

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

  // No matching dictionaries to be deleted.
  EXPECT_TRUE(ClearDictionaries(base::Time::Now() - base::Seconds(200),
                                base::Time::Now() - base::Seconds(4),
                                base::RepeatingCallback<bool(const GURL&)>())
                  .empty());

  std::set<base::UnguessableToken> tokens =
      ClearDictionaries(base::Time::Now() - base::Seconds(3),
                        base::Time::Now() - base::Seconds(1),
                        base::RepeatingCallback<bool(const GURL&)>());
  // The dict2 which res_time is "now - 3 sec" and the dict3
  // which res_time is "now - 2 sec" must be deleted.
  EXPECT_THAT(tokens, UnorderedElementsAreArray({token2, token3}));

  // Check the remaining dictionaries.
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key_,
                               UnorderedElementsAreArray({dict1, dict4}))));
  // Check the total size of remaining dictionaries.
  EXPECT_EQ(dict1.size() + dict4.size(), GetTotalDictionarySize());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       ClearDictionariesWithUrlMatcher) {
  CreateStore();

  auto isolation_key1 =
      CreateIsolationKey("https://a1.example/", "https://a2.example/");
  auto token1 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict1 = SharedDictionaryInfo(
      GURL("https://a3.example/dict"),
      /*last_fetch_time=*/base::Time::Now() - base::Seconds(4),
      /*response_time=*/base::Time::Now() - base::Seconds(4),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/1000, SHA256HashValue({{0x00, 0x01}}),
      /*disk_cache_key_token=*/token1,
      /*primary_key_in_database=*/std::nullopt);
  auto result1 = RegisterDictionary(isolation_key1, dict1);
  dict1.set_primary_key_in_database(result1.primary_key_in_database());

  auto isolation_key2 =
      CreateIsolationKey("https://b1.example/", "https://b2.example/");
  auto token2 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict2 = SharedDictionaryInfo(
      GURL("https://b3.example/dict"),
      /*last_fetch_time=*/base::Time::Now() - base::Seconds(3),
      /*response_time=*/base::Time::Now() - base::Seconds(3),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/3000, SHA256HashValue({{0x00, 0x02}}),
      /*disk_cache_key_token=*/token2,
      /*primary_key_in_database=*/std::nullopt);
  auto result2 = RegisterDictionary(isolation_key2, dict2);
  dict2.set_primary_key_in_database(result2.primary_key_in_database());

  auto isolation_key3 =
      CreateIsolationKey("https://c1.example/", "https://c2.example/");
  auto token3 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict3 = SharedDictionaryInfo(
      GURL("https://c3.example/dict"),
      /*last_fetch_time=*/base::Time::Now() - base::Seconds(2),
      /*response_time=*/base::Time::Now() - base::Seconds(2),
      /*expira
```