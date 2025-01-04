Response:
The user wants to understand the functionality of the provided C++ code snippet, which is a part of a unit test file for `SQLitePersistentSharedDictionaryStore` in Chromium's network stack.

Here's a breakdown of how to address the user's request:

1. **Identify the Core Functionality:** The code primarily tests the behavior of storing and managing shared dictionaries in a persistent SQLite database. It focuses on scenarios involving multiple dictionaries with varying origins, sites, and matching patterns. Key functionalities being tested are registering dictionaries, handling size and count limits per site, and eviction policies.

2. **Relate to JavaScript (if applicable):** Shared dictionaries are a web platform feature accessible through JavaScript. Consider how the C++ backend interacts with JavaScript APIs.

3. **Illustrate with Logical Reasoning (Input/Output):**  For complex scenarios like eviction, provide concrete examples of what happens when certain conditions are met. This involves defining initial states (input) and the resulting state after the operation (output).

4. **Highlight Common User/Programming Errors:** Think about how developers might misuse or misunderstand the shared dictionary API or the underlying storage mechanism.

5. **Explain User Interaction for Debugging:** Trace the steps a user might take that would lead to this code being executed, particularly in a debugging context.

6. **Summarize the Functionality of the Provided Snippet:** Condense the observations into a concise summary.

**Mental Sandbox Simulation:**

* **Scenario 1: Multiple Dictionaries, Different Origins:**  Imagine two websites from different origins using shared dictionaries. The test verifies that these dictionaries are stored separately.
* **Scenario 2: Multiple Dictionaries, Same Site:** Now consider two websites under the same top-level site. The test checks if the dictionaries are correctly associated with that site and if size/count limits are applied correctly at the site level.
* **Scenario 3: Eviction:** The most complex part is understanding eviction. Imagine adding dictionaries until storage limits are reached. The tests demonstrate how the system evicts older dictionaries to make space for new ones. Consider both size and count limits.
* **Relating to JavaScript:** A website uses JavaScript to fetch and apply a shared dictionary. The C++ code is the underlying storage mechanism that the browser uses to manage these dictionaries.
* **Debugging:**  A developer might be investigating why a shared dictionary isn't being applied or why it's being evicted unexpectedly. They might set breakpoints in this C++ code to understand the storage behavior.

**Self-Correction/Refinement:**

* Initially, I might focus too much on the low-level SQLite details. The user is asking for the *functionality* in a broader sense, including how it relates to the web platform. I need to balance the technical details with the higher-level purpose.
* The "User Interaction for Debugging" needs to be practical. Thinking about common debugging scenarios (e.g., "why is my dictionary gone?") is more helpful than simply saying "the user browses the web."

By following these steps and simulating different scenarios, I can generate a comprehensive and informative answer for the user.
这是对`net/extras/sqlite/sqlite_persistent_shared_dictionary_store_unittest.cc` 文件第2部分代码功能的归纳。这部分代码主要关注于测试 `SQLitePersistentSharedDictionaryStore` 类在处理多个共享字典时的行为，特别是针对以下几种情况：

**功能归纳:**

1. **测试多个字典的注册和管理:**
   - 这部分代码通过 `RunMultipleDictionariesTest` 模板函数，测试了在数据库中注册和管理多个共享字典的能力。
   - 它验证了即使对于相同的 `isolation_key`，如果字典的 `match` 或 `match_dest_string` 不同，则可以注册多个独立的字典。
   - 它也测试了当所有关键属性（`isolation_key`，`match`，`match_dest_string`）都相同时，新注册的字典会覆盖旧的字典（`expect_merged=true` 的情况）。

2. **测试在不同 Origin 和 Site 下注册多个字典:**
   - 代码测试了当注册的字典来自不同的 Origin 但属于相同的 Site 时，以及来自完全不同的 Site 时，字典是否能够正确存储和区分。

3. **测试注册字典时的大小和数量限制以及驱逐策略:**
   -  代码中包含了多个 `TEST_F` 函数，专门测试了在注册新字典时，如果超出每个站点的最大大小 (`max_size_per_site`) 或最大数量 (`max_count_per_site`) 限制时，旧的字典会被驱逐的机制。
   - 它验证了在超出限制时，最早注册的字典会被优先驱逐，并且返回被驱逐字典的 `disk_cache_key_token`。
   - 它还测试了仅有数量限制而没有大小限制的情况下的驱逐行为。

4. **测试 `GetTotalDictionarySize` 的错误处理:**
   - 代码测试了在数据库初始化失败或无法获取总字典大小时，`GetTotalDictionarySize` 方法是否会返回预期的错误。

5. **测试 `RegisterDictionary` 的错误处理:**
   - 代码详细测试了 `RegisterDictionary` 方法在各种错误情况下的行为，包括：
     - 数据库初始化失败 (`kFailedToInitializeDatabase`)
     - SQL 语句无效 (`kInvalidSql`)
     - SQL 执行失败 (`kFailedToExecuteSql`) (在非 Fuchsia 和 Windows 平台上测试)
     - 无法获取总字典大小 (`kFailedToGetTotalDictSize`)
     - 总字典大小计算错误 (`kInvalidTotalDictSize`)
     - 尝试注册过大的字典 (`kTooBigDictionary`)

**与 JavaScript 的关系:**

这部分代码测试的是浏览器底层存储共享字典的功能。当网页通过 JavaScript 使用 Shared Dictionary API 时，例如：

```javascript
const dictionary = await fetch('/my-dictionary.dict');
const response = await fetch('/my-resource', {
  headers: {
    'Accept-Encoding': 'shared-dictionary',
    'Dictionary-Count': '1',
    'Dictionary-Name': 'my-dictionary'
  }
});
const text = await response.text();
```

- 浏览器会根据请求头中的 `Dictionary-Name` 和其他信息，查找匹配的共享字典。
- `SQLitePersistentSharedDictionaryStore` 负责存储和检索这些字典的信息，例如字典的内容、匹配规则、过期时间等。
- 当注册一个新的共享字典时（通常是服务器通过 `Cache-Control: private, shared-dictionary=...` 响应头指示浏览器存储），这部分 C++ 代码会被调用来将字典信息持久化到 SQLite 数据库中。
- 这里的测试确保了即使有多个来自不同 Origin 或 Site 的字典，浏览器也能正确存储和管理它们，并能在 JavaScript 请求时找到正确的字典。

**逻辑推理 (假设输入与输出):**

**场景:** 注册两个来自相同 Site 但不同 Origin 的字典，并设置了大小限制。

**假设输入:**

1. **已注册字典 1:**
   - `isolation_key`: Origin "https://origin1.test", Top-frame site "https://top-frame-site.test"
   - `size`: 10000 字节 (假设 `max_size_per_site` 为 10000)
2. **尝试注册字典 2:**
   - `isolation_key`: Origin "https://origin2.test", Top-frame site "https://top-frame-site.test"
   - `size`: 5000 字节

**预期输出:**

- 字典 2 成功注册。
- `GetTotalDictionarySize()` 返回 15000 字节。
- `GetAllDictionaries()` 将包含两个不同的字典条目，分别对应字典 1 和字典 2，但它们属于相同的 Top-frame site。

**场景:** 在相同 Site 下注册超出数量限制的字典。

**假设输入:**

1. **已注册字典 1:** Top-frame site "https://top-frame-site.test"
2. **已注册字典 2:** Top-frame site "https://top-frame-site.test"
   - (假设 `max_count_per_site` 为 2)
3. **尝试注册字典 3:** Top-frame site "https://top-frame-site.test"

**预期输出:**

- 字典 1 (假设它是最早注册的) 会被驱逐。
- `RegisterDictionary` 方法会返回包含字典 1 的 `disk_cache_key_token` 的结果。
- `GetAllDictionaries()` 将只包含字典 2 和字典 3。

**用户或编程常见的使用错误:**

1. **超过每个站点的存储限制:** 开发者可能会错误地假设浏览器可以无限存储共享字典，导致在超出 `max_size_per_site` 或 `max_count_per_site` 限制后，新的字典无法注册或旧的字典被意外驱逐。
   - **例子:** 服务器端配置不当，导致浏览器尝试存储大量大型的共享字典。
2. **不理解 Origin 和 Site 的区别:** 开发者可能认为来自相同 Origin 的内容共享相同的字典存储空间，但实际上共享字典的限制是基于 Top-frame site 的。
   - **例子:** 一个网站的多个子域名提供了不同的共享字典，开发者可能期望它们都在同一个配额下，但实际上它们属于同一个 Site，会受到相同的限制。
3. **错误地配置匹配规则 (`match` 和 `match_dest_string`):**  如果匹配规则配置不当，可能会导致预期的字典没有被使用，或者意外地使用了错误的字典。
   - **例子:** `match` 规则过于宽泛，导致不同的资源意外匹配到同一个共享字典。

**用户操作到达这里的调试线索:**

一个开发者在调试与共享字典相关的问题时，可能会逐步到达这里：

1. **用户报告或开发者发现共享字典没有生效。**
2. **开发者开始检查网络请求和响应头，查看 `Accept-Encoding`，`Dictionary-Name` 等相关信息。**
3. **开发者可能会使用 Chrome 的开发者工具，查看 "Application" -> "Shared Dictionary Storage"，看是否有预期的字典被存储。**
4. **如果发现字典没有被存储，或者被意外驱逐，开发者可能会怀疑是存储层的问题。**
5. **为了进一步调查，开发者可能会下载 Chromium 的源代码，并开始查看 `net/` 目录下的与共享字典相关的代码。**
6. **他们可能会找到 `SQLitePersistentSharedDictionaryStore` 类，因为它负责持久化存储共享字典。**
7. **为了理解存储逻辑和可能出现的错误情况，开发者会查看对应的单元测试文件 `sqlite_persistent_shared_dictionary_store_unittest.cc`。**
8. **他们可能会在相关的测试用例中设置断点，例如测试注册多个字典或测试驱逐策略的用例，来观察代码的执行流程和变量状态。**
9. **通过分析这些测试用例，开发者可以了解在各种情况下，字典是如何被存储、检索和驱逐的，从而找到问题的根源。**

总而言之，这部分代码主要测试了 `SQLitePersistentSharedDictionaryStore` 类在处理多个共享字典时的正确性和健壮性，包括注册、管理、大小和数量限制以及错误处理等方面。这些测试确保了浏览器能够可靠地存储和管理共享字典，从而支持 Web 平台的这一特性。

Prompt: 
```
这是目录为net/extras/sqlite/sqlite_persistent_shared_dictionary_store_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能

"""
)));
    EXPECT_THAT(GetUsageInfo(),
                UnorderedElementsAreArray(
                    {SharedDictionaryUsageInfo{
                         .isolation_key = isolation_key1,
                         .total_size_bytes = dictionary_info1.size()},
                     SharedDictionaryUsageInfo{
                         .isolation_key = isolation_key2,
                         .total_size_bytes = dictionary_info2.size()}}));
    EXPECT_THAT(GetOriginsBetween(oldest_response_time,
                                  latest_response_time + base::Seconds(1)),
                UnorderedElementsAreArray({isolation_key1.frame_origin(),
                                           isolation_key2.frame_origin()}));
  }

  EXPECT_THAT(ClearAllDictionaries(),
              UnorderedElementsAreArray(registered_tokens));
  EXPECT_TRUE(GetDictionaries(isolation_key_).empty());
  EXPECT_TRUE(GetAllDictionaries().empty());
  EXPECT_TRUE(GetUsageInfo().empty());
  EXPECT_TRUE(GetOriginsBetween(oldest_response_time,
                                latest_response_time + base::Seconds(1))
                  .empty());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       MultipleDictionariesDifferentOriginSameSite) {
  SharedDictionaryIsolationKey isolation_key1 =
      CreateIsolationKey("https://www1.origin.test/");
  SharedDictionaryIsolationKey isolation_key2 =
      CreateIsolationKey("https://www2.origin.test/");
  EXPECT_NE(isolation_key1, isolation_key2);
  EXPECT_NE(isolation_key1.frame_origin(), isolation_key2.frame_origin());
  EXPECT_EQ(isolation_key1.top_frame_site(), isolation_key2.top_frame_site());
  RunMultipleDictionariesTest(isolation_key1, dictionary_info_, isolation_key2,
                              dictionary_info_, /*expect_merged=*/false);
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       MultipleDictionariesDifferentSite) {
  SharedDictionaryIsolationKey isolation_key1 =
      CreateIsolationKey("https://origin1.test/");
  SharedDictionaryIsolationKey isolation_key2 =
      CreateIsolationKey("https://origin2.test/");
  EXPECT_NE(isolation_key1, isolation_key2);
  EXPECT_NE(isolation_key1.frame_origin(), isolation_key2.frame_origin());
  EXPECT_NE(isolation_key1.top_frame_site(), isolation_key2.top_frame_site());
  RunMultipleDictionariesTest(isolation_key1, dictionary_info_, isolation_key2,
                              dictionary_info_, /*expect_merged=*/false);
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       MultipleDictionariesDifferentHostDifferentMatch) {
  RunMultipleDictionariesTest(
      isolation_key_,
      SharedDictionaryInfo(
          GURL("https://origin1.test/dict"),
          /*last_fetch_time=*/base::Time::Now() - base::Seconds(9),
          /*response_time=*/base::Time::Now() - base::Seconds(10),
          /*expiration*/ base::Seconds(100), /*match=*/"/pattern1*",
          /*match_dest_string=*/"", /*id=*/"",
          /*last_used_time*/ base::Time::Now(),
          /*size=*/1000, SHA256HashValue({{0x00, 0x01}}),
          /*disk_cache_key_token=*/base::UnguessableToken::Create(),
          /*primary_key_in_database=*/std::nullopt),
      isolation_key_,
      SharedDictionaryInfo(
          GURL("https://origin2.test/dict"),
          /*last_fetch_time=*/base::Time::Now() - base::Seconds(19),
          /*response_time=*/base::Time::Now() - base::Seconds(20),
          /*expiration*/ base::Seconds(200), /*match=*/"/pattern2*",
          /*match_dest_string=*/"", /*id=*/"",
          /*last_used_time*/ base::Time::Now(),
          /*size=*/2000, SHA256HashValue({{0x00, 0x02}}),
          /*disk_cache_key_token=*/base::UnguessableToken::Create(),
          /*primary_key_in_database=*/std::nullopt),
      /*expect_merged=*/false);
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       SameIsolationKeySameHostDifferentMatchSameMatchDest) {
  RunMultipleDictionariesTest(
      isolation_key_,
      SharedDictionaryInfo(
          GURL("https://origin.test/dict"),
          /*last_fetch_time=*/base::Time::Now() - base::Seconds(9),
          /*response_time=*/base::Time::Now() - base::Seconds(10),
          /*expiration*/ base::Seconds(100), /*match=*/"/pattern1*",
          /*match_dest_string=*/"", /*id=*/"",
          /*last_used_time*/ base::Time::Now(),
          /*size=*/1000, SHA256HashValue({{0x00, 0x01}}),
          /*disk_cache_key_token=*/base::UnguessableToken::Create(),
          /*primary_key_in_database=*/std::nullopt),
      isolation_key_,
      SharedDictionaryInfo(
          GURL("https://origin.test/dict"),
          /*last_fetch_time=*/base::Time::Now() - base::Seconds(19),
          /*response_time=*/base::Time::Now() - base::Seconds(20),
          /*expiration*/ base::Seconds(200), /*match=*/"/pattern2*",
          /*match_dest_string=*/"", /*id=*/"",
          /*last_used_time*/ base::Time::Now(),
          /*size=*/2000, SHA256HashValue({{0x00, 0x02}}),
          /*disk_cache_key_token=*/base::UnguessableToken::Create(),
          /*primary_key_in_database=*/std::nullopt),
      /*expect_merged=*/false);
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       SameIsolationKeySameHostSameMatchSameMatchDest) {
  RunMultipleDictionariesTest(
      isolation_key_,
      SharedDictionaryInfo(
          GURL("https://origin.test/dict"),
          /*last_fetch_time=*/base::Time::Now() - base::Seconds(9),
          /*response_time=*/base::Time::Now() - base::Seconds(10),
          /*expiration*/ base::Seconds(100), /*match=*/"/pattern*",
          /*match_dest_string=*/"", /*id=*/"",
          /*last_used_time*/ base::Time::Now(),
          /*size=*/1000, SHA256HashValue({{0x00, 0x01}}),
          /*disk_cache_key_token=*/base::UnguessableToken::Create(),
          /*primary_key_in_database=*/std::nullopt),
      isolation_key_,
      SharedDictionaryInfo(
          GURL("https://origin.test/dict"),
          /*last_fetch_time=*/base::Time::Now() - base::Seconds(19),
          /*response_time=*/base::Time::Now() - base::Seconds(20),
          /*expiration*/ base::Seconds(200), /*match=*/"/pattern*",
          /*match_dest_string=*/"", /*id=*/"",
          /*last_used_time*/ base::Time::Now(),
          /*size=*/2000, SHA256HashValue({{0x00, 0x02}}),
          /*disk_cache_key_token=*/base::UnguessableToken::Create(),
          /*primary_key_in_database=*/std::nullopt),
      /*expect_merged=*/true);
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       SameIsolationKeySameHostSameMatchDifferentMatchDest) {
  RunMultipleDictionariesTest(
      isolation_key_,
      SharedDictionaryInfo(
          GURL("https://origin.test/dict"),
          /*last_fetch_time=*/base::Time::Now() - base::Seconds(9),
          /*response_time=*/base::Time::Now() - base::Seconds(10),
          /*expiration*/ base::Seconds(100), /*match=*/"/pattern*",
          /*match_dest_string=*/"document", /*id=*/"",
          /*last_used_time*/ base::Time::Now(),
          /*size=*/1000, SHA256HashValue({{0x00, 0x01}}),
          /*disk_cache_key_token=*/base::UnguessableToken::Create(),
          /*primary_key_in_database=*/std::nullopt),
      isolation_key_,
      SharedDictionaryInfo(
          GURL("https://origin.test/dict"),
          /*last_fetch_time=*/base::Time::Now() - base::Seconds(19),
          /*response_time=*/base::Time::Now() - base::Seconds(20),
          /*expiration*/ base::Seconds(200), /*match=*/"/pattern*",
          /*match_dest_string=*/"script", /*id=*/"",
          /*last_used_time*/ base::Time::Now(),
          /*size=*/2000, SHA256HashValue({{0x00, 0x02}}),
          /*disk_cache_key_token=*/base::UnguessableToken::Create(),
          /*primary_key_in_database=*/std::nullopt),
      /*expect_merged=*/false);
}

void SQLitePersistentSharedDictionaryStoreTest::
    RunGetTotalDictionarySizeFailureTest(
        SQLitePersistentSharedDictionaryStore::Error expected_error) {
  CreateStore();
  base::RunLoop run_loop;
  store_->GetTotalDictionarySize(base::BindLambdaForTesting(
      [&](base::expected<uint64_t, SQLitePersistentSharedDictionaryStore::Error>
              result) {
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(expected_error, result.error());
        run_loop.Quit();
      }));
  run_loop.Run();
  DestroyStore();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       GetTotalDictionarySizeErrorInitializationFailure) {
  CorruptDatabaseFile();
  RunGetTotalDictionarySizeFailureTest(SQLitePersistentSharedDictionaryStore::
                                           Error::kFailedToInitializeDatabase);
  CheckStoreRecovered();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       GetTotalDictionarySizeErrorFailedToGetTotalDictSize) {
  CreateStore();
  EXPECT_TRUE(ClearAllDictionaries().empty());
  DestroyStore();
  ManipulateDatabase({"DELETE FROM meta WHERE key='total_dict_size'"});

  RunGetTotalDictionarySizeFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::kFailedToGetTotalDictSize);

  CreateStore();
  // ClearAllDictionaries() resets total_dict_size in metadata.
  EXPECT_TRUE(ClearAllDictionaries().empty());
  // So GetTotalDictionarySize() should succeed.
  EXPECT_EQ(0u, GetTotalDictionarySize());
}

void SQLitePersistentSharedDictionaryStoreTest::
    RunRegisterDictionaryFailureTest(
        SQLitePersistentSharedDictionaryStore::Error expected_error) {
  CreateStore();
  base::RunLoop run_loop;
  store_->RegisterDictionary(
      isolation_key_, dictionary_info_, /*max_size_per_site=*/1000000,
      /*max_count_per_site=*/1000,
      base::BindLambdaForTesting(
          [&](SQLitePersistentSharedDictionaryStore::
                  RegisterDictionaryResultOrError result) {
            ASSERT_FALSE(result.has_value());
            EXPECT_EQ(expected_error, result.error());
            run_loop.Quit();
          }));
  run_loop.Run();
  DestroyStore();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       RegisterDictionaryErrorDatabaseInitializationFailure) {
  CorruptDatabaseFile();
  RunRegisterDictionaryFailureTest(SQLitePersistentSharedDictionaryStore::
                                       Error::kFailedToInitializeDatabase);
  CheckStoreRecovered();
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       RegisterDictionaryErrorInvalidSql) {
  ManipulateDatabase({"CREATE TABLE dictionaries (dummy TEST NOT NULL)"});
  RunRegisterDictionaryFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::kInvalidSql);
}

#if !BUILDFLAG(IS_FUCHSIA) && !BUILDFLAG(IS_WIN)
// MakeFileUnwritable() doesn't cause the failure on Fuchsia and Windows. So
// disabling the test on Fuchsia and Windows.
TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       RegisterDictionaryErrorSqlExecutionFailure) {
  CreateStore();
  ClearAllDictionaries();
  DestroyStore();
  MakeFileUnwritable();
  RunRegisterDictionaryFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::kFailedToExecuteSql);
}
#endif  // !BUILDFLAG(IS_FUCHSIA)

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       RegisterDictionaryErrorFailedToGetTotalDictSize) {
  CreateStore();
  ClearAllDictionaries();
  DestroyStore();
  ManipulateDatabase({"DELETE FROM meta WHERE key='total_dict_size'"});

  RunRegisterDictionaryFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::kFailedToGetTotalDictSize);

  CreateStore();
  // ClearAllDictionaries() resets total_dict_size in metadata.
  EXPECT_TRUE(ClearAllDictionaries().empty());
  // So RegisterDictionary() should succeed.
  RegisterDictionary(isolation_key_, dictionary_info_);
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       RegisterDictionaryErrorInvalidTotalDictSize) {
  CreateStore();

  SharedDictionaryInfo dictionary_info(
      dictionary_info_.url(), /*last_fetch_time*/ base::Time::Now(),
      /*response_time*/ base::Time::Now(), dictionary_info_.expiration(),
      dictionary_info_.match(), dictionary_info_.match_dest_string(),
      dictionary_info_.id(),
      /*last_used_time*/ base::Time::Now(), dictionary_info_.size() + 1,
      SHA256HashValue({{0x00, 0x02}}),
      /*disk_cache_key_token=*/base::UnguessableToken::Create(),
      /*primary_key_in_database=*/std::nullopt);

  // Register the dictionary which size is dictionary_info_.size() + 1.
  base::RunLoop run_loop;
  store_->RegisterDictionary(
      isolation_key_, dictionary_info, /*max_size_per_site=*/1000000,
      /*max_count_per_site=*/1000,
      base::BindLambdaForTesting(
          [&](SQLitePersistentSharedDictionaryStore::
                  RegisterDictionaryResultOrError result) {
            EXPECT_TRUE(result.has_value());
            run_loop.Quit();
          }));
  run_loop.Run();

  DestroyStore();

  // Set total_dict_size in metadata to 0.
  ManipulateDatabase({"UPDATE meta SET value=0 WHERE key='total_dict_size'"});

  // Registering `dictionary_info_` which size is smaller than the previous
  // dictionary cause InvalidTotalDictSize error because the calculated total
  // size will be negative.
  RunRegisterDictionaryFailureTest(
      SQLitePersistentSharedDictionaryStore::Error::kInvalidTotalDictSize);
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       RegisterDictionaryErrorTooBigDictionary) {
  CreateStore();
  uint64_t max_size_per_site = 10000;
  base::RunLoop run_loop;
  store_->RegisterDictionary(
      isolation_key_,
      SharedDictionaryInfo(
          GURL("https://a.example/dict"), /*last_fetch_time*/ base::Time::Now(),
          /*response_time=*/base::Time::Now(),
          /*expiration*/ base::Seconds(100), "/pattern*",
          /*match_dest_string=*/"", /*id=*/"",
          /*last_used_time*/ base::Time::Now(),
          /*size=*/max_size_per_site + 1, SHA256HashValue({{0x00, 0x01}}),
          /*disk_cache_key_token=*/base::UnguessableToken::Create(),
          /*primary_key_in_database=*/std::nullopt),
      max_size_per_site,
      /*max_count_per_site=*/1000,
      base::BindLambdaForTesting(
          [&](SQLitePersistentSharedDictionaryStore::
                  RegisterDictionaryResultOrError result) {
            ASSERT_FALSE(result.has_value());
            EXPECT_EQ(
                SQLitePersistentSharedDictionaryStore::Error::kTooBigDictionary,
                result.error());
            run_loop.Quit();
          }));
  run_loop.Run();
  EXPECT_EQ(0u, GetTotalDictionarySize());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       RegisterDictionaryPerSiteEvictionWhenExceededSizeLimit) {
  CreateStore();

  uint64_t max_size_per_site = 10000;
  uint64_t max_count_per_site = 100;

  auto isolation_key1 = CreateIsolationKey("https://origin1.test",
                                           "https://top-frame-site1.test");
  auto dict1 = SharedDictionaryInfo(
      GURL("https://a.example/dict"), /*last_fetch_time*/ base::Time::Now(),
      /*response_time=*/base::Time::Now(),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/max_size_per_site, SHA256HashValue({{0x00, 0x01}}),
      /*disk_cache_key_token=*/base::UnguessableToken::Create(),
      /*primary_key_in_database=*/std::nullopt);
  auto result1 = RegisterDictionaryImpl(store_.get(), isolation_key1, dict1,
                                        max_size_per_site, max_count_per_site);
  dict1.set_primary_key_in_database(result1.primary_key_in_database());
  EXPECT_TRUE(result1.evicted_disk_cache_key_tokens().empty());
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key1, ElementsAreArray({dict1}))));

  FastForwardBy(base::Seconds(1));

  auto isolation_key2 = CreateIsolationKey("https://origin1.test",
                                           "https://top-frame-site2.test");
  auto dict2 = SharedDictionaryInfo(
      GURL("https://b.example/dict"), /*last_fetch_time*/ base::Time::Now(),
      /*response_time=*/base::Time::Now(),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/max_size_per_site / 2, SHA256HashValue({{0x00, 0x02}}),
      /*disk_cache_key_token=*/base::UnguessableToken::Create(),
      /*primary_key_in_database=*/std::nullopt);
  auto result2 = RegisterDictionaryImpl(store_.get(), isolation_key2, dict2,
                                        max_size_per_site, max_count_per_site);
  dict2.set_primary_key_in_database(result2.primary_key_in_database());
  EXPECT_TRUE(result2.evicted_disk_cache_key_tokens().empty());
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key1, ElementsAreArray({dict1})),
                          Pair(isolation_key2, ElementsAreArray({dict2}))));

  FastForwardBy(base::Seconds(1));

  auto dict3 = SharedDictionaryInfo(
      GURL("https://c.example/dict"), /*last_fetch_time*/ base::Time::Now(),
      /*response_time=*/base::Time::Now(),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/max_size_per_site / 2, SHA256HashValue({{0x00, 0x03}}),
      /*disk_cache_key_token=*/base::UnguessableToken::Create(),
      /*primary_key_in_database=*/std::nullopt);
  auto result3 = RegisterDictionaryImpl(store_.get(), isolation_key2, dict3,
                                        max_size_per_site, max_count_per_site);
  dict3.set_primary_key_in_database(result3.primary_key_in_database());
  EXPECT_TRUE(result3.evicted_disk_cache_key_tokens().empty());
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key1, ElementsAreArray({dict1})),
                          Pair(isolation_key2,
                               UnorderedElementsAreArray({dict2, dict3}))));

  FastForwardBy(base::Seconds(1));

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
      /*size=*/1, SHA256HashValue({{0x00, 0x04}}),
      /*disk_cache_key_token=*/base::UnguessableToken::Create(),
      /*primary_key_in_database=*/std::nullopt);
  auto result4 = RegisterDictionaryImpl(store_.get(), isolation_key3, dict4,
                                        max_size_per_site, max_count_per_site);
  dict4.set_primary_key_in_database(result4.primary_key_in_database());
  // dict2.size() + dict3.size() + dict4.size() exceeds `max_size_per_site`. So
  // the oldest dictionary `dict2` must be evicted.
  EXPECT_THAT(result4.evicted_disk_cache_key_tokens(),
              ElementsAreArray({dict2.disk_cache_key_token()}));
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key1, ElementsAreArray({dict1})),
                          Pair(isolation_key2, ElementsAreArray({dict3})),
                          Pair(isolation_key3, ElementsAreArray({dict4}))));
  EXPECT_EQ(dict1.size() + dict3.size() + dict4.size(),
            GetTotalDictionarySize());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       RegisterDictionaryPerSiteEvictionWhenExceededCountLimit) {
  CreateStore();

  uint64_t max_size_per_site = 10000;
  uint64_t max_count_per_site = 2;

  auto isolation_key1 = CreateIsolationKey("https://origin1.test",
                                           "https://top-frame-site1.test");
  auto dict1 = SharedDictionaryInfo(
      GURL("https://a.example/dict"), /*last_fetch_time*/ base::Time::Now(),
      /*response_time=*/base::Time::Now(),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/100, SHA256HashValue({{0x00, 0x01}}),
      /*disk_cache_key_token=*/base::UnguessableToken::Create(),
      /*primary_key_in_database=*/std::nullopt);
  auto result1 = RegisterDictionaryImpl(store_.get(), isolation_key1, dict1,
                                        max_size_per_site, max_count_per_site);
  dict1.set_primary_key_in_database(result1.primary_key_in_database());
  EXPECT_TRUE(result1.evicted_disk_cache_key_tokens().empty());
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key1, ElementsAreArray({dict1}))));

  FastForwardBy(base::Seconds(1));

  auto isolation_key2 = CreateIsolationKey("https://origin1.test",
                                           "https://top-frame-site2.test");
  auto dict2 = SharedDictionaryInfo(
      GURL("https://b.example/dict"), /*last_fetch_time*/ base::Time::Now(),
      /*response_time=*/base::Time::Now(),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/200, SHA256HashValue({{0x00, 0x02}}),
      /*disk_cache_key_token=*/base::UnguessableToken::Create(),
      /*primary_key_in_database=*/std::nullopt);
  auto result2 = RegisterDictionaryImpl(store_.get(), isolation_key2, dict2,
                                        max_size_per_site, max_count_per_site);
  dict2.set_primary_key_in_database(result2.primary_key_in_database());
  EXPECT_TRUE(result2.evicted_disk_cache_key_tokens().empty());
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key1, ElementsAreArray({dict1})),
                          Pair(isolation_key2, ElementsAreArray({dict2}))));

  FastForwardBy(base::Seconds(1));

  auto dict3 = SharedDictionaryInfo(
      GURL("https://c.example/dict"), /*last_fetch_time*/ base::Time::Now(),
      /*response_time=*/base::Time::Now(),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/400, SHA256HashValue({{0x00, 0x03}}),
      /*disk_cache_key_token=*/base::UnguessableToken::Create(),
      /*primary_key_in_database=*/std::nullopt);
  auto result3 = RegisterDictionaryImpl(store_.get(), isolation_key2, dict3,
                                        max_size_per_site, max_count_per_site);
  dict3.set_primary_key_in_database(result3.primary_key_in_database());
  EXPECT_TRUE(result3.evicted_disk_cache_key_tokens().empty());
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key1, ElementsAreArray({dict1})),
                          Pair(isolation_key2,
                               UnorderedElementsAreArray({dict2, dict3}))));

  FastForwardBy(base::Seconds(1));

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
  // `max_count_per_site`. So the oldest dictionary `dict2` must be evicted.
  EXPECT_THAT(result4.evicted_disk_cache_key_tokens(),
              ElementsAreArray({dict2.disk_cache_key_token()}));
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key1, ElementsAreArray({dict1})),
                          Pair(isolation_key2, ElementsAreArray({dict3})),
                          Pair(isolation_key3, ElementsAreArray({dict4}))));
  EXPECT_EQ(dict1.size() + dict3.size() + dict4.size(),
            GetTotalDictionarySize());
}

TEST_F(
    SQLitePersistentSharedDictionaryStoreTest,
    RegisterDictionaryPerSiteEvictionWhenExceededCountLimitWithoutSizeLimit) {
  CreateStore();

  uint64_t max_size_per_site = 0;
  uint64_t max_count_per_site = 2;

  auto isolation_key1 = CreateIsolationKey("https://origin1.test",
                                           "https://top-frame-site1.test");
  auto dict1 = SharedDictionaryInfo(
      GURL("https://a.example/dict"), /*last_fetch_time*/ base::Time::Now(),
      /*response_time=*/base::Time::Now(),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/100, SHA256HashValue({{0x00, 0x01}}),
      /*disk_cache_key_token=*/base::UnguessableToken::Create(),
      /*primary_key_in_database=*/std::nullopt);
  auto result1 = RegisterDictionaryImpl(store_.get(), isolation_key1, dict1,
                                        max_size_per_site, max_count_per_site);
  dict1.set_primary_key_in_database(result1.primary_key_in_database());
  EXPECT_TRUE(result1.evicted_disk_cache_key_tokens().empty());
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key1, ElementsAreArray({dict1}))));

  FastForwardBy(base::Seconds(1));

  auto isolation_key2 = CreateIsolationKey("https://origin1.test",
                                           "https://top-frame-site2.test");
  auto dict2 = SharedDictionaryInfo(
      GURL("https://b.example/dict"), /*last_fetch_time*/ base::Time::Now(),
      /*response_time=*/base::Time::Now(),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/200, SHA256HashValue({{0x00, 0x02}}),
      /*disk_cache_key_token=*/base::UnguessableToken::Create(),
      /*primary_key_in_database=*/std::nullopt);
  auto result2 = RegisterDictionaryImpl(store_.get(), isolation_key2, dict2,
                                        max_size_per_site, max_count_per_site);
  dict2.set_primary_key_in_database(result2.primary_key_in_database());
  EXPECT_TRUE(result2.evicted_disk_cache_key_tokens().empty());
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key1, ElementsAreArray({dict1})),
                          Pair(isolation_key2, ElementsAreArray({dict2}))));

  FastForwardBy(base::Seconds(1));

  auto dict3 = SharedDictionaryInfo(
      GURL("https://c.example/dict"), /*last_fetch_time*/ base::Time::Now(),
      /*response_time=*/base::Time::Now(),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/400, SHA256HashValue({{0x00, 0x03}}),
      /*disk_cache_key_token=*/base::UnguessableToken::Create(),
      /*primary_key_in_database=*/std::nullopt);
  auto result3 = RegisterDictionaryImpl(store_.get(), isolation_key2, dict3,
                                        max_size_per_site, max_count_per_site);
  dict3.set_primary_key_in_database(result3.primary_key_in_database());
  EXPECT_TRUE(result3.evicted_disk_cache_key_tokens().empty());
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key1, ElementsAreArray({dict1})),
                          Pair(isolation_key2,
                               UnorderedElementsAreArray({dict2, dict3}))));

  FastForwardBy(base::Seconds(1));

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
  // `max_count_per_site`. So the oldest dictionary `dict2` must be evicted.
  EXPECT_THAT(result4.evicted_disk_cache_key_tokens(),
              ElementsAreArray({dict2.disk_cache_key_token()}));
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key1, ElementsAreArray({dict1})),
                          Pair(isolation_key2, ElementsAreArray({dict3})),
                          Pair(isolation_key3, ElementsAreArray({dict4}))));
  EXPECT_EQ(dict1.size() + dict3.size() + dict4.size(),
            GetTotalDictionarySize());
}

TEST_F(SQLitePersistentSharedDictionaryStoreTest,
       RegisterDictionaryPerSiteEvictionWhenExceededBothSizeAndCountLimit) {
  CreateStore();

  uint64_t max_size_per_site = 800;
  uint64_t max_count_per_site = 2;

  auto isolation_key1 = CreateIsolationKey("https://origin1.test",
                                           "https://top-frame-site1.test");
  auto dict1 = SharedDictionaryInfo(
      GURL("https://a.example/dict"), /*last_fetch_time*/ base::Time::Now(),
      /*response_time=*/base::Time::Now(),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/100, SHA256HashValue({{0x00, 0x01}}),
      /*disk_cache_key_token=*/base::UnguessableToken::Create(),
      /*primary_key_in_database=*/std::nullopt);
  auto result1 = RegisterDictionaryImpl(store_.get(), isolation_key1, dict1,
                                        max_size_per_site, max_count_per_site);
  dict1.set_primary_key_in_database(result1.primary_key_in_database());
  EXPECT_TRUE(result1.evicted_disk_cache_key_tokens().empty());
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key1, ElementsAreArray({dict1}))));

  FastForwardBy(base::Seconds(1));

  auto isolation_key2 = CreateIsolationKey("https://origin1.test",
                                           "https://top-frame-site2.test");
  auto dict2 = SharedDictionaryInfo(
      GURL("https://b.example/dict"), /*last_fetch_time*/ base::Time::Now(),
      /*response_time=*/base::Time::Now(),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/200, SHA256HashValue({{0x00, 0x02}}),
      /*disk_cache_key_token=*/base::UnguessableToken::Create(),
      /*primary_key_in_database=*/std::nullopt);
  auto result2 = RegisterDictionaryImpl(store_.get(), isolation_key2, dict2,
                                        max_size_per_site, max_count_per_site);
  dict2.set_primary_key_in_database(result2.primary_key_in_database());
  EXPECT_TRUE(result2.evicted_disk_cache_key_tokens().empty());
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key1, ElementsAreArray({dict1})),
                          Pair(isolation_key2, ElementsAreArray({dict2}))));

  FastForwardBy(base::Seconds(1));

  auto dict3 = SharedDictionaryInfo(
      GURL("https://c.example/dict"), /*last_fetch_time*/ base::Time::Now(),
      /*response_time=*/base::Time::Now(),
      /*expiration*/ base::Seconds(100), "/pattern*", /*match_dest_string=*/"",
      /*id=*/"",
      /*last_used_time*/ base::Time::Now(),
      /*size=*/400, SHA256HashValue({{0x00, 0x03}}),
      /*disk_cache_key_token=*/base::UnguessableToken::Create(),
      /*primary_key_in_database=*/std::nullopt);
  auto result3 = RegisterDictionaryImpl(store_.get(), isolation_key2, dict3,
                                        max_size_per_site, max_count_per_site);
  dict3.set_primary_key_in_database(result3.primary_key_in_database());
  EXPECT_TRUE(result3.evicted_disk_cache_key_tokens().empty());
  EXPECT_THAT(GetAllDictionaries(),
              ElementsAre(Pair(isolation_key1, ElementsAreArray({dict1})),
                          Pair(isolation_key2,
                               UnorderedElementsAreArray({dict2, dict3}))));

  FastForwardBy(base::Seconds(1
"""


```