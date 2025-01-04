Response:
The user wants a summary of the provided C++ code file, specifically `net/extras/sqlite/sqlite_persistent_shared_dictionary_store_unittest.cc`. They are asking for:

1. **Functionality:** What does the code do?
2. **Relationship to JavaScript:** Does it interact with JavaScript, and how?
3. **Logical Reasoning (with examples):**  If there's logic, provide example inputs and outputs.
4. **Common Usage Errors:** What mistakes could a user or programmer make when using this code?
5. **User Path to Reach This Code (Debugging):** How would a user's actions lead to this code being executed?
6. **Overall Functionality (for Part 1):** A concise summary of the code's purpose.

**Thinking Process:**

1. **Identify the core purpose:** The filename and the `#include` statements clearly indicate this is a unit test file for `SQLitePersistentSharedDictionaryStore`. The primary goal is to test the functionality of this store.

2. **Analyze the test structure:**  Notice the `TEST_F` macros. These define individual test cases. Each test case likely focuses on a specific aspect of the `SQLitePersistentSharedDictionaryStore`'s functionality.

3. **Break down the functionality based on test cases:**  Skim through the test case names and the actions performed within them. Key operations seem to be:
    * Registering dictionaries.
    * Retrieving dictionaries (by isolation key and all).
    * Getting usage information.
    * Clearing dictionaries (all, by time, by isolation key).
    * Deleting expired dictionaries.
    * Eviction logic.
    * Getting and deleting by disk cache key tokens.
    * Updating the last fetch time.
    * Handling database corruption and file permissions.

4. **Consider JavaScript interaction:**  The code is C++ and directly interacts with an SQLite database. There's no explicit JavaScript code. However, shared dictionaries are a web platform feature. The *purpose* of this store is to persist data related to shared dictionaries, which *are* used by the browser when handling web requests triggered by JavaScript or other browser functionalities. The connection is indirect – this C++ code supports a feature accessible from JavaScript.

5. **Think about logical reasoning:** Many test cases involve setting up some data (registering dictionaries) and then verifying the outcome of an operation (e.g., getting dictionaries, clearing). This is where input/output examples can be derived.

6. **Identify potential usage errors:** Since this is a lower-level component, direct "user" errors are less likely. "Programmer" errors are more relevant, such as incorrect usage of the API, file permission issues, or database corruption.

7. **Trace the user path:** How does a shared dictionary even get stored?  A server sends a `Shared-Dictionary` header. The browser fetches the dictionary and then, presumably, the networking stack's components (including the `SQLitePersistentSharedDictionaryStore`) handle the persistence. This involves network requests, header parsing, and storage operations.

8. **Synthesize the information for Part 1:** Focus on the high-level purpose of the file.

**Pre-computation and Pre-analysis (Internal Trial and Error):**

* Initially, I might have focused too much on the SQL queries. However, the request is about the *functionality* of the test file, not the SQL details. The SQL is an *implementation detail* being tested.
* I considered whether the "user" in "user error" referred to the end-user of the browser or a developer. In this context, "programmer" or a developer working with the Chromium codebase is more appropriate.
*  I thought about how deeply to go into the specifics of each test case. For a summary in Part 1, a higher-level overview is sufficient. Details will be more relevant in later parts.
This C++ code file, `sqlite_persistent_shared_dictionary_store_unittest.cc`, is a unit test suite for the `SQLitePersistentSharedDictionaryStore` class in Chromium's network stack. Its primary function is to **thoroughly test the functionalities of the `SQLitePersistentSharedDictionaryStore`**, ensuring that it correctly interacts with an SQLite database to store and retrieve shared dictionary information.

Here's a breakdown of its functions:

* **Database Schema Management:** It defines and tests the creation and upgrading of the SQLite database schema used to store shared dictionary metadata. This includes creating tables (`dictionaries`) with appropriate columns and indexes for efficient querying. It tests schema versions 1 and 2 and the current version (3).
* **Registering Dictionaries:**  The tests verify the ability to register (insert) new shared dictionary entries into the database. This includes checking that metadata like origin, top-frame site, host, match pattern, URL, timestamps, size, and SHA256 hash are correctly stored. It also tests scenarios where registering a duplicate dictionary might occur, potentially leading to merging or replacement.
* **Retrieving Dictionaries:**  The tests validate the logic for retrieving dictionaries from the database based on different criteria:
    * **By Isolation Key:**  Fetching dictionaries associated with a specific frame origin and top-frame site.
    * **All Dictionaries:** Retrieving all stored shared dictionaries.
* **Getting Usage Information:** Tests the ability to retrieve aggregated usage information about the stored dictionaries, specifically the total size of dictionaries associated with each isolation key.
* **Clearing Dictionaries:** The tests cover different scenarios for removing dictionaries from the database:
    * **Clearing All Dictionaries:** Removing all stored entries.
    * **Clearing Dictionaries within a Time Range:** Deleting dictionaries based on their response time.
    * **Clearing Dictionaries for a Specific Isolation Key:** Removing dictionaries associated with a given origin and top-frame site.
* **Deleting Expired Dictionaries:**  Tests the functionality to remove dictionaries whose expiration time has passed.
* **Eviction Logic:**  The tests examine the process of evicting dictionaries to manage storage space, based on a maximum size and count per site. It checks that the eviction process correctly identifies and removes the least recently used dictionaries.
* **Disk Cache Key Token Management:**  The tests verify the ability to store and retrieve disk cache key tokens associated with dictionaries and to delete dictionaries based on these tokens. This is likely related to coordinating with the browser's disk cache.
* **Updating Dictionary Last Used Time:** Tests the ability to update the last used timestamp of a dictionary, crucial for eviction logic.
* **Error Handling and Database Integrity:** The tests include scenarios that simulate database corruption and file permission issues to ensure the store can gracefully handle these situations and potentially recover.

**Relationship to JavaScript:**

While this C++ code doesn't directly execute JavaScript, it plays a crucial role in supporting the Shared Dictionary API, which *is* accessible and used by JavaScript on web pages.

**Example:**

1. **JavaScript initiates a request:** A JavaScript on a website `https://example.com` might trigger a network request for a resource.
2. **Server responds with a `Shared-Dictionary` header:** The server responding to the request includes a `Shared-Dictionary` header, indicating the availability of a compression dictionary at a specific URL (e.g., `https://dict.example.com/my_dict`).
3. **Browser fetches the dictionary:** Chromium's network stack fetches the dictionary.
4. **`SQLitePersistentSharedDictionaryStore` is involved:** The `SQLitePersistentSharedDictionaryStore` would be used to store metadata about this fetched dictionary (URL, match pattern, expiration time, etc.) in the local SQLite database. This allows the browser to reuse this dictionary for future requests matching the specified criteria, improving loading performance.

**Logical Reasoning Examples:**

**Assumption:** The store has a maximum size limit per top-frame site.

**Hypothetical Input:**

* **Existing Dictionaries for `https://a.example`:**
    * Dictionary 1: Size = 600 KB
    * Dictionary 2: Size = 500 KB
* **New Dictionary to Register for `https://a.example`:** Size = 200 KB
* **Maximum Size per Site:** 1000 KB

**Output:** The new dictionary might be registered, but potentially after evicting older dictionaries. If the eviction policy prioritizes removing the least recently used, and Dictionary 1 was used less recently, Dictionary 1 might be removed to make space for the new 200 KB dictionary, keeping the total size under 1000 KB.

**Hypothetical Input (Clear Dictionaries by Time):**

* **Dictionaries with the following response times:**
    * Dictionary A: 2024-07-26 10:00:00
    * Dictionary B: 2024-07-26 10:15:00
    * Dictionary C: 2024-07-26 10:30:00
* **Clear Dictionaries with Start Time:** 2024-07-26 10:10:00
* **Clear Dictionaries with End Time:** 2024-07-26 10:20:00

**Output:** Dictionary B would be deleted, as its response time falls within the specified range. Dictionary A and C would remain.

**Common Usage Errors (from a programmer's perspective integrating with this store):**

* **Incorrectly constructing `SharedDictionaryIsolationKey`:** Providing the wrong frame origin or top-frame site when registering or retrieving dictionaries would lead to incorrect storage or retrieval.
    * **Example:** Registering a dictionary intending it for `https://site1.com` but accidentally using the origin of an iframe within that page, leading to it not being found when the main page tries to use it.
* **Not handling asynchronous operations correctly:** The store likely performs database operations on a background thread. Failing to use callbacks or handle the asynchronous nature of the API could lead to race conditions or incorrect data access.
    * **Example:** Trying to access dictionary data immediately after registering it without waiting for the registration callback to complete.
* **Ignoring error results:** The store's methods return results indicating success or failure. Ignoring these error conditions could lead to unexpected behavior and data inconsistency.
    * **Example:**  A registration fails due to a database error, but the calling code proceeds as if the registration was successful.
* **Manually manipulating the database:** Directly modifying the underlying SQLite database file outside of the `SQLitePersistentSharedDictionaryStore`'s API could corrupt the data and lead to unpredictable behavior.

**User Operations Leading Here (as debugging clues):**

1. **User visits a website:** The user navigates to a website that utilizes shared dictionaries for compression.
2. **Browser receives a `Shared-Dictionary` header:** The web server sends a response with a `Shared-Dictionary` header, indicating the availability of a compression dictionary.
3. **Chromium fetches and stores the dictionary metadata:**  The network stack in Chromium fetches the dictionary. The `SQLitePersistentSharedDictionaryStore` is then used to store the metadata of this dictionary in the local SQLite database. This involves:
    * Parsing the `Shared-Dictionary` header.
    * Creating a `SharedDictionaryInfo` object.
    * Calling the `RegisterDictionary` method of `SQLitePersistentSharedDictionaryStore`.
4. **Subsequent requests might use the dictionary:** When the user makes subsequent requests to the same site or other sites that can use the same dictionary (based on the match pattern and isolation key), the browser will consult the `SQLitePersistentSharedDictionaryStore` to check for available dictionaries.
    * The `GetDictionaries` method might be called to find a suitable dictionary.
5. **Browser data clearing:** If the user clears their browsing data (cookies, cache, etc.), the `ClearAllDictionaries` or `ClearDictionaries` methods might be called to remove the stored dictionary metadata.
6. **Automatic eviction:** If the storage for shared dictionaries exceeds its limits, the `ProcessEviction` method will be invoked to remove less recently used dictionaries.
7. **Dictionary expiration:**  When a dictionary's expiration time is reached, the `DeleteExpiredDictionaries` method will be called.

**Functionality Summary (Part 1):**

This part of the unit test file (`sqlite_persistent_shared_dictionary_store_unittest.cc`) primarily focuses on testing the fundamental operations of the `SQLitePersistentSharedDictionaryStore` related to **database schema management, registering new dictionaries, and retrieving dictionaries based on isolation keys.** It sets up the basic framework for verifying the store's ability to correctly persist and retrieve shared dictionary metadata in an SQLite database.

Prompt: 
```
这是目录为net/extras/sqlite/sqlite_persistent_shared_dictionary_store_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/extras/sqlite/sqlite_persistent_shared_dictionary_store.h"

#include <optional>
#include <tuple>

#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/logging.h"
#include "base/memory/scoped_refptr.h"
#include "base/numerics/safe_conversions.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/test/bind.h"
#include "base/test/test_file_util.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/base/schemeful_site.h"
#include "net/extras/shared_dictionary/shared_dictionary_info.h"
#include "net/shared_dictionary/shared_dictionary_isolation_key.h"
#include "net/test/test_with_task_environment.h"
#include "sql/database.h"
#include "sql/meta_table.h"
#include "sql/statement.h"
#include "sql/test/test_helpers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::ElementsAre;
using ::testing::ElementsAreArray;
using ::testing::Pair;
using ::testing::UnorderedElementsAreArray;

namespace net {

namespace {

const base::FilePath::CharType kSharedDictionaryStoreFilename[] =
    FILE_PATH_LITERAL("SharedDictionary");

const int kCurrentVersionNumber = 3;

int GetDBCurrentVersionNumber(sql::Database* db) {
  static constexpr char kGetDBCurrentVersionQuery[] =
      "SELECT value FROM meta WHERE key='version'";
  sql::Statement statement(db->GetUniqueStatement(kGetDBCurrentVersionQuery));
  statement.Step();
  return statement.ColumnInt(0);
}

bool CreateV1Schema(sql::Database* db) {
  sql::MetaTable meta_table;
  CHECK(meta_table.Init(db, 1, 1));
  constexpr char kTotalDictSizeKey[] = "total_dict_size";
  static constexpr char kCreateTableQuery[] =
      // clang-format off
      "CREATE TABLE dictionaries("
          "id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
          "frame_origin TEXT NOT NULL,"
          "top_frame_site TEXT NOT NULL,"
          "host TEXT NOT NULL,"
          "match TEXT NOT NULL,"
          "url TEXT NOT NULL,"
          "res_time INTEGER NOT NULL,"
          "exp_time INTEGER NOT NULL,"
          "last_used_time INTEGER NOT NULL,"
          "size INTEGER NOT NULL,"
          "sha256 BLOB NOT NULL,"
          "token_high INTEGER NOT NULL,"
          "token_low INTEGER NOT NULL)";
  // clang-format on

  static constexpr char kCreateUniqueIndexQuery[] =
      // clang-format off
      "CREATE UNIQUE INDEX unique_index ON dictionaries("
          "frame_origin,"
          "top_frame_site,"
          "host,"
          "match)";
  // clang-format on

  // This index is used for the size and count limitation per top_frame_site.
  static constexpr char kCreateTopFrameSiteIndexQuery[] =
      // clang-format off
      "CREATE INDEX top_frame_site_index ON dictionaries("
          "top_frame_site)";
  // clang-format on

  // This index is used for GetDictionaries().
  static constexpr char kCreateIsolationIndexQuery[] =
      // clang-format off
      "CREATE INDEX isolation_index ON dictionaries("
          "frame_origin,"
          "top_frame_site)";
  // clang-format on

  // This index will be used when implementing garbage collection logic of
  // SharedDictionaryDiskCache.
  static constexpr char kCreateTokenIndexQuery[] =
      // clang-format off
      "CREATE INDEX token_index ON dictionaries("
          "token_high, token_low)";
  // clang-format on

  // This index will be used when implementing clearing expired dictionary
  // logic.
  static constexpr char kCreateExpirationTimeIndexQuery[] =
      // clang-format off
      "CREATE INDEX exp_time_index ON dictionaries("
          "exp_time)";
  // clang-format on

  // This index will be used when implementing clearing dictionary logic which
  // will be called from BrowsingDataRemover.
  static constexpr char kCreateLastUsedTimeIndexQuery[] =
      // clang-format off
      "CREATE INDEX last_used_time_index ON dictionaries("
          "last_used_time)";
  // clang-format on

  if (!db->Execute(kCreateTableQuery) ||
      !db->Execute(kCreateUniqueIndexQuery) ||
      !db->Execute(kCreateTopFrameSiteIndexQuery) ||
      !db->Execute(kCreateIsolationIndexQuery) ||
      !db->Execute(kCreateTokenIndexQuery) ||
      !db->Execute(kCreateExpirationTimeIndexQuery) ||
      !db->Execute(kCreateLastUsedTimeIndexQuery) ||
      !meta_table.SetValue(kTotalDictSizeKey, 0)) {
    return false;
  }
  return true;
}

bool CreateV2Schema(sql::Database* db) {
  sql::MetaTable meta_table;
  CHECK(meta_table.Init(db, 2, 2));
  constexpr char kTotalDictSizeKey[] = "total_dict_size";
  static constexpr char kCreateTableQuery[] =
      // clang-format off
      "CREATE TABLE dictionaries("
          "primary_key INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
          "frame_origin TEXT NOT NULL,"
          "top_frame_site TEXT NOT NULL,"
          "host TEXT NOT NULL,"
          "match TEXT NOT NULL,"
          "match_dest TEXT NOT NULL,"
          "id TEXT NOT NULL,"
          "url TEXT NOT NULL,"
          "res_time INTEGER NOT NULL,"
          "exp_time INTEGER NOT NULL,"
          "last_used_time INTEGER NOT NULL,"
          "size INTEGER NOT NULL,"
          "sha256 BLOB NOT NULL,"
          "token_high INTEGER NOT NULL,"
          "token_low INTEGER NOT NULL)";
  // clang-format on

  static constexpr char kCreateUniqueIndexQuery[] =
      // clang-format off
      "CREATE UNIQUE INDEX unique_index ON dictionaries("
          "frame_origin,"
          "top_frame_site,"
          "host,"
          "match,"
          "match_dest)";
  // clang-format on

  // This index is used for the size and count limitation per top_frame_site.
  static constexpr char kCreateTopFrameSiteIndexQuery[] =
      // clang-format off
      "CREATE INDEX top_frame_site_index ON dictionaries("
          "top_frame_site)";
  // clang-format on

  // This index is used for GetDictionaries().
  static constexpr char kCreateIsolationIndexQuery[] =
      // clang-format off
      "CREATE INDEX isolation_index ON dictionaries("
          "frame_origin,"
          "top_frame_site)";
  // clang-format on

  // This index will be used when implementing garbage collection logic of
  // SharedDictionaryDiskCache.
  static constexpr char kCreateTokenIndexQuery[] =
      // clang-format off
      "CREATE INDEX token_index ON dictionaries("
          "token_high, token_low)";
  // clang-format on

  // This index will be used when implementing clearing expired dictionary
  // logic.
  static constexpr char kCreateExpirationTimeIndexQuery[] =
      // clang-format off
      "CREATE INDEX exp_time_index ON dictionaries("
          "exp_time)";
  // clang-format on

  // This index will be used when implementing clearing dictionary logic which
  // will be called from BrowsingDataRemover.
  static constexpr char kCreateLastUsedTimeIndexQuery[] =
      // clang-format off
      "CREATE INDEX last_used_time_index ON dictionaries("
          "last_used_time)";
  // clang-format on

  if (!db->Execute(kCreateTableQuery) ||
      !db->Execute(kCreateUniqueIndexQuery) ||
      !db->Execute(kCreateTopFrameSiteIndexQuery) ||
      !db->Execute(kCreateIsolationIndexQuery) ||
      !db->Execute(kCreateTokenIndexQuery) ||
      !db->Execute(kCreateExpirationTimeIndexQuery) ||
      !db->Execute(kCreateLastUsedTimeIndexQuery) ||
      !meta_table.SetValue(kTotalDictSizeKey, 0)) {
    return false;
  }
  return true;
}

SQLitePersistentSharedDictionaryStore::RegisterDictionaryResult
RegisterDictionaryImpl(SQLitePersistentSharedDictionaryStore* store,
                       const SharedDictionaryIsolationKey& isolation_key,
                       SharedDictionaryInfo dictionary_info,
                       uint64_t max_size_per_site = 1000000,
                       uint64_t max_count_per_site = 1000) {
  std::optional<SQLitePersistentSharedDictionaryStore::RegisterDictionaryResult>
      result_out;
  base::RunLoop run_loop;
  store->RegisterDictionary(
      isolation_key, std::move(dictionary_info), max_size_per_site,
      max_count_per_site,
      base::BindLambdaForTesting(
          [&](SQLitePersistentSharedDictionaryStore::
                  RegisterDictionaryResultOrError result) {
            ASSERT_TRUE(result.has_value());
            result_out = result.value();
            run_loop.Quit();
          }));
  run_loop.Run();
  CHECK(result_out);
  return *result_out;
}

// Register following 4 dictionaries for ProcessEviction tests.
//   dict1: size=1000 last_used_time=now
//   dict2: size=3000 last_used_time=now+4
//   dict3: size=5000 last_used_time=now+2
//   dict4: size=7000 last_used_time=now+3
std::tuple<SharedDictionaryInfo,
           SharedDictionaryInfo,
           SharedDictionaryInfo,
           SharedDictionaryInfo>
RegisterSharedDictionariesForProcessEvictionTest(
    SQLitePersistentSharedDictionaryStore* store,
    const SharedDictionaryIsolationKey& isolation_key) {
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
  auto result1 = RegisterDictionaryImpl(store, isolation_key, dict1);
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
  auto result2 = RegisterDictionaryImpl(store, isolation_key, dict2);
  dict2.set_primary_key_in_database(result2.primary_key_in_database());

  auto token3 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict3 =
      SharedDictionaryInfo(GURL("https://c.example/dict"),
                           /*last_fetch_time=*/now, /*response_time=*/now,
                           /*expiration*/ base::Seconds(100), "/pattern*",
                           /*match_dest_string=*/"", /*id=*/"",
                           /*last_used_time*/ now + base::Seconds(2),
                           /*size=*/5000, SHA256HashValue({{0x00, 0x03}}),
                           /*disk_cache_key_token=*/token3,
                           /*primary_key_in_database=*/std::nullopt);
  auto result3 = RegisterDictionaryImpl(store, isolation_key, dict3);
  dict3.set_primary_key_in_database(result3.primary_key_in_database());

  auto token4 = base::UnguessableToken::Create();
  SharedDictionaryInfo dict4 =
      SharedDictionaryInfo(GURL("https://d.example/dict"),
                           /*last_fetch_time=*/now, /*response_time=*/now,
                           /*expiration*/ base::Seconds(100), "/pattern*",
                           /*match_dest_string=*/"", /*id=*/"",
                           /*last_used_time*/ now + base::Seconds(3),
                           /*size=*/7000, SHA256HashValue({{0x00, 0x04}}),
                           /*disk_cache_key_token=*/token4,
                           /*primary_key_in_database=*/std::nullopt);
  auto result4 = RegisterDictionaryImpl(store, isolation_key, dict4);
  dict4.set_primary_key_in_database(result4.primary_key_in_database());

  // Call UpdateDictionaryLastUsedTime to update the last used time of dict2.
  store->UpdateDictionaryLastUsedTime(*dict2.primary_key_in_database(),
                                      now + base::Seconds(4));

  SharedDictionaryInfo updated_dict2 = SharedDictionaryInfo(
      dict2.url(), dict2.last_fetch_time(), dict2.response_time(),
      dict2.expiration(), dict2.match(), dict2.match_dest_string(), dict2.id(),
      now + base::Seconds(4), dict2.size(), dict2.hash(),
      dict2.disk_cache_key_token(), dict2.primary_key_in_database());

  return {dict1, updated_dict2, dict3, dict4};
}

}  // namespace

SharedDictionaryIsolationKey CreateIsolationKey(
    const std::string& frame_origin_str,
    const std::optional<std::string>& top_frame_site_str = std::nullopt) {
  return SharedDictionaryIsolationKey(
      url::Origin::Create(GURL(frame_origin_str)),
      top_frame_site_str ? SchemefulSite(GURL(*top_frame_site_str))
                         : SchemefulSite(GURL(frame_origin_str)));
}

class SQLitePersistentSharedDictionaryStoreTest : public ::testing::Test,
                                                  public WithTaskEnvironment {
 public:
  SQLitePersistentSharedDictionaryStoreTest()
      : WithTaskEnvironment(base::test::TaskEnvironment::TimeSource::MOCK_TIME),
        isolation_key_(CreateIsolationKey("https://origin.test/")),
        dictionary_info_(
            GURL("https://origin.test/dict"),
            /*last_fetch_time=*/base::Time::Now() - base::Seconds(9),
            /*response_time=*/base::Time::Now() - base::Seconds(10),
            /*expiration*/ base::Seconds(100),
            "/pattern*",
            /*match_dest_string=*/"",
            /*id=*/"dictionary_id",
            /*last_used_time*/ base::Time::Now(),
            /*size=*/1000,
            SHA256HashValue({{0x00, 0x01}}),
            /*disk_cache_key_token=*/base::UnguessableToken::Create(),
            /*primary_key_in_database=*/std::nullopt) {}

  SQLitePersistentSharedDictionaryStoreTest(
      const SQLitePersistentSharedDictionaryStoreTest&) = delete;
  SQLitePersistentSharedDictionaryStoreTest& operator=(
      const SQLitePersistentSharedDictionaryStoreTest&) = delete;

  void SetUp() override { ASSERT_TRUE(temp_dir_.CreateUniqueTempDir()); }

  void TearDown() override { DestroyStore(); }

 protected:
  base::FilePath GetStroeFilePath() const {
    return temp_dir_.GetPath().Append(kSharedDictionaryStoreFilename);
  }

  void CreateStore() {
    CHECK(!store_);
    store_ = std::make_unique<SQLitePersistentSharedDictionaryStore>(
        GetStroeFilePath(), client_task_runner_, background_task_runner_);
  }

  void DestroyStore() {
    store_.reset();
    // Make sure we wait until the destructor has run by running all
    // TaskEnvironment tasks.
    RunUntilIdle();
  }

  uint64_t GetTotalDictionarySize() {
    base::RunLoop run_loop;
    uint64_t total_dictionary_size_out = 0;
    store_->GetTotalDictionarySize(base::BindLambdaForTesting(
        [&](base::expected<
            uint64_t, SQLitePersistentSharedDictionaryStore::Error> result) {
          ASSERT_TRUE(result.has_value());
          total_dictionary_size_out = result.value();
          run_loop.Quit();
        }));
    run_loop.Run();
    return total_dictionary_size_out;
  }

  SQLitePersistentSharedDictionaryStore::RegisterDictionaryResult
  RegisterDictionary(const SharedDictionaryIsolationKey& isolation_key,
                     SharedDictionaryInfo dictionary_info) {
    return RegisterDictionaryImpl(store_.get(), isolation_key,
                                  std::move(dictionary_info));
  }

  std::vector<SharedDictionaryInfo> GetDictionaries(
      const SharedDictionaryIsolationKey& isolation_key) {
    std::vector<SharedDictionaryInfo> result_dictionaries;
    base::RunLoop run_loop;
    store_->GetDictionaries(
        isolation_key,
        base::BindLambdaForTesting(
            [&](SQLitePersistentSharedDictionaryStore::DictionaryListOrError
                    result) {
              ASSERT_TRUE(result.has_value());
              result_dictionaries = std::move(result.value());
              run_loop.Quit();
            }));
    run_loop.Run();
    return result_dictionaries;
  }

  std::map<SharedDictionaryIsolationKey, std::vector<SharedDictionaryInfo>>
  GetAllDictionaries() {
    std::map<SharedDictionaryIsolationKey, std::vector<SharedDictionaryInfo>>
        result_all_dictionaries;
    base::RunLoop run_loop;
    store_->GetAllDictionaries(base::BindLambdaForTesting(
        [&](SQLitePersistentSharedDictionaryStore::DictionaryMapOrError
                result) {
          ASSERT_TRUE(result.has_value());
          result_all_dictionaries = std::move(result.value());
          run_loop.Quit();
        }));
    run_loop.Run();
    return result_all_dictionaries;
  }

  std::vector<SharedDictionaryUsageInfo> GetUsageInfo() {
    std::vector<SharedDictionaryUsageInfo> result_usage_info;
    base::RunLoop run_loop;
    store_->GetUsageInfo(base::BindLambdaForTesting(
        [&](SQLitePersistentSharedDictionaryStore::UsageInfoOrError result) {
          ASSERT_TRUE(result.has_value());
          result_usage_info = std::move(result.value());
          run_loop.Quit();
        }));
    run_loop.Run();
    return result_usage_info;
  }

  std::vector<url::Origin> GetOriginsBetween(const base::Time start_time,
                                             const base::Time end_time) {
    std::vector<url::Origin> origins;
    base::RunLoop run_loop;
    store_->GetOriginsBetween(
        start_time, end_time,
        base::BindLambdaForTesting(
            [&](SQLitePersistentSharedDictionaryStore::OriginListOrError
                    result) {
              ASSERT_TRUE(result.has_value());
              origins = std::move(result.value());
              run_loop.Quit();
            }));
    run_loop.Run();
    return origins;
  }

  std::set<base::UnguessableToken> ClearAllDictionaries() {
    base::RunLoop run_loop;
    std::set<base::UnguessableToken> tokens;
    store_->ClearAllDictionaries(base::BindLambdaForTesting(
        [&](SQLitePersistentSharedDictionaryStore::UnguessableTokenSetOrError
                result) {
          ASSERT_TRUE(result.has_value());
          tokens = std::move(result.value());
          run_loop.Quit();
        }));
    run_loop.Run();
    return tokens;
  }

  std::set<base::UnguessableToken> ClearDictionaries(
      const base::Time start_time,
      const base::Time end_time,
      base::RepeatingCallback<bool(const GURL&)> url_matcher) {
    base::RunLoop run_loop;
    std::set<base::UnguessableToken> tokens;
    store_->ClearDictionaries(
        start_time, end_time, std::move(url_matcher),
        base::BindLambdaForTesting([&](SQLitePersistentSharedDictionaryStore::
                                           UnguessableTokenSetOrError result) {
          ASSERT_TRUE(result.has_value());
          tokens = std::move(result.value());
          run_loop.Quit();
        }));
    run_loop.Run();
    return tokens;
  }

  std::set<base::UnguessableToken> ClearDictionariesForIsolationKey(
      const SharedDictionaryIsolationKey& isolation_key) {
    base::RunLoop run_loop;
    std::set<base::UnguessableToken> tokens;
    store_->ClearDictionariesForIsolationKey(
        isolation_key,
        base::BindLambdaForTesting([&](SQLitePersistentSharedDictionaryStore::
                                           UnguessableTokenSetOrError result) {
          ASSERT_TRUE(result.has_value());
          tokens = std::move(result.value());
          run_loop.Quit();
        }));
    run_loop.Run();
    return tokens;
  }

  std::set<base::UnguessableToken> DeleteExpiredDictionaries(
      const base::Time now) {
    base::RunLoop run_loop;
    std::set<base::UnguessableToken> tokens;
    store_->DeleteExpiredDictionaries(
        now,
        base::BindLambdaForTesting([&](SQLitePersistentSharedDictionaryStore::
                                           UnguessableTokenSetOrError result) {
          ASSERT_TRUE(result.has_value());
          tokens = std::move(result.value());
          run_loop.Quit();
        }));
    run_loop.Run();
    return tokens;
  }

  std::set<base::UnguessableToken> ProcessEviction(
      uint64_t cache_max_size,
      uint64_t size_low_watermark,
      uint64_t cache_max_count,
      uint64_t count_low_watermark) {
    base::RunLoop run_loop;
    std::set<base::UnguessableToken> tokens;
    store_->ProcessEviction(
        cache_max_size, size_low_watermark, cache_max_count,
        count_low_watermark,
        base::BindLambdaForTesting([&](SQLitePersistentSharedDictionaryStore::
                                           UnguessableTokenSetOrError result) {
          ASSERT_TRUE(result.has_value());
          tokens = std::move(result.value());
          run_loop.Quit();
        }));
    run_loop.Run();
    return tokens;
  }

  std::set<base::UnguessableToken> GetAllDiskCacheKeyTokens() {
    base::RunLoop run_loop;
    std::set<base::UnguessableToken> tokens;
    store_->GetAllDiskCacheKeyTokens(base::BindLambdaForTesting(
        [&](SQLitePersistentSharedDictionaryStore::UnguessableTokenSetOrError
                result) {
          ASSERT_TRUE(result.has_value());
          tokens = std::move(result.value());
          run_loop.Quit();
        }));
    run_loop.Run();
    return tokens;
  }

  SQLitePersistentSharedDictionaryStore::Error
  DeleteDictionariesByDiskCacheKeyTokens(
      std::set<base::UnguessableToken> disk_cache_key_tokens) {
    base::RunLoop run_loop;
    SQLitePersistentSharedDictionaryStore::Error error_out;
    store_->DeleteDictionariesByDiskCacheKeyTokens(
        std::move(disk_cache_key_tokens),
        base::BindLambdaForTesting(
            [&](SQLitePersistentSharedDictionaryStore::Error result_error) {
              error_out = result_error;
              run_loop.Quit();
            }));
    run_loop.Run();
    return error_out;
  }

  SQLitePersistentSharedDictionaryStore::Error UpdateDictionaryLastFetchTime(
      const int64_t primary_key_in_database,
      const base::Time last_fetch_time) {
    base::RunLoop run_loop;
    SQLitePersistentSharedDictionaryStore::Error error_out;
    store_->UpdateDictionaryLastFetchTime(
        primary_key_in_database, last_fetch_time,
        base::BindLambdaForTesting(
            [&](SQLitePersistentSharedDictionaryStore::Error result_error) {
              error_out = result_error;
              run_loop.Quit();
            }));
    run_loop.Run();
    return error_out;
  }

  void CorruptDatabaseFile() {
    // Execute CreateStore(), ClearAllDictionaries() and DestroyStore() to
    // create a database file.
    CreateStore();
    ClearAllDictionaries();
    DestroyStore();

    // Corrupt the database.
    CHECK(sql::test::CorruptSizeInHeader(GetStroeFilePath()));
  }

  void ManipulateDatabase(const std::vector<std::string>& queries) {
    // We don't allow manipulating the database while `store_` exists.
    ASSERT_FALSE(store_);

    std::unique_ptr<sql::Database> db =
        std::make_unique<sql::Database>(sql::DatabaseOptions{});
    ASSERT_TRUE(db->Open(GetStroeFilePath()));

    sql::MetaTable meta_table;
    ASSERT_TRUE(meta_table.Init(db.get(), kCurrentVersionNumber,
                                kCurrentVersionNumber));
    for (const std::string& query : queries) {
      ASSERT_TRUE(db->Execute(query));
    }
    db->Close();
  }

  void MakeFileUnwritable() {
    file_permissions_restorer_ =
        std::make_unique<base::FilePermissionRestorer>(GetStroeFilePath());
    ASSERT_TRUE(base::MakeFileUnwritable(GetStroeFilePath()));
  }

  void CheckStoreRecovered() {
    CreateStore();
    EXPECT_TRUE(GetDictionaries(isolation_key_).empty());
    EXPECT_TRUE(GetAllDictionaries().empty());
    DestroyStore();
  }

  void RunMultipleDictionariesTest(
      const SharedDictionaryIsolationKey isolation_key1,
      const SharedDictionaryInfo dictionary_info1,
      const SharedDictionaryIsolationKey isolation_key2,
      const SharedDictionaryInfo dictionary_info2,
      bool expect_merged);

  void RunGetTotalDictionarySizeFailureTest(
      SQLitePersistentSharedDictionaryStore::Error expected_error);
  void RunRegisterDictionaryFailureTest(
      SQLitePersistentSharedDictionaryStore::Error expected_error);
  void RunGetDictionariesFailureTest(
      SQLitePersistentSharedDictionaryStore::Error expected_error);
  void RunGetAllDictionariesFailureTest(
      SQLitePersistentSharedDictionaryStore::Error expected_error);
  void RunGetUsageInfoFailureTest(
      SQLitePersistentSharedDictionaryStore::Error expected_error);
  void RunGetOriginsBetweenFailureTest(
      SQLitePersistentSharedDictionaryStore::Error expected_error);
  void RunClearAllDictionariesFailureTest(
      SQLitePersistentSharedDictionaryStore::Error expected_error);
  void RunClearDictionariesFailureTest(
      base::RepeatingCallback<bool(const GURL&)> url_matcher,
      SQLitePersistentSharedDictionaryStore::Error expected_error);
  void RunClearDictionariesForIsolationKeyFailureTest(
      SQLitePersistentSharedDictionaryStore::Error expected_error);
  void RunDeleteExpiredDictionariesFailureTest(
      SQLitePersistentSharedDictionaryStore::Error expected_error);
  void RunProcessEvictionFailureTest(
      SQLitePersistentSharedDictionaryStore::Error expected_error);
  void RunGetAllDiskCacheKeyTokensFailureTest(
      SQLitePersistentSharedDictionaryStore::Error expected_error);

  base::ScopedTempDir temp_dir_;
  std::unique_ptr<SQLitePersistentSharedDictionaryStore> store_;
  const scoped_refptr<base::SequencedTaskRunner> client_task_runner_ =
      base::SingleThreadTaskRunner::GetCurrentDefault();
  const scoped_refptr<base::SequencedTaskRunner> background_task_runner_ =
      base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock()});
  // `file_permissions_restorer_` must be below `temp_dir_` to restore the
  // file permission correctly.
  std::unique_ptr<base::FilePermissionRestorer> file_permissions_restorer_;

  const SharedDictionaryIsolationKey isolation_key_;
  const SharedDictionaryInfo dictionary_info_;
};

TEST_F(SQLitePersistentSharedDictionaryStoreTest, SingleDictionary) {
  CreateStore();

  EXPECT_EQ(0u, GetTotalDictionarySize());

  auto register_dictionary_result =
      RegisterDictionary(isolation_key_, dictionary_info_);
  EXPECT_EQ(dictionary_info_.size(),
            register_dictionary_result.total_dictionary_size());
  EXPECT_EQ(1u, register_dictionary_result.total_dictionary_count());

  SharedDictionaryInfo expected_info = dictionary_info_;
  expected_info.set_primary_key_in_database(
      register_dictionary_result.primary_key_in_database());

  EXPECT_EQ(dictionary_info_.size(), GetTotalDictionarySize());
  EXPECT_THAT(GetDictionaries(isolation_key_),
              ElementsAreArray({expected_info}));
  EXPECT_THAT(
      GetAllDictionaries(),
      ElementsAre(Pair(isolation_key_, ElementsAreArray({expected_info}))));
  EXPECT_THAT(GetUsageInfo(),
              ElementsAre(SharedDictionaryUsageInfo{
                  .isolation_key = isolation_key_,
                  .total_size_bytes = dictionary_info_.size()}));
  EXPECT_TRUE(
      GetOriginsBetween(dictionary_info_.response_time() - base::Seconds(1),
                        dictionary_info_.response_time())
          .empty());
  EXPECT_THAT(
      GetOriginsBetween(dictionary_info_.response_time(),
                        dictionary_info_.response_time() + base::Seconds(1)),
      ElementsAreArray({isolation_key_.frame_origin()}));

  EXPECT_THAT(
      ClearAllDictionaries(),
      UnorderedElementsAreArray({dictionary_info_.disk_cache_key_token()}));

  EXPECT_EQ(0u, GetTotalDictionarySize());
  EXPECT_TRUE(GetDictionaries(isolation_key_).empty());
  EXPECT_TRUE(GetAllDictionaries().empty());
  EXPECT_TRUE(GetUsageInfo().empty());
}

void SQLitePersistentSharedDictionaryStoreTest::RunMultipleDictionariesTest(
    const SharedDictionaryIsolationKey isolation_key1,
    const SharedDictionaryInfo dictionary_info1,
    const SharedDictionaryIsolationKey isolation_key2,
    const SharedDictionaryInfo dictionary_info2,
    bool expect_merged) {
  CreateStore();

  auto register_dictionary_result1 =
      RegisterDictionary(isolation_key1, dictionary_info1);
  EXPECT_EQ(dictionary_info1.size(),
            register_dictionary_result1.total_dictionary_size());
  EXPECT_EQ(1u, register_dictionary_result1.total_dictionary_count());
  auto register_dictionary_result2 =
      RegisterDictionary(isolation_key2, dictionary_info2);
  EXPECT_EQ(expect_merged ? 1u : 2u,
            register_dictionary_result2.total_dictionary_count());

  EXPECT_NE(register_dictionary_result1.primary_key_in_database(),
            register_dictionary_result2.primary_key_in_database());

  SharedDictionaryInfo expected_info1 = dictionary_info1;
  SharedDictionaryInfo expected_info2 = dictionary_info2;
  expected_info1.set_primary_key_in_database(
      register_dictionary_result1.primary_key_in_database());
  expected_info2.set_primary_key_in_database(
      register_dictionary_result2.primary_key_in_database());
  base::Time oldest_response_time = std::min(dictionary_info1.response_time(),
                                             dictionary_info2.response_time());
  base::Time latest_response_time = std::max(dictionary_info1.response_time(),
                                             dictionary_info2.response_time());

  std::set<base::UnguessableToken> registered_tokens;

  if (isolation_key1 == isolation_key2) {
    if (expect_merged) {
      registered_tokens.insert(expected_info2.disk_cache_key_token());
      EXPECT_EQ(dictionary_info2.size(),
                register_dictionary_result2.total_dictionary_size());
      EXPECT_THAT(GetDictionaries(isolation_key1),
                  ElementsAreArray({expected_info2}));
      EXPECT_THAT(GetAllDictionaries(),
                  ElementsAre(Pair(isolation_key1,
                                   ElementsAreArray({expected_info2}))));
      ASSERT_TRUE(register_dictionary_result2.replaced_disk_cache_key_token());
      EXPECT_EQ(dictionary_info1.disk_cache_key_token(),
                *register_dictionary_result2.replaced_disk_cache_key_token());
      EXPECT_THAT(GetUsageInfo(),
                  ElementsAre(SharedDictionaryUsageInfo{
                      .isolation_key = isolation_key1,
                      .total_size_bytes = dictionary_info2.size()}));
      EXPECT_THAT(GetOriginsBetween(oldest_response_time,
                                    latest_response_time + base::Seconds(1)),
                  ElementsAreArray({isolation_key2.frame_origin()}));
    } else {
      registered_tokens.insert(expected_info1.disk_cache_key_token());
      registered_tokens.insert(expected_info2.disk_cache_key_token());

      EXPECT_EQ(dictionary_info1.size() + dictionary_info2.size(),
                register_dictionary_result2.total_dictionary_size());
      EXPECT_THAT(GetDictionaries(isolation_key1),
                  UnorderedElementsAreArray({expected_info1, expected_info2}));
      EXPECT_THAT(GetAllDictionaries(),
                  ElementsAre(Pair(isolation_key1,
                                   UnorderedElementsAreArray(
                                       {expected_info1, expected_info2}))));
      EXPECT_THAT(GetUsageInfo(),
                  ElementsAre(SharedDictionaryUsageInfo{
                      .isolation_key = isolation_key1,
                      .total_size_bytes =
                          dictionary_info1.size() + dictionary_info2.size()}));
      EXPECT_THAT(GetOriginsBetween(oldest_response_time,
                                    latest_response_time + base::Seconds(1)),
                  UnorderedElementsAreArray({isolation_key1.frame_origin()}));
    }
  } else {
    registered_tokens.insert(expected_info1.disk_cache_key_token());
    registered_tokens.insert(expected_info2.disk_cache_key_token());
    EXPECT_EQ(dictionary_info1.size() + dictionary_info2.size(),
              register_dictionary_result2.total_dictionary_size());
    EXPECT_THAT(GetDictionaries(isolation_key1),
                ElementsAreArray({expected_info1}));
    EXPECT_THAT(GetDictionaries(isolation_key2),
                ElementsAreArray({expected_info2}));
    EXPECT_THAT(
        GetAllDictionaries(),
        ElementsAre(Pair(isolation_key1, ElementsAreArray({expected_info1})),
                    Pair(isolation_key2, ElementsAreArray({expected_info2})
"""


```