Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack. This snippet belongs to the `SQLitePersistentSharedDictionaryStore::Backend` class and deals with fetching shared dictionaries from a SQLite database.

Here's a breakdown of the thought process to answer the request:

1. **Identify the Core Function:** The code primarily consists of methods within the `SQLitePersistentSharedDictionaryStore::Backend` class. The names of the methods (e.g., `GetAllDictionariesImpl`, `GetDictionariesImpl`) strongly suggest their function is to retrieve dictionary data from the underlying SQLite database.

2. **Analyze Individual Methods:**
   - **`GetAllDictionariesImpl()`:** This method fetches *all* dictionaries from the `dictionaries` table. It queries all columns and organizes the results into a map where the key is `SharedDictionaryIsolationKey` and the value is a vector of `SharedDictionaryInfo`.
   - **`GetDictionariesImpl()`:** This method retrieves dictionaries associated with a specific `SharedDictionaryIsolationKey`. It filters the query based on `frame_origin` and `top_frame_site`.
   - **Data Extraction and Conversion:** Both methods iterate through the query results using `statement.Step()`. They extract data from each row using methods like `statement.ColumnString()`, `statement.ColumnTime()`, `statement.ColumnInt64()`, and `statement.ColumnBlob()`. They also convert raw data into more useful types like `GURL`, `base::Time`, `SHA256HashValue`, and `base::UnguessableToken`. Error handling is present for invalid hash and token values.

3. **Database Interaction:** The code utilizes `sql::Statement` to execute SQL queries. It defines SQL queries as `constexpr char[]`. The `InitializeDatabase()` method is called at the beginning of each function, suggesting a need to ensure the database is open before proceeding.

4. **Relationship to JavaScript:**  Shared dictionaries are a web platform feature that can be utilized by JavaScript. The purpose of this C++ code is to manage the persistent storage of these dictionaries. JavaScript can initiate requests that eventually lead to this code being executed to retrieve the stored dictionary data.

5. **Logical Inference (Input/Output):**
   - **Input:** The primary input to these functions is an implicit state of the SQLite database and, for `GetDictionariesImpl`, a `SharedDictionaryIsolationKey`.
   - **Output:** The output is a `DictionaryMapOrError` (for `GetAllDictionariesImpl`) or `DictionaryListOrError` (for `GetDictionariesImpl`). These types represent either a successful retrieval of dictionary data or an error. The data is structured as a map or vector of `SharedDictionaryInfo` objects.

6. **User/Programming Errors:** The code itself has some internal error handling (e.g., checking for invalid SQL, database initialization failures, invalid hash/token). A common programming error would be providing incorrect or malformed data that gets stored in the database, potentially leading to the "Invalid hash" or "Invalid token" warnings.

7. **User Operation to Reach Here (Debugging):**  A user browsing the web is the starting point. Specifically, a website utilizing shared dictionaries would trigger this code.
    - A website might use a `<link>` tag with `rel="preload"` and `as="dictionary"` to request a shared dictionary.
    - The browser would check its local storage for the dictionary.
    - If the dictionary is not in memory, the browser would query the persistent store, leading to the execution of these `GetDictionaries` methods.

8. **Summarize Functionality:** The core function of this code segment is to retrieve shared dictionary information from a SQLite database, either all dictionaries or those associated with a specific isolation key.

**(Self-Correction/Refinement):** Initially, I focused heavily on the SQL queries. However, it's crucial to also highlight the data transformation and the role of the `SharedDictionaryIsolationKey`. Also, connecting the functionality to the broader context of web browsing and JavaScript usage of shared dictionaries is important. The error handling mechanisms also deserve mention.
这是对 `net/extras/sqlite/sqlite_persistent_shared_dictionary_store.cc` 文件中部分代码的分析，延续了之前对该文件功能的探讨。这部分代码主要集中在**从 SQLite 数据库中检索共享字典信息**的功能。

**归纳一下这部分代码的功能:**

这部分代码主要实现了 `SQLitePersistentSharedDictionaryStore::Backend` 类的以下功能：

1. **检索所有共享字典 (`GetAllDictionariesImpl`):**  从 `dictionaries` 表中读取所有已存储的共享字典信息，并按照主键 `primary_key` 排序。它将结果组织成一个 `std::map`，其中键是 `SharedDictionaryIsolationKey`（用于标识字典的隔离上下文），值是 `std::vector<SharedDictionaryInfo>`（包含该隔离上下文中所有字典的详细信息）。

2. **检索特定隔离上下文的共享字典 (`GetDictionariesImpl`):**  根据提供的 `SharedDictionaryIsolationKey`，从 `dictionaries` 表中读取属于该隔离上下文的共享字典信息，同样按照主键 `primary_key` 排序。返回一个包含 `SharedDictionaryInfo` 的 `std::vector`。

3. **获取共享字典的使用信息 (`GetUsageInfoImpl`):**  从 `dictionaries` 表中读取每个隔离上下文的字典大小总和。它返回一个 `std::vector<SharedDictionaryUsageInfo>`，其中包含每个隔离上下文及其对应的总大小。

4. **获取指定时间范围内的来源 (`GetOriginsBetweenImpl`):**  查询在指定 `start_time` 和 `end_time` 之间的响应时间 (`res_time`) 内存储的字典的来源 (`frame_origin`)，并返回一个去重后的 `url::Origin` 列表。

**与 JavaScript 的关系：**

这段代码本身不直接执行 JavaScript，但它提供的功能是支持浏览器中与共享字典相关的 Web API。JavaScript 可以使用这些 API 来请求和使用共享字典。

**举例说明:**

假设一个网页 (`https://example.com`) 嵌入了一个来自另一个来源 (`https://cdn.example.net`) 的 iframe。

- 当 `https://example.com` 或 `https://cdn.example.net` 中的 JavaScript 代码尝试获取或使用一个共享字典时，浏览器会查询本地存储。
- 如果共享字典存储在 SQLite 数据库中，`GetDictionariesImpl` 方法会被调用，传入相应的 `SharedDictionaryIsolationKey` (可能包含 `frame_origin` 为 `https://example.com` 或 `https://cdn.example.net`，以及 `top_frame_site` 为 `https://example.com`)。
- 该方法会返回与该隔离上下文匹配的共享字典信息，这些信息随后会被浏览器用于后续操作，例如解压资源。

**逻辑推理（假设输入与输出）：**

**假设输入 (对于 `GetDictionariesImpl`):**

```c++
SharedDictionaryIsolationKey isolation_key(
    url::Origin::Create(GURL("https://example.com")),
    SchemefulSite(GURL("https://example.com"))
);
```

数据库中 `dictionaries` 表包含以下数据 (部分列)：

| primary_key | frame_origin        | top_frame_site      | url                     | ... |
|-------------|---------------------|----------------------|-------------------------|-----|
| 1           | https://example.com | https://example.com  | https://dict.example.com | ... |
| 2           | https://example.com | https://example.com  | https://dict2.example.com| ... |
| 3           | https://other.com   | https://other.com    | https://dict3.other.com  | ... |

**预期输出:**

`GetDictionariesImpl` 方法会返回一个 `base::ok` 包含一个 `std::vector<SharedDictionaryInfo>`，其中包含对应于 `primary_key` 为 1 和 2 的字典信息，因为它们的 `frame_origin` 和 `top_frame_site` 与输入的 `isolation_key` 匹配。

**假设输入 (对于 `GetAllDictionariesImpl`):**

假设数据库中 `dictionaries` 表包含与上述相同的三个条目。

**预期输出:**

`GetAllDictionariesImpl` 方法会返回一个 `base::ok` 包含一个 `std::map<SharedDictionaryIsolationKey, std::vector<SharedDictionaryInfo>>`，其中包含两个键值对：

- 键: `SharedDictionaryIsolationKey(url::Origin::Create(GURL("https://example.com")), SchemefulSite(GURL("https://example.com")))`，值: 包含 `primary_key` 为 1 和 2 的 `SharedDictionaryInfo` 的 `std::vector`。
- 键: `SharedDictionaryIsolationKey(url::Origin::Create(GURL("https://other.com")), SchemefulSite(GURL("https://other.com")))`，值: 包含 `primary_key` 为 3 的 `SharedDictionaryInfo` 的 `std::vector`。

**用户或编程常见的使用错误（虽然这段代码主要是内部实现，但可以推测）：**

1. **数据库初始化失败：** 如果由于文件权限或其他原因导致数据库无法初始化，这些方法会返回 `base::unexpected(Error::kFailedToInitializeDatabase)`。这通常是环境配置问题，而不是直接的用户操作错误。

2. **SQL 查询无效：**  如果代码中定义的 SQL 查询语句有语法错误，这些方法会返回 `base::unexpected(Error::kInvalidSql)`。这是编程错误，需要在开发阶段修复。

3. **数据类型不匹配：** 尽管代码中做了类型转换，但如果数据库中存储的数据类型与代码期望的不符（例如，本应是时间的字段存储了字符串），可能会导致解析错误，例如 "Invalid hash" 或 "Invalid token" 的警告。这可能是由于之前的代码写入了错误的数据，或者数据库被外部工具修改过。

**用户操作如何一步步的到达这里（作为调试线索）：**

1. **用户访问一个网页:** 用户在浏览器中输入网址或点击链接，访问一个网页。
2. **网页请求资源:** 网页加载过程中，可能会请求一些使用了共享字典压缩的资源。这可以通过服务器发送 `Accept-Encoding: br, ...` 并返回 `Content-Encoding: dictionary` 的响应头来指示。
3. **浏览器检查本地共享字典:** 浏览器接收到压缩资源后，会查找对应的共享字典。
4. **查询持久化存储:** 如果在内存中找不到该字典，浏览器会查询持久化存储，即 SQLite 数据库。
5. **调用 `GetDictionaries` 或 `GetAllDictionaries`:**  根据具体的查询需求，`SQLitePersistentSharedDictionaryStore::Backend` 中的 `GetDictionariesImpl` (查询特定隔离上下文) 或 `GetAllDictionariesImpl` (查询所有) 方法会被调用。
6. **执行 SQL 查询:**  这些方法会执行相应的 SQL 查询语句从 `dictionaries` 表中检索数据。
7. **返回结果:**  查询结果被封装成 `SharedDictionaryInfo` 对象并返回给浏览器的其他组件，以便用于解压缩资源。

因此，当你在调试一个网页加载缓慢，并且怀疑是由于共享字典加载或使用出现问题时，可以检查网络请求头和响应头，确认是否使用了共享字典。如果使用了，并且你怀疑本地存储有问题，就可以深入到 `net/extras/sqlite/sqlite_persistent_shared_dictionary_store.cc` 这个文件中相关的读取功能进行分析，查看是否能正常从数据库中读取到预期的共享字典信息。你可以设置断点在 `statement.Step()`，查看每次迭代读取到的数据是否正确。

### 提示词
```
这是目录为net/extras/sqlite/sqlite_persistent_shared_dictionary_store.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ime expiration_time = statement.ColumnTime(7);
    const base::Time last_used_time = statement.ColumnTime(8);
    const size_t size = statement.ColumnInt64(9);

    std::optional<SHA256HashValue> sha256_hash =
        ToSHA256HashValue(statement.ColumnBlob(10));
    if (!sha256_hash) {
      LOG(WARNING) << "Invalid hash";
      continue;
    }
    std::optional<base::UnguessableToken> disk_cache_key_token =
        ToUnguessableToken(statement.ColumnInt64(11),
                           statement.ColumnInt64(12));
    if (!disk_cache_key_token) {
      LOG(WARNING) << "Invalid token";
      continue;
    }
    result.emplace_back(GURL(url_string), last_fetch_time, response_time,
                        expiration_time - response_time, match, match_dest, id,
                        last_used_time, size, *sha256_hash,
                        *disk_cache_key_token, primary_key_in_database);
  }
  return base::ok(std::move(result));
}

SQLitePersistentSharedDictionaryStore::DictionaryMapOrError
SQLitePersistentSharedDictionaryStore::Backend::GetAllDictionariesImpl() {
  CHECK(background_task_runner()->RunsTasksInCurrentSequence());
  if (!InitializeDatabase()) {
    return base::unexpected(Error::kFailedToInitializeDatabase);
  }

  static constexpr char kQuery[] =
      // clang-format off
      "SELECT "
          "primary_key,"
          "frame_origin,"
          "top_frame_site,"
          "match,"
          "match_dest,"
          "id,"
          "url,"
          "last_fetch_time,"
          "res_time,"
          "exp_time,"
          "last_used_time,"
          "size,"
          "sha256,"
          "token_high,"
          "token_low FROM dictionaries "
          "ORDER BY primary_key";
  // clang-format on

  if (!db()->IsSQLValid(kQuery)) {
    return base::unexpected(Error::kInvalidSql);
  }

  std::map<SharedDictionaryIsolationKey, std::vector<SharedDictionaryInfo>>
      result;
  sql::Statement statement(db()->GetCachedStatement(SQL_FROM_HERE, kQuery));

  while (statement.Step()) {
    const int64_t primary_key_in_database = statement.ColumnInt64(0);
    const std::string frame_origin_string = statement.ColumnString(1);
    const std::string top_frame_site_string = statement.ColumnString(2);
    const std::string match = statement.ColumnString(3);
    const std::string match_dest = statement.ColumnString(4);
    const std::string id = statement.ColumnString(5);
    const std::string url_string = statement.ColumnString(6);
    const base::Time last_fetch_time = statement.ColumnTime(7);
    const base::Time response_time = statement.ColumnTime(8);
    const base::Time expiration_time = statement.ColumnTime(9);
    const base::Time last_used_time = statement.ColumnTime(10);
    const size_t size = statement.ColumnInt64(11);

    std::optional<SHA256HashValue> sha256_hash =
        ToSHA256HashValue(statement.ColumnBlob(12));
    if (!sha256_hash) {
      LOG(WARNING) << "Invalid hash";
      continue;
    }

    std::optional<base::UnguessableToken> disk_cache_key_token =
        ToUnguessableToken(statement.ColumnInt64(13),
                           statement.ColumnInt64(14));
    if (!disk_cache_key_token) {
      LOG(WARNING) << "Invalid token";
      continue;
    }

    url::Origin frame_origin = url::Origin::Create(GURL(frame_origin_string));
    SchemefulSite top_frame_site = SchemefulSite(GURL(top_frame_site_string));

    result[SharedDictionaryIsolationKey(frame_origin, top_frame_site)]
        .emplace_back(GURL(url_string), last_fetch_time, response_time,
                      expiration_time - response_time, match, match_dest, id,
                      last_used_time, size, *sha256_hash, *disk_cache_key_token,
                      primary_key_in_database);
  }
  return base::ok(std::move(result));
}

SQLitePersistentSharedDictionaryStore::UsageInfoOrError
SQLitePersistentSharedDictionaryStore::Backend::GetUsageInfoImpl() {
  CHECK(background_task_runner()->RunsTasksInCurrentSequence());
  if (!InitializeDatabase()) {
    return base::unexpected(Error::kFailedToInitializeDatabase);
  }

  static constexpr char kQuery[] =
      // clang-format off
      "SELECT "
          "frame_origin,"
          "top_frame_site,"
          "size FROM dictionaries "
          "ORDER BY primary_key";
  // clang-format on

  if (!db()->IsSQLValid(kQuery)) {
    return base::unexpected(Error::kInvalidSql);
  }

  std::map<SharedDictionaryIsolationKey, SharedDictionaryUsageInfo> result_map;
  sql::Statement statement(db()->GetCachedStatement(SQL_FROM_HERE, kQuery));

  while (statement.Step()) {
    const std::string frame_origin_string = statement.ColumnString(0);
    const std::string top_frame_site_string = statement.ColumnString(1);
    const size_t size = statement.ColumnInt64(2);

    const SharedDictionaryIsolationKey key = SharedDictionaryIsolationKey(
        url::Origin::Create(GURL(frame_origin_string)),
        SchemefulSite(GURL(top_frame_site_string)));
    auto it = result_map.find(key);
    if (it != result_map.end()) {
      it->second.total_size_bytes += size;
    } else {
      result_map[key] = SharedDictionaryUsageInfo{.isolation_key = key,
                                                  .total_size_bytes = size};
    }
  }

  std::vector<SharedDictionaryUsageInfo> result;
  for (auto& it : result_map) {
    result.push_back(std::move(it.second));
  }
  return base::ok(std::move(result));
}

SQLitePersistentSharedDictionaryStore::OriginListOrError
SQLitePersistentSharedDictionaryStore::Backend::GetOriginsBetweenImpl(
    const base::Time start_time,
    const base::Time end_time) {
  CHECK(background_task_runner()->RunsTasksInCurrentSequence());
  if (!InitializeDatabase()) {
    return base::unexpected(Error::kFailedToInitializeDatabase);
  }

  static constexpr char kQuery[] =
      // clang-format off
      "SELECT "
          "frame_origin FROM dictionaries "
          "WHERE res_time>=? AND res_time<? "
          "ORDER BY primary_key";
  // clang-format on

  if (!db()->IsSQLValid(kQuery)) {
    return base::unexpected(Error::kInvalidSql);
  }

  sql::Statement statement(db()->GetCachedStatement(SQL_FROM_HERE, kQuery));
  statement.BindTime(0, start_time);
  statement.BindTime(1, end_time);

  std::set<url::Origin> origins;
  while (statement.Step()) {
    const std::string frame_origin_string = statement.ColumnString(0);
    origins.insert(url::Origin::Create(GURL(frame_origin_string)));
  }
  return base::ok(std::vector<url::Origin>(origins.begin(), origins.end()));
}

SQLitePersistentSharedDictionaryStore::UnguessableTokenSetOrError
SQLitePersistentSharedDictionaryStore::Backend::ClearAllDictionariesImpl() {
  CHECK(background_task_runner()->RunsTasksInCurrentSequence());

  if (!InitializeDatabase()) {
    return base::unexpected(Error::kFailedToInitializeDatabase);
  }

  sql::Transaction transaction(db());
  if (!transaction.Begin()) {
    return base::unexpected(Error::kFailedToBeginTransaction);
  }

  static constexpr char kQuery[] =
      "DELETE FROM dictionaries RETURNING token_high, token_low";
  if (!db()->IsSQLValid(kQuery)) {
    return base::unexpected(Error::kInvalidSql);
  }
  sql::Statement statement(db()->GetCachedStatement(SQL_FROM_HERE, kQuery));

  std::vector<base::UnguessableToken> tokens;
  while (statement.Step()) {
    const int64_t token_high = statement.ColumnInt64(0);
    const int64_t token_low = statement.ColumnInt64(1);
    std::optional<base::UnguessableToken> disk_cache_key_token =
        ToUnguessableToken(token_high, token_low);
    if (!disk_cache_key_token) {
      continue;
    }
    tokens.emplace_back(*disk_cache_key_token);
  }

  if (!meta_table()->SetValue(kTotalDictSizeKey, 0)) {
    return base::unexpected(Error::kFailedToSetTotalDictSize);
  }

  if (!transaction.Commit()) {
    return base::unexpected(Error::kFailedToCommitTransaction);
  }
  return base::ok(
      std::set<base::UnguessableToken>(tokens.begin(), tokens.end()));
}

SQLitePersistentSharedDictionaryStore::UnguessableTokenSetOrError
SQLitePersistentSharedDictionaryStore::Backend::ClearDictionariesImpl(
    base::Time start_time,
    base::Time end_time,
    base::RepeatingCallback<bool(const GURL&)> url_matcher) {
  CHECK(background_task_runner()->RunsTasksInCurrentSequence());
  if (!InitializeDatabase()) {
    return base::unexpected(Error::kFailedToInitializeDatabase);
  }

  // Commit `pending_last_used_time_updates_`.
  DoCommit();

  sql::Transaction transaction(db());
  if (!transaction.Begin()) {
    return base::unexpected(Error::kFailedToBeginTransaction);
  }
  std::vector<int64_t> primary_keys;
  std::vector<base::UnguessableToken> tokens;
  int64_t total_size = 0;
  Error error = url_matcher ? SelectMatchingDictionariesWithUrlMatcher(
                                  start_time, end_time, std::move(url_matcher),
                                  &primary_keys, &tokens, &total_size)
                            : SelectMatchingDictionaries(start_time, end_time,
                                                         &primary_keys, &tokens,
                                                         &total_size);
  if (error != Error::kOk) {
    return base::unexpected(error);
  }
  for (int64_t primary_key : primary_keys) {
    error = DeleteDictionaryByPrimaryKey(primary_key);
    if (error != Error::kOk) {
      return base::unexpected(error);
    }
  }
  if (total_size != 0) {
    uint64_t total_dictionary_size = 0;
    error = UpdateTotalDictionarySizeInMetaTable(-total_size,
                                                 &total_dictionary_size);
    if (error != Error::kOk) {
      return base::unexpected(error);
    }
  }

  transaction.Commit();
  return base::ok(
      std::set<base::UnguessableToken>(tokens.begin(), tokens.end()));
}

SQLitePersistentSharedDictionaryStore::Error
SQLitePersistentSharedDictionaryStore::Backend::SelectMatchingDictionaries(
    base::Time start_time,
    base::Time end_time,
    std::vector<int64_t>* primary_keys_out,
    std::vector<base::UnguessableToken>* tokens_out,
    int64_t* total_size_out) {
  CHECK(background_task_runner()->RunsTasksInCurrentSequence());
  static constexpr char kQuery[] =
      // clang-format off
      "SELECT "
          "primary_key,"
          "size,"
          "token_high,"
          "token_low FROM dictionaries "
          "WHERE res_time>=? AND res_time<? "
          "ORDER BY primary_key";
  // clang-format on

  if (!db()->IsSQLValid(kQuery)) {
    return Error::kInvalidSql;
  }

  sql::Statement statement(db()->GetCachedStatement(SQL_FROM_HERE, kQuery));
  statement.BindTime(0, start_time);
  statement.BindTime(1, end_time.is_null() ? base::Time::Max() : end_time);

  base::CheckedNumeric<int64_t> checked_total_size;
  while (statement.Step()) {
    const int64_t primary_key_in_database = statement.ColumnInt64(0);
    const size_t size = statement.ColumnInt64(1);
    const int64_t token_high = statement.ColumnInt64(2);
    const int64_t token_low = statement.ColumnInt64(3);
    std::optional<base::UnguessableToken> disk_cache_key_token =
        ToUnguessableToken(token_high, token_low);
    if (!disk_cache_key_token) {
      LOG(WARNING) << "Invalid token";
      continue;
    }
    primary_keys_out->emplace_back(primary_key_in_database);
    tokens_out->emplace_back(*disk_cache_key_token);
    checked_total_size += size;
  }
  *total_size_out = checked_total_size.ValueOrDie();
  return Error::kOk;
}

SQLitePersistentSharedDictionaryStore::Error
SQLitePersistentSharedDictionaryStore::Backend::
    SelectMatchingDictionariesWithUrlMatcher(
        base::Time start_time,
        base::Time end_time,
        base::RepeatingCallback<bool(const GURL&)> url_matcher,
        std::vector<int64_t>* primary_keys_out,
        std::vector<base::UnguessableToken>* tokens_out,
        int64_t* total_size_out) {
  CHECK(background_task_runner()->RunsTasksInCurrentSequence());
  static constexpr char kQuery[] =
      // clang-format off
      "SELECT "
          "primary_key,"
          "frame_origin,"
          "top_frame_site,"
          "host,"
          "size,"
          "token_high,"
          "token_low FROM dictionaries "
          "WHERE res_time>=? AND res_time<? "
          "ORDER BY primary_key";
  // clang-format on

  if (!db()->IsSQLValid(kQuery)) {
    return Error::kInvalidSql;
  }

  sql::Statement statement(db()->GetCachedStatement(SQL_FROM_HERE, kQuery));
  statement.BindTime(0, start_time);
  statement.BindTime(1, end_time.is_null() ? base::Time::Max() : end_time);

  base::CheckedNumeric<int64_t> checked_total_size;
  while (statement.Step()) {
    const int64_t primary_key_in_database = statement.ColumnInt64(0);
    const std::string frame_origin_string = statement.ColumnString(1);
    const std::string top_frame_site_string = statement.ColumnString(2);
    const std::string host = statement.ColumnString(3);
    const size_t size = statement.ColumnInt64(4);
    const int64_t token_high = statement.ColumnInt64(5);
    const int64_t token_low = statement.ColumnInt64(6);

    if (!url_matcher.Run(GURL(frame_origin_string)) &&
        !url_matcher.Run(GURL(top_frame_site_string)) &&
        !url_matcher.Run(GURL(host))) {
      continue;
    }
    std::optional<base::UnguessableToken> disk_cache_key_token =
        ToUnguessableToken(token_high, token_low);
    if (!disk_cache_key_token) {
      LOG(WARNING) << "Invalid token";
      continue;
    }
    primary_keys_out->emplace_back(primary_key_in_database);
    tokens_out->emplace_back(*disk_cache_key_token);
    checked_total_size += size;
  }
  *total_size_out = checked_total_size.ValueOrDie();
  return Error::kOk;
}

SQLitePersistentSharedDictionaryStore::UnguessableTokenSetOrError
SQLitePersistentSharedDictionaryStore::Backend::
    ClearDictionariesForIsolationKeyImpl(
        const SharedDictionaryIsolationKey& isolation_key) {
  CHECK(background_task_runner()->RunsTasksInCurrentSequence());
  if (!InitializeDatabase()) {
    return base::unexpected(Error::kFailedToInitializeDatabase);
  }
  sql::Transaction transaction(db());
  if (!transaction.Begin()) {
    return base::unexpected(Error::kFailedToBeginTransaction);
  }

  static constexpr char kQuery[] =
      // clang-format off
      "DELETE FROM dictionaries "
          "WHERE frame_origin=? AND top_frame_site=? "
          "RETURNING size, token_high, token_low";
  // clang-format on

  if (!db()->IsSQLValid(kQuery)) {
    return base::unexpected(Error::kInvalidSql);
  }

  sql::Statement statement(db()->GetCachedStatement(SQL_FROM_HERE, kQuery));
  statement.BindString(0, isolation_key.frame_origin().Serialize());
  statement.BindString(1, isolation_key.top_frame_site().Serialize());

  std::vector<base::UnguessableToken> tokens;
  base::CheckedNumeric<int64_t> checked_total_size = 0;
  while (statement.Step()) {
    const size_t size = statement.ColumnInt64(0);
    const int64_t token_high = statement.ColumnInt64(1);
    const int64_t token_low = statement.ColumnInt64(2);

    checked_total_size += size;

    std::optional<base::UnguessableToken> disk_cache_key_token =
        ToUnguessableToken(token_high, token_low);
    if (!disk_cache_key_token) {
      continue;
    }
    tokens.emplace_back(*disk_cache_key_token);
  }

  int64_t total_size = checked_total_size.ValueOrDie();
  if (total_size != 0) {
    uint64_t total_dictionary_size = 0;
    Error error = UpdateTotalDictionarySizeInMetaTable(-total_size,
                                                       &total_dictionary_size);
    if (error != Error::kOk) {
      return base::unexpected(error);
    }
  }
  transaction.Commit();
  return base::ok(
      std::set<base::UnguessableToken>(tokens.begin(), tokens.end()));
}

SQLitePersistentSharedDictionaryStore::UnguessableTokenSetOrError
SQLitePersistentSharedDictionaryStore::Backend::DeleteExpiredDictionariesImpl(
    base::Time now) {
  CHECK(background_task_runner()->RunsTasksInCurrentSequence());
  if (!InitializeDatabase()) {
    return base::unexpected(Error::kFailedToInitializeDatabase);
  }
  sql::Transaction transaction(db());
  if (!transaction.Begin()) {
    return base::unexpected(Error::kFailedToBeginTransaction);
  }
  static constexpr char kQuery[] =
      // clang-format off
      "DELETE FROM dictionaries "
          "WHERE exp_time<=? "
          "RETURNING size, token_high, token_low";
  // clang-format on

  if (!db()->IsSQLValid(kQuery)) {
    return base::unexpected(Error::kInvalidSql);
  }

  sql::Statement statement(db()->GetCachedStatement(SQL_FROM_HERE, kQuery));
  statement.BindTime(0, now);

  std::vector<base::UnguessableToken> tokens;
  base::CheckedNumeric<int64_t> checked_total_size = 0;
  while (statement.Step()) {
    const size_t size = statement.ColumnInt64(0);
    const int64_t token_high = statement.ColumnInt64(1);
    const int64_t token_low = statement.ColumnInt64(2);

    checked_total_size += size;

    std::optional<base::UnguessableToken> disk_cache_key_token =
        ToUnguessableToken(token_high, token_low);
    if (!disk_cache_key_token) {
      LOG(WARNING) << "Invalid token";
      continue;
    }
    tokens.emplace_back(*disk_cache_key_token);
  }

  int64_t total_size = checked_total_size.ValueOrDie();
  if (total_size != 0) {
    uint64_t total_dictionary_size = 0;
    Error error = UpdateTotalDictionarySizeInMetaTable(-total_size,
                                                       &total_dictionary_size);
    if (error != Error::kOk) {
      return base::unexpected(error);
    }
  }
  transaction.Commit();
  return base::ok(
      std::set<base::UnguessableToken>(tokens.begin(), tokens.end()));
}

SQLitePersistentSharedDictionaryStore::UnguessableTokenSetOrError
SQLitePersistentSharedDictionaryStore::Backend::ProcessEvictionImpl(
    uint64_t cache_max_size,
    uint64_t size_low_watermark,
    uint64_t cache_max_count,
    uint64_t count_low_watermark) {
  if (!InitializeDatabase()) {
    return base::unexpected(Error::kFailedToInitializeDatabase);
  }

  // Commit `pending_last_used_time_updates_`.
  DoCommit();

  sql::Transaction transaction(db());
  if (!transaction.Begin()) {
    return base::unexpected(Error::kFailedToBeginTransaction);
  }
  std::vector<int64_t> primary_keys;
  std::vector<base::UnguessableToken> tokens;
  int64_t total_size_after_eviction = 0;
  Error error = SelectEvictionCandidates(
      cache_max_size, size_low_watermark, cache_max_count, count_low_watermark,
      &primary_keys, &tokens, &total_size_after_eviction);
  if (error != Error::kOk) {
    return base::unexpected(error);
  }
  CHECK_EQ(primary_keys.size(), tokens.size());
  if (primary_keys.empty()) {
    return base::ok(std::set<base::UnguessableToken>());
  }
  for (int64_t primary_key : primary_keys) {
    error = DeleteDictionaryByPrimaryKey(primary_key);
    if (error != Error::kOk) {
      return base::unexpected(error);
    }
  }

  if (!meta_table()->SetValue(kTotalDictSizeKey, total_size_after_eviction)) {
    return base::unexpected(Error::kFailedToSetTotalDictSize);
  }

  transaction.Commit();
  return base::ok(
      std::set<base::UnguessableToken>(tokens.begin(), tokens.end()));
}

SQLitePersistentSharedDictionaryStore::Error
SQLitePersistentSharedDictionaryStore::Backend::SelectEvictionCandidates(
    uint64_t cache_max_size,
    uint64_t size_low_watermark,
    uint64_t cache_max_count,
    uint64_t count_low_watermark,
    std::vector<int64_t>* primary_keys_out,
    std::vector<base::UnguessableToken>* tokens_out,
    int64_t* total_size_after_eviction_out) {
  ASSIGN_OR_RETURN(uint64_t total_dictionary_size,
                   GetTotalDictionarySizeImpl());
  ASSIGN_OR_RETURN(uint64_t total_dictionary_count, GetTotalDictionaryCount());

  if ((cache_max_size == 0 || total_dictionary_size <= cache_max_size) &&
      total_dictionary_count <= cache_max_count) {
    return Error::kOk;
  }

  uint64_t to_be_removed_count = 0;
  if (total_dictionary_count > count_low_watermark) {
    to_be_removed_count = total_dictionary_count - count_low_watermark;
  }

  base::CheckedNumeric<uint64_t> checked_total_dictionary_size =
      total_dictionary_size;

  static constexpr char kQuery[] =
      // clang-format off
      "SELECT "
          "primary_key,"
          "size,"
          "token_high,"
          "token_low FROM dictionaries "
          "ORDER BY last_used_time";
  // clang-format on

  if (!db()->IsSQLValid(kQuery)) {
    return Error::kInvalidSql;
  }

  sql::Statement statement(db()->GetCachedStatement(SQL_FROM_HERE, kQuery));
  while (statement.Step()) {
    const int64_t primary_key_in_database = statement.ColumnInt64(0);
    const size_t size = statement.ColumnInt64(1);
    const int64_t token_high = statement.ColumnInt64(2);
    const int64_t token_low = statement.ColumnInt64(3);
    std::optional<base::UnguessableToken> disk_cache_key_token =
        ToUnguessableToken(token_high, token_low);
    if (!disk_cache_key_token) {
      LOG(WARNING) << "Invalid token";
      continue;
    }
    checked_total_dictionary_size -= size;

    if (!checked_total_dictionary_size.IsValid()) {
      base::debug::DumpWithoutCrashing();
      return Error::kInvalidTotalDictSize;
    }

    *total_size_after_eviction_out =
        base::checked_cast<int64_t>(checked_total_dictionary_size.ValueOrDie());
    primary_keys_out->emplace_back(primary_key_in_database);
    tokens_out->emplace_back(*disk_cache_key_token);

    if ((cache_max_size == 0 ||
         size_low_watermark >= checked_total_dictionary_size.ValueOrDie()) &&
        tokens_out->size() >= to_be_removed_count) {
      break;
    }
  }
  return Error::kOk;
}

SQLitePersistentSharedDictionaryStore::Error
SQLitePersistentSharedDictionaryStore::Backend::DeleteDictionaryByPrimaryKey(
    int64_t primary_key) {
  CHECK(background_task_runner()->RunsTasksInCurrentSequence());
  static constexpr char kQuery[] =
      "DELETE FROM dictionaries WHERE primary_key=?";
  if (!db()->IsSQLValid(kQuery)) {
    return Error::kInvalidSql;
  }
  sql::Statement statement(db()->GetCachedStatement(SQL_FROM_HERE, kQuery));
  statement.BindInt64(0, primary_key);

  if (!statement.Run()) {
    return Error::kFailedToExecuteSql;
  }
  return Error::kOk;
}

SQLitePersistentSharedDictionaryStore::Error
SQLitePersistentSharedDictionaryStore::Backend::
    DeleteDictionariesByDiskCacheKeyTokensImpl(
        const std::set<base::UnguessableToken>& disk_cache_key_tokens) {
  if (!InitializeDatabase()) {
    return Error::kFailedToInitializeDatabase;
  }

  sql::Transaction transaction(db());
  if (!transaction.Begin()) {
    return Error::kFailedToBeginTransaction;
  }

  base::CheckedNumeric<int64_t> checked_total_deleted_dictionary_size;
  for (const auto& token : disk_cache_key_tokens) {
    ASSIGN_OR_RETURN(uint64_t deleted_dictionary_size,
                     DeleteDictionaryByDiskCacheToken(token));
    checked_total_deleted_dictionary_size += deleted_dictionary_size;
  }

  int64_t total_deleted_dictionary_size =
      checked_total_deleted_dictionary_size.ValueOrDie();
  if (total_deleted_dictionary_size != 0) {
    uint64_t total_dictionary_size = 0;
    Error error = UpdateTotalDictionarySizeInMetaTable(
        -total_deleted_dictionary_size, &total_dictionary_size);
    if (error != Error::kOk) {
      return error;
    }
  }

  if (!transaction.Commit()) {
    return Error::kFailedToCommitTransaction;
  }
  return Error::kOk;
}

SQLitePersistentSharedDictionaryStore::Error
SQLitePersistentSharedDictionaryStore::Backend::
    UpdateDictionaryLastFetchTimeImpl(int64_t primary_key_in_database,
                                      base::Time last_fetch_time) {
  if (!InitializeDatabase()) {
    return Error::kFailedToInitializeDatabase;
  }
  static constexpr char kQuery[] =
      "UPDATE dictionaries SET last_fetch_time=? WHERE primary_key=?";

  if (!db()->IsSQLValid(kQuery)) {
    return Error::kInvalidSql;
  }
  sql::Statement statement(db()->GetCachedStatement(SQL_FROM_HERE, kQuery));
  statement.BindTime(0, last_fetch_time);
  statement.BindInt64(1, primary_key_in_database);
  if (!statement.Run()) {
    return Error::kFailedToExecuteSql;
  }
  return Error::kOk;
}

base::expected<uint64_t, SQLitePersistentSharedDictionaryStore::Error>
SQLitePersistentSharedDictionaryStore::Backend::
    DeleteDictionaryByDiskCacheToken(
        const base::UnguessableToken& disk_cache_key_token) {
  CHECK(background_task_runner()->RunsTasksInCurrentSequence());
  if (!InitializeDatabase()) {
    return base::unexpected(Error::kFailedToInitializeDatabase);
  }
  static constexpr char kQuery[] =
      // clang-format off
      "DELETE FROM dictionaries "
          "WHERE token_high=? AND token_low=?"
          "RETURNING size";
  // clang-format on

  if (!db()->IsSQLValid(kQuery)) {
    return base::unexpected(Error::kInvalidSql);
  }

  sql::Statement statement(db()->GetCachedStatement(SQL_FROM_HERE, kQuery));
  // There is no `sql::Statement::BindUint64()` method. So we cast to int64_t.
  int64_t token_high =
      static_cast<int64_t>(disk_cache_key_token.GetHighForSerialization());
  int64_t token_low =
      static_cast<int64_t>(disk_cache_key_token.GetLowForSerialization());
  statement.BindInt64(0, token_high);
  statement.BindInt64(1, token_low);

  base::CheckedNumeric<uint64_t> checked_size = 0;
  while (statement.Step()) {
    const size_t size = statement.ColumnInt64(0);
    checked_size += size;
  }
  return base::ok(checked_size.ValueOrDie());
}

SQLitePersistentSharedDictionaryStore::UnguessableTokenSetOrError
SQLitePersistentSharedDictionaryStore::Backend::GetAllDiskCacheKeyTokensImpl() {
  CHECK(background_task_runner()->RunsTasksInCurrentSequence());
  if (!InitializeDatabase()) {
    return base::unexpected(Error::kFailedToInitializeDatabase);
  }

  static constexpr char kQuery[] =
      // clang-format off
      "SELECT "
          "primary_key,"
          "token_high,"
          "token_low FROM dictionaries "
          "ORDER BY primary_key";
  // clang-format on

  if (!db()->IsSQLValid(kQuery)) {
    return base::unexpected(Error::kInvalidSql);
  }

  sql::Statement statement(db()->GetCachedStatement(SQL_FROM_HERE, kQuery));
  std::vector<base::UnguessableToken> tokens;
  while (statement.Step()) {
    std::optional<base::UnguessableToken> disk_cache_key_token =
        ToUnguessableToken(statement.ColumnInt64(1), statement.ColumnInt64(2));
    if (!disk_cache_key_token) {
      LOG(WARNING) << "Invalid token";
      continue;
    }
    tokens.emplace_back(*disk_cache_key_token);
  }
  return base::ok(
      std::set<base::UnguessableToken>(tokens.begin(), tokens.end()));
}

void SQLitePersistentSharedDictionaryStore::Backend::
    UpdateDictionaryLastUsedTime(int64_t primary_key_in_database,
                                 base::Time last_used_time) {
  CHECK(client_task_runner()->RunsTasksInCurrentSequence());
  CHECK(!background_task_runner()->RunsTasksInCurrentSequence());
  size_t num_pending;
  {
    base::AutoLock locked(lock_);
    pending_last_used_time_updates_[primary_key_in_database] = last_used_time;
    num_pending = ++num_pending_;
  }
  // Commit every 30 seconds.
  static const int kCommitIntervalMs = 30 * 1000;
  // Commit right away if we have more than 100 operations.
  static const size_t kCommitAfterBatchSize = 100;
  if (num_pending == 1) {
    // We've gotten our first entry for this batch, fire off the timer.
    if (!background_task_runner()->PostDelayedTask(
            FROM_HERE, base::BindOnce(&Backend::Commit, this),
            base::Milliseconds(kCommitIntervalMs))) {
      NOTREACHED() << "background_task_runner_ is not running.";
    }
  } else if (num_pending >= kCommitAfterBatchSize) {
    // We've reached a big enough batch, fire off a commit now.
    PostBackgroundTask(FROM_HERE, base::BindOnce(&Backend::Commit, this));
  }
}

base::expected<uint64_t, SQLitePersistentSharedDictionaryStore::Error>
SQLitePersistentSharedDictionaryStore::Backend::GetTotalDictionaryCount() {
  CHECK(background_task_runner()->RunsTasksInCurrentSequence());
  static constexpr char kQuery[] =
      "SELECT COUNT(primary_key) FROM dictionaries";

  if (!db()->IsSQLValid(kQuery)) {
    return base::unexpected(Error::kInvalidSql);
  }
  uint64_t dictionary_count = 0;
  sql::Statement statement(db()->GetCachedStatement(SQL_FROM_HERE, kQuery));
  if (statement.Step()) {
    dictionary_count = statement.ColumnInt64(0);
  }
  return base::ok(dictionary_count);
}

bool SQLitePersistentSharedDictionaryStore::Backend::
    GetExistingDictionarySizeAndDiskCacheKeyToken(
        const SharedDictionaryIsolationKey& isolation_key,
        const url::SchemeHostPort& host,
        const std::string& match,
        const std::string& match_dest,
        int64_t* size_out,
        std::optional<base::UnguessableToken>* disk_cache_key_out) {
  CHECK(background_task_runner()->RunsTasksInCurrentSequence());

  static constexpr char kQuery[] =
      // clang-format off
      "SELECT "
          "size,"
          "token_high,"
          "token_low FROM dictionaries "
          "WHERE "
              "frame_origin=? AND "
              "top_frame_site=? AND "
              "host=? AND "
              "match=? AND "
              "match_dest=? "
          "ORDER BY primary_key";
  // clang-format on

  if (!db()->IsSQLValid(kQuery)) {
    return false;
  }
  sql::Statement statement(db()->GetCachedStatement(SQL_FROM_HERE, kQuery));
  statement.BindString(0, isolation_key.frame_origin().Serialize());
  statement.BindString(1, isolation_key.top_frame_site().Serialize());
  statement.BindString(2, host.Serialize());
  statement.BindString(3, match);
  statement.BindString(4, match_dest);

  if (statement.Step()) {
    *size_out = statement.ColumnInt64(0);
    *disk_cache_key_out =
        ToUnguessableToken(statement.ColumnInt64(1), statement.ColumnInt64(2));
    return true;
  }
  return false;
}

SQLitePersistentSharedDictionaryStore::Error
SQLitePersistentSharedDictionaryStore::Backend::
    UpdateTotalDictionarySizeInMetaTable(int64_t size_delta,
                                         uint64_t* total_dictionary_size_out) {
  CHECK(background_task_runner()->RunsTasksInCurrentSequence());
  ASSIGN_OR_RETURN(uint64_t total_dictionary_size,
                   GetTotalDictionarySizeImpl());
  base::CheckedNumeric<uint64_t> checked_total_dictionary_size =
      total_dictionary_size;
  checked_total_dictionary_size += size_delta;
  if (!checked_total_dictionary_size.IsValid()) {
    LOG(ERROR) << "Invalid total_dict_size detected.";
    base::debug::DumpWithoutCrashing();
    return Error::kInvalidTotalDictSize;
  }
  *total_dictionary_size_out = checked_total_dictionary_size.ValueOrDie();
  if (!meta_table()->SetValue(kTotalDictSizeKey, *total_dictionary_size_out)) {
    return Error::kFailedToSetTotalDictSize;
  }
  return Error::kOk;
}

SQLitePersistentSharedDictionaryStore::SQLitePersistentSharedDictionaryStore(
    const base::FilePath& path,
    const scoped_refptr<base::SequencedTaskRunner>& client_task_runner,
    const scoped_refptr<base::SequencedTaskRunner>& background_task_runner)
    : backend_(base::MakeRefCounted<Backend>(path,
                                             client_task_runner,
                                             background_task_runner)) {}

SQLitePersistentSharedDictionaryStore::
    ~SQLitePersistentSharedDictionaryStore() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  backend_->Close();
}

void SQLitePersistentSharedDictionaryStore::GetTotalDictionarySize(
    base::OnceCallback<void(SizeOrError)> callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  backend_->GetTotalDictionarySize(
      WrapCallbackWithWeakPtrCheck(GetWeakPtr(), std::move(callback)));
}

void SQLitePersistentSharedDictionaryStore::RegisterDictionary(
    const SharedDictionaryIsolationKey& isolation_key,
    SharedDictionaryInfo dictionary_info,
    const uint64_t max_size_per_site,
    const uint64_t max_count_per_site,
    base::OnceCallback<void(RegisterDictionaryResultOrError)> callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  backend_->RegisterDictionary(
      WrapCallbackWithWeakPtrCheck(GetWeakPtr(), std::move(callback)),
      isolation_key, std::move(dictionary_info), max_size_per_site,
      max_count_per_site);
}

void SQLitePersistentSharedDictionaryStore::GetDictionaries(
    const SharedDictionaryIsolationKey& isolation_key,
    base::OnceCallback<void(DictionaryListOrError)> callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  backend_->GetDictionaries(
      WrapCallbackWithWeakPtrCheck(GetWeakPtr(), std::move(callback)),
      isolation_key);
}

void SQLitePersistentSharedDictionaryStore::GetAl
```