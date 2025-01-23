Response:
The user wants a summary of the provided C++ code snippet. This snippet is part of the `SQLitePersistentCookieStore::Backend` class in Chromium, specifically dealing with loading cookies from the SQLite database.

Here's a breakdown of the code's functionality:

1. **`FinishedLoadingCookies`**:  Finalizes the cookie loading process, merging loaded cookies and running the callback.
2. **`CreateDatabaseSchema`**: Checks if the cookie table exists or creates it if needed.
3. **`DoInitializeDatabase`**:  Reads all distinct host keys from the database to prepare for loading cookies for each domain. It also handles deleting session cookies if `restore_old_session_cookies_` is false.
4. **`ChainLoadCookies`**:  Implements a chained loading mechanism to load cookies for different domains in the background. It loads cookies for one domain key at a time and schedules the loading of the next domain key.
5. **`LoadCookiesForDomains`**:  Loads cookies from the database for a given set of domains. It constructs SQL queries based on whether old session cookies should be restored. It handles potential errors during cookie loading and attempts to recover by deleting the entire eTLD group of cookies if necessary.
6. **`DeleteTopFrameSiteKeys`**:  Deletes cookies based on their `top_frame_site_key`.
7. **`MakeCookiesFromSQLStatement`**:  Iterates through the results of an SQL query and attempts to construct `CanonicalCookie` objects. It handles decryption of cookie values if encryption is enabled and skips invalid or problematic cookies.
8. **`DoMigrateDatabaseSchema`**:  Contains logic to migrate the database schema to newer versions, performing necessary table alterations and data transformations.
9. **`AddCookie`**, **`UpdateCookieAccessTime`**, **`DeleteCookie`**: Queue cookie operations for later batch commitment to the database.
10. **`BatchOperation`**:  Adds a cookie operation to a queue and triggers a commit to the database after a certain time or batch size is reached.
11. **`DoCommit`**:  Persists the queued cookie operations (add, update, delete) to the SQLite database.
12. **`GetQueueLengthForTesting`**:  Returns the number of pending cookie operations (used for testing).
13. **`DeleteAllInList`**:  Initiates the deletion of cookies specified in a list.

The primary goal of this code is to efficiently and reliably load and manage cookies from a persistent SQLite database in Chromium's network stack. It includes mechanisms for background loading, batch writing, schema migration, and handling potential data inconsistencies.
这是 Chromium 网络栈中 `SQLitePersistentCookieStore::Backend` 类的部分源代码，主要负责从 SQLite 数据库中**加载 (Loading)** 和 **批量写入 (Batch Writing)** Cookie 数据。

**主要功能归纳:**

1. **延迟加载 Cookie 数据 (Lazy Loading):**  为了避免启动时阻塞主线程，Cookie 数据不是一次性全部加载，而是按需分批加载。`DoInitializeDatabase` 方法会先读取所有不同的 `host_key` (域名)，然后 `ChainLoadCookies` 和 `LoadCookiesForDomains` 方法会逐步加载这些域名的 Cookie。

2. **从 SQLite 数据库读取 Cookie:** `LoadCookiesForDomains` 方法使用 SQL 查询语句从数据库中读取指定域名的 Cookie 数据。它可以选择加载所有 Cookie (包括 session Cookie) 或仅加载持久化 Cookie，这取决于 `restore_old_session_cookies_` 标志。

3. **Cookie 数据反序列化:** `MakeCookiesFromSQLStatement` 方法将从数据库读取的原始数据转换为 `CanonicalCookie` 对象。这个过程包括：
    * **解密 (Decryption):** 如果启用了加密 (`crypto_` 不为空)，则会解密存储的加密 Cookie 值。
    * **校验 (Validation):** 检查 Cookie 的有效性，例如，处理同时存在加密和未加密值的情况，以及校验解密后的哈希值。
    * **创建 `CanonicalCookie` 对象:** 使用从数据库读取的数据创建标准的 Cookie 对象。

4. **数据库 Schema 管理:** `CreateDatabaseSchema` 检查 Cookie 表是否存在，如果不存在则创建。 `DoMigrateDatabaseSchema` 负责数据库 Schema 的升级迁移，以适应代码的更新。

5. **批量写入 Cookie 操作 (Batch Writing):**  为了提高性能，Cookie 的添加、更新和删除操作不会立即写入数据库，而是先被缓存起来。`BatchOperation` 方法将这些操作添加到队列中，并在达到一定数量或时间间隔后，通过 `DoCommit` 方法批量写入数据库。

6. **处理数据一致性问题:**  在加载 Cookie 的过程中，如果遇到无法加载的 Cookie，为了保证数据一致性，`LoadCookiesForDomains` 可能会选择删除整个域名下的 Cookie 数据。

**与 JavaScript 的关系举例:**

这个 C++ 代码直接负责浏览器后端 Cookie 数据的存储和管理，JavaScript 无法直接访问或操作 SQLite 数据库。但是，JavaScript 通过浏览器提供的 Web API (例如 `document.cookie`) 与 Cookie 进行交互。

**举例说明:**

1. **JavaScript 设置 Cookie:** 当 JavaScript 代码执行 `document.cookie = "name=value"` 时，浏览器会将这个 Cookie 信息传递到网络栈的 C++ 代码。最终，`SQLitePersistentCookieStore::Backend::AddCookie` 方法会被调用，将这个 Cookie 信息添加到待写入数据库的队列中。

2. **JavaScript 读取 Cookie:** 当 JavaScript 代码尝试读取 Cookie 时 (通常通过 `document.cookie` 属性)，浏览器会从内存中的 Cookie 存储 (`CookieMonster`) 中读取。而 `CookieMonster` 的数据正是通过 `SQLitePersistentCookieStore::Backend` 从 SQLite 数据库加载而来。

**假设输入与输出 (逻辑推理):**

**假设输入:**

* **场景 1 (加载 Cookie):**
    * 数据库中存在以下两条 Cookie 数据 (简化表示):
        * `host_key`: "example.com", `name`: "cookie1", `value`: "value1", `is_persistent`: 1
        * `host_key`: "example.com", `name`: "cookie2", `value`: "value2", `is_persistent`: 0
    * `restore_old_session_cookies_` 为 false。
* **场景 2 (批量添加 Cookie):**
    * 调用 `BatchOperation` 添加了两个 Cookie 对象:
        * `domain`: "test.com", `name`: "new_cookie1", `value`: "new_value1"
        * `domain`: "test.com", `name`: "new_cookie2", `value`: "new_value2"
    * 随后调用 `Commit` 方法。

**预期输出:**

* **场景 1:** `LoadCookiesForDomains` 方法会查询 `host_key` 为 "example.com" 且 `is_persistent` 为 1 的 Cookie，最终 `cookies_` 成员变量会包含一个 `CanonicalCookie` 对象，对应数据库中的 "cookie1"。 "cookie2" 是 session Cookie，由于 `restore_old_session_cookies_` 为 false，所以不会被加载。

* **场景 2:** `DoCommit` 方法会将这两个 Cookie 对象的信息插入到 SQLite 数据库的 `cookies` 表中。

**用户或编程常见的使用错误举例:**

1. **数据库文件损坏或权限问题:** 如果 SQLite 数据库文件被损坏或者程序没有足够的权限访问该文件，会导致 Cookie 加载或写入失败。这可能表现为网站的登录状态丢失，或者无法保存用户的偏好设置。

2. **数据库 Schema 不匹配:** 如果代码更新导致数据库 Schema 发生变化，而用户本地的数据库 Schema 仍然是旧版本，可能会导致程序崩溃或数据加载错误。`DoMigrateDatabaseSchema` 的存在正是为了解决这个问题，但如果迁移逻辑存在错误，也会导致问题。

3. **并发访问数据库:** 如果有多个进程或线程同时尝试读写 Cookie 数据库，可能会导致数据损坏。`SQLitePersistentCookieStore::Backend` 使用锁 (`lock_`) 来保护对 `cookies_` 成员变量的访问，并使用 SQLite 的事务来保证数据库操作的原子性。但是，如果在外部有其他程序直接操作该数据库文件，仍然可能出现问题。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户访问了一个网站 `example.com`，并且该网站设置了一个持久化的 Cookie。

1. **用户访问网站:** 用户在浏览器地址栏输入 `example.com` 并回车。
2. **浏览器发送请求:** 浏览器向 `example.com` 的服务器发送 HTTP 请求。
3. **服务器设置 Cookie:** 服务器在 HTTP 响应头中包含 `Set-Cookie` 指令，例如 `Set-Cookie: mycookie=myvalue; Expires=...; Path=/; Domain=example.com; Secure; HttpOnly`.
4. **浏览器接收响应:** 浏览器接收到服务器的响应。
5. **解析 `Set-Cookie`:** 浏览器解析 `Set-Cookie` 指令，创建一个 `CanonicalCookie` 对象。
6. **存储 Cookie:**  网络栈中的 Cookie 管理模块 (例如 `CookieMonster`) 接收到这个 `CanonicalCookie` 对象，并决定将其持久化。
7. **调用 `AddCookie`:** `SQLitePersistentCookieStore::Backend::AddCookie` 方法被调用，将这个 Cookie 对象添加到待写入数据库的队列中。
8. **触发 `Commit`:**  经过一段时间或达到一定数量的操作后，`DoCommit` 方法被调用。
9. **写入数据库:** `DoCommit` 方法将 Cookie 信息写入到 SQLite 数据库文件中。

在调试 Cookie 相关问题时，可以关注以下线索：

* **查看网络请求头:**  检查浏览器发送的请求头和接收的响应头中是否包含预期的 Cookie 信息。
* **查看浏览器开发者工具:**  使用浏览器开发者工具的 "Application" 或 "Storage" 选项卡，查看当前存储的 Cookie 信息，确认是否存在目标 Cookie，以及其属性是否正确。
* **检查 SQLite 数据库文件:**  可以使用 SQLite 数据库浏览器打开本地的 Cookie 数据库文件，查看 `cookies` 表中的数据，确认 Cookie 是否被正确写入。
* **查看 Chromium 日志:**  启用 Chromium 的网络日志，可以查看 Cookie 的加载和存储过程中的详细信息，例如 SQL 查询语句、错误信息等。

**当前代码段功能归纳 (第 2 部分):**

这段代码主要负责 `SQLitePersistentCookieStore::Backend` 在后台线程中**从 SQLite 数据库中异步加载 Cookie 数据**，并将其转换为 `CanonicalCookie` 对象。它采用了分批加载的策略，并处理了数据库 Schema 的迁移以及潜在的数据一致性问题。此外，它还包含了将 Cookie 添加、更新和删除操作添加到队列中进行批量处理的逻辑。

### 提示词
```
这是目录为net/extras/sqlite/sqlite_persistent_cookie_store.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
okies.swap(cookies_);
  }

  std::move(loaded_callback).Run(std::move(cookies));
}

bool SQLitePersistentCookieStore::Backend::CreateDatabaseSchema() {
  DCHECK(db());

  return db()->DoesTableExist("cookies") || CreateV24Schema(db());
}

bool SQLitePersistentCookieStore::Backend::DoInitializeDatabase() {
  DCHECK(db());

  // Retrieve all the domains
  sql::Statement smt(
      db()->GetUniqueStatement("SELECT DISTINCT host_key FROM cookies"));

  if (!smt.is_valid()) {
    Reset();
    return false;
  }

  std::vector<std::string> host_keys;
  while (smt.Step())
    host_keys.push_back(smt.ColumnString(0));

  // Build a map of domain keys (always eTLD+1) to domains.
  for (const auto& domain : host_keys) {
    std::string key = CookieMonster::GetKey(domain);
    keys_to_load_[key].insert(domain);
  }

  if (!restore_old_session_cookies_)
    DeleteSessionCookiesOnStartup();

  return true;
}

void SQLitePersistentCookieStore::Backend::ChainLoadCookies(
    LoadedCallback loaded_callback) {
  DCHECK(background_task_runner()->RunsTasksInCurrentSequence());

  bool load_success = true;

  if (!db()) {
    // Close() has been called on this store.
    load_success = false;
  } else if (keys_to_load_.size() > 0) {
    // Load cookies for the first domain key.
    auto it = keys_to_load_.begin();
    load_success = LoadCookiesForDomains(it->second);
    keys_to_load_.erase(it);
  }

  // If load is successful and there are more domain keys to be loaded,
  // then post a background task to continue chain-load;
  // Otherwise notify on client runner.
  if (load_success && keys_to_load_.size() > 0) {
    bool success = background_task_runner()->PostTask(
        FROM_HERE, base::BindOnce(&Backend::ChainLoadCookies, this,
                                  std::move(loaded_callback)));
    if (!success) {
      LOG(WARNING) << "Failed to post task from " << FROM_HERE.ToString()
                   << " to background_task_runner().";
    }
  } else {
    FinishedLoadingCookies(std::move(loaded_callback), load_success);
  }
}

bool SQLitePersistentCookieStore::Backend::LoadCookiesForDomains(
    const std::set<std::string>& domains) {
  DCHECK(background_task_runner()->RunsTasksInCurrentSequence());

  sql::Statement smt, delete_statement;
  if (restore_old_session_cookies_) {
    smt.Assign(db()->GetCachedStatement(
        SQL_FROM_HERE,
        "SELECT creation_utc, host_key, top_frame_site_key, name, value, path, "
        "expires_utc, is_secure, is_httponly, last_access_utc, has_expires, "
        "is_persistent, priority, encrypted_value, samesite, source_scheme, "
        "source_port, last_update_utc, source_type, has_cross_site_ancestor "
        "FROM cookies WHERE host_key "
        "= "
        "?"));
  } else {
    smt.Assign(db()->GetCachedStatement(
        SQL_FROM_HERE,
        "SELECT creation_utc, host_key, top_frame_site_key, name, value, path, "
        "expires_utc, is_secure, is_httponly, last_access_utc, has_expires, "
        "is_persistent, priority, encrypted_value, samesite, source_scheme, "
        "source_port, last_update_utc, source_type, has_cross_site_ancestor "
        "FROM cookies WHERE "
        "host_key = ? AND "
        "is_persistent = 1"));
  }
  delete_statement.Assign(db()->GetCachedStatement(
      SQL_FROM_HERE, "DELETE FROM cookies WHERE host_key = ?"));
  if (!smt.is_valid() || !delete_statement.is_valid()) {
    delete_statement.Clear();
    smt.Clear();  // Disconnect smt_ref from db_.
    Reset();
    return false;
  }

  std::vector<std::unique_ptr<CanonicalCookie>> cookies;
  std::unordered_set<std::string> top_frame_site_keys_to_delete;
  auto it = domains.begin();
  bool ok = true;
  for (; it != domains.end() && ok; ++it) {
    smt.BindString(0, *it);
    ok = MakeCookiesFromSQLStatement(cookies, smt,
                                     top_frame_site_keys_to_delete);
    smt.Reset(true);
  }

  DeleteTopFrameSiteKeys(std::move(top_frame_site_keys_to_delete));

  if (ok) {
    base::AutoLock locked(lock_);
    std::move(cookies.begin(), cookies.end(), std::back_inserter(cookies_));
  } else {
    // There were some cookies that were in database but could not be loaded
    // and handed over to CookieMonster. This is trouble since it means that
    // if some website tries to send them again, CookieMonster won't know to
    // issue a delete, and then the addition would violate the uniqueness
    // constraints and not go through.
    //
    // For data consistency, we drop the entire eTLD group.
    for (const std::string& domain : domains) {
      delete_statement.BindString(0, domain);
      if (!delete_statement.Run()) {
        // TODO(morlovich): Is something more drastic called for here?
        RecordCookieLoadProblem(CookieLoadProblem::KRecoveryFailed);
      }
      delete_statement.Reset(true);
    }
  }
  return true;
}

void SQLitePersistentCookieStore::Backend::DeleteTopFrameSiteKeys(
    const std::unordered_set<std::string>& top_frame_site_keys) {
  if (top_frame_site_keys.empty())
    return;

  sql::Statement delete_statement;
  delete_statement.Assign(db()->GetCachedStatement(
      SQL_FROM_HERE, "DELETE FROM cookies WHERE top_frame_site_key = ?"));
  if (!delete_statement.is_valid())
    return;

  for (const std::string& key : top_frame_site_keys) {
    delete_statement.BindString(0, key);
    if (!delete_statement.Run())
      RecordCookieLoadProblem(CookieLoadProblem::kDeleteCookiePartitionFailed);
    delete_statement.Reset(true);
  }
}

bool SQLitePersistentCookieStore::Backend::MakeCookiesFromSQLStatement(
    std::vector<std::unique_ptr<CanonicalCookie>>& cookies,
    sql::Statement& statement,
    std::unordered_set<std::string>& top_frame_site_keys_to_delete) {
  DCHECK(background_task_runner()->RunsTasksInCurrentSequence());
  bool ok = true;
  while (statement.Step()) {
    std::string domain = statement.ColumnString(1);
    std::string value = statement.ColumnString(4);
    std::string encrypted_value = statement.ColumnString(13);
    const bool encrypted_and_plaintext_values =
        !value.empty() && !encrypted_value.empty();
    UMA_HISTOGRAM_BOOLEAN("Cookie.EncryptedAndPlaintextValues",
                          encrypted_and_plaintext_values);

    // Ensure feature is fully activated for all users who load cookies, before
    // checking the validity of the row.
    if (base::FeatureList::IsEnabled(
            features::kEncryptedAndPlaintextValuesAreInvalid)) {
      if (encrypted_and_plaintext_values) {
        RecordCookieLoadProblem(
            CookieLoadProblem::kValuesExistInBothEncryptedAndPlaintext);
        ok = false;
        continue;
      }
    }

    if (!encrypted_value.empty()) {
      if (!crypto_) {
        RecordCookieLoadProblem(CookieLoadProblem::kNoCrypto);
        ok = false;
        continue;
      }
      bool decrypt_ok = crypto_->DecryptString(encrypted_value, &value);
      if (!decrypt_ok) {
        RecordCookieLoadProblem(CookieLoadProblem::kDecryptFailed);
        ok = false;
        continue;
      }
      std::string correct_hash = crypto::SHA256HashString(domain);
      if (!base::StartsWith(value, correct_hash,
                            base::CompareCase::SENSITIVE)) {
        RecordCookieLoadProblem(CookieLoadProblem::kHashFailed);
        ok = false;
        continue;
      }
      value = value.substr(correct_hash.length());
    }

    // If we can't create a CookiePartitionKey from SQL values, we delete any
    // cookie with the same top_frame_site_key value.
    base::expected<std::optional<CookiePartitionKey>, std::string>
        partition_key = CookiePartitionKey::FromStorage(
            statement.ColumnString(2), statement.ColumnBool(19));
    if (!partition_key.has_value()) {
      top_frame_site_keys_to_delete.insert(statement.ColumnString(2));
      continue;
    }
    // Returns nullptr if the resulting cookie is not canonical.
    std::unique_ptr<net::CanonicalCookie> cc = CanonicalCookie::FromStorage(
        /*name=*/statement.ColumnString(3),        //
        value,                                     //
        domain,                                    //
        /*path=*/statement.ColumnString(5),        //
        /*creation=*/statement.ColumnTime(0),      //
        /*expiration=*/statement.ColumnTime(6),    //
        /*last_access=*/statement.ColumnTime(9),   //
        /*last_update=*/statement.ColumnTime(17),  //
        /*secure=*/statement.ColumnBool(7),        //
        /*httponly=*/statement.ColumnBool(8),      //
                                                   /*same_site=*/
        DBCookieSameSiteToCookieSameSite(
            static_cast<DBCookieSameSite>(statement.ColumnInt(14))),  //
        /*priority=*/
        DBCookiePriorityToCookiePriority(
            static_cast<DBCookiePriority>(statement.ColumnInt(12))),        //
        /*partition_key=*/std::move(partition_key.value()),                 //
        /*source_scheme=*/DBToCookieSourceScheme(statement.ColumnInt(15)),  //
        /*source_port=*/statement.ColumnInt(16),                            //
        /*source_type=*/
        DBCookieSourceTypeToCookieSourceType(
            static_cast<DBCookieSourceType>(statement.ColumnInt(18))));  //
    if (cc) {
      DLOG_IF(WARNING, cc->CreationDate() > Time::Now())
          << "CreationDate too recent";
      if (!cc->LastUpdateDate().is_null()) {
        DLOG_IF(WARNING, cc->LastUpdateDate() > Time::Now())
            << "LastUpdateDate too recent";
        // In order to anticipate the potential effects of the expiry limit in
        // rfc6265bis, we need to check how long it's been since the cookie was
        // refreshed (if LastUpdateDate is populated). We use 100 buckets for
        // the highest reasonable granularity, set 1 day as the minimum and
        // don't track over a 400 max (since these cookies will expire anyway).
        UMA_HISTOGRAM_CUSTOM_COUNTS(
            "Cookie.DaysSinceRefreshForRetrieval",
            (base::Time::Now() - cc->LastUpdateDate()).InDays(), 1, 400, 100);
      }
      HistogramCookieAge(*cc);
      cookies.push_back(std::move(cc));
    } else {
      RecordCookieLoadProblem(CookieLoadProblem::kNotCanonical);
      ok = false;
    }
  }

  return ok;
}

std::optional<int>
SQLitePersistentCookieStore::Backend::DoMigrateDatabaseSchema() {
  int cur_version = meta_table()->GetVersionNumber();

  if (cur_version == 18) {
    SCOPED_UMA_HISTOGRAM_TIMER("Cookie.TimeDatabaseMigrationToV19");

    sql::Statement update_statement(
        db()->GetCachedStatement(SQL_FROM_HERE,
                                 "UPDATE cookies SET expires_utc = ? WHERE "
                                 "has_expires = 1 AND expires_utc > ?"));
    if (!update_statement.is_valid()) {
      return std::nullopt;
    }

    sql::Transaction transaction(db());
    if (!transaction.Begin()) {
      return std::nullopt;
    }

    base::Time expires_cap = base::Time::Now() + base::Days(400);
    update_statement.BindTime(0, expires_cap);
    update_statement.BindTime(1, expires_cap);
    if (!update_statement.Run()) {
      return std::nullopt;
    }

    ++cur_version;
    if (!meta_table()->SetVersionNumber(cur_version) ||
        !meta_table()->SetCompatibleVersionNumber(
            std::min(cur_version, kCompatibleVersionNumber)) ||
        !transaction.Commit()) {
      return std::nullopt;
    }
  }

  if (cur_version == 19) {
    SCOPED_UMA_HISTOGRAM_TIMER("Cookie.TimeDatabaseMigrationToV20");

    sql::Transaction transaction(db());
    if (!transaction.Begin()) {
      return std::nullopt;
    }

    if (!db()->Execute("DROP TABLE IF EXISTS cookies_old")) {
      return std::nullopt;
    }
    if (!db()->Execute("ALTER TABLE cookies RENAME TO cookies_old")) {
      return std::nullopt;
    }
    if (!db()->Execute("DROP INDEX IF EXISTS cookies_unique_index")) {
      return std::nullopt;
    }

    if (!CreateV20Schema(db())) {
      return std::nullopt;
    }

    static constexpr char insert_cookies_sql[] =
        "INSERT OR REPLACE INTO cookies "
        "(creation_utc, host_key, top_frame_site_key, name, value, "
        "encrypted_value, path, expires_utc, is_secure, is_httponly, "
        "last_access_utc, has_expires, is_persistent, priority, samesite, "
        "source_scheme, source_port, is_same_party, last_update_utc) "
        "SELECT creation_utc, host_key, top_frame_site_key, name, value,"
        "       encrypted_value, path, expires_utc, is_secure, is_httponly,"
        "       last_access_utc, has_expires, is_persistent, priority, "
        "       samesite, source_scheme, source_port, is_same_party, "
        "last_update_utc "
        "FROM cookies_old ORDER BY creation_utc ASC";
    if (!db()->Execute(insert_cookies_sql)) {
      return std::nullopt;
    }
    if (!db()->Execute("DROP TABLE cookies_old")) {
      return std::nullopt;
    }

    ++cur_version;
    if (!meta_table()->SetVersionNumber(cur_version) ||
        !meta_table()->SetCompatibleVersionNumber(
            std::min(cur_version, kCompatibleVersionNumber)) ||
        !transaction.Commit()) {
      return std::nullopt;
    }
  }

  if (cur_version == 20) {
    SCOPED_UMA_HISTOGRAM_TIMER("Cookie.TimeDatabaseMigrationToV21");

    sql::Transaction transaction(db());
    if (!transaction.Begin()) {
      return std::nullopt;
    }

    if (!db()->Execute("DROP TABLE IF EXISTS cookies_old")) {
      return std::nullopt;
    }
    if (!db()->Execute("ALTER TABLE cookies RENAME TO cookies_old")) {
      return std::nullopt;
    }
    if (!db()->Execute("DROP INDEX IF EXISTS cookies_unique_index")) {
      return std::nullopt;
    }

    if (!CreateV21Schema(db())) {
      return std::nullopt;
    }

    static constexpr char insert_cookies_sql[] =
        "INSERT OR REPLACE INTO cookies "
        "(creation_utc, host_key, top_frame_site_key, name, value, "
        "encrypted_value, path, expires_utc, is_secure, is_httponly, "
        "last_access_utc, has_expires, is_persistent, priority, samesite, "
        "source_scheme, source_port, last_update_utc) "
        "SELECT creation_utc, host_key, top_frame_site_key, name, value,"
        "       encrypted_value, path, expires_utc, is_secure, is_httponly,"
        "       last_access_utc, has_expires, is_persistent, priority, "
        "       samesite, source_scheme, source_port, last_update_utc "
        "FROM cookies_old ORDER BY creation_utc ASC";
    if (!db()->Execute(insert_cookies_sql)) {
      return std::nullopt;
    }
    if (!db()->Execute("DROP TABLE cookies_old")) {
      return std::nullopt;
    }

    ++cur_version;
    if (!meta_table()->SetVersionNumber(cur_version) ||
        !meta_table()->SetCompatibleVersionNumber(
            std::min(cur_version, kCompatibleVersionNumber)) ||
        !transaction.Commit()) {
      return std::nullopt;
    }
  }

  if (cur_version == 21) {
    SCOPED_UMA_HISTOGRAM_TIMER("Cookie.TimeDatabaseMigrationToV22");

    sql::Transaction transaction(db());
    if (!transaction.Begin()) {
      return std::nullopt;
    }

    if (!db()->Execute("DROP TABLE IF EXISTS cookies_old")) {
      return std::nullopt;
    }
    if (!db()->Execute("ALTER TABLE cookies RENAME TO cookies_old")) {
      return std::nullopt;
    }
    if (!db()->Execute("DROP INDEX IF EXISTS cookies_unique_index")) {
      return std::nullopt;
    }

    if (!CreateV22Schema(db())) {
      return std::nullopt;
    }

    // The default `source_type` is 0 which is CookieSourceType::kUnknown.
    static constexpr char insert_cookies_sql[] =
        "INSERT OR REPLACE INTO cookies "
        "(creation_utc, host_key, top_frame_site_key, name, value, "
        "encrypted_value, path, expires_utc, is_secure, is_httponly, "
        "last_access_utc, has_expires, is_persistent, priority, samesite, "
        "source_scheme, source_port, last_update_utc, source_type) "
        "SELECT creation_utc, host_key, top_frame_site_key, name, value,"
        "       encrypted_value, path, expires_utc, is_secure, is_httponly,"
        "       last_access_utc, has_expires, is_persistent, priority, "
        "       samesite, source_scheme, source_port, last_update_utc, 0 "
        "FROM cookies_old ORDER BY creation_utc ASC";
    if (!db()->Execute(insert_cookies_sql)) {
      return std::nullopt;
    }
    if (!db()->Execute("DROP TABLE cookies_old")) {
      return std::nullopt;
    }

    ++cur_version;
    if (!meta_table()->SetVersionNumber(cur_version) ||
        !meta_table()->SetCompatibleVersionNumber(
            std::min(cur_version, kCompatibleVersionNumber)) ||
        !transaction.Commit()) {
      return std::nullopt;
    }
  }

  if (cur_version == 22) {
    SCOPED_UMA_HISTOGRAM_TIMER("Cookie.TimeDatabaseMigrationToV23");
    sql::Transaction transaction(db());
    if (!transaction.Begin()) {
      return std::nullopt;
    }

    if (!db()->Execute("DROP TABLE IF EXISTS cookies_old")) {
      return std::nullopt;
    }
    if (!db()->Execute("ALTER TABLE cookies RENAME TO cookies_old")) {
      return std::nullopt;
    }
    if (!db()->Execute("DROP INDEX IF EXISTS cookies_unique_index")) {
      return std::nullopt;
    }

    if (!CreateV23Schema(db())) {
      return std::nullopt;
    }
    /*
     For the case statement setting source_scheme,
     value of 0 reflects int value of CookieSourceScheme::kUnset
     value of 2 reflects int value of CookieSourceScheme::kSecure

     For the case statement setting has_cross_site_ancestor, it has the
     potential to have a origin mismatch due to substring operations.
      EX: the domain ample.com will appear as a substring of the domain
      example.com even though they are different origins.
     We are ok with this because the other elements of the UNIQUE INDEX
     will always be different preventing accidental access.
    */

    static constexpr char insert_cookies_sql[] =
        "INSERT OR REPLACE INTO cookies "
        "(creation_utc, host_key, top_frame_site_key, name, value, "
        "encrypted_value, path, expires_utc, is_secure, is_httponly, "
        "last_access_utc, has_expires, is_persistent, priority, samesite, "
        "source_scheme, source_port, last_update_utc, source_type, "
        "has_cross_site_ancestor) "
        "SELECT creation_utc, host_key, top_frame_site_key, name, value,"
        "       encrypted_value, path, expires_utc, is_secure, is_httponly,"
        "       last_access_utc, has_expires, is_persistent, priority, "
        "       samesite, "
        "       CASE WHEN source_scheme = 0 AND is_secure = 1 "
        "           THEN 2 ELSE source_scheme END, "
        "       source_port, last_update_utc, source_type, "
        "       CASE WHEN INSTR(top_frame_site_key, '://') > 0 AND host_key "
        "           LIKE CONCAT('%', SUBSTR(top_frame_site_key, "
        "           INSTR(top_frame_site_key,'://') + 3),  '%') "
        "           THEN 0 ELSE 1 "
        "           END AS has_cross_site_ancestor "
        "FROM cookies_old ORDER BY creation_utc ASC";
    if (!db()->Execute(insert_cookies_sql)) {
      return std::nullopt;
    }
    if (!db()->Execute("DROP TABLE cookies_old")) {
      return std::nullopt;
    }

    ++cur_version;
    if (!meta_table()->SetVersionNumber(cur_version) ||
        !meta_table()->SetCompatibleVersionNumber(
            std::min(cur_version, kCompatibleVersionNumber)) ||
        !transaction.Commit()) {
      return std::nullopt;
    }
  }

  if (cur_version == 23) {
    SCOPED_UMA_HISTOGRAM_TIMER("Cookie.TimeDatabaseMigrationToV24");
    sql::Transaction transaction(db());
    if (!transaction.Begin()) {
      return std::nullopt;
    }

    if (crypto_) {
      sql::Statement select_smt, update_smt;

      select_smt.Assign(db()->GetCachedStatement(
          SQL_FROM_HERE,
          "SELECT rowid, host_key, encrypted_value, value FROM cookies"));

      update_smt.Assign(db()->GetCachedStatement(
          SQL_FROM_HERE,
          "UPDATE cookies SET encrypted_value=?, value=? WHERE "
          "rowid=?"));

      if (!select_smt.is_valid() || !update_smt.is_valid()) {
        return std::nullopt;
      }

      std::map<int64_t, std::string> encrypted_values;

      while (select_smt.Step()) {
        int64_t rowid = select_smt.ColumnInt64(0);
        std::string domain = select_smt.ColumnString(1);
        std::string encrypted_value = select_smt.ColumnString(2);
        std::string value = select_smt.ColumnString(3);
        // If encrypted value is empty but value is non-empty it means that in a
        // previous version of the database, there was no crypto and the value
        // was stored unencrypted. In this case, since we have crypto now, we
        // should encrypt the value.
        // In the case that both plaintext and encrypted values exist, the
        // encrypted value always takes precedence.
        std::string decrypted_value;
        if (encrypted_value.empty() && !value.empty()) {
          decrypted_value = value;
        } else {
          if (!crypto_->DecryptString(encrypted_value, &decrypted_value)) {
            RecordCookieLoadProblem(CookieLoadProblem::kDecryptFailed);
            continue;
          }
        }
        std::string new_encrypted_value;

        if (!crypto_->EncryptString(
                base::StrCat(
                    {crypto::SHA256HashString(domain), decrypted_value}),
                &new_encrypted_value)) {
          RecordCookieCommitProblem(CookieCommitProblem::kEncryptFailed);
          continue;
        }
        encrypted_values[rowid] = new_encrypted_value;
      }

      for (const auto& entry : encrypted_values) {
        update_smt.Reset(true);
        update_smt.BindString(/*encrypted_value*/ 0, entry.second);
        // Clear the value, since it is now encrypted.
        update_smt.BindString(/*value*/ 1, {});
        update_smt.BindInt64(/*rowid*/ 2, entry.first);
        if (!update_smt.Run()) {
          return std::nullopt;
        }
      }
    }

    ++cur_version;
    if (!meta_table()->SetVersionNumber(cur_version) ||
        !meta_table()->SetCompatibleVersionNumber(
            std::min(cur_version, kCompatibleVersionNumber)) ||
        !transaction.Commit()) {
      return std::nullopt;
    }
  }

  // Put future migration cases here.
  return std::make_optional(cur_version);
}

void SQLitePersistentCookieStore::Backend::AddCookie(
    const CanonicalCookie& cc) {
  BatchOperation(PendingOperation::COOKIE_ADD, cc);
}

void SQLitePersistentCookieStore::Backend::UpdateCookieAccessTime(
    const CanonicalCookie& cc) {
  BatchOperation(PendingOperation::COOKIE_UPDATEACCESS, cc);
}

void SQLitePersistentCookieStore::Backend::DeleteCookie(
    const CanonicalCookie& cc) {
  BatchOperation(PendingOperation::COOKIE_DELETE, cc);
}

void SQLitePersistentCookieStore::Backend::BatchOperation(
    PendingOperation::OperationType op,
    const CanonicalCookie& cc) {
  // Commit every 30 seconds.
  constexpr base::TimeDelta kCommitInterval = base::Seconds(30);
  // Commit right away if we have more than 512 outstanding operations.
  constexpr size_t kCommitAfterBatchSize = 512;
  DCHECK(!background_task_runner()->RunsTasksInCurrentSequence());

  // We do a full copy of the cookie here, and hopefully just here.
  auto po = std::make_unique<PendingOperation>(op, cc);

  PendingOperationsMap::size_type num_pending;
  {
    base::AutoLock locked(lock_);
    // When queueing the operation, see if it overwrites any already pending
    // ones for the same row.
    auto key = cc.StrictlyUniqueKey();
    auto iter_and_result = pending_.emplace(key, PendingOperationsForKey());
    PendingOperationsForKey& ops_for_key = iter_and_result.first->second;
    if (!iter_and_result.second) {
      // Insert failed -> already have ops.
      if (po->op() == PendingOperation::COOKIE_DELETE) {
        // A delete op makes all the previous ones irrelevant.
        ops_for_key.clear();
      } else if (po->op() == PendingOperation::COOKIE_UPDATEACCESS) {
        if (!ops_for_key.empty() &&
            ops_for_key.back()->op() == PendingOperation::COOKIE_UPDATEACCESS) {
          // If access timestamp is updated twice in a row, can dump the earlier
          // one.
          ops_for_key.pop_back();
        }
        // At most delete + add before (and no access time updates after above
        // conditional).
        DCHECK_LE(ops_for_key.size(), 2u);
      } else {
        // Nothing special is done for adds, since if they're overwriting,
        // they'll be preceded by deletes anyway.
        DCHECK_LE(ops_for_key.size(), 1u);
      }
    }
    ops_for_key.push_back(std::move(po));
    // Note that num_pending_ counts number of calls to BatchOperation(), not
    // the current length of the queue; this is intentional to guarantee
    // progress, as the length of the queue may decrease in some cases.
    num_pending = ++num_pending_;
  }

  if (num_pending == 1) {
    // We've gotten our first entry for this batch, fire off the timer.
    if (!background_task_runner()->PostDelayedTask(
            FROM_HERE, base::BindOnce(&Backend::Commit, this),
            kCommitInterval)) {
      DUMP_WILL_BE_NOTREACHED() << "background_task_runner() is not running.";
    }
  } else if (num_pending == kCommitAfterBatchSize) {
    // We've reached a big enough batch, fire off a commit now.
    PostBackgroundTask(FROM_HERE, base::BindOnce(&Backend::Commit, this));
  }
}

void SQLitePersistentCookieStore::Backend::DoCommit() {
  DCHECK(background_task_runner()->RunsTasksInCurrentSequence());

  PendingOperationsMap ops;
  {
    base::AutoLock locked(lock_);
    pending_.swap(ops);
    num_pending_ = 0;
  }

  // Maybe an old timer fired or we are already Close()'ed.
  if (!db() || ops.empty())
    return;

  sql::Statement add_statement(db()->GetCachedStatement(
      SQL_FROM_HERE,
      "INSERT INTO cookies (creation_utc, host_key, top_frame_site_key, name, "
      "value, encrypted_value, path, expires_utc, is_secure, is_httponly, "
      "last_access_utc, has_expires, is_persistent, priority, samesite, "
      "source_scheme, source_port, last_update_utc, source_type, "
      "has_cross_site_ancestor) "
      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"));
  if (!add_statement.is_valid())
    return;

  sql::Statement update_access_statement(db()->GetCachedStatement(
      SQL_FROM_HERE,
      "UPDATE cookies SET last_access_utc=? WHERE "
      "name=? AND host_key=? AND top_frame_site_key=? AND path=? AND "
      "source_scheme=? AND source_port=? AND has_cross_site_ancestor=?"));
  if (!update_access_statement.is_valid())
    return;

  sql::Statement delete_statement(db()->GetCachedStatement(
      SQL_FROM_HERE,
      "DELETE FROM cookies WHERE "
      "name=? AND host_key=? AND top_frame_site_key=? AND path=? AND "
      "source_scheme=? AND source_port=? AND has_cross_site_ancestor=?"));
  if (!delete_statement.is_valid())
    return;

  sql::Transaction transaction(db());
  if (!transaction.Begin())
    return;

  for (auto& kv : ops) {
    for (std::unique_ptr<PendingOperation>& po_entry : kv.second) {
      // Free the cookies as we commit them to the database.
      std::unique_ptr<PendingOperation> po(std::move(po_entry));
      base::expected<CookiePartitionKey::SerializedCookiePartitionKey,
                     std::string>
          serialized_partition_key =
              CookiePartitionKey::Serialize(po->cc().PartitionKey());
      if (!serialized_partition_key.has_value()) {
        continue;
      }

      switch (po->op()) {
        case PendingOperation::COOKIE_ADD:
          add_statement.Reset(true);
          add_statement.BindTime(0, po->cc().CreationDate());
          add_statement.BindString(1, po->cc().Domain());
          add_statement.BindString(2, serialized_partition_key->TopLevelSite());
          add_statement.BindString(3, po->cc().Name());
          if (crypto_) {
            std::string encrypted_value;
            if (!crypto_->EncryptString(
                    base::StrCat({crypto::SHA256HashString(po->cc().Domain()),
                                  po->cc().Value()}),
                    &encrypted_value)) {
              DLOG(WARNING) << "Could not encrypt a cookie, skipping add.";
              RecordCookieCommitProblem(CookieCommitProblem::kEncryptFailed);
              continue;
            }
            add_statement.BindCString(4, "");  // value
            // BindBlob() immediately makes an internal copy of the data.
            add_statement.BindBlob(5, encrypted_value);
          } else {
            add_statement.BindString(4, po->cc().Value());
            add_statement.BindBlob(5,
                                   base::span<uint8_t>());  // encrypted_value
          }
          add_statement.BindString(6, po->cc().Path());
          add_statement.BindTime(7, po->cc().ExpiryDate());
          add_statement.BindBool(8, po->cc().SecureAttribute());
          add_statement.BindBool(9, po->cc().IsHttpOnly());
          add_statement.BindTime(10, po->cc().LastAccessDate());
          add_statement.BindBool(11, po->cc().IsPersistent());
          add_statement.BindBool(12, po->cc().IsPersistent());
          add_statement.BindInt(
              13, CookiePriorityToDBCookiePriority(po->cc().Priority()));
          add_statement.BindInt(
              14, CookieSameSiteToDBCookieSameSite(po->cc().SameSite()));
          add_statement.BindInt(15, static_cast<int>(po->cc().SourceScheme()));
          add_statement.BindInt(16, po->cc().SourcePort());
          add_statement.BindTime(17, po->cc().LastUpdateDate());
          add_statement.BindInt(
              18, CookieSourceTypeToDBCookieSourceType(po->cc().SourceType()));
          add_statement.BindBool(
              19, serialized_partition_key->has_cross_site_ancestor());

          if (!add_statement.Run()) {
            DLOG(WARNING) << "Could not add a cookie to the DB.";
            RecordCookieCommitProblem(CookieCommitProblem::kAdd);
          }
          break;

        case PendingOperation::COOKIE_UPDATEACCESS:
          update_access_statement.Reset(true);
          update_access_statement.BindTime(0, po->cc().LastAccessDate());
          update_access_statement.BindString(1, po->cc().Name());
          update_access_statement.BindString(2, po->cc().Domain());
          update_access_statement.BindString(
              3, serialized_partition_key->TopLevelSite());
          update_access_statement.BindString(4, po->cc().Path());
          update_access_statement.BindInt(
              5, static_cast<int>(po->cc().SourceScheme()));
          update_access_statement.BindInt(6, po->cc().SourcePort());
          update_access_statement.BindBool(
              7, serialized_partition_key->has_cross_site_ancestor());
          if (!update_access_statement.Run()) {
            DLOG(WARNING)
                << "Could not update cookie last access time in the DB.";
            RecordCookieCommitProblem(CookieCommitProblem::kUpdateAccess);
          }
          break;

        case PendingOperation::COOKIE_DELETE:
          delete_statement.Reset(true);
          delete_statement.BindString(0, po->cc().Name());
          delete_statement.BindString(1, po->cc().Domain());
          delete_statement.BindString(2,
                                      serialized_partition_key->TopLevelSite());
          delete_statement.BindString(3, po->cc().Path());
          delete_statement.BindInt(4,
                                   static_cast<int>(po->cc().SourceScheme()));
          delete_statement.BindInt(5, po->cc().SourcePort());
          delete_statement.BindBool(
              6, serialized_partition_key->has_cross_site_ancestor());
          if (!delete_statement.Run()) {
            DLOG(WARNING) << "Could not delete a cookie from the DB.";
            RecordCookieCommitProblem(CookieCommitProblem::kDelete);
          }
          break;

        default:
          NOTREACHED();
      }
    }
  }
  bool commit_ok = transaction.Commit();
  if (!commit_ok) {
    RecordCookieCommitProblem(CookieCommitProblem::kTransactionCommit);
  }
}

size_t SQLitePersistentCookieStore::Backend::GetQueueLengthForTesting() {
  DCHECK(client_task_runner()->RunsTasksInCurrentSequence());
  size_t total = 0u;
  {
    base::AutoLock locked(lock_);
    for (const auto& key_val : pending_) {
      total += key_val.second.size();
    }
  }
  return total;
}

void SQLitePersistentCookieStore::Backend::DeleteAllInList(
    const std::list<CookieOrigin>& cookies) {
  if (cookies.empty())
    return;

  if (background_task_runner()->RunsTasksInCurrentSequence()) {
    BackgroundDeleteAllInList(cookies);
  } else {
    // Perform deletion on background t
```