Response:
The user wants a summary of the provided C++ code snippet from Chromium's network stack.
The code defines functions for creating and populating SQLite database schemas for storing cookies, specifically focusing on database version migrations.

I need to:
1. **Identify the main purpose** of the code.
2. **Explain the functionality** of the defined functions (e.g., `CreateV22Schema`, `AddV23CookiesToDB`).
3. **Check for relationships with JavaScript**. This is unlikely given the nature of the code, but I need to confirm.
4. **Analyze for logical reasoning** and provide hypothetical inputs/outputs if present. The schema creation involves some implicit logic.
5. **Identify common user/programming errors** related to this code. This will likely involve database manipulation.
6. **Describe how a user might reach this code**, focusing on debugging scenarios.
7. **Summarize the functionality** as requested for "Part 3".
这是对 Chromium 网络栈中 `net/extras/sqlite/sqlite_persistent_cookie_store_unittest.cc` 文件中一部分代码的功能归纳。这段代码主要关注 **SQLite 数据库模式的创建和数据迁移，用于测试持久化存储 Cookie 的功能**。

**具体功能归纳:**

1. **定义了多个版本的 SQLite 数据库模式 (`CreateV22Schema`, `CreateV23Schema`)：** 这些函数定义了不同版本 Cookie 数据库的表结构（`cookies` 表）。每个版本可能包含不同的列，例如，V23 版本相较于 V22 版本增加了 `has_cross_site_ancestor` 列。
2. **定义了获取当前数据库版本号的函数 (`GetDBCurrentVersionNumber`)：**  该函数查询 `meta` 表中的 `version` 键的值，以确定当前数据库的版本。
3. **定义了用于迁移测试的示例 Cookie 数据 (`CookiesForMigrationTest`)：**  该函数创建了一组 `CanonicalCookie` 对象，用于在不同数据库版本之间进行迁移测试。这些 Cookie 具有不同的属性，如域名、路径、过期时间等。
4. **定义了向不同版本数据库添加 Cookie 数据的函数 (`AddV18CookiesToDB`, `AddV20CookiesToDB`, `AddV21CookiesToDB`, `AddV22CookiesToDB`, `AddV23CookiesToDB`)：** 这些函数使用预定义的 SQL `INSERT` 语句将示例 Cookie 数据添加到指定版本的数据库中。这些函数会根据数据库版本和 Cookie 的属性进行数据绑定。例如，在较新的版本中，可能会对 Cookie 的值进行加密。
5. **定义了在迁移后验证 Cookie 数据的函数 (`ConfirmCookiesAfterMigrationTest`)：** 该函数用于检查从数据库中读取的 Cookie 数据是否与预期的一致，验证迁移过程的正确性。它会比较 Cookie 的各个属性。
6. **定义了在迁移后验证数据库版本的函数 (`ConfirmDatabaseVersionAfterMigration`)：**  该函数打开数据库并检查其版本号是否已成功更新到预期版本。

**与 JavaScript 的关系：**

这段 C++ 代码本身不直接与 JavaScript 代码交互。它的功能是管理浏览器内部的 Cookie 存储。然而，JavaScript 可以通过 `document.cookie` API 来读取、设置和修改 Cookie。

**举例说明：**

当 JavaScript 代码执行 `document.cookie = "mycookie=myvalue"` 时，浏览器网络栈最终会将这个 Cookie 的信息（域名、路径、值、过期时间等）传递给 C++ 代码，并由 `SQLitePersistentCookieStore` 使用这里定义的数据库模式和函数将其存储到 SQLite 数据库中。

**逻辑推理与假设输入输出：**

**假设输入：** 一个使用旧版本（例如 V22）数据库模式的 Cookie 数据库文件。

**执行的操作：** 启动 Chromium 浏览器，并且浏览器需要访问存储在该数据库中的 Cookie。

**逻辑推理：** `SQLitePersistentCookieStore` 会检测到数据库版本较低，并尝试将其升级到最新版本（例如 V24）。升级过程可能涉及执行 `CreateV23Schema` 等函数来创建新的表结构，并使用 `AddV23CookiesToDB` 等函数将旧数据迁移到新结构中。

**预期输出：**  数据库结构被更新到 V23 或更高版本，并且旧的 Cookie 数据被成功迁移到新表中。`GetDBCurrentVersionNumber` 函数将返回新的版本号。`ConfirmCookiesAfterMigrationTest` 将验证迁移后的 Cookie 数据是否正确。

**用户或编程常见的使用错误：**

1. **手动修改数据库文件：** 用户或恶意软件可能直接编辑 SQLite 数据库文件，导致数据损坏或不一致。例如，错误地修改了 `meta` 表中的版本号，或者修改了 `cookies` 表中的某些字段类型或约束，这会导致程序在尝试读取或写入 Cookie 时崩溃或产生不可预测的行为。
    * **例子：**  用户使用 SQLite 工具将 `cookies` 表中的某个 `INTEGER NOT NULL` 列的值设置为了 `NULL`。当 Chromium 尝试读取该 Cookie 时，SQL 查询会失败。
2. **数据库文件权限问题：** 如果运行 Chromium 的用户没有足够的权限读取或写入 Cookie 数据库文件，会导致 Cookie 存储功能失效。
    * **例子：**  在 Linux 系统上，Cookie 数据库文件的权限被设置为只有 `root` 用户才能访问，导致普通用户运行的 Chromium 无法存储或读取 Cookie。
3. **数据库损坏：**  由于磁盘错误、电源故障等原因，SQLite 数据库文件可能会损坏，导致 Cookie 数据丢失或无法访问。
    * **例子：**  突然断电导致数据库写入操作中断，可能导致数据库文件中的数据页损坏。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户浏览网页：**  用户访问一个网站，该网站设置了一些 Cookie。
2. **浏览器接收 Cookie：** 浏览器接收到来自服务器的 `Set-Cookie` 响应头。
3. **Cookie 入队待存储：** 浏览器网络栈将接收到的 Cookie 对象添加到待持久化存储的队列中。
4. **`SQLitePersistentCookieStore::PersistCookie()` 被调用：**  `SQLitePersistentCookieStore` 类的 `PersistCookie()` 方法被调用，负责将 Cookie 写入数据库。
5. **数据库操作：** `PersistCookie()` 方法会使用 SQL 语句（例如 `INSERT` 或 `REPLACE`）将 Cookie 信息写入到 `cookies` 表中。
6. **数据库升级（如果需要）：** 如果当前数据库的版本低于最新版本，`SQLitePersistentCookieStore` 会执行升级逻辑，调用如 `CreateV23Schema` 和 `AddV23CookiesToDB` 这样的函数。

**作为调试线索，如果发现 Cookie 存储出现问题，例如：**

* 用户设置的 Cookie 没有被保存。
* 浏览器启动后 Cookie 丢失。
* 浏览器行为异常，可能与 Cookie 相关。

开发者可能会查看 `net/extras/sqlite/sqlite_persistent_cookie_store_unittest.cc` 这样的测试文件，来理解 Cookie 存储的内部逻辑，特别是数据库模式的定义和迁移过程，以便：

* **验证数据库模式是否正确：** 检查表结构和索引是否符合预期。
* **模拟数据迁移过程：** 使用测试用例模拟从旧版本数据库迁移到新版本的场景，排查迁移过程中的错误。
* **分析 SQL 查询：**  理解用于读取和写入 Cookie 的 SQL 语句，排查 SQL 语句中的逻辑错误。
* **检查错误处理逻辑：**  查看代码中处理数据库错误的逻辑，例如数据库打开失败、SQL 执行失败等。

**总结 Part 3 的功能：**

Part 3 的代码主要负责 **定义和创建不同版本的 SQLite 数据库模式，用于存储 Cookie 数据，并提供了一些辅助函数用于添加示例数据、获取数据库版本以及验证数据迁移的正确性**。 这部分代码是 `SQLitePersistentCookieStore` 的核心组成部分，确保了 Cookie 数据能够可靠地持久化存储，并在浏览器版本升级时能够正确地迁移数据。

### 提示词
```
这是目录为net/extras/sqlite/sqlite_persistent_cookie_store_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
22Schema(sql::Database* db) {
  sql::MetaTable meta_table;
  if (!meta_table.Init(db, 22, 22)) {
    return false;
  }

  // Version 22 schema
  static constexpr char kCreateSql[] =
      "CREATE TABLE cookies("
      "creation_utc INTEGER NOT NULL,"
      "host_key TEXT NOT NULL,"
      "top_frame_site_key TEXT NOT NULL,"
      "name TEXT NOT NULL,"
      "value TEXT NOT NULL,"
      "encrypted_value BLOB NOT NULL,"
      "path TEXT NOT NULL,"
      "expires_utc INTEGER NOT NULL,"
      "is_secure INTEGER NOT NULL,"
      "is_httponly INTEGER NOT NULL,"
      "last_access_utc INTEGER NOT NULL,"
      "has_expires INTEGER NOT NULL,"
      "is_persistent INTEGER NOT NULL,"
      "priority INTEGER NOT NULL,"
      "samesite INTEGER NOT NULL,"
      "source_scheme INTEGER NOT NULL,"
      "source_port INTEGER NOT NULL,"
      "last_update_utc INTEGER NOT NULL,"
      "source_type INTEGER NOT NULL,"
      "UNIQUE (host_key, top_frame_site_key, name, path, source_scheme, "
      "source_port))";

  static constexpr char kCreateIndexSql[] =
      "CREATE UNIQUE INDEX cookies_unique_index "
      "ON cookies(host_key, top_frame_site_key, name, path, source_scheme, "
      "source_port)";

  return db->Execute(kCreateSql) && db->Execute(kCreateIndexSql);
}

bool CreateV23Schema(sql::Database* db) {
  sql::MetaTable meta_table;
  if (!meta_table.Init(db, 23, 23)) {
    return false;
  }

  // Version 23 schema
  static constexpr char kCreateSql[] =
      "CREATE TABLE cookies("
      "creation_utc INTEGER NOT NULL,"
      "host_key TEXT NOT NULL,"
      "top_frame_site_key TEXT NOT NULL,"
      "name TEXT NOT NULL,"
      "value TEXT NOT NULL,"
      "encrypted_value BLOB NOT NULL,"
      "path TEXT NOT NULL,"
      "expires_utc INTEGER NOT NULL,"
      "is_secure INTEGER NOT NULL,"
      "is_httponly INTEGER NOT NULL,"
      "last_access_utc INTEGER NOT NULL,"
      "has_expires INTEGER NOT NULL,"
      "is_persistent INTEGER NOT NULL,"
      "priority INTEGER NOT NULL,"
      "samesite INTEGER NOT NULL,"
      "source_scheme INTEGER NOT NULL,"
      "source_port INTEGER NOT NULL,"
      "last_update_utc INTEGER NOT NULL,"
      "source_type INTEGER NOT NULL,"
      "has_cross_site_ancestor INTEGER NOT NULL);";

  static constexpr char kCreateIndexSql[] =
      "CREATE UNIQUE INDEX cookies_unique_index "
      "ON cookies(host_key, top_frame_site_key, has_cross_site_ancestor, "
      "name, path, source_scheme, source_port)";

  return db->Execute(kCreateSql) && db->Execute(kCreateIndexSql);
}

int GetDBCurrentVersionNumber(sql::Database* db) {
  static constexpr char kGetDBCurrentVersionQuery[] =
      "SELECT value FROM meta WHERE key='version'";
  sql::Statement statement(db->GetUniqueStatement(kGetDBCurrentVersionQuery));
  statement.Step();
  return statement.ColumnInt(0);
}

std::vector<CanonicalCookie> CookiesForMigrationTest() {
  const base::Time now = base::Time::Now();

  std::vector<CanonicalCookie> cookies;
  cookies.push_back(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "B", "example.com", "/", /*creation=*/now, /*expiration=*/now,
      /*last_access=*/now, /*last_update=*/now, /*secure=*/true,
      /*httponly=*/false, CookieSameSite::UNSPECIFIED,
      COOKIE_PRIORITY_DEFAULT));
  cookies.push_back(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "C", "B", "example.com", "/", /*creation=*/now, /*expiration=*/now,
      /*last_access=*/now, /*last_update=*/now, /*secure=*/true,
      /*httponly=*/false, CookieSameSite::UNSPECIFIED,
      COOKIE_PRIORITY_DEFAULT));
  cookies.push_back(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "B", "example2.com", "/", /*creation=*/now, /*expiration=*/now,
      /*last_access=*/now, /*last_update=*/now, /*secure=*/true,
      /*httponly=*/false, CookieSameSite::UNSPECIFIED,
      COOKIE_PRIORITY_DEFAULT));
  cookies.push_back(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "C", "B", "example2.com", "/", /*creation=*/now,
      /*expiration=*/now + base::Days(399), /*last_access=*/now,
      /*last_update=*/now,
      /*secure=*/false, /*httponly=*/false, CookieSameSite::UNSPECIFIED,
      COOKIE_PRIORITY_DEFAULT));
  cookies.push_back(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "B", "example.com", "/path", /*creation=*/now,
      /*expiration=*/now + base::Days(400), /*last_access=*/now,
      /*last_update=*/now,
      /*secure=*/false, /*httponly=*/false, CookieSameSite::UNSPECIFIED,
      COOKIE_PRIORITY_DEFAULT));
  cookies.push_back(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "C", "B", "example.com", "/path", /*creation=*/now,
      /*expiration=*/now + base::Days(401), /*last_access=*/now,
      /*last_update=*/now,
      /*secure=*/false, /*httponly=*/false, CookieSameSite::UNSPECIFIED,
      COOKIE_PRIORITY_DEFAULT));
  cookies.push_back(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "D", "", "empty.com", "/", /*creation=*/now, /*expiration=*/now,
      /*last_access=*/now, /*last_update=*/now, /*secure=*/true,
      /*httponly=*/false, CookieSameSite::UNSPECIFIED,
      COOKIE_PRIORITY_DEFAULT));
  return cookies;
}

// Versions 18, 19, and 20 use the same schema so they can reuse this function.
// AddV20CookiesToDB (and future versions) need to set max_expiration_delta to
// base::Days(400) to simulate expiration limits introduced in version 19.
bool AddV18CookiesToDB(sql::Database* db,
                       base::TimeDelta max_expiration_delta) {
  std::vector<CanonicalCookie> cookies = CookiesForMigrationTest();
  sql::Statement statement(db->GetCachedStatement(
      SQL_FROM_HERE,
      "INSERT INTO cookies (creation_utc, top_frame_site_key, host_key, name, "
      "value, encrypted_value, path, expires_utc, is_secure, is_httponly, "
      "samesite, last_access_utc, has_expires, is_persistent, priority, "
      "source_scheme, source_port, is_same_party, last_update_utc) "
      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"));
  if (!statement.is_valid()) {
    return false;
  }
  sql::Transaction transaction(db);
  if (!transaction.Begin()) {
    return false;
  }
  for (const CanonicalCookie& cookie : cookies) {
    base::Time max_expiration(cookie.CreationDate() + max_expiration_delta);

    statement.Reset(true);
    statement.BindTime(0, cookie.CreationDate());
    // TODO (crbug.com/326605834) Once ancestor chain bit changes are
    // implemented update this method utilize the ancestor bit.
    base::expected<CookiePartitionKey::SerializedCookiePartitionKey,
                   std::string>
        serialized_partition_key =
            CookiePartitionKey::Serialize(cookie.PartitionKey());
    EXPECT_TRUE(serialized_partition_key.has_value());

    statement.BindString(1, serialized_partition_key->TopLevelSite());
    statement.BindString(2, cookie.Domain());
    statement.BindString(3, cookie.Name());
    statement.BindString(4, cookie.Value());
    statement.BindBlob(5, base::span<uint8_t>());  // encrypted_value
    statement.BindString(6, cookie.Path());
    statement.BindTime(7, std::min(cookie.ExpiryDate(), max_expiration));
    statement.BindInt(8, cookie.SecureAttribute());
    statement.BindInt(9, cookie.IsHttpOnly());
    // Note that this, Priority(), and SourceScheme() below nominally rely on
    // the enums in sqlite_persistent_cookie_store.cc having the same values as
    // the ones in ../../cookies/cookie_constants.h.  But nothing in this test
    // relies on that equivalence, so it's not worth the hassle to guarantee
    // that.
    statement.BindInt(10, static_cast<int>(cookie.SameSite()));
    statement.BindTime(11, cookie.LastAccessDate());
    statement.BindInt(12, cookie.IsPersistent());
    statement.BindInt(13, cookie.IsPersistent());
    statement.BindInt(14, static_cast<int>(cookie.Priority()));
    statement.BindInt(15, static_cast<int>(cookie.SourceScheme()));
    statement.BindInt(16, cookie.SourcePort());
    statement.BindInt(17, /*is_same_party=*/false);
    statement.BindTime(18, cookie.LastUpdateDate());
    if (!statement.Run()) {
      return false;
    }
  }
  return transaction.Commit();
}

bool AddV20CookiesToDB(sql::Database* db) {
  return AddV18CookiesToDB(db, base::Days(400));
}

bool AddV21CookiesToDB(sql::Database* db) {
  std::vector<CanonicalCookie> cookies = CookiesForMigrationTest();
  sql::Statement statement(db->GetCachedStatement(
      SQL_FROM_HERE,
      "INSERT INTO cookies (creation_utc, top_frame_site_key, host_key, name, "
      "value, encrypted_value, path, expires_utc, is_secure, is_httponly, "
      "samesite, last_access_utc, has_expires, is_persistent, priority, "
      "source_scheme, source_port, last_update_utc) "
      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"));
  if (!statement.is_valid()) {
    return false;
  }
  sql::Transaction transaction(db);
  if (!transaction.Begin()) {
    return false;
  }
  for (const CanonicalCookie& cookie : cookies) {
    base::Time max_expiration(cookie.CreationDate() + base::Days(400));

    statement.Reset(true);
    statement.BindTime(0, cookie.CreationDate());
    // TODO (crbug.com/326605834) Once ancestor chain bit changes are
    // implemented update this method utilize the ancestor bit.
    base::expected<CookiePartitionKey::SerializedCookiePartitionKey,
                   std::string>
        serialized_partition_key =
            CookiePartitionKey::Serialize(cookie.PartitionKey());
    EXPECT_TRUE(serialized_partition_key.has_value());

    statement.BindString(1, serialized_partition_key->TopLevelSite());
    statement.BindString(2, cookie.Domain());
    statement.BindString(3, cookie.Name());
    statement.BindString(4, cookie.Value());
    statement.BindBlob(5, base::span<uint8_t>());  // encrypted_value
    statement.BindString(6, cookie.Path());
    statement.BindTime(7, std::min(cookie.ExpiryDate(), max_expiration));
    statement.BindInt(8, cookie.SecureAttribute());
    statement.BindInt(9, cookie.IsHttpOnly());
    // Note that this, Priority(), and SourceScheme() below nominally rely on
    // the enums in sqlite_persistent_cookie_store.cc having the same values as
    // the ones in ../../cookies/cookie_constants.h.  But nothing in this test
    // relies on that equivalence, so it's not worth the hassle to guarantee
    // that.
    statement.BindInt(10, static_cast<int>(cookie.SameSite()));
    statement.BindTime(11, cookie.LastAccessDate());
    statement.BindInt(12, cookie.IsPersistent());
    statement.BindInt(13, cookie.IsPersistent());
    statement.BindInt(14, static_cast<int>(cookie.Priority()));
    statement.BindInt(15, static_cast<int>(cookie.SourceScheme()));
    statement.BindInt(16, cookie.SourcePort());
    statement.BindTime(17, cookie.LastUpdateDate());
    if (!statement.Run()) {
      return false;
    }
  }
  return transaction.Commit();
}

bool AddV22CookiesToDB(sql::Database* db,
                       const std::vector<CanonicalCookie>& cookies) {
  sql::Statement statement(db->GetCachedStatement(
      SQL_FROM_HERE,
      "INSERT INTO cookies (creation_utc, top_frame_site_key, host_key, name, "
      "value, encrypted_value, path, expires_utc, is_secure, is_httponly, "
      "samesite, last_access_utc, has_expires, is_persistent, priority, "
      "source_scheme, source_port, last_update_utc, source_type) "
      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"));
  if (!statement.is_valid()) {
    return false;
  }
  sql::Transaction transaction(db);
  if (!transaction.Begin()) {
    return false;
  }
  for (const CanonicalCookie& cookie : cookies) {
    base::Time max_expiration(cookie.CreationDate() + base::Days(400));

    statement.Reset(true);
    statement.BindTime(0, cookie.CreationDate());
    // TODO (crbug.com/326605834) Once ancestor chain bit changes are
    // implemented update this method utilize the ancestor bit.
    base::expected<CookiePartitionKey::SerializedCookiePartitionKey,
                   std::string>
        serialized_partition_key =
            CookiePartitionKey::Serialize(cookie.PartitionKey());
    EXPECT_TRUE(serialized_partition_key.has_value());

    statement.BindString(1, serialized_partition_key->TopLevelSite());
    statement.BindString(2, cookie.Domain());
    statement.BindString(3, cookie.Name());
    statement.BindString(4, cookie.Value());
    statement.BindBlob(5, base::span<uint8_t>());  // encrypted_value
    statement.BindString(6, cookie.Path());
    statement.BindTime(7, std::min(cookie.ExpiryDate(), max_expiration));
    statement.BindInt(8, cookie.SecureAttribute());
    statement.BindInt(9, cookie.IsHttpOnly());
    // Note that this, Priority(), and SourceScheme() below nominally rely on
    // the enums in sqlite_persistent_cookie_store.cc having the same values as
    // the ones in ../../cookies/cookie_constants.h.  But nothing in this test
    // relies on that equivalence, so it's not worth the hassle to guarantee
    // that.
    statement.BindInt(10, static_cast<int>(cookie.SameSite()));
    statement.BindTime(11, cookie.LastAccessDate());
    statement.BindInt(12, cookie.IsPersistent());
    statement.BindInt(13, cookie.IsPersistent());
    statement.BindInt(14, static_cast<int>(cookie.Priority()));
    statement.BindInt(15, static_cast<int>(cookie.SourceScheme()));
    statement.BindInt(16, cookie.SourcePort());
    statement.BindTime(17, cookie.LastUpdateDate());
    statement.BindInt(18, static_cast<int>(cookie.SourceType()));
    if (!statement.Run()) {
      return false;
    }
  }
  return transaction.Commit();
}

bool AddV23CookiesToDB(sql::Database* db,
                       const std::vector<CanonicalCookie>& cookies,
                       CookieCryptoDelegate* crypto,
                       bool place_unencrypted_too) {
  sql::Statement statement(db->GetCachedStatement(
      SQL_FROM_HERE,
      "INSERT INTO cookies (creation_utc, host_key, top_frame_site_key, name, "
      "value, encrypted_value, path, expires_utc, is_secure, is_httponly, "
      "samesite, last_access_utc, has_expires, is_persistent, priority, "
      "source_scheme, source_port, last_update_utc, source_type, "
      "has_cross_site_ancestor) "
      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"));
  if (!statement.is_valid()) {
    return false;
  }
  sql::Transaction transaction(db);
  if (!transaction.Begin()) {
    return false;
  }
  for (const CanonicalCookie& cookie : cookies) {
    base::Time max_expiration(cookie.CreationDate() + base::Days(400));

    statement.Reset(true);
    statement.BindTime(0, cookie.CreationDate());
    // TODO (crbug.com/326605834) Once ancestor chain bit changes are
    // implemented update this method utilize the ancestor bit.
    base::expected<CookiePartitionKey::SerializedCookiePartitionKey,
                   std::string>
        serialized_partition_key =
            CookiePartitionKey::Serialize(cookie.PartitionKey());
    EXPECT_TRUE(serialized_partition_key.has_value());

    statement.BindString(1, cookie.Domain());
    statement.BindString(2, serialized_partition_key->TopLevelSite());
    statement.BindString(3, cookie.Name());
    if (crypto) {
      statement.BindString(
          4, place_unencrypted_too
                 ? cookie.Value()
                 : "");  // value is encrypted. If `place_unencrypted_too` is
                         // set then place it here too, to test bad databases.
      std::string encrypted_value;
      // v23 and below simply encrypted the cookie and stored it in this value.
      EXPECT_TRUE(crypto->EncryptString(cookie.Value(), &encrypted_value));
      statement.BindBlob(5, encrypted_value);  // encrypted_value.
    } else {
      statement.BindString(4, cookie.Value());
      statement.BindBlob(5, base::span<uint8_t>());  // encrypted_value empty.
    }
    statement.BindString(6, cookie.Path());
    statement.BindTime(7, std::min(cookie.ExpiryDate(), max_expiration));
    statement.BindInt(8, cookie.SecureAttribute());
    statement.BindInt(9, cookie.IsHttpOnly());
    // Note that this, Priority(), and SourceScheme() below nominally rely on
    // the enums in sqlite_persistent_cookie_store.cc having the same values as
    // the ones in ../../cookies/cookie_constants.h.  But nothing in this test
    // relies on that equivalence, so it's not worth the hassle to guarantee
    // that.
    statement.BindInt(10, static_cast<int>(cookie.SameSite()));
    statement.BindTime(11, cookie.LastAccessDate());
    statement.BindInt(12, cookie.IsPersistent());
    statement.BindInt(13, cookie.IsPersistent());
    statement.BindInt(14, static_cast<int>(cookie.Priority()));

    // Version 23 updated any preexisting cookies with a source_scheme value of
    // kUnset and a is_secure of true to have a source_scheme value of kSecure.
    // This situation can occur with the test cookies, so update the data to
    // reflect a v23 cookie store.
    auto source_scheme = cookie.SourceScheme();
    if (cookie.SourceScheme() == CookieSourceScheme::kUnset &&
        cookie.IsSecure()) {
      source_scheme = CookieSourceScheme::kSecure;
    }
    statement.BindInt(15, static_cast<int>(source_scheme));
    statement.BindInt(16, cookie.SourcePort());
    statement.BindTime(17, cookie.LastUpdateDate());
    statement.BindInt(18, static_cast<int>(cookie.SourceType()));
    statement.BindBool(19, serialized_partition_key->has_cross_site_ancestor());

    if (!statement.Run()) {
      return false;
    }
  }
  return transaction.Commit();
}

// Confirm the cookie list passed in has the above cookies in it.
void ConfirmCookiesAfterMigrationTest(
    std::vector<std::unique_ptr<CanonicalCookie>> read_in_cookies,
    bool expect_last_update_date = false) {
  ASSERT_EQ(read_in_cookies.size(), 7u);

  std::sort(read_in_cookies.begin(), read_in_cookies.end(), &CompareCookies);
  int i = 0;
  EXPECT_EQ("A", read_in_cookies[i]->Name());
  EXPECT_EQ("B", read_in_cookies[i]->Value());
  EXPECT_EQ("example.com", read_in_cookies[i]->Domain());
  EXPECT_EQ("/", read_in_cookies[i]->Path());
  EXPECT_TRUE(read_in_cookies[i]->SecureAttribute());
  EXPECT_EQ(CookieSourceScheme::kSecure, read_in_cookies[i]->SourceScheme());
  EXPECT_EQ(read_in_cookies[i]->LastUpdateDate(),
            expect_last_update_date ? read_in_cookies[i]->CreationDate()
                                    : base::Time());
  EXPECT_EQ(read_in_cookies[i]->ExpiryDate(),
            read_in_cookies[i]->CreationDate());
  EXPECT_EQ(read_in_cookies[i]->SourceType(), CookieSourceType::kUnknown);

  i++;
  EXPECT_EQ("A", read_in_cookies[i]->Name());
  EXPECT_EQ("B", read_in_cookies[i]->Value());
  EXPECT_EQ("example.com", read_in_cookies[i]->Domain());
  EXPECT_EQ("/path", read_in_cookies[i]->Path());
  EXPECT_FALSE(read_in_cookies[i]->SecureAttribute());
  EXPECT_EQ(CookieSourceScheme::kUnset, read_in_cookies[i]->SourceScheme());
  EXPECT_EQ(read_in_cookies[i]->LastUpdateDate(),
            expect_last_update_date ? read_in_cookies[i]->CreationDate()
                                    : base::Time());
  EXPECT_EQ(read_in_cookies[i]->ExpiryDate(),
            read_in_cookies[i]->CreationDate() + base::Days(400));
  EXPECT_EQ(read_in_cookies[i]->SourceType(), CookieSourceType::kUnknown);

  i++;
  EXPECT_EQ("A", read_in_cookies[i]->Name());
  EXPECT_EQ("B", read_in_cookies[i]->Value());
  EXPECT_EQ("example2.com", read_in_cookies[i]->Domain());
  EXPECT_EQ("/", read_in_cookies[i]->Path());
  EXPECT_TRUE(read_in_cookies[i]->SecureAttribute());
  EXPECT_EQ(CookieSourceScheme::kSecure, read_in_cookies[i]->SourceScheme());
  EXPECT_EQ(read_in_cookies[i]->LastUpdateDate(),
            expect_last_update_date ? read_in_cookies[i]->CreationDate()
                                    : base::Time());
  EXPECT_EQ(read_in_cookies[i]->ExpiryDate(),
            read_in_cookies[i]->CreationDate());
  EXPECT_EQ(read_in_cookies[i]->SourceType(), CookieSourceType::kUnknown);

  i++;
  EXPECT_EQ("C", read_in_cookies[i]->Name());
  EXPECT_EQ("B", read_in_cookies[i]->Value());
  EXPECT_EQ("example.com", read_in_cookies[i]->Domain());
  EXPECT_EQ("/", read_in_cookies[i]->Path());
  EXPECT_TRUE(read_in_cookies[i]->SecureAttribute());
  EXPECT_EQ(CookieSourceScheme::kSecure, read_in_cookies[i]->SourceScheme());
  EXPECT_EQ(read_in_cookies[i]->LastUpdateDate(),
            expect_last_update_date ? read_in_cookies[i]->CreationDate()
                                    : base::Time());
  EXPECT_EQ(read_in_cookies[i]->ExpiryDate(),
            read_in_cookies[i]->CreationDate());
  EXPECT_EQ(read_in_cookies[i]->SourceType(), CookieSourceType::kUnknown);

  i++;
  EXPECT_EQ("C", read_in_cookies[i]->Name());
  EXPECT_EQ("B", read_in_cookies[i]->Value());
  EXPECT_EQ("example.com", read_in_cookies[i]->Domain());
  EXPECT_EQ("/path", read_in_cookies[i]->Path());
  EXPECT_FALSE(read_in_cookies[i]->SecureAttribute());
  EXPECT_EQ(CookieSourceScheme::kUnset, read_in_cookies[i]->SourceScheme());
  EXPECT_EQ(read_in_cookies[i]->LastUpdateDate(),
            expect_last_update_date ? read_in_cookies[i]->CreationDate()
                                    : base::Time());
  // The exact time will be within the last minute due to the cap.
  EXPECT_LE(read_in_cookies[i]->ExpiryDate(),
            base::Time::Now() + base::Days(400));
  EXPECT_GE(read_in_cookies[i]->ExpiryDate(),
            base::Time::Now() + base::Days(400) - base::Minutes(1));
  EXPECT_EQ(read_in_cookies[i]->SourceType(), CookieSourceType::kUnknown);

  i++;
  EXPECT_EQ("C", read_in_cookies[i]->Name());
  EXPECT_EQ("B", read_in_cookies[i]->Value());
  EXPECT_EQ("example2.com", read_in_cookies[i]->Domain());
  EXPECT_EQ("/", read_in_cookies[i]->Path());
  EXPECT_FALSE(read_in_cookies[i]->SecureAttribute());
  EXPECT_EQ(CookieSourceScheme::kUnset, read_in_cookies[i]->SourceScheme());
  EXPECT_EQ(read_in_cookies[i]->LastUpdateDate(),
            expect_last_update_date ? read_in_cookies[i]->CreationDate()
                                    : base::Time());
  EXPECT_EQ(read_in_cookies[i]->ExpiryDate(),
            read_in_cookies[i]->CreationDate() + base::Days(399));
  EXPECT_EQ(read_in_cookies[i]->SourceType(), CookieSourceType::kUnknown);

  i++;
  EXPECT_EQ("D", read_in_cookies[i]->Name());
  EXPECT_EQ("", read_in_cookies[i]->Value());
  EXPECT_EQ("empty.com", read_in_cookies[i]->Domain());
  EXPECT_EQ("/", read_in_cookies[i]->Path());
  EXPECT_TRUE(read_in_cookies[i]->SecureAttribute());
  EXPECT_EQ(CookieSourceScheme::kSecure, read_in_cookies[i]->SourceScheme());
  EXPECT_EQ(read_in_cookies[i]->LastUpdateDate(),
            expect_last_update_date ? read_in_cookies[i]->CreationDate()
                                    : base::Time());
  EXPECT_EQ(read_in_cookies[i]->ExpiryDate(),
            read_in_cookies[i]->CreationDate());
  EXPECT_EQ(read_in_cookies[i]->SourceType(), CookieSourceType::kUnknown);
}

void ConfirmDatabaseVersionAfterMigration(const base::FilePath path,
                                          int version) {
  sql::Database connection;
  ASSERT_TRUE(connection.Open(path));
  ASSERT_GE(GetDBCurrentVersionNumber(&connection), version);
}

TEST_F(SQLitePersistentCookieStoreTest, UpgradeToSchemaVersion19) {
  // Open db.
  const base::FilePath database_path =
      temp_dir_.GetPath().Append(kCookieFilename);
  {
    sql::Database connection;
    ASSERT_TRUE(connection.Open(database_path));
    ASSERT_TRUE(CreateV18Schema(&connection));
    ASSERT_EQ(GetDBCurrentVersionNumber(&connection), 18);
    ASSERT_TRUE(AddV18CookiesToDB(&connection, base::TimeDelta::Max()));
  }

  CanonicalCookieVector read_in_cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/false);
  ASSERT_NO_FATAL_FAILURE(
      ConfirmCookiesAfterMigrationTest(std::move(read_in_cookies),
                                       /*expect_last_update_date=*/true));
  DestroyStore();

  ASSERT_NO_FATAL_FAILURE(
      ConfirmDatabaseVersionAfterMigration(database_path, 19));
}

TEST_F(SQLitePersistentCookieStoreTest, UpgradeToSchemaVersion20) {
  // Open db.
  const base::FilePath database_path =
      temp_dir_.GetPath().Append(kCookieFilename);
  {
    sql::Database connection;
    ASSERT_TRUE(connection.Open(database_path));
    // V19's schema is the same as V18, so we can reuse the creation function.
    ASSERT_TRUE(CreateV18Schema(&connection));
    ASSERT_EQ(GetDBCurrentVersionNumber(&connection), 18);
    ASSERT_TRUE(AddV18CookiesToDB(&connection, base::TimeDelta::Max()));
  }

  CanonicalCookieVector read_in_cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/false);
  ASSERT_NO_FATAL_FAILURE(
      ConfirmCookiesAfterMigrationTest(std::move(read_in_cookies),
                                       /*expect_last_update_date=*/true));
  DestroyStore();

  ASSERT_NO_FATAL_FAILURE(
      ConfirmDatabaseVersionAfterMigration(database_path, 20));
}

TEST_F(SQLitePersistentCookieStoreTest, UpgradeToSchemaVersion21) {
  // Open db.
  const base::FilePath database_path =
      temp_dir_.GetPath().Append(kCookieFilename);
  {
    sql::Database connection;
    ASSERT_TRUE(connection.Open(database_path));
    ASSERT_TRUE(CreateV20Schema(&connection));
    ASSERT_EQ(GetDBCurrentVersionNumber(&connection), 20);
    ASSERT_TRUE(AddV20CookiesToDB(&connection));
  }

  CanonicalCookieVector read_in_cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/false);
  ASSERT_NO_FATAL_FAILURE(
      ConfirmCookiesAfterMigrationTest(std::move(read_in_cookies),
                                       /*expect_last_update_date=*/true));
  DestroyStore();

  ASSERT_NO_FATAL_FAILURE(
      ConfirmDatabaseVersionAfterMigration(database_path, 21));
}

TEST_F(SQLitePersistentCookieStoreTest, UpgradeToSchemaVersion22) {
  // Open db.
  const base::FilePath database_path =
      temp_dir_.GetPath().Append(kCookieFilename);
  {
    sql::Database connection;
    ASSERT_TRUE(connection.Open(database_path));
    ASSERT_TRUE(CreateV21Schema(&connection));
    ASSERT_EQ(GetDBCurrentVersionNumber(&connection), 21);
    ASSERT_TRUE(AddV21CookiesToDB(&connection));
  }

  CanonicalCookieVector read_in_cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/false);
  ASSERT_NO_FATAL_FAILURE(
      ConfirmCookiesAfterMigrationTest(std::move(read_in_cookies),
                                       /*expect_last_update_date=*/true));
  DestroyStore();

  ASSERT_NO_FATAL_FAILURE(
      ConfirmDatabaseVersionAfterMigration(database_path, 22));
}

TEST_F(SQLitePersistentCookieStoreTest, UpgradeToSchemaVersion23) {
  // Open db.
  const base::FilePath database_path =
      temp_dir_.GetPath().Append(kCookieFilename);
  {
    sql::Database connection;
    ASSERT_TRUE(connection.Open(database_path));
    ASSERT_TRUE(CreateV22Schema(&connection));
    ASSERT_EQ(GetDBCurrentVersionNumber(&connection), 22);
    ASSERT_TRUE(AddV22CookiesToDB(&connection, CookiesForMigrationTest()));
  }

  CanonicalCookieVector read_in_cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/false);
  ASSERT_NO_FATAL_FAILURE(
      ConfirmCookiesAfterMigrationTest(std::move(read_in_cookies),
                                       /*expect_last_update_date=*/true));
  DestroyStore();

  ASSERT_NO_FATAL_FAILURE(
      ConfirmDatabaseVersionAfterMigration(database_path, 23));
}

class SQLitePersistentCookieStorev24UpgradeTest
    : public SQLitePersistentCookieStoreTest,
      public ::testing::WithParamInterface<
          std::tuple</*crypto_for_encrypt*/ bool,
                     /*crypto_for_decrypt*/ bool,
                     /*place_unencrypted_too*/ bool,
                     /*kEncryptedAndPlaintextValuesAreInvalid*/ bool>> {
 protected:
  void SetUp() override {
    features_.InitWithFeatureState(
        features::kEncryptedAndPlaintextValuesAreInvalid,
        std::get<3>(GetParam()));
    SQLitePersistentCookieStoreTest::SetUp();
  }

 private:
  base::test::ScopedFeatureList features_;
};

TEST_P(SQLitePersistentCookieStorev24UpgradeTest, UpgradeToSchemaVersion24) {
  const bool crypto_for_encrypt = std::get<0>(GetParam());
  const bool crypto_for_decrypt = std::get<1>(GetParam());
  const bool place_unencrypted_too = std::get<2>(GetParam());
  const bool drop_dup_values = std::get<3>(GetParam());

  const base::FilePath database_path =
      temp_dir_.GetPath().Append(kCookieFilename);
  {
    sql::Database connection;
    ASSERT_TRUE(connection.Open(database_path));
    ASSERT_TRUE(CreateV23Schema(&connection));
    ASSERT_EQ(GetDBCurrentVersionNumber(&connection), 23);
    auto cryptor = std::make_unique<CookieCryptor>();

    ASSERT_TRUE(AddV23CookiesToDB(&connection, CookiesForMigrationTest(),
                                  crypto_for_encrypt ? cryptor.get() : nullptr,
                                  place_unencrypted_too));
  }
  {
    base::HistogramTester histogram_tester;
    CanonicalCookieVector read_in_cookies = CreateAndLoad(
        /*crypt_cookies=*/crypto_for_decrypt,
        /*restore_old_session_cookies=*/false);

    // If encryption is enabled for encrypt and not available for decrypt, then
    // most cookies will be gone, as the data is encrypted with no way to
    // decrypt.
    if (crypto_for_encrypt && !crypto_for_decrypt) {
      // Subtle: The empty cookie for empty.com will not trigger a cookie load
      // failure. This is because during the migration there is no crypto so no
      // migration occurs for any cookie, including the empty one. Then when
      // attempting to load a v24 store the cookie with an empty value and empty
      // encrypted value will simply load empty.
      EXPECT_EQ(read_in_cookies.size(), 1u);
      // The case of plaintext and encrypted values is always checked when
      // loading a cookie before the availability of crypto. This means the
      // error code here depends on whether migration from v23 to v24 was done
      // with crypto available or not. In this case, crypto was not available
      // during migration so the values were left alone - meaning that if there
      // are both plaintext and encrypted values the
      // kValuesExistInBothEncryptedAndPlaintext error is returned. However, if
      // this cookie does not have both plaintext and encrypted values, then the
      // second check is hit which reports encrypted data that cannot be
      // decrypted - kNoCrypto. Functionality for an already-migrated store (v24
      // and above) with both plaintext and encrypted values is tested in the
      // `OverridePlaintextValue` test below.
      const base::Histogram::Sample expected_bucket =
          drop_dup_values && place_unencrypted_too
              ? /*CookieLoadProblem::kValuesExistInBothEncryptedAndPlaintext*/ 8
              : /*CookieLoadProblem::kNoCrypto*/ 7;
      histogram_tester.ExpectBucketCount("Cookie.LoadProblem", expected_bucket,
                                         CookiesForMigrationTest().size() - 1);
    } else {
      histogram_tester.ExpectTotalCount("Cookie.LoadProblem", 0);
      ASSERT_NO_FATAL_FAILURE(
          ConfirmCookiesAfterMigrationTest(std::move(read_in_cookies),
                                           /*expect_last_update_date=*/true));
    }
    DestroyStore();
  }

  ASSERT_NO_FATAL_FAILURE(
      ConfirmDatabaseVersionAfterMigration(database_path, 24));
}

INSTANTIATE_TEST_SUITE_P(,
                         SQLitePersistentCookieStorev24UpgradeTest,
                         ::testing::Combine(::testing::Bool(),
                                            ::testing::Bool(),
                                            ::testing::Bool(),
                                            ::testing::Bool()));

TEST_F(SQLitePersistentCookieStoreTest, CannotModifyHostName) {
  {
    CreateAndLoad(/*crypt_cookies=*/true,
                  /*restore_old_session_cookies=*/false);
    AddCookie("A", "B", "sensitive.com", "/", base::Time::Now());
    AddCookie("A", "B", "example.com", "/", base::Time::Now());
    DestroyStore();
  }
  {
    const base::FilePath database_path =
        temp_dir_.GetPath().Append(kCookieFilename);
    // Simulate an attacker modifying hostname to attacker controlled, to
    // perform a cookie replay attack.
    sql::Database connection;
    ASSERT_TRUE(connection.Open(database_path));
    sql::Transaction transaction(&connection);
    ASSERT_TRUE(transaction.Begin());
    ASSERT_TRUE(
        connection.Execute("UPDATE cookies SET host_key='attacker.com' WHERE "
                           "host_key='sensitive.com'"));
    ASSERT_TRUE(transaction.Commit());
  }
  {
    base::HistogramTester histogram_tester;
    auto cookies = CreateAndLoad(/*crypt_cookies=*/true,
                                 /*restore_old_se
```