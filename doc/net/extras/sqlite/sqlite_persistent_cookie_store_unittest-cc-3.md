Response:
The user wants a summary of the functionalities implemented in the provided C++ code, which is a unit test file for `SQLitePersistentCookieStore` in Chromium's network stack. I need to identify the core purpose of the code and highlight specific testing scenarios. I also need to check for any interaction with JavaScript, any logical reasoning with input/output examples, common user/programming errors, and a debugging walkthrough. Finally, I need to ensure this is the fourth and final part of the summary.

Here's a breakdown of the code's functionalities:

1. **Basic Cookie Storage and Retrieval:** Tests adding, retrieving, and deleting cookies.
2. **Encryption:** Tests encrypting and decrypting cookies, including scenarios with corrupted or missing encryption.
3. **Schema Upgrades:** Verifies the database schema upgrade process, specifically focusing on new columns like `source_scheme` and `has_cross_site_ancestor`.
4. **Origin-Bound Cookies:** Tests the behavior of cookies with specific source schemes (HTTP/HTTPS) and ports.
5. **Partitioned Cookies:** Tests storing and loading cookies with `CookiePartitionKey`.
6. **Handling Corrupted Data:**  Tests how the store handles corrupted data, such as invalid hashes or mismatched encrypted/plaintext values.

Let's plan the response structure:

- **Functionality Summary:** Briefly describe the overall purpose of the test file.
- **JavaScript Relationship:** Analyze if any tests directly relate to JavaScript functionalities.
- **Logical Reasoning:** Identify tests with clear input and expected output based on cookie operations.
- **Common Errors:**  Point out potential errors users or programmers might encounter.
- **Debugging Walkthrough:**  Describe how a developer might end up in this code during debugging.
- **Overall Functionality (Part 4):**  Summarize the functionalities covered in this specific part of the code.
这是对 Chromium 网络堆栈中 `net/extras/sqlite/sqlite_persistent_cookie_store_unittest.cc` 文件功能的总结，作为第 4 部分，也是最后一部分。

**功能归纳:**

这部分代码主要集中在以下几个方面的测试，以确保 `SQLitePersistentCookieStore` 的稳定性和正确性：

1. **数据校验与完整性:**
   - **哈希校验失败:** 测试当数据库中加密的 Cookie 数据被篡改（例如，修改了值但未重新计算哈希值）时，CookieStore 如何处理。预期行为是丢弃这些损坏的 Cookie，并记录 `Cookie.LoadProblem` 统计信息。
   - **短哈希处理:** 模拟攻击者修改敏感 Cookie 数据，故意创建一个短的、没有完整哈希值的加密字符串，验证解密代码是否能够正确处理，并丢弃此类损坏的 Cookie。

2. **数据库 Schema 升级:**
   - **`source_scheme` 字段回填:**  测试从旧版本数据库（v22）升级到新版本（v23）时，对于已存在的 Cookie，`source_scheme` 字段是否能根据 `is_secure` 字段的值正确回填（HTTPS Cookie 设置为 `kSecure`，非 HTTPS Cookie 保留 `kUnset`）。
   - **`has_cross_site_ancestor` 字段添加:**  测试从旧版本数据库升级到新版本时，是否正确添加了 `has_cross_site_ancestor` 字段，并根据 Cookie 的域名和 `CookiePartitionKey` 的 top-level site 确定其初始值。

3. **源绑定 Cookie (Origin-Bound Cookies):**
   - **唯一性约束:**  测试具有相同域名、路径和名称，但源 Scheme (HTTP/HTTPS) 或端口不同的 Cookie 被认为是不同的 Cookie，并能同时存储。
   - **删除操作:**  验证删除特定源 Scheme 或端口的 Cookie 时，其他具有相同域名、路径和名称但不同源 Scheme 或端口的 Cookie 不会受到影响。
   - **更新访问时间:**  验证更新特定源 Scheme 或端口的 Cookie 的访问时间时，其他具有相同域名、路径和名称但不同源 Scheme 或端口的 Cookie 的访问时间不会受到影响。

4. **分区 Cookie (Partitioned Cookies):**
   - **保存分区 Cookie:** 测试能够正确地将带有 `CookiePartitionKey` 的 Cookie 保存到数据库中。
   - **加载分区 Cookie:** 测试能够正确地从数据库中加载带有 `CookiePartitionKey` 的 Cookie，并能正确解析其属性。

5. **加密处理:**
   - **没有加密器进行解密:** 测试当数据库中的 Cookie 是加密的，但加载时没有提供加密器时，CookieStore 是否会丢弃这些 Cookie，并记录 `Cookie.LoadProblem`。

6. **处理加密值和明文值同时存在的情况:**
   - **优先级处理:** 测试当数据库中同时存在 Cookie 的加密值和明文值时，默认情况下加密值优先。
   - **功能标志 `kEncryptedAndPlaintextValuesAreInvalid`:**  引入了一个功能标志，当启用时，如果检测到 Cookie 同时存在加密值和明文值，则会直接丢弃该 Cookie，并记录相应的 `Cookie.LoadProblem`。这用于加强数据一致性，避免使用可能不一致的明文值。

**与 JavaScript 的关系:**

虽然此代码是 C++ 的单元测试，但它间接关系到 JavaScript 的 Cookie 功能。JavaScript 可以通过 `document.cookie` API 来读取、设置和修改浏览器的 Cookie。`SQLitePersistentCookieStore` 负责将这些 Cookie 持久化存储到本地数据库中。

**举例说明:**

- 当 JavaScript 代码使用 `document.cookie = "A=B; domain=example.com"` 设置一个 Cookie 时，`SQLitePersistentCookieStore` 会将此 Cookie 的信息（名称、值、域名等）保存到 SQLite 数据库中。
- 当 JavaScript 代码尝试读取 `document.cookie` 时，浏览器会从 `SQLitePersistentCookieStore` 加载相关的 Cookie 信息并返回给 JavaScript。
- 对于分区 Cookie，如果 JavaScript 在一个顶级站点 `toplevelsite.com` 的上下文中，为一个 `example.com` 的站点设置了分区 Cookie，`SQLitePersistentCookieStore` 会记录这个 Cookie 与 `toplevelsite.com` 的关联。当在同一个 `toplevelsite.com` 上下文访问 `example.com` 时，这个分区 Cookie 才会被返回给 JavaScript。

**逻辑推理与假设输入/输出:**

**示例 1: 哈希校验失败测试**

* **假设输入:** 数据库中存在一个加密的 Cookie，其值被修改，但哈希值未更新。
* **预期输出:**  `CreateAndLoad` 方法不会加载这个被篡改的 Cookie，返回的 Cookie 列表不包含这个 Cookie，并且 `Cookie.LoadProblem` 统计信息中 `kHashFailed` 的计数会增加。

**示例 2:  `source_scheme` 字段回填测试**

* **假设输入:** 一个旧版本的 SQLite 数据库，包含 `is_secure` 为 true 和 false 的 Cookie。
* **预期输出:**  升级数据库后，读取这些 Cookie，`is_secure` 为 true 的 Cookie 的 `source_scheme` 字段值为 `kSecure`， `is_secure` 为 false 的 Cookie 的 `source_scheme` 字段值为 `kUnset`。

**涉及用户或编程常见的使用错误:**

1. **手动修改数据库文件:** 用户或开发者不应直接修改 SQLite 数据库文件，这可能导致数据损坏，如哈希校验失败的测试所演示的那样。
2. **不理解分区 Cookie 的作用域:** 开发者可能会错误地认为分区 Cookie 在所有上下文中都可用，而实际上它们只在特定的顶级站点上下文中有效。
3. **混淆加密和非加密状态:**  在过去，如果加密功能不可用，Cookie 可能以明文形式存储。当加密功能恢复时，如果开发者没有意识到这一点，可能会导致加载时出现意外行为，例如 `OverridePlaintextValue` 测试所涵盖的情况。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户报告 Cookie 相关的问题:** 用户可能遇到网站登录状态丢失、偏好设置重置等与 Cookie 相关的问题。
2. **开发者开始调试:** 开发者可能会检查浏览器的 Cookie 设置，查看 `chrome://settings/cookies/detail` 或使用开发者工具的 "Application" 面板查看 Cookie。
3. **怀疑持久化存储问题:** 如果怀疑 Cookie 没有正确地保存或加载，开发者可能会深入研究 Chromium 的网络堆栈代码。
4. **定位到 `SQLitePersistentCookieStore`:** 开发者可能会通过代码搜索或调用链跟踪，最终定位到 `SQLitePersistentCookieStore`，因为它负责 Cookie 的持久化存储。
5. **查看单元测试:** 为了理解 `SQLitePersistentCookieStore` 的工作原理和可能出现的问题，开发者可能会查看其单元测试文件 `sqlite_persistent_cookie_store_unittest.cc`，特别是这部分代码，了解各种边界情况和错误处理机制。例如，如果用户报告 Cookie 数据损坏，开发者可能会查看关于哈希校验失败的测试。

总而言之，这部分单元测试主要关注 `SQLitePersistentCookieStore` 在数据完整性、数据库升级、处理不同类型的 Cookie（如源绑定和分区 Cookie）以及加密方面的行为，确保了 Cookie 存储机制的健壮性和可靠性。

### 提示词
```
这是目录为net/extras/sqlite/sqlite_persistent_cookie_store_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
ssion_cookies=*/false);
    // Modified cookie should not load.
    ASSERT_EQ(cookies.size(), 1u);
    ASSERT_EQ(cookies[0]->Domain(), "example.com");
    ASSERT_EQ(cookies[0]->Name(), "A");
    ASSERT_EQ(cookies[0]->Value(), "B");
    DestroyStore();
    histogram_tester.ExpectBucketCount("Cookie.LoadProblem",
                                       /*CookieLoadProblem::kHashFailed*/ 6, 1);
  }
  {
    base::HistogramTester histogram_tester;
    auto cookies = CreateAndLoad(/*crypt_cookies=*/true,
                                 /*restore_old_session_cookies=*/false);
    // Modified cookie should not load.
    ASSERT_EQ(cookies.size(), 1u);
    ASSERT_EQ(cookies[0]->Domain(), "example.com");
    ASSERT_EQ(cookies[0]->Name(), "A");
    ASSERT_EQ(cookies[0]->Value(), "B");
    DestroyStore();
    // The hash failure should only appear once, during the first read, as the
    // invalid cookie gets deleted afterwards.
    histogram_tester.ExpectTotalCount("Cookie.LoadProblem", 0);
  }
}

TEST_F(SQLitePersistentCookieStoreTest, ShortHash) {
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
    sql::Statement set_encrypted_value(connection.GetUniqueStatement(
        "UPDATE cookies SET encrypted_value=? WHERE host_key='sensitive.com'"));
    CookieCryptor crypto;
    // Short string, without a hash, but valid encryption. This verifies that
    // the decryption code handles short-length encrypted data fine.
    std::string encrypted_data;
    crypto.EncryptString("a", &encrypted_data);
    set_encrypted_value.BindBlob(0, encrypted_data);

    ASSERT_TRUE(transaction.Begin());
    ASSERT_TRUE(set_encrypted_value.Run());
    ASSERT_TRUE(transaction.Commit());
  }
  {
    base::HistogramTester histogram_tester;
    auto cookies = CreateAndLoad(/*crypt_cookies=*/true,
                                 /*restore_old_session_cookies=*/false);
    // Modified cookie should not load.
    ASSERT_EQ(cookies.size(), 1u);
    ASSERT_EQ(cookies[0]->Domain(), "example.com");
    ASSERT_EQ(cookies[0]->Name(), "A");
    ASSERT_EQ(cookies[0]->Value(), "B");
    DestroyStore();
    histogram_tester.ExpectBucketCount("Cookie.LoadProblem",
                                       /*CookieLoadProblem::kHashFailed*/ 6, 1);
  }
  {
    base::HistogramTester histogram_tester;
    auto cookies = CreateAndLoad(/*crypt_cookies=*/true,
                                 /*restore_old_session_cookies=*/false);
    // Modified cookie should not load.
    ASSERT_EQ(cookies.size(), 1u);
    ASSERT_EQ(cookies[0]->Domain(), "example.com");
    ASSERT_EQ(cookies[0]->Name(), "A");
    ASSERT_EQ(cookies[0]->Value(), "B");
    DestroyStore();
    // The hash failure should only appear once, during the first read, as the
    // invalid cookie gets deleted afterwards.
    histogram_tester.ExpectTotalCount("Cookie.LoadProblem", 0);
  }
}

TEST_F(SQLitePersistentCookieStoreTest,
       UpgradeToSchemaVersion23_ConfirmSourceSchemeRecalculation) {
  const base::FilePath database_path =
      temp_dir_.GetPath().Append(kCookieFilename);
  const base::Time now = base::Time::Now();
  std::vector<CanonicalCookie> cookies;

  cookies.push_back(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "secure_true", "A", "example.com", "/", now, now, now, now,
      /*secure=*/true, /*httponly=*/false, CookieSameSite::UNSPECIFIED,
      COOKIE_PRIORITY_DEFAULT, std::optional<CookiePartitionKey>(),
      CookieSourceScheme::kUnset));

  cookies.push_back(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "secure_false", "B", "example.com", "/", now, now, now, now,
      /*secure=*/false, /*httponly=*/false, CookieSameSite::UNSPECIFIED,
      COOKIE_PRIORITY_DEFAULT, std::optional<CookiePartitionKey>(),
      CookieSourceScheme::kUnset));

  // Open database, populate and close db.
  {
    sql::Database db;
    ASSERT_TRUE(db.Open(database_path));
    ASSERT_TRUE(CreateV22Schema(&db));
    ASSERT_EQ(GetDBCurrentVersionNumber(&db), 22);
    ASSERT_TRUE(AddV22CookiesToDB(&db, cookies));
  }

  CanonicalCookieVector read_in_cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/true);

  EXPECT_EQ(read_in_cookies.size(), cookies.size());

  // Reopen database for testing.
  sql::Database connection;
  ASSERT_TRUE(connection.Open(database_path));
  ASSERT_GE(GetDBCurrentVersionNumber(&connection), 23);
  for (const auto& cookie : cookies) {
    sql::Statement verify_stmt(connection.GetUniqueStatement(
        "SELECT source_scheme FROM cookies WHERE is_secure=?"));

    verify_stmt.BindBool(0, cookie.SecureAttribute());

    ASSERT_TRUE(verify_stmt.is_valid());

    EXPECT_TRUE(verify_stmt.Step());
    EXPECT_EQ(
        static_cast<int>(cookie.SecureAttribute() ? CookieSourceScheme::kSecure
                                                  : CookieSourceScheme::kUnset),
        verify_stmt.ColumnInt(0));
    // Confirm that exactly one cookie matches the SQL query
    EXPECT_FALSE(verify_stmt.Step());
  }
}

class SQLitePersistentCookieStoreTest_OriginBoundCookies
    : public SQLitePersistentCookieStoreTest {
 public:
  // Creates and stores 4 cookies that differ only by scheme and/or port. When
  // this function returns, the store will be created and all the cookies loaded
  // into cookies_.
  void InitializeTest() {
    InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/false);

    basic_cookie_ = CanonicalCookie::CreateForTesting(
        basic_url_, "a=b; max-age=100000", /*creation_time=*/base::Time::Now());

    http_cookie_ = std::make_unique<CanonicalCookie>(*basic_cookie_);
    http_cookie_->SetSourceScheme(CookieSourceScheme::kNonSecure);

    port_444_cookie_ = std::make_unique<CanonicalCookie>(*basic_cookie_);
    port_444_cookie_->SetSourcePort(444);

    http_444_cookie_ = std::make_unique<CanonicalCookie>(*basic_cookie_);
    http_444_cookie_->SetSourceScheme(CookieSourceScheme::kNonSecure);
    http_444_cookie_->SetSourcePort(444);

    store_->AddCookie(*basic_cookie_);
    store_->AddCookie(*http_cookie_);
    store_->AddCookie(*port_444_cookie_);
    store_->AddCookie(*http_444_cookie_);
    // Force the store to write its data to the disk.
    DestroyStore();

    cookies_ = CreateAndLoad(/*crypt_cookies=*/false,
                             /*restore_old_session_cookies=*/false);

    EXPECT_EQ(cookies_.size(), 4UL);
  }

  GURL basic_url_ = GURL("https://example.com");
  std::unique_ptr<net::CanonicalCookie> basic_cookie_;
  std::unique_ptr<net::CanonicalCookie> http_cookie_;
  std::unique_ptr<net::CanonicalCookie> port_444_cookie_;
  std::unique_ptr<net::CanonicalCookie> http_444_cookie_;

  CanonicalCookieVector cookies_;
};

// Tests that cookies which differ only in their scheme and port are considered
// distinct.
TEST_F(SQLitePersistentCookieStoreTest_OriginBoundCookies,
       UniquenessConstraint) {
  InitializeTest();

  // Try to add another cookie that is the same as basic_cookie_ except that its
  // value is different. Value isn't considered as part of the unique constraint
  // and so this cookie won't be considered unique and should fail to be added.
  auto basic_cookie2 =
      CanonicalCookie::CreateForTesting(basic_url_, "a=b2; max-age=100000",
                                        /*creation_time=*/base::Time::Now());

  store_->AddCookie(*basic_cookie2);

  // Force the store to write its data to the disk.
  DestroyStore();

  cookies_.clear();
  cookies_ = CreateAndLoad(/*crypt_cookies=*/false,
                           /*restore_old_session_cookies=*/false);

  // Confirm that basic_cookie2 failed to be added.
  EXPECT_THAT(cookies_, testing::UnorderedElementsAre(
                            MatchesEveryCookieField(*basic_cookie_),
                            MatchesEveryCookieField(*http_cookie_),
                            MatchesEveryCookieField(*port_444_cookie_),
                            MatchesEveryCookieField(*http_444_cookie_)));
}

// Tests that deleting a cookie correctly takes the scheme and port into
// account.
TEST_F(SQLitePersistentCookieStoreTest_OriginBoundCookies, DeleteCookie) {
  InitializeTest();

  // Try to delete just one of the cookies.
  store_->DeleteCookie(*http_444_cookie_);
  DestroyStore();
  cookies_.clear();

  cookies_ = CreateAndLoad(/*crypt_cookies=*/false,
                           /*restore_old_session_cookies=*/false);

  // Only the single cookie should be deleted.
  EXPECT_THAT(cookies_, testing::UnorderedElementsAre(
                            MatchesEveryCookieField(*basic_cookie_),
                            MatchesEveryCookieField(*http_cookie_),
                            MatchesEveryCookieField(*port_444_cookie_)));
}

// Tests that updating a cookie correctly takes the scheme and port into
// account.
TEST_F(SQLitePersistentCookieStoreTest_OriginBoundCookies,
       UpdateCookieAccessTime) {
  InitializeTest();

  base::Time basic_last_access = basic_cookie_->LastAccessDate();
  base::Time http_last_access = http_cookie_->LastAccessDate();
  base::Time port_444_last_access = port_444_cookie_->LastAccessDate();
  base::Time http_444_last_access = http_444_cookie_->LastAccessDate();

  base::Time new_last_access = http_444_last_access + base::Hours(1);
  http_444_cookie_->SetLastAccessDate(new_last_access);

  store_->UpdateCookieAccessTime(*http_444_cookie_);
  DestroyStore();
  cookies_.clear();

  cookies_ = CreateAndLoad(/*crypt_cookies=*/false,
                           /*restore_old_session_cookies=*/false);

  // All loaded cookies' should have their original LastAccessDate() except for
  // the one updated to new_last_access.
  EXPECT_THAT(
      cookies_,
      testing::UnorderedElementsAre(
          MatchesCookieKeyAndLastAccessDate(basic_cookie_->StrictlyUniqueKey(),
                                            basic_last_access),
          MatchesCookieKeyAndLastAccessDate(http_cookie_->StrictlyUniqueKey(),
                                            http_last_access),
          MatchesCookieKeyAndLastAccessDate(
              port_444_cookie_->StrictlyUniqueKey(), port_444_last_access),
          MatchesCookieKeyAndLastAccessDate(
              http_444_cookie_->StrictlyUniqueKey(), new_last_access)));
}

TEST_F(SQLitePersistentCookieStoreTest, SavingPartitionedCookies) {
  InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/false);

  store_->AddCookie(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "__Host-foo", "bar", GURL("https://example.com/").host(), "/",
      /*creation=*/base::Time::Now(),
      /*expiration=*/base::Time::Now() + base::Days(1),
      /*last_access=*/base::Time::Now(),
      /*last_update=*/base::Time::Now(), /*secure=*/true, /*httponly=*/false,
      CookieSameSite::UNSPECIFIED, COOKIE_PRIORITY_DEFAULT,
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com"))));
  Flush();

  std::string got_db_content(ReadRawDBContents());
  EXPECT_NE(got_db_content.find("__Host-foo"), std::string::npos);

  DestroyStore();
}

TEST_F(SQLitePersistentCookieStoreTest, LoadingPartitionedCookies) {
  InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/false);
  DestroyStore();

  // Insert a partitioned cookie into the database manually.
  base::FilePath store_name(temp_dir_.GetPath().Append(kCookieFilename));
  std::unique_ptr<sql::Database> db(std::make_unique<sql::Database>());
  ASSERT_TRUE(db->Open(store_name));

  sql::Statement stmt(db->GetUniqueStatement(
      "INSERT INTO cookies (creation_utc, host_key, top_frame_site_key, name, "
      "value, encrypted_value, path, expires_utc, is_secure, is_httponly, "
      "samesite, last_access_utc, has_expires, is_persistent, priority, "
      "source_scheme, source_port, last_update_utc, source_type, "
      "has_cross_site_ancestor) "
      "VALUES (?,?,?,?,?,'',?,?,1,0,0,?,1,1,0,?,?,?,0, 1)"));
  ASSERT_TRUE(stmt.is_valid());

  base::Time creation(base::Time::Now());
  base::Time expiration(creation + base::Days(1));
  base::Time last_access(base::Time::Now());
  base::Time last_update(base::Time::Now());

  stmt.BindTime(0, creation);
  stmt.BindString(1, GURL("https://www.example.com/").host());
  stmt.BindString(2, "https://toplevelsite.com");
  stmt.BindString(3, "__Host-foo");
  stmt.BindString(4, "bar");
  stmt.BindString(5, "/");
  stmt.BindTime(6, expiration);
  stmt.BindTime(7, last_access);
  stmt.BindInt(8, static_cast<int>(CookieSourceScheme::kUnset));
  stmt.BindInt(9, SQLitePersistentCookieStore::kDefaultUnknownPort);
  stmt.BindTime(10, last_update);
  ASSERT_TRUE(stmt.Run());
  stmt.Clear();
  db.reset();

  CanonicalCookieVector cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/false);

  EXPECT_EQ(1u, cookies.size());
  auto cc = std::move(cookies[0]);
  EXPECT_EQ("__Host-foo", cc->Name());
  EXPECT_EQ("bar", cc->Value());
  EXPECT_EQ(GURL("https://www.example.com/").host(), cc->Domain());
  EXPECT_TRUE(cc->IsPartitioned());
  EXPECT_EQ(
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com")),
      cc->PartitionKey());
  EXPECT_EQ(last_update, cc->LastUpdateDate());
}

std::unique_ptr<CanonicalCookie> CreatePartitionedCookie(
    const std::string& name,
    const std::string& domain,
    const std::string& top_frame_site_key,
    CookiePartitionKey::AncestorChainBit ancestor_chain_bit,
    CookieSourceScheme scheme = CookieSourceScheme::kUnset,
    bool partitioned_cookies_enabled = true) {
  const base::Time now = base::Time::Now();

  return CanonicalCookie::CreateUnsafeCookieForTesting(
      name, "B", domain, "/", now, now, now, now, /*secure=*/true,
      /*httponly=*/false, CookieSameSite::UNSPECIFIED, COOKIE_PRIORITY_DEFAULT,
      partitioned_cookies_enabled
          ? CookiePartitionKey::FromURLForTesting(GURL(top_frame_site_key),
                                                  ancestor_chain_bit)
          :
          /* std::nullopt can't be used because of the ternary evaluation might
           result in different types */
          std::optional<CookiePartitionKey>(),
      scheme);
}

// Pairs contain a cookie, and hard coded value for has_cross_site_ancestor
// value.
//
// During migration we have no way of knowing if a cross site ancestor was
// present. When the existing domain and the top_level_site of the partition key
// are the same. The default behavior is to set the cross site value to
// kSameSite, so ignore the kCrossSite cookie when testing migration.
std::vector<std::pair<CanonicalCookie, std::string>>
GenerateHasCrossSiteAncestorCookiesAndVals(bool migrating = false) {
  std::vector<std::pair<CanonicalCookie, std::string>> results;
  const std::string default_domain = "example.com";

  // Key and domain are the same site
  results.emplace_back(
      *CreatePartitionedCookie("A", default_domain, "https://www.example.com",
                               CookiePartitionKey::AncestorChainBit::kSameSite),
      "0");
  if (!migrating) {
    // Key and domain are the same site but with kCrossSite
    results.emplace_back(*CreatePartitionedCookie(
                             "B", default_domain, "https://www.example.com",
                             CookiePartitionKey::AncestorChainBit::kCrossSite),
                         "1");
  }
  // Key and domain are different
  results.emplace_back(*CreatePartitionedCookie(
                           "C", default_domain, "https://www.toplevelsite.com",
                           CookiePartitionKey::AncestorChainBit::kCrossSite),
                       "1");
  // Domain is a substring
  results.emplace_back(*CreatePartitionedCookie(
                           "D", "ample.com", "https://www.example.com",
                           CookiePartitionKey::AncestorChainBit::kCrossSite),
                       "1");
  // http check kNonSecure scheme match.
  results.emplace_back(
      *CreatePartitionedCookie("E", default_domain, "http://www.example.com",
                               CookiePartitionKey::AncestorChainBit::kSameSite),
      "0");

  return results;
}

TEST_F(SQLitePersistentCookieStoreTest,
       UpgradeToSchemaVersion23_AddingHasCrossSiteAncestor) {
  const base::FilePath database_path =
      temp_dir_.GetPath().Append(kCookieFilename);

  std::vector<std::pair<CanonicalCookie, std::string>>
      cookies_and_expected_values =
          GenerateHasCrossSiteAncestorCookiesAndVals(true);

  std::vector<CanonicalCookie> cookies;
  for (auto cookie_pair : cookies_and_expected_values) {
    cookies.push_back(cookie_pair.first);
  }
  // Open database, populate and close db.
  {
    sql::Database db;
    ASSERT_TRUE(db.Open(database_path));
    ASSERT_TRUE(CreateV22Schema(&db));
    ASSERT_EQ(GetDBCurrentVersionNumber(&db), 22);
    ASSERT_TRUE(AddV22CookiesToDB(&db, cookies));
  }

  CanonicalCookieVector read_in_cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/true);

  EXPECT_EQ(read_in_cookies.size(), cookies.size());

  // Reopen database for testing.
  sql::Database connection;
  ASSERT_TRUE(connection.Open(database_path));
  ASSERT_GE(GetDBCurrentVersionNumber(&connection), 23);

  for (const auto& cookie_pair : cookies_and_expected_values) {
    // TODO (crbug.com/326605834) Once ancestor chain bit changes are
    // implemented update this method utilize the ancestor bit.
    base::expected<CookiePartitionKey::SerializedCookiePartitionKey,
                   std::string>
        serialized_partition_key =
            CookiePartitionKey::Serialize(cookie_pair.first.PartitionKey());
    ASSERT_TRUE(serialized_partition_key.has_value());

    sql::Statement verify_stmt(connection.GetUniqueStatement(
        "SELECT name FROM cookies WHERE host_key=?"
        " AND top_frame_site_key=?"
        " AND has_cross_site_ancestor=?"));

    verify_stmt.BindString(0, cookie_pair.first.Domain());
    verify_stmt.BindString(1, serialized_partition_key->TopLevelSite());
    verify_stmt.BindString(2, cookie_pair.second);

    ASSERT_TRUE(verify_stmt.is_valid());
    EXPECT_TRUE(verify_stmt.Step());
    EXPECT_EQ(cookie_pair.first.Name(), verify_stmt.ColumnString(0));
    // Confirm that exactly one cookie matches the SQL query
    EXPECT_FALSE(verify_stmt.Step());
  }
}

TEST_F(SQLitePersistentCookieStoreTest,
       TestValueOfHasCrossSiteAncestorOnDoCommit) {
  InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/false);

  std::vector<std::pair<CanonicalCookie, std::string>>
      cookies_and_expected_values =
          GenerateHasCrossSiteAncestorCookiesAndVals();
  for (const auto& cookie_pair : cookies_and_expected_values) {
    store_->AddCookie(cookie_pair.first);
  }

  // Force the store to write its data to the disk.
  DestroyStore();

  cookies_ = CreateAndLoad(/*crypt_cookies=*/false,
                           /*restore_old_session_cookies=*/false);
  EXPECT_EQ(cookies_.size(), cookies_and_expected_values.size());

  sql::Database connection;
  ASSERT_TRUE(connection.Open(temp_dir_.GetPath().Append(kCookieFilename)));
  ASSERT_GT(GetDBCurrentVersionNumber(&connection), 23);

  for (const auto& cookie_pair : cookies_and_expected_values) {
    // TODO (crbug.com/326605834) Once ancestor chain bit changes are
    // implemented update this method utilize the ancestor bit.
    base::expected<CookiePartitionKey::SerializedCookiePartitionKey,
                   std::string>
        serialized_partition_key =
            CookiePartitionKey::Serialize(cookie_pair.first.PartitionKey());
    ASSERT_TRUE(serialized_partition_key.has_value());

    sql::Statement verify_stmt(connection.GetUniqueStatement(
        "SELECT name FROM cookies WHERE host_key=?"
        " AND top_frame_site_key=?"
        " AND has_cross_site_ancestor=?"));

    verify_stmt.BindString(0, cookie_pair.first.Domain());
    verify_stmt.BindString(1, serialized_partition_key->TopLevelSite());
    verify_stmt.BindString(2, cookie_pair.second);
    ASSERT_TRUE(verify_stmt.is_valid());

    EXPECT_TRUE(verify_stmt.Step());
    EXPECT_EQ(cookie_pair.first.Name(), verify_stmt.ColumnString(0));
    // Confirm that exactly one cookie matches the SQL query
    EXPECT_FALSE(verify_stmt.Step());
  }
}

TEST_F(SQLitePersistentCookieStoreTest, NoCryptoForDecryption) {
  InitializeStore(/*crypt=*/true, /*restore_old_session_cookies=*/false);
  AddCookie("X", "Y", "foo.bar", "/", base::Time::Now());
  DestroyStore();

  {
    base::HistogramTester histogram_tester;
    const auto cookies =
        CreateAndLoad(/*crypt=*/false, /*restore_old_session_cookies=*/false);
    ASSERT_TRUE(cookies.empty());
    histogram_tester.ExpectBucketCount("Cookie.LoadProblem",
                                       /*CookieLoadProblem::kNoCrypto*/ 7, 1);
  }
}

class SQLitePersistentCookieStoreTestWithDropDupDataFeature
    : public ::testing::WithParamInterface<
          /*features::kEncryptedAndPlaintextValuesAreInvalid*/ bool>,
      public SQLitePersistentCookieStoreTest {
 public:
  void SetUp() override {
    features_.InitWithFeatureState(
        features::kEncryptedAndPlaintextValuesAreInvalid,
        IsDroppingCookiesEnabled());
    SQLitePersistentCookieStoreTest::SetUp();
  }

 protected:
  bool IsDroppingCookiesEnabled() const { return GetParam(); }

 private:
  base::test::ScopedFeatureList features_;
};

// This test verifies that if a plaintext value is in the store (e.g. written in
// manually, or crypto was at some point not available in the past) and crypto
// is now available, it can still be read fine, including if the value is empty.
// It also tests the case where both a plaintext and encrypted value exist,
// where the encrypted value should always take precedence except if
// kEncryptedAndPlaintextValuesAreInvalid is enabled, in which case the cookie
// is dropped.
TEST_P(SQLitePersistentCookieStoreTestWithDropDupDataFeature,
       OverridePlaintextValue) {
  {
    CreateAndLoad(/*crypt_cookies=*/true,
                  /*restore_old_session_cookies=*/false);
    AddCookie("A", "B", "example.com", "/", base::Time::Now());
    AddCookie("C", "D", "example2.com", "/", base::Time::Now());
    AddCookie("E", "F", "example3.com", "/", base::Time::Now());
    DestroyStore();
  }
  {
    base::HistogramTester histogram_tester;
    auto cookies = CreateAndLoad(/*crypt_cookies=*/true,
                                 /*restore_old_session_cookies=*/false);
    ASSERT_EQ(cookies.size(), 3u);
    EXPECT_EQ(cookies[0]->Domain(), "example.com");
    EXPECT_EQ(cookies[0]->Name(), "A");
    EXPECT_EQ(cookies[0]->Value(), "B");
    EXPECT_EQ(cookies[1]->Domain(), "example2.com");
    EXPECT_EQ(cookies[1]->Name(), "C");
    EXPECT_EQ(cookies[1]->Value(), "D");
    EXPECT_EQ(cookies[2]->Domain(), "example3.com");
    EXPECT_EQ(cookies[2]->Name(), "E");
    EXPECT_EQ(cookies[2]->Value(), "F");
    DestroyStore();
  }
  {
    const base::FilePath database_path =
        temp_dir_.GetPath().Append(kCookieFilename);
    sql::Database connection;
    ASSERT_TRUE(connection.Open(database_path));
    sql::Transaction transaction(&connection);
    ASSERT_TRUE(transaction.Begin());
    // Clear the encrypted value and set the plaintext value to something else.
    ASSERT_TRUE(
        connection.Execute("UPDATE cookies SET encrypted_value=x'', "
                           "value='Val' WHERE host_key='example.com'"));
    // Verify also that an empty value can be injected.
    ASSERT_TRUE(
        connection.Execute("UPDATE cookies SET encrypted_value=x'', "
                           "value='' WHERE host_key='example2.com'"));
    // Verify if both are present, it's dealt with correctly (encrypted data
    // takes priority), and a histogram is recorded.
    ASSERT_TRUE(connection.Execute(
        "UPDATE cookies SET value='not-F' WHERE host_key='example3.com'"));
    ASSERT_TRUE(transaction.Commit());
  }
  {
    base::HistogramTester histogram_tester;
    auto cookies = CreateAndLoad(/*crypt_cookies=*/true,
                                 /*restore_old_session_cookies=*/false);
    histogram_tester.ExpectBucketCount("Cookie.EncryptedAndPlaintextValues",
                                       true, 1);

    // Third cookie (example3.com) should be dropped if
    // kEncryptedAndPlaintextValuesAreInvalid is enabled.
    ASSERT_EQ(cookies.size(), IsDroppingCookiesEnabled() ? 2u : 3u);
    // Cookie should load fine since it's been modified by writing plaintext and
    // clearing ciphertext.
    EXPECT_EQ(cookies[0]->Domain(), "example.com");
    EXPECT_EQ(cookies[0]->Name(), "A");
    EXPECT_EQ(cookies[0]->Value(), "Val");
    EXPECT_EQ(cookies[1]->Domain(), "example2.com");
    EXPECT_EQ(cookies[1]->Name(), "C");
    EXPECT_TRUE(cookies[1]->Value().empty());

    if (IsDroppingCookiesEnabled()) {
      // Cookie should be dropped and a metric recorded.
      histogram_tester.ExpectBucketCount(
          "Cookie.LoadProblem",
          /*CookieLoadProblem::kValuesExistInBothEncryptedAndPlaintext*/ 8, 1u);
    } else {
      // If the kEncryptedAndPlaintextValuesAreInvalid feature is disabled (and
      // the cookie was not dropped) then the final cookie should always use the
      // encrypted value and not the plaintext value.
      EXPECT_EQ(cookies[2]->Domain(), "example3.com");
      EXPECT_EQ(cookies[2]->Name(), "E");
      EXPECT_EQ(cookies[2]->Value(), "F");
      histogram_tester.ExpectTotalCount("Cookie.LoadProblem", 0);
    }
    DestroyStore();
  }
}

INSTANTIATE_TEST_SUITE_P(,
                         SQLitePersistentCookieStoreTestWithDropDupDataFeature,
                         ::testing::Bool(),
                         [](auto& info) {
                           return info.param ? "Enabled" : "Disabled";
                         });

}  // namespace net
```