Response:
The user wants a summary of the provided C++ code snippet, which is part of a unit test for the `SQLitePersistentCookieStore` in Chromium's networking stack.

Here's a breakdown of how to address the user's request:

1. **Identify the Core Functionality:** The code primarily tests the persistence of various cookie attributes using `SQLitePersistentCookieStore`. This involves adding cookies, saving them to disk, and then loading them back to verify if the attributes are correctly restored.

2. **List Key Tested Attributes:** Go through each `TEST_F` function and identify the cookie attributes being tested for persistence. These include:
    * `IsPersistent` (session vs. persistent cookies)
    * `Priority` (low, medium, high)
    * `SameSite` (None, Lax, Strict)
    * `SourcePort`
    * Encryption status
    * Handling of identical creation times
    * Resilience to key inconsistencies (though this test highlights a past issue)
    * Handling initialization failures
    * Operation coalescing
    * Exclusive access locking (Windows-specific)
    * Handling corrupted store files
    * Schema migrations (across different database versions)

3. **Note Absence of JavaScript Relation:**  Carefully review the code. There's no direct interaction with JavaScript. The tests focus on the internal workings of the cookie store.

4. **Illustrate Logic with Input/Output (where applicable):**  For tests like `IsPersistent`, `PriorityIsPersistent`, and `SameSiteIsPersistent`, we can describe the input cookies added and the expected output when the store is reloaded.

5. **Identify Potential User Errors:**  Think about how users or developers might interact with cookie storage and what could go wrong. This relates to corruption of the database file and issues with concurrent access (addressed by the exclusive locking tests).

6. **Describe User Actions Leading to This Code:** This code is for *unit testing*. Users don't directly reach this code through normal web browsing. The relevant scenario is a Chromium developer writing or running these tests to ensure the cookie store functions correctly.

7. **Focus on "Part 2" Aspect:**  The prompt explicitly mentions this is part 2 of 4. Therefore, the summary should reflect the tests contained within *this specific snippet*, and avoid drawing conclusions or summarizing the entire test suite.

8. **Structure the Summary:** Organize the findings into clear categories based on the user's request (functionality, JavaScript relation, logic with input/output, user errors, debugging).

**(Self-Correction/Refinement):**

* Initial thought: "This code tests cookie storage."  Refinement: Be more specific about *what aspects* of cookie storage are being tested (persistence of attributes).
* Initial thought on JavaScript: "Cookies are related to JavaScript." Refinement: While true in general, *this specific code* doesn't directly interact with JavaScript. It tests the C++ implementation of the cookie store.
* Initial thought on user errors: Focus on actions *affecting the storage itself*, not just general cookie-related browser issues.

By following these steps, a comprehensive and accurate summary can be generated.
这是对 `net/extras/sqlite/sqlite_persistent_cookie_store_unittest.cc` 文件中一部分代码的分析，主要集中在测试 `SQLitePersistentCookieStore` 的持久化能力，确保各种 Cookie 属性在存储到磁盘并重新加载后能够被正确恢复。

**功能归纳:**

这部分代码主要测试了 `SQLitePersistentCookieStore` 将 Cookie 的各种属性持久化到 SQLite 数据库，并在重新加载时正确恢复这些属性的能力。测试覆盖了以下 Cookie 属性的持久化：

* **IsPersistent 属性:** 测试了会话 Cookie（`IsPersistent` 为 false）和持久 Cookie（`IsPersistent` 为 true）在存储和加载后的状态是否一致。
* **Priority 属性:**  测试了不同优先级的 Cookie (LOW, MEDIUM, HIGH) 在存储和加载后优先级是否被正确保留。
* **SameSite 属性:** 测试了不同 `SameSite` 属性 (NO_RESTRICTION, LAX_MODE, STRICT_MODE) 的 Cookie 在存储和加载后 `SameSite` 的值是否正确。
* **SameSite Extended 属性处理:**  测试了当数据库中存在旧的 "Extended" `SameSite` 值时，`SQLitePersistentCookieStore` 会将其视为 UNSPECIFIED。
* **SourcePort 属性:** 测试了 Cookie 的 `SourcePort` 属性在存储和加载后是否被正确保存和恢复。
* **加密状态的更新:**  测试了从非加密的 Cookie 存储升级到加密的 Cookie 存储后，旧的 Cookie 能够被读取，并且新的 Cookie 会以加密形式存储。同时也验证了加密后的 Cookie 值在数据库文件中是不可见的。
* **相同创建时间的 Cookie 处理:** 测试了当多个 Cookie 具有相同的创建时间时，`SQLitePersistentCookieStore` 能够正确存储和加载它们。
* **处理密钥不一致的情况:**  这是一个回归测试，用于验证在特定情况下（例如，处理 "ftp" 协议的 Cookie），`SQLitePersistentCookieStore` 能否正确加载 Cookie。

**与 JavaScript 的关系 (间接):**

虽然这段 C++ 代码本身不直接与 JavaScript 交互，但它所测试的 `SQLitePersistentCookieStore` 组件是浏览器网络栈的一部分，负责管理和持久化 HTTP Cookie。这些 Cookie 通常由服务器通过 HTTP 响应的 `Set-Cookie` 头设置，并且可以通过 JavaScript 的 `document.cookie` API 进行访问和操作。

**举例说明:**

例如，在测试 `SameSiteIsPersistent` 的场景中，如果一个服务器设置了如下的 HTTP 响应头：

```
Set-Cookie: none=value; Domain=sessioncookie.com; Path=/
Set-Cookie: lax=value; Domain=sessioncookie.com; Path=/; SameSite=Lax
Set-Cookie: strict=value; Domain=sessioncookie.com; Path=/; SameSite=Strict
```

浏览器接收到这些响应后，`SQLitePersistentCookieStore` 会将这些 Cookie 存储到数据库中，并记录它们的 `SameSite` 属性。当浏览器重启后，JavaScript 代码可以使用 `document.cookie` 访问这些 Cookie，并期望它们保留之前设置的 `SameSite` 属性，从而影响浏览器在不同场景下发送这些 Cookie 的行为（例如跨站点请求）。

**逻辑推理 (假设输入与输出):**

**测试 `IsPersistentIsPersistent`:**

* **假设输入:**
    * 添加一个会话 Cookie (没有 `expires` 属性或 `Max-Age` 指令)。
    * 添加一个持久 Cookie (有 `expires` 属性)。
* **操作:** 关闭并重新打开 Cookie 存储。
* **预期输出:**
    * 加载的会话 Cookie 的 `IsPersistent()` 方法返回 `false`。
    * 加载的持久 Cookie 的 `IsPersistent()` 方法返回 `true`。

**测试 `PriorityIsPersistent`:**

* **假设输入:**
    * 添加一个优先级为 LOW 的持久 Cookie。
    * 添加一个优先级为 MEDIUM 的持久 Cookie。
    * 添加一个优先级为 HIGH 的持久 Cookie。
* **操作:** 关闭并重新打开 Cookie 存储。
* **预期输出:**
    * 加载的 LOW 优先级 Cookie 的 `Priority()` 方法返回 `COOKIE_PRIORITY_LOW`。
    * 加载的 MEDIUM 优先级 Cookie 的 `Priority()` 方法返回 `COOKIE_PRIORITY_MEDIUM`。
    * 加载的 HIGH 优先级 Cookie 的 `Priority()` 方法返回 `COOKIE_PRIORITY_HIGH`。

**涉及用户或编程常见的使用错误:**

* **数据库文件损坏:** 用户的磁盘错误或者程序异常可能导致 SQLite 数据库文件损坏。`TEST_F(SQLitePersistentCookieStoreTest, CorruptStore)` 测试了这种情况，表明当检测到数据库损坏时，Cookie 存储会尝试处理这种情况，但可能会丢失 Cookie 数据。
* **并发访问冲突 (Windows 特有):** 在 Windows 系统上，如果其他进程正在访问 Cookie 数据库文件，并且启用了独占访问模式，则 `SQLitePersistentCookieStore` 初始化可能会失败。`TEST_P(SQLitePersistentCookieStoreExclusiveAccessTest, LockedStoreAlreadyOpen)` 模拟了这种情况。
* **错误的数据库升级逻辑:** 如果在 Chromium 更新过程中，Cookie 数据库的 schema 需要升级，但升级逻辑存在错误，可能导致数据丢失或不一致。代码中包含了一些测试不同数据库 schema 版本的函数 (`CreateV18Schema`, `CreateV20Schema`, `CreateV21Schema`)，这暗示了对数据库 schema 迁移的关注。

**用户操作如何一步步的到达这里，作为调试线索:**

作为调试线索，用户操作如何一步步到达这里需要理解 Chromium 中 Cookie 的存储流程：

1. **用户浏览网页或执行网络请求:** 当用户访问一个网站或者执行一个涉及 HTTP 请求的操作时，服务器可能会通过 `Set-Cookie` 头在响应中设置 Cookie。
2. **网络栈接收 Cookie:** Chromium 的网络栈接收到这些 `Set-Cookie` 指令。
3. **CookieMonster 处理 Cookie:**  `CookieMonster` 类负责管理内存中的 Cookie，并决定是否应该持久化这些 Cookie。
4. **SQLitePersistentCookieStore 写入数据库:** 如果 Cookie 需要持久化（例如，非会话 Cookie），`CookieMonster` 会调用 `SQLitePersistentCookieStore` 的方法（例如 `AddCookie`）将 Cookie 信息写入 SQLite 数据库。
5. **关闭浏览器或重启:** 当浏览器关闭或者重启时，内存中的 Cookie 数据会丢失，但持久化的 Cookie 数据仍然保存在 SQLite 数据库中。
6. **启动浏览器:** 当浏览器再次启动时，`SQLitePersistentCookieStore` 会从 SQLite 数据库中读取 Cookie 数据，并加载到 `CookieMonster` 中。

因此，当开发者调试 Cookie 持久化相关的问题时，他们可能会关注以下步骤：

* **检查 `Set-Cookie` 头:** 确认服务器是否正确设置了 Cookie，包括各种属性 (例如，`expires`, `Max-Age`, `SameSite`)。
* **检查 `CookieMonster` 的行为:** 确认 `CookieMonster` 是否正确地接收和处理了 Cookie，并决定是否需要持久化。
* **检查 `SQLitePersistentCookieStore` 的日志:**  查看 `SQLitePersistentCookieStore` 在写入和读取数据库时的日志，确认是否有任何错误发生。
* **使用 SQLite 工具查看数据库内容:** 开发者可以使用 SQLite 客户端工具（例如 `sqlite3`) 直接打开 Cookie 数据库文件（通常名为 `Cookies`），查看表结构和数据，验证 Cookie 是否按照预期存储。
* **运行单元测试:** 运行 `sqlite_persistent_cookie_store_unittest.cc` 中的单元测试，确保 `SQLitePersistentCookieStore` 的各种功能正常工作，并且 Cookie 的属性能够正确持久化和恢复。

**总结 (针对第 2 部分):**

这部分代码专注于测试 `SQLitePersistentCookieStore` 的核心功能：**持久化存储和正确恢复各种关键的 Cookie 属性**。它通过创建不同类型的 Cookie，强制存储到磁盘，然后重新加载并验证这些属性是否被完整保留，从而确保了 Cookie 存储的可靠性和数据一致性。 这部分测试还涵盖了从非加密存储迁移到加密存储的情况，以及对一些潜在错误场景的处理，例如数据库损坏和并发访问冲突。

### 提示词
```
这是目录为net/extras/sqlite/sqlite_persistent_cookie_store_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
xpiration=*/base::Time(), /*last_access=*/base::Time(),
      /*last_update=*/base::Time(), /*secure=*/false, /*httponly=*/false,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT));
  // Add a persistent cookie.
  store_->AddCookie(*CanonicalCookie::CreateUnsafeCookieForTesting(
      kPersistentName, "val", "sessioncookie.com", "/",
      /*creation=*/base::Time::Now() - base::Days(1),
      /*expiration=*/base::Time::Now() + base::Days(1),
      /*last_access=*/base::Time(), /*last_update=*/base::Time(),
      /*secure=*/false, /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT));

  // Force the store to write its data to the disk.
  DestroyStore();

  // Create a store that loads session cookie and test that the IsPersistent
  // attribute is restored.
  CanonicalCookieVector cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/true);
  ASSERT_EQ(2U, cookies.size());

  std::map<std::string, CanonicalCookie*> cookie_map;
  for (const auto& cookie : cookies)
    cookie_map[cookie->Name()] = cookie.get();

  auto it = cookie_map.find(kSessionName);
  ASSERT_TRUE(it != cookie_map.end());
  EXPECT_FALSE(cookie_map[kSessionName]->IsPersistent());

  it = cookie_map.find(kPersistentName);
  ASSERT_TRUE(it != cookie_map.end());
  EXPECT_TRUE(cookie_map[kPersistentName]->IsPersistent());
}

TEST_F(SQLitePersistentCookieStoreTest, PriorityIsPersistent) {
  static const char kDomain[] = "sessioncookie.com";
  static const char kLowName[] = "low";
  static const char kMediumName[] = "medium";
  static const char kHighName[] = "high";
  static const char kCookieValue[] = "value";
  static const char kCookiePath[] = "/";

  InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/true);

  // Add a low-priority persistent cookie.
  store_->AddCookie(*CanonicalCookie::CreateUnsafeCookieForTesting(
      kLowName, kCookieValue, kDomain, kCookiePath,
      /*creation=*/base::Time::Now() - base::Minutes(1),
      /*expiration=*/base::Time::Now() + base::Days(1),
      /*last_access=*/base::Time(), /*last_update=*/base::Time(),
      /*secure=*/false, /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_LOW));

  // Add a medium-priority persistent cookie.
  store_->AddCookie(*CanonicalCookie::CreateUnsafeCookieForTesting(
      kMediumName, kCookieValue, kDomain, kCookiePath,
      /*creation=*/base::Time::Now() - base::Minutes(2),
      /*expiration=*/base::Time::Now() + base::Days(1),
      /*last_access=*/base::Time(), /*last_update=*/base::Time(),
      /*secure=*/false, /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_MEDIUM));

  // Add a high-priority persistent cookie.
  store_->AddCookie(*CanonicalCookie::CreateUnsafeCookieForTesting(
      kHighName, kCookieValue, kDomain, kCookiePath,
      /*creation=*/base::Time::Now() - base::Minutes(3),
      /*expiration=*/base::Time::Now() + base::Days(1),
      /*last_access=*/base::Time(), /*last_update=*/base::Time(),
      /*secure=*/false, /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_HIGH));

  // Force the store to write its data to the disk.
  DestroyStore();

  // Create a store that loads session cookie and test that the priority
  // attribute values are restored.
  CanonicalCookieVector cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/true);
  ASSERT_EQ(3U, cookies.size());

  // Put the cookies into a map, by name, so we can easily find them.
  std::map<std::string, CanonicalCookie*> cookie_map;
  for (const auto& cookie : cookies)
    cookie_map[cookie->Name()] = cookie.get();

  // Validate that each cookie has the correct priority.
  auto it = cookie_map.find(kLowName);
  ASSERT_TRUE(it != cookie_map.end());
  EXPECT_EQ(COOKIE_PRIORITY_LOW, cookie_map[kLowName]->Priority());

  it = cookie_map.find(kMediumName);
  ASSERT_TRUE(it != cookie_map.end());
  EXPECT_EQ(COOKIE_PRIORITY_MEDIUM, cookie_map[kMediumName]->Priority());

  it = cookie_map.find(kHighName);
  ASSERT_TRUE(it != cookie_map.end());
  EXPECT_EQ(COOKIE_PRIORITY_HIGH, cookie_map[kHighName]->Priority());
}

TEST_F(SQLitePersistentCookieStoreTest, SameSiteIsPersistent) {
  const char kDomain[] = "sessioncookie.com";
  const char kNoneName[] = "none";
  const char kLaxName[] = "lax";
  const char kStrictName[] = "strict";
  const char kCookieValue[] = "value";
  const char kCookiePath[] = "/";

  InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/true);

  // Add a non-samesite persistent cookie.
  store_->AddCookie(*CanonicalCookie::CreateUnsafeCookieForTesting(
      kNoneName, kCookieValue, kDomain, kCookiePath,
      /*creation=*/base::Time::Now() - base::Minutes(1),
      /*expiration=*/base::Time::Now() + base::Days(1),
      /*last_access=*/base::Time(), /*last_update=*/base::Time(),
      /*secure=*/false, /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT));

  // Add a lax-samesite persistent cookie.
  store_->AddCookie(*CanonicalCookie::CreateUnsafeCookieForTesting(
      kLaxName, kCookieValue, kDomain, kCookiePath,
      /*creation=*/base::Time::Now() - base::Minutes(2),
      /*expiration=*/base::Time::Now() + base::Days(1),
      /*last_access=*/base::Time(), /*last_update=*/base::Time(),
      /*secure=*/false, /*httponly=*/false, CookieSameSite::LAX_MODE,
      COOKIE_PRIORITY_DEFAULT));

  // Add a strict-samesite persistent cookie.
  store_->AddCookie(*CanonicalCookie::CreateUnsafeCookieForTesting(
      kStrictName, kCookieValue, kDomain, kCookiePath,
      /*creation=*/base::Time::Now() - base::Minutes(3),
      /*expiration=*/base::Time::Now() + base::Days(1),
      /*last_access=*/base::Time(), /*last_update=*/base::Time(),
      /*secure=*/false, /*httponly=*/false, CookieSameSite::STRICT_MODE,
      COOKIE_PRIORITY_DEFAULT));

  // Force the store to write its data to the disk.
  DestroyStore();

  // Create a store that loads session cookie and test that the SameSite
  // attribute values are restored.
  CanonicalCookieVector cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/true);
  ASSERT_EQ(3U, cookies.size());

  // Put the cookies into a map, by name, for comparison below.
  std::map<std::string, CanonicalCookie*> cookie_map;
  for (const auto& cookie : cookies)
    cookie_map[cookie->Name()] = cookie.get();

  // Validate that each cookie has the correct SameSite.
  ASSERT_EQ(1u, cookie_map.count(kNoneName));
  EXPECT_EQ(CookieSameSite::NO_RESTRICTION, cookie_map[kNoneName]->SameSite());

  ASSERT_EQ(1u, cookie_map.count(kLaxName));
  EXPECT_EQ(CookieSameSite::LAX_MODE, cookie_map[kLaxName]->SameSite());

  ASSERT_EQ(1u, cookie_map.count(kStrictName));
  EXPECT_EQ(CookieSameSite::STRICT_MODE, cookie_map[kStrictName]->SameSite());
}

TEST_F(SQLitePersistentCookieStoreTest, SameSiteExtendedTreatedAsUnspecified) {
  constexpr char kDomain[] = "sessioncookie.com";
  constexpr char kExtendedName[] = "extended";
  constexpr char kCookieValue[] = "value";
  constexpr char kCookiePath[] = "/";

  InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/true);

  // Add an extended-samesite persistent cookie by first adding a strict-same
  // site cookie, then turning that into the legacy extended-samesite state with
  // direct SQL DB access.
  store_->AddCookie(*CanonicalCookie::CreateUnsafeCookieForTesting(
      kExtendedName, kCookieValue, kDomain, kCookiePath,
      /*creation=*/base::Time::Now() - base::Minutes(1),
      /*expiration=*/base::Time::Now() + base::Days(1),
      /*last_access=*/base::Time(), /*last_update=*/base::Time(),
      /*secure=*/false, /*httponly=*/false, CookieSameSite::STRICT_MODE,
      COOKIE_PRIORITY_DEFAULT));

  // Force the store to write its data to the disk.
  DestroyStore();

  // Open db.
  sql::Database connection;
  ASSERT_TRUE(connection.Open(temp_dir_.GetPath().Append(kCookieFilename)));
  std::string update_stmt(
      "UPDATE cookies SET samesite=3"  // 3 is Extended.
      " WHERE samesite=2"              // 2 is Strict.
  );
  ASSERT_TRUE(connection.Execute(update_stmt));
  connection.Close();

  // Create a store that loads session cookie and test that the
  // SameSite=Extended attribute values is ignored.
  CanonicalCookieVector cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/true);
  ASSERT_EQ(1U, cookies.size());

  // Validate that the cookie has the correct SameSite.
  EXPECT_EQ(kExtendedName, cookies[0]->Name());
  EXPECT_EQ(CookieSameSite::UNSPECIFIED, cookies[0]->SameSite());
}

TEST_F(SQLitePersistentCookieStoreTest, SourcePortIsPersistent) {
  const char kDomain[] = "sessioncookie.com";
  const char kCookieValue[] = "value";
  const char kCookiePath[] = "/";

  struct CookieTestValues {
    std::string name;
    int port;
  };

  const std::vector<CookieTestValues> kTestCookies = {
      {"1", 80},
      {"2", 443},
      {"3", 1234},
      {"4", url::PORT_UNSPECIFIED},
      {"5", url::PORT_INVALID}};

  InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/true);

  for (const auto& input : kTestCookies) {
    // Add some persistent cookies.
    store_->AddCookie(*CanonicalCookie::CreateUnsafeCookieForTesting(
        input.name, kCookieValue, kDomain, kCookiePath,
        /*creation=*/base::Time::Now() - base::Minutes(1),
        /*expiration=*/base::Time::Now() + base::Days(1),
        /*last_access=*/base::Time(), /*last_update=*/base::Time(),
        /*secure=*/true, /*httponly=*/false, CookieSameSite::LAX_MODE,
        COOKIE_PRIORITY_DEFAULT,
        /*partition_key=*/std::nullopt,
        CookieSourceScheme::kUnset /* Doesn't matter for this test. */,
        input.port));
  }

  // Force the store to write its data to the disk.
  DestroyStore();

  // Create a store that loads session cookie and test that the source_port
  // attribute values are restored.
  CanonicalCookieVector cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/true);
  ASSERT_EQ(kTestCookies.size(), cookies.size());

  // Put the cookies into a map, by name, for comparison below.
  std::map<std::string, CanonicalCookie*> cookie_map;
  for (const auto& cookie : cookies)
    cookie_map[cookie->Name()] = cookie.get();

  for (const auto& expected : kTestCookies) {
    ASSERT_EQ(1u, cookie_map.count(expected.name));
    ASSERT_EQ(expected.port, cookie_map[expected.name]->SourcePort());
  }
}

TEST_F(SQLitePersistentCookieStoreTest, UpdateToEncryption) {

  // Create unencrypted cookie store and write something to it.
  InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/false);
  AddCookie("name", "value123XYZ", "foo.bar", "/", base::Time::Now());
  DestroyStore();

  // Verify that "value" is visible in the file.  This is necessary in order to
  // have confidence in a later test that "encrypted_value" is not visible.
  std::string contents = ReadRawDBContents();
  EXPECT_NE(0U, contents.length());
  EXPECT_NE(contents.find("value123XYZ"), std::string::npos);

  // Create encrypted cookie store and ensure old cookie still reads.
  CanonicalCookieVector cookies = CreateAndLoad(
      /*crypt_cookies=*/true, /*restore_old_session_cookies=*/false);
  EXPECT_EQ(1U, cookies.size());
  EXPECT_EQ("name", cookies[0]->Name());
  EXPECT_EQ("value123XYZ", cookies[0]->Value());

  // Make sure we can update existing cookie and add new cookie as encrypted.
  store_->DeleteCookie(*(cookies[0]));
  AddCookie("name", "encrypted_value123XYZ", "foo.bar", "/", base::Time::Now());
  AddCookie("other", "something456ABC", "foo.bar", "/",
            base::Time::Now() + base::Microseconds(10));
  DestroyStore();
  cookies = CreateAndLoad(/*crypt_cookies=*/true,
                          /*restore_old_session_cookies=*/false);
  EXPECT_EQ(2U, cookies.size());
  CanonicalCookie* cookie_name = nullptr;
  CanonicalCookie* cookie_other = nullptr;
  if (cookies[0]->Name() == "name") {
    cookie_name = cookies[0].get();
    cookie_other = cookies[1].get();
  } else {
    cookie_name = cookies[1].get();
    cookie_other = cookies[0].get();
  }
  EXPECT_EQ("encrypted_value123XYZ", cookie_name->Value());
  EXPECT_EQ("something456ABC", cookie_other->Value());
  DestroyStore();

  // Examine the real record to make sure plaintext version doesn't exist.
  sql::Database db;
  sql::Statement smt;

  ASSERT_TRUE(db.Open(temp_dir_.GetPath().Append(kCookieFilename)));
  smt.Assign(db.GetCachedStatement(SQL_FROM_HERE,
                                   "SELECT * "
                                   "FROM cookies "
                                   "WHERE host_key = 'foo.bar'"));
  int resultcount = 0;
  for (; smt.Step(); ++resultcount) {
    for (int i = 0; i < smt.ColumnCount(); i++) {
      EXPECT_EQ(smt.ColumnString(i).find("value"), std::string::npos);
      EXPECT_EQ(smt.ColumnString(i).find("something"), std::string::npos);
    }
  }
  EXPECT_EQ(2, resultcount);

  // Verify that "encrypted_value" is NOT visible in the file.
  contents = ReadRawDBContents();
  EXPECT_NE(0U, contents.length());
  EXPECT_EQ(contents.find("encrypted_value123XYZ"), std::string::npos);
  EXPECT_EQ(contents.find("something456ABC"), std::string::npos);
}

bool CompareCookies(const std::unique_ptr<CanonicalCookie>& a,
                    const std::unique_ptr<CanonicalCookie>& b) {
  return a->PartialCompare(*b);
}

// Confirm the store can handle having cookies with identical creation
// times stored in it.
TEST_F(SQLitePersistentCookieStoreTest, IdenticalCreationTimes) {
  InitializeStore(/*crypt=*/false, /*restore_old_session_cookies=*/false);
  base::Time cookie_time(base::Time::Now());
  base::Time cookie_expiry(cookie_time + base::Days(1));
  AddCookieWithExpiration("A", "B", "example.com", "/", cookie_time,
                          cookie_expiry);
  AddCookieWithExpiration("C", "B", "example.com", "/", cookie_time,
                          cookie_expiry);
  AddCookieWithExpiration("A", "B", "example2.com", "/", cookie_time,
                          cookie_expiry);
  AddCookieWithExpiration("C", "B", "example2.com", "/", cookie_time,
                          cookie_expiry);
  AddCookieWithExpiration("A", "B", "example.com", "/path", cookie_time,
                          cookie_expiry);
  AddCookieWithExpiration("C", "B", "example.com", "/path", cookie_time,
                          cookie_expiry);
  Flush();
  DestroyStore();

  CanonicalCookieVector read_in_cookies = CreateAndLoad(
      /*crypt_cookies=*/false, /*restore_old_session_cookies=*/false);
  ASSERT_EQ(6u, read_in_cookies.size());

  std::sort(read_in_cookies.begin(), read_in_cookies.end(), &CompareCookies);
  int i = 0;
  EXPECT_EQ("A", read_in_cookies[i]->Name());
  EXPECT_EQ("example.com", read_in_cookies[i]->Domain());
  EXPECT_EQ("/", read_in_cookies[i]->Path());

  i++;
  EXPECT_EQ("A", read_in_cookies[i]->Name());
  EXPECT_EQ("example.com", read_in_cookies[i]->Domain());
  EXPECT_EQ("/path", read_in_cookies[i]->Path());

  i++;
  EXPECT_EQ("A", read_in_cookies[i]->Name());
  EXPECT_EQ("example2.com", read_in_cookies[i]->Domain());
  EXPECT_EQ("/", read_in_cookies[i]->Path());

  i++;
  EXPECT_EQ("C", read_in_cookies[i]->Name());
  EXPECT_EQ("example.com", read_in_cookies[i]->Domain());
  EXPECT_EQ("/", read_in_cookies[i]->Path());

  i++;
  EXPECT_EQ("C", read_in_cookies[i]->Name());
  EXPECT_EQ("example.com", read_in_cookies[i]->Domain());
  EXPECT_EQ("/path", read_in_cookies[i]->Path());

  i++;
  EXPECT_EQ("C", read_in_cookies[i]->Name());
  EXPECT_EQ("example2.com", read_in_cookies[i]->Domain());
  EXPECT_EQ("/", read_in_cookies[i]->Path());
}

TEST_F(SQLitePersistentCookieStoreTest, KeyInconsistency) {
  // Regression testcase for previous disagreement between CookieMonster
  // and SQLitePersistentCookieStoreTest as to what keys to LoadCookiesForKey
  // mean. The particular example doesn't, of course, represent an actual in-use
  // scenario, but while the inconstancy could happen with chrome-extension
  // URLs in real life, it was irrelevant for them in practice since their
  // rows would get key = "" which would get sorted before actual domains,
  // and therefore get loaded first by CookieMonster::FetchAllCookiesIfNecessary
  // with the task runners involved ensuring that would finish before the
  // incorrect LoadCookiesForKey got the chance to run.
  //
  // This test uses a URL that used to be treated differently by the two
  // layers that also sorts after other rows to avoid this scenario.

  // SQLitePersistentCookieStore will run its callbacks on what's passed to it
  // as |client_task_runner|, and CookieMonster expects to get callbacks from
  // its PersistentCookieStore on the same thread as its methods are invoked on;
  // so to avoid needing to post every CookieMonster API call, this uses the
  // current thread for SQLitePersistentCookieStore's |client_task_runner|.
  // Note: Cookie encryption is explicitly enabled here to verify threading
  // model with async initialization functions correctly.
  Create(/*crypt_cookies=*/true, /*restore_old_session_cookies=*/false,
         /*use_current_thread=*/true, /*enable_exclusive_access=*/false);

  // Create a cookie on a scheme that doesn't handle cookies by default,
  // and save it.
  std::unique_ptr<CookieMonster> cookie_monster =
      std::make_unique<CookieMonster>(store_.get(), /*net_log=*/nullptr);
  ResultSavingCookieCallback<bool> cookie_scheme_callback1;
  cookie_monster->SetCookieableSchemes({"ftp", "http"},
                                       cookie_scheme_callback1.MakeCallback());
  cookie_scheme_callback1.WaitUntilDone();
  EXPECT_TRUE(cookie_scheme_callback1.result());
  ResultSavingCookieCallback<CookieAccessResult> set_cookie_callback;
  GURL ftp_url("ftp://subdomain.ftperiffic.com/page/");
  auto cookie = CanonicalCookie::CreateForTesting(ftp_url, "A=B; max-age=3600",
                                                  base::Time::Now());
  cookie_monster->SetCanonicalCookieAsync(std::move(cookie), ftp_url,
                                          CookieOptions::MakeAllInclusive(),
                                          set_cookie_callback.MakeCallback());
  set_cookie_callback.WaitUntilDone();
  EXPECT_TRUE(set_cookie_callback.result().status.IsInclude());

  // Also insert a whole bunch of cookies to slow down the background loading of
  // all the cookies.
  for (int i = 0; i < 50; ++i) {
    ResultSavingCookieCallback<CookieAccessResult> set_cookie_callback2;
    GURL url(base::StringPrintf("http://example%d.com/", i));
    auto canonical_cookie = CanonicalCookie::CreateForTesting(
        url, "A=B; max-age=3600", base::Time::Now());
    cookie_monster->SetCanonicalCookieAsync(
        std::move(canonical_cookie), url, CookieOptions::MakeAllInclusive(),
        set_cookie_callback2.MakeCallback());
    set_cookie_callback2.WaitUntilDone();
    EXPECT_TRUE(set_cookie_callback2.result().status.IsInclude());
  }

  net::TestClosure flush_closure;
  cookie_monster->FlushStore(flush_closure.closure());
  flush_closure.WaitForResult();
  cookie_monster = nullptr;

  // Re-create the PersistentCookieStore & CookieMonster. Note that the
  // destroyed store's ops will happen on same runners as the previous
  // instances, so they should complete before the new PersistentCookieStore
  // starts looking at the state on disk.
  Create(/*crypt_cookies=*/true, /*restore_old_session_cookies=*/false,
         /*use_current_thread=*/true, /*enable_exclusive_access=*/false);
  cookie_monster =
      std::make_unique<CookieMonster>(store_.get(), /*net_log=*/nullptr);
  ResultSavingCookieCallback<bool> cookie_scheme_callback2;
  cookie_monster->SetCookieableSchemes({"ftp", "http"},
                                       cookie_scheme_callback2.MakeCallback());
  cookie_scheme_callback2.WaitUntilDone();
  EXPECT_TRUE(cookie_scheme_callback2.result());

  // Now try to get the cookie back.
  GetCookieListCallback get_callback;
  cookie_monster->GetCookieListWithOptionsAsync(
      GURL("ftp://subdomain.ftperiffic.com/page"),
      CookieOptions::MakeAllInclusive(), CookiePartitionKeyCollection(),
      base::BindOnce(&GetCookieListCallback::Run,
                     base::Unretained(&get_callback)));
  get_callback.WaitUntilDone();
  ASSERT_EQ(1u, get_callback.cookies().size());
  EXPECT_EQ("A", get_callback.cookies()[0].Name());
  EXPECT_EQ("B", get_callback.cookies()[0].Value());
  EXPECT_EQ("subdomain.ftperiffic.com", get_callback.cookies()[0].Domain());
}

TEST_F(SQLitePersistentCookieStoreTest, OpsIfInitFailed) {
  // Test to make sure we don't leak pending operations when initialization
  // fails really hard. To inject the failure, we put a directory where the
  // database file ought to be. This test relies on an external leak checker
  // (e.g. lsan) to actual catch thing.
  ASSERT_TRUE(
      base::CreateDirectory(temp_dir_.GetPath().Append(kCookieFilename)));
  Create(/*crypt_cookies=*/false, /*restore_old_session_cookies=*/false,
         /*use_current_thread=*/true,
         /*enable_exclusive_access=*/false);
  std::unique_ptr<CookieMonster> cookie_monster =
      std::make_unique<CookieMonster>(store_.get(), /*net_log=*/nullptr);

  ResultSavingCookieCallback<CookieAccessResult> set_cookie_callback;
  GURL url("http://www.example.com/");
  auto cookie = CanonicalCookie::CreateForTesting(url, "A=B; max-age=3600",
                                                  base::Time::Now());
  cookie_monster->SetCanonicalCookieAsync(std::move(cookie), url,
                                          CookieOptions::MakeAllInclusive(),
                                          set_cookie_callback.MakeCallback());
  set_cookie_callback.WaitUntilDone();
  EXPECT_TRUE(set_cookie_callback.result().status.IsInclude());

  // Things should commit once going out of scope.
  expect_init_errors_ = true;
}

TEST_F(SQLitePersistentCookieStoreTest, Coalescing) {
  enum class Op { kAdd, kDelete, kUpdate };

  struct TestCase {
    std::vector<Op> operations;
    size_t expected_queue_length;
  };

  std::vector<TestCase> testcases = {
      {{Op::kAdd, Op::kDelete}, 1u},
      {{Op::kUpdate, Op::kDelete}, 1u},
      {{Op::kAdd, Op::kUpdate, Op::kDelete}, 1u},
      {{Op::kUpdate, Op::kUpdate}, 1u},
      {{Op::kAdd, Op::kUpdate, Op::kUpdate}, 2u},
      {{Op::kDelete, Op::kAdd}, 2u},
      {{Op::kDelete, Op::kAdd, Op::kUpdate}, 3u},
      {{Op::kDelete, Op::kAdd, Op::kUpdate, Op::kUpdate}, 3u},
      {{Op::kDelete, Op::kDelete}, 1u},
      {{Op::kDelete, Op::kAdd, Op::kDelete}, 1u},
      {{Op::kDelete, Op::kAdd, Op::kUpdate, Op::kDelete}, 1u}};

  std::unique_ptr<CanonicalCookie> cookie = CanonicalCookie::CreateForTesting(
      GURL("http://www.example.com/path"), "Tasty=Yes", base::Time::Now());

  for (const TestCase& testcase : testcases) {
    Create(/*crypt_cookies=*/false, /*restore_old_session_cookies=*/false,
           /*use_current_thread=*/true,
           /*enable_exclusive_access=*/false);

    base::RunLoop run_loop;
    store_->Load(base::BindLambdaForTesting(
                     [&](CanonicalCookieVector cookies) { run_loop.Quit(); }),
                 NetLogWithSource());
    run_loop.Run();

    // Wedge the background thread to make sure that it doesn't start consuming
    // the queue.
    background_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&SQLitePersistentCookieStoreTest::WaitOnDBEvent,
                       base::Unretained(this)));

    // Now run the ops, and check how much gets queued.
    for (const Op op : testcase.operations) {
      switch (op) {
        case Op::kAdd:
          store_->AddCookie(*cookie);
          break;

        case Op::kDelete:
          store_->DeleteCookie(*cookie);
          break;

        case Op::kUpdate:
          store_->UpdateCookieAccessTime(*cookie);
          break;
      }
    }

    EXPECT_EQ(testcase.expected_queue_length,
              store_->GetQueueLengthForTesting());

    db_thread_event_.Signal();
    DestroyStore();
  }
}

TEST_F(SQLitePersistentCookieStoreTest, NoCoalesceUnrelated) {
  Create(/*crypt_cookies=*/false, /*restore_old_session_cookies=*/false,
         /*use_current_thread=*/true,
         /*enable_exclusive_access=*/false);

  base::RunLoop run_loop;
  store_->Load(base::BindLambdaForTesting(
                   [&](CanonicalCookieVector cookies) { run_loop.Quit(); }),
               NetLogWithSource());
  run_loop.Run();

  std::unique_ptr<CanonicalCookie> cookie1 = CanonicalCookie::CreateForTesting(
      GURL("http://www.example.com/path"), "Tasty=Yes", base::Time::Now());

  std::unique_ptr<CanonicalCookie> cookie2 = CanonicalCookie::CreateForTesting(
      GURL("http://not.example.com/path"), "Tasty=No", base::Time::Now());

  // Wedge the background thread to make sure that it doesn't start consuming
  // the queue.
  background_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&SQLitePersistentCookieStoreTest::WaitOnDBEvent,
                                base::Unretained(this)));

  store_->AddCookie(*cookie1);
  store_->DeleteCookie(*cookie2);
  // delete on cookie2 shouldn't cancel op on unrelated cookie1.
  EXPECT_EQ(2u, store_->GetQueueLengthForTesting());

  db_thread_event_.Signal();
}

// Locking is only supported on Windows.
#if BUILDFLAG(IS_WIN)

class SQLitePersistentCookieStoreExclusiveAccessTest
    : public SQLitePersistentCookieStoreTest,
      public ::testing::WithParamInterface<bool> {
 protected:
  const bool& ShouldBeExclusive() { return GetParam(); }
};

TEST_P(SQLitePersistentCookieStoreExclusiveAccessTest, LockedStore) {
  Create(/*crypt_cookies=*/false, /*restore_old_session_cookies=*/false,
         /*use_current_thread=*/true,
         /*enable_exclusive_access=*/ShouldBeExclusive());

  base::RunLoop run_loop;
  store_->Load(base::BindLambdaForTesting(
                   [&](CanonicalCookieVector cookies) { run_loop.Quit(); }),
               NetLogWithSource());
  run_loop.Run();

  std::unique_ptr<CanonicalCookie> cookie = CanonicalCookie::CreateForTesting(
      GURL("http://www.example.com/path"), "Tasty=Yes", base::Time::Now());

  // Wedge the background thread to make sure that it doesn't start consuming
  // the queue.
  background_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&SQLitePersistentCookieStoreTest::WaitOnDBEvent,
                                base::Unretained(this)));

  store_->AddCookie(*cookie);

  {
    base::File file(
        temp_dir_.GetPath().Append(kCookieFilename),
        base::File::Flags::FLAG_OPEN_ALWAYS | base::File::Flags::FLAG_READ);
    // If locked, should not be able to open file even for read.
    EXPECT_EQ(ShouldBeExclusive(), !file.IsValid());
  }

  db_thread_event_.Signal();
}

TEST_P(SQLitePersistentCookieStoreExclusiveAccessTest, LockedStoreAlreadyOpen) {
  base::HistogramTester histograms;
  base::File file(
      temp_dir_.GetPath().Append(kCookieFilename),
      base::File::Flags::FLAG_CREATE | base::File::Flags::FLAG_READ);
  ASSERT_TRUE(file.IsValid());

  Create(/*crypt_cookies=*/false, /*restore_old_session_cookies=*/false,
         /*use_current_thread=*/true,
         /*enable_exclusive_access=*/ShouldBeExclusive());

  base::RunLoop run_loop;
  store_->Load(base::BindLambdaForTesting(
                   [&](CanonicalCookieVector cookies) { run_loop.Quit(); }),
               NetLogWithSource());
  run_loop.Run();

  // Note: The non-exclusive path is verified in the TearDown for the fixture.
  if (ShouldBeExclusive()) {
    expect_init_errors_ = true;
    histograms.ExpectUniqueSample("Cookie.ErrorInitializeDB",
                                  sql::SqliteLoggedResultCode::kCantOpen, 1);
    histograms.ExpectUniqueSample("Cookie.WinGetLastErrorInitializeDB",
                                  ERROR_SHARING_VIOLATION, 1);
  }
}

INSTANTIATE_TEST_SUITE_P(All,
                         SQLitePersistentCookieStoreExclusiveAccessTest,
                         ::testing::Bool(),
                         [](const auto& info) {
                           return info.param ? "Exclusive" : "NotExclusive";
                         });

#endif  // BUILDFLAG(IS_WIN)

TEST_F(SQLitePersistentCookieStoreTest, CorruptStore) {
  base::HistogramTester histograms;
  base::WriteFile(temp_dir_.GetPath().Append(kCookieFilename),
                  "SQLite format 3 foobarfoobarfoobar");

  Create(/*crypt_cookies=*/false, /*restore_old_session_cookies=*/false,
         /*use_current_thread=*/true,
         /*enable_exclusive_access=*/false);

  base::RunLoop run_loop;
  store_->Load(base::BindLambdaForTesting(
                   [&](CanonicalCookieVector cookies) { run_loop.Quit(); }),
               NetLogWithSource());
  run_loop.Run();

  expect_init_errors_ = true;
  histograms.ExpectUniqueSample("Cookie.ErrorInitializeDB",
                                sql::SqliteLoggedResultCode::kNotADatabase, 1);
}

bool CreateV18Schema(sql::Database* db) {
  sql::MetaTable meta_table;
  if (!meta_table.Init(db, 18, 18)) {
    return false;
  }

  // Version 18 schema
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
      "is_same_party INTEGER NOT NULL,"
      "last_update_utc INTEGER NOT NULL,"
      "UNIQUE (host_key, top_frame_site_key, name, path))";

  static constexpr char kCreateIndexSql[] =
      "CREATE UNIQUE INDEX cookies_unique_index "
      "ON cookies(host_key, top_frame_site_key, name, path)";

  return db->Execute(kCreateSql) && db->Execute(kCreateIndexSql);
}

bool CreateV20Schema(sql::Database* db) {
  sql::MetaTable meta_table;
  if (!meta_table.Init(db, 20, 20)) {
    return false;
  }

  // Version 20 schema
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
      "is_same_party INTEGER NOT NULL,"
      "last_update_utc INTEGER NOT NULL,"
      "UNIQUE (host_key, top_frame_site_key, name, path, source_scheme, "
      "source_port))";

  static constexpr char kCreateIndexSql[] =
      "CREATE UNIQUE INDEX cookies_unique_index "
      "ON cookies(host_key, top_frame_site_key, name, path, source_scheme, "
      "source_port)";

  return db->Execute(kCreateSql) && db->Execute(kCreateIndexSql);
}

bool CreateV21Schema(sql::Database* db) {
  sql::MetaTable meta_table;
  if (!meta_table.Init(db, 21, 21)) {
    return false;
  }

  // Version 21 schema
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
      "UNIQUE (host_key, top_frame_site_key, name, path, source_scheme, "
      "source_port))";

  static constexpr char kCreateIndexSql[] =
      "CREATE UNIQUE INDEX cookies_unique_index "
      "ON cookies(host_key, top_frame_site_key, name, path, source_scheme, "
      "source_port)";

  return db->Execute(kCreateSql) && db->Execute(kCreateIndexSql);
}

bool CreateV
```