Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a unit test for Chromium's cookie management (`net/cookies/cookie_monster_unittest.cc`). I need to identify the key features being tested in this specific chunk of code.

Here's a breakdown of the tests:

1. **CookieExclusionNotOnPath:** Tests a scenario where a cookie is excluded because the requested URL's path doesn't match the cookie's path.
2. **CookieSorting:** Verifies the order in which cookies are retrieved based on path length and creation time.
3. **InheritCreationDate:** Checks if overwriting a cookie with the same value preserves the original creation date, while updating the last update date. It also checks if a new value leads to a new creation date.
4. **OverwriteSource:** Tests how the cookie's source type (HTTP, Script, Other) is updated when a cookie is overwritten.
5. **DeleteExpiredCookiesOnGet:** Confirms that expired cookies are not returned by `GetAllCookiesForURL` and are deleted. This includes testing for partitioned cookies.
6. **DeleteExpiredCookiesAfterTimeElapsed:** Checks if cookies with `max-age` expire and are deleted after the specified time has elapsed.
7. **DeleteExpiredPartitionedCookiesAfterTimeElapsed:** Similar to the previous test, but specifically for partitioned cookies.
8. **ExpireSinglePartitionedCookie:** Focuses on the expiration of a single partitioned cookie based on `max-age`.
9. **DeleteExpiredAfterTimeElapsed_GetAllCookies:** Tests cookie expiration with `GetAllCookiesAsync`.
10. **DeleteExpiredPartitionedCookiesAfterTimeElapsed_GetAllCookies:** Tests partitioned cookie expiration with `GetAllCookiesAsync`.
11. **DeletePartitionedCookie:** Verifies the deletion of a specific partitioned cookie while leaving other cookies (partitioned and unpartitioned) unaffected.
12. **DontImportDuplicateCookies:** Tests the scenario where the cookie store contains duplicate cookies, and ensures that only the most recent one is imported.
13. **DontImportDuplicateCookies_PartitionedCookies:** Same as above, but for partitioned cookies.
14. **ImportDuplicateCreationTimes:** Tests the handling of cookies with the same creation time during import.
15. **ImportDuplicateCreationTimes_PartitionedCookies:** Same as above, but for partitioned cookies.
16. **PredicateSeesAllCookies:** Checks if a cookie deletion predicate can see and delete various types of cookies (host, domain, secure, etc.).
17. **GetKey:** Tests the `GetKey` function, which determines the effective domain for cookie storage.
18. **BackingStoreCommunication:** Verifies the correct transfer of cookie data between the in-memory `CookieMonster` and the persistent backing store.
19. **RestoreDifferentCookieSameCreationTime:** Checks that distinct cookies with the same creation time are correctly restored from the store.
20. **CookieListOrdering:** Tests the ordering of cookies returned by `GetAllCookiesForURL` and `GetAllCookies`.

Based on this analysis, I can now summarize the functionality.
这个代码片段是 `net/cookies/cookie_monster_unittest.cc` 文件的一部分，它主要测试 `CookieMonster` 类的各种功能。 `CookieMonster` 是 Chromium 网络栈中负责管理 HTTP Cookie 的核心类。

**这个代码片段主要测试了 `CookieMonster` 的以下功能：**

1. **Cookie 排除 (Exclusion):** 测试了当请求的路径与 Cookie 的路径不匹配时，Cookie 是否会被正确排除。
    *   **假设输入:** 设置一个路径为 `/foo` 的 Cookie "A"，然后尝试从 `/bar` 路径请求 Cookie。
    *   **预期输出:** Cookie "A" 会被排除，并给出排除原因是 `EXCLUDE_NOT_ON_PATH`。

2. **Cookie 排序 (Sorting):** 测试了在获取 Cookie 时，Cookie 的排序规则，主要是根据路径长度和创建时间排序。
    *   **假设输入:**  设置多个同名 Cookie，但路径不同，并设置不同的创建时间。
    *   **预期输出:** 获取到的 Cookie 列表按照路径长度降序排列，相同路径长度的按照创建时间降序排列。即使重新设置 Cookie，只要值相同，创建时间也会保留，排序顺序不变。

3. **继承创建日期 (Inherit Creation Date):** 测试了当使用相同的键值对再次设置 Cookie 时，是否会继承原有的创建日期，但更新日期会更新。而当设置不同的值时，创建日期也会更新。
    *   **假设输入:**  先设置一个 Cookie "Name=Value"，然后再次设置 "Name=Value"，最后设置 "Name=NewValue"。
    *   **预期输出:** 前两次设置的 Cookie 具有相同的创建日期，但第二次的更新日期会晚于第一次。第三次设置的 Cookie 具有不同的创建日期和更新日期。

4. **覆盖来源 (Overwrite Source):** 测试了设置 Cookie 时，可以指定 Cookie 的来源类型 (例如 HTTP, Script, Other)，并且覆盖已有的 Cookie 时会更新来源类型。
    *   **假设输入:**  多次设置同一个 Cookie "A"，但每次指定不同的来源类型 (Unknown, HTTP, Script, Other)。
    *   **预期输出:**  每次获取到的 Cookie 的来源类型都与最后一次设置的来源类型一致。

5. **获取时删除过期 Cookie (Delete Expired Cookies On Get):** 测试了在调用 `GetAllCookiesForURL` 获取 Cookie 时，是否会自动删除已过期的 Cookie。也测试了 partitioned cookies 的相同行为。
    *   **假设输入:** 设置两个 Cookie，其中一个已过期。
    *   **预期输出:** 调用 `GetAllCookiesForURL` 时，只会返回未过期的 Cookie。

6. **时间流逝后删除过期 Cookie (Delete Expired Cookies After Time Elapsed):** 测试了当 Cookie 的 `max-age` 属性到期后，即使没有显式调用删除，Cookie 是否会被自动删除。也测试了 partitioned cookies 的相同行为。
    *   **假设输入:** 设置一个带有 `max-age=1` 的 Cookie。
    *   **预期输出:** 等待 1 秒后再次获取 Cookie，该 Cookie 不存在。

7. **删除单个分区 Cookie (Expire Single Partitioned Cookie):**  针对一个特定的 bugfix (https://crbug.com/353034832)，测试了单个分区 Cookie 在 `max-age` 到期后是否能被正确删除。

8. **`GetAllCookiesAsync` 删除过期 Cookie:**  使用异步方法 `GetAllCookiesAsync` 测试过期 Cookie 的删除。

9. **删除分区 Cookie (Delete Partitioned Cookie):** 测试了删除特定的分区 Cookie，同时确保其他分区和非分区 Cookie 不受影响。
    *   **假设输入:** 设置多个分区 Cookie 和非分区 Cookie，然后尝试删除其中一个分区 Cookie。
    *   **预期输出:** 只有指定的分区 Cookie 被删除，其他 Cookie 仍然存在。

10. **不导入重复 Cookie (Don't Import Duplicate Cookies):**  测试了从持久化存储中导入 Cookie 时，如果存在重复的 Cookie (相同的域名、路径、名称)，只会保留创建时间最新的那一个。
    *   **假设输入:**  模拟一个持久化存储，其中包含多个具有相同域名、路径和名称的 Cookie，但创建时间不同。
    *   **预期输出:**  导入后，`CookieMonster` 中只包含创建时间最新的那个 Cookie，并且持久化存储会收到删除重复 Cookie的指令。

11. **不导入重复分区 Cookie (Don't Import Duplicate Cookies - Partitioned Cookies):**  与上一点类似，但针对的是分区 Cookie。

12. **导入具有重复创建时间的 Cookie (Import Duplicate Creation Times):** 测试了导入具有相同创建时间的 Cookie 的情况，尽管现在这是允许的，但仍然会触发去重逻辑。
    *   **假设输入:**  模拟一个持久化存储，其中包含多个具有相同域名、路径和名称的 Cookie，其中一部分的创建时间相同。
    *   **预期输出:** 导入后，`CookieMonster` 中会保留一部分 Cookie，但具体保留哪些是随机的，但会保证每个创建时间点都有至少一个 Cookie 被保留。

13. **谓词查看所有 Cookie (Predicate Sees All Cookies):** 测试了使用谓词 (Predicate) 删除 Cookie 时，可以查看到所有类型的 Cookie，包括 host-only、http-only、secure 和 domain Cookie。

14. **获取键 (GetKey):** 测试了 `GetKey` 函数，这个函数用于确定 Cookie 的有效域名，用于内部存储。

15. **与后端存储通信 (Backing Store Communication):**  测试了 Cookie 能否正确地写入后端存储，并且之后能从后端存储中正确读取出来。
    *   **假设输入:** 创建一些 Cookie 并让 `CookieMonster` 将它们刷新到后端存储。
    *   **预期输出:** 新的 `CookieMonster` 从后端存储加载 Cookie 后，能获取到之前创建的 Cookie。

16. **恢复具有相同创建时间的不同 Cookie (Restore Different Cookie Same Creation Time):** 测试了即使两个不同的 Cookie 具有相同的创建时间，也能从持久化存储中正确恢复。

17. **Cookie 列表排序 (Cookie List Ordering):**  测试了 `GetAllCookiesForURL` 和 `GetAllCookies` 返回的 Cookie 列表的排序规则。

**与 Javascript 功能的关系：**

`CookieMonster` 管理的是浏览器中存储的 HTTP Cookie，这些 Cookie 可以被 Javascript 通过 `document.cookie` API 访问和操作。

*   **举例说明:** Javascript 可以使用 `document.cookie = "name=value; path=/";` 来设置一个 Cookie，这个操作最终会通过 Chromium 的内部机制到达 `CookieMonster` 进行处理和存储。  `CookieMonster` 的测试用例，例如 **CookieExclusionNotOnPath**，就直接影响了 Javascript 在不同路径下能否访问到特定的 Cookie。同样，**CookieSorting** 的测试结果决定了当 Javascript 通过 `document.cookie` 获取 Cookie 字符串时，Cookie 的排列顺序。

**假设输入与输出 (更多例子):**

*   **假设输入 (OverwriteSource):**  Javascript 代码在某个页面上执行 `document.cookie = "test=1";` (来源类型为 Script)，然后服务器返回一个 Set-Cookie 头 `Set-Cookie: test=1; HttpOnly` (来源类型为 HTTP)。
*   **预期输出 (OverwriteSource):**  `CookieMonster` 中存储的 `test` Cookie 的来源类型会更新为 HTTP。

**用户或编程常见的使用错误举例说明：**

*   **用户错误:** 用户在浏览器设置中清除了 Cookie。这会导致 `CookieMonster` 中的数据被清空。
*   **编程错误:**  开发者在设置 Cookie 时，`path` 属性设置不正确，导致 Cookie 无法在预期的页面上访问。例如，设置了 `path=/admin` 的 Cookie，在访问 `/user` 路径时，Javascript 将无法通过 `document.cookie` 获取到该 Cookie。  **CookieExclusionNotOnPath** 的测试就模拟了这种情况。
*   **编程错误:** 开发者没有正确处理 Cookie 的过期时间，导致 Cookie 过期后仍然被 Javascript 依赖，从而引发错误。 **DeleteExpiredCookiesOnGet** 和 **DeleteExpiredCookiesAfterTimeElapsed** 的测试用例强调了 `CookieMonster` 对过期 Cookie 的管理。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入 URL 并访问一个网站。**
2. **服务器在 HTTP 响应头中包含 `Set-Cookie` 指令，要求浏览器存储 Cookie。**
3. **浏览器接收到响应，网络栈解析 `Set-Cookie` 头。**
4. **`CookieMonster::SetCanonicalCookie()` 方法被调用，用于存储或更新 Cookie。**  相关的测试用例，如 **InheritCreationDate** 和 **OverwriteSource**，模拟了此过程。
5. **用户在同一个网站或相关网站上进行后续操作，浏览器需要发送 Cookie。**
6. **当浏览器发起新的 HTTP 请求时，`CookieMonster::GetCookieListForURL()` 或类似方法被调用，根据请求的 URL 检索相关的 Cookie。** **CookieSorting** 和 **CookieExclusionNotOnPath** 的测试与此步骤相关。
7. **检索到的 Cookie 被添加到 HTTP 请求头中发送给服务器。**
8. **如果用户在 Javascript 中使用 `document.cookie` 访问 Cookie，也会调用 `CookieMonster` 的相应方法获取 Cookie 信息。**

调试线索可能包括：

*   查看网络请求头中的 `Cookie` 字段，确认发送了哪些 Cookie。
*   使用浏览器的开发者工具查看应用程序选项卡下的 Cookie 信息，了解当前存储的 Cookie 及其属性。
*   如果涉及到持久化存储，可以检查本地的 Cookie 存储文件（具体位置取决于浏览器和操作系统）。

**归纳一下它的功能 (针对提供的代码片段):**

这个代码片段主要集中在测试 `CookieMonster` 类对 **Cookie 的管理和维护** 的核心功能，包括：

*   **根据路径匹配规则排除 Cookie。**
*   **按照特定的规则对 Cookie 进行排序。**
*   **正确处理 Cookie 的创建和更新时间。**
*   **维护 Cookie 的来源信息。**
*   **在获取 Cookie 时自动删除过期 Cookie。**
*   **根据 `max-age` 属性自动删除过期 Cookie。**
*   **支持和管理分区 Cookie。**
*   **在从持久化存储导入 Cookie 时处理重复项。**
*   **确保 Cookie 数据能正确地写入和读取持久化存储。**

总而言之，这个代码片段通过一系列单元测试，验证了 `CookieMonster` 作为 Chromium 中负责 Cookie 管理的关键组件，其核心逻辑的正确性和健壮性。

Prompt: 
```
这是目录为net/cookies/cookie_monster_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共10部分，请归纳一下它的功能

"""
                CookiePartitionKeyCollection());
  it = excluded_cookies.begin();

  ASSERT_TRUE(it != excluded_cookies.end());
  EXPECT_EQ("A", it->cookie.Name());
  EXPECT_EQ("/foo", it->cookie.Path());
  EXPECT_TRUE(it->access_result.status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_NOT_ON_PATH}));

  ASSERT_TRUE(++it == excluded_cookies.end());
}

TEST_F(CookieMonsterTest, CookieSorting) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  base::Time system_time = base::Time::Now();
  for (const char* cookie_line :
       {"B=B1; path=/", "B=B2; path=/foo", "B=B3; path=/foo/bar",
        "A=A1; path=/", "A=A2; path=/foo", "A=A3; path=/foo/bar"}) {
    EXPECT_TRUE(SetCookieWithSystemTime(cm.get(), http_www_foo_.url(),
                                        cookie_line, system_time));
    system_time += base::Milliseconds(100);
  }

  // Re-set cookie which should not change sort order, as the creation date
  // will be retained, as per RFC 6265 5.3.11.3.
  EXPECT_TRUE(SetCookieWithSystemTime(cm.get(), http_www_foo_.url(),
                                      "B=B3; path=/foo/bar", system_time));

  CookieList cookies = GetAllCookies(cm.get());
  ASSERT_EQ(6u, cookies.size());
  EXPECT_EQ("B3", cookies[0].Value());
  EXPECT_EQ("A3", cookies[1].Value());
  EXPECT_EQ("B2", cookies[2].Value());
  EXPECT_EQ("A2", cookies[3].Value());
  EXPECT_EQ("B1", cookies[4].Value());
  EXPECT_EQ("A1", cookies[5].Value());
}

TEST_F(CookieMonsterTest, InheritCreationDate) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  base::Time the_not_so_distant_past(base::Time::Now() - base::Seconds(1000));
  EXPECT_TRUE(SetCookieWithCreationTime(cm.get(), http_www_foo_.url(),
                                        "Name=Value; path=/",
                                        the_not_so_distant_past));

  CookieList cookies = GetAllCookies(cm.get());
  ASSERT_EQ(1u, cookies.size());
  EXPECT_EQ(the_not_so_distant_past, cookies[0].CreationDate());
  base::Time last_update = cookies[0].LastUpdateDate();

  // Overwrite the cookie with the same value, and verify that the creation date
  // is inherited. The update date isn't inherited though.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "Name=Value; path=/"));

  cookies = GetAllCookies(cm.get());
  ASSERT_EQ(1u, cookies.size());
  EXPECT_EQ(the_not_so_distant_past, cookies[0].CreationDate());
  // If this is flakey you many need to manually set the last update time.
  EXPECT_LT(last_update, cookies[0].LastUpdateDate());
  last_update = cookies[0].LastUpdateDate();

  // New value => new creation date.
  EXPECT_TRUE(
      SetCookie(cm.get(), http_www_foo_.url(), "Name=NewValue; path=/"));

  cookies = GetAllCookies(cm.get());
  ASSERT_EQ(1u, cookies.size());
  EXPECT_NE(the_not_so_distant_past, cookies[0].CreationDate());
  // If this is flakey you many need to manually set the last update time.
  EXPECT_LT(last_update, cookies[0].LastUpdateDate());
}

TEST_F(CookieMonsterTest, OverwriteSource) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  // Set cookie with unknown source.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=0", std::nullopt,
                        CookieSourceType::kUnknown));
  CookieList cookies = GetAllCookies(cm.get());
  ASSERT_EQ(1u, cookies.size());
  EXPECT_EQ("0", cookies[0].Value());
  EXPECT_EQ(CookieSourceType::kUnknown, cookies[0].SourceType());

  // Overwrite the cookie with the same value and an http source.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=0", std::nullopt,
                        CookieSourceType::kHTTP));
  cookies = GetAllCookies(cm.get());
  ASSERT_EQ(1u, cookies.size());
  EXPECT_EQ("0", cookies[0].Value());
  EXPECT_EQ(CookieSourceType::kHTTP, cookies[0].SourceType());

  // Overwrite the cookie with a new value and a script source.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=1", std::nullopt,
                        CookieSourceType::kScript));
  cookies = GetAllCookies(cm.get());
  ASSERT_EQ(1u, cookies.size());
  EXPECT_EQ("1", cookies[0].Value());
  EXPECT_EQ(CookieSourceType::kScript, cookies[0].SourceType());

  // Overwrite the cookie with the same value and an other source.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=1", std::nullopt,
                        CookieSourceType::kOther));
  cookies = GetAllCookies(cm.get());
  ASSERT_EQ(1u, cookies.size());
  EXPECT_EQ("1", cookies[0].Value());
  EXPECT_EQ(CookieSourceType::kOther, cookies[0].SourceType());
}

// Check that GetAllCookiesForURL() does not return expired cookies and deletes
// them.
TEST_F(CookieMonsterTest, DeleteExpiredCookiesOnGet) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=B;"));

  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "C=D;"));

  CookieList cookies = GetAllCookiesForURL(cm.get(), http_www_foo_.url());
  EXPECT_EQ(2u, cookies.size());

  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(),
                        "C=D; expires=Thu, 01-Jan-1970 00:00:00 GMT"));

  cookies = GetAllCookiesForURL(cm.get(), http_www_foo_.url());
  EXPECT_EQ(1u, cookies.size());

  // Test partitioned cookies. They should exhibit the same behavior but are
  // stored in a different data structure internally.
  auto cookie_partition_key =
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com"));

  EXPECT_TRUE(SetCookie(cm.get(), https_www_bar_.url(),
                        "__Host-A=B; secure; path=/; partitioned",
                        cookie_partition_key));
  EXPECT_TRUE(SetCookie(cm.get(), https_www_bar_.url(),
                        "__Host-C=D; secure; path=/; partitioned",
                        cookie_partition_key));

  cookies =
      GetAllCookiesForURL(cm.get(), https_www_bar_.url(),
                          CookiePartitionKeyCollection(cookie_partition_key));
  EXPECT_EQ(2u, cookies.size());

  EXPECT_TRUE(SetCookie(cm.get(), https_www_bar_.url(),
                        "__Host-C=D; secure; path=/; partitioned; expires=Thu, "
                        "01-Jan-1970 00:00:00 GMT",
                        cookie_partition_key));

  cookies =
      GetAllCookiesForURL(cm.get(), https_www_bar_.url(),
                          CookiePartitionKeyCollection(cookie_partition_key));
  EXPECT_EQ(1u, cookies.size());
}

// Test that cookie expiration works correctly when a cookie expires because
// time elapses.
TEST_F(CookieMonsterTest, DeleteExpiredCookiesAfterTimeElapsed) {
  auto cm = std::make_unique<CookieMonster>(
      /*store=*/nullptr, net::NetLog::Get());

  EXPECT_TRUE(SetCookie(cm.get(), https_www_bar_.url(),
                        "__Host-A=B; secure; path=/",
                        /*cookie_partition_key=*/std::nullopt));
  // Set a cookie with a Max-Age. Since we only parse integers for this
  // attribute, 1 second is the minimum allowable time.
  EXPECT_TRUE(SetCookie(cm.get(), https_www_bar_.url(),
                        "__Host-C=D; secure; path=/; max-age=1",
                        /*cookie_partition_key=*/std::nullopt));

  CookieList cookies = GetAllCookiesForURL(cm.get(), https_www_bar_.url(),
                                           CookiePartitionKeyCollection());
  EXPECT_EQ(2u, cookies.size());

  // Sleep for entire Max-Age of the second cookie.
  base::PlatformThread::Sleep(base::Seconds(1));

  cookies = GetAllCookiesForURL(cm.get(), https_www_bar_.url(),
                                CookiePartitionKeyCollection());
  EXPECT_EQ(1u, cookies.size());
  EXPECT_EQ("__Host-A", cookies[0].Name());
}

TEST_F(CookieMonsterTest, DeleteExpiredPartitionedCookiesAfterTimeElapsed) {
  auto cm = std::make_unique<CookieMonster>(
      /*store=*/nullptr, net::NetLog::Get());
  auto cookie_partition_key =
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com"));

  EXPECT_TRUE(SetCookie(cm.get(), https_www_bar_.url(),
                        "__Host-A=B; secure; path=/; partitioned",
                        cookie_partition_key));
  // Set a cookie with a Max-Age. Since we only parse integers for this
  // attribute, 1 second is the minimum allowable time.
  EXPECT_TRUE(SetCookie(cm.get(), https_www_bar_.url(),
                        "__Host-C=D; secure; path=/; partitioned; max-age=1",
                        cookie_partition_key));

  CookieList cookies =
      GetAllCookiesForURL(cm.get(), https_www_bar_.url(),
                          CookiePartitionKeyCollection(cookie_partition_key));
  EXPECT_EQ(2u, cookies.size());

  // Sleep for entire Max-Age of the second cookie.
  base::PlatformThread::Sleep(base::Seconds(1));

  cookies =
      GetAllCookiesForURL(cm.get(), https_www_bar_.url(),
                          CookiePartitionKeyCollection(cookie_partition_key));
  EXPECT_EQ(1u, cookies.size());
  EXPECT_EQ("__Host-A", cookies[0].Name());
}

// This test is for verifying the fix of https://crbug.com/353034832.
TEST_F(CookieMonsterTest, ExpireSinglePartitionedCookie) {
  auto cm = std::make_unique<CookieMonster>(
      /*store=*/nullptr, net::NetLog::Get());
  auto cookie_partition_key =
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com"));

  // Set a cookie with a Max-Age. Since we only parse integers for this
  // attribute, 1 second is the minimum allowable time.
  ASSERT_TRUE(SetCookie(cm.get(), https_www_bar_.url(),
                        "__Host-A=1; secure; path=/; partitioned; max-age=1",
                        cookie_partition_key));
  CookieList cookies =
      GetAllCookiesForURL(cm.get(), https_www_bar_.url(),
                          CookiePartitionKeyCollection(cookie_partition_key));
  ASSERT_EQ(1u, cookies.size());

  // Sleep for entire Max-Age of the cookie.
  base::PlatformThread::Sleep(base::Seconds(1));

  cookies = GetAllCookiesForURL(cm.get(), https_www_bar_.url(),
                                CookiePartitionKeyCollection::ContainsAll());
  EXPECT_EQ(0u, cookies.size());
}

TEST_F(CookieMonsterTest, DeleteExpiredAfterTimeElapsed_GetAllCookies) {
  auto cm = std::make_unique<CookieMonster>(
      /*store=*/nullptr, net::NetLog::Get());

  EXPECT_TRUE(SetCookie(cm.get(), https_www_bar_.url(),
                        "__Host-A=B; secure; path=/",
                        /*cookie_partition_key=*/std::nullopt));
  // Set a cookie with a Max-Age. Since we only parse integers for this
  // attribute, 1 second is the minimum allowable time.
  EXPECT_TRUE(SetCookie(cm.get(), https_www_bar_.url(),
                        "__Host-C=D; secure; path=/; max-age=1",
                        /*cookie_partition_key=*/std::nullopt));

  GetAllCookiesCallback get_cookies_callback1;
  cm->GetAllCookiesAsync(get_cookies_callback1.MakeCallback());
  get_cookies_callback1.WaitUntilDone();
  ASSERT_EQ(2u, get_cookies_callback1.cookies().size());

  // Sleep for entire Max-Age of the second cookie.
  base::PlatformThread::Sleep(base::Seconds(1));

  GetAllCookiesCallback get_cookies_callback2;
  cm->GetAllCookiesAsync(get_cookies_callback2.MakeCallback());
  get_cookies_callback2.WaitUntilDone();

  ASSERT_EQ(1u, get_cookies_callback2.cookies().size());
  EXPECT_EQ("__Host-A", get_cookies_callback2.cookies()[0].Name());
}

TEST_F(CookieMonsterTest,
       DeleteExpiredPartitionedCookiesAfterTimeElapsed_GetAllCookies) {
  auto cm = std::make_unique<CookieMonster>(
      /*store=*/nullptr, net::NetLog::Get());
  auto cookie_partition_key =
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com"));

  EXPECT_TRUE(SetCookie(cm.get(), https_www_bar_.url(),
                        "__Host-A=B; secure; path=/; partitioned",
                        cookie_partition_key));
  // Set a cookie with a Max-Age. Since we only parse integers for this
  // attribute, 1 second is the minimum allowable time.
  EXPECT_TRUE(SetCookie(cm.get(), https_www_bar_.url(),
                        "__Host-C=D; secure; path=/; max-age=1; partitioned",
                        cookie_partition_key));

  GetAllCookiesCallback get_cookies_callback1;
  cm->GetAllCookiesAsync(get_cookies_callback1.MakeCallback());
  get_cookies_callback1.WaitUntilDone();
  ASSERT_EQ(2u, get_cookies_callback1.cookies().size());

  // Sleep for entire Max-Age of the second cookie.
  base::PlatformThread::Sleep(base::Seconds(1));

  GetAllCookiesCallback get_cookies_callback2;
  cm->GetAllCookiesAsync(get_cookies_callback2.MakeCallback());
  get_cookies_callback2.WaitUntilDone();

  ASSERT_EQ(1u, get_cookies_callback2.cookies().size());
  EXPECT_EQ("__Host-A", get_cookies_callback2.cookies()[0].Name());
}

TEST_F(CookieMonsterTest, DeletePartitionedCookie) {
  auto cm = std::make_unique<CookieMonster>(
      /*store=*/nullptr, net::NetLog::Get());
  auto cookie_partition_key =
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com"));

  EXPECT_TRUE(SetCookie(cm.get(), https_www_bar_.url(),
                        "__Host-A=B; secure; path=/; partitioned",
                        cookie_partition_key));
  // Set another partitioned and an unpartitioned cookie and make sure they are
  // unaffected.
  EXPECT_TRUE(SetCookie(cm.get(), https_www_bar_.url(),
                        "__Host-C=D; secure; path=/; partitioned",
                        cookie_partition_key));
  EXPECT_TRUE(SetCookie(cm.get(), https_www_bar_.url(),
                        "__Host-E=F; secure; path=/", std::nullopt));

  auto cookie = CanonicalCookie::CreateForTesting(
      https_www_bar_.url(), "__Host-A=B; secure; path=/; partitioned",
      /*creation_time=*/Time::Now(), /*server_time=*/std::nullopt,
      cookie_partition_key);
  ASSERT_TRUE(cookie);

  ResultSavingCookieCallback<unsigned int> delete_callback;
  cm->DeleteCanonicalCookieAsync(*cookie, delete_callback.MakeCallback());
  delete_callback.WaitUntilDone();

  CookieList cookies =
      GetAllCookiesForURL(cm.get(), https_www_bar_.url(),
                          CookiePartitionKeyCollection(cookie_partition_key));
  EXPECT_EQ(2u, cookies.size());
  EXPECT_EQ(cookies[0].Name(), "__Host-C");
  EXPECT_EQ(cookies[1].Name(), "__Host-E");
}

// Tests importing from a persistent cookie store that contains duplicate
// equivalent cookies. This situation should be handled by removing the
// duplicate cookie (both from the in-memory cache, and from the backing store).
//
// This is a regression test for: http://crbug.com/17855.
TEST_F(CookieMonsterTest, DontImportDuplicateCookies) {
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();

  // We will fill some initial cookies into the PersistentCookieStore,
  // to simulate a database with 4 duplicates.  Note that we need to
  // be careful not to have any duplicate creation times at all (as it's a
  // violation of a CookieMonster invariant) even if Time::Now() doesn't
  // move between calls.
  std::vector<std::unique_ptr<CanonicalCookie>> initial_cookies;

  // Insert 4 cookies with name "X" on path "/", with varying creation
  // dates. We expect only the most recent one to be preserved following
  // the import.

  AddCookieToList(GURL("http://www.foo.com"),
                  "X=1; path=/" + FutureCookieExpirationString(),
                  Time::Now() + base::Days(3), &initial_cookies);

  AddCookieToList(GURL("http://www.foo.com"),
                  "X=2; path=/" + FutureCookieExpirationString(),
                  Time::Now() + base::Days(1), &initial_cookies);

  // ===> This one is the WINNER (biggest creation time).  <====
  AddCookieToList(GURL("http://www.foo.com"),
                  "X=3; path=/" + FutureCookieExpirationString(),
                  Time::Now() + base::Days(4), &initial_cookies);

  AddCookieToList(GURL("http://www.foo.com"),
                  "X=4; path=/" + FutureCookieExpirationString(), Time::Now(),
                  &initial_cookies);

  // Insert 2 cookies with name "X" on path "/2", with varying creation
  // dates. We expect only the most recent one to be preserved the import.

  // ===> This one is the WINNER (biggest creation time).  <====
  AddCookieToList(GURL("http://www.foo.com"),
                  "X=a1; path=/2" + FutureCookieExpirationString(),
                  Time::Now() + base::Days(9), &initial_cookies);

  AddCookieToList(GURL("http://www.foo.com"),
                  "X=a2; path=/2" + FutureCookieExpirationString(),
                  Time::Now() + base::Days(2), &initial_cookies);

  // Insert 1 cookie with name "Y" on path "/".
  AddCookieToList(GURL("http://www.foo.com"),
                  "Y=a; path=/" + FutureCookieExpirationString(),
                  Time::Now() + base::Days(10), &initial_cookies);

  // Inject our initial cookies into the mock PersistentCookieStore.
  store->SetLoadExpectation(true, std::move(initial_cookies));

  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  // Verify that duplicates were not imported for path "/".
  // (If this had failed, GetCookies() would have also returned X=1, X=2, X=4).
  EXPECT_EQ("X=3; Y=a", GetCookies(cm.get(), GURL("http://www.foo.com/")));

  // Verify that same-named cookie on a different path ("/x2") didn't get
  // messed up.
  EXPECT_EQ("X=a1; X=3; Y=a",
            GetCookies(cm.get(), GURL("http://www.foo.com/2/x")));

  // Verify that the PersistentCookieStore was told to kill its 4 duplicates.
  ASSERT_EQ(4u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[0].type);
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[1].type);
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[2].type);
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[3].type);
}

TEST_F(CookieMonsterTest, DontImportDuplicateCookies_PartitionedCookies) {
  std::vector<std::unique_ptr<CanonicalCookie>> initial_cookies;

  auto cookie_partition_key =
      CookiePartitionKey::FromURLForTesting(GURL("https://www.foo.com"));
  GURL cookie_url("https://www.bar.com");

  // Insert 3 partitioned cookies with same name, partition key, and path.

  // ===> This one is the WINNER (biggest creation time).  <====
  auto cc = CanonicalCookie::CreateForTesting(
      cookie_url, "__Host-Z=a; Secure; Path=/; Partitioned; Max-Age=3456000",
      Time::Now() + base::Days(2), std::nullopt, cookie_partition_key);
  initial_cookies.push_back(std::move(cc));

  cc = CanonicalCookie::CreateForTesting(
      cookie_url, "__Host-Z=b; Secure; Path=/; Partitioned; Max-Age=3456000",
      Time::Now(), std::nullopt, cookie_partition_key);
  initial_cookies.push_back(std::move(cc));

  cc = CanonicalCookie::CreateForTesting(
      cookie_url, "__Host-Z=c; Secure; Path=/; Partitioned; Max-Age=3456000",
      Time::Now() + base::Days(1), std::nullopt, cookie_partition_key);
  initial_cookies.push_back(std::move(cc));

  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  store->SetLoadExpectation(true, std::move(initial_cookies));

  EXPECT_EQ("__Host-Z=a",
            GetCookies(cm.get(), GURL("https://www.bar.com/"),
                       CookiePartitionKeyCollection(cookie_partition_key)));

  // Verify that the PersistentCookieStore was told to kill the 2
  // duplicates.
  ASSERT_EQ(2u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[0].type);
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[1].type);
}

// Tests importing from a persistent cookie store that contains cookies
// with duplicate creation times.  This is OK now, but it still interacts
// with the de-duplication algorithm.
//
// This is a regression test for: http://crbug.com/43188.
TEST_F(CookieMonsterTest, ImportDuplicateCreationTimes) {
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();

  Time now(Time::Now());
  Time earlier(now - base::Days(1));

  // Insert 8 cookies, four with the current time as creation times, and
  // four with the earlier time as creation times.  We should only get
  // two cookies remaining, but which two (other than that there should
  // be one from each set) will be random.
  std::vector<std::unique_ptr<CanonicalCookie>> initial_cookies;
  AddCookieToList(GURL("http://www.foo.com"), "X=1; path=/", now,
                  &initial_cookies);
  AddCookieToList(GURL("http://www.foo.com"), "X=2; path=/", now,
                  &initial_cookies);
  AddCookieToList(GURL("http://www.foo.com"), "X=3; path=/", now,
                  &initial_cookies);
  AddCookieToList(GURL("http://www.foo.com"), "X=4; path=/", now,
                  &initial_cookies);

  AddCookieToList(GURL("http://www.foo.com"), "Y=1; path=/", earlier,
                  &initial_cookies);
  AddCookieToList(GURL("http://www.foo.com"), "Y=2; path=/", earlier,
                  &initial_cookies);
  AddCookieToList(GURL("http://www.foo.com"), "Y=3; path=/", earlier,
                  &initial_cookies);
  AddCookieToList(GURL("http://www.foo.com"), "Y=4; path=/", earlier,
                  &initial_cookies);

  // Inject our initial cookies into the mock PersistentCookieStore.
  store->SetLoadExpectation(true, std::move(initial_cookies));

  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  CookieList list(GetAllCookies(cm.get()));
  EXPECT_EQ(2U, list.size());
  // Confirm that we have one of each.
  std::string name1(list[0].Name());
  std::string name2(list[1].Name());
  EXPECT_TRUE(name1 == "X" || name2 == "X");
  EXPECT_TRUE(name1 == "Y" || name2 == "Y");
  EXPECT_NE(name1, name2);
}

TEST_F(CookieMonsterTest, ImportDuplicateCreationTimes_PartitionedCookies) {
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();

  Time now(Time::Now());
  Time earlier(now - base::Days(1));

  GURL cookie_url("https://www.foo.com");
  auto cookie_partition_key =
      CookiePartitionKey::FromURLForTesting(GURL("https://www.bar.com"));

  // Insert 6 cookies, four with the current time as creation times, and
  // four with the earlier time as creation times.  We should only get
  // two cookies remaining, but which two (other than that there should
  // be one from each set) will be random.

  std::vector<std::unique_ptr<CanonicalCookie>> initial_cookies;
  auto cc = CanonicalCookie::CreateForTesting(
      cookie_url, "__Host-X=1; Secure; Path=/; Partitioned; Max-Age=3456000",
      now, std::nullopt, cookie_partition_key);
  initial_cookies.push_back(std::move(cc));
  cc = CanonicalCookie::CreateForTesting(
      cookie_url, "__Host-X=2; Secure; Path=/; Partitioned; Max-Age=3456000",
      now, std::nullopt, cookie_partition_key);
  initial_cookies.push_back(std::move(cc));
  cc = CanonicalCookie::CreateForTesting(
      cookie_url, "__Host-X=3; Secure; Path=/; Partitioned; Max-Age=3456000",
      now, std::nullopt, cookie_partition_key);
  initial_cookies.push_back(std::move(cc));

  cc = CanonicalCookie::CreateForTesting(
      cookie_url, "__Host-Y=1; Secure; Path=/; Partitioned; Max-Age=3456000",
      earlier, std::nullopt, cookie_partition_key);
  initial_cookies.push_back(std::move(cc));
  cc = CanonicalCookie::CreateForTesting(
      cookie_url, "__Host-Y=2; Secure; Path=/; Partitioned; Max-Age=3456000",
      earlier, std::nullopt, cookie_partition_key);
  initial_cookies.push_back(std::move(cc));
  cc = CanonicalCookie::CreateForTesting(
      cookie_url, "__Host-Y=3; Secure; Path=/; Partitioned; Max-Age=3456000",
      earlier, std::nullopt, cookie_partition_key);
  initial_cookies.push_back(std::move(cc));

  // Inject our initial cookies into the mock PersistentCookieStore.
  store->SetLoadExpectation(true, std::move(initial_cookies));

  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  CookieList list(GetAllCookies(cm.get()));
  EXPECT_EQ(2U, list.size());
  // Confirm that we have one of each.
  std::string name1(list[0].Name());
  std::string name2(list[1].Name());
  EXPECT_TRUE(name1 == "__Host-X" || name2 == "__Host-X");
  EXPECT_TRUE(name1 == "__Host-Y" || name2 == "__Host-Y");
  EXPECT_NE(name1, name2);
}

TEST_F(CookieMonsterTest, PredicateSeesAllCookies) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  const base::Time now = PopulateCmForPredicateCheck(cm.get());
  // We test that we can see all cookies with |delete_info|. This includes
  // host, http_only, host secure, and all domain cookies.
  CookieDeletionInfo delete_info(base::Time(), now);
  delete_info.value_for_testing = "A";

  EXPECT_EQ(8u, DeleteAllMatchingInfo(cm.get(), std::move(delete_info)));

  EXPECT_EQ("dom_2=B; dom_3=C; host_3=C",
            GetCookies(cm.get(), GURL(kTopLevelDomainPlus3)));
  EXPECT_EQ("dom_2=B; host_2=B; sec_host=B",
            GetCookies(cm.get(), GURL(kTopLevelDomainPlus2Secure)));
  EXPECT_EQ("", GetCookies(cm.get(), GURL(kTopLevelDomainPlus1)));
  EXPECT_EQ("dom_path_2=B; host_path_2=B; dom_2=B; host_2=B; sec_host=B",
            GetCookies(cm.get(), GURL(kTopLevelDomainPlus2Secure +
                                      std::string("/dir1/dir2/xxx"))));
  EXPECT_EQ("dom_2=B; host_2=B; sec_host=B; __Host-pc_2=B",
            GetCookies(cm.get(), GURL(kTopLevelDomainPlus2Secure),
                       CookiePartitionKeyCollection(
                           CookiePartitionKey::FromURLForTesting(
                               GURL(kTopLevelDomainPlus1)))));
}

// Mainly a test of GetEffectiveDomain, or more specifically, of the
// expected behavior of GetEffectiveDomain within the CookieMonster.
TEST_F(CookieMonsterTest, GetKey) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  // This test is really only interesting if GetKey() actually does something.
  EXPECT_EQ("foo.com", cm->GetKey("www.foo.com"));
  EXPECT_EQ("google.izzie", cm->GetKey("www.google.izzie"));
  EXPECT_EQ("google.izzie", cm->GetKey(".google.izzie"));
  EXPECT_EQ("bbc.co.uk", cm->GetKey("bbc.co.uk"));
  EXPECT_EQ("bbc.co.uk", cm->GetKey("a.b.c.d.bbc.co.uk"));
  EXPECT_EQ("apple.com", cm->GetKey("a.b.c.d.apple.com"));
  EXPECT_EQ("apple.izzie", cm->GetKey("a.b.c.d.apple.izzie"));

  // Cases where the effective domain is null, so we use the host
  // as the key.
  EXPECT_EQ("co.uk", cm->GetKey("co.uk"));
  const std::string extension_name("iehocdgbbocmkdidlbnnfbmbinnahbae");
  EXPECT_EQ(extension_name, cm->GetKey(extension_name));
  EXPECT_EQ("com", cm->GetKey("com"));
  EXPECT_EQ("hostalias", cm->GetKey("hostalias"));
  EXPECT_EQ("localhost", cm->GetKey("localhost"));
}

// Test that cookies transfer from/to the backing store correctly.
// TODO(crbug.com/40188414): Include partitioned cookies in this test when we
// start saving them in the persistent store.
TEST_F(CookieMonsterTest, BackingStoreCommunication) {
  // Store details for cookies transforming through the backing store interface.

  base::Time current(base::Time::Now());
  auto store = base::MakeRefCounted<MockSimplePersistentCookieStore>();
  base::Time expires(base::Time::Now() + base::Seconds(100));

  const CookiesInputInfo input_info[] = {
      {GURL("https://a.b.foo.com"), "a", "1", "a.b.foo.com", "/path/to/cookie",
       expires, true /* secure */, false, CookieSameSite::NO_RESTRICTION,
       COOKIE_PRIORITY_DEFAULT},
      {GURL("https://www.foo.com"), "b", "2", ".foo.com", "/path/from/cookie",
       expires + base::Seconds(10), true, true, CookieSameSite::NO_RESTRICTION,
       COOKIE_PRIORITY_DEFAULT},
      {GURL("https://foo.com"), "c", "3", "foo.com", "/another/path/to/cookie",
       base::Time::Now() + base::Seconds(100), false, false,
       CookieSameSite::STRICT_MODE, COOKIE_PRIORITY_DEFAULT}};
  const int INPUT_DELETE = 1;

  // Create new cookies and flush them to the store.
  {
    auto cmout =
        std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());
    for (const auto& cookie : input_info) {
      EXPECT_TRUE(SetCanonicalCookie(
          cmout.get(),
          CanonicalCookie::CreateUnsafeCookieForTesting(
              cookie.name, cookie.value, cookie.domain, cookie.path,
              base::Time(), cookie.expiration_time, base::Time(), base::Time(),
              cookie.secure, cookie.http_only, cookie.same_site,
              cookie.priority),
          cookie.url, true /*modify_httponly*/));
    }

    EXPECT_TRUE(FindAndDeleteCookie(cmout.get(),
                                    input_info[INPUT_DELETE].domain,
                                    input_info[INPUT_DELETE].name));
  }

  // Create a new cookie monster and make sure that everything is correct
  {
    auto cmin =
        std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());
    CookieList cookies(GetAllCookies(cmin.get()));
    ASSERT_EQ(2u, cookies.size());
    // Ordering is path length, then creation time.  So second cookie
    // will come first, and we need to swap them.
    std::swap(cookies[0], cookies[1]);
    for (int output_index = 0; output_index < 2; output_index++) {
      int input_index = output_index * 2;
      const CookiesInputInfo* input = &input_info[input_index];
      const CanonicalCookie* output = &cookies[output_index];

      EXPECT_EQ(input->name, output->Name());
      EXPECT_EQ(input->value, output->Value());
      EXPECT_EQ(input->url.host(), output->Domain());
      EXPECT_EQ(input->path, output->Path());
      EXPECT_LE(current.ToInternalValue(),
                output->CreationDate().ToInternalValue());
      EXPECT_EQ(input->secure, output->SecureAttribute());
      EXPECT_EQ(input->http_only, output->IsHttpOnly());
      EXPECT_EQ(input->same_site, output->SameSite());
      EXPECT_TRUE(output->IsPersistent());
      EXPECT_EQ(input->expiration_time.ToInternalValue(),
                output->ExpiryDate().ToInternalValue());
    }
  }
}

TEST_F(CookieMonsterTest, RestoreDifferentCookieSameCreationTime) {
  // Test that we can restore different cookies with duplicate creation times.
  base::Time current(base::Time::Now());
  scoped_refptr<MockPersistentCookieStore> store =
      base::MakeRefCounted<MockPersistentCookieStore>();

  {
    CookieMonster cmout(store.get(), net::NetLog::Get());
    GURL url("http://www.example.com/");
    EXPECT_TRUE(
        SetCookieWithCreationTime(&cmout, url, "A=1; max-age=600", current));
    EXPECT_TRUE(
        SetCookieWithCreationTime(&cmout, url, "B=2; max-age=600", current));
  }

  // Play back the cookies into store 2.
  scoped_refptr<MockPersistentCookieStore> store2 =
      base::MakeRefCounted<MockPersistentCookieStore>();
  std::vector<std::unique_ptr<CanonicalCookie>> load_expectation;
  EXPECT_EQ(2u, store->commands().size());
  for (const CookieStoreCommand& command : store->commands()) {
    ASSERT_EQ(command.type, CookieStoreCommand::ADD);
    load_expectation.push_back(
        std::make_unique<CanonicalCookie>(command.cookie));
  }
  store2->SetLoadExpectation(true, std::move(load_expectation));

  // Now read them in. Should get two cookies, not one.
  {
    CookieMonster cmin(store2.get(), net::NetLog::Get());
    CookieList cookies(GetAllCookies(&cmin));
    ASSERT_EQ(2u, cookies.size());
  }
}

TEST_F(CookieMonsterTest, CookieListOrdering) {
  // Put a random set of cookies into a monster and make sure
  // they're returned in the right order.
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  EXPECT_TRUE(
      SetCookie(cm.get(), GURL("http://d.c.b.a.foo.com/aa/x.html"), "c=1"));
  EXPECT_TRUE(SetCookie(cm.get(), GURL("http://b.a.foo.com/aa/bb/cc/x.html"),
                        "d=1; domain=b.a.foo.com"));
  EXPECT_TRUE(SetCookie(cm.get(), GURL("http://b.a.foo.com/aa/bb/cc/x.html"),
                        "a=4; domain=b.a.foo.com"));
  EXPECT_TRUE(SetCookie(cm.get(), GURL("http://c.b.a.foo.com/aa/bb/cc/x.html"),
                        "e=1; domain=c.b.a.foo.com"));
  EXPECT_TRUE(
      SetCookie(cm.get(), GURL("http://d.c.b.a.foo.com/aa/bb/x.html"), "b=1"));
  EXPECT_TRUE(SetCookie(cm.get(), GURL("http://news.bbc.co.uk/midpath/x.html"),
                        "g=10"));
  {
    unsigned int i = 0;
    CookieList cookies(GetAllCookiesForURL(
        cm.get(), GURL("http://d.c.b.a.foo.com/aa/bb/cc/dd")));
    ASSERT_EQ(5u, cookies.size());
    EXPECT_EQ("d", cookies[i++].Name());
    EXPECT_EQ("a", cookies[i++].Name());
    EXPECT_EQ("e", cookies[i++].Name());
    EXPECT_EQ("b", cookies[i++].Name());
    EXPECT_EQ("c", cookies[i++].Name());
  }

  {
    unsigned int i = 0;
    CookieList cookies(GetAllCookies(cm.get()));
    ASSERT_EQ(6u, cookies.size());
    EXPECT_EQ("d", cookies[i++].Name());
    EXPECT_EQ("a", cookies[i++].Name());
    EXPECT_EQ("e", cookies[i++].Name());
    EXPECT_EQ
"""


```