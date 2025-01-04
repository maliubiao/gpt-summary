Response:
The user wants a summary of the functionality of the provided C++ code snippet from `cookie_monster_unittest.cc`. This is part 8 of 10, suggesting a series of tests related to cookie management in Chromium's network stack.

I need to analyze the code, identify the key functionalities being tested, and explain them in a way that's understandable, including connections to JavaScript if applicable, examples of logical reasoning, common user errors, and how a user might trigger these code paths.

The code predominantly focuses on testing cookie eviction logic based on domain limits, secure/non-secure status, and global limits. It also includes tests for setting and deleting cookies, handling SameSite attributes, and legacy cookie access. Notifications and interaction with `PersistentCookieStore` are also covered.

Here's a breakdown of the tests:

1. **Secure Cookie Eviction (`TestSecureCookieEviction`):**  This appears to be the central theme of this section, testing how secure and non-secure cookies are evicted when domain limits are reached. Different scenarios are tested based on the number of secure and non-secure cookies.
2. **Equivalent Cookies:** Tests that cookies are considered different if their path or domain attributes differ.
3. **SetCanonicalCookieDoesNotBlockForLoadAll:** Checks that setting a cookie doesn't block operations that load all cookies from the persistent store.
4. **DeleteDuplicateCTime:** Tests deleting cookies with the same creation time.
5. **DeleteCookieWithInheritedTimestamps:** Verifies cookie deletion when creation timestamps are inherited due to overwriting.
6. **RejectCreatedSameSiteCookieOnSet:** Checks that a cookie with a `SameSite` attribute might be rejected during the set operation based on the context.
7. **RejectCreatedSecureCookieOnSet:** Checks that a `Secure` cookie is rejected when set on a non-secure origin.
8. **RejectCreatedHttpOnlyCookieOnSet:** Checks that `HttpOnly` cookies can be rejected based on `CookieOptions`.
9. **CookiesWithoutSameSiteMustBeSecure:** Tests that `SameSite=None` requires the `Secure` attribute.
10. **CookieMonsterNotificationTest:** Focuses on testing the notification system for cookie changes.
11. **CookieMonsterLegacyCookieAccessTest:** Tests the behavior of cookies under "legacy" semantics, particularly with regards to `SameSite`.
12. **IsCookieSentToSamePortThatSetIt:** Tests a utility function to determine if a cookie is being sent to the same port it was set on.
13. **CookieDomainSetHistogram:**  This part is incomplete in the provided snippet, but it clearly intends to test histogram recording for cookie domain settings.

Now, let's structure the answer based on the user's requirements.
基于您提供的 Chromium 网络栈源代码文件 `net/cookies/cookie_monster_unittest.cc` 的第 8 部分，我们可以归纳出其主要功能是**测试 `CookieMonster` 类在各种复杂场景下的 cookie 管理和驱逐策略，特别是关于 secure 和 non-secure cookies 的处理。**

以下是更详细的列举：

**功能列表:**

1. **测试 Secure Cookie 的驱逐机制 (Secure Cookie Eviction):**
    *   验证当单个域名下的 secure cookies 达到域名限制时，非 secure cookie 不会驱逐它们。
    *   验证当单个域名下的 non-secure cookies 达到域名限制时，创建 secure cookies 会优先驱逐 non-secure cookies。
    *   验证当单个域名下的 secure cookies 超过域名限制时，会按照一定的数量被驱逐。
    *   验证当创建一个 non-secure cookie，同时 secure cookies 超过域名限制时，会优先驱逐 non-secure cookie。
    *   验证在域名限制内创建同等数量的 secure 和 non-secure cookies 不会发生驱逐。
    *   验证当 secure 和 non-secure cookies 总数超过域名限制时，会保留 secure cookies 并驱逐 non-secure cookies。
    *   验证当其他域名存在过期的 non-secure cookies 时，当前域名达到限制后，其他域名的 cookies 不受影响。
    *   验证当其他域名存在大量的 secure cookies 并达到全局 cookie 限制时，新创建的 non-secure cookie 不会被立即驱逐（如果它足够新）。
    *   验证当其他域名存在大量的 non-secure cookies 并达到全局 cookie 限制时，新创建的 non-secure cookie 会导致其他 non-secure cookies 被驱逐。
    *   验证当其他域名存在大量的 non-secure cookies 并达到全局 cookie 限制时，新创建的 secure cookie 不会被驱逐。
    *   验证当其他域名存在大量的 secure 和 non-secure cookies 并达到全局 cookie 限制时，新创建的 non-secure cookie 会导致其他 non-secure cookies 被驱逐，但 secure cookies 不会被驱逐。
    *   验证当其他域名存在大量的 secure 和 non-secure cookies 并达到全局 cookie 限制时，新创建的 secure cookie 会导致其他 non-secure cookies 被驱逐，但 secure cookies 不会被驱逐。

2. **测试等价 Cookie 的处理 (Equivalent Cookies):**
    *   验证即使 cookie 的名字相同，但路径 (path) 不同时，可以成功设置多个 cookie。
    *   验证即使 cookie 的名字相同，但域名 (domain) 不同时，可以成功设置多个 cookie。

3. **测试 `SetCanonicalCookieAsync` 在加载所有 cookies 时不会阻塞 (SetCanonicalCookieDoesNotBlockForLoadAll):**
    *   验证异步设置 canonical cookie 的操作不会阻塞获取所有 cookies 的操作。

4. **测试删除具有相同创建时间的 Cookie (DeleteDuplicateCTime):**
    *   验证 `DeleteCanonicalCookie` 可以正确区分具有相同创建时间但名字或路径不同的 cookie。

5. **测试删除具有继承时间戳的 Cookie (DeleteCookieWithInheritedTimestamps):**
    *   验证即使 cookie 由于被覆盖而继承了旧的创建时间戳，仍然可以被正确删除。

6. **测试拒绝设置已创建的 SameSite Cookie (RejectCreatedSameSiteCookieOnSet):**
    *   验证即使 cookie 在创建时带有 `SameSite` 属性，但在设置时如果上下文不符合 `SameSite` 的要求，仍然会被拒绝。

7. **测试拒绝设置已创建的 Secure Cookie (RejectCreatedSecureCookieOnSet):**
    *   验证即使 cookie 在创建时带有 `Secure` 属性，但在非 HTTPS 页面尝试设置时会被拒绝。

8. **测试拒绝设置已创建的 HttpOnly Cookie (RejectCreatedHttpOnlyCookieOnSet):**
    *   验证即使 cookie 在创建时带有 `HttpOnly` 属性，但在设置时如果 `CookieOptions` 不允许 HttpOnly，则会被拒绝。

9. **测试缺少 SameSite 属性的 Cookie 必须是 Secure 的 (CookiesWithoutSameSiteMustBeSecure):**
    *   测试在启用 SameSite 功能后，从安全来源设置的未指定 `SameSite` 属性的 cookie 不会被拒绝。
    *   测试 `SameSite=None` 属性的 cookie 必须同时设置 `Secure` 属性，否则会被拒绝。
    *   测试从非安全来源设置的未指定 `SameSite` 属性的 cookie 不会被拒绝（会默认使用 Lax 策略）。

10. **测试 CookieMonster 的通知机制 (CookieMonsterNotificationTest):**
    *   验证在加载 cookie 时不会触发 cookie 变更的通知。
    *   验证在进行 cookie 设置、覆盖、删除等操作时会触发相应的通知。

11. **测试 CookieMonster 的旧版 Cookie 访问 (CookieMonsterLegacyCookieAccessTest):**
    *   测试在非旧版语义下设置和获取未指定 `SameSite` 属性的 cookie 会失败，但在旧版语义下可以成功。
    *   测试在非旧版语义下设置和获取 `SameSite=None` 但非 `Secure` 的 cookie 会失败，但在旧版语义下可以成功。

12. **测试 Cookie 是否发送到设置它的相同端口 (IsCookieSentToSamePortThatSetIt):**
    *   测试一个用于判断 cookie 是否发送到与设置它的来源相同的端口的实用函数，涵盖了各种端口和来源 scheme 的组合情况。

13. **测试 Cookie 域名设置的 Histogram 记录 (CookieDomainSetHistogram):**
    *   这部分代码片段不完整，但可以推断出其目的是测试与 cookie 域名设置相关的 histogram 记录功能。

**与 Javascript 的关系及举例说明:**

`CookieMonster` 类是 Chromium 网络栈中负责管理 HTTP Cookie 的核心组件。它与 JavaScript 中的 `document.cookie` API 有着直接的关系。JavaScript 代码通过 `document.cookie` 读取、设置和删除浏览器中的 cookie，而 `CookieMonster` 类则负责处理这些操作背后的逻辑，包括存储、过期管理、安全策略检查等。

**举例说明:**

假设一个 JavaScript 脚本在 HTTPS 网站 `https://example.com` 上尝试设置一个 cookie：

```javascript
document.cookie = "myCookie=value; SameSite=None; Secure";
```

当浏览器执行这段 JavaScript 代码时，它会调用 Chromium 网络栈的相应接口，最终会调用到 `CookieMonster` 类的相关方法来处理这个 cookie 的设置。 这部分测试代码（例如，"CookiesWithoutSameSiteMustBeSecure" 测试用例）会验证 `CookieMonster` 是否正确地执行了 `SameSite` 和 `Secure` 属性的检查。如果缺少 `Secure` 属性，即使在 HTTPS 网站上，这个 cookie 也应该被拒绝设置。

**逻辑推理、假设输入与输出:**

**示例：测试 Secure Cookie 的驱逐机制 (test1)**

*   **假设输入:**
    *   当前域名下已存在 180 个 secure cookies。
    *   尝试设置 1 个 non-secure cookie。
*   **逻辑推理:** 由于已达到 secure cookie 的域名限制，新创建的 non-secure cookie 不应驱逐已有的 secure cookie。实际上，由于无法添加新 cookie，这个 non-secure cookie 会在创建后立即被移除。
*   **预期输出:** non-secure cookie 设置失败或立即被删除，secure cookies 的数量保持 180 个。

**用户或编程常见的使用错误及举例说明:**

1. **在非 HTTPS 页面设置 Secure Cookie:** 用户（开发者）可能会错误地尝试在 HTTP 页面上设置带有 `Secure` 属性的 cookie。
    *   **错误示例 (JavaScript):**  在 `http://example.com` 页面执行 `document.cookie = "myCookie=value; Secure";`
    *   **测试覆盖:** "RejectCreatedSecureCookieOnSet" 测试用例模拟了这种情况，并验证 `CookieMonster` 会拒绝设置该 cookie。

2. **缺少 SameSite=None 时未设置 Secure 属性:**  为了在跨站场景下发送 cookie，开发者可能会设置 `SameSite=None`，但忘记同时设置 `Secure` 属性。
    *   **错误示例 (JavaScript):** `document.cookie = "myCookie=value; SameSite=None";`
    *   **测试覆盖:** "CookiesWithoutSameSiteMustBeSecure" 测试用例验证了 `CookieMonster` 会拒绝这样的 cookie 设置。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中访问一个网页 (例如，`https://example.com`)。**
2. **网页上的 JavaScript 代码尝试设置一个或多个 cookie，例如使用 `document.cookie`。**
3. **浏览器接收到 JavaScript 的 cookie 设置请求。**
4. **浏览器将 cookie 设置请求传递给 Chromium 的网络栈。**
5. **网络栈中的 `CookieMonster` 类接收到 cookie 设置请求。**
6. **`CookieMonster` 会根据 cookie 的属性（例如，`Secure`、`HttpOnly`、`SameSite`）、域名、路径等信息以及当前的浏览器状态（例如，是否是 HTTPS 页面）进行一系列的检查和处理。**
7. **这部分测试代码模拟了各种可能的 cookie 设置场景，以验证 `CookieMonster` 在不同情况下的行为是否符合预期，包括 cookie 驱逐、安全策略执行等。**

**总结第 8 部分的功能:**

总而言之，这段代码主要集中于对 `CookieMonster` 类的 cookie 驱逐策略进行细致的测试，特别是关注 secure 和 non-secure cookies 在达到域名和全局限制时的行为。此外，它还涵盖了对 cookie 设置、删除、以及与安全相关的属性（`Secure`、`HttpOnly`、`SameSite`）处理的测试，以及对通知机制和旧版 cookie 访问的支持情况的验证。 这些测试确保了 Chromium 的 cookie 管理机制的正确性和健壮性。

Prompt: 
```
这是目录为net/cookies/cookie_monster_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共10部分，请归纳一下它的功能

"""
30, CookieMonster::kSafeFromGlobalPurgeDays);

  // If secure cookies for one domain hit the per domain limit (180), a
  // non-secure cookie will not evict them (and, in fact, the non-secure cookie
  // will be removed right after creation).
  const CookiesEntry test1[] = {{180U, true}, {1U, false}};
  TestSecureCookieEviction(test1, 150U, 0U, nullptr);

  // If non-secure cookies for one domain hit the per domain limit (180), the
  // creation of secure cookies will evict the non-secure cookies first, making
  // room for the secure cookies.
  const CookiesEntry test2[] = {{180U, false}, {20U, true}};
  TestSecureCookieEviction(test2, 20U, 149U, nullptr);

  // If secure cookies for one domain go past the per domain limit (180), they
  // will be evicted as normal by the per domain purge amount (30) down to a
  // lower amount (150), and then will continue to create the remaining cookies
  // (19 more to 169).
  const CookiesEntry test3[] = {{200U, true}};
  TestSecureCookieEviction(test3, 169U, 0U, nullptr);

  // If a non-secure cookie is created, and a number of secure cookies exceeds
  // the per domain limit (18), the total cookies will be evicted down to a
  // lower amount (150), enforcing the eviction of the non-secure cookie, and
  // the remaining secure cookies will be created (another 19 to 169).
  const CookiesEntry test4[] = {{1U, false}, {199U, true}};
  TestSecureCookieEviction(test4, 169U, 0U, nullptr);

  // If an even number of non-secure and secure cookies are created below the
  // per-domain limit (180), all will be created and none evicted.
  const CookiesEntry test5[] = {{75U, false}, {75U, true}};
  TestSecureCookieEviction(test5, 75U, 75U, nullptr);

  // If the same number of secure and non-secure cookies are created (50 each)
  // below the per domain limit (180), and then another set of secure cookies
  // are created to bring the total above the per-domain limit, all secure
  // cookies will be retained, and the non-secure cookies will be culled down
  // to the limit.
  const CookiesEntry test6[] = {{50U, true}, {50U, false}, {81U, true}};
  TestSecureCookieEviction(test6, 131U, 19U, nullptr);

  // If the same number of non-secure and secure cookies are created (50 each)
  // below the per domain limit (180), and then another set of non-secure
  // cookies are created to bring the total above the per-domain limit, all
  // secure cookies will be retained, and the non-secure cookies will be culled
  // down to the limit.
  const CookiesEntry test7[] = {{50U, false}, {50U, true}, {81U, false}};
  TestSecureCookieEviction(test7, 50U, 100U, nullptr);

  // If the same number of non-secure and secure cookies are created (50 each)
  // below the per domain limit (180), and then another set of non-secure
  // cookies are created to bring the total above the per-domain limit, all
  // secure cookies will be retained, and the non-secure cookies will be culled
  // down to the limit, then the remaining non-secure cookies will be created
  // (9).
  const CookiesEntry test8[] = {{50U, false}, {50U, true}, {90U, false}};
  TestSecureCookieEviction(test8, 50U, 109U, nullptr);

  // If a number of non-secure cookies are created on other hosts (20) and are
  // past the global 'safe' date, and then the number of non-secure cookies for
  // a single domain are brought to the per-domain limit (180), followed by
  // another set of secure cookies on that same domain (20), all the secure
  // cookies for that domain should be retained, while the non-secure should be
  // culled down to the per-domain limit. The non-secure cookies for other
  // domains should remain untouched.
  const CookiesEntry test9[] = {{180U, false}, {20U, true}};
  const AltHosts test9_alt_hosts(0, 20);
  TestSecureCookieEviction(test9, 20U, 169U, &test9_alt_hosts);

  // If a number of secure cookies are created on other hosts and hit the global
  // cookie limit (3300) and are past the global 'safe' date, and then a single
  // non-secure cookie is created now, the secure cookies are removed so that
  // the global total number of cookies is at the global purge goal (3000), but
  // the non-secure cookie is not evicted since it is too young.
  const CookiesEntry test10[] = {{1U, false}};
  const AltHosts test10_alt_hosts(3300, 0);
  TestSecureCookieEviction(test10, 2999U, 1U, &test10_alt_hosts);

  // If a number of non-secure cookies are created on other hosts and hit the
  // global cookie limit (3300) and are past the global 'safe' date, and then a
  // single non-secure cookie is created now, the non-secure cookies are removed
  // so that the global total number of cookies is at the global purge goal
  // (3000).
  const CookiesEntry test11[] = {{1U, false}};
  const AltHosts test11_alt_hosts(0, 3300);
  TestSecureCookieEviction(test11, 0U, 3000U, &test11_alt_hosts);

  // If a number of non-secure cookies are created on other hosts and hit the
  // global cookie limit (3300) and are past the global 'safe' date, and then a
  // single ecure cookie is created now, the non-secure cookies are removed so
  // that the global total number of cookies is at the global purge goal (3000),
  // but the secure cookie is not evicted.
  const CookiesEntry test12[] = {{1U, true}};
  const AltHosts test12_alt_hosts(0, 3300);
  TestSecureCookieEviction(test12, 1U, 2999U, &test12_alt_hosts);

  // If a total number of secure and non-secure cookies are created on other
  // hosts and hit the global cookie limit (3300) and are past the global 'safe'
  // date, and then a single non-secure cookie is created now, the global
  // non-secure cookies are removed so that the global total number of cookies
  // is at the global purge goal (3000), but the secure cookies are not evicted.
  const CookiesEntry test13[] = {{1U, false}};
  const AltHosts test13_alt_hosts(1500, 1800);
  TestSecureCookieEviction(test13, 1500U, 1500, &test13_alt_hosts);

  // If a total number of secure and non-secure cookies are created on other
  // hosts and hit the global cookie limit (3300) and are past the global 'safe'
  // date, and then a single secure cookie is created now, the global non-secure
  // cookies are removed so that the global total number of cookies is at the
  // global purge goal (3000), but the secure cookies are not evicted.
  const CookiesEntry test14[] = {{1U, true}};
  const AltHosts test14_alt_hosts(1500, 1800);
  TestSecureCookieEviction(test14, 1501U, 1499, &test14_alt_hosts);
}

// Tests that strict secure cookies doesn't trip equivalent cookie checks
// accidentally. Regression test for https://crbug.com/569943.
TEST_F(CookieMonsterTest, EquivalentCookies) {
  auto cm = std::make_unique<CookieMonster>(nullptr, nullptr);
  GURL http_url("http://www.foo.com");
  GURL http_superdomain_url("http://foo.com");
  GURL https_url("https://www.foo.com");

  // Tests that non-equivalent cookies because of the path attribute can be set
  // successfully.
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), https_url, "A=B; Secure")
                  .IsInclude());
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), https_url,
                                             "A=C; path=/some/other/path")
                  .IsInclude());
  EXPECT_FALSE(SetCookie(cm.get(), http_url, "A=D; path=/some/other/path"));

  // Tests that non-equivalent cookies because of the domain attribute can be
  // set successfully.
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), https_url, "A=B; Secure")
                  .IsInclude());
  EXPECT_TRUE(
      CreateAndSetCookieReturnStatus(cm.get(), https_url, "A=C; domain=foo.com")
          .IsInclude());
  EXPECT_FALSE(SetCookie(cm.get(), http_url, "A=D; domain=foo.com"));
}

TEST_F(CookieMonsterTest, SetCanonicalCookieDoesNotBlockForLoadAll) {
  scoped_refptr<MockPersistentCookieStore> persistent_store =
      base::MakeRefCounted<MockPersistentCookieStore>();
  // Collect load commands so we have control over their execution.
  persistent_store->set_store_load_commands(true);
  CookieMonster cm(persistent_store.get(), nullptr);

  // Start of a canonical cookie set.
  ResultSavingCookieCallback<CookieAccessResult> callback_set;
  GURL cookie_url("http://a.com/");
  cm.SetCanonicalCookieAsync(
      CanonicalCookie::CreateForTesting(cookie_url, "A=B", base::Time::Now()),
      cookie_url, CookieOptions::MakeAllInclusive(),
      callback_set.MakeCallback());

  // Get cookies for a different URL.
  GetCookieListCallback callback_get;
  cm.GetCookieListWithOptionsAsync(
      GURL("http://b.com/"), CookieOptions::MakeAllInclusive(),
      CookiePartitionKeyCollection(), callback_get.MakeCallback());

  // Now go through the store commands, and execute individual loads.
  const auto& commands = persistent_store->commands();
  for (size_t i = 0; i < commands.size(); ++i) {
    if (commands[i].type == CookieStoreCommand::LOAD_COOKIES_FOR_KEY)
      persistent_store->TakeCallbackAt(i).Run(
          std::vector<std::unique_ptr<CanonicalCookie>>());
  }

  // This should be enough for both individual commands.
  callback_set.WaitUntilDone();
  callback_get.WaitUntilDone();

  // Now execute full-store loads as well.
  for (size_t i = 0; i < commands.size(); ++i) {
    if (commands[i].type == CookieStoreCommand::LOAD)
      persistent_store->TakeCallbackAt(i).Run(
          std::vector<std::unique_ptr<CanonicalCookie>>());
  }
}

TEST_F(CookieMonsterTest, DeleteDuplicateCTime) {
  const char* const kNames[] = {"A", "B", "C"};

  // Tests that DeleteCanonicalCookie properly distinguishes different cookies
  // (e.g. different name or path) with identical ctime on same domain.
  // This gets tested a few times with different deletion target, to make sure
  // that the implementation doesn't just happen to pick the right one because
  // of implementation details.
  for (const auto* name : kNames) {
    CookieMonster cm(nullptr, nullptr);
    Time now = Time::Now();
    GURL url("http://www.example.com");

    for (size_t i = 0; i < std::size(kNames); ++i) {
      std::string cookie_string =
          base::StrCat({kNames[i], "=", base::NumberToString(i)});
      EXPECT_TRUE(SetCookieWithCreationTime(&cm, url, cookie_string, now));
    }

    // Delete the run'th cookie.
    CookieList all_cookies = GetAllCookiesForURLWithOptions(
        &cm, url, CookieOptions::MakeAllInclusive());
    ASSERT_EQ(all_cookies.size(), std::size(kNames));
    for (size_t i = 0; i < std::size(kNames); ++i) {
      const CanonicalCookie& cookie = all_cookies[i];
      if (cookie.Name() == name) {
        EXPECT_TRUE(DeleteCanonicalCookie(&cm, cookie));
      }
    }

    // Check that the right cookie got removed.
    all_cookies = GetAllCookiesForURLWithOptions(
        &cm, url, CookieOptions::MakeAllInclusive());
    ASSERT_EQ(all_cookies.size(), std::size(kNames) - 1);
    for (size_t i = 0; i < std::size(kNames) - 1; ++i) {
      const CanonicalCookie& cookie = all_cookies[i];
      EXPECT_NE(cookie.Name(), name);
    }
  }
}

TEST_F(CookieMonsterTest, DeleteCookieWithInheritedTimestamps) {
  Time t1 = Time::Now();
  Time t2 = t1 + base::Seconds(1);
  GURL url("http://www.example.com");
  std::string cookie_line = "foo=bar";
  CookieOptions options = CookieOptions::MakeAllInclusive();
  std::optional<base::Time> server_time = std::nullopt;
  std::optional<CookiePartitionKey> partition_key = std::nullopt;
  CookieMonster cm(nullptr, nullptr);

  // Write a cookie created at |t1|.
  auto cookie = CanonicalCookie::CreateForTesting(url, cookie_line, t1,
                                                  server_time, partition_key);
  ResultSavingCookieCallback<CookieAccessResult> set_callback_1;
  cm.SetCanonicalCookieAsync(std::move(cookie), url, options,
                             set_callback_1.MakeCallback());
  set_callback_1.WaitUntilDone();

  // Overwrite the cookie at |t2|.
  cookie = CanonicalCookie::CreateForTesting(url, cookie_line, t2, server_time,
                                             partition_key);
  ResultSavingCookieCallback<CookieAccessResult> set_callback_2;
  cm.SetCanonicalCookieAsync(std::move(cookie), url, options,
                             set_callback_2.MakeCallback());
  set_callback_2.WaitUntilDone();

  // The second cookie overwrites the first one but it will inherit the creation
  // timestamp |t1|. Test that deleting the new cookie still works.
  cookie = CanonicalCookie::CreateForTesting(url, cookie_line, t2, server_time,
                                             partition_key);
  ResultSavingCookieCallback<unsigned int> delete_callback;
  cm.DeleteCanonicalCookieAsync(*cookie, delete_callback.MakeCallback());
  delete_callback.WaitUntilDone();
  EXPECT_EQ(1U, delete_callback.result());
}

TEST_F(CookieMonsterTest, RejectCreatedSameSiteCookieOnSet) {
  GURL url("http://www.example.com");
  std::string cookie_line = "foo=bar; SameSite=Lax";

  CookieMonster cm(nullptr, nullptr);
  CookieOptions env_cross_site;
  env_cross_site.set_same_site_cookie_context(
      CookieOptions::SameSiteCookieContext(
          CookieOptions::SameSiteCookieContext::ContextType::CROSS_SITE));

  CookieInclusionStatus status;
  // Cookie can be created successfully; SameSite is not checked on Creation.
  auto cookie =
      CanonicalCookie::CreateForTesting(url, cookie_line, base::Time::Now(),
                                        /*server_time=*/std::nullopt,
                                        /*cookie_partition_key=*/std::nullopt,
                                        CookieSourceType::kUnknown, &status);
  ASSERT_TRUE(cookie != nullptr);
  ASSERT_TRUE(status.IsInclude());

  // ... but the environment is checked on set, so this may be rejected then.
  ResultSavingCookieCallback<CookieAccessResult> callback;
  cm.SetCanonicalCookieAsync(std::move(cookie), url, env_cross_site,
                             callback.MakeCallback());
  callback.WaitUntilDone();
  EXPECT_TRUE(callback.result().status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_SAMESITE_LAX}));
}

TEST_F(CookieMonsterTest, RejectCreatedSecureCookieOnSet) {
  GURL http_url("http://www.example.com");
  std::string cookie_line = "foo=bar; Secure";

  CookieMonster cm(nullptr, nullptr);
  CookieInclusionStatus status;
  // Cookie can be created successfully from an any url. Secure is not checked
  // on Create.
  auto cookie = CanonicalCookie::CreateForTesting(
      http_url, cookie_line, base::Time::Now(), /*server_time=*/std::nullopt,
      /*cookie_partition_key=*/std::nullopt, CookieSourceType::kUnknown,
      &status);

  ASSERT_TRUE(cookie != nullptr);
  ASSERT_TRUE(status.IsInclude());

  // Cookie is rejected when attempting to set from a non-secure scheme.
  ResultSavingCookieCallback<CookieAccessResult> callback;
  cm.SetCanonicalCookieAsync(std::move(cookie), http_url,
                             CookieOptions::MakeAllInclusive(),
                             callback.MakeCallback());
  callback.WaitUntilDone();
  EXPECT_TRUE(callback.result().status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_SECURE_ONLY}));
}

TEST_F(CookieMonsterTest, RejectCreatedHttpOnlyCookieOnSet) {
  GURL url("http://www.example.com");
  std::string cookie_line = "foo=bar; HttpOnly";

  CookieMonster cm(nullptr, nullptr);
  CookieInclusionStatus status;
  // Cookie can be created successfully; HttpOnly is not checked on Create.
  auto cookie =
      CanonicalCookie::CreateForTesting(url, cookie_line, base::Time::Now(),
                                        /*server_time=*/std::nullopt,
                                        /*cookie_partition_key=*/std::nullopt,
                                        CookieSourceType::kUnknown, &status);

  ASSERT_TRUE(cookie != nullptr);
  ASSERT_TRUE(status.IsInclude());

  // Cookie is rejected when attempting to set with a CookieOptions that does
  // not allow httponly.
  CookieOptions options_no_httponly;
  options_no_httponly.set_same_site_cookie_context(
      CookieOptions::SameSiteCookieContext(
          CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_STRICT));
  options_no_httponly.set_exclude_httponly();  // Default, but make it explicit.
  ResultSavingCookieCallback<CookieAccessResult> callback;
  cm.SetCanonicalCookieAsync(std::move(cookie), url, options_no_httponly,
                             callback.MakeCallback());
  callback.WaitUntilDone();
  EXPECT_TRUE(callback.result().status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_HTTP_ONLY}));
}

// Test that SameSite=None requires Secure.
TEST_F(CookieMonsterTest, CookiesWithoutSameSiteMustBeSecure) {
  const base::TimeDelta kLongAge = kLaxAllowUnsafeMaxAge * 4;
  const base::TimeDelta kShortAge = kLaxAllowUnsafeMaxAge / 4;

  struct TestCase {
    bool is_url_secure;
    std::string cookie_line;
    CookieInclusionStatus expected_set_cookie_result;
    // Only makes sense to check if result is INCLUDE:
    CookieEffectiveSameSite expected_effective_samesite =
        CookieEffectiveSameSite::NO_RESTRICTION;
    base::TimeDelta creation_time_delta = base::TimeDelta();
  } test_cases[] = {
      // Feature enabled:
      // Cookie set from a secure URL with SameSite enabled is not rejected.
      {true, "A=B; SameSite=Lax", CookieInclusionStatus(),
       CookieEffectiveSameSite::LAX_MODE},
      // Cookie set from a secure URL which is defaulted into Lax is not
      // rejected.
      {true, "A=B",  // recently-set session cookie.
       CookieInclusionStatus(), CookieEffectiveSameSite::LAX_MODE_ALLOW_UNSAFE,
       kShortAge},
      {true, "A=B",  // not-recently-set session cookie.
       CookieInclusionStatus(), CookieEffectiveSameSite::LAX_MODE, kLongAge},
      // Cookie set from a secure URL with SameSite=None and Secure is set.
      {true, "A=B; SameSite=None; Secure", CookieInclusionStatus(),
       CookieEffectiveSameSite::NO_RESTRICTION},
      // Cookie set from a secure URL with SameSite=None but not specifying
      // Secure is rejected.
      {true, "A=B; SameSite=None",
       CookieInclusionStatus(
           CookieInclusionStatus::EXCLUDE_SAMESITE_NONE_INSECURE,
           CookieInclusionStatus::WARN_SAMESITE_NONE_INSECURE)},
      // Cookie set from an insecure URL which defaults into LAX_MODE is not
      // rejected.
      {false, "A=B",  // recently-set session cookie.
       CookieInclusionStatus(), CookieEffectiveSameSite::LAX_MODE_ALLOW_UNSAFE,
       kShortAge},
      {false, "A=B",  // not-recently-set session cookie.
       CookieInclusionStatus(), CookieEffectiveSameSite::LAX_MODE, kLongAge},
      {false, "A=B; Max-Age=1000000",  // recently-set persistent cookie.
       CookieInclusionStatus(), CookieEffectiveSameSite::LAX_MODE_ALLOW_UNSAFE,
       kShortAge},
      {false,
       "A=B; Max-Age=1000000",  // not-recently-set persistent cookie.
       CookieInclusionStatus(), CookieEffectiveSameSite::LAX_MODE, kLongAge},
  };

  auto cm = std::make_unique<CookieMonster>(nullptr, nullptr);
  GURL secure_url("https://www.example1.test");
  GURL insecure_url("http://www.example2.test");

  int length = sizeof(test_cases) / sizeof(test_cases[0]);
  for (int i = 0; i < length; ++i) {
    TestCase test = test_cases[i];

    GURL url = test.is_url_secure ? secure_url : insecure_url;
    base::Time creation_time = base::Time::Now() - test.creation_time_delta;
    auto cookie =
        CanonicalCookie::CreateForTesting(url, test.cookie_line, creation_time);
    // Make a copy so we can delete it after the test.
    CanonicalCookie cookie_copy = *cookie;
    CookieAccessResult result = SetCanonicalCookieReturnAccessResult(
        cm.get(), std::move(cookie), url,
        true /* can_modify_httponly (irrelevant) */);
    EXPECT_EQ(test.expected_set_cookie_result, result.status)
        << "Test case " << i << " failed.";
    if (result.status.IsInclude()) {
      auto cookies = GetAllCookiesForURL(cm.get(), url);
      ASSERT_EQ(1u, cookies.size());
      EXPECT_EQ(test.expected_effective_samesite, result.effective_same_site)
          << "Test case " << i << " failed.";
      DeleteCanonicalCookie(cm.get(), cookie_copy);
    }
  }
}

class CookieMonsterNotificationTest : public CookieMonsterTest {
 public:
  CookieMonsterNotificationTest()
      : test_url_("http://www.foo.com/foo"),
        store_(base::MakeRefCounted<MockPersistentCookieStore>()),
        monster_(std::make_unique<CookieMonster>(store_.get(), nullptr)) {}

  ~CookieMonsterNotificationTest() override = default;

  CookieMonster* monster() { return monster_.get(); }

 protected:
  const GURL test_url_;

 private:
  scoped_refptr<MockPersistentCookieStore> store_;
  std::unique_ptr<CookieMonster> monster_;
};

void RecordCookieChanges(std::vector<CanonicalCookie>* out_cookies,
                         std::vector<CookieChangeCause>* out_causes,
                         const CookieChangeInfo& change) {
  DCHECK(out_cookies);
  out_cookies->push_back(change.cookie);
  if (out_causes)
    out_causes->push_back(change.cause);
}

// Tests that there are no changes emitted for cookie loading, but there are
// changes emitted for other operations.
TEST_F(CookieMonsterNotificationTest, NoNotificationOnLoad) {
  // Create a persistent store that will not synchronously satisfy the
  // loading requirement.
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  store->set_store_load_commands(true);

  // Bind it to a CookieMonster
  auto monster = std::make_unique<CookieMonster>(store.get(), nullptr);

  // Trigger load dispatch and confirm it.
  monster->GetAllCookiesAsync(CookieStore::GetAllCookiesCallback());
  ASSERT_EQ(1u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::LOAD, store->commands()[0].type);

  // Attach a change subscription.
  std::vector<CanonicalCookie> cookies;
  std::vector<CookieChangeCause> causes;
  std::unique_ptr<CookieChangeSubscription> subscription =
      monster->GetChangeDispatcher().AddCallbackForAllChanges(
          base::BindRepeating(&RecordCookieChanges, &cookies, &causes));

  // Set up some initial cookies, including duplicates.
  std::vector<std::unique_ptr<CanonicalCookie>> initial_cookies;
  GURL url("http://www.foo.com");
  initial_cookies.push_back(
      CanonicalCookie::CreateForTesting(url, "X=1; path=/", base::Time::Now()));
  initial_cookies.push_back(
      CanonicalCookie::CreateForTesting(url, "Y=1; path=/", base::Time::Now()));
  initial_cookies.push_back(CanonicalCookie::CreateForTesting(
      url, "Y=2; path=/", base::Time::Now() + base::Days(1)));

  // Execute the load
  store->TakeCallbackAt(0).Run(std::move(initial_cookies));
  base::RunLoop().RunUntilIdle();

  // We should see no insertions (because loads do not cause notifications to be
  // dispatched), no deletions (because overwriting a duplicate cookie on load
  // does not trigger a notification), and two cookies in the monster.
  EXPECT_EQ(0u, cookies.size());
  EXPECT_EQ(0u, causes.size());
  EXPECT_EQ(2u, this->GetAllCookies(monster.get()).size());

  // Change the cookies again to make sure that other changes do emit
  // notifications.
  this->CreateAndSetCookie(monster.get(), url, "X=2; path=/",
                           CookieOptions::MakeAllInclusive());
  this->CreateAndSetCookie(monster.get(), url, "Y=3; path=/; max-age=0",
                           CookieOptions::MakeAllInclusive());

  base::RunLoop().RunUntilIdle();
  ASSERT_EQ(3u, cookies.size());
  ASSERT_EQ(3u, causes.size());
  EXPECT_EQ("X", cookies[0].Name());
  EXPECT_EQ("1", cookies[0].Value());
  EXPECT_EQ(CookieChangeCause::OVERWRITE, causes[0]);
  EXPECT_EQ("X", cookies[1].Name());
  EXPECT_EQ("2", cookies[1].Value());
  EXPECT_EQ(CookieChangeCause::INSERTED, causes[1]);
  EXPECT_EQ("Y", cookies[2].Name());
  EXPECT_EQ("2", cookies[2].Value());
  EXPECT_EQ(CookieChangeCause::EXPIRED_OVERWRITE, causes[2]);
}

class CookieMonsterLegacyCookieAccessTest : public CookieMonsterTest {
 public:
  CookieMonsterLegacyCookieAccessTest()
      : cm_(std::make_unique<CookieMonster>(nullptr /* store */,
                                            nullptr /* netlog */
                                            )) {
    // Need to reset first because there cannot be two TaskEnvironments at the
    // same time.
    task_environment_.reset();
    task_environment_ =
        std::make_unique<base::test::SingleThreadTaskEnvironment>(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME);

    std::unique_ptr<TestCookieAccessDelegate> access_delegate =
        std::make_unique<TestCookieAccessDelegate>();
    access_delegate_ = access_delegate.get();
    cm_->SetCookieAccessDelegate(std::move(access_delegate));
  }

  ~CookieMonsterLegacyCookieAccessTest() override = default;

 protected:
  const std::string kDomain = "example.test";
  const GURL kHttpsUrl = GURL("https://example.test");
  const GURL kHttpUrl = GURL("http://example.test");
  std::unique_ptr<CookieMonster> cm_;
  raw_ptr<TestCookieAccessDelegate> access_delegate_;
};

TEST_F(CookieMonsterLegacyCookieAccessTest, SetLegacyNoSameSiteCookie) {
  // Check that setting unspecified-SameSite cookie from cross-site context
  // fails if not set to Legacy semantics, but succeeds if set to legacy.
  EXPECT_FALSE(CreateAndSetCookie(cm_.get(), kHttpUrl, "cookie=chocolate_chip",
                                  CookieOptions()));
  access_delegate_->SetExpectationForCookieDomain(
      kDomain, CookieAccessSemantics::UNKNOWN);
  EXPECT_FALSE(CreateAndSetCookie(cm_.get(), kHttpUrl, "cookie=chocolate_chip",
                                  CookieOptions()));
  access_delegate_->SetExpectationForCookieDomain(
      kDomain, CookieAccessSemantics::NONLEGACY);
  EXPECT_FALSE(CreateAndSetCookie(cm_.get(), kHttpUrl, "cookie=chocolate_chip",
                                  CookieOptions()));
  access_delegate_->SetExpectationForCookieDomain(
      kDomain, CookieAccessSemantics::LEGACY);
  EXPECT_TRUE(CreateAndSetCookie(cm_.get(), kHttpUrl, "cookie=chocolate_chip",
                                 CookieOptions()));
}

TEST_F(CookieMonsterLegacyCookieAccessTest, GetLegacyNoSameSiteCookie) {
  // Set a cookie with no SameSite attribute.
  ASSERT_TRUE(CreateAndSetCookie(cm_.get(), kHttpUrl, "cookie=chocolate_chip",
                                 CookieOptions::MakeAllInclusive()));

  // Getting the cookie fails unless semantics is legacy.
  access_delegate_->SetExpectationForCookieDomain(
      kDomain, CookieAccessSemantics::UNKNOWN);
  EXPECT_EQ("", GetCookiesWithOptions(cm_.get(), kHttpUrl, CookieOptions()));
  access_delegate_->SetExpectationForCookieDomain(
      kDomain, CookieAccessSemantics::NONLEGACY);
  EXPECT_EQ("", GetCookiesWithOptions(cm_.get(), kHttpUrl, CookieOptions()));
  access_delegate_->SetExpectationForCookieDomain(
      kDomain, CookieAccessSemantics::LEGACY);
  EXPECT_EQ("cookie=chocolate_chip",
            GetCookiesWithOptions(cm_.get(), kHttpUrl, CookieOptions()));
}

TEST_F(CookieMonsterLegacyCookieAccessTest,
       SetLegacySameSiteNoneInsecureCookie) {
  access_delegate_->SetExpectationForCookieDomain(
      kDomain, CookieAccessSemantics::UNKNOWN);
  EXPECT_FALSE(CreateAndSetCookie(cm_.get(), kHttpsUrl,
                                  "cookie=oatmeal_raisin; SameSite=None",
                                  CookieOptions()));
  access_delegate_->SetExpectationForCookieDomain(
      kDomain, CookieAccessSemantics::NONLEGACY);
  EXPECT_FALSE(CreateAndSetCookie(cm_.get(), kHttpsUrl,
                                  "cookie=oatmeal_raisin; SameSite=None",
                                  CookieOptions()));
  // Setting the access semantics to legacy allows setting the cookie.
  access_delegate_->SetExpectationForCookieDomain(
      kDomain, CookieAccessSemantics::LEGACY);
  EXPECT_TRUE(CreateAndSetCookie(cm_.get(), kHttpsUrl,
                                 "cookie=oatmeal_raisin; SameSite=None",
                                 CookieOptions()));
  EXPECT_EQ("cookie=oatmeal_raisin",
            GetCookiesWithOptions(cm_.get(), kHttpsUrl, CookieOptions()));
}

TEST_F(CookieMonsterLegacyCookieAccessTest,
       GetLegacySameSiteNoneInsecureCookie) {
  // Need to inject such a cookie under legacy semantics.
  access_delegate_->SetExpectationForCookieDomain(
      kDomain, CookieAccessSemantics::LEGACY);
  ASSERT_TRUE(CreateAndSetCookie(cm_.get(), kHttpUrl,
                                 "cookie=oatmeal_raisin; SameSite=None",
                                 CookieOptions::MakeAllInclusive()));
  // Getting a SameSite=None but non-Secure cookie fails unless semantics is
  // legacy.
  access_delegate_->SetExpectationForCookieDomain(
      kDomain, CookieAccessSemantics::UNKNOWN);
  EXPECT_EQ("", GetCookiesWithOptions(cm_.get(), kHttpUrl, CookieOptions()));
  access_delegate_->SetExpectationForCookieDomain(
      kDomain, CookieAccessSemantics::NONLEGACY);
  EXPECT_EQ("", GetCookiesWithOptions(cm_.get(), kHttpUrl, CookieOptions()));
  access_delegate_->SetExpectationForCookieDomain(
      kDomain, CookieAccessSemantics::LEGACY);
  EXPECT_EQ("cookie=oatmeal_raisin",
            GetCookiesWithOptions(cm_.get(), kHttpUrl, CookieOptions()));
}

TEST_F(CookieMonsterTest, IsCookieSentToSamePortThatSetIt) {
  // Note: `IsCookieSentToSamePortThatSetIt()` only uses the source_scheme if
  // the port is valid, specified, and doesn't match the url's port. So for test
  // cases where the above aren't true the value of source_scheme is irreleant.

  // Test unspecified.
  ASSERT_EQ(CookieMonster::IsCookieSentToSamePortThatSetIt(
                GURL("https://foo.com"), url::PORT_UNSPECIFIED,
                CookieSourceScheme::kSecure),
            CookieMonster::CookieSentToSamePort::kSourcePortUnspecified);

  // Test invalid.
  ASSERT_EQ(CookieMonster::IsCookieSentToSamePortThatSetIt(
                GURL("https://foo.com"), url::PORT_INVALID,
                CookieSourceScheme::kSecure),
            CookieMonster::CookieSentToSamePort::kInvalid);

  // Test same.
  ASSERT_EQ(CookieMonster::IsCookieSentToSamePortThatSetIt(
                GURL("https://foo.com"), 443, CookieSourceScheme::kSecure),
            CookieMonster::CookieSentToSamePort::kYes);

  ASSERT_EQ(
      CookieMonster::IsCookieSentToSamePortThatSetIt(
          GURL("https://foo.com:1234"), 1234, CookieSourceScheme::kSecure),
      CookieMonster::CookieSentToSamePort::kYes);

  // Test different but default.
  ASSERT_EQ(CookieMonster::IsCookieSentToSamePortThatSetIt(
                GURL("https://foo.com"), 80, CookieSourceScheme::kNonSecure),
            CookieMonster::CookieSentToSamePort::kNoButDefault);

  ASSERT_EQ(
      CookieMonster::IsCookieSentToSamePortThatSetIt(
          GURL("https://foo.com:443"), 80, CookieSourceScheme::kNonSecure),
      CookieMonster::CookieSentToSamePort::kNoButDefault);

  ASSERT_EQ(CookieMonster::IsCookieSentToSamePortThatSetIt(
                GURL("wss://foo.com"), 80, CookieSourceScheme::kNonSecure),
            CookieMonster::CookieSentToSamePort::kNoButDefault);

  ASSERT_EQ(CookieMonster::IsCookieSentToSamePortThatSetIt(
                GURL("http://foo.com"), 443, CookieSourceScheme::kSecure),
            CookieMonster::CookieSentToSamePort::kNoButDefault);

  ASSERT_EQ(CookieMonster::IsCookieSentToSamePortThatSetIt(
                GURL("ws://foo.com"), 443, CookieSourceScheme::kSecure),
            CookieMonster::CookieSentToSamePort::kNoButDefault);

  // Test different.
  ASSERT_EQ(CookieMonster::IsCookieSentToSamePortThatSetIt(
                GURL("http://foo.com:9000"), 85, CookieSourceScheme::kSecure),
            CookieMonster::CookieSentToSamePort::kNo);

  ASSERT_EQ(CookieMonster::IsCookieSentToSamePortThatSetIt(
                GURL("https://foo.com"), 80, CookieSourceScheme::kSecure),
            CookieMonster::CookieSentToSamePort::kNo);

  ASSERT_EQ(CookieMonster::IsCookieSentToSamePortThatSetIt(
                GURL("wss://foo.com"), 80, CookieSourceScheme::kSecure),
            CookieMonster::CookieSentToSamePort::kNo);

  ASSERT_EQ(CookieMonster::IsCookieSentToSamePortThatSetIt(
                GURL("http://foo.com"), 443, CookieSourceScheme::kNonSecure),
            CookieMonster::CookieSentToSamePort::kNo);

  ASSERT_EQ(CookieMonster::IsCookieSentToSamePortThatSetIt(
                GURL("ws://foo.com"), 443, CookieSourceScheme::kNonSecure),
            CookieMonster::CookieSentToSamePort::kNo);

  ASSERT_EQ(CookieMonster::IsCookieSentToSamePortThatSetIt(
                GURL("http://foo.com:444"), 443, CookieSourceScheme::kSecure),
            CookieMonster::CookieSentToSamePort::kNo);
}

TEST_F(CookieMonsterTest, CookieDomainSetHistogram) {
  base::HistogramTester histog
"""


```