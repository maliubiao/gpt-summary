Response:
The user wants me to analyze a part of the `canonical_cookie_unittest.cc` file in Chromium. Specifically, this is part 2 of 9. I need to summarize the functionality of this code snippet.

Looking at the code, it appears to be a series of unit tests for the `CanonicalCookie` class. These tests focus on the `Create` and related methods, specifically testing various scenarios involving:

- **Secure attribute:** Checking if a cookie created with the `Secure` flag is indeed secure.
- **Partitioned attribute:** Verifying the correct handling of the `Partitioned` attribute.
- **Max-Age attribute:**  Testing different values for `max-age` (positive, zero, negative, whitespace, non-integer, overflow, underflow) and ensuring the expiry date is calculated correctly. It also checks that `max-age` takes precedence over `expires`.
- **Expires attribute:**  Testing various `expires` values (past, future, far future) and how they affect the cookie's expiry date and persistence. It also tests the behavior with `CreateUnsafeCookieForTesting` and `FromStorage` regarding the `expires` attribute.
- **Empty Expires attribute:** Testing how the code handles an empty `Expires` attribute.
- **Last Update attribute:**  Verifying how the `LastUpdateDate` is set when creating cookies through different methods (`CreateForTesting`, `CreateSanitizedCookie`, `CreateUnsafeCookieForTesting`, `FromStorage`).
- **IsEquivalent method:** Testing various scenarios to determine if two cookies are considered equivalent, focusing on differences in name, domain, path, secure/httponly attributes, same-site policy, priority, and partition key. It also tests `IsEquivalentForSecureCookieMatching`, which has slightly different equivalence rules.
- **IsEquivalentForSecureCookieMatching method:** Explicitly testing different combinations of cookie attributes to confirm the behavior of `IsEquivalentForSecureCookieMatching`.
- **IsEquivalentForOriginBoundCookies method:**  Testing the effect of scheme and port binding on cookie equivalence.

Based on this analysis, I can summarize the functionality of this code snippet.
这是 `net/cookies/canonical_cookie_unittest.cc` 文件的第 2 部分，主要功能是测试 `CanonicalCookie` 类的创建和属性判断方法，特别是关于 cookie 的有效期、更新时间以及等价性判断。

以下是更详细的功能分解和相关说明：

**功能归纳:**

这部分代码主要测试了 `CanonicalCookie` 类的以下功能：

1. **使用 `Secure` 属性创建 Cookie:**
    *   测试创建带有 `Secure` 属性的 Cookie，并验证其 `SecureAttribute()` 方法返回 `true`。
    *   测试创建带有 `Partitioned` 属性的 Cookie，并验证其 `IsPartitioned()` 方法返回 `true`，且 `PartitionKey()` 返回正确的值。

2. **使用 `Max-Age` 属性创建 Cookie:**
    *   测试使用正整数、0、负数等不同值的 `max-age` 属性创建 Cookie，验证其是否持久化 (`IsPersistent()`)，是否过期 (`IsExpired()`)，以及计算出的过期时间 (`ExpiryDate()`) 是否正确。
    *   测试 `max-age` 属性的优先级高于 `expires` 属性。
    *   测试 `max-age` 属性中的空格会被忽略。
    *   测试当 `max-age` 值为非整数时，该属性会被忽略，Cookie 不会持久化。
    *   测试 `max-age` 溢出和下溢的情况，验证过期时间会被裁剪到最大或最小值。

3. **使用 `Expires` 属性创建 Cookie:**
    *   测试使用过去、未来和遥远未来的时间作为 `expires` 属性值创建 Cookie，验证其是否持久化，是否过期，以及计算出的过期时间是否正确。
    *   测试使用 `CreateUnsafeCookieForTesting` 和 `FromStorage` 方法创建具有遥远未来过期时间的 Cookie。

4. **处理空的 `Expires` 属性:**
    *   测试当 Cookie 字符串中 `Expires` 属性为空时，创建的 Cookie 不会持久化，也不会过期。

5. **创建并设置 `LastUpdateDate` 属性:**
    *   测试使用 `CreateForTesting` 创建 Cookie 时，`LastUpdateDate` 会被设置为当前时间。
    *   测试使用 `CreateSanitizedCookie` 创建 Cookie 时，`LastUpdateDate` 也会被设置为当前时间。
    *   测试使用 `CreateUnsafeCookieForTesting` 和 `FromStorage` 创建 Cookie 时，可以显式设置 `LastUpdateDate`。

6. **判断 Cookie 的等价性 (`IsEquivalent`)：**
    *   测试一个 Cookie 与自身是等价的。
    *   测试两个完全相同的 Cookie 是等价的。
    *   测试仅属性值不同的 Cookie (例如 value, creation\_time, secure, httponly, samesite, priority) 在某些情况下仍然被认为是等价的。
    *   测试 Cookie 的名称 (`name`) 不同则不相等价。
    *   测试域名 Cookie 和主机名 Cookie 在严格等价性判断中不相等价，但在安全 Cookie 匹配中可能等价。
    *   测试路径 (`path`) 不同则不相等价，但安全 Cookie 匹配有不同的路径比较规则。
    *   测试带分区键的 Cookie 和不带分区键的 Cookie 不相等价。
    *   测试带有相同分区键的 Cookie 是等价的。
    *   测试带有不同分区键的 Cookie 不相等价。

7. **判断 Cookie 的安全 Cookie 匹配等价性 (`IsEquivalentForSecureCookieMatching`)：**
    *   定义了一系列测试用例，详细比较了不同 Cookie 的名称、域名、路径和分区键，以验证 `IsEquivalentForSecureCookieMatching` 方法的正确性。

8. **判断源绑定 Cookie 的等价性 (`IsEquivalentForOriginBoundCookies`)：**
    *   测试了在启用或禁用 Scheme 和 Port 绑定特性时，Cookie 的等价性判断。
    *   验证了主机名 Cookie 和域名 Cookie 永远不相等价。
    *   测试了当 Scheme 绑定启用时，不同 Scheme 的 Cookie 不相等价。
    *   测试了当 Port 绑定启用时，主机名 Cookie 的不同端口不相等价，但域名 Cookie 的不同端口可能相等价。
    *   测试了当 Scheme 和 Port 绑定都启用时的等价性判断规则。

**与 Javascript 的关系：**

这段 C++ 代码是 Chromium 浏览器网络栈的一部分，负责处理底层的 Cookie 逻辑。虽然这段代码本身不是 Javascript，但它直接影响了 Javascript 中通过 `document.cookie` API 读写 Cookie 的行为。

**举例说明：**

*   **Javascript 设置 Secure Cookie:** 当 Javascript 代码尝试设置一个带有 `secure` 标志的 Cookie 时，浏览器底层会调用类似于 `CanonicalCookie::Create` 的函数来创建对应的 Cookie 对象，并根据 `SecureAttribute()` 的结果来决定是否在非 HTTPS 连接中发送此 Cookie。
    ```javascript
    // 在 HTTPS 页面中设置 secure cookie
    document.cookie = "mySecureCookie=value; secure";
    ```
    这段 Javascript 代码最终会触发 C++ 代码中对 `Secure` 属性的处理逻辑。

*   **Javascript 设置 Max-Age 或 Expires Cookie:** 当 Javascript 代码设置带有 `max-age` 或 `expires` 属性的 Cookie 时，浏览器会解析这些属性，并将其传递给底层的 C++ 代码来计算 Cookie 的过期时间。
    ```javascript
    // 设置一个 60 秒后过期的 cookie
    document.cookie = "myCookie=value; max-age=60";

    // 设置一个特定时间过期的 cookie
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 7); // 7 天后过期
    document.cookie = "anotherCookie=value; expires=" + expiryDate.toUTCString();
    ```
    这些 Javascript 代码会触发 C++ 代码中 `CreateWithMaxAge` 和 `CreateWithExpires` 测试中涉及的逻辑。

**逻辑推理、假设输入与输出：**

**例子 1: `CreateWithMaxAge` 测试**

*   **假设输入:** `url = "http://www.example.com/test/foo.html"`, `cookie_line = "A=1; max-age=60"`, `creation_time = 某个时间点`
*   **逻辑推理:** `CanonicalCookie::CreateForTesting` 函数会解析 `max-age=60`，计算出过期时间为 `creation_time + 60秒`，并将 `IsPersistent()` 设置为 `true`。
*   **预期输出:** `cookie->IsPersistent()` 返回 `true`，`cookie->IsExpired(creation_time)` 返回 `false`，`cookie->ExpiryDate()` 等于 `creation_time + 60秒`。

**例子 2: `IsEquivalent` 测试**

*   **假设输入:** `cookie1` 的属性为 `name="A", domain=".www.example.com", path="/path"`, `cookie2` 的属性为 `name="A", domain="www.example.com", path="/path"`
*   **逻辑推理:**  `IsEquivalent` 方法会比较两个 Cookie 的名称、域名和路径。由于 `cookie1` 是域名 Cookie，`cookie2` 是主机名 Cookie，尽管域名相同，但严格等价性判断会认为它们不相等。
*   **预期输出:** `cookie1->IsEquivalent(*cookie2)` 返回 `false`。

**用户或编程常见的使用错误：**

1. **在非 HTTPS 连接中设置 Secure Cookie:**  用户可能会在非 HTTPS 页面中尝试设置带有 `secure` 标志的 Cookie。尽管 Javascript API 允许这样做，但浏览器会阻止此类 Cookie 被发送到服务器，这可能会导致用户期望的功能无法正常工作。这段 C++ 代码中的 `Create` 相关测试保证了底层能正确识别 `Secure` 属性。

2. **`Expires` 或 `Max-Age` 格式错误:**  用户可能会在设置 Cookie 时使用错误的 `expires` 日期格式或非法的 `max-age` 值。这段 C++ 代码测试了各种边界情况和错误格式，确保了 Cookie 解析的健壮性。例如，非整数的 `max-age` 会被忽略。

3. **误解域名和主机名 Cookie 的区别:** 开发者可能不清楚域名 Cookie (`.example.com`) 和主机名 Cookie (`example.com`) 的区别，导致设置的 Cookie 作用域超出预期或无法覆盖所有子域名。`IsEquivalent` 的测试用例明确了这两种 Cookie 在严格等价性判断中是不同的。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器地址栏输入 URL 或点击链接，发起 HTTP(S) 请求。**
2. **服务器在 HTTP 响应头中设置 `Set-Cookie`。** 例如：`Set-Cookie: mycookie=value; Path=/; Secure; Max-Age=3600`
3. **浏览器接收到响应头，网络栈开始解析 `Set-Cookie` 头部。**
4. **`net/cookies` 目录下的代码（包括 `canonical_cookie.cc` 和相关的解析逻辑）会被调用，根据 `Set-Cookie` 的内容创建 `CanonicalCookie` 对象。**  这里的测试用例模拟了各种 `Set-Cookie` 的情况。
5. **如果涉及到 Javascript 操作 Cookie，例如使用 `document.cookie` 设置 Cookie，浏览器底层仍然会调用 `net/cookies` 目录下的相关代码来处理。**
6. **在后续的请求中，当浏览器需要发送 Cookie 时，会根据 Cookie 的属性（如 domain, path, secure, partitioned）以及当前的请求上下文，判断哪些 Cookie 需要被包含在请求头中。**  `IsEquivalent` 和 `IsEquivalentForSecureCookieMatching` 等测试用例影响着这个判断过程。

总而言之，这部分单元测试确保了 `CanonicalCookie` 类能够正确地创建、解析和管理 Cookie 的各种属性，这是浏览器处理 Cookie 的核心逻辑，直接影响着 Web 应用的功能和安全性。

Prompt: 
```
这是目录为net/cookies/canonical_cookie_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共9部分，请归纳一下它的功能

"""
r.html");
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  auto partition_key =
      CookiePartitionKey::FromURLForTesting(GURL("http://localhost:8000"));
  CookieInclusionStatus status;

  std::unique_ptr<CanonicalCookie> cookie = CanonicalCookie::Create(
      url, "foo=bar; Path=/; Secure; Partitioned", creation_time, server_time,
      partition_key, CookieSourceType::kUnknown, &status);
  ASSERT_TRUE(cookie.get());
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(cookie->SecureAttribute());
  EXPECT_TRUE(cookie->IsPartitioned());
  EXPECT_EQ(partition_key, cookie->PartitionKey());
  EXPECT_EQ(CookieSameSite::UNSPECIFIED, cookie->SameSite());
}

TEST(CanonicalCookieTest, CreateWithMaxAge) {
  GURL url("http://www.example.com/test/foo.html");
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;

  // Max-age with positive integer.
  std::unique_ptr<CanonicalCookie> cookie = CanonicalCookie::CreateForTesting(
      url, "A=1; max-age=60", creation_time, server_time);
  EXPECT_TRUE(cookie.get());
  EXPECT_TRUE(cookie->IsPersistent());
  EXPECT_FALSE(cookie->IsExpired(creation_time));
  EXPECT_EQ(base::Seconds(60) + creation_time, cookie->ExpiryDate());
  EXPECT_TRUE(cookie->IsCanonical());

  // Max-age with expires (max-age should take precedence).
  cookie = CanonicalCookie::CreateForTesting(
      url, "A=1; expires=01-Jan-1970, 00:00:00 GMT; max-age=60", creation_time,
      server_time);
  EXPECT_TRUE(cookie.get());
  EXPECT_TRUE(cookie->IsPersistent());
  EXPECT_FALSE(cookie->IsExpired(creation_time));
  EXPECT_EQ(base::Seconds(60) + creation_time, cookie->ExpiryDate());
  EXPECT_TRUE(cookie->IsCanonical());

  // Max-age=0 should create an expired cookie with expiry equal to the earliest
  // representable time.
  cookie = CanonicalCookie::CreateForTesting(url, "A=1; max-age=0",
                                             creation_time, server_time);
  EXPECT_TRUE(cookie.get());
  EXPECT_TRUE(cookie->IsPersistent());
  EXPECT_TRUE(cookie->IsExpired(creation_time));
  EXPECT_EQ(base::Time::Min(), cookie->ExpiryDate());
  EXPECT_TRUE(cookie->IsCanonical());

  // Negative max-age should create an expired cookie with expiry equal to the
  // earliest representable time.
  cookie = CanonicalCookie::CreateForTesting(url, "A=1; max-age=-1",
                                             creation_time, server_time);
  EXPECT_TRUE(cookie.get());
  EXPECT_TRUE(cookie->IsPersistent());
  EXPECT_TRUE(cookie->IsExpired(creation_time));
  EXPECT_EQ(base::Time::Min(), cookie->ExpiryDate());
  EXPECT_TRUE(cookie->IsCanonical());

  // Max-age with whitespace (should be trimmed out).
  cookie = CanonicalCookie::CreateForTesting(url, "A=1; max-age = 60  ; Secure",
                                             creation_time, server_time);
  EXPECT_TRUE(cookie.get());
  EXPECT_TRUE(cookie->IsPersistent());
  EXPECT_FALSE(cookie->IsExpired(creation_time));
  EXPECT_EQ(base::Seconds(60) + creation_time, cookie->ExpiryDate());
  EXPECT_TRUE(cookie->IsCanonical());

  // Max-age with non-integer should be ignored.
  cookie = CanonicalCookie::CreateForTesting(url, "A=1; max-age=abcd",
                                             creation_time, server_time);
  EXPECT_TRUE(cookie.get());
  EXPECT_FALSE(cookie->IsPersistent());
  EXPECT_FALSE(cookie->IsExpired(creation_time));
  EXPECT_TRUE(cookie->IsCanonical());

  // Overflow max-age should be clipped.
  cookie = CanonicalCookie::CreateForTesting(
      url,
      "A=1; "
      "max-age="
      "9999999999999999999999999999999999999999999"
      "999999999999999999999999999999999999999999",
      creation_time, server_time);
  EXPECT_TRUE(cookie.get());
  EXPECT_TRUE(cookie->IsPersistent());
  EXPECT_FALSE(cookie->IsExpired(creation_time));
  EXPECT_EQ(creation_time + base::Days(400), cookie->ExpiryDate());
  EXPECT_TRUE(cookie->IsCanonical());

  // Underflow max-age should be clipped.
  cookie = CanonicalCookie::CreateForTesting(
      url,
      "A=1; "
      "max-age=-"
      "9999999999999999999999999999999999999999999"
      "999999999999999999999999999999999999999999",
      creation_time, server_time);
  EXPECT_TRUE(cookie.get());
  EXPECT_TRUE(cookie->IsPersistent());
  EXPECT_TRUE(cookie->IsExpired(creation_time));
  EXPECT_EQ(base::Time::Min(), cookie->ExpiryDate());
  EXPECT_TRUE(cookie->IsCanonical());
}

TEST(CanonicalCookieTest, CreateWithExpires) {
  GURL url("http://www.example.com/test/foo.html");
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;

  // Expires in the past
  base::Time past_date = base::Time::Now() - base::Days(10);
  std::unique_ptr<CanonicalCookie> cookie = CanonicalCookie::CreateForTesting(
      url, "A=1; expires=" + HttpUtil::TimeFormatHTTP(past_date), creation_time,
      server_time);
  EXPECT_TRUE(cookie.get());
  EXPECT_TRUE(cookie->IsPersistent());
  EXPECT_TRUE(cookie->IsExpired(creation_time));
  EXPECT_TRUE((past_date - cookie->ExpiryDate()).magnitude() <
              base::Seconds(1));
  EXPECT_TRUE(cookie->IsCanonical());

  // Expires in the future
  base::Time future_date = base::Time::Now() + base::Days(10);
  cookie = CanonicalCookie::CreateForTesting(
      url, "A=1; expires=" + HttpUtil::TimeFormatHTTP(future_date),
      creation_time, server_time);
  EXPECT_TRUE(cookie.get());
  EXPECT_TRUE(cookie->IsPersistent());
  EXPECT_FALSE(cookie->IsExpired(creation_time));
  EXPECT_TRUE((future_date - cookie->ExpiryDate()).magnitude() <
              base::Seconds(1));
  EXPECT_TRUE(cookie->IsCanonical());

  // Expires in the far future
  future_date = base::Time::Now() + base::Days(800);
  cookie = CanonicalCookie::CreateForTesting(
      url, "A=1; expires=" + HttpUtil::TimeFormatHTTP(future_date),
      creation_time, server_time);
  EXPECT_TRUE(cookie.get());
  EXPECT_TRUE(cookie->IsPersistent());
  EXPECT_FALSE(cookie->IsExpired(creation_time));
  EXPECT_TRUE(
      (cookie->ExpiryDate() - creation_time - base::Days(400)).magnitude() <
      base::Seconds(1));
  EXPECT_TRUE(cookie->IsCanonical());

  // Expires in the far future using CreateUnsafeCookieForTesting.
  cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "1", url.host(), url.path(), creation_time, base::Time::Max(),
      base::Time(), base::Time(), true, false, CookieSameSite::UNSPECIFIED,
      COOKIE_PRIORITY_HIGH, std::nullopt /* cookie_partition_key */,
      CookieSourceScheme::kSecure, 443);
  EXPECT_TRUE(cookie.get());
  EXPECT_TRUE(cookie->IsPersistent());
  EXPECT_FALSE(cookie->IsExpired(creation_time));
  EXPECT_EQ(base::Time::Max(), cookie->ExpiryDate());
  EXPECT_EQ(base::Time(), cookie->LastUpdateDate());
  EXPECT_FALSE(cookie->IsCanonical());

  // Expires in the far future using FromStorage.
  cookie = CanonicalCookie::FromStorage(
      "A", "B", "www.foo.com", "/bar", creation_time, base::Time::Max(),
      base::Time(), base::Time(), false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, CookieSourceScheme::kSecure, 443,
      CookieSourceType::kUnknown);
  EXPECT_TRUE(cookie.get());
  EXPECT_TRUE(cookie->IsPersistent());
  EXPECT_FALSE(cookie->IsExpired(creation_time));
  EXPECT_EQ(base::Time::Max(), cookie->ExpiryDate());
  EXPECT_EQ(base::Time(), cookie->LastUpdateDate());
  EXPECT_FALSE(cookie->IsCanonical());
}

TEST(CanonicalCookieTest, EmptyExpiry) {
  GURL url("http://www7.ipdl.inpit.go.jp/Tokujitu/tjkta.ipdl?N0000=108");
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;

  std::string cookie_line =
      "ACSTM=20130308043820420042; path=/; domain=ipdl.inpit.go.jp; Expires=";
  std::unique_ptr<CanonicalCookie> cookie(CanonicalCookie::CreateForTesting(
      url, cookie_line, creation_time, server_time));
  EXPECT_TRUE(cookie.get());
  EXPECT_FALSE(cookie->IsPersistent());
  EXPECT_FALSE(cookie->IsExpired(creation_time));
  EXPECT_EQ(base::Time(), cookie->ExpiryDate());

  // With a stale server time
  server_time = creation_time - base::Hours(1);
  cookie = CanonicalCookie::CreateForTesting(url, cookie_line, creation_time,
                                             server_time);
  EXPECT_TRUE(cookie.get());
  EXPECT_FALSE(cookie->IsPersistent());
  EXPECT_FALSE(cookie->IsExpired(creation_time));
  EXPECT_EQ(base::Time(), cookie->ExpiryDate());

  // With a future server time
  server_time = creation_time + base::Hours(1);
  cookie = CanonicalCookie::CreateForTesting(url, cookie_line, creation_time,
                                             server_time);
  EXPECT_TRUE(cookie.get());
  EXPECT_FALSE(cookie->IsPersistent());
  EXPECT_FALSE(cookie->IsExpired(creation_time));
  EXPECT_EQ(base::Time(), cookie->ExpiryDate());
}

TEST(CanonicalCookieTest, CreateWithLastUpdate) {
  GURL url("http://www.example.com/test/foo.html");
  base::Time creation_time = base::Time::Now() - base::Days(1);
  base::Time last_update_time = base::Time::Now() - base::Hours(1);
  std::optional<base::Time> server_time = std::nullopt;

  // Creating a cookie sets the last update date as now.
  std::unique_ptr<CanonicalCookie> cookie =
      CanonicalCookie::CreateForTesting(url, "A=1", creation_time, server_time,
                                        /*cookie_partition_key=*/std::nullopt);
  ASSERT_TRUE(cookie.get());
  EXPECT_TRUE((base::Time::Now() - cookie->LastUpdateDate()).magnitude() <
              base::Seconds(1));

  // Creating a sanitized cookie sets the last update date as now.
  cookie = CanonicalCookie::CreateSanitizedCookie(
      url, "A", "1", url.host(), url.path(), creation_time, base::Time(),
      creation_time, /*secure=*/true,
      /*http_only=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT,
      /*partition_key=*/std::nullopt, /*status=*/nullptr);
  ASSERT_TRUE(cookie.get());
  EXPECT_TRUE((base::Time::Now() - cookie->LastUpdateDate()).magnitude() <
              base::Seconds(1));

  // Creating an unsafe cookie allows us to set the last update date.
  cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "1", url.host(), url.path(), creation_time, base::Time(),
      base::Time(), last_update_time, /*secure=*/true,
      /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT,
      /*partition_key=*/std::nullopt, CookieSourceScheme::kSecure,
      /*source_port=*/443);
  ASSERT_TRUE(cookie.get());
  EXPECT_EQ(last_update_time, cookie->LastUpdateDate());

  // Loading a cookie from storage allows us to set the last update date.
  cookie = CanonicalCookie::FromStorage(
      "A", "1", url.host(), url.path(), creation_time, base::Time(),
      base::Time(), last_update_time, /*secure=*/true,
      /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT,
      /*partition_key=*/std::nullopt, CookieSourceScheme::kSecure,
      /*source_port=*/443, CookieSourceType::kUnknown);
  ASSERT_TRUE(cookie.get());
  EXPECT_EQ(last_update_time, cookie->LastUpdateDate());
}

TEST(CanonicalCookieTest, IsEquivalent) {
  GURL url("https://www.example.com/");
  std::string cookie_name = "A";
  std::string cookie_value = "2EDA-EF";
  std::string cookie_domain = ".www.example.com";
  std::string cookie_path = "/path";
  base::Time creation_time = base::Time::Now();
  base::Time expiration_time = creation_time + base::Days(2);
  base::Time update_time = creation_time + base::Days(1);
  bool secure = false;
  bool httponly = false;
  CookieSameSite same_site = CookieSameSite::NO_RESTRICTION;

  // Test that a cookie is equivalent to itself.
  auto cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      cookie_name, cookie_value, cookie_domain, cookie_path, creation_time,
      expiration_time, base::Time(), update_time, secure, httponly, same_site,
      COOKIE_PRIORITY_MEDIUM);
  EXPECT_TRUE(cookie->IsEquivalent(*cookie));
  EXPECT_TRUE(cookie->IsEquivalentForSecureCookieMatching(*cookie));

  // Test that two identical cookies are equivalent.
  auto other_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      cookie_name, cookie_value, cookie_domain, cookie_path, creation_time,
      expiration_time, base::Time(), update_time, secure, httponly, same_site,
      COOKIE_PRIORITY_MEDIUM);
  EXPECT_TRUE(cookie->IsEquivalent(*other_cookie));
  EXPECT_TRUE(other_cookie->IsEquivalentForSecureCookieMatching(*cookie));

  // Tests that use different variations of attribute values that
  // DON'T affect cookie equivalence.
  other_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      cookie_name, "2", cookie_domain, cookie_path, creation_time,
      expiration_time, base::Time(), update_time, secure, httponly, same_site,
      COOKIE_PRIORITY_HIGH);
  EXPECT_TRUE(cookie->IsEquivalent(*other_cookie));
  EXPECT_TRUE(cookie->IsEquivalentForSecureCookieMatching(*other_cookie));
  EXPECT_TRUE(other_cookie->IsEquivalentForSecureCookieMatching(*cookie));

  base::Time other_creation_time = creation_time + base::Minutes(2);
  other_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      cookie_name, "2", cookie_domain, cookie_path, other_creation_time,
      expiration_time, base::Time(), update_time, secure, httponly, same_site,
      COOKIE_PRIORITY_MEDIUM);
  EXPECT_TRUE(cookie->IsEquivalent(*other_cookie));
  EXPECT_TRUE(cookie->IsEquivalentForSecureCookieMatching(*other_cookie));
  EXPECT_TRUE(other_cookie->IsEquivalentForSecureCookieMatching(*cookie));

  other_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      cookie_name, cookie_name, cookie_domain, cookie_path, creation_time,
      expiration_time, base::Time(), update_time, true, httponly, same_site,
      COOKIE_PRIORITY_LOW);
  EXPECT_TRUE(cookie->IsEquivalent(*other_cookie));
  EXPECT_TRUE(cookie->IsEquivalentForSecureCookieMatching(*other_cookie));
  EXPECT_TRUE(other_cookie->IsEquivalentForSecureCookieMatching(*cookie));

  other_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      cookie_name, cookie_name, cookie_domain, cookie_path, creation_time,
      expiration_time, base::Time(), update_time, secure, true, same_site,
      COOKIE_PRIORITY_LOW);
  EXPECT_TRUE(cookie->IsEquivalent(*other_cookie));
  EXPECT_TRUE(cookie->IsEquivalentForSecureCookieMatching(*other_cookie));
  EXPECT_TRUE(other_cookie->IsEquivalentForSecureCookieMatching(*cookie));

  other_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      cookie_name, cookie_name, cookie_domain, cookie_path, creation_time,
      expiration_time, base::Time(), update_time, secure, httponly,
      CookieSameSite::STRICT_MODE, COOKIE_PRIORITY_LOW);
  EXPECT_TRUE(cookie->IsEquivalent(*other_cookie));
  EXPECT_TRUE(cookie->IsEquivalentForSecureCookieMatching(*other_cookie));
  EXPECT_TRUE(other_cookie->IsEquivalentForSecureCookieMatching(*cookie));

  // Test the effect of a differing last_update_time on equivalency.
  other_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      cookie_name, cookie_name, cookie_domain, cookie_path, creation_time,
      expiration_time, base::Time(), base::Time(), secure, httponly, same_site,
      COOKIE_PRIORITY_LOW);
  EXPECT_TRUE(cookie->IsEquivalent(*other_cookie));
  EXPECT_TRUE(cookie->IsEquivalentForSecureCookieMatching(*other_cookie));
  EXPECT_TRUE(other_cookie->IsEquivalentForSecureCookieMatching(*cookie));
  EXPECT_FALSE(cookie->HasEquivalentDataMembers(*other_cookie));

  // Cookies whose names mismatch are not equivalent.
  other_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      "B", cookie_value, cookie_domain, cookie_path, creation_time,
      expiration_time, base::Time(), update_time, secure, httponly, same_site,
      COOKIE_PRIORITY_MEDIUM);
  EXPECT_FALSE(cookie->IsEquivalent(*other_cookie));
  EXPECT_FALSE(cookie->IsEquivalentForSecureCookieMatching(*other_cookie));
  EXPECT_FALSE(other_cookie->IsEquivalentForSecureCookieMatching(*cookie));

  // A domain cookie at 'www.example.com' is not equivalent to a host cookie
  // at the same domain. These are, however, equivalent according to the laxer
  // rules of 'IsEquivalentForSecureCookieMatching'.
  other_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      cookie_name, cookie_value, "www.example.com", cookie_path, creation_time,
      expiration_time, base::Time(), update_time, secure, httponly, same_site,
      COOKIE_PRIORITY_MEDIUM);
  EXPECT_TRUE(cookie->IsDomainCookie());
  EXPECT_FALSE(other_cookie->IsDomainCookie());
  EXPECT_FALSE(cookie->IsEquivalent(*other_cookie));
  EXPECT_TRUE(cookie->IsEquivalentForSecureCookieMatching(*other_cookie));
  EXPECT_TRUE(other_cookie->IsEquivalentForSecureCookieMatching(*cookie));

  // Likewise, a cookie on 'example.com' is not equivalent to a cookie on
  // 'www.example.com', but they are equivalent for secure cookie matching.
  other_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      cookie_name, cookie_value, ".example.com", cookie_path, creation_time,
      expiration_time, base::Time(), update_time, secure, httponly, same_site,
      COOKIE_PRIORITY_MEDIUM);
  EXPECT_FALSE(cookie->IsEquivalent(*other_cookie));
  EXPECT_TRUE(cookie->IsEquivalentForSecureCookieMatching(*other_cookie));
  EXPECT_TRUE(other_cookie->IsEquivalentForSecureCookieMatching(*cookie));

  // Paths are a bit more complicated. 'IsEquivalent' requires an exact path
  // match, while secure cookie matching uses a more relaxed 'IsOnPath' check.
  // That is, |cookie| set on '/path' is not equivalent in either way to
  // |other_cookie| set on '/test' or '/path/subpath'. It is, however,
  // equivalent for secure cookie matching to |other_cookie| set on '/'.
  other_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      cookie_name, cookie_value, cookie_domain, "/test", creation_time,
      expiration_time, base::Time(), update_time, secure, httponly, same_site,
      COOKIE_PRIORITY_MEDIUM);
  EXPECT_FALSE(cookie->IsEquivalent(*other_cookie));
  EXPECT_FALSE(cookie->IsEquivalentForSecureCookieMatching(*other_cookie));
  EXPECT_FALSE(other_cookie->IsEquivalentForSecureCookieMatching(*cookie));

  other_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      cookie_name, cookie_value, cookie_domain, cookie_path + "/subpath",
      creation_time, expiration_time, base::Time(), update_time, secure,
      httponly, same_site, COOKIE_PRIORITY_MEDIUM);
  EXPECT_FALSE(cookie->IsEquivalent(*other_cookie));
  // The path comparison is asymmetric
  EXPECT_FALSE(cookie->IsEquivalentForSecureCookieMatching(*other_cookie));
  EXPECT_TRUE(other_cookie->IsEquivalentForSecureCookieMatching(*cookie));

  other_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      cookie_name, cookie_value, cookie_domain, "/", creation_time,
      expiration_time, base::Time(), update_time, secure, httponly, same_site,
      COOKIE_PRIORITY_MEDIUM);
  EXPECT_FALSE(cookie->IsEquivalent(*other_cookie));
  EXPECT_TRUE(cookie->IsEquivalentForSecureCookieMatching(*other_cookie));
  EXPECT_FALSE(other_cookie->IsEquivalentForSecureCookieMatching(*cookie));

  // Partitioned cookies are not equivalent to unpartitioned cookies.
  other_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      cookie_name, cookie_value, cookie_domain, cookie_path, creation_time,
      expiration_time, base::Time(), update_time, secure, httponly, same_site,
      COOKIE_PRIORITY_MEDIUM,
      CookiePartitionKey::FromURLForTesting(GURL("https://foo.com")));
  EXPECT_FALSE(cookie->IsEquivalent(*other_cookie));
  EXPECT_FALSE(cookie->IsEquivalentForSecureCookieMatching(*other_cookie));

  // Partitioned cookies are equal if they have the same partition key.
  auto paritioned_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      cookie_name, cookie_value, cookie_domain, cookie_path, creation_time,
      expiration_time, base::Time(), update_time, secure, httponly, same_site,
      COOKIE_PRIORITY_MEDIUM,
      CookiePartitionKey::FromURLForTesting(GURL("https://foo.com")));
  EXPECT_TRUE(paritioned_cookie->IsEquivalent(*other_cookie));
  EXPECT_TRUE(
      paritioned_cookie->IsEquivalentForSecureCookieMatching(*other_cookie));

  // Partitioned cookies with different partition keys are not equal
  other_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      cookie_name, cookie_value, cookie_domain, cookie_path, creation_time,
      expiration_time, base::Time(), update_time, secure, httponly, same_site,
      COOKIE_PRIORITY_MEDIUM,
      CookiePartitionKey::FromURLForTesting(GURL("https://bar.com")));
  EXPECT_FALSE(paritioned_cookie->IsEquivalent(*other_cookie));
  EXPECT_FALSE(
      paritioned_cookie->IsEquivalentForSecureCookieMatching(*other_cookie));
}

TEST(CanonicalCookieTest, IsEquivalentForSecureCookieMatching) {
  struct {
    struct {
      const char* name;
      const char* domain;
      const char* path;
      std::optional<CookiePartitionKey> cookie_partition_key = std::nullopt;
    } cookie, secure_cookie;
    bool equivalent;
    bool is_symmetric;  // Whether the reverse comparison has the same result.
  } kTests[] = {
      // Equivalent to itself
      {{"A", "a.foo.com", "/"}, {"A", "a.foo.com", "/"}, true, true},
      {{"A", ".a.foo.com", "/"}, {"A", ".a.foo.com", "/"}, true, true},
      // Names are different
      {{"A", "a.foo.com", "/"}, {"B", "a.foo.com", "/"}, false, true},
      // Host cookie and domain cookie with same hostname match
      {{"A", "a.foo.com", "/"}, {"A", ".a.foo.com", "/"}, true, true},
      // Subdomains and superdomains match
      {{"A", "a.foo.com", "/"}, {"A", ".foo.com", "/"}, true, true},
      {{"A", ".a.foo.com", "/"}, {"A", ".foo.com", "/"}, true, true},
      {{"A", "a.foo.com", "/"}, {"A", "foo.com", "/"}, true, true},
      {{"A", ".a.foo.com", "/"}, {"A", "foo.com", "/"}, true, true},
      // Different domains don't match
      {{"A", "a.foo.com", "/"}, {"A", "b.foo.com", "/"}, false, true},
      {{"A", "a.foo.com", "/"}, {"A", "ba.foo.com", "/"}, false, true},
      // Path attribute matches if it is a subdomain, but not vice versa.
      {{"A", "a.foo.com", "/sub"}, {"A", "a.foo.com", "/"}, true, false},
      // Different paths don't match
      {{"A", "a.foo.com", "/sub"}, {"A", "a.foo.com", "/other"}, false, true},
      {{"A", "a.foo.com", "/a/b"}, {"A", "a.foo.com", "/a/c"}, false, true},
      // Partitioned cookies are not equivalent to unpartitioned cookies.
      {{"A", ".a.foo.com", "/"},
       {"A", ".a.foo.com", "/",
        CookiePartitionKey::FromURLForTesting(GURL("https://bar.com"))},
       false,
       true},
      // Partitioned cookies are equivalent if they have the same partition key.
      {{"A", "a.foo.com", "/",
        CookiePartitionKey::FromURLForTesting(GURL("https://bar.com"))},
       {"A", "a.foo.com", "/",
        CookiePartitionKey::FromURLForTesting(GURL("https://bar.com"))},
       true,
       true},
      // Partitioned cookies are *not* equivalent if they have the different
      // partition keys.
      {{"A", "a.foo.com", "/",
        CookiePartitionKey::FromURLForTesting(GURL("https://bar.com"))},
       {"A", "a.foo.com", "/",
        CookiePartitionKey::FromURLForTesting(GURL("https://baz.com"))},
       false,
       true},
  };

  for (auto test : kTests) {
    auto cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
        test.cookie.name, "value1", test.cookie.domain, test.cookie.path,
        base::Time(), base::Time(), base::Time(), base::Time(),
        false /* secure */, false /* httponly */, CookieSameSite::LAX_MODE,
        COOKIE_PRIORITY_MEDIUM, test.cookie.cookie_partition_key);
    auto secure_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
        test.secure_cookie.name, "value2", test.secure_cookie.domain,
        test.secure_cookie.path, base::Time(), base::Time(), base::Time(),
        base::Time(), true /* secure */, false /* httponly */,
        CookieSameSite::LAX_MODE, COOKIE_PRIORITY_MEDIUM,
        test.secure_cookie.cookie_partition_key);

    EXPECT_EQ(test.equivalent,
              cookie->IsEquivalentForSecureCookieMatching(*secure_cookie));
    EXPECT_EQ(test.equivalent == test.is_symmetric,
              secure_cookie->IsEquivalentForSecureCookieMatching(*cookie));
  }
}

TEST(CanonicalCookieTest, IsEquivalentForOriginBoundCookies) {
  auto create_cookie = [](const char* domain_field,
                          CookieSourceScheme source_scheme, int source_port) {
    const char* cookie_name = "A";
    const char* cookie_value = "2EDA-EF";
    const char* cookie_path = "/";
    const base::Time creation_time = base::Time::Now();
    const base::Time expiration_time = creation_time + base::Days(2);
    const base::Time update_time = creation_time + base::Days(1);
    const bool secure = false;
    const bool httponly = false;
    const CookieSameSite same_site = CookieSameSite::NO_RESTRICTION;
    const std::optional<CookiePartitionKey> partition_key = std::nullopt;

    return CanonicalCookie::CreateUnsafeCookieForTesting(
        cookie_name, cookie_value, domain_field, cookie_path, creation_time,
        expiration_time, base::Time(), update_time, secure, httponly, same_site,
        COOKIE_PRIORITY_MEDIUM, partition_key, source_scheme, source_port);
  };

  const char* domain = ".www.example.com";
  const char* host_only_domain = "www.example.com";
  const CookieSourceScheme http_scheme = CookieSourceScheme::kNonSecure;
  const int port_80 = 80;

  auto domain_cookie = create_cookie(domain, http_scheme, port_80);

  auto host_cookie = create_cookie(host_only_domain, http_scheme, port_80);

  // Host cookies are never equivalent to domain cookies.
  ASSERT_FALSE(domain_cookie->IsEquivalent(*host_cookie));
  ASSERT_FALSE(host_cookie->IsEquivalent(*domain_cookie));

  // With neither binding enabled, difference in scheme and port have no effect
  // on equivalency.
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitWithFeatures({}, {features::kEnableSchemeBoundCookies,
                                       features::kEnablePortBoundCookies});

    // Different schemes are equivalent.
    auto other_cookie =
        create_cookie(domain, CookieSourceScheme::kSecure, port_80);
    EXPECT_TRUE(domain_cookie->IsEquivalent(*other_cookie));

    other_cookie = create_cookie(domain, CookieSourceScheme::kUnset, port_80);
    EXPECT_TRUE(domain_cookie->IsEquivalent(*other_cookie));

    other_cookie =
        create_cookie(host_only_domain, CookieSourceScheme::kSecure, port_80);
    EXPECT_TRUE(host_cookie->IsEquivalent(*other_cookie));

    other_cookie =
        create_cookie(host_only_domain, CookieSourceScheme::kUnset, port_80);
    EXPECT_TRUE(host_cookie->IsEquivalent(*other_cookie));

    // Different ports are equivalent.
    other_cookie = create_cookie(domain, http_scheme, -1);
    EXPECT_TRUE(domain_cookie->IsEquivalent(*other_cookie));

    other_cookie = create_cookie(domain, http_scheme, 123);
    EXPECT_TRUE(domain_cookie->IsEquivalent(*other_cookie));

    other_cookie = create_cookie(host_only_domain, http_scheme, -1);
    EXPECT_TRUE(host_cookie->IsEquivalent(*other_cookie));

    other_cookie = create_cookie(host_only_domain, http_scheme, 123);
    EXPECT_TRUE(host_cookie->IsEquivalent(*other_cookie));

    // Different scheme and ports are equivalent.
    other_cookie = create_cookie(domain, CookieSourceScheme::kSecure, 123);
    EXPECT_TRUE(domain_cookie->IsEquivalent(*other_cookie));

    other_cookie =
        create_cookie(host_only_domain, CookieSourceScheme::kSecure, 123);
    EXPECT_TRUE(host_cookie->IsEquivalent(*other_cookie));
  }

  // With scheme binding enabled, differences in scheme means cookies are not
  // equivalent.
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitWithFeatures({features::kEnableSchemeBoundCookies},
                                  {features::kEnablePortBoundCookies});

    // Different schemes are not equivalent.
    auto other_cookie =
        create_cookie(domain, CookieSourceScheme::kSecure, port_80);
    EXPECT_FALSE(domain_cookie->IsEquivalent(*other_cookie));

    other_cookie = create_cookie(domain, CookieSourceScheme::kUnset, port_80);
    EXPECT_FALSE(domain_cookie->IsEquivalent(*other_cookie));

    other_cookie =
        create_cookie(host_only_domain, CookieSourceScheme::kSecure, port_80);
    EXPECT_FALSE(host_cookie->IsEquivalent(*other_cookie));

    other_cookie =
        create_cookie(host_only_domain, CookieSourceScheme::kUnset, port_80);
    EXPECT_FALSE(host_cookie->IsEquivalent(*other_cookie));

    // Different ports are equivalent.
    other_cookie = create_cookie(domain, http_scheme, -1);
    EXPECT_TRUE(domain_cookie->IsEquivalent(*other_cookie));

    other_cookie = create_cookie(domain, http_scheme, 123);
    EXPECT_TRUE(domain_cookie->IsEquivalent(*other_cookie));

    other_cookie = create_cookie(host_only_domain, http_scheme, -1);
    EXPECT_TRUE(host_cookie->IsEquivalent(*other_cookie));

    other_cookie = create_cookie(host_only_domain, http_scheme, 123);
    EXPECT_TRUE(host_cookie->IsEquivalent(*other_cookie));

    // Different scheme and ports are not equivalent.
    other_cookie = create_cookie(domain, CookieSourceScheme::kSecure, 123);
    EXPECT_FALSE(domain_cookie->IsEquivalent(*other_cookie));

    other_cookie =
        create_cookie(host_only_domain, CookieSourceScheme::kSecure, 123);
    EXPECT_FALSE(host_cookie->IsEquivalent(*other_cookie));
  }
  // With port binding enabled, domain cookies with the different ports are
  // equivalent. Host cookies are not equivalent.
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitWithFeatures({features::kEnablePortBoundCookies},
                                  {features::kEnableSchemeBoundCookies});

    // Different schemes are equivalent.
    auto other_cookie =
        create_cookie(domain, CookieSourceScheme::kSecure, port_80);
    EXPECT_TRUE(domain_cookie->IsEquivalent(*other_cookie));

    other_cookie = create_cookie(domain, CookieSourceScheme::kUnset, port_80);
    EXPECT_TRUE(domain_cookie->IsEquivalent(*other_cookie));

    other_cookie =
        create_cookie(host_only_domain, CookieSourceScheme::kSecure, port_80);
    EXPECT_TRUE(host_cookie->IsEquivalent(*other_cookie));

    other_cookie =
        create_cookie(host_only_domain, CookieSourceScheme::kUnset, port_80);
    EXPECT_TRUE(host_cookie->IsEquivalent(*other_cookie));

    // Different ports are equivalent for domain cookies.
    other_cookie = create_cookie(domain, http_scheme, -1);
    EXPECT_TRUE(domain_cookie->IsEquivalent(*other_cookie));

    other_cookie = create_cookie(domain, http_scheme, 123);
    EXPECT_TRUE(domain_cookie->IsEquivalent(*other_cookie));

    // But not so for host cookies.
    other_cookie = create_cookie(host_only_domain, http_scheme, -1);
    EXPECT_FALSE(host_cookie->IsEquivalent(*other_cookie));

    other_cookie = create_cookie(host_only_domain, http_scheme, 123);
    EXPECT_FALSE(host_cookie->IsEquivalent(*other_cookie));

    // Different scheme and ports are equivalent for domain cookies.
    other_cookie = create_cookie(domain, CookieSourceScheme::kSecure, 123);
    EXPECT_TRUE(domain_cookie->IsEquivalent(*other_cookie));

    // But not so for host cookies.
    other_cookie =
        create_cookie(host_only_domain, CookieSourceScheme::kSecure, 123);
    EXPECT_FALSE(host_cookie->IsEquivalent(*other_cookie));
  }

  // When both scheme and port binding are enabled, different schemes are always
  // not equivalent while different ports depend on whether the cookie is host
  // or domain.
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitWithFeatures({features::kEnablePortBoundCookies,
                                   features::kEnableSchemeBoundCookies},
                                  {});

    // Different schemes are not equivalent.
    auto other_cookie =
        create_cookie(domain, CookieSourceScheme::kSecure, port_80);
    EXPECT_FALSE(domain_cookie->IsEquivalent(*other_cookie));

    other_cookie = create_cookie(domain, CookieSourceScheme::kSecure, port_80);
    EXPECT_FALSE(domain_cookie->IsEquivalent(*other_cookie));

    other_cookie =
        create_cookie(host_only_domain, CookieSourceScheme::kSecure, port_80);
    EXPECT_FALSE(host_cookie->IsEquivalent(*other_cookie));

    other_cookie =
        create_cookie(host_only_domain, CookieSourceScheme::kUnset, port_80);
    EXPECT_FALSE(host_cookie->IsEquivalent(*other_cookie));

    // Different ports are equivalent for domain cookies.
    other_cookie = create_cookie(domain, http_scheme, -1);
    EXPECT_TRUE(domain_cookie->IsEquivalent(*ot
"""


```