Response:
My thought process for analyzing the provided C++ code snippet goes like this:

1. **Identify the Core Functionality:**  The code consists of a series of test cases (`TEST_F`) within a larger unit test file (`cookie_monster_unittest.cc`). The file name itself strongly suggests it's testing the `CookieMonster` class. Skimming the test names and the operations performed within them confirms this.

2. **Analyze Individual Test Cases:**  I go through each `TEST_F` individually, noting the key actions:
    * **Instantiation:**  Almost all tests start by creating a `CookieMonster` object.
    * **Cookie Setting:**  The `SetCookieWithCreationTime` and `SetCookie` functions are used extensively. I pay attention to the parameters: URL, cookie string, creation time, and importantly, `CookiePartitionKey` (indicating partitioned cookies are being tested).
    * **Cookie Deletion:**  Several functions related to deleting cookies are present: `DeleteAllCreatedInTimeRange`, `DeleteAllMatchingInfo`, `DeleteMatchingCookies`, and `DeleteAll`. I note the different criteria for deletion (time range, matching info, a predicate function).
    * **Cookie Retrieval:** Functions like `GetAllCookies`, `GetCookies`, `GetAllCookiesForURL`, and `GetExcludedCookiesForURL` are used. I observe the options being passed to these functions, particularly `CookieOptions` and `CookiePartitionKeyCollection`.
    * **Assertions:**  `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, and `EXPECT_THAT` are used to verify the expected behavior. I pay close attention to what is being asserted.
    * **Time Manipulation:**  `Time::Now()` and calculations using `base::Days` indicate that time-based cookie management is being tested.

3. **Identify Key Themes and Concepts:**  As I analyze the individual tests, patterns emerge. The key themes I identify are:
    * **Cookie Creation and Storage:** Testing how cookies are created and stored, including both regular and partitioned cookies.
    * **Cookie Deletion:**  Thoroughly testing various ways to delete cookies based on different criteria (time, content, etc.). This is a major focus.
    * **Time-Based Operations:** Testing how cookies are managed based on their creation and access times. The `kLastAccessThreshold` variable is a clue here.
    * **Partitioned Cookies:**  The code explicitly tests the behavior of partitioned cookies, noting they are treated similarly to regular cookies for some operations but have distinct storage.
    * **Cookie Attributes:**  The tests consider attributes like "Secure", "HttpOnly", "Domain", and "Path".
    * **Garbage Collection:**  The test names containing "GarbageCollection" indicate testing the automatic removal of cookies based on limits.
    * **Cookieable Schemes:** The `SetCookieableSchemes` test explores the ability to restrict cookies to certain URL schemes.
    * **Excluding Cookies:**  The `GetExcludedCookiesForURL` tests how and why cookies might be excluded from being sent.

4. **Analyze Relationships to JavaScript:** I look for connections to how cookies are used in a web browser context. I know JavaScript uses the `document.cookie` API to interact with cookies. While this C++ code doesn't directly *execute* JavaScript, it's testing the underlying cookie management logic that JavaScript relies on. I consider the implications of the tested behaviors for JavaScript: setting, getting, and deleting cookies. The partitioned cookie tests are particularly relevant to modern web development and privacy.

5. **Infer Logical Reasoning and Examples:** For tests involving deletion by time range, I can easily construct example scenarios. If a cookie was created two days ago, and I delete cookies created in the last three days, that cookie should be deleted. Similarly, I can reason about the outcomes of deleting cookies based on matching criteria.

6. **Identify Potential User/Programming Errors:** Based on the tests, I can think about common mistakes developers or users might make:
    * **Incorrect Date Ranges for Deletion:**  Deleting cookies within a range that doesn't actually include the target cookies.
    * **Misunderstanding Inclusive/Exclusive Boundaries:**  The tests explicitly check if the start and end times of deletion ranges are inclusive or exclusive.
    * **Forgetting Partition Keys:** When dealing with partitioned cookies, providing the correct partition key is essential for retrieval and deletion.
    * **Incorrect Cookie Attributes:**  Setting attributes like "Secure" or "HttpOnly" incorrectly can lead to unexpected behavior.

7. **Trace User Actions (Debugging Clues):**  I consider how a user's actions in a browser might lead to the execution of this code. Visiting websites, logging in, staying logged in, and clearing browsing data are all actions that interact with cookie management. The tests provide clues about what to examine during debugging:
    * **Time Stamps:** When were the cookies created? When were they last accessed?
    * **Cookie Attributes:** Are the "Secure", "HttpOnly", "Domain", and "Path" attributes set correctly?
    * **Partition Keys:** For partitioned cookies, what are the associated partition keys?
    * **Browser Settings:**  Are there any browser settings affecting cookie behavior (e.g., blocking third-party cookies)?

8. **Synthesize a Summary:** Finally, I combine my observations and analysis to provide a concise summary of the code's functionality. I emphasize the core purpose (testing `CookieMonster`), the major areas covered (creation, deletion, time, partitioning, garbage collection), and the relevance to web browser functionality. Since this is part 3 of 10, I acknowledge that it's focusing on a subset of the overall cookie management system.

By following these steps, I can systematically analyze the code snippet and provide a comprehensive explanation of its functionality, its relationship to JavaScript, potential errors, and debugging information.
这是chromium网络栈的源代码文件`net/cookies/cookie_monster_unittest.cc`的第3部分，主要的功能是测试`CookieMonster`类中关于**Cookie删除**和**垃圾回收**相关的逻辑。

**功能归纳:**

这部分代码主要测试了 `CookieMonster` 类的以下功能：

1. **基于创建时间的范围删除 Cookie:**  测试了 `DeleteAllCreatedInTimeRange` 方法，验证了可以根据 Cookie 的创建时间范围来删除 Cookie，并验证了时间范围的开始是包含的，结束是不包含的。同时测试了对分区 Cookie 的相同删除逻辑。
2. **基于 `CookieDeletionInfo` 删除 Cookie:** 测试了 `DeleteAllMatchingInfo` 方法，它提供了更丰富的删除条件，例如可以只指定开始时间，或者同时指定开始和结束时间。同样也测试了对分区 Cookie 的相同删除逻辑。
3. **基于匹配器删除 Cookie:** 测试了 `DeleteMatchingCookies` 方法，允许使用一个 lambda 表达式作为匹配条件来删除符合条件的 Cookie。这提供了非常灵活的删除方式，可以基于 Cookie 的任何属性进行删除，例如是否是 Secure Cookie，或者属于特定的 Domain。同时也测试了对分区 Cookie 的删除。
4. **Cookie 的最后访问时间记录和更新:** 测试了 `CookieMonster` 如何记录和更新 Cookie 的最后访问时间 (`TestLastAccess`)，并验证了在短时间内重复访问 Cookie 不会更新访问时间，以及可以通过 `CookieOptions` 来控制是否更新访问时间。
5. **基于优先级进行垃圾回收:** 通过不同的 `TEST_P` 宏定义（例如 `CookieMonsterTestPriorityGarbageCollectionObc`），测试了 CookieMonster 的垃圾回收机制，特别是如何根据 Cookie 的优先级（Priority），以及是否是 Secure Cookie 来进行回收。
6. **垃圾回收时域名 Cookie 优先于主机 Cookie 删除:** 测试了在进行垃圾回收时，对于相同优先级和安全性的 Cookie，域名 Cookie 会优先于主机 Cookie 被删除。
7. **垃圾回收时非 Secure Cookie 优先于 Secure Cookie 删除:** 测试了在进行垃圾回收时，非 Secure 的 Cookie 会优先于 Secure 的 Cookie 被删除。
8. **分区 Cookie 的垃圾回收限制 (内存和数量):** 测试了分区 Cookie 的垃圾回收机制，包括基于每个分区域名的最大内存限制和最大 Cookie 数量限制。
9. **设置可接受的 Cookie Scheme:** 测试了 `SetCookieableSchemes` 方法，允许 CookieMonster 接受特定 scheme 的 Cookie，例如 `foo://`。同时也测试了在 CookieStore 初始化后设置 scheme 会失败的情况。
10. **获取指定 URL 的所有 Cookie (包括分区 Cookie):** 测试了 `GetAllCookiesForURL` 方法，验证了可以获取指定 URL 的所有 Cookie，并且可以根据 `CookiePartitionKeyCollection` 参数来指定需要获取的分区 Cookie。
11. **获取指定 URL 被排除的 Cookie 及其排除原因:** 测试了 `GetExcludedCookiesForURL` 方法，可以获取由于各种原因（例如 SecureOnly，HttpOnly，Path不匹配等）而被排除在发送到服务器的 Cookie。
12. **根据路径匹配获取 Cookie 和排除的 Cookie:** 测试了 `GetAllCookiesForURL` 和 `GetExcludedCookiesForURL` 方法在路径匹配方面的行为。

**与 Javascript 的关系及举例说明:**

`CookieMonster` 是浏览器网络栈中管理 Cookie 的核心组件。Javascript 通过 `document.cookie` API 与浏览器的 Cookie 进行交互。

* **设置 Cookie:** 当 Javascript 代码执行 `document.cookie = "mycookie=value"` 时，浏览器会将这个操作传递给底层的 `CookieMonster` 来创建或更新 Cookie。
* **获取 Cookie:** 当 Javascript 代码读取 `document.cookie` 时，浏览器会调用 `CookieMonster` 的相应方法来获取符合条件的 Cookie，并将其格式化为字符串返回给 Javascript。
* **删除 Cookie:** Javascript 可以通过设置过期时间为过去的时间来删除 Cookie，这最终也会调用 `CookieMonster` 的删除方法。

**举例说明:**

* **Javascript 设置 Cookie:** `document.cookie = "test=123; path=/; secure";` 这个操作会触发 `CookieMonster` 的 `SetCookie` 或类似的内部方法，`secure` 属性会影响 `CookieMonster` 对 Secure Cookie 的处理。
* **Javascript 获取 Cookie:**  如果 Javascript 代码在 `https://www.foo.com/` 页面执行 `document.cookie`，那么 `CookieMonster` 的 `GetAllCookiesForURL` 方法会被调用，传入 `https://www.foo.com/` 这个 URL，`CookieMonster` 会返回所有与该 URL 匹配的 Cookie。
* **Javascript 尝试获取 HttpOnly Cookie:** 如果一个 Cookie 被标记为 `HttpOnly`，那么当 Javascript 尝试读取 `document.cookie` 时，这个 Cookie 将不会被包含在返回的字符串中，这是由 `CookieMonster` 的逻辑控制的。在测试代码中，`GetAllCookiesForURLWithOptions` 方法就演示了如何排除 HttpOnly 的 Cookie。
* **Javascript 与分区 Cookie:** 如果网站设置了分区 Cookie，Javascript 的 `document.cookie` API 并不能直接区分或指定分区。浏览器的底层 `CookieMonster` 会根据当前页面的顶层站点来管理和发送分区 Cookie。

**逻辑推理、假设输入与输出:**

**例子 1: `DeleteAllCreatedInTimeRange`**

* **假设输入:**
    * `CookieMonster` 中存在以下 Cookie (假设当前时间为 `now`):
        * Cookie A: 创建时间 `now - base::Days(1)`
        * Cookie B: 创建时间 `now - base::Days(2)`
        * Cookie C: 创建时间 `now - base::Days(3)`
    * 调用 `DeleteAllCreatedInTimeRange(cm.get(), TimeRange(now - base::Days(2), now));`
* **逻辑推理:**  删除创建时间在 `now - base::Days(2)` (包含) 和 `now` (不包含) 之间的 Cookie。
* **预期输出:** Cookie A 和 Cookie B 被删除，Cookie C 保留。`EXPECT_EQ(2u, ...)` 会成立。

**例子 2: `DeleteMatchingCookies`**

* **假设输入:**
    * `CookieMonster` 中存在以下 Cookie:
        * Cookie D: Domain `a.com`, Secure: true
        * Cookie E: Domain `b.com`, Secure: false
        * Cookie F: Domain `c.com`, Secure: true
    * 调用 `DeleteMatchingCookies(cm.get(), base::BindRepeating([](const net::CanonicalCookie& cookie) { return !cookie.SecureAttribute(); }));`
* **逻辑推理:** 删除所有 `SecureAttribute` 为 false 的 Cookie。
* **预期输出:** Cookie E 被删除，Cookie D 和 Cookie F 保留。`EXPECT_EQ(1u, ...)` 会成立，并且后续的 `GetAllCookies` 断言会验证剩余的 Cookie。

**用户或编程常见的使用错误:**

1. **删除 Cookie 时时间范围设置错误:** 用户可能希望删除昨天创建的 Cookie，但设置的时间范围不正确，例如 `TimeRange(now - base::Days(2), now - base::Hours(12))`，这可能会漏掉部分目标 Cookie。
2. **使用 `DeleteMatchingCookies` 时匹配条件过于宽泛或过于狭窄:** 开发者可能编写的匹配条件错误地删除了不应该删除的 Cookie，或者遗漏了应该删除的 Cookie。
3. **混淆主机 Cookie 和域名 Cookie 的作用域:**  用户或开发者可能不清楚主机 Cookie 和域名 Cookie 的区别，导致设置或删除 Cookie 时出现意料之外的结果。例如，在子域名下设置了域名 Cookie，然后在父域名下尝试删除，可能会出现问题。
4. **忘记处理分区 Cookie:**  在涉及分区 Cookie 的场景下，如果开发者只考虑非分区 Cookie 的逻辑，可能会导致某些 Cookie 没有被正确处理（例如，删除时需要指定正确的 `CookiePartitionKey`）。
5. **错误地理解 Cookie 的 `Secure` 和 `HttpOnly` 属性:** 开发者可能不清楚这两个属性的作用，导致 Cookie 的安全性和可访问性出现问题。例如，将敏感信息存储在非 Secure 的 Cookie 中，或者尝试在 Javascript 中访问 HttpOnly 的 Cookie。

**用户操作如何一步步到达这里 (调试线索):**

假设用户希望清除某个网站的所有 Cookie：

1. **用户打开浏览器设置或历史记录:** 用户在浏览器界面上操作，例如点击菜单栏的“设置” -> “隐私和安全” -> “Cookie 及其他网站数据” -> “查看所有网站数据和权限”。
2. **用户搜索或浏览到目标网站:** 用户在 Cookie 管理界面中找到想要清除 Cookie 的特定网站，例如 `www.foo.com`。
3. **用户点击“删除”或“清除”按钮:** 用户执行删除操作，浏览器会将这个请求传递给底层的 Cookie 管理模块。
4. **浏览器调用 `CookieMonster` 的删除方法:**  浏览器内部会根据用户的选择调用 `CookieMonster` 相应的删除方法，例如 `DeleteAllForDomain` 或 `DeleteAllCreatedInTimeRange` (如果根据时间范围删除)。
5. **`CookieMonster` 执行删除逻辑:**  `CookieMonster` 根据传入的参数，在其内部的数据结构中查找并删除匹配的 Cookie。这期间就会执行到 `cookie_monster_unittest.cc` 中测试的那些删除逻辑。

**调试线索:**

* **查看浏览器的开发者工具 (Application -> Cookies):** 可以查看当前网站存储的 Cookie 及其属性 (Domain, Path, Secure, HttpOnly, Partition Key 等)，帮助理解 Cookie 的状态。
* **使用浏览器的网络请求面板 (Network):** 可以查看请求头中的 `Cookie` 字段和响应头中的 `Set-Cookie` 字段，了解 Cookie 的发送和设置情况。
* **在 Chrome 浏览器中可以使用 `chrome://net-internals/#cookies` 查看更详细的 Cookie 信息。**
* **在测试环境中，可以通过断点调试 `CookieMonster` 的相关方法，查看 Cookie 的添加、删除和访问过程。**

总而言之，这部分代码是 `CookieMonster` 单元测试的重要组成部分，它细致地测试了 Cookie 的删除和垃圾回收机制的各种场景和边界情况，确保了 Chromium 浏览器能够正确地管理用户的 Cookie 数据。

Prompt: 
```
这是目录为net/cookies/cookie_monster_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共10部分，请归纳一下它的功能

"""
TimeRange(
                    cm.get(), TimeRange(now - base::Days(2), now)));

  // Make sure the delete_begin is inclusive.
  EXPECT_EQ(1u, DeleteAllCreatedInTimeRange(
                    cm.get(), TimeRange(now - base::Days(7), now)));

  // Delete the last (now) item.
  EXPECT_EQ(1u, DeleteAllCreatedInTimeRange(cm.get(), TimeRange()));

  // Really make sure everything is gone.
  EXPECT_EQ(0u, DeleteAll(cm.get()));

  // Test the same deletion process with partitioned cookies. Partitioned
  // cookies should behave the same way as unpartitioned cookies here, they are
  // just stored in a different data structure internally.

  EXPECT_TRUE(
      SetCookieWithCreationTime(cm.get(), http_www_foo_.url(), "T-0=Now", now,
                                CookiePartitionKey::FromURLForTesting(
                                    GURL("https://toplevelsite0.com"))));
  EXPECT_TRUE(SetCookieWithCreationTime(
      cm.get(), https_www_foo_.url(), "T-1=Yesterday", now - base::Days(1),
      CookiePartitionKey::FromURLForTesting(
          GURL("https://toplevelsite1.com"))));
  EXPECT_TRUE(SetCookieWithCreationTime(
      cm.get(), http_www_foo_.url(), "T-2=DayBefore", now - base::Days(2),
      CookiePartitionKey::FromURLForTesting(
          GURL("https://toplevelsite1.com"))));
  EXPECT_TRUE(SetCookieWithCreationTime(
      cm.get(), http_www_foo_.url(), "T-3=ThreeDays", now - base::Days(3),
      CookiePartitionKey::FromURLForTesting(
          GURL("https://toplevelsite2.com"))));
  EXPECT_TRUE(SetCookieWithCreationTime(
      cm.get(), http_www_foo_.url(), "T-7=LastWeek", now - base::Days(7),
      CookiePartitionKey::FromURLForTesting(
          GURL("https://toplevelsite3.com"))));

  // Try to delete threedays and the daybefore.
  EXPECT_EQ(2u,
            DeleteAllCreatedInTimeRange(
                cm.get(), TimeRange(now - base::Days(3), now - base::Days(1))));

  // Try to delete yesterday, also make sure that delete_end is not
  // inclusive.
  EXPECT_EQ(1u, DeleteAllCreatedInTimeRange(
                    cm.get(), TimeRange(now - base::Days(2), now)));

  // Make sure the delete_begin is inclusive.
  EXPECT_EQ(1u, DeleteAllCreatedInTimeRange(
                    cm.get(), TimeRange(now - base::Days(7), now)));

  // Delete the last (now) item.
  EXPECT_EQ(1u, DeleteAllCreatedInTimeRange(cm.get(), TimeRange()));

  // Really make sure everything is gone.
  EXPECT_EQ(0u, DeleteAll(cm.get()));
}

TEST_F(CookieMonsterTest,
       TestCookieDeleteAllCreatedInTimeRangeTimestampsWithInfo) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  Time now = Time::Now();

  CanonicalCookie test_cookie;

  // Nothing has been added so nothing should be deleted.
  EXPECT_EQ(0u,
            DeleteAllMatchingInfo(
                cm.get(), CookieDeletionInfo(now - base::Days(99), Time())));

  // Create 5 cookies with different creation dates.
  EXPECT_TRUE(
      SetCookieWithCreationTime(cm.get(), http_www_foo_.url(), "T-0=Now", now));
  EXPECT_TRUE(SetCookieWithCreationTime(cm.get(), http_www_foo_.url(),
                                        "T-1=Yesterday", now - base::Days(1)));
  EXPECT_TRUE(SetCookieWithCreationTime(cm.get(), http_www_foo_.url(),
                                        "T-2=DayBefore", now - base::Days(2)));
  EXPECT_TRUE(SetCookieWithCreationTime(cm.get(), http_www_foo_.url(),
                                        "T-3=ThreeDays", now - base::Days(3)));
  EXPECT_TRUE(SetCookieWithCreationTime(cm.get(), http_www_foo_.url(),
                                        "T-7=LastWeek", now - base::Days(7)));

  // Delete threedays and the daybefore.
  EXPECT_EQ(2u, DeleteAllMatchingInfo(cm.get(),
                                      CookieDeletionInfo(now - base::Days(3),
                                                         now - base::Days(1))));

  // Delete yesterday, also make sure that delete_end is not inclusive.
  EXPECT_EQ(1u, DeleteAllMatchingInfo(
                    cm.get(), CookieDeletionInfo(now - base::Days(2), now)));

  // Make sure the delete_begin is inclusive.
  EXPECT_EQ(1u, DeleteAllMatchingInfo(
                    cm.get(), CookieDeletionInfo(now - base::Days(7), now)));

  // Delete the last (now) item.
  EXPECT_EQ(1u, DeleteAllMatchingInfo(cm.get(), CookieDeletionInfo()));

  // Really make sure everything is gone.
  EXPECT_EQ(0u, DeleteAll(cm.get()));

  // Test the same deletion process with partitioned cookies. Partitioned
  // cookies should behave the same way as unpartitioned cookies here, they are
  // just stored in a different data structure internally.

  EXPECT_TRUE(
      SetCookieWithCreationTime(cm.get(), http_www_foo_.url(), "T-0=Now", now,
                                CookiePartitionKey::FromURLForTesting(
                                    GURL("https://toplevelsite0.com"))));
  EXPECT_TRUE(SetCookieWithCreationTime(
      cm.get(), https_www_foo_.url(), "T-1=Yesterday", now - base::Days(1),
      CookiePartitionKey::FromURLForTesting(
          GURL("https://toplevelsite1.com"))));
  EXPECT_TRUE(SetCookieWithCreationTime(
      cm.get(), http_www_foo_.url(), "T-2=DayBefore", now - base::Days(2),
      CookiePartitionKey::FromURLForTesting(
          GURL("https://toplevelsite1.com"))));
  EXPECT_TRUE(SetCookieWithCreationTime(
      cm.get(), http_www_foo_.url(), "T-3=ThreeDays", now - base::Days(3),
      CookiePartitionKey::FromURLForTesting(
          GURL("https://toplevelsite2.com"))));
  EXPECT_TRUE(SetCookieWithCreationTime(
      cm.get(), http_www_foo_.url(), "T-7=LastWeek", now - base::Days(7),
      CookiePartitionKey::FromURLForTesting(
          GURL("https://toplevelsite3.com"))));

  // Delete threedays and the daybefore.
  EXPECT_EQ(2u, DeleteAllMatchingInfo(cm.get(),
                                      CookieDeletionInfo(now - base::Days(3),
                                                         now - base::Days(1))));

  // Delete yesterday, also make sure that delete_end is not inclusive.
  EXPECT_EQ(1u, DeleteAllMatchingInfo(
                    cm.get(), CookieDeletionInfo(now - base::Days(2), now)));

  // Make sure the delete_begin is inclusive.
  EXPECT_EQ(1u, DeleteAllMatchingInfo(
                    cm.get(), CookieDeletionInfo(now - base::Days(7), now)));

  // Delete the last (now) item.
  EXPECT_EQ(1u, DeleteAllMatchingInfo(cm.get(), CookieDeletionInfo()));

  // Really make sure everything is gone.
  EXPECT_EQ(0u, DeleteAll(cm.get()));
}

TEST_F(CookieMonsterTest, TestCookieDeleteMatchingCookies) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());
  Time now = Time::Now();

  // Nothing has been added so nothing should be deleted.
  EXPECT_EQ(0u, DeleteMatchingCookies(
                    cm.get(),
                    base::BindRepeating([](const net::CanonicalCookie& cookie) {
                      return true;
                    })));

  // Create 5 cookies with different domains and security status.
  EXPECT_TRUE(SetCookieWithCreationTime(cm.get(), GURL("https://a.com"),
                                        "a1=1;Secure", now));
  EXPECT_TRUE(
      SetCookieWithCreationTime(cm.get(), GURL("https://a.com"), "a2=2", now));
  EXPECT_TRUE(SetCookieWithCreationTime(cm.get(), GURL("https://b.com"),
                                        "b1=1;Secure", now));
  EXPECT_TRUE(
      SetCookieWithCreationTime(cm.get(), GURL("http://b.com"), "b2=2", now));
  EXPECT_TRUE(SetCookieWithCreationTime(cm.get(), GURL("https://c.com"),
                                        "c1=1;Secure", now));

  // Set a partitioned cookie.
  EXPECT_TRUE(SetCookieWithCreationTime(
      cm.get(), GURL("https://d.com"),
      "__Host-pc=123; path=/; secure; partitioned", now,
      CookiePartitionKey::FromURLForTesting(GURL("https://e.com"))));

  // Delete http cookies.
  EXPECT_EQ(2u, DeleteMatchingCookies(
                    cm.get(),
                    base::BindRepeating([](const net::CanonicalCookie& cookie) {
                      return !cookie.SecureAttribute();
                    })));
  EXPECT_THAT(GetAllCookies(cm.get()),
              ElementsAre(MatchesCookieNameDomain("a1", "a.com"),
                          MatchesCookieNameDomain("b1", "b.com"),
                          MatchesCookieNameDomain("c1", "c.com"),
                          MatchesCookieNameDomain("__Host-pc", "d.com")));

  // Delete remaining cookie for a.com.
  EXPECT_EQ(1u, DeleteMatchingCookies(
                    cm.get(),
                    base::BindRepeating([](const net::CanonicalCookie& cookie) {
                      return cookie.Domain() == "a.com";
                    })));
  EXPECT_THAT(GetAllCookies(cm.get()),
              ElementsAre(MatchesCookieNameDomain("b1", "b.com"),
                          MatchesCookieNameDomain("c1", "c.com"),
                          MatchesCookieNameDomain("__Host-pc", "d.com")));

  // Delete the partitioned cookie.
  EXPECT_EQ(1u, DeleteMatchingCookies(
                    cm.get(),
                    base::BindRepeating([](const net::CanonicalCookie& cookie) {
                      return cookie.IsPartitioned();
                    })));

  // Delete the last two item.
  EXPECT_EQ(2u, DeleteMatchingCookies(
                    cm.get(),
                    base::BindRepeating([](const net::CanonicalCookie& cookie) {
                      return true;
                    })));

  // Really make sure everything is gone.
  EXPECT_TRUE(GetAllCookies(cm.get()).empty());
}

static const base::TimeDelta kLastAccessThreshold = base::Milliseconds(200);
static const base::TimeDelta kAccessDelay =
    kLastAccessThreshold + base::Milliseconds(20);

TEST_F(CookieMonsterTest, TestLastAccess) {
  auto cm = std::make_unique<CookieMonster>(nullptr, kLastAccessThreshold,
                                            net::NetLog::Get());

  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=B"));
  const Time last_access_date(GetFirstCookieAccessDate(cm.get()));

  // Reading the cookie again immediately shouldn't update the access date,
  // since we're inside the threshold.
  EXPECT_EQ("A=B", GetCookies(cm.get(), http_www_foo_.url()));
  EXPECT_EQ(last_access_date, GetFirstCookieAccessDate(cm.get()));

  // Reading after a short wait will update the access date, if the cookie
  // is requested with options that would update the access date. First, test
  // that the flag's behavior is respected.
  base::PlatformThread::Sleep(kAccessDelay);
  CookieOptions options = CookieOptions::MakeAllInclusive();
  options.set_do_not_update_access_time();
  EXPECT_EQ("A=B",
            GetCookiesWithOptions(cm.get(), http_www_foo_.url(), options));
  EXPECT_EQ(last_access_date, GetFirstCookieAccessDate(cm.get()));

  // Getting all cookies for a URL doesn't update the accessed time either.
  CookieList cookies = GetAllCookiesForURL(cm.get(), http_www_foo_.url());
  auto it = cookies.begin();
  ASSERT_TRUE(it != cookies.end());
  EXPECT_EQ(http_www_foo_.host(), it->Domain());
  EXPECT_EQ("A", it->Name());
  EXPECT_EQ("B", it->Value());
  EXPECT_EQ(last_access_date, GetFirstCookieAccessDate(cm.get()));
  EXPECT_TRUE(++it == cookies.end());

  // If the flag isn't set, the last accessed time should be updated.
  options.set_update_access_time();
  EXPECT_EQ("A=B",
            GetCookiesWithOptions(cm.get(), http_www_foo_.url(), options));
  EXPECT_FALSE(last_access_date == GetFirstCookieAccessDate(cm.get()));
}

TEST_P(CookieMonsterTestPriorityGarbageCollectionObc,
       TestHostGarbageCollection) {
  TestHostGarbageCollectHelper();
}

TEST_P(CookieMonsterTestPriorityGarbageCollectionObc,
       TestPriorityAwareGarbageCollectionNonSecure) {
  TestPriorityAwareGarbageCollectHelperNonSecure();
}

TEST_P(CookieMonsterTestPriorityGarbageCollectionObc,
       TestPriorityAwareGarbageCollectionSecure) {
  TestPriorityAwareGarbageCollectHelperSecure();
}

TEST_P(CookieMonsterTestPriorityGarbageCollectionObc,
       TestPriorityAwareGarbageCollectionMixed) {
  TestPriorityAwareGarbageCollectHelperMixed();
}

// Test that domain cookies are always deleted before host cookies for a given
// {priority, secureness}. In this case, default priority and secure.
TEST_P(CookieMonsterTestGarbageCollectionObc, DomainCookiesPreferred) {
  ASSERT_TRUE(cookie_util::IsOriginBoundCookiesPartiallyEnabled());
  // This test requires the following values.
  ASSERT_EQ(180U, CookieMonster::kDomainMaxCookies);
  ASSERT_EQ(150U, CookieMonster::kDomainMaxCookies -
                      CookieMonster::kDomainPurgeCookies);

  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  // Insert an extra host cookie so that one will need to be deleted;
  // demonstrating that host cookies will still be deleted if need be but they
  // aren't preferred.
  for (int i = 0; i < 151; i++) {
    std::string cookie = "host_" + base::NumberToString(i) + "=foo; Secure";
    EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(), cookie));
  }

  // By adding the domain cookies after the host cookies they are more recently
  // accessed, which would normally cause these cookies to be preserved. By
  // showing that they're still deleted before the host cookies we can
  // demonstrate that domain cookies are preferred for deletion.
  for (int i = 0; i < 30; i++) {
    std::string cookie = "domain_" + base::NumberToString(i) +
                         "=foo; Secure; Domain=" + https_www_foo_.domain();
    EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(), cookie));
  }

  auto cookie_list = this->GetAllCookiesForURL(cm.get(), https_www_foo_.url());

  int domain_count = 0;
  int host_count = 0;
  for (const auto& cookie : cookie_list) {
    if (cookie.IsHostCookie()) {
      host_count++;
    } else {
      domain_count++;
    }
  }

  EXPECT_EQ(host_count, 150);
  EXPECT_EQ(domain_count, 0);
}

// Securely set cookies should always be deleted after non-securely set cookies.
TEST_P(CookieMonsterTestGarbageCollectionObc, SecureCookiesPreferred) {
  ASSERT_TRUE(cookie_util::IsOriginBoundCookiesPartiallyEnabled());
  // This test requires the following values.
  ASSERT_EQ(180U, CookieMonster::kDomainMaxCookies);
  ASSERT_EQ(150U, CookieMonster::kDomainMaxCookies -
                      CookieMonster::kDomainPurgeCookies);

  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  // If scheme binding is enabled then the secure url is enough, otherwise we
  // need to also add "Secure" to the cookie line.
  std::string secure_attr =
      cookie_util::IsSchemeBoundCookiesEnabled() ? "" : "; Secure";

  // These cookies would normally be preferred for deletion because they're 1)
  // Domain cookies, and 2) they're least recently accessed. But, since they're
  // securely set they'll be deleted after non-secure cookies.
  for (int i = 0; i < 151; i++) {
    std::string cookie = "domain_" + base::NumberToString(i) +
                         "=foo; Domain=" + https_www_foo_.domain() +
                         secure_attr;
    EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(), cookie));
  }

  for (int i = 0; i < 30; i++) {
    std::string cookie = "host_" + base::NumberToString(i) + "=foo";
    EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), cookie));
  }

  auto secure_cookie_list =
      this->GetAllCookiesForURL(cm.get(), https_www_foo_.url());
  auto insecure_cookie_list =
      this->GetAllCookiesForURL(cm.get(), http_www_foo_.url());

  int domain_count = 0;
  int host_count = 0;

  for (const auto& cookie : secure_cookie_list) {
    if (cookie.IsHostCookie()) {
      host_count++;
    } else {
      domain_count++;
    }
  }

  for (const auto& cookie : insecure_cookie_list) {
    if (cookie.IsHostCookie()) {
      host_count++;
    } else {
      domain_count++;
    }
  }

  EXPECT_EQ(host_count, 0);
  EXPECT_EQ(domain_count, 150);
}

TEST_F(CookieMonsterTest, TestPartitionedCookiesGarbageCollection_Memory) {
  // Limit should be 10 KB.
  DCHECK_EQ(1024u * 10u, CookieMonster::kPerPartitionDomainMaxCookieBytes);

  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());
  auto cookie_partition_key =
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite1.com"));

  for (size_t i = 0; i < 41; ++i) {
    std::string cookie_value((10240 / 40) - (i < 10 ? 1 : 2), '0');
    std::string cookie =
        base::StrCat({base::NumberToString(i), "=", cookie_value});
    EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(),
                          cookie + "; secure; path=/; partitioned",
                          cookie_partition_key))
        << "Failed to set cookie " << i;
  }

  std::string cookies =
      this->GetCookies(cm.get(), https_www_foo_.url(),
                       CookiePartitionKeyCollection(cookie_partition_key));

  EXPECT_THAT(cookies, CookieStringIs(
                           testing::Not(testing::Contains(testing::Key("0")))));
  for (size_t i = 1; i < 41; ++i) {
    EXPECT_THAT(cookies, CookieStringIs(testing::Contains(
                             testing::Key(base::NumberToString(i)))))
        << "Failed to find cookie " << i;
  }
}

TEST_F(CookieMonsterTest, TestPartitionedCookiesGarbageCollection_MaxCookies) {
  // Partitioned cookies also limit domains to 180 cookies per partition.
  DCHECK_EQ(180u, CookieMonster::kPerPartitionDomainMaxCookies);

  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());
  auto cookie_partition_key =
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com"));

  for (size_t i = 0; i < 181; ++i) {
    std::string cookie = base::StrCat({base::NumberToString(i), "=0"});
    EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(),
                          cookie + "; secure; path=/; partitioned",
                          cookie_partition_key))
        << "Failed to set cookie " << i;
  }

  std::string cookies =
      this->GetCookies(cm.get(), https_www_foo_.url(),
                       CookiePartitionKeyCollection(cookie_partition_key));
  EXPECT_THAT(cookies, CookieStringIs(
                           testing::Not(testing::Contains(testing::Key("0")))));
  for (size_t i = 1; i < 181; ++i) {
    std::string cookie = base::StrCat({base::NumberToString(i), "=0"});
    EXPECT_THAT(cookies, CookieStringIs(testing::Contains(
                             testing::Key(base::NumberToString(i)))))
        << "Failed to find cookie " << i;
  }
}

TEST_F(CookieMonsterTest, SetCookieableSchemes) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  auto cm_foo = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  // Only cm_foo should allow foo:// cookies.
  std::vector<std::string> schemes;
  schemes.push_back("foo");
  ResultSavingCookieCallback<bool> cookie_scheme_callback;
  cm_foo->SetCookieableSchemes(schemes, cookie_scheme_callback.MakeCallback());
  cookie_scheme_callback.WaitUntilDone();
  EXPECT_TRUE(cookie_scheme_callback.result());

  GURL foo_url("foo://host/path");
  GURL http_url("http://host/path");

  base::Time now = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  EXPECT_TRUE(
      CreateAndSetCookieReturnStatus(cm.get(), http_url, "x=1").IsInclude());
  EXPECT_TRUE(
      SetCanonicalCookieReturnAccessResult(
          cm.get(),
          CanonicalCookie::CreateForTesting(http_url, "y=1", now, server_time),
          http_url, false /*modify_httponly*/)
          .status.IsInclude());

  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), foo_url, "x=1")
                  .HasExactlyExclusionReasonsForTesting(
                      {CookieInclusionStatus::EXCLUDE_NONCOOKIEABLE_SCHEME}));
  EXPECT_TRUE(
      SetCanonicalCookieReturnAccessResult(
          cm.get(),
          CanonicalCookie::CreateForTesting(foo_url, "y=1", now, server_time),
          foo_url, false /*modify_httponly*/)
          .status.HasExactlyExclusionReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_NONCOOKIEABLE_SCHEME}));

  EXPECT_TRUE(
      CreateAndSetCookieReturnStatus(cm_foo.get(), foo_url, "x=1").IsInclude());
  EXPECT_TRUE(
      SetCanonicalCookieReturnAccessResult(
          cm_foo.get(),
          CanonicalCookie::CreateForTesting(foo_url, "y=1", now, server_time),
          foo_url, false /*modify_httponly*/)
          .status.IsInclude());

  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm_foo.get(), http_url, "x=1")
                  .HasExactlyExclusionReasonsForTesting(
                      {CookieInclusionStatus::EXCLUDE_NONCOOKIEABLE_SCHEME}));
  EXPECT_TRUE(
      SetCanonicalCookieReturnAccessResult(
          cm_foo.get(),
          CanonicalCookie::CreateForTesting(http_url, "y=1", now, server_time),
          http_url, false /*modify_httponly*/)
          .status.HasExactlyExclusionReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_NONCOOKIEABLE_SCHEME}));
}

TEST_F(CookieMonsterTest, SetCookieableSchemes_StoreInitialized) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());
  // Initializes the cookie store.
  this->GetCookies(cm.get(), https_www_foo_.url(),
                   CookiePartitionKeyCollection());

  std::vector<std::string> schemes;
  schemes.push_back("foo");
  ResultSavingCookieCallback<bool> cookie_scheme_callback;
  cm->SetCookieableSchemes(schemes, cookie_scheme_callback.MakeCallback());
  cookie_scheme_callback.WaitUntilDone();
  EXPECT_FALSE(cookie_scheme_callback.result());

  base::Time now = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  GURL foo_url("foo://host/path");
  EXPECT_TRUE(
      SetCanonicalCookieReturnAccessResult(
          cm.get(),
          CanonicalCookie::CreateForTesting(foo_url, "y=1", now, server_time),
          foo_url, false /*modify_httponly*/)
          .status.HasExactlyExclusionReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_NONCOOKIEABLE_SCHEME}));
}

TEST_F(CookieMonsterTest, GetAllCookiesForURL) {
  auto cm = std::make_unique<CookieMonster>(nullptr, kLastAccessThreshold,
                                            net::NetLog::Get());

  // Create an httponly cookie.
  CookieOptions options = CookieOptions::MakeAllInclusive();

  EXPECT_TRUE(CreateAndSetCookie(cm.get(), http_www_foo_.url(), "A=B; httponly",
                                 options));
  EXPECT_TRUE(CreateAndSetCookie(cm.get(), http_www_foo_.url(),
                                 http_www_foo_.Format("C=D; domain=.%D"),
                                 options));
  EXPECT_TRUE(CreateAndSetCookie(
      cm.get(), https_www_foo_.url(),
      http_www_foo_.Format("E=F; domain=.%D; secure"), options));

  EXPECT_TRUE(CreateAndSetCookie(cm.get(), http_www_bar_.url(),
                                 http_www_bar_.Format("G=H; domain=.%D"),
                                 options));

  EXPECT_TRUE(CreateAndSetCookie(
      cm.get(), https_www_foo_.url(),
      https_www_foo_.Format("I=J; domain=.%D; secure"), options));

  // Create partitioned cookies for the same site with some partition key.
  auto cookie_partition_key1 =
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite1.com"));
  auto cookie_partition_key2 =
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite2.com"));
  auto cookie_partition_key3 =
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite3.com"));
  EXPECT_TRUE(CreateAndSetCookie(
      cm.get(), https_www_bar_.url(), "__Host-K=L; secure; path=/; partitioned",
      options, std::nullopt, std::nullopt, cookie_partition_key1));
  EXPECT_TRUE(CreateAndSetCookie(
      cm.get(), https_www_bar_.url(), "__Host-M=N; secure; path=/; partitioned",
      options, std::nullopt, std::nullopt, cookie_partition_key2));
  EXPECT_TRUE(CreateAndSetCookie(
      cm.get(), https_www_bar_.url(), "__Host-O=P; secure; path=/; partitioned",
      options, std::nullopt, std::nullopt, cookie_partition_key3));

  const Time last_access_date(GetFirstCookieAccessDate(cm.get()));

  base::PlatformThread::Sleep(kAccessDelay);

  // Check cookies for url.
  EXPECT_THAT(
      GetAllCookiesForURL(cm.get(), http_www_foo_.url()),
      ElementsAre(MatchesCookieNameDomain("A", http_www_foo_.host()),
                  MatchesCookieNameDomain("C", http_www_foo_.Format(".%D"))));

  // Check cookies for url excluding http-only cookies.
  CookieOptions exclude_httponly = options;
  exclude_httponly.set_exclude_httponly();

  EXPECT_THAT(
      GetAllCookiesForURLWithOptions(cm.get(), http_www_foo_.url(),
                                     exclude_httponly),
      ElementsAre(MatchesCookieNameDomain("C", http_www_foo_.Format(".%D"))));

  // Test secure cookies.
  EXPECT_THAT(
      GetAllCookiesForURL(cm.get(), https_www_foo_.url()),
      ElementsAre(MatchesCookieNameDomain("A", http_www_foo_.host()),
                  MatchesCookieNameDomain("C", http_www_foo_.Format(".%D")),
                  MatchesCookieNameDomain("E", http_www_foo_.Format(".%D")),
                  MatchesCookieNameDomain("I", http_www_foo_.Format(".%D"))));

  // Test reading partitioned cookies for a single partition.
  EXPECT_THAT(
      GetAllCookiesForURL(cm.get(), https_www_bar_.url(),
                          CookiePartitionKeyCollection(cookie_partition_key1)),
      ElementsAre(MatchesCookieNameDomain("G", https_www_bar_.Format(".%D")),
                  MatchesCookieNameDomain("__Host-K", https_www_bar_.host())));
  EXPECT_THAT(
      GetAllCookiesForURL(cm.get(), https_www_bar_.url(),
                          CookiePartitionKeyCollection(cookie_partition_key2)),
      ElementsAre(MatchesCookieNameDomain("G", https_www_bar_.Format(".%D")),
                  MatchesCookieNameDomain("__Host-M", https_www_bar_.host())));

  // Test reading partitioned cookies from multiple partitions.
  EXPECT_THAT(
      GetAllCookiesForURL(cm.get(), https_www_bar_.url(),
                          CookiePartitionKeyCollection(
                              {cookie_partition_key1, cookie_partition_key2})),
      ElementsAre(MatchesCookieNameDomain("G", https_www_bar_.Format(".%D")),
                  MatchesCookieNameDomain("__Host-K", https_www_bar_.host()),
                  MatchesCookieNameDomain("__Host-M", https_www_bar_.host())));

  // Test reading partitioned cookies from every partition.
  EXPECT_THAT(
      GetAllCookiesForURL(cm.get(), https_www_bar_.url(),
                          CookiePartitionKeyCollection::ContainsAll()),
      ElementsAre(MatchesCookieNameDomain("G", https_www_bar_.Format(".%D")),
                  MatchesCookieNameDomain("__Host-K", https_www_bar_.host()),
                  MatchesCookieNameDomain("__Host-M", https_www_bar_.host()),
                  MatchesCookieNameDomain("__Host-O", https_www_bar_.host())));

  // Test excluding partitioned cookies.
  EXPECT_THAT(
      GetAllCookiesForURL(cm.get(), https_www_bar_.url(),
                          CookiePartitionKeyCollection()),
      ElementsAre(MatchesCookieNameDomain("G", https_www_bar_.Format(".%D"))));

  // Reading after a short wait should not update the access date.
  EXPECT_EQ(last_access_date, GetFirstCookieAccessDate(cm.get()));
}

TEST_F(CookieMonsterTest, GetExcludedCookiesForURL) {
  auto cm = std::make_unique<CookieMonster>(nullptr, kLastAccessThreshold,
                                            net::NetLog::Get());

  // Create an httponly cookie.
  CookieOptions options = CookieOptions::MakeAllInclusive();

  EXPECT_TRUE(CreateAndSetCookie(cm.get(), http_www_foo_.url(), "A=B; httponly",
                                 options));
  EXPECT_TRUE(CreateAndSetCookie(cm.get(), http_www_foo_.url(),
                                 http_www_foo_.Format("C=D; domain=.%D"),
                                 options));
  EXPECT_TRUE(CreateAndSetCookie(
      cm.get(), https_www_foo_.url(),
      http_www_foo_.Format("E=F; domain=.%D; secure"), options));

  base::PlatformThread::Sleep(kAccessDelay);

  // Check that no cookies are sent when option is turned off
  CookieOptions do_not_return_excluded;
  do_not_return_excluded.unset_return_excluded_cookies();

  CookieAccessResultList excluded_cookies = GetExcludedCookiesForURLWithOptions(
      cm.get(), http_www_foo_.url(), do_not_return_excluded);
  auto iter = excluded_cookies.begin();

  EXPECT_TRUE(excluded_cookies.empty());

  // Checking that excluded cookies get sent with their statuses with http
  // request.
  excluded_cookies = GetExcludedCookiesForURL(cm.get(), http_www_foo_.url(),
                                              CookiePartitionKeyCollection());
  iter = excluded_cookies.begin();

  ASSERT_TRUE(iter != excluded_cookies.end());
  EXPECT_EQ(http_www_foo_.Format(".%D"), iter->cookie.Domain());
  EXPECT_EQ("E", iter->cookie.Name());
  EXPECT_TRUE(iter->access_result.status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_SECURE_ONLY}));

  ASSERT_TRUE(++iter == excluded_cookies.end());

  // Checking that excluded cookies get sent with their statuses with http-only.
  CookieOptions return_excluded;
  return_excluded.set_return_excluded_cookies();
  return_excluded.set_exclude_httponly();
  return_excluded.set_same_site_cookie_context(
      CookieOptions::SameSiteCookieContext(
          CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_STRICT));

  excluded_cookies = GetExcludedCookiesForURLWithOptions(
      cm.get(), http_www_foo_.url(), return_excluded);
  iter = excluded_cookies.begin();

  ASSERT_TRUE(iter != excluded_cookies.end());
  EXPECT_EQ(http_www_foo_.host(), iter->cookie.Domain());
  EXPECT_EQ("A", iter->cookie.Name());
  EXPECT_TRUE(iter->access_result.status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_HTTP_ONLY}));

  ASSERT_TRUE(++iter != excluded_cookies.end());
  EXPECT_EQ(http_www_foo_.Format(".%D"), iter->cookie.Domain());
  EXPECT_EQ("E", iter->cookie.Name());
  EXPECT_TRUE(iter->access_result.status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_SECURE_ONLY}));

  ASSERT_TRUE(++iter == excluded_cookies.end());

  // Check that no excluded cookies are sent with secure request
  excluded_cookies = GetExcludedCookiesForURL(cm.get(), https_www_foo_.url(),
                                              CookiePartitionKeyCollection());
  iter = excluded_cookies.begin();

  EXPECT_TRUE(excluded_cookies.empty());
}

TEST_F(CookieMonsterTest, GetAllCookiesForURLPathMatching) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  CookieOptions options = CookieOptions::MakeAllInclusive();

  EXPECT_TRUE(CreateAndSetCookie(cm.get(), www_foo_foo_.url(),
                                 "A=B; path=/foo;", options));
  EXPECT_TRUE(CreateAndSetCookie(cm.get(), www_foo_bar_.url(),
                                 "C=D; path=/bar;", options));
  EXPECT_TRUE(
      CreateAndSetCookie(cm.get(), http_www_foo_.url(), "E=F;", options));

  CookieList cookies = GetAllCookiesForURL(cm.get(), www_foo_foo_.url());
  auto it = cookies.begin();

  ASSERT_TRUE(it != cookies.end());
  EXPECT_EQ("A", it->Name());
  EXPECT_EQ("/foo", it->Path());

  ASSERT_TRUE(++it != cookies.end());
  EXPECT_EQ("E", it->Name());
  EXPECT_EQ("/", it->Path());

  ASSERT_TRUE(++it == cookies.end());

  cookies = GetAllCookiesForURL(cm.get(), www_foo_bar_.url());
  it = cookies.begin();

  ASSERT_TRUE(it != cookies.end());
  EXPECT_EQ("C", it->Name());
  EXPECT_EQ("/bar", it->Path());

  ASSERT_TRUE(++it != cookies.end());
  EXPECT_EQ("E", it->Name());
  EXPECT_EQ("/", it->Path());

  ASSERT_TRUE(++it == cookies.end());
}

TEST_F(CookieMonsterTest, GetExcludedCookiesForURLPathMatching) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  CookieOptions options = CookieOptions::MakeAllInclusive();

  EXPECT_TRUE(CreateAndSetCookie(cm.get(), www_foo_foo_.url(),
                                 "A=B; path=/foo;", options));
  EXPECT_TRUE(CreateAndSetCookie(cm.get(), www_foo_bar_.url(),
                                 "C=D; path=/bar;", options));
  EXPECT_TRUE(
      CreateAndSetCookie(cm.get(), http_www_foo_.url(), "E=F;", options));

  CookieAccessResultList excluded_cookies = GetExcludedCookiesForURL(
      cm.get(), www_foo_foo_.url(), CookiePartitionKeyCollection());
  auto it = excluded_cookies.begin();

  ASSERT_TRUE(it != excluded_cookies.end());
  EXPECT_EQ("C", it->cookie.Name());
  EXPECT_EQ("/bar", it->cookie.Path());
  EXPECT_TRUE(it->access_result.status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_NOT_ON_PATH}));

  ASSERT_TRUE(++it == excluded_cookies.end());

  excluded_cookies = GetExcludedCookiesForURL(cm.get(), www_foo_bar_.url(),
                              
"""


```