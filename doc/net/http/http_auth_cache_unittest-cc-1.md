Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a unit test file for Chromium's `HttpAuthCache`.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Class:** The filename `http_auth_cache_unittest.cc` and the repeated use of `HttpAuthCache` strongly suggest this file tests the `HttpAuthCache` class.

2. **Recognize the Purpose of Unit Tests:** Unit tests verify the correct behavior of individual units of code (in this case, the `HttpAuthCache` class). The tests will demonstrate how the class functions under various conditions.

3. **Scan for Key Actions/Methods:** Look for the primary verbs and associated methods used in the tests. Common actions for a cache would include:
    * Adding entries (`cache.Add(...)`)
    * Retrieving entries (`cache.Lookup(...)`, `cache.LookupByPath(...)`)
    * Removing entries (`cache.Remove(...)`)
    * Clearing entries (`cache.ClearEntriesAddedBetween(...)`, `cache.ClearAllEntries()`)
    * Updating entries (`cache.UpdateStaleChallenge(...)`)
    * Copying entries (`second_cache.CopyProxyEntriesFrom(first_cache)`)

4. **Group Tests by Functionality:**  Organize the identified actions into logical groups. For example, all tests involving `cache.Add` and `cache.Lookup` relate to adding and retrieving entries.

5. **Analyze Specific Test Cases:**  Examine the `EXPECT_TRUE` and `EXPECT_FALSE` statements to understand the expected behavior in different scenarios. Pay attention to the parameters passed to the `HttpAuthCache` methods and the assertions made.

6. **Look for Edge Cases and Error Handling:** Notice the tests that explicitly check for failures (`EXPECT_FALSE`) when incorrect credentials or parameters are provided. This indicates testing for robustness and error handling.

7. **Consider Time-Based Operations:** The `ClearEntriesAddedBetween` tests and the use of `base::SimpleTestClock` indicate that the cache tracks the time of entry addition and supports clearing based on time ranges.

8. **Identify Specific Features:** Note any specialized functionalities like `UpdateStaleChallenge` (for handling stale authentication challenges) and `CopyProxyEntriesFrom` (for transferring proxy authentication entries).

9. **Address the JavaScript Question:**  Since the code is C++, there's no direct interaction with JavaScript at this level. However, recognize that the *purpose* of the `HttpAuthCache` is to store authentication credentials, which are relevant to web requests initiated by JavaScript running in a browser.

10. **Handle the "User Errors" Question:**  Identify scenarios where the tests intentionally simulate incorrect usage (e.g., wrong username, password, realm).

11. **Consider the "User Operation" for Debugging:** Think about how a user interacting with a website might trigger the need for authentication and thus involve the `HttpAuthCache`.

12. **Synthesize the Summary:**  Combine the observations into a concise description of the file's purpose and the functionalities it tests.

13. **Address the "Part 2" Request:**  Since this is part 2, assume the user has read the previous description and focus on summarizing the functionality covered *in this specific snippet*.

**Self-Correction/Refinement during the process:**

* Initially, I might have just listed the methods tested. However, realizing the user wants a *functional* description, I grouped the tests by the actions they demonstrate.
* I recognized the importance of explaining *why* certain tests pass or fail, connecting it back to the expected behavior of the `HttpAuthCache`.
* I made sure to explicitly state the lack of direct JavaScript interaction while acknowledging the conceptual link.
* I explicitly noted the testing of error conditions and provided examples.
* I focused the final summary on the functionalities showcased in the provided code *segment*, as requested by "Part 2".
好的，这是对提供的代码片段（`net/http/http_auth_cache_unittest.cc` 的第二部分）的功能归纳：

**代码片段功能归纳：**

这段代码延续了对 `HttpAuthCache` 类的单元测试，主要集中在以下功能点的测试：

1. **删除缓存条目 (`Remove`) 的多种情况：**  测试了成功删除指定认证缓存条目的场景，以及各种导致删除失败的情况，例如：
    * 不存在的 Realm
    * 错误的 Origin (SchemeHostPort)
    * 错误的用户名或密码
    * 错误的认证类型 (Scheme)
    * 尝试删除刚刚删除的条目
    * 针对同一 Origin 和 Realm 存在多种认证类型时，删除特定认证类型。

2. **根据添加时间范围清除缓存条目 (`ClearEntriesAddedBetween`)：**
    * 测试了根据指定的时间范围清除缓存条目的功能。
    * 验证了只有在指定时间范围内添加的条目才会被清除，而早于或晚于该时间范围的条目则不受影响。
    * 强调了清除操作是针对整个认证条目，而不是针对条目下的特定路径。
    * 测试了使用 URL 过滤器来限制清除范围，只清除特定 Host 的缓存条目。
    * 测试了使用 `base::Time::Min()` 和 `base::Time::Max()` 作为时间范围参数，即清除所有条目的情况。

3. **清除所有缓存条目 (`ClearAllEntries`)：**
    * 验证了可以清除缓存中的所有认证条目。

4. **更新过期的认证质询 (`UpdateStaleChallenge`)：**
    * 测试了当服务器返回 `stale=true` 的认证质询时，更新缓存中对应条目的功能。
    * 验证了成功更新后，缓存条目依然存在，并且与认证相关的计数器（nonce count）会被重置。
    * 测试了当缓存中不存在匹配的条目时，更新操作会失败。

5. **从另一个缓存复制代理认证条目 (`CopyProxyEntriesFrom`)：**
    * 测试了将一个 `HttpAuthCache` 中的代理认证条目复制到另一个 `HttpAuthCache` 的功能。
    * 验证了只有代理认证条目会被复制，服务器认证条目不会被复制。
    * 验证了复制操作会覆盖目标缓存中已存在的同 Origin、Realm 和 Scheme 的条目。
    * 验证了认证凭据和相关的计数器（nonce count）会被正确复制。
    * 验证了同一个认证条目下的所有路径都会被复制。

6. **缓存条目的驱逐策略（Eviction）：**
    * 使用 `HttpAuthCacheEvictionTest` 测试夹具测试了缓存的驱逐策略。
    * **Realm 条目驱逐：**  当缓存达到最大 Realm 条目数量时，新添加的 Realm 条目会按照最近最少使用 (LRU) 原则驱逐旧的 Realm 条目。
    * **路径驱逐：** 当一个 Realm 条目下的路径数量达到最大值时，新添加的路径会驱逐该 Realm 条目下最旧的路径。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不直接与 JavaScript 交互，但 `HttpAuthCache` 的功能对于基于 Web 的应用程序（包括使用 JavaScript 的应用程序）至关重要。

* **身份验证信息的存储和管理：** 当用户在网页上进行需要身份验证的操作时（例如登录），浏览器会将服务器返回的认证质询和用户的凭据存储在 `HttpAuthCache` 中。
* **自动身份验证：**  后续对相同域名的请求，浏览器会从 `HttpAuthCache` 中查找匹配的凭据，并自动添加到请求头中，无需用户再次输入用户名和密码，提升用户体验。
* **JavaScript 发起的请求：**  当 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起跨域或同域请求时，如果服务器需要身份验证，浏览器会利用 `HttpAuthCache` 中的信息来处理认证。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户访问需要身份验证的网站或资源：** 用户在浏览器地址栏输入 URL 或点击链接，尝试访问一个需要 HTTP 身份验证（例如 Basic 或 Digest 认证）的网页或资源。
2. **服务器返回 401 或 407 状态码：**  Web 服务器收到用户的请求后，发现用户未经过身份验证，会返回 HTTP 状态码 401 (Unauthorized，用于服务器认证) 或 407 (Proxy Authentication Required，用于代理认证)，并在响应头中包含 `WWW-Authenticate` 或 `Proxy-Authenticate` 字段，指明所需的认证方案和 Realm。
3. **浏览器接收到认证质询：** 浏览器接收到包含认证质询的响应头。
4. **浏览器提示用户输入凭据：** 如果 `HttpAuthCache` 中没有匹配的凭据，浏览器会弹出身份验证对话框，要求用户输入用户名和密码。
5. **用户输入凭据并提交：** 用户输入用户名和密码后，浏览器会根据认证方案对凭据进行编码，并添加到后续请求的 `Authorization` 或 `Proxy-Authorization` 头中。
6. **认证成功，凭据被缓存：** 如果服务器验证凭据成功，会返回 200 OK 等成功状态码。浏览器会将用户的凭据、认证方案、Realm 等信息添加到 `HttpAuthCache` 中。
7. **后续请求：**  当用户再次访问相同域名下需要相同认证的资源时，浏览器会在发送请求前检查 `HttpAuthCache`，找到匹配的凭据，并自动添加到请求头中，无需再次弹出身份验证对话框。

**假设输入与输出（针对 `Remove` 功能）：**

**假设输入：**

* `cache` 中已存在以下条目：
    * `http://foobar.com`, Server, "Realm1", Basic, `AuthCredentials("alice", "123")`
    * `http://foobar.com`, Server, "Realm2", Basic, `AuthCredentials("bob", "princess")`
* 调用 `cache.Remove(url::SchemeHostPort(GURL("http://foobar.com")), HttpAuth::AUTH_SERVER, "Realm1", HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(), AuthCredentials("alice", "123"));`

**预期输出：**

* `Remove` 方法返回 `true` (删除成功)。
* 再次调用 `cache.Lookup` 查询 `http://foobar.com`, Server, "Realm1", Basic，将返回 `nullptr`，表示该条目已被删除。
* `http://foobar.com`, Server, "Realm2", Basic 的条目仍然存在。

**用户或编程常见的使用错误举例：**

1. **在用户代码中错误地假设凭据始终存在：** 开发者可能会错误地认为只要用户登录过一次，凭据就永远存在于缓存中。但实际上，凭据可能会因为用户手动清除缓存、缓存策略过期、或者达到缓存容量限制而被移除。
   * **错误示例 (JavaScript):**
     ```javascript
     fetch('/api/protected-resource', {
       headers: {
         'Authorization': 'Basic ' + btoa('user:password') // 假设凭据始终为 'user:password'
       }
     });
     ```
   * **正确做法：**  依赖浏览器自动处理身份验证，或者在需要时提示用户重新登录。

2. **在测试环境中没有正确清理缓存：** 在自动化测试中，如果没有在测试用例之间或之后清理 `HttpAuthCache`，可能会导致测试结果相互影响，产生误报。

3. **错误地配置服务器认证：**  服务器配置不当，例如 Realm 设置不一致，可能导致浏览器无法正确缓存和使用凭据。

这段代码通过详尽的测试用例，确保了 `HttpAuthCache` 类的各个功能模块的正确性和健壮性，对于理解 Chromium 如何处理 HTTP 身份验证的缓存机制非常有帮助。

### 提示词
```
这是目录为net/http/http_auth_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
CIICredentials("bob", "princess"),
            "/");
  cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm3,
            HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
            "basic realm=Realm3", AuthCredentials(kAdmin, kPassword), "/");
  cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm3,
            HttpAuth::AUTH_SCHEME_DIGEST, NetworkAnonymizationKey(),
            "digest realm=Realm3", AuthCredentials(kRoot, kWileCoyote), "/");

  // Fails, because there is no realm "Realm5".
  EXPECT_FALSE(cache.Remove(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm5,
                            HttpAuth::AUTH_SCHEME_BASIC,
                            NetworkAnonymizationKey(),
                            AuthCredentials(kAlice, k123)));

  // Fails because the origin is wrong.
  EXPECT_FALSE(
      cache.Remove(url::SchemeHostPort(GURL("http://foobar2.com:100")),
                   HttpAuth::AUTH_SERVER, kRealm1, HttpAuth::AUTH_SCHEME_BASIC,
                   NetworkAnonymizationKey(), AuthCredentials(kAlice, k123)));

  // Fails because the username is wrong.
  EXPECT_FALSE(cache.Remove(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm1,
                            HttpAuth::AUTH_SCHEME_BASIC,
                            NetworkAnonymizationKey(),
                            AuthCredentials(kAlice2, k123)));

  // Fails because the password is wrong.
  EXPECT_FALSE(cache.Remove(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm1,
                            HttpAuth::AUTH_SCHEME_BASIC,
                            NetworkAnonymizationKey(),
                            AuthCredentials(kAlice, k1234)));

  // Fails because the authentication type is wrong.
  EXPECT_FALSE(cache.Remove(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm1,
                            HttpAuth::AUTH_SCHEME_DIGEST,
                            NetworkAnonymizationKey(),
                            AuthCredentials(kAlice, k123)));

  // Succeeds.
  EXPECT_TRUE(cache.Remove(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm1,
                           HttpAuth::AUTH_SCHEME_BASIC,
                           NetworkAnonymizationKey(),
                           AuthCredentials(kAlice, k123)));

  // Fails because we just deleted the entry!
  EXPECT_FALSE(cache.Remove(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm1,
                            HttpAuth::AUTH_SCHEME_BASIC,
                            NetworkAnonymizationKey(),
                            AuthCredentials(kAlice, k123)));

  // Succeed when there are two authentication types for the same origin,realm.
  EXPECT_TRUE(cache.Remove(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm3,
                           HttpAuth::AUTH_SCHEME_DIGEST,
                           NetworkAnonymizationKey(),
                           AuthCredentials(kRoot, kWileCoyote)));

  // Succeed as above, but when entries were added in opposite order
  cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm3,
            HttpAuth::AUTH_SCHEME_DIGEST, NetworkAnonymizationKey(),
            "digest realm=Realm3", AuthCredentials(kRoot, kWileCoyote), "/");
  EXPECT_TRUE(cache.Remove(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm3,
                           HttpAuth::AUTH_SCHEME_BASIC,
                           NetworkAnonymizationKey(),
                           AuthCredentials(kAdmin, kPassword)));

  // Make sure that removing one entry still leaves the other available for
  // lookup.
  HttpAuthCache::Entry* entry =
      cache.Lookup(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm3,
                   HttpAuth::AUTH_SCHEME_DIGEST, NetworkAnonymizationKey());
  EXPECT_FALSE(nullptr == entry);
}

TEST(HttpAuthCacheTest, ClearEntriesAddedBetween) {
  url::SchemeHostPort scheme_host_port(GURL("http://foobar.com"));

  base::Time start_time;
  ASSERT_TRUE(base::Time::FromString("30 May 2018 12:00:00", &start_time));
  base::SimpleTestClock test_clock;
  test_clock.SetNow(start_time);

  HttpAuthCache cache(false /* key_entries_by_network_anonymization_key */);
  cache.set_clock_for_testing(&test_clock);

  cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm1,
            HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
            "basic realm=Realm1", AuthCredentials(kAlice, k123), "/");
  cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm2,
            HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
            "basic realm=Realm2", AuthCredentials(kRoot, kWileCoyote), "/");

  test_clock.Advance(base::Seconds(10));  // Time now 12:00:10
  cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm3,
            HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
            "basic realm=Realm3", AuthCredentials(kAlice2, k1234), "/");
  cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm4,
            HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
            "basic realm=Realm4", AuthCredentials(kUsername, kPassword), "/");
  // Add path to existing entry.
  cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm2,
            HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
            "basic realm=Realm2", AuthCredentials(kAdmin, kPassword), "/baz/");

  test_clock.Advance(base::Seconds(10));  // Time now 12:00:20
  cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm5,
            HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
            "basic realm=Realm5", AuthCredentials(kAlice3, k12345), "/");

  base::Time test_time1;
  ASSERT_TRUE(base::Time::FromString("30 May 2018 12:00:05", &test_time1));
  base::Time test_time2;
  ASSERT_TRUE(base::Time::FromString("30 May 2018 12:00:15", &test_time2));
  cache.ClearEntriesAddedBetween(test_time1, test_time2,
                                 base::RepeatingCallback<bool(const GURL&)>());

  // Realms 1 and 2 are older than 12:00:05 and should not be cleared
  EXPECT_NE(nullptr, cache.Lookup(scheme_host_port, HttpAuth::AUTH_SERVER,
                                  kRealm1, HttpAuth::AUTH_SCHEME_BASIC,
                                  NetworkAnonymizationKey()));
  EXPECT_NE(nullptr, cache.Lookup(scheme_host_port, HttpAuth::AUTH_SERVER,
                                  kRealm2, HttpAuth::AUTH_SCHEME_BASIC,
                                  NetworkAnonymizationKey()));

  // Realms 5 is newer than 12:00:15 and should not be cleared
  EXPECT_NE(nullptr, cache.Lookup(scheme_host_port, HttpAuth::AUTH_SERVER,
                                  kRealm5, HttpAuth::AUTH_SCHEME_BASIC,
                                  NetworkAnonymizationKey()));

  // Creation time is set for a whole entry rather than for a particular path.
  // Path added within the requested duration isn't be removed.
  EXPECT_NE(nullptr, cache.LookupByPath(scheme_host_port, HttpAuth::AUTH_SERVER,
                                        NetworkAnonymizationKey(), "/baz/"));

  // Realms 3 and 4 are between 12:00:05 and 12:00:10 and should be cleared.
  EXPECT_EQ(nullptr, cache.Lookup(scheme_host_port, HttpAuth::AUTH_SERVER,
                                  kRealm3, HttpAuth::AUTH_SCHEME_BASIC,
                                  NetworkAnonymizationKey()));
  EXPECT_EQ(nullptr, cache.Lookup(scheme_host_port, HttpAuth::AUTH_SERVER,
                                  kRealm4, HttpAuth::AUTH_SCHEME_BASIC,
                                  NetworkAnonymizationKey()));

  cache.ClearEntriesAddedBetween(start_time - base::Seconds(1),
                                 base::Time::Max(),
                                 base::RepeatingCallback<bool(const GURL&)>());
  EXPECT_EQ(nullptr, cache.Lookup(scheme_host_port, HttpAuth::AUTH_SERVER,
                                  kRealm1, HttpAuth::AUTH_SCHEME_BASIC,
                                  NetworkAnonymizationKey()));
  EXPECT_EQ(nullptr, cache.Lookup(scheme_host_port, HttpAuth::AUTH_SERVER,
                                  kRealm2, HttpAuth::AUTH_SCHEME_BASIC,
                                  NetworkAnonymizationKey()));
  EXPECT_EQ(nullptr, cache.LookupByPath(scheme_host_port, HttpAuth::AUTH_SERVER,
                                        NetworkAnonymizationKey(), "/baz/"));
}

TEST(HttpAuthCacheTest, ClearEntriesAddedBetweenByFilter) {
  url::SchemeHostPort scheme_host_port_1(GURL("http://foobar.com"));
  url::SchemeHostPort scheme_host_port_2(GURL("http://foobar2.com"));

  base::SimpleTestClock test_clock;
  test_clock.SetNow(base::Time::Now());

  HttpAuthCache cache(false /* key_entries_by_network_anonymization_key */);
  cache.set_clock_for_testing(&test_clock);

  cache.Add(scheme_host_port_1, HttpAuth::AUTH_SERVER, kRealm1,
            HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
            "basic realm=Realm1", AuthCredentials(kAlice, k123), "/");
  cache.Add(scheme_host_port_2, HttpAuth::AUTH_SERVER, kRealm1,
            HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
            "basic realm=Realm1", AuthCredentials(kRoot, kWileCoyote), "/");

  cache.ClearEntriesAddedBetween(
      base::Time::Min(), base::Time::Max(),
      base::BindRepeating(&DoesUrlMatchFilter,
                          std::set<std::string>({scheme_host_port_1.host()})));

  // Only foobar.com should be cleared while foobar2.com remains.
  EXPECT_EQ(nullptr, cache.Lookup(scheme_host_port_1, HttpAuth::AUTH_SERVER,
                                  kRealm1, HttpAuth::AUTH_SCHEME_BASIC,
                                  NetworkAnonymizationKey()));
  EXPECT_NE(nullptr, cache.Lookup(scheme_host_port_2, HttpAuth::AUTH_SERVER,
                                  kRealm1, HttpAuth::AUTH_SCHEME_BASIC,
                                  NetworkAnonymizationKey()));
}

TEST(HttpAuthCacheTest, ClearEntriesAddedBetweenWithAllTimeValues) {
  url::SchemeHostPort scheme_host_port(GURL("http://foobar.com"));

  base::SimpleTestClock test_clock;
  test_clock.SetNow(base::Time::Now());

  HttpAuthCache cache(false /* key_entries_by_network_anonymization_key */);
  cache.set_clock_for_testing(&test_clock);

  cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm1,
            HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
            "basic realm=Realm1", AuthCredentials(kAlice, k123), "/");
  cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm2,
            HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
            "basic realm=Realm2", AuthCredentials(kRoot, kWileCoyote), "/");

  test_clock.Advance(base::Seconds(10));
  cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm3,
            HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
            "basic realm=Realm3", AuthCredentials(kAlice2, k1234), "/");
  cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm4,
            HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
            "basic realm=Realm4", AuthCredentials(kUsername, kPassword), "/");
  // Add path to existing entry.
  cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm2,
            HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
            "basic realm=Realm2", AuthCredentials(kAdmin, kPassword), "/baz/");

  cache.ClearEntriesAddedBetween(base::Time::Min(), base::Time::Max(),
                                 base::RepeatingCallback<bool(const GURL&)>());

  // All entries should be cleared.
  EXPECT_EQ(nullptr, cache.Lookup(scheme_host_port, HttpAuth::AUTH_SERVER,
                                  kRealm1, HttpAuth::AUTH_SCHEME_BASIC,
                                  NetworkAnonymizationKey()));
  EXPECT_EQ(nullptr, cache.Lookup(scheme_host_port, HttpAuth::AUTH_SERVER,
                                  kRealm2, HttpAuth::AUTH_SCHEME_BASIC,
                                  NetworkAnonymizationKey()));
  EXPECT_EQ(nullptr, cache.LookupByPath(scheme_host_port, HttpAuth::AUTH_SERVER,
                                        NetworkAnonymizationKey(), "/baz/"));
  EXPECT_EQ(nullptr, cache.Lookup(scheme_host_port, HttpAuth::AUTH_SERVER,
                                  kRealm3, HttpAuth::AUTH_SCHEME_BASIC,
                                  NetworkAnonymizationKey()));
  EXPECT_EQ(nullptr, cache.Lookup(scheme_host_port, HttpAuth::AUTH_SERVER,
                                  kRealm4, HttpAuth::AUTH_SCHEME_BASIC,
                                  NetworkAnonymizationKey()));
}

TEST(HttpAuthCacheTest, ClearAllEntries) {
  url::SchemeHostPort scheme_host_port(GURL("http://foobar.com"));

  base::SimpleTestClock test_clock;
  test_clock.SetNow(base::Time::Now());

  HttpAuthCache cache(false /* key_entries_by_network_anonymization_key */);
  cache.set_clock_for_testing(&test_clock);

  cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm1,
            HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
            "basic realm=Realm1", AuthCredentials(kAlice, k123), "/");
  cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm2,
            HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
            "basic realm=Realm2", AuthCredentials(kRoot, kWileCoyote), "/");

  test_clock.Advance(base::Seconds(10));
  cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm3,
            HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
            "basic realm=Realm3", AuthCredentials(kAlice2, k1234), "/");
  cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm4,
            HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
            "basic realm=Realm4", AuthCredentials(kUsername, kPassword), "/");
  // Add path to existing entry.
  cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm2,
            HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
            "basic realm=Realm2", AuthCredentials(kAdmin, kPassword), "/baz/");

  test_clock.Advance(base::Seconds(55));
  cache.ClearAllEntries();

  // All entries should be cleared.
  EXPECT_EQ(nullptr, cache.Lookup(scheme_host_port, HttpAuth::AUTH_SERVER,
                                  kRealm1, HttpAuth::AUTH_SCHEME_BASIC,
                                  NetworkAnonymizationKey()));
  EXPECT_EQ(nullptr, cache.Lookup(scheme_host_port, HttpAuth::AUTH_SERVER,
                                  kRealm2, HttpAuth::AUTH_SCHEME_BASIC,
                                  NetworkAnonymizationKey()));
  EXPECT_EQ(nullptr, cache.LookupByPath(scheme_host_port, HttpAuth::AUTH_SERVER,
                                        NetworkAnonymizationKey(), "/baz/"));
  EXPECT_EQ(nullptr, cache.Lookup(scheme_host_port, HttpAuth::AUTH_SERVER,
                                  kRealm3, HttpAuth::AUTH_SCHEME_BASIC,
                                  NetworkAnonymizationKey()));
  EXPECT_EQ(nullptr, cache.Lookup(scheme_host_port, HttpAuth::AUTH_SERVER,
                                  kRealm4, HttpAuth::AUTH_SCHEME_BASIC,
                                  NetworkAnonymizationKey()));
}

TEST(HttpAuthCacheTest, UpdateStaleChallenge) {
  HttpAuthCache cache(false /* key_entries_by_network_anonymization_key */);
  url::SchemeHostPort scheme_host_port(GURL("http://foobar2.com"));
  HttpAuthCache::Entry* entry_pre = cache.Add(
      scheme_host_port, HttpAuth::AUTH_SERVER, kRealm1,
      HttpAuth::AUTH_SCHEME_DIGEST, NetworkAnonymizationKey(),
      "Digest realm=Realm1,"
      "nonce=\"s3MzvFhaBAA=4c520af5acd9d8d7ae26947529d18c8eae1e98f4\"",
      CreateASCIICredentials("realm-digest-user", "realm-digest-password"),
      "/baz/index.html");
  ASSERT_TRUE(entry_pre != nullptr);

  EXPECT_EQ(2, entry_pre->IncrementNonceCount());
  EXPECT_EQ(3, entry_pre->IncrementNonceCount());
  EXPECT_EQ(4, entry_pre->IncrementNonceCount());

  bool update_success = cache.UpdateStaleChallenge(
      scheme_host_port, HttpAuth::AUTH_SERVER, kRealm1,
      HttpAuth::AUTH_SCHEME_DIGEST, NetworkAnonymizationKey(),
      "Digest realm=Realm1,"
      "nonce=\"claGgoRXBAA=7583377687842fdb7b56ba0555d175baa0b800e3\","
      "stale=\"true\"");
  EXPECT_TRUE(update_success);

  // After the stale update, the entry should still exist in the cache and
  // the nonce count should be reset to 0.
  HttpAuthCache::Entry* entry_post =
      cache.Lookup(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm1,
                   HttpAuth::AUTH_SCHEME_DIGEST, NetworkAnonymizationKey());
  ASSERT_TRUE(entry_post != nullptr);
  EXPECT_EQ(2, entry_post->IncrementNonceCount());

  // UpdateStaleChallenge will fail if an entry doesn't exist in the cache.
  bool update_failure = cache.UpdateStaleChallenge(
      scheme_host_port, HttpAuth::AUTH_SERVER, kRealm2,
      HttpAuth::AUTH_SCHEME_DIGEST, NetworkAnonymizationKey(),
      "Digest realm=Realm2,"
      "nonce=\"claGgoRXBAA=7583377687842fdb7b56ba0555d175baa0b800e3\","
      "stale=\"true\"");
  EXPECT_FALSE(update_failure);
}

TEST(HttpAuthCacheTest, CopyProxyEntriesFrom) {
  url::SchemeHostPort scheme_host_port(GURL("http://example.com"));
  std::string path("/some/path");
  std::string another_path("/another/path");

  HttpAuthCache first_cache(
      false /* key_entries_by_network_anonymization_key */);
  HttpAuthCache::Entry* entry;

  first_cache.Add(scheme_host_port, HttpAuth::AUTH_PROXY, kRealm1,
                  HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
                  "basic realm=Realm1", AuthCredentials(kAlice, k123), path);
  first_cache.Add(scheme_host_port, HttpAuth::AUTH_PROXY, kRealm2,
                  HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
                  "basic realm=Realm2", AuthCredentials(kAlice2, k1234), path);
  first_cache.Add(scheme_host_port, HttpAuth::AUTH_PROXY, kRealm3,
                  HttpAuth::AUTH_SCHEME_DIGEST, NetworkAnonymizationKey(),
                  "digest realm=Realm3", AuthCredentials(kRoot, kWileCoyote),
                  path);
  entry = first_cache.Add(scheme_host_port, HttpAuth::AUTH_PROXY, kRealm3,
                          HttpAuth::AUTH_SCHEME_DIGEST,
                          NetworkAnonymizationKey(), "digest realm=Realm3",
                          AuthCredentials(kRoot, kWileCoyote), another_path);

  EXPECT_EQ(2, entry->IncrementNonceCount());

  // Server entry, which should not be copied.
  first_cache.Add(scheme_host_port, HttpAuth::AUTH_SERVER, kRealm1,
                  HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
                  "basic realm=Realm1", AuthCredentials(kAlice, k123), path);

  HttpAuthCache second_cache(
      false /* key_entries_by_network_anonymization_key */);
  // Will be overwritten by kRoot:kWileCoyote.
  second_cache.Add(scheme_host_port, HttpAuth::AUTH_PROXY, kRealm3,
                   HttpAuth::AUTH_SCHEME_DIGEST, NetworkAnonymizationKey(),
                   "digest realm=Realm3", AuthCredentials(kAlice2, k1234),
                   path);
  // Should be left intact.
  second_cache.Add(scheme_host_port, HttpAuth::AUTH_PROXY, kRealm4,
                   HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
                   "basic realm=Realm4", AuthCredentials(kAdmin, kRoot), path);

  second_cache.CopyProxyEntriesFrom(first_cache);

  // Copied from first_cache.
  entry = second_cache.Lookup(scheme_host_port, HttpAuth::AUTH_PROXY, kRealm1,
                              HttpAuth::AUTH_SCHEME_BASIC,
                              NetworkAnonymizationKey());
  EXPECT_TRUE(nullptr != entry);
  EXPECT_EQ(kAlice, entry->credentials().username());
  EXPECT_EQ(k123, entry->credentials().password());

  // Copied from first_cache.
  entry = second_cache.Lookup(scheme_host_port, HttpAuth::AUTH_PROXY, kRealm2,
                              HttpAuth::AUTH_SCHEME_BASIC,
                              NetworkAnonymizationKey());
  EXPECT_TRUE(nullptr != entry);
  EXPECT_EQ(kAlice2, entry->credentials().username());
  EXPECT_EQ(k1234, entry->credentials().password());

  // Overwritten from first_cache.
  entry = second_cache.Lookup(scheme_host_port, HttpAuth::AUTH_PROXY, kRealm3,
                              HttpAuth::AUTH_SCHEME_DIGEST,
                              NetworkAnonymizationKey());
  EXPECT_TRUE(nullptr != entry);
  EXPECT_EQ(kRoot, entry->credentials().username());
  EXPECT_EQ(kWileCoyote, entry->credentials().password());
  // Nonce count should get copied.
  EXPECT_EQ(3, entry->IncrementNonceCount());

  // All paths should get copied.
  entry = second_cache.LookupByPath(scheme_host_port, HttpAuth::AUTH_PROXY,
                                    NetworkAnonymizationKey(), another_path);
  EXPECT_TRUE(nullptr != entry);
  EXPECT_EQ(kRoot, entry->credentials().username());
  EXPECT_EQ(kWileCoyote, entry->credentials().password());

  // Left intact in second_cache.
  entry = second_cache.Lookup(scheme_host_port, HttpAuth::AUTH_PROXY, kRealm4,
                              HttpAuth::AUTH_SCHEME_BASIC,
                              NetworkAnonymizationKey());
  EXPECT_TRUE(nullptr != entry);
  EXPECT_EQ(kAdmin, entry->credentials().username());
  EXPECT_EQ(kRoot, entry->credentials().password());

  // AUTH_SERVER entry should not have been copied from first_cache.
  EXPECT_TRUE(first_cache.Lookup(scheme_host_port, HttpAuth::AUTH_SERVER,
                                 kRealm1, HttpAuth::AUTH_SCHEME_BASIC,
                                 NetworkAnonymizationKey()));
  EXPECT_FALSE(second_cache.Lookup(scheme_host_port, HttpAuth::AUTH_SERVER,
                                   kRealm1, HttpAuth::AUTH_SCHEME_BASIC,
                                   NetworkAnonymizationKey()));
}

// Test fixture class for eviction tests (contains helpers for bulk
// insertion and existence testing).
class HttpAuthCacheEvictionTest : public testing::Test {
 protected:
  HttpAuthCacheEvictionTest()
      : scheme_host_port_(GURL("http://www.google.com")),
        cache_(false /* key_entries_by_network_anonymization_key */) {}

  std::string GenerateRealm(int realm_i) {
    return base::StringPrintf("Realm %d", realm_i);
  }

  std::string GeneratePath(int realm_i, int path_i) {
    return base::StringPrintf("/%d/%d/x/y", realm_i, path_i);
  }

  void AddRealm(int realm_i) {
    AddPathToRealm(realm_i, 0);
  }

  void AddPathToRealm(int realm_i, int path_i) {
    cache_.Add(scheme_host_port_, HttpAuth::AUTH_SERVER, GenerateRealm(realm_i),
               HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
               std::string(), AuthCredentials(kUsername, kPassword),
               GeneratePath(realm_i, path_i));
  }

  void CheckRealmExistence(int realm_i, bool exists) {
    const HttpAuthCache::Entry* entry = cache_.Lookup(
        scheme_host_port_, HttpAuth::AUTH_SERVER, GenerateRealm(realm_i),
        HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey());
    if (exists) {
      EXPECT_FALSE(entry == nullptr);
      EXPECT_EQ(GenerateRealm(realm_i), entry->realm());
    } else {
      EXPECT_TRUE(entry == nullptr);
    }
  }

  void CheckPathExistence(int realm_i, int path_i, bool exists) {
    const HttpAuthCache::Entry* entry = cache_.LookupByPath(
        scheme_host_port_, HttpAuth::AUTH_SERVER, NetworkAnonymizationKey(),
        GeneratePath(realm_i, path_i));
    if (exists) {
      EXPECT_FALSE(entry == nullptr);
      EXPECT_EQ(GenerateRealm(realm_i), entry->realm());
    } else {
      EXPECT_TRUE(entry == nullptr);
    }
  }

  url::SchemeHostPort scheme_host_port_;
  HttpAuthCache cache_;

  static const int kMaxPaths = HttpAuthCache::kMaxNumPathsPerRealmEntry;
  static const int kMaxRealms = HttpAuthCache::kMaxNumRealmEntries;
};

// Add the maxinim number of realm entries to the cache. Each of these entries
// must still be retrievable. Next add three more entries -- since the cache is
// full this causes FIFO eviction of the first three entries by time of last
// use.
TEST_F(HttpAuthCacheEvictionTest, RealmEntryEviction) {
  base::SimpleTestTickClock test_clock;
  test_clock.SetNowTicks(base::TimeTicks::Now());
  cache_.set_tick_clock_for_testing(&test_clock);

  for (int i = 0; i < kMaxRealms; ++i) {
    AddRealm(i);
    test_clock.Advance(base::Seconds(1));
  }

  for (int i = 0; i < kMaxRealms; ++i) {
    CheckRealmExistence(i, true);
    test_clock.Advance(base::Seconds(1));
  }

  for (int i = 0; i < 3; ++i) {
    AddRealm(i + kMaxRealms);
    test_clock.Advance(base::Seconds(1));
  }

  for (int i = 0; i < 3; ++i) {
    CheckRealmExistence(i, false);
    test_clock.Advance(base::Seconds(1));
  }

  for (int i = 0; i < kMaxRealms; ++i) {
    CheckRealmExistence(i + 3, true);
    test_clock.Advance(base::Seconds(1));
  }

  cache_.set_tick_clock_for_testing(nullptr);
}

// Add the maximum number of paths to a single realm entry. Each of these
// paths should be retrievable. Next add 3 more paths -- since the cache is
// full this causes FIFO eviction of the first three paths.
TEST_F(HttpAuthCacheEvictionTest, RealmPathEviction) {
  for (int i = 0; i < kMaxPaths; ++i)
    AddPathToRealm(0, i);

  for (int i = 1; i < kMaxRealms; ++i)
    AddRealm(i);

  for (int i = 0; i < 3; ++i)
    AddPathToRealm(0, i + kMaxPaths);

  for (int i = 0; i < 3; ++i)
    CheckPathExistence(0, i, false);

  for (int i = 0; i < kMaxPaths; ++i)
    CheckPathExistence(0, i + 3, true);

  for (int i = 0; i < kMaxRealms; ++i)
    CheckRealmExistence(i, true);
}

}  // namespace net
```