Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's `cookie_monster_unittest.cc`. I need to identify the key functionalities being tested in this specific section. The code primarily focuses on testing the cookie eviction logic based on priority and security status.

Here's a breakdown of the code's function:

1. **Priority-Aware Garbage Collection Tests:** The `TestPriorityAwareGarbageCollectHelperSame()` and `TestPriorityAwareGarbageCollectHelperMixed()` functions test how the `CookieMonster` evicts cookies when the maximum number of cookies per domain is exceeded. The eviction logic prioritizes keeping higher priority cookies (High > Medium > Low). It also considers whether a cookie is secure.

2. **Test Cases with Specific Scenarios:** The code uses helper functions like `TestPriorityCookieCase` to set up various scenarios with different combinations of cookie priorities (Low, Medium, High), security status (secure/non-secure), and quantities.

3. **Assertions on Eviction:**  Each test case asserts the expected number of cookies remaining for each priority level (Low Non-secure, Low Secure, Medium Non-secure, Medium Secure, High Non-secure, High Secure) after the garbage collection process.

4. **Deferred Cookie Task Tests:**  The `DeferredCookieTaskTest` suite verifies that asynchronous cookie operations (like getting, setting, deleting cookies) on an uninitialized cookie store are correctly deferred until the store is loaded. It checks the order of execution of these deferred tasks.

5. **Individual Cookie Management Tests:** The `TEST_F(CookieMonsterTest, ...)` blocks test individual functionalities like deleting all cookies, deleting cookies within a specific time range, and deleting specific cookies.

6. **Mocking for Testing:** The code uses `MockPersistentCookieStore` to simulate the persistent storage of cookies, allowing for controlled testing of the `CookieMonster`'s interaction with the storage layer.

Now, let's organize this information into a concise summary addressing the user's requests.
这是 `net/cookies/cookie_monster_unittest.cc` 文件的一部分，主要功能是**测试 `CookieMonster` 类的 cookie 管理和垃圾回收机制，特别是针对 cookie 优先级和安全性的策略。**

**功能归纳：**

* **测试基于优先级的 Cookie 垃圾回收 (Garbage Collection)：**
    * 验证当 cookie 数量超过域的限制时，`CookieMonster` 如何根据 cookie 的优先级（Low, Medium, High）进行删除。
    * 包含仅有相同安全级别的 cookie (非 secure 或 secure) 的测试用例 (`TestPriorityAwareGarbageCollectHelperSame`)。
    * 包含混合安全级别 cookie 的测试用例 (`TestPriorityAwareGarbageCollectHelperMixed`)，验证 secure cookie 在同等或更低优先级下优先被保留。
* **测试异步 Cookie 操作的延迟执行 (Deferred Cookie Task)：**
    * 验证在 `CookieMonster` 初始化完成之前，异步的 cookie 操作（例如 `GetCookieListWithOptionsAsync`, `SetCanonicalCookieAsync`, `DeleteAllAsync` 等）会被正确地延迟执行，直到 cookie 存储加载完毕。
    * 验证延迟任务的执行顺序。
* **测试各种 Cookie 管理操作：**
    * `TestCookieDeleteAll`: 测试删除所有 cookie 的功能。
    * `TestCookieDeleteAllCreatedInTimeRangeTimestamps`: 测试删除在指定时间范围内创建的 cookie 的功能。

**与 JavaScript 功能的关系：**

虽然这段 C++ 代码本身不直接涉及 JavaScript，但它测试的 `CookieMonster` 类是浏览器网络栈中管理 HTTP Cookie 的核心组件。JavaScript 通过 `document.cookie` API 与浏览器交互，读取、设置和删除 cookie。

**举例说明：**

* 当 JavaScript 使用 `document.cookie = "mycookie=value"` 设置一个 cookie 时，浏览器底层会调用 `CookieMonster` 的相关方法来处理这个请求，包括存储 cookie、检查 cookie 限制等。
* 当 JavaScript 使用 `document.cookie` 读取 cookie 时，浏览器会调用 `CookieMonster` 的方法来获取符合当前上下文的 cookie 列表。
* `CookieMonster` 的垃圾回收机制影响着 JavaScript 能访问到的 cookie 集合。如果某个 cookie 因为优先级较低或超过了数量限制而被 `CookieMonster` 删除，JavaScript 就无法再通过 `document.cookie` 访问到它。

**逻辑推理、假设输入与输出：**

在 `TestPriorityCookieCase` 函数中，代码模拟了添加不同数量和优先级的 cookie，并断言在垃圾回收后剩余的各种优先级 cookie 的数量。

**假设输入 (以 `TestPriorityCookieCase(cm.get(), "181LS", 150U, 0U, 0U, 0U, 150U)` 为例):**

* `cm.get()`: 一个 `CookieMonster` 实例。
* `"181LS"`:  表示添加 181 个 Low 优先级的 Secure cookie (LS)。
* `150U`: 预期剩余的 Low 优先级 Non-secure cookie 数量 (这里是 0，因为只添加了 Secure cookie)。
* `0U`: 预期剩余的 Low 优先级 Secure cookie 数量。
* `0U`: 预期剩余的 Medium 优先级 Non-secure cookie 数量。
* `0U`: 预期剩余的 Medium 优先级 Secure cookie 数量。
* `150U`: 预期剩余的 High 优先级 Non-secure cookie 数量 (这里是 0)。
* `150U`: 预期剩余的 High 优先级 Secure cookie 数量 (这里是 0)。

**预期输出:**

由于每个域的最大 cookie 数量是 180，添加 181 个 Low 优先级的 Secure cookie 会触发垃圾回收，删除 31 个 cookie (181 - 150)。由于只添加了 Low 优先级的 Secure cookie，所以预期剩余 Low 优先级 Secure cookie 的数量是 150，其他优先级的 cookie 数量为 0。

**用户或编程常见的使用错误：**

* **过度依赖 cookie 存储大量数据：**  浏览器对每个域的 cookie 数量和大小都有限制。如果网站尝试存储过多 cookie，`CookieMonster` 的垃圾回收机制可能会删除一些 cookie，导致数据丢失或功能异常。
* **不理解 cookie 的优先级：** 开发者可能认为重要的 cookie 会一直存在，但如果未正确设置 cookie 的优先级，当 cookie 数量达到限制时，这些 cookie 可能会被优先删除。
* **在异步操作完成前假设 cookie 已存在：** 在 `DeferredCookieTaskTest` 中体现了这一点。在 cookie 存储加载完成前，尝试读取或操作 cookie 可能会得到不一致的结果。

**用户操作到达此处的调试线索：**

1. **用户访问一个网站：** 当用户在浏览器中输入网址或点击链接访问一个网站时。
2. **网站设置 Cookie：** 网站的服务器或 JavaScript 代码通过 HTTP 响应头或 `document.cookie` API 尝试设置 cookie。
3. **Cookie 数量达到限制：** 如果为该域名设置的 cookie 数量超过了浏览器的限制（`CookieMonster::kDomainMaxCookies`），`CookieMonster` 会启动垃圾回收过程。
4. **垃圾回收触发测试：**  `cookie_monster_unittest.cc` 中的测试用例模拟了这种 cookie 数量超限的情况，并验证 `CookieMonster` 的垃圾回收逻辑是否符合预期。开发者可以通过运行这些单元测试来确保 cookie 管理的正确性。

**总结第 2 部分的功能：**

这段代码主要测试了 `CookieMonster` 类在 cookie 数量达到上限时，如何根据 cookie 的优先级和安全性进行智能的删除，以及在 cookie 存储未加载完成时，如何正确地处理和延迟异步的 cookie 操作。这是为了保证浏览器能够有效地管理 cookie，避免因 cookie 数量过多而导致的问题，并确保异步操作的正确性。

### 提示词
```
这是目录为net/cookies/cookie_monster_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
EQ(180U, CookieMonster::kDomainMaxCookies);
    DCHECK_EQ(150U, CookieMonster::kDomainMaxCookies -
                        CookieMonster::kDomainPurgeCookies);

    auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());
    // Key:
    // Round 1 => LN; round 2 => LS; round 3 => MN.
    // Round 4 => HN; round 5 => MS; round 6 => HS

    // Each test case adds 181 cookies, so 31 cookies are evicted.
    // Cookie same priority, repeated for each priority.
    // Round 1 => 31L; round2 => none; round 3 => none.
    TestPriorityCookieCase(cm.get(), "181LS", 150U, 0U, 0U, 0U, 150U);
    // Round 1 => none; round2 => 31M; round 3 => none.
    TestPriorityCookieCase(cm.get(), "181MS", 0U, 150U, 0U, 0U, 150U);
    // Round 1 => none; round2 => none; round 3 => 31H.
    TestPriorityCookieCase(cm.get(), "181HS", 0U, 0U, 150U, 0U, 150U);

    // Pairwise scenarios.
    // Round 1 => none; round2 => 31M; round 3 => none.
    TestPriorityCookieCase(cm.get(), "10HS 171MS", 0U, 140U, 10U, 0U, 150U);
    // Round 1 => 10L; round2 => 21M; round 3 => none.
    TestPriorityCookieCase(cm.get(), "141MS 40LS", 30U, 120U, 0U, 0U, 150U);
    // Round 1 => none; round2 => 30M; round 3 => 1H.
    TestPriorityCookieCase(cm.get(), "101HS 80MS", 0U, 50U, 100U, 0U, 150U);

    // For {low, medium} priorities right on quota, different orders.
    // Round 1 => 1L; round 2 => none, round3 => 30H.
    TestPriorityCookieCase(cm.get(), "31LS 50MS 100HS", 30U, 50U, 70U, 0U,
                           150U);
    // Round 1 => none; round 2 => 1M, round3 => 30H.
    TestPriorityCookieCase(cm.get(), "51MS 100HS 30LS", 30U, 50U, 70U, 0U,
                           150U);
    // Round 1 => none; round 2 => none; round3 => 31H.
    TestPriorityCookieCase(cm.get(), "101HS 50MS 30LS", 30U, 50U, 70U, 0U,
                           150U);

    // Round 1 => 10L; round 2 => 10M; round3 => 11H.
    TestPriorityCookieCase(cm.get(), "81HS 60MS 40LS", 30U, 50U, 70U, 0U, 150U);

    // More complex scenarios.
    // Round 1 => 10L; round 2 => 10M; round 3 => 11H.
    TestPriorityCookieCase(cm.get(), "21HS 60MS 40LS 60HS", 30U, 50U, 70U, 0U,
                           150U);
    // Round 1 => 10L; round 2 => 21M; round 3 => none.
    TestPriorityCookieCase(cm.get(), "11HS 10MS 20LS 110MS 20LS 10HS", 30U, 99U,
                           21U, 0U, 150U);
    // Round 1 => none; round 2 => none; round 3 => 31H.
    TestPriorityCookieCase(cm.get(), "11LS 10MS 140HS 10MS 10LS", 21U, 20U,
                           109U, 0U, 150U);
    // Round 1 => none; round 2 => 21M; round 3 => 10H.
    TestPriorityCookieCase(cm.get(), "11MS 10HS 10LS 60MS 90HS", 10U, 50U, 90U,
                           0U, 150U);
    // Round 1 => none; round 2 => 31M; round 3 => none.
    TestPriorityCookieCase(cm.get(), "11MS 10HS 10LS 90MS 60HS", 10U, 70U, 70U,
                           0U, 150U);
  }

  void TestPriorityAwareGarbageCollectHelperMixed() {
    // Hard-coding limits in the test, but use DCHECK_EQ to enforce constraint.
    DCHECK_EQ(180U, CookieMonster::kDomainMaxCookies);
    DCHECK_EQ(150U, CookieMonster::kDomainMaxCookies -
                        CookieMonster::kDomainPurgeCookies);

    auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());
    // Key:
    // Round 1 => LN; round 2 => LS; round 3 => MN.
    // Round 4 => HN; round 5 => MS; round 6 => HS

    // Each test case adds 180 secure cookies, and some non-secure cookie. The
    // secure cookies take priority, so the non-secure cookie is removed, along
    // with 30 secure cookies. Repeated for each priority, and with the
    // non-secure cookie as older and newer.
    // Round 1 => 1LN; round 2 => 30LS; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "1LN 180LS", 150U, 0U, 0U, 0U, 150U);
    // Round 1 => none; round 2 => none; round 3 => 1MN.
    // Round 4 => none; round 5 => 30MS; round 6 => none.
    TestPriorityCookieCase(cm.get(), "1MN 180MS", 0U, 150U, 0U, 0U, 150U);
    // Round 1 => none; round 2 => none; round 3 => none.
    // Round 4 => 1HN; round 5 => none; round 6 => 30HS.
    TestPriorityCookieCase(cm.get(), "1HN 180HS", 0U, 0U, 150U, 0U, 150U);
    // Round 1 => 1LN; round 2 => 30LS; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "180LS 1LN", 150U, 0U, 0U, 0U, 150U);
    // Round 1 => none; round 2 => none; round 3 => 1MN.
    // Round 4 => none; round 5 => 30MS; round 6 => none.
    TestPriorityCookieCase(cm.get(), "180MS 1MN", 0U, 150U, 0U, 0U, 150U);
    // Round 1 => none; round 2 => none; round 3 => none.
    // Round 4 => 1HN; round 5 => none; round 6 => 30HS.
    TestPriorityCookieCase(cm.get(), "180HS 1HN", 0U, 0U, 150U, 0U, 150U);

    // Quotas should be correctly maintained when a given priority has both
    // secure and non-secure cookies.
    //
    // Round 1 => 10LN; round 2 => none; round 3 => none.
    // Round 4 => 21HN; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "39LN 1LS 141HN", 30U, 0U, 120U, 149U, 1U);
    // Round 1 => none; round 2 => none; round 3 => 10MN.
    // Round 4 => none; round 5 => none; round 6 => 21HS.
    TestPriorityCookieCase(cm.get(), "29LN 1LS 59MN 1MS 91HS", 30U, 50U, 70U,
                           78U, 72U);

    // Low-priority secure cookies are removed before higher priority non-secure
    // cookies.
    // Round 1 => none; round 2 => 31LS; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "180LS 1MN", 149U, 1U, 0U, 1U, 149U);
    // Round 1 => none; round 2 => 31LS; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "180LS 1HN", 149U, 0U, 1U, 1U, 149U);
    // Round 1 => none; round 2 => 31LS; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "1MN 180LS", 149U, 1U, 0U, 1U, 149U);
    // Round 1 => none; round 2 => 31LS; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "1HN 180LS", 149U, 0U, 1U, 1U, 149U);

    // Higher-priority non-secure cookies are removed before any secure cookie
    // with greater than low-priority. Is it true? How about the quota?
    // Round 1 => none; round 2 => none; round 3 => none.
    // Round 4 => none; round 5 => 31MS; round 6 => none.
    TestPriorityCookieCase(cm.get(), "180MS 1HN", 0U, 149U, 1U, 1U, 149U);
    // Round 1 => none; round 2 => none; round 3 => none.
    // Round 4 => none; round 5 => 31MS; round 6 => none.
    TestPriorityCookieCase(cm.get(), "1HN 180MS", 0U, 149U, 1U, 1U, 149U);

    // Pairwise:
    // Round 1 => 31LN; round 2 => none; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "1LS 180LN", 150U, 0U, 0U, 149U, 1U);
    // Round 1 => 31LN; round 2 => none; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "100LS 81LN", 150U, 0U, 0U, 50U, 100U);
    // Round 1 => 31LN; round 2 => none; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "150LS 31LN", 150U, 0U, 0U, 0U, 150U);
    // Round 1 => none; round 2 => none; round 3 => none.
    // Round 4 => 31HN; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "1LS 180HN", 1U, 0U, 149U, 149U, 1U);
    // Round 1 => none; round 2 => 31LS; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "100LS 81HN", 69U, 0U, 81U, 81U, 69U);
    // Round 1 => none; round 2 => 31LS; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "150LS 31HN", 119U, 0U, 31U, 31U, 119U);

    // Quota calculations inside non-secure/secure blocks remain in place:
    // Round 1 => none; round 2 => 20LS; round 3 => none.
    // Round 4 => 11HN; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "50HN 50LS 81HS", 30U, 0U, 120U, 39U,
                           111U);
    // Round 1 => none; round 2 => none; round 3 => 31MN.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "11MS 10HN 10LS 90MN 60HN", 10U, 70U, 70U,
                           129U, 21U);
    // Round 1 => 31LN; round 2 => none; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    TestPriorityCookieCase(cm.get(), "40LS 40LN 101HS", 49U, 0U, 101U, 9U,
                           141U);

    // Multiple GC rounds end up with consistent behavior:
    // GC is started as soon as there are 181 cookies in the store.
    // On each major round it tries to preserve the quota for each priority.
    // It is not aware about more cookies going in.
    // 1 GC notices there are 181 cookies - 100HS 81LN 0MN
    // Round 1 => 31LN; round 2 => none; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    // 2 GC notices there are 181 cookies - 100HS 69LN 12MN
    // Round 1 => 31LN; round 2 => none; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => none.
    // 3 GC notices there are 181 cookies - 100HS 38LN 43MN
    // Round 1 =>  8LN; round 2 => none; round 3 => none.
    // Round 4 => none; round 5 => none; round 6 => 23HS.
    // 4 GC notcies there are 181 cookies - 77HS 30LN 74MN
    // Round 1 => none; round 2 => none; round 3 => 24MN.
    // Round 4 => none; round 5 => none; round 6 =>  7HS.
    TestPriorityCookieCase(cm.get(), "100HS 100LN 100MN", 30U, 76U, 70U, 106U,
                           70U);
  }

  // Function for creating a CM with a number of cookies in it,
  // no store (and hence no ability to affect access time).
  std::unique_ptr<CookieMonster> CreateMonsterForGC(int num_cookies) {
    auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());
    base::Time creation_time = base::Time::Now();
    for (int i = 0; i < num_cookies; i++) {
      std::unique_ptr<CanonicalCookie> cc(
          CanonicalCookie::CreateUnsafeCookieForTesting(
              "a", "1", base::StringPrintf("h%05d.izzle", i), /*path=*/"/",
              creation_time, /*=expiration_time=*/base::Time(),
              /*last_access=*/creation_time, /*last_update=*/creation_time,
              /*secure=*/true,
              /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
              COOKIE_PRIORITY_DEFAULT));
      GURL source_url = cookie_util::SimulatedCookieSource(*cc, "https");
      cm->SetCanonicalCookieAsync(std::move(cc), source_url,
                                  CookieOptions::MakeAllInclusive(),
                                  CookieStore::SetCookiesCallback());
    }
    return cm;
  }

  bool IsCookieInList(const CanonicalCookie& cookie, const CookieList& list) {
    for (const auto& c : list) {
      if (c.Name() == cookie.Name() && c.Value() == cookie.Value() &&
          c.Domain() == cookie.Domain() && c.Path() == cookie.Path() &&
          c.CreationDate() == cookie.CreationDate() &&
          c.ExpiryDate() == cookie.ExpiryDate() &&
          c.LastAccessDate() == cookie.LastAccessDate() &&
          c.LastUpdateDate() == cookie.LastUpdateDate() &&
          c.SecureAttribute() == cookie.SecureAttribute() &&
          c.IsHttpOnly() == cookie.IsHttpOnly() &&
          c.Priority() == cookie.Priority()) {
        return true;
      }
    }

    return false;
  }
  RecordingNetLogObserver net_log_;
};

using CookieMonsterTest = CookieMonsterTestBase<CookieMonsterTestTraits>;

class CookieMonsterTestGarbageCollectionObc
    : public CookieMonsterTest,
      public testing::WithParamInterface<std::tuple<bool, bool>> {
 public:
  CookieMonsterTestGarbageCollectionObc() {
    scoped_feature_list_.InitWithFeatureStates(
        {{net::features::kEnableSchemeBoundCookies, IsSchemeBoundEnabled()},
         {net::features::kEnablePortBoundCookies, IsPortBoundEnabled()}});
  }

  bool IsSchemeBoundEnabled() const { return std::get<0>(GetParam()); }

  bool IsPortBoundEnabled() const { return std::get<1>(GetParam()); }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

using CookieMonsterTestPriorityGarbageCollectionObc =
    CookieMonsterTestGarbageCollectionObc;

struct CookiesInputInfo {
  const GURL url;
  const std::string name;
  const std::string value;
  const std::string domain;
  const std::string path;
  const base::Time expiration_time;
  bool secure;
  bool http_only;
  CookieSameSite same_site;
  CookiePriority priority;
};

}  // namespace

// This test suite verifies the task deferral behaviour of the CookieMonster.
// Specifically, for each asynchronous method, verify that:
// 1. invoking it on an uninitialized cookie store causes the store to begin
//    chain-loading its backing data or loading data for a specific domain key
//    (eTLD+1).
// 2. The initial invocation does not complete until the loading completes.
// 3. Invocations after the loading has completed complete immediately.
class DeferredCookieTaskTest : public CookieMonsterTest {
 protected:
  DeferredCookieTaskTest() {
    persistent_store_ = base::MakeRefCounted<MockPersistentCookieStore>();
    persistent_store_->set_store_load_commands(true);
    cookie_monster_ = std::make_unique<CookieMonster>(persistent_store_.get(),
                                                      net::NetLog::Get());
  }

  // Defines a cookie to be returned from PersistentCookieStore::Load
  void DeclareLoadedCookie(const GURL& url,
                           const std::string& cookie_line,
                           const base::Time& creation_time) {
    AddCookieToList(url, cookie_line, creation_time, &loaded_cookies_);
  }

  void ExecuteLoads(CookieStoreCommand::Type type) {
    const auto& commands = persistent_store_->commands();
    for (size_t i = 0; i < commands.size(); ++i) {
      // Only the first load command will produce the cookies.
      if (commands[i].type == type) {
        persistent_store_->TakeCallbackAt(i).Run(std::move(loaded_cookies_));
      }
    }
  }

  std::string CommandSummary(
      const MockPersistentCookieStore::CommandList& commands) {
    std::string out;
    for (const auto& command : commands) {
      switch (command.type) {
        case CookieStoreCommand::LOAD:
          base::StrAppend(&out, {"LOAD; "});
          break;
        case CookieStoreCommand::LOAD_COOKIES_FOR_KEY:
          base::StrAppend(&out, {"LOAD_FOR_KEY:", command.key, "; "});
          break;
        case CookieStoreCommand::ADD:
          base::StrAppend(&out, {"ADD; "});
          break;
        case CookieStoreCommand::REMOVE:
          base::StrAppend(&out, {"REMOVE; "});
          break;
      }
    }
    return out;
  }

  std::string TakeCommandSummary() {
    return CommandSummary(persistent_store_->TakeCommands());
  }

  // Holds cookies to be returned from PersistentCookieStore::Load or
  // PersistentCookieStore::LoadCookiesForKey.
  std::vector<std::unique_ptr<CanonicalCookie>> loaded_cookies_;

  std::unique_ptr<CookieMonster> cookie_monster_;
  scoped_refptr<MockPersistentCookieStore> persistent_store_;
};

TEST_F(DeferredCookieTaskTest, DeferredGetCookieList) {
  DeclareLoadedCookie(http_www_foo_.url(),
                      "X=1; path=/" + FutureCookieExpirationString(),
                      Time::Now() + base::Days(3));

  GetCookieListCallback call1;
  cookie_monster_->GetCookieListWithOptionsAsync(
      http_www_foo_.url(), CookieOptions::MakeAllInclusive(),
      CookiePartitionKeyCollection(), call1.MakeCallback());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(call1.was_run());

  // Finish the per-key load, not everything-load (which is always initiated).
  ExecuteLoads(CookieStoreCommand::LOAD_COOKIES_FOR_KEY);
  call1.WaitUntilDone();
  EXPECT_THAT(call1.cookies(), MatchesCookieLine("X=1"));
  EXPECT_EQ("LOAD; LOAD_FOR_KEY:foo.com; ", TakeCommandSummary());

  GetCookieListCallback call2;
  cookie_monster_->GetCookieListWithOptionsAsync(
      http_www_foo_.url(), CookieOptions::MakeAllInclusive(),
      CookiePartitionKeyCollection(), call2.MakeCallback());
  // Already ready, no need for second load.
  EXPECT_THAT(call2.cookies(), MatchesCookieLine("X=1"));
  EXPECT_EQ("", TakeCommandSummary());
}

TEST_F(DeferredCookieTaskTest, DeferredSetCookie) {
  // Generate puts to store w/o needing a proper expiration.
  cookie_monster_->SetPersistSessionCookies(true);

  ResultSavingCookieCallback<CookieAccessResult> call1;
  cookie_monster_->SetCanonicalCookieAsync(
      CanonicalCookie::CreateForTesting(http_www_foo_.url(), "A=B",
                                        base::Time::Now()),
      http_www_foo_.url(), CookieOptions::MakeAllInclusive(),
      call1.MakeCallback());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(call1.was_run());

  ExecuteLoads(CookieStoreCommand::LOAD_COOKIES_FOR_KEY);
  call1.WaitUntilDone();
  EXPECT_TRUE(call1.result().status.IsInclude());
  EXPECT_EQ("LOAD; LOAD_FOR_KEY:foo.com; ADD; ", TakeCommandSummary());

  ResultSavingCookieCallback<CookieAccessResult> call2;
  cookie_monster_->SetCanonicalCookieAsync(
      CanonicalCookie::CreateForTesting(http_www_foo_.url(), "X=Y",
                                        base::Time::Now()),
      http_www_foo_.url(), CookieOptions::MakeAllInclusive(),
      call2.MakeCallback());
  ASSERT_TRUE(call2.was_run());
  EXPECT_TRUE(call2.result().status.IsInclude());
  EXPECT_EQ("ADD; ", TakeCommandSummary());
}

TEST_F(DeferredCookieTaskTest, DeferredSetAllCookies) {
  // Generate puts to store w/o needing a proper expiration.
  cookie_monster_->SetPersistSessionCookies(true);

  CookieList list;
  list.push_back(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "B", "." + http_www_foo_.domain(), "/", base::Time::Now(),
      base::Time(), base::Time(), base::Time(), false, true,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT));
  list.push_back(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "C", "D", "." + http_www_foo_.domain(), "/", base::Time::Now(),
      base::Time(), base::Time(), base::Time(), false, true,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT));

  ResultSavingCookieCallback<CookieAccessResult> call1;
  cookie_monster_->SetAllCookiesAsync(list, call1.MakeCallback());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(call1.was_run());

  ExecuteLoads(CookieStoreCommand::LOAD);
  call1.WaitUntilDone();
  EXPECT_TRUE(call1.result().status.IsInclude());
  EXPECT_EQ("LOAD; ADD; ADD; ", TakeCommandSummary());

  // 2nd set doesn't need to read from store. It erases the old cookies, though.
  ResultSavingCookieCallback<CookieAccessResult> call2;
  cookie_monster_->SetAllCookiesAsync(list, call2.MakeCallback());
  ASSERT_TRUE(call2.was_run());
  EXPECT_TRUE(call2.result().status.IsInclude());
  EXPECT_EQ("REMOVE; REMOVE; ADD; ADD; ", TakeCommandSummary());
}

TEST_F(DeferredCookieTaskTest, DeferredGetAllCookies) {
  DeclareLoadedCookie(http_www_foo_.url(),
                      "X=1; path=/" + FutureCookieExpirationString(),
                      Time::Now() + base::Days(3));

  GetAllCookiesCallback call1;
  cookie_monster_->GetAllCookiesAsync(call1.MakeCallback());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(call1.was_run());

  ExecuteLoads(CookieStoreCommand::LOAD);
  call1.WaitUntilDone();
  EXPECT_THAT(call1.cookies(), MatchesCookieLine("X=1"));
  EXPECT_EQ("LOAD; ", TakeCommandSummary());

  GetAllCookiesCallback call2;
  cookie_monster_->GetAllCookiesAsync(call2.MakeCallback());
  EXPECT_TRUE(call2.was_run());
  EXPECT_THAT(call2.cookies(), MatchesCookieLine("X=1"));
  EXPECT_EQ("", TakeCommandSummary());
}

TEST_F(DeferredCookieTaskTest, DeferredGetAllForUrlCookies) {
  DeclareLoadedCookie(http_www_foo_.url(),
                      "X=1; path=/" + FutureCookieExpirationString(),
                      Time::Now() + base::Days(3));

  GetCookieListCallback call1;
  cookie_monster_->GetCookieListWithOptionsAsync(
      http_www_foo_.url(), CookieOptions::MakeAllInclusive(),
      CookiePartitionKeyCollection(), call1.MakeCallback());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(call1.was_run());

  ExecuteLoads(CookieStoreCommand::LOAD_COOKIES_FOR_KEY);
  call1.WaitUntilDone();
  EXPECT_THAT(call1.cookies(), MatchesCookieLine("X=1"));
  EXPECT_EQ("LOAD; LOAD_FOR_KEY:foo.com; ", TakeCommandSummary());

  GetCookieListCallback call2;
  cookie_monster_->GetCookieListWithOptionsAsync(
      http_www_foo_.url(), CookieOptions::MakeAllInclusive(),
      CookiePartitionKeyCollection(), call2.MakeCallback());
  EXPECT_TRUE(call2.was_run());
  EXPECT_THAT(call2.cookies(), MatchesCookieLine("X=1"));
  EXPECT_EQ("", TakeCommandSummary());
}

TEST_F(DeferredCookieTaskTest, DeferredGetAllForUrlWithOptionsCookies) {
  DeclareLoadedCookie(http_www_foo_.url(),
                      "X=1; path=/" + FutureCookieExpirationString(),
                      Time::Now() + base::Days(3));

  GetCookieListCallback call1;
  cookie_monster_->GetCookieListWithOptionsAsync(
      http_www_foo_.url(), CookieOptions::MakeAllInclusive(),
      CookiePartitionKeyCollection(), call1.MakeCallback());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(call1.was_run());

  ExecuteLoads(CookieStoreCommand::LOAD_COOKIES_FOR_KEY);
  call1.WaitUntilDone();
  EXPECT_THAT(call1.cookies(), MatchesCookieLine("X=1"));
  EXPECT_EQ("LOAD; LOAD_FOR_KEY:foo.com; ", TakeCommandSummary());

  GetCookieListCallback call2;
  cookie_monster_->GetCookieListWithOptionsAsync(
      http_www_foo_.url(), CookieOptions::MakeAllInclusive(),
      CookiePartitionKeyCollection(), call2.MakeCallback());
  EXPECT_TRUE(call2.was_run());
  EXPECT_THAT(call2.cookies(), MatchesCookieLine("X=1"));
  EXPECT_EQ("", TakeCommandSummary());
}

TEST_F(DeferredCookieTaskTest, DeferredDeleteAllCookies) {
  DeclareLoadedCookie(http_www_foo_.url(),
                      "X=1; path=/" + FutureCookieExpirationString(),
                      Time::Now() + base::Days(3));

  ResultSavingCookieCallback<uint32_t> call1;
  cookie_monster_->DeleteAllAsync(call1.MakeCallback());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(call1.was_run());

  ExecuteLoads(CookieStoreCommand::LOAD);
  call1.WaitUntilDone();
  EXPECT_EQ(1u, call1.result());
  EXPECT_EQ("LOAD; REMOVE; ", TakeCommandSummary());

  ResultSavingCookieCallback<uint32_t> call2;
  cookie_monster_->DeleteAllAsync(call2.MakeCallback());
  // This needs an event loop spin since DeleteAllAsync always reports
  // asynchronously.
  call2.WaitUntilDone();
  EXPECT_EQ(0u, call2.result());
  EXPECT_EQ("", TakeCommandSummary());
}

TEST_F(DeferredCookieTaskTest, DeferredDeleteAllCreatedInTimeRangeCookies) {
  const TimeRange time_range(base::Time(), base::Time::Now());

  ResultSavingCookieCallback<uint32_t> call1;
  cookie_monster_->DeleteAllCreatedInTimeRangeAsync(time_range,
                                                    call1.MakeCallback());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(call1.was_run());

  ExecuteLoads(CookieStoreCommand::LOAD);
  call1.WaitUntilDone();
  EXPECT_EQ(0u, call1.result());
  EXPECT_EQ("LOAD; ", TakeCommandSummary());

  ResultSavingCookieCallback<uint32_t> call2;
  cookie_monster_->DeleteAllCreatedInTimeRangeAsync(time_range,
                                                    call2.MakeCallback());
  call2.WaitUntilDone();
  EXPECT_EQ(0u, call2.result());
  EXPECT_EQ("", TakeCommandSummary());
}

TEST_F(DeferredCookieTaskTest,
       DeferredDeleteAllWithPredicateCreatedInTimeRangeCookies) {
  ResultSavingCookieCallback<uint32_t> call1;
  cookie_monster_->DeleteAllMatchingInfoAsync(
      CookieDeletionInfo(Time(), Time::Now()), call1.MakeCallback());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(call1.was_run());

  ExecuteLoads(CookieStoreCommand::LOAD);
  call1.WaitUntilDone();
  EXPECT_EQ(0u, call1.result());
  EXPECT_EQ("LOAD; ", TakeCommandSummary());

  ResultSavingCookieCallback<uint32_t> call2;
  cookie_monster_->DeleteAllMatchingInfoAsync(
      CookieDeletionInfo(Time(), Time::Now()), call2.MakeCallback());
  call2.WaitUntilDone();
  EXPECT_EQ(0u, call2.result());
  EXPECT_EQ("", TakeCommandSummary());
}

TEST_F(DeferredCookieTaskTest, DeferredDeleteMatchingCookies) {
  ResultSavingCookieCallback<uint32_t> call1;
  cookie_monster_->DeleteMatchingCookiesAsync(
      base::BindRepeating(
          [](const net::CanonicalCookie& cookie) { return true; }),
      call1.MakeCallback());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(call1.was_run());

  ExecuteLoads(CookieStoreCommand::LOAD);
  call1.WaitUntilDone();
  EXPECT_EQ(0u, call1.result());
  EXPECT_EQ("LOAD; ", TakeCommandSummary());

  ResultSavingCookieCallback<uint32_t> call2;
  cookie_monster_->DeleteMatchingCookiesAsync(
      base::BindRepeating(
          [](const net::CanonicalCookie& cookie) { return true; }),
      call2.MakeCallback());
  call2.WaitUntilDone();
  EXPECT_EQ(0u, call2.result());
  EXPECT_EQ("", TakeCommandSummary());
}

TEST_F(DeferredCookieTaskTest, DeferredDeleteCanonicalCookie) {
  std::unique_ptr<CanonicalCookie> cookie = BuildCanonicalCookie(
      http_www_foo_.url(), "X=1; path=/", base::Time::Now());

  ResultSavingCookieCallback<uint32_t> call1;
  cookie_monster_->DeleteCanonicalCookieAsync(*cookie, call1.MakeCallback());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(call1.was_run());

  // TODO(morlovich): Fix DeleteCanonicalCookieAsync. This test should pass
  // when using LOAD_COOKIES_FOR_KEY instead, with that reflected in
  // TakeCommandSummary() as well.
  ExecuteLoads(CookieStoreCommand::LOAD);
  call1.WaitUntilDone();
  EXPECT_EQ(0u, call1.result());
  EXPECT_EQ("LOAD; ", TakeCommandSummary());

  ResultSavingCookieCallback<uint32_t> call2;
  cookie_monster_->DeleteCanonicalCookieAsync(*cookie, call2.MakeCallback());
  call2.WaitUntilDone();
  EXPECT_EQ(0u, call2.result());
  EXPECT_EQ("", TakeCommandSummary());
}

TEST_F(DeferredCookieTaskTest, DeferredDeleteSessionCookies) {
  ResultSavingCookieCallback<uint32_t> call1;
  cookie_monster_->DeleteSessionCookiesAsync(call1.MakeCallback());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(call1.was_run());

  ExecuteLoads(CookieStoreCommand::LOAD);
  call1.WaitUntilDone();
  EXPECT_EQ(0u, call1.result());
  EXPECT_EQ("LOAD; ", TakeCommandSummary());

  ResultSavingCookieCallback<uint32_t> call2;
  cookie_monster_->DeleteSessionCookiesAsync(call2.MakeCallback());
  call2.WaitUntilDone();
  EXPECT_EQ(0u, call2.result());
  EXPECT_EQ("", TakeCommandSummary());
}

// Verify that a series of queued tasks are executed in order upon loading of
// the backing store and that new tasks received while the queued tasks are
// being dispatched go to the end of the queue.
TEST_F(DeferredCookieTaskTest, DeferredTaskOrder) {
  cookie_monster_->SetPersistSessionCookies(true);
  DeclareLoadedCookie(http_www_foo_.url(),
                      "X=1; path=/" + FutureCookieExpirationString(),
                      Time::Now() + base::Days(3));

  bool get_cookie_list_callback_was_run = false;
  GetCookieListCallback get_cookie_list_callback_deferred;
  ResultSavingCookieCallback<CookieAccessResult> set_cookies_callback;
  base::RunLoop run_loop;
  cookie_monster_->GetCookieListWithOptionsAsync(
      http_www_foo_.url(), CookieOptions::MakeAllInclusive(),
      CookiePartitionKeyCollection(),
      base::BindLambdaForTesting(
          [&](const CookieAccessResultList& cookies,
              const CookieAccessResultList& excluded_list) {
            // This should complete before the set.
            get_cookie_list_callback_was_run = true;
            EXPECT_FALSE(set_cookies_callback.was_run());
            EXPECT_THAT(cookies, MatchesCookieLine("X=1"));
            // Can't use TakeCommandSummary here since ExecuteLoads is walking
            // through the data it takes.
            EXPECT_EQ("LOAD; LOAD_FOR_KEY:foo.com; ",
                      CommandSummary(persistent_store_->commands()));

            // Queue up a second get. It should see the result of the set queued
            // before it.
            cookie_monster_->GetCookieListWithOptionsAsync(
                http_www_foo_.url(), CookieOptions::MakeAllInclusive(),
                CookiePartitionKeyCollection(),
                get_cookie_list_callback_deferred.MakeCallback());

            run_loop.Quit();
          }));

  cookie_monster_->SetCanonicalCookieAsync(
      CanonicalCookie::CreateForTesting(http_www_foo_.url(), "A=B",
                                        base::Time::Now()),
      http_www_foo_.url(), CookieOptions::MakeAllInclusive(),
      set_cookies_callback.MakeCallback());

  // Nothing happened yet, before loads are done.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(get_cookie_list_callback_was_run);
  EXPECT_FALSE(set_cookies_callback.was_run());

  ExecuteLoads(CookieStoreCommand::LOAD_COOKIES_FOR_KEY);
  run_loop.Run();
  EXPECT_EQ("LOAD; LOAD_FOR_KEY:foo.com; ADD; ", TakeCommandSummary());
  EXPECT_TRUE(get_cookie_list_callback_was_run);
  ASSERT_TRUE(set_cookies_callback.was_run());
  EXPECT_TRUE(set_cookies_callback.result().status.IsInclude());

  ASSERT_TRUE(get_cookie_list_callback_deferred.was_run());
  EXPECT_THAT(get_cookie_list_callback_deferred.cookies(),
              MatchesCookieLine("A=B; X=1"));
}

TEST_F(CookieMonsterTest, TestCookieDeleteAll) {
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());
  CookieOptions options = CookieOptions::MakeAllInclusive();

  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), kValidCookieLine));
  EXPECT_EQ("A=B", GetCookies(cm.get(), http_www_foo_.url()));

  EXPECT_TRUE(CreateAndSetCookie(cm.get(), http_www_foo_.url(), "C=D; httponly",
                                 options));
  EXPECT_EQ("A=B; C=D",
            GetCookiesWithOptions(cm.get(), http_www_foo_.url(), options));

  EXPECT_EQ(2u, DeleteAll(cm.get()));
  EXPECT_EQ("", GetCookiesWithOptions(cm.get(), http_www_foo_.url(), options));
  EXPECT_EQ(0u, store->commands().size());

  // Create a persistent cookie.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(),
                        kValidCookieLine + FutureCookieExpirationString()));
  ASSERT_EQ(1u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::ADD, store->commands()[0].type);

  EXPECT_EQ(1u, DeleteAll(cm.get()));  // sync_to_store = true.
  ASSERT_EQ(2u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[1].type);

  EXPECT_EQ("", GetCookiesWithOptions(cm.get(), http_www_foo_.url(), options));

  // Create a Partitioned cookie.
  auto cookie_partition_key =
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com"));
  EXPECT_TRUE(SetCookie(
      cm.get(), https_www_foo_.url(),
      "__Host-" + std::string(kValidCookieLine) + "; partitioned; secure",
      cookie_partition_key));
  EXPECT_EQ(1u, DeleteAll(cm.get()));
  EXPECT_EQ("", GetCookiesWithOptions(
                    cm.get(), http_www_foo_.url(), options,
                    CookiePartitionKeyCollection(cookie_partition_key)));
  EXPECT_EQ(2u, store->commands().size());
}

TEST_F(CookieMonsterTest, TestCookieDeleteAllCreatedInTimeRangeTimestamps) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  Time now = Time::Now();

  // Nothing has been added so nothing should be deleted.
  EXPECT_EQ(0u, DeleteAllCreatedInTimeRange(
                    cm.get(), TimeRange(now - base::Days(99), Time())));

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

  // Try to delete threedays and the daybefore.
  EXPECT_EQ(2u,
            DeleteAllCreatedInTimeRange(
                cm.get(), TimeRange(now - base::Days(3), now - base::Days(1))));

  // Try to delete yesterday, also make sure that delete_end is not
  // inclusive.
  EXPECT_EQ(1u, DeleteAllCreatedIn
```