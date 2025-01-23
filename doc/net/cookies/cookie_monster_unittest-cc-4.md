Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The request asks for a summary of the functionality of the provided C++ code snippet, specifically focusing on its relationship with JavaScript, logical inferences, common usage errors, debugging, and a concise overall function. It's also marked as part 5 of 10, suggesting a larger context.

2. **Initial Code Scan - Identify Key Areas:** I'll quickly read through the code, looking for patterns and keywords. I see:
    * `TEST_F`:  This immediately tells me it's unit test code using a testing framework (likely Google Test).
    * `CookieMonsterTest`: This indicates the tests are for a class named `CookieMonster`.
    * `GarbageCollection`: Several tests explicitly mention garbage collection.
    * `SetCookie`, `GetAllCookies`, `DeleteAll`: These are methods likely belonging to the `CookieMonster` class and suggest cookie management functionality.
    * `MockPersistentCookieStore`: This suggests testing interactions with a persistent storage mechanism for cookies.
    * `Async` suffixes (e.g., `GetAllCookiesAsync`): Indicates asynchronous operations.
    * `FlushStore`: A method related to flushing the cookie store.
    * `SetAllCookies`:  Setting multiple cookies at once.
    * Histogram-related code:  Suggests tracking and reporting metrics.
    * References to `kMaxCookies`, `kPurgeCookies`, `kSafeFromGlobalPurgeDays`: These look like constants related to cookie limits and garbage collection policies.

3. **Categorize Functionality:** Based on the initial scan, I can group the tests into logical categories:
    * **Basic Cookie Operations:** Setting, getting, and deleting individual cookies.
    * **Garbage Collection:** Testing the logic and behavior of cookie garbage collection under various conditions (number of cookies, age, etc.).
    * **Asynchronous Operations and Loading:** Testing scenarios where cookie operations occur during the loading of cookies from persistent storage. This involves managing asynchronous callbacks and ensuring correct ordering of operations.
    * **Flushing the Store:** Testing the `FlushStore` functionality.
    * **Setting Multiple Cookies:**  Testing the `SetAllCookies` functionality.
    * **Histograms:** Testing the recording of cookie-related statistics.
    * **Persistence:** Testing how cookies are stored and retrieved from persistent storage.
    * **Control Character Handling:**  Testing how the system handles cookies with potentially problematic characters.
    * **Key Management:** Testing the tracking and management of cookie keys.

4. **Address Specific Requirements:**

    * **JavaScript Relationship:** Cookies are fundamental to web browsing and are heavily interacted with by JavaScript. I'll need to explain this connection and provide examples like `document.cookie`.
    * **Logical Inferences (Hypothetical Inputs & Outputs):**  For some of the tests (especially garbage collection), I can create simplified scenarios to illustrate the expected input (initial cookie state) and output (cookie state after garbage collection).
    * **Common Usage Errors:**  I'll think about typical mistakes developers make when dealing with cookies, such as incorrect domain/path settings, forgetting `Secure` or `HttpOnly` flags, and issues with expiry dates.
    * **User Operation to Reach This Code (Debugging):** I'll explain the typical user actions that lead to cookie operations and how a developer might end up investigating the `CookieMonster` code during debugging.
    * **Concise Function Summary:** I need to distill the overall purpose of the code snippet.

5. **Construct the Answer - Iterative Refinement:**

    * **Start with the Core Function:**  Clearly state that the code tests the `CookieMonster` class, which manages cookies.
    * **Expand on Key Functionality Areas:**  Go through the categorized functionalities and describe what each set of tests verifies. Use the keywords and observations from the code scan.
    * **Integrate JavaScript:**  Explain the browser-JavaScript cookie interaction and provide the `document.cookie` example.
    * **Provide Logical Inferences:** Choose a couple of the garbage collection tests and create simplified input/output scenarios.
    * **Illustrate Common Errors:**  Give practical examples of mistakes developers make with cookies.
    * **Describe the User Journey:**  Outline the steps a user takes that result in cookie-related actions.
    * **Connect to Debugging:** Explain how this code becomes relevant during debugging.
    * **Formulate the Concise Summary:**  Reiterate the main purpose of the `cookie_monster_unittest.cc` file.
    * **Review and Refine:** Read through the answer to ensure clarity, accuracy, and completeness. Check if I've addressed all parts of the request. For instance, ensure the part number (5/10) is acknowledged and factored into the summary if possible (e.g., focusing on the aspects evident in this specific part).

By following these steps, I can systematically analyze the code snippet and generate a comprehensive and informative answer that addresses all the requirements of the prompt. The process involves understanding the code's purpose, categorizing its functionality, connecting it to broader concepts like JavaScript and user interactions, and structuring the answer logically.
这是 Chromium 网络栈中 `net/cookies/cookie_monster_unittest.cc` 文件的第 5 部分，主要功能是测试 `CookieMonster` 类的垃圾回收机制和在加载 Cookie 过程中进行各种操作的正确性。

**核心功能归纳：**

* **测试 CookieMonster 的垃圾回收（Garbage Collection）机制：** 这部分测试着重验证 `CookieMonster` 如何在 Cookie 数量超过限制时，根据最近访问时间和一定的策略（例如保留最近的 Cookie），正确地删除旧的 Cookie。
* **测试在 CookieStore 加载期间执行操作的正确性：**  这部分测试模拟了在 `CookieMonster` 从持久化存储加载 Cookie 的过程中，执行设置、获取和删除 Cookie 等操作，确保这些异步操作能够正确排队和执行，避免竞态条件和数据不一致。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不直接包含 JavaScript 代码，但它测试的网络栈组件 `CookieMonster` 负责管理浏览器中的 HTTP Cookie。JavaScript 可以通过 `document.cookie` API  读取、设置和删除这些 Cookie。

**举例说明：**

1. **JavaScript 设置 Cookie：**
   ```javascript
   document.cookie = "myCookie=myValue; expires=Thu, 18 Dec 2023 12:00:00 UTC; path=/";
   ```
   这个 JavaScript 操作最终会触发浏览器网络栈中的 Cookie 处理逻辑，`CookieMonster` 负责接收、解析、存储这个 Cookie，并可能触发垃圾回收如果 Cookie 数量超过限制。 这部分测试就在验证 `CookieMonster` 在接收到新的 Cookie 时，垃圾回收机制是否正常工作。

2. **JavaScript 读取 Cookie：**
   ```javascript
   let allCookies = document.cookie;
   ```
   这个操作会调用浏览器网络栈的接口去获取匹配当前上下文的 Cookie。`CookieMonster` 负责从内存或持久化存储中检索 Cookie。 这部分测试中 `GetAllCookies` 函数模拟了这种读取操作，验证了在加载期间或垃圾回收后，`CookieMonster` 返回的 Cookie 列表是否正确。

**逻辑推理与假设输入输出：**

以下针对部分测试用例进行逻辑推理：

**测试用例：`GarbageCollectionKeepsOnlyRecentCookies`**

* **假设输入：**
    * `CookieMonster` 的容量限制为 `kMaxCookies`。
    * 初始状态有 `2 * kMaxCookies` 个 Cookie。
    * 其中 `kMaxCookies / 2` 个是“旧”的 Cookie (访问时间较早)。
    * 剩余 `2 * kMaxCookies - kMaxCookies / 2` 个是“最近”的 Cookie。
    * 执行 `SetCookie` 操作添加一个新的 Cookie。

* **逻辑推理：**
    * 当添加新的 Cookie 时，Cookie 总数超过了限制，触发垃圾回收。
    * 垃圾回收策略会优先保留最近的 Cookie。
    * 应该删除所有旧的 `kMaxCookies / 2` 个 Cookie。
    * 新添加的 Cookie 会被保留。

* **预期输出：**
    * 在垃圾回收后，Cookie 的总数应该为： `(2 * kMaxCookies - kMaxCookies / 2) + 1` （最近的 Cookie + 新添加的 Cookie）。 这与测试代码中的 `EXPECT_EQ(CookieMonster::kMaxCookies * 2 - CookieMonster::kMaxCookies / 2 + 1, GetAllCookies(cm.get()).size());` 相符。

**测试用例：`WhileLoadingGetAllSetGetAll`**

* **假设输入：**
    * `CookieMonster` 正在从持久化存储加载 Cookie (模拟 `store->set_store_load_commands(true);`)。
    * 依次执行以下操作：
        1. `GetAllCookiesAsync` (获取所有 Cookie，回调函数1)
        2. `SetCanonicalCookieAsync` (设置一个 Cookie)
        3. `GetAllCookiesAsync` (获取所有 Cookie，回调函数2)

* **逻辑推理：**
    * 由于 CookieStore 正在加载，所有操作都会被放入队列等待加载完成后执行。
    * 第一个 `GetAllCookiesAsync` 会在加载完成后立即执行，此时还没有设置新的 Cookie。
    * `SetCanonicalCookieAsync` 会在第一个 `GetAllCookiesAsync` 之后执行，将新的 Cookie 添加到 `CookieMonster` 的内存中。
    * 第二个 `GetAllCookiesAsync` 会在 `SetCanonicalCookieAsync` 之后执行，此时新的 Cookie 已经存在。

* **预期输出：**
    * 回调函数1 返回的 Cookie 列表应该是空的（因为加载完成时假设没有 Cookie）。
    * 回调函数2 返回的 Cookie 列表应该包含刚刚设置的 Cookie。 这与测试代码中的 `EXPECT_EQ(0u, get_cookies_callback1.cookies().size());` 和 `EXPECT_EQ(1u, get_cookies_callback2.cookies().size());` 相符。

**用户或编程常见的使用错误：**

1. **Cookie 数量过多导致性能问题：**  用户在短时间内访问大量设置 Cookie 的网站，可能导致浏览器存储过多的 Cookie，影响性能。 `CookieMonster` 的垃圾回收机制旨在缓解这个问题，但如果网站过度设置 Cookie，仍然可能超出限制。

2. **在 CookieStore 加载期间进行操作导致意外行为：** 开发者可能不清楚 `CookieMonster` 的异步加载机制，在 CookieStore 尚未完全加载时就执行依赖 Cookie 数据的操作，可能导致读取到不完整或过时的数据。 这部分 "WhileLoading..." 的测试就是为了验证 `CookieMonster` 如何处理这种情况。

3. **不理解垃圾回收策略导致 Cookie 意外丢失：**  开发者可能假设设置的 Cookie 会一直存在，但由于垃圾回收机制，旧的或不常访问的 Cookie 可能会被删除。不了解 `kMaxCookies`、`kPurgeCookies` 等参数的含义可能导致困惑。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户访问一个网站：** 当用户在浏览器中输入网址或点击链接访问一个网站时，浏览器会向服务器发送 HTTP 请求。
2. **服务器设置 Cookie：** 服务器在 HTTP 响应头中通过 `Set-Cookie` 字段来指示浏览器存储 Cookie。例如：`Set-Cookie: myCookie=myValue; expires=...`
3. **浏览器接收并处理 Cookie：** 浏览器网络栈接收到响应头，解析 `Set-Cookie` 字段，并将 Cookie 信息传递给 `CookieMonster` 进行管理。
4. **`CookieMonster` 存储 Cookie：** `CookieMonster` 将 Cookie 存储在内存中，并可能在后台异步地写入持久化存储。
5. **Cookie 数量超过限制：** 如果用户持续访问设置 Cookie 的网站，或者网站设置了大量的 Cookie，`CookieMonster` 中存储的 Cookie 数量可能超过 `kMaxCookies`。
6. **触发垃圾回收：** 当 `CookieMonster` 接收到新的 Cookie 且当前 Cookie 数量超过限制时，会触发垃圾回收机制。
7. **调试过程：**  如果用户遇到 Cookie 丢失或行为异常的问题，开发者可能会怀疑是 `CookieMonster` 的垃圾回收机制导致，从而需要查看 `cookie_monster_unittest.cc` 中的相关测试，了解垃圾回收的逻辑和策略，并进行调试。他们可能会设置断点在 `CookieMonster` 的垃圾回收相关代码中，观察 Cookie 的删除过程。

**作为第 5 部分的功能归纳：**

作为系列测试的第 5 部分，这段代码专注于 `CookieMonster` 的核心功能之一：**在资源受限的情况下（Cookie 数量过多）如何维持一个合理有效的 Cookie 集合，并通过测试确保在复杂的异步操作场景下，Cookie 的管理依然是可靠的。** 它深入测试了垃圾回收的边界条件和在加载期间进行操作的并发安全性，这对于保证浏览器 Cookie 功能的稳定性和用户体验至关重要。

### 提示词
```
这是目录为net/cookies/cookie_monster_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
("g", cookies[i++].Name());
    EXPECT_EQ("b", cookies[i++].Name());
    EXPECT_EQ("c", cookies[i++].Name());
  }
}

// These garbage collection tests and CookieMonstertest.TestGCTimes (in
// cookie_monster_perftest.cc) are somewhat complementary.  These tests probe
// for whether garbage collection always happens when it should (i.e. that we
// actually get rid of cookies when we should).  The perftest is probing for
// whether garbage collection happens when it shouldn't.  See comments
// before that test for more details.

// Check to make sure that a whole lot of recent cookies doesn't get rid of
// anything after garbage collection is checked for.
TEST_F(CookieMonsterTest, GarbageCollectionKeepsRecentEphemeralCookies) {
  std::unique_ptr<CookieMonster> cm(
      CreateMonsterForGC(CookieMonster::kMaxCookies * 2 /* num_cookies */));
  EXPECT_EQ(CookieMonster::kMaxCookies * 2, GetAllCookies(cm.get()).size());
  // Will trigger GC.
  SetCookie(cm.get(), GURL("http://newdomain.com"), "b=2");
  EXPECT_EQ(CookieMonster::kMaxCookies * 2 + 1, GetAllCookies(cm.get()).size());
}

// A whole lot of recent cookies; GC shouldn't happen.
TEST_F(CookieMonsterTest, GarbageCollectionKeepsRecentCookies) {
  std::unique_ptr<CookieMonster> cm = CreateMonsterFromStoreForGC(
      CookieMonster::kMaxCookies * 2 /* num_cookies */, 0 /* num_old_cookies */,
      0, 0, CookieMonster::kSafeFromGlobalPurgeDays * 2);
  EXPECT_EQ(CookieMonster::kMaxCookies * 2, GetAllCookies(cm.get()).size());
  // Will trigger GC.
  SetCookie(cm.get(), GURL("http://newdomain.com"), "b=2");
  EXPECT_EQ(CookieMonster::kMaxCookies * 2 + 1, GetAllCookies(cm.get()).size());
}

// Test case where there are more than kMaxCookies - kPurgeCookies recent
// cookies. All old cookies should be garbage collected, all recent cookies
// kept.
TEST_F(CookieMonsterTest, GarbageCollectionKeepsOnlyRecentCookies) {
  std::unique_ptr<CookieMonster> cm = CreateMonsterFromStoreForGC(
      CookieMonster::kMaxCookies * 2 /* num_cookies */,
      CookieMonster::kMaxCookies / 2 /* num_old_cookies */, 0, 0,
      CookieMonster::kSafeFromGlobalPurgeDays * 2);
  EXPECT_EQ(CookieMonster::kMaxCookies * 2, GetAllCookies(cm.get()).size());
  // Will trigger GC.
  SetCookie(cm.get(), GURL("http://newdomain.com"), "b=2");
  EXPECT_EQ(CookieMonster::kMaxCookies * 2 - CookieMonster::kMaxCookies / 2 + 1,
            GetAllCookies(cm.get()).size());
}

// Test case where there are exactly kMaxCookies - kPurgeCookies recent cookies.
// All old cookies should be deleted.
TEST_F(CookieMonsterTest, GarbageCollectionExactlyAllOldCookiesDeleted) {
  std::unique_ptr<CookieMonster> cm = CreateMonsterFromStoreForGC(
      CookieMonster::kMaxCookies * 2 /* num_cookies */,
      CookieMonster::kMaxCookies + CookieMonster::kPurgeCookies +
          1 /* num_old_cookies */,
      0, 0, CookieMonster::kSafeFromGlobalPurgeDays * 2);
  EXPECT_EQ(CookieMonster::kMaxCookies * 2, GetAllCookies(cm.get()).size());
  // Will trigger GC.
  SetCookie(cm.get(), GURL("http://newdomain.com"), "b=2");
  EXPECT_EQ(CookieMonster::kMaxCookies - CookieMonster::kPurgeCookies,
            GetAllCookies(cm.get()).size());
}

// Test case where there are less than kMaxCookies - kPurgeCookies recent
// cookies. Enough old cookies should be deleted to reach kMaxCookies -
// kPurgeCookies total cookies, but no more. Some old cookies should be kept.
TEST_F(CookieMonsterTest, GarbageCollectionTriggers5) {
  std::unique_ptr<CookieMonster> cm = CreateMonsterFromStoreForGC(
      CookieMonster::kMaxCookies * 2 /* num_cookies */,
      CookieMonster::kMaxCookies * 3 / 2 /* num_old_cookies */, 0, 0,
      CookieMonster::kSafeFromGlobalPurgeDays * 2);
  EXPECT_EQ(CookieMonster::kMaxCookies * 2, GetAllCookies(cm.get()).size());
  // Will trigger GC.
  SetCookie(cm.get(), GURL("http://newdomain.com"), "b=2");
  EXPECT_EQ(CookieMonster::kMaxCookies - CookieMonster::kPurgeCookies,
            GetAllCookies(cm.get()).size());
}

// Tests garbage collection when there are only secure cookies.
// See https://crbug/730000
TEST_F(CookieMonsterTest, GarbageCollectWithSecureCookiesOnly) {
  // Create a CookieMonster at its cookie limit. A bit confusing, but the second
  // number is a subset of the first number.
  std::unique_ptr<CookieMonster> cm = CreateMonsterFromStoreForGC(
      CookieMonster::kMaxCookies /* num_secure_cookies */,
      CookieMonster::kMaxCookies /* num_old_secure_cookies */,
      0 /* num_non_secure_cookies */, 0 /* num_old_non_secure_cookies */,
      CookieMonster::kSafeFromGlobalPurgeDays * 2 /* days_old */);
  EXPECT_EQ(CookieMonster::kMaxCookies, GetAllCookies(cm.get()).size());

  // Trigger purge with a secure cookie (So there are still no insecure
  // cookies).
  SetCookie(cm.get(), GURL("https://newdomain.com"), "b=2; Secure");
  EXPECT_EQ(CookieMonster::kMaxCookies - CookieMonster::kPurgeCookies,
            GetAllCookies(cm.get()).size());
}

// Tests that if the main load event happens before the loaded event for a
// particular key, the tasks for that key run first.
TEST_F(CookieMonsterTest, WhileLoadingLoadCompletesBeforeKeyLoadCompletes) {
  const GURL kUrl = GURL(kTopLevelDomainPlus1);

  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  store->set_store_load_commands(true);
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  auto cookie =
      CanonicalCookie::CreateForTesting(kUrl, "a=b", base::Time::Now());
  ResultSavingCookieCallback<CookieAccessResult> set_cookie_callback;
  cm->SetCanonicalCookieAsync(std::move(cookie), kUrl,
                              CookieOptions::MakeAllInclusive(),
                              set_cookie_callback.MakeCallback());

  GetAllCookiesCallback get_cookies_callback1;
  cm->GetAllCookiesAsync(get_cookies_callback1.MakeCallback());

  // Two load events should have been queued.
  ASSERT_EQ(2u, store->commands().size());
  ASSERT_EQ(CookieStoreCommand::LOAD, store->commands()[0].type);
  ASSERT_EQ(CookieStoreCommand::LOAD_COOKIES_FOR_KEY,
            store->commands()[1].type);

  // The main load completes first (With no cookies).
  store->TakeCallbackAt(0).Run(std::vector<std::unique_ptr<CanonicalCookie>>());

  // The tasks should run in order, and the get should see the cookies.

  set_cookie_callback.WaitUntilDone();
  EXPECT_TRUE(set_cookie_callback.result().status.IsInclude());

  get_cookies_callback1.WaitUntilDone();
  EXPECT_EQ(1u, get_cookies_callback1.cookies().size());

  // The loaded for key event completes late, with not cookies (Since they
  // were already loaded).
  store->TakeCallbackAt(1).Run(std::vector<std::unique_ptr<CanonicalCookie>>());

  // The just set cookie should still be in the store.
  GetAllCookiesCallback get_cookies_callback2;
  cm->GetAllCookiesAsync(get_cookies_callback2.MakeCallback());
  get_cookies_callback2.WaitUntilDone();
  EXPECT_EQ(1u, get_cookies_callback2.cookies().size());
}

// Tests that case that DeleteAll is waiting for load to complete, and then a
// get is queued. The get should wait to run until after all the cookies are
// retrieved, and should return nothing, since all cookies were just deleted.
TEST_F(CookieMonsterTest, WhileLoadingDeleteAllGetForURL) {
  const GURL kUrl = GURL(kTopLevelDomainPlus1);

  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  store->set_store_load_commands(true);
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  ResultSavingCookieCallback<uint32_t> delete_callback;
  cm->DeleteAllAsync(delete_callback.MakeCallback());

  GetCookieListCallback get_cookie_list_callback;
  cm->GetCookieListWithOptionsAsync(kUrl, CookieOptions::MakeAllInclusive(),
                                    CookiePartitionKeyCollection(),
                                    get_cookie_list_callback.MakeCallback());

  // Only the main load should have been queued.
  ASSERT_EQ(1u, store->commands().size());
  ASSERT_EQ(CookieStoreCommand::LOAD, store->commands()[0].type);

  std::vector<std::unique_ptr<CanonicalCookie>> cookies;
  // When passed to the CookieMonster, it takes ownership of the pointed to
  // cookies.
  cookies.push_back(
      CanonicalCookie::CreateForTesting(kUrl, "a=b", base::Time::Now()));
  ASSERT_TRUE(cookies[0]);
  store->TakeCallbackAt(0).Run(std::move(cookies));

  delete_callback.WaitUntilDone();
  EXPECT_EQ(1u, delete_callback.result());

  get_cookie_list_callback.WaitUntilDone();
  EXPECT_EQ(0u, get_cookie_list_callback.cookies().size());
}

// Tests that a set cookie call sandwiched between two get all cookies, all
// before load completes, affects the first but not the second. The set should
// also not trigger a LoadCookiesForKey (As that could complete only after the
// main load for the store).
TEST_F(CookieMonsterTest, WhileLoadingGetAllSetGetAll) {
  const GURL kUrl = GURL(kTopLevelDomainPlus1);

  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  store->set_store_load_commands(true);
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  GetAllCookiesCallback get_cookies_callback1;
  cm->GetAllCookiesAsync(get_cookies_callback1.MakeCallback());

  auto cookie =
      CanonicalCookie::CreateForTesting(kUrl, "a=b", base::Time::Now());
  ResultSavingCookieCallback<CookieAccessResult> set_cookie_callback;
  cm->SetCanonicalCookieAsync(std::move(cookie), kUrl,
                              CookieOptions::MakeAllInclusive(),
                              set_cookie_callback.MakeCallback());

  GetAllCookiesCallback get_cookies_callback2;
  cm->GetAllCookiesAsync(get_cookies_callback2.MakeCallback());

  // Only the main load should have been queued.
  ASSERT_EQ(1u, store->commands().size());
  ASSERT_EQ(CookieStoreCommand::LOAD, store->commands()[0].type);

  // The load completes (With no cookies).
  store->TakeCallbackAt(0).Run(std::vector<std::unique_ptr<CanonicalCookie>>());

  get_cookies_callback1.WaitUntilDone();
  EXPECT_EQ(0u, get_cookies_callback1.cookies().size());

  set_cookie_callback.WaitUntilDone();
  EXPECT_TRUE(set_cookie_callback.result().status.IsInclude());

  get_cookies_callback2.WaitUntilDone();
  EXPECT_EQ(1u, get_cookies_callback2.cookies().size());
}

namespace {

void RunClosureOnAllCookiesReceived(base::OnceClosure closure,
                                    const CookieList& cookie_list) {
  std::move(closure).Run();
}

}  // namespace

// Tests that if a single cookie task is queued as a result of a task performed
// on all cookies when loading completes, it will be run after any already
// queued tasks.
TEST_F(CookieMonsterTest, CheckOrderOfCookieTaskQueueWhenLoadingCompletes) {
  const GURL kUrl = GURL(kTopLevelDomainPlus1);

  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  store->set_store_load_commands(true);
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  // Get all cookies task that queues a task to set a cookie when executed.
  auto cookie =
      CanonicalCookie::CreateForTesting(kUrl, "a=b", base::Time::Now());
  ResultSavingCookieCallback<CookieAccessResult> set_cookie_callback;
  cm->GetAllCookiesAsync(base::BindOnce(
      &RunClosureOnAllCookiesReceived,
      base::BindOnce(&CookieStore::SetCanonicalCookieAsync,
                     base::Unretained(cm.get()), std::move(cookie), kUrl,
                     CookieOptions::MakeAllInclusive(),
                     set_cookie_callback.MakeCallback(), std::nullopt)));

  // Get cookie task. Queued before the delete task is executed, so should not
  // see the set cookie.
  GetAllCookiesCallback get_cookies_callback1;
  cm->GetAllCookiesAsync(get_cookies_callback1.MakeCallback());

  // Only the main load should have been queued.
  ASSERT_EQ(1u, store->commands().size());
  ASSERT_EQ(CookieStoreCommand::LOAD, store->commands()[0].type);

  // The load completes.
  store->TakeCallbackAt(0).Run(std::vector<std::unique_ptr<CanonicalCookie>>());

  // The get cookies call should see no cookies set.
  get_cookies_callback1.WaitUntilDone();
  EXPECT_EQ(0u, get_cookies_callback1.cookies().size());

  set_cookie_callback.WaitUntilDone();
  EXPECT_TRUE(set_cookie_callback.result().status.IsInclude());

  // A subsequent get cookies call should see the new cookie.
  GetAllCookiesCallback get_cookies_callback2;
  cm->GetAllCookiesAsync(get_cookies_callback2.MakeCallback());
  get_cookies_callback2.WaitUntilDone();
  EXPECT_EQ(1u, get_cookies_callback2.cookies().size());
}

// Test that FlushStore() is forwarded to the store and callbacks are posted.
TEST_F(CookieMonsterTest, FlushStore) {
  auto counter = base::MakeRefCounted<CallbackCounter>();
  auto store = base::MakeRefCounted<FlushablePersistentStore>();
  auto cm = std::make_unique<CookieMonster>(store, net::NetLog::Get());

  ASSERT_EQ(0, store->flush_count());
  ASSERT_EQ(0, counter->callback_count());

  // Before initialization, FlushStore() should just run the callback.
  cm->FlushStore(base::BindOnce(&CallbackCounter::Callback, counter));
  base::RunLoop().RunUntilIdle();

  ASSERT_EQ(0, store->flush_count());
  ASSERT_EQ(1, counter->callback_count());

  // NULL callback is safe.
  cm->FlushStore(base::OnceClosure());
  base::RunLoop().RunUntilIdle();

  ASSERT_EQ(0, store->flush_count());
  ASSERT_EQ(1, counter->callback_count());

  // After initialization, FlushStore() should delegate to the store.
  GetAllCookies(cm.get());  // Force init.
  cm->FlushStore(base::BindOnce(&CallbackCounter::Callback, counter));
  base::RunLoop().RunUntilIdle();

  ASSERT_EQ(1, store->flush_count());
  ASSERT_EQ(2, counter->callback_count());

  // NULL callback is still safe.
  cm->FlushStore(base::DoNothing());
  base::RunLoop().RunUntilIdle();

  ASSERT_EQ(2, store->flush_count());
  ASSERT_EQ(2, counter->callback_count());

  // If there's no backing store, FlushStore() is always a safe no-op.
  cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());
  GetAllCookies(cm.get());  // Force init.
  cm->FlushStore(base::DoNothing());
  base::RunLoop().RunUntilIdle();

  ASSERT_EQ(2, counter->callback_count());

  cm->FlushStore(base::BindOnce(&CallbackCounter::Callback, counter));
  base::RunLoop().RunUntilIdle();

  ASSERT_EQ(3, counter->callback_count());
}

TEST_F(CookieMonsterTest, SetAllCookies) {
  auto store = base::MakeRefCounted<FlushablePersistentStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());
  cm->SetPersistSessionCookies(true);

  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "U=V; path=/"));
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "W=X; path=/foo"));
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "Y=Z; path=/"));

  CookieList list;
  list.push_back(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "B", "." + http_www_foo_.url().host(), "/", base::Time::Now(),
      base::Time(), base::Time(), base::Time(), false, false,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT));
  list.push_back(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "C", "D", "." + http_www_foo_.url().host(), "/bar", base::Time::Now(),
      base::Time(), base::Time(), base::Time(), false, false,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT));
  list.push_back(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "W", "X", "." + http_www_foo_.url().host(), "/", base::Time::Now(),
      base::Time(), base::Time(), base::Time(), false, false,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT));
  list.push_back(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "__Host-Y", "Z", https_www_foo_.url().host(), "/", base::Time::Now(),
      base::Time(), base::Time(), base::Time(), true, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com"))));
  // Expired cookie, should not be stored.
  list.push_back(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "expired", "foobar", https_www_foo_.url().host(), "/",
      base::Time::Now() - base::Days(1), base::Time::Now() - base::Days(2),
      base::Time(), base::Time(), /*secure=*/true, /*httponly=*/false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT));

  // SetAllCookies must not flush.
  ASSERT_EQ(0, store->flush_count());
  EXPECT_TRUE(SetAllCookies(cm.get(), list));
  EXPECT_EQ(0, store->flush_count());

  CookieList cookies = GetAllCookies(cm.get());
  size_t expected_size = 4;  // "A", "W" and "Y". "U" is gone.
  EXPECT_EQ(expected_size, cookies.size());
  auto it = cookies.begin();

  ASSERT_TRUE(it != cookies.end());
  EXPECT_EQ("C", it->Name());
  EXPECT_EQ("D", it->Value());
  EXPECT_EQ("/bar", it->Path());  // The path has been updated.

  ASSERT_TRUE(++it != cookies.end());
  EXPECT_EQ("A", it->Name());
  EXPECT_EQ("B", it->Value());

  ASSERT_TRUE(++it != cookies.end());
  EXPECT_EQ("W", it->Name());
  EXPECT_EQ("X", it->Value());

  ASSERT_TRUE(++it != cookies.end());
  EXPECT_EQ("__Host-Y", it->Name());
  EXPECT_EQ("Z", it->Value());

  cm = nullptr;
  auto entries = net_log_.GetEntries();
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::COOKIE_STORE_ALIVE, NetLogEventPhase::BEGIN);
  pos = ExpectLogContainsSomewhere(
      entries, pos, NetLogEventType::COOKIE_STORE_SESSION_PERSISTENCE,
      NetLogEventPhase::NONE);
  pos = ExpectLogContainsSomewhere(entries, pos,
                                   NetLogEventType::COOKIE_STORE_COOKIE_ADDED,
                                   NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(entries, pos, NetLogEventType::COOKIE_STORE_ALIVE,
                             NetLogEventPhase::END);
}

// Check that DeleteAll does flush (as a quick check that flush_count() works).
TEST_F(CookieMonsterTest, DeleteAll) {
  auto store = base::MakeRefCounted<FlushablePersistentStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());
  cm->SetPersistSessionCookies(true);

  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "X=Y; path=/"));

  ASSERT_EQ(0, store->flush_count());
  EXPECT_EQ(1u, DeleteAll(cm.get()));
  EXPECT_EQ(1, store->flush_count());

  cm = nullptr;
  auto entries = net_log_.GetEntries();
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::COOKIE_STORE_ALIVE, NetLogEventPhase::BEGIN);
  pos = ExpectLogContainsSomewhere(
      entries, pos, NetLogEventType::COOKIE_STORE_SESSION_PERSISTENCE,
      NetLogEventPhase::NONE);
  pos = ExpectLogContainsSomewhere(entries, pos,
                                   NetLogEventType::COOKIE_STORE_COOKIE_ADDED,
                                   NetLogEventPhase::NONE);
  pos = ExpectLogContainsSomewhere(entries, pos,
                                   NetLogEventType::COOKIE_STORE_COOKIE_DELETED,
                                   NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(entries, pos, NetLogEventType::COOKIE_STORE_ALIVE,
                             NetLogEventPhase::END);
}

TEST_F(CookieMonsterTest, HistogramCheck) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  // Should match call in InitializeHistograms, but doesn't really matter
  // since the histogram should have been initialized by the CM construction
  // above.
  base::HistogramBase* expired_histogram = base::Histogram::FactoryGet(
      "Cookie.ExpirationDurationMinutesSecure", 1, 10 * 365 * 24 * 60, 50,
      base::Histogram::kUmaTargetedHistogramFlag);

  std::unique_ptr<base::HistogramSamples> samples1(
      expired_histogram->SnapshotSamples());
  auto cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      "a", "b", "a.url", "/", base::Time(),
      base::Time::Now() + base::Minutes(59), base::Time(), base::Time(),
      /*secure=*/true,
      /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT);
  GURL source_url = cookie_util::SimulatedCookieSource(*cookie, "https");
  ASSERT_TRUE(SetCanonicalCookie(cm.get(), std::move(cookie), source_url,
                                 /*modify_httponly=*/true));

  std::unique_ptr<base::HistogramSamples> samples2(
      expired_histogram->SnapshotSamples());
  EXPECT_EQ(samples1->TotalCount() + 1, samples2->TotalCount());

  // kValidCookieLine creates a session cookie.
  ASSERT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), kValidCookieLine));

  std::unique_ptr<base::HistogramSamples> samples3(
      expired_histogram->SnapshotSamples());
  EXPECT_EQ(samples2->TotalCount(), samples3->TotalCount());
}

TEST_F(CookieMonsterTest, InvalidExpiryTime) {
  std::string cookie_line =
      std::string(kValidCookieLine) + "; expires=Blarg arg arg";
  std::unique_ptr<CanonicalCookie> cookie(CanonicalCookie::CreateForTesting(
      http_www_foo_.url(), cookie_line, Time::Now()));
  ASSERT_FALSE(cookie->IsPersistent());
}

// Test that CookieMonster writes session cookies into the underlying
// CookieStore if the "persist session cookies" option is on.
TEST_F(CookieMonsterTest, PersistSessionCookies) {
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());
  cm->SetPersistSessionCookies(true);

  // All cookies set with SetCookie are session cookies.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=B"));
  EXPECT_EQ("A=B", GetCookies(cm.get(), http_www_foo_.url()));

  // The cookie was written to the backing store.
  EXPECT_EQ(1u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::ADD, store->commands()[0].type);
  EXPECT_EQ("A", store->commands()[0].cookie.Name());
  EXPECT_EQ("B", store->commands()[0].cookie.Value());

  // Modify the cookie.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=C"));
  EXPECT_EQ("A=C", GetCookies(cm.get(), http_www_foo_.url()));
  EXPECT_EQ(3u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[1].type);
  EXPECT_EQ("A", store->commands()[1].cookie.Name());
  EXPECT_EQ("B", store->commands()[1].cookie.Value());
  EXPECT_EQ(CookieStoreCommand::ADD, store->commands()[2].type);
  EXPECT_EQ("A", store->commands()[2].cookie.Name());
  EXPECT_EQ("C", store->commands()[2].cookie.Value());

  // Delete the cookie. Using .host() here since it's a host and not domain
  // cookie.
  EXPECT_TRUE(FindAndDeleteCookie(cm.get(), http_www_foo_.host(), "A"));
  EXPECT_EQ("", GetCookies(cm.get(), http_www_foo_.url()));
  ASSERT_EQ(4u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[3].type);
  EXPECT_EQ("A", store->commands()[3].cookie.Name());
  EXPECT_EQ("C", store->commands()[3].cookie.Value());
}

// Test the commands sent to the persistent cookie store.
TEST_F(CookieMonsterTest, PersisentCookieStorageTest) {
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  // Add a cookie.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(),
                        "A=B" + FutureCookieExpirationString()));
  this->MatchCookieLines("A=B", GetCookies(cm.get(), http_www_foo_.url()));
  ASSERT_EQ(1u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::ADD, store->commands()[0].type);
  // Remove it.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "A=B; max-age=0"));
  this->MatchCookieLines(std::string(),
                         GetCookies(cm.get(), http_www_foo_.url()));
  ASSERT_EQ(2u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[1].type);

  // Add a cookie.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(),
                        "A=B" + FutureCookieExpirationString()));
  this->MatchCookieLines("A=B", GetCookies(cm.get(), http_www_foo_.url()));
  ASSERT_EQ(3u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::ADD, store->commands()[2].type);
  // Overwrite it.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(),
                        "A=Foo" + FutureCookieExpirationString()));
  this->MatchCookieLines("A=Foo", GetCookies(cm.get(), http_www_foo_.url()));
  ASSERT_EQ(5u, store->commands().size());
  EXPECT_EQ(CookieStoreCommand::REMOVE, store->commands()[3].type);
  EXPECT_EQ(CookieStoreCommand::ADD, store->commands()[4].type);

  // Create some non-persistent cookies and check that they don't go to the
  // persistent storage.
  EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), "B=Bar"));
  this->MatchCookieLines("A=Foo; B=Bar",
                         GetCookies(cm.get(), http_www_foo_.url()));
  EXPECT_EQ(5u, store->commands().size());
}

// Test to assure that cookies with control characters are purged appropriately.
// See http://crbug.com/238041 for background.
TEST_F(CookieMonsterTest, ControlCharacterPurge) {
  const Time now1(Time::Now());
  const Time now2(Time::Now() + base::Seconds(1));
  const Time now3(Time::Now() + base::Seconds(2));
  const Time now4(Time::Now() + base::Seconds(3));
  const Time later(now1 + base::Days(1));
  const GURL url("https://host/path");
  const std::string domain("host");
  const std::string path("/path");

  auto store = base::MakeRefCounted<MockPersistentCookieStore>();

  std::vector<std::unique_ptr<CanonicalCookie>> initial_cookies;

  AddCookieToList(url, "foo=bar; path=" + path, now1, &initial_cookies);

  // We have to manually build these cookies because they contain control
  // characters, and our cookie line parser rejects control characters.
  std::unique_ptr<CanonicalCookie> cc =
      CanonicalCookie::CreateUnsafeCookieForTesting(
          "baz",
          "\x05"
          "boo",
          "." + domain, path, now2, later, base::Time(), base::Time(),
          true /* secure */, false /* httponly */,
          CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT);
  initial_cookies.push_back(std::move(cc));

  std::unique_ptr<CanonicalCookie> cc2 =
      CanonicalCookie::CreateUnsafeCookieForTesting(
          "baz",
          "\x7F"
          "boo",
          "." + domain, path, now3, later, base::Time(), base::Time(),
          true /* secure */, false /* httponly */,
          CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT);
  initial_cookies.push_back(std::move(cc2));

  // Partitioned cookies with control characters should not be loaded.
  auto cookie_partition_key =
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com"));
  std::unique_ptr<CanonicalCookie> cc3 =
      CanonicalCookie::CreateUnsafeCookieForTesting(
          "__Host-baz",
          "\x7F"
          "boo",
          domain, "/", now3, later, base::Time(), base::Time(),
          true /* secure */, false /* httponly */,
          CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
          cookie_partition_key);
  initial_cookies.push_back(std::move(cc3));

  AddCookieToList(url, "hello=world; path=" + path, now4, &initial_cookies);

  // Inject our initial cookies into the mock PersistentCookieStore.
  store->SetLoadExpectation(true, std::move(initial_cookies));

  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  EXPECT_EQ("foo=bar; hello=world",
            GetCookies(cm.get(), url,
                       CookiePartitionKeyCollection(cookie_partition_key)));
}

// Test that inserting the first cookie for a key and deleting the last cookie
// for a key correctly reflected in the Cookie.NumKeys histogram.
TEST_F(CookieMonsterTest, NumKeysHistogram) {
  const char kHistogramName[] = "Cookie.NumKeys";

  // Test loading cookies from store.
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  std::vector<std::unique_ptr<CanonicalCookie>> initial_cookies;
  initial_cookies.push_back(CanonicalCookie::CreateForTesting(
      GURL("http://domain1.test"), "A=1", base::Time::Now()));
  initial_cookies.push_back(CanonicalCookie::CreateForTesting(
      GURL("http://domain2.test"), "A=1", base::Time::Now()));
  initial_cookies.push_back(CanonicalCookie::CreateForTesting(
      GURL("http://sub.domain2.test"), "A=1", base::Time::Now()));
  initial_cookies.push_back(CanonicalCookie::CreateForTesting(
      GURL("http://domain3.test"), "A=1", base::Time::Now()));
  initial_cookies.push_back(CanonicalCookie::CreateForTesting(
      GURL("http://domain3.test"), "B=1", base::Time::Now()));
  store->SetLoadExpectation(true /* return_value */,
                            std::move(initial_cookies));
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());
  {
    base::HistogramTester histogram_tester;
    // Access the cookies to trigger loading from the persistent store.
    EXPECT_EQ(5u, this->GetAllCookies(cm.get()).size());
    EXPECT_TRUE(cm->DoRecordPeriodicStatsForTesting());
    // There should be 3 keys: "domain1.test", "domain2.test", and
    // "domain3.test".
    histogram_tester.ExpectUniqueSample(kHistogramName, 3 /* sample */,
                                        1 /* count */);
  }

  // Test adding cookies for already existing key.
  {
    base::HistogramTester histogram_tester;
    EXPECT_TRUE(CreateAndSetCookie(cm.get(), GURL("https://domain1.test"),
                                   "B=1", CookieOptions::MakeAllInclusive()));
    EXPECT_TRUE(CreateAndSetCookie(cm.get(), GURL("http://sub.domain1.test"),
                                   "B=1", CookieOptions::MakeAllInclusive()));
    EXPECT_TRUE(cm->DoRecordPeriodicStatsForTesting());
    histogram_tester.ExpectUniqueSample(kHistogramName, 3 /* sample */,
                                        1 /* count */);
  }

  // Test adding a cookie for a new key.
  {
    base::HistogramTester histogram_tester;
    EXPECT_TRUE(CreateAndSetCookie(cm.get(), GURL("https://domain4.test"),
                                   "A=1", CookieOptions::MakeAllInclusive()));
    EXPECT_TRUE(cm->DoRecordPeriodicStatsForTesting());
    histogram_tester.ExpectUniqueSample(kHistogramName, 4 /* sample */,
                                        1 /* count */);
  }

  // Test overwriting the only cookie for a key. (Deletes and inserts, so the
  // total doesn't change.)
  {
    base::HistogramTester histogram_tester;
    EXPECT_TRUE(CreateAndSetCookie(cm.get(), GURL("https://domain4.test"),
                                   "A=2", CookieOptions::MakeAllInclusive()));
    EXPECT_TRUE(cm->DoRecordPeriodicStatsForTesting());
    histogram_tester.ExpectUniqueSample(kHistogramName, 4 /* sample */,
                                        1 /* count */);
  }

  // Test deleting cookie for a key with more than one cookie.
  {
    base::HistogramTester histogram_tester;
    EXPECT_TRUE(CreateAndSetCookie(cm.get(), GURL("https://domain2.test"),
                                   "A=1; Max-Age=0",
                                   CookieOptions::MakeAllInclusive()));
    EXPECT_TRUE(cm->DoRecordPeriodicStatsForTesting());
    histogram_tester.ExpectUniqueSample(kHistogramName, 4 /* sample */,
                                        1 /* count */);
  }

  // Test deleting cookie for a key with only one cookie.
  {
    base::HistogramTester histogram_tester;
    EXPECT_TRUE(CreateAndSetCookie(cm.get(), GURL("https://domain4.test"),
                                   "A=1; Max-Age=0",
                                   CookieOptions::MakeAllInclusive()));
    EXPECT_TRUE(cm->DoRecordPeriodicStatsForTesting());
    histogram_tester.ExpectUniqueSample(kHistogramName, 3 /* sample */,
                                        1 /* count */);
  }
}

TEST_F(CookieMonsterTest, CookieCount2Histogram) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  {
    base::HistogramTester histogram_tester;
    ASSERT_TRUE(cm->DoRecordPeriodicStatsForTesting());
    histogram_tester.ExpectUniqueSample("Cookie.Count2",
                                        /*sample=*/0,
                                        /*expected_bucket_count=*/1);
  }

  {
    base::HistogramTester histogram_tester;

    auto cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
        "a", "b", "a.url", "/", base::Time(),
        base::Time::Now() + base::Minutes(59), base::Time(), base::Time(),
        /*secure=*/true,
        /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
        COOKIE_PRIORITY_DEFAULT);
    GURL source_url = cookie_util::SimulatedCookieSource(*cookie, "https");
    ASSERT_TRUE(SetCanonicalCookie(cm.get(), std::move(cookie), source_url,
                                   /*modify_httponly=*/true));

    ASSERT_TRUE(cm->DoRecordPeriodicStatsForTesting());

    histogram_tester.ExpectUniqueSample("Cookie.Count2", /*sample=*/1,
                                        /*expected_bucket_count=*/1);
  }
}

TEST_F(CookieMons
```