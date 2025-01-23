Response:
The user wants a summary of the functionality of the provided C++ code snippet from `net/cookies/cookie_monster.cc`.

Here's a breakdown of the code and the thought process to generate the summary:

1. **Identify the Class:** The code is part of the `CookieMonster` class. This immediately tells us the code is related to managing cookies.

2. **Analyze the Methods:** Go through each method in the provided snippet and understand its purpose.

    * `DeleteCanonicalCookie`: Deletes a specific cookie. It checks if the cookie is partitioned and removes it from the appropriate map. It also verifies the cookie hasn't changed since it was retrieved.
    * `DeleteMatchingCookies`: Deletes cookies based on a provided predicate. It iterates through both regular and partitioned cookies, applying the predicate to each.
    * `MarkCookieStoreAsInitialized`: Sets a flag indicating the cookie store has been initialized.
    * `FetchAllCookiesIfNecessary`: Triggers the fetching of all cookies if it hasn't started yet.
    * `FetchAllCookies`: Starts the process of loading all cookies from the persistent store.
    * `OnLoaded`: Handles the completion of loading all cookies. It stores the loaded cookies, records timing metrics, and invokes queued tasks.
    * `OnKeyLoaded`: Handles the completion of loading cookies for a specific key. It stores the loaded cookies and runs tasks associated with that key.
    * `StoreLoadedCookies`: Inserts loaded cookies into the in-memory storage. It also checks for and deletes cookies with control characters.
    * `InvokeQueue`: Executes all pending cookie-related tasks.
    * `EnsureCookiesMapIsValid`: Checks for and removes duplicate cookies in the in-memory storage.
    * `TrimDuplicateCookiesForKey`: A helper function to find and delete duplicate cookies for a given host key.
    * `FindCookiesForRegistryControlledHost`: Finds non-expired cookies for a given host, deleting expired ones.
    * `FindPartitionedCookiesForRegistryControlledHost`: Finds partitioned cookies for a given host and partition key.
    * `FilterCookiesWithOptions`: Filters cookies based on provided options (like HTTP-only) and records access statistics. It also handles domain cookie shadowing.
    * `MaybeDeleteEquivalentCookieAndUpdateStatus`: Checks for and potentially deletes an equivalent cookie before setting a new one. It handles secure cookie overwriting restrictions and logs relevant events.
    * `InternalInsertCookie`: Inserts a cookie into the in-memory storage and optionally syncs it to the persistent store.
    * `ShouldUpdatePersistentStore`: Determines if a cookie should be persisted.
    * `InternalInsertPartitionedCookie`: Inserts a partitioned cookie into the in-memory storage and optionally syncs it.

3. **Identify Core Functionalities:** Group the methods based on the actions they perform. Key functionalities that emerge are:
    * Deleting cookies (specific or matching criteria)
    * Loading cookies (all or for a specific key)
    * Storing cookies (including handling duplicates and control characters)
    * Filtering cookies based on various criteria
    * Managing partitioned cookies
    * Handling secure cookie overwriting
    * Queueing and executing tasks

4. **Check for JavaScript Interaction:**  While this specific snippet doesn't directly interact with JavaScript, the comments mention "getter" methods. This hints that JavaScript (or other parts of the browser) might retrieve cookie information which could then be used in deletion operations. Specifically, `DeleteCanonicalCookie` checks if the cookie's value has changed since a "getter" returned it.

5. **Look for Logic and Assumptions:**  The code makes assumptions about the structure of the `CookieMap` and `PartitionedCookieMap`. The `DeleteCanonicalCookie` method assumes that if a cookie is found to be equivalent but the value has changed, something unexpected has happened.

6. **Identify Potential User/Programming Errors:** The check in `DeleteCanonicalCookie` for a changed cookie value suggests a potential programming error where a stale `CanonicalCookie` object is being used for deletion. Also, trying to overwrite a secure cookie from a non-secure context is handled and could be considered a user/programming error the browser prevents.

7. **Consider User Operations as Debugging Clues:** Think about how user actions lead to these functions being called. Deleting a cookie from browser settings, clearing browsing data, or a website attempting to delete a cookie via JavaScript (`document.cookie = ...; expires=...`) are all potential triggers. The loading functions are triggered when the browser starts or when cookie data needs to be accessed.

8. **Synthesize the Summary:** Combine the identified functionalities into a concise summary. Emphasize the core purpose of managing cookies, including deletion, loading, and filtering. Highlight the handling of partitioned cookies and security considerations.

9. **Address the "Part 2" Instruction:**  The request specifically asks to summarize the provided part. Focus only on the methods within this snippet and avoid bringing in information from the other (missing) parts.

By following this process, we can arrive at a comprehensive summary that addresses the user's request, including the specific aspects of JavaScript interaction, logical assumptions, potential errors, and debugging context.
这是 `net/cookies/cookie_monster.cc` 文件中 `CookieMonster` 类的第二部分代码，主要关注于**删除 Cookie、加载 Cookie 数据以及保证 Cookie 数据一致性**的功能。

以下是该部分代码功能的详细归纳：

**1. Cookie 删除功能：**

* **`DeleteCanonicalCookie(const CanonicalCookie& cookie, DeleteCallback callback)`:**
    * **功能:**  删除指定的 `CanonicalCookie`。
    * **逻辑推理（假设输入与输出）:**
        * **假设输入:** 一个 `CanonicalCookie` 对象，例如表示域名为 "example.com"，名称为 "test"，值为 "123" 的 Cookie。
        * **输出:**  如果该 Cookie 存在于 `CookieMonster` 的内部存储中，则将其删除，并在成功删除后调用 `callback`。如果不存在，则不进行任何操作。
        * **内部逻辑:**  首先根据 Cookie 是否是 partitioned 来确定在哪个内部存储结构（`cookies_` 或 `partitioned_cookies_`）中查找。找到匹配的 Cookie 后，会再次校验其值是否与传入的 `cookie` 对象的值一致，防止在获取 Cookie 对象到删除期间 Cookie 值被修改。
    * **与 JavaScript 的关系:** JavaScript 可以通过 `document.cookie = "name=; expires=Thu, 01 Jan 1970 00:00:00 UTC;"` 的方式来请求浏览器删除 Cookie。浏览器接收到这个请求后，最终可能会调用到 `CookieMonster::DeleteCanonicalCookie` 来执行实际的删除操作。
    * **用户操作如何到达这里 (调试线索):**
        1. 用户在浏览器地址栏输入或访问一个网页。
        2. 网页的 JavaScript 代码执行，并设置了删除 Cookie 的 `document.cookie` 命令。
        3. 浏览器解析该命令，并识别出需要删除的 Cookie。
        4. 浏览器网络栈将删除请求传递给 `CookieMonster`，并调用 `DeleteCanonicalCookie`。

* **`DeleteMatchingCookies(DeletePredicate predicate, DeletionCause cause, DeleteCallback callback)`:**
    * **功能:**  根据提供的 `predicate`（谓词）删除所有匹配的 Cookie。
    * **逻辑推理（假设输入与输出）:**
        * **假设输入:** 一个 `DeletePredicate`，例如一个 Lambda 表达式，用于判断 Cookie 的域名是否包含 ".example.com"。
        * **输出:** 删除所有域名包含 ".example.com" 的 Cookie，并在删除完成后调用 `callback` 并传入删除的 Cookie 数量。
        * **内部逻辑:** 遍历 `cookies_` 和 `partitioned_cookies_` 中的所有 Cookie，对每个 Cookie 执行 `predicate.Run(*cc)`，如果返回 `true`，则删除该 Cookie。
    * **与 JavaScript 的关系:**  虽然 JavaScript 不能直接指定复杂的谓词来删除 Cookie，但浏览器的一些内部功能，例如清除特定站点的浏览数据，可能会使用类似的谓词来删除 Cookie。
    * **用户操作如何到达这里 (调试线索):**
        1. 用户在浏览器设置中选择清除浏览数据。
        2. 用户选择了清除 Cookie 并且可能指定了特定的网站。
        3. 浏览器内部根据用户的选择构建相应的 `DeletePredicate`。
        4. `CookieMonster::DeleteMatchingCookies` 被调用来执行删除操作。

**2. Cookie 加载和初始化功能：**

* **`MarkCookieStoreAsInitialized()`:**
    * **功能:**  标记 Cookie 存储已初始化完成。
    * **与 JavaScript 的关系:**  没有直接关系。这是一个内部状态管理。
* **`FetchAllCookiesIfNecessary()`:**
    * **功能:**  如果需要，启动加载所有 Cookie 的流程。
    * **内部逻辑:** 检查是否已经启动了加载所有 Cookie 的流程 (`started_fetching_all_cookies_`)，如果没有并且存在持久化存储 (`store_.get()`)，则启动加载。
    * **用户操作如何到达这里 (调试线索):**  浏览器启动时，`CookieMonster` 可能被创建，并会调用此方法来确保 Cookie 数据被加载。
* **`FetchAllCookies()`:**
    * **功能:**  从持久化存储中加载所有 Cookie。
    * **内部逻辑:** 调用 `store_->Load()` 方法来异步加载所有 Cookie。
* **`OnLoaded(TimeTicks beginning_time, std::vector<std::unique_ptr<CanonicalCookie>> cookies)`:**
    * **功能:**  当所有 Cookie 从持久化存储加载完成后被调用。
    * **内部逻辑:**  调用 `StoreLoadedCookies` 来处理加载的 Cookie，并记录加载时间等统计信息。然后调用 `InvokeQueue` 来执行等待处理的 Cookie 操作。
* **`OnKeyLoaded(const std::string& key, std::vector<std::unique_ptr<CanonicalCookie>> cookies)`:**
    * **功能:**  当特定域名的 Cookie 从持久化存储加载完成后被调用 (可能用于优化加载)。
    * **内部逻辑:**  将加载的 Cookie 存储起来，并执行与该域名相关的等待处理的 Cookie 操作。
* **`StoreLoadedCookies(std::vector<std::unique_ptr<CanonicalCookie>> cookies)`:**
    * **功能:**  将加载的 Cookie 存储到内部的 `cookies_` 和 `partitioned_cookies_` 容器中。
    * **内部逻辑:** 遍历加载的 Cookie，根据是否是 partitioned 调用 `InternalInsertPartitionedCookie` 或 `InternalInsertCookie` 进行插入。同时，会检查并删除包含控制字符的 Cookie。加载完成后会调用 `EnsureCookiesMapIsValid` 检查数据一致性。
    * **用户操作如何到达这里 (调试线索):**  这是 `OnLoaded` 和 `OnKeyLoaded` 的回调，因此与浏览器启动和 Cookie 加载流程相关。

**3. Cookie 数据一致性保证功能：**

* **`InvokeQueue()`:**
    * **功能:**  执行所有等待处理的 Cookie 操作任务队列。
    * **内部逻辑:** 将按域名分组的任务合并到全局队列，并依次执行。
* **`EnsureCookiesMapIsValid()`:**
    * **功能:**  遍历内部的 Cookie 存储，检查并删除重复的 Cookie，保证数据的一致性。
    * **内部逻辑:**  遍历 `cookies_` 和 `partitioned_cookies_`，按域名分组，并调用 `TrimDuplicateCookiesForKey` 来删除重复的 Cookie。
* **`TrimDuplicateCookiesForKey(const std::string& key, CookieMap::iterator begin, CookieMap::iterator end, std::optional<PartitionedCookieMap::iterator> cookie_partition_it)`:**
    * **功能:**  辅助函数，用于查找并删除特定域名下的重复 Cookie。
    * **内部逻辑:**  创建一个映射，将 Cookie 的唯一键映射到具有相同键的 Cookie 列表（按创建时间倒序排序）。然后遍历这些列表，保留创建时间最新的 Cookie，删除其余的重复 Cookie。

**4. Cookie 查找功能：**

* **`FindCookiesForRegistryControlledHost(const GURL& url, CookieMap* cookie_map, CookieMonster::PartitionedCookieMap::iterator* partition_it)`:**
    * **功能:**  查找指定域名下所有未过期的 Cookie。
    * **内部逻辑:**  在提供的 `cookie_map` 中查找指定域名的 Cookie，并删除已过期的 Cookie。
* **`FindPartitionedCookiesForRegistryControlledHost(const CookiePartitionKey& cookie_partition_key, const GURL& url)`:**
    * **功能:**  查找指定 Cookie Partition Key 和域名下所有未过期的 partitioned Cookie。
    * **内部逻辑:**  先根据 `cookie_partition_key` 找到对应的 partitioned Cookie 存储，然后调用 `FindCookiesForRegistryControlledHost` 进行查找。

**5. Cookie 过滤功能：**

* **`FilterCookiesWithOptions(const GURL& url, const CookieOptions options, std::vector<CanonicalCookie*>* cookie_ptrs, CookieAccessResultList* included_cookies, CookieAccessResultList* excluded_cookies)`:**
    * **功能:**  根据提供的 `CookieOptions` 过滤 Cookie。
    * **内部逻辑:**  遍历提供的 Cookie 指针列表，根据 `CookieOptions`（例如是否允许 HTTP-only Cookie、是否需要 secure Cookie 等）判断 Cookie 是否应该被包含。同时会记录 Cookie 的访问统计信息，并处理 domain cookie shadowing 的情况。
    * **与 JavaScript 的关系:** 当 JavaScript 通过 `document.cookie` 获取 Cookie 时，浏览器会调用类似的过滤逻辑来决定哪些 Cookie 可以被返回给 JavaScript。
    * **用户操作如何到达这里 (调试线索):**
        1. 用户访问一个网页。
        2. 网页的 JavaScript 代码尝试通过 `document.cookie` 获取 Cookie。
        3. 浏览器网络栈调用 `CookieMonster` 的相关方法来获取匹配的 Cookie，并使用 `FilterCookiesWithOptions` 进行过滤。

**6. Cookie 设置前的检查和更新功能：**

* **`MaybeDeleteEquivalentCookieAndUpdateStatus(const std::string& key, const CanonicalCookie& cookie_being_set, bool allowed_to_set_secure_cookie, bool skip_httponly, bool already_expired, base::Time* creation_date_to_inherit, CookieInclusionStatus* status, std::optional<PartitionedCookieMap::iterator> cookie_partition_it)`:**
    * **功能:**  在设置新 Cookie 之前，检查是否存在等价的 Cookie，并根据情况删除旧的 Cookie，并更新设置操作的状态。
    * **内部逻辑:**  查找与即将设置的 Cookie 等价的现有 Cookie。如果存在，根据 secure 和 httponly 属性以及设置的上下文来决定是否应该删除现有 Cookie。如果删除，则记录删除原因。
    * **编程常见的使用错误:**
        * **尝试在非安全上下文（HTTP）下覆盖一个 secure Cookie。** `MaybeDeleteEquivalentCookieAndUpdateStatus` 会检查 `allowed_to_set_secure_cookie`，如果为 `false` 且存在等价的 secure Cookie，则不会覆盖，并设置 `status` 的相应错误码 (`EXCLUDE_OVERWRITE_SECURE`).
        * **尝试用非 HTTP-only 的 Cookie 覆盖一个 HTTP-only 的 Cookie。** 如果 `skip_httponly` 为 `true` 且存在等价的 HTTP-only Cookie，则不会覆盖，并设置 `status` 的相应错误码 (`EXCLUDE_OVERWRITE_HTTP_ONLY`).
    * **与 JavaScript 的关系:** 当 JavaScript 通过 `document.cookie = "name=value"` 设置 Cookie 时，会触发此处的逻辑。
    * **用户操作如何到达这里 (调试线索):**
        1. 用户在浏览器地址栏输入或访问一个网页。
        2. 网页的 JavaScript 代码执行，并设置了新的 Cookie 或尝试修改现有 Cookie 的值。
        3. 浏览器解析该命令，并识别出需要设置的 Cookie。
        4. 浏览器网络栈将设置请求传递给 `CookieMonster`，并调用相关方法，最终可能会调用到 `MaybeDeleteEquivalentCookieAndUpdateStatus`。

**7. Cookie 插入功能：**

* **`InternalInsertCookie(const std::string& key, std::unique_ptr<CanonicalCookie> cc, bool sync_to_store, const CookieAccessResult& access_result, bool dispatch_change)`:**
    * **功能:**  将一个 Cookie 插入到内部的 `cookies_` 容器中。
    * **内部逻辑:**  将 Cookie 添加到 `cookies_` 中，如果 `sync_to_store` 为 `true` 且需要持久化，则会同步到持久化存储。同时会记录 Cookie 存储的 UMA 指标，并分发 Cookie 变更通知。
* **`ShouldUpdatePersistentStore(CanonicalCookie* cc)`:**
    * **功能:**  判断一个 Cookie 是否应该被持久化存储。
    * **内部逻辑:**  如果 Cookie 是持久化的，或者启用了会话 Cookie 的持久化，并且存在持久化存储，则返回 `true`。
* **`InternalInsertPartitionedCookie(std::string key, std::unique_ptr<CanonicalCookie> cc, bool sync_to_store, const CookieAccessResult& access_result, bool dispatch_change)`:**
    * **功能:**  将一个 partitioned Cookie 插入到内部的 `partitioned_cookies_` 容器中。
    * **内部逻辑:** 类似 `InternalInsertCookie`，但操作的是 `partitioned_cookies_` 容器。还会更新 partitioned Cookie 的字节数统计。

**总结该部分的功能:**

这部分 `CookieMonster` 代码的核心功能在于**管理 Cookie 的生命周期，特别是删除和加载 Cookie，并确保 Cookie 数据在内存中的一致性**。 它处理了从持久化存储加载 Cookie，根据不同条件删除 Cookie，以及在设置新 Cookie 前进行必要的检查和清理工作。 同时，它也负责维护内部数据结构的一致性，防止重复 Cookie 的存在。 此外，还包含了对 partitioned Cookie 的处理。这些功能共同支撑了浏览器网络栈中 Cookie 的核心管理逻辑。

### 提示词
```
这是目录为net/cookies/cookie_monster.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
delegate_treats_url_as_trustworthy});
}

void CookieMonster::DeleteCanonicalCookie(const CanonicalCookie& cookie,
                                          DeleteCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  uint32_t result = 0u;
  CookieMap* cookie_map = nullptr;
  PartitionedCookieMap::iterator cookie_partition_it;

  if (cookie.IsPartitioned()) {
    cookie_partition_it =
        partitioned_cookies_.find(cookie.PartitionKey().value());
    if (cookie_partition_it != partitioned_cookies_.end())
      cookie_map = cookie_partition_it->second.get();
  } else {
    cookie_map = &cookies_;
  }
  if (cookie_map) {
    for (CookieMapItPair its = cookie_map->equal_range(GetKey(cookie.Domain()));
         its.first != its.second; ++its.first) {
      const std::unique_ptr<CanonicalCookie>& candidate = its.first->second;
      // Historically, this has refused modification if the cookie has changed
      // value in between the CanonicalCookie object was returned by a getter
      // and when this ran.  The later parts of the conditional (everything but
      // the equivalence check) attempt to preserve this behavior.
      if (candidate->IsEquivalent(cookie) &&
          candidate->Value() == cookie.Value()) {
        if (cookie.IsPartitioned()) {
          InternalDeletePartitionedCookie(cookie_partition_it, its.first, true,
                                          DELETE_COOKIE_EXPLICIT);
        } else {
          InternalDeleteCookie(its.first, true, DELETE_COOKIE_EXPLICIT);
        }
        result = 1u;
        break;
      }
    }
  }
  FlushStore(
      base::BindOnce(&MaybeRunDeleteCallback, weak_ptr_factory_.GetWeakPtr(),
                     callback ? base::BindOnce(std::move(callback), result)
                              : base::OnceClosure()));
}

void CookieMonster::DeleteMatchingCookies(DeletePredicate predicate,
                                          DeletionCause cause,
                                          DeleteCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(predicate);

  uint32_t num_deleted = 0;
  for (auto it = cookies_.begin(); it != cookies_.end();) {
    auto curit = it;
    CanonicalCookie* cc = curit->second.get();
    ++it;
    if (predicate.Run(*cc)) {
      InternalDeleteCookie(curit, true /*sync_to_store*/, cause);
      ++num_deleted;
    }
  }
  for (auto partition_it = partitioned_cookies_.begin();
       partition_it != partitioned_cookies_.end();) {
    // InternalDeletePartitionedCookie may invalidate |partition_it| if that
    // cookie partition only has one cookie.
    auto cur_partition_it = partition_it;
    CookieMap::iterator cookie_it = cur_partition_it->second->begin();
    CookieMap::iterator cookie_end = cur_partition_it->second->end();
    ++partition_it;

    while (cookie_it != cookie_end) {
      auto cur_cookie_it = cookie_it;
      CanonicalCookie* cc = cur_cookie_it->second.get();
      ++cookie_it;

      if (predicate.Run(*cc)) {
        InternalDeletePartitionedCookie(cur_partition_it, cur_cookie_it, true,
                                        cause);
        ++num_deleted;
      }
    }
  }

  FlushStore(
      base::BindOnce(&MaybeRunDeleteCallback, weak_ptr_factory_.GetWeakPtr(),
                     callback ? base::BindOnce(std::move(callback), num_deleted)
                              : base::OnceClosure()));
}

void CookieMonster::MarkCookieStoreAsInitialized() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  initialized_ = true;
}

void CookieMonster::FetchAllCookiesIfNecessary() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (store_.get() && !started_fetching_all_cookies_) {
    started_fetching_all_cookies_ = true;
    FetchAllCookies();
  }
}

void CookieMonster::FetchAllCookies() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(store_.get()) << "Store must exist to initialize";
  DCHECK(!finished_fetching_all_cookies_)
      << "All cookies have already been fetched.";

  // We bind in the current time so that we can report the wall-clock time for
  // loading cookies.
  store_->Load(base::BindOnce(&CookieMonster::OnLoaded,
                              weak_ptr_factory_.GetWeakPtr(), TimeTicks::Now()),
               net_log_);
}

void CookieMonster::OnLoaded(
    TimeTicks beginning_time,
    std::vector<std::unique_ptr<CanonicalCookie>> cookies) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  StoreLoadedCookies(std::move(cookies));
  base::TimeTicks now = base::TimeTicks::Now();
  base::UmaHistogramCustomTimes("Cookie.TimeBlockedOnLoad",
                                now - beginning_time, base::Milliseconds(1),
                                base::Minutes(1), 50);
  base::TimeDelta blocked_due_to_global_op = base::Milliseconds(0);
  if (time_start_block_load_all_.has_value()) {
    blocked_due_to_global_op = now - *time_start_block_load_all_;
  }

  base::UmaHistogramCustomTimes("Cookie.TimeOpsBlockedDueToGlobalOp",
                                blocked_due_to_global_op, base::Milliseconds(1),
                                base::Minutes(1), 50);

  // Invoke the task queue of cookie request.
  InvokeQueue();
}

void CookieMonster::OnKeyLoaded(
    const std::string& key,
    std::vector<std::unique_ptr<CanonicalCookie>> cookies) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  StoreLoadedCookies(std::move(cookies));

  auto tasks_pending_for_key = tasks_pending_for_key_.find(key);

  // TODO(mmenke): Can this be turned into a DCHECK?
  if (tasks_pending_for_key == tasks_pending_for_key_.end())
    return;

  // Run all tasks for the key. Note that running a task can result in multiple
  // tasks being added to the back of the deque.
  while (!tasks_pending_for_key->second.empty()) {
    base::OnceClosure task = std::move(tasks_pending_for_key->second.front());
    tasks_pending_for_key->second.pop_front();
    std::move(task).Run();
  }

  tasks_pending_for_key_.erase(tasks_pending_for_key);

  // This has to be done last, in case running a task queues a new task for the
  // key, to ensure tasks are run in the correct order.
  keys_loaded_.insert(key);
}

void CookieMonster::StoreLoadedCookies(
    std::vector<std::unique_ptr<CanonicalCookie>> cookies) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Even if a key is expired, insert it so it can be garbage collected,
  // removed, and sync'd.
  CookieItVector cookies_with_control_chars;
  std::vector<PartitionedCookieMapIterators>
      partitioned_cookies_with_control_chars;

  for (auto& cookie : cookies) {
    CanonicalCookie* cookie_ptr = cookie.get();
    CookieAccessResult access_result;
    access_result.access_semantics = CookieAccessSemantics::UNKNOWN;

    if (cookie_ptr->IsPartitioned()) {
      auto inserted = InternalInsertPartitionedCookie(
          GetKey(cookie_ptr->Domain()), std::move(cookie),
          false /* sync_to_store */, access_result,
          false /* dispatch_change */);
      if (ContainsControlCharacter(cookie_ptr->Name()) ||
          ContainsControlCharacter(cookie_ptr->Value())) {
        partitioned_cookies_with_control_chars.push_back(inserted);
      }
    } else {
      auto inserted =
          InternalInsertCookie(GetKey(cookie_ptr->Domain()), std::move(cookie),
                               false /* sync_to_store */, access_result,
                               false /* dispatch_change */);

      if (ContainsControlCharacter(cookie_ptr->Name()) ||
          ContainsControlCharacter(cookie_ptr->Value())) {
        cookies_with_control_chars.push_back(inserted);
      }
    }

    const Time cookie_access_time(cookie_ptr->LastAccessDate());
    if (earliest_access_time_.is_null() ||
        cookie_access_time < earliest_access_time_) {
      earliest_access_time_ = cookie_access_time;
    }
  }

  // Any cookies that contain control characters that we have loaded from the
  // persistent store should be deleted. See http://crbug.com/238041.
  for (auto it = cookies_with_control_chars.begin();
       it != cookies_with_control_chars.end();) {
    auto curit = it;
    ++it;
    InternalDeleteCookie(*curit, true, DELETE_COOKIE_CONTROL_CHAR);
  }
  for (auto it = partitioned_cookies_with_control_chars.begin();
       it != partitioned_cookies_with_control_chars.end();) {
    // InternalDeletePartitionedCookie may invalidate the current iterator, so
    // we increment the iterator in the loop before calling the function.
    auto curit = it;
    ++it;
    InternalDeletePartitionedCookie(curit->first, curit->second, true,
                                    DELETE_COOKIE_CONTROL_CHAR);
  }

  // After importing cookies from the PersistentCookieStore, verify that
  // none of our other constraints are violated.
  // In particular, the backing store might have given us duplicate cookies.

  // This method could be called multiple times due to priority loading, thus
  // cookies loaded in previous runs will be validated again, but this is OK
  // since they are expected to be much fewer than total DB.
  EnsureCookiesMapIsValid();
}

void CookieMonster::InvokeQueue() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Move all per-key tasks into the global queue, if there are any.  This is
  // protection about a race where the store learns about all cookies loading
  // before it learned about the cookies for a key loading.

  // Needed to prevent any recursively queued tasks from going back into the
  // per-key queues.
  seen_global_task_ = true;
  for (auto& tasks_for_key : tasks_pending_for_key_) {
    tasks_pending_.insert(tasks_pending_.begin(),
                          std::make_move_iterator(tasks_for_key.second.begin()),
                          std::make_move_iterator(tasks_for_key.second.end()));
  }
  tasks_pending_for_key_.clear();

  while (!tasks_pending_.empty()) {
    base::OnceClosure request_task = std::move(tasks_pending_.front());
    tasks_pending_.pop_front();
    std::move(request_task).Run();
  }

  DCHECK(tasks_pending_for_key_.empty());

  finished_fetching_all_cookies_ = true;
  keys_loaded_.clear();
}

void CookieMonster::EnsureCookiesMapIsValid() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Iterate through all the of the cookies, grouped by host.
  for (auto next = cookies_.begin(); next != cookies_.end();) {
    auto cur_range_begin = next;
    const std::string key = cur_range_begin->first;  // Keep a copy.
    auto cur_range_end = cookies_.upper_bound(key);
    next = cur_range_end;

    // Ensure no equivalent cookies for this host.
    TrimDuplicateCookiesForKey(key, cur_range_begin, cur_range_end,
                               std::nullopt);
  }

  for (auto cookie_partition_it = partitioned_cookies_.begin();
       cookie_partition_it != partitioned_cookies_.end();) {
    auto cur_cookie_partition_it = cookie_partition_it;
    ++cookie_partition_it;

    // Iterate through the cookies in this partition, grouped by host.
    CookieMap* cookie_partition = cur_cookie_partition_it->second.get();
    auto prev_range_end = cookie_partition->begin();
    while (prev_range_end != cookie_partition->end()) {
      auto cur_range_begin = prev_range_end;
      const std::string key = cur_range_begin->first;  // Keep a copy.
      auto cur_range_end = cookie_partition->upper_bound(key);
      prev_range_end = cur_range_end;

      // Ensure no equivalent cookies for this host and cookie partition key.
      TrimDuplicateCookiesForKey(key, cur_range_begin, cur_range_end,
                                 std::make_optional(cur_cookie_partition_it));
    }
  }
}

// Our strategy to find duplicates is:
// (1) Build a map from cookie unique key to
//     {list of cookies with this signature, sorted by creation time}.
// (2) For each list with more than 1 entry, keep the cookie having the
//     most recent creation time, and delete the others.
//
void CookieMonster::TrimDuplicateCookiesForKey(
    const std::string& key,
    CookieMap::iterator begin,
    CookieMap::iterator end,
    std::optional<PartitionedCookieMap::iterator> cookie_partition_it) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Set of cookies ordered by creation time.
  typedef std::multiset<CookieMap::iterator, OrderByCreationTimeDesc> CookieSet;

  // Helper map we populate to find the duplicates.
  typedef std::map<CanonicalCookie::UniqueCookieKey, CookieSet> EquivalenceMap;
  typedef std::map<CanonicalCookie::UniqueDomainCookieKey, CookieSet>
      DomainEquivalenceMap;
  EquivalenceMap equivalent_cookies;
  DomainEquivalenceMap equivalent_domain_cookies;

  // The number of duplicate cookies that have been found.
  int num_duplicates = 0;
  int num_domain_duplicates = 0;

  // Iterate through all of the cookies in our range, and insert them into
  // the equivalence map.
  for (auto it = begin; it != end; ++it) {
    DCHECK_EQ(key, it->first);
    CanonicalCookie* cookie = it->second.get();

    if (cookie->IsHostCookie()) {
      CanonicalCookie::UniqueCookieKey signature(cookie->UniqueKey());
      CookieSet& set = equivalent_cookies[signature];

      // We found a duplicate!
      if (!set.empty()) {
        num_duplicates++;
      }

      // We save the iterator into |cookies_| rather than the actual cookie
      // pointer, since we may need to delete it later.
      set.insert(it);
    }
    // Is a domain cookie.
    else {
      CanonicalCookie::UniqueDomainCookieKey signature(
          cookie->UniqueDomainKey());
      CookieSet& domain_set = equivalent_domain_cookies[signature];

      // We found a duplicate!
      if (!domain_set.empty()) {
        num_domain_duplicates++;
      }

      // We save the iterator into |cookies_| rather than the actual cookie
      // pointer, since we may need to delete it later.
      domain_set.insert(it);
    }
  }

  // If there were no duplicates, we are done!
  if (num_duplicates == 0 && num_domain_duplicates == 0) {
    return;
  }

  // Make sure we find everything below that we did above.
  int num_duplicates_found = 0;

  // Otherwise, delete all the duplicate host cookies, both from our in-memory
  // store and from the backing store.
  for (std::pair<const CanonicalCookie::UniqueCookieKey, CookieSet>&
           equivalent_cookie : equivalent_cookies) {
    const CanonicalCookie::UniqueCookieKey& signature = equivalent_cookie.first;
    CookieSet& dupes = equivalent_cookie.second;

    if (dupes.size() <= 1) {
      continue;  // This cookiename/path has no duplicates.
    }

    num_duplicates_found += dupes.size() - 1;

    // Since |dupes| is sorted by creation time (descending), the first cookie
    // is the most recent one (or tied for it), so we will keep it. The rest are
    // duplicates.
    dupes.erase(dupes.begin());

    // TODO(crbug.com/40188414) Include cookie partition key in this log
    // statement as well if needed.
    // TODO(crbug.com/40165805): Include source scheme and source port.
    LOG(ERROR) << base::StringPrintf(
        "Found %d duplicate cookies for key='%s', "
        "with {name='%s', domain='%s', path='%s'}",
        static_cast<int>(dupes.size()), key.c_str(),
        std::get<1>(signature).c_str(), std::get<2>(signature).c_str(),
        std::get<3>(signature).c_str());

    // Remove all the cookies identified by |dupes|. It is valid to delete our
    // list of iterators one at a time, since |cookies_| is a multimap (they
    // don't invalidate existing iterators following deletion).
    for (const CookieMap::iterator& dupe : dupes) {
      if (cookie_partition_it) {
        InternalDeletePartitionedCookie(
            cookie_partition_it.value(), dupe, true,
            DELETE_COOKIE_DUPLICATE_IN_BACKING_STORE);
      } else {
        InternalDeleteCookie(dupe, true,
                             DELETE_COOKIE_DUPLICATE_IN_BACKING_STORE);
      }
    }
  }
  CHECK_EQ(num_duplicates, num_duplicates_found);

  // Do the same again for domain cookies.

  if (num_domain_duplicates == 0) {
    return;
  }

  int num_domain_duplicates_found = 0;

  for (std::pair<const CanonicalCookie::UniqueDomainCookieKey, CookieSet>&
           equivalent_domain_cookie : equivalent_domain_cookies) {
    const CanonicalCookie::UniqueDomainCookieKey& signature =
        equivalent_domain_cookie.first;
    CookieSet& dupes = equivalent_domain_cookie.second;

    if (dupes.size() <= 1) {
      continue;
    }

    num_domain_duplicates_found += dupes.size() - 1;

    // Since |dupes| is sorted by creation time (descending), the first cookie
    // is the most recent one (or tied for it), so we will keep it. The rest are
    // duplicates.
    dupes.erase(dupes.begin());

    // TODO(crbug.com/40188414) Include cookie partition key in this log
    // statement as well if needed.
    // TODO(crbug.com/40165805): Include source scheme and source port.
    LOG(ERROR) << base::StringPrintf(
        "Found %d duplicate domain cookies for key='%s', "
        "with {name='%s', domain='%s', path='%s'}",
        static_cast<int>(dupes.size()), key.c_str(),
        std::get<1>(signature).c_str(), std::get<2>(signature).c_str(),
        std::get<3>(signature).c_str());

    // Remove all the cookies identified by |dupes|. It is valid to delete our
    // list of iterators one at a time, since |cookies_| is a multimap (they
    // don't invalidate existing iterators following deletion).
    for (const CookieMap::iterator& dupe : dupes) {
      if (cookie_partition_it) {
        InternalDeletePartitionedCookie(
            cookie_partition_it.value(), dupe, true,
            DELETE_COOKIE_DUPLICATE_IN_BACKING_STORE);
      } else {
        InternalDeleteCookie(dupe, true,
                             DELETE_COOKIE_DUPLICATE_IN_BACKING_STORE);
      }
    }
  }

  CHECK_EQ(num_domain_duplicates, num_domain_duplicates_found);
}

std::vector<CanonicalCookie*>
CookieMonster::FindCookiesForRegistryControlledHost(
    const GURL& url,
    CookieMap* cookie_map,
    CookieMonster::PartitionedCookieMap::iterator* partition_it) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (!cookie_map)
    cookie_map = &cookies_;

  Time current_time = Time::Now();

  // Retrieve all cookies for a given key
  const std::string key(GetKey(url.host_piece()));

  std::vector<CanonicalCookie*> cookies;
  for (CookieMapItPair its = cookie_map->equal_range(key);
       its.first != its.second;) {
    auto curit = its.first;
    CanonicalCookie* cc = curit->second.get();
    ++its.first;

    // If the cookie is expired, delete it.
    if (cc->IsExpired(current_time)) {
      if (cc->IsPartitioned()) {
        DCHECK(partition_it);
        DCHECK_EQ((*partition_it)->second.get(), cookie_map);
        InternalDeletePartitionedCookie(*partition_it, curit, true,
                                        DELETE_COOKIE_EXPIRED);
      } else {
        InternalDeleteCookie(curit, true, DELETE_COOKIE_EXPIRED);
      }
      continue;
    }
    cookies.push_back(cc);
  }
  return cookies;
}

std::vector<CanonicalCookie*>
CookieMonster::FindPartitionedCookiesForRegistryControlledHost(
    const CookiePartitionKey& cookie_partition_key,
    const GURL& url) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  PartitionedCookieMap::iterator it =
      partitioned_cookies_.find(cookie_partition_key);
  if (it == partitioned_cookies_.end())
    return std::vector<CanonicalCookie*>();

  return FindCookiesForRegistryControlledHost(url, it->second.get(), &it);
}

void CookieMonster::FilterCookiesWithOptions(
    const GURL& url,
    const CookieOptions options,
    std::vector<CanonicalCookie*>* cookie_ptrs,
    CookieAccessResultList* included_cookies,
    CookieAccessResultList* excluded_cookies) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Probe to save statistics relatively frequently.  We do it here rather
  // than in the set path as many websites won't set cookies, and we
  // want to collect statistics whenever the browser's being used.
  Time current_time = Time::Now();
  RecordPeriodicStats(current_time);

  bool delegate_treats_url_as_trustworthy =
      cookie_access_delegate() &&
      cookie_access_delegate()->ShouldTreatUrlAsTrustworthy(url);

  std::vector<std::pair<CanonicalCookie*, CookieAccessResult>>
      cookies_and_access_results;
  cookies_and_access_results.reserve(cookie_ptrs->size());
  std::set<std::string> origin_cookie_names;

  for (CanonicalCookie* cookie_ptr : *cookie_ptrs) {
    // Filter out cookies that should not be included for a request to the
    // given |url|. HTTP only cookies are filtered depending on the passed
    // cookie |options|.
    CookieAccessResult access_result = cookie_ptr->IncludeForRequestURL(
        url, options,
        CookieAccessParams{GetAccessSemanticsForCookie(*cookie_ptr),
                           delegate_treats_url_as_trustworthy});
    cookies_and_access_results.emplace_back(cookie_ptr, access_result);

    // Record the names of all origin cookies that would be included if both
    // kEnablePortBoundCookies and kEnableSchemeBoundCookies are enabled.
    //
    // We DO want to record origin cookies that are being excluded for path
    // reasons, so we'll remove any potential path exclusions.
    CookieInclusionStatus status_copy = access_result.status;
    status_copy.RemoveExclusionReason(
        CookieInclusionStatus::EXCLUDE_NOT_ON_PATH);

    bool exclusion_or_warning =
        !status_copy.IsInclude() ||
        status_copy.HasWarningReason(
            CookieInclusionStatus::WARN_SCHEME_MISMATCH) ||
        status_copy.HasWarningReason(CookieInclusionStatus::WARN_PORT_MISMATCH);

    if (!exclusion_or_warning && cookie_ptr->IsHostCookie()) {
      origin_cookie_names.insert(cookie_ptr->Name());
    }
  }

  for (auto& cookie_result : cookies_and_access_results) {
    CanonicalCookie* cookie_ptr = cookie_result.first;
    CookieAccessResult& access_result = cookie_result.second;

    // We want to collect these metrics for cookies that would be included
    // without considering shadowing domain cookies.
    if (access_result.status.IsInclude()) {
      int destination_port = url.EffectiveIntPort();

      if (IsLocalhost(url)) {
        UMA_HISTOGRAM_ENUMERATION(
            "Cookie.Port.Read.Localhost",
            ReducePortRangeForCookieHistogram(destination_port));
        UMA_HISTOGRAM_ENUMERATION(
            "Cookie.Port.ReadDiffersFromSet.Localhost",
            IsCookieSentToSamePortThatSetIt(url, cookie_ptr->SourcePort(),
                                            cookie_ptr->SourceScheme()));
      } else {
        UMA_HISTOGRAM_ENUMERATION(
            "Cookie.Port.Read.RemoteHost",
            ReducePortRangeForCookieHistogram(destination_port));
        UMA_HISTOGRAM_ENUMERATION(
            "Cookie.Port.ReadDiffersFromSet.RemoteHost",
            IsCookieSentToSamePortThatSetIt(url, cookie_ptr->SourcePort(),
                                            cookie_ptr->SourceScheme()));
      }

      if (cookie_ptr->IsDomainCookie()) {
        UMA_HISTOGRAM_ENUMERATION(
            "Cookie.Port.ReadDiffersFromSet.DomainSet",
            IsCookieSentToSamePortThatSetIt(url, cookie_ptr->SourcePort(),
                                            cookie_ptr->SourceScheme()));
      }
    }

    // Filter out any domain `cookie_ptr` which are shadowing origin cookies.
    // Don't apply domain shadowing exclusion/warning reason if `cookie_ptr` is
    // already being excluded/warned for scheme matching reasons (Note, domain
    // cookies match every port so they'll never get excluded/warned for port
    // reasons).
    bool scheme_mismatch =
        access_result.status.HasExclusionReason(
            CookieInclusionStatus::EXCLUDE_SCHEME_MISMATCH) ||
        access_result.status.HasWarningReason(
            CookieInclusionStatus::WARN_SCHEME_MISMATCH);

    if (cookie_ptr->IsDomainCookie() && !scheme_mismatch &&
        origin_cookie_names.count(cookie_ptr->Name())) {
      if (cookie_util::IsSchemeBoundCookiesEnabled()) {
        access_result.status.AddExclusionReason(
            CookieInclusionStatus::EXCLUDE_SHADOWING_DOMAIN);
      } else {
        access_result.status.AddWarningReason(
            CookieInclusionStatus::WARN_SHADOWING_DOMAIN);
      }
    }

    if (!access_result.status.IsInclude()) {
      if (options.return_excluded_cookies()) {
        excluded_cookies->push_back({*cookie_ptr, access_result});
      }
      continue;
    }

    if (options.update_access_time()) {
      InternalUpdateCookieAccessTime(cookie_ptr, current_time);
    }

    included_cookies->push_back({*cookie_ptr, access_result});
  }
}

void CookieMonster::MaybeDeleteEquivalentCookieAndUpdateStatus(
    const std::string& key,
    const CanonicalCookie& cookie_being_set,
    bool allowed_to_set_secure_cookie,
    bool skip_httponly,
    bool already_expired,
    base::Time* creation_date_to_inherit,
    CookieInclusionStatus* status,
    std::optional<PartitionedCookieMap::iterator> cookie_partition_it) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!status->HasExclusionReason(
      CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE));
  DCHECK(!status->HasExclusionReason(
      CookieInclusionStatus::EXCLUDE_OVERWRITE_HTTP_ONLY));

  CookieMap* cookie_map = &cookies_;
  if (cookie_partition_it) {
    cookie_map = cookie_partition_it.value()->second.get();
  }

  bool found_equivalent_cookie = false;
  CookieMap::iterator deletion_candidate_it = cookie_map->end();
  CanonicalCookie* skipped_secure_cookie = nullptr;

  // Check every cookie matching this domain key for equivalence.
  CookieMapItPair range_its = cookie_map->equal_range(key);
  for (auto cur_it = range_its.first; cur_it != range_its.second; ++cur_it) {
    CanonicalCookie* cur_existing_cookie = cur_it->second.get();

    // Evaluate "Leave Secure Cookies Alone":
    // If the cookie is being set from an insecure source, then if an
    // "equivalent" Secure cookie already exists, then the cookie should *not*
    // be updated.
    //
    // "Equivalent" means they are the same by
    // IsEquivalentForSecureCookieMatching(). See the comment there for
    // details. (Note this is not a symmetric comparison.) This notion of
    // equivalence is slightly more inclusive than the usual IsEquivalent() one.
    //
    // See: https://tools.ietf.org/html/draft-ietf-httpbis-cookie-alone
    if (cur_existing_cookie->SecureAttribute() &&
        !allowed_to_set_secure_cookie &&
        cookie_being_set.IsEquivalentForSecureCookieMatching(
            *cur_existing_cookie)) {
      // Hold onto this for additional Netlogging later if we end up preserving
      // a would-have-been-deleted cookie because of this.
      skipped_secure_cookie = cur_existing_cookie;
      net_log_.AddEvent(NetLogEventType::COOKIE_STORE_COOKIE_REJECTED_SECURE,
                        [&](NetLogCaptureMode capture_mode) {
                          return NetLogCookieMonsterCookieRejectedSecure(
                              skipped_secure_cookie, &cookie_being_set,
                              capture_mode);
                        });
      status->AddExclusionReason(
          CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE);
    }

    if (cookie_being_set.IsEquivalent(*cur_existing_cookie)) {
      // We should never have more than one equivalent cookie, since they should
      // overwrite each other.
      CHECK(!found_equivalent_cookie)
          << "Duplicate equivalent cookies found, cookie store is corrupted.";
      DCHECK(deletion_candidate_it == cookie_map->end());
      found_equivalent_cookie = true;

      // The |cookie_being_set| is rejected for trying to overwrite an httponly
      // cookie when it should not be able to.
      if (skip_httponly && cur_existing_cookie->IsHttpOnly()) {
        net_log_.AddEvent(
            NetLogEventType::COOKIE_STORE_COOKIE_REJECTED_HTTPONLY,
            [&](NetLogCaptureMode capture_mode) {
              return NetLogCookieMonsterCookieRejectedHttponly(
                  cur_existing_cookie, &cookie_being_set, capture_mode);
            });
        status->AddExclusionReason(
            CookieInclusionStatus::EXCLUDE_OVERWRITE_HTTP_ONLY);
      } else {
        deletion_candidate_it = cur_it;
      }
    }
  }

  if (deletion_candidate_it != cookie_map->end()) {
    CanonicalCookie* deletion_candidate = deletion_candidate_it->second.get();
    if (deletion_candidate->Value() == cookie_being_set.Value())
      *creation_date_to_inherit = deletion_candidate->CreationDate();
    if (status->IsInclude()) {
      if (cookie_being_set.IsPartitioned()) {
        InternalDeletePartitionedCookie(
            cookie_partition_it.value(), deletion_candidate_it,
            true /* sync_to_store */,
            already_expired ? DELETE_COOKIE_EXPIRED_OVERWRITE
                            : DELETE_COOKIE_OVERWRITE);
      } else {
        InternalDeleteCookie(deletion_candidate_it, true /* sync_to_store */,
                             already_expired ? DELETE_COOKIE_EXPIRED_OVERWRITE
                                             : DELETE_COOKIE_OVERWRITE);
      }
    } else if (status->HasExclusionReason(
                   CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE)) {
      // Log that we preserved a cookie that would have been deleted due to
      // Leave Secure Cookies Alone. This arbitrarily only logs the last
      // |skipped_secure_cookie| that we were left with after the for loop, even
      // if there were multiple matching Secure cookies that were left alone.
      DCHECK(skipped_secure_cookie);
      net_log_.AddEvent(
          NetLogEventType::COOKIE_STORE_COOKIE_PRESERVED_SKIPPED_SECURE,
          [&](NetLogCaptureMode capture_mode) {
            return NetLogCookieMonsterCookiePreservedSkippedSecure(
                skipped_secure_cookie, deletion_candidate, &cookie_being_set,
                capture_mode);
          });
    }
  }
}

CookieMonster::CookieMap::iterator CookieMonster::InternalInsertCookie(
    const std::string& key,
    std::unique_ptr<CanonicalCookie> cc,
    bool sync_to_store,
    const CookieAccessResult& access_result,
    bool dispatch_change) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  CanonicalCookie* cc_ptr = cc.get();

  net_log_.AddEvent(NetLogEventType::COOKIE_STORE_COOKIE_ADDED,
                    [&](NetLogCaptureMode capture_mode) {
                      return NetLogCookieMonsterCookieAdded(
                          cc.get(), sync_to_store, capture_mode);
                    });
  if (ShouldUpdatePersistentStore(cc_ptr) && sync_to_store)
    store_->AddCookie(*cc_ptr);

  auto inserted = cookies_.insert(CookieMap::value_type(key, std::move(cc)));

  LogStoredCookieToUMA(*cc_ptr, access_result);

  DCHECK(access_result.status.IsInclude());
  if (dispatch_change) {
    change_dispatcher_.DispatchChange(
        CookieChangeInfo(*cc_ptr, access_result, CookieChangeCause::INSERTED),
        true);
  }

  // If this is the first cookie in |cookies_| with this key, increment the
  // |num_keys_| counter.
  bool different_prev =
      inserted == cookies_.begin() || std::prev(inserted)->first != key;
  // According to std::multiqueue documentation:
  // "If the container has elements with equivalent key, inserts at the upper
  // bound of that range. (since C++11)"
  // This means that "inserted" iterator either points to the last element in
  // the map, or the element succeeding it has to have different key.
  DCHECK(std::next(inserted) == cookies_.end() ||
         std::next(inserted)->first != key);
  if (different_prev)
    ++num_keys_;

  return inserted;
}

bool CookieMonster::ShouldUpdatePersistentStore(CanonicalCookie* cc) {
  return (cc->IsPersistent() || persist_session_cookies_) && store_.get();
}

CookieMonster::PartitionedCookieMapIterators
CookieMonster::InternalInsertPartitionedCookie(
    std::string key,
    std::unique_ptr<CanonicalCookie> cc,
    bool sync_to_store,
    const CookieAccessResult& access_result,
    bool dispatch_change) {
  DCHECK(cc->IsPartitioned());
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  CanonicalCookie* cc_ptr = cc.get();

  net_log_.AddEvent(NetLogEventType::COOKIE_STORE_COOKIE_ADDED,
                    [&](NetLogCaptureMode capture_mode) {
                      return NetLogCookieMonsterCookieAdded(
                          cc.get(), sync_to_store, capture_mode);
                    });
  if (ShouldUpdatePersistentStore(cc_ptr) && sync_to_store)
    store_->AddCookie(*cc_ptr);

  CookiePartitionKey partition_key(cc->PartitionKey().value());

  size_t n_bytes = NameValueSizeBytes(*cc);
  num_partitioned_cookies_bytes_ += n_bytes;
  bytes_per_cookie_partition_[partition_key]
```