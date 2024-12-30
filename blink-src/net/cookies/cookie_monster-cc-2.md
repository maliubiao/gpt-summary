Response:
The user wants a summary of the functionality of the provided C++ code snippet from `net/cookies/cookie_monster.cc`. I need to analyze the code, focusing on the methods and their interactions related to cookie management. Specifically, I should identify:

1. **Core Functionality:** What does this code do in terms of cookie handling?
2. **JavaScript Relation:** Are there any interactions or implications for JavaScript's cookie access?
3. **Logic and Data Flow:** Can I infer inputs and outputs for the methods?
4. **Potential Errors:** What are common mistakes users or developers might make when using or interacting with this code?
5. **User Journey:** How might a user's actions lead to this code being executed?
6. **Overall Purpose:**  Synthesize a concise summary of the code's role.

Let's break down the provided code:

- **`InternalInsertCookie` and `InternalInsertPartitionedCookie`:** These functions seem responsible for adding cookies to the internal storage, both regular and partitioned cookies. They handle bookkeeping like byte counts and dispatch change notifications.
- **`SetCanonicalCookie`:** This is the main entry point for setting a cookie. It performs checks (like source type, secure context), determines if overwriting is allowed, handles cookie expiration, and calls the internal insertion functions.
- **`SetAllCookies`:**  This method clears the existing cookies and sets a new list of cookies.
- **`InternalUpdateCookieAccessTime`:**  Updates the last access time of a cookie, potentially triggering a store update.
- **`InternalDeleteCookie` and `InternalDeletePartitionedCookie`:**  Remove cookies from the internal storage and handle associated bookkeeping and change notifications.
- **`GarbageCollect` and `GarbageCollectPartitionedCookies`:**  Implement logic to remove expired or excessive cookies based on various criteria (domain limits, global limits, access time).
- **Helper functions within `GarbageCollect`:**  `PurgeLeastRecentMatches`, `PurgeLeastRecentMatchesForOBC`, `GarbageCollectExpired`, `GarbageCollectExpiredPartitionedCookies`, `GarbageCollectDeleteRange`, `GarbageCollectLeastRecentlyAccessed` - these manage the detailed logic for removing cookies based on different eviction strategies.

**JavaScript Relationship:**  The code doesn't directly interact with JavaScript. However, the functions it provides (setting, getting, deleting cookies) are the underlying mechanisms that JavaScript's `document.cookie` API and the `Set-Cookie` HTTP header rely on.

**Logic and Data Flow:** For example, in `SetCanonicalCookie`:
    - **Input:** A `CanonicalCookie` object, source URL, `CookieOptions`, a callback, and an optional `CookieAccessResult`.
    - **Processing:** Checks permissions, determines if duplicates exist, handles expiration, inserts the cookie using `InternalInsertCookie` or `InternalInsertPartitionedCookie`, and triggers garbage collection.
    - **Output:** Potentially a callback invocation with the `CookieAccessResult`.

**Potential Errors:**  A common user error would be trying to set a secure cookie from a non-secure origin, which this code handles via `IsSetPermittedInContext`. A developer error might be not setting the `CookieSourceType` correctly, which the code checks for in non-test environments.

**User Journey:** A user navigating to a website, and that website's server sending a `Set-Cookie` header, or JavaScript on the page calling `document.cookie = ...`, would eventually lead to `SetCanonicalCookie` being called.

**Overall Purpose:** This section of the code focuses on the core logic for adding, updating, and removing cookies within Chromium's network stack. It manages both regular and partitioned cookies, enforces limits, and handles cookie expiration and eviction.

**Final Summary Structure:** I should organize the summary around the core functionalities, highlighting the relationship with JavaScript, providing examples of logic, common errors, and user actions leading to this code.
这是 `net/cookies/cookie_monster.cc` 文件的第三部分，主要包含 `CookieMonster` 类中设置、更新和删除 Cookie 的核心逻辑，以及进行垃圾回收以维护 Cookie 存储大小的功能。

以下是其功能的归纳：

**1. Cookie 的插入和设置：**

*   **`InternalInsertCookie(const std::string& key, std::unique_ptr<CanonicalCookie> cc, bool dispatch_change, const CookieAccessResult& access_result)` 和 `InternalInsertPartitionedCookie(...)`:**  这两个函数负责将 `CanonicalCookie` 对象插入到内部的 Cookie 存储 (`cookies_` 和 `partitioned_cookies_`) 中。它们会更新相关的统计信息（如字节数和 Cookie 数量），并可以选择性地分发 Cookie 变更通知。
    *   **假设输入（`InternalInsertPartitionedCookie`）：**  一个域名键 `key`，一个指向 `CanonicalCookie` 的唯一指针 `cc` (该 Cookie 是已分区的)，一个布尔值 `dispatch_change` 指示是否分发变更通知，以及一个 `CookieAccessResult` 对象。
    *   **预期输出：** Cookie 被成功插入到 `partitioned_cookies_` 中，相关的统计信息被更新，如果 `dispatch_change` 为 true，则会发出 Cookie 变更通知。返回一个迭代器对，指向插入的 Cookie 在 `partitioned_cookies_` 中的位置。
*   **`SetCanonicalCookie(std::unique_ptr<CanonicalCookie> cc, const GURL& source_url, const CookieOptions& options, SetCookiesCallback callback, std::optional<CookieAccessResult> cookie_access_result)`:**  这是设置 Cookie 的主要入口点。它接收一个 `CanonicalCookie` 对象，来源 URL，Cookie 选项，一个回调函数，以及一个可选的 Cookie 访问结果。
    *   它会进行一系列检查，例如来源 URL 的可信度，是否允许在当前上下文中设置 Cookie。
    *   它会处理 Cookie 的创建日期，如果未设置则使用当前时间。
    *   它会检查是否存在需要删除的重复 Cookie。
    *   如果 Cookie 满足设置条件，则调用 `InternalInsertCookie` 或 `InternalInsertPartitionedCookie` 将其添加到存储中。
    *   它会触发垃圾回收以防止 Cookie 数量或大小超出限制。
    *   **与 JavaScript 的关系：** 当 JavaScript 代码通过 `document.cookie = ...` 设置 Cookie 时，或者当服务器发送 `Set-Cookie` 响应头时，最终会调用到 `SetCanonicalCookie`。例如，如果 JavaScript 执行 `document.cookie = "mycookie=value; path=/;"`，网络栈会将这个字符串解析成一个 `CanonicalCookie` 对象，并调用 `SetCanonicalCookie` 来存储它。
    *   **用户操作如何到达这里作为调试线索：**
        1. 用户在浏览器地址栏输入 URL 并访问一个网站，或者点击了一个链接。
        2. 网站的服务器返回一个 HTTP 响应，其中包含 `Set-Cookie` 头部。
        3. Chromium 的网络栈接收到这个响应头，并解析其中的 Cookie 信息。
        4. 解析后的 Cookie 信息被封装成一个 `CanonicalCookie` 对象。
        5. `SetCanonicalCookie` 函数被调用，传入该 `CanonicalCookie` 对象和相关的上下文信息。
*   **`SetAllCookies(CookieList list, SetCookiesCallback callback)`:**  这个函数用于一次性设置多个 Cookie。它首先清空现有的 Cookie 存储，然后遍历传入的 Cookie 列表并逐个设置。
    *   **用户或编程常见的使用错误：**  调用 `SetAllCookies` 会清空所有现有的 Cookie，这可能会导致用户会话丢失或其他意外行为。开发者应该谨慎使用此方法，并确保这是预期的行为。

**2. Cookie 的访问时间更新：**

*   **`InternalUpdateCookieAccessTime(CanonicalCookie* cc, const Time& current)`:**  当 Cookie 被访问时（例如，在发送请求时需要包含该 Cookie），此函数会被调用以更新 Cookie 的最后访问时间。为了优化性能，它会检查上次访问时间是否在最近的阈值内，如果是则跳过更新。

**3. Cookie 的删除：**

*   **`InternalDeleteCookie(CookieMap::iterator it, bool sync_to_store, DeletionCause deletion_cause)` 和 `InternalDeletePartitionedCookie(...)`:**  这两个函数负责从内部存储中删除 Cookie。它们会更新相关的统计信息，并分发 Cookie 删除通知。`sync_to_store` 参数指示是否需要同步到持久化存储。`DeletionCause` 参数说明了删除的原因。
    *   **假设输入（`InternalDeleteCookie`）：** 一个指向要删除的 Cookie 的迭代器 `it`，一个布尔值 `sync_to_store`，以及一个 `DeletionCause` 枚举值。
    *   **预期输出：**  指定的 Cookie 从 `cookies_` 中被删除，相关的统计信息被更新，如果 `sync_to_store` 为 true，则持久化存储也会被更新，并且会发出 Cookie 删除通知。
    *   **与 JavaScript 的关系：** 当 JavaScript 代码通过设置一个过期时间为过去的 Cookie 来删除它时（例如，`document.cookie = "mycookie=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;"`），最终会触发 `InternalDeleteCookie` 的调用。
*   **用户操作如何到达这里作为调试线索（删除 Cookie）：**
    1. 用户在浏览器设置中手动清除了特定网站的 Cookie。
    2. 网站的服务器发送一个 `Set-Cookie` 头部，其 `Max-Age` 或 `Expires` 指令指示浏览器删除该 Cookie。
    3. JavaScript 代码执行类似 `document.cookie = "mycookie=; expires=..."` 的操作。
    4. `InternalDeleteCookie` 或 `InternalDeletePartitionedCookie` 函数被调用，执行删除操作。

**4. Cookie 的垃圾回收 (Garbage Collection):**

*   **`GarbageCollect(const Time& current, const std::string& key)` 和 `GarbageCollectPartitionedCookies(...)`:**  这些函数负责定期清理过期的或超出数量限制的 Cookie。它们会根据不同的策略（例如，最近最少使用、优先级）删除 Cookie。
    *   **`GarbageCollect`:**  处理非分区 Cookie 的垃圾回收。它会检查特定域名下的 Cookie 数量是否超过限制 (`kDomainMaxCookies`)，以及全局 Cookie 总数是否超过限制 (`kMaxCookies`)。
    *   **`GarbageCollectPartitionedCookies`:** 处理分区 Cookie 的垃圾回收。它会检查每个分区的 Cookie 数量和大小是否超过限制。
    *   **假设输入（`GarbageCollect`）：**  当前时间 `current` 和一个域名键 `key`。
    *   **预期输出：**  根据配置的策略，过期的或超出限制的 Cookie 被删除。返回被删除的 Cookie 数量。
*   **辅助的垃圾回收函数：** `PurgeLeastRecentMatches`, `PurgeLeastRecentMatchesForOBC`, `GarbageCollectExpired`, `GarbageCollectExpiredPartitionedCookies`, `GarbageCollectDeleteRange`, `GarbageCollectLeastRecentlyAccessed`。这些函数实现了具体的 Cookie 清理逻辑，例如根据最后访问时间或 Cookie 优先级进行删除。
*   **用户操作如何导致垃圾回收：**  垃圾回收通常是定期触发的，或者在尝试设置新 Cookie 时触发，以确保 Cookie 存储不会无限增长。用户不需要执行特定的操作来触发垃圾回收，它是浏览器后台自动运行的维护过程。

**常见的使用错误和调试线索：**

*   **尝试在不安全的上下文中设置 Secure Cookie：** `SetCanonicalCookie` 会检查来源 URL 的安全性，如果尝试在 HTTP 页面上设置带有 `Secure` 属性的 Cookie，则会被阻止。调试时可以检查 `access_result.status` 中的 `EXCLUDE_SECURE_ONLY` 标志。
*   **Cookie 数量或大小超出限制：** 当尝试设置新的 Cookie 时，如果已达到域名或全局的 Cookie 数量或大小限制，垃圾回收会被触发。如果新的 Cookie 无法添加，可能是因为垃圾回收未能清理出足够的空间。可以通过查看网络日志或调试 Cookie 存储状态来确认是否达到了限制。
*   **Partitioned Cookie 相关的错误：**  与 Partitioned Cookie 相关的逻辑 (例如，`InternalInsertPartitionedCookie`, `GarbageCollectPartitionedCookies`) 处理了更细粒度的 Cookie 隔离。错误可能发生在分区键的计算或匹配上。

**总结:**

这部分代码负责 `CookieMonster` 类中 Cookie 的核心生命周期管理，包括添加、更新、删除 Cookie，并实施垃圾回收策略以维护 Cookie 存储的健康状态。它连接了浏览器接收到的 HTTP `Set-Cookie` 头部和 JavaScript 的 `document.cookie` API 与底层的 Cookie 存储和管理机制。理解这部分代码对于调试 Cookie 相关的问题，例如 Cookie 设置失败、意外删除或行为不符合预期至关重要。

Prompt: 
```
这是目录为net/cookies/cookie_monster.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能

"""
 += n_bytes;
  if (partition_key.nonce()) {
    num_nonced_partitioned_cookie_bytes_ += n_bytes;
  }

  PartitionedCookieMap::iterator partition_it =
      partitioned_cookies_.find(partition_key);
  if (partition_it == partitioned_cookies_.end()) {
    partition_it =
        partitioned_cookies_
            .insert(PartitionedCookieMap::value_type(
                std::move(partition_key), std::make_unique<CookieMap>()))
            .first;
  }

  CookieMap::iterator cookie_it = partition_it->second->insert(
      CookieMap::value_type(std::move(key), std::move(cc)));
  ++num_partitioned_cookies_;
  if (partition_it->first.nonce()) {
    ++num_nonced_partitioned_cookies_;
  }
  CHECK_GE(num_partitioned_cookies_, num_nonced_partitioned_cookies_);

  LogStoredCookieToUMA(*cc_ptr, access_result);

  DCHECK(access_result.status.IsInclude());
  if (dispatch_change) {
    change_dispatcher_.DispatchChange(
        CookieChangeInfo(*cc_ptr, access_result, CookieChangeCause::INSERTED),
        true);
  }

  return std::pair(partition_it, cookie_it);
}

void CookieMonster::SetCanonicalCookie(
    std::unique_ptr<CanonicalCookie> cc,
    const GURL& source_url,
    const CookieOptions& options,
    SetCookiesCallback callback,
    std::optional<CookieAccessResult> cookie_access_result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
// TODO(crbug.com/40281870): Fix macos specific issue with CHECK_IS_TEST
// crashing network service process.
#if !BUILDFLAG(IS_MAC)
  // Only tests should be adding new cookies with source type kUnknown. If this
  // line causes a fatal track down the callsite and have it correctly set the
  // source type to kOther (or kHTTP/kScript where applicable). See
  // CookieSourceType in net/cookies/cookie_constants.h for more.
  if (cc->SourceType() == CookieSourceType::kUnknown) {
    CHECK_IS_TEST(base::NotFatalUntil::M126);
  }
#endif

  bool delegate_treats_url_as_trustworthy =
      cookie_access_delegate() &&
      cookie_access_delegate()->ShouldTreatUrlAsTrustworthy(source_url);

  CookieAccessResult access_result = cc->IsSetPermittedInContext(
      source_url, options,
      CookieAccessParams(GetAccessSemanticsForCookie(*cc),
                         delegate_treats_url_as_trustworthy),
      cookieable_schemes_, cookie_access_result);

  const std::string key(GetKey(cc->Domain()));

  base::Time creation_date = cc->CreationDate();
  if (creation_date.is_null()) {
    creation_date = Time::Now();
    cc->SetCreationDate(creation_date);
  }
  bool already_expired = cc->IsExpired(creation_date);

  base::Time creation_date_to_inherit;

  std::optional<PartitionedCookieMap::iterator> cookie_partition_it;
  bool should_try_to_delete_duplicates = true;

  if (cc->IsPartitioned()) {
    auto it = partitioned_cookies_.find(cc->PartitionKey().value());
    if (it == partitioned_cookies_.end()) {
      // This is the first cookie in its partition, so it won't have any
      // duplicates.
      should_try_to_delete_duplicates = false;
    } else {
      cookie_partition_it = std::make_optional(it);
    }
  }

  // Iterates through existing cookies for the same eTLD+1, and potentially
  // deletes an existing cookie, so any ExclusionReasons in |status| that would
  // prevent such deletion should be finalized beforehand.
  if (should_try_to_delete_duplicates) {
    MaybeDeleteEquivalentCookieAndUpdateStatus(
        key, *cc, access_result.is_allowed_to_access_secure_cookies,
        options.exclude_httponly(), already_expired, &creation_date_to_inherit,
        &access_result.status, cookie_partition_it);
  }

  if (access_result.status.HasExclusionReason(
          CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE) ||
      access_result.status.HasExclusionReason(
          CookieInclusionStatus::EXCLUDE_OVERWRITE_HTTP_ONLY)) {
    DVLOG(net::cookie_util::kVlogSetCookies)
        << "SetCookie() not clobbering httponly cookie or secure cookie for "
           "insecure scheme";
  }

  if (access_result.status.IsInclude()) {
    DVLOG(net::cookie_util::kVlogSetCookies)
        << "SetCookie() key: " << key << " cc: " << cc->DebugString();

    if (cc->IsEffectivelySameSiteNone()) {
      size_t cookie_size = NameValueSizeBytes(*cc);
      UMA_HISTOGRAM_COUNTS_10000("Cookie.SameSiteNoneSizeBytes", cookie_size);
      if (cc->IsPartitioned()) {
        UMA_HISTOGRAM_COUNTS_10000("Cookie.SameSiteNoneSizeBytes.Partitioned",
                                   cookie_size);
      } else {
        UMA_HISTOGRAM_COUNTS_10000("Cookie.SameSiteNoneSizeBytes.Unpartitioned",
                                   cookie_size);
      }
    }

    std::optional<CookiePartitionKey> cookie_partition_key = cc->PartitionKey();
    CHECK_EQ(cc->IsPartitioned(), cookie_partition_key.has_value());

    // Realize that we might be setting an expired cookie, and the only point
    // was to delete the cookie which we've already done.
    if (!already_expired) {
      HistogramExpirationDuration(*cc, creation_date);

      UMA_HISTOGRAM_BOOLEAN("Cookie.DomainSet", cc->IsDomainCookie());

      if (!creation_date_to_inherit.is_null()) {
        cc->SetCreationDate(creation_date_to_inherit);
      }

      if (cookie_partition_key.has_value()) {
        InternalInsertPartitionedCookie(key, std::move(cc), true,
                                        access_result);
      } else {
        InternalInsertCookie(key, std::move(cc), true, access_result);
      }
    } else {
      DVLOG(net::cookie_util::kVlogSetCookies)
          << "SetCookie() not storing already expired cookie.";
    }

    // We assume that hopefully setting a cookie will be less common than
    // querying a cookie.  Since setting a cookie can put us over our limits,
    // make sure that we garbage collect...  We can also make the assumption
    // that if a cookie was set, in the common case it will be used soon after,
    // and we will purge the expired cookies in GetCookies().
    if (cookie_partition_key.has_value()) {
      GarbageCollectPartitionedCookies(creation_date,
                                       cookie_partition_key.value(), key);
    } else {
      GarbageCollect(creation_date, key);
    }

    if (IsLocalhost(source_url)) {
      UMA_HISTOGRAM_ENUMERATION(
          "Cookie.Port.Set.Localhost",
          ReducePortRangeForCookieHistogram(source_url.EffectiveIntPort()));
    } else {
      UMA_HISTOGRAM_ENUMERATION(
          "Cookie.Port.Set.RemoteHost",
          ReducePortRangeForCookieHistogram(source_url.EffectiveIntPort()));
    }

    UMA_HISTOGRAM_ENUMERATION("Cookie.CookieSourceSchemeName",
                              GetSchemeNameEnum(source_url));
  } else {
    // If the cookie would be excluded, don't bother warning about the 3p cookie
    // phaseout.
    access_result.status.RemoveWarningReason(
        net::CookieInclusionStatus::WARN_THIRD_PARTY_PHASEOUT);
  }

  // TODO(chlily): Log metrics.
  MaybeRunCookieCallback(std::move(callback), access_result);
}

void CookieMonster::SetAllCookies(CookieList list,
                                  SetCookiesCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Nuke the existing store.
  while (!cookies_.empty()) {
    // TODO(rdsmith): The CANONICAL is a lie.
    InternalDeleteCookie(cookies_.begin(), true, DELETE_COOKIE_EXPLICIT);
  }

  // Set all passed in cookies.
  for (const auto& cookie : list) {
    const std::string key(GetKey(cookie.Domain()));
    Time creation_time = cookie.CreationDate();
    if (cookie.IsExpired(creation_time))
      continue;

    HistogramExpirationDuration(cookie, creation_time);

    CookieAccessResult access_result;
    access_result.access_semantics = GetAccessSemanticsForCookie(cookie);

    if (cookie.IsPartitioned()) {
      InternalInsertPartitionedCookie(
          key, std::make_unique<CanonicalCookie>(cookie), true, access_result);
      GarbageCollectPartitionedCookies(creation_time,
                                       cookie.PartitionKey().value(), key);
    } else {
      InternalInsertCookie(key, std::make_unique<CanonicalCookie>(cookie), true,
                           access_result);
      GarbageCollect(creation_time, key);
    }
  }

  // TODO(rdsmith): If this function always returns the same value, it
  // shouldn't have a return value.  But it should also be deleted (see
  // https://codereview.chromium.org/2882063002/#msg64), which would
  // solve the return value problem.
  MaybeRunCookieCallback(std::move(callback), CookieAccessResult());
}

void CookieMonster::InternalUpdateCookieAccessTime(CanonicalCookie* cc,
                                                   const Time& current) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Based off the Mozilla code.  When a cookie has been accessed recently,
  // don't bother updating its access time again.  This reduces the number of
  // updates we do during pageload, which in turn reduces the chance our storage
  // backend will hit its batch thresholds and be forced to update.
  if ((current - cc->LastAccessDate()) < last_access_threshold_)
    return;

  cc->SetLastAccessDate(current);
  if (ShouldUpdatePersistentStore(cc))
    store_->UpdateCookieAccessTime(*cc);
}

// InternalDeleteCookies must not invalidate iterators other than the one being
// deleted.
void CookieMonster::InternalDeleteCookie(CookieMap::iterator it,
                                         bool sync_to_store,
                                         DeletionCause deletion_cause) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Ideally, this would be asserted up where we define kChangeCauseMapping,
  // but DeletionCause's visibility (or lack thereof) forces us to make
  // this check here.
  static_assert(std::size(kChangeCauseMapping) == DELETE_COOKIE_LAST_ENTRY + 1,
                "kChangeCauseMapping size should match DeletionCause size");

  CanonicalCookie* cc = it->second.get();
  DVLOG(net::cookie_util::kVlogSetCookies)
      << "InternalDeleteCookie()"
      << ", cause:" << deletion_cause << ", cc: " << cc->DebugString();

  ChangeCausePair mapping = kChangeCauseMapping[deletion_cause];
  if (deletion_cause != DELETE_COOKIE_DONT_RECORD) {
    net_log_.AddEvent(NetLogEventType::COOKIE_STORE_COOKIE_DELETED,
                      [&](NetLogCaptureMode capture_mode) {
                        return NetLogCookieMonsterCookieDeleted(
                            cc, mapping.cause, sync_to_store, capture_mode);
                      });
  }

  if (ShouldUpdatePersistentStore(cc) && sync_to_store)
    store_->DeleteCookie(*cc);

  change_dispatcher_.DispatchChange(
      CookieChangeInfo(
          *cc,
          CookieAccessResult(CookieEffectiveSameSite::UNDEFINED,
                             CookieInclusionStatus(),
                             GetAccessSemanticsForCookie(*cc),
                             true /* is_allowed_to_access_secure_cookies */),
          mapping.cause),
      mapping.notify);

  // If this is the last cookie in |cookies_| with this key, decrement the
  // |num_keys_| counter.
  bool different_prev =
      it == cookies_.begin() || std::prev(it)->first != it->first;
  bool different_next =
      std::next(it) == cookies_.end() || std::next(it)->first != it->first;
  if (different_prev && different_next)
    --num_keys_;

  DCHECK(cookies_.find(it->first) != cookies_.end())
      << "Called erase with an iterator not in the cookie map";
  cookies_.erase(it);
}

void CookieMonster::InternalDeletePartitionedCookie(
    PartitionedCookieMap::iterator partition_it,
    CookieMap::iterator cookie_it,
    bool sync_to_store,
    DeletionCause deletion_cause) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Ideally, this would be asserted up where we define kChangeCauseMapping,
  // but DeletionCause's visibility (or lack thereof) forces us to make
  // this check here.
  static_assert(std::size(kChangeCauseMapping) == DELETE_COOKIE_LAST_ENTRY + 1,
                "kChangeCauseMapping size should match DeletionCause size");

  CanonicalCookie* cc = cookie_it->second.get();
  DCHECK(cc->IsPartitioned());
  DVLOG(net::cookie_util::kVlogSetCookies)
      << "InternalDeletePartitionedCookie()"
      << ", cause:" << deletion_cause << ", cc: " << cc->DebugString();

  ChangeCausePair mapping = kChangeCauseMapping[deletion_cause];
  if (deletion_cause != DELETE_COOKIE_DONT_RECORD) {
    net_log_.AddEvent(NetLogEventType::COOKIE_STORE_COOKIE_DELETED,
                      [&](NetLogCaptureMode capture_mode) {
                        return NetLogCookieMonsterCookieDeleted(
                            cc, mapping.cause, sync_to_store, capture_mode);
                      });
  }

  if (ShouldUpdatePersistentStore(cc) && sync_to_store)
    store_->DeleteCookie(*cc);

  change_dispatcher_.DispatchChange(
      CookieChangeInfo(
          *cc,
          CookieAccessResult(CookieEffectiveSameSite::UNDEFINED,
                             CookieInclusionStatus(),
                             GetAccessSemanticsForCookie(*cc),
                             true /* is_allowed_to_access_secure_cookies */),
          mapping.cause),
      mapping.notify);

  size_t n_bytes = NameValueSizeBytes(*cc);
  num_partitioned_cookies_bytes_ -= n_bytes;
  bytes_per_cookie_partition_[*cc->PartitionKey()] -= n_bytes;
  if (CookiePartitionKey::HasNonce(cc->PartitionKey())) {
    num_nonced_partitioned_cookie_bytes_ -= n_bytes;
  }

  DCHECK(partition_it->second->find(cookie_it->first) !=
         partition_it->second->end())
      << "Called erase with an iterator not in this partitioned cookie map";
  partition_it->second->erase(cookie_it);
  --num_partitioned_cookies_;
  if (partition_it->first.nonce()) {
    --num_nonced_partitioned_cookies_;
  }
  CHECK_GE(num_partitioned_cookies_, num_nonced_partitioned_cookies_);

  if (partition_it->second->empty())
    partitioned_cookies_.erase(partition_it);
}

// Domain expiry behavior is unchanged by key/expiry scheme (the
// meaning of the key is different, but that's not visible to this routine).
size_t CookieMonster::GarbageCollect(const Time& current,
                                     const std::string& key) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  size_t num_deleted = 0;
  const Time safe_date(Time::Now() - base::Days(kSafeFromGlobalPurgeDays));

  const bool obc_behavior_enabled =
      cookie_util::IsOriginBoundCookiesPartiallyEnabled();

  // Collect garbage for this key, minding cookie priorities.
  if (cookies_.count(key) > kDomainMaxCookies) {
    DVLOG(net::cookie_util::kVlogGarbageCollection)
        << "GarbageCollect() key: " << key;

    CookieItVector* cookie_its;

    CookieItVector non_expired_cookie_its;
    cookie_its = &non_expired_cookie_its;
    num_deleted +=
        GarbageCollectExpired(current, cookies_.equal_range(key), cookie_its);

    if (cookie_its->size() > kDomainMaxCookies) {
      DVLOG(net::cookie_util::kVlogGarbageCollection)
          << "Deep Garbage Collect domain.";

      if (domain_purged_keys_.size() < kMaxDomainPurgedKeys)
        domain_purged_keys_.insert(key);

      size_t purge_goal =
          cookie_its->size() - (kDomainMaxCookies - kDomainPurgeCookies);
      DCHECK(purge_goal > kDomainPurgeCookies);

      // Sort the cookies by access date, from least-recent to most-recent.
      std::sort(cookie_its->begin(), cookie_its->end(), LRACookieSorter);

      CookieItList cookie_it_list;
      if (obc_behavior_enabled) {
        cookie_it_list = CookieItList(cookie_its->begin(), cookie_its->end());
      }

      // Remove all but the kDomainCookiesQuotaLow most-recently accessed
      // cookies with low-priority. Then, if cookies still need to be removed,
      // bump the quota and remove low- and medium-priority. Then, if cookies
      // _still_ need to be removed, bump the quota and remove cookies with
      // any priority.
      //
      // 1.  Low-priority non-secure cookies.
      // 2.  Low-priority secure cookies.
      // 3.  Medium-priority non-secure cookies.
      // 4.  High-priority non-secure cookies.
      // 5.  Medium-priority secure cookies.
      // 6.  High-priority secure cookies.
      constexpr struct {
        CookiePriority priority;
        bool protect_secure_cookies;
      } kPurgeRounds[] = {
          // 1.  Low-priority non-secure cookies.
          {COOKIE_PRIORITY_LOW, true},
          // 2.  Low-priority secure cookies.
          {COOKIE_PRIORITY_LOW, false},
          // 3.  Medium-priority non-secure cookies.
          {COOKIE_PRIORITY_MEDIUM, true},
          // 4.  High-priority non-secure cookies.
          {COOKIE_PRIORITY_HIGH, true},
          // 5.  Medium-priority secure cookies.
          {COOKIE_PRIORITY_MEDIUM, false},
          // 6.  High-priority secure cookies.
          {COOKIE_PRIORITY_HIGH, false},
      };

      size_t quota = 0;
      for (const auto& purge_round : kPurgeRounds) {
        // Adjust quota according to the priority of cookies. Each round should
        // protect certain number of cookies in order to avoid starvation.
        // For example, when each round starts to remove cookies, the number of
        // cookies of that priority are counted and a decision whether they
        // should be deleted or not is made. If yes, some number of cookies of
        // that priority are deleted considering the quota.
        switch (purge_round.priority) {
          case COOKIE_PRIORITY_LOW:
            quota = kDomainCookiesQuotaLow;
            break;
          case COOKIE_PRIORITY_MEDIUM:
            quota = kDomainCookiesQuotaMedium;
            break;
          case COOKIE_PRIORITY_HIGH:
            quota = kDomainCookiesQuotaHigh;
            break;
        }
        size_t just_deleted = 0u;
        // Purge up to |purge_goal| for all cookies at the given priority.  This
        // path will be taken only if the initial non-secure purge did not evict
        // enough cookies.
        if (purge_goal > 0) {
          if (obc_behavior_enabled) {
            just_deleted = PurgeLeastRecentMatchesForOBC(
                &cookie_it_list, purge_round.priority, quota, purge_goal,
                !purge_round.protect_secure_cookies);
          } else {
            just_deleted = PurgeLeastRecentMatches(
                cookie_its, purge_round.priority, quota, purge_goal,
                purge_round.protect_secure_cookies);
          }
          DCHECK_LE(just_deleted, purge_goal);
          purge_goal -= just_deleted;
          num_deleted += just_deleted;
        }
      }

      DCHECK_EQ(0u, purge_goal);
    }
  }

  // Collect garbage for everything. With firefox style we want to preserve
  // cookies accessed in kSafeFromGlobalPurgeDays, otherwise evict.
  if (cookies_.size() > kMaxCookies && earliest_access_time_ < safe_date) {
    DVLOG(net::cookie_util::kVlogGarbageCollection)
        << "GarbageCollect() everything";
    CookieItVector cookie_its;

    num_deleted += GarbageCollectExpired(
        current, CookieMapItPair(cookies_.begin(), cookies_.end()),
        &cookie_its);

    if (cookie_its.size() > kMaxCookies) {
      DVLOG(net::cookie_util::kVlogGarbageCollection)
          << "Deep Garbage Collect everything.";
      size_t purge_goal = cookie_its.size() - (kMaxCookies - kPurgeCookies);
      DCHECK(purge_goal > kPurgeCookies);

      CookieItVector secure_cookie_its;
      CookieItVector non_secure_cookie_its;
      SplitCookieVectorIntoSecureAndNonSecure(cookie_its, &secure_cookie_its,
                                              &non_secure_cookie_its);
      size_t non_secure_purge_goal =
          std::min<size_t>(purge_goal, non_secure_cookie_its.size());

      base::Time earliest_non_secure_access_time;
      size_t just_deleted = GarbageCollectLeastRecentlyAccessed(
          current, safe_date, non_secure_purge_goal,
          std::move(non_secure_cookie_its), &earliest_non_secure_access_time);
      num_deleted += just_deleted;

      if (secure_cookie_its.size() == 0) {
        // This case is unlikely, but should still update
        // |earliest_access_time_| if only have non-secure cookies.
        earliest_access_time_ = earliest_non_secure_access_time;
        // Garbage collection can't delete all cookies.
        DCHECK(!earliest_access_time_.is_null());
      } else if (just_deleted < purge_goal) {
        size_t secure_purge_goal = std::min<size_t>(purge_goal - just_deleted,
                                                    secure_cookie_its.size());
        base::Time earliest_secure_access_time;
        num_deleted += GarbageCollectLeastRecentlyAccessed(
            current, safe_date, secure_purge_goal, std::move(secure_cookie_its),
            &earliest_secure_access_time);

        if (!earliest_non_secure_access_time.is_null() &&
            earliest_non_secure_access_time < earliest_secure_access_time) {
          earliest_access_time_ = earliest_non_secure_access_time;
        } else {
          earliest_access_time_ = earliest_secure_access_time;
        }

        // Garbage collection can't delete all cookies.
        DCHECK(!earliest_access_time_.is_null());
      }

      // If there are secure cookies, but deleting non-secure cookies was enough
      // to meet the purge goal, secure cookies are never examined, so
      // |earliest_access_time_| can't be determined. Leaving it alone will mean
      // it's no later than the real earliest last access time, so this won't
      // lead to any problems.
    }
  }

  return num_deleted;
}

size_t CookieMonster::GarbageCollectPartitionedCookies(
    const base::Time& current,
    const CookiePartitionKey& cookie_partition_key,
    const std::string& key) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  size_t num_deleted = 0;
  PartitionedCookieMap::iterator cookie_partition_it =
      partitioned_cookies_.find(cookie_partition_key);

  if (cookie_partition_it == partitioned_cookies_.end())
    return num_deleted;

  if (NumBytesInCookieMapForKey(*cookie_partition_it->second.get(), key) >
          kPerPartitionDomainMaxCookieBytes ||
      cookie_partition_it->second->count(key) > kPerPartitionDomainMaxCookies) {
    // TODO(crbug.com/40188414): Log garbage collection for partitioned cookies.

    CookieItVector non_expired_cookie_its;
    num_deleted += GarbageCollectExpiredPartitionedCookies(
        current, cookie_partition_it,
        cookie_partition_it->second->equal_range(key), &non_expired_cookie_its);

    size_t bytes_used = NumBytesInCookieItVector(non_expired_cookie_its);

    if (bytes_used > kPerPartitionDomainMaxCookieBytes ||
        non_expired_cookie_its.size() > kPerPartitionDomainMaxCookies) {
      // TODO(crbug.com/40188414): Log deep garbage collection for partitioned
      // cookies.
      std::sort(non_expired_cookie_its.begin(), non_expired_cookie_its.end(),
                LRACookieSorter);

      for (size_t i = 0;
           bytes_used > kPerPartitionDomainMaxCookieBytes ||
           non_expired_cookie_its.size() - i > kPerPartitionDomainMaxCookies;
           ++i) {
        bytes_used -= NameValueSizeBytes(*non_expired_cookie_its[i]->second);
        InternalDeletePartitionedCookie(
            cookie_partition_it, non_expired_cookie_its[i], true,
            DELETE_COOKIE_EVICTED_PER_PARTITION_DOMAIN);
        ++num_deleted;
      }
    }
  }

  // TODO(crbug.com/40188414): Enforce global limit on partitioned cookies.

  return num_deleted;
}

size_t CookieMonster::PurgeLeastRecentMatches(CookieItVector* cookies,
                                              CookiePriority priority,
                                              size_t to_protect,
                                              size_t purge_goal,
                                              bool protect_secure_cookies) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // 1. Count number of the cookies at |priority|
  size_t cookies_count_possibly_to_be_deleted = CountCookiesForPossibleDeletion(
      priority, cookies, false /* count all cookies */);

  // 2. If |cookies_count_possibly_to_be_deleted| at |priority| is less than or
  // equal |to_protect|, skip round in order to preserve the quota. This
  // involves secure and non-secure cookies at |priority|.
  if (cookies_count_possibly_to_be_deleted <= to_protect)
    return 0u;

  // 3. Calculate number of secure cookies at |priority|
  // and number of cookies at |priority| that can possibly be deleted.
  // It is guaranteed we do not delete more than |purge_goal| even if
  // |cookies_count_possibly_to_be_deleted| is higher.
  size_t secure_cookies = 0u;
  if (protect_secure_cookies) {
    secure_cookies = CountCookiesForPossibleDeletion(
        priority, cookies, protect_secure_cookies /* count secure cookies */);
    cookies_count_possibly_to_be_deleted -=
        std::max(secure_cookies, to_protect);
  } else {
    cookies_count_possibly_to_be_deleted -= to_protect;
  }

  size_t removed = 0u;
  size_t current = 0u;
  while ((removed < purge_goal && current < cookies->size()) &&
         cookies_count_possibly_to_be_deleted > 0) {
    const CanonicalCookie* current_cookie = cookies->at(current)->second.get();
    // Only delete the current cookie if the priority is equal to
    // the current level.
    if (IsCookieEligibleForEviction(priority, protect_secure_cookies,
                                    current_cookie)) {
      InternalDeleteCookie(cookies->at(current), true,
                           DELETE_COOKIE_EVICTED_DOMAIN);
      cookies->erase(cookies->begin() + current);
      removed++;
      cookies_count_possibly_to_be_deleted--;
    } else {
      current++;
    }
  }
  return removed;
}

size_t CookieMonster::PurgeLeastRecentMatchesForOBC(
    CookieItList* cookies,
    CookiePriority priority,
    size_t to_protect,
    size_t purge_goal,
    bool delete_secure_cookies) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // 1. Count number of the cookies at `priority`. Includes both secure and
  // non-secure cookies.
  DeletionCookieLists could_be_deleted;
  size_t total_could_be_deleted_for_priority =
      CountCookiesAndGenerateListsForPossibleDeletion(
          priority, could_be_deleted, cookies, delete_secure_cookies);

  // 2. If we have fewer cookies at this priority than we intend to keep/protect
  // then just skip this round entirely.
  if (total_could_be_deleted_for_priority <= to_protect) {
    return 0u;
  }

  // 3. Calculate the number of cookies that could be deleted for this round.
  // This number is the lesser of either: The number of cookies that exist at
  // this {priority, secureness} tuple, or the number of cookies at this
  // priority less the number to protect. We won't exceed the `purge_goal` even
  // if this resulting value is larger.
  size_t total_deletable = could_be_deleted.host_cookies.size() +
                           could_be_deleted.domain_cookies.size();
  size_t max_cookies_to_delete_this_round = std::min(
      total_deletable, total_could_be_deleted_for_priority - to_protect);

  // 4. Remove domain cookies. As per "Origin-Bound Cookies" behavior, domain
  // cookies should always be deleted before host cookies.
  size_t removed = 0u;
  // At this point we have 3 layers of iterators to consider:
  // * The `could_be_deleted` list's iterator, which points to...
  // * The `cookies` list's iterator, which points to...
  // * The CookieMap's iterator which is used to delete the actual cookie from
  // the backend.
  // For each cookie deleted all three of these will need to erased, in a bottom
  // up approach.
  for (auto domain_list_it = could_be_deleted.domain_cookies.begin();
       domain_list_it != could_be_deleted.domain_cookies.end() &&
       removed < purge_goal && max_cookies_to_delete_this_round > 0;) {
    auto cookies_list_it = *domain_list_it;
    auto cookie_map_it = *cookies_list_it;
    // Delete from the cookie store.
    InternalDeleteCookie(cookie_map_it, /*sync_to_store=*/true,
                         DELETE_COOKIE_EVICTED_DOMAIN);
    // Delete from `cookies`.
    cookies->erase(cookies_list_it);
    // Delete from `could_be_deleted`.
    domain_list_it = could_be_deleted.domain_cookies.erase(domain_list_it);

    max_cookies_to_delete_this_round--;
    removed++;
  }

  // 5. Remove host cookies
  for (auto host_list_it = could_be_deleted.host_cookies.begin();
       host_list_it != could_be_deleted.host_cookies.end() &&
       removed < purge_goal && max_cookies_to_delete_this_round > 0;) {
    auto cookies_list_it = *host_list_it;
    auto cookie_map_it = *cookies_list_it;
    // Delete from the cookie store.
    InternalDeleteCookie(cookie_map_it, /*sync_to_store=*/true,
                         DELETE_COOKIE_EVICTED_DOMAIN);
    // Delete from `cookies`.
    cookies->erase(cookies_list_it);
    // Delete from `could_be_deleted`.
    host_list_it = could_be_deleted.host_cookies.erase(host_list_it);

    max_cookies_to_delete_this_round--;
    removed++;
  }
  return removed;
}

size_t CookieMonster::GarbageCollectExpired(const Time& current,
                                            const CookieMapItPair& itpair,
                                            CookieItVector* cookie_its) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  int num_deleted = 0;
  for (CookieMap::iterator it = itpair.first, end = itpair.second; it != end;) {
    auto curit = it;
    ++it;

    if (curit->second->IsExpired(current)) {
      InternalDeleteCookie(curit, true, DELETE_COOKIE_EXPIRED);
      ++num_deleted;
    } else if (cookie_its) {
      cookie_its->push_back(curit);
    }
  }

  return num_deleted;
}

size_t CookieMonster::GarbageCollectExpiredPartitionedCookies(
    const Time& current,
    const PartitionedCookieMap::iterator& cookie_partition_it,
    const CookieMapItPair& itpair,
    CookieItVector* cookie_its) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  int num_deleted = 0;
  for (CookieMap::iterator it = itpair.first, end = itpair.second; it != end;) {
    auto curit = it;
    ++it;

    if (curit->second->IsExpired(current)) {
      InternalDeletePartitionedCookie(cookie_partition_it, curit, true,
                                      DELETE_COOKIE_EXPIRED);
      ++num_deleted;
    } else if (cookie_its) {
      cookie_its->push_back(curit);
    }
  }

  return num_deleted;
}

void CookieMonster::GarbageCollectAllExpiredPartitionedCookies(
    const Time& current) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  for (auto it = partitioned_cookies_.begin();
       it != partitioned_cookies_.end();) {
    // GarbageCollectExpiredPartitionedCookies calls
    // InternalDeletePartitionedCookie which may invalidate
    // |cur_cookie_partition_it|.
    auto cur_cookie_partition_it = it;
    ++it;
    GarbageCollectExpiredPartitionedCookies(
        current, cur_cookie_partition_it,
        CookieMapItPair(cur_cookie_partition_it->second->begin(),
                        cur_cookie_partition_it->second->end()),
        nullptr /*cookie_its*/);
  }
}

size_t CookieMonster::GarbageCollectDeleteRange(
    const Time& current,
    DeletionCause cause,
    CookieItVector::iterator it_begin,
    CookieItVector::iterator it_end) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  for (auto it = it_begin; it != it_end; it++) {
    InternalDeleteCookie((*it), true, cause);
  }
  return it_end - it_begin;
}

size_t CookieMonster::GarbageCollectLeastRecentlyAccessed(
    const base::Time& current,
    const base::Time& safe_date,
    size_t purge_goal,
    CookieItVector cookie_its,
    base::Time* earliest_time) {
  DCHECK_LE(purge_goal, cookie_its.size());
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Sorts up to *and including* |cookie_its[purge_goal]| (if it exists), so
  // |earliest_time| will be properly assigned even if
  // |global_purge_it| == |cookie_its.begin() + purge_goal|.
  SortLeastRecentlyAccessed(
      cookie_its.begin(), cookie_its.end(),
      cookie_its.size() < purge_goal ? purge_goal + 1 : purge_goal);
  // Find boundary to cookies older than safe_date.
  auto global_purge_it = LowerBoundAccessDate(
      cookie_its.begin(), cookie_its.begin() + purge_goal, safe_date);
  // Only delete the old cookies and delete non-secure ones first.
  size_t num_deleted =
      GarbageCollectDeleteRange(current, DELETE_COOKIE_EVICTED_GLOBAL,
                                cookie_its.begin(), global_purge_it);
  if (global_purge_it != cookie_its.end())
    *earliest_time = (*global_purge_it)->second->LastAccessDate();
  return num_deleted;
}

// A wrapper around registry_controlled_domains::GetDomainAndRegistry
// to make clear we're creating a key for our local map or for the persistent
// store's use. Here 
"""


```