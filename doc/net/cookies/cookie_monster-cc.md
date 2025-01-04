Response:
The user wants a summary of the functionality of the `cookie_monster.cc` file in the Chromium network stack. They also want to know about its relationship to JavaScript, logical reasoning (input/output), common user/programming errors, and how user actions lead to this code being executed (debugging clues).

**Plan:**

1. **Functionality Summary:**  Focus on the core responsibilities of `CookieMonster`: managing cookies (setting, getting, deleting), persistence, and applying cookie policies.
2. **JavaScript Relationship:** Explain how JavaScript's `document.cookie` interacts with the browser's cookie management system, including `CookieMonster`. Provide a simple example.
3. **Logical Reasoning (Input/Output):**  Choose a simple function, like `SetCanonicalCookie`, and describe a hypothetical input (a cookie) and its expected effect (cookie storage).
4. **User/Programming Errors:** Identify common mistakes related to cookie handling, such as setting incorrect domain/path attributes or exceeding cookie limits.
5. **User Actions (Debugging Clues):**  Outline the sequence of user actions that trigger cookie-related operations, like visiting a website or JavaScript manipulating cookies.
6. **Part 1 Summary:** Concisely summarize the main functions covered in the provided code snippet.

**Constraint Checklist:**

* 列举一下它的功能: Yes
* 如果它与javascript的功能有关系，请做出对应的举例说明: Yes
* 如果做了逻辑推理，请给出假设输入与输出: Yes
* 如果涉及用户或者编程常见的使用错误，请举例说明: Yes
* 说明用户操作是如何一步步的到达这里，作为调试线索: Yes
* 这是第1部分，共4部分，请归纳一下它的功能: Yes

**Mental Sandbox:**

* **Functionality:**  The code clearly deals with cookie management. It has methods for setting, getting, and deleting cookies. Persistence is handled through the `PersistentCookieStore`. There's also logic for garbage collection and enforcing limits.
* **JavaScript:**  The most obvious connection is `document.cookie`. Setting a cookie in JavaScript ultimately leads to the browser's cookie manager being involved.
* **Input/Output:** Setting a cookie is a good example. Input: cookie data, source URL, options. Output: The cookie being stored (or rejected).
* **Errors:**  Incorrect domain attributes are a classic mistake. Also, exceeding cookie limits can lead to unexpected behavior.
* **User Actions:**  Typing a URL, clicking a link, or JavaScript setting a cookie are key actions.
* **Part 1 Summary:** The provided code focuses on the basic structure of `CookieMonster`, asynchronous API methods, and core cookie manipulation logic.

**Refinement:**

* For the JavaScript example, keep it simple and focus on the connection to `CookieMonster`.
* When describing input/output, specify the data types involved for clarity.
* For user errors, highlight the consequences of those errors.
* For debugging clues, provide a clear sequence of events.

Strategizing complete. I will now generate the response following these steps.
这是 `net/cookies/cookie_monster.cc` 文件的第一部分，它主要负责 Chromium 网络栈中 Cookie 的核心管理功能。  以下是对其功能的归纳：

**功能归纳 (基于第1部分代码):**

1. **Cookie 的存储和管理:** `CookieMonster` 类是 Chromium 中负责存储、检索和管理 HTTP Cookie 的核心组件。它维护着内存中的 Cookie 缓存 (`cookies_` 和 `partitioned_cookies_`)，并负责与持久化存储 (`PersistentCookieStore`) 进行交互。

2. **异步 API:**  提供了异步的 API 来执行 Cookie 的操作，例如设置 (`SetCanonicalCookieAsync`, `SetAllCookiesAsync`)、获取 (`GetCookieListWithOptionsAsync`, `GetAllCookiesAsync`) 和删除 (`DeleteCanonicalCookieAsync`, `DeleteAllCreatedInTimeRangeAsync`, `DeleteAllMatchingInfoAsync`, `DeleteSessionCookiesAsync`, `DeleteMatchingCookiesAsync`) Cookie。 这些异步操作通过 `DoCookieCallback` 和 `DoCookieCallbackForURL/HostOrDomain` 等方法将任务放入队列中，确保操作不会阻塞主线程。

3. **与持久化存储交互:**  `CookieMonster` 使用 `PersistentCookieStore` 来持久化存储 Cookie 数据，以便在浏览器重启后仍然可以恢复 Cookie。  它会在适当的时机从持久化存储加载 Cookie，并在内存中的 Cookie 发生变化时同步到持久化存储。

4. **Cookie 策略执行:**  `CookieMonster` 负责执行各种 Cookie 策略，例如 SameSite 属性的限制、Secure 属性的限制、HttpOnly 属性的限制等。  从代码中可以看出，它在 `GetCookieListWithOptions` 方法中会根据 `CookieOptions` 对 Cookie 进行过滤。

5. **Cookie 过期和清理:**  `GarbageCollectExpired` 和 `GarbageCollectAllExpiredPartitionedCookies` 方法负责清理过期的 Cookie，以避免 Cookie 列表无限增长。

6. **Cookie 变更通知:**  通过 `CookieChangeDispatcher` 类来通知 Cookie 的变更，例如添加、删除或修改。这允许其他组件监听 Cookie 的变化。

7. **支持 Partitioned Cookies (CHIPS):**  代码中出现了 `partitioned_cookies_` 成员变量，这表明 `CookieMonster` 支持 Partitioned Cookies (Cookies Having Independent Partitioned State)，也称为 CHIPS。Partitioned Cookies 允许顶级站点为每个嵌入的第三方站点拥有独立的 Cookie 存储。

8. **线程安全:**  通过 `base::ThreadChecker` 确保 `CookieMonster` 的方法只能在创建它的线程上调用。

9. **NetLog 集成:**  使用 `net::NetLog` 来记录 Cookie 相关的事件，用于调试和性能分析。

10. **Cookie 配额管理:**  代码中定义了诸如 `kDomainMaxCookies` 和 `kMaxCookies` 等常量，表明 `CookieMonster` 具备一定的 Cookie 配额管理机制，防止单个域名或所有域名存储过多的 Cookie。

**与 Javascript 功能的关系和举例说明:**

`CookieMonster` 直接响应 JavaScript 代码中通过 `document.cookie` 进行的 Cookie 操作。

**举例说明:**

假设一个网页的 JavaScript 代码执行了以下操作：

```javascript
document.cookie = "myCookie=myValue; domain=example.com; path=/";
```

1. **用户操作:** JavaScript 代码调用 `document.cookie` 设置 Cookie。
2. **浏览器处理:** 浏览器接收到这个设置 Cookie 的请求。
3. **`CookieMonster` 介入:**  浏览器的网络栈会将这个请求传递给 `CookieMonster`。
4. **`SetCanonicalCookieAsync` 调用:**  `CookieMonster` 内部可能会调用 `SetCanonicalCookieAsync` 方法来处理这个请求，创建一个 `CanonicalCookie` 对象并将其存储在内存中。
5. **持久化存储 (可选):** 如果是非会话 Cookie，`CookieMonster` 还会通知 `PersistentCookieStore` 将其写入持久化存储。
6. **后续访问:** 当 JavaScript 代码或浏览器发起对 `example.com` 的请求时，`CookieMonster` 会根据请求的 URL 和 Cookie 策略，从内存中检索相关的 Cookie，并将其添加到 HTTP 请求头中。

**逻辑推理的假设输入与输出:**

**假设输入:**

* **方法:** `SetCanonicalCookieAsync`
* **`cookie`:** 一个指向 `CanonicalCookie` 对象的智能指针，表示要设置的 Cookie，例如：`name="test_cookie"`, `value="test_value"`, `domain="example.com"`, `path="/"`.
* **`source_url`:** `GURL("https://www.example.com")`
* **`options`:**  `CookieOptions()` (默认选项)

**假设输出:**

* 如果设置成功，`CookieMonster` 的内部 Cookie 存储 (`cookies_`) 中会添加或更新一个与输入 Cookie 匹配的 `CanonicalCookie` 对象。
* 如果这是一个非会话 Cookie，并且持久化存储已加载，则该 Cookie 也会被写入到 `PersistentCookieStore` 中。
* 如果设置失败（例如，违反了 Cookie 策略），则 Cookie 不会被存储，并且可能会触发错误或警告日志。

**涉及用户或者编程常见的使用错误和举例说明:**

1. **设置错误的 Domain 或 Path:**
   * **错误示例 (JavaScript):** `document.cookie = "myCookie=myValue; domain=sub.anotherdomain.com";`  如果当前页面是 `example.com`，则这个 Cookie 将无法被设置，因为域名不匹配。
   * **后果:** Cookie 不会被正确地存储或发送，导致网站功能异常。

2. **设置 Secure 属性的 Cookie 在非 HTTPS 页面上:**
   * **错误示例 (JavaScript):** 在 `http://example.com` 页面上设置 `document.cookie = "secureCookie=value; Secure";`
   * **后果:** 浏览器通常会阻止这种操作，因为 Secure 属性的 Cookie 只能在 HTTPS 连接下设置。

3. **Cookie 名称或值包含控制字符:**
   * **代码中的提示:**  `ContainsControlCharacter(cookie->Name())` 和 `ContainsControlCharacter(cookie->Value())` 表明 `CookieMonster` 会检查控制字符。
   * **错误示例 (尝试通过编程方式设置包含控制字符的 Cookie):**  尝试设置一个名字包含换行符的 Cookie。
   * **后果:**  `CookieMonster` 会拒绝存储这种 Cookie，并在日志中记录错误。

4. **超出 Cookie 数量或大小限制:**
   * **代码中的常量:** `kDomainMaxCookies`, `kMaxCookies`, `kPerPartitionDomainMaxCookieBytes`, `kPerPartitionDomainMaxCookies` 等定义了限制。
   * **用户操作示例:**  一个网站尝试设置大量 Cookie 或非常大的 Cookie。
   * **后果:**  `CookieMonster` 会根据 LRU (Least Recently Used) 或其他策略清理旧的 Cookie，或者直接拒绝设置新的 Cookie。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

以下是一些用户操作如何触发 `net/cookies/cookie_monster.cc` 中代码执行的场景：

1. **用户在浏览器地址栏输入 URL 并访问网站:**
   * 用户输入 URL，例如 `https://www.example.com` 并按下回车。
   * 浏览器发起对该 URL 的 HTTP 请求。
   * **调试线索:** 在请求发送之前，网络栈会调用 `CookieMonster::GetCookieListWithOptionsAsync` 或类似的方法，根据目标 URL 和 Cookie 策略，检索需要添加到请求头中的 Cookie。

2. **网页通过 JavaScript 设置 Cookie:**
   * 网页上的 JavaScript 代码执行 `document.cookie = "..."`。
   * 浏览器接收到这个设置 Cookie 的指令。
   * **调试线索:** 浏览器会将这个请求传递给 `CookieMonster::SetCanonicalCookieAsync` 或 `CookieMonster::SetAllCookiesAsync` 来处理。

3. **网页发起包含 Cookie 的请求:**
   * 网页上的 JavaScript 代码或浏览器自身发起对服务器的请求 (例如，加载图片、AJAX 请求)。
   * **调试线索:**  在发送请求之前，网络栈会再次调用 `CookieMonster::GetCookieListWithOptionsAsync` 来获取与目标 URL 匹配的 Cookie。

4. **用户清除浏览器 Cookie:**
   * 用户在浏览器设置中选择清除 Cookie。
   * **调试线索:**  浏览器会调用 `CookieMonster` 相应的删除方法，例如 `DeleteAllMatchingInfoAsync` 或 `DeleteSessionCookiesAsync`。

5. **浏览器启动或关闭:**
   * **启动:** 浏览器启动时，`CookieMonster` 会尝试从 `PersistentCookieStore` 加载之前保存的 Cookie。
   * **关闭:** 浏览器关闭时，`CookieMonster` 会将内存中的 Cookie 同步到 `PersistentCookieStore` (如果适用)。

**总结:**

`net/cookies/cookie_monster.cc` 的这部分代码是 Chromium 中 Cookie 管理的核心，负责存储、检索、删除 Cookie，执行 Cookie 策略，并与持久化存储进行交互。它通过异步 API 响应来自浏览器其他组件（包括 JavaScript 代码触发的操作）的 Cookie 请求，并维护 Cookie 的生命周期。 理解 `CookieMonster` 的工作原理对于调试网络请求中与 Cookie 相关的问题至关重要。

Prompt: 
```
这是目录为net/cookies/cookie_monster.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Portions of this code based on Mozilla:
//   (netwerk/cookie/src/nsCookieService.cpp)
/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is mozilla.org code.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 2003
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Daniel Witte (dwitte@stanford.edu)
 *   Michiel van Leeuwen (mvl@exedo.nl)
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/cookies/cookie_monster.h"

#include <functional>
#include <list>
#include <numeric>
#include <optional>
#include <set>
#include <string_view>
#include <utility>

#include "base/check_is_test.h"
#include "base/containers/flat_map.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/ranges/algorithm.h"
#include "base/strings/strcat.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/thread_checker.h"
#include "base/time/time.h"
#include "net/base/isolation_info.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "net/base/schemeful_site.h"
#include "net/base/url_util.h"
#include "net/cookies/canonical_cookie.h"
#include "net/cookies/cookie_constants.h"
#include "net/cookies/cookie_monster_change_dispatcher.h"
#include "net/cookies/cookie_monster_netlog_params.h"
#include "net/cookies/cookie_partition_key.h"
#include "net/cookies/cookie_partition_key_collection.h"
#include "net/cookies/cookie_util.h"
#include "net/cookies/parsed_cookie.h"
#include "net/http/http_util.h"
#include "net/log/net_log.h"
#include "net/log/net_log_values.h"
#include "url/origin.h"
#include "url/third_party/mozilla/url_parse.h"
#include "url/url_canon.h"
#include "url/url_constants.h"

using base::Time;
using base::TimeTicks;
using TimeRange = net::CookieDeletionInfo::TimeRange;

// In steady state, most cookie requests can be satisfied by the in memory
// cookie monster store. If the cookie request cannot be satisfied by the in
// memory store, the relevant cookies must be fetched from the persistent
// store. The task is queued in CookieMonster::tasks_pending_ if it requires
// all cookies to be loaded from the backend, or tasks_pending_for_key_ if it
// only requires all cookies associated with an eTLD+1.
//
// On the browser critical paths (e.g. for loading initial web pages in a
// session restore) it may take too long to wait for the full load. If a cookie
// request is for a specific URL, DoCookieCallbackForURL is called, which
// triggers a priority load if the key is not loaded yet by calling
// PersistentCookieStore::LoadCookiesForKey. The request is queued in
// CookieMonster::tasks_pending_for_key_ and executed upon receiving
// notification of key load completion via CookieMonster::OnKeyLoaded(). If
// multiple requests for the same eTLD+1 are received before key load
// completion, only the first request calls
// PersistentCookieStore::LoadCookiesForKey, all subsequent requests are queued
// in CookieMonster::tasks_pending_for_key_ and executed upon receiving
// notification of key load completion triggered by the first request for the
// same eTLD+1.

static const int kDaysInTenYears = 10 * 365;
static const int kMinutesInTenYears = kDaysInTenYears * 24 * 60;

namespace {

// This enum is used to generate a histogramed bitmask measureing the types
// of stored cookies. Please do not reorder the list when adding new entries.
// New items MUST be added at the end of the list, just before
// COOKIE_TYPE_LAST_ENTRY;
// There will be 2^COOKIE_TYPE_LAST_ENTRY buckets in the linear histogram.
enum CookieType {
  COOKIE_TYPE_SAME_SITE = 0,
  COOKIE_TYPE_HTTPONLY,
  COOKIE_TYPE_SECURE,
  COOKIE_TYPE_PERSISTENT,
  COOKIE_TYPE_LAST_ENTRY
};

void MaybeRunDeleteCallback(base::WeakPtr<net::CookieMonster> cookie_monster,
                            base::OnceClosure callback) {
  if (cookie_monster && callback)
    std::move(callback).Run();
}

template <typename CB, typename... R>
void MaybeRunCookieCallback(base::OnceCallback<CB> callback, R&&... result) {
  if (callback) {
    std::move(callback).Run(std::forward<R>(result)...);
  }
}

// Anonymous and Fenced Frame uses a CookiePartitionKey with a nonce. In these
// contexts, access to unpartitioned cookie is not granted.
//
// This returns true if the |list| of key should include unpartitioned cookie in
// GetCookie...().
bool IncludeUnpartitionedCookies(
    const net::CookiePartitionKeyCollection& list) {
  if (list.IsEmpty() || list.ContainsAllKeys())
    return true;

  for (const net::CookiePartitionKey& key : list.PartitionKeys()) {
    if (!key.nonce())
      return true;
  }
  return false;
}

size_t NameValueSizeBytes(const net::CanonicalCookie& cc) {
  base::CheckedNumeric<size_t> name_value_pair_size = cc.Name().size();
  name_value_pair_size += cc.Value().size();
  DCHECK(name_value_pair_size.IsValid());
  return name_value_pair_size.ValueOrDie();
}

size_t NumBytesInCookieMapForKey(
    const net::CookieMonster::CookieMap& cookie_map,
    const std::string& key) {
  size_t result = 0;
  auto range = cookie_map.equal_range(key);
  for (auto it = range.first; it != range.second; ++it) {
    result += NameValueSizeBytes(*it->second);
  }
  return result;
}

size_t NumBytesInCookieItVector(
    const net::CookieMonster::CookieItVector& cookie_its) {
  size_t result = 0;
  for (const auto& it : cookie_its) {
    result += NameValueSizeBytes(*it->second);
  }
  return result;
}

void LogStoredCookieToUMA(const net::CanonicalCookie& cc,
                          const net::CookieAccessResult& access_result) {
  // Cookie.Type2 collects a bitvector of important cookie attributes.
  int32_t type_sample =
      !cc.IsEffectivelySameSiteNone(access_result.access_semantics)
          ? 1 << COOKIE_TYPE_SAME_SITE
          : 0;
  type_sample |= cc.IsHttpOnly() ? 1 << COOKIE_TYPE_HTTPONLY : 0;
  type_sample |= cc.SecureAttribute() ? 1 << COOKIE_TYPE_SECURE : 0;
  type_sample |= cc.IsPersistent() ? 1 << COOKIE_TYPE_PERSISTENT : 0;
  UMA_HISTOGRAM_EXACT_LINEAR("Cookie.Type2", type_sample,
                             (1 << COOKIE_TYPE_LAST_ENTRY));

  // Cookie.SourceType collects the CookieSourceType of the stored cookie.
  UMA_HISTOGRAM_ENUMERATION("Cookie.SourceType", cc.SourceType());
}

}  // namespace

namespace net {

// See comments at declaration of these variables in cookie_monster.h
// for details.
const size_t CookieMonster::kDomainMaxCookies = 180;
const size_t CookieMonster::kDomainPurgeCookies = 30;
const size_t CookieMonster::kMaxCookies = 3300;
const size_t CookieMonster::kPurgeCookies = 300;

const size_t CookieMonster::kMaxDomainPurgedKeys = 100;

const size_t CookieMonster::kPerPartitionDomainMaxCookieBytes = 10240;
const size_t CookieMonster::kPerPartitionDomainMaxCookies = 180;

const size_t CookieMonster::kDomainCookiesQuotaLow = 30;
const size_t CookieMonster::kDomainCookiesQuotaMedium = 50;
const size_t CookieMonster::kDomainCookiesQuotaHigh =
    kDomainMaxCookies - kDomainPurgeCookies - kDomainCookiesQuotaLow -
    kDomainCookiesQuotaMedium;

const int CookieMonster::kSafeFromGlobalPurgeDays = 30;

namespace {

bool ContainsControlCharacter(const std::string& s) {
  return base::ranges::any_of(s, &HttpUtil::IsControlChar);
}

typedef std::vector<CanonicalCookie*> CanonicalCookieVector;

// Default minimum delay after updating a cookie's LastAccessDate before we
// will update it again.
const int kDefaultAccessUpdateThresholdSeconds = 60;

// Comparator to sort cookies from highest creation date to lowest
// creation date.
struct OrderByCreationTimeDesc {
  bool operator()(const CookieMonster::CookieMap::iterator& a,
                  const CookieMonster::CookieMap::iterator& b) const {
    return a->second->CreationDate() > b->second->CreationDate();
  }
};

bool LRACookieSorter(const CookieMonster::CookieMap::iterator& it1,
                     const CookieMonster::CookieMap::iterator& it2) {
  if (it1->second->LastAccessDate() != it2->second->LastAccessDate())
    return it1->second->LastAccessDate() < it2->second->LastAccessDate();

  // Ensure stability for == last access times by falling back to creation.
  return it1->second->CreationDate() < it2->second->CreationDate();
}

// For a CookieItVector iterator range [|it_begin|, |it_end|),
// sorts the first |num_sort| elements by LastAccessDate().
void SortLeastRecentlyAccessed(CookieMonster::CookieItVector::iterator it_begin,
                               CookieMonster::CookieItVector::iterator it_end,
                               size_t num_sort) {
  DCHECK_LE(static_cast<int>(num_sort), it_end - it_begin);
  std::partial_sort(it_begin, it_begin + num_sort, it_end, LRACookieSorter);
}

// Given a single cookie vector |cookie_its|, pushs all of the secure cookies in
// |cookie_its| into |secure_cookie_its| and all of the non-secure cookies into
// |non_secure_cookie_its|. Both |secure_cookie_its| and |non_secure_cookie_its|
// must be non-NULL.
void SplitCookieVectorIntoSecureAndNonSecure(
    const CookieMonster::CookieItVector& cookie_its,
    CookieMonster::CookieItVector* secure_cookie_its,
    CookieMonster::CookieItVector* non_secure_cookie_its) {
  DCHECK(secure_cookie_its && non_secure_cookie_its);
  for (const auto& curit : cookie_its) {
    if (curit->second->SecureAttribute()) {
      secure_cookie_its->push_back(curit);
    } else {
      non_secure_cookie_its->push_back(curit);
    }
  }
}

bool LowerBoundAccessDateComparator(const CookieMonster::CookieMap::iterator it,
                                    const Time& access_date) {
  return it->second->LastAccessDate() < access_date;
}

// For a CookieItVector iterator range [|it_begin|, |it_end|)
// from a CookieItVector sorted by LastAccessDate(), returns the
// first iterator with access date >= |access_date|, or cookie_its_end if this
// holds for all.
CookieMonster::CookieItVector::iterator LowerBoundAccessDate(
    const CookieMonster::CookieItVector::iterator its_begin,
    const CookieMonster::CookieItVector::iterator its_end,
    const Time& access_date) {
  return std::lower_bound(its_begin, its_end, access_date,
                          LowerBoundAccessDateComparator);
}

// Mapping between DeletionCause and CookieChangeCause; the
// mapping also provides a boolean that specifies whether or not an
// OnCookieChange notification ought to be generated.
typedef struct ChangeCausePair_struct {
  CookieChangeCause cause;
  bool notify;
} ChangeCausePair;
const ChangeCausePair kChangeCauseMapping[] = {
    // DELETE_COOKIE_EXPLICIT
    {CookieChangeCause::EXPLICIT, true},
    // DELETE_COOKIE_OVERWRITE
    {CookieChangeCause::OVERWRITE, true},
    // DELETE_COOKIE_EXPIRED
    {CookieChangeCause::EXPIRED, true},
    // DELETE_COOKIE_EVICTED
    {CookieChangeCause::EVICTED, true},
    // DELETE_COOKIE_DUPLICATE_IN_BACKING_STORE
    {CookieChangeCause::EXPLICIT, false},
    // DELETE_COOKIE_DONT_RECORD
    {CookieChangeCause::EXPLICIT, false},
    // DELETE_COOKIE_EVICTED_DOMAIN
    {CookieChangeCause::EVICTED, true},
    // DELETE_COOKIE_EVICTED_GLOBAL
    {CookieChangeCause::EVICTED, true},
    // DELETE_COOKIE_EVICTED_DOMAIN_PRE_SAFE
    {CookieChangeCause::EVICTED, true},
    // DELETE_COOKIE_EVICTED_DOMAIN_POST_SAFE
    {CookieChangeCause::EVICTED, true},
    // DELETE_COOKIE_EXPIRED_OVERWRITE
    {CookieChangeCause::EXPIRED_OVERWRITE, true},
    // DELETE_COOKIE_CONTROL_CHAR
    {CookieChangeCause::EVICTED, true},
    // DELETE_COOKIE_NON_SECURE
    {CookieChangeCause::EVICTED, true},
    // DELETE_COOKIE_EVICTED_PER_PARTITION_DOMAIN
    {CookieChangeCause::EVICTED, true},
    // DELETE_COOKIE_LAST_ENTRY
    {CookieChangeCause::EXPLICIT, false}};

bool IsCookieEligibleForEviction(CookiePriority current_priority_level,
                                 bool protect_secure_cookies,
                                 const CanonicalCookie* cookie) {
  if (cookie->Priority() == current_priority_level && protect_secure_cookies)
    return !cookie->SecureAttribute();

  return cookie->Priority() == current_priority_level;
}

size_t CountCookiesForPossibleDeletion(
    CookiePriority priority,
    const CookieMonster::CookieItVector* cookies,
    bool protect_secure_cookies) {
  size_t cookies_count = 0U;
  for (const auto& cookie : *cookies) {
    if (cookie->second->Priority() == priority) {
      if (!protect_secure_cookies || cookie->second->SecureAttribute()) {
        cookies_count++;
      }
    }
  }
  return cookies_count;
}

struct DeletionCookieLists {
  std::list<CookieMonster::CookieItList::const_iterator> host_cookies;
  std::list<CookieMonster::CookieItList::const_iterator> domain_cookies;
};

// Performs 2 tasks
// * Counts every cookie at the given `priority` in `cookies`. This is the
// return value.
// * Fills in the host & domain lists for `could_be_deleted` with every cookie
// of the given {secureness, priority} in `cookies`.
size_t CountCookiesAndGenerateListsForPossibleDeletion(
    CookiePriority priority,
    DeletionCookieLists& could_be_deleted,
    const CookieMonster::CookieItList* cookies,
    bool generate_for_secure) {
  size_t total_cookies_at_priority = 0;

  for (auto list_it = cookies->begin(); list_it != cookies->end(); list_it++) {
    const auto cookiemap_it = *list_it;
    const auto& cookie = cookiemap_it->second;

    if (cookie->Priority() != priority) {
      continue;
    }

    // Because we want to keep a specific number of cookies per priority level,
    // independent of securness of the cookies, we need to count all the cookies
    // at the level even if we'll skip adding them to the deletion lists.
    total_cookies_at_priority++;

    if (cookie->IsSecure() != generate_for_secure) {
      continue;
    }

    if (cookie->IsHostCookie()) {
      could_be_deleted.host_cookies.push_back(list_it);
    } else {  // Is a domain cookie.
      could_be_deleted.domain_cookies.push_back(list_it);
    }
  }

  return total_cookies_at_priority;
}

// Records minutes until the expiration date of a cookie to the appropriate
// histogram. Only histograms cookies that have an expiration date (i.e. are
// persistent).
void HistogramExpirationDuration(const CanonicalCookie& cookie,
                                 base::Time creation_time) {
  if (!cookie.IsPersistent())
    return;

  int expiration_duration_minutes =
      (cookie.ExpiryDate() - creation_time).InMinutes();
  if (cookie.SecureAttribute()) {
    UMA_HISTOGRAM_CUSTOM_COUNTS("Cookie.ExpirationDurationMinutesSecure",
                                expiration_duration_minutes, 1,
                                kMinutesInTenYears, 50);
  } else {
    UMA_HISTOGRAM_CUSTOM_COUNTS("Cookie.ExpirationDurationMinutesNonSecure",
                                expiration_duration_minutes, 1,
                                kMinutesInTenYears, 50);
  }
  // The proposed rfc6265bis sets an upper limit on Expires/Max-Age attribute
  // values of 400 days. We need to study the impact this change would have:
  // https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html
  int expiration_duration_days = (cookie.ExpiryDate() - creation_time).InDays();
  if (expiration_duration_days > 400) {
    UMA_HISTOGRAM_CUSTOM_COUNTS("Cookie.ExpirationDuration400DaysGT",
                                expiration_duration_days, 401, kDaysInTenYears,
                                100);
  } else {
    UMA_HISTOGRAM_CUSTOM_COUNTS("Cookie.ExpirationDuration400DaysLTE",
                                expiration_duration_days, 1, 400, 50);
  }
}

}  // namespace

CookieMonster::CookieMonster(scoped_refptr<PersistentCookieStore> store,
                             NetLog* net_log)
    : CookieMonster(std::move(store),
                    base::Seconds(kDefaultAccessUpdateThresholdSeconds),
                    net_log) {}

CookieMonster::CookieMonster(scoped_refptr<PersistentCookieStore> store,
                             base::TimeDelta last_access_threshold,
                             NetLog* net_log)
    : change_dispatcher_(this),
      net_log_(NetLogWithSource::Make(net_log, NetLogSourceType::COOKIE_STORE)),
      store_(std::move(store)),
      last_access_threshold_(last_access_threshold),
      last_statistic_record_time_(base::Time::Now()) {
  cookieable_schemes_.insert(
      cookieable_schemes_.begin(), kDefaultCookieableSchemes,
      kDefaultCookieableSchemes + kDefaultCookieableSchemesCount);
  net_log_.BeginEvent(NetLogEventType::COOKIE_STORE_ALIVE, [&] {
    return NetLogCookieMonsterConstructorParams(store_ != nullptr);
  });
}

// Asynchronous CookieMonster API

void CookieMonster::FlushStore(base::OnceClosure callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (initialized_ && store_.get()) {
    store_->Flush(std::move(callback));
  } else if (callback) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, std::move(callback));
  }
}

void CookieMonster::SetForceKeepSessionState() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (store_)
    store_->SetForceKeepSessionState();
}

void CookieMonster::SetAllCookiesAsync(const CookieList& list,
                                       SetCookiesCallback callback) {
  DoCookieCallback(base::BindOnce(
      // base::Unretained is safe as DoCookieCallback stores
      // the callback on |*this|, so the callback will not outlive
      // the object.
      &CookieMonster::SetAllCookies, base::Unretained(this), list,
      std::move(callback)));
}

void CookieMonster::SetCanonicalCookieAsync(
    std::unique_ptr<CanonicalCookie> cookie,
    const GURL& source_url,
    const CookieOptions& options,
    SetCookiesCallback callback,
    std::optional<CookieAccessResult> cookie_access_result) {
  DCHECK(cookie->IsCanonical());

  std::string domain = cookie->Domain();
  DoCookieCallbackForHostOrDomain(
      base::BindOnce(
          // base::Unretained is safe as DoCookieCallbackForHostOrDomain stores
          // the callback on |*this|, so the callback will not outlive
          // the object.
          &CookieMonster::SetCanonicalCookie, base::Unretained(this),
          std::move(cookie), source_url, options, std::move(callback),
          std::move(cookie_access_result)),
      domain);
}

void CookieMonster::GetCookieListWithOptionsAsync(
    const GURL& url,
    const CookieOptions& options,
    const CookiePartitionKeyCollection& cookie_partition_key_collection,
    GetCookieListCallback callback) {
  DoCookieCallbackForURL(
      base::BindOnce(
          // base::Unretained is safe as DoCookieCallbackForURL stores
          // the callback on |*this|, so the callback will not outlive
          // the object.
          &CookieMonster::GetCookieListWithOptions, base::Unretained(this), url,
          options, cookie_partition_key_collection, std::move(callback)),
      url);
}

void CookieMonster::GetAllCookiesAsync(GetAllCookiesCallback callback) {
  DoCookieCallback(base::BindOnce(
      // base::Unretained is safe as DoCookieCallback stores
      // the callback on |*this|, so the callback will not outlive
      // the object.
      &CookieMonster::GetAllCookies, base::Unretained(this),
      std::move(callback)));
}

void CookieMonster::GetAllCookiesWithAccessSemanticsAsync(
    GetAllCookiesWithAccessSemanticsCallback callback) {
  DoCookieCallback(base::BindOnce(
      // base::Unretained is safe as DoCookieCallback stores
      // the callback on |*this|, so the callback will not outlive
      // the object.
      &CookieMonster::GetAllCookies, base::Unretained(this),
      base::BindOnce(&CookieMonster::AttachAccessSemanticsListForCookieList,
                     base::Unretained(this), std::move(callback))));
}

void CookieMonster::DeleteCanonicalCookieAsync(const CanonicalCookie& cookie,
                                               DeleteCallback callback) {
  DoCookieCallback(base::BindOnce(
      // base::Unretained is safe as DoCookieCallback stores
      // the callback on |*this|, so the callback will not outlive
      // the object.
      &CookieMonster::DeleteCanonicalCookie, base::Unretained(this), cookie,
      std::move(callback)));
}

void CookieMonster::DeleteAllCreatedInTimeRangeAsync(
    const TimeRange& creation_range,
    DeleteCallback callback) {
  DoCookieCallback(base::BindOnce(
      // base::Unretained is safe as DoCookieCallback stores
      // the callback on |*this|, so the callback will not outlive
      // the object.
      &CookieMonster::DeleteAllCreatedInTimeRange, base::Unretained(this),
      creation_range, std::move(callback)));
}

void CookieMonster::DeleteAllMatchingInfoAsync(CookieDeletionInfo delete_info,
                                               DeleteCallback callback) {
  auto cookie_matcher =
      base::BindRepeating(&CookieMonster::MatchCookieDeletionInfo,
                          base::Unretained(this), std::move(delete_info));

  DoCookieCallback(base::BindOnce(
      // base::Unretained is safe as DoCookieCallback stores
      // the callback on |*this|, so the callback will not outlive
      // the object.
      &CookieMonster::DeleteMatchingCookies, base::Unretained(this),
      std::move(cookie_matcher), DELETE_COOKIE_EXPLICIT, std::move(callback)));
}

void CookieMonster::DeleteSessionCookiesAsync(
    CookieStore::DeleteCallback callback) {
  auto session_cookie_matcher =
      base::BindRepeating([](const net::CanonicalCookie& cookie) {
        return !cookie.IsPersistent();
      });
  DoCookieCallback(base::BindOnce(
      // base::Unretained is safe as DoCookieCallback stores
      // the callback on |*this|, so the callback will not outlive
      // the object.
      &CookieMonster::DeleteMatchingCookies, base::Unretained(this),
      std::move(session_cookie_matcher), DELETE_COOKIE_EXPIRED,
      std::move(callback)));
}

void CookieMonster::DeleteMatchingCookiesAsync(
    CookieStore::DeletePredicate predicate,
    CookieStore::DeleteCallback callback) {
  DoCookieCallback(base::BindOnce(
      // base::Unretained is safe as DoCookieCallback stores
      // the callback on |*this|, so the callback will not outlive
      // the object.
      &CookieMonster::DeleteMatchingCookies, base::Unretained(this),
      std::move(predicate), DELETE_COOKIE_EXPLICIT, std::move(callback)));
}

void CookieMonster::SetCookieableSchemes(
    const std::vector<std::string>& schemes,
    SetCookieableSchemesCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Calls to this method will have no effect if made after a WebView or
  // CookieManager instance has been created.
  if (initialized_) {
    MaybeRunCookieCallback(std::move(callback), false);
    return;
  }

  cookieable_schemes_ = schemes;
  MaybeRunCookieCallback(std::move(callback), true);
}

// This function must be called before the CookieMonster is used.
void CookieMonster::SetPersistSessionCookies(bool persist_session_cookies) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!initialized_);
  net_log_.AddEntryWithBoolParams(
      NetLogEventType::COOKIE_STORE_SESSION_PERSISTENCE, NetLogEventPhase::NONE,
      "persistence", persist_session_cookies);
  persist_session_cookies_ = persist_session_cookies;
}

const char* const CookieMonster::kDefaultCookieableSchemes[] = {"http", "https",
                                                                "ws", "wss"};
const int CookieMonster::kDefaultCookieableSchemesCount =
    std::size(kDefaultCookieableSchemes);

CookieChangeDispatcher& CookieMonster::GetChangeDispatcher() {
  return change_dispatcher_;
}

CookieMonster::~CookieMonster() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  net_log_.EndEvent(NetLogEventType::COOKIE_STORE_ALIVE);
}

// static
bool CookieMonster::CookieSorter(const CanonicalCookie* cc1,
                                 const CanonicalCookie* cc2) {
  // Mozilla sorts on the path length (longest first), and then it sorts by
  // creation time (oldest first).  The RFC says the sort order for the domain
  // attribute is undefined.
  if (cc1->Path().length() == cc2->Path().length())
    return cc1->CreationDate() < cc2->CreationDate();
  return cc1->Path().length() > cc2->Path().length();
}

void CookieMonster::GetAllCookies(GetAllCookiesCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // This function is being called to scrape the cookie list for management UI
  // or similar.  We shouldn't show expired cookies in this list since it will
  // just be confusing to users, and this function is called rarely enough (and
  // is already slow enough) that it's OK to take the time to garbage collect
  // the expired cookies now.
  //
  // Note that this does not prune cookies to be below our limits (if we've
  // exceeded them) the way that calling GarbageCollect() would.
  GarbageCollectExpired(
      Time::Now(), CookieMapItPair(cookies_.begin(), cookies_.end()), nullptr);
  GarbageCollectAllExpiredPartitionedCookies(Time::Now());

  // Copy the CanonicalCookie pointers from the map so that we can use the same
  // sorter as elsewhere, then copy the result out.
  std::vector<CanonicalCookie*> cookie_ptrs;
  cookie_ptrs.reserve(cookies_.size());
  for (const auto& cookie : cookies_)
    cookie_ptrs.push_back(cookie.second.get());

  for (const auto& cookie_partition : partitioned_cookies_) {
    for (const auto& cookie : *cookie_partition.second.get())
      cookie_ptrs.push_back(cookie.second.get());
  }

  std::sort(cookie_ptrs.begin(), cookie_ptrs.end(), CookieSorter);

  CookieList cookie_list;
  cookie_list.reserve(cookie_ptrs.size());
  for (auto* cookie_ptr : cookie_ptrs)
    cookie_list.push_back(*cookie_ptr);

  MaybeRunCookieCallback(std::move(callback), cookie_list);
}

void CookieMonster::AttachAccessSemanticsListForCookieList(
    GetAllCookiesWithAccessSemanticsCallback callback,
    const CookieList& cookie_list) {
  std::vector<CookieAccessSemantics> access_semantics_list;
  for (const CanonicalCookie& cookie : cookie_list) {
    access_semantics_list.push_back(GetAccessSemanticsForCookie(cookie));
  }
  MaybeRunCookieCallback(std::move(callback), cookie_list,
                         access_semantics_list);
}

void CookieMonster::GetCookieListWithOptions(
    const GURL& url,
    const CookieOptions& options,
    const CookiePartitionKeyCollection& cookie_partition_key_collection,
    GetCookieListCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  CookieAccessResultList included_cookies;
  CookieAccessResultList excluded_cookies;
  if (HasCookieableScheme(url)) {
    std::vector<CanonicalCookie*> cookie_ptrs;
    if (IncludeUnpartitionedCookies(cookie_partition_key_collection)) {
      cookie_ptrs = FindCookiesForRegistryControlledHost(url);
    } else {
      DCHECK(!cookie_partition_key_collection.IsEmpty());
    }

    if (!cookie_partition_key_collection.IsEmpty()) {
      if (cookie_partition_key_collection.ContainsAllKeys()) {
        for (PartitionedCookieMap::iterator partition_it =
                 partitioned_cookies_.begin();
             partition_it != partitioned_cookies_.end();) {
          // InternalDeletePartitionedCookie may invalidate |partition_it| if
          // that cookie partition only has one cookie and it expires.
          auto cur_partition_it = partition_it;
          ++partition_it;

          std::vector<CanonicalCookie*> partitioned_cookie_ptrs =
              FindPartitionedCookiesForRegistryControlledHost(
                  cur_partition_it->first, url);
          cookie_ptrs.insert(cookie_ptrs.end(), partitioned_cookie_ptrs.begin(),
                             partitioned_cookie_ptrs.end());
        }
      } else {
        for (const CookiePartitionKey& key :
             cookie_partition_key_collection.PartitionKeys()) {
          std::vector<CanonicalCookie*> partitioned_cookie_ptrs =
              FindPartitionedCookiesForRegistryControlledHost(key, url);
          cookie_ptrs.insert(cookie_ptrs.end(), partitioned_cookie_ptrs.begin(),
                             partitioned_cookie_ptrs.end());
        }
      }
    }
    std::sort(cookie_ptrs.begin(), cookie_ptrs.end(), CookieSorter);

    included_cookies.reserve(cookie_ptrs.size());
    FilterCookiesWithOptions(url, options, &cookie_ptrs, &included_cookies,
                             &excluded_cookies);
  }

  MaybeRunCookieCallback(std::move(callback), included_cookies,
                         excluded_cookies);
}

void CookieMonster::DeleteAllCreatedInTimeRange(const TimeRange& creation_range,
                                                DeleteCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  uint32_t num_deleted = 0;
  for (auto it = cookies_.begin(); it != cookies_.end();) {
    auto curit = it;
    CanonicalCookie* cc = curit->second.get();
    ++it;

    if (creation_range.Contains(cc->CreationDate())) {
      InternalDeleteCookie(curit, true, /*sync_to_store*/
                           DELETE_COOKIE_EXPLICIT);
      ++num_deleted;
    }
  }

  for (PartitionedCookieMap::iterator partition_it =
           partitioned_cookies_.begin();
       partition_it != partitioned_cookies_.end();) {
    auto cur_partition_it = partition_it;
    CookieMap::iterator cookie_it = cur_partition_it->second->begin();
    CookieMap::iterator cookie_end = cur_partition_it->second->end();
    // InternalDeletePartitionedCookie may delete this cookie partition if it
    // only has one cookie, so we need to increment the iterator beforehand.
    ++partition_it;

    while (cookie_it != cookie_end) {
      auto cur_cookie_it = cookie_it;
      CanonicalCookie* cc = cur_cookie_it->second.get();
      ++cookie_it;

      if (creation_range.Contains(cc->CreationDate())) {
        InternalDeletePartitionedCookie(cur_partition_it, cur_cookie_it,
                                        true /*sync_to_store*/,
                                        DELETE_COOKIE_EXPLICIT);
        ++num_deleted;
      }
    }
  }

  FlushStore(
      base::BindOnce(&MaybeRunDeleteCallback, weak_ptr_factory_.GetWeakPtr(),
                     callback ? base::BindOnce(std::move(callback), num_deleted)
                              : base::OnceClosure()));
}

bool CookieMonster::MatchCookieDeletionInfo(
    const CookieDeletionInfo& delete_info,
    const net::CanonicalCookie& cookie) {
  bool delegate_treats_url_as_trustworthy = false;  // irrelevant if no URL.
  if (delete_info.url.has_value()) {
    delegate_treats_url_as_trustworthy =
        cookie_access_delegate() &&
        cookie_access_delegate()->ShouldTreatUrlAsTrustworthy(
            delete_info.url.value());
  }

  return delete_info.Matches(
      cookie, CookieAccessParams{GetAccessSemanticsForCookie(cookie),
        
"""


```