Response:
The user wants a summary of the functionality of the `canonical_cookie.cc` file in the Chromium network stack. I need to extract the key responsibilities and capabilities of this file, considering the provided code snippet. I also need to identify any connections to JavaScript, logical inferences with examples, common usage errors, and debugging clues.

Here's a breakdown of the analysis:

1. **Core Functionality:** Based on the code, the primary function appears to be creating and managing `CanonicalCookie` objects. This involves parsing cookie strings, validating cookie attributes, setting default values, and ensuring compliance with cookie specifications.

2. **JavaScript Interaction:**  Cookies are directly accessible and manipulated by JavaScript through the `document.cookie` API. The `canonical_cookie.cc` file is responsible for handling the backend representation of these cookies, so any cookie set or accessed via JavaScript will eventually interact with the logic in this file.

3. **Logical Inferences:** The code contains logic for handling cookie attributes like `Max-Age` and `Expires`, domain and path matching, and secure/HTTP-only flags. I can infer the input (cookie string, URL, etc.) and the expected output (a `CanonicalCookie` object or an error).

4. **User/Programming Errors:**  The code includes checks for invalid cookie formats, domain mismatches, and other potential issues. These can stem from incorrect cookie settings in server responses or JavaScript code.

5. **Debugging Clues:** The file includes logging statements (`DVLOG`) and usage of histograms (`UMA_HISTOGRAM_*`). These are valuable for debugging and monitoring cookie behavior. Understanding how user actions lead to the execution of the code in this file is essential for tracing cookie-related issues.
This代码文件 `net/cookies/canonical_cookie.cc` 是 Chromium 网络栈的一部分，它主要负责表示和管理 **规范化的 Cookie (CanonicalCookie)** 对象。以下是它的主要功能归纳：

**核心功能:**

1. **Cookie 的创建和解析:**
   - 接收一个 URL 和一个 Cookie 字符串 (例如，来自 HTTP `Set-Cookie` 响应头)，以及其他相关信息（创建时间，服务器时间等）。
   - 使用 `ParsedCookie` 类来解析 Cookie 字符串，提取出 Cookie 的名称、值、域、路径、过期时间、安全标志、HttpOnly 标志、SameSite 属性等。
   - 基于解析后的信息，创建一个 `CanonicalCookie` 对象。

2. **Cookie 属性的验证和标准化:**
   - 验证 Cookie 的各种属性是否符合规范（例如，域名是否有效，路径是否正确）。
   - 对 Cookie 的某些属性进行标准化，例如将相对路径转换为绝对路径。
   - 处理 `Max-Age` 和 `Expires` 属性来确定 Cookie 的确切过期时间，并考虑服务器和客户端的时间差。

3. **Cookie 的存储和检索的中间表示:**
   - `CanonicalCookie` 对象是 Chromium 内部表示 Cookie 的标准方式。
   - 它包含了 Cookie 的所有关键信息，方便在网络栈的不同组件之间传递和处理。

4. **支持 Cookie 的各种特性:**
   - 处理 `Secure` 和 `HttpOnly` 标志，限制 Cookie 的访问范围。
   - 处理 `SameSite` 属性，控制 Cookie 在跨站请求中的行为。
   - 支持 Cookie 前缀 (`__Secure-`, `__Host-`)，强制执行额外的安全约束。
   - 支持 `Partitioned` 属性，允许在不同的顶级站点上下文中隔离 Cookie。

5. **提供 Cookie 比较和匹配的功能:**
   - 提供了 `PartialCookieOrdering` 函数用于比较 Cookie，以确定它们是否“等价”（具有相同的名称、域和路径）。
   - 提供了 `IsEquivalentForSecureCookieMatching` 函数用于更宽松的比较，用于匹配安全 Cookie。
   - 提供了 `HasEquivalentDataMembers` 函数用于比较两个 Cookie 是否具有完全相同的数据成员。

6. **记录 Cookie 相关的指标:**
   - 使用 `UMA_HISTOGRAM_*` 宏记录各种 Cookie 相关的统计信息，例如 Cookie 名称或值中是否包含 HTAB 字符，Domain 属性是否包含非 ASCII 字符，是否使用了双下划线前缀的名称等，用于分析 Cookie 的使用情况和潜在问题。

**与 Javascript 的关系及举例说明:**

`CanonicalCookie` 的功能与 JavaScript 的 `document.cookie` API 密切相关。当 JavaScript 代码使用 `document.cookie` 设置一个新的 Cookie 时，浏览器会将 Cookie 字符串传递给底层的网络栈进行处理，最终会调用 `CanonicalCookie::Create` 或 `CanonicalCookie::CreateSanitizedCookie` 来创建 `CanonicalCookie` 对象。

**举例:**

假设网页的 JavaScript 代码执行了以下操作：

```javascript
document.cookie = "myCookie=myValue; domain=example.com; path=/; secure";
```

1. 浏览器会解析这个 Cookie 字符串。
2. 网络栈会调用 `CanonicalCookie::Create` 函数，传入当前页面的 URL，Cookie 字符串 `"myCookie=myValue; domain=example.com; path=/; secure"` 和当前时间等参数。
3. `CanonicalCookie::Create` 会使用 `ParsedCookie` 解析 Cookie 字符串，提取出名称 `myCookie`，值 `myValue`，域 `example.com`，路径 `/`，以及 `secure` 标志。
4. 函数会验证这些属性，例如检查 `example.com` 是否是当前页面的有效域。
5. 如果验证通过，将创建一个 `CanonicalCookie` 对象，其中存储了这些解析后的信息。

**假设输入与输出 (逻辑推理):**

**假设输入 1:**

- `url`: `https://www.example.com/page.html`
- `cookie_line`: `"test_cookie=123"`
- `creation_time`: `[当前时间]`
- 其他参数使用默认值。

**输出 1:**

- 创建一个 `CanonicalCookie` 对象，其属性可能如下：
  - `name`: `"test_cookie"`
  - `value`: `"123"`
  - `domain`: `"www.example.com"` (根据当前 URL 推断)
  - `path`: `"/page.html"` (根据当前 URL 推断)
  - `expiry_date`: `[会话 Cookie，即过期时间为空]`
  - `secure`: `false`
  - `httponly`: `false`
  - `samesite`: `kNone` (默认值)
  - ...

**假设输入 2:**

- `url`: `http://sub.test.com/`
- `cookie_line`: `"other_cookie=abc; domain=.test.com; Max-Age=3600"`
- `creation_time`: `[当前时间]`
- `server_time`: `[与 creation_time 相差 -10 秒]` (模拟服务器时间比客户端慢)

**输出 2:**

- 创建一个 `CanonicalCookie` 对象，其属性可能如下：
  - `name`: `"other_cookie"`
  - `value`: `"abc"`
  - `domain`: `".test.com"`
  - `path`: `"/"`
  - `expiry_date`: `[当前时间 + 3600 秒 - 10 秒]` (考虑了服务器时间差)
  - `secure`: `false`
  - `httponly`: `false`
  - `samesite`: `kNone`
  - ...

**用户或编程常见的使用错误及举例说明:**

1. **设置无效的 Cookie 域名:**
   - **错误:** JavaScript 代码尝试设置一个不属于当前页面或其父域的 Cookie 域名。
   - **例子:** 在 `www.example.com` 页面上执行 `document.cookie = "mycookie=value; domain=not-my-domain.com";`
   - **结果:** `CanonicalCookie::Create` 中的 `GetCookieDomain` 会返回失败，导致 Cookie 无法存储，并设置相应的 `CookieInclusionStatus`。

2. **设置带有非法字符的 Cookie 名称或值:**
   - **错误:**  Cookie 的名称或值包含不允许的字符（例如，控制字符）。
   - **例子:**  `document.cookie = "my-cookie;name=value";` (名称中包含分号)
   - **结果:** `ParsedCookie` 的解析会失败，或者 `CanonicalCookie::CreateSanitizedCookie` 中的验证会发现非法字符，导致 Cookie 无法存储。

3. **设置超出大小限制的 Cookie:**
   - **错误:** Cookie 的名称、值或整个 Cookie 字符串超过了浏览器允许的最大大小。
   - **例子:** 设置一个非常长的 Cookie 值。
   - **结果:** 在 `ParsedCookie` 或 `CanonicalCookie::CreateSanitizedCookie` 中会进行大小检查，超出限制的 Cookie 将无法存储。

4. **在不安全的页面上设置带有 `secure` 标志的 Cookie:**
   - **错误:** 在 `http://` 页面上尝试设置带有 `secure` 标志的 Cookie。
   - **例子:** `document.cookie = "secure_cookie=test; secure";` 在 `http://example.com` 上执行。
   - **结果:**  虽然 `CanonicalCookie` 对象可能被创建，但在后续的存储过程中，浏览器可能会阻止这种 Cookie 的设置，因为 `secure` 标志意味着该 Cookie 只能通过 HTTPS 连接发送。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中访问一个网页 (例如，通过输入 URL 或点击链接)。**
2. **服务器响应用户的请求，并在 HTTP 响应头中包含 `Set-Cookie` 指令。**
3. **浏览器接收到响应后，网络栈会解析 `Set-Cookie` 头。**
4. **网络栈调用 `CanonicalCookie::Create` 函数，将 URL、Cookie 字符串和当前时间等信息传递给它。**
5. **`CanonicalCookie::Create` 函数内部会进行 Cookie 的解析、验证和标准化。**
6. **如果 Cookie 是有效的，则创建一个 `CanonicalCookie` 对象，并将其存储在浏览器的 Cookie 存储中。**

**或者，**

1. **网页上的 JavaScript 代码使用 `document.cookie` API 来设置新的 Cookie。**
2. **浏览器接收到 JavaScript 的 `document.cookie` 设置请求。**
3. **浏览器会将 Cookie 字符串传递给底层的网络栈进行处理，最终调用 `CanonicalCookie::Create` 或 `CanonicalCookie::CreateSanitizedCookie`。**

**调试线索:**

- 如果用户报告 Cookie 没有生效，或者行为异常，可以检查浏览器的开发者工具中的 "Application" (或 "Storage") -> "Cookies" 部分，查看实际存储的 Cookie 值和属性，与预期进行比较。
- 使用网络抓包工具（如 Wireshark）或浏览器开发者工具的网络面板，检查 HTTP 响应头中的 `Set-Cookie` 内容，确认服务器发送的 Cookie 是否正确。
- 在 Chromium 的源代码中，可以使用断点调试 `CanonicalCookie::Create` 和 `CanonicalCookie::CreateSanitizedCookie` 函数，查看 Cookie 的解析和验证过程。
- 查看相关的 UMA 指标，了解 Cookie 设置过程中的一些统计信息和潜在问题。
- 检查 `CookieInclusionStatus` 中记录的排除原因，了解 Cookie 被拒绝的具体原因。

**功能归纳 (第 1 部分):**

`net/cookies/canonical_cookie.cc` 文件的主要功能是定义和实现 `CanonicalCookie` 类，该类是 Chromium 网络栈中 Cookie 的标准表示形式。它负责从原始的 Cookie 字符串创建和解析 `CanonicalCookie` 对象，验证和标准化 Cookie 的各种属性，并提供 Cookie 的比较和匹配功能。这个文件是浏览器处理和管理 Cookie 的核心组件，直接参与了浏览器接收、存储和发送 Cookie 的全过程。

### 提示词
```
这是目录为net/cookies/canonical_cookie.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
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

#include "net/cookies/canonical_cookie.h"

#include <limits>
#include <optional>
#include <string_view>
#include <tuple>
#include <utility>

#include "base/containers/contains.h"
#include "base/feature_list.h"
#include "base/format_macros.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "net/base/features.h"
#include "net/base/url_util.h"
#include "net/cookies/cookie_constants.h"
#include "net/cookies/cookie_inclusion_status.h"
#include "net/cookies/cookie_options.h"
#include "net/cookies/cookie_util.h"
#include "net/cookies/parsed_cookie.h"
#include "net/http/http_util.h"
#include "url/gurl.h"
#include "url/url_canon.h"
#include "url/url_util.h"

using base::Time;

namespace net {

namespace {

static constexpr int kMinutesInTwelveHours = 12 * 60;
static constexpr int kMinutesInTwentyFourHours = 24 * 60;

// Determine the cookie domain to use for setting the specified cookie.
bool GetCookieDomain(const GURL& url,
                     const ParsedCookie& pc,
                     CookieInclusionStatus& status,
                     std::string* result) {
  std::string domain_string;
  if (pc.HasDomain())
    domain_string = pc.Domain();
  return cookie_util::GetCookieDomainWithString(url, domain_string, status,
                                                result);
}

// Compares cookies using name, domain and path, so that "equivalent" cookies
// (per RFC 2965) are equal to each other.
int PartialCookieOrdering(const CanonicalCookie& a, const CanonicalCookie& b) {
  int diff = a.Name().compare(b.Name());
  if (diff != 0)
    return diff;

  diff = a.Domain().compare(b.Domain());
  if (diff != 0)
    return diff;

  return a.Path().compare(b.Path());
}

void AppendCookieLineEntry(const CanonicalCookie& cookie,
                           std::string* cookie_line) {
  if (!cookie_line->empty())
    *cookie_line += "; ";
  // In Mozilla, if you set a cookie like "AAA", it will have an empty token
  // and a value of "AAA". When it sends the cookie back, it will send "AAA",
  // so we need to avoid sending "=AAA" for a blank token value.
  if (!cookie.Name().empty())
    *cookie_line += cookie.Name() + "=";
  *cookie_line += cookie.Value();
}

// Converts CookieSameSite to CookieSameSiteForMetrics by adding 1 to it.
CookieSameSiteForMetrics CookieSameSiteToCookieSameSiteForMetrics(
    CookieSameSite enum_in) {
  return static_cast<CookieSameSiteForMetrics>((static_cast<int>(enum_in) + 1));
}

auto GetAllDataMembersAsTuple(const CanonicalCookie& c) {
  return std::make_tuple(c.CreationDate(), c.LastAccessDate(), c.ExpiryDate(),
                         c.SecureAttribute(), c.IsHttpOnly(), c.SameSite(),
                         c.Priority(), c.PartitionKey(), c.Name(), c.Value(),
                         c.Domain(), c.Path(), c.LastUpdateDate(),
                         c.SourceScheme(), c.SourcePort(), c.SourceType());
}

}  // namespace

CookieAccessParams::CookieAccessParams(CookieAccessSemantics access_semantics,
                                       bool delegate_treats_url_as_trustworthy)
    : access_semantics(access_semantics),
      delegate_treats_url_as_trustworthy(delegate_treats_url_as_trustworthy) {}

CanonicalCookie::CanonicalCookie() = default;

CanonicalCookie::CanonicalCookie(const CanonicalCookie& other) = default;

CanonicalCookie::CanonicalCookie(CanonicalCookie&& other) = default;

CanonicalCookie& CanonicalCookie::operator=(const CanonicalCookie& other) =
    default;

CanonicalCookie& CanonicalCookie::operator=(CanonicalCookie&& other) = default;

CanonicalCookie::CanonicalCookie(
    base::PassKey<CanonicalCookie> pass_key,
    std::string name,
    std::string value,
    std::string domain,
    std::string path,
    base::Time creation,
    base::Time expiration,
    base::Time last_access,
    base::Time last_update,
    bool secure,
    bool httponly,
    CookieSameSite same_site,
    CookiePriority priority,
    std::optional<CookiePartitionKey> partition_key,
    CookieSourceScheme source_scheme,
    int source_port,
    CookieSourceType source_type)
    : CookieBase(std::move(name),
                 std::move(domain),
                 std::move(path),
                 creation,
                 secure,
                 httponly,
                 same_site,
                 std::move(partition_key),
                 source_scheme,
                 source_port),
      value_(std::move(value)),
      expiry_date_(expiration),
      last_access_date_(last_access),
      last_update_date_(last_update),
      priority_(priority),
      source_type_(source_type) {}

CanonicalCookie::~CanonicalCookie() = default;

// static
Time CanonicalCookie::ParseExpiration(const ParsedCookie& pc,
                                      const Time& current,
                                      const Time& server_time) {
  // First, try the Max-Age attribute.
  if (pc.HasMaxAge()) {
    int64_t max_age = 0;
    // Use the output if StringToInt64 returns true ("perfect" conversion). This
    // case excludes overflow/underflow, leading/trailing whitespace, non-number
    // strings, and empty string. (ParsedCookie trims whitespace.)
    if (base::StringToInt64(pc.MaxAge(), &max_age)) {
      // RFC 6265bis algorithm for parsing Max-Age:
      // "If delta-seconds is less than or equal to zero (0), let expiry-
      // time be the earliest representable date and time. ... "
      if (max_age <= 0)
        return Time::Min();
      // "... Otherwise, let the expiry-time be the current date and time plus
      // delta-seconds seconds."
      return current + base::Seconds(max_age);
    } else {
      // If the conversion wasn't perfect, but the best-effort conversion
      // resulted in an overflow/underflow, use the min/max representable time.
      // (This is alluded to in the spec, which says the user agent MAY clip an
      // Expires attribute to a saturated time. We'll do the same for Max-Age.)
      if (max_age == std::numeric_limits<int64_t>::min())
        return Time::Min();
      if (max_age == std::numeric_limits<int64_t>::max())
        return Time::Max();
    }
  }

  // Try the Expires attribute.
  if (pc.HasExpires() && !pc.Expires().empty()) {
    // Adjust for clock skew between server and host.
    Time parsed_expiry = cookie_util::ParseCookieExpirationTime(pc.Expires());
    if (!parsed_expiry.is_null()) {
      // Record metrics related to prevalence of clock skew.
      base::TimeDelta clock_skew = (current - server_time);
      // Record the magnitude (absolute value) of the skew in minutes.
      int clock_skew_magnitude = clock_skew.magnitude().InMinutes();
      // Determine the new expiry with clock skew factored in.
      Time adjusted_expiry = parsed_expiry + (current - server_time);
      if (clock_skew.is_positive() || clock_skew.is_zero()) {
        UMA_HISTOGRAM_CUSTOM_COUNTS("Cookie.ClockSkew.AddMinutes",
                                    clock_skew_magnitude, 1,
                                    kMinutesInTwelveHours, 100);
        UMA_HISTOGRAM_CUSTOM_COUNTS("Cookie.ClockSkew.AddMinutes12To24Hours",
                                    clock_skew_magnitude, kMinutesInTwelveHours,
                                    kMinutesInTwentyFourHours, 100);
        // Also record the range of minutes added that allowed the cookie to
        // avoid expiring immediately.
        if (parsed_expiry <= Time::Now() && adjusted_expiry > Time::Now()) {
          UMA_HISTOGRAM_CUSTOM_COUNTS(
              "Cookie.ClockSkew.WithoutAddMinutesExpires", clock_skew_magnitude,
              1, kMinutesInTwentyFourHours, 100);
        }
      } else if (clock_skew.is_negative()) {
        // These histograms only support positive numbers, so negative skews
        // will be converted to positive (via magnitude) before recording.
        UMA_HISTOGRAM_CUSTOM_COUNTS("Cookie.ClockSkew.SubtractMinutes",
                                    clock_skew_magnitude, 1,
                                    kMinutesInTwelveHours, 100);
        UMA_HISTOGRAM_CUSTOM_COUNTS(
            "Cookie.ClockSkew.SubtractMinutes12To24Hours", clock_skew_magnitude,
            kMinutesInTwelveHours, kMinutesInTwentyFourHours, 100);
      }
      // Record if we were going to expire the cookie before we added the clock
      // skew.
      UMA_HISTOGRAM_BOOLEAN(
          "Cookie.ClockSkew.ExpiredWithoutSkew",
          parsed_expiry <= Time::Now() && adjusted_expiry > Time::Now());
      return adjusted_expiry;
    }
  }

  // Invalid or no expiration, session cookie.
  return Time();
}

// static
base::Time CanonicalCookie::ValidateAndAdjustExpiryDate(
    const base::Time& expiry_date,
    const base::Time& creation_date,
    net::CookieSourceScheme scheme) {
  if (expiry_date.is_null())
    return expiry_date;
  base::Time fixed_creation_date = creation_date;
  if (fixed_creation_date.is_null()) {
    // TODO(crbug.com/40800807): Push this logic into
    // CanonicalCookie::CreateSanitizedCookie. The four sites that call it
    // with a null `creation_date` (CanonicalCookie::Create cannot be called
    // this way) are:
    // * GaiaCookieManagerService::ForceOnCookieChangeProcessing
    // * CookiesSetFunction::Run
    // * cookie_store.cc::ToCanonicalCookie
    // * network_handler.cc::MakeCookieFromProtocolValues
    fixed_creation_date = base::Time::Now();
  }
  base::Time maximum_expiry_date;
  if (!cookie_util::IsTimeLimitedInsecureCookiesEnabled() ||
      scheme == net::CookieSourceScheme::kSecure) {
    maximum_expiry_date = fixed_creation_date + base::Days(400);
  } else {
    maximum_expiry_date = fixed_creation_date + base::Hours(3);
  }
  if (expiry_date > maximum_expiry_date) {
    return maximum_expiry_date;
  }
  return expiry_date;
}

// static
std::unique_ptr<CanonicalCookie> CanonicalCookie::Create(
    const GURL& url,
    std::string_view cookie_line,
    const base::Time& creation_time,
    std::optional<base::Time> server_time,
    std::optional<CookiePartitionKey> cookie_partition_key,
    CookieSourceType source_type,
    CookieInclusionStatus* status) {
  // Put a pointer on the stack so the rest of the function can assign to it if
  // the default nullptr is passed in.
  CookieInclusionStatus blank_status;
  if (status == nullptr) {
    status = &blank_status;
  }
  *status = CookieInclusionStatus();

  // Check the URL; it may be nonsense since some platform APIs may permit
  // it to be specified directly.
  if (!url.is_valid()) {
    status->AddExclusionReason(CookieInclusionStatus::EXCLUDE_FAILURE_TO_STORE);
    return nullptr;
  }

  ParsedCookie parsed_cookie(cookie_line, status);

  // We record this metric before checking validity because the presence of an
  // HTAB will invalidate the ParsedCookie.
  UMA_HISTOGRAM_BOOLEAN("Cookie.NameOrValueHtab",
                        parsed_cookie.HasInternalHtab());

  if (!parsed_cookie.IsValid()) {
    DVLOG(net::cookie_util::kVlogSetCookies)
        << "WARNING: Couldn't parse cookie";
    DCHECK(!status->IsInclude());
    // Don't continue, because an invalid ParsedCookie doesn't have any
    // attributes.
    // TODO(chlily): Log metrics.
    return nullptr;
  }

  // Record warning for non-ASCII octecs in the Domain attribute.
  // This should lead to rejection of the cookie in the future.
  UMA_HISTOGRAM_BOOLEAN("Cookie.DomainHasNonASCII",
                        parsed_cookie.HasDomain() &&
                            !base::IsStringASCII(parsed_cookie.Domain()));

  std::string cookie_domain;
  if (!GetCookieDomain(url, parsed_cookie, *status, &cookie_domain)) {
    DVLOG(net::cookie_util::kVlogSetCookies)
        << "Create() failed to get a valid cookie domain";
    status->AddExclusionReason(CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN);
  }

  std::string cookie_path = cookie_util::CanonPathWithString(
      url, parsed_cookie.HasPath() ? parsed_cookie.Path() : std::string());

  Time cookie_server_time(creation_time);
  if (server_time.has_value() && !server_time->is_null())
    cookie_server_time = server_time.value();

  DCHECK(!creation_time.is_null());

  CookiePrefix prefix = cookie_util::GetCookiePrefix(parsed_cookie.Name());

  bool is_cookie_prefix_valid =
      cookie_util::IsCookiePrefixValid(prefix, url, parsed_cookie);

  RecordCookiePrefixMetrics(prefix);

  if (parsed_cookie.Name() == "") {
    is_cookie_prefix_valid = !HasHiddenPrefixName(parsed_cookie.Value());
  }

  if (!is_cookie_prefix_valid) {
    DVLOG(net::cookie_util::kVlogSetCookies)
        << "Create() failed because the cookie violated prefix rules.";
    status->AddExclusionReason(CookieInclusionStatus::EXCLUDE_INVALID_PREFIX);
  }

  bool partition_has_nonce = CookiePartitionKey::HasNonce(cookie_partition_key);
  bool is_partitioned_valid = cookie_util::IsCookiePartitionedValid(
      url, parsed_cookie, partition_has_nonce);
  if (!is_partitioned_valid) {
    status->AddExclusionReason(
        CookieInclusionStatus::EXCLUDE_INVALID_PARTITIONED);
  }

  // Collect metrics on whether usage of the Partitioned attribute is correct.
  // Do not include implicit nonce-based partitioned cookies in these metrics.
  if (parsed_cookie.IsPartitioned()) {
    if (!partition_has_nonce)
      UMA_HISTOGRAM_BOOLEAN("Cookie.IsPartitionedValid", is_partitioned_valid);
  } else if (!partition_has_nonce) {
    cookie_partition_key = std::nullopt;
  }

  if (!status->IsInclude())
    return nullptr;

  CookieSameSiteString samesite_string = CookieSameSiteString::kUnspecified;
  CookieSameSite samesite = parsed_cookie.SameSite(&samesite_string);

  // The next two sections set the source_scheme_ and source_port_. Normally
  // these are taken directly from the url's scheme and port but if the url
  // setting this cookie is considered a trustworthy origin then we may make
  // some modifications. Note that here we assume that a trustworthy url must
  // have a non-secure scheme (http). Since we can't know at this point if a url
  // is trustworthy or not, we'll assume it is if the cookie is set with the
  // `Secure` attribute.
  //
  // For both convenience and to try to match expectations, cookies that have
  // the `Secure` attribute are modified to look like they were created by a
  // secure url. This is helpful because this cookie can be treated like any
  // other secure cookie when we're retrieving them and helps to prevent the
  // cookie from getting "trapped" if the url loses trustworthiness.

  CookieSourceScheme source_scheme;
  if (parsed_cookie.IsSecure() || url.SchemeIsCryptographic()) {
    // It's possible that a trustworthy origin is setting this cookie with the
    // `Secure` attribute even if the url's scheme isn't secure. In that case
    // we'll act like it was a secure scheme. This cookie will be rejected later
    // if the url isn't allowed to access secure cookies so this isn't a
    // problem.
    source_scheme = CookieSourceScheme::kSecure;

    if (!url.SchemeIsCryptographic()) {
      status->AddWarningReason(
          CookieInclusionStatus::
              WARN_TENTATIVELY_ALLOWING_SECURE_SOURCE_SCHEME);
    }
  } else {
    source_scheme = CookieSourceScheme::kNonSecure;
  }

  // Get the port, this will get a default value if a port isn't explicitly
  // provided. Similar to the source scheme, it's possible that a trustworthy
  // origin is setting this cookie with the `Secure` attribute even if the url's
  // scheme isn't secure. This function will return 443 to pretend like this
  // cookie was set by a secure scheme.
  int source_port = CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(
      url, parsed_cookie.IsSecure());

  Time cookie_expires = CanonicalCookie::ParseExpiration(
      parsed_cookie, creation_time, cookie_server_time);
  cookie_expires =
      ValidateAndAdjustExpiryDate(cookie_expires, creation_time, source_scheme);

  auto cc = std::make_unique<CanonicalCookie>(
      base::PassKey<CanonicalCookie>(), parsed_cookie.Name(),
      parsed_cookie.Value(), std::move(cookie_domain), std::move(cookie_path),
      creation_time, cookie_expires, creation_time,
      /*last_update=*/base::Time::Now(), parsed_cookie.IsSecure(),
      parsed_cookie.IsHttpOnly(), samesite, parsed_cookie.Priority(),
      cookie_partition_key, source_scheme, source_port, source_type);

  // TODO(chlily): Log metrics.
  if (!cc->IsCanonical()) {
    status->AddExclusionReason(
        net::CookieInclusionStatus::EXCLUDE_FAILURE_TO_STORE);
    return nullptr;
  }

  RecordCookieSameSiteAttributeValueHistogram(samesite_string);

  // These metrics capture whether or not a cookie has a Non-ASCII character in
  // it.
  UMA_HISTOGRAM_BOOLEAN("Cookie.HasNonASCII.Name",
                        !base::IsStringASCII(cc->Name()));
  UMA_HISTOGRAM_BOOLEAN("Cookie.HasNonASCII.Value",
                        !base::IsStringASCII(cc->Value()));

  // Check for "__" prefixed names, excluding the cookie prefixes.
  bool name_prefixed_with_underscores =
      (prefix == COOKIE_PREFIX_NONE) && parsed_cookie.Name().starts_with("__");

  UMA_HISTOGRAM_BOOLEAN("Cookie.DoubleUnderscorePrefixedName",
                        name_prefixed_with_underscores);

  return cc;
}

// static
std::unique_ptr<CanonicalCookie> CanonicalCookie::CreateSanitizedCookie(
    const GURL& url,
    const std::string& name,
    const std::string& value,
    const std::string& domain,
    const std::string& path,
    base::Time creation_time,
    base::Time expiration_time,
    base::Time last_access_time,
    bool secure,
    bool http_only,
    CookieSameSite same_site,
    CookiePriority priority,
    std::optional<CookiePartitionKey> partition_key,
    CookieInclusionStatus* status) {
  // Put a pointer on the stack so the rest of the function can assign to it if
  // the default nullptr is passed in.
  CookieInclusionStatus blank_status;
  if (status == nullptr) {
    status = &blank_status;
  }
  *status = CookieInclusionStatus();

  // Validate consistency of passed arguments.
  if (ParsedCookie::ParseTokenString(name) != name) {
    status->AddExclusionReason(
        net::CookieInclusionStatus::EXCLUDE_DISALLOWED_CHARACTER);
  } else if (ParsedCookie::ParseValueString(value) != value) {
    status->AddExclusionReason(
        net::CookieInclusionStatus::EXCLUDE_DISALLOWED_CHARACTER);
  } else if (ParsedCookie::ParseValueString(path) != path) {
    // NOTE: If `path` contains  "terminating characters" ('\r', '\n', and
    // '\0'), ';', or leading / trailing whitespace, path will be rejected,
    // but any other control characters will just get URL-encoded below.
    status->AddExclusionReason(
        net::CookieInclusionStatus::EXCLUDE_DISALLOWED_CHARACTER);
  }

  // Validate name and value against character set and size limit constraints.
  // If IsValidCookieNameValuePair identifies that `name` and/or `value` are
  // invalid, it will add an ExclusionReason to `status`.
  ParsedCookie::IsValidCookieNameValuePair(name, value, status);

  // Validate domain against character set and size limit constraints.
  bool domain_is_valid = true;

  if ((ParsedCookie::ParseValueString(domain) != domain)) {
    status->AddExclusionReason(
        net::CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN);
    domain_is_valid = false;
  }

  if (!ParsedCookie::CookieAttributeValueHasValidCharSet(domain)) {
    status->AddExclusionReason(
        net::CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN);
    domain_is_valid = false;
  }
  if (!ParsedCookie::CookieAttributeValueHasValidSize(domain)) {
    status->AddExclusionReason(
        net::CookieInclusionStatus::EXCLUDE_ATTRIBUTE_VALUE_EXCEEDS_MAX_SIZE);
    domain_is_valid = false;
  }
  const std::string& domain_attribute =
      domain_is_valid ? domain : std::string();

  std::string cookie_domain;
  // This validation step must happen before GetCookieDomainWithString, so it
  // doesn't fail DCHECKs.
  if (!cookie_util::DomainIsHostOnly(url.host())) {
    status->AddExclusionReason(
        net::CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN);
  } else if (!cookie_util::GetCookieDomainWithString(url, domain_attribute,
                                                     *status, &cookie_domain)) {
    status->AddExclusionReason(
        net::CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN);
  }

  // The next two sections set the source_scheme_ and source_port_. Normally
  // these are taken directly from the url's scheme and port but if the url
  // setting this cookie is considered a trustworthy origin then we may make
  // some modifications. Note that here we assume that a trustworthy url must
  // have a non-secure scheme (http). Since we can't know at this point if a url
  // is trustworthy or not, we'll assume it is if the cookie is set with the
  // `Secure` attribute.
  //
  // For both convenience and to try to match expectations, cookies that have
  // the `Secure` attribute are modified to look like they were created by a
  // secure url. This is helpful because this cookie can be treated like any
  // other secure cookie when we're retrieving them and helps to prevent the
  // cookie from getting "trapped" if the url loses trustworthiness.

  CookieSourceScheme source_scheme = CookieSourceScheme::kNonSecure;
  // This validation step must happen before SchemeIsCryptographic, so it
  // doesn't fail DCHECKs.
  if (!url.is_valid()) {
    status->AddExclusionReason(
        net::CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN);
  } else {
    // It's possible that a trustworthy origin is setting this cookie with the
    // `Secure` attribute even if the url's scheme isn't secure. In that case
    // we'll act like it was a secure scheme. This cookie will be rejected later
    // if the url isn't allowed to access secure cookies so this isn't a
    // problem.
    source_scheme = (secure || url.SchemeIsCryptographic())
                        ? CookieSourceScheme::kSecure
                        : CookieSourceScheme::kNonSecure;

    if (source_scheme == CookieSourceScheme::kSecure &&
        !url.SchemeIsCryptographic()) {
      status->AddWarningReason(
          CookieInclusionStatus::
              WARN_TENTATIVELY_ALLOWING_SECURE_SOURCE_SCHEME);
    }
  }

  // Get the port, this will get a default value if a port isn't explicitly
  // provided. Similar to the source scheme, it's possible that a trustworthy
  // origin is setting this cookie with the `Secure` attribute even if the url's
  // scheme isn't secure. This function will return 443 to pretend like this
  // cookie was set by a secure scheme.
  int source_port =
      CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(url, secure);

  std::string cookie_path = cookie_util::CanonPathWithString(url, path);
  // Canonicalize path again to make sure it escapes characters as needed.
  url::Component path_component(0, cookie_path.length());
  url::RawCanonOutputT<char> canon_path;
  url::Component canon_path_component;
  url::CanonicalizePath(cookie_path.data(), path_component, &canon_path,
                        &canon_path_component);
  std::string encoded_cookie_path = std::string(
      canon_path.data() + canon_path_component.begin, canon_path_component.len);

  if (!path.empty()) {
    if (cookie_path != path) {
      // The path attribute was specified and found to be invalid, so record an
      // error.
      status->AddExclusionReason(
          net::CookieInclusionStatus::EXCLUDE_FAILURE_TO_STORE);
    } else if (!ParsedCookie::CookieAttributeValueHasValidSize(
                   encoded_cookie_path)) {
      // The path attribute was specified and encodes into a value that's longer
      // than the length limit, so record an error.
      status->AddExclusionReason(
          net::CookieInclusionStatus::EXCLUDE_ATTRIBUTE_VALUE_EXCEEDS_MAX_SIZE);
    }
  }

  CookiePrefix prefix = cookie_util::GetCookiePrefix(name);
  if (!cookie_util::IsCookiePrefixValid(prefix, url, secure, domain_attribute,
                                        cookie_path)) {
    status->AddExclusionReason(
        net::CookieInclusionStatus::EXCLUDE_INVALID_PREFIX);
  }

  if (name == "" && HasHiddenPrefixName(value)) {
    status->AddExclusionReason(
        net::CookieInclusionStatus::EXCLUDE_INVALID_PREFIX);
  }

  if (!cookie_util::IsCookiePartitionedValid(
          url, secure,
          /*is_partitioned=*/partition_key.has_value(),
          /*partition_has_nonce=*/
          CookiePartitionKey::HasNonce(partition_key))) {
    status->AddExclusionReason(
        net::CookieInclusionStatus::EXCLUDE_INVALID_PARTITIONED);
  }

  if (!last_access_time.is_null() && creation_time.is_null()) {
    status->AddExclusionReason(
        net::CookieInclusionStatus::EXCLUDE_FAILURE_TO_STORE);
  }
  expiration_time = ValidateAndAdjustExpiryDate(expiration_time, creation_time,
                                                source_scheme);

  if (!status->IsInclude())
    return nullptr;

  auto cc = std::make_unique<CanonicalCookie>(
      base::PassKey<CanonicalCookie>(), name, value, std::move(cookie_domain),
      std::move(encoded_cookie_path), creation_time, expiration_time,
      last_access_time,
      /*last_update=*/base::Time::Now(), secure, http_only, same_site, priority,
      partition_key, source_scheme, source_port, CookieSourceType::kOther);
  DCHECK(cc->IsCanonical());

  return cc;
}

// static
std::unique_ptr<CanonicalCookie> CanonicalCookie::FromStorage(
    std::string name,
    std::string value,
    std::string domain,
    std::string path,
    base::Time creation,
    base::Time expiration,
    base::Time last_access,
    base::Time last_update,
    bool secure,
    bool httponly,
    CookieSameSite same_site,
    CookiePriority priority,
    std::optional<CookiePartitionKey> partition_key,
    CookieSourceScheme source_scheme,
    int source_port,
    CookieSourceType source_type) {
  // We check source_port here because it could have concievably been
  // corrupted and changed to out of range. Eventually this would be caught by
  // IsCanonical*() but since the source_port is only used by metrics so far
  // nothing else checks it. So let's normalize it here and then update this
  // method when origin-bound cookies is implemented.
  // TODO(crbug.com/40165805)
  int validated_port = CookieBase::ValidateAndAdjustSourcePort(source_port);

  auto cc = std::make_unique<CanonicalCookie>(
      base::PassKey<CanonicalCookie>(), std::move(name), std::move(value),
      std::move(domain), std::move(path), creation, expiration, last_access,
      last_update, secure, httponly, same_site, priority, partition_key,
      source_scheme, validated_port, source_type);

  if (cc->IsCanonicalForFromStorage()) {
    // This will help capture the number of times a cookie is canonical but does
    // not have a valid name+value size length
    bool valid_cookie_name_value_pair =
        ParsedCookie::IsValidCookieNameValuePair(cc->Name(), cc->Value());
    UMA_HISTOGRAM_BOOLEAN("Cookie.FromStorageWithValidLength",
                          valid_cookie_name_value_pair);
  } else {
    return nullptr;
  }
  return cc;
}

// static
std::unique_ptr<CanonicalCookie> CanonicalCookie::CreateUnsafeCookieForTesting(
    const std::string& name,
    const std::string& value,
    const std::string& domain,
    const std::string& path,
    const base::Time& creation,
    const base::Time& expiration,
    const base::Time& last_access,
    const base::Time& last_update,
    bool secure,
    bool httponly,
    CookieSameSite same_site,
    CookiePriority priority,
    std::optional<CookiePartitionKey> partition_key,
    CookieSourceScheme source_scheme,
    int source_port,
    CookieSourceType source_type) {
  return std::make_unique<CanonicalCookie>(
      base::PassKey<CanonicalCookie>(), name, value, domain, path, creation,
      expiration, last_access, last_update, secure, httponly, same_site,
      priority, partition_key, source_scheme, source_port, source_type);
}

// static
std::unique_ptr<CanonicalCookie> CanonicalCookie::CreateForTesting(
    const GURL& url,
    const std::string& cookie_line,
    const base::Time& creation_time,
    std::optional<base::Time> server_time,
    std::optional<CookiePartitionKey> cookie_partition_key,
    CookieSourceType source_type,
    CookieInclusionStatus* status) {
  return CanonicalCookie::Create(url, cookie_line, creation_time, server_time,
                                 cookie_partition_key, source_type, status);
}

std::string CanonicalCookie::Value() const {
  if (!value_.has_value()) {
    return std::string();
  }
  return value_->value();
}

bool CanonicalCookie::IsEquivalentForSecureCookieMatching(
    const CanonicalCookie& secure_cookie) const {
  // Partition keys must both be equivalent.
  bool same_partition_key = PartitionKey() == secure_cookie.PartitionKey();

  // Names must be the same
  bool same_name = Name() == secure_cookie.Name();

  // They should domain-match in one direction or the other. (See RFC 6265bis
  // section 5.1.3.)
  // TODO(chlily): This does not check for the IP address case. This is bad due
  // to https://crbug.com/1069935.
  bool domain_match =
      IsSubdomainOf(DomainWithoutDot(), secure_cookie.DomainWithoutDot()) ||
      IsSubdomainOf(secure_cookie.DomainWithoutDot(), DomainWithoutDot());

  bool path_match = secure_cookie.IsOnPath(Path());

  bool equivalent_for_secure_cookie_matching =
      same_partition_key && same_name && domain_match && path_match;

  // IsEquivalent() is a stricter check than this.
  DCHECK(!IsEquivalent(secure_cookie) || equivalent_for_secure_cookie_matching);

  return equivalent_for_secure_cookie_matching;
}

bool CanonicalCookie::HasEquivalentDataMembers(
    const CanonicalCookie& other) const {
  return GetAllDataMembersAsTuple(*this) == GetAllDataMembersAsTuple(other);
}

void CanonicalCookie::PostIncludeForRequestURL(
    const CookieAccessResult& access_result,
    const CookieOptions& options_used,
    CookieOptions::SameSiteCookieContext::ContextType
        cookie_inclusion_context_used) const {
  UMA_HISTOGRAM_ENUMERATION(
      "Cookie.RequestSameSiteContext", cookie_inclusion_context_used,
      CookieOptions::SameSiteCookieContext::ContextType::COUNT);

  // For the metric, we only want to consider first party partitioned cookies.
  if (IsFirstPartyPartitioned()) {
    UMA_HISTOGRAM_BOOLEAN(
        "C
```