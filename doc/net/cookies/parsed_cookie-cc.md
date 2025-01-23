Response:
Let's break down the thought process for analyzing this `parsed_cookie.cc` file.

**1. Understanding the Core Purpose:**

The first step is to read the initial comments and the overall structure. The name "parsed_cookie" immediately suggests its function: to take a raw cookie string and break it down into its constituent parts. The copyright and license information are important for legal context but don't directly contribute to understanding the functionality. The inclusion of headers like `<string>`, `<vector>`, and Chromium-specific headers like `net/base/features.h` provides hints about the data structures and dependencies involved.

**2. Identifying Key Data Structures:**

The `ParsedCookie` class is central. The `pairs_` member (a vector of pairs) is crucial. This tells us that the cookie is represented as a collection of name-value pairs. The presence of `*_index_` members suggests a way to quickly access specific cookie attributes (path, domain, etc.) without iterating through the entire `pairs_` vector.

**3. Analyzing Key Methods:**

Next, we need to examine the core methods:

* **Constructor (`ParsedCookie`)**: This is where the main parsing logic resides. It takes the raw cookie string and populates the `pairs_` vector. The call to `ParseTokenValuePairs` is a key step, and examining that function will reveal the details of the parsing process. The `CookieInclusionStatus` parameter indicates the function also deals with validation and reporting errors.
* **`IsValid()`**:  A simple check to see if any pairs were successfully parsed.
* **Attribute Accessors (`SameSite`, `Priority`, etc.)**: These methods provide ways to retrieve specific cookie attributes. They often rely on the `*_index_` members.
* **Attribute Setters (`SetName`, `SetValue`, `SetPath`, etc.)**: These methods allow modification of the parsed cookie. It's important to note if they perform validation.
* **`ToCookieLine()`**:  The reverse of the constructor. It takes the parsed representation and reconstructs the raw cookie string.
* **Static Parsing Helper Functions (`FindFirstTerminator`, `ParseToken`, `ParseValue`, etc.)**:  These are low-level utilities used by the constructor and other methods to break down the cookie string. Understanding these is key to understanding the parsing logic.
* **Static Validation Functions (`IsValidCookieName`, `IsValidCookieValue`, `IsValidCookieNameValuePair`, etc.)**:  These functions enforce rules about the validity of cookie names, values, and attribute values.

**4. Tracing the Flow and Logic:**

By examining the interactions between these methods, we can trace the flow of data:

1. A raw cookie string comes in (likely from an HTTP response header).
2. The constructor uses the parsing helper functions to break it down into name-value pairs, storing them in `pairs_`.
3. `SetupAttributes` populates the `*_index_` members for efficient access.
4. The accessors provide ways to read the parsed information.
5. The setters allow modification, with validation to ensure consistency.
6. `ToCookieLine` can reconstruct the string representation.

**5. Identifying Connections to JavaScript:**

Cookies are fundamentally a mechanism for web servers to store information in the user's browser. JavaScript has direct access to cookies via the `document.cookie` property. This is a critical connection point. The example of `document.cookie = "my_cookie=my_value"` demonstrates how JavaScript interacts with cookies.

**6. Considering Error Scenarios and User Mistakes:**

Think about common ways cookies can be malformed or how users might misuse the API:

* Invalid characters in names or values.
* Exceeding size limits.
* Incorrect syntax in the `Set-Cookie` header or when setting cookies via JavaScript.

**7. Debugging Scenarios:**

Imagine a situation where a cookie isn't being set or isn't behaving as expected. Understanding the parsing logic in `parsed_cookie.cc` helps in debugging:

* **Where did the parsing fail?**  Did a specific character cause an error?
* **Is a specific attribute being parsed correctly?**
* **How did the user's action lead to this code being executed?** (e.g., a specific website setting a cookie).

**8. Logical Inference and Examples:**

Once the core functionality is understood, create examples to illustrate how the code behaves:

* **Input:** A specific cookie string.
* **Expected Output:** How the `pairs_` vector will be populated, how the indices will be set.

**9. Iterative Refinement:**

The process isn't always linear. You might need to go back and forth between different parts of the code to fully understand the interactions. Reading comments and looking for TODOs can provide further insights.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe the parsing is done using regular expressions.
* **Correction:**  Looking at the code, it uses manual iteration and character-by-character analysis with helper functions like `SeekTo` and `SeekPast`. This is more efficient for this specific task.
* **Initial thought:** The validation might be very strict based on the newest RFC.
* **Correction:** The comments indicate they allow a slightly wider range of characters than the strictest interpretation of some RFCs, balancing compatibility with the need for correctness. The comments also point to specific bug reports (crbug.com/...) which can give further context.

By following these steps, you can systematically analyze a complex piece of code like `parsed_cookie.cc` and understand its functionality, its interactions with other parts of the system (like JavaScript), and potential error scenarios.
好的，让我们来详细分析一下 `net/cookies/parsed_cookie.cc` 这个 Chromium 网络栈的源代码文件。

**文件功能概述**

`parsed_cookie.cc` 文件的核心功能是**解析 HTTP `Set-Cookie` 响应头字段的值，并将其分解成结构化的数据表示**。简单来说，它负责将一个包含 Cookie 信息的字符串，例如 `"name=value; Path=/; Domain=example.com"`, 转换为易于程序处理的内部格式。

具体来说，它执行以下操作：

1. **解析 Cookie 的名称和值 (Name-Value Pair):** 提取出 Cookie 的名称和与之关联的值。
2. **解析 Cookie 的属性 (Attributes):**  识别并解析各种 Cookie 属性，例如 `Path`, `Domain`, `Expires`, `Max-Age`, `Secure`, `HttpOnly`, `SameSite`, `Priority`, `Partitioned` 等。
3. **存储解析后的信息:**  将解析出的名称、值和属性存储在 `ParsedCookie` 类内部的数据结构中（主要是 `pairs_` 成员变量）。
4. **提供访问接口:**  提供方法来访问解析出的 Cookie 的各个部分，例如获取 `SameSite` 值，`Priority` 值，以及判断 `Secure` 或 `HttpOnly` 标记是否设置。
5. **提供修改接口:**  提供方法来修改已解析的 Cookie 的属性。
6. **提供重新生成 Cookie 字符串的功能:**  可以将解析后的 Cookie 对象重新转换为符合 HTTP 规范的 `Set-Cookie` 字符串。
7. **进行基本的 Cookie 语法校验:**  在解析过程中，会进行一些基本的语法检查，例如检查非法字符等。

**与 JavaScript 功能的关系及举例**

`parsed_cookie.cc` 的功能与 JavaScript 在客户端操作 Cookie 密切相关。当浏览器接收到来自服务器的 `Set-Cookie` 响应头时，网络栈会使用 `parsed_cookie.cc` 来解析这些 Cookie 信息。解析后的 Cookie 数据会被浏览器存储，并且可以通过 JavaScript 的 `document.cookie` 属性进行访问和操作。

**举例说明:**

1. **服务器设置 Cookie:**
   - 假设服务器发送了以下 `Set-Cookie` 响应头：
     ```
     Set-Cookie: my_cookie=my_value; Path=/; Secure; HttpOnly
     ```
   - Chromium 的网络栈会调用 `parsed_cookie.cc` 来解析这个字符串。
   - `ParsedCookie` 对象会被创建，其中：
     - `pairs_` 可能会包含：`[("", "my_cookie=my_value"), ("path", "/"), ("secure", ""), ("httponly", "")]` (具体实现可能略有不同，但会包含这些信息)。
     - `path_index_`, `secure_index_`, `httponly_index_` 等索引会被设置为指向对应的属性。

2. **JavaScript 读取 Cookie:**
   - 在 JavaScript 中，可以使用 `document.cookie` 来获取当前页面的 Cookie。
   - 浏览器会根据之前 `parsed_cookie.cc` 解析并存储的 Cookie 信息，将符合当前页面上下文的 Cookie 拼接成字符串返回给 JavaScript。例如，如果当前页面是 `https://example.com/somepath`,  那么 JavaScript 可能会读取到 `my_cookie=my_value`。浏览器在拼接时会考虑 `Path`, `Domain`, `Secure` 等属性。

3. **JavaScript 设置 Cookie:**
   - JavaScript 也可以通过 `document.cookie = "another_cookie=another_value; path=/";` 来设置 Cookie。
   - 尽管 `parsed_cookie.cc` 主要用于解析服务器发送的 Cookie，但浏览器在内部处理 JavaScript 设置的 Cookie 时，也会进行类似的结构化处理和存储，以便后续使用和发送。

**逻辑推理及假设输入输出**

**假设输入:**  一个 `Set-Cookie` 头部字段的值字符串。

**示例 1:**

- **假设输入:** `"session_id=12345"`
- **逻辑推理:**
    - 解析器会识别出名称为 `session_id`，值为 `12345`。
    - 没有其他属性。
- **预期输出:**
    - `pairs_`: `[("", "session_id=12345")]`
    - 其他索引 (如 `path_index_`, `domain_index_` 等) 为 0。

**示例 2:**

- **假设输入:** `"user=John Doe; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Secure"`
- **逻辑推理:**
    - 解析器会识别出名称为 `user`，值为 `John Doe`。
    - 识别出 `Expires` 属性，值为 `Wed, 21 Oct 2015 07:28:00 GMT`。
    - 识别出 `Secure` 属性，没有值。
- **预期输出:**
    - `pairs_`: `[("", "user=John Doe"), ("expires", "Wed, 21 Oct 2015 07:28:00 GMT"), ("secure", "")]`
    - `expires_index_` 指向 `("expires", ...)` 在 `pairs_` 中的位置。
    - `secure_index_` 指向 `("secure", "")` 在 `pairs_` 中的位置。

**示例 3 (包含空格和特殊字符):**

- **假设输入:** `"data =  some value with spaces ; Path=/folder"`
- **逻辑推理:**
    - 解析器会识别出名称为 `data ` (注意尾部空格)，值为 ` some value with spaces ` (注意首尾空格)。
    - 识别出 `Path` 属性，值为 `/folder`。
- **预期输出:**
    - `pairs_`: `[("", "data =  some value with spaces "), ("path", "/folder")]`
    - `path_index_` 指向 `("path", "/folder")`。
    - **注意:**  `ParseTokenString` 和 `ParseValueString` 函数会处理首尾空格。

**用户或编程常见的使用错误及举例**

1. **`Set-Cookie` 头部语法错误:**
   - **错误示例:** `Set-Cookie: my_cookie=value; Path /` (缺少等号)
   - **后果:** `parsed_cookie.cc` 在解析时可能会失败，导致 Cookie 无法正确设置或被忽略。`CookieInclusionStatus` 可能会记录排除原因。

2. **Cookie 名称或值包含非法字符:**
   - **错误示例:** `Set-Cookie: my;cookie=value` (名称包含 `;`)
   - **后果:** `IsValidCookieName` 或 `IsValidCookieValue` 函数会返回 `false`，导致 Cookie 被拒绝。

3. **Cookie 属性值包含非法字符或过长:**
   - **错误示例:** `Set-Cookie: my_cookie=value; Path=folder with spaces and ;`
   - **后果:**  `CookieAttributeValueHasValidCharSet` 或 `CookieAttributeValueHasValidSize` 函数会返回 `false`，可能导致整个 Cookie 被忽略或属性被忽略。

4. **尝试通过 JavaScript 设置格式错误的 Cookie 字符串:**
   - **错误示例:** `document.cookie = "bad cookie string"`
   - **后果:** 虽然 `parsed_cookie.cc` 主要处理服务器的 `Set-Cookie`，但浏览器在处理 JavaScript 设置的 Cookie 时也会进行类似的校验。格式错误的字符串可能导致 Cookie 设置失败或产生意想不到的结果。

**用户操作如何一步步到达这里 (调试线索)**

当你在调试 Cookie 相关问题时，理解用户操作如何触发 `parsed_cookie.cc` 的执行是至关重要的。以下是一些常见的场景：

1. **用户访问网页，服务器发送 `Set-Cookie` 头部:**
   - 用户在浏览器地址栏输入 URL 或点击链接。
   - 浏览器发送 HTTP 请求到服务器。
   - 服务器处理请求并返回 HTTP 响应。
   - 响应头中包含 `Set-Cookie` 字段。
   - Chromium 网络栈接收到响应头。
   - **网络栈代码会调用 `parsed_cookie.cc` 中的 `ParsedCookie` 构造函数来解析 `Set-Cookie` 的值。**

2. **JavaScript 代码设置 Cookie:**
   - 网页上的 JavaScript 代码执行了类似 `document.cookie = "my_cookie=value";` 的操作。
   - 浏览器内部会处理这个操作，虽然不直接调用 `parsed_cookie.cc` 的构造函数，但内部的 Cookie 管理逻辑会进行类似的解析和校验，与 `parsed_cookie.cc` 的设计理念和校验规则一致。

3. **浏览器接收到重定向响应，包含 `Set-Cookie` 头部:**
   - 用户访问某个 URL，服务器返回一个 3xx 重定向响应，并且该响应的头部包含 `Set-Cookie` 字段。
   - 浏览器会处理重定向，并且在处理响应头时，会调用 `parsed_cookie.cc` 来解析 Cookie。

**作为调试线索:**

- **查看网络请求:** 使用 Chrome 的开发者工具 (F12)，在 "Network" 标签页中查看 HTTP 响应头，特别是 `Set-Cookie` 字段的值。检查其语法是否正确。
- **断点调试:** 如果你有 Chromium 的源代码，可以在 `parsed_cookie.cc` 的关键函数（例如构造函数、`ParseTokenValuePairs` 等）设置断点，查看解析过程中的变量值，例如 `pairs_` 的内容，以及 `CookieInclusionStatus` 的状态，了解 Cookie 是否被成功解析以及被拒绝的原因。
- **查看 `chrome://net-internals/#cookies`:**  这个页面可以查看浏览器当前存储的所有 Cookie。如果某个 Cookie 没有出现或值不正确，可能是在解析阶段出了问题。
- **分析 `CookieInclusionStatus`:**  如果 Cookie 被拒绝，`CookieInclusionStatus` 对象会记录拒绝的原因。查看这个状态可以帮助定位问题。

总而言之，`net/cookies/parsed_cookie.cc` 是 Chromium 处理 HTTP Cookie 的核心组件之一，负责将服务器发送的 Cookie 信息转化为浏览器可以理解和使用的结构化数据。理解其功能和工作原理对于调试 Cookie 相关的问题至关重要。

### 提示词
```
这是目录为net/cookies/parsed_cookie.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
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

#include "net/cookies/parsed_cookie.h"

#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/checked_math.h"
#include "base/strings/string_util.h"
#include "net/base/features.h"
#include "net/cookies/cookie_constants.h"
#include "net/cookies/cookie_inclusion_status.h"
#include "net/http/http_util.h"

namespace {

const char kPathTokenName[] = "path";
const char kDomainTokenName[] = "domain";
const char kExpiresTokenName[] = "expires";
const char kMaxAgeTokenName[] = "max-age";
const char kSecureTokenName[] = "secure";
const char kHttpOnlyTokenName[] = "httponly";
const char kSameSiteTokenName[] = "samesite";
const char kPriorityTokenName[] = "priority";
const char kPartitionedTokenName[] = "partitioned";

const char kTerminator[] = "\n\r\0";
const int kTerminatorLen = sizeof(kTerminator) - 1;
const char kWhitespace[] = " \t";
const char kValueSeparator = ';';
const char kTokenSeparator[] = ";=";

// Returns true if |c| occurs in |chars|
// TODO(erikwright): maybe make this take an iterator, could check for end also?
inline bool CharIsA(const char c, const char* chars) {
  return strchr(chars, c) != nullptr;
}

// Seek the iterator to the first occurrence of |character|.
// Returns true if it hits the end, false otherwise.
inline bool SeekToCharacter(std::string_view::iterator* it,
                            const std::string_view::iterator& end,
                            const char character) {
  for (; *it != end && **it != character; ++(*it)) {
  }
  return *it == end;
}

// Seek the iterator to the first occurrence of a character in |chars|.
// Returns true if it hit the end, false otherwise.
inline bool SeekTo(std::string_view::iterator* it,
                   const std::string_view::iterator& end,
                   const char* chars) {
  for (; *it != end && !CharIsA(**it, chars); ++(*it)) {
  }
  return *it == end;
}
// Seek the iterator to the first occurrence of a character not in |chars|.
// Returns true if it hit the end, false otherwise.
inline bool SeekPast(std::string_view::iterator* it,
                     const std::string_view::iterator& end,
                     const char* chars) {
  for (; *it != end && CharIsA(**it, chars); ++(*it)) {
  }
  return *it == end;
}
inline bool SeekBackPast(std::string_view::iterator* it,
                         const std::string_view::iterator& end,
                         const char* chars) {
  for (; *it != end && CharIsA(**it, chars); --(*it)) {
  }
  return *it == end;
}

// Returns the string piece within `value` that is a valid cookie value.
std::string_view ValidStringPieceForValue(std::string_view value) {
  std::string_view::iterator it = value.begin();
  std::string_view::iterator end =
      net::ParsedCookie::FindFirstTerminator(value);
  std::string_view::iterator value_start;
  std::string_view::iterator value_end;

  net::ParsedCookie::ParseValue(&it, end, &value_start, &value_end);

  return std::string_view(value_start, value_end);
}

}  // namespace

namespace net {

ParsedCookie::ParsedCookie(std::string_view cookie_line,
                           CookieInclusionStatus* status_out) {
  // Put a pointer on the stack so the rest of the function can assign to it if
  // the default nullptr is passed in.
  CookieInclusionStatus blank_status;
  if (status_out == nullptr) {
    status_out = &blank_status;
  }
  *status_out = CookieInclusionStatus();

  ParseTokenValuePairs(cookie_line, *status_out);
  if (IsValid()) {
    SetupAttributes();
  } else {
    // Status should indicate exclusion if the resulting ParsedCookie is
    // invalid.
    CHECK(!status_out->IsInclude());
  }
}

ParsedCookie::~ParsedCookie() = default;

bool ParsedCookie::IsValid() const {
  return !pairs_.empty();
}

CookieSameSite ParsedCookie::SameSite(
    CookieSameSiteString* samesite_string) const {
  CookieSameSite samesite = CookieSameSite::UNSPECIFIED;
  if (same_site_index_ != 0) {
    samesite = StringToCookieSameSite(pairs_[same_site_index_].second,
                                      samesite_string);
  } else if (samesite_string) {
    *samesite_string = CookieSameSiteString::kUnspecified;
  }
  return samesite;
}

CookiePriority ParsedCookie::Priority() const {
  return (priority_index_ == 0)
             ? COOKIE_PRIORITY_DEFAULT
             : StringToCookiePriority(pairs_[priority_index_].second);
}

bool ParsedCookie::SetName(const std::string& name) {
  const std::string& value = pairs_.empty() ? "" : pairs_[0].second;

  // Ensure there are no invalid characters in `name`. This should be done
  // before calling ParseTokenString because we want terminating characters
  // ('\r', '\n', and '\0') and '=' in `name` to cause a rejection instead of
  // truncation.
  // TODO(crbug.com/40191620) Once we change logic more broadly to reject
  // cookies containing these characters, we should be able to simplify this
  // logic since IsValidCookieNameValuePair() also calls IsValidCookieName().
  // Also, this check will currently fail if `name` has a tab character in the
  // leading or trailing whitespace, which is inconsistent with what happens
  // when parsing a cookie line in the constructor (but the old logic for
  // SetName() behaved this way as well).
  if (!IsValidCookieName(name)) {
    return false;
  }

  // Use the same whitespace trimming code as the constructor.
  const std::string& parsed_name = ParseTokenString(name);

  if (!IsValidCookieNameValuePair(parsed_name, value)) {
    return false;
  }

  if (pairs_.empty())
    pairs_.emplace_back("", "");
  pairs_[0].first = parsed_name;

  return true;
}

bool ParsedCookie::SetValue(const std::string& value) {
  const std::string& name = pairs_.empty() ? "" : pairs_[0].first;

  // Ensure there are no invalid characters in `value`. This should be done
  // before calling ParseValueString because we want terminating characters
  // ('\r', '\n', and '\0') in `value` to cause a rejection instead of
  // truncation.
  // TODO(crbug.com/40191620) Once we change logic more broadly to reject
  // cookies containing these characters, we should be able to simplify this
  // logic since IsValidCookieNameValuePair() also calls IsValidCookieValue().
  // Also, this check will currently fail if `value` has a tab character in
  // the leading or trailing whitespace, which is inconsistent with what
  // happens when parsing a cookie line in the constructor (but the old logic
  // for SetValue() behaved this way as well).
  if (!IsValidCookieValue(value)) {
    return false;
  }

  // Use the same whitespace trimming code as the constructor.
  const std::string& parsed_value = ParseValueString(value);

  if (!IsValidCookieNameValuePair(name, parsed_value)) {
    return false;
  }
  if (pairs_.empty())
    pairs_.emplace_back("", "");
  pairs_[0].second = parsed_value;

  return true;
}

bool ParsedCookie::SetPath(const std::string& path) {
  return SetString(&path_index_, kPathTokenName, path);
}

bool ParsedCookie::SetDomain(const std::string& domain) {
  return SetString(&domain_index_, kDomainTokenName, domain);
}

bool ParsedCookie::SetExpires(const std::string& expires) {
  return SetString(&expires_index_, kExpiresTokenName, expires);
}

bool ParsedCookie::SetMaxAge(const std::string& maxage) {
  return SetString(&maxage_index_, kMaxAgeTokenName, maxage);
}

bool ParsedCookie::SetIsSecure(bool is_secure) {
  return SetBool(&secure_index_, kSecureTokenName, is_secure);
}

bool ParsedCookie::SetIsHttpOnly(bool is_http_only) {
  return SetBool(&httponly_index_, kHttpOnlyTokenName, is_http_only);
}

bool ParsedCookie::SetSameSite(const std::string& same_site) {
  return SetString(&same_site_index_, kSameSiteTokenName, same_site);
}

bool ParsedCookie::SetPriority(const std::string& priority) {
  return SetString(&priority_index_, kPriorityTokenName, priority);
}

bool ParsedCookie::SetIsPartitioned(bool is_partitioned) {
  return SetBool(&partitioned_index_, kPartitionedTokenName, is_partitioned);
}

std::string ParsedCookie::ToCookieLine() const {
  std::string out;
  for (auto it = pairs_.begin(); it != pairs_.end(); ++it) {
    if (!out.empty())
      out.append("; ");
    out.append(it->first);
    // Determine whether to emit the pair's value component. We should always
    // print it for the first pair(see crbug.com/977619). After the first pair,
    // we need to consider whether the name component is a special token.
    if (it == pairs_.begin() ||
        (it->first != kSecureTokenName && it->first != kHttpOnlyTokenName &&
         it->first != kPartitionedTokenName)) {
      out.append("=");
      out.append(it->second);
    }
  }
  return out;
}

// static
std::string_view::iterator ParsedCookie::FindFirstTerminator(
    std::string_view s) {
  std::string_view::iterator end = s.end();
  size_t term_pos =
      s.find_first_of(std::string_view(kTerminator, kTerminatorLen));
  if (term_pos != std::string_view::npos) {
    // We found a character we should treat as an end of string.
    end = s.begin() + term_pos;
  }
  return end;
}

// static
bool ParsedCookie::ParseToken(std::string_view::iterator* it,
                              const std::string_view::iterator& end,
                              std::string_view::iterator* token_start,
                              std::string_view::iterator* token_end) {
  DCHECK(it && token_start && token_end);
  std::string_view::iterator token_real_end;

  // Seek past any whitespace before the "token" (the name).
  // token_start should point at the first character in the token
  if (SeekPast(it, end, kWhitespace))
    return false;  // No token, whitespace or empty.
  *token_start = *it;

  // Seek over the token, to the token separator.
  // token_real_end should point at the token separator, i.e. '='.
  // If it == end after the seek, we probably have a token-value.
  SeekTo(it, end, kTokenSeparator);
  token_real_end = *it;

  // Ignore any whitespace between the token and the token separator.
  // token_end should point after the last interesting token character,
  // pointing at either whitespace, or at '=' (and equal to token_real_end).
  if (*it != *token_start) {  // We could have an empty token name.
    --(*it);                  // Go back before the token separator.
    // Skip over any whitespace to the first non-whitespace character.
    SeekBackPast(it, *token_start, kWhitespace);
    // Point after it.
    ++(*it);
  }
  *token_end = *it;

  // Seek us back to the end of the token.
  *it = token_real_end;
  return true;
}

// static
void ParsedCookie::ParseValue(std::string_view::iterator* it,
                              const std::string_view::iterator& end,
                              std::string_view::iterator* value_start,
                              std::string_view::iterator* value_end) {
  DCHECK(it && value_start && value_end);

  // Seek past any whitespace that might be in-between the token and value.
  SeekPast(it, end, kWhitespace);
  // value_start should point at the first character of the value.
  *value_start = *it;

  // Just look for ';' to terminate ('=' allowed).
  // We can hit the end, maybe they didn't terminate.
  SeekToCharacter(it, end, kValueSeparator);

  // Will point at the ; separator or the end.
  *value_end = *it;

  // Ignore any unwanted whitespace after the value.
  if (*value_end != *value_start) {  // Could have an empty value
    --(*value_end);
    // Skip over any whitespace to the first non-whitespace character.
    SeekBackPast(value_end, *value_start, kWhitespace);
    // Point after it.
    ++(*value_end);
  }
}

// static
std::string ParsedCookie::ParseTokenString(std::string_view token) {
  std::string_view::iterator it = token.begin();
  std::string_view::iterator end = FindFirstTerminator(token);

  std::string_view::iterator token_start, token_end;
  if (ParseToken(&it, end, &token_start, &token_end))
    return std::string(token_start, token_end);
  return std::string();
}

// static
std::string ParsedCookie::ParseValueString(std::string_view value) {
  return std::string(ValidStringPieceForValue(value));
}

// static
bool ParsedCookie::ValueMatchesParsedValue(const std::string& value) {
  // ValidStringPieceForValue() returns a valid substring of |value|.
  // If |value| can be fully parsed the result will have the same length
  // as |value|.
  return ValidStringPieceForValue(value).length() == value.length();
}

// static
bool ParsedCookie::IsValidCookieName(const std::string& name) {
  // IsValidCookieName() returns whether a string matches the following
  // grammar:
  //
  // cookie-name       = *cookie-name-octet
  // cookie-name-octet = %x20-3A / %x3C / %x3E-7E / %x80-FF
  //                       ; octets excluding CTLs, ";", and "="
  //
  // This can be used to determine whether cookie names and cookie attribute
  // names contain any invalid characters.
  //
  // Note that RFC6265bis section 4.1.1 suggests a stricter grammar for
  // parsing cookie names, but we choose to allow a wider range of characters
  // than what's allowed by that grammar (while still conforming to the
  // requirements of the parsing algorithm defined in section 5.2).
  //
  // For reference, see:
  //  - https://crbug.com/238041
  for (char i : name) {
    if (HttpUtil::IsControlChar(i) || i == ';' || i == '=')
      return false;
  }
  return true;
}

// static
bool ParsedCookie::IsValidCookieValue(const std::string& value) {
  // IsValidCookieValue() returns whether a string matches the following
  // grammar:
  //
  // cookie-value       = *cookie-value-octet
  // cookie-value-octet = %x20-3A / %x3C-7E / %x80-FF
  //                       ; octets excluding CTLs and ";"
  //
  // This can be used to determine whether cookie values contain any invalid
  // characters.
  //
  // Note that RFC6265bis section 4.1.1 suggests a stricter grammar for
  // parsing cookie values, but we choose to allow a wider range of characters
  // than what's allowed by that grammar (while still conforming to the
  // requirements of the parsing algorithm defined in section 5.2).
  //
  // For reference, see:
  //  - https://crbug.com/238041
  for (char i : value) {
    if (HttpUtil::IsControlChar(i) || i == ';')
      return false;
  }
  return true;
}

// static
bool ParsedCookie::CookieAttributeValueHasValidCharSet(
    const std::string& value) {
  // A cookie attribute value has the same character set restrictions as cookie
  // values, so re-use the validation function for that.
  return IsValidCookieValue(value);
}

// static
bool ParsedCookie::CookieAttributeValueHasValidSize(const std::string& value) {
  return (value.size() <= kMaxCookieAttributeValueSize);
}

// static
bool ParsedCookie::IsValidCookieNameValuePair(
    const std::string& name,
    const std::string& value,
    CookieInclusionStatus* status_out) {
  // Ignore cookies with neither name nor value.
  if (name.empty() && value.empty()) {
    if (status_out != nullptr) {
      status_out->AddExclusionReason(
          CookieInclusionStatus::EXCLUDE_NO_COOKIE_CONTENT);
    }
    // TODO(crbug.com/40189703) Note - if the exclusion reasons change to no
    // longer be the same, we'll need to not return right away and evaluate all
    // of the checks.
    return false;
  }

  // Enforce a length limit for name + value per RFC6265bis.
  base::CheckedNumeric<size_t> name_value_pair_size = name.size();
  name_value_pair_size += value.size();
  if (!name_value_pair_size.IsValid() ||
      (name_value_pair_size.ValueOrDie() > kMaxCookieNamePlusValueSize)) {
    if (status_out != nullptr) {
      status_out->AddExclusionReason(
          CookieInclusionStatus::EXCLUDE_NAME_VALUE_PAIR_EXCEEDS_MAX_SIZE);
    }
    return false;
  }

  // Ignore Set-Cookie directives containing control characters. See
  // http://crbug.com/238041.
  if (!IsValidCookieName(name) || !IsValidCookieValue(value)) {
    if (status_out != nullptr) {
      status_out->AddExclusionReason(
          CookieInclusionStatus::EXCLUDE_DISALLOWED_CHARACTER);
    }
    return false;
  }
  return true;
}

// Parse all token/value pairs and populate pairs_.
void ParsedCookie::ParseTokenValuePairs(std::string_view cookie_line,
                                        CookieInclusionStatus& status_out) {
  pairs_.clear();

  // Ok, here we go.  We should be expecting to be starting somewhere
  // before the cookie line, not including any header name...
  std::string_view::iterator start = cookie_line.begin();
  std::string_view::iterator it = start;

  // TODO(erikwright): Make sure we're stripping \r\n in the network code.
  // Then we can log any unexpected terminators.
  std::string_view::iterator end = FindFirstTerminator(cookie_line);

  // Block cookies that were truncated by control characters.
  if (end < cookie_line.end()) {
    status_out.AddExclusionReason(
        CookieInclusionStatus::EXCLUDE_DISALLOWED_CHARACTER);
    return;
  }

  // Exit early for an empty cookie string.
  if (it == end) {
    status_out.AddExclusionReason(
        CookieInclusionStatus::EXCLUDE_NO_COOKIE_CONTENT);
    return;
  }

  for (int pair_num = 0; it != end; ++pair_num) {
    TokenValuePair pair;

    std::string_view::iterator token_start, token_end;
    if (!ParseToken(&it, end, &token_start, &token_end)) {
      // Allow first token to be treated as empty-key if unparsable
      if (pair_num != 0)
        break;

      // If parsing failed, start the value parsing at the very beginning.
      token_start = start;
    }

    if (it == end || *it != '=') {
      // We have a token-value, we didn't have any token name.
      if (pair_num == 0) {
        // For the first time around, we want to treat single values
        // as a value with an empty name. (Mozilla bug 169091).
        // IE seems to also have this behavior, ex "AAA", and "AAA=10" will
        // set 2 different cookies, and setting "BBB" will then replace "AAA".
        pair.first = "";
        // Rewind to the beginning of what we thought was the token name,
        // and let it get parsed as a value.
        it = token_start;
      } else {
        // Any not-first attribute we want to treat a value as a
        // name with an empty value...  This is so something like
        // "secure;" will get parsed as a Token name, and not a value.
        pair.first = std::string(token_start, token_end);
      }
    } else {
      // We have a TOKEN=VALUE.
      pair.first = std::string(token_start, token_end);
      ++it;  // Skip past the '='.
    }

    // OK, now try to parse a value.
    std::string_view::iterator value_start, value_end;
    ParseValue(&it, end, &value_start, &value_end);

    // OK, we're finished with a Token/Value.
    pair.second = std::string(value_start, value_end);

    // For metrics, check if either the name or value contain an internal HTAB
    // (0x9). That is, not leading or trailing.
    if (pair_num == 0 &&
        (pair.first.find_first_of("\t") != std::string::npos ||
         pair.second.find_first_of("\t") != std::string::npos)) {
      internal_htab_ = true;
    }

    bool ignore_pair = false;
    if (pair_num == 0) {
      if (!IsValidCookieNameValuePair(pair.first, pair.second, &status_out)) {
        pairs_.clear();
        break;
      }
    } else {
      // From RFC2109: "Attributes (names) (attr) are case-insensitive."
      pair.first = base::ToLowerASCII(pair.first);

      // Attribute names have the same character set limitations as cookie
      // names, but only a handful of values are allowed. We don't check that
      // this attribute name is one of the allowed ones here, so just re-use
      // the cookie name check.
      if (!IsValidCookieName(pair.first)) {
        status_out.AddExclusionReason(
            CookieInclusionStatus::EXCLUDE_DISALLOWED_CHARACTER);
        pairs_.clear();
        break;
      }

      if (!CookieAttributeValueHasValidCharSet(pair.second)) {
        // If the attribute value contains invalid characters, the whole
        // cookie should be ignored.
        status_out.AddExclusionReason(
            CookieInclusionStatus::EXCLUDE_DISALLOWED_CHARACTER);
        pairs_.clear();
        break;
      }

      if (!CookieAttributeValueHasValidSize(pair.second)) {
        // If the attribute value is too large, it should be ignored.
        ignore_pair = true;
        status_out.AddWarningReason(
            CookieInclusionStatus::WARN_ATTRIBUTE_VALUE_EXCEEDS_MAX_SIZE);
      }
    }

    if (!ignore_pair) {
      pairs_.emplace_back(std::move(pair));
    }

    // We've processed a token/value pair, we're either at the end of
    // the string or a ValueSeparator like ';', which we want to skip.
    if (it != end)
      ++it;
  }
}

void ParsedCookie::SetupAttributes() {
  // We skip over the first token/value, the user supplied one.
  for (size_t i = 1; i < pairs_.size(); ++i) {
    if (pairs_[i].first == kPathTokenName) {
      path_index_ = i;
    } else if (pairs_[i].first == kDomainTokenName) {
      domain_index_ = i;
    } else if (pairs_[i].first == kExpiresTokenName) {
      expires_index_ = i;
    } else if (pairs_[i].first == kMaxAgeTokenName) {
      maxage_index_ = i;
    } else if (pairs_[i].first == kSecureTokenName) {
      secure_index_ = i;
    } else if (pairs_[i].first == kHttpOnlyTokenName) {
      httponly_index_ = i;
    } else if (pairs_[i].first == kSameSiteTokenName) {
      same_site_index_ = i;
    } else if (pairs_[i].first == kPriorityTokenName) {
      priority_index_ = i;
    } else if (pairs_[i].first == kPartitionedTokenName) {
      partitioned_index_ = i;
    } else {
      /* some attribute we don't know or don't care about. */
    }
  }
}

bool ParsedCookie::SetString(size_t* index,
                             const std::string& key,
                             const std::string& untrusted_value) {
  // This function should do equivalent input validation to the
  // constructor. Otherwise, the Set* functions can put this ParsedCookie in a
  // state where parsing the output of ToCookieLine() produces a different
  // ParsedCookie.
  //
  // Without input validation, invoking pc.SetPath(" baz ") would result in
  // pc.ToCookieLine() == "path= baz ". Parsing the "path= baz " string would
  // produce a cookie with "path" attribute equal to "baz" (no spaces). We
  // should not produce cookie lines that parse to different key/value pairs!

  // Inputs containing invalid characters or attribute value strings that are
  // too large should be ignored. Note that we check the attribute value size
  // after removing leading and trailing whitespace.
  if (!CookieAttributeValueHasValidCharSet(untrusted_value))
    return false;

  // Use the same whitespace trimming code as the constructor.
  const std::string parsed_value = ParseValueString(untrusted_value);

  if (!CookieAttributeValueHasValidSize(parsed_value))
    return false;

  if (parsed_value.empty()) {
    ClearAttributePair(*index);
    return true;
  } else {
    return SetAttributePair(index, key, parsed_value);
  }
}

bool ParsedCookie::SetBool(size_t* index, const std::string& key, bool value) {
  if (!value) {
    ClearAttributePair(*index);
    return true;
  } else {
    return SetAttributePair(index, key, std::string());
  }
}

bool ParsedCookie::SetAttributePair(size_t* index,
                                    const std::string& key,
                                    const std::string& value) {
  if (!HttpUtil::IsToken(key))
    return false;
  if (!IsValid())
    return false;
  if (*index) {
    pairs_[*index].second = value;
  } else {
    pairs_.emplace_back(key, value);
    *index = pairs_.size() - 1;
  }
  return true;
}

void ParsedCookie::ClearAttributePair(size_t index) {
  // The first pair (name/value of cookie at pairs_[0]) cannot be cleared.
  // Cookie attributes that don't have a value at the moment, are
  // represented with an index being equal to 0.
  if (index == 0)
    return;

  size_t* indexes[] = {
      &path_index_,      &domain_index_,   &expires_index_,
      &maxage_index_,    &secure_index_,   &httponly_index_,
      &same_site_index_, &priority_index_, &partitioned_index_};
  for (size_t* attribute_index : indexes) {
    if (*attribute_index == index)
      *attribute_index = 0;
    else if (*attribute_index > index)
      --(*attribute_index);
  }
  pairs_.erase(pairs_.begin() + index);
}

}  // namespace net
```