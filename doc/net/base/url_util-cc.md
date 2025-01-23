Response:
Let's break down the thought process for analyzing this `url_util.cc` file.

**1. Initial Understanding of the File's Purpose:**

The filename `url_util.cc` immediately suggests that this file contains utility functions related to URLs. The `#include` directives confirm this, bringing in headers like `net/base/ip_address.h`, `url/gurl.h`, `url/url_canon.h`, etc. This strongly indicates the file provides helper functions for manipulating, parsing, and validating URLs within the Chromium networking stack.

**2. Scanning for Key Functionalities (High-Level):**

I would then perform a quick scan of the function names and comments. Keywords like "Append," "Replace," "Parse," "Get," "Is," "Canonicalize," "Unescape" stand out. This gives a preliminary idea of the types of operations performed by the utility functions. Specifically, I see:

* **Query Parameter Manipulation:**  `AppendQueryParameter`, `AppendOrReplaceQueryParameter`, `QueryIterator`, `GetValueForKeyInQuery`.
* **Ref/Fragment Handling:** `AppendOrReplaceRef`.
* **Host and Port Parsing/Formatting:** `ParseHostAndPort`, `GetHostAndPort`, `GetHostAndOptionalPort`.
* **Host Normalization and Validation:** `TrimEndingDot`, `GetSuperdomain`, `IsSubdomainOf`, `CanonicalizeHost`, `IsCanonicalizedHostCompliant`, `IsHostnameNonUnique`, `IsLocalhost`, `HostStringIsLocalhost`, `IsLocalHostname`.
* **URL Simplification:** `SimplifyUrlForRequest`.
* **Scheme Conversion:** `ChangeWebSocketSchemeToHttpScheme`.
* **Scheme Checking:** `IsStandardSchemeWithNetworkHost`.
* **Credential Handling:** `GetIdentityFromURL`.
* **Google-Specific Checks:** `HasGoogleHost`, `IsGoogleHost`, `IsGoogleHostWithAlpnH3`.
* **Decoding:** `UnescapePercentEncodedUrl`.

**3. Deeper Dive into Functionalities and Relationships:**

With the high-level understanding, I'd examine each function more closely, considering:

* **Input and Output:** What does the function take as input? What does it return?  Are there any side effects (e.g., modifying output parameters)?
* **Core Logic:**  What is the main purpose of the function? How does it achieve that purpose?  Are there any interesting algorithms or data structures involved? (In this case, the use of `url::Component` and the URL canonicalization library are notable).
* **Dependencies:** What other functions or classes does this function rely on?  This helps understand the relationships within the file and the larger codebase.
* **Edge Cases and Error Handling:** Are there specific checks for invalid inputs or unusual situations?

**4. Connecting to JavaScript:**

Now, I'd consider how these functionalities might relate to JavaScript in a browser context. Key areas of connection include:

* **URL Manipulation:**  JavaScript's `URL` API allows developers to create, parse, and modify URLs. The functions in `url_util.cc` provide the underlying implementation for many of these operations.
* **Query Parameters:**  JavaScript's `URLSearchParams` interface provides ways to work with query strings. The `AppendQueryParameter`, `AppendOrReplaceQueryParameter`, and `QueryIterator` functions are directly relevant to how the browser handles query parameters.
* **Host and Port:**  JavaScript's `URL` object has properties like `hostname` and `port`. The `ParseHostAndPort`, `GetHostAndPort`, etc., functions are used to extract and format these components.
* **Security and Privacy:** Functions like `IsHostnameNonUnique` (related to identifying local network resources) and the Google-specific checks are relevant to security features and potentially tracking prevention.
* **Encoding and Decoding:**  JavaScript's `encodeURIComponent` and `decodeURIComponent` are related to the `UnescapePercentEncodedUrl` function.

**5. Generating Examples, Assumptions, and Error Scenarios:**

For each function or related group of functions, I would try to create concrete examples of input and expected output. This helps illustrate their behavior and identify potential edge cases. I'd also think about common mistakes developers might make when working with URLs that these utility functions might help prevent or handle.

* **Assumptions:** For example, the `AppendQueryParameter` function assumes the input URL is valid.
* **Inputs/Outputs:**  Testing with different URL structures and parameter combinations.
* **Errors:**  Considering scenarios like invalid hostnames, incorrect port numbers, or malformed query strings.

**6. Tracing User Actions:**

Finally, I'd consider how a user's actions in a browser could lead to these functions being called. This requires understanding the browser's architecture and how different components interact. Examples include:

* **Typing a URL in the address bar:**  This triggers URL parsing and validation.
* **Clicking a link:**  The browser needs to parse the link's URL.
* **Submitting a form:**  Form data is often encoded in the URL's query string.
* **JavaScript code manipulating URLs:**  The browser's JavaScript engine interacts with the underlying URL handling mechanisms.

**Self-Correction/Refinement During the Process:**

* **Realizing Interdependencies:**  As I analyze individual functions, I might notice how they rely on each other. For example, `GetHostAndPort` uses `url.EffectiveIntPort()`, which is part of the `GURL` class.
* **Identifying Patterns:**  Functions related to query parameters often use similar logic for iterating and manipulating the query string.
* **Focusing on Key Concepts:**  Recognizing the importance of URL canonicalization for security and consistency.

By following this structured approach, combining a high-level overview with detailed analysis, and considering the context of a web browser, I can effectively understand the functionality of the `url_util.cc` file and its relevance to JavaScript and user interactions.
这个文件 `net/base/url_util.cc` 包含了 Chromium 网络栈中用于处理 URL 的各种实用工具函数。它的主要功能可以归纳为以下几点：

**1. URL 查询参数操作:**

* **`AppendQueryParameter(const GURL& url, std::string_view name, std::string_view value)`:**  向 URL 的查询字符串中添加一个新的键值对。
    * **假设输入:** `url = "https://example.com?a=1"`, `name = "b"`, `value = "2"`
    * **输出:** `"https://example.com?a=1&b=2"`
* **`AppendOrReplaceQueryParameter(const GURL& url, std::string_view name, std::optional<std::string_view> value)`:**  向 URL 的查询字符串中添加或替换一个键值对。如果已存在同名键，则替换其值；如果 `value` 为空，则移除该键。
    * **假设输入 (添加):** `url = "https://example.com?a=1"`, `name = "b"`, `value = "2"`
    * **输出:** `"https://example.com?a=1&b=2"`
    * **假设输入 (替换):** `url = "https://example.com?a=1"`, `name = "a"`, `value = "3"`
    * **输出:** `"https://example.com?a=3"`
    * **假设输入 (移除):** `url = "https://example.com?a=1&b=2"`, `name = "b"`, `value = std::nullopt`
    * **输出:** `"https://example.com?a=1"`
* **`QueryIterator`:** 提供了一种迭代访问 URL 查询参数的机制。
    * **假设输入:** `url = "https://example.com?a=1&b=2"`
    * **迭代过程:**
        * 第一次迭代: `GetKey() == "a"`, `GetValue() == "1"`, `GetUnescapedValue() == "1"`
        * 第二次迭代: `GetKey() == "b"`, `GetValue() == "2"`, `GetUnescapedValue() == "2"`
* **`GetValueForKeyInQuery(const GURL& url, std::string_view search_key, std::string* out_value)`:**  从 URL 的查询字符串中查找指定键的值。
    * **假设输入:** `url = "https://example.com?a=1&b=2"`, `search_key = "b"`
    * **输出:** `*out_value` 将被设置为 `"2"`, 返回 `true`。

**与 JavaScript 的关系:**

这些功能与 JavaScript 的 `URL` 接口密切相关。JavaScript 可以通过 `URL` 对象访问和修改 URL 的各个部分，包括查询参数。

* **`URLSearchParams` 接口:** JavaScript 的 `URLSearchParams` 接口提供了类似的功能来操作 URL 的查询字符串，例如添加、删除、替换参数。`AppendQueryParameter` 和 `AppendOrReplaceQueryParameter` 的功能与 `URLSearchParams.append()` 和 `URLSearchParams.set()` 类似。
* **`URL.searchParams` 属性:** JavaScript 的 `URL.searchParams` 属性返回一个 `URLSearchParams` 对象，允许 JavaScript 代码访问和修改 URL 的查询参数。`QueryIterator` 的功能可以被认为是在 C++ 层对 `URLSearchParams` 的一种实现。

**举例说明:**

假设一个网页的 JavaScript 代码需要向当前 URL 添加一个新的查询参数 `debug=true`：

```javascript
const url = new URL(window.location.href);
url.searchParams.append('debug', 'true');
window.location.href = url.toString();
```

当 JavaScript 执行 `url.searchParams.append('debug', 'true')` 时，浏览器底层可能会调用到 C++ 层的 `AppendQueryParameter` 或类似的函数来实现参数的添加。

**2. 主机和端口处理:**

* **`ParseHostAndPort(std::string_view input, std::string* host, int* port)`:**  解析主机名和端口号。
    * **假设输入:** `"example.com:8080"`
    * **输出:** `*host` 将被设置为 `"example.com"`, `*port` 将被设置为 `8080`，返回 `true`。
    * **假设输入:** `"192.168.1.1"`
    * **输出:** `*host` 将被设置为 `"192.168.1.1"`, `*port` 将被设置为 `-1`（表示没有指定端口），返回 `true`。
    * **假设输入:** `"[::1]:80"`
    * **输出:** `*host` 将被设置为 `"::1"`, `*port` 将被设置为 `80`, 返回 `true`。
    * **假设输入错误:** `"example.com:"`
    * **输出:** 返回 `false`。
* **`GetHostAndPort(const GURL& url)`:**  获取包含主机名和端口号的字符串。
    * **假设输入:** `url = "https://example.com:8080/path"`
    * **输出:** `"example.com:8080"`
* **`GetHostAndOptionalPort(const GURL& url)`:** 获取包含主机名和可选端口号的字符串。如果没有指定端口，则只返回主机名。
    * **假设输入 (有端口):** `url = "https://example.com:8080/path"`
    * **输出:** `"example.com:8080"`
    * **假设输入 (无端口):** `url = "https://example.com/path"`
    * **输出:** `"example.com"`
* **`TrimEndingDot(std::string_view host)`:**  移除主机名末尾的点号。
    * **假设输入:** `"example.com."`
    * **输出:** `"example.com"`

**与 JavaScript 的关系:**

这些功能与 JavaScript `URL` 对象的 `hostname` 和 `port` 属性对应。

**举例说明:**

当 JavaScript 代码访问 `window.location.hostname` 或 `window.location.port` 时，浏览器底层可能会调用 `ParseHostAndPort` 或类似的函数来解析当前页面的 URL，并将结果返回给 JavaScript。

**3. 主机名规范化和验证:**

* **`CanonicalizeHost(std::string_view host, url::CanonHostInfo* host_info)`:** 规范化主机名，例如将大写字母转换为小写，处理 Punycode 等。
    * **假设输入:** `"ExamPle.COM"`
    * **输出:** `"example.com"`
* **`IsCanonicalizedHostCompliant(std::string_view host)`:** 检查主机名是否符合规范化后的要求。
* **`IsHostnameNonUnique(std::string_view hostname)`:** 判断主机名是否为非唯一名称，例如局域网地址、本地主机名等。这对于安全策略很重要。
    * **假设输入:** `"localhost"`
    * **输出:** `true`
    * **假设输入:** `"example.com"`
    * **输出:** `false`
    * **假设输入:** `"192.168.1.1"`
    * **输出:** `true`
* **`IsLocalhost(const GURL& url)`:** 判断 URL 的主机名是否为本地主机名（"localhost" 或 "127.0.0.1" 等）。
* **`HostStringIsLocalhost(std::string_view host)`:** 判断主机名字符串是否为本地主机名。
* **`IsLocalHostname(std::string_view host)`:** 判断主机名是否是 "localhost" 或以 ".localhost" 结尾（不区分大小写）。

**与 JavaScript 的关系:**

虽然 JavaScript 本身没有直接提供主机名规范化的 API，但在网络请求、安全策略等方面，浏览器的底层会使用这些规范化和验证功能。例如，在进行跨域请求时，浏览器需要判断请求的目标主机是否与当前页面同源，这时就需要进行主机名的比较，而规范化是比较的前提。

**4. 其他 URL 操作:**

* **`AppendOrReplaceRef(const GURL& url, const std::string_view& ref)`:**  添加或替换 URL 的片段标识符 (fragment/hash)。
    * **假设输入:** `url = "https://example.com"`, `ref = "section1"`
    * **输出:** `"https://example.com#section1"`
    * **假设输入:** `url = "https://example.com#old"`, `ref = "new"`
    * **输出:** `"https://example.com#new"`
* **`SimplifyUrlForRequest(const GURL& url)`:**  简化 URL 以用于请求，例如移除用户名、密码和片段标识符。
    * **假设输入:** `"https://user:password@example.com/path#ref"`
    * **输出:** `"https://example.com/path"`
* **`ChangeWebSocketSchemeToHttpScheme(const GURL& url)`:** 将 WebSocket 协议 (ws:// 或 wss://) 的 URL 转换为对应的 HTTP 协议 (http:// 或 https://) 的 URL。
    * **假设输入:** `"wss://example.com/socket"`
    * **输出:** `"https://example.com/socket"`
* **`IsStandardSchemeWithNetworkHost(std::string_view scheme)`:** 判断协议是否是标准的且需要网络主机名（例如 http, https, ftp）。
* **`GetIdentityFromURL(const GURL& url, std::u16string* username, std::u16string* password)`:** 从 URL 中提取用户名和密码。
* **`GetSuperdomain(std::string_view domain)`:** 获取给定域名的父域名。
    * **假设输入:** `"sub.example.com"`
    * **输出:** `"example.com"`
* **`IsSubdomainOf(std::string_view subdomain, std::string_view superdomain)`:** 判断一个域名是否是另一个域名的子域名。
    * **假设输入:** `"sub.example.com"`, `"example.com"`
    * **输出:** `true`
* **`HasGoogleHost(const GURL& url)`:** 判断 URL 的主机名是否属于 Google 的域。
* **`IsGoogleHost(std::string_view host)`:** 判断主机名是否属于 Google 的域。
* **`IsGoogleHostWithAlpnH3(std::string_view host)`:** 判断主机名是否是启用了 ALPN H3 的 Google 主机。
* **`UnescapePercentEncodedUrl(std::string_view input)`:** 解码百分号编码的 URL。
    * **假设输入:** `"a%20b+c"`
    * **输出:** `"a b c"` (注意 '+' 会被解码为空格)

**与 JavaScript 的关系:**

这些功能也与 JavaScript 的 `URL` 接口和浏览器行为相关：

* **`URL.hash` 属性:**  `AppendOrReplaceRef` 对应于 JavaScript 中设置 `URL.hash` 属性。
* **网络请求:** `SimplifyUrlForRequest` 的功能在浏览器发起网络请求时可能会被使用，以去除敏感信息。
* **协议转换:** `ChangeWebSocketSchemeToHttpScheme` 在某些场景下可能用于将 WebSocket 连接升级到 HTTP 连接。
* **同源策略:** `GetSuperdomain` 和 `IsSubdomainOf` 等函数可能用于实现同源策略的检查。

**用户操作是如何一步步的到达这里，作为调试线索:**

以下是一些用户操作可能导致这些 `url_util.cc` 中的代码被执行的场景：

1. **在地址栏中输入 URL 并回车:**
   * 用户输入 URL 后，浏览器首先需要解析这个 URL，这会涉及到 `ParseHostAndPort` 等函数。
   * 如果 URL 包含查询参数，`QueryIterator` 或相关函数会被用来提取这些参数。
   * 如果涉及到 HTTPS 连接，浏览器可能会检查主机名是否为 Google 的主机 (`IsGoogleHost`)，以便进行特定的优化或处理。
   * 在发起网络请求之前，可能会调用 `SimplifyUrlForRequest` 来清理 URL。

2. **点击网页上的链接:**
   * 浏览器需要解析链接的 `href` 属性，这同样会用到 URL 解析相关的函数。

3. **网页上的 JavaScript 代码操作 URL:**
   * 当 JavaScript 使用 `new URL()`, `URLSearchParams`, `window.location` 等 API 操作 URL 时，浏览器底层会调用到 `url_util.cc` 中的相应函数。例如，使用 `URLSearchParams.append()` 添加查询参数时，可能会调用到 `AppendQueryParameter`。

4. **提交表单:**
   * 当用户提交一个 HTTP GET 表单时，表单数据会被编码到 URL 的查询字符串中。浏览器需要构建这个 URL，这会涉及到 URL 参数的添加和编码。

5. **处理 WebSocket 连接:**
   * 当 JavaScript 代码尝试建立 WebSocket 连接时，浏览器可能会调用 `ChangeWebSocketSchemeToHttpScheme` 来获取对应的 HTTP URL，用于某些握手或检查。

6. **浏览器安全策略的执行:**
   * 为了执行同源策略、内容安全策略 (CSP) 等安全策略，浏览器需要比较不同 URL 的来源，这会涉及到主机名规范化、域名比较等操作，例如 `CanonicalizeHost`, `IsSubdomainOf`。

**用户或编程常见的使用错误示例:**

1. **手动拼接 URL 查询参数时忘记编码:**
   ```javascript
   // 错误示例
   const baseUrl = 'https://example.com?search=';
   const query = '我的 搜索';
   const url = baseUrl + query; // 错误的 URL，空格没有被编码
   ```
   在这种情况下，浏览器在解析 URL 时可能会出错，或者将空格理解为 `%20`，导致与预期不符。`url_util.cc` 中的 URL 解码函数会处理这种情况，但最佳实践是在 JavaScript 中使用 `encodeURIComponent()` 进行编码。

2. **错误地判断是否为本地主机:**
   ```javascript
   // 错误示例
   const url = new URL('http://localhost:8080');
   if (url.hostname === 'localhost') {
       console.log('This is localhost');
   }
   ```
   虽然这个例子看起来正确，但在某些情况下，主机名可能以其他形式表示本地主机，例如 `127.0.0.1` 或 `::1`。使用 `url_util.cc` 中的 `IsLocalhost` 或 `HostStringIsLocalhost` 函数可以更准确地判断。

3. **在 C++ 代码中手动拼接 URL，忘记使用 URL 编码:**
   ```c++
   // 错误示例
   std::string url = "https://example.com?name=" + name; // 如果 name 包含特殊字符，URL 将无效
   ```
   应该使用 `base::EscapeQueryParamValue` 或类似的函数进行编码。

4. **假设主机名已经规范化:**
   在进行主机名比较时，如果没有先进行规范化，可能会导致比较失败，例如 `"example.com"` 和 `"EXAMPLE.COM"` 应该被认为是相同的。

**调试线索:**

当遇到与 URL 处理相关的问题时，可以考虑以下调试线索：

* **检查 URL 的拼写和格式:**  确保 URL 的各个部分（协议、主机名、端口、路径、查询参数、片段标识符）都是正确的。
* **使用浏览器的开发者工具:**  查看网络请求的 URL，检查请求头和响应头中的相关信息。
* **在 C++ 代码中添加日志:**  在 `url_util.cc` 的相关函数中添加日志输出，以便观察 URL 解析和处理的中间过程。
* **使用断点调试:**  在 `url_util.cc` 中设置断点，逐步跟踪代码的执行流程，查看变量的值。
* **理解 URL 规范:**  参考 RFC 3986 等 URL 规范文档，了解 URL 的结构和编码规则。

总而言之，`net/base/url_util.cc` 是 Chromium 网络栈中一个核心的实用工具文件，提供了大量用于处理和操作 URL 的功能，这些功能在浏览器的各种操作中被广泛使用，并且与 JavaScript 的 URL 相关 API 有着密切的联系。理解这些功能有助于理解浏览器如何处理 URL，排查网络相关的问题，并编写更健壮的网络应用程序。

### 提示词
```
这是目录为net/base/url_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/url_util.h"

#include "build/build_config.h"

#if BUILDFLAG(IS_POSIX)
#include <netinet/in.h>
#elif BUILDFLAG(IS_WIN)
#include <ws2tcpip.h>
#endif

#include <optional>
#include <string_view>

#include "base/check_op.h"
#include "base/containers/fixed_flat_set.h"
#include "base/strings/escape.h"
#include "base/strings/strcat.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "net/base/ip_address.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"
#include "url/url_canon.h"
#include "url/url_canon_internal.h"
#include "url/url_canon_ip.h"
#include "url/url_constants.h"
#include "url/url_util.h"

namespace net {

namespace {

bool IsHostCharAlphanumeric(char c) {
  // We can just check lowercase because uppercase characters have already been
  // normalized.
  return ((c >= 'a') && (c <= 'z')) || ((c >= '0') && (c <= '9'));
}

bool IsNormalizedLocalhostTLD(std::string_view host) {
  return base::EndsWith(host, ".localhost",
                        base::CompareCase::INSENSITIVE_ASCII);
}

// Helper function used by GetIdentityFromURL. If |escaped_text| can be "safely
// unescaped" to a valid UTF-8 string, return that string, as UTF-16. Otherwise,
// convert it as-is to UTF-16. "Safely unescaped" is defined as having no
// escaped character between '0x00' and '0x1F', inclusive.
std::u16string UnescapeIdentityString(std::string_view escaped_text) {
  std::string unescaped_text;
  if (base::UnescapeBinaryURLComponentSafe(
          escaped_text, false /* fail_on_path_separators */, &unescaped_text)) {
    std::u16string result;
    if (base::UTF8ToUTF16(unescaped_text.data(), unescaped_text.length(),
                          &result)) {
      return result;
    }
  }
  return base::UTF8ToUTF16(escaped_text);
}

}  // namespace

GURL AppendQueryParameter(const GURL& url,
                          std::string_view name,
                          std::string_view value) {
  std::string query(url.query());

  if (!query.empty())
    query += "&";

  query += (base::EscapeQueryParamValue(name, true) + "=" +
            base::EscapeQueryParamValue(value, true));
  GURL::Replacements replacements;
  replacements.SetQueryStr(query);
  return url.ReplaceComponents(replacements);
}

GURL AppendOrReplaceQueryParameter(const GURL& url,
                                   std::string_view name,
                                   std::optional<std::string_view> value) {
  bool replaced = false;
  std::string param_name = base::EscapeQueryParamValue(name, true);
  bool should_keep_param = value.has_value();

  std::string param_value;
  if (should_keep_param)
    param_value = base::EscapeQueryParamValue(value.value(), true);

  const std::string_view input = url.query_piece();
  url::Component cursor(0, input.size());
  std::string output;
  url::Component key_range, value_range;
  while (url::ExtractQueryKeyValue(input, &cursor, &key_range, &value_range)) {
    const std::string_view key = input.substr(key_range.begin, key_range.len);
    std::string key_value_pair;
    // Check |replaced| as only the first pair should be replaced.
    if (!replaced && key == param_name) {
      replaced = true;
      if (!should_keep_param)
        continue;

      key_value_pair = param_name + "=" + param_value;
    } else {
      key_value_pair = std::string(
          input.substr(key_range.begin, value_range.end() - key_range.begin));
    }
    if (!output.empty())
      output += "&";

    output += key_value_pair;
  }
  if (!replaced && should_keep_param) {
    if (!output.empty())
      output += "&";

    output += (param_name + "=" + param_value);
  }
  GURL::Replacements replacements;
  replacements.SetQueryStr(output);
  return url.ReplaceComponents(replacements);
}

GURL AppendOrReplaceRef(const GURL& url, const std::string_view& ref) {
  GURL::Replacements replacements;
  replacements.SetRefStr(ref);
  return url.ReplaceComponents(replacements);
}

QueryIterator::QueryIterator(const GURL& url)
    : url_(url), at_end_(!url.is_valid()) {
  if (!at_end_) {
    query_ = url.parsed_for_possibly_invalid_spec().query;
    Advance();
  }
}

QueryIterator::~QueryIterator() = default;

std::string_view QueryIterator::GetKey() const {
  DCHECK(!at_end_);
  if (key_.is_nonempty())
    return std::string_view(url_->spec()).substr(key_.begin, key_.len);
  return std::string_view();
}

std::string_view QueryIterator::GetValue() const {
  DCHECK(!at_end_);
  if (value_.is_nonempty())
    return std::string_view(url_->spec()).substr(value_.begin, value_.len);
  return std::string_view();
}

const std::string& QueryIterator::GetUnescapedValue() {
  DCHECK(!at_end_);
  if (value_.is_nonempty() && unescaped_value_.empty()) {
    unescaped_value_ = base::UnescapeURLComponent(
        GetValue(),
        base::UnescapeRule::SPACES | base::UnescapeRule::PATH_SEPARATORS |
            base::UnescapeRule::URL_SPECIAL_CHARS_EXCEPT_PATH_SEPARATORS |
            base::UnescapeRule::REPLACE_PLUS_WITH_SPACE);
  }
  return unescaped_value_;
}

bool QueryIterator::IsAtEnd() const {
  return at_end_;
}

void QueryIterator::Advance() {
  DCHECK(!at_end_);
  key_.reset();
  value_.reset();
  unescaped_value_.clear();
  at_end_ = !url::ExtractQueryKeyValue(url_->spec(), &query_, &key_, &value_);
}

bool GetValueForKeyInQuery(const GURL& url,
                           std::string_view search_key,
                           std::string* out_value) {
  for (QueryIterator it(url); !it.IsAtEnd(); it.Advance()) {
    if (it.GetKey() == search_key) {
      *out_value = it.GetUnescapedValue();
      return true;
    }
  }
  return false;
}

bool ParseHostAndPort(std::string_view input, std::string* host, int* port) {
  if (input.empty())
    return false;

  url::Component auth_component(0, input.size());
  url::Component username_component;
  url::Component password_component;
  url::Component hostname_component;
  url::Component port_component;

  // `input` is not NUL-terminated, so `input.data()` must be accompanied by a
  // length. In these calls, `url::Component` provides an offset and length.
  url::ParseAuthority(input.data(), auth_component, &username_component,
                      &password_component, &hostname_component,
                      &port_component);

  // There shouldn't be a username/password.
  if (username_component.is_valid() || password_component.is_valid())
    return false;

  if (hostname_component.is_empty())
    return false;  // Failed parsing.

  int parsed_port_number = -1;
  if (port_component.is_nonempty()) {
    parsed_port_number = url::ParsePort(input.data(), port_component);

    // If parsing failed, port_number will be either PORT_INVALID or
    // PORT_UNSPECIFIED, both of which are negative.
    if (parsed_port_number < 0)
      return false;  // Failed parsing the port number.
  }

  if (port_component.len == 0)
    return false;  // Reject inputs like "foo:"

  unsigned char tmp_ipv6_addr[16];

  // If the hostname starts with a bracket, it is either an IPv6 literal or
  // invalid. If it is an IPv6 literal then strip the brackets.
  if (hostname_component.len > 0 && input[hostname_component.begin] == '[') {
    if (input[hostname_component.end() - 1] == ']' &&
        url::IPv6AddressToNumber(input.data(), hostname_component,
                                 tmp_ipv6_addr)) {
      // Strip the brackets.
      hostname_component.begin++;
      hostname_component.len -= 2;
    } else {
      return false;
    }
  }

  // Pass results back to caller.
  *host = std::string(
      input.substr(hostname_component.begin, hostname_component.len));
  *port = parsed_port_number;

  return true;  // Success.
}

std::string GetHostAndPort(const GURL& url) {
  // For IPv6 literals, GURL::host() already includes the brackets so it is
  // safe to just append a colon.
  return base::StringPrintf("%s:%d", url.host().c_str(),
                            url.EffectiveIntPort());
}

std::string GetHostAndOptionalPort(const GURL& url) {
  // For IPv6 literals, GURL::host() already includes the brackets
  // so it is safe to just append a colon.
  if (url.has_port())
    return base::StringPrintf("%s:%s", url.host().c_str(), url.port().c_str());
  return url.host();
}

NET_EXPORT std::string GetHostAndOptionalPort(
    const url::SchemeHostPort& scheme_host_port) {
  int default_port = url::DefaultPortForScheme(scheme_host_port.scheme());
  if (default_port != scheme_host_port.port()) {
    return base::StringPrintf("%s:%i", scheme_host_port.host().c_str(),
                              scheme_host_port.port());
  }
  return scheme_host_port.host();
}

std::string TrimEndingDot(std::string_view host) {
  std::string_view host_trimmed = host;
  size_t len = host_trimmed.length();
  if (len > 1 && host_trimmed[len - 1] == '.') {
    host_trimmed.remove_suffix(1);
  }
  return std::string(host_trimmed);
}

std::string GetHostOrSpecFromURL(const GURL& url) {
  return url.has_host() ? TrimEndingDot(url.host_piece()) : url.spec();
}

std::string GetSuperdomain(std::string_view domain) {
  size_t dot_pos = domain.find('.');
  if (dot_pos == std::string::npos)
    return "";
  return std::string(domain.substr(dot_pos + 1));
}

bool IsSubdomainOf(std::string_view subdomain, std::string_view superdomain) {
  // Subdomain must be identical or have strictly more labels than the
  // superdomain.
  if (subdomain.length() <= superdomain.length())
    return subdomain == superdomain;

  // Superdomain must be suffix of subdomain, and the last character not
  // included in the matching substring must be a dot.
  if (!subdomain.ends_with(superdomain)) {
    return false;
  }
  subdomain.remove_suffix(superdomain.length());
  return subdomain.back() == '.';
}

namespace {
std::string CanonicalizeHost(std::string_view host,
                             bool is_file_scheme,
                             url::CanonHostInfo* host_info) {
  // Try to canonicalize the host.
  const url::Component raw_host_component(0, static_cast<int>(host.length()));
  std::string canon_host;
  url::StdStringCanonOutput canon_host_output(&canon_host);
  // A url::StdStringCanonOutput starts off with a zero length buffer. The
  // first time through Grow() immediately resizes it to 32 bytes, incurring
  // a malloc. With libcxx a 22 byte or smaller request can be accommodated
  // within the std::string itself (i.e. no malloc occurs). Start the buffer
  // off at the max size to avoid a malloc on short strings.
  // NOTE: To ensure the final size is correctly reflected, it's necessary
  // to call Complete() which will adjust the size to the actual bytes written.
  // This is handled below for success cases, while failure cases discard all
  // the output.
  const int kCxxMaxStringBufferSizeWithoutMalloc = 22;
  canon_host_output.Resize(kCxxMaxStringBufferSizeWithoutMalloc);
  if (is_file_scheme) {
    url::CanonicalizeFileHostVerbose(host.data(), raw_host_component,
                                     canon_host_output, *host_info);
  } else {
    url::CanonicalizeSpecialHostVerbose(host.data(), raw_host_component,
                                        canon_host_output, *host_info);
  }

  if (host_info->out_host.is_nonempty() &&
      host_info->family != url::CanonHostInfo::BROKEN) {
    // Success!  Assert that there's no extra garbage.
    canon_host_output.Complete();
    DCHECK_EQ(host_info->out_host.len, static_cast<int>(canon_host.length()));
  } else {
    // Empty host, or canonicalization failed.  We'll return empty.
    canon_host.clear();
  }

  return canon_host;
}
}  // namespace

std::string CanonicalizeHost(std::string_view host,
                             url::CanonHostInfo* host_info) {
  return CanonicalizeHost(host, /*is_file_scheme=*/false, host_info);
}

std::string CanonicalizeFileHost(std::string_view host,
                                 url::CanonHostInfo* host_info) {
  return CanonicalizeHost(host, /*is_file_scheme=*/true, host_info);
}

bool IsCanonicalizedHostCompliant(std::string_view host) {
  if (host.empty() || host.size() > 254 ||
      (host.back() != '.' && host.size() == 254)) {
    return false;
  }

  bool in_component = false;
  bool most_recent_component_started_alphanumeric = false;
  size_t label_size = 0;

  for (char c : host) {
    ++label_size;
    if (!in_component) {
      most_recent_component_started_alphanumeric = IsHostCharAlphanumeric(c);
      if (!most_recent_component_started_alphanumeric && (c != '-') &&
          (c != '_')) {
        return false;
      }
      in_component = true;
    } else if (c == '.') {
      in_component = false;
      if (label_size > 64 || label_size == 1) {
        // Label should not be empty or longer than 63 characters (+1 for '.'
        // character included in `label_size`).
        return false;
      } else {
        label_size = 0;
      }
    } else if (!IsHostCharAlphanumeric(c) && (c != '-') && (c != '_')) {
      return false;
    }
  }

  // Check for too-long label when not ended with final '.'.
  if (label_size > 63)
    return false;

  return most_recent_component_started_alphanumeric;
}

bool IsHostnameNonUnique(std::string_view hostname) {
  // CanonicalizeHost requires surrounding brackets to parse an IPv6 address.
  const std::string host_or_ip = hostname.find(':') != std::string::npos
                                     ? base::StrCat({"[", hostname, "]"})
                                     : std::string(hostname);
  url::CanonHostInfo host_info;
  std::string canonical_name = CanonicalizeHost(host_or_ip, &host_info);

  // If canonicalization fails, then the input is truly malformed. However,
  // to avoid mis-reporting bad inputs as "non-unique", treat them as unique.
  if (canonical_name.empty())
    return false;

  // If |hostname| is an IP address, check to see if it's in an IANA-reserved
  // range reserved for non-publicly routable networks.
  if (host_info.IsIPAddress()) {
    IPAddress host_addr;
    if (!host_addr.AssignFromIPLiteral(hostname.substr(
            host_info.out_host.begin, host_info.out_host.len))) {
      return false;
    }
    switch (host_info.family) {
      case url::CanonHostInfo::IPV4:
      case url::CanonHostInfo::IPV6:
        return !host_addr.IsPubliclyRoutable();
      case url::CanonHostInfo::NEUTRAL:
      case url::CanonHostInfo::BROKEN:
        return false;
    }
  }

  // Check for a registry controlled portion of |hostname|, ignoring private
  // registries, as they already chain to ICANN-administered registries,
  // and explicitly ignoring unknown registries. Registry identifiers themselves
  // are also treated as unique, since a TLD is a valid hostname and can host a
  // web server.
  //
  // Note: This means that as new gTLDs are introduced on the Internet, they
  // will be treated as non-unique until the registry controlled domain list
  // is updated. However, because gTLDs are expected to provide significant
  // advance notice to deprecate older versions of this code, this an
  // acceptable tradeoff.
  return !registry_controlled_domains::HostHasRegistryControlledDomain(
             canonical_name,
             registry_controlled_domains::EXCLUDE_UNKNOWN_REGISTRIES,
             registry_controlled_domains::EXCLUDE_PRIVATE_REGISTRIES) &&
         !registry_controlled_domains::HostIsRegistryIdentifier(
             canonical_name,
             registry_controlled_domains::EXCLUDE_PRIVATE_REGISTRIES);
}

bool IsLocalhost(const GURL& url) {
  return HostStringIsLocalhost(url.HostNoBracketsPiece());
}

bool HostStringIsLocalhost(std::string_view host) {
  IPAddress ip_address;
  if (ip_address.AssignFromIPLiteral(host))
    return ip_address.IsLoopback();
  return IsLocalHostname(host);
}

GURL SimplifyUrlForRequest(const GURL& url) {
  DCHECK(url.is_valid());
  // Fast path to avoid re-canonicalization via ReplaceComponents.
  if (!url.has_username() && !url.has_password() && !url.has_ref())
    return url;
  GURL::Replacements replacements;
  replacements.ClearUsername();
  replacements.ClearPassword();
  replacements.ClearRef();
  return url.ReplaceComponents(replacements);
}

GURL ChangeWebSocketSchemeToHttpScheme(const GURL& url) {
  DCHECK(url.SchemeIsWSOrWSS());
  GURL::Replacements replace_scheme;
  replace_scheme.SetSchemeStr(url.SchemeIs(url::kWssScheme) ? url::kHttpsScheme
                                                            : url::kHttpScheme);
  return url.ReplaceComponents(replace_scheme);
}

bool IsStandardSchemeWithNetworkHost(std::string_view scheme) {
  // file scheme is special. Windows file share origins can have network hosts.
  if (scheme == url::kFileScheme)
    return true;

  url::SchemeType scheme_type;
  if (!url::GetStandardSchemeType(
          scheme.data(), url::Component(0, scheme.length()), &scheme_type)) {
    return false;
  }
  return scheme_type == url::SCHEME_WITH_HOST_PORT_AND_USER_INFORMATION ||
         scheme_type == url::SCHEME_WITH_HOST_AND_PORT;
}

void GetIdentityFromURL(const GURL& url,
                        std::u16string* username,
                        std::u16string* password) {
  *username = UnescapeIdentityString(url.username());
  *password = UnescapeIdentityString(url.password());
}

bool HasGoogleHost(const GURL& url) {
  return IsGoogleHost(url.host_piece());
}

bool IsGoogleHost(std::string_view host) {
  static const char* kGoogleHostSuffixes[] = {
      ".google.com",
      ".youtube.com",
      ".gmail.com",
      ".doubleclick.net",
      ".gstatic.com",
      ".googlevideo.com",
      ".googleusercontent.com",
      ".googlesyndication.com",
      ".google-analytics.com",
      ".googleadservices.com",
      ".googleapis.com",
      ".ytimg.com",
  };
  for (const char* suffix : kGoogleHostSuffixes) {
    // Here it's possible to get away with faster case-sensitive comparisons
    // because the list above is all lowercase, and a GURL's host name will
    // always be canonicalized to lowercase as well.
    if (host.ends_with(suffix)) {
      return true;
    }
  }
  return false;
}

bool IsGoogleHostWithAlpnH3(std::string_view host) {
  return base::EqualsCaseInsensitiveASCII(host, "google.com") ||
         base::EqualsCaseInsensitiveASCII(host, "www.google.com");
}

bool IsLocalHostname(std::string_view host) {
  // Remove any trailing '.'.
  if (!host.empty() && *host.rbegin() == '.')
    host.remove_suffix(1);

  return base::EqualsCaseInsensitiveASCII(host, "localhost") ||
         IsNormalizedLocalhostTLD(host);
}

std::string UnescapePercentEncodedUrl(std::string_view input) {
  std::string result(input);
  // Replace any 0x2B (+) with 0x20 (SP).
  for (char& c : result) {
    if (c == '+') {
      c = ' ';
    }
  }
  // Run UTF-8 decoding without BOM on the percent-decoding.
  url::RawCanonOutputT<char16_t> canon_output;
  url::DecodeURLEscapeSequences(result, url::DecodeURLMode::kUTF8,
                                &canon_output);
  return base::UTF16ToUTF8(canon_output.view());
}

}  // namespace net
```