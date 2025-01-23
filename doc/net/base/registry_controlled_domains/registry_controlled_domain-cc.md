Response:
Let's break down the thought process for analyzing the C++ code and generating the response.

1. **Understand the Core Purpose:** The initial comment block and the file name (`registry_controlled_domain.cc`) immediately suggest the primary function: dealing with Registry Controlled Domains (RCDs), also known as effective top-level domains (eTLDs). The Mozilla origin further reinforces this idea.

2. **Identify Key Data Structures and Algorithms:**  Scanning the code, I noticed the inclusion of `effective_tld_names-reversed-inc.cc` and the variable `g_graph`. The comment "// See make_dafsa.py for documentation of the generated dafsa byte array." is a massive clue. This tells me:
    * There's a dataset of eTLDs.
    * This dataset is likely optimized for searching.
    * The "reversed" part suggests a reverse lookup approach, common for suffix matching.
    * "dafsa" points to a Directed Acyclic Finite State Automaton, a data structure ideal for efficient prefix/suffix searching.

3. **Analyze Key Functions:** I then started examining the most important-looking functions:
    * `GetRegistryLengthImpl`: This function seems central to determining the length of the RCD within a hostname. The `LookupSuffixInReversedSet` call confirms the DAFSA usage.
    * `GetDomainAndRegistryImpl`: This function utilizes `GetRegistryLengthImpl` to extract the domain and registry part of a hostname.
    * `SameDomainOrHost`:  This function compares two hosts to see if they share the same domain and registry.
    * `HostHasRegistryControlledDomain`:  Checks if a host has an RCD.
    * `HostIsRegistryIdentifier`: Checks if a host *is* an RCD.
    * `PermissiveGetHostRegistryLength`:  A more lenient version, likely handling non-canonicalized input.

4. **Trace Data Flow and Logic:** I followed the logic within `GetRegistryLengthImpl`. I saw the handling of:
    * Leading and trailing dots.
    * Wildcard rules (`kDafsaWildcardRule`).
    * Exception rules (`kDafsaExceptionRule`).
    * Unknown registries (via `unknown_filter`).
    * Private registries (via `private_filter`).

5. **Connect to JavaScript (if applicable):** The prompt specifically asked about JavaScript interaction. I considered how RCD information is used in web browsers. The most prominent connection is with the Same-Origin Policy and related security features like cookies and localStorage. This is where the concept of a "site" comes into play, often defined using the eTLD+1 rule (domain name + eTLD).

6. **Construct Examples and Scenarios:** To illustrate the functionality and potential errors, I brainstormed examples:
    * **Assumptions and Outputs:**  I created examples showing how different inputs to `GetRegistryLengthImpl` would be processed, focusing on the wildcard and exception rule logic.
    * **User/Programming Errors:** I thought about common mistakes, like expecting IP addresses to have RCDs or misunderstanding the impact of the `private_filter`.
    * **User Actions and Debugging:** I traced a typical user journey (typing a URL, clicking a link) and how it might lead to the code being executed, providing debugging insights.

7. **Structure the Response:** I organized the findings into clear sections: Functionality, JavaScript Relationship, Logical Inference, Common Errors, and User Actions/Debugging. This makes the information easier to understand.

8. **Refine and Elaborate:** I reviewed the generated response, adding detail and clarity where needed. For example, I explained *why* the permissive version exists (handling non-canonical input) and connected the JavaScript examples more explicitly to security mechanisms. I also made sure to explain the meaning of the `UnknownRegistryFilter` and `PrivateRegistryFilter` enums.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps the code directly manages cookie settings. **Correction:** While RCDs are *related* to cookie behavior, this code primarily focuses on *identifying* the RCD, not setting cookies. The cookie logic would reside elsewhere in the Chromium codebase.
* **Initial thought:** Maybe this code is involved in DNS resolution. **Correction:** While the name mentions "registry," it's about the *logical* registry of domain names, not the DNS system itself. The `net` namespace confirms this focus on network-level abstractions.
* **Ensuring clarity of "dafsa":** I made sure to briefly explain what a DAFSA is and why it's used, as not everyone will be familiar with the term.

By following these steps, iteratively analyzing the code, connecting it to relevant concepts, and constructing illustrative examples, I could generate a comprehensive and accurate response.
好的，让我们来分析一下 `net/base/registry_controlled_domains/registry_controlled_domain.cc` 这个文件的功能。

**主要功能：**

该文件的核心功能是 **判断和提取 Registry Controlled Domain (RCD)**，有时也被称为 Effective Top-Level Domain (eTLD)。 RCD 是指互联网域名层级结构中，由公共后缀列表（Public Suffix List, PSL）定义的那些后缀。例如，`.com`, `.org`, `.uk`, `.co.uk` 等都是 RCD。

更具体地说，这个文件提供了以下几个关键功能：

1. **判断一个域名是否包含 RCD:**  `HostHasRegistryControlledDomain` 函数用于判断给定的主机名是否包含一个有效的 RCD。
2. **获取一个域名的 RCD 的长度:** `GetRegistryLength` 和 `GetCanonicalHostRegistryLength` 函数用于计算给定主机名中 RCD 部分的长度。
3. **获取一个域名的 Domain 和 Registry 部分:** `GetDomainAndRegistry` 函数用于提取给定主机名的 "Domain + RCD" 部分。例如，对于 `www.example.co.uk`，Domain 和 Registry 部分是 `example.co.uk`。
4. **判断两个域名是否属于同一个 Domain 和 Registry:** `SameDomainOrHost` 函数用于判断两个主机名是否拥有相同的 Domain 和 Registry。
5. **判断一个主机名是否是 RCD 本身:** `HostIsRegistryIdentifier` 函数用于判断给定的主机名是否就是一个有效的 RCD。
6. **处理非规范化的主机名:** `PermissiveGetHostRegistryLength` 函数提供了一种更宽松的方式来获取 RCD 的长度，可以处理一些非完全规范化的主机名。

**与 JavaScript 的关系：**

虽然这个文件本身是 C++ 代码，运行在 Chromium 的网络栈中，但它的功能对 JavaScript 的执行环境有重要的影响，尤其是在安全和隔离方面。

**举例说明：**

* **Same-Origin Policy (同源策略):** JavaScript 的同源策略依赖于对域名来源的判断。浏览器使用 RCD 来确定两个不同的域名是否被认为是“同一个站点 (site)”。例如，`example.com` 和 `www.example.com` 属于同一个站点，因为它们的 RCD 都是 `com`，并且共享相同的上一级域名 `example`。而 `example.co.uk` 和 `example.com` 则被认为是不同的站点，因为它们的 RCD 不同。这个文件中的 `SameDomainOrHost` 函数的逻辑，在某种程度上，支持了浏览器对同源的判断。
* **Cookie 隔离:** 浏览器使用 RCD 来决定 Cookie 的作用域。默认情况下，Cookie 只会被发送到设置它的域名及其子域名。RCD 的存在防止了 `.com` 这样的顶级域名设置的 Cookie 影响到所有以 `.com` 结尾的域名。
* **localStorage 和其他 Web Storage:** 类似于 Cookie，浏览器通常也会基于站点的概念隔离 localStorage 和其他 Web Storage。RCD 在这里也扮演了定义站点边界的角色。
* **`document.domain`:** JavaScript 可以通过 `document.domain` 属性来放宽同源策略的限制，但有一定的限制，通常要求设置的 `document.domain` 是当前域名的一个有效的父域名。RCD 的概念在这里也很重要，因为不能将 `document.domain` 设置为 RCD 本身。

**假设输入与输出 (逻辑推理)：**

假设我们调用 `GetRegistryLengthImpl` 函数，并提供不同的输入，来看一下可能的输出：

* **假设输入:** `host = "www.example.com"`, `unknown_filter = EXCLUDE_UNKNOWN_REGISTRIES`, `private_filter = EXCLUDE_PRIVATE_REGISTRIES`
   * **输出:** `registry_length = 3` (对应 `.com` 的长度), `is_registry_identifier = false`
* **假设输入:** `host = "example.co.uk"`, `unknown_filter = EXCLUDE_UNKNOWN_REGISTRIES`, `private_filter = EXCLUDE_PRIVATE_REGISTRIES`
   * **输出:** `registry_length = 5` (对应 `.co.uk` 的长度), `is_registry_identifier = true` (因为主机名本身就是 RCD)
* **假设输入:** `host = "192.168.1.1"`, `unknown_filter = EXCLUDE_UNKNOWN_REGISTRIES`, `private_filter = EXCLUDE_PRIVATE_REGISTRIES`
   * **输出:** `registry_length = 0`, `is_registry_identifier = false` (IP 地址没有 RCD)
* **假设输入:** `host = "example.unknown"` (假设 `.unknown` 不在 PSL 中), `unknown_filter = INCLUDE_UNKNOWN_REGISTRIES`, `private_filter = EXCLUDE_PRIVATE_REGISTRIES`
   * **输出:** `registry_length = 7` (对应 `.unknown` 的长度), `is_registry_identifier = false` (因为 `unknown_filter` 设置为包含未知注册域)
* **假设输入:** `host = "test.blogspot.com"` (假设 `blogspot.com` 是一个 PSL 中的条目), `unknown_filter = EXCLUDE_UNKNOWN_REGISTRIES`, `private_filter = EXCLUDE_PRIVATE_REGISTRIES`
    * **输出:** `registry_length = 11` (对应 `blogspot.com` 的长度), `is_registry_identifier = false`

**用户或编程常见的使用错误：**

1. **假设 IP 地址有 RCD:** 程序员可能会错误地认为 IP 地址也像域名一样有 RCD，并尝试调用相关的函数。例如：
   ```c++
   std::string domain = GetDomainAndRegistry(GURL("http://192.168.1.1"));
   // domain 将会是空字符串，可能会导致后续逻辑错误。
   ```
2. **错误地处理 `private_filter`:** 用户可能不理解 `PrivateRegistryFilter` 的作用，导致在需要区分公共和私有 RCD 的场景下得到错误的结果。例如，如果需要判断一个域名是否属于某个私有网络，但没有包含私有 RCD，则可能判断错误。
3. **混淆主机名和域名:** 用户可能会混淆主机名 (例如 `www.example.com`) 和域名 (例如 `example.com`)，导致在调用函数时传入错误的参数。
4. **未考虑非规范化的主机名:**  直接使用用户输入的主机名而没有进行规范化处理，可能会导致 `GetRegistryLengthImpl` 等函数返回意外的结果。这时可能需要使用 `PermissiveGetHostRegistryLength`。

**用户操作如何一步步的到达这里 (调试线索)：**

当用户在浏览器中进行各种操作时，都可能触发网络请求和资源加载，从而间接地调用到这个文件中的代码。以下是一些可能的场景：

1. **用户在地址栏输入 URL 并回车:**
   * 浏览器解析输入的 URL。
   * Chromium 的网络栈会尝试解析主机名。
   * 在建立网络连接或进行安全检查（例如，检查 Cookie 的作用域）时，可能需要判断域名的 RCD。
   * 这时会调用 `GetRegistryLength` 或 `GetDomainAndRegistry` 等函数。

2. **用户点击一个链接:**
   * 浏览器获取链接的目标 URL。
   * 类似于第一步，网络栈需要处理目标 URL 的主机名。
   * 进行同源检查，判断是否允许 JavaScript 访问目标页面的资源。

3. **网页上的 JavaScript 代码尝试访问另一个域名的资源 (例如，通过 `fetch` 或 `XMLHttpRequest`):**
   * 浏览器会进行 CORS (跨域资源共享) 检查。
   * 这涉及到比较请求来源的域名和目标域名的 RCD，以判断是否需要进行额外的安全验证。
   * `SameDomainOrHost` 等函数可能被调用。

4. **浏览器处理 Cookie:**
   * 当浏览器需要发送 Cookie 时，它需要确定哪些 Cookie 应该被包含在请求中。
   * Cookie 的 `domain` 属性定义了 Cookie 的作用域，而 RCD 用于防止顶级域名设置的 Cookie 影响所有子域名。

5. **浏览器处理 localStorage 或其他 Web Storage:**
   * 当网页尝试读写 localStorage 时，浏览器需要确定存储的隔离边界，这通常基于站点的概念，而站点的定义又依赖于 RCD。

**作为调试线索：**

当开发者在调试与网络、安全或存储相关的 Chromium 功能时，如果怀疑 RCD 的判断出现了问题，可以设置断点在这个文件中的关键函数上，例如：

* `GetRegistryLengthImpl`
* `GetDomainAndRegistryImpl`
* `SameDomainOrHost`
* `HostHasRegistryControlledDomain`

通过观察这些函数的输入 (例如，主机名、过滤器参数) 和输出，可以了解 RCD 的计算过程，并定位问题所在。例如，如果发现 `GetRegistryLengthImpl` 对某个主机名返回了错误的 RCD 长度，可能意味着 PSL 数据有问题，或者主机名本身存在非预期的格式。

总而言之，`registry_controlled_domain.cc` 文件虽然是一个底层的 C++ 文件，但它提供的 RCD 判断功能是 Chromium 网络栈中许多高层功能（如安全策略、Cookie 管理、Web Storage 隔离）的基础。理解这个文件的作用对于理解浏览器的网络行为至关重要。

### 提示词
```
这是目录为net/base/registry_controlled_domains/registry_controlled_domain.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

// NB: Modelled after Mozilla's code (originally written by Pamela Greene,
// later modified by others), but almost entirely rewritten for Chrome.
//   (netwerk/dns/src/nsEffectiveTLDService.cpp)
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
 * The Original Code is Mozilla Effective-TLD Service
 *
 * The Initial Developer of the Original Code is
 * Google Inc.
 * Portions created by the Initial Developer are Copyright (C) 2006
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Pamela Greene <pamg.bugs@gmail.com> (original author)
 *   Daniel Witte <dwitte@stanford.edu>
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

#include "net/base/registry_controlled_domains/registry_controlled_domain.h"

#include <cstdint>
#include <ostream>
#include <string_view>

#include "base/check_op.h"
#include "base/containers/span.h"
#include "base/notreached.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "net/base/lookup_string_in_fixed_set.h"
#include "net/base/net_module.h"
#include "net/base/url_util.h"
#include "url/gurl.h"
#include "url/origin.h"
#include "url/third_party/mozilla/url_parse.h"
#include "url/url_util.h"

namespace net::registry_controlled_domains {

namespace {
#include "net/base/registry_controlled_domains/effective_tld_names-reversed-inc.cc"

// See make_dafsa.py for documentation of the generated dafsa byte array.

// This is mutable so that it can be overridden for testing.
base::span<const uint8_t> g_graph = kDafsa;

struct MappedHostComponent {
  size_t original_begin;
  size_t original_end;

  size_t canonical_begin;
  size_t canonical_end;
};

// Used as the output of functions that calculate the registry length in a
// hostname. |registry_length| is the length of the registry identifier (or zero
// if none is found or the hostname is itself a registry identifier).
// |is_registry_identifier| is true if the host is itself a match for a registry
// identifier.
struct RegistryLengthOutput {
  size_t registry_length;
  bool is_registry_identifier;
};

// This version assumes we already removed leading dots from host as well as the
// last trailing dot if it had one. If the host is itself a registry identifier,
// the returned |registry_length| will be 0 and |is_registry_identifier| will be
// true.
RegistryLengthOutput GetRegistryLengthInTrimmedHost(
    std::string_view host,
    UnknownRegistryFilter unknown_filter,
    PrivateRegistryFilter private_filter) {
  size_t length;
  int type = LookupSuffixInReversedSet(
      g_graph, private_filter == INCLUDE_PRIVATE_REGISTRIES, host, &length);

  CHECK_LE(length, host.size());

  // No rule found in the registry.
  if (type == kDafsaNotFound) {
    // If we allow unknown registries, return the length of last subcomponent.
    if (unknown_filter == INCLUDE_UNKNOWN_REGISTRIES) {
      const size_t last_dot = host.find_last_of('.');
      if (last_dot != std::string_view::npos) {
        length = host.size() - last_dot - 1;
        return {length, false};
      }
    }
    return {length, false};
  }

  // Exception rules override wildcard rules when the domain is an exact
  // match, but wildcards take precedence when there's a subdomain.
  if (type & kDafsaWildcardRule) {
    // If the complete host matches, then the host is the wildcard suffix, so
    // return 0.
    if (length == host.size()) {
      length = 0;
      return {length, true};
    }

    CHECK_LE(length + 2, host.size());
    CHECK_EQ('.', host[host.size() - length - 1]);

    const size_t preceding_dot =
        host.find_last_of('.', host.size() - length - 2);

    // If no preceding dot, then the host is the registry itself, so return 0.
    if (preceding_dot == std::string_view::npos) {
      return {0, true};
    }

    // Return suffix size plus size of subdomain.
    return {host.size() - preceding_dot - 1, false};
  }

  if (type & kDafsaExceptionRule) {
    size_t first_dot = host.find_first_of('.', host.size() - length);
    if (first_dot == std::string_view::npos) {
      // If we get here, we had an exception rule with no dots (e.g.
      // "!foo").  This would only be valid if we had a corresponding
      // wildcard rule, which would have to be "*".  But we explicitly
      // disallow that case, so this kind of rule is invalid.
      // TODO(crbug.com/40406311): This assumes that all wildcard entries,
      // such as *.foo.invalid, also have their parent, foo.invalid, as an entry
      // on the PSL, which is why it returns the length of foo.invalid. This
      // isn't entirely correct.
      NOTREACHED() << "Invalid exception rule";
    }
    return {host.length() - first_dot - 1, false};
  }

  CHECK_NE(type, kDafsaNotFound);

  // If a complete match, then the host is the registry itself, so return 0.
  if (length == host.size()) {
    return {0, true};
  }

  return {length, false};
}

RegistryLengthOutput GetRegistryLengthImpl(
    std::string_view host,
    UnknownRegistryFilter unknown_filter,
    PrivateRegistryFilter private_filter) {
  if (host.empty())
    return {std::string::npos, false};

  // Skip leading dots.
  const size_t host_check_begin = host.find_first_not_of('.');
  if (host_check_begin == std::string_view::npos) {
    return {0, false};  // Host is only dots.
  }

  // A single trailing dot isn't relevant in this determination, but does need
  // to be included in the final returned length.
  size_t host_check_end = host.size();
  if (host.back() == '.')
    --host_check_end;

  RegistryLengthOutput output = GetRegistryLengthInTrimmedHost(
      host.substr(host_check_begin, host_check_end - host_check_begin),
      unknown_filter, private_filter);

  if (output.registry_length == 0) {
    return output;
  }

  output.registry_length =
      output.registry_length + host.size() - host_check_end;
  return output;
}

std::string_view GetDomainAndRegistryImpl(
    std::string_view host,
    PrivateRegistryFilter private_filter) {
  CHECK(!host.empty());

  // Find the length of the registry for this host.
  const RegistryLengthOutput registry_length_output =
      GetRegistryLengthImpl(host, INCLUDE_UNKNOWN_REGISTRIES, private_filter);
  if ((registry_length_output.registry_length == std::string::npos) ||
      (registry_length_output.registry_length == 0)) {
    return std::string_view();  // No registry.
  }
  // The "2" in this next line is 1 for the dot, plus a 1-char minimum preceding
  // subcomponent length.
  CHECK_GE(host.length(), 2u);
  CHECK_LE(registry_length_output.registry_length, host.length() - 2)
      << "Host does not have at least one subcomponent before registry!";

  // Move past the dot preceding the registry, and search for the next previous
  // dot.  Return the host from after that dot, or the whole host when there is
  // no dot.
  const size_t dot = host.rfind(
      '.', host.length() - registry_length_output.registry_length - 2);
  if (dot == std::string::npos)
    return host;
  return host.substr(dot + 1);
}

// Same as GetDomainAndRegistry, but returns the domain and registry as a
// std::string_view that references the underlying string of the passed-in
// |gurl|.
// TODO(pkalinnikov): Eliminate this helper by exposing std::string_view as the
// interface type for all the APIs.
std::string_view GetDomainAndRegistryAsStringPiece(
    std::string_view host,
    PrivateRegistryFilter filter) {
  if (host.empty() || url::HostIsIPAddress(host))
    return std::string_view();
  return GetDomainAndRegistryImpl(host, filter);
}

// These two functions append the given string as-is to the given output,
// converting to UTF-8 if necessary.
void AppendInvalidString(std::string_view str, url::CanonOutput* output) {
  output->Append(str);
}
void AppendInvalidString(std::u16string_view str, url::CanonOutput* output) {
  output->Append(base::UTF16ToUTF8(str));
}

// Backend for PermissiveGetHostRegistryLength that handles both UTF-8 and
// UTF-16 input.
template <typename T, typename CharT = typename T::value_type>
size_t DoPermissiveGetHostRegistryLength(T host,
                                         UnknownRegistryFilter unknown_filter,
                                         PrivateRegistryFilter private_filter) {
  std::string canonical_host;  // Do not modify outside of canon_output.
  canonical_host.reserve(host.length());
  url::StdStringCanonOutput canon_output(&canonical_host);

  std::vector<MappedHostComponent> components;

  for (size_t current = 0; current < host.length(); current++) {
    size_t begin = current;

    // Advance to next "." or end.
    current = host.find('.', begin);
    if (current == std::string::npos)
      current = host.length();

    MappedHostComponent mapping;
    mapping.original_begin = begin;
    mapping.original_end = current;
    mapping.canonical_begin = canon_output.length();

    // Try to append the canonicalized version of this component.
    int current_len = static_cast<int>(current - begin);
    if (!url::CanonicalizeHostSubstring(
            host.data(), url::Component(static_cast<int>(begin), current_len),
            &canon_output)) {
      // Failed to canonicalize this component; append as-is.
      AppendInvalidString(host.substr(begin, current_len), &canon_output);
    }

    mapping.canonical_end = canon_output.length();
    components.push_back(mapping);

    if (current < host.length())
      canon_output.push_back('.');
  }
  canon_output.Complete();

  size_t canonical_rcd_len =
      GetRegistryLengthImpl(canonical_host, unknown_filter, private_filter)
          .registry_length;
  if (canonical_rcd_len == 0 || canonical_rcd_len == std::string::npos)
    return canonical_rcd_len;  // Error or no registry controlled domain.

  // Find which host component the result started in.
  size_t canonical_rcd_begin = canonical_host.length() - canonical_rcd_len;
  for (const auto& mapping : components) {
    // In the common case, GetRegistryLengthImpl will identify the beginning
    // of a component and we can just return where that component was in the
    // original string.
    if (canonical_rcd_begin == mapping.canonical_begin)
      return host.length() - mapping.original_begin;

    if (canonical_rcd_begin >= mapping.canonical_end)
      continue;

    // The registry controlled domain begin was identified as being in the
    // middle of this dot-separated domain component in the non-canonical
    // input. This indicates some form of escaped dot, or a non-ASCII
    // character that was canonicalized to a dot.
    //
    // Brute-force search from the end by repeatedly canonicalizing longer
    // substrings until we get a match for the canonicalized version. This
    // can't be done with binary search because canonicalization might increase
    // or decrease the length of the produced string depending on where it's
    // split. This depends on the canonicalization process not changing the
    // order of the characters. Punycode can change the order of characters,
    // but it doesn't work across dots so this is safe.

    // Expected canonical registry controlled domain.
    std::string_view canonical_rcd(&canonical_host[canonical_rcd_begin],
                                   canonical_rcd_len);

    for (int current_try = static_cast<int>(mapping.original_end) - 1;
         current_try >= static_cast<int>(mapping.original_begin);
         current_try--) {
      std::string try_string;
      url::StdStringCanonOutput try_output(&try_string);

      if (!url::CanonicalizeHostSubstring(
              host.data(),
              url::Component(
                  current_try,
                  static_cast<int>(mapping.original_end) - current_try),
              &try_output))
        continue;  // Invalid substring, skip.

      try_output.Complete();
      if (try_string == canonical_rcd)
        return host.length() - current_try;
    }
  }

  NOTREACHED();
}

bool SameDomainOrHost(std::string_view host1,
                      std::string_view host2,
                      PrivateRegistryFilter filter) {
  // Quickly reject cases where either host is empty.
  if (host1.empty() || host2.empty())
    return false;

  // Check for exact host matches, which is faster than looking up the domain
  // and registry.
  if (host1 == host2)
    return true;

  // Check for a domain and registry match.
  std::string_view domain1 = GetDomainAndRegistryAsStringPiece(host1, filter);
  return !domain1.empty() &&
         (domain1 == GetDomainAndRegistryAsStringPiece(host2, filter));
}

}  // namespace

std::string GetDomainAndRegistry(const GURL& gurl,
                                 PrivateRegistryFilter filter) {
  return std::string(
      GetDomainAndRegistryAsStringPiece(gurl.host_piece(), filter));
}

std::string GetDomainAndRegistry(const url::Origin& origin,
                                 PrivateRegistryFilter filter) {
  return std::string(GetDomainAndRegistryAsStringPiece(origin.host(), filter));
}

std::string GetDomainAndRegistry(std::string_view host,
                                 PrivateRegistryFilter filter) {
  url::CanonHostInfo host_info;
  const std::string canon_host(CanonicalizeHost(host, &host_info));
  if (canon_host.empty() || host_info.IsIPAddress())
    return std::string();
  return std::string(GetDomainAndRegistryImpl(canon_host, filter));
}

std::string_view GetDomainAndRegistryAsStringPiece(
    const url::Origin& origin,
    PrivateRegistryFilter filter) {
  return GetDomainAndRegistryAsStringPiece(origin.host(), filter);
}

bool SameDomainOrHost(
    const GURL& gurl1,
    const GURL& gurl2,
    PrivateRegistryFilter filter) {
  return SameDomainOrHost(gurl1.host_piece(), gurl2.host_piece(), filter);
}

bool SameDomainOrHost(const url::Origin& origin1,
                      const url::Origin& origin2,
                      PrivateRegistryFilter filter) {
  return SameDomainOrHost(origin1.host(), origin2.host(), filter);
}

bool SameDomainOrHost(const url::Origin& origin1,
                      const std::optional<url::Origin>& origin2,
                      PrivateRegistryFilter filter) {
  return origin2.has_value() &&
         SameDomainOrHost(origin1, origin2.value(), filter);
}

bool SameDomainOrHost(const GURL& gurl,
                      const url::Origin& origin,
                      PrivateRegistryFilter filter) {
  return SameDomainOrHost(gurl.host_piece(), origin.host(), filter);
}

size_t GetRegistryLength(
    const GURL& gurl,
    UnknownRegistryFilter unknown_filter,
    PrivateRegistryFilter private_filter) {
  return GetRegistryLengthImpl(gurl.host_piece(), unknown_filter,
                               private_filter)
      .registry_length;
}

bool HostHasRegistryControlledDomain(std::string_view host,
                                     UnknownRegistryFilter unknown_filter,
                                     PrivateRegistryFilter private_filter) {
  url::CanonHostInfo host_info;
  const std::string canon_host(CanonicalizeHost(host, &host_info));

  size_t rcd_length;
  switch (host_info.family) {
    case url::CanonHostInfo::IPV4:
    case url::CanonHostInfo::IPV6:
      // IP addresses don't have R.C.D.'s.
      return false;
    case url::CanonHostInfo::BROKEN:
      // Host is not canonicalizable. Fall back to the slower "permissive"
      // version.
      rcd_length =
          PermissiveGetHostRegistryLength(host, unknown_filter, private_filter);
      break;
    case url::CanonHostInfo::NEUTRAL:
      rcd_length =
          GetRegistryLengthImpl(canon_host, unknown_filter, private_filter)
              .registry_length;
      break;
    default:
      NOTREACHED();
  }
  return (rcd_length != 0) && (rcd_length != std::string::npos);
}

bool HostIsRegistryIdentifier(std::string_view canon_host,
                              PrivateRegistryFilter private_filter) {
  // The input is expected to be a valid, canonicalized hostname (not an IP
  // address).
  CHECK(!canon_host.empty());
  url::CanonHostInfo host_info;
  std::string canonicalized = CanonicalizeHost(canon_host, &host_info);
  CHECK_EQ(canonicalized, canon_host);
  CHECK_EQ(host_info.family, url::CanonHostInfo::NEUTRAL);
  return GetRegistryLengthImpl(canon_host, EXCLUDE_UNKNOWN_REGISTRIES,
                               private_filter)
      .is_registry_identifier;
}

size_t GetCanonicalHostRegistryLength(std::string_view canon_host,
                                      UnknownRegistryFilter unknown_filter,
                                      PrivateRegistryFilter private_filter) {
#ifndef NDEBUG
  // Ensure passed-in host name is canonical.
  url::CanonHostInfo host_info;
  DCHECK_EQ(net::CanonicalizeHost(canon_host, &host_info), canon_host);
#endif

  return GetRegistryLengthImpl(canon_host, unknown_filter, private_filter)
      .registry_length;
}

size_t PermissiveGetHostRegistryLength(std::string_view host,
                                       UnknownRegistryFilter unknown_filter,
                                       PrivateRegistryFilter private_filter) {
  return DoPermissiveGetHostRegistryLength(host, unknown_filter,
                                           private_filter);
}

size_t PermissiveGetHostRegistryLength(std::u16string_view host,
                                       UnknownRegistryFilter unknown_filter,
                                       PrivateRegistryFilter private_filter) {
  return DoPermissiveGetHostRegistryLength(host, unknown_filter,
                                           private_filter);
}

void ResetFindDomainGraphForTesting() {
  g_graph = kDafsa;
}

void SetFindDomainGraphForTesting(base::span<const uint8_t> domains) {
  CHECK(!domains.empty());
  g_graph = domains;
}

}  // namespace net::registry_controlled_domains
```