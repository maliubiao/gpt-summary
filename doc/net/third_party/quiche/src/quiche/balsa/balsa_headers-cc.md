Response:
My thinking process to answer the request about `balsa_headers.cc` went something like this:

1. **Understand the Core Request:** The user wants to know the functionality of this specific Chromium source file (`balsa_headers.cc`) and its potential relationship to JavaScript. They also want examples of logic, common errors, debugging hints, and a summary of the functionality.

2. **Initial Code Scan and High-Level Interpretation:** I quickly scanned the code, noting the includes (`<string>`, `<vector>`, `absl/strings/...`, etc.), the namespace (`quiche`), and the class definition (`BalsaHeaders`). The presence of header-related constants like `kContentLength`, `kCookie`, and functions like `ParseTokenList`, `Clear`, `AddAndMakeDescription`, `GetHeader`, and `RemoveAllOfHeader` strongly suggested this file deals with HTTP header manipulation. The "balsa" prefix also hints at a lightweight or efficient approach.

3. **Break Down Functionality by Examining Key Methods:** I started focusing on the public methods of the `BalsaHeaders` class to deduce its responsibilities.

    * **Adding and Modifying Headers:**  Methods like `AddAndMakeDescription`, `AppendHeader`, `AppendToHeader`, `ReplaceOrAppendHeader` clearly indicate functionality for adding, appending, and replacing HTTP headers. The `MakeDescription` part suggests internal bookkeeping related to header storage.

    * **Retrieving Headers:**  `GetHeader`, `GetAllOfHeader`, `GetHeaderPosition`, `GetIteratorForKey` are used for retrieving header values, either a single value or multiple values for headers that can appear more than once.

    * **Removing Headers:**  `RemoveAllOfHeader`, `RemoveAllOfHeaderStartingAt`, `RemoveAllOfHeaderInList`, `RemoveAllHeadersWithPrefix`, `RemoveValue` provide ways to remove headers based on exact matches, starting points, lists of keys, prefixes, or specific values.

    * **Parsing:** `ParseTokenList` suggests handling comma-separated lists within header values.

    * **Internal Management:**  `Clear`, `CopyFrom` manage the internal state of the `BalsaHeaders` object. The `BalsaBuffer` member suggests an underlying buffer for storing header data efficiently.

    * **Special Header Handling:** The code explicitly checks for `Content-Length` and `Transfer-Encoding`, indicating special logic for these crucial headers.

    * **Envoy Compatibility:** The large `ALL_ENVOY_HEADERS` macro points to an attempt to maintain compatibility with how the Envoy proxy handles multi-valued headers.

4. **Relate to HTTP Concepts:** I connected the observed functionality to core HTTP concepts:

    * **Headers:** The fundamental unit of information being managed.
    * **Key-Value Pairs:**  The structure of HTTP headers.
    * **Multi-valued Headers:** Headers that can appear multiple times or have comma-separated values.
    * **Content-Length and Transfer-Encoding:** Essential for determining the size and format of the message body.

5. **Address the JavaScript Connection:**  I considered how JavaScript interacts with HTTP headers. JavaScript running in a browser or in Node.js can:

    * **Send HTTP Requests:**  Using `fetch` or `XMLHttpRequest`, JavaScript can set request headers.
    * **Receive HTTP Responses:**  The browser makes response headers available to JavaScript.
    * **Server-Side JavaScript (Node.js):**  Node.js can both send and receive requests and responses, manipulating headers directly.

    I made the connection that while this C++ code doesn't *directly* execute JavaScript, it's part of the network stack that handles the underlying details of HTTP communication, which JavaScript relies upon.

6. **Construct Examples (Hypothetical Input/Output):** I created simple scenarios to illustrate how some of the core methods might work. This involved imagining input header data and the expected output after calling specific `BalsaHeaders` methods.

7. **Identify Common Usage Errors:** I thought about how developers might misuse header manipulation functionality:

    * **Case Sensitivity:** Forgetting that headers are case-insensitive.
    * **Incorrectly Handling Multi-valued Headers:**  Trying to get a single value when multiple exist.
    * **Modifying Special Headers:**  Not understanding the implications of changing `Content-Length` or `Transfer-Encoding`.

8. **Provide Debugging Clues:**  I outlined the likely steps to reach this code during debugging within Chromium:

    * Starting with a network request.
    * Identifying where header parsing and manipulation might occur in the network stack.
    * Mentioning debugging tools like breakpoints and logging.

9. **Summarize the Functionality (Part 1):** I condensed the key capabilities of the code into a concise summary for the first part of the request.

10. **Iterative Refinement:** Throughout the process, I reread the code snippets and my explanations to ensure accuracy and clarity. I also checked for consistency and made sure I addressed all parts of the user's request. For example, I initially focused heavily on the individual methods, but then broadened my perspective to explain how they fit into the larger context of HTTP header handling within a networking stack. I also made sure to clearly separate the direct functionality of the C++ code from its relationship with JavaScript.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/balsa/balsa_headers.cc` 文件的第一部分，主要负责 **HTTP 头的存储、解析和操作**。

以下是该部分代码功能的归纳：

**核心功能：**

1. **HTTP 头的存储:**  `BalsaHeaders` 类使用 `BalsaBuffer` 来存储 HTTP 头部的原始数据，并使用 `HeaderLineDescription` 结构体来记录每个头部行的关键信息（起始位置、键的结束位置、值的起始位置、结束位置等）。
2. **HTTP 头的解析:** 提供 `ParseTokenList` 方法用于解析逗号分隔的头部值列表。虽然这部分代码本身不包含完整的 HTTP 头解析逻辑（例如解析状态行），但它提供了操作已解析头部的基础结构。
3. **HTTP 头的添加和修改:**
    * `AddAndMakeDescription`: 添加一个新的头部键值对，并在内部 `BalsaBuffer` 中分配空间存储。
    * `AppendHeader`:  追加一个新的头部键值对。
    * `AppendToHeader`: 如果头部已存在，则将新值追加到现有头部值的末尾 (通常用逗号分隔)。
    * `ReplaceOrAppendHeader`: 如果头部已存在，则替换所有同名头部，否则添加一个新的头部。
4. **HTTP 头的删除:**
    * `RemoveAllOfHeader`: 删除所有指定名称的头部。
    * `RemoveAllOfHeaderStartingAt`: 从指定的迭代器位置开始删除指定名称的头部。
    * `RemoveAllOfHeaderInList`: 删除列表中指定的所有头部。
    * `RemoveAllHeadersWithPrefix`: 删除所有具有指定前缀的头部。
    * `RemoveValue`: 从指定头部中移除特定的值。
5. **HTTP 头的获取:**
    * `GetHeader`: 获取指定名称的**第一个**头部的值 (注意，对于可能存在多个值的头部，应该使用 `GetAllOfHeader`)。
    * `GetAllOfHeader`: 获取指定名称的所有头部的值，并存储到 `std::vector<absl::string_view>` 中。
    * `GetAllOfHeaderIncludeRemoved`: 获取指定名称的所有头部的值，包括已标记为删除的头部。
    * `GetAllOfHeaderAsString`: 获取指定名称的所有头部的值，并将它们连接成一个逗号分隔的字符串。
    * `GetAllOfHeaderWithPrefix`: 获取所有具有指定前缀的头部及其值。
    * `GetAllHeadersWithLimit`: 获取所有头部及其值，但限制返回的数量。
    * `GetHeaderPosition`: 获取指定名称的第一个头部的迭代器。
    * `GetIteratorForKey`: 获取指定名称的第一个头部的键值对迭代器。
6. **HTTP 头的检查:**
    * `HeaderHasValueHelper`: 检查指定头部是否包含特定的值（可以区分大小写）。
    * `HasNonEmptyHeader`: 检查是否存在指定名称且值不为空的头部。
    * `HasHeadersWithPrefix`: 检查是否存在具有指定前缀的头部。
7. **内部状态管理:**
    * `Clear`: 清空所有头部信息。
    * `CopyFrom`: 从另一个 `BalsaHeaders` 对象复制头部信息。
    * `MaybeClearSpecialHeaderValues`: 在删除头部时，根据头部名称清除相关的内部状态，例如 `Content-Length` 和 `Transfer-Encoding`。
8. **与 Envoy 的兼容性:**  定义了一个 `multivalued_envoy_headers` 静态成员，包含 Envoy 认为可以有多个值的头部列表。这表明该代码旨在与 Envoy 的行为保持一致，以便在某些场景下可以互操作。
9. **实用工具函数:** 提供了一些内部使用的实用工具函数，例如 `FindIgnoreCase` (忽略大小写查找字符串)， `RemoveLeadingWhitespace`， `RemoveTrailingWhitespace`， `RemoveWhitespaceContext` (移除字符串周围的空格)。

**与 JavaScript 的关系：**

该 C++ 代码本身**不直接**与 JavaScript 执行有关。然而，它在 Chromium 的网络栈中扮演着关键角色，负责处理 HTTP 协议的底层细节，而 JavaScript 代码（尤其是在浏览器环境中）会通过浏览器提供的 API (例如 `fetch` 或 `XMLHttpRequest`) 与 HTTP 进行交互。

**举例说明：**

假设一个 JavaScript 代码发起了一个 HTTP 请求，并设置了一些请求头：

```javascript
fetch('https://example.com', {
  headers: {
    'Content-Type': 'application/json',
    'X-Custom-Header': 'some value',
    'Cookie': 'sessionid=12345'
  }
});
```

当 Chromium 的网络栈处理这个请求时，`balsa_headers.cc` 中的代码会被用来存储和操作这些请求头。例如，`AddAndMakeDescription` 可能会被调用来添加 `Content-Type`， `X-Custom-Header` 和 `Cookie` 这几个头部到内部的存储结构中。

类似地，当接收到 HTTP 响应时，`balsa_headers.cc` 中的代码会被用来解析和存储响应头。JavaScript 可以通过浏览器的 API 访问这些响应头，例如：

```javascript
fetch('https://example.com')
  .then(response => {
    console.log(response.headers.get('Content-Type')); // 获取 Content-Type 响应头
    console.log(response.headers.get('Set-Cookie')); // 获取 Set-Cookie 响应头
  });
```

在这个过程中，`balsa_headers.cc` 中的 `GetHeader` 或 `GetAllOfHeader` 等方法可能会被间接调用，以提供 JavaScript 代码所需的头部信息。

**逻辑推理的假设输入与输出：**

假设输入以下 HTTP 头部：

```
Content-Type: text/plain
Accept-Language: en-US,zh-CN
User-Agent: Chrome/114.0.0.0
Accept-Encoding: gzip, deflate
```

调用 `GetAllOfHeader("Accept-Language", &output)`  后，`output` 应该包含 `{"en-US", "zh-CN"}`。

调用 `GetHeader("User-Agent")` 应该返回 `"Chrome/114.0.0.0"`。

调用 `RemoveAllOfHeader("Accept-Encoding")` 后，再次获取所有头部时，将不再包含 `Accept-Encoding` 头部。

调用 `AppendToHeader("Accept-Language", "ko-KR")` 后，再次获取 `Accept-Language` 头部，可能得到 `{"en-US,zh-CN", "ko-KR"}` (具体取决于内部实现是否会合并多行同名头部)。

**用户或编程常见的使用错误：**

1. **错误地使用 `GetHeader` 处理多值头部:**  如果一个头部可能出现多次（例如 `Set-Cookie`），使用 `GetHeader` 只会返回第一个出现的值，导致信息丢失。应该使用 `GetAllOfHeader` 来获取所有值。
   ```c++
   // 错误示例：对于 Set-Cookie 头部
   absl::string_view cookie = headers.GetHeader("Set-Cookie"); // 可能只获取到第一个 Cookie
   ```
   ```c++
   // 正确示例：
   std::vector<absl::string_view> cookies;
   headers.GetAllOfHeader("Set-Cookie", &cookies); // 获取所有 Cookie
   ```

2. **大小写敏感性混淆:** HTTP 头部名称是大小写不敏感的，但值通常是大小写敏感的。在比较或查找头部时，应该使用忽略大小写的比较函数，例如 `absl::EqualsIgnoreCase`。

3. **修改特殊头部时的不当处理:**  直接修改 `Content-Length` 或 `Transfer-Encoding` 头部可能会导致 HTTP 消息格式错误，引起解析问题。应该谨慎处理这些头部。

4. **忘记调用 `Clear()` 清理头部:** 在重用 `BalsaHeaders` 对象时，忘记调用 `Clear()` 会导致旧的头部信息残留。

**用户操作是如何一步步的到达这里，作为调试线索：**

作为一个 Chromium 的开发者，当你调试网络相关的代码时，可能会因为以下原因进入 `balsa_headers.cc`：

1. **网络请求/响应解析错误:**  当你发现一个网络请求或响应的头部解析出现问题（例如，头部信息丢失、值不正确等），你可能会设置断点在 `BalsaHeaders` 相关的代码中，例如 `AddAndMakeDescription` 或 `GetHeader`，来查看头部的存储和获取过程。

2. **性能瓶颈分析:** 如果你怀疑 HTTP 头的处理是网络性能的瓶颈，你可能会使用性能分析工具来查看 `BalsaHeaders` 中哪些方法被频繁调用，并分析其性能开销。

3. **实现新的网络特性:**  当你开发需要处理特定 HTTP 头的新功能时，你可能会直接修改或扩展 `BalsaHeaders` 的功能。

4. **排查与其他网络组件的交互问题:**  `BalsaHeaders` 是网络栈中一个核心的组件，它与其他组件（例如 HTTP 流处理、QUIC 实现等）密切交互。当你排查这些组件之间的交互问题时，可能会需要跟踪头部信息的传递和修改过程，从而进入 `balsa_headers.cc`。

**调试步骤示例:**

1. 用户在浏览器中访问一个网页。
2. 浏览器发起一个 HTTP 请求。
3. Chromium 的网络栈开始处理这个请求。
4. 请求头被解析并存储到 `BalsaHeaders` 对象中。
5. 如果你设置了断点在 `balsa_headers.cc` 的 `AddAndMakeDescription` 函数中，当处理到请求头时，程序会停在这里。你可以查看当前正在处理的头部名称和值，以及 `BalsaHeaders` 对象的内部状态。
6. 如果响应返回，响应头也会被解析并存储到 `BalsaHeaders` 对象中。你可以在 `GetHeader` 或 `GetAllOfHeader` 等函数中设置断点，查看 JavaScript 代码尝试获取头部信息时，`BalsaHeaders` 中存储的值是否正确。

**归纳一下它的功能 (第 1 部分):**

总而言之，`net/third_party/quiche/src/quiche/balsa/balsa_headers.cc` 的第一部分主要定义了 `BalsaHeaders` 类，该类是 Chromium 网络栈中用于**高效存储、解析、操作和管理 HTTP 头部**的核心组件。它提供了添加、删除、修改和检索 HTTP 头的各种方法，并考虑了与 Envoy 的兼容性。虽然它本身不直接执行 JavaScript，但它是 JavaScript 通过浏览器 API 进行 HTTP 通信的基础。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/balsa/balsa_headers.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/balsa/balsa_headers.h"

#include <sys/types.h>

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "quiche/balsa/balsa_enums.h"
#include "quiche/balsa/header_properties.h"
#include "quiche/common/platform/api/quiche_header_policy.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace {

constexpr absl::string_view kContentLength("Content-Length");
constexpr absl::string_view kCookie("Cookie");
constexpr absl::string_view kHost("Host");
constexpr absl::string_view kTransferEncoding("Transfer-Encoding");

// The following list defines list of headers that Envoy considers multivalue.
// Headers on this list are coalesced by EFG in order to provide forward
// compatibility with Envoy behavior. See b/143490671 for details.
// Date, Last-Modified and Location are excluded because they're found on Chrome
// HttpUtil::IsNonCoalescingHeader() list.
#define ALL_ENVOY_HEADERS(HEADER_FUNC)                    \
  HEADER_FUNC("Accept")                                   \
  HEADER_FUNC("Accept-Encoding")                          \
  HEADER_FUNC("Access-Control-Request-Headers")           \
  HEADER_FUNC("Access-Control-Request-Method")            \
  HEADER_FUNC("Access-Control-Allow-Origin")              \
  HEADER_FUNC("Access-Control-Allow-Headers")             \
  HEADER_FUNC("Access-Control-Allow-Methods")             \
  HEADER_FUNC("Access-Control-Allow-Credentials")         \
  HEADER_FUNC("Access-Control-Expose-Headers")            \
  HEADER_FUNC("Access-Control-Max-Age")                   \
  HEADER_FUNC("Authorization")                            \
  HEADER_FUNC("Cache-Control")                            \
  HEADER_FUNC("X-Client-Trace-Id")                        \
  HEADER_FUNC("Connection")                               \
  HEADER_FUNC("Content-Encoding")                         \
  HEADER_FUNC("Content-Length")                           \
  HEADER_FUNC("Content-Type")                             \
  /* HEADER_FUNC("Date") */                               \
  HEADER_FUNC("Envoy-Attempt-Count")                      \
  HEADER_FUNC("Envoy-Degraded")                           \
  HEADER_FUNC("Envoy-Decorator-Operation")                \
  HEADER_FUNC("Envoy-Downstream-Service-Cluster")         \
  HEADER_FUNC("Envoy-Downstream-Service-Node")            \
  HEADER_FUNC("Envoy-Expected-Request-Timeout-Ms")        \
  HEADER_FUNC("Envoy-External-Address")                   \
  HEADER_FUNC("Envoy-Force-Trace")                        \
  HEADER_FUNC("Envoy-Hedge-On-Per-Try-Timeout")           \
  HEADER_FUNC("Envoy-Immediate-Health-Check-Fail")        \
  HEADER_FUNC("Envoy-Internal-Request")                   \
  HEADER_FUNC("Envoy-Ip-Tags")                            \
  HEADER_FUNC("Envoy-Max-Retries")                        \
  HEADER_FUNC("Envoy-Original-Path")                      \
  HEADER_FUNC("Envoy-Original-Url")                       \
  HEADER_FUNC("Envoy-Overloaded")                         \
  HEADER_FUNC("Envoy-Rate-Limited")                       \
  HEADER_FUNC("Envoy-Retry-On")                           \
  HEADER_FUNC("Envoy-Retry-Grpc-On")                      \
  HEADER_FUNC("Envoy-Retriable-StatusCodes")              \
  HEADER_FUNC("Envoy-Retriable-HeaderNames")              \
  HEADER_FUNC("Envoy-Upstream-AltStatName")               \
  HEADER_FUNC("Envoy-Upstream-Canary")                    \
  HEADER_FUNC("Envoy-Upstream-HealthCheckedCluster")      \
  HEADER_FUNC("Envoy-Upstream-RequestPerTryTimeoutMs")    \
  HEADER_FUNC("Envoy-Upstream-RequestTimeoutAltResponse") \
  HEADER_FUNC("Envoy-Upstream-RequestTimeoutMs")          \
  HEADER_FUNC("Envoy-Upstream-ServiceTime")               \
  HEADER_FUNC("Etag")                                     \
  HEADER_FUNC("Expect")                                   \
  HEADER_FUNC("X-Forwarded-Client-Cert")                  \
  HEADER_FUNC("X-Forwarded-For")                          \
  HEADER_FUNC("X-Forwarded-Proto")                        \
  HEADER_FUNC("Grpc-Accept-Encoding")                     \
  HEADER_FUNC("Grpc-Message")                             \
  HEADER_FUNC("Grpc-Status")                              \
  HEADER_FUNC("Grpc-Timeout")                             \
  HEADER_FUNC("Host")                                     \
  HEADER_FUNC("Keep-Alive")                               \
  /* HEADER_FUNC("Last-Modified") */                      \
  /* HEADER_FUNC("Location") */                           \
  HEADER_FUNC("Method")                                   \
  HEADER_FUNC("No-Chunks")                                \
  HEADER_FUNC("Origin")                                   \
  HEADER_FUNC("X-Ot-Span-Context")                        \
  HEADER_FUNC("Path")                                     \
  HEADER_FUNC("Protocol")                                 \
  HEADER_FUNC("Proxy-Connection")                         \
  HEADER_FUNC("Referer")                                  \
  HEADER_FUNC("X-Request-Id")                             \
  HEADER_FUNC("Scheme")                                   \
  HEADER_FUNC("Server")                                   \
  HEADER_FUNC("Status")                                   \
  HEADER_FUNC("TE")                                       \
  HEADER_FUNC("Transfer-Encoding")                        \
  HEADER_FUNC("Upgrade")                                  \
  HEADER_FUNC("User-Agent")                               \
  HEADER_FUNC("Vary")                                     \
  HEADER_FUNC("Via")

// HEADER_FUNC to insert "name" into the MultivaluedHeadersSet of Envoy headers.
#define MULTIVALUE_ENVOY_HEADER(name) {name},

absl::string_view::difference_type FindIgnoreCase(absl::string_view haystack,
                                                  absl::string_view needle) {
  absl::string_view::difference_type pos = 0;
  while (haystack.size() >= needle.size()) {
    if (absl::StartsWithIgnoreCase(haystack, needle)) {
      return pos;
    }
    ++pos;
    haystack.remove_prefix(1);
  }

  return absl::string_view::npos;
}

absl::string_view::difference_type RemoveLeadingWhitespace(
    absl::string_view* text) {
  size_t count = 0;
  const char* ptr = text->data();
  while (count < text->size() && absl::ascii_isspace(*ptr)) {
    count++;
    ptr++;
  }
  text->remove_prefix(count);
  return count;
}

absl::string_view::difference_type RemoveTrailingWhitespace(
    absl::string_view* text) {
  size_t count = 0;
  const char* ptr = text->data() + text->size() - 1;
  while (count < text->size() && absl::ascii_isspace(*ptr)) {
    ++count;
    --ptr;
  }
  text->remove_suffix(count);
  return count;
}

absl::string_view::difference_type RemoveWhitespaceContext(
    absl::string_view* text) {
  return RemoveLeadingWhitespace(text) + RemoveTrailingWhitespace(text);
}

}  // namespace

namespace quiche {

const size_t BalsaBuffer::kDefaultBlocksize;

const BalsaHeaders::MultivaluedHeadersSet&
BalsaHeaders::multivalued_envoy_headers() {
  static const MultivaluedHeadersSet* multivalued_envoy_headers =
      new MultivaluedHeadersSet({ALL_ENVOY_HEADERS(MULTIVALUE_ENVOY_HEADER)});
  return *multivalued_envoy_headers;
}

void BalsaHeaders::ParseTokenList(absl::string_view header_value,
                                  HeaderTokenList* tokens) {
  if (header_value.empty()) {
    return;
  }
  const char* start = header_value.data();
  const char* end = header_value.data() + header_value.size();
  while (true) {
    // Cast `*start` to unsigned char to make values above 127 rank as expected
    // on platforms with signed char, where such values are represented as
    // negative numbers before the cast.

    // search for first nonwhitespace, non separator char.
    while (*start == ',' || static_cast<unsigned char>(*start) <= ' ') {
      ++start;
      if (start == end) {
        return;
      }
    }
    // found. marked.
    const char* nws = start;

    // search for next whitspace or separator char.
    while (*start != ',' && static_cast<unsigned char>(*start) > ' ') {
      ++start;
      if (start == end) {
        if (nws != start) {
          tokens->push_back(absl::string_view(nws, start - nws));
        }
        return;
      }
    }
    tokens->push_back(absl::string_view(nws, start - nws));
  }
}

// This can be called after a std::move() operation, so things might be
// in an unspecified state after the move.
void BalsaHeaders::Clear() {
  balsa_buffer_.Clear();
  transfer_encoding_is_chunked_ = false;
  content_length_ = 0;
  content_length_status_ = BalsaHeadersEnums::NO_CONTENT_LENGTH;
  parsed_response_code_ = 0;
  firstline_buffer_base_idx_ = 0;
  whitespace_1_idx_ = 0;
  non_whitespace_1_idx_ = 0;
  whitespace_2_idx_ = 0;
  non_whitespace_2_idx_ = 0;
  whitespace_3_idx_ = 0;
  non_whitespace_3_idx_ = 0;
  whitespace_4_idx_ = 0;
  header_lines_.clear();
  header_lines_.shrink_to_fit();
}

void BalsaHeaders::CopyFrom(const BalsaHeaders& other) {
  // Protect against copying with self.
  if (this == &other) {
    return;
  }

  balsa_buffer_.CopyFrom(other.balsa_buffer_);
  transfer_encoding_is_chunked_ = other.transfer_encoding_is_chunked_;
  content_length_ = other.content_length_;
  content_length_status_ = other.content_length_status_;
  parsed_response_code_ = other.parsed_response_code_;
  firstline_buffer_base_idx_ = other.firstline_buffer_base_idx_;
  whitespace_1_idx_ = other.whitespace_1_idx_;
  non_whitespace_1_idx_ = other.non_whitespace_1_idx_;
  whitespace_2_idx_ = other.whitespace_2_idx_;
  non_whitespace_2_idx_ = other.non_whitespace_2_idx_;
  whitespace_3_idx_ = other.whitespace_3_idx_;
  non_whitespace_3_idx_ = other.non_whitespace_3_idx_;
  whitespace_4_idx_ = other.whitespace_4_idx_;
  header_lines_ = other.header_lines_;
}

void BalsaHeaders::AddAndMakeDescription(absl::string_view key,
                                         absl::string_view value,
                                         HeaderLineDescription* d) {
  QUICHE_CHECK(d != nullptr);

  if (enforce_header_policy_) {
    QuicheHandleHeaderPolicy(key);
  }

  // + 2 to size for ": "
  size_t line_size = key.size() + 2 + value.size();
  BalsaBuffer::Blocks::size_type block_buffer_idx = 0;
  char* storage = balsa_buffer_.Reserve(line_size, &block_buffer_idx);
  size_t base_idx = storage - GetPtr(block_buffer_idx);

  char* cur_loc = storage;
  memcpy(cur_loc, key.data(), key.size());
  cur_loc += key.size();
  *cur_loc = ':';
  ++cur_loc;
  *cur_loc = ' ';
  ++cur_loc;
  memcpy(cur_loc, value.data(), value.size());
  *d = HeaderLineDescription(
      base_idx, base_idx + key.size(), base_idx + key.size() + 2,
      base_idx + key.size() + 2 + value.size(), block_buffer_idx);
}

void BalsaHeaders::AppendAndMakeDescription(absl::string_view key,
                                            absl::string_view value,
                                            HeaderLineDescription* d) {
  // Figure out how much space we need to reserve for the new header size.
  size_t old_value_size = d->last_char_idx - d->value_begin_idx;
  if (old_value_size == 0) {
    AddAndMakeDescription(key, value, d);
    return;
  }
  absl::string_view old_value(GetPtr(d->buffer_base_idx) + d->value_begin_idx,
                              old_value_size);

  BalsaBuffer::Blocks::size_type block_buffer_idx = 0;
  // + 3 because we potentially need to add ": ", and "," to the line.
  size_t new_size = key.size() + 3 + old_value_size + value.size();
  char* storage = balsa_buffer_.Reserve(new_size, &block_buffer_idx);
  size_t base_idx = storage - GetPtr(block_buffer_idx);

  absl::string_view first_value = old_value;
  absl::string_view second_value = value;
  char* cur_loc = storage;
  memcpy(cur_loc, key.data(), key.size());
  cur_loc += key.size();
  *cur_loc = ':';
  ++cur_loc;
  *cur_loc = ' ';
  ++cur_loc;
  memcpy(cur_loc, first_value.data(), first_value.size());
  cur_loc += first_value.size();
  *cur_loc = ',';
  ++cur_loc;
  memcpy(cur_loc, second_value.data(), second_value.size());

  *d = HeaderLineDescription(base_idx, base_idx + key.size(),
                             base_idx + key.size() + 2, base_idx + new_size,
                             block_buffer_idx);
}

// Reset internal flags for chunked transfer encoding or content length if a
// header we're removing is one of those headers.
void BalsaHeaders::MaybeClearSpecialHeaderValues(absl::string_view key) {
  if (absl::EqualsIgnoreCase(key, kContentLength)) {
    if (transfer_encoding_is_chunked_) {
      return;
    }

    content_length_status_ = BalsaHeadersEnums::NO_CONTENT_LENGTH;
    content_length_ = 0;
    return;
  }

  if (absl::EqualsIgnoreCase(key, kTransferEncoding)) {
    transfer_encoding_is_chunked_ = false;
  }
}

// Removes all keys value pairs with key 'key' starting at 'start'.
void BalsaHeaders::RemoveAllOfHeaderStartingAt(absl::string_view key,
                                               HeaderLines::iterator start) {
  MaybeClearSpecialHeaderValues(key);
  while (start != header_lines_.end()) {
    start->skip = true;
    ++start;
    start = GetHeaderLinesIterator(key, start);
  }
}

void BalsaHeaders::ReplaceOrAppendHeader(absl::string_view key,
                                         absl::string_view value) {
  const HeaderLines::iterator end = header_lines_.end();
  const HeaderLines::iterator begin = header_lines_.begin();
  HeaderLines::iterator i = GetHeaderLinesIterator(key, begin);
  if (i != end) {
    // First, remove all of the header lines including this one.  We want to
    // remove before replacing, in case our replacement ends up being appended
    // at the end (and thus would be removed by this call)
    RemoveAllOfHeaderStartingAt(key, i);
    // Now, take the first instance and replace it.  This will remove the
    // 'skipped' tag if the replacement is done in-place.
    AddAndMakeDescription(key, value, &(*i));
    return;
  }
  AppendHeader(key, value);
}

void BalsaHeaders::AppendHeader(absl::string_view key,
                                absl::string_view value) {
  HeaderLineDescription hld;
  AddAndMakeDescription(key, value, &hld);
  header_lines_.push_back(hld);
}

void BalsaHeaders::AppendToHeader(absl::string_view key,
                                  absl::string_view value) {
  HeaderLines::iterator i = GetHeaderLinesIterator(key, header_lines_.begin());
  if (i == header_lines_.end()) {
    // The header did not exist already.  Instead of appending to an existing
    // header simply append the key/value pair to the headers.
    AppendHeader(key, value);
    return;
  }
  HeaderLineDescription hld = *i;

  AppendAndMakeDescription(key, value, &hld);

  // Invalidate the old header line and add the new one.
  i->skip = true;
  header_lines_.push_back(hld);
}

void BalsaHeaders::AppendToHeaderWithCommaAndSpace(absl::string_view key,
                                                   absl::string_view value) {
  HeaderLines::iterator i = GetHeaderLinesIteratorForLastMultivaluedHeader(key);
  if (i == header_lines_.end()) {
    // The header did not exist already. Instead of appending to an existing
    // header simply append the key/value pair to the headers. No extra
    // space will be added before the value.
    AppendHeader(key, value);
    return;
  }

  std::string space_and_value = absl::StrCat(" ", value);

  HeaderLineDescription hld = *i;
  AppendAndMakeDescription(key, space_and_value, &hld);

  // Invalidate the old header line and add the new one.
  i->skip = true;
  header_lines_.push_back(hld);
}

absl::string_view BalsaHeaders::GetValueFromHeaderLineDescription(
    const HeaderLineDescription& line) const {
  QUICHE_DCHECK_GE(line.last_char_idx, line.value_begin_idx);
  return absl::string_view(GetPtr(line.buffer_base_idx) + line.value_begin_idx,
                           line.last_char_idx - line.value_begin_idx);
}

absl::string_view BalsaHeaders::GetHeader(absl::string_view key) const {
  QUICHE_DCHECK(!header_properties::IsMultivaluedHeader(key))
      << "Header '" << key << "' may consist of multiple lines. Do not "
      << "use BalsaHeaders::GetHeader() or you may be missing some of its "
      << "values.";
  const HeaderLines::const_iterator end = header_lines_.end();
  HeaderLines::const_iterator i = GetConstHeaderLinesIterator(key);
  if (i == end) {
    return absl::string_view();
  }
  return GetValueFromHeaderLineDescription(*i);
}

BalsaHeaders::const_header_lines_iterator BalsaHeaders::GetHeaderPosition(
    absl::string_view key) const {
  const HeaderLines::const_iterator end = header_lines_.end();
  HeaderLines::const_iterator i = GetConstHeaderLinesIterator(key);
  if (i == end) {
    // TODO(tgreer) Convert from HeaderLines::const_iterator to
    // const_header_lines_iterator without calling lines().end(), which is
    // nontrivial. Look for other needless calls to lines().end(), or make
    // lines().end() trivial.
    return lines().end();
  }

  return const_header_lines_iterator(this, (i - header_lines_.begin()));
}

BalsaHeaders::const_header_lines_key_iterator BalsaHeaders::GetIteratorForKey(
    absl::string_view key) const {
  HeaderLines::const_iterator i = GetConstHeaderLinesIterator(key);
  if (i == header_lines_.end()) {
    return header_lines_key_end();
  }

  return const_header_lines_key_iterator(this, (i - header_lines_.begin()),
                                         key);
}

BalsaHeaders::HeaderLines::const_iterator
BalsaHeaders::GetConstHeaderLinesIterator(absl::string_view key) const {
  const HeaderLines::const_iterator end = header_lines_.end();
  for (HeaderLines::const_iterator i = header_lines_.begin(); i != end; ++i) {
    const HeaderLineDescription& line = *i;
    if (line.skip) {
      continue;
    }
    const absl::string_view current_key(
        GetPtr(line.buffer_base_idx) + line.first_char_idx,
        line.key_end_idx - line.first_char_idx);
    if (absl::EqualsIgnoreCase(current_key, key)) {
      QUICHE_DCHECK_GE(line.last_char_idx, line.value_begin_idx);
      return i;
    }
  }
  return end;
}

BalsaHeaders::HeaderLines::iterator BalsaHeaders::GetHeaderLinesIterator(
    absl::string_view key, BalsaHeaders::HeaderLines::iterator start) {
  const HeaderLines::iterator end = header_lines_.end();
  for (HeaderLines::iterator i = start; i != end; ++i) {
    const HeaderLineDescription& line = *i;
    if (line.skip) {
      continue;
    }
    const absl::string_view current_key(
        GetPtr(line.buffer_base_idx) + line.first_char_idx,
        line.key_end_idx - line.first_char_idx);
    if (absl::EqualsIgnoreCase(current_key, key)) {
      QUICHE_DCHECK_GE(line.last_char_idx, line.value_begin_idx);
      return i;
    }
  }
  return end;
}

BalsaHeaders::HeaderLines::iterator
BalsaHeaders::GetHeaderLinesIteratorForLastMultivaluedHeader(
    absl::string_view key) {
  const HeaderLines::iterator end = header_lines_.end();
  HeaderLines::iterator last_found_match;
  bool found_a_match = false;
  for (HeaderLines::iterator i = header_lines_.begin(); i != end; ++i) {
    const HeaderLineDescription& line = *i;
    if (line.skip) {
      continue;
    }
    const absl::string_view current_key(
        GetPtr(line.buffer_base_idx) + line.first_char_idx,
        line.key_end_idx - line.first_char_idx);
    if (absl::EqualsIgnoreCase(current_key, key)) {
      QUICHE_DCHECK_GE(line.last_char_idx, line.value_begin_idx);
      last_found_match = i;
      found_a_match = true;
    }
  }
  return (found_a_match ? last_found_match : end);
}

void BalsaHeaders::GetAllOfHeader(absl::string_view key,
                                  std::vector<absl::string_view>* out) const {
  for (const_header_lines_key_iterator it = GetIteratorForKey(key);
       it != lines().end(); ++it) {
    out->push_back(it->second);
  }
}

void BalsaHeaders::GetAllOfHeaderIncludeRemoved(
    absl::string_view key, std::vector<absl::string_view>* out) const {
  const HeaderLines::const_iterator begin = header_lines_.begin();
  const HeaderLines::const_iterator end = header_lines_.end();
  for (bool add_removed : {false, true}) {
    for (HeaderLines::const_iterator i = begin; i != end; ++i) {
      const HeaderLineDescription& line = *i;
      if ((!add_removed && line.skip) || (add_removed && !line.skip)) {
        continue;
      }
      const absl::string_view current_key(
          GetPtr(line.buffer_base_idx) + line.first_char_idx,
          line.key_end_idx - line.first_char_idx);
      if (absl::EqualsIgnoreCase(current_key, key)) {
        QUICHE_DCHECK_GE(line.last_char_idx, line.value_begin_idx);
        out->push_back(GetValueFromHeaderLineDescription(line));
      }
    }
  }
}

namespace {

// Helper function for HeaderHasValue that checks that the specified region
// within line is preceded by whitespace and a comma or beginning of line,
// and followed by whitespace and a comma or end of line.
bool SurroundedOnlyBySpacesAndCommas(absl::string_view::difference_type idx,
                                     absl::string_view::difference_type end_idx,
                                     absl::string_view line) {
  for (idx = idx - 1; idx >= 0; --idx) {
    if (line[idx] == ',') {
      break;
    }
    if (line[idx] != ' ') {
      return false;
    }
  }

  for (; end_idx < static_cast<int64_t>(line.size()); ++end_idx) {
    if (line[end_idx] == ',') {
      break;
    }
    if (line[end_idx] != ' ') {
      return false;
    }
  }
  return true;
}

}  // namespace

bool BalsaHeaders::HeaderHasValueHelper(absl::string_view key,
                                        absl::string_view value,
                                        bool case_sensitive) const {
  for (const_header_lines_key_iterator it = GetIteratorForKey(key);
       it != lines().end(); ++it) {
    absl::string_view line = it->second;
    absl::string_view::size_type idx =
        case_sensitive ? line.find(value, 0) : FindIgnoreCase(line, value);
    while (idx != absl::string_view::npos) {
      absl::string_view::difference_type end_idx = idx + value.size();
      if (SurroundedOnlyBySpacesAndCommas(idx, end_idx, line)) {
        return true;
      }
      idx = line.find(value, idx + 1);
    }
  }
  return false;
}

bool BalsaHeaders::HasNonEmptyHeader(absl::string_view key) const {
  for (const_header_lines_key_iterator it = GetIteratorForKey(key);
       it != header_lines_key_end(); ++it) {
    if (!it->second.empty()) {
      return true;
    }
  }
  return false;
}

std::string BalsaHeaders::GetAllOfHeaderAsString(absl::string_view key) const {
  // Use custom formatter to ignore header key and join only header values.
  // absl::AlphaNumFormatter is the default formatter for absl::StrJoin().
  auto formatter = [](std::string* out,
                      std::pair<absl::string_view, absl::string_view> header) {
    return absl::AlphaNumFormatter()(out, header.second);
  };
  return absl::StrJoin(GetIteratorForKey(key), header_lines_key_end(), ",",
                       formatter);
}

void BalsaHeaders::RemoveAllOfHeaderInList(const HeaderTokenList& keys) {
  if (keys.empty()) {
    return;
  }

  // This extra copy sacrifices some performance to prevent the possible
  // mistakes that the caller does not lower case the headers in keys.
  // Better performance can be achieved by asking caller to lower case
  // the keys and RemoveAllOfheaderInlist just does lookup.
  absl::flat_hash_set<std::string> lowercase_keys;
  lowercase_keys.reserve(keys.size());
  for (const auto& key : keys) {
    MaybeClearSpecialHeaderValues(key);
    lowercase_keys.insert(absl::AsciiStrToLower(key));
  }

  for (HeaderLineDescription& line : header_lines_) {
    if (line.skip) {
      continue;
    }
    // Remove the header if it matches any of the keys to remove.
    const size_t key_len = line.key_end_idx - line.first_char_idx;
    absl::string_view key(GetPtr(line.buffer_base_idx) + line.first_char_idx,
                          key_len);

    std::string lowercase_key = absl::AsciiStrToLower(key);
    if (lowercase_keys.count(lowercase_key) != 0) {
      line.skip = true;
    }
  }
}

void BalsaHeaders::RemoveAllOfHeader(absl::string_view key) {
  HeaderLines::iterator it = GetHeaderLinesIterator(key, header_lines_.begin());
  RemoveAllOfHeaderStartingAt(key, it);
}

void BalsaHeaders::RemoveAllHeadersWithPrefix(absl::string_view prefix) {
  for (HeaderLines::size_type i = 0; i < header_lines_.size(); ++i) {
    if (header_lines_[i].skip) {
      continue;
    }

    HeaderLineDescription& line = header_lines_[i];
    const size_t key_len = line.key_end_idx - line.first_char_idx;
    if (key_len < prefix.size()) {
      continue;
    }

    const absl::string_view current_key_prefix(
        GetPtr(line.buffer_base_idx) + line.first_char_idx, prefix.size());
    if (absl::EqualsIgnoreCase(current_key_prefix, prefix)) {
      const absl::string_view current_key(
          GetPtr(line.buffer_base_idx) + line.first_char_idx, key_len);
      MaybeClearSpecialHeaderValues(current_key);
      line.skip = true;
    }
  }
}

bool BalsaHeaders::HasHeadersWithPrefix(absl::string_view prefix) const {
  for (HeaderLines::size_type i = 0; i < header_lines_.size(); ++i) {
    if (header_lines_[i].skip) {
      continue;
    }

    const HeaderLineDescription& line = header_lines_[i];
    if (line.key_end_idx - line.first_char_idx < prefix.size()) {
      continue;
    }

    const absl::string_view current_key_prefix(
        GetPtr(line.buffer_base_idx) + line.first_char_idx, prefix.size());
    if (absl::EqualsIgnoreCase(current_key_prefix, prefix)) {
      return true;
    }
  }
  return false;
}

void BalsaHeaders::GetAllOfHeaderWithPrefix(
    absl::string_view prefix,
    std::vector<std::pair<absl::string_view, absl::string_view>>* out) const {
  for (HeaderLines::size_type i = 0; i < header_lines_.size(); ++i) {
    if (header_lines_[i].skip) {
      continue;
    }
    const HeaderLineDescription& line = header_lines_[i];
    absl::string_view key(GetPtr(line.buffer_base_idx) + line.first_char_idx,
                          line.key_end_idx - line.first_char_idx);
    if (absl::StartsWithIgnoreCase(key, prefix)) {
      out->push_back(std::make_pair(
          key,
          absl::string_view(GetPtr(line.buffer_base_idx) + line.value_begin_idx,
                            line.last_char_idx - line.value_begin_idx)));
    }
  }
}

void BalsaHeaders::GetAllHeadersWithLimit(
    std::vector<std::pair<absl::string_view, absl::string_view>>* out,
    int limit) const {
  for (HeaderLines::size_type i = 0; i < header_lines_.size(); ++i) {
    if (limit >= 0 && out->size() >= static_cast<size_t>(limit)) {
      return;
    }
    if (header_lines_[i].skip) {
      continue;
    }
    const HeaderLineDescription& line = header_lines_[i];
    absl::string_view key(GetPtr(line.buffer_base_idx) + line.first_char_idx,
                          line.key_end_idx - line.first_char_idx);
    out->push_back(std::make_pair(
        key,
        absl::string_view(GetPtr(line.buffer_base_idx) + line.value_begin_idx,
                          line.last_char_idx - line.value_begin_idx)));
  }
}

size_t BalsaHeaders::RemoveValue(absl::string_view key,
                                 absl::string_view search_value) {
  // Remove whitespace around search value.
  absl::string_view needle = search_value;
  RemoveWhitespaceContext(&needle);
  QUICHE_BUG_IF(bug_22783_2, needle != search_value)
      << "Search value should not be surrounded by spaces.";

  // We have nothing to do for empty needle strings.
  if (needle.empty()) {
    return 0;
  }

  // The return value: number of removed values.
  size_t removals = 0;

  // Iterate over all header lines matching key with skip=false.
  for (HeaderLines::iterator it =
           GetHeaderLinesIterator(key, header_lines_.begin());
       it != header_lines_.end(); it = GetHeaderLinesIterator(key, ++it)) {
    HeaderLineDescription* line = &(*it);

    // If needle given to us is longer than this header, don't consider it.
    if (line->ValuesLength() < needle.size()) {
      continue;
    }

    // If the values are equivalent, just remove the whole line.
    char* buf = GetPtr(line->buffer_base_idx);  // The head of our buffer.
    char* value_begin = buf + line->value_begin_idx;
    // StringPiece containing values that have yet to be processed. The head of
    // this stringpiece will continually move forward, and its tail
    // (head+length) will always remain the same.
    absl::string_view values(value_begin, line->ValuesLength());
    RemoveWhitespaceContext(&values);
    if (values.size() == needle.size()) {
      if (values == needle) {
        line->skip = true;
        removals++;
      }
      continue;
    }

    // Find all occurrences of the needle to be removed.
    char* insertion = value_begin;
    while (values.size() >= needle.size()) {
      // Strip leading whitespace.
      ssize_t cur_leading_whitespace = RemoveLeadingWhitespace(&values);

      // See if we've got a match (at least as a prefix).
      bool found = absl::StartsWith(values, needle);

      // Find the entirety of this value (including trailing comma if existent).
      const size_t next_comma =
          values.find(',', /* pos = */ (found ? needle.size() : 0));
      const bool comma_found = next_comma != absl::string_view::npos;
      const size_t cur_size = (comma_found ? next_comma + 1 : values.size());

      // Make sure that our prefix match is a full match.
      if (found && cur_size != needle.size()) {
        absl::string_view cur(values.data(), cur_size);
        if (comma_found) {
          cur.remove_suffix(1);
        }
        RemoveTrailingWhitespace(&cur);
        found = (cur.size() == needle.size());
      }

      // Move as necessary (avoid move just for the sake of leading whitespace).
      if (found) {
        removals++;
        // Remove trailing comma if we happen to have found the last value.
        if (!comma_found) {
          // We modify insertion since it'll be used to update last_char_idx.
          insertion--;
        }
      } else {
        if (insertion + cur_leading_whitespace != values.data()) {
          // Has the side-effect of also copying any trailing whitespace.
          memmove(insertion, values.data(), cur_size);
          insertion += cur_size;
        } else {
          insertion += cur_leading_whitespace + cur_size;
        }
      }

      // No longer consider the current value. (Increment.)
      values.remove_prefix(cur_size);
    }
    // Move remaining data.
    if (!values.empty()) {
      if (insertion != values.data()) {
        memmove(insertion, values.data(), values.size());
      }
      insertion += values.size();
    }
    // Set new line size.
    if (insertion <= value_begin) {
      // All values removed.
      line->skip = true;
    } else {
      line->last_char_idx = insertion - buf;
    }
  }

  return removals;
}

size_t BalsaHeaders::GetSizeForWriteBuffer() const {
  // First add the space required for the first line + line separator.
  size_t write_buf_size = whitespace_4_idx_ - non_whitespace_1_idx_ + 2;
  // Then add the space needed for each header line to write out + line
  // separator.
  const HeaderLines::size_type end = header_lines_.size();
  for (HeaderLines::size_type i = 0; i < end; ++i) {
    const HeaderLineDescription& line = header_lines_[i];
    if (!line.skip) {
      // Add the key size and ": ".
      write_buf_size += line.key_end_idx - line.first_char_idx + 2;
      // Add the value size and the line separator.
      write_buf_size += line.last_char_idx - line.value_begin_idx + 2;
    }
  }
  // Finally tack on the terminal line separator.
  return write_buf_size + 2;
}

void BalsaHeaders::DumpToString(std::string* str) const {
  DumpToPrefixedString(" ", str);
}

std::string BalsaHeaders::DebugString() const {
  std::string s;
  DumpToString(&s);
  return s;
}

bool BalsaHeaders::ForEachHeader(
    quiche::UnretainedCallback<bool(const absl::string_view key,
                                    const absl::string_view value)>
        fn) const {
  int s = header_lines_.size();
  for (int i = 0; i < s; ++i) {
    const HeaderLineDescription& desc = header_lines_[i];
    if (!desc.skip && desc.KeyLength() > 0) {
      const c
```