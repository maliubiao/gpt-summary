Response:
Let's break down the thought process for analyzing this C++ code snippet.

**1. Initial Understanding: Naming and Context**

The filename `spdy_alt_svc_wire_format.cc` and the namespace `spdy` immediately suggest this code deals with the "Alt-Svc" (Alternative Service) HTTP header, specifically within the context of the SPDY protocol (and likely HTTP/2 since SPDY is its predecessor). The `wire_format` part indicates it's responsible for handling the raw string representation of this header. The Chromium network stack context further reinforces this.

**2. Core Functionality Identification (Keywords & Structure)**

* **`ParseHeaderFieldValue`:** This function clearly takes a string (`value`) and populates a vector of `AlternativeService` objects. The name "Parse" and the output parameter `altsvc_vector` are key. This signals the primary purpose: converting a header string into a structured representation.
* **`SerializeHeaderFieldValue`:** The counterpart to `ParseHeaderFieldValue`. It takes a vector of `AlternativeService` objects and generates the corresponding header string.
* **`AlternativeService` struct/class:** This defines the structure representing a single alternative service. It holds `protocol_id`, `host`, `port`, `max_age_seconds`, and `version`.
* **Helper functions:**  Functions like `SkipWhiteSpace`, `PercentDecode`, `ParseAltAuthority`, `ParsePositiveInteger16/32`, `HexDigitToInt`, and `HexDecodeToUInt32` are clearly utility functions supporting the main parsing logic. They handle specific aspects of the format.

**3. Detailed Analysis of `ParseHeaderFieldValue`**

This is the most complex part. The strategy is to follow the code's logic step-by-step, focusing on how it interprets the input string.

* **Initial Checks:** Empty value handling and the "clear" directive.
* **Iteration and Delimiters:** The `while` loop and the use of `,` as a separator between alternative services.
* **Individual Service Parsing:**
    * **`protocol_id`:** Looking for the `=` delimiter. Noting the percent-decoding. Special handling for "hq" (QUIC).
    * **`alt-authority`:**  Parsing the host and port within the double quotes. Recognizing backslash escaping. Calling `ParseAltAuthority`.
    * **Parameters:** Parsing semicolon-separated parameters (`ma`, `v`, `quic`). Handling the different formats for the "v" (version) parameter (comma-separated vs. quoted string) and the "quic" parameter (hex encoding).
* **Error Handling:** Returning `false` on various parsing failures.

**4. Detailed Analysis of `SerializeHeaderFieldValue`**

This is the reverse process.

* **"clear" Handling:**  Returning "clear" for an empty vector.
* **Iteration:** Looping through the `AlternativeService` objects.
* **Individual Service Serialization:**
    * **`protocol_id`:** Percent-encoding.
    * **`alt-authority`:**  Quoting and backslash escaping.
    * **Parameters:** Appending `ma` and `v`/`quic` based on their values and the `protocol_id`. Noting the special formatting for QUIC versions.

**5. Identifying Connections to JavaScript (and General Browser Behavior)**

The core function of this code is to process the `Alt-Svc` header. Knowing how browsers use this header leads to the JavaScript connection.

* **Resource Hints:**  The `Alt-Svc` header is a type of resource hint. Browsers use it to learn about alternative ways to access the same resources.
* **`fetch()` API:** The `fetch()` API in JavaScript is the primary way to make network requests. The browser's handling of the `Alt-Svc` header *affects* how subsequent `fetch()` calls might be routed.
* **`navigator.connect()` (Less Common):** Briefly considered but deemed less directly relevant than `fetch()`.
* **Service Workers:** Another area where the browser intercepts and handles network requests, potentially influenced by `Alt-Svc`.

**6. Constructing Examples and Scenarios**

* **Input/Output:**  Creating simple examples for both parsing and serialization helps illustrate the code's behavior. Including edge cases (empty values, different parameter combinations).
* **User Errors:**  Thinking about what mistakes a developer might make when setting the `Alt-Svc` header on their server.
* **Debugging Scenario:**  Walking through a hypothetical user action that triggers the code, showing how a developer might trace through the network stack.

**7. Refining and Organizing the Explanation**

* **Clear Headings:**  Organizing the information into logical sections (Functionality, JavaScript Relation, Examples, Errors, Debugging).
* **Concise Language:**  Avoiding overly technical jargon where possible, explaining concepts clearly.
* **Code Snippets (Where Helpful):** Including small snippets of the C++ code to illustrate specific points.
* **Emphasis on Key Aspects:** Highlighting the parsing logic, serialization logic, and the role of the `AlternativeService` structure.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe focus too much on the intricacies of the percent encoding/decoding. *Correction:*  Recognize that while important, the core functionality is parsing and serialization of the overall header structure.
* **Considering other JavaScript APIs:**  Initially thought about `XMLHttpRequest`, but realized `fetch()` is the more modern and relevant API in this context.
* **Realizing the "why":**  Not just *what* the code does, but *why* it's necessary (optimizing connections, improving performance). This helps connect the C++ code to the broader browser behavior.

By following this structured approach, breaking down the code into smaller pieces, and connecting it to the wider context of web development, a comprehensive and accurate explanation can be generated.
这个C++源代码文件 `spdy_alt_svc_wire_format.cc`  在 Chromium 的网络栈中，其主要功能是**解析和序列化 HTTP 的 `Alt-Svc` (Alternative Service) 头部字段**。

`Alt-Svc` 头部允许服务器声明可以用来访问相同资源的替代网络位置（例如，不同的协议、主机或端口）。这有助于客户端尝试更优的连接方式，例如升级到 HTTP/3 或使用 QUIC 协议。

以下是该文件的具体功能分解：

**主要功能：**

1. **`ParseHeaderFieldValue(absl::string_view value, AlternativeServiceVector* altsvc_vector)`:**
   - **功能:**  接收一个表示 `Alt-Svc` 头部字段值的字符串 (`value`)，并将其解析成一个 `AlternativeService` 对象的向量 (`altsvc_vector`)。
   - **解析过程:**
     - 遍历 `Alt-Svc` 字符串，按照 RFC 中定义的格式解析出多个备用服务的信息。
     - 解析每个备用服务的协议 ID（例如 "h3"、"hq"）。
     - 解析备用服务的地址（主机和端口）。
     - 解析可选参数，例如 `ma` (max-age，最大缓存时间) 和 `v` (版本列表，通常用于 QUIC)。
     - 特殊处理 QUIC 的 IETF 格式（例如 `hq=":443";quic=51303338`）。
   - **输出:** 将解析出的备用服务信息存储在 `altsvc_vector` 中。
   - **错误处理:** 如果解析失败（例如格式错误），则返回 `false`。

2. **`SerializeHeaderFieldValue(const AlternativeServiceVector& altsvc_vector)`:**
   - **功能:** 接收一个 `AlternativeService` 对象的向量 (`altsvc_vector`)，并将其序列化成一个符合 `Alt-Svc` 头部字段格式的字符串。
   - **序列化过程:**
     - 遍历 `altsvc_vector` 中的每个 `AlternativeService` 对象。
     - 将每个对象的信息格式化成 `protocol_id="host:port"; ma=value; v="v1,v2"` 的形式。
     - 对协议 ID 进行百分号编码，对主机进行必要的转义。
     - 特殊处理 QUIC 的 IETF 格式序列化。
   - **输出:** 返回序列化后的 `Alt-Svc` 头部字段字符串。
   - **特殊情况:** 如果 `altsvc_vector` 为空，则返回字符串 "clear"，表示清除之前的备用服务信息。

**辅助功能：**

- **`AlternativeService` 结构体:**  定义了一个用于存储单个备用服务信息的结构，包含 `protocol_id`、`host`、`port`、`max_age_seconds` 和 `version`。
- **`SkipWhiteSpace`:** 跳过字符串中的空格和制表符。
- **`PercentDecode`:**  对 URL 百分号编码的字符串进行解码。
- **`ParseAltAuthority`:**  解析备用服务的地址部分（`host:port`）。
- **`ParsePositiveInteger16` 和 `ParsePositiveInteger32`:** 解析字符串中的正整数。
- **`HexDigitToInt`:** 将十六进制字符转换为整数。
- **`HexDecodeToUInt32`:** 将十六进制字符串解码为无符号 32 位整数。

**与 JavaScript 功能的关系：**

这个 C++ 文件直接在浏览器的底层网络栈中工作，负责处理网络协议的细节。它与 JavaScript 的关系是间接的，但至关重要：

- **`fetch()` API:** 当 JavaScript 代码使用 `fetch()` API 发起网络请求时，浏览器会接收服务器返回的 HTTP 响应头，其中可能包含 `Alt-Svc` 头部。
- **浏览器优化:** 浏览器网络栈会解析这个 `Alt-Svc` 头部，并将其存储起来。在后续对相同域名的请求中，浏览器可能会尝试使用 `Alt-Svc` 提供的备用服务（例如，如果服务器声明支持 HTTP/3，浏览器可能会尝试使用 HTTP/3 连接）。
- **用户体验提升:**  通过使用更优的协议（如 HTTP/3 或 QUIC），可以减少延迟，提高网页加载速度，从而提升用户体验。

**举例说明：**

假设服务器返回以下 `Alt-Svc` 头部：

```
Alt-Svc: h3=":443"; ma=3600, hq=":443"; quic=51303338; ma=3600
```

这个头部表示：

- 有一个使用 HTTP/3 协议的备用服务，主机为当前主机，端口为 443，有效期为 3600 秒。
- 有一个使用 QUIC 协议的备用服务，主机为当前主机，端口为 443，QUIC 版本标签为 `51303338`（对应 "Q038"），有效期为 3600 秒。

当浏览器接收到这个头部时，`ParseHeaderFieldValue` 函数会被调用，输入是 `h3=":443"; ma=3600, hq=":443"; quic=51303338; ma=3600`。

**假设输入与输出 (ParseHeaderFieldValue):**

**假设输入:** `value = "h3=\":443\"; ma=3600, hq=\":443\";quic=51303338;ma=3600"`

**逻辑推理:**

1. 解析第一个备用服务：
   - `protocol_id` = "h3"
   - `host` = "" (空，表示当前主机)
   - `port` = 443
   - `max_age_seconds` = 3600
   - `version` = 空向量

2. 解析第二个备用服务：
   - `protocol_id` = "hq"
   - `host` = "" (空，表示当前主机)
   - `port` = 443
   - `max_age_seconds` = 3600
   - `version` = [0x51303338]  (解码 "51303338" 为十六进制)

**假设输出:** `altsvc_vector` 将包含两个 `AlternativeService` 对象，分别对应上述解析结果。

**假设输入与输出 (SerializeHeaderFieldValue):**

**假设输入:** `altsvc_vector` 包含以下两个 `AlternativeService` 对象:

```cpp
AlternativeService("h3", "", 443, 3600, {});
AlternativeService("hq", "", 443, 3600, {0x51303338});
```

**假设输出:** `std::string` 将为 `"h3=\":443\";ma=3600,hq=\":443\";quic=51303338;ma=3600"`

**用户或编程常见的使用错误：**

1. **服务器配置错误:**
   - **错误的语法:** 服务器配置了不符合 RFC 规范的 `Alt-Svc` 头部，例如缺少引号、分号或等号，导致解析失败。
   - **错误的端口号:** 配置了错误的备用服务端口号，导致客户端连接失败。
   - **未转义特殊字符:**  在主机名中使用了需要转义的字符但未进行转义。

   **例子:** `Alt-Svc: h3=:443, hq=:443;quic=Q038` (缺少引号，QUIC 版本格式错误)

2. **客户端缓存问题:**
   - 浏览器可能会缓存 `Alt-Svc` 信息，即使服务器已经移除了这些备用服务。这可能导致客户端尝试连接不再存在的服务。

3. **中间件修改:**
   - 中间的代理或 CDN 可能错误地修改或剥离 `Alt-Svc` 头部，导致客户端无法获取备用服务信息。

**用户操作如何一步步地到达这里，作为调试线索：**

1. **用户在浏览器中输入 URL 并访问一个网站。**
2. **浏览器向服务器发起 HTTP 请求。**
3. **服务器处理请求并返回 HTTP 响应，响应头中包含 `Alt-Svc` 头部。**
4. **浏览器网络栈接收到响应头。**
5. **网络栈中的代码（包括 `spdy_alt_svc_wire_format.cc`）被调用，解析 `Alt-Svc` 头部字段的值。**
6. **如果解析成功，浏览器会记住这些备用服务信息。**
7. **在后续对相同域名的请求中，浏览器可能会尝试使用这些备用服务。**

**调试线索:**

- **抓包分析:** 使用 Wireshark 或 Chrome 的开发者工具 Network 面板，查看服务器返回的 `Alt-Svc` 头部字段的值，确认其格式是否正确。
- **Chrome 内部状态:** 在 Chrome 中访问 `chrome://net-internals/#alt-svc` 可以查看浏览器当前缓存的备用服务信息。这可以帮助确定浏览器是否正确解析了 `Alt-Svc` 头部。
- **日志记录:** Chromium 的网络栈有详细的日志记录。通过配置合适的日志级别，可以查看 `spdy_alt_svc_wire_format.cc` 中的日志输出，了解解析过程中的详细信息和可能的错误。
- **断点调试:** 如果需要深入了解解析过程，可以使用调试器在 `spdy_alt_svc_wire_format.cc` 的相关函数中设置断点，单步执行代码，查看变量的值。

总而言之，`spdy_alt_svc_wire_format.cc` 文件是 Chromium 网络栈中处理 `Alt-Svc` 头部的重要组成部分，它负责在底层解析和生成这种头部，使得浏览器能够利用服务器提供的备用服务信息来优化网络连接。虽然 JavaScript 代码本身不直接调用这个文件中的函数，但 JavaScript 发起的网络请求的行为会受到其解析结果的影响。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/core/spdy_alt_svc_wire_format.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/core/spdy_alt_svc_wire_format.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace spdy {

namespace {

template <class T>
bool ParsePositiveIntegerImpl(absl::string_view::const_iterator c,
                              absl::string_view::const_iterator end, T* value) {
  *value = 0;
  for (; c != end && std::isdigit(*c); ++c) {
    if (*value > std::numeric_limits<T>::max() / 10) {
      return false;
    }
    *value *= 10;
    if (*value > std::numeric_limits<T>::max() - (*c - '0')) {
      return false;
    }
    *value += *c - '0';
  }
  return (c == end && *value > 0);
}

}  // namespace

SpdyAltSvcWireFormat::AlternativeService::AlternativeService() = default;

SpdyAltSvcWireFormat::AlternativeService::AlternativeService(
    const std::string& protocol_id, const std::string& host, uint16_t port,
    uint32_t max_age_seconds, VersionVector version)
    : protocol_id(protocol_id),
      host(host),
      port(port),
      max_age_seconds(max_age_seconds),
      version(std::move(version)) {}

SpdyAltSvcWireFormat::AlternativeService::~AlternativeService() = default;

SpdyAltSvcWireFormat::AlternativeService::AlternativeService(
    const AlternativeService& other) = default;

// static
bool SpdyAltSvcWireFormat::ParseHeaderFieldValue(
    absl::string_view value, AlternativeServiceVector* altsvc_vector) {
  // Empty value is invalid according to the specification.
  if (value.empty()) {
    return false;
  }
  altsvc_vector->clear();
  if (value == absl::string_view("clear")) {
    return true;
  }
  absl::string_view::const_iterator c = value.begin();
  while (c != value.end()) {
    // Parse protocol-id.
    absl::string_view::const_iterator percent_encoded_protocol_id_end =
        std::find(c, value.end(), '=');
    std::string protocol_id;
    if (percent_encoded_protocol_id_end == c ||
        !PercentDecode(c, percent_encoded_protocol_id_end, &protocol_id)) {
      return false;
    }
    // Check for IETF format for advertising QUIC:
    // hq=":443";quic=51303338;quic=51303334
    const bool is_ietf_format_quic = (protocol_id == "hq");
    c = percent_encoded_protocol_id_end;
    if (c == value.end()) {
      return false;
    }
    // Parse alt-authority.
    QUICHE_DCHECK_EQ('=', *c);
    ++c;
    if (c == value.end() || *c != '"') {
      return false;
    }
    ++c;
    absl::string_view::const_iterator alt_authority_begin = c;
    for (; c != value.end() && *c != '"'; ++c) {
      // Decode backslash encoding.
      if (*c != '\\') {
        continue;
      }
      ++c;
      if (c == value.end()) {
        return false;
      }
    }
    if (c == alt_authority_begin || c == value.end()) {
      return false;
    }
    QUICHE_DCHECK_EQ('"', *c);
    std::string host;
    uint16_t port;
    if (!ParseAltAuthority(alt_authority_begin, c, &host, &port)) {
      return false;
    }
    ++c;
    // Parse parameters.
    uint32_t max_age_seconds = 86400;
    VersionVector version;
    absl::string_view::const_iterator parameters_end =
        std::find(c, value.end(), ',');
    while (c != parameters_end) {
      SkipWhiteSpace(&c, parameters_end);
      if (c == parameters_end) {
        break;
      }
      if (*c != ';') {
        return false;
      }
      ++c;
      SkipWhiteSpace(&c, parameters_end);
      if (c == parameters_end) {
        break;
      }
      std::string parameter_name;
      for (; c != parameters_end && *c != '=' && *c != ' ' && *c != '\t'; ++c) {
        parameter_name.push_back(tolower(*c));
      }
      SkipWhiteSpace(&c, parameters_end);
      if (c == parameters_end || *c != '=') {
        return false;
      }
      ++c;
      SkipWhiteSpace(&c, parameters_end);
      absl::string_view::const_iterator parameter_value_begin = c;
      for (; c != parameters_end && *c != ';' && *c != ' ' && *c != '\t'; ++c) {
      }
      if (c == parameter_value_begin) {
        return false;
      }
      if (parameter_name == "ma") {
        if (!ParsePositiveInteger32(parameter_value_begin, c,
                                    &max_age_seconds)) {
          return false;
        }
      } else if (!is_ietf_format_quic && parameter_name == "v") {
        // Version is a comma separated list of positive integers enclosed in
        // quotation marks.  Since it can contain commas, which are not
        // delineating alternative service entries, |parameters_end| and |c| can
        // be invalid.
        if (*parameter_value_begin != '"') {
          return false;
        }
        c = std::find(parameter_value_begin + 1, value.end(), '"');
        if (c == value.end()) {
          return false;
        }
        ++c;
        parameters_end = std::find(c, value.end(), ',');
        absl::string_view::const_iterator v_begin = parameter_value_begin + 1;
        while (v_begin < c) {
          absl::string_view::const_iterator v_end = v_begin;
          while (v_end < c - 1 && *v_end != ',') {
            ++v_end;
          }
          uint16_t v;
          if (!ParsePositiveInteger16(v_begin, v_end, &v)) {
            return false;
          }
          version.push_back(v);
          v_begin = v_end + 1;
          if (v_begin == c - 1) {
            // List ends in comma.
            return false;
          }
        }
      } else if (is_ietf_format_quic && parameter_name == "quic") {
        // IETF format for advertising QUIC. Version is hex encoding of QUIC
        // version tag. Hex-encoded string should not include leading "0x" or
        // leading zeros.
        // Example for advertising QUIC versions "Q038" and "Q034":
        // hq=":443";quic=51303338;quic=51303334
        if (*parameter_value_begin == '0') {
          return false;
        }
        // Versions will be stored as the uint32_t hex decoding of the param
        // value string. Example: QUIC version "Q038", which is advertised as:
        // hq=":443";quic=51303338
        // ... will be stored in |versions| as 0x51303338.
        uint32_t quic_version;
        if (!HexDecodeToUInt32(absl::string_view(&*parameter_value_begin,
                                                 c - parameter_value_begin),
                               &quic_version) ||
            quic_version == 0) {
          return false;
        }
        version.push_back(quic_version);
      }
    }
    altsvc_vector->emplace_back(protocol_id, host, port, max_age_seconds,
                                version);
    for (; c != value.end() && (*c == ' ' || *c == '\t' || *c == ','); ++c) {
    }
  }
  return true;
}

// static
std::string SpdyAltSvcWireFormat::SerializeHeaderFieldValue(
    const AlternativeServiceVector& altsvc_vector) {
  if (altsvc_vector.empty()) {
    return std::string("clear");
  }
  const char kNibbleToHex[] = "0123456789ABCDEF";
  std::string value;
  for (const AlternativeService& altsvc : altsvc_vector) {
    if (!value.empty()) {
      value.push_back(',');
    }
    // Check for IETF format for advertising QUIC.
    const bool is_ietf_format_quic = (altsvc.protocol_id == "hq");
    // Percent escape protocol id according to
    // http://tools.ietf.org/html/rfc7230#section-3.2.6.
    for (char c : altsvc.protocol_id) {
      if (isalnum(c)) {
        value.push_back(c);
        continue;
      }
      switch (c) {
        case '!':
        case '#':
        case '$':
        case '&':
        case '\'':
        case '*':
        case '+':
        case '-':
        case '.':
        case '^':
        case '_':
        case '`':
        case '|':
        case '~':
          value.push_back(c);
          break;
        default:
          value.push_back('%');
          // Network byte order is big-endian.
          value.push_back(kNibbleToHex[c >> 4]);
          value.push_back(kNibbleToHex[c & 0x0f]);
          break;
      }
    }
    value.push_back('=');
    value.push_back('"');
    for (char c : altsvc.host) {
      if (c == '"' || c == '\\') {
        value.push_back('\\');
      }
      value.push_back(c);
    }
    absl::StrAppend(&value, ":", altsvc.port, "\"");
    if (altsvc.max_age_seconds != 86400) {
      absl::StrAppend(&value, "; ma=", altsvc.max_age_seconds);
    }
    if (!altsvc.version.empty()) {
      if (is_ietf_format_quic) {
        for (uint32_t quic_version : altsvc.version) {
          absl::StrAppend(&value, "; quic=", absl::Hex(quic_version));
        }
      } else {
        value.append("; v=\"");
        for (auto it = altsvc.version.begin(); it != altsvc.version.end();
             ++it) {
          if (it != altsvc.version.begin()) {
            value.append(",");
          }
          absl::StrAppend(&value, *it);
        }
        value.append("\"");
      }
    }
  }
  return value;
}

// static
void SpdyAltSvcWireFormat::SkipWhiteSpace(
    absl::string_view::const_iterator* c,
    absl::string_view::const_iterator end) {
  for (; *c != end && (**c == ' ' || **c == '\t'); ++*c) {
  }
}

// static
bool SpdyAltSvcWireFormat::PercentDecode(absl::string_view::const_iterator c,
                                         absl::string_view::const_iterator end,
                                         std::string* output) {
  output->clear();
  for (; c != end; ++c) {
    if (*c != '%') {
      output->push_back(*c);
      continue;
    }
    QUICHE_DCHECK_EQ('%', *c);
    ++c;
    if (c == end || !std::isxdigit(*c)) {
      return false;
    }
    // Network byte order is big-endian.
    char decoded = HexDigitToInt(*c) << 4;
    ++c;
    if (c == end || !std::isxdigit(*c)) {
      return false;
    }
    decoded += HexDigitToInt(*c);
    output->push_back(decoded);
  }
  return true;
}

// static
bool SpdyAltSvcWireFormat::ParseAltAuthority(
    absl::string_view::const_iterator c, absl::string_view::const_iterator end,
    std::string* host, uint16_t* port) {
  host->clear();
  if (c == end) {
    return false;
  }
  if (*c == '[') {
    for (; c != end && *c != ']'; ++c) {
      if (*c == '"') {
        // Port is mandatory.
        return false;
      }
      host->push_back(*c);
    }
    if (c == end) {
      return false;
    }
    QUICHE_DCHECK_EQ(']', *c);
    host->push_back(*c);
    ++c;
  } else {
    for (; c != end && *c != ':'; ++c) {
      if (*c == '"') {
        // Port is mandatory.
        return false;
      }
      if (*c == '\\') {
        ++c;
        if (c == end) {
          return false;
        }
      }
      host->push_back(*c);
    }
  }
  if (c == end || *c != ':') {
    return false;
  }
  QUICHE_DCHECK_EQ(':', *c);
  ++c;
  return ParsePositiveInteger16(c, end, port);
}

// static
bool SpdyAltSvcWireFormat::ParsePositiveInteger16(
    absl::string_view::const_iterator c, absl::string_view::const_iterator end,
    uint16_t* value) {
  return ParsePositiveIntegerImpl<uint16_t>(c, end, value);
}

// static
bool SpdyAltSvcWireFormat::ParsePositiveInteger32(
    absl::string_view::const_iterator c, absl::string_view::const_iterator end,
    uint32_t* value) {
  return ParsePositiveIntegerImpl<uint32_t>(c, end, value);
}

// static
char SpdyAltSvcWireFormat::HexDigitToInt(char c) {
  QUICHE_DCHECK(std::isxdigit(c));

  if (std::isdigit(c)) {
    return c - '0';
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }

  return 0;
}

// static
bool SpdyAltSvcWireFormat::HexDecodeToUInt32(absl::string_view data,
                                             uint32_t* value) {
  if (data.empty() || data.length() > 8u) {
    return false;
  }

  *value = 0;
  for (char c : data) {
    if (!std::isxdigit(c)) {
      return false;
    }

    *value <<= 4;
    *value += HexDigitToInt(c);
  }

  return true;
}

}  // namespace spdy

"""

```