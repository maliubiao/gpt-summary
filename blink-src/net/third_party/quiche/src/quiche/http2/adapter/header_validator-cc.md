Response:
Let's break down the thought process for analyzing the C++ code and generating the explanation.

**1. Initial Understanding and Goal:**

The primary goal is to understand the functionality of the `header_validator.cc` file in the Chromium network stack. This involves identifying its purpose, how it operates, its relationship to JavaScript (if any), potential errors, and how one might reach this code during debugging.

**2. Code Examination - Top-Down Approach:**

* **Includes:**  Start by looking at the included headers. This gives clues about the file's dependencies and general area of concern. We see things like `<string>`, `<bitset>`, `absl/strings/...`, `quiche/http2/...`, and `quiche/common/...`. This strongly suggests the file is involved in HTTP/2 processing and string manipulation. The "quiche" namespace points to Google's QUIC/HTTP/3 implementation, but since the path is `net/third_party/quiche/src/quiche/http2/`, it's specifically about the HTTP/2 part.

* **Namespace:**  Note the `http2::adapter` namespace. This suggests the code is an adapter or intermediary for HTTP/2 functionality within a larger system (likely Chromium).

* **Constants:** Look at the `constexpr absl::string_view` constants. These define allowed characters for various parts of HTTP headers (token, header name, header value, status, authority, path). This immediately points to the file's core responsibility: validating the syntax of HTTP/2 headers.

* **Helper Functions:** Examine small helper functions like `BuildValidCharMap`, `AllowObsText`, and `AllCharsInMap`. These are building blocks for the validation logic. `BuildValidCharMap` creates a lookup table for allowed characters, `AllowObsText` adds support for obsolete text, and `AllCharsInMap` checks if a string consists entirely of allowed characters. The functions `IsValidStatus`, `IsValidMethod`, `IsValidAuthority`, and `IsValidPath` use these helpers to perform specific validations.

* **`HeaderValidator` Class:** This is the main class. Analyze its methods:
    * `StartHeaderBlock()`:  Likely initializes the state for validating a new set of headers.
    * `RecordPseudoHeader()`:  Handles recording the presence of pseudo-headers (like `:status`, `:method`).
    * `ValidateSingleHeader()`: This is the core validation logic for individual header key-value pairs. Pay close attention to its conditional checks (e.g., checking for leading colons, specific pseudo-header names, and using the helper functions for character validation).
    * `FinishHeaderBlock()`:  Performs final checks after processing all headers in a block, based on the header type (request, response, trailers).
    * `IsValidHeaderName()`, `IsValidHeaderValue()`, `IsValidAuthority()`, `IsValidPath()`: These are public interfaces for specific validation checks.
    * `HandleContentLength()`: Specifically handles the `Content-Length` header, checking for consistency and validity.
    * `ValidateAndSetAuthority()`: Validates and stores the `authority` (or `Host`) header.
    * `ValidateRequestHeaders()`, `ValidateRequestTrailers()`, `ValidateResponseHeaders()`, `ValidateResponseTrailers()`: Implement the specific validation rules for different types of header blocks.

**3. Functional Summary:**

Based on the code examination, formulate a concise summary of the file's functionality. The core purpose is to validate HTTP/2 headers according to RFC specifications. It checks syntax, required/forbidden headers based on the message type, and consistency of certain headers (like `Content-Length`).

**4. Relationship to JavaScript:**

Think about how HTTP headers are used in web development. JavaScript running in a browser interacts with HTTP requests and responses. While this C++ code doesn't *directly* execute JavaScript, it plays a crucial role in ensuring the integrity of HTTP communication that JavaScript relies on. Consider scenarios like `fetch()` API calls or server-sent events.

**5. Logical Reasoning (Input/Output Examples):**

Create simple scenarios to illustrate the validation logic. Choose cases that would pass and fail validation for different rules (e.g., invalid characters, missing required headers, invalid `Content-Length`). This demonstrates the practical application of the code.

**6. Common User/Programming Errors:**

Consider typical mistakes developers might make when constructing HTTP requests or responses. These errors would likely be caught by this validation code. Examples include incorrect header names, invalid characters in values, or violating HTTP/2 protocol rules.

**7. Debugging Scenario:**

Think about how a developer might end up in this code during debugging. Focus on the sequence of actions that leads to header processing, such as a browser making a request or a server receiving one. Mention debugging tools and techniques that could be used.

**8. Refinement and Organization:**

Review the generated explanation for clarity, accuracy, and completeness. Organize the information logically using headings and bullet points for better readability. Ensure the language is clear and avoids overly technical jargon where possible. For instance, instead of just saying "RFC 7540 Section 8.3," briefly explain what that section relates to (CONNECT requests).

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Is this just about syntax?  **Correction:** Realize it also enforces semantic rules (required headers, forbidden headers, consistency checks).
* **Initial thought:** Is the JavaScript connection very direct? **Correction:**  Recognize the indirect but critical role in ensuring the reliability of the underlying HTTP communication that JavaScript depends on.
* **Initial thought:**  Should I list every possible error? **Correction:** Focus on common and illustrative examples.
* **Initial thought:** Is the debugging scenario too technical? **Correction:**  Provide a high-level overview of the user actions and debugging tools.

By following this structured approach, combining code analysis with reasoning about the broader context of HTTP and web development, we can generate a comprehensive and informative explanation of the `header_validator.cc` file.
这个 `header_validator.cc` 文件是 Chromium 网络栈中 HTTP/2 协议适配器的一部分，它的主要功能是**验证 HTTP/2 头部字段的有效性**。更具体地说，它负责检查接收到的 HTTP/2 头部是否符合 RFC 7540 等相关规范的要求。

以下是它的具体功能列表：

1. **基本头部字段语法验证:**
   - 检查头部名称和值的字符是否在允许的字符集中。例如，头部名称只能包含特定的符号、数字和字母，而头部值允许的字符集略有不同。
   - 检查 `:status` 伪头的值是否为三位数字。
   - 检查 `:method` 伪头的值是否为合法的 HTTP 方法。

2. **伪头字段验证:**
   - 跟踪已出现的伪头字段（例如 `:method`, `:path`, `:authority`, `:scheme`, `:status`）。
   - 确保必要的伪头字段存在，并且没有出现额外的、不应该出现的伪头字段，这取决于请求或响应的类型。
   - 验证伪头字段的顺序是否符合规范（虽然代码中没有显式强制顺序，但会记录它们的出现）。

3. **特定头部字段验证:**
   - 检查 `host` 头部字段是否与 `:authority` 伪头一致（在不允许两者不同时）。
   - 处理 `content-length` 头部，检查其值是否为数字，并处理重复的 `content-length` 头部。
   - 检查 `te` 头部是否为 `trailers`。
   - 阻止使用在 HTTP/2 中无效的头部字段，例如 `upgrade`。

4. **状态管理:**
   - 维护一些内部状态，例如是否看到了特定的伪头字段，以及 `:method` 是否为 `OPTIONS` 或 `CONNECT`。
   - 记录 `:authority` 伪头的值。

5. **路径验证:**
   - 可选地验证 `:path` 伪头的值是否包含有效的字符。

6. **最大头部字段大小限制:**
   - 如果设置了最大头部字段大小，则会检查单个头部字段（名称 + 值）的大小是否超过限制。

7. **OBS-text 支持:**
   - 可以配置是否允许在头部值中使用 `obs-text`（RFC 7230 中定义的过时文本）。

**与 JavaScript 功能的关系:**

虽然这个 C++ 代码本身不包含 JavaScript，但它对于基于浏览器的 JavaScript 应用与服务器之间的 HTTP/2 通信至关重要。当 JavaScript 代码发起网络请求（例如使用 `fetch` API 或 `XMLHttpRequest`）时，浏览器底层的网络栈（包括这个 `header_validator.cc` 模块）会处理这些请求的构造和发送，以及接收和解析服务器的响应。

**举例说明:**

假设一个 JavaScript 应用使用 `fetch` 发起一个 GET 请求：

```javascript
fetch('https://example.com/data');
```

在浏览器内部，网络栈会将这个请求转换为 HTTP/2 帧。`header_validator.cc` 会参与验证请求头部，例如：

- 验证 `:method` 的值为 `GET` 是否合法。
- 验证 `:path` 的值为 `/data` 是否合法。
- 验证 `:authority` 的值为 `example.com` 是否合法。
- 验证其他头部（例如 `User-Agent`, `Accept`）的字符是否在允许的范围内。

如果服务器返回一个 HTTP/2 响应，`header_validator.cc` 也会验证响应头部：

- 验证 `:status` 的值是否为三位数字（例如 `200`）。
- 验证其他响应头部（例如 `Content-Type`, `Content-Length`）的有效性。

**逻辑推理的假设输入与输出:**

**假设输入 1 (请求头部):**

```
:method: GET
:path: /users?id=123
:authority: example.com
:scheme: https
User-Agent: MyBrowser
```

**预期输出 1:**  `ValidateSingleHeader` 会对每个头部返回 `HEADER_OK`，`FinishHeaderBlock(HeaderType::REQUEST)` 返回 `true`，表示头部块有效。

**假设输入 2 (请求头部，包含非法字符):**

```
:method: GET
:path: /data with spaces
:authority: example.com
:scheme: https
```

**预期输出 2:** `ValidateSingleHeader` 在处理 `:path` 时会因为空格字符返回 `HEADER_FIELD_INVALID`，因为路径中包含空格。

**假设输入 3 (响应头部，缺少必要的 :status 伪头):**

```
Content-Type: application/json
```

**预期输出 3:** `FinishHeaderBlock(HeaderType::RESPONSE)` 返回 `false`，因为缺少 `:status` 伪头。

**用户或编程常见的使用错误举例说明:**

1. **在 HTTP/2 请求中包含 `Upgrade` 头部:**  HTTP/2 不支持 `Upgrade` 机制。如果 JavaScript 代码或服务器尝试发送包含 `Upgrade` 头的 HTTP/2 请求，`ValidateSingleHeader` 会返回 `HEADER_FIELD_INVALID`，阻止请求的发送或处理。

   ```javascript
   // 错误示例
   fetch('/resource', {
       headers: {
           'Upgrade': 'websocket'
       }
   });
   ```

2. **在 HTTP/2 请求中包含 Host 头部，并且与 :authority 不一致:**  HTTP/2 中，`:authority` 伪头是指定主机名的标准方式。如果同时存在 `Host` 头部且与 `:authority` 不同，`ValidateSingleHeader` 可能会返回 `HEADER_FIELD_INVALID`。

   ```javascript
   // 假设 :authority 是 example.com
   fetch('https://different.com/resource', {
       headers: {
           'Host': 'example.com'
       }
   });
   ```

3. **在头部值中使用非法字符:**  如果 JavaScript 代码尝试设置包含不允许字符的头部值，`ValidateSingleHeader` 会检测到并返回 `HEADER_FIELD_INVALID`。

   ```javascript
   fetch('/resource', {
       headers: {
           'Custom-Header': 'value with \x00' // 包含空字符
       }
   });
   ```

**用户操作如何一步步到达这里 (调试线索):**

假设一个用户在使用 Chromium 浏览器访问一个网站时遇到网络问题，开发者想要调试 HTTP/2 头部验证的问题：

1. **用户在浏览器中输入网址并访问，或者 JavaScript 代码发起一个网络请求。**
2. **Chromium 浏览器会与服务器建立 HTTP/2 连接。**
3. **如果是一个新的请求，浏览器会构建 HTTP/2 请求头部。**
4. **在将头部发送到网络之前，Chromium 的 HTTP/2 实现会使用 `HeaderValidator` 来验证这些头部。**
5. **如果接收到服务器的 HTTP/2 响应，`HeaderValidator` 也会验证响应头部。**

**调试线索:**

- **抓包工具 (例如 Wireshark):** 可以捕获浏览器和服务器之间的 HTTP/2 数据包，查看实际发送和接收的头部内容，确认是否存在格式错误或其他异常。
- **浏览器开发者工具 (Network 面板):** 可以查看浏览器发送和接收的请求头和响应头。虽然开发者工具通常会显示解析后的头部，但如果头部格式严重错误，可能会在控制台中看到网络错误。
- **Chromium 源码调试:**  如果问题比较复杂，开发者可能需要在 Chromium 源码中设置断点，例如在 `HeaderValidator::ValidateSingleHeader` 或 `HeaderValidator::FinishHeaderBlock` 等方法中，来跟踪头部验证的流程，查看具体的输入和输出，以及验证失败的原因。
- **Chromium 网络日志 (net-internals):**  Chromium 提供了 `chrome://net-internals/#http2` 和 `chrome://net-internals/#events` 页面，可以查看详细的网络事件日志，包括 HTTP/2 会话和帧的详细信息，这有助于了解头部验证是否失败以及失败的具体原因。

总而言之，`header_validator.cc` 是 Chromium 网络栈中一个关键的组件，负责确保 HTTP/2 通信的正确性和安全性，防止因格式错误的头部而导致的问题。虽然 JavaScript 开发者通常不会直接操作这个文件，但它的正确运行对于所有依赖 HTTP/2 的 Web 应用至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/header_validator.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#include "quiche/http2/adapter/header_validator.h"

#include <array>
#include <bitset>
#include <string>

#include "absl/strings/ascii.h"
#include "absl/strings/escaping.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "quiche/http2/adapter/header_validator_base.h"
#include "quiche/http2/http2_constants.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace http2 {
namespace adapter {

namespace {

// From RFC 9110 Section 5.6.2.
constexpr absl::string_view kHttpTokenChars =
    "!#$%&'*+-.^_`|~0123456789"
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

constexpr absl::string_view kHttp2HeaderNameAllowedChars =
    "!#$%&'*+-.0123456789"
    "^_`abcdefghijklmnopqrstuvwxyz|~";

constexpr absl::string_view kHttp2HeaderValueAllowedChars =
    "\t "
    "!\"#$%&'()*+,-./"
    "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
    "abcdefghijklmnopqrstuvwxyz{|}~";

constexpr absl::string_view kHttp2StatusValueAllowedChars = "0123456789";

constexpr absl::string_view kValidAuthorityChars =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~%!$&'()["
    "]*+,;=:";

constexpr absl::string_view kValidPathChars =
    "/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~%!$&'()"
    "*+,;=:@?";

constexpr absl::string_view kValidPathCharsWithFragment =
    "/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~%!$&'()"
    "*+,;=:@?#";

using CharMap = std::array<bool, 256>;

constexpr CharMap BuildValidCharMap(absl::string_view valid_chars) {
  CharMap map = {};
  for (char c : valid_chars) {
    // An array index must be a nonnegative integer, hence the cast to uint8_t.
    map[static_cast<uint8_t>(c)] = true;
  }
  return map;
}
constexpr CharMap AllowObsText(CharMap map) {
  // Characters above 0x80 are allowed in header field values as `obs-text` in
  // RFC 7230.
  for (uint8_t c = 0xff; c >= 0x80; --c) {
    map[c] = true;
  }
  return map;
}

bool AllCharsInMap(absl::string_view str, const CharMap& map) {
  for (char c : str) {
    if (!map[static_cast<uint8_t>(c)]) {
      return false;
    }
  }
  return true;
}

bool IsValidStatus(absl::string_view status) {
  static constexpr CharMap valid_chars =
      BuildValidCharMap(kHttp2StatusValueAllowedChars);
  return AllCharsInMap(status, valid_chars);
}

bool IsValidMethod(absl::string_view method) {
  static constexpr CharMap valid_chars = BuildValidCharMap(kHttpTokenChars);
  return AllCharsInMap(method, valid_chars);
}

}  // namespace

void HeaderValidator::StartHeaderBlock() {
  HeaderValidatorBase::StartHeaderBlock();
  pseudo_headers_.reset();
  pseudo_header_state_.reset();
  authority_.clear();
}

void HeaderValidator::RecordPseudoHeader(PseudoHeaderTag tag) {
  if (pseudo_headers_[tag]) {
    pseudo_headers_[TAG_UNKNOWN_EXTRA] = true;
  } else {
    pseudo_headers_[tag] = true;
  }
}

HeaderValidator::HeaderStatus HeaderValidator::ValidateSingleHeader(
    absl::string_view key, absl::string_view value) {
  if (key.empty()) {
    return HEADER_FIELD_INVALID;
  }
  if (max_field_size_.has_value() &&
      key.size() + value.size() > *max_field_size_) {
    QUICHE_VLOG(2) << "Header field size is " << key.size() + value.size()
                   << ", exceeds max size of " << *max_field_size_;
    return HEADER_FIELD_TOO_LONG;
  }
  if (key[0] == ':') {
    // Remove leading ':'.
    key.remove_prefix(1);
    if (key == "status") {
      if (value.size() != 3 || !IsValidStatus(value)) {
        QUICHE_VLOG(2) << "malformed status value: [" << absl::CEscape(value)
                       << "]";
        return HEADER_FIELD_INVALID;
      }
      if (value == "101") {
        // Switching protocols is not allowed on a HTTP/2 stream.
        return HEADER_FIELD_INVALID;
      }
      status_ = std::string(value);
      RecordPseudoHeader(TAG_STATUS);
    } else if (key == "method") {
      if (value == "OPTIONS") {
        pseudo_header_state_[STATE_METHOD_IS_OPTIONS] = true;
      } else if (value == "CONNECT") {
        pseudo_header_state_[STATE_METHOD_IS_CONNECT] = true;
      } else if (!IsValidMethod(value)) {
        return HEADER_FIELD_INVALID;
      }
      RecordPseudoHeader(TAG_METHOD);
    } else if (key == "authority") {
      if (!ValidateAndSetAuthority(value)) {
        return HEADER_FIELD_INVALID;
      }
      RecordPseudoHeader(TAG_AUTHORITY);
    } else if (key == "path") {
      if (value == "*") {
        pseudo_header_state_[STATE_PATH_IS_STAR] = true;
      } else if (value.empty()) {
        pseudo_header_state_[STATE_PATH_IS_EMPTY] = true;
        return HEADER_FIELD_INVALID;
      } else if (validate_path_ &&
                 !IsValidPath(value, allow_fragment_in_path_)) {
        return HEADER_FIELD_INVALID;
      }
      if (value[0] == '/') {
        pseudo_header_state_[STATE_PATH_INITIAL_SLASH] = true;
      }
      RecordPseudoHeader(TAG_PATH);
    } else if (key == "protocol") {
      RecordPseudoHeader(TAG_PROTOCOL);
    } else if (key == "scheme") {
      RecordPseudoHeader(TAG_SCHEME);
    } else {
      pseudo_headers_[TAG_UNKNOWN_EXTRA] = true;
      if (!IsValidHeaderName(key)) {
        QUICHE_VLOG(2) << "invalid chars in header name: ["
                       << absl::CEscape(key) << "]";
        return HEADER_FIELD_INVALID;
      }
    }
    if (!IsValidHeaderValue(value, obs_text_option_)) {
      QUICHE_VLOG(2) << "invalid chars in header value: ["
                     << absl::CEscape(value) << "]";
      return HEADER_FIELD_INVALID;
    }
  } else {
    std::string lowercase_key;
    if (allow_uppercase_in_header_names_) {
      // Convert header name to lowercase for validation and also for comparison
      // to lowercase string literals below.
      lowercase_key = absl::AsciiStrToLower(key);
      key = lowercase_key;
    }

    if (!IsValidHeaderName(key)) {
      QUICHE_VLOG(2) << "invalid chars in header name: [" << absl::CEscape(key)
                     << "]";
      return HEADER_FIELD_INVALID;
    }
    if (!IsValidHeaderValue(value, obs_text_option_)) {
      QUICHE_VLOG(2) << "invalid chars in header value: ["
                     << absl::CEscape(value) << "]";
      return HEADER_FIELD_INVALID;
    }
    if (key == "host") {
      if (pseudo_headers_[TAG_STATUS]) {
        // Response headers can contain "Host".
      } else {
        if (!ValidateAndSetAuthority(value)) {
          return HEADER_FIELD_INVALID;
        }
        pseudo_headers_[TAG_AUTHORITY] = true;
      }
    } else if (key == "content-length") {
      const ContentLengthStatus status = HandleContentLength(value);
      switch (status) {
        case CONTENT_LENGTH_ERROR:
          return HEADER_FIELD_INVALID;
        case CONTENT_LENGTH_SKIP:
          return HEADER_SKIP;
        case CONTENT_LENGTH_OK:
          return HEADER_OK;
        default:
          return HEADER_FIELD_INVALID;
      }
    } else if (key == "te" && value != "trailers") {
      return HEADER_FIELD_INVALID;
    } else if (key == "upgrade" || GetInvalidHttp2HeaderSet().contains(key)) {
      // TODO(b/78024822): Remove the "upgrade" here once it's added to
      // GetInvalidHttp2HeaderSet().
      return HEADER_FIELD_INVALID;
    }
  }
  return HEADER_OK;
}

// Returns true if all required pseudoheaders and no extra pseudoheaders are
// present for the given header type.
bool HeaderValidator::FinishHeaderBlock(HeaderType type) {
  switch (type) {
    case HeaderType::REQUEST:
      return ValidateRequestHeaders(pseudo_headers_, pseudo_header_state_,
                                    allow_extended_connect_);
    case HeaderType::REQUEST_TRAILER:
      return ValidateRequestTrailers(pseudo_headers_);
    case HeaderType::RESPONSE_100:
    case HeaderType::RESPONSE:
      return ValidateResponseHeaders(pseudo_headers_);
    case HeaderType::RESPONSE_TRAILER:
      return ValidateResponseTrailers(pseudo_headers_);
  }
  return false;
}

bool HeaderValidator::IsValidHeaderName(absl::string_view name) {
  static constexpr CharMap valid_chars =
      BuildValidCharMap(kHttp2HeaderNameAllowedChars);
  return AllCharsInMap(name, valid_chars);
}

bool HeaderValidator::IsValidHeaderValue(absl::string_view value,
                                         ObsTextOption option) {
  static constexpr CharMap valid_chars =
      BuildValidCharMap(kHttp2HeaderValueAllowedChars);
  static constexpr CharMap valid_chars_with_obs_text =
      AllowObsText(BuildValidCharMap(kHttp2HeaderValueAllowedChars));
  return AllCharsInMap(value, option == ObsTextOption::kAllow
                                  ? valid_chars_with_obs_text
                                  : valid_chars);
}

bool HeaderValidator::IsValidAuthority(absl::string_view authority) {
  static constexpr CharMap valid_chars =
      BuildValidCharMap(kValidAuthorityChars);
  return AllCharsInMap(authority, valid_chars);
}

bool HeaderValidator::IsValidPath(absl::string_view path, bool allow_fragment) {
  static constexpr CharMap valid_chars = BuildValidCharMap(kValidPathChars);
  static constexpr CharMap valid_chars_with_fragment =
      BuildValidCharMap(kValidPathCharsWithFragment);
  if (allow_fragment) {
    return AllCharsInMap(path, valid_chars_with_fragment);
  } else {
    return AllCharsInMap(path, valid_chars);
  }
}

HeaderValidator::ContentLengthStatus HeaderValidator::HandleContentLength(
    absl::string_view value) {
  if (value.empty()) {
    return CONTENT_LENGTH_ERROR;
  }

  if (status_ == "204" && value != "0") {
    // There should be no body in a "204 No Content" response.
    return CONTENT_LENGTH_ERROR;
  }
  if (!status_.empty() && status_[0] == '1' && value != "0") {
    // There should also be no body in a 1xx response.
    return CONTENT_LENGTH_ERROR;
  }

  size_t content_length = 0;
  const bool valid = absl::SimpleAtoi(value, &content_length);
  if (!valid) {
    return CONTENT_LENGTH_ERROR;
  }

  if (content_length_.has_value()) {
    return content_length == *content_length_ ? CONTENT_LENGTH_SKIP
                                              : CONTENT_LENGTH_ERROR;
  }
  content_length_ = content_length;
  return CONTENT_LENGTH_OK;
}

// Returns whether `authority` contains only characters from the `host` ABNF
// from RFC 3986 section 3.2.2.
bool HeaderValidator::ValidateAndSetAuthority(absl::string_view authority) {
  if (!IsValidAuthority(authority)) {
    return false;
  }
  if (!allow_different_host_and_authority_ && pseudo_headers_[TAG_AUTHORITY] &&
      authority != authority_) {
    return false;
  }
  if (!authority.empty()) {
    pseudo_header_state_[STATE_AUTHORITY_IS_NONEMPTY] = true;
    if (authority_.empty()) {
      authority_ = authority;
    } else {
      absl::StrAppend(&authority_, ", ", authority);
    }
  }
  return true;
}

bool HeaderValidator::ValidateRequestHeaders(
    const PseudoHeaderTagSet& pseudo_headers,
    const PseudoHeaderStateSet& pseudo_header_state,
    bool allow_extended_connect) {
  QUICHE_VLOG(2) << "Request pseudo-headers: [" << pseudo_headers
                 << "], pseudo_header_state: [" << pseudo_header_state
                 << "], allow_extended_connect: " << allow_extended_connect;
  if (pseudo_header_state[STATE_METHOD_IS_CONNECT]) {
    if (allow_extended_connect) {
      // See RFC 8441. Extended CONNECT should have: authority, method, path,
      // protocol and scheme pseudo-headers. The tags corresponding to status
      // and unknown_extra should not be set.
      static const auto* kExtendedConnectHeaders =
          new PseudoHeaderTagSet(0b0011111);
      if (pseudo_headers == *kExtendedConnectHeaders) {
        return true;
      }
    }
    // See RFC 7540 Section 8.3. Regular CONNECT should have authority and
    // method, but no other pseudo headers.
    static const auto* kConnectHeaders = new PseudoHeaderTagSet(0b0000011);
    return pseudo_header_state[STATE_AUTHORITY_IS_NONEMPTY] &&
           pseudo_headers == *kConnectHeaders;
  }

  if (pseudo_header_state[STATE_PATH_IS_EMPTY]) {
    return false;
  }
  if (pseudo_header_state[STATE_PATH_IS_STAR]) {
    if (!pseudo_header_state[STATE_METHOD_IS_OPTIONS]) {
      return false;
    }
  } else if (!pseudo_header_state[STATE_PATH_INITIAL_SLASH]) {
    return false;
  }

  // Regular HTTP requests require authority, method, path and scheme.
  static const auto* kRequiredHeaders = new PseudoHeaderTagSet(0b0010111);
  return pseudo_headers == *kRequiredHeaders;
}

bool HeaderValidator::ValidateRequestTrailers(
    const PseudoHeaderTagSet& pseudo_headers) {
  return pseudo_headers.none();
}

bool HeaderValidator::ValidateResponseHeaders(
    const PseudoHeaderTagSet& pseudo_headers) {
  // HTTP responses require only the status pseudo header.
  static const auto* kRequiredHeaders = new PseudoHeaderTagSet(0b0100000);
  return pseudo_headers == *kRequiredHeaders;
}

bool HeaderValidator::ValidateResponseTrailers(
    const PseudoHeaderTagSet& pseudo_headers) {
  return pseudo_headers.none();
}

}  // namespace adapter
}  // namespace http2

"""

```