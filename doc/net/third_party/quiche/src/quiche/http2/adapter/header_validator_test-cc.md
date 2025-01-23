Response:
The user wants to understand the functionality of the C++ source code file `header_validator_test.cc`. I need to:

1. **Identify the purpose of the file:** Based on the name, it's a test file for a header validator.
2. **Describe its functions:**  The file contains several test cases that validate different aspects of header validation in the HTTP/2 protocol. These tests cover things like invalid characters in header names and values, handling of pseudo-headers, specific header validation rules (like `:status`, `:authority`, `content-length`), and edge cases.
3. **Check for JavaScript relevance:**  HTTP/2 is a foundational protocol for web communication, so it indirectly relates to JavaScript's ability to make network requests. However, this specific C++ code doesn't directly interact with JavaScript. The browser's networking stack, written in C++, implements the HTTP/2 protocol, which JavaScript uses.
4. **Provide examples of logical reasoning:**  Each test case demonstrates logical reasoning. I need to pick a few representative examples and show the input (header name and value), the expected output (validation status), and the underlying logic being tested.
5. **Illustrate common usage errors:**  The tests themselves often highlight potential errors developers might make when constructing HTTP headers. I need to translate these internal test cases into scenarios a user or programmer might encounter.
6. **Explain how a user's actions reach this code:**  This involves tracing a high-level path from user interaction in a browser to the execution of this specific code within the browser's network stack.

**Mental Sandbox Simulation:**

* **JavaScript Relevance:** I can think of a scenario where a JavaScript developer incorrectly sets a header in a `fetch()` request. While the JavaScript itself doesn't execute this C++ code, the browser's underlying network stack (where this code resides) will validate the headers.
* **Logical Reasoning Example:**  The test for invalid characters in header names is a good example. Input: a header name containing a semicolon, expected output: `HEADER_FIELD_INVALID`. Logic: HTTP/2 header names have specific allowed characters.
* **User Error Example:** A user might inadvertently copy-paste a header value with a newline character. The test `ValueHasInvalidChar` covers this. The error happens in the user's data, but this code catches it.
* **User Action to Code:** User types a URL, browser initiates a request, the request headers are constructed, and *this* code validates those headers before sending.

Strategizing complete. I will now generate the response based on these points.
这个文件 `net/third_party/quiche/src/quiche/http2/adapter/header_validator_test.cc` 是 Chromium 网络栈中 QUIC 库（一个实现了 HTTP/2 和 HTTP/3 的库）的一部分，具体来说，它是 `HeaderValidator` 类的单元测试文件。 `HeaderValidator` 类的作用是验证 HTTP 头部（Headers）的有效性，确保它们符合 HTTP/2 协议规范。

**主要功能:**

1. **测试 HTTP 头部名称的有效性:**  测试各种合法的和非法的头部名称，包括空名称、包含非法字符的名称、大小写问题等。
2. **测试 HTTP 头部值的有效性:** 测试各种合法的和非法的头部值，包括空值、包含非法字符的值、是否允许 obs-text 等。
3. **测试特定伪头部的有效性:** 验证 HTTP/2 中以冒号 `:` 开头的伪头部的有效性，例如 `:authority`、`:method`、`:path`、`:scheme`、`:status` 和 `:protocol`。
4. **测试请求头部的组合和完整性:** 验证请求头部是否包含所有必需的伪头部，以及是否存在额外的或重复的伪头部。针对 CONNECT 请求和 OPTIONS 请求的特殊情况进行测试。
5. **测试响应头部的组合和完整性:** 验证响应头部是否包含必需的 `:status` 伪头部，以及针对不同状态码（如 204 和 100）的特殊规则进行测试，例如 `content-length` 的处理。
6. **测试 Trailer 头部的有效性:** 验证 Trailer 头部中是否不允许出现伪头部。
7. **测试 `content-length` 头部的有效性:** 验证 `content-length` 头部的值是否为有效的数字。
8. **测试 `te` 头部的有效性:**  验证 `te` 头部是否只允许 "trailers" 值。
9. **测试连接特定的头部:** 验证是否正确禁止了 HTTP/1.1 中连接特定的头部，例如 `connection`、`proxy-connection`、`keep-alive`、`transfer-encoding` 和 `upgrade`。
10. **测试对头部名称大小写的处理:**  测试在允许的情况下，是否能正确处理大写字母的头部名称。
11. **测试 `:authority` (或 `host`) 头部的有效性:** 验证 `:authority` 和 `host` 头部的值是否符合规范，包括域名、IPv4 和 IPv6 地址。
12. **测试 `:method` 头部的有效性:** 验证 `:method` 头部的值是否为合法的 HTTP 方法。
13. **测试 `:path` 头部的有效性:** 验证 `:path` 头部的值是否以斜杠 `/` 开头，并包含有效的字符。

**与 JavaScript 的关系:**

虽然这段 C++ 代码本身不是 JavaScript，但它直接影响着浏览器中 JavaScript 发起的网络请求的行为。当 JavaScript 使用 `fetch()` API 或 `XMLHttpRequest` 发送 HTTP 请求时，浏览器底层的网络栈会使用类似 `HeaderValidator` 这样的组件来验证请求头部。

**举例说明:**

假设 JavaScript 代码尝试发送一个带有非法头部名称的请求：

```javascript
fetch('https://example.com', {
  headers: {
    'Invalid-Header!': 'some value' // 头部名称包含非法字符 '!'
  }
});
```

当浏览器处理这个请求时，`HeaderValidator` 就会检测到 `Invalid-Header!` 中的 `!` 是不允许的字符，从而阻止请求的发送或返回一个错误。这与 `HeaderValidatorTest` 中的 `NameHasInvalidChar` 测试用例的功能类似。

**逻辑推理的假设输入与输出:**

**假设输入:**  验证一个请求头，包含以下键值对：
```
":authority": "www.example.com"
":method": "GET"
":path": "/data"
":scheme": "https"
"Content-Type": "application/json"
```

**预期输出:**  所有头部都有效，`FinishHeaderBlock(HeaderType::REQUEST)` 返回 `true`。

**另一个例子：**

**假设输入:**  验证一个请求头，包含以下键值对：
```
":authority": "www.example.com"
":method": "GET"
":path": "data"  // 缺少开头的斜杠
":scheme": "https"
```

**预期输出:** `ValidateSingleHeader(":path", "data")` 返回 `HEADER_FIELD_INVALID` (如果启用了路径验证)，或者 `FinishHeaderBlock(HeaderType::REQUEST)` 返回 `false` (如果启用了路径验证)。

**用户或编程常见的使用错误及举例说明:**

1. **在头部名称中使用空格或其他非法字符:**

   ```
   // JavaScript 代码
   fetch('https://example.com', {
     headers: {
       'Content Type': 'application/json' // 错误：头部名称包含空格
     }
   });
   ```
   `HeaderValidator` 会将 `Content Type` 识别为无效的头部名称。

2. **在头部值中使用换行符 (`\r` 或 `\n`):**

   ```
   // JavaScript 代码
   fetch('https://example.com', {
     headers: {
       'X-Custom-Info': 'Line 1\nLine 2' // 错误：头部值包含换行符
     }
   });
   ```
   `HeaderValidator` 会将包含换行符的头部值标记为无效。

3. **在请求中缺少必要的伪头部 (例如 `:authority`, `:method`, `:path`, `:scheme`):**

   ```javascript
   fetch('data', { // 错误：缺少足够的信息来构建完整的请求
     // 缺少 :authority 等信息
   });
   ```
   虽然 `fetch` API 会尝试补全一些信息，但在某些情况下，底层的 HTTP/2 实现仍然需要这些伪头部，`HeaderValidator` 会检查这些伪头部的存在。

4. **在响应中缺少 `:status` 伪头部:**

   如果服务端返回的头部中没有 `:status`，`HeaderValidator` 会认为响应头部无效。

5. **在不应该出现伪头部的场景下使用了伪头部 (例如 Trailer 头部):**

   如果 Trailer 头部中包含了类似 `:status` 这样的伪头部，`HeaderValidator` 会将其标记为错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用 Chrome 浏览器访问一个网站时遇到网络错误。以下是可能到达 `HeaderValidator` 的步骤：

1. **用户在地址栏输入 URL 并按下回车，或者点击一个链接。**
2. **浏览器解析 URL，确定目标服务器和协议（例如 HTTPS）。**
3. **浏览器（或操作系统）进行 DNS 查询，获取目标服务器的 IP 地址。**
4. **如果使用 HTTPS，浏览器会与服务器建立 TLS 连接。**
5. **浏览器构建 HTTP/2 请求头部。** 这可能涉及到：
   - 从 URL 中提取 `:authority`、`:path` 和 `:scheme`。
   - 根据请求类型设置 `:method`（GET, POST 等）。
   - 添加其他必要的请求头部，如 `User-Agent`、`Accept` 等。
   - 如果 JavaScript 代码使用了 `fetch` 或 `XMLHttpRequest`，那么 JavaScript 代码设置的头部也会被包含进来。
6. **在请求头部被发送之前，Chromium 的网络栈会使用 `HeaderValidator` 来验证这些头部的有效性。**  `HeaderValidatorTest` 中定义的各种测试用例模拟了各种可能的头部组合和错误情况。
7. **如果 `HeaderValidator` 检测到任何无效的头部，它会返回相应的错误状态。**
8. **根据错误状态，浏览器可能会：**
   - 阻止请求的发送。
   - 发送带有错误的请求（这通常会导致服务器返回错误）。
   - 向开发者工具报告错误信息。

**作为调试线索:**

当开发者或用户遇到网络问题时，可以利用以下线索进行调试：

* **浏览器开发者工具 (Network 面板):** 查看请求和响应的头部信息，检查是否存在格式错误或不符合规范的头部。
* **Chrome 的内部日志 (chrome://net-export/):**  捕获网络事件日志，可以更详细地了解请求发送过程中的头部信息和错误。
* **对比 RFC 规范:**  查阅 HTTP/2 的 RFC 文档（RFC 7540 和相关 RFC），确认头部的格式和取值是否符合规范。
* **分析 `HeaderValidatorTest` 的测试用例:**  如果怀疑是头部验证的问题，可以查看 `HeaderValidatorTest` 中的测试用例，了解哪些头部组合和字符是被允许或禁止的。这有助于理解 `HeaderValidator` 的行为，从而找到问题根源。

总而言之，`header_validator_test.cc` 文件通过大量的单元测试，确保了 `HeaderValidator` 类能够严格按照 HTTP/2 协议规范验证 HTTP 头部，从而保证了 Chromium 网络栈的健壮性和安全性。它间接地影响着 JavaScript 发起的网络请求的成功与否。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/header_validator_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
#include "quiche/http2/adapter/header_validator.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/str_cat.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {

using ::testing::Optional;

using Header = std::pair<absl::string_view, absl::string_view>;
constexpr Header kSampleRequestPseudoheaders[] = {{":authority", "www.foo.com"},
                                                  {":method", "GET"},
                                                  {":path", "/foo"},
                                                  {":scheme", "https"}};

TEST(HeaderValidatorTest, HeaderNameEmpty) {
  HeaderValidator v;
  HeaderValidator::HeaderStatus status = v.ValidateSingleHeader("", "value");
  EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID, status);
}

TEST(HeaderValidatorTest, HeaderValueEmpty) {
  HeaderValidator v;
  HeaderValidator::HeaderStatus status = v.ValidateSingleHeader("name", "");
  EXPECT_EQ(HeaderValidator::HEADER_OK, status);
}

TEST(HeaderValidatorTest, ExceedsMaxSize) {
  HeaderValidator v;
  v.SetMaxFieldSize(64u);
  HeaderValidator::HeaderStatus status =
      v.ValidateSingleHeader("name", "value");
  EXPECT_EQ(HeaderValidator::HEADER_OK, status);
  status = v.ValidateSingleHeader(
      "name2",
      "Antidisestablishmentariansism is supercalifragilisticexpialodocious.");
  EXPECT_EQ(HeaderValidator::HEADER_FIELD_TOO_LONG, status);
}

TEST(HeaderValidatorTest, NameHasInvalidChar) {
  HeaderValidator v;
  for (const bool is_pseudo_header : {true, false}) {
    // These characters should be allowed. (Not exhaustive.)
    for (const char* c : {"!", "3", "a", "_", "|", "~"}) {
      const std::string name = is_pseudo_header ? absl::StrCat(":met", c, "hod")
                                                : absl::StrCat("na", c, "me");
      HeaderValidator::HeaderStatus status =
          v.ValidateSingleHeader(name, "value");
      EXPECT_EQ(HeaderValidator::HEADER_OK, status);
    }
    // These should not. (Not exhaustive.)
    for (const char* c : {"\\", "<", ";", "[", "=", " ", "\r", "\n", ",", "\"",
                          "\x1F", "\x91"}) {
      const std::string name = is_pseudo_header ? absl::StrCat(":met", c, "hod")
                                                : absl::StrCat("na", c, "me");
      HeaderValidator::HeaderStatus status =
          v.ValidateSingleHeader(name, "value");
      EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID, status)
          << "with name [" << name << "]";
    }
    // Test nul separately.
    {
      const absl::string_view name = is_pseudo_header
                                         ? absl::string_view(":met\0hod", 8)
                                         : absl::string_view("na\0me", 5);
      HeaderValidator::HeaderStatus status =
          v.ValidateSingleHeader(name, "value");
      EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID, status);
    }
    // Uppercase characters in header names should not be allowed.
    const std::string uc_name = is_pseudo_header ? ":Method" : "Name";
    HeaderValidator::HeaderStatus status =
        v.ValidateSingleHeader(uc_name, "value");
    EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID, status);
  }
}

TEST(HeaderValidatorTest, ValueHasInvalidChar) {
  HeaderValidator v;
  // These characters should be allowed. (Not exhaustive.)
  for (const char* c :
       {"!", "3", "a", "_", "|", "~", "\\", "<", ";", "[", "=", "A", "\t"}) {
    const std::string value = absl::StrCat("val", c, "ue");
    EXPECT_TRUE(
        HeaderValidator::IsValidHeaderValue(value, ObsTextOption::kDisallow));
    HeaderValidator::HeaderStatus status =
        v.ValidateSingleHeader("name", value);
    EXPECT_EQ(HeaderValidator::HEADER_OK, status);
  }
  // These should not.
  for (const char* c : {"\r", "\n"}) {
    const std::string value = absl::StrCat("val", c, "ue");
    EXPECT_FALSE(
        HeaderValidator::IsValidHeaderValue(value, ObsTextOption::kDisallow));
    HeaderValidator::HeaderStatus status =
        v.ValidateSingleHeader("name", value);
    EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID, status);
  }
  // Test nul separately.
  {
    const std::string value("val\0ue", 6);
    EXPECT_FALSE(
        HeaderValidator::IsValidHeaderValue(value, ObsTextOption::kDisallow));
    HeaderValidator::HeaderStatus status =
        v.ValidateSingleHeader("name", value);
    EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID, status);
  }
  {
    const std::string obs_text_value = "val\xa9ue";
    // Test that obs-text is disallowed by default.
    EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
              v.ValidateSingleHeader("name", obs_text_value));
    // Test that obs-text is disallowed when configured.
    v.SetObsTextOption(ObsTextOption::kDisallow);
    EXPECT_FALSE(HeaderValidator::IsValidHeaderValue(obs_text_value,
                                                     ObsTextOption::kDisallow));
    EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
              v.ValidateSingleHeader("name", obs_text_value));
    // Test that obs-text is allowed when configured.
    v.SetObsTextOption(ObsTextOption::kAllow);
    EXPECT_TRUE(HeaderValidator::IsValidHeaderValue(obs_text_value,
                                                    ObsTextOption::kAllow));
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader("name", obs_text_value));
  }
}

TEST(HeaderValidatorTest, StatusHasInvalidChar) {
  HeaderValidator v;

  for (HeaderType type : {HeaderType::RESPONSE, HeaderType::RESPONSE_100}) {
    // When `:status` has a non-digit value, validation will fail.
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
              v.ValidateSingleHeader(":status", "bar"));
    EXPECT_FALSE(v.FinishHeaderBlock(type));

    // When `:status` is too short, validation will fail.
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
              v.ValidateSingleHeader(":status", "10"));
    EXPECT_FALSE(v.FinishHeaderBlock(type));

    // When `:status` is too long, validation will fail.
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
              v.ValidateSingleHeader(":status", "9000"));
    EXPECT_FALSE(v.FinishHeaderBlock(type));

    // When `:status` is just right, validation will succeed.
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":status", "400"));
    EXPECT_TRUE(v.FinishHeaderBlock(type));
  }
}

TEST(HeaderValidatorTest, AuthorityHasInvalidChar) {
  for (absl::string_view key : {":authority", "host"}) {
    // These characters should be allowed. (Not exhaustive.)
    for (const absl::string_view c : {"1", "-", "!", ":", "+", "=", ","}) {
      const std::string value = absl::StrCat("ho", c, "st.example.com");
      EXPECT_TRUE(HeaderValidator::IsValidAuthority(value));

      HeaderValidator v;
      v.StartHeaderBlock();
      HeaderValidator::HeaderStatus status = v.ValidateSingleHeader(key, value);
      EXPECT_EQ(HeaderValidator::HEADER_OK, status)
          << " with name [" << key << "] and value [" << value << "]";
    }
    // These should not.
    for (const absl::string_view c : {"\r", "\n", "|", "\\", "`"}) {
      const std::string value = absl::StrCat("ho", c, "st.example.com");
      EXPECT_FALSE(HeaderValidator::IsValidAuthority(value));

      HeaderValidator v;
      v.StartHeaderBlock();
      HeaderValidator::HeaderStatus status = v.ValidateSingleHeader(key, value);
      EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID, status);
    }

    {
      // IPv4 example
      const std::string value = "123.45.67.89";
      EXPECT_TRUE(HeaderValidator::IsValidAuthority(value));

      HeaderValidator v;
      v.StartHeaderBlock();
      HeaderValidator::HeaderStatus status = v.ValidateSingleHeader(key, value);
      EXPECT_EQ(HeaderValidator::HEADER_OK, status);
    }

    {
      // IPv6 examples
      const std::string value1 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
      EXPECT_TRUE(HeaderValidator::IsValidAuthority(value1));

      HeaderValidator v;
      v.StartHeaderBlock();
      HeaderValidator::HeaderStatus status =
          v.ValidateSingleHeader(key, value1);
      EXPECT_EQ(HeaderValidator::HEADER_OK, status);

      const std::string value2 = "[::1]:80";
      EXPECT_TRUE(HeaderValidator::IsValidAuthority(value2));
      HeaderValidator v2;
      v2.StartHeaderBlock();
      status = v2.ValidateSingleHeader(key, value2);
      EXPECT_EQ(HeaderValidator::HEADER_OK, status);
    }

    {
      // Empty field
      EXPECT_TRUE(HeaderValidator::IsValidAuthority(""));

      HeaderValidator v;
      v.StartHeaderBlock();
      HeaderValidator::HeaderStatus status = v.ValidateSingleHeader(key, "");
      EXPECT_EQ(HeaderValidator::HEADER_OK, status);
    }
  }
}

TEST(HeaderValidatorTest, RequestHostAndAuthority) {
  HeaderValidator v;
  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(to_add.first, to_add.second));
  }
  // If both "host" and ":authority" have the same value, validation succeeds.
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("host", "www.foo.com"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));

  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(to_add.first, to_add.second));
  }
  // If "host" and ":authority" have different values, validation fails.
  EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
            v.ValidateSingleHeader("host", "www.bar.com"));
}

TEST(HeaderValidatorTest, RequestHostAndAuthorityLax) {
  HeaderValidator v;
  v.SetAllowDifferentHostAndAuthority();
  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(to_add.first, to_add.second));
  }
  // Since the option is set, validation succeeds even if "host" and
  // ":authority" have different values.
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("host", "www.bar.com"));
}

TEST(HeaderValidatorTest, MethodHasInvalidChar) {
  HeaderValidator v;
  v.StartHeaderBlock();

  std::vector<absl::string_view> bad_methods = {
      "In[]valid{}",   "co,mma", "spac e",     "a@t",    "equals=",
      "question?mark", "co:lon", "semi;colon", "sla/sh", "back\\slash",
  };

  std::vector<absl::string_view> good_methods = {
      "lowercase",   "MiXeDcAsE", "NONCANONICAL", "HASH#",
      "under_score", "PI|PE",     "Tilde~",       "quote'",
  };

  for (absl::string_view value : bad_methods) {
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
              v.ValidateSingleHeader(":method", value));
  }

  for (absl::string_view value : good_methods) {
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":method", value));
    for (Header to_add : kSampleRequestPseudoheaders) {
      if (to_add.first == ":method") {
        continue;
      }
      EXPECT_EQ(HeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, to_add.second));
    }
    EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));
  }
}

TEST(HeaderValidatorTest, RequestPseudoHeaders) {
  HeaderValidator v;
  for (Header to_skip : kSampleRequestPseudoheaders) {
    v.StartHeaderBlock();
    for (Header to_add : kSampleRequestPseudoheaders) {
      if (to_add != to_skip) {
        EXPECT_EQ(HeaderValidator::HEADER_OK,
                  v.ValidateSingleHeader(to_add.first, to_add.second));
      }
    }
    // When any pseudo-header is missing, final validation will fail.
    EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::REQUEST));
  }

  // When all pseudo-headers are present, final validation will succeed.
  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(to_add.first, to_add.second));
  }
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));

  // When an extra pseudo-header is present, final validation will fail.
  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(to_add.first, to_add.second));
  }
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":extra", "blah"));
  EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::REQUEST));

  // When a required pseudo-header is repeated, final validation will fail.
  for (Header to_repeat : kSampleRequestPseudoheaders) {
    v.StartHeaderBlock();
    for (Header to_add : kSampleRequestPseudoheaders) {
      EXPECT_EQ(HeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, to_add.second));
      if (to_add == to_repeat) {
        EXPECT_EQ(HeaderValidator::HEADER_OK,
                  v.ValidateSingleHeader(to_add.first, to_add.second));
      }
    }
    EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::REQUEST));
  }
}

TEST(HeaderValidatorTest, ConnectHeaders) {
  // Too few headers.
  HeaderValidator v;
  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":authority", "athena.dialup.mit.edu:23"));
  EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::REQUEST));

  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":method", "CONNECT"));
  EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::REQUEST));

  // Too many headers.
  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":authority", "athena.dialup.mit.edu:23"));
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":method", "CONNECT"));
  EXPECT_EQ(HeaderValidator::HEADER_OK, v.ValidateSingleHeader(":path", "/"));
  EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::REQUEST));

  // Empty :authority
  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":authority", ""));
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":method", "CONNECT"));
  EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::REQUEST));

  // Just right.
  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":authority", "athena.dialup.mit.edu:23"));
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":method", "CONNECT"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));

  v.SetAllowExtendedConnect();
  // "Classic" CONNECT headers should still be accepted.
  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":authority", "athena.dialup.mit.edu:23"));
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":method", "CONNECT"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));
}

TEST(HeaderValidatorTest, WebsocketPseudoHeaders) {
  HeaderValidator v;
  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(to_add.first, to_add.second));
  }
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":protocol", "websocket"));
  // At this point, `:protocol` is treated as an extra pseudo-header.
  EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::REQUEST));

  // Future header blocks may send the `:protocol` pseudo-header for CONNECT
  // requests.
  v.SetAllowExtendedConnect();

  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(to_add.first, to_add.second));
  }
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":protocol", "websocket"));
  // The method is not "CONNECT", so `:protocol` is still treated as an extra
  // pseudo-header.
  EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::REQUEST));

  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    if (to_add.first == ":method") {
      EXPECT_EQ(HeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, "CONNECT"));
    } else {
      EXPECT_EQ(HeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, to_add.second));
    }
  }
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":protocol", "websocket"));
  // After allowing the method, `:protocol` is acepted for CONNECT requests.
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));
}

TEST(HeaderValidatorTest, AsteriskPathPseudoHeader) {
  HeaderValidator v;

  // An asterisk :path should not be allowed for non-OPTIONS requests.
  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    if (to_add.first == ":path") {
      EXPECT_EQ(HeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, "*"));
    } else {
      EXPECT_EQ(HeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, to_add.second));
    }
  }
  EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::REQUEST));

  // An asterisk :path should be allowed for OPTIONS requests.
  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    if (to_add.first == ":path") {
      EXPECT_EQ(HeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, "*"));
    } else if (to_add.first == ":method") {
      EXPECT_EQ(HeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, "OPTIONS"));
    } else {
      EXPECT_EQ(HeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, to_add.second));
    }
  }
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));
}

TEST(HeaderValidatorTest, InvalidPathPseudoHeader) {
  HeaderValidator v;

  // An empty path should fail on single header validation and finish.
  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    if (to_add.first == ":path") {
      EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
                v.ValidateSingleHeader(to_add.first, ""));
    } else {
      EXPECT_EQ(HeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, to_add.second));
    }
  }
  EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::REQUEST));

  // The remainder of the checks require enabling path validation.
  v.SetValidatePath();

  // A path that does not start with a slash should fail on finish.
  v.StartHeaderBlock();
  for (Header to_add : kSampleRequestPseudoheaders) {
    if (to_add.first == ":path") {
      EXPECT_EQ(HeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, "shawarma"));
    } else {
      EXPECT_EQ(HeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add.first, to_add.second));
    }
  }
  EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::REQUEST));

  // Various valid path characters.
  for (const absl::string_view c :
       {"/", "?", "_", "'", "9", "&", "(", "@", ":"}) {
    const std::string value = absl::StrCat("/shawa", c, "rma");

    HeaderValidator validator;
    validator.SetValidatePath();
    validator.StartHeaderBlock();
    for (Header to_add : kSampleRequestPseudoheaders) {
      if (to_add.first == ":path") {
        EXPECT_EQ(HeaderValidator::HEADER_OK,
                  validator.ValidateSingleHeader(to_add.first, value))
            << "Problematic char: [" << c << "]";
      } else {
        EXPECT_EQ(HeaderValidator::HEADER_OK,
                  validator.ValidateSingleHeader(to_add.first, to_add.second));
      }
    }
    EXPECT_TRUE(validator.FinishHeaderBlock(HeaderType::REQUEST));
  }

  // Various invalid path characters.
  for (const absl::string_view c : {"[", "<", "}", "`", "\\", " ", "\t", "#"}) {
    const std::string value = absl::StrCat("/shawa", c, "rma");

    HeaderValidator validator;
    validator.SetValidatePath();
    validator.StartHeaderBlock();
    for (Header to_add : kSampleRequestPseudoheaders) {
      if (to_add.first == ":path") {
        EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
                  validator.ValidateSingleHeader(to_add.first, value));
      } else {
        EXPECT_EQ(HeaderValidator::HEADER_OK,
                  validator.ValidateSingleHeader(to_add.first, to_add.second));
      }
    }
    EXPECT_FALSE(validator.FinishHeaderBlock(HeaderType::REQUEST));
  }

  // The fragment initial character can be explicitly allowed.
  {
    HeaderValidator validator;
    validator.SetValidatePath();
    validator.SetAllowFragmentInPath();
    validator.StartHeaderBlock();
    for (Header to_add : kSampleRequestPseudoheaders) {
      if (to_add.first == ":path") {
        EXPECT_EQ(HeaderValidator::HEADER_OK,
                  validator.ValidateSingleHeader(to_add.first, "/shawa#rma"));
      } else {
        EXPECT_EQ(HeaderValidator::HEADER_OK,
                  validator.ValidateSingleHeader(to_add.first, to_add.second));
      }
    }
    EXPECT_TRUE(validator.FinishHeaderBlock(HeaderType::REQUEST));
  }
}

TEST(HeaderValidatorTest, ResponsePseudoHeaders) {
  HeaderValidator v;

  for (HeaderType type : {HeaderType::RESPONSE, HeaderType::RESPONSE_100}) {
    // When `:status` is missing, validation will fail.
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_OK, v.ValidateSingleHeader("foo", "bar"));
    EXPECT_FALSE(v.FinishHeaderBlock(type));

    // When all pseudo-headers are present, final validation will succeed.
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":status", "199"));
    EXPECT_TRUE(v.FinishHeaderBlock(type));
    EXPECT_EQ("199", v.status_header());

    // When `:status` is repeated, validation will fail.
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":status", "199"));
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":status", "299"));
    EXPECT_FALSE(v.FinishHeaderBlock(type));

    // When an extra pseudo-header is present, final validation will fail.
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":status", "199"));
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":extra", "blorp"));
    EXPECT_FALSE(v.FinishHeaderBlock(type));
  }
}

TEST(HeaderValidatorTest, ResponseWithHost) {
  HeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "200"));
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("host", "myserver.com"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::RESPONSE));
}

TEST(HeaderValidatorTest, Response204) {
  HeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "204"));
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("x-content", "is not present"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::RESPONSE));
}

TEST(HeaderValidatorTest, ResponseWithMultipleIdenticalContentLength) {
  HeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "200"));
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "13"));
  EXPECT_EQ(HeaderValidator::HEADER_SKIP,
            v.ValidateSingleHeader("content-length", "13"));
}

TEST(HeaderValidatorTest, ResponseWithMultipleDifferingContentLength) {
  HeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "200"));
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "13"));
  EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
            v.ValidateSingleHeader("content-length", "17"));
}

TEST(HeaderValidatorTest, Response204WithContentLengthZero) {
  HeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "204"));
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("x-content", "is not present"));
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "0"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::RESPONSE));
}

TEST(HeaderValidatorTest, Response204WithContentLength) {
  HeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "204"));
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("x-content", "is not present"));
  EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
            v.ValidateSingleHeader("content-length", "1"));
}

TEST(HeaderValidatorTest, Response100) {
  HeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "100"));
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("x-content", "is not present"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::RESPONSE));
}

TEST(HeaderValidatorTest, Response100WithContentLengthZero) {
  HeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "100"));
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("x-content", "is not present"));
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "0"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::RESPONSE));
}

TEST(HeaderValidatorTest, Response100WithContentLength) {
  HeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "100"));
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("x-content", "is not present"));
  EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
            v.ValidateSingleHeader("content-length", "1"));
}

TEST(HeaderValidatorTest, ResponseTrailerPseudoHeaders) {
  HeaderValidator v;

  // When no pseudo-headers are present, validation will succeed.
  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK, v.ValidateSingleHeader("foo", "bar"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::RESPONSE_TRAILER));

  // When any pseudo-header is present, final validation will fail.
  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "200"));
  EXPECT_EQ(HeaderValidator::HEADER_OK, v.ValidateSingleHeader("foo", "bar"));
  EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::RESPONSE_TRAILER));
}

TEST(HeaderValidatorTest, ValidContentLength) {
  HeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(v.content_length(), std::nullopt);
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "41"));
  EXPECT_THAT(v.content_length(), Optional(41));

  v.StartHeaderBlock();
  EXPECT_EQ(v.content_length(), std::nullopt);
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "42"));
  EXPECT_THAT(v.content_length(), Optional(42));
}

TEST(HeaderValidatorTest, InvalidContentLength) {
  HeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(v.content_length(), std::nullopt);
  EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
            v.ValidateSingleHeader("content-length", ""));
  EXPECT_EQ(v.content_length(), std::nullopt);
  EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
            v.ValidateSingleHeader("content-length", "nan"));
  EXPECT_EQ(v.content_length(), std::nullopt);
  EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
            v.ValidateSingleHeader("content-length", "-42"));
  EXPECT_EQ(v.content_length(), std::nullopt);
  // End on a positive note.
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "42"));
  EXPECT_THAT(v.content_length(), Optional(42));
}

TEST(HeaderValidatorTest, TeHeader) {
  HeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("te", "trailers"));

  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
            v.ValidateSingleHeader("te", "trailers, deflate"));
}

TEST(HeaderValidatorTest, ConnectionSpecificHeaders) {
  const std::vector<Header> connection_headers = {
      {"connection", "keep-alive"}, {"proxy-connection", "keep-alive"},
      {"keep-alive", "timeout=42"}, {"transfer-encoding", "chunked"},
      {"upgrade", "h2c"},
  };
  for (const auto& [connection_key, connection_value] : connection_headers) {
    HeaderValidator v;
    v.StartHeaderBlock();
    for (const auto& [sample_key, sample_value] : kSampleRequestPseudoheaders) {
      EXPECT_EQ(HeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(sample_key, sample_value));
    }
    EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
              v.ValidateSingleHeader(connection_key, connection_value));
  }
}

TEST(HeaderValidatorTest, MixedCaseHeaderName) {
  HeaderValidator v;
  v.SetAllowUppercaseInHeaderNames();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("MixedCaseName", "value"));
}

// SetAllowUppercaseInHeaderNames() only applies to non-pseudo-headers.
TEST(HeaderValidatorTest, MixedCasePseudoHeader) {
  HeaderValidator v;
  v.SetAllowUppercaseInHeaderNames();
  EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
            v.ValidateSingleHeader(":PATH", "/"));
}

// Matching `host` is case-insensitive.
TEST(HeaderValidatorTest, MixedCaseHost) {
  HeaderValidator v;
  v.SetAllowUppercaseInHeaderNames();
  for (Header to_add : kSampleRequestPseudoheaders) {
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(to_add.first, to_add.second));
  }
  // Validation fails, because "host" and ":authority" have different values.
  EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
            v.ValidateSingleHeader("Host", "www.bar.com"));
}

// Matching `content-length` is case-insensitive.
TEST(HeaderValidatorTest, MixedCaseContentLength) {
  HeaderValidator v;
  v.SetAllowUppercaseInHeaderNames();
  EXPECT_EQ(v.content_length(), std::nullopt);
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("Content-Length", "42"));
  EXPECT_THAT(v.content_length(), Optional(42));
}

}  // namespace test
}  // namespace adapter
}  // namespace http2
```