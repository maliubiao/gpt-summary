Response:
Let's break down the thought process for analyzing this C++ unit test file.

1. **Identify the Core Functionality:** The filename `http_security_headers_unittest.cc` and the included header `net/http/http_security_headers.h` immediately suggest that this file tests the parsing and handling of HTTP security headers. Specifically, the presence of `ParseHSTSHeader` and the various test cases indicate a focus on the HTTP Strict Transport Security (HSTS) header.

2. **Understand the Purpose of Unit Tests:** Unit tests are designed to isolate and verify the behavior of small, independent units of code. In this case, the unit is likely the `ParseHSTSHeader` function. The goal is to ensure this function correctly parses different variations of the HSTS header string.

3. **Analyze the Test Structure:** The code uses the Google Test framework (`testing/gtest/include/gtest/gtest.h`). This tells us we'll see test fixtures (`HttpSecurityHeadersTest`) and individual test cases (`TEST_F`).

4. **Examine Individual Test Cases:**  Now, go through each `TEST_F` function:

    * **`LeadingTrailingSemicolons`:** The name clearly indicates the test's focus. The `test_cases` array contains strings with various leading, trailing, and multiple semicolons. The assertions (`EXPECT_TRUE`, `EXPECT_EQ`, `EXPECT_FALSE`) check that the parser handles these semicolons correctly. The parser should extract `max-age` and `include_subdomains` accurately despite the extra semicolons.

    * **`InvalidDirectiveNames`:**  This test aims to check how the parser handles malformed directive names within the HSTS header. The `test_cases` array contains strings with invalid characters, duplicates, and incorrect casing. The expectation (`EXPECT_FALSE`) is that the parser rejects these invalid headers.

    * **`InvalidDirectiveValues`:** Similar to the previous test, but focuses on invalid values associated with directives. The test cases include missing values, incorrect characters, and unexpected data types for `max-age` and `includeSubdomains`. The expectation is that parsing fails.

    * **`BogusHeaders`:** This test is designed to throw a wide variety of completely invalid HSTS header strings at the parser. It checks for handling of empty strings, whitespace, incorrect keywords, missing equals signs, and non-numeric `max-age` values. Again, the expected outcome is parsing failure.

    * **`ValidSTSHeaders`:** This is the "happy path" test. It verifies that the parser correctly extracts the `max-age` and `include_subdomains` values from correctly formatted HSTS headers, including variations in capitalization, whitespace, and the order of directives. It also tests the upper bound of `max-age`.

5. **Look for Interactions with JavaScript (and the Web Platform):** HSTS is a web standard that directly affects how browsers interact with websites. While this C++ code doesn't *execute* JavaScript, its purpose is to parse and interpret a header sent *by* a web server and *used by* the browser. This means there's a clear relationship:

    * A web server sends the `Strict-Transport-Security` header.
    * The Chromium network stack (where this code resides) receives this header.
    * The `ParseHSTSHeader` function processes the header.
    * Based on the parsed values, Chromium will enforce HSTS policies, which directly influences how JavaScript running on a web page can interact with the server (e.g., forcing HTTPS connections).

6. **Consider Logic and Assumptions:**  The core logic being tested is the parsing algorithm itself. The assumptions are that the input string is the value of the `Strict-Transport-Security` header and that the output should correctly represent the `max-age` and `include_subdomains` directives.

7. **Think About User Errors and Debugging:**  Users don't directly interact with this C++ code. However, *developers* of web servers might misconfigure the `Strict-Transport-Security` header. This unit test helps ensure Chromium correctly handles those misconfigurations. For debugging, understanding how a malformed header is processed (and potentially rejected) is crucial. The test cases themselves serve as examples of common errors.

8. **Trace User Interaction (Debugging Clues):**  Imagine a user visiting a website:

    * The user types a URL in the address bar or clicks a link.
    * The browser sends an HTTP request to the server.
    * The server responds with an HTTP response, including the `Strict-Transport-Security` header.
    * The Chromium networking stack receives and parses this header using code involving `ParseHSTSHeader`.
    * If parsing fails (as tested in the "Invalid..." and "BogusHeaders" tests), the HSTS policy might not be applied, or an error might be logged internally.
    * If parsing succeeds (as in "ValidSTSHeaders"), the browser will remember the HSTS policy and enforce HTTPS for future visits to that domain.

9. **Refine and Organize the Analysis:**  Finally, structure the analysis into clear sections addressing the prompt's specific questions: functionality, relationship to JavaScript, logical reasoning (with input/output examples), common errors, and debugging clues. Use clear and concise language.

This detailed thought process allows for a thorough understanding of the code's purpose and its role within the larger Chromium project and the web ecosystem.
这个文件 `net/http/http_security_headers_unittest.cc` 是 Chromium 网络栈的一部分，它的主要功能是**测试 HTTP 安全头部的解析功能，特别是 HTTP Strict Transport Security (HSTS) 头部。**

以下是更详细的功能说明：

**1. 测试 `ParseHSTSHeader` 函数:**

   - 该文件中的测试用例主要围绕 `ParseHSTSHeader` 函数展开。这个函数的功能是将 `Strict-Transport-Security` HTTP 响应头的值解析成结构化的数据，包括 `max-age` 指令（HSTS 策略的有效期）和 `includeSubdomains` 指令（是否将 HSTS 策略应用于子域名）。

**2. 覆盖各种 HSTS 头部格式:**

   - **有效格式:** 测试用例中包含了各种有效的 `Strict-Transport-Security` 头部格式，例如包含 `max-age`、`includeSubdomains`，以及它们的不同顺序和大小写组合。
   - **带有前导/尾随分号:**  测试了头部值中存在多余的前导和尾随分号的情况，验证解析器是否能正确处理。
   - **无效的指令名称:** 测试了包含无效指令名称的情况，例如包含引号、特殊字符或重复的指令。
   - **无效的指令值:** 测试了指令值无效的情况，例如 `max-age` 不是数字，或者 `includeSubdomains` 带有不期望的值。
   - **格式错误的头部:**  测试了各种完全错误的头部格式，例如缺少等号、只有指令名没有值、包含非法字符等。

**3. 验证解析结果:**

   - 每个测试用例都使用 `EXPECT_TRUE` 和 `EXPECT_FALSE` 来断言 `ParseHSTSHeader` 函数的返回值是否符合预期（解析成功或失败）。
   - 对于成功的解析，使用 `EXPECT_EQ` 来验证解析出的 `max_age` 和 `include_subdomains` 值是否正确。

**与 JavaScript 的关系：**

虽然这个 C++ 代码本身不包含 JavaScript 代码，但它直接影响浏览器如何处理来自服务器的 HTTP 安全头部，从而**间接影响 JavaScript 的行为**。

**举例说明:**

假设一个网站的服务器发送了以下 `Strict-Transport-Security` 头部：

```
Strict-Transport-Security: max-age=31536000; includeSubdomains
```

1. **浏览器接收到头部:** 当浏览器加载该网站的页面时，会接收到这个 HTTP 响应头。
2. **C++ 代码解析头部:** Chromium 的网络栈会使用 `ParseHSTSHeader` 函数解析这个头部。根据这个文件中的测试，该函数应该能成功解析出 `max_age` 为 31536000 秒，并且 `include_subdomains` 为 true。
3. **浏览器应用 HSTS 策略:**  解析成功后，浏览器会记住该网站的 HSTS 策略。在 `max_age` 指定的时间内，以及对于该网站的所有子域名，浏览器会：
   - **自动将 HTTP 请求升级为 HTTPS 请求:**  如果 JavaScript 代码尝试通过 `http://` URL 发起请求到该网站或其子域名，浏览器会自动将其转换为 `https://`。
   - **阻止用户忽略 HTTPS 证书错误:** 如果 HTTPS 连接存在证书问题，浏览器会阻止用户继续访问，即使 JavaScript 代码尝试通过某些方式绕过。

**JavaScript 的影响举例:**

```javascript
// 在启用了 HSTS 的网站上执行
fetch('http://example.com/api') // 浏览器会自动将其转换为 https://example.com/api
  .then(response => response.json())
  .then(data => console.log(data));

// 如果 example.com 的 HSTS 策略包含 includeSubdomains
fetch('http://sub.example.com/data') // 浏览器也会自动转换为 https://sub.example.com/data
  .then(response => response.text())
  .then(text => console.log(text));
```

如果 `ParseHSTSHeader` 函数存在 bug，未能正确解析 HSTS 头部，那么浏览器可能无法正确应用 HSTS 策略，从而导致 JavaScript 代码发起的 HTTP 请求不会被升级到 HTTPS，降低了网站的安全性。

**逻辑推理（假设输入与输出）：**

**假设输入:**

```
"max-age=600; includeSubdomains"
```

**预期输出 (通过 `ParseHSTSHeader` 解析后):**

- `max_age`:  一个表示 600 秒的 `base::TimeDelta` 对象。
- `include_subdomains`: `true`

**假设输入 (无效格式):**

```
"max-age=abc"
```

**预期输出:**

- `ParseHSTSHeader` 函数返回 `false`。
- `max_age` 和 `include_subdomains` 的值保持不变（或者被设置为默认值，具体取决于实现）。

**用户或编程常见的使用错误举例:**

**用户错误 (非直接，更多是服务器配置错误):**

1. **忘记配置 HTTPS:** 用户访问一个本应该启用 HSTS 的网站，但服务器没有正确配置 HTTPS，或者没有将 HTTP 请求重定向到 HTTPS。这时即使浏览器收到了 HSTS 头部，也只是在第一次 HTTPS 访问后生效，之前的 HTTP 访问仍然存在安全风险。
2. **配置错误的 `max-age`:**  网站管理员设置了一个过短的 `max-age` 值，导致浏览器很快忘记 HSTS 策略，用户在策略失效后再次通过 HTTP 访问时，仍然面临中间人攻击的风险。
3. **`includeSubdomains` 使用不当:**  网站管理员在主域名上启用了 `includeSubdomains`，但某些子域名可能还没有完全支持 HTTPS，这会导致这些子域名无法访问。

**编程错误 (服务器端):**

1. **拼写错误:**  在服务器配置中错误地拼写了头部名称 (`Strict-Transport-Securit` 而不是 `Strict-Transport-Security`)，或者指令名称 (`includesubdomain` 而不是 `includeSubdomains`)。这将导致浏览器无法识别该头部。
2. **语法错误:**  HTTP 头部的值需要遵循特定的语法。例如，忘记使用等号连接指令和值 (`max-age 3600`)，或者使用了错误的字符。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户在浏览器地址栏输入一个 URL 或点击一个链接。**
2. **浏览器向目标服务器发送 HTTP(S) 请求。**
3. **服务器处理请求并返回 HTTP 响应，其中可能包含 `Strict-Transport-Security` 头部。**
4. **Chromium 的网络栈接收到这个 HTTP 响应。**
5. **网络栈中的代码会检查是否存在 `Strict-Transport-Security` 头部。**
6. **如果存在，`net/http/http_security_headers.cc` 文件中的 `ParseHSTSHeader` 函数会被调用，解析该头部的值。**

**调试线索:**

- **如果用户报告网站连接不是 HTTPS，即使该网站应该强制使用 HTTPS，** 可能是因为服务器没有发送有效的 `Strict-Transport-Security` 头部，或者 `ParseHSTSHeader` 函数未能正确解析该头部。
- **可以使用浏览器的开发者工具 (Network 标签) 查看服务器返回的 HTTP 响应头，确认是否存在 `Strict-Transport-Security` 头部以及它的值。**
- **在 Chromium 的源代码中，可以设置断点在 `ParseHSTSHeader` 函数内部，查看头部的值是如何被解析的，以及解析的结果。**
- **如果怀疑是解析逻辑的问题，可以参考 `net/http/http_security_headers_unittest.cc` 中的测试用例，看看是否有类似的错误情况没有被覆盖到，或者测试用例本身存在问题。**

总而言之，`net/http/http_security_headers_unittest.cc` 文件通过大量的测试用例，确保了 Chromium 能够可靠地解析 HTTP Strict Transport Security 头部，这对于保障用户的网络安全至关重要，并且间接地影响了 JavaScript 在浏览器中的行为。

Prompt: 
```
这是目录为net/http/http_security_headers_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_security_headers.h"

#include <stdint.h>

#include <iterator>

#include "base/base64.h"
#include "base/stl_util.h"
#include "crypto/sha2.h"
#include "net/base/host_port_pair.h"
#include "net/base/test_completion_callback.h"
#include "net/http/http_util.h"
#include "net/http/transport_security_state.h"
#include "net/ssl/ssl_info.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

namespace test_default {
#include "base/time/time.h"
#include "net/http/transport_security_state_static_unittest_default.h"
}

}  // anonymous namespace

class HttpSecurityHeadersTest : public testing::Test {
 public:
  ~HttpSecurityHeadersTest() override {
    SetTransportSecurityStateSourceForTesting(nullptr);
  }
};

TEST_F(HttpSecurityHeadersTest, LeadingTrailingSemicolons) {
  base::TimeDelta max_age;
  bool include_subdomains = false;

  const char* test_cases[] = {
      "max-age=123",       ";max-age=123",        ";;max-age=123",
      ";;;;max-age=123",   "; ;max-age=123",      "; ; max-age=123",
      ";max-age=123;",     ";;max-age=123;;",     ";;;;max-age=123;;;;",
      "; ;max-age=123; ;", "; ; max-age=123; ; ", "max-age=123;",
      "max-age=123;;",     "max-age=123;;;;",     "max-age=123; ;",
      "max-age=123; ; ",
  };
  for (const char* value : test_cases) {
    SCOPED_TRACE(value);
    EXPECT_TRUE(ParseHSTSHeader(value, &max_age, &include_subdomains));
    EXPECT_EQ(base::Seconds(123), max_age);
    EXPECT_FALSE(include_subdomains);
  }
}

TEST_F(HttpSecurityHeadersTest, InvalidDirectiveNames) {
  base::TimeDelta max_age;
  bool include_subdomains = false;

  const char* test_cases[] = {
      "'max-age'=1",
      "\"max-age\"=1",
      "max-age=1; max-age=2",
      "max-age=1; MaX-AgE=2",
      "max-age=1; includeSubDomains; iNcLUdEsUbDoMaInS",
      "max-age=1; \"",
      "max-age=1; \"includeSubdomains",
      "max-age=1; in\"cludeSubdomains",
      "max-age=1; includeSubdomains\"",
      "max-age=1; \"includeSubdomains\"",
      "max-age=1; includeSubdomains; non\"token",
      "max-age=1; includeSubdomains; non@token",
      "max-age=1; includeSubdomains; non,token",
      "max-age=1; =2",
      "max-age=1; =2; unknownDirective",
  };

  for (const char* value : test_cases) {
    SCOPED_TRACE(value);
    EXPECT_FALSE(ParseHSTSHeader(value, &max_age, &include_subdomains));
  }
}

TEST_F(HttpSecurityHeadersTest, InvalidDirectiveValues) {
  base::TimeDelta max_age;
  bool include_subdomains = false;

  const char* test_cases[] = {
      "max-age=",
      "max-age=@",
      "max-age=1a;",
      "max-age=1a2;",
      "max-age=1##;",
      "max-age=12\";",
      "max-age=-1;",
      "max-age=+1;",
      "max-age='1';",
      "max-age=1abc;",
      "max-age=1 abc;",
      "max-age=1.5;",
      "max-age=1; includeSubDomains=true",
      "max-age=1; includeSubDomains=false",
      "max-age=1; includeSubDomains=\"\"",
      "max-age=1; includeSubDomains=''",
      "max-age=1; includeSubDomains=\"true\"",
      "max-age=1; includeSubDomains=\"false\"",
      "max-age=1; unknownDirective=non\"token",
      "max-age=1; unknownDirective=non@token",
      "max-age=1; unknownDirective=non,token",
      "max-age=1; unknownDirective=",
  };

  for (const char* value : test_cases) {
    SCOPED_TRACE(value);
    EXPECT_FALSE(ParseHSTSHeader(value, &max_age, &include_subdomains));
  }
}

TEST_F(HttpSecurityHeadersTest, BogusHeaders) {
  base::TimeDelta max_age;
  bool include_subdomains = false;

  EXPECT_FALSE(
      ParseHSTSHeader(std::string(), &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("    ", &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("abc", &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("  abc", &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("  abc   ", &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age", &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("  max-age", &max_age,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("  max-age  ", &max_age,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age=", &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("   max-age=", &max_age,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("   max-age  =", &max_age,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("   max-age=   ", &max_age,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("   max-age  =     ", &max_age,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("   max-age  =     xy", &max_age,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("   max-age  =     3488a923", &max_age,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age=3488a923  ", &max_age,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-ag=3488923", &max_age,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-aged=3488923", &max_age,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age==3488923", &max_age,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("amax-age=3488923", &max_age,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age=-3488923", &max_age,
                               &include_subdomains));
  EXPECT_FALSE(
      ParseHSTSHeader("max-age=+3488923", &max_age, &include_subdomains));
  EXPECT_FALSE(
      ParseHSTSHeader("max-age=13####", &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age=9223372036854775807#####", &max_age,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age=18446744073709551615####", &max_age,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age=999999999999999999999999$.&#!",
                               &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age=3488923     e", &max_age,
                               &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age=3488923     includesubdomain",
                               &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age=3488923includesubdomains",
                               &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age=3488923=includesubdomains",
                               &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age=3488923 includesubdomainx",
                               &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age=3488923 includesubdomain=",
                               &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age=3488923 includesubdomain=true",
                               &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age=3488923 includesubdomainsx",
                               &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age=3488923 includesubdomains x",
                               &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age=34889.23 includesubdomains",
                               &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age=34889 includesubdomains",
                               &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(";;;; ;;;",
                               &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(";;;; includeSubDomains;;;",
                               &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("   includeSubDomains;  ",
                               &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader(";",
                               &max_age, &include_subdomains));
  EXPECT_FALSE(ParseHSTSHeader("max-age; ;",
                               &max_age, &include_subdomains));

  // Check the out args were not updated by checking the default
  // values for its predictable fields.
  EXPECT_EQ(0, max_age.InSeconds());
  EXPECT_FALSE(include_subdomains);
}

TEST_F(HttpSecurityHeadersTest, ValidSTSHeaders) {
  base::TimeDelta max_age;
  base::TimeDelta expect_max_age;
  bool include_subdomains = false;

  EXPECT_TRUE(ParseHSTSHeader("max-age=243", &max_age,
                              &include_subdomains));
  expect_max_age = base::Seconds(243);
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_FALSE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader("max-age=3488923;", &max_age,
                              &include_subdomains));

  EXPECT_TRUE(ParseHSTSHeader("  Max-agE    = 567", &max_age,
                              &include_subdomains));
  expect_max_age = base::Seconds(567);
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_FALSE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader("  mAx-aGe    = 890      ", &max_age,
                              &include_subdomains));
  expect_max_age = base::Seconds(890);
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_FALSE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader("max-age=123;incLudesUbdOmains", &max_age,
                              &include_subdomains));
  expect_max_age = base::Seconds(123);
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader("incLudesUbdOmains; max-age=123", &max_age,
                              &include_subdomains));
  expect_max_age = base::Seconds(123);
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader("   incLudesUbdOmains; max-age=123",
                              &max_age, &include_subdomains));
  expect_max_age = base::Seconds(123);
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(
      "   incLudesUbdOmains; max-age=123; pumpkin=kitten", &max_age,
                                   &include_subdomains));
  expect_max_age = base::Seconds(123);
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(
      "   pumpkin=894; incLudesUbdOmains; max-age=123  ", &max_age,
                                   &include_subdomains));
  expect_max_age = base::Seconds(123);
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(
      "   pumpkin; incLudesUbdOmains; max-age=123  ", &max_age,
                                   &include_subdomains));
  expect_max_age = base::Seconds(123);
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(
      "   pumpkin; incLudesUbdOmains; max-age=\"123\"  ", &max_age,
                                   &include_subdomains));
  expect_max_age = base::Seconds(123);
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(
      "animal=\"squirrel; distinguished\"; incLudesUbdOmains; max-age=123",
                                   &max_age, &include_subdomains));
  expect_max_age = base::Seconds(123);
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader("max-age=394082;  incLudesUbdOmains",
                              &max_age, &include_subdomains));
  expect_max_age = base::Seconds(394082);
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(
      "max-age=39408299  ;incLudesUbdOmains", &max_age,
      &include_subdomains));
  expect_max_age = base::Seconds(std::min(kMaxHSTSAgeSecs, 39408299u));
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(
      "max-age=394082038  ; incLudesUbdOmains", &max_age,
      &include_subdomains));
  expect_max_age = base::Seconds(std::min(kMaxHSTSAgeSecs, 394082038u));
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(
      "max-age=394082038  ; incLudesUbdOmains;", &max_age,
      &include_subdomains));
  expect_max_age = base::Seconds(std::min(kMaxHSTSAgeSecs, 394082038u));
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(
      ";; max-age=394082038  ; incLudesUbdOmains; ;", &max_age,
      &include_subdomains));
  expect_max_age = base::Seconds(std::min(kMaxHSTSAgeSecs, 394082038u));
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(
      ";; max-age=394082038  ;", &max_age,
      &include_subdomains));
  expect_max_age = base::Seconds(std::min(kMaxHSTSAgeSecs, 394082038u));
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_FALSE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(
      ";;    ; ; max-age=394082038;;; includeSubdomains     ;;  ;", &max_age,
      &include_subdomains));
  expect_max_age = base::Seconds(std::min(kMaxHSTSAgeSecs, 394082038u));
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(
      "incLudesUbdOmains   ; max-age=394082038 ;;", &max_age,
      &include_subdomains));
  expect_max_age = base::Seconds(std::min(kMaxHSTSAgeSecs, 394082038u));
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(
      "  max-age=0  ;  incLudesUbdOmains   ", &max_age,
      &include_subdomains));
  expect_max_age = base::Seconds(0);
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_TRUE(include_subdomains);

  EXPECT_TRUE(ParseHSTSHeader(
      "  max-age=999999999999999999999999999999999999999999999  ;"
      "  incLudesUbdOmains   ", &max_age, &include_subdomains));
  expect_max_age = base::Seconds(kMaxHSTSAgeSecs);
  EXPECT_EQ(expect_max_age, max_age);
  EXPECT_TRUE(include_subdomains);
}

}  // namespace net

"""

```