Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/http/http_util_unittest.cc`. This file seems to contain unit tests for the `HttpUtil` class in Chromium's networking stack.

Here's a plan to address the user's request:

1. **Identify the main functionalities being tested:**  Analyze each `TEST` block to understand the specific aspects of `HttpUtil` being verified.
2. **Explain the functionalities in plain terms:**  Describe what each test is checking.
3. **Check for JavaScript relevance:** Determine if any of the tested functionalities have direct counterparts or implications for JavaScript in a browser environment. Provide examples if applicable.
4. **Provide input/output examples:** For tests involving parsing or formatting, give hypothetical inputs and their expected outputs.
5. **Identify potential user/programmer errors:**  Based on the tests, point out common mistakes developers might make when using the `HttpUtil` functionalities.
6. **Explain user actions leading to the code:** Describe how user interactions in a browser could trigger the execution of the code being tested.
7. **Summarize the overall functionality:** Concisely state the purpose of the code snippet.
这是 Chromium 网络栈中 `net/http/http_util_unittest.cc` 文件的第二部分，它主要包含以下功能：

**1. `TimeFormatHTTP` 函数的单元测试:**

*   **功能:** 测试 `HttpUtil::TimeFormatHTTP` 函数，该函数将 `base::Time` 对象格式化为 HTTP 标准的日期和时间字符串。
*   **假设输入与输出:**
    *   **假设输入:** 一个 `base::Time` 对象，例如表示 2011 年 4 月 30 日 22:42:07 的时间。
    *   **预期输出:**  字符串 "Sat, 30 Apr 2011 22:42:07 GMT"。
*   **与 JavaScript 的关系:**  JavaScript 中的 `Date` 对象也可以格式化为字符串，虽然格式不同，但 HTTP 头部中经常需要这种格式的时间戳。例如，JavaScript 可以使用 `Date.prototype.toUTCString()`  产生类似的但可能略有差异的格式。
    ```javascript
    const date = new Date(Date.UTC(2011, 3, 30, 22, 42, 7)); // 月份从 0 开始
    console.log(date.toUTCString()); // 输出可能为 "Sat, 30 Apr 2011 22:42:07 GMT"
    ```

**2. `NameValuePairsIterator` 类的单元测试:**

*   **功能:**  测试 `HttpUtil::NameValuePairsIterator` 类，该类用于解析 HTTP 头部中常见的 "名称=值" 对的字符串，例如 `Content-Type: text/html; charset=utf-8` 或 `Cache-Control: max-age=3600, private`.
*   **具体测试点包括:**
    *   **拷贝和赋值操作:** 测试迭代器的拷贝构造函数和赋值运算符是否正确工作，确保拷贝后的迭代器指向相同的位置，并且独立移动一个迭代器不会影响另一个。
    *   **空输入:**  测试处理空字符串输入的情况。
    *   **基本迭代:**  测试正常情况下的迭代，包括处理带空格、单引号、双引号以及转义字符的值。
    *   **可选值:**  测试处理值可以省略的情况 (例如，`Cache-Control: private`)，以及要求必须有值的情况。
    *   **非法输入:**  测试处理各种非法输入的情况，例如缺少分隔符、引号不匹配等。
    *   **额外的分隔符:** 测试对于额外的分隔符的容错性。
    *   **缺少结束引号:** 测试当值用双引号包裹但缺少结束引号时的处理。
    *   **严格引号模式:** 测试启用严格引号解析模式时的行为，例如处理转义的引号、值中包含引号以及单引号的处理。
*   **假设输入与输出 (以 `NameValuePairsIterator` 为例):**
    *   **假设输入:** 字符串 `"alpha=1; beta= 2 ; cappa =' 3; foo='; cappa =" 3; foo="; delta= " \"4\" "; e= " '5'"; e=6; f="\"\\h\\e\\l\\l\\o\\ \\w\\o\\r\\l\\d\\\""; g=""; h="hello"`，分隔符为 `;`。
    *   **预期输出 (按迭代顺序):**
        *   name: "alpha", value: "1"
        *   name: "beta", value: "2"
        *   name: "cappa", value: "' 3"
        *   name: "foo", value: "'"
        *   name: "cappa", value: " 3; foo="
        *   name: "delta", value: " \"4\" "
        *   name: "e", value: " '5'"
        *   name: "e", value: "6"
        *   name: "f", value: "\"hello world\""
        *   name: "g", value: ""
        *   name: "h", value: "hello"
*   **与 JavaScript 的关系:**  在 JavaScript 中，处理类似 "名称=值" 对的字符串很常见，尤其是在解析 HTTP 头部或 Cookie 时。开发者可能需要自己编写代码来分割字符串和提取名称值对，或者使用一些库来辅助处理。
    ```javascript
    const headerValue = 'alpha=1; beta=2';
    const pairs = headerValue.split(';');
    pairs.forEach(pair => {
      const [name, value] = pair.trim().split('=');
      console.log(`Name: ${name}, Value: ${value}`);
    });
    ```
*   **用户或编程常见的使用错误:**
    *   **错误地假设所有值都被双引号包裹:**  并非所有值都有引号，需要能够处理没有引号的情况。
    *   **忘记处理转义字符:** 如果值被双引号包裹，可能包含转义字符，需要正确解析。
    *   **错误地使用单引号作为引号:**  HTTP 规范中双引号才是值的引用符号。
    *   **未能处理缺少值的情况 (如果允许):**  某些参数可能只有名称，没有值。

**3. `HasValidators` 函数的单元测试:**

*   **功能:** 测试 `HttpUtil::HasValidators` 函数，该函数判断给定 HTTP 版本以及 `ETag` 和 `Last-Modified` 头部是否存在有效的验证器，用于缓存协商。
*   **假设输入与输出:**
    *   **假设输入:**  HTTP 版本 (例如 `HttpVersion(1, 1)`), `ETag` 值 (例如 `"strong"` 或 `W/"weak"`)，`Last-Modified` 值 (例如 `"Tue, 15 Nov 1994 12:45:26 GMT"` 或 `""`)。
    *   **预期输出:** `true` 或 `false`，表示是否存在有效的验证器。
*   **与 JavaScript 的关系:**  在前端 JavaScript 中，Service Worker 或浏览器缓存 API 涉及到缓存管理和验证，开发者需要了解 `ETag` 和 `Last-Modified` 的概念。当发起网络请求时，浏览器会自动处理这些头部进行缓存协商。
*   **用户或编程常见的使用错误:**
    *   **错误地假设 HTTP/0.9 也支持验证器:** HTTP/0.9 不支持 `ETag` 和 `Last-Modified`。
    *   **混淆强 ETag 和弱 ETag 的含义。**
    *   **错误地格式化 `Last-Modified` 的值。**

**4. HTTP 头部值验证相关的单元测试:**

*   **功能:** 测试 `HttpUtil::IsValidHeaderValue` 函数，该函数验证 HTTP 头部的值是否包含不允许的字符（例如 NULL 字符、换行符等）。
*   **假设输入与输出:**
    *   **假设输入:**  一个字符串，表示 HTTP 头部的值，例如 `"text/html"` 或 `"chrome\nSec-Unsafe: injected"`。
    *   **预期输出:** `true` 或 `false`，表示该值是否有效。
*   **与 JavaScript 的关系:**  在 JavaScript 中，如果开发者需要手动构建 HTTP 请求头部，需要确保头部值的安全性，避免注入攻击。浏览器在设置头部时通常会进行一些基本的验证。
*   **用户或编程常见的使用错误:**
    *   **在 HTTP 头部值中包含控制字符或换行符，可能导致安全问题或解析错误。**

**5. Token 和 LWS (Linear White Space) 相关的单元测试:**

*   **功能:** 测试 `HttpUtil::IsToken` 和 `HttpUtil::IsLWS` 函数，这些函数用于判断字符或字符串是否符合 HTTP 规范中 Token 和 LWS 的定义。
*   **假设输入与输出:**
    *   **`IsToken` 假设输入:** 字符串，例如 `"valid"`, `"hello, world"`, `""`。
    *   **`IsToken` 预期输出:** `true` 或 `false`。
    *   **`IsLWS` 假设输入:** 字符，例如 `' '`, `'\t'`, `'\n'`。
    *   **`IsLWS` 预期输出:** `true` 或 `false`。
*   **与 JavaScript 的关系:**  了解 Token 和 LWS 的概念有助于理解 HTTP 规范，例如在解析 HTTP 头部时。
*   **用户或编程常见的使用错误:**  在手动构建 HTTP 头部时，可能会错误地使用空格或其他字符，导致不符合规范。

**6. 控制字符相关的单元测试:**

*   **功能:** 测试 `HttpUtil::IsControlChar` 函数，判断字符是否为 HTTP 控制字符。
*   **假设输入与输出:**
    *   **假设输入:** 字符，例如 `'\0'`, `'\n'`, `'a'`。
    *   **预期输出:** `true` 或 `false`。
*   **与 JavaScript 的关系:**  与头部值验证类似，避免在不应该出现控制字符的地方使用它们。

**7. `ParseAcceptEncoding` 函数的单元测试:**

*   **功能:** 测试 `HttpUtil::ParseAcceptEncoding` 函数，该函数解析 `Accept-Encoding` 头部的值，提取浏览器支持的内容编码类型。
*   **假设输入与输出:**
    *   **假设输入:**  `Accept-Encoding` 头部的值，例如 `"gzip, deflate"`, `"identity;q=1, *;q=0"`。
    *   **预期输出:**  一个包含允许的编码类型的集合 (例如 `{"gzip", "deflate", "identity", "x-gzip"}`) 或者 "INVALID" 表示解析失败。
*   **与 JavaScript 的关系:**  浏览器发送的 `Accept-Encoding` 头部会影响服务器返回的内容压缩方式。开发者可以通过浏览器开发者工具查看此头部。
*   **用户或编程常见的使用错误:**  手动设置 `Accept-Encoding` 头部时，可能会使用不合法的格式。

**8. `ParseContentEncoding` 函数的单元测试:**

*   **功能:** 测试 `HttpUtil::ParseContentEncoding` 函数，该函数解析 `Content-Encoding` 头部的值，提取响应体使用的内容编码类型。
*   **假设输入与输出:**
    *   **假设输入:** `Content-Encoding` 头部的值，例如 `"gzip"`, `"br, gzip"`。
    *   **预期输出:**  一个包含使用的编码类型的集合 (例如 `{"gzip"}`) 或者 "INVALID" 表示解析失败。
*   **与 JavaScript 的关系:**  JavaScript 可以通过 `Response` 对象的 `headers` 属性获取 `Content-Encoding` 的值，从而知道响应体是否被压缩。
*   **用户或编程常见的使用错误:** 服务器配置错误可能导致 `Content-Encoding` 的值不正确。

**9. `ExpandLanguageList` 函数的单元测试:**

*   **功能:** 测试 `HttpUtil::ExpandLanguageList` 函数，该函数展开语言列表，例如将 `"en-US"` 展开为 `"en-US,en"`。
*   **假设输入与输出:**
    *   **假设输入:**  一个语言标签列表字符串，例如 `"en-US,fr-CA"`.
    *   **预期输出:**  展开后的语言标签列表字符串，例如 `"en-US,en,fr-CA,fr"`.
*   **与 JavaScript 的关系:**  浏览器发送的 `Accept-Language` 头部包含用户偏好的语言列表。JavaScript 可以使用 `navigator.languages` 获取用户的语言偏好。
*   **用户或编程常见的使用错误:**  用户可能会在浏览器设置中配置错误的语言偏好。

**用户操作是如何一步步的到达这里，作为调试线索:**

虽然用户本身的操作不会直接调用 `net/http/http_util_unittest.cc` 中的测试代码，但用户在浏览器中的各种操作会触发网络请求，而这些网络请求的处理过程中可能会用到 `HttpUtil` 类中的函数。当开发者需要调试与 HTTP 相关的网络问题时，他们可能会运行这些单元测试来验证 `HttpUtil` 的行为是否符合预期。

例如：

1. **用户在浏览器地址栏输入 URL 并访问一个网页:** 这会触发一个 HTTP 请求。
2. **浏览器解析 URL，创建 HTTP 请求，并设置各种头部，例如 `Accept-Encoding` 和 `Accept-Language`。**  `HttpUtil::TimeFormatHTTP` 可能用于格式化日期头部，`HttpUtil::ExpandLanguageList` 用于处理 `Accept-Language` 头部。
3. **服务器返回 HTTP 响应，包含各种头部，例如 `Content-Encoding`, `ETag`, `Last-Modified`。**
4. **浏览器接收到响应，开始解析头部。** `HttpUtil::NameValuePairsIterator` 可能用于解析像 `Cache-Control` 这样的头部。`HttpUtil::ParseContentEncoding` 用于解析 `Content-Encoding` 头部。`HttpUtil::HasValidators` 用于判断响应是否包含缓存验证器。
5. **如果在处理这些头部时出现错误，开发者可能会怀疑 `HttpUtil` 的实现有问题，并运行相关的单元测试来定位问题。**

**归纳一下它的功能 (第二部分):**

这部分 `http_util_unittest.cc` 文件的主要功能是 **对 Chromium 网络栈中 `HttpUtil` 类提供的各种 HTTP 实用工具函数进行全面的单元测试**。 这些测试涵盖了日期时间格式化、HTTP 头部中键值对的解析、缓存验证器的判断、HTTP 头部值的合法性验证、Token 和 LWS 的判断、以及 `Accept-Encoding`、`Content-Encoding` 和 `Accept-Language` 等重要 HTTP 头的解析和处理。 通过这些测试，可以确保 `HttpUtil` 类的各个功能模块按照 HTTP 规范正确地工作，提高网络栈的稳定性和可靠性。

### 提示词
```
这是目录为net/http/http_util_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
T(HttpUtilTest, TimeFormatHTTP) {
  constexpr base::Time::Exploded kTime = {.year = 2011,
                                          .month = 4,
                                          .day_of_week = 6,
                                          .day_of_month = 30,
                                          .hour = 22,
                                          .minute = 42,
                                          .second = 7};
  base::Time time;
  EXPECT_TRUE(base::Time::FromUTCExploded(kTime, &time));
  EXPECT_EQ("Sat, 30 Apr 2011 22:42:07 GMT", HttpUtil::TimeFormatHTTP(time));
}

namespace {
void CheckCurrentNameValuePair(HttpUtil::NameValuePairsIterator* parser,
                               bool expect_valid,
                               std::string expected_name,
                               std::string expected_value) {
  ASSERT_EQ(expect_valid, parser->valid());
  if (!expect_valid) {
    return;
  }

  // Let's make sure that this never changes (i.e., when a quoted value is
  // unquoted, it should be cached on the first calls and not regenerated
  // later).
  const std::string_view first_value = parser->value();

  ASSERT_EQ(expected_name, parser->name());
  ASSERT_EQ(expected_value, parser->value());

  // Make sure they didn't/don't change.
  ASSERT_TRUE(first_value.data() == parser->value().data());
  ASSERT_TRUE(first_value.length() == parser->value().length());
}

void CheckNextNameValuePair(HttpUtil::NameValuePairsIterator* parser,
                            bool expect_next,
                            bool expect_valid,
                            std::string expected_name,
                            std::string expected_value) {
  ASSERT_EQ(expect_next, parser->GetNext());
  ASSERT_EQ(expect_valid, parser->valid());
  if (!expect_next || !expect_valid) {
    return;
  }

  CheckCurrentNameValuePair(parser,
                            expect_valid,
                            expected_name,
                            expected_value);
}

void CheckInvalidNameValuePair(std::string valid_part,
                               std::string invalid_part) {
  std::string whole_string = valid_part + invalid_part;

  HttpUtil::NameValuePairsIterator valid_parser(valid_part, /*delimiter=*/';');
  HttpUtil::NameValuePairsIterator invalid_parser(whole_string,
                                                  /*delimiter=*/';');

  ASSERT_TRUE(valid_parser.valid());
  ASSERT_TRUE(invalid_parser.valid());

  // Both parsers should return all the same values until "valid_parser" is
  // exhausted.
  while (valid_parser.GetNext()) {
    ASSERT_TRUE(invalid_parser.GetNext());
    ASSERT_TRUE(valid_parser.valid());
    ASSERT_TRUE(invalid_parser.valid());
    ASSERT_EQ(valid_parser.name(), invalid_parser.name());
    ASSERT_EQ(valid_parser.value(), invalid_parser.value());
  }

  // valid_parser is exhausted and remains 'valid'
  ASSERT_TRUE(valid_parser.valid());
  // But all data in it should have been cleared.
  EXPECT_TRUE(valid_parser.name().empty());
  EXPECT_TRUE(valid_parser.value().empty());
  EXPECT_TRUE(valid_parser.raw_value().empty());
  EXPECT_FALSE(valid_parser.value_is_quoted());

  // invalid_parser's corresponding call to GetNext also returns false...
  ASSERT_FALSE(invalid_parser.GetNext());
  // ...but the parser is in an invalid state.
  ASSERT_FALSE(invalid_parser.valid());

  // All values in an invalid parser should be cleared.
  EXPECT_TRUE(invalid_parser.name().empty());
  EXPECT_TRUE(invalid_parser.value().empty());
  EXPECT_TRUE(invalid_parser.raw_value().empty());
  EXPECT_FALSE(invalid_parser.value_is_quoted());
}

}  // namespace

TEST(HttpUtilTest, NameValuePairsIteratorCopyAndAssign) {
  std::string data =
      "alpha=\"\\\"a\\\"\"; beta=\" b \"; cappa=\"c;\"; delta=\"d\"";
  HttpUtil::NameValuePairsIterator parser_a(data, /*delimiter=*/';');

  EXPECT_TRUE(parser_a.valid());
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser_a, true, true, "alpha", "\"a\""));

  HttpUtil::NameValuePairsIterator parser_b(parser_a);
  // a and b now point to same location
  ASSERT_NO_FATAL_FAILURE(
      CheckCurrentNameValuePair(&parser_b, true, "alpha", "\"a\""));
  ASSERT_NO_FATAL_FAILURE(
      CheckCurrentNameValuePair(&parser_a, true, "alpha", "\"a\""));

  // advance a, no effect on b
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser_a, true, true, "beta", " b "));
  ASSERT_NO_FATAL_FAILURE(
      CheckCurrentNameValuePair(&parser_b, true, "alpha", "\"a\""));

  // assign b the current state of a, no effect on a
  parser_b = parser_a;
  ASSERT_NO_FATAL_FAILURE(
      CheckCurrentNameValuePair(&parser_b, true, "beta", " b "));
  ASSERT_NO_FATAL_FAILURE(
      CheckCurrentNameValuePair(&parser_a, true, "beta", " b "));

  // advance b, no effect on a
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser_b, true, true, "cappa", "c;"));
  ASSERT_NO_FATAL_FAILURE(
      CheckCurrentNameValuePair(&parser_a, true, "beta", " b "));
}

TEST(HttpUtilTest, NameValuePairsIteratorEmptyInput) {
  std::string data;
  HttpUtil::NameValuePairsIterator parser(data, /*delimiter=*/';');

  EXPECT_TRUE(parser.valid());
  ASSERT_NO_FATAL_FAILURE(CheckNextNameValuePair(
      &parser, false, true, std::string(), std::string()));
}

TEST(HttpUtilTest, NameValuePairsIterator) {
  std::string data =
      "alpha=1; beta= 2 ;"
      "cappa =' 3; foo=';"
      "cappa =\" 3; foo=\";"
      "delta= \" \\\"4\\\" \"; e= \" '5'\"; e=6;"
      "f=\"\\\"\\h\\e\\l\\l\\o\\ \\w\\o\\r\\l\\d\\\"\";"
      "g=\"\"; h=\"hello\"";
  HttpUtil::NameValuePairsIterator parser(data, /*delimiter=*/';');
  EXPECT_TRUE(parser.valid());

  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "alpha", "1"));
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "beta", "2"));

  // Single quotes shouldn't be treated as quotes.
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "cappa", "' 3"));
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "foo", "'"));

  // But double quotes should be, and can contain semi-colons and equal signs.
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "cappa", " 3; foo="));

  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "delta", " \"4\" "));
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "e", " '5'"));
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "e", "6"));
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "f", "\"hello world\""));
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "g", std::string()));
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "h", "hello"));
  ASSERT_NO_FATAL_FAILURE(CheckNextNameValuePair(
      &parser, false, true, std::string(), std::string()));
}

TEST(HttpUtilTest, NameValuePairsIteratorOptionalValues) {
  std::string data = "alpha=1; beta;cappa ;  delta; e    ; f=1";
  // Test that the default parser requires values.
  HttpUtil::NameValuePairsIterator default_parser(data, /*delimiter=*/';');
  EXPECT_TRUE(default_parser.valid());
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&default_parser, true, true, "alpha", "1"));
  ASSERT_NO_FATAL_FAILURE(CheckNextNameValuePair(&default_parser, false, false,
                                                 std::string(), std::string()));

  HttpUtil::NameValuePairsIterator values_required_parser(
      data, /*delimiter=*/';',
      HttpUtil::NameValuePairsIterator::Values::REQUIRED,
      HttpUtil::NameValuePairsIterator::Quotes::NOT_STRICT);
  EXPECT_TRUE(values_required_parser.valid());
  ASSERT_NO_FATAL_FAILURE(CheckNextNameValuePair(&values_required_parser, true,
                                                 true, "alpha", "1"));
  ASSERT_NO_FATAL_FAILURE(CheckNextNameValuePair(
      &values_required_parser, false, false, std::string(), std::string()));

  HttpUtil::NameValuePairsIterator parser(
      data, /*delimiter=*/';',
      HttpUtil::NameValuePairsIterator::Values::NOT_REQUIRED,
      HttpUtil::NameValuePairsIterator::Quotes::NOT_STRICT);
  EXPECT_TRUE(parser.valid());

  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "alpha", "1"));
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "beta", std::string()));
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "cappa", std::string()));
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "delta", std::string()));
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "e", std::string()));
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "f", "1"));
  ASSERT_NO_FATAL_FAILURE(CheckNextNameValuePair(&parser, false, true,
                                                 std::string(), std::string()));
  EXPECT_TRUE(parser.valid());
}

TEST(HttpUtilTest, NameValuePairsIteratorIllegalInputs) {
  ASSERT_NO_FATAL_FAILURE(CheckInvalidNameValuePair("alpha=1", "; beta"));
  ASSERT_NO_FATAL_FAILURE(CheckInvalidNameValuePair(std::string(), "beta"));

  ASSERT_NO_FATAL_FAILURE(CheckInvalidNameValuePair("alpha=1", "; \"beta\"=2"));
  ASSERT_NO_FATAL_FAILURE(
      CheckInvalidNameValuePair(std::string(), "\"beta\"=2"));
  ASSERT_NO_FATAL_FAILURE(CheckInvalidNameValuePair("alpha=1", ";beta="));
  ASSERT_NO_FATAL_FAILURE(CheckInvalidNameValuePair("alpha=1",
                                                    ";beta=;cappa=2"));

  // According to the spec this is an error, but it doesn't seem appropriate to
  // change our behaviour to be less permissive at this time.
  // See NameValuePairsIteratorExtraSeparators test
  // ASSERT_NO_FATAL_FAILURE(CheckInvalidNameValuePair("alpha=1", ";; beta=2"));
}

// If we are going to support extra separators against the spec, let's just make
// sure they work rationally.
TEST(HttpUtilTest, NameValuePairsIteratorExtraSeparators) {
  std::string data = " ; ;;alpha=1; ;; ; beta= 2;cappa=3;;; ; ";
  HttpUtil::NameValuePairsIterator parser(data, /*delimiter=*/';');
  EXPECT_TRUE(parser.valid());

  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "alpha", "1"));
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "beta", "2"));
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "cappa", "3"));
  ASSERT_NO_FATAL_FAILURE(CheckNextNameValuePair(
      &parser, false, true, std::string(), std::string()));
}

// See comments on the implementation of NameValuePairsIterator::GetNext
// regarding this derogation from the spec.
TEST(HttpUtilTest, NameValuePairsIteratorMissingEndQuote) {
  std::string data = "name=\"value";
  HttpUtil::NameValuePairsIterator parser(data, /*delimiter=*/';');
  EXPECT_TRUE(parser.valid());

  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "name", "value"));
  ASSERT_NO_FATAL_FAILURE(CheckNextNameValuePair(
      &parser, false, true, std::string(), std::string()));
}

TEST(HttpUtilTest, NameValuePairsIteratorStrictQuotesEscapedEndQuote) {
  std::string data = "foo=bar; name=\"value\\\"";
  HttpUtil::NameValuePairsIterator parser(
      data, /*delimiter=*/';',
      HttpUtil::NameValuePairsIterator::Values::REQUIRED,
      HttpUtil::NameValuePairsIterator::Quotes::STRICT_QUOTES);
  EXPECT_TRUE(parser.valid());

  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "foo", "bar"));
  ASSERT_NO_FATAL_FAILURE(CheckNextNameValuePair(&parser, false, false,
                                                 std::string(), std::string()));
}

TEST(HttpUtilTest, NameValuePairsIteratorStrictQuotesQuoteInValue) {
  std::string data = "foo=\"bar\"; name=\"va\"lue\"";
  HttpUtil::NameValuePairsIterator parser(
      data, /*delimiter=*/';',
      HttpUtil::NameValuePairsIterator::Values::REQUIRED,
      HttpUtil::NameValuePairsIterator::Quotes::STRICT_QUOTES);
  EXPECT_TRUE(parser.valid());

  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "foo", "bar"));
  ASSERT_NO_FATAL_FAILURE(CheckNextNameValuePair(&parser, false, false,
                                                 std::string(), std::string()));
}

TEST(HttpUtilTest, NameValuePairsIteratorStrictQuotesMissingEndQuote) {
  std::string data = "foo=\"bar\"; name=\"value";
  HttpUtil::NameValuePairsIterator parser(
      data, /*delimiter=*/';',
      HttpUtil::NameValuePairsIterator::Values::REQUIRED,
      HttpUtil::NameValuePairsIterator::Quotes::STRICT_QUOTES);
  EXPECT_TRUE(parser.valid());

  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "foo", "bar"));
  ASSERT_NO_FATAL_FAILURE(CheckNextNameValuePair(&parser, false, false,
                                                 std::string(), std::string()));
}

TEST(HttpUtilTest, NameValuePairsIteratorStrictQuotesSingleQuotes) {
  std::string data = "foo=\"bar\"; name='value; ok=it'";
  HttpUtil::NameValuePairsIterator parser(
      data, /*delimiter=*/';',
      HttpUtil::NameValuePairsIterator::Values::REQUIRED,
      HttpUtil::NameValuePairsIterator::Quotes::STRICT_QUOTES);
  EXPECT_TRUE(parser.valid());

  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "foo", "bar"));
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "name", "'value"));
  ASSERT_NO_FATAL_FAILURE(
      CheckNextNameValuePair(&parser, true, true, "ok", "it'"));
}

TEST(HttpUtilTest, HasValidators) {
  const char* const kMissing = "";
  const char* const kEtagEmpty = "\"\"";
  const char* const kEtagStrong = "\"strong\"";
  const char* const kEtagWeak = "W/\"weak\"";
  const char* const kLastModified = "Tue, 15 Nov 1994 12:45:26 GMT";
  const char* const kLastModifiedInvalid = "invalid";

  const HttpVersion v0_9 = HttpVersion(0, 9);
  EXPECT_FALSE(HttpUtil::HasValidators(v0_9, kMissing, kMissing));
  EXPECT_FALSE(HttpUtil::HasValidators(v0_9, kEtagStrong, kMissing));
  EXPECT_FALSE(HttpUtil::HasValidators(v0_9, kEtagWeak, kMissing));
  EXPECT_FALSE(HttpUtil::HasValidators(v0_9, kEtagEmpty, kMissing));

  EXPECT_FALSE(HttpUtil::HasValidators(v0_9, kMissing, kLastModified));
  EXPECT_FALSE(HttpUtil::HasValidators(v0_9, kEtagStrong, kLastModified));
  EXPECT_FALSE(HttpUtil::HasValidators(v0_9, kEtagWeak, kLastModified));
  EXPECT_FALSE(HttpUtil::HasValidators(v0_9, kEtagEmpty, kLastModified));

  EXPECT_FALSE(HttpUtil::HasValidators(v0_9, kMissing, kLastModifiedInvalid));
  EXPECT_FALSE(
      HttpUtil::HasValidators(v0_9, kEtagStrong, kLastModifiedInvalid));
  EXPECT_FALSE(HttpUtil::HasValidators(v0_9, kEtagWeak, kLastModifiedInvalid));
  EXPECT_FALSE(HttpUtil::HasValidators(v0_9, kEtagEmpty, kLastModifiedInvalid));

  const HttpVersion v1_0 = HttpVersion(1, 0);
  EXPECT_FALSE(HttpUtil::HasValidators(v1_0, kMissing, kMissing));
  EXPECT_FALSE(HttpUtil::HasValidators(v1_0, kEtagStrong, kMissing));
  EXPECT_FALSE(HttpUtil::HasValidators(v1_0, kEtagWeak, kMissing));
  EXPECT_FALSE(HttpUtil::HasValidators(v1_0, kEtagEmpty, kMissing));

  EXPECT_TRUE(HttpUtil::HasValidators(v1_0, kMissing, kLastModified));
  EXPECT_TRUE(HttpUtil::HasValidators(v1_0, kEtagStrong, kLastModified));
  EXPECT_TRUE(HttpUtil::HasValidators(v1_0, kEtagWeak, kLastModified));
  EXPECT_TRUE(HttpUtil::HasValidators(v1_0, kEtagEmpty, kLastModified));

  EXPECT_FALSE(HttpUtil::HasValidators(v1_0, kMissing, kLastModifiedInvalid));
  EXPECT_FALSE(
      HttpUtil::HasValidators(v1_0, kEtagStrong, kLastModifiedInvalid));
  EXPECT_FALSE(HttpUtil::HasValidators(v1_0, kEtagWeak, kLastModifiedInvalid));
  EXPECT_FALSE(HttpUtil::HasValidators(v1_0, kEtagEmpty, kLastModifiedInvalid));

  const HttpVersion v1_1 = HttpVersion(1, 1);
  EXPECT_FALSE(HttpUtil::HasValidators(v1_1, kMissing, kMissing));
  EXPECT_TRUE(HttpUtil::HasValidators(v1_1, kEtagStrong, kMissing));
  EXPECT_TRUE(HttpUtil::HasValidators(v1_1, kEtagWeak, kMissing));
  EXPECT_TRUE(HttpUtil::HasValidators(v1_1, kEtagEmpty, kMissing));

  EXPECT_TRUE(HttpUtil::HasValidators(v1_1, kMissing, kLastModified));
  EXPECT_TRUE(HttpUtil::HasValidators(v1_1, kEtagStrong, kLastModified));
  EXPECT_TRUE(HttpUtil::HasValidators(v1_1, kEtagWeak, kLastModified));
  EXPECT_TRUE(HttpUtil::HasValidators(v1_1, kEtagEmpty, kLastModified));

  EXPECT_FALSE(HttpUtil::HasValidators(v1_1, kMissing, kLastModifiedInvalid));
  EXPECT_TRUE(HttpUtil::HasValidators(v1_1, kEtagStrong, kLastModifiedInvalid));
  EXPECT_TRUE(HttpUtil::HasValidators(v1_1, kEtagWeak, kLastModifiedInvalid));
  EXPECT_TRUE(HttpUtil::HasValidators(v1_1, kEtagEmpty, kLastModifiedInvalid));
}

TEST(HttpUtilTest, IsValidHeaderValue) {
  const char* const invalid_values[] = {
      "X-Requested-With: chrome${NUL}Sec-Unsafe: injected",
      "X-Requested-With: chrome\r\nSec-Unsafe: injected",
      "X-Requested-With: chrome\nSec-Unsafe: injected",
      "X-Requested-With: chrome\rSec-Unsafe: injected",
  };
  for (const std::string& value : invalid_values) {
    std::string replaced = value;
    base::ReplaceSubstringsAfterOffset(&replaced, 0, "${NUL}",
                                       std::string(1, '\0'));
    EXPECT_FALSE(HttpUtil::IsValidHeaderValue(replaced)) << replaced;
  }

  // Check that all characters permitted by RFC7230 3.2.6 are allowed.
  std::string allowed = "\t";
  for (char c = '\x20'; c < '\x7F'; ++c) {
    allowed.append(1, c);
  }
  for (int c = 0x80; c <= 0xFF; ++c) {
    allowed.append(1, static_cast<char>(c));
  }
  EXPECT_TRUE(HttpUtil::IsValidHeaderValue(allowed));
}

TEST(HttpUtilTest, IsToken) {
  EXPECT_TRUE(HttpUtil::IsToken("valid"));
  EXPECT_TRUE(HttpUtil::IsToken("!"));
  EXPECT_TRUE(HttpUtil::IsToken("~"));

  EXPECT_FALSE(HttpUtil::IsToken(""));
  EXPECT_FALSE(HttpUtil::IsToken(std::string_view()));
  EXPECT_FALSE(HttpUtil::IsToken("hello, world"));
  EXPECT_FALSE(HttpUtil::IsToken(" "));
  EXPECT_FALSE(HttpUtil::IsToken(std::string_view("\0", 1)));
  EXPECT_FALSE(HttpUtil::IsToken("\x01"));
  EXPECT_FALSE(HttpUtil::IsToken("\x7F"));
  EXPECT_FALSE(HttpUtil::IsToken("\x80"));
  EXPECT_FALSE(HttpUtil::IsToken("\xff"));
}

TEST(HttpUtilTest, IsLWS) {
  EXPECT_FALSE(HttpUtil::IsLWS('\v'));
  EXPECT_FALSE(HttpUtil::IsLWS('\0'));
  EXPECT_FALSE(HttpUtil::IsLWS('1'));
  EXPECT_FALSE(HttpUtil::IsLWS('a'));
  EXPECT_FALSE(HttpUtil::IsLWS('.'));
  EXPECT_FALSE(HttpUtil::IsLWS('\n'));
  EXPECT_FALSE(HttpUtil::IsLWS('\r'));

  EXPECT_TRUE(HttpUtil::IsLWS('\t'));
  EXPECT_TRUE(HttpUtil::IsLWS(' '));
}

TEST(HttpUtilTest, IsControlChar) {
  EXPECT_FALSE(HttpUtil::IsControlChar('1'));
  EXPECT_FALSE(HttpUtil::IsControlChar('a'));
  EXPECT_FALSE(HttpUtil::IsControlChar('.'));
  EXPECT_FALSE(HttpUtil::IsControlChar('$'));
  EXPECT_FALSE(HttpUtil::IsControlChar('\x7E'));
  EXPECT_FALSE(HttpUtil::IsControlChar('\x80'));
  EXPECT_FALSE(HttpUtil::IsControlChar('\xFF'));

  EXPECT_TRUE(HttpUtil::IsControlChar('\0'));
  EXPECT_TRUE(HttpUtil::IsControlChar('\v'));
  EXPECT_TRUE(HttpUtil::IsControlChar('\n'));
  EXPECT_TRUE(HttpUtil::IsControlChar('\r'));
  EXPECT_TRUE(HttpUtil::IsControlChar('\t'));
  EXPECT_TRUE(HttpUtil::IsControlChar('\x01'));
  EXPECT_TRUE(HttpUtil::IsControlChar('\x7F'));
}

TEST(HttpUtilTest, ParseAcceptEncoding) {
  const struct {
    const char* const value;
    const char* const expected;
  } tests[] = {
      {"", "*"},
      {"identity;q=1, *;q=0", "identity"},
      {"identity", "identity"},
      {"FOO, Bar", "bar|foo|identity"},
      {"foo; q=1", "foo|identity"},
      {"abc, foo; Q=1.0", "abc|foo|identity"},
      {"abc, foo;q= 1.00 , bar", "abc|bar|foo|identity"},
      {"abc, foo; q=1.000, bar", "abc|bar|foo|identity"},
      {"abc, foo ; q = 0 , bar", "abc|bar|identity"},
      {"abc, foo; q=0.0, bar", "abc|bar|identity"},
      {"abc, foo; q=0.00, bar", "abc|bar|identity"},
      {"abc, foo; q=0.000, bar", "abc|bar|identity"},
      {"abc, foo; q=0.001, bar", "abc|bar|foo|identity"},
      {"gzip", "gzip|identity|x-gzip"},
      {"x-gzip", "gzip|identity|x-gzip"},
      {"compress", "compress|identity|x-compress"},
      {"x-compress", "compress|identity|x-compress"},
      {"x-compress", "compress|identity|x-compress"},
      {"foo bar", "INVALID"},
      {"foo;", "INVALID"},
      {"foo;w=1", "INVALID"},
      {"foo;q+1", "INVALID"},
      {"foo;q=2", "INVALID"},
      {"foo;q=1.001", "INVALID"},
      {"foo;q=0.", "INVALID"},
      {"foo,\"bar\"", "INVALID"},
  };

  for (const auto& test : tests) {
    std::string value(test.value);
    std::string reformatted;
    std::set<std::string> allowed_encodings;
    if (!HttpUtil::ParseAcceptEncoding(value, &allowed_encodings)) {
      reformatted = "INVALID";
    } else {
      std::vector<std::string> encodings_list;
      for (auto const& encoding : allowed_encodings)
        encodings_list.push_back(encoding);
      reformatted = base::JoinString(encodings_list, "|");
    }
    EXPECT_STREQ(test.expected, reformatted.c_str())
        << "value=\"" << value << "\"";
  }
}

TEST(HttpUtilTest, ParseContentEncoding) {
  const struct {
    const char* const value;
    const char* const expected;
  } tests[] = {
      {"", ""},
      {"identity;q=1, *;q=0", "INVALID"},
      {"identity", "identity"},
      {"FOO, zergli , Bar", "bar|foo|zergli"},
      {"foo, *", "INVALID"},
      {"foo,\"bar\"", "INVALID"},
  };

  for (const auto& test : tests) {
    std::string value(test.value);
    std::string reformatted;
    std::set<std::string> used_encodings;
    if (!HttpUtil::ParseContentEncoding(value, &used_encodings)) {
      reformatted = "INVALID";
    } else {
      std::vector<std::string> encodings_list;
      for (auto const& encoding : used_encodings)
        encodings_list.push_back(encoding);
      reformatted = base::JoinString(encodings_list, "|");
    }
    EXPECT_STREQ(test.expected, reformatted.c_str())
        << "value=\"" << value << "\"";
  }
}

// Test the expansion of the Language List.
TEST(HttpUtilTest, ExpandLanguageList) {
  EXPECT_EQ("", HttpUtil::ExpandLanguageList(""));
  EXPECT_EQ("en-US,en", HttpUtil::ExpandLanguageList("en-US"));
  EXPECT_EQ("fr", HttpUtil::ExpandLanguageList("fr"));

  // The base language is added after all regional codes...
  EXPECT_EQ("en-US,en-CA,en", HttpUtil::ExpandLanguageList("en-US,en-CA"));

  // ... but before other language families.
  EXPECT_EQ("en-US,en-CA,en,fr",
            HttpUtil::ExpandLanguageList("en-US,en-CA,fr"));
  EXPECT_EQ("en-US,en-CA,en,fr,en-AU",
            HttpUtil::ExpandLanguageList("en-US,en-CA,fr,en-AU"));
  EXPECT_EQ("en-US,en-CA,en,fr-CA,fr",
            HttpUtil::ExpandLanguageList("en-US,en-CA,fr-CA"));

  // Add a base language even if it's already in the list.
  EXPECT_EQ("en-US,en,fr-CA,fr,it,es-AR,es,it-IT",
            HttpUtil::ExpandLanguageList("en-US,fr-CA,it,fr,es-AR,it-IT"));
  // Trims a whitespace.
  EXPECT_EQ("en-US,en,fr", HttpUtil::ExpandLanguageList("en-US, fr"));

  // Do not expand the single character subtag 'x' as a language.
  EXPECT_EQ("x-private-agreement-subtags",
            HttpUtil::ExpandLanguageList("x-private-agreement-subtags"));
  // Do not expand the single character subtag 'i' as a language.
  EXPECT_EQ("i-klingon", HttpUtil::ExpandLanguageList("i-klingon"));
}

}  // namespace net
```