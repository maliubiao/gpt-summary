Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The core request is to analyze a Chromium network stack test file (`structured_headers_test.cc`). The key is to identify its purpose, any connections to JavaScript, its logic, potential user/developer errors, and how a user might reach this code.

2. **Initial Scan for Clues:**  A quick skim of the file reveals several important things:
    * **`#include` statements:** These tell us the file depends on `quiche/common/structured_headers.h` and standard C++ libraries (`<math.h>`, `<limits>`, etc.). This suggests the file is testing the functionality defined in that header file.
    * **`namespace quiche::structured_headers`:** This confirms the file belongs to the QUIC implementation within Chromium and specifically to the "structured_headers" component.
    * **`TEST(...)` macros:**  These are the standard Google Test (gtest) framework constructs. Each `TEST` block represents a set of test cases for a specific function or aspect of the code.
    * **Data structures like `ItemTestCase`, `ParameterizedItemTestCase`, `ListTestCase`, `DictionaryTestCase`:** These structs define test cases, holding the input (`raw`), the expected output (`expected`), and sometimes a canonical representation (`canonical`). This strongly suggests the file is testing parsing and serialization of structured headers.
    * **Helper functions like `Token`, `Integer`, `Param`, etc.:** These are helper functions to make the test cases more readable and less verbose. They construct the expected output data structures.

3. **Identify the Core Functionality Under Test:** Based on the `TEST` names and the structure of the test cases, the file primarily focuses on:
    * **Parsing:**  `ParseBareItem`, `ParseItem`, `ParseSH09Item`, `ParseListOfLists`, `ParseParameterisedList`, `ParseList`, `ParseDictionary`. These functions take raw string input and try to convert it into structured data.
    * **Serialization:** `SerializeItem`, `SerializeParameterizedItem`, `SerializeList`, `SerializeDictionary`. These functions take the structured data and convert it back into string representations.
    * **Specific versions/drafts:**  The presence of `ParseSH09Item` indicates testing for an older version of the Structured Headers specification.

4. **Analyze the Test Cases:**  Examining the individual test cases provides detailed insights into the functionality being tested. Look for:
    * **Positive tests:** Cases with valid input and expected output.
    * **Negative tests:** Cases with invalid input where parsing is expected to fail (`std::nullopt`).
    * **Edge cases:** Tests for boundary conditions, like very large numbers, empty inputs, or specific whitespace handling.
    * **Canonicalization tests:** Cases where the serialized output should be in a specific "canonical" format, even if the input was slightly different.

5. **JavaScript Relevance:**  Consider how structured headers might relate to JavaScript in a web browser context. HTTP headers are a prime candidate. Think about:
    * **`fetch()` API:**  JavaScript uses this to make HTTP requests and receive responses. HTTP headers are a key part of these interactions.
    * **`Headers` API:**  JavaScript provides a `Headers` object to work with HTTP headers.
    * **Caching:** HTTP headers control caching behavior, which affects how JavaScript applications load resources.
    * **Content Negotiation:** Headers like `Accept` and `Content-Type` influence how servers and browsers handle data.

6. **Logic and Reasoning (Input/Output Examples):**  Choose a few representative test cases and explain the logic:
    * **Simple parsing:**  `{"leading whitespace", " foo", Token("foo"), "foo"}`  Input " foo" should be parsed into a Token with the value "foo", and the canonical representation is "foo" (no leading space).
    * **Parsing with parameters:** `{"single parameter item", "text/html;q=1.0", {{Token("text/html"), {DoubleParam("q", 1)}}}, nullptr}`  Input "text/html;q=1.0" should be parsed into a ParameterizedItem with a token "text/html" and a parameter "q" with a double value of 1.0.
    * **Serialization:**  Find a test case where the `canonical` value differs from the `raw` value to demonstrate serialization logic.

7. **Common Errors:**  Think about what could go wrong when dealing with structured headers, both from a user's perspective (configuring a server) and a developer's perspective (implementing the parsing/serialization logic):
    * **Incorrect syntax:**  Missing quotes, semicolons, commas, or using invalid characters.
    * **Type mismatches:** Providing a string when a number is expected.
    * **Case sensitivity issues:** Although structured headers are generally case-insensitive for parameter names, there can be nuances.
    * **Exceeding limits:**  Numbers being too large, strings being too long.

8. **Debugging Scenario:** Imagine a user experiencing a problem related to structured headers. Trace the likely steps:
    * User reports an issue (e.g., a website isn't behaving correctly).
    * Developer investigates network requests in the browser's developer tools.
    * They examine HTTP headers and notice a potentially malformed structured header.
    * They might then look at the Chromium source code (like this test file) to understand how the browser parses and handles that header.

9. **Structure the Answer:** Organize the findings into logical sections as requested by the prompt: functionality, JavaScript relation, logic examples, common errors, and debugging. Use clear and concise language. Use code examples where appropriate.

10. **Review and Refine:**  Read through the answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For example, ensure the JavaScript examples are relevant to the specific features being tested.
这个文件 `net/third_party/quiche/src/quiche/common/structured_headers_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，专门用于测试 **结构化头部 (Structured Headers)** 的解析和序列化功能。结构化头部是一种用于表示 HTTP 头部字段值的标准格式，旨在提供一种更清晰、更易于解析和处理的方式。

**功能:**

1. **解析测试 (Parsing Tests):**
   - 测试各种不同格式的结构化头部字符串能否被正确解析成对应的数据结构，例如：
     - **Item:**  单个的基本值，可以是 token、整数、浮点数、字符串或字节序列。
     - **Parameterized Item:** 带有参数的 Item。
     - **List:**  由 Item 或 Parameterized Item 组成的列表。
     - **Dictionary:**  由键值对组成的字典，其中值可以是 Item、Parameterized Item 或 List。
   - 涵盖了结构化头部规范中定义的各种语法规则和边缘情况，包括：
     - 合法的语法和值。
     - 各种空白字符的处理。
     - 引号、转义字符的处理。
     - 参数的解析（键值对，布尔参数）。
     - 嵌套结构（列表中的列表）。
   - 针对不同的结构化头部草案版本 (例如 Draft 09 和 Draft 15) 进行测试，因为不同版本之间可能存在细微的差异。

2. **序列化测试 (Serialization Tests):**
   - 测试将内部数据结构（如 Item, ParameterizedItem, List, Dictionary）转换回符合结构化头部规范的字符串格式的功能。
   - 验证序列化后的字符串是否与预期的规范格式一致。
   - 测试哪些类型的内部数据结构可以被正确序列化，哪些不可以（例如，超出范围的数字，包含非法字符的字符串等）。

3. **错误处理测试:**
   - 测试对于格式错误的结构化头部字符串，解析器是否能够正确识别并返回错误（通常通过返回 `std::nullopt` 表示）。
   - 涵盖了各种常见的语法错误，例如：
     - 不合法的 token 字符。
     - 数字超出范围。
     - 字符串中包含非法字符。
     - 缺少分隔符或引号。
     - 参数键名不合法。

4. **数据结构测试:**
   - 测试 `Dictionary` 数据结构的各种操作，例如构造、赋值、访问、清空等。

**与 JavaScript 的关系:**

结构化头部规范主要应用于 HTTP 协议，因此与 Web 浏览器中的 JavaScript 功能有密切关系，特别是与以下方面：

- **`fetch()` API:**  JavaScript 中的 `fetch()` API 用于发起 HTTP 请求和接收 HTTP 响应。HTTP 响应头中可能包含使用结构化头部格式定义的字段。浏览器在接收到响应后，需要解析这些头部字段，并将解析后的数据提供给 JavaScript 代码。
- **`Headers` API:**  JavaScript 提供了 `Headers` 对象来表示 HTTP 头部。当使用 `fetch()` 获取响应后，可以通过 `response.headers` 访问 `Headers` 对象。如果某个头部字段使用了结构化头部，浏览器内部会使用类似于这个测试文件中测试的解析逻辑来处理这些值。
- **Service Workers:** Service Workers 可以拦截和修改 HTTP 请求和响应，也需要处理 HTTP 头部，包括结构化头部。
- **Cache API:**  浏览器缓存机制也依赖于 HTTP 头部来决定如何缓存资源。结构化头部可能会影响缓存行为的配置。

**举例说明:**

假设一个 HTTP 响应头包含以下字段：

```
Accept-CH: Sec-CH-UA-Platform-Version=("13.0.1"), Sec-CH-UA-Arch=("arm64")
```

这是一个使用结构化头部格式定义的 `Accept-CH` 头部字段。在 JavaScript 中，当使用 `fetch()` 获取这个响应后，你可以通过 `response.headers.get('Accept-CH')` 获取到这个原始字符串。

浏览器内部的网络栈（包括这个测试文件所测试的代码）会解析这个字符串，将其转换为一个 `Dictionary`，其中：

- 键 "Sec-CH-UA-Platform-Version" 对应的值是一个 `ParameterizedItem`，其 Item 是字符串 "13.0.1"。
- 键 "Sec-CH-UA-Arch" 对应的值是一个 `ParameterizedItem`，其 Item 是字符串 "arm64"。

虽然 JavaScript 自身通常不会直接操作这些底层的结构化头部数据结构，但浏览器会将解析后的信息用于后续的处理，例如：

- **Client Hints:**  `Accept-CH` 用于声明客户端支持的 Client Hints，浏览器会根据解析后的信息在后续请求中发送对应的提示头部。

**逻辑推理 (假设输入与输出):**

**假设输入:**  `"text/html;q=0.8"` (一个表示 MIME 类型及其质量因子的结构化头部字符串)

**测试的函数:** `ParseItem`

**预期输出:** `ParameterizedItem`  对象，其内部结构为：

```
{
  item: Token("text/html"),
  params: {
    "q": Item(0.8)
  }
}
```

**假设输入:** `" (1 2 3);a=true,  4;b"` (一个包含列表和参数的结构化头部字符串)

**测试的函数:** `ParseList`

**预期输出:** `List` 对象，其内部结构为：

```
[
  {
    inner_list: [ Item(1), Item(2), Item(3) ],
    params: { "a": Item(true) }
  },
  {
    inner_list: [ Item(4) ],
    params: { "b": Item(true) }
  }
]
```

**用户或编程常见的使用错误 (举例说明):**

1. **服务端配置错误:**  服务端配置 HTTP 头部时，没有遵循结构化头部的语法规则。例如：
   ```
   // 错误示例：缺少引号
   Content-Type: text/html; charset=utf-8
   // 如果 "utf-8" 需要作为 token 处理，则不需要引号。但如果需要区分大小写或者包含特殊字符，则应该加引号。
   ```
   浏览器在解析时可能会失败，导致功能异常。

2. **JavaScript 代码中手动构建错误的头部值:**  虽然通常不建议在 JavaScript 中手动构建复杂的结构化头部，但如果需要这样做，开发者可能会犯错：
   ```javascript
   // 错误示例：参数值缺少引号
   fetch('/api', {
     headers: {
       'My-Custom-Header': 'value;param=bad value'
     }
   });
   ```
   如果服务端期望 `param` 的值是带引号的字符串，则会导致解析错误。

3. **服务端和客户端对结构化头部规范理解不一致:**  服务端按照旧版本的规范生成头部，而客户端按照新版本的规范解析，或者反之，可能导致解析错误或数据丢失。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户报告一个网页功能异常，例如某个特定的资源加载失败或行为不符合预期。以下是调试过程可能涉及这个测试文件的步骤：

1. **用户访问网页并触发功能异常。**
2. **开发者打开浏览器的开发者工具 (通常按 F12)。**
3. **在 "Network" (网络) 标签页中，开发者检查与功能异常相关的 HTTP 请求和响应。**
4. **开发者注意到某个相关的 HTTP 响应头字段的值看起来很奇怪或者与预期不符，怀疑是头部解析问题。**
5. **如果该头部字段使用了结构化头部规范，开发者可能会怀疑浏览器的结构化头部解析器存在问题。**
6. **Chromium 开发者可能会查看 `net/third_party/quiche/src/quiche/common/structured_headers_test.cc` 这个测试文件，以了解结构化头部解析器的实现逻辑和已知的测试用例。**
7. **开发者可以尝试在本地运行相关的测试用例，或者添加新的测试用例来复现和调试用户报告的问题。**
8. **如果发现解析器存在 bug，开发者会修改 `quiche/common/structured_headers.cc` 中的解析代码，并确保修改后的代码能够通过 `structured_headers_test.cc` 中的所有测试。**

总而言之，`net/third_party/quiche/src/quiche/common/structured_headers_test.cc` 是 Chromium 中用于确保其结构化头部解析和序列化功能正确性的关键测试文件，这对于浏览器正确处理 HTTP 头部至关重要，并直接影响到 Web 页面的功能和性能。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/common/structured_headers_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/common/structured_headers.h"

#include <math.h>

#include <limits>
#include <optional>
#include <string>
#include <utility>

#include "quiche/common/platform/api/quiche_test.h"

namespace quiche {
namespace structured_headers {
namespace {

// Helpers to make test cases clearer

Item Token(std::string value) { return Item(value, Item::kTokenType); }

Item Integer(int64_t value) { return Item(value); }

// Parameter with null value, only used in Structured Headers Draft 09
std::pair<std::string, Item> NullParam(std::string key) {
  return std::make_pair(key, Item());
}

std::pair<std::string, Item> BooleanParam(std::string key, bool value) {
  return std::make_pair(key, Item(value));
}

std::pair<std::string, Item> DoubleParam(std::string key, double value) {
  return std::make_pair(key, Item(value));
}

std::pair<std::string, Item> Param(std::string key, int64_t value) {
  return std::make_pair(key, Item(value));
}

std::pair<std::string, Item> Param(std::string key, std::string value) {
  return std::make_pair(key, Item(value));
}

std::pair<std::string, Item> ByteSequenceParam(std::string key,
                                               std::string value) {
  return std::make_pair(key, Item(value, Item::kByteSequenceType));
}

std::pair<std::string, Item> TokenParam(std::string key, std::string value) {
  return std::make_pair(key, Token(value));
}

// Test cases taken from https://github.com/httpwg/structured-header-tests can
// be found in structured_headers_generated_unittest.cc

const struct ItemTestCase {
  const char* name;
  const char* raw;
  const std::optional<Item> expected;  // nullopt if parse error is expected.
  const char* canonical;  // nullptr if parse error is expected, or if canonical
                          // format is identical to raw.
} item_test_cases[] = {
    // Token
    {"bad token - item", "abc$@%!", std::nullopt, nullptr},
    {"leading whitespace", " foo", Token("foo"), "foo"},
    {"trailing whitespace", "foo ", Token("foo"), "foo"},
    {"leading asterisk", "*foo", Token("*foo"), nullptr},
    // Number
    {"long integer", "999999999999999", Integer(999999999999999L), nullptr},
    {"long negative integer", "-999999999999999", Integer(-999999999999999L),
     nullptr},
    {"too long integer", "1000000000000000", std::nullopt, nullptr},
    {"negative too long integer", "-1000000000000000", std::nullopt, nullptr},
    {"integral decimal", "1.0", Item(1.0), nullptr},
    // String
    {"basic string", "\"foo\"", Item("foo"), nullptr},
    {"non-ascii string", "\"f\xC3\xBC\xC3\xBC\"", std::nullopt, nullptr},
    // Additional tests
    {"valid quoting containing \\n", "\"\\\\n\"", Item("\\n"), nullptr},
    {"valid quoting containing \\t", "\"\\\\t\"", Item("\\t"), nullptr},
    {"valid quoting containing \\x", "\"\\\\x61\"", Item("\\x61"), nullptr},
    {"c-style hex escape in string", "\"\\x61\"", std::nullopt, nullptr},
    {"valid quoting containing \\u", "\"\\\\u0061\"", Item("\\u0061"), nullptr},
    {"c-style unicode escape in string", "\"\\u0061\"", std::nullopt, nullptr},
};

const ItemTestCase sh09_item_test_cases[] = {
    // Integer
    {"large integer", "9223372036854775807", Integer(9223372036854775807L),
     nullptr},
    {"large negative integer", "-9223372036854775807",
     Integer(-9223372036854775807L), nullptr},
    {"too large integer", "9223372036854775808", std::nullopt, nullptr},
    {"too large negative integer", "-9223372036854775808", std::nullopt,
     nullptr},
    // Byte Sequence
    {"basic binary", "*aGVsbG8=*", Item("hello", Item::kByteSequenceType),
     nullptr},
    {"empty binary", "**", Item("", Item::kByteSequenceType), nullptr},
    {"bad paddding", "*aGVsbG8*", Item("hello", Item::kByteSequenceType),
     "*aGVsbG8=*"},
    {"bad end delimiter", "*aGVsbG8=", std::nullopt, nullptr},
    {"extra whitespace", "*aGVsb G8=*", std::nullopt, nullptr},
    {"extra chars", "*aGVsbG!8=*", std::nullopt, nullptr},
    {"suffix chars", "*aGVsbG8=!*", std::nullopt, nullptr},
    {"non-zero pad bits", "*iZ==*", Item("\x89", Item::kByteSequenceType),
     "*iQ==*"},
    {"non-ASCII binary", "*/+Ah*", Item("\xFF\xE0!", Item::kByteSequenceType),
     nullptr},
    {"base64url binary", "*_-Ah*", std::nullopt, nullptr},
    {"token with leading asterisk", "*foo", std::nullopt, nullptr},
};

// For Structured Headers Draft 15
const struct ParameterizedItemTestCase {
  const char* name;
  const char* raw;
  const std::optional<ParameterizedItem>
      expected;           // nullopt if parse error is expected.
  const char* canonical;  // nullptr if parse error is expected, or if canonical
                          // format is identical to raw.
} parameterized_item_test_cases[] = {
    {"single parameter item",
     "text/html;q=1.0",
     {{Token("text/html"), {DoubleParam("q", 1)}}},
     nullptr},
    {"missing parameter value item",
     "text/html;a;q=1.0",
     {{Token("text/html"), {BooleanParam("a", true), DoubleParam("q", 1)}}},
     nullptr},
    {"missing terminal parameter value item",
     "text/html;q=1.0;a",
     {{Token("text/html"), {DoubleParam("q", 1), BooleanParam("a", true)}}},
     nullptr},
    {"duplicate parameter keys with different value",
     "text/html;a=1;b=2;a=3.0",
     {{Token("text/html"), {DoubleParam("a", 3), Param("b", 2L)}}},
     "text/html;a=3.0;b=2"},
    {"multiple duplicate parameter keys at different position",
     "text/html;c=1;a=2;b;b=3.0;a",
     {{Token("text/html"),
       {Param("c", 1L), BooleanParam("a", true), DoubleParam("b", 3)}}},
     "text/html;c=1;a;b=3.0"},
    {"duplicate parameter keys with missing value",
     "text/html;a;a=1",
     {{Token("text/html"), {Param("a", 1L)}}},
     "text/html;a=1"},
    {"whitespace before = parameterised item", "text/html, text/plain;q =0.5",
     std::nullopt, nullptr},
    {"whitespace after = parameterised item", "text/html, text/plain;q= 0.5",
     std::nullopt, nullptr},
    {"whitespace before ; parameterised item", "text/html, text/plain ;q=0.5",
     std::nullopt, nullptr},
    {"whitespace after ; parameterised item",
     "text/plain; q=0.5",
     {{Token("text/plain"), {DoubleParam("q", 0.5)}}},
     "text/plain;q=0.5"},
    {"extra whitespace parameterised item",
     "text/plain;  q=0.5;  charset=utf-8",
     {{Token("text/plain"),
       {DoubleParam("q", 0.5), TokenParam("charset", "utf-8")}}},
     "text/plain;q=0.5;charset=utf-8"},
};

// For Structured Headers Draft 15
const struct ListTestCase {
  const char* name;
  const char* raw;
  const std::optional<List> expected;  // nullopt if parse error is expected.
  const char* canonical;  // nullptr if parse error is expected, or if canonical
                          // format is identical to raw.
} list_test_cases[] = {
    // Lists of lists
    {"extra whitespace list of lists",
     "(1  42)",
     {{{{{Integer(1L), {}}, {Integer(42L), {}}}, {}}}},
     "(1 42)"},
    // Parameterized Lists
    {"basic parameterised list",
     "abc_123;a=1;b=2; cdef_456, ghi;q=\"9\";r=\"+w\"",
     {{{Token("abc_123"),
        {Param("a", 1), Param("b", 2), BooleanParam("cdef_456", true)}},
       {Token("ghi"), {Param("q", "9"), Param("r", "+w")}}}},
     "abc_123;a=1;b=2;cdef_456, ghi;q=\"9\";r=\"+w\""},
    // Parameterized inner lists
    {"parameterised basic list of lists",
     "(1;a=1.0 2), (42 43)",
     {{{{{Integer(1L), {DoubleParam("a", 1.0)}}, {Integer(2L), {}}}, {}},
       {{{Integer(42L), {}}, {Integer(43L), {}}}, {}}}},
     nullptr},
    {"parameters on inner members",
     "(1;a=1.0 2;b=c), (42;d=?0 43;e=:Zmdo:)",
     {{{{{Integer(1L), {DoubleParam("a", 1.0)}},
         {Integer(2L), {TokenParam("b", "c")}}},
        {}},
       {{{Integer(42L), {BooleanParam("d", false)}},
         {Integer(43L), {ByteSequenceParam("e", "fgh")}}},
        {}}}},
     nullptr},
    {"parameters on inner lists",
     "(1 2);a=1.0, (42 43);b=?0",
     {{{{{Integer(1L), {}}, {Integer(2L), {}}}, {DoubleParam("a", 1.0)}},
       {{{Integer(42L), {}}, {Integer(43L), {}}}, {BooleanParam("b", false)}}}},
     nullptr},
    {"default true values for parameters on inner list members",
     "(1;a 2), (42 43;b)",
     {{{{{Integer(1L), {BooleanParam("a", true)}}, {Integer(2L), {}}}, {}},
       {{{Integer(42L), {}}, {Integer(43L), {BooleanParam("b", true)}}}, {}}}},
     nullptr},
    {"default true values for parameters on inner lists",
     "(1 2);a, (42 43);b",
     {{{{{Integer(1L), {}}, {Integer(2L), {}}}, {BooleanParam("a", true)}},
       {{{Integer(42L), {}}, {Integer(43L), {}}}, {BooleanParam("b", true)}}}},
     nullptr},
    {"extra whitespace before semicolon in parameters on inner list member",
     "(a;b ;c b)", std::nullopt, nullptr},
    {"extra whitespace between parameters on inner list member",
     "(a;b; c b)",
     {{{{{Token("a"), {BooleanParam("b", true), BooleanParam("c", true)}},
         {Token("b"), {}}},
        {}}}},
     "(a;b;c b)"},
    {"extra whitespace before semicolon in parameters on inner list",
     "(a b);c ;d, (e)", std::nullopt, nullptr},
    {"extra whitespace between parameters on inner list",
     "(a b);c; d, (e)",
     {{{{{Token("a"), {}}, {Token("b"), {}}},
        {BooleanParam("c", true), BooleanParam("d", true)}},
       {{{Token("e"), {}}}, {}}}},
     "(a b);c;d, (e)"},
};

// For Structured Headers Draft 15
const struct DictionaryTestCase {
  const char* name;
  const char* raw;
  const std::optional<Dictionary>
      expected;           // nullopt if parse error is expected.
  const char* canonical;  // nullptr if parse error is expected, or if canonical
                          // format is identical to raw.
} dictionary_test_cases[] = {
    {"basic dictionary",
     "en=\"Applepie\", da=:aGVsbG8=:",
     {Dictionary{{{"en", {Item("Applepie"), {}}},
                  {"da", {Item("hello", Item::kByteSequenceType), {}}}}}},
     nullptr},
    {"tab separated dictionary",
     "a=1\t,\tb=2",
     {Dictionary{{{"a", {Integer(1L), {}}}, {"b", {Integer(2L), {}}}}}},
     "a=1, b=2"},
    {"missing value with params dictionary",
     "a=1, b;foo=9, c=3",
     {Dictionary{{{"a", {Integer(1L), {}}},
                  {"b", {Item(true), {Param("foo", 9)}}},
                  {"c", {Integer(3L), {}}}}}},
     nullptr},
    // Parameterised dictionary tests
    {"parameterised inner list member dict",
     "a=(\"1\";b=1;c=?0 \"2\");d=\"e\"",
     {Dictionary{{{"a",
                   {{{Item("1"), {Param("b", 1), BooleanParam("c", false)}},
                     {Item("2"), {}}},
                    {Param("d", "e")}}}}}},
     nullptr},
    {"explicit true value with parameter",
     "a=?1;b=1",
     {Dictionary{{{"a", {Item(true), {Param("b", 1)}}}}}},
     "a;b=1"},
    {"implicit true value with parameter",
     "a;b=1",
     {Dictionary{{{"a", {Item(true), {Param("b", 1)}}}}}},
     nullptr},
    {"implicit true value with implicitly-valued parameter",
     "a;b",
     {Dictionary{{{"a", {Item(true), {BooleanParam("b", true)}}}}}},
     nullptr},
};
}  // namespace

TEST(StructuredHeaderTest, ParseBareItem) {
  for (const auto& c : item_test_cases) {
    SCOPED_TRACE(c.name);
    std::optional<Item> result = ParseBareItem(c.raw);
    EXPECT_EQ(result, c.expected);
  }
}

// For Structured Headers Draft 15, these tests include parameters on Items.
TEST(StructuredHeaderTest, ParseItem) {
  for (const auto& c : parameterized_item_test_cases) {
    SCOPED_TRACE(c.name);
    std::optional<ParameterizedItem> result = ParseItem(c.raw);
    EXPECT_EQ(result, c.expected);
  }
}

// Structured Headers Draft 9 parsing rules are different than Draft 15, and
// some strings which are considered invalid in SH15 should parse in SH09.
// The SH09 Item parser is not directly exposed, but can be used indirectly by
// calling the parser for SH09-specific lists.
TEST(StructuredHeaderTest, ParseSH09Item) {
  for (const auto& c : sh09_item_test_cases) {
    SCOPED_TRACE(c.name);
    std::optional<ListOfLists> result = ParseListOfLists(c.raw);
    if (c.expected.has_value()) {
      EXPECT_TRUE(result.has_value());
      EXPECT_EQ(result->size(), 1UL);
      EXPECT_EQ((*result)[0].size(), 1UL);
      EXPECT_EQ((*result)[0][0], c.expected);
    } else {
      EXPECT_FALSE(result.has_value());
    }
  }
}

// In Structured Headers Draft 9, floats can have more than three fractional
// digits, and can be larger than 1e12. This behaviour is exposed in the parser
// for SH09-specific lists, so test it through that interface.
TEST(StructuredHeaderTest, SH09HighPrecisionFloats) {
  // These values are exactly representable in binary floating point, so no
  // accuracy issues are expected in this test.
  std::optional<ListOfLists> result =
      ParseListOfLists("1.03125;-1.03125;12345678901234.5;-12345678901234.5");
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(*result,
            (ListOfLists{{Item(1.03125), Item(-1.03125), Item(12345678901234.5),
                          Item(-12345678901234.5)}}));

  result = ParseListOfLists("123456789012345.0");
  EXPECT_FALSE(result.has_value());

  result = ParseListOfLists("-123456789012345.0");
  EXPECT_FALSE(result.has_value());
}

// For Structured Headers Draft 9
TEST(StructuredHeaderTest, ParseListOfLists) {
  static const struct TestCase {
    const char* name;
    const char* raw;
    ListOfLists expected;  // empty if parse error is expected
  } cases[] = {
      {"basic list of lists",
       "1;2, 42;43",
       {{Integer(1L), Integer(2L)}, {Integer(42L), Integer(43L)}}},
      {"empty list of lists", "", {}},
      {"single item list of lists", "42", {{Integer(42L)}}},
      {"no whitespace list of lists", "1,42", {{Integer(1L)}, {Integer(42L)}}},
      {"no inner whitespace list of lists",
       "1;2, 42;43",
       {{Integer(1L), Integer(2L)}, {Integer(42L), Integer(43L)}}},
      {"extra whitespace list of lists",
       "1 , 42",
       {{Integer(1L)}, {Integer(42L)}}},
      {"extra inner whitespace list of lists",
       "1 ; 2,42 ; 43",
       {{Integer(1L), Integer(2L)}, {Integer(42L), Integer(43L)}}},
      {"trailing comma list of lists", "1;2, 42,", {}},
      {"trailing semicolon list of lists", "1;2, 42;43;", {}},
      {"leading comma list of lists", ",1;2, 42", {}},
      {"leading semicolon list of lists", ";1;2, 42;43", {}},
      {"empty item list of lists", "1,,42", {}},
      {"empty inner item list of lists", "1;;2,42", {}},
  };
  for (const auto& c : cases) {
    SCOPED_TRACE(c.name);
    std::optional<ListOfLists> result = ParseListOfLists(c.raw);
    if (!c.expected.empty()) {
      EXPECT_TRUE(result.has_value());
      EXPECT_EQ(*result, c.expected);
    } else {
      EXPECT_FALSE(result.has_value());
    }
  }
}

// For Structured Headers Draft 9
TEST(StructuredHeaderTest, ParseParameterisedList) {
  static const struct TestCase {
    const char* name;
    const char* raw;
    ParameterisedList expected;  // empty if parse error is expected
  } cases[] = {
      {"basic param-list",
       "abc_123;a=1;b=2; cdef_456, ghi;q=\"9\";r=\"w\"",
       {
           {Token("abc_123"),
            {Param("a", 1), Param("b", 2), NullParam("cdef_456")}},
           {Token("ghi"), {Param("q", "9"), Param("r", "w")}},
       }},
      {"empty param-list", "", {}},
      {"single item param-list",
       "text/html;q=1",
       {{Token("text/html"), {Param("q", 1)}}}},
      {"empty param-list", "", {}},
      {"no whitespace param-list",
       "text/html,text/plain;q=1",
       {{Token("text/html"), {}}, {Token("text/plain"), {Param("q", 1)}}}},
      {"whitespace before = param-list", "text/html, text/plain;q =1", {}},
      {"whitespace after = param-list", "text/html, text/plain;q= 1", {}},
      {"extra whitespace param-list",
       "text/html  ,  text/plain ;  q=1",
       {{Token("text/html"), {}}, {Token("text/plain"), {Param("q", 1)}}}},
      {"duplicate key", "abc;a=1;b=2;a=1", {}},
      {"numeric key", "abc;a=1;1b=2;c=1", {}},
      {"uppercase key", "abc;a=1;B=2;c=1", {}},
      {"bad key", "abc;a=1;b!=2;c=1", {}},
      {"another bad key", "abc;a=1;b==2;c=1", {}},
      {"empty key name", "abc;a=1;=2;c=1", {}},
      {"empty parameter", "abc;a=1;;c=1", {}},
      {"empty list item", "abc;a=1,,def;b=1", {}},
      {"extra semicolon", "abc;a=1;b=1;", {}},
      {"extra comma", "abc;a=1,def;b=1,", {}},
      {"leading semicolon", ";abc;a=1", {}},
      {"leading comma", ",abc;a=1", {}},
  };
  for (const auto& c : cases) {
    SCOPED_TRACE(c.name);
    std::optional<ParameterisedList> result = ParseParameterisedList(c.raw);
    if (c.expected.empty()) {
      EXPECT_FALSE(result.has_value());
      continue;
    }
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), c.expected.size());
    if (result->size() == c.expected.size()) {
      for (size_t i = 0; i < c.expected.size(); ++i) {
        EXPECT_EQ((*result)[i], c.expected[i]);
      }
    }
  }
}

// For Structured Headers Draft 15
TEST(StructuredHeaderTest, ParseList) {
  for (const auto& c : list_test_cases) {
    SCOPED_TRACE(c.name);
    std::optional<List> result = ParseList(c.raw);
    EXPECT_EQ(result, c.expected);
  }
}

// For Structured Headers Draft 15
TEST(StructuredHeaderTest, ParseDictionary) {
  for (const auto& c : dictionary_test_cases) {
    SCOPED_TRACE(c.name);
    std::optional<Dictionary> result = ParseDictionary(c.raw);
    EXPECT_EQ(result, c.expected);
  }
}

// Serializer tests are all exclusively for Structured Headers Draft 15

TEST(StructuredHeaderTest, SerializeItem) {
  for (const auto& c : item_test_cases) {
    SCOPED_TRACE(c.name);
    if (c.expected) {
      std::optional<std::string> result = SerializeItem(*c.expected);
      EXPECT_TRUE(result.has_value());
      EXPECT_EQ(result.value(), std::string(c.canonical ? c.canonical : c.raw));
    }
  }
}

TEST(StructuredHeaderTest, SerializeParameterizedItem) {
  for (const auto& c : parameterized_item_test_cases) {
    SCOPED_TRACE(c.name);
    if (c.expected) {
      std::optional<std::string> result = SerializeItem(*c.expected);
      EXPECT_TRUE(result.has_value());
      EXPECT_EQ(result.value(), std::string(c.canonical ? c.canonical : c.raw));
    }
  }
}

TEST(StructuredHeaderTest, UnserializableItems) {
  // Test that items with unknown type are not serialized.
  EXPECT_FALSE(SerializeItem(Item()).has_value());
}

TEST(StructuredHeaderTest, UnserializableTokens) {
  static const struct UnserializableString {
    const char* name;
    const char* value;
  } bad_tokens[] = {
      {"empty token", ""},
      {"contains high ascii", "a\xff"},
      {"contains nonprintable character", "a\x7f"},
      {"contains C0", "a\x01"},
      {"UTF-8 encoded", "a\xc3\xa9"},
      {"contains TAB", "a\t"},
      {"contains LF", "a\n"},
      {"contains CR", "a\r"},
      {"contains SP", "a "},
      {"begins with digit", "9token"},
      {"begins with hyphen", "-token"},
      {"begins with LF", "\ntoken"},
      {"begins with SP", " token"},
      {"begins with colon", ":token"},
      {"begins with percent", "%token"},
      {"begins with period", ".token"},
      {"begins with slash", "/token"},
  };
  for (const auto& bad_token : bad_tokens) {
    SCOPED_TRACE(bad_token.name);
    std::optional<std::string> serialization =
        SerializeItem(Token(bad_token.value));
    EXPECT_FALSE(serialization.has_value()) << *serialization;
  }
}

TEST(StructuredHeaderTest, UnserializableKeys) {
  static const struct UnserializableString {
    const char* name;
    const char* value;
  } bad_keys[] = {
      {"empty key", ""},
      {"contains high ascii", "a\xff"},
      {"contains nonprintable character", "a\x7f"},
      {"contains C0", "a\x01"},
      {"UTF-8 encoded", "a\xc3\xa9"},
      {"contains TAB", "a\t"},
      {"contains LF", "a\n"},
      {"contains CR", "a\r"},
      {"contains SP", "a "},
      {"begins with uppercase", "Atoken"},
      {"begins with digit", "9token"},
      {"begins with hyphen", "-token"},
      {"begins with LF", "\ntoken"},
      {"begins with SP", " token"},
      {"begins with colon", ":token"},
      {"begins with percent", "%token"},
      {"begins with period", ".token"},
      {"begins with slash", "/token"},
  };
  for (const auto& bad_key : bad_keys) {
    SCOPED_TRACE(bad_key.name);
    std::optional<std::string> serialization =
        SerializeItem(ParameterizedItem("a", {{bad_key.value, "a"}}));
    EXPECT_FALSE(serialization.has_value()) << *serialization;
  }
}

TEST(StructuredHeaderTest, UnserializableStrings) {
  static const struct UnserializableString {
    const char* name;
    const char* value;
  } bad_strings[] = {
      {"contains high ascii", "a\xff"},
      {"contains nonprintable character", "a\x7f"},
      {"UTF-8 encoded", "a\xc3\xa9"},
      {"contains TAB", "a\t"},
      {"contains LF", "a\n"},
      {"contains CR", "a\r"},
      {"contains C0", "a\x01"},
  };
  for (const auto& bad_string : bad_strings) {
    SCOPED_TRACE(bad_string.name);
    std::optional<std::string> serialization =
        SerializeItem(Item(bad_string.value));
    EXPECT_FALSE(serialization.has_value()) << *serialization;
  }
}

TEST(StructuredHeaderTest, UnserializableIntegers) {
  EXPECT_FALSE(SerializeItem(Integer(1e15L)).has_value());
  EXPECT_FALSE(SerializeItem(Integer(-1e15L)).has_value());
}

TEST(StructuredHeaderTest, UnserializableDecimals) {
  for (double value :
       {std::numeric_limits<double>::quiet_NaN(),
        std::numeric_limits<double>::infinity(),
        -std::numeric_limits<double>::infinity(), 1e12, 1e12 - 0.0001,
        1e12 - 0.0005, -1e12, -1e12 + 0.0001, -1e12 + 0.0005}) {
    auto x = SerializeItem(Item(value));
    EXPECT_FALSE(SerializeItem(Item(value)).has_value());
  }
}

// These values cannot be directly parsed from headers, but are valid doubles
// which can be serialized as sh-floats (though rounding is expected.)
TEST(StructuredHeaderTest, SerializeUnparseableDecimals) {
  struct UnparseableDecimal {
    const char* name;
    double value;
    const char* canonical;
  } float_test_cases[] = {
      {"negative 0", -0.0, "0.0"},
      {"0.0001", 0.0001, "0.0"},
      {"0.0000001", 0.0000001, "0.0"},
      {"1.0001", 1.0001, "1.0"},
      {"1.0009", 1.0009, "1.001"},
      {"round positive odd decimal", 0.0015, "0.002"},
      {"round positive even decimal", 0.0025, "0.002"},
      {"round negative odd decimal", -0.0015, "-0.002"},
      {"round negative even decimal", -0.0025, "-0.002"},
      {"round decimal up to integer part", 9.9995, "10.0"},
      {"subnormal numbers", std::numeric_limits<double>::denorm_min(), "0.0"},
      {"round up to 10 digits", 1e9 - 0.0000001, "1000000000.0"},
      {"round up to 11 digits", 1e10 - 0.000001, "10000000000.0"},
      {"round up to 12 digits", 1e11 - 0.00001, "100000000000.0"},
      {"largest serializable float", nextafter(1e12 - 0.0005, 0),
       "999999999999.999"},
      {"largest serializable negative float", -nextafter(1e12 - 0.0005, 0),
       "-999999999999.999"},
      // This will fail if we simply truncate the fractional portion.
      {"float rounds up to next int", 3.9999999, "4.0"},
      // This will fail if we first round to >3 digits, and then round again to
      // 3 digits.
      {"don't double round", 3.99949, "3.999"},
      // This will fail if we first round to 3 digits, and then round again to
      // max_avail_digits.
      {"don't double round", 123456789.99949, "123456789.999"},
  };
  for (const auto& test_case : float_test_cases) {
    SCOPED_TRACE(test_case.name);
    std::optional<std::string> serialization =
        SerializeItem(Item(test_case.value));
    EXPECT_TRUE(serialization.has_value());
    EXPECT_EQ(*serialization, test_case.canonical);
  }
}

TEST(StructuredHeaderTest, SerializeList) {
  for (const auto& c : list_test_cases) {
    SCOPED_TRACE(c.name);
    if (c.expected) {
      std::optional<std::string> result = SerializeList(*c.expected);
      EXPECT_TRUE(result.has_value());
      EXPECT_EQ(result.value(), std::string(c.canonical ? c.canonical : c.raw));
    }
  }
}

TEST(StructuredHeaderTest, UnserializableLists) {
  static const struct UnserializableList {
    const char* name;
    const List value;
  } bad_lists[] = {
      {"Null item as member", {{Item(), {}}}},
      {"Unserializable item as member", {{Token("\n"), {}}}},
      {"Key is empty", {{Token("abc"), {Param("", 1)}}}},
      {"Key containswhitespace", {{Token("abc"), {Param("a\n", 1)}}}},
      {"Key contains UTF8", {{Token("abc"), {Param("a\xc3\xa9", 1)}}}},
      {"Key contains unprintable characters",
       {{Token("abc"), {Param("a\x7f", 1)}}}},
      {"Key contains disallowed characters",
       {{Token("abc"), {Param("a:", 1)}}}},
      {"Param value is unserializable", {{Token("abc"), {{"a", Token("\n")}}}}},
      {"Inner list contains unserializable item",
       {{std::vector<ParameterizedItem>{{Token("\n"), {}}}, {}}}},
  };
  for (const auto& bad_list : bad_lists) {
    SCOPED_TRACE(bad_list.name);
    std::optional<std::string> serialization = SerializeList(bad_list.value);
    EXPECT_FALSE(serialization.has_value()) << *serialization;
  }
}

TEST(StructuredHeaderTest, SerializeDictionary) {
  for (const auto& c : dictionary_test_cases) {
    SCOPED_TRACE(c.name);
    if (c.expected) {
      std::optional<std::string> result = SerializeDictionary(*c.expected);
      EXPECT_TRUE(result.has_value());
      EXPECT_EQ(result.value(), std::string(c.canonical ? c.canonical : c.raw));
    }
  }
}

TEST(StructuredHeaderTest, DictionaryConstructors) {
  const std::string key0 = "key0";
  const std::string key1 = "key1";
  const ParameterizedMember member0{Item("Applepie"), {}};
  const ParameterizedMember member1{Item("hello", Item::kByteSequenceType), {}};

  Dictionary dict;
  EXPECT_TRUE(dict.empty());
  EXPECT_EQ(0U, dict.size());
  dict[key0] = member0;
  EXPECT_FALSE(dict.empty());
  EXPECT_EQ(1U, dict.size());

  const Dictionary dict_copy = dict;
  EXPECT_FALSE(dict_copy.empty());
  EXPECT_EQ(1U, dict_copy.size());
  EXPECT_EQ(dict, dict_copy);

  const Dictionary dict_init{{{key0, member0}, {key1, member1}}};
  EXPECT_FALSE(dict_init.empty());
  EXPECT_EQ(2U, dict_init.size());
  EXPECT_EQ(member0, dict_init.at(key0));
  EXPECT_EQ(member1, dict_init.at(key1));
}

TEST(StructuredHeaderTest, DictionaryClear) {
  const std::string key0 = "key0";
  const ParameterizedMember member0{Item("Applepie"), {}};

  Dictionary dict({{key0, member0}});
  EXPECT_EQ(1U, dict.size());
  EXPECT_FALSE(dict.empty());
  EXPECT_TRUE(dict.contains(key0));

  dict.clear();
  EXPECT_EQ(0U, dict.size());
  EXPECT_TRUE(dict.empty());
  EXPECT_FALSE(dict.contains(key0));
}

TEST(StructuredHeaderTest, DictionaryAccessors) {
  const std::string key0 = "key0";
  const std::string key1 = "key1";

  const ParameterizedMember nonempty_member0{Item("Applepie"), {}};
  const ParameterizedMember nonempty_member1{
      Item("hello", Item::kByteSequenceType), {}};
  const ParameterizedMember empty_member;

  Dictionary dict{{{key0, nonempty_member0}}};
  EXPECT_TRUE(dict.contains(key0));
  EXPECT_EQ(nonempty_member0, dict[key0]);
  EXPECT_EQ(&dict[key0], &dict.at(key0));
  EXPECT_EQ(&dict[key0], &dict[0]);
  EXPECT_EQ(&dict[key0], &dict.at(0));

  {
    auto it = dict.find(key0);
    ASSERT_TRUE(it != dict.end());
    EXPECT_EQ(it->first, key0);
    EXPECT_EQ(it->second, nonempty_member0);
  }

  // Even if the key does not yet exist in |dict|, operator[]() should
  // automatically create an empty entry.
  ASSERT_FALSE(dict.contains(key1));
  EXPECT_TRUE(dict.find(key1) == dict.end());
  ParameterizedMember& member1 = dict[key1];
  EXPECT_TRUE(dict.contains(key1));
  EXPECT_EQ(empty_member, member1);
  EXPECT_EQ(&member1, &dict[key1]);
  EXPECT_EQ(&member1, &dict.at(key1));
  EXPECT_EQ(&member1, &dict[1]);
  EXPECT_EQ(&member1, &dict.at(1));

  member1 = nonempty_member1;
  EXPECT_EQ(nonempty_member1, dict[key1]);
  EXPECT_EQ(&dict[key1], &dict.at(key1));
  EXPECT_EQ(&dict[key1], &dict[1]);
  EXPECT_EQ(&dict[key1], &dict.at(1));

  // at(StringPiece) and indexed accessors have const overloads.
  const Dictionary& dict_ref = dict;
  EXPECT_EQ(&member1, &dict_ref.at(key1));
  EXPECT_EQ(&member1, &dict_ref[1]);
  EXPECT_EQ(&member1, &dict_ref.at(1));
}

TEST(StructuredHeaderTest, UnserializableDictionary) {
  static const struct UnserializableDictionary {
    const char* name;
    const Dictionary value;
  } bad_dictionaries[] = {
      {"Unserializable dict key", Dictionary{{{"ABC", {Token("abc"), {}}}}}},
      {"Dictionary item is unserializable",
       Dictionary{{{"abc", {Token("abc="), {}}}}}},
      {"Param value is unserializable",
       Dictionary{{{"abc", {Token("abc"), {{"a", Token("\n")}}}}}}},
      {"Dictionary inner-list contains unserializable item",
       Dictionary{
           {{"abc",
             {std::vector<ParameterizedItem>{{Token("abc="), {}}}, {}}}}}},
  };
  for (const auto& bad_dictionary : bad_dictionaries) {
    SCOPED_TRACE(bad_dictionary.name);
    std::optional<std::string> serialization =
        SerializeDictionary(bad_dictionary.value);
    EXPECT_FALSE(serialization.has_value()) << *serialization;
  }
}

}  // namespace structured_headers
}  // namespace quiche
```