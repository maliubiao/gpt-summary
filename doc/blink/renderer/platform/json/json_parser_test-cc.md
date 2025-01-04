Response:
Let's break down the thought process for analyzing the `json_parser_test.cc` file.

1. **Identify the Core Purpose:** The filename immediately suggests this is a test file for a JSON parser. The presence of `TEST` macros from `gtest` confirms this.

2. **Understand the Testing Strategy:**  The file uses `gtest` extensively. This means the code within each `TEST` block focuses on verifying specific aspects of the `JSONParser` class. We need to examine the assertions (`ASSERT_TRUE`, `EXPECT_EQ`, `EXPECT_FALSE`, `EXPECT_DOUBLE_EQ`) to understand *what* is being tested.

3. **Analyze Individual Test Cases (`TEST` blocks):**

   * **`Reading` Test:** This is a comprehensive test. We can go through it section by section:
      * **Basic Valid JSON:** Tests parsing of simple JSON values (number, string, array, object).
      * **Whitespace:** Checks how whitespace is handled.
      * **Error Reporting:** Examines how the parser reports errors (message, line, column, type).
      * **Comments:** Tests parsing with and without comments (using `ParseJSONWithCommentsDeprecated`). This tells us the parser has comment-handling capabilities, even if deprecated.
      * **Number Formats:**  Crucially, this section tests various valid and *invalid* number formats according to the JSON specification (e.g., no leading zeros, handling of large numbers, floating-point numbers, exponents). This is vital for understanding the parser's adherence to the standard.
      * **String Parsing:** Tests basic string parsing, including escape sequences (quotes, backslashes, common escape characters). It also checks for invalid escape sequences and unclosed quotes.
      * **Control Characters:** Highlights a key restriction in JSON: bare control characters are disallowed in strings.
      * **Arrays:** Tests parsing of simple, empty, and nested arrays. It also checks for common array syntax errors (missing commas, trailing commas, too many commas).
      * **Objects:** Similar to arrays, tests parsing of simple and nested objects. It also verifies error handling for invalid object syntax (missing braces, unquoted keys, trailing commas, missing separators).
      * **Newline Equivalence:**  Demonstrates that different newline characters (`\n`, `\r\n`) are treated the same.
      * **Whitespace Restrictions:**  Explicitly tests allowed and disallowed whitespace characters, reinforcing the strictness of the JSON format.
      * **Nesting:** Checks parsing of nested objects and arrays.
      * **Keys with Periods:**  Tests whether keys containing periods are handled correctly (they should be as strings).
      * **Stack Overflow:**  Tests the parser's robustness against excessively nested structures (a potential denial-of-service vulnerability). It also shows that a large number of *adjacent* lists is handled correctly.
      * **UTF-8 and UTF-16:** Tests parsing of strings with Unicode characters, including surrogate pairs. It also highlights errors for invalid Unicode sequences.
      * **Literal Root Objects:** Tests parsing of single JSON values as the root (e.g., just `null`, `true`, a number, or a string).

   * **`InvalidSanity` Test:** This is a quick check for a range of obviously invalid JSON strings to ensure the parser correctly identifies them as errors.

   * **`LimitedDepth` Test:** This focuses on the parser's ability to limit the maximum nesting depth. It demonstrates:
      * Successful parsing at the default and minimum allowed depths.
      * Parsing failures at depths below the minimum required.
      * That a depth of 0 prevents any parsing.
      * That the parser has a built-in maximum nesting depth.

4. **Identify Relationships to Web Technologies (JavaScript, HTML, CSS):**

   * **JavaScript:** JSON is a fundamental data exchange format for JavaScript. The parser's ability to handle various JSON constructs directly impacts how web pages process data received from servers or stored locally. Think of `JSON.parse()` in JavaScript – this parser is essentially doing the underlying work for that.
   * **HTML:** While HTML doesn't directly "parse" JSON in the same way, JSON is often embedded within `<script>` tags for configuration or data initialization. Also, server responses containing JSON are frequently used to dynamically update HTML content.
   * **CSS:** CSS is less directly related. However, with the advent of CSS Custom Properties and the `env()` function, there's a potential, though less common, scenario where JSON-like structures might be used for configuration passed to CSS. This is a weaker connection.

5. **Infer Logical Reasoning and Provide Examples:** The tests themselves provide excellent examples of input and expected output (success or failure, error messages). We can summarize these based on the test cases. For instance:

   * **Assumption:** The parser correctly handles escape sequences.
   * **Input:** `"\\n"`
   * **Output:**  A string containing a newline character.

   * **Assumption:** The parser correctly identifies syntax errors.
   * **Input:** `"{a:1}"`
   * **Output:**  Parsing failure with a "Syntax error" message indicating the unquoted key.

6. **Identify Common Usage Errors:** By looking at the *negative* test cases (where parsing fails), we can infer common mistakes developers might make when dealing with JSON. Examples include:

   * Forgetting closing quotes or braces.
   * Using unquoted keys in objects.
   * Including trailing commas in arrays or objects.
   * Using invalid escape sequences.
   * Including comments when the parser isn't configured to allow them.
   * Exceeding the maximum nesting depth.
   * Using invalid number formats (leading zeros, etc.).

7. **Structure the Output:**  Organize the findings into clear categories (Functionality, Relationship to Web Technologies, Logical Reasoning, Common Errors) for better readability. Use bullet points and code examples where appropriate.

This systematic approach, going from the general purpose to specific test cases and then connecting those findings to broader concepts, allows for a comprehensive understanding of the `json_parser_test.cc` file and the functionality it verifies.
这个C++源代码文件 `json_parser_test.cc` 是 Chromium Blink 引擎中 JSON 解析器 (`JSONParser`) 的单元测试文件。它的主要功能是：

**功能列举：**

1. **验证 JSON 解析器能否正确解析有效的 JSON 字符串：**
   - 测试各种 JSON 数据类型：null, boolean, integer, double, string, array, object。
   - 测试不同格式的数字，包括整数、浮点数、科学计数法。
   - 测试字符串的转义字符，包括 `\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`, `\v` 和 Unicode 字符（`\uXXXX`）。
   - 测试空字符串、空数组和空对象。
   - 测试嵌套的数组和对象。
   - 测试包含空格的 JSON 字符串。
   - 测试允许的空白字符（TAB, CR, LF, SP）和不允许的空白字符。
   - 测试具有包含句点的键的对象。
   - 测试 UTF-16 编码的字符串。
   - 测试将单个 JSON 字面量（null, true, number, string）作为根对象进行解析。

2. **验证 JSON 解析器能否正确识别和报告无效的 JSON 字符串：**
   - 测试各种语法错误，例如：
     - 缺少引号或括号。
     - 错误的标点符号（逗号，冒号）。
     - 非法的转义字符。
     - 不允许的注释（在默认配置下）。
     - 数字格式错误（例如，前导零，非法的指数）。
     - 字符串中包含控制字符。
     - 多余的逗号。
     - 意外的字符。
   - 测试堆栈溢出场景，即当 JSON 结构过于深层嵌套时，解析器应能正确处理。
   - 测试无效的 UTF-8 编码。
   - 测试包含无效 Unicode 字符的 JSON 字符串。

3. **测试 JSON 解析器对注释的处理 (通过 `ParseJSONWithCommentsDeprecated`)：**
   - 测试单行注释 (`//`) 和多行注释 (`/* ... */`)。
   - 验证在允许注释的情况下，解析器能够忽略注释并正确解析 JSON 内容。
   - 验证在不允许注释的情况下，包含注释的 JSON 字符串会被识别为无效。

4. **测试 JSON 解析器对最大嵌套深度的限制：**
   - 验证可以设置最大嵌套深度，并且当 JSON 结构超出该深度时，解析会失败并报告错误。
   - 验证最大嵌套深度有一个上限。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:** JSON (JavaScript Object Notation) 最初是为 JavaScript 设计的数据交换格式，因此该测试文件直接关系到 Blink 引擎中 JavaScript 对 JSON 的处理能力。
    * **举例说明:** 当 JavaScript 代码使用 `JSON.parse()` 函数解析从服务器接收到的 JSON 数据时，底层的解析工作可能就由 `JSONParser` 完成。这个测试文件确保了 `JSONParser` 能够正确解析 JavaScript 代码中可能遇到的各种 JSON 结构。
    * **假设输入与输出:**
        * **假设输入:**  JavaScript 代码接收到 JSON 字符串 `{"name": "John", "age": 30}`。
        * **输出:**  `JSONParser` 成功解析，并返回一个可以被 JavaScript 代码操作的 JSON 对象，其中包含键值对 "name": "John" 和 "age": 30。

* **HTML:** HTML 本身不直接解析 JSON，但 JSON 常常被嵌入在 HTML 的 `<script>` 标签中，用于初始化 JavaScript 变量或存储配置数据。
    * **举例说明:**  HTML 中可能包含 `<script>const config = {"api_url": "https://example.com/api"};</script>`。虽然这不是直接由 HTML 解析器处理的，但当这段 JavaScript 代码执行时，JSON 字面量会被解析。`json_parser_test.cc` 确保了 Blink 引擎能够正确处理这类嵌入在 HTML 中的 JSON 数据。
    * **假设输入与输出:**
        * **假设输入:** HTML 中嵌入了 JSON 字符串 `[1, 2, 3]`。
        * **输出:** 当 JavaScript 执行到使用这个 JSON 字面量的代码时，`JSONParser` 能够成功将其解析为一个包含三个数字的数组。

* **CSS:** CSS 本身与 JSON 的关系相对较弱。尽管如此，在一些高级场景中，例如通过 JavaScript 操作 CSS 变量或自定义属性时，可能会涉及到 JSON 数据。
    * **举例说明:** JavaScript 可能从服务器获取 JSON 数据，然后根据这些数据动态生成或修改 CSS 样式。例如，根据 JSON 数据中的颜色值设置元素的背景色。 虽然 CSS 本身不解析 JSON，但 JSON 数据的正确解析是实现这种功能的前提。
    * **假设输入与输出:**
        * **假设输入:** JavaScript 从服务器获取 JSON 字符串 `{"background_color": "red"}`。
        * **输出:** `JSONParser` 成功解析，JavaScript 代码可以读取 `background_color` 的值，并将其应用到 CSS 样式中。

**逻辑推理的假设输入与输出:**

* **假设输入:** JSON 字符串 `"true"`
* **输出:**  一个 `JSONValue` 对象，其类型为 `kTypeBoolean`，值为 `true`。

* **假设输入:** JSON 字符串 `"{\"key\": 123}"`
* **输出:** 一个 `JSONValue` 对象，其类型为 `kTypeObject`，包含一个键值对 `"key": 123`。

* **假设输入:** 无效的 JSON 字符串 `"{key: 123}"` (键没有加引号)
* **输出:** `ParseJSON` 返回 `nullptr`，并且 `JSONParseError` 对象会包含错误信息，例如 "Line: 1, column: 2, Syntax error."

**涉及用户或编程常见的使用错误：**

1. **忘记在字符串键或值上使用引号：**
   * **错误示例:** `{key: value}` 或 `{"key": value}` (如果 value 是字符串，应该写成 `"value"`)
   * **测试用例体现:**  `root = ParseJSON("{foo:true}", &error);`

2. **在数组或对象的末尾添加多余的逗号：**
   * **错误示例:** `[1, 2,]` 或 `{"a": 1,}`
   * **测试用例体现:** `root = ParseJSON("[true,]", &error);` 和 `root = ParseJSON("{\"a\":true,}", &error);`

3. **在数组或对象元素之间缺少逗号：**
   * **错误示例:** `[1 2]` 或 `{"a": 1 "b": 2}`
   * **测试用例体现:** `root = ParseJSON("[true null]", &error);` 和 `root = ParseJSON("{\"a\" \"b\"}", &error);`

4. **使用不允许的转义字符：**
   * **错误示例:** `"invalid escape \\z"`
   * **测试用例体现:** `root = ParseJSON("\"\\z invalid escape char\"", &error);`

5. **在字符串中包含未转义的控制字符（例如换行符）：**
   * **错误示例:** `"包含\n换行符"`
   * **测试用例体现:** `root = ParseJSON("\"\n\"", &error);`

6. **尝试解析包含注释的 JSON 字符串，但解析器配置为不允许注释：**
   * **错误示例:**  `/* comment */{"key": "value"}` (当使用 `ParseJSON` 而不是 `ParseJSONWithCommentsDeprecated` 时)
   * **测试用例体现:** `root = ParseJSON("/* comment */null", &error);`

7. **JSON 结构嵌套过深，导致堆栈溢出：**
   * **错误示例:**  一个包含数千层嵌套数组的 JSON 字符串。
   * **测试用例体现:**  `StringBuilder evil; ... root = ParseJSON(evil.ToString(), &error);`

8. **数字格式不符合 JSON 规范，例如前导零或非法的指数格式：**
   * **错误示例:** `0123` 或 `1e`
   * **测试用例体现:** `root = ParseJSON("043", &error);` 和 `root = ParseJSON("1e", &error);`

通过这些测试用例，开发者可以确保 `JSONParser` 的正确性和健壮性，避免在实际的 Web 浏览器中使用时出现解析错误，从而保证网页功能的正常运行。

Prompt: 
```
这是目录为blink/renderer/platform/json/json_parser_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/json/json_parser.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/json/json_values.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

TEST(JSONParserTest, Reading) {
  JSONParseError error;
  bool has_comments = false;
  JSONValue* tmp_value;
  std::unique_ptr<JSONValue> root;
  std::unique_ptr<JSONValue> root2;
  String str_val;
  int int_val = 0;

  // Successful parsing returns kNoError.
  root = ParseJSON("1", &error);
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONParseErrorType::kNoError, error.type);
  root = ParseJSON("\"string\"", &error);
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONParseErrorType::kNoError, error.type);
  root = ParseJSON("[]", &error);
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONParseErrorType::kNoError, error.type);
  root = ParseJSON("{}", &error);
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONParseErrorType::kNoError, error.type);

  // some whitespace checking
  root = ParseJSON("    null    ", &error);
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeNull, root->GetType());
  EXPECT_EQ(JSONParseErrorType::kNoError, error.type);

  // Invalid JSON string
  root = ParseJSON("nu", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 1, Syntax error.", error.message);

  // Error reporting
  root = ParseJSON("\n\n  nu", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 3, column: 3, Syntax error.", error.message);
  EXPECT_EQ(JSONParseErrorType::kSyntaxError, error.type);
  EXPECT_EQ(3, error.line);
  EXPECT_EQ(3, error.column);

  // Simple bool
  root = ParseJSON("true  ");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeBoolean, root->GetType());

  // Embedded comment
  root = ParseJSONWithCommentsDeprecated("40 /*/", &error, &has_comments);
  EXPECT_EQ(has_comments, true);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 4, Syntax error.", error.message);
  root = ParseJSONWithCommentsDeprecated("/* comment */null", &error,
                                         &has_comments);
  EXPECT_EQ(has_comments, true);
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeNull, root->GetType());
  root = ParseJSONWithCommentsDeprecated("40 /* comment */", &error,
                                         &has_comments);
  EXPECT_EQ(has_comments, true);
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeInteger, root->GetType());
  EXPECT_TRUE(root->AsInteger(&int_val));
  EXPECT_EQ(40, int_val);
  root = ParseJSONWithCommentsDeprecated(
      "/**/ 40 /* multi-line\n comment */ // more comment", &error,
      &has_comments);
  EXPECT_EQ(has_comments, true);
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeInteger, root->GetType());
  EXPECT_TRUE(root->AsInteger(&int_val));
  EXPECT_EQ(40, int_val);
  root =
      ParseJSONWithCommentsDeprecated("true // comment", &error, &has_comments);
  EXPECT_EQ(has_comments, true);
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeBoolean, root->GetType());
  root = ParseJSONWithCommentsDeprecated("/* comment */\"sample string\"",
                                         &error, &has_comments);
  EXPECT_EQ(has_comments, true);
  ASSERT_TRUE(root.get());
  EXPECT_TRUE(root->AsString(&str_val));
  EXPECT_EQ("sample string", str_val);
  root = ParseJSONWithCommentsDeprecated("[1, /* comment, 2 ] */ \n 3]", &error,
                                         &has_comments);
  EXPECT_EQ(has_comments, true);
  ASSERT_TRUE(root.get());
  JSONArray* list = JSONArray::Cast(root.get());
  ASSERT_TRUE(list);
  EXPECT_EQ(2u, list->size());
  tmp_value = list->at(0);
  ASSERT_TRUE(tmp_value);
  EXPECT_TRUE(tmp_value->AsInteger(&int_val));
  EXPECT_EQ(1, int_val);
  tmp_value = list->at(1);
  ASSERT_TRUE(tmp_value);
  EXPECT_TRUE(tmp_value->AsInteger(&int_val));
  EXPECT_EQ(3, int_val);
  root =
      ParseJSONWithCommentsDeprecated("[1, /*a*/2, 3]", &error, &has_comments);
  EXPECT_EQ(has_comments, true);
  ASSERT_TRUE(root.get());
  list = JSONArray::Cast(root.get());
  ASSERT_TRUE(list);
  EXPECT_EQ(3u, list->size());
  root = ParseJSONWithCommentsDeprecated("/* comment **/42", &error,
                                         &has_comments);
  EXPECT_EQ(has_comments, true);
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeInteger, root->GetType());
  EXPECT_TRUE(root->AsInteger(&int_val));
  EXPECT_EQ(42, int_val);
  root = ParseJSONWithCommentsDeprecated(
      "/* comment **/\n"
      "// */ 43\n"
      "44",
      &error, &has_comments);
  EXPECT_EQ(has_comments, true);
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeInteger, root->GetType());
  EXPECT_TRUE(root->AsInteger(&int_val));
  EXPECT_EQ(44, int_val);

  // Comments are otherwise rejected.
  root = ParseJSON("/* comment */null", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 1, Syntax error.", error.message);
  root = ParseJSON("40 /* comment */", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 4, Unexpected data after root element.",
            error.message);
  root = ParseJSON("[1, /*a*/2, 3]", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 5, Syntax error.", error.message);

  // Test number formats
  root = ParseJSON("43");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeInteger, root->GetType());
  EXPECT_TRUE(root->AsInteger(&int_val));
  EXPECT_EQ(43, int_val);

  // According to RFC4627, oct, hex, and leading zeros are invalid JSON.
  root = ParseJSON("043", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 2, Syntax error.", error.message);
  root = ParseJSON("0x43", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 2, Unexpected data after root element.",
            error.message);
  root = ParseJSON("00", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 2, Syntax error.", error.message);

  // Test 0 (which needs to be special cased because of the leading zero
  // clause).
  root = ParseJSON("0");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeInteger, root->GetType());
  int_val = 1;
  EXPECT_TRUE(root->AsInteger(&int_val));
  EXPECT_EQ(0, int_val);

  // Numbers that overflow ints should succeed, being internally promoted to
  // storage as doubles
  root = ParseJSON("2147483648");
  ASSERT_TRUE(root.get());
  double double_val;
  EXPECT_EQ(JSONValue::kTypeDouble, root->GetType());
  double_val = 0.0;
  EXPECT_TRUE(root->AsDouble(&double_val));
  EXPECT_DOUBLE_EQ(2147483648.0, double_val);
  root = ParseJSON("-2147483649");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeDouble, root->GetType());
  double_val = 0.0;
  EXPECT_TRUE(root->AsDouble(&double_val));
  EXPECT_DOUBLE_EQ(-2147483649.0, double_val);

  // Parse a double
  root = ParseJSON("43.1");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeDouble, root->GetType());
  double_val = 0.0;
  EXPECT_TRUE(root->AsDouble(&double_val));
  EXPECT_DOUBLE_EQ(43.1, double_val);

  root = ParseJSON("4.3e-1");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeDouble, root->GetType());
  double_val = 0.0;
  EXPECT_TRUE(root->AsDouble(&double_val));
  EXPECT_DOUBLE_EQ(.43, double_val);

  root = ParseJSON("2.1e0");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeDouble, root->GetType());
  double_val = 0.0;
  EXPECT_TRUE(root->AsDouble(&double_val));
  EXPECT_DOUBLE_EQ(2.1, double_val);

  root = ParseJSON("2.1e+0001");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeInteger, root->GetType());
  double_val = 0.0;
  EXPECT_TRUE(root->AsDouble(&double_val));
  EXPECT_DOUBLE_EQ(21.0, double_val);

  root = ParseJSON("0.01");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeDouble, root->GetType());
  double_val = 0.0;
  EXPECT_TRUE(root->AsDouble(&double_val));
  EXPECT_DOUBLE_EQ(0.01, double_val);

  root = ParseJSON("1.00");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeInteger, root->GetType());
  double_val = 0.0;
  EXPECT_TRUE(root->AsDouble(&double_val));
  EXPECT_DOUBLE_EQ(1.0, double_val);

  // Fractional parts must have a digit before and after the decimal point.
  root = ParseJSON("1.", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 3, Syntax error.", error.message);
  root = ParseJSON(".1", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 1, Syntax error.", error.message);
  root = ParseJSON("1.e10", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 3, Syntax error.", error.message);

  // Exponent must have a digit following the 'e'.
  root = ParseJSON("1e", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 3, Syntax error.", error.message);
  root = ParseJSON("1E", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 3, Syntax error.", error.message);
  root = ParseJSON("1e1.", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 4, Unexpected data after root element.",
            error.message);
  root = ParseJSON("1e1.0", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 4, Unexpected data after root element.",
            error.message);

  // INF/-INF/NaN are not valid
  root = ParseJSON("NaN", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 1, Syntax error.", error.message);
  root = ParseJSON("nan", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 1, Syntax error.", error.message);
  root = ParseJSON("inf", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 1, Syntax error.", error.message);

  // Invalid number formats
  root = ParseJSON("4.3.1", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 4, Unexpected data after root element.",
            error.message);
  root = ParseJSON("4e3.1", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 4, Unexpected data after root element.",
            error.message);

  // Test string parser
  root = ParseJSON("\"hello world\"");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeString, root->GetType());
  EXPECT_TRUE(root->AsString(&str_val));
  EXPECT_EQ("hello world", str_val);

  // Empty string
  root = ParseJSON("\"\"");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeString, root->GetType());
  EXPECT_TRUE(root->AsString(&str_val));
  EXPECT_EQ("", str_val);

  // Test basic string escapes
  root = ParseJSON("\" \\\"\\\\\\/\\b\\f\\n\\r\\t\\v\"");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeString, root->GetType());
  EXPECT_TRUE(root->AsString(&str_val));
  EXPECT_EQ(" \"\\/\b\f\n\r\t\v", str_val);

  // Test hex and unicode escapes including the null character.
  root = ParseJSON("\"\\x41\\x00\\u1234\"", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 4, Invalid escape sequence.", error.message);

  // Test invalid strings
  root = ParseJSON("\"no closing quote", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 18, Syntax error.", error.message);
  root = ParseJSON("\"\\z invalid escape char\"", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 4, Invalid escape sequence.", error.message);
  root = ParseJSON("\"not enough escape chars\\u123\"", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 27, Invalid escape sequence.", error.message);
  root = ParseJSON("\"extra backslash at end of input\\\"", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 35, Syntax error.", error.message);
  root = ParseJSON("\"a\"extra data", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 4, Unexpected data after root element.",
            error.message);

  // Bare control characters (including newlines) are not permitted in string
  // literals.
  root = ParseJSON("\"\n\"", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 3, Syntax error.", error.message);
  root = ParseJSON("[\"\n\"]", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 4, Syntax error.", error.message);
  root = ParseJSON("{\"\n\": true}", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 4, Syntax error.", error.message);
  root = ParseJSON("{\"key\": \"\n\"}", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 11, Syntax error.", error.message);
  root = ParseJSON("\"\x1b\"", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 3, Syntax error.", error.message);
  root = ParseJSON("[\"\x07\"]", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 4, Syntax error.", error.message);
  root = ParseJSON("{\"\x09\": true}", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 4, Syntax error.", error.message);
  root = ParseJSON("{\"key\": \"\x01\"}", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 11, Syntax error.", error.message);

  // Basic array
  root = ParseJSON("[true, false, null]");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeArray, root->GetType());
  list = JSONArray::Cast(root.get());
  ASSERT_TRUE(list);
  EXPECT_EQ(3U, list->size());

  // Empty array
  root = ParseJSON("[]");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeArray, root->GetType());
  list = JSONArray::Cast(root.get());
  ASSERT_TRUE(list);
  EXPECT_EQ(0U, list->size());

  // Nested arrays
  root = ParseJSON("[[true], [], [false, [], [null]], null]");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeArray, root->GetType());
  list = JSONArray::Cast(root.get());
  ASSERT_TRUE(list);
  EXPECT_EQ(4U, list->size());

  // Invalid, missing close brace.
  root = ParseJSON("[[true], [], [false, [], [null]], null", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 39, Syntax error.", error.message);

  // Invalid, too many commas
  root = ParseJSON("[true,, null]", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 7, Unexpected token.", error.message);

  // Invalid, no commas
  root = ParseJSON("[true null]", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 7, Unexpected token.", error.message);

  // Invalid, trailing comma
  root = ParseJSON("[true,]", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 7, Unexpected token.", error.message);

  root = ParseJSON("[true]");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeArray, root->GetType());
  list = JSONArray::Cast(root.get());
  ASSERT_TRUE(list);
  EXPECT_EQ(1U, list->size());
  tmp_value = list->at(0);
  ASSERT_TRUE(tmp_value);
  EXPECT_EQ(JSONValue::kTypeBoolean, tmp_value->GetType());
  bool bool_value = false;
  EXPECT_TRUE(tmp_value->AsBoolean(&bool_value));
  EXPECT_TRUE(bool_value);

  // Don't allow empty elements.
  root = ParseJSON("[,]", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 2, Unexpected token.", error.message);
  root = ParseJSON("[true,,]", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 7, Unexpected token.", error.message);
  root = ParseJSON("[,true,]", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 2, Unexpected token.", error.message);
  root = ParseJSON("[true,,false]", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 7, Unexpected token.", error.message);

  // Test objects
  root = ParseJSON("{}");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeObject, root->GetType());

  root = ParseJSON("{\"number\":9.87654321, \"null\":null , \"S\" : \"str\" }");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeObject, root->GetType());
  JSONObject* object_val = JSONObject::Cast(root.get());
  ASSERT_TRUE(object_val);
  double_val = 0.0;
  EXPECT_TRUE(object_val->GetDouble("number", &double_val));
  EXPECT_DOUBLE_EQ(9.87654321, double_val);
  JSONValue* null_val = object_val->Get("null");
  ASSERT_TRUE(null_val);
  EXPECT_EQ(JSONValue::kTypeNull, null_val->GetType());
  EXPECT_TRUE(object_val->GetString("S", &str_val));
  EXPECT_EQ("str", str_val);

  // Test newline equivalence.
  root2 = ParseJSON(
      "{\n"
      "  \"number\":9.87654321,\n"
      "  \"null\":null,\n"
      "  \"S\":\"str\"\n"
      "}\n");
  ASSERT_TRUE(root2.get());
  EXPECT_EQ(root->ToJSONString(), root2->ToJSONString());

  root2 = ParseJSON(
      "{\r\n"
      "  \"number\":9.87654321,\r\n"
      "  \"null\":null,\r\n"
      "  \"S\":\"str\"\r\n"
      "}\r\n");
  ASSERT_TRUE(root2.get());
  EXPECT_EQ(root->ToJSONString(), root2->ToJSONString());

  // Test that allowed whitespace is limited to TAB, CR, LF and SP. There are
  // several other Unicode characters defined as whitespace, so a selection of
  // them are tested to ensure that they are not allowed.
  // U+0009 CHARACTER TABULATION is allowed
  root = ParseJSON("\t{\t\"key\"\t:\t[\t\"value1\"\t,\t\"value2\"\t]\t}\t");
  ASSERT_TRUE(root.get());
  // U+000A LINE FEED is allowed
  root = ParseJSON("\n{\n\"key\"\n:\n[\n\"value1\"\n,\n\"value2\"\n]\n}\n");
  ASSERT_TRUE(root.get());
  // U+000D CARRIAGE RETURN is allowed
  root = ParseJSON("\r{\r\"key\"\r:\r[\r\"value1\"\r,\r\"value2\"\r]\r}\r");
  ASSERT_TRUE(root.get());
  // U+0020 SPACE is allowed
  root = ParseJSON(" { \"key\" : [ \"value1\" , \"value2\" ] } ");
  ASSERT_TRUE(root.get());
  // U+000B LINE TABULATION is not allowed
  root = ParseJSON("[\x0b\"value\"]");
  ASSERT_FALSE(root.get());
  // U+00A0 NO-BREAK SPACE is not allowed
  UChar invalid_space_1[] = {0x5b, 0x00a0, 0x5d};  // [<U+00A0>]
  root = ParseJSON(String(base::span(invalid_space_1)));
  ASSERT_FALSE(root.get());
  // U+3000 IDEOGRAPHIC SPACE is not allowed
  UChar invalid_space_2[] = {0x5b, 0x3000, 0x5d};  // [<U+3000>]
  root = ParseJSON(String(base::span(invalid_space_2)));
  ASSERT_FALSE(root.get());

  // Test nesting
  root = ParseJSON("{\"inner\":{\"array\":[true]},\"false\":false,\"d\":{}}");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeObject, root->GetType());
  object_val = JSONObject::Cast(root.get());
  ASSERT_TRUE(object_val);
  JSONObject* inner_object = object_val->GetJSONObject("inner");
  ASSERT_TRUE(inner_object);
  JSONArray* inner_array = inner_object->GetArray("array");
  ASSERT_TRUE(inner_array);
  EXPECT_EQ(1U, inner_array->size());
  bool_value = true;
  EXPECT_TRUE(object_val->GetBoolean("false", &bool_value));
  EXPECT_FALSE(bool_value);
  inner_object = object_val->GetJSONObject("d");
  EXPECT_TRUE(inner_object);

  // Test keys with periods
  root = ParseJSON("{\"a.b\":3,\"c\":2,\"d.e.f\":{\"g.h.i.j\":1}}");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeObject, root->GetType());
  object_val = JSONObject::Cast(root.get());
  ASSERT_TRUE(object_val);
  int integer_value = 0;
  EXPECT_TRUE(object_val->GetInteger("a.b", &integer_value));
  EXPECT_EQ(3, integer_value);
  EXPECT_TRUE(object_val->GetInteger("c", &integer_value));
  EXPECT_EQ(2, integer_value);
  inner_object = object_val->GetJSONObject("d.e.f");
  ASSERT_TRUE(inner_object);
  EXPECT_EQ(1U, inner_object->size());
  EXPECT_TRUE(inner_object->GetInteger("g.h.i.j", &integer_value));
  EXPECT_EQ(1, integer_value);

  root = ParseJSON("{\"a\":{\"b\":2},\"a.b\":1}");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeObject, root->GetType());
  object_val = JSONObject::Cast(root.get());
  ASSERT_TRUE(object_val);
  inner_object = object_val->GetJSONObject("a");
  ASSERT_TRUE(inner_object);
  EXPECT_TRUE(inner_object->GetInteger("b", &integer_value));
  EXPECT_EQ(2, integer_value);
  EXPECT_TRUE(object_val->GetInteger("a.b", &integer_value));
  EXPECT_EQ(1, integer_value);

  // Invalid, no closing brace
  root = ParseJSON("{\"a\": true");
  EXPECT_FALSE(root.get());

  // Invalid, keys must be quoted
  root = ParseJSON("{foo:true}", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 2, Syntax error.", error.message);

  // Invalid, trailing comma
  root = ParseJSON("{\"a\":true,}", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 11, Unexpected token.", error.message);

  // Invalid, too many commas
  root = ParseJSON("{\"a\":true,,\"b\":false}", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 11, Unexpected token.", error.message);

  // Invalid, no separator
  root = ParseJSON("{\"a\" \"b\"}", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 6, Unexpected token.", error.message);

  // Invalid, lone comma.
  root = ParseJSON("{,}", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 2, Unexpected token.", error.message);
  root = ParseJSON("{\"a\":true,,}", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 11, Unexpected token.", error.message);
  root = ParseJSON("{,\"a\":true}", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 2, Unexpected token.", error.message);
  root = ParseJSON("{\"a\":true,,\"b\":false}", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 11, Unexpected token.", error.message);

  // Test stack overflow
  StringBuilder evil;
  evil.ReserveCapacity(2000000);
  for (int i = 0; i < 1000000; ++i)
    evil.Append('[');
  for (int i = 0; i < 1000000; ++i)
    evil.Append(']');
  root = ParseJSON(evil.ToString(), &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 1001, Too much nesting.", error.message);

  // A few thousand adjacent lists is fine.
  StringBuilder not_evil;
  not_evil.ReserveCapacity(15010);
  not_evil.Append('[');
  for (int i = 0; i < 5000; ++i)
    not_evil.Append("[],");
  not_evil.Append("[]]");
  root = ParseJSON(not_evil.ToString());
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeArray, root->GetType());
  list = JSONArray::Cast(root.get());
  ASSERT_TRUE(list);
  EXPECT_EQ(5001U, list->size());

  // Test utf8 encoded input
  root = ParseJSON("\"\\xe7\\xbd\\x91\\xe9\\xa1\\xb5\"", &error);
  ASSERT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 4, Invalid escape sequence.", error.message);

  // Test utf16 encoded strings.
  root = ParseJSON("\"\\u20ac3,14\"");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeString, root->GetType());
  EXPECT_TRUE(root->AsString(&str_val));
  UChar tmp2[] = {0x20ac, 0x33, 0x2c, 0x31, 0x34};
  EXPECT_EQ(String(base::span(tmp2)), str_val);

  root = ParseJSON("\"\\ud83d\\udca9\\ud83d\\udc6c\"");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeString, root->GetType());
  EXPECT_TRUE(root->AsString(&str_val));
  UChar tmp3[] = {0xd83d, 0xdca9, 0xd83d, 0xdc6c};
  EXPECT_EQ(String(base::span(tmp3)), str_val);

  // Invalid unicode in a string literal after applying escape sequences.
  root = ParseJSON("\n\n    \"\\ud800\"", &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ(
      "Line: 3, column: 5, Unsupported encoding. JSON and all string literals "
      "must contain valid Unicode characters.",
      error.message);

  // Invalid unicode in a JSON itself.
  UChar tmp4[] = {0x22, 0xd800, 0x22};  // "?"
  root = ParseJSON(String(base::span(tmp4)), &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ(
      "Line: 1, column: 1, Unsupported encoding. JSON and all string literals "
      "must contain valid Unicode characters.",
      error.message);

  // Invalid unicode in a JSON itself.
  UChar tmp5[] = {0x7b, 0x22, 0xd800, 0x22, 0x3a, 0x31, 0x7d};  // {"?":1}
  root = ParseJSON(String(base::span(tmp5)), &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ(
      "Line: 1, column: 2, Unsupported encoding. JSON and all string literals "
      "must contain valid Unicode characters.",
      error.message);

  // Test literal root objects.
  root = ParseJSON("null");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(JSONValue::kTypeNull, root->GetType());

  root = ParseJSON("true");
  ASSERT_TRUE(root.get());
  EXPECT_TRUE(root->AsBoolean(&bool_value));
  EXPECT_TRUE(bool_value);

  root = ParseJSON("10");
  ASSERT_TRUE(root.get());
  EXPECT_TRUE(root->AsInteger(&integer_value));
  EXPECT_EQ(10, integer_value);

  root = ParseJSON("\"root\"");
  ASSERT_TRUE(root.get());
  EXPECT_TRUE(root->AsString(&str_val));
  EXPECT_EQ("root", str_val);
}

TEST(JSONParserTest, InvalidSanity) {
  const char* const kInvalidJson[] = {
      "/* test *", "{\"foo\"", "{\"foo\":", "  [", "\"\\u123g\"", "{\n\"eh:\n}",
      "////",      "*/**/",    "/**/",      "/*/", "//**/",       "\"\\"};

  for (size_t i = 0; i < std::size(kInvalidJson); ++i) {
    std::unique_ptr<JSONValue> result = ParseJSON(kInvalidJson[i]);
    EXPECT_FALSE(result.get());
  }
}

// Test that the nesting depth can be limited to values less than 1000, but
// cannot be extended past that maximum.
TEST(JSONParserTest, LimitedDepth) {
  std::unique_ptr<JSONValue> root;
  JSONCommentState comment_state = JSONCommentState::kDisallowed;
  JSONParseError error;

  // Test cases. Each pair is a JSON string, and the minimum depth required
  // to successfully parse that string.
  Vector<std::pair<const char*, int>> test_cases = {
      {"[[[[[]]]]]", 5},
      {"[[[[[\"a\"]]]]]", 6},
      {"[[],[],[],[],[]]", 2},
      {"{\"a\":{\"a\":{\"a\":{\"a\":{\"a\": \"a\"}}}}}", 6},
      {"\"root\"", 1}};

  for (const auto& test_case : test_cases) {
    // Each test case should parse successfully at the default depth
    root = ParseJSON(test_case.first);
    EXPECT_TRUE(root.get());

    // ... and should parse successfully at the minimum depth
    root = ParseJSON(test_case.first, comment_state, test_case.second);
    EXPECT_TRUE(root.get());

    // ... but should fail to parse at a shallower depth.
    root = ParseJSON(test_case.first, comment_state, test_case.second - 1);
    EXPECT_FALSE(root.get());
  }

  // Test that everything fails to parse with depth 0
  root = ParseJSON("", comment_state, 0, &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 1, Syntax error.", error.message);
  root = ParseJSON("", comment_state, -1, &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 1, Syntax error.", error.message);
  root = ParseJSON("true", comment_state, 0, &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 1, Too much nesting.", error.message);

  // Test that the limit can be set to the constant maximum.
  StringBuilder evil;
  evil.ReserveCapacity(2002);
  for (int i = 0; i < 1000; ++i)
    evil.Append('[');
  for (int i = 0; i < 1000; ++i)
    evil.Append(']');
  root = ParseJSON(evil.ToString());
  EXPECT_TRUE(root.get());
  root = ParseJSON(evil.ToString(), comment_state, 1000);
  EXPECT_TRUE(root.get());

  // Test that the limit cannot be set higher than the constant maximum.
  evil.Clear();
  for (int i = 0; i < 1001; ++i)
    evil.Append('[');
  for (int i = 0; i < 1001; ++i)
    evil.Append(']');
  root = ParseJSON(evil.ToString(), &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 1001, Too much nesting.", error.message);
  root = ParseJSON(evil.ToString(), comment_state, 1001, &error);
  EXPECT_FALSE(root.get());
  EXPECT_EQ("Line: 1, column: 1001, Too much nesting.", error.message);
}

}  // namespace blink

"""

```