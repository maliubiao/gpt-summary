Response:
My thinking process to analyze the `protocol_parser_test.cc` file goes like this:

1. **Understand the Goal:** The filename and the `#include` directives clearly indicate this is a unit test file. The core purpose is to test the functionality of a JSON parser used in the Blink rendering engine's inspector.

2. **Identify Key Components:** I look for the most important elements within the code:
    * **`ParseJSON` function:** This is the function being tested. It takes a string as input and returns a `protocol::Value` pointer. The implementation shows it converts the JSON string to a CBOR (Concise Binary Object Representation) format before parsing. This is an important detail.
    * **`TEST` macros:** These define the individual test cases. Each `TEST` focuses on a specific aspect of the parser.
    * **Assertions (`ASSERT_TRUE`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `EXPECT_DOUBLE_EQ`):**  These are the mechanisms used to verify the parser's behavior. They check for expected outcomes.
    * **`protocol::Value`, `protocol::DictionaryValue`, `protocol::ListValue`:** These are data structures used to represent the parsed JSON. They indicate the parser's ability to handle different JSON types (null, boolean, integer, double, string, array, object).

3. **Analyze Test Cases:**  I go through each `TEST` block (`Reading` and `InvalidSanity`) and break down what they are testing:
    * **`Reading` Test:** This test covers various scenarios of valid JSON input:
        * **Basic types:** `null`, `true`, integers, doubles.
        * **Whitespace and comments:**  It checks if the parser correctly ignores whitespace and both single-line (`//`) and multi-line (`/* ... */`) comments.
        * **Number formats:**  It tests different integer and floating-point representations, including exponents. It also verifies handling of edge cases like leading zeros (invalid), `0`, and large numbers that might overflow integers.
        * **String parsing:** It checks basic string literals, escape sequences (`\`, `"`, `/`, `b`, `f`, `n`, `r`, `t`, `v`), and importantly, attempts at hex and Unicode escapes (and notes their invalidity in this context).
        * **Arrays:** It tests empty arrays, nested arrays, and handles cases with and without trailing commas, and multiple commas (invalid).
        * **Objects:**  It tests empty objects, objects with various data types as values, nested objects, keys with periods, and cases with duplicate keys (implicitly overwrites based on the test setup).
        * **Error Handling (Implicit):** Many of the `EXPECT_FALSE(root.get())` calls within the `Reading` test demonstrate testing of *invalid* JSON syntax and verifying the parser correctly identifies them.
        * **Stack Overflow:** Tests how the parser handles extremely deeply nested structures.
        * **UTF-8 and UTF-16:** Tests handling of different character encodings in strings.
        * **Literal Roots:** Tests parsing of single JSON values as the root.

    * **`InvalidSanity` Test:** This test focuses solely on providing a collection of *invalid* JSON strings and ensuring the parser correctly rejects them (`EXPECT_FALSE(result.get())`). This provides a quick sanity check for common parsing errors.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):** I consider how JSON is used in the context of web development:
    * **JavaScript:** JSON is a fundamental data exchange format for JavaScript applications. The inspector often communicates with the browser's JavaScript engine using JSON.
    * **HTML:** While HTML itself isn't directly JSON, the data *associated* with HTML elements (e.g., in data attributes) might be represented or transferred as JSON. The inspector can inspect these attributes.
    * **CSS:**  Similar to HTML, CSS doesn't use JSON directly, but style information or configuration data *related* to CSS could be exchanged as JSON. The inspector helps in debugging CSS.
    * **DevTools Protocol:**  The "inspector protocol" mentioned in the file name is key. The Chrome DevTools communicate with the browser's rendering engine using a protocol that heavily relies on JSON for sending commands and receiving responses. This test file directly relates to ensuring that the JSON used in this protocol is parsed correctly.

5. **Identify Logic and Assumptions:**
    * The core logic is within the `ParseJSON` function (though its implementation is partially hidden behind `crdtp::json::ConvertJSONToCBOR` and `protocol::Value::parseBinary`).
    * The tests assume that `crdtp::json::ConvertJSONToCBOR` correctly converts JSON to CBOR, and that `protocol::Value::parseBinary` correctly parses the CBOR. The current test focuses on the initial JSON parsing stage within `ParseJSON`.

6. **Consider Common Errors:** Based on the test cases, I identify potential errors developers might make:
    * **Syntax errors:** Missing quotes, commas, braces, brackets.
    * **Incorrect escaping:** Using invalid escape sequences.
    * **Trailing commas:**  A common mistake in JSON arrays and objects.
    * **Unquoted keys:** Forgetting to put quotes around object keys.
    * **Comments in unexpected places:** Although the parser supports comments, developers might assume they can place them anywhere.
    * **Invalid number formats:** Leading zeros, missing digits in exponents, etc.

7. **Structure the Output:** Finally, I organize my findings into the requested categories: Functionality, Relationship to Web Technologies, Logic and Assumptions, and Common Errors, providing specific examples from the test code. I aim for clarity and conciseness in my explanations.
这个 `blink/renderer/core/inspector/protocol_parser_test.cc` 文件是 Chromium Blink 引擎中用于测试 JSON 解析器的单元测试文件。这个解析器被用于 Inspector (开发者工具) 的协议处理中。

**主要功能:**

1. **测试 JSON 解析的正确性:**  该文件包含了大量的测试用例，用于验证 `ParseJSON` 函数（或与其功能类似的内部实现）能否正确地将 JSON 字符串解析成内部的数据结构 `protocol::Value`。

2. **覆盖各种 JSON 语法:** 测试用例覆盖了 JSON 的各种语法元素，包括：
   - **基本类型:** `null`, `true`, `false`, 数字 (整数和浮点数)，字符串。
   - **空白字符和注释:** 测试解析器是否能正确处理 JSON 中的空格、制表符、换行符以及单行 `//` 和多行 `/* ... */` 注释。
   - **数字格式:** 测试各种合法的数字表示，包括正负数、小数、科学计数法等，以及各种非法的数字格式。
   - **字符串:** 测试带转义字符的字符串 (如 `\"`, `\\`, `\n`, `\t` 等)，以及 UTF-8 和 UTF-16 编码的字符串。
   - **数组:** 测试空数组、嵌套数组以及包含不同类型元素的数组。同时也测试了各种非法的数组语法。
   - **对象:** 测试空对象、嵌套对象以及包含不同类型键值对的对象。同时也测试了各种非法的对象语法。
   - **字面量根对象:** 测试直接解析 `null`, `true`, 数字或字符串作为顶层 JSON 值。

**与 JavaScript, HTML, CSS 的功能关系及举例说明:**

虽然这个测试文件本身不直接操作 JavaScript, HTML 或 CSS，但它测试的 JSON 解析器是 Inspector (开发者工具) 与浏览器引擎之间通信的关键组成部分。开发者工具协议 (Chrome DevTools Protocol, CDP) 使用 JSON 作为数据交换格式。

* **JavaScript:**
    - **举例:** 当你在开发者工具的 "Console" 面板中执行 JavaScript 代码时，浏览器引擎执行结果可能会通过 Inspector 协议以 JSON 格式返回。例如，执行 `console.log({a: 1, b: "hello"})`，返回的 JSON 可能是 `{"result":{"type":"object","subtype":"null","className":"Object","description":"Object","objectId":"...","preview":{"type":"object","subtype":"null","description":"Object","overflow":false,"properties":[{"name":"a","type":"number","value":"1"},{"name":"b","type":"string","value":"hello"}]}}}`。这个测试文件确保了能正确解析这种复杂的 JSON 结构。

* **HTML:**
    - **举例:** 在 "Elements" 面板中查看 HTML 元素属性时，这些属性信息可能通过 Inspector 协议以 JSON 格式传递。例如，获取一个 `<div>` 元素的属性，返回的 JSON 可能是 `{"attributes":["id","myDiv","class","container"]}`。这个测试文件确保了属性列表能够被正确解析。

* **CSS:**
    - **举例:** 在 "Styles" 面板中查看元素的 CSS 样式时，样式信息（包括属性名和属性值）也可能通过 Inspector 协议以 JSON 格式传输。例如，获取某个元素的样式，返回的 JSON 可能包含类似 `{"name":"color","value":"red","priority":"","implicit":false,"text":"color: red;","parsedOk":true,"disabled":false,"range":{"startLine":2,"startColumn":4,"endLine":2,"endColumn":13}}` 的结构。该测试文件确保了 CSS 样式信息的 JSON 表示能够被正确解析。

**逻辑推理及假设输入与输出:**

该测试文件通过大量的断言来验证解析器的行为。以下是一些假设输入和期望输出的例子：

* **假设输入:** `"true"`
   - **期望输出:** `protocol::Value` 类型为布尔型，值为 `true`。

* **假设输入:** `"{\"name\":\"test\", \"value\":123}"`
   - **期望输出:** `protocol::Value` 类型为对象，包含两个键值对：`"name"` 对应字符串 `"test"`，`"value"` 对应整数 `123`。

* **假设输入:** `"[1, \"hello\", true]"`
   - **期望输出:** `protocol::Value` 类型为数组，包含三个元素：整数 `1`，字符串 `"hello"`，布尔值 `true`。

* **假设输入 (非法 JSON):** `"{\"name\":\"test\", \"value\":}"`
   - **期望输出:** 解析失败，`ParseJSON` 函数返回空指针或表示错误的状态。

**涉及用户或编程常见的使用错误及举例说明:**

虽然这个文件测试的是底层的 JSON 解析器，但它间接反映了用户或开发者在使用 JSON 时可能遇到的错误。

* **忘记加引号:**
   - **错误示例:**  `{name: "test"}` (在 JSON 中，键必须是带引号的字符串)
   - **测试用例体现:**  `root = ParseJSON("{foo:true}"); EXPECT_FALSE(root.get());`  测试用例验证了解析器会拒绝未加引号的键。

* **结尾多余的逗号:**
   - **错误示例:** `["a", "b", ]` 或 `{"a": 1, "b": 2, }`
   - **测试用例体现:** `root = ParseJSON("[true,]"); EXPECT_FALSE(root.get());` 和 `root = ParseJSON("{\"a\":true,}"); EXPECT_FALSE(root.get());` 验证了解析器会拒绝结尾多余的逗号。

* **缺少逗号或冒号:**
   - **错误示例:** `["a" "b"]` 或 `{"a" 1}`
   - **测试用例体现:** `root = ParseJSON("[true null]"); EXPECT_FALSE(root.get());` 和 `root = ParseJSON("{\"a\" \"b\"}"); EXPECT_FALSE(root.get());` 验证了解析器会拒绝缺少分隔符的情况。

* **使用了非法的转义字符:**
   - **错误示例:** `"invalid escape \\z"`
   - **测试用例体现:** `root = ParseJSON("\"\\z invalid escape char\""); EXPECT_FALSE(root.get());` 验证了解析器会拒绝非法的转义字符。

* **数字格式错误:**
   - **错误示例:** `012` (JSON 不允许数字以 `0` 开头，除非是单个 `0`)， `1.` 或 `.1` (小数点前后必须有数字)
   - **测试用例体现:** `root = ParseJSON("043"); EXPECT_FALSE(root.get());`, `root = ParseJSON("1."); EXPECT_FALSE(root.get());`, `root = ParseJSON(".1"); EXPECT_FALSE(root.get());`  验证了解析器对数字格式的严格要求。

总而言之，`protocol_parser_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎的 Inspector 组件能够可靠地解析 JSON 数据，从而保证开发者工具的正常功能。它覆盖了各种 JSON 语法和潜在的错误情况，提高了代码的健壮性。

Prompt: 
```
这是目录为blink/renderer/core/inspector/protocol_parser_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/inspector/protocol/protocol.h"

#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/inspector_protocol/crdtp/json.h"

namespace blink {

using protocol::DictionaryValue;
using protocol::ListValue;
using protocol::Value;

static std::unique_ptr<protocol::Value> ParseJSON(const String& string) {
  std::vector<uint8_t> cbor;
  if (string.Is8Bit()) {
    crdtp::json::ConvertJSONToCBOR(
        crdtp::span<uint8_t>(string.Characters8(), string.length()), &cbor);
  } else {
    crdtp::json::ConvertJSONToCBOR(
        crdtp::span<uint16_t>(
            reinterpret_cast<const uint16_t*>(string.Characters16()),
            string.length()),
        &cbor);
  }
  return protocol::Value::parseBinary(cbor.data(), cbor.size());
}

TEST(ProtocolParserTest, Reading) {
  Value* tmp_value;
  std::unique_ptr<Value> root;
  std::unique_ptr<Value> root2;
  String str_val;
  int int_val = 0;

  // some whitespace checking
  root = ParseJSON("    null    ");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeNull, root->type());

  // Invalid JSON string
  root = ParseJSON("nu");
  EXPECT_FALSE(root.get());

  // Simple bool
  root = ParseJSON("true  ");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeBoolean, root->type());

  // Embedded comment
  root = ParseJSON("40 /*/");
  EXPECT_FALSE(root.get());
  root = ParseJSON("/* comment */null");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeNull, root->type());
  root = ParseJSON("40 /* comment */");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeInteger, root->type());
  EXPECT_TRUE(root->asInteger(&int_val));
  EXPECT_EQ(40, int_val);
  root = ParseJSON("/**/ 40 /* multi-line\n comment */ // more comment");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeInteger, root->type());
  EXPECT_TRUE(root->asInteger(&int_val));
  EXPECT_EQ(40, int_val);
  root = ParseJSON("true // comment");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeBoolean, root->type());
  root = ParseJSON("/* comment */\"sample string\"");
  ASSERT_TRUE(root.get());
  EXPECT_TRUE(root->asString(&str_val));
  EXPECT_EQ("sample string", str_val);
  root = ParseJSON("[1, /* comment, 2 ] */ \n 3]");
  ASSERT_TRUE(root.get());
  ListValue* list = ListValue::cast(root.get());
  ASSERT_TRUE(list);
  EXPECT_EQ(2u, list->size());
  tmp_value = list->at(0);
  ASSERT_TRUE(tmp_value);
  EXPECT_TRUE(tmp_value->asInteger(&int_val));
  EXPECT_EQ(1, int_val);
  tmp_value = list->at(1);
  ASSERT_TRUE(tmp_value);
  EXPECT_TRUE(tmp_value->asInteger(&int_val));
  EXPECT_EQ(3, int_val);
  root = ParseJSON("[1, /*a*/2, 3]");
  ASSERT_TRUE(root.get());
  list = ListValue::cast(root.get());
  ASSERT_TRUE(list);
  EXPECT_EQ(3u, list->size());
  root = ParseJSON("/* comment **/42");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeInteger, root->type());
  EXPECT_TRUE(root->asInteger(&int_val));
  EXPECT_EQ(42, int_val);
  root = ParseJSON(
      "/* comment **/\n"
      "// */ 43\n"
      "44");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeInteger, root->type());
  EXPECT_TRUE(root->asInteger(&int_val));
  EXPECT_EQ(44, int_val);

  // Test number formats
  root = ParseJSON("43");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeInteger, root->type());
  EXPECT_TRUE(root->asInteger(&int_val));
  EXPECT_EQ(43, int_val);

  // According to RFC4627, oct, hex, and leading zeros are invalid JSON.
  root = ParseJSON("043");
  EXPECT_FALSE(root.get());
  root = ParseJSON("0x43");
  EXPECT_FALSE(root.get());
  root = ParseJSON("00");
  EXPECT_FALSE(root.get());

  // Test 0 (which needs to be special cased because of the leading zero
  // clause).
  root = ParseJSON("0");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeInteger, root->type());
  int_val = 1;
  EXPECT_TRUE(root->asInteger(&int_val));
  EXPECT_EQ(0, int_val);

  // Numbers that overflow ints should succeed, being internally promoted to
  // storage as doubles
  root = ParseJSON("2147483648");
  ASSERT_TRUE(root.get());
  double double_val;
  EXPECT_EQ(Value::TypeDouble, root->type());
  double_val = 0.0;
  EXPECT_TRUE(root->asDouble(&double_val));
  EXPECT_DOUBLE_EQ(2147483648.0, double_val);
  root = ParseJSON("-2147483649");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeDouble, root->type());
  double_val = 0.0;
  EXPECT_TRUE(root->asDouble(&double_val));
  EXPECT_DOUBLE_EQ(-2147483649.0, double_val);

  // Parse a double
  root = ParseJSON("43.1");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeDouble, root->type());
  double_val = 0.0;
  EXPECT_TRUE(root->asDouble(&double_val));
  EXPECT_DOUBLE_EQ(43.1, double_val);

  root = ParseJSON("4.3e-1");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeDouble, root->type());
  double_val = 0.0;
  EXPECT_TRUE(root->asDouble(&double_val));
  EXPECT_DOUBLE_EQ(.43, double_val);

  root = ParseJSON("2.1e0");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeDouble, root->type());
  double_val = 0.0;
  EXPECT_TRUE(root->asDouble(&double_val));
  EXPECT_DOUBLE_EQ(2.1, double_val);

  root = ParseJSON("2.1e+0001");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeInteger, root->type());
  double_val = 0.0;
  EXPECT_TRUE(root->asDouble(&double_val));
  EXPECT_DOUBLE_EQ(21.0, double_val);

  root = ParseJSON("0.01");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeDouble, root->type());
  double_val = 0.0;
  EXPECT_TRUE(root->asDouble(&double_val));
  EXPECT_DOUBLE_EQ(0.01, double_val);

  root = ParseJSON("1.00");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeInteger, root->type());
  double_val = 0.0;
  EXPECT_TRUE(root->asDouble(&double_val));
  EXPECT_DOUBLE_EQ(1.0, double_val);

  // Fractional parts must have a digit before and after the decimal point.
  root = ParseJSON("1.");
  EXPECT_FALSE(root.get());
  root = ParseJSON(".1");
  EXPECT_FALSE(root.get());
  root = ParseJSON("1.e10");
  EXPECT_FALSE(root.get());

  // Exponent must have a digit following the 'e'.
  root = ParseJSON("1e");
  EXPECT_FALSE(root.get());
  root = ParseJSON("1E");
  EXPECT_FALSE(root.get());
  root = ParseJSON("1e1.");
  EXPECT_FALSE(root.get());
  root = ParseJSON("1e1.0");
  EXPECT_FALSE(root.get());

  // INF/-INF/NaN are not valid
  root = ParseJSON("NaN");
  EXPECT_FALSE(root.get());
  root = ParseJSON("nan");
  EXPECT_FALSE(root.get());
  root = ParseJSON("inf");
  EXPECT_FALSE(root.get());

  // Invalid number formats
  root = ParseJSON("4.3.1");
  EXPECT_FALSE(root.get());
  root = ParseJSON("4e3.1");
  EXPECT_FALSE(root.get());

  // Test string parser
  root = ParseJSON("\"hello world\"");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeString, root->type());
  EXPECT_TRUE(root->asString(&str_val));
  EXPECT_EQ("hello world", str_val);

  // Empty string
  root = ParseJSON("\"\"");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeString, root->type());
  EXPECT_TRUE(root->asString(&str_val));
  EXPECT_EQ("", str_val);

  // Test basic string escapes
  root = ParseJSON("\" \\\"\\\\\\/\\b\\f\\n\\r\\t\\v\"");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeString, root->type());
  EXPECT_TRUE(root->asString(&str_val));
  EXPECT_EQ(" \"\\/\b\f\n\r\t\v", str_val);

  // Test hex and unicode escapes including the null character.
  root = ParseJSON("\"\\x41\\x00\\u1234\"");
  EXPECT_FALSE(root.get());

  // Test invalid strings
  root = ParseJSON("\"no closing quote");
  EXPECT_FALSE(root.get());
  root = ParseJSON("\"\\z invalid escape char\"");
  EXPECT_FALSE(root.get());
  root = ParseJSON("\"not enough escape chars\\u123\"");
  EXPECT_FALSE(root.get());
  root = ParseJSON("\"extra backslash at end of input\\\"");
  EXPECT_FALSE(root.get());

  // Basic array
  root = ParseJSON("[true, false, null]");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeArray, root->type());
  list = ListValue::cast(root.get());
  ASSERT_TRUE(list);
  EXPECT_EQ(3U, list->size());

  // Empty array
  root = ParseJSON("[]");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeArray, root->type());
  list = ListValue::cast(root.get());
  ASSERT_TRUE(list);
  EXPECT_EQ(0U, list->size());

  // Nested arrays
  root = ParseJSON("[[true], [], [false, [], [null]], null]");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeArray, root->type());
  list = ListValue::cast(root.get());
  ASSERT_TRUE(list);
  EXPECT_EQ(4U, list->size());

  // Invalid, missing close brace.
  root = ParseJSON("[[true], [], [false, [], [null]], null");
  EXPECT_FALSE(root.get());

  // Invalid, too many commas
  root = ParseJSON("[true,, null]");
  EXPECT_FALSE(root.get());

  // Invalid, no commas
  root = ParseJSON("[true null]");
  EXPECT_FALSE(root.get());

  // Invalid, trailing comma
  root = ParseJSON("[true,]");
  EXPECT_FALSE(root.get());

  root = ParseJSON("[true]");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeArray, root->type());
  list = ListValue::cast(root.get());
  ASSERT_TRUE(list);
  EXPECT_EQ(1U, list->size());
  tmp_value = list->at(0);
  ASSERT_TRUE(tmp_value);
  EXPECT_EQ(Value::TypeBoolean, tmp_value->type());
  bool bool_value = false;
  EXPECT_TRUE(tmp_value->asBoolean(&bool_value));
  EXPECT_TRUE(bool_value);

  // Don't allow empty elements.
  root = ParseJSON("[,]");
  EXPECT_FALSE(root.get());
  root = ParseJSON("[true,,]");
  EXPECT_FALSE(root.get());
  root = ParseJSON("[,true,]");
  EXPECT_FALSE(root.get());
  root = ParseJSON("[true,,false]");
  EXPECT_FALSE(root.get());

  // Test objects
  root = ParseJSON("{}");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeObject, root->type());

  // The three test cases in the loop differ only by their newlines; therefore
  // the same assertions are valid.
  for (const char* test :
       {"{\"number\":9.87654321, \"null\":null , \"S\" : \"str\" }",
        "{\n"
        "  \"number\":9.87654321,\n"
        "  \"null\":null,\n"
        "  \"S\":\"str\"\n"
        "}\n",
        "{\r\n"
        "  \"number\":9.87654321,\r\n"
        "  \"null\":null,\r\n"
        "  \"S\":\"str\"\r\n"
        "}\r\n"}) {
    root = ParseJSON(String(test));
    ASSERT_TRUE(root.get());
    EXPECT_EQ(Value::TypeObject, root->type());
    DictionaryValue* object_val = DictionaryValue::cast(root.get());
    ASSERT_TRUE(object_val);
    double_val = 0.0;
    EXPECT_TRUE(object_val->getDouble("number", &double_val));
    EXPECT_DOUBLE_EQ(9.87654321, double_val);
    Value* null_val = object_val->get("null");
    ASSERT_TRUE(null_val);
    EXPECT_EQ(Value::TypeNull, null_val->type());
    EXPECT_TRUE(object_val->getString("S", &str_val));
    EXPECT_EQ("str", str_val);
  }

  // Test nesting
  root = ParseJSON("{\"inner\":{\"array\":[true]},\"false\":false,\"d\":{}}");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeObject, root->type());
  DictionaryValue* object_val = DictionaryValue::cast(root.get());
  ASSERT_TRUE(object_val);
  DictionaryValue* inner_object = object_val->getObject("inner");
  ASSERT_TRUE(inner_object);
  ListValue* inner_array = inner_object->getArray("array");
  ASSERT_TRUE(inner_array);
  EXPECT_EQ(1U, inner_array->size());
  bool_value = true;
  EXPECT_TRUE(object_val->getBoolean("false", &bool_value));
  EXPECT_FALSE(bool_value);
  inner_object = object_val->getObject("d");
  EXPECT_TRUE(inner_object);

  // Test keys with periods
  root = ParseJSON("{\"a.b\":3,\"c\":2,\"d.e.f\":{\"g.h.i.j\":1}}");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeObject, root->type());
  object_val = DictionaryValue::cast(root.get());
  ASSERT_TRUE(object_val);
  int integer_value = 0;
  EXPECT_TRUE(object_val->getInteger("a.b", &integer_value));
  EXPECT_EQ(3, integer_value);
  EXPECT_TRUE(object_val->getInteger("c", &integer_value));
  EXPECT_EQ(2, integer_value);
  inner_object = object_val->getObject("d.e.f");
  ASSERT_TRUE(inner_object);
  EXPECT_EQ(1U, inner_object->size());
  EXPECT_TRUE(inner_object->getInteger("g.h.i.j", &integer_value));
  EXPECT_EQ(1, integer_value);

  root = ParseJSON("{\"a\":{\"b\":2},\"a.b\":1}");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeObject, root->type());
  object_val = DictionaryValue::cast(root.get());
  ASSERT_TRUE(object_val);
  inner_object = object_val->getObject("a");
  ASSERT_TRUE(inner_object);
  EXPECT_TRUE(inner_object->getInteger("b", &integer_value));
  EXPECT_EQ(2, integer_value);
  EXPECT_TRUE(object_val->getInteger("a.b", &integer_value));
  EXPECT_EQ(1, integer_value);

  // Invalid, no closing brace
  root = ParseJSON("{\"a\": true");
  EXPECT_FALSE(root.get());

  // Invalid, keys must be quoted
  root = ParseJSON("{foo:true}");
  EXPECT_FALSE(root.get());

  // Invalid, trailing comma
  root = ParseJSON("{\"a\":true,}");
  EXPECT_FALSE(root.get());

  // Invalid, too many commas
  root = ParseJSON("{\"a\":true,,\"b\":false}");
  EXPECT_FALSE(root.get());

  // Invalid, no separator
  root = ParseJSON("{\"a\" \"b\"}");
  EXPECT_FALSE(root.get());

  // Invalid, lone comma.
  root = ParseJSON("{,}");
  EXPECT_FALSE(root.get());
  root = ParseJSON("{\"a\":true,,}");
  EXPECT_FALSE(root.get());
  root = ParseJSON("{,\"a\":true}");
  EXPECT_FALSE(root.get());
  root = ParseJSON("{\"a\":true,,\"b\":false}");
  EXPECT_FALSE(root.get());

  // Test stack overflow
  StringBuilder evil;
  evil.ReserveCapacity(2000000);
  for (int i = 0; i < 1000000; ++i)
    evil.Append('[');
  for (int i = 0; i < 1000000; ++i)
    evil.Append(']');
  root = ParseJSON(evil.ToString());
  EXPECT_FALSE(root.get());

  // A few thousand adjacent lists is fine.
  StringBuilder not_evil;
  not_evil.ReserveCapacity(15010);
  not_evil.Append('[');
  for (int i = 0; i < 5000; ++i)
    not_evil.Append("[],");
  not_evil.Append("[]]");
  root = ParseJSON(not_evil.ToString());
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeArray, root->type());
  list = ListValue::cast(root.get());
  ASSERT_TRUE(list);
  EXPECT_EQ(5001U, list->size());

  // Test utf8 encoded input
  root = ParseJSON("\"\\xe7\\xbd\\x91\\xe9\\xa1\\xb5\"");
  ASSERT_FALSE(root.get());

  // Test utf16 encoded strings.
  root = ParseJSON("\"\\u20ac3,14\"");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeString, root->type());
  EXPECT_TRUE(root->asString(&str_val));
  UChar tmp2[] = {0x20ac, 0x33, 0x2c, 0x31, 0x34};
  EXPECT_EQ(String(base::span(tmp2)), str_val);

  root = ParseJSON("\"\\ud83d\\udca9\\ud83d\\udc6c\"");
  ASSERT_TRUE(root.get());
  EXPECT_EQ(Value::TypeString, root->type());
  EXPECT_TRUE(root->asString(&str_val));
  UChar tmp3[] = {0xd83d, 0xdca9, 0xd83d, 0xdc6c};
  EXPECT_EQ(String(base::span(tmp3)), str_val);

  // Test literal root objects.
  root = ParseJSON("null");
  EXPECT_EQ(Value::TypeNull, root->type());

  root = ParseJSON("true");
  ASSERT_TRUE(root.get());
  EXPECT_TRUE(root->asBoolean(&bool_value));
  EXPECT_TRUE(bool_value);

  root = ParseJSON("10");
  ASSERT_TRUE(root.get());
  EXPECT_TRUE(root->asInteger(&integer_value));
  EXPECT_EQ(10, integer_value);

  root = ParseJSON("\"root\"");
  ASSERT_TRUE(root.get());
  EXPECT_TRUE(root->asString(&str_val));
  EXPECT_EQ("root", str_val);
}

TEST(ProtocolParserTest, InvalidSanity) {
  const auto kInvalidJson = std::to_array<const char*>(
      {"/* test *", "{\"foo\"", "{\"foo\":", "  [", "\"\\u123g\"",
       "{\n\"eh:\n}", "////", "*/**/", "/**/", "/*/", "//**/"});

  for (const auto* invalid_json : kInvalidJson) {
    std::unique_ptr<Value> result = ParseJSON(invalid_json);
    EXPECT_FALSE(result.get());
  }
}

}  // namespace blink

"""

```