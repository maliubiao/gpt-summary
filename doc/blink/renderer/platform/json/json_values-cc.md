Response:
Let's break down the thought process for analyzing the `json_values.cc` file and generating the detailed response.

1. **Understand the Goal:** The primary goal is to understand the functionality of this C++ file within the Chromium Blink rendering engine, specifically as it relates to JSON handling. I need to identify its purpose, its connections to web technologies (JavaScript, HTML, CSS), potential use cases, and common pitfalls.

2. **Initial Scan for Keywords and Structure:** I'd first quickly scan the code for obvious keywords like "JSON," "String," "Boolean," "Object," "Array," "escape," "quote," "write," "parse," etc. The `#include` directives also give clues (e.g., `wtf/text/string_builder.h`). The copyright notice indicates it's a Google contribution. The namespace `blink` confirms its location within the Blink engine.

3. **Identify Core Classes:**  The code defines several classes: `JSONValue`, `JSONBasicValue`, `JSONString`, `JSONObject`, and `JSONArray`. This immediately suggests a hierarchical structure for representing JSON data.

4. **Analyze `JSONValue` (Base Class):**
    * It has a `kTypeNull` default. This is significant as `null` is a fundamental JSON type.
    * Virtual methods like `AsBoolean`, `AsDouble`, `AsInteger`, `AsString`, `WriteJSON`, `PrettyWriteJSON`, and `Clone` strongly suggest this is an abstract base class providing a common interface for different JSON types.
    * The `ToJSONString` and `ToPrettyJSONString` methods indicate the class handles serialization of JSON to strings, both in compact and pretty-printed formats.

5. **Analyze Derived Classes:**
    * **`JSONBasicValue`:** Holds boolean, integer, and double values. The `As...` methods are implemented to return the contained value if the type matches. The `WriteJSON` method handles the specific formatting of these basic types.
    * **`JSONString`:** Holds a string value. The `AsString` and `WriteJSON` methods handle string retrieval and JSON string formatting (including escaping). The `DoubleQuoteStringForJSON` and `EscapeStringForJSON` functions are clearly involved in this process.
    * **`JSONObject`:** Represents a JSON object (key-value pairs). It uses a `Dictionary` (likely a Blink/WTF implementation of a hash map) to store the data and a `Vector` (`order_`) to maintain the order of insertion. It has methods for setting and getting different types of values, as well as nested objects and arrays. The `WriteJSON` and `PrettyWriteJSONInternal` methods handle the formatting of JSON objects, including indentation for pretty printing.
    * **`JSONArray`:** Represents a JSON array (ordered list of values). It uses a `Vector` to store the values. It has methods for pushing different types of values. The `WriteJSON` and `PrettyWriteJSONInternal` methods handle the formatting of JSON arrays.

6. **Identify Key Functions and Logic:**
    * **Escaping:** The `EscapeChar`, `AppendUnsignedAsHex`, `EscapeStringForJSON`, and `DoubleQuoteStringForJSON` functions are crucial for correctly formatting JSON strings, handling special characters and Unicode.
    * **Writing JSON:** The `WriteJSON` and `PrettyWriteJSONInternal` methods in each class implement the logic for serializing the JSON data into strings. The pretty printing logic involves indentation.
    * **Cloning:** The `Clone` methods are essential for creating deep copies of JSON values.
    * **Type Checking:**  The `As...` methods perform type checks before returning values.

7. **Connect to Web Technologies:**
    * **JavaScript:** The most obvious connection is the direct correspondence between these classes and JavaScript's built-in JSON object structure. This code is used internally by Blink when processing JSON data received from or sent to JavaScript. Examples would include `JSON.parse()` and `JSON.stringify()`.
    * **HTML:**  While not directly manipulating HTML structure, JSON is frequently used in web development to transmit data, which might then be used to dynamically update HTML content. For instance, a website might fetch data in JSON format and then use JavaScript to insert that data into the DOM.
    * **CSS:** The connection to CSS is less direct, but CSS custom properties can sometimes be used to store or retrieve JSON-like structures, although direct parsing would still likely involve JavaScript and this underlying JSON parsing logic.

8. **Infer Use Cases:**  Based on the functionality, the primary use cases are:
    * **Parsing JSON:**  (While this file doesn't *parse*, it represents the parsed *result*). Another part of Blink likely uses these classes as the output of parsing.
    * **Serializing JSON:**  Converting internal data structures into JSON strings for transmission or storage.
    * **Manipulating JSON data:**  Creating, modifying, and accessing JSON data within the rendering engine.

9. **Consider Potential Errors:**
    * **Type Mismatches:** Attempting to retrieve a value as the wrong type (e.g., calling `AsBoolean` on a `JSONString`).
    * **Accessing Non-existent Keys/Indices:** Trying to access a key in a `JSONObject` or an index in a `JSONArray` that doesn't exist.
    * **Invalid JSON Stringification:**  While the code handles most cases, there might be edge cases or limitations. (Though this file focuses on *creating* valid JSON).

10. **Construct Hypothetical Inputs and Outputs:**  Create simple examples to illustrate how the classes and methods work. This helps solidify understanding and demonstrate the behavior.

11. **Structure the Response:** Organize the information logically into the requested categories (functionality, relation to web technologies, logical reasoning, common errors). Use clear and concise language. Provide specific code examples where possible.

By following these steps, I can systematically analyze the provided code and generate a comprehensive and informative response like the example you provided. The process involves understanding the code's structure, its purpose within the larger system, and its connections to the broader web development ecosystem.
这个 `blink/renderer/platform/json/json_values.cc` 文件是 Chromium Blink 引擎中负责 **表示和操作 JSON 值的核心组件**。它定义了用于在 C++ 代码中表示 JSON 数据结构的类，并提供了将这些结构序列化为 JSON 字符串的方法。

**主要功能：**

1. **定义 JSON 数据类型的 C++ 类：**
   - `JSONValue`：所有 JSON 值的基类，定义了通用的接口。
   - `JSONBasicValue`：表示 JSON 的基本类型，如布尔值 (`true`, `false`)、数字（整数和浮点数）。
   - `JSONString`：表示 JSON 字符串。
   - `JSONObject`：表示 JSON 对象（键值对的集合）。
   - `JSONArray`：表示 JSON 数组（有序的值列表）。

2. **提供创建和操作 JSON 值的接口：**
   - 提供了创建不同类型 JSON 值对象的方法，例如 `JSONValue::CreateBoolean()`, `JSONValue::CreateString()`, `JSONObject::create()`, `JSONArray::create()` 等。（虽然在这个文件中没有直接看到 `Create` 方法，但这些类本身就是用于创建这些值的）
   - 提供了在 `JSONObject` 中设置和获取键值对的方法 (`SetBoolean`, `GetString`, `GetJSONObject` 等)。
   - 提供了在 `JSONArray` 中添加元素的方法 (`PushBoolean`, `PushString`, `PushValue` 等)。

3. **实现 JSON 值的序列化 (转换为 JSON 字符串)：**
   - `WriteJSON(StringBuilder* output)`：将 JSON 值序列化为紧凑的 JSON 字符串。
   - `PrettyWriteJSON(StringBuilder* output)`：将 JSON 值序列化为格式化（带缩进）的 JSON 字符串，提高可读性。
   - 内部使用 `EscapeStringForJSON` 和 `DoubleQuoteStringForJSON` 等辅助函数来正确地转义和引用 JSON 字符串中的特殊字符。

4. **提供 JSON 值类型判断和转换的方法：**
   - `AsBoolean(bool*)`, `AsDouble(double*)`, `AsInteger(int*)`, `AsString(String*)`：尝试将 JSON 值转换为特定的 C++ 类型。

5. **实现 JSON 值的克隆：**
   - `Clone()`：创建 JSON 值的深拷贝。

**与 JavaScript, HTML, CSS 的关系：**

这个文件在 Blink 引擎中扮演着桥梁的角色，连接着 C++ 代码和前端技术（JavaScript, HTML, CSS），因为它负责处理在两者之间传递的 JSON 数据。

* **与 JavaScript 的关系最为密切：**
    - **数据交换：** 当 JavaScript 代码（例如通过 `XMLHttpRequest` 或 `fetch`）从服务器接收到 JSON 数据时，Blink 引擎会解析这些数据并使用这里的 `JSONValue` 类及其子类来表示解析后的 JSON 结构。
        - **假设输入（服务器响应）：**  `{"name": "example", "value": 123, "active": true, "items": [1, 2, 3]}`
        - **内部表示（`json_values.cc` 的输出）：** 将会创建一个 `JSONObject` 实例，其中包含：
            - 键 "name" 对应一个 `JSONString` 实例，值为 "example"。
            - 键 "value" 对应一个 `JSONBasicValue` 实例，类型为整数，值为 123。
            - 键 "active" 对应一个 `JSONBasicValue` 实例，类型为布尔值，值为 true。
            - 键 "items" 对应一个 `JSONArray` 实例，包含三个 `JSONBasicValue` 实例，值分别为 1, 2, 3。
    - **JavaScript API 的实现：** JavaScript 中的 `JSON.parse()` 方法的底层实现会使用到 Blink 的 JSON 解析器，解析器会生成这里的 `JSONValue` 对象。 `JSON.stringify()` 的底层实现则会调用这里的 `WriteJSON` 或 `PrettyWriteJSON` 方法将 JavaScript 对象转换为 JSON 字符串。
        - **假设输入（JavaScript 对象）：**  `{a: 1, b: "test"}`
        - **`JSON.stringify()` 调用后的输出（对应 `json_values.cc` 的 `WriteJSON` 输出）：**  `{"a":1,"b":"test"}`

* **与 HTML 的关系：**
    - **数据驱动的 HTML 生成：**  JavaScript 代码通常会从服务器获取 JSON 数据，然后动态地修改 HTML 文档对象模型 (DOM)。`json_values.cc` 提供的 JSON 数据表示使得 JavaScript 能够方便地访问和处理这些数据，从而更新 HTML 内容。
        - **场景：** 一个网页从服务器获取用户列表 JSON 数据，然后将其渲染到 HTML 表格中。
        - **`json_values.cc` 的作用：**  用于表示用户列表的 JSON 结构（`JSONArray` 包含多个 `JSONObject`，每个 `JSONObject` 代表一个用户），JavaScript 可以遍历这些 `JSONValue` 对象，提取用户名、邮箱等信息，并将其插入到 HTML 表格的 `<tr>` 和 `<td>` 元素中。

* **与 CSS 的关系：**
    - **间接关系：** CSS 本身不直接处理 JSON 数据。然而，JSON 数据可以被用来驱动 JavaScript 代码，从而动态地修改 CSS 样式。例如，根据 JSON 数据中的状态值来应用不同的 CSS 类。
        - **场景：**  一个按钮的状态由服务器返回的 JSON 数据控制。
        - **`json_values.cc` 的作用：** 用于表示服务器返回的状态信息（例如，一个 `JSONObject` 中包含键 "enabled"，值为布尔类型），JavaScript 根据这个布尔值，可以添加或移除按钮的 CSS 类，从而改变按钮的显示样式。

**逻辑推理的假设输入与输出：**

假设我们有一个 `JSONObject` 实例，表示一个包含用户信息的 JSON 对象：

**假设输入 (JSONObject 实例):**

```c++
auto user_object = JSONObject::Create();
user_object->SetString("name", "Alice");
user_object->SetInteger("age", 30);
user_object->SetBoolean("is_active", true);
```

**输出 (调用 `WriteJSON()`):**

```
{"name":"Alice","age":30,"is_active":true}
```

**输出 (调用 `PrettyWriteJSON()`):**

```
{
  "name": "Alice",
  "age": 30,
  "is_active": true
}
```

**用户或编程常见的使用错误：**

1. **类型假设错误：** 程序员可能错误地假设 JSON 值的类型，导致尝试进行错误的类型转换。
   - **示例：**  假设一个 `JSONObject` 的键 "count" 对应的是一个整数，但实际上服务器返回的是一个字符串。如果代码尝试使用 `GetInteger("count")`，则会失败。
   - **预防措施：** 在进行类型转换之前，最好先检查 JSON 值的类型，或者使用返回值来判断转换是否成功。

2. **访问不存在的键或索引：**  尝试访问 `JSONObject` 中不存在的键或 `JSONArray` 中越界的索引。
   - **示例：**  `JSONObject` 中没有键 "email"，但代码尝试调用 `GetString("email")`，这将返回空值或导致错误（取决于具体的实现细节）。
   - **预防措施：** 在访问键或索引之前，最好先检查它们是否存在。对于 `JSONObject` 可以使用 `Get()` 方法并检查返回值是否为空，对于 `JSONArray` 可以检查大小。

3. **忘记处理 JSON 中的 `null` 值：**  JSON 中可以包含 `null` 值，如果没有正确处理，可能会导致程序崩溃或产生意外行为。
   - **示例：**  一个 `JSONObject` 的某个键可能对应 `null` 值。如果代码直接尝试将 `null` 值转换为特定的类型（例如字符串），可能会出错。
   - **预防措施：** 在处理从 JSON 获取的值时，需要考虑 `null` 的可能性。

4. **在应该使用字符串的地方使用了其他类型：** 有些 API 或操作可能期望接收字符串类型的 JSON 值，但如果传递了其他类型，可能会导致错误。
   - **示例：**  某个 JavaScript 函数期望接收一个表示颜色的字符串，但 JSON 中对应的值是一个数字（例如 RGB 值的整数表示）。
   - **预防措施：** 确保传递给 API 或操作的 JSON 值的类型是符合预期的。

5. **不正确的 JSON 序列化：**  虽然 `json_values.cc` 提供了正确的序列化方法，但在其他地方构建 JSON 数据时，可能会因为手动拼接字符串等方式而产生不符合 JSON 规范的字符串。
   - **示例：**  手动拼接 JSON 字符串时，忘记转义特殊字符，例如在字符串值中包含未转义的双引号。
   - **预防措施：** 尽量使用提供的 `JSONObject` 和 `JSONArray` 类来构建 JSON 数据，并使用 `WriteJSON` 或 `PrettyWriteJSON` 进行序列化，避免手动拼接。

总而言之，`blink/renderer/platform/json/json_values.cc` 文件定义了 Blink 引擎处理 JSON 数据的基础结构，它使得 C++ 代码能够方便地表示、操作和序列化 JSON 数据，这对于与前端 JavaScript 代码以及外部服务进行数据交换至关重要。理解其功能和使用方式对于开发和调试 Chromium 相关的项目非常重要。

### 提示词
```
这是目录为blink/renderer/platform/json/json_values.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2010 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/json/json_values.h"

#include <algorithm>
#include <cmath>

#include "base/notreached.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/decimal.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

inline bool EscapeChar(UChar c, StringBuilder* dst) {
  switch (c) {
    case '\b':
      dst->Append("\\b");
      break;
    case '\f':
      dst->Append("\\f");
      break;
    case '\n':
      dst->Append("\\n");
      break;
    case '\r':
      dst->Append("\\r");
      break;
    case '\t':
      dst->Append("\\t");
      break;
    case '\\':
      dst->Append("\\\\");
      break;
    case '"':
      dst->Append("\\\"");
      break;
    default:
      return false;
  }
  return true;
}

const LChar kHexDigits[17] = "0123456789ABCDEF";

void AppendUnsignedAsHex(UChar number, StringBuilder* dst) {
  dst->Append("\\u");
  for (size_t i = 0; i < 4; ++i) {
    dst->Append(kHexDigits[(number & 0xF000) >> 12]);
    number <<= 4;
  }
}

void WriteIndent(int depth, StringBuilder* output) {
  for (int i = 0; i < depth; ++i)
    output->Append("  ");
}

}  // anonymous namespace

const char kJSONNullString[] = "null";
const char kJSONTrueString[] = "true";
const char kJSONFalseString[] = "false";

void EscapeStringForJSON(const String& str, StringBuilder* dst) {
  for (unsigned i = 0; i < str.length(); ++i) {
    UChar c = str[i];
    if (!EscapeChar(c, dst)) {
      if (c < 32 || c == '<' || c == '>') {
        // 1. Escaping <, > to prevent script execution.
        AppendUnsignedAsHex(c, dst);
      } else {
        dst->Append(c);
      }
    }
  }
}

void DoubleQuoteStringForJSON(const String& str, StringBuilder* dst) {
  dst->Append('"');
  EscapeStringForJSON(str, dst);
  dst->Append('"');
}

String JSONValue::QuoteString(const String& input) {
  StringBuilder builder;
  DoubleQuoteStringForJSON(input, &builder);
  return builder.ToString();
}

bool JSONValue::AsBoolean(bool*) const {
  return false;
}

bool JSONValue::AsDouble(double*) const {
  return false;
}

bool JSONValue::AsInteger(int*) const {
  return false;
}

bool JSONValue::AsString(String*) const {
  return false;
}

String JSONValue::ToJSONString() const {
  StringBuilder result;
  result.ReserveCapacity(512);
  WriteJSON(&result);
  return result.ToString();
}

String JSONValue::ToPrettyJSONString() const {
  StringBuilder result;
  result.ReserveCapacity(512);
  PrettyWriteJSON(&result);
  return result.ToString();
}

void JSONValue::WriteJSON(StringBuilder* output) const {
  DCHECK(type_ == kTypeNull);
  output->Append(base::byte_span_from_cstring(kJSONNullString));
}

void JSONValue::PrettyWriteJSON(StringBuilder* output) const {
  PrettyWriteJSONInternal(output, 0);
  output->Append('\n');
}

void JSONValue::PrettyWriteJSONInternal(StringBuilder* output,
                                        int depth) const {
  WriteJSON(output);
}

std::unique_ptr<JSONValue> JSONValue::Clone() const {
  return JSONValue::Null();
}

bool JSONBasicValue::AsBoolean(bool* output) const {
  if (GetType() != kTypeBoolean)
    return false;
  *output = bool_value_;
  return true;
}

bool JSONBasicValue::AsDouble(double* output) const {
  if (GetType() == kTypeDouble) {
    *output = double_value_;
    return true;
  }
  if (GetType() == kTypeInteger) {
    *output = integer_value_;
    return true;
  }
  return false;
}

bool JSONBasicValue::AsInteger(int* output) const {
  if (GetType() != kTypeInteger)
    return false;
  *output = integer_value_;
  return true;
}

void JSONBasicValue::WriteJSON(StringBuilder* output) const {
  DCHECK(GetType() == kTypeBoolean || GetType() == kTypeInteger ||
         GetType() == kTypeDouble);
  if (GetType() == kTypeBoolean) {
    if (bool_value_)
      output->Append(base::byte_span_from_cstring(kJSONTrueString));
    else
      output->Append(base::byte_span_from_cstring(kJSONFalseString));
  } else if (GetType() == kTypeDouble) {
    if (!std::isfinite(double_value_)) {
      output->Append(base::byte_span_from_cstring(kJSONNullString));
      return;
    }
    output->Append(Decimal::FromDouble(double_value_).ToString());
  } else if (GetType() == kTypeInteger) {
    output->Append(String::Number(integer_value_));
  }
}

std::unique_ptr<JSONValue> JSONBasicValue::Clone() const {
  switch (GetType()) {
    case kTypeDouble:
      return std::make_unique<JSONBasicValue>(double_value_);
    case kTypeInteger:
      return std::make_unique<JSONBasicValue>(integer_value_);
    case kTypeBoolean:
      return std::make_unique<JSONBasicValue>(bool_value_);
    default:
      NOTREACHED();
  }
}

bool JSONString::AsString(String* output) const {
  *output = string_value_;
  return true;
}

void JSONString::WriteJSON(StringBuilder* output) const {
  DCHECK(GetType() == kTypeString);
  DoubleQuoteStringForJSON(string_value_, output);
}

std::unique_ptr<JSONValue> JSONString::Clone() const {
  return std::make_unique<JSONString>(string_value_);
}

JSONObject::~JSONObject() = default;

bool JSONObject::SetBoolean(const String& name, bool value) {
  return SetValue(name, std::make_unique<JSONBasicValue>(value));
}

bool JSONObject::SetInteger(const String& name, int value) {
  return SetValue(name, std::make_unique<JSONBasicValue>(value));
}

bool JSONObject::SetDouble(const String& name, double value) {
  return SetValue(name, std::make_unique<JSONBasicValue>(value));
}

bool JSONObject::SetString(const String& name, const String& value) {
  return SetValue(name, std::make_unique<JSONString>(value));
}

bool JSONObject::SetValue(const String& name,
                          std::unique_ptr<JSONValue> value) {
  return Set(name, value);
}

bool JSONObject::SetObject(const String& name,
                           std::unique_ptr<JSONObject> value) {
  return Set(name, value);
}

bool JSONObject::SetArray(const String& name,
                          std::unique_ptr<JSONArray> value) {
  return Set(name, value);
}

bool JSONObject::GetBoolean(const String& name, bool* output) const {
  JSONValue* value = Get(name);
  if (!value)
    return false;
  return value->AsBoolean(output);
}

bool JSONObject::GetInteger(const String& name, int* output) const {
  JSONValue* value = Get(name);
  if (!value)
    return false;
  return value->AsInteger(output);
}

bool JSONObject::GetDouble(const String& name, double* output) const {
  JSONValue* value = Get(name);
  if (!value)
    return false;
  return value->AsDouble(output);
}

bool JSONObject::GetString(const String& name, String* output) const {
  JSONValue* value = Get(name);
  if (!value)
    return false;
  return value->AsString(output);
}

JSONObject* JSONObject::GetJSONObject(const String& name) const {
  return JSONObject::Cast(Get(name));
}

JSONArray* JSONObject::GetArray(const String& name) const {
  return JSONArray::Cast(Get(name));
}

JSONValue* JSONObject::Get(const String& name) const {
  Dictionary::const_iterator it = data_.find(name);
  if (it == data_.end())
    return nullptr;
  return it->value.get();
}

JSONObject::Entry JSONObject::at(wtf_size_t index) const {
  const String key = order_[index];
  return std::make_pair(key, data_.find(key)->value.get());
}

bool JSONObject::BooleanProperty(const String& name, bool default_value) const {
  bool result = default_value;
  GetBoolean(name, &result);
  return result;
}

int JSONObject::IntegerProperty(const String& name, int default_value) const {
  int result = default_value;
  GetInteger(name, &result);
  return result;
}

double JSONObject::DoubleProperty(const String& name,
                                  double default_value) const {
  double result = default_value;
  GetDouble(name, &result);
  return result;
}

void JSONObject::Remove(const String& name) {
  data_.erase(name);
  for (wtf_size_t i = 0; i < order_.size(); ++i) {
    if (order_[i] == name) {
      order_.EraseAt(i);
      break;
    }
  }
}

void JSONObject::WriteJSON(StringBuilder* output) const {
  output->Append('{');
  for (wtf_size_t i = 0; i < order_.size(); ++i) {
    Dictionary::const_iterator it = data_.find(order_[i]);
    CHECK(it != data_.end());
    if (i)
      output->Append(',');
    DoubleQuoteStringForJSON(it->key, output);
    output->Append(':');
    it->value->WriteJSON(output);
  }
  output->Append('}');
}

void JSONObject::PrettyWriteJSONInternal(StringBuilder* output,
                                         int depth) const {
  output->Append("{\n");
  for (wtf_size_t i = 0; i < order_.size(); ++i) {
    Dictionary::const_iterator it = data_.find(order_[i]);
    CHECK(it != data_.end());
    if (i)
      output->Append(",\n");
    WriteIndent(depth + 1, output);
    DoubleQuoteStringForJSON(it->key, output);
    output->Append(": ");
    it->value->PrettyWriteJSONInternal(output, depth + 1);
  }
  output->Append('\n');
  WriteIndent(depth, output);
  output->Append('}');
}

std::unique_ptr<JSONValue> JSONObject::Clone() const {
  auto result = std::make_unique<JSONObject>();
  for (const String& key : order_) {
    Dictionary::const_iterator value = data_.find(key);
    DCHECK(value != data_.end() && value->value);
    result->SetValue(key, value->value->Clone());
  }
  return std::move(result);
}

JSONObject::JSONObject() : JSONValue(kTypeObject), data_(), order_() {}

JSONArray::~JSONArray() = default;

void JSONArray::WriteJSON(StringBuilder* output) const {
  output->Append('[');
  bool first = true;
  for (const std::unique_ptr<JSONValue>& value : data_) {
    if (!first)
      output->Append(',');
    value->WriteJSON(output);
    first = false;
  }
  output->Append(']');
}

void JSONArray::PrettyWriteJSONInternal(StringBuilder* output,
                                        int depth) const {
  output->Append('[');
  bool first = true;
  bool last_inserted_new_line = false;
  for (const std::unique_ptr<JSONValue>& value : data_) {
    bool insert_new_line = value->GetType() == JSONValue::kTypeObject ||
                           value->GetType() == JSONValue::kTypeArray ||
                           value->GetType() == JSONValue::kTypeString;
    if (first) {
      if (insert_new_line) {
        output->Append('\n');
        WriteIndent(depth + 1, output);
      }
      first = false;
    } else {
      output->Append(',');
      if (last_inserted_new_line) {
        output->Append('\n');
        WriteIndent(depth + 1, output);
      } else {
        output->Append(' ');
      }
    }
    value->PrettyWriteJSONInternal(output, depth + 1);
    last_inserted_new_line = insert_new_line;
  }
  if (last_inserted_new_line) {
    output->Append('\n');
    WriteIndent(depth, output);
  }
  output->Append(']');
}

std::unique_ptr<JSONValue> JSONArray::Clone() const {
  auto result = std::make_unique<JSONArray>();
  for (const std::unique_ptr<JSONValue>& value : data_)
    result->PushValue(value->Clone());
  return std::move(result);
}

JSONArray::JSONArray() : JSONValue(kTypeArray) {}

void JSONArray::PushBoolean(bool value) {
  data_.push_back(std::make_unique<JSONBasicValue>(value));
}

void JSONArray::PushInteger(int value) {
  data_.push_back(std::make_unique<JSONBasicValue>(value));
}

void JSONArray::PushDouble(double value) {
  data_.push_back(std::make_unique<JSONBasicValue>(value));
}

void JSONArray::PushString(const String& value) {
  data_.push_back(std::make_unique<JSONString>(value));
}

void JSONArray::PushValue(std::unique_ptr<JSONValue> value) {
  DCHECK(value);
  data_.push_back(std::move(value));
}

void JSONArray::PushObject(std::unique_ptr<JSONObject> value) {
  DCHECK(value);
  data_.push_back(std::move(value));
}

void JSONArray::PushArray(std::unique_ptr<JSONArray> value) {
  DCHECK(value);
  data_.push_back(std::move(value));
}

JSONValue* JSONArray::at(wtf_size_t index) const {
  DCHECK_LT(index, data_.size());
  return data_[index].get();
}

}  // namespace blink
```