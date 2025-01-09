Response:
Let's break down the thought process for analyzing the `json.cc` file.

1. **Identify the Core Purpose:** The filename `json.cc` and the `#include "json.h"` immediately suggest this file deals with JSON processing. The namespace `v8_crdtp::json` further clarifies it's related to V8 (JavaScript engine), specifically the Chrome Remote Debugging Protocol (CRDP).

2. **Scan for Key Components:** Quickly read through the code, looking for major structures, classes, and functions. This initial scan reveals:
    * `NewJSONEncoder`:  Appears to be for converting something *to* JSON.
    * `JSONEncoder`:  A class that seems to handle the encoding process.
    * `ParseJSON`:  Clearly for parsing JSON.
    * `JsonParser`: A class handling the parsing logic.
    * `ConvertCBORToJSON` and `ConvertJSONToCBOR`: Functions for converting between CBOR and JSON.

3. **Analyze `NewJSONEncoder` and `JSONEncoder`:**
    * **Purpose:** The name strongly indicates this is for creating JSON output. The comments confirm this: "for encoding streaming parser events as JSON".
    * **Mechanism:**  The `JSONEncoder` class implements the `ParserHandler` interface. This suggests it's designed to receive events from a streaming parser (although in this file, it's used directly with the *output* stream).
    * **State Management:** The `State` class and the `std::stack<State> state_` member are crucial. This is used to keep track of the current JSON structure (object or array) to correctly insert commas, colons, and brackets.
    * **Handling Different Types:**  The `Handle...` methods (e.g., `HandleMapBegin`, `HandleString8`, `HandleDouble`) show how different data types are converted to their JSON string representations. Pay attention to special handling for things like NaN, Infinity, and UTF-8 encoding.
    * **Base64 Encoding:**  The `Base64Encode` function is interesting. It suggests binary data can be embedded in the JSON, likely as base64 strings.

4. **Analyze `ParseJSON` and `JsonParser`:**
    * **Purpose:**  The name `ParseJSON` is self-explanatory. The comments reinforce this: "for receiving streaming parser events for JSON."
    * **Mechanism:**  The `JsonParser` class also uses a streaming approach. It takes a `ParserHandler` as input, meaning it will call methods on that handler as it parses the JSON. This design allows for different actions to be taken on the parsed JSON data.
    * **Tokenization:** The `ParseToken` function is key. It identifies different JSON elements (objects, arrays, strings, numbers, booleans, null). The `Token` enum lists the possible tokens.
    * **Error Handling:** The code checks for various JSON syntax errors and uses the `HandleError` method to report them.
    * **Recursion:** The `ParseValue` function is recursive, necessary to handle nested JSON structures. The `kStackLimit` constant is important for preventing stack overflow.
    * **String Decoding:** The `DecodeString` function handles the unescaping of characters in JSON strings, including Unicode characters.

5. **Analyze `ConvertCBORToJSON` and `ConvertJSONToCBOR`:**
    * **Purpose:** These functions perform transcoding between CBOR (Concise Binary Object Representation) and JSON. This is a common need in data serialization.
    * **Mechanism:** They leverage the `NewJSONEncoder` and `cbor::NewCBOREncoder` (we assume this exists in `cbor.h`), along with the `ParseJSON` and `cbor::ParseCBOR` functions, to perform the conversions. This highlights the flexible, event-driven design of the parsing and encoding components.

6. **Address Specific Questions in the Prompt:**
    * **Functionality Listing:** Summarize the findings from steps 3, 4, and 5.
    * **`.tq` Extension:**  Explain that `.tq` indicates Torque (V8's internal type system and code generation language) and that `json.cc` is C++, not Torque.
    * **JavaScript Relationship:** Connect the JSON processing to how JavaScript works with JSON (e.g., `JSON.stringify`, `JSON.parse`). Provide simple examples.
    * **Code Logic Inference (Hypothetical Input/Output):** Create basic examples for both encoding and parsing to illustrate the flow of data and the expected output.
    * **Common Programming Errors:** Think about typical mistakes when working with JSON, such as incorrect syntax, type mismatches, and handling errors. Provide illustrative code examples.

7. **Review and Refine:** Read through the analysis to ensure clarity, accuracy, and completeness. Check for any missing points or areas that could be explained better. Make sure the JavaScript examples are clear and relevant.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps the `ParserHandler` in `JSONEncoder` means it's designed to receive events from a *JSON* parser.
* **Correction:** Realize that the `JSONEncoder` is *generating* JSON. It's used as a handler for *other* types of parser events (like CBOR in the `ConvertCBORToJSON` function). This is a key design pattern: a common handler interface allows for flexible data transformations.
* **Initial thought:**  Focus too much on the low-level details of string escaping.
* **Correction:**  Shift focus to the overall purpose and the higher-level structure of the code. The details of escaping are important but shouldn't overshadow the main functionality.
* **Initial thought:**  Forget to explicitly mention the dependency on `cbor.h`.
* **Correction:**  Add a note about the CBOR integration in the functionality description.

By following these steps, combining code analysis with an understanding of the problem domain (JSON processing, V8, CRDP), and addressing the specific requirements of the prompt, a comprehensive explanation of the `json.cc` file can be constructed.
这个 `v8/third_party/inspector_protocol/crdtp/json.cc` 文件是 V8 JavaScript 引擎中用于处理 JSON (JavaScript Object Notation) 的源代码文件。它提供了一系列功能，用于将数据编码为 JSON 格式以及从 JSON 格式解码数据。

以下是该文件的主要功能：

1. **JSON 编码 (Serialization):**
   - **`NewJSONEncoder` 函数:**  这个函数创建并返回一个 `ParserHandler` 接口的实现，用于将流式的解析器事件转换为 JSON 字符串。
   - **`JSONEncoder` 类:**  这是一个实现了 `ParserHandler` 接口的类，负责接收各种类型的数据（例如，Map 开始/结束、Array 开始/结束、字符串、数字、布尔值、null、二进制数据）的事件，并将它们格式化为符合 JSON 语法的字符串。它使用一个栈 (`state_`) 来跟踪当前的 JSON 结构（对象或数组），以便正确地插入逗号、冒号和括号。
   - **支持多种数据类型:** 可以编码字符串（支持 Unicode 转义）、数字（包括整数和浮点数，并处理 `NaN` 和 `Infinity`）、布尔值、null 以及二进制数据（编码为 Base64 字符串）。

2. **JSON 解码 (Deserialization/Parsing):**
   - **`ParseJSON` 函数:**  这个函数接收一个包含 JSON 数据的 `span<uint8_t>` 或 `span<uint16_t>`（表示 UTF-8 或 UTF-16 编码的 JSON 字符串），以及一个 `ParserHandler` 对象。它会解析 JSON 数据，并调用 `ParserHandler` 上的相应方法来通知解析事件（例如，遇到对象开始、数组开始、字符串值等）。
   - **`JsonParser` 类:**  这是一个模板类，实现了 JSON 的解析逻辑。它负责词法分析（将 JSON 字符串分解为 token）和语法分析（根据 JSON 语法规则处理 token）。它能够识别对象、数组、字符串、数字、布尔值和 null。
   - **错误处理:**  `JsonParser` 能够检测 JSON 语法错误，并通过调用 `ParserHandler` 的 `HandleError` 方法报告错误及其在输入中的位置。
   - **支持注释:**  JSON 解析器支持单行 (`//`) 和多行 (`/* ... */`) 注释。

3. **CBOR 和 JSON 之间的转换 (Transcoding):**
   - **`ConvertCBORToJSON` 函数:**  将 CBOR (Concise Binary Object Representation) 格式的数据转换为 JSON 格式。它利用 CBOR 解析器 (`cbor::ParseCBOR`) 和 JSON 编码器 (`NewJSONEncoder`) 来实现转换。
   - **`ConvertJSONToCBOR` 函数:**  将 JSON 格式的数据转换为 CBOR 格式。它利用 JSON 解析器 (`ParseJSON`) 和 CBOR 编码器 (`cbor::NewCBOREncoder`) 来实现转换。

**关于文件扩展名和 Torque:**

如果 `v8/third_party/inspector_protocol/crdtp/json.cc` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。Torque 是 V8 用来定义内置函数、运行时函数和类型系统的内部语言。然而，根据你提供的代码内容，这个文件是以 `.cc` 结尾的，这意味着它是一个 **C++** 源代码文件。

**与 JavaScript 的关系 (及其示例):**

这个 `json.cc` 文件的功能与 JavaScript 中内置的 `JSON` 对象的功能密切相关。`JSON` 对象提供了 `stringify()` 方法用于将 JavaScript 对象转换为 JSON 字符串，以及 `parse()` 方法用于将 JSON 字符串解析为 JavaScript 对象。

- **`JSON.stringify()` (JavaScript 编码):**  `json.cc` 中的编码功能类似于 JavaScript 的 `JSON.stringify()`。它将数据结构（在 C++ 中表示）转换为符合 JSON 格式的字符串。

   ```javascript
   // JavaScript 示例：JSON.stringify()
   const myObject = {
     name: "Alice",
     age: 30,
     city: "New York"
   };
   const jsonString = JSON.stringify(myObject);
   console.log(jsonString); // 输出: {"name":"Alice","age":30,"city":"New York"}
   ```

- **`JSON.parse()` (JavaScript 解码):** `json.cc` 中的解码功能类似于 JavaScript 的 `JSON.parse()`。它将 JSON 字符串解析为可以操作的数据结构（在 C++ 中，这些数据结构由 `ParserHandler` 的实现来处理）。

   ```javascript
   // JavaScript 示例：JSON.parse()
   const jsonString = '{"name":"Bob","age":25,"city":"London"}';
   const parsedObject = JSON.parse(jsonString);
   console.log(parsedObject.name); // 输出: Bob
   console.log(parsedObject.age);  // 输出: 25
   ```

**代码逻辑推理 (假设输入与输出):**

**JSON 编码示例:**

**假设输入 (C++ 中的事件流):**

```c++
std::string output;
v8_crdtp::json::Status status;
auto encoder = v8_crdtp::json::NewJSONEncoder(&output, &status);

encoder->HandleMapBegin();
encoder->HandleString8(v8_crdtp::base::StringView("name"));
encoder->HandleString8(v8_crdtp::base::StringView("Charlie"));
encoder->HandleString8(v8_crdtp::base::StringView("age"));
encoder->HandleInt32(35);
encoder->HandleMapEnd();
```

**预期输出 (JSON 字符串):**

```json
{"name":"Charlie","age":35}
```

**JSON 解码示例:**

**假设输入 (JSON 字符串):**

```json
{"city":"Paris","country":"France"}
```

**假设 `ParserHandler` 实现（简化版，仅打印键值对）:**

```c++
class MyHandler : public v8_crdtp::json::ParserHandler {
 public:
  void HandleString16(v8_crdtp::base::span<uint16_t> chars) override {
    std::string str(chars.begin(), chars.end());
    if (expecting_key_) {
      current_key_ = str;
      expecting_key_ = false;
    } else {
      std::cout << current_key_ << ": " << str << std::endl;
      expecting_key_ = true;
    }
  }
  void HandleMapBegin() override { expecting_key_ = true; }
  void HandleMapEnd() override {}
  void HandleError(v8_crdtp::json::Status error) override {
    std::cerr << "Error parsing JSON: " << error.message() << std::endl;
  }
 private:
  bool expecting_key_ = false;
  std::string current_key_;
};
```

**预期输出 (基于 `MyHandler`):**

```
city: Paris
country: France
```

**用户常见的编程错误:**

1. **JSON 编码时的数据类型不匹配:** 尝试将 C++ 中不支持直接转换为 JSON 的数据类型（例如，复杂的对象 без 自定义序列化逻辑）传递给编码器。

   ```c++
   // 错误示例：尝试编码一个不适合 JSON 的 C++ 对象
   struct MyComplexObject {
     int id;
     std::vector<int> data;
   };

   MyComplexObject obj = {123, {1, 2, 3}};
   std::string output;
   v8_crdtp::json::Status status;
   auto encoder = v8_crdtp::json::NewJSONEncoder(&output, &status);

   // 没有为 MyComplexObject 提供序列化逻辑，会导致不期望的结果或错误
   // 常见的做法是手动构建 JSON 结构
   encoder->HandleMapBegin();
   encoder->HandleString8(v8_crdtp::base::StringView("id"));
   encoder->HandleInt32(obj.id);
   encoder->HandleString8(v8_crdtp::base::StringView("data"));
   encoder->HandleArrayBegin();
   for (int val : obj.data) {
     encoder->HandleInt32(val);
   }
   encoder->HandleArrayEnd();
   encoder->HandleMapEnd();
   ```

2. **JSON 解码时假设错误的结构:**  在 `ParserHandler` 的实现中，假设 JSON 数据的结构是固定的，而实际接收到的 JSON 可能有不同的字段或嵌套方式。

   ```c++
   // 错误示例：假设 JSON 总是包含 "name" 和 "age" 字段
   class NaiveHandler : public v8_crdtp::json::ParserHandler {
     // ... (省略其他方法)
     void HandleString16(v8_crdtp::base::span<uint16_t> chars) override {
       std::string str(chars.begin(), chars.end());
       if (expecting_name_) {
         name_ = str;
         expecting_age_ = true;
         expecting_name_ = false;
       } else if (expecting_age_) {
         // 假设下一个字符串总是 age，但 JSON 可能有其他字段
         age_ = std::stoi(str); // 如果不是数字字符串会出错
         expecting_age_ = false;
       }
     }
     // ...
   private:
     bool expecting_name_ = true;
     bool expecting_age_ = false;
     std::string name_;
     int age_;
   };

   // 如果 JSON 是 {"city": "London"}，这个 Handler 会出错
   ```

3. **未能处理 JSON 解析错误:**  在调用 `ParseJSON` 后，没有检查 `Status` 对象以确定是否发生了错误。

   ```c++
   std::string json_data = R"({"invalid": json,)"; // 错误的 JSON
   MyHandler handler;
   v8_crdtp::json::ParseJSON(
       v8_crdtp::base::as_bytes(v8_crdtp::base::StringView(json_data)), &handler);
   // 没有检查 handler 的状态，可能忽略了解析错误
   ```

4. **手动构建 JSON 字符串时出现语法错误:**  如果尝试手动拼接 JSON 字符串而不是使用编码器，很容易引入语法错误（例如，忘记引号、逗号或括号）。

   ```c++
   // 错误示例：手动构建 JSON 字符串时忘记引号
   std::string name = "David";
   int age = 40;
   std::string json_string = "{\"name\":" + name + ",\"age\":" + std::to_string(age) + "}";
   // 缺少 name 周围的引号，正确的应该是: "{\"name\":\"" + name + "\",\"age\":" + ...
   ```

理解这些功能和潜在的错误可以帮助开发者更有效地使用 V8 的 JSON 处理能力。

Prompt: 
```
这是目录为v8/third_party/inspector_protocol/crdtp/json.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/third_party/inspector_protocol/crdtp/json.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "json.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <limits>
#include <stack>

#include "cbor.h"
#include "json_platform.h"

namespace v8_crdtp {
namespace json {
// =============================================================================
// json::NewJSONEncoder - for encoding streaming parser events as JSON
// =============================================================================

namespace {
// Prints |value| to |out| with 4 hex digits, most significant chunk first.
template <typename C>
void PrintHex(uint16_t value, C* out) {
  for (int ii = 3; ii >= 0; --ii) {
    int four_bits = 0xf & (value >> (4 * ii));
    out->push_back(four_bits + ((four_bits <= 9) ? '0' : ('a' - 10)));
  }
}

// In the writer below, we maintain a stack of State instances.
// It is just enough to emit the appropriate delimiters and brackets
// in JSON.
enum class Container {
  // Used for the top-level, initial state.
  NONE,
  // Inside a JSON object.
  MAP,
  // Inside a JSON array.
  ARRAY
};

class State {
 public:
  explicit State(Container container) : container_(container) {}
  void StartElement(std::vector<uint8_t>* out) { StartElementTmpl(out); }
  void StartElement(std::string* out) { StartElementTmpl(out); }
  Container container() const { return container_; }

 private:
  template <typename C>
  void StartElementTmpl(C* out) {
    assert(container_ != Container::NONE || size_ == 0);
    if (size_ != 0) {
      char delim = (!(size_ & 1) || container_ == Container::ARRAY) ? ',' : ':';
      out->push_back(delim);
    }
    ++size_;
  }

  Container container_ = Container::NONE;
  int size_ = 0;
};

constexpr char kBase64Table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz0123456789+/";

template <typename C>
void Base64Encode(const span<uint8_t>& in, C* out) {
  // The following three cases are based on the tables in the example
  // section in https://en.wikipedia.org/wiki/Base64. We process three
  // input bytes at a time, emitting 4 output bytes at a time.
  size_t ii = 0;

  // While possible, process three input bytes.
  for (; ii + 3 <= in.size(); ii += 3) {
    uint32_t twentyfour_bits = (in[ii] << 16) | (in[ii + 1] << 8) | in[ii + 2];
    out->push_back(kBase64Table[(twentyfour_bits >> 18)]);
    out->push_back(kBase64Table[(twentyfour_bits >> 12) & 0x3f]);
    out->push_back(kBase64Table[(twentyfour_bits >> 6) & 0x3f]);
    out->push_back(kBase64Table[twentyfour_bits & 0x3f]);
  }
  if (ii + 2 <= in.size()) {  // Process two input bytes.
    uint32_t twentyfour_bits = (in[ii] << 16) | (in[ii + 1] << 8);
    out->push_back(kBase64Table[(twentyfour_bits >> 18)]);
    out->push_back(kBase64Table[(twentyfour_bits >> 12) & 0x3f]);
    out->push_back(kBase64Table[(twentyfour_bits >> 6) & 0x3f]);
    out->push_back('=');  // Emit padding.
    return;
  }
  if (ii + 1 <= in.size()) {  // Process a single input byte.
    uint32_t twentyfour_bits = (in[ii] << 16);
    out->push_back(kBase64Table[(twentyfour_bits >> 18)]);
    out->push_back(kBase64Table[(twentyfour_bits >> 12) & 0x3f]);
    out->push_back('=');  // Emit padding.
    out->push_back('=');  // Emit padding.
  }
}

// Implements a handler for JSON parser events to emit a JSON string.
template <typename C>
class JSONEncoder : public ParserHandler {
 public:
  JSONEncoder(C* out, Status* status) : out_(out), status_(status) {
    *status_ = Status();
    state_.emplace(Container::NONE);
  }

  void HandleMapBegin() override {
    if (!status_->ok())
      return;
    assert(!state_.empty());
    state_.top().StartElement(out_);
    state_.emplace(Container::MAP);
    Emit('{');
  }

  void HandleMapEnd() override {
    if (!status_->ok())
      return;
    assert(state_.size() >= 2 && state_.top().container() == Container::MAP);
    state_.pop();
    Emit('}');
  }

  void HandleArrayBegin() override {
    if (!status_->ok())
      return;
    state_.top().StartElement(out_);
    state_.emplace(Container::ARRAY);
    Emit('[');
  }

  void HandleArrayEnd() override {
    if (!status_->ok())
      return;
    assert(state_.size() >= 2 && state_.top().container() == Container::ARRAY);
    state_.pop();
    Emit(']');
  }

  void HandleString16(span<uint16_t> chars) override {
    if (!status_->ok())
      return;
    state_.top().StartElement(out_);
    Emit('"');
    for (const uint16_t ch : chars) {
      if (ch == '"') {
        Emit('\\');
        Emit('"');
      } else if (ch == '\\') {
        Emit('\\');
        Emit('\\');
      } else if (ch >= 32 && ch <= 127) {
        Emit(ch);
      } else if (ch == '\n') {
        Emit('\\');
        Emit('n');
      } else if (ch == '\r') {
        Emit('\\');
        Emit('r');
      } else if (ch == '\t') {
        Emit('\\');
        Emit('t');
      } else if (ch == '\b') {
        Emit('\\');
        Emit('b');
      } else if (ch == '\f') {
        Emit('\\');
        Emit('f');
      } else {
        Emit('\\');
        Emit('u');
        PrintHex(ch, out_);
      }
    }
    Emit('"');
  }

  void HandleString8(span<uint8_t> chars) override {
    if (!status_->ok())
      return;
    state_.top().StartElement(out_);
    Emit('"');
    for (size_t ii = 0; ii < chars.size(); ++ii) {
      uint8_t c = chars[ii];
      if (c == '"') {
        Emit('\\');
        Emit('"');
      } else if (c == '\\') {
        Emit('\\');
        Emit('\\');
      } else if (c >= 32 && c <= 127) {
        Emit(c);
      } else if (c == '\n') {
        Emit('\\');
        Emit('n');
      } else if (c == '\r') {
        Emit('\\');
        Emit('r');
      } else if (c == '\t') {
        Emit('\\');
        Emit('t');
      } else if (c == '\b') {
        Emit('\\');
        Emit('b');
      } else if (c == '\f') {
        Emit('\\');
        Emit('f');
      } else if (c < 32) {
        Emit('\\');
        Emit('u');
        PrintHex(static_cast<uint16_t>(c), out_);
      } else {
        // Inspect the leading byte to figure out how long the utf8
        // byte sequence is; while doing this initialize |codepoint|
        // with the first few bits.
        // See table in: https://en.wikipedia.org/wiki/UTF-8
        // byte one is 110x xxxx -> 2 byte utf8 sequence
        // byte one is 1110 xxxx -> 3 byte utf8 sequence
        // byte one is 1111 0xxx -> 4 byte utf8 sequence
        uint32_t codepoint;
        int num_bytes_left;
        if ((c & 0xe0) == 0xc0) {  // 2 byte utf8 sequence
          num_bytes_left = 1;
          codepoint = c & 0x1f;
        } else if ((c & 0xf0) == 0xe0) {  // 3 byte utf8 sequence
          num_bytes_left = 2;
          codepoint = c & 0x0f;
        } else if ((c & 0xf8) == 0xf0) {  // 4 byte utf8 sequence
          codepoint = c & 0x07;
          num_bytes_left = 3;
        } else {
          continue;  // invalid leading byte
        }

        // If we have enough bytes in our input, decode the remaining ones
        // belonging to this Unicode character into |codepoint|.
        if (ii + num_bytes_left >= chars.size())
          continue;
        bool invalid_byte_seen = false;
        while (num_bytes_left > 0) {
          c = chars[++ii];
          --num_bytes_left;
          // Check the next byte is a continuation byte, that is 10xx xxxx.
          if ((c & 0xc0) != 0x80)
            invalid_byte_seen = true;
          codepoint = (codepoint << 6) | (c & 0x3f);
        }
        if (invalid_byte_seen)
          continue;

        // Disallow overlong encodings for ascii characters, as these
        // would include " and other characters significant to JSON
        // string termination / control.
        if (codepoint <= 0x7f)
          continue;
        // Invalid in UTF8, and can't be represented in UTF16 anyway.
        if (codepoint > 0x10ffff)
          continue;

        // So, now we transcode to UTF16,
        // using the math described at https://en.wikipedia.org/wiki/UTF-16,
        // for either one or two 16 bit characters.
        if (codepoint <= 0xffff) {
          Emit("\\u");
          PrintHex(static_cast<uint16_t>(codepoint), out_);
          continue;
        }
        codepoint -= 0x10000;
        // high surrogate
        Emit("\\u");
        PrintHex(static_cast<uint16_t>((codepoint >> 10) + 0xd800), out_);
        // low surrogate
        Emit("\\u");
        PrintHex(static_cast<uint16_t>((codepoint & 0x3ff) + 0xdc00), out_);
      }
    }
    Emit('"');
  }

  void HandleBinary(span<uint8_t> bytes) override {
    if (!status_->ok())
      return;
    state_.top().StartElement(out_);
    Emit('"');
    Base64Encode(bytes, out_);
    Emit('"');
  }

  void HandleDouble(double value) override {
    if (!status_->ok())
      return;
    state_.top().StartElement(out_);
    // JSON cannot represent NaN or Infinity. So, for compatibility,
    // we behave like the JSON object in web browsers: emit 'null'.
    if (!std::isfinite(value)) {
      Emit("null");
      return;
    }
    // If |value| is a scalar, emit it as an int. Taken from json_writer.cc in
    // Chromium.
    if (value < static_cast<double>(std::numeric_limits<int64_t>::max()) &&
        value >= std::numeric_limits<int64_t>::min() &&
        std::floor(value) == value) {
      Emit(std::to_string(static_cast<int64_t>(value)));
      return;
    }
    std::string str_value = json::platform::DToStr(value);
    // The following is somewhat paranoid, but also taken from json_writer.cc
    // in Chromium:
    // Ensure that the number has a .0 if there's no decimal or 'e'.  This
    // makes sure that when we read the JSON back, it's interpreted as a
    // real rather than an int.
    if (str_value.find_first_of(".eE") == std::string::npos)
      str_value.append(".0");

    // DToStr may fail to emit a 0 before the decimal dot. E.g. this is
    // the case in base::NumberToString in Chromium (which is based on
    // dmg_fp). So, much like
    // https://cs.chromium.org/chromium/src/base/json/json_writer.cc
    // we probe for this and emit the leading 0 anyway if necessary.
    if (str_value[0] == '.') {
      Emit('0');
      Emit(str_value);
    } else if (str_value[0] == '-' && str_value[1] == '.') {
      Emit("-0");
      // Skip the '-' from the original string and emit the rest.
      out_->insert(out_->end(), str_value.begin() + 1, str_value.end());
    } else {
      Emit(str_value);
    }
  }

  void HandleInt32(int32_t value) override {
    if (!status_->ok())
      return;
    state_.top().StartElement(out_);
    Emit(std::to_string(value));
  }

  void HandleBool(bool value) override {
    if (!status_->ok())
      return;
    state_.top().StartElement(out_);
    if (value)
      Emit("true");
    else
      Emit("false");
  }

  void HandleNull() override {
    if (!status_->ok())
      return;
    state_.top().StartElement(out_);
    Emit("null");
  }

  void HandleError(Status error) override {
    assert(!error.ok());
    *status_ = error;
    out_->clear();
  }

 private:
  inline void Emit(char c) { out_->push_back(c); }
  template <size_t N>
  inline void Emit(const char (&str)[N]) {
    out_->insert(out_->end(), str, str + N - 1);
  }
  inline void Emit(const std::string& str) {
    out_->insert(out_->end(), str.begin(), str.end());
  }

  C* out_;
  Status* status_;
  std::stack<State> state_;
};
}  // namespace

std::unique_ptr<ParserHandler> NewJSONEncoder(std::vector<uint8_t>* out,
                                              Status* status) {
  return std::unique_ptr<ParserHandler>(
      new JSONEncoder<std::vector<uint8_t>>(out, status));
}

std::unique_ptr<ParserHandler> NewJSONEncoder(std::string* out,
                                              Status* status) {
  return std::unique_ptr<ParserHandler>(
      new JSONEncoder<std::string>(out, status));
}

// =============================================================================
// json::ParseJSON - for receiving streaming parser events for JSON.
// =============================================================================

namespace {
const int kStackLimit = 300;

enum Token {
  ObjectBegin,
  ObjectEnd,
  ArrayBegin,
  ArrayEnd,
  StringLiteral,
  Number,
  BoolTrue,
  BoolFalse,
  NullToken,
  ListSeparator,
  ObjectPairSeparator,
  InvalidToken,
  NoInput
};

const char* const kNullString = "null";
const char* const kTrueString = "true";
const char* const kFalseString = "false";

template <typename Char>
class JsonParser {
 public:
  explicit JsonParser(ParserHandler* handler) : handler_(handler) {}

  void Parse(const Char* start, size_t length) {
    start_pos_ = start;
    const Char* end = start + length;
    const Char* tokenEnd = nullptr;
    ParseValue(start, end, &tokenEnd, 0);
    if (error_)
      return;
    if (tokenEnd != end) {
      HandleError(Error::JSON_PARSER_UNPROCESSED_INPUT_REMAINS, tokenEnd);
    }
  }

 private:
  bool CharsToDouble(const uint16_t* chars, size_t length, double* result) {
    std::string buffer;
    buffer.reserve(length + 1);
    for (size_t ii = 0; ii < length; ++ii) {
      bool is_ascii = !(chars[ii] & ~0x7F);
      if (!is_ascii)
        return false;
      buffer.push_back(static_cast<char>(chars[ii]));
    }
    return platform::StrToD(buffer.c_str(), result);
  }

  bool CharsToDouble(const uint8_t* chars, size_t length, double* result) {
    std::string buffer(reinterpret_cast<const char*>(chars), length);
    return platform::StrToD(buffer.c_str(), result);
  }

  static bool ParseConstToken(const Char* start,
                              const Char* end,
                              const Char** token_end,
                              const char* token) {
    // |token| is \0 terminated, it's one of the constants at top of the file.
    while (start < end && *token != '\0' && *start++ == *token++) {
    }
    if (*token != '\0')
      return false;
    *token_end = start;
    return true;
  }

  static bool ReadInt(const Char* start,
                      const Char* end,
                      const Char** token_end,
                      bool allow_leading_zeros) {
    if (start == end)
      return false;
    bool has_leading_zero = '0' == *start;
    int length = 0;
    while (start < end && '0' <= *start && *start <= '9') {
      ++start;
      ++length;
    }
    if (!length)
      return false;
    if (!allow_leading_zeros && length > 1 && has_leading_zero)
      return false;
    *token_end = start;
    return true;
  }

  static bool ParseNumberToken(const Char* start,
                               const Char* end,
                               const Char** token_end) {
    // We just grab the number here. We validate the size in DecodeNumber.
    // According to RFC4627, a valid number is: [minus] int [frac] [exp]
    if (start == end)
      return false;
    Char c = *start;
    if ('-' == c)
      ++start;

    if (!ReadInt(start, end, &start, /*allow_leading_zeros=*/false))
      return false;
    if (start == end) {
      *token_end = start;
      return true;
    }

    // Optional fraction part
    c = *start;
    if ('.' == c) {
      ++start;
      if (!ReadInt(start, end, &start, /*allow_leading_zeros=*/true))
        return false;
      if (start == end) {
        *token_end = start;
        return true;
      }
      c = *start;
    }

    // Optional exponent part
    if ('e' == c || 'E' == c) {
      ++start;
      if (start == end)
        return false;
      c = *start;
      if ('-' == c || '+' == c) {
        ++start;
        if (start == end)
          return false;
      }
      if (!ReadInt(start, end, &start, /*allow_leading_zeros=*/true))
        return false;
    }

    *token_end = start;
    return true;
  }

  static bool ReadHexDigits(const Char* start,
                            const Char* end,
                            const Char** token_end,
                            int digits) {
    if (end - start < digits)
      return false;
    for (int i = 0; i < digits; ++i) {
      Char c = *start++;
      if (!(('0' <= c && c <= '9') || ('a' <= c && c <= 'f') ||
            ('A' <= c && c <= 'F')))
        return false;
    }
    *token_end = start;
    return true;
  }

  static bool ParseStringToken(const Char* start,
                               const Char* end,
                               const Char** token_end) {
    while (start < end) {
      Char c = *start++;
      if ('\\' == c) {
        if (start == end)
          return false;
        c = *start++;
        // Make sure the escaped char is valid.
        switch (c) {
          case 'x':
            if (!ReadHexDigits(start, end, &start, 2))
              return false;
            break;
          case 'u':
            if (!ReadHexDigits(start, end, &start, 4))
              return false;
            break;
          case '\\':
          case '/':
          case 'b':
          case 'f':
          case 'n':
          case 'r':
          case 't':
          case 'v':
          case '"':
            break;
          default:
            return false;
        }
      } else if ('"' == c) {
        *token_end = start;
        return true;
      }
    }
    return false;
  }

  static bool SkipComment(const Char* start,
                          const Char* end,
                          const Char** comment_end) {
    if (start == end)
      return false;

    if (*start != '/' || start + 1 >= end)
      return false;
    ++start;

    if (*start == '/') {
      // Single line comment, read to newline.
      for (++start; start < end; ++start) {
        if (*start == '\n' || *start == '\r') {
          *comment_end = start + 1;
          return true;
        }
      }
      *comment_end = end;
      // Comment reaches end-of-input, which is fine.
      return true;
    }

    if (*start == '*') {
      Char previous = '\0';
      // Block comment, read until end marker.
      for (++start; start < end; previous = *start++) {
        if (previous == '*' && *start == '/') {
          *comment_end = start + 1;
          return true;
        }
      }
      // Block comment must close before end-of-input.
      return false;
    }

    return false;
  }

  static bool IsSpaceOrNewLine(Char c) {
    // \v = vertial tab; \f = form feed page break.
    return c == ' ' || c == '\n' || c == '\v' || c == '\f' || c == '\r' ||
           c == '\t';
  }

  static void SkipWhitespaceAndComments(const Char* start,
                                        const Char* end,
                                        const Char** whitespace_end) {
    while (start < end) {
      if (IsSpaceOrNewLine(*start)) {
        ++start;
      } else if (*start == '/') {
        const Char* comment_end = nullptr;
        if (!SkipComment(start, end, &comment_end))
          break;
        start = comment_end;
      } else {
        break;
      }
    }
    *whitespace_end = start;
  }

  static Token ParseToken(const Char* start,
                          const Char* end,
                          const Char** tokenStart,
                          const Char** token_end) {
    SkipWhitespaceAndComments(start, end, tokenStart);
    start = *tokenStart;

    if (start == end)
      return NoInput;

    switch (*start) {
      case 'n':
        if (ParseConstToken(start, end, token_end, kNullString))
          return NullToken;
        break;
      case 't':
        if (ParseConstToken(start, end, token_end, kTrueString))
          return BoolTrue;
        break;
      case 'f':
        if (ParseConstToken(start, end, token_end, kFalseString))
          return BoolFalse;
        break;
      case '[':
        *token_end = start + 1;
        return ArrayBegin;
      case ']':
        *token_end = start + 1;
        return ArrayEnd;
      case ',':
        *token_end = start + 1;
        return ListSeparator;
      case '{':
        *token_end = start + 1;
        return ObjectBegin;
      case '}':
        *token_end = start + 1;
        return ObjectEnd;
      case ':':
        *token_end = start + 1;
        return ObjectPairSeparator;
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
      case '-':
        if (ParseNumberToken(start, end, token_end))
          return Number;
        break;
      case '"':
        if (ParseStringToken(start + 1, end, token_end))
          return StringLiteral;
        break;
    }
    return InvalidToken;
  }

  static int HexToInt(Char c) {
    if ('0' <= c && c <= '9')
      return c - '0';
    if ('A' <= c && c <= 'F')
      return c - 'A' + 10;
    if ('a' <= c && c <= 'f')
      return c - 'a' + 10;
    assert(false);  // Unreachable.
    return 0;
  }

  static bool DecodeString(const Char* start,
                           const Char* end,
                           std::vector<uint16_t>* output) {
    if (start == end)
      return true;
    if (start > end)
      return false;
    output->reserve(end - start);
    while (start < end) {
      uint16_t c = *start++;
      // If the |Char| we're dealing with is really a byte, then
      // we have utf8 here, and we need to check for multibyte characters
      // and transcode them to utf16 (either one or two utf16 chars).
      if (sizeof(Char) == sizeof(uint8_t) && c > 0x7f) {
        // Inspect the leading byte to figure out how long the utf8
        // byte sequence is; while doing this initialize |codepoint|
        // with the first few bits.
        // See table in: https://en.wikipedia.org/wiki/UTF-8
        // byte one is 110x xxxx -> 2 byte utf8 sequence
        // byte one is 1110 xxxx -> 3 byte utf8 sequence
        // byte one is 1111 0xxx -> 4 byte utf8 sequence
        uint32_t codepoint;
        int num_bytes_left;
        if ((c & 0xe0) == 0xc0) {  // 2 byte utf8 sequence
          num_bytes_left = 1;
          codepoint = c & 0x1f;
        } else if ((c & 0xf0) == 0xe0) {  // 3 byte utf8 sequence
          num_bytes_left = 2;
          codepoint = c & 0x0f;
        } else if ((c & 0xf8) == 0xf0) {  // 4 byte utf8 sequence
          codepoint = c & 0x07;
          num_bytes_left = 3;
        } else {
          return false;  // invalid leading byte
        }

        // If we have enough bytes in our inpput, decode the remaining ones
        // belonging to this Unicode character into |codepoint|.
        if (start + num_bytes_left > end)
          return false;
        while (num_bytes_left > 0) {
          c = *start++;
          --num_bytes_left;
          // Check the next byte is a continuation byte, that is 10xx xxxx.
          if ((c & 0xc0) != 0x80)
            return false;
          codepoint = (codepoint << 6) | (c & 0x3f);
        }

        // Disallow overlong encodings for ascii characters, as these
        // would include " and other characters significant to JSON
        // string termination / control.
        if (codepoint <= 0x7f)
          return false;
        // Invalid in UTF8, and can't be represented in UTF16 anyway.
        if (codepoint > 0x10ffff)
          return false;

        // So, now we transcode to UTF16,
        // using the math described at https://en.wikipedia.org/wiki/UTF-16,
        // for either one or two 16 bit characters.
        if (codepoint <= 0xffff) {
          output->push_back(codepoint);
          continue;
        }
        codepoint -= 0x10000;
        output->push_back((codepoint >> 10) + 0xd800);    // high surrogate
        output->push_back((codepoint & 0x3ff) + 0xdc00);  // low surrogate
        continue;
      }
      if ('\\' != c) {
        output->push_back(c);
        continue;
      }
      if (start == end)
        return false;
      c = *start++;

      if (c == 'x') {
        // \x is not supported.
        return false;
      }

      switch (c) {
        case '"':
        case '/':
        case '\\':
          break;
        case 'b':
          c = '\b';
          break;
        case 'f':
          c = '\f';
          break;
        case 'n':
          c = '\n';
          break;
        case 'r':
          c = '\r';
          break;
        case 't':
          c = '\t';
          break;
        case 'v':
          c = '\v';
          break;
        case 'u':
          c = (HexToInt(*start) << 12) + (HexToInt(*(start + 1)) << 8) +
              (HexToInt(*(start + 2)) << 4) + HexToInt(*(start + 3));
          start += 4;
          break;
        default:
          return false;
      }
      output->push_back(c);
    }
    return true;
  }

  void ParseValue(const Char* start,
                  const Char* end,
                  const Char** value_token_end,
                  int depth) {
    if (depth > kStackLimit) {
      HandleError(Error::JSON_PARSER_STACK_LIMIT_EXCEEDED, start);
      return;
    }
    const Char* token_start = nullptr;
    const Char* token_end = nullptr;
    Token token = ParseToken(start, end, &token_start, &token_end);
    switch (token) {
      case NoInput:
        HandleError(Error::JSON_PARSER_NO_INPUT, token_start);
        return;
      case InvalidToken:
        HandleError(Error::JSON_PARSER_INVALID_TOKEN, token_start);
        return;
      case NullToken:
        handler_->HandleNull();
        break;
      case BoolTrue:
        handler_->HandleBool(true);
        break;
      case BoolFalse:
        handler_->HandleBool(false);
        break;
      case Number: {
        double value;
        if (!CharsToDouble(token_start, token_end - token_start, &value)) {
          HandleError(Error::JSON_PARSER_INVALID_NUMBER, token_start);
          return;
        }
        if (value >= std::numeric_limits<int32_t>::min() &&
            value <= std::numeric_limits<int32_t>::max() &&
            static_cast<int32_t>(value) == value)
          handler_->HandleInt32(static_cast<int32_t>(value));
        else
          handler_->HandleDouble(value);
        break;
      }
      case StringLiteral: {
        std::vector<uint16_t> value;
        bool ok = DecodeString(token_start + 1, token_end - 1, &value);
        if (!ok) {
          HandleError(Error::JSON_PARSER_INVALID_STRING, token_start);
          return;
        }
        handler_->HandleString16(span<uint16_t>(value.data(), value.size()));
        break;
      }
      case ArrayBegin: {
        handler_->HandleArrayBegin();
        start = token_end;
        token = ParseToken(start, end, &token_start, &token_end);
        while (token != ArrayEnd) {
          ParseValue(start, end, &token_end, depth + 1);
          if (error_)
            return;

          // After a list value, we expect a comma or the end of the list.
          start = token_end;
          token = ParseToken(start, end, &token_start, &token_end);
          if (token == ListSeparator) {
            start = token_end;
            token = ParseToken(start, end, &token_start, &token_end);
            if (token == ArrayEnd) {
              HandleError(Error::JSON_PARSER_UNEXPECTED_ARRAY_END, token_start);
              return;
            }
          } else if (token != ArrayEnd) {
            // Unexpected value after list value. Bail out.
            HandleError(Error::JSON_PARSER_COMMA_OR_ARRAY_END_EXPECTED,
                        token_start);
            return;
          }
        }
        handler_->HandleArrayEnd();
        break;
      }
      case ObjectBegin: {
        handler_->HandleMapBegin();
        start = token_end;
        token = ParseToken(start, end, &token_start, &token_end);
        while (token != ObjectEnd) {
          if (token != StringLiteral) {
            HandleError(Error::JSON_PARSER_STRING_LITERAL_EXPECTED,
                        token_start);
            return;
          }
          std::vector<uint16_t> key;
          if (!DecodeString(token_start + 1, token_end - 1, &key)) {
            HandleError(Error::JSON_PARSER_INVALID_STRING, token_start);
            return;
          }
          handler_->HandleString16(span<uint16_t>(key.data(), key.size()));
          start = token_end;

          token = ParseToken(start, end, &token_start, &token_end);
          if (token != ObjectPairSeparator) {
            HandleError(Error::JSON_PARSER_COLON_EXPECTED, token_start);
            return;
          }
          start = token_end;

          ParseValue(start, end, &token_end, depth + 1);
          if (error_)
            return;
          start = token_end;

          // After a key/value pair, we expect a comma or the end of the
          // object.
          token = ParseToken(start, end, &token_start, &token_end);
          if (token == ListSeparator) {
            start = token_end;
            token = ParseToken(start, end, &token_start, &token_end);
            if (token == ObjectEnd) {
              HandleError(Error::JSON_PARSER_UNEXPECTED_MAP_END, token_start);
              return;
            }
          } else if (token != ObjectEnd) {
            // Unexpected value after last object value. Bail out.
            HandleError(Error::JSON_PARSER_COMMA_OR_MAP_END_EXPECTED,
                        token_start);
            return;
          }
        }
        handler_->HandleMapEnd();
        break;
      }

      default:
        // We got a token that's not a value.
        HandleError(Error::JSON_PARSER_VALUE_EXPECTED, token_start);
        return;
    }

    SkipWhitespaceAndComments(token_end, end, value_token_end);
  }

  void HandleError(Error error, const Char* pos) {
    assert(error != Error::OK);
    if (!error_) {
      handler_->HandleError(
          Status{error, static_cast<size_t>(pos - start_pos_)});
      error_ = true;
    }
  }

  const Char* start_pos_ = nullptr;
  bool error_ = false;
  ParserHandler* handler_;
};
}  // namespace

void ParseJSON(span<uint8_t> chars, ParserHandler* handler) {
  JsonParser<uint8_t> parser(handler);
  parser.Parse(chars.data(), chars.size());
}

void ParseJSON(span<uint16_t> chars, ParserHandler* handler) {
  JsonParser<uint16_t> parser(handler);
  parser.Parse(chars.data(), chars.size());
}

// =============================================================================
// json::ConvertCBORToJSON, json::ConvertJSONToCBOR - for transcoding
// =============================================================================
template <typename C>
Status ConvertCBORToJSONTmpl(span<uint8_t> cbor, C* json) {
  Status status;
  std::unique_ptr<ParserHandler> json_writer = NewJSONEncoder(json, &status);
  cbor::ParseCBOR(cbor, json_writer.get());
  return status;
}

Status ConvertCBORToJSON(span<uint8_t> cbor, std::vector<uint8_t>* json) {
  return ConvertCBORToJSONTmpl(cbor, json);
}

Status ConvertCBORToJSON(span<uint8_t> cbor, std::string* json) {
  return ConvertCBORToJSONTmpl(cbor, json);
}

template <typename T>
Status ConvertJSONToCBORTmpl(span<T> json, std::vector<uint8_t>* cbor) {
  Status status;
  std::unique_ptr<ParserHandler> encoder = cbor::NewCBOREncoder(cbor, &status);
  ParseJSON(json, encoder.get());
  return status;
}

Status ConvertJSONToCBOR(span<uint8_t> json, std::vector<uint8_t>* cbor) {
  return ConvertJSONToCBORTmpl(json, cbor);
}

Status ConvertJSONToCBOR(span<uint16_t> json, std::vector<uint8_t>* cbor) {
  return ConvertJSONToCBORTmpl(json, cbor);
}
}  // namespace json
}  // namespace v8_crdtp

"""

```