Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understand the Core Goal:** The file name `json.cc` and the namespace `v8_crdtp::json` strongly suggest this code deals with JSON (JavaScript Object Notation) manipulation within the V8 (JavaScript engine) context, specifically related to the Chrome DevTools Protocol (CRDP).

2. **Initial Scan for Key Components:**  Quickly read through the code, looking for structural elements and keywords that indicate functionality. Notice the presence of:
    * `#include` directives for standard libraries (`<algorithm>`, `<cassert>`, etc.) and custom headers (`"cbor.h"`, `"json_platform.h"`). This hints at dependencies and potential interactions with CBOR (Concise Binary Object Representation).
    * Namespaces (`v8_crdtp`, `json`).
    * Classes (`JSONEncoder`, `JsonParser`).
    * Enums (`Container`, `Token`).
    * Function-like entities that return unique pointers (`NewJSONEncoder`).
    * Functions starting with `Parse` and `Convert`.

3. **Focus on `JSONEncoder`:** The name clearly suggests a mechanism for *creating* JSON. Examine its methods:
    * `HandleMapBegin`, `HandleMapEnd`, `HandleArrayBegin`, `HandleArrayEnd`: These methods deal with the structural elements of JSON (objects and arrays). The stack `state_` is likely used to track the current nesting level.
    * `HandleString16`, `HandleString8`: These handle string encoding, including escaping special characters and handling UTF-8.
    * `HandleBinary`:  This suggests support for encoding binary data as Base64 within JSON.
    * `HandleDouble`, `HandleInt32`, `HandleBool`, `HandleNull`: These methods handle the encoding of primitive JSON types.
    * `HandleError`:  Indicates error handling during the encoding process.
    * The `Emit` helper functions simplify writing characters and strings to the output.

4. **Focus on `JsonParser`:**  The name implies a mechanism for *reading* JSON. Look at its methods:
    * `Parse`: The main entry point for parsing a JSON string.
    * `ParseValue`: A recursive function for parsing different JSON value types.
    * Helper functions like `ParseToken`, `ParseConstToken`, `ParseNumberToken`, `ParseStringToken`: These break down the JSON input into meaningful units (tokens).
    * `DecodeString`: Handles decoding escaped characters and UTF-8 within JSON strings.
    * `HandleError`: Reports errors during parsing.

5. **Analyze the `Convert` Functions:**  The names `ConvertCBORToJSON` and `ConvertJSONToCBOR` strongly suggest the code provides functionality to transcode between these two data formats. Notice they use the `JSONEncoder` and (presumably) a `CBOREncoder` (from `cbor.h`) along with the `ParseJSON` and `ParseCBOR` functions. This points to the core functionality of the file: JSON serialization and deserialization, with the ability to interact with CBOR.

6. **Infer Relationships with JavaScript:**  The namespace `v8_crdtp` is the crucial link to JavaScript. V8 is Google's JavaScript engine. The "inspector protocol" (CRDP) is used for debugging and inspecting JavaScript execution in environments like Chrome. Therefore, the JSON functionality here is likely used to:
    * **Serialize JavaScript data:** Convert JavaScript objects and arrays into JSON strings for transmission over the debugging protocol.
    * **Deserialize JSON data:**  Convert JSON strings received from the debugger back into native C++ data structures, potentially mirroring JavaScript data structures.

7. **Structure the Summary:** Organize the findings into a clear and concise summary, highlighting the key functionalities: JSON encoding, JSON parsing, and CBOR conversion. Mention the relationship with V8 and CRDP.

8. **Construct the JavaScript Example:**  Think about common scenarios where JSON is used in JavaScript. The most obvious is representing data structures. Create a simple JavaScript object that would correspond to the kind of data this C++ code might be handling. Then, show how `JSON.stringify()` would be used to serialize it and `JSON.parse()` to deserialize it, mirroring the encoding and parsing roles of the C++ code. The key is to demonstrate the *conceptual* correspondence, even though the internal implementation in C++ is different.

9. **Refine and Review:** Read through the summary and example to ensure clarity, accuracy, and completeness. Check for any technical terms that might need explanation. Make sure the JavaScript example clearly illustrates the connection to the C++ functionality. For instance, mentioning how the C++ code might be used *within* the V8 engine when the debugger interacts with the JavaScript code makes the link explicit.

This iterative process of scanning, analyzing specific components, inferring relationships, and then structuring the information allows for a comprehensive understanding of the code's functionality and its relevance to JavaScript.这个C++源代码文件 `json.cc` 的主要功能是 **提供 JSON 的编码和解析功能，并支持与 CBOR (Concise Binary Object Representation) 格式的相互转换**。  它被设计用于 V8 引擎的 Chrome DevTools Protocol (CRDP) 中，用于在 C++ 和 JavaScript 之间传递结构化数据。

更具体地说，它包含以下几个核心部分：

**1. JSON 编码器 (JSON Encoder):**

*   **功能:** 将各种 C++ 数据类型（如字符串、数字、布尔值、数组、对象）编码成 JSON 字符串。
*   **实现:**  `JSONEncoder` 类实现了 `ParserHandler` 接口，这意味着它可以作为 JSON 解析器事件的接收者，并将这些事件转换为 JSON 输出。这是一种流式编码的方式，可以逐步生成 JSON，而不需要一次性构建整个 JSON 结构。
*   **特点:**
    *   处理字符串的转义，包括 Unicode 字符。
    *   处理数字的特殊情况，例如 NaN 和 Infinity，将其转换为 "null"。
    *   支持将二进制数据编码为 Base64 字符串。
    *   使用栈来维护 JSON 结构的层级关系，确保输出的 JSON 格式正确。

**2. JSON 解析器 (JSON Parser):**

*   **功能:** 将 JSON 字符串解析成 C++ 可以理解的数据结构，并触发 `ParserHandler` 接口的回调函数。
*   **实现:** `JsonParser` 类负责读取 JSON 字符串，识别不同的 JSON 标记（如 `[`, `{`, `}`, `]`, `"`, 数字等），并根据这些标记来触发 `ParserHandler` 接口中相应的方法。
*   **特点:**
    *   支持 UTF-8 和 UTF-16 编码的 JSON 字符串。
    *   处理 JSON 中的注释 (`//` 和 `/* ... */`)。
    *   进行严格的 JSON 语法检查，并在遇到错误时报告。
    *   限制解析的深度，防止栈溢出。

**3. CBOR 与 JSON 的转换器 (CBOR/JSON Converter):**

*   **功能:** 提供将 CBOR 数据转换为 JSON 字符串，以及将 JSON 数据转换为 CBOR 的功能。
*   **实现:**  `ConvertCBORToJSON` 函数使用 CBOR 解析器将 CBOR 数据解析成事件，然后使用 `JSONEncoder` 将这些事件编码成 JSON。`ConvertJSONToCBOR` 函数则相反，使用 JSON 解析器解析 JSON 数据，然后使用 CBOR 编码器（在 `cbor.h` 中定义）将事件编码成 CBOR。

**它与 JavaScript 的功能关系:**

这个文件在 V8 引擎的上下文中，直接服务于与 JavaScript 的交互，尤其是在 Chrome DevTools Protocol (CRDP) 中。

*   **CRDP 通信:**  Chrome 开发者工具使用 CRDP 与浏览器中的 JavaScript 引擎进行通信。这些通信通常使用 JSON 格式来表示请求和响应。
*   **JavaScript 对象的序列化:** 当需要将 JavaScript 对象发送到 C++ 端（例如，通过 CRDP 发送调试信息）时，V8 引擎会使用这里的 JSON 编码器将 JavaScript 对象序列化成 JSON 字符串。
*   **JSON 的反序列化为 JavaScript 对象:** 当 C++ 端通过 CRDP 发送 JSON 数据到 JavaScript 端时，JavaScript 引擎会使用内置的 JSON 解析器（`JSON.parse()`）将 JSON 字符串反序列化成 JavaScript 对象。

**JavaScript 举例说明:**

假设在 JavaScript 中有以下一个对象：

```javascript
const myObject = {
  name: "示例",
  age: 30,
  hobbies: ["编程", "阅读"],
  address: {
    city: "北京",
    zip: 100000
  }
};
```

当需要将这个 `myObject` 发送到 C++ 端（例如，通过 CRDP），V8 引擎内部会使用类似 `json.cc` 中实现的 JSON 编码器，将其转换为如下的 JSON 字符串：

```json
{
  "name": "示例",
  "age": 30,
  "hobbies": [
    "编程",
    "阅读"
  ],
  "address": {
    "city": "北京",
    "zip": 100000
  }
}
```

反之，如果 C++ 端构建了一个表示某些信息的 JSON 字符串，并通过 CRDP 发送给 JavaScript，JavaScript 代码可以使用 `JSON.parse()` 将其解析为 JavaScript 对象：

```javascript
const jsonStringFromCpp = `{ "status": "ok", "message": "数据已收到" }`;
const parsedObject = JSON.parse(jsonStringFromCpp);
console.log(parsedObject.status); // 输出: ok
console.log(parsedObject.message); // 输出: 数据已收到
```

**CBOR 的作用:**

CBOR 是一种二进制的 JSON 替代品，通常用于需要更高效的数据传输或存储的场景。`json.cc` 中提供的 CBOR 转换功能使得 V8 引擎可以在需要时使用 CBOR 进行数据交换，例如，在某些内部优化或特定协议中。JavaScript 本身没有内置的 CBOR 支持，通常需要使用第三方库来处理 CBOR 数据。

**总结:**

`v8/third_party/inspector_protocol/crdtp/json.cc` 文件是 V8 引擎中处理 JSON 数据序列化和反序列化的关键组件，它使得 C++ 和 JavaScript 之间能够有效地交换结构化数据，这对于 Chrome 开发者工具的正常运作至关重要。它还提供了与 CBOR 格式的转换能力，以满足不同的数据交换需求。

### 提示词
```
这是目录为v8/third_party/inspector_protocol/crdtp/json.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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
```