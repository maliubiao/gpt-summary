Response:
My thinking process to analyze the `json_parser.cc` file goes like this:

1. **Understand the Core Purpose:** The file name `json_parser.cc` immediately tells me this code is responsible for parsing JSON (JavaScript Object Notation) data. This is the central function.

2. **Identify Key Data Structures:**  I scan the includes and the code itself for important classes and enums. I see:
    * `JSONValue`, `JSONObject`, `JSONArray`, `JSONBasicValue`, `JSONString`: These represent the parsed JSON data structure. They're the output of the parser.
    * `JSONParseErrorType`, `JSONParseError`: These structures handle error reporting during parsing.
    * `JSONCommentState`: This enum indicates whether comments are allowed and if they were present in the input.
    * `Cursor`: This struct keeps track of the current position in the input string during parsing.
    * `Token`:  This enum represents the basic building blocks of JSON syntax (like `{`, `[`, `"`, numbers, etc.).

3. **Trace the Parsing Process (High-Level):** I look for the main entry points. `ParseJSON` is clearly a public function. I see variations like `ParseJSONWithCommentsDeprecated`. I then look inside these functions to see how they initiate the parsing. I see calls to the internal `ParseJSONInternal` template function. This suggests the core parsing logic is templatized to handle both 8-bit and 16-bit character strings.

4. **Delve into the Parsing Logic (Mid-Level):**  I examine the `ParseJSONInternal` function. It creates a `Cursor` and calls `BuildValue`. This suggests `BuildValue` is the core recursive function that actually constructs the `JSONValue` tree.

5. **Analyze the `BuildValue` Function (Detailed):**  This is where the grammar of JSON is implemented. I see it:
    * Calls `ParseToken` to get the next syntactic element.
    * Uses a `switch` statement based on the `Token` to determine how to handle different JSON constructs (null, booleans, numbers, strings, arrays, objects).
    * Recursively calls `BuildValue` for nested arrays and objects.
    * Uses `DecodeString` to handle escape sequences in strings.

6. **Examine Helper Functions:**  I look at functions called by `BuildValue` and other core functions:
    * `ParseToken`: Skips whitespace and comments, identifies the next token.
    * `ParseConstToken`: Checks for literal tokens like "true", "false", "null".
    * `ParseNumberToken`:  Identifies a sequence of characters that form a number.
    * `ReadInt`, `ReadHexDigits`: Helpers for parsing numbers and escape sequences.
    * `SkipWhitespaceAndComments`, `SkipComment`: Handle whitespace and comments (if allowed).
    * `DecodeString`:  Handles the decoding of string literals, including escape sequences and UTF-8 validation.
    * `FormatErrorMessage`: Creates a user-friendly error message.

7. **Identify Relationships to Web Technologies:**  JSON is fundamental to web development. I connect the functionality to:
    * **JavaScript:** JSON is a subset of JavaScript syntax. The parser allows Blink to process JSON data often used for configuration, data exchange with servers (AJAX), and web APIs.
    * **HTML:** While HTML itself doesn't directly *use* JSON, JavaScript running in an HTML page frequently parses JSON received from the server. Configuration within HTML (like `<script type="application/json">`) might also be processed.
    * **CSS:** CSS doesn't directly involve JSON, so I note the lack of a direct relationship.

8. **Infer Logic and Examples:** Based on the code, I can infer how different JSON structures would be parsed and what errors would be generated. For instance:
    * Input `{"key": "value"}` will be parsed into a `JSONObject` with a key-value pair.
    * Input `[1, 2, 3]` will be parsed into a `JSONArray` with three numeric values.
    * Invalid JSON like `{"key": }` will result in a `kUnexpectedToken` error.

9. **Consider Common Errors:** I think about the kinds of mistakes developers might make when dealing with JSON, and how this parser might handle them:
    * Syntax errors (missing commas, colons, quotes).
    * Invalid escape sequences.
    * Too much nesting.
    * Unexpected data after the root element.
    * Incorrect encoding.
    * Duplicate keys (the parser flags these).

10. **Structure the Output:** I organize my findings into logical sections: Functionality, Relationships to Web Technologies, Logic and Examples, Common Usage Errors. I use clear and concise language, providing specific code snippets or examples where helpful. I also explicitly state my reasoning for each point.

By following this systematic approach, I can thoroughly analyze the code and extract the relevant information to answer the prompt effectively. The key is to start with the big picture and gradually drill down into the details, understanding the purpose of each component and how they work together.
这个 `json_parser.cc` 文件是 Chromium Blink 引擎中负责解析 JSON (JavaScript Object Notation) 数据的核心组件。它的主要功能是将 JSON 格式的文本转换为 Blink 引擎内部可以理解和操作的数据结构，例如 `JSONObject` 和 `JSONArray`。

以下是它的详细功能列表，以及与 JavaScript、HTML、CSS 的关系和使用错误的示例：

**文件功能:**

1. **JSON 解析:**  这是该文件的核心功能。它接收一个字符串形式的 JSON 数据，并将其解析成一个 `JSONValue` 类型的对象。`JSONValue` 可以是 `JSONObject`（JSON 对象），`JSONArray`（JSON 数组），`JSONBasicValue`（基本类型如数字、布尔值、null）或 `JSONString`（字符串）。

2. **错误处理:**  当输入的 JSON 字符串格式不正确时，解析器能够检测到错误并返回 `JSONParseError` 结构体，其中包含了错误类型 (`JSONParseErrorType`)、发生错误的行号和列号，以及错误消息。

3. **支持不同的字符编码:**  代码中可以看到对 8-bit 和 16-bit 字符的处理，这意味着它可以解析不同编码的 JSON 字符串。

4. **处理 JSON 注释 (可选):**  文件中包含 `JSONCommentState`，并且有 `ParseJSONWithCommentsDeprecated` 函数，这表明该解析器可能支持解析包含注释的 JSON（尽管被标记为 deprecated，可能为了兼容旧代码或者允许特定场景下使用）。

5. **限制解析深度:**  `kMaxStackLimit` 常量和 `max_depth` 参数用于防止因 JSON 嵌套过深而导致的栈溢出。

6. **检测重复的键:**  在解析 JSON 对象时，解析器会检测重复的键，并将它们添加到 `JSONParseError` 的 `duplicate_keys` 列表中。

**与 JavaScript, HTML, CSS 的关系:**

* **与 JavaScript 的关系非常密切:**
    * **核心数据格式:** JSON 是 JavaScript 的一个子集，广泛用于 JavaScript 中表示数据。该解析器的主要目的是让 Blink 引擎能够理解和操作 JavaScript 代码中或者从服务器接收到的 JSON 数据。
    * **`JSON.parse()` 的底层实现:**  在浏览器中，JavaScript 的内置函数 `JSON.parse()` 的底层实现很可能就依赖于类似的 C++ JSON 解析器。当 JavaScript 代码调用 `JSON.parse()` 时，Blink 引擎会使用这个 `json_parser.cc` 文件中的逻辑来解析 JSON 字符串。

    **举例说明:**
    ```javascript
    // JavaScript 代码
    const jsonString = '{"name": "Alice", "age": 30}';
    const jsonObject = JSON.parse(jsonString);
    console.log(jsonObject.name); // 输出 "Alice"
    ```
    在这个例子中，当 JavaScript 引擎执行 `JSON.parse(jsonString)` 时，Blink 引擎的 JSON 解析器（如 `json_parser.cc`）会被调用，将 `jsonString` 解析成一个 JavaScript 对象。

* **与 HTML 的关系:**
    * **通过 `<script>` 标签传递 JSON 数据:**  HTML 中可以使用 `<script type="application/json">` 标签来嵌入 JSON 数据。JavaScript 代码可以获取这个标签的内容，并使用 `JSON.parse()` 来解析。

    **举例说明:**
    ```html
    <!-- HTML 代码 -->
    <script type="application/json" id="config">
    {
      "api_url": "https://example.com/api",
      "theme": "dark"
    }
    </script>
    <script>
      const configElement = document.getElementById('config');
      const configData = JSON.parse(configElement.textContent);
      console.log(configData.api_url); // 输出 "https://example.com/api"
    </script>
    ```
    在这个例子中，HTML 中的 JSON 数据被 JavaScript 代码获取并使用 `JSON.parse()` 解析，而 `JSON.parse()` 的底层实现就依赖于 `json_parser.cc`。

* **与 CSS 的关系:**
    * **间接关系，通过 JavaScript:** CSS 本身不直接处理 JSON 数据。然而，JavaScript 代码可能会从服务器获取 JSON 数据，然后根据这些数据动态地修改 CSS 样式。

    **举例说明:**
    假设服务器返回一个包含用户主题设置的 JSON：
    ```json
    {
      "background_color": "#f0f0f0",
      "text_color": "#333"
    }
    ```
    JavaScript 代码可以解析这个 JSON，并动态地更新页面的 CSS：
    ```javascript
    // JavaScript 代码
    fetch('/user/theme')
      .then(response => response.json()) // response.json() 内部使用了 JSON 解析
      .then(theme => {
        document.body.style.backgroundColor = theme.background_color;
        document.body.style.color = theme.text_color;
      });
    ```
    在这个例子中，`response.json()` 方法内部会调用 JSON 解析器来处理服务器返回的 JSON 数据，从而间接地影响了页面的 CSS 样式。

**逻辑推理的假设输入与输出:**

**假设输入 1:**
```json
{
  "name": "Bob",
  "age": 25,
  "address": {
    "street": "Main St",
    "city": "Anytown"
  },
  "hobbies": ["reading", "coding"]
}
```

**假设输出 1:**
一个 `JSONObject` 对象，包含以下键值对：
* "name": `JSONString` ("Bob")
* "age": `JSONBasicValue` (25)
* "address": 一个嵌套的 `JSONObject` 对象，包含 "street" 和 "city" 键值对。
* "hobbies": 一个 `JSONArray` 对象，包含 "reading" 和 "coding" 两个 `JSONString` 对象。

**假设输入 2 (包含注释，假设 `JSONCommentState` 允许):**
```json
{
  "name": "Charlie", // 姓名
  "age": 35 /* 年龄 */
}
```

**假设输出 2:**
一个 `JSONObject` 对象，包含 "name" 和 "age" 键值对。注释会被忽略。

**假设输入 3 (语法错误):**
```json
{
  "name": "David",
  "age": 40,
}  // 缺少 "age" 对应的值
```

**假设输出 3:**
`JSONParseError` 对象，`type` 为 `Error::kUnexpectedToken` 或 `Error::kSyntaxError`，`line` 和 `column` 指向错误发生的位置（可能在逗号后面）。`result` 为 `nullptr`。

**涉及用户或者编程常见的使用错误:**

1. **语法错误:**  这是最常见的错误。例如，忘记添加引号、逗号或冒号，或者括号不匹配。

    **举例:**
    ```javascript
    const invalidJSON = '{name: "Eve", age: 28}'; // 键名缺少引号
    // JSON.parse(invalidJSON); // 会抛出 SyntaxError
    ```
    `json_parser.cc` 会返回 `Error::kSyntaxError`。

2. **无效的转义字符:**  JSON 字符串中只允许特定的转义字符。使用未定义的转义字符会导致解析错误。

    **举例:**
    ```javascript
    const invalidEscapeJSON = '{"path": "C:\MyDocuments"}'; // 反斜杠需要转义
    // JSON.parse(invalidEscapeJSON); // 会抛出 SyntaxError
    ```
    `json_parser.cc` 会返回 `Error::kInvalidEscape`。

3. **过深的嵌套:**  JSON 结构如果嵌套得太深，可能会导致解析器栈溢出。`kMaxStackLimit` 的存在就是为了防止这种情况。

    **举例:**
    ```javascript
    // 创建一个深度嵌套的 JSON 对象
    let deeplyNested = {};
    let current = deeplyNested;
    for (let i = 0; i < 10000; i++) {
      current.child = {};
      current = current.child;
    }
    const deeplyNestedJSON = JSON.stringify(deeplyNested);
    // JSON.parse(deeplyNestedJSON); // 可能导致错误
    ```
    `json_parser.cc` 会返回 `Error::kTooMuchNesting`。

4. **JSON 中包含 JavaScript 代码:**  JSON 是一种数据交换格式，不应该包含可执行的 JavaScript 代码。尝试解析包含 JavaScript 代码的字符串会导致解析错误。

    **举例:**
    ```javascript
    const maliciousJSON = '{"data": "<script>alert(\'hacked\')</script>"}';
    // JSON.parse(maliciousJSON); // 解析成功，但数据本身可能存在安全风险
    ```
    虽然 `json_parser.cc` 可以解析这个 JSON 字符串，但将解析后的数据直接插入到 HTML 中可能会导致 XSS 攻击。这不是解析器本身的错误，而是使用方式的错误。

5. **处理非 UTF-8 编码的 JSON (如果不支持):**  虽然代码中看起来支持不同的字符编码，但如果 JSON 数据使用了不支持的编码，解析可能会失败。

    **举例:**  如果输入的 JSON 是使用某种特殊的单字节编码，并且解析器没有正确处理，可能会导致解析错误。`json_parser.cc` 会返回 `Error::kUnsupportedEncoding`。

6. **意外的根元素后的数据:** JSON 文档应该只有一个根元素（对象或数组）。如果在根元素之后还有其他数据，解析器会报错。

    **举例:**
    ```json
    {"key": "value"} extra data
    ```
    `json_parser.cc` 会返回 `Error::kUnexpectedDataAfterRoot`。

理解 `json_parser.cc` 的功能对于理解 Blink 引擎如何处理 Web 页面中的数据至关重要，特别是当涉及到与服务器进行数据交互时。

Prompt: 
```
这是目录为blink/renderer/platform/json/json_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "base/memory/raw_ptr.h"
#include "base/notreached.h"
#include "base/numerics/safe_conversions.h"
#include "third_party/blink/renderer/platform/json/json_values.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_to_number.h"

namespace blink {

namespace {

const int kMaxStackLimit = 1000;

using Error = JSONParseErrorType;

String FormatErrorMessage(Error error, int line, int column) {
  String text;
  switch (error) {
    case Error::kNoError:
      NOTREACHED();
    case Error::kUnexpectedToken:
      text = "Unexpected token.";
      break;
    case Error::kSyntaxError:
      text = "Syntax error.";
      break;
    case Error::kInvalidEscape:
      text = "Invalid escape sequence.";
      break;
    case Error::kTooMuchNesting:
      text = "Too much nesting.";
      break;
    case Error::kUnexpectedDataAfterRoot:
      text = "Unexpected data after root element.";
      break;
    case Error::kUnsupportedEncoding:
      text =
          "Unsupported encoding. JSON and all string literals must contain "
          "valid Unicode characters.";
      break;
  }
  return "Line: " + String::Number(line) +
         ", column: " + String::Number(column) + ", " + text;
}

// Note: all parsing functions take a |cursor| parameter which is
// where they start parsing from.
// If the parsing succeeds, |cursor| will point to the position
// right after the parsed value, "consuming" some portion of the input.
// If the parsing fails, |cursor| will point to the error position.

template <typename CharType>
struct Cursor {
  int line;
  raw_ptr<const CharType, AllowPtrArithmetic> line_start;
  raw_ptr<const CharType, AllowPtrArithmetic> pos;
};

enum Token {
  kObjectBegin,
  kObjectEnd,
  kArrayBegin,
  kArrayEnd,
  kStringLiteral,
  kNumber,
  kBoolTrue,
  kBoolFalse,
  kNullToken,
  kListSeparator,
  kObjectPairSeparator,
};

template <typename CharType>
Error ParseConstToken(Cursor<CharType>* cursor,
                      const CharType* end,
                      const char* token) {
  const CharType* token_start = cursor->pos;
  while (cursor->pos < end && *token != '\0' && *(cursor->pos++) == *token++) {
  }
  if (*token != '\0') {
    cursor->pos = token_start;
    return Error::kSyntaxError;
  }
  return Error::kNoError;
}

template <typename CharType>
Error ReadInt(Cursor<CharType>* cursor,
              const CharType* end,
              bool can_have_leading_zeros) {
  if (cursor->pos == end)
    return Error::kSyntaxError;
  const CharType* start_ptr = cursor->pos;
  bool have_leading_zero = '0' == *(cursor->pos);
  int length = 0;
  while (cursor->pos < end && '0' <= *(cursor->pos) && *(cursor->pos) <= '9') {
    ++(cursor->pos);
    ++length;
  }
  if (!length)
    return Error::kSyntaxError;
  if (!can_have_leading_zeros && length > 1 && have_leading_zero) {
    cursor->pos = start_ptr + 1;
    return Error::kSyntaxError;
  }
  return Error::kNoError;
}

template <typename CharType>
Error ParseNumberToken(Cursor<CharType>* cursor, const CharType* end) {
  // We just grab the number here. We validate the size in DecodeNumber.
  // According to RFC4627, a valid number is: [minus] int [frac] [exp]
  if (cursor->pos == end)
    return Error::kSyntaxError;
  if (*(cursor->pos) == '-')
    ++(cursor->pos);

  Error error = ReadInt(cursor, end, false);
  if (error != Error::kNoError)
    return error;

  if (cursor->pos == end)
    return Error::kNoError;

  // Optional fraction part
  CharType c = *(cursor->pos);
  if ('.' == c) {
    ++(cursor->pos);
    error = ReadInt(cursor, end, true);
    if (error != Error::kNoError)
      return error;
    if (cursor->pos == end)
      return Error::kNoError;
    c = *(cursor->pos);
  }

  // Optional exponent part
  if ('e' == c || 'E' == c) {
    ++(cursor->pos);
    if (cursor->pos == end)
      return Error::kSyntaxError;
    c = *(cursor->pos);
    if ('-' == c || '+' == c) {
      ++(cursor->pos);
      if (cursor->pos == end)
        return Error::kSyntaxError;
    }
    error = ReadInt(cursor, end, true);
    if (error != Error::kNoError)
      return error;
  }

  return Error::kNoError;
}

template <typename CharType>
Error ReadHexDigits(Cursor<CharType>* cursor, const CharType* end, int digits) {
  const CharType* token_start = cursor->pos;
  if (end - cursor->pos < digits)
    return Error::kInvalidEscape;
  for (int i = 0; i < digits; ++i) {
    CharType c = *(cursor->pos)++;
    if (!(('0' <= c && c <= '9') || ('a' <= c && c <= 'f') ||
          ('A' <= c && c <= 'F'))) {
      cursor->pos = token_start;
      return Error::kInvalidEscape;
    }
  }
  return Error::kNoError;
}

template <typename CharType>
Error ParseStringToken(Cursor<CharType>* cursor, const CharType* end) {
  if (cursor->pos == end)
    return Error::kSyntaxError;
  if (*(cursor->pos) != '"')
    return Error::kSyntaxError;
  ++(cursor->pos);
  while (cursor->pos < end) {
    CharType c = *(cursor->pos)++;
    if ('\\' == c) {
      if (cursor->pos == end)
        return Error::kInvalidEscape;
      c = *(cursor->pos)++;
      // Make sure the escaped char is valid.
      switch (c) {
        case 'x': {
          Error error = ReadHexDigits(cursor, end, 2);
          if (error != Error::kNoError)
            return error;
          break;
        }
        case 'u': {
          Error error = ReadHexDigits(cursor, end, 4);
          if (error != Error::kNoError)
            return error;
          break;
        }
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
          return Error::kInvalidEscape;
      }
    } else if (c < 0x20) {
      return Error::kSyntaxError;
    } else if ('"' == c) {
      return Error::kNoError;
    }
  }
  return Error::kSyntaxError;
}

template <typename CharType>
Error SkipComment(Cursor<CharType>* cursor, const CharType* end) {
  const CharType* pos = cursor->pos;
  if (pos == end)
    return Error::kSyntaxError;

  if (*pos != '/' || pos + 1 >= end)
    return Error::kSyntaxError;
  ++pos;

  if (*pos == '/') {
    // Single line comment, read to newline.
    for (++pos; pos < end; ++pos) {
      if (*pos == '\n') {
        cursor->line++;
        cursor->pos = pos + 1;
        cursor->line_start = cursor->pos;
        return Error::kNoError;
      }
    }
    cursor->pos = end;
    // Comment reaches end-of-input, which is fine.
    return Error::kNoError;
  }

  if (*pos == '*') {
    CharType previous = '\0';
    // Block comment, read until end marker.
    for (++pos; pos < end; previous = *pos++) {
      if (*pos == '\n') {
        cursor->line++;
        cursor->line_start = pos + 1;
      }
      if (previous == '*' && *pos == '/') {
        cursor->pos = pos + 1;
        return Error::kNoError;
      }
    }
    // Block comment must close before end-of-input.
    return Error::kSyntaxError;
  }

  return Error::kSyntaxError;
}

template <typename CharType>
Error SkipWhitespaceAndComments(Cursor<CharType>* cursor,
                                const CharType* end,
                                JSONCommentState& comment_state) {
  while (cursor->pos < end) {
    CharType c = *(cursor->pos);
    if (c == '\n') {
      cursor->line++;
      ++(cursor->pos);
      cursor->line_start = cursor->pos;
    } else if (c == ' ' || c == '\r' || c == '\t') {
      ++(cursor->pos);
    } else if (c == '/' && comment_state != JSONCommentState::kDisallowed) {
      comment_state = JSONCommentState::kAllowedAndPresent;
      Error error = SkipComment(cursor, end);
      if (error != Error::kNoError)
        return error;
    } else {
      break;
    }
  }
  return Error::kNoError;
}

template <typename CharType>
Error ParseToken(Cursor<CharType>* cursor,
                 const CharType* end,
                 Token* token,
                 Cursor<CharType>* token_start,
                 JSONCommentState& comment_state) {
  Error error = SkipWhitespaceAndComments(cursor, end, comment_state);
  if (error != Error::kNoError)
    return error;
  *token_start = *cursor;

  if (cursor->pos == end)
    return Error::kSyntaxError;

  switch (*(cursor->pos)) {
    case 'n':
      *token = kNullToken;
      return ParseConstToken(cursor, end, kJSONNullString);
    case 't':
      *token = kBoolTrue;
      return ParseConstToken(cursor, end, kJSONTrueString);
    case 'f':
      *token = kBoolFalse;
      return ParseConstToken(cursor, end, kJSONFalseString);
    case '[':
      ++(cursor->pos);
      *token = kArrayBegin;
      return Error::kNoError;
    case ']':
      ++(cursor->pos);
      *token = kArrayEnd;
      return Error::kNoError;
    case ',':
      ++(cursor->pos);
      *token = kListSeparator;
      return Error::kNoError;
    case '{':
      ++(cursor->pos);
      *token = kObjectBegin;
      return Error::kNoError;
    case '}':
      ++(cursor->pos);
      *token = kObjectEnd;
      return Error::kNoError;
    case ':':
      ++(cursor->pos);
      *token = kObjectPairSeparator;
      return Error::kNoError;
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
      *token = kNumber;
      return ParseNumberToken(cursor, end);
    case '"':
      *token = kStringLiteral;
      return ParseStringToken(cursor, end);
  }

  return Error::kSyntaxError;
}

template <typename CharType>
inline int HexToInt(CharType c) {
  if ('0' <= c && c <= '9')
    return c - '0';
  if ('A' <= c && c <= 'F')
    return c - 'A' + 10;
  if ('a' <= c && c <= 'f')
    return c - 'a' + 10;
  NOTREACHED();
}

template <typename CharType>
Error DecodeString(Cursor<CharType>* cursor,
                   const CharType* end,
                   String* output) {
  if (cursor->pos + 1 > end - 1)
    return Error::kSyntaxError;
  if (cursor->pos + 1 == end - 1) {
    *output = "";
    return Error::kNoError;
  }

  const CharType* string_start = cursor->pos;
  StringBuilder buffer;
  buffer.ReserveCapacity(static_cast<wtf_size_t>(end - cursor->pos - 2));

  cursor->pos++;
  while (cursor->pos < end - 1) {
    UChar c = *(cursor->pos)++;
    if (c == '\n') {
      cursor->line++;
      cursor->line_start = cursor->pos;
    }
    if ('\\' != c) {
      buffer.Append(c);
      continue;
    }
    if (cursor->pos == end - 1)
      return Error::kInvalidEscape;
    c = *(cursor->pos)++;

    if (c == 'x') {
      // \x is not supported.
      return Error::kInvalidEscape;
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
        c = (HexToInt(*(cursor->pos)) << 12) +
            (HexToInt(*(cursor->pos + 1)) << 8) +
            (HexToInt(*(cursor->pos + 2)) << 4) + HexToInt(*(cursor->pos + 3));
        cursor->pos += 4;
        break;
      default:
        return Error::kInvalidEscape;
    }
    buffer.Append(c);
  }
  *output = buffer.ToString();

  // Validate constructed utf16 string.
  if (output->Utf8(kStrictUTF8Conversion).empty()) {
    cursor->pos = string_start;
    return Error::kUnsupportedEncoding;
  }
  return Error::kNoError;
}

template <typename CharType>
Error BuildValue(Cursor<CharType>* cursor,
                 const CharType* end,
                 int max_depth,
                 JSONCommentState& comment_state,
                 std::unique_ptr<JSONValue>* result,
                 Vector<String>* duplicate_keys) {
  if (max_depth == 0)
    return Error::kTooMuchNesting;

  Cursor<CharType> token_start;
  Token token;
  Error error = ParseToken(cursor, end, &token, &token_start, comment_state);
  if (error != Error::kNoError)
    return error;

  switch (token) {
    case kNullToken:
      *result = JSONValue::Null();
      break;
    case kBoolTrue:
      *result = std::make_unique<JSONBasicValue>(true);
      break;
    case kBoolFalse:
      *result = std::make_unique<JSONBasicValue>(false);
      break;
    case kNumber: {
      bool ok;
      double value = CharactersToDouble(
          base::span<const CharType>(
              token_start.pos.get(),
              static_cast<size_t>(cursor->pos - token_start.pos)),
          &ok);
      if (!ok || std::isinf(value)) {
        *cursor = token_start;
        return Error::kSyntaxError;
      }
      if (base::IsValueInRangeForNumericType<int>(value) &&
          static_cast<int>(value) == value)
        *result = std::make_unique<JSONBasicValue>(static_cast<int>(value));
      else
        *result = std::make_unique<JSONBasicValue>(value);
      break;
    }
    case kStringLiteral: {
      String value;
      error = DecodeString(&token_start, cursor->pos.get(), &value);
      if (error != Error::kNoError) {
        *cursor = token_start;
        return error;
      }
      *result = std::make_unique<JSONString>(value);
      break;
    }
    case kArrayBegin: {
      auto array = std::make_unique<JSONArray>();
      Cursor<CharType> before_token = *cursor;
      error = ParseToken(cursor, end, &token, &token_start, comment_state);
      if (error != Error::kNoError)
        return error;
      while (token != kArrayEnd) {
        *cursor = before_token;
        std::unique_ptr<JSONValue> array_node;
        error = BuildValue(cursor, end, max_depth - 1, comment_state,
                           &array_node, duplicate_keys);
        if (error != Error::kNoError)
          return error;
        array->PushValue(std::move(array_node));

        // After a list value, we expect a comma or the end of the list.
        error = ParseToken(cursor, end, &token, &token_start, comment_state);
        if (error != Error::kNoError)
          return error;
        if (token == kListSeparator) {
          before_token = *cursor;
          error = ParseToken(cursor, end, &token, &token_start, comment_state);
          if (error != Error::kNoError)
            return error;
          if (token == kArrayEnd) {
            *cursor = token_start;
            return Error::kUnexpectedToken;
          }
        } else if (token != kArrayEnd) {
          // Unexpected value after list value. Bail out.
          *cursor = token_start;
          return Error::kUnexpectedToken;
        }
      }
      if (token != kArrayEnd) {
        *cursor = token_start;
        return Error::kUnexpectedToken;
      }
      *result = std::move(array);
      break;
    }
    case kObjectBegin: {
      auto object = std::make_unique<JSONObject>();
      error = ParseToken(cursor, end, &token, &token_start, comment_state);
      if (error != Error::kNoError)
        return error;
      while (token != kObjectEnd) {
        if (token != kStringLiteral) {
          *cursor = token_start;
          return Error::kUnexpectedToken;
        }
        String key;
        error = DecodeString(&token_start, cursor->pos.get(), &key);
        if (error != Error::kNoError) {
          *cursor = token_start;
          return error;
        }

        error = ParseToken(cursor, end, &token, &token_start, comment_state);
        if (token != kObjectPairSeparator) {
          *cursor = token_start;
          return Error::kUnexpectedToken;
        }

        std::unique_ptr<JSONValue> value;
        error = BuildValue(cursor, end, max_depth - 1, comment_state, &value,
                           duplicate_keys);
        if (error != Error::kNoError)
          return error;
        if (!object->SetValue(key, std::move(value)) &&
            !duplicate_keys->Contains(key)) {
          duplicate_keys->push_back(key);
        }

        // After a key/value pair, we expect a comma or the end of the
        // object.
        error = ParseToken(cursor, end, &token, &token_start, comment_state);
        if (error != Error::kNoError)
          return error;
        if (token == kListSeparator) {
          error = ParseToken(cursor, end, &token, &token_start, comment_state);
          if (error != Error::kNoError)
            return error;
          if (token == kObjectEnd) {
            *cursor = token_start;
            return Error::kUnexpectedToken;
          }
        } else if (token != kObjectEnd) {
          // Unexpected value after last object value. Bail out.
          *cursor = token_start;
          return Error::kUnexpectedToken;
        }
      }
      if (token != kObjectEnd) {
        *cursor = token_start;
        return Error::kUnexpectedToken;
      }
      *result = std::move(object);
      break;
    }

    default:
      // We got a token that's not a value.
      *cursor = token_start;
      return Error::kUnexpectedToken;
  }

  return SkipWhitespaceAndComments(cursor, end, comment_state);
}

template <typename CharType>
JSONParseError ParseJSONInternal(const CharType* start_ptr,
                                 unsigned length,
                                 int max_depth,
                                 JSONCommentState& comment_state,
                                 std::unique_ptr<JSONValue>* result) {
  Cursor<CharType> cursor;
  cursor.pos = start_ptr;
  cursor.line = 0;
  cursor.line_start = start_ptr;
  const CharType* end = start_ptr + length;
  JSONParseError error;
  error.type = BuildValue(&cursor, end, max_depth, comment_state, result,
                          &error.duplicate_keys);
  error.line = cursor.line;
  error.column = static_cast<int>(cursor.pos - cursor.line_start);
  if (error.type != Error::kNoError) {
    *result = nullptr;
  } else if (cursor.pos != end) {
    error.type = Error::kUnexpectedDataAfterRoot;
    *result = nullptr;
  }
  return error;
}

}  // anonymous namespace

std::unique_ptr<JSONValue> ParseJSON(const String& json,
                                     JSONParseError* opt_error) {
  JSONCommentState comments = JSONCommentState::kDisallowed;
  auto result = ParseJSON(json, comments, kMaxStackLimit, opt_error);
  DCHECK_EQ(comments, JSONCommentState::kDisallowed);
  return result;
}

std::unique_ptr<JSONValue> ParseJSONWithCommentsDeprecated(
    const String& json,
    JSONParseError* opt_error,
    bool* opt_has_comments) {
  JSONCommentState comment_state = JSONCommentState::kAllowedButAbsent;
  auto result = ParseJSON(json, comment_state, kMaxStackLimit, opt_error);
  if (opt_has_comments) {
    *opt_has_comments = (comment_state == JSONCommentState::kAllowedAndPresent);
  }
  return result;
}

std::unique_ptr<JSONValue> ParseJSON(const String& json,
                                     JSONCommentState& comment_state,
                                     int max_depth,
                                     JSONParseError* opt_error) {
  if (max_depth < 0)
    max_depth = 0;
  if (max_depth > kMaxStackLimit)
    max_depth = kMaxStackLimit;

  std::unique_ptr<JSONValue> result;
  JSONParseError error;

  if (json.empty()) {
    error.type = Error::kSyntaxError;
    error.line = 0;
    error.column = 0;
  } else if (json.Is8Bit()) {
    error = ParseJSONInternal(json.Characters8(), json.length(), max_depth,
                              comment_state, &result);
  } else {
    error = ParseJSONInternal(json.Characters16(), json.length(), max_depth,
                              comment_state, &result);
  }

  if (opt_error) {
    error.line++;
    error.column++;
    if (error.type != Error::kNoError)
      error.message = FormatErrorMessage(error.type, error.line, error.column);
    *opt_error = error;
  }
  return result;
}

}  // namespace blink

"""

```