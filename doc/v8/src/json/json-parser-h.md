Response:
Let's break down the thought process for analyzing the provided C++ header file.

1. **Identify the Core Purpose:** The filename `json-parser.h` immediately suggests this file is responsible for parsing JSON data. The `#ifndef V8_JSON_JSON_PARSER_H_` guard confirms it's a header file meant to be included in other C++ source files.

2. **Scan for Key Classes/Structs:** Look for the main building blocks. In this case, the prominent ones are:
    * `JsonString`:  Likely represents a JSON string internally.
    * `JsonProperty`: Represents a key-value pair in a JSON object.
    * `JsonParseInternalizer`:  Seems involved in post-processing or refinement of the parsed JSON.
    * `JsonToken`: An enumeration suggesting different JSON elements (numbers, strings, brackets, etc.).
    * `JsonParser`:  The main class that likely handles the actual parsing logic.

3. **Analyze Individual Components:**  Go through each class/struct and understand its members and methods.

    * **`JsonString`:**  Notice the union for `start_` and `index_`. This suggests it handles both regular string segments (with start and length) and potentially pre-computed indices (perhaps for optimization). The boolean flags (`needs_conversion_`, `internalize_`, `has_escape_`) indicate properties of the string that might affect processing.

    * **`JsonProperty`:** Simple structure holding a `JsonString` (the key) and a `Handle<Object>` (the value). The `Handle<Object>` hints at V8's object representation.

    * **`JsonParseInternalizer`:** The static `Internalize` method and the internal `InternalizeJsonProperty` and `RecurseAndApply` suggest this class is responsible for applying a "reviver" function (from JavaScript's `JSON.parse`) to the parsed structure. The template parameter `WithOrWithoutSource` implies handling cases with and without source tracking.

    * **`JsonToken`:** This is straightforward – a list of possible JSON tokens the parser recognizes.

    * **`JsonParser`:**  This is the most complex. Pay attention to:
        * **Template `<typename Char>`:** This indicates the parser can handle different character encodings (likely UTF-8 and UTF-16).
        * **Static `CheckRawJson` and `Parse`:** These are the primary entry points for using the parser. `Parse` handles the optional reviver function.
        * **`advance()`, `CurrentCharacter()`, `NextCharacter()`:** Basic input stream manipulation.
        * **`peek()`, `Consume()`, `Expect()`:** Token handling and error checking.
        * **`ScanLiteral()`, `ScanJsonString()`, `ScanJsonPropertyKey()`, `ScanUnicodeCharacter()`:** Lexical analysis – identifying and extracting tokens from the input.
        * **`SkipWhitespace()`:**  Handles insignificant whitespace.
        * **`ParseJsonNumber()`, `ParseJsonValue()`, `ParseJsonArray()`, `ParseJsonObject()`:** The core parsing logic, likely recursive descent.
        * **`BuildJsonObject()`, `BuildJsonArray()`:** Constructing the V8 object representation of the parsed JSON.
        * **Error Reporting Methods (`ReportUnexpectedCharacter`, `ReportUnexpectedToken`):** Important for providing informative error messages.
        * **`UpdatePointersCallback()` and `UpdatePointers()`:** Handle potential garbage collection and relocation of string data.

4. **Identify Key Functionality:**  Based on the analysis of the classes and methods, summarize the file's functionality. This involves:
    * Parsing JSON strings into V8 objects.
    * Handling different JSON data types (strings, numbers, booleans, null, objects, arrays).
    * Supporting the optional reviver function.
    * Handling different character encodings.
    * Providing error reporting.

5. **Address Specific Prompts:** Now go back and address each part of the original request:

    * **Functionality List:**  Directly list the identified functionalities.
    * **`.tq` Extension:** Explain that `.tq` would indicate a Torque file, a V8-specific language. Confirm this file is C++ (`.h`).
    * **JavaScript Relationship:** Connect the C++ code to the `JSON.parse()` function in JavaScript. Provide a simple JavaScript example.
    * **Code Logic/Input-Output:** Focus on the `Parse` method. Provide a basic JSON string as input and describe the expected V8 object output.
    * **Common Programming Errors:** Think about typical JSON parsing errors (syntax errors, invalid characters, etc.) and how they would manifest in a JavaScript context using `JSON.parse()`.

6. **Review and Refine:**  Read through the entire explanation. Ensure clarity, accuracy, and completeness. Check for any jargon that might need further explanation. Make sure the JavaScript examples are clear and correct. Ensure that the input/output example reflects a plausible scenario.

**Self-Correction/Refinement Example During Thought Process:**

Initially, I might have just seen `JsonParseInternalizer` and thought it was solely for string interning. However, looking at the method names (`Internalize`, `InternalizeJsonProperty`, `RecurseAndApply`) and the `reviver` parameter, I'd realize it's implementing the full reviver functionality of `JSON.parse`. This requires a correction in my understanding of its purpose.

Similarly, upon seeing the template parameter `<typename Char>` in `JsonParser`, I might initially overlook its significance. However, recalling that JavaScript strings can be either one-byte or two-byte encoded, I'd realize this is about handling different character encodings. This adds a layer of detail to the explanation of the parser's capabilities.
这个头文件 `v8/src/json/json-parser.h` 定义了 V8 引擎中用于解析 JSON (JavaScript Object Notation) 数据的类和数据结构。让我们详细列举它的功能：

**主要功能:**

1. **JSON 解析:**  核心功能是将 JSON 格式的字符串转换为 V8 引擎内部的对象表示形式 (例如，`JSObject`, `JSArray`, `String`, `Number`, `Boolean`, `Null`)。这是 `JSON.parse()` 在 V8 引擎中的实现基础。

2. **错误处理:**  当 JSON 字符串格式不正确时，能够检测并报告错误。这包括语法错误，例如缺少逗号、冒号，或者使用了非法的字符。

3. **可选的 Reviver 函数支持:** 实现了 `JSON.parse()` 的第二个可选参数 `reviver` 的功能。`reviver` 是一个函数，它可以在解析过程中对每个键值对进行处理和转换。

4. **支持不同的字符编码:** 通过模板类 `JsonParser<Char>`，该解析器可以处理不同字符类型的 JSON 字符串，例如 UTF-8 和 UTF-16。

5. **高性能:**  作为 V8 引擎的一部分，这个解析器设计为高性能和高效率，以满足 JavaScript 引擎快速解析 JSON 的需求。

**具体组件功能:**

* **`JsonString` 类:**  表示 JSON 字符串的一部分，可能是一个属性名或一个字符串值。它存储了字符串的起始位置、长度以及一些用于优化的标志，例如是否需要转换编码、是否需要内部化（intern）。 `is_index_` 标志可能用于优化数组索引的处理。

* **`JsonProperty` 结构体:**  表示 JSON 对象中的一个键值对，包含一个 `JsonString` 类型的键和一个 `Handle<Object>` 类型的值。`Handle<Object>` 是 V8 中用于管理垃圾回收的智能指针，指向一个 V8 对象。

* **`JsonParseInternalizer` 类:**  负责在解析完成后，应用用户提供的 `reviver` 函数。它递归地遍历解析得到的对象结构，并对每个属性调用 `reviver` 函数。

* **`JsonToken` 枚举:**  定义了 JSON 语法中的各种词法单元（token），例如数字、字符串、大括号、方括号、true、false、null、冒号、逗号等。解析器会先将输入的 JSON 字符串分解成这些 token。

* **`JsonParser` 模板类:**  是实际执行 JSON 解析的类。它包含了：
    * **`ParseRawJson()`:**  可能用于快速检查 JSON 字符串的基本格式是否正确，但不构建完整的对象。
    * **`Parse()`:**  是主要的解析入口点，负责将 JSON 字符串转换为 V8 对象，并支持 `reviver` 函数。
    * **词法分析方法:** 例如 `ScanJsonString`, `ScanJsonPropertyKey`, `ScanLiteral` 等，用于识别和提取 JSON 字符串中的各种 token。
    * **语法分析方法:** 例如 `ParseJsonValue`, `ParseJsonObject`, `ParseJsonArray` 等，用于根据 JSON 的语法规则构建对象结构。
    * **错误报告方法:** 例如 `ReportUnexpectedCharacter`, `ReportUnexpectedToken`，用于在解析过程中发现错误时生成错误信息。

**关于文件名以 `.tq` 结尾:**

如果 `v8/src/json/json-parser.h` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。Torque 是 V8 自研的一种类型化的中间语言，用于编写性能关键的运行时代码。然而，根据你提供的文件名，它以 `.h` 结尾，所以它是一个标准的 C++ 头文件。该头文件中定义的类很可能在其他 `.tq` 或 `.cc` 文件中被使用。

**与 JavaScript 功能的关系及示例:**

`v8/src/json/json-parser.h` 中定义的类是 JavaScript 中全局对象 `JSON` 的 `parse()` 方法在 V8 引擎中的底层实现。

**JavaScript 示例:**

```javascript
const jsonString = '{"name": "John Doe", "age": 30, "city": "New York"}';

// 使用 JSON.parse() 解析 JSON 字符串
const parsedObject = JSON.parse(jsonString);

console.log(parsedObject.name); // 输出: John Doe
console.log(parsedObject.age);  // 输出: 30
console.log(parsedObject.city); // 输出: New York

// 使用 reviver 函数
const jsonStringWithDate = '{"date": "2023-10-27T10:00:00.000Z"}';
const parsedObjectWithDate = JSON.parse(jsonStringWithDate, (key, value) => {
  if (key === 'date') {
    return new Date(value);
  }
  return value;
});

console.log(parsedObjectWithDate.date instanceof Date); // 输出: true
console.log(parsedObjectWithDate.date.getFullYear());   // 输出: 2023
```

在这个例子中，`JSON.parse(jsonString)`  的操作在 V8 引擎内部会调用 `v8/src/json/json-parser.h` 中定义的 `JsonParser` 类来完成解析工作。第二个例子展示了 `reviver` 函数的使用，这对应于 `JsonParseInternalizer` 类的功能。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

```json
'{"a": 123, "b": "hello", "c": true, "d": null, "e": [1, 2, 3]}'
```

**预期输出 (V8 内部对象表示，逻辑上的等价物):**

一个 V8 `JSObject`，它具有以下属性：

* 属性名为 "a"，值为 V8 的数字对象表示 123。
* 属性名为 "b"，值为 V8 的字符串对象表示 "hello"。
* 属性名为 "c"，值为 V8 的布尔对象表示 true。
* 属性名为 "d"，值为 V8 的 null 对象。
* 属性名为 "e"，值为 V8 的 `JSArray` 对象，包含 V8 的数字对象 1, 2, 3。

**用户常见的编程错误 (与 `JSON.parse()` 相关):**

1. **JSON 字符串格式不正确:**  这是最常见的错误。例如：
   ```javascript
   const invalidJson = "{'name': 'John'}"; // 错误: 属性名和字符串值应使用双引号
   try {
     JSON.parse(invalidJson);
   } catch (e) {
     console.error(e); // 输出 SyntaxError
   }
   ```

2. **JSON 字符串中存在尾随逗号:**  虽然某些 JavaScript 引擎可能容忍，但标准的 JSON 格式不允许尾随逗号。
   ```javascript
   const trailingCommaJson = '{"a": 1,}';
   try {
     JSON.parse(trailingCommaJson);
   } catch (e) {
     console.error(e); // 输出 SyntaxError
   }
   ```

3. **尝试解析非 JSON 格式的字符串:**
   ```javascript
   const notJson = "hello world";
   try {
     JSON.parse(notJson);
   } catch (e) {
     console.error(e); // 输出 SyntaxError
   }
   ```

4. **在 `reviver` 函数中返回 `undefined`:**  如果在 `reviver` 函数中对某个键值对返回 `undefined`，则该属性会被从最终的对象中删除。这可能不是用户的预期行为。
   ```javascript
   const jsonString = '{"removeMe": 1, "keepMe": 2}';
   const parsedObject = JSON.parse(jsonString, (key, value) => {
     if (key === 'removeMe') {
       return undefined;
     }
     return value;
   });
   console.log(parsedObject); // 输出: { keepMe: 2 }
   ```

总而言之，`v8/src/json/json-parser.h` 是 V8 引擎中至关重要的一个头文件，它定义了用于高效、准确地解析 JSON 数据的核心组件，直接支撑了 JavaScript 中 `JSON.parse()` 的功能。

Prompt: 
```
这是目录为v8/src/json/json-parser.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/json/json-parser.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_JSON_JSON_PARSER_H_
#define V8_JSON_JSON_PARSER_H_

#include <optional>

#include "include/v8-callbacks.h"
#include "src/base/small-vector.h"
#include "src/base/strings.h"
#include "src/common/high-allocation-throughput-scope.h"
#include "src/execution/isolate.h"
#include "src/heap/factory.h"
#include "src/objects/objects.h"
#include "src/objects/string.h"
#include "src/roots/roots.h"

namespace v8 {
namespace internal {

enum ParseElementResult { kElementFound, kElementNotFound };

class JsonString final {
 public:
  JsonString()
      : start_(0),
        length_(0),
        needs_conversion_(false),
        internalize_(false),
        has_escape_(false),
        is_index_(false) {}

  explicit JsonString(uint32_t index)
      : index_(index),
        length_(0),
        needs_conversion_(false),
        internalize_(false),
        has_escape_(false),
        is_index_(true) {}

  JsonString(int start, int length, bool needs_conversion, bool internalize,
             bool has_escape)
      : start_(start),
        length_(length),
        needs_conversion_(needs_conversion),
        internalize_(internalize),
        has_escape_(has_escape),
        is_index_(false) {}

  bool internalize() const {
    DCHECK(!is_index_);
    return internalize_;
  }

  bool needs_conversion() const {
    DCHECK(!is_index_);
    return needs_conversion_;
  }

  bool has_escape() const {
    DCHECK(!is_index_);
    return has_escape_;
  }

  int start() const {
    DCHECK(!is_index_);
    return start_;
  }

  int length() const {
    DCHECK(!is_index_);
    return length_;
  }

  uint32_t index() const {
    DCHECK(is_index_);
    return index_;
  }

  bool is_index() const { return is_index_; }

 private:
  union {
    const int start_;
    const uint32_t index_;
  };
  const int length_;
  const bool needs_conversion_ : 1;
  const bool internalize_ : 1;
  const bool has_escape_ : 1;
  const bool is_index_ : 1;
};

struct JsonProperty {
  JsonProperty() { UNREACHABLE(); }
  explicit JsonProperty(const JsonString& string) : string(string) {}
  JsonProperty(const JsonString& string, Handle<Object> value)
      : string(string), value(value) {}

  JsonString string;
  Handle<Object> value;
};

class JsonParseInternalizer {
 public:
  static MaybeHandle<Object> Internalize(Isolate* isolate,
                                         Handle<Object> result,
                                         Handle<Object> reviver,
                                         Handle<String> source,
                                         MaybeHandle<Object> val_node);

 private:
  JsonParseInternalizer(Isolate* isolate, Handle<JSReceiver> reviver,
                        Handle<String> source)
      : isolate_(isolate), reviver_(reviver), source_(source) {}

  enum WithOrWithoutSource { kWithoutSource, kWithSource };

  template <WithOrWithoutSource with_source>
  MaybeHandle<Object> InternalizeJsonProperty(Handle<JSReceiver> holder,
                                              Handle<String> key,
                                              Handle<Object> val_node,
                                              Handle<Object> snapshot);

  template <WithOrWithoutSource with_source>
  bool RecurseAndApply(Handle<JSReceiver> holder, Handle<String> name,
                       Handle<Object> val_node, Handle<Object> snapshot);

  Isolate* isolate_;
  Handle<JSReceiver> reviver_;
  Handle<String> source_;
};

enum class JsonToken : uint8_t {
  NUMBER,
  STRING,
  LBRACE,
  RBRACE,
  LBRACK,
  RBRACK,
  TRUE_LITERAL,
  FALSE_LITERAL,
  NULL_LITERAL,
  WHITESPACE,
  COLON,
  COMMA,
  ILLEGAL,
  EOS
};

// A simple json parser.
template <typename Char>
class JsonParser final {
 public:
  using SeqString = typename CharTraits<Char>::String;
  using SeqExternalString = typename CharTraits<Char>::ExternalString;

  V8_WARN_UNUSED_RESULT static bool CheckRawJson(Isolate* isolate,
                                                 Handle<String> source) {
    return JsonParser(isolate, source).ParseRawJson();
  }

  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> Parse(
      Isolate* isolate, Handle<String> source, Handle<Object> reviver) {
    HighAllocationThroughputScope high_throughput_scope(
        V8::GetCurrentPlatform());
    Handle<Object> result;
    MaybeHandle<Object> val_node;
    {
      JsonParser parser(isolate, source);
      ASSIGN_RETURN_ON_EXCEPTION(isolate, result, parser.ParseJson(reviver));
      val_node = parser.parsed_val_node_;
    }
    if (IsCallable(*reviver)) {
      return JsonParseInternalizer::Internalize(isolate, result, reviver,
                                                source, val_node);
    }
    return result;
  }

  static constexpr base::uc32 kEndOfString = static_cast<base::uc32>(-1);
  static constexpr base::uc32 kInvalidUnicodeCharacter =
      static_cast<base::uc32>(-1);

 private:
  class NamedPropertyIterator;

  template <typename T>
  using SmallVector = base::SmallVector<T, 16>;
  struct JsonContinuation {
    enum Type : uint8_t { kReturn, kObjectProperty, kArrayElement };
    JsonContinuation(Isolate* isolate, Type type, size_t index)
        : scope(isolate),
          type_(type),
          index(static_cast<uint32_t>(index)),
          max_index(0),
          elements(0) {}

    Type type() const { return static_cast<Type>(type_); }
    void set_type(Type type) { type_ = static_cast<uint8_t>(type); }

    HandleScope scope;
    // Unfortunately GCC doesn't like packing Type in two bits.
    uint32_t type_ : 2;
    uint32_t index : 30;
    uint32_t max_index;
    uint32_t elements;
  };

  JsonParser(Isolate* isolate, Handle<String> source);
  ~JsonParser();

  // Parse a string containing a single JSON value.
  MaybeHandle<Object> ParseJson(DirectHandle<Object> reviver);

  bool ParseRawJson();

  void advance() { ++cursor_; }

  base::uc32 CurrentCharacter() {
    if (V8_UNLIKELY(is_at_end())) return kEndOfString;
    return *cursor_;
  }

  base::uc32 NextCharacter() {
    advance();
    return CurrentCharacter();
  }

  void AdvanceToNonDecimal();

  V8_INLINE JsonToken peek() const { return next_; }

  void Consume(JsonToken token) {
    DCHECK_EQ(peek(), token);
    advance();
  }

  void Expect(JsonToken token,
              std::optional<MessageTemplate> errorMessage = std::nullopt) {
    if (V8_LIKELY(peek() == token)) {
      advance();
    } else {
      errorMessage ? ReportUnexpectedToken(peek(), errorMessage.value())
                   : ReportUnexpectedToken(peek());
    }
  }

  void ExpectNext(JsonToken token,
                  std::optional<MessageTemplate> errorMessage = std::nullopt) {
    SkipWhitespace();
    errorMessage ? Expect(token, errorMessage.value()) : Expect(token);
  }

  bool Check(JsonToken token) {
    SkipWhitespace();
    if (next_ != token) return false;
    advance();
    return true;
  }

  template <size_t N>
  void ScanLiteral(const char (&s)[N]) {
    DCHECK(!is_at_end());
    // There's at least 1 character, we always consume a character and compare
    // the next character. The first character was compared before we jumped
    // to ScanLiteral.
    static_assert(N > 2);
    size_t remaining = static_cast<size_t>(end_ - cursor_);
    if (V8_LIKELY(remaining >= N - 1 &&
                  CompareCharsEqual(s + 1, cursor_ + 1, N - 2))) {
      cursor_ += N - 1;
      return;
    }

    cursor_++;
    for (size_t i = 0; i < std::min(N - 2, remaining - 1); i++) {
      if (*(s + 1 + i) != *cursor_) {
        ReportUnexpectedCharacter(*cursor_);
        return;
      }
      cursor_++;
    }

    DCHECK(is_at_end());
    ReportUnexpectedToken(JsonToken::EOS);
  }

  // The JSON lexical grammar is specified in the ECMAScript 5 standard,
  // section 15.12.1.1. The only allowed whitespace characters between tokens
  // are tab, carriage-return, newline and space.
  void SkipWhitespace();

  // A JSON string (production JSONString) is subset of valid JavaScript string
  // literals. The string must only be double-quoted (not single-quoted), and
  // the only allowed backslash-escapes are ", /, \, b, f, n, r, t and
  // four-digit hex escapes (uXXXX). Any other use of backslashes is invalid.
  JsonString ScanJsonString(bool needs_internalization);
  JsonString ScanJsonPropertyKey(JsonContinuation* cont);
  base::uc32 ScanUnicodeCharacter();
  base::Vector<const Char> GetKeyChars(JsonString key) {
    return base::Vector<const Char>(chars_ + key.start(), key.length());
  }
  Handle<String> MakeString(const JsonString& string,
                            Handle<String> hint = Handle<String>());

  template <typename SinkChar>
  void DecodeString(SinkChar* sink, int start, int length);

  template <typename SinkSeqString>
  Handle<String> DecodeString(const JsonString& string,
                              Handle<SinkSeqString> intermediate,
                              Handle<String> hint);

  // A JSON number (production JSONNumber) is a subset of the valid JavaScript
  // decimal number literals.
  // It includes an optional minus sign, must have at least one
  // digit before and after a decimal point, may not have prefixed zeros (unless
  // the integer part is zero), and may include an exponent part (e.g., "e-10").
  // Hexadecimal and octal numbers are not allowed.
  Handle<Object> ParseJsonNumber();

  // Parse a single JSON value from input (grammar production JSONValue).
  // A JSON value is either a (double-quoted) string literal, a number literal,
  // one of "true", "false", or "null", or an object or array literal.
  template <bool should_track_json_source>
  MaybeHandle<Object> ParseJsonValue();

  V8_INLINE MaybeHandle<Object> ParseJsonValueRecursive(
      Handle<Map> feedback = {});
  MaybeHandle<Object> ParseJsonArray();
  MaybeHandle<Object> ParseJsonObject(Handle<Map> feedback);

  template <bool should_track_json_source>
  Handle<JSObject> BuildJsonObject(const JsonContinuation& cont,
                                   Handle<Map> feedback);
  Handle<Object> BuildJsonArray(size_t start);

  static const int kMaxContextCharacters = 10;
  static const int kMinOriginalSourceLengthForContext =
      (kMaxContextCharacters * 2) + 1;

  // Mark that a parsing error has happened at the current character.
  void ReportUnexpectedCharacter(base::uc32 c);
  bool IsSpecialString();
  MessageTemplate GetErrorMessageWithEllipses(DirectHandle<Object>& arg,
                                              DirectHandle<Object>& arg2,
                                              int pos);
  MessageTemplate LookUpErrorMessageForJsonToken(JsonToken token,
                                                 DirectHandle<Object>& arg,
                                                 DirectHandle<Object>& arg2,
                                                 int pos);

  // Calculate line and column based on the current cursor position.
  // Both values start at 1.
  void CalculateFileLocation(DirectHandle<Object>& line,
                             DirectHandle<Object>& column);
  // Mark that a parsing error has happened at the current token.
  void ReportUnexpectedToken(
      JsonToken token,
      std::optional<MessageTemplate> errorMessage = std::nullopt);

  inline Isolate* isolate() { return isolate_; }
  inline Factory* factory() { return isolate_->factory(); }
  inline ReadOnlyRoots roots() { return ReadOnlyRoots(isolate_); }
  inline Handle<JSFunction> object_constructor() { return object_constructor_; }

  static const int kInitialSpecialStringLength = 32;

  static void UpdatePointersCallback(void* parser) {
    reinterpret_cast<JsonParser<Char>*>(parser)->UpdatePointers();
  }

  void UpdatePointers() {
    DisallowGarbageCollection no_gc;
    const Char* chars = Cast<SeqString>(source_)->GetChars(no_gc);
    if (chars_ != chars) {
      size_t position = cursor_ - chars_;
      size_t length = end_ - chars_;
      chars_ = chars;
      cursor_ = chars_ + position;
      end_ = chars_ + length;
    }
  }

 private:
  static const bool kIsOneByte = sizeof(Char) == 1;

  bool is_at_end() const {
    DCHECK_LE(cursor_, end_);
    return cursor_ == end_;
  }

  int position() const { return static_cast<int>(cursor_ - chars_); }

  Isolate* isolate_;
  const uint64_t hash_seed_;
  JsonToken next_;
  // Indicates whether the bytes underneath source_ can relocate during GC.
  bool chars_may_relocate_;
  Handle<JSFunction> object_constructor_;
  const Handle<String> original_source_;
  Handle<String> source_;
  // The parsed value's source to be passed to the reviver, if the reviver is
  // callable.
  MaybeHandle<Object> parsed_val_node_;

  SmallVector<Handle<Object>> element_stack_;
  SmallVector<JsonProperty> property_stack_;

  // Cached pointer to the raw chars in source. In case source is on-heap, we
  // register an UpdatePointers callback. For this reason, chars_, cursor_ and
  // end_ should never be locally cached across a possible allocation. The scope
  // in which we cache chars has to be guarded by a DisallowGarbageCollection
  // scope.
  const Char* cursor_;
  const Char* end_;
  const Char* chars_;
};

// Explicit instantiation declarations.
extern template class JsonParser<uint8_t>;
extern template class JsonParser<uint16_t>;

}  // namespace internal
}  // namespace v8

#endif  // V8_JSON_JSON_PARSER_H_

"""

```