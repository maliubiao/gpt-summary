Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/json/json-parser.cc`. I need to analyze the code and explain its role in parsing JSON.

Here's a breakdown of the requested information and how to approach it:

1. **Functionality:**  Analyze the code to determine its primary purpose and key operations. This involves looking at the class structure, methods, and logic flow. The presence of `JsonParser`, `JsonToken`, and methods like `ParseJsonValue`, `BuildJsonObject`, and `BuildJsonArray` strongly suggests this code is responsible for parsing JSON strings into V8 JavaScript objects.

2. **Torque Source:** Check the file extension. The prompt explicitly states how to identify a Torque source. The provided file ends in `.cc`, so it's not a Torque file.

3. **Relationship to JavaScript:** Explain how the JSON parsing relates to JavaScript. JSON is a common format for data exchange, and JavaScript has built-in functions (`JSON.parse()`) for this. The V8 JSON parser implements the underlying logic for these functions.

4. **Code Logic Inference (Input/Output):**  Choose a simple JSON input string and trace the likely execution flow through the code to predict the output (a V8 object). Focus on the `ParseJsonValue` and the object/array building methods.

5. **Common Programming Errors:**  Identify potential errors that developers might make when working with JSON, and how this parser helps in detecting them (e.g., unterminated strings, invalid characters).

6. **归纳功能 (Summarize Functionality):** Condense the findings into a concise summary of the code's purpose.

**Plan:**

* Briefly describe the overall role of `v8/src/json/json-parser.cc`.
* Explicitly state that it's a C++ file, not a Torque file.
* Explain its connection to JavaScript's `JSON.parse()`.
* Provide a simple JSON input example and the expected JavaScript object output.
* Give examples of common JSON formatting errors that the parser would catch.
* Conclude with a concise summary of the parser's function.
```javascript
// 假设我们有以下 JSON 字符串
const jsonString = '{"name": "John Doe", "age": 30, "city": "New York"}';

// 使用 JavaScript 的 JSON.parse() 方法解析 JSON 字符串
const jsonObject = JSON.parse(jsonString);

// jsonObject 现在是一个 JavaScript 对象
console.log(jsonObject.name); // 输出: John Doe
console.log(jsonObject.age);  // 输出: 30
console.log(jsonObject.city); // 输出: New York

// 另一个例子，包含嵌套对象和数组
const complexJsonString =
  '{"name": "Alice", "details": {"age": 25, "occupation": "Engineer"}, "hobbies": ["reading", "coding"]}';
const complexJsonObject = JSON.parse(complexJsonString);

console.log(complexJsonObject.details.age);    // 输出: 25
console.log(complexJsonObject.hobbies[0]);   // 输出: reading
```

**功能归纳:**

这段 C++ 代码是 V8 引擎中用于解析 JSON 字符串的核心组件。它实现了将符合 JSON 语法规则的字符串转换为 V8 引擎内部表示的 JavaScript 对象和值的逻辑。

**详细功能列表:**

* **解析 JSON 值:**  代码的主要功能是 `ParseJsonValue` 方法，它负责递归地解析 JSON 字符串中的各种值类型，包括对象、数组、字符串、数字、布尔值（`true`, `false`）和空值（`null`）。
* **构建 JSON 对象:** 当遇到 JSON 对象（以 `{` 开头，以 `}` 结尾）时，`BuildJsonObject` 方法会被调用。它负责解析对象中的键值对，并将它们存储在 V8 的对象结构中。代码中还涉及到优化，例如在解析过程中收集反馈信息 (`feedback`)，以便更高效地创建对象。
* **构建 JSON 数组:** 当遇到 JSON 数组（以 `[` 开头，以 `]` 结尾）时，`BuildJsonArray` 方法会被调用。它负责解析数组中的元素，并将它们存储在 V8 的数组结构中。
* **处理字符串:** `ScanJsonString` 方法用于扫描和解析 JSON 字符串。它会处理转义字符，并根据字符串的内容和长度决定是否需要内部化（intern）。`DecodeString` 方法用于解码包含转义字符的 JSON 字符串。
* **处理数字:** `ParseJsonNumber` 方法负责解析 JSON 中的数字，包括整数和浮点数，并将其转换为 V8 的数字类型（Smi 或 HeapNumber）。这段代码还考虑了性能优化，例如快速路径处理小的整数 (Smi)。
* **错误处理:** 代码中包含 `Expect` 和 `ExpectNext` 等方法，用于检查当前解析到的 token 是否符合 JSON 语法规则，并在遇到错误时报告相应的错误消息。例如，期望逗号或右大括号，但遇到了其他字符。
* **跳过空格:** 解析器会自动跳过 JSON 结构中的空白字符，例如空格、制表符和换行符。
* **源信息追踪 (可选):**  代码中存在 `should_track_json_source` 模板参数，表明 V8 可以在解析 JSON 的同时追踪源信息，这对于调试和错误报告很有用。这部分代码会记录每个属性和元素的源位置和快照。

**如果 v8/src/json/json-parser.cc 以 .tq 结尾:**

如果 `v8/src/json/json-parser.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是 V8 用于编写高性能运行时代码的领域特定语言。这意味着 JSON 解析的某些部分（可能是性能关键的部分）会使用 Torque 来实现，以便进行更底层的优化和类型安全。

**与 JavaScript 功能的关系:**

`v8/src/json/json-parser.cc` 中实现的 JSON 解析器是 JavaScript 中全局对象 `JSON` 的 `parse()` 方法的底层实现。当你在 JavaScript 中调用 `JSON.parse(jsonString)` 时，V8 引擎会调用这个 C++ 代码来解析 `jsonString` 并将其转换为 JavaScript 对象。

**代码逻辑推理 (假设输入与输出):**

**假设输入 JSON 字符串:**  `"[123, true, \"hello\"]"`

**解析过程推断:**

1. **开始解析:** `ParseJsonValue` 被调用。
2. **识别数组开始:** 解析器遇到 `[`，识别出这是一个 JSON 数组。
3. **创建数组上下文:**  `cont_stack` 中压入一个 `JsonContinuation::kArrayElement` 类型的 continuation，`cont.index` 初始化为 0。
4. **解析第一个元素:**
   - 解析器读取 `123`，调用 `ParseJsonNumber` 将其转换为 V8 的 Smi 对象。
   - `element_stack_` 存储该 Smi 对象。
   - 如果启用了源信息追踪，`element_val_node_stack` 也会存储相关信息。
5. **解析逗号:** 解析器遇到 `,`，准备解析下一个元素。
6. **解析第二个元素:**
   - 解析器读取 `true`，将其转换为 V8 的布尔值 `true`。
   - `element_stack_` 存储该布尔值。
   - 如果启用了源信息追踪，`element_val_node_stack` 也会存储相关信息。
7. **解析逗号:** 解析器遇到 `,`，准备解析下一个元素。
8. **解析第三个元素:**
   - 解析器读取 `"hello"`，调用 `ScanJsonString` 和 `MakeString` 将其转换为 V8 的字符串对象。
   - `element_stack_` 存储该字符串对象。
   - 如果启用了源信息追踪，`element_val_node_stack` 也会存储相关信息。
9. **识别数组结束:** 解析器遇到 `]`。
10. **构建数组:** `BuildJsonArray(0)` 被调用，根据 `element_stack_` 中的元素构建 V8 数组。
11. **返回数组:** 函数返回构建好的 V8 数组对象。

**预期输出 (JavaScript 表示):** `[123, true, "hello"]`

**涉及用户常见的编程错误:**

1. **JSON 格式错误:**
   ```javascript
   // 缺少引号
   try {
     JSON.parse('{name: "John"}');
   } catch (e) {
     console.error(e); // 可能会看到 "SyntaxError: Unexpected token n in JSON at position 1"
   }

   // 缺少逗号
   try {
     JSON.parse('{"name": "John" "age": 30}');
   } catch (e) {
     console.error(e); // 可能会看到 "SyntaxError: Unexpected string in JSON at position 16"
   }

   // 尾部逗号
   try {
     JSON.parse('[1, 2,]');
   } catch (e) {
     console.error(e); // 可能会看到 "SyntaxError: Unexpected token ] in JSON at position 6"
   }
   ```
   `v8/src/json/json-parser.cc` 中的错误处理机制会捕获这些格式错误，并抛出相应的 JavaScript `SyntaxError` 异常。例如，`Expect(JsonToken::RBRACE, MessageTemplate::kJsonParseExpectedCommaOrRBrace)` 会在期望逗号或右大括号时遇到其他字符而抛出错误。

2. **使用了 JavaScript 特有的对象字面量语法:**
   ```javascript
   // JSON 必须使用双引号作为键名
   try {
     JSON.parse("{name: 'John'}");
   } catch (e) {
     console.error(e); // 可能会看到 "SyntaxError: Unexpected token n in JSON at position 1"
   }
   ```
   JSON 规范要求键名必须是双引号括起来的字符串。V8 的 JSON 解析器会严格遵循这个规范。

3. **使用了单引号字符串:**
   ```javascript
   try {
     JSON.parse('{"name": \'John\'}');
   } catch (e) {
     console.error(e); // 可能会看到 "SyntaxError: Unexpected token ' in JSON at position 10"
   }
   ```
   JSON 字符串必须使用双引号。

**第 3 部分功能归纳:**

这段 `v8/src/json/json-parser.cc` 代码片段是 V8 引擎 JSON 解析器的核心部分，负责将 JSON 字符串转换为 V8 内部表示的 JavaScript 对象和值。它实现了对 JSON 对象、数组、字符串和数字的解析，并包含了错误处理逻辑以检测不符合 JSON 语法规则的输入。这段代码是 JavaScript 中 `JSON.parse()` 方法的底层实现基础。其主要功能是遍历 JSON 字符串的 token，根据 JSON 的语法规则构建相应的 V8 对象结构，并处理各种边界情况和错误。可选的源信息追踪功能增强了调试和错误报告的能力。

### 提示词
```
这是目录为v8/src/json/json-parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/json/json-parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
de_stack.back() = val_node;
          }

          if (V8_LIKELY(Check(JsonToken::COMMA))) {
            // Parse the property key.
            ExpectNext(
                JsonToken::STRING,
                MessageTemplate::kJsonParseExpectedDoubleQuotedPropertyName);

            property_stack_.emplace_back(ScanJsonPropertyKey(&cont));
            if constexpr (should_track_json_source) {
              property_val_node_stack.emplace_back(Handle<Object>());
            }
            ExpectNext(
                JsonToken::COLON,
                MessageTemplate::kJsonParseExpectedColonAfterPropertyName);

            // Break to start producing the subsequent property value.
            break;
          }

          Handle<Map> feedback;
          if (cont_stack.size() > 0 &&
              cont_stack.back().type() == JsonContinuation::kArrayElement &&
              cont_stack.back().index < element_stack_.size() &&
              IsJSObject(*element_stack_.back())) {
            Tagged<Map> maybe_feedback =
                Cast<JSObject>(*element_stack_.back())->map();
            // Don't consume feedback from objects with a map that's detached
            // from the transition tree.
            if (!maybe_feedback->IsDetached(isolate_)) {
              feedback = handle(maybe_feedback, isolate_);
            }
          }
          value = BuildJsonObject<should_track_json_source>(cont, feedback);
          Expect(JsonToken::RBRACE,
                 MessageTemplate::kJsonParseExpectedCommaOrRBrace);
          // Return the object.
          if constexpr (should_track_json_source) {
            size_t start = cont.index;
            int num_properties =
                static_cast<int>(property_stack_.size() - start);
            Handle<ObjectTwoHashTable> table =
                ObjectTwoHashTable::New(isolate(), num_properties);
            for (int i = 0; i < num_properties; i++) {
              const JsonProperty& property = property_stack_[start + i];
              Handle<Object> property_val_node =
                  property_val_node_stack[start + i];
              Handle<Object> property_snapshot = property.value;
              Handle<String> key;
              if (property.string.is_index()) {
                key = factory()->Uint32ToString(property.string.index());
              } else {
                key = MakeString(property.string);
              }
              table = ObjectTwoHashTable::Put(
                  isolate(), table, key,
                  {property_val_node, property_snapshot});
            }
            property_val_node_stack.resize_no_init(cont.index);
            DisallowGarbageCollection no_gc;
            Tagged<ObjectTwoHashTable> raw_table = *table;
            value = cont.scope.CloseAndEscape(value);
            val_node = cont.scope.CloseAndEscape(handle(raw_table, isolate_));
          } else {
            value = cont.scope.CloseAndEscape(value);
          }
          property_stack_.resize_no_init(cont.index);

          // Pop the continuation.
          cont = std::move(cont_stack.back());
          cont_stack.pop_back();
          // Consume to produced object.
          continue;
        }

        case JsonContinuation::kArrayElement: {
          // Store the previous element on the stack.
          element_stack_.emplace_back(value);
          if constexpr (should_track_json_source) {
            element_val_node_stack.emplace_back(val_node);
          }
          // Break to start producing the subsequent element value.
          if (V8_LIKELY(Check(JsonToken::COMMA))) break;

          value = BuildJsonArray(cont.index);
          Expect(JsonToken::RBRACK,
                 MessageTemplate::kJsonParseExpectedCommaOrRBrack);
          // Return the array.
          if constexpr (should_track_json_source) {
            size_t start = cont.index;
            int num_elements = static_cast<int>(element_stack_.size() - start);
            DirectHandle<FixedArray> val_node_and_snapshot_array =
                factory()->NewFixedArray(num_elements * 2);
            DisallowGarbageCollection no_gc;
            Tagged<FixedArray> raw_val_node_and_snapshot_array =
                *val_node_and_snapshot_array;
            for (int i = 0; i < num_elements; i++) {
              raw_val_node_and_snapshot_array->set(
                  i * 2, *element_val_node_stack[start + i]);
              raw_val_node_and_snapshot_array->set(i * 2 + 1,
                                                   *element_stack_[start + i]);
            }
            element_val_node_stack.resize_no_init(cont.index);
            value = cont.scope.CloseAndEscape(value);
            val_node = cont.scope.CloseAndEscape(
                handle(raw_val_node_and_snapshot_array, isolate_));
          } else {
            value = cont.scope.CloseAndEscape(value);
          }
          element_stack_.resize_no_init(cont.index);
          // Pop the continuation.
          cont = std::move(cont_stack.back());
          cont_stack.pop_back();
          // Consume the produced array.
          continue;
        }
      }

      // Done consuming a value. Produce next value.
      break;
    }
  }
}

template <typename Char>
void JsonParser<Char>::AdvanceToNonDecimal() {
  cursor_ =
      std::find_if(cursor_, end_, [](Char c) { return !IsDecimalDigit(c); });
}

template <typename Char>
Handle<Object> JsonParser<Char>::ParseJsonNumber() {
  double number;
  int sign = 1;

  {
    const Char* start = cursor_;
    DisallowGarbageCollection no_gc;

    base::uc32 c = *cursor_;
    if (c == '-') {
      sign = -1;
      c = NextCharacter();
    }

    if (c == '0') {
      // Prefix zero is only allowed if it's the only digit before
      // a decimal point or exponent.
      c = NextCharacter();
      if (base::IsInRange(c, 0,
                          static_cast<int32_t>(unibrow::Latin1::kMaxChar)) &&
          IsNumberPart(character_json_scan_flags[c])) {
        if (V8_UNLIKELY(IsDecimalDigit(c))) {
          AllowGarbageCollection allow_before_exception;
          ReportUnexpectedToken(JsonToken::NUMBER);
          return handle(Smi::FromInt(0), isolate_);
        }
      } else if (sign > 0) {
        return handle(Smi::FromInt(0), isolate_);
      }
    } else {
      const Char* smi_start = cursor_;
      static_assert(Smi::IsValid(-999999999));
      static_assert(Smi::IsValid(999999999));
      const int kMaxSmiLength = 9;
      int32_t i = 0;
      const Char* stop = cursor_ + kMaxSmiLength;
      if (stop > end_) stop = end_;
      while (cursor_ < stop && IsDecimalDigit(*cursor_)) {
        i = (i * 10) + ((*cursor_) - '0');
        cursor_++;
      }
      if (V8_UNLIKELY(smi_start == cursor_)) {
        AllowGarbageCollection allow_before_exception;
        ReportUnexpectedToken(
            JsonToken::ILLEGAL,
            MessageTemplate::kJsonParseNoNumberAfterMinusSign);
        return handle(Smi::FromInt(0), isolate_);
      }
      c = CurrentCharacter();
      if (!base::IsInRange(c, 0,
                           static_cast<int32_t>(unibrow::Latin1::kMaxChar)) ||
          !IsNumberPart(character_json_scan_flags[c])) {
        // Smi.
        // TODO(verwaest): Cache?
        return handle(Smi::FromInt(i * sign), isolate_);
      }
      AdvanceToNonDecimal();
    }

    if (CurrentCharacter() == '.') {
      c = NextCharacter();
      if (!IsDecimalDigit(c)) {
        AllowGarbageCollection allow_before_exception;
        ReportUnexpectedToken(
            JsonToken::ILLEGAL,
            MessageTemplate::kJsonParseUnterminatedFractionalNumber);
        return handle(Smi::FromInt(0), isolate_);
      }
      AdvanceToNonDecimal();
    }

    if (AsciiAlphaToLower(CurrentCharacter()) == 'e') {
      c = NextCharacter();
      if (c == '-' || c == '+') c = NextCharacter();
      if (!IsDecimalDigit(c)) {
        AllowGarbageCollection allow_before_exception;
        ReportUnexpectedToken(
            JsonToken::ILLEGAL,
            MessageTemplate::kJsonParseExponentPartMissingNumber);
        return handle(Smi::FromInt(0), isolate_);
      }
      AdvanceToNonDecimal();
    }

    base::Vector<const Char> chars(start, cursor_ - start);
    number = StringToDouble(chars,
                            NO_CONVERSION_FLAG,  // Hex, octal or trailing junk.
                            std::numeric_limits<double>::quiet_NaN());

    DCHECK(!std::isnan(number));
  }

  return factory()->NewNumber(number);
}

namespace {

template <typename Char>
bool Matches(base::Vector<const Char> chars, Handle<String> string) {
  DCHECK(!string.is_null());
  return string->IsEqualTo(chars);
}

}  // namespace

template <typename Char>
template <typename SinkSeqString>
Handle<String> JsonParser<Char>::DecodeString(
    const JsonString& string, Handle<SinkSeqString> intermediate,
    Handle<String> hint) {
  using SinkChar = typename SinkSeqString::Char;
  {
    DisallowGarbageCollection no_gc;
    SinkChar* dest = intermediate->GetChars(no_gc);
    if (!string.has_escape()) {
      DCHECK(!string.internalize());
      CopyChars(dest, chars_ + string.start(), string.length());
      return intermediate;
    }
    DecodeString(dest, string.start(), string.length());

    if (!string.internalize()) return intermediate;

    base::Vector<const SinkChar> data(dest, string.length());
    if (!hint.is_null() && Matches(data, hint)) return hint;
  }

  return factory()->InternalizeString(intermediate, 0, string.length());
}

template <typename Char>
Handle<String> JsonParser<Char>::MakeString(const JsonString& string,
                                            Handle<String> hint) {
  if (string.length() == 0) return factory()->empty_string();

  if (string.internalize() && !string.has_escape()) {
    if (!hint.is_null()) {
      base::Vector<const Char> data(chars_ + string.start(), string.length());
      if (Matches(data, hint)) return hint;
    }
    if (chars_may_relocate_) {
      return factory()->InternalizeString(Cast<SeqString>(source_),
                                          string.start(), string.length(),
                                          string.needs_conversion());
    }
    base::Vector<const Char> chars(chars_ + string.start(), string.length());
    return factory()->InternalizeString(chars, string.needs_conversion());
  }

  if (sizeof(Char) == 1 ? V8_LIKELY(!string.needs_conversion())
                        : string.needs_conversion()) {
    Handle<SeqOneByteString> intermediate =
        factory()->NewRawOneByteString(string.length()).ToHandleChecked();
    return DecodeString(string, intermediate, hint);
  }

  Handle<SeqTwoByteString> intermediate =
      factory()->NewRawTwoByteString(string.length()).ToHandleChecked();
  return DecodeString(string, intermediate, hint);
}

template <typename Char>
template <typename SinkChar>
void JsonParser<Char>::DecodeString(SinkChar* sink, int start, int length) {
  SinkChar* sink_start = sink;
  const Char* cursor = chars_ + start;
  while (true) {
    const Char* end = cursor + length - (sink - sink_start);
    cursor = std::find_if(cursor, end, [&sink](Char c) {
      if (c == '\\') return true;
      *sink++ = c;
      return false;
    });

    if (cursor == end) return;

    cursor++;

    switch (GetEscapeKind(character_json_scan_flags[*cursor])) {
      case EscapeKind::kSelf:
        *sink++ = *cursor;
        break;

      case EscapeKind::kBackspace:
        *sink++ = '\x08';
        break;

      case EscapeKind::kTab:
        *sink++ = '\x09';
        break;

      case EscapeKind::kNewLine:
        *sink++ = '\x0A';
        break;

      case EscapeKind::kFormFeed:
        *sink++ = '\x0C';
        break;

      case EscapeKind::kCarriageReturn:
        *sink++ = '\x0D';
        break;

      case EscapeKind::kUnicode: {
        base::uc32 value = 0;
        for (int i = 0; i < 4; i++) {
          value = value * 16 + base::HexValue(*++cursor);
        }
        if (value <=
            static_cast<base::uc32>(unibrow::Utf16::kMaxNonSurrogateCharCode)) {
          *sink++ = value;
        } else {
          *sink++ = unibrow::Utf16::LeadSurrogate(value);
          *sink++ = unibrow::Utf16::TrailSurrogate(value);
        }
        break;
      }

      case EscapeKind::kIllegal:
        UNREACHABLE();
    }
    cursor++;
  }
}

template <typename Char>
JsonString JsonParser<Char>::ScanJsonString(bool needs_internalization) {
  DisallowGarbageCollection no_gc;
  int start = position();
  int offset = start;
  bool has_escape = false;
  base::uc32 bits = 0;

  while (true) {
    cursor_ = std::find_if(cursor_, end_, [&bits](Char c) {
      if (sizeof(Char) == 2 && V8_UNLIKELY(c > unibrow::Latin1::kMaxChar)) {
        bits |= c;
        return false;
      }
      return MayTerminateJsonString(character_json_scan_flags[c]);
    });

    if (V8_UNLIKELY(is_at_end())) {
      AllowGarbageCollection allow_before_exception;
      ReportUnexpectedToken(JsonToken::ILLEGAL,
                            MessageTemplate::kJsonParseUnterminatedString);
      break;
    }

    if (*cursor_ == '"') {
      int end = position();
      advance();
      int length = end - offset;
      bool convert = sizeof(Char) == 1 ? bits > unibrow::Latin1::kMaxChar
                                       : bits <= unibrow::Latin1::kMaxChar;
      constexpr int kMaxInternalizedStringValueLength = 10;
      bool internalize =
          needs_internalization ||
          (sizeof(Char) == 1 && length < kMaxInternalizedStringValueLength);
      return JsonString(start, length, convert, internalize, has_escape);
    }

    if (*cursor_ == '\\') {
      has_escape = true;
      base::uc32 c = NextCharacter();
      if (V8_UNLIKELY(!base::IsInRange(
              c, 0, static_cast<int32_t>(unibrow::Latin1::kMaxChar)))) {
        AllowGarbageCollection allow_before_exception;
        ReportUnexpectedCharacter(c);
        break;
      }

      switch (GetEscapeKind(character_json_scan_flags[c])) {
        case EscapeKind::kSelf:
        case EscapeKind::kBackspace:
        case EscapeKind::kTab:
        case EscapeKind::kNewLine:
        case EscapeKind::kFormFeed:
        case EscapeKind::kCarriageReturn:
          offset += 1;
          break;

        case EscapeKind::kUnicode: {
          base::uc32 value = ScanUnicodeCharacter();
          if (value == kInvalidUnicodeCharacter) {
            AllowGarbageCollection allow_before_exception;
            ReportUnexpectedToken(JsonToken::ILLEGAL,
                                  MessageTemplate::kJsonParseBadUnicodeEscape);
            return JsonString();
          }
          bits |= value;
          // \uXXXX results in either 1 or 2 Utf16 characters, depending on
          // whether the decoded value requires a surrogate pair.
          offset += 5 - (value > static_cast<base::uc32>(
                                     unibrow::Utf16::kMaxNonSurrogateCharCode));
          break;
        }

        case EscapeKind::kIllegal:
          AllowGarbageCollection allow_before_exception;
          ReportUnexpectedToken(JsonToken::ILLEGAL,
                                MessageTemplate::kJsonParseBadEscapedCharacter);
          return JsonString();
      }

      advance();
      continue;
    }

    DCHECK_LT(*cursor_, 0x20);
    AllowGarbageCollection allow_before_exception;
    ReportUnexpectedToken(JsonToken::ILLEGAL,
                          MessageTemplate::kJsonParseBadControlCharacter);
    break;
  }

  return JsonString();
}

// Explicit instantiation.
template class JsonParser<uint8_t>;
template class JsonParser<uint16_t>;

}  // namespace internal
}  // namespace v8
```