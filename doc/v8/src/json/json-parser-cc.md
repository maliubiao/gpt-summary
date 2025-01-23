Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

1. **Initial Scan for Clues:** The first step is to quickly read through the code, paying attention to keywords, class names, function names, and included headers. This gives a general sense of the code's purpose. I noticed:
    * Headers like `<optional>`, `"src/base/strings.h"`, `"src/objects/...h"`, `"src/strings/...h"`, etc., which strongly suggest V8 internals, string manipulation, and object management.
    * The namespace `v8::internal`, confirming it's V8 internal code.
    * Class names like `JsonParser`, `JsonParseInternalizer`, `JsonToken`, and `JSDataObjectBuilder`, which are strong indicators of JSON parsing functionality.
    * Function names like `Internalize`, `ParseJson`, `ScanJsonString`, `SkipWhitespace`, and `ReportUnexpectedToken`, further reinforcing the JSON parsing theme.
    * The copyright notice at the beginning, confirming it's V8 code.

2. **Focusing on Key Classes and Functions:**  After the initial scan, I'd focus on the most prominent classes and their core methods:

    * **`JsonParser`:** This class appears to be the main entry point for parsing JSON. I'd look for its constructor, the `ParseJson` method, and any other methods that handle tokenization and value parsing (like `ScanJsonPropertyKey`, `ScanJsonString`). The template `<typename Char>` hints at supporting different character encodings.

    * **`JsonParseInternalizer`:** The name and the `Internalize` method strongly suggest this class is responsible for processing the parsed JSON structure and potentially applying a reviver function (as mentioned in the comments). The recursive nature of `InternalizeJsonProperty` is also apparent.

    * **Helper Structures/Enums:** I'd note `JsonToken` and the anonymous namespace containing `GetOneCharJsonToken`, as these are likely related to the tokenization process. The `EscapeKind` enum and the associated flag manipulation are likely for handling escape sequences in JSON strings.

    * **`JSDataObjectBuilder`:** This class seems interesting. Its name and comments suggest it's an optimization for creating JavaScript objects efficiently during parsing, potentially mirroring object literal creation.

3. **Tracing the Parsing Flow (Hypothetical):**  Based on the names and structure, I'd mentally trace a simplified JSON parsing flow:

    1. `JsonParser` is instantiated with the JSON string.
    2. `ParseJson` is called.
    3. `ParseJson` likely uses methods to tokenize the input (`GetOneCharJsonToken`, the `one_char_json_tokens` table, `SkipWhitespace`).
    4. It then parses different JSON values (objects, arrays, primitives) recursively. This is where `ParseJsonValue` comes into play.
    5. If a reviver is provided, `JsonParseInternalizer`'s `Internalize` is called to process the parsed structure. This likely involves traversing the parsed JSON and calling the reviver function for each key-value pair.
    6. Error handling (`ReportUnexpectedToken`, `ReportUnexpectedCharacter`) is used when invalid JSON is encountered.

4. **Checking for Torque (.tq):** The prompt specifically asks about `.tq` files. I checked the file extension (`.cc`) and concluded it's not a Torque file.

5. **Relating to JavaScript:**  The presence of classes like `JSObject` and the overall goal of parsing JSON immediately links it to JavaScript's `JSON.parse()` function. I would formulate a simple JavaScript example to illustrate this connection.

6. **Inferring Code Logic and Examples:**

    * **Tokenization:** The `one_char_json_tokens` table clearly maps characters to `JsonToken` values. I'd create simple examples to demonstrate this mapping.
    * **String Scanning:** The `ScanJsonString` function (even though the implementation isn't fully visible) likely handles escape sequences. I'd create examples with escaped characters to illustrate.
    * **Number Scanning:** Similar to strings, I'd infer that the code needs to handle different number formats (integers, decimals, exponents).
    * **Error Handling:** The `ReportUnexpectedToken` function suggests scenarios with invalid JSON. I'd create examples of common JSON syntax errors.
    * **Reviver Function:** The `JsonParseInternalizer` with the `Internalize` method strongly suggests the functionality of the optional reviver function in `JSON.parse()`. I'd create a JavaScript example demonstrating its usage.

7. **Considering Common Errors:** Based on my experience with JSON and JavaScript, I'd list common parsing errors like:
    * Missing quotes around strings.
    * Trailing commas in arrays or objects.
    * Incorrectly escaped characters.
    * Invalid JSON structures (e.g., multiple top-level elements).

8. **Summarizing Functionality:** Finally, I would synthesize all the observations into a concise summary of the file's purpose, highlighting its key responsibilities.

**Self-Correction/Refinement During the Process:**

* **Initially, I might have focused too much on the `JSDataObjectBuilder`**. While important for optimization, it's not the core function of the file. I'd adjust my focus to the primary parsing mechanisms.
* **If the code were more complex, I might have needed to look up V8 documentation or related source files** to understand certain classes or data structures. For example, if I weren't familiar with `Tagged` or `Handle`, I'd need to research those.
* **I'd continuously re-read the prompt** to ensure I'm addressing all the specific questions (Torque, JavaScript examples, code logic, errors).

By following this structured approach, I can systematically analyze the code snippet and provide a comprehensive and accurate description of its functionality.
这是目录为 `v8/src/json/json-parser.cc` 的一个 V8 源代码文件，让我们来分析一下它的功能：

**1. 主要功能：JSON 解析**

从文件名和代码内容来看，`json-parser.cc` 的核心功能是 **解析 JSON (JavaScript Object Notation) 字符串**。它负责将符合 JSON 语法规则的文本转换为 V8 引擎可以理解和操作的 JavaScript 对象。

**2. 详细功能分解：**

* **词法分析 (Tokenization):** 代码中定义了 `JsonToken` 枚举，以及 `GetOneCharJsonToken` 函数和 `one_char_json_tokens` 数组。这些用于将输入的 JSON 字符串分解成一个个独立的词法单元（token），例如：
    * 字符串（`"` 包裹的内容）
    * 数字
    * 布尔值 (`true`, `false`)
    * `null`
    * 方括号 (`[`, `]`) 表示数组
    * 花括号 (`{`, `}`) 表示对象
    * 冒号 (`:`) 分隔键值对
    * 逗号 (`,`) 分隔元素或键值对
    * 空格等空白字符

* **语法分析 (Parsing):**  `JsonParser` 类是进行语法分析的核心。它读取 token 流，并根据 JSON 的语法规则构建相应的 JavaScript 数据结构（例如，`JSObject`, `JSArray`, `HeapNumber`, `String` 等）。`ParseJsonValue` 或 `ParseJsonValueRecursive` 等方法负责递归地解析不同类型的 JSON 值。

* **错误处理:** 代码中包含 `ReportUnexpectedToken` 和 `ReportUnexpectedCharacter` 等方法，用于在解析过程中遇到不符合 JSON 语法规则的字符或 token 时报告错误。这些错误信息会转化为 JavaScript 的 `SyntaxError`。

* **Reviver 功能 (可选):** `JsonParseInternalizer` 类实现了 `JSON.parse()` 方法的可选 `reviver` 参数的功能。`Internalize` 和 `InternalizeJsonProperty` 方法允许用户自定义函数在解析过程中修改或过滤解析出的值。

* **性能优化:**  `JSDataObjectBuilder` 类看起来是为了优化创建 JavaScript 对象的过程，特别是在解析 JSON 对象字面量时。它尝试快速构建对象，避免不必要的 map 转换。

* **处理特殊字符串:** `IsSpecialString` 函数用于处理一些特殊情况，比如 `undefined`, `NaN`, `Infinity` 以及 `"[object Object]"` 被直接传递给 `JSON.parse` 的情况。

**如果 `v8/src/json/json-parser.cc` 以 `.tq` 结尾：**

如果文件以 `.tq` 结尾，那么它就是一个 **V8 Torque 源代码**。Torque 是一种 V8 内部使用的类型化的中间表示和代码生成器。在这种情况下，`json-parser.tq` 会使用 Torque 的语法来定义 JSON 解析的逻辑，并最终被编译成 C++ 代码。

**与 JavaScript 功能的关系及示例：**

`v8/src/json/json-parser.cc` 直接对应于 JavaScript 中的全局对象 `JSON` 的 `parse()` 方法。

**JavaScript 示例：**

```javascript
const jsonString = '{"name": "John Doe", "age": 30, "isEmployed": true, "address": {"city": "New York", "zip": "10001"}, "hobbies": ["reading", "coding"]}';

try {
  const parsedObject = JSON.parse(jsonString);
  console.log(parsedObject.name); // 输出: John Doe
  console.log(parsedObject.address.city); // 输出: New York
} catch (error) {
  console.error("JSON 解析出错:", error);
}

// 使用 reviver 函数的例子
const jsonStringWithDates = '{"name": "Jane Doe", "birthDate": "2000-01-01T00:00:00.000Z"}';
const parsedObjectWithDate = JSON.parse(jsonStringWithDates, (key, value) => {
  if (key === 'birthDate') {
    return new Date(value);
  }
  return value;
});
console.log(parsedObjectWithDate.birthDate instanceof Date); // 输出: true
```

**代码逻辑推理及示例：**

**假设输入 JSON 字符串：** `{"a": 10, "b": "hello"}`

1. **词法分析：** `JsonParser` 会将输入分解为以下 token 序列：
   `{`, `"a"`, `:`, `10`, `,`, `"b"`, `:`, `"hello"`, `}`

2. **语法分析：**
   - 遇到 `{`，开始解析一个 JSON 对象。
   - 遇到 `"a"`，解析为一个字符串键。
   - 遇到 `:`，表示键值对的分隔。
   - 遇到 `10`，解析为一个数字值。
   - 遇到 `,`，表示下一个键值对。
   - 遇到 `"b"`，解析为另一个字符串键。
   - 遇到 `:`。
   - 遇到 `"hello"`，解析为一个字符串值。
   - 遇到 `}`，表示对象解析完成。

3. **输出：** V8 会创建一个 JavaScript 对象，其结构等同于：
   ```javascript
   { a: 10, b: "hello" }
   ```

**用户常见的编程错误及示例：**

* **忘记使用引号包裹字符串键：**
   ```json
   { a: 10 } // 错误，键 "a" 应该用双引号包裹
   ```
   V8 的 JSON 解析器会抛出 `SyntaxError: Unexpected token a in JSON at position 2` 类似的错误。

* **在最后一个元素或键值对后添加逗号：**
   ```json
   {"a": 10, "b": 20,} // 错误，尾部逗号是不允许的
   [1, 2, 3,]         // 错误，尾部逗号是不允许的
   ```
   V8 会抛出 `SyntaxError: Unexpected token } in JSON at position 17` 或类似的错误。

* **使用了 JSON 不支持的 JavaScript 语法：**
   ```json
   { name: 'John' } // 错误，JSON 字符串值必须用双引号
   ```
   V8 会抛出 `SyntaxError: Unexpected token ' in JSON at position 9` 类似的错误。

* **不匹配的括号或引号：**
   ```json
   {"a": 10  // 错误，缺少闭合的花括号
   ```
   V8 会抛出 `SyntaxError: Unexpected end of JSON input` 或类似的错误。

* **使用了单引号而不是双引号包裹字符串：**
   ```json
   {'a': 10} // 错误，JSON 规范要求使用双引号
   ```
   V8 会抛出 `SyntaxError: Unexpected token ' in JSON at position 2` 类似的错误。

**功能归纳（第 1 部分）：**

`v8/src/json/json-parser.cc` 的主要功能是 **实现 V8 引擎中 JSON 字符串的解析**。它负责将输入的 JSON 文本进行词法和语法分析，将其转换为 V8 可以操作的 JavaScript 对象。该文件还包含了处理解析错误和实现 `JSON.parse()` 方法可选的 `reviver` 功能的代码。此外，它还包含了一些性能优化的机制，例如 `JSDataObjectBuilder` 用于加速对象创建。 简而言之，它是 V8 中 `JSON.parse()` 功能的核心实现。

### 提示词
```
这是目录为v8/src/json/json-parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/json/json-parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/json/json-parser.h"

#include <optional>

#include "src/base/strings.h"
#include "src/builtins/builtins.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/common/message-template.h"
#include "src/debug/debug.h"
#include "src/execution/frames-inl.h"
#include "src/heap/factory.h"
#include "src/numbers/conversions.h"
#include "src/numbers/hash-seed-inl.h"
#include "src/objects/elements-kind.h"
#include "src/objects/field-type.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/map-updater.h"
#include "src/objects/objects-inl.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/property-details.h"
#include "src/roots/roots.h"
#include "src/strings/char-predicates-inl.h"
#include "src/strings/string-hasher.h"
#include "src/utils/boxed-float.h"

namespace v8 {
namespace internal {

namespace {

constexpr JsonToken GetOneCharJsonToken(uint8_t c) {
  // clang-format off
  return
     c == '"' ? JsonToken::STRING :
     IsDecimalDigit(c) ?  JsonToken::NUMBER :
     c == '-' ? JsonToken::NUMBER :
     c == '[' ? JsonToken::LBRACK :
     c == '{' ? JsonToken::LBRACE :
     c == ']' ? JsonToken::RBRACK :
     c == '}' ? JsonToken::RBRACE :
     c == 't' ? JsonToken::TRUE_LITERAL :
     c == 'f' ? JsonToken::FALSE_LITERAL :
     c == 'n' ? JsonToken::NULL_LITERAL :
     c == ' ' ? JsonToken::WHITESPACE :
     c == '\t' ? JsonToken::WHITESPACE :
     c == '\r' ? JsonToken::WHITESPACE :
     c == '\n' ? JsonToken::WHITESPACE :
     c == ':' ? JsonToken::COLON :
     c == ',' ? JsonToken::COMMA :
     JsonToken::ILLEGAL;
  // clang-format on
}

// Table of one-character tokens, by character (0x00..0xFF only).
static const constexpr JsonToken one_char_json_tokens[256] = {
#define CALL_GET_SCAN_FLAGS(N) GetOneCharJsonToken(N),
    INT_0_TO_127_LIST(CALL_GET_SCAN_FLAGS)
#undef CALL_GET_SCAN_FLAGS
#define CALL_GET_SCAN_FLAGS(N) GetOneCharJsonToken(128 + N),
        INT_0_TO_127_LIST(CALL_GET_SCAN_FLAGS)
#undef CALL_GET_SCAN_FLAGS
};

enum class EscapeKind : uint8_t {
  kIllegal,
  kSelf,
  kBackspace,
  kTab,
  kNewLine,
  kFormFeed,
  kCarriageReturn,
  kUnicode
};

using EscapeKindField = base::BitField8<EscapeKind, 0, 3>;
using MayTerminateStringField = EscapeKindField::Next<bool, 1>;
using NumberPartField = MayTerminateStringField::Next<bool, 1>;

constexpr bool MayTerminateJsonString(uint8_t flags) {
  return MayTerminateStringField::decode(flags);
}

constexpr EscapeKind GetEscapeKind(uint8_t flags) {
  return EscapeKindField::decode(flags);
}

constexpr bool IsNumberPart(uint8_t flags) {
  return NumberPartField::decode(flags);
}

constexpr uint8_t GetJsonScanFlags(uint8_t c) {
  // clang-format off
  return (c == 'b' ? EscapeKindField::encode(EscapeKind::kBackspace)
          : c == 't' ? EscapeKindField::encode(EscapeKind::kTab)
          : c == 'n' ? EscapeKindField::encode(EscapeKind::kNewLine)
          : c == 'f' ? EscapeKindField::encode(EscapeKind::kFormFeed)
          : c == 'r' ? EscapeKindField::encode(EscapeKind::kCarriageReturn)
          : c == 'u' ? EscapeKindField::encode(EscapeKind::kUnicode)
          : c == '"' ? EscapeKindField::encode(EscapeKind::kSelf)
          : c == '\\' ? EscapeKindField::encode(EscapeKind::kSelf)
          : c == '/' ? EscapeKindField::encode(EscapeKind::kSelf)
          : EscapeKindField::encode(EscapeKind::kIllegal)) |
         (c < 0x20 ? MayTerminateStringField::encode(true)
          : c == '"' ? MayTerminateStringField::encode(true)
          : c == '\\' ? MayTerminateStringField::encode(true)
          : MayTerminateStringField::encode(false)) |
         NumberPartField::encode(c == '.' ||
                                 c == 'e' ||
                                 c == 'E' ||
                                 IsDecimalDigit(c) ||
                                 c == '-' ||
                                 c == '+');
  // clang-format on
}

// Table of one-character scan flags, by character (0x00..0xFF only).
static const constexpr uint8_t character_json_scan_flags[256] = {
#define CALL_GET_SCAN_FLAGS(N) GetJsonScanFlags(N),
    INT_0_TO_127_LIST(CALL_GET_SCAN_FLAGS)
#undef CALL_GET_SCAN_FLAGS
#define CALL_GET_SCAN_FLAGS(N) GetJsonScanFlags(128 + N),
        INT_0_TO_127_LIST(CALL_GET_SCAN_FLAGS)
#undef CALL_GET_SCAN_FLAGS
};

}  // namespace

MaybeHandle<Object> JsonParseInternalizer::Internalize(
    Isolate* isolate, Handle<Object> result, Handle<Object> reviver,
    Handle<String> source, MaybeHandle<Object> val_node) {
  DCHECK(IsCallable(*reviver));
  JsonParseInternalizer internalizer(isolate, Cast<JSReceiver>(reviver),
                                     source);
  Handle<JSObject> holder =
      isolate->factory()->NewJSObject(isolate->object_function());
  Handle<String> name = isolate->factory()->empty_string();
  JSObject::AddProperty(isolate, holder, name, result, NONE);
  return internalizer.InternalizeJsonProperty<kWithSource>(
      holder, name, val_node.ToHandleChecked(), result);
}

template <JsonParseInternalizer::WithOrWithoutSource with_source>
MaybeHandle<Object> JsonParseInternalizer::InternalizeJsonProperty(
    Handle<JSReceiver> holder, Handle<String> name, Handle<Object> val_node,
    Handle<Object> snapshot) {
  DCHECK_EQ(with_source == kWithSource,
            !val_node.is_null() && !snapshot.is_null());
  DCHECK(IsCallable(*reviver_));
  HandleScope outer_scope(isolate_);
  Handle<Object> value;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate_, value, Object::GetPropertyOrElement(isolate_, holder, name));

  // When with_source == kWithSource, the source text is passed to the reviver
  // if the reviver has not mucked with the originally parsed value.
  //
  // When with_source == kWithoutSource, this is unused.
  bool pass_source_to_reviver =
      with_source == kWithSource && Object::SameValue(*value, *snapshot);

  if (IsJSReceiver(*value)) {
    Handle<JSReceiver> object = Cast<JSReceiver>(value);
    Maybe<bool> is_array = Object::IsArray(object);
    if (is_array.IsNothing()) return MaybeHandle<Object>();
    if (is_array.FromJust()) {
      Handle<Object> length_object;
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate_, length_object,
          Object::GetLengthFromArrayLike(isolate_, object));
      double length = Object::NumberValue(*length_object);
      if (pass_source_to_reviver) {
        auto val_nodes_and_snapshots = Cast<FixedArray>(val_node);
        int snapshot_length = val_nodes_and_snapshots->length() / 2;
        for (int i = 0; i < length; i++) {
          HandleScope inner_scope(isolate_);
          DirectHandle<Object> index = isolate_->factory()->NewNumber(i);
          Handle<String> index_name =
              isolate_->factory()->NumberToString(index);
          // Even if the array pointer snapshot matched, it's possible the
          // array had new elements added that are not in the snapshotted
          // elements.
          const bool rv =
              i < snapshot_length
                  ? RecurseAndApply<kWithSource>(
                        object, index_name,
                        handle(val_nodes_and_snapshots->get(i * 2), isolate_),
                        handle(val_nodes_and_snapshots->get(i * 2 + 1),
                               isolate_))
                  : RecurseAndApply<kWithoutSource>(
                        object, index_name, Handle<Object>(), Handle<Object>());
          if (!rv) {
            return MaybeHandle<Object>();
          }
        }
      } else {
        for (int i = 0; i < length; i++) {
          HandleScope inner_scope(isolate_);
          DirectHandle<Object> index = isolate_->factory()->NewNumber(i);
          Handle<String> index_name =
              isolate_->factory()->NumberToString(index);
          if (!RecurseAndApply<kWithoutSource>(
                  object, index_name, Handle<Object>(), Handle<Object>())) {
            return MaybeHandle<Object>();
          }
        }
      }
    } else {
      Handle<FixedArray> contents;
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate_, contents,
          KeyAccumulator::GetKeys(isolate_, object, KeyCollectionMode::kOwnOnly,
                                  ENUMERABLE_STRINGS,
                                  GetKeysConversion::kConvertToString));
      if (pass_source_to_reviver) {
        auto val_nodes_and_snapshots = Cast<ObjectTwoHashTable>(val_node);
        for (int i = 0; i < contents->length(); i++) {
          HandleScope inner_scope(isolate_);
          Handle<String> key_name(Cast<String>(contents->get(i)), isolate_);
          auto property_val_node_and_snapshot =
              val_nodes_and_snapshots->Lookup(isolate_, key_name);
          Handle<Object> property_val_node(property_val_node_and_snapshot[0],
                                           isolate_);
          Handle<Object> property_snapshot(property_val_node_and_snapshot[1],
                                           isolate_);
          // Even if the object pointer snapshot matched, it's possible the
          // object had new properties added that are not in the snapshotted
          // contents.
          const bool rv =
              !IsTheHole(*property_snapshot)
                  ? RecurseAndApply<kWithSource>(
                        object, key_name, property_val_node, property_snapshot)
                  : RecurseAndApply<kWithoutSource>(
                        object, key_name, Handle<Object>(), Handle<Object>());
          if (!rv) {
            return MaybeHandle<Object>();
          }
        }
      } else {
        for (int i = 0; i < contents->length(); i++) {
          HandleScope inner_scope(isolate_);
          Handle<String> key_name(Cast<String>(contents->get(i)), isolate_);
          if (!RecurseAndApply<kWithoutSource>(
                  object, key_name, Handle<Object>(), Handle<Object>())) {
            return MaybeHandle<Object>();
          }
        }
      }
    }
  }

  Handle<JSObject> context =
      isolate_->factory()->NewJSObject(isolate_->object_function());
  if (pass_source_to_reviver && IsString(*val_node)) {
    JSReceiver::CreateDataProperty(isolate_, context,
                                   isolate_->factory()->source_string(),
                                   val_node, Just(kThrowOnError))
        .Check();
  }
  Handle<Object> argv[] = {name, value, context};
  Handle<Object> result;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate_, result, Execution::Call(isolate_, reviver_, holder, 3, argv));
  return outer_scope.CloseAndEscape(result);
}

template <JsonParseInternalizer::WithOrWithoutSource with_source>
bool JsonParseInternalizer::RecurseAndApply(Handle<JSReceiver> holder,
                                            Handle<String> name,
                                            Handle<Object> val_node,
                                            Handle<Object> snapshot) {
  STACK_CHECK(isolate_, false);
  DCHECK(IsCallable(*reviver_));
  Handle<Object> result;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate_, result,
      InternalizeJsonProperty<with_source>(holder, name, val_node, snapshot),
      false);
  Maybe<bool> change_result = Nothing<bool>();
  if (IsUndefined(*result, isolate_)) {
    change_result = JSReceiver::DeletePropertyOrElement(isolate_, holder, name,
                                                        LanguageMode::kSloppy);
  } else {
    PropertyDescriptor desc;
    desc.set_value(Cast<JSAny>(result));
    desc.set_configurable(true);
    desc.set_enumerable(true);
    desc.set_writable(true);
    change_result = JSReceiver::DefineOwnProperty(isolate_, holder, name, &desc,
                                                  Just(kDontThrow));
  }
  MAYBE_RETURN(change_result, false);
  return true;
}

template <typename Char>
JsonParser<Char>::JsonParser(Isolate* isolate, Handle<String> source)
    : isolate_(isolate),
      hash_seed_(HashSeed(isolate)),
      object_constructor_(isolate_->object_function()),
      original_source_(source) {
  size_t start = 0;
  size_t length = source->length();
  PtrComprCageBase cage_base(isolate);
  if (IsSlicedString(*source, cage_base)) {
    Tagged<SlicedString> string = Cast<SlicedString>(*source);
    start = string->offset();
    Tagged<String> parent = string->parent();
    if (IsThinString(parent, cage_base))
      parent = Cast<ThinString>(parent)->actual();
    source_ = handle(parent, isolate);
  } else {
    source_ = String::Flatten(isolate, source);
  }

  if (StringShape(*source_, cage_base).IsExternal()) {
    chars_ =
        static_cast<const Char*>(Cast<SeqExternalString>(*source_)->GetChars());
    chars_may_relocate_ = false;
  } else {
    DisallowGarbageCollection no_gc;
    isolate->main_thread_local_heap()->AddGCEpilogueCallback(
        UpdatePointersCallback, this);
    chars_ = Cast<SeqString>(*source_)->GetChars(no_gc);
    chars_may_relocate_ = true;
  }
  cursor_ = chars_ + start;
  end_ = cursor_ + length;
}

template <typename Char>
bool JsonParser<Char>::IsSpecialString() {
  // The special cases are undefined, NaN, Infinity, and {} being passed to the
  // parse method
  int offset = IsSlicedString(*original_source_)
                   ? Cast<SlicedString>(*original_source_)->offset()
                   : 0;
  size_t length = original_source_->length();
#define CASES(V)       \
  V("[object Object]") \
  V("undefined")       \
  V("Infinity")        \
  V("NaN")
  switch (length) {
#define CASE(n)          \
  case arraysize(n) - 1: \
    return CompareCharsEqual(chars_ + offset, n, arraysize(n) - 1);
    CASES(CASE)
    default:
      return false;
  }
#undef CASE
#undef CASES
}

template <typename Char>
MessageTemplate JsonParser<Char>::GetErrorMessageWithEllipses(
    DirectHandle<Object>& arg, DirectHandle<Object>& arg2, int pos) {
  MessageTemplate message;
  Factory* factory = this->factory();
  arg = factory->LookupSingleCharacterStringFromCode(*cursor_);
  int origin_source_length = original_source_->length();
  // only provide context for strings with at least
  // kMinOriginalSourceLengthForContext charcacters in length
  if (origin_source_length >= kMinOriginalSourceLengthForContext) {
    int substring_start = 0;
    int substring_end = origin_source_length;
    if (pos < kMaxContextCharacters) {
      message =
          MessageTemplate::kJsonParseUnexpectedTokenStartStringWithContext;
      // Output the string followed by elipses
      substring_end = pos + kMaxContextCharacters;
    } else if (pos >= kMaxContextCharacters &&
               pos < origin_source_length - kMaxContextCharacters) {
      message =
          MessageTemplate::kJsonParseUnexpectedTokenSurroundStringWithContext;
      // Add context before and after position of bad token surrounded by
      // elipses
      substring_start = pos - kMaxContextCharacters;
      substring_end = pos + kMaxContextCharacters;
    } else {
      message = MessageTemplate::kJsonParseUnexpectedTokenEndStringWithContext;
      // Add ellipses followed by some context before bad token
      substring_start = pos - kMaxContextCharacters;
    }
    arg2 =
        factory->NewSubString(original_source_, substring_start, substring_end);
  } else {
    arg2 = original_source_;
    // Output the entire string without ellipses but provide the token which
    // was unexpected
    message = MessageTemplate::kJsonParseUnexpectedTokenShortString;
  }
  return message;
}

template <typename Char>
MessageTemplate JsonParser<Char>::LookUpErrorMessageForJsonToken(
    JsonToken token, DirectHandle<Object>& arg, DirectHandle<Object>& arg2,
    int pos) {
  MessageTemplate message;
  switch (token) {
    case JsonToken::EOS:
      message = MessageTemplate::kJsonParseUnexpectedEOS;
      break;
    case JsonToken::NUMBER:
      message = MessageTemplate::kJsonParseUnexpectedTokenNumber;
      break;
    case JsonToken::STRING:
      message = MessageTemplate::kJsonParseUnexpectedTokenString;
      break;
    default:
      // Output entire string without ellipses and don't provide the token
      // that was unexpected because it makes the error messages more confusing
      if (IsSpecialString()) {
        arg = original_source_;
        message = MessageTemplate::kJsonParseShortString;
      } else {
        message = GetErrorMessageWithEllipses(arg, arg2, pos);
      }
  }
  return message;
}

template <typename Char>
void JsonParser<Char>::CalculateFileLocation(DirectHandle<Object>& line,
                                             DirectHandle<Object>& column) {
  // JSON allows only \r and \n as line terminators.
  // (See https://www.json.org/json-en.html - "whitespace")
  int line_number = 1;
  const Char* start =
      chars_ + (IsSlicedString(*original_source_)
                    ? Cast<SlicedString>(*original_source_)->offset()
                    : 0);
  const Char* last_line_break = start;
  const Char* cursor = start;
  const Char* end = cursor_;  // cursor_ points to the position of the error.
  for (; cursor < end; ++cursor) {
    if (*cursor == '\r' && cursor < end - 1 && cursor[1] == '\n') {
      // \r\n counts as a single line terminator, as of
      // https://tc39.es/ecma262/#sec-line-terminators. JSON itself does not
      // have a notion of lines or line terminators.
      ++cursor;
    }
    if (*cursor == '\r' || *cursor == '\n') {
      ++line_number;
      last_line_break = cursor + 1;
    }
  }
  int column_number = 1 + static_cast<int>(cursor - last_line_break);
  line = direct_handle(Smi::FromInt(line_number), isolate());
  column = direct_handle(Smi::FromInt(column_number), isolate());
}

template <typename Char>
void JsonParser<Char>::ReportUnexpectedToken(
    JsonToken token, std::optional<MessageTemplate> errorMessage) {
  // Some exception (for example stack overflow) was already thrown.
  if (isolate_->has_exception()) return;

  // Parse failed. Current character is the unexpected token.
  Factory* factory = this->factory();
  int offset = IsSlicedString(*original_source_)
                   ? Cast<SlicedString>(*original_source_)->offset()
                   : 0;
  int pos = position() - offset;
  DirectHandle<Object> arg(Smi::FromInt(pos), isolate());
  DirectHandle<Object> arg2;
  DirectHandle<Object> arg3;
  CalculateFileLocation(arg2, arg3);

  MessageTemplate message =
      errorMessage ? errorMessage.value()
                   : LookUpErrorMessageForJsonToken(token, arg, arg2, pos);

  Handle<Script> script(factory->NewScript(original_source_));
  DCHECK_IMPLIES(isolate_->NeedsSourcePositions(), script->has_line_ends());
  DebuggableStackFrameIterator it(isolate_);
  if (!it.done() && it.is_javascript()) {
    FrameSummary summary = it.GetTopValidFrame();
    script->set_eval_from_shared(summary.AsJavaScript().function()->shared());
    if (IsScript(*summary.script())) {
      script->set_origin_options(
          Cast<Script>(*summary.script())->origin_options());
    }
  }

  // We should sent compile error event because we compile JSON object in
  // separated source file.
  isolate()->debug()->OnCompileError(script);
  MessageLocation location(script, pos, pos + 1);
  isolate()->ThrowAt(factory->NewSyntaxError(message, arg, arg2, arg3),
                     &location);

  // Move the cursor to the end so we won't be able to proceed parsing.
  cursor_ = end_;
}

template <typename Char>
void JsonParser<Char>::ReportUnexpectedCharacter(base::uc32 c) {
  JsonToken token = JsonToken::ILLEGAL;
  if (c == kEndOfString) {
    token = JsonToken::EOS;
  } else if (c <= unibrow::Latin1::kMaxChar) {
    token = one_char_json_tokens[c];
  }
  return ReportUnexpectedToken(token);
}

template <typename Char>
JsonParser<Char>::~JsonParser() {
  if (StringShape(*source_).IsExternal()) {
    // Check that the string shape hasn't changed. Otherwise our GC hooks are
    // broken.
    Cast<SeqExternalString>(*source_);
  } else {
    // Check that the string shape hasn't changed. Otherwise our GC hooks are
    // broken.
    Cast<SeqString>(*source_);
    isolate()->main_thread_local_heap()->RemoveGCEpilogueCallback(
        UpdatePointersCallback, this);
  }
}

template <typename Char>
MaybeHandle<Object> JsonParser<Char>::ParseJson(DirectHandle<Object> reviver) {
  Handle<Object> result;
  // Only record the val node when reviver is callable.
  bool reviver_is_callable = IsCallable(*reviver);
  bool should_track_json_source = reviver_is_callable;
  if (V8_UNLIKELY(should_track_json_source)) {
    ASSIGN_RETURN_ON_EXCEPTION(isolate(), result, ParseJsonValue<true>());
  } else {
    ASSIGN_RETURN_ON_EXCEPTION(isolate(), result, ParseJsonValueRecursive());
  }

  if (!Check(JsonToken::EOS)) {
    ReportUnexpectedToken(
        peek(), MessageTemplate::kJsonParseUnexpectedNonWhiteSpaceCharacter);
    return MaybeHandle<Object>();
  }
  if (isolate_->has_exception()) {
    return MaybeHandle<Object>();
  }
  return result;
}

MaybeHandle<Object> InternalizeJsonProperty(Handle<JSObject> holder,
                                            Handle<String> key);

namespace {
template <typename Char>
JsonToken GetTokenForCharacter(Char c) {
  return V8_LIKELY(c <= unibrow::Latin1::kMaxChar) ? one_char_json_tokens[c]
                                                   : JsonToken::ILLEGAL;
}
}  // namespace

template <typename Char>
void JsonParser<Char>::SkipWhitespace() {
  JsonToken local_next = JsonToken::EOS;

  cursor_ = std::find_if(cursor_, end_, [&](Char c) {
    JsonToken current = GetTokenForCharacter(c);
    bool result = current != JsonToken::WHITESPACE;
    if (V8_LIKELY(result)) local_next = current;
    return result;
  });

  next_ = local_next;
}

template <typename Char>
base::uc32 JsonParser<Char>::ScanUnicodeCharacter() {
  base::uc32 value = 0;
  for (int i = 0; i < 4; i++) {
    int digit = base::HexValue(NextCharacter());
    if (V8_UNLIKELY(digit < 0)) return kInvalidUnicodeCharacter;
    value = value * 16 + digit;
  }
  return value;
}

// Parse any JSON value.
template <typename Char>
JsonString JsonParser<Char>::ScanJsonPropertyKey(JsonContinuation* cont) {
  {
    DisallowGarbageCollection no_gc;
    const Char* start = cursor_;
    base::uc32 first = CurrentCharacter();
    if (first == '\\' && NextCharacter() == 'u') first = ScanUnicodeCharacter();
    if (IsDecimalDigit(first)) {
      if (first == '0') {
        if (NextCharacter() == '"') {
          advance();
          // Record element information.
          cont->elements++;
          DCHECK_LE(0, cont->max_index);
          return JsonString(0);
        }
      } else {
        uint32_t index = first - '0';
        while (true) {
          cursor_ = std::find_if(cursor_ + 1, end_, [&index](Char c) {
            return !TryAddArrayIndexChar(&index, c);
          });

          if (CurrentCharacter() == '"') {
            advance();
            // Record element information.
            cont->elements++;
            cont->max_index = std::max(cont->max_index, index);
            return JsonString(index);
          }

          if (CurrentCharacter() == '\\' && NextCharacter() == 'u') {
            if (TryAddArrayIndexChar(&index, ScanUnicodeCharacter())) continue;
          }

          break;
        }
      }
    }
    // Reset cursor_ to start if the key is not an index.
    cursor_ = start;
  }
  return ScanJsonString(true);
}

class FoldedMutableHeapNumberAllocation {
 public:
  // TODO(leszeks): If allocation alignment is ever enabled, we'll need to add
  // padding fillers between heap numbers.
  static_assert(!USE_ALLOCATION_ALIGNMENT_BOOL);

  FoldedMutableHeapNumberAllocation(Isolate* isolate, int count) {
    if (count == 0) return;
    int size = count * sizeof(HeapNumber);
    raw_bytes_ = isolate->factory()->NewByteArray(size);
  }

  Handle<ByteArray> raw_bytes() const { return raw_bytes_; }

 private:
  Handle<ByteArray> raw_bytes_ = {};
};

class FoldedMutableHeapNumberAllocator {
 public:
  FoldedMutableHeapNumberAllocator(
      Isolate* isolate, FoldedMutableHeapNumberAllocation* allocation,
      DisallowGarbageCollection& no_gc)
      : isolate_(isolate), roots_(isolate) {
    if (allocation->raw_bytes().is_null()) return;

    raw_bytes_ = allocation->raw_bytes();
    mutable_double_address_ =
        reinterpret_cast<Address>(allocation->raw_bytes()->begin());
  }

  ~FoldedMutableHeapNumberAllocator() {
    // Make all mutable HeapNumbers alive.
    if (mutable_double_address_ == 0) {
      DCHECK(raw_bytes_.is_null());
      return;
    }

    DCHECK_EQ(mutable_double_address_,
              reinterpret_cast<Address>(raw_bytes_->end()));
    // Before setting the length of mutable_double_buffer back to zero, we
    // must ensure that the sweeper is not running or has already swept the
    // object's page. Otherwise the GC can add the contents of
    // mutable_double_buffer to the free list.
    isolate_->heap()->EnsureSweepingCompletedForObject(*raw_bytes_);
    raw_bytes_->set_length(0);
  }

  Tagged<HeapNumber> AllocateNext(ReadOnlyRoots roots, Float64 value) {
    DCHECK_GE(mutable_double_address_,
              reinterpret_cast<Address>(raw_bytes_->begin()));
    Tagged<HeapObject> hn = HeapObject::FromAddress(mutable_double_address_);
    hn->set_map_after_allocation(isolate_, roots.heap_number_map());
    Cast<HeapNumber>(hn)->set_value_as_bits(value.get_bits());
    mutable_double_address_ +=
        ALIGN_TO_ALLOCATION_ALIGNMENT(sizeof(HeapNumber));
    DCHECK_LE(mutable_double_address_,
              reinterpret_cast<Address>(raw_bytes_->end()));
    return Cast<HeapNumber>(hn);
  }

 private:
  Isolate* isolate_;
  ReadOnlyRoots roots_;
  Handle<ByteArray> raw_bytes_ = {};
  Address mutable_double_address_ = 0;
};

// JSDataObjectBuilder is a helper for efficiently building a data object,
// similar (in semantics and efficiency) to a JS object literal, based on
// key/value pairs.
//
// The JSDataObjectBuilder works by first trying to find the right map for the
// object, and then letting the caller stamp out the object fields linearly.
// There are several fast paths that can be fallen out of; if the builder bails
// out, then it's still possible to stamp out the object partially based on the
// last map found, and then continue with slow object setup afterward.
//
// The maps start from the object literal cache (to try to share maps with
// equivalent object literals in JS code). From there, when adding properties,
// there are several fast paths that the builder follows:
//
//   1. At construction, it can be passed an expected final map for the object
//      (e.g. cached from previous runs, or assumed from surrounding objects).
//      If given, then we first check whether the property matches the
//      entry in the DescriptorArray of the final map; if yes, then we don't
//      need to do any map transitions.
//   2. When given a property key, it looks for whether there is exactly one
//      transition away from the current map ("ExpectedTransition").
//      The expected key is passed as a hint to the current property key
//      getter, for e.g. faster internalised string materialisation.
//   3. Otherwise, it searches for whether there is any transition in the
//      current map that matches the key.
//   4. For all of the above, it checks whether the field represntation of the
//      found map matches the representation of the value. If it doesn't, it
//      migrates the map, potentially deprecating it too.
//   5. If there is no transition, it tries to allocate a new map transition,
//      bailing out if this fails.
class JSDataObjectBuilder {
 public:
  // HeapNumberMode determines whether incoming HeapNumber values will be
  // guaranteed to be uniquely owned by this object, and therefore can be used
  // directly as mutable HeapNumbers for double representation fields.
  enum HeapNumberMode {
    kNormalHeapNumbers,
    kHeapNumbersGuaranteedUniquelyOwned
  };
  JSDataObjectBuilder(Isolate* isolate, ElementsKind elements_kind,
                      int expected_named_properties,
                      Handle<Map> expected_final_map,
                      HeapNumberMode heap_number_mode)
      : isolate_(isolate),
        elements_kind_(elements_kind),
        expected_property_count_(expected_named_properties),
        heap_number_mode_(heap_number_mode),
        expected_final_map_(expected_final_map) {
    if (!TryInitializeMapFromExpectedFinalMap()) {
      InitializeMapFromZero();
    }
  }

  // Builds and returns an object whose properties are based on a property
  // iterator.
  //
  // Expects an iterator of the form:
  //
  // struct Iterator {
  //   void Advance();
  //   bool Done();
  //
  //   // Get the key of the current property, optionally returning the hinted
  //   // expected key if applicable.
  //   Handle<String> GetKey(Handle<String> expected_key_hint);
  //
  //   // Get the value of the current property. `will_revisit_value` is true
  //   // if this value will need to be revisited later via RevisitValues().
  //   Handle<Object> GetValue(bool will_revisit_value);
  //
  //   // Return an iterator over the values that were already visited by
  //   // GetValue. Might require caching those values if necessary.
  //   ValueIterator RevisitValues();
  // }
  template <typename PropertyIterator>
  Handle<JSObject> BuildFromIterator(
      PropertyIterator&& it, MaybeHandle<FixedArrayBase> maybe_elements = {}) {
    Handle<String> failed_property_add_key;
    for (; !it.Done(); it.Advance()) {
      Handle<String> property_key;
      if (!TryAddFastPropertyForValue(
              it.GetKeyChars(),
              [&](Handle<String> expected_key) {
                return property_key = it.GetKey(expected_key);
              },
              [&]() { return it.GetValue(true); })) {
        failed_property_add_key = property_key;
        break;
      }
    }

    Handle<FixedArrayBase> elements;
    if (!maybe_elements.ToHandle(&elements)) {
      elements = isolate_->factory()->empty_fixed_array();
    }
    CreateAndInitialiseObject(it.RevisitValues(), elements);

    // Slow path: define remaining named properties.
    for (; !it.Done(); it.Advance()) {
      Handle<String> key;
      if (!failed_property_add_key.is_null()) {
        key = std::exchange(failed_property_add_key, {});
      } else {
        key = it.GetKey({});
      }
#ifdef DEBUG
      uint32_t index;
      DCHECK(!key->AsArrayIndex(&index));
#endif
      Handle<Object> value = it.GetValue(false);
      AddSlowProperty(key, value);
    }

    return object();
  }

  template <typename Char, typename GetKeyFunction, typename GetValueFunction>
  V8_INLINE bool TryAddFastPropertyForValue(base::Vector<const Char> key_chars,
                                            GetKeyFunction&& get_key,
                                            GetValueFunction&& get_value) {
    // The fast path is only valid as long as we haven't allocated an object
    // yet.
    DCHECK(object_.is_null());

    Handle<String> key;
    bool existing_map_found =
        TryFastTransitionToPropertyKey(key_chars, get_key, &key);
    // Unconditionally get the value after getting the transition result.
    DirectHandle<Object> value = get_value();
    if (existing_map_found) {
      // We found a map with a field for our value -- now make sure that field
      // is compatible with our value.
      if (!TryGeneralizeFieldToValue(value)) {
        // TODO(leszeks): Try to stay on the fast path if we just deprecate
        // here.
        return false;
      }
      AdvanceToNextProperty();
      return true;
    }

    // Try to stay on a semi-fast path (being able to stamp out the object
    // fields after creating the correct map) by manually creating the next
    // map here.

    Tagged<DescriptorArray> descriptors = map_->instance_descriptors(isolate_);
    InternalIndex descriptor_number =
        descriptors->SearchWithCache(isolate_, *key, *map_);
    if (descriptor_number.is_found()) {
      // Duplicate property, we need to bail out of even the semi-fast path
      // because we can no longer stamp out values linearly.
      return false;
    }

    if (!TransitionsAccessor::CanHaveMoreTransitions(isolate_, map_)) {
      return false;
    }

    Representation representation =
        Object::OptimalRepresentation(*value, isolate_);
    Handle<FieldType> type =
        Object::OptimalType(*value, isolate_, representation);
    MaybeHandle<Map> maybe_map = Map::CopyWithField(
        isolate_, map_, key, type, NONE, PropertyConstness::kConst,
        representation, INSERT_TRANSITIO
```