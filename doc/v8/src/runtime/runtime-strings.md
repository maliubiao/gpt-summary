Response: Let's break down the thought process to analyze the C++ code and generate the summary and JavaScript examples.

1. **Understand the Goal:** The request is to analyze a C++ file (`runtime-strings.cc`) from the V8 engine. The goal is to understand its functionality and relate it to JavaScript string operations, providing examples.

2. **Initial Scan and Keyword Recognition:**  Quickly scan the code looking for familiar terms related to strings and JavaScript. Keywords like `String`, `substring`, `replace`, `indexOf`, `charCodeAt`, `codePointAt`, `concat`, `length`, `compare`, `escape`, and `wellFormed` immediately stand out. The `RUNTIME_FUNCTION` macro also indicates these are functions accessible from the V8 runtime, which is the bridge between C++ and JavaScript.

3. **Function-by-Function Analysis:** Go through each `RUNTIME_FUNCTION` block individually. For each function:
    * **Identify the Name:**  The name after `RUNTIME_FUNCTION` (e.g., `Runtime_GetSubstitution`) gives a strong hint about its purpose.
    * **Examine Arguments:** The `DCHECK_EQ(..., args.length())` line tells us how many arguments the function expects. The `args.at<...>(...)` calls reveal the expected types of the arguments (usually `String`, `Smi` for small integers).
    * **Analyze the Logic:**  Understand the core operation of the function. Look for calls to V8 internal functions like `String::GetSubstitution`, `String::IndexOf`, `String::Compare`, `isolate->factory()->NewSubString`, etc. These internal functions encapsulate the low-level string manipulation.
    * **Infer JavaScript Relationship:** Based on the function name, arguments, and internal calls, deduce the corresponding JavaScript string method or operation. For instance, `Runtime_GetSubstitution` looks like it's related to the `replace` method's substitution logic. `Runtime_StringSubstring` clearly maps to `substring()`.
    * **Note Key Details:**  Pay attention to specific handling, like the recursion limit in `Runtime_StringReplaceOneCharWithString` or the flattening of strings in several functions. These details provide a deeper understanding of the implementation.

4. **Grouping and Categorization:**  After analyzing individual functions, group them into logical categories based on their JavaScript counterparts. This makes the summary more organized and easier to understand. Common categories include:
    * String manipulation (substring, replace, concat)
    * String searching (indexOf, lastIndexOf)
    * Character access (charCodeAt, codePointAt)
    * String comparison
    * String conversion/creation (internalize, flatten, escape)
    * String properties (length, maxLength)
    * Advanced/internal operations (substitution, well-formedness)

5. **Crafting the Summary:** Write a concise overview of the file's purpose. Emphasize that it implements core JavaScript string functionalities at the C++ level within the V8 engine. Highlight the use of `RUNTIME_FUNCTION` to expose these functions.

6. **Developing JavaScript Examples:** For each significant function or group of functions, create clear and illustrative JavaScript examples. The goal is to demonstrate how the C++ code's functionality is used in everyday JavaScript.
    * **Keep it Simple:**  Use straightforward examples that are easy to understand.
    * **Match Functionality:**  Ensure the JavaScript code accurately reflects the C++ function's behavior.
    * **Provide Context:** Briefly explain what the JavaScript example is doing and how it relates to the C++ code.

7. **Review and Refine:**  Read through the summary and examples to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas where more explanation might be needed. For example, initially, I might just say "handles string replacement," but refining it to "Handles single-character string replacement with consideration for cons strings and recursion limits" is more informative. Similarly, for `Runtime_GetSubstitution`, the connection to the `replace` method's *second* argument (the replacement string with special patterns) needs to be explicitly stated.

**Self-Correction/Refinement Example During Analysis:**

Initially, when looking at `Runtime_GetSubstitution`, I might think it's just a general string substitution function. However, noticing the specific arguments (`matched`, `subject`, `position`, `replacement`, `start_index`) and the creation of a `SimpleMatch` object hints that this is related to the more complex substitution logic used within the `String.prototype.replace()` method, especially when dealing with capturing groups (even though this specific implementation handles a simple case without captures). This leads to a more accurate explanation in the summary and examples.

Another example:  Seeing the handling of "cons strings" in `Runtime_StringReplaceOneCharWithString` makes me realize that V8 has a specific optimization for string concatenation and replacement involving these cons strings, which is a detail worth mentioning in the explanation.

By following this structured approach of analyzing each function, grouping related functionalities, and creating corresponding JavaScript examples, we can effectively understand and explain the purpose of the given C++ code.
这个C++源代码文件 `v8/src/runtime/runtime-strings.cc` 实现了 V8 JavaScript 引擎中与字符串操作相关的 **运行时（Runtime）函数**。这些运行时函数是 V8 引擎内部用 C++ 实现的，但会被 JavaScript 代码调用。

**功能归纳:**

该文件主要包含以下功能的实现：

1. **字符串替换 (`Runtime_GetSubstitution`, `Runtime_StringReplaceOneCharWithString`)**:
   - `Runtime_GetSubstitution`:  处理字符串替换操作中的子串替换逻辑，特别是与正则表达式匹配相关的替换，允许使用 `$n` 等特殊模式。
   - `Runtime_StringReplaceOneCharWithString`:  实现将字符串中第一个出现的指定字符子串替换为另一个字符串的功能，并考虑了 V8 内部的 `ConsString` 优化。

2. **字符串查找 (`Runtime_StringLastIndexOf`)**:
   - `Runtime_StringLastIndexOf`: 实现从字符串末尾开始查找子字符串的功能，对应 JavaScript 的 `String.prototype.lastIndexOf()`。

3. **获取子字符串 (`Runtime_StringSubstring`)**:
   - `Runtime_StringSubstring`: 实现提取字符串指定范围的子字符串功能，对应 JavaScript 的 `String.prototype.substring()` 和 `String.prototype.slice()`。

4. **字符串连接 (`Runtime_StringAdd`, `Runtime_StringBuilderConcat`)**:
   - `Runtime_StringAdd`:  实现简单的字符串连接操作，对应 JavaScript 的 `+` 运算符或 `String.prototype.concat()`。
   - `Runtime_StringBuilderConcat`:  用于高效地连接多个字符串片段，通常在内部被字符串构建器（StringBuilder）使用。

5. **字符串内部化 (`Runtime_InternalizeString`)**:
   - `Runtime_InternalizeString`:  将字符串添加到 V8 引擎的内部字符串表中，如果该字符串已存在，则返回已存在的字符串。这有助于节省内存。

6. **获取字符编码 (`Runtime_StringCharCodeAt`, `Runtime_StringCodePointAt`)**:
   - `Runtime_StringCharCodeAt`: 获取字符串指定位置的 UTF-16 编码单元，对应 JavaScript 的 `String.prototype.charCodeAt()`。
   - `Runtime_StringCodePointAt`: 获取字符串指定位置的 Unicode 码点，可以处理 UTF-16 代理对，对应 JavaScript 的 `String.prototype.codePointAt()`。

7. **字符串转数组 (`Runtime_StringToArray`)**:
   - `Runtime_StringToArray`:  将字符串拆分成包含单个字符的字符串数组，对应 JavaScript 中将字符串作为可迭代对象进行解构或使用 `Array.from()`。

8. **字符串比较 (`Runtime_StringLessThan`, `Runtime_StringLessThanOrEqual`, `Runtime_StringGreaterThan`, `Runtime_StringGreaterThanOrEqual`, `Runtime_StringEqual`, `Runtime_StringCompare`)**:
   - 这些函数实现了各种字符串比较操作，对应 JavaScript 中的 `<`、`<=`、`>`、`>=` 和 `==` 运算符以及 `String.prototype.localeCompare()` 等。

9. **字符串扁平化 (`Runtime_FlattenString`)**:
   - `Runtime_FlattenString`: 将由多个片段（如 `ConsString`）组成的字符串转换为一个连续的字符串。

10. **获取最大字符串长度 (`Runtime_StringMaxLength`)**:
    - `Runtime_StringMaxLength`: 返回 V8 引擎允许的最大字符串长度。

11. **转义引号 (`Runtime_StringEscapeQuotes`)**:
    - `Runtime_StringEscapeQuotes`:  将字符串中的双引号转义为 `&quot;`，常用于 HTML 上下文。

12. **判断字符串是否为良构 Unicode (`Runtime_StringIsWellFormed`)**:
    - `Runtime_StringIsWellFormed`:  检查字符串是否包含任何未配对的代理项，如果包含则不是良构的 Unicode 字符串。

13. **将字符串转换为良构 Unicode (`Runtime_StringToWellFormed`)**:
    - `Runtime_StringToWellFormed`:  将可能包含未配对代理项的字符串转换为良构的 Unicode 字符串，通过替换未配对的代理项。

**与 JavaScript 的关系及示例:**

这些运行时函数是 JavaScript 字符串操作的底层实现。当你在 JavaScript 中使用字符串方法或运算符时，V8 引擎会在内部调用这些 C++ 实现的运行时函数。

以下是一些 JavaScript 示例，说明了这些运行时函数对应的 JavaScript 功能：

**1. 字符串替换 (`Runtime_GetSubstitution`, `Runtime_StringReplaceOneCharWithString`)**

```javascript
const str = "hello world";
const newStr1 = str.replace("world", "javascript"); // 对应 Runtime_StringReplaceOneCharWithString (简单替换)
console.log(newStr1); // 输出: hello javascript

const str2 = "The quick brown fox jumps over the lazy dog.";
const newStr2 = str2.replace(/the (\w+)/g, '<b>$1</b>'); // 对应 Runtime_GetSubstitution (带捕获组的替换)
console.log(newStr2); // 输出: The quick brown fox jumps over <b>lazy</b> dog.
```

**2. 字符串查找 (`Runtime_StringLastIndexOf`)**

```javascript
const str = "hello world hello";
const index = str.lastIndexOf("hello"); // 对应 Runtime_StringLastIndexOf
console.log(index); // 输出: 12
```

**3. 获取子字符串 (`Runtime_StringSubstring`)**

```javascript
const str = "hello";
const sub = str.substring(1, 4); // 对应 Runtime_StringSubstring
console.log(sub); // 输出: ell
```

**4. 字符串连接 (`Runtime_StringAdd`, `Runtime_StringBuilderConcat`)**

```javascript
const str1 = "hello";
const str2 = "world";
const combined = str1 + " " + str2; // 对应 Runtime_StringAdd
console.log(combined); // 输出: hello world

const parts = ["hello", " ", "world"];
const joined = parts.join(""); // 内部可能使用 Runtime_StringBuilderConcat 进行优化
console.log(joined); // 输出: hello world
```

**5. 获取字符编码 (`Runtime_StringCharCodeAt`, `Runtime_StringCodePointAt`)**

```javascript
const str = "你好";
const charCode = str.charCodeAt(0); // 对应 Runtime_StringCharCodeAt (返回 '你' 的 UTF-16 编码)
console.log(charCode);

const codePoint = str.codePointAt(0); // 对应 Runtime_StringCodePointAt (返回 '你' 的 Unicode 码点)
console.log(codePoint);
```

**6. 字符串转数组 (`Runtime_StringToArray`)**

```javascript
const str = "abc";
const arr = Array.from(str); // 对应 Runtime_StringToArray
console.log(arr); // 输出: ["a", "b", "c"]
```

**7. 字符串比较 (`Runtime_StringLessThan`, 等)**

```javascript
const str1 = "apple";
const str2 = "banana";
console.log(str1 < str2); // 对应 Runtime_StringLessThan
console.log(str1 === "apple"); // 对应 Runtime_StringEqual
```

**8. 转义引号 (`Runtime_StringEscapeQuotes`)**

```javascript
const text = 'This is a "quoted" string.';
// JavaScript 没有直接对应的内置函数，但可以自定义或使用库实现类似功能
const escapedText = text.replace(/"/g, '&quot;'); // 模拟 Runtime_StringEscapeQuotes 的功能
console.log(escapedText); // 输出: This is a &quot;quoted&quot; string.
```

**9. 判断/转换良构 Unicode (`Runtime_StringIsWellFormed`, `Runtime_StringToWellFormed`)**

```javascript
const illFormed = String.fromCharCode(0xD800); // 单独的高位代理项
console.log(illFormed);
console.log(illFormed.isWellFormed()); // 对应 Runtime_StringIsWellFormed (新的 ES 标准方法)

const wellFormed = illFormed.toWellFormed(); // 对应 Runtime_StringToWellFormed (新的 ES 标准方法)
console.log(wellFormed); // 输出: � (替换了未配对的代理项)
```

总而言之，`v8/src/runtime/runtime-strings.cc` 文件是 V8 引擎中处理 JavaScript 字符串操作的核心组成部分，它提供了高效且底层的实现，确保 JavaScript 字符串操作的性能和正确性。理解这些运行时函数有助于深入了解 JavaScript 引擎的工作原理。

### 提示词
```
这是目录为v8/src/runtime/runtime-strings.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/arguments-inl.h"
#include "src/heap/heap-inl.h"
#include "src/numbers/conversions.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/slots.h"
#include "src/objects/smi.h"
#include "src/runtime/runtime-utils.h"
#include "src/strings/string-builder-inl.h"
#include "src/strings/unicode-inl.h"

namespace v8 {
namespace internal {

RUNTIME_FUNCTION(Runtime_GetSubstitution) {
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  Handle<String> matched = args.at<String>(0);
  Handle<String> subject = args.at<String>(1);
  int position = args.smi_value_at(2);
  Handle<String> replacement = args.at<String>(3);
  int start_index = args.smi_value_at(4);

  // A simple match without captures.
  class SimpleMatch : public String::Match {
   public:
    SimpleMatch(Handle<String> match, Handle<String> prefix,
                Handle<String> suffix)
        : match_(match), prefix_(prefix), suffix_(suffix) {}

    Handle<String> GetMatch() override { return match_; }
    Handle<String> GetPrefix() override { return prefix_; }
    Handle<String> GetSuffix() override { return suffix_; }

    int CaptureCount() override { return 0; }
    bool HasNamedCaptures() override { return false; }
    MaybeHandle<String> GetCapture(int i, bool* capture_exists) override {
      *capture_exists = false;
      return match_;  // Return arbitrary string handle.
    }
    MaybeHandle<String> GetNamedCapture(Handle<String> name,
                                        CaptureState* state) override {
      UNREACHABLE();
    }

   private:
    Handle<String> match_, prefix_, suffix_;
  };

  Handle<String> prefix =
      isolate->factory()->NewSubString(subject, 0, position);
  Handle<String> suffix = isolate->factory()->NewSubString(
      subject, position + matched->length(), subject->length());
  SimpleMatch match(matched, prefix, suffix);

  RETURN_RESULT_OR_FAILURE(
      isolate,
      String::GetSubstitution(isolate, &match, replacement, start_index));
}

// This may return an empty MaybeHandle if an exception is thrown or
// we abort due to reaching the recursion limit.
MaybeHandle<String> StringReplaceOneCharWithString(
    Isolate* isolate, Handle<String> subject, Handle<String> search,
    Handle<String> replace, bool* found, int recursion_limit) {
  StackLimitCheck stackLimitCheck(isolate);
  if (stackLimitCheck.HasOverflowed() || (recursion_limit == 0)) {
    return MaybeHandle<String>();
  }
  recursion_limit--;
  if (IsConsString(*subject)) {
    Tagged<ConsString> cons = Cast<ConsString>(*subject);
    Handle<String> first = handle(cons->first(), isolate);
    Handle<String> second = handle(cons->second(), isolate);
    Handle<String> new_first;
    if (!StringReplaceOneCharWithString(isolate, first, search, replace, found,
                                        recursion_limit).ToHandle(&new_first)) {
      return MaybeHandle<String>();
    }
    if (*found) return isolate->factory()->NewConsString(new_first, second);

    Handle<String> new_second;
    if (!StringReplaceOneCharWithString(isolate, second, search, replace, found,
                                        recursion_limit)
             .ToHandle(&new_second)) {
      return MaybeHandle<String>();
    }
    if (*found) return isolate->factory()->NewConsString(first, new_second);

    return subject;
  } else {
    int index = String::IndexOf(isolate, subject, search, 0);
    if (index == -1) return subject;
    *found = true;
    Handle<String> first = isolate->factory()->NewSubString(subject, 0, index);
    Handle<String> cons1;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, cons1, isolate->factory()->NewConsString(first, replace));
    Handle<String> second =
        isolate->factory()->NewSubString(subject, index + 1, subject->length());
    return isolate->factory()->NewConsString(cons1, second);
  }
}

RUNTIME_FUNCTION(Runtime_StringReplaceOneCharWithString) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<String> subject = args.at<String>(0);
  Handle<String> search = args.at<String>(1);
  Handle<String> replace = args.at<String>(2);

  // If the cons string tree is too deep, we simply abort the recursion and
  // retry with a flattened subject string.
  const int kRecursionLimit = 0x1000;
  bool found = false;
  Handle<String> result;
  if (StringReplaceOneCharWithString(isolate, subject, search, replace, &found,
                                     kRecursionLimit).ToHandle(&result)) {
    return *result;
  }
  if (isolate->has_exception()) return ReadOnlyRoots(isolate).exception();

  subject = String::Flatten(isolate, subject);
  if (StringReplaceOneCharWithString(isolate, subject, search, replace, &found,
                                     kRecursionLimit).ToHandle(&result)) {
    return *result;
  }
  if (isolate->has_exception()) return ReadOnlyRoots(isolate).exception();
  // In case of empty handle and no exception we have stack overflow.
  return isolate->StackOverflow();
}

RUNTIME_FUNCTION(Runtime_StringLastIndexOf) {
  HandleScope handle_scope(isolate);
  return String::LastIndexOf(isolate, args.at(0), args.at(1),
                             isolate->factory()->undefined_value());
}

RUNTIME_FUNCTION(Runtime_StringSubstring) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<String> string = args.at<String>(0);
  int start = args.smi_value_at(1);
  int end = args.smi_value_at(2);
  DCHECK_LE(0, start);
  DCHECK_LE(start, end);
  DCHECK_LE(end, string->length());
  return *isolate->factory()->NewSubString(string, start, end);
}

RUNTIME_FUNCTION(Runtime_StringAdd) {
  // This is used by Wasm.
  SaveAndClearThreadInWasmFlag non_wasm_scope(isolate);
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<String> str1 = args.at<String>(0);
  Handle<String> str2 = args.at<String>(1);
  RETURN_RESULT_OR_FAILURE(isolate,
                           isolate->factory()->NewConsString(str1, str2));
}


RUNTIME_FUNCTION(Runtime_InternalizeString) {
  HandleScope handles(isolate);
  DCHECK_EQ(1, args.length());
  Handle<String> string = args.at<String>(0);
  return *isolate->factory()->InternalizeString(string);
}

RUNTIME_FUNCTION(Runtime_StringCharCodeAt) {
  SaveAndClearThreadInWasmFlag non_wasm_scope(isolate);
  HandleScope handle_scope(isolate);
  DCHECK_EQ(2, args.length());

  Handle<String> subject = args.at<String>(0);
  uint32_t i = NumberToUint32(args[1]);

  // Flatten the string.  If someone wants to get a char at an index
  // in a cons string, it is likely that more indices will be
  // accessed.
  subject = String::Flatten(isolate, subject);

  if (i >= static_cast<uint32_t>(subject->length())) {
    return ReadOnlyRoots(isolate).nan_value();
  }

  return Smi::FromInt(subject->Get(i));
}

RUNTIME_FUNCTION(Runtime_StringCodePointAt) {
  HandleScope handle_scope(isolate);
  DCHECK_EQ(2, args.length());

  Handle<String> subject = args.at<String>(0);
  uint32_t i = NumberToUint32(args[1]);

  // Flatten the string.  If someone wants to get a char at an index
  // in a cons string, it is likely that more indices will be
  // accessed.
  subject = String::Flatten(isolate, subject);

  if (i >= static_cast<uint32_t>(subject->length())) {
    return ReadOnlyRoots(isolate).nan_value();
  }

  int first_code_point = subject->Get(i);
  if ((first_code_point & 0xFC00) != 0xD800) {
    return Smi::FromInt(first_code_point);
  }

  if (i + 1 >= static_cast<uint32_t>(subject->length())) {
    return Smi::FromInt(first_code_point);
  }

  int second_code_point = subject->Get(i + 1);
  if ((second_code_point & 0xFC00) != 0xDC00) {
    return Smi::FromInt(first_code_point);
  }

  int surrogate_offset = 0x10000 - (0xD800 << 10) - 0xDC00;
  return Smi::FromInt((first_code_point << 10) +
                      (second_code_point + surrogate_offset));
}

RUNTIME_FUNCTION(Runtime_StringBuilderConcat) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  DirectHandle<FixedArray> array = args.at<FixedArray>(0);

  int array_length = args.smi_value_at(1);

  DirectHandle<String> special = args.at<String>(2);

  // This assumption is used by the slice encoding in one or two smis.
  DCHECK_GE(Smi::kMaxValue, String::kMaxLength);

  int special_length = special->length();

  int length;
  bool one_byte = special->IsOneByteRepresentation();

  {
    DisallowGarbageCollection no_gc;
    Tagged<FixedArray> fixed_array = *array;

    if (array_length == 0) {
      return ReadOnlyRoots(isolate).empty_string();
    } else if (array_length == 1) {
      Tagged<Object> first = fixed_array->get(0);
      if (IsString(first)) return first;
    }
    length = StringBuilderConcatLength(special_length, fixed_array,
                                       array_length, &one_byte);
  }

  if (length == -1) {
    return isolate->Throw(ReadOnlyRoots(isolate).illegal_argument_string());
  }
  if (length == 0) {
    return ReadOnlyRoots(isolate).empty_string();
  }

  if (one_byte) {
    Handle<SeqOneByteString> answer;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, answer, isolate->factory()->NewRawOneByteString(length));
    DisallowGarbageCollection no_gc;
    StringBuilderConcatHelper(*special, answer->GetChars(no_gc), *array,
                              array_length);
    return *answer;
  } else {
    Handle<SeqTwoByteString> answer;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, answer, isolate->factory()->NewRawTwoByteString(length));
    DisallowGarbageCollection no_gc;
    StringBuilderConcatHelper(*special, answer->GetChars(no_gc), *array,
                              array_length);
    return *answer;
  }
}

// Converts a String to JSArray.
// For example, "foo" => ["f", "o", "o"].
RUNTIME_FUNCTION(Runtime_StringToArray) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<String> s = args.at<String>(0);
  uint32_t limit = NumberToUint32(args[1]);

  s = String::Flatten(isolate, s);
  const int length =
      static_cast<int>(std::min(static_cast<uint32_t>(s->length()), limit));

  DirectHandle<FixedArray> elements = isolate->factory()->NewFixedArray(length);
  bool elements_are_initialized = false;

  if (s->IsFlat() && s->IsOneByteRepresentation()) {
    DisallowGarbageCollection no_gc;
    String::FlatContent content = s->GetFlatContent(no_gc);
    // Use pre-initialized single characters to intialize all the elements.
    // This can be false if the string is sliced from an externalized
    // two-byte string that has only one-byte chars, in that case we will do
    // a LookupSingleCharacterStringFromCode for each of the characters.
    if (content.IsOneByte()) {
      base::Vector<const uint8_t> chars = content.ToOneByteVector();
      Tagged<FixedArray> one_byte_table =
          isolate->heap()->single_character_string_table();
      for (int i = 0; i < length; ++i) {
        Tagged<Object> value = one_byte_table->get(chars[i]);
        DCHECK(IsString(value));
        DCHECK(ReadOnlyHeap::Contains(Cast<HeapObject>(value)));
        // The single-character strings are in RO space so it should
        // be safe to skip the write barriers.
        elements->set(i, value, SKIP_WRITE_BARRIER);
      }
      elements_are_initialized = true;
    }
  }

  if (!elements_are_initialized) {
    for (int i = 0; i < length; ++i) {
      DirectHandle<Object> str =
          isolate->factory()->LookupSingleCharacterStringFromCode(s->Get(i));
      elements->set(i, *str);
    }
  }

#ifdef DEBUG
  for (int i = 0; i < length; ++i) {
    DCHECK_EQ(Cast<String>(elements->get(i))->length(), 1);
  }
#endif

  return *isolate->factory()->NewJSArrayWithElements(elements);
}

RUNTIME_FUNCTION(Runtime_StringLessThan) {
  HandleScope handle_scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<String> x = args.at<String>(0);
  Handle<String> y = args.at<String>(1);
  ComparisonResult result = String::Compare(isolate, x, y);
  DCHECK_NE(result, ComparisonResult::kUndefined);
  return isolate->heap()->ToBoolean(
      ComparisonResultToBool(Operation::kLessThan, result));
}

RUNTIME_FUNCTION(Runtime_StringLessThanOrEqual) {
  HandleScope handle_scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<String> x = args.at<String>(0);
  Handle<String> y = args.at<String>(1);
  ComparisonResult result = String::Compare(isolate, x, y);
  DCHECK_NE(result, ComparisonResult::kUndefined);
  return isolate->heap()->ToBoolean(
      ComparisonResultToBool(Operation::kLessThanOrEqual, result));
}

RUNTIME_FUNCTION(Runtime_StringGreaterThan) {
  HandleScope handle_scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<String> x = args.at<String>(0);
  Handle<String> y = args.at<String>(1);
  ComparisonResult result = String::Compare(isolate, x, y);
  DCHECK_NE(result, ComparisonResult::kUndefined);
  return isolate->heap()->ToBoolean(
      ComparisonResultToBool(Operation::kGreaterThan, result));
}

RUNTIME_FUNCTION(Runtime_StringGreaterThanOrEqual) {
  HandleScope handle_scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<String> x = args.at<String>(0);
  Handle<String> y = args.at<String>(1);
  ComparisonResult result = String::Compare(isolate, x, y);
  DCHECK_NE(result, ComparisonResult::kUndefined);
  return isolate->heap()->ToBoolean(
      ComparisonResultToBool(Operation::kGreaterThanOrEqual, result));
}

RUNTIME_FUNCTION(Runtime_StringEqual) {
  SaveAndClearThreadInWasmFlag non_wasm_scope(isolate);
  HandleScope handle_scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<String> x = args.at<String>(0);
  Handle<String> y = args.at<String>(1);
  return isolate->heap()->ToBoolean(String::Equals(isolate, x, y));
}

RUNTIME_FUNCTION(Runtime_StringCompare) {
  SaveAndClearThreadInWasmFlag non_wasm_scope(isolate);
  DCHECK_EQ(2, args.length());
  HandleScope scope(isolate);
  Handle<String> lhs(Cast<String>(args[0]), isolate);
  Handle<String> rhs(Cast<String>(args[1]), isolate);
  ComparisonResult result = String::Compare(isolate, lhs, rhs);
  DCHECK_NE(result, ComparisonResult::kUndefined);
  return Smi::FromInt(static_cast<int>(result));
}

RUNTIME_FUNCTION(Runtime_FlattenString) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<String> str = args.at<String>(0);
  return *String::Flatten(isolate, str);
}

RUNTIME_FUNCTION(Runtime_StringMaxLength) {
  SealHandleScope shs(isolate);
  return Smi::FromInt(String::kMaxLength);
}

RUNTIME_FUNCTION(Runtime_StringEscapeQuotes) {
  HandleScope handle_scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<String> string = args.at<String>(0);

  // Equivalent to global replacement `string.replace(/"/g, "&quot")`, but this
  // does not modify any global state (e.g. the regexp match info).

  const int string_length = string->length();
  Handle<String> quotes =
      isolate->factory()->LookupSingleCharacterStringFromCode('"');

  int quote_index = String::IndexOf(isolate, string, quotes, 0);

  // No quotes, nothing to do.
  if (quote_index == -1) return *string;

  // Find all quotes.
  std::vector<int> indices = {quote_index};
  while (quote_index + 1 < string_length) {
    quote_index = String::IndexOf(isolate, string, quotes, quote_index + 1);
    if (quote_index == -1) break;
    indices.emplace_back(quote_index);
  }

  // Build the replacement string.
  DirectHandle<String> replacement =
      isolate->factory()->NewStringFromAsciiChecked("&quot;");
  const int estimated_part_count = static_cast<int>(indices.size()) * 2 + 1;
  ReplacementStringBuilder builder(isolate->heap(), string,
                                   estimated_part_count);

  int prev_index = -1;  // Start at -1 to avoid special-casing the first match.
  for (int index : indices) {
    const int slice_start = prev_index + 1;
    const int slice_end = index;
    if (slice_end > slice_start) {
      builder.AddSubjectSlice(slice_start, slice_end);
    }
    builder.AddString(replacement);
    prev_index = index;
  }

  if (prev_index < string_length - 1) {
    builder.AddSubjectSlice(prev_index + 1, string_length);
  }

  DirectHandle<String> result;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, result, builder.ToString());
  return *result;
}

RUNTIME_FUNCTION(Runtime_StringIsWellFormed) {
  HandleScope handle_scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<String> string = args.at<String>(0);
  return isolate->heap()->ToBoolean(
      String::IsWellFormedUnicode(isolate, string));
}

RUNTIME_FUNCTION(Runtime_StringToWellFormed) {
  HandleScope handle_scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<String> source = args.at<String>(0);
  if (String::IsWellFormedUnicode(isolate, source)) return *source;
  // String::IsWellFormedUnicode would have returned true above otherwise.
  DCHECK(!source->IsOneByteRepresentation());
  const int length = source->length();
  DirectHandle<SeqTwoByteString> dest =
      isolate->factory()->NewRawTwoByteString(length).ToHandleChecked();
  DisallowGarbageCollection no_gc;
  String::FlatContent source_contents = source->GetFlatContent(no_gc);
  DCHECK(source_contents.IsFlat());
  const uint16_t* source_data = source_contents.ToUC16Vector().begin();
  uint16_t* dest_data = dest->GetChars(no_gc);
  unibrow::Utf16::ReplaceUnpairedSurrogates(source_data, dest_data, length);
  return *dest;
}

}  // namespace internal
}  // namespace v8
```